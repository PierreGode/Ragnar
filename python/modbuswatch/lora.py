"""
modbuswatch — LoRaWAN gateway-backhaul decoder (Semtech GWMP / "packet forwarder").

This is the LoRaWAN *wire* tier: the UDP link between a LoRa gateway and its
network server, not the radio. Ragnar taps copper, so the radio side belongs to
the SDR suite; what a tap sees is the Semtech UDP protocol (default port 1700),
which carries every uplink and downlink PHYPayload in cleartext with an 8-byte
gateway EUI as the only identity.

Two decode layers:
  1. GWMP header + JSON object  -- Semtech PROTOCOL.TXT, protocol version 0x02
  2. PHYPayload inside rxpk[].data / txpk.data (base64) -- LoRaWAN 1.0.x/1.1

Both are hand-rolled, like parser.py: no LoRa library is linked in, so the
module cannot inherit a parsing CVE from the stack it watches.

GWMP packet layouts (bytes):
    PUSH_DATA 0x00 : ver(1) token(2) id(1) gwEUI(8) JSON(var)   min 12
    PUSH_ACK  0x01 : ver(1) token(2) id(1)                      == 4
    PULL_DATA 0x02 : ver(1) token(2) id(1) gwEUI(8)             == 12
    PULL_RESP 0x03 : ver(1) token(2) id(1) JSON(var)            min 5
    PULL_ACK  0x04 : ver(1) token(2) id(1)                      == 4
    TX_ACK    0x05 : ver(1) token(2) id(1) gwEUI(8) [JSON]      min 12

Only PUSH_DATA, PULL_DATA and TX_ACK carry the gateway EUI; both acks are four
bytes and echo the token of the packet they acknowledge (Semtech PROTOCOL.TXT).

Validation is strict and silent: anything that is not a well-formed GWMP packet
is dropped, not reported. UDP/1700 is a well-known port but IPv6 is admitted
whole by the kernel filter, so a loose decoder here would manufacture findings
out of unrelated traffic. There is deliberately no "malformed GWMP" finding.

Address-family-agnostic: identical bytes over IPv4 and IPv6; the family is
carried alongside by the caller, never inferred here.
"""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass, field

GWMP_VERSION = 0x02
# The current PROTOCOL.TXT documents version 2 only; version 1 is the legacy
# forwarder and is accepted so a v1 deployment is not invisible to the census.
GWMP_VERSIONS = (0x01, 0x02)
DEFAULT_LORA_PORT = 1700

# Server-learning window for the backhaul tier, seconds.
#
# Sized off the packet forwarder's own announce cadence, not off the Modbus
# window. The only thing this window has to capture is one ack from the real
# network server, and the forwarder forces one out quickly:
#   - PULL_DATA keepalive: 5 s (DEFAULT_KEEPALIVE in lora_pkt_fwd.c), 10 s in
#     the shipped global_conf.json -> answered with PULL_ACK
#   - stat PUSH_DATA: 30 s (DEFAULT_STAT) even on a gateway with no device
#     traffic at all -> answered with PUSH_ACK
# Both acks come back in well under a second on a wired backhaul. Worst case is
# therefore one stat interval from an arbitrary capture start: 30 s. 60 s is two
# of those, which is as short as this can be and still be right, and it is also
# why LoraServers keeps learning past the window until it knows one server --
# a short window must not turn a quiet backhaul into permanent blindness.
DEFAULT_LORA_WINDOW = 60.0

PUSH_DATA = 0x00
PUSH_ACK = 0x01
PULL_DATA = 0x02
PULL_RESP = 0x03
PULL_ACK = 0x04
TX_ACK = 0x05

PKT_NAMES = {
    PUSH_DATA: "PUSH_DATA",
    PUSH_ACK: "PUSH_ACK",
    PULL_DATA: "PULL_DATA",
    PULL_RESP: "PULL_RESP",
    PULL_ACK: "PULL_ACK",
    TX_ACK: "TX_ACK",
}

# Packets a gateway sends (uplink to the server) vs the server sends (downlink).
GW_TO_SERVER = frozenset({PUSH_DATA, PULL_DATA, TX_ACK})
SERVER_TO_GW = frozenset({PUSH_ACK, PULL_RESP, PULL_ACK})

# Server identity is NOT learned from any packet a server sends. It is the
# DESTINATION of the gateway's own PULL_DATA (see state.GatewayServerMap), so
# nothing an attacker transmits can nominate itself and no learning window is
# needed. Kept as a named empty set so the invariant is checkable.
LEARN_SERVER_FROM = frozenset()

# Packets carrying the 8-byte gateway EUI at offset 4. Both acks are excluded:
# PUSH_ACK and PULL_ACK are four bytes and carry no identifier.
_HAS_EUI = frozenset({PUSH_DATA, PULL_DATA, TX_ACK})

# Exact or minimum length per identifier.
_EXACT_LEN = {PUSH_ACK: (4,), PULL_DATA: (12,), PULL_ACK: (4,)}
_MIN_LEN = {PUSH_DATA: 12, PULL_RESP: 5, TX_ACK: 12}

MAX_JSON = 65535          # a GWMP packet cannot exceed one UDP datagram
MAX_PHY_PER_PACKET = 64   # cap rxpk entries decoded from one PUSH_DATA

# --- LoRaWAN MHDR message types ---
MT_JOIN_REQUEST = 0
MT_JOIN_ACCEPT = 1
MT_UNCONF_DATA_UP = 2
MT_UNCONF_DATA_DOWN = 3
MT_CONF_DATA_UP = 4
MT_CONF_DATA_DOWN = 5
MT_REJOIN_REQUEST = 6
MT_PROPRIETARY = 7

MT_NAMES = {
    MT_JOIN_REQUEST: "JoinRequest",
    MT_JOIN_ACCEPT: "JoinAccept",
    MT_UNCONF_DATA_UP: "UnconfirmedDataUp",
    MT_UNCONF_DATA_DOWN: "UnconfirmedDataDown",
    MT_CONF_DATA_UP: "ConfirmedDataUp",
    MT_CONF_DATA_DOWN: "ConfirmedDataDown",
    MT_REJOIN_REQUEST: "RejoinRequest",
    MT_PROPRIETARY: "Proprietary",
}

DATA_UP = frozenset({MT_UNCONF_DATA_UP, MT_CONF_DATA_UP})
DATA_DOWN = frozenset({MT_UNCONF_DATA_DOWN, MT_CONF_DATA_DOWN})

MIC_LEN = 4
JOIN_REQUEST_LEN = 23          # MHDR(1) + AppEUI(8) + DevEUI(8) + DevNonce(2) + MIC(4)
DATA_MIN_LEN = 12              # MHDR(1) + DevAddr(4) + FCtrl(1) + FCnt(2) + MIC(4)

# 16-bit FCnt wraps legitimately at 0xFFFF; anything above this is treated as a
# rollover candidate, not a reset, however low the next counter is.
FCNT_ROLLOVER_GUARD = 0xFF00


@dataclass
class Gwmp:
    """One decoded GWMP packet. Only well-formed packets are ever returned."""
    identifier: int
    token: int
    version: int = GWMP_VERSION
    gw_eui: str | None = None          # "a840411e8c4c4150" style, as on the wire
    obj: dict | None = None            # decoded JSON object, if the packet has one
    phy: list["Phy"] = field(default_factory=list)

    @property
    def name(self) -> str:
        return PKT_NAMES.get(self.identifier, f"0x{self.identifier:02x}")

    @property
    def from_gateway(self) -> bool:
        return self.identifier in GW_TO_SERVER


@dataclass
class Phy:
    """One decoded LoRaWAN PHYPayload from an rxpk/txpk data field."""
    mtype: int
    dev_eui: str | None = None      # JoinRequest only
    join_eui: str | None = None     # JoinRequest only
    dev_nonce: int | None = None    # JoinRequest only
    dev_addr: str | None = None     # data frames only
    fcnt: int | None = None         # data frames only
    fport: int | None = None
    adr: bool | None = None         # FCtrl bit 7, data frames only
    uplink: bool = True
    # The rxpk/txpk fields that came with this PHYPayload: datr, freq, chan,
    # rssi, lsnr, size. Radio metadata the gateway reports in cleartext, which
    # is what the behavioural fingerprint is built from.
    rx: dict | None = None

    @property
    def mtype_name(self) -> str:
        return MT_NAMES.get(self.mtype, f"MType{self.mtype}")


def _hexle(b: bytes) -> str:
    """LoRaWAN carries EUIs and DevAddr little-endian; render big-endian hex."""
    return b[::-1].hex()


def parse_gwmp(payload: bytes) -> Gwmp | None:
    """
    Decode one GWMP datagram. Returns None unless the packet is well formed:
    version 0x02, a known identifier, and a length consistent with it.
    """
    if not payload or len(payload) < 4 or len(payload) > MAX_JSON:
        return None
    if payload[0] not in GWMP_VERSIONS:
        return None
    ident = payload[3]
    if ident not in PKT_NAMES:
        return None

    n = len(payload)
    exact = _EXACT_LEN.get(ident)
    if exact is not None:
        if n not in exact:
            return None
    elif n < _MIN_LEN[ident]:
        return None

    pkt = Gwmp(identifier=ident, token=struct.unpack_from(">H", payload, 1)[0],
               version=payload[0])
    if ident in _HAS_EUI and n >= 12:
        pkt.gw_eui = payload[4:12].hex()

    # JSON body, where the layout has one.
    body = b""
    if ident in (PUSH_DATA, TX_ACK):
        body = payload[12:]
    elif ident == PULL_RESP:
        body = payload[4:]
    if body:
        try:
            obj = json.loads(body.decode("utf-8", "strict"))
        except (UnicodeDecodeError, ValueError):
            return None          # claims a JSON body and hasn't got one
        if not isinstance(obj, dict):
            return None
        pkt.obj = obj
        pkt.phy = _phys_from(obj)
    elif ident == PULL_RESP:
        return None              # PULL_RESP without a body is not well formed

    return pkt


# rxpk/txpk fields kept for the behavioural fingerprint. Everything else in the
# entry (tmst, tmms, rfch, modu, codr, stat, …) is ignored.
RX_KEYS = ("datr", "freq", "chan", "rssi", "lsnr", "size")


def _rx_meta(entry: dict) -> dict:
    return {k: entry[k] for k in RX_KEYS if k in entry}


def _phys_from(obj: dict) -> list[Phy]:
    """Pull and decode every base64 PHYPayload out of an rxpk list / txpk object."""
    out: list[Phy] = []
    rxpk = obj.get("rxpk")
    if isinstance(rxpk, list):
        for entry in rxpk[:MAX_PHY_PER_PACKET]:
            if isinstance(entry, dict):
                p = _phy_from_b64(entry.get("data"), uplink=True)
                if p is not None:
                    p.rx = _rx_meta(entry)
                    out.append(p)
    txpk = obj.get("txpk")
    if isinstance(txpk, dict):
        p = _phy_from_b64(txpk.get("data"), uplink=False)
        if p is not None:
            p.rx = _rx_meta(txpk)
            out.append(p)
    return out


def _phy_from_b64(data, uplink: bool) -> Phy | None:
    if not isinstance(data, str) or not data:
        return None
    try:
        raw = base64.b64decode(data, validate=True)
    except Exception:
        return None
    return parse_phy(raw, uplink=uplink)


def parse_phy(raw: bytes, uplink: bool = True) -> Phy | None:
    """
    Decode a LoRaWAN PHYPayload. Returns None when the frame is not internally
    consistent — length against MType, FOptsLen against what arrived — so a
    random byte string never becomes a DevAddr or a DevNonce.

    JoinAccept and the FRMPayload of data frames are encrypted; only the
    cleartext fields (MHDR, FHDR, DevNonce, FPort) are read.
    """
    if not raw:
        return None
    mhdr = raw[0]
    mtype = (mhdr >> 5) & 0x07
    major = mhdr & 0x03
    if major != 0:               # only LoRaWAN R1 is defined
        return None

    if mtype == MT_JOIN_REQUEST:
        if len(raw) != JOIN_REQUEST_LEN:
            return None
        join_eui = _hexle(raw[1:9])
        dev_eui = _hexle(raw[9:17])
        dev_nonce = struct.unpack_from("<H", raw, 17)[0]
        return Phy(mtype=mtype, join_eui=join_eui, dev_eui=dev_eui,
                   dev_nonce=dev_nonce, uplink=True)

    if mtype in DATA_UP or mtype in DATA_DOWN:
        if len(raw) < DATA_MIN_LEN:
            return None
        dev_addr = _hexle(raw[1:5])
        fctrl = raw[5]
        fcnt = struct.unpack_from("<H", raw, 6)[0]
        fopts_len = fctrl & 0x0F
        # FHDR(7) + FOpts + MIC(4) must fit, and FPort is present only if there
        # is at least one byte of MACPayload left after FOpts.
        fixed = 1 + 4 + 1 + 2 + fopts_len + MIC_LEN
        if len(raw) < fixed:
            return None
        fport = None
        if len(raw) > fixed:
            fport = raw[8 + fopts_len]
        # FCtrl bit 7 is ADR on both uplink and downlink.
        adr = bool(fctrl & 0x80)
        return Phy(mtype=mtype, dev_addr=dev_addr, fcnt=fcnt, fport=fport,
                   adr=adr, uplink=mtype in DATA_UP)

    # JoinAccept / RejoinRequest / Proprietary: census only, nothing cleartext
    # worth keying a finding on.
    return Phy(mtype=mtype, uplink=mtype == MT_REJOIN_REQUEST)
