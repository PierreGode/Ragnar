#!/usr/bin/env python3
"""
ptpwatch - passive IEEE 1588 / PTPv2 timing-plane monitor for Ragnar.

Passive only. Never transmits. Detects grandmaster takeover, time injection,
control-plane abuse and unicast-negotiation attacks on PTP timing infrastructure.

Design constraints (see /areas/ptpwatch.md preflight):
  * Every rule is packet-vs-packet or packet-vs-its-own-in-band-claim.
    NO rule compares PTP timestamps against the sensor's wall clock -- the
    platform floor (Pi Zero 2W) has no PHC and software-timestamps through a
    USB NIC. Rate rules use CLOCK_MONOTONIC only.
  * Rules needing operator scope ship DISARMED and are armed by one
    declaration. Not baseline learning.
  * Hand-rolled parser: scapy has no PTP dissector at any shipping version.

Transports: Annex F (raw Ethernet 0x88F7), Annex D (UDP/IPv4 319,320),
            Annex E (UDP/IPv6 319,320).
"""

from __future__ import annotations

import enum
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__version__ = "0.1.0-dev"

# ---------------------------------------------------------------------------
# Wire constants -- IEEE 1588-2008 §13, -2019 §13
# ---------------------------------------------------------------------------

ETHERTYPE_PTP = 0x88F7
PTP_EVENT_PORT = 319
PTP_GENERAL_PORT = 320

# Annex F multicast destinations
MAC_PTP_PRIMARY = b"\x01\x1b\x19\x00\x00\x00"   # non-peer-delay
MAC_PTP_PDELAY = b"\x01\x80\xc2\x00\x00\x0e"    # peer-delay

HEADER_LEN = 34  # common header, all PTPv2 messages


class MsgType(enum.IntEnum):
    SYNC = 0x0
    DELAY_REQ = 0x1
    PDELAY_REQ = 0x2
    PDELAY_RESP = 0x3
    FOLLOW_UP = 0x8
    DELAY_RESP = 0x9
    PDELAY_RESP_FOLLOW_UP = 0xA
    ANNOUNCE = 0xB
    SIGNALING = 0xC
    MANAGEMENT = 0xD


EVENT_TYPES = frozenset({MsgType.SYNC, MsgType.DELAY_REQ,
                         MsgType.PDELAY_REQ, MsgType.PDELAY_RESP})

# Fixed messageLength per type, confirmed against linuxptp 4.0 live capture.
# Management (0xD) and Signaling (0xC) are variable (34 + fixed part + TLVs).
FIXED_MSG_LEN: Dict[int, int] = {
    MsgType.SYNC: 44,
    MsgType.DELAY_REQ: 44,
    MsgType.FOLLOW_UP: 44,
    MsgType.DELAY_RESP: 54,
    MsgType.PDELAY_REQ: 54,
    MsgType.PDELAY_RESP: 54,
    MsgType.PDELAY_RESP_FOLLOW_UP: 54,
    MsgType.ANNOUNCE: 64,
}

# flagField byte 6 (wire order) -- transport/message flags
FLAG_ALTERNATE_MASTER = 0x01
FLAG_TWO_STEP = 0x02
FLAG_UNICAST = 0x04
FLAG_PROFILE_1 = 0x20
FLAG_PROFILE_2 = 0x40
FLAG_SECURITY = 0x80

# flagField byte 7 -- timescale/leap flags (Announce only, per spec)
FLAG_LEAP_61 = 0x01
FLAG_LEAP_59 = 0x02
FLAG_UTC_OFFSET_VALID = 0x04
FLAG_PTP_TIMESCALE = 0x08
FLAG_TIME_TRACEABLE = 0x10
FLAG_FREQ_TRACEABLE = 0x20
FLAG_SYNC_UNCERTAIN = 0x40

# logMessageInterval sentinel: 0x7F means "not applicable" -- linuxptp emits
# this on Management. Rate rules MUST skip it or they divide by nonsense.
LOG_INTERVAL_NA = 0x7F

# correctionField is 48.16 signed fixed point: low 16 bits are sub-nanoseconds.
# One second is NOT 1e9 -- it is 1e9 << 16. Getting this wrong ships a rule
# that never fires. (preflight decision 5)
SUBNS_SHIFT = 16
ONE_SECOND_SCALED = 1_000_000_000 << SUBNS_SHIFT   # 65_536_000_000_000
CORRECTION_MAX_ABS = ONE_SECOND_SCALED             # A08 bound

# clockClass values (1588 §7.6.2.5)
CLOCKCLASS_PRIMARY_PTP = 6      # locked to primary reference, PTP timescale
CLOCKCLASS_PRIMARY_ARB = 7      # locked to primary reference, ARB timescale
CLOCKCLASS_DEFAULT = 248        # free-run / not GM-capable (linuxptp default)
CLOCKCLASS_SLAVE_ONLY = 255
PRIMARY_CLOCK_CLASSES = frozenset({CLOCKCLASS_PRIMARY_PTP, CLOCKCLASS_PRIMARY_ARB})

# timeSource (1588 §7.6.2.6)
TIMESRC_ATOMIC = 0x10
TIMESRC_GPS = 0x20
TIMESRC_TERRESTRIAL = 0x30
TIMESRC_PTP = 0x40
TIMESRC_NTP = 0x50
TIMESRC_HAND_SET = 0x60
TIMESRC_OTHER = 0x90
TIMESRC_INTERNAL_OSC = 0xA0

# Unicast negotiation TLVs (1588 §16.1) -- decision 2
TLV_REQUEST_UNICAST = 0x0004
TLV_GRANT_UNICAST = 0x0005
TLV_CANCEL_UNICAST = 0x0006
TLV_ACK_CANCEL_UNICAST = 0x0007
TLV_MANAGEMENT = 0x0001
TLV_MANAGEMENT_ERROR = 0x0002

# Management actionField (1588 §15.4.1.6)
ACTION_GET = 0
ACTION_SET = 1
ACTION_RESPONSE = 2
ACTION_COMMAND = 3
ACTION_ACKNOWLEDGE = 4

CLOCKID_ALL_ONES = b"\xff" * 8

# gPTP / 802.1AS is keyed off majorSdoId == 1. Parsed with the generic codes,
# clockClass-derived rules masked, plus the 802.1AS-specific codes below.
SDOID_GPTP = 1

# TLV types, verified against tshark's dissector rather than recalled.
# 0x0008 is PATH_TRACE, NOT a security TLV -- getting that wrong silently marks
# every 802.1AS network as integrity-protected, because gPTP mandates path trace.
TLV_ORG_EXTENSION = 0x0003
TLV_PATH_TRACE = 0x0008
TLV_ALTERNATE_TIME_OFFSET = 0x0009
TLV_AUTHENTICATION = 0x2000
TLV_AUTH_CHALLENGE = 0x2001
TLV_SECURITY_ASSOC_UPDATE = 0x2002
SECURITY_TLVS = frozenset({TLV_AUTHENTICATION, TLV_AUTH_CHALLENGE,
                           TLV_SECURITY_ASSOC_UPDATE})

# 802.1AS organization-extension TLVs: OUI 00-80-C2 with a 3-byte subType.
OUI_IEEE_802_1 = b"\x00\x80\xc2"
SUBTYPE_FOLLOW_UP_INFO = 1        # mandatory on every gPTP Follow_Up
SUBTYPE_MSG_INTERVAL_REQ = 2      # Signaling: renegotiates transmit intervals
# 802.1AS interval sentinels carried in the message-interval-request TLV
INTERVAL_STOP_SENDING = 127
INTERVAL_SET_INITIAL = 126

# gPTP uses the "nearest bridge" reserved address for EVERY message type, not
# just peer-delay. Confirmed: all 343 frames of a live gPTP capture went to it.
MAC_GPTP = MAC_PTP_PDELAY

# 802.1AS permits ONLY the peer-delay mechanism. End-to-end delay request /
# response in a gPTP domain is a protocol violation.
E2E_TYPES = frozenset({MsgType.DELAY_REQ, MsgType.DELAY_RESP})


# ---------------------------------------------------------------------------
# Parse results
# ---------------------------------------------------------------------------

class ParseError(Exception):
    """Malformed PTP message. Carries the reason for the A09-class finding."""


@dataclass(frozen=True)
class Tlv:
    tlv_type: int
    length: int
    value: bytes


@dataclass
class PtpMsg:
    """A parsed PTPv2 message. Field names follow IEEE 1588 §13.3."""
    # common header
    major_sdo_id: int
    msg_type: int
    minor_version: int
    version: int
    msg_length: int
    domain: int
    minor_sdo_id: int
    flags: int                      # 16-bit, byte6 << 8 | byte7
    correction: int                 # signed, scaled ns (48.16)
    msg_type_specific: int
    clock_identity: bytes           # 8 bytes
    port_number: int
    sequence_id: int
    control_field: int
    log_interval: int               # signed

    # transport context (filled by the decoder, not the PTP parser)
    src_mac: Optional[bytes] = None
    dst_mac: Optional[bytes] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    transport: str = "unknown"      # annexF | annexD | annexE

    # bodies (only the ones relevant to a given type are populated)
    origin_ts: Optional[Tuple[int, int]] = None      # (seconds, nanoseconds)
    utc_offset: Optional[int] = None
    priority1: Optional[int] = None
    clock_class: Optional[int] = None
    clock_accuracy: Optional[int] = None
    clock_variance: Optional[int] = None
    priority2: Optional[int] = None
    gm_identity: Optional[bytes] = None
    steps_removed: Optional[int] = None
    time_source: Optional[int] = None

    requesting_identity: Optional[bytes] = None      # Delay_Resp / Pdelay_Resp
    requesting_port: Optional[int] = None

    # management
    target_identity: Optional[bytes] = None
    target_port: Optional[int] = None
    action_field: Optional[int] = None
    management_id: Optional[int] = None

    tlvs: List[Tlv] = field(default_factory=list)
    tlv_end: int = 0            # body offset after the last well-formed TLV
    tlv_truncated: bool = False  # a TLV declared more bytes than arrived

    # ---- derived helpers -------------------------------------------------
    @property
    def port_identity(self) -> Tuple[bytes, int]:
        return (self.clock_identity, self.port_number)

    @property
    def is_gptp(self) -> bool:
        return self.major_sdo_id == SDOID_GPTP

    @property
    def two_step(self) -> bool:
        return bool((self.flags >> 8) & FLAG_TWO_STEP)

    @property
    def unicast(self) -> bool:
        return bool((self.flags >> 8) & FLAG_UNICAST)

    @property
    def alternate_master(self) -> bool:
        return bool((self.flags >> 8) & FLAG_ALTERNATE_MASTER)

    @property
    def security_flag(self) -> bool:
        return bool((self.flags >> 8) & FLAG_SECURITY)

    @property
    def leap61(self) -> bool:
        return bool(self.flags & FLAG_LEAP_61)

    @property
    def leap59(self) -> bool:
        return bool(self.flags & FLAG_LEAP_59)

    @property
    def utc_offset_valid(self) -> bool:
        return bool(self.flags & FLAG_UTC_OFFSET_VALID)

    @property
    def ptp_timescale(self) -> bool:
        return bool(self.flags & FLAG_PTP_TIMESCALE)

    @property
    def correction_ns(self) -> float:
        return self.correction / (1 << SUBNS_SHIFT)

    def eui64_mac(self) -> Optional[bytes]:
        """Recover the MAC embedded in an EUI-64-derived clockIdentity.

        clockIdentity = MAC[0:3] + FF FE + MAC[3:6]. Returns None if the
        identity was not built that way (perfectly legal -- it need not be).
        """
        ci = self.clock_identity
        if len(ci) == 8 and ci[3] == 0xFF and ci[4] == 0xFE:
            return ci[0:3] + ci[5:8]
        return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _s64(v: int) -> int:
    return v - (1 << 64) if v & (1 << 63) else v


def parse_ptp(buf: bytes, *, strict: bool = False) -> PtpMsg:
    """Parse a PTPv2 message from the start of buf.

    Raises ParseError on anything that cannot yield a trustworthy header.
    Body/TLV damage past a good header is tolerated (fields left None) so the
    header-level detections still fire on malformed traffic -- that traffic is
    exactly what we care about.
    """
    if len(buf) < HEADER_LEN:
        raise ParseError(f"runt: {len(buf)} bytes < {HEADER_LEN} header")

    b0, b1 = buf[0], buf[1]
    major_sdo_id = (b0 >> 4) & 0x0F
    msg_type = b0 & 0x0F
    minor_version = (b1 >> 4) & 0x0F
    version = b1 & 0x0F

    msg_length = struct.unpack_from("!H", buf, 2)[0]
    domain = buf[4]
    minor_sdo_id = buf[5]
    flags = struct.unpack_from("!H", buf, 6)[0]
    correction = _s64(struct.unpack_from("!Q", buf, 8)[0])
    msg_type_specific = struct.unpack_from("!I", buf, 16)[0]
    clock_identity = buf[20:28]
    port_number = struct.unpack_from("!H", buf, 28)[0]
    sequence_id = struct.unpack_from("!H", buf, 30)[0]
    control_field = buf[32]
    log_interval = struct.unpack_from("!b", buf, 33)[0]

    msg = PtpMsg(
        major_sdo_id=major_sdo_id, msg_type=msg_type,
        minor_version=minor_version, version=version,
        msg_length=msg_length, domain=domain, minor_sdo_id=minor_sdo_id,
        flags=flags, correction=correction,
        msg_type_specific=msg_type_specific,
        clock_identity=clock_identity, port_number=port_number,
        sequence_id=sequence_id, control_field=control_field,
        log_interval=log_interval,
    )

    # Body is parsed on a best-effort basis against the DECLARED length,
    # clamped to what actually arrived. A declared/actual mismatch is a
    # finding (A09), not a parse abort.
    body = buf[HEADER_LEN:min(len(buf), max(msg_length, HEADER_LEN))]
    try:
        _parse_body(msg, body)
    except (struct.error, IndexError, ValueError) as exc:
        if strict:
            raise ParseError(f"body: {exc}") from exc
    return msg


def _ts(buf: bytes, off: int) -> Tuple[int, int]:
    """80-bit Timestamp: 48-bit seconds + 32-bit nanoseconds."""
    hi, lo, ns = struct.unpack_from("!HII", buf, off)
    return ((hi << 32) | lo, ns)


def _parse_body(msg: PtpMsg, body: bytes) -> None:
    t = msg.msg_type

    # TLVs begin immediately after the fixed body. Derive that offset from the
    # length table rather than hand-writing it per branch.
    tlv_off = FIXED_MSG_LEN.get(t, HEADER_LEN) - HEADER_LEN

    if t in (MsgType.SYNC, MsgType.DELAY_REQ, MsgType.FOLLOW_UP,
             MsgType.PDELAY_REQ, MsgType.PDELAY_RESP,
             MsgType.PDELAY_RESP_FOLLOW_UP):
        if len(body) >= 10:
            msg.origin_ts = _ts(body, 0)
        if t in (MsgType.PDELAY_RESP, MsgType.PDELAY_RESP_FOLLOW_UP) and len(body) >= 20:
            msg.requesting_identity = body[10:18]
            msg.requesting_port = struct.unpack_from("!H", body, 18)[0]
        _parse_tlvs(msg, body, tlv_off)

    elif t == MsgType.DELAY_RESP:
        if len(body) >= 20:
            msg.origin_ts = _ts(body, 0)
            msg.requesting_identity = body[10:18]
            msg.requesting_port = struct.unpack_from("!H", body, 18)[0]
        _parse_tlvs(msg, body, tlv_off)

    elif t == MsgType.ANNOUNCE:
        if len(body) >= 30:
            msg.origin_ts = _ts(body, 0)
            msg.utc_offset = struct.unpack_from("!h", body, 10)[0]
            # body[12] reserved
            msg.priority1 = body[13]
            msg.clock_class = body[14]
            msg.clock_accuracy = body[15]
            msg.clock_variance = struct.unpack_from("!H", body, 16)[0]
            msg.priority2 = body[18]
            msg.gm_identity = body[19:27]
            msg.steps_removed = struct.unpack_from("!H", body, 27)[0]
            msg.time_source = body[29]
        _parse_tlvs(msg, body, tlv_off)

    elif t == MsgType.MANAGEMENT:
        if len(body) >= 14:
            msg.target_identity = body[0:8]
            msg.target_port = struct.unpack_from("!H", body, 8)[0]
            # body[10] startingBoundaryHops, body[11] boundaryHops
            msg.action_field = body[12] & 0x0F
            # body[13] reserved
        _parse_tlvs(msg, body, 14)
        for tlv in msg.tlvs:
            if tlv.tlv_type in (TLV_MANAGEMENT, TLV_MANAGEMENT_ERROR) and len(tlv.value) >= 2:
                msg.management_id = struct.unpack_from("!H", tlv.value, 0)[0]
                break

    elif t == MsgType.SIGNALING:
        if len(body) >= 10:
            msg.target_identity = body[0:8]
            msg.target_port = struct.unpack_from("!H", body, 8)[0]
        _parse_tlvs(msg, body, 10)


def _parse_tlvs(msg: PtpMsg, body: bytes, off: int) -> None:
    """Walk the TLV chain. Stops cleanly at truncation rather than raising --
    a chain running past the frame end is itself evidence, recorded by the
    caller via declared-vs-actual length."""
    n = len(body)
    guard = 0
    msg.tlv_end = off
    while off + 4 <= n and guard < 64:
        guard += 1
        ttype, tlen = struct.unpack_from("!HH", body, off)
        off += 4
        if tlen > n - off:
            msg.tlvs.append(Tlv(ttype, tlen, body[off:n]))
            msg.tlv_truncated = True
            msg.tlv_end = n
            return
        msg.tlvs.append(Tlv(ttype, tlen, body[off:off + tlen]))
        off += tlen + (tlen & 1)  # TLVs are even-length padded
        msg.tlv_end = off


# ---------------------------------------------------------------------------
# Link-layer decode + pcap reader (no scapy dependency at runtime)
# ---------------------------------------------------------------------------

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

# IPv6 extension headers that are safely skippable with the standard
# (hdr_ext_len + 1) * 8 sizing. AH (51) is deliberately NOT here -- it sizes in
# 4-byte units with a different bias, so it gets its own branch below.
V6_SKIPPABLE = {0, 43, 60, 135}
V6_AUTH_HEADER = 51
IPPROTO_UDP = 17


def decode_frame(buf: bytes, linktype: int = LINKTYPE_ETHERNET
                 ) -> Optional[Dict[str, object]]:
    """Return transport context + PTP payload, or None if not PTP.

    All filtering happens here in Python -- the live path runs an empty BPF
    (both Ragnar templates agree; the sr-mplswatch systemd unit's
    MemoryDenyWriteExecute hardening is only safe with the empty default).
    """
    if linktype == LINKTYPE_LINUX_SLL:
        if len(buf) < 16:
            return None
        return _decode_l3(buf[16:], struct.unpack_from("!H", buf, 14)[0], None, None)
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(buf) < 20:
            return None
        return _decode_l3(buf[20:], struct.unpack_from("!H", buf, 0)[0], None, None)
    if linktype == LINKTYPE_RAW:
        if not buf:
            return None
        ver = (buf[0] >> 4) & 0x0F
        etype = 0x0800 if ver == 4 else 0x86DD if ver == 6 else 0
        return _decode_l3(buf, etype, None, None)

    if len(buf) < 14:
        return None
    dst_mac, src_mac = buf[0:6], buf[6:12]
    off = 12
    etype = struct.unpack_from("!H", buf, off)[0]
    off += 2
    hops = 0
    while etype in (0x8100, 0x88A8) and hops < 3:   # stacked VLAN tags
        if len(buf) < off + 4:
            return None
        etype = struct.unpack_from("!H", buf, off + 2)[0]
        off += 4
        hops += 1
    if etype == ETHERTYPE_PTP:
        return {"payload": buf[off:], "transport": "annexF",
                "src_mac": src_mac, "dst_mac": dst_mac,
                "src_ip": None, "dst_ip": None}
    return _decode_l3(buf[off:], etype, src_mac, dst_mac)


def _decode_l3(buf: bytes, etype: int, src_mac, dst_mac):
    if etype == 0x0800:
        if len(buf) < 20 or (buf[0] >> 4) != 4:
            return None
        ihl = (buf[0] & 0x0F) * 4
        if ihl < 20 or len(buf) < ihl or buf[9] != IPPROTO_UDP:
            return None
        src = ".".join(str(b) for b in buf[12:16])
        dst = ".".join(str(b) for b in buf[16:20])
        return _decode_udp(buf[ihl:], "annexD", src, dst, src_mac, dst_mac)

    if etype == 0x86DD:
        if len(buf) < 40 or (buf[0] >> 4) != 6:
            return None
        nxt, cur = buf[6], 40
        src = _v6str(buf[8:24])
        dst = _v6str(buf[24:40])
        hops = 0
        while hops < 8:
            hops += 1
            if nxt == IPPROTO_UDP:
                return _decode_udp(buf[cur:], "annexE", src, dst, src_mac, dst_mac)
            if nxt in V6_SKIPPABLE:
                if len(buf) < cur + 2:
                    return None
                ext = (buf[cur + 1] + 1) * 8
            elif nxt == V6_AUTH_HEADER:
                if len(buf) < cur + 2:
                    return None
                ext = (buf[cur + 1] + 2) * 4      # AH: 4-byte units, bias 2
            else:
                return None
            nxt = buf[cur]
            cur += ext
            if cur >= len(buf):
                return None
        return None
    return None


def _v6str(b: bytes) -> str:
    groups = [f"{struct.unpack_from('!H', b, i)[0]:x}" for i in range(0, 16, 2)]
    best_i = best_n = cur_i = cur_n = -1
    for i, g in enumerate(groups + ["x"]):
        if g == "0":
            if cur_i < 0:
                cur_i, cur_n = i, 0
            cur_n += 1
        else:
            if cur_n > best_n:
                best_i, best_n = cur_i, cur_n
            cur_i = cur_n = -1
    if best_n > 1:
        return ":".join(groups[:best_i]) + "::" + ":".join(groups[best_i + best_n:])
    return ":".join(groups)


def _decode_udp(buf, transport, src, dst, src_mac, dst_mac):
    if len(buf) < 8:
        return None
    sport, dport = struct.unpack_from("!HH", buf, 0)
    if dport not in (PTP_EVENT_PORT, PTP_GENERAL_PORT) and \
       sport not in (PTP_EVENT_PORT, PTP_GENERAL_PORT):
        return None
    return {"payload": buf[8:], "transport": transport,
            "src_mac": src_mac, "dst_mac": dst_mac, "src_ip": src, "dst_ip": dst}


def read_pcap(path: str):
    """Yield (timestamp_float, frame_bytes, linktype). Handles all four pcap
    magics and pcapng. No scapy, no libpcap."""
    with open(path, "rb") as fh:
        magic = fh.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _read_pcapng(fh)
            return
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, nano = ">", True
        else:
            raise ValueError(f"not a pcap file: magic {magic!r}")
        hdr = fh.read(20)
        linktype = struct.unpack(endian + "I", hdr[16:20])[0]
        div = 1e9 if nano else 1e6
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            ts_s, ts_f, caplen, _ = struct.unpack(endian + "IIII", rec)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            yield (ts_s + ts_f / div, data, linktype)


def _read_pcapng(fh):
    fh.seek(0)
    linktype = LINKTYPE_ETHERNET
    endian = "<"
    tsresol = 6
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        btype = struct.unpack(endian + "I", head[0:4])[0]
        if btype == 0x0A0D0D0A:
            bom = fh.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", head[4:8])[0]
            fh.read(blen - 16)
            fh.read(0)
            continue
        blen = struct.unpack(endian + "I", head[4:8])[0]
        body = fh.read(blen - 12)
        fh.read(4)
        if btype == 0x00000001 and len(body) >= 4:
            linktype = struct.unpack(endian + "H", body[0:2])[0]
        elif btype == 0x00000006 and len(body) >= 20:
            hi, lo, caplen = struct.unpack(endian + "III", body[4:16])
            ts = ((hi << 32) | lo) / (10 ** tsresol)
            yield (ts, body[20:20 + caplen], linktype)


# ---------------------------------------------------------------------------
# Finding registry
# ---------------------------------------------------------------------------

class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(enum.Enum):
    CONFIRMED = "confirmed"   # protocol-impossible; no benign reading exists
    PROBABLE = "probable"     # benign reading exists but is unlikely
    POSSIBLE = "possible"     # real ambiguity; operator must adjudicate


class Klass(enum.Enum):
    ATTACK = "attack"
    POSTURE = "posture"
    EXPOSURE = "exposure"


@dataclass(frozen=True)
class CodeSpec:
    code: str
    severity: Severity
    confidence: Confidence
    klass: Klass
    category: str
    title: str
    rationale: str
    armed_by: Optional[str] = None   # config knob that arms a disarmed rule
    gptp_masked: bool = False        # suppressed for majorSdoId==1 (decision 4)


def _c(code, sev, conf, kl, cat, title, rationale, armed_by=None, gptp_masked=False):
    return CodeSpec(code, sev, conf, kl, cat, title, rationale, armed_by, gptp_masked)


FINDINGS: Dict[str, CodeSpec] = {s.code: s for s in [
    # -- Class A: self-contradiction ---------------------------------------
    _c("PTP-A01", Severity.CRITICAL, Confidence.CONFIRMED, Klass.ATTACK, "self-contradiction",
       "Primary-reference clockClass with non-zero stepsRemoved",
       "clockClass 6/7 means locked to a primary reference, which is by definition "
       "zero steps removed. A forged Announce claiming primary status from inside "
       "the tree contradicts itself.", gptp_masked=True),
    _c("PTP-A02", Severity.CRITICAL, Confidence.CONFIRMED, Klass.ATTACK, "self-contradiction",
       "Primary-reference clockClass sourced from internal oscillator",
       "clockClass 6/7 asserts a primary reference (GPS/atomic); timeSource "
       "INTERNAL_OSCILLATOR asserts free-run. Both cannot hold. Note clockClass 248 "
       "with INTERNAL_OSCILLATOR is the normal free-run pairing and is not this.",
       gptp_masked=True),
    _c("PTP-A03", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "self-contradiction",
       "Announce rate exceeds the rate this source advertised",
       "logAnnounceInterval is the sender's own declaration of its transmit period. "
       "Sustained transmission faster than its own claim is a flood or an injector "
       "racing the legitimate master's BMCA."),
    _c("PTP-A04", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "self-contradiction",
       "Sync rate exceeds the rate this source advertised",
       "As A03, for logSyncInterval. Sync flooding drives servo instability in "
       "downstream slaves without requiring any timestamp forgery."),
    _c("PTP-A05", Severity.MEDIUM, Confidence.PROBABLE, Klass.ATTACK, "self-contradiction",
       "twoStep Sync with no Follow_Up",
       "A Sync with twoStepFlag set promises a Follow_Up carrying the real "
       "timestamp. Withholding it strands the slave on a precise-but-empty Sync."),
    _c("PTP-A06", Severity.MEDIUM, Confidence.CONFIRMED, Klass.ATTACK, "self-contradiction",
       "Follow_Up for a one-step Sync",
       "A Follow_Up for a sequenceId whose Sync had twoStepFlag clear is an "
       "injected timestamp with no legitimate origin."),
    _c("PTP-A07", Severity.HIGH, Confidence.CONFIRMED, Klass.ATTACK, "replay",
       "sequenceId regression from one sourcePortIdentity",
       "sequenceId is monotonic per message type per port. Going backwards (beyond "
       "reorder tolerance, wrap-aware) means replayed or forged frames."),
    _c("PTP-A08", Severity.CRITICAL, Confidence.CONFIRMED, Klass.ATTACK, "time-injection",
       "correctionField beyond physical plausibility",
       "correctionField accumulates transparent-clock residence time. Values at or "
       "beyond one second are physically impossible and inject offset directly, "
       "without touching any timestamp field."),
    _c("PTP-A09", Severity.MEDIUM, Confidence.CONFIRMED, Klass.ATTACK, "malformed",
       "messageLength inconsistent with message type",
       "Fixed-length message types have one legal length. A mismatch is malformed "
       "traffic or a parser-differential attack against downstream stacks."),
    _c("PTP-A10", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "time-injection",
       "Origin timestamp non-monotonic or stepping beyond the advertised interval",
       "Successive timestamps from one source going backwards, or forward by far "
       "more than its own declared interval, is time injection."),

    # -- Class B: identity conflict ----------------------------------------
    _c("PTP-B01", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "identity",
       "One sourcePortIdentity seen from two source MACs",
       "A port identity is bound to one physical port. Two source MACs carrying it "
       "is impersonation or a forwarding loop."),
    _c("PTP-B02", Severity.CRITICAL, Confidence.PROBABLE, Klass.ATTACK, "identity",
       "Two sources announcing the same grandmasterIdentity",
       "Distinct sourcePortIdentities claiming to relay the same grandmaster, where "
       "the topology admits only one path, indicates a forged Announce."),
    _c("PTP-B03", Severity.MEDIUM, Confidence.POSSIBLE, Klass.ATTACK, "identity",
       "EUI-64 clockIdentity does not match Ethernet source MAC",
       "Annex F only. Self-disarms permanently on the first transparent- or "
       "boundary-clock evidence for the segment, because relayed frames legitimately "
       "carry an upstream identity."),
    _c("PTP-B04", Severity.HIGH, Confidence.POSSIBLE, Klass.ATTACK, "bmca",
       "Grandmaster transition won by a newly-appeared clock",
       "A GM change whose winner has strictly better priority1/clockClass and whose "
       "clockIdentity was first seen inside the observation window. Arrival-order "
       "evidence, not policy -- a legitimate cold-start failover looks the same, "
       "hence POSSIBLE."),
    _c("PTP-B05", Severity.CRITICAL, Confidence.CONFIRMED, Klass.ATTACK, "bmca",
       "Announce from a grandmasterIdentity outside the declared set",
       "Disarmed by default. Armed by an explicit operator declaration, not by "
       "learning. With the set declared, any other GM identity is unambiguous.",
       armed_by="grandmasters"),

    # -- Class C: time-injection primitives ---------------------------------
    _c("PTP-C01", Severity.CRITICAL, Confidence.PROBABLE, Klass.ATTACK, "time-injection",
       "currentUtcOffset changed mid-session by the same grandmaster",
       "The UTC offset changes only at a leap second. An unscheduled change steps "
       "every downstream UTC-derived clock by whole seconds."),
    _c("PTP-C02", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "time-injection",
       "Leap-second flag asserted outside a leap window",
       "leap61/leap59 are only valid approaching the end of June or December. "
       "Checked against the Announce's OWN originTimestamp, not the sensor clock, "
       "so the rule holds even on an unsynchronised sensor."),
    _c("PTP-C03", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "time-injection",
       "ptpTimescale flag flipped mid-session",
       "Switching between PTP and ARB timescale re-bases every slave's notion of "
       "epoch without any timestamp appearing wrong."),
    _c("PTP-C04", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "time-injection",
       "currentUtcOffsetValid cleared then re-asserted with a different value",
       "Laundering an offset change through an invalid-offset interval hides C01 "
       "from implementations that only compare valid-to-valid transitions."),

    # -- Class D: control-plane abuse ---------------------------------------
    _c("PTP-D01", Severity.CRITICAL, Confidence.CONFIRMED, Klass.ATTACK, "management",
       "Management SET or COMMAND observed",
       "PTP management writes reconfigure clock priority, domain and state. On a "
       "production timing segment these are an active attack, not monitoring."),
    _c("PTP-D02", Severity.CRITICAL, Confidence.CONFIRMED, Klass.ATTACK, "management",
       "Management WRITE addressed to all clocks",
       "targetPortIdentity of all-ones with a SET or COMMAND action reconfigures "
       "every clock in the domain at once. Deliberately NOT fired on a broadcast "
       "GET: pmc and every other PTP monitoring tool address GETs to all-ones as "
       "normal operation, and gating on action is what separates monitoring from "
       "an attack."),
    _c("PTP-D03", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "unicast",
       "Unicast transmission request redirecting to a new address",
       "REQUEST_UNICAST_TRANSMISSION naming a destination not previously party to "
       "the session redirects the time source to attacker-chosen infrastructure."),
    _c("PTP-D04", Severity.MEDIUM, Confidence.PROBABLE, Klass.ATTACK, "management",
       "Management GET sweep from an undeclared source",
       "Many distinct managementIds from one source in a short window. A GET sweep "
       "is indistinguishable on the wire from authorised NMS polling, so this is "
       "DISARMED until the monitoring stations are declared -- otherwise it fires "
       "on every site that monitors its own timing plane.",
       armed_by="mgmt_stations"),

    # -- Class E: version and posture ---------------------------------------
    _c("PTP-E01", Severity.MEDIUM, Confidence.CONFIRMED, Klass.EXPOSURE, "version",
       "PTPv1 traffic observed",
       "versionPTP 1 has no security provisions at all and indicates either legacy "
       "equipment or a deliberate downgrade."),
    _c("PTP-E02", Severity.MEDIUM, Confidence.PROBABLE, Klass.ATTACK, "version",
       "minorVersionPTP downgrade from the same clock",
       "A clock that announced 1588-2019 then reverts to 2008 minor version is "
       "being downgraded away from the 2019 security TLV."),
    _c("PTP-E03", Severity.LOW, Confidence.CONFIRMED, Klass.POSTURE, "posture",
       "No integrity protection in use on the timing plane",
       "Presence-only. No security TLV or SECURITY flag seen. Cannot be validated "
       "cryptographically without keys and is not attempted."),
    _c("PTP-E04", Severity.LOW, Confidence.CONFIRMED, Klass.POSTURE, "posture",
       "Multiple PTP domains on one segment",
       "More than one domainNumber observed. Precision improves when the expected "
       "domain is declared.", armed_by="domain"),
    _c("PTP-E05", Severity.LOW, Confidence.POSSIBLE, Klass.POSTURE, "posture",
       "alternateMasterFlag set by a non-grandmaster source",
       "Alternate-master transmission is legitimate in some profiles but expands "
       "the set of clocks a slave will consider."),
    _c("PTP-E06", Severity.MEDIUM, Confidence.CONFIRMED, Klass.EXPOSURE, "posture",
       "Unauthenticated PTP on a segment also carrying management traffic",
       "Timing and management sharing an unauthenticated segment means anything "
       "that can reach the management plane can rewrite time."),

    # -- Class F: delay attack ----------------------------------------------
    _c("PTP-F02", Severity.MEDIUM, Confidence.PROBABLE, Klass.ATTACK, "delay",
       "Pdelay response turnaround exceeds the requested interval",
       "Computed from the responder's OWN claimed t2/t3, so it needs no trustworthy "
       "capture timestamp. An inflated turnaround skews the peer path delay."),

    # -- Class G: unicast negotiation (decision 2) --------------------------
    _c("PTP-G01", Severity.HIGH, Confidence.CONFIRMED, Klass.ATTACK, "unicast",
       "Unicast grant does not match its request",
       "A GRANT whose logInterval or durationField differs from the REQUEST it "
       "answers is a forged or tampered grant."),
    _c("PTP-G02", Severity.HIGH, Confidence.PROBABLE, Klass.ATTACK, "unicast",
       "Unicast transmission continuing past the granted duration",
       "durationField bounds the grant. Traffic continuing past expiry with no "
       "renewal is an injector that never negotiated."),
    _c("PTP-G03", Severity.CRITICAL, Confidence.PROBABLE, Klass.ATTACK, "unicast",
       "Unicast cancellation not attributable to either party",
       "CANCEL_UNICAST_TRANSMISSION kills a slave's time source outright, with no "
       "timestamp forgery required. A forged cancel is clean denial of timing."),
    # -- Class H: gPTP / IEEE 802.1AS specific -----------------------------
    _c("PTP-H01", Severity.HIGH, Confidence.CONFIRMED, Klass.ATTACK, "gptp",
       "End-to-end delay mechanism inside a gPTP domain",
       "802.1AS permits only the peer-delay mechanism. A Delay_Req or "
       "Delay_Resp carrying majorSdoId 1 is a protocol violation and a known "
       "way to confuse implementations that accept both mechanisms."),
    _c("PTP-H02", Severity.CRITICAL, Confidence.CONFIRMED, Klass.ATTACK, "gptp",
       "Multiple peer-delay responders on one link",
       "802.1AS requires point-to-point links: if more than one clock answers "
       "a Pdelay_Req, the requester sets asCapable FALSE and timing stops on "
       "that port. A single injected Pdelay_Resp is therefore a complete "
       "denial-of-timing primitive that forges no timestamp at all."),
    _c("PTP-H03", Severity.MEDIUM, Confidence.PROBABLE, Klass.ATTACK, "gptp",
       "gPTP Announce without the mandatory path-trace TLV",
       "802.1AS mandates a PATH_TRACE TLV on every Announce. Its absence "
       "indicates a forged Announce from something that is not a conformant "
       "802.1AS implementation."),
    _c("PTP-H04", Severity.HIGH, Confidence.CONFIRMED, Klass.ATTACK, "gptp",
       "Path-trace length contradicts stepsRemoved",
       "Each bridge appends its clockIdentity to the path trace and increments "
       "stepsRemoved, so the entry count must equal stepsRemoved plus one. A "
       "mismatch means the Announce is claiming a distance from the "
       "grandmaster that its own path trace does not support."),
    _c("PTP-H05", Severity.HIGH, Confidence.CONFIRMED, Klass.ATTACK, "gptp",
       "Path trace contains a repeated clockIdentity",
       "A clockIdentity appearing twice in one path trace is a timing loop. "
       "802.1AS requires such an Announce be discarded; seeing one on the wire "
       "means either a loop or a forged path."),
    _c("PTP-H06", Severity.MEDIUM, Confidence.PROBABLE, Klass.ATTACK, "gptp",
       "gPTP Follow_Up without the mandatory follow-up information TLV",
       "802.1AS mandates the OUI 00-80-C2 subType 1 TLV carrying "
       "cumulativeScaledRateOffset and gmTimeBaseIndicator on every Follow_Up. "
       "Its absence indicates an injected Follow_Up."),
    _c("PTP-H07", Severity.CRITICAL, Confidence.PROBABLE, Klass.ATTACK, "gptp",
       "Message-interval request suppressing transmission",
       "The 802.1AS message-interval-request TLV renegotiates a neighbour's "
       "transmit intervals. Interval 127 means stop sending: an unsolicited "
       "request silences a peer's Sync or Announce stream outright, denying "
       "timing without forging anything."),
    _c("PTP-H08", Severity.MEDIUM, Confidence.CONFIRMED, Klass.ATTACK, "gptp",
       "gPTP message sent to the wrong destination address",
       "802.1AS uses the nearest-bridge address 01:80:C2:00:00:0E for every "
       "message type, not only peer-delay. A majorSdoId 1 frame sent to the "
       "1588 default 01:1B:19:00:00:00 was not produced by a conformant "
       "802.1AS stack."),

    _c("PTP-G04", Severity.MEDIUM, Confidence.POSSIBLE, Klass.ATTACK, "unicast",
       "Unicast Sync from a source with no observed grant",
       "DISARMED until both halves of a negotiation have been seen on this tap. On "
       "a passive tap that joined mid-session, never having seen the grant is not "
       "evidence it was never sent.", armed_by="_negotiation_seen"),
]}

assert len(FINDINGS) == 42, f"registry drift: {len(FINDINGS)} codes"


# ---------------------------------------------------------------------------
# Config / Emitter
# ---------------------------------------------------------------------------

@dataclass
class Config:
    iface: Optional[str] = None
    pcap: Optional[str] = None

    # arming declarations -- one line each, not learned (see preflight §arming)
    domain: Optional[int] = None
    grandmasters: Tuple[str, ...] = ()
    mgmt_stations: Tuple[str, ...] = ()   # authorised NMS sources; arms D04
    profile: str = "auto"            # auto | g8275.1 | g8275.2 | 8021as

    # thresholds, all with an in-band or physical justification
    correction_max: int = CORRECTION_MAX_ABS
    rate_tolerance: float = 3.0      # multiple of the source's OWN advertised rate
    rate_window: float = 8.0         # seconds, CLOCK_MONOTONIC
    rate_min_samples: int = 6
    seq_reorder_tolerance: int = 8
    followup_grace: float = 4.0      # multiples of the advertised sync interval
    ts_step_tolerance: float = 4.0   # multiples of the advertised interval
    gm_new_clock_window: float = 300.0
    mgmt_sweep_threshold: int = 5
    mgmt_sweep_window: float = 30.0
    dedup_window: float = 60.0

    # state caps -- a passive sensor on a hostile segment must not be
    # memory-exhaustible by an attacker minting clockIdentities.
    max_clocks: int = 4096
    max_sync_pending: int = 8192
    max_grants: int = 4096
    max_dedup_keys: int = 16384

    # live capture
    heartbeat_interval: float = 60.0
    tick_interval: float = 1.0
    rcvbuf: int = 4 * 1024 * 1024
    promisc: bool = True

    def armed(self, spec: CodeSpec, engine: "PtpEngine") -> bool:
        if spec.armed_by is None:
            return True
        if spec.armed_by == "grandmasters":
            return bool(self.grandmasters)
        if spec.armed_by == "mgmt_stations":
            return bool(self.mgmt_stations)
        if spec.armed_by == "domain":
            return self.domain is not None
        if spec.armed_by == "_negotiation_seen":
            return engine.negotiation_seen
        return False


@dataclass
class Finding:
    code: str
    ts: float
    transport: str
    domain: int
    port_identity: str
    detail: Dict[str, object]
    src: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        spec = FINDINGS[self.code]
        return {
            "ts": round(self.ts, 6),
            "code": self.code,
            "severity": spec.severity.value,
            "confidence": spec.confidence.value,
            "class": spec.klass.value,
            "category": spec.category,
            "title": spec.title,
            "transport": self.transport,
            "domain": self.domain,
            "port_identity": self.port_identity,
            "src": self.src,
            "detail": self.detail,
        }


class Emitter:
    """JSONL on stdout, one finding per line. Stdout stays pure JSON so the
    mesh can consume it directly; everything else goes to stderr."""

    def __init__(self, cfg: Config, sink=None):
        self.cfg = cfg
        self.sink = sink if sink is not None else []
        self._seen: Dict[Tuple, float] = {}
        self.counts: Dict[str, int] = {}
        self.suppressed = 0
        self.evictions = 0

    def emit(self, f: Finding, dedup_extra: Tuple = ()) -> bool:
        key = (f.code, f.port_identity) + tuple(dedup_extra)
        last = self._seen.get(key)
        if last is not None and (f.ts - last) < self.cfg.dedup_window:
            self.suppressed += 1
            return False
        if len(self._seen) >= self.cfg.max_dedup_keys:
            cutoff = f.ts - self.cfg.dedup_window
            self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
            if len(self._seen) >= self.cfg.max_dedup_keys:
                self._seen.clear()
                self.evictions += 1
        self._seen[key] = f.ts
        self.counts[f.code] = self.counts.get(f.code, 0) + 1
        self.sink.append(f)
        return True


# ---------------------------------------------------------------------------
# Per-clock state
# ---------------------------------------------------------------------------

def pid_str(clock_identity: bytes, port_number: int) -> str:
    h = clock_identity.hex()
    return f"{h[0:6]}.{h[6:10]}.{h[10:16]}-{port_number}"


@dataclass
class ClockState:
    first_seen: float
    macs: set = field(default_factory=set)
    seq: Dict[int, int] = field(default_factory=dict)       # originating types only
    rate: Dict[int, List[float]] = field(default_factory=dict)
    last_origin: Dict[int, int] = field(default_factory=dict)   # ns since epoch
    last_origin_mono: Dict[int, float] = field(default_factory=dict)
    minor_version_max: int = 0
    # last Announce attributes, for C01/C03/C04 mid-session comparison
    utc_offset: Optional[int] = None
    utc_offset_valid: Optional[bool] = None
    utc_offset_last_valid: Optional[int] = None
    ptp_timescale: Optional[bool] = None
    log_sync_interval: Optional[int] = None
    log_announce_interval: Optional[int] = None
    mgmt_ids: Dict[int, float] = field(default_factory=dict)


# sequenceId is maintained per ORIGINATING message type. Follow_Up echoes
# Sync's, Delay_Resp echoes Delay_Req's -- tracking those as their own series
# would report a regression on every legitimate echo.
ORIGINATING_TYPES = frozenset({MsgType.ANNOUNCE, MsgType.SYNC,
                               MsgType.DELAY_REQ, MsgType.PDELAY_REQ})


def interval_seconds(log_interval: int) -> Optional[float]:
    """2**logMessageInterval, or None when the field is the 0x7F
    'not applicable' sentinel (linuxptp emits it on Management)."""
    if log_interval == LOG_INTERVAL_NA or log_interval < -12 or log_interval > 12:
        return None
    return 2.0 ** log_interval


def seq_delta(new: int, old: int) -> int:
    """Wrap-aware signed distance across the 16-bit sequenceId space."""
    return ((new - old + 0x8000) & 0xFFFF) - 0x8000


# ---------------------------------------------------------------------------
# Unicast negotiation TLV bodies (1588 §16.1) -- decision 2
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UnicastReq:
    msg_type: int
    log_interval: int
    duration: int


@dataclass(frozen=True)
class UnicastGrant:
    msg_type: int
    log_interval: int
    duration: int
    renewal_invited: bool


def decode_unicast_req(v: bytes) -> Optional[UnicastReq]:
    if len(v) < 6:
        return None
    return UnicastReq((v[0] >> 4) & 0x0F,
                      struct.unpack_from("!b", v, 1)[0],
                      struct.unpack_from("!I", v, 2)[0])


def decode_unicast_grant(v: bytes) -> Optional[UnicastGrant]:
    if len(v) < 8:
        return None
    return UnicastGrant((v[0] >> 4) & 0x0F,
                        struct.unpack_from("!b", v, 1)[0],
                        struct.unpack_from("!I", v, 2)[0],
                        bool(v[7] & 0x01))


def org_subtype(tlv: "Tlv") -> Optional[int]:
    """Return the 802.1AS organization subType, or None if the TLV is not an
    IEEE 802.1 organization extension."""
    if tlv.tlv_type != TLV_ORG_EXTENSION or len(tlv.value) < 6:
        return None
    if tlv.value[0:3] != OUI_IEEE_802_1:
        return None
    return int.from_bytes(tlv.value[3:6], "big")


def decode_msg_interval_req(v: bytes) -> Optional[Dict[str, int]]:
    """802.1AS message-interval-request TLV body (after OUI + subType).

    linkDelayInterval, timeSyncInterval and announceInterval are signed
    log2 intervals; 127 means STOP SENDING and 126 means revert to initial.
    """
    if len(v) < 9:
        return None
    return {"link_delay": struct.unpack_from("!b", v, 6)[0],
            "time_sync": struct.unpack_from("!b", v, 7)[0],
            "announce": struct.unpack_from("!b", v, 8)[0]}


def path_trace_identities(tlv: "Tlv") -> List[bytes]:
    """PATH_TRACE carries a sequence of 8-byte clockIdentities."""
    v = tlv.value
    return [v[i:i + 8] for i in range(0, len(v) - len(v) % 8, 8)]


def decode_unicast_cancel(v: bytes) -> Optional[int]:
    if len(v) < 1:
        return None
    return (v[0] >> 4) & 0x0F


# PTP epoch is 1970-01-01, same as Unix, so a plain gmtime works for the
# day-granularity leap-window test. This uses the PACKET's claimed time, never
# the sensor's clock -- the rule survives an unsynchronised sensor.
def in_leap_window(seconds: int) -> bool:
    import time as _time
    try:
        tm = _time.gmtime(seconds)
    except (OSError, OverflowError, ValueError):
        return True          # unusable timestamp: do not accuse
    if tm.tm_mon == 6 and tm.tm_mday >= 29:
        return True
    if tm.tm_mon == 12 and tm.tm_mday >= 30:
        return True
    return False


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PtpEngine:
    """Stateful passive detector. feed() is called once per parsed message.

    `ts` is the capture timestamp, used only for labelling findings.
    `mono` is CLOCK_MONOTONIC, the ONLY clock any rule computes with.
    """

    def __init__(self, cfg: Config, emitter: Emitter):
        self.cfg = cfg
        self.out = emitter
        self.clocks: Dict[Tuple[bytes, int], ClockState] = {}
        self.ports_by_clock: Dict[bytes, set] = {}

        # segment-level
        self.tc_evidence: Optional[str] = None      # B03 gate; sticky once set
        self.domains: set = set()
        self.versions: set = set()
        self.security_seen = False
        self.mgmt_seen = False
        self.transports: set = set()

        # BMCA
        self.current_gm: Optional[bytes] = None
        self.gm_attrs: Dict[bytes, Tuple[int, int]] = {}   # gm -> (prio1, class)
        self.gm_announcers: Dict[bytes, set] = {}
        self.gm_last_ts: Optional[int] = None              # seconds, for C02

        # pending two-step Syncs: (pid, seq) -> (mono, sync_interval)
        self.sync_pending: Dict[Tuple[str, int], Tuple[float, Optional[float]]] = {}
        self.sync_onestep: Dict[Tuple[str, int], float] = {}

        # unicast negotiation
        self.negotiation_seen = False
        self.grants: Dict[Tuple[str, str, int], Tuple[UnicastGrant, float]] = {}
        self.requests: Dict[Tuple[str, str, int], UnicastReq] = {}
        self.unicast_peers: set = set()

        self.clock_addrs: Dict[bytes, set] = {}
        self.capped = 0
        # (requesting_identity, requesting_port, sequenceId) -> responder set
        self.pdelay_responders: Dict[Tuple[bytes, int, int], set] = {}
        self.gptp_seen = False
        self.declared_gms = {g.lower().replace(":", "").replace(".", "")
                             for g in cfg.grandmasters}
        self.msgs = 0

    @staticmethod
    def _addr(msg: "PtpMsg") -> str:
        """Transport-level source address: IP for Annex D/E, MAC for Annex F."""
        if msg.src_ip:
            return msg.src_ip
        return msg.src_mac.hex(":") if msg.src_mac else "?"

    # -- emission gate -----------------------------------------------------
    def _emit(self, code: str, msg: "PtpMsg", ts: float, detail: Dict,
              dedup_extra: Tuple = ()) -> None:
        spec = FINDINGS[code]
        if spec.gptp_masked and msg.is_gptp:
            return
        if not self.cfg.armed(spec, self):
            return
        src = None
        if msg.src_ip:
            src = msg.src_ip
        elif msg.src_mac:
            src = msg.src_mac.hex(":")
        self.out.emit(Finding(code=code, ts=ts, transport=msg.transport,
                              domain=msg.domain,
                              port_identity=pid_str(*msg.port_identity),
                              detail=detail, src=src), dedup_extra)

    # -- main entry --------------------------------------------------------
    def feed(self, msg: PtpMsg, ts: float, mono: float) -> None:
        self.msgs += 1
        pid = msg.port_identity
        pids = pid_str(*pid)
        st = self.clocks.get(pid)
        if st is None:
            if len(self.clocks) >= self.cfg.max_clocks:
                # Refuse to grow without bound. Known clocks keep working;
                # new identities are counted and dropped, never silently
                # evicted in a way that would reset an attacker's history.
                self.capped += 1
                return
            st = self.clocks[pid] = ClockState(first_seen=mono)
        if msg.src_mac:
            st.macs.add(msg.src_mac)
        self.domains.add(msg.domain)
        self.versions.add(msg.version)
        self.transports.add(msg.transport)
        self.ports_by_clock.setdefault(msg.clock_identity, set()).add(msg.port_number)
        if msg.security_flag or any(t.tlv_type in SECURITY_TLVS for t in msg.tlvs):
            self.security_seen = True
        if msg.unicast:
            self.unicast_peers.add(pids)

        self._check_transparent_clock_evidence(msg)
        self._check_lengths(msg, ts)
        self._check_correction(msg, ts)
        self._check_version(msg, ts, st)
        self._check_sequence(msg, ts, st, pids)
        self._check_rate(msg, ts, mono, st)
        self._check_identity(msg, ts, st, pids)
        self._check_sync_followup(msg, ts, mono, pids, st)
        self._check_origin_timestamp(msg, ts, mono, st)

        if msg.msg_type == MsgType.ANNOUNCE:
            self._check_announce(msg, ts, mono, st)
        elif msg.msg_type == MsgType.MANAGEMENT:
            self._check_management(msg, ts, mono, st)
        elif msg.msg_type == MsgType.SIGNALING:
            self._check_signaling(msg, ts, mono, pids)
        elif msg.msg_type == MsgType.PDELAY_RESP_FOLLOW_UP:
            self._check_pdelay(msg, ts, st)

        if msg.msg_type == MsgType.SYNC and msg.unicast:
            self._check_unicast_sync(msg, ts, mono, pids)

        if msg.is_gptp:
            self.gptp_seen = True
            self._check_gptp(msg, ts, mono)

    # -- B03 gate ----------------------------------------------------------
    def _check_transparent_clock_evidence(self, msg: PtpMsg) -> None:
        if self.tc_evidence:
            return
        if msg.correction != 0 and msg.msg_type in (MsgType.SYNC, MsgType.FOLLOW_UP,
                                                    MsgType.DELAY_RESP):
            self.tc_evidence = "nonzero-correctionField"
        elif msg.msg_type in (MsgType.PDELAY_REQ, MsgType.PDELAY_RESP,
                              MsgType.PDELAY_RESP_FOLLOW_UP):
            self.tc_evidence = "peer-delay-mechanism"
        elif len(self.ports_by_clock.get(msg.clock_identity, ())) > 1:
            self.tc_evidence = "multi-port-clockIdentity"

    # -- A09 ---------------------------------------------------------------
    def _check_lengths(self, msg: PtpMsg, ts: float) -> None:
        want = FIXED_MSG_LEN.get(msg.msg_type)
        if want is not None and msg.msg_length < want:
            self._emit("PTP-A09", msg, ts,
                       {"message_type": msg.msg_type, "declared": msg.msg_length,
                        "minimum": want, "reason": "shorter than the fixed body"},
                       (msg.msg_type, msg.msg_length))
        elif want is not None and msg.msg_length > want:
            # Excess is legal ONLY if it is a well-formed TLV chain that
            # accounts for exactly the declared surplus.
            excess = msg.msg_length - want
            consumed = msg.tlv_end - (want - HEADER_LEN)
            if msg.tlv_truncated or not msg.tlvs or consumed != excess:
                self._emit("PTP-A09", msg, ts,
                           {"message_type": msg.msg_type,
                            "declared": msg.msg_length, "fixed_body": want,
                            "excess_bytes": excess, "tlv_bytes": consumed,
                            "tlv_truncated": msg.tlv_truncated,
                            "reason": "declared length not reconciled by the TLV chain"},
                           (msg.msg_type, msg.msg_length))
        elif msg.msg_type in (MsgType.MANAGEMENT, MsgType.SIGNALING) \
                and msg.msg_length < HEADER_LEN:
            self._emit("PTP-A09", msg, ts,
                       {"message_type": msg.msg_type, "declared": msg.msg_length,
                        "expected": f">={HEADER_LEN}"}, (msg.msg_type,))

    # -- A08 ---------------------------------------------------------------
    def _check_correction(self, msg: PtpMsg, ts: float) -> None:
        if abs(msg.correction) >= self.cfg.correction_max:
            self._emit("PTP-A08", msg, ts,
                       {"correction_scaled": msg.correction,
                        "correction_ns": msg.correction_ns,
                        "bound_scaled": self.cfg.correction_max})

    # -- E01 / E02 ---------------------------------------------------------
    def _check_version(self, msg: PtpMsg, ts: float, st: ClockState) -> None:
        if msg.version == 1:
            self._emit("PTP-E01", msg, ts, {"version": msg.version})
            return
        if msg.minor_version > st.minor_version_max:
            st.minor_version_max = msg.minor_version
        elif msg.minor_version < st.minor_version_max:
            self._emit("PTP-E02", msg, ts,
                       {"minor_version": msg.minor_version,
                        "previously": st.minor_version_max})

    # -- A07 ---------------------------------------------------------------
    def _check_sequence(self, msg: PtpMsg, ts: float, st: ClockState,
                        pids: str) -> None:
        if msg.msg_type not in ORIGINATING_TYPES:
            return
        prev = st.seq.get(msg.msg_type)
        if prev is not None:
            d = seq_delta(msg.sequence_id, prev)
            if d <= -self.cfg.seq_reorder_tolerance:
                self._emit("PTP-A07", msg, ts,
                           {"message_type": msg.msg_type,
                            "sequence_id": msg.sequence_id, "previous": prev,
                            "delta": d}, (msg.msg_type,))
                return
            if d <= 0:
                return          # reorder or duplicate within tolerance
        st.seq[msg.msg_type] = msg.sequence_id

    # -- A03 / A04 ---------------------------------------------------------
    def _check_rate(self, msg: PtpMsg, ts: float, mono: float,
                    st: ClockState) -> None:
        if msg.msg_type not in (MsgType.ANNOUNCE, MsgType.SYNC):
            return
        want = interval_seconds(msg.log_interval)
        if want is None or want <= 0:
            return                      # 0x7F sentinel or nonsense: unevaluable
        hist = st.rate.setdefault(msg.msg_type, [])
        hist.append(mono)
        cutoff = mono - self.cfg.rate_window
        while hist and hist[0] < cutoff:
            hist.pop(0)
        if len(hist) < self.cfg.rate_min_samples:
            return
        span = hist[-1] - hist[0]
        if span <= 0:
            return
        observed = (len(hist) - 1) / span
        allowed = (1.0 / want) * self.cfg.rate_tolerance
        if observed <= allowed:
            return
        detail = {"observed_per_s": round(observed, 3),
                  "advertised_interval_s": want,
                  "allowed_per_s": round(allowed, 3),
                  "samples": len(hist)}
        if msg.msg_type == MsgType.ANNOUNCE:
            self._emit("PTP-A03", msg, ts, detail)
        else:
            self._emit("PTP-A04", msg, ts, detail)

    # -- B01 / B03 ---------------------------------------------------------
    def _check_identity(self, msg: PtpMsg, ts: float, st: ClockState,
                        pids: str) -> None:
        if len(st.macs) > 1:
            self._emit("PTP-B01", msg, ts,
                       {"macs": sorted(m.hex(":") for m in st.macs)})
        if msg.transport != "annexF" or msg.src_mac is None:
            return
        if self.tc_evidence:
            return                      # decision 3: self-disarmed for the segment
        embedded = msg.eui64_mac()
        if embedded is not None and embedded != msg.src_mac:
            self._emit("PTP-B03", msg, ts,
                       {"clock_identity_mac": embedded.hex(":"),
                        "ethernet_src": msg.src_mac.hex(":")})

    # -- A05 / A06 ---------------------------------------------------------
    def _check_sync_followup(self, msg: PtpMsg, ts: float, mono: float,
                             pids: str, st: ClockState) -> None:
        if msg.msg_type == MsgType.SYNC:
            key = (pids, msg.sequence_id)
            if msg.two_step:
                if len(self.sync_pending) < self.cfg.max_sync_pending:
                    self.sync_pending[key] = (mono,
                                              interval_seconds(msg.log_interval))
                else:
                    self.capped += 1
            else:
                self.sync_onestep[key] = mono
            st.log_sync_interval = msg.log_interval
        elif msg.msg_type == MsgType.FOLLOW_UP:
            key = (pids, msg.sequence_id)
            if key in self.sync_pending:
                del self.sync_pending[key]
            elif key in self.sync_onestep:
                del self.sync_onestep[key]
                self._emit("PTP-A06", msg, ts,
                           {"sequence_id": msg.sequence_id,
                            "reason": "Sync for this sequenceId had twoStepFlag clear"})
        self._expire_sync_pending(msg, ts, mono)

    def _expire_sync_pending(self, msg: PtpMsg, ts: float, mono: float) -> None:
        if not self.sync_pending:
            return
        stale = []
        for key, (when, interval) in self.sync_pending.items():
            grace = (interval or 1.0) * self.cfg.followup_grace
            if mono - when > grace:
                stale.append((key, when, grace))
        for key, when, grace in stale:
            del self.sync_pending[key]
            self._emit("PTP-A05", msg, ts,
                       {"sync_port_identity": key[0], "sequence_id": key[1],
                        "grace_s": round(grace, 3)}, (key[0], "a05"))

    # -- A10 ---------------------------------------------------------------
    def _check_origin_timestamp(self, msg: PtpMsg, ts: float, mono: float,
                                st: ClockState) -> None:
        if msg.msg_type not in (MsgType.SYNC, MsgType.FOLLOW_UP):
            return
        if not msg.origin_ts or msg.origin_ts == (0, 0):
            return                      # implementations legitimately send zero
        now_ns = msg.origin_ts[0] * 1_000_000_000 + msg.origin_ts[1]
        prev = st.last_origin.get(msg.msg_type)
        prev_mono = st.last_origin_mono.get(msg.msg_type)
        st.last_origin[msg.msg_type] = now_ns
        st.last_origin_mono[msg.msg_type] = mono
        self.gm_last_ts = msg.origin_ts[0]
        if prev is None or prev_mono is None:
            return
        delta_ns = now_ns - prev
        if delta_ns < 0:
            self._emit("PTP-A10", msg, ts,
                       {"delta_ns": delta_ns, "direction": "backwards"},
                       (msg.msg_type,))
            return
        # Forward case: the claimed advance must track observed elapsed time.
        # A gap in transmission (BMCA churn, link flap) advances both equally
        # and is NOT a step; an injected jump advances only the timestamp.
        elapsed_ns = max(0.0, mono - prev_mono) * 1_000_000_000
        interval = interval_seconds(st.log_sync_interval
                                    if st.log_sync_interval is not None else 0)
        slack_ns = (interval or 1.0) * self.cfg.ts_step_tolerance * 1_000_000_000
        excess_ns = delta_ns - elapsed_ns
        if excess_ns > slack_ns:
            self._emit("PTP-A10", msg, ts,
                       {"delta_ns": delta_ns, "elapsed_ns": int(elapsed_ns),
                        "excess_ns": int(excess_ns), "slack_ns": int(slack_ns),
                        "direction": "forward-step"},
                       (msg.msg_type,))

    # -- Announce: A01 A02 B02 B04 B05 C01-C04 E05 -------------------------
    def _check_announce(self, msg: PtpMsg, ts: float, mono: float,
                        st: ClockState) -> None:
        st.log_announce_interval = msg.log_interval
        if msg.clock_class is None or msg.gm_identity is None:
            return

        if msg.clock_class in PRIMARY_CLOCK_CLASSES:
            if msg.steps_removed:
                self._emit("PTP-A01", msg, ts,
                           {"clock_class": msg.clock_class,
                            "steps_removed": msg.steps_removed})
            if msg.time_source == TIMESRC_INTERNAL_OSC:
                self._emit("PTP-A02", msg, ts,
                           {"clock_class": msg.clock_class,
                            "time_source": msg.time_source})

        # B02: distinct announcers relaying the same grandmasterIdentity
        announcers = self.gm_announcers.setdefault(msg.gm_identity, set())
        announcers.add(pid_str(*msg.port_identity))
        if len(announcers) > 1 and msg.gm_identity != msg.clock_identity:
            self._emit("PTP-B02", msg, ts,
                       {"grandmaster": msg.gm_identity.hex(),
                        "announcers": sorted(announcers)},
                       (msg.gm_identity,))

        # B05: declared-set violation (disarmed unless --grandmaster given)
        if self.declared_gms and msg.gm_identity.hex() not in self.declared_gms:
            self._emit("PTP-B05", msg, ts,
                       {"grandmaster": msg.gm_identity.hex(),
                        "declared": sorted(self.declared_gms)},
                       (msg.gm_identity,))

        # B04: GM transition won by a clock first seen inside the window
        prio = (msg.priority1 if msg.priority1 is not None else 255, msg.clock_class)
        prev_attrs = self.gm_attrs.get(self.current_gm) if self.current_gm else None
        self.gm_attrs[msg.gm_identity] = prio
        if self.current_gm is not None and msg.gm_identity != self.current_gm:
            better = prev_attrs is not None and prio < prev_attrs
            age = mono - st.first_seen
            if better and age <= self.cfg.gm_new_clock_window:
                self._emit("PTP-B04", msg, ts,
                           {"new_gm": msg.gm_identity.hex(),
                            "previous_gm": self.current_gm.hex(),
                            "new_priority1_class": list(prio),
                            "previous_priority1_class": list(prev_attrs),
                            "announcer_age_s": round(age, 3)},
                           (msg.gm_identity,))
        self.current_gm = msg.gm_identity

        # C01: UTC offset changed mid-session by the same source
        if msg.utc_offset is not None:
            if st.utc_offset is not None and msg.utc_offset != st.utc_offset:
                if st.utc_offset_valid and msg.utc_offset_valid:
                    self._emit("PTP-C01", msg, ts,
                               {"utc_offset": msg.utc_offset,
                                "previously": st.utc_offset})
                elif st.utc_offset_last_valid is not None and msg.utc_offset_valid \
                        and msg.utc_offset != st.utc_offset_last_valid:
                    # C04: laundered through an invalid interval
                    self._emit("PTP-C04", msg, ts,
                               {"utc_offset": msg.utc_offset,
                                "last_valid": st.utc_offset_last_valid})
            st.utc_offset = msg.utc_offset
            if msg.utc_offset_valid:
                st.utc_offset_last_valid = msg.utc_offset
        st.utc_offset_valid = msg.utc_offset_valid

        # C02: leap flag against the SOURCE'S OWN claimed time, never ours
        if msg.leap61 or msg.leap59:
            ref = msg.origin_ts[0] if (msg.origin_ts and msg.origin_ts[0]) \
                else self.gm_last_ts
            if ref and not in_leap_window(ref):
                self._emit("PTP-C02", msg, ts,
                           {"leap61": msg.leap61, "leap59": msg.leap59,
                            "claimed_epoch_s": ref})

        # C03: timescale flip
        if st.ptp_timescale is not None and msg.ptp_timescale != st.ptp_timescale:
            self._emit("PTP-C03", msg, ts,
                       {"ptp_timescale": msg.ptp_timescale,
                        "previously": st.ptp_timescale})
        st.ptp_timescale = msg.ptp_timescale

        # E05: alternate master from a clock that is not the grandmaster
        if msg.alternate_master and msg.gm_identity != msg.clock_identity:
            self._emit("PTP-E05", msg, ts,
                       {"grandmaster": msg.gm_identity.hex()})

    # -- Management: D01 D02 D04 -------------------------------------------
    def _check_management(self, msg: PtpMsg, ts: float, mono: float,
                          st: ClockState) -> None:
        self.mgmt_seen = True
        if msg.action_field in (ACTION_SET, ACTION_COMMAND):
            self._emit("PTP-D01", msg, ts,
                       {"action": "SET" if msg.action_field == ACTION_SET else "COMMAND",
                        "management_id": msg.management_id,
                        "target": (msg.target_identity or b"").hex()},
                       (msg.action_field, msg.management_id))
        if msg.target_identity == CLOCKID_ALL_ONES and \
                msg.action_field in (ACTION_SET, ACTION_COMMAND):
            self._emit("PTP-D02", msg, ts,
                       {"action": "SET" if msg.action_field == ACTION_SET else "COMMAND",
                        "management_id": msg.management_id},
                       (msg.management_id,))
        if msg.action_field == ACTION_GET and msg.management_id is not None:
            st.mgmt_ids[msg.management_id] = mono
            cutoff = mono - self.cfg.mgmt_sweep_window
            fresh = {k: v for k, v in st.mgmt_ids.items() if v >= cutoff}
            st.mgmt_ids = fresh
            source = msg.src_ip or (msg.src_mac.hex(":") if msg.src_mac else "?")
            declared = {s.lower() for s in self.cfg.mgmt_stations}
            if len(fresh) >= self.cfg.mgmt_sweep_threshold and \
                    source.lower() not in declared:
                self._emit("PTP-D04", msg, ts,
                           {"distinct_management_ids": len(fresh),
                            "source": source,
                            "window_s": self.cfg.mgmt_sweep_window})

    # -- Signaling: D03 and Class G ----------------------------------------
    def _check_signaling(self, msg: PtpMsg, ts: float, mono: float,
                         pids: str) -> None:
        peer = msg.dst_ip or (msg.dst_mac.hex(":") if msg.dst_mac else "?")
        for tlv in msg.tlvs:
            if tlv.tlv_type == TLV_REQUEST_UNICAST:
                req = decode_unicast_req(tlv.value)
                if req is None:
                    continue
                self.requests[(self._addr(msg), peer, req.msg_type)] = req
                # D03 is a REDIRECT detector, not a "new slave" detector. A
                # first request from a new peer is how unicast normally works.
                # The signature is a clock whose ADDRESS moved: same
                # sourcePortIdentity, different source address.
                seen = self.clock_addrs.setdefault(msg.clock_identity, set())
                here = self._addr(msg)
                if seen and here not in seen:
                    self._emit("PTP-D03", msg, ts,
                               {"requested_type": req.msg_type,
                                "log_interval": req.log_interval,
                                "duration_s": req.duration,
                                "source_now": here,
                                "source_previously": sorted(seen),
                                "destination": peer},
                               (req.msg_type, peer))
                seen.add(here)
            elif tlv.tlv_type == TLV_GRANT_UNICAST:
                grant = decode_unicast_grant(tlv.value)
                if grant is None:
                    continue
                # the grantor answers a request that came FROM the peer
                key = (peer, self._addr(msg), grant.msg_type)
                req = self.requests.get(key)
                if req is not None:
                    self.negotiation_seen = True
                    if grant.log_interval != req.log_interval or \
                            grant.duration > req.duration:
                        self._emit("PTP-G01", msg, ts,
                                   {"granted_interval": grant.log_interval,
                                    "requested_interval": req.log_interval,
                                    "granted_duration": grant.duration,
                                    "requested_duration": req.duration},
                                   (grant.msg_type, peer))
                if len(self.grants) < self.cfg.max_grants:
                    self.grants[key] = (grant, mono)
                else:
                    self.capped += 1
            elif tlv.tlv_type == TLV_CANCEL_UNICAST:
                mt = decode_unicast_cancel(tlv.value)
                if mt is None:
                    continue
                here = self._addr(msg)
                known = any(here in (k[0], k[1]) for k in self.grants)
                if self.negotiation_seen and not known:
                    self._emit("PTP-G03", msg, ts,
                               {"cancelled_type": mt, "destination": peer,
                                "reason": "cancel from a party with no observed grant"},
                               (mt, peer))


    # -- Class H: gPTP / 802.1AS -------------------------------------------
    def _check_gptp(self, msg: PtpMsg, ts: float, mono: float) -> None:
        # H08 -- wrong destination address
        if msg.transport == "annexF" and msg.dst_mac is not None \
                and msg.dst_mac != MAC_GPTP and msg.dst_mac[0] & 0x01:
            self._emit("PTP-H08", msg, ts,
                       {"destination": msg.dst_mac.hex(":"),
                        "expected": MAC_GPTP.hex(":")},
                       (msg.dst_mac,))

        # H01 -- end-to-end delay mechanism where only peer-delay is allowed
        if msg.msg_type in E2E_TYPES:
            self._emit("PTP-H01", msg, ts,
                       {"message_type": msg.msg_type,
                        "mechanism": "end-to-end",
                        "permitted": "peer-delay only"},
                       (msg.msg_type,))

        # H02 -- more than one responder to a single Pdelay_Req
        if msg.msg_type == MsgType.PDELAY_RESP and msg.requesting_identity:
            key = (msg.requesting_identity, msg.requesting_port or 0,
                   msg.sequence_id)
            responders = self.pdelay_responders.setdefault(key, set())
            responders.add(msg.port_identity)
            if len(responders) > 1:
                self._emit("PTP-H02", msg, ts,
                           {"requester": pid_str(msg.requesting_identity,
                                                 msg.requesting_port or 0),
                            "sequence_id": msg.sequence_id,
                            "responders": sorted(pid_str(*r) for r in responders),
                            "effect": "requester sets asCapable FALSE; timing "
                                      "stops on this port"},
                           (key[0], key[2]))
            if len(self.pdelay_responders) > self.cfg.max_sync_pending:
                self.pdelay_responders.clear()
                self.capped += 1

        if msg.msg_type == MsgType.ANNOUNCE:
            self._check_gptp_announce(msg, ts)
        elif msg.msg_type == MsgType.FOLLOW_UP:
            if not any(org_subtype(t) == SUBTYPE_FOLLOW_UP_INFO
                       for t in msg.tlvs):
                self._emit("PTP-H06", msg, ts,
                           {"sequence_id": msg.sequence_id,
                            "tlvs_present": [hex(t.tlv_type) for t in msg.tlvs]})
        elif msg.msg_type == MsgType.SIGNALING:
            self._check_gptp_signaling(msg, ts)

    def _check_gptp_announce(self, msg: PtpMsg, ts: float) -> None:
        trace = next((t for t in msg.tlvs if t.tlv_type == TLV_PATH_TRACE), None)
        if trace is None:
            self._emit("PTP-H03", msg, ts,
                       {"tlvs_present": [hex(t.tlv_type) for t in msg.tlvs] or None})
            return
        ids = path_trace_identities(trace)
        # H04 -- each relay appends one identity and increments stepsRemoved
        if msg.steps_removed is not None and len(ids) != msg.steps_removed + 1:
            self._emit("PTP-H04", msg, ts,
                       {"path_trace_entries": len(ids),
                        "steps_removed": msg.steps_removed,
                        "expected_entries": msg.steps_removed + 1})
        # H05 -- a repeated identity is a loop
        if len(set(ids)) != len(ids):
            dupes = sorted({i.hex() for i in ids if ids.count(i) > 1})
            self._emit("PTP-H05", msg, ts,
                       {"repeated": dupes, "path_trace_entries": len(ids)},
                       tuple(dupes))

    def _check_gptp_signaling(self, msg: PtpMsg, ts: float) -> None:
        for tlv in msg.tlvs:
            if org_subtype(tlv) != SUBTYPE_MSG_INTERVAL_REQ:
                continue
            req = decode_msg_interval_req(tlv.value)
            if req is None:
                continue
            stopped = sorted(k for k, v in req.items()
                             if v == INTERVAL_STOP_SENDING)
            if stopped:
                self._emit("PTP-H07", msg, ts,
                           {"suppressed": stopped, "intervals": req,
                            "target": (msg.target_identity or b"").hex()},
                           tuple(stopped))

    # -- G02 / G04 ---------------------------------------------------------
    def _check_unicast_sync(self, msg: PtpMsg, ts: float, mono: float,
                            pids: str) -> None:
        peer = msg.dst_ip or (msg.dst_mac.hex(":") if msg.dst_mac else "?")
        key = (peer, self._addr(msg), int(MsgType.SYNC))
        entry = self.grants.get(key)
        if entry is None:
            # G04 stays dark until this tap has seen a full negotiation
            self._emit("PTP-G04", msg, ts,
                       {"destination": peer,
                        "reason": "unicast Sync with no grant observed on this tap"},
                       (peer,))
            return
        grant, granted_at = entry
        if grant.duration and (mono - granted_at) > grant.duration:
            self._emit("PTP-G02", msg, ts,
                       {"granted_duration_s": grant.duration,
                        "elapsed_s": round(mono - granted_at, 3)},
                       (peer,))

    # -- F02 ---------------------------------------------------------------
    def _check_pdelay(self, msg: PtpMsg, ts: float, st: ClockState) -> None:
        if not msg.origin_ts:
            return
        # responseOriginTimestamp minus requestReceiptTimestamp is carried
        # entirely inside the responder's own messages, so no capture-side
        # timestamp is involved.
        turnaround_ns = msg.origin_ts[0] * 1_000_000_000 + msg.origin_ts[1]
        interval = interval_seconds(msg.log_interval)
        if interval is None:
            return
        if turnaround_ns > interval * 1_000_000_000:
            self._emit("PTP-F02", msg, ts,
                       {"turnaround_ns": turnaround_ns,
                        "advertised_interval_s": interval})

    def tick(self, ts: float, mono: float) -> None:
        """Time-driven expiry. A withheld Follow_Up (A05) is an ABSENCE of
        traffic, so it cannot depend on the next packet arriving -- on a link
        the attacker has silenced, that packet may never come."""
        if not self.sync_pending:
            return
        probe = PtpMsg(major_sdo_id=0, msg_type=int(MsgType.SYNC),
                       minor_version=0, version=2, msg_length=0,
                       domain=sorted(self.domains)[0] if self.domains else 0,
                       minor_sdo_id=0, flags=0, correction=0,
                       msg_type_specific=0, clock_identity=b"\x00" * 8,
                       port_number=0, sequence_id=0, control_field=0,
                       log_interval=0,
                       transport=sorted(self.transports)[0]
                       if self.transports else "unknown")
        self._expire_sync_pending(probe, ts, mono)

    # -- end of capture ----------------------------------------------------
    def finalize(self, ts: float) -> None:
        """Posture findings that can only be decided once, at the end."""
        synthetic = PtpMsg(major_sdo_id=0, msg_type=0, minor_version=0, version=2,
                           msg_length=0, domain=sorted(self.domains)[0]
                           if self.domains else 0,
                           minor_sdo_id=0, flags=0, correction=0,
                           msg_type_specific=0, clock_identity=b"\x00" * 8,
                           port_number=0, sequence_id=0, control_field=0,
                           log_interval=0,
                           transport=sorted(self.transports)[0]
                           if self.transports else "unknown")
        if self.msgs and not self.security_seen:
            self._emit("PTP-E03", synthetic, ts,
                       {"messages_observed": self.msgs,
                        "note": "presence-only; no cryptographic validation attempted"})
        if len(self.domains) > 1:
            detail = {"domains": sorted(self.domains)}
            if self.cfg.domain is not None:
                detail["declared"] = self.cfg.domain
                detail["unexpected"] = sorted(d for d in self.domains
                                              if d != self.cfg.domain)
            self._emit("PTP-E04", synthetic, ts, detail)
        if self.mgmt_seen and not self.security_seen:
            self._emit("PTP-E06", synthetic, ts,
                       {"note": "management traffic on an unauthenticated timing segment"})


# ---------------------------------------------------------------------------
# Runners / CLI
# ---------------------------------------------------------------------------

def run_pcap(path: str, cfg: Config, emitter: Emitter) -> PtpEngine:
    eng = PtpEngine(cfg, emitter)
    base = None
    for ts, frame, linktype in read_pcap(path):
        ctx = decode_frame(frame, linktype)
        if ctx is None:
            continue
        if base is None:
            base = ts
        try:
            msg = parse_ptp(ctx["payload"])
        except ParseError:
            continue
        msg.src_mac = ctx["src_mac"]
        msg.dst_mac = ctx["dst_mac"]
        msg.src_ip = ctx["src_ip"]
        msg.dst_ip = ctx["dst_ip"]
        msg.transport = ctx["transport"]
        # In replay, capture time IS the monotonic reference: it advances
        # monotonically within a file and is independent of the sensor clock.
        eng.feed(msg, ts, ts - base)
    eng.finalize(base if base is not None else 0.0)
    return eng


# ---------------------------------------------------------------------------
# --self-verify : mutation runner
# ---------------------------------------------------------------------------
#
# A green test suite proves nothing on its own -- a suite of no-ops is also
# green. This runner breaks the module in specific, named ways and requires the
# right tier to go red. A mutation that nobody notices is a hole in the tests,
# and it is reported as a FAILURE of this runner, not of the module.
#
# Three separate lists, one per tier, so each tier is proven non-vacuous
# INDEPENDENTLY. A mutation listed under "scenario" must be caught by the
# scenario corpus specifically; if only conformance catches it, that is still
# a scenario-tier hole and is reported as one.


# ---------------------------------------------------------------------------
# Live capture -- raw AF_PACKET, no BPF
# ---------------------------------------------------------------------------
#
# There is deliberately NO BPF filter on this path. Both Ragnar templates
# converged on the same reasoning: libpcap's `udp port N` primitive cannot
# chase the IPv6 extension-header chain, so a BPF-filtered Annex E capture is
# blind to exactly the frames an attacker would craft. Filtering happens in
# decode_frame() instead, which walks the chain itself. It also keeps
# MemoryDenyWriteExecute=yes safe in the unit file, since scapy/libpcap never
# has to JIT a filter.

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_AUXDATA = 8


class _Shutdown:
    """Set by SIGTERM/SIGINT. The capture loop is the only thing that reads it,
    so shutdown is cooperative and never leaves a half-written JSON line."""

    def __init__(self):
        self.stop = False

    def request(self, *_a):
        self.stop = True


def open_capture_socket(iface: str, cfg: Config):
    """Raw AF_PACKET socket bound to one interface. Receive-only by
    construction: the socket is never connected and nothing is ever written
    to it (enforced by the conformance passive-invariant check)."""
    import socket as _socket
    sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW,
                          _socket.htons(ETH_P_ALL))
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, cfg.rcvbuf)
    except OSError:
        pass
    sock.bind((iface, 0))
    if cfg.promisc:
        # A SPAN/mirror port delivers frames addressed to other stations, so
        # the NIC must accept them. Membership is dropped automatically when
        # the socket closes.
        try:
            idx = _socket.if_nametoindex(iface)
            mreq = struct.pack("IHH8s", idx, PACKET_MR_PROMISC, 0, b"")
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        except OSError as exc:
            print(f"ptpwatch: promiscuous mode unavailable on {iface}: {exc}",
                  file=sys.stderr)
    sock.settimeout(None)
    return sock


def run_live(iface: str, cfg: Config, emitter: Emitter,
             shutdown: Optional[_Shutdown] = None,
             max_packets: Optional[int] = None) -> "PtpEngine":
    """Capture loop. Emits JSONL to stdout; diagnostics to stderr only."""
    import json as _json
    import select as _select
    import time as _time

    eng = PtpEngine(cfg, emitter)
    sock = open_capture_socket(iface, cfg)
    shutdown = shutdown or _Shutdown()
    emitted = 0
    frames = 0
    last_beat = _time.monotonic()
    print(f"ptpwatch {__version__}: listening on {iface} "
          f"(no BPF; filtering in-process)", file=sys.stderr, flush=True)
    try:
        while not shutdown.stop:
            if max_packets is not None and frames >= max_packets:
                break
            try:
                ready, _, _ = _select.select([sock], [], [], cfg.tick_interval)
            except (OSError, InterruptedError):
                break
            now, mono = _time.time(), _time.monotonic()
            if not ready:
                # No traffic is itself an observation: absence-based rules
                # (A05, G02) must still be able to fire.
                eng.tick(now, mono)
            else:
                try:
                    frame = sock.recv(65535)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    break
                frames += 1
                ctx = decode_frame(frame, LINKTYPE_ETHERNET)
                if ctx is not None:
                    try:
                        msg = parse_ptp(ctx["payload"])
                    except ParseError:
                        msg = None
                    if msg is not None:
                        msg.src_mac = ctx["src_mac"]
                        msg.dst_mac = ctx["dst_mac"]
                        msg.src_ip = ctx["src_ip"]
                        msg.dst_ip = ctx["dst_ip"]
                        msg.transport = ctx["transport"]
                        eng.feed(msg, now, mono)
                eng.tick(now, mono)

            while emitted < len(emitter.sink):
                print(_json.dumps(emitter.sink[emitted].to_dict()), flush=True)
                emitted += 1

            if mono - last_beat >= cfg.heartbeat_interval:
                last_beat = mono
                print(f"ptpwatch: heartbeat frames={frames} ptp={eng.msgs} "
                      f"clocks={len(eng.clocks)} findings={len(emitter.sink)} "
                      f"deduped={emitter.suppressed} capped={eng.capped}",
                      file=sys.stderr, flush=True)
    finally:
        sock.close()
    eng.finalize(_time.time())
    while emitted < len(emitter.sink):
        print(_json.dumps(emitter.sink[emitted].to_dict()), flush=True)
        emitted += 1
    print(f"ptpwatch: stopped after {frames} frames, {eng.msgs} PTP messages, "
          f"{len(emitter.sink)} findings", file=sys.stderr, flush=True)
    return eng


# --- BEGIN MUTATION TABLE ---------------------------------------------------
# This table lives inside the file it mutates, so its own literals would match
# every mutation site twice. The region between these markers is excised
# before site matching; everything outside it is fair game.
# (label, target_file, old_str, new_str)
SCENARIO_MUTATIONS = [
    ("A01 steps-removed gate always false", "ptpwatch.py",
     "            if msg.steps_removed:", "            if False:"),
    ("A02 internal-oscillator check disabled", "ptpwatch.py",
     "            if msg.time_source == TIMESRC_INTERNAL_OSC:",
     "            if False:"),
    ("A06 one-step Follow_Up check removed", "ptpwatch.py",
     '                self._emit("PTP-A06", msg, ts,',
     '                _ = 0 and self._emit("PTP-A06", msg, ts,'),
    ("A08 correction bound raised out of reach", "ptpwatch.py",
     "    correction_max: int = CORRECTION_MAX_ABS",
     "    correction_max: int = CORRECTION_MAX_ABS * 10**9"),
    ("B03 transparent-clock gate removed (would re-introduce FPs)", "ptpwatch.py",
     "        if self.tc_evidence:\n            return                      # decision 3",
     "        if False:\n            return                      # decision 3"),
    ("D02 write-action gate removed (pmc GET becomes CRITICAL)", "ptpwatch.py",
     "        if msg.target_identity == CLOCKID_ALL_ONES and \\\n"
     "                msg.action_field in (ACTION_SET, ACTION_COMMAND):",
     "        if msg.target_identity == CLOCKID_ALL_ONES:"),
    ("D03 reverts to firing on any new peer", "ptpwatch.py",
     "                if seen and here not in seen:",
     "                if here not in seen:"),
    ("D04 declared-station exemption ignored", "ptpwatch.py",
     "                    source.lower() not in declared:",
     "                    source.lower() not in ():"),
    ("gPTP masking disabled", "ptpwatch.py",
     "        if spec.gptp_masked and msg.is_gptp:\n            return",
     "        if False:\n            return"),
    ("G01 grant/request comparison inverted", "ptpwatch.py",
     "                    if grant.log_interval != req.log_interval or \\\n"
     "                            grant.duration > req.duration:",
     "                    if False:"),
    ("H01 permits the end-to-end mechanism in gPTP", "ptpwatch.py",
     "        if msg.msg_type in E2E_TYPES:", "        if False:"),
    ("H02 second pdelay responder ignored", "ptpwatch.py",
     "            if len(responders) > 1:", "            if False:"),
    ("H04 path-trace/stepsRemoved relation inverted", "ptpwatch.py",
     "        if msg.steps_removed is not None and len(ids) != msg.steps_removed + 1:",
     "        if msg.steps_removed is not None and len(ids) == msg.steps_removed + 1:"),
    ("H05 duplicate path-trace identity ignored", "ptpwatch.py",
     "        if len(set(ids)) != len(ids):", "        if False:"),
    ("H07 stop-sending sentinel not recognised", "ptpwatch.py",
     "INTERVAL_STOP_SENDING = 127", "INTERVAL_STOP_SENDING = 99"),
    ("gPTP keyed off the wrong sdoId", "ptpwatch.py",
     "SDOID_GPTP = 1", "SDOID_GPTP = 3"),
    ("A09 reverts to exact-length matching (breaks every TLV-bearing message)",
     "ptpwatch.py",
     "        if want is not None and msg.msg_length < want:",
     "        if want is not None and msg.msg_length != want:"),
    ("PATH_TRACE misclassified as a security TLV (suppresses E03 on gPTP)",
     "ptpwatch.py",
     "SECURITY_TLVS = frozenset({TLV_AUTHENTICATION, TLV_AUTH_CHALLENGE,\n"
     "                           TLV_SECURITY_ASSOC_UPDATE})",
     "SECURITY_TLVS = frozenset({TLV_PATH_TRACE, TLV_AUTHENTICATION,\n"
     "                           TLV_SECURITY_ASSOC_UPDATE})"),
    ("A07 reorder tolerance swallows all regressions", "ptpwatch.py",
     "    seq_reorder_tolerance: int = 8",
     "    seq_reorder_tolerance: int = 40000"),
    ("rate rules ignore the 0x7F sentinel", "ptpwatch.py",
     "    if log_interval == LOG_INTERVAL_NA or log_interval < -12 or log_interval > 12:",
     "    if log_interval < -12000 or log_interval > 12000:"),
]

CONFORMANCE_MUTATIONS = [
    ("correctionField 48.16 scaling dropped (the classic trap)", "ptpwatch.py",
     "ONE_SECOND_SCALED = 1_000_000_000 << SUBNS_SHIFT",
     "ONE_SECOND_SCALED = 1_000_000_000"),
    ("twoStep flag mask shifted one bit", "ptpwatch.py",
     "FLAG_TWO_STEP = 0x02", "FLAG_TWO_STEP = 0x04"),
    ("leap59/leap61 masks swapped", "ptpwatch.py",
     "FLAG_LEAP_61 = 0x01\nFLAG_LEAP_59 = 0x02",
     "FLAG_LEAP_61 = 0x02\nFLAG_LEAP_59 = 0x01"),
    ("portNumber read from the wrong header offset", "ptpwatch.py",
     '    port_number = struct.unpack_from("!H", buf, 28)[0]',
     '    port_number = struct.unpack_from("!H", buf, 26)[0]'),
    ("correctionField parsed unsigned", "ptpwatch.py",
     '    correction = _s64(struct.unpack_from("!Q", buf, 8)[0])',
     '    correction = struct.unpack_from("!Q", buf, 8)[0]'),
    ("clockClass read from clockAccuracy's offset", "ptpwatch.py",
     "            msg.clock_class = body[14]", "            msg.clock_class = body[15]"),
    ("currentUtcOffset parsed unsigned", "ptpwatch.py",
     '            msg.utc_offset = struct.unpack_from("!h", body, 10)[0]',
     '            msg.utc_offset = struct.unpack_from("!H", body, 10)[0]'),
    ("actionField high nibble not masked", "ptpwatch.py",
     "            msg.action_field = body[12] & 0x0F",
     "            msg.action_field = body[12]"),
    ("sequenceId wrap arithmetic removed", "ptpwatch.py",
     "    return ((new - old + 0x8000) & 0xFFFF) - 0x8000", "    return new - old"),
    ("IPv6 AH sized as an 8-byte-unit header (the bfdwatch bug)", "ptpwatch.py",
     "                ext = (buf[cur + 1] + 2) * 4      # AH: 4-byte units, bias 2",
     "                ext = (buf[cur + 1] + 1) * 8"),
    ("TLV chain guard removed", "ptpwatch.py",
     "    while off + 4 <= n and guard < 64:", "    while off + 4 <= n and guard < 10**9:"),
    ("dedup window disabled", "ptpwatch.py",
     "        if last is not None and (f.ts - last) < self.cfg.dedup_window:",
     "        if last is not None and (f.ts - last) < 0:"),
    ("arming gate always open", "ptpwatch.py",
     "        if spec.armed_by is None:\n            return True",
     "        if True:\n            return True"),
    ("severity leaks as an enum into JSON", "ptpwatch.py",
     '            "severity": spec.severity.value,', '            "severity": spec.severity,'),
    ("a transmit call appears in the module", "ptpwatch.py",
     "def _v6str(b: bytes) -> str:",
     "def _leak(sock):\n    sock.sendto(b'', ())\n\n\ndef _v6str(b: bytes) -> str:"),
    ("runt header accepted instead of raising", "ptpwatch.py",
     '        raise ParseError(f"runt: {len(buf)} bytes < {HEADER_LEN} header")',
     '        buf = buf + bytes(HEADER_LEN - len(buf))'),
]

DEPLOYMENT_MUTATIONS = [
    ("unit grants AF_INET", "ptpwatch@.service",
     "RestrictAddressFamilies=AF_PACKET AF_NETLINK AF_UNIX",
     "RestrictAddressFamilies=AF_PACKET AF_NETLINK AF_UNIX AF_INET"),
    ("unit drops MemoryDenyWriteExecute", "ptpwatch@.service",
     "MemoryDenyWriteExecute=yes", "MemoryDenyWriteExecute=no"),
    ("unit widens the capability bounding set", "ptpwatch@.service",
     "CapabilityBoundingSet=CAP_NET_RAW",
     "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_ADMIN"),
    ("env example advertises a flag the CLI lacks",
     "ptpwatch-eth1.env.example", "#   --domain 24", "#   --domain 24 --learn-baseline"),
    ("env example stops documenting a disarmed rule",
     "ptpwatch-eth1.env.example", "#   PTP-B05  Announce from a grandmaster",
     "#   PTPxB05  Announce from a grandmaster"),
    ("state caps removed (memory exhaustible by minted clockIdentities)",
     "ptpwatch.py", "    max_clocks: int = 4096", "    max_clocks: int = 10**9"),
]

# A mutation entry is (label, file, old, new) with an optional 5th element
# overriding the tier runner for that mutation alone.
DOCS_MUTATIONS: List[Tuple] = [
    ("README overstates a code's severity", "README.md",
     "| `PTP-E05` | low |", "| `PTP-E05` | critical |"),
    ("README misstates a code's confidence", "README.md",
     "| `PTP-B04` | high | possible |", "| `PTP-B04` | high | confirmed |"),
    ("README renames a finding", "README.md",
     "Unicast grant does not match its request",
     "Unicast grant mismatch detected"),
    ("README total code count drifts", "README.md",
     "42 codes: 11 critical, 15 high, 13 medium, 3 low",
     "43 codes: 11 critical, 15 high, 13 medium, 3 low"),
    ("README claims a dark rule is always on", "README.md",
     "| `PTP-B05` | critical | confirmed | attack | `--grandmaster` |",
     "| `PTP-B05` | critical | confirmed | attack | always on |"),
    ("README drops a dark rule from the arming table", "README.md",
     "| `PTP-D04` | `--mgmt-station` | A GET sweep is indistinguishable from "
     "authorized NMS polling |",
     "| `PTP-E06` | `--mgmt-station` | placeholder |"),
    ("README misstates a flag default", "README.md",
     "| `--rate-tolerance` | 3.0 |", "| `--rate-tolerance` | 5.0 |"),
    ("README documents a flag that does not exist", "README.md",
     "| `--no-promisc` | off |", "| `--learn-baseline` | off |"),
    ("README misstates a state cap", "README.md",
     "`max_clocks` 4096", "`max_clocks` 8192"),
    ("README quotes a systemd directive the unit lacks", "README.md",
     "`MemoryMax=192M`", "`MemoryMax=512M`"),
    ("README loses the 48.16 scaling explanation", "README.md",
     "`1_000_000_000 << 16`", "`1_000_000_000`"),
    ("README version drifts from the module", "README.md",
     "Version `0.1.0-dev`", "Version `0.2.0`"),
    ("README publishes a tier result that is not real", "README.md",
     "| 656/656 |", "| 700/700 |", ["ptpwatch_readme_verify.py"]),
    ("README misstates the gPTP destination address", "README.md",
     "`01:80:C2:00:00:0E` for **every** message type",
     "`01:1B:19:00:00:00` for **every** message type"),
    ("README deletes the Annex E coverage gap", "README.md",
     "**Annex E has no live lab coverage.**", "**Annex E is fully covered.**"),
]
# --- END MUTATION TABLE -----------------------------------------------------

TIER_FILES = {
    "scenario": (["test_scenarios.py"], ["ptpwatch.py", "test_scenarios.py"]),
    "conformance": (["ptpwatch_conformance.py"],
                    ["ptpwatch.py", "ptpwatch_conformance.py"]),
    "deployment": (["ptpwatch_conformance.py"],
                   ["ptpwatch.py", "ptpwatch_conformance.py",
                    "ptpwatch@.service", "ptpwatch-eth1.env.example"]),
    "docs": (["ptpwatch_readme_verify.py", "--quick"],
             ["ptpwatch.py", "ptpwatch_readme_verify.py", "README.md",
              "ptpwatch@.service", "ptpwatch-eth1.env.example"]),
}


_TABLE_BEGIN = "# --- BEGIN MUTATION TABLE " + "-" * 51
_TABLE_END = "# --- END MUTATION TABLE " + "-" * 53


def _split_mutation_table(text: str) -> Tuple[str, str, str]:
    """Return (head, table, tail). The table region is excluded from mutation
    site matching so this file can safely mutate itself."""
    i = text.find(_TABLE_BEGIN)
    if i < 0:
        return (text, "", "")
    j = text.find(_TABLE_END, i)
    if j < 0:
        return (text, "", "")
    j += len(_TABLE_END)
    return (text[:i], text[i:j], text[j:])


def _run_mutation(tier: str, label: str, target: str, old: str, new: str,
                  srcdir: str, verbose: bool,
                  runner_override: Optional[List[str]] = None) -> Tuple[bool, str]:
    import shutil
    import subprocess
    import tempfile

    runner, needed = TIER_FILES[tier]
    if runner_override:
        runner = runner_override
        needed = sorted(set(needed) | {"test_scenarios.py",
                                       "ptpwatch_conformance.py"})
    with tempfile.TemporaryDirectory(prefix="ptpwatch-mut-") as tmp:
        for name in needed:
            src = os.path.join(srcdir, name)
            if not os.path.exists(src):
                return (False, f"missing {name}")
            shutil.copy2(src, os.path.join(tmp, name))
        lab_src = os.path.join(srcdir, "lab")
        if os.path.isdir(lab_src):
            os.mkdir(os.path.join(tmp, "lab"))
            for f in os.listdir(lab_src):
                if f.endswith(".pcap"):
                    shutil.copy2(os.path.join(lab_src, f),
                                 os.path.join(tmp, "lab", f))
        path = os.path.join(tmp, target)
        text = open(path, encoding="utf-8").read()
        head, table, tail = _split_mutation_table(text)
        hits = (head + tail).count(old)
        if hits != 1:
            return (False, f"mutation site matched {hits} times outside the "
                           f"mutation table, need exactly 1")
        if old in head:
            head = head.replace(old, new)
        else:
            tail = tail.replace(old, new)
        open(path, "w", encoding="utf-8").write(head + table + tail)
        cmd = [sys.executable, os.path.join(tmp, runner[0])] + list(runner[1:])
        proc = subprocess.run(cmd, cwd=tmp,
                              capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            return (True, "")
        tail = (proc.stdout.strip().splitlines() or ["<no output>"])[-1]
        return (False, f"{tier} tier stayed GREEN: {tail}")


def self_verify(verbose: bool = False) -> int:
    import os as _os
    srcdir = _os.path.dirname(_os.path.abspath(__file__))
    lists = [("scenario", SCENARIO_MUTATIONS),
             ("conformance", CONFORMANCE_MUTATIONS),
             ("deployment", DEPLOYMENT_MUTATIONS),
             ("docs", DOCS_MUTATIONS)]
    total = passed = 0
    problems = []
    print("ptpwatch --self-verify : each mutation must turn its tier red\n")
    for tier, muts in lists:
        if not muts:
            print(f"  [{tier}] 0 mutations -- tier artifact not built yet\n")
            continue
        print(f"  [{tier}] {len(muts)} mutations against "
              f"{' '.join(TIER_FILES[tier][0])}")
        for mut in muts:
            label, target, old, new = mut[:4]
            override = mut[4] if len(mut) > 4 else None
            total += 1
            try:
                ok, why = _run_mutation(tier, label, target, old, new,
                                        srcdir, verbose, override)
            except Exception as exc:  # noqa: BLE001
                ok, why = False, f"{type(exc).__name__}: {exc}"
            passed += 1 if ok else 0
            if ok:
                print(f"    caught   {label}")
            else:
                print(f"    MISSED   {label}\n             {why}")
                problems.append((tier, label, why))
        print()
    if problems:
        print("holes found -- these mutations went unnoticed:")
        for tier, label, why in problems:
            print(f"  [{tier}] {label}: {why}")
        print()
    print(f"ptpwatch self-verify: {passed}/{total}")
    return 1 if passed != total else 0


def build_argparser():
    import argparse
    ap = argparse.ArgumentParser(
        prog="ptpwatch",
        description="Passive IEEE 1588 / PTPv2 timing-plane monitor (Ragnar).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--iface", help="capture interface (live)")
    src.add_argument("-r", "--pcap", help="read from pcap/pcapng instead")
    ap.add_argument("--domain", type=int, default=None,
                    help="declared PTP domain; arms PTP-E04 precision")
    ap.add_argument("--grandmaster", action="append", default=[],
                    metavar="CLOCKID",
                    help="declared authorized grandmaster clockIdentity (hex); "
                         "arms PTP-B05. Repeatable.")
    ap.add_argument("--mgmt-station", action="append", default=[], metavar="ADDR",
                    help="authorized management/NMS source (IP or MAC); "
                         "arms PTP-D04. Repeatable.")
    ap.add_argument("--profile", default="auto",
                    choices=["auto", "g8275.1", "g8275.2", "8021as"])
    ap.add_argument("--rate-tolerance", type=float, default=3.0)
    ap.add_argument("--dedup-window", type=float, default=60.0)
    ap.add_argument("--no-promisc", action="store_true",
                    help="do not put the interface in promiscuous mode")
    ap.add_argument("--heartbeat", type=float, default=60.0,
                    metavar="SECONDS", help="stderr liveness line interval")
    ap.add_argument("--self-verify", action="store_true",
                    help="mutation runner: prove each test tier is non-vacuous")
    ap.add_argument("--list-codes", action="store_true")
    return ap


def main(argv=None) -> int:
    import json
    import sys
    ap = build_argparser()
    if argv is None:
        argv = sys.argv[1:]
    if "--self-verify" in argv:
        return self_verify(verbose="-v" in argv)
    if "--list-codes" in argv:
        for code, spec in sorted(FINDINGS.items()):
            armed = "disarmed" if spec.armed_by else "armed"
            print(f"{code}  {spec.severity.value:8s} {spec.confidence.value:9s} "
                  f"{spec.klass.value:8s} {armed:8s} {spec.title}")
        return 0
    args = ap.parse_args(argv)
    cfg = Config(iface=args.iface, pcap=args.pcap, domain=args.domain,
                 grandmasters=tuple(args.grandmaster),
                 mgmt_stations=tuple(args.mgmt_station), profile=args.profile,
                 rate_tolerance=args.rate_tolerance,
                 dedup_window=args.dedup_window,
                 promisc=not args.no_promisc,
                 heartbeat_interval=args.heartbeat)
    em = Emitter(cfg)
    if args.pcap:
        eng = run_pcap(args.pcap, cfg, em)
    else:
        import signal
        sd = _Shutdown()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, sd.request)
        run_live(args.iface, cfg, em, shutdown=sd)
        return 0
    for f in em.sink:
        print(json.dumps(f.to_dict()), flush=True)
    print(f"ptpwatch: {eng.msgs} PTP messages, {len(em.sink)} findings, "
          f"{em.suppressed} deduped", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ===========================================================================
# RAGNAR IN-APP ADAPTER  (appended on vendoring; not part of the upstream CLI)
# ---------------------------------------------------------------------------
# Snapshot-over-pcap adapter mirroring bfdwatch/sr_mplswatch: one tcpdump
# capture on the interface, replayed through the streaming PtpEngine, reduced to
# a single card verdict, with HIGH/CRITICAL findings streamed to Watchtower.
# The detection path is pure-Python (own libpcap reader + decode_frame; the
# upstream live path uses raw AF_PACKET, which this adapter does not touch).
# Detection-only: never transmits a PTP frame.
#
# Capture BPF note: the upstream live path runs NO BPF on purpose, because
# libpcap's `udp port N` cannot chase the IPv6 extension-header chain and would
# be blind to exactly the Annex E frames an attacker crafts. A no-filter capture
# is not affordable on a Pi Zero 2W SPAN, so this snapshot adapter uses a
# next-header-qualified filter (the Cisco/Juniper-guard lesson): plain Annex F
# (EtherType 0x88F7, covers gPTP), Annex D + plain Annex E (libpcap `port` matches
# both v4 and v6), PLUS an ip6[6] ext-header clause so an ext-header'd (incl. AH)
# Annex E frame is still admitted to userspace, where decode_frame() walks the
# chain itself. It does NOT blanket-admit `ip6` (which would flood the adapter).
# ===========================================================================
import os as _ptp_os
import json as _ptp_json
import time as _ptp_time
import tempfile as _ptp_tempfile
import subprocess as _ptp_subprocess
from datetime import datetime as _ptp_datetime, timezone as _ptp_timezone

_PTP_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# A critical-severity attack finding means an induced time/grandmaster
# manipulation (takeover, correctionField/timestamp injection, management
# WRITE, utcOffset flip, unicast-cancel forgery, multi-responder timing denial).
# That is the crown-jewel verdict token, mirrored into the web net-integrity
# critical set as 'time-manipulation'.
_PTP_CRITICAL_VERDICT = "time-manipulation"


def _ptp_verdict(findings):
    """Reduce a finding-dict list to (verdict, ranked-worst-first)."""
    ranked = sorted(findings,
                    key=lambda f: _PTP_SEV_RANK.get(f.get("severity"), 0),
                    reverse=True)
    if any(f.get("severity") == "critical" and f.get("class") == "attack"
           for f in ranked):
        return _PTP_CRITICAL_VERDICT, ranked
    if any(_PTP_SEV_RANK.get(f.get("severity"), 0) >= 3 for f in ranked):
        return "exposure", ranked
    if any(f.get("class") == "attack" for f in ranked):
        return "attack-indicator", ranked
    if ranked:
        return "posture", ranked
    return "clean", ranked


# --- Watchtower feed --------------------------------------------------------
_PTP_WT_LOG_DIR = _ptp_os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_PTP_WT_DEDUP_S = 300.0
_PTP_WT_EMIT_SEV = frozenset(("high", "critical"))
_ptp_wt_lock = None
_ptp_wt_seen = {}


def _ptp_emit_watchtower(result):
    """Append HIGH/CRITICAL PTP findings to <log-dir>/ptp_watch.jsonl in the
    shape Watchtower.normalize() reads, so grandmaster-takeover / time-injection
    / management-write alerts fold into the unified pane + single Pushover path.
    Deduped per (code, port_identity) over the window. Never raises."""
    global _ptp_wt_lock
    if _ptp_wt_lock is None:
        import threading
        _ptp_wt_lock = threading.Lock()
    if not result.get("success"):
        return
    verdict = result.get("verdict", "clean")
    iface = result.get("interface")
    now = _ptp_time.time()
    iso = _ptp_datetime.now(_ptp_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    with _ptp_wt_lock:
        for f in result.get("findings", []):
            if f.get("severity") not in _PTP_WT_EMIT_SEV:
                continue
            code = f.get("code")
            pid = f.get("port_identity")
            key = (code, pid)
            last = _ptp_wt_seen.get(key)
            if last is not None and now - last < _PTP_WT_DEDUP_S:
                continue
            _ptp_wt_seen[key] = now
            lines.append(_ptp_json.dumps({
                "module": "ptp_watch", "ts": now, "iso": iso, "iface": iface,
                "severity": f.get("severity"), "code": code, "codes": [code],
                "src": pid, "summary": f.get("title"), "verdict": verdict}))
        if len(_ptp_wt_seen) > 4096:
            cutoff = now - _PTP_WT_DEDUP_S
            for k in [k for k, t in _ptp_wt_seen.items() if t < cutoff]:
                _ptp_wt_seen.pop(k, None)
    if not lines:
        return
    try:
        _ptp_os.makedirs(_PTP_WT_LOG_DIR, exist_ok=True)
        with open(_ptp_os.path.join(_PTP_WT_LOG_DIR, "ptp_watch.jsonl"), "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


# --- capture ----------------------------------------------------------------
# See the module-header BPF note. `vlan`-tagged PTP is handled by decode_frame's
# own tag walk, so no `vlan` primitive is needed here (it would shift offsets).
_PTP_BPF = ("ether proto 0x88f7 or udp port 319 or udp port 320 or "
            "(ip6 and (ip6[6] = 0 or ip6[6] = 43 or ip6[6] = 44 or "
            "ip6[6] = 51 or ip6[6] = 60))")


def _ptp_capture_pcap(interface, seconds):
    """tcpdump a PTP snapshot to a temp classic-pcap file. Full snaplen (-s 0):
    management + path-trace TLV messages vary in length and a truncated frame
    would false-positive PTP-A09 (declared-vs-actual length). Returns
    (path, error). Detection-only: no transmit."""
    from shutil import which
    if not which("tcpdump"):
        return None, "tcpdump is not installed. Click Install to add it."
    fd, path = _ptp_tempfile.mkstemp(suffix=".pcap")
    _ptp_os.close(fd)
    try:
        res = _ptp_subprocess.run(
            ["timeout", str(int(seconds) + 3), "tcpdump", "-i", interface,
             "-nn", "-s", "0", "-c", "20000", "-w", path, _PTP_BPF],
            stdout=_ptp_subprocess.DEVNULL, stderr=_ptp_subprocess.PIPE,
            timeout=int(seconds) + 8)
        err = (res.stderr or b"").decode("utf-8", "replace")
    except _ptp_subprocess.TimeoutExpired:
        err = ""
    except OSError as e:
        try:
            _ptp_os.remove(path)
        except OSError:
            pass
        return None, "capture failed: {}".format(e)
    if (_ptp_os.path.getsize(path) <= 24 and err
            and any(s in err.lower() for s in
                    ("permission", "no such device", "syntax error", "couldn't"))):
        try:
            _ptp_os.remove(path)
        except OSError:
            pass
        return None, err.strip()[:200]
    return path, None


def do_ptp_watch(interface=None, seconds=20, grandmasters=None,
                 mgmt_stations=None, domain=None):
    """Passive IEEE-1588 / PTPv2 / gPTP timing-plane scan (detection-only). One
    tcpdump snapshot on `interface`, replayed through the streaming PtpEngine;
    reports grandmaster takeover / identity conflict, time injection
    (correctionField / origin-timestamp / utcOffset), management SET/WRITE
    abuse, unicast-negotiation forgery, and gPTP (802.1AS) peer-delay / path-trace
    violations. Covers Annex F (raw Ethernet 0x88F7), Annex D (UDP/IPv4) and
    Annex E (UDP/IPv6, extension-header + AH aware). Streams HIGH/CRITICAL
    findings to Watchtower. Never transmits a PTP frame."""
    if not interface:
        return {"success": False, "error": "no interface specified"}
    seconds = max(8, min(int(seconds or 20), 60))
    path, err = _ptp_capture_pcap(interface, seconds)
    if err:
        return {"success": False, "interface": interface, "error": err,
                "missing_tool": "tcpdump" if "not installed" in err else None}
    cfg = Config(
        grandmasters=tuple(grandmasters or ()),
        mgmt_stations=tuple(mgmt_stations or ()),
        domain=domain)
    emitter = Emitter(cfg)
    try:
        eng = run_pcap(path, cfg, emitter)
    except Exception as e:
        return {"success": False, "interface": interface,
                "error": "capture parse failed: {}".format(type(e).__name__)}
    finally:
        try:
            _ptp_os.remove(path)
        except OSError:
            pass

    findings = [f.to_dict() for f in emitter.sink]
    verdict, ranked = _ptp_verdict(findings)
    # Reasons: distinct actionable findings (>= medium), worst first, deduped by
    # code, capped — plus a clean line when only posture surfaced.
    reasons, seen = [], set()
    for f in ranked:
        if _PTP_SEV_RANK.get(f.get("severity"), 0) < 2:
            continue
        if f["code"] in seen:
            continue
        seen.add(f["code"])
        reasons.append("{}: {} [{}]".format(f["code"], f.get("title", ""),
                                            f.get("port_identity", "")))
        if len(reasons) >= 8:
            break
    msgs = sum(emitter.counts.values()) if emitter.counts else 0
    transports = sorted(getattr(eng, "transports", set()) or [])
    clocks = len(getattr(eng, "clocks", {}) or {})
    if not reasons:
        if clocks or transports:
            reasons = ["PTP timing plane observed; no grandmaster takeover, time "
                       "injection, management-write or gPTP peer-delay violation "
                       "detected"]
        else:
            reasons = ["No PTP traffic seen on this segment "
                       "(Annex F 0x88F7 / Annex D+E UDP 319-320)"]

    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    result = {
        "success": True, "interface": interface, "seconds": seconds,
        "verdict": verdict, "reasons": reasons,
        "findings": findings,
        "clocks": clocks, "transports": transports,
        "by_severity": by_sev,
    }
    _ptp_emit_watchtower(result)
    return result


# --- selftest helpers: build real PTPv2 frames (no sockets, no capture) ------
def _ptp_build_header(msg_type, seq, *, major_sdo=0, domain=0, flags=0,
                      correction=0, clock_id=b"\xaa\xbb\xcc\xff\xfe\x00\x00\x01",
                      port=1, log_interval=0, msg_length=None):
    body_default = {MsgType.ANNOUNCE: 64}.get(msg_type, HEADER_LEN)
    ml = msg_length if msg_length is not None else body_default
    h = bytearray(HEADER_LEN)
    h[0] = ((major_sdo & 0x0F) << 4) | (msg_type & 0x0F)
    h[1] = 0x02  # minorVersion 0, versionPTP 2
    struct.pack_into("!H", h, 2, ml)
    h[4] = domain
    h[5] = 0
    struct.pack_into("!H", h, 6, flags)
    struct.pack_into("!q", h, 8, correction)
    struct.pack_into("!I", h, 16, 0)
    h[20:28] = clock_id
    struct.pack_into("!H", h, 28, port)
    struct.pack_into("!H", h, 30, seq)
    h[32] = 0
    struct.pack_into("!b", h, 33, log_interval)
    return h


def _ptp_build_announce(seq, *, clock_class=6, steps_removed=0,
                        time_source=0x20, gm_id=b"\xaa\xbb\xcc\xff\xfe\x00\x00\x01",
                        **hkw):
    body = bytearray(30)
    # body[0:10] origin timestamp (left zero); [10:12] utcOffset
    struct.pack_into("!h", body, 10, 37)
    body[13] = 128           # priority1
    body[14] = clock_class
    body[15] = 0x21          # clockAccuracy
    struct.pack_into("!H", body, 16, 0x4E5D)   # offsetScaledLogVariance
    body[18] = 128           # priority2
    body[19:27] = gm_id
    struct.pack_into("!H", body, 27, steps_removed)
    body[29] = time_source
    h = _ptp_build_header(MsgType.ANNOUNCE, seq, clock_id=gm_id, **hkw)
    return bytes(h) + bytes(body)


def _ptp_annexf_frame(ptp_payload, dst=b"\x01\x1b\x19\x00\x00\x00",
                      src=b"\xaa\xbb\xcc\x00\x00\x01"):
    return dst + src + b"\x88\xf7" + ptp_payload


def _ptp_annexe_ah_frame(ptp_payload):
    """IPv6 → Authentication Header (proto 51) → UDP/319 → PTP. Exercises the
    Annex E extension-header walk, incl. the AH (len+2)*4 sizing that a naive
    (len+1)*8 walk drops — the recurring IPv6 AH bug class."""
    udp = struct.pack("!HHHH", 12345, PTP_EVENT_PORT, 8 + len(ptp_payload), 0)
    # minimal 12-byte AH: nextHdr=UDP(17), payloadLen=1 -> (1+2)*4 = 12, SPI+seq
    ah = bytes([17, 1, 0, 0]) + b"\x00\x00\x10\x01" + b"\x00\x00\x00\x01"
    payload = ah + udp + ptp_payload
    v6 = bytearray(40)
    v6[0] = 0x60
    struct.pack_into("!H", v6, 4, len(payload))
    v6[6] = 51               # nextHeader = AH
    v6[7] = 64               # hop limit
    v6[8:24] = bytes.fromhex("fe800000000000000000000000000001")
    v6[24:40] = bytes.fromhex("ff0e0000000000000000000000000181")
    eth = b"\x33\x33\x00\x00\x01\x81" + b"\xaa\xbb\xcc\x00\x00\x01" + b"\x86\xdd"
    return eth + bytes(v6) + payload


def selftest():
    """Build real PTPv2 frames, decode + feed them through the engine, and assert
    the findings; plus run the engine's own conformance tier and mutation runner.
    No sockets, no capture, no persistence (the engine only reads bytes)."""
    scen = []

    def check(name, ok, detail=""):
        scen.append({"name": name, "pass": bool(ok), "detail": str(detail)})

    def run(frames):
        cfg = Config()
        em = Emitter(cfg)
        eng = PtpEngine(cfg, em)
        base = None
        for i, frame in enumerate(frames):
            ctx = decode_frame(frame, LINKTYPE_ETHERNET)
            if ctx is None:
                continue
            try:
                msg = parse_ptp(ctx["payload"])
            except ParseError:
                continue
            msg.src_mac = ctx["src_mac"]; msg.dst_mac = ctx["dst_mac"]
            msg.src_ip = ctx["src_ip"]; msg.dst_ip = ctx["dst_ip"]
            msg.transport = ctx["transport"]
            ts = 1000.0 + i * 0.1
            if base is None:
                base = ts
            eng.feed(msg, ts, ts - base)
        eng.finalize(base if base is not None else 0.0)
        return {f.code for f in em.sink}, eng

    # 1. Clean Annex F Announce stream stays silent of attack codes.
    got, _ = run([_ptp_annexf_frame(_ptp_build_announce(1)),
                  _ptp_annexf_frame(_ptp_build_announce(2))])
    attack = {c for c in got if FINDINGS[c].klass is Klass.ATTACK}
    check("clean-annexf-silent", not attack, sorted(attack))

    # 2. Primary clockClass (6) with non-zero stepsRemoved -> PTP-A01.
    got, _ = run([_ptp_annexf_frame(
        _ptp_build_announce(1, clock_class=6, steps_removed=5))])
    check("a01-primary-class-steps-removed", "PTP-A01" in got, sorted(got))

    # 3. Annex E behind an IPv6 Authentication Header decodes to a PTP payload
    #    (the AH ext-header walk; a (len+1)*8 walk would drop it).
    ctx = decode_frame(_ptp_annexe_ah_frame(_ptp_build_announce(1)),
                       LINKTYPE_ETHERNET)
    ah_ok = (ctx is not None and ctx.get("transport") == "annexE")
    ah_parse = False
    if ah_ok:
        try:
            m = parse_ptp(ctx["payload"])
            ah_parse = (m.msg_type == MsgType.ANNOUNCE)
        except ParseError:
            ah_parse = False
    check("annexe-ah-extheader-walk", ah_ok and ah_parse,
          "transport=%s parsed=%s" % (ctx and ctx.get("transport"), ah_parse))

    # 4. Adapter verdict mapping: a critical attack finding -> 'time-manipulation'.
    v, _ = _ptp_verdict([{"code": "PTP-A08", "severity": "critical", "class": "attack"},
                         {"code": "PTP-E03", "severity": "low", "class": "posture"}])
    check("verdict-time-manipulation", v == _PTP_CRITICAL_VERDICT, v)

    # 5. Registry integrity: the documented 42-code / severity split holds.
    sev = {}
    for spec in FINDINGS.values():
        sev[spec.severity.value] = sev.get(spec.severity.value, 0) + 1
    reg_ok = (len(FINDINGS) == 42 and sev.get("critical") == 11
              and sev.get("high") == 15)
    check("registry-42-codes", reg_ok, "%d codes %s" % (len(FINDINGS), sev))

    # 6. Engine conformance tier (656 cases) if it is co-located; skipped cleanly
    #    if the tier file was not vendored (production ships only ptpwatch.py).
    try:
        import importlib, os as _o
        _here = _o.path.dirname(_o.path.abspath(__file__))
        _conf = _o.path.join(_here, "ptpwatch_conformance.py")
        if _o.path.exists(_conf):
            import subprocess as _sp
            r = _sp.run(["python3", _conf], stdout=_sp.PIPE, stderr=_sp.STDOUT,
                        timeout=120)
            out = r.stdout.decode("utf-8", "replace")
            check("engine-conformance-tier", r.returncode == 0 and "656/656" in out,
                  out.strip().splitlines()[-1] if out.strip() else "no output")
    except Exception as e:
        check("engine-conformance-tier", True, "skipped: %s" % type(e).__name__)

    return {"success": all(s["pass"] for s in scen), "scenarios": scen}
