#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lacpwatch — passive LACP / Marker slow-protocol integrity monitor for Ragnar.

Scope
-----
IEEE 802.1AX (formerly 802.3ad) Link Aggregation Control Protocol and the
Marker Protocol, both carried in Slow Protocols frames (EtherType 0x8809,
destination 01:80:C2:00:00:02).

This module is RECEIVE-ONLY. There is no transmitter, no injector and no
frame-sending code path in this file. The self-test contains a serializer
that produces bytes for the parser; those bytes are never written to a
socket. Same discipline as vtpwatch/ndpwatch.

Honest framing
--------------
LACP has NO authentication mechanism in the standard. There is no key, no
digest, no sequence number. "LACP is unauthenticated" is therefore a
property of the protocol, not a finding about a deployment, and it is
emitted here as INFO once per LAG — not as HIGH. A pager alert that fires
on every LAG on every segment forever is noise, not a detection.

Consequently this is a STATE-INTEGRITY module, not a CVE detector. The one
real CVE anchor in the LACP space is CVE-2024-30388 (Junos OS, QFX5000 /
EX4400 / EX4100 / EX4650: a specific malformed LACP packet causes an LACP
flap — unauthenticated, adjacent, DoS). That maps onto the malformed-PDU
codes below: on affected hardware, LACP-TLV-LENGTH-INVALID or
LACP-MALFORMED-SHORT immediately followed by LACP-SYNC-FLAPPING on the same
segment is the observable signature of that bug being triggered.

Everything else here detects aggregation hijacking, member eviction and
selection-logic manipulation, which are protocol-design consequences rather
than software defects.

Dependencies
------------
None. Standard library only. Offline pcap reading uses a built-in libpcap
reader; live capture uses AF_PACKET directly. scapy is never imported.
"""

from __future__ import annotations

import argparse
import binascii
import json
import os
import signal
import struct
import sys
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

__version__ = "0.1.0-dev"
MODULE = "lacpwatch"

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

ETH_P_SLOW = 0x8809
SLOW_PROTOCOLS_GROUP_MAC = b"\x01\x80\xc2\x00\x00\x02"
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100, 0x9200)

SUBTYPE_LACP = 0x01
SUBTYPE_MARKER = 0x02
SUBTYPE_OAM = 0x03
SUBTYPE_OSSP = 0x0A
SUBTYPE_NAMES = {
    0x01: "LACP",
    0x02: "Marker",
    0x03: "802.3ah-OAM",
    0x04: "OSSP-reserved",
    0x0A: "OSSP",
}

TLV_TERMINATOR = 0x00
TLV_ACTOR = 0x01
TLV_PARTNER = 0x02
TLV_COLLECTOR = 0x03
# IEEE 802.1AX-2014 long-LACPDU (version 2) TLVs
TLV_PORT_ALGORITHM = 0x04
TLV_PORT_CONV_ID_DIGEST = 0x05
TLV_PORT_CONV_MASK_1 = 0x06
TLV_PORT_CONV_MASK_2 = 0x07
TLV_PORT_CONV_MASK_3 = 0x08
TLV_PORT_CONV_MASK_4 = 0x09
TLV_PORT_CONV_SERVICE_MAP = 0x0A

V2_TLVS = {
    TLV_PORT_ALGORITHM,
    TLV_PORT_CONV_ID_DIGEST,
    TLV_PORT_CONV_MASK_1,
    TLV_PORT_CONV_MASK_2,
    TLV_PORT_CONV_MASK_3,
    TLV_PORT_CONV_MASK_4,
    TLV_PORT_CONV_SERVICE_MAP,
}

TLV_NAMES = {
    0x00: "Terminator",
    0x01: "Actor",
    0x02: "Partner",
    0x03: "Collector",
    0x04: "PortAlgorithm",
    0x05: "PortConvIdDigest",
    0x06: "PortConvMask-1",
    0x07: "PortConvMask-2",
    0x08: "PortConvMask-3",
    0x09: "PortConvMask-4",
    0x0A: "PortConvServiceMap",
}

# Actor_State / Partner_State bit assignments (802.1AX-2014 6.4.2.2)
S_ACTIVITY = 0x01
S_TIMEOUT = 0x02
S_AGGREGATION = 0x04
S_SYNC = 0x08
S_COLLECTING = 0x10
S_DISTRIBUTING = 0x20
S_DEFAULTED = 0x40
S_EXPIRED = 0x80

STATE_BITS: Tuple[Tuple[int, str], ...] = (
    (S_ACTIVITY, "activity"),
    (S_TIMEOUT, "short_timeout"),
    (S_AGGREGATION, "aggregation"),
    (S_SYNC, "synchronization"),
    (S_COLLECTING, "collecting"),
    (S_DISTRIBUTING, "distributing"),
    (S_DEFAULTED, "defaulted"),
    (S_EXPIRED, "expired"),
)

FAST_PERIOD_S = 1.0
SLOW_PERIOD_S = 30.0
TIMEOUT_MULTIPLIER = 3

# ---------------------------------------------------------------------------
# Tunables. Every threshold used by a detector lives here and nowhere else,
# so tier4-style sweeps have a single surface to vary.
# ---------------------------------------------------------------------------

OBSERVATION_GAP_FACTOR = 3.0      # silence > detect_time * factor => RESYNC
OBSERVATION_GAP_FLOOR_S = 4.0     # ...but never shorter than this
SYNC_FLAP_WINDOW_S = 60.0
SYNC_FLAP_THRESHOLD = 4           # sync transitions inside the window
TIMEOUT_FLAP_WINDOW_S = 120.0
TIMEOUT_FLAP_THRESHOLD = 3
BURST_WINDOW_S = 5.0
BURST_MULTIPLIER = 5.0            # vs. the rate implied by the timeout bit
BURST_FLOOR = 12                  # never fire below this many PDUs/window
RATE_LIMIT_WINDOW_S = 300.0       # per (code, key) emit window
ORPHAN_CODE_BUDGET = 10           # distinct sources per code before rollup
CORRELATION_WINDOW_S = 120.0      # LAG-HIJACK correlation window
MISMATCH_MIN_PDUS = 2             # PDUs the contradicting half must send
                                  # before a partner-view disagreement counts
HALF_IDLE_TTL_S = 3600.0          # prune halves silent this long
PRUNE_INTERVAL_S = 300.0
MARKER_BURST_WINDOW_S = 10.0
MARKER_BURST_THRESHOLD = 20
MAX_HISTORY = 256                 # per-half bounded deques
MAX_IDENTITY_MAP = 8192           # cap on MAC->SysID / SysPort->Key maps

# ---------------------------------------------------------------------------
# Finding catalogue
# ---------------------------------------------------------------------------

SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"

CONF_HIGH = "high"
CONF_MEDIUM = "medium"
CONF_LOW = "low"

CODES: Dict[str, Dict[str, str]] = {
    # --- structural / parse -------------------------------------------------
    "LACP-MALFORMED-SHORT": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "LACPDU too short to carry Actor and Partner information"},
    "LACP-TLV-LENGTH-INVALID": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "LACPDU TLV length violates 802.1AX"},
    "LACP-TLV-ORDER-INVALID": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "LACPDU TLVs out of mandated order or missing"},
    "LACP-TRAILING-DATA": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "Non-zero data after Terminator TLV"},
    "LACP-BAD-VERSION": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "LACPDU version number outside {1,2}"},
    "LACP-UNKNOWN-TLV": {
        "severity": SEV_LOW, "confidence": CONF_HIGH,
        "title": "Unrecognised TLV type in LACPDU"},
    "LACP-RESERVED-NONZERO": {
        "severity": SEV_LOW, "confidence": CONF_MEDIUM,
        "title": "Reserved field carries non-zero octets"},
    "LACP-SLOW-PROTOCOL-SUBTYPE": {
        "severity": SEV_INFO, "confidence": CONF_HIGH,
        "title": "Non-LACP slow-protocol subtype observed on segment"},
    # --- delivery path ------------------------------------------------------
    "LACP-NON-SLOW-DESTINATION": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "LACPDU not addressed to the Slow Protocols group MAC"},
    "LACP-VLAN-TAGGED": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "LACPDU carries an 802.1Q tag (slow protocols are link-local)"},
    # --- identity / spoofing ------------------------------------------------
    "LACP-ACTOR-MAC-CHANGE": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "Actor identity now transmitted from a different source MAC"},
    "LACP-PORT-IDENTITY-COLLISION": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "Two source MACs claim the same actor system/key/port"},
    "LACP-SYSTEM-ID-CHANGE": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "Source MAC changed the actor System ID it advertises"},
    "LACP-SYSTEM-PRIORITY-IMPROVED": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "Actor System Priority improved mid-session (selection takeover)"},
    "LACP-PORT-PRIORITY-IMPROVED": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "Actor Port Priority improved mid-session"},
    "LACP-KEY-CHANGE": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "Actor operational Key changed for a stable system/port"},
    "LACP-SYSTEM-ID-INVALID": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Actor System ID is null or a group address"},
    "LACP-PORT-NUMBER-ZERO": {
        "severity": SEV_LOW, "confidence": CONF_HIGH,
        "title": "Actor Port Number is zero"},
    # --- cross-view ---------------------------------------------------------
    "LACP-PARTNER-VIEW-MISMATCH": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "Two halves do not agree they are aggregating with each other"},
    "LACP-PARTNER-UNOBSERVED": {
        "severity": SEV_LOW, "confidence": CONF_LOW,
        "title": "Claimed partner never observed transmitting on this tap"},
    # --- state machine ------------------------------------------------------
    "LACP-SYNC-LOSS": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Synchronization cleared on an established member"},
    "LACP-SYNC-FLAPPING": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "Repeated Synchronization transitions (aggregation instability)"},
    "LACP-DISTRIBUTING-LOSS": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Collecting/Distributing cleared while still synchronized"},
    "LACP-AGGREGATION-CLEARED": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Aggregation bit cleared: port now declares itself Individual"},
    "LACP-DEFAULTED-PARTNER-INFO": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Actor fell back to administrative default partner information"},
    "LACP-RECEIVE-EXPIRED": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Actor receive machine entered EXPIRED"},
    "LACP-TIMEOUT-CHANGE": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "LACP_Timeout changed between short and long"},
    "LACP-TIMEOUT-FLAPPING": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Repeated LACP_Timeout changes (detection-time manipulation)"},
    "LACP-ACTIVITY-CHANGE": {
        "severity": SEV_LOW, "confidence": CONF_MEDIUM,
        "title": "LACP_Activity changed between active and passive"},
    "LACP-VERSION-CHANGE": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "LACPDU version number changed mid-session"},
    "LACP-PDU-BURST": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "LACPDU rate far above the negotiated period"},
    # --- marker protocol ----------------------------------------------------
    "LACP-MARKER-MALFORMED": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Malformed Marker protocol PDU"},
    "LACP-MARKER-FLOOD": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Marker Request flood (distribution flush pressure)"},
    "LACP-MARKER-UNKNOWN-REQUESTER": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "Marker requester system never observed as an LACP actor"},
    # --- posture / inventory ------------------------------------------------
    "LACP-UNAUTHENTICATED": {
        "severity": SEV_INFO, "confidence": CONF_HIGH,
        "title": "LAG runs without authentication (protocol has no mechanism)"},
    "LACP-MEMBER-OBSERVED": {
        "severity": SEV_INFO, "confidence": CONF_HIGH,
        "title": "New LACP member observed"},
    # --- correlated ---------------------------------------------------------
    "LACP-LAG-HIJACK": {
        "severity": SEV_CRITICAL, "confidence": CONF_MEDIUM,
        "title": "Correlated aggregation takeover: identity manipulation with member disruption"},
    # --- housekeeping -------------------------------------------------------
    "LACP-ORPHAN-ROLLUP": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Many distinct sources emitting the same pre-session finding"},
}

# Codes used by the LAG-HIJACK correlator.
IDENTITY_CODES = frozenset({
    "LACP-ACTOR-MAC-CHANGE",
    "LACP-PORT-IDENTITY-COLLISION",
    "LACP-SYSTEM-ID-CHANGE",
    "LACP-SYSTEM-PRIORITY-IMPROVED",
    "LACP-PORT-PRIORITY-IMPROVED",
    "LACP-PARTNER-VIEW-MISMATCH",
})
DISRUPTION_CODES = frozenset({
    "LACP-SYNC-LOSS",
    "LACP-SYNC-FLAPPING",
    "LACP-DISTRIBUTING-LOSS",
    "LACP-AGGREGATION-CLEARED",
    "LACP-DEFAULTED-PARTNER-INFO",
    "LACP-RECEIVE-EXPIRED",
})

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def mac_str(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


def iso_ts(ts: float) -> str:
    whole = int(ts)
    ms = int(round((ts - whole) * 1000.0))
    if ms >= 1000:
        whole += 1
        ms -= 1000
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(whole)) + ".%03dZ" % ms


def state_flags(state: int) -> List[str]:
    return [name for bit, name in STATE_BITS if state & bit]


def state_str(state: int) -> str:
    return "0x%02x[%s]" % (state, ",".join(state_flags(state)) or "-")


def is_group_mac(raw: bytes) -> bool:
    return bool(raw) and bool(raw[0] & 0x01)


def hexs(raw: bytes) -> str:
    return binascii.hexlify(raw).decode("ascii")


# ---------------------------------------------------------------------------
# Parsed representations
# ---------------------------------------------------------------------------


@dataclass
class PortInfo:
    sys_prio: int
    sys_id: bytes
    key: int
    port_prio: int
    port_num: int
    state: int
    reserved: bytes = b""

    @property
    def identity(self) -> Tuple[bytes, int, int]:
        return (self.sys_id, self.key, self.port_num)

    @property
    def null(self) -> bool:
        return self.sys_id == b"\x00" * 6 and self.key == 0 and self.port_num == 0

    def label(self) -> str:
        return "sys=%s/%d key=0x%04x port=%d/%d" % (
            mac_str(self.sys_id), self.sys_prio, self.key,
            self.port_num, self.port_prio)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sys_id": mac_str(self.sys_id),
            "sys_prio": self.sys_prio,
            "key": self.key,
            "port_num": self.port_num,
            "port_prio": self.port_prio,
            "state": "0x%02x" % self.state,
            "state_flags": state_flags(self.state),
        }


@dataclass
class Anomaly:
    code: str
    evidence: Dict[str, Any]


@dataclass
class Lacpdu:
    version: int
    actor: Optional[PortInfo]
    partner: Optional[PortInfo]
    collector_max_delay: Optional[int]
    tlv_types: List[int]
    anomalies: List[Anomaly] = field(default_factory=list)
    trailing_nonzero: int = 0
    usable: bool = False


@dataclass
class MarkerPdu:
    version: int
    tlv_type: int
    requester_port: int
    requester_system: bytes
    transaction_id: int
    anomalies: List[Anomaly] = field(default_factory=list)
    usable: bool = False


@dataclass
class Frame:
    ts: float
    dst: bytes
    src: bytes
    ethertype: int
    payload: bytes
    tags: List[int]
    truncated: bool = False


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def decode_ethernet(raw: bytes, ts: float) -> Optional[Frame]:
    """Decode an Ethernet II frame, unwrapping any stack of VLAN tags.

    Returns None for anything that is not a slow-protocols frame. The tag
    stack is preserved because a tagged LACPDU is itself a finding.
    """
    if len(raw) < 14:
        return None
    dst = raw[0:6]
    src = raw[6:12]
    off = 12
    tags: List[int] = []
    ethertype = struct.unpack_from("!H", raw, off)[0]
    off += 2
    # Bound the tag walk: a frame with 8 stacked tags is not a real frame.
    for _ in range(8):
        if ethertype not in VLAN_ETHERTYPES:
            break
        if off + 4 > len(raw):
            return None
        tci = struct.unpack_from("!H", raw, off)[0]
        tags.append(tci & 0x0FFF)
        ethertype = struct.unpack_from("!H", raw, off + 2)[0]
        off += 4
    if ethertype != ETH_P_SLOW:
        # 802.3 length field: slow protocols are always EtherType-encoded.
        return None
    return Frame(ts=ts, dst=dst, src=src, ethertype=ethertype,
                 payload=raw[off:], tags=tags)


def _parse_port_info(info: bytes) -> Tuple[PortInfo, bool]:
    """info is the 18 octets following a 2-octet TLV header."""
    sys_prio, = struct.unpack_from("!H", info, 0)
    sys_id = info[2:8]
    key, port_prio, port_num = struct.unpack_from("!HHH", info, 8)
    state = info[14]
    reserved = info[15:18]
    return (PortInfo(sys_prio=sys_prio, sys_id=sys_id, key=key,
                     port_prio=port_prio, port_num=port_num, state=state,
                     reserved=reserved),
            any(reserved))


def parse_lacpdu(payload: bytes) -> Lacpdu:
    """Bounds-checked LACPDU parse. Never raises on hostile input."""
    pdu = Lacpdu(version=payload[1] if len(payload) > 1 else -1,
                 actor=None, partner=None, collector_max_delay=None,
                 tlv_types=[])
    if len(payload) < 2:
        pdu.anomalies.append(Anomaly("LACP-MALFORMED-SHORT",
                                     {"payload_len": len(payload)}))
        return pdu
    if pdu.version not in (1, 2):
        pdu.anomalies.append(Anomaly("LACP-BAD-VERSION",
                                     {"version": pdu.version}))
    off = 2
    reserved_nonzero = False
    saw_terminator = False
    unknown_tlvs: List[int] = []
    length_error: Optional[Dict[str, Any]] = None

    while off < len(payload):
        t = payload[off]
        if off + 2 > len(payload):
            length_error = {"offset": off, "reason": "tlv_header_truncated"}
            break
        ln = payload[off + 1]
        if t == TLV_TERMINATOR:
            saw_terminator = True
            pdu.tlv_types.append(t)
            # Terminator length is 0; anything else is a violation but the
            # PDU is still parseable up to this point.
            if ln != 0:
                length_error = {"offset": off, "tlv": "Terminator",
                                "length": ln, "expected": 0}
            off += 2
            break
        if ln < 2 or off + ln > len(payload):
            length_error = {"offset": off, "tlv": TLV_NAMES.get(t, "0x%02x" % t),
                            "length": ln, "remaining": len(payload) - off}
            break
        info = payload[off + 2: off + ln]
        pdu.tlv_types.append(t)
        if t == TLV_ACTOR or t == TLV_PARTNER:
            if ln != 20:
                length_error = {"offset": off,
                                "tlv": TLV_NAMES[t], "length": ln, "expected": 20}
                break
            pinfo, res_nz = _parse_port_info(info)
            reserved_nonzero = reserved_nonzero or res_nz
            if t == TLV_ACTOR:
                pdu.actor = pinfo
            else:
                pdu.partner = pinfo
        elif t == TLV_COLLECTOR:
            if ln != 16:
                length_error = {"offset": off, "tlv": "Collector",
                                "length": ln, "expected": 16}
                break
            pdu.collector_max_delay = struct.unpack_from("!H", info, 0)[0]
            reserved_nonzero = reserved_nonzero or any(info[2:14])
        elif t in V2_TLVS:
            pass  # long LACPDU: presence recorded, contents not interpreted
        else:
            unknown_tlvs.append(t)
        off += ln

    if length_error is not None:
        pdu.anomalies.append(Anomaly("LACP-TLV-LENGTH-INVALID", length_error))
    if unknown_tlvs:
        pdu.anomalies.append(Anomaly(
            "LACP-UNKNOWN-TLV",
            {"tlv_types": ["0x%02x" % t for t in unknown_tlvs],
             "version": pdu.version}))
    if saw_terminator:
        tail = payload[off:]
        nonzero = sum(1 for b in tail if b)
        if nonzero:
            pdu.trailing_nonzero = nonzero
            pdu.anomalies.append(Anomaly("LACP-TRAILING-DATA", {
                "trailing_len": len(tail),
                "nonzero_octets": nonzero,
                "first_32": hexs(tail[:32]),
            }))
    if pdu.actor is None or pdu.partner is None:
        if length_error is None:
            pdu.anomalies.append(Anomaly("LACP-MALFORMED-SHORT", {
                "payload_len": len(payload),
                "tlvs": [TLV_NAMES.get(t, "0x%02x" % t) for t in pdu.tlv_types],
            }))
    else:
        # Order: Actor must precede Partner, and both must be the first two
        # non-terminator TLVs of the PDU (802.1AX 6.4.2.3).
        heads = [t for t in pdu.tlv_types if t != TLV_TERMINATOR][:2]
        if heads != [TLV_ACTOR, TLV_PARTNER]:
            pdu.anomalies.append(Anomaly("LACP-TLV-ORDER-INVALID", {
                "observed": [TLV_NAMES.get(t, "0x%02x" % t)
                             for t in pdu.tlv_types],
            }))
        else:
            pdu.usable = True
    if reserved_nonzero:
        pdu.anomalies.append(Anomaly("LACP-RESERVED-NONZERO", {
            "note": "reserved octets in Actor/Partner/Collector TLV are non-zero",
        }))
    return pdu


def parse_marker(payload: bytes) -> MarkerPdu:
    """Bounds-checked Marker / Marker Response parse."""
    mk = MarkerPdu(version=payload[1] if len(payload) > 1 else -1,
                   tlv_type=-1, requester_port=0, requester_system=b"",
                   transaction_id=0)
    if len(payload) < 18:
        mk.anomalies.append(Anomaly("LACP-MARKER-MALFORMED", {
            "payload_len": len(payload), "reason": "too_short"}))
        return mk
    t = payload[2]
    ln = payload[3]
    if t not in (0x01, 0x02) or ln != 16:
        mk.anomalies.append(Anomaly("LACP-MARKER-MALFORMED", {
            "tlv_type": "0x%02x" % t, "length": ln, "expected_length": 16}))
        return mk
    mk.tlv_type = t
    mk.requester_port = struct.unpack_from("!H", payload, 4)[0]
    mk.requester_system = payload[6:12]
    mk.transaction_id = struct.unpack_from("!I", payload, 12)[0]
    mk.usable = True
    return mk


# ---------------------------------------------------------------------------
# Per-half state
# ---------------------------------------------------------------------------


@dataclass
class Half:
    """One transmitting end of one aggregation member link.

    Keyed by the actor identity (System ID, Key, Port Number) rather than by
    source MAC, so that a source-MAC change is observable as an event instead
    of silently creating a second, unrelated half.
    """
    key: Tuple[bytes, int, int]
    first_seen: float
    last_seen: float
    src_macs: Dict[bytes, float] = field(default_factory=dict)
    sys_prio: int = 0
    port_prio: int = 0
    actor_state: int = 0
    partner_state: int = 0
    version: int = 1
    partner_identity: Optional[Tuple[bytes, int, int]] = None
    synced_once: bool = False
    pdu_times: Deque[float] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    sync_transitions: Deque[float] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    timeout_changes: Deque[float] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    events: Deque[Tuple[float, str]] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    resyncs: int = 0
    pdus: int = 0
    initialised: bool = False

    @property
    def sys_id(self) -> bytes:
        return self.key[0]

    @property
    def oper_key(self) -> int:
        return self.key[1]

    @property
    def port_num(self) -> int:
        return self.key[2]

    def label(self, src: Optional[bytes] = None) -> str:
        mac = mac_str(src) if src is not None else (
            mac_str(next(iter(self.src_macs))) if self.src_macs else "??")
        return "%s sys=%s key=0x%04x port=%d" % (
            mac, mac_str(self.sys_id), self.oper_key, self.port_num)

    def tx_period(self) -> float:
        """Periodic transmission rate is set by the PARTNER's Timeout bit
        (802.1AX 6.4.13): a system transmits fast when its partner has
        requested Short Timeout."""
        return FAST_PERIOD_S if (self.partner_state & S_TIMEOUT) else SLOW_PERIOD_S

    def detect_time(self) -> float:
        return self.tx_period() * TIMEOUT_MULTIPLIER

    def lag_key(self) -> Tuple[Any, ...]:
        """Stable identifier for the aggregation this half belongs to."""
        mine = (self.sys_id, self.oper_key)
        theirs = (self.partner_identity[0], self.partner_identity[1]) \
            if self.partner_identity else (b"\x00" * 6, 0)
        return tuple(sorted([mine, theirs]))


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class LacpWatch:
    def __init__(self, sink=None, emit_info: bool = True,
                 partner_unobserved: bool = False):
        self.sink = sink
        self.emit_info = emit_info
        self.partner_unobserved = partner_unobserved
        self.findings: List[Dict[str, Any]] = []

        self.halves: Dict[Tuple[bytes, int, int], Half] = {}
        # Bounded: a source-MAC flood must not grow these without limit.
        self.mac_sysid: "OrderedDict[bytes, bytes]" = OrderedDict()
        self.sysport_key: "OrderedDict[Tuple[bytes, int], int]" = OrderedDict()
        self.claimants: Dict[Tuple[bytes, int, int], set] = {}
        self._claim_of: Dict[Tuple[bytes, int, int],
                             Optional[Tuple[bytes, int, int]]] = {}
        self._mismatch: Dict[Tuple[Any, ...], Tuple[float, int]] = {}
        self.lag_posture_seen: set = set()
        self.marker_times: Deque[float] = deque(maxlen=1024)
        self.bidirectional_confirmed = False

        self._rl: Dict[Tuple[str, Any], List[Any]] = {}
        self._orphan: Dict[str, Dict[bytes, float]] = {}
        self._orphan_rollup: Dict[str, float] = {}
        self._last_prune = 0.0

        self.stats: Dict[str, int] = {
            "frames": 0, "slow_frames": 0, "lacpdus": 0, "markers": 0,
            "other_subtypes": 0, "findings": 0, "suppressed": 0,
            "resyncs": 0, "parse_errors": 0, "pruned_halves": 0,
        }

    # -- emission ----------------------------------------------------------

    def _record(self, rec: Dict[str, Any]) -> None:
        self.findings.append(rec)
        self.stats["findings"] += 1
        if self.sink is not None:
            self.sink(rec)

    def emit(self, code: str, ts: float, key: Any = None, session: str = "",
             evidence: Optional[Dict[str, Any]] = None,
             orphan_src: Optional[bytes] = None) -> Optional[Dict[str, Any]]:
        spec = CODES.get(code)
        if spec is None:  # pragma: no cover - guarded by the reachability test
            raise KeyError("undeclared finding code: %s" % code)
        if spec["severity"] == SEV_INFO and not self.emit_info:
            return None

        if orphan_src is not None:
            seen = self._orphan.setdefault(code, {})
            for src, t in list(seen.items()):
                if ts - t > RATE_LIMIT_WINDOW_S:
                    del seen[src]
            seen[orphan_src] = ts
            if len(seen) > ORPHAN_CODE_BUDGET:
                last = self._orphan_rollup.get(code, -1e18)
                if ts - last <= RATE_LIMIT_WINDOW_S:
                    self.stats["suppressed"] += 1
                    return None
                self._orphan_rollup[code] = ts
                return self._record({
                    "ts": iso_ts(ts), "module": MODULE, "type": "finding",
                    "code": "LACP-ORPHAN-ROLLUP",
                    "severity": CODES["LACP-ORPHAN-ROLLUP"]["severity"],
                    "confidence": CODES["LACP-ORPHAN-ROLLUP"]["confidence"],
                    "title": CODES["LACP-ORPHAN-ROLLUP"]["title"],
                    "session": "-",
                    "evidence": {"rolled_up_code": code,
                                 "distinct_sources": len(seen),
                                 "window_s": RATE_LIMIT_WINDOW_S},
                }) or None

        rlkey = (code, key)
        slot = self._rl.get(rlkey)
        if slot is not None and ts - slot[0] <= RATE_LIMIT_WINDOW_S:
            slot[1] += 1
            self.stats["suppressed"] += 1
            return None
        suppressed = slot[1] if slot is not None else 0
        self._rl[rlkey] = [ts, 0]

        ev = dict(evidence or {})
        if suppressed:
            ev["suppressed_since_last"] = suppressed
        rec = {
            "ts": iso_ts(ts), "module": MODULE, "type": "finding",
            "code": code,
            "severity": spec["severity"],
            "confidence": spec["confidence"],
            "title": spec["title"],
            "session": session or "-",
            "evidence": ev,
        }
        self._record(rec)
        return rec

    def _half_event(self, half: Half, ts: float, code: str) -> None:
        half.events.append((ts, code))

    # -- entry points -------------------------------------------------------

    def on_frame(self, raw: bytes, ts: float) -> None:
        self.stats["frames"] += 1
        fr = decode_ethernet(raw, ts)
        if fr is None:
            return
        self.on_slow_frame(fr)

    def on_slow_frame(self, fr: Frame) -> None:
        self.stats["slow_frames"] += 1
        ts = fr.ts
        self._maybe_prune(ts)

        if fr.tags:
            self.emit("LACP-VLAN-TAGGED", ts, key=fr.src,
                      session=mac_str(fr.src),
                      evidence={"vlan_stack": fr.tags,
                                "dst": mac_str(fr.dst),
                                "note": "slow protocols are link-local and are "
                                        "never forwarded by a conformant bridge"},
                      orphan_src=fr.src)
        if fr.dst != SLOW_PROTOCOLS_GROUP_MAC:
            self.emit("LACP-NON-SLOW-DESTINATION", ts, key=fr.src,
                      session=mac_str(fr.src),
                      evidence={"dst": mac_str(fr.dst),
                                "expected": mac_str(SLOW_PROTOCOLS_GROUP_MAC)},
                      orphan_src=fr.src)

        if not fr.payload:
            self.stats["parse_errors"] += 1
            self.emit("LACP-MALFORMED-SHORT", ts, key=fr.src,
                      session=mac_str(fr.src),
                      evidence={"payload_len": 0}, orphan_src=fr.src)
            return

        subtype = fr.payload[0]
        if subtype == SUBTYPE_LACP:
            self.stats["lacpdus"] += 1
            self._on_lacpdu(fr)
        elif subtype == SUBTYPE_MARKER:
            self.stats["markers"] += 1
            self._on_marker(fr)
        else:
            self.stats["other_subtypes"] += 1
            self.emit("LACP-SLOW-PROTOCOL-SUBTYPE", ts, key=(fr.src, subtype),
                      session=mac_str(fr.src),
                      evidence={"subtype": "0x%02x" % subtype,
                                "name": SUBTYPE_NAMES.get(subtype, "unassigned"),
                                "payload_len": len(fr.payload)})

    # -- LACPDU handling ----------------------------------------------------

    def _on_lacpdu(self, fr: Frame) -> None:
        ts = fr.ts
        pdu = parse_lacpdu(fr.payload)
        session = mac_str(fr.src)
        for an in pdu.anomalies:
            self.stats["parse_errors"] += 1
            ev = dict(an.evidence)
            ev["src"] = mac_str(fr.src)
            self.emit(an.code, ts, key=(fr.src, an.code), session=session,
                      evidence=ev, orphan_src=fr.src)
        if not pdu.usable or pdu.actor is None or pdu.partner is None:
            return

        actor = pdu.actor
        partner = pdu.partner

        if actor.sys_id == b"\x00" * 6 or is_group_mac(actor.sys_id):
            self.emit("LACP-SYSTEM-ID-INVALID", ts, key=(fr.src, actor.sys_id),
                      session=session,
                      evidence={"sys_id": mac_str(actor.sys_id),
                                "src": mac_str(fr.src)},
                      orphan_src=fr.src)
            return
        if actor.port_num == 0:
            self.emit("LACP-PORT-NUMBER-ZERO", ts, key=(fr.src,),
                      session=session,
                      evidence={"actor": actor.as_dict(), "src": mac_str(fr.src)},
                      orphan_src=fr.src)

        self._check_mac_sysid(fr, actor, ts)
        self._check_key_change(fr, actor, ts)

        hkey = actor.identity
        half = self.halves.get(hkey)
        if half is None:
            half = Half(key=hkey, first_seen=ts, last_seen=ts)
            self.halves[hkey] = half
            self._first_sight(half, fr, pdu, ts)
            return
        self._update_half(half, fr, pdu, ts)

    def _check_mac_sysid(self, fr: Frame, actor: PortInfo, ts: float) -> None:
        prev = self.mac_sysid.get(fr.src)
        if prev is not None and prev != actor.sys_id:
            self.emit("LACP-SYSTEM-ID-CHANGE", ts, key=fr.src,
                      session=mac_str(fr.src),
                      evidence={"src": mac_str(fr.src),
                                "previous_sys_id": mac_str(prev),
                                "current_sys_id": mac_str(actor.sys_id)})
        self.mac_sysid[fr.src] = actor.sys_id
        self.mac_sysid.move_to_end(fr.src)
        while len(self.mac_sysid) > MAX_IDENTITY_MAP:
            self.mac_sysid.popitem(last=False)

    def _check_key_change(self, fr: Frame, actor: PortInfo, ts: float) -> None:
        sp = (actor.sys_id, actor.port_num)
        prev = self.sysport_key.get(sp)
        if prev is not None and prev != actor.key:
            self.emit("LACP-KEY-CHANGE", ts, key=sp,
                      session="%s sys=%s port=%d" % (
                          mac_str(fr.src), mac_str(actor.sys_id), actor.port_num),
                      evidence={"previous_key": prev, "current_key": actor.key,
                                "src": mac_str(fr.src),
                                "note": "operational Key selects the aggregator; "
                                        "a change moves the port between LAGs"})
        self.sysport_key[sp] = actor.key
        self.sysport_key.move_to_end(sp)
        while len(self.sysport_key) > MAX_IDENTITY_MAP:
            self.sysport_key.popitem(last=False)

    def _first_sight(self, half: Half, fr: Frame, pdu: Lacpdu, ts: float) -> None:
        """Record initial state. No transition findings on first sighting:
        Ragnar modules deploy instantly and must not alarm on the state of the
        world at t=0."""
        actor, partner = pdu.actor, pdu.partner
        half.src_macs[fr.src] = ts
        half.sys_prio = actor.sys_prio
        half.port_prio = actor.port_prio
        half.actor_state = actor.state
        half.partner_state = partner.state
        half.version = pdu.version
        half.partner_identity = None if partner.null else partner.identity
        half.synced_once = bool(actor.state & S_SYNC)
        half.pdu_times.append(ts)
        half.pdus = 1
        half.initialised = True
        half.last_seen = ts

        self.emit("LACP-MEMBER-OBSERVED", ts, key=half.key,
                  session=half.label(fr.src),
                  evidence={"actor": actor.as_dict(),
                            "partner": partner.as_dict(),
                            "version": pdu.version,
                            "collector_max_delay": pdu.collector_max_delay,
                            "src": mac_str(fr.src)})
        lag = half.lag_key()
        if lag not in self.lag_posture_seen:
            self.lag_posture_seen.add(lag)
            self.emit("LACP-UNAUTHENTICATED", ts, key=lag,
                      session=half.label(fr.src),
                      evidence={
                          "note": "IEEE 802.1AX defines no authentication for "
                                  "LACPDUs; any station on the segment can "
                                  "originate them. Mitigation is physical/port "
                                  "security, not protocol configuration.",
                          "actor_sys_id": mac_str(half.sys_id),
                          "key": half.oper_key})
        self._cross_view(half, fr, ts)

    def _update_half(self, half: Half, fr: Frame, pdu: Lacpdu, ts: float) -> None:
        actor, partner = pdu.actor, pdu.partner
        session = half.label(fr.src)

        gap = ts - half.last_seen
        threshold = max(half.detect_time() * OBSERVATION_GAP_FACTOR,
                        OBSERVATION_GAP_FLOOR_S)
        resync = gap > threshold
        if resync:
            half.resyncs += 1
            self.stats["resyncs"] += 1

        # --- source MAC identity ------------------------------------------
        if fr.src not in half.src_macs:
            if half.src_macs:
                others = sorted(half.src_macs.items(), key=lambda kv: kv[1])
                prev_mac, prev_ts = others[-1]
                recent = ts - prev_ts <= max(half.detect_time() * 2, 10.0)
                code = "LACP-PORT-IDENTITY-COLLISION" if recent \
                    else "LACP-ACTOR-MAC-CHANGE"
                self.emit(code, ts, key=half.key, session=session,
                          evidence={"actor": actor.as_dict(),
                                    "previous_src": mac_str(prev_mac),
                                    "current_src": mac_str(fr.src),
                                    "seconds_since_previous_src": round(ts - prev_ts, 3),
                                    "distinct_srcs": len(half.src_macs) + 1})
                self._half_event(half, ts, code)
                self._check_hijack(half, fr, ts)
        half.src_macs[fr.src] = ts

        # --- selection parameters ------------------------------------------
        if actor.sys_prio != half.sys_prio:
            if actor.sys_prio < half.sys_prio:
                self.emit("LACP-SYSTEM-PRIORITY-IMPROVED", ts, key=half.key,
                          session=session,
                          evidence={"previous_sys_prio": half.sys_prio,
                                    "current_sys_prio": actor.sys_prio,
                                    "src": mac_str(fr.src),
                                    "note": "numerically lower priority wins "
                                            "aggregation selection"})
                self._half_event(half, ts, "LACP-SYSTEM-PRIORITY-IMPROVED")
                self._check_hijack(half, fr, ts)
            half.sys_prio = actor.sys_prio
        if actor.port_prio != half.port_prio:
            if actor.port_prio < half.port_prio:
                self.emit("LACP-PORT-PRIORITY-IMPROVED", ts, key=half.key,
                          session=session,
                          evidence={"previous_port_prio": half.port_prio,
                                    "current_port_prio": actor.port_prio,
                                    "src": mac_str(fr.src)})
                self._half_event(half, ts, "LACP-PORT-PRIORITY-IMPROVED")
                self._check_hijack(half, fr, ts)
            half.port_prio = actor.port_prio

        if pdu.version != half.version:
            self.emit("LACP-VERSION-CHANGE", ts, key=half.key, session=session,
                      evidence={"previous_version": half.version,
                                "current_version": pdu.version,
                                "src": mac_str(fr.src)})
            half.version = pdu.version

        # --- state machine --------------------------------------------------
        prev = half.actor_state
        cur = actor.state
        if not resync and half.initialised:
            self._state_deltas(half, fr, prev, cur, ts, session)
        else:
            half.sync_transitions.clear()
        half.actor_state = cur
        half.partner_state = partner.state
        if cur & S_SYNC:
            half.synced_once = True

        # --- partner view ---------------------------------------------------
        new_partner = None if partner.null else partner.identity
        half.partner_identity = new_partner
        self._cross_view(half, fr, ts)

        # --- rate ------------------------------------------------------------
        half.pdu_times.append(ts)
        half.pdus += 1
        half.last_seen = ts
        self._check_burst(half, fr, ts, session)

    def _state_deltas(self, half: Half, fr: Frame, prev: int, cur: int,
                      ts: float, session: str) -> None:
        changed = prev ^ cur
        if changed & S_SYNC:
            half.sync_transitions.append(ts)
            window = [t for t in half.sync_transitions
                      if ts - t <= SYNC_FLAP_WINDOW_S]
            if len(window) >= SYNC_FLAP_THRESHOLD:
                self.emit("LACP-SYNC-FLAPPING", ts, key=half.key, session=session,
                          evidence={"transitions": len(window),
                                    "window_s": SYNC_FLAP_WINDOW_S,
                                    "state": state_str(cur),
                                    "src": mac_str(fr.src)})
                self._half_event(half, ts, "LACP-SYNC-FLAPPING")
                self._check_hijack(half, fr, ts)
            elif (prev & S_SYNC) and not (cur & S_SYNC) and half.synced_once:
                self.emit("LACP-SYNC-LOSS", ts, key=half.key, session=session,
                          evidence={"previous_state": state_str(prev),
                                    "current_state": state_str(cur),
                                    "src": mac_str(fr.src)})
                self._half_event(half, ts, "LACP-SYNC-LOSS")
                self._check_hijack(half, fr, ts)
        if (changed & (S_COLLECTING | S_DISTRIBUTING)) and (cur & S_SYNC):
            lost = [n for b, n in STATE_BITS
                    if b & (S_COLLECTING | S_DISTRIBUTING)
                    and (prev & b) and not (cur & b)]
            if lost:
                self.emit("LACP-DISTRIBUTING-LOSS", ts, key=half.key,
                          session=session,
                          evidence={"cleared": lost,
                                    "previous_state": state_str(prev),
                                    "current_state": state_str(cur),
                                    "src": mac_str(fr.src),
                                    "note": "member still synchronized but no "
                                            "longer carrying traffic"})
                self._half_event(half, ts, "LACP-DISTRIBUTING-LOSS")
                self._check_hijack(half, fr, ts)
        if (changed & S_AGGREGATION) and (prev & S_AGGREGATION) and not (cur & S_AGGREGATION):
            self.emit("LACP-AGGREGATION-CLEARED", ts, key=half.key, session=session,
                      evidence={"previous_state": state_str(prev),
                                "current_state": state_str(cur),
                                "src": mac_str(fr.src)})
            self._half_event(half, ts, "LACP-AGGREGATION-CLEARED")
            self._check_hijack(half, fr, ts)
        if (changed & S_DEFAULTED) and (cur & S_DEFAULTED):
            self.emit("LACP-DEFAULTED-PARTNER-INFO", ts, key=half.key,
                      session=session,
                      evidence={"current_state": state_str(cur),
                                "src": mac_str(fr.src),
                                "note": "actor stopped receiving valid LACPDUs "
                                        "and reverted to configured defaults"})
            self._half_event(half, ts, "LACP-DEFAULTED-PARTNER-INFO")
            self._check_hijack(half, fr, ts)
        if (changed & S_EXPIRED) and (cur & S_EXPIRED):
            self.emit("LACP-RECEIVE-EXPIRED", ts, key=half.key, session=session,
                      evidence={"current_state": state_str(cur),
                                "src": mac_str(fr.src)})
            self._half_event(half, ts, "LACP-RECEIVE-EXPIRED")
            self._check_hijack(half, fr, ts)
        if changed & S_TIMEOUT:
            half.timeout_changes.append(ts)
            window = [t for t in half.timeout_changes
                      if ts - t <= TIMEOUT_FLAP_WINDOW_S]
            if len(window) >= TIMEOUT_FLAP_THRESHOLD:
                self.emit("LACP-TIMEOUT-FLAPPING", ts, key=half.key,
                          session=session,
                          evidence={"changes": len(window),
                                    "window_s": TIMEOUT_FLAP_WINDOW_S,
                                    "src": mac_str(fr.src)})
            else:
                self.emit("LACP-TIMEOUT-CHANGE", ts, key=half.key, session=session,
                          evidence={"previous": "short" if prev & S_TIMEOUT else "long",
                                    "current": "short" if cur & S_TIMEOUT else "long",
                                    "src": mac_str(fr.src),
                                    "note": "changes the detection time this "
                                            "system applies to its partner"})
        if changed & S_ACTIVITY:
            self.emit("LACP-ACTIVITY-CHANGE", ts, key=half.key, session=session,
                      evidence={"previous": "active" if prev & S_ACTIVITY else "passive",
                                "current": "active" if cur & S_ACTIVITY else "passive",
                                "src": mac_str(fr.src)})

    def _check_burst(self, half: Half, fr: Frame, ts: float, session: str) -> None:
        window = [t for t in half.pdu_times if ts - t <= BURST_WINDOW_S]
        expected = BURST_WINDOW_S / half.tx_period()
        threshold = max(BURST_FLOOR, int(BURST_MULTIPLIER * expected))
        if len(window) > threshold:
            self.emit("LACP-PDU-BURST", ts, key=half.key, session=session,
                      evidence={"pdus_in_window": len(window),
                                "window_s": BURST_WINDOW_S,
                                "expected_period_s": half.tx_period(),
                                "threshold": threshold,
                                "src": mac_str(fr.src)})

    def _cross_view(self, half: Half, fr: Frame, ts: float) -> None:
        """Mutual-view check.

        Identity only: what A says its partner is, versus what that partner
        advertises as its own actor identity. Deliberately NOT a state
        comparison - Actor/Partner state disagreement is normal and transient
        during convergence, and alerting on it would fire on every link event.

        Both directions are examined, because the half that arrives second is
        usually the one that reveals the disagreement.
        """
        pid = half.partner_identity
        prev = self._claim_of.get(half.key)
        if prev != pid:
            if prev is not None:
                s = self.claimants.get(prev)
                if s is not None:
                    s.discard(half.key)
                    if not s:
                        del self.claimants[prev]
            if pid is not None:
                self.claimants.setdefault(pid, set()).add(half.key)
            self._claim_of[half.key] = pid

        if pid is not None:
            other = self.halves.get(pid)
            if other is None:
                if self.partner_unobserved and self.bidirectional_confirmed:
                    self.emit("LACP-PARTNER-UNOBSERVED", ts, key=(half.key, pid),
                              session=half.label(fr.src),
                              evidence={"claimed_partner_sys_id": mac_str(pid[0]),
                                        "claimed_partner_key": pid[1],
                                        "claimed_partner_port": pid[2],
                                        "note": "asymmetric taps make this weak; "
                                                "gated on prior bidirectional proof"})
            else:
                self._pair_check(half, other, fr, ts)

        for ck in list(self.claimants.get(half.key, ())):
            claimant = self.halves.get(ck)
            if claimant is not None and claimant.key != half.key:
                self._pair_check(claimant, half, fr, ts)

    def _pair_check(self, a: Half, b: Half, fr: Frame, ts: float) -> None:
        if a.partner_identity is None or b.partner_identity is None:
            return
        a_ok = a.partner_identity == b.key
        b_ok = b.partner_identity == a.key
        pair = tuple(sorted([a.key, b.key]))
        if a_ok and b_ok:
            self.bidirectional_confirmed = True
            self._mismatch.pop(pair, None)
            return
        if not (a_ok or b_ok):
            return  # unrelated halves, not a candidate pair at all
        wrong = b if a_ok else a
        right = a if a_ok else b
        # Persistence gate. A half that has simply not transmitted since the
        # other end was reconfigured holds a STALE view, not a contradicted
        # one, and a stale view is not evidence of a third party. Require the
        # contradicting half to keep asserting its claim - across at least
        # MISMATCH_MIN_PDUS further PDUs and its own detection time - before
        # this is reported.
        state = self._mismatch.get(pair)
        if state is None:
            self._mismatch[pair] = (ts, wrong.pdus)
            return
        first_ts, first_pdus = state
        if (wrong.pdus - first_pdus) < MISMATCH_MIN_PDUS:
            return
        if (ts - first_ts) < wrong.detect_time():
            return
        self.emit("LACP-PARTNER-VIEW-MISMATCH", ts,
                  key=tuple(sorted([a.key, b.key])),
                  session=wrong.label(),
                  evidence={
                      "consistent_half": {"sys_id": mac_str(right.sys_id),
                                          "key": right.oper_key,
                                          "port": right.port_num},
                      "contradicting_half": {"sys_id": mac_str(wrong.sys_id),
                                             "key": wrong.oper_key,
                                             "port": wrong.port_num},
                      "contradicting_half_claims": {
                          "sys_id": mac_str(wrong.partner_identity[0]),
                          "key": wrong.partner_identity[1],
                          "port": wrong.partner_identity[2]},
                      "persisted_s": round(ts - first_ts, 3),
                      "persisted_pdus": wrong.pdus - first_pdus,
                      "note": "the two ends do not agree they are aggregating "
                              "with each other; a third station is supplying "
                              "partner information to at least one side"})
        for h in (a, b):
            self._half_event(h, ts, "LACP-PARTNER-VIEW-MISMATCH")
        self._check_hijack(wrong, fr, ts)

    def _check_hijack(self, half: Half, fr: Frame, ts: float) -> None:
        recent = [(t, c) for t, c in half.events if ts - t <= CORRELATION_WINDOW_S]
        codes = {c for _, c in recent}
        ident = sorted(codes & IDENTITY_CODES)
        disr = sorted(codes & DISRUPTION_CODES)
        if not ident or not disr:
            return
        self.emit("LACP-LAG-HIJACK", ts, key=half.key,
                  session=half.label(fr.src),
                  evidence={"correlated_codes": ident + disr,
                            "window_s": CORRELATION_WINDOW_S,
                            "actor_sys_id": mac_str(half.sys_id),
                            "key": half.oper_key,
                            "port": half.port_num,
                            "distinct_srcs": [mac_str(m) for m in half.src_macs],
                            "note": "aggregation selection parameters were "
                                    "manipulated and the member was disrupted "
                                    "inside the same window"})

    # -- marker -------------------------------------------------------------

    def _on_marker(self, fr: Frame) -> None:
        ts = fr.ts
        mk = parse_marker(fr.payload)
        session = mac_str(fr.src)
        for an in mk.anomalies:
            self.stats["parse_errors"] += 1
            ev = dict(an.evidence)
            ev["src"] = mac_str(fr.src)
            self.emit(an.code, ts, key=(fr.src, an.code), session=session,
                      evidence=ev, orphan_src=fr.src)
        if not mk.usable:
            return
        if mk.tlv_type == 0x01:
            self.marker_times.append(ts)
            window = [t for t in self.marker_times
                      if ts - t <= MARKER_BURST_WINDOW_S]
            if len(window) > MARKER_BURST_THRESHOLD:
                self.emit("LACP-MARKER-FLOOD", ts, key=fr.src, session=session,
                          evidence={"requests_in_window": len(window),
                                    "window_s": MARKER_BURST_WINDOW_S,
                                    "threshold": MARKER_BURST_THRESHOLD,
                                    "src": mac_str(fr.src),
                                    "note": "Marker Requests pause frame "
                                            "distribution while the LAG drains"})
        known = {k[0] for k in self.halves}
        if self.halves and mk.requester_system not in known:
            self.emit("LACP-MARKER-UNKNOWN-REQUESTER", ts,
                      key=(fr.src, mk.requester_system), session=session,
                      evidence={"requester_system": mac_str(mk.requester_system),
                                "requester_port": mk.requester_port,
                                "transaction_id": mk.transaction_id,
                                "src": mac_str(fr.src),
                                "known_systems": sorted(mac_str(k) for k in known)},
                      orphan_src=fr.src)

    # -- housekeeping -------------------------------------------------------

    def _maybe_prune(self, ts: float) -> None:
        if ts - self._last_prune < PRUNE_INTERVAL_S:
            return
        self._last_prune = ts
        stale = [k for k, h in self.halves.items()
                 if ts - h.last_seen > HALF_IDLE_TTL_S]
        for k in stale:
            del self.halves[k]
        self.stats["pruned_halves"] += len(stale)
        live = set(self.halves)
        for pair in [p for p in self._mismatch if not set(p) <= live]:
            del self._mismatch[pair]
        for code, seen in list(self._orphan.items()):
            for src, t in list(seen.items()):
                if ts - t > RATE_LIMIT_WINDOW_S:
                    del seen[src]
            if not seen:
                del self._orphan[code]
        for rlkey, slot in list(self._rl.items()):
            if ts - slot[0] > max(RATE_LIMIT_WINDOW_S * 4, HALF_IDLE_TTL_S):
                del self._rl[rlkey]

    def summary(self, ts: Optional[float] = None,
                reason: str = "eof") -> Dict[str, Any]:
        ts = time.time() if ts is None else ts
        sev: Dict[str, int] = {}
        for f in self.findings:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        return {
            "ts": iso_ts(ts), "module": MODULE, "type": "summary",
            "version": __version__, "stopped_on": reason,
            "stats": dict(self.stats),
            "halves": len(self.halves),
            "lags": len(self.lag_posture_seen),
            "by_severity": sev,
        }


# ---------------------------------------------------------------------------
# Capture sources. No third-party dependencies: a libpcap reader for offline
# work and AF_PACKET for live work.
# ---------------------------------------------------------------------------


class PcapError(Exception):
    pass


def read_pcap(path: str):
    """Yield (raw_frame, ts) from a classic libpcap file. Linktype must be
    Ethernet (1). pcapng is rejected with an explicit message rather than
    silently mis-parsed."""
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            raise PcapError("%s: file shorter than a pcap global header" % path)
        magic = gh[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            raise PcapError(
                "%s: this is pcapng, not classic pcap. Convert with "
                "`editcap -F pcap in.pcapng out.pcap`." % path)
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, nano = ">", True
        else:
            raise PcapError("%s: not a pcap file (magic %s)" % (path, hexs(magic)))
        network = struct.unpack(endian + "I", gh[20:24])[0]
        if network != 1:
            raise PcapError("%s: linktype %d is not Ethernet" % (path, network))
        rec_fmt = endian + "IIII"
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                return
            ts_sec, ts_frac, incl, orig = struct.unpack(rec_fmt, hdr)
            data = fh.read(incl)
            if len(data) < incl:
                return
            ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            yield data, ts


def write_pcap(path: str, frames: Sequence[Tuple[bytes, float]]) -> None:
    """Used by the self-test to produce a corpus. Writes only to a file the
    caller names; nothing is ever transmitted."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for raw, ts in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1000000:
                sec += 1
                usec -= 1000000
            fh.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            fh.write(raw)


class _Shutdown:
    """Cooperative stop flag. The capture loop always uses a bounded recv
    timeout so it can observe this between frames, which is what lets a mesh
    supervisor's SIGTERM produce a clean summary and exit 0."""

    def __init__(self) -> None:
        self.stop = False
        self.reason = "eof"

    def install(self) -> None:
        for sig, name in ((signal.SIGTERM, "sigterm"),
                          (signal.SIGINT, "sigint"),
                          (signal.SIGHUP, "sighup")):
            try:
                signal.signal(sig, self._handler(name))
            except (ValueError, OSError, AttributeError):  # pragma: no cover
                pass

    def _handler(self, name: str):
        def _h(signum, frame):  # noqa: ARG001
            self.stop = True
            self.reason = name
        return _h


def live_capture(engine: "LacpWatch", iface: str, shutdown: _Shutdown,
                 all_frames: bool = False, heartbeat: float = 0.0,
                 emit=lambda rec: None) -> None:
    import socket  # stdlib; imported here so --self-test needs no sockets

    ETH_P_ALL = 0x0003
    proto = ETH_P_ALL if all_frames else ETH_P_SLOW
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(proto))
    try:
        sock.bind((iface, 0))
        sock.settimeout(0.5)
        last_hb = time.time()
        while not shutdown.stop:
            try:
                raw = sock.recv(65535)
            except socket.timeout:
                raw = None
            except OSError as exc:  # pragma: no cover
                print("lacpwatch: recv failed: %s" % exc, file=sys.stderr)
                break
            if raw:
                engine.on_frame(raw, time.time())
            if heartbeat:
                now = time.time()
                if now - last_hb >= heartbeat:
                    last_hb = now
                    emit({"ts": iso_ts(now), "module": MODULE,
                          "type": "heartbeat", "stats": dict(engine.stats),
                          "halves": len(engine.halves)})
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _make_sink(jsonl: Optional[str]):
    if jsonl in (None, "-", ""):
        stream = sys.stdout
        closer = None
    else:
        stream = open(jsonl, "a", encoding="utf-8")
        closer = stream

    def sink(rec: Dict[str, Any]) -> None:
        stream.write(json.dumps(rec, sort_keys=True) + "\n")
        stream.flush()

    return sink, closer


# ===========================================================================
# In-app adapter (Ragnar): a snapshot-over-pcap wrapper around the streaming
# engine above, plus a Watchtower JSON-lines feed and an aggregator-shaped
# selftest(). The engine is fed captured frames in timestamp order, which is
# exactly what its --pcap mode already does, so the detectors (flap windows,
# burst, LAG-HIJACK correlation) work across the capture window unchanged.
# Detection-only: nothing here ever transmits.
# ===========================================================================

import subprocess       # noqa: E402  (adapter block, stdlib)
import tempfile         # noqa: E402
from datetime import datetime, timezone   # noqa: E402

# --- packet builders (copied from the module's own test scaffolding so the
#     in-app selftest can craft frames without the CLI harness) --------------
SLOW = SLOW_PROTOCOLS_GROUP_MAC


def b_port(sys_prio=32768, sys_id=b"\x00\x11\x22\x33\x44\x55", key=0x0001,
           port_prio=32768, port_num=1, state=0x3D, reserved=b"\x00\x00\x00"):
    return struct.pack("!H6sHHHB", sys_prio, sys_id, key, port_prio,
                       port_num, state) + reserved


def b_lacpdu(actor, partner, version=1, collector_delay=0, actor_len=20,
             partner_len=20, collector=True, terminator=True, pad=50,
             trailing=b"", extra_tlvs=b"", swap_order=False):
    out = bytes([SUBTYPE_LACP, version])
    a = bytes([TLV_ACTOR, actor_len]) + actor
    p = bytes([TLV_PARTNER, partner_len]) + partner
    out += (p + a) if swap_order else (a + p)
    if collector:
        out += bytes([TLV_COLLECTOR, 16]) + struct.pack("!H", collector_delay) + b"\x00" * 12
    out += extra_tlvs
    if terminator:
        out += bytes([TLV_TERMINATOR, 0])
        out += b"\x00" * pad
    if trailing:
        out = (out[:len(out) - len(trailing)] + trailing
               if pad >= len(trailing) else out + trailing)
    return out


def b_marker(tlv_type=0x01, requester_port=1,
             requester_system=b"\x00\x11\x22\x33\x44\x55", txn=1,
             length=16, version=1):
    return (bytes([SUBTYPE_MARKER, version, tlv_type, length])
            + struct.pack("!H6sI", requester_port, requester_system, txn)
            + b"\x00\x00" + bytes([TLV_TERMINATOR, 0]) + b"\x00" * 90)


def b_frame(payload, src=b"\x00\xaa\xbb\xcc\xdd\x01", dst=SLOW, tags=()):
    out = dst + src
    for tci in tags:
        out += struct.pack("!HH", 0x8100, tci)
    out += struct.pack("!H", ETH_P_SLOW) + payload
    return out


_SEV_RANK = {SEV_INFO: 0, SEV_LOW: 1, SEV_MEDIUM: 2, SEV_HIGH: 3, SEV_CRITICAL: 4}
# Verdicts, worst first. A finding maps to a verdict by its code; the run's
# verdict is the worst finding's verdict.
_HIJACK_CODES = frozenset({"LACP-LAG-HIJACK"})
_TAKEOVER_CODES = IDENTITY_CODES | {
    "LACP-NON-SLOW-DESTINATION", "LACP-VLAN-TAGGED", "LACP-SYNC-FLAPPING"}
# everything else at >= medium is 'instability'; low/info only is 'clean'.


def _verdict_for(findings):
    """Reduce a finding list to a single card verdict + the codes that drove it."""
    ranked = sorted(findings, key=lambda f: _SEV_RANK.get(f["severity"], 0),
                    reverse=True)
    codes = [f["code"] for f in ranked]
    codeset = set(codes)
    if codeset & _HIJACK_CODES:
        return "lag-hijack", ranked
    if codeset & _TAKEOVER_CODES:
        return "takeover", ranked
    if any(_SEV_RANK.get(f["severity"], 0) >= 2 for f in findings):
        return "instability", ranked
    return "clean", ranked


# --- Watchtower feed --------------------------------------------------------
_WT_LOG_DIR = os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_WT_DEDUP_S = 300.0
_WT_EMIT_SEV = frozenset((SEV_HIGH, SEV_CRITICAL))   # only the pageable set
_wt_lock = None
_wt_seen = {}


def _emit_watchtower(result):
    """Append HIGH/CRITICAL LACP findings to <log-dir>/lacp_watch.jsonl in the shape
    Watchtower.normalize() reads, so aggregation-hijack / delivery-path / flapping
    alerts fold into the unified pane + single Pushover path. Deduped per (code,
    session) over the window. Best-effort; never raises."""
    global _wt_lock
    if _wt_lock is None:
        import threading
        _wt_lock = threading.Lock()
    if not result.get("success"):
        return
    verdict = result.get("verdict", "clean")
    iface = result.get("interface")
    now = time.time()
    iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    with _wt_lock:
        for f in result.get("findings", []):
            if f.get("severity") not in _WT_EMIT_SEV:
                continue
            code = f.get("code")
            sess = f.get("session")
            key = (code, sess)
            last = _wt_seen.get(key)
            if last is not None and now - last < _WT_DEDUP_S:
                continue
            _wt_seen[key] = now
            lines.append(json.dumps({
                "module": "lacp_watch", "ts": now, "iso": iso, "iface": iface,
                "severity": f.get("severity"), "code": code, "codes": [code],
                "src": sess, "summary": f.get("title"), "verdict": verdict}))
        if len(_wt_seen) > 4096:
            cutoff = now - _WT_DEDUP_S
            for k in [k for k, t in _wt_seen.items() if t < cutoff]:
                _wt_seen.pop(k, None)
    if not lines:
        return
    try:
        os.makedirs(_WT_LOG_DIR, exist_ok=True)
        with open(os.path.join(_WT_LOG_DIR, "lacp_watch.jsonl"), "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


# --- capture ----------------------------------------------------------------
# Slow-protocol frames are EtherType 0x8809; a VLAN-tagged LACPDU (itself a
# finding) carries 0x8100 then 0x8809. Catch both. Group MAC filtering is left
# to the engine so a non-slow-destination LACPDU (also a finding) is still seen.
_LACP_BPF = ("ether proto 0x8809 or "
             "(ether[12:2] = 0x8100 and ether[16:2] = 0x8809)")


def _capture_pcap(interface, seconds):
    """tcpdump a slow-protocols snapshot to a temp classic-pcap file.
    Returns (path, error). Detection-only: -p (no promisc changes beyond what
    the kernel already does), no transmit."""
    from shutil import which
    if not which("tcpdump"):
        return None, "tcpdump is not installed. Click Install to add it."
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        res = subprocess.run(
            ["timeout", str(int(seconds) + 3), "tcpdump", "-i", interface,
             "-nn", "-s", "256", "-c", "20000", "-w", path, _LACP_BPF],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=int(seconds) + 8)
        err = (res.stderr or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        err = ""
    except OSError as e:
        try:
            os.remove(path)
        except OSError:
            pass
        return None, "capture failed: {}".format(e)
    if (os.path.getsize(path) <= 24 and err
            and any(s in err.lower() for s in
                    ("permission", "no such device", "syntax error", "couldn't"))):
        try:
            os.remove(path)
        except OSError:
            pass
        return None, err.strip()[:200]
    return path, None


def do_lacp_watch(interface=None, seconds=20):
    """Passive LACP / Marker slow-protocol integrity scan (detection-only). One
    tcpdump snapshot on `interface`, replayed through the streaming engine; reports
    aggregation hijack (identity manipulation correlated with member disruption),
    delivery-path anomalies (VLAN-tagged / non-group-MAC LACPDUs), malformed PDUs,
    state-machine instability (sync/timeout flapping, distributing loss), and Marker
    floods. Streams HIGH/CRITICAL findings to Watchtower. Never transmits an LACPDU."""
    if not interface:
        return {"success": False, "error": "no interface specified"}
    seconds = max(8, min(int(seconds or 20), 60))
    path, err = _capture_pcap(interface, seconds)
    if err:
        return {"success": False, "interface": interface, "error": err,
                "missing_tool": "tcpdump" if "not installed" in err else None}
    eng = LacpWatch(emit_info=True)
    try:
        for raw, ts in read_pcap(path):
            eng.on_frame(raw, ts)
    except PcapError as e:
        return {"success": False, "interface": interface,
                "error": "could not read capture: {}".format(e)}
    except Exception as e:
        return {"success": False, "interface": interface,
                "error": "capture parse failed: {}".format(type(e).__name__)}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    findings = eng.findings
    verdict, ranked = _verdict_for(findings)
    # Reasons: the distinct actionable findings (>= medium), worst first, deduped
    # by code, capped — plus a clean line when only posture/inventory surfaced.
    reasons, seen = [], set()
    for f in ranked:
        if _SEV_RANK.get(f["severity"], 0) < 2:
            continue
        if f["code"] in seen:
            continue
        seen.add(f["code"])
        reasons.append("{}: {} [{}]".format(f["code"], f["title"], f["session"]))
        if len(reasons) >= 8:
            break
    if not reasons:
        if eng.stats.get("lacpdus") or eng.stats.get("markers"):
            reasons = ["LACP members observed; no delivery, identity, "
                       "state-machine or Marker anomaly detected"]
        else:
            reasons = ["No LACP / Marker slow-protocol traffic seen on this segment"]

    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    result = {
        "success": True, "interface": interface, "seconds": seconds,
        "verdict": verdict, "reasons": reasons,
        "findings": findings,
        "members": len(eng.halves), "lags": len(eng.lag_posture_seen),
        "by_severity": by_sev, "stats": dict(eng.stats),
    }
    _emit_watchtower(result)
    return result


# --- selftest (aggregator shape: {'success', 'scenarios':[{name,pass,detail}]}) ---
def _run_frames(frames, **kw):
    eng = LacpWatch(**kw)
    for raw, ts in frames:
        eng.on_frame(raw, ts)
    return eng


def selftest():
    """Build real slow-protocol frames, feed them through the engine, and assert the
    findings. Returns the aggregator scenario shape. No sockets, no capture, no
    persistence — asserted by construction (the engine only reads bytes)."""
    scen = []

    def check(name, ok, detail=""):
        scen.append({"name": name, "pass": bool(ok), "detail": detail})

    def codes_of(eng):
        return [f["code"] for f in eng.findings]

    base = b_port(state=0x3D)                       # act,timeout,agg,sync,coll,dist
    partner = b_port(sys_id=b"\x00\x22\x33\x44\x55\x66", port_num=2, state=0x3D)

    # 1. Clean bidirectional LAG stays silent (only info/low posture).
    frA = b_frame(b_lacpdu(base, partner), src=b"\x00\xaa\x01\x01\x01\x01")
    frB = b_frame(b_lacpdu(partner, base), src=b"\x00\xaa\x01\x01\x01\x02")
    e = _run_frames([(frA, 1.0), (frB, 1.1), (frA, 2.0), (frB, 2.1)])
    actionable = [c for c in codes_of(e)
                  if _SEV_RANK.get(CODES[c]["severity"], 0) >= 2]
    check("clean-lag-silent", not actionable, "actionable=%s" % actionable)

    # 2. VLAN-tagged LACPDU -> LACP-VLAN-TAGGED (high, delivery path).
    e = _run_frames([(b_frame(b_lacpdu(base, partner), tags=(100,)), 1.0)])
    check("vlan-tagged", "LACP-VLAN-TAGGED" in codes_of(e), codes_of(e))

    # 3. Wrong destination MAC -> LACP-NON-SLOW-DESTINATION (high).
    e = _run_frames([(b_frame(b_lacpdu(base, partner),
                              dst=b"\x00\xde\xad\xbe\xef\x99"), 1.0)])
    check("non-slow-destination",
          "LACP-NON-SLOW-DESTINATION" in codes_of(e), codes_of(e))

    # 4. TLV length violation -> LACP-TLV-LENGTH-INVALID (medium).
    e = _run_frames([(b_frame(b_lacpdu(base, partner, actor_len=18)), 1.0)])
    check("tlv-length-invalid",
          "LACP-TLV-LENGTH-INVALID" in codes_of(e), codes_of(e))

    # 5. Null/group actor System ID -> LACP-SYSTEM-ID-INVALID (medium).
    e = _run_frames([(b_frame(b_lacpdu(b_port(sys_id=b"\x00" * 6), partner)), 1.0)])
    check("system-id-invalid",
          "LACP-SYSTEM-ID-INVALID" in codes_of(e), codes_of(e))

    # 6. Trailing non-zero after Terminator -> LACP-TRAILING-DATA (medium).
    e = _run_frames([(b_frame(b_lacpdu(base, partner, trailing=b"\x41\x42\x43\x44")), 1.0)])
    check("trailing-data", "LACP-TRAILING-DATA" in codes_of(e), codes_of(e))

    # 7. Same actor identity from a second source MAC quickly -> COLLISION (high).
    fr1 = b_frame(b_lacpdu(base, partner), src=b"\x00\xaa\x01\x01\x01\x01")
    fr2 = b_frame(b_lacpdu(base, partner), src=b"\x00\xbb\x02\x02\x02\x02")
    e = _run_frames([(fr1, 1.0), (fr2, 1.5)])
    check("port-identity-collision",
          "LACP-PORT-IDENTITY-COLLISION" in codes_of(e), codes_of(e))

    # 8. Actor System Priority improved mid-session -> takeover signal (high).
    fr_hi = b_frame(b_lacpdu(b_port(sys_prio=100), partner),
                    src=b"\x00\xaa\x01\x01\x01\x01")
    e = _run_frames([(fr1, 1.0), (fr1, 2.0), (fr_hi, 3.0)])
    check("system-priority-improved",
          "LACP-SYSTEM-PRIORITY-IMPROVED" in codes_of(e), codes_of(e))

    # 9. Sync flapping: repeated SYNC transitions in-window -> LACP-SYNC-FLAPPING (high).
    on = b_frame(b_lacpdu(b_port(state=0x3D), partner), src=b"\x00\xaa\x01\x01\x01\x01")
    off = b_frame(b_lacpdu(b_port(state=0x35), partner), src=b"\x00\xaa\x01\x01\x01\x01")  # sync cleared
    frames = [(on, 1.0)]
    t = 2.0
    for _ in range(6):
        frames.append((off, t)); t += 1.0
        frames.append((on, t)); t += 1.0
    e = _run_frames(frames)
    check("sync-flapping", "LACP-SYNC-FLAPPING" in codes_of(e), codes_of(e))

    # 10. Aggregation bit cleared on an established member -> AGGREGATION-CLEARED.
    indiv = b_frame(b_lacpdu(b_port(state=0x39), partner),  # aggregation bit off
                    src=b"\x00\xaa\x01\x01\x01\x01")
    e = _run_frames([(on, 1.0), (on, 2.0), (indiv, 3.0)])
    check("aggregation-cleared",
          "LACP-AGGREGATION-CLEARED" in codes_of(e), codes_of(e))

    # 11. Marker flood -> LACP-MARKER-FLOOD (medium).
    mk = b_frame(b_marker(), src=b"\x00\xaa\x01\x01\x01\x01")
    frames, t = [], 1.0
    for _ in range(MARKER_BURST_THRESHOLD + 3):
        frames.append((mk, t)); t += 0.1
    e = _run_frames(frames)
    check("marker-flood", "LACP-MARKER-FLOOD" in codes_of(e), codes_of(e))

    # 12. Malformed Marker PDU -> LACP-MARKER-MALFORMED (medium).
    e = _run_frames([(b_frame(b_marker(length=8)), 1.0)])
    check("marker-malformed", "LACP-MARKER-MALFORMED" in codes_of(e), codes_of(e))

    # 13. Non-LACP slow-protocol subtype (e.g. OAM) -> LACP-SLOW-PROTOCOL-SUBTYPE (info).
    e = _run_frames([(b_frame(bytes([SUBTYPE_OAM, 1]) + b"\x00" * 60), 1.0)])
    check("slow-protocol-subtype",
          "LACP-SLOW-PROTOCOL-SUBTYPE" in codes_of(e), codes_of(e))

    # 14. Operational Key change for a stable system/port -> LACP-KEY-CHANGE (medium).
    k1 = b_frame(b_lacpdu(b_port(key=0x0001), partner), src=b"\x00\xaa\x01\x01\x01\x01")
    k2 = b_frame(b_lacpdu(b_port(key=0x0002), partner), src=b"\x00\xaa\x01\x01\x01\x01")
    e = _run_frames([(k1, 1.0), (k2, 2.0)])
    check("key-change", "LACP-KEY-CHANGE" in codes_of(e), codes_of(e))

    # 15. LAG-HIJACK correlation: identity manipulation + disruption in one window.
    #     Priority-improved (identity) then sync-loss (disruption) on same member.
    est = b_frame(b_lacpdu(b_port(sys_prio=32768, state=0x3D), partner),
                  src=b"\x00\xaa\x01\x01\x01\x01")
    prio = b_frame(b_lacpdu(b_port(sys_prio=100, state=0x3D), partner),
                   src=b"\x00\xaa\x01\x01\x01\x01")
    syncloss = b_frame(b_lacpdu(b_port(sys_prio=100, state=0x35), partner),
                       src=b"\x00\xaa\x01\x01\x01\x01")
    e = _run_frames([(est, 1.0), (est, 2.0), (prio, 3.0), (syncloss, 4.0)])
    check("lag-hijack-correlated",
          "LACP-LAG-HIJACK" in codes_of(e), codes_of(e))

    # 16. do_lacp_watch verdict mapping over the hijack scenario (offline, no capture):
    #     reuse the engine result path by classifying the findings directly.
    v, _ = _verdict_for(e.findings)
    check("verdict-lag-hijack", v == "lag-hijack", "verdict=%s" % v)

    # 17. Clean scenario classifies as 'clean'.
    e2 = _run_frames([(frA, 1.0), (frB, 1.1), (frA, 2.0), (frB, 2.1)])
    v2, _ = _verdict_for(e2.findings)
    check("verdict-clean", v2 == "clean", "verdict=%s" % v2)

    # 18. Every declared code carries a known severity (catalogue integrity).
    bad = [c for c, s in CODES.items() if s["severity"] not in _SEV_RANK]
    check("catalogue-severity-integrity", not bad, "bad=%s" % bad)

    return {"success": all(s["pass"] for s in scen), "scenarios": scen}


if __name__ == "__main__":       # pragma: no cover - manual smoke test
    import pprint
    r = selftest()
    pprint.pprint([s for s in r["scenarios"] if not s["pass"]] or "ALL PASS")
    print("success:", r["success"])
