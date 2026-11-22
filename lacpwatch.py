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
import re
import signal
import struct
import sys
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

__version__ = "0.2.0-dev"
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
MALFORMED_FLAP_WINDOW_S = 30.0    # malformed PDU -> induced flap correlation.
                                  # Deliberately short: in CVE-2024-30388 the
                                  # flap follows receipt immediately, so a wide
                                  # window would only buy coincidences.
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
    "LACP-MALFORMED-INDUCED-FLAP": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "Malformed LACPDU followed by member flap (CVE-2024-30388 class)"},
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
# Parse failures that a vulnerable forwarding engine may act on. Used by the
# malformed-induced-flap correlator, NOT by the hijack correlator.
MALFORMED_CODES = frozenset({
    "LACP-MALFORMED-SHORT",
    "LACP-TLV-LENGTH-INVALID",
    "LACP-TLV-ORDER-INVALID",
    "LACP-BAD-VERSION",
})
# Disruptions that a malformed PDU could plausibly have induced.
INDUCED_DISRUPTION_CODES = frozenset({
    "LACP-SYNC-FLAPPING",
    "LACP-SYNC-LOSS",
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
# PAgP (abuse / semantics half) and PFC/PAUSE tiers
#
# Two additional L2 tiers that ride alongside the LACP engine.
#
# PAgP -- Cisco's proprietary sibling to 802.1AX. This module owns the
# ABUSE/SEMANTICS half only: aggregation identity, partner view, bundle state.
# The TRANSPORT/STRUCTURAL half (presence, TLV bounds, oversized/trailing,
# truncated header, declared-vs-present TLV count) is owned by cdpwatch, which
# shares the CDP-family destination MAC and SNAP grammar. The split is
# deliberate and reciprocal: cdpwatch reads no partner state and renders no
# aggregation verdict; this tier emits NO structural findings at all. A
# malformed PAgP frame is counted and dropped here, never double-reported.
#
# Code naming: cdpwatch already owns the numeric PAGP-0NN space (PAGP-001,
# PAGP-040..045). These codes are DESCRIPTIVE for exactly that reason -- two
# modules reporting into one pipeline must never collide on a code string.
#
# PFC/PAUSE -- IEEE 802.3x PAUSE and 802.1Qbb Priority Flow Control, EtherType
# 0x8808 (MAC Control), destination 01:80:C2:00:00:01. No CVE exists; the abuse
# model is documented in lossless-Ethernet/RDMA literature rather than CVE
# records, so this is a posture/abuse tier like the LACP state-integrity work.
# ---------------------------------------------------------------------------

# --- PAgP wire constants (layout cross-checked against Wireshark/tshark) ----

PAGP_GROUP_MAC = b"\x01\x00\x0c\xcc\xcc\xcc"
SNAP_OUI_CISCO = b"\x00\x00\x0c"
PAGP_SNAP_PID = 0x0104
LLC_SNAP_HEADER = b"\xaa\xaa\x03"

PAGP_VERSION_INFO = 1
PAGP_VERSION_FLUSH = 2
PAGP_INFO_HEADER_LEN = 46
PAGP_FLUSH_LEN = 18

PAGP_FLAG_SLOW_HELLO = 0x01
PAGP_FLAG_AUTO_MODE = 0x02
PAGP_FLAG_CONSISTENT_STATE = 0x04
PAGP_FLAG_BITS = (
    (PAGP_FLAG_SLOW_HELLO, "slow_hello"),
    (PAGP_FLAG_AUTO_MODE, "auto_mode"),
    (PAGP_FLAG_CONSISTENT_STATE, "consistent_state"),
)

PAGP_TLV_DEVICE_NAME = 1
PAGP_TLV_PORT_NAME = 2
PAGP_TLV_AGPORT_MAC = 3

# PAgP hello timing: fast ~1s, slow ~30s (the Slow Hello flag selects).
PAGP_FAST_HELLO_S = 1.0
PAGP_SLOW_HELLO_S = 30.0

# --- PFC / PAUSE wire constants --------------------------------------------

ETH_P_MAC_CONTROL = 0x8808
MAC_CONTROL_GROUP_MAC = b"\x01\x80\xc2\x00\x00\x01"
MACC_OPCODE_PAUSE = 0x0001
MACC_OPCODE_PFC = 0x0101
MACC_OPCODE_NAMES = {0x0001: "PAUSE", 0x0101: "PFC"}
PFC_PRIORITIES = 8
PAUSE_QUANTA_MAX = 0xFFFF

# --- tunables ---------------------------------------------------------------

PAGP_HELLO_FLAP_WINDOW_S = 120.0
PAGP_HELLO_FLAP_THRESHOLD = 3
PAGP_STATE_FLAP_WINDOW_S = 60.0
PAGP_STATE_FLAP_THRESHOLD = 4
PAGP_BURST_WINDOW_S = 5.0
PAGP_BURST_MULTIPLIER = 5.0
PAGP_BURST_FLOOR = 12
PAGP_FLUSH_WINDOW_S = 30.0
PAGP_FLUSH_THRESHOLD = 5
PAGP_CORRELATION_WINDOW_S = 120.0

# PFC: a pause is only interesting when it persists. A single XOFF is normal
# congestion signalling on any lossless fabric and must never alert.
PFC_XOFF_STORM_WINDOW_S = 5.0
PFC_XOFF_STORM_THRESHOLD = 200     # frames/window from one source
PFC_DEADLOCK_S = 10.0              # continuous XOFF on one priority, no XON
PFC_STARVATION_S = 10.0            # one priority held down while others free
PFC_STARVATION_MIN_FRAMES = 20


CODES.update({
    # --- PAgP abuse / semantics (descriptive names: cdpwatch owns PAGP-0NN) -
    "PAGP-MEMBER-OBSERVED": {
        "severity": SEV_INFO, "confidence": CONF_HIGH,
        "title": "New PAgP bundle member observed"},
    "PAGP-UNAUTHENTICATED": {
        "severity": SEV_INFO, "confidence": CONF_HIGH,
        "title": "PAgP bundle runs without authentication (protocol has no mechanism)"},
    "PAGP-DEVICE-ID-COLLISION": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "Two source MACs claim the same PAgP Device ID and port ifindex"},
    "PAGP-ACTOR-MAC-CHANGE": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "PAgP member identity now transmitted from a different source MAC"},
    "PAGP-DEVICE-ID-CHANGE": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "Source MAC changed the PAgP Device ID it advertises"},
    "PAGP-PORT-PRIORITY-IMPROVED": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "PAgP port priority raised mid-session (bundle selection takeover)"},
    "PAGP-GROUP-CAP-CHANGE": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "PAgP group capability changed: port moved between bundles"},
    "PAGP-PARTNER-VIEW-MISMATCH": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "Two PAgP members do not agree they are bundling with each other"},
    "PAGP-PARTNER-INFO-RESET": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "PAgP partner information cleared: member relearning its peer"},
    "PAGP-CONSISTENT-STATE-LOSS": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "PAgP Consistent State cleared on an established member"},
    "PAGP-STATE-FLAPPING": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "Repeated PAgP Consistent State transitions (bundle instability)"},
    "PAGP-HELLO-RATE-CHANGE": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "PAgP Slow Hello flag changed (detection time manipulation)"},
    "PAGP-HELLO-RATE-FLAPPING": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Repeated PAgP hello-rate changes"},
    "PAGP-MODE-CHANGE": {
        "severity": SEV_LOW, "confidence": CONF_MEDIUM,
        "title": "PAgP Auto/Desirable mode changed"},
    "PAGP-FLUSH-FROM-UNKNOWN-DEVICE": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "PAgP Flush naming a Device ID never observed on this segment"},
    "PAGP-FLUSH-BURST": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "PAgP Flush burst (forced bundle teardown pressure)"},
    "PAGP-PDU-BURST": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "PAgP PDU rate far above the negotiated hello interval"},
    "PAGP-BUNDLE-HIJACK": {
        "severity": SEV_CRITICAL, "confidence": CONF_MEDIUM,
        "title": "Correlated PAgP bundle takeover: identity manipulation with member disruption"},
    # --- PFC / PAUSE (802.3x + 802.1Qbb) ------------------------------------
    "PFC-PAUSE-OBSERVED": {
        "severity": SEV_INFO, "confidence": CONF_HIGH,
        "title": "802.3x PAUSE flow control observed on segment"},
    "PFC-PFC-OBSERVED": {
        "severity": SEV_INFO, "confidence": CONF_HIGH,
        "title": "802.1Qbb Priority Flow Control observed on segment"},
    "PFC-MALFORMED": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Malformed MAC Control frame"},
    "PFC-UNKNOWN-OPCODE": {
        "severity": SEV_LOW, "confidence": CONF_HIGH,
        "title": "Unrecognised MAC Control opcode"},
    "PFC-NON-GROUP-DESTINATION": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "MAC Control frame not addressed to the reserved group MAC"},
    "PFC-MAX-QUANTA": {
        "severity": SEV_MEDIUM, "confidence": CONF_MEDIUM,
        "title": "Pause requested at maximum quanta (longest possible stall)"},
    "PFC-XOFF-STORM": {
        "severity": SEV_HIGH, "confidence": CONF_HIGH,
        "title": "Sustained XOFF flood from one source"},
    "PFC-PRIORITY-STARVATION": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "One traffic class held XOFF while others run free (pause attack signature)"},
    "PFC-DEADLOCK-SUSPECTED": {
        "severity": SEV_HIGH, "confidence": CONF_MEDIUM,
        "title": "Priority held continuously XOFF with no XON (PFC deadlock signature)"},
    "PFC-LEGACY-PAUSE-IN-PFC-FABRIC": {
        "severity": SEV_MEDIUM, "confidence": CONF_HIGH,
        "title": "Global 802.3x PAUSE mixed with per-priority PFC on one segment"},
})

PAGP_IDENTITY_CODES = frozenset({
    "PAGP-DEVICE-ID-COLLISION",
    "PAGP-ACTOR-MAC-CHANGE",
    "PAGP-DEVICE-ID-CHANGE",
    "PAGP-PORT-PRIORITY-IMPROVED",
    "PAGP-PARTNER-VIEW-MISMATCH",
})
PAGP_DISRUPTION_CODES = frozenset({
    "PAGP-CONSISTENT-STATE-LOSS",
    "PAGP-STATE-FLAPPING",
    "PAGP-PARTNER-INFO-RESET",
    "PAGP-FLUSH-FROM-UNKNOWN-DEVICE",
    "PAGP-FLUSH-BURST",
})


def pagp_flags(flags: int) -> List[str]:
    return [n for b, n in PAGP_FLAG_BITS if flags & b]


@dataclass
class PagpPdu:
    version: int
    flags: int = 0
    # info (version 1)
    local_devid: bytes = b""
    local_learncap: int = 0
    local_portpri: int = 0
    local_sent_ifindex: int = 0
    local_groupcap: int = 0
    local_group_ifindex: int = 0
    partner_devid: bytes = b""
    partner_learncap: int = 0
    partner_portpri: int = 0
    partner_sent_ifindex: int = 0
    partner_groupcap: int = 0
    partner_group_ifindex: int = 0
    partner_count: int = 0
    numtlvs: int = 0
    tlv_types: List[int] = field(default_factory=list)
    # flush (version 2)
    flush_local_devid: bytes = b""
    flush_partner_devid: bytes = b""
    transid: int = 0
    usable: bool = False
    is_flush: bool = False

    @property
    def identity(self) -> Tuple[bytes, int]:
        return (self.local_devid, self.local_sent_ifindex)

    @property
    def partner_identity(self) -> Optional[Tuple[bytes, int]]:
        if not any(self.partner_devid):
            return None
        return (self.partner_devid, self.partner_sent_ifindex)


def decode_pagp(raw: bytes, ts: float) -> Optional[Frame]:
    """Decode an 802.3/LLC-SNAP frame carrying PAgP (SNAP PID 0x0104).

    PAgP rides LLC/SNAP with a length field, not an EtherType, so it needs its
    own demux rather than the slow-protocols path.
    """
    if len(raw) < 22:
        return None
    dst = raw[0:6]
    src = raw[6:12]
    off = 12
    tags: List[int] = []
    etype_or_len = struct.unpack_from("!H", raw, off)[0]
    off += 2
    for _ in range(8):
        if etype_or_len not in VLAN_ETHERTYPES:
            break
        if off + 4 > len(raw):
            return None
        tags.append(struct.unpack_from("!H", raw, off)[0] & 0x0FFF)
        etype_or_len = struct.unpack_from("!H", raw, off + 2)[0]
        off += 4
    if etype_or_len > 1500:          # EtherType, not an 802.3 length
        return None
    if raw[off:off + 3] != LLC_SNAP_HEADER:
        return None
    if raw[off + 3:off + 6] != SNAP_OUI_CISCO:
        return None
    pid = struct.unpack_from("!H", raw, off + 6)[0]
    if pid != PAGP_SNAP_PID:
        return None
    payload_end = min(len(raw), off + 8 + max(0, etype_or_len - 8))
    return Frame(ts=ts, dst=dst, src=src, ethertype=PAGP_SNAP_PID,
                 payload=raw[off + 8:payload_end], tags=tags)


def parse_pagp(payload: bytes) -> PagpPdu:
    """Bounds-checked PAgP parse. Never raises.

    Structural defects are NOT reported by this module -- cdpwatch owns that
    half. An unusable PDU is simply dropped here.
    """
    if len(payload) < 2:
        return PagpPdu(version=-1)
    version = payload[0]
    pdu = PagpPdu(version=version, flags=payload[1])
    if version == PAGP_VERSION_FLUSH:
        pdu.is_flush = True
        if len(payload) < PAGP_FLUSH_LEN:
            return pdu
        pdu.flush_local_devid = payload[2:8]
        pdu.flush_partner_devid = payload[8:14]
        pdu.transid = struct.unpack_from("!I", payload, 14)[0]
        pdu.usable = True
        return pdu
    if version != PAGP_VERSION_INFO:
        return pdu
    if len(payload) < PAGP_INFO_HEADER_LEN:
        return pdu
    (pdu.local_devid, pdu.local_learncap, pdu.local_portpri,
     pdu.local_sent_ifindex, pdu.local_groupcap,
     pdu.local_group_ifindex) = struct.unpack_from("!6sBBIII", payload, 2)
    (pdu.partner_devid, pdu.partner_learncap, pdu.partner_portpri,
     pdu.partner_sent_ifindex, pdu.partner_groupcap,
     pdu.partner_group_ifindex) = struct.unpack_from("!6sBBIII", payload, 22)
    pdu.partner_count, pdu.numtlvs = struct.unpack_from("!HH", payload, 42)
    off = PAGP_INFO_HEADER_LEN
    for _ in range(min(pdu.numtlvs, 16)):
        if off + 4 > len(payload):
            break
        t, ln = struct.unpack_from("!HH", payload, off)
        if ln < 4 or off + ln > len(payload):
            break
        pdu.tlv_types.append(t)
        off += ln
    pdu.usable = True
    return pdu


@dataclass
class PagpMember:
    """One PAgP bundle member, keyed by (Device ID, sent port ifindex) so a
    source-MAC change is an event rather than a second member."""
    key: Tuple[bytes, int]
    first_seen: float
    last_seen: float
    src_macs: Dict[bytes, float] = field(default_factory=dict)
    flags: int = 0
    portpri: int = 0
    groupcap: int = 0
    group_ifindex: int = 0
    partner_identity: Optional[Tuple[bytes, int]] = None
    pdu_times: Deque[float] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    state_transitions: Deque[float] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    hello_changes: Deque[float] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    events: Deque[Tuple[float, str]] = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))
    consistent_once: bool = False
    pdus: int = 0
    resyncs: int = 0

    @property
    def devid(self) -> bytes:
        return self.key[0]

    @property
    def ifindex(self) -> int:
        return self.key[1]

    def label(self, src: Optional[bytes] = None) -> str:
        mac = mac_str(src) if src is not None else (
            mac_str(next(iter(self.src_macs))) if self.src_macs else "??")
        return "%s devid=%s port=%d" % (mac, mac_str(self.devid), self.ifindex)

    def hello_period(self) -> float:
        return PAGP_SLOW_HELLO_S if (self.flags & PAGP_FLAG_SLOW_HELLO) \
            else PAGP_FAST_HELLO_S

    def detect_time(self) -> float:
        return self.hello_period() * 3

    def bundle_key(self) -> Tuple[Any, ...]:
        mine = (self.devid, self.group_ifindex)
        theirs = (self.partner_identity[0], 0) if self.partner_identity \
            else (b"\x00" * 6, 0)
        return tuple(sorted([mine, theirs]))


# --- PFC / PAUSE ------------------------------------------------------------


@dataclass
class MacControlPdu:
    opcode: int
    pause_time: int = 0                       # PAUSE only
    class_enable: int = 0                     # PFC only
    times: List[int] = field(default_factory=list)   # PFC: 8 priorities
    usable: bool = False
    error: str = ""


def decode_mac_control(raw: bytes, ts: float) -> Optional[Frame]:
    if len(raw) < 14:
        return None
    dst = raw[0:6]
    src = raw[6:12]
    off = 12
    tags: List[int] = []
    ethertype = struct.unpack_from("!H", raw, off)[0]
    off += 2
    for _ in range(8):
        if ethertype not in VLAN_ETHERTYPES:
            break
        if off + 4 > len(raw):
            return None
        tags.append(struct.unpack_from("!H", raw, off)[0] & 0x0FFF)
        ethertype = struct.unpack_from("!H", raw, off + 2)[0]
        off += 4
    if ethertype != ETH_P_MAC_CONTROL:
        return None
    return Frame(ts=ts, dst=dst, src=src, ethertype=ethertype,
                 payload=raw[off:], tags=tags)


def parse_mac_control(payload: bytes) -> MacControlPdu:
    if len(payload) < 2:
        return MacControlPdu(opcode=-1, error="shorter than an opcode")
    opcode = struct.unpack_from("!H", payload, 0)[0]
    pdu = MacControlPdu(opcode=opcode)
    if opcode == MACC_OPCODE_PAUSE:
        if len(payload) < 4:
            pdu.error = "PAUSE with no pause_time"
            return pdu
        pdu.pause_time = struct.unpack_from("!H", payload, 2)[0]
        pdu.usable = True
    elif opcode == MACC_OPCODE_PFC:
        # class_enable_vector(2) + 8 x time(2)
        if len(payload) < 2 + 2 + PFC_PRIORITIES * 2:
            pdu.error = "PFC shorter than class vector plus 8 timers"
            return pdu
        pdu.class_enable = struct.unpack_from("!H", payload, 2)[0]
        pdu.times = list(struct.unpack_from("!8H", payload, 4))
        pdu.usable = True
    return pdu


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

        # PAgP abuse tier
        self.pagp_members: Dict[Tuple[bytes, int], PagpMember] = {}
        self.pagp_mac_devid: "OrderedDict[bytes, bytes]" = OrderedDict()
        self.pagp_bundles_seen: set = set()
        self.pagp_claimants: Dict[Tuple[bytes, int], set] = {}
        self._pagp_claim_of: Dict[Tuple[bytes, int],
                                  Optional[Tuple[bytes, int]]] = {}
        self._pagp_mismatch: Dict[Tuple[Any, ...], Tuple[float, int]] = {}
        self._pagp_flushes: Deque[float] = deque(maxlen=256)

        # PFC / PAUSE tier
        self.pfc_sources: Dict[bytes, Dict[str, Any]] = {}
        self._pfc_seen_opcodes: set = set()
        # Segment-scoped ring of malformed PDUs that were actually EMITTED
        # (not merely observed), so a correlation can never name a finding the
        # operator never saw.
        self._malformed: Deque[Tuple[float, str, bytes]] = deque(maxlen=64)
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
            "pagp_pdus": 0, "pagp_unparseable": 0, "pagp_flushes": 0,
            "macctrl_frames": 0, "pause_frames": 0, "pfc_frames": 0,
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
        if fr is not None:
            self.on_slow_frame(fr)
            return
        mc = decode_mac_control(raw, ts)
        if mc is not None:
            self.on_mac_control_frame(mc)
            return
        pg = decode_pagp(raw, ts)
        if pg is not None:
            self.on_pagp_frame(pg)

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
            rec = self.emit(an.code, ts, key=(fr.src, an.code), session=session,
                            evidence=ev, orphan_src=fr.src)
            # Only an emitted malformed finding can anchor a correlation.
            if rec is not None and an.code in MALFORMED_CODES:
                self._malformed.append((ts, an.code, fr.src))
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
                rec = self.emit("LACP-SYNC-FLAPPING", ts, key=half.key,
                                session=session,
                                evidence={"transitions": len(window),
                                          "window_s": SYNC_FLAP_WINDOW_S,
                                          "state": state_str(cur),
                                          "src": mac_str(fr.src)})
                self._half_event(half, ts, "LACP-SYNC-FLAPPING")
                self._check_hijack(half, fr, ts)
                if rec is not None:
                    self._check_malformed_flap(half, fr, ts,
                                               "LACP-SYNC-FLAPPING")
            elif (prev & S_SYNC) and not (cur & S_SYNC) and half.synced_once:
                rec = self.emit("LACP-SYNC-LOSS", ts, key=half.key,
                                session=session,
                                evidence={"previous_state": state_str(prev),
                                          "current_state": state_str(cur),
                                          "src": mac_str(fr.src)})
                self._half_event(half, ts, "LACP-SYNC-LOSS")
                self._check_hijack(half, fr, ts)
                if rec is not None:
                    self._check_malformed_flap(half, fr, ts, "LACP-SYNC-LOSS")
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

    def _check_malformed_flap(self, half: Half, fr: Frame, ts: float,
                              disruption: str) -> None:
        """Malformed LACPDU on the segment, then a member flaps.

        This is the observable signature of CVE-2024-30388 (Junos QFX5000 /
        EX4100 / EX4400 / EX4650: a specific malformed LACP packet causes an
        LACP flap). Juniper never published the offending byte pattern, so a
        packet signature here would be invention. The *effect* is observable
        without it, and this also catches any future malformed-PDU flap bug in
        any vendor's forwarding engine.

        Scope note: unlike LAG-HIJACK this is SEGMENT-scoped, not member-scoped.
        A malformed PDU fails to parse, so its sender never becomes a member and
        there is no member to attach it to. That is looser, so the window is
        short and two exclusions apply:
          * the malformed sender must not be the flapping member itself - a
            member emitting garbage as it dies is a failing NIC, not an
            induced flap;
          * the malformed finding must have been emitted, not merely observed.
        """
        recent = [(t, code, src) for t, code, src in self._malformed
                  if 0 <= (ts - t) <= MALFORMED_FLAP_WINDOW_S]
        # exclude the flapping member's own source MACs
        own = set(half.src_macs)
        external = [(t, code, src) for t, code, src in recent if src not in own]
        if not external:
            return
        self.emit("LACP-MALFORMED-INDUCED-FLAP", ts, key=half.key,
                  session=half.label(fr.src),
                  evidence={
                      "cve": "CVE-2024-30388",
                      "cve_note": "Junos OS QFX5000 / EX4100 / EX4400 / EX4650: "
                                  "a specific malformed LACP packet causes an "
                                  "LACP flap. The byte pattern is undisclosed, "
                                  "so this correlates the EFFECT, not a "
                                  "signature. Platform cannot be confirmed "
                                  "passively - verify the victim's model and "
                                  "Junos version before treating as exploited.",
                      "disruption": disruption,
                      "window_s": MALFORMED_FLAP_WINDOW_S,
                      "malformed_observations": [
                          {"code": code, "src": mac_str(src),
                           "seconds_before_flap": round(ts - t, 3)}
                          for t, code, src in external],
                      "victim_member": {"sys_id": mac_str(half.sys_id),
                                        "key": half.oper_key,
                                        "port": half.port_num},
                  })

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

    # -- PAgP abuse / semantics tier ---------------------------------------

    def on_pagp_frame(self, fr: Frame) -> None:
        ts = fr.ts
        self._maybe_prune(ts)
        pdu = parse_pagp(fr.payload)
        if not pdu.usable:
            # Structural defects belong to cdpwatch. Count and drop; never
            # double-report the same malformed frame from two modules.
            self.stats["pagp_unparseable"] += 1
            return
        if pdu.is_flush:
            self.stats["pagp_flushes"] += 1
            self._on_pagp_flush(fr, pdu, ts)
            return
        self.stats["pagp_pdus"] += 1
        if not any(pdu.local_devid):
            return

        session = mac_str(fr.src)
        prev_devid = self.pagp_mac_devid.get(fr.src)
        if prev_devid is not None and prev_devid != pdu.local_devid:
            self.emit("PAGP-DEVICE-ID-CHANGE", ts, key=fr.src, session=session,
                      evidence={"src": mac_str(fr.src),
                                "previous_devid": mac_str(prev_devid),
                                "current_devid": mac_str(pdu.local_devid)})
        self.pagp_mac_devid[fr.src] = pdu.local_devid
        self.pagp_mac_devid.move_to_end(fr.src)
        while len(self.pagp_mac_devid) > MAX_IDENTITY_MAP:
            self.pagp_mac_devid.popitem(last=False)

        mkey = pdu.identity
        m = self.pagp_members.get(mkey)
        if m is None:
            m = PagpMember(key=mkey, first_seen=ts, last_seen=ts)
            self.pagp_members[mkey] = m
            self._pagp_first_sight(m, fr, pdu, ts)
            return
        self._pagp_update(m, fr, pdu, ts)

    def _pagp_first_sight(self, m: PagpMember, fr: Frame, pdu: PagpPdu,
                          ts: float) -> None:
        m.src_macs[fr.src] = ts
        m.flags = pdu.flags
        m.portpri = pdu.local_portpri
        m.groupcap = pdu.local_groupcap
        m.group_ifindex = pdu.local_group_ifindex
        m.partner_identity = pdu.partner_identity
        m.consistent_once = bool(pdu.flags & PAGP_FLAG_CONSISTENT_STATE)
        m.pdu_times.append(ts)
        m.pdus = 1
        m.last_seen = ts
        self.emit("PAGP-MEMBER-OBSERVED", ts, key=m.key,
                  session=m.label(fr.src),
                  evidence={"devid": mac_str(pdu.local_devid),
                            "port_ifindex": pdu.local_sent_ifindex,
                            "port_priority": pdu.local_portpri,
                            "group_capability": pdu.local_groupcap,
                            "group_ifindex": pdu.local_group_ifindex,
                            "flags": pagp_flags(pdu.flags),
                            "partner_devid": mac_str(pdu.partner_devid),
                            "src": mac_str(fr.src)})
        bundle = m.bundle_key()
        if bundle not in self.pagp_bundles_seen:
            self.pagp_bundles_seen.add(bundle)
            self.emit("PAGP-UNAUTHENTICATED", ts, key=bundle,
                      session=m.label(fr.src),
                      evidence={
                          "note": "PAgP carries no authentication of any kind; "
                                  "any station on the segment can originate "
                                  "Info or Flush frames. Mitigation is port "
                                  "security, not protocol configuration.",
                          "devid": mac_str(m.devid)})
        self._pagp_cross_view(m, fr, ts)

    def _pagp_update(self, m: PagpMember, fr: Frame, pdu: PagpPdu,
                     ts: float) -> None:
        session = m.label(fr.src)
        gap = ts - m.last_seen
        threshold = max(m.detect_time() * OBSERVATION_GAP_FACTOR,
                        OBSERVATION_GAP_FLOOR_S)
        resync = gap > threshold
        if resync:
            m.resyncs += 1
            self.stats["resyncs"] += 1

        if fr.src not in m.src_macs:
            if m.src_macs:
                prev_mac, prev_ts = sorted(m.src_macs.items(),
                                           key=lambda kv: kv[1])[-1]
                recent = ts - prev_ts <= max(m.detect_time() * 2, 10.0)
                code = "PAGP-DEVICE-ID-COLLISION" if recent \
                    else "PAGP-ACTOR-MAC-CHANGE"
                self.emit(code, ts, key=m.key, session=session,
                          evidence={"devid": mac_str(m.devid),
                                    "port_ifindex": m.ifindex,
                                    "previous_src": mac_str(prev_mac),
                                    "current_src": mac_str(fr.src),
                                    "seconds_since_previous_src":
                                        round(ts - prev_ts, 3)})
                self._pagp_event(m, ts, code)
                self._pagp_check_hijack(m, fr, ts)
        m.src_macs[fr.src] = ts

        # PAgP port priority: HIGHER wins (CISCO-PAGP-MIB pagpPortPriority -
        # "the one with the highest numerical value is selected for use").
        # This is the OPPOSITE of LACP, where numerically lower wins.
        if pdu.local_portpri != m.portpri:
            if pdu.local_portpri > m.portpri:
                self.emit("PAGP-PORT-PRIORITY-IMPROVED", ts, key=m.key,
                          session=session,
                          evidence={"previous_port_priority": m.portpri,
                                    "current_port_priority": pdu.local_portpri,
                                    "src": mac_str(fr.src),
                                    "note": "PAgP selects the numerically "
                                            "HIGHEST port priority (opposite "
                                            "of LACP)"})
                self._pagp_event(m, ts, "PAGP-PORT-PRIORITY-IMPROVED")
                self._pagp_check_hijack(m, fr, ts)
            m.portpri = pdu.local_portpri

        if pdu.local_groupcap != m.groupcap:
            self.emit("PAGP-GROUP-CAP-CHANGE", ts, key=m.key, session=session,
                      evidence={"previous_group_capability": m.groupcap,
                                "current_group_capability": pdu.local_groupcap,
                                "src": mac_str(fr.src),
                                "note": "group capability selects the agport; "
                                        "a change moves this port between "
                                        "bundles"})
            m.groupcap = pdu.local_groupcap
        m.group_ifindex = pdu.local_group_ifindex

        prev_flags, cur_flags = m.flags, pdu.flags
        if not resync:
            self._pagp_flag_deltas(m, fr, prev_flags, cur_flags, ts, session)
        else:
            m.state_transitions.clear()
        m.flags = cur_flags
        if cur_flags & PAGP_FLAG_CONSISTENT_STATE:
            m.consistent_once = True

        new_partner = pdu.partner_identity
        if m.partner_identity is not None and new_partner is None:
            self.emit("PAGP-PARTNER-INFO-RESET", ts, key=m.key, session=session,
                      evidence={"previous_partner_devid":
                                    mac_str(m.partner_identity[0]),
                                "src": mac_str(fr.src),
                                "note": "member cleared its partner record and "
                                        "is relearning the far end"})
            self._pagp_event(m, ts, "PAGP-PARTNER-INFO-RESET")
            self._pagp_check_hijack(m, fr, ts)
        m.partner_identity = new_partner
        self._pagp_cross_view(m, fr, ts)

        m.pdu_times.append(ts)
        m.pdus += 1
        m.last_seen = ts
        window = [t for t in m.pdu_times if ts - t <= PAGP_BURST_WINDOW_S]
        expected = PAGP_BURST_WINDOW_S / m.hello_period()
        limit = max(PAGP_BURST_FLOOR, int(PAGP_BURST_MULTIPLIER * expected))
        if len(window) > limit:
            self.emit("PAGP-PDU-BURST", ts, key=m.key, session=session,
                      evidence={"pdus_in_window": len(window),
                                "window_s": PAGP_BURST_WINDOW_S,
                                "hello_period_s": m.hello_period(),
                                "threshold": limit,
                                "src": mac_str(fr.src)})

    def _pagp_flag_deltas(self, m: PagpMember, fr: Frame, prev: int, cur: int,
                          ts: float, session: str) -> None:
        changed = prev ^ cur
        if changed & PAGP_FLAG_CONSISTENT_STATE:
            m.state_transitions.append(ts)
            window = [t for t in m.state_transitions
                      if ts - t <= PAGP_STATE_FLAP_WINDOW_S]
            if len(window) >= PAGP_STATE_FLAP_THRESHOLD:
                self.emit("PAGP-STATE-FLAPPING", ts, key=m.key, session=session,
                          evidence={"transitions": len(window),
                                    "window_s": PAGP_STATE_FLAP_WINDOW_S,
                                    "src": mac_str(fr.src)})
                self._pagp_event(m, ts, "PAGP-STATE-FLAPPING")
                self._pagp_check_hijack(m, fr, ts)
            elif (prev & PAGP_FLAG_CONSISTENT_STATE) and \
                    not (cur & PAGP_FLAG_CONSISTENT_STATE) and m.consistent_once:
                self.emit("PAGP-CONSISTENT-STATE-LOSS", ts, key=m.key,
                          session=session,
                          evidence={"previous_flags": pagp_flags(prev),
                                    "current_flags": pagp_flags(cur),
                                    "src": mac_str(fr.src)})
                self._pagp_event(m, ts, "PAGP-CONSISTENT-STATE-LOSS")
                self._pagp_check_hijack(m, fr, ts)
        if changed & PAGP_FLAG_SLOW_HELLO:
            m.hello_changes.append(ts)
            window = [t for t in m.hello_changes
                      if ts - t <= PAGP_HELLO_FLAP_WINDOW_S]
            if len(window) >= PAGP_HELLO_FLAP_THRESHOLD:
                self.emit("PAGP-HELLO-RATE-FLAPPING", ts, key=m.key,
                          session=session,
                          evidence={"changes": len(window),
                                    "window_s": PAGP_HELLO_FLAP_WINDOW_S,
                                    "src": mac_str(fr.src)})
            else:
                self.emit("PAGP-HELLO-RATE-CHANGE", ts, key=m.key,
                          session=session,
                          evidence={"previous": "slow" if prev & PAGP_FLAG_SLOW_HELLO else "fast",
                                    "current": "slow" if cur & PAGP_FLAG_SLOW_HELLO else "fast",
                                    "src": mac_str(fr.src)})
        if changed & PAGP_FLAG_AUTO_MODE:
            self.emit("PAGP-MODE-CHANGE", ts, key=m.key, session=session,
                      evidence={"previous": "auto" if prev & PAGP_FLAG_AUTO_MODE else "desirable",
                                "current": "auto" if cur & PAGP_FLAG_AUTO_MODE else "desirable",
                                "src": mac_str(fr.src)})

    def _pagp_event(self, m: PagpMember, ts: float, code: str) -> None:
        m.events.append((ts, code))

    def _pagp_cross_view(self, m: PagpMember, fr: Frame, ts: float) -> None:
        """Mutual-view check, identity only -- same discipline as the LACP
        tier, including the persistence gate that stops a STALE view from
        reading as a third party."""
        pid = m.partner_identity
        prev = self._pagp_claim_of.get(m.key)
        if prev != pid:
            if prev is not None:
                st = self.pagp_claimants.get(prev)
                if st is not None:
                    st.discard(m.key)
                    if not st:
                        del self.pagp_claimants[prev]
            if pid is not None:
                self.pagp_claimants.setdefault(pid, set()).add(m.key)
            self._pagp_claim_of[m.key] = pid
        if pid is not None:
            other = self.pagp_members.get(pid)
            if other is not None:
                self._pagp_pair_check(m, other, fr, ts)
        for ck in list(self.pagp_claimants.get(m.key, ())):
            claimant = self.pagp_members.get(ck)
            if claimant is not None and claimant.key != m.key:
                self._pagp_pair_check(claimant, m, fr, ts)

    def _pagp_pair_check(self, a: PagpMember, b: PagpMember, fr: Frame,
                         ts: float) -> None:
        if a.partner_identity is None or b.partner_identity is None:
            return
        a_ok = a.partner_identity == b.key
        b_ok = b.partner_identity == a.key
        pair = tuple(sorted([a.key, b.key]))
        if a_ok and b_ok:
            self._pagp_mismatch.pop(pair, None)
            return
        if not (a_ok or b_ok):
            return
        wrong = b if a_ok else a
        right = a if a_ok else b
        state = self._pagp_mismatch.get(pair)
        if state is None:
            self._pagp_mismatch[pair] = (ts, wrong.pdus)
            return
        first_ts, first_pdus = state
        if (wrong.pdus - first_pdus) < MISMATCH_MIN_PDUS:
            return
        if (ts - first_ts) < wrong.detect_time():
            return
        self.emit("PAGP-PARTNER-VIEW-MISMATCH", ts, key=pair,
                  session=wrong.label(),
                  evidence={
                      "consistent_member": {"devid": mac_str(right.devid),
                                            "port": right.ifindex},
                      "contradicting_member": {"devid": mac_str(wrong.devid),
                                               "port": wrong.ifindex},
                      "contradicting_member_claims": {
                          "devid": mac_str(wrong.partner_identity[0]),
                          "port": wrong.partner_identity[1]},
                      "persisted_s": round(ts - first_ts, 3),
                      "persisted_pdus": wrong.pdus - first_pdus,
                      "note": "the two ends do not agree they are bundling "
                              "with each other"})
        for x in (a, b):
            self._pagp_event(x, ts, "PAGP-PARTNER-VIEW-MISMATCH")
        self._pagp_check_hijack(wrong, fr, ts)

    def _on_pagp_flush(self, fr: Frame, pdu: PagpPdu, ts: float) -> None:
        """PAgP Flush tears a bundle down. A forged Flush is a cheap, direct
        disruption primitive -- it needs no identity takeover at all."""
        session = mac_str(fr.src)
        self._pagp_flushes.append(ts)
        window = [t for t in self._pagp_flushes
                  if ts - t <= PAGP_FLUSH_WINDOW_S]
        if len(window) > PAGP_FLUSH_THRESHOLD:
            self.emit("PAGP-FLUSH-BURST", ts, key=fr.src, session=session,
                      evidence={"flushes_in_window": len(window),
                                "window_s": PAGP_FLUSH_WINDOW_S,
                                "threshold": PAGP_FLUSH_THRESHOLD,
                                "src": mac_str(fr.src)})
            for m in self.pagp_members.values():
                if m.devid == pdu.flush_local_devid:
                    self._pagp_event(m, ts, "PAGP-FLUSH-BURST")
                    self._pagp_check_hijack(m, fr, ts)
        known = {k[0] for k in self.pagp_members}
        if known and pdu.flush_local_devid not in known:
            self.emit("PAGP-FLUSH-FROM-UNKNOWN-DEVICE", ts,
                      key=(fr.src, pdu.flush_local_devid), session=session,
                      evidence={"flush_local_devid": mac_str(pdu.flush_local_devid),
                                "flush_partner_devid": mac_str(pdu.flush_partner_devid),
                                "transaction_id": pdu.transid,
                                "src": mac_str(fr.src),
                                "known_devids": sorted(mac_str(k) for k in known),
                                "note": "a Flush naming a device never seen on "
                                        "this segment did not come from a "
                                        "bundle member"},
                      orphan_src=fr.src)
            for m in self.pagp_members.values():
                if m.devid == pdu.flush_partner_devid:
                    self._pagp_event(m, ts, "PAGP-FLUSH-FROM-UNKNOWN-DEVICE")
                    self._pagp_check_hijack(m, fr, ts)

    def _pagp_check_hijack(self, m: PagpMember, fr: Frame, ts: float) -> None:
        recent = [(t, c) for t, c in m.events
                  if ts - t <= PAGP_CORRELATION_WINDOW_S]
        codes = {c for _, c in recent}
        ident = sorted(codes & PAGP_IDENTITY_CODES)
        disr = sorted(codes & PAGP_DISRUPTION_CODES)
        if not ident or not disr:
            return
        self.emit("PAGP-BUNDLE-HIJACK", ts, key=m.key, session=m.label(fr.src),
                  evidence={"correlated_codes": ident + disr,
                            "window_s": PAGP_CORRELATION_WINDOW_S,
                            "devid": mac_str(m.devid),
                            "port_ifindex": m.ifindex,
                            "distinct_srcs": [mac_str(x) for x in m.src_macs],
                            "note": "bundle selection parameters were "
                                    "manipulated and the member was disrupted "
                                    "inside the same window"})

    # -- PFC / PAUSE tier ---------------------------------------------------

    def on_mac_control_frame(self, fr: Frame) -> None:
        ts = fr.ts
        self.stats["macctrl_frames"] += 1
        self._maybe_prune(ts)
        session = mac_str(fr.src)

        if fr.dst != MAC_CONTROL_GROUP_MAC:
            self.emit("PFC-NON-GROUP-DESTINATION", ts, key=fr.src,
                      session=session,
                      evidence={"dst": mac_str(fr.dst),
                                "expected": mac_str(MAC_CONTROL_GROUP_MAC),
                                "src": mac_str(fr.src)},
                      orphan_src=fr.src)

        pdu = parse_mac_control(fr.payload)
        if pdu.opcode not in (MACC_OPCODE_PAUSE, MACC_OPCODE_PFC):
            self.emit("PFC-UNKNOWN-OPCODE", ts, key=(fr.src, pdu.opcode),
                      session=session,
                      evidence={"opcode": "0x%04x" % pdu.opcode
                                if pdu.opcode >= 0 else "none",
                                "src": mac_str(fr.src)},
                      orphan_src=fr.src)
            return
        if not pdu.usable:
            self.emit("PFC-MALFORMED", ts, key=(fr.src, pdu.opcode),
                      session=session,
                      evidence={"opcode": "0x%04x" % pdu.opcode,
                                "reason": pdu.error,
                                "payload_len": len(fr.payload),
                                "src": mac_str(fr.src)},
                      orphan_src=fr.src)
            return

        self._pfc_seen_opcodes.add(pdu.opcode)
        st = self.pfc_sources.get(fr.src)
        if st is None:
            st = {"xoff_since": {}, "xon_count": 0, "frames": deque(maxlen=1024),
                  "priorities_seen": set(), "first_seen": ts,
                  "starve_since": {}}
            self.pfc_sources[fr.src] = st
            self.emit("PFC-PAUSE-OBSERVED" if pdu.opcode == MACC_OPCODE_PAUSE
                      else "PFC-PFC-OBSERVED", ts, key=fr.src, session=session,
                      evidence={"src": mac_str(fr.src),
                                "opcode": MACC_OPCODE_NAMES[pdu.opcode],
                                "note": "flow control is normal on a lossless "
                                        "fabric; this is inventory"})
        st["frames"].append(ts)

        if pdu.opcode == MACC_OPCODE_PAUSE:
            self.stats["pause_frames"] += 1
            self._pfc_track(fr, ts, 0, pdu.pause_time, st, legacy=True)
            if pdu.pause_time == PAUSE_QUANTA_MAX:
                self.emit("PFC-MAX-QUANTA", ts, key=(fr.src, "pause"),
                          session=session,
                          evidence={"pause_quanta": pdu.pause_time,
                                    "src": mac_str(fr.src),
                                    "note": "quanta are 512 bit times, so the "
                                            "wall-clock stall depends on link "
                                            "speed, which a passive tap cannot "
                                            "observe"})
        else:
            self.stats["pfc_frames"] += 1
            for pri in range(PFC_PRIORITIES):
                if not (pdu.class_enable & (1 << pri)):
                    continue
                st["priorities_seen"].add(pri)
                self._pfc_track(fr, ts, pri, pdu.times[pri], st, legacy=False)
                if pdu.times[pri] == PAUSE_QUANTA_MAX:
                    self.emit("PFC-MAX-QUANTA", ts, key=(fr.src, pri),
                              session=session,
                              evidence={"priority": pri,
                                        "pause_quanta": pdu.times[pri],
                                        "src": mac_str(fr.src)})

        if len(self._pfc_seen_opcodes) > 1:
            self.emit("PFC-LEGACY-PAUSE-IN-PFC-FABRIC", ts, key="mixed",
                      session=session,
                      evidence={"opcodes": sorted(MACC_OPCODE_NAMES[o]
                                                  for o in self._pfc_seen_opcodes),
                                "note": "global PAUSE stops every class at once "
                                        "and defeats the per-priority "
                                        "guarantees PFC exists to provide"})

        window = [t for t in st["frames"] if ts - t <= PFC_XOFF_STORM_WINDOW_S]
        if len(window) > PFC_XOFF_STORM_THRESHOLD:
            self.emit("PFC-XOFF-STORM", ts, key=fr.src, session=session,
                      evidence={"frames_in_window": len(window),
                                "window_s": PFC_XOFF_STORM_WINDOW_S,
                                "threshold": PFC_XOFF_STORM_THRESHOLD,
                                "src": mac_str(fr.src)})

    def _pfc_track(self, fr: Frame, ts: float, pri: int, quanta: int,
                   st: Dict[str, Any], legacy: bool) -> None:
        """Per-priority XOFF/XON state.

        quanta > 0 is XOFF (stop sending for N quanta); quanta == 0 is XON
        (resume immediately). A single XOFF is ordinary congestion signalling.
        What is NOT ordinary is a priority held down continuously with no XON
        ever arriving - that is the deadlock / starvation signature.
        """
        session = mac_str(fr.src)
        if quanta == 0:
            st["xoff_since"].pop(pri, None)
            st["starve_since"].pop(pri, None)
            st["xon_count"] += 1
            return
        since = st["xoff_since"].get(pri)
        if since is None:
            st["xoff_since"][pri] = [ts, 1]
            return
        since[1] += 1
        held = ts - since[0]
        if held >= PFC_DEADLOCK_S and since[1] >= 3:
            self.emit("PFC-DEADLOCK-SUSPECTED", ts, key=(fr.src, pri),
                      session=session,
                      evidence={"priority": pri,
                                "held_xoff_s": round(held, 3),
                                "refresh_frames": since[1],
                                "xon_frames_from_source": st["xon_count"],
                                "legacy_pause": legacy,
                                "src": mac_str(fr.src),
                                "note": "priority refreshed XOFF continuously "
                                        "with no XON; mutual XOFF between two "
                                        "switches on one priority is the PFC "
                                        "deadlock signature"})
        # Starvation: this priority pinned down while the source leaves at
        # least one other observed priority alone.
        others = st["priorities_seen"] - {pri}
        others_free = others and all(p not in st["xoff_since"] for p in others)
        if (not legacy and others_free and held >= PFC_STARVATION_S
                and since[1] >= PFC_STARVATION_MIN_FRAMES):
            self.emit("PFC-PRIORITY-STARVATION", ts, key=(fr.src, pri),
                      session=session,
                      evidence={"starved_priority": pri,
                                "held_xoff_s": round(held, 3),
                                "xoff_frames": since[1],
                                "other_priorities_running": sorted(others),
                                "src": mac_str(fr.src),
                                "note": "one traffic class selectively held "
                                        "down while others run: the documented "
                                        "pause-attack signature"})

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
        stale_p = [k for k, m in self.pagp_members.items()
                   if ts - m.last_seen > HALF_IDLE_TTL_S]
        for k in stale_p:
            del self.pagp_members[k]
        plive = set(self.pagp_members)
        for pair in [p for p in self._pagp_mismatch if not set(p) <= plive]:
            del self._pagp_mismatch[pair]
        for src in [k for k, v in self.pfc_sources.items()
                    if v["frames"] and ts - v["frames"][-1] > HALF_IDLE_TTL_S]:
            del self.pfc_sources[src]
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
            "pagp_members": len(self.pagp_members),
            "pagp_bundles": len(self.pagp_bundles_seen),
            "pfc_sources": len(self.pfc_sources),
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
    """Live capture.

    The three tiers live on three different link-layer encapsulations:
      * LACP / Marker  -> EtherType 0x8809
      * PFC / PAUSE    -> EtherType 0x8808
      * PAgP           -> an 802.3 LENGTH field with LLC/SNAP, no EtherType

    Binding a single AF_PACKET socket to ETH_P_SLOW would silently deliver only
    the first of those, so by default we bind one kernel-filtered socket per
    encapsulation and poll them together. The kernel still does the filtering,
    so a Pi-class node never sees ordinary traffic. --all-frames falls back to
    one ETH_P_ALL socket, which also catches VLAN-tagged slow protocols at the
    cost of filtering every frame in Python.
    """
    import select
    import socket  # stdlib; imported here so --self-test needs no sockets

    ETH_P_ALL = 0x0003
    ETH_P_802_2 = 0x0004        # 802.3 frames with an LLC header (PAgP)

    protos = [ETH_P_ALL] if all_frames else [ETH_P_SLOW, ETH_P_MAC_CONTROL,
                                             ETH_P_802_2]
    socks = []
    try:
        for proto in protos:
            try:
                sk = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                   socket.htons(proto))
                sk.bind((iface, 0))
                sk.setblocking(False)
                socks.append(sk)
            except OSError as exc:
                print("lacpwatch: cannot bind proto 0x%04x on %s: %s"
                      % (proto, iface, exc), file=sys.stderr)
        if not socks:
            print("lacpwatch: no capture socket could be opened", file=sys.stderr)
            return
        poller = select.poll()
        fdmap = {}
        for sk in socks:
            poller.register(sk.fileno(), select.POLLIN)
            fdmap[sk.fileno()] = sk
        last_hb = time.time()
        while not shutdown.stop:
            for fd, _ev in poller.poll(500):
                sk = fdmap.get(fd)
                if sk is None:
                    continue
                while True:
                    try:
                        raw = sk.recv(65535)
                    except BlockingIOError:
                        break
                    except OSError as exc:  # pragma: no cover
                        print("lacpwatch: recv failed: %s" % exc,
                              file=sys.stderr)
                        shutdown.stop = True
                        break
                    if not raw:
                        break
                    engine.on_frame(raw, time.time())
                    if shutdown.stop:
                        break
            if heartbeat:
                now = time.time()
                if now - last_hb >= heartbeat:
                    last_hb = now
                    emit({"ts": iso_ts(now), "module": MODULE,
                          "type": "heartbeat", "stats": dict(engine.stats),
                          "halves": len(engine.halves),
                          "pagp_members": len(engine.pagp_members),
                          "pfc_sources": len(engine.pfc_sources)})
    finally:
        for sk in socks:
            try:
                sk.close()
            except OSError:
                pass


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


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="lacpwatch",
        description="Passive LACP / Marker slow-protocol integrity monitor "
                    "(receive-only; no transmitter).")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--pcap", help="read a classic libpcap file")
    src.add_argument("--iface", help="live capture on an interface (CAP_NET_RAW)")
    ap.add_argument("--jsonl", default="-",
                    help="write JSONL findings here ('-' = stdout, default)")
    ap.add_argument("--all-frames", action="store_true",
                    help="live: bind ETH_P_ALL and filter in software instead "
                         "of one kernel-filtered socket per encapsulation. "
                         "Needed to observe VLAN-tagged slow protocols; "
                         "costs CPU.")
    ap.add_argument("--heartbeat", type=float, default=0.0,
                    help="live: emit a heartbeat record every N seconds")
    ap.add_argument("--no-info", action="store_true",
                    help="suppress INFO findings (posture and inventory)")
    ap.add_argument("--partner-unobserved", action="store_true",
                    help="enable LACP-PARTNER-UNOBSERVED (off by default: weak "
                         "on asymmetric taps)")
    ap.add_argument("--self-test", action="store_true", help="run the Tier 1 suite")
    ap.add_argument("--list-codes", action="store_true",
                    help="print the finding catalogue and exit")
    ap.add_argument("--version", action="version",
                    version="%(prog)s " + __version__)
    args = ap.parse_args(argv)

    if args.list_codes:
        for code in sorted(CODES):
            spec = CODES[code]
            print("%-32s %-8s %-6s %s" % (code, spec["severity"],
                                          spec["confidence"], spec["title"]))
        return 0

    if args.self_test:
        return run_self_test()

    if not args.pcap and not args.iface:
        ap.error("one of --pcap, --iface, --self-test or --list-codes is required")

    sink, closer = _make_sink(args.jsonl)
    engine = LacpWatch(sink=sink, emit_info=not args.no_info,
                       partner_unobserved=args.partner_unobserved)
    shutdown = _Shutdown()
    shutdown.install()
    rc = 0
    try:
        if args.pcap:
            last_ts = None
            try:
                for raw, ts in read_pcap(args.pcap):
                    engine.on_frame(raw, ts)
                    last_ts = ts
                    if shutdown.stop:
                        break
            except PcapError as exc:
                print("lacpwatch: %s" % exc, file=sys.stderr)
                return 2
            sink(engine.summary(last_ts, shutdown.reason))
        else:
            live_capture(engine, args.iface, shutdown,
                         all_frames=args.all_frames,
                         heartbeat=args.heartbeat, emit=sink)
            sink(engine.summary(time.time(), shutdown.reason))
    finally:
        if closer is not None:
            closer.close()
    return rc


# ---------------------------------------------------------------------------
# Tier 1 self-test
#
# The builders below serialize LACPDUs so the parser can be driven against
# byte-exact input. They construct bytes and nothing else: there is no socket,
# no sendto, no injector anywhere in this module.
# ---------------------------------------------------------------------------

SLOW = SLOW_PROTOCOLS_GROUP_MAC


def b_port(sys_prio=32768, sys_id=b"\x00\x11\x22\x33\x44\x55", key=0x0001,
           port_prio=32768, port_num=1, state=0x3D, reserved=b"\x00\x00\x00") -> bytes:
    return struct.pack("!H6sHHHB", sys_prio, sys_id, key, port_prio,
                       port_num, state) + reserved


def b_lacpdu(actor: bytes, partner: bytes, version: int = 1,
             collector_delay: int = 0, actor_len: int = 20,
             partner_len: int = 20, collector: bool = True,
             terminator: bool = True, pad: int = 50, trailing: bytes = b"",
             extra_tlvs: bytes = b"", swap_order: bool = False) -> bytes:
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
        out = out[:len(out) - len(trailing)] + trailing if pad >= len(trailing) else out + trailing
    return out


def b_marker(tlv_type: int = 0x01, requester_port: int = 1,
             requester_system: bytes = b"\x00\x11\x22\x33\x44\x55",
             txn: int = 1, length: int = 16, version: int = 1) -> bytes:
    return (bytes([SUBTYPE_MARKER, version, tlv_type, length])
            + struct.pack("!H6sI", requester_port, requester_system, txn)
            + b"\x00\x00" + bytes([TLV_TERMINATOR, 0]) + b"\x00" * 90)


def b_frame(payload: bytes, src: bytes = b"\x00\xaa\xbb\xcc\xdd\x01",
            dst: bytes = SLOW, tags: Sequence[int] = ()) -> bytes:
    out = dst + src
    for tci in tags:
        out += struct.pack("!HH", 0x8100, tci)
    out += struct.pack("!H", ETH_P_SLOW) + payload
    return out


def b_pagp_info(devid=b"\x00\x11\x22\x33\x44\x55", learncap=1, portpri=128,
                sent_ifindex=1, groupcap=0x10001, group_ifindex=1,
                p_devid=b"\x00\x66\x77\x88\x99\xaa", p_learncap=1, p_portpri=128,
                p_sent_ifindex=1, p_groupcap=0x10001, p_group_ifindex=1,
                partner_count=1, flags=PAGP_FLAG_CONSISTENT_STATE,
                tlvs=b"", numtlvs=None) -> bytes:
    """PAgP Info (version 1): 46-byte fixed header then CDP-grammar TLVs."""
    n = numtlvs if numtlvs is not None else 0
    return (bytes([PAGP_VERSION_INFO, flags])
            + struct.pack("!6sBBIII", devid, learncap, portpri, sent_ifindex,
                          groupcap, group_ifindex)
            + struct.pack("!6sBBIII", p_devid, p_learncap, p_portpri,
                          p_sent_ifindex, p_groupcap, p_group_ifindex)
            + struct.pack("!HH", partner_count, n) + tlvs)


def b_pagp_tlv(t: int, value: bytes) -> bytes:
    return struct.pack("!HH", t, len(value) + 4) + value


def b_pagp_flush(local_devid=b"\x00\x11\x22\x33\x44\x55",
                 partner_devid=b"\x00\x66\x77\x88\x99\xaa", transid=1,
                 flags=0) -> bytes:
    """PAgP Flush (version 2): a DIFFERENT 18-byte layout, carries no TLVs."""
    return (bytes([PAGP_VERSION_FLUSH, flags]) + local_devid + partner_devid
            + struct.pack("!I", transid))


def b_pagp_frame(payload: bytes, src: bytes = b"\x00\xaa\xbb\xcc\xdd\x01",
                 dst: bytes = PAGP_GROUP_MAC,
                 tags: Sequence[int] = ()) -> bytes:
    """802.3 length + LLC/SNAP (OUI 00:00:0c, PID 0x0104)."""
    snap = LLC_SNAP_HEADER + SNAP_OUI_CISCO + struct.pack("!H", PAGP_SNAP_PID)
    body = snap + payload
    out = dst + src
    for tci in tags:
        out += struct.pack("!HH", 0x8100, tci)
    return out + struct.pack("!H", len(body)) + body


def b_pause(quanta: int = 0xFFFF) -> bytes:
    return struct.pack("!HH", MACC_OPCODE_PAUSE, quanta) + b"\x00" * 42


def b_pfc(enable: int = 0x01, times: Optional[Sequence[int]] = None) -> bytes:
    t = list(times) if times is not None else [0] * PFC_PRIORITIES
    return (struct.pack("!HH", MACC_OPCODE_PFC, enable)
            + struct.pack("!8H", *t) + b"\x00" * 26)


def b_macc_frame(payload: bytes, src: bytes = b"\x00\xaa\xbb\xcc\xdd\x01",
                 dst: bytes = MAC_CONTROL_GROUP_MAC,
                 tags: Sequence[int] = ()) -> bytes:
    out = dst + src
    for tci in tags:
        out += struct.pack("!HH", 0x8100, tci)
    return out + struct.pack("!H", ETH_P_MAC_CONTROL) + payload


_EMITTED_CODES: set = set()
_RESULTS: List[Tuple[str, bool, str]] = []


def _run(frames: Sequence[Tuple[bytes, float]], **kw) -> "LacpWatch":
    eng = LacpWatch(**kw)
    for raw, ts in frames:
        eng.on_frame(raw, ts)
    _EMITTED_CODES.update(f["code"] for f in eng.findings)
    return eng


def _codes(eng: "LacpWatch") -> List[str]:
    return [f["code"] for f in eng.findings]


def _check(name: str, cond: bool, detail: str = "") -> None:
    _RESULTS.append((name, bool(cond), detail))


def _has(eng: "LacpWatch", code: str) -> bool:
    return code in _codes(eng)


def _find(eng: "LacpWatch", code: str) -> Optional[Dict[str, Any]]:
    for f in eng.findings:
        if f["code"] == code:
            return f
    return None


A_SYS = b"\x00\x11\x22\x33\x44\x55"
B_SYS = b"\x00\x66\x77\x88\x99\xaa"
C_SYS = b"\x00\xde\xad\xbe\xef\x01"
A_MAC = b"\x00\xaa\xbb\xcc\xdd\x01"
B_MAC = b"\x00\xaa\xbb\xcc\xdd\x02"
X_MAC = b"\x00\xff\xee\xdd\xcc\xbb"
SYNCED = 0x3D  # activity|aggregation|sync|collecting|distributing


def _a_pdu(state=SYNCED, partner_state=SYNCED, sys_prio=32768, port_prio=32768,
           key=1, port=1, sys_id=A_SYS, p_sys=B_SYS, p_key=1, p_port=1,
           version=1, **kw) -> bytes:
    return b_lacpdu(
        b_port(sys_prio=sys_prio, sys_id=sys_id, key=key, port_prio=port_prio,
               port_num=port, state=state),
        b_port(sys_prio=32768, sys_id=p_sys, key=p_key, port_prio=32768,
               port_num=p_port, state=partner_state),
        version=version, **kw)


def _tier1() -> None:
    # ---------------- parser ------------------------------------------------
    pdu = parse_lacpdu(_a_pdu())
    _check("T01 valid LACPDU parses", pdu.usable and pdu.actor is not None)
    _check("T02 actor fields round-trip",
           pdu.actor.sys_id == A_SYS and pdu.actor.key == 1
           and pdu.actor.port_num == 1 and pdu.actor.state == SYNCED,
           repr(pdu.actor))
    _check("T03 partner fields round-trip",
           pdu.partner.sys_id == B_SYS and pdu.partner.state == SYNCED)
    _check("T04 collector max delay parsed", pdu.collector_max_delay == 0)
    _check("T05 clean PDU raises no anomalies", pdu.anomalies == [],
           str([a.code for a in pdu.anomalies]))

    v2 = parse_lacpdu(_a_pdu(version=2,
                             extra_tlvs=bytes([TLV_PORT_ALGORITHM, 6]) + b"\x00" * 4))
    _check("T06 v2 long LACPDU usable, no unknown-TLV",
           v2.usable and not any(a.code == "LACP-UNKNOWN-TLV" for a in v2.anomalies))

    unk = parse_lacpdu(_a_pdu(extra_tlvs=bytes([0x7F, 6]) + b"\x00" * 4))
    _check("T07 unknown TLV flagged",
           any(a.code == "LACP-UNKNOWN-TLV" for a in unk.anomalies))

    badv = parse_lacpdu(_a_pdu(version=3))
    _check("T08 bad version flagged",
           any(a.code == "LACP-BAD-VERSION" for a in badv.anomalies))

    badlen = parse_lacpdu(_a_pdu(actor_len=21))
    _check("T09 actor TLV length violation flagged",
           any(a.code == "LACP-TLV-LENGTH-INVALID" for a in badlen.anomalies))

    short = parse_lacpdu(_a_pdu()[:20])
    _check("T10 truncated PDU flagged, not usable",
           not short.usable and any(a.code in ("LACP-TLV-LENGTH-INVALID",
                                               "LACP-MALFORMED-SHORT")
                                    for a in short.anomalies))

    _check("T11 empty payload safe",
           parse_lacpdu(b"").anomalies[0].code == "LACP-MALFORMED-SHORT")

    trail = parse_lacpdu(_a_pdu(trailing=b"HELLOATTACKER"))
    _check("T12 trailing non-zero data flagged",
           any(a.code == "LACP-TRAILING-DATA" for a in trail.anomalies),
           str([a.code for a in trail.anomalies]))
    _check("T13 zero padding stays silent",
           not any(a.code == "LACP-TRAILING-DATA"
                   for a in parse_lacpdu(_a_pdu()).anomalies))

    res = parse_lacpdu(b_lacpdu(b_port(reserved=b"\x00\x00\x07"), b_port()))
    _check("T14 reserved non-zero flagged",
           any(a.code == "LACP-RESERVED-NONZERO" for a in res.anomalies))

    swapped = parse_lacpdu(_a_pdu(swap_order=True))
    _check("T15 TLV order violation flagged and PDU not usable",
           not swapped.usable
           and any(a.code == "LACP-TLV-ORDER-INVALID" for a in swapped.anomalies))

    _check("T16 state flag decode",
           state_flags(SYNCED) == ["activity", "aggregation", "synchronization",
                                   "collecting", "distributing"],
           str(state_flags(SYNCED)))

    _check("T17 marker parses", parse_marker(b_marker()).usable)
    _check("T18 marker fields round-trip",
           parse_marker(b_marker(requester_port=7, txn=0xDEADBEEF)).transaction_id
           == 0xDEADBEEF)
    _check("T19 malformed marker flagged",
           any(a.code == "LACP-MARKER-MALFORMED"
               for a in parse_marker(b_marker(length=17)).anomalies))

    fr = decode_ethernet(b_frame(_a_pdu(), tags=(100, 200)), 1.0)
    _check("T20 QinQ tag stack decoded", fr is not None and fr.tags == [100, 200],
           str(fr.tags if fr else None))
    _check("T21 non-slow ethertype ignored",
           decode_ethernet(b"\xff" * 12 + b"\x08\x00" + b"\x00" * 20, 1.0) is None)
    _check("T22 runt frame ignored", decode_ethernet(b"\x00" * 8, 1.0) is None)

    # ---------------- first sighting ---------------------------------------
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0)])
    _check("T23 first sighting: member + posture only",
           set(_codes(eng)) == {"LACP-MEMBER-OBSERVED", "LACP-UNAUTHENTICATED"},
           str(_codes(eng)))
    _check("T24 unauthenticated is INFO, not HIGH",
           _find(eng, "LACP-UNAUTHENTICATED")["severity"] == SEV_INFO)

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0 + i) for i in range(10)])
    _check("T25 steady state is silent after first sighting",
           len(eng.findings) == 2, str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0)], emit_info=False)
    _check("T26 --no-info suppresses posture/inventory", eng.findings == [])

    # ---------------- state machine ----------------------------------------
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 101.0)])
    _check("T27 sync loss on established member", _has(eng, "LACP-SYNC-LOSS"))

    eng = _run([(b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC & ~S_COLLECTING),
                         src=A_MAC), 101.0)])
    _check("T28 no sync-loss for a member never seen synchronized",
           not _has(eng, "LACP-SYNC-LOSS"), str(_codes(eng)))

    frames = [(b_frame(_a_pdu(), src=A_MAC), 100.0)]
    st = SYNCED
    for i in range(4):
        st = st ^ S_SYNC
        frames.append((b_frame(_a_pdu(state=st), src=A_MAC), 101.0 + i))
    eng = _run(frames)
    _check("T29 four sync transitions raise SYNC-FLAPPING",
           _has(eng, "LACP-SYNC-FLAPPING"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_COLLECTING & ~S_DISTRIBUTING),
                         src=A_MAC), 101.0)])
    _check("T30 collecting/distributing cleared while synced",
           _has(eng, "LACP-DISTRIBUTING-LOSS"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_AGGREGATION), src=A_MAC), 101.0)])
    _check("T31 aggregation bit cleared", _has(eng, "LACP-AGGREGATION-CLEARED"))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED | S_DEFAULTED), src=A_MAC), 101.0)])
    _check("T32 defaulted partner info", _has(eng, "LACP-DEFAULTED-PARTNER-INFO"))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED | S_EXPIRED), src=A_MAC), 101.0)])
    _check("T33 receive machine expired", _has(eng, "LACP-RECEIVE-EXPIRED"))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED | S_TIMEOUT), src=A_MAC), 101.0)])
    _check("T34 timeout change", _has(eng, "LACP-TIMEOUT-CHANGE"))

    frames = [(b_frame(_a_pdu(), src=A_MAC), 100.0)]
    st = SYNCED
    for i in range(3):
        st = st ^ S_TIMEOUT
        frames.append((b_frame(_a_pdu(state=st), src=A_MAC), 101.0 + i))
    eng = _run(frames)
    _check("T35 repeated timeout changes raise TIMEOUT-FLAPPING",
           _has(eng, "LACP-TIMEOUT-FLAPPING"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_ACTIVITY), src=A_MAC), 101.0)])
    _check("T36 activity change", _has(eng, "LACP-ACTIVITY-CHANGE"))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(version=2), src=A_MAC), 101.0)])
    _check("T37 version change mid-session", _has(eng, "LACP-VERSION-CHANGE"))

    # ---------------- identity ---------------------------------------------
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(sys_prio=100), src=A_MAC), 101.0)])
    _check("T38 improved system priority", _has(eng, "LACP-SYSTEM-PRIORITY-IMPROVED"))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(sys_prio=65535), src=A_MAC), 101.0)])
    _check("T39 worsened system priority is not a finding",
           not _has(eng, "LACP-SYSTEM-PRIORITY-IMPROVED"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(port_prio=1), src=A_MAC), 101.0)])
    _check("T40 improved port priority", _has(eng, "LACP-PORT-PRIORITY-IMPROVED"))

    eng = _run([(b_frame(_a_pdu(key=1), src=A_MAC), 100.0),
                (b_frame(_a_pdu(key=9), src=A_MAC), 101.0)])
    _check("T41 operational key change", _has(eng, "LACP-KEY-CHANGE"))

    eng = _run([(b_frame(_a_pdu(sys_id=A_SYS), src=A_MAC), 100.0),
                (b_frame(_a_pdu(sys_id=C_SYS), src=A_MAC), 101.0)])
    _check("T42 system id change from one source MAC",
           _has(eng, "LACP-SYSTEM-ID-CHANGE"))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(), src=X_MAC), 101.0)])
    _check("T43 same actor identity from a second MAC = collision",
           _has(eng, "LACP-PORT-IDENTITY-COLLISION"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(), src=X_MAC), 100.0 + 400)])
    _check("T44 same identity from a new MAC long after = MAC change",
           _has(eng, "LACP-ACTOR-MAC-CHANGE") and
           not _has(eng, "LACP-PORT-IDENTITY-COLLISION"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(sys_id=b"\x00" * 6), src=A_MAC), 100.0)])
    _check("T45 null system id rejected, no half created",
           _has(eng, "LACP-SYSTEM-ID-INVALID") and not eng.halves)

    eng = _run([(b_frame(_a_pdu(sys_id=b"\x01\x00\x0c\x00\x00\x01"), src=A_MAC), 100.0)])
    _check("T46 group-address system id rejected",
           _has(eng, "LACP-SYSTEM-ID-INVALID"))

    eng = _run([(b_frame(_a_pdu(port=0), src=A_MAC), 100.0)])
    _check("T47 zero port number", _has(eng, "LACP-PORT-NUMBER-ZERO"))

    # ---------------- delivery path ----------------------------------------
    eng = _run([(b_frame(_a_pdu(), src=A_MAC, tags=(100,)), 100.0)])
    _check("T48 tagged LACPDU flagged", _has(eng, "LACP-VLAN-TAGGED"))
    eng = _run([(b_frame(_a_pdu(), src=A_MAC, dst=B_MAC), 100.0)])
    _check("T49 non-group destination flagged",
           _has(eng, "LACP-NON-SLOW-DESTINATION"))
    eng = _run([(b_frame(bytes([SUBTYPE_OAM, 1]) + b"\x00" * 40, src=A_MAC), 100.0)])
    _check("T50 other slow-protocol subtype inventoried",
           _has(eng, "LACP-SLOW-PROTOCOL-SUBTYPE"))

    # ---------------- rate --------------------------------------------------
    frames = [(b_frame(_a_pdu(), src=A_MAC), 100.0 + i * 0.1) for i in range(25)]
    eng = _run(frames)
    _check("T51 PDU burst detected", _has(eng, "LACP-PDU-BURST"), str(_codes(eng)))

    frames = [(b_frame(_a_pdu(partner_state=SYNCED | S_TIMEOUT), src=A_MAC),
               100.0 + i) for i in range(10)]
    eng = _run(frames)
    _check("T52 fast-rate LACP is not a burst",
           not _has(eng, "LACP-PDU-BURST"), str(_codes(eng)))

    # ---------------- observation gap (false-positive guard) ---------------
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 100.0 + 500)])
    _check("T53 observation gap is a resync, not a state transition",
           not _has(eng, "LACP-SYNC-LOSS") and eng.stats["resyncs"] == 1,
           str(_codes(eng)))

    # ---------------- cross-view -------------------------------------------
    a = b_frame(_a_pdu(sys_id=A_SYS, p_sys=B_SYS), src=A_MAC)
    b = b_frame(_a_pdu(sys_id=B_SYS, p_sys=A_SYS), src=B_MAC)
    eng = _run([(a, 100.0), (b, 100.5), (a, 101.0), (b, 101.5)])
    _check("T54 consistent pair produces no mismatch",
           not _has(eng, "LACP-PARTNER-VIEW-MISMATCH")
           and eng.bidirectional_confirmed, str(_codes(eng)))

    a = b_frame(_a_pdu(sys_id=A_SYS, p_sys=B_SYS), src=A_MAC)
    b_bad = b_frame(_a_pdu(sys_id=B_SYS, p_sys=C_SYS), src=B_MAC)
    eng = _run([(a, 100.0), (b_bad, 100.5), (a, 130.0), (b_bad, 130.5),
                (a, 160.0), (b_bad, 160.5), (a, 200.0), (b_bad, 200.5)])
    _check("T55 persistently disagreeing pair raises PARTNER-VIEW-MISMATCH",
           _has(eng, "LACP-PARTNER-VIEW-MISMATCH"), str(_codes(eng)))

    eng = _run([(a, 100.0), (b_bad, 100.5)])
    _check("T55b a single disagreeing PDU is not yet a mismatch",
           not _has(eng, "LACP-PARTNER-VIEW-MISMATCH"), str(_codes(eng)))

    eng = _run([(a, 100.0), (b_frame(_a_pdu(sys_id=B_SYS, p_sys=A_SYS),
                                     src=B_MAC), 100.5),
                (b_frame(_a_pdu(sys_id=A_SYS, key=7, p_sys=B_SYS), src=A_MAC),
                 130.0),
                (b_frame(_a_pdu(sys_id=A_SYS, key=7, p_sys=B_SYS), src=A_MAC),
                 160.0),
                (b_frame(_a_pdu(sys_id=A_SYS, key=7, p_sys=B_SYS), src=A_MAC),
                 300.0)])
    _check("T55c a stale partner view is not a mismatch",
           not _has(eng, "LACP-PARTNER-VIEW-MISMATCH"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(sys_id=A_SYS, p_sys=B_SYS), src=A_MAC), 100.0),
                (b_frame(_a_pdu(sys_id=B_SYS, p_sys=A_SYS), src=B_MAC), 100.5),
                (b_frame(_a_pdu(sys_id=C_SYS, p_sys=b"\x00\x99\x99\x99\x99\x99"),
                         src=X_MAC), 101.0)],
               partner_unobserved=True)
    _check("T56 unobserved partner gated on bidirectional proof",
           _has(eng, "LACP-PARTNER-UNOBSERVED"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(sys_id=C_SYS,
                                p_sys=b"\x00\x99\x99\x99\x99\x99"), src=X_MAC), 101.0)],
               partner_unobserved=True)
    _check("T57 unobserved partner silent without bidirectional proof",
           not _has(eng, "LACP-PARTNER-UNOBSERVED"), str(_codes(eng)))

    # ---------------- correlation ------------------------------------------
    eng = _run([
        (b_frame(_a_pdu(), src=A_MAC), 100.0),
        (b_frame(_a_pdu(sys_prio=100), src=X_MAC), 101.0),          # identity
        (b_frame(_a_pdu(sys_prio=100, state=SYNCED & ~S_SYNC), src=X_MAC), 102.0),
    ])
    _check("T58 identity manipulation + disruption = LAG-HIJACK",
           _has(eng, "LACP-LAG-HIJACK"), str(_codes(eng)))
    hj = _find(eng, "LACP-LAG-HIJACK")
    _check("T59 hijack severity is critical",
           hj is not None and hj["severity"] == SEV_CRITICAL)
    _check("T60 every correlated code was itself emitted earlier",
           hj is not None and all(
               c in _codes(eng) for c in hj["evidence"]["correlated_codes"]),
           str(hj["evidence"]["correlated_codes"]) if hj else "")

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(sys_prio=100), src=A_MAC), 101.0)])
    _check("T61 identity change alone is not a hijack",
           not _has(eng, "LACP-LAG-HIJACK"), str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 101.0)])
    _check("T62 disruption alone is not a hijack",
           not _has(eng, "LACP-LAG-HIJACK"), str(_codes(eng)))

    # ---------------- malformed-induced flap (CVE-2024-30388 class) --------
    # attacker MAC sends a malformed PDU, then an established member flaps
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(actor_len=21), src=X_MAC), 101.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 102.0)])
    _check("T87 malformed PDU then member flap correlates",
           _has(eng, "LACP-MALFORMED-INDUCED-FLAP"), str(_codes(eng)))
    mf = _find(eng, "LACP-MALFORMED-INDUCED-FLAP")
    _check("T88 induced-flap is HIGH and names the CVE",
           mf is not None and mf["severity"] == SEV_HIGH
           and mf["evidence"]["cve"] == "CVE-2024-30388")
    _check("T89 induced-flap names a malformed finding emitted earlier",
           mf is not None
           and all(o["code"] in _codes(eng)
                   for o in mf["evidence"]["malformed_observations"])
           and all(o["seconds_before_flap"] >= 0
                   for o in mf["evidence"]["malformed_observations"]),
           str(mf["evidence"]["malformed_observations"]) if mf else "")

    # a flap with no malformed PDU at all
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 101.0)])
    _check("T90 flap alone does not correlate",
           not _has(eng, "LACP-MALFORMED-INDUCED-FLAP"), str(_codes(eng)))

    # malformed PDU with no flap following
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(actor_len=21), src=X_MAC), 101.0),
                (b_frame(_a_pdu(), src=A_MAC), 102.0)])
    _check("T91 malformed alone does not correlate",
           not _has(eng, "LACP-MALFORMED-INDUCED-FLAP"), str(_codes(eng)))

    # the flapping member is itself the malformed sender: failing NIC, not an
    # induced flap
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(actor_len=21), src=A_MAC), 101.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 102.0)])
    _check("T92 member emitting its own garbage is excluded",
           not _has(eng, "LACP-MALFORMED-INDUCED-FLAP"), str(_codes(eng)))

    # malformed PDU well outside the correlation window
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(actor_len=21), src=X_MAC), 101.0),
                (b_frame(_a_pdu(), src=A_MAC), 130.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 160.0)])
    _check("T93 malformed outside the window does not correlate",
           not _has(eng, "LACP-MALFORMED-INDUCED-FLAP"), str(_codes(eng)))

    # ordering: the malformed PDU must PRECEDE the flap
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 101.0),
                (b_frame(_a_pdu(actor_len=21), src=X_MAC), 102.0)])
    _check("T94 malformed after the flap does not correlate backwards",
           not _has(eng, "LACP-MALFORMED-INDUCED-FLAP"), str(_codes(eng)))

    # flap-storm variant: correlates against SYNC-FLAPPING too
    frames = [(b_frame(_a_pdu(), src=A_MAC), 100.0),
              (b_frame(_a_pdu(actor_len=21), src=X_MAC), 100.5)]
    st = SYNCED
    for i in range(4):
        st = st ^ S_SYNC
        frames.append((b_frame(_a_pdu(state=st), src=A_MAC), 101.0 + i))
    eng = _run(frames)
    mf = _find(eng, "LACP-MALFORMED-INDUCED-FLAP")
    # Fires on the FIRST disruption after the malformed PDU (earliest
    # detection); the later flap-storm finding is rate-limited under the same
    # key rather than producing a second correlation.
    _check("T95 correlates on the first disruption of a flap storm",
           mf is not None
           and mf["evidence"]["disruption"] in INDUCED_DISRUPTION_CODES
           and len([f for f in eng.findings
                    if f["code"] == "LACP-MALFORMED-INDUCED-FLAP"]) == 1,
           str(_codes(eng)))

    # a second, independent malformed+flap episode on a DIFFERENT member still
    # correlates - rate limiting is per member, not global
    eng = _run([(b_frame(_a_pdu(port=1), src=A_MAC), 100.0),
                (b_frame(_a_pdu(port=2), src=B_MAC), 100.1),
                (b_frame(_a_pdu(actor_len=21), src=X_MAC), 101.0),
                (b_frame(_a_pdu(port=1, state=SYNCED & ~S_SYNC), src=A_MAC), 102.0),
                (b_frame(_a_pdu(port=2, state=SYNCED & ~S_SYNC), src=B_MAC), 102.5)])
    _check("T96 correlation is per-member, not global",
           len([f for f in eng.findings
                if f["code"] == "LACP-MALFORMED-INDUCED-FLAP"]) == 2,
           str(_codes(eng)))

    # ---------------- marker ------------------------------------------------
    frames = [(b_frame(_a_pdu(), src=A_MAC), 100.0)]
    frames += [(b_frame(b_marker(requester_system=A_SYS), src=A_MAC),
                100.0 + i * 0.1) for i in range(30)]
    eng = _run(frames)
    _check("T63 marker request flood", _has(eng, "LACP-MARKER-FLOOD"),
           str(_codes(eng)))

    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(b_marker(requester_system=C_SYS), src=X_MAC), 101.0)])
    _check("T64 marker from an unknown requester system",
           _has(eng, "LACP-MARKER-UNKNOWN-REQUESTER"), str(_codes(eng)))

    eng = _run([(b_frame(b_marker(length=17), src=A_MAC), 100.0)])
    _check("T65 malformed marker", _has(eng, "LACP-MARKER-MALFORMED"))

    # ---------------- rate limiting and rollup ------------------------------
    frames = [(b_frame(_a_pdu(), src=A_MAC), 100.0)]
    for i in range(20):
        frames.append((b_frame(_a_pdu(state=SYNCED ^ (S_SYNC if i % 2 else 0)),
                               src=A_MAC), 200.0 + i * 30))
    eng = _run(frames)
    dl = [f for f in eng.findings if f["code"] == "LACP-SYNC-LOSS"]
    _check("T66 repeated identical findings are rate limited",
           len(dl) <= 3 and eng.stats["suppressed"] > 0,
           "sync-loss=%d suppressed=%d" % (len(dl), eng.stats["suppressed"]))

    frames = []
    for i in range(40):
        src = bytes([0x02, 0, 0, 0, i >> 8, i & 0xFF])
        frames.append((b_frame(_a_pdu()[:20], src=src), 100.0 + i * 0.01))
    eng = _run(frames)
    _check("T67 spoofed-source flood collapses into a rollup",
           _has(eng, "LACP-ORPHAN-ROLLUP") and len(eng.findings) <= 14,
           "findings=%d" % len(eng.findings))
    ru = _find(eng, "LACP-ORPHAN-ROLLUP")
    _check("T68 rollup carries distinct source count",
           ru is not None and ru["evidence"]["distinct_sources"] > ORPHAN_CODE_BUDGET)

    # ---------------- contract ----------------------------------------------
    eng = _run([(b_frame(_a_pdu(), src=A_MAC), 100.0),
                (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC), 101.0)])
    ok = True
    for f in eng.findings:
        try:
            json.dumps(f)
        except (TypeError, ValueError):
            ok = False
        for k in ("ts", "module", "type", "code", "severity", "confidence",
                  "title", "session", "evidence"):
            ok = ok and k in f
        ok = ok and f["severity"] in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM,
                                      SEV_LOW, SEV_INFO)
        ok = ok and f["confidence"] in (CONF_HIGH, CONF_MEDIUM, CONF_LOW)
        ok = ok and f["title"] == CODES[f["code"]]["title"]
    _check("T69 findings are well-formed and JSON-serializable", ok)
    _check("T70 session label carries source, system, key and port",
           all(("sys=" in f["session"] and "key=0x" in f["session"]
                and "port=" in f["session"]) or f["session"] == "-"
               or f["code"] in ("LACP-VLAN-TAGGED", "LACP-NON-SLOW-DESTINATION")
               for f in eng.findings), str([f["session"] for f in eng.findings]))
    _check("T71 timestamps are UTC millisecond ISO-8601",
           all(f["ts"].endswith("Z") and len(f["ts"]) == 24 for f in eng.findings))

    s = eng.summary(200.0, "sigterm")
    _check("T72 summary reports stop reason and stats",
           s["stopped_on"] == "sigterm" and s["stats"]["lacpdus"] == 2
           and s["type"] == "summary")

    # ---------------- robustness -------------------------------------------
    import random
    rnd = random.Random(20260903)
    base = _a_pdu()
    crashes = 0
    for _ in range(3000):
        data = bytearray(base)
        for _ in range(rnd.randint(1, 6)):
            if not data:
                break
            data[rnd.randrange(len(data))] = rnd.randrange(256)
        if rnd.random() < 0.3:
            data = data[:rnd.randrange(len(data) + 1)]
        if rnd.random() < 0.1:
            data += bytes(rnd.randrange(64))
        try:
            e = LacpWatch()
            e.on_frame(b_frame(bytes(data), src=A_MAC), 100.0)
            for f in e.findings:
                json.dumps(f)
        except Exception:  # noqa: BLE001
            crashes += 1
    _check("T73 3000 mutated PDUs: no exceptions", crashes == 0,
           "crashes=%d" % crashes)

    crashes = 0
    for _ in range(1000):
        n = rnd.randrange(0, 200)
        raw = bytes(rnd.randrange(256) for _ in range(n))
        try:
            e = LacpWatch()
            e.on_frame(raw, 100.0)
        except Exception:  # noqa: BLE001
            crashes += 1
    _check("T74 1000 random frames: no exceptions", crashes == 0,
           "crashes=%d" % crashes)

    # T75: lacpwatch is pure-python and scapy-free (live capture uses AF_PACKET
    # directly — see the module header). Verify this from the module's OWN SOURCE,
    # not sys.modules: in a shared interpreter (e.g. Ragnar's aggregate self-test)
    # another module may legitimately pull scapy into the process, which says
    # nothing about whether *this* module imports it. The regex is anchored to the
    # start of a line, so it never matches this check's own text.
    try:
        _src = open(os.path.abspath(__file__), "r", encoding="utf-8").read()
        _self_imports_scapy = re.search(
            r"(?m)^\s*(?:import\s+scapy|from\s+scapy\b)", _src) is not None
    except OSError:
        _self_imports_scapy = "scapy" in sys.modules      # fall back to the process check
    _check("T75 scapy is never imported", not _self_imports_scapy)

    # ---------------- pcap round trip --------------------------------------
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="lacpwatch-t1-")
    path = os.path.join(tmpd, "corpus.pcap")
    write_pcap(path, [(b_frame(_a_pdu(), src=A_MAC), 1725400000.123456),
                      (b_frame(_a_pdu(state=SYNCED & ~S_SYNC), src=A_MAC),
                       1725400001.5)])
    got = list(read_pcap(path))
    _check("T76 pcap writer/reader round-trip", len(got) == 2
           and abs(got[0][1] - 1725400000.123456) < 1e-5)
    eng = LacpWatch()
    for raw, ts in read_pcap(path):
        eng.on_frame(raw, ts)
    _check("T77 engine consumes the pcap path", _has(eng, "LACP-SYNC-LOSS"))
    _EMITTED_CODES.update(_codes(eng))
    with open(os.path.join(tmpd, "bad.pcap"), "wb") as fh:
        fh.write(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    try:
        list(read_pcap(os.path.join(tmpd, "bad.pcap")))
        _check("T78 pcapng rejected with a clear error", False)
    except PcapError as exc:
        _check("T78 pcapng rejected with a clear error", "pcapng" in str(exc))

    # ---------------- memory bounds ----------------------------------------
    eng = LacpWatch()
    for i in range(3000):
        src = bytes([0x02, 0, 0, 0, (i >> 8) & 0xFF, i & 0xFF])
        eng.on_frame(b_frame(_a_pdu(sys_id=src, port=i % 65535 or 1), src=src),
                     100.0 + i * 0.001)
    halves_before = len(eng.halves)
    eng.on_frame(b_frame(_a_pdu(), src=A_MAC), 100.0 + 3600 * 2)
    _check("T79 idle halves are pruned",
           halves_before >= 2900 and len(eng.halves) <= 2,
           "before=%d after=%d" % (halves_before, len(eng.halves)))

    # ---------------- parser anomalies through the engine ------------------
    eng = _run([(b_frame(b"\x01", src=A_MAC), 100.0)])
    _check("T81 sub-minimal LACPDU reaches the engine as MALFORMED-SHORT",
           _has(eng, "LACP-MALFORMED-SHORT"), str(_codes(eng)))
    eng = _run([(b_frame(_a_pdu(version=7), src=A_MAC), 100.0)])
    _check("T82 bad version emitted by the engine", _has(eng, "LACP-BAD-VERSION"))
    eng = _run([(b_frame(_a_pdu(extra_tlvs=bytes([0x7F, 6]) + b"\x00" * 4),
                         src=A_MAC), 100.0)])
    _check("T83 unknown TLV emitted by the engine", _has(eng, "LACP-UNKNOWN-TLV"))
    eng = _run([(b_frame(_a_pdu(trailing=b"SMUGGLED"), src=A_MAC), 100.0)])
    _check("T84 trailing data emitted by the engine",
           _has(eng, "LACP-TRAILING-DATA"), str(_codes(eng)))
    eng = _run([(b_frame(b_lacpdu(b_port(sys_id=A_SYS, reserved=b"\x00\x00\x07"),
                                  b_port(sys_id=B_SYS)), src=A_MAC), 100.0)])
    _check("T85 reserved non-zero emitted by the engine",
           _has(eng, "LACP-RESERVED-NONZERO"), str(_codes(eng)))
    eng = _run([(b_frame(_a_pdu(swap_order=True), src=A_MAC), 100.0)])
    _check("T86 TLV order violation emitted by the engine, no half created",
           _has(eng, "LACP-TLV-ORDER-INVALID") and not eng.halves, str(_codes(eng)))

    # ================= PAgP abuse / semantics tier =========================
    P_DEV = b"\x00\x11\x22\x33\x44\x55"
    Q_DEV = b"\x00\x66\x77\x88\x99\xaa"
    R_DEV = b"\x00\xde\xad\xbe\xef\x01"
    PM = b"\x00\xaa\xaa\x00\x00\x01"
    QM = b"\x00\xbb\xbb\x00\x00\x01"
    CS = PAGP_FLAG_CONSISTENT_STATE

    def pg(src=PM, **kw):
        return b_pagp_frame(b_pagp_info(**kw), src=src)

    # -- decode / parse ------------------------------------------------------
    fr = decode_pagp(b_pagp_frame(b_pagp_info()), 1.0)
    _check("T97 PAgP LLC/SNAP frame decodes", fr is not None
           and fr.ethertype == PAGP_SNAP_PID)
    pp = parse_pagp(fr.payload)
    _check("T98 PAgP info header fields round-trip",
           pp.usable and pp.local_devid == P_DEV and pp.local_sent_ifindex == 1
           and pp.local_portpri == 128 and pp.local_groupcap == 0x10001,
           repr(pp))
    _check("T99 PAgP partner fields round-trip",
           pp.partner_devid == Q_DEV and pp.partner_identity == (Q_DEV, 1))
    _check("T100 PAgP info header is exactly 46 bytes",
           PAGP_INFO_HEADER_LEN == 46 and len(b_pagp_info()) == 46)
    fl = parse_pagp(decode_pagp(b_pagp_frame(b_pagp_flush(transid=7)), 1.0).payload)
    _check("T101 PAgP Flush uses its own 18-byte layout, no TLVs",
           fl.usable and fl.is_flush and fl.transid == 7
           and PAGP_FLUSH_LEN == 18 and len(b_pagp_flush()) == 18)
    tl = parse_pagp(decode_pagp(b_pagp_frame(
        b_pagp_info(tlvs=b_pagp_tlv(PAGP_TLV_DEVICE_NAME, b"sw1") +
                    b_pagp_tlv(PAGP_TLV_PORT_NAME, b"Gi0/1"), numtlvs=2)),
        1.0).payload)
    _check("T102 PAgP TLVs walk in CDP grammar (length includes header)",
           tl.usable and tl.tlv_types == [PAGP_TLV_DEVICE_NAME,
                                          PAGP_TLV_PORT_NAME],
           str(tl.tlv_types))
    _check("T103 non-PAgP SNAP PID ignored",
           decode_pagp(b"\xff" * 12 + b"\x00\x14\xaa\xaa\x03\x00\x00\x0c"
                       + b"\x20\x00" + b"\x00" * 10, 1.0) is None)
    _check("T104 LACP frame is not misread as PAgP",
           decode_pagp(b_frame(_a_pdu(), src=A_MAC), 1.0) is None)

    # -- structural defects are cdpwatch's, not ours -------------------------
    eng = _run([(b_pagp_frame(b"\x01\x04\x00\x00", src=PM), 100.0)])
    _check("T105 truncated PAgP is dropped, not reported (cdpwatch owns it)",
           eng.findings == [] and eng.stats["pagp_unparseable"] == 1,
           str(_codes(eng)))
    _check("T106 no lacpwatch code collides with cdpwatch's PAGP-0NN space",
           not any(re.match(r"^PAGP-\d+$", c) for c in CODES),
           str([c for c in CODES if re.match(r"^PAGP-\d+$", c)]))

    # -- first sighting / steady state --------------------------------------
    eng = _run([(pg(), 100.0)])
    _check("T107 PAgP first sighting: member + posture only",
           set(_codes(eng)) == {"PAGP-MEMBER-OBSERVED", "PAGP-UNAUTHENTICATED"},
           str(_codes(eng)))
    eng = _run([(pg(), 100.0 + i * 30) for i in range(10)])
    _check("T108 steady PAgP is silent after first sighting",
           len(eng.findings) == 2, str(_codes(eng)))

    # -- identity ------------------------------------------------------------
    eng = _run([(pg(), 100.0), (pg(src=QM), 101.0)])
    _check("T109 same PAgP identity from a second MAC = collision",
           _has(eng, "PAGP-DEVICE-ID-COLLISION"), str(_codes(eng)))
    eng = _run([(pg(), 100.0), (pg(src=QM), 100.0 + 400)])
    _check("T110 same identity from a new MAC long after = MAC change",
           _has(eng, "PAGP-ACTOR-MAC-CHANGE")
           and not _has(eng, "PAGP-DEVICE-ID-COLLISION"), str(_codes(eng)))
    eng = _run([(pg(devid=P_DEV), 100.0), (pg(devid=R_DEV), 101.0)])
    _check("T111 one MAC rewriting its Device ID",
           _has(eng, "PAGP-DEVICE-ID-CHANGE"), str(_codes(eng)))

    # PAgP port priority: HIGHER wins (opposite of LACP)
    eng = _run([(pg(portpri=128), 100.0), (pg(portpri=255), 101.0)])
    _check("T112 PAgP priority RAISED is the takeover direction",
           _has(eng, "PAGP-PORT-PRIORITY-IMPROVED"), str(_codes(eng)))
    eng = _run([(pg(portpri=128), 100.0), (pg(portpri=1), 101.0)])
    _check("T113 PAgP priority LOWERED is not a finding (inverse of LACP)",
           not _has(eng, "PAGP-PORT-PRIORITY-IMPROVED"), str(_codes(eng)))

    eng = _run([(pg(groupcap=0x10001), 100.0), (pg(groupcap=0x20002), 101.0)])
    _check("T114 group capability change moves the port between bundles",
           _has(eng, "PAGP-GROUP-CAP-CHANGE"))

    # -- state ---------------------------------------------------------------
    eng = _run([(pg(flags=CS), 100.0), (pg(flags=0), 101.0)])
    _check("T115 consistent state cleared on an established member",
           _has(eng, "PAGP-CONSISTENT-STATE-LOSS"), str(_codes(eng)))
    eng = _run([(pg(flags=0), 100.0), (pg(flags=0), 101.0)])
    _check("T116 member never seen consistent does not report loss",
           not _has(eng, "PAGP-CONSISTENT-STATE-LOSS"), str(_codes(eng)))
    frames = [(pg(flags=CS), 100.0)]
    f_ = CS
    for i in range(4):
        f_ = f_ ^ CS
        frames.append((pg(flags=f_), 101.0 + i))
    eng = _run(frames)
    _check("T117 repeated consistent-state transitions = STATE-FLAPPING",
           _has(eng, "PAGP-STATE-FLAPPING"), str(_codes(eng)))
    eng = _run([(pg(flags=CS), 100.0),
                (pg(flags=CS | PAGP_FLAG_SLOW_HELLO), 101.0)])
    _check("T118 hello-rate change", _has(eng, "PAGP-HELLO-RATE-CHANGE"))
    frames = [(pg(flags=CS), 100.0)]
    f_ = CS
    for i in range(3):
        f_ = f_ ^ PAGP_FLAG_SLOW_HELLO
        frames.append((pg(flags=f_), 101.0 + i))
    eng = _run(frames)
    _check("T119 repeated hello-rate changes = HELLO-RATE-FLAPPING",
           _has(eng, "PAGP-HELLO-RATE-FLAPPING"), str(_codes(eng)))
    eng = _run([(pg(flags=CS), 100.0),
                (pg(flags=CS | PAGP_FLAG_AUTO_MODE), 101.0)])
    _check("T120 auto/desirable mode change", _has(eng, "PAGP-MODE-CHANGE"))
    eng = _run([(pg(p_devid=Q_DEV), 100.0),
                (pg(p_devid=b"\x00" * 6, p_sent_ifindex=0), 101.0)])
    _check("T121 partner info cleared = relearn",
           _has(eng, "PAGP-PARTNER-INFO-RESET"), str(_codes(eng)))

    # -- rate ----------------------------------------------------------------
    eng = _run([(pg(), 100.0 + i * 0.05) for i in range(40)])
    _check("T122 PAgP PDU burst", _has(eng, "PAGP-PDU-BURST"), str(_codes(eng)))
    eng = _run([(pg(flags=CS), 100.0 + i) for i in range(10)])
    _check("T123 fast-hello PAgP is not a burst",
           not _has(eng, "PAGP-PDU-BURST"), str(_codes(eng)))

    # -- observation gap -----------------------------------------------------
    eng = _run([(pg(flags=CS), 100.0), (pg(flags=0), 100.0 + 500)])
    _check("T124 PAgP observation gap is a resync, not a transition",
           not _has(eng, "PAGP-CONSISTENT-STATE-LOSS")
           and eng.stats["resyncs"] >= 1, str(_codes(eng)))

    # -- cross view ----------------------------------------------------------
    a_f = pg(src=PM, devid=P_DEV, sent_ifindex=1, p_devid=Q_DEV, p_sent_ifindex=1)
    b_f = pg(src=QM, devid=Q_DEV, sent_ifindex=1, p_devid=P_DEV, p_sent_ifindex=1)
    eng = _run([(a_f, 100.0), (b_f, 100.5), (a_f, 130.0), (b_f, 130.5)])
    _check("T125 consistent PAgP pair produces no mismatch",
           not _has(eng, "PAGP-PARTNER-VIEW-MISMATCH"), str(_codes(eng)))
    b_bad = pg(src=QM, devid=Q_DEV, sent_ifindex=1, p_devid=R_DEV,
               p_sent_ifindex=1)
    eng = _run([(a_f, 100.0), (b_bad, 100.5), (a_f, 102.0), (b_bad, 102.5),
                (a_f, 104.0), (b_bad, 104.5), (a_f, 110.0), (b_bad, 110.5)])
    _check("T126 persistently disagreeing PAgP pair raises mismatch",
           _has(eng, "PAGP-PARTNER-VIEW-MISMATCH"), str(_codes(eng)))
    eng = _run([(a_f, 100.0), (b_bad, 100.5)])
    _check("T127 a single disagreeing PAgP PDU is not yet a mismatch",
           not _has(eng, "PAGP-PARTNER-VIEW-MISMATCH"), str(_codes(eng)))

    # -- flush ---------------------------------------------------------------
    eng = _run([(pg(), 100.0),
                (b_pagp_frame(b_pagp_flush(local_devid=R_DEV), src=QM), 101.0)])
    _check("T128 Flush naming an unseen device",
           _has(eng, "PAGP-FLUSH-FROM-UNKNOWN-DEVICE"), str(_codes(eng)))
    eng = _run([(pg(), 100.0)] +
               [(b_pagp_frame(b_pagp_flush(local_devid=P_DEV, transid=i),
                              src=PM), 101.0 + i * 0.5) for i in range(10)])
    _check("T129 Flush burst", _has(eng, "PAGP-FLUSH-BURST"), str(_codes(eng)))

    # -- correlation ---------------------------------------------------------
    eng = _run([(pg(flags=CS), 100.0),
                (pg(src=QM, portpri=255, flags=CS), 101.0),
                (pg(src=QM, portpri=255, flags=0), 102.0)])
    _check("T130 PAgP identity manipulation + disruption = BUNDLE-HIJACK",
           _has(eng, "PAGP-BUNDLE-HIJACK"), str(_codes(eng)))
    hj = _find(eng, "PAGP-BUNDLE-HIJACK")
    _check("T131 PAgP hijack is critical and names codes emitted earlier",
           hj is not None and hj["severity"] == SEV_CRITICAL
           and all(c in _codes(eng)
                   for c in hj["evidence"]["correlated_codes"]))
    eng = _run([(pg(flags=CS), 100.0), (pg(portpri=255, flags=CS), 101.0)])
    _check("T132 PAgP identity change alone is not a hijack",
           not _has(eng, "PAGP-BUNDLE-HIJACK"), str(_codes(eng)))

    # ================= PFC / PAUSE tier ====================================
    XM = b"\x00\xcc\xcc\x00\x00\x01"

    _check("T133 802.3x PAUSE parses",
           parse_mac_control(b_pause(100)).pause_time == 100)
    q = parse_mac_control(b_pfc(0x05, [10, 0, 30, 0, 0, 0, 0, 0]))
    _check("T134 802.1Qbb PFC parses class vector and 8 timers",
           q.usable and q.class_enable == 0x05
           and q.times == [10, 0, 30, 0, 0, 0, 0, 0], repr(q))
    _check("T135 truncated PFC flagged malformed",
           not parse_mac_control(b"\x01\x01\x00\x01\x00").usable)

    eng = _run([(b_macc_frame(b_pause(100), src=XM), 100.0)])
    _check("T136 PAUSE observed is INFO inventory",
           _has(eng, "PFC-PAUSE-OBSERVED")
           and _find(eng, "PFC-PAUSE-OBSERVED")["severity"] == SEV_INFO)
    eng = _run([(b_macc_frame(b_pfc(0x01, [10, 0, 0, 0, 0, 0, 0, 0]), src=XM),
                 100.0)])
    _check("T137 PFC observed is INFO inventory", _has(eng, "PFC-PFC-OBSERVED"))

    eng = _run([(b_macc_frame(b_pause(0xFFFF), src=XM), 100.0)])
    _check("T138 maximum-quanta pause flagged", _has(eng, "PFC-MAX-QUANTA"))
    eng = _run([(b_macc_frame(b_pause(100), src=XM, dst=QM), 100.0)])
    _check("T139 MAC Control to a non-group destination",
           _has(eng, "PFC-NON-GROUP-DESTINATION"))
    eng = _run([(b_macc_frame(struct.pack("!H", 0x0999) + b"\x00" * 42,
                              src=XM), 100.0)])
    _check("T140 unknown MAC Control opcode", _has(eng, "PFC-UNKNOWN-OPCODE"))
    eng = _run([(b_macc_frame(b"\x01\x01\x00\x01\x00", src=XM), 100.0)])
    _check("T141 malformed MAC Control", _has(eng, "PFC-MALFORMED"),
           str(_codes(eng)))

    # a single XOFF is ordinary congestion signalling and must stay quiet
    eng = _run([(b_macc_frame(b_pfc(0x01, [100, 0, 0, 0, 0, 0, 0, 0]), src=XM),
                 100.0),
                (b_macc_frame(b_pfc(0x01, [0] * 8), src=XM), 100.5)])
    _check("T142 one XOFF then XON is normal flow control, no alarm",
           not any(f["severity"] in (SEV_HIGH, SEV_CRITICAL)
                   for f in eng.findings), str(_codes(eng)))

    # deadlock: priority held XOFF continuously, no XON ever
    frames = [(b_macc_frame(b_pfc(0x01, [0xFFFF, 0, 0, 0, 0, 0, 0, 0]),
                            src=XM), 100.0 + i) for i in range(20)]
    eng = _run(frames)
    _check("T143 priority held XOFF with no XON = deadlock signature",
           _has(eng, "PFC-DEADLOCK-SUSPECTED"), str(_codes(eng)))

    # starvation: priority 2 pinned while 0 and 1 keep getting XON
    frames = []
    for i in range(40):
        t = 100.0 + i * 0.5
        frames.append((b_macc_frame(
            b_pfc(0x07, [0, 0, 0xFFFF, 0, 0, 0, 0, 0]), src=XM), t))
    eng = _run(frames)
    _check("T144 one class pinned while others run = starvation",
           _has(eng, "PFC-PRIORITY-STARVATION"), str(_codes(eng)))

    frames = [(b_macc_frame(b_pfc(0x01, [50, 0, 0, 0, 0, 0, 0, 0]), src=XM),
               100.0 + i * 0.01) for i in range(300)]
    eng = _run(frames)
    _check("T145 XOFF storm", _has(eng, "PFC-XOFF-STORM"), str(_codes(eng)))

    eng = _run([(b_macc_frame(b_pfc(0x01, [10, 0, 0, 0, 0, 0, 0, 0]), src=XM),
                 100.0),
                (b_macc_frame(b_pause(100), src=QM), 101.0)])
    _check("T146 global PAUSE mixed with PFC on one segment",
           _has(eng, "PFC-LEGACY-PAUSE-IN-PFC-FABRIC"), str(_codes(eng)))

    # -- robustness across both new tiers ------------------------------------
    rnd2 = random.Random(20261013)
    crashes = 0
    for base_build in (lambda: b_pagp_frame(b_pagp_info(), src=PM),
                       lambda: b_macc_frame(b_pfc(0x0F, [1, 2, 3, 4, 5, 6, 7, 8]),
                                            src=XM),
                       lambda: b_macc_frame(b_pause(5), src=XM),
                       lambda: b_pagp_frame(b_pagp_flush(), src=PM)):
        base = bytearray(base_build())
        for _ in range(1500):
            data = bytearray(base)
            for _ in range(rnd2.randint(1, 6)):
                if not data:
                    break
                data[rnd2.randrange(len(data))] = rnd2.randrange(256)
            if rnd2.random() < 0.3:
                data = data[:rnd2.randrange(len(data) + 1)]
            try:
                e = LacpWatch()
                e.on_frame(bytes(data), 100.0)
                for f in e.findings:
                    json.dumps(f)
            except Exception:  # noqa: BLE001
                crashes += 1
    _check("T147 6000 mutated PAgP/MAC-Control frames: no exceptions",
           crashes == 0, "crashes=%d" % crashes)

    eng = LacpWatch()
    for i in range(2000):
        src = bytes([0x02, 0, 0, 1, (i >> 8) & 0xFF, i & 0xFF])
        eng.on_frame(b_pagp_frame(b_pagp_info(devid=src, sent_ifindex=i or 1),
                                  src=src), 100.0 + i * 0.001)
        eng.on_frame(b_macc_frame(b_pfc(0x01, [5, 0, 0, 0, 0, 0, 0, 0]),
                                  src=src), 100.0 + i * 0.001)
    before = (len(eng.pagp_members), len(eng.pfc_sources))
    eng.on_frame(pg(), 100.0 + 3600 * 2)
    _check("T148 PAgP members and PFC sources are pruned",
           before[0] >= 1900 and before[1] >= 1900
           and len(eng.pagp_members) <= 2 and len(eng.pfc_sources) <= 2,
           "before=%s after=(%d,%d)" % (before, len(eng.pagp_members),
                                        len(eng.pfc_sources)))

    # ---------------- catalogue reachability -------------------------------
    unreached = sorted(set(CODES) - _EMITTED_CODES)
    _check("T80 every declared finding code is reachable by the suite",
           not unreached, "unreached=%s" % unreached)


def run_self_test() -> int:
    _tier1()
    failed = [r for r in _RESULTS if not r[1]]
    for name, ok, detail in _RESULTS:
        if not ok:
            print("FAIL %s %s" % (name, ("- " + detail) if detail else ""),
                  file=sys.stderr)
    print("lacpwatch %s tier1: %d/%d checks passed"
          % (__version__, len(_RESULTS) - len(failed), len(_RESULTS)),
          file=sys.stderr)
    return 1 if failed else 0



# --- Ragnar integration layer (do_lacp_watch / selftest / Watchtower) ------
import subprocess
import tempfile
from datetime import datetime, timezone

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
    """Aggregator adapter: run the module's own Tier-1 suite (pure-Python, no
    sockets/capture) and return the {'success', 'scenarios'} shape the Ragnar
    detector self-test renders."""
    del _RESULTS[:]
    _tier1()
    scen = [{"name": n, "pass": bool(ok)} for n, ok, _d in _RESULTS]
    return {"success": all(ok for _n, ok, _d in _RESULTS), "scenarios": scen}


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # `lacpwatch --list-codes | head` and friends: exit quietly instead of
        # letting the interpreter print an ignored-exception traceback.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(0)
