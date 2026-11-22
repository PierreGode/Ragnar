#!/usr/bin/env python3
"""
mrpwatch - passive MVRP/MMRP/GVRP/GMRP detector for Ragnar.

Sibling module to vtpwatch (the way lldpwatch is sibling to cdpwatch).
Covers dynamic VLAN/multicast-MAC registration on both generations:

  modern  MRP  (802.1ak)  MVRP  EtherType 0x88F5  dst 01:80:C2:00:00:21
                          MMRP  EtherType 0x88F6  dst 01:80:C2:00:00:20
  legacy  GARP (802.1D)   GVRP  no EtherType, LLC/802.3, dst 01:80:C2:00:00:21
                          GMRP  no EtherType, LLC/802.3, dst 01:80:C2:00:00:20

PASSIVE ONLY. This module never transmits. It decodes captured frames and
emits findings. There is no active verification tier and none may be added.

ADDRESS FAMILY: MRP and GARP are pure Layer 2 protocols carried directly in
Ethernet frames. There is no IP header of any version anywhere in either
encapsulation, so the IPv4/IPv6 parity mandate is not applicable here - not
deferred, not skipped, structurally absent. Nothing in this module parses,
assumes, or branches on an address family.

Wire encoding verified 2026-10-14 against Linux net/802/mrp.c + include/net/mrp.h
(MVRP), OpenAvnu daemons/mrpd/{mvrp,mmrp}.h (MMRP attribute types and EtherType),
Wireshark epan/etypes.h (EtherType registry), and scapy.contrib.gxrp (GARP).
"""

from __future__ import annotations

import struct
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable

__version__ = "0.1.0-dev"

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

ETHERTYPE_MVRP = 0x88F5
ETHERTYPE_MMRP = 0x88F6

MAC_MMRP_GMRP = "01:80:c2:00:00:20"
MAC_MVRP_GVRP = "01:80:c2:00:00:21"

# The 802.1D GARP application address block. :20 and :21 are GMRP/GVRP;
# :22-:2f are reserved for other GARP applications, none of which are in scope.
GARP_BLOCK_PREFIX = "01:80:c2:00:00:"
GARP_BLOCK_LOW = 0x20
GARP_BLOCK_HIGH = 0x2F

MRP_END_MARK = b"\x00\x00"          # two bytes, at message and PDU level
GARP_END_MARK = 0x00                # one byte, at message and PDU level

MRP_VECATTR_LEN_MASK = 0x1FFF
MRP_VECATTR_FLAG_LA = 0x2000

# MRP event enum - Linux enum mrp_vecattr_event. NOTE this mapping is NOT the
# same as GARP's despite both being 0-5. LeaveAll is absent here; in MRP it is
# a flag in the vector header, not an event.
MRP_EVENTS = {0: "New", 1: "JoinIn", 2: "In", 3: "JoinMt", 4: "Mt", 5: "Lv"}
MRP_EVENT_MAX = 6                   # base of the packing; 6**3 = 216 <= 255
MRP_EVENTS_PER_BYTE = 3

# GARP event enum - scapy.contrib.gxrp. Different meanings from MRP's.
GARP_EVENTS = {
    0: "LeaveAll",
    1: "JoinEmpty",
    2: "JoinIn",
    3: "LeaveEmpty",
    4: "LeaveIn",
    5: "Empty",
}

# Attribute types. MVRP has one; MMRP has two, and note the numbering is the
# reverse of GMRP's - MMRP 1=ServiceRequirement/2=MAC, GMRP 1=Group/2=Service.
MVRP_ATTR_VID = 1
MMRP_ATTR_SVCREQ = 1
MMRP_ATTR_MAC = 2
GMRP_ATTR_GROUP = 1
GMRP_ATTR_SERVICE = 2

# Registration-declaring events. These are the events that assert "this
# attribute exists / I want it", i.e. the ones a flood would abuse.
MRP_DECLARING = {"New", "JoinIn", "JoinMt"}
GARP_DECLARING = {"JoinEmpty", "JoinIn"}

PROTO_MVRP = "MVRP"
PROTO_MMRP = "MMRP"
PROTO_GVRP = "GVRP"
PROTO_GMRP = "GMRP"

MODERN = {PROTO_MVRP, PROTO_MMRP}
LEGACY = {PROTO_GVRP, PROTO_GMRP}


# ---------------------------------------------------------------------------
# Finding registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Code:
    code: str
    severity: str
    title: str


REGISTRY: dict[str, Code] = {c.code: c for c in [
    # --- posture (MRP-0xx) ---
    Code("MRP-001", "INFO", "MVRP in use on segment"),
    Code("MRP-002", "INFO", "MMRP in use on segment"),
    Code("MRP-003", "LOW", "Legacy GVRP in use on segment"),
    Code("MRP-004", "LOW", "Legacy GMRP in use on segment"),
    Code("MRP-005", "LOW", "Mixed-generation registration protocols on same segment"),
    Code("MRP-006", "INFO", "known_vlans baseline scoping note"),
    Code("MRP-007", "INFO", "Unknown GARP application address observed"),
    # --- attack / abuse (MRP-1xx) ---
    Code("MRP-101", "HIGH", "MVRP LeaveAll flood from single source"),
    Code("MRP-102", "MEDIUM", "MVRP registration burst for previously unseen VLANs"),
    Code("MRP-103", "HIGH", "MMRP LeaveAll flood from single source"),
    Code("MRP-104", "MEDIUM", "MMRP registration burst for previously unseen groups"),
    Code("MRP-105", "HIGH", "GVRP LeaveAll flood from single source"),
    Code("MRP-106", "MEDIUM", "GVRP registration burst for previously unseen VLANs"),
    Code("MRP-107", "HIGH", "GMRP LeaveAll flood from single source"),
    Code("MRP-108", "MEDIUM", "GMRP registration burst for previously unseen groups"),
    # --- structural (MRP-12x) ---
    Code("MRP-120", "MEDIUM", "Malformed MRP VectorAttribute (NumberOfValues overruns PDU)"),
    Code("MRP-121", "LOW", "Missing or malformed MRP EndMark"),
    Code("MRP-122", "MEDIUM", "Malformed GARP attribute (length overrun or bad event)"),
    Code("MRP-123", "LOW", "Missing or malformed GARP end mark"),
    Code("MRP-124", "LOW", "Unexpected MRP ProtocolVersion"),
    Code("MRP-125", "MEDIUM", "Malformed MRP vector event byte (outside base-6 range)"),
]}

# Per-protocol code mapping, so the analyzer stays table-driven instead of
# growing four near-identical branches.
FLOOD_CODE = {PROTO_MVRP: "MRP-101", PROTO_MMRP: "MRP-103",
              PROTO_GVRP: "MRP-105", PROTO_GMRP: "MRP-107"}
BURST_CODE = {PROTO_MVRP: "MRP-102", PROTO_MMRP: "MRP-104",
              PROTO_GVRP: "MRP-106", PROTO_GMRP: "MRP-108"}
SEEN_CODE = {PROTO_MVRP: "MRP-001", PROTO_MMRP: "MRP-002",
             PROTO_GVRP: "MRP-003", PROTO_GMRP: "MRP-004"}


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    src: str
    proto: str
    detail: dict = field(default_factory=dict)

    def __str__(self) -> str:
        bits = " ".join(f"{k}={v}" for k, v in self.detail.items())
        return f"[{self.severity:<6}] {self.code} {self.proto} src={self.src} {self.title} {bits}".rstrip()


def _finding(code: str, src: str, proto: str, **detail) -> Finding:
    c = REGISTRY[code]
    return Finding(c.code, c.severity, c.title, src, proto, detail)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """Thresholds are split per protocol but default to shared values - the
    knob family is semantically identical across all four, so a single default
    is right until an operator has a reason to diverge one of them."""

    leaveall_threshold: int = 5          # LeaveAll assertions from one source...
    leaveall_window_s: float = 10.0      # ...within this window
    newattr_threshold: int = 20          # never-before-seen attributes...
    newattr_window_s: float = 10.0       # ...within this window

    # Optional per-protocol overrides, e.g. {"GVRP": 3}. Scoping only.
    leaveall_threshold_by_proto: dict = field(default_factory=dict)
    newattr_threshold_by_proto: dict = field(default_factory=dict)

    # Operator baseline. Scoping only - narrows severity, never gates detection.
    known_vlans: set[int] | None = None

    # Enforce EndMark / trailing-byte edge cases strictly (cfmwatch strict_tail).
    strict_structural: bool = False

    def leaveall_limit(self, proto: str) -> int:
        return self.leaveall_threshold_by_proto.get(proto, self.leaveall_threshold)

    def newattr_limit(self, proto: str) -> int:
        return self.newattr_threshold_by_proto.get(proto, self.newattr_threshold)


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

class DecodeError(Exception):
    """Raised with a finding code attached when a PDU cannot be parsed."""

    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code
        self.msg = msg


@dataclass
class Attribute:
    """One decoded attribute event: a resolved value plus the event applied."""
    attr_type: int
    value: bytes
    event: str

    def as_vlan(self) -> int | None:
        if len(self.value) == 2:
            return struct.unpack("!H", self.value)[0]
        return None

    def as_mac(self) -> str | None:
        if len(self.value) == 6:
            return ":".join(f"{b:02x}" for b in self.value)
        return None

    def key(self) -> str:
        """Stable identity for first-sight tracking."""
        v = self.as_vlan()
        if v is not None:
            return f"vlan:{v}"
        m = self.as_mac()
        if m is not None:
            return f"mac:{m}"
        return "val:" + self.value.hex()


@dataclass
class PDU:
    proto: str
    attributes: list[Attribute] = field(default_factory=list)
    leaveall_count: int = 0
    structural: list[tuple[str, str]] = field(default_factory=list)  # (code, msg)


def _inc_be(value: bytearray) -> None:
    """Increment a big-endian integer in place, matching mrp_attrvalue_inc()."""
    i = len(value) - 1
    while i >= 0:
        value[i] = (value[i] + 1) & 0xFF
        if value[i] != 0:
            return
        i -= 1


def decode_mrp(payload: bytes, proto: str, strict: bool = False) -> PDU:
    """Decode an 802.1ak MRPDU (MVRP or MMRP).

    Layout, per Linux net/802/mrp.c:
        ProtocolVersion(1)
        Message*            each: AttributeType(1) AttributeLength(1)
                                  VectorAttribute* EndMark(2)
        EndMark(2)
    VectorAttribute: lenflags(2) [FirstValue(AttributeLength) Vector(ceil(n/3))]
        lenflags & 0x1FFF = NumberOfValues (count of EVENTS, not bytes)
        lenflags & 0x2000 = LeaveAll flag
        NumberOfValues == 0 means LeaveAll-only: FirstValue and Vector absent.
    Vector bytes pack three events base-6, most significant digit first.
    """
    pdu = PDU(proto=proto)
    if len(payload) < 1:
        raise DecodeError("MRP-121", "PDU shorter than ProtocolVersion field")

    version = payload[0]
    if version != 0:
        pdu.structural.append(("MRP-124", f"ProtocolVersion={version}, expected 0"))
    off = 1
    saw_pdu_endmark = False

    while off < len(payload):
        # PDU-level EndMark terminates the message list.
        if payload[off:off + 2] == MRP_END_MARK:
            off += 2
            saw_pdu_endmark = True
            break
        if off + 2 > len(payload):
            pdu.structural.append(("MRP-121", "truncated before message header"))
            break

        attr_type, attr_len = payload[off], payload[off + 1]
        off += 2
        if attr_type == 0 or attr_len == 0:
            pdu.structural.append(
                ("MRP-120", f"invalid message header type={attr_type} len={attr_len}"))
            break

        saw_msg_endmark = False
        while off < len(payload):
            if payload[off:off + 2] == MRP_END_MARK:
                off += 2
                saw_msg_endmark = True
                break
            if off + 2 > len(payload):
                pdu.structural.append(("MRP-121", "truncated inside vector list"))
                break

            lenflags = struct.unpack("!H", payload[off:off + 2])[0]
            off += 2
            nvalues = lenflags & MRP_VECATTR_LEN_MASK
            if lenflags & MRP_VECATTR_FLAG_LA:
                pdu.leaveall_count += 1

            if nvalues == 0:
                continue  # LeaveAll-only vector; nothing further in this one

            if off + attr_len > len(payload):
                pdu.structural.append(
                    ("MRP-120", f"FirstValue of {attr_len}B overruns PDU"))
                return pdu
            first = bytearray(payload[off:off + attr_len])
            off += attr_len

            nbytes = (nvalues + MRP_EVENTS_PER_BYTE - 1) // MRP_EVENTS_PER_BYTE
            if off + nbytes > len(payload):
                pdu.structural.append((
                    "MRP-120",
                    f"NumberOfValues={nvalues} needs {nbytes}B, "
                    f"{len(payload) - off}B remain"))
                return pdu

            vector = payload[off:off + nbytes]
            off += nbytes

            remaining = nvalues
            for byte in vector:
                if byte >= MRP_EVENT_MAX ** MRP_EVENTS_PER_BYTE:
                    pdu.structural.append(
                        ("MRP-125", f"vector byte 0x{byte:02x} >= 216"))
                    return pdu
                digits = (
                    byte // (MRP_EVENT_MAX * MRP_EVENT_MAX),
                    (byte // MRP_EVENT_MAX) % MRP_EVENT_MAX,
                    byte % MRP_EVENT_MAX,
                )
                for d in digits:
                    if remaining == 0:
                        break
                    pdu.attributes.append(
                        Attribute(attr_type, bytes(first), MRP_EVENTS[d]))
                    _inc_be(first)
                    remaining -= 1

        if not saw_msg_endmark and strict:
            pdu.structural.append(("MRP-121", "message not terminated by EndMark"))

    if not saw_pdu_endmark and strict:
        pdu.structural.append(("MRP-121", "PDU not terminated by EndMark"))
    return pdu


def decode_garp(payload: bytes, proto: str, strict: bool = False) -> PDU:
    """Decode an 802.1D GARP PDU (GVRP or GMRP), i.e. the LLC payload.

    Layout, per scapy.contrib.gxrp:
        ProtocolID(2) = 1
        GARP_MESSAGE*       each: AttributeType(1) GARP_ATTRIBUTE* EndMark(1)
        EndMark(1)
    GARP_ATTRIBUTE: Length(1) Event(1) Value(Length-2)
        Length counts itself and the event byte, so Value is Length-2 bytes.
        Length == 0 is the attribute-list end mark.
    One event per attribute - no packed vector, unlike MRP.
    """
    pdu = PDU(proto=proto)
    if len(payload) < 2:
        raise DecodeError("MRP-123", "PDU shorter than ProtocolID")

    proto_id = struct.unpack("!H", payload[0:2])[0]
    if proto_id != 1:
        pdu.structural.append(("MRP-122", f"ProtocolID={proto_id}, expected 1"))
    off = 2
    saw_pdu_endmark = False

    while off < len(payload):
        if payload[off] == GARP_END_MARK:
            off += 1
            saw_pdu_endmark = True
            break

        attr_type = payload[off]
        off += 1
        saw_msg_endmark = False

        while off < len(payload):
            alen = payload[off]
            if alen == GARP_END_MARK:
                off += 1
                saw_msg_endmark = True
                break
            if alen < 2:
                pdu.structural.append(("MRP-122", f"attribute length {alen} < 2"))
                return pdu
            if off + alen > len(payload):
                pdu.structural.append((
                    "MRP-122",
                    f"attribute length {alen} overruns PDU "
                    f"({len(payload) - off}B remain)"))
                return pdu

            event = payload[off + 1]
            value = payload[off + 2:off + alen]
            off += alen

            if event not in GARP_EVENTS:
                pdu.structural.append(
                    ("MRP-122", f"event byte {event} outside 0-5 enum"))
                return pdu

            name = GARP_EVENTS[event]
            if name == "LeaveAll":
                pdu.leaveall_count += 1
            else:
                pdu.attributes.append(Attribute(attr_type, value, name))

        if not saw_msg_endmark and strict:
            pdu.structural.append(("MRP-123", "message not terminated by end mark"))

    if not saw_pdu_endmark and strict:
        pdu.structural.append(("MRP-123", "PDU not terminated by end mark"))
    return pdu


# ---------------------------------------------------------------------------
# Frame classification
# ---------------------------------------------------------------------------

def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def classify(frame: bytes) -> tuple[str | None, str, bytes, str | None]:
    """Classify a raw Ethernet frame.

    Returns (proto, src_mac, payload, note). proto is None when the frame is
    not ours; note carries a posture observation such as an unknown GARP
    application address.
    """
    if len(frame) < 14:
        return None, "", b"", None

    dst = _mac(frame[0:6])
    src = _mac(frame[6:12])
    tl = struct.unpack("!H", frame[12:14])[0]

    # Ethernet II: EtherType decides, and MVRP/MMRP have distinct ones.
    if tl == ETHERTYPE_MVRP:
        return PROTO_MVRP, src, frame[14:], None
    if tl == ETHERTYPE_MMRP:
        return PROTO_MMRP, src, frame[14:], None

    # 802.3 length framing: GARP has no EtherType at all and is bound purely
    # by destination MAC across the 01:80:C2:00:00:20-2F application block.
    if tl > 1500:
        return None, src, b"", None
    if not dst.startswith(GARP_BLOCK_PREFIX):
        return None, src, b"", None
    last = int(dst[-2:], 16)
    if not (GARP_BLOCK_LOW <= last <= GARP_BLOCK_HIGH):
        return None, src, b"", None

    # LLC: DSAP/SSAP/Control, all zero for GARP, no SNAP.
    body = frame[14:14 + tl]
    if len(body) < 3:
        return None, src, b"", None
    llc = body[0:3]
    payload = body[3:]

    if dst == MAC_MVRP_GVRP:
        return PROTO_GVRP, src, payload, None
    if dst == MAC_MMRP_GMRP:
        return PROTO_GMRP, src, payload, None
    return None, src, b"", f"unknown GARP application at {dst} (llc={llc.hex()})"


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class MrpWatch:
    """Stateful passive analyzer. Feed it frames; it yields Findings."""

    def __init__(self, config: Config | None = None):
        self.cfg = config or Config()
        # Rate windows, keyed (src, proto) -> deque[timestamp]
        self._leaveall: dict[tuple, deque] = defaultdict(deque)
        self._newattr: dict[tuple, deque] = defaultdict(deque)
        # First-sight inventories
        self._seen_attrs: dict[str, set] = defaultdict(set)      # proto -> keys
        self._seen_protos: set[str] = set()
        self._emitted: set[tuple] = set()                        # one-shot codes
        self._mixed_reported = False
        self._baseline_reported = False
        # Latched rate alerts. A sustained flood is ONE event, not one event
        # per frame: once a threshold trips, that (src, proto, code) stays
        # latched and silent until its rate window drains back below the
        # threshold, then it can fire again. Without this a 10-second flood
        # emits an alert per frame and buries the operator.
        self._latched: set[tuple] = set()

    # -- helpers ----------------------------------------------------------

    def _once(self, key: tuple) -> bool:
        if key in self._emitted:
            return False
        self._emitted.add(key)
        return True

    @staticmethod
    def _rate(window: deque, now: float, span: float) -> int:
        cutoff = now - span
        while window and window[0] < cutoff:
            window.popleft()
        return len(window)

    # -- main entry -------------------------------------------------------

    def feed(self, frame: bytes, ts: float) -> list[Finding]:
        out: list[Finding] = []
        proto, src, payload, note = classify(frame)

        if note is not None and self._once(("MRP-007", note)):
            out.append(_finding("MRP-007", src, "GARP", note=note))
        if proto is None:
            return out

        # --- posture: protocol first sight ---
        if self._once((SEEN_CODE[proto],)):
            out.append(_finding(SEEN_CODE[proto], src, proto))
        self._seen_protos.add(proto)

        if (not self._mixed_reported
                and self._seen_protos & MODERN and self._seen_protos & LEGACY):
            self._mixed_reported = True
            out.append(_finding(
                "MRP-005", src, proto,
                modern=",".join(sorted(self._seen_protos & MODERN)),
                legacy=",".join(sorted(self._seen_protos & LEGACY))))

        if not self._baseline_reported and proto in (PROTO_MVRP, PROTO_GVRP):
            self._baseline_reported = True
            out.append(_finding(
                "MRP-006", src, proto,
                known_vlans=("configured" if self.cfg.known_vlans else "absent"),
                effect="severity scoping only, detection ungated"))

        # --- decode ---
        try:
            if proto in MODERN:
                pdu = decode_mrp(payload, proto, self.cfg.strict_structural)
            else:
                pdu = decode_garp(payload, proto, self.cfg.strict_structural)
        except DecodeError as e:
            return out + [_finding(e.code, src, proto, error=e.msg)]

        for code, msg in pdu.structural:
            out.append(_finding(code, src, proto, error=msg))

        # --- LeaveAll flood ---
        if pdu.leaveall_count:
            w = self._leaveall[(src, proto)]
            for _ in range(pdu.leaveall_count):
                w.append(ts)
            n = self._rate(w, ts, self.cfg.leaveall_window_s)
            limit = self.cfg.leaveall_limit(proto)
            latch = (src, proto, FLOOD_CODE[proto])
            if n >= limit:
                if latch not in self._latched:
                    self._latched.add(latch)
                    out.append(_finding(
                        FLOOD_CODE[proto], src, proto, count=n,
                        window_s=self.cfg.leaveall_window_s, threshold=limit))
            else:
                self._latched.discard(latch)

        # --- never-before-seen attribute burst ---
        declaring = MRP_DECLARING if proto in MODERN else GARP_DECLARING
        inventory = self._seen_attrs[proto]
        fresh: list[Attribute] = []
        for attr in pdu.attributes:
            if attr.event not in declaring:
                continue
            k = attr.key()
            if k not in inventory:
                inventory.add(k)
                fresh.append(attr)

        if fresh:
            w = self._newattr[(src, proto)]
            for _ in fresh:
                w.append(ts)
            n = self._rate(w, ts, self.cfg.newattr_window_s)
            limit = self.cfg.newattr_limit(proto)
            latch = (src, proto, BURST_CODE[proto])
            if n < limit:
                self._latched.discard(latch)
            if n >= limit and latch not in self._latched:
                self._latched.add(latch)
                f = _finding(
                    BURST_CODE[proto], src, proto,
                    count=n, window_s=self.cfg.newattr_window_s, threshold=limit,
                    sample=",".join(a.key() for a in fresh[:5]))
                # known_vlans narrows severity; it never decides detection.
                if self.cfg.known_vlans is not None and proto in (PROTO_MVRP, PROTO_GVRP):
                    outside = [a.as_vlan() for a in fresh
                               if a.as_vlan() is not None
                               and a.as_vlan() not in self.cfg.known_vlans]
                    if outside:
                        f.severity = "HIGH"
                        f.detail["outside_baseline"] = ",".join(
                            str(v) for v in outside[:10])
                out.append(f)

        return out

    def feed_all(self, frames: Iterable[tuple[bytes, float]]) -> list[Finding]:
        out = []
        for frame, ts in frames:
            out.extend(self.feed(frame, ts))
        return out


__all__ = [
    "MrpWatch", "Config", "Finding", "REGISTRY",
    "decode_mrp", "decode_garp", "classify", "DecodeError",
]
