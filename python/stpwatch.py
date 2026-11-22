#!/usr/bin/env python3
# stpwatch - passive STP / RSTP / MSTP / PVST+ BPDU security monitor
# Part of the Ragnar network engineering toolbox.
#
# DESIGN CONTRACT
#   * Passive. Detection only. This process NEVER transmits a frame.
#   * No BPDU is ever crafted, replayed, or injected. Remediation lives on the
#     switch (BPDU Guard / Root Guard / BPDU Filter / Loop Guard), not here.
#   * Test floor is the Pi Zero 2W. Pure stdlib at runtime; Scapy only in the
#     self-test harness.
#
# WHAT THIS IS NOT
#   A link-presence checker. "I saw a BPDU on eth0" tells you the segment has a
#   spanning-tree domain. It tells you nothing about whether that domain has
#   been hijacked. stpwatch decodes the BPDU body and reasons about it.

from __future__ import annotations

import argparse
import ctypes
import json
import logging
import logging.handlers
import os
import select
import signal
import socket
import struct
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

__version__ = "1.1.0"

# --------------------------------------------------------------------------
# Wire constants
# --------------------------------------------------------------------------

ETH_P_ALL = 0x0003

BRIDGE_GROUP_ADDR = b"\x01\x80\xc2\x00\x00\x00"   # IEEE 802.1D/1Q spanning tree
PVST_ADDR = b"\x01\x00\x0c\xcc\xcc\xcd"           # Cisco PVST+ / RPVST+

VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)

LLC_STP = b"\x42\x42\x03"      # DSAP/SSAP/UI
LLC_SNAP = b"\xaa\xaa\x03"
SNAP_OUI_CISCO = b"\x00\x00\x0c"
SNAP_PID_PVST = 0x010B

VER_STP, VER_RSTP, VER_MSTP = 0x00, 0x02, 0x03
KNOWN_VERSIONS = (VER_STP, VER_RSTP, VER_MSTP)

TYPE_CONFIG, TYPE_RST, TYPE_TCN = 0x00, 0x02, 0x80
KNOWN_TYPES = (TYPE_CONFIG, TYPE_RST, TYPE_TCN)

CONFIG_BODY_LEN = 35           # protocol id .. forward delay
MST_CFG_ID_LEN = 51            # selector(1) + name(32) + revision(2) + digest(16)
MSTI_RECORD_LEN = 16

FLAG_TC = 0x01
FLAG_PROPOSAL = 0x02
FLAG_LEARNING = 0x10
FLAG_FORWARDING = 0x20
FLAG_AGREEMENT = 0x40
FLAG_TCA = 0x80
FLAG_MSTI_MASTER = 0x80        # MSTI records reuse bit 7 as Master, not TCA
FLAG_RESERVED_8021D = 0x7E     # bits 1..6 must be zero in a version-0 BPDU

# 802.1Q-2018 Table 13-3: CIST is instance 0; MSTIs are 1..4094
MSTID_MIN, MSTID_MAX = 1, 4094
MSTI_DEFAULT_MAX_HOPS = 20

PORT_ROLES = {0: "unknown", 1: "alternate/backup", 2: "root", 3: "designated"}

# 802.1D-2004 legal timer ranges, seconds
HELLO_RANGE = (1.0, 10.0)
MAXAGE_RANGE = (6.0, 40.0)
FWDDELAY_RANGE = (4.0, 30.0)

# --------------------------------------------------------------------------
# Detection catalogue
# --------------------------------------------------------------------------

DETECTIONS: Dict[str, Tuple[str, str, str]] = {
    # id          name                       severity    description
    "STP-001": ("ROOT_CHANGE", "MEDIUM", "Root bridge identifier changed"),
    "STP-002": ("SUPERIOR_BPDU", "CRITICAL", "BPDU advertises a root superior to the established root"),
    "STP-003": ("ROOT_FLAP", "HIGH", "Repeated root bridge changes inside the flap window"),
    "STP-004": ("NEW_BRIDGE", "MEDIUM", "Previously unseen bridge ID sourcing BPDUs"),
    "STP-005": ("BPDU_ON_EDGE_PORT", "CRITICAL", "BPDU received on an interface declared edge/access"),
    "STP-006": ("TCN_FLOOD", "HIGH", "Topology Change Notification rate above threshold"),
    "STP-007": ("TC_EPISODE_FLOOD", "MEDIUM", "Excessive distinct topology-change episodes"),
    "STP-008": ("BPDU_STORM", "HIGH", "BPDU arrival rate far above the hello timer implies"),
    "STP-009": ("LOW_PRIORITY_CLAIM", "HIGH", "Bridge priority at or below the configured floor"),
    "STP-010": ("NONCONFORMANT_PRIORITY", "MEDIUM", "Priority not a multiple of 4096 / sysid-ext mismatch"),
    "STP-011": ("BOGUS_SOURCE_MAC", "MEDIUM", "Source MAC is locally administered or multicast"),
    "STP-012": ("TIMER_ANOMALY", "HIGH", "STP timers outside legal range or mutually inconsistent"),
    "STP-013": ("PROTOCOL_ANOMALY", "MEDIUM", "Malformed protocol id, version, type, or reserved flag bits"),
    "STP-014": ("MESSAGE_AGE_ANOMALY", "MEDIUM", "Message age >= max age, or zero age from a non-root"),
    "STP-015": ("ZERO_PATH_COST", "MEDIUM", "Root path cost is 0 but the sender is not the root"),
    "STP-016": ("RSTP_PROPOSAL_FLOOD", "HIGH", "RSTP proposal/agreement rate above threshold (sync storm)"),
    "STP-017": ("DUAL_PROTOCOL", "MEDIUM", "IEEE and PVST+ spanning tree observed on the same segment"),
    "STP-018": ("TAGGED_IEEE_BPDU", "MEDIUM", "IEEE 802.1D/w/s BPDU carried inside a VLAN tag"),
    "STP-019": ("MULTIPLE_ROOTS", "HIGH", "Two distinct roots advertised concurrently on one segment"),
    "STP-020": ("BPDU_SILENCE", "LOW", "Known bridge stopped sending BPDUs (>3x hello)"),
    "STP-021": ("MST_DIGEST_MISMATCH", "HIGH", "MST region name known but configuration digest differs"),
    "STP-022": ("MST_REGION_UNKNOWN", "MEDIUM", "MST BPDU from a region absent from the baseline"),

    # --- per-MSTI tier: the CIST checks above, re-scoped to one MST instance.
    # An attacker inside a legitimate, correctly-digested region (so STP-021/022
    # stay silent) forges these inside a single MSTI's own 16-octet record.
    "STP-023": ("MSTI_ROOT_CHANGE", "MEDIUM", "Regional root changed for an MST instance"),
    "STP-024": ("MSTI_SUPERIOR_BPDU", "CRITICAL", "MSTI record claims a regional root superior to the established one"),
    "STP-025": ("MSTI_ROOT_FLAP", "HIGH", "Repeated regional-root changes for one MST instance"),
    "STP-026": ("MSTI_LOW_PRIORITY_CLAIM", "HIGH", "MSTI regional-root or bridge priority at or below the floor"),
    "STP-027": ("MSTI_ZERO_PATH_COST", "MEDIUM", "MSTI internal root path cost is 0 but the sender is not the regional root"),
    "STP-028": ("MSTI_MULTIPLE_ROOTS", "HIGH", "Two distinct regional roots advertised concurrently for one MSTI"),
    "STP-029": ("MSTI_RECORD_ANOMALY", "MEDIUM", "Malformed MSTI record: bad MSTID, duplicate instance, or length mismatch"),
    "STP-030": ("MSTI_SET_CHANGE", "MEDIUM", "Set of MST instances advertised by a bridge changed"),
    "STP-031": ("MSTI_HOPS_ANOMALY", "MEDIUM", "MSTI remaining hops exhausted or above the region maximum"),
}

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class ParseError(Exception):
    pass


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("!H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("!I", b, o)[0]


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ticks_to_sec(t: int) -> float:
    """802.1D timer fields are in units of 1/256 second."""
    return t / 256.0


@dataclass(frozen=True)
class BridgeID:
    """8-octet bridge identifier: 4-bit priority | 12-bit sysid-ext | 6-byte MAC."""
    raw_priority: int          # full 16-bit leading field
    mac: bytes

    @classmethod
    def parse(cls, b: bytes, o: int) -> "BridgeID":
        return cls(u16(b, o), bytes(b[o + 2: o + 8]))

    @property
    def priority(self) -> int:
        return self.raw_priority & 0xF000

    @property
    def sysid_ext(self) -> int:
        return self.raw_priority & 0x0FFF

    @property
    def conformant(self) -> bool:
        """True when the low 12 bits are usable as a sysid extension."""
        return True  # meaning is context-dependent; see analyzer

    def key(self) -> Tuple[int, bytes]:
        """Lower tuple == superior bridge. Direct 802.1D comparison order."""
        return (self.raw_priority, self.mac)

    def __str__(self) -> str:
        return f"{self.priority}/{self.sysid_ext}/{mac_str(self.mac)}"

    def to_json(self) -> Dict[str, Any]:
        return {
            "raw_priority": self.raw_priority,
            "priority": self.priority,
            "sysid_ext": self.sysid_ext,
            "mac": mac_str(self.mac),
            "str": str(self),
        }


def bridge_from_json(d: Dict[str, Any]) -> BridgeID:
    return BridgeID(d["raw_priority"], bytes.fromhex(d["mac"].replace(":", "")))


# --------------------------------------------------------------------------
# Frame parsing
# --------------------------------------------------------------------------

@dataclass
class BPDU:
    ts: float
    iface: str
    src: bytes
    dst: bytes
    tags: List[Tuple[int, int]]          # [(tpid, vid), ...] outer first
    encap: str                           # "ieee" | "pvst"
    vlan: Optional[int]                  # PVST VLAN, tag VID, or None
    raw_len: int

    protocol_id: int = 0
    version: int = 0
    bpdu_type: int = 0
    flags: int = 0

    root: Optional[BridgeID] = None
    path_cost: int = 0
    bridge: Optional[BridgeID] = None
    port_id: int = 0
    message_age: float = 0.0
    max_age: float = 0.0
    hello_time: float = 0.0
    forward_delay: float = 0.0

    mst: Optional[Dict[str, Any]] = None
    parse_anomalies: List[str] = field(default_factory=list)

    # -- convenience -------------------------------------------------------
    @property
    def is_tcn(self) -> bool:
        return self.bpdu_type == TYPE_TCN

    @property
    def tc(self) -> bool:
        return bool(self.flags & FLAG_TC)

    @property
    def proposal(self) -> bool:
        return bool(self.flags & FLAG_PROPOSAL)

    @property
    def agreement(self) -> bool:
        return bool(self.flags & FLAG_AGREEMENT)

    @property
    def port_role(self) -> str:
        return PORT_ROLES[(self.flags >> 2) & 0x03]

    @property
    def is_root_originated(self) -> bool:
        return self.root is not None and self.bridge is not None and self.root == self.bridge

    @property
    def port_priority(self) -> int:
        return (self.port_id >> 12) & 0x0F

    @property
    def port_number(self) -> int:
        return self.port_id & 0x0FFF

    def summary(self) -> str:
        if self.is_tcn:
            return f"TCN v{self.version} encap={self.encap} vlan={self.vlan}"
        return (
            f"{'MST' if self.version == VER_MSTP else 'RST' if self.version == VER_RSTP else 'STP'} "
            f"root={self.root} cost={self.path_cost} bridge={self.bridge} "
            f"port={self.port_priority}.{self.port_number} role={self.port_role} "
            f"tc={int(self.tc)} hello={self.hello_time:g} maxage={self.max_age:g} fd={self.forward_delay:g}"
        )

    def to_json(self) -> Dict[str, Any]:
        d = {
            "ts": self.ts,
            "iface": self.iface,
            "src": mac_str(self.src),
            "dst": mac_str(self.dst),
            "tags": self.tags,
            "encap": self.encap,
            "vlan": self.vlan,
            "protocol_id": self.protocol_id,
            "version": self.version,
            "bpdu_type": self.bpdu_type,
            "flags": self.flags,
            "port_role": self.port_role,
            "tc": self.tc,
        }
        if not self.is_tcn:
            d.update(
                root=self.root.to_json() if self.root else None,
                path_cost=self.path_cost,
                bridge=self.bridge.to_json() if self.bridge else None,
                port_id=self.port_id,
                message_age=self.message_age,
                max_age=self.max_age,
                hello_time=self.hello_time,
                forward_delay=self.forward_delay,
            )
        if self.mst:
            d["mst"] = self.mst
        if self.parse_anomalies:
            d["parse_anomalies"] = self.parse_anomalies
        return d


def parse_frame(data: bytes, iface: str, ts: float) -> Optional[BPDU]:
    """Decode an Ethernet frame into a BPDU. Returns None when not a BPDU.

    Raises ParseError on frames that look like BPDUs but are truncated.
    """
    if len(data) < 17:
        return None

    dst = bytes(data[0:6])
    src = bytes(data[6:12])
    if dst != BRIDGE_GROUP_ADDR and dst != PVST_ADDR:
        return None

    off = 12
    tags: List[Tuple[int, int]] = []
    while off + 4 <= len(data):
        tpid = u16(data, off)
        if tpid not in VLAN_TPIDS:
            break
        tags.append((tpid, u16(data, off + 2) & 0x0FFF))
        off += 4
        if len(tags) > 2:              # QinQ is the practical ceiling
            raise ParseError("excessive VLAN tag stack")

    if off + 2 > len(data):
        raise ParseError("truncated at length field")
    length = u16(data, off)
    off += 2
    if length > 1500:
        return None                     # EtherType, not an 802.3 length -> not a BPDU

    if off + 3 > len(data):
        raise ParseError("truncated LLC header")
    llc = bytes(data[off:off + 3])

    if llc == LLC_STP:
        encap = "ieee"
        off += 3
    elif llc == LLC_SNAP:
        if off + 8 > len(data):
            raise ParseError("truncated SNAP header")
        oui = bytes(data[off + 3:off + 6])
        pid = u16(data, off + 6)
        if oui != SNAP_OUI_CISCO or pid != SNAP_PID_PVST:
            return None
        encap = "pvst"
        off += 8
    else:
        return None

    body = data[off:]
    if len(body) < 4:
        raise ParseError("truncated BPDU header")

    p = BPDU(
        ts=ts, iface=iface, src=src, dst=dst, tags=tags,
        encap=encap, vlan=(tags[-1][1] if tags else None), raw_len=len(data),
        protocol_id=u16(body, 0), version=body[2], bpdu_type=body[3],
    )

    if p.protocol_id != 0x0000:
        p.parse_anomalies.append(f"protocol_id=0x{p.protocol_id:04x}")
    if p.version not in KNOWN_VERSIONS:
        p.parse_anomalies.append(f"version={p.version}")
    if p.bpdu_type not in KNOWN_TYPES:
        p.parse_anomalies.append(f"bpdu_type=0x{p.bpdu_type:02x}")

    if p.bpdu_type == TYPE_TCN:
        # A TCN is exactly four octets. Anything trailing is noteworthy but not fatal.
        return p

    if p.bpdu_type == TYPE_RST and p.version < VER_RSTP:
        p.parse_anomalies.append(f"rst_bpdu_with_version_{p.version}")
    if p.bpdu_type == TYPE_CONFIG and p.version >= VER_RSTP:
        p.parse_anomalies.append(f"config_bpdu_with_version_{p.version}")

    if len(body) < CONFIG_BODY_LEN:
        raise ParseError(f"truncated config BPDU: {len(body)} < {CONFIG_BODY_LEN}")

    p.flags = body[4]
    p.root = BridgeID.parse(body, 5)
    p.path_cost = u32(body, 13)
    p.bridge = BridgeID.parse(body, 17)
    p.port_id = u16(body, 25)
    p.message_age = ticks_to_sec(u16(body, 27))
    p.max_age = ticks_to_sec(u16(body, 29))
    p.hello_time = ticks_to_sec(u16(body, 31))
    p.forward_delay = ticks_to_sec(u16(body, 33))

    if p.version == VER_STP and (p.flags & FLAG_RESERVED_8021D):
        p.parse_anomalies.append(f"reserved_flag_bits=0x{p.flags & FLAG_RESERVED_8021D:02x}")

    if p.version == VER_MSTP and p.bpdu_type == TYPE_RST:
        p.mst = _parse_mst(body, p)

    if encap == "pvst":
        vid = _parse_pvst_tlv(body)
        if vid is not None:
            p.vlan = vid

    return p


def _parse_mst(body: bytes, p: BPDU) -> Optional[Dict[str, Any]]:
    # 35: version-1 length | 36..37: version-3 length | 38..: MST config ID
    if len(body) < 38:
        p.parse_anomalies.append("mstp_missing_v3_length")
        return None
    v1_len = body[35]
    v3_len = u16(body, 36)
    need = 38 + MST_CFG_ID_LEN + 4 + 8 + 1
    if len(body) < need:
        p.parse_anomalies.append("mstp_truncated_cist")
        return None

    o = 38
    selector = body[o]
    name = bytes(body[o + 1:o + 33]).split(b"\x00", 1)[0].decode("ascii", "replace")
    revision = u16(body, o + 33)
    digest = bytes(body[o + 35:o + 51]).hex()
    o += MST_CFG_ID_LEN

    cist_internal_cost = u32(body, o); o += 4
    cist_bridge = BridgeID.parse(body, o); o += 8
    remaining_hops = body[o]; o += 1

    declared = max(0, (v3_len - 64)) // MSTI_RECORD_LEN if v3_len >= 64 else 0
    if v1_len != 0:
        p.parse_anomalies.append(f"mstp_v1_length={v1_len}")
    if selector != 0:
        p.parse_anomalies.append(f"mstp_selector={selector}")
    if v3_len >= 64 and (v3_len - 64) % MSTI_RECORD_LEN:
        p.parse_anomalies.append(f"mstp_v3_length_not_record_aligned={v3_len}")

    mstis, record_anomalies = _parse_msti_records(body, o, declared, p)

    return {
        "region_name": name,
        "revision": revision,
        "digest": digest,
        "cist_internal_root_path_cost": cist_internal_cost,
        "cist_bridge": cist_bridge.to_json(),
        "remaining_hops": remaining_hops,
        "msti_count": len(mstis),
        "msti_declared": declared,
        "mstis": mstis,
        "msti_anomalies": record_anomalies,
    }


def _parse_msti_records(body: bytes, o: int, declared: int,
                        p: BPDU) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Deserialize the MSTI Configuration Messages (802.1Q-2018 Table 14-1).

    Each record is exactly 16 octets:
        0      MSTI flags (port role in bits 2-3; bit 7 is Master, not TCA)
        1-8    MSTI Regional Root Identifier (priority nibble | MSTID | MAC)
        9-12   MSTI Internal Root Path Cost
        13     MSTI Bridge Priority  (top nibble significant)
        14     MSTI Port Priority    (top nibble significant)
        15     MSTI Remaining Hops

    The instance number is NOT a separate field: it is carried in the low 12
    bits of the Regional Root Identifier, where the CIST carries a sysid-ext.
    """
    out: List[Dict[str, Any]] = []
    anomalies: List[str] = []

    available = max(0, len(body) - o) // MSTI_RECORD_LEN
    if declared > available:
        anomalies.append(f"declared {declared} MSTI records but only {available} present")
    if available > declared:
        anomalies.append(f"{available - declared} MSTI record(s) beyond the declared length")
    trailing = max(0, len(body) - o) % MSTI_RECORD_LEN
    if trailing:
        anomalies.append(f"{trailing} trailing octet(s) after the last MSTI record")

    seen: Dict[int, int] = {}
    for i in range(min(declared, available)):
        b = o + i * MSTI_RECORD_LEN
        flags = body[b]
        regional_root = BridgeID.parse(body, b + 1)
        internal_cost = u32(body, b + 9)
        bridge_prio_octet = body[b + 13]
        port_prio_octet = body[b + 14]
        hops = body[b + 15]

        mstid = regional_root.sysid_ext
        if not (MSTID_MIN <= mstid <= MSTID_MAX):
            anomalies.append(f"record {i}: MSTID {mstid} outside {MSTID_MIN}-{MSTID_MAX}")
        if mstid in seen:
            anomalies.append(f"record {i}: MSTID {mstid} duplicates record {seen[mstid]}")
        else:
            seen[mstid] = i
        if bridge_prio_octet & 0x0F:
            anomalies.append(f"record {i}: bridge priority low nibble not zero "
                             f"(0x{bridge_prio_octet:02x})")
        if port_prio_octet & 0x0F:
            anomalies.append(f"record {i}: port priority low nibble not zero "
                             f"(0x{port_prio_octet:02x})")

        out.append({
            "index": i,
            "mstid": mstid,
            "flags": flags,
            "port_role": PORT_ROLES[(flags >> 2) & 0x03],
            "tc": bool(flags & FLAG_TC),
            "proposal": bool(flags & FLAG_PROPOSAL),
            "learning": bool(flags & FLAG_LEARNING),
            "forwarding": bool(flags & FLAG_FORWARDING),
            "agreement": bool(flags & FLAG_AGREEMENT),
            "master": bool(flags & FLAG_MSTI_MASTER),
            "regional_root": regional_root.to_json(),
            "regional_root_raw_priority": regional_root.raw_priority,
            "regional_root_mac": mac_str(regional_root.mac),
            "internal_root_path_cost": internal_cost,
            "bridge_priority": (bridge_prio_octet & 0xF0) << 8,
            "port_priority": (port_prio_octet & 0xF0) << 8,
            "remaining_hops": hops,
        })

    return out, anomalies


def _parse_pvst_tlv(body: bytes) -> Optional[int]:
    """PVST+ appends TLV type 0x0000 len 0x0002 value=<vlan>."""
    o = CONFIG_BODY_LEN
    if body[3:4] == bytes([TYPE_RST]):
        o += 1  # version-1 length octet
    while o + 4 <= len(body):
        t = u16(body, o)
        ln = u16(body, o + 2)
        if o + 4 + ln > len(body):
            return None
        if t == 0x0000 and ln == 2:
            return u16(body, o + 4)
        o += 4 + ln
    return None


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass
class Finding:
    ts: float
    id: str
    name: str
    severity: str
    iface: str
    vlan: Any
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        d["time"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.ts))
        return d

    def line(self) -> str:
        return (f"[{self.severity:<8}] {self.id} {self.name} "
                f"iface={self.iface} vlan={self.vlan} :: {self.summary}")


# --------------------------------------------------------------------------
# Analyzer
# --------------------------------------------------------------------------

DEFAULT_THRESHOLDS = {
    "grace_seconds": 30.0,          # learn quietly before firing takeover alerts
    "priority_floor": 4096,         # priority <= this is a takeover smell (yersinia uses 0)
    "bpdu_storm_per_sec": 20.0,
    "bpdu_storm_window": 5.0,
    "tcn_count": 5,
    "tcn_window": 30.0,
    "tc_episodes": 4,
    "tc_episode_window": 300.0,
    "tc_episode_gap": 10.0,
    "proposal_count": 30,
    "proposal_window": 10.0,
    "root_flaps": 3,
    "root_flap_window": 300.0,
    "multi_root_window": 6.0,
    "silence_multiplier": 3.0,
    "silence_floor": 6.0,
    "cooldown": 60.0,
    # per-MSTI tier
    "msti_priority_floor": 4096,    # mirrors priority_floor, scoped to an instance
    "msti_max_hops": MSTI_DEFAULT_MAX_HOPS,
}


def _prune(dq: deque, now: float, window: float) -> None:
    while dq and now - dq[0] > window:
        dq.popleft()


class SegmentState:
    __slots__ = ("root", "root_since", "root_changes", "roots_recent", "bpdu_ts",
                 "tcn_ts", "proposal_ts", "tc_active", "tc_last", "tc_episodes",
                 "bridges", "hello_intervals", "last_bpdu_per_bridge", "encaps",
                 "first_seen", "last_seen", "count", "silence_alerted")

    def __init__(self, ts: float):
        self.root: Optional[BridgeID] = None
        self.root_since = ts
        self.root_changes: deque = deque()
        self.roots_recent: Dict[Tuple[int, bytes], float] = {}
        self.bpdu_ts: deque = deque()
        self.tcn_ts: deque = deque()
        self.proposal_ts: deque = deque()
        self.tc_active = False
        self.tc_last = 0.0
        self.tc_episodes: deque = deque()
        self.bridges: Dict[str, float] = {}
        self.hello_intervals: deque = deque(maxlen=32)
        self.last_bpdu_per_bridge: Dict[str, float] = {}
        self.encaps: set = set()
        self.first_seen = ts
        self.last_seen = ts
        self.count = 0
        self.silence_alerted: set = set()


class MstiState:
    """Per-(iface, region, MSTID) root tracking.

    Deliberately NOT a SegmentState: BPDU arrival rate, hello cadence and
    silence belong to the physical BPDU stream, which the CIST segment already
    owns. One frame carrying twelve MSTI records is still one BPDU; counting it
    twelve times would turn a healthy region into a permanent storm alert.
    """
    __slots__ = ("root", "root_changes", "roots_recent", "first_seen", "last_seen", "count")

    def __init__(self, ts: float):
        self.root: Optional[BridgeID] = None
        self.root_changes: deque = deque()
        self.roots_recent: Dict[Tuple[int, bytes], float] = {}
        self.first_seen = ts
        self.last_seen = ts
        self.count = 0


class Analyzer:
    def __init__(self,
                 baseline: Optional[Dict[str, Any]] = None,
                 edge_ifaces: Iterable[str] = (),
                 thresholds: Optional[Dict[str, Any]] = None,
                 start_ts: Optional[float] = None,
                 learning: bool = False):
        self.t = dict(DEFAULT_THRESHOLDS)
        if thresholds:
            self.t.update(thresholds)
        self.baseline = baseline or {}
        self.edge = set(edge_ifaces)
        self.learning = learning
        self.start_ts = start_ts if start_ts is not None else time.time()
        self.segments: Dict[Tuple[str, Any], SegmentState] = {}
        self.iface_encaps: Dict[str, set] = defaultdict(set)
        self.mstis: Dict[Tuple[str, str, int], MstiState] = {}
        self._msti_sets: Dict[Tuple[str, str], frozenset] = {}
        self._cooldown: Dict[Tuple[str, str, Any, str], float] = {}
        self._suppressed: Dict[Tuple[str, str, Any, str], int] = defaultdict(int)
        self.stats = defaultdict(int)

        # Baseline roots keyed "iface|vlan"
        self._bl_roots: Dict[str, BridgeID] = {
            k: bridge_from_json(v) for k, v in self.baseline.get("roots", {}).items()
        }
        self._bl_bridges: set = set(self.baseline.get("bridges", {}).keys())
        self._bl_regions: Dict[str, Any] = self.baseline.get("mst_regions", {})
        # Baseline regional roots keyed "iface|region|MSTID"
        self._bl_msti_roots: Dict[str, BridgeID] = {
            k: bridge_from_json(v) for k, v in self.baseline.get("msti_roots", {}).items()
        }

    # -- emission control --------------------------------------------------
    def _emit(self, out: List[Finding], fid: str, p_iface: str, vlan: Any,
              summary: str, evidence: Dict[str, Any], ts: float,
              dedup: str = "", severity: Optional[str] = None) -> None:
        name, sev, _ = DETECTIONS[fid]
        key = (fid, p_iface, vlan, dedup)
        last = self._cooldown.get(key)
        if last is not None and ts - last < self.t["cooldown"]:
            self._suppressed[key] += 1
            return
        if self._suppressed[key]:
            evidence = dict(evidence, suppressed_since_last=self._suppressed[key])
            self._suppressed[key] = 0
        self._cooldown[key] = ts
        f = Finding(ts, fid, name, severity or sev, p_iface, vlan, summary, evidence)
        self.stats[f"finding:{fid}"] += 1
        self.stats[f"severity:{f.severity}"] += 1
        out.append(f)

    def _seg(self, iface: str, vlan: Any, ts: float) -> SegmentState:
        k = (iface, vlan)
        s = self.segments.get(k)
        if s is None:
            s = SegmentState(ts)
            self.segments[k] = s
        return s

    @staticmethod
    def _vlan_key(p: BPDU) -> Any:
        if p.encap == "pvst":
            return p.vlan if p.vlan is not None else 1
        if p.version == VER_MSTP:
            return "CIST"
        return p.vlan if p.vlan is not None else 0

    def _msti(self, iface: str, region: str, mstid: int, ts: float) -> MstiState:
        k = (iface, region, mstid)
        st = self.mstis.get(k)
        if st is None:
            st = MstiState(ts)
            self.mstis[k] = st
        return st

    def _past_grace(self, ts: float) -> bool:
        if self._bl_roots or self._bl_msti_roots:
            return True
        return (ts - self.start_ts) >= self.t["grace_seconds"]

    # -- main entry --------------------------------------------------------
    def process(self, p: BPDU) -> List[Finding]:
        out: List[Finding] = []
        self.stats["bpdu_total"] += 1
        self.stats[f"encap:{p.encap}"] += 1
        self.stats[f"version:{p.version}"] += 1

        vlan = self._vlan_key(p)
        s = self._seg(p.iface, vlan, p.ts)
        s.last_seen = p.ts
        s.count += 1
        s.encaps.add(p.encap)

        self._check_frame_hygiene(p, out)
        self._check_rates(p, s, out)

        if p.is_tcn:
            self.stats["tcn"] += 1
            return out

        self._check_priority(p, out, vlan)
        self._check_timers(p, out, vlan)
        self._check_costs_and_age(p, out, vlan)
        self._check_roots(p, s, out, vlan)
        self._check_bridges(p, s, out, vlan)
        self._check_mst(p, out, vlan)
        self._check_msti(p, out)
        return out

    # -- individual checks -------------------------------------------------
    def _check_frame_hygiene(self, p: BPDU, out: List[Finding]) -> None:
        if p.iface in self.edge:
            self._emit(out, "STP-005", p.iface, self._vlan_key(p),
                       "BPDU seen on an interface declared edge/access; BPDU Guard is absent or bypassed",
                       {"src": mac_str(p.src), "bpdu": p.summary()}, p.ts,
                       dedup=mac_str(p.src))

        if p.parse_anomalies:
            self._emit(out, "STP-013", p.iface, self._vlan_key(p),
                       "Malformed BPDU: " + ", ".join(p.parse_anomalies),
                       {"src": mac_str(p.src), "anomalies": p.parse_anomalies,
                        "flags": f"0x{p.flags:02x}"}, p.ts,
                       dedup=",".join(p.parse_anomalies))

        reasons = []
        if p.src[0] & 0x01:
            reasons.append("multicast/broadcast bit set in source MAC")
        elif p.src[0] & 0x02:
            reasons.append("locally administered source MAC (randomized or forged)")
        if reasons:
            self._emit(out, "STP-011", p.iface, self._vlan_key(p),
                       "; ".join(reasons),
                       {"src": mac_str(p.src),
                        "bridge": str(p.bridge) if p.bridge else None}, p.ts,
                       dedup=mac_str(p.src))

        if p.encap == "ieee" and p.tags:
            self._emit(out, "STP-018", p.iface, self._vlan_key(p),
                       "IEEE BPDU arrived inside a VLAN tag; 802.1D/w/s BPDUs ride the native VLAN untagged",
                       {"tags": p.tags, "src": mac_str(p.src)}, p.ts)

        self.iface_encaps[p.iface].add(p.encap)
        if len(self.iface_encaps[p.iface]) > 1:
            self._emit(out, "STP-017", p.iface, "*",
                       "both IEEE and PVST+ spanning tree present on this interface",
                       {"encaps": sorted(self.iface_encaps[p.iface])}, p.ts)

    def _check_rates(self, p: BPDU, s: SegmentState, out: List[Finding]) -> None:
        now = p.ts
        s.bpdu_ts.append(now)
        _prune(s.bpdu_ts, now, self.t["bpdu_storm_window"])
        rate = len(s.bpdu_ts) / self.t["bpdu_storm_window"]
        if rate > self.t["bpdu_storm_per_sec"]:
            self._emit(out, "STP-008", p.iface, self._vlan_key(p),
                       f"BPDU rate {rate:.1f}/s over {self.t['bpdu_storm_window']:g}s window",
                       {"rate_per_sec": round(rate, 2),
                        "expected_hello": p.hello_time or 2.0}, now)

        if p.is_tcn:
            s.tcn_ts.append(now)
            _prune(s.tcn_ts, now, self.t["tcn_window"])
            if len(s.tcn_ts) >= self.t["tcn_count"]:
                self._emit(out, "STP-006", p.iface, self._vlan_key(p),
                           f"{len(s.tcn_ts)} TCN BPDUs in {self.t['tcn_window']:g}s "
                           f"(forces repeated CAM flushes -> unicast flooding)",
                           {"count": len(s.tcn_ts), "src": mac_str(p.src)}, now)
            return

        if p.tc:
            if not s.tc_active or (now - s.tc_last) > self.t["tc_episode_gap"]:
                s.tc_episodes.append(now)
            s.tc_active = True
            s.tc_last = now
            _prune(s.tc_episodes, now, self.t["tc_episode_window"])
            if len(s.tc_episodes) >= self.t["tc_episodes"]:
                self._emit(out, "STP-007", p.iface, self._vlan_key(p),
                           f"{len(s.tc_episodes)} topology-change episodes in "
                           f"{self.t['tc_episode_window']:g}s",
                           {"episodes": len(s.tc_episodes)}, now)
        elif s.tc_active and (now - s.tc_last) > self.t["tc_episode_gap"]:
            s.tc_active = False

        if p.proposal or p.agreement:
            s.proposal_ts.append(now)
            _prune(s.proposal_ts, now, self.t["proposal_window"])
            if len(s.proposal_ts) >= self.t["proposal_count"]:
                self._emit(out, "STP-016", p.iface, self._vlan_key(p),
                           f"{len(s.proposal_ts)} RSTP proposal/agreement BPDUs in "
                           f"{self.t['proposal_window']:g}s",
                           {"count": len(s.proposal_ts), "src": mac_str(p.src)}, now)

    def _check_priority(self, p: BPDU, out: List[Finding], vlan: Any) -> None:
        for who, bid in (("root", p.root), ("bridge", p.bridge)):
            if bid is None:
                continue
            if bid.raw_priority <= self.t["priority_floor"]:
                self._emit(out, "STP-009", p.iface, vlan,
                           f"{who} priority {bid.raw_priority} <= floor "
                           f"{self.t['priority_floor']}; classic root-takeover value",
                           {"which": who, "bridge_id": str(bid),
                            "src": mac_str(p.src)}, p.ts, dedup=who)

        b = p.bridge
        if b is None:
            return
        # In ext-sysid deployments the low 12 bits carry the VLAN or MSTI instance.
        # We can only verify that when the instance is unambiguous: a tagged/PVST
        # VLAN, or the MSTP CIST (which must be 0). An untagged IEEE BPDU on an
        # unknown native VLAN is unverifiable, so we do not guess.
        if vlan == "CIST":
            expected_ext = 0
        elif isinstance(vlan, int) and vlan > 0:
            expected_ext = vlan
        else:
            return
        if b.sysid_ext not in (0, expected_ext):
            self._emit(out, "STP-010", p.iface, vlan,
                       f"bridge priority 0x{b.raw_priority:04x}: sysid-ext {b.sysid_ext} "
                       f"matches neither 0 nor instance {expected_ext}",
                       {"raw_priority": b.raw_priority, "sysid_ext": b.sysid_ext,
                        "expected": expected_ext, "src": mac_str(p.src)}, p.ts)

    def _check_timers(self, p: BPDU, out: List[Finding], vlan: Any) -> None:
        bad = []
        if not (HELLO_RANGE[0] <= p.hello_time <= HELLO_RANGE[1]):
            bad.append(f"hello={p.hello_time:g}s outside {HELLO_RANGE}")
        if not (MAXAGE_RANGE[0] <= p.max_age <= MAXAGE_RANGE[1]):
            bad.append(f"max_age={p.max_age:g}s outside {MAXAGE_RANGE}")
        if not (FWDDELAY_RANGE[0] <= p.forward_delay <= FWDDELAY_RANGE[1]):
            bad.append(f"fwd_delay={p.forward_delay:g}s outside {FWDDELAY_RANGE}")
        if 2 * (p.forward_delay - 1.0) < p.max_age:
            bad.append(f"2*(fwd_delay-1)={2*(p.forward_delay-1):g} < max_age={p.max_age:g}")
        if p.max_age < 2 * (p.hello_time + 1.0):
            bad.append(f"max_age={p.max_age:g} < 2*(hello+1)={2*(p.hello_time+1):g}")
        if bad:
            self._emit(out, "STP-012", p.iface, vlan,
                       "Illegal or inconsistent STP timers: " + "; ".join(bad),
                       {"hello": p.hello_time, "max_age": p.max_age,
                        "forward_delay": p.forward_delay, "src": mac_str(p.src),
                        "violations": bad}, p.ts)

    def _check_costs_and_age(self, p: BPDU, out: List[Finding], vlan: Any) -> None:
        if p.path_cost == 0 and not p.is_root_originated:
            self._emit(out, "STP-015", p.iface, vlan,
                       "root path cost 0 from a bridge that is not the root",
                       {"root": str(p.root), "bridge": str(p.bridge),
                        "src": mac_str(p.src)}, p.ts)

        if p.max_age and p.message_age >= p.max_age:
            self._emit(out, "STP-014", p.iface, vlan,
                       f"message_age {p.message_age:g}s >= max_age {p.max_age:g}s; "
                       f"a conforming bridge would have discarded this",
                       {"message_age": p.message_age, "max_age": p.max_age,
                        "src": mac_str(p.src)}, p.ts)
        elif p.message_age == 0.0 and not p.is_root_originated:
            self._emit(out, "STP-014", p.iface, vlan,
                       "message_age 0 from a non-root bridge",
                       {"root": str(p.root), "bridge": str(p.bridge),
                        "src": mac_str(p.src)}, p.ts, dedup="zero_age")

    def _check_roots(self, p: BPDU, s: SegmentState, out: List[Finding], vlan: Any) -> None:
        if p.root is None:
            return
        now = p.ts
        rk = p.root.key()

        s.roots_recent[rk] = now
        for k in [k for k, t in s.roots_recent.items() if now - t > self.t["multi_root_window"]]:
            del s.roots_recent[k]
        if len(s.roots_recent) > 1:
            self._emit(out, "STP-019", p.iface, vlan,
                       f"{len(s.roots_recent)} distinct roots advertised within "
                       f"{self.t['multi_root_window']:g}s",
                       {"roots": [f"{pr}/{mac_str(m)}" for pr, m in s.roots_recent]}, now)

        bl = self._bl_roots.get(f"{p.iface}|{vlan}")
        reference = bl or s.root
        if reference is not None and rk < reference.key() and self._past_grace(now):
            self._emit(out, "STP-002", p.iface, vlan,
                       f"BPDU claims root {p.root}, superior to established root {reference}",
                       {"claimed_root": p.root.to_json(),
                        "established_root": reference.to_json(),
                        "from_baseline": bl is not None,
                        "sender_bridge": str(p.bridge),
                        "src": mac_str(p.src),
                        "path_cost": p.path_cost}, now,
                       dedup=str(p.root))

        if s.root is None:
            s.root = p.root
            s.root_since = now
        elif s.root != p.root:
            old = s.root
            s.root = p.root
            s.root_since = now
            s.root_changes.append(now)
            _prune(s.root_changes, now, self.t["root_flap_window"])
            self._emit(out, "STP-001", p.iface, vlan,
                       f"root changed {old} -> {p.root}",
                       {"old_root": old.to_json(), "new_root": p.root.to_json(),
                        "src": mac_str(p.src)}, now, dedup=str(p.root))
            if len(s.root_changes) >= self.t["root_flaps"]:
                self._emit(out, "STP-003", p.iface, vlan,
                           f"{len(s.root_changes)} root changes in "
                           f"{self.t['root_flap_window']:g}s",
                           {"changes": len(s.root_changes)}, now)

    def _check_bridges(self, p: BPDU, s: SegmentState, out: List[Finding], vlan: Any) -> None:
        if p.bridge is None:
            return
        bid = str(p.bridge)
        prev = s.last_bpdu_per_bridge.get(bid)
        if prev is not None:
            s.hello_intervals.append(p.ts - prev)
        s.last_bpdu_per_bridge[bid] = p.ts
        s.silence_alerted.discard(bid)

        if bid in s.bridges:
            s.bridges[bid] = p.ts
            return
        s.bridges[bid] = p.ts

        if self.learning:
            return
        known = bid in self._bl_bridges if self._bl_bridges else False
        if not known and self._past_grace(p.ts):
            self._emit(out, "STP-004", p.iface, vlan,
                       f"new bridge {bid} sourcing BPDUs",
                       {"bridge": p.bridge.to_json(), "src": mac_str(p.src),
                        "in_baseline": False,
                        "baseline_present": bool(self._bl_bridges)}, p.ts,
                       dedup=bid)

    def _check_mst(self, p: BPDU, out: List[Finding], vlan: Any) -> None:
        if not p.mst:
            return
        name = p.mst["region_name"]
        if not self._bl_regions:
            return
        known = self._bl_regions.get(name)
        if known is None:
            self._emit(out, "STP-022", p.iface, vlan,
                       f"MST BPDU from region '{name}' which is not in the baseline",
                       {"region": name, "revision": p.mst["revision"],
                        "digest": p.mst["digest"], "src": mac_str(p.src)}, p.ts,
                       dedup=name)
        elif known.get("digest") != p.mst["digest"]:
            self._emit(out, "STP-021", p.iface, vlan,
                       f"MST region '{name}' digest differs from baseline; "
                       f"region boundary shifted or VLAN-to-instance map was altered",
                       {"region": name,
                        "baseline_digest": known.get("digest"),
                        "observed_digest": p.mst["digest"],
                        "baseline_revision": known.get("revision"),
                        "observed_revision": p.mst["revision"],
                        "src": mac_str(p.src)}, p.ts, dedup=name)

    # -- per-MSTI tier -----------------------------------------------------
    def _check_msti(self, p: BPDU, out: List[Finding]) -> None:
        """Re-run the CIST root/priority/cost reasoning inside each MSTI record.

        Everything here is scoped to one MST instance. A forged regional root in
        MSTI 20 never touches the CIST fields, so none of STP-001/002/003/009/015
        can see it, and a correctly-computed digest keeps STP-021/022 quiet too.
        """
        if not p.mst:
            return
        region = p.mst["region_name"]

        for a in p.mst.get("msti_anomalies", ()):
            self._emit(out, "STP-029", p.iface, f"MSTI:*",
                       f"MST region '{region}': {a}",
                       {"region": region, "detail": a, "src": mac_str(p.src),
                        "declared": p.mst.get("msti_declared"),
                        "parsed": p.mst.get("msti_count")}, p.ts, dedup=a)

        records = p.mst.get("mstis") or ()
        if not records:
            return

        # The advertised instance set is a property of the sending bridge.
        sender = str(p.bridge) if p.bridge else mac_str(p.src)
        setkey = (p.iface, f"{region}|{sender}")
        current = frozenset(r["mstid"] for r in records)
        previous = self._msti_sets.get(setkey)
        self._msti_sets[setkey] = current
        if previous is not None and previous != current and self._past_grace(p.ts):
            added = sorted(current - previous)
            removed = sorted(previous - current)
            self._emit(out, "STP-030", p.iface, "MSTI:*",
                       f"bridge {sender} changed its MST instance set in region "
                       f"'{region}': +{added} -{removed}",
                       {"region": region, "bridge": sender,
                        "added": added, "removed": removed,
                        "now": sorted(current)}, p.ts, dedup=sender)

        for rec in records:
            self._check_one_msti(p, rec, region, out)

    def _check_one_msti(self, p: BPDU, rec: Dict[str, Any], region: str,
                        out: List[Finding]) -> None:
        mstid = rec["mstid"]
        scope = f"MSTI:{mstid}"
        now = p.ts
        root = bridge_from_json(rec["regional_root"])
        st = self._msti(p.iface, region, mstid, now)
        st.last_seen = now
        st.count += 1
        rk = root.key()

        # -- STP-031: hop count ------------------------------------------
        hops = rec["remaining_hops"]
        if hops == 0:
            self._emit(out, "STP-031", p.iface, scope,
                       f"MSTI {mstid} remaining hops exhausted (0); "
                       f"the record should have been discarded, not forwarded",
                       {"region": region, "mstid": mstid, "remaining_hops": hops,
                        "src": mac_str(p.src)}, now, dedup="zero")
        elif hops > self.t["msti_max_hops"]:
            self._emit(out, "STP-031", p.iface, scope,
                       f"MSTI {mstid} remaining hops {hops} above region maximum "
                       f"{self.t['msti_max_hops']}; inflates the region diameter",
                       {"region": region, "mstid": mstid, "remaining_hops": hops,
                        "max_hops": self.t["msti_max_hops"],
                        "src": mac_str(p.src)}, now, dedup="high")

        # -- STP-029: the MSTID must match the regional root's sysid-ext --
        # (structural, per-record; set-level anomalies were emitted above)
        if root.sysid_ext != mstid:
            self._emit(out, "STP-029", p.iface, scope,
                       f"MSTI {mstid}: regional root sysid-ext {root.sysid_ext} "
                       f"does not match the instance number",
                       {"region": region, "mstid": mstid,
                        "sysid_ext": root.sysid_ext,
                        "src": mac_str(p.src)}, now, dedup=f"sysid{mstid}")

        # -- STP-026: priority floor --------------------------------------
        floor = self.t["msti_priority_floor"]
        if root.raw_priority <= floor:
            self._emit(out, "STP-026", p.iface, scope,
                       f"MSTI {mstid} regional-root priority {root.raw_priority} "
                       f"<= floor {floor}; instance-scoped root takeover",
                       {"region": region, "mstid": mstid, "which": "regional_root",
                        "regional_root": str(root), "src": mac_str(p.src)}, now,
                       dedup="root")
        if rec["bridge_priority"] <= floor:
            self._emit(out, "STP-026", p.iface, scope,
                       f"MSTI {mstid} bridge priority {rec['bridge_priority']} "
                       f"<= floor {floor}",
                       {"region": region, "mstid": mstid, "which": "bridge",
                        "bridge_priority": rec["bridge_priority"],
                        "src": mac_str(p.src)}, now, dedup="bridge")

        # -- STP-027: zero internal path cost from a non-root -------------
        is_regional_root = p.bridge is not None and root.mac == p.bridge.mac
        if rec["internal_root_path_cost"] == 0 and not is_regional_root:
            self._emit(out, "STP-027", p.iface, scope,
                       f"MSTI {mstid} internal root path cost 0 from a bridge that "
                       f"is not the regional root",
                       {"region": region, "mstid": mstid,
                        "regional_root": str(root),
                        "sender_bridge": str(p.bridge) if p.bridge else None,
                        "src": mac_str(p.src)}, now)

        # -- STP-028: concurrent regional roots ---------------------------
        st.roots_recent[rk] = now
        for k in [k for k, t in st.roots_recent.items()
                  if now - t > self.t["multi_root_window"]]:
            del st.roots_recent[k]
        if len(st.roots_recent) > 1:
            self._emit(out, "STP-028", p.iface, scope,
                       f"{len(st.roots_recent)} distinct regional roots for MSTI "
                       f"{mstid} within {self.t['multi_root_window']:g}s",
                       {"region": region, "mstid": mstid,
                        "roots": [f"{pr}/{mac_str(m)}" for pr, m in st.roots_recent]},
                       now)

        # -- STP-024: superior regional root ------------------------------
        bl = self._bl_msti_roots.get(f"{p.iface}|{region}|{mstid}")
        reference = bl or st.root
        if reference is not None and rk < reference.key() and self._past_grace(now):
            self._emit(out, "STP-024", p.iface, scope,
                       f"MSTI {mstid} record claims regional root {root}, superior "
                       f"to the established {reference}",
                       {"region": region, "mstid": mstid,
                        "claimed_root": root.to_json(),
                        "established_root": reference.to_json(),
                        "from_baseline": bl is not None,
                        "sender_bridge": str(p.bridge) if p.bridge else None,
                        "internal_root_path_cost": rec["internal_root_path_cost"],
                        "src": mac_str(p.src)}, now, dedup=str(root))

        # -- STP-023 / STP-025: regional root change and flap -------------
        if st.root is None:
            st.root = root
            return
        if st.root == root:
            return
        old = st.root
        st.root = root
        st.root_changes.append(now)
        _prune(st.root_changes, now, self.t["root_flap_window"])
        self._emit(out, "STP-023", p.iface, scope,
                   f"MSTI {mstid} regional root changed {old} -> {root}",
                   {"region": region, "mstid": mstid,
                    "old_root": old.to_json(), "new_root": root.to_json(),
                    "src": mac_str(p.src)}, now, dedup=str(root))
        if len(st.root_changes) >= self.t["root_flaps"]:
            self._emit(out, "STP-025", p.iface, scope,
                       f"{len(st.root_changes)} regional-root changes for MSTI "
                       f"{mstid} in {self.t['root_flap_window']:g}s",
                       {"region": region, "mstid": mstid,
                        "changes": len(st.root_changes)}, now)

    # -- time-driven checks ------------------------------------------------
    def tick(self, now: float) -> List[Finding]:
        out: List[Finding] = []
        for (iface, vlan), s in self.segments.items():
            hello = 2.0
            if s.hello_intervals:
                hello = max(1.0, sum(s.hello_intervals) / len(s.hello_intervals))
            limit = max(self.t["silence_floor"], hello * self.t["silence_multiplier"])
            for bid, last in s.last_bpdu_per_bridge.items():
                if now - last > limit and bid not in s.silence_alerted:
                    s.silence_alerted.add(bid)
                    self._emit(out, "STP-020", iface, vlan,
                               f"bridge {bid} silent for {now - last:.1f}s "
                               f"(>{limit:.1f}s); link, peer, or root lost",
                               {"bridge": bid, "silent_for": round(now - last, 2),
                                "threshold": round(limit, 2)}, now, dedup=bid)
        return out

    # -- baseline / reporting ---------------------------------------------
    def build_baseline(self) -> Dict[str, Any]:
        roots, bridges, regions = {}, {}, {}
        for (iface, vlan), s in self.segments.items():
            if s.root:
                roots[f"{iface}|{vlan}"] = s.root.to_json()
            for bid, last in s.bridges.items():
                bridges.setdefault(bid, {"last_seen": last,
                                         "segments": []})["segments"].append(f"{iface}|{vlan}")
        for name, meta in getattr(self, "_seen_regions", {}).items():
            regions[name] = meta
        msti_roots = {}
        for (iface, region, mstid), st in self.mstis.items():
            if st.root:
                msti_roots[f"{iface}|{region}|{mstid}"] = st.root.to_json()
        return {
            "version": __version__,
            "created": time.time(),
            "roots": roots,
            "bridges": bridges,
            "mst_regions": regions,
            "msti_roots": msti_roots,
        }

    def health(self) -> List[Dict[str, Any]]:
        rows = []
        for (iface, vlan), s in sorted(self.segments.items(), key=lambda x: str(x[0])):
            iv = list(s.hello_intervals)
            mean = sum(iv) / len(iv) if iv else 0.0
            jitter = (max(iv) - min(iv)) if len(iv) > 1 else 0.0
            rows.append({
                "iface": iface, "vlan": vlan,
                "root": str(s.root) if s.root else "-",
                "bridges": len(s.bridges),
                "bpdus": s.count,
                "hello_mean": round(mean, 3),
                "hello_jitter": round(jitter, 3),
                "tc_episodes": len(s.tc_episodes),
                "root_changes": len(s.root_changes),
                "encap": "+".join(sorted(s.encaps)),
                "age": round(s.last_seen - s.first_seen, 1),
            })
        return rows

    def msti_health(self) -> List[Dict[str, Any]]:
        rows = []
        for (iface, region, mstid), st in sorted(self.mstis.items(),
                                                 key=lambda x: (x[0][0], x[0][1], x[0][2])):
            rows.append({
                "iface": iface,
                "region": region,
                "mstid": mstid,
                "regional_root": str(st.root) if st.root else "-",
                "records": st.count,
                "root_changes": len(st.root_changes),
                "age": round(st.last_seen - st.first_seen, 1),
            })
        return rows


# --------------------------------------------------------------------------
# Capture: AF_PACKET + classic BPF, receive-only
# --------------------------------------------------------------------------

SO_ATTACH_FILTER = 26
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4

# ldh [0] / jeq 0x0180 / jeq 0x0100 / ld [2] / jeq c2000000 / ld [2] / jeq 0ccccccd / ret 0 / ret 262144
BPF_PROGRAM: Tuple[Tuple[int, int, int, int], ...] = (
    (0x28, 0, 0, 0x00000000),
    (0x15, 1, 0, 0x00000180),
    (0x15, 2, 4, 0x00000100),
    (0x20, 0, 0, 0x00000002),
    (0x15, 3, 2, 0xC2000000),
    (0x20, 0, 0, 0x00000002),
    (0x15, 1, 0, 0x0CCCCCCD),
    (0x06, 0, 0, 0x00000000),
    (0x06, 0, 0, 0x00040000),
)


def _bpf_blob() -> bytes:
    return b"".join(struct.pack("HBBI", *i) for i in BPF_PROGRAM)


class Sniffer:
    """Receive-only AF_PACKET socket. There is deliberately no send path."""

    def __init__(self, ifaces: Iterable[str] = (), promisc: bool = False):
        self.ifaces = list(ifaces)
        self.promisc = promisc
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        self._filter_buf = ctypes.create_string_buffer(_bpf_blob())
        fprog = struct.pack("HL", len(BPF_PROGRAM), ctypes.addressof(self._filter_buf))
        self.sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        for ifn in self.ifaces:
            self._join(ifn)
        self.sock.setblocking(False)

    def _join(self, ifname: str) -> None:
        idx = socket.if_nametoindex(ifname)
        if self.promisc:
            mreq = struct.pack("iHH8s", idx, PACKET_MR_PROMISC, 0, b"")
            self.sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
        else:
            # Gentler than promisc: subscribe to the two BPDU group addresses.
            for addr in (BRIDGE_GROUP_ADDR, PVST_ADDR):
                mreq = struct.pack("iHH8s", idx, PACKET_MR_MULTICAST, 6, addr + b"\x00\x00")
                self.sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)

    def fileno(self) -> int:
        return self.sock.fileno()

    def read(self) -> List[Tuple[float, str, bytes]]:
        frames = []
        while True:
            try:
                data, sa = self.sock.recvfrom(2048)
            except BlockingIOError:
                break
            except OSError:
                break
            ifname, _proto, pkttype = sa[0], sa[1], sa[2]
            if pkttype == PACKET_OUTGOING:
                continue
            if self.ifaces and ifname not in self.ifaces:
                continue
            frames.append((time.time(), ifname, data))
        return frames

    def close(self) -> None:
        self.sock.close()


# --------------------------------------------------------------------------
# Offline pcap replay (classic libpcap, DLT_EN10MB)
# --------------------------------------------------------------------------

def pcap_frames(path: str):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("short pcap header")
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, nano = ">", True
        else:
            raise ValueError("not a classic pcap (pcapng is unsupported)")
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        if linktype != 1:
            raise ValueError(f"need DLT_EN10MB, got linktype {linktype}")
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            yield ts, data


# --------------------------------------------------------------------------
# Reporter
# --------------------------------------------------------------------------

class Reporter:
    def __init__(self, jsonl: Optional[str] = None, use_syslog: bool = False,
                 quiet: bool = False, min_sev: str = "INFO"):
        self.fh = open(jsonl, "a", buffering=1) if jsonl else None
        self.quiet = quiet
        self.min_sev = SEVERITY_ORDER[min_sev]
        self.log = None
        if use_syslog:
            self.log = logging.getLogger("stpwatch")
            self.log.setLevel(logging.INFO)
            h = logging.handlers.SysLogHandler(address="/dev/log",
                                               facility=logging.handlers.SysLogHandler.LOG_LOCAL0)
            h.setFormatter(logging.Formatter("stpwatch[%(process)d]: %(message)s"))
            self.log.addHandler(h)

    def emit(self, f: Finding) -> None:
        if SEVERITY_ORDER[f.severity] < self.min_sev:
            return
        if not self.quiet:
            print(f.line(), flush=True)
        if self.fh:
            self.fh.write(json.dumps(f.to_json(), separators=(",", ":")) + "\n")
        if self.log:
            self.log.warning(json.dumps(f.to_json(), separators=(",", ":")))

    def close(self) -> None:
        if self.fh:
            self.fh.close()


def _print_table(rows: List[Dict[str, Any]], cols: List[str]) -> None:
    widths = {c: max(len(c), max(len(str(r[c])) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols), flush=True)
    print("  ".join("-" * widths[c] for c in cols), flush=True)
    for r in rows:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in cols), flush=True)


def print_msti_health(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    print("\n-- MST instances --", flush=True)
    _print_table(rows, ["iface", "region", "mstid", "regional_root",
                        "records", "root_changes"])


def print_health(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("-- no spanning-tree activity observed --", flush=True)
        return
    _print_table(rows, ["iface", "vlan", "encap", "root", "bridges", "bpdus",
                        "hello_mean", "hello_jitter", "tc_episodes", "root_changes"])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

_RUNNING = True


def _stop(signum, frame):
    global _RUNNING
    _RUNNING = False


def run_live(args) -> int:
    baseline = json.load(open(args.baseline)) if args.baseline else None
    thresholds = json.load(open(args.config)) if args.config else None
    an = Analyzer(baseline=baseline, edge_ifaces=args.edge, thresholds=thresholds,
                  learning=args.learn is not None)
    rep = Reporter(args.jsonl, args.syslog, args.quiet, args.min_severity)

    try:
        sn = Sniffer(args.iface, promisc=args.promisc)
    except PermissionError:
        print("stpwatch: need CAP_NET_RAW (run as root or grant the capability)", file=sys.stderr)
        return 1

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    deadline = time.time() + args.learn if args.learn else None
    next_summary = time.time() + args.summary_interval if args.summary_interval else None
    seen_regions: Dict[str, Any] = {}

    while _RUNNING:
        r, _, _ = select.select([sn], [], [], 1.0)
        now = time.time()
        if r:
            for ts, ifname, data in sn.read():
                try:
                    p = parse_frame(data, ifname, ts)
                except ParseError as e:
                    an.stats["parse_error"] += 1
                    if args.verbose:
                        print(f"parse error on {ifname}: {e}", file=sys.stderr)
                    continue
                if p is None:
                    continue
                if p.mst:
                    seen_regions[p.mst["region_name"]] = {
                        "revision": p.mst["revision"], "digest": p.mst["digest"]}
                if args.verbose:
                    print(f"{ifname} {mac_str(p.src)} {p.summary()}", flush=True)
                for f in an.process(p):
                    rep.emit(f)

        for f in an.tick(now):
            rep.emit(f)

        if next_summary and now >= next_summary:
            print_health(an.health())
            print_msti_health(an.msti_health())
            next_summary = now + args.summary_interval

        if deadline and now >= deadline:
            break

    sn.close()

    if args.learn:
        an._seen_regions = seen_regions  # type: ignore[attr-defined]
        bl = an.build_baseline()
        with open(args.write_baseline, "w") as fh:
            json.dump(bl, fh, indent=2)
        print(f"\nbaseline written to {args.write_baseline}: "
              f"{len(bl['roots'])} segment root(s), {len(bl['bridges'])} bridge(s), "
              f"{len(bl['mst_regions'])} MST region(s), "
              f"{len(bl['msti_roots'])} MSTI regional root(s)", flush=True)

    print("\n-- L2 spanning-tree health --", flush=True)
    print_health(an.health())
    print_msti_health(an.msti_health())
    print(f"\n-- counters -- {dict(sorted(an.stats.items()))}", flush=True)
    rep.close()
    return 0


def run_pcap(args) -> int:
    baseline = json.load(open(args.baseline)) if args.baseline else None
    thresholds = json.load(open(args.config)) if args.config else None
    an = Analyzer(baseline=baseline, edge_ifaces=args.edge, thresholds=thresholds, start_ts=0.0)
    rep = Reporter(args.jsonl, False, args.quiet, args.min_severity)
    n = last = 0
    for ts, data in pcap_frames(args.pcap):
        n += 1
        try:
            p = parse_frame(data, args.pcap_iface, ts)
        except ParseError:
            an.stats["parse_error"] += 1
            continue
        if p is None:
            continue
        if args.verbose:
            print(f"{ts:.6f} {mac_str(p.src)} {p.summary()}", flush=True)
        for f in an.process(p):
            rep.emit(f)
        last = ts
    for f in an.tick(last):
        rep.emit(f)
    print(f"\n-- {n} frames replayed --", flush=True)
    print_health(an.health())
    print_msti_health(an.msti_health())
    print(f"\n-- counters -- {dict(sorted(an.stats.items()))}", flush=True)
    rep.close()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="stpwatch",
        description="Passive STP/RSTP/MSTP/PVST+ BPDU security monitor. "
                    "Never transmits. Detection only.")
    ap.add_argument("--version", action="version", version=f"stpwatch {__version__}")
    ap.add_argument("-i", "--iface", action="append", default=[],
                    help="interface to watch (repeatable; default: all)")
    ap.add_argument("--edge", action="append", default=[],
                    help="interface that must NEVER carry BPDUs (repeatable)")
    ap.add_argument("--promisc", action="store_true",
                    help="enable promiscuous mode instead of BPDU multicast membership")
    ap.add_argument("--baseline", help="baseline JSON to compare against")
    ap.add_argument("--config", help="threshold overrides (JSON)")
    ap.add_argument("--learn", type=float, metavar="SECONDS",
                    help="learn for N seconds, then write a baseline and exit")
    ap.add_argument("--write-baseline", default="stpwatch-baseline.json")
    ap.add_argument("--pcap", help="replay a classic pcap instead of sniffing")
    ap.add_argument("--pcap-iface", default="pcap")
    ap.add_argument("--jsonl", help="append findings as JSON lines to this file")
    ap.add_argument("--syslog", action="store_true", help="also log findings to syslog LOCAL0")
    ap.add_argument("--min-severity", default="INFO", choices=list(SEVERITY_ORDER))
    ap.add_argument("--summary-interval", type=float, default=0.0,
                    help="print the L2 health table every N seconds (0 = only at exit)")
    ap.add_argument("-v", "--verbose", action="store_true", help="decode every BPDU")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress stdout findings")
    ap.add_argument("--list-detections", action="store_true")
    args = ap.parse_args(argv)

    if args.list_detections:
        for k, (name, sev, desc) in DETECTIONS.items():
            print(f"{k}  {sev:<8} {name:<24} {desc}")
        return 0

    if args.pcap:
        return run_pcap(args)
    return run_live(args)


if __name__ == "__main__":
    sys.exit(main())
