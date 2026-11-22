"""Normalized data model for igmpwatch.

A raw Ether/IP/IGMP frame is decoded once into an :class:`IgmpEvent`; every
detector consumes that flat record and never re-parses the packet. Keeps the
hot path cheap on the Zero 2W.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Well-known multicast groups / ranges
# ---------------------------------------------------------------------------
MCAST_NET = ipaddress.ip_network("224.0.0.0/4")            # all multicast
LOCAL_CONTROL = ipaddress.ip_network("224.0.0.0/24")       # link-local, TTL 1, never forwarded
SSM_RANGE = ipaddress.ip_network("232.0.0.0/8")            # source-specific multicast
ADMIN_SCOPED = ipaddress.ip_network("239.0.0.0/8")         # private / org-local

ALL_HOSTS = ipaddress.ip_address("224.0.0.1")
ALL_ROUTERS = ipaddress.ip_address("224.0.0.2")
IGMPV3_ROUTERS = ipaddress.ip_address("224.0.0.22")

# Groups you legitimately see joins for even though they live in a control-ish
# scope; used to suppress benign noise before it reaches the policy engine.
DEFAULT_BENIGN_GROUPS = {
    "224.0.0.251",     # mDNS
    "224.0.0.252",     # LLMNR
    "239.255.255.250", # SSDP / UPnP
    "239.255.255.253", # SLP
}

# --- IPv6 / MLD equivalents ------------------------------------------------
MCAST6_NET = ipaddress.ip_network("ff00::/8")             # all IPv6 multicast
LINK_LOCAL_SCOPE6 = ipaddress.ip_network("ff02::/16")     # link-local scope (MLD control)
ALL_NODES6 = ipaddress.ip_address("ff02::1")
ALL_ROUTERS6 = ipaddress.ip_address("ff02::2")
MLDV2_ROUTERS6 = ipaddress.ip_address("ff02::16")
# IPv6 source-specific multicast: ff3x::/32, i.e. flags nibble = 3 across every
# scope (ff30::/12 covers ff30:: - ff3f::). Parallel to IPv4 232.0.0.0/8.
SSM_RANGE6 = ipaddress.ip_network("ff30::/12")
# Reserved groups that must never be the target of a membership report.
RESERVED_GROUPS = {"224.0.0.1", "224.0.0.2", "ff02::1", "ff02::2"}


class MsgType(IntEnum):
    QUERY_GENERAL = 0
    QUERY_GROUP = 1
    QUERY_GROUP_SRC = 2
    REPORT_V1 = 3
    REPORT_V2 = 4
    REPORT_V3 = 5
    LEAVE = 6
    UNKNOWN = 99


# IGMPv3 group-record types
GR_IS_IN = 1   # MODE_IS_INCLUDE
GR_IS_EX = 2   # MODE_IS_EXCLUDE
GR_TO_IN = 3   # CHANGE_TO_INCLUDE
GR_TO_EX = 4   # CHANGE_TO_EXCLUDE
GR_ALLOW = 5   # ALLOW_NEW_SOURCES
GR_BLOCK = 6   # BLOCK_OLD_SOURCES

# Record types that represent an *active/continued* membership (a "join").
JOIN_RECORDS = {GR_IS_EX, GR_TO_EX, GR_IS_IN, GR_TO_IN, GR_ALLOW}
# A TO_INCLUDE with no sources, or IS_INCLUDE with no sources, is effectively a leave.


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    def label(self) -> str:
        return self.name


@dataclass
class GroupRecord:
    rtype: int
    group: str
    sources: List[str] = field(default_factory=list)

    @property
    def is_join(self) -> bool:
        if self.rtype in (GR_TO_IN, GR_IS_IN) and not self.sources:
            return False  # include{} == leave
        return self.rtype in JOIN_RECORDS

    @property
    def is_leave(self) -> bool:
        if self.rtype in (GR_TO_IN, GR_IS_IN) and not self.sources:
            return True
        return self.rtype == GR_BLOCK and False  # BLOCK trims sources, not a full leave


@dataclass
class IgmpEvent:
    ts: float
    eth_src: str
    eth_dst: str
    ip_src: str
    ip_dst: str
    ttl: int
    version: int                 # 1, 2 or 3
    msg_type: MsgType
    router_alert: bool
    checksum_ok: bool
    raw_len: int
    family: int = 4              # 4 = IGMP/IPv4, 6 = MLD/IPv6
    group: Optional[str] = None          # v1/v2 report/leave/group-query target
    max_resp: float = 0.0                # seconds
    qrv: int = 0                         # v3 querier robustness variable
    records: List[GroupRecord] = field(default_factory=list)
    truncated: bool = False              # numgrp/len mismatch on v3
    trailing_len: int = 0                # bytes after the IP payload in the L2 frame
    trailing_nonzero: int = 0            # of those, how many are non-zero (smuggling)
    declared_numsrc: int = 0             # source count asserted in a v3/MLDv2 query header
    declared_msg_len: int = 0            # message length implied by that source count
    actual_msg_len: int = 0              # message length actually on the wire
    fragmented: bool = False             # arrived as an IP/IPv6 fragment (never legal for IGMP/MLD)
    frag_nonfirst: bool = False          # a non-first fragment: bytes are a message tail, not a header

    # --- convenience -------------------------------------------------------
    @property
    def is_query(self) -> bool:
        return self.msg_type in (
            MsgType.QUERY_GENERAL, MsgType.QUERY_GROUP, MsgType.QUERY_GROUP_SRC
        )

    @property
    def is_report(self) -> bool:
        return self.msg_type in (MsgType.REPORT_V1, MsgType.REPORT_V2, MsgType.REPORT_V3)

    def joined_groups(self) -> List[Tuple[str, List[str]]]:
        """(group, sources) pairs this event asserts membership in."""
        out: List[Tuple[str, List[str]]] = []
        if self.msg_type in (MsgType.REPORT_V1, MsgType.REPORT_V2) and self.group:
            out.append((self.group, []))
        elif self.msg_type == MsgType.REPORT_V3:
            for r in self.records:
                if r.is_join:
                    out.append((r.group, r.sources))
        return out

    def left_groups(self) -> List[str]:
        out: List[str] = []
        if self.msg_type == MsgType.LEAVE and self.group:
            out.append(self.group)
        elif self.msg_type == MsgType.REPORT_V3:
            for r in self.records:
                if r.is_leave:
                    out.append(r.group)
        return out


# ---------------------------------------------------------------------------
# multicast helpers
# ---------------------------------------------------------------------------
def family(addr: str) -> int:
    return 6 if ":" in (addr or "") else 4


def in_ssm_range(addr: str) -> bool:
    """Source-specific multicast: IPv4 232.0.0.0/8 or IPv6 ff3x::/32.
    RFC 4604 requires IGMPv3/MLDv2 for membership in these groups."""
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return a in SSM_RANGE if a.version == 4 else a in SSM_RANGE6


def is_multicast(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_multicast
    except ValueError:
        return False


def in_local_control(addr: str) -> bool:
    """Link-local control scope, never forwarded: IPv4 224.0.0.0/24 or the
    IPv6 link-local multicast scope ff02::/16 (where MLD control lives)."""
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if a.version == 4:
        return a in LOCAL_CONTROL
    return a in LINK_LOCAL_SCOPE6


def addr_in_any(addr: str, nets: List[str]) -> bool:
    """True if addr matches any of the given exact addresses / CIDRs."""
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for n in nets:
        try:
            if "/" in n:
                if a in ipaddress.ip_network(n, strict=False):
                    return True
            elif a == ipaddress.ip_address(n):
                return True
        except ValueError:
            continue
    return False
