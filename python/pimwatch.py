#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pimwatch -- Ragnar passive PIM / RP-discovery / MSDP detector.

PASSIVE ONLY. This module NEVER transmits. It opens a capture handle in
promiscuous listen mode, parses what crosses the tap, and emits findings.
There is no probe, no verification packet, no active tier, by design.

Coverage
    PIM (IP protocol 103, IPv4 + IPv6)
        PIM-SM      RFC 7761    Hello/Register/Register-Stop/Join-Prune/Assert
        PIM-DM      RFC 3973    Graft/Graft-Ack/State-Refresh
        BiDir-PIM   RFC 5015    DF Election (type 10) + Hello option 22
        PIM-SSM     RFC 4607    no messages of its own; range checks on SM msgs
        BSR         RFC 5059    Bootstrap (type 4) + Candidate-RP-Adv (type 8)
        RPF Vector  RFC 5496    Join/Prune attribute TLV
        Anycast-RP  RFC 4610    Register with all-RP semantics
        Embedded-RP RFC 3956    RP address carried inside the group address
        AH posture  RFC 5796    IPsec AH on PIM link-local messages
    Auto-RP (Cisco)  UDP/496, 224.0.1.39 / 224.0.1.40   -- IPv4 only
    MSDP             RFC 3618   TCP/639 TLV stream       -- IPv4 only

RPF note
    RPF is a router-internal decision against the RIB. It is NOT on the wire.
    Everything here labelled RPF is a HEURISTIC over observable state --
    upstream-neighbour membership, Assert churn, and the RFC 5496 RPF Vector.
    No RIB cross-check against pathwatch/ospfwatch: explicitly out of scope.

Dual-stack
    Per the Ragnar prime directive, IPv6 parity wherever the protocol has an
    IPv6 form. Auto-RP and MSDP have no IPv6 variant and are IPv4-only; their
    IPv6 equivalents are RFC 4610 Anycast-RP and RFC 3956 Embedded-RP, which
    are implemented on the PIM side.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import struct
import sys
import time
from collections import defaultdict, deque

MODULE = "pimwatch"
VERSION = "0.1.0-dev"

# --------------------------------------------------------------------------
# Wire constants
# --------------------------------------------------------------------------

IPPROTO_PIM = 103
AUTORP_PORT = 496
MSDP_PORT = 639

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)

PIM_ALL_ROUTERS_V4 = "224.0.0.13"
PIM_ALL_ROUTERS_V6 = "ff02::d"
AUTORP_ANNOUNCE = "224.0.1.39"
AUTORP_DISCOVERY = "224.0.1.40"

SSM_V4_NET = ipaddress.ip_network("232.0.0.0/8")
SSM_V6_PREFIX = "ff3"          # ff3x::/32
EMBEDDED_RP_PREFIX = "ff7"     # ff7x::/12

# PIM message types (RFC 7761 / 3973 / 5015 / 6754 / 8364)
PIM_HELLO = 0
PIM_REGISTER = 1
PIM_REGISTER_STOP = 2
PIM_JOIN_PRUNE = 3
PIM_BOOTSTRAP = 4
PIM_ASSERT = 5
PIM_GRAFT = 6
PIM_GRAFT_ACK = 7
PIM_CAND_RP_ADV = 8
PIM_STATE_REFRESH = 9
PIM_DF_ELECTION = 10
PIM_ECMP_REDIRECT = 11
PIM_PFM = 13

PIM_TYPE_NAME = {
    0: "Hello", 1: "Register", 2: "Register-Stop", 3: "Join/Prune",
    4: "Bootstrap", 5: "Assert", 6: "Graft", 7: "Graft-Ack",
    8: "Candidate-RP-Advertisement", 9: "State-Refresh", 10: "DF-Election",
    11: "ECMP-Redirect", 13: "PFM-SD",
}

# Hello option types (IANA PIM-Hello Options)
HELLO_HOLDTIME = 1
HELLO_LAN_PRUNE_DELAY = 2
HELLO_DR_PRIORITY = 19
HELLO_GENERATION_ID = 20
HELLO_STATE_REFRESH = 21
HELLO_BIDIR_CAPABLE = 22
HELLO_ADDRESS_LIST = 24
HELLO_ADDRESS_LIST_OLD = 65001

# Join/Prune attribute TLVs (RFC 5384 encoding; RFC 5496 RPF Vector = type 0)
JP_ATTR_RPF_VECTOR = 0

# DF Election subtypes (RFC 5015)
DF_OFFER = 1
DF_WINNER = 2
DF_BACKOFF = 3
DF_PASS = 4
DF_SUBTYPE_NAME = {1: "Offer", 2: "Winner", 3: "Backoff", 4: "Pass"}

# Address families in PIM encoded addresses
PIM_AFI_IPV4 = 1
PIM_AFI_IPV6 = 2

# MSDP TLV types (RFC 3618)
MSDP_SA = 1
MSDP_SA_REQUEST = 2
MSDP_SA_RESPONSE = 3
MSDP_KEEPALIVE = 4
MSDP_NOTIFICATION = 5
MSDP_TLV_NAME = {
    1: "IPv4-Source-Active", 2: "SA-Request", 3: "SA-Response",
    4: "KeepAlive", 5: "Notification",
}

# IPv6 extension headers
IPV6_EH = {0: "HopByHop", 43: "Routing", 44: "Fragment", 51: "AH",
           60: "DestOpt", 135: "Mobility"}
IPV6_NO_NEXT = 59
IPPROTO_AH = 51
IPPROTO_ESP = 50


# --------------------------------------------------------------------------
# Finding registry
#
# cls is explicit per code -- never derive an attack band from a lexicographic
# or numeric comparison on the code string (suite LESSON AK).
# --------------------------------------------------------------------------

def _F(sev, cls, title):
    return {"severity": sev, "class": cls, "title": title}


FINDINGS = {
    # -- PIM common / posture -------------------------------------------
    "PMW-001": _F("info", "posture", "PIM speaker observed"),
    "PMW-002": _F("warn", "posture", "PIM version other than 2 observed"),
    "PMW-003": _F("notice", "posture", "PIM message with invalid checksum"),
    "PMW-004": _F("notice", "posture", "PIM message truncated or malformed"),
    "PMW-005": _F("info", "posture", "PIM mode observed on link"),
    "PMW-006": _F("notice", "posture", "PIM Hello without Holdtime option"),
    "PMW-007": _F("notice", "posture", "PIM link-local message with unexpected TTL/hop-limit"),
    "PMW-009": _F("notice", "posture", "PIM message of unknown or reserved type"),
    "PMW-010": _F("notice", "posture", "PIM link-local message not sent to the all-PIM-routers group"),

    # -- AH posture (RFC 5796) -------------------------------------------
    "PMW-020": _F("info", "posture", "PIM protected by IPsec AH"),
    "PMW-021": _F("warn", "attack", "PIM link lost IPsec AH protection"),
    "PMW-022": _F("notice", "posture", "Mixed authenticated and unauthenticated PIM on one link"),
    "PMW-023": _F("notice", "posture", "IPsec AH SPI changed for a PIM neighbour"),

    # -- Neighbour / Hello ------------------------------------------------
    "PMW-040": _F("warn", "attack", "New PIM neighbour appeared after arming"),
    "PMW-041": _F("warn", "attack", "Hello Generation ID changed without holdtime expiry"),
    "PMW-042": _F("warn", "attack", "Neighbour raised DR Priority above the incumbent DR"),
    "PMW-043": _F("critical", "attack", "Designated Router changed on link"),
    "PMW-044": _F("warn", "attack", "Hello with zero Holdtime (neighbour goodbye)"),
    "PMW-045": _F("warn", "attack", "PIM Hello rate anomaly from one source"),
    "PMW-046": _F("notice", "posture", "LAN Prune Delay / T-bit changed"),
    "PMW-047": _F("warn", "attack", "Same PIM neighbour address seen from two MAC addresses"),
    "PMW-048": _F("notice", "posture", "Bidir-Capable advertisement changed"),
    "PMW-049": _F("notice", "posture", "State-Refresh-Capable advertisement changed"),
    "PMW-050": _F("warn", "attack", "Hello Holdtime reduced to a flap-inducing value"),

    # -- Join / Prune / SPT ------------------------------------------------
    "PMW-060": _F("warn", "attack", "Join/Prune upstream neighbour is not a learned neighbour"),
    "PMW-061": _F("warn", "attack", "Prune rate anomaly for a group"),
    "PMW-062": _F("warn", "attack", "Join/Prune with zero Holdtime"),
    "PMW-063": _F("notice", "posture", "SPT switchover observed ((*,G) to (S,G))"),
    "PMW-064": _F("notice", "posture", "RPT prune observed ((S,G,rpt))"),
    "PMW-065": _F("warn", "attack", "Join for a group outside the learned group baseline"),
    "PMW-066": _F("warn", "attack", "Join/Prune with implausible group or source counts"),
    "PMW-067": _F("notice", "posture", "RPF Vector attribute present in Join/Prune"),
    "PMW-068": _F("warn", "attack", "RPF Vector points outside the learned neighbour and RP set"),
    "PMW-070": _F("warn", "attack", "Prune from an unexpected sender after arming"),

    # -- Assert ------------------------------------------------------------
    "PMW-080": _F("notice", "posture", "PIM Assert observed"),
    "PMW-081": _F("warn", "attack", "Assert contention churn for one (S,G)"),
    "PMW-082": _F("warn", "attack", "Assert with anomalous metric preference"),
    "PMW-083": _F("warn", "attack", "Assert winner changed for an (S,G) after arming"),
    "PMW-084": _F("warn", "attack", "Assert from a source that is not a learned neighbour"),

    # -- RP / BSR / Auto-RP / Anycast-RP / Embedded-RP ---------------------
    "PMW-100": _F("info", "posture", "Rendezvous Point learned"),
    "PMW-101": _F("info", "posture", "Bootstrap Router learned"),
    "PMW-102": _F("warn", "attack", "Higher-priority BSR appeared after arming"),
    "PMW-103": _F("critical", "attack", "Bootstrap Router address changed after arming"),
    "PMW-104": _F("warn", "attack", "Candidate-RP advertisement from an unknown RP"),
    "PMW-105": _F("warn", "attack", "Bootstrap RP set changed"),
    "PMW-106": _F("warn", "attack", "Group range mapped to more than one RP"),
    "PMW-107": _F("warn", "attack", "Auto-RP announcement from an unknown RP"),
    "PMW-108": _F("warn", "attack", "Auto-RP mapping agent changed"),
    "PMW-109": _F("notice", "posture", "Auto-RP observed (unauthenticated by design)"),
    "PMW-110": _F("warn", "attack", "Register sent to an RP outside the learned RP set"),
    "PMW-111": _F("notice", "posture", "Register-Stop from an unexpected RP"),
    "PMW-112": _F("warn", "attack", "BSR hash mask length changed"),
    "PMW-113": _F("notice", "posture", "PIM Anycast-RP (RFC 4610) Register observed"),
    "PMW-114": _F("warn", "attack", "Both MSDP and PIM Anycast-RP in use for one RP address"),
    "PMW-115": _F("notice", "posture", "Embedded-RP (RFC 3956) group observed"),
    "PMW-116": _F("warn", "attack", "Embedded-RP address disagrees with the learned RP set"),
    "PMW-117": _F("warn", "attack", "Bootstrap fragment tag churn"),
    "PMW-118": _F("warn", "attack", "Candidate-RP priority escalation"),

    # -- Dense Mode ---------------------------------------------------------
    "PMW-120": _F("notice", "posture", "PIM Dense Mode observed on link"),
    "PMW-121": _F("warn", "attack", "Graft rate anomaly"),
    "PMW-122": _F("warn", "attack", "State Refresh originator is not a learned neighbour"),
    "PMW-123": _F("warn", "attack", "State Refresh TTL or interval anomaly"),
    "PMW-124": _F("notice", "posture", "Graft-Ack without a matching Graft"),
    "PMW-125": _F("warn", "attack", "Dense Mode appeared on a link previously Sparse-only"),

    # -- BiDir DF election ---------------------------------------------------
    "PMW-140": _F("notice", "posture", "BiDir DF election observed"),
    "PMW-141": _F("warn", "attack", "DF election Offer flood"),
    "PMW-142": _F("warn", "attack", "DF winner changed for an RP after arming"),
    "PMW-143": _F("warn", "attack", "DF election message from a non-neighbour"),
    "PMW-144": _F("warn", "attack", "DF Pass to an unknown target"),
    "PMW-145": _F("notice", "posture", "New neighbour advertising Bidir-Capable"),

    # -- SSM -----------------------------------------------------------------
    "PMW-160": _F("notice", "posture", "SSM-range group observed"),
    "PMW-161": _F("warn", "attack", "(*,G) Join for an SSM-range group"),
    "PMW-162": _F("warn", "attack", "Register for an SSM-range group"),
    "PMW-163": _F("warn", "attack", "SSM (S,G) source changed for a group against baseline"),
    "PMW-164": _F("warn", "attack", "SSM-range group present in an RP mapping"),

    # -- MSDP -----------------------------------------------------------------
    "PMW-180": _F("info", "posture", "MSDP peer session observed"),
    "PMW-181": _F("info", "posture", "MSDP Source-Active observed"),
    "PMW-182": _F("warn", "attack", "MSDP SA originating RP is not in the learned RP set"),
    "PMW-183": _F("warn", "attack", "MSDP SA for an SSM-range group"),
    "PMW-184": _F("warn", "attack", "MSDP Source-Active storm"),
    "PMW-185": _F("warn", "attack", "MSDP group advertised by conflicting originating RPs"),
    "PMW-186": _F("notice", "posture", "MSDP session reset or KeepAlive gap"),
    "PMW-187": _F("warn", "attack", "MSDP peer outside the learned peer set"),
    "PMW-188": _F("notice", "posture", "MSDP SA-Request/SA-Response observed"),
    "PMW-189": _F("notice", "posture", "MSDP TLV malformed"),
    "PMW-190": _F("notice", "posture", "MSDP session without TCP-MD5 authentication"),
    "PMW-191": _F("warn", "attack", "MSDP SA carrying encapsulated data"),
    "PMW-192": _F("notice", "posture", "MSDP SA entry count inconsistent with TLV length"),
}

SEVERITY_ORDER = {"info": 0, "notice": 1, "warn": 2, "critical": 3}

# Which protocol each code belongs to -- used instead of any string-prefix or
# numeric-band test, so adding a tier can never silently reclassify codes.
CODE_PROTO = {}
for _c in FINDINGS:
    _n = int(_c.split("-")[1])
    if 180 <= _n <= 199:
        CODE_PROTO[_c] = "msdp"
    elif _c in ("PMW-107", "PMW-108", "PMW-109"):
        CODE_PROTO[_c] = "autorp"
    else:
        CODE_PROTO[_c] = "pim"


def attack_class_codes(proto=None):
    """Codes whose registry class is 'attack', optionally for one protocol."""
    return {c for c, m in FINDINGS.items()
            if m["class"] == "attack" and (proto is None or CODE_PROTO[c] == proto)}


def posture_class_codes(proto=None):
    return {c for c, m in FINDINGS.items()
            if m["class"] == "posture" and (proto is None or CODE_PROTO[c] == proto)}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

class ParseError(Exception):
    """Raised on any malformed or truncated input. Never escapes handle_frame."""


def fmt_ep(addr, port=None):
    """RFC 3986 endpoint rendering. IPv6 literals are bracketed so the string
    can be split back into host and port by every downstream consumer."""
    if addr is None:
        return None
    if port is None:
        return addr
    if ":" in addr:
        return "[%s]:%d" % (addr, port)
    return "%s:%d" % (addr, port)


def split_ep(ep):
    """Inverse of fmt_ep -- used by the round-trip test."""
    if ep.startswith("["):
        host, _, rest = ep[1:].partition("]")
        return host, int(rest.lstrip(":"))
    host, _, p = ep.rpartition(":")
    return host, int(p)


def af_of(addr):
    return 6 if ":" in addr else 4


def inet_ntop4(b):
    return socket.inet_ntop(socket.AF_INET, b)


def inet_ntop6(b):
    return socket.inet_ntop(socket.AF_INET6, b)


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def checksum16(data):
    """Standard Internet checksum over a byte string."""
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def pim_checksum_v4(msg):
    return checksum16(msg)


def pim_checksum_v6(src_b, dst_b, msg):
    """IPv6 requires the RFC 2460 pseudo-header with Next Header = 103."""
    ph = src_b + dst_b + struct.pack("!IBBBB", len(msg), 0, 0, 0, IPPROTO_PIM)
    return checksum16(ph + msg)


def is_ssm_group(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version == 4:
        return ip in SSM_V4_NET
    return addr.lower().startswith(SSM_V6_PREFIX)


def is_embedded_rp_group(addr):
    if ":" not in addr:
        return False
    return addr.lower().startswith(EMBEDDED_RP_PREFIX)


def embedded_rp_address(group):
    """RFC 3956: ff70::/12 group carries the RP's interface ID in bits 32..39
    (RIID) and the RP prefix in the following plen bits.

       | 8 | 4  | 4  | 4  |  4  |  8  |  64   |  32   |
       |ff |flgs|scop|rsvd|RIID |plen |prefix | gid   |

    Returns the RP address string, or None if the fields are not usable.
    """
    try:
        b = ipaddress.ip_address(group).packed
    except ValueError:
        return None
    if len(b) != 16:
        return None
    riid = b[2] & 0x0F
    plen = b[3]
    if plen == 0 or plen > 64:
        return None
    prefix = b[4:12]                       # 64 bits of RP prefix
    rp = bytearray(16)
    # keep the top plen bits of the prefix, zero the rest
    full = int.from_bytes(prefix, "big")
    mask = ((1 << plen) - 1) << (64 - plen)
    rp[0:8] = (full & mask).to_bytes(8, "big")
    rp[15] = riid
    return inet_ntop6(bytes(rp))


# --------------------------------------------------------------------------
# PIM encoded-address parsing (RFC 7761 s4.9.1)
# --------------------------------------------------------------------------

def _addr_from_afi(afi, buf, off):
    if afi == PIM_AFI_IPV4:
        if off + 4 > len(buf):
            raise ParseError("short IPv4 encoded address")
        return inet_ntop4(buf[off:off + 4]), off + 4
    if afi == PIM_AFI_IPV6:
        if off + 16 > len(buf):
            raise ParseError("short IPv6 encoded address")
        return inet_ntop6(buf[off:off + 16]), off + 16
    raise ParseError("unsupported PIM address family %d" % afi)


def parse_encoded_unicast(buf, off):
    if off + 2 > len(buf):
        raise ParseError("short encoded-unicast header")
    afi = buf[off]
    enc = buf[off + 1]
    if enc != 0:
        raise ParseError("non-native encoding type %d" % enc)
    addr, off = _addr_from_afi(afi, buf, off + 2)
    return {"afi": afi, "addr": addr}, off


def parse_encoded_group(buf, off):
    if off + 4 > len(buf):
        raise ParseError("short encoded-group header")
    afi = buf[off]
    enc = buf[off + 1]
    flags = buf[off + 2]
    masklen = buf[off + 3]
    if enc != 0:
        raise ParseError("non-native encoding type %d" % enc)
    addr, off = _addr_from_afi(afi, buf, off + 4)
    return {"afi": afi, "addr": addr, "masklen": masklen,
            "bidir": bool(flags & 0x80), "zone": bool(flags & 0x01)}, off


def parse_encoded_source(buf, off):
    if off + 4 > len(buf):
        raise ParseError("short encoded-source header")
    afi = buf[off]
    enc = buf[off + 1]
    flags = buf[off + 2]
    masklen = buf[off + 3]
    if enc != 0:
        raise ParseError("non-native encoding type %d" % enc)
    addr, off = _addr_from_afi(afi, buf, off + 4)
    return {"afi": afi, "addr": addr, "masklen": masklen,
            "sparse": bool(flags & 0x04),
            "wildcard": bool(flags & 0x02),
            "rpt": bool(flags & 0x01)}, off


# --------------------------------------------------------------------------
# PIM message parsing
# --------------------------------------------------------------------------

def parse_pim_header(buf):
    if len(buf) < 4:
        raise ParseError("PIM message shorter than header")
    ver = (buf[0] >> 4) & 0x0F
    typ = buf[0] & 0x0F
    flags = buf[1]
    csum = struct.unpack("!H", buf[2:4])[0]
    return {"version": ver, "type": typ, "flags": flags, "checksum": csum}


def parse_hello(buf):
    """Hello options. Tolerant: stops cleanly at the first unusable TLV."""
    out = {"options": {}, "unknown_options": [], "option_order": []}
    off = 4
    while off + 4 <= len(buf):
        otype, olen = struct.unpack("!HH", buf[off:off + 4])
        off += 4
        if off + olen > len(buf):
            raise ParseError("Hello option %d overruns message" % otype)
        val = buf[off:off + olen]
        off += olen
        out["option_order"].append(otype)
        if otype == HELLO_HOLDTIME and olen == 2:
            out["options"]["holdtime"] = struct.unpack("!H", val)[0]
        elif otype == HELLO_LAN_PRUNE_DELAY and olen == 4:
            raw = struct.unpack("!H", val[0:2])[0]
            out["options"]["lan_prune_delay"] = raw & 0x7FFF
            out["options"]["t_bit"] = bool(raw & 0x8000)
            out["options"]["override_interval"] = struct.unpack("!H", val[2:4])[0]
        elif otype == HELLO_DR_PRIORITY and olen == 4:
            out["options"]["dr_priority"] = struct.unpack("!I", val)[0]
        elif otype == HELLO_GENERATION_ID and olen == 4:
            out["options"]["generation_id"] = struct.unpack("!I", val)[0]
        elif otype == HELLO_STATE_REFRESH and olen >= 4:
            out["options"]["state_refresh_capable"] = True
            out["options"]["state_refresh_interval"] = val[1]
        elif otype == HELLO_BIDIR_CAPABLE:
            out["options"]["bidir_capable"] = True
        elif otype in (HELLO_ADDRESS_LIST, HELLO_ADDRESS_LIST_OLD):
            addrs = []
            o = 0
            while o < len(val):
                try:
                    a, o = parse_encoded_unicast(val, o)
                except ParseError:
                    break
                addrs.append(a["addr"])
            out["options"]["address_list"] = addrs
        else:
            out["unknown_options"].append((otype, olen))
    return out


def parse_register(buf):
    if len(buf) < 8:
        raise ParseError("Register shorter than 8 bytes")
    flags = struct.unpack("!I", buf[4:8])[0]
    out = {"border": bool(flags & 0x80000000),
           "null_register": bool(flags & 0x40000000),
           "inner_src": None, "inner_group": None, "inner_af": None}
    inner = buf[8:]
    if len(inner) >= 1:
        v = (inner[0] >> 4) & 0x0F
        if v == 4 and len(inner) >= 20:
            out["inner_af"] = 4
            out["inner_src"] = inet_ntop4(inner[12:16])
            out["inner_group"] = inet_ntop4(inner[16:20])
        elif v == 6 and len(inner) >= 40:
            out["inner_af"] = 6
            out["inner_src"] = inet_ntop6(inner[8:24])
            out["inner_group"] = inet_ntop6(inner[24:40])
    return out


def parse_register_stop(buf):
    grp, off = parse_encoded_group(buf, 4)
    src, off = parse_encoded_unicast(buf, off)
    return {"group": grp, "source": src}


def _parse_jp_attributes(buf, off, end):
    """RFC 5384 source-address attribute TLVs, which may trail a source entry.
    Each: F|E|Attr Type (1 byte), Length (1 byte), Value."""
    attrs = []
    while off < end:
        if off + 2 > end:
            raise ParseError("Join/Prune attribute truncated")
        b0 = buf[off]
        atype = b0 & 0x3F
        end_bit = bool(b0 & 0x40)
        alen = buf[off + 1]
        off += 2
        if off + alen > end:
            raise ParseError("Join/Prune attribute value overruns")
        attrs.append({"type": atype, "value": buf[off:off + alen]})
        off += alen
        if end_bit:
            break
    return attrs, off


def parse_join_prune(buf):
    up, off = parse_encoded_unicast(buf, 4)
    if off + 4 > len(buf):
        raise ParseError("Join/Prune header truncated")
    num_groups = buf[off + 1]
    holdtime = struct.unpack("!H", buf[off + 2:off + 4])[0]
    off += 4
    groups = []
    for _ in range(num_groups):
        grp, off = parse_encoded_group(buf, off)
        if off + 4 > len(buf):
            raise ParseError("Join/Prune group counts truncated")
        njoin, nprune = struct.unpack("!HH", buf[off:off + 4])
        off += 4
        if njoin > 4096 or nprune > 4096:
            raise ParseError("implausible join/prune counts")
        joins, prunes = [], []
        for _j in range(njoin):
            s, off = parse_encoded_source(buf, off)
            joins.append(s)
        for _p in range(nprune):
            s, off = parse_encoded_source(buf, off)
            prunes.append(s)
        groups.append({"group": grp, "joins": joins, "prunes": prunes})
    attrs = []
    if off < len(buf):
        try:
            attrs, off = _parse_jp_attributes(buf, off, len(buf))
        except ParseError:
            attrs = []
    return {"upstream": up, "holdtime": holdtime, "groups": groups,
            "num_groups": num_groups, "attributes": attrs}


def parse_assert(buf):
    grp, off = parse_encoded_group(buf, 4)
    src, off = parse_encoded_unicast(buf, off)
    if off + 8 > len(buf):
        raise ParseError("Assert metrics truncated")
    pref_raw, metric = struct.unpack("!II", buf[off:off + 8])
    return {"group": grp, "source": src,
            "rpt": bool(pref_raw & 0x80000000),
            "metric_pref": pref_raw & 0x7FFFFFFF,
            "metric": metric}


def parse_bootstrap(buf):
    if len(buf) < 8:
        raise ParseError("Bootstrap truncated")
    frag_tag = struct.unpack("!H", buf[4:6])[0]
    hash_mask_len = buf[6]
    bsr_priority = buf[7]
    bsr, off = parse_encoded_unicast(buf, 8)
    group_sets = []
    while off < len(buf):
        grp, off = parse_encoded_group(buf, off)
        if off + 4 > len(buf):
            raise ParseError("Bootstrap group set truncated")
        rp_count = buf[off]
        frag_rp_count = buf[off + 1]
        off += 4
        if frag_rp_count > 255:
            raise ParseError("implausible fragment RP count")
        rps = []
        for _ in range(frag_rp_count):
            rp, off = parse_encoded_unicast(buf, off)
            if off + 4 > len(buf):
                raise ParseError("Bootstrap RP record truncated")
            holdtime = struct.unpack("!H", buf[off:off + 2])[0]
            priority = buf[off + 2]
            off += 4
            rps.append({"addr": rp["addr"], "holdtime": holdtime,
                        "priority": priority})
        group_sets.append({"group": grp, "rp_count": rp_count,
                           "frag_rp_count": frag_rp_count, "rps": rps})
    return {"fragment_tag": frag_tag, "hash_mask_len": hash_mask_len,
            "bsr_priority": bsr_priority, "bsr": bsr,
            "group_sets": group_sets}


def parse_cand_rp_adv(buf):
    if len(buf) < 8:
        raise ParseError("Candidate-RP-Adv truncated")
    prefix_cnt = buf[4]
    priority = buf[5]
    holdtime = struct.unpack("!H", buf[6:8])[0]
    rp, off = parse_encoded_unicast(buf, 8)
    groups = []
    for _ in range(prefix_cnt):
        if off >= len(buf):
            break
        g, off = parse_encoded_group(buf, off)
        groups.append(g)
    return {"prefix_count": prefix_cnt, "priority": priority,
            "holdtime": holdtime, "rp": rp, "groups": groups}


def parse_state_refresh(buf):
    grp, off = parse_encoded_group(buf, 4)
    src, off = parse_encoded_unicast(buf, off)
    orig, off = parse_encoded_unicast(buf, off)
    if off + 12 > len(buf):
        raise ParseError("State-Refresh fields truncated")
    pref_raw, metric = struct.unpack("!II", buf[off:off + 8])
    off += 8
    masklen = buf[off]
    ttl = buf[off + 1]
    flags = buf[off + 2]
    interval = buf[off + 3]
    return {"group": grp, "source": src, "originator": orig,
            "rpt": bool(pref_raw & 0x80000000),
            "metric_pref": pref_raw & 0x7FFFFFFF, "metric": metric,
            "masklen": masklen, "ttl": ttl, "interval": interval,
            "prune_indicator": bool(flags & 0x80),
            "prune_now": bool(flags & 0x40),
            "assert_override": bool(flags & 0x20)}


def parse_df_election(buf):
    """RFC 5015 s3.3: the DF subtype occupies the HIGH nibble of the PIM
    common header's second octet -- the field other message types leave
    reserved -- NOT the first octet of the body. Reading it from the body
    makes every subtype decode as 0, which silently disables every
    subtype-dependent rule. Confirmed against Wireshark's dissector."""
    if len(buf) < 4:
        raise ParseError("DF-Election truncated")
    subtype = (buf[1] >> 4) & 0x0F
    rp, off = parse_encoded_unicast(buf, 4)
    if off + 8 > len(buf):
        raise ParseError("DF-Election sender metrics truncated")
    pref, metric = struct.unpack("!II", buf[off:off + 8])
    off += 8
    out = {"subtype": subtype, "rp": rp, "metric_pref": pref, "metric": metric,
           "target": None, "target_metric_pref": None, "target_metric": None}
    if subtype in (DF_BACKOFF, DF_PASS):
        tgt, off = parse_encoded_unicast(buf, off)
        if off + 8 > len(buf):
            raise ParseError("DF-Election target metrics truncated")
        tp, tm = struct.unpack("!II", buf[off:off + 8])
        out["target"] = tgt
        out["target_metric_pref"] = tp
        out["target_metric"] = tm
    return out


PIM_PARSERS = {
    PIM_HELLO: parse_hello,
    PIM_REGISTER: parse_register,
    PIM_REGISTER_STOP: parse_register_stop,
    PIM_JOIN_PRUNE: parse_join_prune,
    PIM_BOOTSTRAP: parse_bootstrap,
    PIM_ASSERT: parse_assert,
    PIM_GRAFT: parse_join_prune,
    PIM_GRAFT_ACK: parse_join_prune,
    PIM_CAND_RP_ADV: parse_cand_rp_adv,
    PIM_STATE_REFRESH: parse_state_refresh,
    PIM_DF_ELECTION: parse_df_election,
}


# --------------------------------------------------------------------------
# Auto-RP (Cisco, UDP/496) -- IPv4 only
# --------------------------------------------------------------------------

def parse_autorp(buf):
    if len(buf) < 8:
        raise ParseError("Auto-RP shorter than header")
    version = (buf[0] >> 4) & 0x0F
    ptype = buf[0] & 0x0F
    rp_count = buf[1]
    holdtime = struct.unpack("!H", buf[2:4])[0]
    off = 8
    rps = []
    for _ in range(rp_count):
        if off + 6 > len(buf):
            raise ParseError("Auto-RP RP record truncated")
        rp_addr = inet_ntop4(buf[off:off + 4])
        pim_ver = buf[off + 4]
        gcount = buf[off + 5]
        off += 6
        groups = []
        for _g in range(gcount):
            # Cisco layout per group prefix:
            #   1 byte sign (bit 0 set => negative/deny prefix)
            #   1 byte mask length
            #   4 byte group address
            if off + 6 > len(buf):
                raise ParseError("Auto-RP group record truncated")
            negative = bool(buf[off] & 0x01)
            masklen = buf[off + 1]
            gaddr = inet_ntop4(buf[off + 2:off + 6])
            off += 6
            groups.append({"group": gaddr, "masklen": masklen,
                           "negative": negative})
        rps.append({"addr": rp_addr, "pim_version": pim_ver,
                    "groups": groups})
    return {"version": version, "type": ptype, "holdtime": holdtime,
            "rp_count": rp_count, "rps": rps}


# --------------------------------------------------------------------------
# MSDP (RFC 3618, TCP/639) -- IPv4 only
# --------------------------------------------------------------------------

def parse_msdp_tlv(buf, off):
    """Parse one TLV at off. Returns (tlv, new_off) or (None, off) if the
    buffer does not yet hold a complete TLV."""
    if off + 3 > len(buf):
        return None, off
    ttype = buf[off]
    tlen = struct.unpack("!H", buf[off + 1:off + 3])[0]
    if tlen < 3:
        raise ParseError("MSDP TLV length %d below minimum" % tlen)
    if off + tlen > len(buf):
        return None, off
    body = buf[off + 3:off + tlen]
    tlv = {"type": ttype, "length": tlen, "name": MSDP_TLV_NAME.get(ttype, "Unknown")}
    if ttype == MSDP_SA:
        if len(body) < 5:
            raise ParseError("MSDP SA shorter than fixed fields")
        entry_count = body[0]
        rp = inet_ntop4(body[1:5])
        entries = []
        o = 5
        for _ in range(entry_count):
            if o + 12 > len(body):
                break
            sprefix_len = body[o + 3]
            group = inet_ntop4(body[o + 4:o + 8])
            source = inet_ntop4(body[o + 8:o + 12])
            entries.append({"group": group, "source": source,
                            "sprefix_len": sprefix_len})
            o += 12
        tlv.update({"entry_count": entry_count, "rp": rp, "entries": entries,
                    "entries_parsed": len(entries),
                    "encapsulated_len": max(0, len(body) - o)})
    elif ttype in (MSDP_SA_REQUEST, MSDP_SA_RESPONSE):
        tlv["group"] = inet_ntop4(body[1:5]) if len(body) >= 5 else None
    return tlv, off + tlen


class MsdpStream:
    """Byte-oriented reassembler for one direction of one MSDP TCP session.

    Anchors on the first byte that can begin a valid TLV, so a mid-stream
    attach does not emit garbage (suite LESSON O)."""

    MAX_BUF = 256 * 1024

    def __init__(self):
        self.buf = bytearray()
        self.anchored = False
        self.dropped = 0

    def _try_anchor(self):
        # Scan for a plausible TLV head: known type and sane length.
        for i in range(0, min(len(self.buf), 4096)):
            t = self.buf[i]
            if t not in MSDP_TLV_NAME:
                continue
            if i + 3 > len(self.buf):
                break
            ln = struct.unpack("!H", self.buf[i + 1:i + 3])[0]
            if 3 <= ln <= 9192:
                if i:
                    self.dropped += i
                    del self.buf[:i]
                self.anchored = True
                return True
        return False

    def feed(self, data):
        """Returns a list of complete TLVs, plus a list of parse errors."""
        self.buf.extend(data)
        if len(self.buf) > self.MAX_BUF:
            del self.buf[:len(self.buf) - self.MAX_BUF]
            self.anchored = False
        tlvs, errors = [], []
        if not self.anchored and not self._try_anchor():
            return tlvs, errors
        off = 0
        while True:
            try:
                tlv, noff = parse_msdp_tlv(bytes(self.buf), off)
            except ParseError as e:
                errors.append(str(e))
                self.anchored = False
                off = len(self.buf)
                break
            if tlv is None:
                break
            tlvs.append(tlv)
            off = noff
        if off:
            del self.buf[:off]
        return tlvs, errors


# --------------------------------------------------------------------------
# L2/L3 decode
# --------------------------------------------------------------------------

def parse_ethernet(buf):
    if len(buf) < 14:
        raise ParseError("frame shorter than Ethernet header")
    dst = buf[0:6]
    src = buf[6:12]
    off = 12
    vlans = []
    etype = struct.unpack("!H", buf[off:off + 2])[0]
    off += 2
    while etype in VLAN_TPIDS:
        if off + 4 > len(buf):
            raise ParseError("truncated VLAN tag")
        tci = struct.unpack("!H", buf[off:off + 2])[0]
        vlans.append(tci & 0x0FFF)
        etype = struct.unpack("!H", buf[off + 2:off + 4])[0]
        off += 4
    return {"dst_mac": mac_str(dst), "src_mac": mac_str(src),
            "ethertype": etype, "vlans": vlans, "payload_off": off}


def parse_ipv4(buf, off):
    if off + 20 > len(buf):
        raise ParseError("truncated IPv4 header")
    ihl = (buf[off] & 0x0F) * 4
    if ihl < 20 or off + ihl > len(buf):
        raise ParseError("bad IPv4 IHL")
    total_len = struct.unpack("!H", buf[off + 2:off + 4])[0]
    proto = buf[off + 9]
    ttl = buf[off + 8]
    src = inet_ntop4(buf[off + 12:off + 16])
    dst = inet_ntop4(buf[off + 16:off + 20])
    end = off + total_len if 20 <= total_len <= len(buf) - off else len(buf)
    return {"af": 4, "src": src, "dst": dst, "proto": proto, "ttl": ttl,
            "payload_off": off + ihl, "payload_end": end,
            "src_b": buf[off + 12:off + 16], "dst_b": buf[off + 16:off + 20],
            "ah": None}


def parse_ipv6(buf, off):
    """Walks the extension-header chain. AH is recorded, not skipped blindly:
    its presence and SPI are the RFC 5796 posture signal."""
    if off + 40 > len(buf):
        raise ParseError("truncated IPv6 header")
    plen = struct.unpack("!H", buf[off + 4:off + 6])[0]
    nh = buf[off + 6]
    hlim = buf[off + 7]
    src = inet_ntop6(buf[off + 8:off + 24])
    dst = inet_ntop6(buf[off + 24:off + 40])
    src_b = buf[off + 8:off + 24]
    dst_b = buf[off + 24:off + 40]
    end = off + 40 + plen if plen and off + 40 + plen <= len(buf) else len(buf)
    p = off + 40
    ah = None
    chain = []
    hops = 0
    while nh in IPV6_EH or nh == IPPROTO_AH:
        hops += 1
        if hops > 16:
            raise ParseError("IPv6 extension-header chain too long")
        if p + 2 > len(buf):
            raise ParseError("truncated IPv6 extension header")
        chain.append(nh)
        if nh == IPPROTO_AH:
            ahlen = (buf[p + 1] + 2) * 4
            if p + ahlen > len(buf) or ahlen < 12:
                raise ParseError("truncated AH header")
            spi = struct.unpack("!I", buf[p + 4:p + 8])[0]
            seq = struct.unpack("!I", buf[p + 8:p + 12])[0]
            ah = {"spi": spi, "seq": seq, "icv_len": ahlen - 12}
            nxt = buf[p]
            p += ahlen
            nh = nxt
            continue
        if nh == 44:                       # Fragment header is fixed 8 bytes
            ext = 8
        else:
            ext = (buf[p + 1] + 1) * 8
        if p + ext > len(buf):
            raise ParseError("truncated IPv6 extension header")
        nxt = buf[p]
        p += ext
        nh = nxt
        if nh == IPV6_NO_NEXT:
            break
    return {"af": 6, "src": src, "dst": dst, "proto": nh, "ttl": hlim,
            "payload_off": p, "payload_end": end,
            "src_b": src_b, "dst_b": dst_b, "ah": ah, "eh_chain": chain}


def parse_tcp(buf, off, end):
    if off + 20 > len(buf):
        raise ParseError("truncated TCP header")
    sport, dport = struct.unpack("!HH", buf[off:off + 4])
    seq = struct.unpack("!I", buf[off + 4:off + 8])[0]
    doff = ((buf[off + 12] >> 4) & 0x0F) * 4
    flags = buf[off + 13]
    if doff < 20 or off + doff > len(buf):
        raise ParseError("bad TCP data offset")
    md5 = False
    o = off + 20
    optend = off + doff
    while o < optend:
        kind = buf[o]
        if kind == 0:
            break
        if kind == 1:
            o += 1
            continue
        if o + 1 >= optend:
            break
        olen = buf[o + 1]
        if olen < 2 or o + olen > optend:
            break
        if kind == 19:
            md5 = True
        o += olen
    body_end = min(end, len(buf))
    return {"sport": sport, "dport": dport, "seq": seq, "flags": flags,
            "syn": bool(flags & 0x02), "fin": bool(flags & 0x01),
            "rst": bool(flags & 0x04), "md5": md5,
            "payload_off": off + doff, "payload_end": body_end}


def parse_udp(buf, off, end):
    if off + 8 > len(buf):
        raise ParseError("truncated UDP header")
    sport, dport, ulen = struct.unpack("!HHH", buf[off:off + 6])
    pend = off + ulen if 8 <= ulen <= end - off else end
    return {"sport": sport, "dport": dport,
            "payload_off": off + 8, "payload_end": min(pend, len(buf))}


# --------------------------------------------------------------------------
# Detector engine
# --------------------------------------------------------------------------

DEFAULTS = {
    "learn_seconds": 900,
    "hello_rate_window": 10.0,
    "hello_rate_max": 12,
    "prune_rate_window": 10.0,
    "prune_rate_max": 40,
    "graft_rate_window": 10.0,
    "graft_rate_max": 20,
    "df_offer_window": 10.0,
    "df_offer_max": 12,
    "assert_churn_window": 30.0,
    "assert_churn_max": 6,
    "sa_rate_window": 30.0,
    "sa_rate_max": 500,
    "jp_group_max": 512,
    "jp_source_max": 1024,
    "holdtime_flap_threshold": 3,
    "state_refresh_interval_max": 100,
    "max_findings_per_code": 200,
}


class RateWindow:
    def __init__(self, window):
        self.window = window
        self.events = defaultdict(deque)

    def hit(self, key, ts):
        dq = self.events[key]
        dq.append(ts)
        cutoff = ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(self.events) > 4096:
            # bounded: drop the least recently touched key
            oldest = min(self.events, key=lambda k: self.events[k][-1]
                         if self.events[k] else 0)
            if oldest != key:
                del self.events[oldest]
        return len(dq)


class PimWatch:
    def __init__(self, config=None, now=None, armed=False):
        self.cfg = dict(DEFAULTS)
        if config:
            self.cfg.update(config)
        self.findings = []
        self.code_counts = defaultdict(int)
        self.suppressed = defaultdict(int)
        self.stats = defaultdict(int)
        self._clock = now or time.time
        self.started = self._clock()
        self.armed = armed

        # -------- learned baseline --------
        self.neighbors = {}          # (af, addr) -> record
        self.neighbor_macs = defaultdict(set)
        self.dr = {}                 # (af, vlan) -> (priority, addr)
        self.rp_set = {}             # (af, addr) -> record
        self.bsr = {}                # af -> record
        self.autorp_agents = {}      # addr -> record
        self.group_rp = {}           # (af, group, masklen) -> rp addr
        self.bsr_rp_sets = {}        # (af, group, masklen) -> frozenset of RPs
        self.groups_seen = set()
        self.modes = defaultdict(set)   # (af, vlan) -> {"sm","dm","bidir"}
        self.df_winner = {}          # (af, rp) -> addr
        self.assert_winner = {}      # (af, s, g) -> (pref, metric, addr)
        self.ssm_sources = defaultdict(set)   # (af, group) -> {sources}
        self.ah_seen = {}            # (af, addr) -> spi
        self.ah_links = set()
        self.nonah_links = set()
        self.msdp_peers = set()
        self.msdp_streams = {}       # (src,sport,dst,dport) -> MsdpStream
        self.msdp_sessions = {}      # frozenset endpoints -> record
        self.msdp_group_rp = {}      # group -> rp
        self.anycast_rp_pim = set()
        self.anycast_rp_msdp = set()
        self.register_rps = set()
        self.graft_state = set()     # (af, s, g) pruned, for Graft-Ack pairing
        self.rpt_joined = set()      # (af, group) where (*,G) join was seen

        # -------- rate windows --------
        self.r_hello = RateWindow(self.cfg["hello_rate_window"])
        self.r_prune = RateWindow(self.cfg["prune_rate_window"])
        self.r_graft = RateWindow(self.cfg["graft_rate_window"])
        self.r_offer = RateWindow(self.cfg["df_offer_window"])
        self.r_assert = RateWindow(self.cfg["assert_churn_window"])
        self.r_sa = RateWindow(self.cfg["sa_rate_window"])

    # ---------------- arming ----------------

    # Rate-based detectors are all attack-class, and every one of them is
    # gated on self.armed: during the learning window the rate windows fill
    # but raise nothing, because a static default threshold applied to an
    # unmeasured fabric is a false-positive generator. The sealed lab asserts
    # that no attack-class finding appears before arming.

    def maybe_arm(self, ts):
        if not self.armed and (ts - self.started) >= self.cfg["learn_seconds"]:
            self.armed = True
        return self.armed

    def arm(self):
        self.armed = True

    # ---------------- finding emission ----------------

    def finding(self, code, ts, detail, af=None, severity=None):
        if code not in FINDINGS:
            raise KeyError("undeclared finding code %s" % code)
        if self.code_counts[code] >= self.cfg["max_findings_per_code"]:
            self.suppressed[code] += 1
            return None
        meta = FINDINGS[code]
        rec = {
            "module": MODULE,
            "version": VERSION,
            "code": code,
            "severity": severity or meta["severity"],
            "class": meta["class"],
            "proto": CODE_PROTO[code],
            "title": meta["title"],
            "ts": round(ts, 6),
            "af": af,
            "armed": self.armed,
            "detail": detail,
        }
        self.findings.append(rec)
        self.code_counts[code] += 1
        return rec

    # ---------------- top-level frame entry ----------------

    def handle_frame(self, buf, ts=None):
        """Entry point for every tier. Never raises."""
        ts = self._clock() if ts is None else ts
        self.stats["frames"] += 1
        try:
            self._handle_frame_inner(buf, ts)
        except ParseError as e:
            self.stats["parse_errors"] += 1
            self.stats["last_parse_error"] = str(e)
        except Exception as e:                     # noqa: BLE001
            self.stats["internal_errors"] += 1
            self.stats["last_internal_error"] = "%s: %s" % (type(e).__name__, e)

    def _handle_frame_inner(self, buf, ts):
        self.maybe_arm(ts)
        eth = parse_ethernet(buf)
        vlan = eth["vlans"][-1] if eth["vlans"] else 0
        if eth["ethertype"] == ETH_P_IPV4:
            l3 = parse_ipv4(buf, eth["payload_off"])
        elif eth["ethertype"] == ETH_P_IPV6:
            l3 = parse_ipv6(buf, eth["payload_off"])
        else:
            return
        ctx = {"eth": eth, "l3": l3, "vlan": vlan, "ts": ts,
               "af": l3["af"], "src": l3["src"], "dst": l3["dst"]}

        proto = l3["proto"]
        if proto == IPPROTO_PIM:
            self.stats["pim_packets"] += 1
            self._handle_pim(buf, ctx)
        elif proto == socket.IPPROTO_UDP:
            udp = parse_udp(buf, l3["payload_off"], l3["payload_end"])
            # Auto-RP is IPv4 only by protocol definition.
            if l3["af"] == 4 and udp["dport"] == AUTORP_PORT:
                self.stats["autorp_packets"] += 1
                self._handle_autorp(buf[udp["payload_off"]:udp["payload_end"]], ctx)
        elif proto == socket.IPPROTO_TCP:
            tcp = parse_tcp(buf, l3["payload_off"], l3["payload_end"])
            if l3["af"] == 4 and MSDP_PORT in (tcp["sport"], tcp["dport"]):
                self.stats["msdp_packets"] += 1
                self._handle_msdp(buf, ctx, tcp)
        elif proto == IPPROTO_ESP:
            # Encrypted. Nothing to read; recorded only as link posture.
            self.stats["esp_packets"] += 1

    # ---------------- PIM ----------------

    def _handle_pim(self, buf, ctx):
        l3 = ctx["l3"]
        msg = buf[l3["payload_off"]:l3["payload_end"]]
        if not msg:
            raise ParseError("empty PIM payload")
        hdr = parse_pim_header(msg)
        ts, af, src = ctx["ts"], ctx["af"], ctx["src"]
        ctx["pim"] = hdr

        if hdr["version"] != 2:
            self.finding("PMW-002", ts,
                         {"src": src, "version": hdr["version"],
                          "note": "pimwatch decodes PIMv2 only; "
                                  "PIMv1 is a different wire format"}, af=af)
            return

        # Checksum. Register messages are checksummed over the first 8 bytes
        # by several implementations, so accept either reading there.
        self._check_checksum(msg, hdr, ctx)

        typ = hdr["type"]
        if typ not in PIM_TYPE_NAME:
            self.finding("PMW-009", ts, {"src": src, "type": typ}, af=af)
            return

        # Link-local hygiene: these types are sent to the all-PIM-routers
        # group with TTL/hop-limit 1.
        link_local_types = (PIM_HELLO, PIM_JOIN_PRUNE, PIM_ASSERT, PIM_GRAFT,
                            PIM_GRAFT_ACK, PIM_STATE_REFRESH, PIM_DF_ELECTION)
        if typ in link_local_types:
            expect = PIM_ALL_ROUTERS_V4 if af == 4 else PIM_ALL_ROUTERS_V6
            if ctx["dst"].lower() != expect:
                self.finding("PMW-010", ts,
                             {"src": src, "dst": ctx["dst"],
                              "expected": expect,
                              "type": PIM_TYPE_NAME[typ]}, af=af)
            if l3["ttl"] != 1:
                self.finding("PMW-007", ts,
                             {"src": src, "ttl": l3["ttl"],
                              "type": PIM_TYPE_NAME[typ],
                              "note": "link-local PIM should use TTL/hop-limit 1; "
                                      "a larger value can indicate an off-link "
                                      "injector"}, af=af)

        self._track_ah(ctx)

        parser = PIM_PARSERS.get(typ)
        if parser is None:
            return
        body = parser(msg)

        if typ == PIM_HELLO:
            self._on_hello(body, ctx)
        elif typ == PIM_REGISTER:
            self._on_register(body, ctx)
        elif typ == PIM_REGISTER_STOP:
            self._on_register_stop(body, ctx)
        elif typ in (PIM_JOIN_PRUNE, PIM_GRAFT, PIM_GRAFT_ACK):
            self._on_join_prune(body, ctx, typ)
        elif typ == PIM_BOOTSTRAP:
            self._on_bootstrap(body, ctx)
        elif typ == PIM_ASSERT:
            self._on_assert(body, ctx)
        elif typ == PIM_CAND_RP_ADV:
            self._on_cand_rp(body, ctx)
        elif typ == PIM_STATE_REFRESH:
            self._on_state_refresh(body, ctx)
        elif typ == PIM_DF_ELECTION:
            self._on_df_election(body, ctx)

    def _check_checksum(self, msg, hdr, ctx):
        l3, ts, af, src = ctx["l3"], ctx["ts"], ctx["af"], ctx["src"]
        zeroed = bytearray(msg)
        zeroed[2:4] = b"\x00\x00"
        if af == 4:
            calc = pim_checksum_v4(bytes(zeroed))
            ok = (calc == hdr["checksum"])
            if not ok and hdr["type"] == PIM_REGISTER and len(msg) >= 8:
                ok = (pim_checksum_v4(bytes(zeroed[:8])) == hdr["checksum"])
        else:
            calc = pim_checksum_v6(l3["src_b"], l3["dst_b"], bytes(zeroed))
            ok = (calc == hdr["checksum"])
            if not ok and hdr["type"] == PIM_REGISTER and len(msg) >= 8:
                ok = (pim_checksum_v6(l3["src_b"], l3["dst_b"],
                                      bytes(zeroed[:8])) == hdr["checksum"])
        if not ok:
            self.finding("PMW-003", ts,
                         {"src": src, "type": PIM_TYPE_NAME.get(hdr["type"]),
                          "observed": hdr["checksum"], "computed": calc},
                         af=af)
        return ok

    def _track_ah(self, ctx):
        ts, af, src, vlan = ctx["ts"], ctx["af"], ctx["src"], ctx["vlan"]
        ah = ctx["l3"].get("ah")
        link = (af, vlan)
        key = (af, src)
        if ah:
            self.ah_links.add(link)
            prev = self.ah_seen.get(key)
            if prev is None:
                self.ah_seen[key] = ah["spi"]
                self.finding("PMW-020", ts,
                             {"src": src, "spi": ah["spi"],
                              "note": "RFC 5796 IPsec AH protection present"},
                             af=af)
            elif prev != ah["spi"]:
                self.ah_seen[key] = ah["spi"]
                self.finding("PMW-023", ts,
                             {"src": src, "old_spi": prev, "new_spi": ah["spi"]},
                             af=af)
        else:
            self.nonah_links.add(link)
            if key in self.ah_seen:
                spi = self.ah_seen.pop(key)
                self.finding("PMW-021", ts,
                             {"src": src, "previous_spi": spi,
                              "note": "this speaker was previously AH-protected "
                                      "and is now sending unauthenticated PIM"},
                             af=af)
            if link in self.ah_links:
                self.finding("PMW-022", ts,
                             {"link_af": af, "vlan": vlan, "src": src},
                             af=af)

    # ---------------- Hello ----------------

    def _on_hello(self, body, ctx):
        ts, af, src, vlan = ctx["ts"], ctx["af"], ctx["src"], ctx["vlan"]
        opts = body["options"]
        key = (af, src)
        new = key not in self.neighbors
        rec = self.neighbors.setdefault(key, {
            "first_seen": ts, "last_seen": ts, "gen_id": None,
            "dr_priority": None, "holdtime": None, "bidir": False,
            "state_refresh": False, "t_bit": None, "vlan": vlan,
        })
        rec["last_seen"] = ts

        mac = ctx["eth"]["src_mac"]
        macs = self.neighbor_macs[key]
        if mac not in macs:
            macs.add(mac)
            if len(macs) > 1:
                self.finding("PMW-047", ts,
                             {"neighbor": src, "macs": sorted(macs),
                              "note": "one PIM router address advertised from "
                                      "two L2 addresses"}, af=af)

        if new:
            code = "PMW-040" if self.armed else "PMW-001"
            self.finding(code, ts,
                         {"neighbor": src, "vlan": vlan,
                          "mac": mac}, af=af)

        if "holdtime" not in opts:
            self.finding("PMW-006", ts, {"neighbor": src}, af=af)
        else:
            ht = opts["holdtime"]
            if ht == 0:
                self.finding("PMW-044", ts,
                             {"neighbor": src,
                              "note": "holdtime 0 tears down the adjacency "
                                      "immediately"}, af=af)
            elif 0 < ht <= self.cfg["holdtime_flap_threshold"]:
                self.finding("PMW-050", ts,
                             {"neighbor": src, "holdtime": ht,
                              "threshold": self.cfg["holdtime_flap_threshold"]},
                             af=af)
            if rec["holdtime"] is not None and rec["holdtime"] != ht and ht == 0:
                pass
            rec["holdtime"] = ht

        gid = opts.get("generation_id")
        if gid is not None:
            if rec["gen_id"] is not None and rec["gen_id"] != gid and self.armed:
                self.finding("PMW-041", ts,
                             {"neighbor": src, "old": rec["gen_id"],
                              "new": gid,
                              "note": "a Generation ID change signals a restart; "
                                      "repeated changes without a restart "
                                      "indicate spoofed Hellos"}, af=af)
            rec["gen_id"] = gid

        if "t_bit" in opts:
            if rec["t_bit"] is not None and rec["t_bit"] != opts["t_bit"]:
                self.finding("PMW-046", ts,
                             {"neighbor": src, "t_bit": opts["t_bit"],
                              "lan_prune_delay": opts.get("lan_prune_delay")},
                             af=af)
            rec["t_bit"] = opts["t_bit"]

        if opts.get("bidir_capable"):
            if not rec["bidir"]:
                rec["bidir"] = True
                code = "PMW-145" if self.armed else "PMW-048"
                self.finding(code, ts, {"neighbor": src}, af=af)
            self.modes[(af, vlan)].add("bidir")
        elif rec["bidir"]:
            rec["bidir"] = False
            self.finding("PMW-048", ts,
                         {"neighbor": src, "bidir_capable": False}, af=af)

        if opts.get("state_refresh_capable"):
            if not rec["state_refresh"]:
                rec["state_refresh"] = True
                self.finding("PMW-049", ts,
                             {"neighbor": src, "state_refresh_capable": True},
                             af=af)

        # DR election tracking: highest DR priority wins, address breaks ties.
        prio = opts.get("dr_priority")
        if prio is not None:
            old_prio = rec["dr_priority"]
            rec["dr_priority"] = prio
            link = (af, vlan)
            cur = self.dr.get(link)
            cand = (prio, self._addr_key(src), src)
            if cur is None:
                self.dr[link] = cand
            else:
                if (old_prio is not None and prio > old_prio
                        and cand[:2] > cur[:2] and self.armed
                        and src != cur[2]):
                    self.finding("PMW-042", ts,
                                 {"neighbor": src, "old_priority": old_prio,
                                  "new_priority": prio,
                                  "incumbent_dr": cur[2],
                                  "incumbent_priority": cur[0]}, af=af)
                if cand[:2] > cur[:2]:
                    self.dr[link] = cand
                    if src != cur[2] and self.armed:
                        self.finding("PMW-043", ts,
                                     {"vlan": vlan, "old_dr": cur[2],
                                      "new_dr": src,
                                      "new_priority": prio}, af=af)

        n = self.r_hello.hit(("hello", af, src), ts)
        if n > self.cfg["hello_rate_max"] and self.armed:
            self.finding("PMW-045", ts,
                         {"neighbor": src, "hellos": n,
                          "window_s": self.cfg["hello_rate_window"]}, af=af)

    @staticmethod
    def _addr_key(addr):
        try:
            return int(ipaddress.ip_address(addr))
        except ValueError:
            return 0

    # ---------------- Register / Register-Stop ----------------

    def _on_register(self, body, ctx):
        ts, af, src, dst = ctx["ts"], ctx["af"], ctx["src"], ctx["dst"]
        rp_key = (af, dst)
        self.register_rps.add(dst)
        known = rp_key in self.rp_set
        if not known:
            if self.armed:
                self.finding("PMW-110", ts,
                             {"register_from": src, "rp": dst,
                              "note": "Register sent to an address that was "
                                      "never advertised as an RP by BSR, "
                                      "Auto-RP or an earlier Register"}, af=af)
            else:
                self.rp_set[rp_key] = {"source": "register", "first_seen": ts,
                                       "priority": None}
                self.finding("PMW-100", ts,
                             {"rp": dst, "learned_from": "Register"}, af=af)

        grp = body.get("inner_group")
        if grp:
            self.groups_seen.add((af, grp))
            if is_ssm_group(grp):
                self.finding("PMW-162", ts,
                             {"rp": dst, "group": grp,
                              "source": body.get("inner_src"),
                              "note": "SSM groups must not be registered to an "
                                      "RP; RFC 4607 has no RP in the SSM range"},
                             af=af)
            if is_embedded_rp_group(grp):
                self._check_embedded_rp(grp, ctx)

        # RFC 4610 Anycast-RP: Register relayed between RPs for the same
        # anycast address. Observed as a Register whose outer source is itself
        # a learned RP.
        if (af, src) in self.rp_set or src in self.register_rps:
            if (af, src) in self.rp_set:
                self.anycast_rp_pim.add(dst)
                self.finding("PMW-113", ts,
                             {"from_rp": src, "to_rp": dst,
                              "note": "RP-to-RP Register is the RFC 4610 "
                                      "Anycast-RP mechanism"}, af=af)
                self._check_anycast_collision(dst, ctx)

    def _on_register_stop(self, body, ctx):
        ts, af, src = ctx["ts"], ctx["af"], ctx["src"]
        if (af, src) not in self.rp_set and self.armed:
            self.finding("PMW-111", ts,
                         {"from": src, "group": body["group"]["addr"],
                          "source": body["source"]["addr"]}, af=af)

    def _check_anycast_collision(self, rp, ctx):
        if rp in self.anycast_rp_pim and rp in self.anycast_rp_msdp:
            self.finding("PMW-114", ctx["ts"],
                         {"rp": rp,
                          "note": "RFC 4610 PIM Anycast-RP and RFC 3446 MSDP "
                                  "Anycast-RP both active for one RP address; "
                                  "the two mechanisms can loop source state "
                                  "against each other"}, af=ctx["af"])

    def _check_embedded_rp(self, group, ctx):
        ts, af = ctx["ts"], ctx["af"]
        rp = embedded_rp_address(group)
        self.finding("PMW-115", ts, {"group": group, "embedded_rp": rp}, af=af)
        if rp and self.armed and self.rp_set:
            known6 = {a for (f, a) in self.rp_set if f == 6}
            if known6 and rp not in known6:
                self.finding("PMW-116", ts,
                             {"group": group, "embedded_rp": rp,
                              "learned_rps": sorted(known6),
                              "note": "the RP encoded inside the group address "
                                      "is not one this fabric advertises"},
                             af=af)

    # ---------------- Join / Prune / Graft ----------------

    def _on_join_prune(self, body, ctx, typ):
        ts, af, src, vlan = ctx["ts"], ctx["af"], ctx["src"], ctx["vlan"]
        up = body["upstream"]["addr"]
        is_graft = typ in (PIM_GRAFT, PIM_GRAFT_ACK)

        if is_graft:
            self._note_dm(ctx)
            n = self.r_graft.hit(("graft", af, src), ts)
            if typ == PIM_GRAFT and n > self.cfg["graft_rate_max"] and self.armed:
                self.finding("PMW-121", ts,
                             {"src": src, "grafts": n,
                              "window_s": self.cfg["graft_rate_window"]}, af=af)
            # Graft/Graft-Ack pairing. A Graft names its upstream router; the
            # Ack comes back from that router for the same channels.
            for g in body["groups"]:
                gaddr = g["group"]["addr"]
                for s in list(g["joins"]) + list(g["prunes"]):
                    chan = (af, s["addr"], gaddr)
                    if typ == PIM_GRAFT:
                        self.graft_state.add(chan)
                    elif chan not in self.graft_state:
                        self.finding("PMW-124", ts,
                                     {"src": src, "group": gaddr,
                                      "source": s["addr"],
                                      "note": "a Graft-Ack with no observed "
                                              "Graft can indicate a forged ack "
                                              "cancelling a legitimate graft "
                                              "retransmission"}, af=af)
                    else:
                        self.graft_state.discard(chan)
        else:
            modes = self.modes[(af, vlan)]
            if "sm" not in modes:
                modes.add("sm")
                self.finding("PMW-005", ts,
                             {"vlan": vlan, "mode": "sparse",
                              "evidence": "Join/Prune"}, af=af)

        # Upstream neighbour must be a router we have heard Hellos from.
        if up not in ("0.0.0.0", "::") and (af, up) not in self.neighbors:
            if self.armed:
                self.finding("PMW-060", ts,
                             {"src": src, "upstream": up,
                              "known_neighbors": sorted(
                                  a for (f, a) in self.neighbors if f == af)[:16],
                              "note": "RPF heuristic: the Join/Prune names an "
                                      "upstream router that has never sent a "
                                      "Hello on this link"}, af=af)

        if body["holdtime"] == 0 and not is_graft:
            self.finding("PMW-062", ts,
                         {"src": src, "upstream": up,
                          "note": "zero holdtime expires the join state at the "
                                  "upstream router immediately"}, af=af)

        if body["num_groups"] > self.cfg["jp_group_max"]:
            self.finding("PMW-066", ts,
                         {"src": src, "num_groups": body["num_groups"],
                          "limit": self.cfg["jp_group_max"]}, af=af)

        total_sources = sum(len(g["joins"]) + len(g["prunes"])
                            for g in body["groups"])
        if total_sources > self.cfg["jp_source_max"]:
            self.finding("PMW-066", ts,
                         {"src": src, "total_sources": total_sources,
                          "limit": self.cfg["jp_source_max"],
                          "note": "large source lists drive multicast state "
                                  "growth at every router on the path"}, af=af)

        for attr in body.get("attributes", []):
            if attr["type"] == JP_ATTR_RPF_VECTOR:
                self._on_rpf_vector(attr, ctx)

        for g in body["groups"]:
            gaddr = g["group"]["addr"]
            first_time = (af, gaddr) not in self.groups_seen
            self.groups_seen.add((af, gaddr))
            ssm = is_ssm_group(gaddr)
            if ssm:
                self.finding("PMW-160", ts, {"group": gaddr}, af=af)
            if is_embedded_rp_group(gaddr):
                self._check_embedded_rp(gaddr, ctx)

            if self.armed and first_time and g["joins"]:
                self.finding("PMW-065", ts,
                             {"src": src, "group": gaddr,
                              "note": "a group never seen during the learning "
                                      "window is now being joined"}, af=af)

            for s in g["joins"]:
                wildcard = s["wildcard"]
                rpt = s["rpt"]
                if wildcard and rpt:
                    # (*,G) join -- the source field carries the RP address.
                    self.rpt_joined.add((af, gaddr))
                    if ssm:
                        self.finding("PMW-161", ts,
                                     {"src": src, "group": gaddr,
                                      "rp": s["addr"],
                                      "note": "RFC 4607 forbids shared-tree "
                                              "joins in the SSM range"}, af=af)
                elif not wildcard and not rpt:
                    if (af, gaddr) in self.rpt_joined:
                        self.finding("PMW-063", ts,
                                     {"src": src, "group": gaddr,
                                      "source": s["addr"]}, af=af)
                    if ssm:
                        self._track_ssm_source(gaddr, s["addr"], ctx)

            for s in g["prunes"]:
                if s["rpt"] and not s["wildcard"]:
                    self.finding("PMW-064", ts,
                                 {"src": src, "group": gaddr,
                                  "source": s["addr"]}, af=af)
                n = self.r_prune.hit(("prune", af, gaddr), ts)
                if n > self.cfg["prune_rate_max"] and self.armed:
                    self.finding("PMW-061", ts,
                                 {"group": gaddr, "prunes": n,
                                  "window_s": self.cfg["prune_rate_window"],
                                  "last_sender": src}, af=af)
                if self.armed and (af, src) not in self.neighbors:
                    self.finding("PMW-070", ts,
                                 {"src": src, "group": gaddr}, af=af)

    def _track_ssm_source(self, group, source, ctx):
        ts, af = ctx["ts"], ctx["af"]
        key = (af, group)
        known = self.ssm_sources[key]
        if not known:
            known.add(source)
            return
        if source not in known:
            self.finding("PMW-163", ts,
                         {"group": group, "new_source": source,
                          "baseline_sources": sorted(known),
                          "note": "the source for an SSM channel changed. "
                                  "Causes include a poisoned DNS SSM mapping, "
                                  "a changed static mapping, or a rogue native "
                                  "SSM join. The mapping mechanism itself is "
                                  "not on the wire; this is the observable "
                                  "effect of all three."},
                         af=af)
            known.add(source)

    def _on_rpf_vector(self, attr, ctx):
        ts, af, src = ctx["ts"], ctx["af"], ctx["src"]
        val = attr["value"]
        try:
            vec, _ = parse_encoded_unicast(val, 0)
        except ParseError:
            self.finding("PMW-004", ts,
                         {"src": src, "what": "RPF Vector attribute"}, af=af)
            return
        addr = vec["addr"]
        self.finding("PMW-067", ts, {"src": src, "rpf_vector": addr}, af=af)
        if not self.armed:
            return
        known = {a for (f, a) in self.neighbors if f == af}
        known |= {a for (f, a) in self.rp_set if f == af}
        if addr not in known:
            self.finding("PMW-068", ts,
                         {"src": src, "rpf_vector": addr,
                          "note": "RFC 5496 vector steers the upstream join "
                                  "toward an address this fabric has not "
                                  "advertised as a neighbour or RP"}, af=af)

    def _note_dm(self, ctx):
        af, vlan, ts = ctx["af"], ctx["vlan"], ctx["ts"]
        link = (af, vlan)
        modes = self.modes[link]
        if "dm" not in modes:
            self.finding("PMW-120", ts, {"vlan": vlan}, af=af)
        if self.armed and "sm" in modes and "dm" not in modes:
            self.finding("PMW-125", ts,
                         {"vlan": vlan,
                          "note": "dense-mode flooding appearing on a "
                                  "sparse-mode link expands the forwarding "
                                  "set without any receiver join"}, af=af)
        modes.add("dm")

    # ---------------- Assert ----------------

    def _on_assert(self, body, ctx):
        ts, af, src = ctx["ts"], ctx["af"], ctx["src"]
        g = body["group"]["addr"]
        s = body["source"]["addr"]
        self.finding("PMW-080", ts,
                     {"src": src, "group": g, "source": s,
                      "metric_pref": body["metric_pref"],
                      "metric": body["metric"], "rpt": body["rpt"]}, af=af)

        if self.armed and (af, src) not in self.neighbors:
            self.finding("PMW-084", ts,
                         {"src": src, "group": g, "source": s,
                          "note": "an Assert from a non-adjacent router can "
                                  "capture the forwarder role for this (S,G)"},
                         af=af)

        if body["metric_pref"] == 0 or body["metric"] == 0:
            self.finding("PMW-082", ts,
                         {"src": src, "group": g, "source": s,
                          "metric_pref": body["metric_pref"],
                          "metric": body["metric"],
                          "note": "a zero metric wins every Assert contest"},
                         af=af)

        key = (af, s, g)
        n = self.r_assert.hit(key, ts)
        if n > self.cfg["assert_churn_max"] and self.armed:
            self.finding("PMW-081", ts,
                         {"group": g, "source": s, "asserts": n,
                          "window_s": self.cfg["assert_churn_window"],
                          "note": "RPF heuristic: sustained Assert contention "
                                  "for one channel"}, af=af)

        cand = (body["metric_pref"], body["metric"], src)
        cur = self.assert_winner.get(key)
        # lower preference wins, then lower metric, then higher address
        def better(a, b):
            if a[0] != b[0]:
                return a[0] < b[0]
            if a[1] != b[1]:
                return a[1] < b[1]
            return PimWatch._addr_key(a[2]) > PimWatch._addr_key(b[2])

        if cur is None:
            self.assert_winner[key] = cand
        elif better(cand, cur):
            self.assert_winner[key] = cand
            if cand[2] != cur[2] and self.armed:
                self.finding("PMW-083", ts,
                             {"group": g, "source": s,
                              "old_winner": cur[2], "new_winner": cand[2]},
                             af=af)

    # ---------------- Bootstrap / Candidate-RP ----------------

    def _on_bootstrap(self, body, ctx):
        ts, af, src = ctx["ts"], ctx["af"], ctx["src"]
        bsr = body["bsr"]["addr"]
        prio = body["bsr_priority"]
        cur = self.bsr.get(af)
        if cur is None:
            self.bsr[af] = {"addr": bsr, "priority": prio,
                            "hash_mask_len": body["hash_mask_len"],
                            "fragment_tags": {body["fragment_tag"]},
                            "first_seen": ts}
            self.finding("PMW-101", ts,
                         {"bsr": bsr, "priority": prio,
                          "hash_mask_len": body["hash_mask_len"]}, af=af)
        else:
            if cur["addr"] != bsr:
                if self.armed:
                    code = "PMW-102" if prio > cur["priority"] else "PMW-103"
                    self.finding(code, ts,
                                 {"old_bsr": cur["addr"],
                                  "old_priority": cur["priority"],
                                  "new_bsr": bsr, "new_priority": prio,
                                  "note": "the BSR distributes the RP set for "
                                          "the whole domain"}, af=af)
                cur["addr"] = bsr
                cur["priority"] = prio
            if cur["hash_mask_len"] != body["hash_mask_len"]:
                if self.armed:
                    self.finding("PMW-112", ts,
                                 {"bsr": bsr, "old": cur["hash_mask_len"],
                                  "new": body["hash_mask_len"]}, af=af)
                cur["hash_mask_len"] = body["hash_mask_len"]
            tags = cur["fragment_tags"]
            tags.add(body["fragment_tag"])
            if len(tags) > 8 and self.armed:
                self.finding("PMW-117", ts,
                             {"bsr": bsr, "distinct_tags": len(tags)}, af=af)
                cur["fragment_tags"] = {body["fragment_tag"]}

        for gs in body["group_sets"]:
            gaddr = gs["group"]["addr"]
            mlen = gs["group"]["masklen"]
            gkey = (af, gaddr, mlen)
            advertised = frozenset(r["addr"] for r in gs["rps"])
            prev_set = self.bsr_rp_sets.get(gkey)
            if prev_set is None:
                self.bsr_rp_sets[gkey] = advertised
            elif prev_set != advertised and self.armed:
                self.finding("PMW-105", ts,
                             {"bsr": bsr, "group": gaddr, "masklen": mlen,
                              "removed": sorted(prev_set - advertised),
                              "added": sorted(advertised - prev_set),
                              "note": "the RP set for this range changed; "
                                      "withdrawing an RP moves every shared "
                                      "tree under it"}, af=af)
                self.bsr_rp_sets[gkey] = advertised
            else:
                self.bsr_rp_sets[gkey] = advertised
            if is_ssm_group(gaddr):
                self.finding("PMW-164", ts,
                             {"bsr": bsr, "group": gaddr, "masklen": mlen,
                              "note": "the SSM range has no RP"}, af=af)
            for rp in gs["rps"]:
                self._learn_rp(rp["addr"], gaddr, mlen, ctx,
                               source="bsr", priority=rp["priority"])

    def _learn_rp(self, rp, group, masklen, ctx, source, priority=None):
        ts, af = ctx["ts"], ctx["af"]
        key = (af, rp)
        if key not in self.rp_set:
            self.rp_set[key] = {"source": source, "first_seen": ts,
                                "priority": priority}
            self.finding("PMW-100", ts,
                         {"rp": rp, "learned_from": source,
                          "group": group, "masklen": masklen,
                          "priority": priority}, af=af)
        else:
            old = self.rp_set[key].get("priority")
            if (priority is not None and old is not None
                    and priority < old and self.armed):
                self.finding("PMW-118", ts,
                             {"rp": rp, "old_priority": old,
                              "new_priority": priority,
                              "note": "a numerically lower Candidate-RP "
                                      "priority wins the election"}, af=af)
            self.rp_set[key]["priority"] = priority if priority is not None else old

        gkey = (af, group, masklen)
        prev = self.group_rp.get(gkey)
        if prev is None:
            self.group_rp[gkey] = rp
        elif prev != rp:
            self.finding("PMW-106", ts,
                         {"group": group, "masklen": masklen,
                          "rp_a": prev, "rp_b": rp, "advertised_by": source,
                          "note": "one group range mapped to two RPs; "
                                  "receivers split across shared trees"},
                         af=af)
            self.group_rp[gkey] = rp

    def _on_cand_rp(self, body, ctx):
        ts, af, src = ctx["ts"], ctx["af"], ctx["src"]
        rp = body["rp"]["addr"]
        if self.armed and (af, rp) not in self.rp_set:
            self.finding("PMW-104", ts,
                         {"candidate_rp": rp, "from": src,
                          "priority": body["priority"],
                          "groups": [g["addr"] for g in body["groups"]]}, af=af)
        for g in body["groups"]:
            if is_ssm_group(g["addr"]):
                self.finding("PMW-164", ts,
                             {"candidate_rp": rp, "group": g["addr"]}, af=af)
            self._learn_rp(rp, g["addr"], g["masklen"], ctx,
                           source="candidate-rp", priority=body["priority"])

    # ---------------- State Refresh (DM) ----------------

    def _on_state_refresh(self, body, ctx):
        ts, af, src = ctx["ts"], ctx["af"], ctx["src"]
        self._note_dm(ctx)
        orig = body["originator"]["addr"]
        if self.armed and (af, orig) not in self.neighbors:
            self.finding("PMW-122", ts,
                         {"src": src, "originator": orig,
                          "group": body["group"]["addr"],
                          "source": body["source"]["addr"],
                          "note": "State Refresh keeps a dense-mode prune "
                                  "alive; a forged originator can hold a "
                                  "branch pruned indefinitely"}, af=af)
        if body["ttl"] == 0 or body["interval"] > self.cfg["state_refresh_interval_max"]:
            self.finding("PMW-123", ts,
                         {"src": src, "ttl": body["ttl"],
                          "interval": body["interval"]}, af=af)

    # ---------------- DF election (BiDir) ----------------

    def _on_df_election(self, body, ctx):
        ts, af, src, vlan = ctx["ts"], ctx["af"], ctx["src"], ctx["vlan"]
        self.modes[(af, vlan)].add("bidir")
        sub = body["subtype"]
        rp = body["rp"]["addr"]
        self.finding("PMW-140", ts,
                     {"src": src, "rp": rp,
                      "subtype": DF_SUBTYPE_NAME.get(sub, sub),
                      "metric_pref": body["metric_pref"]}, af=af)

        if self.armed and (af, src) not in self.neighbors:
            self.finding("PMW-143", ts,
                         {"src": src, "rp": rp,
                          "subtype": DF_SUBTYPE_NAME.get(sub, sub)}, af=af)

        if sub == DF_OFFER:
            n = self.r_offer.hit(("offer", af, rp), ts)
            if n > self.cfg["df_offer_max"] and self.armed:
                self.finding("PMW-141", ts,
                             {"rp": rp, "offers": n,
                              "window_s": self.cfg["df_offer_window"],
                              "last_sender": src}, af=af)

        if sub == DF_WINNER:
            key = (af, rp)
            cur = self.df_winner.get(key)
            if cur is None:
                self.df_winner[key] = src
            elif cur != src:
                self.df_winner[key] = src
                if self.armed:
                    self.finding("PMW-142", ts,
                                 {"rp": rp, "old_df": cur, "new_df": src,
                                  "note": "the DF forwards all traffic for this "
                                          "RP on the link"}, af=af)

        if sub == DF_PASS and body["target"]:
            tgt = body["target"]["addr"]
            if self.armed and (af, tgt) not in self.neighbors:
                self.finding("PMW-144", ts,
                             {"src": src, "rp": rp, "target": tgt}, af=af)

    # ---------------- Auto-RP ----------------

    def _handle_autorp(self, payload, ctx):
        ts, af, src, dst = ctx["ts"], 4, ctx["src"], ctx["dst"]
        body = parse_autorp(payload)
        self.finding("PMW-109", ts,
                     {"src": src, "dst": dst, "type": body["type"],
                      "note": "Auto-RP has no authentication mechanism; any "
                              "host on the segment can originate it"}, af=af)

        if dst == AUTORP_DISCOVERY:
            prev = self.autorp_agents.get("mapping_agent")
            if prev is None:
                self.autorp_agents["mapping_agent"] = src
            elif prev != src:
                self.autorp_agents["mapping_agent"] = src
                if self.armed:
                    self.finding("PMW-108", ts,
                                 {"old_agent": prev, "new_agent": src}, af=af)

        for rp in body["rps"]:
            rpa = rp["addr"]
            if self.armed and (4, rpa) not in self.rp_set:
                self.finding("PMW-107", ts,
                             {"rp": rpa, "announced_by": src,
                              "groups": [g["group"] for g in rp["groups"]]},
                             af=af)
            for g in rp["groups"]:
                if is_ssm_group(g["group"]):
                    self.finding("PMW-164", ts,
                                 {"rp": rpa, "group": g["group"],
                                  "via": "auto-rp"}, af=af)
                self._learn_rp(rpa, g["group"], g["masklen"], ctx,
                               source="auto-rp")

    # ---------------- MSDP ----------------

    def _handle_msdp(self, buf, ctx, tcp):
        ts, src, dst = ctx["ts"], ctx["src"], ctx["dst"]
        af = 4
        sess = frozenset(((src, tcp["sport"]), (dst, tcp["dport"])))
        rec = self.msdp_sessions.get(sess)
        if rec is None:
            rec = {"first_seen": ts, "md5": tcp["md5"], "last": ts,
                   "peers": sorted({src, dst})}
            self.msdp_sessions[sess] = rec
            self.finding("PMW-180", ts,
                         {"peer_a": fmt_ep(src, tcp["sport"]),
                          "peer_b": fmt_ep(dst, tcp["dport"]),
                          "tcp_md5": tcp["md5"]}, af=af)
            if not tcp["md5"]:
                self.finding("PMW-190", ts,
                             {"peer_a": fmt_ep(src, tcp["sport"]),
                              "peer_b": fmt_ep(dst, tcp["dport"]),
                              "note": "no TCP-MD5 signature option observed on "
                                      "this session; RFC 3618 relies on it for "
                                      "peer authentication"}, af=af)
        rec["md5"] = rec["md5"] or tcp["md5"]
        rec["last"] = ts

        for p in (src, dst):
            if p in self.msdp_peers:
                continue
            if self.armed:
                self.finding("PMW-187", ts, {"peer": p}, af=af)
            self.msdp_peers.add(p)

        if tcp["rst"] or tcp["fin"]:
            self.finding("PMW-186", ts,
                         {"peer_a": fmt_ep(src, tcp["sport"]),
                          "peer_b": fmt_ep(dst, tcp["dport"]),
                          "flag": "RST" if tcp["rst"] else "FIN"}, af=af)

        payload = buf[tcp["payload_off"]:tcp["payload_end"]]
        if not payload:
            return
        skey = (src, tcp["sport"], dst, tcp["dport"])
        stream = self.msdp_streams.get(skey)
        if stream is None:
            stream = self.msdp_streams[skey] = MsdpStream()
        tlvs, errors = stream.feed(bytes(payload))
        for e in errors:
            self.finding("PMW-189", ts,
                         {"peer": fmt_ep(src, tcp["sport"]), "error": e}, af=af)
        for tlv in tlvs:
            self._on_msdp_tlv(tlv, ctx, src)

    def _on_msdp_tlv(self, tlv, ctx, peer):
        ts, af = ctx["ts"], 4
        t = tlv["type"]
        if t in (MSDP_SA_REQUEST, MSDP_SA_RESPONSE):
            self.finding("PMW-188", ts,
                         {"peer": peer, "tlv": tlv["name"],
                          "group": tlv.get("group")}, af=af)
            return
        if t != MSDP_SA:
            return

        rp = tlv["rp"]
        self.finding("PMW-181", ts,
                     {"peer": peer, "originating_rp": rp,
                      "entries": tlv["entries_parsed"]}, af=af)

        if tlv["entries_parsed"] != tlv["entry_count"]:
            self.finding("PMW-192", ts,
                         {"peer": peer, "declared": tlv["entry_count"],
                          "parsed": tlv["entries_parsed"],
                          "tlv_length": tlv["length"]}, af=af)

        if tlv["encapsulated_len"] > 0:
            self.finding("PMW-191", ts,
                         {"peer": peer, "originating_rp": rp,
                          "encapsulated_bytes": tlv["encapsulated_len"],
                          "note": "data-encapsulated SA carries multicast "
                                  "payload inside the control session"}, af=af)

        if (4, rp) not in self.rp_set:
            if self.armed:
                self.finding("PMW-182", ts,
                             {"peer": peer, "originating_rp": rp,
                              "note": "peer-RPF heuristic: the originating RP "
                                      "is not one this fabric advertises. The "
                                      "real RFC 3618 peer-RPF check is against "
                                      "the RIB and is not observable passively."},
                             af=af)
            else:
                self.rp_set[(4, rp)] = {"source": "msdp-sa", "first_seen": ts,
                                        "priority": None}
                self.finding("PMW-100", ts,
                             {"rp": rp, "learned_from": "MSDP SA"}, af=af)

        self.anycast_rp_msdp.add(rp)
        self._check_anycast_collision(rp, ctx)

        n = self.r_sa.hit(("sa", peer), ts)
        if n > self.cfg["sa_rate_max"] and self.armed:
            self.finding("PMW-184", ts,
                         {"peer": peer, "sa_messages": n,
                          "window_s": self.cfg["sa_rate_window"]}, af=af)

        for e in tlv["entries"]:
            g, s = e["group"], e["source"]
            if is_ssm_group(g):
                self.finding("PMW-183", ts,
                             {"peer": peer, "group": g, "source": s,
                              "originating_rp": rp,
                              "note": "the SSM range has no RP, so no SA "
                                      "should ever describe it"}, af=af)
            prev = self.msdp_group_rp.get(g)
            if prev is None:
                self.msdp_group_rp[g] = rp
            elif prev != rp:
                self.finding("PMW-185", ts,
                             {"group": g, "rp_a": prev, "rp_b": rp,
                              "source": s}, af=af)
                self.msdp_group_rp[g] = rp

    # ---------------- reporting ----------------

    def summary(self):
        by_sev = defaultdict(int)
        for f in self.findings:
            by_sev[f["severity"]] += 1
        return {
            "module": MODULE, "version": VERSION,
            "armed": self.armed,
            "frames": self.stats["frames"],
            "pim_packets": self.stats["pim_packets"],
            "autorp_packets": self.stats["autorp_packets"],
            "msdp_packets": self.stats["msdp_packets"],
            "parse_errors": self.stats["parse_errors"],
            "internal_errors": self.stats["internal_errors"],
            "findings": len(self.findings),
            "by_severity": dict(by_sev),
            "neighbors": len(self.neighbors),
            "rps": len(self.rp_set),
            "msdp_peers": len(self.msdp_peers),
            "suppressed": dict(self.suppressed),
        }


# --------------------------------------------------------------------------
# Capture path -- the only place scapy is imported (suite LESSON C)
# --------------------------------------------------------------------------

# bare `ip6` is required: a `port`/`proto` primitive cannot walk an IPv6
# extension-header chain, so the natural-looking narrow form is a measured
# no-op (suite LESSON AE). The software gate below is therefore load-bearing
# for IPv6 and has its own explicit negative test.
BPF_FILTER = ("(ip proto 103) or (ip and udp port 496) or "
              "(ip and tcp port 639) or ip6")


def run_capture(iface, watcher, timeout=None, offline=None):
    from scapy.all import sniff            # noqa: PLC0415

    def _cb(pkt):
        try:
            watcher.handle_frame(bytes(pkt), ts=float(pkt.time))
        except Exception:                   # noqa: BLE001
            watcher.stats["callback_errors"] += 1

    kwargs = {"prn": _cb, "store": False, "filter": BPF_FILTER}
    if offline is not None:
        kwargs["offline"] = offline
    else:
        kwargs["iface"] = iface
        if timeout:
            kwargs["timeout"] = timeout
    sniff(**kwargs)
    return watcher


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _print_codes():
    for code in sorted(FINDINGS):
        m = FINDINGS[code]
        print("%s  %-8s %-8s %-7s %s" % (code, m["severity"], m["class"],
                                         CODE_PROTO[code], m["title"]))


def main(argv=None):
    ap = argparse.ArgumentParser(prog=MODULE, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", help="interface to listen on (passive)")
    ap.add_argument("--pcap", help="read from a pcap instead of a live tap")
    ap.add_argument("--timeout", type=int, default=0)
    ap.add_argument("--learn-seconds", type=int, default=DEFAULTS["learn_seconds"])
    ap.add_argument("--arm-now", action="store_true",
                    help="skip the learning window (for replay and labs)")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--print-codes", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--version", action="store_true")
    args = ap.parse_args(argv)

    if args.version:
        print("%s %s" % (MODULE, VERSION))
        return 0
    if args.print_codes:
        _print_codes()
        return 0
    if args.self_test:
        from pimwatch_selftest import run_self_test   # noqa: PLC0415
        return run_self_test()

    if not args.iface and not args.pcap:
        ap.error("one of --iface or --pcap is required")

    w = PimWatch(config={"learn_seconds": args.learn_seconds},
                 armed=args.arm_now)
    run_capture(args.iface, w, timeout=args.timeout or None,
                offline=args.pcap)

    if args.json:
        print(json.dumps({"summary": w.summary(), "findings": w.findings},
                         indent=2, sort_keys=True))
    else:
        for f in w.findings:
            print("[%-8s] %s  %s" % (f["severity"], f["code"],
                                     json.dumps(f["detail"], sort_keys=True)))
        print(json.dumps(w.summary(), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
