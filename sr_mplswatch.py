#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sr-mplswatch - passive MPLS / SR-MPLS / SRv6 label & segment manipulation detector.

Part of the Ragnar passive network security suite.

OSI layer:  L2.5 (MPLS shim) / L3 (IPv6 SRH) / L4-L5 (LDP, RSVP-TE, BGP-LU/SR)
Hardware floor: Raspberry Pi Zero 2W
Passive invariant: this module NEVER transmits. It has no transmit primitives.
                   The self-test asserts that by grepping this source.

Scope (see README):
  * MPLS data plane      - ethertype 0x8847 / 0x8848, label stack semantics
  * SR-MPLS              - SIDs carried as MPLS labels, SRGB conformance
  * SRv6                 - IPv6 Routing Header type 4 (RFC 8754)
  * LDP                  - udp/646 discovery, tcp/646 session (RFC 5036)
  * RSVP-TE              - ip proto 46 (RFC 2205 / 3209)
  * BGP-SR               - Prefix-SID attribute (RFC 8669), labeled unicast

Deliberately NOT in scope - see README "Deferrals":
  * IGP-SR sub-TLVs (IS-IS / OSPF SR extensions)  -> isiswatch / ospfwatch own the IGP wire
  * Comware/Huawei VRF-hopping CVE detection      -> vrfwatch owns CVE-2015-5434 / CVE-2015-8087
  * Full BGP session semantics                    -> bgpwatch owns that

Author: Ragnar suite
Version: 0.1.0-dev
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import struct
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, fields as dc_fields
from typing import Any, Dict, List, Optional, Tuple

__version__ = "0.1.0-dev"
MODULE_NAME = "sr-mplswatch"

# ---------------------------------------------------------------------------
# Protocol constants  (transcribed from the RFCs / IANA registries; the
# conformance tier re-derives these from the RFC text as external ground truth)
# ---------------------------------------------------------------------------

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_VLAN_9100 = 0x9100
ETHERTYPE_MPLS_UNICAST = 0x8847        # RFC 3032
ETHERTYPE_MPLS_MULTICAST = 0x8848      # RFC 3032
ETHERTYPE_IPV6 = 0x86DD

VLAN_ETHERTYPES = frozenset((ETHERTYPE_VLAN, ETHERTYPE_QINQ, ETHERTYPE_VLAN_9100))
MPLS_ETHERTYPES = frozenset((ETHERTYPE_MPLS_UNICAST, ETHERTYPE_MPLS_MULTICAST))

# IANA "Special-Purpose MPLS Label Values" registry (RFC 3032, 3429, 5586,
# 6790, 7274).  Labels 0-15 are reserved; only a subset is legal in the
# data plane on the wire.
LABEL_IPV4_EXPLICIT_NULL = 0     # RFC 3032 - legal on the wire, bottom of stack
LABEL_ROUTER_ALERT = 1           # RFC 3032 - legal, must not be bottom of stack
LABEL_IPV6_EXPLICIT_NULL = 2     # RFC 3032 - legal on the wire, bottom of stack
LABEL_IMPLICIT_NULL = 3          # RFC 3032 - CONTROL PLANE ONLY, never on the wire
LABEL_ELI = 7                    # RFC 6790 - Entropy Label Indicator
LABEL_GAL = 13                   # RFC 5586 - Generic Associated Channel Label
LABEL_OAM_ALERT = 14             # RFC 3429 - OAM Alert Label
LABEL_EXTENSION = 15             # RFC 7274 - Extension Label

# 4,5,6 and 8..12 have never been assigned.  Seeing one as a forwarding label
# means something built the stack that does not share our label semantics.
LABEL_UNASSIGNED_SPECIAL = frozenset((4, 5, 6, 8, 9, 10, 11, 12))
LABEL_SPECIAL_MAX = 15
LABEL_MAX = (1 << 20) - 1        # 20-bit label field

# Labels that are legal to observe in a forwarding position on the wire.
LABEL_WIRE_LEGAL_SPECIAL = frozenset((
    LABEL_IPV4_EXPLICIT_NULL,
    LABEL_ROUTER_ALERT,
    LABEL_IPV6_EXPLICIT_NULL,
    LABEL_ELI,
    LABEL_GAL,
    LABEL_OAM_ALERT,
    LABEL_EXTENSION,
))

# IPv6 / SRH - RFC 8200, RFC 8754
IPPROTO_HOPOPT = 0
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_IPV6_ROUTE = 43
IPPROTO_IPV6_FRAG = 44
IPPROTO_RSVP = 46                # RFC 2205
IPPROTO_GRE = 47
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_ICMPV6 = 58
IPPROTO_NONXT = 59
IPPROTO_IPV6_OPTS = 60
IPPROTO_MPLS_IN_IP = 137         # RFC 4023

IPV6_EXT_HEADERS = frozenset((
    IPPROTO_HOPOPT, IPPROTO_IPV6_ROUTE, IPPROTO_IPV6_FRAG,
    IPPROTO_AH, IPPROTO_IPV6_OPTS,
))

SRH_ROUTING_TYPE = 4             # RFC 8754 s2 - Segment Routing Header
SRH_TLV_PAD1 = 0                 # RFC 8754 s2.1.1
SRH_TLV_PADN = 4                 # RFC 8754 s2.1.1
SRH_TLV_HMAC = 5                 # RFC 8754 s2.1.2
SRH_FLAG_UNUSED_MASK = 0xFF      # RFC 8754 s2: all 8 flag bits currently unassigned
SRV6_SID_LEN = 16                # bytes per segment-list entry

# LDP - RFC 5036
LDP_PORT = 646
LDP_VERSION = 1
LDP_MSG_NOTIFICATION = 0x0001
LDP_MSG_HELLO = 0x0100
LDP_MSG_INITIALIZATION = 0x0200
LDP_MSG_KEEPALIVE = 0x0201
LDP_MSG_ADDRESS = 0x0300
LDP_MSG_ADDRESS_WITHDRAW = 0x0301
LDP_MSG_LABEL_MAPPING = 0x0400
LDP_MSG_LABEL_REQUEST = 0x0401
LDP_MSG_LABEL_WITHDRAW = 0x0402
LDP_MSG_LABEL_RELEASE = 0x0403
LDP_MSG_LABEL_ABORT_REQUEST = 0x0404

LDP_TLV_FEC = 0x0100
LDP_TLV_GENERIC_LABEL = 0x0200
LDP_TLV_HOP_COUNT = 0x0103
LDP_TLV_PATH_VECTOR = 0x0104
LDP_TLV_COMMON_HELLO = 0x0400
LDP_TLV_IPV4_TRANSPORT = 0x0401
LDP_TLV_CONFIG_SEQNO = 0x0402
LDP_TLV_IPV6_TRANSPORT = 0x0403
LDP_TLV_COMMON_SESSION = 0x0500

LDP_HELLO_FLAG_TARGETED = 0x8000   # RFC 5036 s3.5.2 "T" bit
LDP_HELLO_FLAG_REQUEST = 0x4000    # "R" bit

LDP_FEC_WILDCARD = 0x01
LDP_FEC_PREFIX = 0x02
LDP_FEC_HOST = 0x03

# RSVP / RSVP-TE - RFC 2205, RFC 3209, RFC 2747
RSVP_VERSION = 1
RSVP_MSG_PATH = 1
RSVP_MSG_RESV = 2
RSVP_MSG_PATH_ERR = 3
RSVP_MSG_RESV_ERR = 4
RSVP_MSG_PATH_TEAR = 5
RSVP_MSG_RESV_TEAR = 6
RSVP_MSG_RESV_CONF = 7
RSVP_MSG_HELLO = 20

RSVP_TEARDOWN_MSGS = frozenset((RSVP_MSG_PATH_TEAR, RSVP_MSG_RESV_TEAR))

RSVP_OBJ_SESSION = 1
RSVP_OBJ_RSVP_HOP = 3
RSVP_OBJ_INTEGRITY = 4           # RFC 2747 - cryptographic authentication
RSVP_OBJ_TIME_VALUES = 5
RSVP_OBJ_ERROR_SPEC = 6
RSVP_OBJ_SENDER_TEMPLATE = 11
RSVP_OBJ_SENDER_TSPEC = 12
RSVP_OBJ_LABEL = 16              # RFC 3209
RSVP_OBJ_LABEL_REQUEST = 19      # RFC 3209
RSVP_OBJ_ERO = 20                # RFC 3209 EXPLICIT_ROUTE
RSVP_OBJ_RRO = 21                # RFC 3209 RECORD_ROUTE
RSVP_OBJ_SESSION_ATTRIBUTE = 207  # RFC 3209

# BGP - RFC 4271, RFC 8669 (Prefix-SID), RFC 8277 (labeled unicast)
BGP_PORT = 179
BGP_MARKER = b"\xff" * 16
BGP_HDR_LEN = 19
BGP_MSG_OPEN = 1
BGP_MSG_UPDATE = 2
BGP_MSG_NOTIFICATION = 3
BGP_MSG_KEEPALIVE = 4
BGP_MSG_ROUTE_REFRESH = 5        # RFC 2918
BGP_MSG_TYPES = frozenset((1, 2, 3, 4, 5))
BGP_MAX_STD_LEN = 4096           # RFC 4271 s4.1
BGP_MAX_EXT_LEN = 65535          # RFC 8654, UPDATE / ROUTE-REFRESH only
BGP_EXT_LEN_TYPES = frozenset((2, 5))

BGP_ATTR_ORIGIN = 1
BGP_ATTR_AS_PATH = 2
BGP_ATTR_NEXT_HOP = 3
BGP_ATTR_MP_REACH_NLRI = 14
BGP_ATTR_MP_UNREACH_NLRI = 15
BGP_ATTR_PREFIX_SID = 40         # RFC 8669
BGP_ATTR_FLAG_EXT_LEN = 0x10

BGP_PREFIX_SID_TLV_LABEL_INDEX = 1     # RFC 8669 s3.1
BGP_PREFIX_SID_TLV_ORIGINATOR_SRGB = 3  # RFC 8669 s3.2
BGP_PREFIX_SID_TLV_SRV6_L3_SERVICE = 5  # RFC 9252

BGP_AFI_IPV4 = 1
BGP_AFI_IPV6 = 2
BGP_SAFI_UNICAST = 1
BGP_SAFI_LABELED_UNICAST = 4     # RFC 8277
BGP_SAFI_MPLS_VPN = 128          # RFC 4364

# ---------------------------------------------------------------------------
# IGP-SR control plane.
#
# Codepoints below are transcribed from the IANA tables in RFC 8667 s4
# (IS-IS) and RFC 8665 s8 / the IANA OSPFv2 sub-TLV registries (OSPFv2).
# The conformance harness re-derives them as external ground truth.
# ---------------------------------------------------------------------------

# -- IS-IS (ISO 10589 framing, RFC 8667 SR extensions) ----------------------
LLC_SAP_ISIS = 0xFE              # DSAP == SSAP == 0xFE, control 0x03
LLC_CONTROL_UI = 0x03
ISIS_DISCRIMINATOR = 0x83        # Intradomain Routing Protocol Discriminator
ISIS_VERSION = 1
ETH_MAX_LENGTH_FIELD = 1500      # <=1500 in the type/length slot means 802.3

ISIS_PDU_L1_LAN_IIH = 15
ISIS_PDU_L2_LAN_IIH = 16
ISIS_PDU_P2P_IIH = 17
ISIS_PDU_L1_LSP = 18
ISIS_PDU_L2_LSP = 20
ISIS_PDU_L1_CSNP = 24
ISIS_PDU_L2_CSNP = 25
ISIS_PDU_L1_PSNP = 26
ISIS_PDU_L2_PSNP = 27
ISIS_LSP_TYPES = frozenset((ISIS_PDU_L1_LSP, ISIS_PDU_L2_LSP))

ISIS_TLV_EXT_IS_REACH = 22       # RFC 5305 - carries Adj-SID (31) / LAN-Adj-SID (32)
ISIS_TLV_IS_NEIGH_ATTR = 23      # RFC 5311
ISIS_TLV_INTER_AS_REACH = 141    # RFC 5316
ISIS_TLV_EXT_IPV4_REACH = 135    # RFC 5305 - carries Prefix-SID (3)
ISIS_TLV_MT_IPV4_REACH = 235     # RFC 5120
ISIS_TLV_IPV6_REACH = 236        # RFC 5308
ISIS_TLV_MT_IPV6_REACH = 237     # RFC 5120
ISIS_TLV_MT_IS_NEIGH = 222       # RFC 5120
ISIS_TLV_MT_IS_NEIGH_ATTR = 223  # RFC 5311
ISIS_TLV_ROUTER_CAPABILITY = 242  # RFC 7981
ISIS_TLV_SID_BINDING = 149       # RFC 8667 s2.4
ISIS_TLV_MT_SID_BINDING = 150    # RFC 8667 s2.5

ISIS_PREFIX_TLVS = frozenset((ISIS_TLV_EXT_IPV4_REACH, ISIS_TLV_MT_IPV4_REACH,
                              ISIS_TLV_IPV6_REACH, ISIS_TLV_MT_IPV6_REACH))
ISIS_NEIGHBOR_TLVS = frozenset((ISIS_TLV_EXT_IS_REACH, ISIS_TLV_IS_NEIGH_ATTR,
                                ISIS_TLV_INTER_AS_REACH, ISIS_TLV_MT_IS_NEIGH,
                                ISIS_TLV_MT_IS_NEIGH_ATTR))

# RFC 8667 s4.2 - sub-TLVs for TLVs 135/235/236/237
ISIS_SUB_PREFIX_SID = 3
# RFC 8667 s4.1 - sub-TLVs for TLVs 22/23/25/141/222/223
ISIS_SUB_ADJ_SID = 31
ISIS_SUB_LAN_ADJ_SID = 32
# RFC 8667 s4.3 - sub-TLVs for TLV 242
ISIS_SUB_SR_CAPABILITY = 2
ISIS_SUB_SR_ALGORITHM = 19
ISIS_SUB_SR_LOCAL_BLOCK = 22
ISIS_SUB_SRMS_PREFERENCE = 24
# RFC 8667 s2.3 - sub-TLVs for TLVs 149/150
ISIS_SUB_SID_LABEL = 1

# RFC 8667 s2.1: Prefix-SID flags  R|N|P|E|V|L
PSID_FLAG_R = 0x80
PSID_FLAG_N = 0x40
PSID_FLAG_P = 0x20
PSID_FLAG_E = 0x10
PSID_FLAG_V = 0x08
PSID_FLAG_L = 0x04
# RFC 8667 s2.2.1: Adj-SID flags  F|B|V|L|S|P
ASID_FLAG_F = 0x80
ASID_FLAG_B = 0x40
ASID_FLAG_V = 0x20
ASID_FLAG_L = 0x10
ASID_FLAG_S = 0x08
ASID_FLAG_P = 0x04

# RFC 8665 s8.4 "IGP Algorithm Type": 0 SPF, 1 Strict SPF.  128-255 are the
# Flex-Algo range (RFC 9350).
SR_ALGO_SPF = 0
SR_ALGO_STRICT_SPF = 1
SR_ALGO_FLEX_MIN = 128
SR_ALGO_FLEX_MAX = 255

# -- OSPFv2 (RFC 2328 framing, RFC 7684 opaque LSAs, RFC 8665 SR) -----------
IPPROTO_OSPF = 89
OSPF_VERSION = 2
OSPF_TYPE_HELLO = 1
OSPF_TYPE_DB_DESC = 2
OSPF_TYPE_LS_REQUEST = 3
OSPF_TYPE_LS_UPDATE = 4
OSPF_TYPE_LS_ACK = 5
OSPF_HDR_LEN = 24
OSPF_LSA_HDR_LEN = 20

OSPF_LSA_OPAQUE_LINK = 9
OSPF_LSA_OPAQUE_AREA = 10
OSPF_LSA_OPAQUE_AS = 11
OSPF_OPAQUE_LSA_TYPES = frozenset((OSPF_LSA_OPAQUE_LINK, OSPF_LSA_OPAQUE_AREA,
                                   OSPF_LSA_OPAQUE_AS))

OSPF_OPAQUE_ROUTER_INFO = 4      # RFC 7770
OSPF_OPAQUE_EXT_PREFIX = 7       # RFC 7684
OSPF_OPAQUE_EXT_LINK = 8         # RFC 7684

OSPF_TLV_EXT_PREFIX = 1          # RFC 7684 s2.1
OSPF_TLV_EXT_PREFIX_RANGE = 2    # RFC 7684 s2.2
OSPF_TLV_EXT_LINK = 1            # RFC 7684 s3.1

# RFC 8665 s8.1 - OSPF Router Information TLVs
OSPF_RI_TLV_SR_ALGORITHM = 8
OSPF_RI_TLV_SID_LABEL_RANGE = 9
OSPF_RI_TLV_SR_LOCAL_BLOCK = 14
OSPF_RI_TLV_SRMS_PREFERENCE = 15
# OSPFv2 Extended Prefix TLV sub-TLVs (IANA registry, RFC 8665)
OSPF_SUB_SID_LABEL = 1
OSPF_SUB_PREFIX_SID = 2
# OSPFv2 Extended Link TLV sub-TLVs (RFC 8665 s6.1 / s6.2)
OSPF_SUB_ADJ_SID = 2
OSPF_SUB_LAN_ADJ_SID = 3

# RFC 8665 s5: OSPFv2 Prefix-SID flags   |  |NP|M|E|V|L|  |
OSPF_PSID_FLAG_NP = 0x40
OSPF_PSID_FLAG_M = 0x20
OSPF_PSID_FLAG_E = 0x10
OSPF_PSID_FLAG_V = 0x08
OSPF_PSID_FLAG_L = 0x04
# RFC 8665 s6.1: OSPFv2 Adj-SID flags    |  |B|V|L|S|  |  |
OSPF_ASID_FLAG_B = 0x40
OSPF_ASID_FLAG_V = 0x20
OSPF_ASID_FLAG_L = 0x10
OSPF_ASID_FLAG_S = 0x08

_MAX_ISIS_TLVS = 128
_MAX_ISIS_SUBTLVS = 64
_MAX_OSPF_LSAS = 64
_MAX_OSPF_TLVS = 64

# TCP option kind 19 = TCP-MD5 signature (RFC 2385).  Its presence on the
# LDP/BGP handshake is the only passively observable authentication posture.
TCP_OPT_END = 0
TCP_OPT_NOP = 1
TCP_OPT_MD5 = 19
TCP_OPT_AO = 29                  # RFC 5925 TCP-AO

# Parser hard caps - a hostile frame must not be able to exhaust a Zero 2W.
_MAX_STACK_PARSE = 32            # label stack entries we will ever walk
_MAX_SRH_SEGMENTS = 64           # segment-list entries we will ever walk
_MAX_IPV6_EXT_CHAIN = 12         # extension headers we will ever walk
_MAX_LDP_MSGS = 64
_MAX_LDP_TLVS = 64
_MAX_RSVP_OBJS = 64
_MAX_BGP_ATTRS = 64
_MAX_BGP_BUF = 65536             # one BGP message max (RFC 4271 s4)

# State caps.  The Zero 2W floor is the whole reason these exist: on a carrier
# tap the flow, session and label spaces are effectively unbounded, and every
# correlator here is a dict keyed on one of them.  Each cap is enforced by
# _prune(), which evicts the oldest quarter by insertion order.  Losing the
# oldest state costs a correlation; not capping costs the process.
_CAP_BGP_FLOWS = 2048
_CAP_LABEL_BINDINGS = 8192
_CAP_LDP_FEC = 8192
_CAP_RSVP_SESSIONS = 4096
_CAP_TTL_PROBE = 4096
_CAP_LDP_FLAP = 2048
_CAP_SID_OWNERS = 8192
_CAP_PREFIX_SID = 8192
_CAP_DEDUP_KEYS = 16384
_PRUNE_FRACTION = 4              # evict len//4 entries when a cap is hit


def _prune(d: dict, cap: int) -> int:
    """Evict the oldest entries once `d` exceeds `cap`.  Returns the count.

    Python dicts preserve insertion order, so the first keys are the least
    recently CREATED.  That is deliberately not an LRU - an LRU needs a touch
    on every read, and the read path here is the packet path."""
    if len(d) <= cap:
        return 0
    drop = max(1, len(d) // _PRUNE_FRACTION)
    for k in list(d)[:drop]:
        d.pop(k, None)
    return drop

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

INTERFACE_ROLES = ("ce", "core", "unknown")


# ---------------------------------------------------------------------------
# Findings catalogue
#
# Three-class split, ciscoguard / vrfwatch precedent:
#   ATTACK   - somebody is doing something to the network right now
#   POSTURE  - the network is configured in a way that permits the attack
#   EXPOSURE - information is on the wire that should not be reachable here
#
# Every code is keyed on frame BODY content or on a declared interface role.
# Nothing here keys on a rate alone except SRM-LDP-SESSION-FLAP, which is
# documented as the one behavioural correlator in the module.
# ---------------------------------------------------------------------------

FINDINGS: Dict[str, Dict[str, str]] = {
    # -- MPLS core / ATTACK -------------------------------------------------
    "SRM-MPLS-ON-CE-PORT": {
        "severity": "critical", "klass": "ATTACK", "category": "mpls",
        "title": "MPLS-labelled frame on a customer-facing interface",
        "desc": "A frame carrying an MPLS shim header was observed on an interface "
                "declared (or defaulted) as customer-facing. The label was chosen by "
                "whatever sent the frame, not by this network. This is the label-injection "
                "/ VRF-hopping primitive.",
    },
    "SRM-RESERVED-LABEL-DATA": {
        "severity": "high", "klass": "ATTACK", "category": "mpls",
        "title": "Reserved or unassigned special-purpose label used for forwarding",
        "desc": "A label in the reserved 0-15 range was used in a position where a "
                "forwarding label is expected. Implicit NULL (3) must never appear on "
                "the wire at all; 4-6 and 8-12 have never been assigned.",
    },
    "SRM-TTL-ZERO-FORWARDED": {
        "severity": "high", "klass": "ATTACK", "category": "mpls",
        "title": "Labelled frame forwarded with an expired TTL",
        "desc": "The outermost label carries TTL 0. A conforming LSR drops or punts "
                "this. Seeing it forwarded is TTL-handling abuse (CVE-2014-7271 class).",
    },
    "SRM-TTL-PROBE-SWEEP": {
        "severity": "medium", "klass": "ATTACK", "category": "mpls",
        "title": "Incrementing MPLS TTL sweep from a single source",
        "desc": "Monotonically increasing label TTL values toward the same label from "
                "one source: an LSP traceroute probe. Expected from operators on a core "
                "interface, so this only fires on a customer-facing interface.",
    },
    "SRM-SBIT-CORRUPT": {
        "severity": "medium", "klass": "ATTACK", "category": "mpls",
        "title": "Bottom-of-stack bit inconsistent with the payload",
        "desc": "S=1 was asserted but the bytes that follow are not a plausible IPv4, "
                "IPv6 or pseudowire payload. MPLS has no length field, so a wrong S bit "
                "silently reinterprets the rest of the frame.",
    },
    "SRM-STACK-UNTERMINATED": {
        "severity": "high", "klass": "ATTACK", "category": "mpls",
        "title": "Label stack never reaches bottom of stack",
        "desc": "The parser walked its hard cap of label stack entries without seeing "
                "S=1. Either the stack is deeper than any real forwarding plane uses, or "
                "the S bit was stripped to make the frame unparseable.",
    },
    "SRM-LABEL-REBIND": {
        "severity": "high", "klass": "ATTACK", "category": "mpls",
        "title": "Label carrying traffic outside its advertised binding",
        "desc": "A label learned from an LDP Label Mapping or a BGP labeled-unicast "
                "advertisement on this same tap is now carrying an inner packet whose "
                "destination is outside the advertised FEC, with no withdraw in between.",
    },
    "SRM-LDP-HELLO-OFFLINK": {
        "severity": "high", "klass": "ATTACK", "category": "ldp",
        "title": "LDP hello from outside the declared peer set",
        "desc": "An LDP discovery hello (targeted, or on a customer-facing interface) "
                "arrived from a source that is not a declared LDP peer. This is the "
                "session-hijack precursor: a bogus peer that wins adjacency can install "
                "label mappings.",
    },
    "SRM-LDP-MAPPING-NO-WITHDRAW": {
        "severity": "medium", "klass": "ATTACK", "category": "ldp",
        "title": "FEC re-bound to a new label with no withdraw or release",
        "desc": "The same FEC was mapped to a different label by the same LSR without an "
                "intervening Label Withdraw, Label Release or Address Withdraw. Orderly "
                "control planes withdraw before rebinding.",
    },
    "SRM-LDP-SESSION-FLAP": {
        "severity": "medium", "klass": "ATTACK", "category": "ldp",
        "title": "LDP session state churn above threshold",
        "desc": "Repeated Initialization or fatal Notification messages for the same LSR "
                "pair inside the flap window. Convergence storm, or a deliberate reset "
                "loop to force label reallocation.",
    },
    "SRM-RSVP-TEAR-NO-INTEGRITY": {
        "severity": "critical", "klass": "ATTACK", "category": "rsvp",
        "title": "RSVP-TE teardown with no INTEGRITY object on an authenticated session",
        "desc": "A PathTear or ResvTear arrived without an INTEGRITY object for a session "
                "whose Path/Resv messages were carrying one. Off-path teardown injection: "
                "the classic RSVP-TE LSP takedown.",
    },
    # -- SR-MPLS / ATTACK ---------------------------------------------------
    "SRM-SID-OUT-OF-SRGB": {
        "severity": "high", "klass": "ATTACK", "category": "sr-mpls",
        "title": "Segment identifier outside the declared SRGB",
        "desc": "A label inside the segment-routing global block range was observed with "
                "a value the declared SRGB does not cover. Either a forged SID or an "
                "SRGB the operator did not declare.",
    },
    "SRM-SID-COLLISION": {
        "severity": "high", "klass": "ATTACK", "category": "sr-mpls",
        "title": "Same SID index claimed by two distinct originators",
        "desc": "Two different BGP originators advertised the same Prefix-SID label index "
                "for different prefixes. Unless the SID is a declared anycast SID, one of "
                "them is claiming a segment it does not own.",
    },
    "SRM-SR-STACK-LOOP": {
        "severity": "medium", "klass": "ATTACK", "category": "sr-mpls",
        "title": "Segment list repeats a segment identifier",
        "desc": "The same SID appears more than once in one label stack. A legitimate "
                "SR policy encodes a loop-free path; a repeat is a hand-built stack.",
    },
    "SRM-SR-MAPPING-CONFLICT": {
        "severity": "high", "klass": "ATTACK", "category": "sr-mpls",
        "title": "Conflicting Prefix-SID index for the same prefix",
        "desc": "The same prefix was advertised with two different SID indexes for the "
                "same algorithm. The SR control plane is being fed inconsistent "
                "segment-to-prefix mappings. Sources are compared across BGP, IS-IS and "
                "OSPFv2, so a cross-protocol disagreement is visible too.",
    },
    "SRM-SRGB-CONFLICT": {
        "severity": "high", "klass": "ATTACK", "category": "sr-mpls",
        "title": "Advertised SRGB is self-overlapping, changed, or outside the declared block",
        "desc": "RFC 8667 s3.1 forbids an originator advertising overlapping SRGB "
                "descriptors, and warns that changing an advertised range churns the FIB "
                "and blackholes traffic during convergence. This also fires when an "
                "advertised SRGB falls outside the operator-declared --srgb.",
    },
    "SRM-ADJ-SID-UNSTABLE": {
        "severity": "medium", "klass": "ATTACK", "category": "sr-mpls",
        "title": "Persistent Adj-SID changed value for the same adjacency",
        "desc": "RFC 8667 s2.2.1: when the P-Flag is set the Adj-SID MUST be persistent "
                "across restart and interface flap. A P-flagged Adj-SID that changes "
                "value for the same originator and neighbour is either a spec-violating "
                "implementation or somebody re-advertising the adjacency.",
    },
    "SRM-SR-ALGO-UNEXPECTED": {
        "severity": "medium", "klass": "ATTACK", "category": "sr-mpls",
        "title": "Prefix-SID advertised with an algorithm its originator never advertised",
        "desc": "RFC 8667 s2.1: a router receiving a Prefix-SID whose algorithm the "
                "originator has not advertised in its SR-Algorithm sub-TLV MUST ignore "
                "it. Both halves must be seen on this tap before the rule arms.",
    },
    "SRM-SID-FLAGS-INVALID": {
        "severity": "medium", "klass": "ATTACK", "category": "sr-mpls",
        "title": "SID advertised with an invalid V-Flag / L-Flag combination",
        "desc": "RFC 8667 s2.1.1.1 and RFC 8665 s5: only V=0,L=0 (global index) and "
                "V=1,L=1 (local label) are valid. Every other combination MUST be "
                "ignored by a conforming receiver, so one on the wire was not produced "
                "by a conforming one.",
    },
    # -- SRv6 / ATTACK ------------------------------------------------------
    "SRM-SRH-ON-CE-PORT": {
        "severity": "critical", "klass": "ATTACK", "category": "srv6",
        "title": "Segment Routing Header on a customer-facing interface",
        "desc": "An SRH crossed a domain boundary. RFC 8754 s5.1 requires an SR domain to "
                "drop SRH-bearing packets arriving from outside it. The segment list was "
                "chosen by whatever sent the packet: source routing into the core.",
    },
    "SRM-SRH-DA-MISMATCH": {
        "severity": "high", "klass": "ATTACK", "category": "srv6",
        "title": "IPv6 destination address does not match the active segment",
        "desc": "RFC 8754 s4.1: while Segments Left is non-zero the destination address "
                "equals Segment List[Segments Left]. A mismatch means the SRH or the DA "
                "was rewritten in transit.",
    },
    "SRM-SRH-MALFORMED": {
        "severity": "high", "klass": "ATTACK", "category": "srv6",
        "title": "Structurally invalid Segment Routing Header",
        "desc": "Segments Left exceeds Last Entry, or Hdr Ext Len does not account for "
                "the declared segment list. RFC 8754 s4.3.1.1 requires this packet be "
                "discarded; a node that processes it anyway can be steered anywhere.",
    },
    "SRM-SRV6-SID-OUT-OF-LOCATOR": {
        "severity": "high", "klass": "ATTACK", "category": "srv6",
        "title": "Active SRv6 SID outside every declared locator block",
        "desc": "The active segment is not covered by any declared SRv6 locator. Inside "
                "the SR domain that is a forged SID; on the edge it is a leak.",
    },
    "SRM-SRV6-FUNCTION-UNKNOWN": {
        "severity": "medium", "klass": "ATTACK", "category": "srv6",
        "title": "SRv6 SID in a declared locator with an undeclared function",
        "desc": "The locator matches, so the SID claims to be ours, but the function bits "
                "are not in the declared function map. Function-space probing.",
    },
    # -- POSTURE ------------------------------------------------------------
    "SRM-LDP-NO-MD5": {
        "severity": "high", "klass": "POSTURE", "category": "ldp",
        "title": "LDP session established without TCP-MD5 or TCP-AO",
        "desc": "The tcp/646 handshake carried neither a TCP-MD5 signature (RFC 2385) "
                "nor TCP-AO (RFC 5925). Any host that can reach the LSR can attempt to "
                "open an LDP session and inject label mappings.",
    },
    "SRM-RSVP-NO-INTEGRITY": {
        "severity": "medium", "klass": "POSTURE", "category": "rsvp",
        "title": "RSVP-TE session carries no INTEGRITY object",
        "desc": "No message for this RSVP session has ever carried an INTEGRITY object. "
                "Teardown and reservation messages are unauthenticated and spoofable from "
                "anywhere that can reach the interface.",
    },
    "SRM-ENTROPY-LABEL-ANOMALY": {
        "severity": "medium", "klass": "POSTURE", "category": "mpls",
        "title": "Malformed entropy label indicator or entropy label",
        "desc": "RFC 6790: the ELI (label 7) must not be at the bottom of the stack, must "
                "be immediately followed by the entropy label, and both carry TTL 0. A "
                "violation means the entropy pair is being used as a forwarding label.",
    },
    "SRM-EXPLICIT-NULL-EXPOSED": {
        "severity": "low", "klass": "POSTURE", "category": "mpls",
        "title": "Explicit NULL label observed above the bottom of the stack",
        "desc": "Explicit NULL (0 or 2) is only meaningful as the last label. Above the "
                "bottom of stack it means penultimate-hop behaviour is not what the "
                "topology implies.",
    },
    "SRM-SRH-NO-HMAC": {
        "severity": "medium", "klass": "POSTURE", "category": "srv6",
        "title": "SRH without an HMAC TLV where policy requires one",
        "desc": "--require-srh-hmac is set but this SRH carried no HMAC TLV (RFC 8754 "
                "s2.1.2). The segment list is unauthenticated.",
    },
    # -- EXPOSURE -----------------------------------------------------------
    "SRM-LABEL-STACK-DEPTH": {
        "severity": "low", "klass": "EXPOSURE", "category": "mpls",
        "title": "Label stack deeper than the declared expectation",
        "desc": "Stack depth above --max-stack-depth. Deep stacks are how SR policies "
                "encode long explicit paths and how an attacker encodes one too.",
    },
    "SRM-SRH-PATH-DISCLOSURE": {
        "severity": "low", "klass": "EXPOSURE", "category": "srv6",
        "title": "Full SRv6 segment list readable on a customer-facing interface",
        "desc": "An SRH exposes every hop of the intended path in cleartext. On a "
                "customer-facing interface that is free internal topology.",
    },
    # -- Operational / fail-loud -------------------------------------------
    "SRM-ROLE-UNDECLARED": {
        "severity": "info", "klass": "POSTURE", "category": "config",
        "title": "Interface role not declared; presence rules default to customer-facing",
        "desc": "--role was not given. vrfwatch precedent: an undeclared interface fails "
                "loud toward CE, so MPLS and SRH presence rules stay armed. Declare "
                "--role core on a backbone tap to silence them.",
    },
    "SRM-SR-CAP-NOT-SEEN": {
        "severity": "info", "klass": "POSTURE", "category": "config",
        "title": "SID indexes observed but no SR-Capabilities advertisement on this tap",
        "desc": "Index-form SIDs resolve against the ORIGINATOR's advertised SRGB. No "
                "IS-IS SR-Capabilities or OSPF SID/Label Range advertisement has been "
                "seen here, so index resolution falls back to the operator-declared "
                "--srgb rather than the originator's own block.",
    },
    "SRM-IGP-SR-TOPOLOGY": {
        "severity": "low", "klass": "EXPOSURE", "category": "sr-mpls",
        "title": "IGP segment routing advertisements readable on a customer-facing interface",
        "desc": "Prefix-SID, Adj-SID and SRGB advertisements expose the segment map of "
                "the whole IGP domain. On a customer-facing interface that is the label "
                "plan handed over for free. Generic IGP adjacency and authentication "
                "issues stay with isiswatch / ospfwatch; this is the SR-specific half.",
    },
    "SRM-SRGB-UNDECLARED": {
        "severity": "info", "klass": "POSTURE", "category": "config",
        "title": "SR-MPLS traffic observed with no SRGB declared",
        "desc": "Labels consistent with segment routing were seen but --srgb was not "
                "given, so the SID conformance rules are disarmed. Declare the SRGB to "
                "arm them.",
    },
    "SRM-SRV6-LOCATOR-UNDECLARED": {
        "severity": "info", "klass": "POSTURE", "category": "config",
        "title": "SRv6 traffic observed with no locator block declared",
        "desc": "SRHs were seen but --srv6-locator was not given, so the SID conformance "
                "rules are disarmed. Declare the locator to arm them.",
    },
    "SRM-CONFIG-BPF-OVERRIDE": {
        "severity": "info", "klass": "POSTURE", "category": "config",
        "title": "Non-empty BPF filter supplied",
        "desc": "vrfwatch LESSON F/H: the default filter is deliberately empty because a "
                "kernel filter can drop the exact frames this module exists to see. A "
                "supplied --bpf is recorded so a later quiet period is explainable.",
    },
}

ATTACK_CODES = frozenset(c for c, m in FINDINGS.items() if m["klass"] == "ATTACK")
POSTURE_CODES = frozenset(c for c, m in FINDINGS.items() if m["klass"] == "POSTURE")
EXPOSURE_CODES = frozenset(c for c, m in FINDINGS.items() if m["klass"] == "EXPOSURE")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """Runtime configuration.  Every attribute here must be READ somewhere in
    the module - the conformance tier walks the AST and fails on a dead knob."""

    iface: str = "eth0"
    role: str = "unknown"                       # ce | core | unknown
    bpf: str = ""                               # deliberately empty, LESSON F/H
    min_severity: str = "info"
    dedup_window: float = 60.0
    max_stack_depth: int = 8                    # EXPOSURE threshold, not a parse cap
    srgb: Optional[Tuple[int, int]] = None      # (base, base+range-1) inclusive
    anycast_sids: Tuple[int, ...] = ()
    srv6_locators: Tuple[Any, ...] = ()         # ip_network objects
    srv6_functions: Tuple[int, ...] = ()        # declared function values
    srv6_function_bits: int = 16                # bits of function field after locator
    require_srh_hmac: bool = False
    ldp_peers: Tuple[Any, ...] = ()             # ip_address objects
    ldp_flap_threshold: int = 4
    ldp_flap_window: float = 60.0
    ttl_probe_threshold: int = 4
    ttl_probe_window: float = 20.0
    local_nets: Tuple[Any, ...] = ()            # ip_network objects, inner-dst scope
    output: Optional[str] = None                # JSONL path; None = stdout
    quiet: bool = False

    def role_is_ce(self) -> bool:
        """Undeclared fails loud toward customer-facing (vrfwatch precedent)."""
        return self.role in ("ce", "unknown")


def parse_srgb(text: str) -> Tuple[int, int]:
    """'16000-23999' or '16000:8000' (base:range) -> inclusive (lo, hi)."""
    text = text.strip()
    if "-" in text:
        lo_s, hi_s = text.split("-", 1)
        lo, hi = int(lo_s), int(hi_s)
    elif ":" in text:
        base_s, size_s = text.split(":", 1)
        lo = int(base_s)
        hi = lo + int(size_s) - 1
    else:
        raise ValueError("SRGB must be 'lo-hi' or 'base:range'")
    if lo < 16 or hi > LABEL_MAX or hi < lo:
        raise ValueError("SRGB out of the legal 16..%d label range" % LABEL_MAX)
    return (lo, hi)


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------

class Emitter:
    """Line-buffered JSONL emitter with a time-windowed dedup key."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._min_rank = _SEV_RANK[cfg.min_severity]
        self._seen: Dict[Tuple[str, str], float] = {}
        self._fh = None
        self.records: List[Dict[str, Any]] = []
        self.collect = False
        self.counts: Dict[str, int] = defaultdict(int)
        self.suppressed = 0
        self.evictions = 0

    def open(self) -> None:
        if self.cfg.output:
            self._fh = open(self.cfg.output, "a", buffering=1)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def emit(self, code: str, key: str = "", ts: Optional[float] = None,
             **evidence: Any) -> Optional[Dict[str, Any]]:
        meta = FINDINGS.get(code)
        if meta is None:
            raise KeyError("unknown finding code %r" % code)
        if _SEV_RANK[meta["severity"]] < self._min_rank:
            return None
        now = time.time() if ts is None else ts
        dk = (code, key)
        prev = self._seen.get(dk)
        if prev is not None and (now - prev) < self.cfg.dedup_window:
            self.suppressed += 1
            return None
        self._seen[dk] = now
        if len(self._seen) > _CAP_DEDUP_KEYS:
            cutoff = now - self.cfg.dedup_window
            for k in [k for k, v in self._seen.items() if v < cutoff]:
                self._seen.pop(k, None)
            self.evictions += _prune(self._seen, _CAP_DEDUP_KEYS)

        rec = {
            "ts": round(now, 6),
            "module": MODULE_NAME,
            "version": __version__,
            "code": code,
            "severity": meta["severity"],
            "class": meta["klass"],
            "category": meta["category"],
            "title": meta["title"],
            "iface": self.cfg.iface,
            "role": self.cfg.role,
            "key": key,
            "evidence": evidence,
        }
        self.counts[code] += 1
        if self.collect:
            self.records.append(rec)
        line = json.dumps(rec, sort_keys=True, default=str)
        if self._fh:
            self._fh.write(line + "\n")
        elif not self.cfg.quiet:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        return rec


# ---------------------------------------------------------------------------
# Parsers - pure bytes in, dicts out.  No third-party imports on this path.
# ---------------------------------------------------------------------------

class ParseError(Exception):
    """Raised on structurally impossible input.  Callers count, never crash."""


@dataclass(frozen=True)
class LSE:
    """One MPLS label stack entry (RFC 3032 s2.1)."""
    label: int
    tc: int
    s: int
    ttl: int
    depth: int      # 0 = outermost


def parse_label_stack(data: bytes, max_entries: int = _MAX_STACK_PARSE
                      ) -> Tuple[List[LSE], int, bool]:
    """Walk an MPLS label stack.

    Returns (entries, payload_offset, terminated).  `terminated` is False when
    the hard cap was hit without seeing S=1 - the caller turns that into
    SRM-STACK-UNTERMINATED rather than guessing where the payload starts.
    """
    entries: List[LSE] = []
    off = 0
    n = len(data)
    while off + 4 <= n and len(entries) < max_entries:
        word = struct.unpack_from("!I", data, off)[0]
        lse = LSE(
            label=(word >> 12) & 0xFFFFF,
            tc=(word >> 9) & 0x7,
            s=(word >> 8) & 0x1,
            ttl=word & 0xFF,
            depth=len(entries),
        )
        entries.append(lse)
        off += 4
        if lse.s:
            return entries, off, True
    if not entries:
        raise ParseError("truncated label stack")
    return entries, off, False


def classify_mpls_payload(data: bytes) -> str:
    """Best-effort classification of what sits below the bottom of stack.

    MPLS has no protocol/length field, so this is the only handle there is.
    Deliberately conservative: anything not clearly IPv4/IPv6/pseudowire is
    'unknown', which is what SRM-SBIT-CORRUPT keys on.
    """
    if not data:
        return "empty"
    nib = data[0] >> 4
    if nib == 4:
        if len(data) < 20:
            return "unknown"
        ihl = data[0] & 0x0F
        if ihl < 5:
            return "unknown"
        total = struct.unpack_from("!H", data, 2)[0]
        if total < ihl * 4:
            return "unknown"
        return "ipv4"
    if nib == 6:
        if len(data) < 40:
            return "unknown"
        return "ipv6"
    if nib == 0:
        # RFC 4385 pseudowire control word: first nibble 0000.
        return "pw-cw"
    if nib == 1:
        # RFC 5085 associated channel header.
        return "pw-ach"
    return "unknown"


def inner_destination(data: bytes, kind: str) -> Optional[str]:
    """Destination address of the payload below the bottom of stack."""
    try:
        if kind == "ipv4" and len(data) >= 20:
            return str(ipaddress.IPv4Address(data[16:20]))
        if kind == "ipv6" and len(data) >= 40:
            return str(ipaddress.IPv6Address(data[24:40]))
    except (ValueError, ipaddress.AddressValueError):
        return None
    return None


def parse_ethernet(frame: bytes) -> Tuple[int, bytes, List[int]]:
    """Strip Ethernet + any stack of VLAN tags.  Returns (ethertype, payload, vlans)."""
    if len(frame) < 14:
        raise ParseError("runt frame")
    etype = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    vlans: List[int] = []
    guard = 0
    while etype in VLAN_ETHERTYPES and guard < 4:
        if off + 4 > len(frame):
            raise ParseError("truncated VLAN tag")
        tci = struct.unpack_from("!H", frame, off)[0]
        vlans.append(tci & 0x0FFF)
        etype = struct.unpack_from("!H", frame, off + 2)[0]
        off += 4
        guard += 1
    return etype, frame[off:], vlans


def walk_ipv6_headers(data: bytes) -> Tuple[Optional[Dict[str, Any]], int, Optional[bytes]]:
    """Walk the IPv6 extension-header chain looking for a Routing Header.

    Returns (srh_or_None, final_next_header, raw_srh_bytes_or_None).
    """
    if len(data) < 40:
        raise ParseError("truncated IPv6 header")
    nh = data[6]
    off = 40
    hops = 0
    while hops < _MAX_IPV6_EXT_CHAIN:
        if nh not in IPV6_EXT_HEADERS:
            return None, nh, None
        if nh == IPPROTO_IPV6_FRAG:
            if off + 8 > len(data):
                raise ParseError("truncated fragment header")
            nh = data[off]
            off += 8
            hops += 1
            continue
        if off + 2 > len(data):
            raise ParseError("truncated extension header")
        this_nh = data[off]
        hdr_ext_len = data[off + 1]
        ext_len = (hdr_ext_len + 1) * 8
        if nh == IPPROTO_IPV6_ROUTE:
            if off + 8 > len(data):
                raise ParseError("truncated routing header")
            if data[off + 2] == SRH_ROUTING_TYPE:
                raw = data[off:off + ext_len]
                srh = parse_srh(data, off, len(data))
                return srh, this_nh, raw
        if nh == IPPROTO_AH:
            ext_len = (hdr_ext_len + 2) * 4
        if ext_len <= 0 or off + ext_len > len(data):
            raise ParseError("extension header length overruns packet")
        nh = this_nh
        off += ext_len
        hops += 1
    raise ParseError("extension header chain too long")


def parse_srh(data: bytes, off: int, cap: int) -> Dict[str, Any]:
    """Parse a Segment Routing Header (RFC 8754 s2) at `off` inside `data`.

    Structural violations are RECORDED, not raised - SRM-SRH-MALFORMED is a
    finding, so the parser must survive the very packets it exists to report.
    Only genuine truncation raises.
    """
    if off + 8 > cap:
        raise ParseError("truncated SRH")
    next_header = data[off]
    hdr_ext_len = data[off + 1]
    routing_type = data[off + 2]
    segments_left = data[off + 3]
    last_entry = data[off + 4]
    flags = data[off + 5]
    tag = struct.unpack_from("!H", data, off + 6)[0]

    declared_len = (hdr_ext_len + 1) * 8
    seg_area = off + 8
    # How many complete segments the header actually claims to carry.
    claimed = last_entry + 1
    available = max(0, min(cap, off + declared_len) - seg_area) // SRV6_SID_LEN
    readable = min(claimed, available, _MAX_SRH_SEGMENTS)

    segments: List[str] = []
    for i in range(readable):
        raw = data[seg_area + i * SRV6_SID_LEN: seg_area + (i + 1) * SRV6_SID_LEN]
        if len(raw) < SRV6_SID_LEN:
            break
        segments.append(str(ipaddress.IPv6Address(raw)))

    # RFC 8754 s2: Hdr Ext Len must account for the segment list; TLVs may follow.
    min_ext_len = claimed * 2                       # in 8-octet units, minus the 8-byte fixed part
    len_consistent = hdr_ext_len >= min_ext_len

    # TLVs occupy whatever the declared length leaves after the segment list.
    tlv_start = seg_area + claimed * SRV6_SID_LEN
    tlv_end = min(cap, off + declared_len)
    tlvs = parse_srh_tlvs(data, tlv_start, tlv_end) if tlv_end > tlv_start else []

    return {
        "next_header": next_header,
        "hdr_ext_len": hdr_ext_len,
        "routing_type": routing_type,
        "segments_left": segments_left,
        "last_entry": last_entry,
        "flags": flags,
        "tag": tag,
        "segments": segments,
        "segments_readable": readable,
        "segments_claimed": claimed,
        "len_consistent": len_consistent,
        "sl_valid": segments_left <= last_entry,
        "tlv_types": [t[0] for t in tlvs],
        "has_hmac": any(t[0] == SRH_TLV_HMAC for t in tlvs),
        "declared_len": declared_len,
    }


def parse_srh_tlvs(data: bytes, start: int, end: int) -> List[Tuple[int, int]]:
    """Return [(type, length)] for the TLVs in the SRH trailer."""
    out: List[Tuple[int, int]] = []
    off = start
    guard = 0
    while off < end and guard < 32:
        t = data[off]
        if t == SRH_TLV_PAD1:
            off += 1
            guard += 1
            continue
        if off + 2 > end:
            break
        ln = data[off + 1]
        out.append((t, ln))
        off += 2 + ln
        guard += 1
    return out


def active_segment(srh: Dict[str, Any]) -> Optional[str]:
    """Segment List[Segments Left] - the segment the packet is heading to."""
    sl = srh["segments_left"]
    segs = srh["segments"]
    if 0 <= sl < len(segs):
        return segs[sl]
    return None


# -- LDP --------------------------------------------------------------------

def parse_ldp_pdu(data: bytes) -> Dict[str, Any]:
    """Parse an LDP PDU (RFC 5036 s3.1) and its messages."""
    if len(data) < 10:
        raise ParseError("truncated LDP PDU")
    version, pdu_len = struct.unpack_from("!HH", data, 0)
    if version != LDP_VERSION:
        raise ParseError("not LDP version 1")
    lsr_id = str(ipaddress.IPv4Address(data[4:8]))
    label_space = struct.unpack_from("!H", data, 8)[0]
    end = min(len(data), 4 + pdu_len)
    off = 10
    msgs: List[Dict[str, Any]] = []
    guard = 0
    while off + 4 <= end and guard < _MAX_LDP_MSGS:
        mtype = struct.unpack_from("!H", data, off)[0] & 0x7FFF
        mlen = struct.unpack_from("!H", data, off + 2)[0]
        body_start = off + 4
        body_end = min(end, body_start + mlen)
        if mlen < 4 or body_end <= body_start:
            break
        msg_id = struct.unpack_from("!I", data, body_start)[0] if body_end - body_start >= 4 else 0
        tlvs = parse_ldp_tlvs(data, body_start + 4, body_end)
        msgs.append({"type": mtype, "id": msg_id, "tlvs": tlvs})
        off = body_start + mlen
        guard += 1
    return {"version": version, "pdu_len": pdu_len, "lsr_id": lsr_id,
            "label_space": label_space, "messages": msgs}


def parse_ldp_tlvs(data: bytes, start: int, end: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    off = start
    guard = 0
    while off + 4 <= end and guard < _MAX_LDP_TLVS:
        raw_type = struct.unpack_from("!H", data, off)[0]
        ttype = raw_type & 0x3FFF
        tlen = struct.unpack_from("!H", data, off + 2)[0]
        vstart = off + 4
        vend = min(end, vstart + tlen)
        if vend < vstart:
            break
        out.append({"type": ttype, "len": tlen, "value": data[vstart:vend]})
        off = vstart + tlen
        guard += 1
    return out


def ldp_hello_flags(tlvs: List[Dict[str, Any]]) -> Optional[int]:
    for t in tlvs:
        if t["type"] == LDP_TLV_COMMON_HELLO and len(t["value"]) >= 4:
            return struct.unpack_from("!H", t["value"], 2)[0]
    return None


def ldp_hello_hold(tlvs: List[Dict[str, Any]]) -> Optional[int]:
    for t in tlvs:
        if t["type"] == LDP_TLV_COMMON_HELLO and len(t["value"]) >= 4:
            return struct.unpack_from("!H", t["value"], 0)[0]
    return None


def ldp_fec_prefixes(tlvs: List[Dict[str, Any]]) -> List[str]:
    """Decode FEC Prefix elements (RFC 5036 s3.4.1) to CIDR strings."""
    out: List[str] = []
    for t in tlvs:
        if t["type"] != LDP_TLV_FEC:
            continue
        v = t["value"]
        off = 0
        guard = 0
        while off < len(v) and guard < 32:
            etype = v[off]
            off += 1
            guard += 1
            if etype == LDP_FEC_WILDCARD:
                out.append("0.0.0.0/0")
                continue
            if etype not in (LDP_FEC_PREFIX, LDP_FEC_HOST):
                break
            if off + 3 > len(v):
                break
            fam = struct.unpack_from("!H", v, off)[0]
            plen = v[off + 2]
            off += 3
            nbytes = (plen + 7) // 8
            if off + nbytes > len(v):
                break
            raw = v[off:off + nbytes]
            off += nbytes
            try:
                if fam == 1:
                    padded = raw + b"\x00" * (4 - len(raw))
                    net = ipaddress.ip_network("%s/%d" % (ipaddress.IPv4Address(padded), plen),
                                               strict=False)
                elif fam == 2:
                    padded = raw + b"\x00" * (16 - len(raw))
                    net = ipaddress.ip_network("%s/%d" % (ipaddress.IPv6Address(padded), plen),
                                               strict=False)
                else:
                    break
                out.append(str(net))
            except (ValueError, ipaddress.AddressValueError):
                break
    return out


def ldp_generic_labels(tlvs: List[Dict[str, Any]]) -> List[int]:
    out: List[int] = []
    for t in tlvs:
        if t["type"] == LDP_TLV_GENERIC_LABEL and len(t["value"]) >= 4:
            out.append(struct.unpack_from("!I", t["value"], 0)[0] & 0xFFFFF)
    return out


# -- RSVP-TE ----------------------------------------------------------------

def parse_rsvp(data: bytes) -> Dict[str, Any]:
    """Parse an RSVP common header (RFC 2205 s3.1) and its object list."""
    if len(data) < 8:
        raise ParseError("truncated RSVP header")
    ver_flags = data[0]
    version = ver_flags >> 4
    if version != RSVP_VERSION:
        raise ParseError("not RSVP version 1")
    msg_type = data[1]
    length = struct.unpack_from("!H", data, 6)[0]
    send_ttl = data[4]
    end = min(len(data), max(8, length))
    off = 8
    objs: List[Dict[str, Any]] = []
    guard = 0
    while off + 4 <= end and guard < _MAX_RSVP_OBJS:
        olen = struct.unpack_from("!H", data, off)[0]
        cnum = data[off + 2]
        ctype = data[off + 3]
        if olen < 4:
            break
        vend = min(end, off + olen)
        objs.append({"class": cnum, "ctype": ctype, "len": olen,
                     "value": data[off + 4:vend]})
        off += olen
        guard += 1
    return {"version": version, "msg_type": msg_type, "length": length,
            "send_ttl": send_ttl, "objects": objs}


def rsvp_session_key(objs: List[Dict[str, Any]]) -> Optional[str]:
    """A stable identity for an RSVP session from its SESSION object."""
    for o in objs:
        if o["class"] == RSVP_OBJ_SESSION and len(o["value"]) >= 8:
            v = o["value"]
            try:
                if o["ctype"] == 7 and len(v) >= 8:            # LSP_TUNNEL_IPv4
                    dest = str(ipaddress.IPv4Address(v[0:4]))
                    tid = struct.unpack_from("!H", v, 6)[0]
                    return "%s/%d" % (dest, tid)
                if o["ctype"] == 8 and len(v) >= 20:           # LSP_TUNNEL_IPv6
                    dest = str(ipaddress.IPv6Address(v[0:16]))
                    tid = struct.unpack_from("!H", v, 18)[0]
                    return "%s/%d" % (dest, tid)
                return "raw:" + v[:8].hex()
            except (ValueError, ipaddress.AddressValueError):
                return "raw:" + v[:8].hex()
    return None


def rsvp_has(objs: List[Dict[str, Any]], class_num: int) -> bool:
    return any(o["class"] == class_num for o in objs)


# -- BGP --------------------------------------------------------------------

def parse_bgp_message(data: bytes) -> Dict[str, Any]:
    """Parse one framed BGP message (RFC 4271 s4.1)."""
    if len(data) < BGP_HDR_LEN:
        raise ParseError("truncated BGP header")
    if data[:16] != BGP_MARKER:
        raise ParseError("bad BGP marker")
    length = struct.unpack_from("!H", data, 16)[0]
    mtype = data[18]
    # RFC 4271 s4.1 bounds the header at 19..4096; RFC 8654 raises the ceiling
    # to 65535 for UPDATE and ROUTE-REFRESH only, and only when negotiated.
    # Without the type check, sixteen 0xff octets followed by anything at all
    # is a "valid" BGP message - the marker IS 0xff, and 0xffff is a legal
    # length.  The conformance discrimination matrix caught exactly that.
    if mtype not in BGP_MSG_TYPES:
        raise ParseError("unknown BGP message type %d" % mtype)
    cap = BGP_MAX_EXT_LEN if mtype in BGP_EXT_LEN_TYPES else BGP_MAX_STD_LEN
    if length < BGP_HDR_LEN or length > cap:
        raise ParseError("illegal BGP length %d for type %d" % (length, mtype))
    body = data[BGP_HDR_LEN:length]
    out: Dict[str, Any] = {"type": mtype, "length": length, "attrs": []}
    if mtype == BGP_MSG_UPDATE:
        out["attrs"] = parse_bgp_update_attrs(body)
    return out


def parse_bgp_update_attrs(body: bytes) -> List[Dict[str, Any]]:
    """Walk the path attributes of a BGP UPDATE."""
    if len(body) < 2:
        return []
    wd_len = struct.unpack_from("!H", body, 0)[0]
    off = 2 + wd_len
    if off + 2 > len(body):
        return []
    pa_len = struct.unpack_from("!H", body, off)[0]
    off += 2
    end = min(len(body), off + pa_len)
    attrs: List[Dict[str, Any]] = []
    guard = 0
    while off + 3 <= end and guard < _MAX_BGP_ATTRS:
        flags = body[off]
        atype = body[off + 1]
        if flags & BGP_ATTR_FLAG_EXT_LEN:
            if off + 4 > end:
                break
            alen = struct.unpack_from("!H", body, off + 2)[0]
            vstart = off + 4
        else:
            alen = body[off + 2]
            vstart = off + 3
        vend = min(end, vstart + alen)
        if vend < vstart:
            break
        attrs.append({"flags": flags, "type": atype, "value": body[vstart:vend]})
        off = vstart + alen
        guard += 1
    return attrs


def parse_prefix_sid(value: bytes) -> Dict[str, Any]:
    """BGP Prefix-SID attribute (RFC 8669 s3): TLVs of {type, len(2), value}."""
    out: Dict[str, Any] = {"label_index": None, "srgb": [], "srv6_service": False}
    off = 0
    guard = 0
    while off + 3 <= len(value) and guard < 16:
        ttype = value[off]
        tlen = struct.unpack_from("!H", value, off + 1)[0]
        vstart = off + 3
        vend = min(len(value), vstart + tlen)
        v = value[vstart:vend]
        if ttype == BGP_PREFIX_SID_TLV_LABEL_INDEX and len(v) >= 7:
            # RESERVED(1) FLAGS(2) LABEL-INDEX(4)
            out["label_index"] = struct.unpack_from("!I", v, 3)[0]
        elif ttype == BGP_PREFIX_SID_TLV_ORIGINATOR_SRGB and len(v) >= 2:
            body = v[2:]
            for i in range(0, len(body) - 5, 6):
                base = int.from_bytes(body[i:i + 3], "big")
                rng = int.from_bytes(body[i + 3:i + 6], "big")
                out["srgb"].append((base, rng))
        elif ttype == BGP_PREFIX_SID_TLV_SRV6_L3_SERVICE:
            out["srv6_service"] = True
        off = vstart + tlen
        guard += 1
    return out


def parse_mp_reach_labeled(value: bytes) -> Dict[str, Any]:
    """MP_REACH_NLRI carrying labelled NLRI (RFC 8277 / RFC 4364).

    Returns {'afi','safi','routes':[(prefix_str, label)]}.
    """
    out: Dict[str, Any] = {"afi": None, "safi": None, "routes": []}
    if len(value) < 5:
        return out
    afi = struct.unpack_from("!H", value, 0)[0]
    safi = value[2]
    out["afi"], out["safi"] = afi, safi
    if safi not in (BGP_SAFI_LABELED_UNICAST, BGP_SAFI_MPLS_VPN):
        return out
    nh_len = value[3]
    off = 4 + nh_len
    if off + 1 > len(value):
        return out
    off += 1                       # reserved octet
    guard = 0
    while off < len(value) and guard < 128:
        bitlen = value[off]
        off += 1
        nbytes = (bitlen + 7) // 8
        if nbytes == 0 or off + nbytes > len(value):
            break
        blob = value[off:off + nbytes]
        off += nbytes
        guard += 1
        if len(blob) < 3:
            continue
        label = (int.from_bytes(blob[0:3], "big")) >> 4
        rest = blob[3:]
        plen = bitlen - 24
        if safi == BGP_SAFI_MPLS_VPN:
            if len(rest) < 8:
                continue
            rest = rest[8:]        # strip the route distinguisher
            plen -= 64
        if plen < 0:
            continue
        try:
            if afi == BGP_AFI_IPV4:
                padded = rest + b"\x00" * (4 - len(rest))
                net = ipaddress.ip_network(
                    "%s/%d" % (ipaddress.IPv4Address(padded[:4]), plen), strict=False)
            elif afi == BGP_AFI_IPV6:
                padded = rest + b"\x00" * (16 - len(rest))
                net = ipaddress.ip_network(
                    "%s/%d" % (ipaddress.IPv6Address(padded[:16]), plen), strict=False)
            else:
                continue
        except (ValueError, ipaddress.AddressValueError):
            continue
        out["routes"].append((str(net), label))
    return out


def parse_bgp_nlri_prefixes(body: bytes) -> List[str]:
    """Plain IPv4 NLRI at the tail of an UPDATE (used for Prefix-SID binding)."""
    if len(body) < 2:
        return []
    wd_len = struct.unpack_from("!H", body, 0)[0]
    off = 2 + wd_len
    if off + 2 > len(body):
        return []
    pa_len = struct.unpack_from("!H", body, off)[0]
    off += 2 + pa_len
    out: List[str] = []
    guard = 0
    while off < len(body) and guard < 128:
        bitlen = body[off]
        off += 1
        nbytes = (bitlen + 7) // 8
        if off + nbytes > len(body) or bitlen > 32:
            break
        raw = body[off:off + nbytes] + b"\x00" * (4 - nbytes)
        off += nbytes
        guard += 1
        try:
            out.append(str(ipaddress.ip_network(
                "%s/%d" % (ipaddress.IPv4Address(raw), bitlen), strict=False)))
        except (ValueError, ipaddress.AddressValueError):
            break
    return out


# -- TCP --------------------------------------------------------------------

def parse_tcp_options(data: bytes, doff_bytes: int) -> List[int]:
    """Return the list of TCP option kinds present in the header."""
    kinds: List[int] = []
    off = 20
    guard = 0
    while off < doff_bytes and off < len(data) and guard < 40:
        kind = data[off]
        guard += 1
        if kind == TCP_OPT_END:
            break
        if kind == TCP_OPT_NOP:
            off += 1
            continue
        if off + 1 >= len(data):
            break
        ln = data[off + 1]
        if ln < 2:
            break
        kinds.append(kind)
        off += ln
    return kinds


# -- IGP-SR: IS-IS (RFC 8667) ----------------------------------------------
#
# sr-mplswatch parses IS-IS and OSPFv2 ONLY to reach their Segment Routing
# sub-TLVs.  Generic IGP security - adjacency hijack, authentication posture,
# LSP flooding, LSA churn - stays with isiswatch / ospfwatch.  The seam is the
# finding, not the parser: everything emitted from this path is SR-specific.


def sid_from_flags(flags: int, blob: bytes, v_mask: int, l_mask: int
                   ) -> Tuple[str, Optional[int]]:
    """Decode a SID/Index/Label field using the V-Flag and L-Flag.

    RFC 8667 s2.1.1.1 (and RFC 8665 s5 for OSPFv2): V=0,L=0 means a 4-octet
    global INDEX into the originator's SRGB; V=1,L=1 means a 3-octet local
    LABEL in the low 20 bits.  Every other combination is invalid and a
    conforming receiver MUST ignore the advertisement - which is exactly why
    seeing one on the wire is worth a finding.
    """
    v = bool(flags & v_mask)
    l = bool(flags & l_mask)
    if not v and not l:
        if len(blob) < 4:
            return ("truncated", None)
        return ("index", struct.unpack_from("!I", blob, 0)[0])
    if v and l:
        if len(blob) < 3:
            return ("truncated", None)
        return ("label", int.from_bytes(blob[0:3], "big") & 0xFFFFF)
    return ("invalid", None)


def parse_isis_pdu(data: bytes) -> Dict[str, Any]:
    """Parse an IS-IS PDU header (ISO 10589 s9) and, for LSPs, its TLVs."""
    if len(data) < 8:
        raise ParseError("truncated IS-IS header")
    if data[0] != ISIS_DISCRIMINATOR:
        raise ParseError("not an IS-IS PDU")
    hdr_len = data[1]
    if data[2] != ISIS_VERSION:
        raise ParseError("unsupported IS-IS version")
    id_len = data[3] or 6
    pdu_type = data[4] & 0x1F
    out: Dict[str, Any] = {"pdu_type": pdu_type, "id_length": id_len,
                           "header_length": hdr_len, "lsp_id": None, "tlvs": []}
    if pdu_type not in ISIS_LSP_TYPES:
        return out                       # IIH/CSNP/PSNP carry no SR sub-TLVs
    off = 8
    if off + 4 + id_len + 2 + 4 + 2 + 1 > len(data):
        raise ParseError("truncated IS-IS LSP header")
    pdu_length = struct.unpack_from("!H", data, off)[0]
    off += 4                             # PDU length + remaining lifetime
    lsp_id = data[off:off + id_len + 2]
    off += id_len + 2
    seq = struct.unpack_from("!I", data, off)[0]
    off += 6                             # sequence number + checksum
    off += 1                             # P/ATT/OL/IS-Type
    end = min(len(data), pdu_length if pdu_length >= off else len(data))
    out["lsp_id"] = lsp_id.hex()
    out["sequence"] = seq
    out["pdu_length"] = pdu_length
    out["tlvs"] = parse_isis_tlvs(data, off, end)
    return out


def parse_isis_tlvs(data: bytes, start: int, end: int,
                    cap: int = _MAX_ISIS_TLVS) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    off = start
    guard = 0
    while off + 2 <= end and guard < cap:
        ttype = data[off]
        tlen = data[off + 1]
        vstart = off + 2
        vend = min(end, vstart + tlen)
        if vend < vstart:
            break
        out.append({"type": ttype, "len": tlen, "value": data[vstart:vend]})
        off = vstart + tlen
        guard += 1
    return out


def parse_isis_subtlvs(value: bytes) -> List[Dict[str, Any]]:
    """Sub-TLVs share the IS-IS 1-octet type / 1-octet length shape."""
    return parse_isis_tlvs(value, 0, len(value), cap=_MAX_ISIS_SUBTLVS)


def isis_prefix_entries(tlv_type: int, value: bytes) -> List[Dict[str, Any]]:
    """Walk TLV 135/235/236/237 entries and return prefix + sub-TLVs.

    TLV 135 (RFC 5305 s3): metric(4) | control(1: U|X|len6) | prefix | subTLVs
    TLV 236 (RFC 5308 s2): metric(4) | control(1: U|X|S)   | plen(1) | prefix
    Multi-topology variants prepend a 2-octet MT ID.
    """
    out: List[Dict[str, Any]] = []
    off = 0
    v6 = tlv_type in (ISIS_TLV_IPV6_REACH, ISIS_TLV_MT_IPV6_REACH)
    if tlv_type in (ISIS_TLV_MT_IPV4_REACH, ISIS_TLV_MT_IPV6_REACH):
        off += 2                          # MT ID
    guard = 0
    while off + 5 <= len(value) and guard < 64:
        guard += 1
        off += 4                          # metric
        control = value[off]
        off += 1
        if v6:
            has_sub = bool(control & 0x20)
            if off >= len(value):
                break
            plen = value[off]
            off += 1
        else:
            has_sub = bool(control & 0x80)
            plen = control & 0x3F
        nbytes = (plen + 7) // 8
        if plen > (128 if v6 else 32) or off + nbytes > len(value):
            break
        raw = value[off:off + nbytes]
        off += nbytes
        subs: List[Dict[str, Any]] = []
        if has_sub:
            if off >= len(value):
                break
            slen = value[off]
            off += 1
            if off + slen > len(value):
                break
            subs = parse_isis_subtlvs(value[off:off + slen])
            off += slen
        try:
            if v6:
                padded = raw + b"\x00" * (16 - len(raw))
                net = ipaddress.ip_network(
                    "%s/%d" % (ipaddress.IPv6Address(padded), plen), strict=False)
            else:
                padded = raw + b"\x00" * (4 - len(raw))
                net = ipaddress.ip_network(
                    "%s/%d" % (ipaddress.IPv4Address(padded), plen), strict=False)
        except (ValueError, ipaddress.AddressValueError):
            break
        out.append({"prefix": str(net), "subtlvs": subs})
    return out


def isis_neighbor_entries(value: bytes) -> List[Dict[str, Any]]:
    """TLV 22 (RFC 5305 s2): neighbour(7) | metric(3) | subTLVlen(1) | subTLVs."""
    out: List[Dict[str, Any]] = []
    off = 0
    guard = 0
    while off + 11 <= len(value) and guard < 64:
        guard += 1
        neigh = value[off:off + 7]
        off += 7
        off += 3                          # metric
        slen = value[off]
        off += 1
        if off + slen > len(value):
            break
        out.append({"neighbor": neigh.hex(),
                    "subtlvs": parse_isis_subtlvs(value[off:off + slen])})
        off += slen
    return out


def parse_isis_prefix_sid(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 8667 s2.1: Flags(1) | Algorithm(1) | SID/Index/Label(4 or 3)."""
    if len(value) < 3:
        return None
    flags, algorithm = value[0], value[1]
    kind, sid = sid_from_flags(flags, value[2:], PSID_FLAG_V, PSID_FLAG_L)
    return {"flags": flags, "algorithm": algorithm, "kind": kind, "sid": sid,
            "node": bool(flags & PSID_FLAG_N),
            "readvertised": bool(flags & PSID_FLAG_R)}


def parse_isis_adj_sid(value: bytes, lan: bool = False,
                       id_len: int = 6) -> Optional[Dict[str, Any]]:
    """RFC 8667 s2.2.1: Flags(1) | Weight(1) | SID.  LAN form (s2.2.2) inserts
    the neighbour System-ID between the weight and the SID."""
    if len(value) < 3:
        return None
    flags, weight = value[0], value[1]
    off = 2
    neighbor = None
    if lan:
        if len(value) < 2 + id_len:
            return None
        neighbor = value[2:2 + id_len].hex()
        off = 2 + id_len
    kind, sid = sid_from_flags(flags, value[off:], ASID_FLAG_V, ASID_FLAG_L)
    return {"flags": flags, "weight": weight, "kind": kind, "sid": sid,
            "neighbor": neighbor, "persistent": bool(flags & ASID_FLAG_P),
            "set": bool(flags & ASID_FLAG_S)}


def parse_isis_sr_ranges(value: bytes) -> Dict[str, Any]:
    """RFC 8667 s3.1 / s3.3: Flags(1) then one or more descriptors of
    Range(3) + SID/Label sub-TLV(type 1) giving the first label."""
    out: Dict[str, Any] = {"flags": value[0] if value else 0, "ranges": []}
    off = 1
    guard = 0
    while off + 3 <= len(value) and guard < 16:
        guard += 1
        rng = int.from_bytes(value[off:off + 3], "big")
        off += 3
        if off + 2 > len(value):
            break
        stype, slen = value[off], value[off + 1]
        off += 2
        if off + slen > len(value) or stype != ISIS_SUB_SID_LABEL:
            break
        blob = value[off:off + slen]
        off += slen
        if slen == 3:
            base = int.from_bytes(blob, "big") & 0xFFFFF
        elif slen == 4:
            base = struct.unpack_from("!I", blob, 0)[0]
        else:
            break
        if rng > 0:
            out["ranges"].append((base, rng))
    return out


def parse_isis_sr_algorithms(value: bytes) -> List[int]:
    """RFC 8667 s3.2: a list of 1-octet algorithm identifiers."""
    return list(value[:32])


# -- IGP-SR: OSPFv2 (RFC 7684 opaque LSAs, RFC 8665 SR) ---------------------

def parse_ospf_header(data: bytes) -> Dict[str, Any]:
    if len(data) < OSPF_HDR_LEN:
        raise ParseError("truncated OSPF header")
    if data[0] != OSPF_VERSION:
        raise ParseError("not OSPFv2")
    return {"version": data[0], "type": data[1],
            "length": struct.unpack_from("!H", data, 2)[0],
            "router_id": str(ipaddress.IPv4Address(data[4:8])),
            "area_id": str(ipaddress.IPv4Address(data[8:12])),
            "autype": struct.unpack_from("!H", data, 14)[0]}


def parse_ospf_lsas(data: bytes) -> List[Dict[str, Any]]:
    """LS Update (RFC 2328 sA.3.5): count(4) then that many LSAs."""
    if len(data) < OSPF_HDR_LEN + 4:
        return []
    count = struct.unpack_from("!I", data, OSPF_HDR_LEN)[0]
    off = OSPF_HDR_LEN + 4
    out: List[Dict[str, Any]] = []
    guard = 0
    while off + OSPF_LSA_HDR_LEN <= len(data) and guard < min(count, _MAX_OSPF_LSAS):
        guard += 1
        ls_type = data[off + 3]
        ls_id = data[off + 4:off + 8]
        adv = str(ipaddress.IPv4Address(data[off + 8:off + 12]))
        length = struct.unpack_from("!H", data, off + 18)[0]
        if length < OSPF_LSA_HDR_LEN:
            break
        end = min(len(data), off + length)
        lsa = {"ls_type": ls_type, "adv_router": adv, "length": length,
               "opaque_type": ls_id[0], "opaque_id": int.from_bytes(ls_id[1:], "big"),
               "body": data[off + OSPF_LSA_HDR_LEN:end]}
        out.append(lsa)
        off += length
    return out


def parse_ospf_tlvs(value: bytes, cap: int = _MAX_OSPF_TLVS) -> List[Dict[str, Any]]:
    """RFC 3630 TLV shape used by RFC 7684/7770/8665: type(2) len(2) value,
    with the value padded out to a 4-octet boundary."""
    out: List[Dict[str, Any]] = []
    off = 0
    guard = 0
    while off + 4 <= len(value) and guard < cap:
        guard += 1
        ttype, tlen = struct.unpack_from("!HH", value, off)
        vstart = off + 4
        vend = min(len(value), vstart + tlen)
        if vend < vstart:
            break
        out.append({"type": ttype, "len": tlen, "value": value[vstart:vend]})
        off = vstart + tlen + ((-tlen) % 4)
    return out


def parse_ospf_ext_prefix(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 7684 s2.1: RouteType(1) PrefixLength(1) AF(1) Flags(1) Prefix subTLVs."""
    if len(value) < 4:
        return None
    plen, af = value[1], value[2]
    if af != 0:                            # 0 == IPv4 per RFC 7684
        return None
    nwords = (plen + 31) // 32
    off = 4 + nwords * 4
    if plen > 32 or off > len(value):
        return None
    raw = value[4:4 + nwords * 4] + b"\x00" * 4
    try:
        net = ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv4Address(raw[:4]), plen), strict=False)
    except (ValueError, ipaddress.AddressValueError):
        return None
    return {"prefix": str(net), "route_type": value[0],
            "subtlvs": parse_ospf_tlvs(value[off:])}


def parse_ospf_ext_link(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 7684 s3.1: LinkType(1) Reserved(3) LinkID(4) LinkData(4) subTLVs."""
    if len(value) < 12:
        return None
    return {"link_type": value[0],
            "link_id": str(ipaddress.IPv4Address(value[4:8])),
            "subtlvs": parse_ospf_tlvs(value[12:])}


def parse_ospf_prefix_sid(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 8665 s5: Flags(1) Reserved(1) MT-ID(1) Algorithm(1) SID(4 or 3)."""
    if len(value) < 5:
        return None
    flags, algorithm = value[0], value[3]
    kind, sid = sid_from_flags(flags, value[4:], OSPF_PSID_FLAG_V, OSPF_PSID_FLAG_L)
    return {"flags": flags, "algorithm": algorithm, "kind": kind, "sid": sid,
            "mapping_server": bool(flags & OSPF_PSID_FLAG_M)}


def parse_ospf_adj_sid(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 8665 s6.1: Flags(1) Reserved(1) MT-ID(1) Weight(1) SID(4 or 3)."""
    if len(value) < 5:
        return None
    flags, weight = value[0], value[3]
    kind, sid = sid_from_flags(flags, value[4:], OSPF_ASID_FLAG_V, OSPF_ASID_FLAG_L)
    return {"flags": flags, "weight": weight, "kind": kind, "sid": sid,
            "set": bool(flags & OSPF_ASID_FLAG_S)}


def parse_ospf_sid_range(value: bytes) -> Dict[str, Any]:
    """RFC 8665 s3.2 / s3.3: RangeSize(3) Reserved(1) then a SID/Label sub-TLV."""
    out: Dict[str, Any] = {"ranges": []}
    if len(value) < 8:
        return out
    rng = int.from_bytes(value[0:3], "big")
    for sub in parse_ospf_tlvs(value[4:]):
        if sub["type"] != OSPF_SUB_SID_LABEL:
            continue
        blob = sub["value"]
        if len(blob) == 3:
            base = int.from_bytes(blob, "big") & 0xFFFFF
        elif len(blob) == 4:
            base = struct.unpack_from("!I", blob, 0)[0]
        else:
            continue
        if rng > 0:
            out["ranges"].append((base, rng))
    return out


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class SRMPLSEngine:
    """Stateful correlator.  One instance per capture interface."""

    def __init__(self, cfg: Config, emitter: Emitter):
        self.cfg = cfg
        self.out = emitter

        # -- MPLS / label bindings ------------------------------------------
        # label -> {"fec": ip_network, "src": str, "ts": float, "ambiguous": bool}
        self.label_bindings: Dict[int, Dict[str, Any]] = {}
        # (lsr_id, fec_str) -> label   (LDP orderly-rebinding check)
        self.ldp_fec_label: Dict[Tuple[str, str], int] = {}
        # (src, outer_label) -> deque[(ttl, ts)]
        self.ttl_probe: Dict[Tuple[str, int], deque] = defaultdict(lambda: deque(maxlen=16))
        # (lsr_a, lsr_b) -> deque[ts]
        self.ldp_flap: Dict[str, deque] = defaultdict(lambda: deque(maxlen=32))

        # -- RSVP -----------------------------------------------------------
        # session key -> {"integrity": bool, "msgs": int, "posture_fired": bool}
        self.rsvp_sessions: Dict[str, Dict[str, Any]] = {}

        # -- BGP-SR ---------------------------------------------------------
        self.bgp_bufs: Dict[Tuple[str, int, str, int], bytearray] = {}

        # -- unified SR ledger, fed by BGP, IS-IS and OSPFv2 ----------------
        # Keyed by (algorithm, index) so a collision is visible even when the
        # two claimants speak different protocols.
        self.sid_owners: Dict[Tuple[int, int], Dict[str, Tuple[str, str]]] = defaultdict(dict)
        self.prefix_sid: Dict[str, Tuple[int, int, str, str]] = {}
        self.srgb_adv: Dict[str, List[Tuple[int, int]]] = {}
        self.srlb_adv: Dict[str, List[Tuple[int, int]]] = {}
        self.sr_algos: Dict[str, set] = {}
        self.adj_sids: Dict[Tuple[str, str], int] = {}

        # -- one-shot latches -----------------------------------------------
        self._role_warned = False
        self._srgb_warned = False
        self._locator_warned = False
        self._srcap_warned = False

        # -- counters -------------------------------------------------------
        self.stats: Dict[str, int] = defaultdict(int)

    # -- helpers ------------------------------------------------------------

    def _fire(self, code: str, key: str, ts: float, **ev: Any) -> None:
        self.out.emit(code, key=key, ts=ts, **ev)

    def _warn_role(self, ts: float) -> None:
        if self.cfg.role == "unknown" and not self._role_warned:
            self._role_warned = True
            self._fire("SRM-ROLE-UNDECLARED", "iface:%s" % self.cfg.iface, ts,
                       iface=self.cfg.iface,
                       effect="presence rules armed as customer-facing")

    def _ce_gate(self, ts: float) -> bool:
        """THE single place the customer-facing decision is made.

        Every presence rule goes through here, so the fail-loud latch cannot
        drift out of sync with the rules it explains.  It did: the scapy pcap
        tier caught an LDP-only capture emitting a high-severity
        SRM-LDP-HELLO-OFFLINK - which fires only BECAUSE the role defaulted to
        customer-facing - with no SRM-ROLE-UNDECLARED to say so.  The latch
        used to be raised by hand in the MPLS and IPv6 paths only."""
        self._warn_role(ts)
        return self.cfg.role_is_ce()

    def _in_local(self, addr: str) -> Optional[bool]:
        if not self.cfg.local_nets:
            return None
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return None
        return any(ip in n for n in self.cfg.local_nets
                   if n.version == ip.version)

    def _in_locator(self, addr: str) -> Optional[Any]:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return None
        for net in self.cfg.srv6_locators:
            if net.version == ip.version and ip in net:
                return net
        return None

    # -- top-level dispatch -------------------------------------------------

    def handle_frame(self, frame: bytes, ts: float) -> None:
        self.stats["frames"] += 1
        try:
            etype, payload, vlans = parse_ethernet(frame)
        except ParseError:
            self.stats["parse_errors"] += 1
            return
        try:
            if etype in MPLS_ETHERTYPES:
                self.handle_mpls(payload, ts, etype, vlans)
            elif etype == ETHERTYPE_IPV6:
                self.handle_ipv6(payload, ts)
            elif etype == ETHERTYPE_IPV4:
                self.handle_ipv4(payload, ts)
            elif etype <= ETH_MAX_LENGTH_FIELD:
                # 802.3: the type/length slot is a LENGTH, and IS-IS rides on
                # LLC underneath it rather than on an ethertype.
                self.handle_llc(payload[:etype], ts)
        except ParseError:
            self.stats["parse_errors"] += 1

    # -- MPLS ---------------------------------------------------------------

    def handle_mpls(self, data: bytes, ts: float, etype: int, vlans: List[int]) -> None:
        self.stats["mpls"] += 1
        entries, poff, terminated = parse_label_stack(data)
        outer = entries[0]
        labels = [e.label for e in entries]
        stack_str = "/".join(str(x) for x in labels)

        # ATTACK: label-bearing frame where no label should exist at all.
        if self._ce_gate(ts):
            self._fire("SRM-MPLS-ON-CE-PORT", "label:%d" % outer.label, ts,
                       outer_label=outer.label, stack=labels, depth=len(entries),
                       ttl=outer.ttl, tc=outer.tc, ethertype=hex(etype), vlans=vlans,
                       declared_role=self.cfg.role)

        # ATTACK: TTL already expired but the frame is still moving.
        if outer.ttl == 0:
            self._fire("SRM-TTL-ZERO-FORWARDED", "label:%d" % outer.label, ts,
                       outer_label=outer.label, stack=labels)

        # EXPOSURE: stack deeper than the operator expects here.
        if len(entries) > self.cfg.max_stack_depth:
            self._fire("SRM-LABEL-STACK-DEPTH", "depth:%d" % len(entries), ts,
                       depth=len(entries), expected_max=self.cfg.max_stack_depth,
                       stack=labels)

        # ATTACK: S bit stripped, or a stack no forwarding plane would build.
        if not terminated:
            self._fire("SRM-STACK-UNTERMINATED", "stack:%s" % stack_str, ts,
                       parsed_entries=len(entries), parse_cap=_MAX_STACK_PARSE,
                       stack=labels)
            return

        self._check_special_labels(entries, ts, stack_str)
        self._check_sr_stack(entries, ts, stack_str)

        payload = data[poff:]
        kind = classify_mpls_payload(payload)
        if kind in ("unknown", "empty"):
            self._fire("SRM-SBIT-CORRUPT", "stack:%s" % stack_str, ts,
                       stack=labels, payload_first_byte=payload[0] if payload else None,
                       payload_len=len(payload), classified=kind)
            return

        inner_dst = inner_destination(payload, kind)
        inner_src = None
        try:
            if kind == "ipv4" and len(payload) >= 20:
                inner_src = str(ipaddress.IPv4Address(payload[12:16]))
            elif kind == "ipv6" and len(payload) >= 40:
                inner_src = str(ipaddress.IPv6Address(payload[8:24]))
        except (ValueError, ipaddress.AddressValueError):
            inner_src = None

        self._check_label_binding(outer, inner_dst, ts, labels)
        self._check_ttl_sweep(outer, inner_src, ts)

        # An SRH can be tunnelled under MPLS; keep walking.
        if kind == "ipv6":
            self.handle_ipv6(payload, ts, under_mpls=True)

    def _check_special_labels(self, entries: List[LSE], ts: float, stack_str: str) -> None:
        last = len(entries) - 1
        for i, e in enumerate(entries):
            if e.label > LABEL_SPECIAL_MAX:
                continue
            at_bottom = (e.s == 1)
            if e.label == LABEL_IMPLICIT_NULL:
                # RFC 3032: implicit NULL is a signalling value only.
                self._fire("SRM-RESERVED-LABEL-DATA", "label:3@%d" % e.depth, ts,
                           label=e.label, name="implicit-null", depth=e.depth,
                           stack=stack_str, reason="control-plane-only value on the wire")
            elif e.label in LABEL_UNASSIGNED_SPECIAL:
                self._fire("SRM-RESERVED-LABEL-DATA", "label:%d@%d" % (e.label, e.depth), ts,
                           label=e.label, name="unassigned-special", depth=e.depth,
                           stack=stack_str, reason="never assigned by IANA")
            elif e.label == LABEL_ROUTER_ALERT and at_bottom:
                self._fire("SRM-RESERVED-LABEL-DATA", "label:1@%d" % e.depth, ts,
                           label=e.label, name="router-alert", depth=e.depth,
                           stack=stack_str, reason="router alert must not be bottom of stack")
            elif e.label == LABEL_GAL and not at_bottom:
                self._fire("SRM-RESERVED-LABEL-DATA", "label:13@%d" % e.depth, ts,
                           label=e.label, name="gal", depth=e.depth,
                           stack=stack_str, reason="GAL must be bottom of stack (RFC 5586)")
            elif e.label in (LABEL_IPV4_EXPLICIT_NULL, LABEL_IPV6_EXPLICIT_NULL) and not at_bottom:
                self._fire("SRM-EXPLICIT-NULL-EXPOSED", "label:%d@%d" % (e.label, e.depth), ts,
                           label=e.label, depth=e.depth, stack=stack_str,
                           name="ipv4-explicit-null" if e.label == 0 else "ipv6-explicit-null")
            elif e.label == LABEL_ELI:
                # RFC 6790: ELI is never bottom of stack and is always followed
                # by the entropy label itself.
                if at_bottom or i == last:
                    self._fire("SRM-ENTROPY-LABEL-ANOMALY", "eli@%d" % e.depth, ts,
                               depth=e.depth, stack=stack_str, eli_ttl=e.ttl,
                               bottom_of_stack=bool(at_bottom),
                               reason="ELI with no entropy label following it")

    def _check_sr_stack(self, entries: List[LSE], ts: float, stack_str: str) -> None:
        """Repeated segment identifier inside one stack."""
        if len(entries) < 3:
            return
        seen: Dict[int, int] = {}
        skip_next = False
        for e in entries:
            if skip_next:                       # the entropy label itself is random
                skip_next = False
                continue
            if e.label == LABEL_ELI:
                skip_next = True
                continue
            if e.label <= LABEL_SPECIAL_MAX:
                continue
            if self.cfg.srgb is not None:
                lo, hi = self.cfg.srgb
                if not (lo <= e.label <= hi):
                    continue                    # only reason about declared SIDs
            if e.label in seen:
                self._fire("SRM-SR-STACK-LOOP", "label:%d" % e.label, ts,
                           label=e.label, first_depth=seen[e.label],
                           repeat_depth=e.depth, stack=stack_str,
                           srgb_scoped=self.cfg.srgb is not None)
                return
            seen[e.label] = e.depth

    def _check_label_binding(self, outer: LSE, inner_dst: Optional[str],
                             ts: float, labels: List[int]) -> None:
        if inner_dst is None:
            return
        b = self.label_bindings.get(outer.label)
        if not b or b.get("ambiguous"):
            return
        fec = b["fec"]
        try:
            ip = ipaddress.ip_address(inner_dst)
        except ValueError:
            return
        if ip.version != fec.version:
            return
        if ip in fec:
            return
        self._fire("SRM-LABEL-REBIND", "label:%d" % outer.label, ts,
                   label=outer.label, advertised_fec=str(fec),
                   advertised_by=b["src"], advertised_via=b.get("via", "ldp"),
                   observed_inner_dst=inner_dst,
                   inner_dst_local=self._in_local(inner_dst),
                   stack=labels)

    def _check_ttl_sweep(self, outer: LSE, inner_src: Optional[str], ts: float) -> None:
        if inner_src is None or not self._ce_gate(ts):
            return
        self.stats["evictions"] += _prune(self.ttl_probe, _CAP_TTL_PROBE)
        dq = self.ttl_probe[(inner_src, outer.label)]
        cutoff = ts - self.cfg.ttl_probe_window
        while dq and dq[0][1] < cutoff:
            dq.popleft()
        dq.append((outer.ttl, ts))
        ttls = [t for t, _ in dq]
        if len(ttls) < self.cfg.ttl_probe_threshold:
            return
        window = ttls[-self.cfg.ttl_probe_threshold:]
        if all(window[i] < window[i + 1] for i in range(len(window) - 1)):
            self._fire("SRM-TTL-PROBE-SWEEP", "src:%s/label:%d" % (inner_src, outer.label), ts,
                       inner_src=inner_src, label=outer.label, ttl_sequence=window,
                       window_s=self.cfg.ttl_probe_window)
            dq.clear()

    # -- IPv6 / SRv6 --------------------------------------------------------

    def handle_ipv6(self, data: bytes, ts: float, under_mpls: bool = False) -> None:
        if len(data) < 40:
            raise ParseError("truncated IPv6")
        self.stats["ipv6"] += 1
        src = str(ipaddress.IPv6Address(data[8:24]))
        dst = str(ipaddress.IPv6Address(data[24:40]))
        srh, final_nh, _raw = walk_ipv6_headers(data)
        if srh is None:
            if final_nh == IPPROTO_RSVP:
                pass                                   # RSVP over IPv6: rare, see README
            return
        self.stats["srh"] += 1
        self._check_srh(srh, src, dst, ts, under_mpls)

    def _check_srh(self, srh: Dict[str, Any], src: str, dst: str,
                   ts: float, under_mpls: bool) -> None:
        sl = srh["segments_left"]
        le = srh["last_entry"]
        segs = srh["segments"]
        key = "%s>%s" % (src, dst)

        # ATTACK: RFC 8754 s5.1 - an SR domain drops SRH arriving from outside it.
        if self._ce_gate(ts):
            self._fire("SRM-SRH-ON-CE-PORT", key, ts,
                       src=src, dst=dst, segments_left=sl, last_entry=le,
                       segments=segs, tag=srh["tag"], under_mpls=under_mpls,
                       declared_role=self.cfg.role)

        # ATTACK: structural violations RFC 8754 s4.3.1.1 says must be dropped.
        if not srh["sl_valid"]:
            self._fire("SRM-SRH-MALFORMED", key, ts,
                       reason="segments_left exceeds last_entry",
                       segments_left=sl, last_entry=le, src=src, dst=dst,
                       under_mpls=under_mpls)
        elif not srh["len_consistent"]:
            self._fire("SRM-SRH-MALFORMED", key, ts,
                       reason="hdr_ext_len does not cover the declared segment list",
                       hdr_ext_len=srh["hdr_ext_len"], last_entry=le,
                       required_min=(le + 1) * 2, src=src, dst=dst,
                       under_mpls=under_mpls)

        # ATTACK: RFC 8754 s4.1 - DA tracks the active segment.
        #
        # The one legitimate mismatch is a REDUCED SRH (s4.1.1): at the first
        # hop the originator omits its own first segment from the list, so
        # DA != SegmentList[SL] while SL is still == Last Entry.  Once any
        # endpoint has decremented SL the invariant is unconditional, so this
        # rule only arms for SL < Last Entry.  That is the whole false-positive
        # surface of the rule, and it is closed by construction.
        if srh["sl_valid"] and sl < le and 0 <= sl < len(segs):
            if segs[sl] != dst:
                self._fire("SRM-SRH-DA-MISMATCH", key, ts,
                           dst=dst, active_segment=segs[sl], segments_left=sl,
                           last_entry=le, segments=segs, src=src,
                           under_mpls=under_mpls,
                           note="reduced-SRH exemption does not apply below last_entry")

        # POSTURE: unauthenticated segment list where policy says otherwise.
        if self.cfg.require_srh_hmac and not srh["has_hmac"]:
            self._fire("SRM-SRH-NO-HMAC", key, ts,
                       src=src, dst=dst, tlv_types=srh["tlv_types"],
                       segments=segs, under_mpls=under_mpls)

        # EXPOSURE: the intended path is readable by whoever is on this segment.
        if self._ce_gate(ts) and len(segs) >= 2:
            self._fire("SRM-SRH-PATH-DISCLOSURE", key, ts,
                       src=src, dst=dst, hop_count=len(segs), segments=segs,
                       under_mpls=under_mpls)

        # SID conformance needs a declared locator; fail loud if it is missing.
        if not self.cfg.srv6_locators:
            if not self._locator_warned:
                self._locator_warned = True
                self._fire("SRM-SRV6-LOCATOR-UNDECLARED", "iface:%s" % self.cfg.iface, ts,
                           iface=self.cfg.iface,
                           disarmed=["SRM-SRV6-SID-OUT-OF-LOCATOR",
                                     "SRM-SRV6-FUNCTION-UNKNOWN"])
            return

        active = active_segment(srh)
        if active is None:
            return
        net = self._in_locator(active)
        if net is None:
            self._fire("SRM-SRV6-SID-OUT-OF-LOCATOR", "sid:%s" % active, ts,
                       active_sid=active, segments_left=sl, src=src, dst=dst,
                       under_mpls=under_mpls,
                       declared_locators=[str(n) for n in self.cfg.srv6_locators])
            return
        if self.cfg.srv6_functions:
            fn = self._sid_function(active, net)
            if fn is not None and fn not in self.cfg.srv6_functions:
                self._fire("SRM-SRV6-FUNCTION-UNKNOWN", "sid:%s" % active, ts,
                           active_sid=active, locator=str(net), function=fn,
                           function_bits=self.cfg.srv6_function_bits,
                           under_mpls=under_mpls,
                           declared_functions=list(self.cfg.srv6_functions))

    def _sid_function(self, sid: str, locator: Any) -> Optional[int]:
        """Extract the function field: the bits immediately after the locator."""
        try:
            raw = int(ipaddress.IPv6Address(sid))
        except (ValueError, ipaddress.AddressValueError):
            return None
        loc_bits = locator.prefixlen
        fn_bits = self.cfg.srv6_function_bits
        if loc_bits + fn_bits > 128 or fn_bits <= 0:
            return None
        shift = 128 - loc_bits - fn_bits
        return (raw >> shift) & ((1 << fn_bits) - 1)

    # -- IPv4 dispatch ------------------------------------------------------

    def handle_ipv4(self, data: bytes, ts: float) -> None:
        if len(data) < 20:
            raise ParseError("truncated IPv4")
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or ihl > len(data):
            raise ParseError("bad IPv4 IHL")
        proto = data[9]
        src = str(ipaddress.IPv4Address(data[12:16]))
        dst = str(ipaddress.IPv4Address(data[16:20]))
        total = struct.unpack_from("!H", data, 2)[0]
        body = data[ihl:total] if 0 < total <= len(data) else data[ihl:]

        if proto == IPPROTO_RSVP:
            self.handle_rsvp(body, src, dst, ts)
        elif proto == IPPROTO_OSPF:
            self.handle_ospf(body, src, dst, ts)
        elif proto == IPPROTO_UDP:
            if len(body) < 8:
                return
            sport, dport, _ulen, _ck = struct.unpack_from("!HHHH", body, 0)
            if LDP_PORT in (sport, dport):
                self.handle_ldp(body[8:], src, dst, ts, transport="udp")
        elif proto == IPPROTO_TCP:
            if len(body) < 20:
                return
            sport, dport = struct.unpack_from("!HH", body, 0)
            doff = (body[12] >> 4) * 4
            flags = body[13]
            if doff < 20 or doff > len(body):
                return
            seg = body[doff:]
            if LDP_PORT in (sport, dport):
                self._check_ldp_tcp_auth(body, doff, flags, src, dst, sport, dport, ts)
                if seg:
                    self.handle_ldp(seg, src, dst, ts, transport="tcp")
            elif BGP_PORT in (sport, dport) and seg:
                self.handle_bgp(seg, src, sport, dst, dport, ts)

    # -- LDP ----------------------------------------------------------------

    def _check_ldp_tcp_auth(self, tcp: bytes, doff: int, flags: int,
                            src: str, dst: str, sport: int, dport: int,
                            ts: float) -> None:
        """TCP-MD5 / TCP-AO posture, observable only on the handshake."""
        syn = bool(flags & 0x02)
        if not syn:
            return
        kinds = parse_tcp_options(tcp, doff)
        if TCP_OPT_MD5 in kinds or TCP_OPT_AO in kinds:
            return
        pair = "/".join(sorted((src, dst)))
        self._fire("SRM-LDP-NO-MD5", "pair:%s" % pair, ts,
                   src=src, dst=dst, sport=sport, dport=dport,
                   tcp_options=kinds, ack=bool(flags & 0x10))

    def handle_ldp(self, data: bytes, src: str, dst: str, ts: float,
                   transport: str) -> None:
        pdu = parse_ldp_pdu(data)
        self.stats["ldp"] += 1
        lsr = pdu["lsr_id"]
        for msg in pdu["messages"]:
            mtype = msg["type"]
            tlvs = msg["tlvs"]
            if mtype == LDP_MSG_HELLO:
                self._check_ldp_hello(pdu, msg, tlvs, src, dst, ts, transport)
            elif mtype == LDP_MSG_LABEL_MAPPING:
                self._check_ldp_mapping(lsr, tlvs, src, ts)
            elif mtype in (LDP_MSG_LABEL_WITHDRAW, LDP_MSG_LABEL_RELEASE):
                self._clear_ldp_binding(lsr, tlvs)
            elif mtype in (LDP_MSG_INITIALIZATION, LDP_MSG_NOTIFICATION):
                self._check_ldp_flap(lsr, src, dst, mtype, ts)

    def _check_ldp_hello(self, pdu: Dict[str, Any], msg: Dict[str, Any],
                         tlvs: List[Dict[str, Any]], src: str, dst: str,
                         ts: float, transport: str) -> None:
        flags = ldp_hello_flags(tlvs) or 0
        targeted = bool(flags & LDP_HELLO_FLAG_TARGETED)
        hold = ldp_hello_hold(tlvs)
        known = None
        if self.cfg.ldp_peers:
            try:
                known = ipaddress.ip_address(src) in self.cfg.ldp_peers
            except ValueError:
                known = False
        elif self.cfg.local_nets:
            known = self._in_local(src)

        offlink = False
        reason = ""
        if self._ce_gate(ts):
            offlink, reason = True, "LDP discovery on a customer-facing interface"
        elif known is False:
            offlink, reason = True, "source is not a declared LDP peer"
        elif targeted and known is None:
            offlink, reason = True, "targeted hello with no declared peer set"
        if offlink:
            self._fire("SRM-LDP-HELLO-OFFLINK", "src:%s" % src, ts,
                       src=src, dst=dst, lsr_id=pdu["lsr_id"],
                       label_space=pdu["label_space"], targeted=targeted,
                       hold_time=hold, transport=transport, reason=reason,
                       declared_role=self.cfg.role)

    def _check_ldp_mapping(self, lsr: str, tlvs: List[Dict[str, Any]],
                           src: str, ts: float) -> None:
        fecs = ldp_fec_prefixes(tlvs)
        labels = ldp_generic_labels(tlvs)
        if not fecs or not labels:
            return
        label = labels[0]
        for fec in fecs:
            prev = self.ldp_fec_label.get((lsr, fec))
            if prev is not None and prev != label:
                self._fire("SRM-LDP-MAPPING-NO-WITHDRAW", "%s/%s" % (lsr, fec), ts,
                           lsr_id=lsr, fec=fec, previous_label=prev,
                           new_label=label, src=src)
            self.stats["evictions"] += _prune(self.ldp_fec_label, _CAP_LDP_FEC)
            self.ldp_fec_label[(lsr, fec)] = label
            try:
                net = ipaddress.ip_network(fec, strict=False)
            except ValueError:
                continue
            existing = self.label_bindings.get(label)
            if existing and existing["src"] != lsr:
                # Label spaces are per-LSR; a value claimed by two advertisers
                # cannot be attributed from the data plane.  Disarm it.
                existing["ambiguous"] = True
                continue
            self.stats["evictions"] += _prune(self.label_bindings, _CAP_LABEL_BINDINGS)
            self.label_bindings[label] = {"fec": net, "src": lsr, "ts": ts,
                                          "via": "ldp", "ambiguous": False}

    def _clear_ldp_binding(self, lsr: str, tlvs: List[Dict[str, Any]]) -> None:
        for label in ldp_generic_labels(tlvs):
            b = self.label_bindings.get(label)
            if b and b["src"] == lsr:
                del self.label_bindings[label]
        for fec in ldp_fec_prefixes(tlvs):
            self.ldp_fec_label.pop((lsr, fec), None)

    def _check_ldp_flap(self, lsr: str, src: str, dst: str, mtype: int,
                        ts: float) -> None:
        pair = "/".join(sorted((src, dst)))
        self.stats["evictions"] += _prune(self.ldp_flap, _CAP_LDP_FLAP)
        dq = self.ldp_flap[pair]
        cutoff = ts - self.cfg.ldp_flap_window
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(ts)
        if len(dq) >= self.cfg.ldp_flap_threshold:
            self._fire("SRM-LDP-SESSION-FLAP", "pair:%s" % pair, ts,
                       pair=pair, lsr_id=lsr, events=len(dq),
                       window_s=self.cfg.ldp_flap_window,
                       threshold=self.cfg.ldp_flap_threshold,
                       last_msg_type=mtype)
            dq.clear()

    # -- RSVP-TE ------------------------------------------------------------

    def handle_rsvp(self, data: bytes, src: str, dst: str, ts: float) -> None:
        pkt = parse_rsvp(data)
        self.stats["rsvp"] += 1
        objs = pkt["objects"]
        mtype = pkt["msg_type"]
        skey = rsvp_session_key(objs)
        if skey is None:
            return
        has_integrity = rsvp_has(objs, RSVP_OBJ_INTEGRITY)
        self.stats["evictions"] += _prune(self.rsvp_sessions, _CAP_RSVP_SESSIONS)
        st = self.rsvp_sessions.setdefault(
            skey, {"integrity": False, "msgs": 0, "posture_fired": False})
        st["msgs"] += 1

        if mtype in RSVP_TEARDOWN_MSGS:
            # ATTACK: the session authenticated itself, this teardown did not.
            if st["integrity"] and not has_integrity:
                self._fire("SRM-RSVP-TEAR-NO-INTEGRITY", "session:%s" % skey, ts,
                           session=skey, src=src, dst=dst,
                           msg_type="PathTear" if mtype == RSVP_MSG_PATH_TEAR else "ResvTear",
                           send_ttl=pkt["send_ttl"],
                           object_classes=sorted({o["class"] for o in objs}),
                           prior_messages=st["msgs"] - 1)
        if has_integrity:
            st["integrity"] = True
            return

        # POSTURE: nothing in this session has ever been authenticated.
        if (mtype in (RSVP_MSG_PATH, RSVP_MSG_RESV) and not st["integrity"]
                and not st["posture_fired"]):
            st["posture_fired"] = True
            self._fire("SRM-RSVP-NO-INTEGRITY", "session:%s" % skey, ts,
                       session=skey, src=src, dst=dst,
                       msg_type="Path" if mtype == RSVP_MSG_PATH else "Resv",
                       object_classes=sorted({o["class"] for o in objs}))

    # -- BGP-SR -------------------------------------------------------------

    def handle_bgp(self, seg: bytes, src: str, sport: int, dst: str,
                   dport: int, ts: float) -> None:
        """Length-prefix framing over a per-flow buffer.

        sr-mplswatch does NOT own BGP session semantics - bgpwatch does.  This
        path exists only to learn Prefix-SID and labelled-unicast bindings from
        the same tap that carries the data plane.  On a corrupt frame the
        buffer for that half-stream is dropped rather than resynchronised.
        """
        flow = (src, sport, dst, dport)
        self.stats["evictions"] += _prune(self.bgp_bufs, _CAP_BGP_FLOWS)
        buf = self.bgp_bufs.setdefault(flow, bytearray())
        buf.extend(seg)
        if len(buf) > _MAX_BGP_BUF * 2:
            del buf[:]
            return
        while len(buf) >= BGP_HDR_LEN:
            if bytes(buf[:16]) != BGP_MARKER:
                del buf[:]
                return
            length = struct.unpack_from("!H", buf, 16)[0]
            mtype = buf[18]
            cap = BGP_MAX_EXT_LEN if mtype in BGP_EXT_LEN_TYPES else BGP_MAX_STD_LEN
            if (length < BGP_HDR_LEN or length > cap
                    or mtype not in BGP_MSG_TYPES):
                del buf[:]
                return
            if len(buf) < length:
                return
            raw = bytes(buf[:length])
            del buf[:length]
            try:
                msg = parse_bgp_message(raw)
            except ParseError:
                self.stats["parse_errors"] += 1
                del buf[:]
                return
            if msg["type"] == BGP_MSG_UPDATE:
                self.stats["bgp_update"] += 1
                self._check_bgp_update(raw[BGP_HDR_LEN:], msg["attrs"], src, ts)

    def _check_bgp_update(self, body: bytes, attrs: List[Dict[str, Any]],
                          originator: str, ts: float) -> None:
        psid = None
        labelled: List[Tuple[str, int]] = []
        for a in attrs:
            if a["type"] == BGP_ATTR_PREFIX_SID:
                psid = parse_prefix_sid(a["value"])
            elif a["type"] == BGP_ATTR_MP_REACH_NLRI:
                mp = parse_mp_reach_labeled(a["value"])
                labelled.extend(mp["routes"])

        for prefix, label in labelled:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if label <= LABEL_SPECIAL_MAX:
                continue
            existing = self.label_bindings.get(label)
            if existing and existing["src"] != originator:
                existing["ambiguous"] = True
                continue
            self.stats["evictions"] += _prune(self.label_bindings, _CAP_LABEL_BINDINGS)
            self.label_bindings[label] = {"fec": net, "src": originator, "ts": ts,
                                          "via": "bgp-lu", "ambiguous": False}

        if psid is None:
            return
        self.stats["prefix_sid"] += 1

        for base, rng in psid["srgb"]:
            self._record_srgb(originator, [(base, rng)], ts, "bgp")

        idx = psid["label_index"]
        prefixes = parse_bgp_nlri_prefixes(body) or [p for p, _ in labelled]
        if idx is None:
            return

        for prefix in prefixes:
            self._record_prefix_sid(originator, "bgp", prefix, SR_ALGO_SPF,
                                    "index", idx, ts)


    # -- shared SR ledger ---------------------------------------------------

    @staticmethod
    def _ranges_overlap(ranges: List[Tuple[int, int]]) -> Optional[Tuple[Any, Any]]:
        """RFC 8667 s3.1 / s3.3: an originator MUST NOT advertise overlapping
        ranges.  Returns the first offending pair, or None."""
        spans = [(b, b + n - 1) for b, n in ranges if n > 0]
        for i in range(len(spans)):
            for j in range(i + 1, len(spans)):
                a, b = spans[i], spans[j]
                if a[0] <= b[1] and b[0] <= a[1]:
                    return (a, b)
        return None

    @staticmethod
    def _resolve_index(ranges: List[Tuple[int, int]], idx: int) -> Optional[int]:
        """RFC 8667 s3.1: descriptors concatenate IN ADVERTISED ORDER, and the
        index walks across them.  None when the index runs off the end."""
        remaining = idx
        for base, size in ranges:
            if remaining < size:
                return base + remaining
            remaining -= size
        return None

    def _record_srgb(self, originator: str, ranges: List[Tuple[int, int]],
                     ts: float, source: str) -> None:
        if not ranges:
            return
        bad = self._ranges_overlap(ranges)
        if bad:
            self._fire("SRM-SRGB-CONFLICT", "srgb:%s" % originator, ts,
                       originator=originator, source=source, reason="self-overlapping "
                       "SRGB descriptors", overlapping=[list(bad[0]), list(bad[1])],
                       ranges=[list(r) for r in ranges])
        prev = self.srgb_adv.get(originator)
        if prev is not None and prev != ranges:
            self._fire("SRM-SRGB-CONFLICT", "srgb-change:%s" % originator, ts,
                       originator=originator, source=source,
                       reason="advertised SRGB changed",
                       previous=[list(r) for r in prev],
                       current=[list(r) for r in ranges])
        if self.cfg.srgb is not None:
            lo, hi = self.cfg.srgb
            outside = [[b, n] for b, n in ranges if b < lo or b + n - 1 > hi]
            if outside:
                self._fire("SRM-SRGB-CONFLICT", "srgb-declared:%s" % originator, ts,
                           originator=originator, source=source,
                           reason="advertised SRGB outside the declared block",
                           declared=[lo, hi], outside=outside)
        self.stats["evictions"] += _prune(self.srgb_adv, _CAP_SID_OWNERS)
        self.srgb_adv[originator] = list(ranges)

    def _record_algos(self, originator: str, algos: List[int]) -> None:
        self.stats["evictions"] += _prune(self.sr_algos, _CAP_SID_OWNERS)
        self.sr_algos[originator] = set(algos)

    def _record_adj_sid(self, originator: str, neighbor: str,
                        adj: Dict[str, Any], ts: float, source: str) -> None:
        if adj["kind"] == "invalid":
            self._fire("SRM-SID-FLAGS-INVALID", "adj:%s/%s" % (originator, neighbor), ts,
                       originator=originator, neighbor=neighbor, source=source,
                       kind="adj-sid", flags=adj["flags"])
            return
        if adj["sid"] is None or not adj.get("persistent"):
            return
        key = (originator, neighbor)
        prev = self.adj_sids.get(key)
        if prev is not None and prev != adj["sid"]:
            self._fire("SRM-ADJ-SID-UNSTABLE", "adj:%s/%s" % (originator, neighbor), ts,
                       originator=originator, neighbor=neighbor, source=source,
                       previous_sid=prev, new_sid=adj["sid"], flags=adj["flags"],
                       weight=adj["weight"])
        self.stats["evictions"] += _prune(self.adj_sids, _CAP_SID_OWNERS)
        self.adj_sids[key] = adj["sid"]

    def _record_prefix_sid(self, originator: str, source: str, prefix: str,
                           algorithm: int, kind: str, sid: Optional[int],
                           ts: float, **extra: Any) -> None:
        """The single entry point for every Prefix-SID, whatever advertised it."""
        if kind == "invalid":
            self._fire("SRM-SID-FLAGS-INVALID", "prefix:%s" % prefix, ts,
                       originator=originator, source=source, prefix=prefix,
                       kind="prefix-sid", algorithm=algorithm, **extra)
            return
        if sid is None:
            return

        # ATTACK: RFC 8667 s2.1 - a Prefix-SID whose algorithm the originator
        # never advertised MUST be ignored by a conforming receiver.  Both
        # halves must be on this tap: absence of an SR-Algorithm advertisement
        # is NOT evidence the originator never sent one, only that we did not
        # see it, so the rule stays disarmed until we have.
        advertised = self.sr_algos.get(originator)
        if advertised is not None and algorithm not in advertised:
            self._fire("SRM-SR-ALGO-UNEXPECTED", "algo:%s/%d" % (originator, algorithm), ts,
                       originator=originator, source=source, prefix=prefix,
                       algorithm=algorithm, advertised_algorithms=sorted(advertised))

        if kind == "label":
            return                      # a local label is not a global segment

        # Index resolution prefers the ORIGINATOR's advertised SRGB and falls
        # back to the operator-declared one.
        ranges = self.srgb_adv.get(originator)
        if ranges:
            resolved = self._resolve_index(ranges, sid)
            if resolved is None:
                self._fire("SRM-SID-OUT-OF-SRGB", "index:%d/%s" % (sid, originator), ts,
                           label_index=sid, originator=originator, source=source,
                           prefix=prefix, algorithm=algorithm,
                           advertised_srgb=[list(r) for r in ranges],
                           reason="index beyond the originator's advertised SRGB")
        else:
            if not self._srcap_warned:
                self._srcap_warned = True
                self._fire("SRM-SR-CAP-NOT-SEEN", "iface:%s" % self.cfg.iface, ts,
                           iface=self.cfg.iface, first_originator=originator,
                           fallback="--srgb" if self.cfg.srgb else None)
            if self.cfg.srgb is not None:
                lo, hi = self.cfg.srgb
                if lo + sid > hi:
                    self._fire("SRM-SID-OUT-OF-SRGB", "index:%d" % sid, ts,
                               label_index=sid, srgb_base=lo, srgb_top=hi,
                               resolved_label=lo + sid, originator=originator,
                               source=source, prefix=prefix, algorithm=algorithm)
            elif not self._srgb_warned:
                self._srgb_warned = True
                self._fire("SRM-SRGB-UNDECLARED", "iface:%s" % self.cfg.iface, ts,
                           iface=self.cfg.iface, disarmed=["SRM-SID-OUT-OF-SRGB"])

        prev = self.prefix_sid.get(prefix)
        if prev is not None and (prev[0], prev[1]) != (algorithm, sid):
            self._fire("SRM-SR-MAPPING-CONFLICT", "prefix:%s" % prefix, ts,
                       prefix=prefix, previous_algorithm=prev[0], previous_index=prev[1],
                       previous_originator=prev[2], previous_source=prev[3],
                       new_algorithm=algorithm, new_index=sid,
                       new_originator=originator, new_source=source)
        self.stats["evictions"] += _prune(self.prefix_sid, _CAP_PREFIX_SID)
        self.prefix_sid[prefix] = (algorithm, sid, originator, source)

        self.stats["evictions"] += _prune(self.sid_owners, _CAP_SID_OWNERS)
        owners = self.sid_owners[(algorithm, sid)]
        if sid not in self.cfg.anycast_sids:
            for other_orig, (other_pfx, other_src) in owners.items():
                if other_orig != originator and other_pfx != prefix:
                    self._fire("SRM-SID-COLLISION", "index:%d/%d" % (algorithm, sid), ts,
                               label_index=sid, algorithm=algorithm,
                               originators=[other_orig, originator],
                               prefixes=[other_pfx, prefix],
                               sources=[other_src, source],
                               anycast_allowlist=list(self.cfg.anycast_sids))
                    break
        owners[originator] = (prefix, source)

    def _igp_sr_seen(self, ts: float, protocol: str, originator: str) -> None:
        self.stats["igp_sr"] += 1
        if self._ce_gate(ts):
            self._fire("SRM-IGP-SR-TOPOLOGY", "%s:%s" % (protocol, originator), ts,
                       protocol=protocol, originator=originator,
                       declared_role=self.cfg.role)

    # -- IS-IS --------------------------------------------------------------

    def handle_llc(self, data: bytes, ts: float) -> None:
        if len(data) < 4:
            raise ParseError("truncated LLC header")
        if not (data[0] == LLC_SAP_ISIS and data[1] == LLC_SAP_ISIS
                and data[2] == LLC_CONTROL_UI):
            return                       # some other 802.3 payload; not ours
        self.handle_isis(data[3:], ts)

    def handle_isis(self, data: bytes, ts: float) -> None:
        pdu = parse_isis_pdu(data)
        self.stats["isis"] += 1
        if pdu["pdu_type"] not in ISIS_LSP_TYPES:
            return
        id_len = pdu["id_length"]
        originator = (pdu["lsp_id"] or "")[:id_len * 2]
        saw_sr = False
        for tlv in pdu["tlvs"]:
            t, value = tlv["type"], tlv["value"]
            if t == ISIS_TLV_ROUTER_CAPABILITY:
                # RFC 7981 s2: Router ID(4) | Flags(1) | sub-TLVs
                if len(value) < 5:
                    continue
                for sub in parse_isis_subtlvs(value[5:]):
                    if sub["type"] == ISIS_SUB_SR_CAPABILITY:
                        saw_sr = True
                        self._record_srgb(
                            originator, parse_isis_sr_ranges(sub["value"])["ranges"],
                            ts, "isis")
                    elif sub["type"] == ISIS_SUB_SR_LOCAL_BLOCK:
                        saw_sr = True
                        self.srlb_adv[originator] = \
                            parse_isis_sr_ranges(sub["value"])["ranges"]
                    elif sub["type"] == ISIS_SUB_SR_ALGORITHM:
                        saw_sr = True
                        self._record_algos(
                            originator, parse_isis_sr_algorithms(sub["value"]))
            elif t in ISIS_PREFIX_TLVS:
                for entry in isis_prefix_entries(t, value):
                    for sub in entry["subtlvs"]:
                        if sub["type"] != ISIS_SUB_PREFIX_SID:
                            continue
                        p = parse_isis_prefix_sid(sub["value"])
                        if not p:
                            continue
                        saw_sr = True
                        self._record_prefix_sid(originator, "isis", entry["prefix"],
                                                p["algorithm"], p["kind"], p["sid"], ts,
                                                node_sid=p["node"], isis_tlv=t)
            elif t in ISIS_NEIGHBOR_TLVS:
                mt = t in (ISIS_TLV_MT_IS_NEIGH, ISIS_TLV_MT_IS_NEIGH_ATTR)
                for entry in isis_neighbor_entries(value[2:] if mt else value):
                    for sub in entry["subtlvs"]:
                        if sub["type"] == ISIS_SUB_ADJ_SID:
                            a = parse_isis_adj_sid(sub["value"])
                        elif sub["type"] == ISIS_SUB_LAN_ADJ_SID:
                            a = parse_isis_adj_sid(sub["value"], lan=True, id_len=id_len)
                        else:
                            continue
                        if not a:
                            continue
                        saw_sr = True
                        self._record_adj_sid(originator,
                                             a.get("neighbor") or entry["neighbor"],
                                             a, ts, "isis")
        if saw_sr:
            self._igp_sr_seen(ts, "isis", originator)

    # -- OSPFv2 -------------------------------------------------------------

    def handle_ospf(self, data: bytes, src: str, dst: str, ts: float) -> None:
        hdr = parse_ospf_header(data)
        self.stats["ospf"] += 1
        if hdr["type"] != OSPF_TYPE_LS_UPDATE:
            return
        saw_sr = False
        last_originator = hdr["router_id"]
        for lsa in parse_ospf_lsas(data):
            if lsa["ls_type"] not in OSPF_OPAQUE_LSA_TYPES:
                continue
            originator = lsa["adv_router"]
            last_originator = originator
            ot = lsa["opaque_type"]
            if ot == OSPF_OPAQUE_ROUTER_INFO:
                for tlv in parse_ospf_tlvs(lsa["body"]):
                    if tlv["type"] == OSPF_RI_TLV_SID_LABEL_RANGE:
                        saw_sr = True
                        self._record_srgb(
                            originator, parse_ospf_sid_range(tlv["value"])["ranges"],
                            ts, "ospf")
                    elif tlv["type"] == OSPF_RI_TLV_SR_LOCAL_BLOCK:
                        saw_sr = True
                        self.srlb_adv[originator] = \
                            parse_ospf_sid_range(tlv["value"])["ranges"]
                    elif tlv["type"] == OSPF_RI_TLV_SR_ALGORITHM:
                        saw_sr = True
                        self._record_algos(originator, list(tlv["value"][:32]))
            elif ot == OSPF_OPAQUE_EXT_PREFIX:
                for tlv in parse_ospf_tlvs(lsa["body"]):
                    if tlv["type"] != OSPF_TLV_EXT_PREFIX:
                        continue
                    ep = parse_ospf_ext_prefix(tlv["value"])
                    if not ep:
                        continue
                    for sub in ep["subtlvs"]:
                        if sub["type"] != OSPF_SUB_PREFIX_SID:
                            continue
                        p = parse_ospf_prefix_sid(sub["value"])
                        if not p:
                            continue
                        saw_sr = True
                        self._record_prefix_sid(originator, "ospf", ep["prefix"],
                                                p["algorithm"], p["kind"], p["sid"], ts,
                                                mapping_server=p["mapping_server"])
            elif ot == OSPF_OPAQUE_EXT_LINK:
                for tlv in parse_ospf_tlvs(lsa["body"]):
                    if tlv["type"] != OSPF_TLV_EXT_LINK:
                        continue
                    el = parse_ospf_ext_link(tlv["value"])
                    if not el:
                        continue
                    for sub in el["subtlvs"]:
                        if sub["type"] not in (OSPF_SUB_ADJ_SID, OSPF_SUB_LAN_ADJ_SID):
                            continue
                        a = parse_ospf_adj_sid(sub["value"])
                        if not a:
                            continue
                        saw_sr = True
                        self._record_adj_sid(originator, el["link_id"], a, ts, "ospf")
        if saw_sr:
            self._igp_sr_seen(ts, "ospf", last_originator)


# ---------------------------------------------------------------------------
# Live capture - the ONE function in this module that imports scapy.
# Suite LESSON C: this path is driven for the first time by the scapy pcap
# tier, so it must stay small enough to read in one screen.
# ---------------------------------------------------------------------------

def run_capture(cfg: Config, engine: SRMPLSEngine, count: int = 0,
                pcap: Optional[str] = None) -> None:
    from scapy.all import sniff                      # noqa: F401  (lazy by design)
    from scapy.config import conf                    # noqa: F401

    def handle(pkt) -> None:
        try:
            raw = bytes(pkt)
        except Exception:
            engine.stats["parse_errors"] += 1
            return
        ts = float(getattr(pkt, "time", time.time()))
        engine.handle_frame(raw, ts)

    kwargs: Dict[str, Any] = {"prn": handle, "store": False}
    if cfg.bpf:
        kwargs["filter"] = cfg.bpf
    if count:
        kwargs["count"] = count
    if pcap:
        sniff(offline=pcap, **kwargs)
    else:
        sniff(iface=cfg.iface, **kwargs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=MODULE_NAME,
        description="Passive MPLS / SR-MPLS / SRv6 label and segment manipulation detector.",
        epilog="This module never transmits.",
    )
    p.add_argument("-i", "--iface", default="eth0", help="capture interface")
    p.add_argument("--role", choices=INTERFACE_ROLES, default="unknown",
                   help="interface role; an undeclared interface fails loud toward 'ce'")
    p.add_argument("--bpf", default="",
                   help="kernel BPF filter; EMPTY BY DEFAULT on purpose (see README)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="floor severity; default info so the fail-loud "
                        "config codes are never silently dropped")
    p.add_argument("--dedup-window", type=float, default=60.0,
                   help="seconds a (code,key) pair stays suppressed")
    p.add_argument("--max-stack-depth", type=int, default=8,
                   help="label stack depth above which SRM-LABEL-STACK-DEPTH fires")
    p.add_argument("--srgb", default=None, metavar="LO-HI|BASE:RANGE",
                   help="segment routing global block, e.g. 16000-23999")
    p.add_argument("--anycast-sid", action="append", default=[], type=int,
                   metavar="INDEX", help="SID index legitimately shared (repeatable)")
    p.add_argument("--srv6-locator", action="append", default=[], metavar="CIDR",
                   help="SRv6 locator block, e.g. 2001:db8:a::/48 (repeatable)")
    p.add_argument("--srv6-function", action="append", default=[], type=int,
                   metavar="VALUE", help="declared SRv6 function value (repeatable)")
    p.add_argument("--srv6-function-bits", type=int, default=16,
                   help="width of the function field following the locator")
    p.add_argument("--require-srh-hmac", action="store_true",
                   help="arm SRM-SRH-NO-HMAC")
    p.add_argument("--ldp-peer", action="append", default=[], metavar="IP",
                   help="declared LDP peer (repeatable)")
    p.add_argument("--ldp-flap-threshold", type=int, default=4)
    p.add_argument("--ldp-flap-window", type=float, default=60.0)
    p.add_argument("--ttl-probe-threshold", type=int, default=4)
    p.add_argument("--ttl-probe-window", type=float, default=20.0)
    p.add_argument("--local-net", action="append", default=[], metavar="CIDR",
                   help="address space considered internal (repeatable)")
    p.add_argument("-o", "--output", default=None, help="JSONL output path")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress stdout when no --output is given")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N packets")
    p.add_argument("-r", "--read", default=None, metavar="PCAP",
                   help="read from a pcap instead of a live interface")
    p.add_argument("--selftest", action="store_true", help="run the offline self-test")
    p.add_argument("--print-codes", action="store_true",
                   help="print the finding catalogue as JSON and exit")
    p.add_argument("--version", action="version", version="%s %s" % (MODULE_NAME, __version__))
    return p


def config_from_args(args: argparse.Namespace) -> Config:
    srgb = parse_srgb(args.srgb) if args.srgb else None
    locators = tuple(ipaddress.ip_network(c, strict=False) for c in args.srv6_locator)
    locals_ = tuple(ipaddress.ip_network(c, strict=False) for c in args.local_net)
    peers = tuple(ipaddress.ip_address(a) for a in args.ldp_peer)
    return Config(
        iface=args.iface,
        role=args.role,
        bpf=args.bpf,
        min_severity=args.min_severity,
        dedup_window=args.dedup_window,
        max_stack_depth=args.max_stack_depth,
        srgb=srgb,
        anycast_sids=tuple(args.anycast_sid),
        srv6_locators=locators,
        srv6_functions=tuple(args.srv6_function),
        srv6_function_bits=args.srv6_function_bits,
        require_srh_hmac=args.require_srh_hmac,
        ldp_peers=peers,
        ldp_flap_threshold=args.ldp_flap_threshold,
        ldp_flap_window=args.ldp_flap_window,
        ttl_probe_threshold=args.ttl_probe_threshold,
        ttl_probe_window=args.ttl_probe_window,
        local_nets=locals_,
        output=args.output,
        quiet=args.quiet,
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.print_codes:
        print(json.dumps(FINDINGS, indent=2, sort_keys=True))
        return 0

    if args.selftest:
        here = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, here)
        try:
            import test_sr_mplswatch as t
        except ImportError:
            sys.stderr.write("self-test not found next to the module\n")
            return 2
        return t.run_all()

    cfg = config_from_args(args)
    emitter = Emitter(cfg)
    emitter.open()
    engine = SRMPLSEngine(cfg, emitter)

    if cfg.bpf:
        emitter.emit("SRM-CONFIG-BPF-OVERRIDE", key="bpf", bpf=cfg.bpf,
                     note="default is empty; a kernel filter can drop the frames "
                          "this module exists to see")
    try:
        run_capture(cfg, engine, count=args.count, pcap=args.read)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.stderr.write("need CAP_NET_RAW to capture on %s\n" % cfg.iface)
        return 1
    finally:
        emitter.close()
        sys.stderr.write("[%s] frames=%d mpls=%d srh=%d ldp=%d rsvp=%d "
                         "isis=%d ospf=%d igp_sr=%d "
                         "bgp_update=%d parse_errors=%d findings=%d suppressed=%d "
                         "evictions=%d\n"
                         % (MODULE_NAME, engine.stats["frames"], engine.stats["mpls"],
                            engine.stats["srh"], engine.stats["ldp"], engine.stats["rsvp"],
                            engine.stats["isis"], engine.stats["ospf"],
                            engine.stats["igp_sr"], engine.stats["bgp_update"], engine.stats["parse_errors"],
                            sum(emitter.counts.values()), emitter.suppressed,
                            engine.stats["evictions"] + emitter.evictions))
    return 0


# CLI entrypoint removed on vendoring; this module is imported by Ragnar.


# ===========================================================================
# RAGNAR IN-APP ADAPTER  (appended on vendoring; not part of the upstream CLI)
# ---------------------------------------------------------------------------
# Snapshot-over-pcap adapter mirroring lacp/rpc/bfd: one tcpdump capture on the
# interface, replayed frame-by-frame through SRMPLSEngine.handle_frame with the
# Emitter in collect mode, reduced to one card verdict, HIGH/CRITICAL findings
# streamed to Watchtower. The engine is pure-Python (own parsers); replay uses
# bfdwatch.read_pcap (also pure-Python), so scapy is never needed. The interface
# `role` is load-bearing: an undeclared interface fails loud toward customer-
# facing, so presence rules (MPLS/SRH on a CE port) stay armed. Detection-only:
# the engine has no transmit primitives (its own conformance greps the source).
# ===========================================================================
import os as _os
import json as _json
import time as _time
import struct as _struct
import ipaddress as _ipaddress
import tempfile as _tempfile
import subprocess as _subprocess
from datetime import datetime as _datetime, timezone as _timezone

_SRM_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# The critical verdict token: a label/segment chosen by the far end appearing
# where this network's own control plane should have chosen it — the label-
# injection / VRF-hopping / segment-injection primitive. Mirrored into the web
# net-integrity critical set as 'segment-injection'.
_SRM_INJECTION_CODES = frozenset((
    "SRM-MPLS-ON-CE-PORT", "SRM-SRH-ON-CE-PORT", "SRM-SRV6-ON-CE-PORT"))


def _srm_verdict(records):
    """Reduce a collected finding-record list to (verdict, ranked-worst-first)."""
    ranked = sorted(records,
                    key=lambda r: _SRM_SEV_ORDER.get(r.get("severity"), 0),
                    reverse=True)
    codeset = {r.get("code") for r in ranked}
    has_crit = any(r.get("severity") == "critical" for r in ranked)
    has_attack_high = any(r.get("class") == "ATTACK"
                          and _SRM_SEV_ORDER.get(r.get("severity"), 0) >= 3
                          for r in ranked)
    if (codeset & _SRM_INJECTION_CODES) or has_crit:
        return "segment-injection", ranked
    if has_attack_high:
        return "label-manipulation", ranked
    if any(_SRM_SEV_ORDER.get(r.get("severity"), 0) >= 3 for r in ranked):
        return "exposure", ranked
    if any(_SRM_SEV_ORDER.get(r.get("severity"), 0) >= 2 for r in ranked):
        return "posture", ranked
    return "clean", ranked


# --- Watchtower feed --------------------------------------------------------
_SRM_WT_LOG_DIR = _os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_SRM_WT_DEDUP_S = 300.0
_SRM_WT_EMIT_SEV = frozenset(("high", "critical"))
_srm_wt_lock = None
_srm_wt_seen = {}


def _srm_emit_watchtower(result):
    """Append HIGH/CRITICAL SR-MPLS findings to <log-dir>/sr_mpls_watch.jsonl in the
    shape Watchtower.normalize() reads, so label/segment-injection, reserved-label,
    TTL-expiry-forwarded and control-plane spoof alerts fold into the unified pane +
    single Pushover path. Deduped per (code, key) over the window. Never raises."""
    global _srm_wt_lock
    if _srm_wt_lock is None:
        import threading
        _srm_wt_lock = threading.Lock()
    if not result.get("success"):
        return
    verdict = result.get("verdict", "clean")
    iface = result.get("interface")
    now = _time.time()
    iso = _datetime.now(_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    with _srm_wt_lock:
        for f in result.get("findings", []):
            if f.get("severity") not in _SRM_WT_EMIT_SEV:
                continue
            code = f.get("code")
            key = f.get("key")
            dk = (code, key)
            last = _srm_wt_seen.get(dk)
            if last is not None and now - last < _SRM_WT_DEDUP_S:
                continue
            _srm_wt_seen[dk] = now
            lines.append(_json.dumps({
                "module": "sr_mpls_watch", "ts": now, "iso": iso, "iface": iface,
                "severity": f.get("severity"), "code": code, "codes": [code],
                "src": key, "summary": f.get("title"), "verdict": verdict}))
        if len(_srm_wt_seen) > 4096:
            cutoff = now - _SRM_WT_DEDUP_S
            for k in [k for k, t in _srm_wt_seen.items() if t < cutoff]:
                _srm_wt_seen.pop(k, None)
    if not lines:
        return
    try:
        _os.makedirs(_SRM_WT_LOG_DIR, exist_ok=True)
        with open(_os.path.join(_SRM_WT_LOG_DIR, "sr_mpls_watch.jsonl"), "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


# --- capture ----------------------------------------------------------------
# Union of the SR-MPLS transports, by ethertype/proto so it is NON-stateful and
# always compiles: MPLS uni/multicast (0x8847/0x8848), all IPv6 0x86dd (an SRH
# lives in a routing-extension header and cannot be BPF-matched precisely), all
# 802.1Q 0x8100 (so a VLAN-tagged MPLS/SRH frame is still seen — the engine walks
# the tags), RSVP-TE (ip proto 46), OSPFv2 (ip proto 89), LDP (port 646), BGP
# (tcp 179), and IS-IS over 802.3/LLC (length field <= 1500 with DSAP/SSAP 0xfe).
# The libpcap `mpls`/`vlan`/`isis` primitives are deliberately avoided: they are
# stateful (they shift the offset for every following predicate in an OR chain),
# so an otherwise-correct union fails to compile. The engine self-filters; all
# structural checks are left to it.
_SRM_BPF = ("ether proto 0x8847 or ether proto 0x8848 or ether proto 0x86dd or "
            "ether proto 0x8100 or (ip and (ip proto 46 or ip proto 89)) or "
            "port 646 or tcp port 179 or "
            "(ether[12:2] <= 1500 and ether[14:2] = 0xfefe)")


def _srm_capture_pcap(interface, seconds, bpf=None):
    """tcpdump an SR-MPLS snapshot to a temp classic-pcap file. Returns (path, error).
    Detection-only: no transmit."""
    from shutil import which
    if not which("tcpdump"):
        return None, "tcpdump is not installed. Click Install to add it."
    fd, path = _tempfile.mkstemp(suffix=".pcap")
    _os.close(fd)
    try:
        res = _subprocess.run(
            ["timeout", str(int(seconds) + 3), "tcpdump", "-i", interface,
             "-nn", "-s", "512", "-c", "20000", "-w", path, bpf or _SRM_BPF],
            stdout=_subprocess.DEVNULL, stderr=_subprocess.PIPE,
            timeout=int(seconds) + 8)
        err = (res.stderr or b"").decode("utf-8", "replace")
    except _subprocess.TimeoutExpired:
        err = ""
    except OSError as e:
        try:
            _os.remove(path)
        except OSError:
            pass
        return None, "capture failed: {}".format(e)
    if (_os.path.getsize(path) <= 24 and err
            and any(s in err.lower() for s in
                    ("permission", "no such device", "syntax error", "couldn't"))):
        try:
            _os.remove(path)
        except OSError:
            pass
        return None, err.strip()[:200]
    return path, None


def do_sr_mpls_watch(interface=None, seconds=20, role="unknown"):
    """Passive MPLS / SR-MPLS / SRv6 label & segment-manipulation scan (detection-only).
    One tcpdump snapshot on `interface`, replayed through the streaming engine; reports
    label/segment injection (MPLS or an SRH on a customer-facing port — the VRF-hopping
    primitive), reserved/implicit-null labels forwarded, TTL-expired frames forwarded,
    excessive label depth, SRv6 path disclosure / missing HMAC, and control-plane tells
    across LDP / RSVP-TE / BGP-SR / IS-IS-SR / OSPFv2-SR. `role` (ce|core|unknown) is
    load-bearing: an undeclared interface fails loud toward customer-facing so the
    presence rules stay armed. Streams HIGH/CRITICAL findings to Watchtower. Never
    transmits."""
    if not interface:
        return {"success": False, "error": "no interface specified"}
    seconds = max(8, min(int(seconds or 20), 60))
    if role not in INTERFACE_ROLES:
        role = "unknown"
    path, err = _srm_capture_pcap(interface, seconds)
    if err:
        return {"success": False, "interface": interface, "error": err,
                "missing_tool": "tcpdump" if "not installed" in err else None}
    try:
        from bfdwatch import read_pcap as _read_pcap
    except Exception:
        try:
            _os.remove(path)
        except OSError:
            pass
        return {"success": False, "interface": interface,
                "error": "pcap reader unavailable"}
    cfg = Config(iface=interface, role=role, quiet=True, min_severity="info")
    em = Emitter(cfg)
    em.collect = True
    eng = SRMPLSEngine(cfg, em)
    try:
        for ts, frame in _read_pcap(path):
            eng.handle_frame(frame, ts)
    except Exception as e:
        try:
            _os.remove(path)
        except OSError:
            pass
        return {"success": False, "interface": interface,
                "error": "capture parse failed: {}".format(type(e).__name__)}
    finally:
        try:
            _os.remove(path)
        except OSError:
            pass

    records = em.records
    verdict, ranked = _srm_verdict(records)
    reasons, seen = [], set()
    for r in ranked:
        if _SRM_SEV_ORDER.get(r.get("severity"), 0) < 2:
            continue
        if r["code"] in seen:
            continue
        seen.add(r["code"])
        reasons.append("{}: {} [{}]".format(r["code"], r.get("title", ""),
                                            r.get("key", "")))
        if len(reasons) >= 8:
            break
    st = dict(eng.stats)
    if not reasons:
        if st.get("mpls_frames") or st.get("srh_frames") or st.get("frames"):
            reasons = ["Traffic observed; no label/segment injection, reserved-label, "
                       "TTL-expiry or SR control-plane anomaly detected "
                       "(role=%s)" % role]
        else:
            reasons = ["No MPLS / SR-MPLS / SRv6 traffic seen on this segment"]

    by_sev = {}
    for r in records:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1

    # Findings surfaced to the card/Watchtower carry a compact subset.
    findings = [{"code": r["code"], "severity": r["severity"], "class": r["class"],
                 "category": r.get("category"), "title": r.get("title"),
                 "key": r.get("key")} for r in records]

    result = {
        "success": True, "interface": interface, "seconds": seconds, "role": role,
        "verdict": verdict, "reasons": reasons, "findings": findings,
        "by_severity": by_sev, "stats": st,
    }
    _srm_emit_watchtower(result)
    return result


# --- selftest (aggregator shape: {'success', 'scenarios':[{name,pass,detail}]}) ---
def selftest():
    """Build real MPLS / SRv6 frames, feed them through the engine with the Emitter in
    collect mode, and assert the findings + role semantics. No sockets, no capture, no
    persistence — asserted by construction (the engine only reads bytes)."""
    scen = []
    _MAC_A = b"\x02\x00\x00\x00\x00\x0a"
    _MAC_B = b"\x02\x00\x00\x00\x00\x0b"

    def check(name, ok, detail=""):
        scen.append({"name": name, "pass": bool(ok), "detail": detail})

    def _eth(etype, payload, vlans=None):
        out = _MAC_B + _MAC_A
        tags = list(vlans or [])
        if not tags:
            return out + _struct.pack("!H", etype) + payload
        out += _struct.pack("!H", ETHERTYPE_VLAN)
        for i, v in enumerate(tags):
            nxt = ETHERTYPE_VLAN if i < len(tags) - 1 else etype
            out += _struct.pack("!HH", v & 0x0FFF, nxt)
        return out + payload

    def _lse(label, tc=0, s=0, ttl=64):
        word = ((label & 0xFFFFF) << 12) | ((tc & 0x7) << 9) | ((s & 1) << 8) | (ttl & 0xFF)
        return _struct.pack("!I", word)

    def _stack(entries):
        return b"".join(_lse(*e) for e in entries)

    def _udp(sport, dport, payload):
        return _struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload

    def _ipv4(src, dst, proto, payload):
        total = 20 + len(payload)
        hdr = _struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0,
                           _ipaddress.IPv4Address(src).packed,
                           _ipaddress.IPv4Address(dst).packed)
        return hdr + payload

    def _ipv6(src, dst, nh, payload):
        hdr = _struct.pack("!IHBB", 0x60000000, len(payload), nh, 64)
        return (hdr + _ipaddress.IPv6Address(src).packed
                + _ipaddress.IPv6Address(dst).packed + payload)

    def _srh(segments, sl):
        seg_blob = b"".join(_ipaddress.IPv6Address(s).packed for s in segments)
        body = seg_blob
        body += b"\x00" * ((-len(body)) % 8)
        le = max(0, len(segments) - 1)
        hel = (8 + len(body)) // 8 - 1
        return _struct.pack("!BBBBBBH", IPPROTO_NONXT, hel, SRH_ROUTING_TYPE,
                            sl, le, 0, 0) + body

    def _ip_payload():
        return _ipv4("192.0.2.10", "198.51.100.20", 17, _udp(1000, 2000, b"x" * 8))

    def _mpls_frame(entries, payload):
        return _eth(ETHERTYPE_MPLS_UNICAST, _stack(entries) + payload)

    def _v6_srh_frame(segments, sl, dst):
        h = _srh(segments, sl)
        return _eth(ETHERTYPE_IPV6, _ipv6("2001:db8:a:ff::9", dst, IPPROTO_IPV6_ROUTE, h))

    def _run(frames, **cfgkw):
        cfgkw.setdefault("quiet", True)
        cfgkw.setdefault("min_severity", "info")
        cfg = Config(**cfgkw)
        em = Emitter(cfg)
        em.collect = True
        eng = SRMPLSEngine(cfg, em)
        for i, f in enumerate(frames):
            eng.handle_frame(f, 1000.0 + i)
        return em.records

    def _codes(recs):
        return {r["code"] for r in recs}

    # 1. MPLS-labelled frame on a customer-facing (default 'unknown') port -> critical.
    r = _run([_mpls_frame([(16001, 0, 1, 64)], _ip_payload())], role="ce")
    check("mpls-on-ce-port", "SRM-MPLS-ON-CE-PORT" in _codes(r), sorted(_codes(r)))

    # 2. The same frame on a declared core port is silent of the presence rule.
    r = _run([_mpls_frame([(16001, 0, 1, 64)], _ip_payload())], role="core")
    check("mpls-on-core-silent", "SRM-MPLS-ON-CE-PORT" not in _codes(r), sorted(_codes(r)))

    # 3. Implicit NULL (reserved label 3) forwarded on the wire -> reserved-label.
    r = _run([_mpls_frame([(3, 0, 0, 64), (16001, 0, 1, 64)], _ip_payload())], role="core")
    check("reserved-implicit-null", "SRM-RESERVED-LABEL-DATA" in _codes(r), sorted(_codes(r)))

    # 4. Labelled frame forwarded with an expired TTL -> TTL-zero-forwarded.
    r = _run([_mpls_frame([(16001, 0, 1, 0)], _ip_payload())], role="core")
    check("ttl-zero-forwarded", "SRM-TTL-ZERO-FORWARDED" in _codes(r), sorted(_codes(r)))

    # 5. An SRv6 SRH on a customer-facing port -> SRH-on-CE (segment injection).
    r = _run([_v6_srh_frame(["2001:db8:1::1", "2001:db8:2::1", "2001:db8:3::1"], 2,
                            "2001:db8:3::1")], role="ce")
    check("srh-on-ce-port", "SRM-SRH-ON-CE-PORT" in _codes(r), sorted(_codes(r)))

    # 6. Adapter verdict mapping: an MPLS-on-CE critical ranks 'segment-injection'.
    v, _ = _srm_verdict([{"code": "SRM-MPLS-ON-CE-PORT", "severity": "critical",
                          "class": "ATTACK"}])
    check("verdict-segment-injection", v == "segment-injection", v)

    # 7. Undeclared role fires the fail-loud warning once.
    r = _run([_mpls_frame([(16001, 0, 1, 64)], _ip_payload())], role="unknown")
    check("role-undeclared-warns", "SRM-ROLE-UNDECLARED" in _codes(r), sorted(_codes(r)))

    return {"success": all(s["pass"] for s in scen), "scenarios": scen}
