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

__version__ = "0.2.0-dev"
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

# ---------------------------------------------------------------------------
# MPLS Generalized Associated Channel (G-ACh) - RFC 5586
#
# ACH layout: 0001 (4b) | Version (4b) | Reserved (8b) | Channel Type (16b).
# Version and Reserved MUST be zero.  The GAL (label 13) carries it for LSP
# and section OAM; a pseudowire carries it with no GAL at all (RFC 4385).
#
# Every value below was read off the IANA "MPLS Generalized Associated Channel
# (G-ACh) Types" registry, not from recall.  Two of them are traps:
#   * RFC 6374 owns FIVE channel types, not two (DLM/ILM/DM/DLM+DM/ILM+DM).
#   * ACH-carries-IPv6 is 0x0057, nowhere near ACH-carries-IPv4 (0x0021).
#     Guessing the adjacent value lands on MPLS-TP CC.
# ---------------------------------------------------------------------------
ACH_FIRST_NIBBLE = 1             # RFC 5586 s3.2 - 0001
ACH_HEADER_LEN = 4

GACH_MCC = 0x0001                # RFC 5718
GACH_SCC = 0x0002                # RFC 5718
GACH_BFD_PW_ACH = 0x0007         # RFC 5885  - VCCV-BFD, no IP/UDP
GACH_SBFD_PW_ACH = 0x0008        # RFC 7885
GACH_DHC = 0x0009                # RFC 8185
GACH_DLM = 0x000A                # RFC 6374  - Direct Loss Measurement
GACH_ILM = 0x000B                # RFC 6374  - Inferred Loss Measurement
GACH_DM = 0x000C                 # RFC 6374  - Delay Measurement
GACH_DLM_DM = 0x000D             # RFC 6374  - combined
GACH_ILM_DM = 0x000E             # RFC 6374  - combined
GACH_RTM = 0x000F                # RFC 8169
GACH_MULTIPOINT_BFD = 0x0013     # RFC 9780
GACH_IPV4 = 0x0021               # RFC 4385  - ACH carries an IPv4 packet
GACH_MPLS_TP_CC = 0x0022         # RFC 6428
GACH_MPLS_TP_CV = 0x0023         # RFC 6428
GACH_PSC = 0x0024                # RFC 6378
GACH_ON_DEMAND_CV = 0x0025       # RFC 6426
GACH_LI = 0x0026                 # RFC 6435
GACH_PW_OAM = 0x0027             # RFC 6478
GACH_MAC_WITHDRAW = 0x0028       # RFC 7769
GACH_PW_STATUS_REFRESH = 0x0029  # RFC 8237
GACH_RPS = 0x002A                # RFC 8227
GACH_IPV6 = 0x0057               # RFC 4385  - ACH carries an IPv6 packet
GACH_FAULT_OAM = 0x0058          # RFC 6427
GACH_GAP = 0x0059                # RFC 7212
GACH_G8113_1 = 0x8902            # RFC 6671

GACH_EXPERIMENTAL = range(0x7FF8, 0x8000)   # RFC 5586 - experimental use

# The two channel types that mean "the payload is an ordinary IP packet".
# These are the bfdwatch seam: everything they expose is handed to the IP
# path, so IP/UDP-rooted protocols (BFD included) stay with the module that
# owns IP/UDP.  sr-mplswatch never decodes BFD reached via IP/UDP.
GACH_IP_PAYLOAD = frozenset((GACH_IPV4, GACH_IPV6))

# RFC 6374 message families, keyed by channel type -> (name, fixed_size).
# Sizes exclude the TLV block and are derived from the RFC 6374 s3.1/3.2/3.3
# diagrams: LM 52, DM 44, combined 76.
GACH_MEASUREMENT: Dict[int, Tuple[str, int]] = {
    GACH_DLM: ("dlm", 52),
    GACH_ILM: ("ilm", 52),
    GACH_DM: ("dm", 44),
    GACH_DLM_DM: ("dlm+dm", 76),
    GACH_ILM_DM: ("ilm+dm", 76),
}

# ---------------------------------------------------------------------------
# IOAM - RFC 9197 data fields, RFC 9486 IPv6 encapsulation
#
# IOAM rides as an IPv6 Hop-by-Hop or Destination option.  There are TWO
# option type values and a parser matching one misses half the traffic:
#   0x11 (chg=0) : IOAM E2E (Destination), IOAM DEX (Hop-by-Hop)
#   0x31 (chg=1) : IOAM Pre-allocated Trace (HbH), IOAM POT (HbH)
#
# Trace option header (RFC 9197 s4.4.1, identical for pre-allocated and
# incremental):
#   Namespace-ID (16b) | NodeLen (5b) | Flags (4b) | RemainingLen (7b)
#   IOAM Trace-Type (24b) | Reserved (8b)
#
# IOAM IS IPv6-ONLY HERE, AND THAT IS THE PROTOCOL, NOT AN OMISSION.
# RFC 9486 defines IOAM as IPv6 extension-header options; there is no IPv4
# equivalent to parse.  Recorded explicitly so the asymmetry is visible to a
# future reader rather than looking like a dual-stack gap.
# ---------------------------------------------------------------------------
IPV6_OPT_IOAM_IMMUTABLE = 0x11   # RFC 9486 - chg = 0
IPV6_OPT_IOAM_MUTABLE = 0x31     # RFC 9486 - chg = 1
IPV6_OPT_IOAM = frozenset((IPV6_OPT_IOAM_IMMUTABLE, IPV6_OPT_IOAM_MUTABLE))

IPV6_OPT_PAD1 = 0x00
IPV6_OPT_PADN = 0x01

IOAM_OPT_PREALLOC_TRACE = 0      # RFC 9197 s4.4.1
IOAM_OPT_INCREMENTAL_TRACE = 1   # RFC 9197 s4.4.1
IOAM_OPT_POT = 2                 # RFC 9197 s4.5
IOAM_OPT_E2E = 3                 # RFC 9197 s4.6
IOAM_OPT_DEX = 4                 # RFC 9326
IOAM_OPT_NAMES: Dict[int, str] = {
    IOAM_OPT_PREALLOC_TRACE: "pre-allocated-trace",
    IOAM_OPT_INCREMENTAL_TRACE: "incremental-trace",
    IOAM_OPT_POT: "pot",
    IOAM_OPT_E2E: "e2e",
    IOAM_OPT_DEX: "dex",
    64: "integrity-protected-prealloc-trace",
    65: "integrity-protected-incremental-trace",
    66: "integrity-protected-pot",
    67: "integrity-protected-e2e",
}
IOAM_TRACE_OPTS = frozenset((IOAM_OPT_PREALLOC_TRACE, IOAM_OPT_INCREMENTAL_TRACE))

IOAM_OPT_HEADER_LEN = 4          # Option-Type | Opt Data Len | Reserved | IOAM-Type
IOAM_TRACE_HEADER_LEN = 8        # the two words above
IOAM_MAX_TOTAL_LEN = 255         # RFC 9486 s4
IOAM_ALIGNMENT = 4               # RFC 9486 s4 - multiples of 4 octets

# RFC 9197 s4.4.2: data each Trace-Type bit contributes, in 4-octet units.
# Bit 0 is the MOST significant bit of the 24-bit Trace-Type.  Bits 8/9/10 are
# the WIDE formats and cost TWO units each; bits 12-21 are undefined but MUST
# be 4 octets; bit 22 is variable and EXCLUDED from NodeLen; bit 23 has no
# data field at all.
IOAM_TRACE_UNITS: Dict[int, int] = {}
for _b in range(0, 8):
    IOAM_TRACE_UNITS[_b] = 1
for _b in (8, 9, 10):
    IOAM_TRACE_UNITS[_b] = 2
IOAM_TRACE_UNITS[11] = 1
for _b in range(12, 22):
    IOAM_TRACE_UNITS[_b] = 1
del _b

IOAM_TRACE_BIT_OPAQUE = 22       # variable length, excluded from NodeLen
IOAM_TRACE_BIT_RESERVED = 23     # MUST be zero on transmission
IOAM_TRACE_BITS_UNDEFINED = frozenset(range(12, 22))

# The largest NodeLen any legal Trace-Type can imply.  The field is 5 bits so
# it can encode 31, but no combination of bits reaches past this, which makes
# it a bound independent of which bits are actually set.
IOAM_NODELEN_MAX = sum(IOAM_TRACE_UNITS.values())      # 25

IOAM_TRACE_FLAG_OVERFLOW = 0x8   # RFC 9197 - O-bit, first Flags bit
IOAM_TRACE_FLAG_LOOPBACK = 0x4   # RFC 9322 - L-bit
IOAM_TRACE_FLAG_ACTIVE = 0x2     # RFC 9322 - A-bit
IOAM_TRACE_FLAG_MBZ = 0x1        # remaining bit unassigned

IOAM_NAMESPACE_DEFAULT = 0x0000
IOAM_NAMESPACE_PRIVATE = range(0x0001, 0x8000)   # reserved for private use

# ---------------------------------------------------------------------------
# LSP Ping - RFC 8029 MPLS Echo Request / Reply  (+ VCCV, RFC 5085)
#
# UDP port 3503 (IANA service name 'lsp-ping', ref RFC 8029), both directions.
# Header, from the RFC 8029 s3 diagram - note the FIELD WIDTHS, which are a
# common source of error:
#   Version Number (16b) | Global Flags (16b)
#   Message Type (8b) | Reply Mode (8b) | Return Code (8b) | Return Subcode (8b)
#   Sender's Handle (32b) | Sequence Number (32b)
#   TimeStamp Sent (64b) | TimeStamp Received (64b) | TLVs...
# Version Number is SIXTEEN bits with value 1, not an 8-bit field.
#
# The destination-address rule is the strongest signal here.  An echo request
# is addressed into 127/8 (IPv4) or 0:0:0:0:0:FFFF:7F00:0/104 (IPv6) precisely
# so that a packet which escapes the LSP is DROPPED rather than delivered:
# RFC 1122 forbids 127/8 outside a host and RFC 1812 tells routers not to
# forward it.  A request addressed anywhere else has lost that property.
# ---------------------------------------------------------------------------
LSPPING_PORT = 3503
LSPPING_VERSION = 1
LSPPING_HEADER_LEN = 32

LSPPING_MSG_ECHO_REQUEST = 1     # RFC 8029
LSPPING_MSG_ECHO_REPLY = 2       # RFC 8029
LSPPING_MSG_PROXY_REQUEST = 3    # RFC 7555
LSPPING_MSG_PROXY_REPLY = 4      # RFC 7555
LSPPING_MSG_RELAYED_REPLY = 5    # RFC 7743
LSPPING_MSG_ASSIGNED = frozenset((
    LSPPING_MSG_ECHO_REQUEST, LSPPING_MSG_ECHO_REPLY,
    LSPPING_MSG_PROXY_REQUEST, LSPPING_MSG_PROXY_REPLY,
    LSPPING_MSG_RELAYED_REPLY,
))

LSPPING_REPLY_NO_REPLY = 1
LSPPING_REPLY_UDP = 2
LSPPING_REPLY_UDP_ROUTER_ALERT = 3   # DEPRECATED by RFC 9570
LSPPING_REPLY_CONTROL_CHANNEL = 4
LSPPING_REPLY_SPECIFIED_PATH = 5     # RFC 7110
LSPPING_REPLY_ASSIGNED = frozenset(range(1, 6))

# TLV types below 32768 are mandatory; 32768 and above are optional.
LSPPING_TLV_MANDATORY_MAX = 32767

LSPPING_TLV_TARGET_FEC = 1           # RFC 8029
LSPPING_TLV_DOWNSTREAM_MAP = 2       # RFC 8029 - DEPRECATED in favour of 20
LSPPING_TLV_PAD = 3
LSPPING_TLV_VENDOR_ENTERPRISE = 5
LSPPING_TLV_INTERFACE_LABEL_STACK = 7
LSPPING_TLV_ERRORED_TLVS = 9
LSPPING_TLV_REPLY_TOS = 10
LSPPING_TLV_BFD_DISCRIMINATOR = 15   # RFC 5884
LSPPING_TLV_REVERSE_PATH_FEC = 16    # RFC 6426
LSPPING_TLV_DDMAP = 20               # RFC 8029 - Downstream Detailed Mapping
LSPPING_TLV_REPLY_PATH = 21          # RFC 7110

# Target FEC Stack sub-TLVs carrying these types also appear in TLV 16 and 21.
# The registry is ADDRESS-FAMILY-SPLIT by design, which is what makes a
# family-mismatch detection expressible at all.
LSPPING_FEC_V4: Dict[int, str] = {
    1: "ldp-ipv4-prefix", 3: "rsvp-ipv4-lsp", 6: "vpn-ipv4-prefix",
    9: "fec128-pw-ipv4-deprecated", 10: "fec128-pw-ipv4",
    11: "fec129-pw-ipv4", 12: "bgp-labeled-ipv4", 14: "generic-ipv4-prefix",
    17: "rsvp-p2mp-ipv4", 26: "ipv4-rsvp-tunnel", 31: "mt-ldp-ipv4-prefix",
    34: "ipv4-igp-prefix-sid", 47: "ipv4-node-address-sr-mpls",
    49: "sr-policy-psid-ipv4", 50: "sr-cp-psid-ipv4", 51: "sr-sl-psid-ipv4",
}
LSPPING_FEC_V6: Dict[int, str] = {
    2: "ldp-ipv6-prefix", 4: "rsvp-ipv6-lsp", 7: "vpn-ipv6-prefix",
    13: "bgp-labeled-ipv6", 15: "generic-ipv6-prefix", 18: "rsvp-p2mp-ipv6",
    24: "fec128-pw-ipv6", 25: "fec129-pw-ipv6", 27: "ipv6-rsvp-tunnel",
    32: "mt-ldp-ipv6-prefix", 35: "ipv6-igp-prefix-sid",
    48: "ipv6-node-address-sr-mpls", 52: "sr-policy-psid-ipv6",
    53: "sr-cp-psid-ipv6", 54: "sr-sl-psid-ipv6",
}
# Family-neutral sub-TLVs, listed so an unknown type is distinguishable from
# a known-but-neutral one.
LSPPING_FEC_NEUTRAL: Dict[int, str] = {
    8: "l2vpn-endpoint", 16: "nil-fec", 19: "multicast-p2mp-ldp",
    20: "multicast-mp2mp-ldp", 22: "static-lsp", 23: "static-pw",
    28: "static-tunnel", 29: "hsmp-upstream-ldp", 30: "hsmp-downstream-ldp",
    33: "entropy-label-fec", 36: "igp-adjacency-sid", 37: "p2mp-pw",
    38: "peeradj-sid", 39: "peernode-sid", 40: "peerset-sid",
    41: "sr-mpls-p2mp-policy-tree", 42: "evpn-mac-ip",
    43: "evpn-inclusive-multicast", 44: "evpn-eth-auto-discovery",
    45: "evpn-ip-prefix", 46: "sid-only-mpls-label",
}
# RFC 8287 SR sub-TLVs: the only OAM codepoints that NAME A SID on the wire,
# which is what lets them be cross-checked against this module's SR ledger.
LSPPING_FEC_SR_V4 = 34
LSPPING_FEC_SR_V6 = 35
LSPPING_FEC_SR_ADJ = 36

LSPPING_FEC_DEPRECATED = {9: "RFC 8029 (use sub-TLV 10)"}

# Downstream (Detailed) Mapping Address Type -> exact K-octet length.
LSPPING_ADDR_TYPE_LEN: Dict[int, Tuple[str, int]] = {
    1: ("ipv4-numbered", 16),
    2: ("ipv4-unnumbered", 16),
    3: ("ipv6-numbered", 40),
    4: ("ipv6-unnumbered", 28),
    5: ("non-ip", 12),
}

# RFC 8029 s4.3: the loopback ranges an echo request is addressed into.
LSPPING_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
LSPPING_LOOPBACK_V6 = ipaddress.ip_network("::ffff:127.0.0.0/104")

# VCCV - RFC 5085 s5.3.1.  Advertised in LDP interface parameter 0x0C as two
# octets: a CC Type bitmask then a CV Type bitmask.
VCCV_IFACE_PARAM = 0x0C
VCCV_CC_CONTROL_WORD = 0x01        # Type 1 - PW-ACH, first nibble 0001
VCCV_CC_ROUTER_ALERT = 0x02        # Type 2 - MPLS Router Alert label
VCCV_CC_TTL_EXPIRY = 0x04          # Type 3 - PW label with TTL == 1
VCCV_CC_RESERVED = 0xF8
VCCV_CV_ICMP_PING = 0x01
VCCV_CV_LSP_PING = 0x02
VCCV_CV_RESERVED = 0xFC
# Types 2 and 3 both push the packet to a router's control plane.
VCCV_CC_CONTROL_PLANE = VCCV_CC_ROUTER_ALERT | VCCV_CC_TTL_EXPIRY

# ---------------------------------------------------------------------------
# RFC 6374 Loss / Delay Measurement
#
# Common header, confirmed against the RFC 6374 s3.1/3.2/3.3 diagrams:
#   byte 0 : Version (4b) | Flags (4b)      Flags  = R|T|0|0
#   byte 1 : Control Code (8b)
#   byte 2 : Message Length (16b)
#   word 2 : LM    -> DFlags(4) | OTF(4) | Reserved(24)   DFlags = X|B|0|0
#            DM    -> QTF(4) | RTF(4) | RPTF(4) | Reserved(20)
#            LM+DM -> DFlags(4) | QTF(4) | RTF(4) | RPTF(4) | Reserved(16)
#   word 3 : Session Identifier (24b) | DS (8b)
#
# TRAP, and the reason there is no "DS must be zero" rule anywhere below:
# RFC 6374 s3.1 says that when T = 0 "the value of this field is arbitrary,
# and the field can be considered part of the Session Identifier".  DS is
# only interpretable when T = 1.  Reading it otherwise fires on conforming
# traffic.
# ---------------------------------------------------------------------------
MEAS_VERSION = 0                 # RFC 6374 s3.1 - MUST be 0

MEAS_FLAG_R = 0x08               # query/response indicator, first Flags bit
MEAS_FLAG_T = 0x04               # traffic-class-specific, second Flags bit
MEAS_FLAG_MBZ = 0x03             # remaining two Flags bits MUST be zero

MEAS_DFLAG_X = 0x08              # extended (64-bit) counter format
MEAS_DFLAG_B = 0x04              # octet count rather than packet count
MEAS_DFLAG_MBZ = 0x03            # remaining two DFlags bits MUST be zero

# Timestamp formats - IANA "Measurement Timestamp Type".  0..3 assigned,
# 4..15 unassigned.
MEAS_TS_NULL = 0
MEAS_TS_SEQUENCE = 1
MEAS_TS_NTPV4 = 2
MEAS_TS_PTP = 3
MEAS_TS_MAX_ASSIGNED = MEAS_TS_PTP

# IANA "Loss/Delay Measurement Control Code" - query codes 0x0..0x2.
MEAS_QUERY_CODES = frozenset((0x00, 0x01, 0x02))
# Response codes: 0x1..0x5 non-error, 0x10..0x1D error.  0x0 is Reserved.
MEAS_RESPONSE_CODES = frozenset(range(0x01, 0x06)) | frozenset(range(0x10, 0x1E))

# Mandatory TLV object types are 0..127; optional are 128..255.
MEAS_TLV_MANDATORY_MAX = 127

GACH_ASSIGNED: Dict[int, str] = {
    GACH_MCC: "mcc", GACH_SCC: "scc",
    GACH_BFD_PW_ACH: "bfd-pw-ach", GACH_SBFD_PW_ACH: "s-bfd-pw-ach",
    GACH_DHC: "dual-homing-coordination",
    GACH_DLM: "dlm", GACH_ILM: "ilm", GACH_DM: "dm",
    GACH_DLM_DM: "dlm+dm", GACH_ILM_DM: "ilm+dm",
    GACH_RTM: "residence-time", GACH_MULTIPOINT_BFD: "multipoint-bfd",
    GACH_IPV4: "ipv4-payload", GACH_MPLS_TP_CC: "mpls-tp-cc",
    GACH_MPLS_TP_CV: "mpls-tp-cv", GACH_PSC: "psc",
    GACH_ON_DEMAND_CV: "on-demand-cv", GACH_LI: "lawful-intercept",
    GACH_PW_OAM: "pw-oam", GACH_MAC_WITHDRAW: "mac-withdraw",
    GACH_PW_STATUS_REFRESH: "pw-status-refresh", GACH_RPS: "ring-protection",
    GACH_IPV6: "ipv6-payload", GACH_FAULT_OAM: "fault-oam",
    GACH_GAP: "gach-advertisement", GACH_G8113_1: "g8113.1-oam",
}

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
# Pseudowire FEC elements - RFC 8077 (was RFC 4447).
LDP_FEC_PWID = 128               # 0x80: C|PWType(15) | PWInfoLen(8) |
                                 #       GroupID(32) | PWID(32) | ifparams...
LDP_FEC_GENERALIZED_PWID = 129   # 0x81: AGI/SAII/TAII, NO inline ifparams
# The Generalized FEC carries its interface parameters in a SEPARATE TLV.
LDP_TLV_PW_INTERFACE_PARAMS = 0x096B

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
# -- OSPFv3 SR (RFC 5340 framing, RFC 8362 extended LSAs, RFC 8666 SR) -----
# OSPFv3 LS Type is a 2-octet field: U(1) S2(1) S1(1) + 13-bit function code.
OSPFV3_VERSION = 3
OSPFV3_HDR_LEN = 16              # RFC 5340 sA.3.1 (v2 is 24)
OSPFV3_LSA_HDR_LEN = 20
OSPFV3_LS_TYPE_FC_MASK = 0x1FFF

OSPFV3_FC_ROUTER_INFO = 12       # RFC 7770
OSPFV3_FC_E_ROUTER = 33          # RFC 8362 - LS Type 0xA021
OSPFV3_FC_E_NETWORK = 34         # 0xA022
OSPFV3_FC_E_INTER_AREA_PREFIX = 35   # 0xA023
OSPFV3_FC_E_INTER_AREA_ROUTER = 36   # 0xA024
OSPFV3_FC_E_AS_EXTERNAL = 37     # 0xC025
OSPFV3_FC_E_TYPE_7 = 39          # 0xA027
OSPFV3_FC_E_LINK = 40            # 0x8028
OSPFV3_FC_E_INTRA_AREA_PREFIX = 41   # 0xA029

# RFC 8362 s4: octets of fixed body BEFORE the TLV block, per LSA.  Getting
# one of these wrong shifts every sub-TLV silently, which is why they are
# transcribed from the RFC rather than assumed uniform.
OSPFV3_BODY_PREFIX: Dict[int, int] = {
    OSPFV3_FC_ROUTER_INFO: 0,
    OSPFV3_FC_E_ROUTER: 4,           # flags + options
    OSPFV3_FC_E_NETWORK: 4,          # 0 + options
    OSPFV3_FC_E_INTER_AREA_PREFIX: 0,
    OSPFV3_FC_E_INTER_AREA_ROUTER: 0,
    OSPFV3_FC_E_AS_EXTERNAL: 0,
    OSPFV3_FC_E_TYPE_7: 0,
    OSPFV3_FC_E_LINK: 4,             # router priority + options
    OSPFV3_FC_E_INTRA_AREA_PREFIX: 12,   # 0(2) RefLSType(2) RefLSID(4) RefAdvRtr(4)
}

# "OSPFv3 Extended-LSA TLVs" registry (RFC 8362 s8.1, RFC 8666 s9.1)
OSPFV3_TLV_ROUTER_LINK = 1
OSPFV3_TLV_ATTACHED_ROUTERS = 2
OSPFV3_TLV_INTER_AREA_PREFIX = 3
OSPFV3_TLV_INTER_AREA_ROUTER = 4
OSPFV3_TLV_EXTERNAL_PREFIX = 5
OSPFV3_TLV_INTRA_AREA_PREFIX = 6
OSPFV3_TLV_IPV6_LINK_LOCAL = 7
OSPFV3_TLV_IPV4_LINK_LOCAL = 8
OSPFV3_TLV_EXT_PREFIX_RANGE = 9  # RFC 8666 s5
OSPFV3_PREFIX_TLVS = frozenset((OSPFV3_TLV_INTER_AREA_PREFIX,
                                OSPFV3_TLV_EXTERNAL_PREFIX,
                                OSPFV3_TLV_INTRA_AREA_PREFIX))

# "OSPFv3 Extended-LSA Sub-TLVs" registry (RFC 8666 s9.2)
OSPFV3_SUB_PREFIX_SID = 4
OSPFV3_SUB_ADJ_SID = 5
OSPFV3_SUB_LAN_ADJ_SID = 6
OSPFV3_SUB_SID_LABEL = 7

# RFC 8666 s6: Prefix-SID flags   |  |NP|M |E |V |L |  |  |  (same bit
# positions as OSPFv2, but the FIELD ORDER after them differs - see the
# parser).
OSPFV3_PSID_FLAG_NP = 0x40
OSPFV3_PSID_FLAG_M = 0x20
OSPFV3_PSID_FLAG_E = 0x10
OSPFV3_PSID_FLAG_V = 0x08
OSPFV3_PSID_FLAG_L = 0x04
# RFC 8666 s7.1: Adj-SID flags  |B|V|L|G|P|  |  |  |  -- DIFFERENT bit
# positions from OSPFv2 s6.1, and OSPFv3 has a P (persistent) flag where
# OSPFv2 has an S (set/group) flag.
OSPFV3_ASID_FLAG_B = 0x80
OSPFV3_ASID_FLAG_V = 0x40
OSPFV3_ASID_FLAG_L = 0x20
OSPFV3_ASID_FLAG_G = 0x10
OSPFV3_ASID_FLAG_P = 0x08

OSPFV3_AF_IPV4 = 0               # RFC 8666 s5
OSPFV3_AF_IPV6 = 1

# RFC 8665 s6.1: OSPFv2 Adj-SID flags    |  |B|V|L|S|  |  |
OSPF_ASID_FLAG_B = 0x40
OSPF_ASID_FLAG_V = 0x20
OSPF_ASID_FLAG_L = 0x10
OSPF_ASID_FLAG_S = 0x08

# Minimum value length for each SR sub-TLV, from its fixed fields.  A declared
# length below this is the "size is not validated" half of the FRR OSPF CVEs:
# the parser reads fields the advertisement never carried.
#   ("bgp",  container, type) / ("ospf", container, type) / ("isis", container, type)
SR_TLV_MIN_LEN: Dict[Tuple[str, str, int], int] = {
    # RFC 8669 s3.1: RESERVED(1) FLAGS(2) LABEL-INDEX(4)
    ("bgp", "prefix-sid", 1): 7,
    # RFC 8669 s3.2: RESERVED(2) then 6-octet (base,range) descriptors
    ("bgp", "prefix-sid", 3): 8,
    # RFC 8665 s5: FLAGS(1) RESERVED(1) MT-ID(1) ALGORITHM(1) SID(3 or 4)
    ("ospf", "ext-prefix", OSPF_SUB_PREFIX_SID): 7,
    # RFC 8665 s6.1: FLAGS(1) RESERVED(1) MT-ID(1) WEIGHT(1) SID(3 or 4)
    ("ospf", "ext-link", OSPF_SUB_ADJ_SID): 7,
    ("ospf", "ext-link", OSPF_SUB_LAN_ADJ_SID): 7,
    # RFC 8665 s3.2/s3.3: RANGE SIZE(3) RESERVED(1) + a SID/Label sub-TLV header
    ("ospf", "router-info", OSPF_RI_TLV_SID_LABEL_RANGE): 8,
    ("ospf", "router-info", OSPF_RI_TLV_SR_LOCAL_BLOCK): 8,
    # RFC 8666 s6: Flags(1) Algorithm(1) Reserved(2) SID(3 or 4) -> 7 or 8
    ("ospfv3", "prefix-tlv", OSPFV3_SUB_PREFIX_SID): 7,
    # RFC 8666 s7.1: Flags(1) Weight(1) Reserved(2) SID(3 or 4) -> 7 or 8
    ("ospfv3", "router-link", OSPFV3_SUB_ADJ_SID): 7,
    # RFC 8666 s7.2: adds a 4-octet Neighbor ID -> 11 or 12
    ("ospfv3", "router-link", OSPFV3_SUB_LAN_ADJ_SID): 11,
    ("ospfv3", "router-info", OSPF_RI_TLV_SID_LABEL_RANGE): 8,
    ("ospfv3", "router-info", OSPF_RI_TLV_SR_LOCAL_BLOCK): 8,
    # RFC 8667 s2.1: FLAGS(1) ALGORITHM(1) SID(4 index or 3 label)
    ("isis", "prefix-reach", ISIS_SUB_PREFIX_SID): 5,
    # RFC 8667 s2.2.1: FLAGS(1) WEIGHT(1) SID
    ("isis", "neighbour", ISIS_SUB_ADJ_SID): 5,
    ("isis", "neighbour", ISIS_SUB_LAN_ADJ_SID): 5,
    # RFC 8667 s3.1/s3.3: FLAGS(1) then RANGE(3) + SID/Label sub-TLV
    ("isis", "router-cap", ISIS_SUB_SR_CAPABILITY): 6,
    ("isis", "router-cap", ISIS_SUB_SR_LOCAL_BLOCK): 6,
}

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
# CVE references
#
# Every CVE identifier that appears ANYWHERE in this module must be a key here,
# and the conformance harness enforces that by walking the source for
# CVE-\d{4}-\d{4,} literals.  This registry exists because it did not: an
# earlier revision cited "CVE-2014-7271" in SRM-TTL-ZERO-FORWARDED as an MPLS
# TTL-handling flaw.  CVE-2014-7271 is SDDM, a local desktop login bypass.  The
# reference was invented and passed all six test tiers, because nothing in the
# suite checked that a CVE id corresponded to anything at all.
#
# `score` is the NVD/CNA figure only.  Where NVD has no assessment the entry
# records None rather than an aggregator's number - aggregators disagree with
# the CNA often enough that using one is how a wrong severity gets shipped.
# ---------------------------------------------------------------------------

CVE_REFERENCES: Dict[str, Dict[str, Any]] = {
    "CVE-2014-7271": {
        "score": 7.8, "source": "NVD",
        "component": "SDDM before 0.10.0 - local login bypass as user 'sddm'",
        "owner": None, "detected_here": False, "retracted": True,
        "note": "RETRACTED. Cited in an earlier revision as an MPLS TTL flaw. It is "
                "not: it is a local desktop display-manager login bypass with no "
                "network protocol content whatsoever. Kept here so the mistake is "
                "on the record and the identifier can never be quietly reused.",
    },
    "CVE-2023-31490": {
        "score": 7.5, "source": "NVD",
        "component": "FRRouting bgpd - bgp_attr_psid_sub() missing length checks "
                     "in the BGP Prefix-SID attribute's sub-TLVs",
        "owner": "sr-mplswatch", "detected_here": True,
        "finding": "SRM-SR-TLV-OVERRUN",
    },
    "CVE-2024-31948": {
        "score": 6.5, "source": "NVD",
        "component": "FRRouting bgpd through 9.1 - malformed Prefix SID attribute "
                     "in a BGP UPDATE crashes the daemon",
        "owner": "sr-mplswatch", "detected_here": True,
        "finding": "SRM-SR-TLV-OVERRUN",
    },
    "CVE-2024-31950": {
        "score": 6.5, "source": "NVD",
        "component": "FRRouting ospfd through 9.1 - ospf_te_parse_ri reads Segment "
                     "Routing sub-TLVs of the Router Information LSA without "
                     "validating their size",
        "owner": "sr-mplswatch", "detected_here": True,
        "finding": "SRM-SR-TLV-OVERRUN",
    },
    "CVE-2024-31951": {
        "score": 6.5, "source": "NVD",
        "component": "FRRouting ospfd through 9.1 - ospf_te_parse_ext_link reads "
                     "Segment Routing Adjacency SID sub-TLVs of the Opaque LSA "
                     "Extended Link without validating their lengths",
        "owner": "sr-mplswatch", "detected_here": True,
        "finding": "SRM-SR-TLV-OVERRUN",
    },
    # -- considered and REJECTED during the Sept 2026 sweep -----------------
    # Recorded so they are not re-proposed, and so the reason survives.
    "CVE-2024-31949": {
        "score": 6.5, "source": "NVD",
        "component": "FRRouting bgpd - infinite loop on a MP/GR dynamic capability",
        "owner": "bgpwatch", "detected_here": False,
        "rejected": "BGP capability negotiation, not Segment Routing.",
    },
    "CVE-2022-26125": {
        "score": None, "source": "MITRE",
        "component": "FRRouting isisd - input length checks in isis_tlvs.c",
        "owner": "isiswatch", "detected_here": False,
        "rejected": "Generic IS-IS TLV handling, not the SR sub-TLVs.",
    },
    "CVE-2022-26126": {
        "score": None, "source": "MITRE",
        "component": "FRRouting - strdup on a non-terminated string in "
                     "isis_nb_notifications.c",
        "owner": "isiswatch", "detected_here": False,
        "rejected": "Notification path; no wire signature to key on.",
    },
    "CVE-2023-44204": {
        "score": None, "source": "Juniper CNA",
        "component": "Juniper Junos rpd - malformed BGP UPDATE crashes the daemon",
        "owner": "bgpwatch", "detected_here": False,
        "rejected": "The advisory never identifies the offending field.",
    },
    "CVE-2024-21593": {
        "score": None, "source": "Juniper CNA",
        "component": "Juniper - 'a specific MPLS packet' causes a PFE crash",
        "owner": None, "detected_here": False,
        "rejected": "The advisory never says which packet. No signature exists.",
    },
    # The October 2025 FRR ospfd NULL-dereference cluster (the four recorded
    # below and siblings, all v4.0-v10.4.1, all scored 7.5 by MITRE).  Only
    # ids actually verified against NVD are recorded; the registry check
    # rejects a bare range, which is how a stray unverified id was caught here.
    # Several sit in exactly our structures - Extended Prefix Prefix-SID and
    # Extended Link Adj-SID / LAN-Adj-SID - and the malformed advertisements
    # that reach them ALREADY fire SRM-SR-TLV-OVERRUN's minimum-length half.
    # They are not CLAIMED, because the crash is conditional on the receiver
    # running "debug ospf packet all send/recv detail": these are show/dump
    # helpers, not the packet-processing path. A tap cannot see a receiver's
    # debug configuration, so claiming them would assert a risk we cannot
    # condition. The 7.5 vector models no such precondition.
    "CVE-2025-61103": {
        "score": 7.5, "source": "NVD",
        "component": "FRRouting ospfd - NULL deref in show_vty_ext_link_lan_adj_sid "
                     "(ospf_ext.c) via a crafted LSA Update",
        "owner": "sr-mplswatch", "detected_here": False,
        "rejected": "Crash requires 'debug ospf packet ... detail' on the receiver, "
                    "which a passive tap cannot observe. The wire shape is already "
                    "reported by SRM-SR-TLV-OVERRUN without claiming the CVE.",
    },
    "CVE-2025-61106": {
        "score": 7.5, "source": "NVD",
        "component": "FRRouting ospfd - NULL deref in show_vty_ext_pref_pref_sid "
                     "(ospf_ext.c) via a crafted OSPF packet",
        "owner": "sr-mplswatch", "detected_here": False,
        "rejected": "Same debug-dump precondition as CVE-2025-61103; wire shape "
                    "already covered by SRM-SR-TLV-OVERRUN.",
    },
    "CVE-2025-61107": {
        "score": 7.5, "source": "NVD",
        "component": "FRRouting ospfd - NULL deref in show_vty_pref_info "
                     "(ospf_ext.c) via a crafted LSA Update",
        "owner": "sr-mplswatch", "detected_here": False,
        "rejected": "The reporter documents the attack vector as requiring "
                    "'debug ospf packet all send/recv detail' on the victim.",
    },
    "CVE-2025-61101": {
        "score": 7.5, "source": "NVD",
        "component": "FRRouting ospfd - NULL deref in show_vty_ext_link_rmt_itf_addr "
                     "(ospf_ext.c) via a crafted OSPF packet",
        "owner": "ospfwatch", "detected_here": False,
        "rejected": "Remote Interface Address sub-TLV (RFC 7684) is not a Segment "
                    "Routing structure, plus the same debug-dump precondition.",
    },
    "CVE-2024-27913": {
        "score": None, "source": "MITRE",
        "component": "FRRouting ospfd - ospf_te_parse_te reads a missing attribute",
        "owner": "ospfwatch", "detected_here": False,
        "rejected": "RFC 3630 MPLS-TE LSA parsing, not Segment Routing, and NVD "
                    "publishes no assessment - only aggregators score it 6.5.",
    },
    "CVE-2015-5434": {
        "score": 6.5, "source": "NVD",
        "component": "HPE Comware 5/7, H3C - VRF hopping via MPLS label injection",
        "owner": "vrfwatch", "detected_here": False,
        "note": "Named only in the scope header. vrfwatch owns the detection; "
                "sr-mplswatch is the generic MPLS+SR layer.",
    },
    "CVE-2015-8087": {
        "score": None, "source": "Huawei PSIRT hw-457933",
        "component": "Huawei - same VRF-hopping mechanism, same researcher",
        "owner": "vrfwatch", "detected_here": False,
        "note": "Sibling of CVE-2015-5434. Named only in the scope header.",
    },
}

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
        "desc": "The outermost label carries TTL 0. RFC 3032 s2.4.2 requires an LSR "
                "that decrements a label TTL to zero to stop forwarding the labelled "
                "packet. Seeing one still moving means some hop is not decrementing, or "
                "the stack was built with a TTL the forwarding plane never set.",
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
    "SRM-SR-TLV-OVERRUN": {
        "severity": "high", "klass": "ATTACK", "category": "sr-mpls",
        "title": "Segment Routing TLV length inconsistent with its container",
        "desc": "A TLV or sub-TLV in an SR-bearing structure declares a length that "
                "runs past the container holding it, or is too short for the fixed "
                "fields it must carry. A parser that reads the declared length "
                "without checking it walks off the buffer. This is the wire condition "
                "behind CVE-2023-31490, CVE-2024-31948, CVE-2024-31950 and "
                "CVE-2024-31951, all of which are unvalidated SR TLV lengths in "
                "FRRouting's BGP and OSPF Segment Routing parsers.",
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
    # -- MPLS OAM: RFC 6374 loss / delay measurement ------------------------
    "SRM-OAM-MSG-MALFORMED": {
        "severity": "high", "klass": "ATTACK", "category": "oam",
        "title": "RFC 6374 measurement message malformed",
        "desc": "The measurement message is shorter than the fixed size its channel "
                "type requires (52 octets for LM, 44 for DM, 76 for the combined "
                "form), its Message Length disagrees with the frame it arrived in, or "
                "its TLV block overruns the message. This is the shape that crashes "
                "or over-reads a measurement parser, and it is the same family as the "
                "SR sub-TLV overruns already tracked by this module.",
    },
    "SRM-OAM-FIELD-INVALID": {
        "severity": "medium", "klass": "ATTACK", "category": "oam",
        "title": "RFC 6374 field carries an illegal value",
        "desc": "A measurement header field holds a value no conforming sender emits: "
                "Version other than 0, a must-be-zero Flags or DFlags bit set, a "
                "Control Code outside the assigned query or response sets for the "
                "direction indicated by the R bit, or a timestamp-format selector in "
                "the unassigned 4-15 range.",
    },
    "SRM-OAM-SELF-CONTRADICTORY": {
        "severity": "medium", "klass": "ATTACK", "category": "oam",
        "title": "RFC 6374 message contradicts itself",
        "desc": "The message's own fields disagree: a query carrying a response-only "
                "Control Code or the reverse, a Delay Measurement with the T flag "
                "clear when RFC 6374 requires it set, a query with fields that only a "
                "responder may fill (Counter 2, Timestamp 2, RTF, RPTF), or a response "
                "whose RTF matches neither the QTF nor the RPTF it cites. No single "
                "field is out of range; the combination cannot be produced by a "
                "conforming implementation.",
    },
    # -- MPLS OAM: LSP Ping (RFC 8029) and VCCV (RFC 5085) ------------------
    "SRM-LSPPING-ON-CE-PORT": {
        "severity": "high", "klass": "ATTACK", "category": "lsp-ping",
        "title": "MPLS Echo Request/Reply on a customer-facing port",
        "desc": "LSP Ping is the operator's own LSP diagnostic. On a customer-facing "
                "port, or an undeclared one, it either leaks the provider's label "
                "topology outward or is a customer probing the provider's LSPs; its "
                "Target FEC Stack names FECs, labels and segment identifiers.",
    },
    "SRM-LSPPING-DST-NOT-LOOPBACK": {
        "severity": "high", "klass": "ATTACK", "category": "lsp-ping",
        "title": "MPLS Echo Request not addressed into the loopback range",
        "desc": "RFC 8029 s4.3 addresses an echo request into 127/8 (IPv4) or "
                "0:0:0:0:0:FFFF:7F00:0/104 (IPv6) so that a packet escaping the LSP is "
                "discarded rather than delivered - RFC 1122 bars 127/8 from the wire "
                "and RFC 1812 tells routers not to forward it. A request addressed "
                "anywhere else has lost that containment and will be delivered if the "
                "label stack is wrong or stripped.",
    },
    "SRM-LSPPING-MALFORMED": {
        "severity": "high", "klass": "ATTACK", "category": "lsp-ping",
        "title": "Malformed MPLS Echo Request/Reply",
        "desc": "The datagram violates RFC 8029 framing: Version Number other than 1, "
                "a reserved or unassigned Message Type or Reply Mode, a TLV or sub-TLV "
                "whose length overruns the datagram, a Value not padded to a 4-octet "
                "boundary, or a Downstream Mapping Address Type whose length does not "
                "match the K-octet value the registry fixes for it.",
    },
    "SRM-LSPPING-FEC-FAMILY-MISMATCH": {
        "severity": "medium", "klass": "ATTACK", "category": "lsp-ping",
        "title": "Target FEC Stack sub-TLV carried over the wrong address family",
        "desc": "The IANA Target FEC Stack sub-TLV registry is address-family-split: "
                "sub-TLV 34 is an IPv4 IGP-Prefix Segment ID and 35 is its IPv6 "
                "counterpart, and the same pairing runs through the LDP, RSVP, VPN, "
                "BGP and pseudowire FECs. A family-specific sub-TLV arriving over the "
                "other family cannot be produced by a conforming sender.",
    },
    "SRM-LSPPING-FEC-UNADVERTISED": {
        "severity": "medium", "klass": "ATTACK", "category": "lsp-ping",
        "title": "LSP Ping probes an IGP-Prefix Segment nobody advertised",
        "desc": "An RFC 8287 IGP-Prefix Segment ID sub-TLV (34 for IPv4, 35 for IPv6) "
                "names a prefix for which no IS-IS, OSPFv2, OSPFv3 or BGP speaker has "
                "been seen to advertise a Prefix-SID. LSP Ping is the only OAM "
                "protocol that names segment FECs on the wire, so this is either a "
                "stale operator script or reconnaissance of the SR domain. "
                "BASELINE-DEPENDENT: it fires only once the SR ledger holds "
                "Prefix-SID advertisements, and the ledger size travels with every "
                "finding so a capture that began mid-stream is distinguishable from a "
                "real gap. NOTE: these sub-TLVs carry a PREFIX, not a SID value or "
                "index - RFC 8287 leaves the SID itself to the responder's IGP "
                "database - so the check is prefix-scoped by necessity, and the "
                "Adjacency Segment sub-TLV (36) is deliberately out of scope because "
                "its node identifiers cannot be matched to this module's ledger keys "
                "without guessing at IS-IS versus OSPF identifier formats.",
    },
    "SRM-LSPPING-DEPRECATED-FEATURE": {
        "severity": "low", "klass": "POSTURE", "category": "lsp-ping",
        "title": "Deprecated LSP Ping feature in use",
        "desc": "The exchange uses a feature the IETF has since deprecated: Reply Mode "
                "3 (reply via UDP with Router Alert, deprecated by RFC 9570), the "
                "Downstream Mapping TLV 2 (superseded by Downstream Detailed Mapping, "
                "TLV 20), or Target FEC sub-TLV 9. Router Alert in particular forces "
                "replies through the control plane of every hop.",
    },
    "SRM-VCCV-CC-RISKY": {
        "severity": "medium", "klass": "POSTURE", "category": "lsp-ping",
        "title": "Pseudowire advertises a control-plane-punting VCCV channel",
        "desc": "An LDP pseudowire advertises VCCV CC Type 2 (MPLS Router Alert label) "
                "or Type 3 (PW label with TTL 1). Both deliver the VCCV message to the "
                "control plane of the receiving router rather than keeping it in the "
                "data path, so a pseudowire's peer can meter CPU with ordinary OAM. "
                "Also fires when reserved CC/CV bits are set, or when a CC type is "
                "offered with no connectivity-verification type at all.",
    },
    # -- IOAM (RFC 9197 / RFC 9486) - IPv6 only, see the module constants ---
    "SRM-IOAM-DOMAIN-LEAK": {
        "severity": "critical", "klass": "ATTACK", "category": "ioam",
        "title": "IOAM data crossing an IOAM-domain boundary",
        "desc": "An IOAM option was observed on a customer-facing port, or an "
                "undeclared one. RFC 9486 s5 requires domain boundary routers to "
                "filter IOAM-bearing traffic in BOTH directions and states that such "
                "packets MUST NOT be leaked across domain boundaries. IOAM carries "
                "node identifiers, interface identifiers, queue depths and transit "
                "delays, so a leak is simultaneously a protocol violation and a "
                "disclosure of internal topology and capacity.",
    },
    "SRM-IOAM-MALFORMED": {
        "severity": "high", "klass": "ATTACK", "category": "ioam",
        "title": "Malformed IOAM option",
        "desc": "The IOAM option violates RFC 9197 / RFC 9486 structure: a NodeLen "
                "that disagrees with the sum of the data fields its Trace-Type "
                "selects, a NodeLen larger than any Trace-Type can imply, a "
                "RemainingLen inconsistent with the space the option actually has, an "
                "option not aligned to 4 octets, a total IOAM length beyond the "
                "255-octet ceiling, or a truncated header. The NodeLen relation is a "
                "complete self-consistency check: it needs no baseline, because the "
                "Trace-Type in the same header says exactly how much each node adds.",
    },
    "SRM-IOAM-TRACETYPE-RESERVED": {
        "severity": "medium", "klass": "ATTACK", "category": "ioam",
        "title": "IOAM Trace-Type sets a reserved or undefined bit",
        "desc": "RFC 9197 s4.4.1 requires Trace-Type bit 23 to be zero on "
                "transmission, and requires an IOAM encapsulating node to set every "
                "undefined bit (12-21) to zero. A set bit in either place is a crafted "
                "or fuzzed option, or an implementation using a codepoint IANA has not "
                "assigned - and because each undefined bit still obliges a transit "
                "node to reserve 4 octets, it is a way to inflate what every hop on "
                "the path writes.",
    },
    # -- MPLS OAM: G-ACh / MPLS-TP (RFC 5586, RFC 6428) ---------------------
    "SRM-GACH-ON-CE-PORT": {
        "severity": "critical", "klass": "ATTACK", "category": "oam",
        "title": "MPLS OAM channel on a customer-facing port",
        "desc": "A G-ACh (RFC 5586) carrying MPLS-TP or measurement OAM was seen on a "
                "port declared customer-facing, or on an undeclared port, which fails "
                "loud toward customer-facing. The OAM plane of a transport LSP has no "
                "business crossing a customer boundary: it exposes the operator's own "
                "connectivity-verification and performance-measurement traffic.",
    },
    "SRM-GACH-CHANNEL-INVALID": {
        "severity": "medium", "klass": "ATTACK", "category": "oam",
        "title": "G-ACh Channel Type unassigned, reserved or experimental",
        "desc": "The ACH Channel Type is not an IANA-assigned value, is the reserved "
                "0x0000, or falls in the 0x7FF8-0x7FFF experimental range. No "
                "conforming implementation emits an unassigned channel type on a "
                "production LSP; it is a crafted or fuzzed frame, or gear running a "
                "private extension that the operator has not declared.",
    },
    "SRM-GACH-HEADER-INVALID": {
        "severity": "medium", "klass": "ATTACK", "category": "oam",
        "title": "Malformed Associated Channel Header",
        "desc": "RFC 5586 s3.2 requires the ACH Version and Reserved fields to be zero. "
                "A non-zero value is either a crafted frame or an implementation whose "
                "framing cannot be trusted; in both cases the channel payload below it "
                "should not be relied upon.",
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


def parse_ach(data: bytes) -> Dict[str, Any]:
    """Decode an RFC 5586 Associated Channel Header.

    Four octets: 0001 | Version (4b) | Reserved (8b) | Channel Type (16b).
    Raises ParseError when the frame is too short or the first nibble is not
    0001 - callers reach here only after classify_mpls_payload said 'pw-ach',
    but the guard keeps the parser honest when called directly.
    """
    if len(data) < ACH_HEADER_LEN:
        raise ParseError("truncated associated channel header")
    if (data[0] >> 4) != ACH_FIRST_NIBBLE:
        raise ParseError("not an associated channel header")
    return {
        "version": data[0] & 0x0F,
        "reserved": data[1],
        "channel": struct.unpack_from("!H", data, 2)[0],
        "payload": data[ACH_HEADER_LEN:],
    }


def walk_interface_params(data: bytes,
                          cap: int = 32) -> List[Dict[str, Any]]:
    """Walk pseudowire Interface Parameter sub-TLVs (RFC 8077 s5.3).

    Parameter ID(8) | Length(8) | Value, where Length INCLUDES the two header
    octets - so a VCCV parameter is ID 0x0C, Length 0x04, then one CC octet
    and one CV octet.  A Length below 2 would not advance and is rejected.
    """
    out: List[Dict[str, Any]] = []
    off = 0
    guard = 0
    while off + 2 <= len(data) and guard < cap:
        guard += 1
        pid = data[off]
        plen = data[off + 1]
        if plen < 2 or off + plen > len(data):
            out.append({"id": pid, "length": plen, "value": b"",
                        "malformed": True})
            break
        out.append({"id": pid, "length": plen,
                    "value": data[off + 2:off + plen], "malformed": False})
        off += plen
    return out


def parse_pwid_fec(value: bytes) -> List[Dict[str, Any]]:
    """Decode PWid (128) and Generalized PWid (129) FEC elements.

    Only the PWid form carries interface parameters inline; the Generalized
    form's live in LDP_TLV_PW_INTERFACE_PARAMS.  PW Info Length counts the
    PW ID field PLUS the interface parameters, and a value of 0 is the
    wildcard form with no PW ID and no parameters at all.
    """
    out: List[Dict[str, Any]] = []
    off = 0
    guard = 0
    while off < len(value) and guard < 16:
        guard += 1
        etype = value[off]
        if etype not in (LDP_FEC_PWID, LDP_FEC_GENERALIZED_PWID):
            break
        if off + 4 > len(value):
            break
        cbit = (value[off + 1] >> 7) & 0x01
        pw_type = struct.unpack_from("!H", value, off + 1)[0] & 0x7FFF
        info_len = value[off + 3]
        cursor = off + 4
        rec: Dict[str, Any] = {"fec_type": etype, "control_word": bool(cbit),
                               "pw_type": pw_type, "info_len": info_len,
                               "iface_params": [], "wildcard": info_len == 0}
        if etype == LDP_FEC_PWID:
            if info_len == 0:
                # Wildcard: Group ID only, no PW ID, no parameters.
                if cursor + 4 > len(value):
                    break
                rec["group_id"] = struct.unpack_from("!I", value, cursor)[0]
                cursor += 4
            else:
                if cursor + 8 > len(value) or info_len < 4:
                    break
                rec["group_id"] = struct.unpack_from("!I", value, cursor)[0]
                rec["pw_id"] = struct.unpack_from("!I", value, cursor + 4)[0]
                cursor += 8
                params_len = info_len - 4
                if cursor + params_len > len(value):
                    break
                rec["iface_params"] = walk_interface_params(
                    value[cursor:cursor + params_len])
                cursor += params_len
        else:
            # Generalized: AGI / SAII / TAII, each Type|Length|Value.
            if cursor + info_len > len(value):
                break
            cursor += info_len
        out.append(rec)
        off = cursor
    return out


def parse_vccv_param(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 5085 s5.3.1 VCCV interface parameter value: CC byte then CV byte."""
    if len(value) < 2:
        return None
    cc, cv = value[0], value[1]
    return {
        "cc": cc, "cv": cv,
        "cc_control_word": bool(cc & VCCV_CC_CONTROL_WORD),
        "cc_router_alert": bool(cc & VCCV_CC_ROUTER_ALERT),
        "cc_ttl_expiry": bool(cc & VCCV_CC_TTL_EXPIRY),
        "cc_reserved": cc & VCCV_CC_RESERVED,
        "cv_icmp_ping": bool(cv & VCCV_CV_ICMP_PING),
        "cv_lsp_ping": bool(cv & VCCV_CV_LSP_PING),
        "cv_reserved": cv & VCCV_CV_RESERVED,
    }


def walk_ipv6_options(area: bytes, cap: int = 32) -> List[Dict[str, Any]]:
    """Walk a Hop-by-Hop / Destination Options TLV area (RFC 8200 s4.2).

    Pad1 is a single octet with no length; every other option is
    Type(1) | Opt Data Len(1) | data.  A truncated option terminates the walk
    and is reported through the 'truncated' key rather than raising, because
    the caller must still be able to report the options it did parse.
    """
    out: List[Dict[str, Any]] = []
    off = 0
    guard = 0
    while off < len(area) and guard < cap:
        guard += 1
        otype = area[off]
        if otype == IPV6_OPT_PAD1:
            off += 1
            continue
        if off + 2 > len(area):
            out.append({"type": otype, "offset": off, "truncated": True,
                        "data": b"", "length": None})
            break
        olen = area[off + 1]
        dstart = off + 2
        if dstart + olen > len(area):
            out.append({"type": otype, "offset": off, "truncated": True,
                        "data": area[dstart:], "length": olen})
            break
        out.append({"type": otype, "offset": off, "truncated": False,
                    "length": olen, "data": area[dstart:dstart + olen]})
        off = dstart + olen
    return out


def ioam_nodelen_expected(trace_type: int) -> int:
    """Sum of the 4-octet units the set Trace-Type bits imply.

    Bit 0 is the MOST significant bit of the 24-bit field.  Bit 22 (Opaque
    State Snapshot) is variable and excluded from NodeLen; bit 23 contributes
    no data field.
    """
    total = 0
    for bit, units in IOAM_TRACE_UNITS.items():
        if trace_type & (1 << (23 - bit)):
            total += units
    return total


def ioam_trace_bits_set(trace_type: int) -> List[int]:
    """Which Trace-Type bit positions are set, in RFC bit numbering."""
    return [bit for bit in range(24) if trace_type & (1 << (23 - bit))]


def parse_ioam_option(data: bytes) -> Dict[str, Any]:
    """RFC 9486 Fig. 1 IOAM option body (the part after Type/Len).

    The IPv6 option data begins with Reserved(8) | IOAM Opt-Type(8), so the
    IOAM option type is the SECOND octet of the option data, not the first.
    """
    if len(data) < 2:
        raise ParseError("truncated IOAM option")
    return {"reserved": data[0], "ioam_type": data[1], "body": data[2:]}


def parse_ioam_trace(body: bytes) -> Dict[str, Any]:
    """RFC 9197 s4.4.1 trace option header."""
    if len(body) < IOAM_TRACE_HEADER_LEN:
        raise ParseError("truncated IOAM trace header")
    ns, packed = struct.unpack_from("!HH", body, 0)
    node_len = (packed >> 11) & 0x1F
    flags = (packed >> 7) & 0x0F
    remaining = packed & 0x7F
    w2 = struct.unpack_from("!I", body, 4)[0]
    trace_type = (w2 >> 8) & 0xFFFFFF
    reserved = w2 & 0xFF
    return {"namespace": ns, "node_len": node_len, "flags": flags,
            "remaining_len": remaining, "trace_type": trace_type,
            "reserved": reserved,
            "overflow": bool(flags & IOAM_TRACE_FLAG_OVERFLOW),
            "flags_mbz": flags & IOAM_TRACE_FLAG_MBZ,
            "data": body[IOAM_TRACE_HEADER_LEN:]}


def parse_lspping(data: bytes) -> Dict[str, Any]:
    """Decode an RFC 8029 MPLS Echo Request / Reply header.

    Version Number is 16 bits (value 1) and Global Flags is the other half of
    the first word - not an 8-bit version plus padding.
    """
    if len(data) < LSPPING_HEADER_LEN:
        raise ParseError("truncated MPLS echo header")
    version, gflags = struct.unpack_from("!HH", data, 0)
    msg_type, reply_mode, rc, rsc = struct.unpack_from("!BBBB", data, 4)
    handle, seq = struct.unpack_from("!II", data, 8)
    return {
        "version": version,
        "global_flags": gflags,
        "msg_type": msg_type,
        "reply_mode": reply_mode,
        "return_code": rc,
        "return_subcode": rsc,
        "handle": handle,
        "sequence": seq,
        "tlvs_off": LSPPING_HEADER_LEN,
    }


def walk_lspping_tlvs(data: bytes, off: int,
                      cap: int = 64) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Walk a top-level TLV block.

    Returns (tlvs, error).  RFC 8029 s3: Length counts the Value octets
    EXCLUDING padding, and the Value is zero-padded to a 4-octet boundary, so
    the step to the next TLV is 4 + roundup4(Length).
    """
    out: List[Dict[str, Any]] = []
    guard = 0
    while off + 4 <= len(data) and guard < cap:
        guard += 1
        t_type, t_len = struct.unpack_from("!HH", data, off)
        val_off = off + 4
        if val_off + t_len > len(data):
            return out, "TLV length overruns the datagram"
        padded = t_len + ((-t_len) % 4)
        out.append({
            "type": t_type,
            "length": t_len,
            "value": data[val_off:val_off + t_len],
            "offset": off,
            "padded_len": padded,
            "mandatory": t_type <= LSPPING_TLV_MANDATORY_MAX,
        })
        if val_off + padded > len(data):
            return out, "TLV padding overruns the datagram"
        off += 4 + padded
    if off != len(data) and guard < cap:
        return out, "trailing octets after the final TLV"
    return out, None


def walk_fec_subtlvs(value: bytes,
                     cap: int = 32) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Walk the sub-TLVs inside a Target FEC Stack TLV (same 4-octet rules)."""
    out: List[Dict[str, Any]] = []
    off = 0
    guard = 0
    while off + 4 <= len(value) and guard < cap:
        guard += 1
        s_type, s_len = struct.unpack_from("!HH", value, off)
        v_off = off + 4
        if v_off + s_len > len(value):
            return out, "FEC sub-TLV length overruns the TLV"
        padded = s_len + ((-s_len) % 4)
        out.append({"type": s_type, "length": s_len,
                    "value": value[v_off:v_off + s_len], "offset": off})
        off += 4 + padded
    return out, None


def parse_fec_prefix_sid(value: bytes, family: str) -> Dict[str, Any]:
    """RFC 8287 s5.1 / s5.2 IGP-Prefix Segment ID sub-TLV.

    v4 (sub-TLV 34): Prefix(4) | PrefixLen(1) | Protocol(1) | Reserved(2)  = 8
    v6 (sub-TLV 35): Prefix(16) | PrefixLen(1) | Protocol(1) | Reserved(2) = 20

    These carry NO SID value and no index: RFC 8287 leaves resolution of the
    segment to the responder's own IGP database.  Anything built on top of
    this can therefore only reason about the PREFIX.
    """
    alen = 4 if family == "ipv4" else 16
    need = alen + 4
    if len(value) < need:
        raise ParseError("truncated IGP-Prefix Segment ID sub-TLV")
    raw = value[:alen]
    plen = value[alen]
    proto = value[alen + 1]
    reserved = struct.unpack_from("!H", value, alen + 2)[0]
    max_plen = 32 if family == "ipv4" else 128
    prefix = None
    if 1 <= plen <= max_plen:
        try:
            addr = (ipaddress.IPv4Address(raw) if family == "ipv4"
                    else ipaddress.IPv6Address(raw))
            prefix = str(ipaddress.ip_network("%s/%d" % (addr, plen), strict=False))
        except (ValueError, ipaddress.AddressValueError):
            prefix = None
    return {"prefix": prefix, "prefix_len": plen, "protocol": proto,
            "reserved": reserved, "max_prefix_len": max_plen,
            "value_len": len(value), "expected_len": need}


# RFC 8287 s5.3 Adjacency types.  Parsed only far enough to validate framing:
# the node identifiers are NOT matched against this module's SR ledger, because
# doing so would mean guessing whether a 4-octet field is an OSPF Router ID or
# a truncated IS-IS System ID.
FEC_ADJ_TYPES: Dict[int, Tuple[str, int]] = {
    0: ("unnumbered", 4),
    1: ("parallel", 4),
    4: ("ipv4-non-parallel", 4),
    6: ("ipv6-non-parallel", 16),
}
FEC_PROTOCOL_ANY = 0
FEC_PROTOCOL_OSPF = 1
FEC_PROTOCOL_ISIS = 2


def parse_fec_adj_sid(value: bytes) -> Dict[str, Any]:
    """RFC 8287 s5.3 IGP-Adjacency Segment ID sub-TLV - framing only."""
    if len(value) < 4:
        raise ParseError("truncated IGP-Adjacency Segment ID sub-TLV")
    adj_type = value[0]
    proto = value[1]
    reserved = struct.unpack_from("!H", value, 2)[0]
    info = FEC_ADJ_TYPES.get(adj_type)
    expected = None
    if info is not None:
        iface = info[1]
        # Advertising + Receiving Node Identifier: 4 octets for OSPF or a
        # zeroed Protocol 0, 6 for IS-IS.
        node = 6 if proto == FEC_PROTOCOL_ISIS else 4
        expected = 4 + 2 * iface + 2 * node
    return {"adj_type": adj_type, "adj_type_name": info[0] if info else None,
            "protocol": proto, "reserved": reserved,
            "value_len": len(value), "expected_len": expected}


def fec_subtlv_family(stype: int) -> Optional[str]:
    """'ipv4', 'ipv6', 'neutral' or None (unknown) for a FEC sub-TLV type."""
    if stype in LSPPING_FEC_V4:
        return "ipv4"
    if stype in LSPPING_FEC_V6:
        return "ipv6"
    if stype in LSPPING_FEC_NEUTRAL:
        return "neutral"
    return None


def lspping_in_loopback(addr: str) -> bool:
    """Is this echo destination inside the RFC 8029 s4.3 loopback range?"""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version == 4:
        return ip in LSPPING_LOOPBACK_V4
    # An IPv4-mapped v6 destination is the v6 form of the same rule.
    return ip in LSPPING_LOOPBACK_V6


def parse_measurement(data: bytes, family: str) -> Dict[str, Any]:
    """Decode an RFC 6374 LM / DM / combined measurement message header.

    `family` is 'lm', 'dm' or 'lmdm' and selects the word-2 layout, which is
    the only part that differs between the three.  The caller derives it from
    the G-ACh Channel Type via GACH_MEASUREMENT.
    """
    if len(data) < 8:
        raise ParseError("truncated measurement header")
    version = data[0] >> 4
    flags = data[0] & 0x0F
    ctrl = data[1]
    msg_len = struct.unpack_from("!H", data, 2)[0]

    out: Dict[str, Any] = {
        "version": version,
        "flags": flags,
        "r": bool(flags & MEAS_FLAG_R),
        "t": bool(flags & MEAS_FLAG_T),
        "flags_mbz": flags & MEAS_FLAG_MBZ,
        "control_code": ctrl,
        "msg_len": msg_len,
        "family": family,
        "dflags": None, "dflags_mbz": None, "otf": None,
        "qtf": None, "rtf": None, "rptf": None,
    }

    w2 = struct.unpack_from("!I", data, 4)[0]
    if family == "lm":
        out["dflags"] = (w2 >> 28) & 0x0F
        out["dflags_mbz"] = out["dflags"] & MEAS_DFLAG_MBZ
        out["otf"] = (w2 >> 24) & 0x0F
        out["reserved"] = w2 & 0x00FFFFFF
    elif family == "dm":
        out["qtf"] = (w2 >> 28) & 0x0F
        out["rtf"] = (w2 >> 24) & 0x0F
        out["rptf"] = (w2 >> 20) & 0x0F
        out["reserved"] = w2 & 0x000FFFFF
    else:                                  # lmdm
        out["dflags"] = (w2 >> 28) & 0x0F
        out["dflags_mbz"] = out["dflags"] & MEAS_DFLAG_MBZ
        out["qtf"] = (w2 >> 24) & 0x0F
        out["rtf"] = (w2 >> 20) & 0x0F
        out["rptf"] = (w2 >> 16) & 0x0F
        out["reserved"] = w2 & 0x0000FFFF

    if len(data) >= 12:
        w3 = struct.unpack_from("!I", data, 8)[0]
        out["session_id"] = w3 >> 8
        # DS is only meaningful when T = 1 (RFC 6374 s3.1).  Recorded as None
        # otherwise so no rule can accidentally reason about it.
        out["ds"] = (w3 & 0xFF) if out["t"] else None
    else:
        out["session_id"] = None
        out["ds"] = None

    # Offsets of the fields a conforming QUERY must leave zero.  These differ
    # per family and are read straight off the RFC 6374 diagrams:
    #   LM    : OriginTS 12, Counter1 20, Counter2 28, C3 36, C4 44  (52 total)
    #   DM    : TS1 12, TS2 20, TS3 28, TS4 36                       (44 total)
    #   LM+DM : TS1 12, TS2 20, TS3 28, TS4 36, C1 44, C2 52, C3 60, C4 68 (76)
    out["counter2_off"] = {"lm": 28, "dm": None, "lmdm": 52}[family]
    out["timestamp2_off"] = {"lm": None, "dm": 20, "lmdm": 20}[family]
    return out


def _u64(data: bytes, off: Optional[int]) -> Optional[int]:
    """Read a 64-bit field, or None when it is absent or truncated away."""
    if off is None or off + 8 > len(data):
        return None
    return struct.unpack_from("!Q", data, off)[0]


def measurement_family(channel: int) -> Optional[str]:
    """Map a G-ACh Channel Type to the RFC 6374 word-2 layout family."""
    if channel in (GACH_DLM, GACH_ILM):
        return "lm"
    if channel == GACH_DM:
        return "dm"
    if channel in (GACH_DLM_DM, GACH_ILM_DM):
        return "lmdm"
    return None


def gach_channel_kind(channel: int) -> str:
    """Classify a Channel Type against the IANA registry: 'assigned',
    'reserved', 'experimental' or 'unassigned'."""
    if channel in GACH_ASSIGNED:
        return "assigned"
    if channel == 0x0000:
        return "reserved"
    if channel in GACH_EXPERIMENTAL:
        return "experimental"
    return "unassigned"


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


def walk_ipv6_headers(data: bytes) -> Tuple[Optional[Dict[str, Any]], int,
                                            Optional[bytes], int, bool,
                                            List[Tuple[int, bytes]]]:
    """Walk the whole IPv6 extension-header chain.

    Returns (srh_or_None, final_next_header, raw_srh_or_None, payload_offset,
    is_later_fragment, option_areas).  Unlike the first revision this does NOT
    stop at the Routing Header: it records the SRH and keeps walking, because
    the upper layer protocol behind the chain is what carries LDP, BGP and
    RSVP-TE over IPv6 and the module was blind to all three.

    option_areas is a list of (header_protocol, option_bytes) for every
    Hop-by-Hop and Destination Options header traversed, where option_bytes is
    the TLV area with the 2-byte Next Header / Hdr Ext Len prefix already
    stripped.  The chain used to be walked for length only and the options
    thrown away, which made IOAM (RFC 9486) invisible - it rides in exactly
    these two headers.
    """
    if len(data) < 40:
        raise ParseError("truncated IPv6 header")
    nh = data[6]
    off = 40
    hops = 0
    srh: Optional[Dict[str, Any]] = None
    raw: Optional[bytes] = None
    later_fragment = False
    opts: List[Tuple[int, bytes]] = []
    while hops < _MAX_IPV6_EXT_CHAIN:
        if nh not in IPV6_EXT_HEADERS:
            return srh, nh, raw, off, later_fragment, opts
        if nh == IPPROTO_IPV6_FRAG:
            if off + 8 > len(data):
                raise ParseError("truncated fragment header")
            # RFC 8200 s4.5: only the FIRST fragment carries the upper-layer
            # header, so a later fragment must never be dissected as one.
            if (struct.unpack_from("!H", data, off + 2)[0] >> 3) != 0:
                later_fragment = True
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
            if data[off + 2] == SRH_ROUTING_TYPE and srh is None:
                raw = data[off:off + ext_len]
                srh = parse_srh(data, off, len(data))
        if nh == IPPROTO_AH:
            ext_len = (hdr_ext_len + 2) * 4
        if ext_len <= 0 or off + ext_len > len(data):
            # A malformed header AFTER a valid SRH must not suppress the SRH
            # finding; report what was parsed and dispatch no transport.
            if srh is not None:
                return srh, this_nh, raw, len(data), later_fragment, opts
            raise ParseError("extension header length overruns packet")
        if nh in (IPPROTO_HOPOPT, IPPROTO_IPV6_OPTS):
            # RFC 8200 s4.3/s4.6: the option area is everything after the
            # 2-byte Next Header / Hdr Ext Len prefix.
            opts.append((nh, data[off + 2:off + ext_len]))
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
        attrs.append({"flags": flags, "type": atype, "value": body[vstart:vend],
                      "available": max(0, end - vstart),
                      "overrun": (vstart + alen) > end})
        off = vstart + alen
        guard += 1
    return attrs


def parse_prefix_sid(value: bytes) -> Dict[str, Any]:
    """BGP Prefix-SID attribute (RFC 8669 s3): TLVs of {type, len(2), value}."""
    out: Dict[str, Any] = {"label_index": None, "srgb": [], "srv6_service": False,
                           "tlvs": []}
    off = 0
    guard = 0
    while off + 3 <= len(value) and guard < 16:
        ttype = value[off]
        tlen = struct.unpack_from("!H", value, off + 1)[0]
        vstart = off + 3
        vend = min(len(value), vstart + tlen)
        v = value[vstart:vend]
        out["tlvs"].append({"type": ttype, "len": tlen, "value": v,
                            "available": max(0, len(value) - vstart),
                            "overrun": (vstart + tlen) > len(value)})
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
        out.append({"type": ttype, "len": tlen, "value": data[vstart:vend],
                    "available": max(0, end - vstart),
                    "overrun": (vstart + tlen) > end})
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
        out.append({"type": ttype, "len": tlen, "value": value[vstart:vend],
                    "available": max(0, len(value) - vstart),
                    "overrun": (vstart + tlen) > len(value)})
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


# -- IGP-SR: OSPFv3 (RFC 5340 / RFC 8362 extended LSAs / RFC 8666 SR) ------

def parse_ospfv3_header(data: bytes) -> Dict[str, Any]:
    """RFC 5340 sA.3.1: Version(1) Type(1) Length(2) RouterID(4) AreaID(4)
    Checksum(2) InstanceID(1) Reserved(1) - 16 octets, not 24 like OSPFv2."""
    if len(data) < OSPFV3_HDR_LEN:
        raise ParseError("truncated OSPFv3 header")
    if data[0] != OSPFV3_VERSION:
        raise ParseError("not OSPFv3")
    return {"version": data[0], "type": data[1],
            "length": struct.unpack_from("!H", data, 2)[0],
            "router_id": str(ipaddress.IPv4Address(data[4:8])),
            "area_id": str(ipaddress.IPv4Address(data[8:12])),
            "instance_id": data[12]}


def parse_ospfv3_lsas(data: bytes) -> List[Dict[str, Any]]:
    """LS Update body: count(4) then LSAs.  The OSPFv3 LSA header puts a
    TWO-octet LS Type at offset 2; OSPFv2 puts a one-octet type at offset 3."""
    if len(data) < OSPFV3_HDR_LEN + 4:
        return []
    count = struct.unpack_from("!I", data, OSPFV3_HDR_LEN)[0]
    off = OSPFV3_HDR_LEN + 4
    out: List[Dict[str, Any]] = []
    guard = 0
    while off + OSPFV3_LSA_HDR_LEN <= len(data) and guard < min(count, _MAX_OSPF_LSAS):
        guard += 1
        ls_type = struct.unpack_from("!H", data, off + 2)[0]
        length = struct.unpack_from("!H", data, off + 18)[0]
        if length < OSPFV3_LSA_HDR_LEN:
            break
        end = min(len(data), off + length)
        fc = ls_type & OSPFV3_LS_TYPE_FC_MASK
        body = data[off + OSPFV3_LSA_HDR_LEN:end]
        prefix = OSPFV3_BODY_PREFIX.get(fc)
        out.append({"ls_type": ls_type, "function_code": fc,
                    "adv_router": str(ipaddress.IPv4Address(data[off + 8:off + 12])),
                    "length": length, "body": body,
                    "tlv_block": body[prefix:] if prefix is not None
                                 and prefix <= len(body) else None})
        off += length
    return out


def parse_ospfv3_prefix_tlv(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 8362 s3.4/3.6/3.7 - Inter-Area-Prefix, External-Prefix and
    Intra-Area-Prefix TLVs share one shape:
      Metric word(4) | PrefixLength(1) PrefixOptions(1) 0(2) | Prefix | subTLVs
    The prefix occupies ((PrefixLength + 31) / 32) 32-bit words."""
    if len(value) < 8:
        return None
    plen, popts = value[4], value[5]
    if plen > 128:
        return None
    nwords = (plen + 31) // 32
    off = 8 + nwords * 4
    if off > len(value):
        return None
    raw = value[8:8 + nwords * 4] + b"\x00" * 16
    try:
        net = ipaddress.ip_network(
            "%s/%d" % (ipaddress.IPv6Address(raw[:16]), plen), strict=False)
    except (ValueError, ipaddress.AddressValueError):
        return None
    return {"prefix": str(net), "prefix_options": popts,
            "subtlvs": parse_ospf_tlvs(value[off:])}


def parse_ospfv3_ext_prefix_range(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 8666 s5: PrefixLength(1) AF(1) RangeSize(2) Flags(1) Reserved(3)
    Prefix(variable) subTLVs.  Used by the SR Mapping Server."""
    if len(value) < 8:
        return None
    plen, af = value[0], value[1]
    range_size = struct.unpack_from("!H", value, 2)[0]
    if plen > 128 or af not in (OSPFV3_AF_IPV4, OSPFV3_AF_IPV6):
        return None
    nwords = (plen + 31) // 32
    off = 8 + nwords * 4
    if off > len(value):
        return None
    raw = value[8:8 + nwords * 4]
    try:
        if af == OSPFV3_AF_IPV4:
            net = ipaddress.ip_network(
                "%s/%d" % (ipaddress.IPv4Address((raw + b"\x00" * 4)[:4]), plen),
                strict=False)
        else:
            net = ipaddress.ip_network(
                "%s/%d" % (ipaddress.IPv6Address((raw + b"\x00" * 16)[:16]), plen),
                strict=False)
    except (ValueError, ipaddress.AddressValueError):
        return None
    return {"prefix": str(net), "range_size": range_size, "af": af,
            "subtlvs": parse_ospf_tlvs(value[off:])}


def parse_ospfv3_router_link(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 8362 s3.2: Type(1) 0(1) Metric(2) InterfaceID(4)
    NeighborInterfaceID(4) NeighborRouterID(4) then sub-TLVs."""
    if len(value) < 16:
        return None
    return {"link_type": value[0],
            "interface_id": struct.unpack_from("!I", value, 4)[0],
            "neighbor_router_id": str(ipaddress.IPv4Address(value[12:16])),
            "subtlvs": parse_ospf_tlvs(value[16:])}


def parse_ospfv3_prefix_sid(value: bytes) -> Optional[Dict[str, Any]]:
    """RFC 8666 s6: Flags(1) Algorithm(1) Reserved(2) SID(4 or 3).

    NOTE the field order: OSPFv2 (RFC 8665 s5) is Flags, Reserved, MT-ID,
    Algorithm - the algorithm sits at offset 3 there and offset 1 here.
    Reusing the OSPFv2 parser would read the wrong octet as the algorithm and
    file every SID under a bogus one."""
    if len(value) < 7:
        return None
    flags, algorithm = value[0], value[1]
    kind, sid = sid_from_flags(flags, value[4:], OSPFV3_PSID_FLAG_V,
                               OSPFV3_PSID_FLAG_L)
    return {"flags": flags, "algorithm": algorithm, "kind": kind, "sid": sid,
            "mapping_server": bool(flags & OSPFV3_PSID_FLAG_M)}


def parse_ospfv3_adj_sid(value: bytes, lan: bool = False
                         ) -> Optional[Dict[str, Any]]:
    """RFC 8666 s7.1: Flags(1) Weight(1) Reserved(2) SID(4 or 3).
    s7.2 LAN form inserts a 4-octet Neighbor ID before the SID."""
    need = 11 if lan else 7
    if len(value) < need:
        return None
    flags, weight = value[0], value[1]
    off = 8 if lan else 4
    neighbor = str(ipaddress.IPv4Address(value[4:8])) if lan else None
    kind, sid = sid_from_flags(flags, value[off:], OSPFV3_ASID_FLAG_V,
                               OSPFV3_ASID_FLAG_L)
    return {"flags": flags, "weight": weight, "kind": kind, "sid": sid,
            "neighbor": neighbor,
            "persistent": bool(flags & OSPFV3_ASID_FLAG_P),
            "group": bool(flags & OSPFV3_ASID_FLAG_G)}


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

        # The G-ACh sits below the bottom of stack with no IP header at all.
        # It is reachable only through a label stack, which is why this module
        # owns it (see the bfdwatch seam, handled in _handle_gach).
        if kind == "pw-ach":
            self._handle_gach(payload, ts, entries, stack_str, labels)
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

    # -- MPLS OAM: G-ACh ----------------------------------------------------

    def _handle_gach(self, payload: bytes, ts: float, entries: List[LSE],
                     stack_str: str, labels: List[int]) -> None:
        """Decode an RFC 5586 Associated Channel and route its payload.

        THE bfdwatch SEAM LIVES HERE.  Channel Types 0x0021 and 0x0057 mean
        'the payload is an ordinary IP packet' by IANA assignment, so they are
        handed to the IP path and anything IP/UDP-rooted below them - BFD
        included - belongs to the module that owns IP/UDP.  Every other
        channel type has no IP header anywhere and is reachable only through
        a label stack, so it stays here.

        This module therefore reports the channel and any structural problem
        and stops.  It does NOT decode BFD session state: an ACH-encapsulated
        BFD session is a different session from any IP/UDP one, so sharing
        state across the seam would be wrong rather than merely redundant.
        """
        try:
            ach = parse_ach(payload)
        except ParseError:
            self._fire("SRM-GACH-HEADER-INVALID", "ach:truncated", ts,
                       reason="truncated or non-ACH first nibble",
                       payload_len=len(payload), stack=labels)
            return

        self.stats["gach"] += 1
        channel = ach["channel"]
        kind = gach_channel_kind(channel)
        has_gal = any(e.label == LABEL_GAL for e in entries)

        ev = {"channel": channel, "channel_hex": "0x%04X" % channel,
              "channel_name": GACH_ASSIGNED.get(channel), "stack": labels,
              "gal_present": has_gal}

        # EXPOSURE of the operator's own OAM plane across a customer boundary.
        if self._ce_gate(ts):
            self._fire("SRM-GACH-ON-CE-PORT", "gach:%04X" % channel, ts,
                       declared_role=self.cfg.role, **ev)

        # RFC 5586 s3.2: Version and Reserved MUST be zero.
        if ach["version"] != 0:
            self._fire("SRM-GACH-HEADER-INVALID", "ach:version", ts,
                       field="version", value=ach["version"], **ev)
        if ach["reserved"] != 0:
            self._fire("SRM-GACH-HEADER-INVALID", "ach:reserved", ts,
                       field="reserved", value=ach["reserved"], **ev)

        if kind != "assigned":
            self._fire("SRM-GACH-CHANNEL-INVALID", "gach:%04X" % channel, ts,
                       range_kind=kind, **ev)
            return

        # -- the seam: hand an IP payload to the IP path ---------------------
        if channel in GACH_IP_PAYLOAD:
            inner = ach["payload"]
            try:
                if channel == GACH_IPV4:
                    # handle_ipv4 takes no under_mpls flag: that flag exists
                    # only so srv6-category findings can say how the SRH
                    # arrived, and there is no IPv4 SRH to qualify.
                    self.handle_ipv4(inner, ts)
                else:
                    self.handle_ipv6(inner, ts, under_mpls=True)
            except ParseError:
                pass
            return

        # RFC 6374 measurement: five channel types, three message layouts.
        if channel in GACH_MEASUREMENT:
            self._check_measurement(ach["payload"], ts, channel, ev)
            return

    def _check_measurement(self, body: bytes, ts: float, channel: int,
                           ev: Dict[str, Any]) -> None:
        """RFC 6374 loss / delay measurement structural and consistency rules.

        Deliberately silent about whether counters or timestamps are TRUTHFUL.
        That cannot be judged from the wire without a trusted reference clock
        and a baseline, so no rule here asserts it.
        """
        name, fixed = GACH_MEASUREMENT[channel]
        family = measurement_family(channel)
        if family is None:                      # unreachable; keeps mypy honest
            return
        self.stats["measurement"] += 1
        base = dict(ev)
        base.update({"measurement": name, "fixed_size": fixed})
        key = "meas:%04X" % channel

        # -- length ----------------------------------------------------------
        if len(body) < fixed:
            self._fire("SRM-OAM-MSG-MALFORMED", key + ":short", ts,
                       reason="shorter than the fixed size for this channel type",
                       actual=len(body), expected_min=fixed, **base)
            return

        try:
            m = parse_measurement(body, family)
        except ParseError as exc:
            self._fire("SRM-OAM-MSG-MALFORMED", key + ":parse", ts,
                       reason=str(exc), actual=len(body), expected_min=fixed, **base)
            return

        base["session_id"] = m["session_id"]
        base["r"] = m["r"]
        base["t"] = m["t"]
        base["control_code"] = m["control_code"]

        # Message Length must cover the fixed header and sit inside the frame.
        if m["msg_len"] < fixed or m["msg_len"] > len(body):
            self._fire("SRM-OAM-MSG-MALFORMED", key + ":msglen", ts,
                       reason="Message Length disagrees with the frame",
                       msg_len=m["msg_len"], actual=len(body),
                       expected_min=fixed, **base)

        # TLV block: walk it only as far as the message claims to be.
        tlv_off = fixed
        end = min(m["msg_len"], len(body)) if m["msg_len"] >= fixed else len(body)
        guard = 0
        while tlv_off + 2 <= end and guard < 64:
            guard += 1
            t_type = body[tlv_off]
            t_len = body[tlv_off + 1]
            if tlv_off + 2 + t_len > end:
                self._fire("SRM-OAM-MSG-MALFORMED", key + ":tlv", ts,
                           reason="TLV object overruns the message",
                           tlv_type=t_type, tlv_len=t_len, tlv_offset=tlv_off,
                           message_end=end, mandatory=t_len <= MEAS_TLV_MANDATORY_MAX,
                           **base)
                break
            tlv_off += 2 + t_len

        # -- illegal field values -------------------------------------------
        if m["version"] != MEAS_VERSION:
            self._fire("SRM-OAM-FIELD-INVALID", key + ":version", ts,
                       field="version", value=m["version"],
                       required=MEAS_VERSION, **base)
        if m["flags_mbz"]:
            self._fire("SRM-OAM-FIELD-INVALID", key + ":flags-mbz", ts,
                       field="flags-must-be-zero", value=m["flags_mbz"], **base)
        if m["dflags_mbz"]:
            self._fire("SRM-OAM-FIELD-INVALID", key + ":dflags-mbz", ts,
                       field="dflags-must-be-zero", value=m["dflags_mbz"], **base)

        legal = MEAS_RESPONSE_CODES if m["r"] else MEAS_QUERY_CODES
        if m["control_code"] not in legal:
            # Distinguish "no such code" from "right code, wrong direction":
            # the second is a contradiction, not an unassigned value.
            other = MEAS_QUERY_CODES if m["r"] else MEAS_RESPONSE_CODES
            if m["control_code"] in other:
                self._fire("SRM-OAM-SELF-CONTRADICTORY", key + ":ctrl-direction", ts,
                           rule="control code belongs to the other direction",
                           **base)
            else:
                self._fire("SRM-OAM-FIELD-INVALID", key + ":ctrl", ts,
                           field="control-code", value=m["control_code"],
                           direction="response" if m["r"] else "query", **base)

        for fld in ("otf", "qtf", "rtf", "rptf"):
            val = m[fld]
            if val is not None and val > MEAS_TS_MAX_ASSIGNED:
                self._fire("SRM-OAM-FIELD-INVALID", key + ":" + fld, ts,
                           field=fld, value=val,
                           max_assigned=MEAS_TS_MAX_ASSIGNED, **base)

        # -- self-contradiction ----------------------------------------------
        # RFC 6374 s3.2: DM has the T flag set, always.
        if family in ("dm", "lmdm") and not m["t"]:
            self._fire("SRM-OAM-SELF-CONTRADICTORY", key + ":dm-t-clear", ts,
                       rule="delay measurement with the T flag clear", **base)

        if not m["r"]:
            # A QUERY may not pre-fill the responder's fields.
            if m["rtf"] or m["rptf"]:
                self._fire("SRM-OAM-SELF-CONTRADICTORY", key + ":query-rtf", ts,
                           rule="query carries a responder timestamp format",
                           rtf=m["rtf"], rptf=m["rptf"], **base)
            c2 = _u64(body, m["counter2_off"])
            if c2:
                self._fire("SRM-OAM-SELF-CONTRADICTORY", key + ":query-counter2", ts,
                           rule="query with a non-zero Counter 2", counter2=c2, **base)
            t2 = _u64(body, m["timestamp2_off"])
            if t2:
                self._fire("SRM-OAM-SELF-CONTRADICTORY", key + ":query-ts2", ts,
                           rule="query with a non-zero Timestamp 2", timestamp2=t2,
                           **base)
        else:
            # RFC 6374 s3.2: a responder's RTF is either the format the
            # querier used or the one the responder said it preferred.
            if m["rtf"] is not None and m["rtf"] not in (m["qtf"], m["rptf"]):
                self._fire("SRM-OAM-SELF-CONTRADICTORY", key + ":rtf-unrelated", ts,
                           rule="response RTF matches neither QTF nor RPTF",
                           qtf=m["qtf"], rtf=m["rtf"], rptf=m["rptf"], **base)
            # A RESPONSE must leave Timestamp 2 zero (RFC 6374 s3.2).
            t2 = _u64(body, m["timestamp2_off"])
            if t2:
                self._fire("SRM-OAM-SELF-CONTRADICTORY", key + ":resp-ts2", ts,
                           rule="response with a non-zero Timestamp 2",
                           timestamp2=t2, **base)

    # -- LSP Ping (RFC 8029) ------------------------------------------------

    def handle_lspping(self, body: bytes, src: str, dst: str, ts: float,
                       sport: int, dport: int) -> None:
        """RFC 8029 MPLS Echo Request / Reply.

        Structural and containment rules only.  Whether the FEC a request
        names actually exists in the forwarding plane is not knowable from a
        passive tap, so no rule asserts it; the one rule that reasons beyond a
        single datagram is the SR-ledger cross-check, which says so in its
        own evidence.
        """
        try:
            pdu = parse_lspping(body)
        except ParseError as exc:
            self._fire("SRM-LSPPING-MALFORMED", "lspping:%s:trunc" % src, ts,
                       src=src, dst=dst, reason=str(exc), length=len(body),
                       expected_min=LSPPING_HEADER_LEN)
            return

        self.stats["lspping"] += 1
        family = "ipv6" if ":" in dst else "ipv4"
        is_request = pdu["msg_type"] in (LSPPING_MSG_ECHO_REQUEST,
                                         LSPPING_MSG_PROXY_REQUEST)
        ev = {"src": src, "dst": dst, "sport": sport, "dport": dport,
              "family": family, "msg_type": pdu["msg_type"],
              "reply_mode": pdu["reply_mode"], "return_code": pdu["return_code"],
              "handle": pdu["handle"], "sequence": pdu["sequence"]}
        key = "lspping:%s" % src

        if self._ce_gate(ts):
            self._fire("SRM-LSPPING-ON-CE-PORT", key, ts,
                       declared_role=self.cfg.role, **ev)

        # -- framing ---------------------------------------------------------
        if pdu["version"] != LSPPING_VERSION:
            self._fire("SRM-LSPPING-MALFORMED", key + ":version", ts,
                       field="version", value=pdu["version"],
                       required=LSPPING_VERSION, **ev)
        if pdu["msg_type"] not in LSPPING_MSG_ASSIGNED:
            self._fire("SRM-LSPPING-MALFORMED", key + ":msgtype", ts,
                       field="message-type", value=pdu["msg_type"], **ev)
        if pdu["reply_mode"] not in LSPPING_REPLY_ASSIGNED:
            self._fire("SRM-LSPPING-MALFORMED", key + ":replymode", ts,
                       field="reply-mode", value=pdu["reply_mode"], **ev)
        elif pdu["reply_mode"] == LSPPING_REPLY_UDP_ROUTER_ALERT:
            self._fire("SRM-LSPPING-DEPRECATED-FEATURE", key + ":replymode3", ts,
                       feature="reply-mode-3-router-alert",
                       deprecated_by="RFC 9570", **ev)

        # -- containment: the whole point of the 127/8 convention ------------
        if is_request and not lspping_in_loopback(dst):
            self._fire("SRM-LSPPING-DST-NOT-LOOPBACK", key + ":dst", ts,
                       expected_range=str(LSPPING_LOOPBACK_V4 if family == "ipv4"
                                          else LSPPING_LOOPBACK_V6), **ev)

        # -- TLVs ------------------------------------------------------------
        tlvs, err = walk_lspping_tlvs(body, pdu["tlvs_off"])
        if err:
            self._fire("SRM-LSPPING-MALFORMED", key + ":tlv", ts,
                       reason=err, tlv_count=len(tlvs), **ev)

        for t in tlvs:
            if t["type"] == LSPPING_TLV_DOWNSTREAM_MAP:
                self._fire("SRM-LSPPING-DEPRECATED-FEATURE", key + ":dsmap", ts,
                           feature="downstream-mapping-tlv-2",
                           deprecated_by="RFC 8029 (use TLV 20, DDMAP)", **ev)
                self._check_lspping_addr_type(t, ts, key, ev)
            elif t["type"] == LSPPING_TLV_DDMAP:
                self._check_lspping_addr_type(t, ts, key, ev)
            elif t["type"] in (LSPPING_TLV_TARGET_FEC,
                               LSPPING_TLV_REVERSE_PATH_FEC):
                self._check_fec_stack(t, ts, key, ev, family)

    def _check_lspping_addr_type(self, tlv: Dict[str, Any], ts: float,
                                 key: str, ev: Dict[str, Any]) -> None:
        """Downstream (Detailed) Mapping Address Type vs its fixed K length.

        The registry pins an exact octet count per address type (IPv4 numbered
        16, IPv6 numbered 40, IPv6 unnumbered 28, Non-IP 12), so a mismatch is
        decidable from one datagram.
        """
        v = tlv["value"]
        if len(v) < 4:
            self._fire("SRM-LSPPING-MALFORMED", key + ":dmap-short", ts,
                       reason="downstream mapping shorter than its fixed header",
                       tlv_type=tlv["type"], tlv_len=tlv["length"], **ev)
            return
        # DDMAP: MTU(16) | AddrType(8) | DS flags(8) ... ; DSMAP has the same
        # first three fields in the same order.
        addr_type = v[2]
        if addr_type not in LSPPING_ADDR_TYPE_LEN:
            self._fire("SRM-LSPPING-MALFORMED", key + ":dmap-addrtype", ts,
                       field="downstream-address-type", value=addr_type,
                       tlv_type=tlv["type"], **ev)
            return
        name, klen = LSPPING_ADDR_TYPE_LEN[addr_type]
        if tlv["length"] < klen:
            self._fire("SRM-LSPPING-MALFORMED", key + ":dmap-klen", ts,
                       field="downstream-address-type-length",
                       address_type=addr_type, address_type_name=name,
                       expected_min=klen, actual=tlv["length"],
                       tlv_type=tlv["type"], **ev)

    def _check_fec_stack(self, tlv: Dict[str, Any], ts: float, key: str,
                         ev: Dict[str, Any], family: str) -> None:
        """Target FEC Stack sub-TLVs: framing, family split, deprecation."""
        subs, err = walk_fec_subtlvs(tlv["value"])
        if err:
            self._fire("SRM-LSPPING-MALFORMED", key + ":fec", ts,
                       reason=err, tlv_type=tlv["type"], **ev)
        for sub in subs:
            stype = sub["type"]
            fam = fec_subtlv_family(stype)
            sub_ev = dict(ev)
            sub_ev.update({"fec_subtlv": stype,
                           "fec_name": (LSPPING_FEC_V4.get(stype)
                                        or LSPPING_FEC_V6.get(stype)
                                        or LSPPING_FEC_NEUTRAL.get(stype)),
                           "fec_family": fam, "tlv_type": tlv["type"]})
            if fam is None:
                self._fire("SRM-LSPPING-MALFORMED", key + ":fec-unknown-%d" % stype,
                           ts, field="fec-subtlv-type", value=stype, **sub_ev)
                continue
            if stype in LSPPING_FEC_DEPRECATED:
                self._fire("SRM-LSPPING-DEPRECATED-FEATURE",
                           key + ":fec-dep-%d" % stype, ts,
                           feature="target-fec-subtlv-%d" % stype,
                           deprecated_by=LSPPING_FEC_DEPRECATED[stype], **sub_ev)
            # The registry is family-split, so this is decidable.
            if fam != "neutral" and fam != family:
                self._fire("SRM-LSPPING-FEC-FAMILY-MISMATCH",
                           key + ":fec-fam-%d" % stype, ts,
                           carried_over=family, subtlv_family=fam, **sub_ev)
                continue           # do not parse a sub-TLV as the wrong family

            # -- RFC 8287 segment FECs ------------------------------------
            if stype in (LSPPING_FEC_SR_V4, LSPPING_FEC_SR_V6):
                self._check_fec_prefix_sid(sub, stype, fam, ts, key, sub_ev)
            elif stype == LSPPING_FEC_SR_ADJ:
                self._check_fec_adj_sid(sub, ts, key, sub_ev)

    def _check_fec_prefix_sid(self, sub: Dict[str, Any], stype: int,
                              fam: str, ts: float, key: str,
                              ev: Dict[str, Any]) -> None:
        """RFC 8287 IGP-Prefix Segment ID: framing, then the ledger check."""
        try:
            p = parse_fec_prefix_sid(sub["value"], fam)
        except ParseError as exc:
            # ev already carries fec_subtlv; passing it again would raise a
            # duplicate-keyword TypeError and take the capture down.
            self._fire("SRM-LSPPING-MALFORMED", key + ":fec-sid-%d" % stype, ts,
                       reason=str(exc), actual=len(sub["value"]), **ev)
            return
        if p["prefix"] is None:
            self._fire("SRM-LSPPING-MALFORMED", key + ":fec-plen-%d" % stype, ts,
                       field="prefix-length", value=p["prefix_len"],
                       legal_range="1..%d" % p["max_prefix_len"], **ev)
            return
        if p["reserved"]:
            self._fire("SRM-LSPPING-MALFORMED", key + ":fec-rsv-%d" % stype, ts,
                       field="reserved", value=p["reserved"], **ev)

        # BASELINE-DEPENDENT.  Absence of an advertisement is not evidence
        # that none was sent, only that this tap has not seen one, so the
        # rule stays disarmed until the ledger holds something.
        ledger = len(self.prefix_sid)
        if ledger and p["prefix"] not in self.prefix_sid:
            self._fire("SRM-LSPPING-FEC-UNADVERTISED",
                       key + ":fec-unadv-%s" % p["prefix"], ts,
                       probed_prefix=p["prefix"], prefix_len=p["prefix_len"],
                       igp_protocol=p["protocol"], ledger_size=ledger,
                       **ev)

    def _check_fec_adj_sid(self, sub: Dict[str, Any], ts: float, key: str,
                           ev: Dict[str, Any]) -> None:
        """RFC 8287 IGP-Adjacency Segment ID - framing only.

        No ledger cross-check: the sub-TLV's Advertising and Receiving Node
        Identifiers are 4 octets for OSPF and 6 for IS-IS, and matching them
        against this module's (originator, neighbor) ledger keys would mean
        guessing which identifier format a given 4-octet field holds.  A
        guess there would produce confident wrong findings, so the rule is
        deliberately absent rather than approximate.
        """
        try:
            a = parse_fec_adj_sid(sub["value"])
        except ParseError as exc:
            self._fire("SRM-LSPPING-MALFORMED", key + ":fec-adj", ts,
                       reason=str(exc), actual=len(sub["value"]), **ev)
            return
        if a["adj_type_name"] is None:
            self._fire("SRM-LSPPING-MALFORMED", key + ":fec-adj-type", ts,
                       field="adjacency-type", value=a["adj_type"],
                       legal=sorted(FEC_ADJ_TYPES), **ev)
            return
        if a["expected_len"] is not None and a["value_len"] < a["expected_len"]:
            self._fire("SRM-LSPPING-MALFORMED", key + ":fec-adj-len", ts,
                       field="adjacency-subtlv-length",
                       adj_type=a["adj_type"], adj_type_name=a["adj_type_name"],
                       igp_protocol=a["protocol"],
                       expected_min=a["expected_len"], actual=a["value_len"], **ev)
        if a["reserved"]:
            self._fire("SRM-LSPPING-MALFORMED", key + ":fec-adj-rsv", ts,
                       field="reserved", value=a["reserved"], **ev)

    # -- IOAM (RFC 9197 / RFC 9486) -----------------------------------------

    def _check_ioam_area(self, hdr_proto: int, area: bytes, src: str, dst: str,
                         ts: float, under_mpls: bool) -> None:
        """Scan one option area for IOAM options and check each."""
        total = 0
        for opt in walk_ipv6_options(area):
            if opt["type"] not in IPV6_OPT_IOAM:
                continue
            self.stats["ioam"] += 1
            total += (opt["length"] or 0) + 2
            self._check_ioam_option(opt, hdr_proto, src, dst, ts, under_mpls,
                                    total)

    def _check_ioam_option(self, opt: Dict[str, Any], hdr_proto: int,
                           src: str, dst: str, ts: float, under_mpls: bool,
                           running_total: int) -> None:
        in_hbh = hdr_proto == IPPROTO_HOPOPT
        ev: Dict[str, Any] = {
            "src": src, "dst": dst, "under_mpls": under_mpls,
            "ipv6_option_type": "0x%02X" % opt["type"],
            "mutable": opt["type"] == IPV6_OPT_IOAM_MUTABLE,
            "header": "hop-by-hop" if in_hbh else "destination-options",
        }
        key = "ioam:%s" % src

        # RFC 9486 s5: boundary routers MUST filter IOAM in BOTH directions,
        # and IOAM MUST NOT be leaked across a domain boundary.
        if self._ce_gate(ts):
            self._fire("SRM-IOAM-DOMAIN-LEAK", key, ts,
                       declared_role=self.cfg.role, **ev)

        if opt["truncated"]:
            self._fire("SRM-IOAM-MALFORMED", key + ":trunc", ts,
                       rule="option truncated", declared_len=opt["length"],
                       actual=len(opt["data"]), **ev)
            return

        # RFC 9486 s4: 4-octet alignment and a 255-octet ceiling.
        if (opt["length"] + 2) % IOAM_ALIGNMENT:
            self._fire("SRM-IOAM-MALFORMED", key + ":align", ts,
                       rule="option not aligned to %d octets" % IOAM_ALIGNMENT,
                       option_len=opt["length"] + 2, **ev)
        if running_total > IOAM_MAX_TOTAL_LEN:
            self._fire("SRM-IOAM-MALFORMED", key + ":total", ts,
                       rule="total IOAM option length beyond the ceiling",
                       total=running_total, ceiling=IOAM_MAX_TOTAL_LEN, **ev)

        try:
            io = parse_ioam_option(opt["data"])
        except ParseError as exc:
            self._fire("SRM-IOAM-MALFORMED", key + ":hdr", ts,
                       rule=str(exc), **ev)
            return

        ev["ioam_type"] = io["ioam_type"]
        ev["ioam_name"] = IOAM_OPT_NAMES.get(io["ioam_type"])

        if io["ioam_type"] not in IOAM_TRACE_OPTS:
            return                       # POT / E2E / DEX: header-level only

        try:
            tr = parse_ioam_trace(io["body"])
        except ParseError as exc:
            self._fire("SRM-IOAM-MALFORMED", key + ":trace-hdr", ts,
                       rule=str(exc), body_len=len(io["body"]), **ev)
            return

        ev.update({"namespace": "0x%04X" % tr["namespace"],
                   "trace_type": "0x%06X" % tr["trace_type"],
                   "node_len": tr["node_len"],
                   "remaining_len": tr["remaining_len"],
                   "overflow": tr["overflow"]})

        # -- reserved / undefined Trace-Type bits ----------------------------
        bits = ioam_trace_bits_set(tr["trace_type"])
        undefined = [b for b in bits if b in IOAM_TRACE_BITS_UNDEFINED]
        if IOAM_TRACE_BIT_RESERVED in bits or undefined:
            self._fire("SRM-IOAM-TRACETYPE-RESERVED", key + ":tt", ts,
                       reserved_bit_set=IOAM_TRACE_BIT_RESERVED in bits,
                       undefined_bits_set=undefined, bits_set=bits, **ev)

        # -- THE NodeLen INVARIANT -------------------------------------------
        # NodeLen must equal the sum of the 4-octet units the set Trace-Type
        # bits imply, excluding bit 22.  Complete, computable, no baseline.
        expected = ioam_nodelen_expected(tr["trace_type"])
        opaque = bool(tr["trace_type"] & (1 << (23 - IOAM_TRACE_BIT_OPAQUE)))
        if tr["node_len"] > IOAM_NODELEN_MAX:
            # Unreachable by ANY Trace-Type, whatever bits are set.
            self._fire("SRM-IOAM-MALFORMED", key + ":nodelen-bound", ts,
                       rule="NodeLen beyond anything a Trace-Type can imply",
                       ceiling=IOAM_NODELEN_MAX, **ev)
        elif tr["node_len"] != expected:
            self._fire("SRM-IOAM-MALFORMED", key + ":nodelen", ts,
                       rule="NodeLen disagrees with the Trace-Type it carries",
                       expected=expected, bits_set=bits,
                       opaque_snapshot=opaque, **ev)

        if tr["flags_mbz"]:
            self._fire("SRM-IOAM-MALFORMED", key + ":flags", ts,
                       rule="unassigned Trace-Flags bit set",
                       flags=tr["flags"], **ev)

        # -- RemainingLen vs the space the option actually has ---------------
        # RemainingLen counts 4-octet units still available for node data.
        space = len(tr["data"])
        if tr["remaining_len"] * 4 > space:
            self._fire("SRM-IOAM-MALFORMED", key + ":remaining", ts,
                       rule="RemainingLen exceeds the option's own data space",
                       remaining_octets=tr["remaining_len"] * 4,
                       data_space=space, **ev)

    # -- VCCV (RFC 5085) ----------------------------------------------------

    def _check_vccv(self, tlvs: List[Dict[str, Any]], lsr: str, src: str,
                    dst: str, ts: float, mtype: int) -> None:
        """VCCV control-channel posture from a pseudowire's LDP advertisement.

        CC Type 2 (MPLS Router Alert label) and CC Type 3 (PW label with TTL
        1) both deliver the VCCV message to the receiving router's CONTROL
        PLANE rather than keeping it in the data path, so a pseudowire peer
        can meter CPU with ordinary OAM.  That is an exposure the operator
        chose, hence POSTURE rather than ATTACK.
        """
        params: List[Dict[str, Any]] = []
        pw_ctx: Dict[str, Any] = {}
        for t in tlvs:
            if t["type"] == LDP_TLV_FEC:
                for fec in parse_pwid_fec(t["value"]):
                    if not pw_ctx:
                        pw_ctx = {"fec_type": fec["fec_type"],
                                  "pw_type": fec["pw_type"],
                                  "pw_id": fec.get("pw_id"),
                                  "control_word": fec["control_word"]}
                    params.extend(fec["iface_params"])
            elif t["type"] == LDP_TLV_PW_INTERFACE_PARAMS:
                # The Generalized PWid FEC keeps its parameters here.
                params.extend(walk_interface_params(t["value"]))
        if not params:
            return

        for prm in params:
            if prm["id"] != VCCV_IFACE_PARAM or prm["malformed"]:
                continue
            v = parse_vccv_param(prm["value"])
            if v is None:
                continue
            self.stats["vccv"] += 1
            key = "vccv:%s/%s" % (lsr, pw_ctx.get("pw_id"))
            ev = {"lsr_id": lsr, "src": src, "dst": dst,
                  "ldp_msg_type": mtype, "cc_types": v["cc"],
                  "cv_types": v["cv"],
                  "cc_router_alert": v["cc_router_alert"],
                  "cc_ttl_expiry": v["cc_ttl_expiry"],
                  "cc_control_word": v["cc_control_word"],
                  "cv_lsp_ping": v["cv_lsp_ping"],
                  "cv_icmp_ping": v["cv_icmp_ping"]}
            ev.update(pw_ctx)

            if v["cc"] & VCCV_CC_CONTROL_PLANE:
                which = []
                if v["cc_router_alert"]:
                    which.append("type-2-router-alert")
                if v["cc_ttl_expiry"]:
                    which.append("type-3-ttl-expiry")
                self._fire("SRM-VCCV-CC-RISKY", key + ":punt", ts,
                           reason="control-plane-punting CC type advertised",
                           punting_types=which, **ev)
            if v["cc_reserved"] or v["cv_reserved"]:
                self._fire("SRM-VCCV-CC-RISKY", key + ":reserved", ts,
                           reason="reserved VCCV CC/CV bits set",
                           cc_reserved=v["cc_reserved"],
                           cv_reserved=v["cv_reserved"], **ev)
            if v["cc"] and not v["cv"]:
                self._fire("SRM-VCCV-CC-RISKY", key + ":no-cv", ts,
                           reason="CC type advertised with no CV type",
                           **ev)

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
        (srh, final_nh, _raw, l4_off, later_fragment,
         ext_opts) = walk_ipv6_headers(data)
        if srh is not None:
            self.stats["srh"] += 1
            self._check_srh(srh, src, dst, ts, under_mpls)

        # IOAM rides in the Hop-by-Hop and Destination Options headers the
        # walker now hands back.  IPv6-only by protocol (RFC 9486), not by
        # omission - see the IOAM constants block.
        for hdr_proto, area in ext_opts:
            self._check_ioam_area(hdr_proto, area, src, dst, ts, under_mpls)

        # PRIME DIRECTIVE: LDP (RFC 7552), BGP with IPv6 transport and RSVP-TE
        # all run over IPv6, and every one of them used to be invisible here
        # because the transport dispatch lived only in handle_ipv4.  Both
        # families now go through the SAME function - parity by construction
        # rather than by two copies that drift.
        if later_fragment or l4_off >= len(data):
            return
        plen = struct.unpack_from("!H", data, 4)[0]
        end = min(len(data), 40 + plen) if plen else len(data)
        if end <= l4_off:
            return
        self.stats["v6_transport"] += 1
        self._dispatch_transport(final_nh, data[l4_off:end], src, dst, ts)

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

        self._dispatch_transport(proto, body, src, dst, ts)

    # -- shared transport dispatch (both address families) ------------------

    def _dispatch_transport(self, proto: int, body: bytes, src: str, dst: str,
                            ts: float) -> None:
        """The ONE place an upper-layer protocol is selected.

        handle_ipv4 and handle_ipv6 both land here, so an IPv4-only blind spot
        cannot be reintroduced without deleting a call site that the
        conformance harness counts."""
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
            elif LSPPING_PORT in (sport, dport):
                # Reached from handle_ipv4 AND handle_ipv6 through this one
                # function, so LSP Ping is dual-stack by construction rather
                # than by two copies that drift.
                self.handle_lspping(body[8:], src, dst, ts, sport, dport)
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
            # VCCV rides in pseudowire FEC interface parameters, which appear
            # on any message carrying a PW FEC - typically Label Mapping.
            self._check_vccv(tlvs, lsr, src, dst, ts, mtype)
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
                # CVE-2024-31948: the attribute itself may claim more octets
                # than the UPDATE carries.
                self._check_sr_tlvs("bgp", "path-attribute", [a], ts,
                                    cves=self.CVES_BGP_PSID, originator=originator)
                psid = parse_prefix_sid(a["value"])
                # CVE-2023-31490: bgp_attr_psid_sub() reads the sub-TLVs.
                self._check_sr_tlvs("bgp", "prefix-sid", psid["tlvs"], ts,
                                    cves=self.CVES_BGP_PSID, originator=originator)
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


    # -- OSPFv3 -------------------------------------------------------------

    def handle_ospfv3(self, data: bytes, src: str, dst: str, ts: float) -> None:
        hdr = parse_ospfv3_header(data)
        self.stats["ospfv3"] += 1
        if hdr["type"] != OSPF_TYPE_LS_UPDATE:
            return
        saw_sr = False
        last_originator = hdr["router_id"]
        for lsa in parse_ospfv3_lsas(data):
            block = lsa["tlv_block"]
            if block is None:
                continue                  # LSA type whose body layout we do not model
            fc = lsa["function_code"]
            originator = lsa["adv_router"]
            last_originator = originator
            tlvs = parse_ospf_tlvs(block)

            if fc == OSPFV3_FC_ROUTER_INFO:
                # RFC 8666 s4: SR capabilities live in the OSPFv3 RI LSA and
                # reuse the OSPF RI TLV registry, so the same codepoints and
                # the same ledger apply as for OSPFv2.
                self._check_sr_tlvs("ospfv3", "router-info", tlvs, ts,
                                    cves=self.CVES_OSPF_RI, originator=originator)
                for tlv in tlvs:
                    if tlv["type"] == OSPF_RI_TLV_SID_LABEL_RANGE:
                        saw_sr = True
                        self._record_srgb(
                            originator, parse_ospf_sid_range(tlv["value"])["ranges"],
                            ts, "ospfv3")
                    elif tlv["type"] == OSPF_RI_TLV_SR_LOCAL_BLOCK:
                        saw_sr = True
                        self.srlb_adv[originator] = \
                            parse_ospf_sid_range(tlv["value"])["ranges"]
                    elif tlv["type"] == OSPF_RI_TLV_SR_ALGORITHM:
                        saw_sr = True
                        self._record_algos(originator, list(tlv["value"][:32]))
                continue

            self._check_sr_tlvs("ospfv3", "extended-lsa", tlvs, ts,
                                originator=originator)
            for tlv in tlvs:
                t = tlv["type"]
                entry = None
                if t in OSPFV3_PREFIX_TLVS:
                    entry = parse_ospfv3_prefix_tlv(tlv["value"])
                elif t == OSPFV3_TLV_EXT_PREFIX_RANGE:
                    entry = parse_ospfv3_ext_prefix_range(tlv["value"])
                elif t == OSPFV3_TLV_ROUTER_LINK:
                    rl = parse_ospfv3_router_link(tlv["value"])
                    if not rl:
                        continue
                    self._check_sr_tlvs("ospfv3", "router-link", rl["subtlvs"], ts,
                                        originator=originator)
                    for sub in rl["subtlvs"]:
                        if sub["type"] == OSPFV3_SUB_ADJ_SID:
                            a = parse_ospfv3_adj_sid(sub["value"])
                        elif sub["type"] == OSPFV3_SUB_LAN_ADJ_SID:
                            a = parse_ospfv3_adj_sid(sub["value"], lan=True)
                        else:
                            continue
                        if not a:
                            continue
                        saw_sr = True
                        self._record_adj_sid(
                            originator,
                            a.get("neighbor") or rl["neighbor_router_id"],
                            a, ts, "ospfv3")
                    continue
                if not entry:
                    continue
                self._check_sr_tlvs("ospfv3", "prefix-tlv", entry["subtlvs"], ts,
                                    originator=originator, prefix=entry["prefix"])
                for sub in entry["subtlvs"]:
                    if sub["type"] != OSPFV3_SUB_PREFIX_SID:
                        continue
                    p = parse_ospfv3_prefix_sid(sub["value"])
                    if not p:
                        continue
                    saw_sr = True
                    extra: Dict[str, Any] = {"mapping_server": p["mapping_server"]}
                    if "range_size" in entry:
                        extra["range_size"] = entry["range_size"]
                    self._record_prefix_sid(originator, "ospfv3", entry["prefix"],
                                            p["algorithm"], p["kind"], p["sid"], ts,
                                            **extra)
        if saw_sr:
            self._igp_sr_seen(ts, "ospfv3", last_originator)

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

    # -- SR TLV length conformance -----------------------------------------

    CVES_BGP_PSID = ("CVE-2023-31490", "CVE-2024-31948")
    CVES_OSPF_RI = ("CVE-2024-31950",)
    CVES_OSPF_EXT = ("CVE-2024-31951",)

    def _check_sr_tlvs(self, protocol: str, container: str,
                       entries: List[Dict[str, Any]], ts: float,
                       cves: Tuple[str, ...] = (), **ev: Any) -> None:
        """Both halves of "the length was not validated".

        A declared length that runs past its container is what walks a parser
        off the buffer; a declared length SHORTER than the sub-TLV's fixed
        fields is what makes it read values the advertisement never carried.
        The module used to absorb both silently - every TLV walker clamped
        with min(), so the malformation was seen and thrown away."""
        # The dedup key carries the ORIGINATOR. Without it a single malformed
        # peer suppresses every other peer sending the same malformed TLV for
        # the whole dedup window - including the same condition arriving over
        # the other address family, which is how the pcap tier caught this.
        who = str(ev.get("originator", "?"))
        for e in entries:
            t = e.get("type")
            if e.get("overrun"):
                self._fire("SRM-SR-TLV-OVERRUN",
                           "%s/%s/%s/%s" % (protocol, container, t, who), ts,
                           protocol=protocol, container=container, tlv_type=t,
                           declared_len=e.get("len"), available=e.get("available"),
                           reason="declared length runs past its container",
                           cves=list(cves), **ev)
                continue
            minimum = SR_TLV_MIN_LEN.get((protocol, container, t))
            if minimum is not None and e.get("len", 0) < minimum:
                self._fire("SRM-SR-TLV-OVERRUN",
                           "%s/%s/%s/%s/short" % (protocol, container, t, who), ts,
                           protocol=protocol, container=container, tlv_type=t,
                           declared_len=e.get("len"), required_min=minimum,
                           reason="declared length is shorter than the fixed fields "
                                  "this sub-TLV must carry",
                           cves=list(cves), **ev)

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
                cap_subs = parse_isis_subtlvs(value[5:])
                self._check_sr_tlvs("isis", "router-cap", cap_subs, ts,
                                    originator=originator)
                for sub in cap_subs:
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
                    self._check_sr_tlvs("isis", "prefix-reach", entry["subtlvs"], ts,
                                        originator=originator, prefix=entry["prefix"])
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
                    self._check_sr_tlvs("isis", "neighbour", entry["subtlvs"], ts,
                                        originator=originator,
                                        neighbor=entry["neighbor"])
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
        # OSPFv3 (RFC 5340) rides ip proto 89 over IPv6 and carries its SR
        # extensions in a completely different LSA set (RFC 8362 / RFC 8666).
        if data and data[0] == OSPFV3_VERSION:
            self.handle_ospfv3(data, src, dst, ts)
            return
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
                ri_tlvs = parse_ospf_tlvs(lsa["body"])
                self._check_sr_tlvs("ospf", "router-info", ri_tlvs, ts,
                                    cves=self.CVES_OSPF_RI, originator=originator)
                for tlv in ri_tlvs:
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
                ep_tlvs = parse_ospf_tlvs(lsa["body"])
                self._check_sr_tlvs("ospf", "ext-prefix-lsa", ep_tlvs, ts,
                                    cves=self.CVES_OSPF_EXT, originator=originator)
                for tlv in ep_tlvs:
                    if tlv["type"] != OSPF_TLV_EXT_PREFIX:
                        continue
                    ep = parse_ospf_ext_prefix(tlv["value"])
                    if not ep:
                        continue
                    self._check_sr_tlvs("ospf", "ext-prefix", ep["subtlvs"], ts,
                                        cves=self.CVES_OSPF_EXT, originator=originator,
                                        prefix=ep["prefix"])
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
                el_tlvs = parse_ospf_tlvs(lsa["body"])
                self._check_sr_tlvs("ospf", "ext-link-lsa", el_tlvs, ts,
                                    cves=self.CVES_OSPF_EXT, originator=originator)
                for tlv in el_tlvs:
                    if tlv["type"] != OSPF_TLV_EXT_LINK:
                        continue
                    el = parse_ospf_ext_link(tlv["value"])
                    if not el:
                        continue
                    # CVE-2024-31951: Adjacency SID sub-TLVs, lengths unvalidated.
                    self._check_sr_tlvs("ospf", "ext-link", el["subtlvs"], ts,
                                        cves=self.CVES_OSPF_EXT, originator=originator,
                                        link_id=el["link_id"])
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
                         "isis=%d ospf=%d ospfv3=%d igp_sr=%d v6_transport=%d "
                         "bgp_update=%d parse_errors=%d findings=%d suppressed=%d "
                         "evictions=%d\n"
                         % (MODULE_NAME, engine.stats["frames"], engine.stats["mpls"],
                            engine.stats["srh"], engine.stats["ldp"], engine.stats["rsvp"],
                            engine.stats["isis"], engine.stats["ospf"],
                            engine.stats["ospfv3"], engine.stats["igp_sr"],
                            engine.stats["v6_transport"], engine.stats["bgp_update"], engine.stats["parse_errors"],
                            sum(emitter.counts.values()), emitter.suppressed,
                            engine.stats["evictions"] + emitter.evictions))
    return 0




# --- Ragnar integration layer (do_sr_mpls_watch / selftest / Watchtower) ---
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

    def _tcp(sport, dport, payload):
        return _struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000,
                            (5 << 4), 0x18, 8192, 0, 0) + payload

    def _bgp_msg(mtype, body):
        return BGP_MARKER + _struct.pack("!HB", BGP_HDR_LEN + len(body), mtype) + body

    def _bgp_frame(msg, src="203.0.113.7", dst="198.51.100.1", sport=50001):
        return _eth(ETHERTYPE_IPV4,
                    _ipv4(src, dst, IPPROTO_TCP, _tcp(sport, BGP_PORT, msg)))

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

    # 8. A BGP Prefix-SID path attribute whose declared length overruns the UPDATE
    #    -> SRM-SR-TLV-OVERRUN (CVE-2024-31948 wire condition; unvalidated SR TLV length).
    attr = _struct.pack("!BBB", 0xC0, BGP_ATTR_PREFIX_SID, 250) + b"\x00" * 8
    body = _struct.pack("!H", 0) + _struct.pack("!H", len(attr)) + attr
    r = _run([_bgp_frame(_bgp_msg(BGP_MSG_UPDATE, body))], role="core")
    check("sr-tlv-overrun", "SRM-SR-TLV-OVERRUN" in _codes(r), sorted(_codes(r)))

    # 9. The finding carries the FRR SR-parser CVE it is the wire signature for.
    ov = [x for x in r if x["code"] == "SRM-SR-TLV-OVERRUN"]
    check("sr-tlv-overrun-cve",
          bool(ov) and "CVE-2024-31948" in (ov[0]["evidence"].get("cves") or []),
          str(ov[0]["evidence"]) if ov else "no finding")


    # -- OSPFv3-SR (RFC 5340 framing / RFC 8362 extended LSAs / RFC 8666 SR) --
    # OSPFv3 rides IP proto 89 over IPv6 and carries SR in a different LSA set
    # than OSPFv2; these exercise the whole dispatch: frame -> IPv6 ext-header
    # walk -> shared transport dispatch -> OSPFv3 handler -> SR-TLV checks.
    def _o3_tlv(ttype, value, declared=None):
        dl = len(value) if declared is None else declared
        return (_struct.pack("!HH", ttype, dl) + value
                + b"\x00" * ((-len(value)) % 4))

    def _ospfv3_lsa(fc, body, adv="203.0.113.9"):
        ls_type = 0xA000 | (fc & OSPFV3_LS_TYPE_FC_MASK)
        return (_struct.pack("!HH4s4sIHH", 0, ls_type,
                             _ipaddress.IPv4Address("0.0.0.1").packed,
                             _ipaddress.IPv4Address(adv).packed,
                             0x80000001, 0, OSPFV3_LSA_HDR_LEN + len(body)) + body)

    def _ospfv3_lsu(*lsas):
        upd = _struct.pack("!I", len(lsas)) + b"".join(lsas)
        hdr = _struct.pack("!BBH4s4sHBB", OSPFV3_VERSION, OSPF_TYPE_LS_UPDATE,
                           OSPFV3_HDR_LEN + len(upd),
                           _ipaddress.IPv4Address("203.0.113.9").packed,
                           _ipaddress.IPv4Address("0.0.0.0").packed, 0, 0, 0)
        return _eth(ETHERTYPE_IPV6,
                    _ipv6("2001:db8:a::1", "ff02::5", IPPROTO_OSPF, hdr + upd))

    # 10. An OSPFv3 Extended-Prefix (Intra-Area-Prefix) LSA whose Prefix-SID
    #     sub-TLV declares a length that overruns the prefix TLV -> the OSPFv3
    #     SR sub-TLV overrun path fires SRM-SR-TLV-OVERRUN (protocol 'ospfv3').
    _psid = _o3_tlv(OSPFV3_SUB_PREFIX_SID, b"\x00\x00\x00\x00", declared=100)
    _ptlv = _struct.pack("!IBBH", 10, 0, 0, 0) + _psid
    _iap = _ospfv3_lsa(OSPFV3_FC_E_INTRA_AREA_PREFIX,
                       _struct.pack("!HH4s4s", 0, 0, b"\x00" * 4, b"\x00" * 4)
                       + _o3_tlv(OSPFV3_TLV_INTRA_AREA_PREFIX, _ptlv))
    r = _run([_ospfv3_lsu(_iap)], role="core")
    ov = [x for x in r if x["code"] == "SRM-SR-TLV-OVERRUN"]
    check("ospfv3-sr-subtlv-overrun",
          bool(ov) and any(x["evidence"].get("protocol") == "ospfv3" for x in ov),
          sorted(_codes(r)))

    # 11. An OSPFv3 Router-Information LSA whose SID/Label-Range TLV overruns.
    #     The RI LSA reuses the OSPF RI TLV registry (RFC 8666 s4), so the
    #     finding carries CVE-2024-31950 - an SR-TLV-length CVE now detected on
    #     the OSPFv3 path.  (The 2025 FRR ospf6d CVEs sit in CVE_REFERENCES as
    #     reference-only: detected_here=False, the crash needing a receiver
    #     debug config a passive tap cannot observe.)
    _ri = _ospfv3_lsa(OSPFV3_FC_ROUTER_INFO,
                      _o3_tlv(OSPF_RI_TLV_SID_LABEL_RANGE, b"\x00\x00\x64\x00",
                              declared=200))
    r = _run([_ospfv3_lsu(_ri)], role="core")
    ov = [x for x in r if x["code"] == "SRM-SR-TLV-OVERRUN"]
    check("ospfv3-ri-overrun-cve",
          bool(ov) and "CVE-2024-31950" in (ov[0]["evidence"].get("cves") or []),
          str(ov[0]["evidence"]) if ov else "no finding")

    # 12. A well-formed OSPFv3 SR-LSA (valid SID/Label-Range) on a CE port must
    #     NOT false-positive: it is recognised as SR topology (SRM-IGP-SR-
    #     TOPOLOGY, proving the frame was fully parsed) with no overrun finding.
    _sidlabel = _o3_tlv(OSPF_SUB_SID_LABEL, b"\x00\x03\xe8")
    _good = _ospfv3_lsa(OSPFV3_FC_ROUTER_INFO,
                        _o3_tlv(OSPF_RI_TLV_SID_LABEL_RANGE,
                                b"\x00\x00\x64\x00" + _sidlabel))
    r = _run([_ospfv3_lsu(_good)], role="ce")
    check("ospfv3-wellformed-no-overrun",
          "SRM-SR-TLV-OVERRUN" not in _codes(r)
          and "SRM-IGP-SR-TOPOLOGY" in _codes(r),
          sorted(_codes(r)))

    return {"success": all(s["pass"] for s in scen), "scenarios": scen}


if __name__ == "__main__":
    sys.exit(main())
