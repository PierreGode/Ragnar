#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cfmwatch - passive IEEE 802.1ag CFM / ITU-T Y.1731 service-OAM detector.

Part of the Ragnar passive network security suite.

SCOPE
-----
EtherType 0x8902 (Connectivity Fault Management), including the Y.1731
service-OAM overlay (AIS/LCK/CSF, APS, LB/LT, LM/DM/SL, TST, EXM/VSM).
Rides inside the service VLAN on EVC trunks; 802.1Q and QinQ are parsed.

Sibling module, NOT an oamwatch enhancement. oamwatch covers 802.3ah Link
OAM (EtherType 0x8809) - different EtherType, different destination group,
different grammar, different state machine, different threat model.
oamwatch's README declares CFM out of its scope; that stays true. Do not
wire a CFM dissector into oamwatch's tests, and do not wire a Link OAM
dissector into this module's tests.

PASSIVE ONLY
------------
This module never transmits. No LBM, no LTM, no MEP probing, no active
verification of any kind. There is no CFM transmitter in this tree; the
lab borrows tcpreplay to inject pre-built pcaps. A transmit-guard AST scan
(tier 3) enforces this against the source.

DUAL STACK
----------
Not applicable, and recorded here explicitly so it never reads as an
oversight: CFM is a pure L2 protocol carried directly over Ethernet with
its own EtherType. There is no IP header and therefore no IPv4/IPv6
address-family split to achieve parity across. Same disposition as
oamwatch and lacpwatch. The Ragnar dual-stack prime directive is satisfied
by "IPv6 where applicable"; it is not applicable here.

CVE BACKBONE
------------
CVE-2020-1639   7.5  Juniper Junos, crafted Ethernet OAM packet -> CFM
                     daemon overflow and core. JSA11020. Structural spine.
CVE-2025-52961  6.5  Junos OS Evolved PTX, adjacent device sends valid
                     traffic -> cfmd 100% CPU, cfmman leak, FPC crash.
                     Volumetric; weak as a single-frame signature.
CVE-2014-3223   7.5  Huawei S-series Y.1731 DoS. Trigger field never
                     published - screening row only, no detector claim.

Rejected and not to be re-proposed: CVE-2023-20233 (Cisco IOS XR CFM,
4.3, below the 6.5 bar, not in KEV).
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
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

__version__ = "1.1.0"
MODULE_NAME = "cfmwatch"

# --------------------------------------------------------------------------
# Wire constants
# --------------------------------------------------------------------------

ETHERTYPE_CFM = 0x8902
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100, 0x9200)
# ---- E-LMI (MEF 16), the second EtherType this module parses -----------
#
# E-LMI is NOT independently useful here: the only abuse angle it offers
# is an EVC status that contradicts what CFM reports about the same
# service, and that needs both planes. That dependency is why it lives
# inside this module rather than beside it - the opposite of the
# oamwatch/lacpwatch split, where each plane stood on its own.
#
# The vantage works out for the same reason: E-LMI runs on the PE-CE UNI,
# and the UNI is where MEF mandates service OAM, so the two planes
# coincide on the tap this module already claims.
#
# Layout confirmed by probing Wireshark's 42-field E-LMI dissector:
#   version(1) message_type(1) then information elements
#   IE = tag(1) length(1) value(length)
#     0x01 Report Type      report type (1)
#     0x02 Sequence Numbers send (1), receive (1)
#     0x11 UNI Status       CE-VLAN/EVC map type (1) then sub-IEs
#     0x21 EVC Status       EVC reference (2), status (1), then sub-IEs
#   sub-IE = tag(1) length(1) value(length)
# The internals of the EVC Map Entry sub-IE (0x63) are deliberately NOT
# decoded: Wireshark recognises the tag but does not break out its
# contents, so the EVC-to-VLAN join comes from an operator declaration
# instead of a guess.
ETHERTYPE_ELMI = 0x88EE
ELMI_GROUP = bytes.fromhex("0180c2000007")
ELMI_MSG_STATUS_ENQUIRY = 0x75
ELMI_MSG_STATUS = 0x7D
ELMI_MSG_NAMES: Dict[int, str] = {
    ELMI_MSG_STATUS_ENQUIRY: "Status Enquiry", ELMI_MSG_STATUS: "Status",
}
ELMI_VERSION = 1
ELMI_IE_REPORT_TYPE = 0x01
ELMI_IE_SEQUENCE = 0x02
ELMI_IE_DATA_INSTANCE = 0x03
ELMI_IE_UNI_STATUS = 0x11
ELMI_IE_EVC_STATUS = 0x21
ELMI_IE_MAP = 0x22
ELMI_IE_NAMES: Dict[int, str] = {
    ELMI_IE_REPORT_TYPE: "Report Type",
    ELMI_IE_SEQUENCE: "Sequence Numbers",
    ELMI_IE_DATA_INSTANCE: "Data Instance",
    ELMI_IE_UNI_STATUS: "UNI Status",
    ELMI_IE_EVC_STATUS: "EVC Status",
    ELMI_IE_MAP: "CE-VLAN ID/EVC Map",
}
ELMI_SUB_UNI_ID = 0x51
ELMI_SUB_EVC_PARAMS = 0x61
ELMI_SUB_EVC_ID = 0x62
ELMI_SUB_EVC_MAP_ENTRY = 0x63
ELMI_SUB_BANDWIDTH = 0x71
ELMI_EVC_STATUS_NAMES: Dict[int, str] = {
    0x00: "Not Active", 0x01: "New and Not Active", 0x02: "Active",
    0x03: "New and Active", 0x04: "Partially Active",
    0x05: "New and Partially Active",
}
ELMI_EVC_ACTIVE = frozenset({0x02, 0x03})
ELMI_EVC_INACTIVE = frozenset({0x00, 0x01})
ELMI_EVC_PARTIAL = frozenset({0x04, 0x05})
ELMI_REPORT_TYPES: Dict[int, str] = {
    0: "Full status", 1: "E-LMI check", 2: "Single EVC async status",
    3: "Full status continued",
}


@dataclass(frozen=True)
class Evc:
    """An operator-declared EVC-to-service-VLAN mapping.

    E-LMI names services by EVC reference; CFM state is keyed by VLAN.
    The join between them is not reliably on the wire, so the operator
    declares it - the same shape as the ring declaration, and undeclared
    fails loud rather than looking clean.
    """
    reference: int
    vlan: Tuple[int, ...]
    label: str = ""

    def name(self) -> str:
        return self.label or "evc%d" % self.reference


@dataclass
class ElmiFrame:
    index: int
    ts: float
    frame_len: int
    dst: bytes
    src: bytes
    version: int
    msg_type: int
    ies: List[Tuple[int, bytes]] = field(default_factory=list)
    evcs: List[Dict[str, Any]] = field(default_factory=list)
    uni_id: Optional[bytes] = None
    map_type: Optional[int] = None
    report_type: Optional[int] = None
    snd_seq: Optional[int] = None
    rcv_seq: Optional[int] = None
    structural: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def msg_name(self) -> str:
        return ELMI_MSG_NAMES.get(self.msg_type, "0x%02x" % self.msg_type)

    def note(self, detail: str) -> None:
        self.structural.append(("CFM-252", detail))


def parse_sub_ies(raw: bytes) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    pos = 0
    guard = 0
    while pos + 2 <= len(raw) and guard < 64:
        guard += 1
        tag = raw[pos]
        ln = raw[pos + 1]
        if pos + 2 + ln > len(raw):
            break
        out.append((tag, raw[pos + 2:pos + 2 + ln]))
        pos += 2 + ln
    return out


def parse_elmi(raw: bytes, index: int, ts: float) -> Optional[ElmiFrame]:
    """Parse an E-LMI frame, or return None if this is not one."""
    if len(raw) < 16:
        return None
    if struct.unpack_from("!H", raw, 12)[0] != ETHERTYPE_ELMI:
        return None
    body = raw[14:]
    if len(body) < 2:
        return None
    frame = ElmiFrame(index=index, ts=ts, frame_len=len(raw), dst=raw[0:6],
                      src=raw[6:12], version=body[0], msg_type=body[1])
    if frame.version != ELMI_VERSION:
        frame.note("protocol version %d, expected %d"
                   % (frame.version, ELMI_VERSION))
    if frame.msg_type not in ELMI_MSG_NAMES:
        frame.note("message type 0x%02x is not Status or Status Enquiry"
                   % frame.msg_type)
    if frame.dst != ELMI_GROUP:
        frame.note("destination %s, not the E-LMI group %s"
                   % (mac_str(frame.dst), mac_str(ELMI_GROUP)))

    pos = 2
    guard = 0
    while pos + 2 <= len(body) and guard < 128:
        guard += 1
        tag = body[pos]
        ln = body[pos + 1]
        if tag == 0 and ln == 0:
            break                     # padding
        if pos + 2 + ln > len(body):
            frame.note("information element 0x%02x declares length %d, "
                       "which overruns the frame" % (tag, ln))
            break
        val = body[pos + 2:pos + 2 + ln]
        frame.ies.append((tag, val))
        pos += 2 + ln

        if tag == ELMI_IE_SEQUENCE and ln >= 2:
            frame.snd_seq, frame.rcv_seq = val[0], val[1]
        elif tag == ELMI_IE_REPORT_TYPE and ln >= 1:
            frame.report_type = val[0]
            if val[0] not in ELMI_REPORT_TYPES:
                frame.note("report type %d is not defined" % val[0])
        elif tag == ELMI_IE_UNI_STATUS and ln >= 1:
            frame.map_type = val[0]
            for stag, sval in parse_sub_ies(val[1:]):
                if stag == ELMI_SUB_UNI_ID:
                    frame.uni_id = sval
        elif tag == ELMI_IE_EVC_STATUS and ln >= 3:
            ref = struct.unpack_from("!H", val, 0)[0]
            status = val[2]
            evc_id = None
            for stag, sval in parse_sub_ies(val[3:]):
                if stag == ELMI_SUB_EVC_ID:
                    evc_id = sval
            if status not in ELMI_EVC_STATUS_NAMES:
                frame.note("EVC %d carries status 0x%02x, which MEF 16 "
                           "does not define" % (ref, status))
            frame.evcs.append({
                "reference": ref, "status": status,
                "status_name": ELMI_EVC_STATUS_NAMES.get(
                    status, "undefined(0x%02x)" % status),
                "evc_id": evc_id,
            })
    return frame


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
IPPROTO_UDP = 17
VXLAN_PORT = 4789
VXLAN_HEADER_LEN = 8
VXLAN_FLAG_VNI_VALID = 0x08
# A VNI is 24 bits, so -1 can never collide with one. Used as the "no
# encapsulation" marker in the service key.
NO_VNI = -1

# CFM class 1 group: 01-80-C2-00-00-3x where x = MD level (CCM, multicast LBM)
# CFM class 2 group: 01-80-C2-00-00-3(8+x) where x = MD level (LTM)
CFM_GROUP_PREFIX = (0x01, 0x80, 0xC2, 0x00, 0x00)

OP_CCM = 1
OP_LBR = 2
OP_LBM = 3
OP_LTR = 4
OP_LTM = 5
OP_RFM = 6
OP_SFM = 7
OP_GNM = 32
OP_AIS = 33
OP_LCK = 35
OP_TST = 37
OP_APS = 39
OP_RAPS = 40
OP_MCC = 41
OP_LMR = 42
OP_LMM = 43
OP_1DM = 45
OP_DMR = 46
OP_DMM = 47
OP_EXR = 48
OP_EXM = 49
OP_VSR = 50
OP_VSM = 51
OP_CSF = 52
OP_1SL = 53
OP_SLR = 54
OP_SLM = 55

OPCODE_NAMES: Dict[int, str] = {
    OP_CCM: "CCM", OP_LBR: "LBR", OP_LBM: "LBM", OP_LTR: "LTR", OP_LTM: "LTM",
    OP_RFM: "RFM", OP_SFM: "SFM", OP_GNM: "GNM",
    OP_AIS: "AIS", OP_LCK: "LCK", OP_TST: "TST", OP_APS: "APS", OP_RAPS: "R-APS",
    OP_MCC: "MCC", OP_LMR: "LMR", OP_LMM: "LMM", OP_1DM: "1DM", OP_DMR: "DMR",
    OP_DMM: "DMM", OP_EXR: "EXR", OP_EXM: "EXM", OP_VSR: "VSR", OP_VSM: "VSM",
    OP_CSF: "CSF", OP_1SL: "1SL", OP_SLR: "SLR", OP_SLM: "SLM",
}

# Y.1731 overlay opcodes - presence marks the ITU service-OAM layer in use.
# The split is the opcode range itself: 0-31 are reserved for IEEE 802.1
# (so CCM, LBM/LBR, LTM/LTR, RFM and SFM are 802.1ag), and 32-63 are
# ITU-T's, which is why GNM at 32 belongs here and RFM/SFM at 6 and 7 do
# not.
Y1731_OPCODES = frozenset({
    OP_GNM, OP_AIS, OP_LCK, OP_TST, OP_APS, OP_RAPS, OP_MCC, OP_LMR,
    OP_LMM, OP_1DM, OP_DMR, OP_DMM, OP_EXR, OP_EXM, OP_VSR, OP_VSM,
    OP_CSF, OP_1SL, OP_SLR, OP_SLM,
})

# Two DIFFERENT things, deliberately separated.
#
# OPCODE_MIN_BODY is how many octets of fixed fields the opcode's body
# must contain for the PDU to be parseable at all. Established from the
# field layout and verified empirically against Wireshark's dissector.
#
# OPCODE_FTO is the First TLV Offset the specification mandates, and it
# is populated ONLY where the value is actually established. Where the
# two independent dissectors disagree, the entry is absent and CFM-010
# does not fire for that opcode - asserting a guess there would raise a
# conformance defect on every conforming frame, which is the exact shape
# of bug this module has already hit twice (CFM-008 on G.8032v2 R-APS,
# CFM-083 on SF-P).
#
# Corroboration status:
#   CCM 70, LBM/LBR 4, AIS/LCK 0  - agreed by Wireshark, scapy, and the
#                                   IETF MPLS-TP/Y.1731 draft.
#   LTM 17, LTR 6, APS 4, R-APS 32, TST 4, LMM 12, DMM 32, 1DM 16,
#   SLM/SLR/1SL 16               - agreed by Wireshark and scapy.
#   LMR 12, DMR 32               - structural symmetry with LMM/DMM:
#                                   Wireshark decodes them through the
#                                   SAME field names (cfm.lmm.lmr.*,
#                                   cfm.dmm.dmr.*), so same layout. scapy
#                                   simply omits the reply opcodes from
#                                   its offset table.
#   MCC, EXM, EXR, VSM, VSR, GNM - NOT ESTABLISHED. Wireshark decodes
#                                   OUI+Sub-OpCode at a fixed position,
#                                   implying 4; scapy declares 0 for
#                                   EXM/EXR/VSM/VSR, 10 for MCC and 13
#                                   for GNM. The IETF draft covers none
#                                   of them and defers to Y.1731. So the
#                                   minimum body is asserted (4, or 1 for
#                                   GNM's Sub-OpCode) and the offset is
#                                   not.
OPCODE_MIN_BODY: Dict[int, int] = {
    OP_CCM: 70, OP_LBR: 4, OP_LBM: 4, OP_LTR: 6, OP_LTM: 17,
    OP_RFM: 4, OP_SFM: 4, OP_GNM: 1,
    OP_AIS: 0, OP_LCK: 0, OP_TST: 4, OP_APS: 4, OP_RAPS: 32,
    OP_MCC: 4, OP_LMR: 12, OP_LMM: 12, OP_1DM: 16, OP_DMR: 32, OP_DMM: 32,
    OP_EXR: 4, OP_EXM: 4, OP_VSR: 4, OP_VSM: 4, OP_CSF: 0,
    OP_1SL: 16, OP_SLR: 16, OP_SLM: 16,
}

OPCODE_FTO: Dict[int, int] = {
    OP_CCM: 70, OP_LBR: 4, OP_LBM: 4, OP_LTR: 6, OP_LTM: 17,
    OP_AIS: 0, OP_LCK: 0, OP_CSF: 0, OP_TST: 4, OP_APS: 4, OP_RAPS: 32,
    OP_LMM: 12, OP_LMR: 12, OP_DMM: 32, OP_DMR: 32, OP_1DM: 16,
    OP_1SL: 16, OP_SLR: 16, OP_SLM: 16,
}

# Opcodes whose body begins with a 3-octet OUI and a 1-octet Sub-OpCode.
OUI_OPCODES = frozenset({OP_MCC, OP_EXM, OP_EXR, OP_VSM, OP_VSR})
# Y.1731 reserves these for experimentation; they have no business in a
# production network.
EXPERIMENTAL_OPCODES = frozenset({OP_EXM, OP_EXR})
# Opcodes that carry performance-measurement state.
MEASUREMENT_OPCODES = frozenset({OP_LMM, OP_LMR, OP_DMM, OP_DMR, OP_1DM,
                                 OP_SLM, OP_SLR, OP_1SL})
# PTP-style timestamps: 48-bit seconds then 32-bit nanoseconds.
NANOS_PER_SECOND = 1000000000

TLV_END = 0
TLV_SENDER_ID = 1
TLV_PORT_STATUS = 2
TLV_DATA = 3
TLV_INTERFACE_STATUS = 4
TLV_REPLY_INGRESS = 5
TLV_REPLY_EGRESS = 6
TLV_LTM_EGRESS_ID = 7
TLV_LTR_EGRESS_ID = 8
TLV_TEST = 32
TLV_ORG_SPECIFIC = 31

TLV_NAMES: Dict[int, str] = {
    TLV_END: "End", TLV_SENDER_ID: "SenderID", TLV_PORT_STATUS: "PortStatus",
    TLV_DATA: "Data", TLV_INTERFACE_STATUS: "InterfaceStatus",
    TLV_REPLY_INGRESS: "ReplyIngress", TLV_REPLY_EGRESS: "ReplyEgress",
    TLV_LTM_EGRESS_ID: "LTMEgressID", TLV_LTR_EGRESS_ID: "LTREgressID",
    TLV_ORG_SPECIFIC: "OrganizationSpecific", TLV_TEST: "Test",
}

# CCM interval encoding (Flags bits 2..0) -> nominal period in seconds.
CCM_INTERVAL_SECONDS: Dict[int, float] = {
    1: 0.00333, 2: 0.01, 3: 0.1, 4: 1.0, 5: 10.0, 6: 60.0, 7: 600.0,
}
CCM_INTERVAL_NAMES: Dict[int, str] = {
    0: "invalid", 1: "3.33ms", 2: "10ms", 3: "100ms", 4: "1s", 5: "10s",
    6: "1min", 7: "10min",
}

# ---- G.8032 ERPS / R-APS (opcode 40) --------------------------------------
#
# Body layout, confirmed from two independent sources rather than inferred:
# the ITU-T liaison overview of G.8032 (IEEE 802.1 public docs, 2008) and
# scapy.contrib.oam, which cites ITU-T G.8032/Y.1344 (02/2022).
#
#   Request/State  4 bits
#   Sub-code       4 bits   (Reserved1 in the 2008 text; Sub-code later,
#                            used by the Event request to mean Flush)
#   Status         1 octet  RB bit 7, DNF bit 6, BPR bit 5, rest reserved
#                            (the 2008 text has RB + DNF + 6 reserved bits;
#                             BPR was added by a later revision)
#   Node ID        6 octets source node MAC, informational per spec
#   Reserved       24 octets
#                           -> 32 octets, matching First TLV Offset 32.
#
# Both sources agree the common header carries version 0 and all-zero
# Flags, and that an ERP receiver ignores the Flags field entirely.
RAPS_BODY_LEN = 32

RAPS_NR = 0x0
RAPS_MS = 0x7
RAPS_SF = 0xB
RAPS_FS = 0xD
RAPS_EVENT = 0xE

RAPS_REQUEST_NAMES: Dict[int, str] = {
    RAPS_NR: "NR", RAPS_MS: "MS", RAPS_SF: "SF", RAPS_FS: "FS",
    RAPS_EVENT: "Event",
}
# The 2008 revision defined only NR and SF; MS, FS and Event arrived with
# later revisions. Everything outside the current set is reserved.
RAPS_RESERVED_REQUESTS = frozenset(
    set(range(16)) - set(RAPS_REQUEST_NAMES))
# Operator-intent switches: these move ring traffic on command.
RAPS_COMMAND_REQUESTS = frozenset({RAPS_MS, RAPS_FS})
# Requests that cause receivers to flush the FDB unless DNF is set.
RAPS_FLUSH_REQUESTS = frozenset({RAPS_SF, RAPS_NR})
# Sub-code is only defined for Event, where 0 means Flush.
RAPS_SUBCODE_FLUSH = 0x0

RAPS_STATUS_RB = 0x80          # RPL is blocked
RAPS_STATUS_DNF = 0x40         # do not flush the FDB
RAPS_STATUS_BPR = 0x20         # blocked port reference - G.8032v2 ONLY

# The G.8032 revision is carried in the CFM common-header Version field,
# so v1 and v2 ARE distinguishable frame by frame:
#
#   version 0 -> G.8032v1. Bit 5 of the status octet is RESERVED; there is
#               no BPR field, and only NR and SF are defined requests.
#   version 1 -> G.8032v2. Bit 5 is BPR, and MS, FS and Event (with its
#               Flush sub-code) are defined.
#
# Confirmed against Wireshark, which selects the status layout from this
# field - it populates cfm.raps.status.reserved_v1 with a 0x3F mask for
# version 0 and reserved_v2 with 0x1F plus a decoded BPR for version 1 -
# and against vendor documentation stating that an R-APS version of 1
# corresponds to G.8032 version 2.
RAPS_VERSION_V1 = 0
RAPS_VERSION_V2 = 1
RAPS_REVISION_NAMES: Dict[int, str] = {0: "G.8032v1", 1: "G.8032v2"}
RAPS_STATUS_RESERVED_BY_VERSION: Dict[int, int] = {0: 0x3F, 1: 0x1F}
# Requests and fields that exist only from G.8032v2 onward.
RAPS_V2_ONLY_REQUESTS = frozenset({RAPS_MS, RAPS_FS, RAPS_EVENT})


RING_ROLE_MAJOR = "major"
RING_ROLE_SUB = "sub"
RING_ROLES = (RING_ROLE_MAJOR, RING_ROLE_SUB)


@dataclass(frozen=True)
class Ring:
    """An operator-declared ERPS ring.

    Baseline dependence is the central problem for ring rules: a
    legitimate protection switch and a forged R-APS are identical on the
    wire without the declared topology. This follows the pattern already
    proven in vrfwatch's interface-role declaration - the operator
    declares, an undeclared plane fails loud and raises its own finding,
    presence rules stay quiet while structural rules remain armed.

    G.8032v2 interconnected topologies need three more declared facts,
    because each one decides whether an observed event is normal:

      role/parent   a sub-ring attaches to a parent ring at
                    interconnection nodes.
      interconnect  ONLY an interconnection node legitimately propagates
                    a topology change, and propagation runs one way:
                    toward the ring the sub-ring connects to, never into
                    a sub-ring.
      vc            with a virtual channel the sub-ring's R-APS travels
                    over the parent between the interconnection nodes;
                    without one it must not appear there at all.
      revertive     revertive operation is CONFIGURATION ONLY in G.8032 -
                    it is not carried in R-APS - so a non-revertive ring
                    can only be known by declaration.
    """
    vlan: Tuple[int, ...]
    rpl_owner: Optional[bytes] = None
    nodes: Tuple[bytes, ...] = ()
    label: str = ""
    role: str = RING_ROLE_MAJOR
    parent: str = ""
    interconnect: Tuple[bytes, ...] = ()
    virtual_channel: Optional[bool] = None
    revertive: bool = True

    def name(self) -> str:
        return self.label or ("vlan%s" % "/".join(str(v) for v in self.vlan)
                              if self.vlan else "untagged")

    def is_sub(self) -> bool:
        return self.role == RING_ROLE_SUB


# G.8031 / G.8032 APS request-state codes (high nibble of octet 1).
APS_REQUEST_NAMES: Dict[int, str] = {
    0: "NR", 1: "DNR", 2: "RR", 4: "EXER", 5: "WTR", 7: "MS", 9: "SD",
    11: "SF", 13: "FS", 14: "SF-P", 15: "LO",
}
APS_RESERVED_REQUESTS = frozenset({3, 8, 10, 12})
# Code 6 was assigned by an earlier revision and is deprecated rather than
# reserved. Reported, but named for what it is.
APS_DEPRECATED_REQUESTS = frozenset({6})
# Operator-intent switches: these move production traffic on demand.
APS_COMMAND_REQUESTS = frozenset({7, 13, 15})

APS_NR = 0x0
APS_DNR = 0x1
APS_RR = 0x2
APS_EXER = 0x4
APS_WTR = 0x5
APS_MS = 0x7
APS_SD = 0x9
APS_SF = 0xB            # signal fail on the WORKING entity
APS_FS = 0xD
APS_SF_P = 0xE          # signal fail on the PROTECTION entity
APS_LO = 0xF

# G.8031 protection type, octet 1 low nibble. Bit positions confirmed
# empirically against Wireshark and scapy.contrib.oam, which agree.
#
# The four bits signal, in this order, whether an APS channel is in use,
# whether the architecture is 1:1 or 1+1, whether switching is uni- or
# bidirectional, and whether operation is revertive - which the ITU
# liaison text says is signalled to the far end precisely SO THAT
# mismatches can be detected.
#
# POLARITY IS DELIBERATELY NOT ASSERTED. No primary source consulted here
# states which value of each bit means which mode, so cfmwatch reports the
# bits by name and detects DISAGREEMENT between the two ends, which is
# polarity-independent. It never claims "non-revertive is in use".
APS_PROT_A = 0x08       # APS channel
APS_PROT_B = 0x04       # bridge architecture, 1:1 vs 1+1
APS_PROT_D = 0x02       # directional
APS_PROT_R = 0x01       # revertive
APS_PROT_BITS = (("A", APS_PROT_A), ("B", APS_PROT_B),
                 ("D", APS_PROT_D), ("R", APS_PROT_R))

# Octet 4: bridge type is the single top bit; the rest is reserved.
APS_BRIDGE_TYPE = 0x80
APS_OCTET4_RESERVED = 0x7F

# Requested and Bridged Signal octets: 0 is the null signal, 1 is normal
# traffic. Everything else is unassigned.
APS_SIGNAL_NAMES: Dict[int, str] = {0: "null", 1: "normal"}

MD_NAME_FORMATS: Dict[int, str] = {
    0: "reserved", 1: "none", 2: "domainName", 3: "macAddressAndUint16",
    4: "charString",
}
MA_NAME_FORMATS: Dict[int, str] = {
    0: "reserved", 1: "primaryVID", 2: "charString", 3: "uint16",
    4: "rfc2685VpnId",
}

MEPID_MIN = 1
MEPID_MAX = 8191

SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"
SEV_INFO = "INFO"

SEVERITY_ORDER = {
    SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_LOW: 3, SEV_INFO: 4,
}


# --------------------------------------------------------------------------
# Finding registry
# --------------------------------------------------------------------------
#
# confidence is an honest statement of what the wire evidence supports:
#   HIGH    pathognomonic - the frame cannot legitimately look like this
#   MEDIUM  strong indicator, benign explanations exist and are named
#   LOW     shape-only; needs operator corroboration (named in `caveat`)
#
# CVE-2014-3223 (Huawei S-series Y.1731 DoS) deliberately has NO code here.
# Its trigger field was never published, so no honest detector can be
# written for it. It lives in the README screening table only. Every code
# in this registry is expected to fire in the sealed lab; a code that can
# never fire would be dead weight and would corrupt that guarantee.

@dataclass(frozen=True)
class Spec:
    code: str
    title: str
    severity: str
    cls: str
    confidence: str
    summary: str
    cves: Tuple[str, ...] = ()
    caveat: str = ""


def _s(*args: Any, **kw: Any) -> Spec:
    return Spec(*args, **kw)


SPECS: Tuple[Spec, ...] = (
    # -- Class A: structural / bounds (the CVE-2020-1639 shape) -------------
    _s("CFM-001", "First TLV Offset points past end of frame", SEV_HIGH, "A",
       "HIGH",
       "The common header's First TLV Offset addresses an octet beyond the "
       "received CFM payload. A conforming sender cannot produce this."),
    _s("CFM-002", "TLV length overruns frame content", SEV_HIGH, "A", "HIGH",
       "A TLV declares a length that extends past the end of the CFM "
       "payload. This is the classic unsanitised-length read primitive."),
    _s("CFM-003", "TLV header truncated", SEV_HIGH, "A", "HIGH",
       "The TLV walk reached a position with fewer than 3 octets remaining "
       "but non-zero content, so a TLV header is cut mid-field."),
    _s("CFM-004", "End TLV absent", SEV_MEDIUM, "A", "MEDIUM",
       "The TLV chain ran to the end of content without an End TLV (type 0).",
       caveat="Some implementations omit the End TLV when no TLVs follow."),
    _s("CFM-005", "MAID name-length fields inconsistent", SEV_HIGH, "A",
       "HIGH",
       "The MD Name Length or Short MA Name Length in a CCM MAID overruns "
       "the 48-octet MAID field. Parser bounds violation inside the CCM "
       "body, reachable before any configuration check."),
    _s("CFM-006", "Opcode body shorter than specification minimum",
       SEV_HIGH, "A", "HIGH",
       "The CFM payload is too short to hold the mandatory body for its "
       "opcode. Truncated-body handling is the CVE-2020-1639 family."),
    _s("CFM-007", "Undefined or reserved opcode", SEV_MEDIUM, "A", "MEDIUM",
       "The opcode is not assigned by 802.1ag or Y.1731.",
       caveat="Vendor-private opcodes exist in the reserved ranges."),
    _s("CFM-008", "Non-zero CFM version", SEV_MEDIUM, "A", "MEDIUM",
       "The version field is not 0. No CFM version other than 0 is defined."),
    _s("CFM-009", "Non-zero data after End TLV", SEV_MEDIUM, "A", "MEDIUM",
       "Content follows the End TLV that is neither padding nor a plausible "
       "trailing FCS. Candidate covert-channel or smuggled payload.",
       caveat="Suppressed for one shape only: a 64-octet frame whose tail "
              "is zero padding followed by exactly four non-zero octets, "
              "which is a captured FCS behind a padded minimum-length "
              "frame. --strict-tail withdraws that allowance."),
    _s("CFM-010", "First TLV Offset disagrees with opcode", SEV_MEDIUM, "A",
       "MEDIUM",
       "First TLV Offset does not match the value 802.1ag/Y.1731 specifies "
       "for this opcode, so the body and the TLV chain overlap or gap."),

    # -- Class B: MD level hierarchy ---------------------------------------
    _s("CFM-020", "MD level disagrees with destination group address",
       SEV_HIGH, "B", "HIGH",
       "The MD level in the header does not match the level encoded in the "
       "01-80-C2-00-00-3x destination. Structural; needs no baseline."),
    _s("CFM-021", "MD level above configured domain ceiling", SEV_HIGH, "B",
       "HIGH",
       "A frame arrived at an MD level higher than the ceiling configured "
       "for this tap point, meaning it was not filtered at the domain "
       "boundary. Cross-domain injection.",
       caveat="Armed only when --md-ceiling is set."),
    _s("CFM-022", "Same MAID observed at two MD levels", SEV_HIGH, "B",
       "HIGH",
       "One maintenance association identifier appeared at more than one MD "
       "level. A MA belongs to exactly one level; this is level forgery or "
       "a leak across the domain boundary."),
    _s("CFM-024", "CCM sent to a non-CFM destination address", SEV_MEDIUM,
       "B", "MEDIUM",
       "A CCM was addressed outside the 01-80-C2-00-00-3x CFM group. CCMs "
       "are specified as multicast to the class 1 group for their level."),

    # -- Class C: CCM state and forgery ------------------------------------
    _s("CFM-040", "CCM MAID mismatch for established association",
       SEV_HIGH, "C", "HIGH",
       "A CCM carried a MAID different from the one already established for "
       "this VLAN and MD level. Receiving MEPs raise a cross-connect defect "
       "on this, which can take the service down."),
    _s("CFM-041", "Duplicate MEP ID in one association", SEV_HIGH, "C",
       "HIGH",
       "The same MEP ID was sourced from two different MAC addresses inside "
       "one MA. Pathognomonic for CCM forgery; drives an unexpected-MEP "
       "defect at every receiver."),
    _s("CFM-042", "CCM interval changed for established MEP", SEV_MEDIUM,
       "C", "MEDIUM",
       "A MEP's declared CCM interval changed. Receivers raise an "
       "unexpected-period defect.",
       caveat="Also produced by a legitimate reconfiguration."),
    _s("CFM-043", "CCM interval field invalid", SEV_MEDIUM, "C", "HIGH",
       "The CCM interval encoding is 0, which 802.1ag defines as invalid."),
    _s("CFM-044", "CCM RDI asserted", SEV_LOW, "C", "MEDIUM",
       "Remote Defect Indication is set, so the peer MEP is reporting a "
       "fault in the other direction.",
       caveat="Normal during a genuine fault; value is as corroboration."),
    _s("CFM-045", "Unexpected MEP joined established association",
       SEV_MEDIUM, "C", "MEDIUM",
       "A MEP ID not previously seen started sourcing CCMs into an MA that "
       "had already settled.",
       caveat="Also produced by legitimate MEP provisioning."),
    _s("CFM-046", "Established MEP ID moved to a new source MAC", SEV_HIGH,
       "C", "HIGH",
       "A MEP ID that had a stable source MAC is now sourced from a "
       "different one. MEP impersonation, or a hardware swap."),
    _s("CFM-047", "Sub-100ms CCM interval in use", SEV_LOW, "C", "HIGH",
       "A MEP declared a 3.33ms or 10ms CCM interval. Legitimate for "
       "protection-grade services, and also the cheapest way to put "
       "sustained load on a peer's CFM daemon."),
    _s("CFM-048", "Anomalous MAID name format", SEV_MEDIUM, "C", "MEDIUM",
       "The MD Name Format or Short MA Name Format is reserved or "
       "unassigned.",
       caveat="Y.1731 ICC-based formats occupy part of the MA range."),
    _s("CFM-049", "MEP ID field invalid", SEV_MEDIUM, "C", "HIGH",
       "The 13-bit MEP ID is 0, which 802.1ag excludes, or the three "
       "reserved bits above it are set. Either way the field was not "
       "produced by a conforming MEP."),

    # -- Class D: Y.1731 fault management ----------------------------------
    _s("CFM-060", "AIS observed", SEV_LOW, "D", "HIGH",
       "An Alarm Indication Signal was seen. Recorded because AIS is the "
       "primitive that suppresses downstream alarms.",
       caveat="Normal during a real server-layer fault."),
    _s("CFM-061", "AIS from a source with no CCM history", SEV_HIGH, "D",
       "HIGH",
       "AIS was injected into an association by a MAC that has never "
       "sourced a CCM there. Forged alarm suppression: the NOC stops "
       "seeing a real fault, or starts seeing a fabricated one."),
    _s("CFM-062", "LCK observed", SEV_MEDIUM, "D", "HIGH",
       "A Locked Signal frame was seen, declaring an administrative lock "
       "that suppresses downstream alarms for the client layer.",
       caveat="Normal during planned out-of-service maintenance."),
    _s("CFM-063", "AIS raised while server-layer CCMs are healthy",
       SEV_HIGH, "D", "MEDIUM",
       "AIS claims a fault at the client level while CCMs at or below the "
       "server level continued to arrive on schedule. The fault the AIS "
       "asserts is not visible on the wire.",
       caveat="A fault outside the tap's visibility produces the same "
              "picture; corroborate against the server-layer path."),
    _s("CFM-064", "CSF observed", SEV_LOW, "D", "HIGH",
       "A Client Signal Fail frame was seen, propagating a client-layer "
       "failure indication across the service."),
    _s("CFM-065", "AIS/LCK period field invalid", SEV_MEDIUM, "D", "HIGH",
       "The transmission period encoded in an AIS or LCK frame is 0 or a "
       "reserved value. Y.1731 defines only 1s and 1min for these."),

    # -- Class E: protection switching (the headline class) ----------------
    _s("CFM-080", "APS frame observed", SEV_INFO, "E", "HIGH",
       "G.8031 linear or G.8032 ring protection switching is active on this "
       "segment. Baseline for the rest of the class."),
    _s("CFM-081", "APS Forced Switch requested", SEV_HIGH, "E", "HIGH",
       "A Forced Switch moves production traffic onto the protection path "
       "regardless of its condition. Unauthenticated on the wire."),
    _s("CFM-082", "APS Manual Switch requested", SEV_MEDIUM, "E", "HIGH",
       "A Manual Switch moves production traffic to the protection path."),
    _s("CFM-083", "APS Signal Fail with no corroborating fault",
       SEV_CRITICAL, "E", "MEDIUM",
       "Signal Fail was asserted for a protection group while CCMs on the "
       "working path kept arriving and no AIS was seen. This is the forged "
       "protection switch: it moves live traffic on a fabricated fault.",
       caveat="A fault downstream of the tap produces the same picture."),
    _s("CFM-084", "New source MAC for established protection group",
       SEV_HIGH, "E", "HIGH",
       "APS frames for a protection group are now sourced from a MAC that "
       "has not previously driven it. Injection into the protection plane."),
    _s("CFM-085", "Protection-switch churn", SEV_HIGH, "E", "MEDIUM",
       "The APS request state for one group changed repeatedly inside the "
       "churn window. Sustained churn keeps a service oscillating between "
       "paths.",
       caveat="A genuinely flapping working path looks the same."),
    _s("CFM-086", "APS request code reserved or deprecated", SEV_MEDIUM,
       "E", "HIGH",
       "The APS request/state nibble is a value G.8031 reserves, or the "
       "one code an earlier revision assigned and later deprecated. The "
       "detail names which."),
    _s("CFM-087", "APS Lockout of protection requested", SEV_CRITICAL, "E",
       "HIGH",
       "Lockout disables the protection path entirely, so the next real "
       "fault on the working path takes the service down with no failover. "
       "Pairs naturally with a subsequent attack on the working path."),
    _s("CFM-088", "APS Signal Fail on the protection entity (SF-P)",
       SEV_HIGH, "E", "HIGH",
       "SF-P reports that the PROTECTION path has failed, not the working "
       "one. Traffic keeps flowing on the working path, so nothing breaks "
       "now - but the service is running unprotected, and the next working-"
       "path fault takes it down. Deliberately NOT subject to the "
       "uncorroborated-fault test: healthy working-path CCMs are exactly "
       "what SF-P implies, so treating it like SF produces a false "
       "forged-switch alarm on every genuine protection failure."),
    _s("CFM-089", "APS Signal Degrade requested", SEV_MEDIUM, "E", "HIGH",
       "Signal Degrade asks for a protection switch on degraded rather "
       "than failed signal quality. It is unauthenticated like every other "
       "APS request, and it moves production traffic.",
       caveat="SD is a legitimate request on a path with real bit errors."),
    _s("CFM-090", "APS protection type disagrees between ends", SEV_HIGH,
       "E", "HIGH",
       "The two ends of a protection group advertised different protection "
       "type bits. G.8031 signals this configuration to the far end "
       "specifically so a mismatch can be detected: the ends disagree "
       "about the architecture, the directionality or the revert policy, "
       "so the group will not protect as designed.",
       caveat="cfmwatch reports which bits differ. It does not claim which "
              "mode each value means, because no primary source consulted "
              "pins the polarity of these bits."),
    _s("CFM-091", "APS requested and bridged signal disagree", SEV_MEDIUM,
       "E", "MEDIUM",
       "The Requested Signal and Bridged Signal octets differ, so the "
       "sender is asking for one signal on the protection entity while "
       "bridging another. Transient during a switch; persistent means the "
       "switch never completed and the group is in an inconsistent state.",
       caveat="One frame mid-switch is normal. Weight the repeat count."),
    _s("CFM-092", "APS carries non-zero reserved bits", SEV_LOW, "E",
       "HIGH",
       "The reserved bits of the APS body's last octet are not zero. A "
       "conforming implementation zeroes them, so this identifies the "
       "sender rather than causing harm.",
       caveat="No operational impact by itself; value is as a fingerprint "
              "of a hand-rolled or non-conforming APS source."),
    _s("CFM-093", "Protection group inventory", SEV_INFO, "E", "HIGH",
       "Linear protection groups observed, with the nodes driving each, "
       "the protection type bits they advertise, the bridge type and the "
       "request states seen."),

    # -- Class F: loopback and linktrace -----------------------------------
    _s("CFM-100", "LBM observed", SEV_LOW, "F", "HIGH",
       "An unauthenticated loopback message was seen. Any station on the "
       "segment can emit these at any MD level it chooses."),
    _s("CFM-101", "LBM flood from one source", SEV_HIGH, "F", "MEDIUM",
       "One source exceeded the loopback-burst threshold. LBM is processed "
       "by the control plane, so a flood is a cheap CPU attack.",
       caveat="Also produced by an automated service-assurance probe."),
    _s("CFM-102", "LTM observed", SEV_LOW, "F", "HIGH",
       "A linktrace message was seen. LTM is a topology-disclosure "
       "primitive: each MIP on the path answers with its own identity."),
    _s("CFM-103", "LTM TTL sweep from one source", SEV_HIGH, "F", "HIGH",
       "One source emitted linktraces with ascending TTLs inside the sweep "
       "window. That is deliberate hop-by-hop mapping of the provider's "
       "MIP chain, not fault isolation of a known path."),
    _s("CFM-104", "MIP identity disclosed in linktrace reply", SEV_MEDIUM,
       "F", "HIGH",
       "An LTR carried ingress or egress identifier TLVs, exposing the MAC "
       "address and port identity of an intermediate point to whoever sent "
       "the LTM."),
    _s("CFM-105", "Oversized Data TLV in loopback", SEV_MEDIUM, "F",
       "MEDIUM",
       "An LBM or LBR carried a Data TLV above the size threshold. Large "
       "loopback payloads are used for amplification and to push peers "
       "through reassembly and buffer paths.",
       caveat="Service-activation testing legitimately uses large frames."),
    _s("CFM-106", "Anomalous linktrace TTL", SEV_MEDIUM, "F", "HIGH",
       "An LTM carried TTL 0 or 255. Zero should never be transmitted and "
       "255 maximises the traversal of the discovery."),

    # -- Class G: rate and volume (the CVE-2025-52961 shape) ---------------
    _s("CFM-120", "Aggregate CFM frame rate above threshold", SEV_MEDIUM,
       "G", "MEDIUM",
       "Total CFM frames per second on this tap exceeded the configured "
       "rate threshold.",
       caveat="Thresholds are deployment-specific; tune with --rate-max."),
    _s("CFM-121", "CCM arrival rate exceeds declared interval", SEV_MEDIUM,
       "G", "MEDIUM",
       "A MEP's CCMs arrived materially faster than the interval it "
       "declares in its own flags field.",
       caveat="Duplicated capture, or a SPAN seeing both directions, "
              "produces the same arithmetic."),
    _s("CFM-122", "Sustained valid CFM burst from one adjacent source",
       SEV_HIGH, "G", "LOW",
       "One source sustained a high rate of well-formed CFM frames. This is "
       "the only shape CVE-2025-52961 presents on the wire, because the "
       "triggering traffic is valid.",
       cves=("CVE-2025-52961",),
       caveat="Signature is volumetric, not structural. It cannot "
              "distinguish the CVE from any other heavy CFM talker; treat "
              "it as a prompt to check cfmman RSS on the peer."),

    # -- Class H: CVE triggers ---------------------------------------------
    _s("CFM-140", "Malformed CFM consistent with CVE-2020-1639", SEV_HIGH,
       "H", "MEDIUM",
       "A structurally malformed CFM frame of the shape JSA11020 "
       "describes: improperly sanitised Ethernet OAM leading to an overflow "
       "and a CFM daemon core on affected Junos releases. Raised when a "
       "Class A bounds violation is present. Continued receipt extends the "
       "outage, so repetition is reported.",
       cves=("CVE-2020-1639",),
       caveat="Fires on the frame shape, not on target version. Whether a "
              "receiver is an affected Junos release is not on the wire."),
    _s("CFM-141", "CFM load pattern consistent with CVE-2025-52961",
       SEV_MEDIUM, "H", "LOW",
       "A sustained adjacent-source CFM load of the kind that drives cfmd "
       "to 100% CPU with a cfmman memory leak on Junos OS Evolved PTX "
       "platforms, ending in an FPC crash and restart.",
       cves=("CVE-2025-52961",),
       caveat="The CVE's traffic is valid, so this is a rate correlation "
              "only. The reliable indicator of compromise is cfmman RSS "
              "growth on the device, which is off-wire."),

    # -- Class P: posture inventory ----------------------------------------
    # No "CFM is enabled" finding. Service OAM visibility is by design;
    # reporting its presence as a weakness is the mistake the standing
    # lldpwatch directive exists to prevent. These are inventory records.
    _s("CFM-160", "MD level inventory", SEV_INFO, "P", "HIGH",
       "Maintenance domain levels observed on this tap, with the VLANs they "
       "appeared on."),
    _s("CFM-161", "MEP inventory", SEV_INFO, "P", "HIGH",
       "Maintenance endpoints observed, by MEP ID, source MAC, MAID and "
       "declared CCM interval."),
    _s("CFM-162", "Y.1731 overlay in use", SEV_INFO, "P", "HIGH",
       "ITU-T Y.1731 opcodes were seen alongside 802.1ag, so the service "
       "OAM layer is in use and not just connectivity checking."),
    _s("CFM-163", "Service VLAN inventory", SEV_INFO, "P", "HIGH",
       "VLAN tags observed carrying CFM, including QinQ outer/inner pairs."),

    # -- Class R: ERPS / G.8032 ring protection ----------------------------
    # ERPS rides the Y.1731 machinery this module already owns: R-APS is
    # opcode 40 inside the same 0x8902 frame, and G.8032's primary fault
    # trigger is missed CCMs, which Class C already tracks. The escalation
    # that justifies the class is that on a ring, a forged or suppressed
    # CCM does not merely signal a fault - it causes a protection switch
    # and an FDB flush.
    #
    # ERPS has no CVE of its own. It enters as an abuse and posture tier
    # on a plane the module already parses, not as a CVE-less standalone.
    _s("CFM-180", "R-APS observed", SEV_INFO, "R", "HIGH",
       "G.8032 ring protection is active on this segment. Baseline for the "
       "rest of the class."),
    _s("CFM-181", "R-APS request/state reserved", SEV_MEDIUM, "R", "HIGH",
       "The request/state nibble is not one of NR, MS, SF, FS or Event. "
       "G.8032 reserves every other value."),
    _s("CFM-182", "R-APS carries non-zero Flags or reserved bits",
       SEV_LOW, "R", "HIGH",
       "G.8032 specifies all-zero Flags in the common header and reserved "
       "bits in the status octet. A conforming implementation zeroes them "
       "and a receiver ignores them, so this identifies the sender rather "
       "than causing harm. The reserved mask is revision-dependent: 0x3F "
       "for v1, 0x1F for v2, where bit 5 becomes BPR.",
       caveat="No operational impact by itself; value is as a fingerprint "
              "of a hand-rolled or non-conforming R-APS source."),
    _s("CFM-183", "R-APS Node ID does not match Ethernet source",
       SEV_MEDIUM, "R", "LOW",
       "The Node ID in the R-APS body differs from the frame's source MAC. "
       "The spec marks Node ID informational, so it is unauthenticated and "
       "free to forge.",
       caveat="R-APS is forwarded around the ring, and an implementation "
              "that rewrites the source MAC on forwarding decouples the "
              "two legitimately. Corroborate against the ring topology "
              "before treating this as forgery."),
    _s("CFM-184", "R-APS sub-code set on a request that defines none",
       SEV_MEDIUM, "R", "HIGH",
       "A non-zero sub-code appeared with a request/state other than "
       "Event. G.8032 defines the sub-code only for Event, where zero "
       "means Flush."),
    _s("CFM-185", "R-APS Signal Fail observed", SEV_LOW, "R", "HIGH",
       "An R-APS(SF) was seen, so a node is reporting a ring link failure. "
       "Receivers unblock, stop their own transmission and flush the FDB.",
       caveat="This is the normal fault signal on a healthy ring."),
    _s("CFM-186", "R-APS Signal Fail with no corroborating fault",
       SEV_CRITICAL, "R", "MEDIUM",
       "R-APS(SF) was asserted while CCMs on the ring control VLAN kept "
       "arriving on schedule and no AIS was seen. This is the forged ring "
       "protection switch: it unblocks the RPL, moves live traffic and "
       "flushes every node's FDB on a fabricated fault.",
       caveat="A failure on a ring segment the tap cannot see produces the "
              "same picture. A ring gives one vantage onto a loop."),
    _s("CFM-187", "R-APS Forced Switch requested", SEV_HIGH, "R", "HIGH",
       "A Forced Switch moves ring traffic regardless of link condition. "
       "Unauthenticated on the wire."),
    _s("CFM-188", "R-APS Manual Switch requested", SEV_MEDIUM, "R", "HIGH",
       "A Manual Switch moves ring traffic to the alternate path."),
    _s("CFM-189", "R-APS Event/Flush observed", SEV_MEDIUM, "R", "HIGH",
       "An R-APS(Event) with sub-code Flush is a bare FDB-flush primitive: "
       "it clears learned forwarding state across the ring without any "
       "topology change to justify it.",
       caveat="Suppressed when the source is a declared interconnection "
              "node, where the flush is normal G.8032v2 sub-ring "
              "propagation and is recorded as CFM-209 instead. Without a "
              "declared topology cfmwatch cannot tell the two apart, so "
              "this still fires on an undeclared interconnected ring."),
    _s("CFM-190", "Repeated R-APS Event/Flush", SEV_HIGH, "R", "MEDIUM",
       "Several Event/Flush messages arrived inside the burst window. "
       "Each one clears every node's learned forwarding state, so a "
       "sustained run forces the ring to flood continuously.",
       caveat="Counts only flushes that were not legitimate "
              "interconnection-node propagation. Still legitimate during "
              "repeated genuine topology changes; correlate with whether "
              "any SF or NR,RB accompanied them."),
    _s("CFM-191", "DNF set on a flush-triggering R-APS", SEV_HIGH, "R",
       "MEDIUM",
       "Do-Not-Flush was set on an R-APS that would otherwise cause an FDB "
       "flush. Suppressing the flush leaves stale forwarding entries after "
       "the path has moved, which blackholes or misdelivers traffic rather "
       "than disrupting it visibly.",
       caveat="DNF is legitimate where the implementation knows a flush is "
              "unnecessary; it is the combination with a path change that "
              "matters."),
    _s("CFM-192", "RPL-blocked claimed by a node that is not the declared "
       "RPL owner", SEV_HIGH, "R", "HIGH",
       "The RB status bit is the RPL owner's announcement that it holds "
       "the ring's single block. A different node asserting it is "
       "impersonating the owner.",
       caveat="Armed only when --ring declares an RPL owner."),
    _s("CFM-193", "Two nodes concurrently claim RPL-blocked", SEV_HIGH, "R",
       "HIGH",
       "More than one node asserted RB inside the correlation window. A "
       "ring must have exactly one block; two blocks segment it into two "
       "broken halves."),
    _s("CFM-194", "Ring idle with no node claiming RPL-blocked",
       SEV_HIGH, "R", "LOW",
       "A run of R-APS(NR) was seen on a declared ring with no RB asserted "
       "by anyone. If no node holds the block, the ring is a closed loop.",
       caveat="Two benign causes remain. A tap sees one segment of a "
              "ring, so the RPL owner's R-APS(NR,RB) may simply never "
              "traverse it, and a capture beginning mid-protection looks "
              "identical. The third - non-revertive operation, where no "
              "RB claim is correct - is removed by declaring "
              "revertive=no, since G.8032 carries no revertive flag on "
              "the wire. If the block was observed earlier in the capture "
              "and then vanished, CFM-206 reports that instead."),
    _s("CFM-195", "R-APS from a node outside the declared ring", SEV_HIGH,
       "R", "HIGH",
       "An R-APS was sourced by a MAC that the ring declaration does not "
       "list as a ring node. Injection into the ring control plane from "
       "off-ring.",
       caveat="Armed only when --ring declares a node set."),
    _s("CFM-196", "R-APS on a VLAN not declared as a ring control VLAN",
       SEV_MEDIUM, "R", "MEDIUM",
       "Ring control traffic appeared on a VLAN outside every declared "
       "ring. Either a ring exists that the declaration omits, or R-APS is "
       "being injected where no ring runs.",
       caveat="Armed only when at least one ring is declared."),
    _s("CFM-197", "Ring protection-state churn", SEV_HIGH, "R", "MEDIUM",
       "The R-APS request/state for one ring changed repeatedly inside the "
       "churn window, so the ring is being driven between protected and "
       "idle. Each transition carries its own FDB flush.",
       caveat="A genuinely flapping ring link looks the same."),
    _s("CFM-198", "R-APS flood from one source", SEV_HIGH, "R", "MEDIUM",
       "One source exceeded the R-APS burst threshold. R-APS is processed "
       "by the ring state machine, so volume translates into state churn "
       "and control-plane load.",
       caveat="Thresholds are deployment-specific; tune with "
              "--raps-rate-max."),
    _s("CFM-199", "CCM loss on a declared ring control VLAN", SEV_HIGH,
       "R", "MEDIUM",
       "A MEP on a ring control VLAN went quiet for longer than the "
       "G.8032 fault threshold of three missed CCMs at its own declared "
       "interval. On a ring this is not merely a fault indication: it is "
       "the primary protection trigger, so it moves traffic and flushes "
       "forwarding state.",
       caveat="A lost or filtered capture produces the same gap. The "
              "hold-off timer means a brief gap may not trigger the ring."),
    _s("CFM-200", "Ring protection seen with no ring declared",
       SEV_MEDIUM, "R", "HIGH",
       "R-APS was observed but no --ring declaration covers it, so every "
       "rule that needs the ring topology, RPL owner or node set is "
       "inert. Structural rules still apply. This finding exists so an "
       "undeclared ring fails loudly instead of looking clean."),
    _s("CFM-201", "Ring inventory", SEV_INFO, "R", "HIGH",
       "Rings observed, with the nodes that sourced R-APS on each, which "
       "of them asserted RPL-blocked, the request states seen, and the "
       "G.8032 revision each node speaks."),
    _s("CFM-202", "G.8032v2-only field used in a v1 R-APS", SEV_MEDIUM,
       "R", "HIGH",
       "An R-APS declaring G.8032v1 (version 0) carried a request or "
       "field that only exists from v2: Manual Switch, Forced Switch, "
       "Event/Flush, or the BPR status bit. A conforming v1 node cannot "
       "emit this, so it is either forged or a node misreporting its own "
       "revision."),
    _s("CFM-203", "Mixed G.8032 revisions on one ring", SEV_MEDIUM, "R",
       "HIGH",
       "Both v1 and v2 R-APS were seen on the same ring control VLAN. The "
       "revisions differ in the status-octet layout and in which requests "
       "exist, so a mixed ring does not converge consistently - nodes "
       "disagree about what they were told. Some implementations reject "
       "v1 outright as a protocol failure.",
       caveat="Also produced by a partially completed upgrade, which is a "
              "real risk window rather than a false positive."),
    _s("CFM-204", "Several R-APS destinations on one ring control VLAN",
       SEV_MEDIUM, "R", "MEDIUM",
       "R-APS on this control VLAN arrived at more than one destination "
       "address. The ring ID is carried in the R-APS destination MAC, and "
       "sharing a VLAN between adjoining rings requires exactly that - so "
       "this usually means two ring instances share the VLAN while the "
       "declaration models one, leaving their state merged.",
       caveat="Armed only when a ring is declared. Separating the "
              "instances is out of scope by decision: no primary source "
              "pins the ring ID's offset within the address, and this "
              "module does not infer wire formats it cannot cite. This "
              "finding exists so the condition is visible rather than "
              "silent, and the operator can split the declaration."),
    _s("CFM-205", "R-APS Event/Flush from a node that is not an "
       "interconnection node", SEV_HIGH, "R", "HIGH",
       "Only an interconnection node legitimately propagates a topology "
       "change onto a ring, and it does so as an Event/Flush. A flush "
       "from any other node on a declared topology is a bare FDB-flush "
       "primitive from a source with no business sending one.",
       caveat="Armed only when the ring declaration names its "
              "interconnection nodes."),
    _s("CFM-206", "RPL block withdrawn", SEV_HIGH, "R", "MEDIUM",
       "A node asserted RPL-blocked earlier in this capture, and the ring "
       "is now running a sustained R-APS(NR) stream with nobody asserting "
       "it. The block this tap had already seen is gone, so the ring is "
       "closed into a loop.",
       caveat="Stronger than CFM-194 because the block was observed rather "
              "than assumed, which removes the tap-vantage explanation. A "
              "legitimate switch to non-revertive operation mid-capture "
              "would look the same."),
    _s("CFM-207", "R-APS Event/Flush propagated into a sub-ring",
       SEV_MEDIUM, "R", "HIGH",
       "A flush arrived on a declared sub-ring from its parent's "
       "interconnection node. G.8032 propagation runs one way - a "
       "sub-ring sends flushes toward the ring it connects to, and rings "
       "never send flushes into their sub-rings - so this direction is "
       "never legitimate.",
       caveat="Armed only when the ring is declared role=sub with a "
              "parent."),
    _s("CFM-208", "Sub-ring R-APS on its parent with no virtual channel",
       SEV_MEDIUM, "R", "MEDIUM",
       "A declared sub-ring node that is not an interconnection node "
       "sourced R-APS on the parent ring's control VLAN while the "
       "sub-ring is declared without a virtual channel. Without one the "
       "sub-ring's R-APS must not reach the parent at all, so either the "
       "declaration is wrong or control traffic is leaking between rings.",
       caveat="Armed only when the sub-ring declares vc=no. Interconnection "
              "nodes sit on both rings legitimately and are excluded."),
    _s("CFM-209", "Sub-ring topology-change propagation observed",
       SEV_INFO, "R", "HIGH",
       "An interconnection node propagated a topology change onto the "
       "ring as an Event/Flush. This is normal G.8032v2 operation on an "
       "interconnected topology and is recorded rather than alarmed - it "
       "is what CFM-189 and CFM-190 would otherwise report as a bare "
       "flush primitive."),

    _s("CFM-220", "Measurement frame from a source with no CCM history",
       SEV_MEDIUM, "M", "MEDIUM",
       "An LM, DM or SLM frame arrived on a service from a MAC that has "
       "never sourced a CCM there. Performance measurement is between "
       "established MEPs, so a measurement frame from an unknown source "
       "is either an injected probe or a station measuring a service it "
       "is not part of.",
       caveat="A tap that joined after the MEPs settled, or one that "
              "sees the measurement path but not the CCM path, produces "
              "the same picture."),
    _s("CFM-221", "Frame counter regression in a measurement reply",
       SEV_MEDIUM, "M", "HIGH",
       "A transmit or receive frame counter went backwards for one "
       "measurement session. The counters in LMM/LMR and SLM/SLR are "
       "monotonic by construction, so a decrease means forged or "
       "replayed measurement traffic - which corrupts the loss figures "
       "the NOC uses to judge the service."),
    _s("CFM-222", "Delay-measurement timestamp field invalid", SEV_MEDIUM,
       "M", "HIGH",
       "A timestamp's nanoseconds field is 1,000,000,000 or greater, "
       "which no conforming sender can produce. Structural, and it needs "
       "no assumption about clock synchronisation."),
    _s("CFM-223", "Delay-measurement reply timestamps inconsistent",
       SEV_MEDIUM, "M", "MEDIUM",
       "A DMR's own timestamps contradict each other - the frame was "
       "received before it was sent, or returned before it arrived. One "
       "frame carries all four, so this is judged within the frame and "
       "needs no clock of our own.",
       caveat="Endpoints with unsynchronised clocks legitimately produce "
              "crossed forward and backward pairs; only an ordering "
              "violation within the same direction is unambiguous."),
    _s("CFM-224", "Synthetic-loss reply with no matching test", SEV_MEDIUM,
       "M", "MEDIUM",
       "An SLR carried a Test ID that no observed SLM requested. Either "
       "the replies are forged, or they answer a test this tap cannot "
       "see.",
       caveat="A tap that sees one direction only will report this for "
              "every legitimate reply; weight it by whether SLMs are "
              "visible at all."),
    _s("CFM-225", "TST frames observed", SEV_LOW, "M", "HIGH",
       "ETH-TST test frames are in use. They carry an arbitrary-length "
       "pattern and are the one Y.1731 opcode designed to move bulk "
       "data, which is why the rate matters more than the presence.",
       caveat="Legitimate during service activation testing."),
    _s("CFM-226", "Sustained TST burst from one source", SEV_HIGH, "M",
       "MEDIUM",
       "One source sustained a high rate of TST frames. TST is a "
       "bandwidth-injection primitive wearing OAM clothing: the payload "
       "is arbitrary, the frames are unauthenticated, and they are "
       "carried inside the customer's service.",
       caveat="Service-activation testing to Y.1564 looks exactly like "
              "this and is usually scheduled; correlate with a change "
              "window."),
    _s("CFM-227", "MCC observed", SEV_LOW, "M", "HIGH",
       "A Maintenance Communication Channel frame was seen. MCC carries "
       "vendor management traffic inside the OAM channel, so it is a "
       "management path that does not appear in any routing or firewall "
       "policy.",
       caveat="Legitimate on vendors that use MCC for remote management "
              "of unaddressed devices."),
    _s("CFM-228", "Vendor-specific OAM observed", SEV_LOW, "M", "HIGH",
       "A VSM or VSR frame was seen. The body after the OUI is "
       "undocumented by the standard, so its content cannot be "
       "validated - only its presence and the OUI claiming it."),
    _s("CFM-229", "Experimental OAM opcode in production", SEV_MEDIUM, "M",
       "HIGH",
       "An EXM or EXR frame was seen. Y.1731 reserves these opcodes for "
       "experimentation; they have no defined meaning and no business on "
       "a production service, so any sighting is either a lab leak or a "
       "hand-rolled sender."),
    _s("CFM-230", "Measurement plane inventory", SEV_INFO, "M", "HIGH",
       "Performance-measurement and maintenance opcodes observed, with "
       "the sources using each, the test IDs seen, and the OUIs claiming "
       "vendor-specific and management traffic."),

    _s("CFM-240", "CFM observed inside VXLAN encapsulation", SEV_INFO, "T",
       "HIGH",
       "Service OAM was seen inside a VXLAN tunnel, so this tap is on the "
       "underlay rather than on the customer's segment. Recorded because "
       "it changes what the rest of the findings mean: the VNI is the "
       "service identifier, and without decapsulation none of this plane "
       "would be visible at all."),

    _s("CFM-250", "E-LMI observed", SEV_INFO, "L", "HIGH",
       "MEF 16 E-LMI is running on this segment, so the tap is at a "
       "PE-CE UNI. Carries the EVC references the PE is reporting and "
       "their status - the service map as the provider declares it, "
       "alongside the one this module observes from CFM."),
    _s("CFM-251", "EVC status contradicts the CFM state of the same "
       "service", SEV_HIGH, "L", "MEDIUM",
       "E-LMI tells the customer one thing about an EVC while CFM on the "
       "mapped service says another: either the EVC is reported Active "
       "while CFM shows a fault, so a real outage is being hidden, or it "
       "is reported Not Active while CFM is healthy, so an outage is "
       "being manufactured. Both are what a forged E-LMI achieves, and "
       "neither is visible from either plane alone - which is the whole "
       "reason E-LMI is in this module.",
       caveat="Armed only when --evc maps the EVC reference to a service "
              "VLAN. A fault outside the tap's visibility, or a PE that "
              "has not yet reconverged, produces the same contradiction "
              "briefly; weight the repeat count."),
    _s("CFM-252", "E-LMI structural defect", SEV_MEDIUM, "L", "HIGH",
       "An E-LMI frame violated MEF 16: a protocol version other than 1, "
       "a message type that is neither Status nor Status Enquiry, an "
       "information element whose length overruns the frame, an "
       "undefined report type, an undefined EVC status value, or a "
       "destination outside the E-LMI group address."),
    _s("CFM-253", "E-LMI sequence number anomaly", SEV_MEDIUM, "L",
       "MEDIUM",
       "The send sequence number for this UNI repeated or went "
       "backwards. E-LMI is a polled protocol whose sequence numbers are "
       "how each side detects loss, so a repeat is a replayed frame and a "
       "regression is a spoofed one.",
       caveat="The counter is a single octet and wraps at 255, which is "
              "excluded; a genuine PE restart also resets it."),
    _s("CFM-254", "E-LMI seen with no EVC mapping declared", SEV_MEDIUM,
       "L", "HIGH",
       "E-LMI is present but no --evc declaration maps its EVC "
       "references to service VLANs, so the cross-plane contradiction "
       "rule is inert. The structural and sequence rules still apply. "
       "This exists so an undeclared mapping fails loudly instead of "
       "looking clean."),
)

REGISTRY: Dict[str, Spec] = {s.code: s for s in SPECS}

CLASS_NAMES: Dict[str, str] = {
    "A": "Structural / bounds",
    "B": "MD level hierarchy",
    "C": "CCM state and forgery",
    "D": "Y.1731 fault management",
    "E": "Protection switching (APS)",
    "F": "Loopback and linktrace",
    "G": "Rate and volume",
    "H": "CVE triggers",
    "P": "Posture inventory",
    "R": "ERPS / G.8032 ring protection",
    "M": "Y.1731 measurement and maintenance",
    "T": "Transport and encapsulation",
    "L": "E-LMI cross-plane (MEF 16)",
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def split_service(key: Tuple[int, ...]) -> Tuple[Optional[int],
                                                 Tuple[int, ...]]:
    """Split a service key back into (vni or None, vlan tuple)."""
    if not key:
        return None, ()
    vni = key[0]
    return (None if vni == NO_VNI else vni), tuple(key[1:])


def service_label(key: Tuple[int, ...]) -> str:
    vni, vlans = split_service(key)
    tag = "/".join(str(v) for v in vlans) if vlans else "untagged"
    return ("vni%d:%s" % (vni, tag)) if vni is not None else tag


def mac_str(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


def hexs(raw: bytes, limit: int = 32) -> str:
    cut = raw[:limit]
    out = binascii.hexlify(cut).decode("ascii")
    return out + ("..." if len(raw) > limit else "")


def _printable(raw: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in raw)


@dataclass
class Vlan:
    tpid: int
    vid: int
    pcp: int
    dei: int

    def __str__(self) -> str:
        return "0x%04x/vid%d" % (self.tpid, self.vid)


@dataclass
class CfmFrame:
    """One parsed CFM frame. Structural defects are recorded, never raised."""
    index: int
    ts: float
    frame_len: int
    dst: bytes
    src: bytes
    vlans: List[Vlan]
    md_level: int
    version: int
    opcode: int
    flags: int
    first_tlv_offset: int
    payload: bytes                       # CFM PDU, common header included
    vni: Optional[int] = None            # set when carried inside VXLAN
    tlvs: List[Tuple[int, bytes]] = field(default_factory=list)
    structural: List[Tuple[str, str]] = field(default_factory=list)
    body: Dict[str, Any] = field(default_factory=dict)
    end_tlv_pos: Optional[int] = None

    @property
    def opcode_name(self) -> str:
        return OPCODE_NAMES.get(self.opcode, "op%d" % self.opcode)

    @property
    def vlan_key(self) -> Tuple[int, ...]:
        return tuple(v.vid for v in self.vlans)

    @property
    def service_key(self) -> Tuple[int, ...]:
        """The identity every per-service state table is keyed on.

        Under VXLAN the VNI is the service and the inner VLAN is the
        customer's, so two tenants reusing VLAN 500 behind different VNIs
        must not share maintenance-association or ring state. NO_VNI
        marks native traffic and cannot collide with a 24-bit VNI.
        """
        return (self.vni if self.vni is not None else NO_VNI,) + \
            self.vlan_key

    def note(self, code: str, detail: str) -> None:
        self.structural.append((code, detail))


class ParseError(Exception):
    pass


def strip_vxlan(raw: bytes) -> Optional[Tuple[int, bytes]]:
    """Return (vni, inner Ethernet frame) if `raw` is VXLAN, else None.

    EVPN-VXLAN carries the customer's CFM inside the tunnel, so a tap on
    the underlay sees none of the service layer without this - the module
    reports a clean service plane while watching an encapsulated one.
    Confirmed as a real blind spot by test, and confirmed reachable
    because Wireshark dissects the inner CFM through the same frame.

    Only VXLAN is decapsulated. EVPN-MPLS is NOT, deliberately: a label
    stack carries no payload type, the pseudowire control word is
    optional, and telling an inner Ethernet frame from any other payload
    needs heuristics this module cannot validate. That is recorded as a
    scoped boundary rather than guessed at.
    """
    if len(raw) < 14:
        return None
    pos = 12
    for _ in range(4):
        if pos + 4 > len(raw):
            return None
        etype = struct.unpack_from("!H", raw, pos)[0]
        if etype in VLAN_ETHERTYPES:
            pos += 4
            continue
        break
    else:
        return None
    if pos + 2 > len(raw):
        return None
    etype = struct.unpack_from("!H", raw, pos)[0]
    pos += 2

    if etype == ETHERTYPE_IPV4:
        if pos + 20 > len(raw):
            return None
        vhl = raw[pos]
        if (vhl >> 4) != 4:
            return None
        ihl = (vhl & 0x0F) * 4
        if ihl < 20 or pos + ihl > len(raw):
            return None
        # A fragmented outer packet cannot be reassembled from one frame.
        if struct.unpack_from("!H", raw, pos + 6)[0] & 0x3FFF:
            return None
        if raw[pos + 9] != IPPROTO_UDP:
            return None
        pos += ihl
    elif etype == ETHERTYPE_IPV6:
        if pos + 40 > len(raw):
            return None
        if raw[pos] >> 4 != 6 or raw[pos + 6] != IPPROTO_UDP:
            return None          # extension headers are not walked here
        pos += 40
    else:
        return None

    if pos + 8 > len(raw):
        return None
    dport = struct.unpack_from("!H", raw, pos + 2)[0]
    if dport != VXLAN_PORT:
        return None
    pos += 8

    if pos + VXLAN_HEADER_LEN > len(raw):
        return None
    flags = raw[pos]
    if not flags & VXLAN_FLAG_VNI_VALID:
        return None
    vni = int.from_bytes(raw[pos + 4:pos + 7], "big")
    inner = raw[pos + VXLAN_HEADER_LEN:]
    if len(inner) < 14:
        return None
    return vni, inner


def parse_ethernet(raw: bytes) -> Optional[Tuple[bytes, bytes, List[Vlan], int, bytes]]:
    """Return (dst, src, vlans, ethertype, payload) if this is a CFM frame."""
    if len(raw) < 14:
        return None
    dst = raw[0:6]
    src = raw[6:12]
    pos = 12
    vlans: List[Vlan] = []
    # Bound the tag stack. Real QinQ is two deep; anything past four is a
    # malformed stack and not worth chasing into an unbounded loop.
    for _ in range(4):
        if pos + 4 > len(raw):
            return None
        etype = struct.unpack_from("!H", raw, pos)[0]
        if etype in VLAN_ETHERTYPES:
            tci = struct.unpack_from("!H", raw, pos + 2)[0]
            vlans.append(Vlan(tpid=etype, vid=tci & 0x0FFF,
                              pcp=(tci >> 13) & 0x7, dei=(tci >> 12) & 0x1))
            pos += 4
            continue
        break
    else:
        return None
    if pos + 2 > len(raw):
        return None
    etype = struct.unpack_from("!H", raw, pos)[0]
    if etype != ETHERTYPE_CFM:
        return None
    return dst, src, vlans, etype, raw[pos + 2:]


def _parse_maid(maid: bytes, frame: CfmFrame) -> Dict[str, Any]:
    """Parse the 48-octet MAID. Bounds defects are recorded, not raised."""
    out: Dict[str, Any] = {
        "md_format": None, "md_name": b"", "ma_format": None, "ma_name": b"",
        "raw": maid,
    }
    if len(maid) < 4:
        frame.note("CFM-005", "MAID field only %d octets" % len(maid))
        return out
    p = 0
    md_fmt = maid[p]
    p += 1
    out["md_format"] = md_fmt
    if md_fmt == 1:
        # Format 1 ("no MD name present") carries no length octet.
        md_len = 0
    else:
        md_len = maid[p]
        p += 1
        if p + md_len > len(maid):
            frame.note("CFM-005",
                       "MD Name Length %d overruns MAID at offset %d"
                       % (md_len, p))
            return out
        if md_len > 43:
            frame.note("CFM-005", "MD Name Length %d exceeds 43" % md_len)
        out["md_name"] = maid[p:p + md_len]
        p += md_len
    out["md_len"] = md_len
    if p + 2 > len(maid):
        frame.note("CFM-005", "MAID truncated before Short MA Name")
        return out
    ma_fmt = maid[p]
    p += 1
    ma_len = maid[p]
    p += 1
    out["ma_format"] = ma_fmt
    out["ma_len"] = ma_len
    if p + ma_len > len(maid):
        frame.note("CFM-005",
                   "Short MA Name Length %d overruns MAID at offset %d"
                   % (ma_len, p))
        return out
    if ma_len > 45:
        frame.note("CFM-005", "Short MA Name Length %d exceeds 45" % ma_len)
    out["ma_name"] = maid[p:p + ma_len]
    return out


def maid_key(parsed: Dict[str, Any]) -> str:
    """Stable printable identity for an MA, used as a state-table key."""
    if parsed.get("md_format") is None:
        return "<unparsed>"
    return "md%d:%s/ma%d:%s" % (
        parsed.get("md_format") or 0, _printable(parsed.get("md_name") or b""),
        parsed.get("ma_format") or 0, _printable(parsed.get("ma_name") or b""),
    )


def _walk_tlvs(frame: CfmFrame, start: int, strict_tail: bool) -> None:
    """TLV chain walk, bounded by real content length.

    The padding trap (carried from oamwatch): Ethernet pads short frames to
    60 octets, so len(payload) is NOT the content length. A run of zeros is
    padding and silent. A trailing run of exactly 4 non-zero octets on a
    frame sitting at the padded minimum is almost certainly a captured FCS,
    not smuggled data; --strict-tail withdraws that allowance.
    """
    payload = frame.payload
    hard_end = len(payload)
    pos = start
    if start > hard_end:
        frame.note("CFM-001",
                   "First TLV Offset %d places TLVs at %d, past %d octets"
                   % (frame.first_tlv_offset, start, hard_end))
        return
    guard = 0
    while True:
        guard += 1
        if guard > 256:
            frame.note("CFM-002", "TLV chain exceeded 256 entries")
            return
        if pos >= hard_end:
            frame.note("CFM-004",
                       "content exhausted at %d with no End TLV" % pos)
            return
        ttype = payload[pos]
        if ttype == TLV_END:
            frame.end_tlv_pos = pos + 1
            break
        if pos + 3 > hard_end:
            frame.note("CFM-003",
                       "TLV type 0x%02x at %d has a truncated header "
                       "(%d octets remain)" % (ttype, pos, hard_end - pos))
            return
        tlen = struct.unpack_from("!H", payload, pos + 1)[0]
        if pos + 3 + tlen > hard_end:
            frame.note("CFM-002",
                       "TLV type %s length %d at offset %d overruns payload "
                       "of %d octets"
                       % (TLV_NAMES.get(ttype, "0x%02x" % ttype), tlen, pos,
                          hard_end))
            return
        frame.tlvs.append((ttype, payload[pos + 3:pos + 3 + tlen]))
        pos += 3 + tlen

    tail = payload[frame.end_tlv_pos:]
    if not tail or not any(tail):
        return                                   # padding, silent
    # On a short frame the padding sits BETWEEN the End TLV and a captured
    # FCS, so the tail is zeros followed by four non-zero octets - it is not
    # four octets long. Allow exactly that shape at the padded minimum with
    # an FCS present (60 + 4 = 64), and nothing else.
    if (not strict_tail) and frame.frame_len == 64 and len(tail) >= 4 \
            and not any(tail[:-4]) and any(tail[-4:]):
        return                                   # probable captured FCS
    nz = sum(1 for b in tail if b)
    frame.note("CFM-009",
               "%d octets after End TLV, %d of them non-zero: %s"
               % (len(tail), nz, hexs(tail, 16)))


def parse_cfm(raw: bytes, index: int, ts: float,
              strict_tail: bool = False,
              vxlan: bool = True) -> Optional[CfmFrame]:
    """Parse one Ethernet frame into a CfmFrame, or None if it is not CFM."""
    vni: Optional[int] = None
    outer_len = len(raw)
    eth = parse_ethernet(raw)
    if eth is None and vxlan:
        tun = strip_vxlan(raw)
        if tun is not None:
            vni, inner = tun
            eth = parse_ethernet(inner)
            if eth is not None:
                raw = inner
    if eth is None:
        return None
    dst, src, vlans, _etype, payload = eth
    if len(payload) < 4:
        return None
    b0 = payload[0]
    frame = CfmFrame(
        index=index, ts=ts, frame_len=len(raw), dst=dst, src=src, vlans=vlans,
        md_level=(b0 >> 5) & 0x7, version=b0 & 0x1F, opcode=payload[1],
        flags=payload[2], first_tlv_offset=payload[3], payload=payload,
        vni=vni,
    )
    # Version 0 is the only value 802.1ag defines - EXCEPT for R-APS,
    # where G.8032 carries its own revision here and version 1 means
    # G.8032v2. Firing on that would raise a structural defect on every
    # frame of every modern ERPS deployment.
    if frame.version != 0 and not (frame.opcode == OP_RAPS
                                   and frame.version == RAPS_VERSION_V2):
        frame.note("CFM-008", "version %d" % frame.version)
    if frame.opcode not in OPCODE_NAMES:
        frame.note("CFM-007", "opcode %d unassigned" % frame.opcode)

    min_body = OPCODE_MIN_BODY.get(frame.opcode)
    if min_body is not None and len(payload) < 4 + min_body:
        frame.note("CFM-006",
                   "%s needs %d body octets, payload carries %d"
                   % (frame.opcode_name, min_body, len(payload) - 4))
    # Only assert the offset where the mandated value is established.
    want_fto = OPCODE_FTO.get(frame.opcode)
    if want_fto is not None and frame.first_tlv_offset != want_fto:
        frame.note("CFM-010",
                   "%s specifies First TLV Offset %d, frame declares %d"
                   % (frame.opcode_name, want_fto, frame.first_tlv_offset))

    _parse_body(frame)
    _walk_tlvs(frame, 4 + frame.first_tlv_offset, strict_tail)
    return frame


def _parse_body(frame: CfmFrame) -> None:
    """Opcode-specific body decode. Never reads past the payload."""
    p = frame.payload
    op = frame.opcode
    avail = len(p) - 4

    if op == OP_CCM:
        if avail < 70:
            return
        seq, mepid_raw = struct.unpack_from("!IH", p, 4)
        # 802.1ag gives MEPID 13 bits; the leading 3 bits are reserved and
        # must be zero. Reading all 16 as the MEP ID (which scapy does)
        # turns a reserved-bit violation into a phantom out-of-range ID.
        mepid = mepid_raw & 0x1FFF
        mepid_reserved = (mepid_raw >> 13) & 0x7
        maid = p[10:58]
        parsed = _parse_maid(maid, frame)
        interval = frame.flags & 0x07
        frame.body = {
            "seq": seq, "mepid": mepid, "mepid_raw": mepid_raw,
            "mepid_reserved": mepid_reserved, "maid": parsed,
            "maid_key": maid_key(parsed), "interval": interval,
            "interval_name": CCM_INTERVAL_NAMES.get(interval, "?"),
            "rdi": bool(frame.flags & 0x80),
        }
    elif op in (OP_LBM, OP_LBR):
        if avail < 4:
            return
        frame.body = {"transaction_id": struct.unpack_from("!I", p, 4)[0]}
    elif op == OP_LTM:
        if avail < 17:
            return
        tid, ttl = struct.unpack_from("!IB", p, 4)
        frame.body = {
            "transaction_id": tid, "ttl": ttl,
            "orig_mac": p[9:15], "target_mac": p[15:21],
            "use_fdb_only": bool(frame.flags & 0x80),
        }
    elif op == OP_LTR:
        if avail < 6:
            return
        tid, ttl, relay = struct.unpack_from("!IBB", p, 4)
        frame.body = {
            "transaction_id": tid, "ttl": ttl, "relay_action": relay,
            "forwarded": bool(frame.flags & 0x40),
            "terminal_mep": bool(frame.flags & 0x20),
        }
    elif op in (OP_AIS, OP_LCK, OP_CSF):
        frame.body = {"period": frame.flags & 0x07}
    elif op == OP_APS:
        if avail < 4:
            return
        o1, o2, o3, o4 = struct.unpack_from("!BBBB", p, 4)
        req = (o1 >> 4) & 0x0F
        prot = o1 & 0x0F
        frame.body = {
            "request": req,
            "request_name": APS_REQUEST_NAMES.get(req, "reserved(%d)" % req),
            "protection_type": prot,
            "protection_bits": "".join(
                name for name, mask in APS_PROT_BITS if prot & mask) or "-",
            "requested_signal": o2, "bridged_signal": o3,
            "requested_signal_name": APS_SIGNAL_NAMES.get(
                o2, "unassigned(%d)" % o2),
            "bridged_signal_name": APS_SIGNAL_NAMES.get(
                o3, "unassigned(%d)" % o3),
            # Bridge type is ONE bit. Reading octet 4's top two bits as a
            # 2-bit field reports 0 as 0 but 0x40 as 1 and 0xC0 as 3, none
            # of which is the bridge type.
            "bridge_type": 1 if o4 & APS_BRIDGE_TYPE else 0,
            "octet4_reserved": o4 & APS_OCTET4_RESERVED,
        }
    elif op == OP_RAPS:
        if avail < RAPS_BODY_LEN:
            return
        b0, status = struct.unpack_from("!BB", p, 4)
        req = (b0 >> 4) & 0x0F
        sub = b0 & 0x0F
        # The status octet's layout depends on the G.8032 revision: BPR
        # only exists from v2, and in v1 that bit is reserved. Reading it
        # as BPR regardless would both invent a BPR on v1 frames and miss
        # the reserved-bit violation that setting it actually is.
        is_v2 = frame.version >= RAPS_VERSION_V2
        resv_mask = RAPS_STATUS_RESERVED_BY_VERSION.get(
            frame.version, RAPS_STATUS_RESERVED_BY_VERSION[1])
        frame.body = {
            "request": req,
            "request_name": RAPS_REQUEST_NAMES.get(req,
                                                   "reserved(%d)" % req),
            "sub_code": sub,
            "status": status,
            "rb": bool(status & RAPS_STATUS_RB),
            "dnf": bool(status & RAPS_STATUS_DNF),
            "bpr": bool(status & RAPS_STATUS_BPR) if is_v2 else False,
            "status_reserved": status & resv_mask,
            "revision": frame.version,
            "revision_name": RAPS_REVISION_NAMES.get(
                frame.version, "unknown(v%d)" % frame.version),
            "node_id": p[6:12],
            "reserved": p[12:36],
        }
    elif op in (OP_LMM, OP_LMR):
        if avail < 12:
            return
        txf, rxf, txb = struct.unpack_from("!III", p, 4)
        frame.body = {"tx_fcf": txf, "rx_fcf": rxf, "tx_fcb": txb,
                      "counters": {"TxFCf": txf, "RxFCf": rxf,
                                   "TxFCb": txb}}
    elif op in (OP_DMM, OP_DMR, OP_1DM):
        # PTP-style timestamps: 48-bit seconds, 32-bit nanoseconds.
        # 1DM carries the first pair only; DMM/DMR carry all four.
        need = 16 if op == OP_1DM else 32
        if avail < need:
            return
        # Each timestamp is 8 octets: 32-bit seconds then 32-bit
        # nanoseconds. Four of them fill DMM/DMR's 32-octet body and two
        # fill 1DM's 16 - which is what fixes the stride at 8 rather than
        # the 10 a 48-bit seconds field would need. Verified against
        # Wireshark's decode of a crafted frame.
        stamps: Dict[str, Any] = {}
        names = ("TxTimeStampf", "RxTimeStampf") if op == OP_1DM else \
            ("TxTimeStampf", "RxTimeStampf", "TxTimeStampb", "RxTimeStampb")
        for i, nm in enumerate(names):
            secs, nanos = struct.unpack_from("!II", p, 4 + i * 8)
            stamps[nm] = {"seconds": secs, "nanos": nanos,
                          "value": secs + nanos / 1e9}
        frame.body = {"timestamps": stamps}
    elif op in (OP_SLM, OP_SLR, OP_1SL):
        if avail < 16:
            return
        src_mep, rsp_mep, test_id, txfcf, txfcb = struct.unpack_from(
            "!HHIII", p, 4)
        frame.body = {
            "src_mep_id": src_mep & 0x1FFF,
            # Reserved in SLM and 1SL; the responder's MEP ID in SLR.
            "rsp_mep_id": (rsp_mep & 0x1FFF) if op == OP_SLR else None,
            "test_id": test_id,
            "tx_fcf": txfcf,
            # Reserved in SLM and 1SL; valid in SLR.
            "tx_fcb": txfcb if op == OP_SLR else None,
            "counters": ({"TxFCf": txfcf, "TxFCb": txfcb} if op == OP_SLR
                         else {"TxFCf": txfcf}),
        }
    elif op == OP_TST:
        if avail < 4:
            return
        frame.body = {"seq": struct.unpack_from("!I", p, 4)[0]}
    elif op in OUI_OPCODES:
        if avail < 4:
            return
        frame.body = {
            "oui": p[4:7],
            "oui_str": ":".join("%02x" % b for b in p[4:7]),
            "sub_opcode": p[7],
        }
    elif op == OP_GNM:
        if avail < 1:
            return
        frame.body = {"sub_opcode": p[4]}
    elif op in (OP_RFM, OP_SFM):
        if avail < 4:
            return
        frame.body = {"transaction_id": struct.unpack_from("!I", p, 4)[0]}


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass
class Finding:
    code: str
    key: str
    detail: str
    first_index: int
    first_ts: float
    last_ts: float
    count: int = 1
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def spec(self) -> Spec:
        return REGISTRY[self.code]

    def to_dict(self) -> Dict[str, Any]:
        s = self.spec
        out: Dict[str, Any] = {
            "code": self.code,
            "title": s.title,
            "severity": s.severity,
            "class": s.cls,
            "class_name": CLASS_NAMES[s.cls],
            "confidence": s.confidence,
            "summary": s.summary,
            "context": self.key,
            "detail": self.detail,
            "count": self.count,
            "first_frame": self.first_index,
            "first_seen": round(self.first_ts, 6),
            "last_seen": round(self.last_ts, 6),
        }
        if s.cves:
            out["cves"] = list(s.cves)
        if s.caveat:
            out["caveat"] = s.caveat
        if self.evidence:
            out["evidence"] = self.evidence
        return out


@dataclass
class Config:
    strict_tail: bool = False
    vxlan: bool = True
    md_ceiling: Optional[int] = None
    rate_max: float = 50.0            # aggregate CFM frames/sec
    rate_window: float = 1.0
    src_rate_max: float = 30.0        # per-source frames/sec for CFM-122/141
    src_rate_window: float = 2.0
    src_rate_min_frames: int = 40
    lbm_burst: int = 20               # LBMs from one source
    lbm_window: float = 5.0
    ltm_sweep_min: int = 3            # ascending TTLs to call it a sweep
    ltm_window: float = 10.0
    aps_churn_min: int = 3            # state changes inside the window
    aps_churn_window: float = 30.0
    data_tlv_max: int = 1000
    settle_frames: int = 3            # CCMs before an MA counts as settled
    health_window: float = 3.5        # server-layer CCM freshness
    ccm_overrate_factor: float = 2.0
    ccm_overrate_samples: int = 5
    # ERPS / G.8032
    rings: Tuple[Ring, ...] = ()
    raps_rate_max: float = 10.0       # R-APS frames/sec from one source
    raps_rate_window: float = 2.0
    raps_churn_min: int = 3           # state changes inside the window
    raps_churn_window: float = 30.0
    raps_flush_burst: int = 3         # Event/Flush messages
    raps_flush_window: float = 10.0
    raps_idle_min: int = 5            # NR frames with no RB before CFM-194
    rb_window: float = 20.0           # concurrency window for two RB claims
    # Separate from rb_window on purpose. That one asks "are two nodes
    # claiming the block at the same time" (CFM-193); this one asks "is
    # the block we saw now stale" (CFM-194/206). Same default, different
    # question, so they must be tunable apart.
    rb_stale: float = 20.0
    ccm_loss_misses: float = 3.0      # G.8032 trigger: three missed CCMs
    # Y.1731 measurement and maintenance
    tst_burst: int = 20              # TST frames from one source
    tst_window: float = 5.0
    # E-LMI
    evcs: Tuple[Evc, ...] = ()

    def evc_for(self, reference: int) -> Optional[Evc]:
        for evc in self.evcs:
            if evc.reference == reference:
                return evc
        return None

    def ring_for(self, vlan: Tuple[int, ...]) -> Optional[Ring]:
        for ring in self.rings:
            if ring.vlan == vlan:
                return ring
        return None

    def ring_named(self, label: str) -> Optional[Ring]:
        for ring in self.rings:
            if ring.name() == label:
                return ring
        return None

    def sub_rings_of(self, ring: Ring) -> Tuple[Ring, ...]:
        return tuple(r for r in self.rings
                     if r.is_sub() and r.parent == ring.name())

    def interconnects_for(self, ring: Ring) -> Tuple[bytes, ...]:
        """Nodes that may legitimately propagate a change onto `ring`.

        For a parent ring that is every attached sub-ring's interconnection
        node set, plus any declared on the ring itself. For a sub-ring it
        is its own.
        """
        macs = set(ring.interconnect)
        for sub in self.sub_rings_of(ring):
            macs |= set(sub.interconnect)
        return tuple(sorted(macs))


# --------------------------------------------------------------------------
# Detection engine
# --------------------------------------------------------------------------

class Engine:
    """Stateful passive CFM analyser.

    Feed it frames in capture order. It never transmits and never mutates
    anything outside its own state tables.
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.cfg = config or Config()
        self.findings: Dict[Tuple[str, str], Finding] = {}
        self.frames_total = 0
        self.frames_cfm = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

        # state tables
        self.ma: Dict[Tuple[Any, int, str], Dict[str, Any]] = {}
        self.maid_levels: Dict[str, set] = defaultdict(set)
        self.ma_by_domain: Dict[Tuple[Any, int], str] = {}
        self.mep: Dict[Tuple[Any, int, str, int], Dict[str, Any]] = {}
        self.ccm_macs: Dict[Any, set] = defaultdict(set)
        self.ccm_health: Dict[Tuple[Any, int], float] = {}
        self.ais_recent: Dict[Any, float] = {}
        self.rdi_recent: Dict[Any, float] = {}
        self.elmi_seq: Dict[bytes, int] = {}
        self.inv_elmi: Dict[int, Dict[str, Any]] = {}
        self.aps_groups: Dict[Tuple[Any, int], Dict[str, Any]] = {}
        self.aps_inventory: Dict[Tuple[Any, int], Dict[str, Any]] = {}
        self.lbm_hist: Dict[bytes, deque] = defaultdict(deque)
        self.ltm_hist: Dict[bytes, deque] = defaultdict(deque)
        self.rate_hist: deque = deque()
        self.src_hist: Dict[bytes, deque] = defaultdict(deque)
        self.src_clean: Dict[bytes, int] = defaultdict(int)

        # ERPS / G.8032 ring state
        self.raps_rings: Dict[Tuple[int, ...], Dict[str, Any]] = {}
        self.raps_hist: Dict[bytes, deque] = defaultdict(deque)
        self.flush_hist: Dict[Tuple[int, ...], deque] = defaultdict(deque)
        self.ring_ccm_quiet: Dict[Tuple[Any, int, str, int], bool] = {}

        # Y.1731 measurement and maintenance state
        self.meas_counters: Dict[Tuple[Any, bytes, int, str], int] = {}
        self.slm_tests: Dict[Tuple[Any, int], float] = {}
        self.tst_hist: Dict[bytes, deque] = defaultdict(deque)
        self.inv_meas: Dict[int, Dict[str, Any]] = {}
        self.inv_vni: Dict[int, Dict[str, Any]] = {}

        # posture inventory
        self.inv_levels: Dict[int, set] = defaultdict(set)
        self.inv_meps: Dict[Tuple[int, str, int], Dict[str, Any]] = {}
        self.inv_y1731: Dict[int, int] = defaultdict(int)
        self.inv_vlans: Dict[Tuple[int, ...], int] = defaultdict(int)
        self.inv_opcodes: Dict[int, int] = defaultdict(int)

    # -- emission ----------------------------------------------------------

    def emit(self, code: str, key: str, detail: str, frame: CfmFrame,
             evidence: Optional[Dict[str, Any]] = None) -> None:
        if code not in REGISTRY:
            raise KeyError("unregistered finding code %s" % code)
        k = (code, key)
        existing = self.findings.get(k)
        if existing is None:
            self.findings[k] = Finding(
                code=code, key=key, detail=detail, first_index=frame.index,
                first_ts=frame.ts, last_ts=frame.ts,
                evidence=dict(evidence or {}),
            )
        else:
            existing.count += 1
            existing.last_ts = frame.ts

    def emit_static(self, code: str, key: str, detail: str, ts: float,
                    evidence: Optional[Dict[str, Any]] = None) -> None:
        """Emit outside frame context (posture roll-up at finalize)."""
        k = (code, key)
        if k in self.findings:
            self.findings[k].count += 1
            self.findings[k].last_ts = ts
            return
        self.findings[k] = Finding(
            code=code, key=key, detail=detail, first_index=-1, first_ts=ts,
            last_ts=ts, evidence=dict(evidence or {}),
        )

    # -- ingest ------------------------------------------------------------

    def feed_raw(self, raw: bytes, index: int, ts: float) -> Optional[CfmFrame]:
        self.frames_total += 1
        frame = parse_cfm(raw, index, ts, strict_tail=self.cfg.strict_tail,
                          vxlan=self.cfg.vxlan)
        if frame is None:
            elmi = parse_elmi(raw, index, ts)
            if elmi is not None:
                self.feed_elmi(elmi)
            return None
        self.feed(frame)
        return frame

    def feed(self, frame: CfmFrame) -> None:
        self.frames_cfm += 1
        if self.first_ts is None:
            self.first_ts = frame.ts
        self.last_ts = frame.ts

        self._structural(frame)
        self._levels(frame)
        self._inventory(frame)

        op = frame.opcode
        if op == OP_CCM:
            self._ccm(frame)
        elif op in (OP_LBM, OP_LBR):
            self._loopback(frame)
        elif op == OP_LTM:
            self._linktrace_request(frame)
        elif op == OP_LTR:
            self._linktrace_reply(frame)
        elif op in (OP_AIS, OP_LCK, OP_CSF):
            self._fault_management(frame)
        elif op == OP_APS:
            self._aps(frame)
        elif op == OP_RAPS:
            self._raps(frame)
        elif op in MEASUREMENT_OPCODES:
            self._measurement(frame)
        elif op == OP_TST:
            self._tst(frame)
        elif op in OUI_OPCODES:
            self._oui_opcode(frame)

        self._ring_ccm_watch(frame)
        self._rates(frame)

    # -- Class A -----------------------------------------------------------

    _BOUNDS_CODES = ("CFM-001", "CFM-002", "CFM-003", "CFM-005", "CFM-006")

    def _structural(self, frame: CfmFrame) -> None:
        for code, detail in frame.structural:
            self.emit(code, "%s/%s" % (mac_str(frame.src), frame.opcode_name),
                      detail, frame,
                      {"src": mac_str(frame.src), "opcode": frame.opcode_name,
                       "md_level": frame.md_level,
                       "payload": hexs(frame.payload, 48)})
        hits = sorted({c for c, _ in frame.structural} & set(self._BOUNDS_CODES))
        if hits:
            self.emit("CFM-140", mac_str(frame.src),
                      "bounds violation(s) %s in a %s frame from %s"
                      % (",".join(hits), frame.opcode_name,
                         mac_str(frame.src)),
                      frame,
                      {"src": mac_str(frame.src), "triggers": hits,
                       "opcode": frame.opcode_name,
                       "frame_len": frame.frame_len,
                       "payload": hexs(frame.payload, 48)})

    # -- Class B -----------------------------------------------------------

    def _levels(self, frame: CfmFrame) -> None:
        dst = frame.dst
        if tuple(dst[0:5]) == CFM_GROUP_PREFIX and (dst[5] & 0xF0) == 0x30:
            low = dst[5] & 0x0F
            expect = low & 0x07
            klass = 2 if low >= 8 else 1
            if expect != frame.md_level:
                self.emit("CFM-020",
                          "%s/%s" % (mac_str(frame.src), mac_str(dst)),
                          "header MD level %d, class %d group address "
                          "encodes level %d"
                          % (frame.md_level, klass, expect), frame,
                          {"src": mac_str(frame.src), "dst": mac_str(dst),
                           "header_level": frame.md_level,
                           "address_level": expect})
        elif frame.opcode == OP_CCM:
            self.emit("CFM-024", mac_str(frame.dst),
                      "CCM addressed to %s, outside the CFM group"
                      % mac_str(frame.dst), frame,
                      {"src": mac_str(frame.src), "dst": mac_str(frame.dst),
                       "md_level": frame.md_level})

        ceiling = self.cfg.md_ceiling
        if ceiling is not None and frame.md_level > ceiling:
            self.emit("CFM-021", "level%d" % frame.md_level,
                      "%s at MD level %d, above the configured ceiling %d"
                      % (frame.opcode_name, frame.md_level, ceiling), frame,
                      {"src": mac_str(frame.src), "md_level": frame.md_level,
                       "ceiling": ceiling})

    # -- inventory ---------------------------------------------------------

    def _inventory(self, frame: CfmFrame) -> None:
        self.inv_levels[frame.md_level].add(frame.vlan_key)
        self.inv_vlans[frame.vlan_key] += 1
        self.inv_opcodes[frame.opcode] += 1
        if frame.opcode in Y1731_OPCODES:
            self.inv_y1731[frame.opcode] += 1
        if frame.vni is not None:
            rec = self.inv_vni.setdefault(
                frame.vni, {"vni": frame.vni, "frames": 0, "vlans": set()})
            rec["frames"] += 1
            rec["vlans"].add(frame.vlan_key)

    # -- Class C -----------------------------------------------------------

    def _ccm(self, frame: CfmFrame) -> None:
        body = frame.body
        if not body:
            return
        mepid = body["mepid"]
        mk = body["maid_key"]
        interval = body["interval"]
        vkey = frame.service_key
        src = frame.src

        if body["rdi"]:
            self.rdi_recent[vkey] = frame.ts
            self.emit("CFM-044", "%s/mep%d" % (mk, mepid),
                      "RDI asserted by MEP %d (%s)" % (mepid, mac_str(src)),
                      frame, {"mepid": mepid, "src": mac_str(src),
                              "maid": mk})
        if interval == 0:
            self.emit("CFM-043", "%s/mep%d" % (mk, mepid),
                      "CCM interval field is 0 (invalid) from MEP %d" % mepid,
                      frame, {"mepid": mepid, "src": mac_str(src)})
        elif interval in (1, 2):
            self.emit("CFM-047", "%s/mep%d" % (mk, mepid),
                      "MEP %d declares a %s CCM interval"
                      % (mepid, CCM_INTERVAL_NAMES[interval]), frame,
                      {"mepid": mepid, "interval": CCM_INTERVAL_NAMES[interval],
                       "src": mac_str(src)})
        reserved = body.get("mepid_reserved", 0)
        if mepid < MEPID_MIN or reserved:
            why = []
            if mepid < MEPID_MIN:
                why.append("MEP ID 0 is outside the valid range 1..%d"
                           % MEPID_MAX)
            if reserved:
                # %b is not a Python format character. oamwatch shipped a
                # "0b%02b" that crashed its parser on reserved values and
                # only the bit-flip fuzz tier caught it. Use format().
                why.append("reserved bits 0b%s set in the MEP ID field "
                           "(raw 0x%04x)"
                           % (format(reserved, "03b"), body["mepid_raw"]))
            self.emit("CFM-049", "mep%d" % mepid, "; ".join(why), frame,
                      {"mepid": mepid, "mepid_raw": body["mepid_raw"],
                       "reserved_bits": reserved, "src": mac_str(src)})

        maid = body["maid"]
        mdf, maf = maid.get("md_format"), maid.get("ma_format")
        bad = []
        if mdf is not None and mdf not in MD_NAME_FORMATS:
            bad.append("MD name format %d" % mdf)
        elif mdf == 0:
            bad.append("MD name format 0 (reserved)")
        if maf is not None and maf not in MA_NAME_FORMATS and not (32 <= maf <= 63):
            bad.append("Short MA name format %d" % maf)
        elif maf == 0:
            bad.append("Short MA name format 0 (reserved)")
        if bad:
            self.emit("CFM-048", mk, "; ".join(bad), frame,
                      {"md_format": mdf, "ma_format": maf,
                       "src": mac_str(src)})

        # MAID at more than one MD level
        self.maid_levels[mk].add(frame.md_level)
        if len(self.maid_levels[mk]) > 1:
            self.emit("CFM-022", mk,
                      "MAID %s seen at MD levels %s"
                      % (mk, sorted(self.maid_levels[mk])), frame,
                      {"maid": mk, "levels": sorted(self.maid_levels[mk]),
                       "src": mac_str(src)})

        # One MAID per (VLAN, level)
        dom = (vkey, frame.md_level)
        known = self.ma_by_domain.get(dom)
        if known is None:
            self.ma_by_domain[dom] = mk
        elif known != mk:
            self.emit("CFM-040", "%s/level%d" % (str(vkey), frame.md_level),
                      "CCM carries MAID %s where %s was established"
                      % (mk, known), frame,
                      {"observed_maid": mk, "established_maid": known,
                       "vlan": list(frame.vlan_key), "md_level": frame.md_level,
                       "src": mac_str(src)})

        akey = (vkey, frame.md_level, mk)
        assoc = self.ma.get(akey)
        if assoc is None:
            assoc = {"count": 0, "mepids": set(), "settled": False}
            self.ma[akey] = assoc
        assoc["count"] += 1
        settled = assoc["settled"]
        if mepid not in assoc["mepids"]:
            if settled:
                self.emit("CFM-045", "%s/mep%d" % (mk, mepid),
                          "MEP %d (%s) joined settled association %s"
                          % (mepid, mac_str(src), mk), frame,
                          {"mepid": mepid, "src": mac_str(src), "maid": mk})
            assoc["mepids"].add(mepid)
        if assoc["count"] >= self.cfg.settle_frames:
            assoc["settled"] = True

        self.ccm_macs[vkey].add(src)
        self.ccm_health[(vkey, frame.md_level)] = frame.ts

        mkey = (vkey, frame.md_level, mk, mepid)
        st = self.mep.get(mkey)
        if st is None:
            self.mep[mkey] = {
                "mac": src, "macs": {src}, "interval": interval,
                "last_ts": frame.ts, "count": 1, "fast": deque(),
            }
        else:
            # A MEP ID arriving from an unseen MAC is a move. The same MEP
            # ID arriving from a MAC that is already on record, while a
            # different one is current, means two stations are sourcing it
            # concurrently - that is the duplicate, and it is the condition
            # that drives an unexpected-MEP defect at every receiver.
            if src not in st["macs"]:
                st["macs"].add(src)
                self.emit("CFM-046", "%s/mep%d" % (mk, mepid),
                          "MEP %d moved from %s to %s"
                          % (mepid, mac_str(st["mac"]), mac_str(src)), frame,
                          {"mepid": mepid, "was": mac_str(st["mac"]),
                           "now": mac_str(src), "maid": mk})
                st["mac"] = src
            elif src != st["mac"]:
                self.emit("CFM-041", "%s/mep%d" % (mk, mepid),
                          "MEP ID %d sourced concurrently from %s and %s "
                          "inside %s"
                          % (mepid, mac_str(st["mac"]), mac_str(src), mk),
                          frame,
                          {"mepid": mepid, "maid": mk,
                           "macs": sorted(mac_str(m) for m in st["macs"])})
                st["mac"] = src
            if interval != st["interval"]:
                self.emit("CFM-042", "%s/mep%d" % (mk, mepid),
                          "MEP %d interval changed %s -> %s"
                          % (mepid, CCM_INTERVAL_NAMES.get(st["interval"], "?"),
                             CCM_INTERVAL_NAMES.get(interval, "?")), frame,
                          {"mepid": mepid, "was": st["interval"],
                           "now": interval, "maid": mk})
                st["interval"] = interval
            gap = frame.ts - st["last_ts"]
            nominal = CCM_INTERVAL_SECONDS.get(interval)
            if nominal and gap >= 0:
                if gap * self.cfg.ccm_overrate_factor < nominal:
                    st["fast"].append(frame.ts)
                    if len(st["fast"]) == self.cfg.ccm_overrate_samples:
                        self.emit("CFM-121", "%s/mep%d" % (mk, mepid),
                                  "MEP %d declares %s but %d consecutive "
                                  "arrivals were at or under %.4fs"
                                  % (mepid, CCM_INTERVAL_NAMES.get(interval, "?"),
                                     len(st["fast"]), gap), frame,
                                  {"mepid": mepid, "declared": interval,
                                   "observed_gap": round(gap, 6), "maid": mk})
                else:
                    st["fast"].clear()
            st["last_ts"] = frame.ts
            st["count"] += 1

        self.inv_meps[(frame.md_level, mk, mepid)] = {
            "md_level": frame.md_level, "maid": mk, "mepid": mepid,
            "mac": mac_str(src), "interval": CCM_INTERVAL_NAMES.get(interval, "?"),
            "vlan": list(frame.vlan_key),
        }

    # -- Class F -----------------------------------------------------------

    def _loopback(self, frame: CfmFrame) -> None:
        src = frame.src
        if frame.opcode == OP_LBM:
            self.emit("CFM-100", mac_str(src),
                      "LBM from %s at MD level %d to %s"
                      % (mac_str(src), frame.md_level, mac_str(frame.dst)),
                      frame, {"src": mac_str(src), "dst": mac_str(frame.dst),
                              "md_level": frame.md_level})
            hist = self.lbm_hist[src]
            hist.append(frame.ts)
            while hist and frame.ts - hist[0] > self.cfg.lbm_window:
                hist.popleft()
            if len(hist) >= self.cfg.lbm_burst:
                self.emit("CFM-101", mac_str(src),
                          "%d LBMs from %s within %.1fs"
                          % (len(hist), mac_str(src), self.cfg.lbm_window),
                          frame, {"src": mac_str(src), "count": len(hist),
                                  "window_s": self.cfg.lbm_window})
        for ttype, val in frame.tlvs:
            if ttype == TLV_DATA and len(val) > self.cfg.data_tlv_max:
                self.emit("CFM-105", mac_str(src),
                          "%s carries a %d-octet Data TLV (threshold %d)"
                          % (frame.opcode_name, len(val),
                             self.cfg.data_tlv_max), frame,
                          {"src": mac_str(src), "data_tlv_len": len(val),
                           "opcode": frame.opcode_name})

    def _linktrace_request(self, frame: CfmFrame) -> None:
        src = frame.src
        body = frame.body
        ttl = body.get("ttl")
        self.emit("CFM-102", mac_str(src),
                  "LTM from %s at MD level %d, TTL %s, target %s"
                  % (mac_str(src), frame.md_level, ttl,
                     mac_str(body["target_mac"]) if body.get("target_mac")
                     else "?"), frame,
                  {"src": mac_str(src), "md_level": frame.md_level,
                   "ttl": ttl})
        if ttl in (0, 255):
            self.emit("CFM-106", mac_str(src),
                      "LTM from %s carries TTL %d" % (mac_str(src), ttl),
                      frame, {"src": mac_str(src), "ttl": ttl})
        if ttl is None:
            return
        hist = self.ltm_hist[src]
        hist.append((frame.ts, ttl))
        while hist and frame.ts - hist[0][0] > self.cfg.ltm_window:
            hist.popleft()
        # An ascending TTL run inside the window is hop-by-hop mapping.
        run = 1
        best = 1
        for i in range(1, len(hist)):
            if hist[i][1] > hist[i - 1][1]:
                run += 1
                best = max(best, run)
            else:
                run = 1
        if best >= self.cfg.ltm_sweep_min:
            self.emit("CFM-103", mac_str(src),
                      "%d ascending-TTL linktraces from %s within %.0fs "
                      "(TTLs %s)"
                      % (best, mac_str(src), self.cfg.ltm_window,
                         [t for _, t in hist]), frame,
                      {"src": mac_str(src), "run": best,
                       "ttls": [t for _, t in hist]})

    def _linktrace_reply(self, frame: CfmFrame) -> None:
        disclosed = [TLV_NAMES.get(t, "0x%02x" % t) for t, _ in frame.tlvs
                     if t in (TLV_REPLY_INGRESS, TLV_REPLY_EGRESS,
                              TLV_LTR_EGRESS_ID)]
        if disclosed:
            self.emit("CFM-104", mac_str(frame.src),
                      "LTR from %s discloses %s"
                      % (mac_str(frame.src), ", ".join(sorted(set(disclosed)))),
                      frame, {"src": mac_str(frame.src),
                              "tlvs": sorted(set(disclosed)),
                              "md_level": frame.md_level})

    # -- Class D -----------------------------------------------------------

    def _fault_management(self, frame: CfmFrame) -> None:
        op = frame.opcode
        vkey = frame.service_key
        period = frame.body.get("period", 0)
        name = frame.opcode_name
        src = frame.src

        if op == OP_AIS:
            self.emit("CFM-060", "%s/level%d" % (str(vkey), frame.md_level),
                      "AIS from %s at MD level %d"
                      % (mac_str(src), frame.md_level), frame,
                      {"src": mac_str(src), "md_level": frame.md_level,
                       "vlan": list(frame.vlan_key)})
            self.ais_recent[vkey] = frame.ts
        elif op == OP_LCK:
            self.emit("CFM-062", "%s/level%d" % (str(vkey), frame.md_level),
                      "LCK from %s at MD level %d"
                      % (mac_str(src), frame.md_level), frame,
                      {"src": mac_str(src), "md_level": frame.md_level})
        else:
            self.emit("CFM-064", "%s/level%d" % (str(vkey), frame.md_level),
                      "CSF from %s at MD level %d"
                      % (mac_str(src), frame.md_level), frame,
                      {"src": mac_str(src), "md_level": frame.md_level})

        if op in (OP_AIS, OP_LCK) and period not in (4, 6):
            # Y.1731 defines 1s (4) and 1min (6) for AIS and LCK.
            self.emit("CFM-065", "%s/%s" % (mac_str(src), name),
                      "%s period field %d is not a defined AIS/LCK period"
                      % (name, period), frame,
                      {"src": mac_str(src), "period": period,
                       "opcode": name})

        if op != OP_AIS:
            return

        known = self.ccm_macs.get(vkey)
        if known and src not in known:
            self.emit("CFM-061", "%s/%s" % (str(vkey), mac_str(src)),
                      "AIS injected by %s, which has never sourced a CCM on "
                      "this service" % mac_str(src), frame,
                      {"src": mac_str(src), "vlan": list(frame.vlan_key),
                       "ccm_sources": sorted(mac_str(m) for m in known)})

        # AIS asserts a server-layer fault. If CCMs below this level are
        # still arriving on schedule, the asserted fault is not on the wire.
        healthy = [(lvl, ts) for (vk, lvl), ts in self.ccm_health.items()
                   if vk == vkey and lvl < frame.md_level
                   and frame.ts - ts <= self.cfg.health_window]
        if healthy:
            lvls = sorted(l for l, _ in healthy)
            self.emit("CFM-063", "%s/level%d" % (str(vkey), frame.md_level),
                      "AIS at MD level %d while CCMs at level(s) %s stayed "
                      "live within %.1fs"
                      % (frame.md_level, lvls, self.cfg.health_window), frame,
                      {"src": mac_str(src), "ais_level": frame.md_level,
                       "healthy_levels": lvls, "vlan": list(frame.vlan_key)})

    # -- Class E -----------------------------------------------------------

    def _aps(self, frame: CfmFrame) -> None:
        body = frame.body
        if not body:
            return
        vkey = frame.service_key
        gkey = (vkey, frame.md_level)
        gname = "%s/level%d" % (str(vkey), frame.md_level)
        req = body["request"]
        src = frame.src

        self.emit("CFM-080", gname,
                  "APS on %s, request %s from %s"
                  % (gname, body["request_name"], mac_str(src)), frame,
                  {"src": mac_str(src), "request": body["request_name"],
                   "protection_bits": body["protection_bits"],
                   "bridge_type": body["bridge_type"],
                   "requested_signal": body["requested_signal_name"],
                   "bridged_signal": body["bridged_signal_name"],
                   "md_level": frame.md_level, "vlan": list(frame.vlan_key)})

        inv = self.aps_inventory.get(gkey)
        if inv is None:
            inv = {"nodes": {}, "requests": set(), "bridge_types": set()}
            self.aps_inventory[gkey] = inv
        inv["nodes"].setdefault(src, set()).add(body["protection_bits"])
        inv["requests"].add(body["request_name"])
        inv["bridge_types"].add(body["bridge_type"])

        # G.8031 signals the protection type to the far end precisely so a
        # mismatch can be detected. Compared as advertised bit sets, which
        # needs no knowledge of each bit's polarity.
        advertised = {m: sorted(v) for m, v in inv["nodes"].items()}
        distinct = {tuple(sorted(v)) for v in advertised.values()}
        if len(distinct) > 1:
            self.emit("CFM-090", gname,
                      "protection type differs across %s: %s"
                      % (gname,
                         "; ".join("%s advertises %s"
                                   % (mac_str(m), "/".join(v) or "-")
                                   for m, v in sorted(
                                       advertised.items()))), frame,
                      {"group": gname,
                       "advertised": {mac_str(m): v
                                      for m, v in advertised.items()}})

        grp = self.aps_groups.get(gkey)
        if grp is None:
            grp = {"macs": {src}, "last_req": req, "changes": deque()}
            self.aps_groups[gkey] = grp
        else:
            if src not in grp["macs"]:
                grp["macs"].add(src)
                self.emit("CFM-084", gname,
                          "APS for %s now sourced from %s; previously %s"
                          % (gname, mac_str(src),
                             ", ".join(sorted(mac_str(m) for m in grp["macs"]
                                              if m != src))), frame,
                          {"src": mac_str(src), "group": gname,
                           "macs": sorted(mac_str(m) for m in grp["macs"])})
            if req != grp["last_req"]:
                grp["changes"].append(frame.ts)
                grp["last_req"] = req
                while (grp["changes"] and
                       frame.ts - grp["changes"][0] > self.cfg.aps_churn_window):
                    grp["changes"].popleft()
                if len(grp["changes"]) >= self.cfg.aps_churn_min:
                    self.emit("CFM-085", gname,
                              "%d APS state changes on %s within %.0fs"
                              % (len(grp["changes"]), gname,
                                 self.cfg.aps_churn_window), frame,
                              {"group": gname,
                               "changes": len(grp["changes"]),
                               "window_s": self.cfg.aps_churn_window})

        if req in APS_RESERVED_REQUESTS:
            self.emit("CFM-086", gname,
                      "APS request code %d is reserved by G.8031" % req,
                      frame, {"src": mac_str(src), "request": req,
                              "kind": "reserved"})
        elif req in APS_DEPRECATED_REQUESTS:
            self.emit("CFM-086", gname,
                      "APS request code %d was assigned by an earlier "
                      "G.8031 revision and is deprecated" % req, frame,
                      {"src": mac_str(src), "request": req,
                       "kind": "deprecated"})

        # ---- structural conformance ------------------------------------
        if body["octet4_reserved"]:
            self.emit("CFM-092", gname,
                      "APS from %s carries reserved bits 0x%02x in the "
                      "body's last octet"
                      % (mac_str(src), body["octet4_reserved"]), frame,
                      {"src": mac_str(src),
                       "reserved": body["octet4_reserved"]})
        if body["requested_signal"] != body["bridged_signal"]:
            self.emit("CFM-091", gname,
                      "APS from %s requests the %s signal while bridging "
                      "the %s signal"
                      % (mac_str(src), body["requested_signal_name"],
                         body["bridged_signal_name"]), frame,
                      {"src": mac_str(src),
                       "requested": body["requested_signal_name"],
                       "bridged": body["bridged_signal_name"],
                       "group": gname})

        if req == APS_FS:
            self.emit("CFM-081", gname,
                      "Forced Switch requested on %s by %s"
                      % (gname, mac_str(src)), frame,
                      {"src": mac_str(src), "group": gname})
        elif req == APS_MS:
            self.emit("CFM-082", gname,
                      "Manual Switch requested on %s by %s"
                      % (gname, mac_str(src)), frame,
                      {"src": mac_str(src), "group": gname})
        elif req == APS_LO:
            self.emit("CFM-087", gname,
                      "Lockout of protection requested on %s by %s"
                      % (gname, mac_str(src)), frame,
                      {"src": mac_str(src), "group": gname})
        elif req == APS_SD:
            self.emit("CFM-089", gname,
                      "Signal Degrade requested on %s by %s"
                      % (gname, mac_str(src)), frame,
                      {"src": mac_str(src), "group": gname})
        elif req == APS_SF_P:
            # SF-P is a failure of the PROTECTION entity. The working path
            # is still carrying traffic, so healthy working-path CCMs are
            # what this request implies - not evidence against it. Running
            # it through the CFM-083 uncorroborated test raises a CRITICAL
            # forged-switch alarm on every genuine protection failure.
            self.emit("CFM-088", gname,
                      "SF-P on %s from %s: the protection path has failed, "
                      "so the service is running unprotected"
                      % (gname, mac_str(src)), frame,
                      {"src": mac_str(src), "group": gname,
                       "effect": "service unprotected until cleared"})
        elif req == APS_SF:
            healthy = [(lvl, ts) for (vk, lvl), ts in self.ccm_health.items()
                       if vk == vkey and frame.ts - ts <= self.cfg.health_window]
            ais_ts = self.ais_recent.get(vkey)
            ais_fresh = ais_ts is not None and \
                frame.ts - ais_ts <= self.cfg.health_window
            if healthy and not ais_fresh:
                lvls = sorted(l for l, _ in healthy)
                self.emit("CFM-083", gname,
                          "%s asserted on %s while CCMs at level(s) %s kept "
                          "arriving and no AIS was seen"
                          % (body["request_name"], gname, lvls), frame,
                          {"src": mac_str(src), "group": gname,
                           "request": body["request_name"],
                           "healthy_levels": lvls})

    # -- Class R: ERPS / G.8032 --------------------------------------------

    def _raps(self, frame: CfmFrame) -> None:
        body = frame.body
        if not body:
            return
        vkey = frame.service_key
        src = frame.src
        # Declarations are VLAN-based, so ring matching uses the VLAN
        # part while the state tables key on the full service.
        ring = self.cfg.ring_for(frame.vlan_key)
        rname = ring.name() if ring else ("vlan%s" % "/".join(
            str(v) for v in vkey) if vkey else "untagged")
        req = body["request"]
        req_name = body["request_name"]

        self.emit("CFM-180", rname,
                  "R-APS(%s%s) from %s on %s"
                  % (req_name, ",RB" if body["rb"] else "", mac_str(src),
                     rname), frame,
                  {"src": mac_str(src), "request": req_name,
                   "rb": body["rb"], "dnf": body["dnf"],
                   "bpr": body["bpr"], "revision": body["revision_name"],
                   "node_id": mac_str(body["node_id"]),
                   "dst": mac_str(frame.dst), "vlan": list(frame.vlan_key),
                   "md_level": frame.md_level})

        # ---- declaration state: fail loud rather than look clean --------
        if ring is None:
            if self.cfg.rings:
                self.emit("CFM-196", rname,
                          "R-APS on %s, which no declared ring covers "
                          "(declared: %s)"
                          % (rname, ", ".join(r.name()
                                              for r in self.cfg.rings)),
                          frame, {"src": mac_str(src), "vlan": list(frame.vlan_key),
                                  "declared": [r.name()
                                               for r in self.cfg.rings]})
            else:
                self.emit("CFM-200", rname,
                          "R-APS seen on %s with no ring declared; "
                          "topology-dependent rules are inert" % rname,
                          frame, {"src": mac_str(src), "vlan": list(frame.vlan_key),
                                  "inert_codes": ["CFM-192", "CFM-194",
                                                  "CFM-195", "CFM-199"]})

        # ---- structural conformance, no baseline needed ------------------
        if req in RAPS_RESERVED_REQUESTS:
            self.emit("CFM-181", rname,
                      "R-APS request/state %d is reserved by G.8032" % req,
                      frame, {"src": mac_str(src), "request": req})
        nonzero = []
        if frame.flags:
            nonzero.append("Flags 0x%02x" % frame.flags)
        if body["status_reserved"]:
            nonzero.append("status reserved bits 0x%02x"
                           % body["status_reserved"])
        if any(body["reserved"]):
            nonzero.append("%d non-zero octets in the 24 reserved"
                           % sum(1 for b in body["reserved"] if b))
        if nonzero:
            self.emit("CFM-182", rname,
                      "R-APS from %s carries %s"
                      % (mac_str(src), "; ".join(nonzero)), frame,
                      {"src": mac_str(src), "fields": nonzero,
                       "revision": body["revision_name"]})

        # ---- G.8032 revision: v1 (version 0) vs v2 (version 1) ---------
        if body["revision"] == RAPS_VERSION_V1:
            v2only = []
            if req in RAPS_V2_ONLY_REQUESTS:
                v2only.append("request %s" % req_name)
            if body["status"] & RAPS_STATUS_BPR:
                v2only.append("BPR status bit")
            if v2only:
                self.emit("CFM-202", rname,
                          "R-APS from %s declares G.8032v1 but uses %s, "
                          "which exists only from v2"
                          % (mac_str(src), " and ".join(v2only)), frame,
                          {"src": mac_str(src), "revision": "G.8032v1",
                           "v2_only": v2only})
        if body["node_id"] != src:
            self.emit("CFM-183", rname,
                      "R-APS Node ID %s does not match source %s"
                      % (mac_str(body["node_id"]), mac_str(src)), frame,
                      {"node_id": mac_str(body["node_id"]),
                       "src": mac_str(src)})
        if req != RAPS_EVENT and body["sub_code"]:
            self.emit("CFM-184", rname,
                      "sub-code %d set on R-APS(%s), which defines none"
                      % (body["sub_code"], req_name), frame,
                      {"src": mac_str(src), "sub_code": body["sub_code"],
                       "request": req_name})

        # ---- request semantics ------------------------------------------
        if req == RAPS_FS:
            self.emit("CFM-187", rname,
                      "Forced Switch requested on %s by %s"
                      % (rname, mac_str(src)), frame,
                      {"src": mac_str(src), "ring": rname})
        elif req == RAPS_MS:
            self.emit("CFM-188", rname,
                      "Manual Switch requested on %s by %s"
                      % (rname, mac_str(src)), frame,
                      {"src": mac_str(src), "ring": rname})
        elif req == RAPS_SF:
            self.emit("CFM-185", rname,
                      "R-APS(SF) on %s from %s" % (rname, mac_str(src)),
                      frame, {"src": mac_str(src), "ring": rname})
            self._raps_forged_sf(frame, ring, rname)
        elif req == RAPS_EVENT and body["sub_code"] == RAPS_SUBCODE_FLUSH:
            self._raps_flush(frame, ring, rname)

        # DNF on a message receivers would otherwise flush on.
        if body["dnf"] and (req in RAPS_FLUSH_REQUESTS or req == RAPS_EVENT):
            self.emit("CFM-191", rname,
                      "DNF set on R-APS(%s%s) from %s, suppressing the FDB "
                      "flush receivers would perform"
                      % (req_name, ",RB" if body["rb"] else "",
                         mac_str(src)), frame,
                      {"src": mac_str(src), "request": req_name,
                       "rb": body["rb"], "ring": rname})

        st = self.raps_rings.get(vkey)
        if st is None:
            st = {"nodes": {}, "rb": {}, "last_req": req,
                  "changes": deque(), "idle_run": 0, "requests": set(),
                  "revisions": set(), "dsts": set(), "rb_ever": False,
                  "last_change": None}
            self.raps_rings[vkey] = st
        st["nodes"].setdefault(src, {"node_ids": set(), "rb": False,
                                     "revisions": set()})
        st["nodes"][src]["node_ids"].add(body["node_id"])
        st["nodes"][src]["revisions"].add(body["revision_name"])
        st["requests"].add(req_name)
        st["revisions"].add(body["revision"])
        st["dsts"].add(frame.dst)

        if len(st["revisions"]) > 1:
            self.emit("CFM-203", rname,
                      "both %s R-APS seen on %s"
                      % (" and ".join(
                          RAPS_REVISION_NAMES.get(v, "v%d" % v)
                          for v in sorted(st["revisions"])), rname), frame,
                      {"ring": rname,
                       "revisions": sorted(
                           RAPS_REVISION_NAMES.get(v, "v%d" % v)
                           for v in st["revisions"])})

        # The ring ID lives in the R-APS destination address, so adjoining
        # rings that share a control VLAN are distinguished only by it.
        if ring is not None and len(st["dsts"]) > 1:
            self.emit("CFM-204", rname,
                      "%d distinct R-APS destinations on %s: %s - the "
                      "declaration models one ring here"
                      % (len(st["dsts"]), rname,
                         ", ".join(sorted(mac_str(d) for d in st["dsts"]))),
                      frame,
                      {"ring": rname,
                       "destinations": sorted(mac_str(d)
                                              for d in st["dsts"])})

        # ---- RPL block ownership ----------------------------------------
        if body["rb"]:
            st["rb"][src] = frame.ts
            st["rb_ever"] = True
            st["nodes"][src]["rb"] = True
            st["idle_run"] = 0
            if ring is not None and ring.rpl_owner is not None \
                    and src != ring.rpl_owner:
                self.emit("CFM-192", rname,
                          "%s asserts RPL-blocked on %s; the declared RPL "
                          "owner is %s"
                          % (mac_str(src), rname, mac_str(ring.rpl_owner)),
                          frame,
                          {"src": mac_str(src), "ring": rname,
                           "declared_owner": mac_str(ring.rpl_owner)})
            recent = sorted(m for m, ts in st["rb"].items()
                            if frame.ts - ts <= self.cfg.rb_window)
            if len(recent) > 1:
                self.emit("CFM-193", rname,
                          "%d nodes assert RPL-blocked on %s within %.0fs: "
                          "%s - a second block segments the ring"
                          % (len(recent), rname, self.cfg.rb_window,
                             ", ".join(mac_str(m) for m in recent)), frame,
                          {"ring": rname,
                           "claimants": [mac_str(m) for m in recent],
                           "window_s": self.cfg.rb_window})
        elif req == RAPS_NR:
            # A run of NR with nobody holding the block means no block.
            st["idle_run"] += 1
            held = any(frame.ts - ts <= self.cfg.rb_stale
                       for ts in st["rb"].values())
            # Revertive operation is configuration only in G.8032 - there
            # is no revertive flag on the wire - so a declared
            # non-revertive ring legitimately holds no block after a
            # recovery and neither rule applies.
            if (ring is not None and ring.revertive and not held
                    and st["idle_run"] >= self.cfg.raps_idle_min):
                if st["rb_ever"]:
                    # The block was OBSERVED and is now gone. That removes
                    # the tap-vantage explanation entirely.
                    self.emit("CFM-206", rname,
                              "%d consecutive R-APS(NR) on %s with no node "
                              "asserting RPL-blocked, after RB was "
                              "observed earlier from %s"
                              % (st["idle_run"], rname,
                                 ", ".join(sorted(mac_str(m)
                                                  for m in st["rb"]))),
                              frame,
                              {"ring": rname, "nr_run": st["idle_run"],
                               "previous_rb": sorted(mac_str(m)
                                                     for m in st["rb"]),
                               "stale_after_s": self.cfg.rb_stale})
                else:
                    self.emit("CFM-194", rname,
                              "%d consecutive R-APS(NR) on %s with no node "
                              "asserting RPL-blocked, and none seen at any "
                              "point in this capture"
                              % (st["idle_run"], rname), frame,
                              {"ring": rname, "nr_run": st["idle_run"],
                               "stale_after_s": self.cfg.rb_stale})

        # ---- sub-ring control traffic on the parent ---------------------
        # Without a virtual channel a sub-ring's R-APS must not reach the
        # parent at all. Interconnection nodes sit on both rings
        # legitimately, so they are excluded.
        if ring is not None and not ring.is_sub():
            for sub in self.cfg.sub_rings_of(ring):
                if sub.virtual_channel is not False:
                    continue
                if src in sub.interconnect or not sub.nodes:
                    continue
                if src in sub.nodes:
                    self.emit("CFM-208", rname,
                              "%s is a declared node of sub-ring %s, which "
                              "has no virtual channel, yet it sourced "
                              "R-APS on the parent %s"
                              % (mac_str(src), sub.name(), rname), frame,
                              {"src": mac_str(src), "sub_ring": sub.name(),
                               "parent": rname})

        # ---- ring membership --------------------------------------------
        if ring is not None and ring.nodes:
            if src not in ring.nodes:
                self.emit("CFM-195", rname,
                          "R-APS from %s, which is not a declared node of "
                          "%s" % (mac_str(src), rname), frame,
                          {"src": mac_str(src), "ring": rname,
                           "declared_nodes": [mac_str(m)
                                              for m in ring.nodes]})

        # ---- churn and volume -------------------------------------------
        if req != st["last_req"]:
            st["changes"].append(frame.ts)
            st["last_change"] = frame.ts
            st["last_req"] = req
            while (st["changes"] and
                   frame.ts - st["changes"][0] > self.cfg.raps_churn_window):
                st["changes"].popleft()
            if len(st["changes"]) >= self.cfg.raps_churn_min:
                self.emit("CFM-197", rname,
                          "%d R-APS state changes on %s within %.0fs"
                          % (len(st["changes"]), rname,
                             self.cfg.raps_churn_window), frame,
                          {"ring": rname, "changes": len(st["changes"]),
                           "window_s": self.cfg.raps_churn_window})

        hist = self.raps_hist[src]
        hist.append(frame.ts)
        while hist and frame.ts - hist[0] > self.cfg.raps_rate_window:
            hist.popleft()
        if len(hist) > self.cfg.raps_rate_max * self.cfg.raps_rate_window:
            rate = len(hist) / self.cfg.raps_rate_window
            self.emit("CFM-198", mac_str(src),
                      "%s sent %.0f R-APS frames/s over %.0fs"
                      % (mac_str(src), rate, self.cfg.raps_rate_window),
                      frame, {"src": mac_str(src), "rate_fps": round(rate, 1),
                              "ring": rname})

    def _raps_flush(self, frame: CfmFrame, ring: Optional[Ring],
                    rname: str) -> None:
        """R-APS(Event/Flush): legitimate propagation, or a bare primitive.

        On a G.8032v2 interconnected topology an interconnection node
        propagates a sub-ring topology change onto the ring it connects
        to, as an Event/Flush. That is normal operation. Propagation runs
        ONE WAY - toward the ring the sub-ring connects to, never into a
        sub-ring - and only an interconnection node does it.

        So with a declared topology the three cases separate cleanly:
        normal propagation (recorded, not alarmed), a flush into a
        sub-ring (never legitimate), and a flush from a node that is not
        an interconnection node at all (the bare primitive). Without a
        declaration none of them can be told apart, and the original
        CFM-189/190 behaviour stands.
        """
        src = frame.src
        vkey = frame.service_key

        if ring is not None:
            parent = (self.cfg.ring_named(ring.parent)
                      if ring.is_sub() else None)
            # A flush arriving on a sub-ring from its parent's
            # interconnection node is the wrong direction.
            if ring.is_sub() and parent is not None and \
                    src in self.cfg.interconnects_for(parent):
                self.emit("CFM-207", rname,
                          "Event/Flush on sub-ring %s from %s, an "
                          "interconnection node of parent %s - propagation "
                          "never runs into a sub-ring"
                          % (rname, mac_str(src), parent.name()), frame,
                          {"src": mac_str(src), "sub_ring": rname,
                           "parent": parent.name()})
                return

            allowed = self.cfg.interconnects_for(ring)
            if allowed:
                if src in allowed:
                    # Normal propagation. Record the correlating sub-ring
                    # change when this tap happened to see it; its absence
                    # is not evidence, because a tap sees one segment.
                    changed = []
                    for sub in self.cfg.sub_rings_of(ring):
                        sst = self.raps_rings.get(sub.vlan)
                        if sst and sst.get("last_change") is not None and \
                                frame.ts - sst["last_change"] <= \
                                self.cfg.raps_flush_window:
                            changed.append(sub.name())
                    self.emit("CFM-209", rname,
                              "%s propagated a topology change onto %s as "
                              "an Event/Flush%s"
                              % (mac_str(src), rname,
                                 " (sub-ring %s changed state within %.0fs)"
                                 % (", ".join(changed),
                                    self.cfg.raps_flush_window)
                                 if changed else ""), frame,
                              {"src": mac_str(src), "ring": rname,
                               "interconnection_node": True,
                               "correlated_sub_rings": changed})
                    return
                self.emit("CFM-205", rname,
                          "Event/Flush on %s from %s, which is not a "
                          "declared interconnection node (%s)"
                          % (rname, mac_str(src),
                             ", ".join(mac_str(m) for m in allowed)), frame,
                          {"src": mac_str(src), "ring": rname,
                           "interconnection_nodes": [mac_str(m)
                                                     for m in allowed]})
                return

        # Undeclared topology, or a ring with no interconnection nodes
        # declared: the original behaviour, which cannot distinguish
        # legitimate propagation from a bare flush.
        self.emit("CFM-189", rname,
                  "R-APS(Event/Flush) on %s from %s" % (rname, mac_str(src)),
                  frame, {"src": mac_str(src), "ring": rname})
        hist = self.flush_hist[vkey]
        hist.append(frame.ts)
        while hist and frame.ts - hist[0] > self.cfg.raps_flush_window:
            hist.popleft()
        if len(hist) >= self.cfg.raps_flush_burst:
            self.emit("CFM-190", rname,
                      "%d Event/Flush messages on %s within %.0fs"
                      % (len(hist), rname, self.cfg.raps_flush_window),
                      frame, {"ring": rname, "count": len(hist),
                              "window_s": self.cfg.raps_flush_window})

    def _raps_forged_sf(self, frame: CfmFrame, ring: Optional[Ring],
                        rname: str) -> None:
        """R-APS(SF) that nothing on the wire corroborates.

        Same reasoning as CFM-083 for linear APS, with the ring caveat
        that a tap sees one segment of a loop.
        """
        vkey = frame.service_key
        healthy = [(lvl, ts) for (vk, lvl), ts in self.ccm_health.items()
                   if vk == vkey and frame.ts - ts <= self.cfg.health_window]
        ais_ts = self.ais_recent.get(vkey)
        ais_fresh = ais_ts is not None and \
            frame.ts - ais_ts <= self.cfg.health_window
        if healthy and not ais_fresh:
            lvls = sorted(l for l, _ in healthy)
            self.emit("CFM-186", rname,
                      "R-APS(SF) on %s while CCMs at level(s) %s kept "
                      "arriving and no AIS was seen"
                      % (rname, lvls), frame,
                      {"src": mac_str(frame.src), "ring": rname,
                       "healthy_levels": lvls})

    def _ring_ccm_watch(self, frame: CfmFrame) -> None:
        """G.8032's primary protection trigger is three missed CCMs.

        Checked on every frame carrying a declared ring's VLAN, because a
        passive observer has no timer of its own - the next frame on the
        ring is what reveals that a MEP went quiet. One finding per quiet
        episode per MEP, re-armed when the MEP speaks again.
        """
        if not self.cfg.rings:
            return
        vkey = frame.service_key
        ring = self.cfg.ring_for(frame.vlan_key)
        if ring is None:
            return
        for mkey, st in self.mep.items():
            if mkey[0] != vkey:
                continue
            nominal = CCM_INTERVAL_SECONDS.get(st["interval"])
            if not nominal:
                continue
            gap = frame.ts - st["last_ts"]
            threshold = nominal * self.cfg.ccm_loss_misses
            if gap > threshold:
                if self.ring_ccm_quiet.get(mkey):
                    continue
                self.ring_ccm_quiet[mkey] = True
                self.emit("CFM-199", "%s/mep%d" % (ring.name(), mkey[3]),
                          "MEP %d on ring %s silent for %.3fs, over the "
                          "%.3fs three-miss threshold at its declared %s "
                          "interval"
                          % (mkey[3], ring.name(), gap, threshold,
                             CCM_INTERVAL_NAMES.get(st["interval"], "?")),
                          frame,
                          {"mepid": mkey[3], "ring": ring.name(),
                           "gap_s": round(gap, 6),
                           "threshold_s": round(threshold, 6),
                           "declared_interval": CCM_INTERVAL_NAMES.get(
                               st["interval"], "?")})
            else:
                self.ring_ccm_quiet[mkey] = False

    # -- Class L: E-LMI cross-plane ----------------------------------------

    def _cfm_service_state(self, vlan: Tuple[int, ...],
                           now: float) -> Tuple[bool, bool, List[str]]:
        """What CFM says about a service VLAN: (degraded, healthy, why).

        Matched on the VLAN part of the service key, so a service seen
        natively and one seen inside a tunnel both count.
        """
        why: List[str] = []
        degraded = False
        healthy = False
        for key, ts in self.ais_recent.items():
            if split_service(key)[1] == vlan and now - ts <= \
                    self.cfg.health_window:
                degraded = True
                why.append("AIS within %.1fs" % self.cfg.health_window)
        for key, ts in self.rdi_recent.items():
            if split_service(key)[1] == vlan and now - ts <= \
                    self.cfg.health_window:
                degraded = True
                why.append("RDI within %.1fs" % self.cfg.health_window)
        for mkey, st in self.mep.items():
            if split_service(mkey[0])[1] != vlan:
                continue
            nominal = CCM_INTERVAL_SECONDS.get(st["interval"])
            if not nominal:
                continue
            gap = now - st["last_ts"]
            if gap > nominal * self.cfg.ccm_loss_misses:
                degraded = True
                why.append("MEP %d silent for %.2fs" % (mkey[3], gap))
            elif gap <= nominal * self.cfg.ccm_loss_misses:
                healthy = True
        return degraded, (healthy and not degraded), why

    def feed_elmi(self, frame: ElmiFrame) -> None:
        self.frames_cfm += 1
        if self.first_ts is None:
            self.first_ts = frame.ts
        self.last_ts = frame.ts
        src = frame.src
        uni = (frame.uni_id.decode("latin-1") if frame.uni_id
               else mac_str(src))

        shim = CfmFrame(index=frame.index, ts=frame.ts,
                        frame_len=frame.frame_len, dst=frame.dst, src=src,
                        vlans=[], md_level=0, version=0, opcode=0, flags=0,
                        first_tlv_offset=0, payload=b"")

        self.emit("CFM-250", uni,
                  "E-LMI %s from %s, UNI %s, %d EVC(s): %s"
                  % (frame.msg_name, mac_str(src), uni, len(frame.evcs),
                     ", ".join("%d=%s" % (e["reference"], e["status_name"])
                               for e in frame.evcs) or "none"), shim,
                  {"src": mac_str(src), "uni": uni,
                   "message": frame.msg_name,
                   "report_type": ELMI_REPORT_TYPES.get(
                       frame.report_type, frame.report_type),
                   "evcs": [{"reference": e["reference"],
                             "status": e["status_name"]}
                            for e in frame.evcs]})
        for e in frame.evcs:
            rec = self.inv_elmi.setdefault(
                e["reference"], {"reference": e["reference"],
                                 "statuses": set(), "unis": set(),
                                 "evc_id": None})
            rec["statuses"].add(e["status_name"])
            rec["unis"].add(uni)
            if e["evc_id"]:
                rec["evc_id"] = e["evc_id"].decode("latin-1")

        for code, detail in frame.structural:
            self.emit(code, uni, detail, shim,
                      {"src": mac_str(src), "uni": uni,
                       "message": frame.msg_name})

        # ---- sequence numbers -------------------------------------------
        if frame.snd_seq is not None:
            prev = self.elmi_seq.get(src)
            if prev is not None and frame.snd_seq <= prev and \
                    not (prev == 255 and frame.snd_seq <= 1):
                self.emit("CFM-253", uni,
                          "E-LMI send sequence %d from %s did not advance "
                          "past %d" % (frame.snd_seq, mac_str(src), prev),
                          shim, {"src": mac_str(src), "uni": uni,
                                 "was": prev, "now": frame.snd_seq})
            self.elmi_seq[src] = frame.snd_seq

        # ---- the cross-plane rule ---------------------------------------
        if not self.cfg.evcs:
            if frame.evcs:
                self.emit("CFM-254", uni,
                          "E-LMI reports EVC(s) %s with no --evc mapping "
                          "declared, so the cross-plane rule is inert"
                          % ", ".join(str(e["reference"])
                                      for e in frame.evcs), shim,
                          {"src": mac_str(src), "uni": uni,
                           "references": [e["reference"]
                                          for e in frame.evcs],
                           "inert_codes": ["CFM-251"]})
            return

        for e in frame.evcs:
            evc = self.cfg.evc_for(e["reference"])
            if evc is None:
                continue
            degraded, healthy, why = self._cfm_service_state(evc.vlan,
                                                             frame.ts)
            status = e["status"]
            ev = {"src": mac_str(src), "uni": uni, "evc": evc.name(),
                  "reference": e["reference"],
                  "elmi_status": e["status_name"],
                  "vlan": list(evc.vlan), "cfm_evidence": why}
            if status in ELMI_EVC_ACTIVE and degraded:
                self.emit("CFM-251", "%s/%s" % (uni, evc.name()),
                          "E-LMI reports EVC %s as %s while CFM on VLAN %s "
                          "shows a fault (%s)"
                          % (evc.name(), e["status_name"],
                             "/".join(str(v) for v in evc.vlan) or
                             "untagged", "; ".join(why)), shim, ev)
            elif status in ELMI_EVC_INACTIVE and healthy:
                self.emit("CFM-251", "%s/%s" % (uni, evc.name()),
                          "E-LMI reports EVC %s as %s while CFM on VLAN %s "
                          "is healthy"
                          % (evc.name(), e["status_name"],
                             "/".join(str(v) for v in evc.vlan) or
                             "untagged"), shim, ev)

    # -- Class M: Y.1731 measurement and maintenance ------------------------

    def _meas_inventory(self, frame: CfmFrame, **extra: Any) -> None:
        rec = self.inv_meas.setdefault(
            frame.opcode, {"opcode": frame.opcode_name, "frames": 0,
                           "sources": set(), "test_ids": set(),
                           "ouis": set()})
        rec["frames"] += 1
        rec["sources"].add(mac_str(frame.src))
        for key, val in extra.items():
            if val is not None:
                rec[key].add(val)

    def _no_ccm_history(self, frame: CfmFrame) -> bool:
        known = self.ccm_macs.get(frame.service_key)
        return bool(known) and frame.src not in known

    def _measurement(self, frame: CfmFrame) -> None:
        body = frame.body
        if not body:
            return
        vkey = frame.service_key
        src = frame.src
        name = frame.opcode_name
        ctx = "%s/%s" % (mac_str(src), name)

        self._meas_inventory(frame, test_ids=body.get("test_id"))

        if self._no_ccm_history(frame):
            self.emit("CFM-220", ctx,
                      "%s from %s, which has never sourced a CCM on this "
                      "service" % (name, mac_str(src)), frame,
                      {"src": mac_str(src), "opcode": name,
                       "vlan": list(frame.vlan_key),
                       "ccm_sources": sorted(
                           mac_str(m)
                           for m in self.ccm_macs.get(vkey, ()))})

        # ---- monotonic counters ----------------------------------------
        for cname, value in (body.get("counters") or {}).items():
            session = body.get("test_id", 0)
            key = (vkey, src, session, "%s/%s" % (name, cname))
            prev = self.meas_counters.get(key)
            if prev is not None and value < prev:
                self.emit("CFM-221", "%s/%s" % (ctx, cname),
                          "%s %s went backwards, %d -> %d, from %s"
                          % (name, cname, prev, value, mac_str(src)), frame,
                          {"src": mac_str(src), "opcode": name,
                           "counter": cname, "was": prev, "now": value,
                           "test_id": session})
            self.meas_counters[key] = value

        # ---- delay-measurement timestamps -------------------------------
        stamps = body.get("timestamps") or {}
        bad = [nm for nm, v in stamps.items()
               if v["nanos"] >= NANOS_PER_SECOND]
        if bad:
            self.emit("CFM-222", ctx,
                      "%s carries out-of-range nanoseconds in %s"
                      % (name, ", ".join(sorted(bad))), frame,
                      {"src": mac_str(src), "opcode": name,
                       "fields": sorted(bad),
                       "nanos": {nm: stamps[nm]["nanos"] for nm in bad}})
        if frame.opcode == OP_DMR and len(stamps) == 4 and not bad:
            # Judged within the one frame. Comparing the forward pair
            # against the backward pair would assume the two endpoints
            # share a clock, which a DM measurement does not require, so
            # only same-direction ordering is treated as a violation.
            problems = []
            if stamps["RxTimeStampb"]["value"] < \
                    stamps["TxTimeStampb"]["value"]:
                problems.append("RxTimeStampb precedes TxTimeStampb")
            if stamps["RxTimeStampf"]["value"] < \
                    stamps["TxTimeStampf"]["value"]:
                problems.append("RxTimeStampf precedes TxTimeStampf")
            if problems:
                self.emit("CFM-223", ctx,
                          "DMR timestamps contradict themselves: %s"
                          % "; ".join(problems), frame,
                          {"src": mac_str(src), "problems": problems,
                           "timestamps": {nm: v["value"]
                                          for nm, v in stamps.items()}})

        # ---- synthetic loss test correlation ----------------------------
        test_id = body.get("test_id")
        if test_id is not None:
            if frame.opcode in (OP_SLM, OP_1SL):
                self.slm_tests[(vkey, test_id)] = frame.ts
            elif frame.opcode == OP_SLR and \
                    (vkey, test_id) not in self.slm_tests:
                self.emit("CFM-224", "%s/test%d" % (ctx, test_id),
                          "SLR from %s carries test ID 0x%08x, which no "
                          "observed SLM requested"
                          % (mac_str(src), test_id), frame,
                          {"src": mac_str(src), "test_id": test_id,
                           "known_tests": sorted(
                               t for v, t in self.slm_tests if v == vkey)})

    def _tst(self, frame: CfmFrame) -> None:
        src = frame.src
        self._meas_inventory(frame)
        self.emit("CFM-225", mac_str(src),
                  "TST from %s at MD level %d, sequence %s"
                  % (mac_str(src), frame.md_level,
                     frame.body.get("seq") if frame.body else "?"), frame,
                  {"src": mac_str(src), "md_level": frame.md_level,
                   "frame_len": frame.frame_len})
        hist = self.tst_hist[src]
        hist.append(frame.ts)
        while hist and frame.ts - hist[0] > self.cfg.tst_window:
            hist.popleft()
        if len(hist) >= self.cfg.tst_burst:
            self.emit("CFM-226", mac_str(src),
                      "%d TST frames from %s within %.1fs"
                      % (len(hist), mac_str(src), self.cfg.tst_window),
                      frame, {"src": mac_str(src), "count": len(hist),
                              "window_s": self.cfg.tst_window})

    def _oui_opcode(self, frame: CfmFrame) -> None:
        body = frame.body
        if not body:
            return
        src = frame.src
        name = frame.opcode_name
        self._meas_inventory(frame, ouis=body["oui_str"])
        detail = ("%s from %s, OUI %s, sub-opcode %d"
                  % (name, mac_str(src), body["oui_str"],
                     body["sub_opcode"]))
        ev = {"src": mac_str(src), "opcode": name, "oui": body["oui_str"],
              "sub_opcode": body["sub_opcode"],
              "md_level": frame.md_level}
        if frame.opcode in EXPERIMENTAL_OPCODES:
            self.emit("CFM-229", mac_str(src), detail, frame, ev)
        elif frame.opcode == OP_MCC:
            self.emit("CFM-227", mac_str(src), detail, frame, ev)
        else:
            self.emit("CFM-228", mac_str(src), detail, frame, ev)

    # -- Class G -----------------------------------------------------------

    def _rates(self, frame: CfmFrame) -> None:
        self.rate_hist.append(frame.ts)
        while (self.rate_hist and
               frame.ts - self.rate_hist[0] > self.cfg.rate_window):
            self.rate_hist.popleft()
        if len(self.rate_hist) > self.cfg.rate_max * self.cfg.rate_window:
            self.emit("CFM-120", "aggregate",
                      "%d CFM frames in the last %.1fs (threshold %.0f/s)"
                      % (len(self.rate_hist), self.cfg.rate_window,
                         self.cfg.rate_max), frame,
                      {"frames": len(self.rate_hist),
                       "window_s": self.cfg.rate_window,
                       "threshold_fps": self.cfg.rate_max})

        src = frame.src
        hist = self.src_hist[src]
        hist.append(frame.ts)
        while hist and frame.ts - hist[0] > self.cfg.src_rate_window:
            hist.popleft()
        if not frame.structural:
            self.src_clean[src] += 1
        if (len(hist) >= self.cfg.src_rate_min_frames and
                len(hist) > self.cfg.src_rate_max * self.cfg.src_rate_window):
            rate = len(hist) / self.cfg.src_rate_window
            self.emit("CFM-122", mac_str(src),
                      "%s sustained %.0f CFM frames/s over %.0fs"
                      % (mac_str(src), rate, self.cfg.src_rate_window), frame,
                      {"src": mac_str(src), "rate_fps": round(rate, 1),
                       "window_s": self.cfg.src_rate_window})
            # CVE-2025-52961's traffic is valid, so the correlation only
            # holds when the burst is well formed.
            if self.src_clean[src] >= self.cfg.src_rate_min_frames:
                self.emit("CFM-141", mac_str(src),
                          "%s sustained %.0f well-formed CFM frames/s; "
                          "check cfmman RSS on the adjacent device"
                          % (mac_str(src), rate), frame,
                          {"src": mac_str(src), "rate_fps": round(rate, 1),
                           "clean_frames": self.src_clean[src],
                           "ioc": "cfmman RSS growth, cfmd CPU at 100%"})

    # -- posture roll-up ---------------------------------------------------

    def finalize(self) -> None:
        ts = self.last_ts if self.last_ts is not None else time.time()
        if self.inv_levels:
            detail = ", ".join(
                "level %d on VLAN %s" % (lvl, sorted(list(v) for v in vlans))
                for lvl, vlans in sorted(self.inv_levels.items()))
            self.emit_static("CFM-160", "tap", detail, ts,
                             {"levels": sorted(self.inv_levels),
                              "level_vlans": {
                                  str(l): sorted(list(v) for v in vl)
                                  for l, vl in self.inv_levels.items()}})
        if self.inv_meps:
            self.emit_static(
                "CFM-161", "tap",
                "%d maintenance endpoint(s) observed" % len(self.inv_meps),
                ts, {"meps": [self.inv_meps[k]
                              for k in sorted(self.inv_meps)]})
        if self.inv_y1731:
            names = sorted(OPCODE_NAMES.get(o, str(o))
                           for o in self.inv_y1731)
            self.emit_static(
                "CFM-162", "tap",
                "Y.1731 opcodes present: %s" % ", ".join(names), ts,
                {"opcodes": {OPCODE_NAMES.get(o, str(o)): c
                             for o, c in sorted(self.inv_y1731.items())}})
        if self.inv_elmi:
            rows = [{"reference": r["reference"],
                     "evc_id": r["evc_id"],
                     "statuses": sorted(r["statuses"]),
                     "unis": sorted(r["unis"])}
                    for _, r in sorted(self.inv_elmi.items())]
            self.emit_static(
                "CFM-250", "tap",
                "E-LMI reported %d EVC(s): %s"
                % (len(rows), "; ".join(
                    "%d%s %s" % (r["reference"],
                                 " (%s)" % r["evc_id"] if r["evc_id"]
                                 else "", "/".join(r["statuses"]))
                    for r in rows)), ts, {"evcs": rows})
        if self.inv_vni:
            rows = [{"vni": r["vni"], "frames": r["frames"],
                     "vlans": sorted(list(v) for v in r["vlans"])}
                    for _, r in sorted(self.inv_vni.items())]
            self.emit_static(
                "CFM-240", "tap",
                "CFM seen inside VXLAN on %s"
                % ", ".join("VNI %d (%d frames)" % (r["vni"], r["frames"])
                            for r in rows), ts, {"vnis": rows})
        if self.inv_meas:
            rows = []
            for op, rec in sorted(self.inv_meas.items()):
                rows.append({
                    "opcode": rec["opcode"], "frames": rec["frames"],
                    "sources": sorted(rec["sources"]),
                    "test_ids": ["0x%08x" % t
                                 for t in sorted(rec["test_ids"])],
                    "ouis": sorted(rec["ouis"]),
                })
            self.emit_static(
                "CFM-230", "tap",
                "; ".join("%s x%d from %d source(s)%s"
                          % (r["opcode"], r["frames"], len(r["sources"]),
                             " OUI " + ",".join(r["ouis"])
                             if r["ouis"] else "")
                          for r in rows), ts, {"opcodes": rows})
        if self.aps_inventory:
            groups = []
            for (vkey, lvl), inv in sorted(
                    self.aps_inventory.items(),
                    key=lambda kv: (str(kv[0][0]), kv[0][1])):
                g_vni, g_vlans = split_service(vkey)
                groups.append({
                    "group": "%s/level%d" % (service_label(vkey), lvl),
                    "vlan": list(g_vlans), "vni": g_vni, "md_level": lvl,
                    "nodes": {mac_str(m): sorted(v)
                              for m, v in inv["nodes"].items()},
                    "requests": sorted(inv["requests"]),
                    "bridge_types": sorted(inv["bridge_types"]),
                })
            self.emit_static(
                "CFM-093", "tap",
                "; ".join("%s: %d node(s), protection type %s, states %s"
                          % (g["group"], len(g["nodes"]),
                             "/".join(sorted({b for v in g["nodes"].values()
                                              for b in v})) or "-",
                             ", ".join(g["requests"]))
                          for g in groups), ts, {"groups": groups})
        if self.raps_rings:
            rings = []
            for vkey, st in sorted(self.raps_rings.items()):
                r_vni, r_vlans = split_service(vkey)
                ring = self.cfg.ring_for(r_vlans)
                rings.append({
                    "ring": ring.name() if ring else service_label(vkey),
                    "declared": ring is not None,
                    "vlan": list(r_vlans), "vni": r_vni,
                    "nodes": sorted(mac_str(m) for m in st["nodes"]),
                    "rb_claimants": sorted(mac_str(m) for m in st["rb"]),
                    "requests": sorted(st["requests"]),
                    "revisions": sorted(
                        RAPS_REVISION_NAMES.get(v, "v%d" % v)
                        for v in st["revisions"]),
                    "raps_destinations": sorted(mac_str(d)
                                                for d in st["dsts"]),
                })
            self.emit_static(
                "CFM-201", "tap",
                "; ".join("%s: %s, %d node(s), RB from %s, states %s"
                          % (r["ring"], "/".join(r["revisions"]),
                             len(r["nodes"]),
                             ", ".join(r["rb_claimants"]) or "none",
                             ", ".join(r["requests"]))
                          for r in rings), ts, {"rings": rings})
        if self.inv_vlans:
            desc = []
            for vk, count in sorted(self.inv_vlans.items()):
                tag = "untagged" if not vk else "/".join(str(v) for v in vk)
                desc.append("%s (%d frames)" % (tag, count))
            self.emit_static("CFM-163", "tap",
                             "CFM seen on: %s" % ", ".join(desc), ts,
                             {"vlans": [{"tags": list(vk), "frames": c}
                                        for vk, c in sorted(self.inv_vlans.items())]})

    # -- results -----------------------------------------------------------

    def results(self) -> List[Finding]:
        return sorted(
            self.findings.values(),
            key=lambda f: (SEVERITY_ORDER[f.spec.severity], f.code, f.key))

    def summary(self) -> Dict[str, Any]:
        by_sev: Dict[str, int] = defaultdict(int)
        for f in self.findings.values():
            by_sev[f.spec.severity] += 1
        return {
            "module": MODULE_NAME,
            "version": __version__,
            "frames_seen": self.frames_total,
            "cfm_frames": self.frames_cfm,
            "findings": len(self.findings),
            "codes_fired": sorted({f.code for f in self.findings.values()}),
            "by_severity": {k: by_sev[k] for k in
                            (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW,
                             SEV_INFO) if by_sev[k]},
            "opcodes": {OPCODE_NAMES.get(o, "op%d" % o): c
                        for o, c in sorted(self.inv_opcodes.items())},
            "duration_s": (round(self.last_ts - self.first_ts, 6)
                           if self.first_ts is not None and
                           self.last_ts is not None else 0.0),
        }


# --------------------------------------------------------------------------
# Capture sources
#
# Read-only by construction. The live path opens AF_PACKET with no bound
# transmit path and never calls send/sendto/sendall; the tier 3 AST scan
# enforces that against this file.
# --------------------------------------------------------------------------

# Magic as it appears on disk, so no endian guessing is needed.
PCAP_MAGICS: Dict[bytes, Tuple[str, bool]] = {
    b"\xd4\xc3\xb2\xa1": ("<", False),   # microsecond, little endian
    b"\xa1\xb2\xc3\xd4": (">", False),   # microsecond, big endian
    b"\x4d\x3c\xb2\xa1": ("<", True),    # nanosecond, little endian
    b"\xa1\xb2\x3c\x4d": (">", True),    # nanosecond, big endian
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = 1


def read_pcap(path: str) -> Iterator[Tuple[float, bytes]]:
    """Yield (timestamp, frame) from a classic libpcap file."""
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            raise ParseError("%s: short pcap header" % path)
        magic = hdr[0:4]
        if magic == PCAPNG_MAGIC:
            raise ParseError(
                "%s looks like pcapng; cfmwatch reads classic pcap "
                "(convert with: editcap -F pcap in.pcapng out.pcap)" % path)
        if magic not in PCAP_MAGICS:
            raise ParseError("%s: not a pcap file" % path)
        endian, nanos = PCAP_MAGICS[magic]
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        if linktype != LINKTYPE_ETHERNET:
            raise ParseError("%s: linktype %d, expected Ethernet (1)"
                             % (path, linktype))
        divisor = 1e9 if nanos else 1e6
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                return
            sec, frac, caplen, _origlen = struct.unpack(endian + "IIII", rh)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            yield sec + frac / divisor, data


# Kernel-side prefilter. Accepts the two EtherTypes this module parses -
# CFM (0x8902) and E-LMI (0x88EE) - at the outer position or behind up to
# two VLAN tags, so a carrier tap does not copy every frame on the segment
# into userspace.
#
# Built by a tiny label-resolving assembler rather than written out with
# literal jump offsets. Hand-computed offsets are how the VXLAN splice
# first went wrong, and the program now has three tag depths times two
# EtherTypes plus an optional tunnel clause; that is too many branches to
# keep correct by hand.
#
# What this program CANNOT do is match CFM inside VXLAN: the inner
# EtherType sits behind a variable-length IP header, so its offset is not
# fixed. When VXLAN is enabled the filter therefore also admits UDP to
# port 4789 and userspace decides, which is why enabling it on a busy
# underlay costs copies. Without that clause the kernel drops every
# encapsulated frame and the live path reports the service plane clean.

BPF_LD_H_ABS = 0x28
BPF_LD_B_ABS = 0x30
BPF_LDX_B_MSH = 0xB1
BPF_LD_H_IND = 0x48
BPF_JMP_JA = 0x05
BPF_JMP_JEQ = 0x15
BPF_JMP_JSET = 0x45
BPF_RET_K = 0x06
BPF_ACCEPT = 0x40000
BPF_REJECT = 0

WATCHED_ETHERTYPES = (ETHERTYPE_CFM, ETHERTYPE_ELMI)


def _bpf_assemble(src: List[Any]) -> List[Tuple[int, int, int, int]]:
    """Resolve symbolic labels into a BPF instruction list.

    Each entry is either a string label or a tuple whose jt/jf/k may be
    label names. Offsets are computed relative to the following
    instruction, which is what the BPF jump encoding means.
    """
    labels: Dict[str, int] = {}
    body: List[Tuple[Any, Any, Any, Any]] = []
    for item in src:
        if isinstance(item, str):
            labels[item] = len(body)
        else:
            body.append(item)
    out: List[Tuple[int, int, int, int]] = []
    for idx, (code, jt, jf, k) in enumerate(body):
        def off(target: Any) -> int:
            if isinstance(target, str):
                if target not in labels:
                    raise KeyError("undefined BPF label %r" % target)
                return labels[target] - (idx + 1)
            return int(target)
        if code == BPF_JMP_JA:
            out.append((code, 0, 0, off(k)))
        elif code in (BPF_JMP_JEQ, BPF_JMP_JSET):
            out.append((code, off(jt), off(jf), int(k)))
        else:
            out.append((code, int(jt), int(jf), int(k)))
    for ins in out:
        if ins[1] < 0 or ins[2] < 0 or (ins[0] == BPF_JMP_JA and ins[3] < 0):
            raise ValueError("backward BPF jump: %r" % (ins,))
    return out


def _bpf_ethertype_program() -> List[Any]:
    """Accept the watched EtherTypes at each VLAN tag depth."""
    src: List[Any] = []
    depths = 3
    for depth in range(depths):
        src.append((BPF_LD_H_ABS, 0, 0, 12 + depth * 4))
        for etype in WATCHED_ETHERTYPES:
            src.append((BPF_JMP_JEQ, "accept", 0, etype))
        if depth + 1 < depths:
            for tpid in VLAN_ETHERTYPES:
                src.append((BPF_JMP_JEQ, "depth%d" % (depth + 1), 0, tpid))
            src.append((BPF_JMP_JA, 0, 0, "reject"))
            src.append("depth%d" % (depth + 1))
        else:
            src.append((BPF_JMP_JA, 0, 0, "reject"))
    src.append("accept")
    src.append((BPF_RET_K, 0, 0, BPF_ACCEPT))
    src.append("reject")
    return src


def _bpf_vxlan_program() -> List[Any]:
    """Accept IPv4/IPv6 UDP to the VXLAN port, in label form."""
    return [
        (BPF_LD_H_ABS, 0, 0, 12),                     # ldh  ethertype
        (BPF_JMP_JEQ, 0, "v6", ETHERTYPE_IPV4),
        (BPF_LD_B_ABS, 0, 0, 23),                     # ldb  ip protocol
        (BPF_JMP_JEQ, 0, "drop", IPPROTO_UDP),
        (BPF_LD_H_ABS, 0, 0, 20),                     # ldh  fragment field
        (BPF_JMP_JSET, "drop", 0, 0x1FFF),            # a fragment is useless
        (BPF_LDX_B_MSH, 0, 0, 14),                    # x = 4 * IHL
        (BPF_LD_H_IND, 0, 0, 16),                     # ldh  [x + 16] dport
        (BPF_JMP_JEQ, "accept", "drop", VXLAN_PORT),
        "v6",
        (BPF_JMP_JEQ, 0, "drop", ETHERTYPE_IPV6),
        (BPF_LD_B_ABS, 0, 0, 20),                     # ldb  next header
        (BPF_JMP_JEQ, 0, "drop", IPPROTO_UDP),        # no EH walk here
        (BPF_LD_H_ABS, 0, 0, 56),                     # ldh  dport
        (BPF_JMP_JEQ, 0, "drop", VXLAN_PORT),
        "accept",
        (BPF_RET_K, 0, 0, BPF_ACCEPT),
        "drop",
        (BPF_RET_K, 0, 0, BPF_REJECT),
    ]


def _bpf_source(vxlan: bool) -> List[Any]:
    """The whole filter in label form: EtherTypes, then the reject target.

    The EtherType program has three reject points, one per tag depth, and
    they all branch to the single `reject` label. That label is either a
    plain drop or the first instruction of the tunnel clause, so enabling
    VXLAN redirects every one of them at once instead of relying on a
    trailing instruction being the only exit.
    """
    src = _bpf_ethertype_program()
    if vxlan:
        return src + _bpf_vxlan_program()
    return src + [(BPF_RET_K, 0, 0, BPF_REJECT)]


def _bpf_blob(vxlan: bool = False) -> Tuple[bytes, int]:
    prog = _bpf_assemble(_bpf_source(vxlan))
    blob = b"".join(struct.pack("HBBI", *ins) for ins in prog)
    return blob, len(prog)


class StopSignal:
    """Clean-shutdown latch for the live path.

    A passive monitor must report what it has collected when it is told to
    stop. Two things make that non-obvious:

      * systemd stops a service with SIGTERM, which Python terminates on
        by default - the whole capture would be lost on `systemctl stop`.
      * A background process started by a non-interactive shell inherits
        SIGINT ignored (POSIX job-control rules), so relying on
        KeyboardInterrupt alone does not work for a backgrounded capture.

    Both signals therefore set a latch the capture loop checks, and the
    run falls through to its normal report.
    """

    def __init__(self) -> None:
        self.stop = False
        self.signum: Optional[int] = None

    def install(self) -> "StopSignal":
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(sig, self._handle)
            except (ValueError, OSError, AttributeError):
                pass                     # not the main thread, or no SIGHUP
        return self

    def _handle(self, signum: int, _frame: Any) -> None:
        self.stop = True
        self.signum = signum

    def __call__(self) -> bool:
        return self.stop


# struct tpacket_auxdata: tp_status, tp_len, tp_snaplen (u32 x3),
# tp_mac, tp_net, tp_vlan_tci, tp_vlan_tpid (u16 x4).
_AUXDATA_FMT = "IIIHHHH"
_AUXDATA_LEN = struct.calcsize(_AUXDATA_FMT)
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6


def reinsert_vlan(data: bytes, tci: int, tpid: int) -> bytes:
    """Put a kernel-stripped 802.1Q tag back into the frame bytes.

    Linux moves the outer VLAN tag out of the frame data and into socket
    auxiliary data whenever the interface has receive VLAN offload
    enabled, which is the default on most drivers and on veth. Without
    this, every VLAN-keyed rule in the module silently collapses into the
    untagged bucket on a live tap - not just the ring rules, but the
    per-VLAN maintenance-association and MEP keying in Class C as well.
    The offline pcap path never shows this, because libpcap writes the
    reconstructed frame.
    """
    if len(data) < 12:
        return data
    return data[:12] + struct.pack("!HH", tpid or 0x8100, tci) + data[12:]


def live_capture(iface: str, promisc: bool = True,
                 snaplen: int = 2048,
                 duration: Optional[float] = None,
                 count: Optional[int] = None,
                 should_stop: Optional[Any] = None,
                 vxlan: bool = True,
                 on_warn: Optional[Any] = None) -> Iterator[Tuple[float, bytes]]:
    """Yield (timestamp, frame) from a live interface. Receive only."""
    import ctypes
    import socket

    ETH_P_ALL = 0x0003
    SO_ATTACH_FILTER = 26
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_MR_PROMISC = 1
    PACKET_AUXDATA = 8

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    try:
        prog, length = _bpf_blob(vxlan=vxlan)
        buf = ctypes.create_string_buffer(prog)
        fprog = struct.pack("HxxxxxxP" if ctypes.sizeof(ctypes.c_void_p) == 8
                            else "HxxP", length, ctypes.addressof(buf))
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        except OSError as exc:
            if on_warn:
                on_warn("kernel filter not attached (%s); filtering in "
                        "userspace" % exc)
        # Ask the kernel for the stripped VLAN tag. Without this the tag
        # is simply lost; see reinsert_vlan().
        auxdata = True
        try:
            sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        except OSError as exc:
            auxdata = False
            if on_warn:
                on_warn("PACKET_AUXDATA unavailable (%s); VLAN tags "
                        "stripped by receive offload cannot be recovered. "
                        "Disable it with: ethtool -K %s rxvlan off"
                        % (exc, iface))
        sock.bind((iface, 0))
        if promisc:
            mreq = struct.pack("IHH8s", _if_index(iface), PACKET_MR_PROMISC,
                               0, b"")
            try:
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            except OSError as exc:
                if on_warn:
                    on_warn("promiscuous mode not set (%s)" % exc)
        sock.settimeout(0.5)
        started = time.time()
        seen = 0
        while True:
            if should_stop is not None and should_stop():
                return
            if duration is not None and time.time() - started >= duration:
                return
            if count is not None and seen >= count:
                return
            try:
                if auxdata:
                    data, ancdata, _flags, _addr = sock.recvmsg(
                        snaplen, socket.CMSG_SPACE(_AUXDATA_LEN))
                    for level, ctype, cdata in ancdata:
                        if (level != SOL_PACKET or ctype != PACKET_AUXDATA
                                or len(cdata) < _AUXDATA_LEN):
                            continue
                        (status, _tlen, _snap, _mac, _net, tci,
                         tpid) = struct.unpack_from(_AUXDATA_FMT, cdata)
                        if status & TP_STATUS_VLAN_VALID:
                            data = reinsert_vlan(
                                data, tci,
                                tpid if status & TP_STATUS_VLAN_TPID_VALID
                                else 0x8100)
                        break
                else:
                    data = sock.recv(snaplen)
            except TimeoutError:
                continue
            except socket.timeout:          # pragma: no cover (py<3.10)
                continue
            seen += 1
            yield time.time(), data
    finally:
        sock.close()


def _if_index(iface: str) -> int:
    import socket
    return socket.if_nametoindex(iface)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def render_text(engine: Engine, show_info: bool = True) -> str:
    out: List[str] = []
    summ = engine.summary()
    out.append("%s %s" % (MODULE_NAME, __version__))
    out.append("frames seen %d, CFM frames %d, findings %d, span %.3fs"
               % (summ["frames_seen"], summ["cfm_frames"], summ["findings"],
                  summ["duration_s"]))
    if summ["opcodes"]:
        out.append("opcodes: " + ", ".join(
            "%s=%d" % (k, v) for k, v in summ["opcodes"].items()))
    out.append("")
    results = [f for f in engine.results()
               if show_info or f.spec.severity != SEV_INFO]
    if not results:
        out.append("no findings")
        return "\n".join(out)
    current = None
    for f in results:
        s = f.spec
        if s.severity != current:
            current = s.severity
            out.append("== %s ==" % current)
        head = "[%s] %s" % (f.code, s.title)
        if f.count > 1:
            head += "  (x%d)" % f.count
        out.append(head)
        out.append("    context    : %s" % f.key)
        out.append("    confidence : %s" % s.confidence)
        if s.cves:
            out.append("    cve        : %s" % ", ".join(s.cves))
        out.append("    detail     : %s" % f.detail)
        if f.first_index >= 0:
            out.append("    first seen : frame %d @ %.6f"
                       % (f.first_index, f.first_ts))
        if s.caveat:
            out.append("    caveat     : %s" % s.caveat)
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_json(engine: Engine) -> str:
    return json.dumps({
        "summary": engine.summary(),
        "findings": [f.to_dict() for f in engine.results()],
    }, indent=2, sort_keys=False) + "\n"


def render_ndjson(engine: Engine) -> str:
    return "".join(json.dumps(f.to_dict(), sort_keys=False) + "\n"
                   for f in engine.results())


def render_registry(as_json: bool = False) -> str:
    if as_json:
        return json.dumps(
            [{"code": s.code, "title": s.title, "severity": s.severity,
              "class": s.cls, "class_name": CLASS_NAMES[s.cls],
              "confidence": s.confidence, "cves": list(s.cves),
              "summary": s.summary, "caveat": s.caveat} for s in SPECS],
            indent=2) + "\n"
    lines = ["%s finding registry - %d codes" % (MODULE_NAME, len(SPECS)), ""]
    for cls in sorted(CLASS_NAMES):
        members = [s for s in SPECS if s.cls == cls]
        if not members:
            continue
        lines.append("-- Class %s: %s" % (cls, CLASS_NAMES[cls]))
        for s in members:
            cve = (" [%s]" % ",".join(s.cves)) if s.cves else ""
            lines.append("  %-8s %-8s %-6s %s%s"
                         % (s.code, s.severity, s.confidence, s.title, cve))
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=MODULE_NAME,
        description="Passive IEEE 802.1ag CFM / ITU-T Y.1731 service-OAM "
                    "detector. Receive only; this module never transmits.",
        epilog="Dual stack: not applicable. CFM is carried directly over "
               "Ethernet (0x8902) with no IP header, so there is no "
               "IPv4/IPv6 split to achieve parity across.")
    src = p.add_argument_group("source")
    src.add_argument("--pcap", action="append", default=[], metavar="FILE",
                     help="read a classic libpcap file (repeatable)")
    src.add_argument("--iface", metavar="IF",
                     help="capture live from an interface (receive only)")
    src.add_argument("--duration", type=float, metavar="S",
                     help="stop live capture after S seconds")
    src.add_argument("--count", type=int, metavar="N",
                     help="stop after N captured frames")
    src.add_argument("--no-promisc", action="store_true",
                     help="do not request promiscuous mode")

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="JSON report")
    out.add_argument("--ndjson", action="store_true",
                     help="one JSON finding per line")
    out.add_argument("--no-info", action="store_true",
                     help="suppress INFO posture findings in text output")
    out.add_argument("--list-codes", action="store_true",
                     help="print the finding registry and exit")
    out.add_argument("--version", action="version",
                     version="%s %s" % (MODULE_NAME, __version__))

    tun = p.add_argument_group("tuning")
    tun.add_argument("--md-ceiling", type=int, metavar="L",
                     help="highest MD level legitimate at this tap; arms "
                          "CFM-021")
    tun.add_argument("--no-vxlan", action="store_true",
                     help="do not look inside VXLAN. By default CFM carried "
                          "in an EVPN-VXLAN tunnel is decapsulated, because "
                          "a tap on the underlay otherwise sees none of the "
                          "service layer and reports it clean")
    tun.add_argument("--strict-tail", action="store_true",
                     help="treat a 4-octet non-zero tail on a minimum-length "
                          "frame as data rather than a captured FCS")
    tun.add_argument("--rate-max", type=float, default=Config.rate_max,
                     metavar="FPS", help="aggregate CFM rate threshold")
    tun.add_argument("--src-rate-max", type=float,
                     default=Config.src_rate_max, metavar="FPS",
                     help="per-source CFM rate threshold")
    tun.add_argument("--lbm-burst", type=int, default=Config.lbm_burst,
                     metavar="N", help="LBMs from one source before CFM-101")
    tun.add_argument("--data-tlv-max", type=int, default=Config.data_tlv_max,
                     metavar="OCTETS", help="Data TLV size before CFM-105")
    tun.add_argument("--tst-burst", type=int, default=Config.tst_burst,
                     metavar="N", help="TST frames from one source before "
                                       "CFM-226")
    tun.add_argument("--aps-churn", type=int, default=Config.aps_churn_min,
                     metavar="N", help="APS state changes before CFM-085")

    erps = p.add_argument_group(
        "ERPS / G.8032",
        "Ring rules need the declared topology: a legitimate protection "
        "switch and a forged R-APS are identical on the wire without it. "
        "An undeclared ring fails loud (CFM-200) rather than looking "
        "clean, and the structural rules stay armed either way.")
    erps.add_argument(
        "--ring", action="append", default=[], metavar="SPEC",
        help="declare a ring: VLAN[,rpl=MAC][,nodes=MAC/MAC/...]"
             "[,name=LABEL][,role=major|sub][,parent=LABEL]"
             "[,interconnect=MAC/MAC][,vc=yes|no][,revertive=yes|no]. "
             "VLAN is the ring control VLAN, or 'untagged', or an "
             "outer/inner QinQ pair as OUTER/INNER. Declare "
             "interconnect= to tell legitimate sub-ring topology-change "
             "propagation from a bare flush, and revertive=no on a "
             "non-revertive ring, which G.8032 does not signal on the "
             "wire. Repeatable.")
    erps.add_argument("--raps-rate-max", type=float,
                      default=Config.raps_rate_max, metavar="FPS",
                      help="per-source R-APS rate threshold (CFM-198)")
    erps.add_argument("--raps-churn", type=int,
                      default=Config.raps_churn_min, metavar="N",
                      help="R-APS state changes before CFM-197")
    erps.add_argument("--raps-flush-burst", type=int,
                      default=Config.raps_flush_burst, metavar="N",
                      help="Event/Flush messages before CFM-190")
    elmi = p.add_argument_group(
        "E-LMI (MEF 16)",
        "E-LMI names services by EVC reference while CFM state is keyed "
        "by VLAN, and the join is not reliably on the wire. Declare it to "
        "arm the cross-plane contradiction rule; undeclared fails loud "
        "(CFM-254) and the structural rules stay armed.")
    elmi.add_argument(
        "--evc", action="append", default=[], metavar="SPEC",
        help="map an EVC to a service VLAN: REFERENCE,vlan=VLAN"
             "[,name=LABEL]. VLAN may be a VLAN id, 'untagged', or an "
             "outer/inner pair as OUTER/INNER. Repeatable.")

    erps.add_argument("--rb-stale", type=float, default=Config.rb_stale,
                      metavar="S",
                      help="seconds after which an observed RPL-blocked "
                           "claim counts as stale (CFM-194/206); distinct "
                           "from the CFM-193 concurrency window")
    erps.add_argument("--ccm-loss-misses", type=float,
                      default=Config.ccm_loss_misses, metavar="N",
                      help="missed CCMs before CFM-199; G.8032 uses 3")
    return p


def parse_mac(text: str) -> bytes:
    raw = text.replace(":", "").replace("-", "").replace(".", "")
    if len(raw) != 12:
        raise ValueError("bad MAC %r" % text)
    return bytes.fromhex(raw)


def parse_evc(spec: str) -> Evc:
    """Parse one --evc declaration: REFERENCE,vlan=VLAN[,name=LABEL]."""
    parts = [x.strip() for x in spec.split(",") if x.strip()]
    if not parts:
        raise ValueError("empty --evc specification")
    try:
        ref = int(parts[0], 10)
    except ValueError:
        raise ValueError("EVC reference %r is not numeric" % parts[0])
    if not 0 <= ref <= 65535:
        raise ValueError("EVC reference %d out of range 0..65535" % ref)
    vlan: Optional[Tuple[int, ...]] = None
    label = ""
    for part in parts[1:]:
        if "=" not in part:
            raise ValueError("EVC option %r needs key=value" % part)
        key, val = part.split("=", 1)
        key = key.strip().lower()
        if key == "vlan":
            text = val.strip()
            if text.lower() in ("untagged", "none", "-"):
                vlan = ()
            else:
                try:
                    vlan = tuple(int(v, 10) for v in text.split("/") if v)
                except ValueError:
                    raise ValueError("EVC vlan %r is not numeric" % text)
                for v in vlan:
                    if not 0 <= v <= 4095:
                        raise ValueError("VLAN id %d out of range" % v)
        elif key == "name":
            label = val.strip()
        else:
            raise ValueError("unknown EVC option %r; expected vlan or name"
                             % key)
    if vlan is None:
        raise ValueError("an --evc declaration needs vlan=VLAN")
    return Evc(reference=ref, vlan=vlan, label=label)


def parse_ring(spec: str) -> Ring:
    """Parse one --ring declaration.

    VLAN[,rpl=MAC][,nodes=MAC/MAC][,name=LABEL]
    """
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        raise ValueError("empty --ring specification")
    head = parts[0]
    if head.lower() in ("untagged", "none", "-"):
        vlan: Tuple[int, ...] = ()
    else:
        try:
            vlan = tuple(int(v, 10) for v in head.split("/") if v != "")
        except ValueError:
            raise ValueError("ring VLAN %r is not numeric; expected a VLAN "
                             "id, 'untagged', or OUTER/INNER" % head)
        for v in vlan:
            if not 0 <= v <= 4095:
                raise ValueError("VLAN id %d out of range 0..4095" % v)
    rpl: Optional[bytes] = None
    nodes: List[bytes] = []
    label = ""
    role = RING_ROLE_MAJOR
    parent = ""
    interconnect: List[bytes] = []
    vc: Optional[bool] = None
    revertive = True

    def _yesno(key: str, val: str) -> bool:
        low = val.strip().lower()
        if low in ("yes", "true", "1", "on"):
            return True
        if low in ("no", "false", "0", "off"):
            return False
        raise ValueError("ring option %s needs yes or no, got %r"
                         % (key, val))

    for part in parts[1:]:
        if "=" not in part:
            raise ValueError("ring option %r needs key=value" % part)
        key, val = part.split("=", 1)
        key = key.strip().lower()
        if key == "rpl":
            rpl = parse_mac(val.strip())
        elif key == "nodes":
            nodes = [parse_mac(m.strip()) for m in val.split("/")
                     if m.strip()]
        elif key == "name":
            label = val.strip()
        elif key == "role":
            role = val.strip().lower()
            if role not in RING_ROLES:
                raise ValueError("ring role %r must be major or sub" % role)
        elif key == "parent":
            parent = val.strip()
        elif key == "interconnect":
            interconnect = [parse_mac(m.strip()) for m in val.split("/")
                            if m.strip()]
        elif key == "vc":
            vc = _yesno("vc", val)
        elif key == "revertive":
            revertive = _yesno("revertive", val)
        else:
            raise ValueError("unknown ring option %r; expected rpl, nodes, "
                             "name, role, parent, interconnect, vc or "
                             "revertive" % key)
    # An RPL owner is by definition a ring node; accepting a declaration
    # where it is absent from the node list would make CFM-195 fire on the
    # owner's own R-APS.
    if rpl is not None and nodes and rpl not in nodes:
        nodes.append(rpl)
    # Interconnection nodes are ring nodes by definition; omitting them
    # from the node list would make CFM-195 fire on their own R-APS.
    for mac in interconnect:
        if nodes and mac not in nodes:
            nodes.append(mac)
    if role == RING_ROLE_SUB and not parent:
        raise ValueError("a ring declared role=sub needs parent=LABEL")
    if parent and role != RING_ROLE_SUB:
        raise ValueError("parent= applies only to a ring with role=sub")
    return Ring(vlan=vlan, rpl_owner=rpl, nodes=tuple(nodes), label=label,
                role=role, parent=parent,
                interconnect=tuple(interconnect), virtual_channel=vc,
                revertive=revertive)


def config_from_args(args: argparse.Namespace) -> Config:
    return Config(
        strict_tail=args.strict_tail,
        vxlan=not args.no_vxlan,
        md_ceiling=args.md_ceiling,
        rate_max=args.rate_max,
        src_rate_max=args.src_rate_max,
        lbm_burst=args.lbm_burst,
        data_tlv_max=args.data_tlv_max,
        aps_churn_min=args.aps_churn,
        tst_burst=args.tst_burst,
        rings=tuple(parse_ring(spec) for spec in args.ring),
        evcs=tuple(parse_evc(spec) for spec in args.evc),
        raps_rate_max=args.raps_rate_max,
        raps_churn_min=args.raps_churn,
        raps_flush_burst=args.raps_flush_burst,
        rb_stale=args.rb_stale,
        ccm_loss_misses=args.ccm_loss_misses,
    )


def run(args: argparse.Namespace) -> int:
    engine = Engine(config_from_args(args))
    index = 0

    def warn(msg: str) -> None:
        sys.stderr.write("%s: %s\n" % (MODULE_NAME, msg))

    for path in args.pcap:
        for ts, raw in read_pcap(path):
            engine.feed_raw(raw, index, ts)
            index += 1
            if args.count is not None and index >= args.count:
                break
    if args.iface:
        # A passive monitor that throws away its capture on Ctrl-C is
        # useless for a long watch. Interrupt stops collecting and falls
        # through to the report.
        stopper = StopSignal().install()
        try:
            for ts, raw in live_capture(
                    args.iface, promisc=not args.no_promisc,
                    duration=args.duration, count=args.count,
                    should_stop=stopper, vxlan=engine.cfg.vxlan,
                    on_warn=warn):
                engine.feed_raw(raw, index, ts)
                index += 1
        except KeyboardInterrupt:
            stopper.stop = True
        if stopper.stop:
            warn("stopped by signal %s after %d frames; reporting what was "
                 "seen" % (stopper.signum, index))
    engine.finalize()

    if args.json:
        sys.stdout.write(render_json(engine))
    elif args.ndjson:
        sys.stdout.write(render_ndjson(engine))
    else:
        sys.stdout.write(render_text(engine, show_info=not args.no_info))

    worst = min((SEVERITY_ORDER[f.spec.severity] for f in engine.results()),
                default=99)
    if worst <= SEVERITY_ORDER[SEV_HIGH]:
        return 2
    if worst <= SEVERITY_ORDER[SEV_LOW]:
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_codes:
        sys.stdout.write(render_registry(as_json=args.json))
        return 0
    if not args.pcap and not args.iface:
        build_parser().error("give --pcap FILE or --iface IF")
    try:
        return run(args)
    except ValueError as exc:
        sys.stderr.write("%s: %s\n" % (MODULE_NAME, exc))
        return 3
    except ParseError as exc:
        sys.stderr.write("%s: %s\n" % (MODULE_NAME, exc))
        return 3
    except PermissionError:
        sys.stderr.write("%s: live capture needs CAP_NET_RAW\n" % MODULE_NAME)
        return 3
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
