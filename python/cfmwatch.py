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

__version__ = "0.1.0-dev"
MODULE_NAME = "cfmwatch"

# --------------------------------------------------------------------------
# Wire constants
# --------------------------------------------------------------------------

ETHERTYPE_CFM = 0x8902
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100, 0x9200)

# CFM class 1 group: 01-80-C2-00-00-3x where x = MD level (CCM, multicast LBM)
# CFM class 2 group: 01-80-C2-00-00-3(8+x) where x = MD level (LTM)
CFM_GROUP_PREFIX = (0x01, 0x80, 0xC2, 0x00, 0x00)

OP_CCM = 1
OP_LBR = 2
OP_LBM = 3
OP_LTR = 4
OP_LTM = 5
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
    OP_AIS: "AIS", OP_LCK: "LCK", OP_TST: "TST", OP_APS: "APS", OP_RAPS: "R-APS",
    OP_MCC: "MCC", OP_LMR: "LMR", OP_LMM: "LMM", OP_1DM: "1DM", OP_DMR: "DMR",
    OP_DMM: "DMM", OP_EXR: "EXR", OP_EXM: "EXM", OP_VSR: "VSR", OP_VSM: "VSM",
    OP_CSF: "CSF", OP_1SL: "1SL", OP_SLR: "SLR", OP_SLM: "SLM",
}

# Y.1731 overlay opcodes - presence marks the ITU service-OAM layer in use.
Y1731_OPCODES = frozenset({
    OP_AIS, OP_LCK, OP_TST, OP_APS, OP_RAPS, OP_MCC, OP_LMR, OP_LMM, OP_1DM,
    OP_DMR, OP_DMM, OP_EXR, OP_EXM, OP_VSR, OP_VSM, OP_CSF, OP_1SL, OP_SLR,
    OP_SLM,
})

# Minimum body length (octets after the 4-octet common header, before TLVs)
# and the First TLV Offset each opcode is specified to carry.
OPCODE_BODY: Dict[int, int] = {
    OP_CCM: 70, OP_LBR: 4, OP_LBM: 4, OP_LTR: 6, OP_LTM: 17,
    OP_AIS: 0, OP_LCK: 0, OP_TST: 4, OP_APS: 4, OP_RAPS: 32,
    OP_MCC: 4, OP_LMR: 12, OP_LMM: 12, OP_1DM: 16, OP_DMR: 32, OP_DMM: 32,
    OP_EXR: 0, OP_EXM: 0, OP_VSR: 0, OP_VSM: 0, OP_CSF: 0,
    OP_1SL: 16, OP_SLR: 16, OP_SLM: 16,
}

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

# G.8031 / G.8032 APS request-state codes (high nibble of octet 1).
APS_REQUEST_NAMES: Dict[int, str] = {
    0: "NR", 1: "DNR", 2: "RR", 4: "EXER", 5: "WTR", 7: "MS", 9: "SD",
    11: "SF", 13: "FS", 14: "SF-P", 15: "LO",
}
APS_RESERVED_REQUESTS = frozenset({3, 6, 8, 10, 12})
# Operator-intent switches: these move production traffic on demand.
APS_COMMAND_REQUESTS = frozenset({7, 13, 15})

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
    _s("CFM-086", "APS request code reserved", SEV_MEDIUM, "E", "HIGH",
       "The APS request/state nibble is a value G.8031 does not assign."),
    _s("CFM-087", "APS Lockout of protection requested", SEV_CRITICAL, "E",
       "HIGH",
       "Lockout disables the protection path entirely, so the next real "
       "fault on the working path takes the service down with no failover. "
       "Pairs naturally with a subsequent attack on the working path."),

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
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

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

    def note(self, code: str, detail: str) -> None:
        self.structural.append((code, detail))


class ParseError(Exception):
    pass


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
              strict_tail: bool = False) -> Optional[CfmFrame]:
    """Parse one Ethernet frame into a CfmFrame, or None if it is not CFM."""
    eth = parse_ethernet(raw)
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
    )
    if frame.version != 0:
        frame.note("CFM-008", "version %d" % frame.version)
    if frame.opcode not in OPCODE_NAMES:
        frame.note("CFM-007", "opcode %d unassigned" % frame.opcode)

    spec_body = OPCODE_BODY.get(frame.opcode)
    if spec_body is not None:
        if len(payload) < 4 + spec_body:
            frame.note("CFM-006",
                       "%s needs %d body octets, payload carries %d"
                       % (frame.opcode_name, spec_body, len(payload) - 4))
        if frame.first_tlv_offset != spec_body:
            frame.note("CFM-010",
                       "%s specifies First TLV Offset %d, frame declares %d"
                       % (frame.opcode_name, spec_body,
                          frame.first_tlv_offset))

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
        frame.body = {
            "request": req,
            "request_name": APS_REQUEST_NAMES.get(req, "reserved(%d)" % req),
            "protection_type": o1 & 0x0F,
            "requested_signal": o2, "bridged_signal": o3,
            "bridge_type": (o4 >> 6) & 0x03,
        }
    elif op in (OP_LMM, OP_LMR):
        if avail < 12:
            return
        txf, rxf, txb = struct.unpack_from("!III", p, 4)
        frame.body = {"tx_fcf": txf, "rx_fcf": rxf, "tx_fcb": txb}


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
        self.aps_groups: Dict[Tuple[Any, int], Dict[str, Any]] = {}
        self.lbm_hist: Dict[bytes, deque] = defaultdict(deque)
        self.ltm_hist: Dict[bytes, deque] = defaultdict(deque)
        self.rate_hist: deque = deque()
        self.src_hist: Dict[bytes, deque] = defaultdict(deque)
        self.src_clean: Dict[bytes, int] = defaultdict(int)

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
        frame = parse_cfm(raw, index, ts, strict_tail=self.cfg.strict_tail)
        if frame is None:
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

    # -- Class C -----------------------------------------------------------

    def _ccm(self, frame: CfmFrame) -> None:
        body = frame.body
        if not body:
            return
        mepid = body["mepid"]
        mk = body["maid_key"]
        interval = body["interval"]
        vkey = frame.vlan_key
        src = frame.src

        if body["rdi"]:
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
                       "vlan": list(vkey), "md_level": frame.md_level,
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
            "vlan": list(vkey),
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
        vkey = frame.vlan_key
        period = frame.body.get("period", 0)
        name = frame.opcode_name
        src = frame.src

        if op == OP_AIS:
            self.emit("CFM-060", "%s/level%d" % (str(vkey), frame.md_level),
                      "AIS from %s at MD level %d"
                      % (mac_str(src), frame.md_level), frame,
                      {"src": mac_str(src), "md_level": frame.md_level,
                       "vlan": list(vkey)})
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
                      {"src": mac_str(src), "vlan": list(vkey),
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
                       "healthy_levels": lvls, "vlan": list(vkey)})

    # -- Class E -----------------------------------------------------------

    def _aps(self, frame: CfmFrame) -> None:
        body = frame.body
        if not body:
            return
        vkey = frame.vlan_key
        gkey = (vkey, frame.md_level)
        gname = "%s/level%d" % (str(vkey), frame.md_level)
        req = body["request"]
        src = frame.src

        self.emit("CFM-080", gname,
                  "APS on %s, request %s from %s"
                  % (gname, body["request_name"], mac_str(src)), frame,
                  {"src": mac_str(src), "request": body["request_name"],
                   "md_level": frame.md_level, "vlan": list(vkey)})

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
                      "APS request code %d is unassigned by G.8031" % req,
                      frame, {"src": mac_str(src), "request": req})
        if req == 13:
            self.emit("CFM-081", gname,
                      "Forced Switch requested on %s by %s"
                      % (gname, mac_str(src)), frame,
                      {"src": mac_str(src), "group": gname})
        elif req == 7:
            self.emit("CFM-082", gname,
                      "Manual Switch requested on %s by %s"
                      % (gname, mac_str(src)), frame,
                      {"src": mac_str(src), "group": gname})
        elif req == 15:
            self.emit("CFM-087", gname,
                      "Lockout of protection requested on %s by %s"
                      % (gname, mac_str(src)), frame,
                      {"src": mac_str(src), "group": gname})
        elif req in (11, 14):
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


# Kernel-side prefilter: EtherType 0x8902 at the outer position or behind
# up to two VLAN tags. Keeps a carrier tap from copying every frame on the
# segment into userspace.
_BPF_CFM = [
    (0x28, 0, 0, 12),
    (0x15, 13, 0, ETHERTYPE_CFM),
    (0x15, 3, 0, 0x8100),
    (0x15, 2, 0, 0x88A8),
    (0x15, 1, 0, 0x9100),
    (0x06, 0, 0, 0),
    (0x28, 0, 0, 16),
    (0x15, 7, 0, ETHERTYPE_CFM),
    (0x15, 3, 0, 0x8100),
    (0x15, 2, 0, 0x88A8),
    (0x15, 1, 0, 0x9100),
    (0x06, 0, 0, 0),
    (0x28, 0, 0, 20),
    (0x15, 1, 0, ETHERTYPE_CFM),
    (0x06, 0, 0, 0),
    (0x06, 0, 0, 0x40000),
]


def _bpf_blob() -> Tuple[bytes, int]:
    prog = b"".join(struct.pack("HBBI", *ins) for ins in _BPF_CFM)
    return prog, len(_BPF_CFM)


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


def live_capture(iface: str, promisc: bool = True,
                 snaplen: int = 2048,
                 duration: Optional[float] = None,
                 count: Optional[int] = None,
                 should_stop: Optional[Any] = None,
                 on_warn: Optional[Any] = None) -> Iterator[Tuple[float, bytes]]:
    """Yield (timestamp, frame) from a live interface. Receive only."""
    import ctypes
    import socket

    ETH_P_ALL = 0x0003
    SO_ATTACH_FILTER = 26
    SOL_PACKET = 263
    PACKET_ADD_MEMBERSHIP = 1
    PACKET_MR_PROMISC = 1

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    try:
        prog, length = _bpf_blob()
        buf = ctypes.create_string_buffer(prog)
        fprog = struct.pack("HxxxxxxP" if ctypes.sizeof(ctypes.c_void_p) == 8
                            else "HxxP", length, ctypes.addressof(buf))
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        except OSError as exc:
            if on_warn:
                on_warn("kernel filter not attached (%s); filtering in "
                        "userspace" % exc)
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
    tun.add_argument("--aps-churn", type=int, default=Config.aps_churn_min,
                     metavar="N", help="APS state changes before CFM-085")
    return p


def config_from_args(args: argparse.Namespace) -> Config:
    return Config(
        strict_tail=args.strict_tail,
        md_ceiling=args.md_ceiling,
        rate_max=args.rate_max,
        src_rate_max=args.src_rate_max,
        lbm_burst=args.lbm_burst,
        data_tlv_max=args.data_tlv_max,
        aps_churn_min=args.aps_churn,
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
                    should_stop=stopper, on_warn=warn):
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
