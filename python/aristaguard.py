#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aristaguard - "Arista Switch and Router Guard"

Passive detector for a tracked Arista EOS CVE set across switches, routers,
edge and core devices.  Part of the Ragnar passive network security suite.

PASSIVE INVARIANT
    This module NEVER transmits.  It has no injector, no socket imports, no
    subprocess use, and no transmit primitives.  scapy is imported lazily
    inside run_capture() only, so every offline tier (parser, engine,
    self-test) runs pure-python with no third-party dependency.  The
    invariant is enforced structurally by an AST guard in the self-test
    (see test_passive_invariant), not by grep.

SCOPE
    Arista EOS on switches / routers / edge / core ONLY.

    Non-EOS Arista products are ACTIVELY SCREENED OUT, not merely unlisted:
    VeloCloud Orchestrator, CloudVision Portal, CloudVision eXchange as a
    management target, NG Firewall (Edge Threat Management), DANZ Monitoring
    Fabric, Wi-Fi Access Points and Awake NDR all raise AG-009 and are
    excluded from CVE screening.  (CVX appears in-scope only in its EOS-side
    role: CVE-2025-5089 crashes Sysdb on the EOS switch, not on CVX.)

SEVERITY FLOOR
    CVSSv3.1 >= 6.5, with an explicit exploitation override: a CVE flagged
    exploited=True is carried regardless of score.  CVE-2026-7473 is the
    reason that override exists here - 5.8 on v3.1, actively exploited, and
    Arista has stated no patch is planned.

Version: 0.1.0-dev
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import re
import struct
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Iterable, Optional

__version__ = "0.1.0-dev"
DISPLAY_NAME = "Arista Switch and Router Guard"

# ---------------------------------------------------------------------------
# CVE catalog
# ---------------------------------------------------------------------------
#
# Every entry records, per the ciscoguard convention:
#
#   cvss              CVSSv3.1 base score AS PUBLISHED IN THE ARISTA ADVISORY.
#                     Where NVD or a third party disagrees, the disagreement
#                     is recorded in `note` rather than silently averaged.
#
#   detect            What a passive tap can HONESTLY do about this CVE:
#                       attack     - an exploitation primitive is directly
#                                    observable on the wire
#                       heuristic  - a structural anomaly correlates with
#                                    exploitation but the vendor has not
#                                    published the exact malformation
#                       exposure   - the enabling CONDITION is visible even
#                                    though the exploit itself is not
#                       posture    - version screening only
#                       none       - no network-observable signal exists,
#                                    even in principle
#
#   score_confidence  advisory   - number read from the Arista advisory
#                     secondary  - number from a non-vendor source; RE-VERIFY
#                                  before it drives a patch SLA
#
#   exploited         confirmed exploitation in the wild
#
# A CVE with detect="none" is carried so that posture screening can still
# report it, and so that "aristaguard covers 17 CVEs" can never quietly come
# to mean "aristaguard has 17 detection rules".  It does not.


@dataclass(frozen=True)
class CVEEntry:
    cve: str
    cvss: float
    advisory: str
    title: str
    detect: str
    score_confidence: str
    codes: tuple[str, ...] = ()
    exploited: bool = False
    products: tuple[str, ...] = ("EOS",)
    versions: Optional[tuple] = None
    note: str = ""


CVE_CATALOG: tuple[CVEEntry, ...] = (
    CVEEntry(
        cve="CVE-2023-24509",
        cvss=9.3,
        advisory="SA-0082",
        title="Standby supervisor root login / privilege escalation on modular platforms",
        detect="none",
        score_confidence="advisory",
        codes=("AG-004",),
        note=(
            "AV:L. Requires valid user credentials, BOTH supervisor modules inserted "
            "and active, and redundancy configured as RPR or SSO. The escalation "
            "happens as a login to the standby supervisor - it never crosses the "
            "wire, so no network sensor can observe it even in principle. "
            "NVD scores this 7.8 (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) "
            "against Arista's 9.3 (S:C, PR:N); the advisory number is used here. "
            "POSTURE ONLY - AG-004 reports the platform/redundancy exposure, "
            "never an exploitation verdict."
        ),
    ),
    CVEEntry(
        cve="CVE-2025-1260",
        cvss=9.1,
        advisory="SA-0111",
        title="gNOI Set request executed when it should have been rejected",
        detect="exposure",
        score_confidence="advisory",
        codes=("AG-103", "AG-002"),
        note=(
            "Requires OpenConfig enabled with a gNOI server. gNMI/gNOI is gRPC over "
            "TLS, so the request itself is unreadable from a passive tap - only the "
            "listener, the TLS SNI and the certificate CN are observable. Hence "
            "exposure, not attack. Arista's own workaround is per-RPC authorization "
            "denying OpenConfig.Set."
        ),
    ),
    CVEEntry(
        cve="CVE-2024-3596",
        cvss=9.0,
        advisory="SA-0101",
        title="RADIUS protocol forgery (BlastRADIUS)",
        detect="attack",
        score_confidence="advisory",
        codes=("AG-101", "AG-102", "AG-110", "AG-201", "AG-212", "AG-213",
               "AG-214"),
        note=(
            "STRONGEST signature in this module. RADIUS/UDP is cleartext, so BOTH "
            "the vulnerable precondition (no Message-Authenticator, attribute 80) "
            "and the attack itself (an oversized attacker-controlled attribute "
            "carrying the chosen-prefix collision block) are directly on the wire. "
            "EOS 4.34.0F and older affected, BUG1130020. "
            "TWO LEGS, TWO RULE SETS: a tap sees only one side of the attacker. "
            "AG-201 (Proxy-State total) covers the attacker->SERVER leg, where the "
            "colliding Access-Reject must use Proxy-State because a server echoes "
            "it back unchanged. AG-212/213/214 cover the attacker->NAS leg, where "
            "the forged Access-Accept arrives and, per blastradius.fail, may carry "
            "the collision data in Vendor-Specific or Reply-Message instead."
        ),
        versions=(("4", "0", "4.34.1F", "advisory"),),
    ),
    CVEEntry(
        cve="CVE-2024-6387",
        cvss=8.1,
        advisory="SA-0100",
        title="OpenSSH sshd signal handler race condition (regreSSHion)",
        detect="exposure",
        score_confidence="advisory",
        codes=("AG-104", "AG-210"),
        note=(
            "The SSH identification string is sent BEFORE encryption is negotiated, "
            "so the OpenSSH version is fully readable passively - this is a real "
            "exposure signature, not an inference. The exploit itself is a timing "
            "race against LoginGraceTime and is only heuristically visible "
            "(AG-210). EOS: 4.32.1F and below in the 4.32.x train ONLY; 4.31.x and "
            "below are explicitly NOT impacted."
        ),
        versions=(("4.32", "4.32.0", "4.32.2F", "advisory"),),
    ),
    CVEEntry(
        cve="CVE-2025-8873",
        cvss=7.5,
        advisory="SA-0127",
        title="Crafted packet halts all IPsec dataplane processing",
        detect="exposure",
        score_confidence="advisory",
        codes=("AG-105", "AG-002"),
        note=(
            "Requires IPsec configured. ESP/IKE presence is observable, so the "
            "precondition screens cleanly - but the crafted packet is inside the "
            "IPsec path and Arista has not published the malformation, so no attack "
            "signature is possible. Remediation additionally requires a TCAM "
            "profile change (ipsec-egress-padding-removal), which a version match "
            "alone cannot confirm has been applied."
        ),
    ),
    CVEEntry(
        cve="CVE-2024-9448",
        cvss=7.5,
        advisory="SA-0112",
        title="Untagged packets do not hit configured Traffic Policy rules",
        detect="heuristic",
        score_confidence="advisory",
        codes=("AG-206",),
        note=(
            "A drop rule silently forwards instead. From a single tap the bypass is "
            "only visible as untagged traffic reaching a destination the operator "
            "declared policy-blocked - which needs operator-supplied policy intent "
            "(cfg.policy_blocked) to mean anything. Without it AG-206 stays silent "
            "rather than guessing."
        ),
    ),
    CVEEntry(
        cve="CVE-2023-24545",
        cvss=7.5,
        advisory="SA-0085",
        title="CloudEOS Software Forwarding Engine packet-buffer leak (DoS)",
        detect="posture",
        score_confidence="advisory",
        codes=("AG-003",),
        products=("CloudEOS",),
        note=(
            "CloudEOS ONLY - the virtual/software router, not hardware EOS. The Sfe "
            "does not exist on ASIC platforms. 'Malformed packets' is as specific as "
            "the advisory gets, so there is no malformation to sign against; a "
            "generic malformed-packet rule here would fire on ordinary damaged "
            "traffic. Posture only, gated on a CloudEOS platform identification."
        ),
    ),
    CVEEntry(
        cve="CVE-2025-1259",
        cvss=7.1,
        advisory="SA-0111",
        title="gNOI Get request executed when it should have been rejected",
        detect="exposure",
        score_confidence="advisory",
        codes=("AG-103", "AG-002"),
        note=(
            "Companion to CVE-2025-1260, same advisory and same precondition "
            "(OpenConfig with a gNOI server). Data disclosure rather than config "
            "change. Same TLS opacity, same exposure-not-attack classification."
        ),
    ),
    CVEEntry(
        cve="CVE-2024-6409",
        cvss=7.0,
        advisory="SA-0100",
        title="OpenSSH signal handler race in the privsep child",
        detect="exposure",
        score_confidence="advisory",
        codes=("AG-104", "AG-210"),
        note=(
            "Found during the audit that followed regreSSHion. Wider EOS exposure "
            "than CVE-2024-6387: 4.34.0F and below in 4.34.x, 4.33.3.1F and below "
            "in 4.33.x, 4.32.5.1M and below in 4.32.x. 4.31.x and below not "
            "impacted."
        ),
        versions=(
            ("4.34", "4.34.0", "4.34.1F", "advisory"),
            ("4.33", "4.33.0", "4.33.3.2F", "advisory"),
            ("4.32", "4.32.0", "4.32.5.2M", "advisory"),
        ),
    ),
    CVEEntry(
        cve="CVE-2024-5872",
        cvss=6.5,
        advisory="SA-0106",
        title="Packet with incorrect VLAN tag copied to CPU",
        detect="heuristic",
        score_confidence="advisory",
        codes=("AG-205",),
        note=(
            "Consequences named by the advisory are control-plane: route flaps, "
            "multicast routes learnt. The trigger is a VLAN tag inconsistent with "
            "the port's configuration - observable as a tag anomaly, but the exact "
            "malformation is not published, so this is a structural heuristic and "
            "is documented as such."
        ),
    ),
    CVEEntry(
        cve="CVE-2024-11185",
        cvss=6.5,
        advisory="SA-0118",
        title="Layer 2 ingress forwarded to ports in other VLANs",
        detect="heuristic",
        score_confidence="advisory",
        codes=("AG-207",),
        note=(
            "A breach of VLAN isolation is by definition only visible from a tap on "
            "the RECEIVING VLAN - a single sensor sees a frame whose source MAC it "
            "has previously only ever seen on another VLAN. Requires the sensor to "
            "have observed both VLANs. CWE-1189, an SoC shared-resource isolation "
            "failure. Advisory notes traffic expected to switch in VLAN 1 may be "
            "routed to the default VRF instead."
        ),
    ),
    CVEEntry(
        cve="CVE-2024-6858",
        cvss=6.5,
        advisory="SA-0103",
        title="802.1X multi-auth bypass via an EAPOL-capable device in the fallback VLAN",
        detect="exposure",
        score_confidence="advisory",
        codes=("AG-107", "AG-208"),
        note=(
            "DOWNGRADED FROM detect=attack. EAPOL is cleartext, so the EAPOL half "
            "of the precondition is directly observable (AG-107) - but the bypass "
            "itself is unauthenticated hosts riding the port AFTER a legitimate "
            "authentication, which needs per-port state and a port identity a SPAN "
            "tap does not reliably expose. AG-208 is therefore declared unwired "
            "rather than shipped as a rule that fires on any EAPOL. The catalog "
            "self-test caught this entry claiming detect=attack while every AG-2xx "
            "code it names was unwired. AV:A (adjacent) - which on a colo access "
            "segment means the sensor own broadcast domain."
        ),
    ),
    CVEEntry(
        cve="CVE-2023-24513",
        cvss=6.5,
        advisory="SA-0085",
        title="CloudEOS Software Forwarding Engine size-check bypass / buffer over-read",
        detect="posture",
        score_confidence="advisory",
        codes=("AG-003",),
        products=("CloudEOS",),
        note=(
            "CloudEOS ONLY, same advisory and same Sfe component as CVE-2023-24545. "
            "CWE-126 buffer over-read reached by truncated packets. Truncation alone "
            "is far too common on a real segment to sign against without a false "
            "positive rate that would bury every other finding."
        ),
    ),
    CVEEntry(
        cve="CVE-2025-8872",
        cvss=6.5,
        advisory="SA-0128",
        title="Crafted packet drives OSPFv3 process CPU high, forcing a restart",
        detect="heuristic",
        score_confidence="advisory",
        codes=("AG-109", "AG-209"),
        note=(
            "CVSSv4.0 is 7.1 for this one; the v3.1 number is used for the floor. "
            "Requires OSPFv3 configured in the default or a non-default VRF with at "
            "least one neighbour present. OSPFv3 is on the wire and the adjacency is "
            "cleanly observable (AG-109), but Arista does not publish the "
            "malformation - the same position juniperwatch documented for the whole "
            "RPD/BGP family - so AG-209 is a structural LSA anomaly heuristic, not "
            "a signature."
        ),
    ),
    CVEEntry(
        cve="CVE-2025-0936",
        cvss=6.5,
        advisory="SA-0117",
        title="gNOI File TransferToRemote credentials logged to local or remote accounting",
        detect="attack",
        score_confidence="advisory",
        codes=("AG-103", "AG-211"),
        note=(
            "Unusual among the management-plane CVEs in that the LEAK, unlike the "
            "gNOI call that causes it, is not inside TLS: the credentials land in "
            "accounting records, and TACACS+ accounting is trivially decodable while "
            "RADIUS accounting is cleartext. AG-211 detects the credential material "
            "in an accounting record on the wire. Credentials are NEVER logged by "
            "this module - the finding records lengths and attribute identity only."
        ),
    ),
    CVEEntry(
        cve="CVE-2025-5089",
        cvss=6.5,
        advisory="SA-0126",
        title="EOS Sysdb agent crash from malformed messages sent by a connected CVX server",
        detect="exposure",
        score_confidence="advisory",
        codes=("AG-108", "AG-002"),
        note=(
            "In scope because the CRASH IS ON THE EOS SWITCH (Sysdb agent crash "
            "causing a soft reset), even though the malformed message originates at "
            "CVX. Advisory notes the CVX control channel has no TLS support (tracked "
            "as RFE1294850), so the session is observable - but the message format "
            "is proprietary and undocumented, so exposure only. Switches not "
            "connected to a CVX server are not affected at all."
        ),
    ),
    CVEEntry(
        cve="CVE-2026-7473",
        cvss=5.8,
        advisory="SA-0137",
        title="Tunnel decapsulation does not verify tunnel protocol type",
        detect="attack",
        score_confidence="advisory",
        codes=("AG-005", "AG-006", "AG-106", "AG-203"),
        exploited=True,
        note=(
            "THE EXPLOITATION-OVERRIDE CASE. 5.8 on CVSSv3.1 - below this module's "
            "6.5 floor - while being the only CVE in the set with confirmed "
            "exploitation, and Arista has stated no patch is planned. Carried via "
            "Config.always_include_exploited, exactly as ciscoguard carries "
            "CVE-2024-20399 at 6.0. CVSSv4.0 is 6.8; SecurityWeek reports 6.9, "
            "which is a secondary number and is NOT what the floor logic uses. "
            "Detection is genuinely strong: a device configured to decapsulate one "
            "tunnel type also accepts other tunnel protocols destined to the same "
            "IP, so an unexpected protocol arriving at a known decap endpoint is "
            "directly observable. Affects 7020R, 7280R/R2, 7500R/R2; certain "
            "IP-in-IPv6 and GUE IPv6 decap-group cases also affect 7280R3, 7500R3 "
            "and 7800R3."
        ),
    ),
)


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------
#
# CVEs that were raised in discussion but could NOT be confirmed against an
# Arista advisory, or whose CVSS could not be sourced.  They are recorded here
# with a written reason so that they are never silently promoted into the
# catalog, and so a later pass knows exactly what to go and verify.
#
# This list existing is the point.  A detector that quietly carries an
# unverified CVE is worse than one that carries fewer.

QUARANTINED_CVES: tuple[tuple[str, str], ...] = (
    (
        "CVE-2024-27890",
        "No Arista advisory, NVD record or third-party source could be found for "
        "this identifier at all. It was described in discussion as a 9.6 gNMI Set "
        "authorization bypass, which is almost certainly a conflation of "
        "CVE-2025-1260 (SA-0111, gNOI Set authorization, 9.1) or CVE-2023-24512 "
        "(gNMI arbitrary config update via TerminAttr). Do not build against it.",
    ),
    (
        "CVE-2020-15897",
        "Described in discussion as an Arista IS-IS malformed-LSP crash. No Arista "
        "advisory associating this identifier with EOS could be found. IS-IS "
        "coverage for Arista platforms should be revisited from the advisory index "
        "directly rather than from this identifier.",
    ),
    (
        "CVE-2024-12378",
        "Described in discussion as a secure-VXLAN plaintext fallback after a "
        "Tunnelsec agent restart. No source found. If a real advisory exists it "
        "would pair well with AG-106/AG-203, so this is worth re-checking against "
        "the Arista advisory index.",
    ),
    (
        "CVE-2026-11704",
        "Real - it appears in SA-0143 alongside CVE-2026-11705, CVE-2026-52896, "
        "CVE-2026-52897 and CVE-2026-52898. But that advisory publishes six CVSS "
        "scores without an unambiguous mapping to the five CVE identifiers, so the "
        "8.8 figure quoted in discussion is a GUESS at the pairing. The whole "
        "SA-0143 TerminAttr family needs the advisory read end to end before any of "
        "it enters the catalog.",
    ),
    (
        "CVE-2025-6188",
        "Real - SA-0121, maliciously formed UDP packets with source port 3503 "
        "(LspPing Echo Reply) accepted by EOS, CWE-290 authentication bypass by "
        "spoofing. No published CVSS could be located from Arista or NVD, so it "
        "cannot be placed against the 6.5 floor. NOTE: if it does clear the floor "
        "this is a strong AG-2xx candidate - a fixed source port is about as clean "
        "a passive signature as exists.",
    ),
    (
        "CVE-2023-24548",
        "Real per NVD - EOS with VXLAN configured, malformed or truncated packets "
        "over a VXLAN tunnel leave egress ports unable to forward. No CVSS could be "
        "sourced. Same floor problem as CVE-2025-6188. Would pair with AG-106.",
    ),
)


# ---------------------------------------------------------------------------
# Finding codes
# ---------------------------------------------------------------------------
#
#   AG-0xx  POSTURE   version / platform fingerprint screened against the
#                     catalog.  Always a NOTE - "verify THIS device" - never a
#                     vulnerable/not-vulnerable verdict.
#   AG-1xx  EXPOSURE  the enabling CONDITION for a CVE is visibly present.
#                     Actionable without knowing the version.
#   AG-2xx  ATTACK    an exploitation primitive was observed in transit.


@dataclass(frozen=True)
class FindingSpec:
    code: str
    name: str
    severity: str
    klass: str
    cves: tuple[str, ...] = ()
    pivot: tuple[str, ...] = ()


FINDINGS: dict[str, FindingSpec] = {f.code: f for f in (
    # ---- POSTURE -------------------------------------------------------
    FindingSpec("AG-001", "EOS_VERSION_OBSERVED", "INFO", "posture"),
    FindingSpec("AG-002", "EOS_VULNERABLE_VERSION", "MEDIUM", "posture",
                ("CVE-2024-3596", "CVE-2024-6387", "CVE-2024-6409",
                 "CVE-2025-1259", "CVE-2025-1260", "CVE-2025-8873",
                 "CVE-2025-5089")),
    FindingSpec("AG-003", "CLOUDEOS_VULNERABLE_VERSION", "MEDIUM", "posture",
                ("CVE-2023-24545", "CVE-2023-24513")),
    FindingSpec("AG-004", "SUPERVISOR_REDUNDANCY_PRIVESC_EXPOSURE", "INFO", "posture",
                ("CVE-2023-24509",)),
    FindingSpec("AG-005", "EOS_PLATFORM_OBSERVED", "INFO", "posture"),
    FindingSpec("AG-006", "TUNNEL_DECAP_PLATFORM_AT_RISK", "MEDIUM", "posture",
                ("CVE-2026-7473",)),
    FindingSpec("AG-009", "OUT_OF_SCOPE_PLATFORM", "INFO", "posture"),

    # ---- EXPOSURE ------------------------------------------------------
    FindingSpec("AG-101", "RADIUS_CLEARTEXT_OBSERVED", "MEDIUM", "exposure",
                ("CVE-2024-3596",), ("snmpwatch",)),
    FindingSpec("AG-102", "RADIUS_NO_MESSAGE_AUTHENTICATOR", "HIGH", "exposure",
                ("CVE-2024-3596",)),
    FindingSpec("AG-103", "GNMI_GNOI_LISTENER_OBSERVED", "MEDIUM", "exposure",
                ("CVE-2025-1259", "CVE-2025-1260", "CVE-2025-0936"), ("tlswatch",)),
    FindingSpec("AG-104", "SSH_VULNERABLE_BANNER", "HIGH", "exposure",
                ("CVE-2024-6387", "CVE-2024-6409")),
    FindingSpec("AG-105", "IPSEC_DATAPLANE_PRESENT", "LOW", "exposure",
                ("CVE-2025-8873",)),
    FindingSpec("AG-106", "VXLAN_DECAP_ENDPOINT_OBSERVED", "LOW", "exposure",
                ("CVE-2026-7473",)),
    FindingSpec("AG-107", "DOT1X_FALLBACK_VLAN_EAPOL", "MEDIUM", "exposure",
                ("CVE-2024-6858",), ("dtpwatch",)),
    FindingSpec("AG-108", "CVX_SESSION_OBSERVED", "MEDIUM", "exposure",
                ("CVE-2025-5089",)),
    FindingSpec("AG-109", "OSPFV3_ADJACENCY_OBSERVED", "LOW", "exposure",
                ("CVE-2025-8872",), ("ospfwatch",)),
    FindingSpec("AG-110", "RADIUS_RESPONSE_UNAUTHENTICATED", "HIGH", "exposure",
                ("CVE-2024-3596",)),

    # ---- ATTACK --------------------------------------------------------
    FindingSpec("AG-201", "RADIUS_FORGERY_ATTEMPT", "CRITICAL", "attack",
                ("CVE-2024-3596",)),
    FindingSpec("AG-203", "TUNNEL_PROTOCOL_MISMATCH_DECAP", "HIGH", "attack",
                ("CVE-2026-7473",)),
    FindingSpec("AG-205", "VLAN_TAG_ANOMALY_CPU_PUNT", "MEDIUM", "attack",
                ("CVE-2024-5872",), ("dtpwatch", "vtpwatch")),
    FindingSpec("AG-206", "UNTAGGED_POLICY_BYPASS_SUSPECT", "MEDIUM", "attack",
                ("CVE-2024-9448",)),
    FindingSpec("AG-207", "VLAN_ISOLATION_BREACH_SUSPECT", "HIGH", "attack",
                ("CVE-2024-11185",), ("dtpwatch", "macwatch")),
    FindingSpec("AG-208", "DOT1X_MULTIAUTH_BYPASS_SUSPECT", "HIGH", "attack",
                ("CVE-2024-6858",)),
    FindingSpec("AG-209", "OSPFV3_MALFORMED_LSA", "MEDIUM", "attack",
                ("CVE-2025-8872",), ("ospfwatch",)),
    FindingSpec("AG-210", "SSH_RACE_TIMING_SUSPECT", "LOW", "attack",
                ("CVE-2024-6387", "CVE-2024-6409")),
    FindingSpec("AG-211", "GNOI_CREDENTIAL_IN_ACCOUNTING", "CRITICAL", "attack",
                ("CVE-2025-0936",)),
    FindingSpec("AG-212", "RADIUS_PROXY_STATE_INJECTED", "CRITICAL", "attack",
                ("CVE-2024-3596",)),
    FindingSpec("AG-213", "RADIUS_REPLY_MESSAGE_MALFORMED", "HIGH", "attack",
                ("CVE-2024-3596",)),
    FindingSpec("AG-214", "RADIUS_OPAQUE_VENDOR_ATTRIBUTE", "HIGH", "attack",
                ("CVE-2024-3596",)),
)}


# ---------------------------------------------------------------------------
# Codes with no detection rule wired
# ---------------------------------------------------------------------------
#
# Declared here, in the module, so that the conformance harness and the
# sealed-namespace lab read ONE source rather than each keeping their own
# list that can drift.  Each entry carries a written reason; the self-test
# asserts the reasons are substantive and that no unwired code is claimed as
# a detection anywhere.
#
# legacywatch precedent (LAB_DEFERRED_CODES): a declared gap with a reason is
# honest; a silently-absent rule is not.

UNWIRED_CODES: dict[str, str] = {
    "AG-208": (
        "DOT1X_MULTIAUTH_BYPASS_SUSPECT. Detection needs correlation between "
        "an EAPOL exchange and subsequent traffic from a DIFFERENT, "
        "unauthenticated MAC on the same physical port - which requires "
        "per-port state this build does not carry, and a port identity a "
        "SPAN tap does not reliably expose. AG-107 covers the exposure half "
        "of CVE-2024-6858 today. Left declared rather than shipping a rule "
        "that fires on any EAPOL at all."
    ),
    "AG-210": (
        "SSH_RACE_TIMING_SUSPECT. regreSSHion is a timing race against "
        "LoginGraceTime; telling it apart from an ordinary aborted SSH "
        "session needs per-flow timing state and TCP reassembly, neither of "
        "which this build has. AG-104 covers the banner-based exposure, "
        "which is the reliable half and does not depend on timing at all."
    ),
}

# Numbers permanently retired. A retired code is NEVER reused: an operator
# with an old alert, a saved search or a dashboard panel keyed on AG-202 must
# never silently start matching a different finding. mikrotikwatch's MTK-015
# set this precedent.
RETIRED_CODES: dict[str, str] = {
    "AG-202": (
        "Was RADIUS_RESPONSE_UNAUTHENTICATED, classed as ATTACK. A response "
        "carrying no Message-Authenticator is the standing condition of every "
        "unhardened RADIUS server, not an attack event - and because "
        "known_infra deliberately scopes EXPOSURE only, an attack-class code "
        "could not be scoped at all, making it unsuppressable noise on a "
        "multi-tenant tap. Reclassified to EXPOSURE and renumbered to AG-110, "
        "which also picked up the D3 Message-Authenticator POSITION check. "
        "AG-202 must never be reused."
    ),
}

# Codes that cannot be validated over a Linux AF_PACKET capture path with the
# default filter, for a REASON IN THE CAPTURE STACK rather than a gap in the
# rule.  legacywatch precedent: its radiotap-header codes are deferred because
# mac80211_hwsim regenerates that header on receive; same shape of cause.
LAB_DEFERRED_CODES: dict[str, str] = {
    "AG-207": (
        "Needs SINGLY-tagged frames. On Linux the kernel strips the outer "
        "802.1Q tag into packet auxdata before the BPF program runs, so a "
        "singly-tagged IPv4 frame presents to the filter as plain 0x0800 and "
        "no port/protocol term can admit it. The tag IS restored by libpcap "
        "before the parser sees it, so the RULE is correct - only the filter "
        "is blind. Measured, not assumed: with an identical filter string "
        "tcpdump captured these frames and scapy did not, because scapy "
        "compiles against a dead pcap handle that cannot consult "
        "SKF_AD_VLAN_TAG. Set vlan_broad_capture=True to validate it live, "
        "at the cost of admitting all IP traffic."
    ),
}

# Platforms that are Arista but NOT in this module's scope.  Screened OUT
# actively (AG-009), never merely absent from the catalog.
OUT_OF_SCOPE_PLATFORM_RE = re.compile(
    r"(velocloud|\bvco\b|cloudvision\s+portal|\bcvp\b|"
    r"ng\s*firewall|\bngfw\b|edge\s+threat\s+management|"
    r"danz\s+monitoring|\bdmf\b|converged\s+cloud\s+fabric|\bccf\b|"
    r"awake|network\s+detection\s+and\s+response|"
    r"arista\s+ap\b|\bc-?\d{3}\b\s*access\s*point|wireless\s+access\s+point)",
    re.IGNORECASE,
)

# Platform families named by SA-0137 for CVE-2026-7473.
TUNNEL_DECAP_AFFECTED_RE = re.compile(
    r"\b(7020R|7280R2?|7500R2?)\b", re.IGNORECASE)
TUNNEL_DECAP_R3_RE = re.compile(
    r"\b(7280R3|7500R3|7800R3)\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class Config:
    # --- severity floor -------------------------------------------------
    min_cvss: float = 6.5
    # An exploited CVE is carried regardless of score.  CVE-2026-7473 is 5.8
    # on CVSSv3.1, is actively exploited, and has no patch planned.  Turning
    # this off removes the one CVE in the set with confirmed exploitation.
    always_include_exploited: bool = True

    # --- ports ----------------------------------------------------------
    radius_auth_ports: tuple[int, ...] = (1812, 1645)
    radius_acct_ports: tuple[int, ...] = (1813, 1646)
    tacacs_ports: tuple[int, ...] = (49,)
    gnmi_ports: tuple[int, ...] = (6030, 9339, 50051)
    cvx_ports: tuple[int, ...] = (9979,)
    vxlan_ports: tuple[int, ...] = (4789, 8472)
    ssh_ports: tuple[int, ...] = (22,)

    # --- thresholds -----------------------------------------------------
    # BlastRADIUS needs a large attacker-controlled attribute to carry the
    # chosen-prefix collision block. Proxy-State is the canonical vehicle
    # because a server echoes it back verbatim. This bound is the PER-PACKET
    # TOTAL across every Proxy-State attribute, not a per-attribute limit -
    # a per-attribute limit was evaded by splitting the block across four
    # 100-byte attributes (D2), and keying on any attribute type fired on
    # ordinary 255-byte EAP-Message fragments (D1).
    # STRUCTURAL ANOMALY BOUND, not a published exploit constant.
    radius_proxy_state_total_max: int = 128

    # ---- RADIUS scope: Arista hardware only --------------------------------
    # rule_radius was never vendor-gated and so ran suite-wide; the vendor-
    # neutral copy now lives in the radiuswatch module. Here the Blast-RADIUS
    # rules (AG-101/102/110/201/212/213/214) are kept but LIMITED to Arista
    # devices: a RADIUS exchange is only evaluated when one of its endpoint IPs
    # is a known Arista NAS/RADIUS address. Addresses are learned passively
    # from an Arista device's LLDP management-address TLV, and may also be
    # named here for the common case where the NAS sources RADIUS from an
    # interface whose address is not the one it advertises in LLDP. EMPTY by
    # default: with nothing learned and nothing configured the RADIUS rules
    # stay SILENT rather than firing on every vendor's traffic (the
    # policy_blocked discipline). Set to any string containing "*" to restore
    # the old suite-wide behaviour deliberately.
    radius_arista_endpoints: tuple[str, ...] = ()

    # ---- F2: opaque-attribute classification -------------------------------
    # MEASURED for RADIUS attribute sizes; see classify_opacity(). The gap
    # between print_run_max and cleartext_print_run_min is an "unknown" band
    # that emits nothing. STRUCTURAL ANOMALY BOUNDS, not published exploit
    # constants.
    radius_opaque_min_len: int = 64
    radius_opaque_entropy_min: float = 0.88
    radius_opaque_print_run_max: int = 16
    radius_cleartext_print_run_min: int = 24

    # ---- F1: request/response correlation ----------------------------------
    radius_correlate_window_s: float = 30.0
    radius_pending_max: int = 4096
    # A response carrying Proxy-State whose REQUEST WAS NEVER OBSERVED cannot
    # be judged: on an asymmetric tap, or one placed mid-proxy-chain, that is
    # ordinary. Default OFF so the module stays silent rather than guessing;
    # an operator who knows the tap sees both directions can turn it on for a
    # clearly-labelled low-confidence finding.
    radius_report_unmatched_proxy_state: bool = False
    # NOTE: there is deliberately NO radius_total_len_max knob. RFC 2865 fixes
    # the legal packet length at 20..4096, so the bound is a property of the
    # wire format, not a policy choice - a knob there could never fire and
    # would advertise tunability that does not exist. parse_radius() enforces
    # it as a protocol constant. Same reasoning ciscoguard used when it
    # removed isis_max_tlv_len and dhcp_max_option_len; do not re-add it.
    # OSPFv3 structural bounds.  Set well above anything a real speaker emits;
    # these are anomaly thresholds, NOT the vendor's real parser bound, which
    # Arista has not published.
    ospfv3_max_lsa_count: int = 512
    ospfv3_min_header_len: int = 16
    # A frame carrying more 802.1Q tags than this is a stacking anomaly.
    max_vlan_tags: int = 2
    # BROAD CAPTURE FOR THE VLAN RULES. Off by default; see build_bpf_filter.
    # AG-205 and AG-207 need singly-tagged frames, which a port/protocol
    # filter cannot admit on Linux because the kernel strips the outer tag
    # before BPF runs. Turning this on admits all IP traffic - a real cost on
    # a busy SPAN port, and deliberately the operator's decision to make.
    vlan_broad_capture: bool = False

    # --- operator intent (rules stay SILENT without it) ------------------
    # AG-206 cannot distinguish a Traffic Policy bypass from ordinary allowed
    # traffic unless the operator says what was supposed to be blocked.
    policy_blocked: tuple[str, ...] = ()
    # AG-106/AG-203: IPs known to be configured tunnel decapsulation
    # endpoints.  Learned passively from observed VXLAN, or named here.
    decap_endpoints: tuple[str, ...] = ()
    # Scopes EXPOSURE findings to operator-named infrastructure.  Deliberately
    # NOT applied to ATTACK or POSTURE - scoping an attack away would turn a
    # noise knob into a detection blind spot (ciscoguard precedent).
    known_infra: tuple[str, ...] = ()

    # --- alert suppression ----------------------------------------------
    suppress_s: int = 300
    suppress_max: int = 4096

    # --- runtime --------------------------------------------------------
    learn: bool = False
    iface: str = ""
    timeout: int = 0

    def dump(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def load(cls, blob: dict[str, Any]) -> "Config":
        known = {f for f in cls.__dataclass_fields__}
        kwargs: dict[str, Any] = {}
        for k, v in blob.items():
            if k not in known:
                sys.stderr.write(f"aristaguard: warning: unknown config key {k!r} ignored\n")
                continue
            cur = getattr(cls, k, None)
            if isinstance(cur, tuple) and isinstance(v, list):
                v = tuple(v)
            kwargs[k] = v
        return cls(**kwargs)


def cve_in_scope(entry: CVEEntry, cfg: Config) -> bool:
    """Severity floor with the documented exploitation override."""
    if cfg.always_include_exploited and entry.exploited:
        return True
    return entry.cvss >= cfg.min_cvss


# ---------------------------------------------------------------------------
# EOS version handling
# ---------------------------------------------------------------------------
#
# Arista EOS versions look like:  4.32.5.1M   4.34.0F   4.28.13   4.33.3.1F
# Shape: MAJOR.MINOR.PATCH[.SUB][SUFFIX] where SUFFIX is F (feature),
# M (maintenance), FX, etc.  The suffix sorts AFTER the numeric part but
# never ahead of a higher numeric component.

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)([A-Za-z]*)$")


def parse_version(s: str) -> Optional[tuple[tuple[int, ...], str]]:
    """('4.32.5.1M') -> ((4,32,5,1), 'M').  None if unparseable."""
    if not s:
        return None
    m = _VERSION_RE.match(s.strip())
    if not m:
        return None
    nums = tuple(int(p) for p in m.group(1).split("."))
    return nums, m.group(2).upper()


def _pad(a: tuple[int, ...], n: int) -> tuple[int, ...]:
    return a + (0,) * (n - len(a))


def version_cmp(a: str, b: str) -> Optional[int]:
    """-1 / 0 / 1, or None if either side is unparseable."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    na, sa = pa
    nb, sb = pb
    width = max(len(na), len(nb))
    na, nb = _pad(na, width), _pad(nb, width)
    if na != nb:
        return -1 if na < nb else 1
    if sa == sb:
        return 0
    return -1 if sa < sb else 1


def in_branch(version: str, branch: str) -> bool:
    """'4.32.5.1M' is in branch '4.32'; also in the catch-all branch '4'."""
    pv, pb = parse_version(version), parse_version(branch)
    if pv is None or pb is None:
        return False
    nv, nb = pv[0], pb[0]
    return len(nv) >= len(nb) and nv[:len(nb)] == nb


def screen_version(version: str, entry: CVEEntry) -> tuple[str, str]:
    """
    Screen an observed EOS version against one CVE's version table.

    Returns (verdict, explanation).  Verdicts:
        vulnerable      version falls inside a published vulnerable range
        not_vulnerable  version is at or past this branch's fixed release
        unscreened      no version table exists for this CVE
        inferred_clean  the branch is ABSENT from the advisory's table

    'inferred_clean' deliberately does NOT resolve to not_vulnerable.  A
    branch absent from an advisory table means the advisory did not mention
    it - which is not the same as the vendor stating it is unaffected.
    Reporting silence as a clean bill of health is exactly the ambiguity
    juniperwatch documented as a side effect of catch-all branch entries.
    """
    if not entry.versions:
        return ("unscreened",
                f"no version table captured for {entry.cve}; consult {entry.advisory} directly")
    for row in entry.versions:
        if len(row) == 4:
            branch, lower, cutoff, _conf = row
        else:
            branch, cutoff, _conf = row
            lower = None
        if not in_branch(version, branch):
            continue
        if lower is not None:
            c = version_cmp(version, lower)
            if c is None:
                return ("unscreened", f"could not parse {version!r}")
            if c < 0:
                return ("not_vulnerable",
                        f"{version} predates the vulnerable range start {lower} in branch {branch}")
        c = version_cmp(version, cutoff)
        if c is None:
            return ("unscreened", f"could not parse {version!r}")
        if c < 0:
            return ("vulnerable",
                    f"{version} is below the fixed release {cutoff} in branch {branch}")
        return ("not_vulnerable",
                f"{version} is at or past the fixed release {cutoff} in branch {branch}")
    return ("inferred_clean",
            f"branch of {version} is absent from the {entry.advisory} table - "
            f"inferred from silence, NOT confirmed patched")


# ---------------------------------------------------------------------------
# Bounded raw-byte parsers
# ---------------------------------------------------------------------------
#
# Hand-rolled, no third-party dissectors.  Every parser is bounded, returns
# None rather than raising on malformed input, and never reads past the
# buffer it was given.

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ETH_P_LLDP = 0x88CC
ETH_P_EAPOL = 0x888E

IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_GRE = 47
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_IPIP = 4
IPPROTO_IPV6 = 41
IPPROTO_OSPF = 89

# ---- IPv6 extension headers (D7 / PRIME DIRECTIVE) ------------------------
#
# parse_l3 previously took the IPv6 next-header byte as the L4 protocol with
# no chain walk, so the identical RADIUS packet behind a Hop-by-Hop header
# raised NOTHING while plain IPv6 worked. That blind spot hides traffic from
# EVERY L4 rule in the module - RADIUS, VXLAN, gNMI/gNOI, CVX, SSH, TACACS+ -
# not just the RADIUS ones. Ported from ciscoguard, which measured the same
# failure with tcpdump.
IPV6_EXT_HOPOPT = 0
IPV6_EXT_ROUTING = 43
IPV6_EXT_FRAGMENT = 44
IPV6_EXT_AH = 51
IPV6_EXT_DSTOPTS = 60
IPV6_NO_NEXT_HEADER = 59

IPV6_EXT_HEADERS = frozenset((IPV6_EXT_HOPOPT, IPV6_EXT_ROUTING,
                              IPV6_EXT_FRAGMENT, IPV6_EXT_AH,
                              IPV6_EXT_DSTOPTS))

# Bounded at 8 links. An unbounded walk is a denial-of-service primitive
# against the sensor itself; ciscoguard uses the same bound and documents it
# as a limitation rather than pretending the chain is walked to the end.
IPV6_MAX_EXT_HEADERS = 8

TUNNEL_PROTOS = {
    IPPROTO_GRE: "GRE",
    IPPROTO_IPIP: "IP-in-IP",
    IPPROTO_IPV6: "IPv6-in-IP",
}


def _u16(b: bytes, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def _mac(b: bytes, o: int) -> str:
    return b[o:o + 6].hex(":")


def _ipv4(b: bytes, o: int) -> str:
    return ".".join(str(x) for x in b[o:o + 4])


def _ipv6(b: bytes, o: int) -> str:
    parts = [b[o + i:o + i + 2].hex() for i in range(0, 16, 2)]
    return ":".join(p.lstrip("0") or "0" for p in parts)


@dataclass
class L2:
    dst: str = ""
    src: str = ""
    ethertype: int = 0
    vlan_tags: tuple[int, ...] = ()
    tpids: tuple[int, ...] = ()
    payload: bytes = b""
    truncated: bool = False


def parse_l2(frame: bytes) -> Optional[L2]:
    if not isinstance(frame, (bytes, bytearray)):
        raise TypeError("parse_l2 expects bytes; got %r" % type(frame).__name__)
    frame = bytes(frame)
    if len(frame) < 14:
        return None
    out = L2(dst=_mac(frame, 0), src=_mac(frame, 6))
    off = 12
    tags: list[int] = []
    tpids: list[int] = []
    # Bound the tag walk so a crafted stack cannot spin us.
    for _ in range(8):
        if off + 2 > len(frame):
            out.truncated = True
            return out
        et = _u16(frame, off)
        if et in (ETH_P_8021Q, ETH_P_8021AD):
            if off + 4 > len(frame):
                out.truncated = True
                return out
            tags.append(_u16(frame, off + 2) & 0x0FFF)
            tpids.append(et)
            off += 4
            continue
        out.ethertype = et
        off += 2
        break
    out.vlan_tags = tuple(tags)
    out.tpids = tuple(tpids)
    out.payload = frame[off:]
    return out


@dataclass
class L3:
    version: int = 0
    src: str = ""
    dst: str = ""
    proto: int = 0
    payload: bytes = b""
    total_len: int = 0
    truncated: bool = False
    # IPv6 extension-header chain state. ext_headers records the header types
    # traversed, in order. l4_reachable is False when no L4 header is present
    # to parse - a non-first fragment, a No-Next-Header chain, a malformed
    # length, or a chain longer than IPV6_MAX_EXT_HEADERS.
    ext_headers: tuple[int, ...] = ()
    frag_offset: int = 0
    l4_reachable: bool = True
    ext_chain_truncated: bool = False


def parse_l3(payload: bytes, ethertype: int) -> Optional[L3]:
    if ethertype == ETH_P_IPV4:
        if len(payload) < 20:
            return None
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return None
        tl = _u16(payload, 2)
        body = payload[ihl:tl] if 0 < tl <= len(payload) else payload[ihl:]
        return L3(4, _ipv4(payload, 12), _ipv4(payload, 16), payload[9], body, tl,
                  truncated=(0 < tl > len(payload)))
    if ethertype == ETH_P_IPV6:
        if len(payload) < 40:
            return None
        plen = _u16(payload, 4)
        body = payload[40:40 + plen] if plen else payload[40:]
        proto, l4body, chain, frag_off, reachable, chain_trunc = \
            walk_ipv6_chain(body, payload[6])
        return L3(6, _ipv6(payload, 8), _ipv6(payload, 24), proto, l4body,
                  40 + plen, truncated=(len(payload) < 40 + plen),
                  ext_headers=chain, frag_offset=frag_off,
                  l4_reachable=reachable, ext_chain_truncated=chain_trunc)
    return None


def walk_ipv6_chain(body: bytes, next_header: int) -> tuple:
    """
    Walk an IPv6 extension-header chain to the first non-extension header.

    Returns (proto, payload, ext_headers, frag_offset, l4_reachable,
             chain_truncated).

    Header lengths differ by type and getting this wrong silently mis-parses:
      - Hop-by-Hop / Routing / Dest-Opts: Hdr Ext Len is in 8-octet units NOT
        counting the first 8, so the real length is (len + 1) * 8.
      - Authentication Header: RFC 4302 makes its length field 4-octet units
        MINUS 2, so the real length is (len + 2) * 4. Using the 8-octet rule
        here walks off the end of the header.
      - Fragment: always exactly 8 bytes.

    A NON-FIRST fragment carries no L4 header at all, so l4_reachable is
    False - reporting a protocol there would invite every L4 rule to parse
    payload bytes as a header.
    """
    chain: list[int] = []
    off = 0
    nh = next_header
    for _ in range(IPV6_MAX_EXT_HEADERS):
        if nh == IPV6_NO_NEXT_HEADER:
            return (nh, b"", tuple(chain), 0, False, False)
        if nh not in IPV6_EXT_HEADERS:
            return (nh, body[off:], tuple(chain), 0, True, False)
        if off + 2 > len(body):
            return (nh, b"", tuple(chain), 0, False, True)
        chain.append(nh)
        nxt = body[off]
        if nh == IPV6_EXT_FRAGMENT:
            if off + 8 > len(body):
                return (nh, b"", tuple(chain), 0, False, True)
            frag_off = _u16(body, off + 2) >> 3
            if frag_off != 0:
                return (nxt, b"", tuple(chain), frag_off, False, False)
            hlen = 8
        elif nh == IPV6_EXT_AH:
            hlen = (body[off + 1] + 2) * 4
        else:
            hlen = (body[off + 1] + 1) * 8
        if hlen <= 0 or off + hlen > len(body):
            return (nh, b"", tuple(chain), 0, False, True)
        off += hlen
        nh = nxt
    # Chain longer than the bound. Reporting l4_reachable=True here would
    # hand a rule bytes from the middle of an extension header.
    return (nh, b"", tuple(chain), 0, False, True)


@dataclass
class L4:
    sport: int = 0
    dport: int = 0
    payload: bytes = b""


def parse_l4(l3: L3) -> Optional[L4]:
    # No L4 header is present behind a non-first fragment, a No-Next chain, a
    # malformed extension length, or a chain past the bound.
    if not l3.l4_reachable:
        return None
    p = l3.payload
    if l3.proto == IPPROTO_UDP:
        if len(p) < 8:
            return None
        ln = _u16(p, 4)
        body = p[8:ln] if 8 <= ln <= len(p) else p[8:]
        return L4(_u16(p, 0), _u16(p, 2), body)
    if l3.proto == IPPROTO_TCP:
        if len(p) < 20:
            return None
        off = ((p[12] >> 4) & 0x0F) * 4
        if off < 20 or len(p) < off:
            return None
        return L4(_u16(p, 0), _u16(p, 2), p[off:])
    return None


# ---- LLDP -----------------------------------------------------------------
#
# The richest passive Arista version source there is.  Arista populates the
# LLDP system description with both the EOS version and the platform model by
# default, e.g.
#   "Arista Networks EOS version 4.32.2F running on an Arista Networks
#    DCS-7050SX3-48YC8"

LLDP_TLV_END = 0
LLDP_TLV_CHASSIS = 1
LLDP_TLV_PORT = 2
LLDP_TLV_SYSNAME = 5
LLDP_TLV_SYSDESC = 6
LLDP_TLV_MGMT_ADDR = 8

_EOS_VER_RE = re.compile(
    r"EOS\s+version\s+(\d+(?:\.\d+)+[A-Za-z]*)", re.IGNORECASE)
_EOS_MODEL_RE = re.compile(
    r"running\s+on\s+(?:an?\s+)?(?:Arista\s+Networks\s+)?([A-Za-z0-9\-]+)",
    re.IGNORECASE)
_CLOUDEOS_RE = re.compile(r"cloudeos|vEOS", re.IGNORECASE)


@dataclass
class LLDPInfo:
    sysname: str = ""
    sysdesc: str = ""
    eos_version: str = ""
    platform: str = ""
    is_arista: bool = False
    is_cloudeos: bool = False
    mgmt_addrs: tuple[str, ...] = ()


def parse_lldp(payload: bytes) -> Optional[LLDPInfo]:
    if len(payload) < 2:
        return None
    out = LLDPInfo()
    off = 0
    for _ in range(64):
        if off + 2 > len(payload):
            break
        hdr = _u16(payload, off)
        ttype = (hdr >> 9) & 0x7F
        tlen = hdr & 0x01FF
        off += 2
        if ttype == LLDP_TLV_END:
            break
        if off + tlen > len(payload):
            break
        val = payload[off:off + tlen]
        off += tlen
        if ttype == LLDP_TLV_SYSNAME:
            out.sysname = val.decode("utf-8", "replace")
        elif ttype == LLDP_TLV_SYSDESC:
            out.sysdesc = val.decode("utf-8", "replace")
        elif ttype == LLDP_TLV_MGMT_ADDR:
            # IEEE 802.1AB: 1-byte addr-string length, then 1-byte address
            # subtype (IANA: 1=IPv4, 2=IPv6), then the address. Only the
            # address is needed, to scope the RADIUS rules to Arista IPs.
            if len(val) >= 2:
                alen = val[0]
                if 1 <= alen <= len(val) - 1:
                    subtype = val[1]
                    addr = val[2:1 + alen]
                    if subtype == 1 and len(addr) == 4:
                        out.mgmt_addrs += (_ipv4(addr, 0),)
                    elif subtype == 2 and len(addr) == 16:
                        out.mgmt_addrs += (_ipv6(addr, 0),)
    if out.sysdesc:
        d = out.sysdesc
        out.is_arista = "arista" in d.lower()
        out.is_cloudeos = bool(_CLOUDEOS_RE.search(d))
        m = _EOS_VER_RE.search(d)
        if m:
            out.eos_version = m.group(1)
        m = _EOS_MODEL_RE.search(d)
        if m:
            out.platform = m.group(1)
    return out if (out.sysname or out.sysdesc) else None


# ---- RADIUS ---------------------------------------------------------------
#
# RFC 2865.  Cleartext UDP, which is precisely why BlastRADIUS is the
# strongest signature in this module: the vulnerable precondition and the
# attack payload are both directly readable.

RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCESS_CHALLENGE = 11

RADIUS_CODE_NAMES = {
    1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
    4: "Accounting-Request", 5: "Accounting-Response",
    11: "Access-Challenge",
}

RADIUS_ATTR_USER_NAME = 1
RADIUS_ATTR_USER_PASSWORD = 2
RADIUS_ATTR_PROXY_STATE = 33
RADIUS_ATTR_MESSAGE_AUTHENTICATOR = 80

RADIUS_RESPONSE_CODES = {RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT,
                         RADIUS_ACCESS_CHALLENGE}

# Codes whose mitigation requires Message-Authenticator as the FIRST
# attribute, not merely present. Access-Challenge is presence-only.
RADIUS_MA_FIRST_CODES = {RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT}

# 4096-byte maximum packet, 20-byte header, 2-byte minimum attribute.
RADIUS_MAX_ATTRS = (4096 - 20) // 2


RADIUS_ATTR_REPLY_MESSAGE = 18
RADIUS_ATTR_VENDOR_SPECIFIC = 26


def _norm_entropy(b: bytes) -> float:
    """
    Shannon entropy normalised against the MAXIMUM ACHIEVABLE for this length.

    arubaguard's lesson: raw entropy thresholds are wrong for short buffers -
    64 random bytes can only reach 6.0 bits, so a fixed "7.5 bits" test never
    fires on anything short. Dividing by log2(min(256, n)) makes the number
    comparable across lengths.
    """
    if not b:
        return 0.0
    counts: dict[int, int] = {}
    for x in b:
        counts[x] = counts.get(x, 0) + 1
    n = len(b)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    hmax = math.log2(min(256, n))
    return h / hmax if hmax else 0.0


def _longest_printable_run(b: bytes) -> int:
    best = cur = 0
    for x in b:
        if 32 <= x <= 126 or x in (9, 10, 13):
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def classify_opacity(b: bytes, cfg: "Config") -> str:
    """
    Classify an attribute value as "opaque", "cleartext" or "unknown".

    MEASURED for RADIUS attribute sizes (values cap at 253 bytes), NOT reused
    from arubaguard's numbers - those were measured for 32-1024 byte PAPI
    datagrams and do not transfer. 400 random samples per size 32..247 against
    real vendor AV-pair strings (Cisco-AVPair, Aruba-User-Role, Filter-Id,
    Tunnel-Private-Group-Id, Class):

        normalised entropy   cleartext 0.717-0.902   random 0.881-0.952
        longest printable    cleartext 31-60         random 3-13

    ENTROPY ALONE DOES NOT SEPARATE THEM - the ranges overlap at 0.881-0.902.
    The printable run is the discriminator, with entropy as corroboration.
    The 17..23 gap between the two run bands is deliberately left as an
    "unknown" band that emits NOTHING, exactly as arubaguard does: a middle
    band that guesses is worse than one that abstains.
    """
    if len(b) < cfg.radius_opaque_min_len:
        return "unknown"
    run = _longest_printable_run(b)
    if run >= cfg.radius_cleartext_print_run_min:
        return "cleartext"
    if run <= cfg.radius_opaque_print_run_max \
            and _norm_entropy(b) >= cfg.radius_opaque_entropy_min:
        return "opaque"
    return "unknown"


@dataclass
class RadiusPacket:
    code: int = 0
    identifier: int = 0
    length: int = 0
    authenticator: bytes = b""
    # (type, length) only.  Attribute VALUES are deliberately not retained -
    # this module never logs credential material.
    attrs: tuple[tuple[int, int], ...] = ()
    max_attr_type: int = 0
    max_attr_len: int = 0
    # D1/D2. AG-201 keys on Proxy-State ONLY, and on the per-packet TOTAL.
    #
    # D1: the old rule tested the largest attribute of ANY type against a
    # per-attribute bound. EAP-TLS and PEAP routinely fragment EAP-Message
    # (type 79) into 255-byte attributes, so a perfectly normal 802.1X
    # exchange raised AG-201 at CRITICAL - on the request AND on the server's
    # own Access-Challenge.
    #
    # D2: a per-attribute bound is also trivially evaded. A collision block
    # split across four Proxy-State attributes of 100 bytes each stayed under
    # the 128-byte threshold and raised nothing. The chosen-prefix block must
    # arrive in full, so the per-packet SUM is the quantity that matters. A
    # legitimate proxy adds one small Proxy-State per hop.
    proxy_state_total: int = 0
    proxy_state_count: int = 0
    # F1. Digests of the Proxy-State VALUES, never the values themselves.
    # Proxy-State must be echoed back byte-for-byte by a conforming server,
    # so comparing digests detects injection or substitution without this
    # module ever retaining attribute content.
    proxy_state_digests: tuple[str, ...] = ()
    # F2. Derived statistics only - the bytes are analysed during the walk
    # and discarded. Nothing here can reconstruct an attribute value.
    reply_message_invalid_utf8: int = 0
    reply_message_count: int = 0
    opaque_vendor_attrs: tuple[tuple[int, float, int], ...] = ()
    cleartext_vendor_attrs: int = 0
    unknown_vendor_attrs: int = 0
    malformed: bool = False

    @property
    def has_message_authenticator(self) -> bool:
        return any(t == RADIUS_ATTR_MESSAGE_AUTHENTICATOR for t, _ in self.attrs)

    @property
    def ma_is_first(self) -> bool:
        """D3. Mitigation requires M-A as the FIRST attribute in a response."""
        return bool(self.attrs) and \
            self.attrs[0][0] == RADIUS_ATTR_MESSAGE_AUTHENTICATOR

    @property
    def code_name(self) -> str:
        return RADIUS_CODE_NAMES.get(self.code, f"code-{self.code}")


def parse_radius(payload: bytes,
                 cfg: Optional["Config"] = None) -> Optional[RadiusPacket]:
    """
    cfg is optional so the parser stays usable standalone; without it the
    Vendor-Specific opacity classification is skipped (it is the only part
    that needs tunable bounds). Reply-Message UTF-8 validity and Proxy-State
    digests are computed either way, since neither needs a threshold.
    """
    if len(payload) < 20:
        return None
    pkt = RadiusPacket(code=payload[0], identifier=payload[1],
                       length=_u16(payload, 2), authenticator=payload[4:20])
    if pkt.length < 20 or pkt.length > 4096:
        pkt.malformed = True
    body = payload[20:pkt.length] if 20 <= pkt.length <= len(payload) else payload[20:]
    attrs: list[tuple[int, int]] = []
    ps_digests: list[str] = []
    opaque: list[tuple[int, float, int]] = []
    off = 0
    # D6. The old cap of 256 was below what a legal packet can carry: RFC 2865
    # allows 4096 bytes and an attribute is at least 2, so 2038 attributes fit
    # after the 20-byte header. A legitimate packet with 300 small attributes
    # before Message-Authenticator stopped the walk early, the M-A was never
    # seen, and AG-102 fired falsely.
    for _ in range(RADIUS_MAX_ATTRS):
        if off + 2 > len(body):
            break
        atype, alen = body[off], body[off + 1]
        if alen < 2:
            pkt.malformed = True
            break
        if off + alen > len(body):
            pkt.malformed = True
            break
        attrs.append((atype, alen))
        if alen > pkt.max_attr_len:
            pkt.max_attr_len = alen
            pkt.max_attr_type = atype
        value = body[off + 2:off + alen]
        if atype == RADIUS_ATTR_PROXY_STATE:
            pkt.proxy_state_total += alen
            pkt.proxy_state_count += 1
            # Digest only. See the field comment above.
            ps_digests.append(
                hashlib.blake2b(value, digest_size=8).hexdigest())
        elif atype == RADIUS_ATTR_REPLY_MESSAGE:
            pkt.reply_message_count += 1
            # RFC 2865 defines Reply-Message as displayable text, so invalid
            # UTF-8 is a DETERMINISTIC structural anomaly - no threshold and
            # no entropy estimate needed.
            try:
                value.decode("utf-8")
            except UnicodeDecodeError:
                pkt.reply_message_invalid_utf8 += 1
        elif atype == RADIUS_ATTR_VENDOR_SPECIFIC and cfg is not None:
            # Classify the VENDOR PAYLOAD, not the whole attribute body.
            # RFC 2865 s5.26 puts a 4-byte vendor-id plus a 2-byte
            # vendor-type/vendor-length sub-header in front of it. Those six
            # bytes are structured protocol fields, not attacker-controlled
            # content, and including them dilutes the entropy of short
            # payloads in the wrong direction. The scapy cross-check tier is
            # what surfaced the difference: scapy's RadiusAttr_Vendor_Specific
            # exposes .value as the inner payload only, and its boundary is
            # the correct one to measure.
            vendor_payload = value[6:] if len(value) >= 8 else value
            verdict = classify_opacity(vendor_payload, cfg)
            if verdict == "opaque":
                opaque.append((alen, round(_norm_entropy(vendor_payload), 3),
                               _longest_printable_run(vendor_payload)))
            elif verdict == "cleartext":
                pkt.cleartext_vendor_attrs += 1
            else:
                pkt.unknown_vendor_attrs += 1
        off += alen
    pkt.attrs = tuple(attrs)
    pkt.proxy_state_digests = tuple(ps_digests)
    pkt.opaque_vendor_attrs = tuple(opaque)
    return pkt


# ---- EAPOL / 802.1X -------------------------------------------------------

EAPOL_TYPE_EAP = 0
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2

EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4


@dataclass
class EapolFrame:
    version: int = 0
    etype: int = 0
    body_len: int = 0
    eap_code: int = 0
    eap_id: int = 0


def parse_eapol(payload: bytes) -> Optional[EapolFrame]:
    if len(payload) < 4:
        return None
    f = EapolFrame(version=payload[0], etype=payload[1],
                   body_len=_u16(payload, 2))
    if f.etype == EAPOL_TYPE_EAP and len(payload) >= 8:
        f.eap_code = payload[4]
        f.eap_id = payload[5]
    return f


# ---- SSH identification string -------------------------------------------
#
# Sent before any encryption is negotiated, so this is a real observation and
# not an inference.

_SSH_BANNER_RE = re.compile(rb"^SSH-2\.0-([^\r\n]{0,128})")
_OPENSSH_VER_RE = re.compile(r"OpenSSH[_-]([0-9]+\.[0-9]+)(p[0-9]+)?")


def parse_ssh_banner(payload: bytes) -> Optional[str]:
    m = _SSH_BANNER_RE.match(payload)
    if not m:
        return None
    return m.group(1).decode("ascii", "replace")


def openssh_regresshion_affected(banner: str) -> Optional[str]:
    """
    CVE-2024-6387 reintroduced the CVE-2006-5051 race in OpenSSH >= 8.5p1 and
    < 9.8p1.  Returns an explanation when the banner falls in that window.
    """
    m = _OPENSSH_VER_RE.search(banner)
    if not m:
        return None
    major_minor = m.group(1)
    p = int(m.group(2)[1:]) if m.group(2) else 0
    try:
        maj, mnr = (int(x) for x in major_minor.split("."))
    except ValueError:
        return None
    v = (maj, mnr, p)
    if (8, 5, 1) <= v < (9, 8, 1):
        return (f"OpenSSH {major_minor}{m.group(2) or ''} is inside the "
                f"regreSSHion window (>= 8.5p1, < 9.8p1)")
    return None


# ---------------------------------------------------------------------------
# Findings + suppression
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    code: str
    name: str
    severity: str
    klass: str
    ts: float
    detail: dict[str, Any] = field(default_factory=dict)
    cves: tuple[str, ...] = ()
    pivot: tuple[str, ...] = ()

    def to_json(self) -> str:
        return json.dumps({
            "module": "aristaguard",
            "version": __version__,
            "code": self.code,
            "finding": self.name,
            "severity": self.severity,
            "class": self.klass,
            "ts": round(self.ts, 6),
            "cves": list(self.cves),
            "pivot": list(self.pivot),
            "detail": self.detail,
        }, sort_keys=True)


class Suppressor:
    """
    Throttles ALERTS, never DETECTION.  Fails OPEN - an evicted key just
    alerts again, which is noisy rather than silent.  NEVER auto-learns:
    a suppressed key is not added to any allow-list, because that would be a
    back door for an attacker to teach the sensor to ignore them.
    """

    def __init__(self, window_s: int, cap: int) -> None:
        self.window_s = window_s
        self.cap = cap
        self._seen: dict[tuple, tuple[float, int]] = {}

    def should_alert(self, key: tuple, now: float) -> tuple[bool, int]:
        first, count = self._seen.get(key, (0.0, 0))
        if first and now - first < self.window_s:
            self._seen[key] = (first, count + 1)
            return False, count + 1
        if len(self._seen) >= self.cap:
            oldest = min(self._seen, key=lambda k: self._seen[k][0])
            del self._seen[oldest]
        self._seen[key] = (now, 1)
        return True, count


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AristaEngine:
    def __init__(self, cfg: Optional[Config] = None,
                 emit: Optional[Callable[[Finding], None]] = None) -> None:
        self.cfg = cfg or Config()
        self.findings: list[Finding] = []
        self._emit = emit
        self.sup = Suppressor(self.cfg.suppress_s, self.cfg.suppress_max)
        # passive state
        self.decap_endpoints: set[str] = set(self.cfg.decap_endpoints)
        self.mac_vlans: dict[str, set[int]] = {}
        # F1. key -> (ts, proxy_state_digests, authenticator_hex). Bounded and
        # time-windowed. Eviction FAILS SILENT (no matching request -> no
        # finding), which is a documented limitation: an attacker who floods
        # requests can evict a real one. Recorded in the README rather than
        # papered over.
        self.radius_pending: dict[tuple, tuple[float, tuple[str, ...], str]] = {}
        self.eapol_vlans: set[int] = set()
        self.unauth_after_eapol: dict[int, set[str]] = {}
        # IPs belonging to Arista devices, learned passively from LLDP
        # management-address TLVs, seeded with any operator-named endpoints.
        # Used only to scope the RADIUS rules to Arista hardware.
        self._radius_arista_wildcard = any(
            "*" in e for e in self.cfg.radius_arista_endpoints)
        self.arista_ips: set[str] = {
            e for e in self.cfg.radius_arista_endpoints if "*" not in e}
        self.in_scope_cves = tuple(
            e for e in CVE_CATALOG if cve_in_scope(e, self.cfg))

    # -- emission --------------------------------------------------------
    def add(self, code: str, ts: float, detail: dict[str, Any],
            suppress_key: Optional[tuple] = None) -> Optional[Finding]:
        spec = FINDINGS[code]
        if suppress_key is not None:
            ok, count = self.sup.should_alert((code,) + suppress_key, ts)
            if not ok:
                return None
            if count:
                detail = dict(detail, suppressed_since_last=count)
        f = Finding(code=spec.code, name=spec.name, severity=spec.severity,
                    klass=spec.klass, ts=ts, detail=detail,
                    cves=spec.cves, pivot=spec.pivot)
        self.findings.append(f)
        if self._emit and not self.cfg.learn:
            self._emit(f)
        return f

    def _exposure_scoped(self, addr: Optional[str]) -> bool:
        """
        known_infra scopes EXPOSURE findings only.  Never ATTACK, never
        POSTURE - scoping an attack away turns a noise knob into a blind spot.
        """
        if not self.cfg.known_infra:
            return True
        if addr is None:
            return True
        return addr in self.cfg.known_infra

    # -- top level -------------------------------------------------------
    def handle_frame(self, frame: bytes, ts: Optional[float] = None) -> None:
        ts = time.time() if ts is None else ts
        l2 = parse_l2(frame)
        if l2 is None:
            return
        self.rule_vlan_stack(l2, ts)
        if l2.ethertype == ETH_P_LLDP:
            self.handle_lldp(l2, ts)
            return
        if l2.ethertype == ETH_P_EAPOL:
            self.handle_eapol(l2, ts)
            return
        l3 = parse_l3(l2.payload, l2.ethertype)
        if l3 is None:
            return
        self.rule_vlan_isolation(l2, l3, ts)
        self.rule_tunnel_decap(l2, l3, ts)
        self.rule_ipsec_present(l3, ts)
        self.rule_ospfv3(l3, ts)
        l4 = parse_l4(l3)
        if l4 is None:
            return
        self.handle_l4(l2, l3, l4, ts)

    def handle_l4(self, l2: L2, l3: L3, l4: L4, ts: float) -> None:
        c = self.cfg
        if l4.dport in c.radius_auth_ports or l4.sport in c.radius_auth_ports:
            self.rule_radius(l3, l4, ts, accounting=False)
        elif l4.dport in c.radius_acct_ports or l4.sport in c.radius_acct_ports:
            self.rule_radius(l3, l4, ts, accounting=True)
        if l4.dport in c.vxlan_ports:
            self.rule_vxlan(l3, l4, ts)
        if l4.dport in c.gnmi_ports or l4.sport in c.gnmi_ports:
            self.rule_gnmi(l3, l4, ts)
        if l4.dport in c.cvx_ports or l4.sport in c.cvx_ports:
            self.rule_cvx(l3, l4, ts)
        if l4.sport in c.ssh_ports or l4.dport in c.ssh_ports:
            self.rule_ssh(l3, l4, ts)
        if l4.dport in c.tacacs_ports or l4.sport in c.tacacs_ports:
            self.rule_tacacs(l3, l4, ts)
        self.rule_policy_bypass(l2, l3, ts)

    # -- POSTURE ---------------------------------------------------------
    def handle_lldp(self, l2: L2, ts: float) -> None:
        info = parse_lldp(l2.payload)
        if info is None:
            return
        if info.sysdesc and OUT_OF_SCOPE_PLATFORM_RE.search(info.sysdesc):
            self.add("AG-009", ts, {
                "src_mac": l2.src,
                "system_description": info.sysdesc[:200],
                "reason": "platform is an Arista product outside this module's "
                          "switch/router/edge/core scope; excluded from CVE screening",
            }, suppress_key=(l2.src,))
            return
        if not info.is_arista:
            return
        # Learn this Arista device's management IPs so the RADIUS rules can be
        # scoped to Arista hardware (see rule_radius). Passive and additive.
        self.arista_ips.update(info.mgmt_addrs)
        if info.platform:
            self.add("AG-005", ts, {
                "src_mac": l2.src, "platform": info.platform,
                "system_name": info.sysname,
            }, suppress_key=(l2.src, info.platform))
            self.rule_tunnel_platform(l2, info, ts)
            self.rule_supervisor_exposure(l2, info, ts)
        if info.eos_version:
            self.add("AG-001", ts, {
                "src_mac": l2.src, "eos_version": info.eos_version,
                "platform": info.platform, "source": "lldp_system_description",
            }, suppress_key=(l2.src, info.eos_version))
            self.screen(l2.src, info, ts)

    def screen(self, src: str, info: LLDPInfo, ts: float) -> None:
        """Screen an observed version against every in-scope CVE."""
        buckets: dict[str, list[dict[str, Any]]] = {"AG-002": [], "AG-003": []}
        unscreened: dict[str, list[dict[str, Any]]] = {"AG-002": [], "AG-003": []}
        for entry in self.in_scope_cves:
            is_cloud = "CloudEOS" in entry.products
            if is_cloud != info.is_cloudeos:
                continue
            code = "AG-003" if is_cloud else "AG-002"
            verdict, why = screen_version(info.eos_version, entry)
            row = {
                "cve": entry.cve, "cvss": entry.cvss,
                "advisory": entry.advisory, "verdict": verdict,
                "detect": entry.detect,
                "score_confidence": entry.score_confidence,
                "exploited": entry.exploited, "explanation": why,
            }
            if verdict == "vulnerable":
                buckets[code].append(row)
            elif verdict == "unscreened" and is_cloud:
                # DOCUMENTED EXCEPTION. A CVE with no fixed-release table
                # normally cannot trigger (see the note below). The CloudEOS
                # Sfe CVEs are the exception because they are PLATFORM-GATED:
                # the Software Forwarding Engine exists only on CloudEOS, so
                # identifying the platform is itself the discriminating
                # signal that version screening would otherwise supply. This
                # finding therefore stays informative rather than firing on
                # every Arista device, which is the failure mode the rule
                # below exists to prevent.
                row["explanation"] = (
                    row["explanation"] + "; raised anyway because this CVE is "
                    "CloudEOS-specific and the platform has been identified")
                buckets[code].append(row)
            elif verdict in ("unscreened", "inferred_clean"):
                unscreened[code].append(row)
        # A CONFIRMED vulnerable verdict is what raises the finding.
        #
        # 'unscreened' and 'inferred_clean' are carried as CONTEXT but never
        # trigger, because most catalog entries have no published fixed-release
        # table - so triggering on them would make this finding unconditional
        # on every Arista device the sensor ever sees, which is the same as
        # carrying no information at all. The conformance clean-set contract
        # caught exactly that: a fully patched 4.34.2F raised AG-002.
        for code, rows in buckets.items():
            if not rows:
                continue
            self.add(code, ts, {
                "src_mac": src, "eos_version": info.eos_version,
                "platform": info.platform,
                "note": "POSTURE ONLY - verify THIS device against the named "
                        "advisories. A version match is not an exploitation verdict.",
                "candidates": rows,
                "could_not_screen": unscreened[code],
                "could_not_screen_note":
                    "These CVEs have no fixed-release table captured in the "
                    "catalog, or name a branch this version is absent from. "
                    "Absence of a verdict is NOT evidence of patching - check "
                    "the named advisories directly.",
            }, suppress_key=(src, info.eos_version))

    def rule_tunnel_platform(self, l2: L2, info: LLDPInfo, ts: float) -> None:
        p = info.platform or ""
        r3 = bool(TUNNEL_DECAP_R3_RE.search(p))
        base = bool(TUNNEL_DECAP_AFFECTED_RE.search(p)) and not r3
        if not (r3 or base):
            return
        self.add("AG-006", ts, {
            "src_mac": l2.src, "platform": p,
            "family": "R3" if r3 else "R/R2",
            "note": ("SA-0137 names this platform family for CVE-2026-7473. "
                     "R3 platforms are affected only in certain IP-in-IPv6 and "
                     "GUE IPv6 decap-group configurations."
                     if r3 else
                     "SA-0137 names this platform family for CVE-2026-7473."),
            "exploited": True,
            "no_patch_planned": True,
        }, suppress_key=(l2.src, p))

    def rule_supervisor_exposure(self, l2: L2, info: LLDPInfo, ts: float) -> None:
        # Modular chassis only.  A fixed-config 1U switch has no standby
        # supervisor and cannot be exposed to CVE-2023-24509 at all.
        p = (info.platform or "").upper()
        if not re.search(r"\b(75\d\d|78\d\d)", p):
            return
        self.add("AG-004", ts, {
            "src_mac": l2.src, "platform": info.platform,
            "note": ("Modular platform. CVE-2023-24509 additionally requires BOTH "
                     "supervisors inserted and active AND redundancy configured as "
                     "RPR or SSO - neither of which is observable from the network. "
                     "This finding is an exposure note for manual verification, "
                     "NOT a detection. The escalation is a local login to the "
                     "standby supervisor and never crosses the wire."),
            "detect": "none",
        }, suppress_key=(l2.src,))

    # -- RADIUS / BlastRADIUS -------------------------------------------
    def rule_radius(self, l3: L3, l4: L4, ts: float, accounting: bool) -> None:
        # SCOPE GATE: Arista hardware only. The vendor-neutral RADIUS coverage
        # moved to the radiuswatch module; here the Blast-RADIUS rules are
        # retained but limited to exchanges touching a known Arista device, so
        # the two modules do not double-report. An empty, nothing-learned scope
        # stays silent rather than firing suite-wide (policy_blocked
        # discipline); a configured "*" restores the old behaviour on purpose.
        if not (self._radius_arista_wildcard
                or l3.src in self.arista_ips or l3.dst in self.arista_ips):
            return
        pkt = parse_radius(l4.payload, self.cfg)
        if pkt is None:
            return

        # D5. The RADIUS SERVER is the infrastructure known_infra names, and
        # it is the destination on a request but the SOURCE on a response.
        # Scoping every finding on l3.dst put a response's NAS address through
        # the infra check instead of the server's.
        is_request = l4.dport in (self.cfg.radius_auth_ports
                                  + self.cfg.radius_acct_ports)
        server = l3.dst if is_request else l3.src

        if self._exposure_scoped(server):
            self.add("AG-101", ts, {
                "src": l3.src, "dst": l3.dst,
                "sport": l4.sport, "dport": l4.dport,
                "radius_code": pkt.code_name, "server": server,
                "note": "RADIUS/UDP is cleartext; CVE-2024-3596 requires only an "
                        "on-path position to forge responses",
            }, suppress_key=(l3.src, l3.dst))

        if not accounting:
            if pkt.code in RADIUS_RESPONSE_CODES:
                # D3. For Access-Accept and Access-Reject the mitigation is
                # not merely that Message-Authenticator is PRESENT but that it
                # is the FIRST attribute - an M-A placed after Proxy-State
                # raised nothing at all before this. Access-Challenge stays a
                # presence-only check.
                case = None
                if not pkt.has_message_authenticator:
                    case = "absent"
                elif pkt.code in RADIUS_MA_FIRST_CODES and not pkt.ma_is_first:
                    case = "not_first"
                if case is not None and self._exposure_scoped(server):
                    # D4. EXPOSURE, not ATTACK. This is the standing posture of
                    # an unhardened server, and as an attack-class code it
                    # could not be scoped by known_infra at all.
                    detail = {
                        "src": l3.src, "dst": l3.dst,
                        "radius_code": pkt.code_name,
                        "identifier": pkt.identifier,
                        "server": server, "case": case,
                        "first_attr_type": pkt.attrs[0][0] if pkt.attrs else None,
                    }
                    if case == "absent":
                        detail["note"] = (
                            "Response carries no Message-Authenticator "
                            "(attribute 80). It is protected only by the MD5 "
                            "Response Authenticator, which is what "
                            "CVE-2024-3596 defeats.")
                    else:
                        detail["note"] = (
                            "Message-Authenticator is present but is NOT the "
                            "first attribute. The CVE-2024-3596 mitigation "
                            "requires it first in Access-Accept and "
                            "Access-Reject, so this response is not actually "
                            "hardened despite carrying the attribute.")
                    self.add("AG-110", ts, detail,
                             suppress_key=(l3.src, l3.dst, pkt.code, case))
            elif (pkt.code == RADIUS_ACCESS_REQUEST
                  and not pkt.has_message_authenticator
                  # D5. AG-102 is EXPOSURE-class and was the one RADIUS
                  # finding that never consulted known_infra, breaking the
                  # module's own rule that known_infra scopes exposure.
                  and self._exposure_scoped(server)):
                self.add("AG-102", ts, {
                    "src": l3.src, "dst": l3.dst,
                    "radius_code": pkt.code_name, "server": server,
                    "note": "Access-Request carries no Message-Authenticator; "
                            "the mitigation for CVE-2024-3596 is to require it "
                            "on all requests and responses.",
                }, suppress_key=(l3.src, l3.dst))

        # ---- F1: Proxy-State injected on the NAS-side leg -----------------
        self.rule_radius_proxy_state_correlation(l3, l4, pkt, ts, is_request)

        # ---- F2: collision data smuggled in a non-Proxy-State attribute ----
        self.rule_radius_opaque_payload(l3, l4, pkt, ts)

        # D1/D2. Proxy-State ONLY, summed across the packet.
        #
        # AG-201 is ATTACK-class and is deliberately NOT scoped by
        # known_infra - scoping an attack away turns a noise knob into a
        # detection blind spot.
        if pkt.proxy_state_total > self.cfg.radius_proxy_state_total_max:
            self.add("AG-201", ts, {
                "src": l3.src, "dst": l3.dst,
                "radius_code": pkt.code_name,
                "proxy_state_total": pkt.proxy_state_total,
                "proxy_state_count": pkt.proxy_state_count,
                "threshold": self.cfg.radius_proxy_state_total_max,
                "has_message_authenticator": pkt.has_message_authenticator,
                "note": "Proxy-State bytes in this packet total more than a "
                        "legitimate proxy chain would add, consistent with a "
                        "chosen-prefix collision block - counted as a SUM so that "
                        "splitting the block across several attributes does not "
                        "evade it. THRESHOLD IS A STRUCTURAL ANOMALY BOUND, not a "
                        "published exploit constant. Attributes of other types "
                        "(notably 255-byte EAP-Message fragments in ordinary "
                        "EAP-TLS) are deliberately NOT counted.",
            }, suppress_key=(l3.src, l3.dst))

    def _radius_key(self, l3: L3, l4: L4, is_request: bool) -> tuple:
        """
        Correlation key for matching a response back to its request.

        NOTE / CORRECTION TO THE ORIGINAL DESIGN: the Request Authenticator
        CANNOT be part of the lookup key. A response's Authenticator field is
        the RESPONSE Authenticator - MD5(code|id|len|RequestAuth|attrs|secret)
        - not a copy of the request's, so it is not derivable from the
        response without the shared secret. The key is therefore the standard
        RADIUS pairing: the socket 4-tuple plus the Identifier. The request
        authenticator IS stored alongside and reported in the finding, so an
        analyst can disambiguate an Identifier reused inside the window.
        """
        if is_request:
            return (l3.src, l3.dst, l4.sport, l4.dport, 0)
        # Flip the tuple so a response keys to the request that produced it.
        return (l3.dst, l3.src, l4.dport, l4.sport, 0)

    def _radius_prune(self, now: float) -> None:
        window = self.cfg.radius_correlate_window_s
        stale = [k for k, v in self.radius_pending.items()
                 if now - v[0] > window]
        for k in stale:
            del self.radius_pending[k]
        # Hard cap regardless of the window, so a flood cannot grow the table.
        while len(self.radius_pending) > self.cfg.radius_pending_max:
            oldest = min(self.radius_pending,
                         key=lambda k: self.radius_pending[k][0])
            del self.radius_pending[oldest]

    def rule_radius_proxy_state_correlation(self, l3: L3, l4: L4,
                                            pkt: RadiusPacket, ts: float,
                                            is_request: bool) -> None:
        """
        F1. A conforming RADIUS server echoes back EXACTLY the Proxy-State
        attributes the request carried, byte for byte. A response carrying
        Proxy-State the request did not, or a different set, means something
        between the observed request and the server injected it - which is
        what a forged Access-Accept on the NAS-side leg looks like.

        Correlating rather than applying a flat "a NAS must never receive
        Proxy-State" rule is deliberate: legitimate proxy chains DO return
        Proxy-State to the proxy that added it, so a role-free rule would
        fire on every proxy hop. Correlation needs no operator configuration.
        """
        self._radius_prune(ts)
        key = self._radius_key(l3, l4, is_request) + (pkt.identifier,)

        if is_request:
            self.radius_pending[key] = (ts, pkt.proxy_state_digests,
                                        pkt.authenticator.hex())
            # Enforce the cap AFTER inserting. Pruning only on the way in left
            # the table sitting at radius_pending_max + 1 - caught by the
            # bound assertion in the self-test, which is why that assertion
            # uses a strict <= rather than a rounded "about".
            while len(self.radius_pending) > self.cfg.radius_pending_max:
                oldest = min(self.radius_pending,
                             key=lambda k: self.radius_pending[k][0])
                del self.radius_pending[oldest]
            return

        if pkt.code not in RADIUS_RESPONSE_CODES:
            return
        entry = self.radius_pending.pop(key, None)

        if entry is None:
            if not (pkt.proxy_state_count
                    and self.cfg.radius_report_unmatched_proxy_state):
                return
            self.add("AG-212", ts, {
                "src": l3.src, "dst": l3.dst,
                "radius_code": pkt.code_name, "identifier": pkt.identifier,
                "case": "no_matching_request",
                "confidence": "low",
                "response_proxy_state_count": pkt.proxy_state_count,
                "note": "A response carries Proxy-State but the matching request "
                        "was not observed, so this CANNOT be judged - an "
                        "asymmetric tap, a capture started mid-exchange, or a tap "
                        "placed inside a proxy chain all produce it legitimately. "
                        "Reported only because radius_report_unmatched_proxy_state "
                        "is enabled. LOW CONFIDENCE BY CONSTRUCTION.",
            }, suppress_key=(l3.src, l3.dst))
            return

        _req_ts, req_digests, req_auth = entry
        if set(pkt.proxy_state_digests) == set(req_digests):
            return

        injected = [d for d in pkt.proxy_state_digests if d not in req_digests]
        dropped = [d for d in req_digests if d not in pkt.proxy_state_digests]
        case = "added_to_bare_request" if not req_digests else "set_mismatch"
        self.add("AG-212", ts, {
            "src": l3.src, "dst": l3.dst,
            "radius_code": pkt.code_name, "identifier": pkt.identifier,
            "case": case, "confidence": "high",
            "request_proxy_state_count": len(req_digests),
            "response_proxy_state_count": pkt.proxy_state_count,
            "injected_attr_count": len(injected),
            "dropped_attr_count": len(dropped),
            "request_authenticator": req_auth,
            "note": "The observed request and its response disagree about "
                    "Proxy-State. A conforming server echoes Proxy-State back "
                    "unchanged, so a response carrying attributes the request did "
                    "not is evidence of injection between the tap and the server - "
                    "the shape of a forged Access-Accept on the NAS-side leg of "
                    "CVE-2024-3596. Attribute VALUES are never retained; the "
                    "comparison is over digests only.",
        }, suppress_key=(l3.src, l3.dst, case))

    def rule_radius_opaque_payload(self, l3: L3, l4: L4, pkt: RadiusPacket,
                                   ts: float) -> None:
        """
        F2. Per blastradius.fail the forged Access-Accept does not have to use
        Proxy-State - the collision data can sit in Vendor-Specific or
        Reply-Message instead. AG-201 is Proxy-State-only by design (D1), so
        without these two rules the NAS-side leg is unmonitored.

        Restricted to Access-Accept and Access-Challenge: a REQUEST carrying
        an opaque vendor attribute is ordinary. EAP-Message stays excluded,
        which is the D1 lesson.
        """
        if pkt.code not in (RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_CHALLENGE):
            return

        if pkt.reply_message_invalid_utf8:
            self.add("AG-213", ts, {
                "src": l3.src, "dst": l3.dst,
                "radius_code": pkt.code_name, "identifier": pkt.identifier,
                "invalid_reply_messages": pkt.reply_message_invalid_utf8,
                "reply_message_count": pkt.reply_message_count,
                "note": "RFC 2865 defines Reply-Message as displayable text, so "
                        "invalid UTF-8 is a DETERMINISTIC structural anomaly - no "
                        "threshold and no entropy estimate involved. Consistent "
                        "with a chosen-prefix collision block smuggled in a "
                        "Reply-Message on the NAS-side leg of CVE-2024-3596. "
                        "Message content is never captured.",
            }, suppress_key=(l3.src, l3.dst))

        if pkt.opaque_vendor_attrs:
            worst = max(pkt.opaque_vendor_attrs, key=lambda r: r[0])
            self.add("AG-214", ts, {
                "src": l3.src, "dst": l3.dst,
                "radius_code": pkt.code_name, "identifier": pkt.identifier,
                "opaque_attr_count": len(pkt.opaque_vendor_attrs),
                "largest_attr_len": worst[0],
                "normalised_entropy": worst[1],
                "longest_printable_run": worst[2],
                "cleartext_vendor_attrs": pkt.cleartext_vendor_attrs,
                "unknown_vendor_attrs": pkt.unknown_vendor_attrs,
                "thresholds": {
                    "min_len": self.cfg.radius_opaque_min_len,
                    "entropy_min": self.cfg.radius_opaque_entropy_min,
                    "print_run_max": self.cfg.radius_opaque_print_run_max,
                },
                "note": "A Vendor-Specific attribute is long, high-entropy and "
                        "essentially non-printable, unlike the printable AV-pair "
                        "strings vendors actually send. Consistent with collision "
                        "data smuggled outside Proxy-State on the NAS-side leg. "
                        "THRESHOLDS ARE STRUCTURAL ANOMALY BOUNDS measured against "
                        "real AV-pairs, NOT published exploit constants - entropy "
                        "alone does not separate the two populations, so the "
                        "printable-run length is the discriminator and a middle "
                        "band deliberately emits nothing. Values never captured.",
            }, suppress_key=(l3.src, l3.dst))

    def rule_tacacs(self, l3: L3, l4: L4, ts: float) -> None:
        self.rule_accounting_credential(l3, l4, ts, "tacacs+")

    def rule_accounting_credential(self, l3: L3, l4: L4, ts: float,
                                   proto: str) -> None:
        """
        CVE-2025-0936: gNOI File TransferToRemote credentials end up in local
        or remote accounting records.  Credential material is NEVER logged by
        this module - the finding records the marker and lengths only.
        """
        body = l4.payload
        if not body:
            return
        low = bytes(body[:512]).lower()
        if b"transfertoremote" not in low:
            return
        self.add("AG-211", ts, {
            "src": l3.src, "dst": l3.dst, "protocol": proto,
            "record_len": len(body),
            "note": "An accounting record references gNOI File TransferToRemote. "
                    "Per SA-0117 these records may carry the remote-server "
                    "credentials in the clear. Credential material is deliberately "
                    "NOT captured in this finding - rotate the remote-server "
                    "credentials and check accounting log retention.",
        }, suppress_key=(l3.src, l3.dst))

    # -- tunnels ---------------------------------------------------------
    def rule_vxlan(self, l3: L3, l4: L4, ts: float) -> None:
        self.decap_endpoints.add(l3.dst)
        if self._exposure_scoped(l3.dst):
            self.add("AG-106", ts, {
                "vtep": l3.dst, "src": l3.src, "dport": l4.dport,
                "note": "VXLAN decapsulation endpoint. Per SA-0137 a device "
                        "configured to decapsulate one tunnel type will also accept "
                        "other tunnel protocols destined to the same IP.",
            }, suppress_key=(l3.dst,))

    def rule_tunnel_decap(self, l2: L2, l3: L3, ts: float) -> None:
        name = TUNNEL_PROTOS.get(l3.proto)
        if name is None:
            return
        if l3.dst not in self.decap_endpoints:
            return
        self.add("AG-203", ts, {
            "src": l3.src, "decap_ip": l3.dst,
            "observed_protocol": name, "ip_proto": l3.proto,
            "note": f"{name} traffic destined to an IP observed acting as a tunnel "
                    f"decapsulation endpoint. CVE-2026-7473: the switch does not "
                    f"verify the tunnel protocol type, so a protocol that was never "
                    f"configured is decapsulated and forwarded anyway. ACTIVELY "
                    f"EXPLOITED; Arista has stated no patch is planned.",
            "exploited": True,
        }, suppress_key=(l3.src, l3.dst, l3.proto))

    def rule_ipsec_present(self, l3: L3, ts: float) -> None:
        # AH can appear either as the L4 protocol or as a link in an IPv6
        # extension-header chain. Before the D7 walk, an AH-wrapped packet
        # reported proto=51 and this rule caught it by accident; now that the
        # walk resolves through AH to the real L4, the chain must be checked
        # explicitly or IPsec presence would be silently lost.
        if l3.proto not in (IPPROTO_ESP, IPPROTO_AH) \
                and IPV6_EXT_AH not in l3.ext_headers:
            return
        if not self._exposure_scoped(l3.dst):
            return
        self.add("AG-105", ts, {
            "src": l3.src, "dst": l3.dst,
            "ip_proto": l3.proto,
            "note": "IPsec dataplane in use. CVE-2025-8873 lets a crafted packet "
                    "halt all IPsec processing, and recovery additionally needs the "
                    "ipsec-egress-padding-removal TCAM profile - which a version "
                    "check alone cannot confirm has been applied.",
        }, suppress_key=(l3.src, l3.dst))

    # -- VLAN ------------------------------------------------------------
    def rule_vlan_stack(self, l2: L2, ts: float) -> None:
        if len(l2.vlan_tags) <= self.cfg.max_vlan_tags:
            return
        self.add("AG-205", ts, {
            "src_mac": l2.src, "dst_mac": l2.dst,
            "vlan_tags": list(l2.vlan_tags),
            "tpids": [hex(t) for t in l2.tpids],
            "threshold": self.cfg.max_vlan_tags,
            "note": "VLAN tag stack deeper than configured maximum. Consistent with "
                    "the incorrect-tag condition in CVE-2024-5872, whose consequence "
                    "is a punt to CPU causing route flaps or phantom multicast "
                    "routes. STRUCTURAL HEURISTIC - Arista has not published the "
                    "exact malformation.",
        }, suppress_key=(l2.src, l2.vlan_tags))

    def rule_vlan_isolation(self, l2: L2, l3: L3, ts: float) -> None:
        # An UNTAGGED frame carries no VLAN identity the sensor can read - it
        # is the native VLAN, whose number is a property of the port config,
        # not of the frame.  Comparing untagged against tagged would fire on
        # every trunk that carries both, which is most of them.  Only frames
        # that actually carry a tag take part in the comparison.
        if not l2.vlan_tags:
            return
        vlan = l2.vlan_tags[0]
        seen = self.mac_vlans.setdefault(l2.src, set())
        if seen and vlan not in seen:
            self.add("AG-207", ts, {
                "src_mac": l2.src, "src_ip": l3.src,
                "observed_vlan": vlan,
                "previously_seen_vlans": sorted(seen),
                "note": "Source MAC previously observed only on other VLANs. "
                        "Consistent with CVE-2024-11185 (L2 ingress forwarded to "
                        "ports in other VLANs). REQUIRES the sensor to see both "
                        "VLANs; legitimate causes include a moved host or a trunk "
                        "reconfiguration, so treat as a lead, not a verdict.",
            }, suppress_key=(l2.src, vlan))
        seen.add(vlan)
        if len(seen) > 16:
            seen.clear()
            seen.add(vlan)

    def rule_policy_bypass(self, l2: L2, l3: L3, ts: float) -> None:
        # Stays silent without operator intent.  Without knowing what the
        # Traffic Policy was supposed to drop, "untagged traffic arrived" is
        # not evidence of anything.
        if not self.cfg.policy_blocked:
            return
        if l2.vlan_tags:
            return
        if l3.dst not in self.cfg.policy_blocked:
            return
        self.add("AG-206", ts, {
            "src": l3.src, "dst": l3.dst,
            "note": "Untagged traffic reached a destination the operator declared "
                    "policy-blocked. CVE-2024-9448: untagged packets do not hit "
                    "Traffic Policy rules, so a drop rule silently forwards.",
        }, suppress_key=(l3.src, l3.dst))

    # -- 802.1X ----------------------------------------------------------
    def handle_eapol(self, l2: L2, ts: float) -> None:
        f = parse_eapol(l2.payload)
        if f is None:
            return
        vlan = l2.vlan_tags[0] if l2.vlan_tags else 0
        self.eapol_vlans.add(vlan)
        self.add("AG-107", ts, {
            "src_mac": l2.src, "vlan": vlan,
            "eapol_type": f.etype, "eap_code": f.eap_code,
            "note": "EAPOL-capable device observed. CVE-2024-6858: in multi-auth "
                    "mode, an EAPOL-capable device in the fallback VLAN can let "
                    "unauthenticated hosts onto the port.",
        }, suppress_key=(l2.src, vlan))
        self.unauth_after_eapol.setdefault(vlan, set())

    # -- OSPFv3 ----------------------------------------------------------
    def rule_ospfv3(self, l3: L3, ts: float) -> None:
        if l3.proto != IPPROTO_OSPF or l3.version != 6:
            return
        body = l3.payload
        if len(body) < self.cfg.ospfv3_min_header_len:
            return
        ver = body[0]
        if ver != 3:
            return
        ptype = body[1]
        if self._exposure_scoped(l3.dst):
            self.add("AG-109", ts, {
                "src": l3.src, "dst": l3.dst, "ospf_type": ptype,
                "note": "OSPFv3 speaker observed. CVE-2025-8872 needs OSPFv3 "
                        "configured with at least one neighbour present.",
            }, suppress_key=(l3.src,))
        declared = _u16(body, 2)
        anomaly = None
        if declared > len(body):
            anomaly = (f"declared OSPFv3 packet length {declared} exceeds the "
                       f"{len(body)} bytes actually present")
        elif ptype == 4 and len(body) >= 20:
            count = int.from_bytes(body[16:20], "big")
            if count > self.cfg.ospfv3_max_lsa_count:
                anomaly = (f"LSA count {count} exceeds the structural bound "
                           f"{self.cfg.ospfv3_max_lsa_count}")
        if anomaly:
            self.add("AG-209", ts, {
                "src": l3.src, "dst": l3.dst, "ospf_type": ptype,
                "anomaly": anomaly,
                "note": "STRUCTURAL HEURISTIC. Arista has not published the "
                        "malformation behind CVE-2025-8872, so this rule detects a "
                        "structurally impossible OSPFv3 packet, not the exploit "
                        "itself. Corroborate with ospfwatch and with OSPFv3 process "
                        "CPU on the device.",
            }, suppress_key=(l3.src, ptype))

    # -- management plane ------------------------------------------------
    def rule_gnmi(self, l3: L3, l4: L4, ts: float) -> None:
        if not self._exposure_scoped(l3.dst):
            return
        self.add("AG-103", ts, {
            "src": l3.src, "dst": l3.dst,
            "sport": l4.sport, "dport": l4.dport,
            "note": "gNMI/gNOI listener. CVE-2025-1259/1260 require OpenConfig with "
                    "a gNOI server; CVE-2025-0936 requires a gNMI transport. The "
                    "RPCs themselves are gRPC over TLS and are NOT readable "
                    "passively - this is an exposure finding, not an attack "
                    "detection.",
        }, suppress_key=(l3.dst, l4.dport))

    def rule_cvx(self, l3: L3, l4: L4, ts: float) -> None:
        if not self._exposure_scoped(l3.dst):
            return
        self.add("AG-108", ts, {
            "src": l3.src, "dst": l3.dst, "dport": l4.dport,
            "note": "CVX control session. CVE-2025-5089 crashes the Sysdb agent ON "
                    "THE EOS SWITCH, causing a soft reset, when the connected CVX "
                    "server sends malformed messages. Per SA-0126 this channel has "
                    "no TLS support (RFE1294850). Switches not connected to CVX are "
                    "unaffected.",
        }, suppress_key=(l3.src, l3.dst))

    def rule_ssh(self, l3: L3, l4: L4, ts: float) -> None:
        banner = parse_ssh_banner(l4.payload)
        if banner is None:
            return
        why = openssh_regresshion_affected(banner)
        if why is None:
            return
        self.add("AG-104", ts, {
            "src": l3.src, "dst": l3.dst, "sport": l4.sport,
            "banner": banner, "reason": why,
            "note": "The SSH identification string precedes encryption, so this is "
                    "a direct observation. Confirms the OpenSSH window for "
                    "CVE-2024-6387; CVE-2024-6409 shares the affected trains. Does "
                    "NOT confirm the EOS build - screen the version separately.",
        }, suppress_key=(l3.src, l4.sport, banner))


# ---------------------------------------------------------------------------
# Capture path
# ---------------------------------------------------------------------------
#
# This is the ONE function that imports scapy, and it is never executed by any
# offline tier.  SUITE-WIDE LESSON C: that leaves it untested unless something
# drives it deliberately - a scapy cross-check tier driving it through scapy's
# own offline sniff is the follow-up work for this module.

# BASE terms: the ports, protocols and ethertypes that specific rules key on.
_BPF_BASE = (
    "ether proto 0x88cc or ether proto 0x888e or "
    "udp port 1812 or udp port 1813 or udp port 1645 or udp port 1646 or "
    "udp port 4789 or udp port 8472 or tcp port 49 or udp port 49 or "
    "tcp port 6030 or tcp port 9339 or tcp port 50051 or tcp port 9979 or "
    "tcp port 22 or proto 47 or proto 50 or proto 51 or proto 4 or proto 41 or "
    "proto 89"
)


def build_bpf_filter(cfg: "Config") -> str:
    """
    Build the capture filter for a given configuration.

    THIS IS NOT COSMETIC.  Three rules operate on ARBITRARY traffic rather
    than on a specific port or protocol:

        AG-205  any frame whose VLAN tag stack is too deep
        AG-207  any MAC that appears on a VLAN it has not been seen on
        AG-206  any untagged frame reaching an operator-declared blocked
                destination

    A filter built only from ports and protocols admits none of that, so in
    production those three rules could never fire - the frames would be
    dropped by libpcap before the engine ever saw them.  Every offline tier
    feeds bytes straight to handle_frame() and bypasses BPF entirely, so all
    of them passed while this was broken.  The sealed-namespace lab, which
    puts frames through a real kernel capture path, is what found it.

    THE LINUX VLAN-STRIPPING PROBLEM (found by the sealed-namespace lab)

    On Linux AF_PACKET the kernel strips the OUTER 802.1Q tag into the packet
    auxdata BEFORE the BPF program runs, and libpcap re-inserts it afterwards
    for the reader.  So the parser sees the tag but the FILTER does not:

        3-tag frame  -> BPF sees ethertype 0x8100 (the second tag)  MATCHES
        tagged EAPOL -> BPF sees ethertype 0x888e                   MATCHES
        tagged IPv4  -> BPF sees ethertype 0x0800                   NO MATCH

    tcpdump's `vlan` keyword copes because libpcap, compiling against a LIVE
    handle, emits a program that consults SKF_AD_VLAN_TAG.  scapy compiles
    against a DEAD handle (pcap_open_dead), which cannot, so `vlan` there is
    only an ethertype test.  This was measured, not assumed: with the same
    filter string, tcpdump captured both singly-tagged frames and scapy
    captured neither.

    Consequence: AG-207 (and AG-205 for singly-tagged frames) cannot be
    admitted by a port/protocol filter at all.  cfg.vlan_broad_capture=True
    admits all IP traffic so those rules can work.  It is OFF by default
    because on a busy SPAN port that is a large volume increase, and that is
    the operator's call to make, not a default to bury.

    Ordering matters: in libpcap the bare `vlan` primitive SHIFTS the offsets
    of everything that follows it in the expression, so it must come LAST.
    """
    terms = [f"({_BPF_BASE})"]
    # D7 / PRIME DIRECTIVE. libpcap CANNOT chase the IPv6 extension-header
    # chain: a clause like `udp port 1812` reads the next-header byte at a
    # FIXED offset, so the identical packet behind a Hop-by-Hop header is
    # never admitted. ciscoguard measured this with tcpdump - plain IPv6
    # matched, the same packet behind HBH/Routing/Fragment/AH/Dest-Opts did
    # not. An ethertype branch alone would ship a sensor blind to exactly the
    # evasion traffic. Admit any IPv6 packet whose FIRST next-header is an
    # extension header and let the parser's bounded walk do the rest.
    terms.append("ip6[6] = 0 or ip6[6] = 43 or ip6[6] = 44 or "
                 "ip6[6] = 51 or ip6[6] = 60")
    if cfg.vlan_broad_capture:
        terms.append("ether proto 0x8100 or ether proto 0x88a8 or ip or ip6")
    hosts = sorted(set(cfg.policy_blocked) | set(cfg.decap_endpoints))
    for h in hosts:
        # Quoted per-host terms so an operator-supplied value cannot inject
        # filter syntax.
        if re.fullmatch(r"[0-9a-fA-F:.]{2,45}", h):
            terms.append(f"host {h}")
    # `vlan` matches any VLAN-tagged frame. On a trunk SPAN this admits a lot
    # of traffic - that is the documented cost of AG-205 and AG-207 working
    # at all. MUST BE LAST (see the offset-shift note above).
    terms.append("vlan")
    return " or ".join(terms)


# Default filter, used by the docs and by tests. run_capture() builds its own
# from the live configuration so that policy_blocked and decap_endpoints are
# actually admitted.
BPF_FILTER = build_bpf_filter(Config())


def run_capture(cfg: Config, engine: AristaEngine) -> None:  # pragma: no cover
    from scapy.all import sniff  # noqa: PLC0415  - lazy by design

    def _cb(pkt: Any) -> None:
        engine.handle_frame(bytes(pkt), float(pkt.time))

    sniff(iface=cfg.iface or None, filter=build_bpf_filter(cfg), prn=_cb,
          store=False, timeout=cfg.timeout or None)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_CHECKS = 0
_FAILS: list[str] = []


def check(cond: bool, label: str) -> None:
    global _CHECKS
    _CHECKS += 1
    if not cond:
        _FAILS.append(label)


def _mk_eth(dst: bytes, src: bytes, et: int, payload: bytes = b"",
         vlans: Iterable[int] = ()) -> bytes:
    out = dst + src
    for v in vlans:
        out += b"\x81\x00" + bytes([(v >> 8) & 0x0F, v & 0xFF])
    out += bytes([(et >> 8) & 0xFF, et & 0xFF]) + payload
    return out


def _mk_ipv4(src: str, dst: str, proto: int, payload: bytes = b"") -> bytes:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    tl = 20 + len(payload)
    return (b"\x45\x00" + tl.to_bytes(2, "big") + b"\x00\x00\x40\x00\x40"
            + bytes([proto]) + b"\x00\x00" + s + d + payload)


def _mk_udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    ln = 8 + len(payload)
    return (sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + ln.to_bytes(2, "big") + b"\x00\x00" + payload)


def _mk_tcp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return (sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x02" + b"\x50\x18"
            + b"\xff\xff\x00\x00\x00\x00" + payload)


def _mk_lldp_tlv(t: int, val: bytes) -> bytes:
    hdr = (t << 9) | (len(val) & 0x1FF)
    return hdr.to_bytes(2, "big") + val


def _mk_lldp(sysname: str, sysdesc: str) -> bytes:
    return (_mk_lldp_tlv(1, b"\x04\x00\x1c\x73\x00\x00\x01")
            + _mk_lldp_tlv(2, b"\x03Et1")
            + _mk_lldp_tlv(3, b"\x00\x78")
            + _mk_lldp_tlv(5, sysname.encode())
            + _mk_lldp_tlv(6, sysdesc.encode())
            + _mk_lldp_tlv(0, b""))


def _mk_lldp_mgmt(ip: str, sysdesc: str = "Arista Networks EOS version "
                  "4.32.1F running on an Arista Networks DCS-7280R-48C6",
                  v6: bool = False) -> bytes:
    """An LLDP frame carrying a management-address TLV (type 8), for the
    RADIUS Arista-scope tests. IPv4 (subtype 1) or IPv6 (subtype 2)."""
    if v6:
        # Minimal literal-to-bytes for the test fixtures (handles one "::").
        head, _, tail = ip.partition("::")
        hgroups = [int(g, 16) for g in head.split(":") if g]
        tgroups = [int(g, 16) for g in tail.split(":") if g]
        mid = [0] * (8 - len(hgroups) - len(tgroups))
        groups = hgroups + mid + tgroups
        addr = b"".join(g.to_bytes(2, "big") for g in groups)
        subtype = 2
    else:
        addr = bytes(int(x) for x in ip.split("."))
        subtype = 1
    # addr-string-len (1 + len(addr)) | subtype | address | iface
    # subtype (2=ifIndex) | 4-byte iface number | 1-byte OID string length (0)
    mgmt = (bytes([1 + len(addr), subtype]) + addr
            + bytes([2]) + b"\x00\x00\x00\x01" + bytes([0]))
    return (_mk_lldp_tlv(1, b"\x04\x00\x1c\x73\x00\x00\x02")
            + _mk_lldp_tlv(2, b"\x03Et1")
            + _mk_lldp_tlv(3, b"\x00\x78")
            + _mk_lldp_tlv(5, b"sw-mgmt")
            + _mk_lldp_tlv(6, sysdesc.encode())
            + _mk_lldp_tlv(8, mgmt)
            + _mk_lldp_tlv(0, b""))


def _mk_radius_v(code: int, ident: int,
                 attrs: Iterable[tuple[int, bytes]],
                 auth: bytes = b"\xaa" * 16) -> bytes:
    """Build a RADIUS packet from (type, VALUE) pairs, for the F1/F2 tests
    where attribute CONTENT is what is being exercised."""
    body = b"".join(bytes([t, 2 + len(v)]) + v for t, v in attrs)
    return (bytes([code, ident]) + struct.pack("!H", 20 + len(body))
            + auth + body)


def _mk_vsa(payload: bytes, vendor: int = 9) -> bytes:
    return (vendor.to_bytes(4, "big") + bytes([1, len(payload) + 2]) + payload)


def _mk_radius(code: int, ident: int, attrs: Iterable[tuple[int, int]]) -> bytes:
    body = b""
    for atype, alen in attrs:
        body += bytes([atype, alen]) + b"\x00" * (alen - 2)
    total = 20 + len(body)
    return (bytes([code, ident]) + total.to_bytes(2, "big")
            + b"\xaa" * 16 + body)


RADIUS_ATTR_EAP_MESSAGE = 79


def _mk_ip6(nh: int, payload: bytes,
            src: bytes = b"\x20\x01" + b"\x00" * 14,
            dst: bytes = b"\x20\x01" + b"\x00" * 13 + b"\x02") -> bytes:
    return (b"\x60\x00\x00\x00" + len(payload).to_bytes(2, "big")
            + bytes([nh, 64]) + src + dst + payload)


def _mk_exthdr(kind: int, nxt: int, frag_offset: int = 0) -> bytes:
    """Build one IPv6 extension header of the given kind."""
    if kind == IPV6_EXT_FRAGMENT:
        return bytes([nxt, 0]) + ((frag_offset << 3) | (1 if frag_offset else 0)
                                  ).to_bytes(2, "big") + b"\x00" * 4
    if kind == IPV6_EXT_AH:
        # RFC 4302: length is in 4-octet units MINUS 2, so 1 -> 12 bytes.
        return bytes([nxt, 1]) + b"\x00" * 10
    # HBH / Routing / Dest-Opts: 8-octet units not counting the first 8.
    return bytes([nxt, 0]) + b"\x00" * 6


ARISTA_DESC = ("Arista Networks EOS version 4.32.1F running on an "
               "Arista Networks DCS-7280R-48C6")


# The fixed set of RADIUS endpoint IPs the tests use as NAS/server. Since the
# RADIUS rules are now scoped to Arista hardware (radius_arista_endpoints), a
# test config must place these in scope or every RADIUS fixture goes silent.
# They are declared here once so the individual test bodies stay unchanged; a
# test that needs an OUT-of-scope address (e.g. to prove the gate) passes its
# own cfg. A "*" wildcard would mask scope regressions, so the real IPs are
# listed instead.
_TEST_RADIUS_ENDPOINTS = (
    "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.5.5.5",
    # IPv6 endpoints in the module's own (non-RFC-5952) _ipv6 string form.
    "2001:0:0:0:0:0:0:0", "2001:0:0:0:0:0:0:2",      # F-test v6 / EH helpers
    "2001:db8:0:0:0:0:0:1", "2001:db8:0:0:0:0:0:2",  # D7 EH fixtures
)


def _run(frames: Iterable[bytes], cfg: Optional[Config] = None) -> AristaEngine:
    if isinstance(frames, (bytes, bytearray)):
        raise TypeError("_run expects a SEQUENCE of frames, not a bare bytes "
                        "object - iterating bytes yields ints and would test "
                        "nothing at all")
    if cfg is None:
        cfg = Config(radius_arista_endpoints=_TEST_RADIUS_ENDPOINTS)
    eng = AristaEngine(cfg or Config())
    for i, f in enumerate(frames):
        eng.handle_frame(f, ts=1000.0 + i)
    return eng


def _codes(eng: AristaEngine) -> set[str]:
    return {f.code for f in eng.findings}


# ---- catalog integrity ----------------------------------------------------

def test_catalog() -> None:
    seen = set()
    for e in CVE_CATALOG:
        check(e.cve not in seen, f"duplicate catalog entry {e.cve}")
        seen.add(e.cve)
        check(e.detect in ("attack", "heuristic", "exposure", "posture", "none"),
              f"{e.cve}: bad detect value {e.detect!r}")
        check(e.score_confidence in ("advisory", "secondary"),
              f"{e.cve}: bad score_confidence {e.score_confidence!r}")
        check(0.0 < e.cvss <= 10.0, f"{e.cve}: implausible cvss {e.cvss}")
        check(len(e.note) > 40, f"{e.cve}: note too short to be useful")
        check(e.advisory.startswith("SA-"), f"{e.cve}: advisory not an SA number")
        for c in e.codes:
            check(c in FINDINGS, f"{e.cve} references unknown code {c}")
    check(len(CVE_CATALOG) == 17,
          f"expected 17 catalog entries, got {len(CVE_CATALOG)}")

    # Every detect="none" CVE must SAY so, in writing.  This is the guard
    # against "we cover 17 CVEs" quietly becoming a lie.
    for e in CVE_CATALOG:
        if e.detect == "none":
            check("POSTURE ONLY" in e.note or "no network-observable" in e.note
                  or "never crosses the wire" in e.note,
                  f"{e.cve}: detect=none but the note does not say so")

    # Unwired codes must be declared, reasoned, and never claimed as
    # detections.  A silently-absent rule is how "we cover N CVEs" rots.
    for code, reason in UNWIRED_CODES.items():
        check(code in FINDINGS, f"UNWIRED_CODES names unknown code {code}")
        check(len(reason) > 120, f"{code}: unwired reason too thin")
    check(set(UNWIRED_CODES) == {"AG-208", "AG-210"},
          f"unwired set drifted: {sorted(UNWIRED_CODES)}")
    for code, reason in LAB_DEFERRED_CODES.items():
        check(code in FINDINGS, f"LAB_DEFERRED_CODES names unknown code {code}")
        check(len(reason) > 150, f"{code}: lab-deferred reason too thin")
        check(code not in UNWIRED_CODES,
              f"{code} cannot be both unwired AND lab-deferred - a rule that "
              f"does not exist is not a capture-stack limitation")
    for e in CVE_CATALOG:
        if e.detect == "attack":
            wired = [c for c in e.codes
                     if c.startswith("AG-2") and c not in UNWIRED_CODES]
            check(wired, f"{e.cve} claims detect=attack but every AG-2xx code "
                         f"it names is unwired")

    # Quarantine must carry substantive reasons.
    check(len(QUARANTINED_CVES) == 6,
          f"expected 6 quarantined CVEs, got {len(QUARANTINED_CVES)}")
    for cve, reason in QUARANTINED_CVES:
        check(len(reason) > 80, f"{cve}: quarantine reason too thin")
        check(cve not in seen, f"{cve} is both quarantined AND in the catalog")

    # Every finding code must be reachable from some CVE, except the pure
    # observation codes.
    referenced = {c for e in CVE_CATALOG for c in e.codes}
    observational = {"AG-001", "AG-005", "AG-009"}
    for code in FINDINGS:
        check(code in referenced or code in observational,
              f"{code} is referenced by no CVE and is not observational")

    for code, spec in FINDINGS.items():
        check(spec.klass in ("posture", "exposure", "attack"),
              f"{code}: bad class {spec.klass}")
        check(spec.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
              f"{code}: bad severity {spec.severity}")
        pfx = {"posture": "AG-0", "exposure": "AG-1", "attack": "AG-2"}[spec.klass]
        check(code.startswith(pfx),
              f"{code} is class {spec.klass} but does not use the {pfx}xx range")
        for cve in spec.cves:
            check(cve in seen, f"{code} references non-catalog CVE {cve}")


def test_severity_floor() -> None:
    cfg = Config()
    scoped = [e for e in CVE_CATALOG if cve_in_scope(e, cfg)]
    check(len(scoped) == 17,
          f"default config should carry all 17, got {len(scoped)}")
    e7473 = next(e for e in CVE_CATALOG if e.cve == "CVE-2026-7473")
    check(e7473.cvss < cfg.min_cvss,
          "CVE-2026-7473 is supposed to sit BELOW the floor - if it no longer "
          "does, the exploitation override is no longer being exercised")
    check(cve_in_scope(e7473, cfg), "exploited override failed to carry 7473")
    off = Config(always_include_exploited=False)
    check(not cve_in_scope(e7473, off),
          "with the override off, 7473 must fall out - otherwise the floor "
          "is not actually being applied")
    check(len([e for e in CVE_CATALOG if cve_in_scope(e, off)]) == 16,
          "override off should leave exactly 16")


# ---- version handling -----------------------------------------------------

def test_versions() -> None:
    check(parse_version("4.32.5.1M") == ((4, 32, 5, 1), "M"), "parse 4.32.5.1M")
    check(parse_version("4.34.0F") == ((4, 34, 0), "F"), "parse 4.34.0F")
    check(parse_version("4.28.13") == ((4, 28, 13), ""), "parse 4.28.13")
    check(parse_version("garbage") is None, "unparseable version returns None")
    check(parse_version("") is None, "empty version returns None")

    check(version_cmp("4.32.1F", "4.32.2F") < 0, "4.32.1F < 4.32.2F")
    check(version_cmp("4.32.2F", "4.32.1F") > 0, "4.32.2F > 4.32.1F")
    check(version_cmp("4.32.1F", "4.32.1F") == 0, "equal versions")
    check(version_cmp("4.9.0", "4.10.0") < 0,
          "numeric compare must not be lexical - 4.9 < 4.10")
    check(version_cmp("4.32.1", "4.32.1M") < 0, "empty suffix sorts before M")
    check(version_cmp("4.33.0F", "4.32.9M") > 0,
          "a higher numeric component must beat a suffix")
    check(version_cmp("bad", "4.0") is None, "unparseable compare returns None")

    check(in_branch("4.32.5.1M", "4.32"), "4.32.5.1M in branch 4.32")
    check(not in_branch("4.33.0F", "4.32"), "4.33.0F not in branch 4.32")
    check(in_branch("4.34.0F", "4"), "catch-all branch 4 matches")

    e6387 = next(e for e in CVE_CATALOG if e.cve == "CVE-2024-6387")
    v, _ = screen_version("4.32.1F", e6387)
    check(v == "vulnerable", f"4.32.1F should be vulnerable to 6387, got {v}")
    v, _ = screen_version("4.32.2F", e6387)
    check(v == "not_vulnerable", f"4.32.2F should be fixed for 6387, got {v}")
    # SA-0100 states 4.31.x and below are explicitly NOT impacted, and the
    # table only enumerates 4.32 - so 4.31 must come back inferred_clean,
    # never a confident not_vulnerable.
    v, why = screen_version("4.31.0F", e6387)
    check(v == "inferred_clean",
          f"4.31.0F should be inferred_clean for 6387, got {v}")
    check("NOT confirmed patched" in why,
          "inferred_clean must say in words that it is not a clean bill of health")

    e6409 = next(e for e in CVE_CATALOG if e.cve == "CVE-2024-6409")
    check(screen_version("4.33.3.1F", e6409)[0] == "vulnerable",
          "4.33.3.1F is vulnerable to 6409")
    check(screen_version("4.34.1F", e6409)[0] == "not_vulnerable",
          "4.34.1F is fixed for 6409")

    e24509 = next(e for e in CVE_CATALOG if e.cve == "CVE-2023-24509")
    check(screen_version("4.30.0F", e24509)[0] == "unscreened",
          "a CVE with no version table must return unscreened, not a guess")


# ---- parsers --------------------------------------------------------------

def test_parsers() -> None:
    try:
        parse_l2(b"\x00" * 60)
    except TypeError:
        check(False, "parse_l2 rejected a legitimate bytes frame")
    raised = False
    try:
        parse_l2(0)  # type: ignore[arg-type]
    except TypeError:
        raised = True
    check(raised, "parse_l2 must reject a non-bytes argument loudly")

    check(parse_l2(b"\x00" * 8) is None, "runt frame returns None")

    f = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4, b"payload", vlans=(100, 200))
    l2 = parse_l2(f)
    check(l2 is not None and l2.vlan_tags == (100, 200), "double tag parsed")
    check(l2 is not None and l2.ethertype == ETH_P_IPV4, "inner ethertype found")

    ip = _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(1812, 1812, b"x" * 4))
    l3 = parse_l3(ip, ETH_P_IPV4)
    check(l3 is not None and l3.src == "10.0.0.1", "ipv4 src parsed")
    l4 = parse_l4(l3)
    check(l4 is not None and l4.dport == 1812, "udp dport parsed")

    info = parse_lldp(_mk_lldp("sw1.example", ARISTA_DESC))
    check(info is not None and info.eos_version == "4.32.1F",
          "EOS version extracted from LLDP system description")
    check(info is not None and info.platform == "DCS-7280R-48C6",
          f"platform extracted, got {info.platform if info else None!r}")
    check(info is not None and info.is_arista, "arista flagged")
    check(info is not None and not info.is_cloudeos, "hardware is not CloudEOS")

    cinfo = parse_lldp(_mk_lldp("v1", "Arista Networks EOS version 4.30.2F "
                                   "running on a CloudEOS"))
    check(cinfo is not None and cinfo.is_cloudeos, "CloudEOS flagged")

    r = parse_radius(_mk_radius(RADIUS_ACCESS_REQUEST, 7,
                             [(RADIUS_ATTR_USER_NAME, 8),
                              (RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 18)]))
    check(r is not None and r.has_message_authenticator,
          "Message-Authenticator detected")
    check(r is not None and r.code_name == "Access-Request", "radius code name")
    r2 = parse_radius(_mk_radius(RADIUS_ACCESS_ACCEPT, 7,
                              [(RADIUS_ATTR_PROXY_STATE, 200)]))
    check(r2 is not None and not r2.has_message_authenticator,
          "absent Message-Authenticator detected")
    check(r2 is not None and r2.max_attr_len == 200, "max attr len tracked")
    check(r2 is not None and r2.max_attr_type == RADIUS_ATTR_PROXY_STATE,
          "max attr type tracked")
    # An attribute claiming length 1 is illegal and must not loop forever.
    bad = bytes([RADIUS_ACCESS_REQUEST, 1]) + (22).to_bytes(2, "big") \
        + b"\xaa" * 16 + bytes([1, 1])
    rb = parse_radius(bad)
    check(rb is not None and rb.malformed, "illegal attribute length flagged")

    check(parse_radius(b"\x01\x02") is None, "runt radius returns None")

    check(parse_ssh_banner(b"SSH-2.0-OpenSSH_9.2p1 Debian\r\n")
          == "OpenSSH_9.2p1 Debian", "ssh banner parsed")
    check(parse_ssh_banner(b"GET / HTTP/1.1\r\n") is None,
          "non-ssh payload rejected")
    check(openssh_regresshion_affected("OpenSSH_9.2p1") is not None,
          "9.2p1 is inside the regreSSHion window")
    check(openssh_regresshion_affected("OpenSSH_9.8p1") is None,
          "9.8p1 is the fix and must be outside the window")
    check(openssh_regresshion_affected("OpenSSH_8.4p1") is None,
          "8.4p1 predates the reintroduction and must be outside the window")
    check(openssh_regresshion_affected("OpenSSH_8.5p1") is not None,
          "8.5p1 is the first affected release - boundary")


# ---- per-CVE detection ----------------------------------------------------

def test_posture_rules() -> None:
    eng = _run([_mk_eth(b"\x01\x80\xc2\x00\x00\x0e", b"\x02" * 6, ETH_P_LLDP,
                     _mk_lldp("sw1", ARISTA_DESC))])
    c = _codes(eng)
    check("AG-001" in c, "AG-001 EOS version observed")
    check("AG-005" in c, "AG-005 platform observed")
    check("AG-002" in c, "AG-002 vulnerable version screened")
    check("AG-006" in c, "AG-006 7280R is a tunnel-decap affected family")
    # DCS-7280R is not a modular 7500/7800 chassis.
    check("AG-004" not in c,
          "AG-004 must NOT fire on a fixed-config platform - CVE-2023-24509 "
          "needs two supervisors")

    modular = ARISTA_DESC.replace("DCS-7280R-48C6", "DCS-7504N")
    eng = _run([_mk_eth(b"\x01" * 6, b"\x03" * 6, ETH_P_LLDP,
                     _mk_lldp("core1", modular))])
    check("AG-004" in _codes(eng), "AG-004 fires on a modular chassis")
    f = next(x for x in eng.findings if x.code == "AG-004")
    check(f.detail.get("detect") == "none",
          "AG-004 must state detect=none rather than implying a detection")

    # Scope screen-out.
    for desc in ("Arista VeloCloud Orchestrator 6.1.3",
                 "Arista CloudVision Portal 2024.1.0",
                 "Arista NG Firewall 17.0",
                 "Arista DANZ Monitoring Fabric 8.6",
                 "Arista Awake NDR sensor"):
        eng = _run([_mk_eth(b"\x01" * 6, b"\x04" * 6, ETH_P_LLDP,
                         _mk_lldp("box", desc))])
        cc = _codes(eng)
        check("AG-009" in cc, f"out-of-scope platform not screened: {desc!r}")
        check("AG-002" not in cc,
              f"out-of-scope platform was CVE-screened anyway: {desc!r}")

    # CloudEOS routes to AG-003, never AG-002.
    eng = _run([_mk_eth(b"\x01" * 6, b"\x05" * 6, ETH_P_LLDP,
                     _mk_lldp("v1", "Arista Networks EOS version 4.30.2F "
                                 "running on a CloudEOS router"))])
    cc = _codes(eng)
    check("AG-003" in cc, "AG-003 fires for CloudEOS")
    check("AG-002" not in cc, "CloudEOS must not be screened as hardware EOS")
    f = next(x for x in eng.findings if x.code == "AG-003")
    cves = {r["cve"] for r in f.detail["candidates"]}
    check(cves == {"CVE-2023-24545", "CVE-2023-24513"},
          f"AG-003 should carry exactly the two CloudEOS Sfe CVEs, got {cves}")
    check(all("CloudEOS-specific" in r["explanation"] for r in f.detail["candidates"]),
          "AG-003 rows must state WHY an unscreenable CVE was raised anyway - "
          "platform gating is the exception, and it has to be visible")

    # REGRESSION: a fully PATCHED Arista must raise no version finding at all.
    # The conformance clean-set contract caught AG-002 firing on 4.34.2F,
    # because 'unscreened' verdicts were triggering the finding - which made
    # it unconditional on every Arista device and therefore meaningless.
    patched = _mk_eth(b"\x01" * 6, b"\x0f" * 6, ETH_P_LLDP,
                      _mk_lldp("sw2", "Arista Networks EOS version 4.34.2F "
                                      "running on an Arista Networks "
                                      "DCS-7050SX3-48YC8"))
    pc = _codes(_run([patched]))
    check("AG-002" not in pc,
          "REGRESSION: a patched build must not raise AG-002 - an unscreenable "
          "CVE is not evidence of vulnerability")
    check("AG-001" in pc,
          "the patched device must still be OBSERVED, or the silence above is "
          "vacuous")
    vuln = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_LLDP,
                   _mk_lldp("sw1", ARISTA_DESC))
    check("AG-002" in _codes(_run([vuln])),
          "a genuinely vulnerable build must still raise AG-002 - the fix must "
          "not have disabled screening outright")

    # Posture findings must never claim a verdict.
    eng = _run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_LLDP,
                     _mk_lldp("sw1", ARISTA_DESC))])
    f = next(x for x in eng.findings if x.code == "AG-002")
    check("POSTURE ONLY" in f.detail["note"], "AG-002 must label itself posture")
    check(f.severity == "MEDIUM", "AG-002 severity")


def test_radius_rules() -> None:
    # AG-101: RADIUS on the wire at all.
    good = _mk_radius(RADIUS_ACCESS_REQUEST, 1,
                      [(RADIUS_ATTR_USER_NAME, 8),
                       (RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 18)])
    frame = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                    _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                             _mk_udp(50000, 1812, good)))
    c = _codes(_run([frame]))
    check("AG-101" in c, "AG-101 RADIUS observed")
    check("AG-102" not in c,
          "AG-102 must stay silent when Message-Authenticator IS present")
    check("AG-201" not in c, "AG-201 must stay silent on a normal request")

    # AG-102: request without Message-Authenticator.
    bare = _mk_radius(RADIUS_ACCESS_REQUEST, 2, [(RADIUS_ATTR_USER_NAME, 8)])
    c = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                             _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                                      _mk_udp(50000, 1812, bare)))]))
    check("AG-102" in c, "AG-102 fires on a request with no Message-Authenticator")

    # AG-110 (was AG-202, retired): an unauthenticated RESPONSE. Exposure-class.
    resp = _mk_radius(RADIUS_ACCESS_ACCEPT, 3, [(RADIUS_ATTR_USER_NAME, 8)])
    eng = _run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                        _mk_ipv4("10.0.0.2", "10.0.0.1", IPPROTO_UDP,
                                 _mk_udp(1812, 50000, resp)))])
    c = _codes(eng)
    check("AG-110" in c, "AG-110 fires on an unauthenticated Access-Accept")
    check("AG-102" not in c, "a response must raise AG-110, not AG-102")
    f = next(x for x in eng.findings if x.code == "AG-110")
    check(f.detail["case"] == "absent", "AG-110 records the absent case")
    check(f.klass == "exposure",
          "AG-110 is EXPOSURE - an unhardened server is a standing condition, "
          "not an attack event, and attack-class codes cannot be scoped")

    # AG-201: Proxy-State total over the bound.
    big = _mk_radius(RADIUS_ACCESS_REQUEST, 4, [(RADIUS_ATTR_PROXY_STATE, 250)])
    eng = _run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                        _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                                 _mk_udp(50000, 1812, big)))])
    check("AG-201" in _codes(eng), "AG-201 fires on oversized Proxy-State")
    f = next(x for x in eng.findings if x.code == "AG-201")
    check(f.detail["proxy_state_total"] == 250, "AG-201 reports the total")
    check(f.severity == "CRITICAL", "AG-201 is the module's top severity")
    check("STRUCTURAL ANOMALY BOUND" in f.detail["note"],
          "AG-201 must say its threshold is not a published exploit constant")

    # Boundary: exactly at the threshold stays silent.
    at = _mk_radius(RADIUS_ACCESS_REQUEST, 5,
                    [(RADIUS_ATTR_PROXY_STATE,
                      Config().radius_proxy_state_total_max)])
    check("AG-201" not in _codes(_run([
        _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                         _mk_udp(50000, 1812, at)))
    ])), "AG-201 at exactly the threshold must stay silent")

    # Raising the knob must SILENCE the finding.
    cfg = Config(radius_proxy_state_total_max=255)
    check("AG-201" not in _codes(_run([
        _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                         _mk_udp(50000, 1812, big)))
    ], cfg)), "raising radius_proxy_state_total_max must silence AG-201")

    # Credentials must never reach a finding.
    for f in _run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                           _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                                    _mk_udp(50000, 1812, big)))]).findings:
        blob = json.dumps(f.detail).lower()
        for word in ("password", "secret", "user_password"):
            check(word not in blob, f"RADIUS finding leaked {word!r}")


def test_tunnel_rules() -> None:
    vx = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
              _mk_ipv4("10.1.1.1", "10.1.1.9", IPPROTO_UDP,
                    _mk_udp(50000, 4789, b"\x08" + b"\x00" * 7)))
    gre = _mk_eth(b"\x01" * 6, b"\x03" * 6, ETH_P_IPV4,
               _mk_ipv4("10.9.9.9", "10.1.1.9", IPPROTO_GRE, b"\x00" * 8))

    # GRE BEFORE any VXLAN has taught us the endpoint: must stay silent.
    check("AG-203" not in _codes(_run([gre])),
          "AG-203 must not fire against an IP not known to be a decap endpoint")

    eng = _run([vx, gre])
    c = _codes(eng)
    check("AG-106" in c, "AG-106 VXLAN endpoint observed")
    check("AG-203" in c, "AG-203 GRE to a known VXLAN decap IP")
    f = next(x for x in eng.findings if x.code == "AG-203")
    check(f.detail["observed_protocol"] == "GRE", "protocol named")
    check(f.detail.get("exploited") is True, "AG-203 must carry the exploited flag")
    check("no patch is planned" in f.detail["note"],
          "AG-203 must state that no patch is planned")

    # Operator-declared endpoints work without having seen VXLAN first.
    cfg = Config(decap_endpoints=("10.1.1.9",))
    check("AG-203" in _codes(_run([gre], cfg)),
          "a configured decap endpoint should arm AG-203 directly")

    # IP-in-IP and IPv6-in-IP are the other two SA-0137 shapes.
    for proto, name in ((IPPROTO_IPIP, "IP-in-IP"), (IPPROTO_IPV6, "IPv6-in-IP")):
        fr = _mk_eth(b"\x01" * 6, b"\x03" * 6, ETH_P_IPV4,
                  _mk_ipv4("10.9.9.9", "10.1.1.9", proto, b"\x00" * 8))
        eng = _run([fr], cfg)
        check("AG-203" in _codes(eng), f"AG-203 for {name}")

    esp = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
               _mk_ipv4("10.2.2.1", "10.2.2.2", IPPROTO_ESP, b"\x00" * 16))
    check("AG-105" in _codes(_run([esp])), "AG-105 IPsec present")


def test_vlan_rules() -> None:
    deep = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(1, 2)),
                vlans=(10, 20, 30))
    eng = _run([deep])
    check("AG-205" in _codes(eng), "AG-205 on a 3-deep tag stack")
    f = next(x for x in eng.findings if x.code == "AG-205")
    check("STRUCTURAL HEURISTIC" in f.detail["note"],
          "AG-205 must label itself a heuristic")

    two = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
               _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(1, 2)),
               vlans=(10, 20))
    check("AG-205" not in _codes(_run([two])),
          "a normal QinQ double tag must stay silent at the default bound")
    check("AG-205" in _codes(_run([two], Config(max_vlan_tags=1))),
          "lowering max_vlan_tags must make the double tag fire")

    # AG-207: same MAC seen on two VLANs.
    a = _mk_eth(b"\x0a" * 6, b"\x0b" * 6, ETH_P_IPV4,
             _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(1, 2)), vlans=(10,))
    b = _mk_eth(b"\x0a" * 6, b"\x0b" * 6, ETH_P_IPV4,
             _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(1, 2)), vlans=(20,))
    eng = _run([a, b])
    check("AG-207" in _codes(eng), "AG-207 on a MAC crossing VLANs")
    check("AG-207" not in _codes(_run([a, a])),
          "AG-207 must not fire on repeated traffic within one VLAN")

    # REGRESSION: an untagged frame and a tagged frame from the SAME MAC is
    # ordinary trunk behaviour, not a VLAN isolation breach.  The first build
    # run raised AG-207 on exactly this, caught by the clean-set contract.
    untagged = _mk_eth(b"\x0c" * 6, b"\x0d" * 6, ETH_P_IPV4,
                       _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(1, 2)))
    tagged = _mk_eth(b"\x0c" * 6, b"\x0d" * 6, ETH_P_IPV4,
                     _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(1, 2)),
                     vlans=(10,))
    check("AG-207" not in _codes(_run([untagged, tagged])),
          "REGRESSION: untagged-then-tagged from one MAC is normal trunk "
          "traffic and must not raise AG-207")
    check("AG-207" not in _codes(_run([tagged, untagged])),
          "REGRESSION: tagged-then-untagged must not raise AG-207 either")
    check("AG-207" in _codes(_run([tagged, _mk_eth(
        b"\x0c" * 6, b"\x0d" * 6, ETH_P_IPV4,
        _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(1, 2)),
        vlans=(20,))])),
          "two DIFFERENT tags from one MAC must still raise AG-207 - the fix "
          "must not have disabled the rule outright")

    # AG-206 stays silent without operator intent, and fires with it.
    plain = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                 _mk_ipv4("10.0.0.1", "192.168.5.5", IPPROTO_UDP, _mk_udp(1, 2)))
    check("AG-206" not in _codes(_run([plain])),
          "AG-206 must stay silent without cfg.policy_blocked - untagged "
          "traffic alone is not evidence of a bypass")
    check("AG-206" in _codes(_run([plain], Config(policy_blocked=("192.168.5.5",)))),
          "AG-206 fires once the operator declares the destination blocked")


def test_dot1x_ospf_mgmt_rules() -> None:
    eapol = _mk_eth(b"\x01\x80\xc2\x00\x00\x03", b"\x0c" * 6, ETH_P_EAPOL,
                 b"\x02\x00\x00\x05\x02\x01\x00\x05\x01", vlans=(99,))
    eng = _run([eapol])
    check("AG-107" in _codes(eng), "AG-107 EAPOL observed")
    check(next(x for x in eng.findings if x.code == "AG-107").detail["vlan"] == 99,
          "AG-107 records the VLAN the EAPOL was seen on")

    # OSPFv3 over IPv6 - declared length longer than the bytes present.
    body = b"\x03\x04" + (900).to_bytes(2, "big") + b"\x00" * 12
    ip6 = (b"\x60\x00\x00\x00" + len(body).to_bytes(2, "big")
           + bytes([IPPROTO_OSPF, 64]) + b"\x20\x01" + b"\x00" * 14
           + b"\xff\x02" + b"\x00" * 13 + b"\x05" + body)
    eng = _run([_mk_eth(b"\x33\x33" + b"\x00" * 4, b"\x0d" * 6, ETH_P_IPV6, ip6)])
    c = _codes(eng)
    check("AG-109" in c, "AG-109 OSPFv3 adjacency observed")
    check("AG-209" in c, "AG-209 on a declared length exceeding the frame")
    f = next(x for x in eng.findings if x.code == "AG-209")
    check("STRUCTURAL HEURISTIC" in f.detail["note"],
          "AG-209 must label itself a heuristic, not a signature")

    gnmi = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                _mk_ipv4("10.0.0.5", "10.0.0.6", IPPROTO_TCP,
                      _mk_tcp(40000, 6030, b"\x00" * 8)))
    eng = _run([gnmi])
    check("AG-103" in _codes(eng), "AG-103 gNMI listener observed")
    check("NOT readable passively" in
          next(x for x in eng.findings if x.code == "AG-103").detail["note"],
          "AG-103 must state that the RPCs are inside TLS")

    cvx = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
               _mk_ipv4("10.0.0.7", "10.0.0.8", IPPROTO_TCP,
                     _mk_tcp(40001, 9979, b"\x00" * 8)))
    check("AG-108" in _codes(_run([cvx])), "AG-108 CVX session observed")

    ssh = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
               _mk_ipv4("10.0.0.9", "10.0.0.1", IPPROTO_TCP,
                     _mk_tcp(22, 40002, b"SSH-2.0-OpenSSH_9.2p1 Arista\r\n")))
    check("AG-104" in _codes(_run([ssh])), "AG-104 vulnerable SSH banner")
    ssh_ok = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                  _mk_ipv4("10.0.0.9", "10.0.0.1", IPPROTO_TCP,
                        _mk_tcp(22, 40002, b"SSH-2.0-OpenSSH_9.8p1 Arista\r\n")))
    check("AG-104" not in _codes(_run([ssh_ok])),
          "a patched OpenSSH banner must not raise AG-104")

    acct = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                _mk_ipv4("10.0.0.1", "10.0.0.3", IPPROTO_TCP,
                      _mk_tcp(40003, 49, b"cmd=gnoi File TransferToRemote host=x")))
    eng = _run([acct])
    check("AG-211" in _codes(eng), "AG-211 gNOI creds in accounting")
    f = next(x for x in eng.findings if x.code == "AG-211")
    check("record_len" in f.detail and "credential" not in json.dumps(f.detail).lower()
          or "NOT captured" in f.detail["note"],
          "AG-211 must not carry credential material")


# ---- cross-cutting behaviour ---------------------------------------------

def test_radius_blastradius_fixes() -> None:
    """
    The eight acceptance tests for the Sept 2026 RADIUS review (D1-D6).

    Every one of these passed a 494-check self-test, a 538-check conformance
    run, a 230-check cross-check and a live lab before the review, because no
    fixture anywhere contained an EAP-Message attribute, a split Proxy-State,
    a Message-Authenticator in a non-first position, or 300 attributes.
    """
    def radius_udp(pkt: bytes, dport: int = 1812, sport: int = 50000,
                   src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                       _mk_ipv4(src, dst, IPPROTO_UDP,
                                _mk_udp(sport, dport, pkt)))

    UN, MA, PS, EAP = (RADIUS_ATTR_USER_NAME, RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                       RADIUS_ATTR_PROXY_STATE, RADIUS_ATTR_EAP_MESSAGE)

    # A1 (D1). EAP-TLS request with two 255-byte EAP-Message fragments.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 1,
                                           [(UN, 8), (EAP, 255), (EAP, 255),
                                            (MA, 18)]))]))
    check(c == {"AG-101"},
          f"D1: ordinary EAP-TLS must raise AG-101 only, got {c}. EAP-Message "
          f"fragments at 255 bytes are normal 802.1X, not a collision block")

    # A2 (D1). Server Access-Challenge, M-A first, EAP fragments.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_CHALLENGE, 2,
                                           [(MA, 18), (EAP, 255), (EAP, 255)]),
                                dport=50000, sport=1812,
                                src="10.0.0.2", dst="10.0.0.1")]))
    check(c == {"AG-101"},
          f"D1: a correctly hardened Access-Challenge must raise AG-101 only, "
          f"got {c}")

    # A3 (D3). Access-Reject with Proxy-State BEFORE Message-Authenticator.
    eng = _run([radius_udp(_mk_radius(RADIUS_ACCESS_REJECT, 3,
                                      [(PS, 40), (MA, 18)]),
                           dport=50000, sport=1812,
                           src="10.0.0.2", dst="10.0.0.1")])
    check("AG-110" in _codes(eng),
          "D3: M-A present but not first must still fire - the mitigation "
          "requires it FIRST in Access-Accept/Access-Reject")
    f = next(x for x in eng.findings if x.code == "AG-110")
    check(f.detail["case"] == "not_first",
          f"D3: detail must say which case, got {f.detail.get('case')!r}")
    check(f.detail["first_attr_type"] == PS,
          "D3: detail should record what WAS first")

    # A3b. The same response with M-A first must stay silent.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REJECT, 4,
                                           [(MA, 18), (PS, 40)]),
                                dport=50000, sport=1812,
                                src="10.0.0.2", dst="10.0.0.1")]))
    check("AG-110" not in c, f"D3: a correctly hardened reject must be silent, got {c}")

    # A3c. Access-Challenge is presence-only - M-A not first must NOT fire.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_CHALLENGE, 5,
                                           [(PS, 40), (MA, 18)]),
                                dport=50000, sport=1812,
                                src="10.0.0.2", dst="10.0.0.1")]))
    check("AG-110" not in c,
          f"D3: Access-Challenge is a PRESENCE-only check, not position, got {c}")

    # A4 (D2). Four 100-byte Proxy-State attributes = 400 bytes total.
    eng = _run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 6, [(PS, 100)] * 4))])
    check("AG-201" in _codes(eng),
          "D2: a collision block split across four Proxy-State attributes "
          "must fire - the bound is a per-packet SUM")
    f = next(x for x in eng.findings if x.code == "AG-201")
    check(f.detail["proxy_state_total"] == 400, "D2: total recorded")
    check(f.detail["proxy_state_count"] == 4, "D2: attribute count recorded")
    check("STRUCTURAL ANOMALY BOUND" in f.detail["note"],
          "D2: the structural-bound wording must survive the rewrite")

    # A4b. The knob must still change behaviour.
    check("AG-201" not in _codes(_run(
        [radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 7, [(PS, 100)] * 4))],
        Config(radius_proxy_state_total_max=500))),
        "D2: raising radius_proxy_state_total_max must SILENCE AG-201")

    # A4c. At the limit silent, one over fires.
    for total, want in ((Config().radius_proxy_state_total_max, False),
                        (Config().radius_proxy_state_total_max + 1, True)):
        got = "AG-201" in _codes(_run(
            [radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 8, [(PS, total)]))]))
        check(got is want, f"D2: proxy_state_total={total} expected {want}")

    # A5 (D5). known_infra set, bare PAP request to a non-infra destination.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 9, [(UN, 8)]),
                                dst="10.9.9.9")],
                    Config(known_infra=("172.16.0.1",),
                           radius_arista_endpoints=_TEST_RADIUS_ENDPOINTS)))
    check("AG-102" not in c,
          f"D5: AG-102 is EXPOSURE and must honour known_infra, got {c}")
    check("AG-101" not in c, "D5: AG-101 scoped away too")
    # ... and an in-scope server must still surface.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 10, [(UN, 8)]),
                                dst="10.9.9.9")],
                    Config(known_infra=("10.9.9.9",),
                           radius_arista_endpoints=_TEST_RADIUS_ENDPOINTS)))
    check("AG-102" in c, f"D5: an in-scope server must still raise AG-102, got {c}")

    # A5b. AG-201 is ATTACK-class and must NEVER be scoped away.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 11,
                                           [(PS, 100)] * 4), dst="10.9.9.9")],
                    Config(known_infra=("172.16.0.1",),
                           radius_arista_endpoints=_TEST_RADIUS_ENDPOINTS)))
    check("AG-201" in c,
          "D5: known_infra must NEVER filter an ATTACK finding - that would "
          "turn a noise knob into a detection blind spot")

    # A5c. The server side of a RESPONSE is the SOURCE, not the destination.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_ACCEPT, 12, [(UN, 8)]),
                                dport=50000, sport=1812,
                                src="10.5.5.5", dst="10.0.0.1")],
                    Config(known_infra=("10.5.5.5",),
                           radius_arista_endpoints=_TEST_RADIUS_ENDPOINTS)))
    check("AG-110" in c,
          "D5: on a response the RADIUS server is l3.src; scoping on dst would "
          "put the NAS address through the infra check instead")

    # A6 (D6). 300 two-byte attributes followed by Message-Authenticator.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 13,
                                           [(26, 2)] * 300 + [(MA, 18)]))]))
    check("AG-102" not in c,
          f"D6: the attribute walk must reach an M-A past attribute 256, got {c}")
    check(RADIUS_MAX_ATTRS >= 2038, f"D6: cap is {RADIUS_MAX_ATTRS}, want >= 2038")

    # A8 (regressions). Accounting skips the M-A checks entirely.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCOUNTING_REQUEST, 14,
                                           [(UN, 8)]), dport=1813)]))
    check("AG-102" not in c and "AG-110" not in c,
          f"regression: accounting has no Message-Authenticator requirement, got {c}")
    # A single small Proxy-State from a legitimate proxy stays silent.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 15,
                                           [(UN, 8), (PS, 12), (MA, 18)]))]))
    check(c == {"AG-101"},
          f"regression: one small Proxy-State is ordinary proxying, got {c}")

    # AG-202 is retired and must never come back.
    check("AG-202" not in FINDINGS, "AG-202 must not be a live code")
    check("AG-202" in RETIRED_CODES, "AG-202 must be recorded as retired")
    check(FINDINGS["AG-110"].klass == "exposure", "D4: AG-110 is exposure-class")


def test_ipv6_extension_headers() -> None:
    """
    A7 (D7). The PRIME DIRECTIVE case: plain IPv6 worked and the identical
    packet behind a Hop-by-Hop header raised NOTHING. This affected EVERY L4
    rule in the module, not just RADIUS.
    """
    bare = _mk_radius(RADIUS_ACCESS_REQUEST, 1, [(RADIUS_ATTR_USER_NAME, 8)])
    l4 = _mk_udp(50000, 1812, bare)

    plain = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                                 _mk_ip6(IPPROTO_UDP, l4))]))
    check("AG-101" in plain and "AG-102" in plain,
          f"plain IPv6 RADIUS must fire, got {plain}")

    for kind, name in ((IPV6_EXT_HOPOPT, "Hop-by-Hop"),
                       (IPV6_EXT_ROUTING, "Routing"),
                       (IPV6_EXT_FRAGMENT, "Fragment"),
                       (IPV6_EXT_AH, "AH"),
                       (IPV6_EXT_DSTOPTS, "Dest-Opts")):
        body = _mk_exthdr(kind, IPPROTO_UDP) + l4
        got = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                                   _mk_ip6(kind, body))]))
        check("AG-101" in got and "AG-102" in got,
              f"D7: RADIUS behind a {name} header must produce the same "
              f"findings as plain IPv6; got {got}")

    # A chain of several headers.
    chain = (_mk_exthdr(IPV6_EXT_HOPOPT, IPV6_EXT_DSTOPTS)
             + _mk_exthdr(IPV6_EXT_DSTOPTS, IPV6_EXT_ROUTING)
             + _mk_exthdr(IPV6_EXT_ROUTING, IPPROTO_UDP) + l4)
    got = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                               _mk_ip6(IPV6_EXT_HOPOPT, chain))]))
    check("AG-101" in got, f"D7: a 3-header chain must resolve, got {got}")

    # A NON-FIRST fragment carries no L4 header - reporting one would hand a
    # rule payload bytes to parse as a header.
    body = _mk_exthdr(IPV6_EXT_FRAGMENT, IPPROTO_UDP, frag_offset=185) + l4
    l3 = parse_l3(_mk_ip6(IPV6_EXT_FRAGMENT, body), ETH_P_IPV6)
    check(l3 is not None and not l3.l4_reachable,
          "D7: a non-first fragment must report l4_reachable=False")
    check(parse_l4(l3) is None, "D7: parse_l4 must refuse a non-first fragment")
    check(l3.frag_offset == 185, f"D7: fragment offset recorded, got {l3.frag_offset}")

    # No-Next-Header terminates the chain with no L4.
    l3 = parse_l3(_mk_ip6(IPV6_NO_NEXT_HEADER, b""), ETH_P_IPV6)
    check(l3 is not None and not l3.l4_reachable, "D7: No-Next yields no L4")

    # The walk is BOUNDED - an unbounded walk is a DoS primitive against the
    # sensor itself.
    deep = b"".join(_mk_exthdr(IPV6_EXT_DSTOPTS, IPV6_EXT_DSTOPTS)
                    for _ in range(40)) + l4
    l3 = parse_l3(_mk_ip6(IPV6_EXT_DSTOPTS, deep), ETH_P_IPV6)
    check(l3 is not None, "D7: a deep chain must not crash the parser")
    check(len(l3.ext_headers) <= IPV6_MAX_EXT_HEADERS,
          f"D7: walk must stop at {IPV6_MAX_EXT_HEADERS}, got {len(l3.ext_headers)}")
    check(not l3.l4_reachable,
          "D7: past the bound the module must NOT claim to have found an L4 "
          "header - it would be handing a rule mid-header bytes")
    check(l3.ext_chain_truncated, "D7: exceeding the bound is recorded")

    # AH length uses 4-octet units MINUS 2, not the 8-octet rule. Getting
    # this wrong walks off the end of the header and silently mis-parses.
    ah = _mk_exthdr(IPV6_EXT_AH, IPPROTO_UDP)
    check(len(ah) == 12, f"AH header should be 12 bytes here, got {len(ah)}")
    l3 = parse_l3(_mk_ip6(IPV6_EXT_AH, ah + l4), ETH_P_IPV6)
    check(l3 is not None and l3.proto == IPPROTO_UDP,
          f"D7: AH must resolve to UDP, got proto {l3.proto if l3 else None}")
    check(l3.payload == l4,
          "D7: the AH length rule must land exactly on the L4 header")

    # Truncated / lying extension lengths must not raise or over-read.
    for bad in (b"\x11", b"\x11\xff", b"\x11\xff\x00\x00"):
        try:
            parse_l3(_mk_ip6(IPV6_EXT_HOPOPT, bad), ETH_P_IPV6)
        except Exception as exc:  # noqa: BLE001
            check(False, f"D7: malformed ext header raised {exc!r}")
            break
    else:
        check(True, "D7: malformed extension headers never raise")

    # Other L4 rules must work behind an extension header too - the blind
    # spot was never RADIUS-specific.
    ssh = _mk_tcp(22, 40002, b"SSH-2.0-OpenSSH_9.2p1 Arista\r\n")
    body = _mk_exthdr(IPV6_EXT_HOPOPT, IPPROTO_TCP) + ssh
    got = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                               _mk_ip6(IPV6_EXT_HOPOPT, body))]))
    check("AG-104" in got, f"D7: SSH behind Hop-by-Hop must fire AG-104, got {got}")

    gnmi = _mk_tcp(40000, 6030, b"\x00" * 8)
    body = _mk_exthdr(IPV6_EXT_DSTOPTS, IPPROTO_TCP) + gnmi
    got = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                               _mk_ip6(IPV6_EXT_DSTOPTS, body))]))
    check("AG-103" in got, f"D7: gNMI behind Dest-Opts must fire AG-103, got {got}")

    # BPF must admit extension-header-wrapped IPv6 at all.
    for nh in (0, 43, 44, 51, 60):
        check(f"ip6[6] = {nh}" in BPF_FILTER,
              f"D7: BPF filter omits ip6[6] = {nh}; libpcap cannot chase the "
              f"chain, so without this clause the packets never arrive")
    check(BPF_FILTER.rstrip().endswith("vlan"),
          "D7: `vlan` SHIFTS offsets for every clause after it, so the ip6 "
          "clause must come BEFORE it and vlan must stay last")
    # Only FOUR of the five extension-header types actually depend on the
    # ip6 clause. AH is IP protocol 51, which `proto 51` already admits for
    # IPsec detection, so an AH-wrapped packet arrives either way. The lab's
    # negative control asserts exactly one survivor for this reason - a
    # control expecting zero would fail for a correct filter.
    check("proto 51" in BPF_FILTER,
          "proto 51 is both the IPsec AH term and the reason an AH-wrapped "
          "packet is admitted without the ip6 clause")


def cfg_default_entropy_floor() -> float:
    return Config().radius_opaque_entropy_min


def test_blastradius_nas_side_leg() -> None:
    """
    F1/F2. The NAS-SIDE LEG of CVE-2024-3596.

    A tap sees only one of the two legs. AG-201 (Proxy-State total) is correct
    for the attacker->SERVER leg, where the colliding Access-Reject must use
    Proxy-State because a server echoes it back unchanged. On the
    attacker->NAS leg, where the forged Access-Accept arrives,
    blastradius.fail states the collision data can sit in Vendor-Specific or
    Reply-Message instead - so a Proxy-State-only rule is blind there.

    Every case is run over IPv4, plain IPv6 and IPv6 behind an extension
    header, because the prime directive applies to new rules too.
    """
    UN, MA, PS, RM, VSA, EAP = (RADIUS_ATTR_USER_NAME,
                                RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                                RADIUS_ATTR_PROXY_STATE,
                                RADIUS_ATTR_REPLY_MESSAGE,
                                RADIUS_ATTR_VENDOR_SPECIFIC,
                                RADIUS_ATTR_EAP_MESSAGE)

    # Config with the test RADIUS endpoints placed in Arista scope, so an
    # ad-hoc config here does not re-silence the fixtures the RADIUS scope
    # gate now filters. Any extra knobs the test needs are passed through.
    def _acfg(**kw: Any) -> Config:
        kw.setdefault("radius_arista_endpoints", _TEST_RADIUS_ENDPOINTS)
        return Config(**kw)

    # Deterministic pseudo-random bytes: os.urandom would make a failure
    # unreproducible, and the classifier's behaviour must be pinned exactly.
    def prand(n: int, seed: int = 7) -> bytes:
        out = bytearray()
        x = seed * 2654435761 & 0xFFFFFFFF
        while len(out) < n:
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
            out.append((x >> 16) & 0xFF)
        return bytes(out)

    # --- three transports, exercised identically -------------------------
    def v4(pkt: bytes, request: bool) -> bytes:
        sp, dp = (50000, 1812) if request else (1812, 50000)
        a, b = ("10.0.0.1", "10.0.0.2") if request else ("10.0.0.2", "10.0.0.1")
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                       _mk_ipv4(a, b, IPPROTO_UDP, _mk_udp(sp, dp, pkt)))

    def v6(pkt: bytes, request: bool) -> bytes:
        sp, dp = (50000, 1812) if request else (1812, 50000)
        a = b"\x20\x01" + b"\x00" * 14
        b_ = b"\x20\x01" + b"\x00" * 13 + b"\x02"
        src, dst = (a, b_) if request else (b_, a)
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                       _mk_ip6(IPPROTO_UDP, _mk_udp(sp, dp, pkt), src, dst))

    def v6eh(pkt: bytes, request: bool) -> bytes:
        sp, dp = (50000, 1812) if request else (1812, 50000)
        a = b"\x20\x01" + b"\x00" * 14
        b_ = b"\x20\x01" + b"\x00" * 13 + b"\x02"
        src, dst = (a, b_) if request else (b_, a)
        body = _mk_exthdr(IPV6_EXT_HOPOPT, IPPROTO_UDP) + _mk_udp(sp, dp, pkt)
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                       _mk_ip6(IPV6_EXT_HOPOPT, body, src, dst))

    transports = (("IPv4", v4), ("IPv6", v6), ("IPv6+EH", v6eh))

    for label, mk in transports:
        # F1.1 - request with NO Proxy-State, Accept WITH one.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 7,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 7,
                                           [(MA, b"\x00" * 16),
                                            (PS, prand(60))]), False)]))
        check("AG-212" in got,
              f"F1.1 [{label}]: Proxy-State in a response whose request had "
              f"none must fire, got {sorted(got)}")

        # F1.2 - legitimate proxy hop: the SAME Proxy-State echoed back.
        hop = b"proxy-hop-1-opaque-token"
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 8,
                                           [(UN, b"op"), (PS, hop)]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 8,
                                           [(MA, b"\x00" * 16),
                                            (PS, hop)]), False)]))
        check("AG-212" not in got,
              f"F1.2 [{label}]: a conforming server echoing Proxy-State back "
              f"unchanged is a legitimate proxy hop and must stay SILENT - "
              f"this is why the rule correlates instead of applying a flat "
              f"'a NAS never receives Proxy-State'. Got {sorted(got)}")

        # F1.3 - request has A, response has A plus an injected B.
        eng = _run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 9,
                                    [(PS, b"A" * 10)]), True),
                    mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 9,
                                    [(MA, b"\x00" * 16), (PS, b"A" * 10),
                                     (PS, b"B" * 10)]), False)])
        check("AG-212" in eng and True, f"F1.3 [{label}] placeholder") \
            if False else None
        got = _codes(eng)
        check("AG-212" in got,
              f"F1.3 [{label}]: a response carrying MORE Proxy-State than the "
              f"request must fire, got {sorted(got)}")
        f = next(x for x in eng.findings if x.code == "AG-212")
        check(f.detail["case"] == "set_mismatch",
              f"F1.3 [{label}]: case should be set_mismatch, got {f.detail['case']}")
        check(f.detail["injected_attr_count"] == 1,
              f"F1.3 [{label}]: one injected attribute expected")

        # F1.4 - response with no matching request: SILENT by default.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 10,
                                           [(MA, b"\x00" * 16),
                                            (PS, b"A" * 10)]), False)]))
        check("AG-212" not in got,
              f"F1.4 [{label}]: with no matching request observed the module "
              f"must not guess - an asymmetric tap produces this legitimately. "
              f"Got {sorted(got)}")

        # F2.5 - Reply-Message with invalid UTF-8.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 12,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 12,
                                           [(MA, b"\x00" * 16),
                                            (RM, b"\xff\xfe\x80\x81 bad")]),
                              False)]))
        check("AG-213" in got,
              f"F2.5 [{label}]: invalid UTF-8 in Reply-Message must fire, "
              f"got {sorted(got)}")

        # F2.6 - oversized high-entropy Vendor-Specific.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 13,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 13,
                                           [(MA, b"\x00" * 16),
                                            (VSA, _mk_vsa(prand(180, 11)))]),
                              False)]))
        check("AG-214" in got,
              f"F2.6 [{label}]: an oversized high-entropy Vendor-Specific on "
              f"an Accept must fire, got {sorted(got)}")

        # F2.7a - long PRINTABLE vendor AV-pair must stay silent.
        av = (b"Aruba-User-Role=authenticated-employee-vlan-200-floor3"
              b"-corp-secure-wireless-policy")
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 14,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 14,
                                           [(MA, b"\x00" * 16),
                                            (VSA, _mk_vsa(av))]), False)]))
        check("AG-214" not in got,
              f"F2.7a [{label}]: vendors legitimately send long printable "
              f"AV-pairs; length alone must not fire. Got {sorted(got)}")

        # F2.7b - EAP-TLS fragments stay excluded (the D1 lesson).
        #
        # The payload MUST be high-entropy pseudo-random, not a constant run.
        # A real EAP-TLS fragment is TLS ciphertext and is indistinguishable
        # from random bytes, so it is precisely the content that would trip an
        # entropy rule. An earlier version of this test used b"\x01" * 253 - a
        # zero-entropy constant that could never have tripped anything, so it
        # proved nothing at all. Bite verification caught it: removing the
        # EAP-Message exclusion went undetected.
        eap_ciphertext = prand(253, 29)
        check(_norm_entropy(eap_ciphertext) >= cfg_default_entropy_floor(),
              "the EAP fixture must genuinely be high-entropy, or this test "
              "cannot detect the exclusion being removed")
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 15,
                                           [(UN, b"op"), (EAP, eap_ciphertext),
                                            (MA, b"\x00" * 16)]), True)]))
        check("AG-214" not in got and "AG-201" not in got,
              f"F2.7b [{label}]: EAP-Message stays excluded even when its "
              f"content is high-entropy ciphertext, got {sorted(got)}")
        # And on a RESPONSE, where F2 is actually armed.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 17,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_CHALLENGE, 17,
                                           [(MA, b"\x00" * 16),
                                            (EAP, eap_ciphertext)]), False)]))
        check("AG-214" not in got,
              f"F2.7b [{label}]: a high-entropy EAP-Message on a CHALLENGE - "
              f"an entirely ordinary EAP-TLS exchange - must stay silent, "
              f"got {sorted(got)}")

        # F2.7c - ordinary readable Reply-Message.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 16,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 16,
                                           [(MA, b"\x00" * 16),
                                            (RM, b"Welcome to the network")]),
                              False)]))
        check("AG-213" not in got,
              f"F2.7c [{label}]: a normal Reply-Message must stay silent, "
              f"got {sorted(got)}")

    # --- knobs must change behaviour -------------------------------------
    accept_opaque = [v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 20, [(UN, b"op")]), True),
                     v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 20,
                                     [(MA, b"\x00" * 16),
                                      (VSA, _mk_vsa(prand(180, 11)))]), False)]
    # The classifier must measure the VENDOR PAYLOAD, not the whole attribute
    # body. The 6-byte vendor-id/type/len sub-header barely shifts entropy, so
    # a verdict comparison can never catch this - assert the recorded
    # statistics EXACTLY equal a payload-only computation.
    payload = prand(180, 11)
    eng = _run(accept_opaque)
    f = next(x for x in eng.findings if x.code == "AG-214")
    check(f.detail["normalised_entropy"] == round(_norm_entropy(payload), 3),
          f"AG-214 must measure the vendor PAYLOAD: recorded "
          f"{f.detail['normalised_entropy']}, payload-only "
          f"{round(_norm_entropy(payload), 3)}. Including the 6-byte "
          f"vendor-id/type/len sub-header changes the number without "
          f"changing the verdict, which is why this asserts the statistic "
          f"rather than the classification.")
    check(f.detail["longest_printable_run"] == _longest_printable_run(payload),
          "AG-214's printable run must be measured over the vendor payload")

    check("AG-214" in _codes(_run(accept_opaque)), "AG-214 fires at defaults")
    check("AG-214" not in _codes(_run(accept_opaque,
                                      Config(radius_opaque_min_len=250))),
          "raising radius_opaque_min_len must SILENCE AG-214")
    check("AG-214" not in _codes(_run(accept_opaque,
                                      Config(radius_opaque_entropy_min=0.99))),
          "raising radius_opaque_entropy_min must SILENCE AG-214")
    check("AG-214" not in _codes(_run(accept_opaque,
                                      Config(radius_opaque_print_run_max=1))),
          "lowering radius_opaque_print_run_max must SILENCE AG-214")

    unmatched = [v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 21,
                                 [(MA, b"\x00" * 16), (PS, b"A" * 10)]), False)]
    check("AG-212" not in _codes(_run(unmatched)), "unmatched silent by default")
    eng = _run(unmatched, _acfg(radius_report_unmatched_proxy_state=True))
    check("AG-212" in _codes(eng), "the knob must enable the low-confidence note")
    f = next(x for x in eng.findings if x.code == "AG-212")
    check(f.detail["confidence"] == "low",
          "an unmatched response must be labelled LOW CONFIDENCE")
    check(f.detail["case"] == "no_matching_request", "case recorded")

    # --- attack class, never scoped by known_infra ------------------------
    for code in ("AG-212", "AG-213", "AG-214"):
        check(FINDINGS[code].klass == "attack", f"{code} must be attack-class")
    scoped = _acfg(known_infra=("172.16.0.1",),
                   radius_report_unmatched_proxy_state=True)
    got = _codes(_run([v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 22, [(UN, b"op")]), True),
                       v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 22,
                                       [(MA, b"\x00" * 16), (PS, prand(60)),
                                        (VSA, _mk_vsa(prand(180, 11))),
                                        (RM, b"\xff\xfe bad")]), False)], scoped))
    for code in ("AG-212", "AG-213", "AG-214"):
        check(code in got,
              f"{code} is ATTACK-class and must NEVER be scoped away by "
              f"known_infra, got {sorted(got)}")
    check("AG-101" not in got, "the EXPOSURE finding IS scoped away")

    # --- requests must not trigger the F2 rules ---------------------------
    got = _codes(_run([v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 23,
                                       [(VSA, _mk_vsa(prand(180, 11))),
                                        (RM, b"\xff\xfe bad")]), True)]))
    check("AG-213" not in got and "AG-214" not in got,
          f"F2 applies to Accept/Challenge only; a REQUEST carrying an opaque "
          f"vendor attribute is ordinary. Got {sorted(got)}")

    # --- the pending table must stay bounded ------------------------------
    # Wildcard scope here: this test is about table growth under many DISTINCT
    # source IPs (10.1.x.x), which a fixed endpoint list would gate out, making
    # the bound assertion vacuous. "*" is the documented restore-suite-wide
    # switch and is exactly what exercises the correlation table hardest.
    eng = AristaEngine(_acfg(radius_pending_max=64,
                             radius_arista_endpoints=("*",)))
    for i in range(500):
        eng.handle_frame(
            _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                    _mk_ipv4(f"10.1.{i // 256}.{i % 256}", "10.0.0.2",
                             IPPROTO_UDP,
                             _mk_udp(50000, 1812,
                                     _mk_radius_v(RADIUS_ACCESS_REQUEST,
                                                  i % 256, [(UN, b"op")])))),
            ts=2000.0 + i * 0.001)
    check(len(eng.radius_pending) <= 64,
          f"the pending-request table must stay bounded, got "
          f"{len(eng.radius_pending)} - an unbounded correlation table is a "
          f"memory-exhaustion primitive against the sensor")

    # Entries older than the window must be pruned, not matched.
    eng = AristaEngine(_acfg(radius_correlate_window_s=1.0))
    eng.handle_frame(v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 30, [(UN, b"op")]), True),
                     ts=3000.0)
    eng.handle_frame(v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 30,
                                     [(MA, b"\x00" * 16), (PS, b"A" * 10)]), False),
                     ts=3100.0)
    check("AG-212" not in {x.code for x in eng.findings},
          "a request outside the correlation window must be pruned, and the "
          "unmatched response must then stay silent rather than firing")

    # --- values must never reach a finding --------------------------------
    eng = _run([v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 40, [(UN, b"op")]), True),
                v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 40,
                                [(MA, b"\x00" * 16),
                                 (PS, b"SECRETPROXYSTATE" * 4),
                                 (RM, b"\xff\xfe SECRETMESSAGE"),
                                 (VSA, _mk_vsa(prand(180, 11)))]), False)])
    for f in eng.findings:
        blob = json.dumps(f.detail)
        check("SECRETPROXYSTATE" not in blob,
              f"{f.code} leaked Proxy-State content into a finding")
        check("SECRETMESSAGE" not in blob,
              f"{f.code} leaked Reply-Message content into a finding")


def test_opacity_classifier() -> None:
    """
    The measured basis for AG-214. Entropy ALONE does not separate real
    vendor AV-pairs from random bytes - measured ranges overlap at
    0.881-0.902 normalised - so the printable-run length is the
    discriminator and the gap between the bands emits nothing.
    """
    cfg = Config()

    def prand(n: int, seed: int = 3) -> bytes:
        out = bytearray()
        x = seed * 2654435761 & 0xFFFFFFFF
        while len(out) < n:
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
            out.append((x >> 16) & 0xFF)
        return bytes(out)

    check(_norm_entropy(b"") == 0.0, "empty buffer has no entropy")
    check(_norm_entropy(b"A" * 100) == 0.0, "a constant buffer has zero entropy")
    check(_norm_entropy(prand(200)) > 0.85, "random bytes are high-entropy")
    # Normalisation is the whole point: short random buffers must still score
    # high, which a raw-bits threshold would miss.
    check(_norm_entropy(prand(32)) > 0.85,
          "32 random bytes can only reach 5 bits, so a RAW entropy threshold "
          "would never fire on them - normalisation is what makes short "
          "attributes comparable")

    check(_longest_printable_run(b"hello world") == 11, "printable run")
    check(_longest_printable_run(b"ab\x00cdef") == 4, "run resets on non-print")
    check(_longest_printable_run(b"\x00\x01\x02") == 0, "no printable run")

    # These must be at or above radius_opaque_min_len. A SHORTER AV-pair
    # correctly returns "unknown" - the length gate runs first and the module
    # deliberately does not judge short values at all. The first version of
    # this test used 58-60 byte strings and expected "cleartext", which was a
    # wrong expectation rather than a classifier bug.
    for av in (b"Cisco-AVPair=ip:inacl#1=permit tcp any any established log-input",
               b"Aruba-User-Role=authenticated-employee-vlan-200-floor3-corp-secure",
               b"Class=CACS:0a000101000000AB5F2C9E:ise01/512345678/9876543210/xyz"):
        check(len(av) >= cfg.radius_opaque_min_len,
              f"fixture must clear the length gate to test the run bands: "
              f"{len(av)} < {cfg.radius_opaque_min_len}")
        check(classify_opacity(av, cfg) == "cleartext",
              f"a real AV-pair must classify as cleartext: {av[:30]!r}")
    check(classify_opacity(b"Cisco-AVPair=shell:priv-lvl=15", cfg) == "unknown",
          "a SHORT printable AV-pair is not judged at all - the length gate "
          "runs before the content test")
    for seed in range(1, 8):
        check(classify_opacity(prand(180, seed), cfg) == "opaque",
              f"random 180-byte payload (seed {seed}) must classify as opaque")

    # Short values are never judged, whatever they contain.
    check(classify_opacity(prand(16), cfg) == "unknown",
          "below radius_opaque_min_len nothing is judged")

    # The middle band must genuinely exist and emit nothing.
    mid = b"\x00" * 40 + b"printable-ish-run-here" + b"\x01\x02" * 20
    check(classify_opacity(mid, cfg) in ("unknown", "cleartext"),
          "a mixed buffer must not be called opaque")
    check(cfg.radius_opaque_print_run_max < cfg.radius_cleartext_print_run_min,
          "the opaque and cleartext run bands must not touch - the gap IS the "
          "unknown band, and a classifier with no abstain band guesses")


def test_radius_arista_scope() -> None:
    """
    The RADIUS rules are limited to Arista hardware. The vendor-neutral copy
    lives in radiuswatch; here an exchange is only judged when one endpoint is
    a known Arista device, so the two modules do not double-report.
    """
    UN, MA, PS = (RADIUS_ATTR_USER_NAME, RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                  RADIUS_ATTR_PROXY_STATE)

    def radius_udp(pkt: bytes, src: str = "10.7.7.7", dst: str = "10.8.8.8") -> bytes:
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                       _mk_ipv4(src, dst, IPPROTO_UDP, _mk_udp(50000, 1812, pkt)))

    # A bare Access-Request between two non-Arista IPs would raise AG-102 if
    # the rule were vendor-neutral. With an EMPTY scope it must stay silent.
    bare = _mk_radius(RADIUS_ACCESS_REQUEST, 1, [(UN, 8)])
    check("AG-102" not in _codes(_run([radius_udp(bare)], Config())),
          "with no Arista endpoint configured or learned, the RADIUS rules "
          "must stay SILENT rather than fire suite-wide")

    # Same exchange, destination named as an Arista endpoint: now it fires.
    cfg = Config(radius_arista_endpoints=("10.8.8.8",))
    check("AG-102" in _codes(_run([radius_udp(bare)], cfg)),
          "a configured Arista endpoint must bring the exchange in scope")
    # Either endpoint qualifies - the NAS (source) is just as valid.
    cfg = Config(radius_arista_endpoints=("10.7.7.7",))
    check("AG-102" in _codes(_run([radius_udp(bare)], cfg)),
          "a configured Arista endpoint on the SOURCE side also qualifies")

    # An unrelated in-scope IP does NOT pull in an exchange between two others.
    cfg = Config(radius_arista_endpoints=("10.9.9.9",))
    check("AG-102" not in _codes(_run([radius_udp(bare)], cfg)),
          "an Arista endpoint that is on neither side must not bring the "
          "exchange in scope")

    # Learned-from-LLDP scope: an Arista device advertising a management
    # address in LLDP brings its own RADIUS traffic in scope with no config.
    mgmt = _mk_lldp_mgmt("10.8.8.8")
    eng = _run([_mk_eth(b"\x01" * 6, b"\x0a" * 6, ETH_P_LLDP, mgmt),
                radius_udp(bare)], Config())
    check("10.8.8.8" in eng.arista_ips,
          "an Arista LLDP management address must be learned")
    check("AG-102" in {f.code for f in eng.findings},
          "RADIUS to a passively-learned Arista management IP must be in scope")
    # A NON-Arista LLDP neighbour advertising the same address must NOT.
    cisco = _mk_lldp_mgmt("10.8.8.8",
                          sysdesc="Cisco IOS Software, C9300 Version 17.9.4")
    eng = _run([_mk_eth(b"\x01" * 6, b"\x0b" * 6, ETH_P_LLDP, cisco),
                radius_udp(bare)], Config())
    check("10.8.8.8" not in eng.arista_ips,
          "a non-Arista neighbour's management address must NOT be learned")
    check("AG-102" not in {f.code for f in eng.findings},
          "RADIUS must stay out of scope when only a non-Arista device "
          "advertised the address")

    # IPv6 management address: the TLV subtype must be honoured, so an IPv6
    # address is learned in its own string form and does not get misparsed as
    # a truncated IPv4 address. Prime directive: parity with the IPv4 case.
    mgmt6 = _mk_lldp_mgmt("2001:db8::55", v6=True)
    learned6 = _run([_mk_eth(b"\x01" * 6, b"\x0c" * 6, ETH_P_LLDP, mgmt6)],
                    Config()).arista_ips
    want6 = _ipv6(b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x55", 0)
    check(want6 in learned6,
          f"an IPv6 LLDP management address must be learned as {want6}, "
          f"got {sorted(learned6)}")
    # If the subtype check were dropped, the first 4 bytes (20 01 0d b8) would
    # be read as the IPv4 string "32.1.13.184". It must not appear.
    check(_ipv4(b"\x20\x01\x0d\xb8", 0) not in learned6,
          "an IPv6 management address must NOT be misparsed as IPv4")

    # The "*" wildcard deliberately restores suite-wide behaviour.
    cfg = Config(radius_arista_endpoints=("*",))
    check("AG-102" in _codes(_run([radius_udp(bare)], cfg)),
          "a '*' endpoint must restore the old vendor-neutral behaviour")

    # The gate applies to EVERY RADIUS code, not just AG-102. A split
    # Proxy-State that would raise AG-201 stays silent out of scope.
    big = _mk_radius(RADIUS_ACCESS_REQUEST, 2, [(PS, 100)] * 4)
    check("AG-201" not in _codes(_run([radius_udp(big)], Config())),
          "the Arista scope gate covers the ATTACK codes too, not only AG-102")
    check("AG-201" in _codes(_run([radius_udp(big)],
                                  Config(radius_arista_endpoints=("10.8.8.8",)))),
          "...and AG-201 returns once the exchange is in Arista scope")


def test_known_infra_scoping() -> None:
    """
    known_infra scopes EXPOSURE only.  Never ATTACK.

    ciscoguard's bite run found this exact test written VACUOUSLY: it used a
    finding whose detail carried no address key, so the filter let it through
    for the wrong reason and a real mutation went uncaught.  AG-203 is used
    here specifically BECAUSE it is an ATTACK finding that does carry
    addresses - so if the filter were ever widened to attacks, this fails.
    """
    vx = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
              _mk_ipv4("10.1.1.1", "10.1.1.9", IPPROTO_UDP,
                    _mk_udp(50000, 4789, b"\x08" + b"\x00" * 7)))
    gre = _mk_eth(b"\x01" * 6, b"\x03" * 6, ETH_P_IPV4,
               _mk_ipv4("10.9.9.9", "10.1.1.9", IPPROTO_GRE, b"\x00" * 8))
    cfg = Config(known_infra=("172.16.0.1",))  # deliberately excludes 10.1.1.9
    c = _codes(_run([vx, gre], cfg))
    check("AG-106" not in c,
          "known_infra should scope the AG-106 EXPOSURE finding away")
    check("AG-203" in c,
          "known_infra must NEVER filter an ATTACK finding - that would turn a "
          "noise knob into a detection blind spot")

    esp = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
               _mk_ipv4("10.2.2.1", "10.2.2.2", IPPROTO_ESP, b"\x00" * 16))
    check("AG-105" not in _codes(_run([esp], cfg)),
          "known_infra scopes AG-105 too")
    check("AG-105" in _codes(_run([esp], Config(known_infra=("10.2.2.2",)))),
          "an in-scope address must still surface")

    # POSTURE must be untouched by known_infra.
    lldp = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_LLDP, _mk_lldp("sw1", ARISTA_DESC))
    check("AG-002" in _codes(_run([lldp], cfg)),
          "known_infra must not filter POSTURE findings either")


def test_suppression() -> None:
    bare = _mk_radius(RADIUS_ACCESS_REQUEST, 2, [(RADIUS_ATTR_USER_NAME, 8)])
    fr = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
              _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(50000, 1812, bare)))
    # The RADIUS endpoints must be in Arista scope or the AG-102 fixture is
    # gated out before suppression is ever exercised.
    scfg = Config(radius_arista_endpoints=_TEST_RADIUS_ENDPOINTS)
    eng = AristaEngine(scfg)
    for i in range(5):
        eng.handle_frame(fr, ts=2000.0 + i)
    hits = [f for f in eng.findings if f.code == "AG-102"]
    check(len(hits) == 1, f"5 detections should raise 1 alert, got {len(hits)}")

    eng = AristaEngine(Config(suppress_s=1,
                             radius_arista_endpoints=_TEST_RADIUS_ENDPOINTS))
    for i in range(3):
        eng.handle_frame(fr, ts=3000.0 + i * 10)
    hits = [f for f in eng.findings if f.code == "AG-102"]
    check(len(hits) == 3, "past the window each detection alerts again")
    check(hits[1].detail.get("suppressed_since_last") == 1,
          "a re-fire carries the suppressed count")


def test_learn_mode() -> None:
    emitted: list[Finding] = []
    eng = AristaEngine(Config(learn=True), emit=emitted.append)
    eng.handle_frame(_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_LLDP,
                          _mk_lldp("sw1", ARISTA_DESC)), ts=1.0)
    check(emitted == [], "learn mode must emit nothing")
    check(len(eng.findings) > 0,
          "learn mode still DETECTS - it only withholds emission, so a "
          "baseline run can be reviewed")


def test_clean_set_silence() -> None:
    """
    Benign traffic must raise ZERO attack findings AND screen no version into
    CVE range.  The second half is the trap cdpwatch's lab found: a 'benign'
    fixture that advertised itself as a vulnerable platform.
    """
    benign = [
        _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
             _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(53, 53, b"\x00" * 8))),
        _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
             _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_TCP, _mk_tcp(443, 40000, b"\x16\x03")),
             vlans=(10,)),
        _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
             _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                   _mk_udp(50000, 1812,
                        _mk_radius(RADIUS_ACCESS_REQUEST, 1,
                                [(RADIUS_ATTR_USER_NAME, 8),
                                 (RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 18)])))),
        _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
             _mk_ipv4("10.0.0.9", "10.0.0.1", IPPROTO_TCP,
                   _mk_tcp(22, 40002, b"SSH-2.0-OpenSSH_9.8p1 Arista\r\n"))),
    ]
    eng = _run(benign)
    attacks = [f for f in eng.findings if f.klass == "attack"]
    check(attacks == [], f"benign set raised attack findings: "
                         f"{[f.code for f in attacks]}")
    posture = [f for f in eng.findings if f.code in ("AG-002", "AG-003")]
    check(posture == [], "benign set must not screen any version into CVE range")

    # A non-Arista LLDP neighbour must not be screened at all.
    other = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_LLDP,
                 _mk_lldp("sw9", "Cisco IOS Software, C9300 Software Version 17.9.4"))
    c = _codes(_run([other]))
    check("AG-002" not in c and "AG-001" not in c,
          "a non-Arista neighbour must not be screened by this module")


def test_json_output() -> None:
    eng = _run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_LLDP,
                     _mk_lldp("sw1", ARISTA_DESC))])
    for f in eng.findings:
        blob = json.loads(f.to_json())
        check(blob["module"] == "aristaguard", "json module name")
        check(blob["code"] in FINDINGS, "json code is a real finding code")
        check(blob["class"] in ("posture", "exposure", "attack"), "json class")
        check(isinstance(blob["cves"], list), "json cves is a list")
        check(blob["version"] == __version__, "json carries the module version")


def test_config() -> None:
    cfg = Config()
    d = cfg.dump()
    check("min_cvss" in d and "always_include_exploited" in d, "config dumps")
    round_trip = Config.load(json.loads(json.dumps(d)))
    check(round_trip.min_cvss == cfg.min_cvss, "config round-trips through json")
    check(isinstance(round_trip.radius_auth_ports, tuple),
          "json lists must come back as tuples")
    loaded = Config.load({"min_cvss": 7.0, "policy_blocked": ["10.0.0.1"]})
    check(loaded.min_cvss == 7.0, "config load applies values")
    check(loaded.policy_blocked == ("10.0.0.1",), "list coerced to tuple")


def test_bpf_filter_covers_rules() -> None:
    """
    The capture filter must not silently drop traffic a rule needs.

    REGRESSION: the first version of this test only checked that port numbers
    appeared as SUBSTRINGS of the filter string. That is not reachability.
    AG-205, AG-206 and AG-207 operate on arbitrary traffic and matched no
    filter term at all, so in production they could never fire - and every
    offline tier passed anyway, because they all bypass BPF. The
    sealed-namespace lab found it on a real kernel capture path.
    """
    base = Config()
    for port in (1812, 1813, 4789, 6030, 9339, 9979, 22, 49):
        check(str(port) in BPF_FILTER, f"BPF filter omits port {port}")
    for proto in (47, 50, 4, 41, 89):
        check(f"proto {proto}" in BPF_FILTER, f"BPF filter omits ip proto {proto}")
    check("0x88cc" in BPF_FILTER, "BPF filter omits LLDP")
    check("0x888e" in BPF_FILTER, "BPF filter omits EAPOL")

    # AG-205 / AG-207 need VLAN-tagged frames admitted regardless of port.
    check(BPF_FILTER.rstrip().endswith("vlan"),
          "the bare `vlan` term must be present AND LAST - in libpcap it "
          "shifts the offsets of every term that follows it")

    # AG-206 needs its operator-declared destinations admitted by host.
    f = build_bpf_filter(Config(policy_blocked=("192.168.5.5",)))
    check("host 192.168.5.5" in f,
          "policy_blocked destinations must be admitted by the filter, or "
          "AG-206 can never fire in production")
    check("host 192.168.5.5" not in BPF_FILTER,
          "the default filter must not carry host terms it was not given")

    f2 = build_bpf_filter(Config(decap_endpoints=("10.1.1.9",)))
    check("host 10.1.1.9" in f2,
          "configured decap endpoints must be admitted so AG-203 sees "
          "non-VXLAN tunnel protocols aimed at them")

    # Ordering: every host term must precede the bare vlan term.
    f3 = build_bpf_filter(Config(policy_blocked=("192.168.5.5",),
                                 decap_endpoints=("10.1.1.9",)))
    check(f3.index("host 10.1.1.9") < f3.index(" or vlan"),
          "host terms must come BEFORE the vlan term or their offsets shift")
    check(f3.rstrip().endswith("vlan"), "vlan must remain last with hosts present")

    # vlan_broad_capture is what makes AG-205/AG-207 reachable at all.
    narrow = build_bpf_filter(Config())
    broad = build_bpf_filter(Config(vlan_broad_capture=True))
    check("ip or ip6" not in narrow, "broad capture must be OFF by default")
    check("ip or ip6" in broad, "vlan_broad_capture must widen the filter")
    check(broad.rstrip().endswith("vlan"),
          "vlan must remain the last term even with broad capture on")

    # Operator input must not be able to inject filter syntax.
    evil = build_bpf_filter(Config(policy_blocked=("1.2.3.4 or not tcp",)))
    check("not tcp" not in evil,
          "an operator-supplied value must not reach the filter unvalidated")


# ---- passive invariant (AST, not grep) -----------------------------------
#
# SUITE-WIDE LESSON D: the guard is split by AST call SHAPE, not by name.
# Banning the bare name `run` fired 32 times on ciscoguard's own self-test
# helper.  Bare Name calls are transmit primitives; Attribute calls are
# subprocess.run / os.system and friends, checked against their receiver.

_BANNED_CALL_NAMES = {"send", "sendp", "sendto", "sr", "sr1", "srp", "srp1",
                      "pcap_sendpacket", "pcap_inject"}
_BANNED_CALL_ATTRS = {
    "subprocess": {"run", "call", "Popen", "check_output", "check_call"},
    "os": {"system", "popen", "execv", "execve", "spawnv"},
    "socket": {"socket", "create_connection"},
}
_BANNED_IMPORTS = {"socket", "subprocess", "requests", "urllib", "http"}


def test_passive_invariant() -> None:
    src = open(__file__, "r", encoding="utf-8").read()
    tree = ast.parse(src)
    problems: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in _BANNED_CALL_NAMES:
                problems.append(f"transmit primitive call {fn.id}() at line {node.lineno}")
            elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                banned = _BANNED_CALL_ATTRS.get(fn.value.id, set())
                if fn.attr in banned:
                    problems.append(
                        f"{fn.value.id}.{fn.attr}() at line {node.lineno}")
        elif isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in _BANNED_IMPORTS:
                    problems.append(f"import {a.name} at line {node.lineno}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _BANNED_IMPORTS:
                problems.append(f"from {node.module} import at line {node.lineno}")
        elif isinstance(node, ast.FunctionDef):
            if re.search(r"exploit|attack_|inject|forge_", node.name):
                problems.append(f"offensive-sounding def {node.name}")

    check(problems == [], f"passive invariant violations: {problems}")

    # REGRESSION: a module-level name defined twice silently shadows the
    # first definition.  The self-test's fixture builder _ipv4(src,dst,proto)
    # shadowed the parser's _ipv4(buf,offset) on the very first build run -
    # which broke parse_l3() in PRODUCTION, not just in the tests, because the
    # later definition wins at import time.  Offline tests happened to exercise
    # the fixture path, so nothing else would have caught it before capture.
    seen_defs: dict[str, int] = {}
    dupes: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            if node.name in seen_defs:
                dupes.append(f"{node.name} redefined at line {node.lineno} "
                             f"(first at {seen_defs[node.name]})")
            seen_defs[node.name] = node.lineno
    check(dupes == [], f"module-level name shadowing: {dupes}")

    # scapy may be imported ONLY inside a function body.
    module_level_scapy = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            name = getattr(node, "module", None) or node.names[0].name
            if "scapy" in (name or ""):
                module_level_scapy.append(node.lineno)
    check(module_level_scapy == [],
          f"scapy imported at module scope (lines {module_level_scapy}) - the "
          f"offline tiers must run with no third-party dependency")

    # Non-vacuity: if the banned sets were pruned, this test would pass
    # trivially.  Assert they are populated.
    check(len(_BANNED_CALL_NAMES) >= 6, "banned call-name set was pruned")
    check(len(_BANNED_CALL_ATTRS) >= 3, "banned call-attr set was pruned")
    check(len(_BANNED_IMPORTS) >= 4, "banned import set was pruned")

    # And prove the guard actually bites, on synthetic source rather than by
    # mutating the real module.
    bad = ast.parse("import subprocess\nsubprocess.run(['x'])\nsendp(f)\n")
    hits = 0
    for node in ast.walk(bad):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in _BANNED_CALL_NAMES:
                hits += 1
            elif (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                  and fn.attr in _BANNED_CALL_ATTRS.get(fn.value.id, set())):
                hits += 1
        elif isinstance(node, ast.Import):
            if node.names[0].name.split(".")[0] in _BANNED_IMPORTS:
                hits += 1
    check(hits == 3, f"guard should catch 3 injected violations, caught {hits}")

    # The self-test's own local helper named _run must NOT trip the guard -
    # this is the exact collision that fired 32 times in ciscoguard.
    check("_run" not in _BANNED_CALL_NAMES,
          "a local helper name must never be in the banned-name set")


def selftest() -> int:
    global _CHECKS, _FAILS
    _CHECKS, _FAILS = 0, []
    for fn in (test_catalog, test_severity_floor, test_versions, test_parsers,
               test_posture_rules, test_radius_rules, test_tunnel_rules,
               test_vlan_rules, test_dot1x_ospf_mgmt_rules,
               test_known_infra_scoping, test_suppression, test_learn_mode,
               test_radius_blastradius_fixes, test_ipv6_extension_headers,
               test_blastradius_nas_side_leg, test_opacity_classifier,
               test_radius_arista_scope,
               test_clean_set_silence, test_json_output, test_config,
               test_bpf_filter_covers_rules, test_passive_invariant):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            _FAILS.append(f"{fn.__name__} raised {type(exc).__name__}: {exc}")
    for f in _FAILS:
        print(f"FAIL: {f}")
    print(f"{_CHECKS - len(_FAILS)}/{_CHECKS} checks passed")
    return 1 if _FAILS else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def print_catalog() -> None:
    rows = sorted(CVE_CATALOG, key=lambda e: (-e.cvss, e.cve))
    print(f"{DISPLAY_NAME} - tracked CVEs ({len(rows)})")
    print(f"{'CVE':<18} {'CVSS':>5}  {'ADVISORY':<9} {'DETECT':<10} {'CONF':<9} EXPL")
    for e in rows:
        print(f"{e.cve:<18} {e.cvss:>5.1f}  {e.advisory:<9} {e.detect:<10} "
              f"{e.score_confidence:<9} {'YES' if e.exploited else '-'}")
    print(f"\nQuarantined - NOT built against ({len(QUARANTINED_CVES)}):")
    for cve, _ in QUARANTINED_CVES:
        print(f"  {cve}")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="aristaguard", description=f"{DISPLAY_NAME} - passive Arista EOS CVE detector")
    p.add_argument("--version", action="version",
                   version=f"aristaguard {__version__}")
    p.add_argument("--selftest", action="store_true", help="run the offline self-test")
    p.add_argument("--print-catalog", action="store_true",
                   help="print the tracked CVE table and the quarantine list")
    p.add_argument("--print-lab-codes", action="store_true",
                   help="machine-readable finding codes for the lab harness")
    p.add_argument("--print-unwired", action="store_true",
                   help="codes with no detection rule wired, one per line")
    p.add_argument("--print-lab-deferred", action="store_true",
                   help="codes not validatable over a default-filter capture")
    p.add_argument("--print-config", action="store_true",
                   help="print the effective configuration as json")
    p.add_argument("--iface", default="", help="interface to capture on")
    p.add_argument("--config", default="", help="path to a json config file")
    p.add_argument("--learn", action="store_true",
                   help="baseline mode: detect but emit nothing")
    p.add_argument("--timeout", type=int, default=0, help="capture timeout in seconds")
    p.add_argument("--min-cvss", type=float, default=None,
                   help="severity floor (default 6.5)")
    args = p.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.print_catalog:
        print_catalog()
        return 0
    if args.print_lab_codes:
        for code in sorted(FINDINGS):
            print(code)
        return 0
    if args.print_unwired:
        for code in sorted(UNWIRED_CODES):
            print(code)
        return 0
    if args.print_lab_deferred:
        for code in sorted(LAB_DEFERRED_CODES):
            print(code)
        return 0

    cfg = Config()
    if args.config:
        with open(args.config, "r", encoding="utf-8") as fh:
            cfg = Config.load(json.load(fh))
    if args.min_cvss is not None:
        cfg.min_cvss = args.min_cvss
    cfg.iface = args.iface or cfg.iface
    cfg.learn = args.learn or cfg.learn
    cfg.timeout = args.timeout or cfg.timeout

    if args.print_config:
        print(json.dumps(cfg.dump(), indent=2, sort_keys=True))
        return 0

    def emit(f: Finding) -> None:
        print(f.to_json(), flush=True)

    engine = AristaEngine(cfg, emit=emit)
    if not cfg.iface:
        p.error("--iface is required for capture (or use --selftest)")
    run_capture(cfg, engine)
    return 0


if __name__ == "__main__":
    sys.exit(main())
