#!/usr/bin/env python3
"""dellguard - Dell SmartFabric OS10 Guard.

Passive, single-CVE detector for CVE-2025-22474 (CWE-918 Server-Side Request
Forgery in Dell SmartFabric OS10).

WHAT THIS MODULE IS
-------------------
CVE-2025-22474 carries PR:H - the attacker already holds administrative
privilege on the switch.  This module is therefore a POST-EXPLOITATION EGRESS
DETECTOR, not a vulnerability detector.  A true positive means somebody is
already authenticated as admin on a core switch and is using it as a request
proxy.

The SSRF trigger arrives over the OS10 management plane (HTTPS REST or the SSH
CLI) and is invisible to a passive tap.  The RESULTING EGRESS is not.  So the
detection is by EFFECT: an outbound request originated by the device itself,
to a destination absent from that device's learned baseline.

That effect alone is unattributable - "a switch made an unexpected outbound
request" is a dead end.  To be actionable it must read "THIS Dell OS10 device
made an unexpected outbound request", and supplying that attribution layer is
the entire reason this module is vendor-scoped rather than generic.

WHAT THIS MODULE IS NOT
-----------------------
This is NOT a zero-false-positive-by-construction rule.  Class DG-2xx (except
DG-201) is baseline-dependent and is INERT until a baseline exists.  The module
says so out loud via DG-301 rather than failing silent.

Classes DG-0xx, DG-1xx and DG-201 need no baseline and work from the first
frame, preserving grab-and-go deployment for that half of the module.

PASSIVE INVARIANT
-----------------
dellguard never transmits.  It opens no IP socket, imports no `socket`, and
carries an AST guard (--audit) that proves it.  scapy is imported lazily inside
the live capture path only.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Iterable, Optional

VERSION = "0.1.0-dev"
MODULE = "dellguard"
DISPLAY_NAME = "Dell SmartFabric OS10 Guard"
BASELINE_FORMAT = 1

# ---------------------------------------------------------------------------
# CVE catalog
# ---------------------------------------------------------------------------
# Verified against Dell's own advisories, not aggregator summary rows.
# Where an aggregator and the CNA/NVD disagree, the CNA wins.

CVE_ID = "CVE-2025-22474"

CVE_CATALOG: dict[str, dict[str, Any]] = {
    CVE_ID: {
        "title": "Dell SmartFabric OS10 Server-Side Request Forgery",
        "cwe": "CWE-918",
        "cvss": 6.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N",
        "cna": "Dell (security_alert@emc.com)",
        "published": "2025-03-17",
        "score_confidence": "advisory",
        "exploited": False,          # not in CISA KEV as of 2026-09
        "epss_pct": 0.08,
        "detect": "effect",          # neither attack-signature nor posture-only
        # The vector is C:H / I:N / A:N - CONFIDENTIALITY ONLY.  Claims of
        # "configuration manipulation" (integrity) or "denial of service"
        # (availability) are NOT supported by the CNA record and must not
        # appear in any finding detail emitted by this module.
        "impact": "confidentiality only (C:H/I:N/A:N); scope changed",
        "privilege": "high (PR:H) - the attacker already holds admin on the device",
        "note": (
            "Trigger transits the encrypted management plane and is not "
            "observable.  Detection is by resulting egress, which requires a "
            "per-device baseline for every rule except DG-201."
        ),
    }
}

# (train prefix, first fixed release, Dell advisory, KB article, confidence)
# confidence: "advisory" = read from Dell's own page; "secondary" = read from a
# third-party CERT alert and/or the NVD CPE upper bound, RE-VERIFY before it
# drives a patch SLA.
AFFECTED_TRAINS: tuple[tuple[str, tuple[int, ...], str, str, str], ...] = (
    ("10.5.4", (10, 5, 4, 14), "DSA-2025-070", "000289970", "advisory"),
    ("10.5.5", (10, 5, 5, 13), "DSA-2025-069", "000293638", "advisory"),
    ("10.5.6", (10, 5, 6, 8), "DSA-2025-068", "000295014", "secondary"),
    ("10.6.0", (10, 6, 0, 2), "DSA-2025-079", "000294091", "advisory"),
)

# ---------------------------------------------------------------------------
# Scope screening
# ---------------------------------------------------------------------------
# Dell's networking line is not one OS.  OS9/FTOS and Enterprise SONiC are
# DIFFERENT PRODUCTS and are not affected by CVE-2025-22474.  SONiC's own
# shipped-host-key flaw (CVE-2025-38741) is detected by sshwatch as a
# condition, not here.  Dell also badges servers, storage, thin clients and
# (historically) firewalls, all of which carry Dell OUIs.
#
# An OS9 box emitting a CVE-2025-22474 finding is a false positive with the
# wrong CVE stapled to it, so non-OS10 Dell is ACTIVELY SCREENED OUT (DG-004),
# not merely unlisted.

IN_SCOPE_PLATFORM_RE = re.compile(
    r"(smartfabric\s*os10|dell\s*(emc\s*)?networking\s*os10|\bos10\b)", re.I
)
OUT_OF_SCOPE_PLATFORM_RE = re.compile(
    r"(\bos9\b|ftos|force\s*10|enterprise\s*sonic|\bsonic\b|idrac|poweredge|"
    r"powerstore|powervault|powerscale|\bunity\b|\bwyse\b|sonicwall|optiplex|"
    r"precision|latitude)",
    re.I,
)
DELL_VENDOR_RE = re.compile(r"(dell|smartfabric)", re.I)

# OS10 reports 4-component versions (10.5.4.14).  Accept a 3-component form
# too so a truncated banner still screens, but treat it as train-only.
_VER_RE = re.compile(r"\b(10\.\d{1,2}\.\d{1,2}(?:\.\d{1,4})?)\b")

# ---------------------------------------------------------------------------
# Finding registry
# ---------------------------------------------------------------------------
# Four classes.  DG-3xx is a deliberate FOURTH band beyond ciscoguard's
# posture/exposure/attack split: DG-3xx findings are statements about the
# SENSOR's state, not the network's.  Folding them into EXPOSURE is how an
# operator reads "my switch is exposed" when the message is "your baseline is
# four minutes old".

SEVERITIES = ("info", "notice", "warn", "critical")
CONFIDENCES = ("low", "medium", "high")
CLASSES = ("POSTURE", "EXPOSURE", "ATTACK", "OPERATIONAL")

FINDINGS: dict[str, dict[str, Any]] = {
    # -- POSTURE ------------------------------------------------------------
    "DG-001": {
        "name": "OS10_VERSION_IN_AFFECTED_TRAIN",
        "severity": "warn",
        "class": "POSTURE",
        "confidence": "medium",
        "cves": [CVE_ID],
        "desc": "Observed OS10 version sits below the fixed release for its train.",
    },
    "DG-002": {
        "name": "OS10_VERSION_UNSCREENED",
        "severity": "notice",
        "class": "POSTURE",
        "confidence": "low",
        "cves": [CVE_ID],
        "desc": "Device attributed as OS10 but no version string was observed.",
    },
    "DG-003": {
        "name": "OS10_TRAIN_ABSENT_FROM_ADVISORY",
        "severity": "info",
        "class": "POSTURE",
        "confidence": "low",
        "cves": [CVE_ID],
        "desc": "OS10 train is not in the tracked advisory set - inferred from silence, NOT confirmed patched.",
    },
    "DG-004": {
        "name": "NON_OS10_DELL_SCREENED",
        "severity": "info",
        "class": "POSTURE",
        "confidence": "high",
        "cves": [],
        "desc": "Dell device identified as a non-OS10 platform and excluded from this module's scope.",
    },
    # -- EXPOSURE -----------------------------------------------------------
    "DG-101": {
        "name": "OS10_MGMT_PLANE_ON_MONITORED_SEGMENT",
        "severity": "notice",
        "class": "EXPOSURE",
        "confidence": "medium",
        "cves": [CVE_ID],
        "desc": "OS10 management address is reachable on the monitored segment; PR:H vector is network-reachable.",
    },
    "DG-102": {
        "name": "OS10_MGMT_CLEARTEXT",
        "severity": "warn",
        "class": "EXPOSURE",
        "confidence": "high",
        "cves": [],
        "desc": "Cleartext management (HTTP/Telnet) observed to an attributed OS10 management address.",
    },
    "DG-103": {
        "name": "OS10_NO_MGMT_ADDRESS_TLV",
        "severity": "info",
        "class": "EXPOSURE",
        "confidence": "high",
        "cves": [],
        "desc": "LLDP seen without a Management Address TLV; MAC-to-IP attribution join unavailable for this device.",
    },
    # -- ATTACK -------------------------------------------------------------
    "DG-201": {
        "name": "OS10_EGRESS_METADATA_ENDPOINT",
        "severity": "critical",
        "class": "ATTACK",
        "confidence": "medium",
        "cves": [CVE_ID],
        "desc": "Attributed OS10 device originated traffic to a cloud instance-metadata endpoint. Needs no baseline.",
    },
    "DG-202": {
        "name": "OS10_EGRESS_NEW_ENDPOINT",
        "severity": "warn",
        "class": "ATTACK",
        "confidence": "medium",
        "cves": [CVE_ID],
        "desc": "Device originated traffic to a unicast endpoint absent from its baseline.",
    },
    "DG-203": {
        "name": "OS10_EGRESS_NEW_PROTOCOL",
        "severity": "warn",
        "class": "ATTACK",
        "confidence": "medium",
        "cves": [CVE_ID],
        "desc": "Device originated traffic on a transport/port outside its baseline protocol set.",
    },
    "DG-204": {
        "name": "OS10_EGRESS_NEW_DNS_NAME",
        "severity": "warn",
        "class": "ATTACK",
        "confidence": "medium",
        "cves": [CVE_ID],
        "desc": "Device resolved a hostname absent from its baseline. Cleartext even when the subsequent fetch is TLS.",
    },
    "DG-205": {
        "name": "OS10_EGRESS_FANOUT",
        "severity": "critical",
        "class": "ATTACK",
        "confidence": "medium",
        "cves": [CVE_ID],
        "desc": "Device reached many distinct new destinations inside one window - SSRF-driven internal sweep shape.",
    },
    "DG-206": {
        "name": "OS10_EGRESS_SCOPE_CROSSED",
        "severity": "warn",
        "class": "ATTACK",
        "confidence": "medium",
        "cves": [CVE_ID],
        "desc": "Device egressed into an address scope it never reached during baseline.",
    },
    "DG-207": {
        "name": "EGRESS_ANOMALY_UNATTRIBUTED",
        "severity": "notice",
        "class": "ATTACK",
        "confidence": "low",
        "cves": [],
        "desc": "Egress anomaly from a source that could not be attributed to OS10. Emitted, not dropped - this is a sensor blind spot, not an absence of events.",
    },
    # -- OPERATIONAL --------------------------------------------------------
    "DG-301": {
        "name": "BASELINE_ABSENT",
        "severity": "notice",
        "class": "OPERATIONAL",
        "confidence": "high",
        "cves": [],
        "desc": "No baseline loaded. Baseline-gated rules DG-202..DG-206 are inert.",
    },
    "DG-302": {
        "name": "BASELINE_THIN",
        "severity": "notice",
        "class": "OPERATIONAL",
        "confidence": "high",
        "cves": [],
        "desc": "Baseline did not meet the sufficiency gate. Baseline-gated findings are emitted at reduced severity.",
    },
    "DG-303": {
        "name": "BASELINE_CONFIG_MISMATCH",
        "severity": "warn",
        "class": "OPERATIONAL",
        "confidence": "high",
        "cves": [],
        "desc": "Baseline was built under a different attribution configuration and was refused.",
    },
    "DG-304": {
        "name": "NON_EMPTY_BPF_FILTER",
        "severity": "notice",
        "class": "OPERATIONAL",
        "confidence": "high",
        "cves": [],
        "desc": "A non-empty BPF filter was supplied. Egress rules key on ARBITRARY destinations and are structurally unreachable behind a port-based filter.",
    },
}

BASELINE_GATED_CODES = ("DG-202", "DG-203", "DG-204", "DG-205", "DG-206")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class KnownDevice:
    """Operator-declared OS10 device.

    This is DECLARED GROUND TRUTH, not inference.  It exists because LLDP is
    link-local and never crosses the first bridge, so on a routed span there is
    no observed attribution source at all.  Findings derived from it carry
    attribution.source == "operator" and can never be confused with "lldp".
    """

    mac: str = ""
    addrs: list[str] = field(default_factory=list)
    label: str = ""


@dataclass
class Config:
    iface: str = ""
    # DELIBERATELY EMPTY.  DG-202/203/205/206 key on arbitrary destination
    # addresses and ports; any port-based filter makes them unreachable in
    # production while every offline tier still passes (suite LESSON H).
    bpf: str = ""
    out: str = "-"

    # "l2"   - attribute by source MAC only (cheapest; correct on a span of the
    #          device's own segment).
    # "l2l3" - additionally attribute by source IP against known management
    #          addresses, which survives a routed hop at the cost of parsing L3
    #          on every frame.
    attribution_mode: str = "l2"

    known_os10: list[KnownDevice] = field(default_factory=list)
    oui_file: str = ""

    baseline_path: str = "/var/lib/ragnar/dellguard.baseline.json"

    # Sufficiency gate.  STARTING POINTS, not measured values - these must be
    # re-derived against a real segment before they are trusted.
    learn_min_seconds: int = 86400
    learn_min_frames_per_device: int = 500
    learn_min_endpoints_per_device: int = 3

    fanout_threshold: int = 8
    fanout_window_s: int = 60

    metadata_endpoints: list[str] = field(
        default_factory=lambda: ["169.254.169.254", "fd00:ec2::254"]
    )
    cleartext_mgmt_ports: list[int] = field(default_factory=lambda: [23, 80])

    suppress_window_s: int = 300
    suppress_max: int = 3

    rate_window_max_events: int = 65536
    max_ext_headers: int = 8
    max_vlan_tags: int = 4
    max_dns_name_len: int = 255

    def dump(self) -> dict[str, Any]:
        d = asdict(self)
        d["known_os10"] = [asdict(k) if not isinstance(k, dict) else k for k in self.known_os10]
        return d

    @classmethod
    def load(cls, d: dict[str, Any]) -> "Config":
        d = dict(d)
        known = d.pop("known_os10", [])
        valid = {f for f in cls.__dataclass_fields__ if f != "known_os10"}
        unknown = set(d) - valid
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        cfg = cls(**d)
        cfg.known_os10 = [
            KnownDevice(
                mac=norm_mac(k.get("mac", "")),
                addrs=[canon_addr(a) for a in k.get("addrs", [])],
                label=k.get("label", ""),
            )
            for k in known
        ]
        if cfg.attribution_mode not in ("l2", "l2l3"):
            raise ValueError("attribution_mode must be 'l2' or 'l2l3'")
        return cfg

    def attribution_fingerprint(self) -> str:
        """Hash of every input that changes WHICH DEVICES get attributed.

        A baseline built under a different device set describes a different
        population; applying it silently would produce anomalies that are
        artefacts of the config change.
        """
        payload = json.dumps(
            {
                "attribution_mode": self.attribution_mode,
                "known_os10": sorted(
                    [
                        {"mac": k.mac, "addrs": sorted(k.addrs)}
                        for k in self.known_os10
                    ],
                    key=lambda x: (x["mac"], tuple(x["addrs"])),
                ),
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------


def norm_mac(m: str) -> str:
    if not m:
        return ""
    h = re.sub(r"[^0-9a-fA-F]", "", m)
    if len(h) != 12:
        raise ValueError(f"bad MAC: {m!r}")
    h = h.lower()
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))


def fmt_mac(b: bytes) -> str:
    return b.hex(":")


def _ip4_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _ip6_str(b: bytes) -> str:
    """RFC 5952 canonical IPv6 text, hand-rolled for Zero 2W cost.

    Cross-checked against stdlib ipaddress in the self-test.
    """
    groups = [int.from_bytes(b[i : i + 2], "big") for i in range(0, 16, 2)]
    best_start, best_len = -1, 0
    cur_start, cur_len = -1, 0
    for i, g in enumerate(groups):
        if g == 0:
            if cur_start < 0:
                cur_start, cur_len = i, 1
            else:
                cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_start, cur_len = -1, 0
    if best_len < 2:
        return ":".join(f"{g:x}" for g in groups)
    head = ":".join(f"{g:x}" for g in groups[:best_start])
    tail = ":".join(f"{g:x}" for g in groups[best_start + best_len :])
    return f"{head}::{tail}"


def canon_addr(s: str) -> str:
    """Normalise an operator-written literal so set membership works.

    A hand-written 'FE80::0001' must match inet_ntop output or every rule keyed
    on it silently fails.
    """
    s = s.strip()
    if not s:
        return ""
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s.lower()


# Address scope classification, computed on raw bytes (cheap prefix tests).
# Cross-checked against stdlib ipaddress in the self-test.
def addr_scope(raw: bytes) -> str:
    if len(raw) == 4:
        a, b = raw[0], raw[1]
        if a == 127:
            return "loopback"
        if a == 169 and b == 254:
            return "link-local"
        if a == 10:
            return "private"
        if a == 172 and 16 <= b <= 31:
            return "private"
        if a == 192 and b == 168:
            return "private"
        if a == 100 and 64 <= b <= 127:
            return "cgnat"
        if 224 <= a <= 239:
            return "multicast"
        if a >= 240:
            return "reserved"
        if a == 0:
            return "reserved"
        return "global"
    if len(raw) == 16:
        if raw == b"\x00" * 15 + b"\x01":
            return "loopback"
        if raw == b"\x00" * 16:
            return "reserved"
        if raw[0] == 0xFF:
            return "multicast"
        if raw[0] == 0xFE and (raw[1] & 0xC0) == 0x80:
            return "link-local"
        if (raw[0] & 0xFE) == 0xFC:
            return "private"
        return "global"
    return "unknown"


def is_unicast_dst(raw: bytes) -> bool:
    return addr_scope(raw) not in ("multicast", "reserved", "unknown")


# ---------------------------------------------------------------------------
# Parsers - hand-rolled, no dissector dependency
# ---------------------------------------------------------------------------

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_LLDP = 0x88CC
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
EXT_HDRS = (0, 43, 44, 51, 60)


@dataclass
class L2:
    dst: bytes
    src: bytes
    ethertype: int
    payload_off: int
    vlans: tuple[int, ...]


def parse_l2(buf: bytes, max_tags: int = 4) -> Optional[L2]:
    if len(buf) < 14:
        return None
    dst, src = buf[0:6], buf[6:12]
    off = 12
    et = int.from_bytes(buf[off : off + 2], "big")
    vlans: list[int] = []
    while et in VLAN_TPIDS and len(vlans) < max_tags:
        if len(buf) < off + 8:
            return None
        vlans.append(int.from_bytes(buf[off + 2 : off + 4], "big") & 0x0FFF)
        off += 4
        et = int.from_bytes(buf[off : off + 2], "big")
    off += 2
    return L2(dst=dst, src=src, ethertype=et, payload_off=off, vlans=tuple(vlans))


@dataclass
class L3:
    version: int
    src: bytes
    dst: bytes
    proto: int
    payload_off: int
    # False when payload_off does NOT point at a usable L4 header: a non-first
    # fragment (the L4 header is in fragment zero), or an extension-header
    # chain that ran past its cap. Reading ports in either case fabricates a
    # port out of payload bytes, so the engine must consult this before it
    # forms an endpoint key.
    l4_usable: bool = True


def parse_ipv4(buf: bytes, off: int) -> Optional[L3]:
    if len(buf) < off + 20:
        return None
    ihl = (buf[off] & 0x0F) * 4
    if ihl < 20 or len(buf) < off + ihl:
        return None
    frag_off = int.from_bytes(buf[off + 6 : off + 8], "big") & 0x1FFF
    return L3(
        version=4,
        src=buf[off + 12 : off + 16],
        dst=buf[off + 16 : off + 20],
        proto=buf[off + 9],
        payload_off=off + ihl,
        l4_usable=frag_off == 0,
    )


def parse_ipv6(buf: bytes, off: int, max_ext: int = 8) -> Optional[L3]:
    if len(buf) < off + 40:
        return None
    nh = buf[off + 6]
    src = buf[off + 8 : off + 24]
    dst = buf[off + 24 : off + 40]
    cur = off + 40
    hops = 0
    l4_usable = True
    while nh in EXT_HDRS and hops < max_ext:
        if len(buf) < cur + 2:
            return None
        if nh == 44:  # fragment header is a fixed 8 octets
            hdr_len = 8
            if len(buf) < cur + 4:
                return None
            # Only a NON-FIRST fragment lacks the L4 header. Treating every
            # fragment as unusable would blind the sensor to fragment zero,
            # which is the one that carries the ports.
            if (int.from_bytes(buf[cur + 2 : cur + 4], "big") >> 3) != 0:
                l4_usable = False
        elif nh == 51:  # AH length is in 4-octet units, minus 2
            hdr_len = (buf[cur + 1] + 2) * 4
        else:
            hdr_len = (buf[cur + 1] + 1) * 8
        nxt = buf[cur]
        cur += hdr_len
        nh = nxt
        hops += 1
        if len(buf) < cur:
            return None
    if nh in EXT_HDRS:
        # The walk hit max_ext with the chain unresolved. proto is an extension
        # header, not a transport, and payload_off points into the chain.
        l4_usable = False
    return L3(version=6, src=src, dst=dst, proto=nh, payload_off=cur, l4_usable=l4_usable)


def parse_l4_ports(buf: bytes, l3: L3) -> Optional[tuple[int, int]]:
    if not l3.l4_usable or l3.proto not in (6, 17):
        return None
    off = l3.payload_off
    if len(buf) < off + 4:
        return None
    return (
        int.from_bytes(buf[off : off + 2], "big"),
        int.from_bytes(buf[off + 2 : off + 4], "big"),
    )


# -- LLDP -------------------------------------------------------------------


@dataclass
class Lldp:
    chassis_mac: str = ""
    sys_name: str = ""
    sys_desc: str = ""
    mgmt_addrs: list[str] = field(default_factory=list)
    saw_mgmt_tlv: bool = False


def parse_lldp(buf: bytes, off: int) -> Optional[Lldp]:
    out = Lldp()
    seen_any = False
    while off + 2 <= len(buf):
        hdr = int.from_bytes(buf[off : off + 2], "big")
        ttype = hdr >> 9
        tlen = hdr & 0x01FF
        off += 2
        if ttype == 0:
            break
        if off + tlen > len(buf):
            return out if seen_any else None
        val = buf[off : off + tlen]
        off += tlen
        seen_any = True
        if ttype == 1 and tlen >= 2:
            if val[0] == 4 and tlen == 7:  # subtype 4 = MAC address
                out.chassis_mac = fmt_mac(val[1:7])
        elif ttype == 5:
            out.sys_name = val.decode("utf-8", "replace")
        elif ttype == 6:
            out.sys_desc = val.decode("utf-8", "replace")
        elif ttype == 8 and tlen >= 3:
            out.saw_mgmt_tlv = True
            alen = val[0]
            if alen >= 1 and 1 + alen <= tlen:
                subtype = val[1]
                addr = val[2 : 1 + alen]
                if subtype == 1 and len(addr) == 4:
                    out.mgmt_addrs.append(_ip4_str(addr))
                elif subtype == 2 and len(addr) == 16:
                    out.mgmt_addrs.append(_ip6_str(addr))
    return out if seen_any else None


# -- DNS --------------------------------------------------------------------


def parse_dns_qname(buf: bytes, off: int, max_len: int = 255) -> Optional[str]:
    """Extract the first question name from a DNS message.

    A question name is not compressed in practice, but the loop is bounded
    against a pointer anyway rather than trusting that.
    """
    if len(buf) < off + 12:
        return None
    flags = int.from_bytes(buf[off + 2 : off + 4], "big")
    if flags & 0x8000:  # response, not a query
        return None
    if int.from_bytes(buf[off + 4 : off + 6], "big") < 1:
        return None
    p = off + 12
    labels: list[str] = []
    total = 0
    while p < len(buf):
        ln = buf[p]
        if ln == 0:
            break
        if ln & 0xC0:  # compression pointer in a question - refuse
            return None
        p += 1
        if p + ln > len(buf):
            return None
        total += ln + 1
        if total > max_len:
            return None
        labels.append(buf[p : p + ln].decode("ascii", "replace"))
        p += ln
    if not labels:
        return None
    return ".".join(labels).lower().rstrip(".")


# -- version ----------------------------------------------------------------


def parse_os10_version(text: str) -> Optional[tuple[int, ...]]:
    m = _VER_RE.search(text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def version_train(v: tuple[int, ...]) -> str:
    return ".".join(str(x) for x in v[:3])


def screen_version(v: tuple[int, ...]) -> dict[str, Any]:
    """Screen a parsed OS10 version against the tracked advisory set.

    Never resolves to a clean verdict.  A train absent from the advisory set is
    reported as inferred from silence, NOT confirmed patched - because Dell's
    advisory tables explicitly state they may not be a comprehensive list.
    """
    train = version_train(v)
    for tprefix, fixed, advisory, kb, conf in AFFECTED_TRAINS:
        if train == tprefix:
            if len(v) < 4:
                return {
                    "code": "DG-002",
                    "train": train,
                    "reason": "train is affected but the observed version has no maintenance component to compare",
                    "fixed": ".".join(str(x) for x in fixed),
                    "advisory": advisory,
                    "kb": kb,
                    "score_confidence": conf,
                }
            if v < fixed:
                return {
                    "code": "DG-001",
                    "train": train,
                    "observed": ".".join(str(x) for x in v),
                    "fixed": ".".join(str(x) for x in fixed),
                    "advisory": advisory,
                    "kb": kb,
                    "score_confidence": conf,
                }
            return {
                "code": None,
                "train": train,
                "observed": ".".join(str(x) for x in v),
                "fixed": ".".join(str(x) for x in fixed),
                "advisory": advisory,
                "kb": kb,
                "score_confidence": conf,
            }
    return {
        "code": "DG-003",
        "train": train,
        "observed": ".".join(str(x) for x in v),
        "reason": "train absent from the tracked advisory set - inferred from silence, NOT confirmed patched",
    }


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


@dataclass
class Device:
    key: str
    source: str  # "lldp" | "operator"
    mac: str = ""
    mgmt_addrs: set[str] = field(default_factory=set)
    sys_name: str = ""
    sys_desc: str = ""
    version: Optional[tuple[int, ...]] = None
    oui_vendor: str = ""
    saw_mgmt_tlv: bool = False

    def ident(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "source": self.source,
            "mac": self.mac,
            "mgmt_addrs": sorted(self.mgmt_addrs),
            "sys_name": self.sys_name,
            "version": ".".join(str(x) for x in self.version) if self.version else "",
            "oui_vendor": self.oui_vendor,
        }


class DeviceTable:
    def __init__(self, cfg: Config, oui: Optional[dict[str, str]] = None) -> None:
        self.cfg = cfg
        self.oui = oui or {}
        self.by_mac: dict[str, Device] = {}
        self.by_addr: dict[str, Device] = {}
        self.screened: set[str] = set()
        for k in cfg.known_os10:
            key = k.label or k.mac or (k.addrs[0] if k.addrs else "")
            if not key:
                continue
            dev = Device(key=key, source="operator", mac=k.mac)
            dev.mgmt_addrs.update(k.addrs)
            self._install(dev)

    def _install(self, dev: Device) -> None:
        if dev.mac:
            self.by_mac[dev.mac] = dev
        for a in dev.mgmt_addrs:
            self.by_addr[a] = dev

    def lookup_mac(self, mac: str) -> Optional[Device]:
        return self.by_mac.get(mac)

    def lookup_addr(self, addr: str) -> Optional[Device]:
        return self.by_addr.get(addr)

    def oui_vendor(self, mac: str) -> str:
        return self.oui.get(mac[:8], "")

    def observe_lldp(self, src_mac: str, l: Lldp) -> tuple[Optional[Device], list[str]]:
        """Fold an LLDP advertisement into the table.

        Returns (device, notes).  A device is created only when the
        advertisement positively identifies OS10; a non-OS10 Dell platform is
        recorded as screened so DG-004 fires once and the box stays out of
        scope thereafter.
        """
        notes: list[str] = []
        text = f"{l.sys_desc} {l.sys_name}"
        mac = l.chassis_mac or src_mac

        if OUT_OF_SCOPE_PLATFORM_RE.search(text):
            self.screened.add(mac)
            return None, ["out_of_scope"]
        if not IN_SCOPE_PLATFORM_RE.search(text):
            return None, ["not_os10"]

        dev = self.by_mac.get(mac)
        if dev is None:
            dev = Device(key=l.sys_name or mac, source="lldp", mac=mac)
        elif dev.source == "operator":
            # Operator declaration wins on identity, observation enriches it.
            notes.append("operator_declared_confirmed_by_lldp")
        dev.sys_name = l.sys_name or dev.sys_name
        dev.sys_desc = l.sys_desc or dev.sys_desc
        dev.saw_mgmt_tlv = dev.saw_mgmt_tlv or l.saw_mgmt_tlv
        dev.oui_vendor = self.oui_vendor(mac)
        v = parse_os10_version(text)
        if v:
            dev.version = v
        for a in l.mgmt_addrs:
            dev.mgmt_addrs.add(canon_addr(a))
        self._install(dev)
        return dev, notes


def load_oui_file(path: str) -> dict[str, str]:
    """Load an OPERATOR-SUPPLIED OUI map.

    dellguard ships NO hardcoded OUI table, on purpose.  A Dell OUI cannot
    discriminate an OS10 switch from a PowerEdge NIC or an iDRAC, so it can
    never be sole attribution; an incomplete shipped list would produce silent
    misses; and a table written from memory is fabricated reference data.  The
    map is therefore optional and used only to ENRICH a device already
    attributed by LLDP or operator declaration.

    Format: one "OUI,vendor" per line, '#' comments, OUI as 6 hex digits or
    colon-separated.
    """
    out: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(",", 1)
            h = re.sub(r"[^0-9a-fA-F]", "", parts[0])
            if len(h) != 6:
                continue
            vendor = parts[1].strip() if len(parts) > 1 else ""
            h = h.lower()
            out[":".join(h[i : i + 2] for i in range(0, 6, 2))] = vendor
    return out


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


@dataclass
class DeviceBaseline:
    endpoints: set[str] = field(default_factory=set)   # "addr|proto|port"
    ports: set[str] = field(default_factory=set)       # "proto/port"
    dns_names: set[str] = field(default_factory=set)
    scopes: set[str] = field(default_factory=set)
    frames: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "endpoints": sorted(self.endpoints),
            "ports": sorted(self.ports),
            "dns_names": sorted(self.dns_names),
            "scopes": sorted(self.scopes),
            "frames": self.frames,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "DeviceBaseline":
        return cls(
            endpoints=set(d.get("endpoints", [])),
            ports=set(d.get("ports", [])),
            dns_names=set(d.get("dns_names", [])),
            scopes=set(d.get("scopes", [])),
            frames=int(d.get("frames", 0)),
        )


@dataclass
class Baseline:
    format: int = BASELINE_FORMAT
    module_version: str = VERSION
    attribution_fingerprint: str = ""
    started: float = 0.0
    ended: float = 0.0
    devices: dict[str, DeviceBaseline] = field(default_factory=dict)

    def duration(self) -> float:
        return max(0.0, self.ended - self.started)

    def to_json(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "module_version": self.module_version,
            "attribution_fingerprint": self.attribution_fingerprint,
            "started": self.started,
            "ended": self.ended,
            "devices": {k: v.to_json() for k, v in self.devices.items()},
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Baseline":
        return cls(
            format=int(d.get("format", 0)),
            module_version=d.get("module_version", ""),
            attribution_fingerprint=d.get("attribution_fingerprint", ""),
            started=float(d.get("started", 0.0)),
            ended=float(d.get("ended", 0.0)),
            devices={
                k: DeviceBaseline.from_json(v) for k, v in (d.get("devices") or {}).items()
            },
        )

    def content_hash(self) -> str:
        return hashlib.sha256(
            json.dumps(self.to_json(), sort_keys=True).encode()
        ).hexdigest()

    def sufficiency(self, cfg: Config) -> dict[str, Any]:
        """Hard gate, not a warning.

        A baseline taken for ten minutes at 03:00 is not a baseline.  Below the
        gate, baseline-gated findings are emitted at reduced severity with
        DG-302 attached rather than at full confidence.
        """
        reasons: list[str] = []
        if self.duration() < cfg.learn_min_seconds:
            reasons.append(
                f"duration {int(self.duration())}s < {cfg.learn_min_seconds}s"
            )
        if not self.devices:
            reasons.append("no devices observed during learn")
        for k, db in self.devices.items():
            if db.frames < cfg.learn_min_frames_per_device:
                reasons.append(f"{k}: {db.frames} frames < {cfg.learn_min_frames_per_device}")
            if len(db.endpoints) < cfg.learn_min_endpoints_per_device:
                reasons.append(
                    f"{k}: {len(db.endpoints)} endpoints < {cfg.learn_min_endpoints_per_device}"
                )
        return {"sufficient": not reasons, "reasons": reasons}


# ---------------------------------------------------------------------------
# Rate window and suppressor
# ---------------------------------------------------------------------------


class RateWindow:
    """Bounded sliding window of (ts, value).

    The cap exists because an unbounded window is a memory vector; every
    threshold this module uses is orders of magnitude below the cap.
    """

    def __init__(self, window_s: int, cap: int) -> None:
        self.window_s = window_s
        self.cap = cap
        self.events: list[tuple[float, str]] = []

    def add(self, ts: float, value: str) -> int:
        self.events.append((ts, value))
        if len(self.events) > self.cap:
            del self.events[: len(self.events) - self.cap]
        cutoff = ts - self.window_s
        i = 0
        for i, (t, _) in enumerate(self.events):
            if t >= cutoff:
                break
        if i:
            del self.events[:i]
        return len({v for _, v in self.events})


class Suppressor:
    """Throttles ALERTS, never detection. Fails open. Never auto-learns."""

    def __init__(self, window_s: int, max_per_window: int) -> None:
        self.window_s = window_s
        self.max = max_per_window
        self.state: dict[str, list[float]] = {}
        self.suppressed: dict[str, int] = {}

    def allow(self, key: str, ts: float) -> bool:
        hist = [t for t in self.state.get(key, []) if t > ts - self.window_s]
        hist.append(ts)
        self.state[key] = hist
        if len(hist) > self.max:
            self.suppressed[key] = self.suppressed.get(key, 0) + 1
            return False
        return True


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class DellGuard:
    def __init__(
        self,
        cfg: Config,
        learn: bool = False,
        baseline: Optional[Baseline] = None,
        emit: Optional[Callable[[dict[str, Any]], None]] = None,
        oui: Optional[dict[str, str]] = None,
    ) -> None:
        self.cfg = cfg
        self.learn = learn
        self.emit_fn = emit or (lambda f: None)
        self.devices = DeviceTable(cfg, oui=oui)
        self.suppressor = Suppressor(cfg.suppress_window_s, cfg.suppress_max)
        self.findings: list[dict[str, Any]] = []
        self.counters: dict[str, int] = {}
        self.parse_errors = 0
        self._once: set[str] = set()
        self._fanout: dict[str, RateWindow] = {}
        self.metadata_set = {canon_addr(a) for a in cfg.metadata_endpoints}

        self.baseline = baseline
        self.baseline_state = "absent"
        self.gate: dict[str, Any] = {"sufficient": False, "reasons": ["no baseline"]}
        if learn:
            self.baseline = Baseline(
                attribution_fingerprint=cfg.attribution_fingerprint()
            )
            self.baseline_state = "learning"
        elif baseline is not None:
            if baseline.attribution_fingerprint != cfg.attribution_fingerprint():
                self.baseline_state = "refused"
            else:
                self.gate = baseline.sufficiency(cfg)
                self.baseline_state = "ready" if self.gate["sufficient"] else "thin"

    # -- emission -----------------------------------------------------------

    def _bump(self, code: str) -> None:
        self.counters[code] = self.counters.get(code, 0) + 1

    def _finding(
        self,
        ts: float,
        code: str,
        detail: dict[str, Any],
        device: Optional[Device] = None,
        severity: Optional[str] = None,
        confidence: Optional[str] = None,
        suppress_key: Optional[str] = None,
        pivot: Optional[list[str]] = None,
    ) -> None:
        meta = FINDINGS[code]
        self._bump(code)
        if self.learn:
            # Learn mode is silent STRUCTURALLY, not per rule. Counters stay
            # intact so a learn run can still be measured. Guarding at each
            # call site instead would leave the next rule added free to
            # reintroduce the leak - which is exactly how DG-101 escaped.
            return
        sev = severity or meta["severity"]
        conf = confidence or meta["confidence"]
        if code in BASELINE_GATED_CODES and self.baseline_state == "thin":
            sev = _downgrade(sev)
            conf = "low"
            detail = dict(detail, baseline_thin=True)
        if suppress_key and not self.suppressor.allow(suppress_key, ts):
            return
        f = {
            "ts": ts,
            "module": MODULE,
            "module_version": VERSION,
            "code": code,
            "name": meta["name"],
            "severity": sev,
            "class": meta["class"],
            "confidence": conf,
            "cves": list(meta["cves"]),
            "attribution": device.ident() if device else {"source": "none"},
            "detail": detail,
        }
        if pivot:
            f["pivot"] = pivot
        self.findings.append(f)
        self.emit_fn(f)

    def _once_only(self, key: str) -> bool:
        if key in self._once:
            return False
        self._once.add(key)
        return True

    # -- lifecycle ----------------------------------------------------------

    def start(self, ts: Optional[float] = None) -> None:
        ts = time.time() if ts is None else ts
        if self.learn:
            self.baseline.started = ts
            self.baseline.ended = ts
            return
        if self.cfg.bpf.strip():
            self._finding(
                ts,
                "DG-304",
                {
                    "bpf": self.cfg.bpf,
                    "reason": "egress rules key on arbitrary destinations; a port-based filter makes them unreachable in production while every offline tier still passes",
                },
            )
        if self.baseline_state == "absent":
            self._finding(
                ts,
                "DG-301",
                {"inert_codes": list(BASELINE_GATED_CODES), "baseline_path": self.cfg.baseline_path},
            )
        elif self.baseline_state == "refused":
            self._finding(
                ts,
                "DG-303",
                {
                    "expected": self.cfg.attribution_fingerprint(),
                    "found": self.baseline.attribution_fingerprint if self.baseline else "",
                    "action": "baseline refused; baseline-gated rules are inert",
                },
            )
            self.baseline = None
            self.baseline_state = "absent"
        elif self.baseline_state == "thin":
            self._finding(
                ts,
                "DG-302",
                {"reasons": self.gate["reasons"][:8], "effect": "baseline-gated findings emitted at reduced severity"},
            )

    def finish(self, ts: Optional[float] = None) -> None:
        if self.learn and self.baseline is not None:
            self.baseline.ended = time.time() if ts is None else ts

    # -- frame path ---------------------------------------------------------

    def handle_frame(self, buf: bytes, ts: float) -> None:
        try:
            self._handle(buf, ts)
        except Exception:  # noqa: BLE001 - a malformed frame must never kill the sensor
            self.parse_errors += 1

    def _handle(self, buf: bytes, ts: float) -> None:
        l2 = parse_l2(buf, self.cfg.max_vlan_tags)
        if l2 is None:
            self.parse_errors += 1
            return
        self._bump("frames")

        if l2.ethertype == ETH_LLDP:
            self._on_lldp(buf, l2, ts)
            return

        if l2.ethertype not in (ETH_IPV4, ETH_IPV6):
            return

        # HOT PATH.  The cheapest possible discriminators first: is either the
        # source MAC (egress) or the destination MAC (ingress to the device's
        # own management interface) one we attribute?  Two dict lookups on
        # 6-byte keys; everything else on a busy span exits here before any L3
        # parse is attempted.
        src_mac = fmt_mac(l2.src)
        dev = self.devices.lookup_mac(src_mac)
        ing = None if dev is not None else self.devices.lookup_mac(fmt_mac(l2.dst))
        if dev is None and ing is None and self.cfg.attribution_mode != "l2l3":
            return

        if l2.ethertype == ETH_IPV4:
            l3 = parse_ipv4(buf, l2.payload_off)
        else:
            l3 = parse_ipv6(buf, l2.payload_off, self.cfg.max_ext_headers)
        if l3 is None:
            self.parse_errors += 1
            return

        src_ip = _ip4_str(l3.src) if l3.version == 4 else _ip6_str(l3.src)
        dst_ip = _ip4_str(l3.dst) if l3.version == 4 else _ip6_str(l3.dst)

        if dev is None and ing is None:
            dev = self.devices.lookup_addr(src_ip)
            if dev is None:
                ing = self.devices.lookup_addr(dst_ip)
                if ing is None:
                    return

        if dev is None:
            self._on_ingress(buf, l3, ing, dst_ip, ts)
            return

        # ORIGINATION TEST.  "Traffic from the switch" is not "traffic the
        # switch originated" - the data plane carries everybody's frames.  The
        # MAC test alone is wrong the moment the box is routing, because
        # forwarded frames then carry the router's MAC in the source position.
        # Require BOTH: our MAC in the source position AND a source address
        # that belongs to the device itself.
        if not dev.mgmt_addrs:
            # No address from ANY source - LLDP TLV 8 absent and no operator
            # declaration.  Without an address the origination test cannot run,
            # so every egress rule is dead for this device.  Say so once rather
            # than evaluating rules against transit traffic, which is where the
            # false positives would come from.
            if self._once_only(f"unanchored:{dev.key}"):
                self._finding(
                    ts,
                    "DG-207",
                    {
                        "reason": "no management address from LLDP TLV 8 or operator declaration; egress cannot be anchored to this device",
                        "inert_codes": list(BASELINE_GATED_CODES) + ["DG-201"],
                        "remedy": "enable LLDP management-address advertisement, or declare the device in known_os10",
                    },
                    device=dev,
                )
            return
        if src_ip not in dev.mgmt_addrs:
            return

        self._on_egress(buf, l3, dev, ts)

    def _on_lldp(self, buf: bytes, l2: L2, ts: float) -> None:
        l = parse_lldp(buf, l2.payload_off)
        if l is None:
            self.parse_errors += 1
            return
        src_mac = fmt_mac(l2.src)
        text = f"{l.sys_desc} {l.sys_name}"

        if OUT_OF_SCOPE_PLATFORM_RE.search(text) and DELL_VENDOR_RE.search(text):
            if self._once_only(f"screen:{src_mac}"):
                self._finding(
                    ts,
                    "DG-004",
                    {
                        "sys_name": l.sys_name,
                        "sys_desc": l.sys_desc[:200],
                        "reason": "non-OS10 Dell platform; CVE-2025-22474 does not apply",
                    },
                )
            return

        dev, _notes = self.devices.observe_lldp(src_mac, l)
        if dev is None:
            return

        if l.saw_mgmt_tlv and dev.mgmt_addrs and self._once_only(f"mgmt:{dev.key}"):
            self._finding(
                ts,
                "DG-101",
                {
                    "mgmt_addrs": sorted(dev.mgmt_addrs),
                    "reason": "PR:H vector requires a reachable management plane; it is reachable on this segment",
                },
                device=dev,
            )
        if not l.saw_mgmt_tlv and self._once_only(f"nomgmttlv:{dev.key}"):
            self._finding(
                ts,
                "DG-103",
                {"reason": "LLDP present without a Management Address TLV"},
                device=dev,
            )

        if self.learn:
            return

        if self._once_only(f"ver:{dev.key}"):
            if dev.version is None:
                self._finding(
                    ts,
                    "DG-002",
                    {"reason": "attributed as OS10 but no version string observed", "sys_desc": dev.sys_desc[:200]},
                    device=dev,
                )
            else:
                res = screen_version(dev.version)
                if res["code"]:
                    self._finding(ts, res["code"], res, device=dev)

    def _on_ingress(self, buf: bytes, l3: L3, dev: Device, dst_ip: str, ts: float) -> None:
        """Traffic addressed TO an attributed OS10 management interface.

        Only one rule lives here.  CVE-2025-22474 is PR:H, so it is reachable
        only through the management plane; if that plane is cleartext the
        credential that satisfies PR:H is on the wire too.
        """
        if dst_ip not in dev.mgmt_addrs:
            return  # transit through the box, not addressed to the box
        ports = parse_l4_ports(buf, l3)
        if not ports or l3.proto != 6:
            return
        if ports[1] not in self.cfg.cleartext_mgmt_ports:
            return
        self._finding(
            ts,
            "DG-102",
            {
                "dst": dst_ip,
                "dport": ports[1],
                "reason": "cleartext management to an OS10 management address; the PR:H credential this CVE requires is observable on the wire",
            },
            device=dev,
            suppress_key=f"DG-102:{dev.key}:{ports[1]}",
            pivot=["telnetwatch", "tlswatch"],
        )

    def _on_egress(self, buf: bytes, l3: L3, dev: Device, ts: float) -> None:
        dst_raw = l3.dst
        if not is_unicast_dst(dst_raw):
            # A switch emits control-plane multicast constantly (LLDP, STP,
            # LACP, OSPF, PIM...).  Excluding non-unicast destinations is
            # structural, not a tunable - without it the module drowns.
            return
        dst_ip = _ip4_str(dst_raw) if l3.version == 4 else _ip6_str(dst_raw)
        ports = parse_l4_ports(buf, l3)
        proto = {6: "tcp", 17: "udp"}.get(l3.proto, str(l3.proto))
        scope = addr_scope(dst_raw)
        # Without a usable L4 header there is no port, so no endpoint key and
        # no protocol set entry can honestly be formed. The DESTINATION is
        # still real, so the destination-only rules stay armed.
        keyed = l3.l4_usable
        dport = ports[1] if ports else 0
        endpoint = f"{dst_ip}|{proto}|{dport}"
        portkey = f"{proto}/{dport}"

        qname = None
        if keyed and ports and l3.proto == 17 and dport == 53:
            qname = parse_dns_qname(buf, l3.payload_off + 8, self.cfg.max_dns_name_len)

        if self.learn:
            db = self.baseline.devices.setdefault(dev.key, DeviceBaseline())
            db.frames += 1
            db.scopes.add(scope)
            if keyed:
                db.endpoints.add(endpoint)
                db.ports.add(portkey)
                if qname:
                    db.dns_names.add(qname)
            return

        # DG-201 needs no baseline: a switch has no legitimate reason to reach
        # a cloud instance-metadata endpoint, and in a colo there is no such
        # service to reach.  This is an SSRF/compromise indicator generally -
        # it does not by itself establish CVE-2025-22474.
        if dst_ip in self.metadata_set:
            self._finding(
                ts,
                "DG-201",
                {
                    "dst": dst_ip,
                    "proto": proto,
                    "dport": dport,
                    "note": "indicates SSRF or management-plane compromise generally; does not by itself establish CVE-2025-22474",
                },
                device=dev,
                suppress_key=f"DG-201:{dev.key}:{dst_ip}",
                pivot=["dns_poison_checker"],
            )

        db = self.baseline.devices.get(dev.key) if self.baseline else None
        if db is None:
            return

        if keyed and endpoint not in db.endpoints:
            self._finding(
                ts,
                "DG-202",
                {"dst": dst_ip, "proto": proto, "dport": dport, "scope": scope,
                 "baseline_endpoints": len(db.endpoints)},
                device=dev,
                suppress_key=f"DG-202:{dev.key}:{endpoint}",
            )
            n = self._fanout.setdefault(
                dev.key, RateWindow(self.cfg.fanout_window_s, self.cfg.rate_window_max_events)
            ).add(ts, dst_ip)
            if n >= self.cfg.fanout_threshold:
                # Cardinality guard, not a rate guard: per-destination
                # suppression is useless when every destination is new.
                self._finding(
                    ts,
                    "DG-205",
                    {"distinct_new_destinations": n, "window_s": self.cfg.fanout_window_s,
                     "threshold": self.cfg.fanout_threshold},
                    device=dev,
                    suppress_key=f"DG-205:{dev.key}",
                )

        if keyed and portkey not in db.ports:
            self._finding(
                ts,
                "DG-203",
                {"proto": proto, "dport": dport, "dst": dst_ip,
                 "baseline_ports": sorted(db.ports)[:16]},
                device=dev,
                suppress_key=f"DG-203:{dev.key}:{portkey}",
            )

        if scope not in db.scopes:
            self._finding(
                ts,
                "DG-206",
                {"scope": scope, "dst": dst_ip, "baseline_scopes": sorted(db.scopes)},
                device=dev,
                suppress_key=f"DG-206:{dev.key}:{scope}",
            )

        if qname and qname not in db.dns_names:
            self._finding(
                ts,
                "DG-204",
                {"qname": qname, "resolver": dst_ip,
                 "note": "name is cleartext even when the subsequent fetch is TLS"},
                device=dev,
                suppress_key=f"DG-204:{dev.key}:{qname}",
            )


def _downgrade(sev: str) -> str:
    i = SEVERITIES.index(sev)
    return SEVERITIES[max(0, i - 1)]


# ---------------------------------------------------------------------------
# Live capture path (the one scapy-importing function)
# ---------------------------------------------------------------------------


def run_capture(
    cfg: Config,
    engine: DellGuard,
    timeout: Optional[int] = None,
    pcap: Optional[str] = None,
    _sniff: Any = None,
) -> None:
    """Live or offline capture.

    scapy is imported HERE and nowhere else, so no offline tier ever touches
    it.  `_sniff` exists so a test tier can swap in a recorder and assert the
    live branch passes iface/timeout through, sets store=False, installs the
    BPF filter, and does NOT set offline=.
    """
    if _sniff is None:
        from scapy.all import sniff as _s  # noqa: PLC0415

        _sniff = _s

    def _cb(pkt: Any) -> None:
        engine.handle_frame(bytes(pkt), float(pkt.time))

    kwargs: dict[str, Any] = {"prn": _cb, "store": False}
    if cfg.bpf.strip():
        kwargs["filter"] = cfg.bpf
    if pcap:
        kwargs["offline"] = pcap
    else:
        kwargs["iface"] = cfg.iface
        if timeout:
            kwargs["timeout"] = timeout
    _sniff(**kwargs)


# ---------------------------------------------------------------------------
# Passive-invariant AST guard
# ---------------------------------------------------------------------------

# Split by CALL SHAPE, not by name: a bare `run()` is a local helper, while
# `subprocess.run()` is an Attribute call.  Guarding by name alone makes the
# guard collide with the harness that proves it works.
_BANNED_CALL_NAMES = {"send", "sendp", "sendto", "sr", "sr1", "srp", "pcap_sendpacket", "sendpfast"}
_BANNED_CALL_ATTRS = {
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("os", "system"),
    ("os", "popen"),
    ("socket", "socket"),
}
_BANNED_IMPORTS = {"socket", "subprocess", "requests", "urllib", "http", "ftplib", "telnetlib"}


def audit_passive_invariant(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src)
    problems: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in _BANNED_IMPORTS:
                    problems.append(f"line {node.lineno}: banned import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _BANNED_IMPORTS:
                problems.append(f"line {node.lineno}: banned import from {node.module}")
            if root == "scapy" and node.col_offset == 0:
                problems.append(f"line {node.lineno}: module-scope scapy import")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in _BANNED_CALL_NAMES:
                problems.append(f"line {node.lineno}: banned transmit call {fn.id}()")
            elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                if (fn.value.id, fn.attr) in _BANNED_CALL_ATTRS:
                    problems.append(f"line {node.lineno}: banned call {fn.value.id}.{fn.attr}()")
        elif isinstance(node, ast.FunctionDef):
            if re.match(r"(build|craft|forge|inject)_(exploit|payload|attack)", node.name):
                problems.append(f"line {node.lineno}: offensive helper {node.name}")

    # LESSON G: a module-level name defined twice silently shadows a parser
    # helper with a fixture builder of the same name.
    seen: dict[str, int] = {}
    for node in tree.body:
        names: list[str] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        for n in names:
            if n in seen:
                problems.append(f"line {node.lineno}: module-level name {n!r} redefined (first at {seen[n]})")
            seen[n] = node.lineno

    return problems


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


class _T:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def ok(self, cond: bool, label: str) -> None:
        if cond:
            self.passed += 1
        else:
            self.failed.append(label)

    def eq(self, got: Any, want: Any, label: str) -> None:
        self.ok(got == want, f"{label}: got {got!r} want {want!r}")


def _eth(src: bytes, dst: bytes, et: int, payload: bytes, vlans: Iterable[int] = ()) -> bytes:
    out = dst + src
    for v in vlans:
        out += (0x8100).to_bytes(2, "big") + (v & 0x0FFF).to_bytes(2, "big")
    return out + et.to_bytes(2, "big") + payload


def _ipv4_pkt(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    hdr = bytes([0x45, 0x00]) + (20 + len(payload)).to_bytes(2, "big")
    hdr += b"\x00\x00\x00\x00" + bytes([64, proto]) + b"\x00\x00" + s + d
    return hdr + payload


def _ipv6_pkt(src: str, dst: str, nh: int, payload: bytes, ext: bytes = b"") -> bytes:
    s = ipaddress.ip_address(src).packed
    d = ipaddress.ip_address(dst).packed
    first_nh = ext[0] if ext else nh
    if ext:
        first_nh = 60  # destination options, carrying nh inside
        body = bytes([nh, 0]) + b"\x00" * 6 + payload
    else:
        body = payload
    hdr = b"\x60\x00\x00\x00" + len(body).to_bytes(2, "big") + bytes([first_nh, 64]) + s + d
    return hdr + body


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return (
        sport.to_bytes(2, "big")
        + dport.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )


def _tcp(sport: int, dport: int) -> bytes:
    return sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + b"\x00" * 16


def _dns_query(name: str) -> bytes:
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for lab in name.split("."):
        q += bytes([len(lab)]) + lab.encode()
    return q + b"\x00\x00\x01\x00\x01"


def _tlv(t: int, v: bytes) -> bytes:
    return (((t << 9) | len(v)) & 0xFFFF).to_bytes(2, "big") + v


def _lldp(mac: bytes, sysname: str, sysdesc: str, mgmt: Optional[str] = None) -> bytes:
    body = _tlv(1, b"\x04" + mac) + _tlv(2, b"\x05eth1/1") + _tlv(3, b"\x00\x78")
    body += _tlv(5, sysname.encode()) + _tlv(6, sysdesc.encode())
    if mgmt:
        a = ipaddress.ip_address(mgmt)
        sub = 1 if a.version == 4 else 2
        val = bytes([1 + len(a.packed), sub]) + a.packed + b"\x02" + b"\x00" * 4 + b"\x00"
        body += _tlv(8, val)
    return body + _tlv(0, b"")


SW_MAC = bytes.fromhex("001ec9aabbcc")
OTHER_MAC = bytes.fromhex("aabbccddeeff")
LLDP_DST = bytes.fromhex("0180c200000e")
BCAST = bytes.fromhex("ffffffffffff")
OS10_DESC = "Dell EMC Networking OS10 Enterprise. Dell EMC OS Version: 10.5.6.4"


def _engine(cfg: Optional[Config] = None, **kw: Any) -> DellGuard:
    return DellGuard(cfg or Config(), **kw)


def _run(eng: DellGuard, frames: list[bytes], t0: float = 1000.0) -> list[dict[str, Any]]:
    # Guard against the classic harness bug: iterating a bare bytes object
    # yields ints, so the engine would silently test nothing.
    assert isinstance(frames, (list, tuple)), "frames must be a list, not bytes"
    mark = len(eng.findings)
    for i, f in enumerate(frames):
        assert isinstance(f, (bytes, bytearray)), f"frame {i} is not bytes"
        eng.handle_frame(bytes(f), t0 + i)
    # Return ONLY what the frames produced. Lifecycle findings from start()
    # are inspected via eng.findings, so a test asserting "these frames are
    # silent" cannot be satisfied or broken by an unrelated DG-3xx.
    return eng.findings[mark:]


def _codes(fs: list[dict[str, Any]]) -> list[str]:
    return [f["code"] for f in fs]


def selftest() -> int:  # noqa: PLR0915
    t = _T()

    # -- registry integrity -------------------------------------------------
    for code, meta in FINDINGS.items():
        t.ok(re.fullmatch(r"DG-\d{3}", code) is not None, f"code shape {code}")
        t.ok(meta["severity"] in SEVERITIES, f"{code} severity")
        t.ok(meta["confidence"] in CONFIDENCES, f"{code} confidence")
        t.ok(meta["class"] in CLASSES, f"{code} class")
        t.ok(bool(meta["desc"]), f"{code} desc non-empty")
        for c in meta["cves"]:
            t.ok(c in CVE_CATALOG, f"{code} cites known CVE")
    t.eq(len({m["name"] for m in FINDINGS.values()}), len(FINDINGS), "finding names unique")
    t.ok(all(c in FINDINGS for c in BASELINE_GATED_CODES), "gated codes exist")

    # The CNA vector is C:H/I:N/A:N. Integrity and availability language must
    # not appear anywhere in what this module emits.
    blob = " ".join(
        [m["desc"] for m in FINDINGS.values()]
        + [str(v) for v in CVE_CATALOG[CVE_ID].values()]
    ).lower()
    t.ok("denial of service" not in blob, "no DoS claim (A:N)")
    t.ok("configuration manipulation" not in blob, "no integrity claim (I:N)")
    t.ok("PR:H" in CVE_CATALOG[CVE_ID]["vector"], "vector records PR:H")
    t.eq(CVE_CATALOG[CVE_ID]["cvss"], 6.8, "CVSS is the CNA figure")
    t.eq(len(AFFECTED_TRAINS), 4, "all four affected trains tracked")
    t.ok(any(x[0] == "10.6.0" for x in AFFECTED_TRAINS), "10.6.0 train present")

    # -- address helpers ----------------------------------------------------
    for s in ["::1", "fe80::1", "2001:db8::", "2001:db8:0:0:1:0:0:1", "fd00:ec2::254",
              "ff02::1", "::", "2001:0:0:1:0:0:0:1"]:
        raw = ipaddress.ip_address(s).packed
        t.eq(_ip6_str(raw), str(ipaddress.ip_address(s)), f"_ip6_str RFC5952 {s}")
    t.eq(canon_addr("FE80::0001"), "fe80::1", "canon_addr normalises operator literal")
    t.eq(norm_mac("00-1E-C9-AA-BB-CC"), "00:1e:c9:aa:bb:cc", "norm_mac")

    for s, want in [("127.0.0.1", "loopback"), ("169.254.169.254", "link-local"),
                    ("10.1.2.3", "private"), ("172.20.0.1", "private"),
                    ("172.32.0.1", "global"), ("192.168.1.1", "private"),
                    ("100.64.0.1", "cgnat"), ("8.8.8.8", "global"),
                    ("224.0.0.5", "multicast"), ("::1", "loopback"),
                    ("fe80::1", "link-local"), ("fd00::1", "private"),
                    ("ff02::1", "multicast"), ("2001:db8::1", "global")]:
        t.eq(addr_scope(ipaddress.ip_address(s).packed), want, f"scope {s}")
    # Cross-check the hand-rolled classifier against stdlib where they overlap.
    for s in ["127.0.0.1", "169.254.1.1", "10.0.0.1", "8.8.8.8", "::1", "fe80::1", "fd00::1"]:
        a = ipaddress.ip_address(s)
        got = addr_scope(a.packed)
        t.eq(got == "loopback", a.is_loopback, f"xcheck loopback {s}")
        t.eq(got == "link-local", a.is_link_local, f"xcheck link-local {s}")

    # -- parsers ------------------------------------------------------------
    f = _eth(SW_MAC, OTHER_MAC, ETH_IPV4, _ipv4_pkt("10.0.0.1", "10.0.0.2", 17, _udp(1, 2, b"")))
    l2 = parse_l2(f)
    t.eq(l2.ethertype, ETH_IPV4, "parse_l2 ethertype")
    t.eq(l2.vlans, (), "parse_l2 no vlan")
    f2 = _eth(SW_MAC, OTHER_MAC, ETH_IPV4, _ipv4_pkt("10.0.0.1", "10.0.0.2", 17, _udp(1, 2, b"")), vlans=[100, 200])
    l2b = parse_l2(f2)
    t.eq(l2b.vlans, (100, 200), "parse_l2 qinq")
    t.eq(l2b.ethertype, ETH_IPV4, "parse_l2 ethertype past tags")
    t.ok(parse_l2(b"\x00" * 10) is None, "parse_l2 short frame")

    l3 = parse_ipv4(f, l2.payload_off)
    t.eq(_ip4_str(l3.src), "10.0.0.1", "parse_ipv4 src")
    t.eq(l3.proto, 17, "parse_ipv4 proto")
    t.eq(parse_l4_ports(f, l3), (1, 2), "parse_l4_ports")

    f6 = _eth(SW_MAC, OTHER_MAC, ETH_IPV6, _ipv6_pkt("2001:db8::1", "2001:db8::2", 17, _udp(5, 53, b"")))
    l26 = parse_l2(f6)
    l36 = parse_ipv6(f6, l26.payload_off)
    t.eq(_ip6_str(l36.src), "2001:db8::1", "parse_ipv6 src")
    t.eq(l36.proto, 17, "parse_ipv6 nh")
    f6e = _eth(SW_MAC, OTHER_MAC, ETH_IPV6,
               _ipv6_pkt("2001:db8::1", "2001:db8::2", 17, _udp(5, 53, b""), ext=b"\x3c"))
    l26e = parse_l2(f6e)
    l36e = parse_ipv6(f6e, l26e.payload_off)
    t.eq(l36e.proto, 17, "parse_ipv6 walks a destination-options header")
    t.eq(parse_l4_ports(f6e, l36e), (5, 53), "ports found past ext header")

    # -- LLDP ---------------------------------------------------------------
    lf = _eth(SW_MAC, LLDP_DST, ETH_LLDP, _lldp(SW_MAC, "leaf1", OS10_DESC, "10.10.0.5"))
    ll = parse_lldp(lf, parse_l2(lf).payload_off)
    t.eq(ll.chassis_mac, "00:1e:c9:aa:bb:cc", "lldp chassis mac")
    t.eq(ll.sys_name, "leaf1", "lldp sysname")
    t.eq(ll.mgmt_addrs, ["10.10.0.5"], "lldp mgmt address tlv v4")
    t.ok(ll.saw_mgmt_tlv, "lldp mgmt tlv flag")
    lf6 = _eth(SW_MAC, LLDP_DST, ETH_LLDP, _lldp(SW_MAC, "leaf1", OS10_DESC, "2001:db8::5"))
    ll6 = parse_lldp(lf6, parse_l2(lf6).payload_off)
    t.eq(ll6.mgmt_addrs, ["2001:db8::5"], "lldp mgmt address tlv v6")
    lfn = _eth(SW_MAC, LLDP_DST, ETH_LLDP, _lldp(SW_MAC, "leaf1", OS10_DESC))
    lln = parse_lldp(lfn, parse_l2(lfn).payload_off)
    t.ok(not lln.saw_mgmt_tlv, "lldp without mgmt tlv")

    # -- DNS ----------------------------------------------------------------
    q = _dns_query("attacker.example.com")
    t.eq(parse_dns_qname(q, 0), "attacker.example.com", "dns qname")
    resp = bytearray(q)
    resp[2] |= 0x80
    t.ok(parse_dns_qname(bytes(resp), 0) is None, "dns response ignored")
    t.ok(parse_dns_qname(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c", 0) is None,
         "dns compression pointer in question refused")

    # -- version screening --------------------------------------------------
    t.eq(parse_os10_version(OS10_DESC), (10, 5, 6, 4), "version parse")
    t.eq(screen_version((10, 5, 6, 4))["code"], "DG-001", "10.5.6.4 affected")
    t.eq(screen_version((10, 5, 6, 8))["code"], None, "10.5.6.8 at fixed release")
    t.eq(screen_version((10, 5, 6, 9))["code"], None, "10.5.6.9 above fixed")
    t.eq(screen_version((10, 5, 4, 13))["code"], "DG-001", "10.5.4.13 affected")
    t.eq(screen_version((10, 5, 4, 14))["code"], None, "10.5.4.14 fixed")
    t.eq(screen_version((10, 6, 0, 1))["code"], "DG-001", "10.6.0.1 affected (the train the old list missed)")
    t.eq(screen_version((10, 6, 0, 2))["code"], None, "10.6.0.2 fixed")
    t.eq(screen_version((10, 5, 3, 5))["code"], "DG-003", "untracked train")
    t.ok("NOT confirmed patched" in screen_version((10, 5, 3, 5))["reason"],
         "absent-train wording is emitted by code, not only documented")
    t.eq(screen_version((10, 5, 6))["code"], "DG-002", "3-component version cannot be compared")

    # -- scope screening ----------------------------------------------------
    for desc in ["Dell EMC Networking OS9", "Dell Enterprise SONiC 4.5.0",
                 "Dell iDRAC9", "Dell PowerEdge R750", "Dell Force10 FTOS"]:
        t.ok(OUT_OF_SCOPE_PLATFORM_RE.search(desc) is not None, f"screened out: {desc}")
    t.ok(OUT_OF_SCOPE_PLATFORM_RE.search(OS10_DESC) is None, "OS10 not screened out")
    t.ok(IN_SCOPE_PLATFORM_RE.search(OS10_DESC) is not None, "OS10 in scope")
    t.ok(IN_SCOPE_PLATFORM_RE.search("Dell Enterprise SONiC 4.5.0") is None, "SONiC not in scope")

    eng = _engine()
    eng.start(1000.0)
    fs = _run(eng, [_eth(OTHER_MAC, LLDP_DST, ETH_LLDP,
                         _lldp(OTHER_MAC, "sonic1", "Dell Enterprise SONiC 4.5.0", "10.10.0.9"))])
    t.ok("DG-004" in _codes(fs), "DG-004 fires on non-OS10 Dell")
    t.ok("DG-101" not in _codes(fs), "screened device produces no exposure finding")

    # -- attribution + posture ---------------------------------------------
    eng = _engine()
    eng.start(1000.0)
    fs = _run(eng, [lf])
    t.ok("DG-101" in _codes(fs), "DG-101 mgmt plane reachable")
    t.ok("DG-001" in _codes(fs), "DG-001 version in affected train")
    d101s = [f for f in fs if f["code"] == "DG-101"]
    t.eq((d101s[0]["attribution"]["source"] if d101s else None), "lldp",
         "attribution source lldp")
    t.eq(eng.devices.lookup_addr("10.10.0.5").key, "leaf1", "mgmt address join installed")

    eng = _engine()
    eng.start(1000.0)
    fs = _run(eng, [lfn])
    t.ok("DG-103" in _codes(fs), "DG-103 when no mgmt address TLV")

    cfg_op = Config(known_os10=[KnownDevice(mac="00:1e:c9:aa:bb:cc", addrs=["10.10.0.5"], label="leaf1")])
    eng = _engine(cfg_op)
    t.eq(eng.devices.lookup_mac("00:1e:c9:aa:bb:cc").source, "operator",
         "operator-declared device carries source=operator")

    # -- origination test ---------------------------------------------------
    # A frame carrying the switch's MAC but ANOTHER host's source IP is
    # transit, not origination, and must be ignored.
    base = Baseline(attribution_fingerprint=cfg_op.attribution_fingerprint(),
                    started=0.0, ended=10**6)
    base.devices["leaf1"] = DeviceBaseline(
        endpoints={"10.10.0.20|udp|514", "10.10.0.20|udp|53", "10.10.0.21|udp|123"},
        ports={"udp/514", "udp/53", "udp/123"},
        scopes={"private"},
        dns_names={"ntp.internal"},
        frames=10**5,
    )
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    transit = _eth(SW_MAC, OTHER_MAC, ETH_IPV4,
                   _ipv4_pkt("192.0.2.77", "203.0.113.9", 6, _tcp(1234, 80)))
    fs = _run(eng, [transit])
    t.eq(_codes(fs), [], "transit frame with foreign source IP produces nothing")

    # -- baseline-gated rules ----------------------------------------------
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    t.eq(eng.baseline_state, "ready", "sufficient baseline is ready")
    known = _eth(SW_MAC, OTHER_MAC, ETH_IPV4,
                 _ipv4_pkt("10.10.0.5", "10.10.0.20", 17, _udp(5000, 514, b"x")))
    fs = _run(eng, [known])
    t.eq(_codes(fs), [], "baseline endpoint is silent")

    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    newep = _eth(SW_MAC, OTHER_MAC, ETH_IPV4,
                 _ipv4_pkt("10.10.0.5", "203.0.113.9", 6, _tcp(40000, 80)))
    fs = _run(eng, [newep])
    c = _codes(fs)
    t.ok("DG-202" in c, "DG-202 new endpoint")
    t.ok("DG-203" in c, "DG-203 new protocol/port")
    t.ok("DG-206" in c, "DG-206 new address scope")

    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    dnsf = _eth(SW_MAC, OTHER_MAC, ETH_IPV4,
                _ipv4_pkt("10.10.0.5", "10.10.0.20", 17, _udp(33333, 53, _dns_query("evil.attacker.tld"))))
    fs = _run(eng, [dnsf])
    t.ok("DG-204" in c or "DG-204" in _codes(fs), "DG-204 new DNS name")
    d204s = [f for f in fs if f["code"] == "DG-204"]
    t.eq(len(d204s), 1, "exactly one DG-204")
    t.eq((d204s[0]["detail"]["qname"] if d204s else None), "evil.attacker.tld",
         "DG-204 carries the name")

    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    known_dns = _eth(SW_MAC, OTHER_MAC, ETH_IPV4,
                     _ipv4_pkt("10.10.0.5", "10.10.0.20", 17, _udp(33333, 53, _dns_query("ntp.internal"))))
    t.ok("DG-204" not in _codes(_run(eng, [known_dns])), "baseline DNS name silent")

    # fanout cardinality guard
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    sweep = [
        _eth(SW_MAC, OTHER_MAC, ETH_IPV4,
             _ipv4_pkt("10.10.0.5", f"10.10.9.{i}", 6, _tcp(40000 + i, 80)))
        for i in range(1, 12)
    ]
    fs = _run(eng, sweep)
    t.ok("DG-205" in _codes(fs), "DG-205 fanout")
    t.ok(eng.counters.get("DG-202", 0) >= 8, "detection continues under suppression")

    # metadata endpoint needs no baseline
    eng = _engine(cfg_op)
    eng.start(1000.0)
    meta = _eth(SW_MAC, OTHER_MAC, ETH_IPV4,
                _ipv4_pkt("10.10.0.5", "169.254.169.254", 6, _tcp(40000, 80)))
    fs = _run(eng, [meta])
    t.ok("DG-201" in _codes(fs), "DG-201 fires with no baseline at all")
    t.ok("DG-202" not in _codes(fs), "baseline-gated rules stay inert with no baseline")
    ms = [f for f in fs if f["code"] == "DG-201"]
    t.eq(len(ms), 1, "exactly one DG-201")
    t.ok("does not by itself establish" in (ms[0]["detail"]["note"] if ms else ""),
         "DG-201 does not overclaim the CVE")

    # multicast is excluded structurally
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    mc = _eth(SW_MAC, bytes.fromhex("01005e000005"), ETH_IPV4,
              _ipv4_pkt("10.10.0.5", "224.0.0.5", 89, b"\x00" * 8))
    t.eq(_codes(_run(eng, [mc])), [], "control-plane multicast excluded")

    # -- DG-102 cleartext management (ingress branch) ------------------------
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    telnet_in = _eth(OTHER_MAC, SW_MAC, ETH_IPV4,
                     _ipv4_pkt("10.10.0.99", "10.10.0.5", 6, _tcp(51000, 23)))
    fs = _run(eng, [telnet_in])
    t.ok("DG-102" in _codes(fs), "DG-102 cleartext telnet to the mgmt address")
    d102s = [f for f in fs if f["code"] == "DG-102"]
    t.eq((d102s[0]["detail"]["dport"] if d102s else None), 23, "DG-102 port")

    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    https_in = _eth(OTHER_MAC, SW_MAC, ETH_IPV4,
                    _ipv4_pkt("10.10.0.99", "10.10.0.5", 6, _tcp(51000, 443)))
    t.eq(_codes(_run(eng, [https_in])), [], "encrypted management is silent")

    # Traffic THROUGH the switch on port 23 is not management OF the switch.
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    telnet_thru = _eth(OTHER_MAC, SW_MAC, ETH_IPV4,
                       _ipv4_pkt("10.10.0.99", "198.51.100.7", 6, _tcp(51000, 23)))
    t.eq(_codes(_run(eng, [telnet_thru])), [], "transit telnet is not a management finding")

    # -- DG-207 unanchorable egress -----------------------------------------
    # LLDP identifies an OS10 box but carries no Management Address TLV and no
    # operator declaration supplies one, so nothing can anchor its egress.
    eng = _engine(Config(), baseline=Baseline(
        attribution_fingerprint=Config().attribution_fingerprint(), started=0.0, ended=10**6))
    eng.start(1000.0)
    unanchored_egress = _eth(SW_MAC, OTHER_MAC, ETH_IPV4,
                             _ipv4_pkt("10.10.0.5", "169.254.169.254", 6, _tcp(40000, 80)))
    fs = _run(eng, [lfn, unanchored_egress])
    c207 = _codes(fs)
    t.ok("DG-207" in c207, "DG-207 when egress cannot be anchored")
    t.ok("DG-201" not in c207, "unanchored device evaluates no egress rule, not even DG-201")
    d207s = [f for f in fs if f["code"] == "DG-207"]
    d207 = d207s[0] if d207s else {"detail": {}}
    t.ok("DG-201" in d207["detail"].get("inert_codes", []), "DG-207 names what is dead")
    t.ok("known_os10" in d207["detail"].get("remedy", ""), "DG-207 states the remedy")

    # Declaring the address in config revives it - the remedy actually works.
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    t.ok("DG-201" in _codes(_run(eng, [lfn, unanchored_egress])),
         "operator declaration anchors egress that LLDP could not")

    # -- every declared code has a rule behind it ---------------------------
    emitted: set[str] = set()
    tree_codes = ast.parse(open(__file__, encoding="utf-8").read())
    for node in ast.walk(tree_codes):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "_finding":
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) \
                        and re.fullmatch(r"DG-\d{3}", a.value):
                    emitted.add(a.value)
    # Some codes are emitted through a VARIABLE, not a literal:
    # `self._finding(ts, res["code"], ...)` where res comes from
    # screen_version().  An extractor that only resolves literal arguments
    # silently under-reports and makes this whole check vacuous, so the
    # runtime-dispatched half is resolved by RUNNING the dispatcher over
    # representative inputs rather than by reading the source.
    dispatched = {
        screen_version(v)["code"]
        for v in [(10, 5, 6, 4), (10, 5, 6, 9), (10, 5, 3, 5), (10, 5, 6)]
    } - {None}
    t.ok(dispatched >= {"DG-001", "DG-002", "DG-003"},
         f"screen_version dispatches the posture codes (got {sorted(dispatched)})")
    missing = sorted(set(FINDINGS) - emitted - dispatched)
    t.eq(missing, [], "every declared finding code has an emitting call site")
    # Non-vacuity: the literal extractor must actually have found something.
    t.ok(len(emitted) >= 12, f"literal extractor is not vacuous ({len(emitted)} codes)")

    # -- operational class --------------------------------------------------
    eng = _engine(Config())
    eng.start(1000.0)
    t.ok("DG-301" in _codes(eng.findings), "DG-301 baseline absent")

    thin = Baseline(attribution_fingerprint=cfg_op.attribution_fingerprint(),
                    started=0.0, ended=60.0)
    thin.devices["leaf1"] = DeviceBaseline(endpoints={"10.10.0.20|udp|514"}, ports={"udp/514"},
                                           scopes={"private"}, frames=5)
    eng = _engine(cfg_op, baseline=thin)
    eng.start(1000.0)
    t.eq(eng.baseline_state, "thin", "thin baseline detected")
    t.ok("DG-302" in _codes(eng.findings), "DG-302 emitted")
    fs = _run(eng, [newep])
    d202s = [f for f in fs if f["code"] == "DG-202"]
    t.eq(len(d202s), 1, "thin baseline still detects DG-202")
    d202 = d202s[0] if d202s else {"severity": None, "confidence": None, "detail": {}}
    t.eq(d202["severity"], "notice", "thin baseline downgrades DG-202 severity")
    t.eq(d202["confidence"], "low", "thin baseline downgrades confidence")
    t.ok(d202["detail"].get("baseline_thin") is True, "downgrade is visible in the detail")

    mismatched = Baseline(attribution_fingerprint="deadbeefdeadbeef", started=0.0, ended=10**6)
    eng = _engine(cfg_op, baseline=mismatched)
    eng.start(1000.0)
    t.ok("DG-303" in _codes(eng.findings), "DG-303 config mismatch")
    t.eq(eng.baseline_state, "absent", "refused baseline is not used")

    eng = _engine(Config(bpf="udp port 53"))
    eng.start(1000.0)
    t.ok("DG-304" in _codes(eng.findings), "DG-304 non-empty BPF")
    t.eq(Config().bpf, "", "default BPF filter is empty")

    # -- learn mode ---------------------------------------------------------
    eng = _engine(cfg_op, learn=True)
    eng.start(1000.0)
    fs = _run(eng, [lf, known, newep, dnsf])
    t.eq(fs, [], "learn mode emits nothing")
    eng.finish(1000.0 + 86500)
    t.ok("leaf1" in eng.baseline.devices, "learn recorded the device")
    db = eng.baseline.devices["leaf1"]
    t.ok("203.0.113.9|tcp|80" in db.endpoints, "learn recorded an endpoint")
    t.ok("evil.attacker.tld" in db.dns_names, "learn recorded a DNS name")
    t.ok(eng.counters.get("frames", 0) >= 4, "learn keeps counters intact")
    rt = Baseline.from_json(json.loads(json.dumps(eng.baseline.to_json())))
    t.eq(rt.devices["leaf1"].endpoints, db.endpoints, "baseline round-trips through JSON")
    t.eq(rt.attribution_fingerprint, cfg_op.attribution_fingerprint(), "fingerprint round-trips")

    # NEVER AUTO-LEARN: enforcement must not mutate the baseline.  Structural
    # test, not an inspection of intent - an auto-updating baseline is
    # attacker-poisonable by simply talking to the box often enough.
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    before = base.content_hash()
    _run(eng, sweep + [newep, dnsf, meta])
    t.eq(base.content_hash(), before, "enforcement never mutates the baseline")

    # -- suppressor ---------------------------------------------------------
    sup = Suppressor(300, 3)
    allowed = sum(1 for i in range(10) if sup.allow("k", 1000.0 + i))
    t.eq(allowed, 3, "suppressor caps alerts at max")
    t.eq(sup.suppressed["k"], 7, "suppressor keeps counts")
    rw = RateWindow(60, 16)
    for i in range(100):
        rw.add(1000.0, f"h{i}")
    t.ok(len(rw.events) <= 16, "rate window respects its cap")

    # -- config -------------------------------------------------------------
    c = Config.load(Config().dump())
    t.eq(c.attribution_mode, "l2", "config round-trips")
    try:
        Config.load({"nope": 1})
        t.ok(False, "unknown config key rejected")
    except ValueError:
        t.ok(True, "unknown config key rejected")
    try:
        Config.load({"attribution_mode": "l7"})
        t.ok(False, "bad attribution_mode rejected")
    except ValueError:
        t.ok(True, "bad attribution_mode rejected")
    a = Config(known_os10=[KnownDevice(mac="00:1e:c9:aa:bb:cc")])
    b = Config(known_os10=[KnownDevice(mac="00:1e:c9:aa:bb:cd")])
    t.ok(a.attribution_fingerprint() != b.attribution_fingerprint(),
         "fingerprint changes with the device set")

    # -- robustness ---------------------------------------------------------
    eng = _engine(cfg_op, baseline=base)
    eng.start(1000.0)
    for junk in [b"", b"\x00" * 5, b"\xff" * 64,
                 _eth(SW_MAC, OTHER_MAC, ETH_IPV4, b"\x45"),
                 _eth(SW_MAC, LLDP_DST, ETH_LLDP, b"\xff\xff\x00")]:
        eng.handle_frame(junk, 1000.0)
    t.ok(True, "malformed frames never raise")

    # -- OUI policy ---------------------------------------------------------
    # Behavioural, not a grep: with no --oui-file the map must be EMPTY and
    # enrichment must return nothing, so attribution can never lean on a
    # shipped table. (An earlier version of this check searched the module
    # source for OUI literals and matched its OWN literal - LESSON D in a new
    # shape. Test the behaviour, never the prose.)
    dt = DeviceTable(Config())
    t.eq(dt.oui, {}, "no OUI map is loaded without an operator file")
    t.eq(dt.oui_vendor("00:1e:c9:aa:bb:cc"), "", "OUI enrichment is empty by default")
    dt2 = DeviceTable(Config(), oui={"00:1e:c9": "Dell Inc."})
    t.eq(dt2.oui_vendor("00:1e:c9:aa:bb:cc"), "Dell Inc.", "operator OUI file enriches")
    # An OUI-enriched device is still attributed by LLDP/operator, never by OUI
    # alone: a MAC with a Dell OUI and no OS10 evidence must not be attributed.
    t.ok(dt2.lookup_mac("00:1e:c9:aa:bb:cc") is None,
         "a Dell OUI alone never attributes a device")
    # Structural bound: no module-level literal may look like a shipped OUI
    # table (>8 MAC-prefix-shaped keys in one dict).
    tree = ast.parse(open(__file__, encoding="utf-8").read())
    worst = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            n = sum(
                1
                for k in node.keys
                if isinstance(k, ast.Constant)
                and isinstance(k.value, str)
                and re.fullmatch(r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){2}", k.value)
            )
            worst = max(worst, n)
    t.ok(worst <= 8, f"no shipped OUI table (largest MAC-prefix dict: {worst})")

    # -- passive invariant --------------------------------------------------
    if os.path.exists(__file__):
        probs = audit_passive_invariant(__file__)
        t.eq(probs, [], "passive invariant clean")

    print(f"selftest: {t.passed}/{t.passed + len(t.failed)} passed")
    for fail in t.failed:
        print(f"  FAIL {fail}")
    return 0 if not t.failed else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

NOOP_FLAGS = {
    "--probe": "dellguard never transmits; retained as a documented no-op so scripts that set it do not break.",
}


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog=MODULE, description=f"{DISPLAY_NAME} v{VERSION}")
    p.add_argument("-i", "--iface", default="")
    p.add_argument("-r", "--pcap", default="")
    p.add_argument("--bpf", default="")
    p.add_argument("--config", default="")
    p.add_argument("--baseline", default="")
    p.add_argument("--learn", action="store_true", help="characterise the segment and write a baseline; emits nothing")
    p.add_argument("--timeout", type=int, default=0)
    p.add_argument("--out", default="-")
    p.add_argument("--oui-file", default="")
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--audit", action="store_true")
    p.add_argument("--print-config", action="store_true")
    p.add_argument("--print-lab-codes", action="store_true")
    p.add_argument("--version", action="version", version=f"{MODULE} {VERSION}")
    p.add_argument("--probe", action="store_true", help=NOOP_FLAGS["--probe"])
    args = p.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.audit:
        probs = audit_passive_invariant(__file__)
        for x in probs:
            print(f"PROBLEM {x}")
        print(f"audit: {len(probs)} problems")
        return 1 if probs else 0
    if args.print_lab_codes:
        print(" ".join(sorted(FINDINGS)))
        return 0

    cfg = Config()
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            cfg = Config.load(json.load(fh))
    if args.iface:
        cfg.iface = args.iface
    if args.bpf:
        cfg.bpf = args.bpf
    if args.out:
        cfg.out = args.out
    if args.oui_file:
        cfg.oui_file = args.oui_file
    if args.baseline:
        cfg.baseline_path = args.baseline

    if args.print_config:
        print(json.dumps(cfg.dump(), indent=2, sort_keys=True))
        return 0

    oui = load_oui_file(cfg.oui_file) if cfg.oui_file else {}

    baseline = None
    if not args.learn and os.path.exists(cfg.baseline_path):
        with open(cfg.baseline_path, encoding="utf-8") as fh:
            baseline = Baseline.from_json(json.load(fh))

    sink = sys.stdout if cfg.out == "-" else open(cfg.out, "a", encoding="utf-8")

    def emit(f: dict[str, Any]) -> None:
        sink.write(json.dumps(f) + "\n")
        sink.flush()

    eng = DellGuard(cfg, learn=args.learn, baseline=baseline, emit=emit, oui=oui)
    eng.start()
    try:
        run_capture(cfg, eng, timeout=args.timeout or None, pcap=args.pcap or None)
    except KeyboardInterrupt:
        pass
    eng.finish()

    if args.learn and eng.baseline is not None:
        os.makedirs(os.path.dirname(cfg.baseline_path) or ".", exist_ok=True)
        with open(cfg.baseline_path, "w", encoding="utf-8") as fh:
            json.dump(eng.baseline.to_json(), fh, indent=2, sort_keys=True)
        gate = eng.baseline.sufficiency(cfg)
        print(
            f"baseline written: {cfg.baseline_path} "
            f"devices={len(eng.baseline.devices)} "
            f"duration={int(eng.baseline.duration())}s "
            f"sufficient={gate['sufficient']}",
            file=sys.stderr,
        )
        for r in gate["reasons"][:8]:
            print(f"  gate: {r}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
