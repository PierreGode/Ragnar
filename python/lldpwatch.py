#!/usr/bin/env python3
"""
lldpwatch — passive LLDP (IEEE 802.1AB) security monitor for Ragnar.

Standalone L2 module. Sibling of cdpwatch. Receives only; never transmits.

Two detection dimensions:
  (1) Class A — structural TLV bounds / grammar violations. Vendor-agnostic.
      Catches the malformed-frame shape behind the LLDP parser CVE backbone
      (lldpd, Cisco IOS/IOS-XE/NX-OS/FXOS, Juniper l2cpd, SonicWall SWS).
  (2) Class B — cleartext version screening against a vulnerable-family table.
      NOTE discipline only: never a vulnerable/not verdict.
  (3) Class C — abuse tripwires: flood / neighbour-table exhaustion, and an
      optional learn/enforce forged-neighbour mode (OFF by default).

There is deliberately NO disclosure-posture class: LLDP being enabled and
readable is by design and is not a finding.

Passive invariant: no transmit call anywhere, enforced by an AST self-test.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "0.1.0-dev"

# --------------------------------------------------------------------------
# Wire constants
# --------------------------------------------------------------------------

ETHERTYPE_LLDP = 0x88CC
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100)

# Link-local LLDP destination group MACs (IEEE 802.1AB-2016 Table 7-1)
LLDP_GROUP_MACS = {
    "01:80:c2:00:00:0e": "nearest-bridge",
    "01:80:c2:00:00:03": "nearest-non-tpmr-bridge",
    "01:80:c2:00:00:00": "nearest-customer-bridge",
}

# MEASURED, not assumed (suite LESSON AE, new LLDP-specific instance). The
# flat form `... or (vlan and vlan and ether proto 0x88cc)` is a NO-OP: it is
# behaviourally identical to the two-term filter, because libpcap's `vlan`
# keyword mutates the offset state for the rest of the expression rather than
# composing across an `or`. Measured against real libpcap over untagged,
# 802.1Q, QinQ-0x8100 and QinQ-0x88a8 LLDP:
#   ether proto 0x88cc                                   -> 1/4
#   ... or (vlan and ether proto 0x88cc)                 -> 2/4
#   ... or (vlan and vlan and ether proto 0x88cc)        -> 2/4  (no-op)
#   NESTED form below                                    -> 4/4, zero noise
# This matters because parse_ethernet() walks a QinQ stack: without the
# nested filter that code is unreachable in production (suite LESSON H).
BPF_FILTER = (
    "ether proto 0x88cc or "
    "(vlan and (ether proto 0x88cc or (vlan and ether proto 0x88cc)))"
)

# TLV types
TLV_END = 0
TLV_CHASSIS_ID = 1
TLV_PORT_ID = 2
TLV_TTL = 3
TLV_PORT_DESC = 4
TLV_SYS_NAME = 5
TLV_SYS_DESC = 6
TLV_SYS_CAP = 7
TLV_MGMT_ADDR = 8
TLV_ORG_SPECIFIC = 127

TLV_NAMES = {
    0: "End-of-LLDPDU",
    1: "Chassis ID",
    2: "Port ID",
    3: "Time To Live",
    4: "Port Description",
    5: "System Name",
    6: "System Description",
    7: "System Capabilities",
    8: "Management Address",
    127: "Organizationally Specific",
}

RESERVED_TLV_RANGE = range(9, 127)  # 9..126 inclusive

# Chassis ID subtypes (802.1AB-2016 Table 8-2)
CHASSIS_SUBTYPES = {
    1: "chassis-component",
    2: "interface-alias",
    3: "port-component",
    4: "mac-address",
    5: "network-address",
    6: "interface-name",
    7: "locally-assigned",
}

# Port ID subtypes (Table 8-3)
PORT_SUBTYPES = {
    1: "interface-alias",
    2: "port-component",
    3: "mac-address",
    4: "network-address",
    5: "interface-name",
    6: "agent-circuit-id",
    7: "locally-assigned",
}

# IANA address family numbers used by LLDP network-address encodings
AF_IPV4 = 1
AF_IPV6 = 2
AF_LEN = {AF_IPV4: 4, AF_IPV6: 16}
AF_NAME = {AF_IPV4: "ipv4", AF_IPV6: "ipv6"}

# Organizationally Specific OUIs
OUI_8021 = b"\x00\x80\xc2"
OUI_8023 = b"\x00\x12\x0f"
OUI_MED = b"\x00\x12\xbb"
OUI_NAMES = {
    OUI_8021: "IEEE-802.1",
    OUI_8023: "IEEE-802.3",
    OUI_MED: "LLDP-MED",
}

# Fixed total TLV lengths (including the 3 OUI + 1 subtype bytes) for the
# org-specific subtypes whose length the standard pins. Variable-length
# subtypes are intentionally absent: bounds only, no semantics.
ORG_FIXED_LEN: Dict[Tuple[bytes, int], Tuple[int, ...]] = {
    (OUI_8021, 1): (6,),        # Port VLAN ID
    (OUI_8021, 2): (7,),        # Port and Protocol VLAN ID
    (OUI_8023, 1): (9,),        # MAC/PHY configuration/status
    (OUI_8023, 2): (7, 12),     # Power via MDI (base, or with DLL extensions)
    (OUI_8023, 3): (9,),        # Link Aggregation
    (OUI_8023, 4): (6,),        # Maximum Frame Size
    (OUI_MED, 1): (7,),         # LLDP-MED Capabilities
    (OUI_MED, 2): (8,),         # Network Policy
    (OUI_MED, 4): (7,),         # Extended Power-via-MDI
}

# Spec maxima (802.1AB-2016). The 9-bit TLV length field caps everything at
# 511, so these are the real ceilings a conforming sender respects.
SPEC_MAX_CHASSIS_ID = 255
SPEC_MAX_PORT_ID = 255
SPEC_MAX_STRING = 255        # Port Desc / System Name / System Description
SPEC_MAX_MGMT_ADDR_STRLEN = 31
SPEC_MAX_MGMT_OID_LEN = 128
SPEC_MED_INVENTORY_MAX = 32  # MED inventory strings

# --------------------------------------------------------------------------
# Finding registry
# --------------------------------------------------------------------------

SEVERITIES = ("critical", "high", "medium", "low", "notice")

# code -> (name, severity, group)
FINDINGS: Dict[str, Tuple[str, str, str]] = {
    # --- Class B: version screening (NOTE discipline) --------------------
    "LLDP-020": ("SCREEN_CISCO_LLDP_PARSER", "notice", "screening"),
    "LLDP-021": ("SCREEN_JUNIPER_L2CPD", "notice", "screening"),
    "LLDP-022": ("SCREEN_LLDPD", "notice", "screening"),
    "LLDP-023": ("SCREEN_OPENVSWITCH", "notice", "screening"),
    "LLDP-024": ("SCREEN_SONICWALL_SWS", "notice", "screening"),
    "LLDP-025": ("SCREEN_BELOW_VERSION_FLOOR", "low", "screening"),
    "LLDP-026": ("SCREEN_VERSION_UNPARSEABLE", "notice", "screening"),
    "LLDP-027": ("SCREEN_ARUBA_LLDP", "notice", "screening"),
    "LLDP-028": ("SCREEN_RUCKUS_LLDP", "notice", "screening"),
    "LLDP-029": ("SCREEN_FORTISWITCH_LLDPMEDD", "notice", "screening"),
    "LLDP-030": ("SCREEN_PANOS_LLDP", "notice", "screening"),
    # --- Class A: structural / attack-in-flight ---------------------------
    "LLDP-040": ("TLV_LENGTH_OVERRUN", "critical", "structural"),
    "LLDP-041": ("TLV_LENGTH_ILLEGAL", "high", "structural"),
    "LLDP-042": ("MANDATORY_TLV_MISSING", "high", "structural"),
    "LLDP-043": ("MANDATORY_TLV_OUT_OF_ORDER", "high", "structural"),
    "LLDP-044": ("TLV_DUPLICATED", "medium", "structural"),
    "LLDP-045": ("MGMT_ADDR_TLV_MALFORMED", "critical", "structural"),
    "LLDP-046": ("CHASSIS_ID_MALFORMED", "high", "structural"),
    "LLDP-047": ("PORT_ID_MALFORMED", "high", "structural"),
    "LLDP-050": ("OVERSIZED_STRING_TLV", "high", "structural"),
    "LLDP-051": ("ORG_SPECIFIC_TLV_MALFORMED", "high", "structural"),
    "LLDP-052": ("RESERVED_TLV_TYPE", "medium", "structural"),
    "LLDP-053": ("TRAILING_DATA_AFTER_END", "medium", "structural"),
    "LLDP-054": ("END_TLV_MISSING", "low", "structural"),
    # --- Class C: abuse ----------------------------------------------------
    "LLDP-048": ("LLDP_FLOOD", "high", "abuse"),
    "LLDP-049": ("FORGED_NEIGHBOUR_INJECTION", "high", "abuse"),
}

GROUP_ORDER = ("screening", "structural", "abuse")

# --------------------------------------------------------------------------
# Class B: vulnerable-family screening table
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Family:
    key: str
    code: str
    label: str
    pattern: str
    cves: Tuple[str, ...]
    note: str


BUILTIN_FAMILIES: Tuple[Family, ...] = (
    Family(
        key="cisco",
        code="LLDP-020",
        label="Cisco IOS / IOS-XE / NX-OS / FXOS",
        pattern=r"(?i)\b(cisco\s+(ios[- ]?xe|ios|nx-?os|fxos)|nexus\s*\d|catalyst\b)",
        cves=("CVE-2018-0395", "CVE-2021-34703", "CVE-2023-20089",
              "CVE-2024-20294", "CVE-2026-20010"),
        note=(
            "Cisco LLDP message-parser defects: TLV-header input validation "
            "across FXOS/NX-OS/MDS/Nexus/UCS, improper buffer initialisation "
            "(IOS/IOS-XE), Nexus 9000 ACI-mode memory leak, incorrect-length "
            "field handling, and an LLDP-process restart that reloads the "
            "device. All adjacent, unauthenticated, DoS."
        ),
    ),
    Family(
        key="juniper",
        code="LLDP-021",
        label="Juniper Junos / Junos Evolved (l2cpd)",
        pattern=r"(?i)\b(junos(\s+(os|evolved))?|juniper\s+networks)\b",
        cves=(
            "CVE-2018-0007",
            "CVE-2020-1641",
            "CVE-2021-0277",
            "CVE-2023-36849",
            "CVE-2024-21618",
        ),
        note=(
            "Juniper l2cpd LLDP parsing defects (boundary check, race, OOB read, "
            "past-end memory access). BLAST RADIUS: l2cpd also drives "
            "STP/RSTP/MSTP/VSTP, MVRP, ERP and LACP, so an l2cpd crash reinitialises "
            "spanning tree and flaps aggregation — not contained to LLDP."
        ),
    ),
    Family(
        key="lldpd",
        code="LLDP-022",
        label="lldpd open-source daemon",
        pattern=r"(?i)\blldpd\b",
        cves=("CVE-2015-8011", "CVE-2015-8012", "CVE-2020-27827"),
        note=(
            "lldpd lldp_decode buffer overflow via oversized Management Address / "
            "TLV boundaries (< 0.8.0, DoS with RCE potential), assertion-failure "
            "crash (< 0.8.0), and an optional-TLV memory leak (1.0.8)."
        ),
    ),
    Family(
        key="openvswitch",
        code="LLDP-023",
        label="Open vSwitch",
        pattern=r"(?i)\bopen\s*vswitch\b|\bovs\s+\d",
        cves=("CVE-2020-27827", "CVE-2022-4337", "CVE-2022-4338"),
        note=(
            "Open vSwitch 2.6.x-2.14.x shares the lldpd optional-TLV memory-leak "
            "DoS, whose signal is a sustained stream rather than a single frame "
            "(see LLDP-048). Separately CVE-2022-4337 (out-of-bounds read) and "
            "CVE-2022-4338 (integer underflow, 9.8) both sit in Organizationally "
            "Specific TLV parsing, reached through a malformed Auto Attach TLV "
            "— a single-frame structural defect LLDP-051 catches directly."
        ),
    ),
    Family(
        key="aruba",
        code="LLDP-027",
        label="HPE Aruba AOS-CX / Instant",
        # A JL part number alone is NOT a usable marker: the same JL prefix
        # covers ProCurve-lineage ArubaOS-Switch gear (2930F, 3810, 5400),
        # which these CVEs do not touch, and an AOS-CX advert leads with the
        # part number rather than the model. So the generic branch requires
        # BOTH the word Aruba and a CX-series model number in the same advert.
        pattern=(
            r"(?i)(?:\barubaos[- ](?:cx|instant)\b|\baos-cx\b|\binstantos\b"
            r"|\bscalance\s*w1750\b|\baruba\s+instant\b|\baruba\s+ap[- ]?\d+\b"
            r"|\baruba\b(?=.*\b(?:62|63|64|83|84)\d\d[a-z]?\b))"
        ),
        cves=("CVE-2020-7121", "CVE-2021-34618"),
        note=(
            "ArubaOS-CX LLDP memory corruption on CX 6200/6300/6400/8320/8325/"
            "8400 (crash, possibly remote code execution), and an "
            "unauthenticated adjacent LLDP denial of service on Aruba Instant "
            "APs. Siemens SCALANCE W1750D is an OEM Aruba Instant AP and "
            "carries the same exposure."
        ),
    ),
    Family(
        key="ruckus",
        code="LLDP-028",
        label="Ruckus access points (lldpd-derived)",
        pattern=r"(?i)\b(ruckus|zonedirector|smartzone|unleashed)\b",
        cves=("CVE-2015-8011", "CVE-2015-8012"),
        note=(
            "Ruckus APs ship an lldpd-derived stack and inherit the lldpd "
            "lldp_decode overflow and assertion-failure crash. The advert says "
            "Ruckus, not lldpd, so the lldpd rule (LLDP-022) does not match "
            "these devices — this entry exists so they are not missed."
        ),
    ),
    Family(
        key="fortiswitch",
        code="LLDP-029",
        label="Fortinet FortiSwitch",
        pattern=r"(?i)\bfortiswitch\b",
        cves=("CVE-2021-26111",),
        note=(
            "Memory leak in the FortiSwitch lldpmedd daemon: crafted adjacent "
            "discovery frames exhaust memory. Like the lldpd/OVS and Nexus "
            "leaks the signal is a sustained stream rather than a single frame, "
            "so this leans on LLDP-048."
        ),
    ),
    Family(
        key="panos",
        code="LLDP-030",
        label="Palo Alto Networks PAN-OS",
        pattern=r"(?i)\b(pan-?os|palo\s*alto)\b",
        cves=("CVE-2025-0116",),
        note=(
            "A crafted LLDP frame reboots the firewall; repeated attempts drive "
            "it into maintenance mode. Applies only where LLDP is enabled "
            "globally and on an interface whose profile is transmit-receive or "
            "receive-only."
        ),
    ),
    Family(
        key="sonicwall",
        code="LLDP-024",
        label="SonicWall SWS switches",
        pattern=r"(?i)\bsonicwall\b|\bsws\d{3}\b",
        cves=("CVE-2021-20024",),
        note=(
            "SonicWall SWS LLDP multiple out-of-bounds reads: information "
            "disclosure plus instability, adjacent and unauthenticated "
            "(SNWLID-2021-0011)."
        ),
    ),
)

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def _default_families() -> Dict[str, Dict[str, Any]]:
    return {}


@dataclass
class Config:
    # capture
    iface: str = "eth0"
    allow_fcs_tail: bool = True

    # Class A thresholds
    max_chassis_id: int = SPEC_MAX_CHASSIS_ID
    max_port_id: int = SPEC_MAX_PORT_ID
    max_port_desc: int = SPEC_MAX_STRING
    max_system_name: int = SPEC_MAX_STRING
    max_system_desc: int = SPEC_MAX_STRING
    max_mgmt_addr_strlen: int = SPEC_MAX_MGMT_ADDR_STRLEN
    max_mgmt_oid_len: int = SPEC_MAX_MGMT_OID_LEN
    max_med_inventory: int = SPEC_MED_INVENTORY_MAX

    # Class C
    flood_window: float = 10.0
    flood_threshold: int = 20
    flood_distinct_src: int = 12
    neigh_max: int = 1024
    enforce: bool = False
    baseline: Tuple[str, ...] = ()

    # Class B
    version_floors: Dict[str, str] = field(default_factory=dict)
    extra_families: Dict[str, Dict[str, Any]] = field(default_factory=_default_families)

    # alerting
    suppress_window: float = 60.0
    disabled_codes: Tuple[str, ...] = ()

    # ---- (de)serialisation -------------------------------------------------
    def dump(self) -> Dict[str, Any]:
        return {
            "iface": self.iface,
            "allow_fcs_tail": self.allow_fcs_tail,
            "max_chassis_id": self.max_chassis_id,
            "max_port_id": self.max_port_id,
            "max_port_desc": self.max_port_desc,
            "max_system_name": self.max_system_name,
            "max_system_desc": self.max_system_desc,
            "max_mgmt_addr_strlen": self.max_mgmt_addr_strlen,
            "max_mgmt_oid_len": self.max_mgmt_oid_len,
            "max_med_inventory": self.max_med_inventory,
            "flood_window": self.flood_window,
            "flood_threshold": self.flood_threshold,
            "flood_distinct_src": self.flood_distinct_src,
            "neigh_max": self.neigh_max,
            "enforce": self.enforce,
            "baseline": list(self.baseline),
            "version_floors": dict(self.version_floors),
            "extra_families": dict(self.extra_families),
            "suppress_window": self.suppress_window,
            "disabled_codes": list(self.disabled_codes),
        }

    @classmethod
    def load(cls, data: Dict[str, Any]) -> "Config":
        """Strict load: unknown keys, bad types, bad regexes and unknown codes
        are rejected AT LOAD TIME, not on the first frame."""
        import re as _re

        if not isinstance(data, dict):
            raise ValueError("config must be a JSON object")
        known = set(cls().dump().keys())
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(
                "unknown config key(s): %s (known: %s)"
                % (", ".join(unknown), ", ".join(sorted(known)))
            )
        cfg = cls()
        ints = (
            "max_chassis_id",
            "max_port_id",
            "max_port_desc",
            "max_system_name",
            "max_system_desc",
            "max_mgmt_addr_strlen",
            "max_mgmt_oid_len",
            "max_med_inventory",
            "flood_threshold",
            "flood_distinct_src",
            "neigh_max",
        )
        floats = ("flood_window", "suppress_window")
        bools = ("allow_fcs_tail", "enforce")
        for k in ints:
            if k in data:
                v = data[k]
                if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                    raise ValueError("%s must be a positive integer" % k)
                setattr(cfg, k, v)
        for k in floats:
            if k in data:
                v = data[k]
                if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
                    raise ValueError("%s must be a positive number" % k)
                setattr(cfg, k, float(v))
        for k in bools:
            if k in data:
                if not isinstance(data[k], bool):
                    raise ValueError("%s must be a boolean" % k)
                setattr(cfg, k, data[k])
        if "iface" in data:
            if not isinstance(data["iface"], str) or not data["iface"]:
                raise ValueError("iface must be a non-empty string")
            cfg.iface = data["iface"]
        if "baseline" in data:
            v = data["baseline"]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError("baseline must be a list of MAC strings")
            cfg.baseline = tuple(normalise_mac(x) for x in v)
        if "disabled_codes" in data:
            v = data["disabled_codes"]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError("disabled_codes must be a list of strings")
            bad = sorted(set(v) - set(FINDINGS))
            if bad:
                raise ValueError("unknown finding code(s): %s" % ", ".join(bad))
            cfg.disabled_codes = tuple(v)
        if "version_floors" in data:
            v = data["version_floors"]
            if not isinstance(v, dict) or not all(
                isinstance(a, str) and isinstance(b, str) for a, b in v.items()
            ):
                raise ValueError("version_floors must be a map of family -> version")
            keys = {f.key for f in BUILTIN_FAMILIES} | set(
                (data.get("extra_families") or {}).keys()
            )
            bad = sorted(set(v) - keys)
            if bad:
                raise ValueError("version_floors names unknown family: %s" % ", ".join(bad))
            cfg.version_floors = dict(v)
        if "extra_families" in data:
            v = data["extra_families"]
            if not isinstance(v, dict):
                raise ValueError("extra_families must be an object")
            builtin_keys = {f.key for f in BUILTIN_FAMILIES}
            cleaned: Dict[str, Dict[str, Any]] = {}
            for key, spec in v.items():
                if key in builtin_keys:
                    raise ValueError(
                        "extra_families may not shadow built-in family %r "
                        "(operator tables EXTEND, never replace)" % key
                    )
                if not isinstance(spec, dict):
                    raise ValueError("extra_families[%r] must be an object" % key)
                spec_keys = set(spec)
                required = {"label", "pattern", "cves"}
                if not required <= spec_keys:
                    raise ValueError(
                        "extra_families[%r] missing %s"
                        % (key, ", ".join(sorted(required - spec_keys)))
                    )
                extra = spec_keys - (required | {"note", "code"})
                if extra:
                    raise ValueError(
                        "extra_families[%r] unknown key(s): %s"
                        % (key, ", ".join(sorted(extra)))
                    )
                try:
                    _re.compile(spec["pattern"])
                except _re.error as exc:
                    raise ValueError(
                        "extra_families[%r] bad regex: %s" % (key, exc)
                    ) from None
                code = spec.get("code", "LLDP-026")
                if code not in FINDINGS:
                    raise ValueError(
                        "extra_families[%r] unknown code %r" % (key, code)
                    )
                if not isinstance(spec["cves"], list) or not all(
                    isinstance(c, str) for c in spec["cves"]
                ):
                    raise ValueError("extra_families[%r] cves must be a list" % key)
                cleaned[key] = dict(spec)
            cfg.extra_families = cleaned
        return cfg


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def normalise_mac(raw: Any) -> str:
    if isinstance(raw, (bytes, bytearray)):
        return ":".join("%02x" % b for b in raw)
    s = str(raw).strip().lower().replace("-", ":")
    if ":" not in s and len(s) == 12:
        s = ":".join(s[i : i + 2] for i in range(0, 12, 2))
    return s


def fmt_ipv4(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def fmt_ipv6(b: bytes) -> str:
    """RFC 5952 canonical form, computed locally (no socket import).

    TOTAL on its input: a non-16-octet buffer raises ValueError rather than
    indexing off the end. Found by a conformance mutation — the caller gates
    on the address-family length table, so a single wrong constant there was
    enough to turn a crafted frame into an uncaught IndexError on the live
    capture path. A formatter reached from attacker-controlled bytes does not
    get to trust its caller.
    """
    if len(b) != 16:
        raise ValueError("IPv6 address must be 16 octets, got %d" % len(b))
    groups = [(b[i] << 8) | b[i + 1] for i in range(0, 16, 2)]
    best_start = best_len = -1
    cur_start = -1
    cur_len = 0
    for i, g in enumerate(groups + [1]):
        if i < 16 and g == 0:
            if cur_start < 0:
                cur_start = i
                cur_len = 0
            cur_len += 1
        else:
            if cur_start >= 0 and cur_len > best_len and cur_len > 1:
                best_start, best_len = cur_start, cur_len
            cur_start, cur_len = -1, 0
    parts = ["%x" % g for g in groups]
    if best_start < 0:
        return ":".join(parts)
    head = ":".join(parts[:best_start])
    tail = ":".join(parts[best_start + best_len :])
    return head + "::" + tail


def fmt_endpoint(addr: str, af: int) -> str:
    """RFC 3986 bracket rendering for v6 (suite LESSON AE)."""
    return "[%s]" % addr if af == AF_IPV6 else addr


def printable(b: bytes, limit: int = 120) -> str:
    s = b.decode("utf-8", "replace")
    s = "".join(ch if 32 <= ord(ch) < 127 or ord(ch) > 160 else "." for ch in s)
    return s[:limit]


def version_tuple(s: str) -> Optional[Tuple[int, ...]]:
    import re as _re

    m = _re.search(r"(\d+(?:\.\d+){1,3})", s or "")
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


@dataclass
class TLV:
    type: int
    length: int
    value: bytes
    offset: int


@dataclass
class Frame:
    dst: str
    src: str
    vlans: Tuple[int, ...]
    payload: bytes
    group: Optional[str]


def parse_ethernet(raw: bytes) -> Optional[Frame]:
    """Return a Frame for an LLDP ethertype frame, else None.

    Handles 802.1Q and QinQ stacking. Returns None for anything that is not
    EtherType 0x88CC so the engine never guesses at another protocol's bytes.
    """
    if len(raw) < 14:
        return None
    dst = normalise_mac(raw[0:6])
    src = normalise_mac(raw[6:12])
    off = 12
    vlans: List[int] = []
    while off + 4 <= len(raw):
        et = (raw[off] << 8) | raw[off + 1]
        if et in VLAN_ETHERTYPES:
            vlans.append(((raw[off + 2] << 8) | raw[off + 3]) & 0x0FFF)
            off += 4
            continue
        break
    if off + 2 > len(raw):
        return None
    et = (raw[off] << 8) | raw[off + 1]
    if et != ETHERTYPE_LLDP:
        return None
    return Frame(
        dst=dst,
        src=src,
        vlans=tuple(vlans),
        payload=raw[off + 2 :],
        group=LLDP_GROUP_MACS.get(dst),
    )


@dataclass
class Walk:
    tlvs: List[TLV]
    end_seen: bool
    end_offset: Optional[int]
    tail: bytes
    tail_kind: str  # "none" | "padding" | "fcs" | "data"
    overrun: Optional[Tuple[int, int, int, int]]  # offset, type, declared, available
    truncated_header: Optional[int]  # offset of the stray single byte


def walk_tlvs(buf: bytes, allow_fcs_tail: bool = True) -> Walk:
    """Bounded, padding-aware TLV walk.

    LLDP is EtherType-framed, so unlike CDP there is NO 802.3 length field to
    bound the walk with: the LLDPDU is self-delimiting via End-of-LLDPDU
    (type 0, length 0). The walk therefore runs to the captured end and stops
    at the first End TLV; everything after it is classified as tail.

    The cdpwatch Ethernet-padding false positive is handled here: the kernel
    pads short frames to the 60-byte minimum and some capture paths append the
    4-byte FCS. A short LLDPDU's padding reads as a legal End TLV followed by
    an all-zero tail — silent. A NON-zero tail is smuggled data (LLDP-053).
    """
    tlvs: List[TLV] = []
    overrun = None
    trunc = None
    end_offset = None
    i = 0
    n = len(buf)
    while i < n:
        if n - i < 2:
            trunc = i
            break
        hdr = (buf[i] << 8) | buf[i + 1]
        ttype = (hdr >> 9) & 0x7F
        tlen = hdr & 0x1FF
        avail = n - i - 2
        if tlen > avail:
            overrun = (i, ttype, tlen, avail)
            break
        tlvs.append(TLV(ttype, tlen, buf[i + 2 : i + 2 + tlen], i))
        i += 2 + tlen
        if ttype == TLV_END:
            end_offset = i
            break

    if end_offset is None:
        return Walk(tlvs, False, None, b"", "none", overrun, trunc)

    tail = buf[end_offset:]
    if not tail:
        kind = "none"
    elif all(b == 0 for b in tail):
        kind = "padding"
    elif allow_fcs_tail and len(tail) >= 4 and all(b == 0 for b in tail[:-4]):
        kind = "fcs"
    else:
        kind = "data"
    return Walk(tlvs, True, end_offset, tail, kind, overrun, trunc)


def extract_mgmt_addrs(walk: Walk) -> List[str]:
    """Pull every WELL-FORMED management address out of an LLDPDU.

    Only addresses whose declared family and length agree are returned —
    a malformed one is a finding (LLDP-045), not an address. IPv6 is rendered
    RFC 5952 canonical and RFC 3986 bracketed (suite LESSON AE), so a consumer
    can always split host from any suffix a caller appends.
    """
    out: List[str] = []
    for tlv in walk.tlvs:
        if tlv.type != TLV_MGMT_ADDR or len(tlv.value) < 2:
            continue
        strlen = tlv.value[0]
        if strlen < 2 or 1 + strlen > len(tlv.value):
            continue
        af = tlv.value[1]
        addr = tlv.value[2 : 1 + strlen]
        if AF_LEN.get(af) != len(addr):
            continue
        if af == AF_IPV4 and len(addr) != 4:
            continue
        if af == AF_IPV6 and len(addr) != 16:
            continue
        text = fmt_ipv4(addr) if af == AF_IPV4 else fmt_ipv6(addr)
        out.append(fmt_endpoint(text, af))
    return out


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class Engine:
    def __init__(
        self,
        cfg: Optional[Config] = None,
        emit: Optional[Callable[[Dict[str, Any]], None]] = None,
        learn: bool = False,
    ) -> None:
        import re as _re

        self.cfg = cfg or Config()
        self._emit = emit or (lambda rec: None)
        self.learn = learn
        self.iface = self.cfg.iface
        self.findings: List[Dict[str, Any]] = []
        self.learned: set = set()
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._frame_times: List[float] = []
        self._src_window: List[Tuple[float, str]] = []
        self._neigh: Dict[str, float] = {}
        self._flood_active = False
        self.families: List[Family] = list(BUILTIN_FAMILIES)
        for key, spec in self.cfg.extra_families.items():
            self.families.append(
                Family(
                    key=key,
                    code=spec.get("code", "LLDP-026"),
                    label=spec["label"],
                    pattern=spec["pattern"],
                    cves=tuple(spec["cves"]),
                    note=spec.get("note", ""),
                )
            )
        self._compiled = [(f, _re.compile(f.pattern)) for f in self.families]

    # -- emission ----------------------------------------------------------
    def finding(
        self,
        code: str,
        src: str,
        detail: str,
        ts: Optional[float] = None,
        **extra: Any,
    ) -> Optional[Dict[str, Any]]:
        if code in self.cfg.disabled_codes:
            return None
        if self.learn:
            return None
        name, sev, group = FINDINGS[code]
        now = ts if ts is not None else time.time()
        key = (code, src)
        last = self._last_alert.get(key)
        if last is not None and now - last < self.cfg.suppress_window:
            # Suppressor throttles ALERTS, not detection: the finding is still
            # recorded for counting, just not re-emitted.
            rec = self._record(code, name, sev, group, src, detail, now, extra)
            rec["suppressed"] = True
            return rec
        self._last_alert[key] = now
        rec = self._record(code, name, sev, group, src, detail, now, extra)
        self._emit(rec)
        return rec

    def _record(self, code, name, sev, group, src, detail, now, extra):
        rec: Dict[str, Any] = {
            "ts": round(now, 6),
            "iface": self.iface,
            "module": "lldpwatch",
            "code": code,
            "name": name,
            "severity": sev,
            "group": group,
            "src": src,
            "detail": detail,
        }
        rec.update(extra)
        self.findings.append(rec)
        return rec

    # -- entry point --------------------------------------------------------
    def handle_frame(self, raw: bytes, ts: Optional[float] = None) -> List[Dict[str, Any]]:
        now = ts if ts is not None else time.time()
        before = len(self.findings)
        fr = parse_ethernet(raw)
        if fr is None:
            return []
        if self.learn:
            self.learned.add(fr.src)
        walk = walk_tlvs(fr.payload, self.cfg.allow_fcs_tail)
        mgmt = extract_mgmt_addrs(walk)
        self._abuse(fr, now, mgmt)
        self._structural(fr, walk, now)
        self._screen(fr, walk, now, mgmt)
        return self.findings[before:]

    # -- Class C ------------------------------------------------------------
    def _abuse(self, fr: Frame, now: float, mgmt: Sequence[str] = ()) -> None:
        w = self.cfg.flood_window
        self._frame_times.append(now)
        self._frame_times = [t for t in self._frame_times if now - t <= w]
        self._src_window.append((now, fr.src))
        self._src_window = [(t, s) for (t, s) in self._src_window if now - t <= w]
        distinct = len({s for _, s in self._src_window})

        rate_hit = len(self._frame_times) > self.cfg.flood_threshold
        src_hit = distinct > self.cfg.flood_distinct_src
        if rate_hit or src_hit:
            if not self._flood_active:
                self._flood_active = True
            reason = []
            if rate_hit:
                reason.append(
                    "%d frames in %.1fs (threshold %d)"
                    % (len(self._frame_times), w, self.cfg.flood_threshold)
                )
            if src_hit:
                reason.append(
                    "%d distinct source MACs in %.1fs (threshold %d)"
                    % (distinct, w, self.cfg.flood_distinct_src)
                )
            self.finding(
                "LLDP-048",
                fr.src,
                "LLDP flood / neighbour-table exhaustion pressure: "
                + "; ".join(reason)
                + ". This is the sustained-stream shape behind CVE-2020-27827 "
                "(lldpd/OVS optional-TLV leak) and CVE-2023-20089 (Nexus 9000 "
                "ACI memory leak) — neither has a crisp single-frame signature.",
                ts=now,
                frames_in_window=len(self._frame_times),
                distinct_sources=distinct,
            )
        else:
            self._flood_active = False

        if len(self._neigh) >= self.cfg.neigh_max and fr.src not in self._neigh:
            oldest = min(self._neigh, key=lambda k: self._neigh[k])
            del self._neigh[oldest]
        self._neigh[fr.src] = now

        if self.cfg.enforce and not self.learn:
            if fr.src not in set(self.cfg.baseline):
                self.finding(
                    "LLDP-049",
                    fr.src,
                    "LLDP advertisement from a source MAC absent from the "
                    "operator baseline. This is the injection vector used by the "
                    "Cisco/Juniper adjacent-crafted-frame CVEs and by neighbour "
                    "spoofing. Baseline-dependent: enforce mode only."
                    + (" Advertised management address(es): %s." % ", ".join(mgmt)
                       if mgmt else ""),
                    ts=now,
                    mgmt_addrs=list(mgmt),
                )

    # -- Class A ------------------------------------------------------------
    def _structural(self, fr: Frame, walk: Walk, now: float) -> None:
        cfg = self.cfg
        if walk.overrun is not None:
            off, ttype, declared, avail = walk.overrun
            self.finding(
                "LLDP-040",
                fr.src,
                "TLV at offset %d (type %d / %s) declares length %d but only %d "
                "octets remain in the frame. Declared-length-exceeds-buffer is the "
                "structural shape behind CVE-2015-8011, CVE-2021-20024, "
                "CVE-2024-20294, CVE-2021-0277 and CVE-2024-21618."
                % (off, ttype, TLV_NAMES.get(ttype, "reserved"), declared, avail),
                ts=now,
                tlv_type=ttype,
                tlv_offset=off,
                declared_length=declared,
                available=avail,
            )
        if walk.truncated_header is not None:
            self.finding(
                "LLDP-041",
                fr.src,
                "Single stray octet at offset %d: an LLDP TLV header is 2 octets "
                "(7-bit type + 9-bit length), so the LLDPDU cannot be walked to a "
                "clean end." % walk.truncated_header,
                ts=now,
                tlv_offset=walk.truncated_header,
            )

        types_seen: List[int] = []
        for tlv in walk.tlvs:
            types_seen.append(tlv.type)
            self._check_tlv(fr, tlv, now)

        self._check_grammar(fr, walk, types_seen, now)

        if walk.end_seen and walk.tail_kind == "data":
            self.finding(
                "LLDP-053",
                fr.src,
                "%d octets of non-zero data follow End-of-LLDPDU at offset %d. "
                "A length-respecting parser stops at End, so this is where data "
                "is smuggled past one. (All-zero tails are Ethernet padding and "
                "are silent; a trailing 4-octet FCS is tolerated when "
                "allow_fcs_tail is set.)" % (len(walk.tail), walk.end_offset),
                ts=now,
                tail_len=len(walk.tail),
                tail_hex=walk.tail[:32].hex(),
            )
        if not walk.end_seen and walk.overrun is None and walk.truncated_header is None:
            self.finding(
                "LLDP-054",
                fr.src,
                "LLDPDU ran to the captured end with no End-of-LLDPDU TLV. "
                "Tolerated by permissive parsers, but it removes the only "
                "self-delimiter the protocol has.",
                ts=now,
            )

    def _check_tlv(self, fr: Frame, tlv: TLV, now: float) -> None:
        cfg = self.cfg
        t, ln, v = tlv.type, tlv.length, tlv.value

        if t == TLV_END:
            if ln != 0:
                self.finding(
                    "LLDP-041",
                    fr.src,
                    "End-of-LLDPDU TLV at offset %d declares length %d; the "
                    "standard fixes it at 0." % (tlv.offset, ln),
                    ts=now,
                    tlv_type=t,
                    tlv_offset=tlv.offset,
                )
            return

        if t == TLV_TTL:
            if ln != 2:
                self.finding(
                    "LLDP-041",
                    fr.src,
                    "Time To Live TLV at offset %d declares length %d; the "
                    "standard fixes it at 2." % (tlv.offset, ln),
                    ts=now,
                    tlv_type=t,
                    tlv_offset=tlv.offset,
                )
            return

        if t == TLV_SYS_CAP:
            if ln != 4:
                self.finding(
                    "LLDP-041",
                    fr.src,
                    "System Capabilities TLV at offset %d declares length %d; "
                    "the standard fixes it at 4." % (tlv.offset, ln),
                    ts=now,
                    tlv_type=t,
                    tlv_offset=tlv.offset,
                )
            return

        if t == TLV_CHASSIS_ID:
            self._check_id_tlv(
                fr, tlv, now, "LLDP-046", "Chassis ID", CHASSIS_SUBTYPES,
                mac_subtype=4, addr_subtype=5, maxlen=cfg.max_chassis_id,
            )
            return

        if t == TLV_PORT_ID:
            self._check_id_tlv(
                fr, tlv, now, "LLDP-047", "Port ID", PORT_SUBTYPES,
                mac_subtype=3, addr_subtype=4, maxlen=cfg.max_port_id,
            )
            return

        if t in (TLV_PORT_DESC, TLV_SYS_NAME, TLV_SYS_DESC):
            limit = {
                TLV_PORT_DESC: cfg.max_port_desc,
                TLV_SYS_NAME: cfg.max_system_name,
                TLV_SYS_DESC: cfg.max_system_desc,
            }[t]
            if ln > limit:
                self.finding(
                    "LLDP-050",
                    fr.src,
                    "%s TLV at offset %d carries %d octets, over the %d-octet "
                    "ceiling. The 9-bit TLV length field permits up to 511, so an "
                    "over-length string field is reachable on the wire and is the "
                    "classic parser-overflow feed."
                    % (TLV_NAMES[t], tlv.offset, ln, limit),
                    ts=now,
                    tlv_type=t,
                    tlv_offset=tlv.offset,
                    tlv_length=ln,
                    limit=limit,
                )
            return

        if t == TLV_MGMT_ADDR:
            self._check_mgmt_addr(fr, tlv, now)
            return

        if t == TLV_ORG_SPECIFIC:
            self._check_org_specific(fr, tlv, now)
            return

        if t in RESERVED_TLV_RANGE:
            self.finding(
                "LLDP-052",
                fr.src,
                "TLV type %d at offset %d is in the reserved range 9-126. A "
                "conforming sender never emits one; a receiver that dispatches on "
                "type without a range check is exactly the code path these parser "
                "CVEs live in." % (t, tlv.offset),
                ts=now,
                tlv_type=t,
                tlv_offset=tlv.offset,
            )

    def _check_id_tlv(
        self, fr, tlv, now, code, label, subtypes, mac_subtype, addr_subtype, maxlen
    ) -> None:
        t, ln, v = tlv.type, tlv.length, tlv.value
        if ln < 2:
            self.finding(
                code,
                fr.src,
                "%s TLV at offset %d declares length %d; the minimum is 2 "
                "(1 subtype octet plus at least 1 identifier octet)."
                % (label, tlv.offset, ln),
                ts=now,
                tlv_type=t,
                tlv_offset=tlv.offset,
            )
            return
        sub = v[0]
        body = v[1:]
        if sub not in subtypes:
            self.finding(
                code,
                fr.src,
                "%s TLV at offset %d uses subtype %d, which is reserved "
                "(valid: 1-7)." % (label, tlv.offset, sub),
                ts=now,
                tlv_type=t,
                tlv_offset=tlv.offset,
                subtype=sub,
            )
            return
        if ln > maxlen + 1:
            self.finding(
                code,
                fr.src,
                "%s TLV at offset %d carries a %d-octet identifier, over the "
                "%d-octet ceiling." % (label, tlv.offset, len(body), maxlen),
                ts=now,
                tlv_type=t,
                tlv_offset=tlv.offset,
                subtype=sub,
            )
            return
        if sub == mac_subtype and len(body) != 6:
            self.finding(
                code,
                fr.src,
                "%s TLV at offset %d declares subtype %d (MAC address) but "
                "carries %d octets, not 6. Subtype/length disagreement is the "
                "shape a fixed-size copy trusts."
                % (label, tlv.offset, sub, len(body)),
                ts=now,
                tlv_type=t,
                tlv_offset=tlv.offset,
                subtype=sub,
            )
            return
        if sub == addr_subtype:
            if len(body) < 2:
                self.finding(
                    code,
                    fr.src,
                    "%s TLV at offset %d declares subtype %d (network address) "
                    "but carries %d octets; an address family octet plus an "
                    "address is the minimum." % (label, tlv.offset, sub, len(body)),
                    ts=now,
                    tlv_type=t,
                    tlv_offset=tlv.offset,
                    subtype=sub,
                )
                return
            af = body[0]
            expect = AF_LEN.get(af)
            if expect is not None and len(body) - 1 != expect:
                self.finding(
                    code,
                    fr.src,
                    "%s TLV at offset %d declares address family %d (%s, %d "
                    "octets) but carries %d address octets. Dual-stack length "
                    "disagreement — an IPv6-family claim with an IPv4-sized body "
                    "(or the reverse) is a read past the intended bound."
                    % (
                        label,
                        tlv.offset,
                        af,
                        AF_NAME.get(af, "?"),
                        expect,
                        len(body) - 1,
                    ),
                    ts=now,
                    tlv_type=t,
                    tlv_offset=tlv.offset,
                    subtype=sub,
                    af=AF_NAME.get(af, str(af)),
                )

    def _check_mgmt_addr(self, fr: Frame, tlv: TLV, now: float) -> None:
        """Management Address TLV (type 8) — the CVE-2015-8011 surface.

        Layout: addr-string-length | addr-subtype | address |
                iface-numbering-subtype | iface-number(4) | OID-length | OID

        DUAL-STACK: the address family comes from the addr-subtype octet
        (1 = IPv4 / 4 octets, 2 = IPv6 / 16 octets). A length check written
        only for IPv4 would miss an IPv6-encoded overflow, so both expected
        lengths are pinned here.
        """
        cfg = self.cfg
        v = tlv.value
        off = tlv.offset
        if len(v) < 1:
            self.finding(
                "LLDP-045", fr.src,
                "Management Address TLV at offset %d is empty." % off,
                ts=now, tlv_offset=off,
            )
            return
        strlen = v[0]
        if strlen == 0 or strlen > cfg.max_mgmt_addr_strlen:
            self.finding(
                "LLDP-045",
                fr.src,
                "Management Address TLV at offset %d declares an address string "
                "length of %d; the legal range is 1-%d. An oversized management "
                "address is literally the CVE-2015-8011 overflow in lldpd's "
                "lldp_decode()." % (off, strlen, cfg.max_mgmt_addr_strlen),
                ts=now, tlv_offset=off, addr_strlen=strlen,
            )
            return
        if 1 + strlen > len(v):
            self.finding(
                "LLDP-045",
                fr.src,
                "Management Address TLV at offset %d declares an address string "
                "length of %d but only %d octets follow inside the TLV — an "
                "internal overrun that a length-trusting copy walks straight off "
                "the end of." % (off, strlen, len(v) - 1),
                ts=now, tlv_offset=off, addr_strlen=strlen,
            )
            return
        sub = v[1]
        addr = v[2 : 1 + strlen]
        expect = AF_LEN.get(sub)
        if expect is not None and len(addr) != expect:
            self.finding(
                "LLDP-045",
                fr.src,
                "Management Address TLV at offset %d declares address subtype %d "
                "(%s, %d octets) but the declared string length implies %d "
                "address octets. Dual-stack mismatch: an IPv6 subtype with an "
                "IPv4-sized body, or the reverse."
                % (off, sub, AF_NAME.get(sub, "?"), expect, len(addr)),
                ts=now, tlv_offset=off, addr_strlen=strlen,
                af=AF_NAME.get(sub, str(sub)),
            )
            return
        rest = v[1 + strlen :]
        if len(rest) < 6:
            self.finding(
                "LLDP-045",
                fr.src,
                "Management Address TLV at offset %d is truncated after the "
                "address: %d octets remain where 6 are required (interface "
                "numbering subtype, 4-octet interface number, OID length)."
                % (off, len(rest)),
                ts=now, tlv_offset=off,
            )
            return
        oid_len = rest[5]
        if oid_len > cfg.max_mgmt_oid_len:
            self.finding(
                "LLDP-045",
                fr.src,
                "Management Address TLV at offset %d declares a %d-octet object "
                "identifier, over the %d-octet ceiling."
                % (off, oid_len, cfg.max_mgmt_oid_len),
                ts=now, tlv_offset=off, oid_len=oid_len,
            )
            return
        if len(rest) - 6 < oid_len:
            self.finding(
                "LLDP-045",
                fr.src,
                "Management Address TLV at offset %d declares a %d-octet object "
                "identifier but only %d octets remain in the TLV."
                % (off, oid_len, len(rest) - 6),
                ts=now, tlv_offset=off, oid_len=oid_len,
            )

    def _check_org_specific(self, fr: Frame, tlv: TLV, now: float) -> None:
        """Organizationally Specific TLV (127) — BOUNDS ONLY.

        LLDP-MED TLVs are parsed far enough to bounds-check them and no
        further: no voice-VLAN, endpoint-class, location or PoE semantics.
        Those attacks are out of scope by standing rule.
        """
        v = tlv.value
        off = tlv.offset
        if tlv.length < 4:
            self.finding(
                "LLDP-051",
                fr.src,
                "Organizationally Specific TLV at offset %d declares length %d; "
                "the minimum is 4 (3-octet OUI plus a subtype octet)."
                % (off, tlv.length),
                ts=now, tlv_offset=off,
            )
            return
        oui = bytes(v[0:3])
        sub = v[3]
        fixed = ORG_FIXED_LEN.get((oui, sub))
        if fixed is not None and tlv.length not in fixed:
            self.finding(
                "LLDP-051",
                fr.src,
                "Organizationally Specific TLV at offset %d (OUI %s, subtype %d) "
                "declares length %d; the standard fixes it at %s. A subtype whose "
                "length is fixed is read with a fixed-size accessor."
                % (
                    off,
                    OUI_NAMES.get(oui, oui.hex("-")),
                    sub,
                    tlv.length,
                    " or ".join(str(x) for x in fixed),
                ),
                ts=now, tlv_offset=off, oui=oui.hex("-"), subtype=sub,
            )
            return
        if oui == OUI_MED and 5 <= sub <= 11:
            body = v[4:]
            if len(body) > self.cfg.max_med_inventory:
                self.finding(
                    "LLDP-051",
                    fr.src,
                    "LLDP-MED inventory TLV at offset %d (subtype %d) carries %d "
                    "octets, over the %d-octet ceiling."
                    % (off, sub, len(body), self.cfg.max_med_inventory),
                    ts=now, tlv_offset=off, oui=oui.hex("-"), subtype=sub,
                )
        if oui == OUI_MED and sub == 3:
            # Location Identification: 1 location-data-format octet + body.
            if tlv.length < 5:
                self.finding(
                    "LLDP-051",
                    fr.src,
                    "LLDP-MED Location Identification TLV at offset %d declares "
                    "length %d; the minimum is 5." % (off, tlv.length),
                    ts=now, tlv_offset=off, oui=oui.hex("-"), subtype=sub,
                )

    def _check_grammar(self, fr: Frame, walk: Walk, types_seen: List[int], now: float) -> None:
        """First three TLVs MUST be Chassis ID, Port ID, TTL, in that order."""
        if not walk.tlvs:
            return
        body = [t for t in types_seen if t != TLV_END]
        mandatory = (TLV_CHASSIS_ID, TLV_PORT_ID, TLV_TTL)
        missing = [m for m in mandatory if m not in body]
        if missing:
            self.finding(
                "LLDP-042",
                fr.src,
                "LLDPDU omits mandatory TLV(s): %s. 802.1AB requires Chassis ID, "
                "Port ID and TTL in every LLDPDU; a receiver that assumes they "
                "were present dereferences fields it never filled in."
                % ", ".join("%s (type %d)" % (TLV_NAMES[m], m) for m in missing),
                ts=now, missing=[TLV_NAMES[m] for m in missing],
            )
        else:
            if tuple(body[:3]) != mandatory:
                self.finding(
                    "LLDP-043",
                    fr.src,
                    "Mandatory TLVs are present but out of order: the LLDPDU "
                    "opens with types %s where %s is required."
                    % (
                        ", ".join(str(x) for x in body[:3]),
                        ", ".join(str(x) for x in mandatory),
                    ),
                    ts=now, opening_types=list(body[:3]),
                )
        singleton = (
            TLV_CHASSIS_ID, TLV_PORT_ID, TLV_TTL,
            TLV_PORT_DESC, TLV_SYS_NAME, TLV_SYS_DESC, TLV_SYS_CAP,
        )
        dupes = sorted({t for t in singleton if body.count(t) > 1})
        if dupes:
            self.finding(
                "LLDP-044",
                fr.src,
                "TLV type(s) %s appear more than once in a single LLDPDU; the "
                "standard permits at most one of each. Whether a receiver keeps "
                "the first or the last is implementation-defined, which makes a "
                "duplicate a cheap state-confusion primitive."
                % ", ".join("%s (type %d x%d)" % (TLV_NAMES[t], t, body.count(t)) for t in dupes),
                ts=now, duplicated=[TLV_NAMES[t] for t in dupes],
            )

    # -- Class B ------------------------------------------------------------
    def _screen(self, fr: Frame, walk: Walk, now: float,
                mgmt: Sequence[str] = ()) -> None:
        text_parts: List[str] = []
        for tlv in walk.tlvs:
            if tlv.type in (TLV_SYS_NAME, TLV_SYS_DESC):
                text_parts.append(printable(tlv.value, 400))
        if not text_parts:
            return
        blob = " | ".join(text_parts)
        for fam, rx in self._compiled:
            if not rx.search(blob):
                continue
            floor = self.cfg.version_floors.get(fam.key)
            ver = version_tuple(blob)
            extra: Dict[str, Any] = {
                "family": fam.key,
                "cves": list(fam.cves),
                "advert": blob[:200],
                "mgmt_addrs": list(mgmt),
            }
            self.finding(
                fam.code,
                fr.src,
                "Neighbour advertises %s in cleartext. VERIFY THIS DEVICE against "
                "%s. %s This is a screening note, not a vulnerability verdict: the "
                "advertised string cannot establish patch state, because vendors "
                "and distributions routinely backport without changing it."
                % (fam.label, ", ".join(fam.cves), fam.note),
                ts=now, **extra,
            )
            if floor:
                fl = version_tuple(floor)
                if ver is None or fl is None:
                    self.finding(
                        "LLDP-026",
                        fr.src,
                        "No parseable version in the %s advertisement %r, so the "
                        "configured floor %r could not be applied."
                        % (fam.label, blob[:120], floor),
                        ts=now, family=fam.key,
                    )
                elif ver < fl:
                    self.finding(
                        "LLDP-025",
                        fr.src,
                        "Advertised %s version %s is below the operator-configured "
                        "floor %s. Coarse hint only — the advertised string is not "
                        "patch state."
                        % (fam.label, ".".join(str(x) for x in ver), floor),
                        ts=now, family=fam.key,
                        advertised=".".join(str(x) for x in ver), floor=floor,
                    )

    # -- baseline ------------------------------------------------------------
    def baseline_lines(self) -> List[str]:
        return sorted(self.learned)


# --------------------------------------------------------------------------
# Live capture (the ONE function that imports scapy)
# --------------------------------------------------------------------------


def _run_live(
    iface: str,
    engine: "Engine",
    timeout: Optional[float] = None,
    sniff_fn: Optional[Callable[..., Any]] = None,
) -> None:
    if sniff_fn is None:  # pragma: no cover - exercised by the scapy xcheck tier
        from scapy.all import sniff as sniff_fn  # type: ignore

    def _cb(pkt: Any) -> None:
        try:
            raw = bytes(pkt)
        except Exception:
            return
        ts = float(getattr(pkt, "time", 0.0)) or time.time()
        engine.handle_frame(raw, ts=ts)

    kwargs: Dict[str, Any] = {
        "iface": iface,
        "filter": BPF_FILTER,
        "prn": _cb,
        "store": False,
    }
    if timeout is not None:
        kwargs["timeout"] = timeout
    sniff_fn(**kwargs)


# --------------------------------------------------------------------------
# AST transmit guard
# --------------------------------------------------------------------------

BANNED_BARE_CALLS = {
    "send", "sendp", "sendto", "sendmsg", "pcap_sendpacket", "inject",
    "srp", "srp1", "sr", "sr1", "sendpfast",
}
BANNED_ATTR_CALLS = {
    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
    ("subprocess", "check_output"), ("os", "system"), ("os", "popen"),
    ("os", "execv"), ("socket", "socket"),
}
# Transmit METHODS reached through any receiver (sock.sendto, s.sendall).
# The bare-Name set above cannot see these; the conformance tier's bite list
# found the gap. Receivers known to be safe go in ALLOWED_ATTR_RECEIVERS.
BANNED_ATTR_METHODS = {
    "send", "sendp", "sendto", "sendmsg", "sendall", "sendfile",
    "pcap_sendpacket", "inject", "sendpfast", "srp", "sr1",
}
ALLOWED_ATTR_RECEIVERS: set = set()
BANNED_DEFINED = {
    "build_lldp_exploit", "craft_lldp_attack", "overflow_payload",
    "build_shellcode", "weaponize", "pwn", "exploit", "send_frame",
    "transmit", "inject_frame",
}
MODULE_SCOPE_BANNED_IMPORTS = {"socket", "subprocess", "scapy"}


def audit_source(src: str, filename: str = "<src>") -> List[str]:
    """Return a list of passive-invariant violations. Empty list == clean.

    Split by AST SHAPE, not by name (suite LESSON D): bare Name calls are
    checked against one set, Attribute calls against another, so the guard's
    own banned-identifier strings cannot trip it.
    """
    problems: List[str] = []
    tree = ast.parse(src, filename=filename)

    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in MODULE_SCOPE_BANNED_IMPORTS:
                    problems.append("module-scope import of %s" % root)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in MODULE_SCOPE_BANNED_IMPORTS:
                problems.append("module-scope from-import of %s" % root)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in BANNED_BARE_CALLS:
                problems.append("transmit call %s() at line %d" % (f.id, node.lineno))
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                pair = (f.value.id, f.attr)
                if pair in BANNED_ATTR_CALLS:
                    problems.append(
                        "banned call %s.%s() at line %d" % (pair[0], pair[1], node.lineno)
                    )
            if isinstance(f, ast.Attribute) and f.attr in BANNED_ATTR_METHODS:
                recv = f.value.id if isinstance(f.value, ast.Name) else None
                if recv not in ALLOWED_ATTR_RECEIVERS:
                    problems.append(
                        "transmit method .%s() at line %d" % (f.attr, node.lineno)
                    )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in BANNED_DEFINED:
                problems.append("exploit/transmit builder defined: %s" % node.name)
        if isinstance(node, ast.ClassDef) and node.name in BANNED_DEFINED:
            problems.append("exploit/transmit builder defined: %s" % node.name)

    # module-level duplicate definition guard (suite LESSON G)
    seen: Dict[str, int] = {}
    for node in tree.body:
        name = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
        if name:
            if name in seen:
                problems.append(
                    "module-level name %r defined twice (lines %d and %d)"
                    % (name, seen[name], node.lineno)
                )
            seen[name] = node.lineno
    return problems


def declared_codes(src: str) -> List[str]:
    """Extract every finding code the engine can emit, resolving literal,
    assignment and loop-unpacking forms (suite LESSON M)."""
    tree = ast.parse(src)
    codes: set = set()
    consts: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if isinstance(tgt, ast.Name) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str) and node.value.value.startswith("LLDP-"):
                    consts[tgt.id] = node.value.value
            if isinstance(tgt, ast.Name) and isinstance(node.value, ast.IfExp):
                for br in (node.value.body, node.value.orelse):
                    if isinstance(br, ast.Constant) and isinstance(br.value, str):
                        if br.value.startswith("LLDP-"):
                            codes.add(br.value)
        if isinstance(node, ast.For) and isinstance(node.iter, (ast.Tuple, ast.List)):
            for elt in node.iter.elts:
                if isinstance(elt, (ast.Tuple, ast.List)):
                    for sub in elt.elts:
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            if sub.value.startswith("LLDP-"):
                                codes.add(sub.value)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if name != "finding" or not node.args:
                continue
            a0 = node.args[0]
            if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                codes.add(a0.value)
            elif isinstance(a0, ast.Name) and a0.id in consts:
                codes.add(consts[a0.id])
            elif isinstance(a0, ast.Attribute) and a0.attr == "code":
                # family-driven screening codes
                codes.update(fam.code for fam in BUILTIN_FAMILIES)

    # LESSON M, FOURTH SHAPE (found by this extractor on its own first run):
    # LLDP-046/047 are passed into the shared _check_id_tlv() helper as a
    # PARAMETER from the call site, so neither the literal-first-arg rule nor
    # module-const resolution sees them. Sweep every call argument for a
    # well-formed code literal as well.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for a in list(node.args) + [kw.value for kw in node.keywords]:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    if re.fullmatch(r"LLDP-\d{3}", a.value):
                        codes.add(a.value)
    return sorted(c for c in codes if c in FINDINGS)


def config_keys_read(src: str) -> set:
    """Every cfg.<key> / self.cfg.<key> attribute actually read by the engine.
    Backs the dead-knob check."""
    tree = ast.parse(src)
    out: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute):
            if node.value.attr == "cfg":
                out.add(node.attr)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "cfg":
                out.add(node.attr)
    return out


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

NOOP_FLAGS = {
    "--crack": "lldpwatch never transmits; there is nothing to crack",
    "--inject": "lldpwatch is a receiver only",
    "--spoof": "lldpwatch ships no LLDP transmitter",
}


def _self_test() -> int:
    """Run the offline conformance harness, which drives this module's real
    parser and engine. There is no second, weaker in-file test suite to drift
    away from it."""
    try:
        import lldpwatch_conformance  # type: ignore
    except ImportError:
        sys.stderr.write(
            "lldpwatch_conformance.py not found next to lldpwatch.py\n"
        )
        return 2
    return lldpwatch_conformance.main(["--quiet"])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lldpwatch",
        description="Passive LLDP (IEEE 802.1AB) security monitor. Receive only.",
    )
    p.add_argument("--iface", "-i", default=None, help="capture interface")
    p.add_argument("--config", default=None, help="JSON config file")
    p.add_argument("--dump-config", action="store_true", help="print effective config and exit")
    p.add_argument("--timeout", type=float, default=None, help="stop after N seconds")
    p.add_argument("--learn", action="store_true", help="baseline mode: emit nothing, record source MACs")
    p.add_argument("--baseline-out", default=None, help="write learned baseline here on exit")
    p.add_argument("--enforce", action="store_true", help="enable LLDP-049 against the configured baseline")
    p.add_argument("--self-test", action="store_true", help="run the built-in self-test and exit")
    p.add_argument("--print-codes", action="store_true", help="print the finding registry and exit")
    p.add_argument("--print-bpf", action="store_true", help="print the capture filter and exit")
    p.add_argument("--version", action="version", version="lldpwatch " + __version__)
    for flag, why in NOOP_FLAGS.items():
        p.add_argument(flag, action="store_true", help=why)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.print_bpf:
        print(BPF_FILTER)
        return 0
    if args.print_codes:
        for group in GROUP_ORDER:
            for code, (name, sev, g) in sorted(FINDINGS.items()):
                if g == group:
                    print("%s\t%s\t%s\t%s" % (code, sev, group, name))
        return 0
    if args.self_test:
        return _self_test()

    cfg = Config()
    if args.config:
        with open(args.config, "r", encoding="utf-8") as fh:
            cfg = Config.load(json.load(fh))
    if args.iface:
        cfg.iface = args.iface
    if args.enforce:
        cfg.enforce = True

    if args.dump_config:
        print(json.dumps(cfg.dump(), indent=2, sort_keys=True))
        return 0

    out = sys.stdout

    def emit(rec: Dict[str, Any]) -> None:
        out.write(json.dumps(rec, sort_keys=True) + "\n")
        out.flush()

    engine = Engine(cfg, emit=emit, learn=args.learn)

    stop = {"flag": False}

    def _term(_signo: int, _frame: Any) -> None:
        stop["flag"] = True
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    try:
        _run_live(cfg.iface, engine, timeout=args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        if args.baseline_out:
            tmp = args.baseline_out + ".tmp.%d" % os.getpid()
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {"baseline": engine.baseline_lines()}, indent=2, sort_keys=True
                    )
                    + "\n"
                )
            os.replace(tmp, args.baseline_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
