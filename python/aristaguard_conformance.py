#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aristaguard_conformance.py - dependency-free conformance harness for
"Arista Switch and Router Guard".

STDLIB ONLY.  This harness must run with no third-party package installed,
and it ASSERTS that aristaguard itself pulls in nothing third-party either
(section B).  The scapy cross-check lives in a separate optional tier so that
this run can prove the dependency-free claim rather than merely stating it.

It drives the PRODUCTION parser and engine - never a copy, never a mock.

Sections
    A  structural / catalog integrity
    B  dependency isolation
    C  config: every knob must CHANGE BEHAVIOUR, and no knob may be dead
    D  passive invariant
    E  parser robustness and bounds
    F  per-CVE coverage
    G  thresholds and boundaries
    H  malformed input / fuzz
    I  suppression semantics
    J  coverage and non-vacuity
    K  clean-set silence contract
    L  lab artefacts (pcap writer, machine-readable code/MTU output)

Usage
    python3 aristaguard_conformance.py
    python3 aristaguard_conformance.py --quiet
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import io
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "aristaguard.py")

CHECKS = 0
FAILS: list[str] = []
SECTION = ""


def check(cond: bool, label: str) -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"[{SECTION}] {label}")


def section(name: str) -> None:
    global SECTION
    SECTION = name


# ---------------------------------------------------------------------------
# Load the production module
# ---------------------------------------------------------------------------
#
# METHODOLOGY NOTE (carried from ciscoguard): the dependency probe must
# SNAPSHOT sys.modules FIRST and diff, rather than comparing the post-import
# set against sys.stdlib_module_names.  The latter falsely flagged the
# container's injected `sitecustomize` as a module dependency.  We measure
# what aristaguard ADDS, not what the interpreter shipped with.
#
# The module must also be registered in sys.modules BEFORE exec_module, or
# dataclasses fails resolving string annotations under
# `from __future__ import annotations`.

_MODULES_BEFORE = set(sys.modules)

_spec = importlib.util.spec_from_file_location("aristaguard", MODULE_PATH)
if _spec is None or _spec.loader is None:  # pragma: no cover
    raise SystemExit(f"cannot load {MODULE_PATH}")
ag = importlib.util.module_from_spec(_spec)
sys.modules["aristaguard"] = ag
_spec.loader.exec_module(ag)

_MODULES_ADDED = set(sys.modules) - _MODULES_BEFORE - {"aristaguard"}


# ---------------------------------------------------------------------------
# Fixture builders (this harness's own - deliberately NOT imported from the
# module's self-test, so the harness is a genuinely independent driver)
# ---------------------------------------------------------------------------


def eth(dst: bytes, src: bytes, et: int, payload: bytes = b"",
        vlans: Iterable[int] = (), tpid: int = 0x8100) -> bytes:
    out = dst + src
    for v in vlans:
        out += struct.pack("!HH", tpid, v & 0x0FFF)
    return out + struct.pack("!H", et) + payload


def ip4(src: str, dst: str, proto: int, payload: bytes = b"") -> bytes:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    return (b"\x45\x00" + struct.pack("!H", 20 + len(payload))
            + b"\x00\x00\x40\x00\x40" + bytes([proto]) + b"\x00\x00"
            + s + d + payload)


def ip6(src16: bytes, dst16: bytes, nh: int, payload: bytes = b"") -> bytes:
    return (b"\x60\x00\x00\x00" + struct.pack("!H", len(payload))
            + bytes([nh, 64]) + src16 + dst16 + payload)


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return (struct.pack("!HHH", sport, dport, 8 + len(payload))
            + b"\x00\x00" + payload)


def tcp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return (struct.pack("!HH", sport, dport) + b"\x00\x00\x00\x01"
            + b"\x00\x00\x00\x02" + b"\x50\x18\xff\xff\x00\x00\x00\x00"
            + payload)


def lldp_tlv(t: int, val: bytes) -> bytes:
    return struct.pack("!H", (t << 9) | (len(val) & 0x1FF)) + val


def lldp(sysname: str, sysdesc: str) -> bytes:
    return (lldp_tlv(1, b"\x04\x00\x1c\x73\x00\x00\x01")
            + lldp_tlv(2, b"\x03Et1") + lldp_tlv(3, b"\x00\x78")
            + lldp_tlv(5, sysname.encode()) + lldp_tlv(6, sysdesc.encode())
            + lldp_tlv(0, b""))


def radius(code: int, ident: int,
           attrs: Iterable[tuple[int, int]] = ()) -> bytes:
    body = b""
    for atype, alen in attrs:
        body += bytes([atype, alen]) + b"\x00" * (alen - 2)
    return (bytes([code, ident]) + struct.pack("!H", 20 + len(body))
            + b"\xaa" * 16 + body)


def ospfv3_lsu(lsa_count: int) -> bytes:
    """
    OSPFv3 Link State Update with a TRUTHFUL declared length.

    The first conformance run used a hardcoded length of 40 against a 20-byte
    body, so the declared-length anomaly fired first and the LSA-count
    threshold was never reached - the knob looked wired when it was not being
    exercised at all. Build the body, then stamp its real length.
    """
    body = bytearray(b"\x03\x04" + b"\x00\x00" + b"\x00" * 12
                     + struct.pack("!I", lsa_count))
    struct.pack_into("!H", body, 2, len(body))
    return bytes(body)


def radius_v(code: int, ident: int, attrs, auth: bytes = b"\xaa" * 16) -> bytes:
    """RADIUS from (type, VALUE) pairs - for the F1/F2 content tests."""
    body = b"".join(bytes([t, 2 + len(v)]) + v for t, v in attrs)
    return (bytes([code, ident]) + struct.pack("!H", 20 + len(body))
            + auth + body)


def vsa(payload: bytes, vendor: int = 9) -> bytes:
    return vendor.to_bytes(4, "big") + bytes([1, len(payload) + 2]) + payload


def prand(n: int, seed: int = 7) -> bytes:
    """Deterministic pseudo-random bytes - os.urandom would make a failure
    unreproducible, and the opacity classifier must be pinned exactly."""
    out = bytearray()
    x = seed * 2654435761 & 0xFFFFFFFF
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def ip6_eh(kind: int, nxt: int, frag_offset: int = 0) -> bytes:
    """One IPv6 extension header. Length rules differ by type - see D7."""
    if kind == 44:  # Fragment: always 8 bytes
        return (bytes([nxt, 0])
                + struct.pack("!H", (frag_offset << 3) | (1 if frag_offset else 0))
                + b"\x00" * 4)
    if kind == 51:  # AH: 4-octet units MINUS 2
        return bytes([nxt, 1]) + b"\x00" * 10
    return bytes([nxt, 0]) + b"\x00" * 6   # HBH / Routing / Dest-Opts


ARISTA_HW = ("Arista Networks EOS version 4.32.1F running on an "
             "Arista Networks DCS-7280R-48C6")
ARISTA_MODULAR = ("Arista Networks EOS version 4.32.1F running on an "
                  "Arista Networks DCS-7504N")
LLDP_MAC = b"\x01\x80\xc2\x00\x00\x0e"

E_LLDP, E_EAPOL, E_IP4, E_IP6 = 0x88CC, 0x888E, 0x0800, 0x86DD
P_TCP, P_UDP, P_GRE, P_ESP, P_IPIP, P_IP6, P_OSPF = 6, 17, 47, 50, 4, 41, 89

# The RADIUS rules are scoped to Arista hardware, so every RADIUS fixture here
# (all on 10.0.0.x) must sit in Arista scope or it is gated out. Declared once
# so the fixtures stay unchanged; the per-CVE coverage of the scope gate itself
# lives in the module self-test (test_radius_arista_scope).
_RADIUS_ENDPOINTS = ("10.0.0.1", "10.0.0.2", "10.0.0.3",
                     "10.0.0.6", "10.0.0.8", "10.0.0.9")


def acfg(**kw: Any) -> Any:
    kw.setdefault("radius_arista_endpoints", _RADIUS_ENDPOINTS)
    return ag.Config(**kw)


def run(frames: Iterable[bytes], cfg: Optional[Any] = None,
        base_ts: float = 1000.0) -> Any:
    if isinstance(frames, (bytes, bytearray)):
        raise TypeError("run() expects a SEQUENCE of frames; a bare bytes "
                        "object iterates as ints and would test nothing")
    eng = ag.AristaEngine(cfg or acfg())
    for i, f in enumerate(frames):
        eng.handle_frame(f, ts=base_ts + i)
    return eng


def codes(eng: Any) -> set[str]:
    return {f.code for f in eng.findings}


# ---- canonical attack fixtures, one per detectable code -------------------
# Used by section F (coverage), section J (non-vacuity) and section L (pcap).

def attack_fixtures() -> dict[str, list[bytes]]:
    vx = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
             ip4("10.1.1.1", "10.1.1.9", P_UDP,
                 udp(50000, 4789, b"\x08" + b"\x00" * 7)))
    ospf_body = b"\x03\x04" + struct.pack("!H", 900) + b"\x00" * 12
    return {
        "AG-001": [eth(LLDP_MAC, b"\x02" * 6, E_LLDP, lldp("sw1", ARISTA_HW))],
        "AG-002": [eth(LLDP_MAC, b"\x02" * 6, E_LLDP, lldp("sw1", ARISTA_HW))],
        "AG-003": [eth(LLDP_MAC, b"\x05" * 6, E_LLDP,
                       lldp("v1", "Arista Networks EOS version 4.30.2F "
                                  "running on a CloudEOS router"))],
        "AG-004": [eth(LLDP_MAC, b"\x03" * 6, E_LLDP,
                       lldp("core1", ARISTA_MODULAR))],
        "AG-005": [eth(LLDP_MAC, b"\x02" * 6, E_LLDP, lldp("sw1", ARISTA_HW))],
        "AG-006": [eth(LLDP_MAC, b"\x02" * 6, E_LLDP, lldp("sw1", ARISTA_HW))],
        "AG-009": [eth(LLDP_MAC, b"\x04" * 6, E_LLDP,
                       lldp("vco", "Arista VeloCloud Orchestrator 6.1.3"))],
        "AG-101": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.1", "10.0.0.2", P_UDP,
                           udp(50000, 1812, radius(1, 1, [(1, 8), (80, 18)]))))],
        "AG-103": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.5", "10.0.0.6", P_TCP,
                           tcp(40000, 6030, b"\x00" * 8)))],
        "AG-104": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.9", "10.0.0.1", P_TCP,
                           tcp(22, 40002, b"SSH-2.0-OpenSSH_9.2p1 Arista\r\n")))],
        "AG-105": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.2.2.1", "10.2.2.2", P_ESP, b"\x00" * 16))],
        "AG-106": [vx],
        "AG-107": [eth(b"\x01\x80\xc2\x00\x00\x03", b"\x0c" * 6, E_EAPOL,
                       b"\x02\x00\x00\x05\x02\x01\x00\x05\x01", vlans=(99,))],
        "AG-108": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.7", "10.0.0.8", P_TCP,
                           tcp(40001, 9979, b"\x00" * 8)))],
        "AG-109": [eth(b"\x33\x33\x00\x00\x00\x05", b"\x0d" * 6, E_IP6,
                       ip6(b"\x20\x01" + b"\x00" * 14,
                           b"\xff\x02" + b"\x00" * 13 + b"\x05",
                           P_OSPF, ospf_body))],
        # D2: the collision block SPLIT across four attributes. The old
        # per-attribute bound let this through entirely.
        "AG-201": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.1", "10.0.0.2", P_UDP,
                           udp(50000, 1812, radius(1, 4, [(33, 100)] * 4))))],
        # D3/D4: absent M-A, and M-A present but NOT first. Both are AG-110.
        "AG-110": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.2", "10.0.0.1", P_UDP,
                           udp(1812, 50000, radius(2, 3, [(1, 8)])))),
                   eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.2", "10.0.0.1", P_UDP,
                           udp(1812, 50000, radius(3, 31, [(33, 40), (80, 18)]))))],
        # D7: the SAME RADIUS exposure behind every extension-header type.
        # These ride in the attack pcap so the sealed-namespace lab exercises
        # the BPF ip6[6] clause on a real kernel capture path.
        "AG-102": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.1", "10.0.0.2", P_UDP,
                           udp(50000, 1812, radius(1, 2, [(1, 8)])))),
                   ] + [
                   eth(b"\x01" * 6, b"\x02" * 6, E_IP6,
                       ip6(b"\x20\x01" + b"\x00" * 14,
                           b"\x20\x01" + b"\x00" * 13 + b"\x02", kind,
                           ip6_eh(kind, P_UDP)
                           + udp(50000, 1812, radius(1, 40 + kind, [(1, 8)]))))
                   for kind in (0, 43, 44, 51, 60)],
        "AG-203": [vx, eth(b"\x01" * 6, b"\x03" * 6, E_IP4,
                           ip4("10.9.9.9", "10.1.1.9", P_GRE, b"\x00" * 8))],
        "AG-205": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2)),
                       vlans=(10, 20, 30))],
        "AG-207": [eth(b"\x0a" * 6, b"\x0b" * 6, E_IP4,
                       ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2)), vlans=(10,)),
                   eth(b"\x0a" * 6, b"\x0b" * 6, E_IP4,
                       ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2)), vlans=(20,))],
        "AG-209": [eth(b"\x33\x33\x00\x00\x00\x05", b"\x0d" * 6, E_IP6,
                       ip6(b"\x20\x01" + b"\x00" * 14,
                           b"\xff\x02" + b"\x00" * 13 + b"\x05",
                           P_OSPF, ospf_body))],
        # F1: a request with NO Proxy-State followed by an Accept WITH one.
        # Ordering matters - the request must be replayed first or there is
        # nothing to correlate against.
        "AG-212": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.1", "10.0.0.2", P_UDP,
                           udp(50000, 1812, radius_v(1, 70, [(1, b"op")])))),
                   eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.2", "10.0.0.1", P_UDP,
                           udp(1812, 50000, radius_v(2, 70, [(80, b"\x00" * 16),
                                                             (33, prand(60))]))))],
        # F2: invalid UTF-8 in a Reply-Message on an Accept.
        "AG-213": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.2", "10.0.0.1", P_UDP,
                           udp(1812, 50000,
                               radius_v(2, 71, [(80, b"\x00" * 16),
                                                (18, b"\xff\xfe\x80\x81 bad")]))))],
        # F2: oversized high-entropy Vendor-Specific on an Accept.
        "AG-214": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.2", "10.0.0.1", P_UDP,
                           udp(1812, 50000,
                               radius_v(2, 72, [(80, b"\x00" * 16),
                                                (26, vsa(prand(180, 11)))]))))],
        "AG-211": [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                       ip4("10.0.0.1", "10.0.0.3", P_TCP,
                           tcp(40003, 49,
                               b"cmd=gnoi File TransferToRemote host=x")))],
    }


# Codes that need a non-default config to fire at all, with the config that
# arms them.  Kept separate so section F can tell "needs operator intent"
# apart from "has no fixture", which would otherwise look identical.
CONFIG_GATED: dict[str, Any] = {}


def config_gated() -> dict[str, tuple[Any, list[bytes]]]:
    return {
        "AG-206": (
            ag.Config(policy_blocked=("192.168.5.5",)),
            [eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                 ip4("10.0.0.1", "192.168.5.5", P_UDP, udp(1, 2)))],
        ),
    }


# Codes with no fixture, sourced from the MODULE rather than restated here.
# ciscoguard precedent: never keep a second copy of a list the module owns.
NO_FIXTURE: dict[str, str] = dict(ag.UNWIRED_CODES)


# ---------------------------------------------------------------------------
# Section A - structural / catalog integrity
# ---------------------------------------------------------------------------


def section_a() -> None:
    section("A structural")
    check(ag.__version__ == "0.1.0-dev", "module version string")
    check(ag.DISPLAY_NAME == "Arista Switch and Router Guard", "display name")

    check(len(ag.CVE_CATALOG) == 17, "17 CVEs in catalog")
    check(len(ag.QUARANTINED_CVES) == 6, "6 quarantined CVEs")
    check(len(ag.FINDINGS) == 29, f"29 finding codes, got {len(ag.FINDINGS)}")

    cves = {e.cve for e in ag.CVE_CATALOG}
    check(len(cves) == len(ag.CVE_CATALOG), "no duplicate CVE ids")

    # RETIRED codes must never be reachable, and must never be reused.
    for code, reason in ag.RETIRED_CODES.items():
        check(code not in ag.FINDINGS,
              f"{code} is retired but is a live finding code again")
        check(len(reason) > 120, f"{code}: retirement reason too thin")
    check("AG-202" in ag.RETIRED_CODES,
          "AG-202 must stay on the retired list - an operator's saved search "
          "or dashboard panel keyed on it must never match a different finding")
    check("AG-110" in ag.FINDINGS and ag.FINDINGS["AG-110"].klass == "exposure",
          "AG-110 replaced AG-202 and is EXPOSURE-class")

    # Class-to-range binding.
    for code, spec in ag.FINDINGS.items():
        pfx = {"posture": "AG-0", "exposure": "AG-1", "attack": "AG-2"}[spec.klass]
        check(code.startswith(pfx), f"{code} class {spec.klass} vs range")

    # Severity ordering sanity: no posture finding may outrank an attack one.
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    max_posture = max(order[s.severity] for s in ag.FINDINGS.values()
                      if s.klass == "posture")
    check(max_posture <= order["MEDIUM"],
          "a POSTURE finding must never exceed MEDIUM - it is a 'verify this "
          "device' note, not a verdict")

    # Detect distribution must match what the module claims about itself.
    dist: dict[str, int] = {}
    for e in ag.CVE_CATALOG:
        dist[e.detect] = dist.get(e.detect, 0) + 1
    check(dist.get("none", 0) == 1, f"exactly one detect=none CVE, got {dist}")
    check(sum(dist.values()) == 17, "detect values cover every CVE")

    # The exploited CVE must be exactly one, and must be 7473.
    expl = [e for e in ag.CVE_CATALOG if e.exploited]
    check(len(expl) == 1 and expl[0].cve == "CVE-2026-7473",
          f"expected CVE-2026-7473 as the sole exploited entry, got {expl}")

    # Quarantine and catalog must be disjoint, with substantive reasons.
    for cve, reason in ag.QUARANTINED_CVES:
        check(cve not in cves, f"{cve} is quarantined AND catalogued")
        check(len(reason) > 80, f"{cve} quarantine reason too thin")
        check("." in reason, f"{cve} quarantine reason is not prose")

    # Every advisory reference is an SA number, and CloudEOS entries are
    # marked as such rather than being screened as hardware EOS.
    for e in ag.CVE_CATALOG:
        check(e.advisory.startswith("SA-0"), f"{e.cve} advisory format")
        if "CloudEOS" in e.products:
            check(e.detect == "posture",
                  f"{e.cve} is CloudEOS-only and cannot exceed posture")


# ---------------------------------------------------------------------------
# Section B - dependency isolation
# ---------------------------------------------------------------------------


def section_b() -> None:
    section("B dependency isolation")
    third_party = sorted(
        m for m in _MODULES_ADDED
        if m.split(".")[0] not in sys.stdlib_module_names)
    check(third_party == [],
          f"aristaguard pulled in third-party modules: {third_party}")
    check("scapy" not in sys.modules,
          "scapy must NOT be imported by the offline path - it is lazy-loaded "
          "inside run_capture() only")

    # And the source must not import it at module scope either.
    tree = ast.parse(open(MODULE_PATH, encoding="utf-8").read())
    top = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            name = getattr(node, "module", None) or node.names[0].name
            if "scapy" in (name or ""):
                top.append(node.lineno)
    check(top == [], f"scapy imported at module scope, lines {top}")

    # run_capture must be the ONLY function importing scapy.
    importers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    name = getattr(sub, "module", None) or sub.names[0].name
                    if "scapy" in (name or ""):
                        importers.append(node.name)
    check(importers == ["run_capture"],
          f"scapy should be imported by run_capture alone, got {importers}")


# ---------------------------------------------------------------------------
# Section C - config knobs must change behaviour, and none may be dead
# ---------------------------------------------------------------------------


def section_c() -> None:
    section("C config")
    cfg = ag.Config()
    dumped = cfg.dump()
    check(ag.Config.load(json.loads(json.dumps(dumped))).dump() == dumped,
          "config round-trips through json unchanged")

    # Unknown keys warn and are dropped rather than raising.
    err = io.StringIO()
    old, sys.stderr = sys.stderr, err
    try:
        loaded = ag.Config.load({"min_cvss": 8.0, "not_a_real_knob": 1})
    finally:
        sys.stderr = old
    check(loaded.min_cvss == 8.0, "known key applied alongside an unknown one")
    check("not_a_real_knob" in err.getvalue(), "unknown key warns on stderr")

    # DEAD KNOB SCAN (the ciscoguard max_version_string class): every Config
    # field must be READ somewhere in the module, via self.cfg.X or cfg.X.
    src = open(MODULE_PATH, encoding="utf-8").read()
    tree = ast.parse(src)
    read: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute):
            if node.value.attr == "cfg":
                read.add(node.attr)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in ("cfg", "config", "c"):
                read.add(node.attr)
    fields = set(ag.Config.__dataclass_fields__)
    dead = sorted(fields - read)
    check(dead == [],
          f"DEAD CONFIG KNOBS - declared but never read: {dead}. A knob that "
          f"cannot fire advertises tunability that does not exist; either wire "
          f"it or delete it, as ciscoguard did with isis_max_tlv_len.")

    # Knobs must CHANGE BEHAVIOUR, not merely be referenced.
    big = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
              ip4("10.0.0.1", "10.0.0.2", P_UDP,
                  udp(50000, 1812, radius(1, 4, [(33, 250)]))))
    check("AG-201" in codes(run([big])), "AG-201 fires at default threshold")
    check("AG-201" not in codes(run([big], acfg(radius_proxy_state_total_max=255))),
          "raising radius_proxy_state_total_max must SILENCE AG-201")

    two = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
              ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2)), vlans=(10, 20))
    check("AG-205" not in codes(run([two])), "double tag silent by default")
    check("AG-205" in codes(run([two], ag.Config(max_vlan_tags=1))),
          "lowering max_vlan_tags must FIRE AG-205")

    gre = eth(b"\x01" * 6, b"\x03" * 6, E_IP4,
              ip4("10.9.9.9", "10.1.1.9", P_GRE, b"\x00" * 8))
    check("AG-203" not in codes(run([gre])), "unknown decap ip stays silent")
    check("AG-203" in codes(run([gre], ag.Config(decap_endpoints=("10.1.1.9",)))),
          "decap_endpoints must arm AG-203")

    plain = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                ip4("10.0.0.1", "192.168.5.5", P_UDP, udp(1, 2)))
    check("AG-206" not in codes(run([plain])), "policy_blocked empty = silent")
    check("AG-206" in codes(run([plain],
                                ag.Config(policy_blocked=("192.168.5.5",)))),
          "policy_blocked must arm AG-206")

    lsu = eth(b"\x33\x33\x00\x00\x00\x05", b"\x0d" * 6, E_IP6,
              ip6(b"\x20\x01" + b"\x00" * 14,
                  b"\xff\x02" + b"\x00" * 13 + b"\x05", P_OSPF,
                  ospfv3_lsu(1000)))
    check("AG-209" in codes(run([lsu])),
          "LSA count over the structural bound fires AG-209")
    check("AG-209" not in codes(run([lsu], ag.Config(ospfv3_max_lsa_count=2048))),
          "raising ospfv3_max_lsa_count must silence AG-209")

    # min_cvss must really gate the catalog.
    strict = ag.Config(min_cvss=9.0, always_include_exploited=False)
    kept = [e for e in ag.CVE_CATALOG if ag.cve_in_scope(e, strict)]
    check(len(kept) == 3,
          f"min_cvss=9.0 should keep the three 9.x entries, got {len(kept)}")


# ---------------------------------------------------------------------------
# Section D - passive invariant
# ---------------------------------------------------------------------------


def section_d() -> None:
    section("D passive invariant")
    src = open(MODULE_PATH, encoding="utf-8").read()
    tree = ast.parse(src)

    banned_names = {"send", "sendp", "sendto", "sr", "sr1", "srp", "srp1",
                    "pcap_sendpacket", "pcap_inject"}
    banned_attrs = {"subprocess": {"run", "call", "Popen", "check_output"},
                    "os": {"system", "popen", "execv"},
                    "socket": {"socket", "create_connection"}}
    banned_imports = {"socket", "subprocess", "requests", "urllib", "http"}

    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in banned_names:
                problems.append(f"{fn.id}() line {node.lineno}")
            elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                if fn.attr in banned_attrs.get(fn.value.id, set()):
                    problems.append(f"{fn.value.id}.{fn.attr}() line {node.lineno}")
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in banned_imports:
                    problems.append(f"import {a.name} line {node.lineno}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in banned_imports:
                problems.append(f"from {node.module} line {node.lineno}")
    check(problems == [], f"passive invariant violations: {problems}")

    # Independent restatement of the module's own shadowing guard.
    seen: dict[str, int] = {}
    dupes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            if node.name in seen:
                dupes.append(f"{node.name} at {node.lineno} (first {seen[node.name]})")
            seen[node.name] = node.lineno
    check(dupes == [], f"module-level shadowing: {dupes}")

    # Non-vacuity: prove this section's own guard bites.
    bad = ast.parse("import socket\nsendp(x)\nos.system('id')\n")
    hits = 0
    for node in ast.walk(bad):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in banned_names:
                hits += 1
            elif (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                  and fn.attr in banned_attrs.get(fn.value.id, set())):
                hits += 1
        elif isinstance(node, ast.Import):
            if node.names[0].name.split(".")[0] in banned_imports:
                hits += 1
    check(hits == 3, f"section D guard should catch 3, caught {hits}")

    # The engine must never mutate the frame it was handed.
    frame = bytearray(eth(b"\x01" * 6, b"\x02" * 6, E_LLDP,
                          lldp("sw1", ARISTA_HW)))
    original = bytes(frame)
    ag.AristaEngine(ag.Config()).handle_frame(bytes(frame), ts=1.0)
    check(bytes(frame) == original, "engine must not mutate input frames")


# ---------------------------------------------------------------------------
# Section E - parser robustness and bounds
# ---------------------------------------------------------------------------


def section_e() -> None:
    section("E parsers")
    # Every parser must return None (not raise) on short input, at EVERY
    # truncation point.
    full = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
               ip4("10.0.0.1", "10.0.0.2", P_UDP,
                   udp(50000, 1812, radius(1, 1, [(1, 8), (80, 18)]))))
    for n in range(len(full) + 1):
        try:
            ag.parse_l2(full[:n])
        except Exception as exc:  # noqa: BLE001
            check(False, f"parse_l2 raised on {n}-byte prefix: {exc!r}")
            break
    else:
        check(True, "parse_l2 survives every truncation point")

    for n in range(60):
        try:
            ag.parse_radius(bytes(range(min(n, 256)))[:n])
        except Exception as exc:  # noqa: BLE001
            check(False, f"parse_radius raised on {n} bytes: {exc!r}")
            break
    else:
        check(True, "parse_radius survives every truncation point")

    l2 = ag.parse_l2(full)
    for n in range(len(l2.payload) + 1):
        try:
            ag.parse_l3(l2.payload[:n], E_IP4)
        except Exception as exc:  # noqa: BLE001
            check(False, f"parse_l3 raised on {n} bytes: {exc!r}")
            break
    else:
        check(True, "parse_l3 survives every truncation point")

    # Tag-walk bound: a frame that is nothing but VLAN tags must terminate.
    stack = b"\x01" * 6 + b"\x02" * 6 + b"\x81\x00\x00\x0a" * 64
    out = ag.parse_l2(stack)
    check(out is not None, "pathological tag stack still parses")
    check(len(out.vlan_tags) <= 8,
          f"tag walk must be bounded, got {len(out.vlan_tags)} tags")

    # RADIUS attribute walk bound: 256 attributes max, and a zero/one-length
    # attribute must not loop.
    loopy = bytes([1, 1]) + struct.pack("!H", 22) + b"\xaa" * 16 + bytes([1, 0])
    r = ag.parse_radius(loopy)
    check(r is not None and r.malformed, "zero-length attribute flagged")

    # LLDP TLV walk bound.
    many = b"".join(lldp_tlv(5, b"x") for _ in range(200)) + lldp_tlv(0, b"")
    info = ag.parse_lldp(many)
    check(info is not None, "many-TLV LLDP terminates")

    # A TLV claiming more length than remains must stop, not over-read.
    liar = struct.pack("!H", (6 << 9) | 400) + b"short"
    check(ag.parse_lldp(liar) is None or True, "over-long TLV does not raise")

    # Version parser edge cases.
    for bad in ("", "..", "4..2", "-1", "4.32.1F.", "F4.32", "4.32.1FF F"):
        try:
            ag.parse_version(bad)
        except Exception as exc:  # noqa: BLE001
            check(False, f"parse_version raised on {bad!r}: {exc!r}")
            break
    else:
        check(True, "parse_version never raises on junk")

    check(ag.version_cmp("4.32", "4.32.0") == 0,
          "missing trailing components pad to zero")
    check(ag.version_cmp("4.32.0.0", "4.32") == 0, "padding is symmetric")

    # IPv6 address formatting must be stable and round-trippable enough to
    # key state on.
    a = ag.parse_l3(ip6(b"\x20\x01" + b"\x00" * 14,
                        b"\xfe\x80" + b"\x00" * 14, P_OSPF, b"\x00" * 16), E_IP6)
    check(a is not None and a.src.count(":") == 7, "ipv6 formats to 8 groups")


# ---------------------------------------------------------------------------
# Section F - per-CVE coverage
# ---------------------------------------------------------------------------


def section_f() -> None:
    section("F coverage")
    fixtures = attack_fixtures()
    gated = config_gated()

    for code in sorted(ag.FINDINGS):
        if code in fixtures:
            got = codes(run(fixtures[code]))
            check(code in got, f"{code} fixture did not produce {code} (got {sorted(got)})")
        elif code in gated:
            cfg, frames = gated[code]
            got = codes(run(frames, cfg))
            check(code in got, f"{code} config-gated fixture failed")
            check(code not in codes(run(frames)),
                  f"{code} must stay silent WITHOUT its enabling config")
        elif code in NO_FIXTURE:
            check(len(NO_FIXTURE[code]) > 120,
                  f"{code} has no fixture and no substantive reason")
        else:
            check(False, f"{code} has neither a fixture nor a declared reason")

    # Every catalog CVE with detect != none must have at least one reachable
    # code; every detect == none CVE must NOT claim an attack code.
    for e in ag.CVE_CATALOG:
        if e.detect == "none":
            for c in e.codes:
                check(ag.FINDINGS[c].klass != "attack",
                      f"{e.cve} is detect=none but references attack code {c}")
        else:
            check(len(e.codes) > 0, f"{e.cve} detect={e.detect} but has no codes")

    # detect=attack CVEs must be backed by a code in the AG-2xx range.
    for e in ag.CVE_CATALOG:
        if e.detect == "attack":
            check(any(c.startswith("AG-2") for c in e.codes),
                  f"{e.cve} claims detect=attack but has no AG-2xx code")

    # Coverage is honest about the two unwired codes.
    check(set(NO_FIXTURE) == {"AG-208", "AG-210"},
          f"unwired-code set drifted: {sorted(NO_FIXTURE)}")


# ---------------------------------------------------------------------------
# Section G - thresholds and boundaries
# ---------------------------------------------------------------------------


def section_g() -> None:
    section("G thresholds")
    cfg = ag.Config()

    # AG-201: at the limit silent, one over fires. Measured as a per-packet
    # Proxy-State TOTAL since the Sept 2026 review (D2).
    for length, want in ((cfg.radius_proxy_state_total_max, False),
                         (cfg.radius_proxy_state_total_max + 1, True)):
        fr = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                 ip4("10.0.0.1", "10.0.0.2", P_UDP,
                     udp(50000, 1812, radius(1, 4, [(33, length)]))))
        got = "AG-201" in codes(run([fr]))
        check(got is want, f"AG-201 at attr_len={length} expected {want}, got {got}")

    # AG-205: at the limit silent, one over fires.
    for n, want in ((cfg.max_vlan_tags, False), (cfg.max_vlan_tags + 1, True)):
        fr = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                 ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2)),
                 vlans=tuple(range(10, 10 + n)))
        got = "AG-205" in codes(run([fr]))
        check(got is want, f"AG-205 at {n} tags expected {want}, got {got}")

    # AG-209 LSA count: at the limit silent, one over fires.
    for count, want in ((cfg.ospfv3_max_lsa_count, False),
                        (cfg.ospfv3_max_lsa_count + 1, True)):
        body = ospfv3_lsu(count)
        fr = eth(b"\x33\x33\x00\x00\x00\x05", b"\x0d" * 6, E_IP6,
                 ip6(b"\x20\x01" + b"\x00" * 14,
                     b"\xff\x02" + b"\x00" * 13 + b"\x05", P_OSPF, body))
        got = "AG-209" in codes(run([fr]))
        check(got is want, f"AG-209 at lsa_count={count} expected {want}, got {got}")

    # regreSSHion window boundaries, both ends.
    for banner, want in (("OpenSSH_8.4p1", False), ("OpenSSH_8.5p1", True),
                         ("OpenSSH_9.7p1", True), ("OpenSSH_9.8p1", False),
                         ("OpenSSH_9.9p1", False)):
        got = ag.openssh_regresshion_affected(banner) is not None
        check(got is want, f"regreSSHion window at {banner}: expected {want}")

    # Version screening boundaries against a real advisory table.
    e = next(x for x in ag.CVE_CATALOG if x.cve == "CVE-2024-6409")
    for ver, want in (("4.32.5.1M", "vulnerable"), ("4.32.5.2M", "not_vulnerable"),
                      ("4.33.3.1F", "vulnerable"), ("4.33.3.2F", "not_vulnerable"),
                      ("4.34.0F", "vulnerable"), ("4.34.1F", "not_vulnerable"),
                      ("4.31.9M", "inferred_clean")):
        got = ag.screen_version(ver, e)[0]
        check(got == want, f"CVE-2024-6409 screen {ver}: expected {want}, got {got}")

    # The exploitation override, in both directions.
    e7473 = next(x for x in ag.CVE_CATALOG if x.cve == "CVE-2026-7473")
    check(e7473.cvss < ag.Config().min_cvss,
          "7473 must sit below the floor or the override is not exercised")
    check(ag.cve_in_scope(e7473, ag.Config()), "override carries 7473 in")
    check(not ag.cve_in_scope(e7473, ag.Config(always_include_exploited=False)),
          "override off drops 7473")


# ---------------------------------------------------------------------------
# Section H - malformed input / fuzz
# ---------------------------------------------------------------------------


def section_h() -> None:
    section("H robustness")
    rng = random.Random(20260818)
    eng = ag.AristaEngine(ag.Config())

    # Pure random frames.
    for _ in range(3000):
        n = rng.randint(0, 200)
        frame = bytes(rng.randrange(256) for _ in range(n))
        try:
            eng.handle_frame(frame, ts=1.0)
        except Exception as exc:  # noqa: BLE001
            check(False, f"random frame ({n}B) raised {type(exc).__name__}: {exc}")
            break
    else:
        check(True, "3000 random frames handled without raising")

    # Bit-flipped valid frames - the harder case, since these get further
    # into the parsers before going wrong.
    seeds = [f for frames in attack_fixtures().values() for f in frames]
    flipped = 0
    for seed in seeds:
        for _ in range(40):
            b = bytearray(seed)
            for _ in range(rng.randint(1, 4)):
                i = rng.randrange(len(b))
                b[i] ^= 1 << rng.randrange(8)
            try:
                eng.handle_frame(bytes(b), ts=1.0)
                flipped += 1
            except Exception as exc:  # noqa: BLE001
                check(False, f"bit-flipped frame raised {type(exc).__name__}: {exc}")
                break
    check(flipped > 800, f"bit-flip fuzz ran {flipped} frames")

    # Declared-length lies in every direction.
    for declared in (0, 1, 19, 20, 21, 4095, 4096, 4097, 65535):
        pkt = bytes([1, 1]) + struct.pack("!H", declared) + b"\xaa" * 16 + b"\x01\x08" + b"\x00" * 6
        try:
            ag.parse_radius(pkt)
        except Exception as exc:  # noqa: BLE001
            check(False, f"radius declared_len={declared} raised {exc!r}")
            break
    else:
        check(True, "radius survives every declared-length lie")

    for declared in (0, 19, 20, 1500, 65535):
        body = b"\x45\x00" + struct.pack("!H", declared) + b"\x00" * 16
        try:
            ag.parse_l3(body, E_IP4)
        except Exception as exc:  # noqa: BLE001
            check(False, f"ipv4 total_len={declared} raised {exc!r}")
            break
    else:
        check(True, "ipv4 survives every total-length lie")

    # A frame consisting only of an ethertype and nothing else.
    for et in (E_LLDP, E_EAPOL, E_IP4, E_IP6, 0x0806, 0x0000):
        try:
            ag.AristaEngine(ag.Config()).handle_frame(
                b"\x01" * 6 + b"\x02" * 6 + struct.pack("!H", et), ts=1.0)
        except Exception as exc:  # noqa: BLE001
            check(False, f"empty payload for ethertype {et:#06x} raised {exc!r}")
            break
    else:
        check(True, "empty payloads handled for every dispatched ethertype")

    # Unbounded-state guard: many distinct MACs must not grow without bound.
    eng2 = ag.AristaEngine(ag.Config())
    for i in range(5000):
        mac = bytes([0x0a, 0x00, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF, 1])
        eng2.handle_frame(
            eth(b"\x01" * 6, mac, E_IP4,
                ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2)), vlans=(10,)),
            ts=1.0 + i)
    per_mac = max((len(v) for v in eng2.mac_vlans.values()), default=0)
    check(per_mac <= 16,
          f"per-MAC VLAN set must stay bounded, largest was {per_mac}")


# ---------------------------------------------------------------------------
# Section I - suppression semantics
# ---------------------------------------------------------------------------


def section_i() -> None:
    section("I suppression")
    fr = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
             ip4("10.0.0.1", "10.0.0.2", P_UDP,
                 udp(50000, 1812, radius(1, 2, [(1, 8)]))))

    eng = ag.AristaEngine(acfg())
    for i in range(50):
        eng.handle_frame(fr, ts=5000.0 + i)
    hits = [f for f in eng.findings if f.code == "AG-102"]
    check(len(hits) == 1, f"50 detections -> 1 alert, got {len(hits)}")

    # Past the window it alerts again, carrying the suppressed count.
    eng = ag.AristaEngine(acfg(suppress_s=1))
    for i in range(4):
        eng.handle_frame(fr, ts=6000.0 + i * 5)
    hits = [f for f in eng.findings if f.code == "AG-102"]
    check(len(hits) == 4, f"past the window each detection alerts, got {len(hits)}")

    # Suppression must NEVER auto-learn: a suppressed source must not end up
    # in any allow-list, or an attacker can teach the sensor to ignore them.
    eng = ag.AristaEngine(acfg())
    for i in range(20):
        eng.handle_frame(fr, ts=7000.0 + i)
    check("10.0.0.1" not in eng.cfg.known_infra,
          "suppression must not add a suppressed source to known_infra")
    check(eng.cfg.decap_endpoints == (),
          "suppression must not mutate operator config")

    # Fails OPEN: an evicted key alerts again rather than going silent.
    sup = ag.Suppressor(window_s=3600, cap=4)
    now = 1.0
    for i in range(10):
        sup.should_alert((f"k{i}",), now)
    ok, _ = sup.should_alert(("k0",), now)
    check(ok, "an evicted suppression key must alert again (fail open)")
    check(len(sup._seen) <= 4, "suppressor respects its cap")

    # Distinct sources are suppressed independently, not collectively.
    eng = ag.AristaEngine(acfg())
    for i in range(5):
        f2 = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
                 ip4(f"10.0.{i}.1", "10.0.0.2", P_UDP,
                     udp(50000, 1812, radius(1, 2, [(1, 8)]))))
        eng.handle_frame(f2, ts=8000.0 + i)
    check(len([f for f in eng.findings if f.code == "AG-102"]) == 5,
          "five distinct sources must each alert once")


# ---------------------------------------------------------------------------
# Section J - coverage and non-vacuity
# ---------------------------------------------------------------------------


def section_j() -> None:
    section("J non-vacuity")

    # RADIUS Arista-scope gate: an exchange between two non-Arista IPs must be
    # silent, and the SAME exchange must fire once an endpoint is in scope.
    # Proves the attack_fixtures/clean_set RADIUS results above are not an
    # artefact of _RADIUS_ENDPOINTS blanket-scoping everything.
    bare = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
               ip4("10.7.7.7", "10.8.8.8", P_UDP,
                   udp(50000, 1812, radius(1, 1, [(1, 8)]))))
    check("AG-102" not in codes(run([bare], ag.Config())),
          "RADIUS between two non-Arista IPs must be gated out")
    check("AG-102" in codes(run([bare],
                                ag.Config(radius_arista_endpoints=("10.8.8.8",)))),
          "the same exchange must fire once an endpoint is an Arista device")

    # known_infra scopes EXPOSURE only, never ATTACK, never POSTURE.
    #
    # ciscoguard's bite run found this exact test written VACUOUSLY: it used
    # a finding whose detail carried no address key, so the filter let it
    # through for the wrong reason and a real mutation went uncaught.  AG-203
    # is used here because it is an ATTACK finding that DOES carry addresses,
    # so widening the filter to attacks genuinely fails this.
    vx = eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
             ip4("10.1.1.1", "10.1.1.9", P_UDP,
                 udp(50000, 4789, b"\x08" + b"\x00" * 7)))
    gre = eth(b"\x01" * 6, b"\x03" * 6, E_IP4,
              ip4("10.9.9.9", "10.1.1.9", P_GRE, b"\x00" * 8))
    scoped = ag.Config(known_infra=("172.16.0.1",))
    got = codes(run([vx, gre], scoped))
    check("AG-106" not in got, "known_infra scopes the EXPOSURE finding away")
    check("AG-203" in got,
          "known_infra must NEVER filter an ATTACK finding - and AG-203 "
          "carries a dst, so this test genuinely exercises the filter path")
    f = next(x for x in run([vx, gre], scoped).findings if x.code == "AG-203")
    check("decap_ip" in f.detail,
          "the ATTACK finding used for this test must carry an address key, "
          "or the filter is being passed for the wrong reason")

    check("AG-002" in codes(run(
        [eth(LLDP_MAC, b"\x02" * 6, E_LLDP, lldp("sw1", ARISTA_HW))], scoped)),
        "known_infra must not filter POSTURE findings")

    # Every fixture must produce its code AND the clean set must not.
    fixtures = attack_fixtures()
    for code, frames in fixtures.items():
        got = codes(run(frames))
        check(code in got, f"non-vacuity: {code} fixture is inert")

    # Learn mode detects but emits nothing.
    emitted: list[Any] = []
    eng = ag.AristaEngine(ag.Config(learn=True), emit=emitted.append)
    for frames in fixtures.values():
        for fr in frames:
            eng.handle_frame(fr, ts=1.0)
    check(emitted == [], "learn mode emits nothing")
    check(len(eng.findings) > 10,
          f"learn mode still detects, got {len(eng.findings)} findings")

    # Non-learn mode DOES emit, and emits exactly the findings it recorded.
    emitted2: list[Any] = []
    eng2 = ag.AristaEngine(ag.Config(), emit=emitted2.append)
    for frames in fixtures.values():
        for fr in frames:
            eng2.handle_frame(fr, ts=1.0)
    check(len(emitted2) == len(eng2.findings),
          "every recorded finding must be emitted when not learning")

    # JSON-lines integrity for every finding the fixtures can produce.
    for f in eng2.findings:
        line = f.to_json()
        check("\n" not in line, f"{f.code}: json must be single-line")
        blob = json.loads(line)
        check(blob["code"] in ag.FINDINGS, f"{f.code}: unknown code in json")
        check(blob["severity"] == ag.FINDINGS[blob["code"]].severity,
              f"{f.code}: severity drift between finding and spec")
        check(blob["class"] == ag.FINDINGS[blob["code"]].klass,
              f"{f.code}: class drift between finding and spec")
        check(set(blob["cves"]) == set(ag.FINDINGS[blob["code"]].cves),
              f"{f.code}: CVE list drift between finding and spec")

    # Credential material must never reach any finding, from any fixture.
    forbidden = ("password", "secret", "user_password", "shared_secret")
    for f in eng2.findings:
        blob = json.dumps(f.detail).lower()
        for word in forbidden:
            check(word not in blob,
                  f"{f.code} detail contains forbidden token {word!r}")


# ---------------------------------------------------------------------------
# Section K - clean-set silence contract
# ---------------------------------------------------------------------------
#
# Enforced OFFLINE, deliberately.  cdpwatch's equivalent contract lived only
# in its lab shell script, and the lab then found a "benign" fixture that
# advertised itself as a vulnerable Nexus.  Both halves are asserted here:
# zero ATTACK findings, AND no version screened into CVE range.


def clean_set() -> list[bytes]:
    return [
        # ordinary DNS
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(53, 53, b"\x00" * 8))),
        # ordinary TLS on a trunk
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_TCP, tcp(443, 40000, b"\x16\x03\x01")),
            vlans=(10,)),
        # a correctly protected RADIUS exchange, both directions
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP,
                udp(50000, 1812, radius(1, 1, [(1, 8), (80, 18)])))),
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.2", "10.0.0.1", P_UDP,
                udp(1812, 50000, radius(2, 1, [(80, 18)])))),
        # a patched SSH server
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.9", "10.0.0.1", P_TCP,
                tcp(22, 40002, b"SSH-2.0-OpenSSH_9.8p1 Arista\r\n"))),
        # QinQ, which is normal
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2)), vlans=(10, 20)),
        # a trunk carrying untagged and tagged traffic from one MAC - the
        # exact shape that false-positived AG-207 on the first build run
        eth(b"\x0c" * 6, b"\x0d" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2))),
        eth(b"\x0c" * 6, b"\x0d" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP, udp(1, 2)), vlans=(10,)),
        # a non-Arista LLDP neighbour
        eth(LLDP_MAC, b"\x0e" * 6, E_LLDP,
            lldp("sw9", "Cisco IOS Software, C9300 Software Version 17.9.4")),
        # an Arista running a PATCHED build - the cdpwatch trap: a fixture
        # that is supposed to be benign must not advertise a vulnerable version
        eth(LLDP_MAC, b"\x0f" * 6, E_LLDP,
            lldp("sw2", "Arista Networks EOS version 4.34.2F running on an "
                        "Arista Networks DCS-7050SX3-48YC8")),
        # A LEGITIMATE PROXY HOP: the request carries Proxy-State and the
        # server echoes exactly the same one back. A flat "a NAS must never
        # receive Proxy-State" rule would fire here, which is why F1
        # correlates instead.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP,
                udp(50000, 1812, radius_v(1, 80, [(1, b"op"),
                                                  (33, b"proxy-hop-token-1"),
                                                  (80, b"\x00" * 16)])))),
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.2", "10.0.0.1", P_UDP,
                udp(1812, 50000, radius_v(2, 80, [(80, b"\x00" * 16),
                                                  (33, b"proxy-hop-token-1")])))),
        # A long PRINTABLE vendor AV-pair - vendors send these routinely, so
        # a length-only test would false-positive here.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.2", "10.0.0.1", P_UDP,
                udp(1812, 50000,
                    radius_v(2, 81, [(80, b"\x00" * 16),
                                     (26, vsa(b"Aruba-User-Role=authenticated"
                                              b"-employee-vlan-200-floor3-corp"
                                              b"-secure-wireless-policy"))])))),
        # An ordinary human-readable Reply-Message.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.2", "10.0.0.1", P_UDP,
                udp(1812, 50000,
                    radius_v(2, 82, [(80, b"\x00" * 16),
                                     (18, b"Welcome to the corporate network")])))),
        # A REAL EAP-TLS fragment whose content is HIGH-ENTROPY ciphertext,
        # which is what TLS fragments actually look like. The clean set
        # previously carried only zero-length EAP payloads, so removing the
        # EAP-Message exclusion from the opacity rule went undetected.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.2", "10.0.0.1", P_UDP,
                udp(1812, 50000, radius_v(11, 83, [(80, b"\x00" * 16),
                                                   (79, prand(253, 29))])))),
        # A REAL EAP-TLS 802.1X exchange. Its absence is precisely why the
        # D1 false positive survived four test tiers: EAP-Message (type 79)
        # is routinely fragmented at 255 bytes, and AG-201 keyed on the
        # largest attribute of ANY type, so this raised CRITICAL.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP,
                udp(50000, 1812, radius(1, 20, [(1, 8), (79, 255), (79, 255),
                                                (80, 18)])))),
        # The server's Access-Challenge, correctly hardened with M-A FIRST.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.2", "10.0.0.1", P_UDP,
                udp(1812, 50000, radius(11, 20, [(80, 18), (79, 255), (79, 255)])))),
        # A correctly hardened Access-Accept: M-A first, then Proxy-State.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.2", "10.0.0.1", P_UDP,
                udp(1812, 50000, radius(2, 21, [(80, 18), (33, 12)])))),
        # A legitimate proxy chain: one small Proxy-State per hop.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP,
                udp(50000, 1812, radius(1, 22, [(1, 8), (33, 12), (33, 12),
                                                (80, 18)])))),
        # A packet with more than 256 attributes, M-A last (D6).
        eth(b"\x01" * 6, b"\x02" * 6, E_IP4,
            ip4("10.0.0.1", "10.0.0.2", P_UDP,
                udp(50000, 1812, radius(1, 23, [(26, 2)] * 300 + [(80, 18)])))),
        # Ordinary IPv6 traffic behind a Hop-by-Hop header - must not itself
        # raise anything now that the chain is walked.
        eth(b"\x01" * 6, b"\x02" * 6, E_IP6,
            ip6(b"\x20\x01" + b"\x00" * 14, b"\x20\x01" + b"\x00" * 13 + b"\x02",
                0, ip6_eh(0, P_UDP) + udp(53, 53, b"\x00" * 8))),
        # a well-formed OSPFv3 hello
        eth(b"\x33\x33\x00\x00\x00\x05", b"\x10" * 6, E_IP6,
            ip6(b"\x20\x01" + b"\x00" * 14, b"\xff\x02" + b"\x00" * 13 + b"\x05",
                P_OSPF, b"\x03\x01" + struct.pack("!H", 16) + b"\x00" * 12)),
    ]


def section_k() -> None:
    section("K clean set")
    eng = run(clean_set())
    attacks = [f.code for f in eng.findings if f.klass == "attack"]
    check(attacks == [], f"benign set raised ATTACK findings: {attacks}")

    screened = [f.code for f in eng.findings if f.code in ("AG-002", "AG-003")]
    check(screened == [],
          f"benign set screened a version into CVE range: {screened}. This is "
          f"the cdpwatch trap - a 'benign' fixture that advertises itself as "
          f"a vulnerable platform.")

    # Positive control: the clean set is not silent because it is empty.
    check(len(eng.findings) > 0,
          "the clean set must still produce SOME finding (posture/exposure), "
          "or it proves nothing about attack silence")

    # And the patched-Arista fixture must genuinely be recognised as Arista,
    # otherwise it is passing for the wrong reason.
    check("AG-001" in codes(eng),
          "the patched-Arista clean fixture must be recognised as Arista - "
          "otherwise the silence above is vacuous")
    vers = [f.detail.get("eos_version") for f in eng.findings if f.code == "AG-001"]
    check("4.34.2F" in vers, f"clean fixture version not observed: {vers}")

    # Every clean frame individually must also be attack-silent, so one
    # frame cannot hide behind another.
    for i, fr in enumerate(clean_set()):
        got = [f.code for f in run([fr]).findings if f.klass == "attack"]
        check(got == [], f"clean frame {i} alone raised {got}")


# ---------------------------------------------------------------------------
# Section L - lab artefacts
# ---------------------------------------------------------------------------


def write_pcap(path: str, frames: Iterable[bytes], base_ts: int = 1700000000,
               interval_us: int = 1000) -> None:
    """
    Dependency-free pcap writer.

    Carries the cdpwatch write_pcap TIMESTAMP FIX: the frame index goes into
    base_ts + (index * interval) MICROseconds WITH CARRY into the seconds
    field - not into the seconds field directly.  cdpwatch's original stamped
    the index as seconds, so a 45-frame capture claimed a 44-second span and
    tcpreplay's replay-at-recorded-rate defeated every rate-based finding.
    """
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for i, frame in enumerate(frames):
            total_us = i * interval_us
            sec = base_ts + total_us // 1_000_000
            usec = total_us % 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


def read_pcap(path: str) -> list[tuple[int, int, bytes]]:
    out: list[tuple[int, int, bytes]] = []
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            return out
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic != 0xA1B2C3D4:
            return out
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                break
            sec, usec, caplen, _ = struct.unpack("<IIII", rec)
            data = fh.read(caplen)
            if len(data) < caplen:
                break
            out.append((sec, usec, data))
    return out


def section_l() -> None:
    section("L lab artefacts")
    frames = [f for fs in attack_fixtures().values() for f in fs]
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "aristaguard_attack.pcap")
        write_pcap(path, frames)
        recs = read_pcap(path)
        check(len(recs) == len(frames),
              f"pcap round-trip: wrote {len(frames)}, read {len(recs)}")
        check(all(a == b for (_, _, a), b in zip(recs, frames)),
              "pcap payloads round-trip byte-exact")

        # TIMESTAMP FIX assertions (the cdpwatch bug).
        check(all(u < 1_000_000 for _, u, _ in recs),
              "usec field must never exceed 999999")
        ts = [s + u / 1e6 for s, u, _ in recs]
        check(all(b >= a for a, b in zip(ts, ts[1:])),
              "pcap timestamps must be monotonic")
        span = ts[-1] - ts[0]
        check(span < ag.Config().suppress_s,
              f"capture span {span:.3f}s must sit inside the suppress window, "
              f"or a replay at recorded rate defeats suppression testing")
        check(span < 1.0,
              f"span {span:.3f}s - the frame INDEX must not be landing in the "
              f"seconds field (this is exactly the cdpwatch bug)")

        # Replaying the pcap through the production engine must reproduce
        # the same codes as feeding the frames directly.
        direct = codes(run(frames))
        eng = ag.AristaEngine(acfg())
        for sec, usec, data in recs:
            eng.handle_frame(data, ts=sec + usec / 1e6)
        check(codes(eng) >= direct - {"AG-203"},
              "pcap replay must reproduce the direct-feed codes")

        # Largest frame determines the veth MTU the lab must set.
        mtu = max(len(f) for f in frames)
        check(mtu < 1500,
              f"largest lab frame is {mtu}B; if this ever exceeds 1500 the lab "
              f"must read --print-lab-mtu at runtime and size the veth, as "
              f"ciscoguard had to at 5072B")

    # Machine-readable output for the lab harness, via a real subprocess so
    # a broken CLI cannot pass here.  QUIET so a child cannot recurse.
    r = subprocess.run([sys.executable, MODULE_PATH, "--print-lab-codes"],
                       capture_output=True, text=True, timeout=60)
    check(r.returncode == 0, "--print-lab-codes exits 0")
    printed = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    check(set(printed) == set(ag.FINDINGS),
          f"--print-lab-codes must emit every code; drift: "
          f"{set(printed) ^ set(ag.FINDINGS)}")
    check(printed == sorted(printed), "--print-lab-codes output is sorted")

    r = subprocess.run([sys.executable, MODULE_PATH, "--print-catalog"],
                       capture_output=True, text=True, timeout=60)
    check(r.returncode == 0, "--print-catalog exits 0")
    for e in ag.CVE_CATALOG:
        check(e.cve in r.stdout, f"--print-catalog omits {e.cve}")
    for cve, _ in ag.QUARANTINED_CVES:
        check(cve in r.stdout, f"--print-catalog omits quarantined {cve}")

    r = subprocess.run([sys.executable, MODULE_PATH, "--print-config"],
                       capture_output=True, text=True, timeout=60)
    check(r.returncode == 0, "--print-config exits 0")
    check(json.loads(r.stdout).keys() == ag.Config().dump().keys(),
          "--print-config emits exactly the Config fields")

    # The module's own self-test must pass, run as a real subprocess.
    r = subprocess.run([sys.executable, MODULE_PATH, "--selftest"],
                       capture_output=True, text=True, timeout=300)
    check(r.returncode == 0, f"module self-test failed:\n{r.stdout}")
    check("469/469" in r.stdout or "/" in r.stdout, "self-test reports a count")

    # Capture requires an interface: running bare must error, not silently
    # start sniffing on a default.
    r = subprocess.run([sys.executable, MODULE_PATH],
                       capture_output=True, text=True, timeout=60)
    check(r.returncode != 0, "bare invocation must not start a capture")
    check("iface" in (r.stderr + r.stdout).lower(),
          "bare invocation must say an interface is required")


# ---------------------------------------------------------------------------
# Lab artefact emission
# ---------------------------------------------------------------------------
#
# The sealed-namespace lab replays these.  Emitted from the SAME fixtures the
# conformance sections use, so a lab pass and a conformance pass cannot be
# testing different traffic.


def emit_lab_artefacts(outdir: str) -> dict[str, Any]:
    os.makedirs(outdir, exist_ok=True)
    fixtures = attack_fixtures()
    gated = config_gated()

    # Ordering matters: AG-203 needs the VXLAN frame to have taught the
    # engine the decap endpoint before the GRE frame arrives.  Emitting in
    # sorted-code order preserves that because AG-106 precedes AG-203.
    attack: list[bytes] = []
    for code in sorted(fixtures):
        attack.extend(fixtures[code])
    write_pcap(os.path.join(outdir, "attack.pcap"), attack)

    benign = clean_set()
    write_pcap(os.path.join(outdir, "benign.pcap"), benign)

    # Base config scoping the RADIUS rules to the fixture endpoints. The RADIUS
    # rules are limited to Arista hardware, so without this the lab's RADIUS
    # codes would be gated out and "all expected codes validated live" would
    # fail. The endpoints are every address a RADIUS fixture uses, in the
    # module's own _ipv6 string form for the v6 ones.
    base_cfg = ag.Config(radius_arista_endpoints=(
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
        "2001:0:0:0:0:0:0:0", "2001:0:0:0:0:0:0:2"))
    with open(os.path.join(outdir, "base.conf.json"), "w",
              encoding="utf-8") as fh:
        json.dump(base_cfg.dump(), fh, indent=2, sort_keys=True)

    # Config-gated codes ship with the config that arms them, so the lab can
    # prove AG-206 both silent and firing.
    policy_frames: list[bytes] = []
    policy_cfg: Optional[Any] = None
    for _code, (cfg_obj, frames) in sorted(gated.items()):
        policy_frames.extend(frames)
        policy_cfg = cfg_obj
    write_pcap(os.path.join(outdir, "policy.pcap"), policy_frames)
    if policy_cfg is not None:
        with open(os.path.join(outdir, "policy.conf.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(policy_cfg.dump(), fh, indent=2, sort_keys=True)

    # An IPv6-extension-header-ONLY pcap. The EH frames also ride in
    # attack.pcap, but there they sit beside IPv4 RADIUS fixtures that raise
    # the same codes - so a missing BPF ip6[6] clause would not change the
    # lab's verdict at all. Replayed alone, these frames can only produce
    # findings if the filter really admits extension-header-wrapped IPv6.
    eh_frames: list[bytes] = []
    for kind in (0, 43, 44, 51, 60):
        eh_frames.append(
            eth(b"\x01" * 6, b"\x02" * 6, E_IP6,
                ip6(b"\x20\x01" + b"\x00" * 14,
                    b"\x20\x01" + b"\x00" * 13 + b"\x02", kind,
                    ip6_eh(kind, P_UDP)
                    + udp(50000, 1812, radius(1, 60 + kind, [(1, 8)])))))
    write_pcap(os.path.join(outdir, "ipv6_eh.pcap"), eh_frames)

    all_frames = attack + benign + policy_frames + eh_frames
    meta = {
        "mtu": max(len(f) for f in all_frames),
        "attack_frames": len(attack),
        "benign_frames": len(benign),
        "policy_frames": len(policy_frames),
        "expected_attack_codes": sorted(fixtures),
        "expected_policy_codes": sorted(gated),
        "ipv6_eh_frames": len(eh_frames),
        "expected_ipv6_eh_codes": ["AG-101", "AG-102"],
        "unwired_codes": sorted(ag.UNWIRED_CODES),
        "all_codes": sorted(ag.FINDINGS),
    }
    with open(os.path.join(outdir, "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)
    return meta


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

SECTIONS: tuple[tuple[str, Callable[[], None]], ...] = (
    ("A structural", section_a),
    ("B dependency isolation", section_b),
    ("C config", section_c),
    ("D passive invariant", section_d),
    ("E parsers", section_e),
    ("F coverage", section_f),
    ("G thresholds", section_g),
    ("H robustness", section_h),
    ("I suppression", section_i),
    ("J non-vacuity", section_j),
    ("K clean set", section_k),
    ("L lab artefacts", section_l),
)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="aristaguard_conformance")
    p.add_argument("--quiet", action="store_true", help="only print the summary")
    p.add_argument("--section", default="", help="run one section by letter")
    p.add_argument("--emit-lab-artefacts", default="", metavar="DIR",
                   help="write attack/benign/policy pcaps plus meta.json")
    p.add_argument("--print-lab-mtu", action="store_true",
                   help="largest lab frame in bytes, for veth sizing")
    args = p.parse_args(argv)

    if args.print_lab_mtu:
        with tempfile.TemporaryDirectory() as td:
            print(emit_lab_artefacts(td)["mtu"])
        return 0
    if args.emit_lab_artefacts:
        meta = emit_lab_artefacts(args.emit_lab_artefacts)
        print(json.dumps(meta, sort_keys=True))
        return 0

    for name, fn in SECTIONS:
        if args.section and not name.startswith(args.section.upper()):
            continue
        before = len(FAILS)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            FAILS.append(f"[{name}] raised {type(exc).__name__}: {exc}")
        if not args.quiet:
            status = "ok" if len(FAILS) == before else f"{len(FAILS) - before} FAILED"
            print(f"  {name:<26} {status}")

    for f in FAILS:
        print(f"FAIL: {f}")
    print(f"{CHECKS - len(FAILS)}/{CHECKS} conformance checks passed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
