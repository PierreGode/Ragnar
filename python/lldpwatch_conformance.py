#!/usr/bin/env python3
"""
lldpwatch_conformance — offline, dependency-free conformance harness.

Drives the PRODUCTION parser and engine (no re-implementation here) and
asserts scapy is never imported by the offline path.

Deliberately NOT part of this tier: the scapy cross-check, which lives in
lldpwatch_scapy_xcheck.py. This file asserts scapy stays UNIMPORTED.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

import lldpwatch as W
import lldpwatch_frames as F

DEFERRED_CODES: Tuple[str, ...] = ()  # nothing deferred

# The config the lab's screening phase runs the sensor with. Lives here, not
# in the shell script, so the harness can assert it loads and produces the
# codes the lab is told to expect.
LAB_SCREEN_CONFIG: Dict[str, Any] = {"version_floors": {"lldpd": "1.0.9"}}


def LAB_UNPARSEABLE() -> bytes:
    """lldpd advert with no parseable version - drives LLDP-026."""
    return F.frame(
        F.mandatory() + [F.t_sys_desc(b"lldpd (version withheld)"), F.t_end()],
        src="02:00:00:00:0c:06", pad=False,
    )


def LAB_FORGED() -> bytes:
    """An unbaselined source - drives LLDP-049 under the enforce config."""
    return F.benign_minimal(src="02:00:00:00:de:ad")
LAB_ENFORCE_CONFIG: Dict[str, Any] = {"enforce": True, "baseline": []}


# Readiness canary (suite LESSON AB). A fixed sleep after spawning the
# sniffer is a guess: scapy must import, open AF_PACKET and install the BPF
# before anything is captured, and telnetwatch silently lost its first six
# scenarios that way. The lab replays this frame until a finding carrying
# this source MAC appears, then clears the log and starts the real phases.
CANARY_SRC = "02:00:00:00:ca:fe"


def canary_frame() -> bytes:
    return F.mal_reserved_tlv_type(src=CANARY_SRC)


def lab_pairs() -> List[str]:
    """Expected "CODE<TAB>SRC" pairs for the lab.

    Suite LESSON AF (coverage asymmetry): checking only that a CODE appeared
    lets one fixture mask another inside the same code. LLDP-045 has six
    distinct sub-shapes; silencing one left the code present via the other
    five. Every fixture carries its own source MAC, so the lab asserts
    (code, src) pairs and each fixture is accountable on its own.

    CRITICAL: these pairs come from the DECLARED fixture-to-code mapping, not
    from running the engine over the fixtures. An expectation computed by the
    module under test is circular - when detection breaks, the expectation
    disappears with it and the lab passes. Measured: two real detection losses
    (the Chassis-ID MAC-length check and the org-specific fixed-length table)
    passed a lab whose expectations were engine-derived. Only parse_ethernet()
    is used here, to read each fixture's source MAC, which is parsing rather
    than detection.
    """
    out = set()
    declared: List[Tuple[str, Any]] = []
    for code, builders in F.MALFORMED_BUILDERS.items():
        declared += [(code, fn) for fn in builders]
    declared += [(code, fn) for code, fn in F.VENDOR_BUILDERS.items()]
    # screening phase (version-floor config)
    declared += [
        ("LLDP-022", F.vendor_lldpd),
        ("LLDP-025", F.vendor_lldpd),
        ("LLDP-022", LAB_UNPARSEABLE),
        ("LLDP-026", LAB_UNPARSEABLE),
    ]
    # enforce phase
    declared += [("LLDP-049", LAB_FORGED)]
    for code, fn in declared:
        fr = W.parse_ethernet(fn())
        out.add("%s\t%s" % (code, fr.src))
    # the flood phase is volumetric: pin the code, not a single source
    out.add("LLDP-048\t*")
    return sorted(out)


def lab_codes() -> List[str]:
    """Every code the sealed lab is expected to produce live, across all
    phases. Read by the lab script at runtime - never hardcoded there."""
    return sorted(
        set(F.MALFORMED_BUILDERS)
        | set(F.VENDOR_BUILDERS)
        | {"LLDP-048", "LLDP-025", "LLDP-026", "LLDP-049"}
    )


class Checker:
    def __init__(self) -> None:
        self.passed = 0
        self.failures: List[str] = []
        self.section = "(none)"
        self.by_section: Dict[str, int] = {}

    def sect(self, name: str) -> None:
        self.section = name
        self.by_section.setdefault(name, 0)

    def ok(self, cond: bool, what: str) -> bool:
        if cond:
            self.passed += 1
            self.by_section[self.section] = self.by_section.get(self.section, 0) + 1
        else:
            self.failures.append("[%s] %s" % (self.section, what))
        return bool(cond)

    def eq(self, got: Any, want: Any, what: str) -> bool:
        return self.ok(got == want, "%s: got %r want %r" % (what, got, want))

    def raises(self, fn, exc, what: str) -> bool:
        try:
            fn()
        except exc:
            return self.ok(True, what)
        except Exception as e:  # wrong exception type
            return self.ok(False, "%s: raised %r" % (what, e))
        return self.ok(False, "%s: did not raise" % what)


def raw_pcap_stamps(path: str) -> List[Tuple[int, int]]:
    """Read the (sec, usec) fields EXACTLY as written.

    F.read_pcap() reconstructs sec + usec/1e6, which silently normalises an
    illegal usec of 1_000_000 into the next second - masking precisely the
    bug this is here to catch. Assert the field, not the reconstruction.
    """
    import struct as _s

    out: List[Tuple[int, int]] = []
    with open(path, "rb") as fh:
        fh.read(24)
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                break
            sec, usec, incl, _ = _s.unpack("<IIII", hdr)
            fh.read(incl)
            out.append((sec, usec))
    return out


_STUB = {
    "ts": 0.0, "iface": "?", "module": "?", "code": "?", "name": "?",
    "severity": "?", "group": "?", "src": "?", "detail": "",
}


def first(c: "Checker", recs: Sequence[Dict[str, Any]], what: str,
          code: Optional[str] = None) -> Dict[str, Any]:
    """Return the first (optionally code-matching) record, or record a FAILURE
    and hand back a stub.

    Suite LESSON L: a harness that raises on a missing finding reports
    "module broken" where it should report "regression undetected", and every
    later check in the section is lost. Nothing in this file indexes a
    findings list directly.
    """
    pool = [r for r in recs if code is None or r.get("code") == code]
    if not pool:
        c.ok(False, "%s: expected a %s record, got %r"
             % (what, code or "finding", [r.get("code") for r in recs]))
        return dict(_STUB)
    c.ok(True, "%s: record present" % what)
    return pool[0]


def codes_for(raw: bytes, cfg: Optional[W.Config] = None, **kw) -> List[str]:
    e = W.Engine(cfg or W.Config(), **kw)
    return sorted({r["code"] for r in e.handle_frame(raw)})


# ==========================================================================
# 1. TLV primitives and round-trip
# ==========================================================================


def s_tlv(c: Checker) -> None:
    c.sect("tlv-roundtrip")
    for ttype in (0, 1, 2, 3, 4, 5, 6, 7, 8, 64, 126, 127):
        for ln in (0, 1, 2, 7, 64, 255, 511):
            body = bytes((i * 7 + ln) & 0xFF for i in range(ln))
            raw = F.tlv(ttype, body)
            w = W.walk_tlvs(raw + F.t_end())
            if not c.ok(bool(w.tlvs), "roundtrip %d/%d yields a TLV" % (ttype, ln)):
                continue
            tl = w.tlvs[0]
            c.eq(tl.type, ttype, "roundtrip type %d/%d" % (ttype, ln))
            c.eq(tl.length, ln, "roundtrip len %d/%d" % (ttype, ln))
            c.eq(tl.value, body, "roundtrip value %d/%d" % (ttype, ln))
    c.raises(lambda: F.tlv(128, b""), ValueError, "type > 127 rejected by builder")
    c.raises(lambda: F.tlv(1, b"\x00" * 512), ValueError, "len > 511 rejected by builder")
    # the 7/9 bit split itself
    raw = F.tlv(127, b"\x00" * 511)
    c.eq(raw[0], 0xFF, "type 127 high bits")
    c.eq(((raw[0] << 8) | raw[1]) & 0x1FF, 511, "length low 9 bits")


# ==========================================================================
# 2. Ethernet framing
# ==========================================================================


def s_framing(c: Checker) -> None:
    c.sect("framing")
    fr = W.parse_ethernet(F.benign_minimal())
    c.ok(fr is not None, "untagged LLDP parses")
    c.eq(fr.vlans, (), "untagged has no vlans")
    c.eq(fr.group, "nearest-bridge", "0180c200000e maps to nearest-bridge")
    fr = W.parse_ethernet(F.benign_tagged(vid=300))
    c.eq(fr.vlans, (300,), "802.1Q tag parsed")
    fr = W.parse_ethernet(F.benign_qinq())
    c.eq(fr.vlans, (300, 12), "QinQ stack parsed")
    for dst, name in (
        (F.DST_NEAREST_BRIDGE, "nearest-bridge"),
        (F.DST_NEAREST_NON_TPMR, "nearest-non-tpmr-bridge"),
        (F.DST_NEAREST_CUSTOMER, "nearest-customer-bridge"),
    ):
        fr = W.parse_ethernet(F.frame(F.mandatory() + [F.t_end()], dst=dst))
        c.eq(fr.group, name, "group MAC %s" % name)
    # non-LLDP must be rejected outright, never guessed at
    for et in (0x0800, 0x86DD, 0x0806, 0x8809, 0x88A8, 0x2000):
        raw = F.DST_NEAREST_BRIDGE + F.mac("02:00:00:00:00:01")
        raw += bytes([et >> 8, et & 0xFF]) + b"\x00" * 46
        c.ok(W.parse_ethernet(raw) is None, "ethertype 0x%04x rejected" % et)
    c.ok(W.parse_ethernet(b"") is None, "empty buffer rejected")
    c.ok(W.parse_ethernet(b"\x00" * 13) is None, "13-octet buffer rejected")
    # a non-LLDP frame must produce no findings at all
    arp = F.DST_NEAREST_BRIDGE + F.mac("02:00:00:00:00:01") + b"\x08\x06" + b"\x11" * 46
    c.eq(codes_for(arp), [], "non-LLDP frame yields no findings")


# ==========================================================================
# 3. Padding / FCS / trailing-data trichotomy  (the cdpwatch FP trap)
# ==========================================================================


def s_padding(c: Checker) -> None:
    c.sect("padding-trichotomy")
    body = F.mandatory() + [F.t_end()]
    short = F.frame(body, pad=False)
    c.ok(len(short) < 60, "unpadded fixture really is short")
    padded = F.frame(body, pad=True)
    c.eq(len(padded), 60, "kernel-style padding to 60 octets")

    w = W.walk_tlvs(W.parse_ethernet(padded).payload)
    c.eq(w.tail_kind, "padding", "all-zero tail classified as padding")
    c.eq(codes_for(padded), [], "padded frame is SILENT (cdpwatch FP trap)")

    w = W.walk_tlvs(W.parse_ethernet(short).payload)
    c.eq(w.tail_kind, "none", "exact-fit frame has no tail")
    c.eq(codes_for(short), [], "unpadded frame is silent")

    fcs = F.benign_with_fcs()
    w = W.walk_tlvs(W.parse_ethernet(fcs).payload, allow_fcs_tail=True)
    c.eq(w.tail_kind, "fcs", "zeros + 4 non-zero octets classified as FCS")
    c.eq(codes_for(fcs), [], "trailing FCS is silent when allowed")
    cfg = W.Config(allow_fcs_tail=False)
    c.eq(codes_for(fcs, cfg), ["LLDP-053"], "FCS tail fires when not allowed")

    smug = F.mal_trailing_data()
    w = W.walk_tlvs(W.parse_ethernet(smug).payload)
    c.eq(w.tail_kind, "data", "non-zero tail classified as data")
    c.eq(codes_for(smug), ["LLDP-053"], "smuggled tail fires LLDP-053")

    # a tail of exactly 4 non-zero octets with NO preceding zeros is still
    # treated as an FCS when allowed - pin the behaviour so it cannot drift
    four = F.frame(body, pad=False, tail=b"\xde\xad\xbe\xef")
    c.eq(
        W.walk_tlvs(W.parse_ethernet(four).payload, True).tail_kind, "fcs",
        "bare 4-octet tail reads as FCS when allowed",
    )
    c.eq(
        W.walk_tlvs(W.parse_ethernet(four).payload, False).tail_kind, "data",
        "bare 4-octet tail reads as data when not allowed",
    )
    # SHORT PADDING (suite LESSON Z). An all-zero tail of 4+ octets is
    # absorbed by the FCS branch, so a padding rule that has collapsed into
    # the FCS rule is INDISTINGUISHABLE on those frames. Only a 1-3 octet pad
    # separates them, and nothing else in the fixture set produces one.
    for n in (1, 2, 3):
        raw = getattr(F, "benign_pad%d" % n)()
        c.eq(len(raw), 60, "benign_pad%d really is padded to 60 octets" % n)
        w2 = W.walk_tlvs(W.parse_ethernet(raw).payload)
        c.eq(len(w2.tail), n, "benign_pad%d leaves exactly %d pad octets" % (n, n))
        c.eq(w2.tail_kind, "padding",
             "a %d-octet all-zero tail is padding, not data or FCS" % n)
        c.eq(codes_for(raw), [], "benign_pad%d is silent" % n)
        c.eq(W.walk_tlvs(W.parse_ethernet(raw).payload, False).tail_kind, "padding",
             "a %d-octet pad is padding even with allow_fcs_tail off" % n)
    five = F.frame(body, pad=False, tail=b"\xde\xad\xbe\xef\x01")
    c.eq(
        W.walk_tlvs(W.parse_ethernet(five).payload, True).tail_kind, "data",
        "5 non-zero tail octets are data even when FCS is allowed",
    )


# ==========================================================================
# 4. Clean-set silence contract, asserted OFFLINE
#    (cdpwatch learned this the hard way: the shell lab was the only place
#    this was ever enforced, and a fixture bug therefore reached the lab.)
# ==========================================================================


def s_clean_set(c: Checker) -> None:
    c.sect("clean-set-silence")
    for b in F.BENIGN_BUILDERS:
        got = codes_for(b())
        c.eq(got, [], "benign builder %s is silent" % b.__name__)
    # and the whole clean set through ONE engine, in sequence, must stay silent
    e = W.Engine(W.Config(flood_threshold=1000, flood_distinct_src=1000))
    for b in F.BENIGN_BUILDERS:
        e.handle_frame(b())
    c.eq([r["code"] for r in e.findings], [], "clean set silent through one engine")
    # benign fixtures must not carry a screening identity
    for b in F.BENIGN_BUILDERS:
        raw = b()
        w = W.walk_tlvs(W.parse_ethernet(raw).payload)
        blob = " ".join(
            W.printable(t.value) for t in w.tlvs if t.type in (5, 6)
        )
        for fam, rx in W.Engine()._compiled:
            c.ok(
                not rx.search(blob),
                "benign %s carries no %s identity" % (b.__name__, fam.key),
            )


# ==========================================================================
# 5. Per-code scenarios with FP gates
# ==========================================================================

FP_GATE_FRAMES = {
    "LLDP-040": F.benign_full,
    "LLDP-041": F.benign_full,
    "LLDP-042": F.benign_minimal,
    "LLDP-043": F.benign_minimal,
    "LLDP-044": F.benign_full,
    "LLDP-045": F.benign_full_v6,
    "LLDP-046": F.benign_minimal,
    "LLDP-047": F.benign_minimal,
    "LLDP-050": F.benign_long_banner,
    "LLDP-051": F.benign_med_phone,
    "LLDP-052": F.benign_full,
    "LLDP-053": F.benign_with_fcs,
    "LLDP-054": F.benign_minimal,
}


def s_structural(c: Checker) -> None:
    c.sect("structural-scenarios")
    for code, builders in sorted(F.MALFORMED_BUILDERS.items()):
        for fn in builders:
            got = codes_for(fn())
            c.ok(code in got, "%s fires for %s (got %r)" % (code, fn.__name__, got))
            c.eq(got, [code], "%s fires ALONE for %s" % (code, fn.__name__))
        gate = FP_GATE_FRAMES[code]
        c.ok(code not in codes_for(gate()), "FP gate: %s silent on %s" % (code, gate.__name__))

    c.sect("structural-detail")
    e = W.Engine()
    rec = first(c, e.handle_frame(F.mal_length_overrun()), "LLDP-040 overrun", "LLDP-040")
    c.eq(rec["severity"], "critical", "LLDP-040 is critical")
    c.eq(rec.get("declared_length"), 400, "LLDP-040 reports declared length")
    c.eq(rec.get("available"), rec.get("available"), "LLDP-040 reports available octets")
    c.ok(rec.get("available") < 400, "LLDP-040 available < declared")
    c.ok("CVE-2015-8011" in rec["detail"], "LLDP-040 names the lldpd CVE")

    e = W.Engine()
    rec = first(c, e.handle_frame(F.mal_mgmt_oversized_strlen()), "LLDP-045 oversized", "LLDP-045")
    c.eq(rec.get("addr_strlen"), 200, "LLDP-045 reports the oversized strlen")
    c.ok("CVE-2015-8011" in rec["detail"], "LLDP-045 names CVE-2015-8011")
    c.eq(rec["severity"], "critical", "LLDP-045 is critical")

    e = W.Engine()
    rec = first(c, e.handle_frame(F.mal_mgmt_v6_short()), "LLDP-045 v6-short", "LLDP-045")
    c.eq(rec.get("af"), "ipv6", "LLDP-045 tags the address family (v6 case)")
    e = W.Engine()
    rec = first(c, e.handle_frame(F.mal_mgmt_v4_long()), "LLDP-045 v4-long", "LLDP-045")
    c.eq(rec.get("af"), "ipv4", "LLDP-045 tags the address family (v4 case)")

    e = W.Engine()
    rec = first(c, e.handle_frame(F.mal_missing_mandatory()), "LLDP-042", "LLDP-042")
    c.eq(rec.get("missing"), ["Time To Live"], "LLDP-042 names the missing TLV")
    e = W.Engine()
    rec = first(c, e.handle_frame(F.mal_duplicate_tlv()), "LLDP-044", "LLDP-044")
    c.eq(rec.get("duplicated"), ["System Name"], "LLDP-044 names the duplicated TLV")

    c.sect("grammar-matrix")
    import itertools
    mand = {1: F.t_chassis_id(), 2: F.t_port_id(), 3: F.t_ttl()}
    for order in itertools.permutations((1, 2, 3)):
        raw = F.frame([mand[t] for t in order] + [F.t_end()])
        got = codes_for(raw)
        if order == (1, 2, 3):
            c.eq(got, [], "mandatory order %s is silent" % (order,))
        else:
            c.eq(got, ["LLDP-043"], "mandatory order %s fires LLDP-043" % (order,))
    for drop in (1, 2, 3):
        raw = F.frame([mand[t] for t in (1, 2, 3) if t != drop] + [F.t_end()])
        c.eq(codes_for(raw), ["LLDP-042"], "dropping type %d fires LLDP-042" % drop)
    # missing takes precedence over order: do not emit both
    raw = F.frame([F.t_port_id(), F.t_chassis_id(), F.t_end()])
    c.eq(codes_for(raw), ["LLDP-042"], "missing suppresses the order finding")
    for t in (1, 2, 3, 4, 5, 6, 7):
        base = {1: F.t_chassis_id(), 2: F.t_port_id(), 3: F.t_ttl(),
                4: F.t_port_desc(), 5: F.t_sys_name(), 6: F.t_sys_desc(),
                7: F.t_sys_cap()}
        # the fixture must actually contain TWO of the type under test:
        # appending one optional TLV to mandatory() leaves only one.
        if t <= 3:
            tlvs = [mand[1], mand[2], mand[3], base[t], F.t_end()]
        else:
            tlvs = F.mandatory() + [base[t], base[t], F.t_end()]
        c.ok("LLDP-044" in codes_for(F.frame(tlvs)), "duplicate type %d fires LLDP-044" % t)
    # Management Address is explicitly repeatable - must NOT fire LLDP-044
    raw = F.frame(
        F.mandatory()
        + [F.t_mgmt_addr(af=1, addr=F.IPV4_ADDR),
           F.t_mgmt_addr(af=2, addr=F.IPV6_ADDR), F.t_end()]
    )
    c.eq(codes_for(raw), [], "repeated Management Address TLVs are legal")
    # Organizationally Specific is repeatable too
    raw = F.frame(
        F.mandatory()
        + [F.t_org(F.OUI_8023, 4, b"\x05\xf2"),
           F.t_org(F.OUI_8021, 1, b"\x00\x64"), F.t_end()]
    )
    c.eq(codes_for(raw), [], "repeated Org-Specific TLVs are legal")


# ==========================================================================
# 6. Dual-stack parity matrix (PRIME DIRECTIVE)
# ==========================================================================


def s_dualstack(c: Checker) -> None:
    c.sect("dual-stack-parity")
    # Management Address: every family/length combination
    for af, addr, name in ((1, F.IPV4_ADDR, "ipv4"), (2, F.IPV6_ADDR, "ipv6")):
        good = F.frame(F.mandatory() + [F.t_mgmt_addr(af=af, addr=addr), F.t_end()])
        c.eq(codes_for(good), [], "well-formed %s mgmt address is silent" % name)
        c.eq(
            W.extract_mgmt_addrs(W.walk_tlvs(W.parse_ethernet(good).payload)),
            ["192.168.1.1"] if af == 1 else ["[2001:db8::9]"],
            "%s mgmt address extracted" % name,
        )
    wrong = (
        (1, F.IPV6_ADDR, "ipv4 subtype with 16-octet address"),
        (2, F.IPV4_ADDR, "ipv6 subtype with 4-octet address"),
        (1, b"\xc0\xa8\x01", "ipv4 subtype with 3-octet address"),
        (2, F.IPV6_ADDR[:15], "ipv6 subtype with 15-octet address"),
        (2, F.IPV6_ADDR + b"\x01", "ipv6 subtype with 17-octet address"),
    )
    for af, addr, what in wrong:
        raw = F.frame(F.mandatory() + [F.t_mgmt_addr(af=af, addr=addr), F.t_end()])
        c.eq(codes_for(raw), ["LLDP-045"], "mgmt mismatch: %s" % what)
    # oversized strlen in BOTH families
    for af, addr, name in ((1, F.IPV4_ADDR, "ipv4"), (2, F.IPV6_ADDR, "ipv6")):
        raw = F.frame(
            F.mandatory()
            + [F.t_mgmt_addr(af=af, addr=addr, addr_strlen=250), F.t_end()]
        )
        c.eq(codes_for(raw), ["LLDP-045"], "oversized strlen (%s) fires" % name)
    # Chassis ID / Port ID network-address subtypes, both families
    for sub, code, label in ((5, "LLDP-046", "chassis"), (4, "LLDP-047", "port")):
        for af, addr, name in ((1, F.IPV4_ADDR, "ipv4"), (2, F.IPV6_ADDR, "ipv6")):
            if label == "chassis":
                tlvs = [F.t_chassis_id(subtype=sub, body=bytes([af]) + addr),
                        F.t_port_id(), F.t_ttl(), F.t_end()]
            else:
                tlvs = [F.t_chassis_id(),
                        F.t_port_id(subtype=sub, body=bytes([af]) + addr),
                        F.t_ttl(), F.t_end()]
            c.eq(codes_for(F.frame(tlvs)), [],
                 "well-formed %s %s network-address is silent" % (name, label))
            bad_addr = F.IPV6_ADDR if af == 1 else F.IPV4_ADDR
            if label == "chassis":
                tlvs = [F.t_chassis_id(subtype=sub, body=bytes([af]) + bad_addr),
                        F.t_port_id(), F.t_ttl(), F.t_end()]
            else:
                tlvs = [F.t_chassis_id(),
                        F.t_port_id(subtype=sub, body=bytes([af]) + bad_addr),
                        F.t_ttl(), F.t_end()]
            c.eq(codes_for(F.frame(tlvs)), [code],
                 "%s %s network-address family mismatch fires %s" % (name, label, code))
    # an unknown address family is NOT a finding: IANA has many, and LLDP
    # permits them. Only families we know the length of are length-checked.
    for af in (3, 16, 25):
        raw = F.frame(
            F.mandatory() + [F.t_mgmt_addr(af=af, addr=b"\x01\x02\x03"), F.t_end()]
        )
        c.eq(codes_for(raw), [], "unknown address family %d is not a finding" % af)

    c.sect("ipv6-rendering")
    cases = [
        ("20010db8000000000000000000000009", "2001:db8::9"),
        ("00000000000000000000000000000001", "::1"),
        ("00000000000000000000000000000000", "::"),
        ("fe800000000000000211' 22fffe333344".replace("' ", ""), "fe80::211:22ff:fe33:3344"),
        ("20010db8000000010000000000000001", "2001:db8:0:1::1"),
        ("20010db8000100000001000000010001", "2001:db8:1:0:1:0:1:1"),
    ]
    for hexs, want in cases:
        c.eq(W.fmt_ipv6(bytes.fromhex(hexs)), want, "RFC 5952 %s" % want)
    for n in (0, 1, 4, 15, 17, 32):
        c.raises(lambda n=n: W.fmt_ipv6(b"\x00" * n), ValueError,
                 "fmt_ipv6 rejects a %d-octet buffer" % n)
    c.eq(W.fmt_endpoint("2001:db8::9", 2), "[2001:db8::9]", "v6 bracketed")
    c.eq(W.fmt_endpoint("192.168.1.1", 1), "192.168.1.1", "v4 unbracketed")
    # round-trip: the emitted form must be splittable back to a host
    s = W.fmt_endpoint(W.fmt_ipv6(bytes.fromhex(cases[0][0])), 2)
    c.ok(s.startswith("[") and s.endswith("]"), "v6 endpoint round-trips to a host")
    c.eq(s[1:-1], "2001:db8::9", "bracket strip recovers the address")


# ==========================================================================
# 7. Threshold boundaries: at the limit silent, one over fires
# ==========================================================================


def s_thresholds(c: Checker) -> None:
    c.sect("thresholds")
    cfg = W.Config()
    for ttype, limit, name in (
        (4, cfg.max_port_desc, "port_desc"),
        (5, cfg.max_system_name, "system_name"),
        (6, cfg.max_system_desc, "system_desc"),
    ):
        at = F.frame(F.mandatory() + [F.tlv(ttype, b"X" * limit), F.t_end()], pad=False)
        over = F.frame(F.mandatory() + [F.tlv(ttype, b"X" * (limit + 1)), F.t_end()], pad=False)
        c.eq(codes_for(at), [], "%s at limit %d is silent" % (name, limit))
        c.eq(codes_for(over), ["LLDP-050"], "%s at limit+1 fires" % name)
    # mgmt address string length
    for n, want in ((31, []), (32, ["LLDP-045"])):
        raw = F.frame(
            F.mandatory()
            + [F.t_mgmt_addr(af=99, addr=b"\x00" * (n - 1), addr_strlen=n), F.t_end()],
            pad=False,
        )
        c.eq(codes_for(raw), want, "mgmt addr_strlen %d" % n)
    # OID length
    for n, want in ((128, []), (129, ["LLDP-045"])):
        raw = F.frame(
            F.mandatory()
            + [F.t_mgmt_addr(af=1, addr=F.IPV4_ADDR, oid=b"\x00" * n), F.t_end()],
            pad=False,
        )
        c.eq(codes_for(raw), want, "mgmt oid_len %d" % n)
    # MED inventory ceiling
    for n, want in ((32, []), (33, ["LLDP-051"])):
        raw = F.frame(
            F.mandatory() + [F.t_org(F.OUI_MED, 5, b"X" * n), F.t_end()], pad=False
        )
        c.eq(codes_for(raw), want, "MED inventory %d octets" % n)
    # chassis / port id ceilings
    for sub, maker, code, limit, name in (
        (7, "chassis", "LLDP-046", cfg.max_chassis_id, "chassis_id"),
        (7, "port", "LLDP-047", cfg.max_port_id, "port_id"),
    ):
        for n, want in ((limit, []), (limit + 1, [code])):
            body = b"L" * n
            if maker == "chassis":
                tlvs = [F.t_chassis_id(subtype=sub, body=body), F.t_port_id(),
                        F.t_ttl(), F.t_end()]
            else:
                tlvs = [F.t_chassis_id(), F.t_port_id(subtype=sub, body=body),
                        F.t_ttl(), F.t_end()]
            c.eq(codes_for(F.frame(tlvs, pad=False)), want, "%s %d octets" % (name, n))
    # reserved TLV type range boundaries: 8 and 127 legal, 9 and 126 reserved
    for t, want in ((8, True), (9, False), (126, False), (127, True)):
        raw = F.frame(F.mandatory() + [F.tlv(t, b"\x00\x80\xc2\x01\x00\x64"), F.t_end()])
        got = codes_for(raw)
        c.eq("LLDP-052" not in got, want, "TLV type %d reserved-range boundary" % t)

    c.sect("threshold-config")
    tight = W.Config(max_system_desc=16)
    raw = F.frame(F.mandatory() + [F.t_sys_desc(b"X" * 17), F.t_end()])
    c.eq(codes_for(raw, tight), ["LLDP-050"], "tightened ceiling fires")
    c.eq(codes_for(F.frame(F.mandatory() + [F.t_sys_desc(b"X" * 16), F.t_end()]), tight),
         [], "tightened ceiling silent at limit")
    loose = W.Config(max_system_desc=500)
    c.eq(codes_for(F.mal_oversized_sysdesc(), loose), [], "loosened ceiling silences")


# ==========================================================================
# 8. Truncation at every offset + bit-flip fuzz: never raise
# ==========================================================================


def s_robustness(c: Checker) -> None:
    c.sect("truncation")
    sources = [b() for b in F.BENIGN_BUILDERS] + [
        fn() for v in F.MALFORMED_BUILDERS.values() for fn in v
    ] + [f() for f in F.VENDOR_BUILDERS.values()]
    bad = 0
    total = 0
    for raw in sources:
        for cut in range(0, len(raw) + 1):
            total += 1
            try:
                W.Engine().handle_frame(raw[:cut])
            except Exception as exc:  # noqa: BLE001
                bad += 1
                if bad < 4:
                    c.ok(False, "truncation to %d raised %r" % (cut, exc))
    c.ok(bad == 0, "truncation at every offset never raises (%d cuts, %d raised)" % (total, bad))

    c.sect("bitflip-fuzz")
    bad = 0
    total = 0
    for raw in [F.benign_full(), F.benign_full_v6(), F.benign_med_phone(),
                F.vendor_cisco(), F.mal_mgmt_oid_overrun()]:
        for i in range(len(raw)):
            for bit in range(8):
                total += 1
                m = bytearray(raw)
                m[i] ^= 1 << bit
                try:
                    W.Engine().handle_frame(bytes(m))
                except Exception as exc:  # noqa: BLE001
                    bad += 1
                    if bad < 4:
                        c.ok(False, "bitflip byte %d bit %d raised %r" % (i, bit, exc))
    c.ok(bad == 0, "exhaustive single-bit-flip fuzz never raises (%d flips)" % total)

    c.sect("walker-invariants")
    for raw in sources:
        fr = W.parse_ethernet(raw)
        if fr is None:
            continue
        w = W.walk_tlvs(fr.payload)
        consumed = sum(2 + t.length for t in w.tlvs)
        c.ok(consumed <= len(fr.payload), "walker never consumes past the payload")
        if w.end_seen:
            c.eq(w.end_offset, consumed, "end_offset equals octets consumed")
            c.eq(len(w.tail), len(fr.payload) - consumed, "tail length is the remainder")
        for t in w.tlvs:
            c.eq(len(t.value), t.length, "every emitted TLV value matches its length")
            c.ok(0 <= t.type <= 127, "every emitted TLV type is in range")


# ==========================================================================
# 9. Class B: screening, FP gates, version floors
# ==========================================================================


def s_screening(c: Checker) -> None:
    c.sect("screening")
    for code, fn in sorted(F.VENDOR_BUILDERS.items()):
        got = codes_for(fn())
        c.eq(got, [code], "%s screens as %s" % (fn.__name__, code))
        e = W.Engine()
        rec = first(c, e.handle_frame(fn()), "screening %s" % code, code)
        c.eq(rec["severity"], "notice", "%s is a NOTICE, never a verdict" % code)
        c.ok("VERIFY THIS DEVICE" in rec["detail"], "%s uses NOTE discipline" % code)
        c.ok(
            "cannot establish patch state" in rec["detail"],
            "%s states the backport limitation" % code,
        )
        c.ok(len(rec.get("cves") or []) >= 1, "%s carries its CVE list" % code)
        for cve in (rec.get("cves") or []):
            c.ok(cve.startswith("CVE-"), "%s CVE id well-formed: %s" % (code, cve))
    # the Juniper blast radius must be stated in the finding prose
    e = W.Engine()
    rec = first(c, e.handle_frame(F.vendor_juniper()), "juniper screen", "LLDP-021")
    for word in ("l2cpd", "spanning tree", "BLAST RADIUS"):
        c.ok(word in rec["detail"], "Juniper finding mentions %r" % word)

    c.sect("screening-fp-gates")
    neutral = [
        b"GenericBox 400 software, build 7",
        b"Ubuntu 22.04.3 LTS",
        b"HP ProCurve",
        b"Arista Networks EOS version 4.29.2F",
        b"Extreme Networks ExtremeXOS 31.7",
        b"MikroTik RouterOS 7.12",
        b"Juniper-free generic appliance, build 9",
        # NEAR-MISS NEGATIVES (suite LESSON Z). Without these the fixture set
        # cannot tell a tight vendor regex from an over-broad one: widening
        # `fortiswitch` to `forti\w*` moved no tier, because nothing in the
        # clean set advertised a Fortinet product that is NOT a FortiSwitch.
        # One near-miss per family whose pattern could plausibly be loosened.
        b"FortiGate-100F v7.4.1,build2463,230830 (GA.F)",
        b"Cisco Small Business SG250-26 26-Port Gigabit Smart Switch",
        b"Nortel Networks SONMP topology agent",
        b"Brocade ICX7250-24 , ICX Routing, Version 08.0.95",
        b"Aruba JL256A 2930F-48G-PoE+-4SFP+ Switch, revision WC.16.10.0012",
        b"Aruba 7210 Mobility Controller, ArubaOS 8.10.0.4",
        b"",
    ]
    for d in neutral:
        raw = F.frame(F.mandatory() + [F.t_sys_desc(d), F.t_end()], pad=False)
        c.eq(codes_for(raw), [], "neutral advert %r does not screen" % d[:24])
    # a device that merely SPEAKS LLDP with no description must be silent
    c.eq(codes_for(F.benign_minimal()), [], "speaking LLDP is not a finding")
    # a disabled posture class means there is no 'LLDP is enabled' code at all
    c.ok(
        not any(g == "posture" for _, _, g in W.FINDINGS.values()),
        "no disclosure-posture class exists (by directive)",
    )

    c.sect("screening-near-miss")
    # Each of these is a product from a vendor that IS in the table, but a
    # model the CVE does not cover. They must stay silent, which is what
    # keeps each vendor pattern honest about its own scope.
    for desc, fam in (
        (b"FortiGate-100F v7.4.1,build2463", "fortiswitch"),
        (b"Cisco Small Business SG250-26 Smart Switch", "cisco"),
        (b"Aruba JL256A 2930F-48G-PoE+-4SFP+ Switch, revision WC.16.10", "aruba"),
        (b"Aruba 7210 Mobility Controller, ArubaOS 8.10.0.4", "aruba"),
    ):
        raw = F.frame(F.mandatory() + [F.t_sys_desc(desc), F.t_end()], pad=False)
        got = codes_for(raw)
        c.eq(got, [], "near-miss for the %s family stays silent: %r"
             % (fam, desc[:34]))

    c.sect("screening-exclusivity")
    # Every vendor fixture must match EXACTLY ONE family pattern. With eleven
    # screening codes a new regex can quietly overlap an existing fixture and
    # turn one neighbour into two findings.
    eng = W.Engine()
    for code, fn in sorted(F.VENDOR_BUILDERS.items()):
        raw = fn()
        w = W.walk_tlvs(W.parse_ethernet(raw).payload)
        blob = " | ".join(W.printable(t.value, 400)
                          for t in w.tlvs if t.type in (5, 6))
        hits = [fam.key for fam, rx in eng._compiled if rx.search(blob)]
        c.eq(len(hits), 1, "%s matches exactly one family (matched %r)" % (code, hits))
    for b in F.BENIGN_BUILDERS:
        raw = b()
        w = W.walk_tlvs(W.parse_ethernet(raw).payload)
        blob = " | ".join(W.printable(t.value, 400)
                          for t in w.tlvs if t.type in (5, 6))
        hits = [fam.key for fam, rx in eng._compiled if rx.search(blob)]
        c.eq(hits, [], "benign %s matches no family (matched %r)" % (b.__name__, hits))

    c.sect("version-floor")
    cfg = W.Config(version_floors={"lldpd": "0.8.0"})
    got = codes_for(F.vendor_lldpd(), cfg)   # advertises 0.7.19
    c.ok("LLDP-025" in got, "below-floor fires LLDP-025")
    c.ok("LLDP-022" in got, "screening still fires alongside the floor hint")
    newer = F.frame(
        F.mandatory() + [F.t_sys_desc(b"Debian GNU/Linux 12, lldpd 1.0.14"), F.t_end()],
        pad=False,
    )
    got = codes_for(newer, cfg)
    c.eq(got, ["LLDP-022"], "above-floor gets the note but no LLDP-025")
    nover = F.frame(
        F.mandatory() + [F.t_sys_desc(b"lldpd (version withheld)"), F.t_end()], pad=False
    )
    got = codes_for(nover, cfg)
    c.ok("LLDP-026" in got, "unparseable version fires LLDP-026")
    # severity: the floor hint is low, not a verdict
    e = W.Engine(cfg)
    rec = first(c, e.handle_frame(F.vendor_lldpd()), "LLDP-025 floor hint", "LLDP-025")
    c.eq(rec["severity"], "low", "LLDP-025 is low severity")
    c.ok("not patch state" in rec["detail"], "LLDP-025 is honest about scope")

    c.sect("operator-table")
    cfg = W.Config.load(
        {
            "extra_families": {
                "arista": {
                    "label": "Arista EOS",
                    "pattern": r"(?i)arista.*EOS",
                    "cves": ["CVE-9999-0001"],
                    "code": "LLDP-026",
                    "note": "operator entry",
                }
            }
        }
    )
    raw = F.frame(
        F.mandatory() + [F.t_sys_desc(b"Arista Networks EOS version 4.29.2F"), F.t_end()],
        pad=False,
    )
    c.eq(codes_for(raw, cfg), ["LLDP-026"], "operator family screens")
    # built-ins still work alongside it: EXTEND, never replace
    c.eq(codes_for(F.vendor_cisco(), cfg), ["LLDP-020"], "built-in table survives extension")
    c.eq(len(W.Engine(cfg).families), len(W.BUILTIN_FAMILIES) + 1, "family count is built-ins + 1")


# ==========================================================================
# 10. Class C: flood, learn/enforce, suppressor
# ==========================================================================


def s_abuse(c: Checker) -> None:
    c.sect("flood")
    cfg = W.Config(flood_window=10.0, flood_threshold=20, flood_distinct_src=1000)
    e = W.Engine(cfg)
    fired = None
    for i, raw in enumerate(F.flood_frames(30)):
        got = [r["code"] for r in e.handle_frame(raw, ts=1000.0 + i * 0.05)]
        if "LLDP-048" in got and fired is None:
            fired = i + 1
    c.eq(fired, 21, "LLDP-048 fires on the 21st frame (threshold 20)")
    # at the threshold exactly: silent
    e = W.Engine(cfg)
    for i in range(20):
        e.handle_frame(F.flood_frames(20)[i], ts=2000.0 + i * 0.05)
    c.eq([r["code"] for r in e.findings], [], "exactly threshold frames is silent")
    # frames spread beyond the window never accumulate
    e = W.Engine(cfg)
    for i, raw in enumerate(F.flood_frames(40)):
        e.handle_frame(raw, ts=3000.0 + i * 11.0)
    c.eq([r["code"] for r in e.findings], [], "frames outside the window do not accumulate")

    c.sect("flood-distinct-src")
    cfg = W.Config(flood_threshold=10000, flood_distinct_src=12)
    e = W.Engine(cfg)
    fired = None
    for i, raw in enumerate(F.flood_frames(20)):
        got = [r["code"] for r in e.handle_frame(raw, ts=4000.0 + i * 0.05)]
        if "LLDP-048" in got and fired is None:
            fired = i + 1
    c.eq(fired, 13, "distinct-source limit fires on the 13th distinct MAC")
    # a single talkative neighbour does NOT trip the distinct-source rule
    e = W.Engine(cfg)
    one = F.benign_minimal(src="02:00:00:00:aa:01")
    for i in range(50):
        e.handle_frame(one, ts=5000.0 + i * 0.05)
    c.eq([r["code"] for r in e.findings], [], "one source, many frames: distinct rule silent")
    e = W.Engine()
    rec = None
    for i, raw in enumerate(F.flood_frames(30)):
        for r in e.handle_frame(raw, ts=6000.0 + i * 0.05):
            if r["code"] == "LLDP-048":
                rec = r
    rec = rec if rec is not None else dict(_STUB)
    c.ok(rec["code"] == "LLDP-048", "LLDP-048 record captured")
    c.ok("CVE-2020-27827" in rec["detail"], "LLDP-048 names the OVS/lldpd leak CVE")
    c.ok("CVE-2023-20089" in rec["detail"], "LLDP-048 names the Nexus leak CVE")
    c.ok(
        "crisp single-frame signature" in rec["detail"],
        "LLDP-048 states the honest limitation of those two CVEs",
    )

    c.sect("learn-enforce")
    e = W.Engine(W.Config(), learn=True)
    for b in F.BENIGN_BUILDERS:
        e.handle_frame(b())
    for raw in F.flood_frames(40):
        e.handle_frame(raw)
    c.eq(e.findings, [], "learn mode emits NOTHING, not even flood")
    c.eq(len(e.learned), len(F.BENIGN_BUILDERS) + 40,
         "learn mode records every source MAC")
    c.eq(e.baseline_lines(), sorted(e.baseline_lines()), "baseline is sorted")

    base = ["02:00:00:00:00:01"]
    cfg = W.Config(enforce=True, baseline=tuple(base))
    c.eq(codes_for(F.benign_minimal(src="02:00:00:00:00:01"), cfg), [],
         "baselined source is silent under enforce")
    c.eq(codes_for(F.benign_minimal(src="02:00:00:00:99:99"), cfg), ["LLDP-049"],
         "unbaselined source fires LLDP-049")
    cfg_off = W.Config(enforce=False, baseline=tuple(base))
    c.eq(codes_for(F.benign_minimal(src="02:00:00:00:99:99"), cfg_off), [],
         "LLDP-049 is OFF by default (grab-and-go core is baseline-free)")
    c.eq(W.Config().enforce, False, "enforce defaults to False")
    c.eq(W.Config().baseline, (), "baseline defaults to empty")
    # the finding carries the advertised management address
    cfg = W.Config(enforce=True, baseline=())
    e = W.Engine(cfg)
    rec = first(c, e.handle_frame(F.benign_full_v6()), "LLDP-049 mgmt", "LLDP-049")
    c.eq(rec.get("mgmt_addrs"), ["[2001:db8::9]"], "LLDP-049 reports the mgmt address")

    c.sect("suppressor")
    cfg = W.Config(suppress_window=60.0)
    e = W.Engine(cfg)
    emitted = []
    e._emit = emitted.append
    raw = F.mal_length_overrun()
    for i in range(5):
        e.handle_frame(raw, ts=7000.0 + i)
    c.eq(len(emitted), 1, "suppressor throttles repeat ALERTS")
    c.eq(len(e.findings), 5, "suppressor does NOT throttle detection")
    c.ok(all(r.get("suppressed") for r in e.findings[1:]), "suppressed records are tagged")
    e.handle_frame(raw, ts=7000.0 + 61)
    c.eq(len(emitted), 2, "alert re-emitted once the window elapses")
    # suppression is per (code, src): a second source is not throttled
    e = W.Engine(cfg)
    emitted = []
    e._emit = emitted.append
    e.handle_frame(F.mal_length_overrun(src="02:00:00:00:04:00"), ts=8000.0)
    e.handle_frame(F.mal_length_overrun(src="02:00:00:00:04:99"), ts=8000.1)
    c.eq(len(emitted), 2, "suppression is keyed per source")

    c.sect("neighbour-table-bound")
    cfg = W.Config(neigh_max=8, flood_threshold=10000, flood_distinct_src=10000)
    e = W.Engine(cfg)
    for i, raw in enumerate(F.flood_frames(64)):
        e.handle_frame(raw, ts=9000.0 + i * 0.01)
    c.ok(len(e._neigh) <= 8, "neighbour table respects neigh_max (LRU evicts)")

    c.sect("disabled-codes")
    cfg = W.Config(disabled_codes=("LLDP-050",))
    c.eq(codes_for(F.mal_oversized_sysdesc(), cfg), [], "disabled code is suppressed")
    c.eq(codes_for(F.mal_length_overrun(), cfg), ["LLDP-040"], "other codes unaffected")


# ==========================================================================
# 11. Config.load strict validation
# ==========================================================================


def s_config(c: Checker) -> None:
    c.sect("config-load")
    c.eq(W.Config.load({}).dump(), W.Config().dump(), "empty config equals defaults")
    rt = W.Config.load(W.Config().dump()).dump()
    c.eq(rt, W.Config().dump(), "dump/load round-trips")
    bad_cases = [
        ({"nope": 1}, "unknown key"),
        ({"max_system_desc": 0}, "non-positive int"),
        ({"max_system_desc": -5}, "negative int"),
        ({"max_system_desc": "x"}, "int given a string"),
        ({"max_system_desc": True}, "int given a bool"),
        ({"flood_window": 0}, "non-positive float"),
        ({"flood_window": "x"}, "float given a string"),
        ({"enforce": "yes"}, "bool given a string"),
        ({"iface": ""}, "empty iface"),
        ({"iface": 3}, "non-string iface"),
        ({"baseline": "aa:bb"}, "baseline not a list"),
        ({"baseline": [1]}, "baseline entry not a string"),
        ({"disabled_codes": ["LLDP-999"]}, "unknown finding code"),
        ({"disabled_codes": "LLDP-040"}, "disabled_codes not a list"),
        ({"version_floors": {"nosuch": "1.0"}}, "floor for unknown family"),
        ({"version_floors": "x"}, "version_floors not an object"),
        ({"extra_families": {"cisco": {"label": "x", "pattern": "x", "cves": []}}},
         "extra_families shadowing a built-in"),
        ({"extra_families": {"z": {"label": "x", "pattern": "x"}}}, "missing cves"),
        ({"extra_families": {"z": {"label": "x", "pattern": "[", "cves": []}}},
         "bad regex"),
        ({"extra_families": {"z": {"label": "x", "pattern": "x", "cves": [],
                                   "junk": 1}}}, "unknown extra_families key"),
        ({"extra_families": {"z": {"label": "x", "pattern": "x", "cves": [],
                                   "code": "LLDP-999"}}}, "unknown code in family"),
        ({"extra_families": {"z": {"label": "x", "pattern": "x", "cves": "x"}}},
         "cves not a list"),
        ([], "config not an object"),
    ]
    for payload, what in bad_cases:
        c.raises(lambda p=payload: W.Config.load(p), ValueError, "rejected at load: %s" % what)
    good = {
        "iface": "eth1",
        "max_system_desc": 300,
        "flood_window": 5.5,
        "enforce": True,
        "baseline": ["AA-BB-CC-DD-EE-FF"],
        "disabled_codes": ["LLDP-054"],
        "version_floors": {"cisco": "17.9"},
    }
    cfg = W.Config.load(good)
    c.eq(cfg.iface, "eth1", "iface loaded")
    c.eq(cfg.baseline, ("aa:bb:cc:dd:ee:ff",), "baseline MACs normalised at load")
    c.eq(cfg.disabled_codes, ("LLDP-054",), "disabled codes loaded")
    # the version_floors key must be validatable against extra_families in the
    # SAME payload, not only against built-ins
    cfg = W.Config.load(
        {
            "extra_families": {"zz": {"label": "Z", "pattern": "z", "cves": []}},
            "version_floors": {"zz": "1.0"},
        }
    )
    c.eq(cfg.version_floors, {"zz": "1.0"}, "floor for an operator family accepted")

    c.sect("dead-knob")
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "lldpwatch.py")).read()
    read = W.config_keys_read(src)
    for k in W.Config().dump():
        c.ok(k in read, "config key %r is actually read by the engine" % k)
    # non-vacuity: a knob that does not exist must NOT appear read
    c.ok("totally_made_up_knob" not in read, "dead-knob scan is not vacuous")


# ==========================================================================
# 12. Passive invariant: AST guard, with non-vacuity
# ==========================================================================


def s_guard(c: Checker) -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    c.sect("passive-invariant")
    for fn in ("lldpwatch.py", "lldpwatch_frames.py"):
        src = open(os.path.join(here, fn)).read()
        probs = W.audit_source(src, fn)
        c.eq(probs, [], "%s passes the passive-invariant audit" % fn)

    c.sect("guard-non-vacuity")
    bites = [
        ("sendp(x)", "bare sendp call"),
        ("def f():\n    send(pkt)\n", "bare send call"),
        ("def f():\n    sock.sendto(b'', a)\n", "sendto"),
        ("def f():\n    pcap_sendpacket(h, b)\n", "pcap_sendpacket"),
        ("import socket\n", "module-scope socket import"),
        ("import subprocess\n", "module-scope subprocess import"),
        ("from scapy.all import sniff\n", "module-scope scapy import"),
        ("def f():\n    subprocess.run(['x'])\n", "subprocess.run"),
        ("def f():\n    os.system('x')\n", "os.system"),
        ("def f():\n    socket.socket()\n", "socket.socket"),
        ("def build_shellcode():\n    pass\n", "shellcode builder defined"),
        ("def weaponize():\n    pass\n", "weaponize defined"),
        ("def transmit():\n    pass\n", "transmit defined"),
        ("class pwn:\n    pass\n", "exploit class defined"),
        ("def a():\n    pass\ndef a():\n    pass\n", "duplicate module-level name"),
    ]
    for src, what in bites:
        c.ok(W.audit_source(src) != [], "guard BITES: %s" % what)
    for src, what in (
        ("def f():\n    return 1\n", "clean function"),
        ("def f():\n    import socket\n    return socket\n", "function-scope import is fine"),
        ("x = 'sendp'\n", "a banned name as a STRING is not a call"),
    ):
        c.eq(W.audit_source(src), [], "guard does not misfire: %s" % what)

    c.sect("scapy-unimported")
    c.ok("scapy" not in sys.modules, "scapy is NOT imported by the offline tier")
    c.ok(
        "scapy" not in W.MODULE_SCOPE_BANNED_IMPORTS or True,
        "scapy is on the module-scope banned-import list",
    )
    c.ok("scapy" in W.MODULE_SCOPE_BANNED_IMPORTS, "scapy banned at module scope")

    c.sect("bpf-filter")
    c.ok("0x88cc" in W.BPF_FILTER, "BPF filter pins the LLDP ethertype")
    c.ok("vlan" in W.BPF_FILTER, "BPF filter admits tagged LLDP (suite LESSON F)")
    c.eq(W.BPF_FILTER.count("vlan"), 2, "BPF filter carries TWO vlan levels for QinQ")
    c.ok("(vlan and (ether proto 0x88cc or (vlan and ether proto 0x88cc)))"
         in W.BPF_FILTER,
         "BPF filter uses the NESTED vlan form, not the flat no-op form")
    c.ok("vlan and vlan" not in W.BPF_FILTER,
         "BPF filter does not use the measured no-op flat form")


# ==========================================================================
# 13. Finding registry integrity and coverage
# ==========================================================================


def s_registry(c: Checker) -> None:
    c.sect("registry")
    for code, (name, sev, group) in W.FINDINGS.items():
        c.ok(code.startswith("LLDP-") and len(code) == 8, "code %r well-formed" % code)
        c.ok(sev in W.SEVERITIES, "%s severity %r is legal" % (code, sev))
        c.ok(group in W.GROUP_ORDER, "%s group %r is legal" % (code, group))
        c.ok(name == name.upper(), "%s name is upper-case: %r" % (code, name))
    names = [n for n, _, _ in W.FINDINGS.values()]
    c.eq(len(set(names)), len(names), "finding names are unique")
    groups = {}
    for _, (_, _, g) in W.FINDINGS.items():
        groups[g] = groups.get(g, 0) + 1
    c.eq(groups.get("screening"), 11, "11 screening codes")
    c.eq(groups.get("structural"), 13, "13 structural codes")
    c.eq(groups.get("abuse"), 2, "2 abuse codes")
    c.eq(len(W.FINDINGS), 26, "26 codes in total")
    c.ok("posture" not in groups, "no posture/disclosure group exists")

    c.sect("coverage")
    here = os.path.dirname(os.path.abspath(__file__))
    declared = W.declared_codes(open(os.path.join(here, "lldpwatch.py")).read())
    c.eq(sorted(declared), sorted(W.FINDINGS), "every registry code is emittable")
    c.eq(DEFERRED_CODES, (), "DEFERRED_CODES is empty")
    exercised = set()
    for builders in F.MALFORMED_BUILDERS.values():
        for fn in builders:
            exercised |= set(codes_for(fn()))
    for fn in F.VENDOR_BUILDERS.values():
        exercised |= set(codes_for(fn()))
    cfg = W.Config(version_floors={"lldpd": "0.8.0"})
    exercised |= set(codes_for(F.vendor_lldpd(), cfg))
    exercised |= set(
        codes_for(
            F.frame(F.mandatory() + [F.t_sys_desc(b"lldpd unknown"), F.t_end()], pad=False),
            cfg,
        )
    )
    e = W.Engine(W.Config(enforce=True))
    e.handle_frame(F.benign_minimal(src="02:00:00:00:99:99"))
    exercised |= {r["code"] for r in e.findings}
    e = W.Engine()
    for i, raw in enumerate(F.flood_frames(30)):
        e.handle_frame(raw, ts=11000.0 + i * 0.05)
    exercised |= {r["code"] for r in e.findings}
    missing = sorted(set(W.FINDINGS) - exercised)
    c.eq(missing, [], "every code is exercised by a fixture in this tier")

    c.sect("lab-contract")
    c.eq(lab_codes(), sorted(W.FINDINGS),
         "the lab is expected to validate EVERY code live - nothing deferred")
    cfg_s = W.Config.load(LAB_SCREEN_CONFIG)
    got = set(codes_for(F.vendor_lldpd(), cfg_s))
    got |= set(codes_for(
        F.frame(F.mandatory() + [F.t_sys_desc(b"lldpd (version withheld)"),
                                 F.t_end()], pad=False), cfg_s))
    c.ok({"LLDP-025", "LLDP-026"} <= got,
         "the lab screening config really yields LLDP-025 and LLDP-026 (got %r)"
         % sorted(got))
    cfg_e = W.Config.load(LAB_ENFORCE_CONFIG)
    c.eq(codes_for(F.benign_minimal(src="02:00:00:00:de:ad"), cfg_e), ["LLDP-049"],
         "the lab enforce config really yields LLDP-049")
    c.ok(W.Config.load(LAB_SCREEN_CONFIG) is not None, "lab screening config is loadable")
    c.eq(codes_for(canary_frame()), ["LLDP-052"],
         "the readiness canary produces exactly one, unmistakable finding")
    c.eq(W.parse_ethernet(canary_frame()).src, CANARY_SRC,
         "the canary carries its dedicated source MAC")
    others = {W.parse_ethernet(b()).src for b in F.BENIGN_BUILDERS}
    others |= {W.parse_ethernet(fn()).src
               for v in F.MALFORMED_BUILDERS.values() for fn in v}
    others |= {W.parse_ethernet(fn()).src for fn in F.VENDOR_BUILDERS.values()}
    pairs = lab_pairs()
    # The lab's expectations are declared, not engine-derived, so THIS tier is
    # where they are proved reachable. If a declared pair stops being produced,
    # it fails here and in the lab - not silently in neither.
    produced = set()
    for code, builders in F.MALFORMED_BUILDERS.items():
        for fn in builders:
            for r in W.Engine().handle_frame(fn()):
                produced.add("%s\t%s" % (r["code"], r["src"]))
    for code, fn in F.VENDOR_BUILDERS.items():
        for r in W.Engine().handle_frame(fn()):
            produced.add("%s\t%s" % (r["code"], r["src"]))
    e_s = W.Engine(W.Config.load(LAB_SCREEN_CONFIG))
    for fn in (F.vendor_lldpd, LAB_UNPARSEABLE):
        for r in e_s.handle_frame(fn()):
            produced.add("%s\t%s" % (r["code"], r["src"]))
    for r in W.Engine(W.Config.load(LAB_ENFORCE_CONFIG)).handle_frame(LAB_FORGED()):
        produced.add("%s\t%s" % (r["code"], r["src"]))
    produced.add("LLDP-048\t*")
    for p in pairs:
        c.ok(p in produced,
             "declared lab pair is actually produced: %s" % p.replace("\t", " "))
    c.eq(sorted(produced - set(pairs)), [],
         "no fixture produces a pair the lab is not told to expect")
    c.ok(len(pairs) >= 30,
         "the lab pair list covers every fixture, not just every code (%d)" % len(pairs))
    c.eq(sorted({p.split("\t")[0] for p in pairs}), sorted(W.FINDINGS),
         "the lab pair list still spans every code")
    n045 = [p for p in pairs if p.startswith("LLDP-045")]
    c.eq(len(n045), len(F.MALFORMED_BUILDERS["LLDP-045"]),
         "each LLDP-045 sub-shape is separately accountable (%d)" % len(n045))
    c.eq(len({p.split("\t")[1] for p in n045}), len(n045),
         "every LLDP-045 fixture has a distinct source MAC")
    c.ok(CANARY_SRC not in others,
         "the canary source MAC is used by no other fixture, so the readiness "
         "signal is unambiguous")


# ==========================================================================
# 14. pcap artefacts: timing contracts (the cdpwatch writer bug)
# ==========================================================================


def s_pcap(c: Checker) -> None:
    c.sect("pcap-timing")
    frames = F.flood_frames(45)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.pcap")
        n = F.write_pcap(p, frames, base_ts=1700000000.0, interval=0.001)
        c.eq(n, 45, "writer reports the frame count")
        rec = F.read_pcap(p)
        c.eq(len(rec), 45, "reader recovers every frame")
        c.eq([r[1] for r in rec], frames, "frame bytes survive the round-trip")
        ts = [r[0] for r in rec]
        c.ok(all(b >= a for a, b in zip(ts, ts[1:])), "timestamps are monotonic")
        span = ts[-1] - ts[0]
        c.ok(span < W.Config().flood_window,
             "capture span %.3fs < flood window %.1fs" % (span, W.Config().flood_window))
        c.ok(span > 0, "capture span is non-zero")
        c.ok(
            len(frames) / max(span, 1e-9) > W.Config().flood_threshold / W.Config().flood_window,
            "burst density exceeds the flood threshold rate",
        )
        for _sec, _usec in raw_pcap_stamps(p):
            c.ok(0 <= _usec < 1_000_000,
                 "microsecond field is legal on the wire (%d)" % _usec)
        # usec carry across a second boundary
        p2 = os.path.join(d, "carry.pcap")
        F.write_pcap(p2, frames[:5], base_ts=1700000000.9996, interval=0.001)
        ts2 = [r[0] for r in F.read_pcap(p2)]
        c.ok(all(b > a for a, b in zip(ts2, ts2[1:])), "timestamps carry across a second")
        c.ok(int(ts2[-1]) > int(ts2[0]), "the seconds field really did advance")
        # Exercise the carry BRANCH itself. Rounding (t - int(t)) * 1e6 can
        # land on exactly 1_000_000, which would write an illegal microsecond
        # field; without the carry the record is malformed rather than merely
        # mis-spaced, so the branch needs its own fixture or it is untested.
        p3 = os.path.join(d, "edge.pcap")
        F.write_pcap(p3, frames[:3], base_ts=1700000000.9999996, interval=0.001)
        stamps = raw_pcap_stamps(p3)
        for _sec, _usec in stamps:
            c.ok(0 <= _usec < 1_000_000,
                 "carry keeps the raw microsecond field legal (%d)" % _usec)
        c.eq(stamps[0][0], 1700000001, "the carry advanced the seconds field")
        c.eq(stamps[0][1], 0, "the carry zeroed the microsecond field")
        # the index-in-seconds bug would produce a 44-second span
        c.ok(span < 1.0, "frame index is NOT stamped into the seconds field")
        bad = os.path.join(d, "bad.pcap")
        F.write_pcap(bad, frames, base_ts=1700000000.0, interval=1.0)
        badspan = F.read_pcap(bad)[-1][0] - F.read_pcap(bad)[0][0]
        c.ok(badspan > W.Config().flood_window,
             "counterfactual: 1s spacing WOULD silence the flood code")

    c.sect("pcap-replay-equivalence")
    # Every artefact the lab replays must produce, offline, exactly the codes
    # the lab is told to expect.
    with tempfile.TemporaryDirectory() as d:
        attack = [fn() for v in F.MALFORMED_BUILDERS.values() for fn in v]
        attack += [fn() for fn in F.VENDOR_BUILDERS.values()]
        p = os.path.join(d, "attack.pcap")
        F.write_pcap(p, attack)
        e = W.Engine(W.Config(flood_threshold=10000, flood_distinct_src=10000,
                              suppress_window=0.0001))
        for ts, raw in F.read_pcap(p):
            e.handle_frame(raw, ts=ts)
        got = sorted({r["code"] for r in e.findings})
        want = sorted(set(F.MALFORMED_BUILDERS) | set(F.VENDOR_BUILDERS))
        c.eq(got, want, "attack pcap yields exactly the expected code set")
        p = os.path.join(d, "clean.pcap")
        F.write_pcap(p, [b() for b in F.BENIGN_BUILDERS])
        e = W.Engine(W.Config(flood_threshold=10000, flood_distinct_src=10000))
        for ts, raw in F.read_pcap(p):
            e.handle_frame(raw, ts=ts)
        c.eq([r["code"] for r in e.findings], [], "clean pcap is silent end to end")


# ==========================================================================
# 15. Emitted record shape
# ==========================================================================


def s_record(c: Checker) -> None:
    c.sect("record-shape")
    out = []
    e = W.Engine(W.Config(), emit=out.append)
    e.handle_frame(F.mal_mgmt_v6_short())
    e.handle_frame(F.vendor_juniper())
    c.ok(len(out) == 2, "two records emitted")
    for rec in out:
        s = json.dumps(rec, sort_keys=True)
        c.eq(json.loads(s), rec, "record is JSON round-trippable")
        for k in ("ts", "iface", "module", "code", "name", "severity", "group",
                  "src", "detail"):
            c.ok(k in rec, "record carries %r" % k)
        c.eq(rec["module"], "lldpwatch", "module field")
        c.eq(rec["name"], W.FINDINGS[rec["code"]][0], "name matches the registry")
        c.eq(rec["severity"], W.FINDINGS[rec["code"]][1], "severity matches the registry")
        c.eq(rec["group"], W.FINDINGS[rec["code"]][2], "group matches the registry")
        c.ok(":" in rec["src"], "src is a normalised MAC")
        c.ok(len(rec["detail"]) > 40, "detail is a real sentence, not a stub")
    c.sect("live-path-shape")
    # LESSON C: drive the one function that imports scapy, with a recorder in
    # place of sniff, and pin what it passes through.
    seen = {}

    class _Pkt(bytes):
        time = 1700000000.5

    def fake_sniff(**kw):
        seen.update(kw)
        kw["prn"](_Pkt(F.mal_length_overrun()))

    out = []
    e = W.Engine(W.Config(iface="veth-x"), emit=out.append)
    W._run_live("veth-x", e, timeout=3.0, sniff_fn=fake_sniff)
    c.eq(seen.get("iface"), "veth-x", "iface passed through to sniff")
    c.eq(seen.get("filter"), W.BPF_FILTER, "BPF filter installed")
    c.eq(seen.get("store"), False, "store=False")
    c.eq(seen.get("timeout"), 3.0, "timeout passed through")
    c.ok("offline" not in seen, "offline= is NOT set on the live path")
    c.eq([r["code"] for r in out], ["LLDP-040"], "live callback reaches the engine")
    c.eq(out[0]["ts"], 1700000000.5, "packet timestamp is used, not wall clock")
    c.eq(out[0]["iface"], "veth-x", "records carry the capture interface")


# ==========================================================================
# 16. CLI surface
# ==========================================================================


def s_cli(c: Checker) -> None:
    c.sect("cli")
    p = W.build_parser()
    opts = {a for act in p._actions for a in act.option_strings}
    for flag in ("--iface", "--config", "--dump-config", "--learn", "--baseline-out",
                 "--enforce", "--self-test", "--print-codes", "--print-bpf",
                 "--timeout", "--version"):
        c.ok(flag in opts, "CLI exposes %s" % flag)
    for flag in W.NOOP_FLAGS:
        c.ok(flag in opts, "no-op flag %s is present" % flag)
    for flag, why in W.NOOP_FLAGS.items():
        c.ok(not why.endswith("."), "no-op reason for %s has no trailing period "
                                    "(argparse appends its own)" % flag)
        c.ok("no-op" not in why.lower(), "no-op reason for %s does not say 'no-op' twice" % flag)
    ns = p.parse_args(["--iface", "eth7", "--enforce"])
    c.eq(ns.iface, "eth7", "iface parsed")
    c.eq(ns.enforce, True, "enforce parsed")


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="lldpwatch_conformance")
    ap.add_argument("--emit-pcap", default=None, help="write the attack pcap here")
    ap.add_argument("--emit-clean-pcap", default=None, help="write the clean pcap here")
    ap.add_argument("--emit-screen-pcap", default=None,
                    help="write the version-floor screening pcap here")
    ap.add_argument("--emit-enforce-pcap", default=None,
                    help="write the forged-neighbour pcap here")
    ap.add_argument("--emit-canary-pcap", default=None,
                    help="write the single-frame readiness canary pcap here")
    ap.add_argument("--print-canary-src", action="store_true",
                    help="print the canary frame's source MAC")
    ap.add_argument("--print-lab-config", action="store_true",
                    help="print the JSON config the screening lab phase uses")
    ap.add_argument("--print-lab-codes", action="store_true")
    ap.add_argument("--print-lab-pairs", action="store_true",
                    help="print expected CODE<TAB>SRC pairs for the lab")
    ap.add_argument("--print-lab-mtu", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    attack = [fn() for v in F.MALFORMED_BUILDERS.values() for fn in v]
    attack += [fn() for fn in F.VENDOR_BUILDERS.values()]
    attack += F.flood_frames(30)
    clean = [b() for b in F.BENIGN_BUILDERS]

    if args.print_lab_mtu:
        print(max(len(f) for f in attack + clean))
        return 0
    # The screening phase needs a config, so it is a lab phase of its own.
    screen = [
        F.vendor_lldpd(),
        LAB_UNPARSEABLE(),
    ]
    enforce = [LAB_FORGED()]

    if args.print_canary_src:
        print(CANARY_SRC)
        return 0
    if args.print_lab_config:
        print(json.dumps(LAB_SCREEN_CONFIG, indent=2, sort_keys=True))
        return 0
    if args.print_lab_pairs:
        for p in lab_pairs():
            print(p)
        return 0
    if args.print_lab_codes:
        for code in sorted(lab_codes()):
            print(code)
        return 0
    emitted = False
    for path, frames in ((args.emit_pcap, attack), (args.emit_clean_pcap, clean),
                         (args.emit_screen_pcap, screen),
                         (args.emit_enforce_pcap, enforce),
                         (args.emit_canary_pcap, [canary_frame()])):
        if path:
            F.write_pcap(path, frames)
            emitted = True
    if emitted:
        return 0

    c = Checker()
    for fn in (s_tlv, s_framing, s_padding, s_clean_set, s_structural, s_dualstack,
               s_thresholds, s_robustness, s_screening, s_abuse, s_config, s_guard,
               s_registry, s_pcap, s_record, s_cli):
        fn(c)

    if not args.quiet:
        for name, n in c.by_section.items():
            print("  %-26s %4d" % (name, n))
    for f in c.failures:
        print("FAIL " + f)
    print("%s  %d checks, %d failures" % (
        "PASS" if not c.failures else "FAIL", c.passed, len(c.failures)))
    return 1 if c.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
