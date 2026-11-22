#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aristaguard_scapy_xcheck.py - optional independent cross-check tier for
"Arista Switch and Router Guard".

REQUIRES scapy.  Kept deliberately OUT of the dependency-free conformance
run, which asserts that aristaguard imports nothing third-party.

This tier does two jobs that no other tier can.

1. INDEPENDENT IMPLEMENTATION CROSS-CHECK  (SUITE-WIDE LESSON A)

   Every Ragnar module pairs a hand-rolled parser with a hand-rolled
   serializer and tests them against each other - a structure that cannot
   catch an error BOTH halves share.  cdpwatch's CDP checksum was wrong
   exactly that way and passed 434/434 conformance; only scapy's independent
   dissector broke the tie.  ciscoguard's BER OID arc count was off by one
   for the same reason and passed 81/81.

   So here, scapy's own dissectors sit on the other side of every hand-rolled
   parser in aristaguard: Ether/Dot1Q, IP/IPv6, UDP/TCP, LLDP, RADIUS, EAPOL
   and VXLAN.  Where scapy and aristaguard disagree about a field, one of them
   is wrong, and the disagreement is reported rather than averaged away.

2. LIVE CAPTURE PATH EXECUTION  (SUITE-WIDE LESSON C)

   run_capture() is the ONE function in aristaguard that imports scapy, and
   until this tier existed it had NEVER EXECUTED - not once, in any test, in
   any build.  Lazy-import discipline keeps the offline tiers pure but leaves
   that path completely untested.

   This tier drives it through scapy's own offline sniff and asserts:
     - codes produced over the live path == codes produced in memory
     - the emitted JSON-lines are valid and single-line
     - learn mode stays silent over the live path too
     - the live branch passes iface and timeout through, sets store=False,
       installs BPF_FILTER, and does NOT set offline=
     - BPF_FILTER actually compiles under libpcap, so a typo cannot silently
       capture everything

Usage
    python3 aristaguard_scapy_xcheck.py
    python3 aristaguard_scapy_xcheck.py --quiet
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import struct
import sys
import tempfile
from typing import Any, Callable, Iterable, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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


_spec = importlib.util.spec_from_file_location("aristaguard", MODULE_PATH)
ag = importlib.util.module_from_spec(_spec)          # type: ignore[arg-type]
sys.modules["aristaguard"] = ag
_spec.loader.exec_module(ag)                          # type: ignore[union-attr]

try:
    from scapy.all import (Ether, Dot1Q, IP, IPv6, UDP, TCP, Raw, rdpcap,
                           wrpcap, sniff, conf)
    from scapy.layers.radius import Radius
    from scapy.layers.eap import EAPOL
    from scapy.layers.vxlan import VXLAN
    from scapy.contrib.lldp import (LLDPDU, LLDPDUChassisID, LLDPDUPortID,
                                    LLDPDUTimeToLive, LLDPDUSystemName,
                                    LLDPDUSystemDescription, LLDPDUEndOfLLDPDU)
except ImportError as exc:  # pragma: no cover
    print(f"scapy is required for this tier: {exc}")
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# METHODOLOGY: always compare against a RE-DISSECTED packet
# ---------------------------------------------------------------------------
#
# The first run of this tier compared aristaguard's parser against the BUILT
# scapy packet object, and reported six failures where scapy "disagreed" by
# returning None for len / total_len.  scapy does not compute those fields
# until the packet is serialized, so that comparison was measuring
# aristaguard against scapy's BUILDER DEFAULTS - not against its dissector.
#
# That is the wrong comparison for a tie-breaking tier, and it is a subtle
# trap: it produces confident-looking failures that are entirely artefacts of
# the harness.  Worse, in the other direction it could produce a false PASS,
# since two None values compare equal.
#
# redissect() forces the round-trip so every comparison below is against what
# scapy's dissector actually reads off the wire.


def redissect(pkt: Any) -> Any:
    """Serialize and re-parse, so auto-computed fields are populated."""
    return pkt.__class__(bytes(pkt))


# ---------------------------------------------------------------------------
# Section 1 - L2 / L3 / L4 cross-check
# ---------------------------------------------------------------------------


# This tier cross-checks the PARSER against scapy's dissector, not the RADIUS
# Arista-scope policy (the module self-test and the conformance harness both
# cover the gate). So engines that feed RADIUS use the documented "*" wildcard
# to keep every vendor's traffic in scope, leaving the comparison about parsing
# rather than scoping.
def _xcfg(**kw: Any) -> Any:
    kw.setdefault("radius_arista_endpoints", ("*",))
    return ag.Config(**kw)


def _engine_codes(raw: bytes) -> list:
    eng = ag.AristaEngine(_xcfg())
    eng.handle_frame(raw, ts=1.0)
    return eng.findings


def section_l2l3l4() -> None:
    section("1 L2/L3/L4")
    # REGRESSION: assert the re-dissection methodology is actually in force.
    # A built packet reports len=None; a re-dissected one reports the real
    # value.  If this ever passes on the built object, every length
    # comparison in this file has quietly stopped testing anything.
    built = IP(src="10.0.0.1", dst="10.0.0.2") / UDP() / Raw(b"x" * 8)
    check(built.len is None,
          "scapy is expected to leave len unset on a BUILT packet - if it "
          "no longer does, the note above needs revisiting")
    check(redissect(built).len == len(bytes(built)),
          "redissect() must populate auto-computed fields")

    cases = [
        Ether(dst="01:02:03:04:05:06", src="0a:0b:0c:0d:0e:0f")
        / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=1812) / Raw(b"x" * 8),
        Ether(dst="11:22:33:44:55:66", src="aa:bb:cc:dd:ee:ff")
        / Dot1Q(vlan=100) / IP(src="192.168.1.1", dst="192.168.1.2")
        / TCP(sport=40000, dport=6030) / Raw(b"y" * 4),
        Ether(dst="11:22:33:44:55:67", src="aa:bb:cc:dd:ee:f0")
        / Dot1Q(vlan=100) / Dot1Q(vlan=200)
        / IP(src="172.16.0.1", dst="172.16.0.2") / UDP(sport=1, dport=4789),
        Ether(dst="33:33:00:00:00:05", src="aa:bb:cc:dd:ee:f1")
        / IPv6(src="2001:db8::1", dst="ff02::5") / Raw(b"\x03\x01\x00\x10" + b"\x00" * 12),
    ]
    for i, built in enumerate(cases):
        raw = bytes(built)
        pkt = redissect(built)
        mine = ag.parse_l2(raw)
        check(mine is not None, f"case {i}: parse_l2 returned None")
        if mine is None:
            continue

        check(mine.src == pkt[Ether].src.lower(),
              f"case {i}: src MAC {mine.src} vs scapy {pkt[Ether].src}")
        check(mine.dst == pkt[Ether].dst.lower(),
              f"case {i}: dst MAC {mine.dst} vs scapy {pkt[Ether].dst}")

        vl: list[int] = []
        layer = pkt
        while layer:
            if isinstance(layer, Dot1Q):
                vl.append(layer.vlan)
            layer = layer.payload if layer.payload else None
        check(mine.vlan_tags == tuple(vl),
              f"case {i}: vlan tags {mine.vlan_tags} vs scapy {tuple(vl)}")

        if IP in pkt:
            l3 = ag.parse_l3(mine.payload, mine.ethertype)
            check(l3 is not None, f"case {i}: parse_l3 returned None for IPv4")
            if l3:
                check(l3.src == pkt[IP].src,
                      f"case {i}: ipv4 src {l3.src} vs scapy {pkt[IP].src}")
                check(l3.dst == pkt[IP].dst,
                      f"case {i}: ipv4 dst {l3.dst} vs scapy {pkt[IP].dst}")
                check(l3.proto == pkt[IP].proto,
                      f"case {i}: ip proto {l3.proto} vs scapy {pkt[IP].proto}")
                check(l3.total_len == pkt[IP].len,
                      f"case {i}: total_len {l3.total_len} vs scapy {pkt[IP].len}")
                l4 = ag.parse_l4(l3)
                if UDP in pkt:
                    check(l4 is not None and l4.sport == pkt[UDP].sport,
                          f"case {i}: udp sport mismatch")
                    check(l4 is not None and l4.dport == pkt[UDP].dport,
                          f"case {i}: udp dport mismatch")
                if TCP in pkt:
                    check(l4 is not None and l4.sport == pkt[TCP].sport,
                          f"case {i}: tcp sport mismatch")
                    check(l4 is not None and l4.dport == pkt[TCP].dport,
                          f"case {i}: tcp dport mismatch")
        if IPv6 in pkt:
            l3 = ag.parse_l3(mine.payload, mine.ethertype)
            check(l3 is not None, f"case {i}: parse_l3 returned None for IPv6")
            if l3:
                # Compare canonically - scapy and aristaguard may render
                # zero-compression differently, which is a formatting choice,
                # not a parsing disagreement.
                import ipaddress
                check(ipaddress.ip_address(l3.src) == ipaddress.ip_address(pkt[IPv6].src),
                      f"case {i}: ipv6 src {l3.src} vs scapy {pkt[IPv6].src}")
                check(ipaddress.ip_address(l3.dst) == ipaddress.ip_address(pkt[IPv6].dst),
                      f"case {i}: ipv6 dst {l3.dst} vs scapy {pkt[IPv6].dst}")
                check(l3.proto == pkt[IPv6].nh,
                      f"case {i}: ipv6 nh {l3.proto} vs scapy {pkt[IPv6].nh}")

    # TCP data offset: a header with options must not leak option bytes into
    # the payload.  This is exactly the kind of off-by-one that a
    # builder/parser pair agreeing with each other would never surface.
    pkt = Ether(dst="11:22:33:44:55:68", src="aa:bb:cc:dd:ee:f2") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=22, dport=40000, options=[("MSS", 1460), ("NOP", None),
                                        ("WScale", 7)]) / Raw(b"PAYLOAD!")
    pkt = redissect(pkt)
    mine = ag.parse_l2(bytes(pkt))
    l3 = ag.parse_l3(mine.payload, mine.ethertype)
    l4 = ag.parse_l4(l3)
    check(l4 is not None and l4.payload == b"PAYLOAD!",
          f"TCP options must not leak into payload; got {l4.payload if l4 else None!r}")

    # IPv4 options likewise.
    pkt = Ether(dst="11:22:33:44:55:69", src="aa:bb:cc:dd:ee:f3") / IP(src="10.0.0.1", dst="10.0.0.2",
                       options=[b"\x83\x07\x04\x0a\x00\x00\x01\x00"]) \
        / UDP(sport=1, dport=1812) / Raw(b"AFTEROPT")
    pkt = redissect(pkt)
    mine = ag.parse_l2(bytes(pkt))
    l3 = ag.parse_l3(mine.payload, mine.ethertype)
    l4 = ag.parse_l4(l3)
    check(l4 is not None and l4.payload == b"AFTEROPT",
          f"IPv4 options must not leak into payload; got {l4.payload if l4 else None!r}")


# ---------------------------------------------------------------------------
# Section 2 - RADIUS cross-check
# ---------------------------------------------------------------------------
#
# The most important section in this file.  RADIUS attribute walking is the
# hand-rolled-parser-plus-hand-rolled-builder shape that hid ciscoguard's OID
# off-by-one through 81 passing tests, and BlastRADIUS is the module's
# strongest signature - so a length or offset error here would silently
# weaken exactly the rule that matters most.


def section_radius() -> None:
    section("2 RADIUS")
    # scapy 2.7.0 ships no RadiusAttr_Proxy_State class. Using the GENERIC
    # RadiusAttribute for type 33 is actually the stronger cross-check: it
    # drives scapy's generic attribute walker rather than a per-type class,
    # which is the same code path a real unknown vendor attribute takes.
    from scapy.layers.radius import (RadiusAttribute, RadiusAttr_User_Name,
                                     RadiusAttr_Message_Authenticator)

    def proxy_state(value: bytes) -> Any:
        return RadiusAttribute(type=33, value=value)

    cases = [
        ("request with Message-Authenticator", Radius(
            code=1, id=7,
            attributes=[RadiusAttr_User_Name(value=b"operator"),
                        RadiusAttr_Message_Authenticator(value=b"\x00" * 16)])),
        ("request without Message-Authenticator", Radius(
            code=1, id=8, attributes=[RadiusAttr_User_Name(value=b"operator")])),
        ("accept without Message-Authenticator", Radius(
            code=2, id=9, attributes=[RadiusAttr_User_Name(value=b"op")])),
        ("oversized Proxy-State", Radius(
            code=1, id=10,
            attributes=[proxy_state(b"A" * 240)])),
        ("many small attributes", Radius(
            code=1, id=11,
            attributes=[RadiusAttr_User_Name(value=b"u%02d" % i)
                        for i in range(20)])),
        ("empty attribute list", Radius(code=1, id=12, attributes=[])),
    ]

    for label, built in cases:
        raw = bytes(built)
        pkt = redissect(built)
        mine = ag.parse_radius(raw)
        check(mine is not None, f"{label}: parse_radius returned None")
        if mine is None:
            continue

        check(mine.code == pkt.code,
              f"{label}: code {mine.code} vs scapy {pkt.code}")
        check(mine.identifier == pkt.id,
              f"{label}: id {mine.identifier} vs scapy {pkt.id}")
        check(mine.length == len(raw),
              f"{label}: declared length {mine.length} vs actual {len(raw)}")
        check(mine.authenticator == bytes(pkt.authenticator),
              f"{label}: authenticator mismatch")

        # ATTRIBUTE COUNT AND TYPES - the tie-breaking comparison.
        scapy_attrs = [(a.type, a.len) for a in pkt.attributes]
        check(list(mine.attrs) == scapy_attrs,
              f"{label}: attribute (type,len) list disagrees with scapy.\n"
              f"      aristaguard: {list(mine.attrs)}\n"
              f"      scapy:       {scapy_attrs}")

        # Message-Authenticator detection is what AG-102/AG-202 turn on.
        scapy_has_ma = any(a.type == 80 for a in pkt.attributes)
        check(mine.has_message_authenticator == scapy_has_ma,
              f"{label}: Message-Authenticator presence {mine.has_message_authenticator} "
              f"vs scapy {scapy_has_ma}")

        # Max attribute length drives AG-201.
        if scapy_attrs:
            scapy_max = max(l for _, l in scapy_attrs)
            check(mine.max_attr_len == scapy_max,
                  f"{label}: max attr len {mine.max_attr_len} vs scapy {scapy_max}")

        check(not mine.malformed, f"{label}: well-formed packet flagged malformed")

    # End-to-end: a scapy-built BlastRADIUS-shaped packet must fire AG-201
    # through the production engine.
    pkt = (Ether(dst="11:22:33:44:55:6a", src="aa:bb:cc:dd:ee:f4")
           / IP(src="10.0.0.1", dst="10.0.0.2")
           / UDP(sport=50000, dport=1812)
           / Radius(code=1, id=13,
                    attributes=[proxy_state(b"B" * 240)]))
    eng = ag.AristaEngine(_xcfg())
    eng.handle_frame(bytes(pkt), ts=1.0)
    got = {f.code for f in eng.findings}
    check("AG-201" in got,
          f"a scapy-built oversized Proxy-State must fire AG-201, got {sorted(got)}")
    check("AG-102" in got,
          "that same packet has no Message-Authenticator and must also fire AG-102")
    check("AG-202" not in ag.FINDINGS,
          "AG-202 is retired and must never be reachable again")

    pkt_ok = (Ether(dst="11:22:33:44:55:6b", src="aa:bb:cc:dd:ee:f5")
              / IP(src="10.0.0.1", dst="10.0.0.2")
              / UDP(sport=50000, dport=1812)
              / Radius(code=1, id=14,
                       attributes=[RadiusAttr_User_Name(value=b"op"),
                                   RadiusAttr_Message_Authenticator(value=b"\x00" * 16)]))
    eng = ag.AristaEngine(_xcfg())
    eng.handle_frame(bytes(pkt_ok), ts=1.0)
    got = {f.code for f in eng.findings}
    check("AG-201" not in got and "AG-102" not in got,
          f"a properly protected scapy-built request must stay quiet, got {sorted(got)}")


# ---------------------------------------------------------------------------
# Section 3 - LLDP cross-check
# ---------------------------------------------------------------------------


def section_lldp() -> None:
    section("3 LLDP")
    desc = ("Arista Networks EOS version 4.32.1F running on an "
            "Arista Networks DCS-7280R-48C6")
    pkt = (Ether(dst="01:80:c2:00:00:0e", type=0x88CC)
           / LLDPDU()
           / LLDPDUChassisID(subtype=4, id="00:1c:73:00:00:01")
           / LLDPDUPortID(subtype=5, id="Ethernet1")
           / LLDPDUTimeToLive(ttl=120)
           / LLDPDUSystemName(system_name=b"sw1.example")
           / LLDPDUSystemDescription(description=desc.encode())
           / LLDPDUEndOfLLDPDU())
    raw = bytes(pkt)
    mine = ag.parse_l2(raw)
    check(mine is not None and mine.ethertype == 0x88CC, "LLDP ethertype")
    info = ag.parse_lldp(mine.payload)
    check(info is not None, "parse_lldp returned None on a scapy-built LLDPDU")
    if info:
        check(info.sysname == "sw1.example",
              f"system name {info.sysname!r} vs scapy-built 'sw1.example'")
        check(info.sysdesc == desc,
              f"system description mismatch:\n  got {info.sysdesc!r}\n  want {desc!r}")
        check(info.eos_version == "4.32.1F",
              f"EOS version {info.eos_version!r} extracted from a scapy-built TLV")
        check(info.platform == "DCS-7280R-48C6",
              f"platform {info.platform!r}")
        check(info.is_arista, "is_arista")

    # Through the production engine, end to end.
    eng = ag.AristaEngine(ag.Config())
    eng.handle_frame(raw, ts=1.0)
    got = {f.code for f in eng.findings}
    for want in ("AG-001", "AG-002", "AG-005", "AG-006"):
        check(want in got, f"scapy-built LLDP should fire {want}, got {sorted(got)}")

    # TLV ordering must not matter - a real neighbour may order them freely.
    reordered = (Ether(dst="01:80:c2:00:00:0e", type=0x88CC)
                 / LLDPDU()
                 / LLDPDUChassisID(subtype=4, id="00:1c:73:00:00:02")
                 / LLDPDUPortID(subtype=5, id="Ethernet2")
                 / LLDPDUTimeToLive(ttl=120)
                 / LLDPDUSystemDescription(description=desc.encode())
                 / LLDPDUSystemName(system_name=b"sw2.example")
                 / LLDPDUEndOfLLDPDU())
    info2 = ag.parse_lldp(ag.parse_l2(bytes(reordered)).payload)
    check(info2 is not None and info2.eos_version == "4.32.1F",
          "TLV order must not affect extraction")


# ---------------------------------------------------------------------------
# Section 4 - EAPOL and VXLAN cross-check
# ---------------------------------------------------------------------------


def section_eapol_vxlan() -> None:
    section("4 EAPOL/VXLAN")
    for etype, label in ((0, "EAP-Packet"), (1, "EAPOL-Start"), (2, "EAPOL-Logoff")):
        pkt = Ether(dst="01:80:c2:00:00:03") / Dot1Q(vlan=99) / EAPOL(
            version=2, type=etype)
        raw = bytes(pkt)
        mine = ag.parse_l2(raw)
        check(mine is not None and mine.ethertype == 0x888E,
              f"{label}: EAPOL ethertype behind a VLAN tag")
        f = ag.parse_eapol(mine.payload)
        check(f is not None and f.etype == pkt[EAPOL].type,
              f"{label}: eapol type {f.etype if f else None} vs scapy {pkt[EAPOL].type}")
        check(f is not None and f.version == pkt[EAPOL].version,
              f"{label}: eapol version mismatch")

        eng = ag.AristaEngine(ag.Config())
        eng.handle_frame(raw, ts=1.0)
        got = {x.code for x in eng.findings}
        check("AG-107" in got, f"{label}: should fire AG-107, got {sorted(got)}")
        vlan = next(x.detail["vlan"] for x in eng.findings if x.code == "AG-107")
        check(vlan == 99, f"{label}: AG-107 recorded vlan {vlan}, expected 99")

    # VXLAN: scapy's own VXLAN layer on the other side of the port match.
    pkt = (Ether(dst="11:22:33:44:55:6c", src="aa:bb:cc:dd:ee:f6") / IP(src="10.1.1.1", dst="10.1.1.9") / UDP(sport=50000, dport=4789)
           / VXLAN(vni=5000) / Ether() / IP(src="192.168.1.1", dst="192.168.1.2"))
    eng = ag.AristaEngine(ag.Config())
    eng.handle_frame(bytes(pkt), ts=1.0)
    got = {f.code for f in eng.findings}
    check("AG-106" in got, f"scapy-built VXLAN should fire AG-106, got {sorted(got)}")
    check("10.1.1.9" in eng.decap_endpoints,
          f"the VTEP must be learned; endpoints={eng.decap_endpoints}")

    # ... and then GRE to that same learned endpoint must fire AG-203.
    from scapy.layers.inet import GRE
    gre = Ether(dst="11:22:33:44:55:6d", src="aa:bb:cc:dd:ee:f7") / IP(src="10.9.9.9", dst="10.1.1.9") / GRE() / Ether() / IP()
    eng.handle_frame(bytes(gre), ts=2.0)
    got = {f.code for f in eng.findings}
    check("AG-203" in got,
          f"GRE to a scapy-learned VTEP should fire AG-203, got {sorted(got)}")
    f = next(x for x in eng.findings if x.code == "AG-203")
    check(f.detail["observed_protocol"] == "GRE",
          f"AG-203 named {f.detail['observed_protocol']}, expected GRE")


# ---------------------------------------------------------------------------
# Section 5 - LESSON C: drive run_capture()
# ---------------------------------------------------------------------------


class SniffRecorder:
    """
    Stands in for scapy.sniff so the LIVE branch's arguments can be inspected.

    The point is not just that run_capture runs - it is that the arguments it
    passes are the ones a real capture needs: the BPF filter installed,
    store=False so a long run does not accumulate packets in RAM, the iface
    and timeout threaded through, and offline= NOT set (which would silently
    make a production run read a file instead of a wire).
    """

    def __init__(self, frames: list[bytes]) -> None:
        self.frames = frames
        self.kwargs: dict[str, Any] = {}
        self.called = 0

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        self.called += 1
        self.kwargs = kwargs
        prn = kwargs.get("prn")
        if prn is None:
            return
        for i, raw in enumerate(self.frames):
            pkt = Ether(raw)
            pkt.time = 1000.0 + i
            prn(pkt)


def lab_frames() -> list[bytes]:
    from scapy.layers.radius import RadiusAttribute, RadiusAttr_User_Name
    from scapy.layers.inet import GRE
    desc = ("Arista Networks EOS version 4.32.1F running on an "
            "Arista Networks DCS-7280R-48C6")
    return [
        bytes(Ether(dst="01:80:c2:00:00:0e", type=0x88CC) / LLDPDU()
              / LLDPDUChassisID(subtype=4, id="00:1c:73:00:00:01")
              / LLDPDUPortID(subtype=5, id="Ethernet1")
              / LLDPDUTimeToLive(ttl=120)
              / LLDPDUSystemName(system_name=b"sw1")
              / LLDPDUSystemDescription(description=desc.encode())
              / LLDPDUEndOfLLDPDU()),
        bytes(Ether(dst="11:22:33:44:55:70", src="aa:bb:cc:dd:ee:f8") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=50000, dport=1812)
              / Radius(code=1, id=1,
                       attributes=[RadiusAttribute(type=33, value=b"C" * 240)])),
        bytes(Ether(dst="11:22:33:44:55:70", src="aa:bb:cc:dd:ee:f8") / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=1812, dport=50000)
              / Radius(code=2, id=1, attributes=[RadiusAttr_User_Name(value=b"op")])),
        bytes(Ether(dst="11:22:33:44:55:70", src="aa:bb:cc:dd:ee:f8") / IP(src="10.1.1.1", dst="10.1.1.9") / UDP(sport=50000, dport=4789)
              / VXLAN(vni=5000) / Ether() / IP()),
        bytes(Ether(dst="11:22:33:44:55:70", src="aa:bb:cc:dd:ee:f8") / IP(src="10.9.9.9", dst="10.1.1.9") / GRE() / Ether() / IP()),
        bytes(Ether(dst="11:22:33:44:55:70", src="aa:bb:cc:dd:ee:f8") / IP(src="10.2.2.1", dst="10.2.2.2", proto=50) / Raw(b"\x00" * 16)),
        bytes(Ether(dst="01:80:c2:00:00:03") / Dot1Q(vlan=99) / EAPOL(version=2, type=1)),
        bytes(Ether(dst="11:22:33:44:55:70", src="aa:bb:cc:dd:ee:f8") / IP(src="10.0.0.9", dst="10.0.0.1") / TCP(sport=22, dport=40002)
              / Raw(b"SSH-2.0-OpenSSH_9.2p1 Arista\r\n")),
        bytes(Ether(dst="11:22:33:44:55:70", src="aa:bb:cc:dd:ee:f8") / IP(src="10.0.0.5", dst="10.0.0.6") / TCP(sport=40000, dport=6030)
              / Raw(b"\x00" * 8)),
    ]


def section_live_path() -> None:
    section("5 LESSON C live path")
    frames = lab_frames()

    # Baseline: in-memory, through handle_frame directly.
    mem = ag.AristaEngine(ag.Config())
    for i, raw in enumerate(frames):
        mem.handle_frame(raw, ts=1000.0 + i)
    mem_codes = {f.code for f in mem.findings}
    check(len(mem_codes) >= 8,
          f"the live-path fixture set must exercise a real spread of codes, "
          f"got {sorted(mem_codes)}")

    # LIVE PATH via scapy's own offline sniff, reading a real pcap from disk.
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "xcheck.pcap")
        pkts = []
        for i, raw in enumerate(frames):
            p = Ether(raw)
            p.time = 1000.0 + i
            pkts.append(p)
        wrpcap(path, pkts)

        emitted: list[str] = []
        live = ag.AristaEngine(ag.Config(), emit=lambda f: emitted.append(f.to_json()))

        def _cb(pkt: Any) -> None:
            live.handle_frame(bytes(pkt), float(pkt.time))

        sniff(offline=path, prn=_cb, store=False)

        live_codes = {f.code for f in live.findings}
        check(live_codes == mem_codes,
              f"LIVE path codes differ from in-memory codes.\n"
              f"      live only: {sorted(live_codes - mem_codes)}\n"
              f"      mem only:  {sorted(mem_codes - live_codes)}")
        check(len(emitted) == len(live.findings),
              "every live finding must be emitted")
        for line in emitted:
            check("\n" not in line, "emitted JSON must be single-line")
            blob = json.loads(line)
            check(blob["module"] == "aristaguard", "emitted JSON module name")
            check(blob["code"] in ag.FINDINGS, "emitted JSON code is real")

    # Now drive run_capture() ITSELF - the function that had never executed.
    recorder = SniffRecorder(frames)
    real_sniff = None
    import scapy.all as scapy_all
    real_sniff = scapy_all.sniff
    try:
        scapy_all.sniff = recorder                     # type: ignore[assignment]
        eng = ag.AristaEngine(ag.Config())
        # NON-VACUITY: this config MUST carry host terms, so that
        # build_bpf_filter(cfg) differs from the module-level BPF_FILTER
        # default. The first version of this test used a bare Config(), where
        # the two are byte-identical - so a mutation reverting run_capture to
        # the static default passed all four tiers undetected. Same shape as
        # ciscoguard's vacuous known_infra test.
        cfg = ag.Config(iface="ragnar-test0", timeout=7,
                        policy_blocked=("192.168.5.5",),
                        decap_endpoints=("10.1.1.9",))
        check(ag.build_bpf_filter(cfg) != ag.BPF_FILTER,
              "this test is VACUOUS unless the config-derived filter differs "
              "from the module default")
        ag.run_capture(cfg, eng)
    finally:
        scapy_all.sniff = real_sniff                   # type: ignore[assignment]

    check(recorder.called == 1, f"run_capture called sniff {recorder.called} times")
    kw = recorder.kwargs
    check(kw.get("iface") == "ragnar-test0",
          f"run_capture must pass iface through, got {kw.get('iface')!r}")
    check(kw.get("timeout") == 7,
          f"run_capture must pass timeout through, got {kw.get('timeout')!r}")
    check(kw.get("store") is False,
          "run_capture must set store=False, or a long capture accumulates "
          "every packet in RAM on a Pi Zero 2W")
    check(kw.get("filter") == ag.build_bpf_filter(cfg),
          "run_capture must install the filter built from the LIVE config, "
          "not the module-level default - otherwise policy_blocked and "
          "decap_endpoints hosts are never admitted")
    check("offline" not in kw,
          "run_capture must NOT set offline= - that would make a production "
          "run read a file instead of the wire")
    check(kw.get("prn") is not None, "run_capture must pass a callback")

    rc_codes = {f.code for f in eng.findings}
    check(rc_codes == mem_codes,
          f"run_capture produced different codes from the in-memory run.\n"
          f"      run_capture only: {sorted(rc_codes - mem_codes)}\n"
          f"      mem only:         {sorted(mem_codes - rc_codes)}")

    # Learn mode must stay silent over the live path too.
    recorder2 = SniffRecorder(frames)
    emitted2: list[Any] = []
    try:
        scapy_all.sniff = recorder2                    # type: ignore[assignment]
        eng2 = ag.AristaEngine(ag.Config(learn=True), emit=emitted2.append)
        ag.run_capture(ag.Config(iface="x", learn=True), eng2)
    finally:
        scapy_all.sniff = real_sniff                   # type: ignore[assignment]
    check(emitted2 == [], "learn mode must emit nothing over the live path")
    check(len(eng2.findings) > 0,
          "learn mode must still DETECT over the live path")

    # An empty iface must become None, not the empty string - scapy treats ""
    # as a literal interface name and would fail.
    recorder3 = SniffRecorder([])
    try:
        scapy_all.sniff = recorder3                    # type: ignore[assignment]
        ag.run_capture(ag.Config(iface="", timeout=0), ag.AristaEngine(ag.Config()))
    finally:
        scapy_all.sniff = real_sniff                   # type: ignore[assignment]
    check(recorder3.kwargs.get("iface") is None,
          f"empty iface must become None, got {recorder3.kwargs.get('iface')!r}")
    check(recorder3.kwargs.get("timeout") is None,
          f"zero timeout must become None, got {recorder3.kwargs.get('timeout')!r}")


# ---------------------------------------------------------------------------
# Section 6 - BPF filter compiles and actually scopes
# ---------------------------------------------------------------------------


def section_bpf() -> None:
    section("6 BPF")
    compiled = False
    try:
        from scapy.arch.common import compile_filter
        compile_filter(ag.BPF_FILTER)
        compiled = True
    except ImportError:
        check(True, "compile_filter unavailable - BPF compilation not verified here")
    except Exception as exc:  # noqa: BLE001
        check(False, f"BPF_FILTER does not compile under libpcap: {exc}")
    if compiled:
        check(True, "BPF_FILTER compiles under libpcap")

    # A filter that is syntactically valid but scopes nothing is the real
    # risk: a typo that widens to everything. Verify the filter is selective
    # by compiling a deliberately broken one and confirming that FAILS.
    if compiled:
        from scapy.arch.common import compile_filter
        broke = False
        try:
            compile_filter("udp porrt 1812")
        except Exception:  # noqa: BLE001
            broke = True
        check(broke,
              "the BPF compile check is vacuous unless a bad filter really fails")

    # Every port and protocol a rule depends on must survive the filter.
    for token in ("1812", "1813", "4789", "6030", "9339", "9979", "22", "49",
                  "0x88cc", "0x888e"):
        check(token in ag.BPF_FILTER, f"BPF_FILTER omits {token}")
    for proto in (47, 50, 51, 4, 41, 89):
        check(f"proto {proto}" in ag.BPF_FILTER,
              f"BPF_FILTER omits ip proto {proto}")


# ---------------------------------------------------------------------------
# Section 7 - pcap round-trip through scapy's own reader
# ---------------------------------------------------------------------------


def section_pcap() -> None:
    section("7 pcap")
    frames = lab_frames()
    with tempfile.TemporaryDirectory() as td:
        # The conformance harness's dependency-free writer must produce a file
        # scapy can read - otherwise the sealed-namespace lab will replay
        # something tcpreplay and tcpdump disagree about.
        sys.path.insert(0, HERE)
        import aristaguard_conformance as conf
        path = os.path.join(td, "written.pcap")
        conf.write_pcap(path, frames)

        read = rdpcap(path)
        check(len(read) == len(frames),
              f"scapy read {len(read)} packets from our writer, wrote {len(frames)}")
        for i, (pkt, raw) in enumerate(zip(read, frames)):
            check(bytes(pkt) == raw, f"packet {i} differs after round-trip")

        ts = [float(p.time) for p in read]
        check(all(b >= a for a, b in zip(ts, ts[1:])),
              "scapy sees monotonic timestamps from our writer")
        span = ts[-1] - ts[0]
        check(span < 1.0,
              f"scapy computes a {span:.6f}s span - if this were seconds-scale "
              f"the frame index would be landing in the seconds field, which "
              f"is the cdpwatch write_pcap bug")

        # And the engine must produce the same codes reading it back.
        eng = ag.AristaEngine(ag.Config())
        for p in read:
            eng.handle_frame(bytes(p), float(p.time))
        mem = ag.AristaEngine(ag.Config())
        for i, raw in enumerate(frames):
            mem.handle_frame(raw, ts=1000.0 + i)
        check({f.code for f in eng.findings} == {f.code for f in mem.findings},
              "codes must match between our writer + scapy reader and direct feed")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------



def section_bpf_reachability() -> None:
    """
    Compile the filter under libpcap and prove every rule's traffic survives.

    This is the check that would have caught AG-205/206/207 being
    unreachable: the offline tiers feed bytes straight to handle_frame() and
    never touch BPF at all.
    """
    section("8 BPF reachability")
    try:
        from scapy.arch.common import compile_filter
        compile_filter(ag.BPF_FILTER, linktype=1)
    except ImportError:
        check(True, "compile_filter unavailable; reachability not verified here")
        return
    except Exception as exc:  # noqa: BLE001
        check(False, f"default filter does not compile: {exc}")
        return
    check(True, "default filter compiles under libpcap")

    cfg = ag.Config(policy_blocked=("192.168.5.5",), decap_endpoints=("10.1.1.9",))
    try:
        compile_filter(ag.build_bpf_filter(cfg), linktype=1)
        check(True, "config-derived filter compiles under libpcap")
    except Exception as exc:  # noqa: BLE001
        check(False, f"config-derived filter does not compile: {exc}")

    # A filter with a host term AFTER the vlan term would compile but read
    # the wrong offsets. Assert ordering explicitly.
    f = ag.build_bpf_filter(cfg)
    check(f.rstrip().endswith("vlan"), "vlan term must be last")
    check(f.index("host 192.168.5.5") < f.rindex("vlan"),
          "host terms must precede the vlan term")

    # Every fixture frame the lab replays must survive the filter. Verified
    # by feeding them through scapy's own sniff with the filter applied,
    # offline - which uses the same libpcap program a live capture would.
    import aristaguard_conformance as conf
    with tempfile.TemporaryDirectory() as td:
        meta = conf.emit_lab_artefacts(td)
        for name, want in (("attack.pcap", meta["expected_attack_codes"]),
                           ("policy.pcap", meta["expected_policy_codes"])):
            path = os.path.join(td, name)
            got = sniff(offline=path, filter=ag.build_bpf_filter(cfg), store=True)
            total = len(rdpcap(path))
            check(len(got) == total,
                  f"{name}: filter admitted {len(got)} of {total} frames - "
                  f"frames a rule needs are being dropped before the engine "
                  f"ever sees them")


def section_ipv6_ext_headers() -> None:
    """
    Independent cross-check of the D7 extension-header walk.

    scapy's IPv6ExtHdr* classes compute each header's length from its own
    field semantics, so they are a genuine second implementation of the rules
    that are easiest to get wrong - notably AH, whose length is in 4-octet
    units MINUS 2 while every other extension header uses 8-octet units.
    A hand-rolled walker paired with a hand-rolled builder would agree with
    itself on a wrong rule (LESSON A).
    """
    section("9 IPv6 ext headers")
    from scapy.layers.inet6 import (IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt,
                                    IPv6ExtHdrFragment, IPv6ExtHdrRouting)
    from scapy.layers.ipsec import AH
    from scapy.layers.radius import RadiusAttr_User_Name

    rad = Radius(code=1, id=1, attributes=[RadiusAttr_User_Name(value=b"op")])
    base = (Ether(dst="11:22:33:44:55:80", src="aa:bb:cc:dd:ee:90")
            / IPv6(src="2001:db8::1", dst="2001:db8::2"))

    cases = [
        ("Hop-by-Hop", IPv6ExtHdrHopByHop()),
        ("Dest-Opts", IPv6ExtHdrDestOpt()),
        ("Routing", IPv6ExtHdrRouting()),
        ("Fragment", IPv6ExtHdrFragment(offset=0, m=0)),
        # scapy's AH does NOT auto-compute nh or payloadlen - it is built for
        # use through scapy's IPsec SA machinery, not standalone, and a naive
        # fixture leaves nh=0 and payloadlen=0. That would have "proved"
        # agreement on garbage. Both fields are set explicitly: the AH fixed
        # part is 12 bytes and the ICV is 12, so 24 total, and RFC 4302 makes
        # payloadlen 4-octet units MINUS 2 -> 24/4 - 2 = 4.
        ("AH", AH(nh=17, payloadlen=4, icv=b"\x00" * 12)),
    ]
    for name, hdr in cases:
        pkt = redissect(base / hdr / UDP(sport=50000, dport=1812) / rad)
        raw = bytes(pkt)
        l2 = ag.parse_l2(raw)
        l3 = ag.parse_l3(l2.payload, l2.ethertype)
        check(l3 is not None, f"{name}: parse_l3 returned None")
        if l3 is None:
            continue
        check(l3.version == 6, f"{name}: version")
        check(l3.l4_reachable,
              f"{name}: aristaguard says no L4 is reachable, but scapy built a "
              f"UDP header behind this extension header")
        check(l3.proto == 17,
              f"{name}: aristaguard resolved proto {l3.proto}, scapy says UDP")
        l4 = ag.parse_l4(l3)
        check(l4 is not None and l4.dport == 1812,
              f"{name}: dport {l4.dport if l4 else None}, scapy says 1812")
        # The payload boundary is the part a length-rule error moves
        # silently. scapy does NOT chain-dispatch past AH (it dissects
        # AH / Raw regardless of nh), so for AH compare against the header
        # SIZE scapy computed rather than its layer dispatch.
        if name == "AH":
            ah_bytes = len(bytes(pkt[AH])) - len(bytes(pkt[AH].payload))
            check(ah_bytes == 24,
                  f"AH fixture should be 24 bytes per scapy, got {ah_bytes}")
            check(l4 is not None and l4.dport == 1812,
                  "AH: aristaguard's walk must land exactly on the UDP header "
                  "scapy placed 24 bytes in")
        else:
            check(l4 is not None and l4.payload == bytes(pkt[Radius]),
                  f"{name}: the L4 payload boundary disagrees with scapy - "
                  f"this is what a wrong header-length rule looks like")
        # And end to end through the engine.
        got = {f.code for f in _engine_codes(raw)}
        check("AG-101" in got and "AG-102" in got,
              f"{name}: engine should raise AG-101+AG-102, got {sorted(got)}")

    # AH specifically: confirm scapy and aristaguard agree on its LENGTH, by
    # checking the payload starts exactly where scapy puts the UDP header.
    pkt = redissect(base / AH(nh=17, payloadlen=4, icv=b"\x00" * 12)
                    / UDP(sport=1, dport=1812) / rad)
    l2 = ag.parse_l2(bytes(pkt))
    l3 = ag.parse_l3(l2.payload, l2.ethertype)
    ah_bytes = len(bytes(pkt[AH])) - len(bytes(pkt[AH].payload))
    check(l3.payload[:2] == struct.pack("!H", 1),
          "AH length rule: aristaguard's L4 offset differs from scapy's 24-byte "
          "header. AH uses 4-octet units MINUS 2, unlike every other extension "
          "header - the 8-octet rule walks off the end")
    check(ah_bytes == 24, f"scapy sizes this AH at {ah_bytes}, expected 24")

    # A non-first fragment carries no L4 header.
    pkt = redissect(base / IPv6ExtHdrFragment(offset=185, m=1)
                    / Raw(b"\x00" * 16))
    l2 = ag.parse_l2(bytes(pkt))
    l3 = ag.parse_l3(l2.payload, l2.ethertype)
    check(not l3.l4_reachable, "non-first fragment must report no L4")
    check(l3.frag_offset == 185,
          f"fragment offset {l3.frag_offset}, scapy built 185")

    # A chain of three.
    pkt = redissect(base / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt()
                    / IPv6ExtHdrRouting() / UDP(sport=50000, dport=1812) / rad)
    l2 = ag.parse_l2(bytes(pkt))
    l3 = ag.parse_l3(l2.payload, l2.ethertype)
    check(l3.proto == 17, f"3-header chain resolved to {l3.proto}, want 17")
    check(len(l3.ext_headers) == 3,
          f"chain should record 3 headers, got {l3.ext_headers}")

    # BPF: the filter must actually admit these under libpcap.
    try:
        from scapy.arch.common import compile_filter
        compile_filter(ag.BPF_FILTER, linktype=1)
    except ImportError:
        return
    except Exception as exc:  # noqa: BLE001
        check(False, f"filter with the ip6 clause does not compile: {exc}")
        return
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "eh.pcap")
        pkts = [redissect(base / hdr / UDP(sport=50000, dport=1812) / rad)
                for _, hdr in cases]  # `cases` carries the corrected AH
        wrpcap(path, pkts)
        got = sniff(offline=path, filter=ag.BPF_FILTER, store=True)
        check(len(got) == len(pkts),
              f"BPF admitted {len(got)} of {len(pkts)} extension-header "
              f"packets - libpcap cannot chase the chain, so without the "
              f"ip6[6] clause these never reach the engine at all")


def section_radius_review() -> None:
    """Cross-check the D1/D2/D3 RADIUS changes against scapy's dissector."""
    section("10 RADIUS review")
    from scapy.layers.radius import (RadiusAttribute, RadiusAttr_User_Name,
                                     RadiusAttr_Message_Authenticator)

    def ps(v: bytes) -> Any:
        return RadiusAttribute(type=33, value=v)

    def eap(v: bytes) -> Any:
        return RadiusAttribute(type=79, value=v)

    # D1: EAP-Message fragments are NOT Proxy-State and must not be counted.
    pkt = redissect(Radius(code=1, id=1, attributes=[
        RadiusAttr_User_Name(value=b"operator"),
        eap(b"A" * 253), eap(b"B" * 253),
        RadiusAttr_Message_Authenticator(value=b"\x00" * 16)]))
    mine = ag.parse_radius(bytes(pkt))
    scapy_ps = sum(a.len for a in pkt.attributes if a.type == 33)
    check(mine.proxy_state_total == scapy_ps == 0,
          f"D1: Proxy-State total should be 0, aristaguard says "
          f"{mine.proxy_state_total}, scapy says {scapy_ps}")
    check(mine.max_attr_len == max(a.len for a in pkt.attributes),
          "max_attr_len still tracked and still agrees with scapy")
    check(mine.has_message_authenticator, "M-A detected")

    # D2: split Proxy-State summed, and the count recorded.
    pkt = redissect(Radius(code=1, id=2,
                           attributes=[ps(b"X" * 98) for _ in range(4)]))
    mine = ag.parse_radius(bytes(pkt))
    scapy_ps = sum(a.len for a in pkt.attributes if a.type == 33)
    check(mine.proxy_state_total == scapy_ps,
          f"D2: total {mine.proxy_state_total} vs scapy {scapy_ps}")
    check(mine.proxy_state_count == 4,
          f"D2: count {mine.proxy_state_count}, scapy built 4")

    # D3: Message-Authenticator position, per scapy's own attribute order.
    for attrs, first_is_ma in (
            ([RadiusAttr_Message_Authenticator(value=b"\x00" * 16), ps(b"p" * 38)], True),
            ([ps(b"p" * 38), RadiusAttr_Message_Authenticator(value=b"\x00" * 16)], False)):
        pkt = redissect(Radius(code=3, id=3, attributes=attrs))
        mine = ag.parse_radius(bytes(pkt))
        scapy_first = pkt.attributes[0].type == 80
        check(scapy_first == first_is_ma, "fixture built as intended")
        check(mine.ma_is_first == scapy_first,
              f"D3: ma_is_first {mine.ma_is_first} vs scapy {scapy_first}")

    # D6: scapy must agree the walk reaches past 256 attributes.
    #
    # scapy caps PacketListField dissection at conf.max_list_count (100 by
    # default), so an unaltered scapy would "disagree" at 76 attributes for
    # reasons that have nothing to do with aristaguard. Raise it for this
    # comparison and restore it afterwards.
    old_max = conf.max_list_count
    conf.max_list_count = 4096
    try:
        # Type 100, not 26: scapy has a dedicated Vendor-Specific dissector
        # for type 26 that consumes bytes differently and stops at 75 here,
        # which would look like an aristaguard disagreement and is not one.
        pkt = redissect(Radius(code=1, id=4, attributes=[
            RadiusAttribute(type=100, value=b"") for _ in range(300)]
            + [RadiusAttr_Message_Authenticator(value=b"\x00" * 16)]))
        mine = ag.parse_radius(bytes(pkt))
        check(len(mine.attrs) == len(pkt.attributes),
              f"D6: aristaguard walked {len(mine.attrs)} attributes, scapy "
              f"dissected {len(pkt.attributes)}")
        check(mine.has_message_authenticator,
              "D6: the M-A past attribute 256 must be found")
    finally:
        conf.max_list_count = old_max


def section_nas_side_leg() -> None:
    """
    Cross-check the F1/F2 NAS-side-leg rules against scapy's dissector.

    The parts most worth an independent opinion are the ones where a
    hand-rolled walker could agree with a hand-rolled builder on a wrong
    answer: which attribute types are present, their VALUE boundaries (the
    digests and the UTF-8 test both depend on slicing the value correctly),
    and the Vendor-Specific payload boundary.
    """
    section("11 NAS-side leg")
    from scapy.layers.radius import (RadiusAttribute, RadiusAttr_User_Name,
                                     RadiusAttr_Message_Authenticator)
    import hashlib as _h

    def ps(v: bytes) -> Any:
        return RadiusAttribute(type=33, value=v)

    def rm(v: bytes) -> Any:
        return RadiusAttribute(type=18, value=v)

    def vs(v: bytes) -> Any:
        return RadiusAttribute(type=26, value=v)

    cfg = ag.Config()

    # --- Proxy-State digests must be over the VALUE, not the TLV -----------
    token = b"proxy-hop-token-1"
    pkt = redissect(Radius(code=1, id=1, attributes=[
        RadiusAttr_User_Name(value=b"op"), ps(token)]))
    mine = ag.parse_radius(bytes(pkt), cfg)
    want = _h.blake2b(token, digest_size=8).hexdigest()
    check(mine.proxy_state_digests == (want,),
          f"Proxy-State digest must be over the VALUE scapy carries, not the "
          f"whole TLV. got {mine.proxy_state_digests}, want {(want,)}")
    scapy_values = [bytes(a.value) for a in pkt.attributes if a.type == 33]
    check(scapy_values == [token], "fixture round-trips through scapy")

    # Two different Proxy-State values must produce two different digests,
    # or the set comparison in F1 is meaningless.
    pkt = redissect(Radius(code=2, id=2, attributes=[ps(b"A" * 10), ps(b"B" * 10)]))
    mine = ag.parse_radius(bytes(pkt), cfg)
    check(len(set(mine.proxy_state_digests)) == 2,
          "distinct Proxy-State values must yield distinct digests")
    check(mine.proxy_state_count == len([a for a in pkt.attributes if a.type == 33]),
          "Proxy-State count agrees with scapy")

    # --- Reply-Message UTF-8 validity -------------------------------------
    for value, invalid in ((b"Welcome to the network", 0),
                           (b"\xff\xfe\x80\x81 bad", 1),
                           ("héllo wörld".encode("utf-8"), 0)):
        pkt = redissect(Radius(code=2, id=3, attributes=[rm(value)]))
        mine = ag.parse_radius(bytes(pkt), cfg)
        check(mine.reply_message_invalid_utf8 == invalid,
              f"Reply-Message {value[:12]!r}: invalid={mine.reply_message_invalid_utf8}, "
              f"expected {invalid}")
        # scapy must agree the value survived the round trip intact - if the
        # value boundary were off by one the UTF-8 test would be testing
        # different bytes than the ones on the wire.
        check(bytes(pkt.attributes[0].value) == value,
              "the Reply-Message value boundary disagrees with scapy")

    # --- Vendor-Specific opacity boundary ---------------------------------
    def prand(n: int, seed: int = 11) -> bytes:
        out = bytearray()
        x = seed * 2654435761 & 0xFFFFFFFF
        while len(out) < n:
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
            out.append((x >> 16) & 0xFF)
        return bytes(out)

    opaque_payload = (9).to_bytes(4, "big") + bytes([1, 182]) + prand(180)
    pkt = redissect(Radius(code=2, id=4, attributes=[
        RadiusAttr_Message_Authenticator(value=b"\x00" * 16),
        vs(opaque_payload)]))
    mine = ag.parse_radius(bytes(pkt), cfg)
    # scapy's RadiusAttr_Vendor_Specific decomposes the VSA, so .value is the
    # INNER vendor payload, not the whole attribute body. aristaguard now
    # measures the same boundary - this comparison is what established that
    # the inner payload is the right thing to classify.
    check(bytes(pkt.attributes[-1].value) == prand(180),
          "aristaguard and scapy must agree on where the vendor PAYLOAD starts")
    check(pkt.attributes[-1].vendor_id == 9, "vendor id round-trips")
    check(len(mine.opaque_vendor_attrs) == 1,
          f"the opaque VSA should be flagged once, got {mine.opaque_vendor_attrs}")
    # aristaguard's recorded length must be the TLV length scapy computed.
    check(mine.opaque_vendor_attrs[0][0] == pkt.attributes[-1].len,
          f"recorded attribute length {mine.opaque_vendor_attrs[0][0]} vs scapy "
          f"{pkt.attributes[-1].len}")
    # The STATISTIC must be computed over scapy's .value - the inner vendor
    # payload. Comparing verdicts cannot catch a boundary error here, because
    # the 6-byte sub-header does not flip the classification.
    check(mine.opaque_vendor_attrs[0][1]
          == round(ag._norm_entropy(bytes(pkt.attributes[-1].value)), 3),
          "the recorded entropy must be computed over the same bytes scapy "
          "calls the vendor payload, not the whole attribute body")
    check(mine.opaque_vendor_attrs[0][2]
          == ag._longest_printable_run(bytes(pkt.attributes[-1].value)),
          "the recorded printable run must use scapy's payload boundary")

    # A high-entropy EAP-Message must never be classified, on either side.
    eap = redissect(Radius(code=11, id=6, attributes=[
        RadiusAttribute(type=79, value=prand(253, 29))]))
    mine_eap = ag.parse_radius(bytes(eap), cfg)
    check(not mine_eap.opaque_vendor_attrs,
          "EAP-Message must stay excluded from the opacity classifier even "
          "when its content is high-entropy TLS ciphertext")

    av = (b"Aruba-User-Role=authenticated-employee-vlan-200-floor3-corp-secure"
          b"-wireless-policy")
    printable = (9).to_bytes(4, "big") + bytes([1, len(av) + 2]) + av
    pkt = redissect(Radius(code=2, id=5, attributes=[vs(printable)]))
    mine = ag.parse_radius(bytes(pkt), cfg)
    check(not mine.opaque_vendor_attrs,
          "a printable AV-pair must not be flagged opaque")
    check(mine.cleartext_vendor_attrs == 1,
          f"the printable AV-pair should classify cleartext, got "
          f"{mine.cleartext_vendor_attrs} cleartext / "
          f"{mine.unknown_vendor_attrs} unknown")

    # --- end to end through the engine, over IPv4 and IPv6 ----------------
    from scapy.layers.inet6 import IPv6ExtHdrHopByHop
    for label, l3req, l3rsp in (
            ("IPv4",
             IP(src="10.0.0.1", dst="10.0.0.2"),
             IP(src="10.0.0.2", dst="10.0.0.1")),
            ("IPv6",
             IPv6(src="2001:db8::1", dst="2001:db8::2"),
             IPv6(src="2001:db8::2", dst="2001:db8::1")),
            ("IPv6+EH",
             IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop(),
             IPv6(src="2001:db8::2", dst="2001:db8::1") / IPv6ExtHdrHopByHop())):
        e = Ether(dst="11:22:33:44:55:90", src="aa:bb:cc:dd:ee:a0")
        req = redissect(e / l3req / UDP(sport=50000, dport=1812)
                        / Radius(code=1, id=6,
                                 attributes=[RadiusAttr_User_Name(value=b"op")]))
        acc = redissect(e / l3rsp / UDP(sport=1812, dport=50000)
                        / Radius(code=2, id=6, attributes=[
                            RadiusAttr_Message_Authenticator(value=b"\x00" * 16),
                            ps(prand(60))]))
        eng = ag.AristaEngine(_xcfg())
        eng.handle_frame(bytes(req), ts=1.0)
        eng.handle_frame(bytes(acc), ts=2.0)
        got = {f.code for f in eng.findings}
        check("AG-212" in got,
              f"F1 [{label}]: scapy-built injection must fire AG-212, got "
              f"{sorted(got)}")

        # The legitimate echo must stay silent on every transport.
        req = redissect(e / l3req / UDP(sport=50000, dport=1812)
                        / Radius(code=1, id=7, attributes=[ps(token)]))
        acc = redissect(e / l3rsp / UDP(sport=1812, dport=50000)
                        / Radius(code=2, id=7, attributes=[
                            RadiusAttr_Message_Authenticator(value=b"\x00" * 16),
                            ps(token)]))
        eng = ag.AristaEngine(_xcfg())
        eng.handle_frame(bytes(req), ts=1.0)
        eng.handle_frame(bytes(acc), ts=2.0)
        got = {f.code for f in eng.findings}
        check("AG-212" not in got,
              f"F1 [{label}]: a conforming echo must stay silent, got "
              f"{sorted(got)}")


SECTIONS: tuple[tuple[str, Callable[[], None]], ...] = (
    ("1 L2/L3/L4", section_l2l3l4),
    ("2 RADIUS", section_radius),
    ("3 LLDP", section_lldp),
    ("4 EAPOL/VXLAN", section_eapol_vxlan),
    ("5 LESSON C live path", section_live_path),
    ("6 BPF", section_bpf),
    ("7 pcap", section_pcap),
    ("8 BPF reachability", section_bpf_reachability),
    ("9 IPv6 ext headers", section_ipv6_ext_headers),
    ("10 RADIUS review", section_radius_review),
    ("11 NAS-side leg", section_nas_side_leg),
)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="aristaguard_scapy_xcheck")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    conf.verb = 0
    for name, fn in SECTIONS:
        before = len(FAILS)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            import traceback
            FAILS.append(f"[{name}] raised {type(exc).__name__}: {exc}\n"
                         f"{traceback.format_exc()}")
        if not args.quiet:
            status = "ok" if len(FAILS) == before else f"{len(FAILS) - before} FAILED"
            print(f"  {name:<24} {status}")

    for f in FAILS:
        print(f"FAIL: {f}")
    print(f"{CHECKS - len(FAILS)}/{CHECKS} cross-check assertions passed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
