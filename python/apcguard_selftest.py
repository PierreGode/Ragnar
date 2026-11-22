#!/usr/bin/env python3
"""apcguard self-test tier.

Hand-rolled builders paired against the parsers, plus AST guards, round-trip
checks and a (code x address-family) coverage matrix. The independent (scapy)
cross-check lives in apcguard_scapy_xcheck.py.
"""
from __future__ import annotations

import ast
import ipaddress
import json
import os
import struct
import sys

import apcguard as A

FAILS = []
CHECKS = [0]
FIRED = set()          # (code, af) pairs observed via the _finding spy


def check(cond, msg):
    CHECKS[0] += 1
    if not cond:
        FAILS.append(msg)


# ---------------------------------------------------------------- builders
def eth(payload, ethertype, vlans=(), smac=None):
    src = bytes.fromhex(smac.replace(":", "")) if smac else b"\x02\x00\x00\x00\x00\x01"
    f = b"\x02\x00\x00\x00\x00\x02" + src
    for vid in vlans:
        f += struct.pack("!HH", 0x8100, vid)
    f += struct.pack("!H", ethertype) + payload
    return f


def ipv4(src, dst, proto, payload, ident=1, mf=0, frag_off=0, total=None, vihl=0x45):
    s = ipaddress.ip_address(src).packed
    d = ipaddress.ip_address(dst).packed
    tot = total if total is not None else 20 + len(payload)
    ff = (mf << 13) | (frag_off // 8)
    hdr = struct.pack("!BBHHHBBH", vihl, 0, tot, ident, ff, 64, proto, 0) + s + d
    return hdr + payload


def ipv6(src, dst, nh, payload, ext=b"", frag=None):
    s = ipaddress.ip_address(src).packed
    d = ipaddress.ip_address(dst).packed
    if frag is not None:
        off, more, ident, inner_nh = frag
        fh = struct.pack("!BBHI", inner_nh, 0, (off & 0xFFF8) | (more & 1), ident)
        body, hdr_nh = fh + payload, 44
    else:
        body, hdr_nh = ext + payload, nh
    return struct.pack("!IHBB", 0x60000000, len(body), hdr_nh, 64) + s + d + body


def _csum(b):
    """RFC 1071 Internet checksum (the builder computes it; the module never verifies it)."""
    if len(b) % 2:
        b += b"\x00"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return ~t & 0xFFFF


def icmp_msg(typ, code, quote):
    return struct.pack("!BBHI", typ, code, _csum(struct.pack("!BBHI", typ, code, 0, 0) + quote), 0) + quote


def icmp_frame(src, dst, typ, code, quote, mac=None):
    return v4f(src, dst, 1, icmp_msg(typ, code, quote), mac=mac)


def tcp(sport, dport, payload):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18, 8192, 0, 0) + payload


LEAK = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 11)       # 44 bytes of "heap": deliberately NOT the packet


def jsof_11898(inner_src="9.9.9.9", inner_id=1, outer_id=0xABCD, split=24, dst=None):
    """The whitepaper's CVE-2020-11898 request (ch.4): inner IPv4{ihl=0xf,len=100,proto=0} +
    40 nulls + 100 'A'; outer fragments split after `split` bytes. -> ([frame1, frame2], inner)."""
    dst = dst or N4
    inner = ipv4(inner_src, dst, 0, b"\x00" * 40 + b"\x41" * 100, ident=inner_id, total=100, vihl=0x4F)
    return [v4f("8.8.8.8", dst, 4, inner[:split], ident=outer_id, mf=1, frag_off=0),
            v4f("8.8.8.8", dst, 4, inner[split:], ident=outer_id, mf=0, frag_off=split)], inner


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tlv(tag, val):
    n = len(val)
    if n < 128:
        ln = bytes([n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(nb)]) + nb
    return bytes([tag]) + ln + val


def enc_oid(oid):
    parts = [int(x) for x in oid.split(".")]
    b = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            b += b"\x00"
            continue
        stack = []
        while p:
            stack.append(p & 0x7F)
            p >>= 7
        for i in range(len(stack) - 1, -1, -1):
            b += bytes([stack[i] | (0x80 if i else 0)])
    return b


def snmp_response(sysdescr=None, sysobjectid=None, version=1, community=b"public"):
    vbs = b""
    if sysdescr is not None:
        vbs += tlv(0x30, tlv(0x06, enc_oid(A.OID_SYSDESCR)) + tlv(0x04, sysdescr.encode()))
    if sysobjectid is not None:
        vbs += tlv(0x30, tlv(0x06, enc_oid(A.OID_SYSOBJECTID)) + tlv(0x06, enc_oid(sysobjectid)))
    pdu = tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x30, vbs)
    pdu = tlv(0xA2, pdu)
    msg = tlv(0x02, bytes([version])) + tlv(0x04, community) + pdu
    return tlv(0x30, msg)


def dns_response(records=(), questions=1):
    hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, questions, len(records), 0, 0)
    body = b""
    for _ in range(questions):
        body += b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    for rtype, rdata, rdlen in records:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, rdlen) + rdata
    return hdr + body


def loop_msg():
    m = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 1, 0, 0)
    m += b"\xc0\x0c"                                   # answer name -> itself
    m += struct.pack("!HHIH", 1, 1, 300, 4) + b"\x7f\x00\x00\x01"
    return m


ALL_FINDINGS = []      # every finding any test engine emitted (for t_invariants)


class Collector:
    def __init__(self):
        self.f = []

    def __call__(self, f):
        self.f.append(f)
        ALL_FINDINGS.append(f)

    def codes(self):
        return [x["code"] for x in self.f]


N4, N6 = "192.0.2.10", "2001:db8::10"


def engine(nmcs=(N4, N6)):
    c = Collector()
    return A.Engine(nmcs=nmcs, emit=c, clock=lambda: 1000.0), c


def v4f(src, dst, proto, payload, mac=None, **k):
    return eth(ipv4(src, dst, proto, payload, **k), 0x0800, smac=mac)


def v6f(src, dst, nh, payload, mac=None, **k):
    return eth(ipv6(src, dst, nh, payload, **k), 0x86DD, smac=mac)


def descr(hw, app, pf, mn="AP8959", af1=None):
    """A sysDescr in the on-the-wire grammar confirmed against public captures."""
    n = pf.replace(".", "")
    return ("APC Web/SNMP Management Card (MB:v4.1.0 PF:v%s PN:apc_%s_aos_%s.bin AF1:v%s "
            "AN1:apc_%s_%s_%s.bin MN:%s HR:02 SN: REDACTED MD:01/15/2020)"
            % (pf, hw, n, af1 or pf, hw, app, n, mn))


DESCR = descr("hw05", "rpdu2g", "6.9.4")

# REAL sysDescr strings from public posts and scans (serials redacted; forum line-wrap artifacts
# repaired). (label, text, expected state, hw, app, PF, MN). Expected outcomes are written BY HAND
# from Schneider's rule (affected iff AOS <= last-affected), not taken from the code under test.
_P = "APC Web/SNMP Management Card "
_T = " (Embedded PowerNet SNMP Agent SW v2.2 compatible)"
CORPUS = [
    ("se-community rpdu2g AP8841", _P + "(MB:v4.1.0 PF:v6.4.0 PN:apc_hw05_aos_640.bin AF1:v6.4.0 AN1:apc_hw05_rpdu2g_640.bin MN:AP8841 HR:02 SN: REDACTED MD:04/14/2015)", "affected", "hw05", "rpdu2g", "v6.4.0", "AP8841"),
    ("se-community XRDP hw03", _P + "(MB:v4.0.6 PF:v3.7.5 PN:apc_hw03_aos_375.bin AF1:v3.7.2 AN1:apc_hw03_xrdp_372.bin MN:0G-9354-01 HR:0C SN: REDACTED MD:11/18/2014)", "not_gateable", "hw03", "xrdp", "v3.7.5", "0G-9354-01"),
    ("NUT #2665 AP9630", _P + "(MB:v4.1.0 PF:v6.5.0 PN:apc_hw05_aos_650.bin AF1:v6.5.0 AN1:apc_hw05_sumx_650.bin MN:AP9630 HR:08 SN: REDACTED MD:07/10/2018)" + _T, "affected", "hw05", "sumx", "v6.5.0", "AP9630"),
    ("zabbix forum AP9631 6.6.4", _P + "(MB:v4.1.0 PF:v6.6.4 PN:apc_hw05_aos_664.bin AF1:v6.6.4 AN1:apc_hw05_sumx_664.bin MN:AP9631 HR:08 SN: REDACTED MD:09/03/2019)" + _T, "affected", "hw05", "sumx", "v6.6.4", "AP9631"),
    ("se-community AP9619 NMC1 UPS", _P + "(MB:v3.9.2 PF:v3.7.3 PN:apc_hw02_aos_373.bin AF1:v3.7.2 AN1:apc_hw02_sumx_372.bin MN:AP9619 HR:A10 SN: REDACTED MD:06/28/2006)" + _T, "affected", "hw02", "sumx", "v3.7.3", "AP9619"),
    ("se-community AP7832 NMC1 PDU", _P + "(MB:v3.9.2 PF:v3.9.0 PN:apc_hw02_aos_390.bin AF1:v3.7.4 AN1:apc_hw02_rpdu_374.bin MN:AP7832 HR:B2 SN: REDACTED MD:11/14/2007)", "affected", "hw02", "rpdu", "v3.9.0", "AP7832"),
    ("shodan AP7930 PF=3.9.2 (boundary)", _P + "(MB:v4.1.1 PF:v3.9.2 PN:apc_hw02_aos_392.bin AF1:v3.9.2 AN1:apc_hw02_rpdu_392.bin MN:AP7930 HR:B2 SN: REDACTED MD:05/26/2009)", "affected", "hw02", "rpdu", "v3.9.2", "AP7930"),
    ("observium AP9631 6.0.6", _P + "(MB:v4.0.1 PF:v6.0.6 PN:apc_hw05_aos_606.bin AF1:v6.0.6 AN1:apc_hw05_sumx_606.bin MN:AP9631 HR:05 SN: REDACTED MD:03/29/2011)" + _T, "affected", "hw05", "sumx", "v6.0.6", "AP9631"),
    ("shodan AP9630 5.1.7", _P + "(MB:v4.0.1 PF:v5.1.7 PN:apc_hw05_aos_517.bin AF1:v5.1.7 AN1:apc_hw05_sumx_517.bin MN:AP9630 HR:05 SN: REDACTED MD:09/06/2013)" + _T, "affected", "hw05", "sumx", "v5.1.7", "AP9630"),
    ("se-community AP9641 NMC3 (source truncated after SN)", _P + "(MB:v4.2.9 PF:v1.4.0.23 PN:apc_hw21_aos_1.4.0.23.bin AF1:v1.4.0.19 AN1:apc_hw21_su_1.4.0.19.bin MN:AP9641 HR:5 SN: REDACTED)", "fixed", "hw21", "su", "v1.4.0.23", "AP9641"),
    ("shodan AP8953 AOS 7.0.8", _P + "(MB:v4.1.0 PF:v7.0.8 PN:apc_hw05_aos_708.bin AF1:v7.0.8 AN1:apc_hw05_rpdu2g_708.bin MN:AP8953 HR:02 SN: REDACTED MD:02/19/2015)", "fixed", "hw05", "rpdu2g", "v7.0.8", "AP8953"),
    ("shodan AP7900B = NMC2 despite AP79 prefix", _P + "(MB:v4.1.0 PF:v6.5.6 PN:apc_hw05_aos_656.bin AF1:v6.5.6 AN1:apc_hw05_rpdu2g_656.bin MN:AP7900B HR:B2 SN: REDACTED MD:01/24/2019)", "affected", "hw05", "rpdu2g", "v6.5.6", "AP7900B"),
    ("shodan AP7900 NMC1", _P + "(MB:v3.9.2 PF:v3.7.4 PN:apc_hw02_aos_374.bin AF1:v3.7.4 AN1:apc_hw02_rpdu_374.bin MN:AP7900 HR:B2 SN: REDACTED MD:09/09/2009)", "affected", "hw02", "rpdu", "v3.7.4", "AP7900"),
]


# ---------------------------------------------------------------- version gate
def sv(hw, app, pf, mn="AP8959"):
    return A.screen_version(A.parse_sysdescr(descr(hw, app, pf, mn)))


def _dot(t):
    return ".".join(map(str, t))


def t_version():
    for hw, plat in A.PLATFORMS.items():
        mx, ff = _dot(plat["max_affected"]), _dot(plat["first_fixed"])
        gap = _dot(plat["max_affected"][:-1] + (plat["max_affected"][-1] + 1,))
        check(A.version_le(A.parse_version(gap), plat["first_fixed"]) and gap != ff,
              f"{hw}: test gap version {gap} must sit strictly between last-affected and first-fixed")
        for app in plat["apps"]:
            r = sv(hw, app, mx)
            check(r["code"] == plat["code"] and r["state"] == "affected", f"{hw}/{app} at {mx}: {r}")
            r = sv(hw, app, "0.9.9")
            check(r["code"] == plat["code"], f"{hw}/{app} older version affected")
            r = sv(hw, app, gap)
            check(r["code"] == "APC-011" and r["state"] == "gap", f"{hw}/{app} gap {gap}: {r}")
            r = sv(hw, app, ff)
            check(r["code"] is None and r["state"] == "fixed", f"{hw}/{app} first fixed {ff}: {r}")
            r = sv(hw, app, "99.0")
            check(r["code"] is None and r["state"] == "fixed", f"{hw}/{app} far above fix")
    check(A.version_le((1, 3, 3, 1), (1, 3, 3, 1)) and not A.version_le((1, 3, 3, 2), (1, 3, 3, 1)),
          "4-part version compare")
    check(A.parse_version("v6.9.10") == (6, 9, 10) and not A.version_le((6, 9, 10), (6, 9, 4)),
          "6.9.10 is newer than 6.9.4 (no string compare)")
    for mn in ("AP7900B", "0G-9354-01", "AP9641", "ANYTHING"):
        check(sv("hw05", "rpdu2g", "6.5.6", mn)["code"] == "APC-001", f"model {mn} must not change the verdict")
    r = sv("hw05", "coolingx", "6.9.4")
    check(r["code"] == "APC-011" and r["reason"] == "app_not_in_vendor_table", f"unknown app: {r}")
    r = sv("hw03", "xrdp", "3.7.5")
    check(r["code"] == "APC-011" and r["reason"] == "unknown_platform", f"unknown hw: {r}")
    conflict = ("APC Web/SNMP Management Card (PF:v6.9.4 PN:apc_hw05_aos_694.bin "
                "AN1:apc_hw21_su_1.4.0.19.bin MN:AP9641)")
    r = A.screen_version(A.parse_sysdescr(conflict))
    check(r["code"] == "APC-011" and r["reason"] == "hw_token_conflict", f"hw conflict: {r}")
    check(A.screen_version(A.parse_sysdescr("APC Web/SNMP Management Card (garbage)"))["reason"] == "no_fields",
          "no fields")
    check(A.screen_version(A.parse_sysdescr("APC Web/SNMP Management Card"))["reason"] == "no_field_block",
          "no field block")
    check(A.screen_version(A.parse_sysdescr(descr("hw05", "rpdu2g", "x.y")))["reason"] == "no_aos_version",
          "unparseable AOS")
    check(A.parse_sysdescr("Linux box") is None, "non-APC text is not parsed")
    check("11901" in sv("hw05", "rpdu2g", "6.9.4").get("note", ""), "NMC2 6.9.4 carries the 11901 note")
    check("11901" in sv("hw05", "rpdu2g", "6.9.2").get("note", ""), "NMC2 6.9.2 carries the 11901 note")
    check("note" not in sv("hw05", "rpdu2g", "6.9.1"), "NMC2 6.9.1 carries no partial-fix note")
    check("note" not in sv("hw02", "rpdu", "3.9.2"), "NMC1 never carries the NMC2 note")
    # the gate is on PF (AOS), never AF1 (application firmware): make the two DISAGREE
    r = A.screen_version(A.parse_sysdescr(descr("hw05", "rpdu2g", "6.9.6", af1="6.9.4")))
    check(r["state"] == "fixed", f"PF 6.9.6 with AF1 6.9.4 must be fixed (gate is PF): {r['state']}")
    r = A.screen_version(A.parse_sysdescr(descr("hw05", "rpdu2g", "6.9.4", af1="6.9.6")))
    check(r["state"] == "affected", f"PF 6.9.4 with AF1 6.9.6 must be affected (gate is PF): {r['state']}")
    check(sv("hw05", "rpdu2g", "6.9.4")["app_token_verified"] is True, "rpdu2g is a verified token")
    check(sv("hw05", "ats4g", "6.9.4")["app_token_verified"] is False, "ats4g is NOT a verified token")


def t_corpus():
    """REAL sysDescr strings: parse fields, gate outcome, and the full engine path."""
    check(len(CORPUS) == 13, f"corpus size {len(CORPUS)}")
    for label, text, state, hw, app, pf, mn in CORPUS:
        check("SN: REDACTED" in text, f"{label}: serial not redacted")
        rec = A.parse_sysdescr(text)
        check(rec["hw"] == hw and rec["app"] == app and rec["pf"] == pf and rec["model"] == mn,
              f"{label}: parsed hw={rec.get('hw')} app={rec.get('app')} pf={rec.get('pf')} mn={rec.get('model')}")
        r = A.screen_version(rec)
        check(r["state"] == state, f"{label}: state {r['state']} expected {state}")
        eng, c = engine()
        eng.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=text))))
        want = {"affected": A.PLATFORMS.get(hw, {}).get("code"), "not_gateable": "APC-011", "fixed": None}[state]
        gate_codes = [x["code"] for x in c.f if x["code"] != "APC-010"]
        check(gate_codes == ([want] if want else []), f"{label}: engine emitted {gate_codes}, want {want}")
        check("APC-010" in c.codes(), f"{label}: inventory finding")
    seen = {(A.parse_sysdescr(t)["hw"], A.parse_sysdescr(t)["app"]) for _, t, *_ in CORPUS}
    check(A.VERIFIED_APP_TOKENS <= seen, f"verified tokens not in corpus: {A.VERIFIED_APP_TOKENS - seen}")
    row = [c for c in CORPUS if "AP7900B" in c[0]][0]
    check(A.screen_version(A.parse_sysdescr(row[1]))["platform"] == "NMC2", "AP7900B is NMC2")


# ---------------------------------------------------------------- L3 parse
def t_l3():
    l3 = A.parse_l3(v4f("192.0.2.1", N4, 17, udp(161, 40000, b"x")))
    check(l3.af == 4 and l3.proto == 17 and l3.dst == N4, "ipv4 parse")
    l3 = A.parse_l3(eth(ipv4("192.0.2.1", N4, 17, b"x"), 0x0800, vlans=(100, 200)))
    check(l3 and l3.dst == N4, "qinq parse")
    l3 = A.parse_l3(v6f("2001:db8::1", N6, 17, udp(161, 40000, b"x")))
    check(l3.af == 6 and l3.proto == 17, "ipv6 parse")
    ext = bytes([17, 0]) + b"\x00" * 6
    l3 = A.parse_l3(v6f("2001:db8::1", N6, 0, udp(161, 40000, b"x"), ext=ext))
    check(l3 and l3.proto == 17, "ipv6 ext-hdr walk")
    l3 = A.parse_ipv4(ipv4("1.1.1.1", N4, 4, b"AAAA", mf=1))
    check(l3.frag and not l3.l4_usable, "ipv4 frag flagged")


# ---------------------------------------------------------------- SNMP / Class B
def t_snmp():
    eng, c = engine()
    eng.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR))))
    check("APC-010" in c.codes(), "inventory emitted")
    check("APC-001" in c.codes(), "version gate emitted")
    b = [x for x in c.f if x["code"] == "APC-001"][0]
    check(b["detail"]["model"] == "AP8959" and b["detail"]["aos"] == "v6.9.4", "parsed model/aos")
    check(b["detail"]["hw"] == "hw05" and b["detail"]["app"] == "rpdu2g", "parsed hw/app tokens")
    check(b["confidence"] == "version-in-range" and b["detail"]["state"] == "affected", "confidence label")
    check(b["detail"]["first_fixed"] == "6.9.6" and "note" in b["detail"], "first_fixed + partial-fix note")
    eng2, c2 = engine()
    eng2.handle_frame(v4f(N4, "192.0.2.1", 17,
                          udp(161, 40000, snmp_response(sysdescr=DESCR, version=3))))
    check("APC-001" not in c2.codes(), "v3 not gated")
    eng3, c3 = engine()
    eng3.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(
        sysdescr=descr("hw05", "rpdu2g", "6.9.6")))))
    inv = [x for x in c3.f if x["code"] == "APC-010"]
    check(c3.codes() == ["APC-010"] and inv[0]["detail"]["state"] == "fixed", "fixed -> inventory only, state=fixed")
    eng.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR))))
    check(c.codes().count("APC-001") == 1, "gate dedup")
    eng4, c4 = engine()
    eng4.handle_frame(v4f(N4, "192.0.2.1", 17,
                          udp(161, 40000, snmp_response(sysdescr="Linux box"))))
    check(not c4.f, "non-APC ignored")
    eng5, c5 = engine()
    eng5.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(
        sysdescr="APC Web/SNMP Management Card (PF:v6.9.4)"))))
    x5 = [x for x in c5.f if x["code"] == "APC-011"]
    check(x5 and x5[0]["confidence"] == "low", "APC-011 on missing tokens, low confidence")
    eng6, c6 = engine()
    eng6.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(
        sysdescr=descr("hw05", "rpdu2g", "6.9.5")))))
    x6 = [x for x in c6.f if x["code"] == "APC-011"]
    check(x6 and x6[0]["detail"]["reason"] == "version_gap_between_last_affected_and_first_fixed",
          "6.9.5 gap reported as APC-011")
    for hw, app, ver, mn, code in [("hw02", "rpdu", "3.9.2", "AP7900", "APC-002"),
                                   ("hw21", "su", "1.3.3.1", "AP9641", "APC-003")]:
        e, cc = engine()
        e.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(
            sysdescr=descr(hw, app, ver, mn)))))
        check(code in cc.codes(), f"engine emits {code}")
    eng7, c7 = engine()
    for ver in ("6.9.4", "6.9.6", "6.9.4"):
        eng7.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(
            sysdescr=descr("hw05", "rpdu2g", ver)))))
    check(c7.codes().count("APC-001") == 2, "downgrade after fix is reported again")


def t_snmp_v6():
    eng, c = engine()
    eng.handle_frame(v6f(N6, "2001:db8::1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR))))
    b = [x for x in c.f if x["code"] == "APC-001"]
    check(b and b[0]["af"] == "ipv6", "class B over IPv6")
    check(b and b[0]["src"].startswith("[2001:db8::10]:"), "v6 endpoint bracketed")


# ---------------------------------------------------------------- tunnels
def _tunnel_frags_v4(inner, ident, src="8.8.8.8", dst=N4):
    h = len(inner) // 2
    h -= h % 8
    return [v4f(src, dst, 4, inner[:h], ident=ident, mf=1, frag_off=0),
            v4f(src, dst, 4, inner[h:], ident=ident, mf=0, frag_off=h)]


def t_tunnels():
    inner = ipv4("9.9.9.9", N4, 17, b"P" * 200, total=28)
    f1, f2 = _tunnel_frags_v4(inner, 7)
    eng, c = engine()
    eng.handle_frame(f1)
    check("APC-101" in c.codes(), "APC-101 on first tunnel fragment")
    eng.handle_frame(f2)
    check("APC-102" in c.codes(), "APC-102 on reassembled trim condition")
    r = [x for x in c.f if x["code"] == "APC-102"][0]
    check(r["confidence"] == "high" and r["af"] == "ipv4", "102 v4 high conf")
    r1 = [x for x in c.f if x["code"] == "APC-101"][0]
    check(r1["confidence"] == "high", "101 v4 high conf")
    inner0 = ipv4("9.9.9.9", N4, 0, b"P" * 200, total=28)
    eng2, c2 = engine()
    for fr in _tunnel_frags_v4(inner0, 9):
        eng2.handle_frame(fr)
    r2 = [x for x in c2.f if x["code"] == "APC-102"][0]
    check("CVE-2020-11898" in r2["cves"], "inner proto 0 adds 11898")
    r2b = [x for x in c.f if x["code"] == "APC-102"][0]
    check("CVE-2020-11898" not in r2b["cves"], "inner proto 17 does not add 11898")
    inner200 = ipv4("9.9.9.9", N4, 200, b"P" * 200, total=28)
    eng2b, c2b = engine()
    for fr in _tunnel_frags_v4(inner200, 10):
        eng2b.handle_frame(fr)
    r2c = [x for x in c2b.f if x["code"] == "APC-102"][0]
    check(r2c["cves"] == ["CVE-2020-11896"], f"inner proto 200 must not attribute 11898: {r2c['cves']}")
    eng3, c3 = engine()
    eng3.handle_frame(v4f("8.8.8.8", N4, 41, b"\x60" + b"\x00" * 39))
    check("APC-105" in c3.codes(), "APC-105 proto41")
    eng4, c4 = engine()
    eng4.handle_frame(v4f("8.8.8.8", N4, 4, ipv4("9.9.9.9", N4, 17, b"data")))
    check(c4.codes() == ["APC-104"], "unfragmented tunnel -> 104 only")
    eng5, c5 = engine()
    eng5.handle_frame(v4f("8.8.8.8", "203.0.113.5", 4, inner[:96], ident=3, mf=1))
    check(not c5.f, "tunnel to non-NMC ignored")
    # IPv6-outer fragmented tunnel: reported as APC-104 ONLY -- 11896/11898 are IPv4-outer
    hv = len(inner) // 2
    hv -= hv % 8
    eng6, c6 = engine(nmcs=(N6,))
    eng6.handle_frame(v6f("2001:db8::1", N6, 4, inner[:hv], frag=(0, 1, 5, 4)))
    eng6.handle_frame(v6f("2001:db8::1", N6, 4, inner[hv:], frag=(hv, 0, 5, 4)))
    check(c6.codes() == ["APC-104"] and c6.f[0]["af"] == "ipv6",
          f"v6-outer fragmented tunnel -> 104 only, got {c6.codes()}")
    check(not c6.f[0]["cves"], "v6-outer tunnel finding attributes no CVE")
    # unfragmented v6-outer tunnel -> 104 (v6)
    eng7, c7 = engine(nmcs=(N6,))
    eng7.handle_frame(v6f("2001:db8::1", N6, 4, ipv4("9.9.9.9", N4, 17, b"data")))
    check(c7.codes() == ["APC-104"] and c7.f[0]["af"] == "ipv6", "v6-outer unfragmented -> 104")
    # proto 41 over IPv6 is NOT the 11902 condition: 104, never 105
    eng8, c8 = engine(nmcs=(N6,))
    eng8.handle_frame(v6f("2001:db8::1", N6, 41, b"\x60" + b"\x00" * 39))
    check("APC-105" not in c8.codes() and "APC-104" in c8.codes(),
          "IPv6-in-IPv6 must not claim 11902")


# ---------------------------------------------------------------- JSOF whitepaper fixtures
def t_jsof():
    """The exact packets from JSOF's Ripple20 whitepaper (ch.2.3 and ch.4), reproduced by NVISO."""
    udp_in = struct.pack("!HHHH", 1234, 5678, 12, 0) + b"A" * 1000
    inner = ipv4("9.9.9.9", N4, 17, udp_in, total=32)
    eng, c = engine()
    eng.handle_frame(v4f("8.8.8.8", N4, 4, inner[:40], ident=0xABCD, mf=1, frag_off=0))
    eng.handle_frame(v4f("8.8.8.8", N4, 4, inner[40:], ident=0xABCD, mf=0, frag_off=40))
    check(c.codes() == ["APC-101", "APC-102"], f"JSOF 11896 example: {c.codes()}")
    r = c.f[1]
    check(r["cves"] == ["CVE-2020-11896"] and r["detail"]["inner_total_length"] == 32
          and r["detail"]["inner_data"] == 1028 and r["detail"]["inner_proto"] == 17,
          f"JSOF 11896 example detail: {r['cves']} {r['detail']}")
    inner = ipv4("9.9.9.9", N4, 0, b"\x00" * 40 + b"\x41" * 100, total=100, vihl=0x4F)
    eng2, c2 = engine()
    eng2.handle_frame(v4f("8.8.8.8", N4, 4, inner[:24], ident=0xABCD, mf=1, frag_off=0))
    eng2.handle_frame(v4f("8.8.8.8", N4, 4, inner[24:], ident=0xABCD, mf=0, frag_off=24))
    check(c2.codes() == ["APC-101", "APC-102"], f"JSOF 11898 example: {c2.codes()}")
    r2 = c2.f[1]
    check(r2["cves"] == ["CVE-2020-11896", "CVE-2020-11898"] and r2["detail"]["inner_proto"] == 0
          and r2["detail"]["inner_total_length"] == 100, f"JSOF 11898 example: {r2['cves']} {r2['detail']}")
    longer = ipv4("9.9.9.9", N4, 0, b"\x00" * 40 + b"\x41" * 100, total=500, vihl=0x4F)
    eng3, c3 = engine()
    eng3.handle_frame(v4f("8.8.8.8", N4, 4, longer[:24], ident=0xABCE, mf=1, frag_off=0))
    eng3.handle_frame(v4f("8.8.8.8", N4, 4, longer[24:], ident=0xABCE, mf=0, frag_off=24))
    check("APC-102" not in c3.codes(), "inner length LONGER than data must not raise APC-102")


# ---------------------------------------------------------------- REAL-STACK fixtures
# Recorded Sept 2026 in a sealed network namespace pair (veth) from a Linux 6.18 kernel that has NO
# IPIP or SIT handler, so it answers an unhandled outer protocol 4 / 41 exactly as RFC 792 says a host
# without the protocol should. This is a REAL IP stack, NOT a Treck stack: it validates the parser and
# the request/reply matching on genuine ICMP bytes (note it quotes the WHOLE datagram, up to 180 bytes
# here, not the whitepaper's "header + 8"), and says nothing about what an NMC does. Client 10.99.0.1,
# "card" 10.99.0.2. Whole Ethernet frames.
REAL_LINUX = {
    "unfrag4": {"req": [bytes.fromhex(
        '2e57b92f202e5e43999590ff08004500004411110000400454dd0a6300010a63000245000030000700004011'
        '65ee0a6300010a63000204d2162e001c43614141414141414141414141414141414141414141')],
               "reply": bytes.fromhex(
        '5e43999590ff2e57b92f202e080045c00060822700004001e2ed0a6300020a630001030211f4000000004500'
        '004411110000400454dd0a6300010a6300024500003000070000401165ee0a6300010a63000204d2162e001c'
        '43614141414141414141414141414141414141414141')},
    "frag4": {"req": [bytes.fromhex(
        '2e57b92f202e5e43999590ff08004500002c22222000400423e40a6300010a6300024f000064000100004000'
        '5bd10a6300010a63000200000000'),
                     bytes.fromhex(
        '2e57b92f202e5e43999590ff08004500009c22220003400443710a6300010a63000200000000000000000000'
        '0000000000000000000000000000000000000000000000000000414141414141414141414141414141414141'
        '4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141'
        '4141414141414141414141414141414141414141414141414141414141414141414141414141')],
              "reply": bytes.fromhex(
        '5e43999590ff2e57b92f202e080045c000d0826200004001e2420a6300020a63000103023e3f000000004500'
        '00b4222200004004435c0a6300010a6300024f0000640001000040005bd10a6300010a630002000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000041414141414141414141'
        '4141414141414141414141414141414141414141414141414141414141410000000000000000414141414141'
        '4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141'
        '4141')},
    "proto41": {"req": [bytes.fromhex(
        '2e57b92f202e5e43999590ff08004500004633330000402932940a6300010a63000260000000000a3b402001'
        '0db800000000000000000000000120010db800000000000000000000000242424242424242424242')],
               "reply": bytes.fromhex(
        '5e43999590ff2e57b92f202e080045c00062828a00004001e2880a6300020a6300010302baf2000000004500'
        '004633330000402932940a6300010a63000260000000000a3b4020010db80000000000000000000000012001'
        '0db800000000000000000000000242424242424242424242')},
}
REAL_CARD = "10.99.0.2"


# ---------------------------------------------------------------- tunnel rejection (APC-107 / APC-108)
def t_tunnel_fact():
    inner = ipv4("9.9.9.9", N4, 17, b"data")
    outer = ipv4("8.8.8.8", N4, 4, inner, ident=0x1111)              # unfragmented IP-in-IP
    req = eth(outer, 0x0800)
    q = outer[:28]                                                   # the OUTER header + 8 bytes
    o41 = ipv4("8.8.8.8", N4, 41, b"\x60" + b"\x00" * 39, ident=0x4141)
    req41, q41 = eth(o41, 0x0800), o41[:28]

    def flow(frames, replies, *, nmcs=(N4, N6), delay=0.0):
        t = [1000.0]
        c = Collector()
        eng = A.Engine(nmcs=nmcs, emit=c, clock=lambda: t[0])
        for f in frames:
            eng.handle_frame(f)
        t[0] += delay
        for r in replies:
            eng.handle_frame(r)
        return eng, c

    def rep(quote, *, src=N4, dst="8.8.8.8", typ=3, code=2):
        return icmp_frame(src, dst, typ, code, quote)

    # -- protocol 4: rejected outer header -> APC-104 (the tunnel datagram) + APC-107 (the rejection)
    eng, c = flow([req], [rep(q)])
    check(c.codes() == ["APC-104", "APC-107"], f"proto 4 rejection: {c.codes()}")
    f = c.f[1]
    check(f["severity"] == "info" and f["cves"] == [] and f["src"] == N4 and f["dst"] == "8.8.8.8", f"APC-107 shape: {f}")
    check(f["detail"]["outer_proto"] == 4 and f["detail"]["outer_fragmented"] is False
          and f["detail"]["prerequisite_of"] == "CVE-2020-11896,CVE-2020-11898", f"APC-107 detail: {f['detail']}")
    check("immune" in f["detail"]["note"] and "DoS can remain" in f["detail"]["note"], "the caveats travel with the finding")
    check(eng.tunnel_state(N4) == {"ip-in-ip": "inactive"}, f"per-card state: {eng.tunnel_state(N4)}")
    # -- protocol 41 is its own claim, its own code, its own CVE, and does NOT flip the protocol-4 state
    eng, c = flow([req41], [rep(q41)])
    check(c.codes() == ["APC-105", "APC-108"], f"proto 41 rejection: {c.codes()}")
    check(c.f[1]["detail"]["prerequisite_of"] == "CVE-2020-11902" and c.f[1]["cves"] == [], "APC-108 names 11902 as prerequisite only")
    check(eng.tunnel_state(N4) == {"ipv6-in-ipv4": "inactive"}, "a protocol-41 rejection says nothing about protocol 4")
    eng, c = flow([req, req41], [rep(q), rep(q41)])
    check(eng.tunnel_state(N4) == {"ip-in-ip": "inactive", "ipv6-in-ipv4": "inactive"}, "both observed independently")
    # -- a FRAGMENTED outer datagram is rejected after reassembly; the flag records which case was seen
    frs, inner_f = jsof_11898(outer_id=0x2222)
    ohdr = ipv4("8.8.8.8", N4, 4, inner_f, ident=0x2222)
    eng, c = flow(frs, [rep(ohdr[:28])])
    check(c.codes() == ["APC-101", "APC-102", "APC-107"], f"fragmented outer rejected: {c.codes()}")
    check(c.f[2]["detail"]["outer_fragmented"] is True, "outer_fragmented recorded")
    # -- rejection is NOT an answer to the inner packet: quoting the OUTER header never raises 103/106
    check("APC-103" not in c.codes() and "APC-106" not in c.codes(), "outer rejection is not an inner answer")
    # -- attack findings are NEVER suppressed by an earlier 'inactive' fact
    eng, c = flow([req], [rep(q)])
    n = len(c.f)
    for fr in jsof_11898(outer_id=0x3333)[0]:
        eng.handle_frame(fr)
    check([x["code"] for x in c.f[n:]] == ["APC-101", "APC-102"], "an inactive fact must not suppress attack findings")
    # -- wrong ICMP type / code
    for typ, code in ((3, 3), (3, 1), (3, 13), (11, 1), (5, 2), (12, 2), (8, 0)):
        check(flow([req], [rep(q, typ=typ, code=code)])[1].codes() == ["APC-104"], f"ICMP {typ}/{code} is not a rejection")
    # -- unmatched / spoofed / stale / repeated
    check(flow([req], [rep(q, src="203.0.113.7")])[1].codes() == ["APC-104"], "reply from a non-NMC is ignored")
    check(flow([req], [rep(q, src="192.0.2.11")], nmcs=(N4, N6, "192.0.2.11"))[1].codes() == ["APC-104"],
          "reply from a DIFFERENT NMC than the one probed is ignored")
    check(flow([req], [rep(q, dst="8.8.8.9")])[1].codes() == ["APC-104"], "reply not addressed to the quoted source is ignored")
    check(flow([], [rep(q)])[1].codes() == [], "a reply with no observed request reports nothing")
    other = ipv4("8.8.8.8", N4, 4, inner, ident=0x9999)
    check(flow([req], [rep(other[:28])])[1].codes() == ["APC-104"], "quote of a different datagram (id) is not matched")
    check(flow([req], [rep(q)], delay=A.ANSWER_WINDOW + 1)[1].codes() == ["APC-104"], "reply after the window is ignored")
    e2, c2 = flow([req], [rep(q)])
    e2.handle_frame(eth(ipv4("8.8.8.8", N4, 4, inner, ident=0x1112), 0x0800))
    e2.handle_frame(rep(ipv4("8.8.8.8", N4, 4, inner, ident=0x1112)[:28]))
    check(c2.codes().count("APC-107") == 1, "a repeated rejection is a fact, not a stream")
    # -- the earlier fact is superseded, visibly, when the SAME card later decapsulates (APC-103)
    e3, c3 = flow([req], [rep(q)])
    n = len(c3.f)
    frames2, inner2 = jsof_11898()
    for fr in frames2:
        e3.handle_frame(fr)
    e3.handle_frame(icmp_frame(N4, "9.9.9.9", 3, 2, inner2[:24] + LEAK))
    f103 = [x for x in c3.f[n:] if x["code"] == "APC-103"][0]
    check(f103["detail"].get("previously_observed") == "inactive", "APC-103 marks the earlier inactive fact as stale")
    check(e3.tunnel_state(N4) == {"ip-in-ip": "active"}, f"state is now active: {e3.tunnel_state(N4)}")
    n = len(c3.f)
    e3.handle_frame(eth(ipv4("8.8.8.8", N4, 4, inner, ident=0x5555), 0x0800))
    e3.handle_frame(rep(ipv4("8.8.8.8", N4, 4, inner, ident=0x5555)[:28]))
    check("APC-107" in [x["code"] for x in c3.f[n:]], "a rejection AFTER an active observation is reported again")
    # a normal 103 carries no 'previously_observed'
    check("previously_observed" not in flow(*jsof_11898()[:1], [icmp_frame(N4, "9.9.9.9", 3, 2, jsof_11898()[1][:24] + LEAK)])[1].f[2]["detail"],
          "no stale marker without a prior inactive fact")
    # -- double encapsulation: a quote of the INNER header (matches a flagged datagram) is an answer, not a rejection
    dinner = ipv4("9.9.9.9", N4, 4, b"\x00" * 40 + b"\x41" * 100, total=100, vihl=0x4F)
    dfr = [v4f("8.8.8.8", N4, 4, dinner[:24], ident=0x6666, mf=1, frag_off=0),
           v4f("8.8.8.8", N4, 4, dinner[24:], ident=0x6666, mf=0, frag_off=24)]
    dc = flow(dfr, [icmp_frame(N4, "9.9.9.9", 3, 2, dinner[:24] + LEAK)])[1].codes()
    check("APC-103" in dc and "APC-107" not in dc, f"inner protocol 4 quote is an answer: {dc}")
    # -- IPv6: no counterpart; nothing is remembered, nothing fires
    e6, c6 = engine()
    e6.handle_frame(v6f("2001:db8::1", N6, 4, ipv4("9.9.9.9", N4, 17, b"x")))
    check(not e6.pending_outer and c6.codes() == ["APC-104"], "IPv6-outer tunnels are not tracked for rejection")
    # -- bounded state, and no payload retained
    t = [1000.0]
    c7 = Collector()
    big = A.Engine(nmcs=(N4,), emit=c7, clock=lambda: t[0])
    for i in range(A.MAX_PENDING + 50):
        big.handle_frame(eth(ipv4("8.8.8.8", N4, 4, inner, ident=i + 1), 0x0800))
        t[0] += 0.001
    check(len(big.pending_outer) <= A.MAX_PENDING, f"pending_outer bounded: {len(big.pending_outer)}")
    check(all(set(v) == {"t", "nmc", "frag"} for v in big.pending_outer.values()), "outer entries hold no payload")


def t_real_linux():
    """REAL ICMP replies from a real IP stack (Linux, no IPIP/SIT handler) over the same engine."""
    expect = {"unfrag4": (["APC-104", "APC-107"], 68, False, 4),
              "frag4": (["APC-101", "APC-102", "APC-107"], 180, True, 4),
              "proto41": (["APC-105", "APC-108"], 70, False, 41)}
    for name, (codes, qlen, frag, proto) in expect.items():
        fx = REAL_LINUX[name]
        rp = fx["reply"]
        check(rp[14 + 20] == 3 and rp[14 + 21] == 2, f"{name}: the fixture really is ICMP type 3 code 2")
        check(len(rp) - 14 - 20 - 8 == qlen, f"{name}: real quote length {len(rp) - 42} != {qlen}")
        t = [1000.0]
        c = Collector()
        eng = A.Engine(nmcs=(REAL_CARD,), emit=c, clock=lambda: t[0])
        for r in fx["req"]:
            eng.handle_frame(r)
        eng.handle_frame(rp)
        check(c.codes() == codes, f"{name}: real stack -> {c.codes()}, want {codes}")
        f = c.f[-1]
        check(f["detail"]["outer_proto"] == proto and f["detail"]["outer_fragmented"] is frag
              and f["detail"]["quote_bytes"] == qlen and f["cves"] == [] and f["src"] == REAL_CARD,
              f"{name}: detail {f['detail']}")
        # the reply alone (request not seen) reports nothing
        c2 = Collector()
        A.Engine(nmcs=(REAL_CARD,), emit=c2, clock=lambda: 1000.0).handle_frame(rp)
        check(c2.f == [], f"{name}: a reply without its request reports nothing")
    # a correct real stack quoting the OUTER header is never mistaken for a disclosure or an inner answer
    for name in expect:
        c = Collector()
        eng = A.Engine(nmcs=(REAL_CARD,), emit=c, clock=lambda: 1000.0)
        for fr in REAL_LINUX[name]["req"] + [REAL_LINUX[name]["reply"]]:
            eng.handle_frame(fr)
        check("APC-103" not in c.codes() and "APC-106" not in c.codes(), f"{name}: no false answer/disclosure")


# ---------------------------------------------------------------- ICMP response (APC-103 / APC-106)
def t_icmp():
    frames, inner = jsof_11898()

    def flow(quote=None, *, frs=None, src=N4, dst="9.9.9.9", typ=3, code=2, delay=0.0, times=1, msg=None,
             nmcs=(N4, N6)):
        t = [1000.0]
        c = Collector()
        eng = A.Engine(nmcs=nmcs, emit=c, clock=lambda: t[0])
        for f in (frs if frs is not None else frames):
            eng.handle_frame(f)
        t[0] += delay
        for _ in range(times):
            eng.handle_frame(icmp_frame(src, dst, typ, code, quote) if msg is None else msg)
        return eng, c

    # -- the whitepaper's reply: header + 4 nulls from fragment 1, then 44 bytes of heap
    eng, c = flow(inner[:24] + LEAK)
    check(c.codes() == ["APC-101", "APC-102", "APC-103", "APC-106"], f"leak flow: {c.codes()}")
    f103, f106 = c.f[2], c.f[3]
    check(f103["cves"] == ["CVE-2020-11898"] and f103["src"] == N4 and f103["dst"] == "9.9.9.9"
          and f103["detail"] == {"inner_proto": 0, "quote_bytes": 68, "first_fragment_bytes": 24},
          f"APC-103 shape: {f103}")
    check(f106["detail"] == {"inner_proto": 0, "quote_bytes": 68, "first_fragment_bytes": 24,
                             "beyond_first_fragment": 44, "first_mismatch_offset": 24,
                             "mismatching_bytes": 44}, f"APC-106 shape: {f106['detail']}")
    check(f106["severity"] == "critical" and f103["severity"] == "warn", "severities")
    check(f103["af"] == "ipv4" and f106["af"] == "ipv4", "response findings are IPv4")
    # -- PRIVACY: the disclosed bytes never leave the module
    blob = json.dumps(c.f).lower()
    check("deadbeef" not in blob and "222, 173" not in blob and "\\xde" not in blob,
          "findings must not carry the disclosed bytes")
    check(all(isinstance(v, (int, str, bool, type(None))) for f in c.f for v in f["detail"].values()
              if not isinstance(v, (list, dict))), "detail values are scalars")
    # -- a stack that quotes the REASSEMBLED packet correctly: answered, nothing disclosed
    check(flow(inner[:68])[1].codes() == ["APC-101", "APC-102", "APC-103"], "correct quote -> 103 only")
    # -- short quotes leave no region beyond the first fragment to compare
    check(flow(inner[:24])[1].codes()[-1] == "APC-103", "24-byte quote -> 103 only")
    check(flow(inner[:28])[1].codes() == ["APC-101", "APC-102", "APC-103"], "28-byte matching quote -> 103 only")
    # -- header-only differences (TTL, checksum) are not disclosure: bytes < 20 are never compared
    q = bytearray(inner[:68])
    q[8] ^= 0xFF
    q[10:12] = b"\xAB\xCD"
    check(flow(bytes(q))[1].codes() == ["APC-101", "APC-102", "APC-103"], "TTL/checksum difference is not a leak")
    # -- first fragment SMALLER than the header: bytes 8..20 are still header, disclosure starts at 20
    frs8, inner8 = jsof_11898(split=8)
    q = bytearray(inner8[:68])
    q[12:16] = b"\x01\x02\x03\x04"          # would be src, but the key uses bytes we keep; change others
    q[12:16] = inner8[12:16]
    q[8] ^= 0xFF
    check(flow(bytes(q), frs=frs8)[1].codes() == ["APC-101", "APC-102", "APC-103"],
          "with an 8-byte first fragment, header bytes 8..19 are still not compared")
    q = bytearray(inner8[:68])
    q[30] ^= 0xFF
    r8 = flow(bytes(q), frs=frs8)[1]
    check(r8.codes()[-1] == "APC-106" and r8.f[-1]["detail"]["first_mismatch_offset"] == 30,
          "with an 8-byte first fragment a mismatch at byte 30 is a disclosure")
    # -- wrong ICMP type/code never answers
    # (5, 2) and (12, 2) carry CODE 2 with a type other than 3: they distinguish "type 3 AND code 2"
    # from "code 2 alone" (a fixture set that only varies the code cannot tell them apart)
    for typ, code in ((3, 3), (3, 1), (3, 4), (11, 1), (8, 0), (0, 0), (5, 1), (5, 2), (12, 2)):
        check(flow(inner[:24] + LEAK, typ=typ, code=code)[1].codes() == ["APC-101", "APC-102"],
              f"ICMP type {typ} code {code} must not be treated as an answer")
    # -- unmatched / spoofed / stale
    check(flow(inner[:24] + LEAK, src="203.0.113.7")[1].codes() == ["APC-101", "APC-102"],
          "reply from a non-NMC address is ignored")
    # a DIFFERENT NMC answering for a datagram that was sent to N4: known NMC, wrong card
    check(flow(inner[:24] + LEAK, src="192.0.2.11", nmcs=(N4, N6, "192.0.2.11"))[1].codes() == ["APC-101", "APC-102"],
          "a reply from a different NMC than the one attacked is not matched")
    check(flow(inner[:24] + LEAK, dst="9.9.9.10")[1].codes() == ["APC-101", "APC-102"],
          "reply not addressed to the quoted source is not an RFC 792 error")
    check(flow(inner[:24] + LEAK, frs=[])[1].codes() == [], "a reply with no flagged request reports nothing")
    other, _ = jsof_11898(inner_id=2)
    check(flow(inner[:24] + LEAK, frs=other)[1].codes() == ["APC-101", "APC-102"],
          "quote of a different datagram (inner id) is not matched")
    check(flow(inner[:24] + LEAK, delay=A.ANSWER_WINDOW + 1)[1].codes() == ["APC-101", "APC-102"],
          "reply after the window is not matched")
    check(flow(inner[:24] + LEAK, delay=A.ANSWER_WINDOW - 1)[1].codes()[-1] == "APC-106", "reply inside the window is matched")
    check(flow(inner[:24] + LEAK, times=3)[1].codes().count("APC-103") == 1, "one answer per flagged datagram")
    # -- only datagrams reported as APC-102 are remembered
    good_inner = ipv4("9.9.9.9", N4, 0, b"\x00" * 40 + b"\x41" * 100, total=500, vihl=0x4F)
    nofire = [v4f("8.8.8.8", N4, 4, good_inner[:24], ident=9, mf=1, frag_off=0),
              v4f("8.8.8.8", N4, 4, good_inner[24:], ident=9, mf=0, frag_off=24)]
    check(flow(good_inner[:24] + LEAK, frs=nofire)[1].codes() == ["APC-101"],
          "header claiming MORE than the data: only the fragmented-tunnel notice, nothing to answer")
    # -- malformed / truncated replies never crash
    for junk in (b"", b"\x03", b"\x03\x02\x00\x00", b"\x03\x02\x00\x00\x00\x00\x00\x00", b"\x03\x02" + b"\x00" * 20,
                 b"\x03\x02" + b"\x00" * 6 + b"\x60" + b"\x00" * 30):
        check(flow(msg=v4f(N4, "9.9.9.9", 1, junk))[1].codes() == ["APC-101", "APC-102"], f"junk ICMP {junk[:6]!r} ignored")
    # -- IPv6: no ICMPv6 counterpart exists for this CVE; nothing may fire or crash
    e6, c6 = engine()
    e6.handle_frame(v6f(N6, "2001:db8::1", 58, struct.pack("!BBHI", 4, 1, 0, 0) + b"\x60" + b"\x00" * 39))
    e6.handle_frame(v6f(N6, "2001:db8::1", 58, struct.pack("!BBHI", 1, 4, 0, 0) + b"\x60" + b"\x00" * 39))
    check(not c6.f, "ICMPv6 from an NMC reports nothing")
    # -- bounded state: a flood of flagged datagrams cannot grow the table without limit
    t = [1000.0]
    c2 = Collector()
    big = A.Engine(nmcs=(N4,), emit=c2, clock=lambda: t[0])
    for i in range(A.MAX_PENDING + 44):
        fr, _ = jsof_11898(inner_id=i + 10, outer_id=i + 10)
        for f in fr:
            big.handle_frame(f)
        t[0] += 0.001
    check(len(big.pending_102) <= A.MAX_PENDING, f"pending table bounded: {len(big.pending_102)}")
    last = ipv4("9.9.9.9", N4, 0, b"\x00" * 40 + b"\x41" * 100, ident=A.MAX_PENDING + 43 + 10, total=100, vihl=0x4F)
    first = ipv4("9.9.9.9", N4, 0, b"\x00" * 40 + b"\x41" * 100, ident=10, total=100, vihl=0x4F)
    n0 = len(c2.f)
    big.handle_frame(icmp_frame(N4, "9.9.9.9", 3, 2, first[:24] + LEAK))
    check(len(c2.f) == n0, "the oldest flagged datagram was evicted, its reply is not matched")
    big.handle_frame(icmp_frame(N4, "9.9.9.9", 3, 2, last[:24] + LEAK))
    check([x["code"] for x in c2.f[n0:]] == ["APC-103", "APC-106"], "the newest flagged datagram is still matched")
    check(all(len(v["inner"]) <= A.PENDING_KEEP for v in big.pending_102.values()), "only PENDING_KEEP bytes retained")
    # -- the real Internet checksum builder agrees with a known vector (RFC 1071 example)
    check(_csum(bytes.fromhex("0001f203f4f5f6f7")) == 0x220D, "RFC 1071 checksum vector")


# ---------------------------------------------------------------- bounded state (APC-012)
def t_bounds():
    """Measured: the observed-card table cost ~604 B per spoofed source and the reported-fragment set grew
    without limit. Both are bounded now; operator-declared cards are pinned; hitting the cap is LOUD."""
    # -- fragment keys: de-duplicated inside the window, forgotten after it, bounded always
    t = [1000.0]
    c = Collector()
    eng = A.Engine(nmcs=(N4,), emit=c, clock=lambda: t[0])

    def first_frag(src, ident):
        return v4f(src, N4, 4, b"\x45" + b"\x00" * 39, ident=ident, mf=1, frag_off=0)
    eng.handle_frame(first_frag("8.8.8.8", 1))
    eng.handle_frame(first_frag("8.8.8.8", 1))
    check(c.codes().count("APC-101") == 1, "the same fragment key is reported once inside the window")
    t[0] += eng.reasm.timeout + 1
    eng.handle_frame(first_frag("8.8.8.8", 1))
    check(c.codes().count("APC-101") == 2, "after the reassembly timeout the key is reported again")
    # insertion also PURGES expired entries (memory), not just the age check at lookup: after the jump above
    # only the refreshed key exists, so a DIFFERENT key must leave exactly one entry (the old ones expired)
    eng.handle_frame(first_frag("8.8.8.9", 2))
    check(len(eng.seen_101) == 2, f"expired entries are purged on insert: {len(eng.seen_101)}")
    t[0] += eng.reasm.timeout + 1
    eng.handle_frame(first_frag("8.8.8.10", 3))
    check(list(eng.seen_101) == [(4, "8.8.8.10", N4, 3, 4)] or len(eng.seen_101) == 1,
          f"after a further timeout only the newest key remains: {len(eng.seen_101)}")
    for n in range(A.MAX_SEEN_101 + 500):
        eng.handle_frame(first_frag("10.%d.%d.%d" % (1 + (n >> 16), (n >> 8) & 255, (n & 255) or 1), 7))
        t[0] += 0.001
    check(len(eng.seen_101) <= A.MAX_SEEN_101, f"seen_101 bounded: {len(eng.seen_101)}")
    check(len(eng.reasm.tab) <= eng.reasm.max_dgrams, "reassembly table bounded")

    # -- observed-card table: cap, pinning, throttled loud notice
    t = [1000.0]
    c = Collector()
    eng = A.Engine(nmcs=(N4,), emit=c, clock=lambda: t[0], max_observed=3)

    def apc(src):
        return v4f(src, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR)))
    for i in range(1, 6):
        eng.handle_frame(apc("198.51.100.%d" % i))
    observed = [k for k, v in eng.nmcs.items() if v["source"] == "observed"]
    check(eng.observed == 3 and len(observed) == 3, f"observed cards capped at 3: {eng.observed}/{len(observed)}")
    check(c.codes().count("APC-012") == 1, "one notice inside the throttle window")
    f12 = [x for x in c.f if x["code"] == "APC-012"][0]
    check(f12["severity"] == "warn" and f12["cves"] == [] and f12["detail"]["cap"] == 3
          and f12["detail"]["observed_cards"] == 3, f"APC-012 shape: {f12}")
    check(eng.stats["nmc_ignored"] == 2, f"ignored count: {eng.stats['nmc_ignored']}")
    t[0] += A.FULL_NOTICE_EVERY + 1
    eng.handle_frame(apc("198.51.100.9"))
    check(c.codes().count("APC-012") == 2, "the notice repeats after the throttle window")
    check(eng.stats["nmc_ignored"] == 3, "ignored count keeps counting")
    # a DECLARED card is pinned: still gated while the table is full
    n = len(c.f)
    eng.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR))))
    check("APC-001" in [x["code"] for x in c.f[n:]], "a declared card is unaffected by a full table")
    # an ADMITTED card keeps being analysed; nothing is evicted
    n = len(c.f)
    eng.handle_frame(v4f("8.8.8.8", "198.51.100.1", 4, ipv4("9.9.9.9", "198.51.100.1", 17, b"x")))
    check([x["code"] for x in c.f[n:]] == ["APC-104"], "an admitted card is still analysed after the cap")
    check("198.51.100.1" in eng.nmcs, "no eviction")
    # a card that appears AFTER the cap is ignored: the documented blind spot
    n = len(c.f)
    eng.handle_frame(v4f("8.8.8.8", "198.51.100.77", 4, ipv4("9.9.9.9", "198.51.100.77", 17, b"x")))
    check(c.f[n:] == [], "a card first seen after the cap is not analysed (documented blind spot)")
    # a repeat answer from an admitted card is not new: no notice, no growth
    n, before = len(c.f), eng.observed
    eng.handle_frame(apc("198.51.100.1"))
    check(eng.observed == before and "APC-012" not in [x["code"] for x in c.f[n:]], "admitted card re-answering is not 'new'")
    # -- the same over IPv6
    t6, c6 = [1000.0], Collector()
    e6 = A.Engine(nmcs=(), emit=c6, clock=lambda: t6[0], max_observed=1)
    for src in ("2001:db8::a1", "2001:db8::a2", "2001:db8::a3"):
        e6.handle_frame(v6f(src, "2001:db8::1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR))))
    x6 = [x for x in c6.f if x["code"] == "APC-012"]
    check(len(x6) == 1 and x6[0]["af"] == "ipv6" and e6.observed == 1, f"IPv6 cap: {c6.codes()} observed={e6.observed}")
    # -- default cap is generous but finite
    check(A.MAX_OBSERVED_NMCS >= 4096 and A.MAX_SEEN_101 >= 1024, "default caps are sane")


# ---------------------------------------------------------------- MAC attribution (APC-107/108 attribution, APC-109)
CARD_MAC = "02:aa:bb:cc:dd:10"
OTHER_MAC = "02:ee:ee:ee:ee:99"


def _raises(fn, *a):
    try:
        fn(*a)
    except ValueError:
        return True
    return False


def t_mac_parse():
    check(A.norm_mac("02:AA:BB:CC:DD:10") == CARD_MAC and A.norm_mac("02-aa-bb-cc-dd-10") == CARD_MAC, "MAC canonicalisation")
    for bad in ("", "02:aa:bb:cc:dd", "02:aa:bb:cc:dd:10:11", "zz:aa:bb:cc:dd:10", "01:00:5e:00:00:01",
                "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "03:aa:bb:cc:dd:10", "02aabbccdd1"):
        check(_raises(A.norm_mac, bad), f"norm_mac must reject {bad!r}")
    check(A.parse_nmc_spec("192.0.2.10") == "192.0.2.10", "plain address")
    check(A.parse_nmc_spec("192.0.2.10=02:AA:BB:CC:DD:10") == ("192.0.2.10", CARD_MAC), "address=MAC")
    check(A.parse_nmc_spec("2001:DB8::10=02-aa-bb-cc-dd-10") == ("2001:db8::10", CARD_MAC),
          "IPv6 address=MAC (':' cannot be the separator)")
    for bad in ("192.0.2.999", "192.0.2.10=", "192.0.2.10=zz", "192.0.2.10=01:00:5e:00:00:01", "=02:aa:bb:cc:dd:10"):
        check(_raises(A.parse_nmc_spec, bad), f"parse_nmc_spec must reject {bad!r}")
    import tempfile

    def load(text):
        with tempfile.NamedTemporaryFile("w", suffix=".list", delete=False) as fh:
            fh.write(text)
            p = fh.name
        try:
            return A.load_nmc_file(p)
        finally:
            os.unlink(p)
    got = load("# c\n192.0.2.10  02:AA:BB:CC:DD:10  # a\n\n2001:db8::10\n192.0.2.11 # b\n")
    check(got == [("192.0.2.10", CARD_MAC), "2001:db8::10", "192.0.2.11"], f"nmc file parse: {got}")
    for bad in ("192.0.2.10 02:aa:bb:cc:dd:10 extra\n", "192.0.2.10 zz\n", "nonsense\n"):
        check(_raises(load, bad), f"an nmc file line {bad.strip()!r} must be rejected")
    check(A.parse_l3(v4f(N4, "192.0.2.1", 17, b"x", mac=CARD_MAC)).smac == CARD_MAC, "source MAC parsed")
    check(A.parse_l3(eth(ipv4(N4, "192.0.2.1", 17, b"x"), 0x0800, vlans=(100, 200), smac=CARD_MAC)).smac == CARD_MAC,
          "source MAC read correctly behind two VLAN tags")
    check(A.parse_l3(v6f(N6, "2001:db8::1", 17, b"x", mac=CARD_MAC)).smac == CARD_MAC, "source MAC on IPv6")
    e = A.Engine(nmcs=((N4, CARD_MAC.upper()), N6), emit=lambda f: None)
    check(e.nmcs[N4]["mac_declared"] == CARD_MAC and "mac_declared" not in e.nmcs[N6],
          "a declared MAC is stored canonical; plain addresses are unaffected")
    # the same card declared twice (say --nmc on the command line and again in the file): merged, never silently lost
    for order in (((N4, CARD_MAC), N4), (N4, (N4, CARD_MAC)), ((N4, CARD_MAC), (N4, CARD_MAC.upper()))):
        e = A.Engine(nmcs=order, emit=lambda f: None)
        check(e.nmcs[N4].get("mac_declared") == CARD_MAC and len(e.nmcs) == 1, f"duplicate declaration lost the MAC: {order}")
    check(_raises(A.Engine, ((N4, CARD_MAC), (N4, OTHER_MAC))), "two different MACs for one address must be an error")


def t_mac_attribution():
    inner = ipv4("9.9.9.9", N4, 17, b"data")

    def play(steps, nmcs=(N4,)):
        c = Collector()
        eng = A.Engine(nmcs=nmcs, emit=c, clock=lambda: 1000.0)
        for f in steps:
            eng.handle_frame(f)
        return eng, c

    def probe(ident, mac, proto=4):
        o = ipv4("8.8.8.8", N4, proto, inner if proto == 4 else b"\x60" + b"\x00" * 39, ident=ident)
        return [eth(o, 0x0800), icmp_frame(N4, "8.8.8.8", 3, 2, o[:28], mac=mac)]

    def snmp(mac):
        return v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR)), mac=mac)

    def of(c, code):
        return [x for x in c.f if x["code"] == code]

    # unknown: nothing to compare with
    eng, c = play(probe(1, CARD_MAC))
    d = of(c, "APC-107")[0]["detail"]
    check(d["attribution"] == "unknown" and d["card_mac"] is None and d["reply_src_mac"] == CARD_MAC, f"unknown: {d}")
    # learned, same: an annotation
    eng, c = play([snmp(CARD_MAC)] + probe(1, CARD_MAC))
    d = of(c, "APC-107")[0]["detail"]
    check(d["attribution"] == "same-source-as-snmp" and d["card_mac"] == CARD_MAC, f"learned same: {d}")
    # learned, DIFFERENT: another device answered -> APC-109, and NOTHING is recorded about the card
    eng, c = play([snmp(CARD_MAC)] + probe(1, OTHER_MAC))
    f9 = of(c, "APC-109")
    check(len(f9) == 1 and not of(c, "APC-107"), f"different source: {c.codes()}")
    check(f9[0]["severity"] == "info" and f9[0]["cves"] == [] and f9[0]["af"] == "ipv4"
          and f9[0]["detail"]["card_mac"] == CARD_MAC and f9[0]["detail"]["reply_src_mac"] == OTHER_MAC
          and f9[0]["detail"]["outer_proto"] == 4, f"APC-109 shape: {f9[0]}")
    check(eng.tunnel_state(N4) == {}, "a reply from another device records nothing about the card")
    # ambiguous: two MACs have answered SNMP as this address
    eng, c = play([snmp(CARD_MAC), snmp(OTHER_MAC)] + probe(1, CARD_MAC))
    check(of(c, "APC-107")[0]["detail"]["attribution"] == "ambiguous", "two learned MACs -> ambiguous")
    check(eng.tunnel_state(N4) == {"ip-in-ip": "inactive"}, "ambiguous still records the observation (it cannot lower a severity)")
    # declared: strong, and it OUTRANKS anything learned
    eng, c = play(probe(1, CARD_MAC), nmcs=((N4, CARD_MAC),))
    d = of(c, "APC-107")[0]["detail"]
    check(d["attribution"] == "declared-mac" and d["card_mac"] == CARD_MAC, f"declared: {d}")
    eng, c = play([snmp(OTHER_MAC)] + probe(1, OTHER_MAC), nmcs=((N4, CARD_MAC),))
    check(len(of(c, "APC-109")) == 1 and not of(c, "APC-107") and of(c, "APC-109")[0]["detail"]["card_mac"] == CARD_MAC,
          "declared MAC outranks a learned one that matches the reply")
    # APC-109 is bounded: once per (protocol, MAC), at most MAX_DIFF_MACS per card
    eng, c = play([snmp(CARD_MAC)] + probe(1, OTHER_MAC) + probe(2, OTHER_MAC))
    check(len(of(c, "APC-109")) == 1, "the same foreign MAC is reported once")
    steps = [snmp(CARD_MAC)]
    for i in range(20):
        steps += probe(100 + i, "02:ee:ee:ee:ee:%02x" % i)
    eng, c = play(steps)
    check(len(of(c, "APC-109")) == A.MAX_DIFF_MACS, f"APC-109 bounded per card: {len(of(c, 'APC-109'))}")
    # learned MACs are capped: an attacker can send any number of them
    eng, c = play([snmp("02:cc:cc:cc:cc:%02x" % i) for i in range(20)])
    check(len(eng.nmcs[N4]["macs"]) == A.MAX_MACS_PER_CARD, f"learned MACs capped: {len(eng.nmcs[N4]['macs'])}")
    # a VLAN-tagged SNMP reply teaches the same MAC as an untagged one
    tagged = eth(ipv4(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR))), 0x0800, vlans=(100,), smac=CARD_MAC)
    eng, c = play([tagged] + probe(1, CARD_MAC))
    check(of(c, "APC-107")[0]["detail"]["attribution"] == "same-source-as-snmp", "VLAN-tagged SNMP reply teaches the MAC")
    # protocol 41 is attributed the same way
    eng, c = play(probe(5, CARD_MAC, 41), nmcs=((N4, CARD_MAC),))
    check(of(c, "APC-108")[0]["detail"]["attribution"] == "declared-mac", "APC-108 attribution")
    eng, c = play(probe(5, OTHER_MAC, 41), nmcs=((N4, CARD_MAC),))
    check(of(c, "APC-109")[0]["detail"]["outer_proto"] == 41 and not of(c, "APC-108"), "protocol 41 from another device -> APC-109")
    # IPv6 cards learn their MAC too (no ICMP counterpart, but the annotation source is the same)
    e6 = A.Engine(nmcs=(N6,), emit=lambda f: None)
    e6.handle_frame(v6f(N6, "2001:db8::1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR)), mac=CARD_MAC))
    check(e6.nmcs[N6]["macs"] == {CARD_MAC}, "an IPv6 card learns its MAC")
    # REAL frames from a real stack: the MAC in the recorded reply is what the operator would declare
    for name, code in (("unfrag4", "APC-107"), ("proto41", "APC-108")):
        fx = REAL_LINUX[name]
        rmac = A.mac_str(fx["reply"][6:12])
        steps = fx["req"] + [fx["reply"]]
        _, c = play(steps, nmcs=((REAL_CARD, rmac),))
        check(of(c, code) and of(c, code)[0]["detail"]["attribution"] == "declared-mac", f"real {name}: declared MAC matches")
        _, c = play(steps, nmcs=((REAL_CARD, "02:00:00:00:99:99"),))
        check(of(c, "APC-109") and not of(c, code), f"real {name}: a different declared MAC -> APC-109")
        _, c = play(steps, nmcs=(REAL_CARD,))
        check(of(c, code)[0]["detail"]["attribution"] == "unknown", f"real {name}: no MAC known -> unknown")


# ---------------------------------------------------------------- severity lowering
def t_lowering():
    inner = ipv4("9.9.9.9", N4, 17, b"data")

    def mk(nmcs=((N4, CARD_MAC),), **kw):
        t = [1000.0]
        c = Collector()
        return A.Engine(nmcs=nmcs, emit=c, clock=lambda: t[0], **kw), c, t

    def reject(eng, ident, mac=CARD_MAC, proto=4):
        o = ipv4("8.8.8.8", N4, proto, inner if proto == 4 else b"\x60" + b"\x00" * 39, ident=ident)
        eng.handle_frame(eth(o, 0x0800))
        eng.handle_frame(icmp_frame(N4, "8.8.8.8", 3, 2, o[:28], mac=mac))

    def attempt(eng, ident, dst=N4):
        for f in jsof_11898(outer_id=ident, dst=dst)[0]:
            eng.handle_frame(f)

    def sevs(c, n0):
        return [(x["code"], x["severity"]) for x in c.f[n0:]]

    # before any rejection: critical
    eng, c, t = mk()
    attempt(eng, 1)
    check(sevs(c, 0) == [("APC-101", "critical"), ("APC-102", "critical")], f"no fact yet: {sevs(c, 0)}")
    # after a rejection from the DECLARED MAC: one step down, still emitted, and it says why
    reject(eng, 0x11)
    n = len(c.f)
    attempt(eng, 2)
    check(sevs(c, n) == [("APC-101", "warn"), ("APC-102", "warn")], f"lowered: {sevs(c, n)}")
    for x in c.f[n:]:
        check(x["detail"]["severity_lowered_from"] == "critical" and "ip-in-ip" in x["detail"]["lowered_because"]
              and "declared MAC" in x["detail"]["lowered_because"], f"lowered detail: {x['detail']}")
    check(c.f[-1]["cves"] == ["CVE-2020-11896", "CVE-2020-11898"], "lowering does not touch the CVE attribution")
    check(eng.stats["lowered"] == 2, f"stats count exactly the lowered findings: {eng.stats['lowered']}")
    check([x["severity"] for x in c.f if x["code"] == "APC-104"] == ["notice"], "APC-104 (notice) is never lowered")
    # protocol 41: warn -> notice, and only after ITS OWN rejection
    eng, c, t = mk()
    eng.handle_frame(v4f("8.8.8.8", N4, 41, b"\x60" + b"\x00" * 39, ident=0x51))
    check(sevs(c, 0) == [("APC-105", "warn")], "protocol 41 attempt before any fact")
    reject(eng, 0x52)                                                         # protocol 4 rejected ...
    n = len(c.f)
    eng.handle_frame(v4f("8.8.8.8", N4, 41, b"\x60" + b"\x00" * 39, ident=0x53))
    check(sevs(c, n) == [("APC-105", "warn")], "a protocol-4 rejection must not lower a protocol-41 attempt")
    reject(eng, 0x54, proto=41)                                               # ... now protocol 41 too
    n = len(c.f)
    eng.handle_frame(v4f("8.8.8.8", N4, 41, b"\x60" + b"\x00" * 39, ident=0x55))
    check(sevs(c, n) == [("APC-105", "notice")] and c.f[-1]["detail"]["severity_lowered_from"] == "warn", "protocol 41 lowered")
    # anything weaker than a declared MAC lowers nothing
    eng, c, t = mk(nmcs=(N4,))                                                # unknown attribution
    reject(eng, 0x11)
    n = len(c.f)
    attempt(eng, 2)
    check(sevs(c, n) == [("APC-101", "critical"), ("APC-102", "critical")], "unknown attribution lowers nothing")
    eng, c, t = mk(nmcs=(N4,))                                                # learned, same source
    eng.handle_frame(v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR)), mac=CARD_MAC))
    reject(eng, 0x11)
    check(eng.tunnel_state(N4) == {"ip-in-ip": "inactive"}, "the observation is recorded")
    n = len(c.f)
    attempt(eng, 2)
    check(sevs(c, n) == [("APC-101", "critical"), ("APC-102", "critical")], "a LEARNED MAC lowers nothing (a router or firewall would match it)")
    eng, c, t = mk()                                                          # declared, but ANOTHER device answered
    reject(eng, 0x11, mac=OTHER_MAC)
    n = len(c.f)
    attempt(eng, 2)
    check(sevs(c, n) == [("APC-101", "critical"), ("APC-102", "critical")], "a reply from another device lowers nothing")
    # the fact expires ... unless the card keeps rejecting
    eng, c, t = mk(tunnel_fact_ttl=100)
    reject(eng, 0x11)
    t[0] += 99
    n = len(c.f)
    attempt(eng, 2)
    check(sevs(c, n)[0] == ("APC-101", "warn"), "inside the TTL")
    eng, c, t = mk(tunnel_fact_ttl=100)
    reject(eng, 0x11)
    t[0] += 101
    n = len(c.f)
    attempt(eng, 2)
    check(sevs(c, n)[0] == ("APC-101", "critical"), "after the TTL the fact is stale")
    eng, c, t = mk(tunnel_fact_ttl=100)
    reject(eng, 0x11)
    t[0] += 90
    reject(eng, 0x12)                                                         # a fresh observation refreshes the fact
    t[0] += 90
    n = len(c.f)
    attempt(eng, 2)
    check(sevs(c, n)[0] == ("APC-101", "warn"), "a repeated rejection keeps the fact fresh")
    # a later decapsulation cancels it immediately, and a NEW rejection can re-establish it
    eng, c, t = mk()
    reject(eng, 0x11)
    frames, inner11898 = jsof_11898(outer_id=0x77)
    n = len(c.f)
    for f in frames:
        eng.handle_frame(f)
    eng.handle_frame(icmp_frame(N4, "9.9.9.9", 3, 2, inner11898[:24] + LEAK, mac=CARD_MAC))
    after = {x["code"]: x["severity"] for x in c.f[n:]}
    check(after.get("APC-103") == "warn" and after.get("APC-106") == "critical",
          f"APC-103/106 are never lowered: {after}")
    check(eng.tunnel_state(N4) == {"ip-in-ip": "active"}, "decapsulation flips the state")
    n = len(c.f)
    attempt(eng, 0x78)
    check(sevs(c, n) == [("APC-101", "critical"), ("APC-102", "critical")], "after decapsulation attempts are critical again")
    reject(eng, 0x79)
    n = len(c.f)
    attempt(eng, 0x7A)
    check(sevs(c, n) == [("APC-101", "warn"), ("APC-102", "warn")], "a new rejection re-establishes the fact")
    # the switch: off means off, and the observation is still recorded
    eng, c, t = mk(lower_attempts=False)
    reject(eng, 0x11)
    n = len(c.f)
    attempt(eng, 2)
    check(sevs(c, n) == [("APC-101", "critical"), ("APC-102", "critical")] and eng.tunnel_state(N4) == {"ip-in-ip": "inactive"},
          "lower_attempts=False lowers nothing but still records")
    # the freshness window must be finite and bounded: nan/inf would make the fact immortal
    for bad in (float("nan"), float("inf"), -1.0, A.MAX_TUNNEL_FACT_TTL + 1):
        check(_raises(lambda b: A.Engine(nmcs=(N4,), emit=lambda f: None, tunnel_fact_ttl=b), bad), f"freshness window {bad} must be refused")
    for good in (0.0, 1.0, A.MAX_TUNNEL_FACT_TTL):
        check(A.Engine(nmcs=(N4,), emit=lambda f: None, tunnel_fact_ttl=good).tunnel_fact_ttl == good, f"{good} accepted")
    # per card, not global
    eng, c, t = mk(nmcs=((N4, CARD_MAC), ("192.0.2.11", OTHER_MAC)))
    reject(eng, 0x11)
    n = len(c.f)
    attempt(eng, 2, dst="192.0.2.11")
    check(sevs(c, n) == [("APC-101", "critical"), ("APC-102", "critical")], "another card is unaffected")
    # never a suppression: the same traffic produces the same findings with and without the policy
    def script(**kw):
        e, cc, _ = mk(**kw)
        reject(e, 0x11)
        attempt(e, 2)
        attempt(e, 3)
        return [(x["code"], x["src"], x["dst"]) for x in cc.f]
    check(script() == script(lower_attempts=False), "lowering never adds or removes a finding")
    e0, _, _ = mk(lower_attempts=False)
    reject(e0, 0x11)
    attempt(e0, 2)
    check(e0.stats["lowered"] == 0, "a disabled policy lowers, and counts, nothing")
    # REAL frames from a real stack
    fx_u, fx_f = REAL_LINUX["unfrag4"], REAL_LINUX["frag4"]
    rmac = A.mac_str(fx_u["reply"][6:12])
    for declared, want in ((rmac, "warn"), ("02:00:00:00:99:99", "critical")):
        c = Collector()
        eng = A.Engine(nmcs=((REAL_CARD, declared),), emit=c, clock=lambda: 1000.0)
        for fr in fx_u["req"] + [fx_u["reply"]]:
            eng.handle_frame(fr)
        n = len(c.f)
        for fr in fx_f["req"]:
            eng.handle_frame(fr)
        got = [x["severity"] for x in c.f[n:] if x["code"] in ("APC-101", "APC-102")]
        check(got == [want, want], f"real frames, declared {declared}: {got}, want {want}")


# ---------------------------------------------------------------- APC-110: a declared MAC the card's own SNMP contradicts
def t_declared_mismatch():
    def play(steps, nmcs):
        c = Collector()
        eng = A.Engine(nmcs=nmcs, emit=c, clock=lambda: 1000.0)
        for f in steps:
            eng.handle_frame(f)
        return eng, c

    def snmp4(mac, descr_=None):
        return v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr=descr_ or DESCR)), mac=mac)

    def snmp6(mac):
        return v6f(N6, "2001:db8::1", 17, udp(161, 40000, snmp_response(sysdescr=DESCR)), mac=mac)

    def of(c, code):
        return [x for x in c.f if x["code"] == code]
    # matching MAC: silent
    _, c = play([snmp4(CARD_MAC)], ((N4, CARD_MAC),))
    check(not of(c, "APC-110"), "a matching MAC raises nothing")
    # mismatch: one notice, no CVE, right shape; once per observed MAC
    _, c = play([snmp4(OTHER_MAC), snmp4(OTHER_MAC)], ((N4, CARD_MAC),))
    f = of(c, "APC-110")
    check(len(f) == 1 and f[0]["severity"] == "notice" and f[0]["cves"] == [] and f[0]["af"] == "ipv4"
          and f[0]["detail"]["declared_mac"] == CARD_MAC and f[0]["detail"]["observed_mac"] == OTHER_MAC
          and f[0]["src"].endswith(":161"), f"APC-110 shape: {f}")
    _, c = play([snmp4("02:ee:ee:ee:ee:%02x" % i) for i in range(20)], ((N4, CARD_MAC),))
    check(len(of(c, "APC-110")) == A.MAX_DIFF_MACS, f"APC-110 bounded per card: {len(of(c, 'APC-110'))}")
    _, c = play([snmp4(OTHER_MAC), snmp4(CARD_MAC), snmp4("02:ee:ee:ee:ee:77")], ((N4, CARD_MAC),))
    check(len(of(c, "APC-110")) == 2, "each DIFFERENT observed MAC is reported once")
    # only a declared MAC can be contradicted: none declared -> never, even with several learned MACs
    _, c = play([snmp4(CARD_MAC), snmp4(OTHER_MAC)], (N4,))
    check(not of(c, "APC-110"), "no declared MAC, nothing to contradict")
    # IPv6 parity
    _, c = play([snmp6(OTHER_MAC)], ((N6, CARD_MAC),))
    f = of(c, "APC-110")
    check(len(f) == 1 and f[0]["af"] == "ipv6" and f[0]["detail"]["observed_mac"] == OTHER_MAC, "APC-110 over IPv6")
    _, c = play([snmp6(CARD_MAC)], ((N6, CARD_MAC),))
    check(not of(c, "APC-110"), "IPv6: a matching MAC raises nothing")
    # a reply that is not an APC card's is nobody's business
    plain = v4f(N4, "192.0.2.1", 17, udp(161, 40000, snmp_response(sysdescr="Linux router 5.10")), mac=OTHER_MAC)
    _, c = play([plain], ((N4, CARD_MAC),))
    check(not of(c, "APC-110"), "a non-APC SNMP reply is ignored")
    # an SNMP mismatch does not poison attribution, and the finding does not disturb inventory
    inner = ipv4("9.9.9.9", N4, 17, b"data")
    o = ipv4("8.8.8.8", N4, 4, inner, ident=0x21)
    eng, c = play([snmp4(OTHER_MAC), eth(o, 0x0800), icmp_frame(N4, "8.8.8.8", 3, 2, o[:28], mac=CARD_MAC)], ((N4, CARD_MAC),))
    check(of(c, "APC-107") and of(c, "APC-107")[0]["detail"]["attribution"] == "declared-mac",
          "attribution still compares with the DECLARED MAC")
    check(of(c, "APC-010") and of(c, "APC-001"), "inventory and gate findings are unaffected")


# ---------------------------------------------------------------- a signal before sniff() can swallow it
def t_signal_window():
    """scapy's sniff() swallows KeyboardInterrupt itself, so the `except` in main() only matters for a signal that lands
    BEFORE sniff() starts (while scapy is still importing). Timing that window from outside is a race, so simulate it:
    run main() with run_capture raising KeyboardInterrupt."""
    import contextlib as _c
    import io as _io
    import signal as _sig
    old = {s_: _sig.getsignal(s_) for s_ in (_sig.SIGTERM, _sig.SIGINT)}
    real = A.run_capture

    def boom(*a, **k):
        raise KeyboardInterrupt
    A.run_capture = boom
    err = _io.StringIO()
    installed = {}
    try:
        with _c.redirect_stderr(err):
            try:
                rc = A.main(["--iface", "lo"])
            except KeyboardInterrupt:                  # a BaseException: it must fail this test, not kill the suite
                rc = "KeyboardInterrupt escaped main()"
        installed = {s_: _sig.getsignal(s_) for s_ in (_sig.SIGTERM, _sig.SIGINT)}
    finally:
        A.run_capture = real
        for s_, h in old.items():
            _sig.signal(s_, h)
    check(rc == 0, f"a KeyboardInterrupt before sniff() exits 0, got {rc}")
    check('"stats"' in err.getvalue() and "Traceback" not in err.getvalue(), "... and still prints the stats line")
    check(all(getattr(h, "__name__", "") == "_stop" for h in installed.values()) and len(installed) == 2,
          "main() installs its own handler for BOTH SIGTERM and SIGINT (a background job inherits SIGINT as ignored)")


# ---------------------------------------------------------------- DNS
CNAME = b"\x0aaaaaaaaaaa\x0aaaaaaaaaaa\x00"


def t_dns():
    body = dns_response(records=[(5, CNAME, 4)])          # RDLENGTH lies
    eng, c = engine()
    eng.handle_frame(v4f("192.0.2.1", N4, 17, udp(53, 40000, body)))
    check("APC-111" in c.codes(), "APC-111 CNAME rdlength mismatch")
    eng2, c2 = engine()
    eng2.handle_frame(v4f("192.0.2.1", N4, 17, udp(
        53, 40000, dns_response(records=[(5, CNAME, len(CNAME))]))))
    check("APC-111" not in c2.codes(), "honest CNAME no 111")
    eng3, c3 = engine()
    eng3.handle_frame(v4f("192.0.2.1", N4, 17, udp(53, 40000, loop_msg())))
    check("APC-112" in c3.codes(), "APC-112 pointer loop")
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x03www\x00" + struct.pack("!HH", 1, 1)
    check(A.analyze_dns(q) == [], "query ignored")
    eng4, c4 = engine()
    eng4.handle_frame(v4f("192.0.2.1", "203.0.113.9", 17, udp(53, 40000, body)))
    check(not c4.f, "dns to non-nmc ignored")
    _, _, an = A.dns_name_walk((b"\x3f" + b"a" * 63) * 5 + b"\x00", 0)
    check("name>255" in an, "name>255 anomaly")
    _, _, an = A.dns_name_walk(b"\x80\x00", 0)
    check("reserved-label-type" in an, "reserved label type")
    chain = b"\xc0\x02\xc0\x04\xc0\x06\xc0\x08\x00"
    _, _, an = A.dns_name_walk(chain, 0)
    check("pointer-chain" in an, "pointer chain")


def t_dns_tcp_not_inspected():
    """McAfee advises assuming DNS-over-TCP is vulnerable, but apcguard reads UDP only. Pin it."""
    msg = dns_response(records=[(5, CNAME, 4)])
    seg = tcp(53, 40000, struct.pack("!H", len(msg)) + msg)
    eng, c = engine()
    eng.handle_frame(v4f("192.0.2.1", N4, 6, seg))
    check(not c.f, "DNS over TCP is not inspected (documented blind spot)")


def t_dns_v6():
    body = dns_response(records=[(5, CNAME, 4)])
    eng, c = engine()
    eng.handle_frame(v6f("2001:db8::1", N6, 17, udp(53, 40000, body)))
    x = [f for f in c.f if f["code"] == "APC-111"]
    check(x and x[0]["af"] == "ipv6", "APC-111 over IPv6 transport")
    eng2, c2 = engine()
    eng2.handle_frame(v6f("2001:db8::1", N6, 17, udp(53, 40000, loop_msg())))
    y = [f for f in c2.f if f["code"] == "APC-112"]
    check(y and y[0]["af"] == "ipv6", "APC-112 over IPv6 transport")
    ext = bytes([17, 0]) + b"\x00" * 6                   # hop-by-hop then UDP
    eng3, c3 = engine()
    eng3.handle_frame(v6f("2001:db8::1", N6, 0, udp(53, 40000, loop_msg()), ext=ext))
    check("APC-112" in c3.codes(), "APC-112 behind IPv6 extension header")
    eng4, c4 = engine()
    eng4.handle_frame(v6f("2001:db8::1", "2001:db8::99", 17, udp(53, 40000, loop_msg())))
    check(not c4.f, "v6 dns to non-nmc ignored")


# ---------------------------------------------------------------- round trips
def t_roundtrip():
    for addr, port in [("192.0.2.10", 161), ("2001:db8::10", 161)]:
        ep = A.render_ep(addr, port)
        h, p = A.split_ep(ep)
        check(h == addr and p == port, f"ep round-trip {ep}")
    check(A.render_ep("2001:db8::10", 53) == "[2001:db8::10]:53", "v6 brackets")
    check(A.render_ep("192.0.2.10", 53) == "192.0.2.10:53", "v4 plain")


# ---------------------------------------------------------------- AST guards
def _enclosing_func(tree, target):
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for sub in ast.walk(fn):
                if sub is target:
                    return fn.name
    return None


def t_ast_guards():
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "apcguard.py")).read()
    tree = ast.parse(src)
    seen, dupes = set(), set()
    for node in tree.body:
        names = []
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        for n in names:
            (dupes if n in seen else seen).add(n)
    check(not dupes, f"LESSON G: duplicate module-level names {dupes}")
    importers = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = getattr(node, "module", None) or (node.names[0].name if node.names else "")
            if mod and "scapy" in mod:
                importers.add(_enclosing_func(tree, node))
    check(importers == {"run_capture"}, f"LESSON C: scapy importers {importers}")
    banned = {"send", "sendp", "sr", "sr1", "srp", "pcap_sendpacket"}
    bad = [n.func.id for n in ast.walk(tree)
           if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in banned]
    check(not bad, f"LESSON D: send-like calls present {bad}")
    check(set(A.AF_SCOPE) == set(A.CODES), "AF_SCOPE covers exactly the registry")


# ---------------------------------------------------------------- coverage matrix
def t_coverage():
    codes_fired = {c for c, _ in FIRED}
    check(codes_fired <= set(A.CODES), f"emitted codes undefined: {codes_fired - set(A.CODES)}")
    for must in ("APC-001", "APC-002", "APC-003", "APC-010", "APC-011", "APC-101", "APC-102",
                 "APC-103", "APC-104", "APC-105", "APC-106", "APC-107", "APC-108", "APC-109", "APC-110", "APC-012", "APC-111", "APC-112"):
        check(must in codes_fired, f"coverage: {must} never fired")
    # dual-stack matrix: every code whose declared scope includes v6 is fired over v6,
    # except the three Class-B gate codes that share ONE code path with APC-001 (the
    # `code` variable in Engine._snmp) and APC-011, which shares it too.
    shares_apc001_path = {"APC-002", "APC-003", "APC-011"}
    for code, scope in A.AF_SCOPE.items():
        if "v6" in scope and code not in shares_apc001_path:
            check((code, "ipv6") in FIRED, f"v6 parity: {code} declared v4+v6 but never fired over v6")
        if scope == "v4":
            check((code, "ipv6") not in FIRED, f"{code} is IPv4-only yet fired over IPv6")


# ---------------------------------------------------------------- finding invariants
REQUIRED_KEYS = {"module", "code", "severity", "title", "cves", "confidence", "ts", "src", "dst"}


def t_invariants():
    """Properties EVERY emitted finding must satisfy, whatever produced it.

    A fixed number of checks (one per property) so the total is stable however many
    findings the suite happened to emit. Found by bite: a v6-only mutation stripped
    the CVE list from APC-101 and no per-code assertion looked at `cves`.
    """
    fs = ALL_FINDINGS
    check(len(fs) >= 20, f"non-vacuity: only {len(fs)} findings reached the invariant tier")
    check(all(REQUIRED_KEYS <= set(f) for f in fs), "every finding carries the required keys")
    def sev_ok(f):
        reg = A.CODES[f["code"]][0]
        low = (f.get("detail") or {}).get("severity_lowered_from")
        return f["severity"] == reg if low is None else (low == reg and f["severity"] == A.LOWER_ONE_STEP[reg])
    check(all(sev_ok(f) for f in fs), "severity matches the registry, or is exactly one step below it and says so")
    lowered = [f for f in fs if (f.get("detail") or {}).get("severity_lowered_from")]
    check(all(f["code"] in ("APC-101", "APC-102", "APC-105") and f["detail"].get("lowered_because") for f in lowered),
          "only attempt findings are ever lowered, and each says why")
    check(all(set(A.CODES[f["code"]][2]) <= set(f["cves"]) for f in fs),
          "every finding carries at least its registry CVEs: " +
          str({(f["code"], f.get("af")) for f in fs if not set(A.CODES[f["code"]][2]) <= set(f["cves"])}))
    check(all(f["confidence"] in ("high", "medium", "low", "version-in-range") for f in fs),
          "confidence is a known label")
    check(all(f["code"] in A.CODES for f in fs), "every emitted code is registered")

    def host_of(ep):
        if ep is None:
            return None
        if ep.startswith("["):
            return ep[1:].partition("]")[0]
        if ep.count(":") == 1:                # ipv4:port
            return ep.rpartition(":")[0]
        return ep                             # bare address (v4, or bare v6)

    def valid(ep):
        try:
            return ep is None or bool(ipaddress.ip_address(host_of(ep)))
        except ValueError:
            return False
    check(all(valid(f["src"]) and valid(f["dst"]) for f in fs), "endpoints parse to a valid address")
    check(all(f.get("af") is None or f["af"] == f"ipv{ipaddress.ip_address(host_of(f['src'])).version}"
              for f in fs), "af tag agrees with the address family of src")
    attack = [f for f in fs if f["code"].startswith("APC-1") and A.CODES[f["code"]][2]]
    check(attack and all(f["cves"] for f in attack), "every CVE-attributing attack finding names a CVE")


# ---------------------------------------------------------------- 11899 / 11897
def t_quarantine():
    for c in (c for c in A.CODES if c.startswith("APC-1")):
        check("CVE-2020-11899" not in A.CODES[c][2], f"{c} must not claim 11899 (quarantined)")
    check(any("CVE-2020-11899" in A.CODES[c][2] for c in ("APC-001", "APC-002", "APC-003")),
          "11899 must be carried by the version gates")
    check(all("CVE-2020-11897" not in v[2] for v in A.CODES.values()), "11897 absent")


TESTS = [t_version, t_corpus, t_l3, t_snmp, t_snmp_v6, t_tunnels, t_jsof, t_icmp, t_tunnel_fact, t_real_linux, t_mac_parse, t_mac_attribution, t_lowering, t_declared_mismatch, t_signal_window, t_bounds, t_dns, t_dns_tcp_not_inspected, t_dns_v6,
         t_roundtrip, t_ast_guards, t_quarantine]


def run():
    FAILS.clear()
    CHECKS[0] = 0
    FIRED.clear()
    del ALL_FINDINGS[:]
    orig = A.Engine._finding

    def spy(self, code, l3=None, *a, **k):
        FIRED.add((code, f"ipv{l3.af}" if l3 is not None else None))
        return orig(self, code, l3, *a, **k)

    A.Engine._finding = spy
    try:
        for fn in TESTS:
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                FAILS.append(f"{fn.__name__} raised {e!r}")
    finally:
        A.Engine._finding = orig
    for late in (t_invariants, t_coverage):
        try:
            late()
        except Exception as e:  # noqa: BLE001
            FAILS.append(f"{late.__name__} raised {e!r}")
    print(f"apcguard self-test: {CHECKS[0]} checks, {len(FAILS)} failures")
    for f in FAILS:
        print("  FAIL:", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(run())
