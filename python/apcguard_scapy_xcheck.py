#!/usr/bin/env python3
"""apcguard scapy cross-check (LESSON A/N/AG).

scapy is the independent implementation. Every fixture is BUILT by scapy,
serialized with raw(), and handed to apcguard as bytes -- crossing the
bytes->dissect boundary a live capture crosses.
"""
from __future__ import annotations

import json
import logging
import os
import struct
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (IP, IPv6, UDP, ICMP, IPerror, Ether, Dot1Q, IPv6ExtHdrFragment,  # noqa: E402
                       IPv6ExtHdrHopByHop, DNS, DNSQR, DNSRR, raw, fragment)
from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind  # noqa: E402
from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING  # noqa: E402

import apcguard as A  # noqa: E402
import apcguard_selftest as S  # noqa: E402  (REAL_LINUX fixtures)

FAILS = []
N = [0]


def ck(cond, msg):
    N[0] += 1
    if not cond:
        FAILS.append(msg)


NMC4 = "192.0.2.10"
NMC6 = "2001:db8::10"


def collect(frames, nmcs=(NMC4, NMC6)):
    out = []
    eng = A.Engine(nmcs=nmcs, emit=out.append, clock=lambda: 1.0)
    for fr in frames:
        eng.handle_frame(fr)
    return [f["code"] for f in out], out


def x_l3_agree():
    pkts = [
        Ether() / IP(src="1.2.3.4", dst=NMC4) / UDP(sport=161, dport=40000) / b"x",
        Ether() / Dot1Q(vlan=100) / IP(src="1.2.3.4", dst=NMC4) / UDP(sport=53) / b"x",
        Ether() / IPv6(src="2001:db8::1", dst=NMC6) / UDP(sport=161) / b"x",
        Ether() / IPv6(src="2001:db8::1", dst=NMC6) / IPv6ExtHdrHopByHop() / UDP(sport=161) / b"x",
    ]
    for p in pkts:
        l3 = A.parse_l3(raw(p))
        sp = p.getlayer(IP) or p.getlayer(IPv6)
        ck(l3 is not None and l3.src == sp.src and l3.dst == sp.dst, f"L3 addr agree {sp.dst}")
        ck(l3.proto == 17, "L3 proto agree (udp)")
    frags = fragment(Ether() / IP(src="8.8.8.8", dst=NMC4, id=42, proto=4) / (b"Z" * 400), fragsize=200)
    mf = []
    for fr in frags:
        l3 = A.parse_l3(raw(fr))
        mf.append(l3.more)
        ck(l3.frag, "fragment flagged")
    ck(mf[0] is True and mf[-1] is False, "MF sequence agrees with scapy fragment()")


DESCR = ("APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.4 PN:apc_hw05_aos_694.bin "
         "AF1:v6.9.4 AN1:apc_hw05_rpdu2g_694.bin MN:AP8959 HR:02 SN: REDACTED MD:01/15/2020)")


def build_snmp(descr, version="v2c"):
    vbs = [SNMPvarbind(oid=ASN1_OID(A.OID_SYSDESCR), value=ASN1_STRING(descr))]
    return SNMP(version=version, community="public", PDU=SNMPresponse(varbindlist=vbs))


def x_snmp_agree():
    snmp = build_snmp(DESCR)
    parsed = A.parse_snmp_response(raw(snmp))
    ck(parsed is not None, "our BER parser accepts scapy-built SNMPv2c")
    ck(parsed.get(A.OID_SYSDESCR) == DESCR, "sysDescr value agrees with scapy")
    fr = Ether() / IP(src=NMC4, dst="192.0.2.1") / UDP(sport=161, dport=40000) / snmp
    codes, out = collect([raw(fr)])
    ck("APC-001" in codes and "APC-010" in codes, "engine gates scapy-built SNMP")
    ck([x for x in out if x["code"] == "APC-001"][0]["detail"]["model"] == "AP8959", "model via scapy path")
    # IPv6 transport, same SNMP
    fr6 = Ether() / IPv6(src=NMC6, dst="2001:db8::1") / UDP(sport=161, dport=40000) / snmp
    codes6, out6 = collect([raw(fr6)])
    x6 = [x for x in out6 if x["code"] == "APC-001"]
    ck(x6 and x6[0]["af"] == "ipv6", "engine gates scapy-built SNMP over IPv6")
    # v1 also parses
    ck(A.parse_snmp_response(raw(build_snmp(DESCR, "v1"))) is not None, "scapy SNMPv1 accepted")
    # v3 message: never gated
    try:
        m3 = SNMP(version=3, community="x",
                  PDU=SNMPresponse(varbindlist=[SNMPvarbind(oid=ASN1_OID(A.OID_SYSDESCR),
                                                            value=ASN1_STRING(DESCR))]))
        r = A.parse_snmp_response(raw(m3))
        ck(r is None, "v3 returns None")
    except A.ParseError:
        ck(True, "v3 rejected")


def hostile_loop():
    m = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c"
    return m + struct.pack("!HHIH", 1, 1, 300, 4) + b"\x7f\x00\x00\x01"


def x_dns_agree():
    resp = DNS(qr=1, qd=DNSQR(qname="www.example.com"),
               an=DNSRR(rrname="www.example.com", type="CNAME", rdata="target.example.com"))
    ck(A.analyze_dns(raw(resp)) == [], "honest scapy CNAME -> no finding")
    for label, l3 in (("v4", IP(src="192.0.2.1", dst=NMC4)), ("v6", IPv6(src="2001:db8::1", dst=NMC6))):
        fr = Ether() / l3 / UDP(sport=53, dport=40000) / resp
        codes, _ = collect([raw(fr)])
        ck("APC-111" not in codes and "APC-112" not in codes, f"engine clean on honest DNS ({label})")
        frl = Ether() / l3 / UDP(sport=53, dport=40000) / hostile_loop()
        codes, out = collect([raw(frl)])
        ck("APC-112" in codes, f"engine fires APC-112 on hostile DNS via scapy frame ({label})")
    ck("APC-112" in [c for c, _ in A.analyze_dns(hostile_loop())], "loop detected on hostile DNS")
    # RDLENGTH lie on a scapy-built CNAME, patched at the byte level
    good = bytearray(raw(resp))
    idx = good.rfind(b"\x00\x05\x00\x01")            # type CNAME class IN of the answer RR
    rdl = idx + 8
    good[rdl:rdl + 2] = struct.pack("!H", 2)          # RDLENGTH now too small
    hits = [c for c, _ in A.analyze_dns(bytes(good))]
    ck("APC-111" in hits, "APC-111 on RDLENGTH-tampered scapy CNAME")


def x_tunnels():
    inner = IP(src="9.9.9.9", dst=NMC4, proto=17, len=28) / UDP(dport=161) / (b"P" * 200)
    outer = IP(src="8.8.8.8", dst=NMC4, proto=4) / raw(inner)
    frags = fragment(Ether() / outer, fragsize=120)
    codes, out = collect([raw(f) for f in frags])
    ck("APC-101" in codes, "scapy: APC-101 on tunnel fragment")
    ck("APC-102" in codes, "scapy: APC-102 on reassembled trim")
    # shuffled arrival still reassembles
    codes_r, _ = collect([raw(f) for f in reversed(frags)])
    ck("APC-102" in codes_r, "scapy: APC-102 with fragments arriving in reverse order")
    p41 = Ether() / IP(src="8.8.8.8", dst=NMC4, proto=41) / raw(IPv6(src="::1", dst="::2"))
    ck("APC-105" in collect([raw(p41)])[0], "scapy: APC-105 proto 41")
    ben = Ether() / IP(src="8.8.8.8", dst=NMC4, proto=4) / raw(IP(src="9.9.9.9", dst=NMC4) / UDP() / b"ok")
    ck(collect([raw(ben)])[0] == ["APC-104"], "scapy: unfragmented tunnel -> 104 only")


def x_jsof():
    """scapy builds the JSOF whitepaper packets (ch.2.3, ch.4) as NVISO reproduced them."""
    # CVE-2020-11896: inner IPv4{len=32,proto=17}/UDP{chksum=0,len=12}/'A'*1000; outer split 40 / rest.
    ib = raw(IP(src="9.9.9.9", dst=NMC4, proto=17, len=32) / UDP(sport=1234, dport=5678, chksum=0, len=12)
             / (b"A" * 1000))
    ck(struct.unpack("!H", ib[2:4])[0] == 32 and len(ib) == 1028, "scapy built the 11896 inner as specified")
    f1 = Ether() / IP(src="8.8.8.8", dst=NMC4, id=0xABCD, proto=4, flags="MF", frag=0) / ib[:40]
    f2 = Ether() / IP(src="8.8.8.8", dst=NMC4, id=0xABCD, proto=4, flags=0, frag=5) / ib[40:]
    codes, out = collect([raw(f1), raw(f2)])
    ck(codes == ["APC-101", "APC-102"], f"scapy JSOF 11896: {codes}")
    ck(out[-1]["cves"] == ["CVE-2020-11896"], f"scapy JSOF 11896 attribution: {out[-1]['cves']}")
    # CVE-2020-11898: inner IPv4{ihl=0xf,len=100,proto=0} + 40 nulls + 100 'A'; outer split 24 / rest.
    ib = raw(IP(ihl=0xF, len=100, proto=0, src="9.9.9.9", dst=NMC4) / (b"\x00" * 40 + b"\x41" * 100))
    ck(ib[0] == 0x4F and struct.unpack("!H", ib[2:4])[0] == 100 and ib[9] == 0,
       "scapy built the 11898 inner as specified (ihl=15, len=100, proto=0)")
    f1 = Ether() / IP(src="8.8.8.8", dst=NMC4, id=0xABCD, proto=4, flags="MF", frag=0) / ib[:24]
    f2 = Ether() / IP(src="8.8.8.8", dst=NMC4, id=0xABCD, proto=4, flags=0, frag=3) / ib[24:]
    codes, out = collect([raw(f1), raw(f2)])
    ck(codes == ["APC-101", "APC-102"], f"scapy JSOF 11898: {codes}")
    ck(out[-1]["cves"] == ["CVE-2020-11896", "CVE-2020-11898"], f"scapy JSOF 11898 attribution: {out[-1]['cves']}")
    # inner length LONGER than the data present is rejected by Treck's sanity check -> no finding
    ib = raw(IP(ihl=0xF, len=500, proto=0, src="9.9.9.9", dst=NMC4) / (b"\x00" * 40 + b"\x41" * 100))
    f1 = Ether() / IP(src="8.8.8.8", dst=NMC4, id=0xABCE, proto=4, flags="MF", frag=0) / ib[:24]
    f2 = Ether() / IP(src="8.8.8.8", dst=NMC4, id=0xABCE, proto=4, flags=0, frag=3) / ib[24:]
    ck("APC-102" not in collect([raw(f1), raw(f2)])[0], "scapy: inner length LONGER than data raises no APC-102")


LEAK = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 11)


def _req11898(inner_src="9.9.9.9", outer_id=0xABCD):
    """scapy-built CVE-2020-11898 request (whitepaper ch.4). -> (frames as bytes, inner bytes)."""
    ib = raw(IP(ihl=0xF, len=100, proto=0, src=inner_src, dst=NMC4) / (b"\x00" * 40 + b"\x41" * 100))
    f1 = Ether() / IP(src="8.8.8.8", dst=NMC4, id=outer_id, proto=4, flags="MF", frag=0) / ib[:24]
    f2 = Ether() / IP(src="8.8.8.8", dst=NMC4, id=outer_id, proto=4, flags=0, frag=3) / ib[24:]
    return [raw(f1), raw(f2)], ib


def x_icmp():
    """scapy builds the reply (ICMP type 3 code 2 quoting the inner packet) and its own
    dissection is the oracle for what apcguard keys on."""
    req, ib = _req11898()
    reply = raw(Ether() / IP(src=NMC4, dst="9.9.9.9") / ICMP(type=3, code=2) / (ib[:24] + LEAK))
    d = IP(reply[14:])
    ck(d[ICMP].type == 3 and d[ICMP].code == 2, "scapy dissects the reply as type 3 code 2")
    e = d.getlayer(IPerror)
    ck(e is not None and (e.src, e.dst, e.proto, e.id) == ("9.9.9.9", NMC4, 0, struct.unpack("!H", ib[4:6])[0]),
       f"scapy's IPerror agrees with the bytes apcguard keys on: {e and (e.src, e.dst, e.proto, e.id)}")
    codes, out = collect(req + [reply])
    ck(codes == ["APC-101", "APC-102", "APC-103", "APC-106"], f"scapy ICMP leak flow: {codes}")
    ck(out[3]["detail"]["beyond_first_fragment"] == 44 and out[3]["detail"]["first_mismatch_offset"] == 24
       and out[3]["detail"]["mismatching_bytes"] == 44, f"scapy APC-106 detail: {out[3]['detail']}")
    ck("deadbeef" not in json.dumps(out).lower(), "scapy flow: disclosed bytes never appear in a finding")
    benign = raw(Ether() / IP(src=NMC4, dst="9.9.9.9") / ICMP(type=3, code=2) / ib[:68])
    ck(collect(req + [benign])[0] == ["APC-101", "APC-102", "APC-103"], "scapy: a correct quote answers but discloses nothing")
    for typ, code in ((3, 3), (11, 1), (3, 1)):
        rr = raw(Ether() / IP(src=NMC4, dst="9.9.9.9") / ICMP(type=typ, code=code) / (ib[:24] + LEAK))
        ck(collect(req + [rr])[0] == ["APC-101", "APC-102"], f"scapy: ICMP {typ}/{code} is not an answer")
    # the reply is matched to the request, not to the address family or arrival order
    ck(collect([reply] + req)[0] == ["APC-101", "APC-102"], "a reply seen BEFORE its request is not matched")


def x_tunnel_fact():
    """scapy builds the tunnel datagram and the card's rejection; scapy also dissects the REAL Linux
    replies, so its reading of what the stack quoted is the oracle for apcguard's matching."""
    outer = IP(src="8.8.8.8", dst=NMC4, id=0x1111, proto=4) / IP(src="9.9.9.9", dst=NMC4) / UDP(sport=1, dport=2) / b"data"
    ob = raw(outer)
    req = raw(Ether() / outer)
    reply = raw(Ether() / IP(src=NMC4, dst="8.8.8.8") / ICMP(type=3, code=2) / ob[:28])
    e = IP(reply[14:]).getlayer(IPerror)
    ck(e is not None and (e.src, e.dst, e.proto, e.id) == ("8.8.8.8", NMC4, 4, 0x1111),
       f"scapy's IPerror agrees the reply quotes the OUTER header: {e and (e.src, e.dst, e.proto, e.id)}")
    codes, out = collect([req, reply])
    ck(codes == ["APC-104", "APC-107"], f"scapy proto 4 rejection: {codes}")
    ck(out[1]["cves"] == [] and out[1]["severity"] == "info", "scapy: APC-107 is informational and names no CVE")
    o41 = IP(src="8.8.8.8", dst=NMC4, id=0x4141, proto=41) / raw(IPv6(src="2001:db8::1", dst="2001:db8::2"))
    reply41 = raw(Ether() / IP(src=NMC4, dst="8.8.8.8") / ICMP(type=3, code=2) / raw(o41)[:28])
    codes41, _ = collect([raw(Ether() / o41), reply41])
    ck(codes41 == ["APC-105", "APC-108"], f"scapy proto 41 rejection: {codes41}")
    ck(collect([reply])[0] == [], "scapy: a reply with no observed request reports nothing")
    for typ, code in ((3, 3), (11, 1), (5, 2)):
        rr = raw(Ether() / IP(src=NMC4, dst="8.8.8.8") / ICMP(type=typ, code=code) / ob[:28])
        ck(collect([req, rr])[0] == ["APC-104"], f"scapy: ICMP {typ}/{code} is not a rejection")
    # ---- the REAL Linux frames: scapy is the oracle for what the stack said
    for name, proto, ident, qlen in (("unfrag4", 4, 0x1111, 68), ("frag4", 4, 0x2222, 180), ("proto41", 41, 0x3333, 70)):
        fx = S.REAL_LINUX[name]
        d = Ether(fx["reply"])
        ck(d[ICMP].type == 3 and d[ICMP].code == 2, f"{name}: scapy reads the real reply as type 3 code 2")
        q = d.getlayer(IPerror)
        ck(q is not None and (q.proto, q.id, q.src, q.dst) == (proto, ident, "10.99.0.1", "10.99.0.2"),
           f"{name}: scapy's IPerror on the REAL reply: {q and (q.proto, q.id, q.src, q.dst)}")
        codes, out = collect(fx["req"] + [fx["reply"]], nmcs=("10.99.0.2",))
        ck(out[-1]["code"] in ("APC-107", "APC-108") and out[-1]["detail"]["quote_bytes"] == qlen,
           f"{name}: real reply matched, quote_bytes {out[-1]['detail'].get('quote_bytes')} (scapy sees {len(d[ICMP].payload)})")


def x_cli_cap():
    """The --max-observed-nmcs flag really reaches the engine, through the real CLI and the real capture path."""
    import subprocess
    import tempfile
    from scapy.all import wrpcap
    frames = [Ether(S.v4f("198.51.100.%d" % i, "192.0.2.1", 17, S.udp(161, 40000, S.snmp_response(sysdescr=S.DESCR))))
              for i in range(1, 6)]
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, frames)
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apcguard.py")

        def run(*extra):
            r = subprocess.run([sys.executable, script, "--iface", "lo", "--pcap", path, *extra],
                               capture_output=True, text=True, timeout=60)
            return [json.loads(l)["code"] for l in r.stdout.splitlines() if l.startswith("{")], r
        codes, r = run("--max-observed-nmcs", "2")
        ck(r.returncode == 0 and codes.count("APC-010") == 2 and codes.count("APC-012") == 1,
           f"--max-observed-nmcs 2 over five sources: {codes} rc={r.returncode}")
        codes, r = run()
        ck(codes.count("APC-010") == 5 and "APC-012" not in codes, f"default cap admits all five: {codes}")
    finally:
        os.unlink(path)


def x_mac():
    """scapy is the oracle for the source MAC apcguard reads, and for attribution over scapy-built frames."""
    for label, pkt in (("plain", Ether(src="02:aa:bb:cc:dd:10") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP() / b"x"),
                       ("vlan", Ether(src="02:aa:bb:cc:dd:10") / Dot1Q(vlan=100) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP() / b"x"),
                       ("ipv6", Ether(src="02:aa:bb:cc:dd:10") / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP() / b"x")):
        b = raw(pkt)
        ck(A.parse_l3(b).smac == Ether(b).src, f"{label}: apcguard reads {A.parse_l3(b).smac}, scapy reads {Ether(b).src}")
    for name in ("unfrag4", "frag4", "proto41"):
        fx = S.REAL_LINUX[name]
        ck(A.parse_l3(fx["reply"]).smac == Ether(fx["reply"]).src, f"real {name} reply: source MAC agrees with scapy")
    outer = IP(src="8.8.8.8", dst=NMC4, id=0x1111, proto=4) / IP(src="9.9.9.9", dst=NMC4) / UDP(sport=1, dport=2) / b"data"
    ob = raw(outer)
    req = raw(Ether(src="02:00:00:00:00:01") / outer)

    def reply(mac):
        return raw(Ether(src=mac) / IP(src=NMC4, dst="8.8.8.8") / ICMP(type=3, code=2) / ob[:28])
    good, other = "02:aa:bb:cc:dd:10", "02:ee:ee:ee:ee:99"
    codes, out = collect([req, reply(good)], nmcs=((NMC4, good),))
    ck(codes == ["APC-104", "APC-107"] and out[1]["detail"]["attribution"] == "declared-mac", f"scapy declared MAC: {codes}")
    codes, out = collect([req, reply(other)], nmcs=((NMC4, good),))
    ck(codes == ["APC-104", "APC-109"] and out[1]["cves"] == [], f"scapy foreign MAC: {codes}")


def x_cli_mac():
    """The declared MAC, the lowering, its switches and its error handling, through the real CLI on REAL frames."""
    import subprocess
    import tempfile
    from scapy.all import wrpcap
    u, f = S.REAL_LINUX["unfrag4"], S.REAL_LINUX["frag4"]
    rmac = A.mac_str(u["reply"][6:12])
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apcguard.py")
    try:
        wrpcap(path, [Ether(x) for x in u["req"] + [u["reply"]] + f["req"]])

        def run(*extra):
            r = subprocess.run([sys.executable, script, "--iface", "lo", "--pcap", path, *extra],
                               capture_output=True, text=True, timeout=60)
            fs = [json.loads(l) for l in r.stdout.splitlines() if l.startswith("{")]
            return fs, r

        def attempts(fs):
            return [x["severity"] for x in fs if x["code"] in ("APC-101", "APC-102")]
        fs, r = run("--nmc", f"10.99.0.2={rmac}")
        ck(r.returncode == 0 and [x["code"] for x in fs] == ["APC-104", "APC-107", "APC-101", "APC-102"],
           f"declared MAC: {[x['code'] for x in fs]} rc={r.returncode}")
        ck(fs[1]["detail"]["attribution"] == "declared-mac" and attempts(fs) == ["warn", "warn"],
           f"declared MAC lowers the attempts: {attempts(fs)}")
        ck(all(x["detail"].get("severity_lowered_from") == "critical" for x in fs if x["code"] in ("APC-101", "APC-102")),
           "each lowered finding says what it was lowered from")
        fs, _ = run("--nmc", "10.99.0.2=02:00:00:00:99:99")
        ck("APC-109" in [x["code"] for x in fs] and "APC-107" not in [x["code"] for x in fs] and attempts(fs) == ["critical", "critical"],
           "a wrong declared MAC: APC-109, nothing lowered")
        fs, _ = run("--nmc", "10.99.0.2")
        ck(attempts(fs) == ["critical", "critical"] and fs[1]["detail"]["attribution"] == "unknown", "no declared MAC: nothing lowered")
        fs, _ = run("--nmc", f"10.99.0.2={rmac}", "--no-lower-attempts")
        ck(attempts(fs) == ["critical", "critical"] and "APC-107" in [x["code"] for x in fs], "--no-lower-attempts")
        fs, _ = run("--nmc", f"10.99.0.2={rmac}", "--tunnel-fact-ttl", "0")
        ck(attempts(fs) == ["critical", "critical"], "--tunnel-fact-ttl 0: the fact is never fresh enough")
        fs, _ = run("--nmc", f"10.99.0.2={rmac}", "--min-severity", "warn")
        ck(attempts(fs) == ["warn", "warn"] and "APC-107" not in [x["code"] for x in fs],
           "--min-severity filters on the EFFECTIVE (lowered) severity")
        for bad in ("10.99.0.2=zz", "10.99.0.999=" + rmac, "10.99.0.2=01:00:5e:00:00:01"):
            r = subprocess.run([sys.executable, script, "--iface", "lo", "--pcap", path, "--nmc", bad],
                               capture_output=True, text=True, timeout=60)
            ck(r.returncode == 2 and "cannot use the declared cards" in r.stderr and "Traceback" not in r.stderr,
               f"--nmc {bad}: rc={r.returncode}, a clear error and no traceback")
        # declared twice (command line WITH the MAC, file WITHOUT): still declared; two different MACs: a clear error
        nl0 = tempfile.mktemp(suffix=".list")
        open(nl0, "w").write("10.99.0.2\n")
        fs, r = run("--nmc", f"10.99.0.2={rmac}", "--nmc-file", nl0)
        ck(attempts(fs) == ["warn", "warn"], "a bare duplicate in the file must not erase the command-line MAC")
        open(nl0, "w").write("10.99.0.2  02:00:00:00:99:99\n")
        r = subprocess.run([sys.executable, script, "--iface", "lo", "--pcap", path, "--nmc", f"10.99.0.2={rmac}", "--nmc-file", nl0],
                           capture_output=True, text=True, timeout=60)
        ck(r.returncode != 0 and "two different MACs" in (r.stderr + r.stdout) and "Traceback" not in r.stderr,
           f"conflicting MACs must be a clear error: rc={r.returncode}")
        os.unlink(nl0)
        r = subprocess.run([sys.executable, script, "--iface", "lo", "--pcap", path, "--nmc", f"10.99.0.2={rmac}"],
                           capture_output=True, text=True, timeout=60)
        ck('"lowered": 2' in r.stderr, f"the stderr stats report how many findings were lowered: {r.stderr[-120:]}")
        for bad in ("nan", "inf", "-5", "86401"):
            r = subprocess.run([sys.executable, script, "--iface", "lo", "--pcap", path, "--nmc", f"10.99.0.2={rmac}",
                                "--tunnel-fact-ttl", bad], capture_output=True, text=True, timeout=60)
            ck(r.returncode == 2 and "freshness window" in r.stderr and "Traceback" not in r.stderr,
               f"--tunnel-fact-ttl {bad}: rc={r.returncode}, a clear error")
        nl = tempfile.mktemp(suffix=".list")
        open(nl, "w").write(f"10.99.0.2  {rmac}  # the card\n")
        fs, r = run("--nmc-file", nl)
        ck(attempts(fs) == ["warn", "warn"], "the same declaration from --nmc-file")
        os.unlink(nl)
    finally:
        os.unlink(path)


def x_declared_mismatch():
    """APC-110 over scapy-built SNMP frames, IPv4 and IPv6, and through the real CLI."""
    good, other = "02:aa:bb:cc:dd:10", "02:ee:ee:ee:ee:99"
    from scapy.all import Raw
    body = S.snmp_response(sysdescr=S.DESCR)

    def snmp(mac, v6=False):
        ip = IPv6(src=NMC6, dst="2001:db8::1") if v6 else IP(src=NMC4, dst="192.0.2.1")
        return raw(Ether(src=mac) / ip / UDP(sport=161, dport=40000) / Raw(body))
    codes, out = collect([snmp(other)], nmcs=((NMC4, good),))
    ck("APC-110" in codes and [o for o in out if o["code"] == "APC-110"][0]["detail"]["observed_mac"] == other, f"v4: {codes}")
    codes, _ = collect([snmp(good)], nmcs=((NMC4, good),))
    ck("APC-110" not in codes, "v4: matching MAC is silent")
    codes, out = collect([snmp(other, v6=True)], nmcs=((NMC6, good),))
    ck("APC-110" in codes and [o for o in out if o["code"] == "APC-110"][0]["af"] == "ipv6", f"v6: {codes}")
    import subprocess
    import tempfile
    from scapy.all import wrpcap
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, [Ether(snmp(other)), Ether(snmp(other, v6=True))])
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apcguard.py")
        r = subprocess.run([sys.executable, script, "--iface", "lo", "--pcap", path, "--nmc", f"{NMC4}={good}",
                            "--nmc", f"{NMC6}={good}"], capture_output=True, text=True, timeout=60)
        got = [json.loads(l)["af"] for l in r.stdout.splitlines() if l.startswith("{") and '"APC-110"' in l]
        ck(sorted(got) == ["ipv4", "ipv6"], f"CLI: APC-110 on both families: {got}")
    finally:
        os.unlink(path)


def x_signals():
    """A live sensor stopped by SIGTERM (systemctl stop) or SIGINT exits 0 and still prints its stats."""
    import signal as _sig
    import subprocess
    import time as _t
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "apcguard.py")
    for sig in (_sig.SIGTERM, _sig.SIGINT):
        p = subprocess.Popen([sys.executable, script, "--iface", "lo"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _t.sleep(6)                                        # scapy import + libpcap open, on a one-CPU box
        p.send_signal(sig)
        try:
            _, err = p.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
            ck(False, f"{sig.name}: the sensor did not stop")
            continue
        ck(p.returncode == 0 and '"stats"' in err and "Traceback" not in err, f"{sig.name}: rc={p.returncode} stderr={err[-150:]!r}")


def x_ipv6_tunnel():
    inner = raw(IP(src="9.9.9.9", dst=NMC4, proto=17, len=28) / UDP(dport=161) / (b"P" * 200))
    h = len(inner) // 2
    h -= h % 8
    p1 = IPv6(src="2001:db8::1", dst=NMC6) / IPv6ExtHdrFragment(nh=4, id=5, m=1, offset=0) / inner[:h]
    p2 = IPv6(src="2001:db8::1", dst=NMC6) / IPv6ExtHdrFragment(nh=4, id=5, m=0, offset=h // 8) / inner[h:]
    l3 = A.parse_l3(raw(Ether() / p1))
    ck(l3 is not None and l3.af == 6 and l3.frag, "scapy IPv6 frag hdr parsed")
    codes, out = collect([raw(Ether() / p1), raw(Ether() / p2)])
    ck(codes == ["APC-104"], f"scapy: v6-outer tunnel -> 104 only, got {codes}")
    ck(not any(x["cves"] for x in out), "scapy: v6-outer tunnel attributes no CVE")


def _capture(frames, bpf, nmcs=(NMC4, NMC6, "10.99.0.2")):
    """Drive the REAL run_capture() (scapy offline sniff, real BPF) over a pcap."""
    import os
    import tempfile
    from scapy.all import wrpcap
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, [Ether(f) for f in frames])
        out = []
        eng = A.Engine(nmcs=nmcs, emit=out.append, clock=lambda: 1.0)
        A.run_capture(eng, pcap=path, bpf=bpf)
        return out
    finally:
        os.unlink(path)


def x_capture_path():
    """LESSON C/H/AE: the BPF is bypassed by every other tier. Measure it."""
    hbh = IPv6ExtHdrHopByHop()
    dns_eh = raw(Ether() / IPv6(src="2001:db8::1", dst=NMC6) / hbh / UDP(sport=53, dport=40000) / hostile_loop())
    snmp4 = raw(Ether() / IP(src=NMC4, dst="192.0.2.1") / UDP(sport=161, dport=40000) / build_snmp(DESCR))
    inner = IP(src="9.9.9.9", dst=NMC4, proto=17, len=28) / UDP(dport=161) / (b"P" * 200)
    tun = [raw(f) for f in fragment(Ether() / (IP(src="8.8.8.8", dst=NMC4, proto=4) / raw(inner)), fragsize=120)]
    raw6 = raw(inner)
    h = len(raw6) // 2
    h -= h % 8
    tun6 = [raw(Ether() / IPv6(src="2001:db8::1", dst=NMC6) / IPv6ExtHdrFragment(nh=4, id=5, m=1, offset=0) / raw6[:h]),
            raw(Ether() / IPv6(src="2001:db8::1", dst=NMC6) / IPv6ExtHdrFragment(nh=4, id=5, m=0, offset=h // 8) / raw6[h:])]
    p41 = raw(Ether() / IP(src="8.8.8.8", dst=NMC4, proto=41) / raw(IPv6(src="::1", dst="::2")))
    icmp_req, icmp_ib = _req11898(inner_src="9.9.9.10", outer_id=0xBEEF)
    icmp_reply = raw(Ether() / IP(src=NMC4, dst="9.9.9.10") / ICMP(type=3, code=2) / (icmp_ib[:24] + LEAK))
    real = S.REAL_LINUX["unfrag4"]
    frames = [dns_eh, snmp4] + tun + tun6 + [p41] + icmp_req + [icmp_reply] + real["req"] + [real["reply"]]

    got = _capture(frames, A.BPF_FILTER)
    codes = {(f["code"], f.get("af")) for f in got}
    ck(("APC-112", "ipv6") in codes, "capture: v6 DNS behind hop-by-hop ext header reaches the parser")
    ck(("APC-001", "ipv4") in codes, "capture: v4 SNMP Class B via real BPF")
    ck(("APC-102", "ipv4") in codes, "capture: v4 tunnel fragments via real BPF")
    ck(("APC-104", "ipv6") in codes and ("APC-102", "ipv6") not in codes and
       ("APC-101", "ipv6") not in codes, "capture: v6 tunnel fragments via real BPF -> 104, never 101/102")
    ck(("APC-105", "ipv4") in codes, "capture: proto 41 via real BPF")
    ck(("APC-103", "ipv4") in codes and ("APC-106", "ipv4") in codes,
       "capture: the ICMP reply reaches the parser through the real BPF")
    ck(("APC-107", "ipv4") in codes, "capture: a REAL Linux rejection reaches the parser through the real BPF")
    no_icmp = A.BPF_FILTER.replace("icmp or ", "")
    ck(no_icmp != A.BPF_FILTER, "capture: the icmp-less filter is a genuine variant")
    lost_icmp = {(f["code"], f.get("af")) for f in _capture(frames, no_icmp)}
    ck(("APC-107", "ipv4") not in lost_icmp and ("APC-104", "ipv4") in lost_icmp,
       "capture: a filter without `icmp` loses the real rejection but keeps the tunnel datagram (differential)")
    ck(("APC-103", "ipv4") not in lost_icmp and ("APC-106", "ipv4") not in lost_icmp and ("APC-102", "ipv4") in lost_icmp,
       "capture: a filter without `icmp` loses the reply but keeps the request (differential proves the term matters)")

    # differential: the LESSON AE no-op form must LOSE the extension-header frame
    noop = "(udp port 161) or (udp port 53) or (ip6 and udp port 53) or (ip proto 4) or (ip proto 41)"
    lost = _capture(frames, noop)
    ck(("APC-112", "ipv6") not in {(f["code"], f.get("af")) for f in lost},
       "capture: no-op filter form loses the EH frame (differential proves this tier bites)")
    ck(len(got) > len(lost), "capture: production filter admits strictly more than the no-op form")


def run():
    for fn in [x_l3_agree, x_snmp_agree, x_dns_agree, x_tunnels, x_jsof, x_icmp, x_tunnel_fact, x_cli_cap, x_mac, x_cli_mac, x_declared_mismatch, x_signals, x_ipv6_tunnel, x_capture_path]:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            FAILS.append(f"{fn.__name__} raised {e!r}")
    print(f"apcguard scapy xcheck: {N[0]} checks, {len(FAILS)} failures")
    for f in FAILS:
        print("  FAIL:", f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(run())
