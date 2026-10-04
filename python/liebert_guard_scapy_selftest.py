#!/usr/bin/env python3
"""liebert_guard scapy self-test (runs with REAL scapy installed; the module itself never imports it).

Sections
  S0  harness self-tests (the comparators must bite)
  S1  lazy-import invariant with scapy PRESENT
  S2  scapy dissector cross-check of parse_frame (independent implementation, LESSON A)
  S3  real HTTP stack oracle: stdlib http.server bytes, re-segmented through scapy frames,
      judged by stdlib http.client (a parser neither of us wrote)
  S4  pcap readers: module vs scapy rdpcap, linktypes, pcapng, nanosecond pcap
  S5  CLI end to end over scapy-written captures with background noise
Run: python3 liebert_guard_scapy_selftest.py [-v]
"""
import http.client
import http.server
import io
import ipaddress
import itertools
import json
import logging
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MOD = os.path.join(HERE, "liebert_guard.py")
VERBOSE = "-v" in sys.argv

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy  # noqa: E402
from scapy.all import (ARP, DNS, DNSQR, Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP,  # noqa: E402
                       rdpcap, sniff, wrpcap)
from scapy.layers.inet import IPOption_NOP  # noqa: E402
from scapy.layers.inet6 import (IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,  # noqa: E402
                                IPv6ExtHdrHopByHop, IPv6ExtHdrRouting)
from scapy.layers.l2 import CookedLinux, Dot1AD  # noqa: E402

import liebert_guard as lg  # noqa: E402

try:
    from scapy.layers.l2 import CookedLinuxV2
except ImportError:  # older scapy
    CookedLinuxV2 = None

TALLY = {}
CUR = ["?"]


def section(name):
    CUR[0] = name
    TALLY.setdefault(name, [0, 0])
    if VERBOSE:
        print("--", name)


def check(name, cond):
    TALLY[CUR[0]][0 if cond else 1] += 1
    if not cond:
        print("FAIL[%s]: %s" % (CUR[0], name))


def run_cli(*args, cwd=HERE):
    return subprocess.run([sys.executable, MOD] + list(args), capture_output=True, text=True, cwd=cwd)


def resp(server, body=b"<html></html>", ver="1.1"):
    h = b"HTTP/" + ver.encode() + b" 200 OK\r\n"
    if server is not None:
        h += b"Server: " + server + b"\r\n"
    return h + b"Content-Type: text/html\r\n\r\n" + body


V4S, V4C, V6S, V6C = "10.9.0.5", "10.9.0.77", "2001:db8::5", "2001:db8::77"


def ip_layer(fam, ipopts=0, ext=()):
    if fam == "v4":
        return IP(src=V4S, dst=V4C, options=[IPOption_NOP() for _ in range(ipopts)])
    p = IPv6(src=V6S, dst=V6C)
    for e in ext:
        p = p / e
    return p


def build(payload, fam="v4", seq=1000, sport=80, dport=40000, vlans=(), qinq=False, ipopts=0,
          ext=(), tcpopts=None, pad=0, flags="PA"):
    e = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    if qinq:
        e = e / Dot1AD(vlan=100)
    for v in vlans:
        e = e / Dot1Q(vlan=v)
    t = TCP(sport=sport, dport=dport, seq=seq, flags=flags, options=tcpopts or [])
    p = e / ip_layer(fam, ipopts, ext) / t
    if payload:
        p = p / Raw(payload)
    return bytes(p) + b"\x00" * pad


def scapy_view(raw):
    """What scapy's dissector says about a frame: (family, src, dst, sport, dport, seq, payload)."""
    p = Ether(raw)
    if IP in p:
        ip, fam = p[IP], "ipv4"
    elif IPv6 in p:
        ip, fam = p[IPv6], "ipv6"
    else:
        return None
    if TCP not in p:
        return None
    t = p[TCP]
    return (fam, ip.src, ip.dst, t.sport, t.dport, t.seq, bytes(p[Raw].load) if Raw in p else b"")


def same(ours, theirs):
    if ours is None or theirs is None:
        return ours is theirs
    if ours[0] != theirs[0]:
        return False
    for a, b in ((ours[1], theirs[1]), (ours[2], theirs[2])):
        if ipaddress.ip_address(a) != ipaddress.ip_address(b):
            return False
    return ours[3:] == theirs[3:]


def run_det(frames, ts0=1000.0, **kw):
    out = []
    d = lg.Detector(emit=out.append, **kw)
    for i, f in enumerate(frames):
        d.feed(ts0 + i, f)
    return out


def codes(out):
    return [f["code"] for f in out]


R407 = resp(b"RomPager/4.07 UPnP/1.0")
R434 = resp(b"RomPager/4.34 UPnP/1.0")

# =====================================================================================
section("S0 harness self-tests")
good = build(R407)
check("same() accepts identical views", same(scapy_view(good), lg.parse_frame(good)))
bad = list(lg.parse_frame(good))
bad[5] += 1
check("same() rejects a seq off by one", not same(tuple(bad), scapy_view(good)))
bad = list(lg.parse_frame(good))
bad[6] = bad[6][:-1]
check("same() rejects a payload short by one", not same(tuple(bad), scapy_view(good)))
bad = list(lg.parse_frame(good))
bad[1] = "10.9.0.6"
check("same() rejects a wrong address", not same(tuple(bad), scapy_view(good)))
check("same() treats None/None as equal and None/x as different",
      same(None, None) and not same(None, scapy_view(good)))
check("scapy_view sees the payload we put in", scapy_view(good)[6] == R407)
check("scapy is a real scapy", hasattr(scapy, "__version__") and TCP in Ether(good))

# =====================================================================================
section("S1 lazy-import invariant (scapy installed)")
prog_mod = ("import sys; sys.path.insert(0, %r); import liebert_guard; "
            "print('SCAPY' if any(m.split('.')[0]=='scapy' for m in sys.modules) else 'CLEAN')" % HERE)
r = subprocess.run([sys.executable, "-c", prog_mod], capture_output=True, text=True)
check("importing the module does not import scapy", r.stdout.strip() == "CLEAN")
prog_pre = ("import sys; sys.path.insert(0, %r); import scapy.all; import liebert_guard as m; "
            "print('LEAK' if hasattr(m, 'scapy') or hasattr(m, 'sendp') or hasattr(m, 'sniff') else 'CLEAN')" % HERE)
r = subprocess.run([sys.executable, "-c", prog_pre], capture_output=True, text=True)
check("scapy imported first leaves no scapy names in the module", r.stdout.strip() == "CLEAN")
with tempfile.TemporaryDirectory() as td:
    pc = os.path.join(td, "a.pcap")
    wrpcap(pc, [Ether(build(R407))])
    prog_cli = ("import sys, runpy; sys.argv=['lg','-r',%r]\n"
                "try: runpy.run_path(%r, run_name='__main__')\n"
                "except SystemExit: pass\n"
                "print('SCAPY' if any(m.split('.')[0]=='scapy' for m in sys.modules) else 'CLEAN')" % (pc, MOD))
    r = subprocess.run([sys.executable, "-c", prog_cli], capture_output=True, text=True)
    check("the pcap CLI path never imports scapy", r.stdout.strip().splitlines()[-1] == "CLEAN")
    check("...and still produced its finding", '"LG-001"' in r.stdout)

# =====================================================================================
section("S2 dissector cross-check")
ext_chains = {
    "none": [], "hbh": [IPv6ExtHdrHopByHop()], "dest": [IPv6ExtHdrDestOpt()],
    "routing": [IPv6ExtHdrRouting()], "frag0": [IPv6ExtHdrFragment(offset=0, m=0, id=7)],
    "hbh+dest": [IPv6ExtHdrHopByHop(), IPv6ExtHdrDestOpt()],
    "hbh+routing+dest": [IPv6ExtHdrHopByHop(), IPv6ExtHdrRouting(), IPv6ExtHdrDestOpt()],
    "routing+frag0": [IPv6ExtHdrRouting(), IPv6ExtHdrFragment(offset=0, m=0, id=9)],
}
tcpopt_sets = {
    "none": None,
    "mss+ws": [("MSS", 1460), ("NOP", None), ("WScale", 7)],
    "full": [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (11, 22)), ("NOP", None), ("WScale", 9)],
}
payloads = {"empty": b"", "1B": b"H", "head": R407, "1000B": R407 + b"x" * 1000}
vlan_sets = {"none": ((), False), "one": ((20,), False), "two": ((20, 30), False), "qinq": ((5,), True)}
n = mismatches = 0
for fam in ("v4", "v6"):
    chains = ext_chains if fam == "v6" else {"none": []}
    for (vn, (vl, qq)), (on, ov), (tn, to), (pn, pv), (cn, ch), pad, seq in itertools.product(
            vlan_sets.items(), ((("ipopt0", 0), ("ipopt4", 4), ("ipopt8", 8)) if fam == "v4" else (("-", 0),)),
            tcpopt_sets.items(), payloads.items(), chains.items(), (0, 7, 40),
            (1000, 0xFFFFFFF0)):
        raw = build(pv, fam, seq=seq, vlans=vl, qinq=qq, ipopts=ov, ext=ch, tcpopts=to, pad=pad)
        n += 1
        ours, theirs = lg.parse_frame(raw), scapy_view(raw)
        if not same(ours, theirs):
            mismatches += 1
            if mismatches <= 5:
                print("  MISMATCH", fam, vn, on, tn, pn, cn, pad, seq, "\n   ours  ", ours, "\n   scapy ", theirs)
check("parse_frame == scapy over %d frames (v4+v6, vlan/qinq, ip+tcp options, ext chains, padding, seq wrap)" % n,
      mismatches == 0)

# fixtures scapy sees as non-TCP-or-fragment must be rejected by us too
for name, pkt in (("udp", Ether() / IP(src=V4S, dst=V4C) / UDP(sport=80, dport=1) / Raw(b"HTTP/1.1 200 OK\r\n\r\n")),
                  ("icmp", Ether() / IP(src=V4S, dst=V4C) / ICMP()),
                  ("arp", Ether() / ARP()),
                  ("v6udp", Ether() / IPv6(src=V6S, dst=V6C) / UDP(sport=80, dport=1) / Raw(b"x")),
                  ("v4 nonfirst frag", Ether() / IP(src=V4S, dst=V4C, flags=0, frag=5, proto=6) / Raw(b"x" * 24)),
                  ("v6 nonfirst frag", Ether() / IPv6(src=V6S, dst=V6C) / IPv6ExtHdrFragment(offset=5, m=0, nh=6)
                   / Raw(b"x" * 24))):
    check("non-TCP/non-first-fragment rejected: " + name, lg.parse_frame(bytes(pkt)) is None)

# round trip of rendered addresses: JSON text parses back to the exact address scapy built
out = run_det([build(R407, "v4"), build(R407, "v6", seq=5)])
check("ipv4 server renders as scapy's address", ipaddress.ip_address(out[0]["server"]) == ipaddress.ip_address(V4S))
check("ipv6 server renders as scapy's address", ipaddress.ip_address(out[1]["server"]) == ipaddress.ip_address(V6S))
check("ipv6 server is the compressed canonical form", out[1]["server"] == str(ipaddress.ip_address(V6S)))

# built-vs-dissected: the pipeline is fed BYTES; a dissected re-serialisation must behave identically
for fam in ("v4", "v6"):
    raw = build(R407, fam, ext=[IPv6ExtHdrHopByHop()] if fam == "v6" else [])
    check("bytes(Ether(raw)) == raw (%s)" % fam, bytes(Ether(raw)) == raw)
    check("pipeline identical on dissected round trip (%s)" % fam,
          codes(run_det([bytes(Ether(raw))])) == codes(run_det([raw])) == ["LG-001"])

# =====================================================================================
section("S3 real HTTP stack oracle")


class _Base(http.server.BaseHTTPRequestHandler):
    sys_version = ""

    def do_GET(self):
        body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/close":
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def handler(banner, proto="HTTP/1.0"):
    return type("H", (_Base,), {"server_version": banner, "protocol_version": proto})


def serve_once(cls, requests):
    srv = http.server.HTTPServer(("127.0.0.1", 0), cls)
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    c = socket.create_connection(srv.server_address)
    chunks = []
    for req in requests:
        c.sendall(req)
    c.settimeout(5)
    try:
        while True:
            d = c.recv(65535)
            if not d:
                break
            chunks.append(d)
    except socket.timeout:
        pass
    c.close()
    t.join(2)
    srv.server_close()
    return chunks


class _Sock:
    def __init__(self, b):
        self.b = b

    def makefile(self, *a, **k):
        return io.BytesIO(self.b)


def oracle_servers(stream):
    """Independent parse of every response in a byte stream using stdlib http.client."""
    class Keep(io.BytesIO):          # http.client closes its file after each body; keep ours open
        def close(self):
            pass
    f = Keep(stream)
    banners = []
    while True:
        pos = f.tell()
        if pos >= len(stream):
            break

        class S:
            def makefile(self_, *a, **k):
                return f
        r = http.client.HTTPResponse(S())  # noqa
        try:
            r.begin()
        except Exception:
            break
        banners.append((r.getheader("Server") or "").strip())
        r.read()
    return banners


def frames_for(stream, sizes, fam, isn, order="fwd", seed=1, sport=80, dport=40000):
    segs, off = [], 0
    for s in sizes:
        if off >= len(stream):
            break
        segs.append((off, stream[off:off + s]))
        off += s
    if off < len(stream):
        segs.append((off, stream[off:]))
    if order == "rev":
        segs.reverse()
    elif order == "shuf":
        random.Random(seed).shuffle(segs)
    return [build(d, fam, seq=(isn + o) & 0xFFFFFFFF, sport=sport, dport=dport) for o, d in segs]


cases = [("RomPager/4.07 UPnP/1.0", "HTTP/1.0", "LG-001"),
         ("RomPager/4.07 UPnP/1.0", "HTTP/1.1", "LG-001"),
         ("Allegro-Software-RomPager/4.06", "HTTP/1.0", "LG-001"),
         ("RomPager/4.51 UPnP/1.0", "HTTP/1.0", "LG-003"),
         ("RomPager/5.40", "HTTP/1.1", "LG-003"),
         ("BaseHTTP/0.6 Python/3.12", "HTTP/1.0", None)]
GET = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
for banner, proto, want in cases:
    reqs = [GET] if proto == "HTTP/1.0" else [GET, GET, b"GET /close HTTP/1.1\r\nHost: x\r\n\r\n"]
    chunks = serve_once(handler(banner, proto), reqs)
    stream = b"".join(chunks)
    truth = oracle_servers(stream)
    check("oracle parsed a real response (%s %s)" % (banner, proto), len(truth) >= 1 and truth[0] != "")
    # the real recv() chunk boundaries, then synthetic re-segmentations, forward/reversed/shuffled, both families
    plans = [("recv", [len(c) for c in chunks]), ("mss", [1460] * 50), ("64B", [64] * 200), ("7B", [7] * 600),
             ("1B", [1] * 400), ("whole", [len(stream)])]
    for fam in ("v4", "v6"):
        for pname, sizes in plans:
            for order in ("fwd", "rev", "shuf"):
                got = codes(run_det(frames_for(stream, sizes, fam, (1 << 32) - 50, order)))
                exp = [want] if want else []
                check("%s %s %s %s %s -> %s" % (banner, proto, fam, pname, order, exp), got == exp)
    # banner text matches what http.client independently extracted
    if want:
        out = run_det(frames_for(stream, [len(c) for c in chunks], "v4", 5))
        check("banner equals http.client's Server value (%s)" % banner,
              out and out[0]["banner"].strip() == truth[0])

# retransmission: a lost segment re-sent coalesced with its neighbour, ahead of or behind the original
stream = b"".join(serve_once(handler("RomPager/4.07 UPnP/1.0", "HTTP/1.0"), [GET]))
segs = [(o, stream[o:o + 64]) for o in range(0, len(stream), 64)]
for fam in ("v4", "v6"):
    for k in range(0, min(3, len(segs) - 1)):
        isn = (1 << 32) - 70                                   # the stream wraps inside the head
        mk = lambda off, data: build(data, fam, seq=(isn + off) & 0xFFFFFFFF)       # noqa: E731
        lost = [mk(o, d) for i, (o, d) in enumerate(segs) if i != k]
        co = mk(segs[k][0], segs[k][1] + segs[k + 1][1])
        for label, frs in (("retransmit after", lost + [co]), ("retransmit before", [co] + lost),
                           ("short then long", [mk(*segs[k]), co] + [mk(o, d) for i, (o, d) in enumerate(segs) if i > k + 1])):
            check("%s lost segment %d, coalesced %s -> LG-001" % (fam, k, label), codes(run_det(frs)) == ["LG-001"])

# header spellings an HTTP parser accepts; the oracle says they are all the Server header
variants = [b"server: RomPager/4.07 UPnP/1.0", b"SERVER:RomPager/4.07 UPnP/1.0", b"Server:\tRomPager/4.07",
            b"sErVeR:   RomPager/4.07   ", b"Server: Allegro-Software-RomPager/4.06"]
for v in variants:
    stream = b"HTTP/1.0 200 OK\r\n" + v + b"\r\nContent-Length: 2\r\n\r\nok"
    truth = oracle_servers(stream)
    check("oracle sees Server in %r" % v, truth and "RomPager" in truth[0])
    for fam in ("v4", "v6"):
        got = codes(run_det(frames_for(stream, [20, 20, 20], fam, 77)))
        check("header spelling %r %s -> LG-001" % (v, fam), got == ["LG-001"])

# two responses with different banners on one connection, each in its own segment, are both reported
def resp_cl(server):
    return b"HTTP/1.1 200 OK\r\nServer: " + server + b"\r\nContent-Length: 2\r\n\r\nok"


r1, r2 = resp_cl(b"RomPager/4.07"), resp_cl(b"RomPager/4.51")
stream = r1 + r2
check("oracle agrees the stream holds two banners", oracle_servers(stream) == ["RomPager/4.07", "RomPager/4.51"])
for fam in ("v4", "v6"):
    check("two banners, two segments, %s" % fam,
          codes(run_det(frames_for(stream, [len(r1), len(r2)], fam, 1))) == ["LG-001", "LG-003"])

# =====================================================================================
section("S4 pcap readers")
frames = [build(R407, "v4"), build(R407, "v6", seq=5), build(R434, "v6", seq=9),
          bytes(Ether() / IP(src=V4S, dst=V4C) / UDP() / DNS(rd=1, qd=DNSQR(qname="a.example")))]
with tempfile.TemporaryDirectory() as td:
    pc = os.path.join(td, "t.pcap")
    pkts = [Ether(f) for f in frames]
    for i, p in enumerate(pkts):
        p.time = 1700000000.25 + i * 0.5
    wrpcap(pc, pkts)
    ours = list(lg.read_pcap(pc))
    theirs = rdpcap(pc)
    check("record count equals scapy rdpcap", len(ours) == len(theirs) == len(frames))
    check("frame bytes equal scapy rdpcap", all(o[1] == bytes(t) for o, t in zip(ours, theirs)))
    check("timestamps equal scapy rdpcap (1us)", all(abs(o[0] - float(t.time)) < 2e-6 for o, t in zip(ours, theirs)))
    check("linktype is Ethernet", all(o[2] == 1 for o in ours))
    check("scapy sniff(offline=) sees the same count", len(sniff(offline=pc)) == len(frames))

    # nanosecond pcap, handcrafted (scapy writer is micro) - verify our divisor
    nano = os.path.join(td, "n.pcap")
    with open(nano, "wb") as f:
        import struct
        f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1700000000, 500000000, len(frames[0]), len(frames[0])) + frames[0])
    rec = list(lg.read_pcap(nano))
    check("nanosecond pcap timestamp", rec and abs(rec[0][0] - 1700000000.5) < 1e-6)
    # big-endian pcap
    be = os.path.join(td, "be.pcap")
    with open(be, "wb") as f:
        f.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack(">IIII", 1700000000, 250000, len(frames[0]), len(frames[0])) + frames[0])
    rec = list(lg.read_pcap(be))
    check("big-endian pcap read", rec and abs(rec[0][0] - 1700000000.25) < 1e-6 and rec[0][1] == frames[0])

    # linktypes: every one a carrier is likely to hand us must produce the finding, not silence
    def raw_ip(fam):
        return bytes((IP(src=V4S, dst=V4C) if fam == "v4" else IPv6(src=V6S, dst=V6C))
                     / TCP(sport=80, dport=40000, seq=1, flags="PA") / Raw(R407))

    lt_cases = []
    for fam in ("v4", "v6"):
        lt_cases.append(("ethernet", fam, [Ether(build(R407, fam))]))
        lt_cases.append(("raw-ip", fam, [(IP if fam == "v4" else IPv6)(raw_ip(fam))]))
        proto = 0x0800 if fam == "v4" else 0x86DD
        lt_cases.append(("sll", fam, [CookedLinux(proto=proto) / (IP if fam == "v4" else IPv6)(raw_ip(fam))]))
        if CookedLinuxV2 is not None:
            lt_cases.append(("sll2", fam, [CookedLinuxV2(proto=proto) / (IP if fam == "v4" else IPv6)(raw_ip(fam))]))
    for lname, fam, pk in lt_cases:
        p = os.path.join(td, "lt_%s_%s.pcap" % (lname, fam))
        wrpcap(p, pk)
        r = run_cli("-r", p)
        got = [json.loads(l)["code"] for l in r.stdout.splitlines() if l.strip()]
        check("linktype %s %s -> LG-001 (exit %d)" % (lname, fam, r.returncode), got == ["LG-001"])

    # pcapng must fail LOUDLY and cleanly, never with a traceback and never silently
    try:
        from scapy.utils import PcapNgWriter
        ng = os.path.join(td, "t.pcapng")
        w = PcapNgWriter(ng)
        for p in pkts[:1]:
            w.write(p)
        w.close()
        r = run_cli("-r", ng)
        check("pcapng: non-zero exit", r.returncode != 0)
        check("pcapng: no traceback", "Traceback" not in r.stderr)
        check("pcapng: says what is wrong", "pcap" in r.stderr.lower())
    except ImportError:
        pass
    # a linktype we cannot parse must not produce a silent clean bill of health
    wrpcap(os.path.join(td, "x.pcap"), [Ether(frames[0])], linktype=147)
    r = run_cli("-r", os.path.join(td, "x.pcap"))
    check("unsupported linktype: non-zero exit and message", r.returncode != 0 and r.stderr.strip() != ""
          and "Traceback" not in r.stderr)
    # truncated capture file is tolerated
    data = open(pc, "rb").read()
    tr = os.path.join(td, "trunc.pcap")
    open(tr, "wb").write(data[:-10])
    r = run_cli("-r", tr)
    check("truncated pcap does not crash", r.returncode == 0 and "Traceback" not in r.stderr)
    # empty file
    open(os.path.join(td, "empty.pcap"), "wb").close()
    r = run_cli("-r", os.path.join(td, "empty.pcap"))
    check("empty file fails cleanly", r.returncode != 0 and "Traceback" not in r.stderr)

# =====================================================================================
section("S5 CLI end to end")
RNOVER = resp(b"RomPager")
noise = [Ether() / ARP(),
         Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="x.example")),
         Ether() / IP(src=V4S, dst=V4C) / TCP(sport=80, dport=1, flags="S"),
         Ether() / IP(dst="1.1.1.1") / ICMP(),
         Ether(build(resp(b"Apache/2.4.6"), "v4", sport=80)),
         Ether(build(resp(b"nginx"), "v6", sport=80, seq=3))]
live_pk = [Ether(build(R407, "v4", seq=11)), Ether(build(R407, "v6", seq=12)),
           Ether(build(R434, "v4", seq=13, sport=8080)),
           Ether(build(RNOVER, "v6", seq=14, sport=8080))]
allp = []
for i, p in enumerate(noise[:3] + live_pk + noise[3:]):
    p.time = 1700000000.0 + i
    allp.append(p)
with tempfile.TemporaryDirectory() as td:
    pc = os.path.join(td, "m.pcap")
    wrpcap(pc, allp)
    r = run_cli("-r", pc)
    got = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    check("default port: exactly the two port-80 RomPager findings", [g["code"] for g in got] == ["LG-001", "LG-001"])
    check("families reported", [g["family"] for g in got] == ["ipv4", "ipv6"])
    check("exit 0 and silent stderr", r.returncode == 0 and r.stderr == "")
    want_keys = {"ts", "module", "code", "severity", "family", "server", "client", "port", "banner", "detail",
                 "version", "cve", "note"}
    check("schema keys exact", all(set(g) == want_keys for g in got))
    check("ts equals the pcap packet time", all(abs(g["ts"] - (1700000000.0 + 3 + i)) < 1e-4 for i, g in enumerate(got)))
    check("module name", all(g["module"] == "liebert_guard" for g in got))
    r = run_cli("-r", pc, "-p", "8080")
    got = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    check("-p 8080: LG-003 and LG-002 (RomPager no version) only", [g["code"] for g in got] == ["LG-003", "LG-002"])
    outf = os.path.join(td, "o.jsonl")
    r = run_cli("-r", pc, "-o", outf)
    r2 = run_cli("-r", pc, "-o", outf)
    lines = open(outf).read().splitlines()
    check("-o appends across runs (2 findings x 2 runs)", len(lines) == 4 and all(json.loads(l) for l in lines))
    r = run_cli()
    check("no source -> usage error", r.returncode == 2 and "Traceback" not in r.stderr)
    r = run_cli("-r", pc, "-i", "lo")
    check("-i and -r are mutually exclusive", r.returncode == 2)
    r = run_cli("-r", os.path.join(td, "missing.pcap"))
    check("missing file fails cleanly", r.returncode != 0 and "Traceback" not in r.stderr)
    r = run_cli("-r", pc, "--cooldown", "0")
    got = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    check("--cooldown accepted", r.returncode == 0 and len(got) == 2)


# =====================================================================================
section("S6 request line (LG-101): scapy frames and a real parser")


def REQ(m, ver=b"1.1", eol=b"\r\n"):
    return m + b" /x HTTP/" + ver + eol + b"Host: h" + eol + eol


# (a) scapy-built request frames: methods around the 64 boundary x segmentations x families x encapsulations
for fam in ("v4", "v6"):
    for n in (1, 17, 63, 64, 65, 66, 200):
        stream = REQ(b"A" * n)
        want = ["LG-101"] if n > 64 else []
        for pname, sizes in (("whole", [10 ** 6]), ("2split", [20, 10 ** 6]), ("7B", [7] * 60), ("1B", [1] * 400)):
            for order in ("fwd", "rev", "shuf"):
                got = codes(run_det(frames_for(stream, sizes, fam, (1 << 32) - 30, order, sport=40000, dport=80)))
                check("%s method %d %s %s -> %s" % (fam, n, pname, order, want), got == want)
    raw = build(REQ(b"A" * 70), fam, sport=40000, dport=80, vlans=(7,), qinq=True,
                ext=[IPv6ExtHdrHopByHop(), IPv6ExtHdrDestOpt()] if fam == "v6" else [], pad=20)
    out = run_det([raw])
    check("%s QinQ + padding + extension headers: finding, with the target as server" % fam,
          codes(out) == ["LG-101"] and out[0]["server"] == (V4C if fam == "v4" else V6C)
          and out[0]["client"] == (V4S if fam == "v4" else V6S) and out[0]["detail"] == "method_len=70 sample=" + "A" * 24)
    check("%s scapy dissects the frame the way the module read it (dport 80, our payload)" % fam,
          scapy_view(raw)[4] == 80 and scapy_view(raw)[6] == REQ(b"A" * 70))
    check("%s the server direction of the same bytes is silent" % fam, run_det([build(REQ(b"A" * 70), fam, sport=80, dport=40000)]) == [])


# (b) a REAL request-line parser (http.server) reads the same bytes: its method length decides, we must agree
seen_cmds = []


class _Rec(http.server.BaseHTTPRequestHandler):
    sys_version = ""
    server_version = "Rec"

    def parse_request(self):
        ok = super().parse_request()
        seen_cmds.append(self.command if ok else None)
        return ok

    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if self.raw_requestline and self.parse_request():
                self.send_response(501)
                self.end_headers()
        except OSError:
            pass
        self.close_connection = True

    def log_message(self, *a):
        pass


def real_parse(req):
    seen_cmds.clear()
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Rec)
    th = threading.Thread(target=srv.handle_request, daemon=True)
    th.start()
    c = socket.create_connection(srv.server_address, 5)
    c.sendall(req)
    c.settimeout(5)
    try:
        while c.recv(4096):
            pass
    except socket.timeout:
        pass
    c.close()
    th.join(3)
    srv.server_close()
    return seen_cmds[0] if seen_cmds else None


for n in (1, 3, 8, 16, 17, 40, 63, 64, 65, 66, 100, 500):
    req = REQ(b"X" * n)
    cmd = real_parse(req)
    check("http.server's own parser reads a %d-byte method as %s bytes" % (n, len(cmd) if cmd else cmd), cmd == "X" * n)
    for fam in ("v4", "v6"):
        got = codes(run_det(frames_for(req, [11] * 80, fam, 12345, sport=40000, dport=80)))
        check("%s method %d: module agrees with the real parser (fires iff its length > 64)" % (fam, n),
              (got == ["LG-101"]) == (cmd is not None and len(cmd) > 64))
for m in ("GET", "POST", "UPDATEREDIRECTREF", "BASELINE-CONTROL"):
    cmd = real_parse(REQ(m.encode()))
    check("registered method %s is parsed by http.server as %r and the module is silent" % (m, cmd),
          cmd == m and run_det(frames_for(REQ(m.encode()), [9] * 40, "v4", 1, sport=40000, dport=80)) == [])

# (c) a REAL client writes the request bytes: curl -X with a long and a short method, recorded by a raw server
import shutil as _shutil
shutil_which = _shutil.which("curl")
if shutil_which:
    for n in (10, 64, 65, 120):
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        got_bytes = []

        def serve():
            c, _ = ls.accept()
            c.settimeout(3)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    d = c.recv(4096)
                    if not d:
                        break
                    data += d
            except socket.timeout:
                pass
            got_bytes.append(data)
            c.sendall(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            c.close()
        th = threading.Thread(target=serve, daemon=True)
        th.start()
        subprocess.run([shutil_which, "-s", "-o", "/dev/null", "--max-time", "5", "-X", "Q" * n,
                        "http://127.0.0.1:%d/" % ls.getsockname()[1]], capture_output=True)
        th.join(4)
        ls.close()
        data = got_bytes[0] if got_bytes else b""
        check("curl -X %d-byte method: the recorded request line starts with exactly that method" % n,
              data.startswith(b"Q" * n + b" /"))
        for fam in ("v4", "v6"):
            for pname, sizes in (("whole", [10 ** 6]), ("5B", [5] * 200), ("rev3", [40, 40, 10 ** 6])):
                got = codes(run_det(frames_for(data, sizes, fam, 777, "rev" if pname == "rev3" else "fwd",
                                               sport=40000, dport=80)))
                check("curl %d-byte method, %s %s -> %s" % (n, fam, pname, ["LG-101"] if n > 64 else []),
                      got == (["LG-101"] if n > 64 else []))

# (d) CLI end to end: a request and a response in one capture, v4 and v6
with tempfile.TemporaryDirectory() as td:
    pc = os.path.join(td, "rq.pcap")
    pk = [Ether(build(REQ(b"A" * 70), "v4", seq=1, sport=40000, dport=80)), Ether(build(R407, "v4", seq=2)),
          Ether(build(REQ(b"A" * 70), "v6", seq=3, sport=40001, dport=80)),
          Ether(build(REQ(b"A" * 64), "v6", seq=4, sport=40002, dport=80))]
    for i, p in enumerate(pk):
        p.time = 1700000000.0 + i
    wrpcap(pc, pk)
    r = run_cli("-r", pc)
    got = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    check("CLI over a mixed capture: LG-101 (v4), LG-001, LG-101 (v6); the 64-byte method is silent",
          [g["code"] for g in got] == ["LG-101", "LG-001", "LG-101"] and [g["family"] for g in got] == ["ipv4", "ipv4", "ipv6"])
    check("CLI findings: severity, cve, detail", got[0]["severity"] == "high" and got[0]["cve"] == "CVE-2025-41426"
          and got[0]["detail"] == "method_len=70 sample=" + "A" * 24 and got[1]["detail"] is None)
    r = run_cli("-r", pc, "-p", "8080")
    check("-p 8080 silences both paths", r.returncode == 0 and r.stdout.strip() == "")

# ------------------------------------------------------------------------------------
total_p = sum(v[0] for v in TALLY.values())
total_f = sum(v[1] for v in TALLY.values())
print("scapy %s | liebert_guard v%s scapy self-test" % (scapy.__version__, lg.__version__))
for k, (p_, f_) in TALLY.items():
    print("  %-40s %5d passed %3d failed" % (k, p_, f_))
print("TOTAL %d passed, %d failed" % (total_p, total_f))
sys.exit(1 if total_f else 0)
