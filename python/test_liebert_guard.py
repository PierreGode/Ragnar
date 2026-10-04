#!/usr/bin/env python3
"""liebert_guard verifier. Tier1 classify, Tier2 wire (v4+v6), Tier3 passive proof, Tier4 live loopback,
Tier5 mutation bites. Run: python3 test_liebert_guard.py"""
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

import liebert_guard as lg

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import Ether, IP, IPv6, TCP, Raw, Dot1Q, wrpcap
    from scapy.layers.inet6 import (IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment)
except ImportError:
    sys.exit("scapy required for the test suite (module itself is stdlib-only)")

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def resp(server, body=b"<html></html>", ver="1.1", extra=b""):
    h = b"HTTP/" + ver.encode() + b" 200 OK\r\n"
    if server is not None:
        h += b"Server: " + server + b"\r\n"
    return h + extra + b"Content-Type: text/html\r\n\r\n" + body


V4S, V4C = "10.9.0.5", "10.9.0.77"
V6S, V6C = "2001:db8::5", "2001:db8::77"


def frame(payload, seq=1000, fam="v4", sport=80, dport=40000, vlan=False, ext=(), pad=0):
    e = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    if vlan:
        e = e / Dot1Q(vlan=20)
    if fam == "v4":
        p = e / IP(src=V4S, dst=V4C)
    else:
        p = e / IPv6(src=V6S, dst=V6C)
        for x in ext:
            p = p / x
    p = p / TCP(sport=sport, dport=dport, seq=seq, flags="PA") / Raw(payload)
    return bytes(p) + b"\x00" * pad


def run(frames, **kw):
    out = []
    d = lg.Detector(emit=out.append, **kw)
    for i, f in enumerate(frames):
        d.feed(1000.0 + i, f)
    return out


def codes(out):
    return [f["code"] for f in out]


# ---------------- Tier 1: classify ----------------
table = [
    (b"RomPager/4.07 UPnP/1.0", "LG-001", (4, 7)),
    (b"Allegro-Software-RomPager/4.06", "LG-001", (4, 6)),
    (b"ZyXEL-RomPager/3.02", "LG-001", (3, 2)),
    (b"RomPager/4.33", "LG-001", (4, 33)),
    (b"RomPager/4.34", "LG-003", (4, 34)),
    (b"RomPager/4.51 UPnP/1.0", "LG-003", (4, 51)),
    (b"RomPager/5.40", "LG-003", (5, 40)),
    (b"RomPager/10.2", "LG-003", (10, 2)),      # float compare would call this < 4.34
    (b"rompager/4.07", "LG-001", (4, 7)),       # case-insensitive
    (b"RomPager", "LG-002", None),
    (b"RomPager/abc", "LG-002", None),
    (b"RomPager/4", "LG-002", None),
]
for banner, code, ver in table:
    check("classify %r" % banner, lg.classify(banner) == (code, ver))
for banner in (b"Apache/2.4.6", b"nginx", b"", b"Rom Pager/4.07", b"miniupnpd/1.0"):
    check("classify none %r" % banner, lg.classify(banner) is None)
check("classify accepts str", lg.classify("RomPager/4.07") == ("LG-001", (4, 7)))

# ---------------- Tier 2: wire ----------------
R407 = resp(b"RomPager/4.07 UPnP/1.0")
R434 = resp(b"RomPager/4.34 UPnP/1.0")
RNOVER = resp(b"RomPager")

for fam, S, C in (("v4", V4S, V4C), ("v6", V6S, V6C)):
    o = run([frame(R407, fam=fam)])
    check(fam + " LG-001 fires", codes(o) == ["LG-001"])
    check(fam + " fields", o and o[0]["server"] == S and o[0]["client"] == C
          and o[0]["cve"] == "CVE-2014-9222" and o[0]["severity"] == "critical"
          and o[0]["family"] == ("ipv4" if fam == "v4" else "ipv6") and o[0]["version"] == "4.07")
    check(fam + " LG-002 fires", codes(run([frame(RNOVER, fam=fam)])) == ["LG-002"])
    o = run([frame(R434, fam=fam)])
    check(fam + " LG-003 fires, no LG-001", codes(o) == ["LG-003"] and o[0]["cve"] is None)
    # head split across segments, in order and out of order
    a, b = R407[:30], R407[30:]
    check(fam + " split in-order", codes(run([frame(a, 1000, fam), frame(b, 1000 + len(a), fam)])) == ["LG-001"])
    check(fam + " split out-of-order",
          codes(run([frame(b, 1000 + len(a), fam), frame(a, 1000, fam)])) == ["LG-001"])
    # split mid-"Server:" token
    i = R407.index(b"Server:") + 3
    check(fam + " split mid-token",
          codes(run([frame(R407[:i], 1000, fam), frame(R407[i:], 1000 + i, fam)])) == ["LG-001"])
    # seq wraparound
    s0 = 0xFFFFFFFF - 10
    check(fam + " seq wrap",
          codes(run([frame(a, s0, fam), frame(b, (s0 + len(a)) & 0xFFFFFFFF, fam)])) == ["LG-001"])
    # vlan + ethernet padding
    check(fam + " vlan", codes(run([frame(R407, fam=fam, vlan=True)])) == ["LG-001"])
    check(fam + " eth padding", codes(run([frame(R407, fam=fam, pad=12)])) == ["LG-001"])
    # HTTP/1.0 and extra headers before Server
    check(fam + " http/1.0", codes(run([frame(resp(b"RomPager/4.07", ver="1.0"), fam=fam)])) == ["LG-001"])
    check(fam + " header order",
          codes(run([frame(resp(b"RomPager/4.07", extra=b"Cache-Control: no-cache\r\nSet-Cookie: C0=x\r\n"),
                           fam=fam)])) == ["LG-001"])
    # negatives
    check(fam + " other server", run([frame(resp(b"Apache/2.4.6"), fam=fam)]) == [])
    check(fam + " no server header", run([frame(resp(None), fam=fam)]) == [])
    check(fam + " wrong sport", run([frame(R407, fam=fam, sport=8080)]) == [])
    check(fam + " custom port", codes(run([frame(R407, fam=fam, sport=8080)], port=8080)) == ["LG-001"])
    check(fam + " client->server ignored", run([frame(R407, fam=fam, sport=40000, dport=80)]) == [])
    # banner text only in body must not fire
    body_only = resp(b"Apache/2.4.6", body=b"Server: RomPager/4.07\r\n")
    check(fam + " body text ignored", run([frame(body_only, fam=fam)]) == [])
    # request-looking / garbage payloads
    check(fam + " garbage payload", run([frame(b"\x00\x01garbage", fam=fam)]) == [])
    # dedup + cooldown
    out = []
    d = lg.Detector(cooldown=100, emit=out.append)
    d.feed(0, frame(R407, 1, fam)); d.feed(10, frame(R407, 500, fam)); d.feed(200, frame(R407, 900, fam))
    check(fam + " dedup then re-emit after cooldown", len(out) == 2)
    # same host, banner change -> new finding
    out = []
    d = lg.Detector(emit=out.append)
    d.feed(0, frame(R407, 1, fam)); d.feed(1, frame(R434, 500, fam))
    check(fam + " banner change re-emits", codes(out) == ["LG-001", "LG-003"])

# IPv6 extension headers
for name, ext in (("hbh", [IPv6ExtHdrHopByHop()]),
                  ("dest", [IPv6ExtHdrDestOpt()]),
                  ("hbh+dest", [IPv6ExtHdrHopByHop(), IPv6ExtHdrDestOpt()]),
                  ("frag-first", [IPv6ExtHdrFragment(offset=0, m=0)])):
    check("v6 ext %s" % name, codes(run([frame(R407, fam="v6", ext=ext)])) == ["LG-001"])
check("v6 non-first fragment dropped",
      run([frame(R407, fam="v6", ext=[IPv6ExtHdrFragment(offset=5, m=0)])]) == [])

# robustness: truncated / junk frames never raise
good = frame(R407)
for n in range(0, len(good), 3):
    try:
        run([good[:n]])
        ok = True
    except Exception:
        ok = False
    check("truncated v4 len=%d" % n, ok)
good6 = frame(R407, fam="v6", ext=[IPv6ExtHdrHopByHop()])
for n in range(0, len(good6), 5):
    try:
        run([good6[:n]])
        ok = True
    except Exception:
        ok = False
    check("truncated v6 len=%d" % n, ok)
check("random junk", run([os.urandom(80) for _ in range(200)]) is not None)

# flow table cap
d = lg.Detector(max_flows=8, emit=lambda f: None)
for i in range(50):
    d.feed(0, bytes(Ether() / IP(src="10.1.0.%d" % i, dst=V4C) / TCP(sport=80, dport=1, seq=1) / Raw(b"HTTP/1.1 200 OK\r\nX: ")))
check("flow table capped", len(d.flows) <= 8)

# pcap round trip through the CLI path (v4 + v6 in one file)
with tempfile.TemporaryDirectory() as td:
    pc = os.path.join(td, "t.pcap")
    wrpcap(pc, [Ether(frame(R407)), Ether(frame(R407, fam="v6")), Ether(frame(R434, fam="v6", seq=77))])
    r = subprocess.run([sys.executable, "liebert_guard.py", "-r", pc], capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.abspath(__file__)))
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    check("cli pcap exit 0", r.returncode == 0)
    check("cli pcap 3 findings", len(lines) == 3)
    check("cli pcap json codes", [__import__("json").loads(l)["code"] for l in lines] == ["LG-001", "LG-001", "LG-003"])

# ---------------- LG-101: request line with an oversized method (CVE-2025-41426 shape) ----------------
def REQ(m, ver=b"1.1", eol=b"\r\n"):
    return m + b" /x HTTP/" + ver + eol + b"Host: h" + eol + eol


for fam in ("v4", "v6"):
    for n, want in ((1, []), (8, []), (17, []), (64, []), (65, ["LG-101"]), (66, ["LG-101"]), (200, ["LG-101"])):
        check("LG-101 %s method length %d -> %s" % (fam, n, want),
              codes(run([frame(REQ(b"A" * n), 1000, fam, 40000, 80)])) == want)
    o = run([frame(REQ(b"A" * 70), 1000, fam, 40000, 80)])
    f = o[0] if o else {}
    check("LG-101 %s fields" % fam, f.get("severity") == "high" and f.get("cve") == "CVE-2025-41426"
          and f.get("port") == 80 and f.get("banner") is None and f.get("detail") == "method_len=70 sample=" + "A" * 24
          and f.get("family") == ("ipv4" if fam == "v4" else "ipv6"))
    a, b = REQ(b"A" * 70)[:33], REQ(b"A" * 70)[33:]
    check("LG-101 %s split in order" % fam, codes(run([frame(a, 1000, fam, 40000, 80), frame(b, 1033, fam, 40000, 80)])) == ["LG-101"])
    check("LG-101 %s split reversed" % fam, codes(run([frame(b, 1033, fam, 40000, 80), frame(a, 1000, fam, 40000, 80)])) == ["LG-101"])
    check("LG-101 %s one-byte segments" % fam, codes(run([frame(REQ(b"A" * 70)[i:i + 1], 1000 + i, fam, 40000, 80)
                                                       for i in range(len(REQ(b"A" * 70)))])) == ["LG-101"])
    check("LG-101 %s server direction is silent" % fam, run([frame(REQ(b"A" * 70), 1000, fam, 80, 40000)]) == [])
    check("LG-101 %s normal request is silent" % fam, run([frame(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", 1000, fam, 40000, 80)]) == [])
check("response findings carry detail null", run([frame(R407)])[0]["detail"] is None)

# ---------------- Tier 3: passive proof ----------------
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "liebert_guard.py")).read()
code_only = re.sub(r'"""[\s\S]*?"""', "", src)
for tok in (r"\.send\(", r"\.sendto\(", r"\.sendall\(", r"\.sendmsg\(", r"scapy", r"\bsr1?\(", r"\.connect\(",
            r"\.listen\(", r"\.accept\(", r"subprocess", r"os\.system"):
    check("passive: no %s" % tok, re.search(tok, code_only) is None)

# ---------------- Tier 4: live loopback (needs CAP_NET_RAW) ----------------
def live_case(fam):
    af = socket.AF_INET if fam == "v4" else socket.AF_INET6
    host = "127.0.0.1" if fam == "v4" else "::1"
    srv = socket.socket(af, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    out, stop = [], threading.Event()
    d = lg.Detector(port=port, emit=out.append)
    t = threading.Thread(target=lg.live, args=("lo", d), kwargs={"stop": stop, "idle": 0.1})
    t.start()
    time.sleep(0.4)

    def serve():
        c, _ = srv.accept()
        c.recv(1024)
        c.sendall(resp(b"RomPager/4.07 UPnP/1.0"))
        c.close()
    th = threading.Thread(target=serve)
    th.start()
    cl = socket.socket(af, socket.SOCK_STREAM)
    cl.connect((host, port))
    cl.sendall(b"GET / HTTP/1.0\r\n\r\n")
    cl.recv(4096)
    cl.close()
    th.join()
    time.sleep(0.4)
    stop.set()
    t.join()
    srv.close()
    return codes(out)


LIVE_STATUS = []
for fam in ("v4", "v6"):                         # per family, so one family's skip never hides the other's result
    try:
        got = live_case(fam)
        if got != ["LG-001"]:                    # live checks count only when they FAIL: the documented total must not
            check("live loopback %s -> exactly one LG-001 (got %s)" % (fam, got), False)   # depend on the kernel
        LIVE_STATUS.append("%s ran%s" % (fam, " and passed" if got == ["LG-001"] else " and FAILED"))
    except PermissionError:
        LIVE_STATUS.append("%s SKIPPED (no CAP_NET_RAW)" % fam)
    except OSError as e:
        LIVE_STATUS.append("%s SKIPPED (%s)" % (fam, e))
LIVE = "; ".join(LIVE_STATUS)


# Tier 4b: receive loop through a socketpair stand-in (used when AF_PACKET is unavailable)
def standin(frames):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    real_socket = socket.socket
    out, stop = [], threading.Event()
    d = lg.Detector(emit=out.append)
    socket.socket = lambda *args, **kw: a
    try:
        t = threading.Thread(target=lg.live, args=(None, d), kwargs={"stop": stop, "idle": 0.05})
        t.start()
    finally:
        socket.socket = real_socket
    for f in frames:
        b.send(f)
    time.sleep(0.3)
    stop.set()
    t.join()
    b.close()
    return codes(out), a.fileno() == -1


got, closed = standin([frame(R407), frame(R407, fam="v6", seq=5), frame(R434, fam="v6", seq=9)])
check("live loop stand-in v4+v6 findings", got == ["LG-001", "LG-001", "LG-003"])
check("live loop closes socket on stop", closed)

# ---------------- Tier 5: mutation bites (tests must fail when the code is wrong) ----------------
def bites(name, mutate, probe):
    orig = (lg.classify, lg.parse_frame, lg._parse, lg.FIXED)
    try:
        mutate()
        caught = not probe()
    finally:
        lg.classify, lg.parse_frame, lg._parse, lg.FIXED = orig
    check("bite: %s" % name, caught)


def probe_table():
    return all(lg.classify(b) == (c, v) for b, c, v in table)


def float_compare():
    def c(server):
        r = orig_classify(server)
        if r and r[1]:
            return ("LG-001" if float("%d.%s" % r[1]) < 4.34 else "LG-003"), r[1]
        return r
    lg.classify = c


orig_classify = lg.classify
bites("float version compare", float_compare, probe_table)
bites("fixed boundary 4.35", lambda: setattr(lg, "FIXED", (4, 35)), lambda: lg.classify(b"RomPager/4.34")[0] == "LG-003")
bites("fixed boundary 4.33", lambda: setattr(lg, "FIXED", (4, 33)), lambda: lg.classify(b"RomPager/4.33")[0] == "LG-001")


def probe_ext():
    return codes(run([frame(R407, fam="v6", ext=[IPv6ExtHdrHopByHop(), IPv6ExtHdrDestOpt()])])) == ["LG-001"]


def no_ext_walk():
    real = lg._parse

    def p(buf, lt):
        r = real(buf, lt)
        if r and r[0] == "ipv6" and len(buf) > 14 + 40 + 20 + len(R407) + 8:
            return None
        return r
    lg._parse = p


bites("ipv6 ext-header blind spot", no_ext_walk, probe_ext)


def probe_split():
    a, b = R407[:30], R407[30:]
    return codes(run([frame(a, 1000), frame(b, 1030)])) == ["LG-001"]




real_head = lg.Detector._head
try:
    lg.Detector._head = lambda self, fl: next(
        (d.split(b"\r\n\r\n")[0] for d in fl["segs"].values() if d.startswith(b"HTTP/1.") and b"\r\n\r\n" in d), None)
    check("bite: no-reassembly variant misses split head", not probe_split())
finally:
    lg.Detector._head = real_head

print("liebert_guard v%s: %d passed, %d failed | live tier: %s" % (lg.__version__, PASS, FAIL, LIVE))
sys.exit(1 if FAIL else 0)
