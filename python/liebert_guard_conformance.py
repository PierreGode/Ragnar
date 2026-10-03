#!/usr/bin/env python3
"""liebert_guard conformance harness. Standard library only; drives the PRODUCTION parser and engine.

Sections
  0  harness self-tests            A  structural                 A2 standalone (copy + re-run)
  B  dependency isolation          C  passive invariant (AST)    D  live capture path
  E  frame parser                  F  banner classification      G  reassembly (exhaustive)
  H  robustness / fuzz             I  discrimination + schema    J  clean-set silence
  K  coverage                      L  pcap artefacts + CLI       M  resource bounds
  N  dual-stack parity        O  request line (LG-101)
Hand-rolled builders here pair with the production parser, which cannot catch an error both halves
share; that is the job of liebert_guard_scapy_selftest.py (independent dissector and real HTTP stack).
Run: python3 liebert_guard_conformance.py [-v] [--inner]
"""
import ast
import itertools
import json
import os
import random
import re
import select as lg_select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MODPATH = os.path.join(HERE, "liebert_guard.py")
VERBOSE = "-v" in sys.argv
INNER = "--inner" in sys.argv

import liebert_guard as lg  # noqa: E402

TALLY = OrderedDict()
CUR = ["-"]
OBSERVED = set()          # (code, family) pairs seen from production runs


def section(name):
    CUR[0] = name
    TALLY.setdefault(name, [0, 0])
    if VERBOSE:
        print("--", name)


def check(name, cond):
    TALLY[CUR[0]][0 if cond else 1] += 1
    if not cond:
        print("FAIL[%s]: %s" % (CUR[0], name))


# ------------------------------------------------------------------ builders (stdlib only)
def _a4(s):
    return socket.inet_pton(socket.AF_INET, s)


def _a6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def tcp(sport, dport, seq, payload, doff=5, flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, 0, doff << 4, flags, 65535, 0, 0) \
        + b"\x01" * ((doff - 5) * 4) + payload


def ipv4(src, dst, payload, optwords=0, proto=6, frag=0, total=None):
    ihl = 5 + optwords
    tot = ihl * 4 + len(payload) if total is None else total
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, tot, 0, frag, 64, proto, 0, _a4(src), _a4(dst))
    return hdr + b"\x01" * (optwords * 4) + payload


def ext_chain(types, final_nh=6, hlen=0):
    """Build a valid IPv6 extension chain for `types`; returns (first_nh, bytes)."""
    out, nxt = b"", final_nh
    for t in reversed(types):
        if t in (0, 43, 60):
            blk = bytes([nxt, hlen]) + b"\x00" * ((hlen + 1) * 8 - 2)
        elif t == 44:
            blk = bytes([nxt, 0, 0, 0]) + b"\x00\x00\x00\x01"
        elif t == 51:
            blk = bytes([nxt, 1, 0, 0]) + b"\x00" * 8            # AH: (len+2)*4 = 12 bytes
        else:
            raise ValueError(t)
        out, nxt = blk + out, t
    return nxt, out


def ipv6(src, dst, payload, types=(), plen=None, hlen=0):
    nh, ext = ext_chain(list(types), 6, hlen)
    body = ext + payload
    return struct.pack("!IHBB16s16s", 0x60000000, len(body) if plen is None else plen, nh, 64,
                       _a6(src), _a6(dst)) + body


def eth(et, payload, vlans=(), qinq=False):
    out = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01"
    tags = [0x88A8] * bool(qinq) + [0x8100] * len(vlans)
    for i, tpid in enumerate(tags):
        out += struct.pack("!HH", tpid, 100 + i)         # TPID then TCI
    return out + struct.pack("!H", et) + payload


V4S, V4C, V6S, V6C = "10.9.0.5", "10.9.0.77", "2001:db8::5", "2001:db8::77"


def frame(payload, fam="v4", seq=1000, sport=80, dport=40000, pad=0, vlans=(), qinq=False, optwords=0,
          types=(), doff=5, hlen=0, total=None, frag=0, proto=6, plen=None, lt=1):
    seg = tcp(sport, dport, seq, payload, doff)
    if fam == "v4":
        ip, et = ipv4(V4S, V4C, seg, optwords, proto, frag, total), 0x0800
    else:
        ip, et = ipv6(V6S, V6C, seg, types, plen, hlen), 0x86DD
    if lt == 1:
        return eth(et, ip, vlans, qinq) + b"\x00" * pad
    if lt in (12, 14, 101):
        return ip + b"\x00" * pad
    if lt == 228 or lt == 229:
        return ip + b"\x00" * pad
    if lt == 113:
        return struct.pack("!HHH8sH", 0, 1, 6, b"\x02\x00\x00\x00\x00\x01\x00\x00", et) + ip + b"\x00" * pad
    if lt == 276:
        return struct.pack("!HHIHBB8s", et, 0, 2, 1, 0, 6, b"\x02\x00\x00\x00\x00\x01\x00\x00") + ip + b"\x00" * pad
    raise ValueError(lt)


def resp(server, body=b"<html></html>", ver="1.1", eol=b"\r\n", extra=b""):
    h = b"HTTP/" + ver.encode() + b" 200 OK" + eol
    if server is not None:
        h += b"Server: " + server + eol
    return h + extra + b"Content-Type: text/html" + eol + eol + body


def REQ_(method, uri=b"/", ver=b"1.1", eol=b"\r\n", extra=b""):
    return method + b" " + uri + b" HTTP/" + ver + eol + b"Host: 10.9.0.5" + eol + extra + eol


def run(frames, lt=1, ts0=1000.0, **kw):
    out = []
    d = lg.Detector(emit=out.append, **kw)
    for i, f in enumerate(frames):
        d.feed(ts0 + i, f, lt)
    for f in out:
        OBSERVED.add((f["code"], f["family"]))
    return out


def codes_of(out):
    return [f["code"] for f in out]          # parse the FIELD, never grep the prose (LESSON I)


def split_frames(stream, cuts, fam="v4", isn=1000, order=None, sport=80, dport=40000):
    pts = [0] + list(cuts) + [len(stream)]
    segs = [(pts[i], stream[pts[i]:pts[i + 1]]) for i in range(len(pts) - 1)]
    if order is not None:
        segs = [segs[i] for i in order]
    return [frame(d, fam, seq=(isn + o) & 0xFFFFFFFF, sport=sport, dport=dport) for o, d in segs]


# ------------------------------------------------------------------ AST guards (self-tested in section 0)
BANNED_BARE = {"send", "sendp", "sendpfast", "sendto", "sr", "sr1", "srp", "srp1", "pcap_sendpacket"}
BANNED_ATTR = {"send", "sendto", "sendall", "sendmsg", "sendfile", "connect", "connect_ex", "listen", "accept"}
BANNED_IMPORTS = {"scapy", "subprocess", "urllib", "http", "requests", "smtplib", "ftplib", "telnetlib",
                  "ssl", "ctypes", "os", "multiprocessing"}
STDLIB_ALLOWED = {"argparse", "json", "re", "socket", "struct", "sys", "time", "collections", "select"}


def passive_violations(src):
    tree = ast.parse(src)
    local = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    v = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            v += ["import " + a.name for a in n.names if a.name.split(".")[0] in BANNED_IMPORTS]
        elif isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] in BANNED_IMPORTS:
            v.append("from " + n.module)
        elif isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name) and f.id in BANNED_BARE and f.id not in local:
                v.append("call " + f.id)
            elif isinstance(f, ast.Attribute):
                if f.attr in BANNED_ATTR:
                    v.append("call ." + f.attr)
                if isinstance(f.value, ast.Name) and f.value.id in ("subprocess", "os"):
                    v.append("call %s.%s" % (f.value.id, f.attr))
                if f.attr == "socket" and isinstance(f.value, ast.Name) and f.value.id == "socket":
                    a0 = n.args[0] if n.args else None
                    if not (isinstance(a0, ast.Attribute) and a0.attr == "AF_PACKET"):
                        v.append("socket not AF_PACKET")
                if f.attr == "setsockopt":
                    a0 = n.args[0] if n.args else None
                    if not (isinstance(a0, ast.Constant) and a0.value == 263):
                        v.append("setsockopt not SOL_PACKET")
    return v


def unused_imports(src):
    tree = ast.parse(src)
    imported = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                imported[(a.asname or a.name).split(".")[0]] = n
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                imported[a.asname or a.name] = n
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    return sorted(set(imported) - used)


def duplicate_defs(src):
    seen, dup = set(), set()
    for n in ast.parse(src).body:
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
            (dup if n.name in seen else seen).add(n.name)
    return sorted(dup)


def code_constants(src, rx=r"^LG-\d{3}$"):
    return {n.value for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and re.match(rx, n.value)}


def code_only(node):
    """Unparse an AST node with every docstring removed, so guards scan code and never prose."""
    node = ast.parse(ast.unparse(node))
    for n in ast.walk(node):
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef)) and n.body and isinstance(n.body[0], ast.Expr) \
                and isinstance(n.body[0].value, ast.Constant) and isinstance(n.body[0].value.value, str):
            n.body = n.body[1:] or [ast.Pass()]
    return ast.unparse(node)


def module_imports(src):
    roots = set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import):
            roots |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            roots.add((n.module or "").split(".")[0])
    return roots


SRC = open(MODPATH).read()

# =====================================================================================
section("0 harness self-tests")
import contextlib  # noqa: E402
import io  # noqa: E402

CUR[0] = "_probe"
TALLY["_probe"] = [0, 0]
check("probe", True)
with contextlib.redirect_stdout(io.StringIO()) as _buf:
    check("probe-fail", False)
_probe = list(TALLY["_probe"])
del TALLY["_probe"]
CUR[0] = "0 harness self-tests"
check("check() counts a pass and a failure separately", _probe == [1, 1])
check("check() prints the failing name", "probe-fail" in _buf.getvalue())

f_ = frame(resp(b"RomPager/4.07"))
p_ = lg.parse_frame(f_)
check("builder v4 total length field is right", struct.unpack_from("!H", f_, 16)[0] == len(f_) - 14)
check("builder frames parse", p_ is not None and p_[3:6] == (80, 40000, 1000))
f6_ = frame(resp(b"RomPager/4.07"), "v6", types=(0, 60))
check("builder v6 frame parses through a 2-deep chain", lg.parse_frame(f6_) is not None)
check("builder ext chain sizes: hbh=8, hlen1=16, frag=8, ah=12",
      [len(ext_chain([t], 6, h)[1]) for t, h in ((0, 0), (0, 1), (44, 0), (51, 0))] == [8, 16, 8, 12])
_wf = split_frames(b"A" * 20, [10], "v4", (1 << 32) - 10)
check("wrap fixture really crosses 2**32 (first seq 2**32-10, second seq 0)",
      [lg.parse_frame(x)[5] for x in _wf] == [(1 << 32) - 10, 0])
check("run() records observed (code,family)", run([f_]) and ("LG-001", "ipv4") in OBSERVED)
check("codes_of reads the field not the prose",
      codes_of([{"code": "LG-001", "note": "mentions LG-003 and LG-002"}]) == ["LG-001"])

g = passive_violations
check("guard bites: s.send()", g("s.send(b'x')") == ["call .send"])
check("guard bites: sock.sendto()", "call .sendto" in g("sock.sendto(b'x', a)"))
check("guard bites: bare sendp()", g("sendp(x)") == ["call sendp"])
check("guard bites: bare sr1()", g("sr1(x)") == ["call sr1"])
check("guard: a LOCAL function named run() is not subprocess.run (LESSON D)",
      g("def run():\n    pass\nrun()") == [])
check("guard: a LOCAL function named send() is not a transmit", g("def send(x):\n    return x\nsend(1)") == [])
check("guard bites: subprocess.run", g("import subprocess\nsubprocess.run(['x'])") != [])
check("guard bites: os.system", "call os.system" in g("import os\nos.system('x')"))
check("guard bites: scapy import", g("import scapy.all") != [] and g("from scapy.all import sendp") != [])
check("guard bites: connect/listen/accept", all(g("s.%s()" % m) for m in ("connect", "listen", "accept")))
check("guard bites: AF_INET socket", "socket not AF_PACKET" in g("import socket\nsocket.socket(socket.AF_INET, 1)"))
check("guard allows AF_PACKET socket",
      g("import socket\nsocket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)") == [])
check("guard bites: setsockopt with another level", "setsockopt not SOL_PACKET" in g("s.setsockopt(1, 2, b'')"))
check("guard allows SOL_PACKET membership", g("s.setsockopt(263, 1, b'')") == [])
check("guard: file.write is not a transmit", g("f.write('x')") == [])
check("clean synthetic source passes", g("import re\nx = re.compile('a')") == [])

check("unused-import detector bites", unused_imports("import os\nimport re\nre.compile('a')") == ["os"])
check("unused-import detector quiet on clean", unused_imports("import re\nre.compile('a')") == [])
check("unused-import: attribute use counts", unused_imports("import socket\nsocket.AF_INET") == [])
check("duplicate-def detector bites", duplicate_defs("def a():\n pass\ndef a():\n pass") == ["a"])
check("duplicate-def detector quiet", duplicate_defs("def a():\n pass\ndef b():\n pass") == [])
check("code extractor: dict keys", code_constants("d = {'LG-001': 1, 'LG-002': 2}") == {"LG-001", "LG-002"})
check("code extractor: ternary", code_constants("c = ('LG-001' if x else 'LG-003')") == {"LG-001", "LG-003"})
check("code extractor: tuple return", code_constants("def f():\n    return 'LG-002', None") == {"LG-002"})
check("code extractor: ignores prose", code_constants("x = 'see LG-001 for details'") == set())
check("code_only strips docstrings but keeps code",
      "sockets" not in code_only(ast.parse("class A:\n    \"\"\"no sockets\"\"\"\n    x = 1")) and
      "x = 1" in code_only(ast.parse("class A:\n    \"\"\"no sockets\"\"\"\n    x = 1")))
check("code_only keeps a call to socket", "socket" in code_only(ast.parse("def f():\n    \"\"\"d\"\"\"\n    socket.socket()")))
check("module_imports finds function-level imports", module_imports("def f():\n    import select\n") == {"select"})

# =====================================================================================
section("A structural")
check("module compiles", compile(SRC, MODPATH, "exec") is not None)
check("version string", re.match(r"^\d+\.\d+\.\d+(-dev)?$", lg.__version__) is not None)
for name in ("classify", "parse_frame", "Detector", "read_pcap", "live", "main", "SEVERITY", "NOTES", "FIXED",
             "CVE", "CVES", "SUPPORTED_LINKTYPES"):
    check("public name " + name, hasattr(lg, name))
tree = ast.parse(SRC)
flags = set()
for n in ast.walk(tree):
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "add_argument":
        flags |= {a.value for a in n.args if isinstance(a, ast.Constant) and isinstance(a.value, str)}
check("CLI flag set is exactly the documented one",
      flags == {"-i", "--iface", "-r", "--pcap", "-p", "--port", "--cooldown", "--promisc", "-o", "--out"})
declared = code_constants(SRC)
check("declared codes are exactly LG-001..003 and LG-101", declared == {"LG-001", "LG-002", "LG-003", "LG-101"})
check("NOTES keys == SEVERITY keys == declared", set(lg.NOTES) == set(lg.SEVERITY) == declared)
check("severity vocabulary, and LG-101 is capped below critical (an attempt detector, LESSON T)",
      set(lg.SEVERITY.values()) <= {"critical", "high", "low", "info"} and lg.SEVERITY["LG-001"] == "critical"
      and lg.SEVERITY["LG-101"] == "high")
check("every note is substantive", all(len(v) > 40 for v in lg.NOTES.values()))
check("LG-001 note states the banner limitation and the fixed firmware",
      "banner" in lg.NOTES["LG-001"].lower() and "4.D40.1" in lg.NOTES["LG-001"]
      and "cookie" in lg.NOTES["LG-001"].lower())
check("CVE id well formed and fixed boundary", re.match(r"^CVE-\d{4}-\d{4,}$", lg.CVE) and lg.FIXED == (4, 34))
check("CVES maps exactly LG-001 and LG-101, to the right ids",
      lg.CVES == {"LG-001": "CVE-2014-9222", "LG-101": "CVE-2025-41426"} and lg.CVES["LG-001"] == lg.CVE)
check("LG-101 note states it is an attempt detector and names the affected and fixed versions",
      all(w in lg.NOTES["LG-101"] for w in ("attempt", "RDU101", "1.9.1.2", "IS-UNITY", "8.4.3.1", "does not show")))
check("MAX_METHOD is 64 and MAX_REQ is 8192", lg.Detector.MAX_METHOD == 64 and lg.Detector.MAX_REQ == 8192)
doc = ast.get_docstring(tree) or ""
check("module docstring documents every code", all(c in doc for c in declared))
check("no kernel BPF / pcap compile in the module's CODE (LESSON AE: filtering is in-process)",
      not re.search(r"setfilter|pcap_compile|attach_filter|SO_ATTACH_FILTER|tcp port|BPF filter", code_only(tree), re.I))
check("supported linktypes", set(lg.SUPPORTED_LINKTYPES) == {1, 12, 14, 101, 113, 228, 229, 276})

# =====================================================================================
section("A2 standalone")
if INNER:
    check("inner run: standalone section skipped to stop recursion", True)
else:
    with tempfile.TemporaryDirectory() as td:
        shutil.copy(MODPATH, td)
        shutil.copy(os.path.abspath(__file__), td)
        r = subprocess.run([sys.executable, "-E", os.path.join(td, os.path.basename(__file__)), "--inner"],
                           capture_output=True, text=True, cwd=td)
        check("copy of module+harness in an empty dir passes", r.returncode == 0 and " 0 failed" in r.stdout)
        check("...with no scapy or third-party import", "Traceback" not in r.stderr)

# =====================================================================================
section("B dependency isolation")
imps = module_imports(SRC)
check("imports are stdlib-only and allow-listed: %s" % sorted(imps), imps <= STDLIB_ALLOWED)
check("no module-scope scapy import", not any(
    isinstance(n, (ast.Import, ast.ImportFrom)) and "scapy" in ast.dump(n) for n in tree.body))
check("no unused imports", unused_imports(SRC) == [])
check("no duplicate module-level defs", duplicate_defs(SRC) == [])
check("importing the module pulls in no scapy", "scapy" not in sys.modules)

# =====================================================================================
section("C passive invariant")
viol = passive_violations(SRC)
check("module has no transmit, process, network-client or scapy construct: %s" % viol, viol == [])
socks = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
         and n.func.attr == "socket" and isinstance(n.func.value, ast.Name) and n.func.value.id == "socket"]
check("exactly one socket is ever created", len(socks) == 1)
check("...and it is AF_PACKET/SOCK_RAW", socks and "AF_PACKET" in ast.dump(socks[0]) and "SOCK_RAW" in ast.dump(socks[0]))
opts = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "setsockopt"]
check("the only setsockopt is PACKET_ADD_MEMBERSHIP (receive-side promisc)",
      len(opts) == 1 and isinstance(opts[0].args[0], ast.Constant) and opts[0].args[0].value == 263
      and isinstance(opts[0].args[1], ast.Constant) and opts[0].args[1].value == 1)
_det_cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Detector")
_det_src = code_only(_det_cls)
check("Detector class touches no socket, select, file or process API",
      not re.search(r"socket|select|open\(|subprocess", _det_src))
check("Detector default emit is stdout JSON only", "print(json.dumps(f), flush=True)" in SRC)

# =====================================================================================
section("D live capture path")


class Rec:
    def __init__(self, frames):
        self.frames, self.calls, self.closed = list(frames), [], 0

    def fileno(self):
        return 99

    def bind(self, a):
        self.calls.append(("bind", a))

    def setsockopt(self, *a):
        self.calls.append(("setsockopt",) + a)

    def recv(self, n):
        self.calls.append(("recv", n))
        return self.frames.pop(0)

    def close(self):
        self.closed += 1


def drive(frames, iface=None, promisc=False, det=None, pass_stop=True):
    rec = Rec(frames)
    stop = threading.Event()
    made = []
    real_sock, real_sel, real_idx = socket.socket, lg_select.select, socket.if_nametoindex

    def fake_select(r, w, x, t):
        if rec.frames:
            return [rec], [], []
        stop.set()
        return [], [], []
    socket.socket = lambda *a, **k: (made.append(a), rec)[1]
    lg_select.select = fake_select
    socket.if_nametoindex = lambda n: 7
    out = []
    d = det or lg.Detector(emit=out.append)
    err = None
    try:
        lg.live(iface, d, promisc, stop=stop if pass_stop else None, idle=0.01)
    except Exception as e:                      # noqa: BLE001
        err = e
    finally:
        socket.socket, lg_select.select, socket.if_nametoindex = real_sock, real_sel, real_idx
    return rec, made, out, err


rec, made, out, err = drive([frame(resp(b"RomPager/4.07")), frame(resp(b"RomPager/4.51"), "v6", seq=9)],
                            iface="eth9")
check("live: opens AF_PACKET/SOCK_RAW/ETH_P_ALL",
      made == [(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))])
check("live: binds the requested interface", ("bind", ("eth9", 0)) in rec.calls)
check("live: no promisc unless asked", not any(c[0] == "setsockopt" for c in rec.calls))
check("live: reads with a 65535 buffer", [c for c in rec.calls if c[0] == "recv"] == [("recv", 65535)] * 2)
check("live: drove the real engine, v4+v6 findings", codes_of(out) == ["LG-001", "LG-003"])
check("live: closes its socket exactly once", rec.closed == 1)
check("live: loop ended without error", err is None)
rec, made, out, err = drive([], iface="eth9", promisc=True)
check("live: --promisc issues PACKET_ADD_MEMBERSHIP(ifindex, PACKET_MR_PROMISC)",
      ("setsockopt", 263, 1, struct.pack("iHH8s", 7, 1, 0, b"")) in rec.calls)
rec, made, out, err = drive([], iface=None)
check("live: no iface -> no bind", not any(c[0] == "bind" for c in rec.calls))


class Boom(lg.Detector):
    def feed(self, *a, **k):
        raise RuntimeError("boom")


rec, made, out, err = drive([frame(resp(b"RomPager/4.07"))], iface="eth9", det=Boom(emit=lambda f: None))
check("live: an engine exception propagates", isinstance(err, RuntimeError))
check("live: ...and the socket is still closed (finally)", rec.closed == 1)
rec, made, out, err = drive([b"\x00" * 20, os.urandom(64), frame(resp(b"RomPager/4.07"))], iface="eth9")
check("live: junk frames between real ones do not stop the loop", codes_of(out) == ["LG-001"])
check("live passes timestamps from the wall clock (float)", all(isinstance(f["ts"], float) for f in out))

# =====================================================================================
section("E frame parser")
S = resp(b"RomPager/4.07")


def view(fr, lt=1):
    p = lg.parse_frame(fr, lt)
    return None if p is None else (p[0], p[1], p[2], p[3], p[4], p[5], p[6])


check("v4 canonical fields", view(frame(S)) == ("ipv4", V4S, V4C, 80, 40000, 1000, S))
check("v6 canonical fields", view(frame(S, "v6")) == ("ipv6", V6S, V6C, 80, 40000, 1000, S))
for ow in range(0, 11):
    check("v4 IHL %d" % (5 + ow), view(frame(S, optwords=ow))[6] == S)
for pad in (0, 1, 7, 18, 40, 1500):
    check("v4 eth padding %d trimmed by IP total length" % pad, view(frame(S, pad=pad))[6] == S)
    check("v6 eth padding %d trimmed by payload length" % pad, view(frame(S, "v6", pad=pad))[6] == S)
check("v4 total length beyond captured bytes -> what is present (snaplen)",
      view(frame(S, total=4000))[6] == S)
check("v4 DF flag ignored", view(frame(S, frag=0x4000))[6] == S)
check("v4 first fragment (MF, offset 0) parses", view(frame(S, frag=0x2000))[6] == S)
check("v4 non-first fragment rejected", view(frame(S, frag=0x0005)) is None and view(frame(S, frag=0x2005)) is None)
check("v4 non-TCP rejected", all(view(frame(S, proto=p)) is None for p in (1, 17, 47, 50, 132)))
check("non-IP ethertype rejected", lg.parse_frame(eth(0x0806, b"\x00" * 40)) is None)
for nv in (1, 2, 3, 4):
    check("vlan depth %d" % nv, view(frame(S, vlans=(5,) * nv))[6] == S)
check("qinq (0x88a8 outer)", view(frame(S, vlans=(5,), qinq=True))[6] == S)
for dof in range(5, 16):
    check("tcp data offset %d" % dof, view(frame(S, doff=dof))[6] == S)
check("tcp data offset < 5 rejected", lg.parse_frame(frame(S, doff=4)) is None)
for seq in (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
    check("seq extreme %d" % seq, view(frame(S, seq=seq))[5] == seq)
for port in (0, 1, 80, 8080, 65535):
    check("port extreme %d" % port, view(frame(S, sport=port, dport=port))[3:5] == (port, port))
check("tcp with no payload -> empty payload", view(frame(b""))[6] == b"")

for lt in (1, 12, 14, 101, 113, 276):
    for fam in ("v4", "v6"):
        check("linktype %d %s equals ethernet parse" % (lt, fam), view(frame(S, fam, lt=lt), lt) == view(frame(S, fam)))
check("linktype 228 carries IPv4", view(frame(S, "v4", lt=228), 228) == view(frame(S, "v4")))
check("linktype 229 carries IPv6", view(frame(S, "v6", lt=229), 229) == view(frame(S, "v6")))
check("linktype 228 refuses to parse IPv6 bytes as IPv4 (declared family wins)",
      view(frame(S, "v6", lt=228), 228) is None)
check("raw-ip with a bad version nibble rejected", lg.parse_frame(b"\x55" + b"\x00" * 60, 101) is None)
check("unknown linktype rejected", lg.parse_frame(frame(S), 147) is None)

# every extension-header chain of length 0..3 over {HBH, ROUTING, DEST, FRAG, AH}
n_chain = 0
for k in range(0, 4):
    for chain in itertools.product((0, 43, 60, 44, 51), repeat=k):
        for hl in (0, 2):
            n_chain += 1
            v = view(frame(S, "v6", types=chain, hlen=hl))
            if not (v and v[6] == S and v[3:6] == (80, 40000, 1000)):
                check("v6 chain %s hlen %d" % (chain, hl), False)
check("v6 extension chains (all %d of length<=3 x 2 sizes) parse" % n_chain, True)
check("v6 chain of 8 headers parses", view(frame(S, "v6", types=(0,) * 8))[6] == S)
check("v6 chain of 9 headers is refused (documented bound of 8)", view(frame(S, "v6", types=(0,) * 9)) is None)
nf = bytearray(frame(S, "v6", types=(44,)))
nf[14 + 40 + 2:14 + 40 + 4] = struct.pack("!H", 5 << 3)           # fragment offset 5
check("v6 non-first fragment refused", lg.parse_frame(bytes(nf)) is None)
check("v6 payload length 0 (jumbogram) falls back to captured length",
      view(frame(S, "v6", plen=0))[6] == S)
_udp6 = struct.pack("!IHBB16s16s", 0x60000000, 30, 17, 64, _a6(V6S), _a6(V6C)) + b"\x00" * 30
check("v6 non-TCP next header refused", lg.parse_frame(eth(0x86DD, _udp6)) is None)

# =====================================================================================
section("F banner classification")
bad = []
for minor in range(100):
    for fmt in ("%02d", "%d"):
        b = ("RomPager/4." + fmt % minor).encode()
        want = "LG-001" if minor < 34 else "LG-003"
        if lg.classify(b) != (want, (4, minor)):
            bad.append(b)
check("every RomPager/4.00..4.99 (padded and unpadded) classified on the 4.34 boundary: %s" % bad[:3], not bad)
bad = [(M, m) for M in range(0, 13) for m in (0, 1, 33, 34, 99)
       if lg.classify(("RomPager/%d.%d" % (M, m)).encode()) != (("LG-001" if (M, m) < (4, 34) else "LG-003"), (M, m))]
check("major sweep 0..12 x minor {0,1,33,34,99} tuple-ordered: %s" % bad[:3], not bad)
check("4.34.1 -> 4.34 -> LG-003", lg.classify(b"RomPager/4.34.1") == ("LG-003", (4, 34)))
check("4.07.2 -> LG-001", lg.classify(b"RomPager/4.07.2") == ("LG-001", (4, 7)))
check("leading zeros 004.007", lg.classify(b"RomPager/004.007") == ("LG-001", (4, 7)))
check("absurdly large version stays LG-003", lg.classify(b"RomPager/99999999999999999999.1")[0] == "LG-003")
check("vendor prefixes", all(lg.classify(p + b"RomPager/4.07")[0] == "LG-001"
                             for p in (b"Allegro-Software-", b"ZyXEL-", b"TP-LINK-", b"X.", b" ", b"")))
check("trailing tokens do not matter", lg.classify(b"RomPager/4.07 UPnP/1.0 foo/1.2")[1] == (4, 7))
check("case-insensitive", lg.classify(b"ROMPAGER/4.07")[0] == "LG-001" and lg.classify(b"rompager/4.34")[0] == "LG-003")
check("'RomPager /4.07' (space before slash): present, version unparseable -> LG-002",
      lg.classify(b"RomPager /4.07") == ("LG-002", None))
check("'RomPager 4.07' (no slash) -> LG-002", lg.classify(b"RomPager 4.07") == ("LG-002", None))
check("bare RomPager -> LG-002", lg.classify(b"RomPager") == ("LG-002", None))
check("RomPager/ with nothing -> LG-002", lg.classify(b"RomPager/") == ("LG-002", None))
check("token boundary: mod_rompager / XRomPager / notrompager are not RomPager",
      all(lg.classify(b) is None for b in (b"mod_rompager/4.07", b"XRomPager/4.07", b"notrompager", b"1rompager/4.07")))
check("token boundary: '-', '.', ' ', '/', '(' ahead of the name do count",
      all(lg.classify(p + b"RomPager/4.07") for p in (b"-", b".", b" ", b"/", b"(")))
check("str and bytes agree", lg.classify("RomPager/4.07") == lg.classify(b"RomPager/4.07"))
check("non-ASCII bytes in the banner do not raise", lg.classify(b"RomPager/4.07 \xff\xfe") == ("LG-001", (4, 7)))
check("empty banner -> None", lg.classify(b"") is None)

# =====================================================================================
section("G reassembly (exhaustive)")
HEAD = resp(b"RomPager/4.07 UPnP/1.0", body=b"")
N = len(HEAD)
miss = [i for i in range(1, N) if codes_of(run(split_frames(HEAD, [i]))) != ["LG-001"]]
check("every single split point (%d) in order" % (N - 1), not miss)
miss = [i for i in range(1, N) if codes_of(run(split_frames(HEAD, [i], order=[1, 0]))) != ["LG-001"]]
check("every single split point reversed (anchor must tolerate a late head segment)", not miss)
miss = [(i, off, fam) for i in range(1, N) for off in (-1, 0, 1) for fam in ("v4", "v6")
        if codes_of(run(split_frames(HEAD, [i], fam, ((1 << 32) - i + off) & 0xFFFFFFFF))) != ["LG-001"]]
check("every split point x wrap exactly at / one before / one after the cut x v4+v6: %s" % miss[:3], not miss)
for seed in range(200):
    rng = random.Random(900 + seed)
    cuts = sorted(rng.sample(range(1, N), rng.randint(1, 6)))
    order = list(range(len(cuts) + 1))
    rng.shuffle(order)
    fam = ("v4", "v6")[seed % 2]
    if codes_of(run(split_frames(HEAD, cuts, fam, (1 << 32) - rng.randint(1, N), order))) != ["LG-001"]:
        check("random wrap case %d" % seed, False)
check("200 random multi-segment shuffles that cross 2**32", True)
miss = []
cnt = 0
for i, j in itertools.combinations(range(1, N), 2):
    for order in itertools.permutations(range(3)):
        cnt += 1
        if codes_of(run(split_frames(HEAD, [i, j], order=list(order)))) != ["LG-001"]:
            miss.append((i, j, order))
check("every pair of split points x all 6 arrival orders (%d cases) misses: %s" % (cnt, miss[:2]), not miss)
miss = [o for o in itertools.permutations(range(5))
        if codes_of(run(split_frames(HEAD, [10, 30, 50, 70], order=list(o)))) != ["LG-001"]]
check("five segments, all 120 orders", not miss)
miss = [k for k in range(1, N + 1) if codes_of(run(split_frames(HEAD, list(range(k, N, k))))) != ["LG-001"]]
check("fixed-size chunking at every size 1..%d" % N, not miss)
miss = [k for k in range(1, N + 1) if codes_of(run(split_frames(HEAD, list(range(k, N, k)), order=
                                                              list(reversed(range(len(range(0, N, k)))))))) != ["LG-001"]]
check("fixed-size chunking reversed at every size", not miss)
for seed in range(40):
    rng = random.Random(seed)
    cuts = sorted(rng.sample(range(1, N), rng.randint(1, 10)))
    order = list(range(len(cuts) + 1))
    rng.shuffle(order)
    if codes_of(run(split_frames(HEAD, cuts, order=order))) != ["LG-001"]:
        check("shuffle seed %d" % seed, False)
check("40 seeded random shuffles", True)

fr = split_frames(HEAD, [30, 60])
check("every segment duplicated (retransmission)", codes_of(run([x for f in fr for x in (f, f)])) == ["LG-001"])
check("whole stream replayed twice -> one finding (dedup)", codes_of(run(fr + fr)) == ["LG-001"])
check("missing middle segment -> no finding, no crash", run([fr[0], fr[2]]) == [])
d_ = lg.Detector(emit=(o_ := []).append)
for i, f in enumerate([fr[0], fr[2], fr[1]]):
    d_.feed(1000.0 + i, f)
check("late arrival of the missing segment completes the head exactly once", codes_of(o_) == ["LG-001"])
for fam in ("v4", "v6"):
    fr2 = split_frames(HEAD, [30, 60], fam)
    big = frame(HEAD[:60], fam, seq=1000)                 # coalesced retransmit of segments 0+1 at seg 0's seq
    check("%s: short segment, then a longer retransmit of the same range (middle segment was lost)" % fam,
          codes_of(run([fr2[0], big, fr2[2]])) == ["LG-001"])
    check("%s: longer segment first, then a shorter duplicate of its start (must not shrink it)" % fam,
          codes_of(run([big, fr2[0], fr2[2]])) == ["LG-001"])
    check("%s: longer segment alone plus the tail (no duplicate at all)" % fam, codes_of(run([big, fr2[2]])) == ["LG-001"])
    check("%s: identical duplicates are a no-op" % fam, codes_of(run([fr2[0], fr2[0], fr2[1], fr2[1], fr2[2]])) == ["LG-001"])
a_, b_ = frame(HEAD, seq=1000), frame(HEAD, seq=1000, sport=80, dport=40001)
check("dedup is per server: two clients of one server -> one finding",
      codes_of(run([a_, b_])) == ["LG-001"])
f1 = split_frames(HEAD, [40], isn=100)
f2 = [frame(d, seq=s, dport=41000) for s, d in ((100, HEAD[:40]), (140, HEAD[40:]))]
check("interleaved flows reassemble independently", codes_of(run([f1[0], f2[0], f2[1], f1[1]], cooldown=0)) == ["LG-001"] * 2)
body_first = frame(b"\x00" * 50 + b"junk", seq=500)
check("non-HTTP segments before the head are ignored", codes_of(run([body_first, frame(HEAD, seq=9000)])) == ["LG-001"])
check("continuation bytes of an earlier body do not fire",
      run([frame(b"Server: RomPager/4.07\r\n\r\n", seq=77)]) == [])
two = resp(b"RomPager/4.07", body=b"x" * 20) + resp(b"RomPager/4.51")
cut = len(resp(b"RomPager/4.07", body=b"x" * 20))
check("second response in its own later segment is examined", codes_of(run(split_frames(two, [cut]))) == ["LG-001", "LG-003"])
check("PINNED LIMIT: a second response coalesced into the SAME segment is not examined",
      codes_of(run(split_frames(two, []))) == ["LG-001"])
for eol_name, eol in (("CRLF", b"\r\n"), ("bare LF", b"\n")):
    r_ = resp(b"RomPager/4.07", eol=eol)
    check("head terminated by %s" % eol_name, codes_of(run([frame(r_)])) == ["LG-001"])
    check("head terminated by %s, split mid-token" % eol_name,
          codes_of(run(split_frames(r_, [r_.index(b"Server") + 4, r_.index(b"Server") + 20]))) == ["LG-001"])
mixed = b"HTTP/1.0 200 OK\r\nServer: RomPager/4.07\n\r\nbody"
check("mixed CRLF/LF terminator (\\n\\r\\n)", codes_of(run([frame(mixed)])) == ["LG-001"])
check("HTTP/1.0 and 1.1 status lines", all(codes_of(run([frame(resp(b"RomPager/4.07", ver=v))])) == ["LG-001"]
                                           for v in ("1.0", "1.1")))
check("HTTP/2 or garbage status line is not a response head", run([frame(b"HTTP/2 200\r\nServer: RomPager/4.07\r\n\r\n")]) == [])
big = b"HTTP/1.1 200 OK\r\nServer: RomPager/4.07\r\n" + b"X-Pad: " + b"a" * 9000 + b"\r\n\r\n"
check("head over the 8 KiB cap is still inspected up to the cap", codes_of(run(split_frames(big, [1000, 3000, 6000, 9000]))) == ["LG-001"])
check("head with no terminator and no Server header produces nothing and no crash",
      run(split_frames(b"HTTP/1.1 200 OK\r\n" + b"a" * 20000, list(range(1000, 20000, 1000)))) == [])

# =====================================================================================
section("H robustness / fuzz")
base4, base6 = frame(S), frame(S, "v6", types=(0, 60))
bad = []
for nm, fr0 in (("v4", base4), ("v6+ext", base6), ("vlan", frame(S, vlans=(3, 4))), ("sll", frame(S, lt=113)),
                ("sll2", frame(S, lt=276))):
    lt = 113 if nm == "sll" else 276 if nm == "sll2" else 1
    for n in range(len(fr0) + 1):
        try:
            run([fr0[:n]], lt=lt)
        except Exception as e:                          # noqa: BLE001
            bad.append((nm, n, repr(e)))
check("full truncation sweep (every prefix, 5 shapes) raises nothing: %s" % bad[:2], not bad)
rng = random.Random(1234)
bad = []
for i in range(20000):
    buf = os.urandom(rng.randint(0, 200))
    try:
        run([buf], lt=rng.choice((1, 12, 101, 113, 228, 229, 276, 147)))
    except Exception as e:                              # noqa: BLE001
        bad.append(repr(e))
check("20000 random byte strings across linktypes raise nothing: %s" % bad[:2], not bad)
bad, fired = [], 0
for i in range(20000):
    b = bytearray(rng.choice((base4, base6)))
    for _ in range(rng.randint(1, 4)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    try:
        fired += len(run([bytes(b)]))
    except Exception as e:                              # noqa: BLE001
        bad.append(repr(e))
check("20000 mutated valid frames raise nothing: %s" % bad[:2], not bad)
check("...and the corpus was not vacuous (some mutants still parse and fire)", fired > 1000)
check("bytearray and memoryview inputs accepted",
      lg.parse_frame(bytearray(base4)) == lg.parse_frame(base4) and lg.parse_frame(memoryview(base4)) == lg.parse_frame(base4)
      and codes_of(run([bytearray(base4)])) == ["LG-001"])
check("zero-length and 1-byte frames", lg.parse_frame(b"") is None and lg.parse_frame(b"\x45") is None)
check("banner with control characters serialises to valid JSON",
      json.loads(json.dumps(run([frame(resp(b"RomPager/4.07 \x01\x02\x7f\xff"))])[0]))["code"] == "LG-001")
check("500-byte banner", codes_of(run([frame(resp(b"RomPager/4.07 " + b"A" * 500))])) == ["LG-001"])
check("many Server headers: the first one decides",
      codes_of(run([frame(b"HTTP/1.1 200 OK\r\nServer: Apache\r\nServer: RomPager/4.07\r\n\r\n")])) == [])

# =====================================================================================
section("I discrimination + schema")
KEYS = {"ts", "module", "code", "severity", "family", "server", "client", "port", "banner", "version", "cve", "note",
        "detail"}
for fam in ("v4", "v6"):
    for banner, code in ((b"RomPager/4.07 UPnP/1.0", "LG-001"), (b"RomPager", "LG-002"), (b"RomPager/4.51", "LG-003")):
        o = run([frame(resp(banner), fam, seq=5)], ts0=1234.5)
        check("%s %s: exactly one finding, code %s" % (fam, banner, code), codes_of(o) == [code])
        f = o[0]
        check("%s %s: schema keys exact" % (fam, code), set(f) == KEYS)
        check("%s %s: field types" % (fam, code), isinstance(f["ts"], float) and isinstance(f["port"], int)
              and all(isinstance(f[k], str) for k in ("module", "code", "severity", "family", "server", "client", "banner", "note")))
        check("%s %s: ts is the fed timestamp" % (fam, code), f["ts"] == 1234.5)
        check("%s %s: module/severity/family" % (fam, code), f["module"] == "liebert_guard"
              and f["severity"] == lg.SEVERITY[code] and f["family"] == ("ipv4" if fam == "v4" else "ipv6"))
        check("%s %s: server is the sender, client the receiver, port is the server port" % (fam, code),
              f["server"] == (V4S if fam == "v4" else V6S) and f["client"] == (V4C if fam == "v4" else V6C) and f["port"] == 80)
        check("%s %s: note comes from the registry" % (fam, code), f["note"] == lg.NOTES[code])
        check("%s %s: cve is the registry's (only LG-001 here) and detail is null for a response finding" % (fam, code),
              f["cve"] == lg.CVES.get(code) and (f["cve"] is None) == (code != "LG-001") and f["detail"] is None)
        check("%s %s: version field" % (fam, code),
              f["version"] == {"LG-001": "4.07", "LG-002": None, "LG-003": "4.51"}[code])
        check("%s %s: banner is what was on the wire" % (fam, code), f["banner"] == banner.decode())
        check("%s %s: addresses re-parse" % (fam, code),
              socket.inet_pton(socket.AF_INET if fam == "v4" else socket.AF_INET6, f["server"]))
        check("%s %s: json round trip" % (fam, code), json.loads(json.dumps(f)) == f)
check("v6 server renders compressed (RFC 5952), no brackets or port fused in", run([frame(resp(b"RomPager/4.07"), "v6")])[0]["server"] == "2001:db8::5")
check("LG-001 note names a different code? it must not (LESSON I)",
      all(c not in lg.NOTES["LG-001"] for c in ("LG-002", "LG-003", "LG-101")))
o = run([frame(resp(b"RomPager/4.07")), frame(resp(b"RomPager/4.34"), seq=99, dport=40002)], cooldown=0)
check("one banner -> one code; mutual exclusion", codes_of(o) == ["LG-001", "LG-003"])
out = []
d = lg.Detector(cooldown=100, emit=out.append)
for t, sq in ((0, 1), (99, 500), (100, 900), (250, 1300)):
    d.feed(t, frame(S, seq=sq))
check("cooldown boundary: suppressed at 99s, re-emitted at exactly 100s and again 150s later", [f["ts"] for f in out] == [0, 100, 250])
out = []
d = lg.Detector(emit=out.append)
d.feed(0, frame(S, seq=1))
d.feed(1, frame(resp(b"RomPager/4.07 UPnP/1.0 x"), seq=500))
check("same host, changed banner text -> new finding", len(out) == 2)
srv2 = frame(S, seq=1).replace(socket.inet_aton(V4S), socket.inet_aton("10.9.0.6"))
check("different server address, same banner -> separate dedup key",
      len(run([frame(S, seq=1), srv2], cooldown=3600)) == 2)

# =====================================================================================
section("J clean-set silence")
clean = [b"Apache/2.4.6 (CentOS)", b"Apache", b"nginx/1.18.0", b"nginx", b"lighttpd/1.4.55", b"Microsoft-IIS/10.0",
         b"BaseHTTP/0.6 Python/3.12.3", b"GoAhead-Webs", b"mini_httpd/1.19", b"uhttpd", b"Boa/0.94.14rc21",
         b"thttpd/2.25b", b"Jetty(9.4.z)", b"Rom Pager/4.07", b"RomPage/4.07", b"Rompaer/4.07", b"miniupnpd/1.0",
         b"mod_rompager/4.07", b"XRomPager/4.07", b"Allegro", b"Allegro-Software", b"Cisco-IOS", b"lwIP/2.1.0",
         b"Liebert", b"Emerson Network Power", b"Raritan", b"", b"Server"]
for fam in ("v4", "v6"):
    bad = [c for c in clean if run([frame(resp(c), fam)])]
    check("%d non-RomPager banners silent on %s: %s" % (len(clean), fam, bad), not bad)
    for hdr in (b"X-Powered-By: RomPager/4.07", b"Via: 1.1 RomPager/4.07", b"X-Server: RomPager/4.07",
                b"XServer: RomPager/4.07", b"Set-Cookie: Server=RomPager/4.07", b"Content-Type: RomPager/4.07",
                b"X-Note: Server: RomPager/4.07", b"Servers: RomPager/4.07", b" Server: RomPager/4.07"):
        r = b"HTTP/1.1 200 OK\r\n" + hdr + b"\r\nServer: Apache\r\n\r\n"
        check("%s: other header %r silent" % (fam, hdr), run([frame(r, fam)]) == [])
    body = resp(b"Apache", body=b"Server: RomPager/4.07\r\n\r\n<pre>RomPager/4.07</pre>")
    check("%s: RomPager only in the body is silent" % fam, run([frame(body, fam)]) == [])
    check("%s: no Server header at all is silent" % fam, run([frame(resp(None), fam)]) == [])
    check("%s: no real Server header and RomPager only in the body is silent (head must end at the blank line)" % fam,
          run([frame(resp(None, body=b"Server: RomPager/4.07\r\n"), fam)]) == []
          and run([frame(resp(None, body=b"Server: RomPager/4.07\r\n", eol=b"\n"), fam)]) == [])
    check("%s: client->server traffic is silent" % fam, run([frame(resp(b"RomPager/4.07"), fam, sport=40000, dport=80)]) == [])
    check("%s: a request line is not a response" % fam,
          run([frame(b"GET / HTTP/1.1\r\nServer: RomPager/4.07\r\n\r\n", fam)]) == [])
    check("%s: TCP handshake/ack-only segments are silent" % fam, run([frame(b"", fam)]) == [])
check("a non-80 port is silent by default", run([frame(S, sport=8080)]) == [] and run([frame(S, sport=443)]) == [])
check("--port moves the gate (and only the gate)", codes_of(run([frame(S, sport=8080)], port=8080)) == ["LG-001"]
      and run([frame(S, sport=80)], port=8080) == [])

# =====================================================================================
section("L pcap artefacts + CLI")


def write_pcap(path, frames, linktype=1, base=1700000000, interval_us=1000, be=False, nano=False):
    e = ">" if be else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    mult = 1000 if nano else 1
    with open(path, "wb") as f:
        f.write(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            us = i * interval_us
            f.write(struct.pack(e + "IIII", base + us // 1000000, (us % 1000000) * mult, len(fr), len(fr)) + fr)


def cli(*a):
    return subprocess.run([sys.executable, MODPATH] + list(a), capture_output=True, text=True, cwd=HERE)


with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, "t.pcap")
    n = 1500
    write_pcap(p, [frame(b"x" * 5, seq=i) for i in range(n)], interval_us=1000)
    ts = [t for t, _, _ in lg.read_pcap(p)]
    check("1500 frames read back", len(ts) == n)
    check("packet 999 stays in second 0, packet 1000 rolls to second 1 (the cdpwatch timestamp bug)",
          int(ts[999] - 1700000000) == 0 and int(ts[1000] - 1700000000) == 1)
    check("timestamps strictly increasing and exact to 1us",
          all(abs(ts[i] - (1700000000 + i * 0.001)) < 1e-6 for i in range(n)))
    for nm, kw in (("little-endian micro", {}), ("big-endian micro", {"be": True}), ("little-endian nano", {"nano": True}),
                   ("big-endian nano", {"be": True, "nano": True})):
        write_pcap(p, [frame(S, seq=i) for i in (1, 2, 3)], interval_us=250000, **kw)
        rec = list(lg.read_pcap(p))
        check("pcap flavour: %s (frames, linktype and timestamps 0 / +0.25 / +0.5 s)" % nm,
              len(rec) == 3 and [r[1] for r in rec] == [frame(S, seq=i) for i in (1, 2, 3)]
              and all(r[2] == 1 for r in rec)
              and all(abs(r[0] - (1700000000 + k * 0.25)) < 1e-6 for k, r in enumerate(rec)))
    for lt in (1, 12, 14, 101, 113, 276):
        for fam in ("v4", "v6"):
            write_pcap(p, [frame(S, fam, seq=1, lt=lt)], linktype=lt)
            r = cli("-r", p)
            check("CLI over linktype %d %s -> LG-001" % (lt, fam),
                  r.returncode == 0 and [json.loads(x)["code"] for x in r.stdout.splitlines()] == ["LG-001"])
    write_pcap(p, [frame(S, "v4", seq=1, lt=228)], linktype=228)
    check("CLI over linktype 228", '"LG-001"' in cli("-r", p).stdout)
    write_pcap(p, [frame(S, "v6", seq=1, lt=229)], linktype=229)
    check("CLI over linktype 229", '"LG-001"' in cli("-r", p).stdout)

    write_pcap(p, [frame(S)], linktype=147)
    r = cli("-r", p)
    check("unsupported linktype: exit 2, message names it, no traceback",
          r.returncode == 2 and "147" in r.stderr and "Traceback" not in r.stderr and r.stdout == "")
    open(p, "wb").write(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
    r = cli("-r", p)
    check("pcapng: exit 2, says pcapng, tells you how to convert", r.returncode == 2 and "pcapng" in r.stderr and "editcap" in r.stderr)
    open(p, "wb").write(b"not a capture at all")
    r = cli("-r", p)
    check("garbage file: exit 2, no traceback", r.returncode == 2 and "Traceback" not in r.stderr)
    open(p, "wb").close()
    r = cli("-r", p)
    check("empty file: exit 2, no traceback", r.returncode == 2 and "Traceback" not in r.stderr)
    open(p, "wb").write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)[:10])
    check("truncated header: exit 2", cli("-r", p).returncode == 2)
    r = cli("-r", os.path.join(td, "missing.pcap"))
    check("missing file: exit 2, no traceback", r.returncode == 2 and "Traceback" not in r.stderr)
    write_pcap(p, [frame(S, seq=1), frame(S, "v6", seq=2), frame(S, seq=3)])
    data = open(p, "rb").read()
    open(p, "wb").write(data[:-7])
    r = cli("-r", p)
    check("capture truncated mid-record: findings so far kept, exit 0", r.returncode == 0 and r.stdout.count('"LG-001"') >= 1)
    write_pcap(p, [frame(S, seq=1), frame(resp(b"RomPager/4.51"), "v6", seq=2)])
    o = os.path.join(td, "o.jsonl")
    r1, r2 = cli("-r", p, "-o", o), cli("-r", p, "-o", o)
    lines = open(o).read().splitlines()
    check("-o writes the same JSON lines it prints, appending across runs",
          len(lines) == 4 and lines[:2] == r1.stdout.splitlines() and lines[2:] == r2.stdout.splitlines())
    check("usage errors exit 2", cli().returncode == 2 and cli("-r", p, "-i", "lo").returncode == 2
          and cli("-r", p, "-p", "notanumber").returncode == 2)
    check("--help exits 0", cli("-h").returncode == 0)
    r = cli("-r", p, "--cooldown", "0")
    check("--cooldown 0 accepted", r.returncode == 0 and r.stdout.count("\n") == 2)

# =====================================================================================
section("M resource bounds")
d = lg.Detector(max_flows=16, emit=lambda f: None)
for i in range(5000):
    d.feed(0, frame(b"HTTP/1.1 200 OK\r\nX: ", seq=i, dport=1000 + (i % 60000)).replace(socket.inet_aton(V4S), struct.pack("!I", 0x0A000000 + i)))
check("flow table never exceeds max_flows under 5000 distinct incomplete heads", len(d.flows) <= 16)
d = lg.Detector(emit=lambda f: None)
for i in range(60):
    d.feed(0, frame(b"A" * 1000, seq=i * 1000))
check("a flow of non-HTTP data never holds more than the per-flow byte cap",
      sum(f["size"] for f in d.flows.values()) <= lg.Detector.MAX_FLOW_BYTES)
d = lg.Detector(emit=lambda f: None)
for _ in range(100):
    d.feed(0, frame(b"A" * 1000, seq=5000))
check("100 duplicates of one segment count once toward the flow cap", [f["size"] for f in d.flows.values()] == [1000])
d = lg.Detector(emit=lambda f: None)
d.feed(0, frame(b"A" * 300, seq=5000))
d.feed(0, frame(b"A" * 900, seq=5000))
d.feed(0, frame(b"A" * 100, seq=5000))
check("size follows the longest segment at a seq (300 -> 900, then a 100 duplicate changes nothing)",
      [f["size"] for f in d.flows.values()] == [900])
check("per-flow cap constant is bounded", lg.Detector.MAX_FLOW_BYTES <= 65536 and lg.Detector.MAX_HEAD <= 65536)


class Tiny(lg.Detector):
    MAX_SEEN = 50


out = []
d = Tiny(emit=out.append)
for i in range(400):
    fr_ = frame(S, seq=i).replace(socket.inet_aton(V4S), struct.pack("!I", 0x0A010000 + i))
    d.feed(float(i), fr_)
check("dedup table is bounded (MAX_SEEN) under 400 distinct (server,banner) keys", len(d.seen) <= 50 and len(out) == 400)
d.feed(500.0, frame(S, seq=7).replace(socket.inet_aton(V4S), struct.pack("!I", 0x0A010000 + 399)))
check("a recent key is still suppressed after eviction pressure", len(out) == 400)
d = lg.Detector(max_flows=16, emit=lambda f: None)
for i in range(5000):
    d.feed(0, frame(b"GET /x HTTP/1.1\r\nHost: x", seq=i, sport=1000 + (i % 60000), dport=80).replace(
        socket.inet_aton(V4S), struct.pack("!I", 0x0A000000 + i)))
check("request flow table never exceeds max_flows under 5000 distinct incomplete requests", len(d.reqs) <= 16)
d = lg.Detector(emit=lambda f: None)
for i in range(60):
    d.feed(0, frame(b"B" * 1000, seq=i * 1000, sport=40000, dport=80))
check("a client flow never holds more than MAX_REQ bytes",
      sum(f["size"] for f in d.reqs.values()) <= lg.Detector.MAX_REQ)
d = lg.Detector(emit=lambda f: None)
d.feed(0, frame(b"B" * 60000, seq=1, sport=40000, dport=80))
check("a single huge segment is stored truncated to MAX_REQ", all(len(s) <= lg.Detector.MAX_REQ for f in d.reqs.values()
                                                                    for s in f["segs"].values()))
d = lg.Detector(emit=lambda f: None)
for _ in range(100):
    d.feed(0, frame(b"B" * 1000, seq=5000, sport=40000, dport=80))
check("100 duplicates of one client segment count once toward the request flow size", [f["size"] for f in d.reqs.values()] == [1000])
d = lg.Detector(emit=lambda f: None)
for n_ in (300, 900, 100):
    d.feed(0, frame(b"B" * n_, seq=5000, sport=40000, dport=80))
check("request flow size follows the longest segment at a seq (300 -> 900, then a 100 duplicate changes nothing)",
      [f["size"] for f in d.reqs.values()] == [900])
check("default MAX_SEEN is sane (>= flow cap, <= 1M)", 4096 <= lg.Detector.MAX_SEEN <= 1_000_000)
d = lg.Detector(emit=lambda f: None)
for i in range(200000):
    d.feed(0, b"\x00" * 60)
check("200000 junk frames leave no state behind", len(d.flows) == 0 and len(d.seen) == 0)

# =====================================================================================
section("N dual-stack parity")
SCEN = {
    "LG-001 whole": lambda fam: [frame(resp(b"RomPager/4.07 UPnP/1.0"), fam)],
    "LG-002 whole": lambda fam: [frame(resp(b"RomPager"), fam)],
    "LG-003 whole": lambda fam: [frame(resp(b"RomPager/4.51"), fam)],
    "split 3 reversed": lambda fam: split_frames(HEAD, [20, 50], fam, order=[2, 1, 0]),
    "1-byte segments": lambda fam: split_frames(HEAD, list(range(1, N)), fam),
    "bare LF": lambda fam: [frame(resp(b"RomPager/4.07", eol=b"\n"), fam)],
    "vlan": lambda fam: [frame(S, fam, vlans=(10,))],
    "eth padding": lambda fam: [frame(S, fam, pad=20)],
    "seq wrap": lambda fam: split_frames(HEAD, [30], fam, isn=0xFFFFFFF0),
    "other server silent": lambda fam: [frame(resp(b"Apache"), fam)],
    "client direction silent": lambda fam: [frame(S, fam, sport=40000, dport=80)],
    "body-only banner silent": lambda fam: [frame(resp(b"Apache", body=b"Server: RomPager/4.07"), fam)],
    "gap silent": lambda fam: [split_frames(HEAD, [30, 60], fam)[i] for i in (0, 2)],
    "sll": lambda fam: [frame(S, fam, lt=113)],
    "LG-101 whole": lambda fam: [frame(REQ_(b"A" * 70), fam, sport=40000, dport=80)],
    "LG-101 boundary 64 silent": lambda fam: [frame(REQ_(b"A" * 64), fam, sport=40000, dport=80)],
    "LG-101 boundary 65": lambda fam: [frame(REQ_(b"A" * 65), fam, sport=40000, dport=80)],
    "LG-101 split reversed": lambda fam: split_frames(REQ_(b"A" * 70), [20, 50], fam, order=[2, 1, 0], sport=40000, dport=80),
    "LG-101 1-byte segments": lambda fam: split_frames(REQ_(b"A" * 70), list(range(1, len(REQ_(b"A" * 70)))), fam,
                                                      sport=40000, dport=80),
    "LG-101 vlan + padding": lambda fam: [frame(REQ_(b"A" * 70), fam, sport=40000, dport=80, vlans=(10,), pad=20)],
    "LG-101 seq wrap": lambda fam: split_frames(REQ_(b"A" * 70), [30], fam, isn=0xFFFFFFF0, sport=40000, dport=80),
    "LG-101 server direction silent": lambda fam: [frame(REQ_(b"A" * 70), fam, sport=80, dport=40000)],
}
for name, mk in SCEN.items():
    lt = 113 if name == "sll" else 1
    a, b = codes_of(run(mk("v4"), lt=lt)), codes_of(run(mk("v6"), lt=lt))
    check("parity: %s -> v4 %s == v6 %s" % (name, a, b), a == b)
for name, chain in (("hbh", (0,)), ("dest", (60,)), ("routing", (43,)), ("frag0", (44,)), ("ah", (51,)),
                    ("hbh+dest", (0, 60)), ("hbh+routing+dest+frag", (0, 43, 60, 44))):
    check("ipv6-only: ext chain %s still yields the v4-equivalent finding" % name,
          codes_of(run([frame(S, "v6", types=chain)])) == codes_of(run([frame(S, "v4")])) == ["LG-001"])
check("both families produce identical finding payloads apart from address fields",
      {k: v for k, v in run([frame(S, "v4")])[0].items() if k not in ("server", "client", "family")}
      == {k: v for k, v in run([frame(S, "v6")])[0].items() if k not in ("server", "client", "family")})


# =====================================================================================
section("O request line (LG-101)")


def rq(payload, fam="v4", seq=1000, sport=40000, dport=80, **kw):   # a client -> server frame
    return frame(payload, fam, seq=seq, sport=sport, dport=dport, **kw)


def fires(req, fam="v4", **kw):
    return codes_of(run([rq(req, fam)], **kw)) == ["LG-101"]


def silent(req, fam="v4", **kw):
    return run([rq(req, fam)], **kw) == []


TCHAR = b"!#$%&'*+-.^_`|~" + bytes(range(48, 58)) + bytes(range(65, 91)) + bytes(range(97, 123))
bad = [(n, fam) for n in range(1, 201) for fam in ("v4", "v6") if fires(REQ_(b"A" * n), fam) != (n > 64)]
check("method length 1..200 x v4/v6: fires if and only if longer than 64 (64 silent, 65 fires): %s" % bad[:3], not bad)
check("the boundary really is MAX_METHOD", lg.Detector.MAX_METHOD == 64 and silent(REQ_(b"A" * lg.Detector.MAX_METHOD))
      and fires(REQ_(b"A" * (lg.Detector.MAX_METHOD + 1))))
check("every registered or real method, including the longest ones, is silent", all(
    silent(REQ_(m), f) for f in ("v4", "v6") for m in (b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS",
                                                    b"TRACE", b"PATCH", b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY", b"MOVE",
                                                    b"LOCK", b"UNLOCK", b"MKCALENDAR", b"VERSION-CONTROL", b"BASELINE-CONTROL",
                                                    b"UPDATEREDIRECTREF", b"M-SEARCH", b"NOTIFY", b"SUBSCRIBE")))
check("every token character is allowed in the method (65 of each fires)",
      all(fires(REQ_(bytes([c]) * 65)) for c in TCHAR))
bad = [c for c in range(256) if c not in TCHAR and c not in b" \r\n"
       and not silent(REQ_(b"A" * 70 + bytes([c]) + b"A" * 5))]
check("a non-token byte inside the method breaks the request-line shape, so it is silent: %s" % bad[:5], not bad)
check("a space ends the method token (70-byte token, then a normal line) and still fires", fires(REQ_(b"A" * 70)))
check("method on a line of its own with no target is not a request line", silent(b"A" * 70 + b"\r\nHost: x\r\n\r\n"))

# the rest of the request line
check("HTTP/1.0 and HTTP/1.1 fire", fires(REQ_(b"A" * 70, ver=b"1.0")) and fires(REQ_(b"A" * 70, ver=b"1.1")))
check("other versions and malformed versions are silent",
      all(silent(REQ_(b"A" * 70, ver=v)) for v in (b"0.9", b"2.0", b"1.2", b"1", b"1.", b"11", b"x")))
check("lowercase 'http/1.1' is silent", silent(b"A" * 70 + b" / http/1.1\r\n\r\n"))
check("no version at all (HTTP/0.9 style) is silent", silent(b"A" * 70 + b" /\r\n\r\n"))
check("bare LF line endings fire", fires(REQ_(b"A" * 70, eol=b"\n")))
check("leading empty lines (1, 2, 5) are skipped like servers do", all(fires(b"\r\n" * k + REQ_(b"A" * 70)) for k in (1, 2, 5)))
check("a leading space is not a request line", silent(b" " + REQ_(b"A" * 70)))
check("absolute-form target fires", fires(REQ_(b"A" * 70, uri=b"http://10.9.0.5/index.html?x=1")))
check("a target with high bytes fires", fires(REQ_(b"A" * 70, uri=b"/\xc3\xa9\xff")))
check("a 4000-byte target still fires (inside MAX_REQ)", fires(REQ_(b"A" * 70, uri=b"/" + b"u" * 4000)))
check("PINNED LIMIT: a request line that does not end inside MAX_REQ bytes is not judged",
      silent(b"A" * 70 + b" /" + b"u" * 9000 + b" HTTP/1.1\r\n\r\n"))
check("PINNED: a doubled space between method and target is not a request line", silent(b"A" * 70 + b"  / HTTP/1.1\r\n\r\n"))
check("PINNED: a TAB separator is not a request line", silent(b"A" * 70 + b"\t/ HTTP/1.1\r\n\r\n"))
check("headers and body after the line do not matter", fires(REQ_(b"A" * 70, extra=b"Content-Length: 5\r\n\r\nhello")) and
      fires(b"A" * 70 + b" / HTTP/1.1\r\n"))

# direction and port gating
for fam in ("v4", "v6"):
    check("%s: a long-method line sent BY the server port is silent (request path is client->server only)" % fam,
          run([frame(REQ_(b"A" * 70), fam, sport=80, dport=40000)]) == [])
    check("%s: a long-method line to another port is silent, and --port moves the gate" % fam,
          run([frame(REQ_(b"A" * 70), fam, sport=40000, dport=8080)]) == []
          and codes_of(run([frame(REQ_(b"A" * 70), fam, sport=40000, dport=8080)], port=8080)) == ["LG-101"])
    check("%s: a response head and a request line on the same port do not interfere" % fam,
          codes_of(run([frame(S, fam, seq=1), frame(REQ_(b"A" * 70), fam, seq=9, sport=40001, dport=80)], cooldown=0))
          == ["LG-001", "LG-101"])

# finding fields
KEYS_O = {"ts", "module", "code", "severity", "family", "server", "client", "port", "banner", "version", "cve", "note", "detail"}
for fam, srv_addr, cli_addr in (("v4", V4C, V4S), ("v6", V6C, V6S)):
    o = run([rq(REQ_(b"A" * 70), fam)], ts0=77.5)
    f = o[0] if o else {}
    check("%s: one finding, exact schema" % fam, len(o) == 1 and set(f) == KEYS_O)
    check("%s: code, severity, cve, ts, family, port" % fam, f.get("code") == "LG-101" and f.get("severity") == "high"
          and f.get("cve") == "CVE-2025-41426" and f.get("ts") == 77.5 and f.get("port") == 80
          and f.get("family") == ("ipv4" if fam == "v4" else "ipv6"))
    check("%s: server is the target (destination), client is the sender" % fam,
          f.get("server") == srv_addr and f.get("client") == cli_addr)
    check("%s: banner and version are null, note is the registry text" % fam,
          f.get("banner") is None and f.get("version") is None and f.get("note") == lg.NOTES["LG-101"])
    check("%s: detail names the length and a 24-byte token sample" % fam, f.get("detail") == "method_len=70 sample=" + "A" * 24)
    check("%s: json round trip" % fam, json.loads(json.dumps(f)) == f)
check("detail sample is truncated to 24 bytes for a 200-byte method and stays plain ASCII",
      run([rq(REQ_(b"Z" * 200))])[0]["detail"] == "method_len=200 sample=" + "Z" * 24)
check("detail sample carries token punctuation safely", run([rq(REQ_(b"!#$%&'*+-.^_`|~" * 6))])[0]["detail"].startswith("method_len=90 sample="))

# reassembly of the request line (exhaustive)
RL = REQ_(b"A" * 70)
NR = len(RL)


def rsplit(cuts, fam="v4", isn=1000, order=None):
    return split_frames(RL, cuts, fam, isn, order, sport=40000, dport=80)


miss = [i for i in range(1, NR) if codes_of(run(rsplit([i]))) != ["LG-101"]]
check("every single split point (%d) in order" % (NR - 1), not miss)
miss = [i for i in range(1, NR) if codes_of(run(rsplit([i], order=[1, 0]))) != ["LG-101"]]
check("every single split point reversed (the earliest bytes arrive last)", not miss)
miss = [(i, off, fam) for i in range(1, NR) for off in (-1, 0, 1) for fam in ("v4", "v6")
        if codes_of(run(rsplit([i], fam, ((1 << 32) - i + off) & 0xFFFFFFFF))) != ["LG-101"]]
check("every split point x wrap exactly at / one before / one after the cut x v4+v6: %s" % miss[:3], not miss)
miss = []
cnt = 0
for i, j in itertools.combinations(range(1, NR), 2):
    for order in itertools.permutations(range(3)):
        cnt += 1
        if codes_of(run(rsplit([i, j], order=list(order)))) != ["LG-101"]:
            miss.append((i, j, order))
check("every pair of split points x all 6 arrival orders (%d cases): %s" % (cnt, miss[:2]), not miss)
miss = [k for k in range(1, NR + 1) if codes_of(run(rsplit(list(range(k, NR, k))))) != ["LG-101"]]
check("fixed-size chunking at every size 1..%d" % NR, not miss)
miss = [k for k in range(1, NR + 1)
        if codes_of(run(rsplit(list(range(k, NR, k)), order=list(reversed(range(len(range(0, NR, k)))))))) != ["LG-101"]]
check("fixed-size chunking reversed at every size", not miss)
for seed in range(60):
    rng = random.Random(4000 + seed)
    cuts = sorted(rng.sample(range(1, NR), rng.randint(1, 10)))
    order = list(range(len(cuts) + 1))
    rng.shuffle(order)
    fam = ("v4", "v6")[seed % 2]
    if codes_of(run(rsplit(cuts, fam, (1 << 32) - rng.randint(1, NR), order))) != ["LG-101"]:
        check("shuffle seed %d" % seed, False)
check("60 seeded random multi-segment shuffles that cross 2**32, both families", True)
fr = rsplit([30, 60])
big = rq(RL[:60], seq=1000)
check("every segment duplicated", codes_of(run([x for f in fr for x in (f, f)])) == ["LG-101"])
check("short segment, then a longer retransmit of the same range (middle lost)", codes_of(run([fr[0], big, fr[2]])) == ["LG-101"])
check("longer segment first, then a shorter duplicate of its start", codes_of(run([big, fr[0], fr[2]])) == ["LG-101"])
check("missing middle segment -> no finding, no crash", run([fr[0], fr[2]]) == [])
d_ = lg.Detector(emit=(o_ := []).append)
for i, f in enumerate([fr[0], fr[2], fr[1]]):
    d_.feed(1000.0 + i, f)
check("late arrival of the missing segment completes the line exactly once", codes_of(o_) == ["LG-101"])
check("interleaved client flows reassemble independently", codes_of(run(
    [rq(RL[:50], seq=100, sport=41000), rq(RL[:50], seq=100, sport=41001), rq(RL[50:], seq=150, sport=41001),
     rq(RL[50:], seq=150, sport=41000)], cooldown=0)) == ["LG-101"] * 2)

# first line of the flow only (pinned) and what is not judged
ok_req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
check("PINNED LIMIT: a long-method request that follows a normal request in the same segment is not judged",
      silent(ok_req + REQ_(b"A" * 70)))
check("PINNED: ...but when it arrives in a LATER segment of a flow whose first segment was not a request line it is "
      "judged from the lowest sequence seen, so a mid-flow capture can still catch a first-seen attack",
      codes_of(run([rq(REQ_(b"A" * 70), seq=5000)])) == ["LG-101"])
check("a normal request followed by a long-method request in a separate flow fires for that flow only",
      codes_of(run([rq(ok_req, seq=1, sport=42000), rq(REQ_(b"A" * 70), seq=1, sport=42001)])) == ["LG-101"])

# dedup and cooldown
out = []
d = lg.Detector(cooldown=100, emit=out.append)
for t_, sp in ((0, 43000), (99, 43001), (100, 43002), (250, 43003)):
    d.feed(t_, frame(REQ_(b"A" * 70), seq=1, sport=sp, dport=80))
check("cooldown boundary: suppressed at 99 s, again at exactly 100 s and 150 s later", [f["ts"] for f in out] == [0, 100, 250])
cli2 = frame(REQ_(b"A" * 70), seq=1, sport=44000, dport=80).replace(socket.inet_aton(V4S), socket.inet_aton("10.9.0.99"))
srv2 = frame(REQ_(b"A" * 70), seq=1, sport=44001, dport=80).replace(socket.inet_aton(V4C), socket.inet_aton("10.9.0.100"))
check("a different client is a separate finding; a different server is a separate finding",
      len(run([rq(REQ_(b"A" * 70), seq=1, sport=44002), cli2, srv2], cooldown=3600)) == 3)
check("the same (server, client) is one finding however many connections", len(run(
    [rq(REQ_(b"A" * 70), seq=1, sport=45000 + i) for i in range(5)], cooldown=3600)) == 1)

# clean-set silence: ordinary traffic on port 80
clean_reqs = [b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n",
              b"GET /index.html?q=" + b"a" * 2000 + b" HTTP/1.1\r\nHost: x\r\nCookie: " + b"c" * 3000 + b"\r\n\r\n",
              b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\nuser=a&password=bbbbb",
              b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n",
              b"PROPFIND /dav/ HTTP/1.1\r\nHost: x\r\nDepth: 1\r\n\r\n", b"HEAD /robots.txt HTTP/1.0\r\n\r\n",
              b"GET http://example.org/proxy HTTP/1.1\r\nHost: example.org\r\n\r\n",
              b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\r\n",
              b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 200,                 # a TLS ClientHello on port 80
              b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", b"\x00" * 300, os.urandom(300),
              b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n", b"A" * 500, b"A" * 70 + b"\r\n",
              b"U2VydmVyOiBSb21QYWdlci80LjA3" * 20, b"GET " + b"/" * 8000 + b" HTTP/1.1\r\n\r\n"]
for fam in ("v4", "v6"):
    bad = [i for i, r in enumerate(clean_reqs) if not silent(r, fam)]
    check("%s: %d ordinary or hostile-but-different port-80 payloads are silent: %s" % (fam, len(clean_reqs), bad), not bad)

# robustness
base_rq = rq(RL)
bad = []
for n in range(len(base_rq) + 1):
    try:
        run([base_rq[:n]])
    except Exception as e:                                          # noqa: BLE001
        bad.append((n, repr(e)))
check("full truncation sweep of a request frame raises nothing: %s" % bad[:2], not bad)
rng = random.Random(77)
bad, fired = [], 0
for i in range(20000):
    b = bytearray(rng.choice((base_rq, rq(RL, "v6"))))
    for _ in range(rng.randint(1, 4)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    try:
        fired += len(run([bytes(b)]))
    except Exception as e:                                          # noqa: BLE001
        bad.append(repr(e))
check("20000 mutated request frames raise nothing: %s" % bad[:2], not bad)
check("...and the corpus was not vacuous (some mutants still fire LG-101)", fired > 500)
check("random payloads on the request port raise nothing and stay silent", all(
    run([rq(os.urandom(rng.randint(1, 600)), seq=rng.randrange(1 << 32), sport=1024 + i)]) == [] for i in range(3000)))

# =====================================================================================
section("K coverage")
check("every declared code was produced by production runs: %s" % sorted(declared - {c for c, _ in OBSERVED}),
      declared <= {c for c, _ in OBSERVED})
check("every declared code was produced on BOTH families",
      all((c, fam) in OBSERVED for c in declared for fam in ("ipv4", "ipv6")))
check("no undeclared code was ever emitted", {c for c, _ in OBSERVED} <= declared)
check("every response code is reachable from classify(); LG-101 is reached through the request path (observed above)",
      {lg.classify(b)[0] for b in (b"RomPager/4.07", b"RomPager", b"RomPager/4.34")} == declared - {"LG-101"}
      and ("LG-101", "ipv4") in OBSERVED and ("LG-101", "ipv6") in OBSERVED)

# ------------------------------------------------------------------------------------
tp = sum(v[0] for v in TALLY.values())
tf = sum(v[1] for v in TALLY.values())
print("liebert_guard v%s conformance" % lg.__version__)
for k, (p_, f_) in TALLY.items():
    print("  %-34s %6d passed %3d failed" % (k, p_, f_))
print("TOTAL %d passed, %d failed" % (tp, tf))
sys.exit(1 if tf else 0)
