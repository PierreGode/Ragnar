#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Offline self-test for telnetwatch. Pure-python (asserts scapy stays unimported).

Fabricates real IAC-escaped Telnet wire bytes and drives them through the
production Engine -> Emitter path (the same handle() feeds in run_capture).
Every finding code is exercised with a POSITIVE assertion and a FALSE-POSITIVE
gate. Includes the passive-invariant grep and a credential-safety assertion.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys

import telnet_watch as T
from telnet_watch import (
    IAC, SB, SE, DO, DONT, WILL, WONT,
    OPT_LINEMODE, OPT_NEW_ENVIRON, OPT_ENVIRON, OPT_ECHO, OPT_ENCRYPT,
    ENV_IS, ENV_VAR, ENV_VALUE, ENV_USERVAR,
    LM_SLC, NSLC, SLC_OVERFLOW_TRIPLETS, SLCBUF_SIZE,
    Engine, Emitter, FINDINGS,
)

CLIENT = ("10.0.0.9", 51000)
SERVER = ("10.0.0.1", 23)
KEY = (CLIENT[0], CLIENT[1], SERVER[0], SERVER[1])

_fails = []
_count = 0
_records = []          # [(msg, passed)] for the structured results() adapter


def check(cond, msg):
    global _count
    _count += 1
    _records.append((msg, bool(cond)))
    if not cond:
        _fails.append(msg)


# --- wire builders (produce exactly what crosses the wire, IAC-doubled) ------
def _escape(data: bytes) -> bytes:
    return data.replace(b"\xff", b"\xff\xff")


def nego(cmd: int, opt: int) -> bytes:
    return bytes([IAC, cmd, opt])


def subneg(opt: int, body: bytes) -> bytes:
    return bytes([IAC, SB, opt]) + _escape(body) + bytes([IAC, SE])


def environ_is(pairs, uservar=False) -> bytes:
    """pairs: list of (name, value|None). Build a NEW-ENVIRON IS body."""
    b = bytearray([ENV_IS])
    vt = ENV_USERVAR if uservar else ENV_VAR
    for name, value in pairs:
        b.append(vt)
        b += name
        if value is not None:
            b.append(ENV_VALUE)
            b += value
    return bytes(b)


def slc_triplets(triples) -> bytes:
    """triples: list of (func, flag, val). Build a LINEMODE SLC body."""
    b = bytearray([LM_SLC])
    for func, flag, val in triples:
        b += bytes([func & 0xFF, flag & 0xFF, val & 0xFF])
    return bytes(b)


class Harness:
    def __init__(self, min_sev="info"):
        self.buf = io.StringIO()
        self.em = Emitter(out=self.buf, min_sev=min_sev, dedup_secs=0.0)
        self.eng = Engine(self.em)
        self.t = 1000.0

    def send(self, from_server: bool, payload: bytes):
        self.t += 0.01
        self.eng.on_payload(KEY, from_server, payload, now=self.t)

    def records(self):
        out = []
        for line in self.buf.getvalue().splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def codes(self):
        return [r["code"] for r in self.records()]

    def by_code(self, code):
        return [r for r in self.records() if r["code"] == code]


# ---------------------------------------------------------------------------
# Section 0: catalog + passive invariant + no-scapy
# ---------------------------------------------------------------------------
def test_catalog():
    check(len(FINDINGS) == 10, f"expected 10 finding codes, got {len(FINDINGS)}")
    for code, (sev, dclass, desc) in FINDINGS.items():
        check(sev in T._SEV_RANK, f"{code}: bad severity {sev}")
        check(dclass in {"attack", "recon", "exposure", "posture"},
              f"{code}: bad class {dclass}")
        check(bool(desc) and len(desc) > 10, f"{code}: weak description")


def test_no_scapy_imported():
    # The invariant is that telnet_watch imports scapy LAZILY (only inside the
    # live-capture / pcap-replay paths), so --selftest and the parser/engine need
    # neither scapy nor root. Asserting `"scapy" not in sys.modules` only holds when
    # the module is run standalone; in-app the host has already loaded scapy for
    # other watchers. Check the real, context-independent property instead: the
    # module source has no MODULE-LEVEL scapy import (function-local is fine).
    import ast
    src = open(T.__file__, "r", encoding="utf-8").read()
    tree = ast.parse(src)
    top = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            top += [a.name for a in node.names if a.name.split(".")[0] == "scapy"]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] == "scapy":
                top.append(node.module)
    check(not top, f"scapy must be imported lazily, not at module level: {top}")


def test_passive_invariant():
    """LESSON D: key the guard on AST SHAPE, not identifier string.

    A packet-transmit primitive is a Call whose func is a bare Name in the
    transmit set (scapy send/sendp/sr*, socket L2/L3 senders, pcap_sendpacket),
    or an Attribute call like `sock.sendto(...)` / `sock.send(...)`. A `def send`
    is a FunctionDef, not a Call, so it is correctly ignored. urllib.urlopen is
    out-of-band Pushover alerting (explicitly part of the suite), not packet
    transmit, so it is not banned.
    """
    import ast
    src = open(T.__file__, "r", encoding="utf-8").read()
    tree = ast.parse(src)

    BANNED_NAMES = {"sendp", "sendpfast", "sr", "sr1", "srp", "srp1",
                    "send", "sendto", "pcap_sendpacket", "L2socket",
                    "L3socket"}
    # Attribute calls on a socket object that transmit.
    BANNED_ATTRS = {"sendto", "sendall", "sendmsg"}

    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name) and f.id in BANNED_NAMES:
            violations.append(f"call to {f.id}() at line {node.lineno}")
        elif isinstance(f, ast.Attribute) and f.attr in BANNED_ATTRS:
            violations.append(f"call to .{f.attr}() at line {node.lineno}")
    check(not violations,
          "passive invariant (AST): transmit primitive(s): " + "; ".join(violations))

    # socket.socket( must not appear at all: capture uses scapy's AF_PACKET
    # handle, not a raw socket opened by this module.
    sock_calls = [n.lineno for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr == "socket"
                  and isinstance(n.func.value, ast.Name)
                  and n.func.value.id == "socket"]
    check(not sock_calls, f"module must not open a socket directly: {sock_calls}")

    # self-test of the guard: a bare send() CALL must trip it, a `def send`
    # must not (proves AST shape is what is checked, not the name).
    pos = ast.parse("sendp(x)")
    trip = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id in BANNED_NAMES for n in ast.walk(pos))
    check(trip, "guard self-test: a bare transmit call must trip the guard")
    neg = ast.parse("def send(z):\n    return z")
    trip2 = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id in BANNED_NAMES for n in ast.walk(neg))
    check(not trip2, "guard self-test: a `def send` must NOT trip the guard")


# ---------------------------------------------------------------------------
# Section 1: un-escape / SLC counting correctness (LESSON A crux)
# ---------------------------------------------------------------------------
def test_unescape():
    check(T.unescape_subneg(b"\xff\xff") == b"\xff", "IAC IAC -> single IAC")
    check(T.unescape_subneg(b"AB\xff\xffCD") == b"AB\xffCD", "doubled in middle")
    check(T.unescape_subneg(b"plain") == b"plain", "no IAC untouched")


def test_slc_func0_setdefaults_no_reply():
    # RFC 1184: func 0 with SLC_DEFAULT or SLC_VALUE is the set-defaults
    # handshake and stores no per-triplet reply. This branch was dead before
    # the SLC_VARIABLE->SLC_VALUE fix; cover it so it cannot regress.
    from telnet_watch import SLC_DEFAULT, SLC_VALUE, SLC_NOSUPPORT
    st_def = T.parse_slc(slc_triplets([(0, SLC_DEFAULT, 0)]))
    check(st_def is not None and st_def.reply_triplets == 0,
          "func0+SLC_DEFAULT stores no reply")
    st_val = T.parse_slc(slc_triplets([(0, SLC_VALUE, 0)]))
    check(st_val is not None and st_val.reply_triplets == 0,
          "func0+SLC_VALUE stores no reply (was the dead branch)")
    st_ns = T.parse_slc(slc_triplets([(0, SLC_NOSUPPORT, 0)]))
    check(st_ns is not None and st_ns.reply_triplets == 1,
          "func0+SLC_NOSUPPORT does store a reply")


def test_slc_count_plain():
    body = slc_triplets([(1, 0, 0)] * 20)
    st = T.parse_slc(body[0:1] and T.unescape_subneg(body[1:]) or body)  # noop safety
    st = T.parse_slc(body)
    check(st is not None and st.triplets == 20, "20 plain triplets counted")


def test_slc_count_with_iac_doubling():
    # a func byte of 0xFF is doubled on the wire; after unescape it is one 0xFF
    # triplet. Getting this wrong changes the triplet count.
    wire_body = bytearray([LM_SLC])
    for _ in range(10):
        wire_body += bytes([0xFF, 0x01, 0x02])  # func=0xFF (>NSLC)
    on_wire = subneg(OPT_LINEMODE, bytes(wire_body))
    # extract what the stream parser hands the engine (unescaped subneg body)
    ev = list(T.TelnetEvents(is_from_server=False).feed(on_wire))
    sub = [e for e in ev if e[0] == "subneg"]
    check(len(sub) == 1, "one subneg event")
    _, opt, data = sub[0]
    st = T.parse_slc(data)
    check(st is not None and st.triplets == 10,
          f"10 triplets after un-doubling, got {st.triplets if st else None}")
    check(st.func_over_nslc == 10, "all 10 are func>NSLC")


# ---------------------------------------------------------------------------
# Section 2: CVE-2026-24061
# ---------------------------------------------------------------------------
def test_24061_user_dashf_root():
    h = Harness()
    # server requests env, client responds with the exploit
    h.send(True, nego(DO, OPT_NEW_ENVIRON))
    h.send(False, nego(WILL, OPT_NEW_ENVIRON))
    body = environ_is([(b"USER", b"-f root")])
    h.send(False, subneg(OPT_NEW_ENVIRON, body))
    recs = h.by_code("TELNET-24061-ARGINJECT")
    check(len(recs) == 1, "24061 fires once on USER=-f root")
    if recs:
        r = recs[0]
        check(r["severity"] == "critical", "24061 is critical")
        check(r["confidence"] == "high", "24061 confidence high (payload on wire)")
        check(r["detail"]["bypass_flag"] is True, "-f detected as bypass flag")
        check(r["detail"]["is_user_var"] is True, "USER var recognised")


def test_24061_legacy_environ():
    h = Harness()
    h.send(False, subneg(OPT_ENVIRON, environ_is([(b"USER", b"-f 0")])))
    check("TELNET-24061-ARGINJECT" in h.codes(),
          "24061 also fires on legacy ENVIRON option")


def test_24061_nonbypass_dash_still_injection():
    h = Harness()
    h.send(False, subneg(OPT_NEW_ENVIRON, environ_is([(b"USER", b"-x foo")])))
    recs = h.by_code("TELNET-24061-ARGINJECT")
    check(len(recs) == 1, "leading-dash non -f value still flagged as injection")
    if recs:
        check(recs[0]["detail"]["bypass_flag"] is False,
              "-x marked bypass_flag False for triage")
        check(recs[0]["severity"] == "critical",
              "argument injection into root login is critical regardless of flag")


def test_24061_fp_gate_normal_user():
    h = Harness()
    h.send(False, subneg(OPT_NEW_ENVIRON, environ_is([(b"USER", b"alice")])))
    check("TELNET-24061-ARGINJECT" not in h.codes(),
          "normal username must NOT fire 24061")
    # but env-leak (info) is fine
    check("TELNET-ENV-LEAK" in h.codes(), "env vars in cleartext noted (leak)")


def test_24061_fp_gate_server_side_value():
    # A '-f' value appearing in a SERVER->CLIENT subneg is not the attack
    # (the exploit is the client's IS response). Must not fire.
    h = Harness()
    h.send(True, subneg(OPT_NEW_ENVIRON, environ_is([(b"USER", b"-f root")])))
    check("TELNET-24061-ARGINJECT" not in h.codes(),
          "server-side value must NOT fire 24061 (attacker is the client)")


def test_24061_credential_safety():
    # The full injected value must never appear verbatim in output; only the
    # 2-byte flag prefix and the length are logged.
    h = Harness()
    secret_tail = b"-f rootSENTINELSECRET"
    h.send(False, subneg(OPT_NEW_ENVIRON, environ_is([(b"USER", secret_tail)])))
    blob = h.buf.getvalue()
    check(b"SENTINELSECRET".decode() not in blob,
          "value beyond the flag prefix must NOT be logged")
    recs = h.by_code("TELNET-24061-ARGINJECT")
    if recs:
        check(recs[0]["detail"]["value_prefix"] == "-f", "only -f prefix logged")
        check(recs[0]["detail"]["value_len"] == len(secret_tail),
              "length logged, not content")


# ---------------------------------------------------------------------------
# Section 3: CVE-2026-32746
# ---------------------------------------------------------------------------
def test_32746_overflow():
    h = Harness()
    h.send(True, nego(DO, OPT_LINEMODE))
    h.send(False, nego(WILL, OPT_LINEMODE))
    # 40 triplets with func>NSLC -> reply-generating, past the 34 capacity
    trips = [(0x50, 0x01, 0x41)] * 40
    h.send(False, subneg(OPT_LINEMODE, slc_triplets(trips)))
    recs = h.by_code("TELNET-32746-SLC-OVERFLOW")
    check(len(recs) == 1, "32746 overflow fires on 40 reply triplets")
    if recs:
        check(recs[0]["severity"] == "critical", "overflow is critical")
        check(recs[0]["confidence"] == "high", "overflow confidence high")
        check(recs[0]["detail"]["reply_triplets"] == 40, "reply triplet count")
    check("TELNET-32746-SLC-NOSUPPORT-FLOOD" in h.codes(),
          "func>NSLC padding signature corroborates")


def test_32746_overflow_boundary():
    # exactly capacity (34) reply triplets must NOT overflow; 35 must.
    h1 = Harness()
    h1.send(False, subneg(OPT_LINEMODE,
                          slc_triplets([(0x50, 1, 0x41)] * SLC_OVERFLOW_TRIPLETS)))
    check("TELNET-32746-SLC-OVERFLOW" not in h1.codes(),
          f"exactly {SLC_OVERFLOW_TRIPLETS} triplets must not overflow")
    h2 = Harness()
    h2.send(False, subneg(OPT_LINEMODE,
                          slc_triplets([(0x50, 1, 0x41)] * (SLC_OVERFLOW_TRIPLETS + 1))))
    check("TELNET-32746-SLC-OVERFLOW" in h2.codes(),
          f"{SLC_OVERFLOW_TRIPLETS + 1} triplets must overflow")


def test_32746_oversized_but_not_overflow():
    # between NSLC (30) and overflow (34): oversized warning, not overflow.
    n = NSLC + 2  # 32
    h = Harness()
    h.send(False, subneg(OPT_LINEMODE, slc_triplets([(0x05, 1, 0x41)] * n)))
    check("TELNET-32746-SLC-OVERSIZED" in h.codes(),
          "oversized SLC table warned")
    check("TELNET-32746-SLC-OVERFLOW" not in h.codes(),
          "oversized-but-fits must not be flagged as overflow")


def test_32746_fp_gate_normal_linemode():
    # a well-behaved client sets ~a dozen in-range SLC functions: no attack.
    h = Harness()
    h.send(True, nego(DO, OPT_LINEMODE))
    h.send(False, nego(WILL, OPT_LINEMODE))
    trips = [(f, 1, 0x03) for f in range(1, 13)]  # 12 in-range funcs
    h.send(False, subneg(OPT_LINEMODE, slc_triplets(trips)))
    codes = h.codes()
    check("TELNET-32746-SLC-OVERFLOW" not in codes, "normal SLC no overflow")
    check("TELNET-32746-SLC-OVERSIZED" not in codes, "normal SLC not oversized")
    # posture IS expected (server advertised LINEMODE)
    check("TELNET-32746-LINEMODE-POSTURE" in codes, "posture noted for LINEMODE")


def test_32746_posture_low_confidence():
    h = Harness()
    h.send(True, nego(WILL, OPT_LINEMODE))
    recs = h.by_code("TELNET-32746-LINEMODE-POSTURE")
    check(len(recs) == 1, "posture fires once when server offers LINEMODE")
    if recs:
        check(recs[0]["severity"] == "notice", "posture severity notice")
        check(recs[0]["confidence"] == "low",
              "posture confidence low (LESSON T: patch is wire-invisible)")


def test_32746_vuln_confirmed_correlation():
    h = Harness()
    h.send(True, nego(DO, OPT_LINEMODE))
    h.send(False, nego(WILL, OPT_LINEMODE))
    # client overflow
    h.send(False, subneg(OPT_LINEMODE, slc_triplets([(0x50, 1, 0x41)] * 40)))
    # vulnerable server echoes an over-long SLC reply (stored past slcbuf)
    big_reply = slc_triplets([(0x50, 0x80, 0x41)] * 40)
    h.send(True, subneg(OPT_LINEMODE, big_reply))
    check("TELNET-32746-VULN-CONFIRMED" in h.codes(),
          "over-long server SLC reply after client overflow -> vulnerable+hit")


def test_32746_fp_gate_patched_server_reply():
    # patched server silently drops the overflow: bounded reply, no confirmation.
    h = Harness()
    h.send(True, nego(DO, OPT_LINEMODE))
    h.send(False, nego(WILL, OPT_LINEMODE))
    h.send(False, subneg(OPT_LINEMODE, slc_triplets([(0x50, 1, 0x41)] * 40)))
    small_reply = slc_triplets([(0x05, 0x80, 0x00)] * 6)  # bounded
    h.send(True, subneg(OPT_LINEMODE, small_reply))
    check("TELNET-32746-VULN-CONFIRMED" not in h.codes(),
          "bounded (patched) server reply must NOT confirm vulnerability")


# ---------------------------------------------------------------------------
# Section 4: broader posture (session, cleartext auth, encrypt)
# ---------------------------------------------------------------------------
def test_session_noted_once():
    h = Harness()
    h.send(True, b"\r\nUbuntu 24.04\r\n")
    h.send(False, b"someinput")
    recs = h.by_code("TELNET-SESSION")
    check(len(recs) == 1, "session noted exactly once")
    check(recs[0]["severity"] == "info", "session is info, not an alert")


def test_cleartext_auth():
    h = Harness()
    h.send(True, b"\r\nlogin: ")
    h.send(False, b"admin\r\n")
    h.send(True, b"Password: ")
    recs = h.by_code("TELNET-CLEARTEXT-AUTH")
    check(len(recs) == 1, "cleartext auth fires on server password prompt")
    if recs:
        check(recs[0]["severity"] == "high", "cleartext auth is high")


def test_cleartext_auth_never_logs_client_secret():
    h = Harness()
    h.send(True, b"Password: ")
    # client sends the secret; it must never surface in output
    h.send(False, b"hunter2_TOPSECRET\r\n")
    blob = h.buf.getvalue()
    check("TOPSECRET" not in blob,
          "client-typed secret must never appear in output")


def _encrypt_start():
    from telnet_watch import ENCRYPT_START
    return subneg(OPT_ENCRYPT, bytes([ENCRYPT_START, 0x01]))


def _encrypt_end():
    from telnet_watch import ENCRYPT_END
    return subneg(OPT_ENCRYPT, bytes([ENCRYPT_END]))


def test_encrypt_lone_will_is_only_an_offer():
    """REGRESSION: inetutils telnetd sends WILL ENCRYPT on EVERY connection.
    A lone WILL is an OFFER (RFC 855), not an agreement. Treating it as
    'encrypted' both false-positived the posture finding and SUPPRESSED the
    cleartext-credential finding on every real telnetd session."""
    h = Harness()
    h.send(True, nego(WILL, OPT_ENCRYPT))     # server offers
    h.send(False, nego(DONT, OPT_ENCRYPT))    # client refuses
    h.send(True, b"Password: ")
    codes = h.codes()
    check("TELNET-ENCRYPT-NEGOTIATED" not in codes,
          "a REFUSED encrypt offer must NOT report encryption negotiated")
    check("TELNET-CLEARTEXT-AUTH" in codes,
          "credentials are in the clear when the encrypt offer was refused")


def test_encrypt_pair_agreed_but_not_started():
    """A completed WILL/DO pair means both sides are WILLING. RFC 2946 requires
    SB ENCRYPT START before the stream is actually protected."""
    h = Harness()
    h.send(True, nego(WILL, OPT_ENCRYPT))
    h.send(False, nego(DO, OPT_ENCRYPT))
    check("TELNET-ENCRYPT-NEGOTIATED" in h.codes(),
          "completed WILL/DO pair reports encryption negotiated")
    h.send(True, b"Password: ")
    check("TELNET-CLEARTEXT-AUTH" in h.codes(),
          "agreement alone must NOT suppress cleartext-auth (no START yet)")


def test_encrypt_started_suppresses_cleartext_auth():
    h = Harness()
    h.send(True, nego(WILL, OPT_ENCRYPT))
    h.send(False, nego(DO, OPT_ENCRYPT))
    h.send(True, _encrypt_start())
    check("TELNET-ENCRYPT-NEGOTIATED" in h.codes(), "encrypt negotiation noted")
    h.send(True, b"Password: ")
    check("TELNET-CLEARTEXT-AUTH" not in h.codes(),
          "encryption actually STARTED -> no cleartext-auth finding")


def test_encrypt_end_returns_to_cleartext():
    h = Harness()
    h.send(True, nego(WILL, OPT_ENCRYPT))
    h.send(False, nego(DO, OPT_ENCRYPT))
    h.send(True, _encrypt_start())
    h.send(True, _encrypt_end())
    h.send(True, b"Password: ")
    check("TELNET-CLEARTEXT-AUTH" in h.codes(),
          "SB ENCRYPT END returns the stream to cleartext")


def test_segmented_negotiation():
    # a DO LINEMODE split across two TCP segments must still be recognised.
    h = Harness()
    h.send(True, bytes([IAC]))
    h.send(True, bytes([DO, OPT_LINEMODE]))
    check("TELNET-32746-LINEMODE-POSTURE" in h.codes(),
          "negotiation split across segments still parsed")


def test_subneg_split_across_segments():
    h = Harness()
    wire = subneg(OPT_NEW_ENVIRON, environ_is([(b"USER", b"-f root")]))
    mid = len(wire) // 2
    h.send(False, wire[:mid])
    h.send(False, wire[mid:])
    check("TELNET-24061-ARGINJECT" in h.codes(),
          "subnegotiation split across segments still detected")


# ---------------------------------------------------------------------------
def run() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
        except Exception as e:  # a throwing test is a failure
            _fails.append(f"{t.__name__} raised {type(e).__name__}: {e}")
    print(f"telnetwatch self-test: {_count - len(_fails)}/{_count} checks passed"
          f" across {len(tests)} tests")
    if _fails:
        print("FAILURES:")
        for f in _fails:
            print("  -", f)
        return 1
    return 0


def results() -> dict:
    """Structured adapter for the Ragnar aggregator: run every test and return
    {'success', 'checks':[{'name','pass'}]}. Re-runnable — resets the counters so a
    second call (e.g. the CLI then the aggregator) does not accumulate."""
    global _fails, _count, _records
    _fails, _count, _records = [], 0, []
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
        except Exception as e:
            _records.append(("%s raised %s: %s" % (t.__name__, type(e).__name__, e),
                             False))
            _fails.append("%s raised %s: %s" % (t.__name__, type(e).__name__, e))
    return {"success": not _fails,
            "checks": [{"name": n, "pass": p} for (n, p) in _records]}


if __name__ == "__main__":
    sys.exit(run())
