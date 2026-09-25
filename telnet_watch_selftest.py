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
    IAC, SB, SE, DO, DONT, WILL, WONT, EC, EL, AYT, NOP, GA, DM,
    OPT_LINEMODE, OPT_NEW_ENVIRON, OPT_ENVIRON, OPT_ECHO, OPT_ENCRYPT,
    ENV_IS, ENV_VAR, ENV_VALUE, ENV_USERVAR,
    LM_SLC, NSLC, SLC_OVERFLOW_TRIPLETS, SLCBUF_SIZE, SLC_VALUE,
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
    check(len(FINDINGS) == 26, f"expected 26 finding codes, got {len(FINDINGS)}")
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
# Dual-stack (PRIME DIRECTIVE): the engine is address-family agnostic, but the
# EMITTED endpoint form is not. Telnet's protocol logic is identical over both
# families, so detection must be byte-identical; only rendering differs.
# ---------------------------------------------------------------------------
V6_KEY = ("2001:db8::9", 51000, "2001:db8::1", 23)


class HarnessV6(Harness):
    def send(self, from_server: bool, payload: bytes):
        self.t += 0.01
        self.eng.on_payload(V6_KEY, from_server, payload, now=self.t)


def test_v6_endpoint_bracket_notation():
    check(T.fmt_endpoint("10.0.0.9", 23) == "10.0.0.9:23", "IPv4 endpoint plain")
    check(T.fmt_endpoint("2001:db8::9", 51000) == "[2001:db8::9]:51000",
          "IPv6 endpoint bracketed (RFC 3986)")
    check(T.fmt_endpoint("::1", 23) == "[::1]:23", "loopback IPv6 bracketed")


def test_v6_arginject_parity():
    h = HarnessV6()
    h.send(False, subneg(OPT_NEW_ENVIRON, environ_is([(b"USER", b"-f root")])))
    recs = h.by_code("TELNET-24061-ARGINJECT")
    check(len(recs) == 1, "24061 fires identically over IPv6")
    if recs:
        check(recs[0]["client"] == "[2001:db8::9]:51000",
              f"IPv6 client bracketed in output; got {recs[0]['client']!r}")
        check(recs[0]["af"] == "ipv6", "finding tagged af=ipv6")
        check(recs[0]["detail"]["bypass_flag"] is True,
              "detail is identical over IPv6 (no AF-specific drift)")


def test_v6_slc_overflow_parity():
    h = HarnessV6()
    h.send(False, subneg(OPT_LINEMODE, slc_triplets([(0x50, SLC_VALUE, 0x41)] * 40)))
    check("TELNET-32746-SLC-OVERFLOW" in h.codes(),
          "32746 overflow fires identically over IPv6")


def test_v6_v4_detection_is_byte_identical():
    """Same payloads, two families -> identical code sets. Telnet is
    address-family agnostic, so ANY divergence is a bug."""
    payloads = [
        (True,  nego(WILL, OPT_LINEMODE)),
        (False, subneg(OPT_NEW_ENVIRON, environ_is([(b"USER", b"-f root")]))),
        (False, subneg(OPT_LINEMODE, slc_triplets([(0x50, SLC_VALUE, 0x41)] * 40))),
        (True,  b"Password: "),
    ]
    h4, h6 = Harness(), HarnessV6()
    for frm, pay in payloads:
        h4.send(frm, pay)
        h6.send(frm, pay)
    check(h4.codes() == h6.codes(),
          f"IPv4 and IPv6 produce identical findings\n"
          f"    v4={h4.codes()}\n    v6={h6.codes()}")
    check(len(h6.codes()) >= 4, "non-vacuity: several codes fired in the parity run")
    # and the ONLY difference in the records is the rendered endpoint / af tag
    for r4, r6 in zip(h4.records(), h6.records()):
        d4 = {k: v for k, v in r4.items() if k not in ("client", "server", "af", "ts")}
        d6 = {k: v for k, v in r6.items() if k not in ("client", "server", "af", "ts")}
        check(d4 == d6, f"only endpoint/af differ between families for {r4['code']}")



# ---------------------------------------------------------------------------
# CVE-2011-4862 -- ENCRYPT ENC_KEYID/DEC_KEYID heap overflow
# ---------------------------------------------------------------------------
def _keyid(sub, n, byte=b"A"):
    return subneg(OPT_ENCRYPT, bytes([sub]) + byte * n)


def test_4862_enc_keyid_overflow():
    from telnet_watch import ENCRYPT_ENC_KEYID, MAXKEYLEN
    h = Harness()
    h.send(False, _keyid(ENCRYPT_ENC_KEYID, 200))
    recs = h.by_code("TELNET-4862-KEYID-OVERFLOW")
    check(len(recs) == 1, "4862 fires on a 200-byte ENC_KEYID")
    if recs:
        r = recs[0]
        check(r["severity"] == "critical", "4862 is critical")
        check(r["confidence"] == "high",
              "4862 confidence high (length is countable on the wire)")
        check(r["detail"]["subcmd"] == "ENC_KEYID", "sub-command identified")
        check(r["detail"]["keyid_len"] == 200, "key id length recorded")
        check(r["detail"]["maxkeylen"] == MAXKEYLEN, "MAXKEYLEN(64) recorded")
        check(r["detail"]["overflow_bytes"] == 200 - MAXKEYLEN,
              "overflow size recorded")


def test_4862_dec_keyid_also_covered():
    """encrypt_dec_keyid() funnels into the SAME encrypt_keyid(), so
    sub-command 8 is as dangerous as 7 and must not be missed."""
    from telnet_watch import ENCRYPT_DEC_KEYID
    h = Harness()
    h.send(False, _keyid(ENCRYPT_DEC_KEYID, 120, b"B"))
    recs = h.by_code("TELNET-4862-KEYID-OVERFLOW")
    check(len(recs) == 1, "4862 fires on DEC_KEYID too")
    if recs:
        check(recs[0]["detail"]["subcmd"] == "DEC_KEYID", "DEC_KEYID identified")


def test_4862_boundary_at_maxkeylen():
    """MAXKEYLEN bytes fit; one more is the vulnerable condition."""
    from telnet_watch import ENCRYPT_ENC_KEYID, MAXKEYLEN
    h_ok = Harness()
    h_ok.send(False, _keyid(ENCRYPT_ENC_KEYID, MAXKEYLEN))
    check("TELNET-4862-KEYID-OVERFLOW" not in h_ok.codes(),
          f"exactly MAXKEYLEN({MAXKEYLEN}) must NOT fire")
    h_bad = Harness()
    h_bad.send(False, _keyid(ENCRYPT_ENC_KEYID, MAXKEYLEN + 1))
    check("TELNET-4862-KEYID-OVERFLOW" in h_bad.codes(),
          f"MAXKEYLEN+1 ({MAXKEYLEN + 1}) MUST fire")


def test_4862_fp_gate_normal_keyid():
    """A real key id is a handful of bytes; it must never alarm."""
    from telnet_watch import ENCRYPT_ENC_KEYID
    for n in (0, 1, 8, 16):
        h = Harness()
        h.send(False, _keyid(ENCRYPT_ENC_KEYID, n))
        check("TELNET-4862-KEYID-OVERFLOW" not in h.codes(),
              f"a {n}-byte key id must NOT fire 4862")


def test_4862_fp_gate_other_subcommands():
    """START/END/SUPPORT carry no key id and must not be length-checked."""
    from telnet_watch import ENCRYPT_START, ENCRYPT_SUPPORT
    for sub, label in ((ENCRYPT_START, "START"), (ENCRYPT_SUPPORT, "SUPPORT")):
        h = Harness()
        h.send(False, subneg(OPT_ENCRYPT, bytes([sub]) + b"Z" * 200))
        check("TELNET-4862-KEYID-OVERFLOW" not in h.codes(),
              f"a long ENCRYPT {label} payload must NOT fire 4862")


def test_4862_iac_escaped_keyid_counted_correctly():
    """LESSON A: 0xFF inside the key id is doubled on the wire. The length that
    matters is the UN-DOUBLED one, or the overflow decision is wrong."""
    from telnet_watch import ENCRYPT_ENC_KEYID, MAXKEYLEN
    # 40 real 0xFF bytes -> 80 bytes on the wire, but only 40 after un-doubling,
    # which is UNDER MAXKEYLEN and must NOT fire.
    h = Harness()
    h.send(False, subneg(OPT_ENCRYPT, bytes([ENCRYPT_ENC_KEYID]) + b"\xff" * 40))
    check("TELNET-4862-KEYID-OVERFLOW" not in h.codes(),
          "40 doubled 0xFF bytes (80 on the wire) is UNDER MAXKEYLEN -> no fire")
    # 70 real 0xFF bytes -> over MAXKEYLEN after un-doubling, must fire
    h2 = Harness()
    h2.send(False, subneg(OPT_ENCRYPT, bytes([ENCRYPT_ENC_KEYID]) + b"\xff" * 70))
    recs = h2.by_code("TELNET-4862-KEYID-OVERFLOW")
    check(len(recs) == 1, "70 doubled 0xFF bytes is OVER MAXKEYLEN -> fires")
    if recs:
        check(recs[0]["detail"]["keyid_len"] == 70,
              f"length is the UN-DOUBLED one; got {recs[0]['detail']['keyid_len']}")


# ---------------------------------------------------------------------------
# CVE-2022-39028 -- telrcv() EC/EL NULL dereference (2-byte DoS)
# ---------------------------------------------------------------------------
def test_39028_ec_el_preauth():
    from telnet_watch import EC, EL
    for cmd, label in ((EC, "EC"), (EL, "EL")):
        h = Harness()
        h.send(False, bytes([IAC, cmd]))
        recs = h.by_code("TELNET-39028-EC-EL-PREAUTH")
        check(len(recs) == 1, f"39028 fires on a bare IAC {label}")
        if recs:
            check(recs[0]["severity"] == "warning",
                  "39028 is warning (DoS, not RCE)")
            check(recs[0]["detail"]["cmd"] == label, f"{label} identified")


def test_39028_fp_gate_legitimate_erase():
    """EC/EL are ordinary RFC 854 commands -- a real client sends them on
    backspace. After data has flowed the pointer is valid, so they are benign
    and matching the bytes alone would alarm on every interactive session."""
    from telnet_watch import EC, EL
    for cmd, label in ((EC, "EC"), (EL, "EL")):
        h = Harness()
        h.send(False, b"admin")
        h.send(False, bytes([IAC, cmd]))
        check("TELNET-39028-EC-EL-PREAUTH" not in h.codes(),
              f"IAC {label} AFTER client data must NOT fire (legit erase)")


def test_39028_fp_gate_same_segment_after_data():
    """Data and the command in ONE segment: ordering inside feed() decides it."""
    from telnet_watch import EC
    h = Harness()
    h.send(False, b"admin" + bytes([IAC, EC]))
    check("TELNET-39028-EC-EL-PREAUTH" not in h.codes(),
          "data then EC in the same segment is a legit erase")


def test_39028_direction_gate():
    from telnet_watch import EC
    h = Harness()
    h.send(True, bytes([IAC, EC]))
    check("TELNET-39028-EC-EL-PREAUTH" not in h.codes(),
          "server-side EC must NOT fire (the attacker is the client)")


def test_39028_other_two_byte_commands_ignored():
    """Only EC and EL reach the vulnerable path; AYT/NOP/GA must not alarm."""
    from telnet_watch import AYT, NOP, GA, DM
    for cmd, label in ((AYT, "AYT"), (NOP, "NOP"), (GA, "GA"), (DM, "DM")):
        h = Harness()
        h.send(False, bytes([IAC, cmd]))
        check("TELNET-39028-EC-EL-PREAUTH" not in h.codes(),
              f"IAC {label} must NOT fire 39028")


def test_39028_crash_loop_across_flows():
    """Each attempt kills one telnetd; inetd disables a service that loops, so
    the cumulative per-SERVER count is the operationally important signal."""
    from telnet_watch import EC
    buf = io.StringIO()
    em = T.Emitter(out=buf, min_sev="info", dedup_secs=0.0)
    eng = T.Engine(em, crash_loop_threshold=5)
    for i in range(6):
        eng.on_payload(("10.0.0.9", 52000 + i, "10.0.0.1", 23), False,
                       bytes([IAC, EC]), now=1000.0 + i)
    codes = [json.loads(l)["code"] for l in buf.getvalue().splitlines() if l.strip()]
    check("TELNET-39028-CRASH-LOOP" in codes,
          f"crash loop fires once the per-server threshold is crossed; got "
          f"{sorted(set(codes))}")
    check(codes.count("TELNET-39028-EC-EL-PREAUTH") == 6,
          "every individual attempt is still reported")


def test_39028_crash_loop_below_threshold():
    from telnet_watch import EC
    buf = io.StringIO()
    eng = T.Engine(T.Emitter(out=buf, dedup_secs=0.0), crash_loop_threshold=5)
    for i in range(4):
        eng.on_payload(("10.0.0.9", 53000 + i, "10.0.0.1", 23), False,
                       bytes([IAC, EC]), now=1000.0 + i)
    codes = [json.loads(l)["code"] for l in buf.getvalue().splitlines() if l.strip()]
    check("TELNET-39028-CRASH-LOOP" not in codes,
          "four attempts is below the threshold and must not fire the loop code")


def test_39028_crash_loop_is_per_server():
    """Attempts spread across DIFFERENT servers must not aggregate."""
    from telnet_watch import EC
    buf = io.StringIO()
    eng = T.Engine(T.Emitter(out=buf, dedup_secs=0.0), crash_loop_threshold=5)
    for i in range(6):
        eng.on_payload(("10.0.0.9", 54000 + i, f"10.0.0.{50 + i}", 23), False,
                       bytes([IAC, EC]), now=1000.0 + i)
    codes = [json.loads(l)["code"] for l in buf.getvalue().splitlines() if l.strip()]
    check("TELNET-39028-CRASH-LOOP" not in codes,
          "six attempts against six DIFFERENT servers must not fire the loop")


# ---------------------------------------------------------------------------
# Dual-stack parity for the two new CVEs (PRIME DIRECTIVE)
# ---------------------------------------------------------------------------
def test_new_cves_dualstack_parity():
    from telnet_watch import ENCRYPT_ENC_KEYID, EC
    for label, payload, code in (
        ("4862", _keyid(ENCRYPT_ENC_KEYID, 200), "TELNET-4862-KEYID-OVERFLOW"),
        ("39028", bytes([IAC, EC]), "TELNET-39028-EC-EL-PREAUTH"),
    ):
        h4, h6 = Harness(), HarnessV6()
        h4.send(False, payload)
        h6.send(False, payload)
        check(h4.codes() == h6.codes(),
              f"{label}: identical findings across families\n"
              f"    v4={h4.codes()}\n    v6={h6.codes()}")
        check(code in h6.codes(), f"{label} fires over IPv6")
        r6 = [r for r in h6.records() if r["code"] == code]
        if r6:
            check(r6[0]["client"].startswith("["),
                  f"{label} IPv6 endpoint bracketed")
            check(r6[0]["af"] == "ipv6", f"{label} tagged af=ipv6")



# ---------------------------------------------------------------------------
# rlogin (RFC 1282) -- r-services fold-in
# ---------------------------------------------------------------------------
RL_KEY = ("10.0.0.9", 900, "10.0.0.1", 513)          # privileged source port
RL_KEY_UNPRIV = ("10.0.0.9", 51000, "10.0.0.1", 513)
RL_KEY_FTPDATA = ("10.0.0.9", 20, "10.0.0.1", 513)
RL_KEY_V6 = ("2001:db8::9", 900, "2001:db8::1", 513)


def rl_handshake(client_user=b"alice", server_user=b"bob",
                 term=b"vt100/38400", leading_nul=True):
    out = b"\x00" if leading_nul else b""
    return out + client_user + b"\x00" + server_user + b"\x00" + term + b"\x00"


class RlHarness:
    def __init__(self, key=RL_KEY):
        self.key = key
        self.buf = io.StringIO()
        self.em = T.Emitter(out=self.buf, min_sev="info", dedup_secs=0.0)
        self.eng = T.RloginEngine(self.em)
        self.t = 1000.0

    def send(self, from_server, payload):
        self.t += 0.01
        self.eng.on_payload(self.key, from_server, payload, now=self.t)

    def records(self):
        return [json.loads(l) for l in self.buf.getvalue().splitlines() if l.strip()]

    def codes(self):
        return [r["code"] for r in self.records()]

    def by_code(self, c):
        return [r for r in self.records() if r["code"] == c]


def test_rlogin_session_noted_once():
    h = RlHarness()
    h.send(False, rl_handshake())
    h.send(True, b"\x00")
    recs = h.by_code("RSVC-RLOGIN-SESSION")
    check(len(recs) == 1, "rlogin session noted exactly once")
    if recs:
        check(recs[0]["severity"] == "info", "rlogin session is info, not an alert")


def test_rlogin_handshake_parse():
    hs = T.parse_rlogin_handshake(rl_handshake(b"alice", b"bob", b"xterm/9600"))
    check(hs.complete, "handshake parses as complete")
    check(hs.client_user == b"alice", f"client user; got {hs.client_user!r}")
    check(hs.server_user == b"bob", f"server user; got {hs.server_user!r}")
    check(hs.term == b"xterm/9600", f"term; got {hs.term!r}")


def test_rlogin_handshake_without_leading_nul():
    """RFC 1282 specifies a leading NUL but clients vary; refusing to parse
    without it would silently drop the exploit case."""
    hs = T.parse_rlogin_handshake(rl_handshake(b"alice", b"-froot",
                                               leading_nul=False))
    check(hs.complete, "handshake without a leading NUL still parses")
    check(hs.server_user == b"-froot",
          f"server user recovered; got {hs.server_user!r}")


def test_rlogin_1999_0113_arginject():
    h = RlHarness()
    h.send(False, rl_handshake(b"alice", b"-froot"))
    recs = h.by_code("RSVC-RLOGIN-ARGINJECT")
    check(len(recs) == 1, "CVE-1999-0113 fires on a '-froot' server user")
    if recs:
        r = recs[0]
        check(r["severity"] == "critical", "rlogin arginject is critical")
        check(r["confidence"] == "high", "confidence high (payload on the wire)")
        check(r["detail"]["field"] == "server_user", "field identified")
        check(r["detail"]["bypass_flag"] is True, "-f marked as the bypass flag")
        check(r["detail"]["value_prefix"] == "-f", "only the flag prefix logged")


def test_rlogin_arginject_client_user_field_too():
    """Either user field is attacker-supplied; both must be checked."""
    h = RlHarness()
    h.send(False, rl_handshake(b"-froot", b"bob"))
    recs = h.by_code("RSVC-RLOGIN-ARGINJECT")
    check(len(recs) == 1, "arginject in the client_user field is caught")
    if recs:
        check(recs[0]["detail"]["field"] == "client_user", "field identified")


def test_rlogin_arginject_credential_safety():
    """Only the two-byte flag prefix and a length may be logged."""
    h = RlHarness()
    h.send(False, rl_handshake(b"alice", b"-fRLSENTINELSECRET"))
    check("RLSENTINELSECRET" not in h.buf.getvalue(),
          "the injected value beyond the flag prefix must NOT be logged")
    recs = h.by_code("RSVC-RLOGIN-ARGINJECT")
    if recs:
        check(recs[0]["detail"]["value_len"] == len(b"-fRLSENTINELSECRET"),
              "length is logged, not content")


def test_rlogin_arginject_fp_gate_normal_users():
    for cu, su in ((b"alice", b"bob"), (b"root", b"root"), (b"svc-acct", b"ops")):
        h = RlHarness()
        h.send(False, rl_handshake(cu, su))
        check("RSVC-RLOGIN-ARGINJECT" not in h.codes(),
              f"normal users {cu!r}/{su!r} must NOT fire arginject")


def test_rlogin_handshake_split_across_segments():
    h = RlHarness()
    h.send(False, b"\x00alice\x00")
    h.send(False, b"-froot\x00vt100/38400\x00")
    check("RSVC-RLOGIN-ARGINJECT" in h.codes(),
          "a handshake split across TCP segments is still parsed")


def test_rlogin_1999_0185_ftpdata_srcport():
    h = RlHarness(key=RL_KEY_FTPDATA)
    h.send(False, rl_handshake())
    recs = h.by_code("RSVC-FTPDATA-SRCPORT")
    check(len(recs) == 1, "CVE-1999-0185 fires on source port 20 -> rlogin")
    if recs:
        check(recs[0]["severity"] == "critical", "ftp-data bounce is critical")
        check(recs[0]["detail"]["src_port"] == 20, "source port recorded")


def test_rlogin_unprivileged_source_port():
    h = RlHarness(key=RL_KEY_UNPRIV)
    h.send(False, rl_handshake())
    recs = h.by_code("RSVC-UNPRIV-SRCPORT")
    check(len(recs) == 1, "unprivileged source port is reported")
    if recs:
        check(recs[0]["detail"]["src_port"] == 51000, "source port recorded")
    check("RSVC-FTPDATA-SRCPORT" not in h.codes(),
          "an ordinary high port is not an ftp-data bounce")


def test_rlogin_privileged_source_port_is_silent():
    """A privileged source port is the NORMAL case and must raise neither
    source-port finding -- otherwise every legitimate rlogin alarms."""
    for sport in (513, 900, 1023):
        h = RlHarness(key=("10.0.0.9", sport, "10.0.0.1", 513))
        h.send(False, rl_handshake())
        c = h.codes()
        check("RSVC-UNPRIV-SRCPORT" not in c,
              f"privileged source port {sport} must not fire unpriv")
        check("RSVC-FTPDATA-SRCPORT" not in c,
              f"privileged source port {sport} must not fire ftpdata")


def test_rlogin_srcport_boundary():
    h_ok = RlHarness(key=("10.0.0.9", T.PRIV_PORT_MAX, "10.0.0.1", 513))
    h_ok.send(False, rl_handshake())
    check("RSVC-UNPRIV-SRCPORT" not in h_ok.codes(),
          f"port {T.PRIV_PORT_MAX} is privileged and must not fire")
    h_bad = RlHarness(key=("10.0.0.9", T.PRIV_PORT_MAX + 1, "10.0.0.1", 513))
    h_bad.send(False, rl_handshake())
    check("RSVC-UNPRIV-SRCPORT" in h_bad.codes(),
          f"port {T.PRIV_PORT_MAX + 1} is unprivileged and MUST fire")


def test_rlogin_trust_auth():
    h = RlHarness()
    h.send(False, rl_handshake())
    h.send(True, b"\x00")
    h.send(True, b"Last login: Tue Sep 23\r\n$ ")
    recs = h.by_code("RSVC-TRUST-AUTH")
    check(len(recs) == 1, "trust auth fires when a shell arrives with no password")
    if recs:
        check(recs[0]["severity"] == "high", "trust auth is high")


def test_rlogin_trust_auth_not_on_bare_ack():
    """The single 0x00 handshake ack is not shell output."""
    h = RlHarness()
    h.send(False, rl_handshake())
    h.send(True, b"\x00")
    check("RSVC-TRUST-AUTH" not in h.codes(),
          "the bare handshake ack must NOT be read as a trust login")


def test_rlogin_password_prompt_suppresses_trust():
    h = RlHarness()
    h.send(False, rl_handshake())
    h.send(True, b"\x00")
    h.send(True, b"Password: ")
    c = h.codes()
    check("RSVC-TRUST-AUTH" not in c,
          "a password prompt means this was NOT trust auth")
    check("TELNET-CLEARTEXT-AUTH" in c,
          "an rlogin password prompt is still a cleartext credential exposure")


def test_rlogin_window_control_stripped():
    """RFC 1282 window-size control is in-band framing, not data; leaving it in
    would let a peer smuggle bytes past a content check."""
    win = b"\xff\xffss" + bytes(8)
    check(T.strip_rlogin_window(win + b"Password: ") == b"Password: ",
          "window control sequence removed")
    check(T.strip_rlogin_window(b"plain") == b"plain", "plain data untouched")
    h = RlHarness()
    h.send(False, rl_handshake())
    h.send(True, b"\x00")
    h.send(True, win + b"Password: ")
    check("TELNET-CLEARTEXT-AUTH" in h.codes(),
          "a prompt hidden behind window control is still seen")


def test_rlogin_window_control_not_counted_as_shell_output():
    """LOAD-BEARING: 12-byte resize sequences must never accumulate toward the
    trust-auth data threshold. A server emitting only control traffic has NOT
    produced the shell output that proves a password-free login.

    Added after a bite showed the original window test was vacuous: it asserted
    on a prompt PRECEDED by control bytes, and a substring search does not care
    about a prefix, so removing the strip call changed nothing.
    """
    win = b"\xff\xffss" + bytes(8)
    h = RlHarness()
    h.send(False, rl_handshake())
    h.send(True, b"\x00")
    for _ in range(6):                       # 72 bytes of pure control
        h.send(True, win)
    check("RSVC-TRUST-AUTH" not in h.codes(),
          "resize control must NOT accumulate toward the trust threshold")
    h.send(True, b"Last login: Tue\r\n$ ")   # now real shell output
    check("RSVC-TRUST-AUTH" in h.codes(),
          "real shell output after the control traffic DOES fire trust auth")


def test_rlogin_resize_in_handshake_segment():
    """A resize sharing a segment with the opening burst must not corrupt the
    user fields the CVE-1999-0113 check reads."""
    win = b"\xff\xffss" + bytes(8)
    h = RlHarness()
    h.send(False, win + rl_handshake(b"alice", b"-froot"))
    recs = h.by_code("RSVC-RLOGIN-ARGINJECT")
    check(len(recs) == 1,
          "arginject still detected when a resize shares the handshake segment")
    if recs:
        check(recs[0]["detail"]["field"] == "server_user",
              "the correct field is still identified after stripping")


def test_rlogin_client_data_never_inspected():
    """After the handshake the client stream carries the user's keystrokes and
    must never be parsed or logged."""
    h = RlHarness()
    h.send(False, rl_handshake())
    h.send(False, b"RLTYPEDSECRET\r\n")
    check("RLTYPEDSECRET" not in h.buf.getvalue(),
          "post-handshake client data must never appear in output")


def test_rlogin_malformed_never_crashes():
    for bad in (b"", b"\x00", b"\x00" * 64, b"\xff" * 512, b"\x00a",
                bytes(range(256)), b"\x00" + b"A" * 2000):
        h = RlHarness()
        h.send(False, bad)
        h.send(True, bad)
        check(True, "malformed rlogin input did not raise")


def test_rlogin_field_caps():
    """A hostile peer must not be able to grow our state without bound."""
    hs = T.parse_rlogin_handshake(b"\x00" + b"A" * 5000 + b"\x00b\x00t\x00")
    check(len(hs.client_user) <= T._RL_MAX_FIELD,
          f"client user capped at {T._RL_MAX_FIELD}; got {len(hs.client_user)}")
    check(hs.truncated, "oversized handshake is flagged truncated")


def test_rlogin_dualstack_parity():
    """PRIME DIRECTIVE: rlogin is plain TCP and address-family agnostic, so the
    findings must be identical apart from endpoint rendering."""
    steps = [(False, rl_handshake(b"alice", b"-froot")),
             (True, b"\x00"),
             (True, b"Last login: Tue\r\n$ ")]
    h4, h6 = RlHarness(RL_KEY), RlHarness(RL_KEY_V6)
    for frm, pay in steps:
        h4.send(frm, pay)
        h6.send(frm, pay)
    check(h4.codes() == h6.codes(),
          f"identical rlogin findings across families\n"
          f"    v4={h4.codes()}\n    v6={h6.codes()}")
    check(len(h6.codes()) >= 3, "non-vacuity: several codes in the parity run")
    for r6 in h6.records():
        check(r6["client"].startswith("["), "IPv6 rlogin endpoint bracketed")
        check(r6["af"] == "ipv6", "IPv6 rlogin finding tagged af=ipv6")


def test_rlogin_never_touches_iac_state_machine():
    """An rlogin byte stream containing 0xFF must NOT be run through the Telnet
    parser -- rlogin has no IAC framing and the two paths must stay separate."""
    import inspect
    src = inspect.getsource(T.RloginEngine)
    for banned in ("TelnetEvents", "unescape_subneg", "parse_slc",
                   "parse_environ", "_on_nego", "_on_subneg"):
        check(banned not in src,
              f"RloginEngine must not use the Telnet path: found {banned!r}")
    # and a 0xFF-laden rlogin stream must not raise or produce telnet codes
    h = RlHarness()
    h.send(False, rl_handshake())
    h.send(True, b"\x00")
    h.send(True, b"\xff\xfa\x22\x03" + b"\xff" * 40 + b"\xff\xf0")
    telnet_codes = [c for c in h.codes() if c.startswith("TELNET-32746")
                    or c.startswith("TELNET-24061")]
    check(not telnet_codes,
          f"telnet-shaped bytes on an rlogin flow raise no telnet CVE codes; "
          f"got {telnet_codes}")



# ---------------------------------------------------------------------------
# Serial-console posture: RFC 2217 (option 44) and raw TCP
# ---------------------------------------------------------------------------
def cpo(body: bytes) -> bytes:
    return subneg(T.OPT_COM_PORT, body)


def test_2217_session_from_negotiation():
    from telnet_watch import OPT_COM_PORT
    for cmd, label in ((WILL, "WILL"), (DO, "DO")):
        h = Harness()
        h.send(False, nego(cmd, OPT_COM_PORT))
        recs = h.by_code("CONSOLE-RFC2217-SESSION")
        check(len(recs) == 1, f"IAC {label} COM-PORT-OPTION identifies a console")
        if recs:
            check(recs[0]["severity"] == "warning", "2217 session is warning")
            check(recs[0]["confidence"] == "high",
                  "high confidence: the option code is on the wire")


def test_2217_session_from_subneg_alone():
    """A mid-session tap joins after negotiation, so a sub-option must be
    enough on its own to identify the session."""
    from telnet_watch import CPO_SET_BAUDRATE
    h = Harness()
    h.send(False, cpo(bytes([CPO_SET_BAUDRATE]) + (9600).to_bytes(4, "big")))
    check("CONSOLE-RFC2217-SESSION" in h.codes(),
          "a COM-PORT sub-option alone identifies the session")


def test_2217_break_on_only():
    """SET-CONTROL 5 asserts BREAK. 4 only REQUESTS the state and 6 clears it;
    firing on either would be a false positive on ordinary console housekeeping.
    """
    from telnet_watch import (CPO_SET_CONTROL, CPO_CTRL_BREAK_ON,
                             CPO_CTRL_BREAK_REQUEST, CPO_CTRL_BREAK_OFF)
    h = Harness()
    h.send(False, cpo(bytes([CPO_SET_CONTROL, CPO_CTRL_BREAK_ON])))
    recs = h.by_code("CONSOLE-RFC2217-BREAK")
    check(len(recs) == 1, "SET-CONTROL 5 (BREAK ON) fires")
    if recs:
        check(recs[0]["severity"] == "high", "BREAK is high severity")
        check(recs[0]["detail"]["set_control"] == CPO_CTRL_BREAK_ON,
              "the control value is recorded")
    for val, label in ((CPO_CTRL_BREAK_REQUEST, "4 request"),
                       (CPO_CTRL_BREAK_OFF, "6 off")):
        h2 = Harness()
        h2.send(False, cpo(bytes([CPO_SET_CONTROL, val])))
        check("CONSOLE-RFC2217-BREAK" not in h2.codes(),
              f"SET-CONTROL {label} must NOT fire BREAK")


def test_2217_break_other_control_values_silent():
    """Flow-control, DTR and RTS values share the SET-CONTROL space."""
    from telnet_watch import CPO_SET_CONTROL
    for val in (0, 1, 2, 3, 7, 8, 9, 10, 11, 12, 19):
        h = Harness()
        h.send(False, cpo(bytes([CPO_SET_CONTROL, val])))
        check("CONSOLE-RFC2217-BREAK" not in h.codes(),
              f"SET-CONTROL {val} is not a BREAK assertion")


def test_2217_server_break_detect():
    """NOTIFY-LINESTATE bit 4 is the access server reporting a BREAK seen on
    the physical line; server codes are the client code + 100."""
    from telnet_watch import (CPO_NOTIFY_LINESTATE, CPO_SERVER_OFFSET,
                             CPO_LINESTATE_BREAK_DETECT)
    h = Harness()
    h.send(True, cpo(bytes([CPO_NOTIFY_LINESTATE + CPO_SERVER_OFFSET,
                            CPO_LINESTATE_BREAK_DETECT])))
    recs = h.by_code("CONSOLE-RFC2217-BREAK")
    check(len(recs) == 1, "server break-detect linestate fires")
    if recs:
        check(recs[0]["detail"]["signal"] == "break-detect", "signal labelled")
    h2 = Harness()
    h2.send(True, cpo(bytes([CPO_NOTIFY_LINESTATE + CPO_SERVER_OFFSET, 0x01])))
    check("CONSOLE-RFC2217-BREAK" not in h2.codes(),
          "a data-ready linestate is not a break-detect")


def test_2217_params_captured():
    from telnet_watch import CPO_SET_BAUDRATE, CPO_SET_CONTROL, CPO_CTRL_BREAK_ON
    h = Harness()
    h.send(False, cpo(bytes([CPO_SET_BAUDRATE]) + (115200).to_bytes(4, "big")))
    h.send(False, cpo(bytes([CPO_SET_CONTROL, CPO_CTRL_BREAK_ON])))
    recs = h.by_code("CONSOLE-RFC2217-BREAK")
    if recs:
        check(recs[0]["detail"]["params"].get("baud") == 115200,
              f"line params carried on the BREAK finding; got "
              f"{recs[0]['detail']['params']}")


def test_2217_fp_gate_plain_telnet():
    """An ordinary Telnet session must never be called a console."""
    h = Harness()
    h.send(True, nego(DO, OPT_LINEMODE))
    h.send(False, nego(WILL, OPT_NEW_ENVIRON))
    h.send(False, subneg(OPT_NEW_ENVIRON, environ_is([(b"USER", b"alice")])))
    c = h.codes()
    check("CONSOLE-RFC2217-SESSION" not in c,
          f"plain telnet raises no console finding; got {c}")
    check("CONSOLE-RFC2217-BREAK" not in c, "plain telnet raises no BREAK")


# --- raw TCP console -------------------------------------------------------
CON_KEY = ("10.0.0.9", 51000, "10.0.0.1", 2004)
CON_KEY_V6 = ("2001:db8::9", 51000, "2001:db8::1", 2004)


class ConHarness:
    def __init__(self, key=CON_KEY):
        self.key = key
        self.buf = io.StringIO()
        self.eng = T.ConsoleEngine(T.Emitter(out=self.buf, min_sev="info",
                                             dedup_secs=0.0))
        self.t = 1000.0

    def send(self, from_server, payload):
        self.t += 0.01
        self.eng.on_payload(self.key, from_server, payload, now=self.t)

    def records(self):
        return [json.loads(l) for l in self.buf.getvalue().splitlines() if l.strip()]

    def codes(self):
        return [r["code"] for r in self.records()]


def test_rawconsole_fires_on_multiple_signals():
    h = ConHarness()
    h.send(True, b"\x1b[2J\r\nPress RETURN to get started.\r\n")
    recs = [r for r in h.records() if r["code"] == "CONSOLE-RAW-TCP-SUSPECTED"]
    check(len(recs) == 1, "raw console fires on several terminal signals")
    if recs:
        check(recs[0]["severity"] == "notice", "raw console is notice only")
        check(recs[0]["confidence"] == "low",
              "low confidence: nothing to parse on a raw console")
        check(len(recs[0]["detail"]["signals"]) >= 2, "signals recorded")


def test_rawconsole_single_signal_insufficient():
    """Port alone, or one weak signal, must never be enough -- these ranges
    carry plenty of unrelated services."""
    for payload, label in ((b"\r\n", "crlf only"),
                           (b"\x1b[0m", "ansi only")):
        h = ConHarness()
        h.send(True, payload)
        check("CONSOLE-RAW-TCP-SUSPECTED" not in h.codes(),
              f"{label} is a single signal and must NOT fire")


def test_rawconsole_binary_traffic_gate():
    h = ConHarness()
    h.send(True, bytes(range(256)) * 4)
    check("CONSOLE-RAW-TCP-SUSPECTED" not in h.codes(),
          "binary application traffic on a console port must NOT fire")


def test_rawconsole_telnet_disqualifies():
    """If it is really Telnet on an odd port, the Telnet parser owns it."""
    h = ConHarness()
    h.send(True, bytes([IAC, WILL, T.OPT_SGA]))
    h.send(True, b"\x1b[2J\r\nlogin: ")
    check("CONSOLE-RAW-TCP-SUSPECTED" not in h.codes(),
          "an IAC-framed session is disqualified from the raw-console guess")


def test_rawconsole_client_data_never_inspected():
    h = ConHarness()
    h.send(False, b"\x1b[2J\r\nlogin: admin\r\nCONSENTINELPW\r\n")
    check(not h.codes(), "client keystrokes are never inspected or reported")
    check("CONSENTINELPW" not in h.buf.getvalue(),
          "client-typed data must never appear in output")


def test_rawconsole_signal_helper():
    sig = T.console_signals(b"\x1b[2J\r\nPress RETURN to get started.\r\n")
    check("ansi-csi" in sig, "ANSI CSI detected")
    check("crlf" in sig, "CRLF detected")
    check("vendor-banner" in sig, "vendor banner detected")
    check(T.console_signals(b"") == set(), "empty run yields no signals")


def test_console_dualstack_parity():
    """PRIME DIRECTIVE: both console signals are payload/port level and must be
    identical across families apart from endpoint rendering."""
    from telnet_watch import CPO_SET_CONTROL, CPO_CTRL_BREAK_ON
    # RFC 2217 over the Telnet path
    h4, h6 = Harness(), HarnessV6()
    for h in (h4, h6):
        h.send(False, nego(WILL, T.OPT_COM_PORT))
        h.send(False, cpo(bytes([CPO_SET_CONTROL, CPO_CTRL_BREAK_ON])))
    check(h4.codes() == h6.codes(),
          f"2217 identical across families\n    v4={h4.codes()}\n    v6={h6.codes()}")
    check("CONSOLE-RFC2217-BREAK" in h6.codes(), "2217 BREAK fires over IPv6")
    # raw TCP console
    c4, c6 = ConHarness(CON_KEY), ConHarness(CON_KEY_V6)
    for c in (c4, c6):
        c.send(True, b"\x1b[2J\r\nPress RETURN to get started.\r\n")
    check(c4.codes() == c6.codes(), "raw console identical across families")
    for r in c6.records():
        check(r["client"].startswith("["), "IPv6 console endpoint bracketed")
        check(r["af"] == "ipv6", "IPv6 console finding tagged af=ipv6")


def test_console_port_range_parser():
    check(T._port_ranges("2001-2003") == (2001, 2002, 2003), "range expands")
    check(T._port_ranges("2001,3001-3002") == (2001, 3001, 3002), "mixed list")
    check(T._port_ranges("") == (), "empty disables")
    check(T._port_ranges("bad,2001") == (2001,), "malformed entries skipped")
    check(T._port_ranges("3000-2000") == (), "inverted range rejected")
    check(len(T._port_ranges("1-99999")) == 0, "absurd range rejected (capped)")



# ---------------------------------------------------------------------------
# rsh (514) / rexec (512) / rcp
# ---------------------------------------------------------------------------
RSH_KEY = ("10.0.0.9", 1023, "10.0.0.1", 514)
RSH_KEY_V6 = ("2001:db8::9", 1023, "2001:db8::1", 514)
REXEC_KEY = ("10.0.0.9", 1023, "10.0.0.1", 512)


def rsh_hs(port=1022, a=b"root", b=b"root", cmd=b"echo hi"):
    return str(port).encode() + b"\x00" + a + b"\x00" + b + b"\x00" + cmd + b"\x00"


class RshHarness:
    def __init__(self, key=RSH_KEY, rexec=False):
        self.key, self.rexec = key, rexec
        self.buf = io.StringIO()
        self.eng = T.RshEngine(T.Emitter(out=self.buf, min_sev="info",
                                         dedup_secs=0.0))
        self.t = 1000.0

    def send(self, from_server, payload):
        self.t += 0.01
        self.eng.on_payload(self.key, from_server, payload, now=self.t,
                            is_rexec=self.rexec)

    def records(self):
        return [json.loads(l) for l in self.buf.getvalue().splitlines() if l.strip()]

    def codes(self):
        return [r["code"] for r in self.records()]

    def by_code(self, c):
        return [r for r in self.records() if r["code"] == c]


def test_rsh_session_emitted_once():
    """Emitting from both on_payload and the handshake produced a duplicate
    that only the 60s dedup window hid in production."""
    h = RshHarness()
    h.send(False, rsh_hs())
    h.send(True, b"hi\n")
    check(h.codes().count("RSVC-RSH-SESSION") == 1,
          f"session reported exactly once; got {h.codes()}")


def test_rsh_session_records_first_token_only():
    """The full command routinely carries paths and secrets."""
    h = RshHarness()
    h.send(False, rsh_hs(cmd=b"/usr/bin/rcp -f /srv/RSHSENTINELPATH/secret.txt"))
    recs = h.by_code("RSVC-RSH-SESSION")
    check(len(recs) == 1, "rsh session reported")
    if recs:
        check(recs[0]["detail"]["cmd_first_token"] == "/usr/bin/rcp",
              "only the command's first token is recorded")
        check("RSHSENTINELPATH" not in h.buf.getvalue(),
              "the rest of the command line must NOT be logged")
        check(recs[0]["detail"]["cmd_len"] > 20, "length recorded instead")


def test_rsh_midsession_tap_still_reports():
    h = RshHarness()
    h.send(True, b"uid=0(root) gid=0(root)\n")
    recs = h.by_code("RSVC-RSH-SESSION")
    check(len(recs) == 1, "a mid-session tap still reports the session")
    if recs:
        check("mid-session" in recs[0]["detail"].get("note", ""),
              "and says the handshake was not observed")


def test_rsh_arginject():
    h = RshHarness()
    h.send(False, rsh_hs(b=b"-froot"))
    recs = h.by_code("RSVC-RLOGIN-ARGINJECT")
    check(len(recs) == 1, "rsh remote-user arginject detected")
    if recs:
        check(recs[0]["detail"]["protocol"] == "rsh", "protocol labelled rsh")
        check(recs[0]["detail"]["bypass_flag"] is True, "-f is the bypass flag")


def test_rsh_arginject_fp_gate():
    h = RshHarness()
    h.send(False, rsh_hs(a=b"alice", b=b"bob"))
    check("RSVC-RLOGIN-ARGINJECT" not in h.codes(),
          "ordinary rsh users raise no arginject")


def test_rexec_cleartext_credential():
    h = RshHarness(key=REXEC_KEY, rexec=True)
    h.send(False, rsh_hs(port=0, a=b"admin", b=b"hunter2", cmd=b"id"))
    recs = h.by_code("RSVC-REXEC-CLEARTEXT-CRED")
    check(len(recs) == 1, "rexec cleartext credential reported")
    if recs:
        check(recs[0]["severity"] == "critical", "rexec credential is critical")
        check(recs[0]["detail"]["password_len"] == len(b"hunter2"),
              "password LENGTH recorded")


def test_rexec_password_never_logged():
    h = RshHarness(key=REXEC_KEY, rexec=True)
    h.send(False, rsh_hs(port=0, a=b"admin", b=b"REXECSENTINELPW", cmd=b"id"))
    check("REXECSENTINELPW" not in h.buf.getvalue(),
          "the rexec password value must NEVER appear in output")
    check("RSVC-REXEC-CLEARTEXT-CRED" in h.codes(),
          "the finding still fires without logging the value")


def test_rexec_does_not_emit_rsh_session():
    h = RshHarness(key=REXEC_KEY, rexec=True)
    h.send(False, rsh_hs(port=0, a=b"u", b=b"p", cmd=b"id"))
    check("RSVC-RSH-SESSION" not in h.codes(),
          "rexec is not reported as an rsh session")


def test_rsh_source_port_checks():
    h = RshHarness(key=("10.0.0.9", 20, "10.0.0.1", 514))
    h.send(False, rsh_hs())
    check("RSVC-FTPDATA-SRCPORT" in h.codes(),
          "CVE-1999-0185 ftp-data bounce also applies to rsh/514")
    h2 = RshHarness(key=("10.0.0.9", 51000, "10.0.0.1", 514))
    h2.send(False, rsh_hs())
    check("RSVC-UNPRIV-SRCPORT" in h2.codes(),
          "unprivileged source port reported on rsh")
    h3 = RshHarness(key=("10.0.0.9", 1023, "10.0.0.1", 514))
    h3.send(False, rsh_hs())
    check("RSVC-UNPRIV-SRCPORT" not in h3.codes(),
          "a privileged source port is the normal case on rsh")


def test_rsh_trust_auth():
    h = RshHarness()
    h.send(False, rsh_hs(cmd=b"id"))
    h.send(True, b"uid=0(root) gid=0(root) groups=0\n")
    check("RSVC-TRUST-AUTH" in h.codes(),
          "command output with no password means .rhosts trust")


# --- stderr back-connect correlation (the preflight's settled key) ---------
def test_rsh_backconnect_correlation():
    h = RshHarness(key=("10.88.0.2", 1023, "10.88.0.1", 514))
    h.send(False, rsh_hs(port=1022))
    check(h.eng.on_backconnect("10.88.0.2", 1022) is True,
          "the back-connect correlates to its session")
    check(h.eng.on_backconnect("10.88.0.2", 9999) is False,
          "a different port does not correlate")
    check(h.eng.on_backconnect("10.88.0.3", 1022) is False,
          "the SAME port from a different client does not correlate")


def test_rsh_backconnect_is_family_scoped():
    """rsh draws the advertised port from one small privileged range, so the
    same number recurs constantly. A port-only key would collide across
    families; the key is (family, canonical address, port)."""
    h = RshHarness(key=("10.88.0.2", 1023, "10.88.0.1", 514))
    h.send(False, rsh_hs(port=1022))
    check(h.eng.on_backconnect("2001:db8::2", 1022) is False,
          "an IPv6 client does not match an IPv4 session on the same port")
    h6 = RshHarness(key=("2001:db8::2", 1023, "2001:db8::1", 514))
    h6.send(False, rsh_hs(port=1022))
    check(h6.eng.on_backconnect("2001:db8::2", 1022) is True,
          "the IPv6 back-connect correlates to its IPv6 session")
    check(h6.eng.on_backconnect("2001:0db8:0000:0000:0000:0000:0000:0002",
                                1022) is True,
          "equivalent IPv6 textual forms canonicalize to the same key")


# --- rcp -------------------------------------------------------------------
def rcp_harness(request=b"rcp -f /tmp/a.txt"):
    """The server's first byte is the 0x00 ack; records follow. Fixtures keep
    that ack because gluing it to a record was a real parser bug."""
    h = RshHarness()
    h.send(False, rsh_hs(port=0, cmd=request))
    h.send(True, RCP_ACK)
    return h


RCP_ACK = bytes([0x00])


def rcp_rec(tag: bytes, size: int, name: bytes, mode: bytes = b"0644") -> bytes:
    """Build one rcp record. Fixtures use this rather than hand-escaping a
    newline -- a doubled backslash produced a LITERAL backslash-n and made
    several rcp tests pass vacuously."""
    return tag + mode + b" " + str(size).encode() + b" " + name + bytes([0x0A])


def test_rcp_request_parsing():
    info = T.rcp_request_info(b"rcp -f /tmp/a.txt")
    check(info is not None and info[0] == b"/tmp/a.txt", "source-mode parsed")
    check(info[1] is False and info[2] is False, "no glob, not recursive")
    check(T.rcp_request_info(b"rcp -r -f /srv/dir")[2] is True, "-r recognised")
    check(T.rcp_request_info(b"rcp -f /tmp/*.txt")[1] is True, "glob recognised")
    check(T.rcp_request_info(b"rcp -t /tmp/dst") is None,
          "SINK mode (-t) is not parsed: the server does not choose there")
    check(T.rcp_request_info(b"ls -l") is None, "a non-rcp command is ignored")
    check(T.rcp_request_info(b"") is None, "empty command is ignored")


def test_rcp_ack_byte_not_glued_to_record():
    """REGRESSION: the 0x00 ack is not newline-terminated. Gluing it onto the
    next record makes that record's tag 0x00 instead of C/D, so every record is
    silently dropped -- which reads as a clean transfer, not a parse error. An
    earlier "legit transfer is quiet" check passed vacuously because of it."""
    h = rcp_harness()
    h.send(True, RCP_ACK + rcp_rec(b"C", 5, b"evil!") + b"hello")
    check("RSVC-RCP-7283-UNREQUESTED" in h.codes(),
          "a record preceded by an ack byte is still parsed")


def test_rcp_legit_transfer_silent():
    h = rcp_harness()
    h.send(True, b"C0644 5 a.txt\nhello")
    c = h.codes()
    check(not [x for x in c if "RCP" in x],
          f"a legitimate single-file transfer raises nothing; got {c}")


def test_rcp_7283_name_mismatch():
    h = rcp_harness()
    h.send(True, b"C0644 5 evil!\nhello")
    recs = h.by_code("RSVC-RCP-7283-UNREQUESTED")
    check(len(recs) == 1, "a name that does not match the request is flagged")
    if recs:
        check(recs[0]["confidence"] == "high", "high confidence, no glob")
        check("does not match" in recs[0]["detail"]["reason"], "reason recorded")


def test_rcp_7283_extra_file():
    h = rcp_harness()
    h.send(True, b"C0644 5 a.txt\nhelloC0644 3 a.txt\nbye")
    check("RSVC-RCP-7283-UNREQUESTED" in h.codes(),
          "more files than requested is flagged")


def test_rcp_7283_directory_without_recursive():
    h = rcp_harness()
    h.send(True, b"D0755 0 sub\n")
    recs = h.by_code("RSVC-RCP-7283-UNREQUESTED")
    check(len(recs) == 1, "a directory record without -r is flagged")
    if recs:
        check("-r" in recs[0]["detail"]["reason"], "reason names the missing -r")


def test_rcp_directory_with_recursive_allowed():
    h = rcp_harness(request=b"rcp -r -f /srv/dir")
    h.send(True, b"D0755 0 dir\n")
    check("RSVC-RCP-7283-UNREQUESTED" not in h.codes(),
          "a directory record IS legitimate when -r was requested")


def test_rcp_glob_reduces_confidence():
    """A globbed request legitimately returns many differently-named files, so
    it must not be suppressed outright nor reported at full confidence."""
    h = rcp_harness(request=b"rcp -f /tmp/*.txt")
    h.send(True, b"C0644 5 a.txt\nhelloC0644 3 b.txt\nbye")
    recs = h.by_code("RSVC-RCP-7283-UNREQUESTED")
    check(not recs, f"multiple files under a glob are expected; got {recs}")
    h2 = rcp_harness(request=b"rcp -f /tmp/*.txt")
    h2.send(True, b"D0755 0 sub\n")
    recs2 = h2.by_code("RSVC-RCP-7283-UNREQUESTED")
    check(recs2, "a directory under a non-recursive glob is still flagged")
    if recs2:
        check(recs2[0]["confidence"] == "heuristic",
              "glob requests are reported at reduced confidence")


def test_rcp_7282_dotname():
    for name in (b".", b"", b".."):
        h = rcp_harness()
        h.send(True, b"C0644 0 " + name + b"\n")
        check("RSVC-RCP-7282-DOTNAME" in h.codes(),
              f"CVE-2019-7282 fires on name {name!r}")


def test_rcp_traversal():
    for name in (b"../../etc/passwd", b"/etc/shadow", b"a/../b"):
        h = rcp_harness()
        h.send(True, b"C0644 0 " + name + b"\n")
        check("RSVC-RCP-7283-TRAVERSAL" in h.codes(),
              f"traversal flagged for {name!r}")
    h = rcp_harness()
    h.send(True, b"C0644 5 a.txt\nhello")
    check("RSVC-RCP-7283-TRAVERSAL" not in h.codes(),
          "an ordinary basename is not a traversal")


def test_rcp_file_payload_is_skipped():
    """LOAD-BEARING: file CONTENT containing a record line must never be parsed
    as a record, or a transferred file could fabricate findings.

    The declared size must match the fixture payload EXACTLY -- an off-by-two
    here silently ate the first bytes of the following record and made the
    resume check fail for the wrong reason.
    """
    h = rcp_harness()
    body = rcp_rec(b"C", 0, b"evil") + b"XXXXXX"       # 13 + 6 = 19 bytes
    check(len(body) == 19, f"fixture payload is 19 bytes; got {len(body)}")
    h.send(True, rcp_rec(b"C", len(body), b"a.txt") + body)
    c = h.codes()
    check(not [x for x in c if "RCP" in x],
          f"a record line inside file DATA must not be parsed; got {c}")
    # once the declared payload is consumed, real records resume being parsed
    h.send(True, RCP_ACK + rcp_rec(b"C", 0, b"evil2"))
    check("RSVC-RCP-7283-UNREQUESTED" in h.codes(),
          "parsing resumes correctly after the skipped payload")


def test_rcp_records_split_across_segments():
    h = rcp_harness()
    rec = rcp_rec(b"C", 0, b"evil!")
    h.send(True, rec[:10])
    h.send(True, rec[10:])
    check("RSVC-RCP-7283-UNREQUESTED" in h.codes(),
          "an rcp record split across TCP segments is still parsed")


def test_rcp_malformed_never_crashes():
    for bad in (b"C\n", b"C0644\n", b"Cxxx yyy zzz\n", b"\x01error\n",
                b"T123 0 456 0\n", b"E\n", b"\x00", b"\xff" * 200,
                b"C0644 notanumber name\n"):
        h = rcp_harness()
        h.send(True, bad)
        check(True, "malformed rcp record did not raise")


def test_rsh_dualstack_parity():
    steps = [(False, rsh_hs(port=1022, b=b"-froot", cmd=b"rcp -f /tmp/a.txt")),
             (True, b"\x00C0644 5 evil!\nhello")]
    h4, h6 = RshHarness(RSH_KEY), RshHarness(RSH_KEY_V6)
    for frm, pay in steps:
        h4.send(frm, pay)
        h6.send(frm, pay)
    check(h4.codes() == h6.codes(),
          f"identical rsh/rcp findings across families\n"
          f"    v4={h4.codes()}\n    v6={h6.codes()}")
    check(len(h6.codes()) >= 3, "non-vacuity: several codes in the parity run")
    for r in h6.records():
        check(r["client"].startswith("["), "IPv6 rsh endpoint bracketed")
        check(r["af"] == "ipv6", "IPv6 rsh finding tagged af=ipv6")


def test_rsh_never_touches_other_parsers():
    import inspect
    src = inspect.getsource(T.RshEngine)
    for banned in ("TelnetEvents", "unescape_subneg", "parse_slc",
                   "parse_environ", "parse_rlogin_handshake"):
        check(banned not in src,
              f"RshEngine must not use another protocol's parser: {banned!r}")


def test_bpf_admits_backconnect_range():
    """Without the privileged portrange the stderr channel is never captured,
    so the correlation could never fire."""
    bpf = T._build_bpf((23,), (992,), (513, 514, 512))
    lo, hi = T.PRIV_PORTRANGE
    check(f"portrange {lo}-{hi}" in bpf,
          f"BPF admits the back-connect range when r-services is on; got {bpf}")
    bpf_off = T._build_bpf((23,), (992,), ())
    check("portrange" not in bpf_off,
          "the range is NOT admitted when r-services is disabled")


# ---------------------------------------------------------------------------
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


if __name__ == "__main__":
    sys.exit(run())
