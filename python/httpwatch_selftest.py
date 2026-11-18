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
def test_registry():
    check("registry: 28 codes", len(hw.FINDING_REGISTRY) == 28)
    for code, d in hw.FINDING_REGISTRY.items():
        check(f"registry: {code} code matches key", d.code == code)
        check(f"registry: {code} has a summary", len(d.summary) > 20)
        check(f"registry: {code} severity valid",
              d.severity in (hw.INFO, hw.WARN, hw.HIGH, hw.CRITICAL))
        check(f"registry: {code} confidence valid",
              d.confidence in (hw.EXACT, hw.SHAPE, hw.HEURISTIC, hw.POSTURE))
        check(f"registry: {code} tier valid", d.tier in "ABCD")
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
        check(f"catalog: {cve} has a CVSS vector",
              meta.get("vector", "").startswith("CVSS:3."))
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
