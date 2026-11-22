#!/usr/bin/env python3
"""smtpwatch - passive Exim CVE detector for the Ragnar suite.

Effectively an Exim detector wearing a protocol name (same pattern as ftpwatch
being a ProFTPD detector). Covers three CVEs across two detection classes:

  CVE-2019-10149  "Return of the WIZard"  ${...} expansion in MAIL/RCPT address
  CVE-2019-15846                          malformed SNI / peer-cert DN backslash
  CVE-2018-6789                           b64decode off-by-one via AUTH (len 4n+3)

Class A findings are ungated attack/attempt signatures (near-zero FP by
construction). Class B findings are banner/version exposure, capped at notice
with low confidence because distro backports keep old version strings in the
banner (LESSON T honest-confidence model).

Dual-stack (IPv4/IPv6) is a prime-directive requirement, enforced in the
self-test parity harness. The parse path takes raw bytes only; scapy is imported
solely inside run_capture().
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

VERSION = "0.1.0-dev"
_LAST_SELFTEST = []      # [(check name, passed)] from the most recent self_test()

# server-side SMTP ports we treat as an SMTP endpoint
SMTP_PORTS = (25, 465, 587)
IMPLICIT_TLS_PORTS = (465,)  # TLS from the first byte, no cleartext SMTP

# RFC 5321 4.5.3.1.4 caps a command line at 512 octets incl CRLF; a compliant
# EHLO is well under. CVE-2019-16928's PoC uses an extraordinarily long EHLO,
# so any EHLO/HELO line past this bound is both non-conformant and the attack
# shape (key on the CONDITION, not the CVE - LESSON AF).
EHLO_MAX_LEN = 512

# ---------------------------------------------------------------------------
# finding-code registry
# ---------------------------------------------------------------------------
# Frozen contract. severity in {critical,high,warn,notice,info};
# confidence in {high,medium,low}; cls in {A,B}.
CODES = {
    "SMTP-001": dict(cls="A", cve="CVE-2019-10149", sev="high",     conf="high",
                     name="${...} expansion in MAIL FROM (attempt)"),
    "SMTP-002": dict(cls="A", cve="CVE-2019-10149", sev="high",     conf="high",
                     name="${...} expansion in RCPT TO (attempt)"),
    "SMTP-003": dict(cls="A", cve="CVE-2019-10149", sev="critical", conf="high",
                     name="tainted RCPT accepted by server (payload queued)"),
    "SMTP-004": dict(cls="A", cve="CVE-2019-15846", sev="high",     conf="high",
                     name="malformed SNI (backslash/NUL) in ClientHello"),
    "SMTP-005": dict(cls="A", cve="CVE-2019-15846", sev="high",     conf="medium",
                     name="TLS1.2 client certificate DN ends in backslash"),
    "SMTP-006": dict(cls="A", cve="CVE-2018-6789",  sev="high",     conf="high",
                     name="AUTH base64 length congruent to 3 mod 4 (b64decode overflow)"),
    "SMTP-007": dict(cls="A", cve="CVE-2019-16928", sev="high",     conf="high",
                     name="overlong EHLO/HELO command (string_vformat heap overflow)"),
    "SMTP-010": dict(cls="B", cve=None,             sev="info",     conf="high",
                     name="Exim version disclosed in banner"),
    "SMTP-011": dict(cls="B", cve="CVE-2019-10149", sev="notice",   conf="low",
                     name="banner version in CVE-2019-10149 range (4.87-4.91)"),
    "SMTP-012": dict(cls="B", cve="CVE-2019-15846", sev="notice",   conf="low",
                     name="banner version in CVE-2019-15846 range + STARTTLS offered"),
    "SMTP-013": dict(cls="B", cve="CVE-2018-6789",  sev="notice",   conf="low",
                     name="banner version in CVE-2018-6789 range (<4.90.1)"),
    "SMTP-014": dict(cls="B", cve=None,             sev="info",     conf="high",
                     name="Exim banner suppressed - version gate closed"),
    "SMTP-015": dict(cls="B", cve="CVE-2019-16928", sev="notice",   conf="low",
                     name="banner version in CVE-2019-16928 range (4.92-4.92.2)"),
}

SEVERITIES = {"critical", "high", "warn", "notice", "info"}
CONFIDENCES = {"high", "medium", "low"}
CLASSES = {"A", "B"}
AFS = {"ipv4", "ipv6"}

# ---------------------------------------------------------------------------
# endpoint rendering (LESSON AE - RFC 3986 brackets for IPv6, round-trippable)
# ---------------------------------------------------------------------------
def render_ep(ip: str, port: int, af: str) -> str:
    if af == "ipv6":
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def split_ep(ep: str) -> tuple[str, int]:
    if ep.startswith("["):
        host, _, rest = ep[1:].partition("]")
        return host, int(rest.lstrip(":"))
    host, _, port = ep.rpartition(":")
    return host, int(port)


# ---------------------------------------------------------------------------
# version comparison (preflight trap: Exim uses 3- and 4-component versions,
# e.g. 4.90.1 and fixup 4.90.0.27; a two-part comparator reads 4.90.1 as 4.90)
# ---------------------------------------------------------------------------
_VER_RE = re.compile(rb"Exim\s+(\d+(?:\.\d+){1,3})")


def parse_exim_version(banner: bytes) -> Optional[tuple[int, ...]]:
    """Extract an Exim version tuple from a 220 banner, or None."""
    m = _VER_RE.search(banner)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split(b"."))


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    # native tuple compare is correct as long as we never truncate components:
    # (4,90) < (4,90,1) is True; (4,90,0,27) < (4,90,1) is True.
    return a < b


def in_10149_range(v: tuple[int, ...]) -> bool:
    # 4.87 through 4.91 inclusive; fixed 4.92
    return (not _lt(v, (4, 87))) and _lt(v, (4, 92))


def in_15846_range(v: tuple[int, ...]) -> bool:
    # 4.80 through 4.92.1 inclusive; fixed 4.92.2
    return (not _lt(v, (4, 80))) and _lt(v, (4, 92, 2))


def in_6789_range(v: tuple[int, ...]) -> bool:
    # every version before 4.90.1
    return _lt(v, (4, 90, 1))


def in_16928_range(v: tuple[int, ...]) -> bool:
    # 4.92 through 4.92.2 inclusive; fixed 4.92.3
    return (not _lt(v, (4, 92))) and _lt(v, (4, 92, 3))


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    code: str
    severity: str
    confidence: str
    af: str
    cls: str
    cve: Optional[str]
    detail: str
    cli_ep: str
    srv_ep: str

    def to_dict(self) -> dict:
        return asdict(self)


def _make(code: str, af: str, detail: str, cli_ep: str, srv_ep: str) -> Finding:
    meta = CODES[code]
    return Finding(
        code=code, severity=meta["sev"], confidence=meta["conf"], af=af,
        cls=meta["cls"], cve=meta["cve"], detail=detail,
        cli_ep=cli_ep, srv_ep=srv_ep,
    )


# ---------------------------------------------------------------------------
# base64 helpers (CVE-2018-6789 condition: invalid b64 of length 4n+3)
# ---------------------------------------------------------------------------
_B64_ALPHABET = set(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)


def is_b64_token(tok: bytes) -> bool:
    return len(tok) > 0 and all(c in _B64_ALPHABET for c in tok)


def triggers_6789(tok: bytes) -> bool:
    # legit SMTP AUTH always sends padded base64 (length multiple of 4).
    # only 4n+3 triggers the b64decode over-consume; 4n+1 does not, 4n+2 is
    # a validly-padded length. flag exactly len%4==3 on a base64-charset token.
    return is_b64_token(tok) and (len(tok) % 4 == 3)


# ---------------------------------------------------------------------------
# minimal TLS handshake parser (SNI + client Certificate DN)
# ---------------------------------------------------------------------------
class TlsStream:
    """Accumulates one direction of a TLS byte stream and yields handshake
    messages (type, body). Handles records spanning/segmenting handshake msgs.
    Only cleartext handshake records (content type 22) are followed; once
    ChangeCipherSpec (20) is seen the rest of that direction is opaque."""

    def __init__(self) -> None:
        self._rec = bytearray()   # pending record-layer bytes
        self._hs = bytearray()    # reassembled handshake bytes
        self._opaque = False

    def feed(self, data: bytes):
        if self._opaque:
            return
        self._rec += data
        while len(self._rec) >= 5:
            ctype = self._rec[0]
            length = (self._rec[3] << 8) | self._rec[4]
            if len(self._rec) < 5 + length:
                break
            body = bytes(self._rec[5:5 + length])
            del self._rec[:5 + length]
            if ctype == 20:      # ChangeCipherSpec -> encrypted from here
                self._opaque = True
                self._hs.clear()
                return
            if ctype == 22:      # handshake
                self._hs += body
            # else (alert/appdata) ignored
        # drain complete handshake messages
        while len(self._hs) >= 4:
            htype = self._hs[0]
            hlen = (self._hs[1] << 16) | (self._hs[2] << 8) | self._hs[3]
            if len(self._hs) < 4 + hlen:
                break
            hbody = bytes(self._hs[4:4 + hlen])
            del self._hs[:4 + hlen]
            yield htype, hbody


def parse_client_hello_sni(body: bytes) -> list[bytes]:
    """Return the list of raw server_name host_name byte strings in a
    ClientHello handshake body (may be empty)."""
    try:
        p = 2 + 32  # legacy_version + random
        sid_len = body[p]; p += 1 + sid_len
        cs_len = (body[p] << 8) | body[p + 1]; p += 2 + cs_len
        comp_len = body[p]; p += 1 + comp_len
        if p >= len(body):
            return []
        ext_total = (body[p] << 8) | body[p + 1]; p += 2
        end = p + ext_total
        names: list[bytes] = []
        while p + 4 <= end:
            etype = (body[p] << 8) | body[p + 1]
            elen = (body[p + 2] << 8) | body[p + 3]
            p += 4
            edata = body[p:p + elen]
            p += elen
            if etype == 0x0000:  # server_name
                q = 0
                if len(edata) < 2:
                    continue
                list_len = (edata[q] << 8) | edata[q + 1]; q += 2
                lend = min(len(edata), q + list_len)
                while q + 3 <= lend:
                    ntype = edata[q]
                    nlen = (edata[q + 1] << 8) | edata[q + 2]
                    q += 3
                    names.append(edata[q:q + nlen])
                    q += nlen
        return names
    except (IndexError, ValueError):
        return []


def server_hello_is_tls13(body: bytes) -> bool:
    """True if a ServerHello negotiates TLS 1.3 (via supported_versions)."""
    try:
        p = 2 + 32
        sid_len = body[p]; p += 1 + sid_len
        p += 2 + 1  # cipher_suite + compression_method
        if p + 2 > len(body):
            return False
        ext_total = (body[p] << 8) | body[p + 1]; p += 2
        end = p + ext_total
        while p + 4 <= end:
            etype = (body[p] << 8) | body[p + 1]
            elen = (body[p + 2] << 8) | body[p + 3]
            p += 4
            edata = body[p:p + elen]; p += elen
            if etype == 0x002b and len(edata) >= 2:  # supported_versions
                if edata[0] == 0x03 and edata[1] == 0x04:
                    return True
        return False
    except (IndexError, ValueError):
        return False


# --- bounded DER walk to reach the subject DN of the first client cert -------
_DER_STRING_TAGS = {0x0c, 0x13, 0x16, 0x14, 0x1e, 0x82}  # UTF8/Printable/IA5/T61/BMP


def _der_read_len(buf: bytes, p: int) -> tuple[int, int]:
    first = buf[p]; p += 1
    if first < 0x80:
        return first, p
    n = first & 0x7f
    val = 0
    for _ in range(n):
        val = (val << 8) | buf[p]; p += 1
    return val, p


def _der_children(buf: bytes) -> list[tuple[int, bytes]]:
    """Split a DER SEQUENCE/SET body into (tag, content) children."""
    out = []
    p = 0
    while p < len(buf):
        tag = buf[p]; p += 1
        length, p = _der_read_len(buf, p)
        out.append((tag, buf[p:p + length]))
        p += length
    return out


def subject_dn_strings(cert_der: bytes) -> list[bytes]:
    """Return the RDN attribute value strings from the subject Name of a DER
    Certificate. Bounded, best-effort; returns [] on any structural surprise."""
    try:
        # Certificate ::= SEQ { tbsCertificate SEQ, sigAlg, sig }
        top = _der_children(cert_der)
        if not top or (top[0][0] & 0x1f) != 0x10:
            return []
        # Certificate content = { tbsCertificate SEQ, sigAlg SEQ, signature }
        cert_fields = _der_children(top[0][1])
        if not cert_fields or (cert_fields[0][0] & 0x1f) != 0x10:
            return []
        tbs = _der_children(cert_fields[0][1])
        # tbs: [0]version(optional, tag 0xA0), serial INT, sigAlg SEQ,
        #      issuer Name(SEQ), validity SEQ, subject Name(SEQ), ...
        idx = 0
        if tbs and tbs[0][0] == 0xA0:  # explicit [0] version
            idx = 1
        # serial, sigAlg, issuer, validity, subject
        # positions from idx: 0 serial,1 sigAlg,2 issuer,3 validity,4 subject
        if len(tbs) < idx + 5:
            return []
        subject = tbs[idx + 4]
        if (subject[0] & 0x1f) != 0x10:  # must be SEQUENCE
            return []
        vals: list[bytes] = []
        for rdn_tag, rdn in _der_children(subject[1]):   # SET OF ...
            if (rdn_tag & 0x1f) != 0x11:  # SET
                continue
            for atv_tag, atv in _der_children(rdn):       # SEQ type,value
                if (atv_tag & 0x1f) != 0x10:
                    continue
                parts = _der_children(atv)
                if len(parts) >= 2 and (parts[1][0] in _DER_STRING_TAGS):
                    vals.append(parts[1][1])
        return vals
    except (IndexError, ValueError):
        return []


# ---------------------------------------------------------------------------
# per-flow SMTP/TLS session state machine
# ---------------------------------------------------------------------------
class SmtpSession:
    """Processes ordered (direction, bytes) segments for one TCP flow.
    direction 'c' = client->server, 's' = server->client."""

    def __init__(self, af: str, cli_ep: str, srv_ep: str, srv_port: int) -> None:
        self.af = af
        self.cli_ep = cli_ep
        self.srv_ep = srv_ep
        self.srv_port = srv_port
        self.findings: list[Finding] = []

        # phase: 'smtp' cleartext, or 'tls'
        self.phase = "tls" if srv_port in IMPLICIT_TLS_PORTS else "smtp"
        self._cbuf = bytearray()
        self._sbuf = bytearray()

        # smtp state
        self.saw_banner = False
        self.banner_had_version = False
        self.tls_offered = False           # STARTTLS advertised in EHLO
        self.in_ehlo_reply = False
        self._starttls_pending = False     # client sent STARTTLS, await 220
        self.in_auth = False               # awaiting a b64 continuation
        self._pending_tainted_rcpt = False

        # tls state
        self.tls_c = TlsStream()
        self.tls_s = TlsStream()
        self.server_is_tls13 = False
        self._client_hello_seen = False
        self._version_gate_done = False

    # -- public entry -------------------------------------------------------
    def feed(self, direction: str, data: bytes):
        if self.phase == "smtp":
            self._feed_smtp(direction, data)
        else:
            self._feed_tls(direction, data)

    def finish(self):
        # if the banner was never seen at all on a cleartext port, that is a
        # closed gate (SMTP-014) only when we did observe SMTP traffic.
        if (self.srv_port not in IMPLICIT_TLS_PORTS
                and (self._saw_any_smtp) and not self.banner_had_version):
            self._emit("SMTP-014", "no parseable Exim version in banner; "
                                   "Class B version gate closed, Class A unaffected")

    # -- helpers ------------------------------------------------------------
    _saw_any_smtp = False

    def _emit(self, code: str, detail: str):
        self.findings.append(_make(code, self.af, detail, self.cli_ep, self.srv_ep))

    # -- SMTP cleartext -----------------------------------------------------
    def _feed_smtp(self, direction: str, data: bytes):
        self._saw_any_smtp = True
        buf = self._cbuf if direction == "c" else self._sbuf
        buf += data
        while True:
            idx = buf.find(b"\n")
            if idx < 0:
                break
            line = bytes(buf[:idx]).rstrip(b"\r\n")
            del buf[:idx + 1]
            if direction == "c":
                self._smtp_client_line(line)
            else:
                self._smtp_server_line(line)
            if self.phase != "smtp":
                # switched to TLS; hand any remaining bytes to the TLS parser
                leftover = bytes(buf)
                buf.clear()
                if leftover:
                    self._feed_tls(direction, leftover)
                return

    def _smtp_server_line(self, line: bytes):
        if len(line) < 3 or not line[:3].isdigit():
            return
        code = line[:3]
        # continuation marker: "250-" means more lines follow
        is_cont = len(line) > 3 and line[3:4] == b"-"

        if not self.saw_banner:
            self.saw_banner = True
            if code == b"220":
                v = parse_exim_version(line)
                if v is not None:
                    self.banner_had_version = True
                    self._run_version_gate(v, line)

        rest = line[4:] if len(line) > 4 else b""

        if code == b"250":
            up = rest.upper()
            if b"STARTTLS" in up:
                self.tls_offered = True
            if self._pending_tainted_rcpt:
                self._emit("SMTP-003",
                           "server returned 2xx to a RCPT TO carrying a ${...} "
                           "expansion; payload queued (execution occurs at "
                           "delivery, not observable on the wire)")
                self._pending_tainted_rcpt = False
        elif code[:1] in (b"4", b"5"):
            # tainted RCPT rejected -> attempt stands, accepted does not fire
            self._pending_tainted_rcpt = False

        if code == b"334":
            # server prompts for an AUTH continuation line
            self.in_auth = True
        elif self.in_auth:
            # any non-334 reply concludes the AUTH exchange (235 success,
            # 5xx failure, 501 malformed); a following client line is NOT a
            # base64 continuation. Without this, e.g. a trailing QUIT would be
            # mis-parsed as a continuation token (LESSON AA two-party state).
            self.in_auth = False

        if code == b"220" and self._starttls_pending:
            # STARTTLS accepted -> switch this flow to TLS
            self._starttls_pending = False
            self.phase = "tls"

    def _smtp_client_line(self, line: bytes):
        upper = line[:12].upper()

        if self.in_auth and not upper.startswith(b"AUTH"):
            # this is a base64 continuation response
            tok = line.strip()
            if triggers_6789(tok):
                self._emit("SMTP-006",
                           "AUTH continuation base64 of length %d (== 3 mod 4); "
                           "matches CVE-2018-6789 b64decode over-consume" % len(tok))
            # AUTH LOGIN has two continuations; stay until a non-334 reply.
            return

        if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
            if len(line) > EHLO_MAX_LEN:
                self._emit("SMTP-007",
                           "EHLO/HELO command line of %d octets exceeds the RFC "
                           "5321 512 limit (CVE-2019-16928 string_vformat "
                           "overflow shape)" % len(line))
            return

        if upper.startswith(b"MAIL FROM"):
            if b"${" in line:
                self._emit("SMTP-001",
                           "MAIL FROM contains a ${...} string expansion "
                           "(CVE-2019-10149 attempt)")
        elif upper.startswith(b"RCPT TO"):
            if b"${" in line:
                self._emit("SMTP-002",
                           "RCPT TO contains a ${...} string expansion "
                           "(CVE-2019-10149 attempt)")
                self._pending_tainted_rcpt = True
        elif upper.startswith(b"AUTH"):
            self.in_auth = True
            parts = line.split(None, 2)
            if len(parts) >= 3:
                tok = parts[2].strip()
                if triggers_6789(tok):
                    self._emit("SMTP-006",
                               "AUTH initial-response base64 of length %d "
                               "(== 3 mod 4); matches CVE-2018-6789" % len(tok))
        elif upper.startswith(b"STARTTLS"):
            self._starttls_pending = True

    def _run_version_gate(self, v: tuple[int, ...], banner: bytes):
        if self._version_gate_done:
            return
        self._version_gate_done = True
        vs = ".".join(str(x) for x in v)
        self._emit("SMTP-010", f"Exim {vs} disclosed in banner")
        if in_10149_range(v):
            self._emit("SMTP-011",
                       f"Exim {vs} within CVE-2019-10149 range (4.87-4.91); "
                       "distro backports may patch without a version bump - "
                       "treat as 'version in range', not confirmed vulnerable")
        if in_6789_range(v):
            self._emit("SMTP-013",
                       f"Exim {vs} below 4.90.1 (CVE-2018-6789 range); "
                       "backport caveat applies")
        if in_16928_range(v):
            self._emit("SMTP-015",
                       f"Exim {vs} within CVE-2019-16928 range (4.92-4.92.2); "
                       "backport caveat applies")
        # 15846 requires TLS to be offered; defer until EHLO parsed. record it.
        self._pending_15846 = v

    _pending_15846: Optional[tuple[int, ...]] = None

    # -- TLS ----------------------------------------------------------------
    def _feed_tls(self, direction: str, data: bytes):
        stream = self.tls_c if direction == "c" else self.tls_s
        for htype, body in stream.feed(data):
            if direction == "c" and htype == 1:      # ClientHello
                self._client_hello_seen = True
                for name in parse_client_hello_sni(body):
                    if b"\\" in name or b"\x00" in name:
                        self._emit("SMTP-004",
                                   "SNI host_name contains a backslash or NUL "
                                   "byte (CVE-2019-15846 trigger shape)")
            elif direction == "s" and htype == 2:    # ServerHello
                self.server_is_tls13 = server_hello_is_tls13(body)
            elif direction == "c" and htype == 11:   # client Certificate
                if self.server_is_tls13:
                    continue  # encrypted in 1.3 - documented blind spot
                self._check_client_cert(body)

    def _check_client_cert(self, body: bytes):
        # Certificate: 3-byte total len, then repeated 3-byte cert_len + cert
        try:
            if len(body) < 3:
                return
            total = (body[0] << 16) | (body[1] << 8) | body[2]
            p = 3
            end = min(len(body), 3 + total)
            while p + 3 <= end:
                clen = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2]
                p += 3
                cert = body[p:p + clen]
                p += clen
                for s in subject_dn_strings(cert):
                    if s.endswith(b"\\"):
                        self._emit("SMTP-005",
                                   "client certificate subject DN value ends "
                                   "in a backslash (CVE-2019-15846 peer-DN "
                                   "vector; TLS1.2 only, 1.3 is opaque)")
                        return
        except (IndexError, ValueError):
            return

    def resolve_deferred(self):
        """Call after all segments: emit SMTP-012 iff a 15846-range banner was
        seen AND STARTTLS/implicit-TLS is in play."""
        v = self._pending_15846
        if v is None:
            return
        tls_in_play = self.tls_offered or (self.srv_port in IMPLICIT_TLS_PORTS)
        if in_15846_range(v) and tls_in_play:
            vs = ".".join(str(x) for x in v)
            self._emit("SMTP-012",
                       f"Exim {vs} within CVE-2019-15846 range (<=4.92.1) and "
                       "TLS is offered; backport caveat applies")


# ---------------------------------------------------------------------------
# convenience driver used by tests and by run_capture's assembled flows
# ---------------------------------------------------------------------------
def analyze_segments(segments, af, cli_ep, srv_ep, srv_port) -> list[Finding]:
    """segments: ordered list of ('c'|'s', bytes)."""
    sess = SmtpSession(af, cli_ep, srv_ep, srv_port)
    for direction, data in segments:
        sess.feed(direction, data)
    sess.resolve_deferred()
    sess.finish()
    return sess.findings


# ---------------------------------------------------------------------------
# BPF filter (LESSON AE: bare `ip6` term; software port gate is load-bearing
# for IPv6 and needs its own negative test)
# ---------------------------------------------------------------------------
def bpf_filter() -> str:
    ports = " or ".join(f"port {p}" for p in SMTP_PORTS)
    return f"(tcp and ({ports})) or ip6"


def classify_flow(sport: int, dport: int):
    """The software port gate. Returns (direction, srv_port) or None.
    direction 'c' = packet flows client->server, 's' = server->client.

    This is LOAD-BEARING for IPv6: the BPF admits all ip6 (bare `ip6` term,
    LESSON AE), so this gate is the ONLY rejector of non-SMTP IPv6 traffic -
    a different code path from IPv4, where the kernel BPF drops the packet.
    It needs its own negative test (see conformance)."""
    if dport in SMTP_PORTS:
        return "c", dport
    if sport in SMTP_PORTS:
        return "s", sport
    return None


# ---------------------------------------------------------------------------
# live capture (only place scapy is imported)
# ---------------------------------------------------------------------------
def _flow_handler(flows, on_frame=None):
    """Build the per-packet handler shared by the live sniff and the pcap replay.
    Both paths must run the SAME software port gate (load-bearing for the bare
    `ip6` BPF admit), session assembly and finish/resolve sequence."""
    from scapy.all import TCP, IP, IPv6, Raw

    def flow_key(pkt):
        if IP in pkt:
            l3, af = pkt[IP], "ipv4"
        elif IPv6 in pkt:
            l3, af = pkt[IPv6], "ipv6"
        else:
            return None
        t = pkt[TCP]
        cls = classify_flow(t.sport, t.dport)
        if cls is None:
            return None  # software port gate (load-bearing for the bare-ip6 admit)
        direction, srv_port = cls
        s, d = (l3.src, t.sport), (l3.dst, t.dport)
        if direction == "c":
            srv, cli = d, s
        else:
            srv, cli = s, d
        key = (cli, srv, af)
        return key, direction, srv_port, af, cli, srv

    def handle(pkt):
        if on_frame is not None:
            on_frame(pkt)  # counts every admitted frame (BPF-capture proof)
        if TCP not in pkt or Raw not in pkt:
            return
        info = flow_key(pkt)
        if info is None:
            return
        key, direction, srv_port, af, cli, srv = info
        if key not in flows:
            cli_ep = render_ep(cli[0], cli[1], af)
            srv_ep = render_ep(srv[0], srv[1], af)
            flows[key] = SmtpSession(af, cli_ep, srv_ep, srv_port)
        flows[key].feed(direction, bytes(pkt[Raw].load))

    return handle


def _flow_findings(flows) -> list:
    out = []
    for sess in flows.values():
        sess.resolve_deferred()
        sess.finish()
        out.extend(sess.findings)
    return out


def run_capture(iface: str, timeout: Optional[int] = None,
                on_frame=None):  # pragma: no cover
    from scapy.all import sniff

    flows: dict = {}
    sniff(iface=iface, filter=bpf_filter(), store=False, timeout=timeout,
          prn=_flow_handler(flows, on_frame))
    return _flow_findings(flows)


def run_pcap(path: str, on_frame=None) -> list:
    """Replay a pcap through the same flow table the live path uses. This is how
    Ragnar's in-app do_smtp_watch drives the module: tcpdump writes the capture,
    the module only ever reads it."""
    from scapy.all import PcapReader

    flows: dict = {}
    handle = _flow_handler(flows, on_frame)
    with PcapReader(path) as rd:
        for pkt in rd:
            try:
                handle(pkt)
            except Exception:
                continue          # one malformed frame must never kill the scan
    return _flow_findings(flows)


def selftest() -> dict:
    """Adapt self_test() to the Ragnar Detector Self-Test aggregator shape."""
    import contextlib
    import io as _io
    buf = _io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = self_test()
    return {"success": rc == 0 and bool(_LAST_SELFTEST),
            "scenarios": [{"name": n, "pass": ok} for n, ok in _LAST_SELFTEST]}


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------
def _codes(findings) -> set:
    return {f.code for f in findings}


def self_test() -> int:
    checks = []

    def want(name, segs, af, port, must, mustnot=()):
        cli = render_ep("2001:db8::1" if af == "ipv6" else "10.0.0.1", 51000, af)
        srv = render_ep("2001:db8::2" if af == "ipv6" else "10.0.0.2", port, af)
        got = _codes(analyze_segments(segs, af, cli, srv, port))
        ok = set(must) <= got and not (set(mustnot) & got)
        checks.append((name, ok, must, mustnot, got))

    banner_vuln = b"220 mail ESMTP Exim 4.89 Ubuntu Mon\r\n"
    banner_patch = b"220 mail ESMTP Exim 4.94 Ubuntu Mon\r\n"
    ehlo_tls = (b"250-mail\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n")

    for af in ("ipv4", "ipv6"):
        # --- 10149 attempt in RCPT, accepted ---
        want("10149 rcpt accepted [%s]" % af, [
            ("s", banner_patch),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
            ("c", b"MAIL FROM:<a@b>\r\n"), ("s", b"250 ok\r\n"),
            ("c", b"RCPT TO:<${run{/bin/sh}}@localhost>\r\n"),
            ("s", b"250 accepted\r\n"),
        ], af, 25, must=["SMTP-002", "SMTP-003"], mustnot=["SMTP-001"])

        # --- 10149 in MAIL FROM, rejected -> attempt only, no accepted ---
        want("10149 mail rejected [%s]" % af, [
            ("s", banner_patch),
            ("c", b"MAIL FROM:<${run{id}}@x>\r\n"), ("s", b"550 no\r\n"),
        ], af, 25, must=["SMTP-001"], mustnot=["SMTP-003"])

        # --- legit MAIL/RCPT must not fire ---
        want("legit addresses silent [%s]" % af, [
            ("s", banner_patch),
            ("c", b"MAIL FROM:<user+tag@ex.com>\r\n"), ("s", b"250 ok\r\n"),
            ("c", b"RCPT TO:<dest@ex.com>\r\n"), ("s", b"250 ok\r\n"),
        ], af, 25, must=[], mustnot=["SMTP-001", "SMTP-002", "SMTP-003"])

        # --- a lone '$' without brace must not fire ---
        want("bare dollar silent [%s]" % af, [
            ("s", banner_patch),
            ("c", b"MAIL FROM:<cost$5@x>\r\n"), ("s", b"250 ok\r\n"),
        ], af, 25, must=[], mustnot=["SMTP-001"])

        # --- 6789 inline AUTH, len 4n+3 ---
        want("6789 inline auth [%s]" % af, [
            ("s", banner_patch),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
            ("c", b"AUTH PLAIN AAAAAAA\r\n"),  # 7 chars, %4==3
            ("s", b"535 no\r\n"),
        ], af, 25, must=["SMTP-006"])

        # --- 6789 continuation line (AUTH LOGIN) ---
        want("6789 continuation [%s]" % af, [
            ("s", banner_patch),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
            ("c", b"AUTH LOGIN\r\n"), ("s", b"334 VXNlcm5hbWU6\r\n"),
            ("c", b"AAAAAAAAAAA\r\n"),  # 11 chars, %4==3
            ("s", b"535 no\r\n"),
        ], af, 25, must=["SMTP-006"])

        # --- valid padded base64 must not fire ---
        want("valid b64 auth silent [%s]" % af, [
            ("s", banner_patch),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
            ("c", b"AUTH PLAIN AGZvbwBiYXI=\r\n"),  # 12 chars, %4==0
            ("s", b"235 ok\r\n"),
        ], af, 25, must=[], mustnot=["SMTP-006"])

        # --- '=' empty initial response must not fire ---
        want("empty ir silent [%s]" % af, [
            ("s", banner_patch),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
            ("c", b"AUTH PLAIN =\r\n"), ("s", b"334 \r\n"),
        ], af, 25, must=[], mustnot=["SMTP-006"])

        # --- Class B: vulnerable banner fires 011/013, and 012 (TLS offered) ---
        want("banner ranges + tls [%s]" % af, [
            ("s", banner_vuln),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
        ], af, 25, must=["SMTP-010", "SMTP-011", "SMTP-012", "SMTP-013"])

        # --- patched banner: only version disclosed, no range findings ---
        want("patched banner silent [%s]" % af, [
            ("s", banner_patch),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
        ], af, 25, must=["SMTP-010"],
           mustnot=["SMTP-011", "SMTP-012", "SMTP-013"])

        # --- 15846 range but NO TLS offered -> no 012 ---
        want("15846 no tls no 012 [%s]" % af, [
            ("s", b"220 mail ESMTP Exim 4.91 x\r\n"),
            ("c", b"EHLO x\r\n"), ("s", b"250 mail\r\n250 SIZE 100\r\n"),
        ], af, 25, must=["SMTP-011"], mustnot=["SMTP-012"])

        # --- suppressed banner -> gate closed 014, Class A still works ---
        want("suppressed banner gate closed [%s]" % af, [
            ("s", b"220 mail ESMTP service ready\r\n"),
            ("c", b"MAIL FROM:<${run{id}}@x>\r\n"), ("s", b"250 ok\r\n"),
        ], af, 25, must=["SMTP-014", "SMTP-001"],
           mustnot=["SMTP-010", "SMTP-011"])

        # --- 16928 overlong EHLO fires SMTP-007 ---
        long_ehlo = b"EHLO " + b"A" * 600 + b"\r\n"
        want("16928 overlong ehlo [%s]" % af, [
            ("s", banner_patch), ("c", long_ehlo), ("s", b"500 line too long\r\n"),
        ], af, 25, must=["SMTP-007"])

        # --- normal EHLO must NOT fire SMTP-007 ---
        want("normal ehlo silent [%s]" % af, [
            ("s", banner_patch), ("c", b"EHLO mail.example.com\r\n"), ("s", ehlo_tls),
        ], af, 25, must=[], mustnot=["SMTP-007"])

        # --- 16928 banner range: 4.92.2 is covered ONLY by 16928 (not 15846) ---
        want("16928 banner 4.92.2 [%s]" % af, [
            ("s", b"220 mail ESMTP Exim 4.92.2 x\r\n"),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
        ], af, 25, must=["SMTP-010", "SMTP-015"],
           mustnot=["SMTP-011", "SMTP-012", "SMTP-013"])

        # --- 4.92 sits in BOTH 15846 and 16928 (overlap), with STARTTLS ---
        want("16928+15846 overlap 4.92 [%s]" % af, [
            ("s", b"220 mail ESMTP Exim 4.92 x\r\n"),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
        ], af, 25, must=["SMTP-012", "SMTP-015"], mustnot=["SMTP-011", "SMTP-013"])

        # --- 4.92.3 is the fix: no 16928 range finding ---
        want("16928 fix 4.92.3 [%s]" % af, [
            ("s", b"220 mail ESMTP Exim 4.92.3 x\r\n"),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
        ], af, 25, must=["SMTP-010"], mustnot=["SMTP-015"])

        # --- 4.89 is below the 16928 range: no SMTP-015 ---
        want("4.89 below 16928 [%s]" % af, [
            ("s", banner_vuln),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
        ], af, 25, must=["SMTP-011", "SMTP-013"], mustnot=["SMTP-015"])

        # --- comparator trap: 4.90.1 is THE fix for 6789, must NOT fire 013 ---
        want("4.90.1 is 6789 fix [%s]" % af, [
            ("s", b"220 mail ESMTP Exim 4.90.1 x\r\n"),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
        ], af, 25, must=["SMTP-010", "SMTP-011"], mustnot=["SMTP-013"])

        # --- comparator trap: 4.90.0.27 fixup is BEFORE 4.90.1, must fire 013 ---
        want("4.90.0.27 fixup pre-fix [%s]" % af, [
            ("s", b"220 mail ESMTP Exim 4.90.0.27 x\r\n"),
            ("c", b"EHLO x\r\n"), ("s", ehlo_tls),
        ], af, 25, must=["SMTP-013"])

    # --- 15846 client-cert DN trailing backslash over TLS1.2 (SMTP-005) ---
    tls12_flow = [
        ("s", b"220 mail ESMTP Exim 4.94 x\r\n"),
        ("c", b"EHLO x\r\n"), ("s", b"250-mail\r\n250 STARTTLS\r\n"),
        ("c", b"STARTTLS\r\n"), ("s", b"220 go\r\n"),
        ("c", _mk_client_hello(b"mail.example.com")),
        ("s", _mk_server_hello_tls12()),
        ("c", _mk_client_cert(b"evil.example.com\\")),
    ]
    want("15846 client-cert dn tls1.2", tls12_flow, "ipv4", 587,
         must=["SMTP-005"])

    # --- same cert but TLS1.3 negotiated -> opaque, must NOT fire 005 ---
    tls13_flow = [
        ("s", b"220 mail ESMTP Exim 4.94 x\r\n"),
        ("c", b"EHLO x\r\n"), ("s", b"250-mail\r\n250 STARTTLS\r\n"),
        ("c", b"STARTTLS\r\n"), ("s", b"220 go\r\n"),
        ("c", _mk_client_hello(b"mail.example.com")),
        ("s", _mk_server_hello_tls13()),
        ("c", _mk_client_cert(b"evil.example.com\\")),
    ]
    want("15846 tls1.3 opaque no 005", tls13_flow, "ipv4", 587,
         must=[], mustnot=["SMTP-005"])

    # --- clean client-cert DN must not fire ---
    tls12_clean = [
        ("s", b"220 mail ESMTP Exim 4.94 x\r\n"),
        ("c", b"EHLO x\r\n"), ("s", b"250-mail\r\n250 STARTTLS\r\n"),
        ("c", b"STARTTLS\r\n"), ("s", b"220 go\r\n"),
        ("c", _mk_client_hello(b"mail.example.com")),
        ("s", _mk_server_hello_tls12()),
        ("c", _mk_client_cert(b"good.example.com")),
    ]
    want("15846 clean cert silent", tls12_clean, "ipv4", 587,
         must=[], mustnot=["SMTP-005"])

    # --- STARTTLS switch: SNI backslash after upgrade on 587 ---
    ch = _mk_client_hello(b"ex\\ample.com")
    want("15846 sni after starttls", [
        ("s", b"220 mail ESMTP Exim 4.94 x\r\n"),
        ("c", b"EHLO x\r\n"), ("s", b"250-mail\r\n250 STARTTLS\r\n"),
        ("c", b"STARTTLS\r\n"), ("s", b"220 go ahead\r\n"),
        ("c", ch),
    ], "ipv4", 587, must=["SMTP-004"])

    # --- implicit TLS on 465: clean SNI must not fire ---
    ch_ok = _mk_client_hello(b"mail.example.com")
    want("465 clean sni silent", [("c", ch_ok)], "ipv4", 465,
         must=[], mustnot=["SMTP-004"])

    # --- 465 SNI with NUL fires ---
    ch_nul = _mk_client_hello(b"mail\x00.example.com")
    want("465 nul sni fires", [("c", ch_nul)], "ipv4", 465, must=["SMTP-004"])

    # report
    del _LAST_SELFTEST[:]
    _LAST_SELFTEST.extend((name, bool(ok)) for name, ok, *_ in checks)
    passed = sum(1 for _, ok, *_ in checks if ok)
    total = len(checks)
    for name, ok, must, mustnot, got in checks:
        if not ok:
            print(f"  FAIL {name}: want>={sorted(must)} not{sorted(mustnot)} "
                  f"got={sorted(got)}")
    print(f"self-test: {passed}/{total}")
    return 0 if passed == total else 1


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.insert(0, n & 0xff); n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _mk_client_cert(cn: bytes) -> bytes:
    """Minimal TLS1.2 client Certificate handshake message whose single cert
    has a subject DN with one RDN (CN=cn)."""
    # AttributeTypeAndValue: SEQ { OID cn(2.5.4.3), UTF8String cn }
    oid_cn = _der(0x06, bytes([0x55, 0x04, 0x03]))
    atv = _der(0x30, oid_cn + _der(0x0c, cn))
    rdn = _der(0x31, atv)                 # SET
    name = _der(0x30, rdn)                # SEQUENCE OF RDN
    serial = _der(0x02, b"\x01")
    sigalg = _der(0x30, _der(0x06, bytes([0x2a, 0x86, 0x48, 0x86, 0xf7,
                                          0x0d, 0x01, 0x01, 0x0b])))
    validity = _der(0x30, _der(0x17, b"000101000000Z") + _der(0x17, b"010101000000Z"))
    issuer = name
    subject = name
    tbs = _der(0x30, serial + sigalg + issuer + validity + subject)
    cert = _der(0x30, tbs + sigalg + _der(0x03, b"\x00\x00"))
    # Certificate message: 3-byte list len, then 3-byte cert len + cert
    inner = len(cert).to_bytes(3, "big") + cert
    body = len(inner).to_bytes(3, "big") + inner
    hs = b"\x0b" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _mk_server_hello_tls12() -> bytes:
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00"   # ver 1.2, random, sid_len 0
            + b"\x00\x2f" + b"\x00")                # cipher_suite + comp
    body += b"\x00\x00"                             # empty extensions
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _mk_server_hello_tls13() -> bytes:
    sv = b"\x00\x2b\x00\x02\x03\x04"               # supported_versions -> 1.3
    ext = len(sv).to_bytes(2, "big") + sv
    body = (b"\x03\x03" + b"\x22" * 32 + b"\x00"
            + b"\x13\x01" + b"\x00" + ext)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _mk_client_hello(hostname: bytes) -> bytes:
    """Build a minimal TLS record carrying a ClientHello with one SNI name."""
    sni_list = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    sni_ext_data = len(sni_list).to_bytes(2, "big") + sni_list
    ext = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"        # ver, random, sid_len
            + b"\x00\x02\x00\x2f"                         # cs_len + one suite
            + b"\x01\x00"                                 # comp
            + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    return rec


# ---------------------------------------------------------------------------
# registry sanity (fails loudly if the table is internally inconsistent)
# ---------------------------------------------------------------------------
def _validate_registry():
    for code, m in CODES.items():
        assert m["sev"] in SEVERITIES, code
        assert m["conf"] in CONFIDENCES, code
        assert m["cls"] in CLASSES, code


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    _validate_registry()
    ap = argparse.ArgumentParser(description="smtpwatch - passive Exim CVE detector")
    ap.add_argument("--iface", help="interface to sniff")
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--print-bpf", action="store_true")
    ap.add_argument("--print-codes", action="store_true")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.print_bpf:
        print(bpf_filter())
        return 0
    if args.print_codes:
        for c, m in CODES.items():
            print(f"{c}\t{m['cls']}\t{m['sev']}\t{m['conf']}\t{m['cve']}\t{m['name']}")
        return 0
    if args.iface:
        findings = run_capture(args.iface, args.timeout)
        if args.json:
            print(json.dumps([f.to_dict() for f in findings], indent=2))
        else:
            for f in findings:
                print(f"[{f.severity}] {f.code} {f.srv_ep} {f.detail}")
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
