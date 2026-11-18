#!/usr/bin/env python3
"""httpwatch - passive HTTP/1.x, h2c and gRPC observer for Ragnar.

Layer 7. Cleartext only: HTTP over TLS belongs to tlswatch/certwatch.
Emits nothing on the wire. Every finding comes from bytes other hosts
already sent.

Tiers:
  A  HTTP/1.x framing ambiguity (request smuggling / desync)
  B  HTTP.sys parser CVEs
  C  Credential-in-the-clear posture and slow-read abuse
  D  Cleartext HTTP/2 (h2c) and gRPC

Dual-stack by construction: all rules are L7 over TCP and
address-family agnostic; the capture path admits IPv6 explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "0.1.0-dev"
MODULE = "httpwatch"

# ---------------------------------------------------------------------------
# Finding registry
# ---------------------------------------------------------------------------

INFO, WARN, HIGH, CRITICAL = "info", "warn", "high", "critical"

# confidence classes, as used suite-wide:
#   exact    - the observation IS the condition, no inference
#   shape    - the malformation is read directly; the victim's state is not
#   heuristic- threshold/volume or name-matched, needs judgement
EXACT, SHAPE, HEURISTIC, POSTURE = "exact", "shape", "heuristic", "posture"


@dataclass(frozen=True)
class FindingDef:
    code: str
    name: str
    tier: str
    severity: str
    confidence: str
    summary: str
    cves: Tuple[str, ...] = ()


def _f(code, name, tier, sev, conf, summary, cves=()):
    return FindingDef(code, name, tier, sev, conf, summary, tuple(cves))


FINDING_REGISTRY: Dict[str, FindingDef] = {
    d.code: d
    for d in [
        # ---- Tier A: framing ambiguity ----------------------------------
        _f("HTTP-001", "cl_te_conflict", "A", WARN, POSTURE,
           "Content-Length and Transfer-Encoding both present in one message",
           ["CVE-2026-42584"]),
        _f("HTTP-002", "te_nonstandard", "A", HIGH, SHAPE,
           "Transfer-Encoding is not a clean coding list ending in 'chunked'",
           ["CVE-2026-69205"]),
        _f("HTTP-003", "cl_invalid", "A", HIGH, SHAPE,
           "Content-Length is signed, non-numeric, padded or self-contradictory"),
        _f("HTTP-004", "chunk_size_invalid", "A", HIGH, SHAPE,
           "Chunk size is not plain hex or exceeds 64-bit range",
           ["CVE-2026-42580"]),
        _f("HTTP-005", "chunk_ext_malformed", "A", HIGH, SHAPE,
           "Chunk extension has an unclosed quote, a bare CR/LF or is oversized",
           ["CVE-2026-2332", "CVE-2026-42585"]),
        _f("HTTP-006", "bare_line_terminator", "A", INFO, SHAPE,
           "Bare LF or bare CR used as a line terminator"),
        _f("HTTP-007", "header_name_whitespace", "A", HIGH, SHAPE,
           "Whitespace between a field name and its colon (RFC 9112 5.1)"),
        _f("HTTP-008", "obs_fold_request", "A", WARN, SHAPE,
           "Obsolete line folding in a request header section (RFC 9112 5.2)"),
        _f("HTTP-009", "framer_disagreement", "A", CRITICAL, SHAPE,
           "CL and TE framers end the message at different offsets and the "
           "remainder parses as a request line"),
        _f("HTTP-010", "response_framing_anomaly", "A", HIGH, SHAPE,
           "Response framing is ambiguous or trailing bytes are not a status line"),
        _f("HTTP-011", "host_conflict", "A", WARN, SHAPE,
           "Multiple Host headers, or Host disagrees with an absolute-form target"),
        # ---- Tier B: HTTP.sys -------------------------------------------
        _f("HTTP-020", "cve_2015_1635_range_overflow", "B", CRITICAL, SHAPE,
           "Range header end position at or beyond 2**63 (MS15-034)",
           ["CVE-2015-1635"]),
        _f("HTTP-021", "cve_2021_31166_accept_encoding", "B", CRITICAL, SHAPE,
           "Accept-Encoding with an empty list element after unknown codings",
           ["CVE-2021-31166"]),
        _f("HTTP-022", "cve_2022_21907_request_trailers", "B", WARN, POSTURE,
           "Chunked request carrying trailer fields toward an http.sys host",
           ["CVE-2022-21907"]),
        # ---- Tier C: posture ---------------------------------------------
        _f("HTTP-040", "basic_auth_cleartext", "C", HIGH, EXACT,
           "HTTP Basic credentials sent over cleartext HTTP"),
        _f("HTTP-041", "form_password_cleartext", "C", HIGH, HEURISTIC,
           "Form POST carrying a password-like field over cleartext HTTP"),
        _f("HTTP-042", "cookie_credentials_cleartext", "C", HIGH, HEURISTIC,
           "Cookie carrying username-like and password-like keys in cleartext"),
        _f("HTTP-043", "cve_2025_25613_fs_cookie", "C", HIGH, SHAPE,
           "FS S3150-8T2F credential cookie triple (username/password/GSESSIONID)",
           ["CVE-2025-25613"]),
        _f("HTTP-044", "target_credentials", "C", HIGH, EXACT,
           "Credentials in the request target (userinfo or query string)"),
        _f("HTTP-045", "trace_method", "C", INFO, EXACT,
           "TRACE method request observed"),
        _f("HTTP-046", "slow_headers", "C", WARN, HEURISTIC,
           "One source holding many header sections open below the minimum rate"),
        _f("HTTP-047", "slow_body", "C", WARN, HEURISTIC,
           "One source delivering many declared bodies below the minimum rate"),
        # ---- Tier D: h2c / gRPC -------------------------------------------
        _f("HTTP-060", "h2c_cleartext", "D", INFO, EXACT,
           "Cleartext HTTP/2 (h2c) in use; warn when the path is gNMI/gNOI"),
        _f("HTTP-061", "cve_2023_44487_rapid_reset", "D", HIGH, HEURISTIC,
           "Streams opened and reset before any server frame, beyond the "
           "server's advertised concurrency limit",
           ["CVE-2023-44487"]),
        _f("HTTP-062", "continuation_abuse", "D", HIGH, SHAPE,
           "Header block oversized, over-fragmented, or interrupted by another frame",
           ["CVE-2023-32731", "CVE-2023-33953"]),
        _f("HTTP-063", "hpack_overlong_integer", "D", HIGH, SHAPE,
           "HPACK prefix integer with a trailing zero continuation group",
           ["CVE-2023-33953"]),
        _f("HTTP-064", "grpc_header_violation", "D", HIGH, EXACT,
           "gRPC te/:scheme/grpclb_client_stats header violation",
           ["CVE-2023-1428"]),
        _f("HTTP-065", "grpc_metadata_credentials", "D", HIGH, EXACT,
           "Credentials in gRPC metadata on a cleartext h2 connection"),
    ]
}

# CVE catalog: score of record, dissent, KEV status.  Scores not yet pinned
# against a primary source carry score=None and are never reported as fact.
CVE_CATALOG: Dict[str, Dict[str, Any]] = {
    "CVE-2015-1635": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": True, "kev_added": "2022-02-10", "alias": "MS15-034",
        "note": "http.sys Range integer overflow; DoS confirmed, RCE claimed "
                "by Microsoft but never publicly demonstrated.",
    },
    "CVE-2021-31166": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": True, "kev_added": "2022-04-06", "kev_due": "2022-04-27",
        "note": "http.sys Accept-Encoding use-after-free. KEV confirmed "
                "2026-11-16. Public PoCs achieve DoS only, but CISA lists it "
                "as exploited, so it is treated as KEV-priority.",
    },
    "CVE-2022-21907": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": False,
        "note": "http.sys HTTP trailer handling. NOT in the CISA KEV catalog "
                "(checked 2026-11-16); VulnCheck KEV lists it from 2024-05-07 "
                "and CISA's own ADP records Exploitation: none, so the "
                "evidence conflicts and CISA's is the one recorded here. "
                "Microsoft named the component but not the malformation: "
                "posture-of-possible is the ceiling.",
    },
    "CVE-2025-25613": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "kev": False, "cwe": "CWE-312",
        "note": "FS S3150-8T2F firmware < 2.2.0D sends base64 username and "
                "password in a cookie on every POST.",
    },
    "CVE-2023-44487": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "kev": True, "kev_added": "2023-10-10", "alias": "HTTP/2 Rapid Reset",
        "note": "Protocol-level: no patch removes RST_STREAM, only limits it.",
    },
    "CVE-2023-33953": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "kev": False,
        "note": "gRPC HPACK: unbounded buffering, O(n^2) parse, varint zero-pad.",
    },
    "CVE-2023-32731": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "kev": False,
        "note": "gRPC skipped the rest of an HPACK frame after a size error.",
    },
    "CVE-2023-1428": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "kev": False,
        "note": "gRPC C++ abort() on te/:scheme/grpclb_client_stats once the "
                "header list passes 8 KiB.",
    },
    "CVE-2026-42584": {
        "score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "kev": False,
        "note": "Netty HttpObjectDecoder keeps a conflicting Content-Length on "
                "HTTP/1.0 requests (the 1.1-only guard).",
    },
    # Pinned 2026-11-16 against NVD and the vendor records. Where sources
    # disagree the catalog carries the figure of record AND the dissent,
    # the same discipline tlswatch applies to SWEET32 and CVE-2018-0732.
    "CVE-2026-2332": {
        "score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "kev": False, "disputed": True,
        "dissent": "Red Hat 7.4, CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N "
                   "(AC:H rather than AC:L)",
        "note": "Jetty terminates chunk-extension parsing at CRLF inside an "
                "unclosed quoted string ('funky chunks'). NVD 9.1; Red Hat "
                "rates the attack complexity higher. Above the bar either way.",
    },
    "CVE-2026-42585": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "kev": False, "disputed": True,
        "dissent": "GitHub (CNA) 6.5, "
                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "note": "Netty quoted-string parsing in chunk extensions. NVD 7.5, "
                "GitHub as CNA 6.5. Clears the 6.5 bar on either figure.",
    },
    "CVE-2026-69205": {
        "score": 8.7, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "kev": False,
        "note": "http4s Ember matched Transfer-Encoding with a case-sensitive "
                "substring test, against RFC 9112 7. Scored by GitHub as CNA; "
                "scope-changed, which is why it outscores its siblings.",
    },
    "CVE-2026-42580": {
        "score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "kev": False, "disputed": True,
        "dissent": "SUSE 7.3; Red Hat 6.5 with "
                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "note": "Netty's chunk size parser silently overflows int (CWE-190 + "
                "CWE-444). Sits exactly ON the 6.5 bar. NOTE: this CVE was "
                "originally recorded here as CVE-2026-41417, which is a "
                "different Netty bug - see DEFERRED_CVES.",
    },
}

# CVEs considered and deliberately NOT detected, with the reason.  The
# self-test asserts this is disjoint from the detected set and that every
# reason is substantive (ciscoguard DEFERRED_CVES pattern).
DEFERRED_CVES: Dict[str, str] = {
    "CVE-2026-47291": (
        "HTTP.sys TLS header-line record flood. Assigned to tlswatch on "
        "2026-10-31: it is port-agnostic http.sys over TLS, and the record "
        "layer is tlswatch's to read. Not a cleartext observation."
    ),
    "CVE-2023-4785": (
        "gRPC accept-loop error handling under fd exhaustion. The wire shows "
        "ordinary connection attempts; nothing distinguishes the triggering "
        "flood from load. No observable artifact."
    ),
    "CVE-2024-7246": (
        "gRPC HPACK table poisoning. NVD 5.3, below the 6.5 bar, and Red Hat "
        "scores it lower still at 4.8."
    ),
    "CVE-2023-32732": (
        "gRPC base64 error on -bin suffixed headers. 5.3, below the bar."
    ),
    "CVE-2026-41417": (
        "Netty request-line validation bypass via setUri(): attacker input "
        "reaching that API permits CRLF injection. Deferred on two grounds. "
        "The defect is in an application's use of a library API, not in "
        "anything on the wire - what crosses is an ordinary injected request, "
        "already caught generically by HTTP-009 and HTTP-011 with no CVE "
        "attribution needed. And the CNA scores it 5.3, below the bar (Red "
        "Hat 6.5, NVD none). It was briefly mis-attributed to HTTP-004 as the "
        "chunk-size overflow; that bug is CVE-2026-42580."
    ),
    "CVE-2020-7768": (
        "grpc-js prototype pollution via loadPackageDefinition. The defect is "
        "in a local API call, not in anything that crosses the wire."
    ),
}


def finding_codes() -> List[str]:
    return sorted(FINDING_REGISTRY)


# ---------------------------------------------------------------------------
# Capture filter
# ---------------------------------------------------------------------------

def build_bpf(tcp_ports: Sequence[int]) -> str:
    """Build the capture filter.

    IPv4 stays port-scoped so the kernel rejects what it can. IPv6 is admitted
    by a bare `ip6` term and the port decision is made after dissection,
    because libpcap's `tcp port N` reads the Next Header field at a fixed
    offset and any extension header puts something other than 6 there - the
    frame is then dropped before the dissector sees it. Measured for tlswatch
    in Sept 2026: a port-only filter matched 2 of 6 probe packets, this shape
    matched all 6.

    The cost is explicit: on an IPv6-heavy segment every IPv6 frame is copied
    to userspace and dropped in Python. That is the price of not silently
    missing HTTP on any link using extension headers.
    """
    if not tcp_ports:
        raise ValueError("at least one TCP port is required")
    ports = sorted({int(p) for p in tcp_ports})
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"port out of range: {p}")
    v4 = " or ".join(f"tcp port {p}" for p in ports)
    return f"({v4}) or ip6"


DEFAULT_TCP_PORTS = (80, 8080, 8000, 8888, 5985, 50051, 9339, 6030, 57400)

# Service map. Used only to scope suppressions, never to screen versions.
SERVICE_PORTS: Dict[int, str] = {
    80: "http", 8080: "http", 8000: "http", 8888: "http",
    5985: "winrm", 50051: "grpc", 9339: "gnmi", 6030: "gnmi", 57400: "gnmi",
}

# rpcwatch owns WinRM authentication posture; do not report it twice.
SERVICE_SUPPRESS: Dict[str, Tuple[str, ...]] = {
    "winrm": ("HTTP-040", "HTTP-041"),
}


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def redact(secret: bytes | str) -> str:
    """Hash a secret to a short correlatable token.

    Findings must never carry a usable credential: a log that leaks what it
    is defending against is worse than no log. Eight hex digits is enough to
    notice the same password twice and useless to anyone reading it.
    """
    if isinstance(secret, str):
        secret = secret.encode("utf-8", "replace")
    return "sha256:" + hashlib.sha256(secret).hexdigest()[:8]


# ---------------------------------------------------------------------------
# HTTP/1.x parsing
# ---------------------------------------------------------------------------

METHOD_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
STATUS_LINE_RE = re.compile(rb"^HTTP/1\.[01] [0-9]{3}")
REQUEST_LINE_RE = re.compile(
    rb"^([!#$%&'*+\-.^_`|~0-9A-Za-z]+) (\S+) HTTP/1\.([01])$")

TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

MAX_HEADER_SECTION = 64 * 1024
MAX_CHUNK_EXT = 4096
# How far past the chunked terminator a Content-Length may claim
# before it is treated as bogus rather than waited for.
AMBIGUITY_WINDOW = 64 * 1024

# RFC 9110 content codings plus the ones http.sys knows about. Anything
# outside this set is "unknown" for the CVE-2021-31166 arming condition.
KNOWN_CODINGS = frozenset(
    b"gzip x-gzip deflate compress x-compress br zstd identity *".split())


@dataclass
class ParsedMessage:
    """One HTTP/1 message as it actually appeared on the wire.

    Deviations are recorded, never corrected: a parser that normalises its
    input destroys the only evidence this module exists to find.
    """
    kind: str                       # "request" | "response"
    method: Optional[bytes] = None
    target: Optional[bytes] = None
    version: Optional[bytes] = None
    status: Optional[int] = None
    headers: List[Tuple[bytes, bytes]] = field(default_factory=list)
    # raw observations
    bare_lf: bool = False
    bare_cr: bool = False
    obs_fold: bool = False
    space_before_colon: bool = False
    header_bytes: int = 0
    body_offset: int = 0            # offset of the first body byte
    complete: bool = False
    truncated: bool = False

    def get_all(self, name: bytes) -> List[bytes]:
        low = name.lower()
        return [v for (n, v) in self.headers if n.lower() == low]

    def get(self, name: bytes) -> Optional[bytes]:
        vals = self.get_all(name)
        return vals[0] if vals else None


def split_header_section(buf: bytes) -> Optional[Tuple[bytes, int]]:
    """Return (header section, offset of the first body byte), or None.

    A bare-LF blank line terminates the section too. Servers differ on this
    and that difference is itself a desync primitive, so the parser accepts
    what a tolerant server accepts and records it.
    """
    i = buf.find(b"\r\n\r\n")
    j = buf.find(b"\n\n")
    if i >= 0 and (j < 0 or i + 2 <= j):
        return buf[:i], i + 4
    if j >= 0:
        return buf[:j], j + 2
    return None


def parse_message(buf: bytes, kind: str) -> Optional[ParsedMessage]:
    """Parse one HTTP/1 message head. Returns None if the head is incomplete."""
    split = split_header_section(buf)
    if split is None:
        if len(buf) > MAX_HEADER_SECTION:
            m = ParsedMessage(kind=kind, truncated=True)
            m.header_bytes = len(buf)
            return m
        return None
    section, body_off = split
    msg = ParsedMessage(kind=kind, header_bytes=len(section),
                        body_offset=body_off)

    # Split on LF, then strip one trailing CR. A line that did not end in CR
    # was terminated by a bare LF.
    raw_lines = section.split(b"\n")
    lines: List[bytes] = []
    for idx, ln in enumerate(raw_lines):
        if ln.endswith(b"\r"):
            lines.append(ln[:-1])
        else:
            lines.append(ln)
            # The final element carries no terminator at all - the section was
            # cut before the blank line - so it is never evidence of a bare LF.
            if idx < len(raw_lines) - 1:
                msg.bare_lf = True
    for ln in lines:
        if b"\r" in ln:
            msg.bare_cr = True

    if not lines or not lines[0]:
        return None
    first = lines[0]

    if kind == "request":
        m = REQUEST_LINE_RE.match(first)
        if not m:
            return None
        msg.method, msg.target = m.group(1), m.group(2)
        msg.version = b"1." + m.group(3)
    else:
        if not STATUS_LINE_RE.match(first):
            return None
        msg.version = first[5:8]
        try:
            msg.status = int(first[9:12])
        except ValueError:
            return None

    for ln in lines[1:]:
        if not ln:
            continue
        if ln[:1] in (b" ", b"\t"):
            # obs-fold: continuation of the previous field value
            msg.obs_fold = True
            if msg.headers:
                n, v = msg.headers[-1]
                msg.headers[-1] = (n, v + b" " + ln.strip())
            continue
        c = ln.find(b":")
        if c < 0:
            continue
        name = ln[:c]
        value = ln[c + 1:].strip(b" \t")
        if name != name.strip(b" \t"):
            # RFC 9112 5.1: a recipient MUST reject such a message
            msg.space_before_colon = True
            name = name.strip(b" \t")
        msg.headers.append((name, value))

    msg.complete = True
    return msg


# --- framing ---------------------------------------------------------------

@dataclass
class FramingView:
    """How one framer would delimit this message's body."""
    framer: str                     # "cl" | "te" | "none"
    body_len: Optional[int]         # None when it cannot be determined
    end_offset: Optional[int]       # absolute offset just past the body
    error: Optional[str] = None


def parse_content_length(values: Sequence[bytes]) -> Tuple[Optional[int], List[str]]:
    """Parse Content-Length values. Returns (value, list of defects).

    RFC 9112 6.3: a valid field value is 1*DIGIT, nothing else. A sign, a
    space or a non-digit makes the message invalid, and different stacks
    disagree about which of those they accept - which is the whole attack.
    """
    defects: List[str] = []
    if not values:
        return None, defects
    parsed: List[int] = []
    for v in values:
        # a single field may itself be a comma list
        for part in v.split(b","):
            p = part.strip(b" \t")
            if not p:
                defects.append("empty_value")
                continue
            if not p.isdigit():
                defects.append("non_digit")
                continue
            parsed.append(int(p))
    if not parsed:
        return None, defects
    if len(set(parsed)) > 1:
        defects.append("conflicting_values")
    elif len(parsed) > 1:
        defects.append("duplicate_values")
    return parsed[0], defects


def analyse_transfer_encoding(values: Sequence[bytes]) -> Dict[str, Any]:
    """Decide whether this message is chunked, and record every deviation.

    The comparison is case-insensitive per RFC 9112 7 - the http4s Ember bug
    (CVE-2026-69205) is precisely a case-sensitive test here - but a value
    that needed anything beyond case folding to recognise is reported, since
    the next hop may not fold the same way.
    """
    out: Dict[str, Any] = {
        "present": bool(values), "chunked": False, "defects": [],
        "codings": [],
    }
    if not values:
        return out
    if len(values) > 1:
        out["defects"].append("duplicate_header")
    codings: List[bytes] = []
    for v in values:
        for part in v.split(b","):
            p = part.strip(b" \t")
            codings.append(p)
    out["codings"] = [c.decode("latin-1") for c in codings]
    for c in codings:
        if not c:
            out["defects"].append("empty_coding")
            continue
        if not TOKEN_RE.match(c.split(b";")[0]):
            out["defects"].append("non_token_coding")
    last = codings[-1] if codings else b""
    base = last.split(b";")[0]
    if base.lower() == b"chunked":
        out["chunked"] = True
        if base != b"chunked":
            out["defects"].append("case_variant")
    else:
        # is "chunked" hiding anywhere other than last position?
        for c in codings[:-1]:
            if c.split(b";")[0].lower() == b"chunked":
                out["defects"].append("chunked_not_last")
                out["chunked"] = True
        if not out["chunked"]:
            for c in codings:
                cl = c.lower()
                if b"chunked" in cl and cl.split(b";")[0] != b"chunked":
                    # "notchunked", "chunkedx": a substring test would match
                    out["defects"].append("chunked_substring")
            if not out["defects"]:
                out["defects"].append("unknown_coding")
    return out


@dataclass
class ChunkScan:
    total_body: Optional[int]
    end_offset: Optional[int]
    complete: bool
    defects: List[str] = field(default_factory=list)
    ext_defects: List[str] = field(default_factory=list)
    trailers: List[Tuple[bytes, bytes]] = field(default_factory=list)
    bare_lf: bool = False


def scan_chunked(buf: bytes, start: int) -> ChunkScan:
    """Walk a chunked body from `start`, recording every grammar violation."""
    sc = ChunkScan(total_body=0, end_offset=None, complete=False)
    pos = start
    total = 0
    guard = 0
    while pos < len(buf):
        guard += 1
        if guard > 10000:
            sc.defects.append("too_many_chunks")
            break
        nl = buf.find(b"\n", pos)
        if nl < 0:
            break
        line = buf[pos:nl]
        if line.endswith(b"\r"):
            line = line[:-1]
        else:
            sc.bare_lf = True
        if b"\r" in line:
            sc.ext_defects.append("bare_cr_in_chunk_line")
        semi = line.find(b";")
        size_tok = line if semi < 0 else line[:semi]
        ext = b"" if semi < 0 else line[semi + 1:]
        if ext:
            sc.ext_defects.extend(_scan_chunk_ext(ext))
        size_tok_s = size_tok.strip(b" \t")
        if size_tok_s != size_tok:
            sc.defects.append("chunk_size_padded")
        if not size_tok_s:
            sc.defects.append("chunk_size_empty")
            break
        if not re.match(rb"^[0-9A-Fa-f]+$", size_tok_s):
            sc.defects.append("chunk_size_non_hex")
            break
        if len(size_tok_s.lstrip(b"0") or b"0") > 16:
            sc.defects.append("chunk_size_overflow")
        size = int(size_tok_s, 16)
        if size >= 1 << 64:
            sc.defects.append("chunk_size_overflow")
        pos = nl + 1
        if size == 0:
            # trailer section, then the final CRLF
            while pos < len(buf):
                nl2 = buf.find(b"\n", pos)
                if nl2 < 0:
                    return sc
                tl = buf[pos:nl2]
                if tl.endswith(b"\r"):
                    tl = tl[:-1]
                else:
                    sc.bare_lf = True
                pos = nl2 + 1
                if not tl:
                    sc.complete = True
                    sc.end_offset = pos
                    sc.total_body = total
                    return sc
                c = tl.find(b":")
                if c > 0:
                    sc.trailers.append((tl[:c].strip(b" \t"),
                                        tl[c + 1:].strip(b" \t")))
            return sc
        if pos + size > len(buf):
            sc.total_body = total
            return sc
        total += size
        pos += size
        # the chunk data is followed by CRLF
        if buf[pos:pos + 2] == b"\r\n":
            pos += 2
        elif buf[pos:pos + 1] == b"\n":
            sc.bare_lf = True
            pos += 1
        else:
            sc.defects.append("chunk_data_not_terminated")
            break
    sc.total_body = total
    return sc


def _scan_chunk_ext(ext: bytes) -> List[str]:
    """Check a chunk extension string against RFC 9112 7.1.1.

    The quoted-string state machine is the point: Jetty (CVE-2026-2332) and
    Netty (CVE-2026-42585) both end extension parsing at CRLF while inside an
    unclosed quote, which lets the attacker's smuggled request ride in the
    extension. An unclosed quote cannot occur in a well-formed extension.
    """
    defects: List[str] = []
    if len(ext) > MAX_CHUNK_EXT:
        defects.append("chunk_ext_oversized")
    in_quote = False
    escaped = False
    for b in ext:
        ch = bytes([b])
        if escaped:
            escaped = False
            continue
        if ch == b"\\" and in_quote:
            escaped = True
            continue
        if ch == b'"':
            in_quote = not in_quote
            continue
        if ch in (b"\r", b"\n") and in_quote:
            defects.append("bare_crlf_in_quoted_ext")
    if in_quote:
        defects.append("unclosed_quoted_string")
    if escaped:
        defects.append("dangling_escape")
    return defects


# ---------------------------------------------------------------------------
# HPACK (RFC 7541) - hand-rolled, no library dissector
# ---------------------------------------------------------------------------

HPACK_STATIC_TABLE: Tuple[Tuple[bytes, bytes], ...] = (
    (b":authority", b""), (b":method", b"GET"), (b":method", b"POST"),
    (b":path", b"/"), (b":path", b"/index.html"), (b":scheme", b"http"),
    (b":scheme", b"https"), (b":status", b"200"), (b":status", b"204"),
    (b":status", b"206"), (b":status", b"304"), (b":status", b"400"),
    (b":status", b"404"), (b":status", b"500"), (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"), (b"accept-language", b""),
    (b"accept-ranges", b""), (b"accept", b""),
    (b"access-control-allow-origin", b""), (b"age", b""), (b"allow", b""),
    (b"authorization", b""), (b"cache-control", b""),
    (b"content-disposition", b""), (b"content-encoding", b""),
    (b"content-language", b""), (b"content-length", b""),
    (b"content-location", b""), (b"content-range", b""),
    (b"content-type", b""), (b"cookie", b""), (b"date", b""), (b"etag", b""),
    (b"expect", b""), (b"expires", b""), (b"from", b""), (b"host", b""),
    (b"if-match", b""), (b"if-modified-since", b""), (b"if-none-match", b""),
    (b"if-range", b""), (b"if-unmodified-since", b""), (b"last-modified", b""),
    (b"link", b""), (b"location", b""), (b"max-forwards", b""),
    (b"proxy-authenticate", b""), (b"proxy-authorization", b""),
    (b"range", b""), (b"referer", b""), (b"refresh", b""), (b"retry-after", b""),
    (b"server", b""), (b"set-cookie", b""), (b"strict-transport-security", b""),
    (b"transfer-encoding", b""), (b"user-agent", b""), (b"vary", b""),
    (b"via", b""), (b"www-authenticate", b""),
)

# RFC 7541 Appendix B. (code, bit length) indexed by symbol 0..256.
_HUFF_SPEC: Tuple[Tuple[int, int], ...] = (
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12), (0x1ff9, 13), (0x15, 6),
    (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6), (0x0, 5), (0x1, 5), (0x2, 5),
    (0x19, 6), (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6), (0x1e, 6),
    (0x1f, 6), (0x5c, 7), (0xfb, 8), (0x7ffc, 15), (0x20, 6), (0xffb, 12),
    (0x3fc, 10), (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7), (0x5f, 7),
    (0x60, 7), (0x61, 7), (0x62, 7), (0x63, 7), (0x64, 7), (0x65, 7),
    (0x66, 7), (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7), (0x6b, 7),
    (0x6c, 7), (0x6d, 7), (0x6e, 7), (0x6f, 7), (0x70, 7), (0x71, 7),
    (0x72, 7), (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19),
    (0x1ffc, 13), (0x3ffc, 14), (0x22, 6), (0x7ffd, 15), (0x3, 5), (0x23, 6),
    (0x4, 5), (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5),
    (0x74, 7), (0x75, 7), (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6),
    (0x77, 7), (0x78, 7), (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20),
    (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20), (0x3fffd3, 22),
    (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23), (0x3fffd6, 22),
    (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23),
    (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23), (0xffffec, 24),
    (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24),
    (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23),
    (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23), (0x3fffd9, 22),
    (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22),
    (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22),
    (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21), (0x7fffea, 23),
    (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21),
    (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21),
    (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21), (0x7fffed, 23),
    (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20),
    (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23),
    (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23), (0x3ffffe0, 26),
    (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22),
    (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26),
    (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27), (0x7ffffdf, 27),
    (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19),
    (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27),
    (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24), (0x1fffe4, 21),
    (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28),
    (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20),
    (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21), (0x3fffe9, 22),
    (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22),
    (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24),
    (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23), (0x3ffffeb, 26),
    (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27),
    (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27),
    (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27), (0x7ffffee, 27),
    (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26), (0x3fffffff, 30),
)


class _HuffmanTree:
    """Bit-by-bit Huffman decoder built once from the RFC table."""

    def __init__(self, spec: Sequence[Tuple[int, int]]):
        self.root: Dict[str, Any] = {}
        for sym, (code, nbits) in enumerate(spec):
            node = self.root
            for i in range(nbits - 1, -1, -1):
                bit = (code >> i) & 1
                if i == 0:
                    node[bit] = sym
                else:
                    node = node.setdefault(bit, {})

    def decode(self, data: bytes) -> bytes:
        out = bytearray()
        node = self.root
        nbits = 0
        for byte in data:
            for i in range(7, -1, -1):
                bit = (byte >> i) & 1
                nxt = node.get(bit)
                if nxt is None:
                    raise HpackError("invalid huffman code")
                if isinstance(nxt, int):
                    if nxt == 256:
                        raise HpackError("EOS symbol in huffman string")
                    out.append(nxt)
                    node = self.root
                    nbits = 0
                else:
                    node = nxt
                    nbits += 1
        if nbits > 7:
            raise HpackError("huffman padding too long")
        return bytes(out)


HUFFMAN = _HuffmanTree(_HUFF_SPEC)


class HpackError(Exception):
    pass


def decode_integer(data: bytes, pos: int, prefix_bits: int
                   ) -> Tuple[int, int, List[str]]:
    """Decode an RFC 7541 prefix integer.

    Returns (value, new position, defects).

    The defect that matters is CVE-2023-33953's varint vector: HPACK integers
    are little-endian groups of 7 bits, so the only value-preserving padding
    is a *trailing* zero group. A correct encoder never emits one; a parser
    that walks them all before deciding the value is the bug. Reading the
    final byte is enough, with no need to count how many were sent.
    """
    defects: List[str] = []
    if pos >= len(data):
        raise HpackError("integer truncated")
    mask = (1 << prefix_bits) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos, defects
    shift = 0
    groups = 0
    last = None
    while True:
        if pos >= len(data):
            raise HpackError("integer truncated")
        b = data[pos]
        pos += 1
        groups += 1
        last = b
        value += (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
        if groups > 10:
            defects.append("integer_too_many_groups")
            raise HpackError("integer continuation too long")
    if groups > 1 and last == 0x00:
        defects.append("integer_trailing_zero_group")
    if value > (1 << 32):
        defects.append("integer_exceeds_32bit")
    return value, pos, defects


def decode_string(data: bytes, pos: int) -> Tuple[bytes, int, List[str]]:
    if pos >= len(data):
        raise HpackError("string truncated")
    huff = bool(data[pos] & 0x80)
    length, pos, defects = decode_integer(data, pos, 7)
    if pos + length > len(data):
        raise HpackError("string length past end of block")
    raw = data[pos:pos + length]
    pos += length
    if huff:
        return HUFFMAN.decode(raw), pos, defects
    return raw, pos, defects


class HpackDecoder:
    """Per-connection, per-direction HPACK decoder.

    A tap that joins a connection mid-flight cannot rebuild the dynamic
    table: it never saw the insertions. Such a decoder is marked unsynced,
    header-content rules are skipped for it, and nothing is guessed.
    """

    def __init__(self, max_table_size: int = 4096, synced: bool = True):
        self.table: List[Tuple[bytes, bytes]] = []
        self.max_table_size = max_table_size
        self.size = 0
        self.synced = synced

    def _evict(self) -> None:
        while self.size > self.max_table_size and self.table:
            n, v = self.table.pop()
            self.size -= len(n) + len(v) + 32

    def _insert(self, name: bytes, value: bytes) -> None:
        entry_size = len(name) + len(value) + 32
        if entry_size > self.max_table_size:
            self.table.clear()
            self.size = 0
            return
        self.table.insert(0, (name, value))
        self.size += entry_size
        self._evict()

    def _lookup(self, index: int) -> Tuple[bytes, bytes]:
        if index == 0:
            raise HpackError("index 0 is not valid")
        if index <= len(HPACK_STATIC_TABLE):
            return HPACK_STATIC_TABLE[index - 1]
        dyn = index - len(HPACK_STATIC_TABLE) - 1
        if dyn >= len(self.table):
            raise HpackError(f"dynamic index {index} out of range")
        return self.table[dyn]

    def decode(self, block: bytes) -> Tuple[List[Tuple[bytes, bytes]], List[str]]:
        headers: List[Tuple[bytes, bytes]] = []
        defects: List[str] = []
        pos = 0
        while pos < len(block):
            b = block[pos]
            if b & 0x80:                       # indexed field
                index, pos, d = decode_integer(block, pos, 7)
                defects.extend(d)
                headers.append(self._lookup(index))
            elif b & 0x40:                     # incremental indexing
                index, pos, d = decode_integer(block, pos, 6)
                defects.extend(d)
                name, pos, d2 = (self._lookup(index)[0], pos, []) if index \
                    else decode_string(block, pos)
                defects.extend(d2)
                value, pos, d3 = decode_string(block, pos)
                defects.extend(d3)
                self._insert(name, value)
                headers.append((name, value))
            elif b & 0x20:                     # dynamic table size update
                new_size, pos, d = decode_integer(block, pos, 5)
                defects.extend(d)
                self.max_table_size = new_size
                self._evict()
            else:                              # without indexing / never
                index, pos, d = decode_integer(block, pos, 4)
                defects.extend(d)
                name, pos, d2 = (self._lookup(index)[0], pos, []) if index \
                    else decode_string(block, pos)
                defects.extend(d2)
                value, pos, d3 = decode_string(block, pos)
                defects.extend(d3)
                headers.append((name, value))
        return headers, defects


# ---------------------------------------------------------------------------
# HTTP/2 framing
# ---------------------------------------------------------------------------

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA, FRAME_HEADERS, FRAME_PRIORITY, FRAME_RST_STREAM = 0, 1, 2, 3
FRAME_SETTINGS, FRAME_PUSH_PROMISE, FRAME_PING = 4, 5, 6
FRAME_GOAWAY, FRAME_WINDOW_UPDATE, FRAME_CONTINUATION = 7, 8, 9

FRAME_NAMES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
    5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
    9: "CONTINUATION",
}

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

DEFAULT_MAX_HEADER_LIST = 64 * 1024
DEFAULT_MAX_CONCURRENT = 100
MAX_CONTINUATION_FRAMES = 32


@dataclass
class H2Frame:
    length: int
    ftype: int
    flags: int
    stream_id: int
    payload: bytes

    @property
    def name(self) -> str:
        return FRAME_NAMES.get(self.ftype, f"UNKNOWN({self.ftype})")


def parse_frames(buf: bytes, pos: int = 0) -> Tuple[List[H2Frame], int]:
    """Parse whole frames from buf, returning (frames, bytes consumed)."""
    frames: List[H2Frame] = []
    while pos + 9 <= len(buf):
        length = int.from_bytes(buf[pos:pos + 3], "big")
        ftype = buf[pos + 3]
        flags = buf[pos + 4]
        sid = int.from_bytes(buf[pos + 5:pos + 9], "big") & 0x7FFFFFFF
        if pos + 9 + length > len(buf):
            break
        payload = buf[pos + 9:pos + 9 + length]
        frames.append(H2Frame(length, ftype, flags, sid, payload))
        pos += 9 + length
    return frames, pos


def strip_header_padding(frame: H2Frame) -> bytes:
    """Return the header block fragment of a HEADERS frame."""
    data = frame.payload
    off = 0
    pad = 0
    if frame.flags & FLAG_PADDED:
        if not data:
            return b""
        pad = data[0]
        off = 1
    if frame.flags & FLAG_PRIORITY:
        off += 5
    end = len(data) - pad
    if end < off:
        return b""
    return data[off:end]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    code: str
    name: str
    tier: str
    severity: str
    confidence: str
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    cves: Tuple[str, ...] = ()
    flow: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "code": self.code, "name": self.name, "tier": self.tier,
            "severity": self.severity, "confidence": self.confidence,
            "summary": self.summary, "evidence": self.evidence,
        }
        if self.cves:
            d["cves"] = list(self.cves)
            d["cve_detail"] = {c: CVE_CATALOG[c] for c in self.cves
                               if c in CVE_CATALOG}
        if self.flow:
            d["flow"] = self.flow
        return d


def make_finding(code: str, evidence: Optional[Dict[str, Any]] = None,
                 severity: Optional[str] = None,
                 confidence: Optional[str] = None,
                 flow: Optional[str] = None) -> Finding:
    d = FINDING_REGISTRY[code]
    return Finding(code=d.code, name=d.name, tier=d.tier,
                   severity=severity or d.severity,
                   confidence=confidence or d.confidence,
                   summary=d.summary, evidence=evidence or {},
                   cves=d.cves, flow=flow)


# ---------------------------------------------------------------------------
# Tier A + B + C: rules over one HTTP/1 message
# ---------------------------------------------------------------------------

CRED_USER_KEYS = frozenset(
    b"username user userid user_id login loginname uname email".split())
CRED_PASS_KEYS = frozenset(
    b"password passwd pwd pass passwort userpassword".split())

RANGE_OVERFLOW_THRESHOLD = 1 << 63
MS15_034_EXACT = (1 << 64) - 1

GNMI_PATH_MARKERS = (b"/gnmi.gNMI/", b"/gnoi.")


def _parse_range_values(value: bytes) -> List[Tuple[Optional[int], Optional[int]]]:
    """Parse a Range field value into (first, last) pairs.

    Deliberately tolerant: whitespace inside the value and a missing unit are
    known evasions of the naive content-match signatures published in 2015.
    The rule reads the parsed integer, never the string.
    """
    out: List[Tuple[Optional[int], Optional[int]]] = []
    v = value.strip()
    eq = v.find(b"=")
    if eq >= 0:
        v = v[eq + 1:]
    for part in v.split(b","):
        p = part.strip(b" \t")
        if not p:
            continue
        dash = p.find(b"-")
        if dash < 0:
            continue
        a = p[:dash].strip(b" \t")
        b = p[dash + 1:].strip(b" \t")
        first = int(a) if a.isdigit() else None
        last = int(b) if b.isdigit() else None
        out.append((first, last))
    return out


def check_range_overflow(msg: ParsedMessage) -> List[Finding]:
    findings = []
    for raw in msg.get_all(b"range"):
        for first, last in _parse_range_values(raw):
            if last is not None and last >= RANGE_OVERFLOW_THRESHOLD:
                findings.append(make_finding(
                    "HTTP-020",
                    {
                        "range_last": last,
                        "range_first": first,
                        "exact_ms15_034": last == MS15_034_EXACT,
                        "target": msg.target.decode("latin-1") if msg.target else None,
                        "note": "No resource is 2**63 bytes long; the value has "
                                "no benign reading. Reported whether or not the "
                                "target is patched - the attempt is the event.",
                    }))
    return findings


def check_accept_encoding(msg: ParsedMessage) -> List[Finding]:
    """CVE-2021-31166: empty list element after an unknown content-coding.

    Honest edge, carried in the finding: RFC 9110 list syntax lets a
    recipient ignore empty elements, so ',,' is legal and this is not a
    grammar violation on its own. Requiring at least one unknown coding
    before it removes the remaining benign cases. A trigger built from some
    other invalid token would be missed; the miss is the safe direction.
    """
    findings = []
    for raw in msg.get_all(b"accept-encoding"):
        parts = [p.strip(b" \t") for p in raw.split(b",")]
        if not any(p == b"" for p in parts):
            continue
        unknown = [p.split(b";")[0].lower() for p in parts if p]
        unknown = [u for u in unknown if u and u not in KNOWN_CODINGS]
        if not unknown:
            continue
        findings.append(make_finding(
            "HTTP-021",
            {
                "accept_encoding": raw.decode("latin-1")[:200],
                "unknown_codings": [u.decode("latin-1") for u in unknown],
                "empty_elements": sum(1 for p in parts if p == b""),
                "note": "Empty list element after unknown codings, the public "
                        "crash shape. Whether the host runs a vulnerable "
                        "http.sys is not observable.",
            }))
    return findings


def check_host(msg: ParsedMessage) -> List[Finding]:
    findings = []
    hosts = msg.get_all(b"host")
    if len(hosts) > 1:
        findings.append(make_finding("HTTP-011", {
            "reason": "multiple_host_headers",
            "hosts": [h.decode("latin-1")[:100] for h in hosts],
        }))
        return findings
    target = msg.target or b""
    if b"://" in target:
        rest = target.split(b"://", 1)[1]
        authority = rest.split(b"/", 1)[0]
        if b"@" in authority:
            authority = authority.split(b"@", 1)[1]
        if hosts and authority and authority.lower() != hosts[0].lower():
            findings.append(make_finding("HTTP-011", {
                "reason": "absolute_uri_host_mismatch",
                "target_authority": authority.decode("latin-1")[:100],
                "host_header": hosts[0].decode("latin-1")[:100],
            }))
    return findings


def _b64_or_hex(value: bytes) -> bool:
    if not value:
        return False
    return bool(re.match(rb"^[A-Za-z0-9+/=_\-]+$", value))


def parse_cookie(raw: bytes) -> List[Tuple[bytes, bytes]]:
    out = []
    for part in raw.split(b";"):
        p = part.strip(b" \t")
        if not p:
            continue
        eq = p.find(b"=")
        if eq < 0:
            continue
        out.append((p[:eq].strip(), p[eq + 1:].strip()))
    return out


def check_credentials(msg: ParsedMessage, body: bytes,
                      service: Optional[str]) -> List[Finding]:
    """Tier C credential rules. Nothing here ever logs a secret."""
    findings: List[Finding] = []
    suppressed = SERVICE_SUPPRESS.get(service or "", ())

    # HTTP-040 Basic auth
    for raw in msg.get_all(b"authorization") + msg.get_all(b"proxy-authorization"):
        if raw[:6].lower() == b"basic ":
            import base64
            token = raw[6:].strip()
            user = None
            try:
                decoded = base64.b64decode(token + b"=" * (-len(token) % 4),
                                           validate=False)
                if b":" in decoded:
                    user = decoded.split(b":", 1)[0].decode("latin-1")
            except Exception:
                pass
            if "HTTP-040" not in suppressed:
                findings.append(make_finding("HTTP-040", {
                    "username": user,
                    "credential": redact(token),
                    "service": service,
                }))

    # HTTP-043 / HTTP-042 cookie credentials. One observation, one finding:
    # when the FS triple matches exactly, the generic rule stands down.
    for raw in msg.get_all(b"cookie"):
        pairs = parse_cookie(raw)
        keys = {k.lower() for k, _ in pairs}
        vals = {k.lower(): v for k, v in pairs}
        fs_triple = {b"username", b"password", b"gsessionid"}
        if fs_triple <= keys and all(_b64_or_hex(vals[k]) for k in fs_triple):
            # NOT gated on POST. The advisory describes the cookie as sent
            # "with every POST", but the defect is the cookie itself and a
            # browser returns it on every request to the path - the
            # credentials cross on GETs too. Gating on method would narrow
            # detection for a reason the defect does not support; the method
            # is recorded as evidence instead.
            findings.append(make_finding("HTTP-043", {
                "method": (msg.method or b"").decode("latin-1"),
                "target": (msg.target or b"").decode("latin-1")[:120],
                "username_cookie": redact(vals[b"username"]),
                "password_cookie": redact(vals[b"password"]),
                "session_cookie": redact(vals[b"gsessionid"]),
                "device_hint": "FS S3150-8T2F web UI shape",
                "note": "Version is not readable from the wire: verify this "
                        "device against firmware 2.2.0D, do not assume "
                        "vulnerable.",
            }))
            continue
        has_user = keys & CRED_USER_KEYS
        has_pass = keys & CRED_PASS_KEYS
        if has_user and has_pass:
            findings.append(make_finding("HTTP-042", {
                "username_key": sorted(k.decode() for k in has_user),
                "password_key": sorted(k.decode() for k in has_pass),
                "credential": redact(vals[sorted(has_pass)[0]]),
            }))

    # HTTP-041 form password
    ctype = (msg.get(b"content-type") or b"").lower()
    if (msg.kind == "request" and body
            and b"application/x-www-form-urlencoded" in ctype
            and "HTTP-041" not in suppressed):
        for part in body.split(b"&"):
            eq = part.find(b"=")
            if eq < 0:
                continue
            k = part[:eq].strip().lower()
            v = part[eq + 1:]
            if k in CRED_PASS_KEYS and v:
                findings.append(make_finding("HTTP-041", {
                    "field": k.decode(),
                    "credential": redact(v),
                    "service": service,
                }))
                break

    # HTTP-044 credentials in the target
    target = msg.target or b""
    if b"://" in target:
        authority = target.split(b"://", 1)[1].split(b"/", 1)[0]
        if b"@" in authority:
            userinfo = authority.split(b"@", 1)[0]
            findings.append(make_finding("HTTP-044", {
                "reason": "userinfo_in_absolute_uri",
                "username": userinfo.split(b":")[0].decode("latin-1"),
                "credential": redact(userinfo),
            }))
    q = target.find(b"?")
    if q >= 0:
        for part in target[q + 1:].split(b"&"):
            eq = part.find(b"=")
            if eq < 0:
                continue
            if part[:eq].strip().lower() in CRED_PASS_KEYS and part[eq + 1:]:
                findings.append(make_finding("HTTP-044", {
                    "reason": "password_in_query_string",
                    "field": part[:eq].decode("latin-1"),
                    "credential": redact(part[eq + 1:]),
                }, confidence=HEURISTIC))
                break

    if msg.method == b"TRACE":
        findings.append(make_finding("HTTP-045", {
            "target": target.decode("latin-1")[:200]}))
    return findings


def analyse_http1_message(msg: ParsedMessage, raw: bytes,
                          service: Optional[str] = None,
                          server_banner: Optional[bytes] = None,
                          ) -> List[Finding]:
    """Run every Tier A/B/C rule over one parsed message."""
    findings: List[Finding] = []

    cl_vals = msg.get_all(b"content-length")
    te_vals = msg.get_all(b"transfer-encoding")
    cl_value, cl_defects = parse_content_length(cl_vals)
    te = analyse_transfer_encoding(te_vals)

    # --- HTTP-001 CL + TE both present ---
    if cl_vals and te_vals:
        findings.append(make_finding("HTTP-001", {
            "content_length": [v.decode("latin-1")[:80] for v in cl_vals],
            "transfer_encoding": [v.decode("latin-1")[:80] for v in te_vals],
            "http_version": (msg.version or b"").decode("latin-1"),
            # the Netty 1.1-only guard is exactly this case on HTTP/1.0
            "http_10": msg.version == b"1.0",
        }, severity=HIGH if msg.version == b"1.0" else WARN))

    # --- HTTP-002 Transfer-Encoding deviations ---
    if te["present"] and te["defects"]:
        findings.append(make_finding("HTTP-002", {
            "codings": te["codings"],
            "defects": sorted(set(te["defects"])),
            "treated_as_chunked": te["chunked"],
        }))

    # --- HTTP-003 Content-Length deviations ---
    if cl_defects:
        findings.append(make_finding("HTTP-003", {
            "values": [v.decode("latin-1")[:80] for v in cl_vals],
            "defects": sorted(set(cl_defects)),
        }))

    # --- HTTP-006 / 007 / 008 grammar ---
    if msg.bare_lf or msg.bare_cr:
        findings.append(make_finding("HTTP-006", {
            "bare_lf": msg.bare_lf, "bare_cr": msg.bare_cr,
            "note": "Line terminator deviation. Benign on its own in some "
                    "stacks; a desync primitive when paired with a framing "
                    "finding on the same message.",
        }))
    if msg.space_before_colon:
        findings.append(make_finding("HTTP-007", {
            "note": "RFC 9112 5.1: a recipient MUST reject such a message.",
        }))
    if msg.obs_fold and msg.kind == "request":
        findings.append(make_finding("HTTP-008", {
            "note": "RFC 9112 5.2: obs-fold is not allowed in a request.",
        }))

    # --- chunk-level rules ---
    body = b""
    te_end: Optional[int] = None
    if te["chunked"]:
        sc = scan_chunked(raw, msg.body_offset)
        if sc.defects:
            size_defects = [d for d in sc.defects if d.startswith("chunk_size")]
            if size_defects:
                findings.append(make_finding("HTTP-004", {
                    "defects": sorted(set(size_defects))}))
        if sc.ext_defects:
            findings.append(make_finding("HTTP-005", {
                "defects": sorted(set(sc.ext_defects)),
                "note": "An unclosed quote cannot occur in a well-formed "
                        "chunk extension and is the published smuggling "
                        "vector in Jetty and Netty.",
            }))
        if sc.complete:
            te_end = sc.end_offset
            body = b""  # chunk data is not reassembled; counters only
        # --- HTTP-022 request trailers toward http.sys ---
        if msg.kind == "request" and sc.trailers:
            banner = (server_banner or b"").lower()
            is_httpsys = (b"microsoft-httpapi" in banner
                          or b"microsoft-iis" in banner)
            findings.append(make_finding(
                "HTTP-022",
                {
                    "trailer_fields": [n.decode("latin-1")[:60]
                                       for n, _ in sc.trailers][:10],
                    "trailer_header_declared": bool(msg.get(b"trailer")),
                    "server_banner": (server_banner or b"").decode("latin-1")[:80]
                                     or None,
                    "precondition_unobserved": True,
                    "note": "EnableTrailerSupport is device config and is not "
                            "visible from a tap. Microsoft published the "
                            "component but not the malformation, so "
                            "posture-of-possible is the ceiling; no signature "
                            "will be reverse-engineered.",
                },
                severity=WARN if is_httpsys else INFO))
    else:
        if cl_value is not None:
            end = msg.body_offset + cl_value
            body = raw[msg.body_offset:end]

    # --- HTTP-009 framer disagreement ---
    if cl_value is not None and te["chunked"] and te_end is not None:
        cl_end = msg.body_offset + cl_value
        if cl_end != te_end:
            lo, hi = min(cl_end, te_end), max(cl_end, te_end)
            remainder = raw[lo:hi]
            looks_like_request = bool(
                REQUEST_LINE_RE.match(remainder.split(b"\n", 1)[0].rstrip(b"\r")))
            if looks_like_request:
                findings.append(make_finding("HTTP-009", {
                    "cl_end_offset": cl_end,
                    "te_end_offset": te_end,
                    "smuggled_bytes": hi - lo,
                    "smuggled_request_line":
                        remainder.split(b"\n", 1)[0].rstrip(b"\r")
                        .decode("latin-1")[:120],
                    "note": "The two framers delimit this message differently "
                            "and the difference parses as a request line.",
                }))

    # --- HTTP-010 response framing ---
    if msg.kind == "response":
        anomalies = []
        if cl_vals and te_vals:
            anomalies.append("cl_and_te")
        if cl_defects:
            anomalies.append("invalid_content_length")
        if anomalies:
            findings.append(make_finding("HTTP-010", {
                "anomalies": sorted(set(anomalies))}))

    if msg.kind == "request":
        findings.extend(check_host(msg))
        findings.extend(check_range_overflow(msg))
        findings.extend(check_accept_encoding(msg))
        findings.extend(check_credentials(msg, body, service))

    return findings


# ---------------------------------------------------------------------------
# Tier D: cleartext HTTP/2 and gRPC
# ---------------------------------------------------------------------------

RAPID_RESET_MULTIPLIER = 2.0
RAPID_RESET_WINDOW = 1.0


@dataclass
class H2Stream:
    stream_id: int
    opened_at: float
    server_responded: bool = False
    reset: bool = False
    path: Optional[bytes] = None
    is_grpc: bool = False


class H2ConnectionState:
    """Per-connection HTTP/2 state for the Tier D rules."""

    def __init__(self, flow_id: str, synced: bool = True):
        self.flow_id = flow_id
        self.synced = synced
        self.dec_client = HpackDecoder(synced=synced)
        self.dec_server = HpackDecoder(synced=synced)
        self.streams: Dict[int, H2Stream] = {}
        self.reset_events: List[float] = []
        self.peer_max_concurrent = DEFAULT_MAX_CONCURRENT
        self.peer_max_header_list = DEFAULT_MAX_HEADER_LIST
        self.reported: set = set()
        self.grpc_seen = False
        self.gnmi_seen = False
        self.rapid_reset_reported = False

    # -- helpers ----------------------------------------------------------
    def _once(self, key: str) -> bool:
        if key in self.reported:
            return False
        self.reported.add(key)
        return True

    def observe_settings(self, frame: H2Frame) -> None:
        payload = frame.payload
        for i in range(0, len(payload) - 5, 6):
            ident = int.from_bytes(payload[i:i + 2], "big")
            value = int.from_bytes(payload[i + 2:i + 6], "big")
            if ident == SETTINGS_MAX_CONCURRENT_STREAMS:
                self.peer_max_concurrent = value
            elif ident == SETTINGS_MAX_HEADER_LIST_SIZE:
                self.peer_max_header_list = value
            elif ident == SETTINGS_HEADER_TABLE_SIZE:
                self.dec_client.max_table_size = value

    # -- the rules --------------------------------------------------------
    def feed(self, frames: Sequence[H2Frame], from_client: bool,
             now: Optional[float] = None) -> List[Finding]:
        now = time.time() if now is None else now
        findings: List[Finding] = []
        pending_block: Optional[Dict[str, Any]] = None

        for fr in frames:
            if fr.ftype == FRAME_SETTINGS and not from_client:
                self.observe_settings(fr)
            elif fr.ftype == FRAME_SETTINGS and from_client:
                self.observe_settings(fr)

            # --- HTTP-062: header block assembly ---
            if fr.ftype in (FRAME_HEADERS, FRAME_PUSH_PROMISE):
                if pending_block is not None:
                    findings.append(self._continuation_finding(
                        pending_block, "new_header_block_before_end_headers"))
                frag = strip_header_padding(fr)
                pending_block = {
                    "stream": fr.stream_id, "bytes": len(frag),
                    "frames": 1, "cont_frames": 0, "fragments": [frag],
                }
                if fr.flags & FLAG_END_HEADERS:
                    findings.extend(self._finish_block(pending_block,
                                                       from_client, fr))
                    pending_block = None
            elif fr.ftype == FRAME_CONTINUATION:
                if pending_block is None:
                    if self._once("orphan_continuation"):
                        findings.append(make_finding("HTTP-062", {
                            "reason": "continuation_without_header_block",
                            "stream": fr.stream_id,
                        }, flow=self.flow_id))
                    continue
                pending_block["bytes"] += len(fr.payload)
                pending_block["frames"] += 1
                pending_block["cont_frames"] += 1
                pending_block["fragments"].append(fr.payload)
                if fr.flags & FLAG_END_HEADERS:
                    findings.extend(self._finish_block(pending_block,
                                                       from_client, fr))
                    pending_block = None
            else:
                if pending_block is not None:
                    # RFC 9113 6.10: a header block must not be interrupted.
                    findings.append(self._continuation_finding(
                        pending_block,
                        f"interrupted_by_{FRAME_NAMES.get(fr.ftype, fr.ftype)}"))
                    pending_block = None

            # --- stream bookkeeping for HTTP-061 ---
            if fr.ftype == FRAME_HEADERS and from_client:
                self.streams.setdefault(
                    fr.stream_id, H2Stream(fr.stream_id, now))
            elif fr.ftype in (FRAME_HEADERS, FRAME_DATA) and not from_client:
                st = self.streams.get(fr.stream_id)
                if st:
                    st.server_responded = True
            elif fr.ftype == FRAME_RST_STREAM and from_client:
                st = self.streams.get(fr.stream_id)
                if st and not st.server_responded and not st.reset:
                    st.reset = True
                    self.reset_events.append(now)
                    f = self._check_rapid_reset(now)
                    if f:
                        findings.append(f)

        if pending_block is not None:
            # block left open at the end of this batch: not an error by
            # itself, the next segment may continue it.
            pass
        return findings

    def _continuation_finding(self, block: Dict[str, Any],
                              reason: str) -> Finding:
        return make_finding("HTTP-062", {
            "reason": reason,
            "stream": block["stream"],
            "block_bytes": block["bytes"],
            "continuation_frames": block.get("cont_frames", 0),
            "note": "RFC 9113 6.10 requires an uninterrupted header block; "
                    "an interruption has no benign reading.",
        }, flow=self.flow_id)

    def _finish_block(self, block: Dict[str, Any], from_client: bool,
                      fr: H2Frame) -> List[Finding]:
        findings: List[Finding] = []
        limit = self.peer_max_header_list or DEFAULT_MAX_HEADER_LIST
        if block["bytes"] > limit:
            findings.append(make_finding("HTTP-062", {
                "reason": "header_block_exceeds_peer_limit",
                "stream": block["stream"],
                "block_bytes": block["bytes"],
                "peer_max_header_list_size": limit,
                "note": "Threshold is the peer's own advertised SETTINGS "
                        "value, not an invented number.",
            }, flow=self.flow_id))
        # The cap counts CONTINUATION frames, not the HEADERS frame that
        # opened the block: a cap named for one thing must measure that thing.
        if block.get("cont_frames", 0) > MAX_CONTINUATION_FRAMES:
            findings.append(make_finding("HTTP-062", {
                "reason": "excessive_continuation_frames",
                "stream": block["stream"],
                "continuation_frames": block["cont_frames"],
                "threshold": MAX_CONTINUATION_FRAMES,
            }, confidence=HEURISTIC, flow=self.flow_id))

        decoder = self.dec_client if from_client else self.dec_server
        if not decoder.synced:
            return findings
        blob = b"".join(block["fragments"])
        try:
            headers, defects = decoder.decode(blob)
        except HpackError as exc:
            findings.append(make_finding("HTTP-062", {
                "reason": "hpack_decode_error",
                "stream": block["stream"],
                "error": str(exc),
            }, confidence=HEURISTIC, flow=self.flow_id))
            return findings

        if "integer_trailing_zero_group" in defects:
            findings.append(make_finding("HTTP-063", {
                "stream": block["stream"],
                "defects": sorted(set(defects)),
                "note": "HPACK integers are least-significant group first, so "
                        "a value-preserving pad can only be a trailing zero "
                        "group. A correct encoder never emits one.",
            }, flow=self.flow_id))
        elif "integer_exceeds_32bit" in defects:
            findings.append(make_finding("HTTP-063", {
                "stream": block["stream"],
                "defects": sorted(set(defects)),
            }, confidence=HEURISTIC, flow=self.flow_id))

        findings.extend(self._header_rules(headers, block, from_client))
        return findings

    def _header_rules(self, headers: Sequence[Tuple[bytes, bytes]],
                      block: Dict[str, Any], from_client: bool) -> List[Finding]:
        findings: List[Finding] = []
        hmap: Dict[bytes, bytes] = {}
        for n, v in headers:
            hmap.setdefault(n.lower(), v)
        total = sum(len(n) + len(v) + 32 for n, v in headers)
        ctype = hmap.get(b"content-type", b"")
        path = hmap.get(b":path", b"")
        is_grpc = ctype.startswith(b"application/grpc")
        if is_grpc:
            self.grpc_seen = True
        is_gnmi = any(m in path for m in GNMI_PATH_MARKERS)
        if is_gnmi:
            self.gnmi_seen = True

        if from_client and self._once("h2c_posture"):
            findings.append(make_finding("HTTP-060", {
                "grpc": is_grpc,
                "gnmi": is_gnmi,
                "path": path.decode("latin-1")[:120] or None,
                "note": "Management and telemetry planes carried in cleartext "
                        "h2 are readable and modifiable by anyone on the "
                        "segment.",
            }, severity=WARN if is_gnmi else INFO, flow=self.flow_id))

        # --- HTTP-064 gRPC header violations (CVE-2023-1428) ---
        if is_grpc and from_client:
            violations = []
            te = hmap.get(b"te")
            if te is not None and te.strip().lower() != b"trailers":
                violations.append(f"te={te.decode('latin-1')[:40]}")
            scheme = hmap.get(b":scheme")
            if scheme is not None and scheme.lower() not in (b"http", b"https"):
                violations.append(f"scheme={scheme.decode('latin-1')[:40]}")
            if b"grpclb_client_stats" in hmap:
                violations.append("grpclb_client_stats")
            if violations:
                findings.append(make_finding("HTTP-064", {
                    "stream": block["stream"],
                    "violations": violations,
                    "header_list_bytes": total,
                    "over_8kib": total > 8192,
                    "note": "CVE-2023-1428 aborts the C++ server once the "
                            "header list also passes 8 KiB; below that the "
                            "violation is posture.",
                }, severity=HIGH if total > 8192 else WARN,
                    flow=self.flow_id))

        # --- HTTP-065 credentials in gRPC metadata ---
        if from_client:
            creds = []
            for n, v in headers:
                ln = n.lower()
                if ln in CRED_PASS_KEYS and v:
                    creds.append((ln, v))
                elif ln == b"authorization" and v[:6].lower() == b"basic ":
                    creds.append((ln, v))
            if creds and (is_grpc or self.grpc_seen):
                findings.append(make_finding("HTTP-065", {
                    "stream": block["stream"],
                    "keys": sorted(k.decode("latin-1") for k, _ in creds),
                    "credential": redact(creds[0][1]),
                    "gnmi": is_gnmi,
                }, flow=self.flow_id))
        return findings

    def _check_rapid_reset(self, now: float) -> Optional[Finding]:
        cutoff = now - RAPID_RESET_WINDOW
        self.reset_events = [t for t in self.reset_events if t >= cutoff]
        threshold = max(2, int(self.peer_max_concurrent * RAPID_RESET_MULTIPLIER))
        if len(self.reset_events) <= threshold:
            return None
        if self.rapid_reset_reported:
            return None
        self.rapid_reset_reported = True
        return make_finding("HTTP-061", {
            "resets_in_window": len(self.reset_events),
            "window_seconds": RAPID_RESET_WINDOW,
            "peer_max_concurrent_streams": self.peer_max_concurrent,
            "threshold": threshold,
            "multiplier": RAPID_RESET_MULTIPLIER,
            "note": "Counts only streams reset before the server sent any "
                    "frame on them. gRPC cancels streams legitimately, so the "
                    "bar is scaled to the server's own concurrency limit - "
                    "the limit the attack exists to beat.",
        }, flow=self.flow_id)


# ---------------------------------------------------------------------------
# Slow-read tracking (HTTP-046 / HTTP-047)
# ---------------------------------------------------------------------------

# Apache httpd mod_reqtimeout defaults, used as the per-connection bar rather
# than an invented number: header=20-40,MinRate=500 body=20,MinRate=500.
SLOW_MIN_RATE = 500            # bytes/second
SLOW_HEADER_GRACE = 20.0       # seconds
SLOW_BODY_GRACE = 20.0
SLOW_SOURCE_THRESHOLD = 20     # concurrent slow flows from one source
SLOW_SOURCE_WINDOW = 60.0


class SlowTracker:
    """Per-source volume rule. A single slow connection is a mobile client."""

    def __init__(self, min_rate: int = SLOW_MIN_RATE,
                 threshold: int = SLOW_SOURCE_THRESHOLD,
                 window: float = SLOW_SOURCE_WINDOW):
        self.min_rate = min_rate
        self.threshold = threshold
        self.window = window
        self.events: Dict[Tuple[str, str], List[float]] = {}
        self.reported: set = set()

    def is_slow(self, byte_count: int, elapsed: float, grace: float) -> bool:
        if elapsed <= grace:
            return False
        return byte_count < self.min_rate * elapsed

    def record(self, src: str, kind: str, now: float,
               flow_id: Optional[str] = None) -> Optional[Finding]:
        key = (src, kind)
        bucket = [t for t in self.events.get(key, []) if t >= now - self.window]
        bucket.append(now)
        self.events[key] = bucket
        if len(bucket) <= self.threshold:
            return None
        if key in self.reported:
            return None
        self.reported.add(key)
        code = "HTTP-046" if kind == "headers" else "HTTP-047"
        return make_finding(code, {
            "source": src,
            "slow_flows_in_window": len(bucket),
            "window_seconds": self.window,
            "min_rate_bytes_per_second": self.min_rate,
            "threshold": self.threshold,
            "note": "Per-connection bar is Apache httpd mod_reqtimeout's "
                    "default minimum rate; the finding needs many concurrent "
                    "slow flows from one source, not one slow client.",
        }, flow=flow_id)


# ---------------------------------------------------------------------------
# Flow tracking and reassembly
# ---------------------------------------------------------------------------

FLOW_IDLE_TIMEOUT = 120.0


@dataclass
class Direction:
    buf: bytearray = field(default_factory=bytearray)
    anchored: bool = False
    first_byte_at: float = 0.0
    bytes_seen: int = 0
    head_analysed: bool = False


class Flow:
    """One TCP flow, classified by its first bytes rather than by port."""

    def __init__(self, flow_id: str, src: str, dst: str,
                 service: Optional[str] = None, now: float = 0.0):
        self.flow_id = flow_id
        self.src = src
        self.dst = dst
        self.service = service
        self.created = now
        self.last_seen = now
        self.protocol: Optional[str] = None    # "http1" | "h2c" | None
        self.c2s = Direction()
        self.s2c = Direction()
        self.h2: Optional[H2ConnectionState] = None
        self.server_banner: Optional[bytes] = None
        self.h2_upgrade_pending = False
        self.joined_midstream = False

    def direction(self, from_client: bool) -> Direction:
        return self.c2s if from_client else self.s2c


def looks_like_http1_request(data: bytes) -> bool:
    line = data.split(b"\n", 1)[0].rstrip(b"\r")
    return bool(REQUEST_LINE_RE.match(line))


def looks_like_http1_response(data: bytes) -> bool:
    return bool(STATUS_LINE_RE.match(data))


def classify(data: bytes, from_client: bool) -> Optional[str]:
    if from_client:
        if data.startswith(H2_PREFACE):
            return "h2c"
        if len(data) < len(H2_PREFACE) and H2_PREFACE.startswith(data):
            return None                      # still arriving
        if looks_like_http1_request(data):
            return "http1"
    else:
        if looks_like_http1_response(data):
            return "http1"
    return None


class HttpWatch:
    """The analyzer. Fed TCP payload; returns findings. Emits nothing."""

    def __init__(self, tcp_ports: Sequence[int] = DEFAULT_TCP_PORTS,
                 slow_tracker: Optional[SlowTracker] = None):
        self.tcp_ports = tuple(tcp_ports)
        self.flows: Dict[str, Flow] = {}
        self.slow = slow_tracker or SlowTracker()
        self.stats: Dict[str, int] = {
            "flows": 0, "http1_messages": 0, "h2_frames": 0, "findings": 0,
        }

    # -- lifecycle --------------------------------------------------------
    def _flow(self, flow_id: str, src: str, dst: str, dport: int,
              now: float) -> Flow:
        fl = self.flows.get(flow_id)
        if fl is None:
            fl = Flow(flow_id, src, dst, SERVICE_PORTS.get(dport), now)
            self.flows[flow_id] = fl
            self.stats["flows"] += 1
        fl.last_seen = now
        return fl

    def expire(self, now: float) -> None:
        dead = [k for k, f in self.flows.items()
                if now - f.last_seen > FLOW_IDLE_TIMEOUT]
        for k in dead:
            del self.flows[k]

    # -- the feed ---------------------------------------------------------
    def feed(self, flow_id: str, src: str, dst: str, dport: int,
             payload: bytes, from_client: bool,
             now: Optional[float] = None) -> List[Finding]:
        now = time.time() if now is None else now
        if not payload:
            return []
        fl = self._flow(flow_id, src, dst, dport, now)
        d = fl.direction(from_client)
        if not d.bytes_seen:
            d.first_byte_at = now
        d.bytes_seen += len(payload)
        d.buf.extend(payload)

        if fl.protocol is None:
            proto = classify(bytes(d.buf), from_client)
            if proto is None:
                if len(d.buf) > MAX_HEADER_SECTION:
                    d.buf.clear()            # not HTTP; stop buffering
                return []
            fl.protocol = proto
            if proto == "h2c":
                fl.h2 = H2ConnectionState(flow_id, synced=True)
                del d.buf[:len(H2_PREFACE)]

        if fl.protocol == "h2c":
            return self._feed_h2(fl, d, from_client, now)
        return self._feed_http1(fl, d, from_client, now)

    def join_midstream(self, flow_id: str) -> None:
        """Mark a flow as joined mid-connection.

        An HPACK decoder that did not see the connection's first HEADERS
        frame cannot rebuild the dynamic table. Header-content rules are then
        skipped rather than guessed.
        """
        fl = self.flows.get(flow_id)
        if fl is None:
            return
        fl.joined_midstream = True
        if fl.h2:
            fl.h2.synced = False
            fl.h2.dec_client.synced = False
            fl.h2.dec_server.synced = False

    # -- per-protocol -----------------------------------------------------
    def _feed_h2(self, fl: Flow, d: Direction, from_client: bool,
                 now: float) -> List[Finding]:
        frames, consumed = parse_frames(bytes(d.buf))
        if consumed:
            del d.buf[:consumed]
        if not frames:
            return []
        self.stats["h2_frames"] += len(frames)
        assert fl.h2 is not None
        findings = fl.h2.feed(frames, from_client, now)
        self.stats["findings"] += len(findings)
        return findings

    def _feed_http1(self, fl: Flow, d: Direction, from_client: bool,
                    now: float) -> List[Finding]:
        findings: List[Finding] = []
        kind = "request" if from_client else "response"
        while True:
            raw = bytes(d.buf)
            split = split_header_section(raw)
            if split is None:
                # still collecting the head: slow-headers candidate
                elapsed = now - d.first_byte_at
                if self.slow.is_slow(len(raw), elapsed, SLOW_HEADER_GRACE):
                    f = self.slow.record(fl.src, "headers", now, fl.flow_id)
                    if f:
                        findings.append(f)
                break
            msg = parse_message(raw, kind)
            if msg is None or not msg.complete:
                break
            self.stats["http1_messages"] += 1

            if not from_client:
                banner = msg.get(b"server")
                if banner:
                    fl.server_banner = banner
                # h2c upgrade: 101 hands this flow to the Tier D parser
                if msg.status == 101 and b"h2c" in (
                        msg.get(b"upgrade") or b"").lower():
                    consumed = msg.body_offset
                    del d.buf[:consumed]
                    fl.protocol = "h2c"
                    fl.h2 = H2ConnectionState(fl.flow_id, synced=True)
                    other = fl.direction(True)
                    if bytes(other.buf).startswith(H2_PREFACE):
                        del other.buf[:len(H2_PREFACE)]
                    break

            consumed = self._message_length(msg, raw)
            if consumed is None:
                # The message is not yet whole. Analysing now would report a
                # half-seen message, and re-analysing on every segment would
                # report it many times over, so do it once and only once the
                # buffer is clearly stuck.
                elapsed = now - d.first_byte_at
                declared, _ = parse_content_length(msg.get_all(b"content-length"))
                if declared and self.slow.is_slow(
                        len(raw) - msg.body_offset, elapsed, SLOW_BODY_GRACE):
                    f = self.slow.record(fl.src, "body", now, fl.flow_id)
                    if f:
                        findings.append(f)
                # A chunk grammar violation is visible the moment the
                # chunk line is read, and waiting for a body the attacker
                # never intends to finish would mean never reporting it.
                # Report once, now, rather than holding out for a message
                # that will not arrive.
                stuck = len(raw) > MAX_HEADER_SECTION
                early = False
                if not d.head_analysed:
                    te_now = analyse_transfer_encoding(
                        msg.get_all(b"transfer-encoding"))
                    if te_now["chunked"]:
                        sc_now = scan_chunked(raw, msg.body_offset)
                        early = bool(sc_now.defects or sc_now.ext_defects)
                if not d.head_analysed and (stuck or early):
                    d.head_analysed = True
                    findings.extend(analyse_http1_message(
                        msg, raw, service=fl.service,
                        server_banner=fl.server_banner))
                break

            if not d.head_analysed:
                findings.extend(analyse_http1_message(
                    msg, raw, service=fl.service,
                    server_banner=fl.server_banner))
            d.head_analysed = False
            del d.buf[:consumed]
            if not d.buf:
                break
        self.stats["findings"] += len(findings)
        return findings

    @staticmethod
    def _message_length(msg: ParsedMessage, raw: bytes) -> Optional[int]:
        te = analyse_transfer_encoding(msg.get_all(b"transfer-encoding"))
        cl, _ = parse_content_length(msg.get_all(b"content-length"))
        if te["chunked"]:
            sc = scan_chunked(raw, msg.body_offset)
            if not sc.complete:
                return None
            if cl is not None:
                cl_end = msg.body_offset + cl
                # Both framings must be resolvable at the same moment, or
                # HTTP-009 can never see the bytes the CL framer claims.
                if cl_end > sc.end_offset:
                    if cl_end - sc.end_offset > AMBIGUITY_WINDOW:
                        return sc.end_offset   # bogus CL; do not stall
                    if len(raw) < cl_end:
                        return None            # wait for the window to fill
                return max(cl_end, sc.end_offset)
            return sc.end_offset
        if cl is None:
            return msg.body_offset
        end = msg.body_offset + cl
        return end if end <= len(raw) else None


# ---------------------------------------------------------------------------
# Capture front end
# ---------------------------------------------------------------------------

def emit(record: Dict[str, Any], out=sys.stdout) -> None:
    out.write(json.dumps(record, default=str) + "\n")
    out.flush()


def finding_record(f: Finding, flow: Optional[Flow] = None) -> Dict[str, Any]:
    rec = {
        "module": MODULE,
        "version": __version__,
        "type": "finding",
        "status": "ok",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "findings": [f.to_dict()],
    }
    if flow is not None:
        rec["src"] = flow.src
        rec["dst"] = flow.dst
        rec["service"] = flow.service
    return rec


def dissect_packet(pkt, ports: Sequence[int]) -> Optional[Dict[str, Any]]:
    """Pull the fields httpwatch needs out of one captured packet.

    Returns None when the packet is not TCP payload on a watched port.

    The port decision is made HERE, after dissection, rather than in the
    capture filter, because the IPv6 leg of the filter cannot make it:
    libpcap reads Next Header at a fixed offset and any extension header
    defeats a port-scoped IPv6 term. This function is the only
    address-family-specific code in the module, which is why it is a
    function the tests can call rather than a closure inside run_live().
    """
    from scapy.all import IP as _IP, IPv6 as _IPv6, TCP as _TCP

    if _TCP not in pkt:
        return None
    if _IP in pkt:
        src, dst = pkt[_IP].src, pkt[_IP].dst
        family = "ipv4"
    elif _IPv6 in pkt:
        src, dst = pkt[_IPv6].src, pkt[_IPv6].dst
        family = "ipv6"
    else:
        return None
    tcp = pkt[_TCP]
    sport, dport = int(tcp.sport), int(tcp.dport)
    portset = set(ports)
    if dport in portset:
        from_client, key_port = True, dport
    elif sport in portset:
        from_client, key_port = False, sport
    else:
        return None
    payload = bytes(tcp.payload)
    if not payload:
        return None
    if from_client:
        flow_id = f"{src}:{sport}-{dst}:{dport}"
        a, b = src, dst
    else:
        flow_id = f"{dst}:{dport}-{src}:{sport}"
        a, b = dst, src
    return {"flow_id": flow_id, "src": a, "dst": b, "port": key_port,
            "payload": payload, "from_client": from_client, "family": family}


def run_live(args) -> int:
    try:
        from scapy.all import sniff, IP, IPv6, TCP  # noqa: F401
    except ImportError:
        print("scapy is required for live capture; use --selftest or "
              "--replay otherwise", file=sys.stderr)
        return 2

    from scapy.all import IP as _IP, IPv6 as _IPv6, TCP as _TCP

    watch = HttpWatch(tcp_ports=args.tcp_ports)
    bpf = args.bpf or build_bpf(args.tcp_ports)
    ports = set(args.tcp_ports)

    def handle(pkt):
        d = dissect_packet(pkt, ports)
        if d is None:
            return
        findings = watch.feed(d["flow_id"], d["src"], d["dst"], d["port"],
                              d["payload"], d["from_client"])
        flow = watch.flows.get(d["flow_id"])
        for f in findings:
            emit(finding_record(f, flow))

    emit({"module": MODULE, "version": __version__, "type": "start",
          "status": "ok", "bpf": bpf, "iface": args.iface,
          "tcp_ports": list(args.tcp_ports)})
    try:
        sniff(iface=args.iface, filter=bpf, prn=handle, store=False,
              timeout=args.timeout or None)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        # Without libpcap the kernel cannot compile a BPF program. Capture
        # still works; every frame simply reaches userspace and is filtered
        # in Python. That is a CPU cost, not a blind spot, so carry on and
        # say so plainly rather than failing closed or pretending the filter
        # was applied.
        if "libpcap" not in str(exc) and "filter" not in str(exc).lower():
            raise
        emit({"module": MODULE, "version": __version__, "type": "notice",
              "status": "degraded", "bpf": None,
              "reason": "libpcap unavailable; kernel BPF not applied, "
                        "filtering in userspace instead (higher CPU)"})
        try:
            sniff(iface=args.iface, prn=handle, store=False,
                  timeout=args.timeout or None)
        except KeyboardInterrupt:
            pass
    emit({"module": MODULE, "version": __version__, "type": "summary",
          "status": "ok", "stats": watch.stats})
    return 0


def run_pcap(args) -> int:
    """Read a capture file through the real filter and the real dissector.

    This is the same code path as live capture: libpcap compiles the same
    BPF program and scapy performs the same dissection; only the packet
    source differs. It is how the IPv6 leg is validated on a host whose
    kernel has no IPv6 stack, and it is useful operationally for triaging
    a capture someone hands you.
    """
    try:
        from scapy.all import sniff
    except ImportError:
        print("scapy is required to read a capture file", file=sys.stderr)
        return 2

    watch = HttpWatch(tcp_ports=args.tcp_ports)
    ports = list(args.tcp_ports)
    bpf = args.bpf or build_bpf(args.tcp_ports)
    seen = {"packets": 0, "dissected": 0, "ipv4": 0, "ipv6": 0}

    def handle(pkt):
        seen["packets"] += 1
        d = dissect_packet(pkt, ports)
        if d is None:
            return
        seen["dissected"] += 1
        seen[d["family"]] += 1
        findings = watch.feed(d["flow_id"], d["src"], d["dst"], d["port"],
                              d["payload"], d["from_client"])
        flow = watch.flows.get(d["flow_id"])
        for f in findings:
            emit(finding_record(f, flow))

    emit({"module": MODULE, "version": __version__, "type": "start",
          "status": "ok", "bpf": bpf, "pcap": args.pcap,
          "tcp_ports": ports})
    try:
        sniff(offline=args.pcap, filter=bpf, prn=handle, store=False)
    except Exception as exc:
        if "libpcap" not in str(exc) and "filter" not in str(exc).lower():
            raise
        emit({"module": MODULE, "version": __version__, "type": "notice",
              "status": "degraded", "bpf": None,
              "reason": "libpcap unavailable; kernel BPF not applied, "
                        "filtering in userspace instead (higher CPU)"})
        sniff(offline=args.pcap, prn=handle, store=False)
    stats = dict(watch.stats)
    stats.update(seen)
    emit({"module": MODULE, "version": __version__, "type": "summary",
          "status": "ok", "stats": stats})
    return 0


def run_replay(path: str) -> int:
    """Replay a raw HTTP conversation from a file (one direction, client)."""
    with open(path, "rb") as fh:
        data = fh.read()
    watch = HttpWatch()
    findings = watch.feed("replay", "127.0.0.1", "127.0.0.1", 80, data, True)
    for f in findings:
        emit(finding_record(f, watch.flows.get("replay")))
    emit({"module": MODULE, "version": __version__, "type": "summary",
          "status": "ok", "stats": watch.stats})
    return 0


def print_registry() -> int:
    for code in finding_codes():
        d = FINDING_REGISTRY[code]
        cves = (" [" + ", ".join(d.cves) + "]") if d.cves else ""
        print(f"{d.code}  {d.name:<34} tier {d.tier}  "
              f"{d.severity:<8} {d.confidence:<9}{cves}")
    print(f"\n{len(FINDING_REGISTRY)} finding codes")
    print(f"{len(DEFERRED_CVES)} deferred CVEs (considered, not detected)")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="httpwatch",
        description="Passive HTTP/1.x, h2c and gRPC observer (Ragnar)")
    p.add_argument("-i", "--iface", default=None, help="capture interface")
    p.add_argument("--tcp-ports", type=lambda s: [int(x) for x in s.split(",")],
                   default=list(DEFAULT_TCP_PORTS),
                   help="comma-separated TCP ports")
    p.add_argument("--bpf", default=None, help="override the capture filter")
    p.add_argument("--timeout", type=int, default=0,
                   help="stop after N seconds (0 = run until interrupted)")
    p.add_argument("--replay", metavar="FILE",
                   help="replay raw bytes from a file instead of capturing")
    p.add_argument("--pcap", metavar="FILE",
                   help="read a capture file through the real BPF filter "
                        "and dissector instead of capturing live")
    p.add_argument("--print-bpf", action="store_true",
                   help="print the generated capture filter and exit")
    p.add_argument("--registry", action="store_true",
                   help="print the finding code registry and exit")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    if args.print_bpf:
        print(args.bpf or build_bpf(args.tcp_ports))
        return 0
    if args.registry:
        return print_registry()
    if args.pcap:
        return run_pcap(args)
    if args.replay:
        return run_replay(args.replay)
    return run_live(args)


if __name__ == "__main__":
    sys.exit(main())
