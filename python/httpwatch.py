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
  E  Attack-shaped input in request headers
  F  Attack-shaped input in request bodies and parameters
  G  Content-coding validation (needs a patched decoder; see ARMING)

Dual-stack by construction: all rules are L7 over TCP and
address-family agnostic; the capture path admits IPv6 explicitly.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field, replace
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
        _f("HTTP-048", "php_session_cookie_oversized", "C", HIGH, SHAPE,
           "Set-Cookie PHP session value past any size a cookie can work at "
           "(PHP2Shell memory-disclosure stage)",
           ["CVE-2026-109618", "CVE-2026-109619"]),
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
        # ---- Tier E: attack-shaped request headers -----------------------
        _f("HTTP-080", "shellshock_function_import", "E", HIGH, EXACT,
           "Request header value begins with the bash function-import "
           "prefix '() {' (Shellshock)",
           ["CVE-2014-6271", "CVE-2014-6277", "CVE-2014-6278",
            "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187"]),
        _f("HTTP-081", "java4shell_base64_padding", "E", HIGH, EXACT,
           "Authentication header carries Base64 with padding no encoder "
           "produces, at the length that reaches the JDK intrinsic",
           ["CVE-2026-114938"]),
        # ---- Tier F: attack-shaped request bodies and parameters ---------
        _f("HTTP-084", "struts_s2045_content_type_ognl", "E", CRITICAL, EXACT,
           "Content-Type satisfies all three conditions Struts needs to "
           "evaluate it as OGNL (S2-045)",
           ["CVE-2017-5638"]),
        _f("HTTP-082", "react2shell_flight_path_reference", "F", CRITICAL, SHAPE,
           "RSC Flight reply carries a property-path reference, which a real "
           "encoder never emits (React2Shell)",
           ["CVE-2025-55182", "CVE-2025-66478"]),
        _f("HTTP-083", "spring4shell_class_property_path", "F", CRITICAL, SHAPE,
           "Bean property path runs through 'class' into JVM internals "
           "(Spring4Shell)",
           ["CVE-2022-22965", "CVE-2010-1622"]),
        _f("HTTP-085", "struts_s2046_filename_ognl", "F", CRITICAL, EXACT,
           "Multipart filename carries a NUL and an OGNL opener, which "
           "commons-fileupload echoes into an evaluated message (S2-046)",
           ["CVE-2017-5638"]),
        # ---- Tier G: content-coding validation ---------------------------
        _f("HTTP-090", "brotli_block_switch_violation", "G", CRITICAL, EXACT,
           "Brotli-coded body contains a block switch for a category with "
           "one block type, which the decoder rejects as a format error",
           ["CVE-2026-111497"]),
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
    # Pinned 2026-11-22. Both scores are the PHP security team's own CVSS 4.0
    # figures, confirmed by Tenable's advisory round-up; NVD carries no CVSS
    # 3.1 vector for either, so none is invented here. An earlier 10.0 that
    # circulated before release was withdrawn by the PHP Foundation.
    "CVE-2026-109618": {
        "score": 9.2, "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss_version": "4.0",
        "kev": True, "kev_added": "2026-10-26", "kev_due": "2026-10-29",
        "alias": "PHP2Shell (OOM corruption)",
        "note": "Out-of-memory during partial initialisation of internal "
                "request data leaves cleanup treating that data as valid. "
                "Exploited in the wild. Fixed in 8.2.35, 8.3.36, 8.4.27, "
                "8.5.12; source backports only for 7.4-8.1; nothing for "
                "5.4-7.3. httpwatch sees the memory-disclosure stage of the "
                "public chains, not the host's patch level.",
    },
    "CVE-2026-109619": {
        "score": 9.2, "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss_version": "4.0",
        "kev": True, "kev_added": "2026-10-26", "kev_due": "2026-10-29",
        "alias": "PHP2Shell (stale global state)",
        "note": "Use-after-free: state left by one request points at freed "
                "memory a later request on the same worker reaches. PHP's "
                "advisory lists memory disclosure as a confirmed impact. "
                "Sources split on which of the pair owns the Set-Cookie "
                "leak - Datadog places it in CVE-2026-109618's exploit "
                "requirements, PHP records disclosure under this one - so "
                "HTTP-048 is attributed to the pair and never to one ID.",
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

# Pinned 2026-11-22 against the vendor and CNA records.
CVE_CATALOG.update({
    # --- Tier E -----------------------------------------------------------
    "CVE-2014-6271": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": True, "kev_added": "2021-11-03", "alias": "Shellshock",
        "note": "bash imports a function from an environment variable whose "
                "value begins with the four bytes '() {'. A CGI server copies "
                "every request header into an HTTP_* variable, so the header "
                "value is the delivery vehicle. Fixed by bash 4.3 patch 25; "
                "patch 27 renames imports to BASH_FUNC_name%% and closes the "
                "path. Measured here on bash 5.2.21: the prefix is exactly "
                "those four bytes - no-space, double-space and leading-space "
                "forms are not imported.",
    },
    "CVE-2014-7169": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "kev": True, "kev_added": "2022-05-03",
        "note": "The incomplete-fix sibling: parser state survives the "
                "patch-25 check. Same four-byte prefix on the wire.",
    },
    "CVE-2014-6277": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": False,
        "note": "Function-import parser abuse, uninitialised memory. Same "
                "four-byte prefix. Not separately listed in CISA KEV; the "
                "family entry is CVE-2014-6271.",
    },
    "CVE-2014-6278": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": False,
        "note": "Command execution through the function-import path with the "
                "'() { _; } >_[$($())] {' shape, which still begins with the "
                "same four bytes. Not separately in CISA KEV.",
    },
    "CVE-2014-7186": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": False,
        "note": "redir_stack parser overflow reached through function import. "
                "Not separately in CISA KEV.",
    },
    "CVE-2014-7187": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": False,
        "note": "Nested-loop off-by-one reached through function import. Not "
                "separately in CISA KEV.",
    },
    "CVE-2026-114938": {
        "score": 9.2, "vector": None, "vector_unpublished": True,
        "cvss_version": "4.0",
        "kev": False, "alias": "Java4Shell",
        "disputed": True,
        "dissent": "Oracle 8.1 under CVSS 3.1 in the November CSPU",
        "note": "HotSpot AVX-512 Base64 intrinsic heap overflow, 62-63 bytes "
                "past a heap array. Calif scored it 9.2 under CVSS 4.0 but "
                "published NO vector string, so none is recorded here rather "
                "than one being invented to match the other entries. NOT in "
                "CISA KEV as of 2026-11-22 (probing reported, no confirmed "
                "compromise). Affected: OpenJDK 17.0.6+ and every release "
                "from 18 on, x86-64 with AVX-512 VBMI only; Java 8, 11, "
                "17.0.0-17.0.5 and ARM64 are not affected. Fixed in "
                "17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1. The CPU and JVM "
                "preconditions are host state and are not on the wire.",
    },
    # --- Tier F -----------------------------------------------------------
    "CVE-2025-55182": {
        "score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "kev": True, "kev_added": "2025-12-05", "kev_due": "2025-12-26",
        "alias": "React2Shell",
        "note": "React Server Components Flight protocol resolved references "
                "through inherited properties. The fix makes requireModule "
                "return a value only when hasOwnProperty.call(moduleExports, "
                "name) holds - own-property-only resolution. Affected: "
                "react-server-dom-{webpack,parcel,turbopack} 19.0, 19.1.0, "
                "19.1.1, 19.2.0; fixed 19.0.1, 19.1.2, 19.2.1.",
    },
    "CVE-2025-66478": {
        "score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "kev": False,
        "note": "The Next.js-side identifier for the same defect. Affected: "
                "Next.js 15.x, 16.x and 14.3.0-canary.77 onward; 13.x, 14.x "
                "stable, the Pages Router and the Edge Runtime are not "
                "affected. Fixed in 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, "
                "15.5.7 and 16.0.7. CISA listed the upstream React ID, not "
                "this one, so kev is False here and True on CVE-2025-55182: "
                "one defect, two records, and the catalog says which is "
                "which rather than copying the flag across.",
    },
    "CVE-2022-22965": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "kev": True, "kev_added": "2022-04-04", "alias": "Spring4Shell",
        "note": "Spring DataBinder binds a request parameter whose name is a "
                "bean property path, and a path through 'class' reaches "
                "getClass() and then reflective JVM internals. Needs JDK 9+; "
                "the public chain also needs a Tomcat WAR deployment. Fixed "
                "in Spring Framework 5.3.18 and 5.2.20.",
    },
    "CVE-2010-1622": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "kev": False,
        "note": "The ancestor: class.classLoader reachable through the same "
                "data binder. Covered by the same rule at no extra cost, "
                "which is why it is attributed rather than left unlisted.",
    },
    "CVE-2017-5638": {
        "score": 10.0, "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "kev": True, "kev_added": "2021-11-03",
        "alias": "Struts S2-045 / S2-046",
        "note": "OGNL injection through the Jakarta multipart parser in "
                "Apache Struts 2, and the entry point of the 2017 Equifax "
                "breach. Struts tracks two advisories under this one CVE: "
                "S2-045 (Content-Type) and S2-046 (Content-Disposition "
                "filename). Affected 2.3.5-2.3.31 and 2.5-2.5.10; fixed "
                "2.3.32 and 2.5.10.1. Three conditions, all set by the "
                "victim's own code, pinned from the shipped source on "
                "2026-11-23 - see the module comment above HTTP-084.",
    },
    # --- Tier G -----------------------------------------------------------
    "CVE-2026-111497": {
        "score": 9.2,
        "vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss_version": "4.0",
        "kev": True, "kev_added": "2026-10-27", "kev_due": "2026-11-10",
        "alias": "Node2Shell / HTTP2Shell / Brotli2Shell",
        "cwe": "CWE-252", "disputed": True,
        "dissent": "Microsoft 8.1 under CVSS 3.1 for the .NET surface",
        "note": "Out-of-bounds write in Google's reference Brotli decoder "
                "(c/dec/decode.c), scored 9.2 by Google as CNA. A block "
                "switch for a category declaring one block type returned the "
                "same status as 'needs more input', so the decoder kept "
                "buffering and overran - CWE-252. Affected Brotli 1.0.3 "
                "through 1.2.0; fixed 1.0.10, 1.1.1, 1.2.1, and in Node "
                "22.23.4 / 24.22.1 / 26.12.1, Bun 1.4.4, PyPI Brotli 1.2.1, "
                "brotlicffi 1.2.1.0. Node 20, 23 and 25 are end-of-support "
                "with no fix. Commit 0ed4268a makes a patched decoder return "
                "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH, which is the "
                "oracle HTTP-090 reads; that commit ships no test vector.",
    },
})

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
    "CVE-2026-126714": (
        "phpAfterShell. Every byte of the chain is valid HTTP and success "
        "leaves its mark in on-disk session state, not on the wire. There is "
        "no malformation to read, so there is nothing for a passive observer "
        "to key on. Closed 2026-11-22."
    ),
    "CVE-2026-115560": (
        "PHP session-handler RCE vector. Two config preconditions must both "
        "hold (session.upload_progress enabled, AND the application sets "
        "session.serialize_handler to php_binary or php_serialize then "
        "switches it to php with ini_set() before session_start()). The "
        "advisory describes no distinguishing artifact in the request or the "
        "response, and the trigger is entirely host configuration, so "
        "nothing crosses the wire to observe."
    ),
    "CVE-2017-9791": (
        "Struts 2 Showcase OGNL through a Struts 1 action wrapper. The "
        "expression arrives in an ordinary form field, which is free-form, "
        "and the opener alone is the Confluence-class false positive this "
        "module refuses. No fixed shape at the load-bearing bytes."
    ),
    "CVE-2018-11776": (
        "Struts S2-057: OGNL in the URL namespace. Reachable only when the "
        "action configuration omits a namespace and uses a wildcard mapping, "
        "which is host configuration and not on the wire, and the expression "
        "sits in a free-form path segment. Each Struts OGNL CVE needs its "
        "own walk; this one has no fixed wire shape."
    ),
    "CVE-2020-17530": (
        "Struts S2-061: forced double OGNL evaluation through a tag "
        "attribute. The expression is in free-form application parameters "
        "whose names depend on the app's own tags, so there is no fixed "
        "field and no fixed shape."
    ),
    "CVE-2022-26134": (
        "Confluence OGNL injection. Kept here as the contrast that defines "
        "the Struts gate: it has a SINGLE opener in a free-form path, which "
        "collides with real unrendered-template traffic. Struts S2-045 "
        "stacks three fixed conditions set by the victim's own code, which "
        "is why one is in and the other is not."
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
# HTTP-048: PHP session-cookie memory disclosure (PHP2Shell)
# ---------------------------------------------------------------------------
# The disclosure stage of the public PHP2Shell chains hands back reclaimed
# worker heap in Set-Cookie: PHPSESSID=, percent-encoded by PHP itself: an
# out-of-memory bailout during multipart parsing leaves PS(id) pointing at a
# freed allocation, and a later multipart request on the same worker reaches
# the upload-progress cleanup path before Session initialisation resets it.
# PHP then treats the stale pointer and an attacker-chosen length as a live
# string. It works even where the application never calls session_start().
#
# The rule's boundary was measured, not assumed (PHP 8.3.6, sandbox,
# 2026-11-22), and confirmed over a real loopback HTTP round trip:
#   - the native generator (bits_per_character 4/5/6 x lengths 22/32/256,
#     1,800 cookies) emits only [0-9a-zA-Z,-]; the one escape it can produce
#     is %2C, so its ceiling is 256 * 3 = 768 encoded bytes;
#     NOTE for anyone re-measuring: PHP locks session.sid_length and
#     session.sid_bits_per_character after the first session_create_id()
#     call in a request, and ini_set() then returns false. A single process
#     walking the combinations silently reuses the first one's settings and
#     produces a corpus that looks plausible and is wrong. One process per
#     combination, which is what the self-test's re-measurement does.
#   - session_id() set by the application is emitted unvalidated: 'abc.def',
#     'a%3Db%3Bc' and a 300-character ID all reach the wire as given.
# So neither "outside the alphabet" nor "longer than 256" can be the rule -
# both have legitimate forms. The boundary used instead is RFC 6265 6.1: a
# user agent need only store 4096 bytes per cookie, so a session cookie
# larger than that cannot function as a session and no working application
# emits one. The leak size itself is attacker-chosen; no published source
# fixes it, which is why the threshold is derived from the cookie spec
# rather than from a reported leak size.
PHP_SESSION_COOKIE_NAMES: Tuple[bytes, ...] = (b"PHPSESSID",)
PHP_COOKIE_NATIVE_CEILING = 768      # 256 chars x %2C, measured
PHP_COOKIE_MAX = 4096                # RFC 6265 6.1 minimum UA capability
PHP2SHELL_LABEL = ("PHP2Shell memory-disclosure stage "
                   "(CVE-2026-109618/109619)")
# PHP's own default session.upload_progress.name. Used only to annotate a
# finding that already stands on its own, never to gate one.
PHP_UPLOAD_PROGRESS_FIELD = b"PHP_SESSION_UPLOAD_PROGRESS"
UPLOAD_PROGRESS_WINDOW = 8 * 1024

# Bounds for scanning a header section that has not terminated. A leak
# larger than MAX_HEADER_SECTION never completes one, so the scan has to run
# on the partial buffer; these keep that from becoming quadratic work on a
# flow that never finishes its head.
PHP_SCAN_GROWTH = 4096               # rescan at most once per 4 KiB of growth
PHP_SCAN_CEILING = 256 * 1024        # stop scanning an unterminated head here
HEAD_BUFFER_CEILING = 1024 * 1024    # stop growing an unterminated head here
PHP_DEDUP_WINDOW = 300.0             # one HTTP-048 per server:port per 5 min
# The attack-class codes rate-limit per (code, client, server:port) per five
# minutes. Every one of these fires on attacker-chosen traffic, and an
# internet-facing tap sees scanners hammer them continuously; one alert per
# probe would bury everything else. The count of what was suppressed rides
# on the next finding after the window rolls.
ATTACK_DEDUP_WINDOW = 300.0
ATTACK_CODES = frozenset({
    "HTTP-080", "HTTP-081", "HTTP-082", "HTTP-083",
    "HTTP-084", "HTTP-085", "HTTP-090",
})

_PCT_ESCAPE_RE = re.compile(rb"%([0-9A-Fa-f]{2})")


@dataclass(frozen=True)
class PhpCookieConfig:
    names: Tuple[bytes, ...] = PHP_SESSION_COOKIE_NAMES
    threshold: int = PHP_COOKIE_MAX


PHP_COOKIE_DEFAULTS = PhpCookieConfig()


@dataclass(frozen=True)
class WatchConfig:
    """Everything an operator can turn. Defaults are the safe side.

    One object rather than a growing parameter list, so a rule cannot be
    given a default the operator thought they had overridden.
    """
    php: PhpCookieConfig = PHP_COOKIE_DEFAULTS
    # HTTP-080: attacker-authored command text is off by default. It is the
    # attacker's own bytes, but it carries URLs, tokens and staging hosts an
    # operator may not want copied into syslog.
    log_attack_payload: bool = False
    # Tier F: how much decoded request body a rule will inspect. Over this,
    # the finding-free path records inspect_truncated rather than passing.
    body_cap: int = 1024 * 1024
    # HTTP-080 priority only, never a gate.
    internal_cidrs: Tuple[str, ...] = ()
    # Tier G: set by arm_brotli(); None means HTTP-090 is not armed.
    brotli: Optional[Any] = None
    # Tier G response direction. Most outbound fetches are TLS, so off.
    brotli_scan_responses: bool = False
    # HTTP-083 segment comparison. See the README: Spring's introspection
    # capitalisation fallback is not measurable here, so the rule compares
    # case-insensitively, which can only widen matching.
    spring_case_insensitive: bool = True


WATCH_DEFAULTS = WatchConfig()


def php_cookie_config(threshold: int = PHP_COOKIE_MAX,
                      extra_names: Sequence[str] = ()) -> PhpCookieConfig:
    """Validate and build the HTTP-048 configuration.

    A threshold at or below the measured native ceiling is refused outright:
    below 768 bytes the rule would fire on a legitimate 256-character session
    ID, which is the one thing the measurement rules out. Anything under the
    4096-byte RFC 6265 figure is accepted but is no longer zero-FP, because
    an application may legitimately set a session ID of any length, so it
    warns.
    """
    if threshold <= PHP_COOKIE_NATIVE_CEILING:
        raise ValueError(
            f"HTTP-048 threshold must exceed the measured native generator "
            f"ceiling of {PHP_COOKIE_NATIVE_CEILING} bytes; {threshold} "
            f"would fire on a legitimate 256-character session ID")
    if threshold < PHP_COOKIE_MAX:
        print(f"httpwatch: warning: HTTP-048 threshold {threshold} is below "
              f"the RFC 6265 6.1 figure of {PHP_COOKIE_MAX}; the rule is no "
              f"longer false-positive-free", file=sys.stderr)
    names = list(PHP_SESSION_COOKIE_NAMES)
    for n in extra_names or ():
        b = n.encode("latin-1") if isinstance(n, str) else n
        if b and b not in names:
            names.append(b)
    return PhpCookieConfig(names=tuple(names), threshold=threshold)


def count_escapes(value: bytes) -> Dict[str, int]:
    """R2: count control and high-byte percent-escapes in a cookie value.

    Corroborating only. An application can pass binary to session_id(), so
    on its own this is near-zero-FP rather than zero-FP; it rides on the
    HTTP-048 evidence and is never a finding of its own.
    """
    control = high = total = 0
    for m in _PCT_ESCAPE_RE.finditer(value):
        total += 1
        b = int(m.group(1), 16)
        if b <= 0x1F or b == 0x7F:
            control += 1
        elif b >= 0x80:
            high += 1
    return {"control_escapes": control, "high_byte_escapes": high,
            "percent_escapes": total}


def header_lines(section: bytes) -> List[bytes]:
    """Split a header section into logical lines, joining obsolete folds.

    Folds are joined because a tolerant client joins them, so a folded
    Set-Cookie must not be a way around a length check. The join is
    length-preserving to within the one byte RFC 9110 5.2 replaces the fold
    with, and the last line may be incomplete - that is the normal case when
    this runs on a head still arriving.
    """
    out: List[bytes] = []
    for ln in section.split(b"\n"):
        if ln.endswith(b"\r"):
            ln = ln[:-1]
        if out and ln[:1] in (b" ", b"\t"):
            out[-1] = out[-1] + b" " + ln.lstrip(b" \t")
        else:
            out.append(ln)
    return out


def _php_cookie_hit(name: bytes, value: bytes,
                    cfg: PhpCookieConfig) -> Dict[str, Any]:
    """Build the evidence for one oversized PHP session cookie.

    The value never appears here, not even a prefix: its first bytes are a
    live session token and the rest is reclaimed worker heap that can hold
    other users' credentials and keys. Only lengths, escape counts and a
    short correlation hash leave this function - the discipline the
    r-services credential findings already follow.
    """
    esc = count_escapes(value)
    return {
        "cookie_name": name.decode("latin-1"),
        "encoded_length": len(value),
        "decoded_length": len(value) - 2 * esc["percent_escapes"],
        "threshold": cfg.threshold,
        "native_generator_ceiling": PHP_COOKIE_NATIVE_CEILING,
        "value_digest": redact(value),
        "control_escapes": esc["control_escapes"],
        "high_byte_escapes": esc["high_byte_escapes"],
    }


def _php_cookie_from_field(field: bytes,
                           cfg: PhpCookieConfig) -> Optional[Dict[str, Any]]:
    """Evaluate one Set-Cookie field value.

    RFC 6265 4.1.1 gives set-cookie-string = cookie-pair *( ";" SP
    cookie-av ), so the value is what lies between the first '=' and the
    first ';'. The cookie-name is compared literally: 6265 folds case for
    attribute names and for the domain, and nowhere for the cookie-name
    itself, and PHP matches session.name literally too - so 'phpsessid' is
    not PHP's cookie and is not treated as one.

    The threshold is deliberately conservative. RFC 6265 6.1 measures its
    4096-byte figure as "the sum of the length of the cookie's name, value,
    and attributes", so a value alone past 4096 is past the whole-cookie
    budget with the name and attributes still to count. Measuring the value
    alone can only ever miss a leak, never invent one.
    """
    eq = field.find(b"=")
    if eq < 0:
        return None
    name = field[:eq]
    if name not in cfg.names:
        return None
    value = field[eq + 1:]
    semi = value.find(b";")
    if semi >= 0:
        value = value[:semi]
    if len(value) <= cfg.threshold:
        return None
    return _php_cookie_hit(name, value, cfg)


def php_cookie_hits(section: bytes,
                    cfg: PhpCookieConfig = PHP_COOKIE_DEFAULTS,
                    ) -> List[Dict[str, Any]]:
    """R1 over an HTTP/1.x header section, complete or not.

    The rule is a length floor, so a value already past the threshold is
    past it whether or not the rest of the header ever arrives. Each
    Set-Cookie is evaluated independently; the field name is matched
    case-insensitively.
    """
    hits: List[Dict[str, Any]] = []
    for ln in header_lines(section):
        # field names are case-insensitive (RFC 9110 5.1)
        if ln[:11].lower() != b"set-cookie:":
            continue
        hit = _php_cookie_from_field(ln[11:].lstrip(b" \t"), cfg)
        if hit is not None:
            hits.append(hit)
    return hits


def php_cookie_hits_fields(headers: Sequence[Tuple[bytes, bytes]],
                           cfg: PhpCookieConfig = PHP_COOKIE_DEFAULTS,
                           ) -> List[Dict[str, Any]]:
    """R1 over decoded h2 response fields.

    The length is measured on the HPACK-decoded value, which is the same
    string an HTTP/1.x response carries literally; the Huffman-coded wire
    form is shorter and would make the threshold mean something else. Every
    set-cookie field is evaluated, not just the first: HTTP/2 carries each
    cookie as its own field and a map would drop all but one.
    """
    hits: List[Dict[str, Any]] = []
    for name, value in headers:
        if name.lower() != b"set-cookie":
            continue
        hit = _php_cookie_from_field(value, cfg)
        if hit is not None:
            hits.append(hit)
    return hits


HTTP048_NOTE = (
    "A PHP session cookie past the RFC 6265 6.1 user-agent minimum cannot "
    "function as a session, so this is not a long session ID; it is the "
    "response carrying back reclaimed worker heap. This records an exploit "
    "stage seen on the wire - it is not a vulnerable-or-not verdict on the "
    "host, and the value is deliberately never logged."
)


def php_cookie_findings(hits: Sequence[Dict[str, Any]],
                        flow_id: Optional[str] = None,
                        http_version: Optional[bytes] = None,
                        upload_progress: bool = False,
                        partial: bool = False,
                        ) -> List[Finding]:
    """Turn R1 hits into HTTP-048 findings, with R2 as attributes.

    `partial` marks a measurement taken on a header section that had not
    terminated, where every length is a floor rather than a total. Saying
    so is the difference between a number and a number that is wrong.
    """
    out: List[Finding] = []
    for hit in hits:
        ev = dict(hit)
        ev["attribution"] = PHP2SHELL_LABEL
        ev["finding_class"] = "exploit_stage_observed"
        if partial:
            ev["measured_on"] = "unterminated_head"
            ev["lengths_are_lower_bounds"] = True
        if http_version is not None:
            ev["http_version"] = (http_version.decode("latin-1")
                                  if isinstance(http_version, bytes)
                                  else str(http_version))
        if upload_progress:
            ev["preceded_by_multipart_upload_progress"] = True
        ev["note"] = HTTP048_NOTE
        out.append(make_finding("HTTP-048", ev, flow=flow_id))
    return out


class LeakDedup:
    """One HTTP-048 per server address:port per window.

    The count of hits suppressed in a window is carried on the first
    finding of the next one, because that is the first moment it can be
    known. Reporting every leaked response from a host under active
    exploitation would bury the one alert that matters.
    """

    def __init__(self, window: float = PHP_DEDUP_WINDOW):
        self.window = window
        self._state: Dict[Tuple[str, int], Tuple[float, int]] = {}

    def allow(self, key: Tuple[str, int], now: float) -> Tuple[bool, int]:
        first, suppressed = self._state.get(key, (None, 0))
        if first is None or now - first > self.window:
            self._state[key] = (now, 0)
            return True, suppressed
        self._state[key] = (first, suppressed + 1)
        return False, 0

    def expire(self, now: float) -> None:
        for key in [k for k, (t, _) in self._state.items()
                    if now - t > self.window * 2]:
            del self._state[key]



# ---------------------------------------------------------------------------
# Shared request-body decode pipeline (Tiers F and G)
# ---------------------------------------------------------------------------
# Nothing above this point decoded a request body. Tier C read Content-Length
# framed bodies as raw bytes and that was enough for a form-field name match;
# the Tier F and G rules need the bytes a server would actually hand its
# application, which means dechunking, and for multipart it means parsing the
# way the server's multipart layer parses.
#
# The parity risk is the whole game here (React2Shell's public tooling ships
# charset, padding, boundary and framing evasions). The approach taken is NOT
# "mirror one server exactly": a parser that under-approximates any affected
# server is an evasion route, and there are several affected stacks. Instead
# every part is decoded every plausible way and the rule matches on any of
# them. Over-approximating can only cost a false positive, and the rules it
# feed are anchored grammars where a spurious match is not a realistic
# outcome - which the measured negative corpora then confirm.

MULTIPART_MAX_PARTS = 256
MULTIPART_MAX_PART_BYTES = 1024 * 1024
# Charsets a multipart part may declare and a server may honour. UTF-16 and
# UTF-32 are in the public React2Shell tooling precisely because byte-level
# matchers miss them.
PART_CHARSETS = ("utf-8", "utf-16-le", "utf-16-be", "utf-16",
                 "utf-32-le", "utf-32-be", "utf-32", "latin-1")


def parse_content_type(value: Optional[bytes]) -> Tuple[bytes, Dict[bytes, bytes]]:
    """Split a Content-Type into its type and its parameters.

    Tolerant in the directions servers are tolerant: parameter names fold
    case, values may be quoted or bare, and a quoted value may contain a
    semicolon.
    """
    if not value:
        return b"", {}
    out: Dict[bytes, bytes] = {}
    main = value
    i = value.find(b";")
    if i >= 0:
        main, rest = value[:i], value[i + 1:]
    else:
        rest = b""
    pos = 0
    while pos < len(rest):
        eq = rest.find(b"=", pos)
        if eq < 0:
            break
        name = rest[pos:eq].strip(b" \t").lower()
        pos = eq + 1
        while pos < len(rest) and rest[pos] in b" \t":
            pos += 1
        if pos < len(rest) and rest[pos:pos + 1] == b'"':
            pos += 1
            buf = bytearray()
            while pos < len(rest):
                ch = rest[pos:pos + 1]
                if ch == b"\\" and pos + 1 < len(rest):
                    buf += rest[pos + 1:pos + 2]
                    pos += 2
                    continue
                if ch == b'"':
                    pos += 1
                    break
                buf += ch
                pos += 1
            val = bytes(buf)
        else:
            end = rest.find(b";", pos)
            if end < 0:
                end = len(rest)
            val = rest[pos:end].strip(b" \t")
            pos = end
        if name:
            out.setdefault(name, val)
        semi = rest.find(b";", pos)
        pos = len(rest) if semi < 0 else semi + 1
    return main.strip(b" \t").lower(), out


def dechunk(raw: bytes, start: int, cap: int) -> Tuple[bytes, bool, bool]:
    """Decode a chunked body. Returns (bytes, complete, truncated_at_cap).

    Bounded by construction: it stops at `cap` and says so, so a 23 MB body
    costs `cap` bytes of memory and not 23 MB. Tolerant of a bare-LF chunk
    line, because a server that accepts one hands its application the same
    bytes - and httpwatch already reports the bare LF separately as
    HTTP-006, so tolerating it here loses no evidence.
    """
    out = bytearray()
    pos = start
    n = len(raw)
    truncated = False
    while pos < n:
        nl = raw.find(b"\n", pos)
        if nl < 0:
            return bytes(out), False, truncated
        line = raw[pos:nl].rstrip(b"\r")
        semi = line.find(b";")
        size_field = line if semi < 0 else line[:semi]
        size_field = size_field.strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            return bytes(out), False, truncated
        pos = nl + 1
        if size == 0:
            return bytes(out), True, truncated
        take = raw[pos:pos + size]
        room = max(cap - len(out), 0)
        if len(take) > room:
            truncated = True
        out += take[:room]
        pos += size
        # step over the chunk's trailing CRLF (or bare LF)
        if raw[pos:pos + 2] == b"\r\n":
            pos += 2
        elif raw[pos:pos + 1] == b"\n":
            pos += 1
    return bytes(out), False, truncated


def request_body(msg: ParsedMessage, raw: bytes,
                 cap: int) -> Tuple[bytes, Dict[str, Any]]:
    """The bytes a server would hand its application, bounded by `cap`.

    Content-coding is NOT undone here. Tier G owns Brotli, and a coded body
    that Tier F cannot read is recorded as such rather than guessed at.
    """
    info: Dict[str, Any] = {"framing": None, "truncated": False,
                            "complete": True, "coded": None}
    te = analyse_transfer_encoding(msg.get_all(b"transfer-encoding"))
    enc = (msg.get(b"content-encoding") or b"").strip().lower()
    if enc and enc != b"identity":
        info["coded"] = enc.decode("latin-1")[:64]
    if te["chunked"]:
        info["framing"] = "chunked"
        body, complete, trunc = dechunk(raw, msg.body_offset, cap)
        info["complete"], info["truncated"] = complete, trunc
        return body, info
    cl, _ = parse_content_length(msg.get_all(b"content-length"))
    if cl is None:
        info["framing"] = "none"
        return b"", info
    info["framing"] = "content-length"
    end = msg.body_offset + cl
    body = raw[msg.body_offset:min(end, len(raw))]
    info["complete"] = len(raw) >= end
    if len(body) > cap:
        body = body[:cap]
        info["truncated"] = True
    return body, info


@dataclass
class MultipartPart:
    index: int
    name: Optional[bytes] = None
    filename: Optional[bytes] = None
    charset: Optional[bytes] = None
    content_type: bytes = b""
    content: bytes = b""
    headers: List[Tuple[bytes, bytes]] = field(default_factory=list)


def parse_multipart(body: bytes, boundary: bytes,
                    max_parts: int = MULTIPART_MAX_PARTS,
                    max_part: int = MULTIPART_MAX_PART_BYTES,
                    ) -> Tuple[List[MultipartPart], Dict[str, Any]]:
    """Parse a multipart body the tolerant way servers parse it.

    Deliberately tolerant about: a preamble before the first delimiter
    (which is where the public tooling's 128 KB of junk goes, and it is
    ignored rather than being treated as an inspection window), LF-only line
    endings, part header name case, and a Content-Disposition whose name
    parameter is quoted, bare, or escaped. Duplicate field names are kept as
    separate parts rather than collapsed, because collapsing them is how a
    parameter-pollution evasion gets through.
    """
    meta: Dict[str, Any] = {"parts": 0, "preamble_bytes": 0,
                            "lf_only": False, "truncated_parts": 0,
                            "closed": False}
    if not boundary:
        return [], meta
    delim = b"--" + boundary
    first = body.find(delim)
    if first < 0:
        return [], meta
    meta["preamble_bytes"] = first
    parts: List[MultipartPart] = []
    pos = first
    while pos < len(body) and len(parts) < max_parts:
        pos += len(delim)
        if body[pos:pos + 2] == b"--":
            meta["closed"] = True
            break
        # skip the delimiter's own line ending
        if body[pos:pos + 2] == b"\r\n":
            pos += 2
        elif body[pos:pos + 1] == b"\n":
            pos += 1
            meta["lf_only"] = True
        nxt = body.find(delim, pos)
        chunk = body[pos:] if nxt < 0 else body[pos:nxt]
        # strip the CRLF that belongs to the following delimiter
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]
        elif chunk.endswith(b"\n"):
            chunk = chunk[:-1]
            meta["lf_only"] = True
        split = split_header_section(chunk)
        if split is None:
            hdr_bytes, content = chunk, b""
        else:
            hdr_bytes, off = split
            content = chunk[off:]
        part = MultipartPart(index=len(parts))
        for ln in header_lines(hdr_bytes):
            c = ln.find(b":")
            if c < 0:
                continue
            hname = ln[:c].strip(b" \t").lower()
            hval = ln[c + 1:].strip(b" \t")
            part.headers.append((hname, hval))
            if hname == b"content-disposition":
                _, params = parse_content_type(hval)
                part.name = params.get(b"name")
                part.filename = params.get(b"filename")
            elif hname == b"content-type":
                part.content_type, cparams = parse_content_type(hval)
                part.charset = cparams.get(b"charset")
        if len(content) > max_part:
            content = content[:max_part]
            meta["truncated_parts"] += 1
        part.content = content
        parts.append(part)
        if nxt < 0:
            break
        pos = nxt
    meta["parts"] = len(parts)
    return parts, meta


def decode_every_way(data: bytes,
                     declared: Optional[bytes] = None) -> List[Tuple[str, str]]:
    """Decode one part every plausible way, as (charset_label, text) pairs.

    A single "mirror the server" decode is an evasion route: there are
    several affected stacks and the public tooling ships UTF-16 and UTF-32
    declarations precisely because a matcher that guesses wrong misses. So
    the declared charset is honoured AND utf-8 is always tried, and the rule
    above matches on any decode. Over-approximating costs only a possible
    false positive, and the grammars these feed are anchored.
    """
    order: List[str] = ["utf-8"]
    if declared:
        label = declared.decode("latin-1", "replace").strip().strip('"').lower()
        alias = {"utf16": "utf-16", "utf-16le": "utf-16-le",
                 "utf-16be": "utf-16-be", "utf32": "utf-32",
                 "utf-32le": "utf-32-le", "utf-32be": "utf-32-be",
                 "iso-8859-1": "latin-1", "us-ascii": "ascii",
                 "ucs-2": "utf-16-le"}.get(label, label)
        if alias not in order:
            order.insert(0, alias)
    # The wide encodings are always tried: a part may omit the declaration
    # and still be read as UTF-16 by a server that sniffs a BOM.
    for extra in ("utf-16-le", "utf-16-be"):
        if extra not in order:
            order.append(extra)
    out: List[Tuple[str, str]] = []
    seen: set = set()
    for enc in order:
        try:
            text = data.decode(enc)
        except (UnicodeDecodeError, LookupError, ValueError):
            continue
        if text not in seen:
            seen.add(text)
            out.append((enc, text))
    return out


def urldecode(data: bytes) -> bytes:
    """Percent-decode and turn '+' into a space, as a form parser does."""
    data = data.replace(b"+", b" ")
    if b"%" not in data:
        return data
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i:i + 1] == b"%" and i + 2 < len(data) + 1:
            hexpair = data[i + 1:i + 3]
            if len(hexpair) == 2:
                try:
                    out.append(int(hexpair, 16))
                    i += 3
                    continue
                except ValueError:
                    pass
        out += data[i:i + 1]
        i += 1
    return bytes(out)


def urlencoded_names(data: bytes, limit: int = 4096) -> List[bytes]:
    """Parameter NAMES from a query string or urlencoded body.

    Names only. The values are where a web shell and any legitimate form
    data both live, and no rule here reads them.
    """
    names: List[bytes] = []
    for pair in re.split(rb"[&;]", data):
        if not pair:
            continue
        eq = pair.find(b"=")
        raw = pair if eq < 0 else pair[:eq]
        names.append(urldecode(raw))
        if len(names) >= limit:
            break
    return names


# ---------------------------------------------------------------------------
# Tier E: attack-shaped request headers
# ---------------------------------------------------------------------------
# HTTP-080 Shellshock (CVE-2014-6271 and the function-import siblings).
#
# A vulnerable bash imports a function from an environment variable only when
# the value begins with exactly these four bytes, and a CGI server copies
# every request header into an HTTP_* variable. There is no encoding, case or
# spacing latitude at the load-bearing bytes, which is the whole reason this
# is a rule and ${jndi: is not: Log4Shell tolerates nested lookups and lands
# in any logged field, so the attacker has room to vary it. Here they have
# four bytes and no room at all.
#
# Measured on bash 5.2.21 through the patch-27 BASH_FUNC_name%% import path,
# which runs the same STREQN check in variables.c:
#   '() { echo X; }'   imported        '(){ echo X; }'    not imported
#   '() { echo X;}'    imported        '()  { echo X; }'  not imported
#                                      ' () { echo X; }'  not imported
#                                      '() {echo X; }'    not imported
#                                      '(] { echo X; }'   not imported
# So the prefix is the condition, and the body after it is free - which is
# why every family variant, including 6278's '() { _; } >_[$($())] {', still
# begins with these bytes.
SHELLSHOCK_PREFIX = b"() {"
# The 6278 shape's distinguishing marker, recorded as a variant, not matched.
SHELLSHOCK_6278_MARKER = b">_["


def check_shellshock_fields(headers: Sequence[Tuple[bytes, bytes]],
                            obs_fold: bool = False,
                            cfg: WatchConfig = WATCH_DEFAULTS,
                            flow_id: Optional[str] = None) -> List[Finding]:
    """HTTP-080 over every request header value.

    Scope is every header name without exception - Cookie, User-Agent,
    Referer and anything custom - because CGI exports them all. Values are
    already OWS-trimmed and obs-folds already joined by parse_message, which
    is the recipient behaviour this has to mirror: a fold is a way to split
    the prefix across two lines, and joining it first closes that.
    """
    findings: List[Finding] = []
    for name, value in headers:
        value = value.strip(b" \t")
        if not value.startswith(SHELLSHOCK_PREFIX):
            # Mid-value is not a finding: bash imports on the prefix only.
            continue
        ev = {
            "header_name": name.decode("latin-1")[:64],
            "value_length": len(value),
            "variant": ("6278_redir_shape"
                        if SHELLSHOCK_6278_MARKER in value else "plain"),
            "value_digest": redact(value),
            "obs_folded": obs_fold,
            "note": "A vulnerable bash imports a function only when the "
                    "value begins with exactly '() {'. Measured: no-space, "
                    "double-space and leading-space forms are not imported, "
                    "so there is no latitude here to vary. This records an "
                    "attempt - whether the target runs bash CGI at all is "
                    "not visible on the wire.",
        }
        if cfg.log_attack_payload:
            ev["payload"] = value.decode("latin-1")[:512]
        findings.append(make_finding("HTTP-080", ev, flow=flow_id))
    return findings


def check_shellshock(msg: ParsedMessage,
                     cfg: WatchConfig = WATCH_DEFAULTS) -> List[Finding]:
    return check_shellshock_fields(msg.headers, obs_fold=msg.obs_fold, cfg=cfg)


# ---------------------------------------------------------------------------
# HTTP-081 Java4Shell (CVE-2026-114938).
#
# Crafted Base64 drives HotSpot's AVX-512 intrinsic 62-63 bytes past a heap
# array. The intrinsic is reached on whole 64-byte blocks, so the published
# minimum is 65 characters on JDK 21/25/27 and 129 on 17; the bad length
# comes from a padded tail in the final partial block.
#
# What makes this a rule rather than a signature: RFC 4648 fixes the output
# shape. A padded encoding has a length that is a multiple of four, padding
# only in a trailing run, and at most two '='. No encoder produces anything
# else. Unpadded Base64 carries no '=' at all and is legitimate at any
# length, so it is never flagged.
#
# Scope is deliberately narrow. Calif withheld the product-specific fields,
# saying only that authentication, file uploads and network messages can
# reach the decoder. This rule covers only fields whose content the protocol
# itself fixes as Base64 - RFC 7617 Basic and RFC 4559 Negotiate credentials
# - and does not go looking for the withheld carriers. Note RFC 9110's
# token68 permits any number of trailing '=', so HTTP does not forbid the
# trigger; the violation is at the Base64 level, inside a field specified as
# Base64.
JAVA4SHELL_SCHEMES = (b"basic", b"negotiate")
# 64 is the intrinsic's block size, and covers the JDK 17 threshold too: a
# longer input still has to pass 64 before it reaches the tail.
JAVA4SHELL_MIN_CORE = 64
B64_STD_ALPHABET = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
B64_URL_ONLY = frozenset(b"-_")


def base64_padding_violations(value: bytes) -> Dict[str, Any]:
    """Describe how a Base64 value departs from RFC 4648, if it does.

    Returns the violation list plus the facts a finding needs. Nothing here
    decodes the value: it is a credentials field and stays unread.
    """
    stripped = value.rstrip(b"=")
    pad_run = len(value) - len(stripped)
    violations: List[str] = []
    if pad_run:
        if len(value) % 4 != 0:
            # The published shape: every reported tail (=, ==, X=, X==, XY=,
            # ===) after a whole block lands here.
            violations.append("len_mod4")
        if pad_run > 2:
            violations.append("pad_run")
    if b"=" in stripped:
        violations.append("inner_pad")
    chars = set(stripped)
    return {
        "violations": violations,
        "core_length": len(stripped),
        "pad_run": pad_run,
        "total_length": len(value),
        "non_alphabet": sorted(
            bytes([c]).decode("latin-1")
            for c in chars - B64_STD_ALPHABET - {ord("=")}),
        "base64url_chars": bool(chars & B64_URL_ONLY),
    }


def check_java4shell_fields(headers: Sequence[Tuple[bytes, bytes]],
                            flow_id: Optional[str] = None) -> List[Finding]:
    """HTTP-081 over Authorization and Proxy-Authorization."""
    findings: List[Finding] = []
    by_name: Dict[bytes, List[bytes]] = {}
    for n, v in headers:
        by_name.setdefault(n.lower(), []).append(v)
    for field in (b"authorization", b"proxy-authorization"):
        for raw in by_name.get(field, ()):
            parts = raw.split(None, 1)
            if len(parts) != 2:
                continue
            scheme = parts[0].lower()
            if scheme not in JAVA4SHELL_SCHEMES:
                continue
            creds = parts[1].strip(b" 	")
            info = base64_padding_violations(creds)
            if not info["violations"]:
                continue
            if info["core_length"] < JAVA4SHELL_MIN_CORE:
                # Short malformed values cannot reach the intrinsic. Counter
                # material, not an alert.
                continue
            if info["non_alphabet"]:
                # A value carrying characters outside the alphabet is a
                # client bug, not the trigger shape. Also a counter.
                continue
            ev = {
                "header_name": field.decode("ascii"),
                "scheme": scheme.decode("ascii"),
                "violations": info["violations"],
                "credentials_length": info["total_length"],
                "core_length": info["core_length"],
                "pad_run": info["pad_run"],
                "value_digest": redact(creds),
                "note": "No RFC 4648 encoder emits this padding, and the "
                        "value is long enough to reach the AVX-512 Base64 "
                        "intrinsic (65 characters on JDK 21/25/27, 129 on "
                        "17). Trigger-shaped input sent - the CPU flags and "
                        "JVM build that decide whether the target is "
                        "affected are host state and are not on the wire.",
            }
            findings.append(make_finding("HTTP-081", ev, flow=flow_id))
    return findings


def check_java4shell(msg: ParsedMessage) -> List[Finding]:
    return check_java4shell_fields(msg.headers)



# ---------------------------------------------------------------------------
# Tier F: attack-shaped request bodies and parameters
# ---------------------------------------------------------------------------
# HTTP-082 React2Shell (CVE-2025-55182 / CVE-2025-66478).
#
# React's Flight protocol serialises a Server Action's arguments as numbered
# form fields holding JSON, in which a leading '$' marks a reference. The
# defect was that reference resolution walked inherited properties, so a
# reference path could step from a chunk onto the prototype chain and reach
# the Function constructor. React's fix is one line of intent: requireModule
# returns a value only when hasOwnProperty.call(moduleExports, name) holds.
#
# The rule is NOT a list of dangerous property names, and that matters.
# Trend Micro's analysis shows the minimum viable chain is $1:then:constructor
# - no __proto__, no prototype, and a single constructor segment - so a rule
# keyed on "__proto__ or prototype, or constructor twice" misses the cheapest
# working payload. Elastic's published rule has the same gap and matches on
# the raw request body, which the public tooling's charset and padding flags
# defeat outright.
#
# What is actually invariant is the path traversal itself. MEASURED, not
# assumed: 704 JSON string values produced by real encodeReply from
# react-server-dom-webpack 19.0.0, 19.0.1, 19.1.1, 19.1.2, 19.2.0 and 19.2.1
# - covering every reference form the reply direction emits ($0 back-refs,
# $Q/$W Map and Set, $K FormData, $B Blob, $o typed array, $x async
# iterable, $@ Promise, $F server reference, $D Date, $n BigInt, $NaN,
# $Infinity, $undefined, $-0), objects whose OWN keys are literally named
# constructor, prototype, then and __proto__, Maps and Sets keyed on those
# names, deep nesting, circular references and strings full of colons - and
# ZERO of them is a property-path reference. A real encoder never emits one.
#
# Two details the measurement settled:
#   - a user string that itself begins with '$' is emitted '$$'-escaped, so
#     user data can never be mistaken for a reference;
#   - a Date is emitted as $D2026-11-22T22:00:00.000Z, which CONTAINS colons.
#     An unanchored "reference with a colon in it" rule fires on every Date
#     in every Server Action. Hence the anchor, and the numeric chunk id.
FLIGHT_PATH_REF = re.compile(r"^\$[0-9]+(?::[^:]+)+$")
# Recorded on the finding so an analyst can see which chain was used. These
# never gate the rule - the traversal does.
JS_INHERITED_NAMES = frozenset({
    "__proto__", "prototype", "constructor", "then",
    "toString", "valueOf", "hasOwnProperty", "isPrototypeOf",
    "propertyIsEnumerable", "toLocaleString", "__defineGetter__",
    "__defineSetter__", "__lookupGetter__", "__lookupSetter__",
    "call", "apply", "bind", "arguments", "caller", "__loo",
})
RSC_ACTION_HEADERS = (b"next-action", b"rsc-action-id", b"rsc-action")
_JSON_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def json_string_values(text: str) -> List[str]:
    """Every JSON string value in `text`, with escapes resolved.

    A real parse first, because that is what the server does and it resolves
    \\uXXXX for free. The regex fallback exists because an evasive body need
    not be valid JSON overall, and a rule that gave up on a parse error
    would be evaded by one trailing comma.
    """
    out: List[str] = []
    try:
        doc = json.loads(text)
    except Exception:
        doc = None
    if doc is not None:
        stack = [doc]
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                out.append(node)
            elif isinstance(node, dict):
                stack.extend(node.keys())
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        return out
    for m in _JSON_STRING.finditer(text):
        try:
            out.append(json.loads('"' + m.group(1) + '"'))
        except Exception:
            out.append(m.group(1))
    return out


def flight_path_references(text: str) -> List[Dict[str, Any]]:
    """Property-path Flight references in one decoded part."""
    hits: List[Dict[str, Any]] = []
    for value in json_string_values(text):
        if not FLIGHT_PATH_REF.match(value):
            continue
        chunk, *segments = value[1:].split(":")
        hits.append({
            "chunk_id": chunk,
            "segments": segments,
            "depth": len(segments),
            "traverses_inherited": sorted(
                {sg for sg in segments if sg in JS_INHERITED_NAMES}),
        })
    return hits


def looks_like_flight_field(name: Optional[bytes]) -> bool:
    """Flight numbers its reply fields 0, 1, 2 ... (Next.js also uses an
    $ACTION_ prefix, which is a field NAME and never a reference)."""
    return bool(name) and name.isdigit()


def check_react2shell(msg: ParsedMessage, body: bytes,
                      body_info: Dict[str, Any],
                      cfg: WatchConfig = WATCH_DEFAULTS,
                      stats: Optional[Dict[str, int]] = None) -> List[Finding]:
    """HTTP-082. Gate, decode every way, then apply the invariant."""
    if msg.method != b"POST":
        return []
    names = {n.lower() for n, _ in msg.headers}
    action_header = next((h for h in RSC_ACTION_HEADERS if h in names), None)
    ctype, cparams = parse_content_type(msg.get(b"content-type"))
    is_multipart = ctype == b"multipart/form-data"

    parts: List[MultipartPart]
    meta: Dict[str, Any]
    if is_multipart:
        parts, meta = parse_multipart(body, cparams.get(b"boundary", b""))
    else:
        parts, meta = [MultipartPart(index=0, name=b"0", content=body)], {}
    # The gate is the header OR the body shape, because the other RSC
    # frameworks need not send a Next.js header. A numbered field whose
    # value decodes as JSON containing a $-reference is the body shape.
    numbered = [p for p in parts if looks_like_flight_field(p.name)]
    if action_header is None and not numbered:
        return []

    findings: List[Finding] = []
    evasion: List[str] = []
    if meta.get("lf_only"):
        evasion.append("lf_only_line_endings")
    if meta.get("preamble_bytes", 0) > 1024:
        evasion.append(f"junk_preamble_{meta['preamble_bytes']}_bytes")
    if body_info.get("framing") == "chunked":
        evasion.append("chunked_body")
    if not meta.get("closed", True) and is_multipart:
        evasion.append("no_closing_delimiter")
    if body_info.get("coded"):
        evasion.append(f"content_coding_{body_info['coded']}")

    for part in (numbered or parts):
        for charset, text in decode_every_way(part.content, part.charset):
            hits = flight_path_references(text)
            if not hits:
                continue
            markers = list(evasion)
            if charset != "utf-8":
                markers.append(f"charset_{charset}")
            if part.charset:
                markers.append(
                    "declared_charset_" +
                    part.charset.decode("latin-1", "replace")[:24])
            ev = {
                "gate": ("action_header:" + action_header.decode("ascii")
                         if action_header else "body_shape"),
                "method": msg.method.decode("latin-1"),
                "target": (msg.target or b"").decode("latin-1")[:200],
                "part_index": part.index,
                "field_name": (part.name or b"").decode("latin-1")[:32],
                "decoded_as": charset,
                "references": hits[:8],
                "reference_count": len(hits),
                "traverses_inherited": sorted(
                    {x for h in hits for x in h["traverses_inherited"]}),
                "body_length": len(body),
                "body_truncated": bool(body_info.get("truncated")),
                "evasion_markers": markers,
                "note": "A property-path reference. Measured against real "
                        "encodeReply output from six react-server-dom-webpack "
                        "releases (704 string values, including own keys "
                        "named constructor/prototype/then/__proto__): a "
                        "legitimate encoder emits none. Chunk content is "
                        "never logged - it carries the attacker's command "
                        "and whatever app data sits in the other fields. "
                        "This records an attempt, not a compromise.",
            }
            if action_header is not None:
                val = msg.get(action_header)
                if val:
                    ev["action_id"] = val.decode("latin-1")[:80]
            findings.append(make_finding("HTTP-082", ev))
            break          # one finding per part, whichever decode found it
    if not findings and (body_info.get("truncated")
                         or not body_info.get("complete", True)):
        # An RSC-gated body that did not fit the cap, or had not finished
        # arriving, was only PARTLY inspected. Counting that is the
        # difference between "nothing here" and "we did not look at all of
        # it", and a silent pass would make those two indistinguishable.
        if stats is not None:
            stats["tierf_inspect_truncated"] = (
                stats.get("tierf_inspect_truncated", 0) + 1)
    return findings


# ---------------------------------------------------------------------------
# HTTP-083 Spring4Shell (CVE-2022-22965, and CVE-2010-1622 for free).
#
# Spring's DataBinder treats a request parameter NAME as a bean property
# path, so the payload that matters is the name, not the value. A 'class'
# segment always resolves to getClass(), because no Java bean may declare a
# property called class; a path from there into module, classLoader or
# protectionDomain reaches reflective JVM internals and has no legitimate
# form. The JSP web shell in the parameter VALUES is free-form and is
# ignored entirely - and never logged, because that is also where any
# legitimate form data lives.
SPRING_INTERNAL_AFTER_CLASS = ("module", "classloader", "protectiondomain")
SPRING_CLASS_SEGMENT = "class"


def bean_property_segments(name: bytes) -> List[bytes]:
    """Split a name with Spring's property-path syntax.

    '.' nests, '[...]' indexes, and ['x'] / ["x"] quoted forms unwrap - the
    bracket forms matter because class['module'] is the same path as
    class.module to the binder and a dot-only split misses it.
    """
    segs: List[bytes] = []
    buf = bytearray()
    i = 0
    while i < len(name):
        ch = name[i:i + 1]
        if ch == b".":
            if buf:
                segs.append(bytes(buf))
                buf.clear()
            i += 1
        elif ch == b"[":
            if buf:
                segs.append(bytes(buf))
                buf.clear()
            j = name.find(b"]", i)
            if j < 0:
                i += 1
                continue
            inner = name[i + 1:j].strip(b" \t")
            if (len(inner) >= 2 and inner[:1] in (b"'", b'"')
                    and inner[-1:] == inner[:1]):
                inner = inner[1:-1]
            if inner:
                segs.append(inner)
            i = j + 1
        else:
            buf += ch
            i += 1
    if buf:
        segs.append(bytes(buf))
    return segs


def spring_path_verdict(name: bytes,
                        case_insensitive: bool = True) -> Optional[Dict[str, Any]]:
    """Classify one parameter name. Returns None when it is ordinary.

    Segment comparison is case-insensitive by default. Spring's
    CachedIntrospectionResults has a capitalise/uncapitalise fallback whose
    exact behaviour could not be measured here - Maven is not reachable from
    the build environment, so no real BeanWrapper resolved these paths. The
    README states that. Case-insensitive is the widening direction: it can
    only match more, and the negative corpus is what proves it does not
    match legitimate names.
    """
    segs = bean_property_segments(name)
    if not segs:
        return None
    norm = [sg.decode("latin-1", "replace") for sg in segs]
    cmp = [x.lower() for x in norm] if case_insensitive else norm
    target = SPRING_CLASS_SEGMENT if case_insensitive else "class"
    idx = [i for i, x in enumerate(cmp) if x == target]
    if not idx:
        return None
    first = idx[0]
    after = cmp[first + 1:]
    # Every internal segment reached after the class segment, in order. The
    # canonical chain is class.module.classLoader.resources..., so the first
    # one reached is 'module' and the useful prefix runs through the LAST of
    # them - reporting only 'class.module' would hide that it went on to
    # reach the class loader.
    internal = [(i + first + 1, sg) for i, sg in enumerate(after)
                if sg in SPRING_INTERNAL_AFTER_CLASS]
    # A class loader reached anywhere after a class segment counts, even if
    # the segment right after class is something else.
    adjacent = bool(after) and after[0] in SPRING_INTERNAL_AFTER_CLASS
    if not internal:
        return {
            "segments": norm[:12], "class_segment_index": first,
            "reached_internal": None, "internal_chain": [],
            "matched_prefix": ".".join(norm[:first + 1])[:160],
            "case_varied": any(x != x.lower() for x in norm[:first + 1]),
            "bracket_form": b"[" in name,
        }
    reached = internal[0][1]
    last_idx = internal[-1][0]
    prefix = norm[:last_idx + 1]
    return {
        "segments": norm[:12],
        "class_segment_index": first,
        "reached_internal": reached,
        "internal_chain": [sg for _, sg in internal],
        "adjacent_to_class": adjacent,
        "matched_prefix": ".".join(prefix)[:160],
        "case_varied": any(x != x.lower() for x in norm[:first + 1]),
        "bracket_form": b"[" in name,
    }


def check_spring4shell(msg: ParsedMessage, body: bytes,
                       body_info: Dict[str, Any],
                       cfg: WatchConfig = WATCH_DEFAULTS) -> List[Finding]:
    """HTTP-083 over parameter names from all three carriers."""
    sources: List[Tuple[str, bytes]] = []
    target = msg.target or b""
    q = target.find(b"?")
    if q >= 0:
        for nm in urlencoded_names(target[q + 1:]):
            sources.append(("query", nm))
    ctype, cparams = parse_content_type(msg.get(b"content-type"))
    if ctype == b"application/x-www-form-urlencoded":
        for nm in urlencoded_names(body):
            sources.append(("urlencoded", nm))
    elif ctype == b"multipart/form-data":
        parts, _ = parse_multipart(body, cparams.get(b"boundary", b""))
        for part in parts:
            if part.name:
                sources.append(("multipart", part.name))

    alerting: List[Dict[str, Any]] = []
    corroborating: List[str] = []
    evasion: List[str] = []
    for src, name in sources:
        verdict = spring_path_verdict(name, cfg.spring_case_insensitive)
        if verdict is None:
            continue
        if verdict["reached_internal"] is None:
            # R2: a path through class that stops short, e.g. class.name.
            # An attribute, never a finding of its own.
            corroborating.append(verdict["matched_prefix"])
            continue
        verdict["source"] = src
        alerting.append(verdict)
        if verdict["bracket_form"]:
            evasion.append("bracket_quoted_path")
        if verdict["case_varied"]:
            evasion.append("case_varied_segments")

    if not alerting:
        return []
    if body_info.get("framing") == "chunked":
        evasion.append("chunked_body")
    if body_info.get("coded"):
        evasion.append(f"content_coding_{body_info['coded']}")
    charset = cparams.get(b"charset")
    if charset and charset.lower() not in (b"utf-8", b"utf8"):
        evasion.append("declared_charset_" +
                       charset.decode("latin-1", "replace")[:24])
    ev = {
        "method": (msg.method or b"").decode("latin-1"),
        "target": target.split(b"?")[0].decode("latin-1")[:200],
        "sources": sorted({v["source"] for v in alerting}),
        "matches": alerting[:8],
        "match_count": len(alerting),
        "reached": sorted({v["reached_internal"] for v in alerting}),
        "paths_through_class_only": sorted(set(corroborating))[:8],
        "declared_charset": (charset or b"").decode("latin-1", "replace")[:24]
                            or None,
        "evasion_markers": sorted(set(evasion)),
        "note": "No Java bean may declare a property named 'class', so a "
                "class segment always resolves to getClass(); continuing "
                "into module, classLoader or protectionDomain reaches "
                "reflective JVM internals and has no legitimate form. "
                "Parameter VALUES are never read or logged - the web shell "
                "and any real form data both live there. An attempt is "
                "recorded; the JDK version, Spring version and deployment "
                "type that decide exploitability are not on the wire.",
    }
    return [make_finding("HTTP-083", ev)]




# ---------------------------------------------------------------------------
# HTTP-084 / HTTP-085: Apache Struts S2-045 and S2-046 (CVE-2017-5638).
#
# OGNL injection through the Jakarta multipart parser, CVSS 10.0, in KEV, and
# the entry point of the 2017 Equifax breach. Struts tracks two advisories
# under the one CVE: S2-045 puts the expression in Content-Type, S2-046 puts
# it in a multipart Content-Disposition filename.
#
# What makes this a rule rather than a signature is that THREE conditions
# have to hold at once, and all three are set by the victim's own code, not
# by the attacker. Pinned from the shipped source of the last vulnerable
# releases on 2026-11-23 rather than from a write-up:
#
#   1. Struts routes the request into the multipart parser only when the
#      Content-Type contains the literal lowercase "multipart/form-data".
#      Dispatcher.wrapRequest (struts 2.3.31):
#          String content_type = request.getContentType();
#          if (content_type != null && content_type.contains("multipart/form-data")) {
#      The value is the RAW header. It is not lowercased, trimmed or
#      normalised, and nothing sits between this read and the parser - so
#      the check is case-SENSITIVE on that exact byte sequence.
#
#   2. commons-fileupload raises the exception whose message echoes the
#      header only when the value does NOT start with "multipart/", compared
#      after lowercasing. FileItemIteratorImpl (fileupload 1.3.2):
#          if ((null == contentType)
#                  || (!contentType.toLowerCase(Locale.ENGLISH).startsWith(MULTIPART))) {
#              throw new InvalidContentTypeException(format(
#                  "the request doesn't contain a %s or %s stream, "
#                  "content type header is %s", ...));
#      MULTIPART is "multipart/", and the message carries the ORIGINAL value,
#      not the lowercased one - so the attacker's bytes reach the message.
#
#   3. Struts evaluates that message through its text lookup, which only
#      evaluates behind an opener. XWork TextParseUtil.translateVariables
#      defaults to new char[]{'$', '%'}, each followed by '{' - so "${" and
#      "%{" and nothing else.
#
# Conditions 1 and 2 pull in opposite directions, which is exactly why this
# is zero-FP. The attacker satisfies both by hiding the literal inside a
# quoted parameter of some other media type, so the type stays well-formed:
# text/plain; a="%{...multipart/form-data...}". The rule does not depend on
# grammar validity, which is why that works on it too - but whether they
# bothered is recorded, because it says something about the tooling.
#
# And the near-miss false positive is excluded by construction, not by
# tuning. A broken client template emitting
#     multipart/form-data; boundary=${boundary}
# satisfies 1 and 3 and FAILS 2, because it does start with "multipart/".
# That is the shape that would have made this rule unusable, and the
# victim's own code rules it out.
#
# Contrast with Confluence CVE-2022-26134, which stays OUT: one opener in a
# free-form path, colliding with real unrendered-template traffic. Struts
# stacks three fixed conditions. The difference is the whole gate.
STRUTS_ROUTE_LITERAL = b"multipart/form-data"    # condition 1, case-sensitive
STRUTS_FILEUPLOAD_PREFIX = b"multipart/"         # condition 2, lowercased
OGNL_OPENERS = (b"%{", b"${")                    # condition 3


def ognl_openers_in(value: bytes) -> List[str]:
    return [o.decode("ascii") for o in OGNL_OPENERS if o in value]


def media_type_grammar_valid(value: bytes) -> bool:
    """Does this value obey RFC 9110 8.3's media-type grammar?

    Only '{' and '(' appearing OUTSIDE a quoted-string are treated as
    violations - they cannot occur in a token or a parameter value, so they
    are the cheap tell that the attacker did not bother keeping the type
    well-formed. Recorded as an attribute, never as a condition: the rule
    must hold whether or not they kept it valid, because keeping it valid is
    exactly what the public tooling does.
    """
    in_quotes = False
    i = 0
    while i < len(value):
        ch = value[i:i + 1]
        if in_quotes:
            if ch == b"\\":
                i += 2
                continue
            if ch == b'"':
                in_quotes = False
        elif ch == b'"':
            in_quotes = True
        elif ch in (b"{", b"("):
            return False
        i += 1
    return True


def struts_s2045_verdict(content_type: bytes) -> Optional[Dict[str, Any]]:
    """All three conditions, or None.

    Each condition is evaluated exactly as the corresponding Java does:
    a case-sensitive byte search, a lowercased prefix test, and a literal
    opener search.
    """
    routes = STRUTS_ROUTE_LITERAL in content_type
    throws = not content_type.lower().startswith(STRUTS_FILEUPLOAD_PREFIX)
    openers = ognl_openers_in(content_type)
    if not (routes and throws and openers):
        return None
    return {
        "openers": openers,
        "grammar_valid": media_type_grammar_valid(content_type),
        "value_length": len(content_type),
        "value_digest": redact(content_type),
    }


def check_struts_s2045(msg: ParsedMessage,
                       cfg: WatchConfig = WATCH_DEFAULTS) -> List[Finding]:
    """HTTP-084 over the request's Content-Type header(s).

    Tomcat hands Struts the FIRST Content-Type: MimeHeaders.getHeader
    returns the earliest occurrence, deterministically, whatever its
    javadoc's "an arbitrary one" says. JBoss and WebLogic are also in this
    module's vantage and their choice is not pinned here, so the rule fires
    if ANY Content-Type satisfies the three conditions and records whether
    the one Tomcat would have used was among them. Alerting on the safe
    side, and saying which it was.
    """
    values = msg.get_all(b"content-type")
    if not values:
        return []
    hits = [(i, struts_s2045_verdict(v)) for i, v in enumerate(values)]
    matched = [(i, v) for i, v in hits if v is not None]
    if not matched:
        return []
    first_index, first_verdict = matched[0]
    ev = dict(first_verdict)
    ev.update({
        "advisory": "S2-045",
        "method": (msg.method or b"").decode("latin-1"),
        "target": (msg.target or b"").split(b"?")[0].decode("latin-1")[:200],
        "header_index": first_index,
        "header_count": len(values),
        "multi_header": len(values) > 1,
        "container_visible_match": first_index == 0,
        "matched_header_indexes": [i for i, _ in matched],
        "conditions": {
            "struts_routes_to_multipart_parser": True,
            "fileupload_raises_and_echoes": True,
            "struts_evaluates_behind_opener": True,
        },
        "note": "All three conditions hold at once: the Content-Type "
                "contains the literal 'multipart/form-data' so Struts routes "
                "it into the multipart parser, it does not start with "
                "'multipart/' so commons-fileupload raises the exception "
                "that echoes the header verbatim, and it carries an OGNL "
                "opener so Struts' text lookup evaluates it. All three are "
                "set by the victim's own code. A broken client template "
                "like 'multipart/form-data; boundary=${boundary}' fails the "
                "second and is excluded by construction. This records an "
                "attempt - the Struts version and parser choice are host "
                "state and are not on the wire.",
    })
    if cfg.log_attack_payload:
        ev["payload"] = values[first_index].decode("latin-1")[:512]
    return [make_finding("HTTP-084", ev)]


def check_struts_s2046(msg: ParsedMessage, body: bytes,
                       body_info: Dict[str, Any],
                       cfg: WatchConfig = WATCH_DEFAULTS) -> List[Finding]:
    """HTTP-085 over multipart Content-Disposition filenames.

    commons-fileupload rejects a filename containing a NUL and puts the
    filename in the message. Streams.checkFileName (fileupload 1.3.2):
        if (fileName != null && fileName.indexOf('\\u0000') != -1) {
            ... sb.append("\\\\0"); ...
            throw new InvalidFileNameException(fileName,
                "Invalid file name: " + sb);
    The message is a concatenation, not a format string, and everything in
    the filename other than the NUL itself passes through verbatim - so an
    opener in the filename reaches the evaluated message.

    A NUL in a multipart filename has no legitimate form, which is what
    makes this zero-FP. The opener is required too, because a NUL alone is
    a malformed upload rather than an attack on this CVE.

    NOT covered, and stated as a gap rather than stretched to fit: S2-046's
    oversized-request variant. Its OGNL also sits in the filename, but it
    arrives through JakartaStreamMultiPartRequest, which compares
    request.getContentLength() against struts.multipart.maxSize and then
    calls addFileSkippedError - no NUL involved. Covering it would mean
    "an opener in a filename plus a large body", and large uploads are
    routine while a '${' in a filename is plausible. That is not zero-FP,
    so it is out. It also needs the non-default JakartaStream parser.
    """
    ctype, cparams = parse_content_type(msg.get(b"content-type"))
    if ctype != b"multipart/form-data":
        return []
    parts, meta = parse_multipart(body, cparams.get(b"boundary", b""))
    findings: List[Finding] = []
    for part in parts:
        name = part.filename
        if not name or b"\x00" not in name:
            continue
        openers = ognl_openers_in(name)
        if not openers:
            # A NUL with no opener is a malformed upload, not this attack.
            continue
        ev = {
            "advisory": "S2-046",
            "method": (msg.method or b"").decode("latin-1"),
            "target": (msg.target or b"").split(b"?")[0].decode("latin-1")[:200],
            "part_index": part.index,
            "field_name": (part.name or b"").decode("latin-1")[:64],
            "filename_length": len(name),
            "nul_count": name.count(b"\x00"),
            "openers": openers,
            "filename_digest": redact(name),
            "body_truncated": bool(body_info.get("truncated")),
            "note": "commons-fileupload rejects a filename containing a NUL "
                    "and builds 'Invalid file name: ' + the filename, which "
                    "Struts then evaluates as OGNL. A NUL in a multipart "
                    "filename has no legitimate form. The filename text is "
                    "not logged - OGNL payloads carry commands and staging "
                    "URLs. This records an attempt, not a compromise.",
        }
        if cfg.log_attack_payload:
            ev["payload"] = name.decode("latin-1", "replace")[:512]
        findings.append(make_finding("HTTP-085", ev))
    return findings


# ---------------------------------------------------------------------------
# Tier G: content-coding validation
# ---------------------------------------------------------------------------
# HTTP-090 Node2Shell / HTTP2Shell / Brotli2Shell (CVE-2026-111497).
#
# One bug under four names: an out-of-bounds write in Google's reference
# Brotli decoder. A block-switch command for a block category that declares
# only one block type has nothing to switch to; the vulnerable decoder
# returned the same status for that case as for "needs more input", kept
# buffering, and overran (CWE-252). The fixing commit, 0ed4268a, makes
# DecodeBlockTypeAndLength return BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH
# when the block type count is one or less.
#
# That error code IS the detection. We never need the trigger's internals,
# so nothing here goes near the disclosure ceiling: a patched decoder tells
# us what a vulnerable one would have done, and the stream is simply handed
# to it with the output thrown away.
#
# ARMING. A vulnerable decoder inside the sensor would make Ragnar
# exploitable by the traffic it watches, so HTTP-090 refuses to arm unless
# the decoder it is about to use is demonstrably patched. The obvious test -
# a version floor - is WRONG IN BOTH DIRECTIONS, measured here on
# 2026-11-22 against three real compiled libraries:
#
#   upstream 1.1.0, unpatched      version 1.1.0   errstr(-17) = "INVALID"
#   upstream 1.2.1, patched        version 1.2.1   errstr(-17) = BLOCK_SWITCH
#   Ubuntu 1.1.0-2ubuntu0.1        version 1.1.0   errstr(-17) = BLOCK_SWITCH
#
# The third is a distro security update dated 2026-10-25 that backports the
# fix and keeps the old version string. A floor of 1.0.10/1.1.1/1.2.1 would
# refuse to arm on a perfectly safe sensor and run blind, and "1.1.0" on its
# own says nothing either way - the same backport trap this module already
# records for X-Powered-By version posture.
#
# So the gate is a direct probe of the COMPILED library: upstream introduced
# the -17 code in the fixing commit, replacing a reserved slot, so a library
# that names it has the fix and one that answers "INVALID" does not. The
# version is recorded as an attribute and never gates. It also means a host
# whose distro has patched libbrotli needs no vendored build at all; a
# vendored one is the remedy when the probe fails, not the default.
BROTLI_BLOCK_SWITCH_CODE = -17
BROTLI_BLOCK_SWITCH_NAME = "BLOCK_SWITCH"
BROTLI_RESULT_ERROR, BROTLI_RESULT_SUCCESS = 0, 1
BROTLI_RESULT_NEEDS_MORE_INPUT, BROTLI_RESULT_NEEDS_MORE_OUTPUT = 2, 3
BROTLI_PARAM_LARGE_WINDOW = 1
BROTLI_OUT_CHUNK = 64 * 1024          # output is discarded; this never grows
BROTLI_TIME_BUDGET = 2.0              # seconds per stream, then abandoned
BROTLI_SONAMES = ("libbrotlidec.so.1", "libbrotlidec.so", "libbrotlidec.dylib")


def brotli_patched(error_string_for_minus_17: str) -> bool:
    """Does this library carry the CVE-2026-111497 fix?

    The whole arming decision, as one pure function, because that is the
    only way to test it without an unpatched library to hand. Upstream
    introduced BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH for code -17 in the
    fixing commit, replacing a reserved slot, so naming it is the evidence
    and the version is not.
    """
    return BROTLI_BLOCK_SWITCH_NAME in (error_string_for_minus_17 or "")


class BrotliArmingError(RuntimeError):
    """The decoder available is not demonstrably patched, so HTTP-090 stays
    disarmed. Raised rather than returning a flag, because a silent pass
    here is the one outcome that must not be possible."""


class BrotliProbe:
    """A libbrotli that has passed the arming probe."""

    def __init__(self, lib: Any, path: str, version: Tuple[int, int, int]):
        self.lib = lib
        self.path = path
        self.version = version
        self.decodes = 0
        self.abandoned = 0

    @property
    def version_string(self) -> str:
        return "%d.%d.%d" % self.version

    def decode_status(self, data: bytes,
                      budget: float = BROTLI_TIME_BUDGET) -> Dict[str, Any]:
        """Stream `data` through the decoder and report only how it ended.

        The output is written into one fixed buffer that is reused every
        iteration and never read, so a 23 MB body costs 64 KiB of output
        memory. The large-window extension is refused, which holds the
        window at the RFC 7932 maximum.
        """
        lib = self.lib
        state = lib.BrotliDecoderCreateInstance(None, None, None)
        if not state:
            return {"status": "no_instance"}
        self.decodes += 1
        started = time.monotonic()
        try:
            lib.BrotliDecoderSetParameter(state, BROTLI_PARAM_LARGE_WINDOW, 0)
            inbuf = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(
                data or b"\x00")
            next_in = ctypes.cast(inbuf, ctypes.POINTER(ctypes.c_ubyte))
            avail_in = ctypes.c_size_t(len(data))
            outbuf = (ctypes.c_ubyte * BROTLI_OUT_CHUNK)()
            total_out = ctypes.c_size_t(0)
            while True:
                if time.monotonic() - started > budget:
                    self.abandoned += 1
                    return {"status": "abandoned_time_budget",
                            "seconds": round(time.monotonic() - started, 3),
                            "bytes_consumed": len(data) - avail_in.value}
                next_out = ctypes.cast(outbuf, ctypes.POINTER(ctypes.c_ubyte))
                avail_out = ctypes.c_size_t(BROTLI_OUT_CHUNK)
                res = lib.BrotliDecoderDecompressStream(
                    state, ctypes.byref(avail_in), ctypes.byref(next_in),
                    ctypes.byref(avail_out), ctypes.byref(next_out),
                    ctypes.byref(total_out))
                consumed = len(data) - avail_in.value
                if res == BROTLI_RESULT_ERROR:
                    code = int(lib.BrotliDecoderGetErrorCode(state))
                    name = lib.BrotliDecoderErrorString(code)
                    return {"status": "error", "error_code": code,
                            "error_name": (name or b"").decode("latin-1"),
                            "bytes_consumed": consumed,
                            "bytes_out": total_out.value}
                if res == BROTLI_RESULT_SUCCESS:
                    return {"status": "success", "bytes_consumed": consumed,
                            "bytes_out": total_out.value}
                if res == BROTLI_RESULT_NEEDS_MORE_INPUT:
                    # The captured body ended mid-stream. Truncation is
                    # ordinary on a tap and is never a finding.
                    return {"status": "needs_more_input",
                            "bytes_consumed": consumed,
                            "bytes_out": total_out.value}
                # NEEDS_MORE_OUTPUT: loop, reusing the same buffer.
        finally:
            lib.BrotliDecoderDestroyInstance(state)


def arm_brotli(path: Optional[str] = None) -> BrotliProbe:
    """Load a libbrotli and prove it is patched, or refuse.

    `path` pins an explicit library; without it the host's own is tried,
    which is the right default now that distros have backported the fix.
    """
    candidates = [path] if path else list(BROTLI_SONAMES)
    errors: List[str] = []
    for cand in candidates:
        if not cand:
            continue
        try:
            lib = ctypes.CDLL(cand)
        except OSError as exc:
            errors.append(f"{cand}: {exc}")
            continue
        try:
            lib.BrotliDecoderVersion.restype = ctypes.c_uint32
            lib.BrotliDecoderErrorString.restype = ctypes.c_char_p
            lib.BrotliDecoderErrorString.argtypes = [ctypes.c_int]
            lib.BrotliDecoderGetErrorCode.restype = ctypes.c_int
            lib.BrotliDecoderGetErrorCode.argtypes = [ctypes.c_void_p]
            lib.BrotliDecoderCreateInstance.restype = ctypes.c_void_p
            lib.BrotliDecoderDestroyInstance.argtypes = [ctypes.c_void_p]
            lib.BrotliDecoderSetParameter.argtypes = [
                ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
            lib.BrotliDecoderDecompressStream.restype = ctypes.c_int
            raw = int(lib.BrotliDecoderVersion())
            version = (raw >> 24, (raw >> 12) & 0xFFF, raw & 0xFFF)
            name = (lib.BrotliDecoderErrorString(
                BROTLI_BLOCK_SWITCH_CODE) or b"").decode("latin-1")
        except (AttributeError, OSError) as exc:
            errors.append(f"{cand}: missing symbol ({exc})")
            continue
        if not brotli_patched(name):
            errors.append(
                f"{cand}: version %d.%d.%d does not name the block-switch "
                f"error code (errstr(-17) = {name!r}); this decoder has not "
                f"been patched for CVE-2026-111497" % version)
            continue
        return BrotliProbe(lib, cand, version)
    raise BrotliArmingError(
        "HTTP-090 not armed: no patched libbrotli found. "
        + "; ".join(errors[:4])
        + ". A patched decoder names BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH "
          "for code -17; note a distro backport keeps its old version "
          "string, so the version is not the test.")


def has_brotli_coding(msg: ParsedMessage) -> Optional[str]:
    """Is `br` anywhere in this message's Content-Encoding coding list?"""
    for raw in msg.get_all(b"content-encoding"):
        for token in raw.split(b","):
            if token.strip().lower() == b"br":
                return raw.decode("latin-1")[:80]
    return None


def check_brotli(msg: ParsedMessage, body: bytes, body_info: Dict[str, Any],
                 probe: Optional[BrotliProbe],
                 stats: Optional[Dict[str, int]] = None) -> List[Finding]:
    """HTTP-090. Nothing happens unless a patched decoder is armed."""
    if probe is None:
        return []
    coding = has_brotli_coding(msg)
    if coding is None or not body:
        return []
    if stats is not None:
        stats["brotli_bodies"] = stats.get("brotli_bodies", 0) + 1
    result = probe.decode_status(body)
    status = result.get("status")
    if status != "error":
        # Truncation, success and a time-budget abandon are all ordinary.
        if stats is not None:
            stats["brotli_" + str(status)] = (
                stats.get("brotli_" + str(status), 0) + 1)
        return []
    if result.get("error_code") != BROTLI_BLOCK_SWITCH_CODE:
        # Every other format error is legitimate traffic or recon. The
        # published checker sends valid streams and padded malformed bodies
        # that produce other codes, and neither is pathognomonic.
        if stats is not None:
            stats["brotli_other_format_error"] = (
                stats.get("brotli_other_format_error", 0) + 1)
        return []
    ev = {
        "direction": "request" if msg.kind == "request" else "response",
        "method": (msg.method or b"").decode("latin-1") or None,
        "target": (msg.target or b"").decode("latin-1")[:200] or None,
        "status": msg.status,
        "content_encoding": coding,
        "bytes_consumed_at_error": result.get("bytes_consumed"),
        "body_length_observed": len(body),
        "body_complete": bool(body_info.get("complete")),
        "body_truncated_at_cap": bool(body_info.get("truncated")),
        "framing": body_info.get("framing"),
        "decoder_error": result.get("error_name"),
        "decoder_version": probe.version_string,
        "decoder_path": probe.path,
        "body_digest": redact(body),
        "note": "A patched decoder rejected this stream as a block switch "
                "for a category declaring one block type - the exact "
                "condition an unpatched decoder mistook for 'needs more "
                "input' before overrunning. No encoder produces it. The "
                "decompressed output is discarded and never logged. This "
                "records an attack on the wire, not a compromised host.",
    }
    return [make_finding("HTTP-090", ev)]


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
                          cfg: WatchConfig = WATCH_DEFAULTS,
                          stats: Optional[Dict[str, int]] = None,
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
        # --- Tier E ---
        findings.extend(check_shellshock(msg, cfg))
        findings.extend(check_java4shell(msg))
        findings.extend(check_struts_s2045(msg, cfg))
        # --- Tier F ---
        # The decoded body is built once and shared: dechunking a 23 MB
        # body twice would be the kind of cost that gets a rule disabled.
        decoded, body_info = request_body(msg, raw, cfg.body_cap)
        findings.extend(check_react2shell(msg, decoded, body_info, cfg,
                                          stats))
        findings.extend(check_spring4shell(msg, decoded, body_info, cfg))
        findings.extend(check_struts_s2046(msg, decoded, body_info, cfg))
        # --- Tier G ---
        findings.extend(check_brotli(msg, decoded, body_info, cfg.brotli,
                                     stats))
    elif cfg.brotli is not None and cfg.brotli_scan_responses:
        # Outbound fetches: a client library decoding a br response is the
        # other half of this CVE. Most outbound traffic is TLS, so this is
        # off unless an operator turns it on.
        decoded, body_info = request_body(msg, raw, cfg.body_cap)
        findings.extend(check_brotli(msg, decoded, body_info, cfg.brotli,
                                     stats))

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

    def __init__(self, flow_id: str, synced: bool = True,
                 cfg: WatchConfig = WATCH_DEFAULTS,
                 php_cfg: Optional[PhpCookieConfig] = None):
        self.flow_id = flow_id
        self.synced = synced
        if php_cfg is not None:
            cfg = replace(cfg, php=php_cfg)
        self.cfg = cfg
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

        # --- Tier E over decoded h2 request headers ---
        # _finish_block has already run HPACK, so these two rules get h2c
        # coverage for free. The body rules (Tier F, Tier G) do not: DATA
        # frames reach no body sink, which the README states as a gap.
        if from_client:
            findings.extend(check_shellshock_fields(
                headers, obs_fold=False, cfg=self.cfg, flow_id=self.flow_id))
            findings.extend(check_java4shell_fields(
                headers, flow_id=self.flow_id))

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

        # --- HTTP-048 PHP session-cookie leak, response direction ---
        # _finish_block decodes server header blocks with dec_server, so the
        # fields are already here; only the rules above happened to be
        # client-side. A mid-stream join leaves the decoder unsynced and
        # _finish_block returns before this point - a stated blind spot, not
        # a silent one.
        if not from_client:
            findings.extend(php_cookie_findings(
                php_cookie_hits_fields(headers, self.cfg.php),
                flow_id=self.flow_id, http_version=b"2"))

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
# How often feed() reaps idle state. Nothing called expire() until this was
# wired in: a sensor that runs for weeks under systemd was accumulating a
# Flow for every connection it had ever seen, and the HTTP-048 dedup table
# would have joined it. Reaping on a timer inside feed() means every entry
# point gets it - live capture, a pcap read and a replay alike.
EXPIRE_INTERVAL = 30.0


@dataclass
class Direction:
    buf: bytearray = field(default_factory=bytearray)
    anchored: bool = False
    first_byte_at: float = 0.0
    bytes_seen: int = 0
    head_analysed: bool = False
    # HTTP-048 state for the head currently in buf: how many hits have
    # already been reported, and the buffer length at the last scan.
    php_reported: int = 0
    php_scanned_len: int = -1


class Flow:
    """One TCP flow, classified by its first bytes rather than by port."""

    def __init__(self, flow_id: str, src: str, dst: str,
                 service: Optional[str] = None, now: float = 0.0,
                 port: int = 0):
        self.flow_id = flow_id
        self.src = src
        self.dst = dst
        self.service = service
        # dissect_packet normalises src to the client and dst to the server,
        # so (dst, port) is the server identity HTTP-048 dedups on.
        self.port = port
        self.upload_progress_seen = False
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
                 slow_tracker: Optional[SlowTracker] = None,
                 cfg: WatchConfig = WATCH_DEFAULTS,
                 php_cfg: Optional[PhpCookieConfig] = None):
        self.tcp_ports = tuple(tcp_ports)
        self.flows: Dict[str, Flow] = {}
        self.slow = slow_tracker or SlowTracker()
        # php_cfg is kept as a convenience for callers that only want to set
        # the HTTP-048 threshold; it folds into the one config object.
        if php_cfg is not None:
            cfg = replace(cfg, php=php_cfg)
        self.cfg = cfg
        self.leak_dedup = LeakDedup()
        self.attack_dedup = LeakDedup(ATTACK_DEDUP_WINDOW)
        self._last_expire = 0.0
        self.stats: Dict[str, int] = {
            "flows": 0, "http1_messages": 0, "h2_frames": 0, "findings": 0,
            "leaks_suppressed": 0, "tierf_inspect_truncated": 0,
            "attacks_suppressed": 0,
        }

    # -- lifecycle --------------------------------------------------------
    def _flow(self, flow_id: str, src: str, dst: str, dport: int,
              now: float) -> Flow:
        fl = self.flows.get(flow_id)
        if fl is None:
            fl = Flow(flow_id, src, dst, SERVICE_PORTS.get(dport), now,
                      port=dport)
            self.flows[flow_id] = fl
            self.stats["flows"] += 1
        fl.last_seen = now
        return fl

    def expire(self, now: float) -> None:
        dead = [k for k, f in self.flows.items()
                if now - f.last_seen > FLOW_IDLE_TIMEOUT]
        for k in dead:
            del self.flows[k]
        self.leak_dedup.expire(now)
        self.attack_dedup.expire(now)

    # -- the feed ---------------------------------------------------------
    def feed(self, flow_id: str, src: str, dst: str, dport: int,
             payload: bytes, from_client: bool,
             now: Optional[float] = None) -> List[Finding]:
        now = time.time() if now is None else now
        if not payload:
            return []
        if now - self._last_expire > EXPIRE_INTERVAL:
            self._last_expire = now
            self.expire(now)
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
                fl.h2 = H2ConnectionState(flow_id, synced=True,
                                          cfg=self.cfg)
                del d.buf[:len(H2_PREFACE)]

        if fl.protocol == "h2c":
            out = self._feed_h2(fl, d, from_client, now)
        else:
            out = self._feed_http1(fl, d, from_client, now)
        return self._dedup_attacks(self._dedup_leaks(out, fl, now), fl, now)

    def _dedup_attacks(self, findings: List[Finding], fl: Flow,
                       now: float) -> List[Finding]:
        """Rate-limit each attack-class code per client/server pair."""
        if not any(f.code in ATTACK_CODES for f in findings):
            return findings
        kept: List[Finding] = []
        for f in findings:
            if f.code not in ATTACK_CODES:
                kept.append(f)
                continue
            allowed, suppressed = self.attack_dedup.allow(
                (f"{f.code}|{fl.src}|{fl.dst}", fl.port), now)
            if not allowed:
                self.stats["attacks_suppressed"] += 1
                continue
            if suppressed:
                f.evidence["suppressed_since_last"] = suppressed
                f.evidence["dedup_window_seconds"] = self.attack_dedup.window
            kept.append(f)
        self.stats["findings"] -= len(findings) - len(kept)
        return kept

    def _dedup_leaks(self, findings: List[Finding], fl: Flow,
                     now: float) -> List[Finding]:
        """Rate-limit HTTP-048 to one per server address:port per window."""
        if not any(f.code == "HTTP-048" for f in findings):
            return findings
        key = (fl.dst, fl.port)
        kept: List[Finding] = []
        for f in findings:
            if f.code != "HTTP-048":
                kept.append(f)
                continue
            allowed, suppressed = self.leak_dedup.allow(key, now)
            if not allowed:
                self.stats["leaks_suppressed"] += 1
                continue
            if suppressed:
                f.evidence["suppressed_since_last"] = suppressed
                f.evidence["dedup_window_seconds"] = self.leak_dedup.window
            kept.append(f)
        self.stats["findings"] -= len(findings) - len(kept)
        return kept

    def _php_scan(self, fl: Flow, d: Direction, section: bytes,
                  http_version: Optional[bytes],
                  partial: bool = False) -> List[Finding]:
        """Run R1 over a response header section and report what is new.

        Called on the head still arriving as well as on the complete one, so
        it reports only hits beyond those already reported for this head.
        """
        hits = php_cookie_hits(section, self.cfg.php)
        new = hits[d.php_reported:]
        d.php_reported = len(hits)
        if not new:
            return []
        return php_cookie_findings(
            new, flow_id=fl.flow_id, http_version=http_version,
            upload_progress=fl.upload_progress_seen, partial=partial)

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
                # --- HTTP-048 on a head that can no longer complete ---
                # A leak larger than MAX_HEADER_SECTION never produces a
                # terminated header section, so a rule that waited for one
                # would miss exactly the largest leaks. Below that cap the
                # head still has every chance of completing, and the
                # complete-head scan measures the real length instead of a
                # floor - so the early scan deliberately starts only once
                # the head is already past the cap. The scan is throttled to
                # once per PHP_SCAN_GROWTH bytes and stops at
                # PHP_SCAN_CEILING, which bounds the work on a head that
                # never terminates at all.
                if (not from_client
                        and MAX_HEADER_SECTION < len(raw) <= PHP_SCAN_CEILING
                        and len(raw) - d.php_scanned_len >= PHP_SCAN_GROWTH):
                    d.php_scanned_len = len(raw)
                    findings.extend(
                        self._php_scan(fl, d, raw, None, partial=True))
                if len(d.buf) > HEAD_BUFFER_CEILING:
                    # This head will never complete. Stop growing the buffer,
                    # keeping the prefix so nothing is re-anchored partway
                    # through a stream; the flow leaves on the idle timer.
                    del d.buf[HEAD_BUFFER_CEILING:]
                break
            msg = parse_message(raw, kind)
            if msg is None or not msg.complete:
                break
            self.stats["http1_messages"] += 1

            if from_client and not fl.upload_progress_seen:
                # Annotation source for HTTP-048, never a gate: PHP's
                # upload-progress field must precede the file part, so the
                # head of the body is where it is if it is anywhere.
                ctype = (msg.get(b"content-type") or b"").lower()
                if ctype.startswith(b"multipart/form-data"):
                    window = raw[msg.body_offset:
                                 msg.body_offset + UPLOAD_PROGRESS_WINDOW]
                    if PHP_UPLOAD_PROGRESS_FIELD in window:
                        fl.upload_progress_seen = True

            if not from_client:
                findings.extend(self._php_scan(
                    fl, d, raw[:msg.body_offset], msg.version))
                banner = msg.get(b"server")
                if banner:
                    fl.server_banner = banner
                # h2c upgrade: 101 hands this flow to the Tier D parser
                if msg.status == 101 and b"h2c" in (
                        msg.get(b"upgrade") or b"").lower():
                    consumed = msg.body_offset
                    del d.buf[:consumed]
                    fl.protocol = "h2c"
                    fl.h2 = H2ConnectionState(fl.flow_id, synced=True,
                                              cfg=self.cfg)
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
                        server_banner=fl.server_banner, cfg=self.cfg,
                        stats=self.stats))
                break

            if not d.head_analysed:
                findings.extend(analyse_http1_message(
                    msg, raw, service=fl.service,
                    server_banner=fl.server_banner, cfg=self.cfg,
                        stats=self.stats))
            d.head_analysed = False
            d.php_reported = 0
            d.php_scanned_len = -1
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


def php_cfg_from_args(args) -> PhpCookieConfig:
    return php_cookie_config(
        threshold=getattr(args, "php_cookie_max", PHP_COOKIE_MAX),
        extra_names=getattr(args, "php_session_cookie_name", None) or ())


def cfg_from_args(args) -> Tuple[WatchConfig, List[Dict[str, Any]]]:
    """Build the config, and the health records that must be emitted.

    Arming failure is returned as a record rather than swallowed: a Tier G
    that quietly did not arm is the one outcome that must not be possible,
    because it looks exactly like a segment with no attacks on it.
    """
    notices: List[Dict[str, Any]] = []
    probe = None
    if getattr(args, "brotli", False) or getattr(args, "brotli_lib", None):
        try:
            probe = arm_brotli(getattr(args, "brotli_lib", None))
            notices.append({
                "module": MODULE, "version": __version__, "type": "notice",
                "status": "ok", "tier": "G", "code": "HTTP-090",
                "armed": True, "decoder_path": probe.path,
                "decoder_version": probe.version_string,
                "reason": "libbrotli names the block-switch error code, so "
                          "it carries the CVE-2026-111497 fix. The version "
                          "is recorded but is not the test: a distro "
                          "backport keeps its old version string.",
            })
        except BrotliArmingError as exc:
            notices.append({
                "module": MODULE, "version": __version__, "type": "notice",
                "status": "error", "tier": "G", "code": "HTTP-090",
                "armed": False, "reason": str(exc),
            })
    cfg = WatchConfig(
        php=php_cfg_from_args(args),
        log_attack_payload=bool(getattr(args, "log_attack_payload", False)),
        body_cap=int(getattr(args, "body_cap", WATCH_DEFAULTS.body_cap)),
        internal_cidrs=tuple(getattr(args, "internal_cidr", None) or ()),
        brotli=probe,
        brotli_scan_responses=bool(
            getattr(args, "brotli_scan_responses", False)),
    )
    return cfg, notices


def run_live(args) -> int:
    _cfg, _notices = cfg_from_args(args)
    try:
        from scapy.all import sniff, IP, IPv6, TCP  # noqa: F401
    except ImportError:
        print("scapy is required for live capture; use --selftest or "
              "--replay otherwise", file=sys.stderr)
        return 2

    from scapy.all import IP as _IP, IPv6 as _IPv6, TCP as _TCP

    watch = HttpWatch(tcp_ports=args.tcp_ports, cfg=_cfg)
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

    # systemd stops the unit with SIGTERM. Without this the run summary -
    # packet counts, finding counts, how many duplicate leaks were
    # suppressed - is lost on every normal stop, which is exactly when an
    # operator wants it.
    def _stop(signum, frame):
        raise KeyboardInterrupt
    try:
        import signal
        signal.signal(signal.SIGTERM, _stop)
    except (ImportError, ValueError):
        pass

    emit({"module": MODULE, "version": __version__, "type": "start",
          "status": "ok", "bpf": bpf, "iface": args.iface,
          "tcp_ports": list(args.tcp_ports)})
    for notice in _notices:
        emit(notice)
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
    _cfg, _notices = cfg_from_args(args)
    try:
        from scapy.all import sniff
    except ImportError:
        print("scapy is required to read a capture file", file=sys.stderr)
        return 2

    watch = HttpWatch(tcp_ports=args.tcp_ports, cfg=_cfg)
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
    for notice in _notices:
        emit(notice)
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
    p.add_argument("--php-cookie-max", type=int, default=PHP_COOKIE_MAX,
                   metavar="BYTES",
                   help=f"HTTP-048 threshold (default {PHP_COOKIE_MAX}, the "
                        f"RFC 6265 6.1 figure). Values at or below the "
                        f"measured {PHP_COOKIE_NATIVE_CEILING}-byte native "
                        f"generator ceiling are refused")
    p.add_argument("--php-session-cookie-name", action="append", default=None,
                   metavar="NAME",
                   help="additional PHP session cookie name for HTTP-048 "
                        "(a host with session.name changed); repeatable")
    p.add_argument("--log-attack-payload", action="store_true",
                   help="include the attacker-authored value on HTTP-080. "
                        "Off by default: the text is the attacker's own, but "
                        "it carries URLs, tokens and staging hosts an "
                        "operator may not want in syslog")
    p.add_argument("--body-cap", type=int, default=WATCH_DEFAULTS.body_cap,
                   metavar="BYTES",
                   help=f"how much decoded request body the Tier F rules "
                        f"inspect (default {WATCH_DEFAULTS.body_cap})")
    p.add_argument("--internal-cidr", action="append", default=None,
                   metavar="CIDR",
                   help="raise the priority of a Tier E finding whose source "
                        "is inside this range; never gates a finding; "
                        "repeatable")
    p.add_argument("--brotli", action="store_true",
                   help="arm HTTP-090. Refuses unless the decoder it would "
                        "use demonstrably carries the CVE-2026-111497 fix")
    p.add_argument("--brotli-lib", default=None, metavar="PATH",
                   help="pin the libbrotlidec HTTP-090 uses instead of the "
                        "host's own. Only needed when the host library "
                        "fails the arming probe")
    p.add_argument("--brotli-scan-responses", action="store_true",
                   help="also validate br-coded RESPONSE bodies (outbound "
                        "client fetches). Off by default: almost all "
                        "outbound traffic is TLS and invisible here")
    p.add_argument("--print-bpf", action="store_true",
                   help="print the generated capture filter and exit")
    p.add_argument("--registry", action="store_true",
                   help="print the finding code registry and exit")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    try:
        php_cfg_from_args(args)
    except ValueError as exc:
        print(f"httpwatch: {exc}", file=sys.stderr)
        return 2

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
