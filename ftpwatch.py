#!/usr/bin/env python3
"""
ftpwatch — FTP Watch, a passive Ragnar module.

Passive, dual-stack detector for three ProFTPD CVEs observable in the
cleartext FTP control channel:

  CVE-2015-3306   mod_copy SITE CPFR/CPTO without authentication   (CVSS v2 10.0, no v3 assessment)
  CVE-2019-12815  mod_copy ignores <Limit READ/WRITE>, authed/anon  (CVSS v3 9.8, description disputed)
  CVE-2023-51713  make_ftp_cmd one-byte OOB read, quoted verb       (CVSS v3 7.5, A:H only)

ftpwatch is a ProFTPD detector under a protocol name. It does NOT claim
coverage of vsftpd, Pure-FTPd or any other FTP implementation.

Never transmits. Reads a live interface (scapy, lazily imported) or a
pcap/pcapng file. Every finding carries an `af` field and RFC 3986
bracketed IPv6 endpoints.
"""
from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import re
import struct
import sys
import time

MODULE = "ftpwatch"
_LAST_SELFTEST = []      # [(check name, passed)] from the most recent self_test()
VERSION = "0.1.0-dev"
MASK32 = 0xFFFFFFFF

# --------------------------------------------------------------------------
# Finding registry
# --------------------------------------------------------------------------
CVE_3306, CVE_12815, CVE_51713 = "CVE-2015-3306", "CVE-2019-12815", "CVE-2023-51713"

CODES = {
    # Class A — mod_copy (ungated; attack context established by session state)
    "FTP-001": ("MODCOPY_PREAUTH_ATTEMPT", "A", "high", [CVE_3306]),
    "FTP-002": ("MODCOPY_PREAUTH_SOURCE_ACCEPTED", "A", "critical", [CVE_3306]),
    "FTP-003": ("MODCOPY_PREAUTH_COPY_COMPLETED", "A", "critical", [CVE_3306]),
    "FTP-004": ("MODCOPY_SENSITIVE_SOURCE", "A", "critical", [CVE_3306, CVE_12815]),
    "FTP-005": ("MODCOPY_DANGEROUS_DESTINATION", "A", "critical", [CVE_3306, CVE_12815]),
    "FTP-006": ("MODCOPY_ADVERTISED", "A", "warn", [CVE_3306, CVE_12815]),
    "FTP-007": ("MODCOPY_ANONYMOUS_ATTEMPT", "A", "high", [CVE_12815]),
    "FTP-008": ("MODCOPY_ANONYMOUS_COPY_COMPLETED", "A", "critical", [CVE_12815]),
    # Class B — banner / version (LESSON T: a banner cannot establish patch state)
    "FTP-010": ("PROFTPD_VERSION_DISCLOSED", "B", "info", []),
    "FTP-011": ("PROFTPD_RANGE_CVE_2015_3306", "B", "notice", [CVE_3306]),
    "FTP-012": ("PROFTPD_RANGE_CVE_2019_12815", "B", "notice", [CVE_12815]),
    "FTP-013": ("PROFTPD_RANGE_CVE_2023_51713", "B", "notice", [CVE_51713]),
    "FTP-014": ("PROFTPD_VERSION_SUPPRESSED", "B", "info", []),
    # Class C — quoted command verb (ungated; see README "Why FTP-020 is not gated")
    "FTP-020": ("QUOTED_COMMAND_VERB", "C", "high", [CVE_51713]),
    "FTP-021": ("SESSION_TERMINATED_AFTER_QUOTED_VERB", "C", "high", [CVE_51713]),
}

# --------------------------------------------------------------------------
# ProFTPD version handling
#   ordering: 1.3.5rc3 < 1.3.5 < 1.3.5a < 1.3.5e < 1.3.6rc1 < 1.3.6 < 1.3.6a
# --------------------------------------------------------------------------
_VER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:(rc)(\d+)|([a-z]))?$")


def parse_version(s):
    """Return a sortable tuple for a ProFTPD version string, or None."""
    m = _VER_RE.match(s or "")
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if m.group(4):                       # release candidate sorts BELOW the release
        return (major, minor, patch, 0, int(m.group(5)))
    if m.group(6):                       # maintenance letter sorts ABOVE the release
        return (major, minor, patch, 1, ord(m.group(6)) - ord("a") + 1)
    return (major, minor, patch, 1, 0)


V = parse_version
# Ranges are [lower, upper) over parse_version tuples. Sources in the README.
RANGES = {
    # mod_copy absent in 1.3.3 (Debian: squeeze not-affected); fixed 1.3.5a (NEWS-1.3.5a, Bug 4169)
    CVE_3306: (V("1.3.4rc1"), V("1.3.5a")),
    # researcher advisory: 1.3.6 affected, 1.3.6a fixed; NEVER fixed on the 1.3.5 branch (PR #816)
    CVE_12815: (V("1.3.4rc1"), V("1.3.6a")),
    # fixed 1.3.8a (commit 97bbe683); no lower bound
    CVE_51713: ((0, 0, 0, 0, 0), V("1.3.8a")),
}
STRANDED_1_3_5 = (V("1.3.5a"), V("1.3.6rc1"))   # fixed for 3306, never for 12815


def in_range(ver, cve):
    lo, hi = RANGES[cve]
    return ver is not None and lo <= ver < hi


_BANNER_RE = re.compile(r"\bProFTPD\b(?:\s+(\d+\.\d+\.\d+(?:rc\d+|[a-z])?)(?=[\s)]|$))?")


def parse_banner(text):
    """-> (is_proftpd, version_string_or_None)."""
    m = _BANNER_RE.search(text or "")
    if not m:
        return False, None
    return True, m.group(1)


# --------------------------------------------------------------------------
# Path classification for Class A escalations
# --------------------------------------------------------------------------
_SENSITIVE_SRC = re.compile(
    r"^/proc/(self|\d+)/|^/etc/(passwd|shadow|group|gshadow|sudoers)$|^/etc/proftpd"
    r"|/\.ssh/|(^|/)id_(rsa|dsa|ecdsa|ed25519)$|^/root/")
_DANGEROUS_DST = [
    ("executable_extension", re.compile(
        r"\.(php[3-8]?|phtml|phar|jspx?|aspx?|cgi|pl|py|sh)$", re.I)),
    ("webroot", re.compile(
        r"^/(var|srv)/www/|/public_html/|/htdocs/|/usr/share/nginx/|/cgi-bin/")),
    ("ssh_authorized_keys", re.compile(r"/\.ssh/authorized_keys2?$")),
    ("scheduled_execution", re.compile(r"^/etc/cron|^/var/spool/cron/")),
    ("shell_startup", re.compile(r"(^|/)\.(bashrc|profile|bash_profile|zshrc)$")),
]
ANON_NAMES = frozenset({"anonymous", "ftp"})


def classify_destination(path):
    return [name for name, rx in _DANGEROUS_DST if rx.search(path or "")]


# --------------------------------------------------------------------------
# Endpoint rendering (LESSON AE part 2)
# --------------------------------------------------------------------------
def render_ep(af, ip, port):
    return f"[{ip}]:{port}" if af == "ipv6" else f"{ip}:{port}"


def split_ep(s):
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
        return host, int(port)
    host, _, port = s.rpartition(":")
    return host, int(port)


# --------------------------------------------------------------------------
# L2/L3/L4 decode — raw bytes only (no dissector class dispatch, LESSON AD/AG)
# --------------------------------------------------------------------------
DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LOOP, DLT_SLL, DLT_SLL2 = 0, 1, 101, 108, 113, 276
_RAW_ALIASES = {12, 14, 101}
_VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
# IPv6 extension headers with the generic (len+1)*8 layout
_EH_GENERIC = {0, 43, 60, 135, 139, 140}
EH_MAX = 16


class FragTable:
    """Bounded IPv4/IPv6 fragment reassembly. Overlap policy: first-received bytes win."""

    def __init__(self, timeout=30.0, max_keys=1024, max_frags=64):
        self.t, self.timeout, self.max_keys, self.max_frags = {}, timeout, max_keys, max_frags
        self.reassembled = 0

    def add(self, key, off, data, more, now):
        self._expire(now)
        ent = self.t.get(key)
        if ent is None:
            if len(self.t) >= self.max_keys:
                return None
            ent = self.t[key] = {"frags": [], "total": None, "ts": now}
        if len(ent["frags"]) >= self.max_frags or off + len(data) > 65535:
            del self.t[key]
            return None
        ent["frags"].append((off, data))
        if not more:
            ent["total"] = off + len(data)
        total = ent["total"]
        if total is None:
            return None
        buf, have = bytearray(total), bytearray(total)
        for o, d in ent["frags"]:
            for i, b in enumerate(d):
                p = o + i
                if p < total and not have[p]:
                    buf[p], have[p] = b, 1
        if not all(have):
            return None
        del self.t[key]
        self.reassembled += 1
        return bytes(buf)

    def _expire(self, now):
        for k in [k for k, v in self.t.items() if now - v["ts"] > self.timeout]:
            del self.t[k]


def _tcp(buf):
    if len(buf) < 20:
        return None
    sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", buf[:14])
    hl = (off_flags >> 12) * 4
    if hl < 20 or hl > len(buf):
        return None
    return sport, dport, seq, ack, off_flags & 0x1FF, buf[hl:]


def _ipv6_walk(nh, data, src, dst, frags, now, stats, depth=0):
    """Walk the extension-header chain; returns TCP bytes or None."""
    while depth < EH_MAX:
        if nh == 6:
            return data
        if nh in _EH_GENERIC:
            if len(data) < 2:
                return None
            hl = (data[1] + 1) * 8
            nh, data = data[0], data[hl:]
        elif nh == 51:                                   # AH: (len+2)*4
            if len(data) < 2:
                return None
            hl = (data[1] + 2) * 4
            nh, data = data[0], data[hl:]
        elif nh == 44:                                   # Fragment
            if len(data) < 8:
                return None
            fnh = data[0]
            w, ident = struct.unpack("!HI", data[2:8])
            out = frags.add((6, src, dst, ident), (w >> 3) * 8, data[8:], bool(w & 1), now)
            if out is None:
                return None
            nh, data = fnh, out
        else:
            return None                                  # 59 no-next-header, or not TCP
        depth += 1
        stats["eh_walked"] += 1
    return None


def decode(linktype, frame, now, frags, stats):
    """-> (af, src, dst, tcp_tuple) or None."""
    if linktype == DLT_EN10MB:
        if len(frame) < 14:
            return None
        et, p = struct.unpack("!H", frame[12:14])[0], 14
        tags = 0
        while et in _VLAN_TPIDS and tags < 3 and len(frame) >= p + 4:
            et, p, tags = struct.unpack("!H", frame[p + 2:p + 4])[0], p + 4, tags + 1
        l3 = frame[p:]
    elif linktype == DLT_SLL:
        if len(frame) < 16:
            return None
        et, l3 = struct.unpack("!H", frame[14:16])[0], frame[16:]
    elif linktype == DLT_SLL2:
        if len(frame) < 20:
            return None
        et, l3 = struct.unpack("!H", frame[0:2])[0], frame[20:]
    elif linktype in _RAW_ALIASES:
        if not frame:
            return None
        et, l3 = {4: 0x0800, 6: 0x86DD}.get(frame[0] >> 4, 0), frame
    elif linktype in (DLT_NULL, DLT_LOOP):
        if len(frame) < 4:
            return None
        fam = struct.unpack("<I" if linktype == DLT_NULL else "!I", frame[:4])[0]
        et, l3 = (0x0800 if fam == 2 else 0x86DD if fam in (10, 24, 28, 30) else 0), frame[4:]
    else:
        return None

    if et == 0x0800:
        if len(l3) < 20 or l3[0] >> 4 != 4:
            return None
        ihl = (l3[0] & 0xF) * 4
        tot = struct.unpack("!H", l3[2:4])[0]
        if ihl < 20 or tot < ihl:
            return None
        l3 = l3[:tot]
        ident, ff = struct.unpack("!HH", l3[4:8])
        proto, src, dst = l3[9], str(ipaddress.IPv4Address(l3[12:16])), str(ipaddress.IPv4Address(l3[16:20]))
        if proto != 6:
            return None
        payload = l3[ihl:]
        if ff & 0x3FFF:                                  # MF or non-zero offset
            payload = frags.add((4, src, dst, 6, ident), (ff & 0x1FFF) * 8, payload, bool(ff & 0x2000), now)
            if payload is None:
                return None
        t = _tcp(payload)
        return ("ipv4", src, dst, t) if t else None

    if et == 0x86DD:
        if len(l3) < 40 or l3[0] >> 4 != 6:
            return None
        plen, nh = struct.unpack("!H", l3[4:6])[0], l3[6]
        src, dst = str(ipaddress.IPv6Address(l3[8:24])), str(ipaddress.IPv6Address(l3[24:40]))
        data = _ipv6_walk(nh, l3[40:40 + plen], src, dst, frags, now, stats)
        if data is None:
            return None
        t = _tcp(data)
        return ("ipv6", src, dst, t) if t else None
    return None


# --------------------------------------------------------------------------
# TCP reassembly (LESSON O: anchor tolerantly; never trust the first segment)
# --------------------------------------------------------------------------
def sdiff(a, b):
    d = (a - b) & MASK32
    return d - 0x100000000 if d >= 0x80000000 else d


GAP = object()


class DirStream:
    MAX_SEGS, MAX_BYTES, UNANCHORED_HOLD = 64, 262144, 4

    def __init__(self, anchor_rx):
        self.next, self.pending, self.pbytes = None, {}, 0
        self.from_syn, self.anchor_rx = False, anchor_rx

    def set_isn(self, nxt):
        if self.next is None:
            self.next, self.from_syn = nxt & MASK32, True

    def push(self, seq, data):
        if not data:
            return []
        if self.next is not None and sdiff(seq, self.next) > (1 << 20):
            return []
        if seq in self.pending and len(self.pending[seq]) >= len(data):
            return []
        if seq in self.pending:
            self.pbytes -= len(self.pending[seq])
        self.pending[seq] = data
        self.pbytes += len(data)
        out = []
        if self.next is None:
            ref = next(iter(self.pending))
            low = min(self.pending, key=lambda s: sdiff(s, ref))
            if self.anchor_rx.match(self.pending[low]) or len(self.pending) >= self.UNANCHORED_HOLD:
                self.next = low
            else:
                return []
        while True:
            hit = None
            for s, d in self.pending.items():
                if sdiff(s, self.next) <= 0:
                    hit = s
                    break
            if hit is None:
                break
            d = self.pending.pop(hit)
            self.pbytes -= len(d)
            end = sdiff(hit, self.next) + len(d)
            if end > 0:
                out.append(d[len(d) - end:])
                self.next = (self.next + end) & MASK32
        if self.pending and (len(self.pending) > self.MAX_SEGS or self.pbytes > self.MAX_BYTES):
            self.next = min(self.pending, key=lambda s: sdiff(s, self.next))
            out.append(GAP)
            out.extend(self.push_drain())
        return out

    def push_drain(self):
        out = []
        while True:
            hit = next((s for s in self.pending if sdiff(s, self.next) <= 0), None)
            if hit is None:
                return out
            d = self.pending.pop(hit)
            self.pbytes -= len(d)
            end = sdiff(hit, self.next) + len(d)
            if end > 0:
                out.append(d[len(d) - end:])
                self.next = (self.next + end) & MASK32


# --------------------------------------------------------------------------
# Line assembly. Client side mirrors ProFTPD's telnet handling so that
# IAC-interleaved commands ("SI<IAC NOP>TE CPFR") parse as the server sees them.
# --------------------------------------------------------------------------
IAC, WILL, WONT, DO, DONT = 255, 251, 252, 253, 254
MAX_LINE = 8192


class LineAssembler:
    def __init__(self, telnet):
        self.buf, self.telnet, self.st = bytearray(), telnet, 0
        self.truncated = False

    def reset(self):
        self.buf, self.st, self.truncated = bytearray(), 0, False

    def feed(self, data):
        lines = []
        for b in data:
            if self.telnet:
                if self.st == 1:                               # after IAC
                    if b == IAC:
                        self.st = 0
                    elif b in (WILL, WONT, DO, DONT):
                        self.st = 2
                        continue
                    else:
                        self.st = 0
                        continue
                elif self.st == 2:                             # option byte
                    self.st = 0
                    continue
                elif b == IAC:
                    self.st = 1
                    continue
            if b == 0x0A:
                raw = bytes(self.buf)
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                lines.append((raw, self.truncated))
                self.buf, self.truncated = bytearray(), False
            elif len(self.buf) < MAX_LINE:
                self.buf.append(b)
            else:
                self.truncated = True
        return lines


# --------------------------------------------------------------------------
# Session state machine
# --------------------------------------------------------------------------
_REPLY_RE = re.compile(rb"^(\d{3})([ -])(.*)$", re.S)


class Session:
    def __init__(self, key):
        self.af, self.sip, self.sport, self.cip, self.cport = key
        self.cli = DirStream(re.compile(rb'[A-Za-z"\xff]'))
        self.srv = DirStream(re.compile(rb"\d{3}[ -]"))
        self.cla, self.sla = LineAssembler(True), LineAssembler(False)
        self.queue = []                 # outstanding client commands
        self.multi = None               # (code, [lines]) for a multi-line reply
        self.greeting_done = False
        self.logged_in = False
        self.auth_unresolved = 0
        self.anonymous = False
        self.user = None
        self.trust_broken = False
        self.encrypted = False
        self.closed = False
        self.last = 0.0
        self.emitted = set()

    @property
    def server(self):
        return render_ep(self.af, self.sip, self.sport)

    @property
    def client(self):
        return render_ep(self.af, self.cip, self.cport)

    def preauth_certain(self):
        return (not self.trust_broken and self.cli.from_syn
                and self.logged_in is False and self.auth_unresolved == 0)


class FtpWatch:
    def __init__(self, ports=(21,), emit=None, idle=600.0, max_sessions=4096):
        self.ports = frozenset(ports)
        self.emit_cb = emit or (lambda f: None)
        self.idle, self.max_sessions = idle, max_sessions
        self.sessions = {}
        self.frags = FragTable()
        self.server_seen = {}           # server ep -> set(codes) for once-per-server findings
        self.findings = []
        self.stats = {k: 0 for k in (
            "frames", "ftp_segments", "sessions", "findings", "eh_walked", "gaps",
            "tls_sessions", "copy_auth_unknown", "port_gate_rejects")}

    # ---- emission -------------------------------------------------------
    def _finding(self, code, sess, message, detail=None, confidence="high", dedupe=None, per_server=False):
        name, cls, sev, cves = CODES[code]
        if per_server:
            seen = self.server_seen.setdefault(sess.server, set())
            if (code, dedupe) in seen:
                return
            seen.add((code, dedupe))
        else:
            k = (code, dedupe)
            if k in sess.emitted:
                return
            sess.emitted.add(k)
        f = {
            "ts": sess.last, "module": MODULE, "code": code, "name": name,
            "class": cls, "severity": sev, "confidence": confidence, "cves": list(cves),
            "af": sess.af, "server": sess.server, "client": sess.client,
            "message": message, "detail": detail or {},
        }
        self.findings.append(f)
        self.stats["findings"] += 1
        self.emit_cb(f)

    # ---- ingest ---------------------------------------------------------
    def feed_frame(self, linktype, frame, ts):
        self.stats["frames"] += 1
        d = decode(linktype, frame, ts, self.frags, self.stats)
        if d is None:
            return
        af, src, dst, (sport, dport, seq, ack, flags, payload) = d
        # Software port gate — load-bearing for IPv6, admitted by a bare `ip6` BPF term
        if dport in self.ports and sport not in self.ports:
            server_is_dst = True
        elif sport in self.ports and dport not in self.ports:
            server_is_dst = False
        elif dport in self.ports:          # both in set: guess, documented
            server_is_dst = True
        else:
            self.stats["port_gate_rejects"] += 1
            return
        self.stats["ftp_segments"] += 1
        key = (af, dst, dport, src, sport) if server_is_dst else (af, src, sport, dst, dport)
        sess = self.sessions.get(key)
        if sess is None:
            self._evict(ts)
            sess = self.sessions[key] = Session(key)
            self.stats["sessions"] += 1
        sess.last = ts
        syn, fin, rst, ackf = flags & 0x02, flags & 0x01, flags & 0x04, flags & 0x10
        from_client = server_is_dst
        stream = sess.cli if from_client else sess.srv
        if syn:
            stream.set_isn(seq + 1)
            if not from_client and ackf:
                sess.cli.set_isn(ack)
            seq = seq + 1
        if sess.encrypted:
            return
        for chunk in stream.push(seq & MASK32, payload):
            if chunk is GAP:
                self.stats["gaps"] += 1
                self._gap(sess, from_client)
                continue
            asm = sess.cla if from_client else sess.sla
            for line, trunc in asm.feed(chunk):
                if from_client:
                    self._client_line(sess, line, trunc)
                else:
                    self._server_line(sess, line)
                if sess.encrypted:
                    break
            if sess.encrypted:
                break
        if (fin or rst) and not from_client:
            self._server_teardown(sess, "RST" if rst else "FIN")

    def _gap(self, sess, from_client):
        (sess.cla if from_client else sess.sla).reset()
        sess.trust_broken = True
        sess.multi = None
        sess.queue.clear()

    def _evict(self, now):
        stale = [k for k, s in self.sessions.items() if now - s.last > self.idle]
        for k in stale:
            del self.sessions[k]
        if len(self.sessions) >= self.max_sessions:
            oldest = min(self.sessions, key=lambda k: self.sessions[k].last)
            del self.sessions[oldest]

    # ---- client side ----------------------------------------------------
    def _client_line(self, sess, raw, truncated):
        text = raw.decode("latin-1")
        stripped = text.lstrip(" \t")
        quoted = stripped.startswith('"')
        parts = stripped.split(None, 1)
        verb = parts[0].upper() if parts and not quoted else ""
        arg = parts[1] if len(parts) > 1 else ""
        entry = {"verb": verb, "arg": arg, "quoted": quoted, "sub": None, "path": None, "ctx": None}

        if quoted:
            self._finding("FTP-020", sess,
                          "Command line opens with a double quote. No FTP verb has this form; it is the "
                          "input shape that drives ProFTPD make_ftp_cmd into quote mode on the verb and "
                          "produces the one-byte out-of-bounds read (CVE-2023-51713).",
                          {"line_prefix": text[:64], "leading_whitespace": text != stripped,
                           "truncated": truncated, "banner_verdict": self._banner_verdict(sess, CVE_51713),
                           "note": ("leading whitespace is rejected before tokenizing on 1.3.8, so that "
                                    "variant cannot reach the bug there") if text != stripped else None},
                          dedupe=text[:64])

        if verb in ("USER", "PASS", "ACCT"):
            sess.auth_unresolved += 1
            if verb == "USER":
                sess.user = arg.strip()
                if sess.user.lower() in ANON_NAMES:
                    sess.anonymous = True
        elif verb == "SITE":
            sp = arg.split(None, 1)
            sub = sp[0].upper() if sp else ""
            entry["sub"] = sub
            if sub in ("CPFR", "CPTO"):
                entry["path"] = sp[1] if len(sp) > 1 else ""
                entry["ctx"] = self._copy_context(sess)
                self._copy_command(sess, entry)
        elif verb == "AUTH":
            entry["sub"] = arg.strip().upper()
        sess.queue.append(entry)

    def _copy_context(self, sess):
        if sess.preauth_certain():
            return "preauth"
        if sess.logged_in is True and sess.anonymous and not sess.trust_broken:
            return "anonymous"
        if sess.logged_in is True:
            return "authenticated"
        return "unknown"

    def _copy_command(self, sess, e):
        ctx, sub, path = e["ctx"], e["sub"], e["path"]
        d = {"subcommand": sub, "path": path, "auth_context": ctx, "user": sess.user}
        if ctx == "preauth":
            self._finding("FTP-001", sess,
                          f"SITE {sub} issued before any login on a session observed from its SYN. "
                          "mod_copy commands have no legitimate pre-authentication use.",
                          d, dedupe=(sub, path))
        elif ctx == "anonymous":
            self._finding("FTP-007", sess,
                          f"SITE {sub} issued by an anonymous login. CVE-2019-12815: mod_copy ignores "
                          "<Limit READ/WRITE>, so anonymous users can copy files they cannot write.",
                          d, dedupe=(sub, path))
        else:
            if ctx == "unknown":
                self.stats["copy_auth_unknown"] += 1
            return
        if sub == "CPFR" and _SENSITIVE_SRC.search(path):
            self._finding("FTP-004", sess, f"mod_copy source is a sensitive path ({path}) in an "
                          f"{ctx} context.", d, dedupe=path)
        if sub == "CPTO":
            reasons = classify_destination(path)
            if reasons:
                self._finding("FTP-005", sess, f"mod_copy destination {path} is a code-execution or "
                              f"persistence location ({', '.join(reasons)}) in an {ctx} context.",
                              dict(d, reasons=reasons), dedupe=path)

    # ---- server side ----------------------------------------------------
    def _server_line(self, sess, raw):
        m = _REPLY_RE.match(raw)
        if sess.multi is not None:
            code, body = sess.multi
            body.append(raw.decode("latin-1"))
            if m and m.group(1).decode() == code and m.group(2) == b" ":
                sess.multi = None
                self._reply(sess, int(code), body)
            return
        if not m:
            return
        code, sep, rest = m.group(1).decode(), m.group(2), m.group(3).decode("latin-1")
        if sep == b"-":
            sess.multi = (code, [rest])
        else:
            self._reply(sess, int(code), [rest])

    def _reply(self, sess, code, lines):
        text = "\n".join(lines)
        if not sess.greeting_done and not sess.queue and code in (120, 220):
            if code == 220:
                sess.greeting_done = True
                self._banner(sess, text)
            return
        if 100 <= code < 200:
            return
        sess.greeting_done = True
        if not sess.queue:
            return
        e = sess.queue.pop(0)
        v = e["verb"]
        if v in ("USER", "PASS", "ACCT"):
            sess.auth_unresolved = max(0, sess.auth_unresolved - 1)
            if "anonymous" in text.lower() and code in (230, 331):
                sess.anonymous = True
            if code == 230:
                sess.logged_in = True
        elif v == "REIN" and code == 220 and not sess.trust_broken:
            sess.logged_in, sess.anonymous, sess.user = False, False, None
        elif v == "AUTH" and code == 234:
            sess.encrypted = True
            self.stats["tls_sessions"] += 1
        elif v == "SITE" and e["sub"] in ("CPFR", "CPTO"):
            self._copy_reply(sess, e, code, text)
        elif code == 214 and ((v == "SITE" and e["sub"] == "HELP")
                              or (v == "HELP" and e["arg"].strip().upper() == "SITE")):
            toks = set(re.findall(r"[A-Z]{3,}", text.upper()))
            if {"CPFR", "CPTO"} <= toks:
                self._finding("FTP-006", sess,
                              "SITE HELP advertises CPFR/CPTO: mod_copy is loaded and CopyEngine is on. "
                              "On 1.3.5a-1.3.5e and 1.3.6 this is the only passive signal of exposure to "
                              "CVE-2019-12815; the mitigation is `CopyEngine off` or removing mod_copy.",
                              {"banner_verdict": self._banner_verdict(sess, CVE_12815)}, per_server=True)

    def _copy_reply(self, sess, e, code, text):
        ctx, sub = e["ctx"], e["sub"]
        d = {"subcommand": sub, "path": e["path"], "reply": code, "auth_context": ctx}
        if ctx == "preauth":
            if sub == "CPFR" and code == 350:
                self._finding("FTP-002", sess,
                              "Server accepted a pre-authentication SITE CPFR (350). This is the "
                              "vulnerable behaviour of CVE-2015-3306 observed directly; a fixed server "
                              "answers 530. Server is confirmed vulnerable regardless of its banner.",
                              d, dedupe=e["path"])
            elif sub == "CPTO" and 200 <= code < 300:
                self._finding("FTP-003", sess, "Pre-authentication mod_copy copy COMPLETED "
                              f"({code}): {e['path']} was written on the server.", d, dedupe=e["path"])
        elif ctx == "anonymous" and sub == "CPTO" and 200 <= code < 300:
            self._finding("FTP-008", sess, "Anonymous mod_copy copy COMPLETED "
                          f"({code}): {e['path']} was written on the server.", d, dedupe=e["path"])

    def _server_teardown(self, sess, how):
        if sess.closed:
            return
        sess.closed = True
        for e in sess.queue:
            if e["quoted"]:
                self._finding("FTP-021", sess,
                              f"Server tore the session down ({how}) with no reply and no 421 after a "
                              "quoted-verb command. Consistent with the ProFTPD session process "
                              "crashing on CVE-2023-51713; a 421 or any reply would have removed it from the queue; each session is a separate child, so the "
                              "listener survives.", {"teardown": how}, confidence="medium")
                return

    # ---- banner ---------------------------------------------------------
    def _banner(self, sess, text):
        sess.banner = text
        is_pro, vs = parse_banner(text)
        if not is_pro:
            return
        sess.proftpd = True
        if vs is None:
            sess.version = None
            self._finding("FTP-014", sess, "ProFTPD identified but the version is suppressed "
                          "(ServerIdent). Class B range checks are silent; Class A and C are unaffected.",
                          {"banner": text[:160]}, per_server=True)
            return
        ver = parse_version(vs)
        sess.version = ver
        self._finding("FTP-010", sess, f"ProFTPD {vs} disclosed in the 220 banner.",
                      {"version": vs, "banner": text[:160]}, dedupe=vs, per_server=True)
        caveat = ("Banner version cannot establish patch state: distributions backport fixes without "
                  "changing it. Treat as a lead to verify, not a confirmed vulnerability.")
        for code, cve in (("FTP-011", CVE_3306), ("FTP-012", CVE_12815), ("FTP-013", CVE_51713)):
            if in_range(ver, cve):
                extra = ""
                if cve == CVE_12815 and STRANDED_1_3_5[0] <= ver < STRANDED_1_3_5[1]:
                    extra = (" No upstream fix exists on the 1.3.5 branch; the only mitigation is "
                             "`CopyEngine off` or removing mod_copy (see FTP-006).")
                self._finding(code, sess, f"ProFTPD {vs} is inside the affected range for {cve}. "
                              + caveat + extra, {"version": vs}, confidence="low", dedupe=vs, per_server=True)

    def _banner_verdict(self, sess, cve):
        if not getattr(sess, "greeting_done", False) or not hasattr(sess, "banner"):
            return "unseen"
        if not getattr(sess, "proftpd", False):
            return "not_proftpd"
        if getattr(sess, "version", None) is None:
            return "suppressed"
        return "in_range" if in_range(sess.version, cve) else "outside_range"


# --------------------------------------------------------------------------
# Capture / replay
# --------------------------------------------------------------------------
def build_bpf(ports):
    """LESSON AE: only a BARE `ip6` term admits IPv6 behind extension headers.
    The fragment clause admits IPv4 non-first fragments, which carry no TCP header
    and are dropped by any `port` primitive."""
    p = " or ".join(f"port {int(x)}" for x in sorted(ports))
    return f"(tcp and ({p})) or (ip[6:2] & 0x3fff != 0) or ip6"


_SCAPY_DLT = {"Ether": DLT_EN10MB, "CookedLinux": DLT_SLL, "CookedLinuxV2": DLT_SLL2,
              "IP": DLT_RAW, "IPv6": DLT_RAW, "Loopback": DLT_NULL}


def run_capture(watch, iface, bpf, timeout):
    from scapy.all import sniff  # the only scapy import in the module

    def cb(pkt):
        lt = _SCAPY_DLT.get(pkt.__class__.__name__)
        if lt is None:
            return
        try:
            watch.feed_frame(lt, bytes(pkt), float(pkt.time))
        except Exception as ex:                          # never let one frame kill the sensor
            print(json.dumps({"module": MODULE, "event": "frame_error", "error": repr(ex)}),
                  file=sys.stderr)

    sniff(iface=iface, filter=bpf, prn=cb, store=False, timeout=timeout)


def iter_pcap(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            return
        magic = head[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
        else:
            yield from _iter_pcapng(path)
            return
        lt = struct.unpack(end + "I", head[20:24])[0] & 0x0FFFFFFF
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                return
            s, frac, incl, _ = struct.unpack(end + "IIII", rh)
            data = fh.read(incl)
            if len(data) < incl:
                return
            yield lt, data, s + frac / (1e9 if nano else 1e6)


def _iter_pcapng(path):
    from scapy.utils import PcapNgReader
    for pkt in PcapNgReader(path):
        lt = _SCAPY_DLT.get(pkt.__class__.__name__)
        if lt is not None:
            yield lt, bytes(pkt), float(pkt.time)


# --------------------------------------------------------------------------
# Self-test (bytes-only fixtures: nothing constructed skips the decode path)
# --------------------------------------------------------------------------
def _csum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack(f"!{len(b)//2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class _Net:
    """Test frame builder. Emits real Ethernet frames with valid checksums."""

    def __init__(self, af, cip, sip, cport=40000, sport=21, eh=(), vlan=False):
        self.af, self.cip, self.sip, self.cport, self.sport = af, cip, sip, cport, sport
        self.eh, self.vlan = eh, vlan
        self.cseq, self.sseq = 1000, 5000

    def _tcp(self, src, dst, sp, dp, seq, ack, flags, data):
        hdr = struct.pack("!HHIIHHHH", sp, dp, seq & MASK32, ack & MASK32, (5 << 12) | flags, 65535, 0, 0)
        if self.af == "ipv4":
            ph = ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack("!BBH", 0, 6, len(hdr) + len(data))
        else:
            ph = ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + struct.pack("!IxxxB", len(hdr) + len(data), 6)
        c = _csum(ph + hdr + data)
        return hdr[:16] + struct.pack("!H", c) + hdr[18:] + data

    def _l3(self, src, dst, tcp, ident=1):
        if self.af == "ipv4":
            h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ident, 0, 64, 6, 0,
                            ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
            h = h[:10] + struct.pack("!H", _csum(h)) + h[12:]
            return 0x0800, h + tcp
        body, nh = tcp, 6
        for t in reversed(self.eh):
            ext = bytes([nh, 0]) + b"\x01\x04\x00\x00\x00\x00"   # PadN, 8 bytes total
            body, nh = ext + body, t
        h = struct.pack("!IHBB16s16s", 6 << 28, len(body), nh, 64,
                        ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed)
        return 0x86DD, h + body

    def _eth(self, et, l3):
        tag = struct.pack("!HH", 0x8100, 100) if self.vlan else b""
        return b"\x02" * 6 + b"\x04" * 6 + tag + struct.pack("!H", et) + l3

    def seg(self, from_client, data=b"", flags=0x18, seq=None):
        src, dst, sp, dp = ((self.cip, self.sip, self.cport, self.sport) if from_client
                            else (self.sip, self.cip, self.sport, self.cport))
        s = seq if seq is not None else (self.cseq if from_client else self.sseq)
        a = self.sseq if from_client else self.cseq
        et, l3 = self._l3(src, dst, self._tcp(src, dst, sp, dp, s, a, flags, data))
        if seq is None:
            if from_client:
                self.cseq += len(data) + (1 if flags & 0x03 else 0)
            else:
                self.sseq += len(data) + (1 if flags & 0x03 else 0)
        return self._eth(et, l3)

    def handshake(self):
        return [self.seg(True, flags=0x02), self.seg(False, flags=0x12), self.seg(True, flags=0x10)]

    def fragments(self, from_client, data, cut):
        """Carry one TCP segment in two IP fragments."""
        src, dst, sp, dp = ((self.cip, self.sip, self.cport, self.sport) if from_client
                            else (self.sip, self.cip, self.sport, self.cport))
        tcp = self._tcp(src, dst, sp, dp, self.cseq, self.sseq, 0x18, data)
        self.cseq += len(data)
        a, b = tcp[:cut], tcp[cut:]
        out = []
        if self.af == "ipv4":
            for off, part, more in ((0, a, 1), (cut, b, 0)):
                h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(part), 77, (more << 13) | (off // 8), 64, 6, 0,
                                ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
                h = h[:10] + struct.pack("!H", _csum(h)) + h[12:]
                out.append(self._eth(0x0800, h + part))
        else:
            for off, part, more in ((0, a, 1), (cut, b, 0)):
                fh = struct.pack("!BBHI", 6, 0, ((off // 8) << 3) | more, 0xABCD)
                body = fh + part
                h = struct.pack("!IHBB16s16s", 6 << 28, len(body), 44, 64,
                                ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed)
                out.append(self._eth(0x86DD, h + body))
        return out


AFS = (("ipv4", "192.0.2.10", "192.0.2.21"), ("ipv6", "2001:db8::10", "2001:db8::21"))


def _run(frames, **kw):
    w = FtpWatch(**kw)
    for i, f in enumerate(frames):
        w.feed_frame(DLT_EN10MB, f, 1000.0 + i)
    return w


def _codes(w):
    return [f["code"] for f in w.findings]


def _script(n, steps):
    """steps: list of (from_client, bytes)."""
    out = n.handshake()
    for fc, data in steps:
        out.append(n.seg(fc, data))
    return out


def self_test(verbose=False):
    fails, count, seen = [], [0], set()
    results = _LAST_SELFTEST
    del results[:]

    def check(name, cond):
        count[0] += 1
        results.append((name, bool(cond)))
        if not cond:
            fails.append(name)
        if verbose:
            print(("ok   " if cond else "FAIL ") + name)

    def cov(w):
        seen.update(_codes(w))
        return w

    # ---- version ordering and ranges (PARSER TRAP) -------------------
    check("rc below release", V("1.3.5rc3") < V("1.3.5"))
    check("letter above release", V("1.3.8a") > V("1.3.8"))
    check("1.3.6a below 1.3.7rc1", V("1.3.6a") < V("1.3.7rc1"))
    check("garbage rejected", parse_version("1.3") is None and parse_version("1.3.8.b") is None)
    for vs, c, exp in [("1.3.3", CVE_3306, False), ("1.3.3c", CVE_3306, False), ("1.3.4rc1", CVE_3306, True),
                       ("1.3.4", CVE_3306, True), ("1.3.5rc3", CVE_3306, True), ("1.3.5", CVE_3306, True),
                       ("1.3.5a", CVE_3306, False), ("1.3.5a", CVE_12815, True), ("1.3.5e", CVE_12815, True),
                       ("1.3.6rc4", CVE_12815, True), ("1.3.6", CVE_12815, True), ("1.3.6a", CVE_12815, False),
                       ("1.3.7rc1", CVE_12815, False), ("1.3.8", CVE_51713, True), ("1.3.8a", CVE_51713, False),
                       ("1.3.8b", CVE_51713, False), ("1.3.9rc1", CVE_51713, False), ("1.3.1", CVE_51713, True)]:
        check(f"range {vs} {c} -> {exp}", in_range(V(vs), c) is exp)

    # ---- banner parsing ----------------------------------------------
    check("banner debian", parse_banner("ProFTPD 1.3.5rc3 Server (Debian) [::ffff:80.150.216.115]") == (True, "1.3.5rc3"))
    check("banner suppressed", parse_banner("ProFTPD Server (ProFTPD Default Installation) [x]") == (True, None))
    check("banner vsftpd", parse_banner("(vsFTPd 3.0.3)") == (False, None))
    check("banner git suffix", parse_banner("ProFTPD 1.3.9rc1 (git) Server") == (True, "1.3.9rc1"))

    for af, cip, sip in AFS:
        tag = f"[{af}]"
        # ---- full pre-auth mod_copy chain on a vulnerable server -------
        n = _Net(af, cip, sip)
        w = cov(_run(_script(n, [
            (False, b"220 ProFTPD 1.3.5 Server (Debian) [x]\r\n"),
            (True, b"SITE CPFR /proc/self/cmdline\r\n"),
            (False, b"350 File or directory exists, ready for destination name\r\n"),
            (True, b"SITE CPTO /var/www/html/x.php\r\n"),
            (False, b"250 Copy successful\r\n")])))
        c = set(_codes(w))
        check(f"{tag} preauth chain codes", {"FTP-001", "FTP-002", "FTP-003", "FTP-004", "FTP-005",
                                              "FTP-010", "FTP-011", "FTP-012", "FTP-013"} <= c)
        check(f"{tag} af field", all(f["af"] == af for f in w.findings))
        ep = w.findings[0]["server"]
        check(f"{tag} endpoint round-trips", split_ep(ep) == (sip, 21))
        check(f"{tag} v6 bracketed", (ep.startswith("[")) == (af == "ipv6"))
        check(f"{tag} class B low confidence", all(f["confidence"] == "low"
                                                   for f in w.findings if f["code"] in ("FTP-011", "FTP-012", "FTP-013")))

        # ---- patched server answers 530: attempt only ------------------
        n = _Net(af, cip, sip)
        w = cov(_run(_script(n, [
            (False, b"220 ProFTPD 1.3.6a Server\r\n"),
            (True, b"SITE CPFR /etc/passwd\r\n"),
            (False, b"530 Please login with USER and PASS\r\n")])))
        c = _codes(w)
        check(f"{tag} patched: attempt fires", "FTP-001" in c and "FTP-004" in c)
        check(f"{tag} patched: no accept", "FTP-002" not in c and "FTP-003" not in c)
        check(f"{tag} 1.3.6a outside all mod_copy ranges", not {"FTP-011", "FTP-012"} & set(c))

        # ---- legitimate authenticated copy: silent ---------------------
        n = _Net(af, cip, sip)
        w = _run(_script(n, [
            (False, b"220 ProFTPD Server\r\n"), (True, b"USER alice\r\n"), (False, b"331 Password required\r\n"),
            (True, b"PASS s3cret\r\n"), (False, b"230 User alice logged in\r\n"),
            (True, b"SITE CPFR /home/alice/a.txt\r\n"), (False, b"350 ready\r\n"),
            (True, b"SITE CPTO /home/alice/b.txt\r\n"), (False, b"250 Copy successful\r\n")]))
        check(f"{tag} authed user copy silent", not {"FTP-001", "FTP-002", "FTP-003", "FTP-007", "FTP-008"} & set(_codes(w)))
        cov(w)

        # ---- anonymous copy --------------------------------------------
        n = _Net(af, cip, sip)
        w = cov(_run(_script(n, [
            (False, b"220 ProFTPD 1.3.5e Server\r\n"), (True, b"USER anonymous\r\n"),
            (False, b"331 Anonymous login ok, send your complete email address\r\n"),
            (True, b"PASS a@b.c\r\n"), (False, b"230 Anonymous access granted\r\n"),
            (True, b"SITE CPFR /pub/readme\r\n"), (False, b"350 ready\r\n"),
            (True, b"SITE CPTO /pub/incoming/shell.php\r\n"), (False, b"250 Copy successful\r\n")])))
        c = _codes(w)
        check(f"{tag} anon attempt", "FTP-007" in c)
        check(f"{tag} anon completed", "FTP-008" in c)
        check(f"{tag} anon is not preauth", "FTP-001" not in c)
        stranded = [f for f in w.findings if f["code"] == "FTP-012"]
        check(f"{tag} 1.3.5e stranded-branch note", stranded and "No upstream fix" in stranded[0]["message"])
        check(f"{tag} 1.3.5e not in 3306 range", "FTP-011" not in c)

        # ---- mid-stream join: auth unknown -> suppressed ---------------
        n = _Net(af, cip, sip)
        frames = [n.seg(True, b"SITE CPFR /etc/passwd\r\n"), n.seg(False, b"350 ready\r\n")]
        w = _run(frames)
        check(f"{tag} midstream suppressed", not {"FTP-001", "FTP-002"} & set(_codes(w)))
        check(f"{tag} midstream counted", w.stats["copy_auth_unknown"] == 1)

        # ---- client-only capture, no USER sent: still pre-auth certain -
        n = _Net(af, cip, sip)
        frames = [n.seg(True, flags=0x02), n.seg(True, b"SITE CPFR /etc/shadow\r\n")]
        w = _run(frames)
        check(f"{tag} one-sided capture still preauth", "FTP-001" in _codes(w))

        # ---- quoted verb: fire, crash-correlate, and the FP pins -------
        n = _Net(af, cip, sip)
        frames = _script(n, [(False, b"220 ProFTPD 1.3.8 Server\r\n"), (True, b'"\\a\\b\\c\\d\r\n')])
        frames.append(n.seg(False, flags=0x14))                     # RST, no reply
        w = cov(_run(frames))
        c = _codes(w)
        check(f"{tag} quoted verb fires", "FTP-020" in c)
        check(f"{tag} crash correlates", "FTP-021" in c)
        f20 = next(f for f in w.findings if f["code"] == "FTP-020")
        check(f"{tag} quoted verb verdict in_range", f20["detail"]["banner_verdict"] == "in_range")

        n = _Net(af, cip, sip)
        frames = _script(n, [(False, b"220 ProFTPD 1.3.8 Server\r\n"), (True, b'"x\r\n'),
                             (False, b"500 not understood\r\n")])
        frames.append(n.seg(False, flags=0x11))
        w = _run(frames)
        check(f"{tag} answered quoted verb: no crash finding", "FTP-021" not in _codes(w))

        n = _Net(af, cip, sip)
        frames = _script(n, [(False, b"220 ProFTPD 1.3.8 Server\r\n"), (True, b'"x\r\n'),
                             (False, b"421 Timeout\r\n")])
        frames.append(n.seg(False, flags=0x11))
        w = _run(frames)
        check(f"{tag} 421 suppresses crash finding", "FTP-021" not in _codes(w))

        n = _Net(af, cip, sip)
        w = _run(_script(n, [(False, b"220 ProFTPD 1.3.8 Server\r\n"),
                             (True, b'STOR my "file".txt\r\n'), (True, b'CWD "quoted dir"\r\n'),
                             (True, b'RETR a\\b\\"c\r\n')]))
        check(f"{tag} quotes in ARGUMENTS never fire", "FTP-020" not in _codes(w))

        # ---- telnet IAC interleaving is stripped like the server does --
        n = _Net(af, cip, sip)
        w = _run(_script(n, [(False, b"220 x\r\n"), (True, b"SI\xff\xf1TE CP\xff\xfb\x01FR /etc/passwd\r\n")]))
        check(f"{tag} IAC-interleaved CPFR detected", "FTP-001" in _codes(w))

        # ---- SITE HELP exposure ----------------------------------------
        n = _Net(af, cip, sip)
        w = cov(_run(_script(n, [
            (False, b"220 ProFTPD 1.3.5b Server\r\n"), (True, b"SITE HELP\r\n"),
            (False, b"214-The following SITE commands are recognized (* =>'s unimplemented)\r\n"
                    b" CHMOD CHGRP CPFR CPTO HELP\r\n214 Direct comments to root@x\r\n")])))
        check(f"{tag} SITE HELP advertises mod_copy", "FTP-006" in _codes(w))
        n = _Net(af, cip, sip)
        w = _run(_script(n, [(False, b"220 x\r\n"), (True, b"SITE HELP\r\n"),
                             (False, b"214-Recognized:\r\n CHMOD HELP\r\n214 end\r\n")]))
        check(f"{tag} SITE HELP without mod_copy silent", "FTP-006" not in _codes(w))

        # ---- suppressed version ----------------------------------------
        n = _Net(af, cip, sip)
        w = cov(_run(_script(n, [(False, b"220 ProFTPD Server (Default) [x]\r\n")])))
        check(f"{tag} suppressed banner", _codes(w) == ["FTP-014"])

        # ---- AUTH TLS: stop parsing -----------------------------------
        n = _Net(af, cip, sip)
        w = _run(_script(n, [(False, b"220 ProFTPD 1.3.5 Server\r\n"), (True, b"AUTH TLS\r\n"),
                             (False, b"234 AUTH TLS successful\r\n"), (True, b"SITE CPFR /etc/passwd\r\n")]))
        check(f"{tag} post-AUTH TLS bytes ignored", "FTP-001" not in _codes(w))
        check(f"{tag} tls counted", w.stats["tls_sessions"] == 1)

        # ---- out-of-order delivery after SYN ---------------------------
        n = _Net(af, cip, sip)
        hs = n.handshake()
        g = n.seg(False, b"220 ProFTPD 1.3.5 Server\r\n")
        p1, p2, p3 = n.seg(True, b"SITE "), n.seg(True, b"CPFR /etc/"), n.seg(True, b"passwd\r\n")
        w = _run(hs + [g, p3, p2, p1])
        check(f"{tag} reversed segments reassembled", "FTP-004" in _codes(w))

        # ---- retransmission: no duplicate findings ---------------------
        n = _Net(af, cip, sip)
        hs = n.handshake()
        seq0 = n.cseq
        a = n.seg(True, b"SITE CPFR /etc/passwd\r\n")
        dup = n.seg(True, b"SITE CPFR /etc/passwd\r\n", seq=seq0)
        w = _run(hs + [a, dup])
        check(f"{tag} retransmit dedupe", _codes(w).count("FTP-001") == 1)

        # ---- IP fragmentation -------------------------------------------
        n = _Net(af, cip, sip)
        frames = n.handshake() + n.fragments(True, b"SITE CPFR /etc/shadow\r\n", 24)
        w = _run(frames)
        check(f"{tag} fragmented TCP reassembled", "FTP-004" in _codes(w))
        check(f"{tag} frag counter", w.frags.reassembled == 1)

        # ---- VLAN tag ----------------------------------------------------
        n = _Net(af, cip, sip, vlan=True)
        w = _run(n.handshake() + [n.seg(True, b"SITE CPFR /etc/passwd\r\n")])
        check(f"{tag} 802.1Q tagged frame", "FTP-001" in _codes(w))

        # ---- role by port, not by first speaker (LESSON AC) ------------
        n = _Net(af, cip, sip)
        frames = [n.seg(False, b"220 ProFTPD 1.3.5 Server\r\n")]      # server speaks first, no SYN
        w = _run(frames)
        check(f"{tag} server role by port", w.findings and w.findings[0]["server"] == render_ep(af, sip, 21))

        # ---- non-FTP traffic rejected by the software gate -------------
        n = _Net(af, cip, sip, sport=80)
        w = _run(n.handshake() + [n.seg(True, b"SITE CPFR /etc/passwd\r\n")])
        check(f"{tag} software port gate", not w.findings and w.stats["port_gate_rejects"] > 0)

        # ---- custom port ------------------------------------------------
        n = _Net(af, cip, sip, sport=2121)
        w = _run(n.handshake() + [n.seg(True, b"SITE CPFR /etc/passwd\r\n")], ports=(21, 2121))
        check(f"{tag} custom port", "FTP-001" in _codes(w))

        # ---- reassembly overflow breaks trust (guard needs violating traffic, LESSON Z)
        n = _Net(af, cip, sip)
        hs = n.handshake()
        base = n.cseq
        held = [n.seg(True, b"x" * 8, seq=base + 100 + 8 * i) for i in range(70)]   # hole at base..base+100
        n.cseq = base + 100 + 8 * 70
        w = _run(hs + held + [n.seg(True, b"\r\nSITE CPFR /etc/passwd\r\n")])
        check(f"{tag} gap breaks trust -> suppressed", "FTP-001" not in _codes(w) and w.stats["gaps"] >= 1)

        # ---- client-only capture WITH login attempt: auth unresolved -> suppressed
        n = _Net(af, cip, sip)
        frames = [n.seg(True, flags=0x02), n.seg(True, b"USER admin\r\n"), n.seg(True, b"PASS x\r\n"),
                  n.seg(True, b"SITE CPFR /etc/shadow\r\n")]
        w = _run(frames)
        check(f"{tag} unresolved login suppresses preauth claim", "FTP-001" not in _codes(w))

        # ---- SYN-ACK seen, client SYN lost: client stream still anchored from handshake
        n = _Net(af, cip, sip)
        n.seg(True, flags=0x02)                                   # built, never delivered
        frames = [n.seg(False, flags=0x12), n.seg(False, b"220 x\r\n"),
                  n.seg(True, b"SITE CPFR /etc/passwd\r\n")]
        w = _run(frames)
        check(f"{tag} SYN-ACK alone establishes preauth", "FTP-001" in _codes(w))

        # ---- quoted verb, then CLIENT teardown: not a server crash ----
        n = _Net(af, cip, sip)
        frames = _script(n, [(False, b"220 x\r\n"), (True, b'"x\r\n')])
        frames.append(n.seg(True, flags=0x11))
        w = _run(frames)
        check(f"{tag} client FIN is not a crash", "FTP-021" not in _codes(w))

        # ---- partial overlap must be trimmed, not duplicated ----------
        n = _Net(af, cip, sip)
        hs = n.handshake()
        s0 = n.cseq
        a = n.seg(True, b"SITE CP", seq=s0)
        b = n.seg(True, b"CPFR /etc/passwd\r\n", seq=s0 + 5)
        w = _run(hs + [a, b])
        check(f"{tag} overlapping segment trimmed", "FTP-001" in _codes(w))

        # ---- shorter same-seq retransmit must not replace a held longer one
        n = _Net(af, cip, sip)
        hs = n.handshake()
        s0 = n.cseq
        p1 = n.seg(True, b"SITE ", seq=s0)
        p2 = n.seg(True, b"CPFR /etc/passwd\r\n", seq=s0 + 5)
        p2short = n.seg(True, b"CPFR", seq=s0 + 5)
        w = _run(hs + [p2, p2short, p1])
        check(f"{tag} held segment not clobbered by shorter retransmit", "FTP-001" in _codes(w))

        # ---- REIN returns the session to pre-auth ----------------------
        n = _Net(af, cip, sip)
        w = _run(_script(n, [
            (False, b"220 x\r\n"), (True, b"USER alice\r\n"), (False, b"230 ok\r\n"),
            (True, b"REIN\r\n"), (False, b"220 Service ready for new user\r\n"),
            (True, b"SITE CPFR /etc/passwd\r\n")]))
        check(f"{tag} REIN restores preauth", "FTP-001" in _codes(w))

        # ---- 1xx preliminary replies must not pop the queue ------------
        n = _Net(af, cip, sip)
        w = _run(_script(n, [
            (False, b"220 x\r\n"), (True, b"LIST\r\n"), (True, b"SITE CPFR /etc/passwd\r\n"),
            (False, b"150 Opening data connection\r\n"), (False, b"226 Transfer complete\r\n"),
            (False, b"350 ready\r\n")]))
        check(f"{tag} 1xx does not desync pairing", "FTP-002" in _codes(w))

        # ---- multi-line greeting banner --------------------------------
        n = _Net(af, cip, sip)
        w = _run(_script(n, [(False, b"220-Welcome to example\r\n220 ProFTPD 1.3.5 Server\r\n")]))
        check(f"{tag} multi-line banner parsed", "FTP-010" in _codes(w))

        # ---- once-per-server banner dedupe -----------------------------
        frames = []
        for cp in (40001, 40002):
            n = _Net(af, cip, sip, cport=cp)
            frames += _script(n, [(False, b"220 ProFTPD 1.3.5 Server\r\n")])
        w = _run(frames)
        check(f"{tag} FTP-010 once per server", _codes(w).count("FTP-010") == 1)

    # ---- IPv6 extension headers (LESSON AE) ---------------------------
    for eh in ((0,), (60,), (0, 60), (0, 43, 60)):
        n = _Net("ipv6", "2001:db8::10", "2001:db8::21", eh=eh)
        w = _run(n.handshake() + [n.seg(True, b"SITE CPFR /etc/passwd\r\n")])
        check(f"[ipv6] EH chain {eh}", "FTP-001" in _codes(w) and w.stats["eh_walked"] > 0)

    # ---- BPF shape -----------------------------------------------------
    b = build_bpf((21,))
    check("bpf bare ip6 term", b.rstrip().endswith("or ip6"))
    check("bpf not the no-op form", "ip6 and" not in b)
    check("bpf admits ipv4 fragments", "0x3fff" in b)

    # ---- classic pcap reader round-trip -------------------------------
    import os
    import tempfile
    n = _Net("ipv4", "192.0.2.10", "192.0.2.21")
    frames = n.handshake() + [n.seg(True, b"SITE CPFR /etc/passwd\r\n")]
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, DLT_EN10MB))
        for i, fr in enumerate(frames):
            fh.write(struct.pack("<IIII", 1000 + i, 0, len(fr), len(fr)) + fr)
        pth = fh.name
    w = FtpWatch()
    for lt, fr, ts in iter_pcap(pth):
        w.feed_frame(lt, fr, ts)
    os.unlink(pth)
    check("pcap reader drives detection", "FTP-001" in _codes(w))

    # ---- passive guarantee: AST, split by call SHAPE (LESSON D) ------
    tree = ast.parse(open(__file__, encoding="utf-8").read())
    bad_names = {"send", "sendp", "sr", "sr1", "srp", "srp1", "sendpfast"}
    bad_attrs = {"send", "sendto", "sendall", "sendmsg", "connect", "system", "Popen", "run"}
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in bad_names:
                offenders.append(fn.id)
            elif isinstance(fn, ast.Attribute) and fn.attr in bad_attrs:
                offenders.append(fn.attr)
    check("passive: no transmit calls", not offenders)
    defs = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    check("no shadowed module-level names (LESSON G)", len(defs) == len(set(defs)))

    # ---- every declared code is reachable (runtime, LESSON M) ---------
    missing = set(CODES) - seen
    check(f"all codes emitted by self-test (missing: {sorted(missing)})", not missing)

    return count[0], fails


def selftest():
    """Adapt self_test() to the Ragnar Detector Self-Test aggregator shape.
    (The in-app capture adapter lives in network_diagnostics.do_ftp_watch — this
    module stays free of any transmit-shaped call, which its own AST guard and
    ftpwatch_conformance.py both assert.)"""
    count, fails = self_test()
    return {"success": not fails and count > 0,
            "scenarios": [{"name": n, "pass": ok} for n, ok in _LAST_SELFTEST]}


# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(prog=MODULE, description="FTP Watch — passive ProFTPD CVE detector")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--iface", help="live capture interface")
    src.add_argument("--pcap", help="read a pcap/pcapng file")
    ap.add_argument("--ports", default="21", help="comma-separated FTP control ports (default 21)")
    ap.add_argument("--timeout", type=float, default=None, help="live capture duration in seconds")
    ap.add_argument("--bpf", default=None, help="override the capture filter (keep a bare `ip6` term)")
    ap.add_argument("--min-severity", default="info", choices=["info", "notice", "warn", "high", "critical"])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--print-codes", action="store_true", help="print the finding registry as JSON")
    ap.add_argument("--version", action="version", version=f"{MODULE} {VERSION}")
    a = ap.parse_args(argv)

    if a.print_codes:
        print(json.dumps({k: {"name": v[0], "class": v[1], "severity": v[2], "cves": v[3]}
                          for k, v in CODES.items()}, indent=2))
        return 0
    if a.self_test:
        n, fails = self_test(a.verbose)
        print(f"{MODULE} self-test: {n - len(fails)}/{n}")
        for f in fails:
            print("FAIL", f)
        return 1 if fails else 0

    order = ["info", "notice", "warn", "high", "critical"]
    floor = order.index(a.min_severity)

    def emit(f):
        if order.index(f["severity"]) >= floor:
            print(json.dumps(f), flush=True)

    ports = tuple(int(p) for p in a.ports.split(",") if p.strip())
    w = FtpWatch(ports=ports, emit=emit)
    if a.pcap:
        for lt, fr, ts in iter_pcap(a.pcap):
            w.feed_frame(lt, fr, ts)
    elif a.iface:
        run_capture(w, a.iface, a.bpf or build_bpf(ports), a.timeout)
    else:
        ap.error("one of --iface, --pcap, --self-test or --print-codes is required")
    print(json.dumps({"module": MODULE, "event": "summary", "stats": w.stats}), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
