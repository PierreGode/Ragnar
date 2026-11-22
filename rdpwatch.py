#!/usr/bin/env python3
# rdpwatch -- passive RDP negotiation-posture and abuse detector (Ragnar).
#
# Scope: Windows 10 / Server 2016 and later. Posture and abuse only, no CVE codes.
# Reads only the cleartext X.224 Connection Request / Connection Confirm exchange
# that precedes TLS/CredSSP on TCP/3389 (MS-RDPBCGR 2.2.1.1 / 2.2.1.2).
#
# Passive only. This module never transmits. See ast_guard() and --self-test.
"""rdpwatch: passive RDP (MS-RDPBCGR) negotiation posture and abuse detector."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import secrets
import sys
import time
from collections import deque

__version__ = "0.1.0-dev"
MODULE = "rdpwatch"

# ---------------------------------------------------------------------------
# Wire constants (MS-RDPBCGR)
# ---------------------------------------------------------------------------

TPKT_VERSION = 0x03
TPKT_HDR_LEN = 4

X224_TPDU_CR = 0xE0  # Connection Request
X224_TPDU_CC = 0xD0  # Connection Confirm
X224_CONN_HDR_LEN = 7  # LI + code + dst-ref(2) + src-ref(2) + class

RDP_NEG_REQ = 0x01
RDP_NEG_RSP = 0x02
RDP_NEG_FAILURE = 0x03
RDP_NEG_LEN = 8  # every negotiation structure is exactly 8 octets
RDP_CORRELATION_INFO_LEN = 36

# requestedProtocols / selectedProtocol (u32 little-endian)
PROTOCOL_RDP = 0x00000000  # Standard RDP Security
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002  # CredSSP / NLA
PROTOCOL_RDSTLS = 0x00000004
PROTOCOL_HYBRID_EX = 0x00000008
PROTOCOL_RDSAAD = 0x00000010

PROTOCOL_NAMES = {
    PROTOCOL_SSL: "SSL",
    PROTOCOL_HYBRID: "HYBRID",
    PROTOCOL_RDSTLS: "RDSTLS",
    PROTOCOL_HYBRID_EX: "HYBRID_EX",
    PROTOCOL_RDSAAD: "RDSAAD",
}

# RDP_NEG_REQ flags
NEG_REQ_RESTRICTED_ADMIN_MODE_REQUIRED = 0x01
NEG_REQ_REDIRECTED_AUTHENTICATION_MODE_REQUIRED = 0x02
NEG_REQ_CORRELATION_INFO_PRESENT = 0x08

# RDP_NEG_RSP flags
NEG_RSP_EXTENDED_CLIENT_DATA_SUPPORTED = 0x01
NEG_RSP_DYNVC_GFX_PROTOCOL_SUPPORTED = 0x02
NEG_RSP_RESTRICTED_ADMIN_MODE_SUPPORTED = 0x08
NEG_RSP_REDIRECTED_AUTHENTICATION_MODE_SUPPORTED = 0x10

FAILURE_NAMES = {
    1: "SSL_REQUIRED_BY_SERVER",
    2: "SSL_NOT_ALLOWED_BY_SERVER",
    3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS",
    5: "HYBRID_REQUIRED_BY_SERVER",
    6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
    7: "ENTRA_AUTH_REQUIRED_BY_SERVER",
}

COOKIE_USER_PREFIX = b"Cookie: mstshash="
COOKIE_ROUTE_PREFIX = b"Cookie: msts="
COOKIE_TERM = b"\r\n"

DEFAULT_PORTS = (3389,)

# ---------------------------------------------------------------------------
# Finding registry
# ---------------------------------------------------------------------------

SEV_INFO = "info"
SEV_NOTICE = "notice"
SEV_MEDIUM = "medium"
SEV_HIGH = "high"

FINDINGS = {
    # Negotiation posture
    "RDP-001": (SEV_HIGH, "Standard RDP Security selected by server"),
    "RDP-002": (SEV_HIGH, "Server refuses TLS (SSL_NOT_ALLOWED_BY_SERVER)"),
    "RDP-003": (SEV_MEDIUM, "Legacy negotiation path, Standard Security implied"),
    "RDP-004": (SEV_HIGH, "NLA requested but not enforced, server selected SSL"),
    "RDP-005": (SEV_INFO, "RDP negotiation inventory"),
    "RDP-006": (SEV_NOTICE, "Server has no certificate (SSL_CERT_NOT_ON_SERVER)"),
    # Auth mode
    "RDP-010": (SEV_MEDIUM, "Restricted Admin mode requested by client"),
    "RDP-011": (SEV_NOTICE, "Server advertises Restricted Admin mode support"),
    # Exposure
    "RDP-020": (SEV_NOTICE, "Username present in cleartext mstshash cookie"),
    # Behaviour (latching)
    "RDP-030": (SEV_HIGH, "RDP connection brute force"),
    "RDP-031": (SEV_HIGH, "RDP username spray"),
    "RDP-032": (SEV_MEDIUM, "RDP horizontal scan"),
    # Structural
    "RDP-040": (SEV_NOTICE, "Malformed RDP negotiation"),
}

# Numeric band is the invariant, never a string compare on the code (LESSON AK).
ATTACK_BAND_MIN = 30
ATTACK_BAND_MAX = 39


def code_band(code):
    """Numeric band of a finding code. Never compare codes as strings."""
    return int(code.split("-")[1])


def attack_class_codes():
    """Behavioural (attack) codes, selected numerically."""
    return {c for c in FINDINGS if ATTACK_BAND_MIN <= code_band(c) <= ATTACK_BAND_MAX}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class Config:
    """Tunables. Unknown keyword arguments raise TypeError (rpcwatch REAL BUG 4)."""

    DEFAULTS = {
        "ports": list(DEFAULT_PORTS),
        "max_buffer": 2048,          # per-direction reassembly cap
        "max_flows": 4096,           # flow table ceiling
        "bruteforce_count": 10,      # RDP-030
        "bruteforce_window": 60.0,
        "spray_users": 5,            # RDP-031
        "spray_window": 300.0,
        "scan_targets": 20,          # RDP-032
        "scan_window": 60.0,
        "tracker_max_keys": 8192,
    }

    def __init__(self, **kwargs):
        unknown = sorted(set(kwargs) - set(self.DEFAULTS))
        if unknown:
            raise TypeError(
                "%s: unknown configuration option(s): %s"
                % (MODULE, ", ".join(unknown))
            )
        for key, default in self.DEFAULTS.items():
            value = kwargs.get(key, default)
            if isinstance(default, list):
                value = list(value)
            setattr(self, key, value)

    def as_dict(self):
        return {k: getattr(self, k) for k in self.DEFAULTS}


# ---------------------------------------------------------------------------
# Endpoint rendering (LESSON AE part 2)
# ---------------------------------------------------------------------------


def canon_ip(addr):
    """RFC 5952 canonical text for an address given as text or packed bytes."""
    if isinstance(addr, (bytes, bytearray)):
        return ipaddress.ip_address(bytes(addr)).compressed
    return ipaddress.ip_address(addr).compressed


def af_of(addr):
    return 6 if ipaddress.ip_address(canon_ip(addr)).version == 6 else 4


def fmt_endpoint(addr, port):
    """RFC 3986 rendering: IPv6 literals are bracketed so host:port re-splits."""
    text = canon_ip(addr)
    if af_of(text) == 6:
        return "[%s]:%d" % (text, port)
    return "%s:%d" % (text, port)


def split_endpoint(text):
    """Inverse of fmt_endpoint. Used by the round-trip test."""
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
        return host, int(port)
    host, _, port = text.rpartition(":")
    return host, int(port)


# ---------------------------------------------------------------------------
# Parsing primitives
# ---------------------------------------------------------------------------


class ParseError(Exception):
    pass


def u16be(buf, off):
    if off + 2 > len(buf):
        raise ParseError("u16be past end")
    return (buf[off] << 8) | buf[off + 1]


def u16le(buf, off):
    if off + 2 > len(buf):
        raise ParseError("u16le past end")
    return buf[off] | (buf[off + 1] << 8)


def u32le(buf, off):
    if off + 4 > len(buf):
        raise ParseError("u32le past end")
    return buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)


def tpkt_length(buf):
    """Declared TPKT length, or None if fewer than 4 octets are buffered."""
    if len(buf) < TPKT_HDR_LEN:
        return None
    if buf[0] != TPKT_VERSION:
        raise ParseError("not a TPKT: version 0x%02x" % buf[0])
    return u16be(buf, 2)


def tpkt_anchor(buf):
    """Index of a plausible TPKT start, or -1 (LESSON O: prefix tolerant)."""
    limit = len(buf) - 1
    for i in range(0, max(limit, 0)):
        if buf[i] == TPKT_VERSION and buf[i + 1] == 0x00:
            return i
    return -1


def parse_cookie(var):
    """Return (username_len_or_None, has_routing_token, malformed_reasons).

    The username value is never returned, stored or emitted; only its length.
    """
    reasons = []
    user_len = None
    has_route = False

    pos = var.find(COOKIE_USER_PREFIX)
    if pos >= 0:
        end = var.find(COOKIE_TERM, pos)
        if end < 0:
            reasons.append("mstshash cookie unterminated")
        else:
            user_len = end - (pos + len(COOKIE_USER_PREFIX))

    rpos = var.find(COOKIE_ROUTE_PREFIX)
    # "Cookie: mstshash=" does not match "Cookie: msts=": the '=' disambiguates.
    if rpos >= 0:
        has_route = True
        if var.find(COOKIE_TERM, rpos) < 0:
            reasons.append("routing token unterminated")

    if user_len is not None and has_route:
        # MS-RDPBCGR 2.2.1.1: routingToken and cookie are mutually exclusive.
        reasons.append("both cookie and routing token present")

    return user_len, has_route, reasons


def parse_neg(var, expect_types):
    """Parse an RDP_NEG_* structure at the head of `var`.

    Returns (neg_dict_or_None, malformed_reasons). A negotiation structure is
    optional; its absence is not malformed.
    """
    reasons = []
    if len(var) < 1:
        return None, reasons
    ntype = var[0]
    if ntype not in (RDP_NEG_REQ, RDP_NEG_RSP, RDP_NEG_FAILURE):
        return None, reasons
    if ntype not in expect_types:
        reasons.append("negotiation type 0x%02x wrong for this direction" % ntype)
        return None, reasons
    if len(var) < RDP_NEG_LEN:
        reasons.append("negotiation structure truncated (%d octets)" % len(var))
        return None, reasons
    length = u16le(var, 2)
    if length != RDP_NEG_LEN:
        reasons.append("negotiation length %d, expected %d" % (length, RDP_NEG_LEN))
    neg = {
        "type": ntype,
        "flags": var[1],
        "length": length,
        "value": u32le(var, 4),
    }
    return neg, reasons


def parse_x224_conn(pdu, expect_code):
    """Parse one TPKT-framed X.224 CR or CC.

    `pdu` is the complete TPKT PDU including its 4-octet header.
    Returns a dict describing the connection PDU.
    """
    declared = tpkt_length(pdu)
    if declared is None:
        raise ParseError("short TPKT header")
    reasons = []
    if declared != len(pdu):
        reasons.append("TPKT length %d, %d octets present" % (declared, len(pdu)))
    body = pdu[TPKT_HDR_LEN:]
    if len(body) < X224_CONN_HDR_LEN:
        raise ParseError("X.224 header truncated")
    li = body[0]
    code = body[1]
    if code != expect_code:
        raise ParseError("X.224 TPDU code 0x%02x, expected 0x%02x" % (code, expect_code))
    # LI counts every X.224 octet after itself.
    if TPKT_HDR_LEN + 1 + li != declared:
        reasons.append(
            "X.224 LI %d inconsistent with TPKT length %d" % (li, declared)
        )
    var = body[X224_CONN_HDR_LEN:]

    out = {
        "code": code,
        "li": li,
        "dst_ref": u16be(body, 2),
        "src_ref": u16be(body, 4),
        "class_opts": body[6],
        "malformed": reasons,
        "neg": None,
        "user_len": None,
        "routing_token": False,
        "correlation_info": False,
    }

    if code == X224_TPDU_CR:
        user_len, has_route, creasons = parse_cookie(var)
        out["user_len"] = user_len
        out["routing_token"] = has_route
        reasons.extend(creasons)
        # The negotiation request follows any routing field.
        term = var.rfind(COOKIE_TERM)
        neg_off = term + len(COOKIE_TERM) if term >= 0 else 0
        neg, nreasons = parse_neg(var[neg_off:], (RDP_NEG_REQ,))
        reasons.extend(nreasons)
        out["neg"] = neg
        if neg and neg["flags"] & NEG_REQ_CORRELATION_INFO_PRESENT:
            out["correlation_info"] = True
            tail = len(var) - (neg_off + RDP_NEG_LEN)
            if tail < RDP_CORRELATION_INFO_LEN:
                reasons.append(
                    "correlation info flagged but %d octets follow" % max(tail, 0)
                )
    else:
        neg, nreasons = parse_neg(var, (RDP_NEG_RSP, RDP_NEG_FAILURE))
        reasons.extend(nreasons)
        out["neg"] = neg

    out["malformed"] = reasons
    return out


# ---------------------------------------------------------------------------
# L2/L3/L4 dissection (dual stack)
# ---------------------------------------------------------------------------

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8

IPPROTO_TCP = 6
IPV6_SKIP_HEADERS = {
    0: 8,    # Hop-by-Hop Options
    43: 8,   # Routing
    60: 8,   # Destination Options
    51: 4,   # Authentication Header (length in 4-octet units, +2)
}
IPV6_FRAGMENT = 44


def parse_ethernet(frame):
    """Return (ethertype, offset_of_l3) walking any number of VLAN tags."""
    if len(frame) < 14:
        raise ParseError("runt frame")
    off = 12
    etype = u16be(frame, off)
    off += 2
    while etype in (ETH_P_8021Q, ETH_P_8021AD):
        if off + 4 > len(frame):
            raise ParseError("truncated VLAN tag")
        etype = u16be(frame, off + 2)
        off += 4
    return etype, off


def parse_ipv4(buf, off):
    if off + 20 > len(buf):
        raise ParseError("truncated IPv4 header")
    ihl = (buf[off] & 0x0F) * 4
    if ihl < 20:
        raise ParseError("bad IPv4 IHL")
    frag = u16be(buf, off + 6) & 0x1FFF
    proto = buf[off + 9]
    src = canon_ip(buf[off + 12:off + 16])
    dst = canon_ip(buf[off + 16:off + 20])
    total = u16be(buf, off + 2)
    end = off + total if 0 < total <= len(buf) - off else len(buf)
    return proto, src, dst, off + ihl, end, frag


def parse_ipv6(buf, off):
    """Walk the extension-header chain to the transport header."""
    if off + 40 > len(buf):
        raise ParseError("truncated IPv6 header")
    nxt = buf[off + 6]
    src = canon_ip(buf[off + 8:off + 24])
    dst = canon_ip(buf[off + 24:off + 40])
    plen = u16be(buf, off + 4)
    end = off + 40 + plen if plen else len(buf)
    end = min(end, len(buf))
    cur = off + 40
    frag_off = 0
    guard = 0
    while nxt in IPV6_SKIP_HEADERS or nxt == IPV6_FRAGMENT:
        guard += 1
        if guard > 16:
            raise ParseError("IPv6 extension header chain too long")
        if cur + 8 > len(buf):
            raise ParseError("truncated IPv6 extension header")
        if nxt == IPV6_FRAGMENT:
            frag_off = (u16be(buf, cur + 2) & 0xFFF8) >> 3
            step = 8
        elif nxt == 51:  # AH: length in 4-octet units, minus 2
            step = (buf[cur + 1] + 2) * 4
        else:
            step = (buf[cur + 1] + 1) * 8
        nxt = buf[cur]
        cur += step
    return nxt, src, dst, cur, end, frag_off


def parse_tcp(buf, off, end):
    if off + 20 > len(buf):
        raise ParseError("truncated TCP header")
    sport = u16be(buf, off)
    dport = u16be(buf, off + 2)
    seq = (buf[off + 4] << 24) | (buf[off + 5] << 16) | (buf[off + 6] << 8) | buf[off + 7]
    doff = (buf[off + 12] >> 4) * 4
    if doff < 20:
        raise ParseError("bad TCP data offset")
    payload = buf[off + doff:max(end, off + doff)]
    return sport, dport, seq, bytes(payload)


# ---------------------------------------------------------------------------
# Behavioural trackers (latching)
# ---------------------------------------------------------------------------


class WindowCounter:
    """Sliding-window event counter with per-key latching."""

    def __init__(self, window, threshold, max_keys):
        self.window = float(window)
        self.threshold = int(threshold)
        self.max_keys = int(max_keys)
        self.keys = {}
        self.latched = set()

    def _evict(self):
        while len(self.keys) > self.max_keys:
            # Evict the key whose newest event is oldest. The comparator reads a
            # field explicitly, never the record itself (LESSON AK part 2).
            oldest = min(self.keys, key=lambda k: self.keys[k][-1] if self.keys[k] else 0.0)
            del self.keys[oldest]

    def add(self, key, now):
        """Record an event. Returns the count if this crossed the threshold."""
        dq = self.keys.setdefault(key, deque())
        dq.append(now)
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        self._evict()
        if key in self.latched:
            return None
        if len(dq) >= self.threshold:
            self.latched.add(key)
            return len(dq)
        return None


class WindowSet:
    """Sliding-window distinct-value counter with per-key latching."""

    def __init__(self, window, threshold, max_keys):
        self.window = float(window)
        self.threshold = int(threshold)
        self.max_keys = int(max_keys)
        self.keys = {}
        self.latched = set()

    def _evict(self):
        while len(self.keys) > self.max_keys:
            oldest = min(
                self.keys,
                key=lambda k: max(self.keys[k].values()) if self.keys[k] else 0.0,
            )
            del self.keys[oldest]

    def add(self, key, value, now):
        seen = self.keys.setdefault(key, {})
        seen[value] = now
        cutoff = now - self.window
        for v in [v for v, ts in seen.items() if ts < cutoff]:
            del seen[v]
        self._evict()
        if key in self.latched:
            return None
        if len(seen) >= self.threshold:
            self.latched.add(key)
            return len(seen)
        return None


# ---------------------------------------------------------------------------
# Flow state
# ---------------------------------------------------------------------------


class Flow:
    __slots__ = ("cr", "cc", "done", "buf_c2s", "buf_s2c", "last", "client", "server",
                 "role_guess")

    def __init__(self, now):
        self.cr = None
        self.cc = None
        self.done = False
        self.buf_c2s = bytearray()
        self.buf_s2c = bytearray()
        self.last = now
        self.client = None
        self.server = None
        self.role_guess = False


# ---------------------------------------------------------------------------
# The detector
# ---------------------------------------------------------------------------


class RDPWatch:
    def __init__(self, config=None, emit=None, **kwargs):
        self.cfg = config if config is not None else Config(**kwargs)
        self.findings = []
        self._emit = emit
        self.flows = {}
        self.stats = {
            "frames": 0,
            "tcp_segments": 0,
            "port_rejected": 0,
            "cr_parsed": 0,
            "cc_parsed": 0,
            "parse_errors": 0,
        }
        # Random per-run key: usernames are counted for distinctness and never
        # stored, logged or emitted in any form.
        self._user_key = secrets.token_bytes(32)
        self.bruteforce = WindowCounter(
            self.cfg.bruteforce_window, self.cfg.bruteforce_count,
            self.cfg.tracker_max_keys)
        self.spray = WindowSet(
            self.cfg.spray_window, self.cfg.spray_users, self.cfg.tracker_max_keys)
        self.scan = WindowSet(
            self.cfg.scan_window, self.cfg.scan_targets, self.cfg.tracker_max_keys)

    # -- emit ---------------------------------------------------------------

    def _finding(self, severity, code, detail, src=None, dst=None, af=None):
        rec = {
            "module": MODULE,
            "version": __version__,
            "ts": time.time(),
            "code": code,
            "severity": severity,
            "title": FINDINGS[code][1],
            "detail": detail,
        }
        if src is not None:
            rec["src"] = src
        if dst is not None:
            rec["dst"] = dst
        if af is not None:
            rec["af"] = af
        self.findings.append(rec)
        if self._emit is not None:
            self._emit(rec)
        return rec

    def _user_digest(self, pdu_bytes, user_len):
        """Distinctness token for a cleartext username.

        Keyed with a per-run random key and never emitted. The caller passes the
        raw cookie region; the digest leaves this method and nothing else does.
        """
        return hashlib.blake2b(
            pdu_bytes, key=self._user_key, digest_size=16, person=b"rdpwatch-user"
        ).digest()

    # -- top level ----------------------------------------------------------

    def handle_frame(self, frame, now=None):
        """Feed one Ethernet frame. Returns the findings produced by this frame."""
        if now is None:
            now = time.time()
        before = len(self.findings)
        self.stats["frames"] += 1
        try:
            etype, off = parse_ethernet(frame)
            if etype == ETH_P_IPV4:
                proto, src, dst, l4, end, frag = parse_ipv4(frame, off)
            elif etype == ETH_P_IPV6:
                proto, src, dst, l4, end, frag = parse_ipv6(frame, off)
            else:
                return []
            if proto != IPPROTO_TCP or frag != 0:
                return []
            sport, dport, seq, payload = parse_tcp(frame, l4, end)
        except ParseError:
            self.stats["parse_errors"] += 1
            return []

        self.stats["tcp_segments"] += 1
        ports = set(self.cfg.ports)
        # The BPF admits all of IPv6 bare (LESSON AE part 1), so this software
        # gate is the only rejector on the v6 path. It has its own negative test.
        if sport not in ports and dport not in ports:
            self.stats["port_rejected"] += 1
            return []

        self.handle_segment(src, sport, dst, dport, payload, now)
        return self.findings[before:]

    def handle_segment(self, src, sport, dst, dport, payload, now):
        if not payload:
            return
        ports = set(self.cfg.ports)
        # Roles are decided by PORT, never by who spoke first (LESSON AC).
        guess = False
        if dport in ports and sport not in ports:
            client, cport, server, sport_ = src, sport, dst, dport
            to_server = True
        elif sport in ports and dport not in ports:
            client, cport, server, sport_ = dst, dport, src, sport
            to_server = False
        else:
            client, cport, server, sport_ = src, sport, dst, dport
            to_server = True
            guess = True

        key = (client, cport, server, sport_)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.cfg.max_flows:
                stale = min(self.flows, key=lambda k: self.flows[k].last)
                del self.flows[stale]
            flow = Flow(now)
            flow.client = fmt_endpoint(client, cport)
            flow.server = fmt_endpoint(server, sport_)
            flow.role_guess = guess
            self.flows[key] = flow
        flow.last = now
        if flow.done:
            return

        buf = flow.buf_c2s if to_server else flow.buf_s2c
        buf.extend(payload)
        if len(buf) > self.cfg.max_buffer:
            del buf[self.cfg.max_buffer:]

        anchor = tpkt_anchor(buf)
        if anchor < 0:
            if len(buf) >= self.cfg.max_buffer:
                flow.done = True
            return
        if anchor > 0:
            del buf[:anchor]

        try:
            declared = tpkt_length(buf)
        except ParseError:
            flow.done = True
            return
        if declared is None or len(buf) < declared:
            return
        pdu = bytes(buf[:declared])

        if to_server:
            self._on_cr(flow, pdu, src, sport, dst, dport, now)
        else:
            self._on_cc(flow, pdu, now)

    # -- Connection Request -------------------------------------------------

    def _on_cr(self, flow, pdu, src, sport, dst, dport, now):
        if flow.cr is not None:
            return
        try:
            cr = parse_x224_conn(pdu, X224_TPDU_CR)
        except ParseError:
            self.stats["parse_errors"] += 1
            flow.done = True
            return
        self.stats["cr_parsed"] += 1
        flow.cr = cr
        af = af_of(src)

        if cr["malformed"]:
            self._finding(SEV_NOTICE, "RDP-040",
                          {"reasons": cr["malformed"], "direction": "client-to-server"},
                          src=flow.client, dst=flow.server, af=af)

        neg = cr["neg"]
        if neg and neg["flags"] & NEG_REQ_RESTRICTED_ADMIN_MODE_REQUIRED:
            self._finding(SEV_MEDIUM, "RDP-010", {
                "flags": "0x%02x" % neg["flags"],
                "note": "credential-less logon; enables pass-the-hash reuse of the "
                        "session. Legitimate administrative use is common.",
            }, src=flow.client, dst=flow.server, af=af)

        if cr["user_len"] is not None:
            self._finding(SEV_NOTICE, "RDP-020", {
                "username_length": cr["user_len"],
                "note": "username travels in cleartext before TLS; value not recorded",
            }, src=flow.client, dst=flow.server, af=af)

        # Behaviour
        bkey = (canon_ip(src), canon_ip(dst))
        hit = self.bruteforce.add(bkey, now)
        if hit is not None:
            self._finding(SEV_HIGH, "RDP-030", {
                "connection_requests": hit,
                "window_seconds": self.cfg.bruteforce_window,
                "threshold": self.cfg.bruteforce_count,
            }, src=flow.client, dst=flow.server, af=af)

        if cr["user_len"] is not None:
            digest = self._user_digest(pdu, cr["user_len"])
            hit = self.spray.add(canon_ip(src), digest, now)
            if hit is not None:
                self._finding(SEV_HIGH, "RDP-031", {
                    "distinct_usernames": hit,
                    "window_seconds": self.cfg.spray_window,
                    "threshold": self.cfg.spray_users,
                    "note": "usernames counted via a per-run keyed hash; "
                            "neither hash nor value is recorded",
                }, src=flow.client, dst=flow.server, af=af)

        hit = self.scan.add(canon_ip(src), canon_ip(dst), now)
        if hit is not None:
            self._finding(SEV_MEDIUM, "RDP-032", {
                "distinct_destinations": hit,
                "window_seconds": self.cfg.scan_window,
                "threshold": self.cfg.scan_targets,
            }, src=flow.client, dst=flow.server, af=af)

    # -- Connection Confirm -------------------------------------------------

    def _on_cc(self, flow, pdu, now):
        if flow.cc is not None:
            return
        try:
            cc = parse_x224_conn(pdu, X224_TPDU_CC)
        except ParseError:
            self.stats["parse_errors"] += 1
            flow.done = True
            return
        self.stats["cc_parsed"] += 1
        flow.cc = cc
        flow.done = True
        af = af_of(split_endpoint(flow.server)[0])

        if cc["malformed"]:
            self._finding(SEV_NOTICE, "RDP-040",
                          {"reasons": cc["malformed"], "direction": "server-to-client"},
                          src=flow.server, dst=flow.client, af=af)

        cr = flow.cr
        req_neg = cr["neg"] if cr else None
        requested = req_neg["value"] if req_neg else None
        neg = cc["neg"]

        selected = None
        failure = None
        if neg and neg["type"] == RDP_NEG_RSP:
            selected = neg["value"]
        elif neg and neg["type"] == RDP_NEG_FAILURE:
            failure = neg["value"]

        inv = {
            "requested": self._proto_text(requested),
            "selected": self._proto_text(selected),
            "failure": FAILURE_NAMES.get(failure, failure) if failure is not None else None,
            "secure": self._is_good_state(selected, failure),
        }
        if cr is None:
            inv["note"] = "no Connection Request observed for this flow"
        if flow.role_guess:
            inv["role_source"] = "guessed: neither port is a configured RDP port"
        self._finding(SEV_INFO, "RDP-005", inv,
                      src=flow.server, dst=flow.client, af=af)

        if failure is not None:
            if failure == 2:
                self._finding(SEV_HIGH, "RDP-002", {
                    "failure_code": failure,
                    "failure": FAILURE_NAMES[2],
                    "note": "server speaks Standard RDP Security only; "
                            "the session is MITM-able (posture ref CVE-2005-1794)",
                }, src=flow.server, dst=flow.client, af=af)
            elif failure == 3:
                self._finding(SEV_NOTICE, "RDP-006", {
                    "failure_code": failure,
                    "failure": FAILURE_NAMES[3],
                }, src=flow.server, dst=flow.client, af=af)
            return

        if neg is None:
            if cr is not None and req_neg is None:
                self._finding(SEV_MEDIUM, "RDP-003", {
                    "note": "Connection Request carried no RDP_NEG_REQ and the "
                            "Confirm carried no RDP_NEG_RSP; Standard RDP Security "
                            "is implied (legacy client path)",
                }, src=flow.server, dst=flow.client, af=af)
            return

        if neg["flags"] & NEG_RSP_RESTRICTED_ADMIN_MODE_SUPPORTED:
            self._finding(SEV_NOTICE, "RDP-011", {
                "flags": "0x%02x" % neg["flags"],
            }, src=flow.server, dst=flow.client, af=af)

        if selected == PROTOCOL_RDP:
            self._finding(SEV_HIGH, "RDP-001", {
                "selected": "PROTOCOL_RDP",
                "note": "Standard RDP Security: RC4 with a key derived from a "
                        "server certificate the client cannot validate. "
                        "Posture reference CVE-2005-1794, no CVE code claimed.",
            }, src=flow.server, dst=flow.client, af=af)
        elif selected == PROTOCOL_SSL and requested is not None and (
                requested & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX)):
            self._finding(SEV_HIGH, "RDP-004", {
                "requested": self._proto_text(requested),
                "selected": "SSL",
                "note": "client offered CredSSP/NLA and the server declined it; "
                        "the pre-authentication surface is reachable",
            }, src=flow.server, dst=flow.client, af=af)

    @staticmethod
    def _proto_text(value):
        if value is None:
            return None
        if value == PROTOCOL_RDP:
            return "PROTOCOL_RDP"
        names = [n for bit, n in sorted(PROTOCOL_NAMES.items()) if value & bit]
        rest = value & ~sum(PROTOCOL_NAMES)
        if rest:
            names.append("0x%08x" % rest)
        return "|".join(names) if names else "0x%08x" % value

    @staticmethod
    def _is_good_state(selected, failure):
        if failure == 5:  # HYBRID_REQUIRED_BY_SERVER
            return True
        if selected in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX, PROTOCOL_RDSAAD):
            return True
        return False

    # -- capture ------------------------------------------------------------

    def bpf(self):
        """Capture filter.

        The IPv6 term is BARE on purpose. `(tcp port N) or (ip6 and tcp port N)`
        is a measured no-op: the `port` primitive cannot walk an IPv6
        extension-header chain, so it drops every HopByHop/Routing/Fragment/
        DestOpt frame (LESSON AE part 1). The bare `ip6` admit makes the
        software port gate in handle_frame() load-bearing on the v6 path.
        """
        ports = " or ".join("port %d" % p for p in self.cfg.ports)
        return "(tcp and (%s)) or ip6" % ports

    def run_capture(self, iface=None, pcap=None, timeout=None):
        """The one function that imports scapy. Never executed offline (LESSON C)."""
        from scapy.all import sniff  # noqa: PLC0415

        def _on_pkt(pkt):
            try:
                self.handle_frame(bytes(pkt), now=float(pkt.time))
            except Exception:  # a bad frame must never stop the capture
                self.stats["parse_errors"] += 1

        kwargs = {"prn": _on_pkt, "store": False, "filter": self.bpf()}
        if pcap is not None:
            kwargs["offline"] = pcap
        else:
            kwargs["iface"] = iface
            if timeout is not None:
                kwargs["timeout"] = timeout
        sniff(**kwargs)
        return self.findings


# ---------------------------------------------------------------------------
# AST guard (LESSON D: split banned calls by SHAPE, not name)
# ---------------------------------------------------------------------------


def ast_guard(path=None):
    """Prove this module cannot transmit and has no shadowed module-level names."""
    import ast  # noqa: PLC0415

    path = path or os.path.abspath(__file__)
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)

    bare_banned = {"send", "sendp", "sr", "sr1", "srp", "srp1", "sendpfast",
                   "pcap_sendpacket"}
    attr_banned = {
        ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"),
        ("subprocess", "check_output"), ("os", "system"), ("os", "popen"),
    }
    attr_allowed_receivers = {"self", "socket", "sock"}
    problems = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in bare_banned:
                problems.append("bare transmit call %s() at line %d" % (fn.id, fn.lineno))
            elif isinstance(fn, ast.Attribute):
                recv = fn.value
                if isinstance(recv, ast.Name):
                    if (recv.id, fn.attr) in attr_banned:
                        problems.append(
                            "banned call %s.%s() at line %d" % (recv.id, fn.attr, fn.lineno))
                    if fn.attr in ("send", "sendall", "sendto") and \
                            recv.id not in attr_allowed_receivers:
                        problems.append(
                            "socket transmit %s.%s() at line %d"
                            % (recv.id, fn.attr, fn.lineno))

    # LESSON G: no module-level name may be bound twice.
    seen = {}
    for node in tree.body:
        names = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        for n in names:
            if n in seen:
                problems.append(
                    "module-level name %r redefined at line %d (first at %d)"
                    % (n, node.lineno, seen[n]))
            seen[n] = node.lineno
    return problems


def declared_codes(path=None):
    """Finding codes reachable from _finding() calls.

    Resolves literals, assignments and for-loop tuple targets (LESSON M).
    """
    import ast  # noqa: PLC0415

    path = path or os.path.abspath(__file__)
    with open(path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)

    def literals(node, scope):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.IfExp):
            return literals(node.body, scope) | literals(node.orelse, scope)
        if isinstance(node, ast.Name):
            return set(scope.get(node.id, set()))
        return set()

    found = set()
    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        scope = {}
        # LESSON Y(a): resolve names only inside the enclosing function.
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        scope.setdefault(t.id, set()).update(literals(node.value, scope))
            elif isinstance(node, ast.For) and isinstance(node.target, ast.Tuple):
                if isinstance(node.iter, (ast.Tuple, ast.List)):
                    for item in node.iter.elts:
                        if isinstance(item, (ast.Tuple, ast.List)):
                            for tgt, val in zip(node.target.elts, item.elts):
                                if isinstance(tgt, ast.Name):
                                    scope.setdefault(tgt.id, set()).update(
                                        literals(val, scope))
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "_finding" and len(node.args) >= 2:
                found |= literals(node.args[1], scope)
    return found


# ---------------------------------------------------------------------------
# Fixture builders (test-only; names are prefixed so they cannot shadow the
# parser helpers above -- LESSON G)
# ---------------------------------------------------------------------------


def build_neg_req(flags=0, protocols=PROTOCOL_HYBRID, length=RDP_NEG_LEN):
    return bytes([RDP_NEG_REQ, flags]) + length.to_bytes(2, "little") + \
        protocols.to_bytes(4, "little")


def build_neg_rsp(flags=0, selected=PROTOCOL_HYBRID, length=RDP_NEG_LEN):
    return bytes([RDP_NEG_RSP, flags]) + length.to_bytes(2, "little") + \
        selected.to_bytes(4, "little")


def build_neg_failure(code):
    return bytes([RDP_NEG_FAILURE, 0]) + RDP_NEG_LEN.to_bytes(2, "little") + \
        int(code).to_bytes(4, "little")


def build_x224_cr(cookie=None, routing=None, neg=None, correlation=False,
                  li=None, tpkt_len=None):
    var = b""
    if routing is not None:
        var += COOKIE_ROUTE_PREFIX + routing + COOKIE_TERM
    if cookie is not None:
        var += COOKIE_USER_PREFIX + cookie + COOKIE_TERM
    if neg is not None:
        var += neg
    if correlation:
        var += b"\x00" * RDP_CORRELATION_INFO_LEN
    body = bytes([
        X224_CONN_HDR_LEN - 1 + len(var) if li is None else li,
        X224_TPDU_CR, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]) + var
    total = TPKT_HDR_LEN + len(body) if tpkt_len is None else tpkt_len
    return bytes([TPKT_VERSION, 0x00]) + total.to_bytes(2, "big") + body


def build_x224_cc(neg=None, li=None, tpkt_len=None):
    var = neg or b""
    body = bytes([
        X224_CONN_HDR_LEN - 1 + len(var) if li is None else li,
        X224_TPDU_CC, 0x00, 0x00, 0x12, 0x34, 0x00,
    ]) + var
    total = TPKT_HDR_LEN + len(body) if tpkt_len is None else tpkt_len
    return bytes([TPKT_VERSION, 0x00]) + total.to_bytes(2, "big") + body


def build_frame(src, dst, sport, dport, payload, v6_ext=None, vlan=None):
    """Build an Ethernet frame carrying `payload` over TCP. Test fixtures only."""
    s = ipaddress.ip_address(src)
    d = ipaddress.ip_address(dst)
    tcp = (sport.to_bytes(2, "big") + dport.to_bytes(2, "big") +
           (1).to_bytes(4, "big") + (1).to_bytes(4, "big") +
           bytes([0x50, 0x18]) + b"\xff\xff" + b"\x00\x00" + b"\x00\x00" + payload)
    if s.version == 4:
        etype = ETH_P_IPV4
        total = 20 + len(tcp)
        l3 = (bytes([0x45, 0x00]) + total.to_bytes(2, "big") +
              b"\x00\x01\x00\x00\x40" + bytes([IPPROTO_TCP]) + b"\x00\x00" +
              s.packed + d.packed)
    else:
        etype = ETH_P_IPV6
        ext = b""
        nxt = IPPROTO_TCP
        if v6_ext:
            for hdr in reversed(v6_ext):
                # each ext header: next(1) len(1) + 6 pad = 8 octets
                ext = bytes([nxt, 0x00]) + b"\x00" * 6 + ext
                nxt = hdr
        plen = len(ext) + len(tcp)
        l3 = (b"\x60\x00\x00\x00" + plen.to_bytes(2, "big") + bytes([nxt, 0x40]) +
              s.packed + d.packed) + ext
    tag = b""
    if vlan is not None:
        tag = ETH_P_8021Q.to_bytes(2, "big") + vlan.to_bytes(2, "big")
    return (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" +
            tag + etype.to_bytes(2, "big") + l3 + tcp)


# ---------------------------------------------------------------------------
# Self-test (dependency free)
# ---------------------------------------------------------------------------


class _Checker:
    def __init__(self):
        self.passed = 0
        self.failed = []

    def ok(self, cond, label):
        if cond:
            self.passed += 1
        else:
            self.failed.append(label)

    def eq(self, got, want, label):
        self.ok(got == want, "%s: got %r want %r" % (label, got, want))

    def report(self, name):
        total = self.passed + len(self.failed)
        for f in self.failed:
            print("FAIL %s" % f)
        print("%s: %d/%d checks passed" % (name, self.passed, total))
        return not self.failed


def _leaf_strings(obj):
    """Every emitted string VALUE, keys excluded.

    LESSON I: never grep a structured record for a value that also occurs in
    its own schema. "severity" contains "eve"; a json.dumps() blob check on a
    username fixture is a false positive waiting to happen.
    """
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_leaf_strings(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_leaf_strings(v))
    return out


def _emits_value(findings, needle):
    """True if `needle` occurs in any emitted string value or any raw bytes."""
    if any(needle in s for s in _leaf_strings(findings)):
        return True
    return any(isinstance(v, (bytes, bytearray)) and needle.encode() in v
               for f in findings for v in _leaf_strings_bytes(f))


def _leaf_strings_bytes(obj):
    out = []
    if isinstance(obj, (bytes, bytearray)):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_leaf_strings_bytes(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_leaf_strings_bytes(v))
    return out


def _codes(findings):
    return [f.get("code") for f in findings]


def _first(findings, code):
    """Finding of this code, or a sentinel dict. NEVER index directly in an
    assertion: a mutation that drops the finding must FAIL, not CRASH, because
    a crash loses the summary line (LESSON AK part 2)."""
    return next((f for f in findings if f.get("code") == code), {})


def _run_pair(cr, cc, src="192.0.2.10", dst="192.0.2.20", sport=51000, dport=3389,
              cfg=None, now=1000.0, v6_ext=None):
    w = RDPWatch(config=cfg or Config())
    out = []
    out += w.handle_frame(build_frame(src, dst, sport, dport, cr, v6_ext=v6_ext), now=now)
    if cc is not None:
        out += w.handle_frame(build_frame(dst, src, dport, sport, cc, v6_ext=v6_ext),
                              now=now)
    return w, out


def self_test():
    c = _Checker()

    # -- registry invariants ------------------------------------------------
    c.eq(len(FINDINGS), 13, "registry size")
    c.eq(attack_class_codes(), {"RDP-030", "RDP-031", "RDP-032"}, "attack band")
    # String comparison would have admitted nothing here today, but the band must
    # stay numeric so a second prefix cannot break it (LESSON AK part 1).
    c.ok(all(code_band(k) == int(k.split("-")[1]) for k in FINDINGS), "band parse")

    # -- config -------------------------------------------------------------
    try:
        Config(bruteforce_count=3)
        c.ok(True, "config known kwarg")
    except TypeError:
        c.ok(False, "config known kwarg rejected")
    try:
        Config(brutforce_count=3)
        c.ok(False, "config typo not rejected")
    except TypeError as exc:
        c.ok("brutforce_count" in str(exc), "config typo names the option")
    c.eq(Config().ports, [3389], "default port")
    cfg_a = Config()
    cfg_a.ports.append(4489)
    c.eq(Config().ports, [3389], "DEFAULTS not mutated by instance")

    # -- endpoint rendering round trip (LESSON AE part 2) -------------------
    c.eq(fmt_endpoint("2001:db8::9", 51000), "[2001:db8::9]:51000", "v6 bracket")
    c.eq(fmt_endpoint("192.0.2.1", 3389), "192.0.2.1:3389", "v4 endpoint")
    c.eq(fmt_endpoint("2001:0db8:0000:0000:0000:0000:0000:0009", 1), "[2001:db8::9]:1",
         "RFC 5952 canonical")
    for ep in ("[2001:db8::9]:51000", "192.0.2.1:3389", "[::1]:3389"):
        c.eq(fmt_endpoint(*split_endpoint(ep)), ep, "round trip %s" % ep)

    # -- RDP-001 Standard Security selected ---------------------------------
    w, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_RDP)),
                       build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_RDP)))
    c.ok("RDP-001" in _codes(out), "RDP-001 fires")
    c.ok("RDP-005" in _codes(out), "RDP-005 inventory present")
    inv = _first(out, "RDP-005")
    c.eq(inv.get("detail", {}).get("secure"), False, "RDP-001 state not secure")
    c.eq(inv.get("detail", {}).get("selected"), "PROTOCOL_RDP", "selected text")

    # -- RDP-002 SSL_NOT_ALLOWED_BY_SERVER ----------------------------------
    w, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_SSL)),
                       build_x224_cc(neg=build_neg_failure(2)))
    c.ok("RDP-002" in _codes(out), "RDP-002 fires")
    c.ok("RDP-001" not in _codes(out), "RDP-002 does not also raise RDP-001")

    # -- RDP-006 SSL_CERT_NOT_ON_SERVER -------------------------------------
    w, out = _run_pair(build_x224_cr(neg=build_neg_req()),
                       build_x224_cc(neg=build_neg_failure(3)))
    c.ok("RDP-006" in _codes(out), "RDP-006 fires")

    # -- failure 5 is the good state ----------------------------------------
    w, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_SSL)),
                       build_x224_cc(neg=build_neg_failure(5)))
    inv = _first(out, "RDP-005")
    c.eq(inv.get("detail", {}).get("secure"), True,
         "HYBRID_REQUIRED is the good state")
    c.eq(set(_codes(out)), {"RDP-005"}, "HYBRID_REQUIRED raises nothing else")

    # -- RDP-003 legacy path ------------------------------------------------
    w, out = _run_pair(build_x224_cr(), build_x224_cc())
    c.ok("RDP-003" in _codes(out), "RDP-003 fires")
    c.ok("RDP-040" not in _codes(out), "legacy path is not malformed")

    # -- RDP-004 NLA requested, SSL selected --------------------------------
    for req in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX,
                PROTOCOL_SSL | PROTOCOL_HYBRID):
        w, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=req)),
                           build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_SSL)))
        c.ok("RDP-004" in _codes(out), "RDP-004 fires for requested 0x%x" % req)
    # SSL-only request answered with SSL is not a downgrade.
    w, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_SSL)),
                       build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_SSL)))
    c.ok("RDP-004" not in _codes(out), "SSL requested and selected is not RDP-004")

    # -- clean set: HYBRID negotiated raises no attack or posture code ------
    w, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_HYBRID)),
                       build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_HYBRID)))
    c.eq(set(_codes(out)), {"RDP-005"}, "clean NLA session is quiet")
    inv = _first(out, "RDP-005")
    # Assert the verdict POSITIVELY, not merely that nothing fired (LESSON AL).
    c.eq(inv.get("detail", {}).get("secure"), True, "clean session reported secure")
    c.eq(inv.get("detail", {}).get("selected"), "HYBRID",
         "clean session selected HYBRID")

    # -- RDP-010 / RDP-011 restricted admin ---------------------------------
    w, out = _run_pair(
        build_x224_cr(neg=build_neg_req(
            flags=NEG_REQ_RESTRICTED_ADMIN_MODE_REQUIRED, protocols=PROTOCOL_HYBRID)),
        build_x224_cc(neg=build_neg_rsp(
            flags=NEG_RSP_RESTRICTED_ADMIN_MODE_SUPPORTED, selected=PROTOCOL_HYBRID)))
    c.ok("RDP-010" in _codes(out), "RDP-010 fires")
    c.ok("RDP-011" in _codes(out), "RDP-011 fires")
    # Remote Credential Guard is the good state: inventory only, no code.
    w, out = _run_pair(
        build_x224_cr(neg=build_neg_req(
            flags=NEG_REQ_REDIRECTED_AUTHENTICATION_MODE_REQUIRED,
            protocols=PROTOCOL_HYBRID)),
        build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_HYBRID)))
    c.eq(set(_codes(out)), {"RDP-005"}, "Remote Credential Guard raises no code")

    # -- RDP-020 cookie, and the routing token must NEVER be a username -----
    w, out = _run_pair(build_x224_cr(cookie=b"administrator",
                                     neg=build_neg_req()),
                       build_x224_cc(neg=build_neg_rsp()))
    f = _first(out, "RDP-020")
    c.eq(f.get("detail", {}).get("username_length"), len(b"administrator"),
         "cookie length")
    c.ok(not _emits_value(out, "administrator"), "username value never emitted")
    # the harness itself must be able to see a leak (non-vacuity)
    c.ok(_emits_value([{"detail": {"x": "administrator"}}], "administrator"),
         "leak detector is not vacuous")
    # ... and must NOT be fooled by a schema key, which is what json.dumps was
    c.ok(not _emits_value([{"severity": "high"}], "eve"),
         "leak detector ignores schema keys")

    w, out = _run_pair(build_x224_cr(routing=b"3640205228.15629.0000",
                                     neg=build_neg_req()),
                       build_x224_cc(neg=build_neg_rsp()))
    c.ok("RDP-020" not in _codes(out), "routing token is not a username")
    c.ok("RDP-040" not in _codes(out), "routing token alone is well formed")

    # both present -> malformed, and still not a username finding for the token
    w, out = _run_pair(build_x224_cr(routing=b"tok", cookie=b"bob",
                                     neg=build_neg_req()),
                       build_x224_cc(neg=build_neg_rsp()))
    f40 = _first(out, "RDP-040")
    c.ok(any("both cookie and routing token" in r
             for r in f40.get("detail", {}).get("reasons", [])),
         "RDP-040 flags cookie+token")

    # -- RDP-040 structural -------------------------------------------------
    bad = build_x224_cr(neg=build_neg_req(length=9))
    w, out = _run_pair(bad, None)
    c.ok("RDP-040" in _codes(out), "RDP-040 on bad NEG length")
    # wrong type for the direction: a NEG_RSP inside a Connection Request
    w, out = _run_pair(build_x224_cr(neg=build_neg_rsp()), None)
    c.ok("RDP-040" in _codes(out), "RDP-040 on wrong NEG type for direction")
    # TPKT length inconsistent with the X.224 LI
    w, out = _run_pair(build_x224_cr(neg=build_neg_req(), li=4), None)
    c.ok(any("LI" in r for f in out if f.get("code") == "RDP-040"
             for r in f.get("detail", {}).get("reasons", [])),
         "RDP-040 on LI mismatch")

    # -- correlation info ---------------------------------------------------
    cr = build_x224_cr(neg=build_neg_req(flags=NEG_REQ_CORRELATION_INFO_PRESENT),
                       correlation=True)
    w, out = _run_pair(cr, build_x224_cc(neg=build_neg_rsp()))
    c.ok("RDP-040" not in _codes(out), "correlation info accepted when present")
    cr = build_x224_cr(neg=build_neg_req(flags=NEG_REQ_CORRELATION_INFO_PRESENT))
    w, out = _run_pair(cr, None)
    c.ok(any("correlation" in r for f in out if f.get("code") == "RDP-040"
             for r in f.get("detail", {}).get("reasons", [])),
         "RDP-040 on absent correlation info")

    # -- behaviour: brute force ---------------------------------------------
    cfg = Config(bruteforce_count=4, bruteforce_window=60.0)
    w = RDPWatch(config=cfg)
    cr = build_x224_cr(neg=build_neg_req())
    fired = 0
    for i in range(10):
        got = w.handle_frame(
            build_frame("192.0.2.10", "192.0.2.20", 40000 + i, 3389, cr),
            now=1000.0 + i)
        fired += _codes(got).count("RDP-030")
    c.eq(fired, 1, "RDP-030 latches exactly once")
    # window expiry: events outside the window do not accumulate
    w2 = RDPWatch(config=Config(bruteforce_count=4, bruteforce_window=10.0))
    fired = 0
    for i in range(10):
        got = w2.handle_frame(
            build_frame("192.0.2.11", "192.0.2.20", 40000 + i, 3389, cr),
            now=1000.0 + i * 100)
        fired += _codes(got).count("RDP-030")
    c.eq(fired, 0, "RDP-030 respects the window")

    # -- behaviour: spray ---------------------------------------------------
    w = RDPWatch(config=Config(spray_users=3, spray_window=300.0))
    fired = 0
    for i, name in enumerate([b"alice", b"bob", b"carol", b"dave", b"eve"]):
        pdu = build_x224_cr(cookie=name, neg=build_neg_req())
        got = w.handle_frame(
            build_frame("192.0.2.30", "192.0.2.40", 41000 + i, 3389, pdu), now=2000.0 + i)
        fired += _codes(got).count("RDP-031")
    c.eq(fired, 1, "RDP-031 latches exactly once")
    for name in ("alice", "bob", "carol", "dave", "eve"):
        c.ok(not _emits_value(w.findings, name),
             "spray never emits the username %s" % name)
    # the same username repeated is not a spray
    w = RDPWatch(config=Config(spray_users=3, spray_window=300.0))
    fired = 0
    for i in range(6):
        pdu = build_x224_cr(cookie=b"alice", neg=build_neg_req())
        got = w.handle_frame(
            build_frame("192.0.2.31", "192.0.2.40", 41000 + i, 3389, pdu), now=2000.0 + i)
        fired += _codes(got).count("RDP-031")
    c.eq(fired, 0, "one repeated username is not a spray")
    # distinct keys per run: the digest is not stable across instances
    a = RDPWatch(config=Config())
    b = RDPWatch(config=Config())
    c.ok(a._user_digest(b"x", 1) != b._user_digest(b"x", 1), "per-run digest key")

    # -- behaviour: scan ----------------------------------------------------
    w = RDPWatch(config=Config(scan_targets=5, scan_window=60.0))
    fired = 0
    for i in range(12):
        got = w.handle_frame(
            build_frame("192.0.2.50", "198.51.100.%d" % (i + 1), 42000 + i, 3389, cr),
            now=3000.0 + i)
        fired += _codes(got).count("RDP-032")
    c.eq(fired, 1, "RDP-032 latches exactly once")
    # repeated hits on ONE destination are not a scan
    w = RDPWatch(config=Config(scan_targets=5, scan_window=60.0, bruteforce_count=99))
    fired = 0
    for i in range(12):
        got = w.handle_frame(
            build_frame("192.0.2.51", "198.51.100.9", 42000 + i, 3389, cr),
            now=3000.0 + i)
        fired += _codes(got).count("RDP-032")
    c.eq(fired, 0, "one destination is not a scan")

    # -- IPv6 parity --------------------------------------------------------
    w, out6 = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_RDP)),
                        build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_RDP)),
                        src="2001:db8::10", dst="2001:db8::20")
    w, out4 = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_RDP)),
                        build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_RDP)))
    c.eq(_codes(out6), _codes(out4), "v6 and v4 produce identical code sequences")
    c.ok(bool(out6) and all(f.get("af") == 6 for f in out6),
         "v6 findings tagged af=6")
    c.ok(bool(out4) and all(f.get("af") == 4 for f in out4),
         "v4 findings tagged af=4")
    c.ok(bool(out6) and all(f.get("src", "").startswith("[") for f in out6),
         "v6 endpoints bracketed")

    # IPv6 extension headers do not hide the negotiation
    for ext in ([0], [43], [60], [0, 60]):
        w, oute = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_RDP)),
                            build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_RDP)),
                            src="2001:db8::10", dst="2001:db8::20", v6_ext=ext)
        c.eq(_codes(oute), _codes(out6), "v6 ext chain %r parsed" % ext)

    # -- the software port gate is the only rejector on the v6 path ---------
    w = RDPWatch(config=Config())
    got = w.handle_frame(build_frame("2001:db8::10", "2001:db8::20", 51000, 8443,
                                     build_x224_cr(neg=build_neg_req())))
    c.eq(got, [], "non-RDP IPv6 port produces no finding")
    c.eq(w.stats["port_rejected"], 1, "non-RDP IPv6 port counted as rejected")
    # ... and the same gate on IPv4, where BPF would normally have dropped it
    w = RDPWatch(config=Config())
    w.handle_frame(build_frame("192.0.2.10", "192.0.2.20", 51000, 8443,
                               build_x224_cr(neg=build_neg_req())))
    c.eq(w.stats["port_rejected"], 1, "non-RDP IPv4 port counted as rejected")
    # --ports admits a non-standard port on both stacks
    for src, dst in (("192.0.2.10", "192.0.2.20"), ("2001:db8::10", "2001:db8::20")):
        w = RDPWatch(config=Config(ports=[3389, 8443]))
        got = w.handle_frame(build_frame(src, dst, 51000, 8443,
                                         build_x224_cr(neg=build_neg_req())))
        c.eq(w.stats["port_rejected"], 0, "--ports admits 8443 (%s)" % src)

    # -- BPF shape ----------------------------------------------------------
    f = RDPWatch(config=Config()).bpf()
    c.ok(f.endswith("or ip6"), "BPF ends in a bare ip6 term")
    c.ok("ip6 and tcp" not in f, "BPF avoids the measured no-op form")
    c.ok("port 3389" in f, "BPF carries the port")
    c.eq(RDPWatch(config=Config(ports=[3389, 8443])).bpf(),
         "(tcp and (port 3389 or port 8443)) or ip6", "BPF with --ports")

    # -- segmentation -------------------------------------------------------
    cr = build_x224_cr(cookie=b"administrator", neg=build_neg_req(
        protocols=PROTOCOL_HYBRID))
    cc = build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_RDP))
    for mss in (512, 64, 17, 4, 1):
        w = RDPWatch(config=Config())
        for i in range(0, len(cr), mss):
            w.handle_frame(build_frame("192.0.2.10", "192.0.2.20", 51000, 3389,
                                       cr[i:i + mss]), now=5000.0)
        for i in range(0, len(cc), mss):
            w.handle_frame(build_frame("192.0.2.20", "192.0.2.10", 3389, 51000,
                                       cc[i:i + mss]), now=5000.0)
        c.ok("RDP-001" in _codes(w.findings), "MSS %d reassembles" % mss)
        c.ok("RDP-020" in _codes(w.findings), "MSS %d sees the cookie" % mss)

    # -- anchoring (LESSON O): a tap joining mid-stream ---------------------
    w = RDPWatch(config=Config())
    w.handle_frame(build_frame("192.0.2.10", "192.0.2.20", 51000, 3389,
                               b"\xde\xad\xbe\xef" + cr), now=5000.0)
    w.handle_frame(build_frame("192.0.2.20", "192.0.2.10", 3389, 51000, cc), now=5000.0)
    c.ok("RDP-001" in _codes(w.findings), "anchors past leading junk")
    # unanchorable junk up to the cap closes the direction rather than looping
    w = RDPWatch(config=Config(max_buffer=64))
    w.handle_frame(build_frame("192.0.2.10", "192.0.2.20", 51000, 3389,
                               b"\xff" * 128), now=5000.0)
    c.eq(w.findings, [], "unanchorable junk is silent")

    # -- one CR and one CC per flow, then the flow is done ------------------
    w = RDPWatch(config=Config())
    w.handle_frame(build_frame("192.0.2.10", "192.0.2.20", 51000, 3389, cr), now=6000.0)
    w.handle_frame(build_frame("192.0.2.20", "192.0.2.10", 3389, 51000, cc), now=6000.0)
    n = len(w.findings)
    w.handle_frame(build_frame("192.0.2.20", "192.0.2.10", 3389, 51000, cc), now=6001.0)
    c.eq(len(w.findings), n, "flow is done after the first CC")

    # -- roles are decided by PORT, not by who speaks first (LESSON AC) -----
    w = RDPWatch(config=Config())
    # server speaks first on the wire; its CC must still be read as a CC
    w.handle_frame(build_frame("192.0.2.20", "192.0.2.10", 3389, 51000, cc), now=7000.0)
    w.handle_frame(build_frame("192.0.2.10", "192.0.2.20", 51000, 3389, cr), now=7001.0)
    inv = _first(w.findings, "RDP-005")
    c.ok(bool(inv), "CC arriving first still produces an inventory")
    c.eq(inv.get("src"), "192.0.2.20:3389", "server endpoint identified by port")
    c.ok("no Connection Request observed" in inv.get("detail", {}).get("note", ""),
         "inventory says the CR was not seen")

    # -- VLAN tags ----------------------------------------------------------
    w = RDPWatch(config=Config())
    w.handle_frame(build_frame("192.0.2.10", "192.0.2.20", 51000, 3389, cr, vlan=0x0064),
                   now=8000.0)
    w.handle_frame(build_frame("192.0.2.20", "192.0.2.10", 3389, 51000, cc, vlan=0x0064),
                   now=8000.0)
    c.ok("RDP-001" in _codes(w.findings), "802.1Q tagged frame parsed")

    # -- flow table ceiling -------------------------------------------------
    w = RDPWatch(config=Config(max_flows=8))
    for i in range(40):
        w.handle_frame(build_frame("192.0.2.%d" % (i + 1), "192.0.2.200",
                                   40000 + i, 3389, cr), now=9000.0 + i)
    c.ok(len(w.flows) <= 8, "flow table respects max_flows")

    # -- tracker eviction with a non-scalar record --------------------------
    t = WindowSet(300.0, 5, 2)
    for i in range(10):
        t.add("src%d" % i, "u%d" % i, 1000.0 + i)
    c.ok(len(t.keys) <= 2, "WindowSet evicts under pressure")
    t2 = WindowCounter(60.0, 5, 2)
    for i in range(10):
        t2.add("src%d" % i, 1000.0 + i)
    c.ok(len(t2.keys) <= 2, "WindowCounter evicts under pressure")

    # -- AST guards ---------------------------------------------------------
    problems = ast_guard()
    c.ok(not problems, "ast_guard clean: %r" % (problems,))
    # non-vacuity: the guard must actually reject a transmit
    import tempfile  # noqa: PLC0415
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write("from scapy.all import sendp\n"
                 "def go(p):\n    sendp(p)\n"
                 "def go(p):\n    return p\n")
        tmp = fh.name
    probs = ast_guard(tmp)
    c.ok(any("sendp" in p for p in probs), "ast_guard catches a transmit")
    c.ok(any("redefined" in p for p in probs), "ast_guard catches a shadowed name")
    os.unlink(tmp)

    # -- declared codes match the registry (LESSON M) -----------------------
    decl = declared_codes()
    c.eq(decl, set(FINDINGS), "every registry code is reachable from _finding()")

    # -- parse errors never raise out of handle_frame -----------------------
    w = RDPWatch(config=Config())
    for junk in (b"", b"\x00", b"\xff" * 3, os.urandom(60)):
        try:
            w.handle_frame(junk)
            c.ok(True, "junk frame survived")
        except Exception as exc:
            c.ok(False, "junk frame raised %r" % exc)

    return c.report("self-test")


# ===========================================================================
# In-app adapter (Ragnar): a snapshot-over-pcap wrapper around the streaming
# engine above, an aggregator-shaped selftest(), and a Watchtower JSON-lines
# feed. Detection-only: the engine never builds or sends a frame (ast_guard()
# above asserts it over the parser/engine); this adapter only reads a short
# tcpdump capture and classifies the negotiation posture. RDP's TLS layer
# belongs to the TLS watcher and the CredSSP/NTLM exchange is encrypted and
# invisible here — everything reported comes from the cleartext X.224
# Connection Request / Confirm that precedes encryption.
#
# The standalone CLI (main()/argparse) is intentionally dropped in the vendored
# copy; do_rdp_watch() is the entry point and `self_test()` above remains as the
# module's offline reference suite (its ast_guard() source grep is not part of
# the in-app path, which legitimately shells out to tcpdump for capture — the
# same pattern the other in-app watchers use).
# ===========================================================================

import subprocess          # noqa: E402  (passive tcpdump snapshot)
import tempfile            # noqa: E402
import threading           # noqa: E402
from datetime import datetime, timezone   # noqa: E402
from shutil import which as _which        # noqa: E402

_RDP_SEV_RANK = {"info": 0, "notice": 1, "medium": 2, "high": 3}


def _rdp_verdict(findings):
    """Reduce the finding list to a card verdict + severity-ranked list.
    clean < posture (a medium) < exposure (a high). RDP carries no 'critical'."""
    ranked = sorted(findings,
                    key=lambda f: _RDP_SEV_RANK.get(f.get("severity"), 0),
                    reverse=True)
    worst = max((_RDP_SEV_RANK.get(f.get("severity"), 0) for f in findings),
                default=0)
    if worst >= _RDP_SEV_RANK["high"]:
        return "exposure", ranked
    if worst >= _RDP_SEV_RANK["medium"]:
        return "posture", ranked
    return "clean", ranked


# --- Watchtower feed --------------------------------------------------------
_WT_LOG_DIR = os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_WT_DEDUP_S = 300.0
_WT_EMIT_SEV = frozenset(("high",))
_wt_lock = threading.Lock()
_wt_seen = {}


def _emit_watchtower(result):
    """Append HIGH RDP negotiation/abuse findings to <log-dir>/rdp_watch.jsonl in
    the shape Watchtower.normalize() reads. Deduped per (code, subject) over the
    window. Best-effort."""
    if not result.get("success"):
        return
    verdict = result.get("verdict", "clean")
    iface = result.get("interface")
    now = time.time()
    iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    with _wt_lock:
        for f in result.get("findings", []):
            if f.get("severity") not in _WT_EMIT_SEV:
                continue
            code = f.get("code")
            subj = f.get("src") or f.get("dst")
            key = (code, subj)
            last = _wt_seen.get(key)
            if last is not None and now - last < _WT_DEDUP_S:
                continue
            _wt_seen[key] = now
            lines.append(json.dumps({
                "module": "rdp_watch", "ts": now, "iso": iso, "iface": iface,
                "severity": f.get("severity"), "code": code, "codes": [code],
                "src": subj, "cves": [],
                "summary": f.get("title"), "verdict": verdict}))
        if len(_wt_seen) > 4096:
            cutoff = now - _WT_DEDUP_S
            for k in [k for k, t in _wt_seen.items() if t < cutoff]:
                _wt_seen.pop(k, None)
    if not lines:
        return
    try:
        os.makedirs(_WT_LOG_DIR, exist_ok=True)
        with open(os.path.join(_WT_LOG_DIR, "rdp_watch.jsonl"), "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def _rdp_capture_pcap(interface, seconds, bpf):
    """tcpdump an X.224/RDP-negotiation snapshot to a temp classic-pcap file.
    Returns (path, error). snaplen 1500 keeps the full CR/CC + cookie intact.
    Detection-only: tcpdump captures, it never transmits."""
    if not _which("tcpdump"):
        return None, "tcpdump is not installed. Click Install to add it."
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        res = subprocess.run(
            ["timeout", str(int(seconds) + 3), "tcpdump", "-i", interface,
             "-nn", "-s", "1500", "-c", "20000", "-w", path, bpf],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=int(seconds) + 8)
        err = (res.stderr or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        err = ""
    except OSError as e:
        try:
            os.remove(path)
        except OSError:
            pass
        return None, "capture failed: {}".format(e)
    if (os.path.getsize(path) <= 24 and err
            and any(s in err.lower() for s in
                    ("permission", "no such device", "syntax error", "couldn't"))):
        try:
            os.remove(path)
        except OSError:
            pass
        return None, err.strip()[:200]
    return path, None


def do_rdp_watch(interface=None, seconds=20):
    """Passive RDP negotiation-posture + abuse scan (detection-only).

    One tcpdump snapshot on `interface`, replayed through the streaming engine.
    Reports how each session was negotiated (Standard RDP Security selected and
    MITM-able, TLS refused by the server, the legacy no-RDP_NEG path, and NLA
    requested-but-not-enforced), Restricted-Admin credential-less logon, a
    cleartext mstshash username (length only — the value never leaves the
    parser), and connection-level abuse (brute force, username spray, horizontal
    scan). Reads only the cleartext X.224 Connection Request / Confirm that
    precedes TLS or CredSSP; a routing token is never reported as a username, and
    sessions inside TLS/CredSSP are opaque. The TLS layer belongs to the TLS
    watcher and MadLicense to the RPC watcher; neither is duplicated. Never
    transmits."""
    if not interface:
        return {"success": False, "error": "no interface specified"}
    seconds = max(8, min(int(seconds or 20), 60))
    try:
        import scapy  # noqa: F401
    except Exception:
        return {"success": False, "interface": interface, "missing_tool": "scapy",
                "error": 'the Python "scapy" package is required for pcap dissection'}
    watch = RDPWatch(config=Config())
    bpf = watch.bpf()
    path, err = _rdp_capture_pcap(interface, seconds, bpf)
    if err:
        return {"success": False, "interface": interface, "error": err,
                "missing_tool": "tcpdump" if "not installed" in err else None}
    try:
        watch.run_capture(pcap=path)
    except Exception as e:
        return {"success": False, "interface": interface,
                "error": "capture parse failed: {}".format(type(e).__name__)}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    findings = list(watch.findings)
    verdict, ranked = _rdp_verdict(findings)
    reasons, seen = [], set()
    for f in ranked:
        if f["code"] in seen:
            continue
        seen.add(f["code"])
        subj = f.get("src") or f.get("dst") or "-"
        reasons.append("{}: {} [{}]".format(f["code"], f["title"], subj))
        if len(reasons) >= 8:
            break
    if not reasons:
        reasons = ["No Standard-Security / NLA-downgrade, Restricted-Admin, "
                   "cleartext-cookie or brute/spray/scan exposure detected on "
                   "this segment"]
    by_sev = {}
    for f in ranked:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    result = {
        "success": True, "interface": interface, "seconds": seconds,
        "verdict": verdict, "reasons": reasons, "findings": ranked,
        "by_severity": by_sev, "stats": watch.stats,
    }
    _emit_watchtower(result)
    return result


# ===========================================================================
# selftest — aggregator shape {'success', 'scenarios':[{name,pass,detail}]}.
# Builds real X.224 Connection Request / Confirm bytes with the module's own
# test-side encoders and pushes them through the production RDPWatch.handle_frame
# path. Dependency-free (no scapy).
# ===========================================================================
def selftest():
    scen = []

    def check(name, ok, detail=""):
        scen.append({"name": name, "pass": bool(ok), "detail": str(detail)})

    # Catalogue invariants.
    check("registry-size-13", len(FINDINGS) == 13, len(FINDINGS))
    check("attack-band",
          attack_class_codes() == {"RDP-030", "RDP-031", "RDP-032"},
          sorted(attack_class_codes()))

    # RDP-001 Standard RDP Security selected (MITM-able).
    _, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_RDP)),
                       build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_RDP)))
    check("rdp-001-standard-security", "RDP-001" in _codes(out), _codes(out))

    # RDP-002 server refuses TLS (and does not also raise RDP-001).
    _, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_SSL)),
                       build_x224_cc(neg=build_neg_failure(2)))
    check("rdp-002-ssl-not-allowed",
          "RDP-002" in _codes(out) and "RDP-001" not in _codes(out), _codes(out))

    # RDP-004 NLA requested, SSL selected (NLA not enforced).
    _, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_HYBRID)),
                       build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_SSL)))
    check("rdp-004-nla-not-enforced", "RDP-004" in _codes(out), _codes(out))

    # Clean NLA session is quiet (FP guard) + positive 'secure' verdict.
    _, out = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_HYBRID)),
                       build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_HYBRID)))
    inv = _first(out, "RDP-005")
    check("rdp-clean-nla-quiet",
          set(_codes(out)) == {"RDP-005"}
          and inv.get("detail", {}).get("secure") is True, _codes(out))

    # RDP-010 Restricted Admin requested.
    _, out = _run_pair(
        build_x224_cr(neg=build_neg_req(
            flags=NEG_REQ_RESTRICTED_ADMIN_MODE_REQUIRED, protocols=PROTOCOL_HYBRID)),
        build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_HYBRID)))
    check("rdp-010-restricted-admin", "RDP-010" in _codes(out), _codes(out))

    # RDP-020 cleartext cookie — length only, value never emitted.
    _, out = _run_pair(build_x224_cr(cookie=b"administrator", neg=build_neg_req()),
                       build_x224_cc(neg=build_neg_rsp()))
    check("rdp-020-cookie-length",
          _first(out, "RDP-020").get("detail", {}).get("username_length")
          == len(b"administrator"), _codes(out))
    check("rdp-020-username-never-emitted",
          not _emits_value(out, "administrator"), "")

    # A routing token (msts=) is load-balancer data, never a username.
    _, out = _run_pair(
        build_x224_cr(routing=b"3640205228.15629.0000", neg=build_neg_req()),
        build_x224_cc(neg=build_neg_rsp()))
    check("rdp-routing-token-not-username", "RDP-020" not in _codes(out), _codes(out))

    # RDP-040 malformed negotiation (bad NEG length).
    _, out = _run_pair(build_x224_cr(neg=build_neg_req(length=9)), None)
    check("rdp-040-malformed", "RDP-040" in _codes(out), _codes(out))

    # RDP-030 brute force latches exactly once.
    w = RDPWatch(config=Config(bruteforce_count=4, bruteforce_window=60.0))
    cr = build_x224_cr(neg=build_neg_req())
    fired = sum(_codes(w.handle_frame(
        build_frame("192.0.2.10", "192.0.2.20", 40000 + i, 3389, cr),
        now=1000.0 + i)).count("RDP-030") for i in range(10))
    check("rdp-030-bruteforce-latch", fired == 1, fired)

    # RDP-031 username spray latches once; usernames never emitted.
    w = RDPWatch(config=Config(spray_users=3, spray_window=300.0))
    fired = 0
    for i, name in enumerate([b"alice", b"bob", b"carol", b"dave", b"eve"]):
        pdu = build_x224_cr(cookie=name, neg=build_neg_req())
        fired += _codes(w.handle_frame(
            build_frame("192.0.2.30", "192.0.2.40", 41000 + i, 3389, pdu),
            now=2000.0 + i)).count("RDP-031")
    check("rdp-031-spray-latch", fired == 1, fired)
    check("rdp-031-no-username-leak",
          not any(_emits_value(w.findings, n) for n in ("alice", "bob", "carol")), "")

    # RDP-032 horizontal scan latches exactly once.
    w = RDPWatch(config=Config(scan_targets=5, scan_window=60.0))
    fired = sum(_codes(w.handle_frame(
        build_frame("192.0.2.50", "198.51.100.%d" % (i + 1), 42000 + i, 3389, cr),
        now=3000.0 + i)).count("RDP-032") for i in range(12))
    check("rdp-032-scan-latch", fired == 1, fired)

    # IPv6 parity: identical code sequence, findings tagged af=6.
    _, out6 = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_RDP)),
                        build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_RDP)),
                        src="2001:db8::10", dst="2001:db8::20")
    _, out4 = _run_pair(build_x224_cr(neg=build_neg_req(protocols=PROTOCOL_RDP)),
                        build_x224_cc(neg=build_neg_rsp(selected=PROTOCOL_RDP)))
    check("rdp-ipv6-parity",
          _codes(out6) == _codes(out4) and bool(out6)
          and all(f.get("af") == 6 for f in out6), (_codes(out6), _codes(out4)))

    return {"success": all(s["pass"] for s in scen), "scenarios": scen}
