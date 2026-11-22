#!/usr/bin/env python3
"""ripwatch - passive RIP/RIPng routing-plane security monitor (Ragnar).

Passive-only. Never transmits. Covers RIPv1/RIPv2 (UDP/520, IPv4) and
RIPng (UDP/521, IPv6). Detects route injection / hijack, authentication
posture, and structural malformation. Sibling to ospfwatch / eigrpwatch /
isiswatch in the IGP family.

Dual-stack by protocol pairing (prime directive): RIPv1/v2 have no IPv6
form and RIPng has no IPv4 form, so the v4 codes cover RIP and the v6 codes
cover RIPng; every ABUSE rule exists on both planes with parity tests.
Auth-posture codes are RIPv2-only (RIPng has no native auth) and the
off-link code is RIPng-only (RFC 2080); these are the documented
"apply IPv6 only where applicable" cases, not gaps.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "0.1.0-dev"

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
RIP_PORT = 520
RIPNG_PORT = 521
RIP_MCAST_V4 = "224.0.0.9"
RIPNG_MCAST_V6 = "ff02::9"

CMD_REQUEST = 1
CMD_RESPONSE = 2
# 3=traceon,4=traceoff (obsolete), 5=reserved(Sun), 6=?-deprecated
CMD_VALID = {CMD_REQUEST, CMD_RESPONSE}
CMD_NAMES = {
    1: "Request", 2: "Response", 3: "TraceOn", 4: "TraceOff",
    5: "Reserved(Sun)", 6: "Poll", 7: "PollEntry", 8: "UpdateRequest",
    9: "UpdateResponse", 10: "UpdateAcknowledge",
}

AFI_IP = 2
AFI_AUTH = 0xFFFF
AFI_UNSPEC = 0  # full-table request marker (AFI 0, metric 16)

METRIC_INFINITY = 16

# RIPv2 auth types (first RTE, AFI 0xFFFF)
AUTH_SIMPLE = 2       # 16-byte cleartext password
AUTH_CRYPTO = 3       # RFC 2082 (MD5) / RFC 4822 (HMAC-SHA)  keyed header
AUTH_TRAILER = 1      # trailing auth RTE (AFI 0xFFFF, type 1) carrying digest

# auth-data-length -> algorithm (RFC 2082 / RFC 4822)
AUTH_ALG_BY_LEN = {16: "MD5", 20: "HMAC-SHA1", 32: "HMAC-SHA256",
                   48: "HMAC-SHA384", 64: "HMAC-SHA512"}

# IPv6 extension headers (bounded walk - ciscoguard set)
EH_HOPOPTS = 0
EH_ROUTING = 43
EH_FRAGMENT = 44
EH_AH = 51
EH_DSTOPTS = 60
EH_NONXT = 59
V6_SKIPPABLE = {EH_HOPOPTS, EH_ROUTING, EH_DSTOPTS, EH_AH}
MAX_EH_LINKS = 8
IPPROTO_UDP = 17

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8

MAX_RTES = 25  # RFC 1058/2453: 25 RTEs per message (ceiling for a 512B datagram)

# ---------------------------------------------------------------------------
# Finding-code registry
#
# Numeric bands (LESSON AK - never string-compare codes):
#   001-099  posture
#   100-199  attack / abuse
#   120-199  structural  (subset of attack band start at 120 by convention)
# attack_class is decided by int(code.split("-")[1]) >= 100.
# ---------------------------------------------------------------------------
SEV = ("info", "low", "medium", "high", "critical")
CONF = ("possible", "probable", "confirmed")


@dataclass(frozen=True)
class CodeSpec:
    code: str
    severity: str
    confidence: str
    title: str
    cves: Tuple[str, ...] = ()


def _spec(code, sev, conf, title, cves=()):
    assert sev in SEV, sev
    assert conf in CONF, conf
    return CodeSpec(code, sev, conf, title, tuple(cves))


SPECS: Dict[str, CodeSpec] = {s.code: s for s in [
    # ---- posture (001-099) ----
    _spec("RIP-001", "high", "confirmed", "RIP running unauthenticated"),
    _spec("RIP-002", "high", "confirmed", "RIPv2 simple-password auth (cleartext secret on wire)"),
    _spec("RIP-003", "medium", "confirmed", "RIPv2 keyed MD5 auth (RFC 2082, dated crypto)"),
    _spec("RIP-004", "low", "confirmed", "RIPv2 keyed HMAC-SHA auth"),
    _spec("RIP-005", "info", "confirmed", "RIPng without IPsec protection (native, no auth)"),
    _spec("RIP-006", "info", "confirmed", "RIPng wrapped in IPsec AH/ESP"),
    _spec("RIP-007", "high", "probable", "RIP authentication downgrade"),
    _spec("RIP-008", "medium", "probable", "RIP authentication asymmetry between peers"),
    _spec("RIP-009", "medium", "confirmed", "RIPv1 in use (deprecated, classful, no auth)"),
    # ---- attack / abuse (100-119) ----
    _spec("RIP-101", "high", "probable", "Rogue RIP responder (source not in baseline)"),
    _spec("RIP-102", "high", "possible", "RIP route injection (prefix not previously advertised)"),
    _spec("RIP-103", "high", "probable", "RIP metric-undercut hijack (better metric from new source)"),
    _spec("RIP-104", "high", "probable", "RIP default-route injection"),
    _spec("RIP-105", "high", "probable", "RIP mass poison / metric-16 withdrawal storm"),
    _spec("RIP-106", "high", "confirmed", "RIPng off-link violation (RFC 2080 source/hoplimit/port)"),
    _spec("RIP-107", "medium", "probable", "RIP full-table request (routing-table recon)",
          ("CVE-2006-2223",)),
    _spec("RIP-108", "medium", "possible", "RIP unsolicited unicast Response (targeted injection)"),
    _spec("RIP-109", "high", "probable", "RIPv1 Response where authenticated RIPv2 is the norm (auth-bypass injection)",
          ("CVE-2006-2224",)),
    # ---- structural (120-199) ----
    _spec("RIP-120", "high", "confirmed", "Malformed RIP: RTE count/length overruns datagram",
          ("CVE-2026-102019", "CVE-2013-3470", "CVE-2012-4091")),
    _spec("RIP-121", "medium", "confirmed", "RIPv1 must-be-zero field non-zero (RFC 1058)"),
    _spec("RIP-122", "medium", "confirmed", "RIP invalid/obsolete command"),
    _spec("RIP-123", "low", "confirmed", "RIP metric out of range (>16)"),
    _spec("RIP-124", "medium", "confirmed", "RIP RTE count exceeds 25-per-message ceiling"),
    _spec("RIP-125", "high", "confirmed", "RIPv2 authentication field malformed"),
    _spec("RIP-126", "low", "confirmed", "RIP protocol-version anomaly"),
]}

# proto tag per code (LESSON AK - lookup, never derive from string order)
CODE_PROTO = {c: "rip" for c in SPECS}


def attack_class_codes() -> set:
    """Codes in the attack/abuse/structural band. Numeric, not lexicographic."""
    return {c for c in SPECS if int(c.split("-")[1]) >= 100}


def posture_codes() -> set:
    return {c for c in SPECS if int(c.split("-")[1]) < 100}


# ---------------------------------------------------------------------------
# Finding record
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    code: str
    af: str                       # "ipv4" | "ipv6"
    src: str                      # rendered endpoint (bracketed for v6)
    dst: str
    detail: Dict[str, Any] = field(default_factory=dict)
    ts: float = 0.0
    rolled_up: bool = False
    distinct_sources: int = 0

    def to_dict(self) -> Dict[str, Any]:
        spec = SPECS[self.code]
        d = {
            "code": self.code,
            "severity": spec.severity,
            "confidence": spec.confidence,
            "title": spec.title,
            "af": self.af,
            "src": self.src,
            "dst": self.dst,
            "ts": round(self.ts, 6),
            "detail": self.detail,
        }
        if spec.cves:
            d["cves"] = list(spec.cves)
        if self.rolled_up:
            d["rolled_up"] = True
            d["distinct_sources"] = self.distinct_sources
        return d


# ---------------------------------------------------------------------------
# Endpoint rendering (LESSON AE - bracket v6, never f"{ip}:{port}")
# ---------------------------------------------------------------------------
def render_endpoint(ip: str, port: Optional[int], af: str) -> str:
    if port is None:
        return ip
    if af == "ipv6":
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def parse_endpoint(s: str) -> Tuple[str, Optional[int]]:
    """Round-trip inverse of render_endpoint (used by the LESSON AE test)."""
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, None
    # ipv4 - rightmost colon splits host:port, but a bare v4 has no colon
    if s.count(":") == 1:
        host, _, p = s.partition(":")
        return host, int(p)
    return s, None


# ---------------------------------------------------------------------------
# Parsed message structures
# ---------------------------------------------------------------------------
@dataclass
class RouteEntry:
    afi: int
    route_tag: int
    addr: str              # v4 dotted / v6 prefix
    mask: Optional[str]    # v4 only
    next_hop: Optional[str]
    prefix_len: Optional[int]  # ripng only
    metric: int


@dataclass
class AuthInfo:
    present: bool = False
    auth_type: int = 0            # 2 simple, 3 crypto
    algorithm: str = ""           # derived from auth-data length
    key_id: int = 0
    seq_num: int = 0
    auth_data_len: int = 0
    malformed: str = ""           # non-empty => structural problem


@dataclass
class RipMessage:
    family: str                   # "rip" (v1/v2) | "ripng"
    version: int
    command: int
    entries: List[RouteEntry]
    auth: AuthInfo
    rte_count_declared: int       # entries the length implies
    errors: List[Tuple[str, str]] # (code, note) structural problems
    # L3/L4 context filled by the decode chain
    af: str = "ipv4"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    hop_limit: Optional[int] = None  # ipv6 only
    ttl: Optional[int] = None        # ipv4 only
    ipsec_ah: bool = False           # ipv6: AH (proto 51) seen in the EH chain


class ParseError(Exception):
    pass


# ---------------------------------------------------------------------------
# RIP (v1/v2) parser  -- UDP/520, IPv4
# ---------------------------------------------------------------------------
def parse_rip(payload: bytes) -> RipMessage:
    errors: List[Tuple[str, str]] = []
    if len(payload) < 4:
        raise ParseError("short RIP header")
    # read command/version from raw octets (LESSON AD/AG: never trust a
    # dispatched attribute; hand-rolled so we read the bytes directly)
    command = payload[0]
    version = payload[1]
    must_zero = struct.unpack("!H", payload[2:4])[0]

    if command not in CMD_VALID:
        errors.append(("RIP-122", f"command={command} ({CMD_NAMES.get(command,'?')})"))
    if version not in (1, 2):
        errors.append(("RIP-126", f"version={version}"))

    body = payload[4:]

    # A keyed (crypto) auth packet carries a trailing authentication block
    # (AFI 0xFFFF, type 1, + digest) that is NOT part of the 20-byte RTE grid
    # and is only grid-aligned by accident for MD5 (4+16=20). Carve it off
    # using the RFC 2082/4822 packet-length field before the grid check, or the
    # multiple-of-20 test false-positives RIP-120 on every HMAC-SHA session.
    grid_end = len(body)
    if len(body) >= 20 and struct.unpack("!H", body[0:2])[0] == AFI_AUTH \
            and struct.unpack("!H", body[2:4])[0] == AUTH_CRYPTO:
        pkt_len = struct.unpack("!H", body[4:6])[0]      # from RIP header start
        auth_data_len = body[7]
        trailer_start = pkt_len - 4                       # into body
        if 20 <= trailer_start <= len(body):
            grid_end = trailer_start
            trailer = body[trailer_start:]
            exp = 4 + auth_data_len
            if len(trailer) != exp or trailer[0:2] != b"\xff\xff":
                errors.append(("RIP-125",
                               f"auth trailer {len(trailer)}B != expected {exp}B"))
        else:
            errors.append(("RIP-125", f"auth packet-length {pkt_len} out of range"))

    grid = body[:grid_end]
    rem = len(grid) % 20
    declared = len(grid) // 20
    if rem != 0:
        errors.append(("RIP-120", f"RTE area {len(grid)}B not a multiple of 20 ({rem}B trailing)"))
    if declared > MAX_RTES:
        errors.append(("RIP-124", f"{declared} RTEs > {MAX_RTES} ceiling"))

    auth = AuthInfo()
    entries: List[RouteEntry] = []

    off = 0
    first = True
    while off + 20 <= len(grid):
        rte = grid[off:off + 20]
        afi = struct.unpack("!H", rte[0:2])[0]

        if first and afi == AFI_AUTH:
            auth = _parse_auth_rte(rte, grid[off:], errors, version)
            first = False
            off += 20
            continue
        first = False

        # route entry
        route_tag = struct.unpack("!H", rte[2:4])[0]
        addr = socket.inet_ntoa(rte[4:8])
        if version == 1:
            # RIPv1: route_tag, mask, next_hop MUST be zero (RFC 1058)
            if rte[2:4] != b"\x00\x00" or rte[8:12] != b"\x00\x00\x00\x00" \
               or rte[12:16] != b"\x00\x00\x00\x00":
                errors.append(("RIP-121", f"RIPv1 non-zero must-be-zero field in RTE @ {off}"))
            mask = None
            next_hop = None
        else:
            mask = socket.inet_ntoa(rte[8:12])
            next_hop = socket.inet_ntoa(rte[12:16])
        metric = struct.unpack("!I", rte[16:20])[0]
        if metric > METRIC_INFINITY:
            errors.append(("RIP-123", f"metric={metric} @ RTE {off}"))
        entries.append(RouteEntry(afi, route_tag, addr, mask, next_hop, None, metric))
        off += 20

    return RipMessage(
        family="rip", version=version, command=command, entries=entries,
        auth=auth, rte_count_declared=declared, errors=errors,
    )


def _parse_auth_rte(rte: bytes, rest: bytes, errors, version) -> AuthInfo:
    a = AuthInfo(present=True)
    auth_type = struct.unpack("!H", rte[2:4])[0]
    a.auth_type = auth_type
    if version != 2:
        errors.append(("RIP-126", "auth RTE present but version != 2"))
    if auth_type == AUTH_SIMPLE:
        a.algorithm = "simple-password"
        # 16 bytes cleartext in rte[4:20]
    elif auth_type == AUTH_CRYPTO:
        # keyed header: rte[4:6]=packet length, rte[6]=key id,
        # rte[7]=auth data length, rte[8:12]=sequence number
        a.key_id = rte[6]
        a.auth_data_len = rte[7]
        a.seq_num = struct.unpack("!I", rte[8:12])[0]
        a.algorithm = AUTH_ALG_BY_LEN.get(a.auth_data_len, f"unknown({a.auth_data_len})")
        if a.auth_data_len not in AUTH_ALG_BY_LEN:
            a.malformed = f"auth_data_len={a.auth_data_len} matches no known algorithm"
            errors.append(("RIP-125", a.malformed))
        # trailer length is validated in parse_rip (needs the whole datagram)
    else:
        a.malformed = f"unknown auth type {auth_type}"
        errors.append(("RIP-125", a.malformed))
    return a


# ---------------------------------------------------------------------------
# RIPng parser  -- UDP/521, IPv6
# ---------------------------------------------------------------------------
def parse_ripng(payload: bytes) -> RipMessage:
    errors: List[Tuple[str, str]] = []
    if len(payload) < 4:
        raise ParseError("short RIPng header")
    command = payload[0]
    version = payload[1]
    must_zero = struct.unpack("!H", payload[2:4])[0]

    if command not in CMD_VALID:
        errors.append(("RIP-122", f"command={command} ({CMD_NAMES.get(command,'?')})"))
    if version != 1:
        errors.append(("RIP-126", f"ripng version={version}"))
    if must_zero != 0:
        errors.append(("RIP-121", f"ripng reserved field={must_zero}"))

    body = payload[4:]
    rem = len(body) % 20
    declared = len(body) // 20
    if rem != 0:
        errors.append(("RIP-120", f"RTE area {len(body)}B not a multiple of 20 ({rem}B trailing)"))
    if declared > MAX_RTES:
        errors.append(("RIP-124", f"{declared} RTEs > {MAX_RTES} ceiling"))

    entries: List[RouteEntry] = []
    off = 0
    while off + 20 <= len(body):
        rte = body[off:off + 20]
        prefix = rte[0:16]
        route_tag = struct.unpack("!H", rte[16:18])[0]
        prefix_len = rte[18]
        metric = rte[19]
        addr = socket.inet_ntop(socket.AF_INET6, prefix)
        if metric == 0xFF:
            # next-hop RTE (RFC 2080 s2.1.1): metric 0xFF, prefix is the next hop
            entries.append(RouteEntry(AFI_IP, route_tag, addr, None, addr, prefix_len, metric))
        else:
            if metric > METRIC_INFINITY and metric != 0xFF:
                errors.append(("RIP-123", f"ripng metric={metric} @ RTE {off}"))
            if prefix_len > 128:
                errors.append(("RIP-120", f"ripng prefix_len={prefix_len} > 128 @ RTE {off}"))
            entries.append(RouteEntry(AFI_IP, route_tag, addr, None, None, prefix_len, metric))
        off += 20

    return RipMessage(
        family="ripng", version=version, command=command, entries=entries,
        auth=AuthInfo(), rte_count_declared=declared, errors=errors, af="ipv6",
    )


# ---------------------------------------------------------------------------
# Serializers (LESSON A - tested against the parsers, each other's inverse)
# ---------------------------------------------------------------------------
def build_rip(command: int, version: int, entries: List[RouteEntry],
              auth: Optional[AuthInfo] = None, simple_pw: bytes = b"",
              crypto: Optional[dict] = None) -> bytes:
    out = struct.pack("!BBH", command, version, 0)
    if auth and auth.present:
        if auth.auth_type == AUTH_SIMPLE:
            pw = (simple_pw + b"\x00" * 16)[:16]
            out += struct.pack("!HH", AFI_AUTH, AUTH_SIMPLE) + pw
        elif auth.auth_type == AUTH_CRYPTO:
            c = crypto or {}
            pkt_len = c.get("pkt_len", 0)
            # RFC 2082: the keyed auth entry is a full 20-byte RTE -
            # 12 bytes of fields + 8 reserved(zero) bytes.
            out += struct.pack("!HHHBBI", AFI_AUTH, AUTH_CRYPTO, pkt_len,
                               auth.key_id, auth.auth_data_len, auth.seq_num)
            out += b"\x00" * 8
    for e in entries:
        out += struct.pack("!HH", e.afi, e.route_tag)
        out += socket.inet_aton(e.addr)
        if version == 2:
            out += socket.inet_aton(e.mask or "0.0.0.0")
            out += socket.inet_aton(e.next_hop or "0.0.0.0")
        else:
            out += b"\x00" * 8
        out += struct.pack("!I", e.metric)
    if crypto and crypto.get("trailer_digest"):
        d = crypto["trailer_digest"]
        out += struct.pack("!HH", AFI_AUTH, AUTH_TRAILER) + d
    return out


def build_ripng(command: int, entries: List[RouteEntry]) -> bytes:
    out = struct.pack("!BBH", command, 1, 0)
    for e in entries:
        out += socket.inet_pton(socket.AF_INET6, e.addr)
        out += struct.pack("!HBB", e.route_tag, e.prefix_len or 0, e.metric)
    return out


# ---------------------------------------------------------------------------
# L2/L3/L4 decode chain with bounded IPv6 EH walk
# ---------------------------------------------------------------------------
def _walk_v6_exthdr(buf: bytes, cur: int, nxt: int) -> Tuple[int, int, bool]:
    """Return (l4_proto, l4_offset, saw_ah) after a bounded EH walk, or
    (nxt, cur, False) when nxt is already an upper-layer proto. Raises
    ParseError on overrun. saw_ah records IPsec AH (proto 51) in the chain."""
    links = 0
    saw_ah = False
    while nxt in V6_SKIPPABLE or nxt == EH_FRAGMENT:
        if links >= MAX_EH_LINKS:
            raise ParseError("IPv6 EH chain too long")
        if cur + 2 > len(buf):
            raise ParseError("truncated EH")
        this = nxt
        nxt = buf[cur]
        if this == EH_AH:
            saw_ah = True
            # RFC 2402: AH length field counts 4-octet units, minus 2
            ext_len = (buf[cur + 1] + 2) * 4
        elif this == EH_FRAGMENT:
            ext_len = 8
        else:
            ext_len = (buf[cur + 1] + 1) * 8
        cur += ext_len
        links += 1
        if nxt == EH_NONXT:
            return (EH_NONXT, cur, saw_ah)
    return (nxt, cur, saw_ah)


def decode_frame(frame: bytes) -> Optional[RipMessage]:
    """Decode an Ethernet frame to a RipMessage, or None if not RIP/RIPng.

    Raises ParseError only on a frame that *looks* like RIP but is malformed
    at L3/L4; a non-RIP frame returns None quietly.
    """
    if len(frame) < 14:
        return None
    off = 12
    etype = struct.unpack("!H", frame[off:off + 2])[0]
    off += 2
    # VLAN tags (one or two). NB LESSON F: outer tag may be stripped by the
    # kernel before BPF on AF_PACKET; the parser still copes if present.
    while etype in (ETH_P_8021Q, ETH_P_8021AD):
        if off + 4 > len(frame):
            return None
        etype = struct.unpack("!H", frame[off + 2:off + 4])[0]
        off += 4

    if etype == ETH_P_IP:
        return _decode_v4(frame, off)
    if etype == ETH_P_IPV6:
        return _decode_v6(frame, off)
    return None


def _udp_payload(frame: bytes, l4: int, ulen: int) -> bytes:
    """UDP payload bounded by the header's length field (RFC 768). Falls back
    to end-of-frame when the declared length is absurd or overruns the capture,
    so a lying length degrades to the available bytes rather than crashing."""
    end = len(frame)
    if 8 <= ulen <= (end - l4):
        end = l4 + ulen
    return frame[l4 + 8:end]


def _decode_v4(frame: bytes, off: int) -> Optional[RipMessage]:
    if off + 20 > len(frame):
        return None
    vihl = frame[off]
    if (vihl >> 4) != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or off + ihl > len(frame):
        return None
    proto = frame[off + 9]
    ttl = frame[off + 8]
    src = socket.inet_ntoa(frame[off + 12:off + 16])
    dst = socket.inet_ntoa(frame[off + 16:off + 20])
    if proto != IPPROTO_UDP:
        return None
    l4 = off + ihl
    if l4 + 8 > len(frame):
        return None
    sport, dport, ulen, _ = struct.unpack("!HHHH", frame[l4:l4 + 8])
    if RIP_PORT not in (sport, dport):
        return None
    # Bound the payload by the UDP length, not end-of-frame: on the live path
    # the kernel/NIC pads frames shorter than 60 bytes and frame[l4+8:] would
    # include that padding, corrupting the RTE-grid check. A lying/oversized
    # UDP length falls back to the available bytes (handled as a fuzz case).
    payload = _udp_payload(frame, l4, ulen)
    msg = parse_rip(payload)
    msg.af = "ipv4"
    msg.src_ip, msg.dst_ip = src, dst
    msg.src_port, msg.dst_port = sport, dport
    msg.ttl = ttl
    return msg


def _decode_v6(frame: bytes, off: int) -> Optional[RipMessage]:
    if off + 40 > len(frame):
        return None
    if (frame[off] >> 4) != 6:
        return None
    nxt = frame[off + 6]
    hop_limit = frame[off + 7]
    src = socket.inet_ntop(socket.AF_INET6, frame[off + 8:off + 24])
    dst = socket.inet_ntop(socket.AF_INET6, frame[off + 24:off + 40])
    l4proto, l4, saw_ah = _walk_v6_exthdr(frame, off + 40, nxt)
    if l4proto != IPPROTO_UDP:
        return None
    if l4 + 8 > len(frame):
        return None
    sport, dport, ulen, _ = struct.unpack("!HHHH", frame[l4:l4 + 8])
    # port 521 decided AFTER the EH walk (bare ip6 admitted everything)
    if RIPNG_PORT not in (sport, dport):
        return None
    payload = _udp_payload(frame, l4, ulen)   # UDP-length bound (NIC padding)
    msg = parse_ripng(payload)
    msg.af = "ipv6"
    msg.src_ip, msg.dst_ip = src, dst
    msg.src_port, msg.dst_port = sport, dport
    msg.hop_limit = hop_limit
    msg.ipsec_ah = saw_ah
    return msg


# ---------------------------------------------------------------------------
# Detector / session state
# ---------------------------------------------------------------------------
@dataclass
class Config:
    learn_seconds: float = 300.0
    learn_packets: int = 50
    metric16_threshold: int = 10     # RTEs at metric 16 in one message -> storm
    metric16_window_rate: int = 40   # metric-16 RTEs / window across messages
    rate_window_s: float = 10.0
    request_reply_window_s: float = 180.0  # unicast reply-to-request grace
    orphan_code_budget: int = 10     # distinct sources per code before rollup
    max_sources: int = 50000         # baseline-table ceilings (bound memory)
    max_prefixes: int = 200000
    prune_interval: int = 2000       # messages between prunes
    known_prefixes: Tuple[str, ...] = ()   # operator allowlist (never gates, escalates)
    strict_structural: bool = True

    @staticmethod
    def from_json(path: str) -> "Config":
        with open(path) as f:
            d = json.load(f)
        c = Config()
        for k, v in d.items():
            if hasattr(c, k):
                setattr(c, k, tuple(v) if isinstance(v, list) else v)
        return c


@dataclass
class SourceState:
    first_seen: float
    af: str
    emits_response: bool = False
    auth_type: Optional[int] = None   # last observed auth posture
    saw_unauth: bool = False
    saw_auth: bool = False


class Ripwatch:
    def __init__(self, config: Optional[Config] = None,
                 emit: Optional[Callable[[Finding], None]] = None,
                 start_time: Optional[float] = None):
        self.cfg = config or Config()
        self._emit_cb = emit
        self.findings: List[Finding] = []
        self.t0 = start_time if start_time is not None else time.time()
        # baseline
        self.sources: Dict[Tuple[str, str], SourceState] = {}
        # (prefix, af) -> dict[source_ip] = metric   (learned advertisers)
        self.prefix_table: Dict[Tuple[str, str], Dict[str, int]] = {}
        # posture latch: emit posture once per (src, af, code)
        self._posture_seen: set = set()
        # recent requesters (ip, af) -> ts: a unicast Response back to one of
        # these within REQUEST_REPLY_WINDOW_S is a legitimate reply, not a
        # targeted injection (RFC 2453 - responses to a Request are unicast).
        self._recent_requests: Dict[Tuple[str, str], float] = {}
        # rate / latch bookkeeping
        self._metric16: Dict[Tuple[str, str], List[float]] = {}
        self._latched: set = set()          # (src, af, code) sustained-alert latch
        self._orphan: Dict[Tuple[str, str], set] = {}  # (code, af) -> sources
        self._rolled: set = set()
        self.stats = {"frames": 0, "rip": 0, "ripng": 0, "findings": 0,
                      "parse_errors": 0}
        self._armed_latched = False

    # -- phase --------------------------------------------------------------
    # A packet is a LEARN packet while the latch is unset. The latch flips
    # (freezing the baseline) only AFTER the learn quota is exceeded, so the
    # Nth learn packet still populates the baseline rather than being judged
    # against an empty one. learn_packets=0 / learn_seconds=0 arm immediately.
    def _should_arm(self, now: float) -> bool:
        seen = self.stats["rip"] + self.stats["ripng"]
        return (now - self.t0) >= self.cfg.learn_seconds or seen > self.cfg.learn_packets

    def _armed(self, now: float) -> bool:
        return self._armed_latched

    # -- emission -----------------------------------------------------------
    def _emit(self, code: str, msg: RipMessage, now: float,
              detail: Optional[dict] = None, latch_key=None):
        if latch_key is not None:
            if latch_key in self._latched:
                return
            self._latched.add(latch_key)

        # orphan budget: source spoofing defeats per-source latching, so past
        # orphan_code_budget distinct sources for a (code, af) we stop emitting
        # per-source findings and emit ONE rollup carrying the distinct count
        # (bfdwatch flood lesson). Applies to codes with no latch_key only.
        bkey = (code, msg.af)
        srcs = self._orphan.setdefault(bkey, set())
        rolled = False
        if latch_key is None:
            if msg.src_ip not in srcs and len(srcs) >= self.cfg.orphan_code_budget:
                if bkey in self._rolled:
                    return  # already rolled up this (code, af)
                self._rolled.add(bkey)
                rolled = True
            srcs.add(msg.src_ip)

        f = Finding(
            code=code, af=msg.af,
            src=render_endpoint(msg.src_ip, msg.src_port or None, msg.af),
            dst=render_endpoint(msg.dst_ip, msg.dst_port or None, msg.af),
            detail=detail or {}, ts=now,
            rolled_up=rolled, distinct_sources=(len(srcs) + 1) if rolled else 0,
        )
        self.findings.append(f)
        self.stats["findings"] += 1
        if self._emit_cb:
            self._emit_cb(f)

    def _emit_posture(self, code, msg, now, detail=None):
        key = (msg.src_ip, msg.af, code)
        if key in self._posture_seen:
            return
        self._posture_seen.add(key)
        self._emit(code, msg, now, detail)

    # -- top-level feed -----------------------------------------------------
    def feed_frame(self, frame: bytes, ts: Optional[float] = None):
        now = ts if ts is not None else time.time()
        self.stats["frames"] += 1
        try:
            msg = decode_frame(frame)
        except ParseError as e:
            self.stats["parse_errors"] += 1
            return
        if msg is None:
            return
        self.feed_message(msg, now)

    def feed_message(self, msg: RipMessage, now: float):
        if msg.family == "ripng":
            self.stats["ripng"] += 1
        else:
            self.stats["rip"] += 1

        # arm transition: freeze the learned responder set exactly once, after
        # the learn quota is exceeded.
        if not self._armed_latched and self._should_arm(now):
            self.arm_now()
            self._armed_latched = True

        if (self.stats["rip"] + self.stats["ripng"]) % self.cfg.prune_interval == 0:
            self._prune(now)

        # structural problems fire regardless of phase
        for code, note in msg.errors:
            self._emit(code, msg, now, {"note": note})

        self._check_offlink(msg, now)       # ripng only (RFC 2080)
        self._check_posture(msg, now)
        self._check_request(msg, now)
        self._check_responses(msg, now)

    # -- RFC 2080 off-link (RIPng only) ------------------------------------
    def _check_offlink(self, msg: RipMessage, now: float):
        if msg.family != "ripng":
            return
        problems = []
        try:
            src = ipaddress.IPv6Address(msg.src_ip)
            if not src.is_link_local:
                problems.append(f"source {msg.src_ip} not link-local")
        except ValueError:
            pass
        if msg.hop_limit is not None and msg.hop_limit != 255:
            problems.append(f"hop limit {msg.hop_limit} != 255")
        if msg.src_port != RIPNG_PORT:
            problems.append(f"source port {msg.src_port} != 521")
        if problems:
            self._emit("RIP-106", msg, now, {"violations": problems})

    # -- auth posture -------------------------------------------------------
    def _check_posture(self, msg: RipMessage, now: float):
        key = (msg.src_ip, msg.af)
        st = self.sources.get(key)
        if st is None:
            st = SourceState(first_seen=now, af=msg.af)
            self.sources[key] = st

        if msg.family == "ripng":
            # RIPng has no native auth; posture = whether IPsec protects it.
            # AH (proto 51) authenticates without encrypting, so an AH-wrapped
            # RIPng datagram is still parseable and we can confirm protection.
            # (ESP would encrypt the payload, so it never reaches this parser.)
            if msg.ipsec_ah:
                self._emit_posture("RIP-006", msg, now,
                                   {"note": "RIPng protected by IPsec AH"})
            else:
                self._emit_posture("RIP-005", msg, now,
                                   {"note": "RIPng native, no in-band auth"})
            return

        if msg.version == 1:
            self._emit_posture("RIP-009", msg, now, {})

        a = msg.auth
        if not a.present:
            st.saw_unauth = True
            self._emit_posture("RIP-001", msg, now, {})
        else:
            st.saw_auth = True
            st.auth_type = a.auth_type
            if a.auth_type == AUTH_SIMPLE:
                self._emit_posture("RIP-002", msg, now, {"algorithm": "simple-password"})
            elif a.auth_type == AUTH_CRYPTO:
                if a.algorithm == "MD5":
                    self._emit_posture("RIP-003", msg, now, {"key_id": a.key_id})
                elif a.algorithm.startswith("HMAC-SHA"):
                    self._emit_posture("RIP-004", msg, now,
                                       {"key_id": a.key_id, "algorithm": a.algorithm})

        # downgrade: a source seen authenticated and then unauthenticated
        if st.saw_auth and st.saw_unauth:
            self._emit_posture("RIP-007", msg, now,
                               {"note": "source observed both authenticated and unauthenticated"})

        # asymmetry: this source's posture differs from another peer's on the
        # same plane (mixed authed/unauthed deployment - a config inconsistency
        # an attacker can hide inside). Distinct from RIP-007 (same source).
        others_authed = any(s is not st and s.af == msg.af and s.saw_auth
                            for s in self.sources.values())
        others_unauthed = any(s is not st and s.af == msg.af and s.saw_unauth and not s.saw_auth
                              for s in self.sources.values())
        if (a.present and others_unauthed) or (not a.present and others_authed):
            self._emit_posture("RIP-008", msg, now,
                               {"note": "peer auth posture differs from another peer on this plane"})

    # -- requests -----------------------------------------------------------
    def _check_request(self, msg: RipMessage, now: float):
        if msg.command != CMD_REQUEST:
            return
        # record the requester so a unicast reply to it is not flagged RIP-108
        self._recent_requests[(msg.src_ip, msg.af)] = now
        # A full-table request is ALSO what every RIP router emits at startup
        # (confirmed against real FRR 8.4.4 ripd). A legitimate peer follows it
        # with Responses, so it becomes a known responder; a recon scanner sends
        # only Requests. Fire RIP-107 only for a requester that is NOT an
        # established RIP speaker, and only once armed - otherwise it alerts on
        # every neighbour reboot.
        if not self._armed(now):
            return
        key = (msg.src_ip, msg.af)
        st = self.sources.get(key)
        if st is not None and st.emits_response:
            return  # established neighbour's startup request - benign
        # whole-table request marker:
        #   RIP (RFC 2453 s3.9.1): single RTE, AFI 0, metric 16
        #   RIPng (RFC 2080 s2.4.1): single RTE, prefix ::/0, metric 16
        #     (RIPng RTEs have no AFI field, so family decides the shape)
        if len(msg.entries) == 1:
            e = msg.entries[0]
            if msg.family == "ripng":
                full = (e.addr == "::" and e.prefix_len == 0
                        and e.metric == METRIC_INFINITY)
            else:
                full = (e.afi == AFI_UNSPEC and e.metric == METRIC_INFINITY)
            if full:
                self._emit("RIP-107", msg, now,
                           {"note": "full-table request (table recon)"})

    # -- responses: injection / hijack / storm -----------------------------
    def _check_responses(self, msg: RipMessage, now: float):
        if msg.command != CMD_RESPONSE:
            return
        armed = self._armed(now)
        key = (msg.src_ip, msg.af)
        st = self.sources[key]
        first_response = not st.emits_response
        st.emits_response = True

        # rogue responder: armed, source not among the responders learned at arm
        if armed and first_response and key not in self._known_responders_at_arm:
            self._emit("RIP-101", msg, now,
                       {"note": "source began emitting RIP Responses after arm"})

        # unicast response (targeted injection) - dst is not the RIP multicast.
        # Suppress a legitimate reply to a recent Request from that dst
        # (RFC 2453 s3.9.2; confirmed against real FRR, which unicasts its
        # response to the requester).
        if armed and not self._is_multicast_dst(msg):
            req_ts = self._recent_requests.get((msg.dst_ip, msg.af))
            is_reply = req_ts is not None and (now - req_ts) <= self.cfg.request_reply_window_s
            if not is_reply:
                self._emit("RIP-108", msg, now, {"dst": msg.dst_ip})

        # RIPv1 response where authenticated RIPv2 is the segment norm (CVE-2006-2224)
        if msg.family == "rip" and msg.version == 1 and self._segment_auth_norm(msg.af):
            if armed:
                self._emit("RIP-109", msg, now,
                           {"note": "RIPv1 Response on a segment where authenticated RIPv2 is the norm"})

        # per-entry route analysis + metric-16 accounting
        metric16_in_msg = 0
        for e in msg.entries:
            if e.metric == METRIC_INFINITY:
                metric16_in_msg += 1
            self._analyze_route(msg, e, now, armed)

        # mass poison storm: many metric-16 withdrawals in one message
        if metric16_in_msg >= self.cfg.metric16_threshold:
            self._emit("RIP-105", msg, now,
                       {"metric16_in_message": metric16_in_msg},
                       latch_key=(msg.src_ip, msg.af, "RIP-105"))
        else:
            # sustained across messages
            win = self._metric16.setdefault(key, [])
            win.append(now)
            self._metric16[key] = [t for t in win if now - t <= self.cfg.rate_window_s]
            rate = sum(1 for _ in self._metric16[key]) * metric16_in_msg  # weight
            total16 = len(self._metric16[key])
            if total16 >= self.cfg.metric16_window_rate:
                self._emit("RIP-105", msg, now,
                           {"metric16_window": total16},
                           latch_key=(msg.src_ip, msg.af, "RIP-105"))
            elif total16 < 1:
                self._latched.discard((msg.src_ip, msg.af, "RIP-105"))

    def _analyze_route(self, msg: RipMessage, e: RouteEntry, now: float, armed: bool):
        if e.metric == 0xFF:   # ripng next-hop RTE, not a route
            return
        prefix = self._prefix_key(msg, e)
        pkey = (prefix, msg.af)
        table = self.prefix_table.setdefault(pkey, {})

        is_default = self._is_default(msg, e)

        if not armed:
            # learn phase: record advertiser/metric silently
            if e.metric < METRIC_INFINITY:
                table[msg.src_ip] = e.metric
            return

        # armed:
        if is_default and e.metric < METRIC_INFINITY:
            if msg.src_ip not in table:
                self._emit("RIP-104", msg, now, {"prefix": prefix, "metric": e.metric})

        if e.metric >= METRIC_INFINITY:
            return  # withdrawal handled by the storm accounting

        if msg.src_ip not in table and len(table) == 0:
            # brand-new prefix from an otherwise-silent table: injection
            self._emit("RIP-102", msg, now,
                       {"prefix": prefix, "metric": e.metric,
                        "note": "prefix not advertised during learn phase"})
            table[msg.src_ip] = e.metric
        elif msg.src_ip not in table:
            # prefix known from other sources; new source undercuts metric?
            best = min(table.values())
            if e.metric < best:
                self._emit("RIP-103", msg, now,
                           {"prefix": prefix, "new_metric": e.metric,
                            "baseline_best": best, "new_source": msg.src_ip})
            else:
                self._emit("RIP-102", msg, now,
                           {"prefix": prefix, "metric": e.metric,
                            "note": "new advertiser for known prefix"})
            table[msg.src_ip] = e.metric
        else:
            # known advertiser; update metric
            table[msg.src_ip] = e.metric

    # -- helpers ------------------------------------------------------------
    _known_responders_at_arm: set = frozenset()

    def _is_multicast_dst(self, msg: RipMessage) -> bool:
        try:
            if msg.af == "ipv4":
                return msg.dst_ip == RIP_MCAST_V4 or \
                    ipaddress.IPv4Address(msg.dst_ip).is_multicast
            return msg.dst_ip == RIPNG_MCAST_V6 or \
                ipaddress.IPv6Address(msg.dst_ip).is_multicast
        except ValueError:
            return False

    def _segment_auth_norm(self, af: str) -> bool:
        # true if any source on this af has been seen using auth
        return any(st.saw_auth and st.af == af for st in self.sources.values())

    def _is_default(self, msg: RipMessage, e: RouteEntry) -> bool:
        if msg.af == "ipv4":
            return e.addr == "0.0.0.0" and (e.mask in (None, "0.0.0.0"))
        return e.addr == "::" and (e.prefix_len == 0)

    def _prefix_key(self, msg: RipMessage, e: RouteEntry) -> str:
        if msg.af == "ipv4":
            m = e.mask or "0.0.0.0"
            try:
                plen = ipaddress.IPv4Network(f"0.0.0.0/{m}").prefixlen
            except ValueError:
                plen = 0
            return f"{e.addr}/{plen}"
        return f"{e.addr}/{e.prefix_len}"

    def _prune(self, now: float):
        """Bound memory: expire stale requesters and cap the baseline tables.
        FIFO eviction via dict insertion order; keeps the arm baseline's
        responder set intact where possible (evicts non-responders first)."""
        # drop expired requesters
        self._recent_requests = {
            k: t for k, t in self._recent_requests.items()
            if now - t <= self.cfg.request_reply_window_s
        }
        # cap sources: evict oldest non-responder, non-baseline entries first
        if len(self.sources) > self.cfg.max_sources:
            drop = len(self.sources) - self.cfg.max_sources
            evictable = [k for k, st in self.sources.items()
                         if not st.emits_response
                         and k not in self._known_responders_at_arm]
            for k in evictable[:drop]:
                st = self.sources.pop(k, None)
                self._metric16.pop(k, None)
            # if still over, evict by insertion order
            while len(self.sources) > self.cfg.max_sources:
                k = next(iter(self.sources))
                self.sources.pop(k, None)
                self._metric16.pop(k, None)
        # cap prefix table (FIFO)
        while len(self.prefix_table) > self.cfg.max_prefixes:
            self.prefix_table.pop(next(iter(self.prefix_table)), None)
        # bound posture-latch set to live sources
        live = set(self.sources.keys())
        self._posture_seen = {(ip, af, c) for (ip, af, c) in self._posture_seen
                              if (ip, af) in live}

    def arm_now(self):
        """Freeze the learned responder set as the baseline (called at arm)."""
        self._known_responders_at_arm = {
            k for k, st in self.sources.items() if st.emits_response
        }

    def finalize_learn(self):
        self.arm_now()


# ---------------------------------------------------------------------------
# Live capture path  (the one scapy import; never runs in offline tiers)
# BPF: (ip and udp port 520) or ip6   -- bare ip6 so EH/AH chains reach us,
# port 521 decided in Python after the EH walk (LESSON AE).
# ---------------------------------------------------------------------------
BPF_FILTER = "(ip and udp port 520) or ip6"

# measured no-op form kept ONLY as the counterfactual the BPF test must reject
BPF_NOOP_COUNTERFACTUAL = "udp port 520 or udp port 521"


def run_capture(iface: str, cfg: Config, json_out: bool = True,
                count: int = 0, timeout: Optional[int] = None,
                pidfile: Optional[str] = None):
    from scapy.all import AsyncSniffer  # noqa: local import, live path only

    rw = Ripwatch(cfg)
    stop = {"flag": False}

    if pidfile:
        try:
            with open(pidfile, "w") as pf:
                pf.write(str(__import__("os").getpid()))
        except OSError:
            pass

    def _sig(signum, frame):
        stop["flag"] = True
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(s, _sig)
        except (ValueError, OSError):
            pass

    # SIGUSR1: operator signals "baseline learned, arm now" - freezes the
    # learned responder/prefix set immediately regardless of the learn timer.
    def _arm(signum, frame):
        rw.arm_now()
        rw._armed_latched = True
    try:
        signal.signal(signal.SIGUSR1, _arm)
    except (ValueError, OSError):
        pass

    def _on(pkt):
        # one packet can yield several findings; print EVERY new one, not just
        # the last (printing findings[-1:] silently drops all but the last).
        before = len(rw.findings)
        rw.feed_frame(bytes(pkt), ts=float(pkt.time))
        if json_out:
            for f in rw.findings[before:]:
                sys.stdout.write(json.dumps(f.to_dict()) + "\n")
            sys.stdout.flush()

    # AsyncSniffer runs the capture in a thread so the main loop can observe a
    # signal and stop promptly even on a silent interface - scapy's blocking
    # sniff() only checks stop_filter when a packet arrives (bfdwatch lesson).
    sniffer = AsyncSniffer(iface=iface, filter=BPF_FILTER, store=False, prn=_on,
                           count=count)
    sniffer.start()
    deadline = (time.time() + timeout) if timeout else None

    def _alive():
        # NOT sniffer.running: scapy leaves that True when the capture thread
        # dies on an exception (no CAP_NET_RAW, iface gone), so polling it spins
        # forever on a dead sensor - systemd would show active(running) while
        # nothing is captured. Watch the thread and the exception slot instead.
        t = getattr(sniffer, "thread", None)
        if getattr(sniffer, "exception", None) is not None:
            return False
        return t is not None and t.is_alive()

    try:
        while _alive() and not stop["flag"]:
            if deadline and time.time() >= deadline:
                break
            time.sleep(0.2)
    finally:
        if sniffer.running:
            try:
                sniffer.stop()
            except Exception:
                pass
    # The socket is opened inside the sniffer thread, so a failure there (e.g.
    # no CAP_NET_RAW, interface missing) never reaches this frame on its own.
    # scapy keeps it on .exception; surface it, or the process exits 0 and a
    # supervisor reads a dead sensor as a clean stop.
    if getattr(sniffer, "exception", None) is not None:
        raise CaptureError(f"capture on {iface} failed: {sniffer.exception!r}")
    return rw


class CaptureError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="ripwatch - passive RIP/RIPng monitor")
    ap.add_argument("--iface", help="capture interface (live mode)")
    ap.add_argument("--pcap", help="offline pcap to read")
    ap.add_argument("--config", help="JSON config path")
    ap.add_argument("--json", action="store_true", help="JSON findings to stdout")
    ap.add_argument("--selftest", action="store_true", help="run Tier 1 self-test")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--pidfile", help="write capture PID here (SIGUSR1 to arm)")
    args = ap.parse_args(argv)

    if args.selftest:
        from tier1_selftest import run as t1run
        return t1run()

    cfg = Config.from_json(args.config) if args.config else Config()

    if args.pcap:
        from scapy.all import rdpcap
        rw = Ripwatch(cfg)
        for pkt in rdpcap(args.pcap):
            rw.feed_frame(bytes(pkt), ts=float(pkt.time))
        if args.json:
            for f in rw.findings:
                print(json.dumps(f.to_dict()))
        sys.stderr.write(json.dumps(rw.stats) + "\n")
        return 0

    if args.iface:
        try:
            run_capture(args.iface, cfg, json_out=args.json or True,
                        count=args.count, timeout=args.timeout, pidfile=args.pidfile)
        except CaptureError as e:
            sys.stderr.write(f"ripwatch: {e}\n")
            return 2
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
