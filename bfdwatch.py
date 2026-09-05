#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bfdwatch — passive Bidirectional Forwarding Detection (BFD) failover-manipulation detector
Ragnar module, v0.1.0-dev

Mission
-------
Passive-only. Never transmits. Observes BFD control / echo traffic from a tap or
SPAN and reports auth posture, protocol-conformance violations, off-path injection
evidence, and forced-failover activity.

Zero baseline learning: every threshold below is an RFC-derived invariant or a
fixed operational constant. No per-environment tuning, no learning window.

Scope (RFC anchors)
-------------------
  RFC 5880  BFD (base protocol, control packet format, auth sections, state machine)
  RFC 5881  BFD for IPv4/IPv6 single hop  -> GTSM: TTL/hop-limit MUST be 255
  RFC 5883  BFD for multihop paths        -> crypto auth SHOULD be used
  RFC 7492  BFD security gap analysis     -> Keyed MD5/SHA1 replay window
  RFC 7130  BFD on LAG member links       -> micro-BFD, UDP/6784

Referenced CVEs
---------------
  CVE-2018-0155  Cisco Catalyst 4500/4500-X/4900M/4948E BFD offload. Incomplete BFD
                 header crashes iosd. CVSS 8.6. Directly observable on the wire:
                 a truncated/short BFD header IS the exploit primitive, so
                 BFD-TRUNCATED-HEADER / BFD-MALFORMED-HEADER are exploitation
                 signals here, not just protocol hygiene.
  cisco-sa-nxos-bfd-dos-wGQXrzxn  Nexus 9000 BFD rate-limiter logic error -> BFD
                 drops -> session flaps. Context only. The trigger is a crafted
                 traffic *stream*, not a BFD packet property; detection would be
                 behavioural and low-precision. NOT used as a detection anchor.
                 BFD-SESSION-FLAP will fire on the effect, which is the honest
                 level of confidence available passively.

NOTE: the earlier design note attributing BFD session spoofing to a
"CVE-2013-4796 family" does not check out. That ID is not a BFD vulnerability.
Session spoofing is a *protocol design* property of unauthenticated BFD
(RFC 5880 s.9, RFC 7492), not a CVE. It is treated as posture here.

Author: Solarflere
"""

from __future__ import annotations

import argparse
import binascii
import ipaddress
import json
import os
import struct
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Set, Tuple

__version__ = "0.1.0-dev"
MODULE_NAME = "bfdwatch"


# ===========================================================================
# SECTION 1 — RFC constant tables
# ===========================================================================

# IANA-assigned UDP ports
PORT_SINGLE_HOP = 3784   # RFC 5881 control, GTSM applies
PORT_ECHO = 3785         # RFC 5881 echo
PORT_MULTIHOP = 4784     # RFC 5883 control, GTSM does NOT apply
PORT_LAG = 6784          # RFC 7130 micro-BFD on LAG members, GTSM applies

CONTROL_PORTS = frozenset((PORT_SINGLE_HOP, PORT_MULTIHOP, PORT_LAG))
GTSM_PORTS = frozenset((PORT_SINGLE_HOP, PORT_LAG))
ALL_BFD_PORTS = frozenset((PORT_SINGLE_HOP, PORT_ECHO, PORT_MULTIHOP, PORT_LAG))

PORT_LABEL = {
    PORT_SINGLE_HOP: "single-hop",
    PORT_ECHO: "echo",
    PORT_MULTIHOP: "multihop",
    PORT_LAG: "lag-member",
}

# RFC 5880 s.4.1 — State (2 bits)
STATE_ADMIN_DOWN = 0
STATE_DOWN = 1
STATE_INIT = 2
STATE_UP = 3

STATE_NAME = {
    STATE_ADMIN_DOWN: "AdminDown",
    STATE_DOWN: "Down",
    STATE_INIT: "Init",
    STATE_UP: "Up",
}

# RFC 5880 s.4.1 — Diagnostic (5 bits)
DIAG_NAME = {
    0: "No Diagnostic",
    1: "Control Detection Time Expired",
    2: "Echo Function Failed",
    3: "Neighbor Signaled Session Down",
    4: "Forwarding Plane Reset",
    5: "Path Down",
    6: "Concatenated Path Down",
    7: "Administratively Down",
    8: "Reverse Concatenated Path Down",
}
DIAG_RESERVED_MIN = 9  # 9..31 reserved

# RFC 5880 s.4.2-4.4 — Authentication Type
AUTH_RESERVED = 0
AUTH_SIMPLE_PASSWORD = 1
AUTH_KEYED_MD5 = 2
AUTH_METICULOUS_KEYED_MD5 = 3
AUTH_KEYED_SHA1 = 4
AUTH_METICULOUS_KEYED_SHA1 = 5

AUTH_NAME = {
    AUTH_RESERVED: "Reserved",
    AUTH_SIMPLE_PASSWORD: "Simple Password",
    AUTH_KEYED_MD5: "Keyed MD5",
    AUTH_METICULOUS_KEYED_MD5: "Meticulous Keyed MD5",
    AUTH_KEYED_SHA1: "Keyed SHA1",
    AUTH_METICULOUS_KEYED_SHA1: "Meticulous Keyed SHA1",
}

# Meticulous variants increment the sequence number on EVERY packet.
# Non-meticulous variants are only required to increment occasionally, which
# leaves an intra-session replay window (RFC 7492 s.3-4).
AUTH_METICULOUS = frozenset((AUTH_METICULOUS_KEYED_MD5, AUTH_METICULOUS_KEYED_SHA1))
AUTH_SEQUENCED = frozenset(
    (AUTH_KEYED_MD5, AUTH_METICULOUS_KEYED_MD5,
     AUTH_KEYED_SHA1, AUTH_METICULOUS_KEYED_SHA1)
)

# Expected Auth Len per type (RFC 5880 s.4.2-4.4)
AUTH_LEN_EXPECTED = {
    AUTH_KEYED_MD5: 24,
    AUTH_METICULOUS_KEYED_MD5: 24,
    AUTH_KEYED_SHA1: 28,
    AUTH_METICULOUS_KEYED_SHA1: 28,
}
# Simple Password: 3 header bytes + 1..16 password bytes
AUTH_SIMPLE_LEN_MIN = 4
AUTH_SIMPLE_LEN_MAX = 19

BFD_HDR_LEN = 24         # mandatory section
BFD_MIN_LEN_AUTH = 26    # RFC 5880 s.6.8.6 minimum when A bit set

# Relative auth strength, used for downgrade detection. Higher is stronger.
AUTH_STRENGTH = {
    None: 0,                            # no auth
    AUTH_RESERVED: 0,
    AUTH_SIMPLE_PASSWORD: 1,            # cleartext key on the wire
    AUTH_KEYED_MD5: 2,
    AUTH_KEYED_SHA1: 3,
    AUTH_METICULOUS_KEYED_MD5: 4,
    AUTH_METICULOUS_KEYED_SHA1: 5,
}

# RFC 5880 s.6.2 state machine, restricted to transitions that are unreachable
# *on the wire*, which is not the same as unreachable in the local state machine.
#
# Up -> Init is genuinely impossible: s.6.8.6 gives a system in Up exactly two
# exits, Down (on receiving Down) and AdminDown (administratively). No input
# moves it to Init, transiently or otherwise.
#
# AdminDown -> Init and AdminDown -> Up were originally listed here and are NOT.
# Tier 3 measured FRR 8.4.4 emitting AdminDown -> Init -> Up on all 5 of 5
# `no shutdown` cycles. That is conformant: on re-enable the session enters Down,
# immediately processes the peer's already-queued Down packet and moves to Init,
# all within one transmit interval. The Down state is real but never reaches the
# wire. A passive observer cannot see a state that lives for less than one TX
# interval, so treating its absence as forgery is an observer error, not a peer
# violation. Any implementation with a fast re-enable path will do the same.
INVALID_TRANSITIONS = frozenset((
    (STATE_UP, STATE_INIT),
))


# ===========================================================================
# SECTION 2 — Finding taxonomy
# ===========================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    # Read directly out of the packet. No inference. Cannot be wrong unless the
    # capture itself is wrong.
    CONFIRMED = "CONFIRMED"
    # Derived from multiple observations that are individually solid, but the
    # attacker/misconfiguration distinction is not decidable from the wire.
    PROBABLE = "PROBABLE"
    # Behavioural. Consistent with attack, also consistent with a bad optic.
    POSSIBLE = "POSSIBLE"


@dataclass(frozen=True)
class CodeSpec:
    code: str
    severity: Severity
    confidence: Confidence
    title: str
    rationale: str
    # posture codes fire once per direction; event codes may re-fire (rate limited)
    event: bool = False


def _spec(code, sev, conf, title, rationale, event=False) -> CodeSpec:
    return CodeSpec(code, sev, conf, title, rationale, event)


CODES: Dict[str, CodeSpec] = {c.code: c for c in [

    # ---- Class A: authentication posture -------------------------------
    _spec("BFD-NO-AUTH", Severity.HIGH, Confidence.CONFIRMED,
          "BFD session running without authentication",
          "A bit clear. Any host on the segment can forge control packets for "
          "this session and drive it Down. RFC 5880 s.9."),

    _spec("BFD-SIMPLE-PASSWORD-AUTH", Severity.HIGH, Confidence.CONFIRMED,
          "BFD Simple Password authentication (cleartext key on the wire)",
          "Auth Type 1. The shared key is transmitted in plaintext in every "
          "packet and is recoverable from this capture. Equivalent to no auth "
          "against any on-path observer."),

    _spec("BFD-KEYED-MD5-AUTH", Severity.MEDIUM, Confidence.CONFIRMED,
          "BFD Keyed MD5 authentication (weak digest, replay window)",
          "Auth Type 2. MD5 plus a sequence number that is not required to "
          "increment per packet (RFC 7492)."),

    _spec("BFD-KEYED-SHA1-AUTH", Severity.MEDIUM, Confidence.CONFIRMED,
          "BFD Keyed SHA1 authentication (replay window)",
          "Auth Type 4. Digest is adequate; the sequence number is not required "
          "to increment per packet, leaving an intra-session replay window."),

    _spec("BFD-METICULOUS-MD5-AUTH", Severity.LOW, Confidence.CONFIRMED,
          "BFD Meticulous Keyed MD5 authentication",
          "Auth Type 3. Replay window closed, digest is MD5. Acceptable; "
          "prefer Meticulous Keyed SHA1."),

    _spec("BFD-METICULOUS-SHA1-AUTH", Severity.INFO, Confidence.CONFIRMED,
          "BFD Meticulous Keyed SHA1 authentication",
          "Auth Type 5. Strongest option in RFC 5880. Recorded for posture "
          "inventory, not an issue."),

    _spec("BFD-AUTH-UNKNOWN-TYPE", Severity.LOW, Confidence.CONFIRMED,
          "BFD authentication section with unrecognised Auth Type",
          "Auth Type outside 1..5. Vendor extension or fuzzing."),

    _spec("BFD-AUTH-REPLAY-WINDOW", Severity.HIGH, Confidence.CONFIRMED,
          "BFD non-meticulous auth with an observed stalled sequence number",
          "Not inferred from the auth type alone: the sequence number was "
          "measured as non-increasing across consecutive packets, so a "
          "replayable packet set exists in this capture."),

    _spec("BFD-AUTH-ASYMMETRIC", Severity.HIGH, Confidence.CONFIRMED,
          "BFD session authenticated in one direction only",
          "One endpoint authenticates, the peer does not. The unauthenticated "
          "half is forgeable and one forged Down tears down the whole session."),

    _spec("BFD-AUTH-DOWNGRADE", Severity.CRITICAL, Confidence.CONFIRMED,
          "BFD authentication weakened or removed mid-session",
          "Auth type dropped in strength, or the A bit cleared, on an "
          "established session. Legitimate rekeying does not weaken the type."),

    _spec("BFD-MULTIHOP-NO-AUTH", Severity.HIGH, Confidence.CONFIRMED,
          "Multihop BFD without authentication",
          "UDP/4784 with A bit clear. Multihop cannot use GTSM, so auth is the "
          "only anti-spoofing control available. RFC 5883 s.6."),

    # ---- Class B: protocol conformance ---------------------------------
    _spec("BFD-VERSION-ZERO", Severity.MEDIUM, Confidence.CONFIRMED,
          "BFD version 0 in use",
          "Pre-standard draft version. Predates RFC 5880 authentication and "
          "validation rules."),

    _spec("BFD-VERSION-UNKNOWN", Severity.LOW, Confidence.CONFIRMED,
          "BFD packet with unrecognised version",
          "Version field is neither 0 nor 1. Fuzzing or a malformed injector."),

    _spec("BFD-TRUNCATED-HEADER", Severity.HIGH, Confidence.CONFIRMED,
          "BFD packet shorter than the mandatory 24-byte header",
          "An incomplete BFD header is the exploit primitive for CVE-2018-0155 "
          "(Cisco Catalyst 4500/4500-X BFD offload, iosd crash, CVSS 8.6). "
          "Treat as active exploitation attempt if the segment carries "
          "affected platforms.", event=True),

    _spec("BFD-MALFORMED-HEADER", Severity.HIGH, Confidence.CONFIRMED,
          "BFD header fails RFC 5880 s.6.8.6 validation",
          "Length field inconsistent with the datagram, Detect Mult zero, auth "
          "length mismatch, or Your Discriminator zero in a state that requires "
          "it. Same crafted-header class as CVE-2018-0155.", event=True),

    _spec("BFD-ZERO-DISCRIMINATOR", Severity.MEDIUM, Confidence.CONFIRMED,
          "BFD packet with My Discriminator of zero",
          "RFC 5880 requires a nonzero My Discriminator; a conformant "
          "implementation never emits this. Indicates a forged or fuzzed "
          "injector.", event=True),

    _spec("BFD-RESERVED-DIAG", Severity.LOW, Confidence.CONFIRMED,
          "BFD packet carrying a reserved diagnostic code",
          "Diag 9..31 is reserved. Vendor extension or fuzzing.", event=True),

    _spec("BFD-INVALID-FLAG-COMBO", Severity.MEDIUM, Confidence.CONFIRMED,
          "BFD packet with an illegal flag combination",
          "Poll and Final set together (forbidden by RFC 5880 s.6.8.7), or the "
          "Multipoint bit set on a point-to-point session.", event=True),

    # ---- Class C: path / source integrity ------------------------------
    _spec("BFD-GTSM-VIOLATION", Severity.HIGH, Confidence.CONFIRMED,
          "Single-hop BFD received with TTL/hop-limit other than 255",
          "RFC 5881 requires 255 on single-hop BFD precisely so off-path "
          "injection is impossible. A lower value means the packet was routed "
          "to get here: off-path injection, or a broken middlebox.", event=True),

    _spec("BFD-SOURCE-MIGRATION", Severity.HIGH, Confidence.PROBABLE,
          "BFD discriminator observed from a new source address",
          "An established discriminator started arriving from a different "
          "source IP or MAC. Consistent with session hijacking; also consistent "
          "with a legitimate failover of the peer's control plane.", event=True),

    _spec("BFD-DISCRIMINATOR-COLLISION", Severity.HIGH, Confidence.PROBABLE,
          "Same BFD discriminator pair claimed by two distinct sources",
          "Scoped to the (My, Your) discriminator PAIR, not to My alone. RFC "
          "5880 s.6.8.1 requires My Discriminator to be unique on the emitting "
          "system only, so two routers legitimately reusing the same value is "
          "conformant -- FRR 8.4.4 was measured doing exactly that across 8 "
          "instances (time-seeded generation). A duplicated *pair* is different: "
          "it means two sources claim the same side of the same established "
          "session, which is impersonation.", event=True),

    # ---- Class D: state machine and failover ---------------------------
    _spec("BFD-STATE-REGRESSION", Severity.MEDIUM, Confidence.CONFIRMED,
          "Illegal BFD state transition observed",
          "Up->Init. No input in RFC 5880 s.6.8.6 moves a session from Up to "
          "Init, so the packet was not produced by a conformant peer. Scoped "
          "deliberately narrow: AdminDown->Init is NOT included because real "
          "implementations reach it through a sub-transmit-interval Down that "
          "never appears on the wire (measured on FRR 8.4.4).", event=True),

    _spec("BFD-SESSION-FLAP", Severity.HIGH, Confidence.PROBABLE,
          "BFD session flapping",
          "Repeated Down transitions inside a short window. Either a real "
          "unstable path, an injection campaign, or the effect of a "
          "rate-limiter DoS such as cisco-sa-nxos-bfd-dos-wGQXrzxn.", event=True),

    _spec("BFD-CONVERGENCE-STORM", Severity.HIGH, Confidence.PROBABLE,
          "Multiple BFD sessions transitioned Down simultaneously",
          "Distinct sessions went Down inside one window. Correlated failover "
          "across sessions is what turns a single forged packet into a routing "
          "event.", event=True),

    _spec("BFD-FORCED-ADMINDOWN", Severity.MEDIUM, Confidence.PROBABLE,
          "BFD session driven to AdminDown on the wire",
          "AdminDown is an operator action, so this fires on every planned "
          "maintenance shutdown as well as on an injected teardown. Passive "
          "observation cannot separate the two, so it is scored MEDIUM: "
          "correlate against the change calendar. An AdminDown that arrives "
          "with path-integrity evidence escalates to BFD-SPOOFED-TEARDOWN "
          "instead.", event=True),

    _spec("BFD-DETECT-TIME-DEGRADED", Severity.MEDIUM, Confidence.CONFIRMED,
          "BFD detection time shortened mid-session",
          "Detect Mult reduced or intervals tightened on an established "
          "session, making it far easier to knock down. Escalated when the "
          "change arrived without a Poll sequence, which RFC 5880 s.6.8.3 "
          "requires for interval changes while Up.", event=True),

    # ---- Class E: echo mode --------------------------------------------
    _spec("BFD-ECHO-ENABLED", Severity.INFO, Confidence.CONFIRMED,
          "BFD echo mode advertised",
          "Required Min Echo RX Interval is nonzero. Echo packet contents are "
          "implementation-defined and unauthenticated by the base spec "
          "(RFC 7492 s.3). Posture context for BFD-ECHO-SRC-MISMATCH."),

    _spec("BFD-ECHO-SRC-MISMATCH", Severity.MEDIUM, Confidence.PROBABLE,
          "BFD echo packet that is not self-addressed",
          "Echo packets are sent to the sender's own address to be looped by "
          "the peer. A non-self-addressed echo on UDP/3785 is either an "
          "amplification attempt or a spoofed liveness keeper.", event=True),

    # ---- Flagship correlation ------------------------------------------
    _spec("BFD-SPOOFED-TEARDOWN", Severity.CRITICAL, Confidence.PROBABLE,
          "BFD teardown correlated with off-path injection evidence",
          "A Down/AdminDown transition arrived inside the same window as hard "
          "path-integrity evidence (GTSM violation, source migration, "
          "discriminator collision or auth downgrade) on the same session. "
          "This is the forged-failover signature: one finding, act on it.",
          event=True),
]}


@dataclass
class Finding:
    ts: float
    code: str
    severity: Severity
    confidence: Confidence
    title: str
    session: str
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": MODULE_NAME,
            "version": __version__,
            "ts": round(self.ts, 6),
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ts)),
            "code": self.code,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "session": self.session,
            "detail": self.detail,
            "evidence": self.evidence,
        }


# ===========================================================================
# SECTION 3 — Link/network decode (hand-rolled, no scapy dependency)
# ===========================================================================

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
IPPROTO_UDP = 17

# Extension headers we will walk past to reach UDP in IPv6.
V6_SKIPPABLE = {0: True, 43: True, 60: True}  # hop-by-hop, routing, dest-opts


@dataclass
class PacketMeta:
    """Everything the detectors need about one observed BFD datagram."""
    ts: float
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    ip_version: int
    ttl: int              # IPv4 TTL or IPv6 hop limit
    src_port: int
    dst_port: int
    payload: bytes
    vlan: Optional[int] = None


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode_ethernet(frame: bytes, ts: float) -> Optional[PacketMeta]:
    """Decode Ethernet -> [VLAN...] -> IPv4/IPv6 -> UDP. Returns None if the
    frame is not a UDP datagram on a BFD port."""
    if len(frame) < 14:
        return None
    dst_mac = _mac(frame[0:6])
    src_mac = _mac(frame[6:12])
    off = 12
    ethertype = struct.unpack("!H", frame[off:off + 2])[0]
    off += 2

    vlan = None
    hops = 0
    while ethertype in (ETH_P_8021Q, ETH_P_8021AD) and hops < 3:
        if len(frame) < off + 4:
            return None
        tci = struct.unpack("!H", frame[off:off + 2])[0]
        if vlan is None:
            vlan = tci & 0x0FFF
        ethertype = struct.unpack("!H", frame[off + 2:off + 4])[0]
        off += 4
        hops += 1

    if ethertype == ETH_P_IPV4:
        return _decode_ipv4(frame, off, ts, src_mac, dst_mac, vlan)
    if ethertype == ETH_P_IPV6:
        return _decode_ipv6(frame, off, ts, src_mac, dst_mac, vlan)
    return None


def _decode_ipv4(buf, off, ts, src_mac, dst_mac, vlan) -> Optional[PacketMeta]:
    if len(buf) < off + 20:
        return None
    vihl = buf[off]
    if (vihl >> 4) != 4:
        return None
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(buf) < off + ihl:
        return None
    ttl = buf[off + 8]
    proto = buf[off + 9]
    if proto != IPPROTO_UDP:
        return None
    src_ip = str(ipaddress.IPv4Address(buf[off + 12:off + 16]))
    dst_ip = str(ipaddress.IPv4Address(buf[off + 16:off + 20]))
    # fragmented packets cannot be reassembled passively here; only offset 0 useful
    frag = struct.unpack("!H", buf[off + 6:off + 8])[0] & 0x1FFF
    if frag != 0:
        return None
    return _decode_udp(buf, off + ihl, ts, src_mac, dst_mac,
                       src_ip, dst_ip, 4, ttl, vlan)


def _decode_ipv6(buf, off, ts, src_mac, dst_mac, vlan) -> Optional[PacketMeta]:
    if len(buf) < off + 40:
        return None
    if (buf[off] >> 4) != 6:
        return None
    nxt = buf[off + 6]
    hop_limit = buf[off + 7]
    src_ip = str(ipaddress.IPv6Address(buf[off + 8:off + 24]))
    dst_ip = str(ipaddress.IPv6Address(buf[off + 24:off + 40]))
    cur = off + 40
    hops = 0
    while nxt in V6_SKIPPABLE and hops < 6:
        if len(buf) < cur + 2:
            return None
        ext_len = (buf[cur + 1] + 1) * 8
        nxt = buf[cur]
        cur += ext_len
        hops += 1
    if nxt != IPPROTO_UDP:
        return None
    return _decode_udp(buf, cur, ts, src_mac, dst_mac,
                       src_ip, dst_ip, 6, hop_limit, vlan)


def _decode_udp(buf, off, ts, src_mac, dst_mac, src_ip, dst_ip,
                ipver, ttl, vlan) -> Optional[PacketMeta]:
    if len(buf) < off + 8:
        return None
    sport, dport, ulen = struct.unpack("!HHH", buf[off:off + 6])
    if dport not in ALL_BFD_PORTS and sport not in ALL_BFD_PORTS:
        return None
    body = buf[off + 8:]
    # Trust the UDP length field when it is sane; it bounds the BFD datagram.
    if 8 <= ulen <= len(buf) - off:
        body = buf[off + 8: off + ulen]
    return PacketMeta(ts=ts, src_mac=src_mac, dst_mac=dst_mac,
                      src_ip=src_ip, dst_ip=dst_ip, ip_version=ipver,
                      ttl=ttl, src_port=sport, dst_port=dport,
                      payload=body, vlan=vlan)


# ===========================================================================
# SECTION 4 — BFD control packet parser (hand-rolled, strict)
# ===========================================================================

@dataclass
class AuthSection:
    auth_type: int
    auth_len: int
    key_id: Optional[int] = None
    seq: Optional[int] = None
    password: Optional[bytes] = None
    digest: Optional[bytes] = None
    reserved: Optional[int] = None
    length_ok: bool = True
    length_note: str = ""


@dataclass
class BFDControl:
    version: int
    diag: int
    state: int
    poll: bool
    final: bool
    cpi: bool
    auth_present: bool
    demand: bool
    multipoint: bool
    detect_mult: int
    length: int
    my_disc: int
    your_disc: int
    desired_min_tx: int      # microseconds
    required_min_rx: int     # microseconds
    required_min_echo_rx: int
    auth: Optional[AuthSection] = None
    # RFC 5880 s.6.8.6 validation results, collected rather than raising
    violations: List[str] = field(default_factory=list)


class TruncatedBFD(Exception):
    """Payload shorter than the 24-byte mandatory section."""

    def __init__(self, got: int):
        super().__init__(f"payload {got} bytes < mandatory {BFD_HDR_LEN}")
        self.got = got


def parse_bfd_control(payload: bytes) -> BFDControl:
    """Parse a BFD control packet. Raises TruncatedBFD only when the mandatory
    section is incomplete (which is itself the CVE-2018-0155 primitive).
    Every other defect is recorded in .violations so the packet still yields
    detections instead of being silently dropped."""
    if len(payload) < BFD_HDR_LEN:
        raise TruncatedBFD(len(payload))

    b0, b1, detect_mult, length = payload[0], payload[1], payload[2], payload[3]
    version = (b0 >> 5) & 0x07
    diag = b0 & 0x1F
    state = (b1 >> 6) & 0x03

    pkt = BFDControl(
        version=version,
        diag=diag,
        state=state,
        poll=bool(b1 & 0x20),
        final=bool(b1 & 0x10),
        cpi=bool(b1 & 0x08),
        auth_present=bool(b1 & 0x04),
        demand=bool(b1 & 0x02),
        multipoint=bool(b1 & 0x01),
        detect_mult=detect_mult,
        length=length,
        my_disc=struct.unpack("!I", payload[4:8])[0],
        your_disc=struct.unpack("!I", payload[8:12])[0],
        desired_min_tx=struct.unpack("!I", payload[12:16])[0],
        required_min_rx=struct.unpack("!I", payload[16:20])[0],
        required_min_echo_rx=struct.unpack("!I", payload[20:24])[0],
    )

    # --- RFC 5880 s.6.8.6 reception validation ---------------------------
    min_len = BFD_MIN_LEN_AUTH if pkt.auth_present else BFD_HDR_LEN
    if length < min_len:
        pkt.violations.append(
            f"Length field {length} below minimum {min_len} "
            f"(A bit {'set' if pkt.auth_present else 'clear'})")
    if length > len(payload):
        pkt.violations.append(
            f"Length field {length} exceeds datagram payload {len(payload)}")
    if detect_mult == 0:
        pkt.violations.append("Detect Mult is zero")
    if pkt.your_disc == 0 and state not in (STATE_DOWN, STATE_ADMIN_DOWN):
        pkt.violations.append(
            f"Your Discriminator zero while state is {STATE_NAME.get(state, state)}")

    # --- auth section ----------------------------------------------------
    if pkt.auth_present:
        pkt.auth = _parse_auth(payload, pkt)

    return pkt


def _parse_auth(payload: bytes, pkt: BFDControl) -> Optional[AuthSection]:
    if len(payload) < BFD_HDR_LEN + 2:
        pkt.violations.append("A bit set but auth section header truncated")
        return None
    atype = payload[BFD_HDR_LEN]
    alen = payload[BFD_HDR_LEN + 1]
    sec = AuthSection(auth_type=atype, auth_len=alen)

    if alen < 3:
        sec.length_ok = False
        sec.length_note = f"Auth Len {alen} below minimum 3"
        pkt.violations.append(sec.length_note)
        return sec

    end = BFD_HDR_LEN + alen
    if end > len(payload):
        sec.length_ok = False
        sec.length_note = (f"Auth Len {alen} runs past datagram "
                           f"(need {end}, have {len(payload)})")
        pkt.violations.append(sec.length_note)
        return sec

    # Header length must account for the mandatory section plus the auth section
    if pkt.length != BFD_HDR_LEN + alen and pkt.length <= len(payload):
        pkt.violations.append(
            f"Length {pkt.length} != 24 + Auth Len {alen}")

    body = payload[BFD_HDR_LEN:end]
    sec.key_id = body[2]

    if atype == AUTH_SIMPLE_PASSWORD:
        if not (AUTH_SIMPLE_LEN_MIN <= alen <= AUTH_SIMPLE_LEN_MAX):
            sec.length_ok = False
            sec.length_note = (f"Simple Password Auth Len {alen} outside "
                               f"{AUTH_SIMPLE_LEN_MIN}..{AUTH_SIMPLE_LEN_MAX}")
            pkt.violations.append(sec.length_note)
        sec.password = bytes(body[3:])
    elif atype in AUTH_SEQUENCED:
        expected = AUTH_LEN_EXPECTED[atype]
        if alen != expected:
            sec.length_ok = False
            sec.length_note = (f"{AUTH_NAME[atype]} Auth Len {alen} "
                               f"!= expected {expected}")
            pkt.violations.append(sec.length_note)
        if alen >= 8:
            sec.reserved = body[3]
            sec.seq = struct.unpack("!I", body[4:8])[0]
            sec.digest = bytes(body[8:])
            if sec.reserved != 0:
                pkt.violations.append(
                    f"Auth Reserved byte nonzero ({sec.reserved})")
    return sec


# ===========================================================================
# SECTION 5 — Session state tracking
# ===========================================================================

# Fixed operational constants. RFC-derived where possible, otherwise chosen so
# that a healthy carrier or SMB network never reaches them. No learning.
FLAP_WINDOW_S = 60.0            # observation window for repeated Down events
FLAP_DOWN_THRESHOLD = 4         # Down transitions within the window
STORM_WINDOW_S = 10.0           # window for correlated multi-session Down
STORM_SESSION_THRESHOLD = 3     # distinct sessions going Down in that window
REPLAY_STALL_THRESHOLD = 8      # consecutive non-increasing auth seq numbers
DETECT_TIME_SHRINK_FACTOR = 4.0  # effective detect time reduction that matters
POLL_GRACE_S = 5.0              # how recently a Poll must have been seen
CORRELATION_WINDOW_S = 30.0     # teardown <-> path-integrity evidence window
EVENT_REFIRE_S = 300.0          # per-code, per-direction event rate limit
# Per-session rate limiting alone is defeated by source spoofing: 500 truncated
# headers from 500 forged source IPs produce 500 distinct keys and therefore 500
# findings. This caps distinct sessions per code per window; past the cap the
# individual findings collapse into one rollup carrying the source count.
ORPHAN_CODE_BUDGET = 10
# A passive observer that stops seeing a direction does not know its state.
# When the gap since the last packet exceeds the session's own detection time by
# this factor, the next packet is a RESYNC, not a transition. Measured need: a
# link restored after a 20s outage makes four peers emit their queued Down
# within 0.2s, which reads as a convergence storm and as Up->Init regressions
# unless the gap is accounted for. The same applies to SPAN drops and capture
# restarts, which is why this matters more in production than in the lab.
OBSERVATION_GAP_FACTOR = 3.0
OBSERVATION_GAP_FLOOR_S = 2.0
SESSION_IDLE_TTL_S = 3600.0     # drop direction state idle longer than this
PRUNE_INTERVAL_S = 300.0        # how often to sweep for idle state

# Path-integrity codes that upgrade a teardown to BFD-SPOOFED-TEARDOWN
INTEGRITY_CODES = frozenset((
    "BFD-GTSM-VIOLATION",
    "BFD-SOURCE-MIGRATION",
    "BFD-DISCRIMINATOR-COLLISION",
    "BFD-AUTH-DOWNGRADE",
    "BFD-STATE-REGRESSION",
    "BFD-ZERO-DISCRIMINATOR",
))


@dataclass
class DirectionState:
    """One endpoint's half of a BFD session: (src_ip -> dst_ip, my_disc)."""
    src_ip: str
    dst_ip: str
    my_disc: int
    port: int
    first_seen: float
    last_seen: float
    packets: int = 0

    state: Optional[int] = None
    your_disc: int = 0
    version: Optional[int] = None

    auth_present: bool = False
    auth_type: Optional[int] = None
    last_seq: Optional[int] = None
    seq_stall_run: int = 0
    max_seq_stall: int = 0

    detect_mult: Optional[int] = None
    desired_min_tx: Optional[int] = None
    required_min_rx: Optional[int] = None
    echo_rx: Optional[int] = None
    last_poll_ts: float = 0.0

    src_macs: Set[str] = field(default_factory=set)
    ttls: Set[int] = field(default_factory=set)

    down_events: Deque[float] = field(default_factory=deque)
    integrity_hits: Deque[Tuple[float, str]] = field(default_factory=deque)
    emitted: Set[str] = field(default_factory=set)
    last_event: Dict[str, float] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return (f"{self.src_ip}->{self.dst_ip} "
                f"disc=0x{self.my_disc:08x} "
                f"[{PORT_LABEL.get(self.port, self.port)}]")

    def observation_gap_limit_s(self) -> float:
        """Longest silence after which this direction's state is unknown."""
        det = self.effective_detect_time_us()
        if det is None or det <= 0:
            return OBSERVATION_GAP_FLOOR_S
        return max(det / 1e6 * OBSERVATION_GAP_FACTOR, OBSERVATION_GAP_FLOOR_S)

    def effective_detect_time_us(self) -> Optional[float]:
        """Approximate detection time from this endpoint's advertisement."""
        if self.detect_mult is None or self.desired_min_tx is None:
            return None
        interval = max(self.desired_min_tx, self.required_min_rx or 0)
        return float(self.detect_mult) * float(interval)


# ===========================================================================
# SECTION 6 — Detection engine
# ===========================================================================

class BFDWatch:
    """Passive BFD observer. Feed it PacketMeta, collect Findings."""

    def __init__(self, emit=None, quiet_info: bool = False):
        self.directions: Dict[Tuple[str, str, int], DirectionState] = {}
        # (ip, my_disc) -> direction key, used to pair the two halves
        self.disc_index: Dict[Tuple[str, int], Tuple[str, str, int]] = {}
        # (peer_ip, my_disc, your_disc) -> sources claiming that session half
        self.disc_owners: Dict[Tuple[str, int, int], Set[Tuple[str, str]]] = {}
        self.recent_downs: Deque[Tuple[float, Tuple[str, str, int]]] = deque()
        self.findings: List[Finding] = []
        self.stats = {
            "frames": 0, "bfd_packets": 0, "control": 0, "echo": 0,
            "truncated": 0, "parse_violations": 0, "sessions_expired": 0,
            "resyncs": 0,
        }
        self._emit_cb = emit
        self._quiet_info = quiet_info
        self._storm_last = 0.0
        # rate limiting for findings raised before any session exists
        self._orphan_events: Dict[Tuple[str, str], float] = {}
        self._orphan_suppressed: Dict[Tuple[str, str], int] = {}
        # code -> (window_start, distinct session keys, rollup count)
        self._orphan_code_window: Dict[str, Tuple[float, Set[str], int]] = {}
        self._last_prune = 0.0

    # -- emission helpers -------------------------------------------------

    def _finding(self, ts, code, session, detail, evidence,
                 severity=None, confidence=None) -> Finding:
        spec = CODES[code]
        return Finding(
            ts=ts, code=code,
            severity=severity or spec.severity,
            confidence=confidence or spec.confidence,
            title=spec.title, session=session,
            detail=detail, evidence=evidence,
        )

    def _emit(self, d: Optional[DirectionState], ts, code, detail,
              evidence=None, session=None, severity=None, confidence=None):
        spec = CODES[code]
        if self._quiet_info and (severity or spec.severity) == Severity.INFO:
            return
        if d is None and spec.event:
            # Findings raised before a session exists (truncated headers, echo
            # packets) have no DirectionState to hang a rate limit on. Without
            # this, a flood of malformed packets produces one alert per packet.
            okey = (code, session or "-")
            last = self._orphan_events.get(okey, 0.0)
            if ts - last < EVENT_REFIRE_S:
                self._orphan_suppressed[okey] = \
                    self._orphan_suppressed.get(okey, 0) + 1
                return

            # Global per-code budget, on top of the per-session limit.
            win_start, seen, rolled = self._orphan_code_window.get(
                code, (ts, set(), 0))
            if ts - win_start > EVENT_REFIRE_S:
                win_start, seen, rolled = ts, set(), 0
            seen.add(okey[1])
            over_budget = len(seen) > ORPHAN_CODE_BUDGET
            if over_budget:
                rolled += 1
                self._orphan_code_window[code] = (win_start, seen, rolled)
                # Emit exactly one rollup at the moment the budget is crossed.
                if rolled > 1:
                    return
                detail = (f"{len(seen)} distinct sources triggered {code} "
                          f"within {int(EVENT_REFIRE_S)}s; individual findings "
                          f"suppressed past a budget of {ORPHAN_CODE_BUDGET}. "
                          f"A spread this wide is a flood or a spoofed-source "
                          f"campaign, not {len(seen)} separate incidents.")
                evidence = {"distinct_sources": len(seen),
                            "budget": ORPHAN_CODE_BUDGET,
                            "window_s": EVENT_REFIRE_S,
                            "rollup": True}
                session = "<multiple sources>"
            else:
                self._orphan_code_window[code] = (win_start, seen, rolled)
            self._orphan_events[okey] = ts
            suppressed = self._orphan_suppressed.pop(okey, 0)
            if suppressed and not over_budget:
                evidence = dict(evidence or {})
                evidence["suppressed_since_last"] = suppressed
        if d is not None:
            if not spec.event:
                if code in d.emitted:
                    return
                d.emitted.add(code)
            else:
                last = d.last_event.get(code, 0.0)
                if ts - last < EVENT_REFIRE_S:
                    return
                d.last_event[code] = ts
            if code in INTEGRITY_CODES:
                d.integrity_hits.append((ts, code))
                self._trim(d.integrity_hits, ts, CORRELATION_WINDOW_S)
        f = self._finding(ts, code, session or (d.label if d else "-"),
                          detail, evidence or {}, severity, confidence)
        self.findings.append(f)
        if self._emit_cb:
            self._emit_cb(f)

    @staticmethod
    def _trim(dq: Deque, now: float, window: float):
        while dq:
            head = dq[0]
            head_ts = head[0] if isinstance(head, tuple) else head
            if now - head_ts > window:
                dq.popleft()
            else:
                break

    # -- top level --------------------------------------------------------

    def observe_frame(self, frame: bytes, ts: float):
        self.stats["frames"] += 1
        meta = decode_ethernet(frame, ts)
        if meta is not None:
            self.observe(meta)

    def _prune(self, now: float):
        """Bound memory on long runs. A carrier tap can see thousands of
        sessions come and go; without this, directions/disc_owners grow without
        limit, which matters on a Pi-class node."""
        if now - self._last_prune < PRUNE_INTERVAL_S:
            return
        self._last_prune = now
        stale = [k for k, d in self.directions.items()
                 if now - d.last_seen > SESSION_IDLE_TTL_S]
        for k in stale:
            d = self.directions.pop(k)
            self.disc_index.pop((d.src_ip, d.my_disc), None)
            mine = {(d.src_ip, mac) for mac in d.src_macs}
            for pair in [k for k in self.disc_owners
                         if k[0] == d.dst_ip and k[1] == d.my_disc]:
                self.disc_owners[pair].difference_update(mine)
                if not self.disc_owners[pair]:
                    self.disc_owners.pop(pair, None)
        self.stats["sessions_expired"] += len(stale)
        cutoff = now - EVENT_REFIRE_S
        for key in [k for k, ts in self._orphan_events.items() if ts < cutoff]:
            self._orphan_events.pop(key, None)
            self._orphan_suppressed.pop(key, None)
        for code in [c for c, (st, _, _) in self._orphan_code_window.items()
                     if now - st > EVENT_REFIRE_S]:
            self._orphan_code_window.pop(code, None)

    def observe(self, m: PacketMeta):
        self.stats["bfd_packets"] += 1
        if self._last_prune == 0.0:
            self._last_prune = m.ts
        else:
            self._prune(m.ts)
        if m.dst_port == PORT_ECHO or m.src_port == PORT_ECHO:
            self.stats["echo"] += 1
            self._check_echo(m)
            return
        if m.dst_port not in CONTROL_PORTS:
            return
        self.stats["control"] += 1
        self._observe_control(m)

    # -- echo -------------------------------------------------------------

    def _check_echo(self, m: PacketMeta):
        # RFC 5880 s.6.4: echo packets are addressed to the sender itself so the
        # peer loops them back. Anything else on 3785 is not a normal echo.
        if m.src_ip != m.dst_ip:
            self._emit(
                None, m.ts, "BFD-ECHO-SRC-MISMATCH",
                f"Echo packet {m.src_ip} -> {m.dst_ip} is not self-addressed.",
                {"src_ip": m.src_ip, "dst_ip": m.dst_ip,
                 "src_mac": m.src_mac, "ttl": m.ttl,
                 "payload_len": len(m.payload)},
                session=f"{m.src_ip}->{m.dst_ip} [echo]",
            )

    # -- control ----------------------------------------------------------

    def _observe_control(self, m: PacketMeta):
        try:
            pkt = parse_bfd_control(m.payload)
        except TruncatedBFD as exc:
            self.stats["truncated"] += 1
            self._emit(
                None, m.ts, "BFD-TRUNCATED-HEADER",
                f"BFD datagram carried only {exc.got} bytes; the mandatory "
                f"section is {BFD_HDR_LEN}. Incomplete BFD headers are the "
                f"CVE-2018-0155 crash primitive.",
                {"src_ip": m.src_ip, "dst_ip": m.dst_ip, "src_mac": m.src_mac,
                 "dst_port": m.dst_port, "ttl": m.ttl,
                 "payload_len": exc.got,
                 "payload_hex": binascii.hexlify(m.payload).decode()},
                session=f"{m.src_ip}->{m.dst_ip} [{PORT_LABEL.get(m.dst_port)}]",
            )
            return

        key = (m.src_ip, m.dst_ip, pkt.my_disc)
        d = self.directions.get(key)
        if d is None:
            d = DirectionState(src_ip=m.src_ip, dst_ip=m.dst_ip,
                               my_disc=pkt.my_disc, port=m.dst_port,
                               first_seen=m.ts, last_seen=m.ts)
            self.directions[key] = d
            self.disc_index[(m.src_ip, pkt.my_disc)] = key
            gap = 0.0
        else:
            gap = m.ts - d.last_seen
        d.last_seen = m.ts
        d.packets += 1
        stale = d.packets > 1 and gap > d.observation_gap_limit_s()
        if stale:
            self.stats["resyncs"] += 1

        self._check_conformance(d, m, pkt)
        self._check_path_integrity(d, m, pkt)
        self._check_auth(d, m, pkt)
        self._check_timing(d, m, pkt)
        self._check_state(d, m, pkt, stale=stale, gap=gap)
        self._check_echo_posture(d, m, pkt)

        # commit current view last, so the checks above compare against the
        # previous packet rather than themselves
        d.state = pkt.state
        d.your_disc = pkt.your_disc
        d.version = pkt.version
        d.detect_mult = pkt.detect_mult
        d.desired_min_tx = pkt.desired_min_tx
        d.required_min_rx = pkt.required_min_rx
        d.echo_rx = pkt.required_min_echo_rx
        d.auth_present = pkt.auth_present
        d.auth_type = pkt.auth.auth_type if pkt.auth else None
        if pkt.poll:
            d.last_poll_ts = m.ts

    # -- Class B: conformance --------------------------------------------

    def _check_conformance(self, d, m, pkt: BFDControl):
        if pkt.version == 0:
            self._emit(d, m.ts, "BFD-VERSION-ZERO",
                       "Endpoint advertises BFD version 0 (pre-RFC 5880 draft).",
                       {"version": 0, "src_ip": m.src_ip, "src_mac": m.src_mac})
        elif pkt.version != 1:
            self._emit(d, m.ts, "BFD-VERSION-UNKNOWN",
                       f"BFD version field is {pkt.version}; only 0 and 1 are defined.",
                       {"version": pkt.version, "src_mac": m.src_mac})

        if pkt.violations:
            self.stats["parse_violations"] += 1
            self._emit(d, m.ts, "BFD-MALFORMED-HEADER",
                       "; ".join(pkt.violations),
                       {"violations": pkt.violations,
                        "length_field": pkt.length,
                        "detect_mult": pkt.detect_mult,
                        "payload_len": len(m.payload),
                        "src_mac": m.src_mac, "ttl": m.ttl})

        if pkt.my_disc == 0:
            self._emit(d, m.ts, "BFD-ZERO-DISCRIMINATOR",
                       "My Discriminator is zero; RFC 5880 requires a nonzero "
                       "value, so this was not produced by a conformant stack.",
                       {"src_ip": m.src_ip, "src_mac": m.src_mac,
                        "state": STATE_NAME.get(pkt.state, pkt.state)})

        if pkt.diag >= DIAG_RESERVED_MIN:
            self._emit(d, m.ts, "BFD-RESERVED-DIAG",
                       f"Diagnostic code {pkt.diag} is reserved (9..31).",
                       {"diag": pkt.diag, "src_mac": m.src_mac})

        bad_flags = []
        if pkt.poll and pkt.final:
            bad_flags.append("Poll and Final both set (RFC 5880 s.6.8.7)")
        if pkt.multipoint:
            bad_flags.append("Multipoint bit set on a point-to-point session")
        if bad_flags:
            self._emit(d, m.ts, "BFD-INVALID-FLAG-COMBO", "; ".join(bad_flags),
                       {"flags": bad_flags, "src_mac": m.src_mac,
                        "poll": pkt.poll, "final": pkt.final,
                        "multipoint": pkt.multipoint})

    # -- Class C: path integrity -----------------------------------------

    def _check_path_integrity(self, d, m, pkt: BFDControl):
        # GTSM. RFC 5881 pins single-hop BFD to TTL/hop-limit 255.
        if m.dst_port in GTSM_PORTS and m.ttl != 255:
            self._emit(d, m.ts, "BFD-GTSM-VIOLATION",
                       f"Single-hop BFD arrived with "
                       f"{'hop limit' if m.ip_version == 6 else 'TTL'} {m.ttl}, "
                       f"not 255. The packet crossed a router to reach this "
                       f"segment.",
                       {"ttl": m.ttl, "ip_version": m.ip_version,
                        "src_ip": m.src_ip, "src_mac": m.src_mac,
                        "dst_port": m.dst_port,
                        "state": STATE_NAME.get(pkt.state, pkt.state)})
        d.ttls.add(m.ttl)

        # Source migration for an established discriminator.
        if d.packets > 1 and m.src_mac not in d.src_macs:
            self._emit(d, m.ts, "BFD-SOURCE-MIGRATION",
                       f"Discriminator 0x{pkt.my_disc:08x} previously seen from "
                       f"{sorted(d.src_macs)} now arriving from {m.src_mac}.",
                       {"previous_macs": sorted(d.src_macs),
                        "new_mac": m.src_mac, "src_ip": m.src_ip,
                        "packets_before": d.packets - 1})
        d.src_macs.add(m.src_mac)

        # Discriminator collision, scoped to the established session pair.
        # Keying on my_disc alone produces one false positive per reused value:
        # measured at 49 HIGH findings across 16 healthy FRR sessions. The pair
        # is the session identity, and only a duplicated pair is impersonation.
        # your_disc == 0 means the session is not established (Down/AdminDown
        # zero it), so there is no pair to compare and nothing to conclude.
        if pkt.my_disc != 0 and pkt.your_disc != 0:
            # Keyed on the peer as well as the pair. Without dst_ip, a session
            # whose two endpoints happen to pick the SAME discriminator emits a
            # symmetric pair from both halves and looks like a collision; that
            # occurred in the lab because FRR's time-seeded generation gave hub
            # and spoke .11 the same value. The peer disambiguates which half of
            # which conversation is being claimed.
            pair = (m.dst_ip, pkt.my_disc, pkt.your_disc)
            owners = self.disc_owners.setdefault(pair, set())
            owners.add((m.src_ip, m.src_mac))
            if len(owners) > 1:
                self._emit(d, m.ts, "BFD-DISCRIMINATOR-COLLISION",
                           f"Session half toward {m.dst_ip} "
                           f"(my=0x{pkt.my_disc:08x}, your=0x{pkt.your_disc:08x}) "
                           f"claimed by {len(owners)} distinct sources.",
                           {"peer": m.dst_ip,
                            "my_discriminator": f"0x{pkt.my_disc:08x}",
                            "your_discriminator": f"0x{pkt.your_disc:08x}",
                            "claimants": sorted(f"{ip}/{mac}"
                                                for ip, mac in owners)})

    # -- Class A: authentication -----------------------------------------

    def _check_auth(self, d, m, pkt: BFDControl):
        if not pkt.auth_present or pkt.auth is None:
            self._emit(d, m.ts, "BFD-NO-AUTH",
                       "Authentication Present bit is clear; control packets for "
                       "this session are forgeable by any host on the path.",
                       {"src_ip": m.src_ip, "dst_ip": m.dst_ip,
                        "port": m.dst_port,
                        "state": STATE_NAME.get(pkt.state, pkt.state)})
            if m.dst_port == PORT_MULTIHOP:
                self._emit(d, m.ts, "BFD-MULTIHOP-NO-AUTH",
                           "Multihop BFD (UDP/4784) without authentication. GTSM "
                           "cannot apply here, so nothing constrains the source.",
                           {"src_ip": m.src_ip, "dst_ip": m.dst_ip})
        else:
            a = pkt.auth
            code = {
                AUTH_SIMPLE_PASSWORD: "BFD-SIMPLE-PASSWORD-AUTH",
                AUTH_KEYED_MD5: "BFD-KEYED-MD5-AUTH",
                AUTH_METICULOUS_KEYED_MD5: "BFD-METICULOUS-MD5-AUTH",
                AUTH_KEYED_SHA1: "BFD-KEYED-SHA1-AUTH",
                AUTH_METICULOUS_KEYED_SHA1: "BFD-METICULOUS-SHA1-AUTH",
            }.get(a.auth_type)

            if code is None:
                self._emit(d, m.ts, "BFD-AUTH-UNKNOWN-TYPE",
                           f"Auth Type {a.auth_type} is outside the RFC 5880 "
                           f"range 1..5.",
                           {"auth_type": a.auth_type, "auth_len": a.auth_len,
                            "key_id": a.key_id})
            elif code == "BFD-SIMPLE-PASSWORD-AUTH":
                pw = a.password or b""
                self._emit(d, m.ts, code,
                           f"Simple Password auth, key ID {a.key_id}, "
                           f"{len(pw)}-byte key transmitted in cleartext.",
                           {"auth_type": a.auth_type, "key_id": a.key_id,
                            "key_len": len(pw),
                            # recorded so the operator can confirm rotation;
                            # the key is already in the clear on the wire
                            "key_hex": binascii.hexlify(pw).decode()})
            else:
                self._emit(d, m.ts, code,
                           f"{AUTH_NAME[a.auth_type]} auth, key ID {a.key_id}.",
                           {"auth_type": a.auth_type, "key_id": a.key_id,
                            "meticulous": a.auth_type in AUTH_METICULOUS})

            self._check_replay_window(d, m, a)

        self._check_auth_downgrade(d, m, pkt)
        self._check_auth_asymmetry(d, m, pkt)

    def _check_replay_window(self, d, m, a: AuthSection):
        """Measured, not assumed. Only fires when the sequence number is
        actually observed standing still on a non-meticulous session."""
        if a.auth_type not in AUTH_SEQUENCED or a.seq is None:
            return
        if d.last_seq is not None:
            if a.seq <= d.last_seq:
                d.seq_stall_run += 1
                d.max_seq_stall = max(d.max_seq_stall, d.seq_stall_run)
            else:
                d.seq_stall_run = 0
        d.last_seq = a.seq

        if (a.auth_type not in AUTH_METICULOUS
                and d.seq_stall_run >= REPLAY_STALL_THRESHOLD):
            self._emit(d, m.ts, "BFD-AUTH-REPLAY-WINDOW",
                       f"{AUTH_NAME[a.auth_type]} sequence number held at "
                       f"{a.seq} across {d.seq_stall_run + 1} consecutive "
                       f"packets. Every one of those packets is replayable "
                       f"against this session.",
                       {"auth_type": a.auth_type, "sequence": a.seq,
                        "stalled_packets": d.seq_stall_run + 1,
                        "key_id": a.key_id})

    def _check_auth_downgrade(self, d, m, pkt: BFDControl):
        if d.packets <= 1:
            return
        prev = d.auth_type if d.auth_present else None
        cur = (pkt.auth.auth_type if (pkt.auth_present and pkt.auth) else None)
        if prev == cur:
            return
        if AUTH_STRENGTH.get(cur, 0) < AUTH_STRENGTH.get(prev, 0):
            self._emit(d, m.ts, "BFD-AUTH-DOWNGRADE",
                       f"Authentication weakened mid-session: "
                       f"{AUTH_NAME.get(prev, 'none') if prev is not None else 'none'} "
                       f"-> "
                       f"{AUTH_NAME.get(cur, 'none') if cur is not None else 'none'}.",
                       {"previous_auth_type": prev, "current_auth_type": cur,
                        "src_mac": m.src_mac, "packets": d.packets})

    def _check_auth_asymmetry(self, d, m, pkt: BFDControl):
        """Compare this half against the peer half, once both are known."""
        if pkt.your_disc == 0:
            return
        peer_key = self.disc_index.get((m.dst_ip, pkt.your_disc))
        if peer_key is None:
            return
        peer = self.directions.get(peer_key)
        if peer is None or peer.packets == 0:
            return
        if pkt.auth_present != peer.auth_present:
            authed = d if pkt.auth_present else peer
            plain = peer if pkt.auth_present else d
            self._emit(d, m.ts, "BFD-AUTH-ASYMMETRIC",
                       f"{authed.src_ip} authenticates, {plain.src_ip} does not. "
                       f"A forged Down from the unauthenticated side tears down "
                       f"the whole session.",
                       {"authenticated_side": authed.src_ip,
                        "unauthenticated_side": plain.src_ip,
                        "auth_type": (AUTH_NAME.get(authed.auth_type)
                                      if authed.auth_type is not None else None)})

    # -- Class D: timing --------------------------------------------------

    def _check_timing(self, d, m, pkt: BFDControl):
        prev = d.effective_detect_time_us()
        if prev is None or d.packets <= 1:
            return
        cur_interval = max(pkt.desired_min_tx, pkt.required_min_rx)
        cur = float(pkt.detect_mult) * float(cur_interval)
        if cur <= 0 or prev <= 0:
            return
        if prev / cur < DETECT_TIME_SHRINK_FACTOR:
            return

        # RFC 5880 s.6.8.3: interval changes on an Up session require a Poll
        # sequence. A change without one is a protocol violation on top of
        # making the session brittle.
        no_poll = (not pkt.poll) and (m.ts - d.last_poll_ts > POLL_GRACE_S)
        severity = Severity.HIGH if no_poll else Severity.MEDIUM
        self._emit(d, m.ts, "BFD-DETECT-TIME-DEGRADED",
                   f"Detection time shortened from {prev / 1000.0:.1f} ms to "
                   f"{cur / 1000.0:.1f} ms "
                   f"({'no Poll sequence observed' if no_poll else 'under Poll'}). "
                   f"Detect Mult {d.detect_mult} -> {pkt.detect_mult}.",
                   {"previous_detect_time_us": prev,
                    "current_detect_time_us": cur,
                    "previous_detect_mult": d.detect_mult,
                    "current_detect_mult": pkt.detect_mult,
                    "poll_observed": not no_poll,
                    "src_mac": m.src_mac},
                   severity=severity)

    # -- Class D: state machine and failover ------------------------------

    def _check_state(self, d, m, pkt: BFDControl, stale: bool = False,
                     gap: float = 0.0):
        prev = d.state
        cur = pkt.state
        if prev is None:
            return
        if stale:
            # The direction went silent for longer than its own detection time.
            # Whatever it did in that window is unobserved, so the state we hold
            # is not a predecessor of this one. Resync without concluding
            # anything: no transition, no Down event, no regression.
            return

        if (prev, cur) in INVALID_TRANSITIONS:
            self._emit(d, m.ts, "BFD-STATE-REGRESSION",
                       f"Illegal transition {STATE_NAME[prev]} -> "
                       f"{STATE_NAME[cur]}; unreachable in the RFC 5880 state "
                       f"machine.",
                       {"from": STATE_NAME[prev], "to": STATE_NAME[cur],
                        "src_mac": m.src_mac, "ttl": m.ttl,
                        "diag": DIAG_NAME.get(pkt.diag, pkt.diag)})

        if prev == cur:
            return

        if cur == STATE_ADMIN_DOWN:
            self._emit(d, m.ts, "BFD-FORCED-ADMINDOWN",
                       f"Session moved {STATE_NAME[prev]} -> AdminDown "
                       f"(diag: {DIAG_NAME.get(pkt.diag, pkt.diag)}). AdminDown "
                       f"is an operator action; confirm a change window exists.",
                       {"from": STATE_NAME[prev], "diag": pkt.diag,
                        "diag_name": DIAG_NAME.get(pkt.diag, pkt.diag),
                        "src_ip": m.src_ip, "src_mac": m.src_mac,
                        "ttl": m.ttl})

        if cur in (STATE_DOWN, STATE_ADMIN_DOWN) and prev in (STATE_UP, STATE_INIT):
            self._register_down(d, m, pkt)

    def _register_down(self, d, m, pkt: BFDControl):
        ts = m.ts
        d.down_events.append(ts)
        self._trim(d.down_events, ts, FLAP_WINDOW_S)
        key = (d.src_ip, d.dst_ip, d.my_disc)
        self.recent_downs.append((ts, key))
        self._trim(self.recent_downs, ts, STORM_WINDOW_S)

        # per-session flap
        if len(d.down_events) >= FLAP_DOWN_THRESHOLD:
            self._emit(d, ts, "BFD-SESSION-FLAP",
                       f"{len(d.down_events)} Down transitions in the last "
                       f"{int(FLAP_WINDOW_S)}s.",
                       {"down_count": len(d.down_events),
                        "window_s": FLAP_WINDOW_S,
                        "last_diag": DIAG_NAME.get(pkt.diag, pkt.diag)})

        # cross-session convergence storm
        distinct = {k for _, k in self.recent_downs}
        if (len(distinct) >= STORM_SESSION_THRESHOLD
                and ts - self._storm_last > EVENT_REFIRE_S):
            self._storm_last = ts
            self._emit(None, ts, "BFD-CONVERGENCE-STORM",
                       f"{len(distinct)} distinct BFD sessions transitioned Down "
                       f"within {int(STORM_WINDOW_S)}s.",
                       {"session_count": len(distinct),
                        "window_s": STORM_WINDOW_S,
                        "sessions": [f"{a}->{b} 0x{c:08x}"
                                     for a, b, c in sorted(distinct)]},
                       session="<multiple>")

        # flagship correlation: teardown alongside path-integrity evidence
        self._trim(d.integrity_hits, ts, CORRELATION_WINDOW_S)
        if d.integrity_hits:
            reasons = sorted({c for _, c in d.integrity_hits})
            self._emit(d, ts, "BFD-SPOOFED-TEARDOWN",
                       f"Session went {STATE_NAME.get(pkt.state, pkt.state)} "
                       f"within {int(CORRELATION_WINDOW_S)}s of path-integrity "
                       f"evidence ({', '.join(reasons)}). Treat as a forged "
                       f"failover, not a link fault.",
                       {"trigger_state": STATE_NAME.get(pkt.state, pkt.state),
                        "diag": DIAG_NAME.get(pkt.diag, pkt.diag),
                        "correlated_codes": reasons,
                        "src_ip": m.src_ip, "src_mac": m.src_mac,
                        "ttl": m.ttl,
                        "window_s": CORRELATION_WINDOW_S})

    # -- Class E: echo posture -------------------------------------------

    def _check_echo_posture(self, d, m, pkt: BFDControl):
        if pkt.required_min_echo_rx and pkt.required_min_echo_rx > 0:
            self._emit(d, m.ts, "BFD-ECHO-ENABLED",
                       f"Required Min Echo RX Interval is "
                       f"{pkt.required_min_echo_rx} us; echo mode is offered.",
                       {"echo_rx_us": pkt.required_min_echo_rx})

    # -- reporting --------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        by_code: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for f in self.findings:
            by_code[f.code] = by_code.get(f.code, 0) + 1
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
        return {
            "module": MODULE_NAME,
            "version": __version__,
            "stats": dict(self.stats),
            "sessions_tracked": len(self.directions),
            "findings_total": len(self.findings),
            "by_severity": by_sev,
            "by_code": by_code,
        }


# ===========================================================================
# SECTION 7 — Capture sources
# ===========================================================================

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113


def read_pcap(path: str) -> Iterator[Tuple[float, bytes]]:
    """Minimal classic-pcap reader. pcapng is not handled here; convert with
    `editcap -F pcap in.pcapng out.pcap` or use --scapy."""
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            raise ValueError("file too short to be a pcap")
        magic = struct.unpack("<I", hdr[0:4])[0]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            endian, nsec = "<", magic == PCAP_MAGIC_NS_LE
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            endian, nsec = ">", magic == PCAP_MAGIC_NS_BE
        else:
            raise ValueError(
                f"not a classic pcap (magic 0x{magic:08x}); "
                f"convert pcapng with editcap or use --scapy")
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL):
            raise ValueError(f"unsupported linktype {linktype}; "
                             f"bfdwatch expects Ethernet or Linux SLL")
        sll = linktype == LINKTYPE_LINUX_SLL
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            sec, frac, caplen, _orig = struct.unpack(endian + "IIII", rec)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            ts = sec + (frac / 1e9 if nsec else frac / 1e6)
            if sll:
                # Linux cooked capture: 16-byte header, last 2 bytes = protocol.
                if len(data) < 16:
                    continue
                proto = data[14:16]
                data = b"\x00" * 6 + b"\x00" * 6 + proto + data[16:]
            yield ts, data


class _Shutdown:
    """Cooperative stop flag driven by SIGTERM/SIGINT.

    A mesh supervisor stops workers with SIGTERM. Without this the process dies
    mid-capture: no final summary, no exit code, and the supervisor cannot tell
    a clean stop from a crash. The handler only sets a flag; the capture loop
    finishes its current frame and unwinds normally.
    """

    def __init__(self):
        self.stop = False
        self.signal: Optional[str] = None

    def install(self):
        import signal as _sig
        for name in ("SIGTERM", "SIGINT", "SIGHUP"):
            sig = getattr(_sig, name, None)
            if sig is None:
                continue
            try:
                _sig.signal(sig, self._handle)
            except (ValueError, OSError):
                pass  # not the main thread, or unsupported platform

    def _handle(self, signum, frame):
        import signal as _sig
        self.stop = True
        try:
            self.signal = _sig.Signals(signum).name
        except ValueError:
            self.signal = str(signum)


def sniff_live(iface: str, watcher: BFDWatch, count: int = 0,
               timeout: Optional[float] = None,
               shutdown: Optional[_Shutdown] = None,
               heartbeat: float = 0.0, heartbeat_cb=None):
    """Live capture. Prefers a raw AF_PACKET socket; falls back to scapy."""
    sd = shutdown or _Shutdown()
    started = time.time()
    last_beat = started

    def _tick() -> bool:
        """Returns True when the loop should stop."""
        nonlocal last_beat
        now = time.time()
        if sd.stop:
            return True
        if timeout and now - started > timeout:
            return True
        if heartbeat and heartbeat_cb and now - last_beat >= heartbeat:
            last_beat = now
            heartbeat_cb()
        return False

    try:
        import socket as _s
        sock = _s.socket(_s.AF_PACKET, _s.SOCK_RAW, _s.htons(0x0003))
        sock.bind((iface, 0))
        # Always time out the recv, so the loop can observe the stop flag and
        # emit heartbeats on a quiet segment instead of blocking indefinitely.
        sock.settimeout(1.0)
        n = 0
        while True:
            if _tick() or (count and n >= count):
                return
            try:
                frame = sock.recv(65535)
            except (OSError, _s.timeout):
                continue
            watcher.observe_frame(frame, time.time())
            n += 1
    except PermissionError:
        raise SystemExit("bfdwatch: live capture needs CAP_NET_RAW (run as root)")
    except AttributeError:
        pass  # not Linux; try scapy

    try:
        from scapy.all import sniff  # type: ignore
    except ImportError:
        raise SystemExit("bfdwatch: no AF_PACKET and no scapy available")
    bpf = "udp and (port 3784 or port 3785 or port 4784 or port 6784)"
    sniff(iface=iface, filter=bpf, store=False, count=count or 0,
          timeout=timeout, stop_filter=lambda _p: _tick(),
          prn=lambda p: watcher.observe_frame(bytes(p), float(p.time)))


# ===========================================================================
# SECTION 8 — Tier 1 self-test (synthetic packet construction)
# ===========================================================================

def build_bfd(version=1, diag=0, state=STATE_UP, poll=False, final=False,
              cpi=False, demand=False, multipoint=False, detect_mult=3,
              my_disc=0x11111111, your_disc=0x22222222,
              tx=50000, rx=50000, echo_rx=0,
              auth_type=None, key_id=1, seq=None, password=b"secret",
              length_override=None) -> bytes:
    """Construct a BFD control packet for testing. Test-only; bfdwatch never
    transmits."""
    auth = b""
    if auth_type is not None:
        if auth_type == AUTH_SIMPLE_PASSWORD:
            auth = bytes([auth_type, 3 + len(password), key_id]) + password
        elif auth_type in AUTH_SEQUENCED:
            dlen = 16 if auth_type in (AUTH_KEYED_MD5,
                                       AUTH_METICULOUS_KEYED_MD5) else 20
            alen = 8 + dlen
            auth = (bytes([auth_type, alen, key_id, 0])
                    + struct.pack("!I", seq if seq is not None else 1)
                    + b"\xAB" * dlen)
        else:
            auth = bytes([auth_type, 8, key_id, 0]) + b"\x00" * 4

    b0 = ((version & 0x07) << 5) | (diag & 0x1F)
    b1 = ((state & 0x03) << 6)
    if poll:
        b1 |= 0x20
    if final:
        b1 |= 0x10
    if cpi:
        b1 |= 0x08
    if auth_type is not None:
        b1 |= 0x04
    if demand:
        b1 |= 0x02
    if multipoint:
        b1 |= 0x01
    length = length_override if length_override is not None else BFD_HDR_LEN + len(auth)
    return (bytes([b0, b1, detect_mult, length])
            + struct.pack("!IIIII", my_disc, your_disc, tx, rx, echo_rx)
            + auth)


def meta(payload: bytes, ts=1000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
         src_mac="aa:bb:cc:00:00:01", ttl=255, dport=PORT_SINGLE_HOP,
         sport=49152) -> PacketMeta:
    return PacketMeta(ts=ts, src_mac=src_mac, dst_mac="aa:bb:cc:00:00:02",
                      src_ip=src_ip, dst_ip=dst_ip, ip_version=4, ttl=ttl,
                      src_port=sport, dst_port=dport, payload=payload)


def self_test(verbose: bool = False) -> int:
    """Tier 1: every finding code must be reachable, and clean traffic must be
    silent. Returns the number of failures."""
    results: List[Tuple[str, bool, str]] = []

    def case(name: str, expect: Set[str], forbid: Set[str], run) -> None:
        w = BFDWatch()
        run(w)
        got = {f.code for f in w.findings}
        missing = expect - got
        leaked = forbid & got
        ok = not missing and not leaked
        note = ""
        if missing:
            note += f"missing={sorted(missing)} "
        if leaked:
            note += f"unexpected={sorted(leaked)} "
        if verbose and not ok:
            note += f"| all={sorted(got)}"
        results.append((name, ok, note.strip()))

    NOISE = {"BFD-MALFORMED-HEADER", "BFD-STATE-REGRESSION",
             "BFD-VERSION-UNKNOWN"}

    # --- clean baseline: strong auth, GTSM correct, stable Up -----------
    def clean(w):
        for i in range(5):
            w.observe(meta(build_bfd(
                auth_type=AUTH_METICULOUS_KEYED_SHA1, seq=100 + i),
                ts=1000.0 + i))
    case("clean meticulous SHA1 session",
         {"BFD-METICULOUS-SHA1-AUTH"},
         NOISE | {"BFD-NO-AUTH", "BFD-GTSM-VIOLATION",
                  "BFD-AUTH-REPLAY-WINDOW", "BFD-SESSION-FLAP"}, clean)

    # --- no auth --------------------------------------------------------
    case("unauthenticated single-hop", {"BFD-NO-AUTH"}, NOISE,
         lambda w: w.observe(meta(build_bfd())))

    # --- multihop no auth ----------------------------------------------
    case("unauthenticated multihop",
         {"BFD-NO-AUTH", "BFD-MULTIHOP-NO-AUTH"},
         NOISE | {"BFD-GTSM-VIOLATION"},
         lambda w: w.observe(meta(build_bfd(), ttl=61, dport=PORT_MULTIHOP)))

    # --- simple password -------------------------------------------------
    case("simple password auth", {"BFD-SIMPLE-PASSWORD-AUTH"}, NOISE,
         lambda w: w.observe(meta(build_bfd(auth_type=AUTH_SIMPLE_PASSWORD))))

    # --- keyed md5 / sha1 / meticulous md5 -------------------------------
    case("keyed MD5", {"BFD-KEYED-MD5-AUTH"}, NOISE,
         lambda w: w.observe(meta(build_bfd(auth_type=AUTH_KEYED_MD5, seq=1))))
    case("keyed SHA1", {"BFD-KEYED-SHA1-AUTH"}, NOISE,
         lambda w: w.observe(meta(build_bfd(auth_type=AUTH_KEYED_SHA1, seq=1))))
    case("meticulous MD5", {"BFD-METICULOUS-MD5-AUTH"}, NOISE,
         lambda w: w.observe(meta(build_bfd(
             auth_type=AUTH_METICULOUS_KEYED_MD5, seq=1))))

    # --- unknown auth type ----------------------------------------------
    case("unknown auth type", {"BFD-AUTH-UNKNOWN-TYPE"}, set(),
         lambda w: w.observe(meta(build_bfd(auth_type=9))))

    # --- replay window: measured seq stall -------------------------------
    def stall(w):
        for i in range(12):
            w.observe(meta(build_bfd(auth_type=AUTH_KEYED_MD5, seq=77),
                           ts=1000.0 + i))
    case("keyed MD5 stalled sequence", {"BFD-AUTH-REPLAY-WINDOW"}, NOISE, stall)

    # meticulous with stalled seq must NOT fire replay (it would be malformed
    # behaviour, but the replay code is scoped to non-meticulous by design)
    def stall_meticulous(w):
        for i in range(12):
            w.observe(meta(build_bfd(auth_type=AUTH_METICULOUS_KEYED_SHA1,
                                     seq=77), ts=1000.0 + i))
    case("meticulous stalled seq does not fire replay code",
         {"BFD-METICULOUS-SHA1-AUTH"}, {"BFD-AUTH-REPLAY-WINDOW"},
         stall_meticulous)

    # --- auth asymmetry --------------------------------------------------
    def asym(w):
        w.observe(meta(build_bfd(my_disc=0xAAAA0001, your_disc=0xBBBB0001,
                                 auth_type=AUTH_METICULOUS_KEYED_SHA1, seq=5),
                       src_ip="10.0.0.1", dst_ip="10.0.0.2", ts=1000.0))
        w.observe(meta(build_bfd(my_disc=0xBBBB0001, your_disc=0xAAAA0001),
                       src_ip="10.0.0.2", dst_ip="10.0.0.1",
                       src_mac="aa:bb:cc:00:00:02", ts=1000.1))
    case("one-sided authentication", {"BFD-AUTH-ASYMMETRIC"}, NOISE, asym)

    # --- auth downgrade --------------------------------------------------
    def downgrade(w):
        w.observe(meta(build_bfd(auth_type=AUTH_METICULOUS_KEYED_SHA1, seq=1),
                       ts=1000.0))
        w.observe(meta(build_bfd(auth_type=AUTH_SIMPLE_PASSWORD), ts=1000.1))
    case("mid-session auth downgrade", {"BFD-AUTH-DOWNGRADE"}, NOISE, downgrade)

    # --- version --------------------------------------------------------
    case("BFD version 0", {"BFD-VERSION-ZERO"}, {"BFD-VERSION-UNKNOWN"},
         lambda w: w.observe(meta(build_bfd(version=0))))
    case("BFD version 5", {"BFD-VERSION-UNKNOWN"}, {"BFD-VERSION-ZERO"},
         lambda w: w.observe(meta(build_bfd(version=5))))

    # --- truncated header (CVE-2018-0155 primitive) ---------------------
    case("truncated header", {"BFD-TRUNCATED-HEADER"}, set(),
         lambda w: w.observe(meta(build_bfd()[:11])))

    # --- malformed: length lies, detect mult zero ------------------------
    case("length field overruns datagram", {"BFD-MALFORMED-HEADER"}, set(),
         lambda w: w.observe(meta(build_bfd(length_override=200))))
    case("detect mult zero", {"BFD-MALFORMED-HEADER"}, set(),
         lambda w: w.observe(meta(build_bfd(detect_mult=0))))
    case("your-disc zero while Up", {"BFD-MALFORMED-HEADER"}, set(),
         lambda w: w.observe(meta(build_bfd(your_disc=0, state=STATE_UP))))

    # --- zero my-discriminator ------------------------------------------
    case("zero My Discriminator", {"BFD-ZERO-DISCRIMINATOR"}, set(),
         lambda w: w.observe(meta(build_bfd(my_disc=0))))

    # --- reserved diag ---------------------------------------------------
    case("reserved diagnostic", {"BFD-RESERVED-DIAG"}, NOISE,
         lambda w: w.observe(meta(build_bfd(diag=17))))

    # --- flag combos -----------------------------------------------------
    case("poll and final together", {"BFD-INVALID-FLAG-COMBO"}, NOISE,
         lambda w: w.observe(meta(build_bfd(poll=True, final=True))))
    case("multipoint bit set", {"BFD-INVALID-FLAG-COMBO"}, NOISE,
         lambda w: w.observe(meta(build_bfd(multipoint=True))))

    # --- GTSM ------------------------------------------------------------
    case("single-hop TTL 64", {"BFD-GTSM-VIOLATION"}, NOISE,
         lambda w: w.observe(meta(build_bfd(), ttl=64)))
    case("lag-member TTL 254", {"BFD-GTSM-VIOLATION"}, NOISE,
         lambda w: w.observe(meta(build_bfd(), ttl=254, dport=PORT_LAG)))
    case("multihop TTL 60 is not a GTSM violation", set(),
         {"BFD-GTSM-VIOLATION"},
         lambda w: w.observe(meta(build_bfd(), ttl=60, dport=PORT_MULTIHOP)))

    # --- source migration -------------------------------------------------
    def migrate(w):
        w.observe(meta(build_bfd(), ts=1000.0, src_mac="aa:bb:cc:00:00:01"))
        w.observe(meta(build_bfd(), ts=1000.1, src_mac="de:ad:be:ef:00:99"))
    case("discriminator moves to a new MAC", {"BFD-SOURCE-MIGRATION"}, NOISE,
         migrate)

    # --- discriminator collision -----------------------------------------
    def collide(w):
        w.observe(meta(build_bfd(my_disc=0x5150), src_ip="10.0.0.1", ts=1000.0))
        w.observe(meta(build_bfd(my_disc=0x5150), src_ip="10.0.0.9",
                       src_mac="de:ad:be:ef:00:09", ts=1000.1))
    case("two sources claim one discriminator",
         {"BFD-DISCRIMINATOR-COLLISION"}, NOISE, collide)

    # --- state regression -------------------------------------------------
    def regress(w):
        w.observe(meta(build_bfd(state=STATE_UP), ts=1000.0))
        w.observe(meta(build_bfd(state=STATE_INIT), ts=1000.1))
    case("Up -> Init", {"BFD-STATE-REGRESSION"}, set(), regress)

    def legit_down_up(w):
        w.observe(meta(build_bfd(state=STATE_DOWN, your_disc=0), ts=1000.0))
        w.observe(meta(build_bfd(state=STATE_UP), ts=1000.1))
    case("Down -> Up is legal", set(), {"BFD-STATE-REGRESSION"}, legit_down_up)

    # --- forced admindown -------------------------------------------------
    def admindown(w):
        w.observe(meta(build_bfd(state=STATE_UP), ts=1000.0))
        w.observe(meta(build_bfd(state=STATE_ADMIN_DOWN, diag=7), ts=1000.1))
    case("Up -> AdminDown", {"BFD-FORCED-ADMINDOWN"}, set(), admindown)

    # --- flap -------------------------------------------------------------
    def flap(w):
        t = 1000.0
        for _ in range(6):
            w.observe(meta(build_bfd(state=STATE_UP), ts=t))
            t += 1
            w.observe(meta(build_bfd(state=STATE_DOWN, your_disc=0), ts=t))
            t += 1
    case("repeated down transitions", {"BFD-SESSION-FLAP"}, set(), flap)

    # --- convergence storm -------------------------------------------------
    def storm(w):
        t = 1000.0
        for i in range(4):
            disc = 0x1000 + i
            peer = f"10.0.{i}.2"
            w.observe(meta(build_bfd(my_disc=disc, state=STATE_UP),
                           dst_ip=peer, ts=t))
            w.observe(meta(build_bfd(my_disc=disc, state=STATE_DOWN,
                                     your_disc=0), dst_ip=peer, ts=t + 0.5))
            t += 1
    case("multiple sessions down at once", {"BFD-CONVERGENCE-STORM"}, set(),
         storm)

    # --- detect time degraded ----------------------------------------------
    def shrink(w):
        w.observe(meta(build_bfd(detect_mult=5, tx=1000000, rx=1000000),
                       ts=1000.0))
        w.observe(meta(build_bfd(detect_mult=1, tx=50000, rx=50000), ts=1000.1))
    case("detection time collapsed without a poll",
         {"BFD-DETECT-TIME-DEGRADED"}, set(), shrink)

    # --- echo ---------------------------------------------------------------
    case("echo mode advertised", {"BFD-ECHO-ENABLED"}, NOISE,
         lambda w: w.observe(meta(build_bfd(echo_rx=50000))))
    case("non-self-addressed echo", {"BFD-ECHO-SRC-MISMATCH"}, set(),
         lambda w: w.observe(meta(b"\x00" * 16, src_ip="10.0.0.1",
                                  dst_ip="10.0.0.7", dport=PORT_ECHO)))

    # --- flagship: spoofed teardown -----------------------------------------
    def spoofed(w):
        w.observe(meta(build_bfd(state=STATE_UP), ts=1000.0, ttl=255))
        # off-path injected teardown: TTL wrong, new MAC, session goes down
        w.observe(meta(build_bfd(state=STATE_DOWN, diag=3, your_disc=0),
                       ts=1000.5, ttl=62, src_mac="de:ad:be:ef:66:66"))
    case("GTSM violation correlated with teardown",
         {"BFD-SPOOFED-TEARDOWN", "BFD-GTSM-VIOLATION",
          "BFD-SOURCE-MIGRATION"}, set(), spoofed)

    def clean_teardown(w):
        w.observe(meta(build_bfd(state=STATE_UP), ts=1000.0))
        w.observe(meta(build_bfd(state=STATE_DOWN, diag=1, your_disc=0),
                       ts=1000.5))
    case("clean link-fault teardown does not fire spoofed-teardown",
         set(), {"BFD-SPOOFED-TEARDOWN"}, clean_teardown)

    # --- decode path --------------------------------------------------------
    def decode_roundtrip(w):
        bfd = build_bfd(auth_type=AUTH_SIMPLE_PASSWORD)
        udp = struct.pack("!HHHH", 49152, PORT_SINGLE_HOP, 8 + len(bfd), 0) + bfd
        ip = (bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 255, 17, 0, 0])
              + b"\x0a\x00\x00\x01" + b"\x0a\x00\x00\x02" + udp)
        ip = ip[:2] + struct.pack("!H", len(ip)) + ip[4:]
        eth = (b"\xaa\xbb\xcc\x00\x00\x02" + b"\xaa\xbb\xcc\x00\x00\x01"
               + struct.pack("!H", ETH_P_IPV4) + ip)
        w.observe_frame(eth, 1000.0)
    case("ethernet/IPv4/UDP decode reaches the parser",
         {"BFD-SIMPLE-PASSWORD-AUTH"}, {"BFD-GTSM-VIOLATION"},
         decode_roundtrip)

    def decode_vlan_v6(w):
        bfd = build_bfd()
        udp = struct.pack("!HHHH", 49152, PORT_SINGLE_HOP, 8 + len(bfd), 0) + bfd
        v6 = (b"\x60\x00\x00\x00" + struct.pack("!H", len(udp))
              + bytes([17, 200])
              + ipaddress.IPv6Address("2001:db8::1").packed
              + ipaddress.IPv6Address("2001:db8::2").packed + udp)
        eth = (b"\xaa\xbb\xcc\x00\x00\x02" + b"\xaa\xbb\xcc\x00\x00\x01"
               + struct.pack("!H", ETH_P_8021Q) + struct.pack("!H", 0x0064)
               + struct.pack("!H", ETH_P_IPV6) + v6)
        w.observe_frame(eth, 1000.0)
    case("802.1Q/IPv6 decode plus hop-limit GTSM",
         {"BFD-GTSM-VIOLATION", "BFD-NO-AUTH"}, set(), decode_vlan_v6)

    # --- report --------------------------------------------------------------
    width = max(len(n) for n, _, _ in results)
    failures = 0
    for name, ok, note in results:
        if not ok:
            failures += 1
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name.ljust(width)}"
        if note:
            line += f"  {note}"
        print(line)

    # Code reachability audit. The tested set is maintained by hand so that
    # adding a code without adding a case is a hard failure, not a silent gap.
    covered = {spec.code for spec in CODES.values()}
    tested = {
        "BFD-NO-AUTH", "BFD-SIMPLE-PASSWORD-AUTH", "BFD-KEYED-MD5-AUTH",
        "BFD-KEYED-SHA1-AUTH", "BFD-METICULOUS-MD5-AUTH",
        "BFD-METICULOUS-SHA1-AUTH", "BFD-AUTH-UNKNOWN-TYPE",
        "BFD-AUTH-REPLAY-WINDOW", "BFD-AUTH-ASYMMETRIC", "BFD-AUTH-DOWNGRADE",
        "BFD-MULTIHOP-NO-AUTH", "BFD-VERSION-ZERO", "BFD-VERSION-UNKNOWN",
        "BFD-TRUNCATED-HEADER", "BFD-MALFORMED-HEADER",
        "BFD-ZERO-DISCRIMINATOR", "BFD-RESERVED-DIAG",
        "BFD-INVALID-FLAG-COMBO", "BFD-GTSM-VIOLATION",
        "BFD-SOURCE-MIGRATION", "BFD-DISCRIMINATOR-COLLISION",
        "BFD-STATE-REGRESSION", "BFD-SESSION-FLAP", "BFD-CONVERGENCE-STORM",
        "BFD-FORCED-ADMINDOWN", "BFD-DETECT-TIME-DEGRADED",
        "BFD-ECHO-ENABLED", "BFD-ECHO-SRC-MISMATCH", "BFD-SPOOFED-TEARDOWN",
    }
    unreached = covered - tested
    print()
    print(f"  codes defined: {len(covered)}   codes exercised: {len(tested)}")
    if unreached:
        failures += 1
        print(f"  [FAIL] unreachable codes: {sorted(unreached)}")
    else:
        print("  [PASS] every defined code is exercised by a test case")

    print()
    print(f"  {len(results) - failures}/{len(results)} cases passed")
    return failures


# ===========================================================================
# SECTION 9 — CLI
# ===========================================================================

SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.INFO: 4}
SEV_TAG = {Severity.CRITICAL: "CRIT", Severity.HIGH: "HIGH",
           Severity.MEDIUM: "MED ", Severity.LOW: "LOW ", Severity.INFO: "INFO"}


def print_finding(f: Finding):
    print(f"[{SEV_TAG[f.severity]}] {f.code}  ({f.confidence.value})")
    print(f"        session: {f.session}")
    print(f"        {f.detail}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="bfdwatch",
        description="Passive BFD failover-manipulation detector (Ragnar module)")
    src = p.add_mutually_exclusive_group()
    src.add_argument("-r", "--pcap", help="read from a classic pcap file")
    src.add_argument("-i", "--iface", help="live capture interface")
    p.add_argument("--self-test", action="store_true",
                   help="run the Tier 1 self-test and exit")
    p.add_argument("--json", action="store_true", help="emit JSON lines")
    p.add_argument("--summary", action="store_true", help="print a summary")
    p.add_argument("--min-severity", default="INFO",
                   choices=[s.value for s in Severity])
    p.add_argument("--quiet-info", action="store_true",
                   help="suppress INFO posture findings entirely")
    p.add_argument("--count", type=int, default=0, help="stop after N frames")
    p.add_argument("--timeout", type=float, default=None,
                   help="stop live capture after N seconds")
    p.add_argument("--heartbeat", type=float, default=0.0, metavar="SEC",
                   help="emit a liveness/stats record every SEC seconds "
                        "(live capture only; for mesh health monitoring)")
    p.add_argument("--codes", action="store_true",
                   help="print the finding-code catalogue and exit")
    p.add_argument("--version", action="version",
                   version=f"{MODULE_NAME} {__version__}")
    args = p.parse_args(argv)

    if args.codes:
        for spec in sorted(CODES.values(),
                           key=lambda s: (SEV_ORDER[s.severity], s.code)):
            print(f"{SEV_TAG[spec.severity]}  {spec.code:<32} "
                  f"{spec.confidence.value:<9} {spec.title}")
        return 0

    if args.self_test:
        print(f"{MODULE_NAME} {__version__} — Tier 1 self-test")
        return 1 if self_test() else 0

    if not args.pcap and not args.iface:
        p.error("one of --pcap or --iface is required (or --self-test)")

    floor = SEV_ORDER[Severity(args.min_severity)]

    def emit(f: Finding):
        if SEV_ORDER[f.severity] > floor:
            return
        if args.json:
            print(json.dumps(f.to_dict()), flush=True)
        else:
            print_finding(f)

    w = BFDWatch(emit=emit, quiet_info=args.quiet_info)
    shutdown = _Shutdown()
    shutdown.install()

    def beat():
        rec = w.summary()
        rec["record"] = "heartbeat"
        rec["uptime_s"] = round(time.time() - t_start, 1)
        print(json.dumps(rec), flush=True)

    t_start = time.time()
    if args.pcap:
        n = 0
        for ts, frame in read_pcap(args.pcap):
            if shutdown.stop:
                break
            w.observe_frame(frame, ts)
            n += 1
            if args.count and n >= args.count:
                break
    else:
        sniff_live(args.iface, w, count=args.count, timeout=args.timeout,
                   shutdown=shutdown, heartbeat=args.heartbeat,
                   heartbeat_cb=beat if args.heartbeat else None)

    if shutdown.stop and not args.json:
        print(f"\n  stopped on {shutdown.signal}", file=sys.stderr)

    if args.summary:
        if args.json:
            final = w.summary()
            final["record"] = "summary"
            if shutdown.stop:
                final["stopped_on"] = shutdown.signal
            print(json.dumps(final), flush=True)
        else:
            s = w.summary()
            print()
            print(f"  frames={s['stats']['frames']} "
                  f"bfd={s['stats']['bfd_packets']} "
                  f"control={s['stats']['control']} "
                  f"echo={s['stats']['echo']}")
            print(f"  sessions={s['sessions_tracked']} "
                  f"findings={s['findings_total']}")
            for sev in Severity:
                c = s["by_severity"].get(sev.value)
                if c:
                    print(f"    {sev.value:<9} {c}")

    worst = min((SEV_ORDER[f.severity] for f in w.findings), default=99)
    return 2 if worst <= SEV_ORDER[Severity.HIGH] else 0


# CLI entrypoint removed on vendoring; this module is imported by Ragnar.


# ===========================================================================
# RAGNAR IN-APP ADAPTER  (appended on vendoring; not part of the upstream CLI)
# ---------------------------------------------------------------------------
# Snapshot-over-pcap adapter mirroring lacpwatch/rpcwatch: one tcpdump capture
# on the interface, replayed through the streaming BFDWatch engine, reduced to a
# single card verdict, with HIGH/CRITICAL findings streamed to Watchtower. The
# detection path is pure-Python (own libpcap reader; scapy only for the CLI's
# live mode, which this adapter does not use). Detection-only: never transmits.
# ===========================================================================
import os
import json
import time
import tempfile
import subprocess
from datetime import datetime, timezone

# Severity → rank, worst last (mirrors the engine's SEV_ORDER but as an int
# ladder the adapter can compare with >=).
_BFD_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# A forged BFD packet convinces a router a healthy path is dead; the routing
# protocols then do the damage. These are the codes that mean an *induced*
# failover / teardown — the critical verdict token, mirrored into the web
# net-integrity critical set as 'failover-manipulation'.
_BFD_TEARDOWN_CODES = frozenset((
    "BFD-SPOOFED-TEARDOWN", "BFD-FORCED-ADMINDOWN", "BFD-STATE-REGRESSION"))
# Behavioural instability (flap / storm / detect-time collapse): real but not,
# on its own, proof of a forged teardown.
_BFD_INSTABILITY_CODES = frozenset((
    "BFD-SESSION-FLAP", "BFD-CONVERGENCE-STORM", "BFD-DETECT-TIME-DEGRADED"))


def _bfd_verdict(findings):
    """Reduce a finding-dict list to (verdict, ranked-worst-first)."""
    ranked = sorted(findings,
                    key=lambda f: _BFD_SEV_RANK.get(f.get("severity"), 0),
                    reverse=True)
    codeset = {f.get("code") for f in ranked}
    if codeset & _BFD_TEARDOWN_CODES:
        return "failover-manipulation", ranked
    if any(_BFD_SEV_RANK.get(f.get("severity"), 0) >= 3 for f in ranked):
        return "exposure", ranked
    if codeset & _BFD_INSTABILITY_CODES:
        return "instability", ranked
    return "clean", ranked


# --- Watchtower feed --------------------------------------------------------
_BFD_WT_LOG_DIR = os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_BFD_WT_DEDUP_S = 300.0
_BFD_WT_EMIT_SEV = frozenset(("HIGH", "CRITICAL"))
_bfd_wt_lock = None
_bfd_wt_seen = {}


def _bfd_emit_watchtower(result):
    """Append HIGH/CRITICAL BFD findings to <log-dir>/bfd_watch.jsonl in the shape
    Watchtower.normalize() reads, so spoofed-teardown / forced-admindown / flap /
    malformed-header (CVE-2018-0155) alerts fold into the unified pane + single
    Pushover path. Deduped per (code, session) over the window. Never raises."""
    global _bfd_wt_lock
    if _bfd_wt_lock is None:
        import threading
        _bfd_wt_lock = threading.Lock()
    if not result.get("success"):
        return
    verdict = result.get("verdict", "clean")
    iface = result.get("interface")
    now = time.time()
    iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    with _bfd_wt_lock:
        for f in result.get("findings", []):
            if f.get("severity") not in _BFD_WT_EMIT_SEV:
                continue
            code = f.get("code")
            sess = f.get("session")
            key = (code, sess)
            last = _bfd_wt_seen.get(key)
            if last is not None and now - last < _BFD_WT_DEDUP_S:
                continue
            _bfd_wt_seen[key] = now
            lines.append(json.dumps({
                "module": "bfd_watch", "ts": now, "iso": iso, "iface": iface,
                "severity": f.get("severity"), "code": code, "codes": [code],
                "src": sess, "summary": f.get("title"), "verdict": verdict}))
        if len(_bfd_wt_seen) > 4096:
            cutoff = now - _BFD_WT_DEDUP_S
            for k in [k for k, t in _bfd_wt_seen.items() if t < cutoff]:
                _bfd_wt_seen.pop(k, None)
    if not lines:
        return
    try:
        os.makedirs(_BFD_WT_LOG_DIR, exist_ok=True)
        with open(os.path.join(_BFD_WT_LOG_DIR, "bfd_watch.jsonl"), "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


# --- capture ----------------------------------------------------------------
# BFD rides UDP on the four RFC-assigned ports; catch all of them so echo,
# multihop and micro-BFD (LAG) sessions are all seen. Structural filtering is
# left to the engine.
_BFD_BPF = "udp and (port 3784 or port 3785 or port 4784 or port 6784)"


def _bfd_capture_pcap(interface, seconds):
    """tcpdump a BFD snapshot to a temp classic-pcap file. Returns (path, error).
    Detection-only: no transmit."""
    from shutil import which
    if not which("tcpdump"):
        return None, "tcpdump is not installed. Click Install to add it."
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        res = subprocess.run(
            ["timeout", str(int(seconds) + 3), "tcpdump", "-i", interface,
             "-nn", "-s", "256", "-c", "20000", "-w", path, _BFD_BPF],
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


def do_bfd_watch(interface=None, seconds=20):
    """Passive BFD failover-manipulation scan (detection-only). One tcpdump snapshot
    on `interface`, replayed through the streaming engine; reports forged teardowns
    (spoofed teardown / forced AdminDown / illegal state regression), malformed or
    truncated headers (CVE-2018-0155 iosd crash on affected Catalyst offload),
    auth posture (no-auth / downgrade / asymmetric / replay-window), GTSM (TTL 255)
    violations, discriminator collision / source migration, and behavioural
    instability (flap / convergence storm / detect-time collapse). Streams
    HIGH/CRITICAL findings to Watchtower. Never transmits a BFD packet."""
    if not interface:
        return {"success": False, "error": "no interface specified"}
    seconds = max(8, min(int(seconds or 20), 60))
    path, err = _bfd_capture_pcap(interface, seconds)
    if err:
        return {"success": False, "interface": interface, "error": err,
                "missing_tool": "tcpdump" if "not installed" in err else None}
    eng = BFDWatch()
    try:
        for ts, frame in read_pcap(path):
            eng.observe_frame(frame, ts)
    except Exception as e:
        try:
            os.remove(path)
        except OSError:
            pass
        return {"success": False, "interface": interface,
                "error": "capture parse failed: {}".format(type(e).__name__)}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    findings = [f.to_dict() for f in eng.findings]
    verdict, ranked = _bfd_verdict(findings)
    # Reasons: distinct actionable findings (>= medium), worst first, deduped by
    # code, capped — plus a clean line when only posture/inventory surfaced.
    reasons, seen = [], set()
    for f in ranked:
        if _BFD_SEV_RANK.get(f.get("severity"), 0) < 2:
            continue
        if f["code"] in seen:
            continue
        seen.add(f["code"])
        reasons.append("{}: {} [{}]".format(f["code"], f.get("title", ""),
                                             f.get("session", "")))
        if len(reasons) >= 8:
            break
    stats = eng.summary().get("stats", {})
    if not reasons:
        if stats.get("bfd_packets"):
            reasons = ["BFD sessions observed; no forged teardown, malformed "
                       "header, auth-downgrade, GTSM or instability detected"]
        else:
            reasons = ["No BFD traffic seen on this segment "
                       "(UDP 3784/3785/4784/6784)"]

    by_sev = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    result = {
        "success": True, "interface": interface, "seconds": seconds,
        "verdict": verdict, "reasons": reasons,
        "findings": findings,
        "sessions": eng.summary().get("sessions_tracked", 0),
        "by_severity": by_sev, "stats": stats,
    }
    _bfd_emit_watchtower(result)
    return result


# --- selftest (aggregator shape: {'success', 'scenarios':[{name,pass,detail}]}) ---
def selftest():
    """Build real BFD control packets, feed them through the engine, and assert the
    findings; plus run the engine's own 39-case Tier-1 suite. No sockets, no
    capture, no persistence — asserted by construction (the engine only reads
    bytes)."""
    scen = []

    def check(name, ok, detail=""):
        scen.append({"name": name, "pass": bool(ok), "detail": detail})

    def run(metas):
        w = BFDWatch()
        for m in metas:
            w.observe(m)
        return {f.code for f in w.findings}

    # Real captures carry real epoch timestamps; the engine rate-limits events
    # raised before a session exists in a window seeded at t=0, so — as in the
    # engine's own suite — these constructed frames use ts >= 1000.0.
    # 1. Clean authenticated single-hop session stays silent of attack codes.
    up = build_bfd(state=STATE_UP, auth_type=AUTH_METICULOUS_KEYED_SHA1, seq=1)
    up2 = build_bfd(state=STATE_UP, auth_type=AUTH_METICULOUS_KEYED_SHA1, seq=2)
    got = run([meta(up, ts=1000.0), meta(up2, ts=1000.1)])
    attack = got & (_BFD_TEARDOWN_CODES | _BFD_INSTABILITY_CODES)
    check("clean-authenticated-silent", not attack, "attack=%s" % sorted(attack))

    # 2. Unauthenticated single-hop -> BFD-NO-AUTH.
    got = run([meta(build_bfd(state=STATE_UP), ts=1000.0)])
    check("no-auth", "BFD-NO-AUTH" in got, sorted(got))

    # 3. TTL 64 on single-hop -> GTSM violation (RFC 5881 requires 255).
    got = run([meta(build_bfd(state=STATE_UP), ts=1000.0, ttl=64)])
    check("gtsm-violation", "BFD-GTSM-VIOLATION" in got, sorted(got))

    # 4. Up -> AdminDown teardown -> BFD-FORCED-ADMINDOWN (failover-manip token).
    got = run([meta(build_bfd(state=STATE_UP), ts=1000.0),
               meta(build_bfd(state=STATE_ADMIN_DOWN, diag=7), ts=1000.1)])
    check("forced-admindown", "BFD-FORCED-ADMINDOWN" in got, sorted(got))

    # 5. Truncated header (CVE-2018-0155 exploitation signal).
    got = run([meta(build_bfd(state=STATE_UP)[:11], ts=1000.0)])
    check("truncated-header", "BFD-TRUNCATED-HEADER" in got, sorted(got))

    # 6. Adapter verdict mapping: a forced teardown must rank 'failover-manipulation'.
    v, _ = _bfd_verdict([{"code": "BFD-FORCED-ADMINDOWN", "severity": "HIGH"},
                         {"code": "BFD-NO-AUTH", "severity": "MEDIUM"}])
    check("verdict-failover-manipulation", v == "failover-manipulation", v)

    # 7. Engine's own Tier-1 suite (39 cases): 0 failures.
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        failures = self_test(verbose=False)
    check("engine-tier1-39-cases", failures == 0, "failures=%d" % failures)

    return {"success": all(s["pass"] for s in scen), "scenarios": scen}
