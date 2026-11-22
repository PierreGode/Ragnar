"""
bgp.py -- receive-only BGP route collector for pathwatch.

Purpose: give the convergence detector *causal ground truth*. The external
detector (probe.py/analyze.py) sees symptoms -- latency steps, loss, path
changes. This module peers the Pi as a receive-only BGP speaker and watches the
actual control plane: withdrawals, re-announcements, and AS-path changes per
prefix. When a data-plane symptom on target T coincides with a RIB event on the
prefix covering T, the verdict is no longer "suspected" -- it is *confirmed*,
with the cause attached (which prefix, old vs new AS-path, when).

Two extra payoffs:
  * The RIB is an authoritative ip->origin-AS source, so ASN enrichment no
    longer depends on Team Cymru whois for any covered prefix.
  * Control-plane-first alerting: churn can be flagged even before the data
    plane visibly degrades.

Layering, for testability:
  * codec  (build_* / parse_*)  -- pure bytes <-> objects, no sockets
  * frame_messages()            -- pure buffer framer
  * Rib                         -- pure state machine over parsed UPDATEs
  * BgpSpeaker                  -- the only part that touches a socket / thread

Standards: RFC 4271 (BGP-4), RFC 6793 (4-octet ASN), RFC 4760 (MP-BGP, incl.
IPv6 unicast NLRI), RFC 2545 (use of MP-BGP for IPv6 inter-domain routing).
Receive-only: we send OPEN + KEEPALIVEs and never originate NLRI. Configure the
router side to send routes and (ideally) reject anything from us.

MP-BGP carries IPv6 NLRI in MP_REACH_NLRI/MP_UNREACH_NLRI attributes rather
than the base UPDATE fields (which stay IPv4-only, per RFC 4271); the codec,
the RIB, and the correlator are all already generic on address family (the
RIB even keeps a separate LPM trie per family -- see iptrie.py), so v6 support
is a matter of the wire codec speaking MP_REACH/MP_UNREACH correctly, which is
what encode_mp_reach/encode_mp_unreach/decode_mp_nexthop below do. The BGP
*session* itself can independently run over an IPv4 or IPv6 TCP transport
(BgpSpeaker picks the socket family from `peer_ip`) regardless of which
AFI/SAFI it's carrying -- e.g. peer over an IPv6 loopback while exchanging
IPv4 and/or IPv6 NLRI, or the reverse.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Iterator, Optional

from iptrie import IpTrie, ip_to_int, prefix_to_int

MARKER = b"\xff" * 16
HDR_LEN = 19
MAX_MSG = 4096

# message types
OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE_REFRESH = 1, 2, 3, 4, 5

# capability codes
CAP_MP, CAP_ROUTE_REFRESH, CAP_4OCTET_AS = 1, 2, 65

# path attribute types
ATTR_ORIGIN, ATTR_AS_PATH, ATTR_NEXT_HOP, ATTR_MED = 1, 2, 3, 4
ATTR_LOCAL_PREF, ATTR_ATOMIC_AGG, ATTR_AGGREGATOR = 5, 6, 7
ATTR_COMMUNITIES, ATTR_MP_REACH, ATTR_MP_UNREACH = 8, 14, 15

AS_TRANS = 23456   # placeholder in 2-byte my_as field when real ASN is 32-bit


# --------------------------------------------------------------------------- #
# prefix (NLRI) codec
# --------------------------------------------------------------------------- #
def decode_prefixes(data: bytes, bits: int = 32) -> list[str]:
    """Decode a run of BGP NLRI: 1 byte prefix-length (bits) then ceil(len/8)
    bytes of prefix, MSB-aligned. Returns ['a.b.c.d/len', ...]."""
    out: list[str] = []
    i = 0
    nbytes_full = bits // 8
    while i < len(data):
        plen = data[i]
        i += 1
        if plen > bits:
            break
        nbytes = (plen + 7) // 8
        raw = data[i:i + nbytes]
        i += nbytes
        raw = raw + b"\x00" * (nbytes_full - len(raw))
        val = int.from_bytes(raw, "big")
        if bits == 32:
            ip = socket.inet_ntoa(val.to_bytes(4, "big"))
        else:
            ip = socket.inet_ntop(socket.AF_INET6, val.to_bytes(16, "big"))
        out.append(f"{ip}/{plen}")
    return out


def encode_prefix(prefix: str) -> bytes:
    net_int, plen, bits = prefix_to_int(prefix)
    nbytes = (plen + 7) // 8
    full = net_int.to_bytes(bits // 8, "big")
    return bytes([plen]) + full[:nbytes]


# --------------------------------------------------------------------------- #
# AS_PATH codec (4-octet)
# --------------------------------------------------------------------------- #
def decode_as_path(data: bytes) -> tuple[list[int], bool]:
    """Return (flattened AS sequence, contains_as_set). Assumes 4-octet ASNs."""
    path: list[int] = []
    has_set = False
    i = 0
    while i + 2 <= len(data):
        seg_type = data[i]
        seg_len = data[i + 1]
        i += 2
        for _ in range(seg_len):
            if i + 4 > len(data):
                break
            asn = int.from_bytes(data[i:i + 4], "big")
            i += 4
            path.append(asn)
        if seg_type == 1:      # AS_SET
            has_set = True
    return path, has_set


def encode_as_path(asns: list[int]) -> bytes:
    if not asns:
        return b""
    body = bytes([2, len(asns)]) + b"".join(a.to_bytes(4, "big") for a in asns)
    return body


# --------------------------------------------------------------------------- #
# MP-BGP (RFC 4760): NLRI for any AFI/SAFI beyond plain IPv4 unicast --
# this is how IPv6 (and everything else) actually travels on the wire.
# --------------------------------------------------------------------------- #
def encode_mp_reach(afi: int, safi: int, next_hop: bytes, prefixes: list) -> bytes:
    """Build an MP_REACH_NLRI attribute value (RFC 4760 section 3).

    `next_hop` is the raw address bytes (4 for AFI=1, 16 for AFI=2 -- 32 if
    you want to include a link-local pair per RFC 2545). `prefixes` reuses
    encode_prefix, which is already generic on bit width, so this works for
    any AFI without extra branching.
    """
    nlri = b"".join(encode_prefix(p) for p in prefixes)
    return (struct.pack("!HBB", afi, safi, len(next_hop)) + next_hop
            + b"\x00"           # reserved octet
            + nlri)


def encode_mp_unreach(afi: int, safi: int, prefixes: list) -> bytes:
    """Build an MP_UNREACH_NLRI attribute value (RFC 4760 section 4)."""
    nlri = b"".join(encode_prefix(p) for p in prefixes)
    return struct.pack("!HB", afi, safi) + nlri


# --------------------------------------------------------------------------- #
# messages
# --------------------------------------------------------------------------- #
@dataclass
class BgpOpen:
    version: int
    my_as: int          # real ASN (already resolved from 4-octet cap if present)
    hold: int
    bgp_id: str
    four_octet: bool = False


@dataclass
class BgpUpdate:
    withdrawn: list[str] = field(default_factory=list)
    nlri: list[str] = field(default_factory=list)
    as_path: list[int] = field(default_factory=list)
    has_as_set: bool = False
    next_hop: Optional[str] = None
    origin: Optional[int] = None
    med: Optional[int] = None
    local_pref: Optional[int] = None
    communities: list[tuple[int, int]] = field(default_factory=list)

    @property
    def origin_as(self) -> Optional[int]:
        return self.as_path[-1] if self.as_path else None


@dataclass
class BgpNotification:
    code: int
    subcode: int
    data: bytes = b""


def _header(msg_type: int, body: bytes) -> bytes:
    length = HDR_LEN + len(body)
    return MARKER + struct.pack("!HB", length, msg_type) + body


def build_open(local_as: int, hold: int, bgp_id: str,
               afi_list=(1,)) -> bytes:
    """Build an OPEN advertising 4-octet ASN, route-refresh, and MP for the
    given AFIs (1=IPv4, 2=IPv6), SAFI unicast."""
    my_as_field = local_as if local_as <= 0xFFFF else AS_TRANS
    bid = socket.inet_aton(bgp_id)

    caps = b""
    # 4-octet ASN
    caps += bytes([2, 2 + 4, CAP_4OCTET_AS, 4]) + local_as.to_bytes(4, "big")
    # route refresh
    caps += bytes([2, 2, CAP_ROUTE_REFRESH, 0])
    # MP-BGP per AFI, SAFI=1 unicast
    for afi in afi_list:
        capval = struct.pack("!HBB", afi, 0, 1)
        caps += bytes([2, 2 + len(capval), CAP_MP, len(capval)]) + capval

    body = struct.pack("!BHH", 4, my_as_field, hold) + bid \
        + bytes([len(caps)]) + caps
    return _header(OPEN, body)


def build_keepalive() -> bytes:
    return _header(KEEPALIVE, b"")


def parse_open(body: bytes) -> BgpOpen:
    version, my_as, hold = struct.unpack("!BHH", body[:5])
    bgp_id = socket.inet_ntoa(body[5:9])
    opt_len = body[9]
    opts = body[10:10 + opt_len]
    four = False
    real_as = my_as
    i = 0
    while i + 2 <= len(opts):
        ptype, plen = opts[i], opts[i + 1]
        val = opts[i + 2:i + 2 + plen]
        i += 2 + plen
        if ptype != 2:
            continue
        j = 0
        while j + 2 <= len(val):
            cap_code, cap_len = val[j], val[j + 1]
            cap_val = val[j + 2:j + 2 + cap_len]
            j += 2 + cap_len
            if cap_code == CAP_4OCTET_AS and len(cap_val) == 4:
                four = True
                real_as = int.from_bytes(cap_val, "big")
    return BgpOpen(version, real_as, hold, bgp_id, four)


def parse_notification(body: bytes) -> BgpNotification:
    return BgpNotification(body[0], body[1], body[2:])


def _read_attr_len(data: bytes, i: int, extended: bool) -> tuple[int, int]:
    if extended:
        return struct.unpack("!H", data[i:i + 2])[0], i + 2
    return data[i], i + 1


def decode_mp_nexthop(nh_bytes: bytes, afi: int) -> Optional[str]:
    """Decode an MP_REACH_NLRI next-hop (RFC 4760 section 3).

    IPv6 next hops may carry a global + link-local pair (RFC 2545, 32 bytes
    total) when advertised over a link-local eBGP session. We report the
    global address (the first 16 bytes) -- that's what identifies the path
    for churn detection; the link-local half only matters for local
    forwarding, not RIB monitoring.
    """
    if afi == 2 and len(nh_bytes) >= 16:
        return socket.inet_ntop(socket.AF_INET6, nh_bytes[:16])
    if afi == 1 and len(nh_bytes) >= 4:
        return socket.inet_ntoa(nh_bytes[:4])
    return None


def parse_update(body: bytes) -> BgpUpdate:
    upd = BgpUpdate()
    off = 0
    wlen = struct.unpack("!H", body[off:off + 2])[0]
    off += 2
    upd.withdrawn = decode_prefixes(body[off:off + wlen], 32)
    off += wlen

    palen = struct.unpack("!H", body[off:off + 2])[0]
    off += 2
    attrs = body[off:off + palen]
    off += palen
    upd.nlri = decode_prefixes(body[off:], 32)      # v4 NLRI is the tail

    i = 0
    while i < len(attrs):
        flags = attrs[i]
        atype = attrs[i + 1]
        i += 2
        alen, i = _read_attr_len(attrs, i, bool(flags & 0x10))
        val = attrs[i:i + alen]
        i += alen

        if atype == ATTR_ORIGIN:
            upd.origin = val[0]
        elif atype == ATTR_AS_PATH:
            upd.as_path, upd.has_as_set = decode_as_path(val)
        elif atype == ATTR_NEXT_HOP:
            upd.next_hop = socket.inet_ntoa(val[:4])
        elif atype == ATTR_MED:
            upd.med = int.from_bytes(val, "big")
        elif atype == ATTR_LOCAL_PREF:
            upd.local_pref = int.from_bytes(val, "big")
        elif atype == ATTR_COMMUNITIES:
            for k in range(0, len(val) - 3, 4):
                hi = int.from_bytes(val[k:k + 2], "big")
                lo = int.from_bytes(val[k + 2:k + 4], "big")
                upd.communities.append((hi, lo))
        elif atype == ATTR_MP_REACH:
            afi = struct.unpack("!H", val[:2])[0]
            nh_len = val[3]
            nh_bytes = val[4:4 + nh_len]
            nlri_start = 4 + nh_len + 1        # after nexthop + reserved byte
            bits = 128 if afi == 2 else 32
            nh = decode_mp_nexthop(nh_bytes, afi)
            if nh is not None:
                upd.next_hop = nh
            upd.nlri += decode_prefixes(val[nlri_start:], bits)
        elif atype == ATTR_MP_UNREACH:
            afi = struct.unpack("!H", val[:2])[0]
            bits = 128 if afi == 2 else 32
            upd.withdrawn += decode_prefixes(val[3:], bits)
    return upd


# --------------------------------------------------------------------------- #
# framer (pure): pull complete BGP messages out of a byte buffer
# --------------------------------------------------------------------------- #
def frame_messages(buffer: bytes) -> tuple[list[tuple[int, bytes]], bytes]:
    """Return (list of (msg_type, body), leftover_bytes)."""
    msgs = []
    i = 0
    while len(buffer) - i >= HDR_LEN:
        length, mtype = struct.unpack("!HB", buffer[i + 16:i + 19])
        if length < HDR_LEN or length > MAX_MSG:
            raise ValueError(f"bad BGP length {length}")
        if len(buffer) - i < length:
            break
        body = buffer[i + HDR_LEN:i + length]
        msgs.append((mtype, body))
        i += length
    return msgs, buffer[i:]


# --------------------------------------------------------------------------- #
# RIB with churn tracking + LPM
# --------------------------------------------------------------------------- #
@dataclass
class RibEntry:
    as_path: list[int]
    next_hop: Optional[str]
    origin_as: Optional[int]
    ts: float


@dataclass
class RibEvent:
    prefix: str
    kind: str                       # 'announce' | 'withdraw' | 'path_change'
    old_as_path: Optional[list] = None
    new_as_path: Optional[list] = None
    ts: float = 0.0


class Rib:
    """Single-peer Adj-RIB-In with per-prefix churn counting.

    apply_update() mutates the RIB and returns the list of RibEvents produced.
    A per-prefix rolling window of change timestamps drives flap detection.
    Two LPM tries (v4/v6) map any IP to its covering prefix's origin AS.
    """

    def __init__(self, flap_window_s: float = 120.0, flap_min: int = 4):
        self.entries: dict[str, RibEntry] = {}
        self.flap_window = flap_window_s
        self.flap_min = flap_min
        self._churn: dict[str, deque] = {}
        self.trie4 = IpTrie(32)
        self.trie6 = IpTrie(128)
        self._pending: deque = deque()
        self._lock = threading.Lock()
        self.stats = {"announce": 0, "withdraw": 0, "path_change": 0}

    def _bump_churn(self, prefix: str, ts: float):
        dq = self._churn.setdefault(prefix, deque())
        dq.append(ts)
        cutoff = ts - self.flap_window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _trie_for(self, prefix: str):
        net, plen, bits = prefix_to_int(prefix)
        return (self.trie4 if bits == 32 else self.trie6), net, plen

    def apply_update(self, upd: BgpUpdate, ts: Optional[float] = None) -> list[RibEvent]:
        ts = ts or time.time()
        events: list[RibEvent] = []

        for p in upd.withdrawn:
            if p in self.entries:
                old = self.entries.pop(p)
                trie, net, plen = self._trie_for(p)
                trie.delete(net, plen)
                self._bump_churn(p, ts)
                self.stats["withdraw"] += 1
                events.append(RibEvent(p, "withdraw", old.as_path, None, ts))

        for p in upd.nlri:
            entry = RibEntry(list(upd.as_path), upd.next_hop, upd.origin_as, ts)
            trie, net, plen = self._trie_for(p)
            trie.insert(net, plen, upd.origin_as)
            prev = self.entries.get(p)
            self.entries[p] = entry
            if prev is None:
                self.stats["announce"] += 1
                events.append(RibEvent(p, "announce", None, entry.as_path, ts))
            elif prev.as_path != entry.as_path or prev.next_hop != entry.next_hop:
                self._bump_churn(p, ts)
                self.stats["path_change"] += 1
                events.append(RibEvent(p, "path_change", prev.as_path,
                                       entry.as_path, ts))

        if events:
            with self._lock:
                self._pending.extend(events)
        return events

    def drain(self) -> list[RibEvent]:
        with self._lock:
            out = list(self._pending)
            self._pending.clear()
        return out

    def flapping(self, prefix: str, now: Optional[float] = None) -> bool:
        dq = self._churn.get(prefix)
        if not dq:
            return False
        now = now or time.time()
        cutoff = now - self.flap_window
        recent = sum(1 for t in dq if t >= cutoff)
        return recent >= self.flap_min

    def origin_as_for_ip(self, ip: str) -> Optional[int]:
        val, bits = ip_to_int(ip)
        trie = self.trie4 if bits == 32 else self.trie6
        asn, _ = trie.longest_match(val)
        return asn

    def covering_prefix(self, ip: str) -> Optional[str]:
        """Best-effort: find the covering prefix string for an IP by scanning
        entries with matching LPM depth. (Used for human-readable attribution.)"""
        val, bits = ip_to_int(ip)
        best = None
        best_len = -1
        import ipaddress
        for p in self.entries:
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue
            if (32 if net.version == 4 else 128) != bits:
                continue
            if ipaddress.ip_address(ip) in net and net.prefixlen > best_len:
                best, best_len = p, net.prefixlen
        return best


# --------------------------------------------------------------------------- #
# correlator: bridge RIB truth into the data-plane detector
# --------------------------------------------------------------------------- #
@dataclass
class Corroboration:
    confirmed: bool
    prefix: Optional[str]
    events: list                 # list[RibEvent] within window
    flapping: bool
    cause: str = ""


class BgpCorrelator:
    def __init__(self, rib: Rib, window_s: float = 30.0):
        self.rib = rib
        self.window = window_s
        # keep a short history of recent events for on-demand explain()
        self._recent: deque = deque(maxlen=2000)

    def ingest(self, events: list[RibEvent]) -> None:
        self._recent.extend(events)

    def _covering_from_events(self, target_ip: str, cutoff: float) -> Optional[str]:
        """Most-specific prefix among recent events that covers target_ip.
        Lets us correlate even a transient full withdrawal (prefix absent from
        the live RIB)."""
        import ipaddress
        try:
            ta = ipaddress.ip_address(target_ip)
        except ValueError:
            return None
        best, best_len = None, -1
        for e in self._recent:
            if e.ts < cutoff:
                continue
            try:
                net = ipaddress.ip_network(e.prefix, strict=False)
            except ValueError:
                continue
            if ta in net and net.prefixlen > best_len:
                best, best_len = e.prefix, net.prefixlen
        return best

    def explain(self, target_ip: str, now: Optional[float] = None) -> Corroboration:
        """Did the prefix covering target_ip see a RIB event within the window?"""
        now = now or time.time()
        cutoff = now - self.window
        prefix = self.rib.covering_prefix(target_ip) \
            or self._covering_from_events(target_ip, cutoff)
        hits = [e for e in self._recent
                if e.prefix == prefix and e.ts >= cutoff] if prefix else []
        flap = self.rib.flapping(prefix, now) if prefix else False
        confirmed = bool(hits) or flap
        cause = ""
        if hits:
            last = hits[-1]
            if last.kind == "path_change":
                cause = (f"prefix {prefix} AS-path {last.old_as_path} -> "
                         f"{last.new_as_path}")
            else:
                cause = f"prefix {prefix} {last.kind}"
            if flap:
                cause += " (flapping)"
        elif flap:
            cause = f"prefix {prefix} flapping"
        return Corroboration(confirmed, prefix, hits, flap, cause)


# --------------------------------------------------------------------------- #
# per-peer registry and multi-RIB correlator
# --------------------------------------------------------------------------- #
@dataclass
class PeerConfig:
    """Static config for one BGP peer (one carrier-facing router session)."""
    ip: str
    remote_as: int
    name: str = ""          # human label: "Carrier-A", "HE.net", "NTT", etc.
    afi: tuple = (1,)       # (1,) = IPv4 unicast; (1, 2) = IPv4+IPv6
    passive: bool = False   # True = listen on tcp/port instead of dialing out
    port: int = 179

    def __post_init__(self):
        if not self.name:
            self.name = f"AS{self.remote_as}@{self.ip}"
        self.afi = tuple(self.afi)


@dataclass
class PeerCorroboration:
    """Per-peer slice of a MultiRibCorrelator.explain_all() call."""
    peer_ip: str
    peer_name: str
    confirmed: bool
    prefix: Optional[str]
    events: list               # list[RibEvent] within window
    flapping: bool
    cause: str = ""


class MultiRibCorrelator:
    """One Rib + BgpCorrelator pair per BGP peer, all queryable together.

    The operational value: when a data-plane symptom fires for target T,
    explain_all(T) returns a per-peer breakdown — which carriers' RIB views
    changed and which are stable. That tells the NOC where to open the incident
    call before picking up the phone.

      Only Carrier-A moved, B and C stable ->  churn is in A's AS or A's peer;
                                               not a DFZ-wide event.
      All carriers moved simultaneously    ->  event is upstream of all of them;
                                               look at the origin AS or major transit.
    """

    def __init__(self, window_s: float = 30.0):
        self.window = window_s
        # insertion-order: peer_ip -> (Rib, BgpCorrelator, peer_name)
        self._peers: dict[str, tuple] = {}

    @property
    def peer_count(self) -> int:
        return len(self._peers)

    def add_peer(self, peer_ip: str, peer_name: str,
                 rib: Rib, correlator: BgpCorrelator) -> None:
        self._peers[peer_ip] = (rib, correlator, peer_name)

    def explain_all(self, target_ip: str,
                    now: Optional[float] = None) -> list[PeerCorroboration]:
        """Return one PeerCorroboration per registered peer, confirmed first."""
        results: list[PeerCorroboration] = []
        for peer_ip, (rib, corr, name) in self._peers.items():
            c = corr.explain(target_ip, now)
            results.append(PeerCorroboration(
                peer_ip, name, c.confirmed, c.prefix,
                c.events, c.flapping, c.cause))
        results.sort(key=lambda r: (not r.confirmed, r.peer_name))
        return results

    def drain_all(self) -> dict[str, tuple]:
        """Drain all peer RIBs and ingest into their correlators.

        Returns {peer_ip: (peer_name, [RibEvent])} for peers that had events.
        Ingestion happens here so explain_all() is immediately up-to-date after
        a drain_all() call."""
        out: dict[str, tuple] = {}
        for peer_ip, (rib, corr, name) in self._peers.items():
            evs = rib.drain()
            if evs:
                corr.ingest(evs)
                out[peer_ip] = (name, evs)
        return out

    def cause_summary(self,
                      results: list[PeerCorroboration]) -> tuple[bool, str]:
        """(any_confirmed, human-readable multi-peer cause string).

        e.g. "Carrier-A: prefix 9.9.9.0/24 AS-path [...] -> [...]; stable via: B, C"
        """
        confirmed = [r for r in results if r.confirmed]
        stable    = [r for r in results if not r.confirmed]
        if not confirmed:
            return False, ""
        parts = [f"{r.peer_name}: {r.cause}" for r in confirmed]
        if stable:
            parts.append("stable via: " + ", ".join(r.peer_name for r in stable))
        return True, "; ".join(parts)

    def peer_names(self) -> list[str]:
        return [tup[2] for tup in self._peers.values()]


# --------------------------------------------------------------------------- #
# transport helpers: a BGP *session* can run over an IPv4 or IPv6 TCP socket
# independently of which AFI/SAFI it carries in MP-BGP -- e.g. peering over an
# IPv6 loopback while exchanging IPv4 and/or IPv6 NLRI. Router-ID (bgp_id)
# stays a dotted-quad 32-bit value regardless of transport family, per RFC
# 4271 -- that field is unaffected by any of this.
# --------------------------------------------------------------------------- #
def _is_ipv6(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).version == 6
    except ValueError:
        return False


def _addrs_equal(a: str, b: str) -> bool:
    """Compare two address strings for equality, normalizing through
    ipaddress so e.g. a zone-id suffix or a differently-abbreviated IPv6
    literal still matches. Falls back to a raw string compare if either side
    doesn't parse (shouldn't happen for real socket peer addresses)."""
    try:
        return ipaddress.ip_address(a.split("%")[0]) == ipaddress.ip_address(b.split("%")[0])
    except ValueError:
        return a == b


# --------------------------------------------------------------------------- #
# speaker (the only part with a socket)
# --------------------------------------------------------------------------- #
class BgpSpeaker(threading.Thread):
    """Receive-only BGP speaker. Connects (active) to peer_ip:179, negotiates,
    then feeds UPDATEs into `rib`. Runs as a daemon thread."""

    def __init__(self, peer_ip: str, peer_as: int, local_as: int,
                 local_id: str, rib: Rib, correlator: Optional[BgpCorrelator] = None,
                 hold: int = 90, afi_list=(1,), passive: bool = False,
                 port: int = 179, peer_name: str = "", log=print):
        super().__init__(daemon=True)
        self.peer_ip = peer_ip
        self.peer_as = peer_as
        self.peer_name = peer_name or f"AS{peer_as}@{peer_ip}"
        self.local_as = local_as
        self.local_id = local_id
        self.rib = rib
        self.correlator = correlator
        self.hold = hold
        self.afi_list = afi_list
        self.passive = passive
        self.port = port
        self.log = log
        self.state = "Idle"
        self._stop = False
        self._sock: Optional[socket.socket] = None

    def stop(self):
        self._stop = True
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    def _connect(self) -> Optional[socket.socket]:
        family = socket.AF_INET6 if _is_ipv6(self.peer_ip) else socket.AF_INET
        if self.passive:
            srv = socket.socket(family, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_addr = "::" if family == socket.AF_INET6 else "0.0.0.0"
            srv.bind((bind_addr, self.port))
            srv.listen(1)
            srv.settimeout(30)
            self.log(f"bgp: listening for {self.peer_ip}")
            conn, addr = srv.accept()
            srv.close()
            if not _addrs_equal(addr[0], self.peer_ip):
                conn.close()
                return None
            return conn
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((self.peer_ip, self.port))
        return s

    def run(self):
        while not self._stop:
            try:
                self._session()
            except Exception as e:
                self.log(f"bgp: session error: {e}")
            self.state = "Idle"
            for _ in range(50):            # ~5s backoff, interruptible
                if self._stop:
                    return
                time.sleep(0.1)

    def _session(self):
        self.state = "Connect"
        self._sock = self._connect()
        if self._sock is None:
            return
        s = self._sock
        s.settimeout(1.0)

        s.sendall(build_open(self.local_as, self.hold, self.local_id,
                             self.afi_list))
        self.state = "OpenSent"

        buf = b""
        established = False
        negotiated_hold = self.hold
        last_ka = time.time()
        last_rx = time.time()

        while not self._stop:
            try:
                data = s.recv(4096)
                if not data:
                    self.log("bgp: peer closed")
                    return
                buf += data
                last_rx = time.time()
            except socket.timeout:
                pass

            try:
                msgs, buf = frame_messages(buf)
            except ValueError as e:
                self.log(f"bgp: framing error: {e}")
                return

            for mtype, body in msgs:
                if mtype == OPEN:
                    o = parse_open(body)
                    negotiated_hold = min(self.hold, o.hold) if o.hold else self.hold
                    self.log(f"bgp: OPEN from AS{o.my_as} id={o.bgp_id} "
                             f"4octet={o.four_octet} hold={negotiated_hold}")
                    s.sendall(build_keepalive())
                    self.state = "OpenConfirm"
                elif mtype == KEEPALIVE:
                    if not established:
                        established = True
                        self.state = "Established"
                        self.log(f"bgp: Established with {self.peer_ip}")
                elif mtype == UPDATE:
                    try:
                        upd = parse_update(body)
                    except Exception as e:
                        self.log(f"bgp: bad UPDATE: {e}")
                        continue
                    events = self.rib.apply_update(upd)
                    if events and self.correlator:
                        self.correlator.ingest(events)
                elif mtype == NOTIFICATION:
                    n = parse_notification(body)
                    self.log(f"bgp: NOTIFICATION code={n.code} sub={n.subcode}")
                    return

            now = time.time()
            ka_interval = max(1, negotiated_hold // 3) if negotiated_hold else 30
            if established and now - last_ka >= ka_interval:
                try:
                    s.sendall(build_keepalive())
                    last_ka = now
                except OSError:
                    return
            if negotiated_hold and now - last_rx > negotiated_hold:
                self.log("bgp: hold timer expired")
                return
