"""
bgptap.py -- passive BGP tap: read TCP/179 off a SPAN/mirror port.

WHY THIS EXISTS (and why the peering collector in bgp.py can't do this job)
--------------------------------------------------------------------------
bgp.py's BgpSpeaker is a *peer*: it only ever sees UPDATEs addressed to its own
sessions. Every parser CVE in bgpcve.py is an attack on some *other* router's
bgpd. Those bytes cross the fabric on sessions pathwatch is not a party to, so
the collector is structurally blind to them.

This module is the missing half: no session, no state on the wire, no packets
emitted. It reassembles BGP message boundaries out of mirrored TCP and hands
raw message bytes to the detectors. It reuses bgp.py's codec wholesale -- the
framer and the attribute walk were the hard part and they already exist.

DUAL-STACK (prime directive)
----------------------------
A BGP session runs over IPv4 *or* IPv6 TCP transport, independently of the
AFI/SAFI it carries. Both must be captured at full parity. Two traps here,
both of which have bitten this suite before:

  1. BPF cannot traverse an IPv6 extension-header chain. A filter of
     `ip6 and tcp port 179` silently drops every IPv6 BGP packet that carries
     a Hop-by-Hop, Routing, Fragment, AH or Destination-Options header --
     a measured no-op, not a theoretical one. So the capture filter
     deliberately over-captures IPv6 (any packet whose ip6 next-header is not
     TCP is let through) and the extension-header chain is walked *in
     userspace* by walk_ipv6_chain(), which then discards non-BGP.

  2. An IPv6 header has no length field for options the way IPv4 has IHL --
     the chain must be walked header by header. A fixed 40-byte offset is
     wrong the moment an EH appears.

Layering, for testability (same discipline as probe.py):
  * parse_l3 / walk_ipv6_chain / TcpResync  -- pure bytes -> objects
  * BgpTap.feed_packet()                    -- pure, takes raw frame bytes
  * BgpTap.run_live()                       -- the ONLY part that touches a NIC
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

import bgp

BGP_PORT = 179

# IPv6 extension headers that use the standard (next_header, hdr_ext_len) shape
# where length is in 8-octet units not counting the first 8 octets.
IPV6_EH_STANDARD = {
    0,    # Hop-by-Hop Options
    43,   # Routing
    60,   # Destination Options
    135,  # Mobility
    139,  # HIP
    140,  # Shim6
}
IPV6_EH_FRAGMENT = 44        # fixed 8 bytes
IPV6_EH_AH = 51              # length in 4-octet units, +2 (RFC 4302)
IPV6_NO_NEXT_HEADER = 59
PROTO_TCP = 6

# Capture filter. Deliberately over-captures IPv6 (see trap 1 above): anything
# whose ip6 next-header is not TCP is admitted so userspace can walk the chain.
# Non-BGP traffic is discarded immediately after the walk.
BPF_DUAL_STACK = (
    "(tcp port 179) or "
    "(ip6 and ip6[6] != 6)"
)
# Strict variant, IPv4-only semantics -- kept for environments where the tap
# is known to be v4-only and the extra IPv6 volume is unwanted. NOT the default:
# using it on a dual-stack fabric reintroduces the blind spot above.
BPF_STRICT = "tcp port 179"


# --------------------------------------------------------------------------- #
# Layer 3
# --------------------------------------------------------------------------- #
@dataclass
class L3Result:
    ok: bool
    src: Optional[str] = None
    dst: Optional[str] = None
    proto: Optional[int] = None
    payload: bytes = b""
    family: Optional[int] = None      # 4 or 6
    truncated: bool = False
    fragmented: bool = False
    eh_chain: tuple = ()              # extension headers seen, in order
    reason: str = ""


def walk_ipv6_chain(data: bytes, first_next: int,
                    offset: int) -> tuple[Optional[int], int, tuple, bool]:
    """Walk an IPv6 extension-header chain.

    Returns (final_protocol, payload_offset, headers_seen, fragmented).
    final_protocol is None if the chain is malformed/truncated or terminates
    in No-Next-Header. Bounded by the buffer -- never loops indefinitely, and
    caps chain depth so a crafted cyclic-looking chain can't spin us.
    """
    nxt = first_next
    off = offset
    seen: list[int] = []
    fragmented = False

    for _ in range(16):                       # depth cap; real chains are tiny
        if nxt == PROTO_TCP:
            return nxt, off, tuple(seen), fragmented
        if nxt == IPV6_NO_NEXT_HEADER:
            return None, off, tuple(seen), fragmented

        if nxt in IPV6_EH_STANDARD:
            if off + 2 > len(data):
                return None, off, tuple(seen), fragmented
            seen.append(nxt)
            ext_len = data[off + 1]
            nxt = data[off]
            off += (ext_len + 1) * 8
        elif nxt == IPV6_EH_FRAGMENT:
            if off + 8 > len(data):
                return None, off, tuple(seen), fragmented
            seen.append(nxt)
            frag_off_field = struct.unpack("!H", data[off + 2:off + 4])[0]
            # non-zero fragment offset => not the first fragment; no L4 header
            if (frag_off_field >> 3) != 0:
                fragmented = True
                return None, off, tuple(seen), fragmented
            fragmented = True
            nxt = data[off]
            off += 8
        elif nxt == IPV6_EH_AH:
            if off + 2 > len(data):
                return None, off, tuple(seen), fragmented
            seen.append(nxt)
            ah_len = data[off + 1]
            nxt = data[off]
            off += (ah_len + 2) * 4
        else:
            # not an extension header -- it's the upper-layer protocol
            return nxt, off, tuple(seen), fragmented

        if off > len(data):
            return None, off, tuple(seen), fragmented

    return None, off, tuple(seen), fragmented


def parse_l3(frame: bytes, link_offset: int = 14) -> L3Result:
    """Parse an Ethernet frame's L3 header (IPv4 or IPv6) and return the L4
    payload. link_offset defaults to 14 (Ethernet II); pass 0 for raw IP.

    Handles: IPv4 options via IHL, IPv4 fragmentation, IPv6 extension-header
    chains, VLAN tags (802.1Q / QinQ).
    """
    if len(frame) < link_offset + 1:
        return L3Result(False, truncated=True, reason="short frame")

    off = link_offset
    if link_offset >= 14:
        ethertype = struct.unpack("!H", frame[12:14])[0]
        # strip up to two VLAN tags
        for _ in range(2):
            if ethertype in (0x8100, 0x88A8, 0x9100):
                if off + 4 > len(frame):
                    return L3Result(False, truncated=True, reason="short vlan")
                ethertype = struct.unpack("!H", frame[off + 2:off + 4])[0]
                off += 4
            else:
                break
    else:
        # raw IP: infer from version nibble
        ethertype = 0x0800 if (frame[0] >> 4) == 4 else 0x86DD

    if ethertype == 0x0800:
        return _parse_ipv4(frame, off)
    if ethertype == 0x86DD:
        return _parse_ipv6(frame, off)
    return L3Result(False, reason=f"ethertype 0x{ethertype:04x} not IP")


def _parse_ipv4(data: bytes, off: int) -> L3Result:
    if off + 20 > len(data):
        return L3Result(False, truncated=True, reason="short ipv4 header")
    vihl = data[off]
    ihl = (vihl & 0x0F) * 4
    if ihl < 20:
        return L3Result(False, reason="bad ipv4 IHL")
    total_len = struct.unpack("!H", data[off + 2:off + 4])[0]
    frag_field = struct.unpack("!H", data[off + 6:off + 8])[0]
    proto = data[off + 9]
    src = socket.inet_ntoa(data[off + 12:off + 16])
    dst = socket.inet_ntoa(data[off + 16:off + 20])

    frag_offset = frag_field & 0x1FFF
    more_frags = bool(frag_field & 0x2000)
    fragmented = bool(frag_offset or more_frags)
    if frag_offset:
        # not the first fragment: no L4 header present
        return L3Result(False, src, dst, proto, b"", 4,
                        fragmented=True, reason="non-initial ipv4 fragment")

    if off + ihl > len(data):
        return L3Result(False, src, dst, proto, b"", 4,
                        truncated=True, reason="ipv4 options truncated")

    end = off + total_len if total_len else len(data)
    end = min(end, len(data))
    payload = data[off + ihl:end]
    return L3Result(True, src, dst, proto, payload, 4, fragmented=fragmented)


def _parse_ipv6(data: bytes, off: int) -> L3Result:
    if off + 40 > len(data):
        return L3Result(False, truncated=True, reason="short ipv6 header")
    payload_len = struct.unpack("!H", data[off + 4:off + 6])[0]
    next_header = data[off + 6]
    src = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
    dst = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])

    end = off + 40 + payload_len if payload_len else len(data)
    end = min(end, len(data))

    proto, l4_off, chain, fragmented = walk_ipv6_chain(data, next_header, off + 40)
    if proto is None:
        return L3Result(False, src, dst, None, b"", 6, eh_chain=chain,
                        fragmented=fragmented,
                        reason="ipv6 chain malformed/truncated or non-initial fragment")
    if l4_off > len(data):
        return L3Result(False, src, dst, proto, b"", 6, eh_chain=chain,
                        truncated=True, reason="ipv6 chain past buffer")
    return L3Result(True, src, dst, proto, data[l4_off:end], 6,
                    eh_chain=chain, fragmented=fragmented)


# --------------------------------------------------------------------------- #
# Layer 4
# --------------------------------------------------------------------------- #
@dataclass
class TcpResult:
    ok: bool
    sport: int = 0
    dport: int = 0
    seq: int = 0
    payload: bytes = b""
    rst: bool = False
    fin: bool = False
    syn: bool = False


def parse_tcp(data: bytes) -> TcpResult:
    if len(data) < 20:
        return TcpResult(False)
    sport, dport, seq = struct.unpack("!HHI", data[:8])
    data_off = (data[12] >> 4) * 4
    if data_off < 20 or data_off > len(data):
        return TcpResult(False, sport, dport, seq)
    flags = data[13]
    return TcpResult(True, sport, dport, seq, data[data_off:],
                     rst=bool(flags & 0x04), fin=bool(flags & 0x01),
                     syn=bool(flags & 0x02))


# --------------------------------------------------------------------------- #
# Stream reassembly with marker resync
# --------------------------------------------------------------------------- #
class TcpResync:
    """Per-direction byte accumulator that recovers BGP message alignment.

    A mirror port drops packets. Full TCP state tracking on a Pi across dozens
    of carrier sessions is neither cheap nor necessary here, because BGP hands
    us a free resynchronisation primitive: every message begins with 16 octets
    of 0xFF. On a sequence gap we discard the buffer and scan forward to the
    next marker rather than emitting garbage messages.

    This deliberately trades completeness for correctness: a message straddling
    a lost segment is dropped, never half-parsed into a false finding.
    """

    MAX_BUFFER = 1 << 20       # 1 MiB per direction; guards against a wedged flow

    def __init__(self):
        self.buf = b""
        self.next_seq: Optional[int] = None
        self.synced = False
        self.resyncs = 0
        self.dropped_bytes = 0

    def reset(self):
        self.buf = b""
        self.next_seq = None
        self.synced = False

    def _find_marker(self, data: bytes) -> int:
        return data.find(bgp.MARKER)

    def feed(self, seq: int, payload: bytes) -> list:
        """Add a segment; return complete (msg_type, body, raw) tuples."""
        if not payload:
            return []

        if self.next_seq is not None and seq != self.next_seq:
            if seq < self.next_seq:
                # retransmission / overlap: trim the already-seen prefix
                skip = self.next_seq - seq
                if skip >= len(payload):
                    return []
                payload = payload[skip:]
                seq = self.next_seq
            else:
                # forward gap -- we lost data. Drop and resync on the marker.
                self.dropped_bytes += seq - self.next_seq
                self.resyncs += 1
                self.buf = b""
                self.synced = False

        self.buf += payload
        self.next_seq = seq + len(payload)

        if len(self.buf) > self.MAX_BUFFER:
            self.buf = b""
            self.synced = False
            self.resyncs += 1
            return []

        if not self.synced:
            idx = self._find_marker(self.buf)
            if idx < 0:
                # keep only a marker-length tail; a marker may straddle segments
                if len(self.buf) > len(bgp.MARKER):
                    self.buf = self.buf[-len(bgp.MARKER):]
                return []
            self.buf = self.buf[idx:]
            self.synced = True

        return self._drain()

    def _drain(self) -> list:
        out = []
        while len(self.buf) >= bgp.HDR_LEN:
            if not self.buf.startswith(bgp.MARKER):
                idx = self._find_marker(self.buf)
                if idx < 0:
                    self.synced = False
                    self.buf = self.buf[-len(bgp.MARKER):]
                    self.resyncs += 1
                    return out
                self.buf = self.buf[idx:]
                self.resyncs += 1
                continue
            length, mtype = struct.unpack("!HB", self.buf[16:19])
            if length < bgp.HDR_LEN or length > bgp.MAX_MSG:
                # bogus length: skip this marker and hunt for the next
                idx = self._find_marker(self.buf[1:])
                if idx < 0:
                    self.synced = False
                    self.buf = b""
                    self.resyncs += 1
                    return out
                self.buf = self.buf[1 + idx:]
                self.resyncs += 1
                continue
            if len(self.buf) < length:
                return out
            raw = self.buf[:length]
            out.append((mtype, raw[bgp.HDR_LEN:], raw))
            self.buf = self.buf[length:]
        return out


# --------------------------------------------------------------------------- #
# The tap
# --------------------------------------------------------------------------- #
@dataclass
class TapStats:
    frames: int = 0
    l3_fail: int = 0
    non_bgp: int = 0
    messages: int = 0
    v4_frames: int = 0
    v6_frames: int = 0
    v6_with_eh: int = 0
    fragments: int = 0
    resyncs: int = 0


@dataclass
class TapMessage:
    """One framed BGP message observed on the wire, with its flow context."""
    msg_type: int
    body: bytes
    raw: bytes
    src: str
    dst: str
    sport: int
    dport: int
    family: int                 # 4 or 6 -- transport family, not NLRI AFI
    eh_chain: tuple = ()

    @property
    def flow(self) -> tuple:
        return (self.src, self.sport, self.dst, self.dport)


class BgpTap:
    """Feed it frames; it yields framed BGP messages.

    on_message(TapMessage) is called for each. Detector wiring lives in
    bgpcve.py -- this class knows nothing about CVEs.
    """

    def __init__(self, on_message: Optional[Callable] = None,
                 link_offset: int = 14, port: int = BGP_PORT,
                 on_teardown: Optional[Callable] = None):
        self.on_message = on_message
        # on_teardown(flow, src, dst, family) fires when a session closes
        # (RST/FIN). Some findings are only meaningful as "the trigger landed
        # and then the session died" -- see bgpcve.BgpCveTracker.
        self.on_teardown = on_teardown
        self.link_offset = link_offset
        self.port = port
        self.streams: dict[tuple, TcpResync] = {}
        self.stats = TapStats()

    def feed_packet(self, frame: bytes) -> list:
        """Pure: parse one frame, return the TapMessages it completed."""
        self.stats.frames += 1
        l3 = parse_l3(frame, self.link_offset)

        if l3.family == 4:
            self.stats.v4_frames += 1
        elif l3.family == 6:
            self.stats.v6_frames += 1
            if l3.eh_chain:
                self.stats.v6_with_eh += 1
        if l3.fragmented:
            self.stats.fragments += 1

        if not l3.ok:
            self.stats.l3_fail += 1
            return []
        if l3.proto != PROTO_TCP:
            self.stats.non_bgp += 1
            return []

        tcp = parse_tcp(l3.payload)
        if not tcp.ok:
            self.stats.non_bgp += 1
            return []
        if self.port not in (tcp.sport, tcp.dport):
            self.stats.non_bgp += 1
            return []

        key = (l3.src, tcp.sport, l3.dst, tcp.dport)
        if tcp.rst or tcp.syn:
            # session restart: drop stale buffer rather than splice across it
            had = self.streams.pop(key, None)
            if tcp.rst and self.on_teardown is not None:
                self._teardown(key, l3, had)
            if not tcp.payload:
                return []

        stream = self.streams.get(key)
        if stream is None:
            stream = TcpResync()
            self.streams[key] = stream

        before = stream.resyncs
        framed = stream.feed(tcp.seq, tcp.payload)
        self.stats.resyncs += stream.resyncs - before

        out = []
        for mtype, body, raw in framed:
            msg = TapMessage(mtype, body, raw, l3.src, l3.dst,
                             tcp.sport, tcp.dport, l3.family or 0,
                             l3.eh_chain)
            self.stats.messages += 1
            out.append(msg)
            if self.on_message:
                self.on_message(msg)

        if tcp.fin:
            had = self.streams.pop(key, None)
            if self.on_teardown is not None:
                self._teardown(key, l3, had)
        return out

    def _teardown(self, key, l3, had) -> None:
        """Notify the detector layer that a session closed. Contained: a
        failing callback must never take the tap down."""
        try:
            self.on_teardown(key, l3.src, l3.dst, l3.family or 0)
        except Exception:
            pass

    # -- live capture: the only part that touches a NIC --------------------- #
    def run_live(self, iface: str, bpf: str = BPF_DUAL_STACK,
                 count: int = 0, stop_filter=None):
        """Sniff with scapy. Receive-only; emits nothing.

        Requires CAP_NET_RAW. Raises RuntimeError with an actionable message
        rather than a bare scapy traceback if the interface isn't capturable.
        """
        try:
            from scapy.all import sniff  # type: ignore
        except ImportError as e:
            raise RuntimeError(f"scapy required for live capture: {e}")

        def _handle(pkt):
            try:
                self.feed_packet(bytes(pkt))
            except Exception:
                # a malformed frame must never kill the tap -- that is the
                # entire threat model here
                self.stats.l3_fail += 1

        try:
            sniff(iface=iface, filter=bpf, prn=_handle, store=False,
                  count=count, stop_filter=stop_filter)
        except PermissionError as e:
            raise RuntimeError(
                f"raw capture denied on {iface}: grant CAP_NET_RAW ({e})")
