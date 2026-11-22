#!/usr/bin/env python3
"""
taptest.py -- offline tests for the BGP tap tier (bgptap.py + bgpcve.py).

No packets are sent and no NIC is touched: frames are synthesized byte-for-byte
(Ethernet/VLAN, IPv4 with options, IPv6 with extension-header chains, TCP) and
fed to BgpTap.feed_packet(), which is pure. Every detector is exercised on
crafted malformed messages AND on conformant traffic (negative cases), because
a detector that fires on clean BGP is worse than one that misses.

Dual-stack: the parity block runs the same malformed UPDATE over IPv4 transport,
IPv6 transport, and IPv6-with-extension-headers, asserting identical findings.
Run: python3 taptest.py
"""

from __future__ import annotations

import socket
import struct
import sys

import bgp
import bgpcve
import bgptap

_checks = []


def check(name):
    def deco(fn):
        _checks.append((name, fn))
        return fn
    return deco


def _eq(a, b, msg=""):
    assert a == b, f"{msg} expected {b!r} got {a!r}"


def codes(findings):
    return sorted({f.code for f in findings})


# --------------------------------------------------------------------------- #
# frame synthesis
# --------------------------------------------------------------------------- #
def eth(payload: bytes, ethertype: int, vlans=()) -> bytes:
    hdr = b"\x02" * 6 + b"\x03" * 6
    body = b""
    tail_type = ethertype
    for v in reversed(vlans):
        body = struct.pack("!HH", tail_type, v) + body if False else body
    # build tags outward: [tag0][tag1][ethertype]
    if vlans:
        out = hdr
        for i, v in enumerate(vlans):
            out += struct.pack("!HH", 0x8100, v)
        # the last tag's "type" field must be the ethertype; rebuild properly
        out = hdr
        tags = b""
        for i, v in enumerate(vlans):
            nxt = 0x8100 if i + 1 < len(vlans) else ethertype
            tags += struct.pack("!HH", 0x8100 if i == 0 else 0x8100, v)
        # simpler: emit [0x8100][vid] pairs then ethertype
        out = hdr + b"".join(struct.pack("!HH", 0x8100, v) for v in vlans)
        out += struct.pack("!H", ethertype) + payload
        return out
    return hdr + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, src="10.0.0.1", dst="10.0.0.2", proto=6,
         options=b"") -> bytes:
    ihl = 5 + len(options) // 4
    total = ihl * 4 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x40 | ihl, 0, total, 0x1234, 0, 64, proto, 0)
    hdr += socket.inet_aton(src) + socket.inet_aton(dst) + options
    return hdr + payload


def ipv6(payload: bytes, src="2001:db8::1", dst="2001:db8::2",
         next_header=6, ext_headers=()) -> bytes:
    """ext_headers: list of (type_of_this_header, body_bytes) built as a chain."""
    chain = b""
    # build the chain from the back so each header points at the next
    nxt = next_header
    for htype, hbody in reversed(ext_headers):
        if htype == bgptap.IPV6_EH_FRAGMENT:
            # [next][reserved][2B frag offset/flags][4B id] = 8 bytes
            blk = struct.pack("!BBHI", nxt, 0, 0, 0xAABBCCDD)
        elif htype == bgptap.IPV6_EH_AH:
            # RFC 4302: [next][payload len][2B reserved][SPI+seq+ICV...]
            # payload len is the AH length in 4-octet units MINUS 2, counting
            # the whole header. Pad to an 8-octet boundary for IPv6.
            pad = hbody if hbody else b"\x00" * 12
            total = 4 + len(pad)
            if total % 8:
                pad += b"\x00" * (8 - total % 8)
                total = 4 + len(pad)
            ah_len = total // 4 - 2
            blk = struct.pack("!BB", nxt, ah_len) + b"\x00" * 2 + pad
        else:
            pad = hbody if hbody else b"\x00" * 6
            # total must be a multiple of 8: [next][len][pad]
            total = 2 + len(pad)
            if total % 8:
                pad += b"\x00" * (8 - total % 8)
            ext_len = (2 + len(pad)) // 8 - 1
            blk = struct.pack("!BB", nxt, ext_len) + pad
        chain = blk + chain
        nxt = htype
    body = chain + payload
    hdr = struct.pack("!IHBB", 0x60000000, len(body), nxt, 64)
    hdr += socket.inet_pton(socket.AF_INET6, src)
    hdr += socket.inet_pton(socket.AF_INET6, dst)
    return hdr + body


def tcp(payload: bytes, sport=50000, dport=179, seq=1000, flags=0x18) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags,
                      8192, 0, 0)
    return hdr + payload


def bgp_msg(msg_type: int, body: bytes) -> bytes:
    return bgp.MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def frame_v4(bgp_bytes, **kw):
    return eth(ipv4(tcp(bgp_bytes, **kw)), 0x0800)


def frame_v6(bgp_bytes, ext_headers=(), **kw):
    return eth(ipv6(tcp(bgp_bytes, **kw), ext_headers=ext_headers), 0x86DD)


# --------------------------------------------------------------------------- #
# UPDATE body builders
# --------------------------------------------------------------------------- #
def attr(flags, atype, value: bytes) -> bytes:
    if flags & 0x10:
        return struct.pack("!BBH", flags, atype, len(value)) + value
    return struct.pack("!BBB", flags, atype, len(value)) + value


def update_body(withdrawn=b"", attrs=b"", nlri=b"",
                wlen=None, alen=None) -> bytes:
    """wlen/alen override the declared lengths -- that's how underflow is forged."""
    w = struct.pack("!H", len(withdrawn) if wlen is None else wlen)
    a = struct.pack("!H", len(attrs) if alen is None else alen)
    return w + withdrawn + a + attrs + nlri


def clean_attrs(as_path=(64500, 64510), next_hop="10.0.0.1") -> bytes:
    out = attr(0x40, 1, b"\x00")                       # ORIGIN
    apv = bgp.encode_as_path(list(as_path))
    out += attr(0x40, 2, apv)                          # AS_PATH
    out += attr(0x40, 3, socket.inet_aton(next_hop))   # NEXT_HOP
    return out


def clean_update() -> bytes:
    return update_body(attrs=clean_attrs(),
                       nlri=bgp.encode_prefix("203.0.113.0/24"))


# --------------------------------------------------------------------------- #
# L3 / tap plumbing
# --------------------------------------------------------------------------- #
@check("parse_l3: IPv4 basic")
def t_l3_v4():
    f = frame_v4(bgp_msg(bgp.KEEPALIVE, b""))
    r = bgptap.parse_l3(f)
    assert r.ok and r.family == 4 and r.proto == 6
    _eq(r.src, "10.0.0.1")


@check("parse_l3: IPv4 with options (IHL > 5)")
def t_l3_v4_opts():
    opts = b"\x01" * 8
    f = eth(ipv4(tcp(bgp_msg(bgp.KEEPALIVE, b"")), options=opts), 0x0800)
    r = bgptap.parse_l3(f)
    assert r.ok, r.reason
    t = bgptap.parse_tcp(r.payload)
    assert t.ok and t.dport == 179


@check("parse_l3: IPv6 basic, no extension headers")
def t_l3_v6():
    f = frame_v6(bgp_msg(bgp.KEEPALIVE, b""))
    r = bgptap.parse_l3(f)
    assert r.ok and r.family == 6 and r.proto == 6, r.reason
    _eq(r.src, "2001:db8::1")
    _eq(r.eh_chain, ())


@check("parse_l3: IPv6 with Hop-by-Hop + Destination Options chain")
def t_l3_v6_eh():
    f = frame_v6(bgp_msg(bgp.KEEPALIVE, b""),
                 ext_headers=[(0, b""), (60, b"")])
    r = bgptap.parse_l3(f)
    assert r.ok, f"EH chain must be walked, got: {r.reason}"
    _eq(r.family, 6)
    _eq(r.proto, 6)
    _eq(r.eh_chain, (0, 60))
    t = bgptap.parse_tcp(r.payload)
    assert t.ok and t.dport == 179


@check("parse_l3: IPv6 with Routing + AH chain")
def t_l3_v6_ah():
    f = frame_v6(bgp_msg(bgp.KEEPALIVE, b""),
                 ext_headers=[(43, b""), (51, b"\x00" * 8)])
    r = bgptap.parse_l3(f)
    assert r.ok, r.reason
    _eq(r.eh_chain, (43, 51))


@check("parse_l3: IPv6 non-initial fragment yields no L4 (not a false parse)")
def t_l3_v6_frag():
    # craft a fragment header with a non-zero offset
    inner = tcp(bgp_msg(bgp.KEEPALIVE, b""))
    frag = struct.pack("!BBHI", 6, 0, (8 << 3), 0xAABBCCDD)
    body = frag + inner
    hdr = struct.pack("!IHBB", 0x60000000, len(body), 44, 64)
    hdr += socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    hdr += socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    r = bgptap.parse_l3(eth(hdr + body, 0x86DD))
    assert not r.ok and r.fragmented


@check("parse_l3: VLAN-tagged IPv4 and QinQ")
def t_l3_vlan():
    f = eth(ipv4(tcp(bgp_msg(bgp.KEEPALIVE, b""))), 0x0800, vlans=[100])
    r = bgptap.parse_l3(f)
    assert r.ok, r.reason
    f2 = eth(ipv4(tcp(bgp_msg(bgp.KEEPALIVE, b""))), 0x0800, vlans=[100, 200])
    r2 = bgptap.parse_l3(f2)
    assert r2.ok, r2.reason


@check("walk_ipv6_chain: depth cap prevents spin on absurd chain")
def t_v6_chain_cap():
    data = b"\x00\x00" + b"\x00" * 6          # self-referential HBH chain
    proto, off, seen, _ = bgptap.walk_ipv6_chain(data * 40, 0, 0)
    assert proto is None or proto == 0
    assert len(seen) <= 16


@check("tap: frames both families produce identical message stream")
def t_tap_dual():
    msg = bgp_msg(bgp.UPDATE, clean_update())
    for name, f in [("v4", frame_v4(msg)),
                    ("v6", frame_v6(msg)),
                    ("v6+eh", frame_v6(msg, ext_headers=[(0, b"")]))]:
        tap = bgptap.BgpTap()
        got = tap.feed_packet(f)
        _eq(len(got), 1, f"{name}: expected one framed message")
        _eq(got[0].msg_type, bgp.UPDATE, name)


@check("tap: non-BGP TCP port ignored")
def t_tap_other_port():
    tap = bgptap.BgpTap()
    got = tap.feed_packet(eth(ipv4(tcp(b"\xff" * 40, dport=22)), 0x0800))
    _eq(got, [])
    assert tap.stats.non_bgp == 1


@check("tap: message split across two TCP segments is reassembled")
def t_tap_split():
    msg = bgp_msg(bgp.UPDATE, clean_update())
    a, b = msg[:25], msg[25:]
    tap = bgptap.BgpTap()
    _eq(tap.feed_packet(frame_v4(a, seq=1000)), [])
    got = tap.feed_packet(frame_v4(b, seq=1000 + len(a)))
    _eq(len(got), 1)


@check("tap: two messages in one segment both emitted")
def t_tap_coalesced():
    msg = bgp_msg(bgp.KEEPALIVE, b"") + bgp_msg(bgp.UPDATE, clean_update())
    tap = bgptap.BgpTap()
    got = tap.feed_packet(frame_v4(msg))
    _eq(len(got), 2)
    _eq([m.msg_type for m in got], [bgp.KEEPALIVE, bgp.UPDATE])


@check("tap: sequence gap triggers marker resync, no garbage message")
def t_tap_resync():
    tap = bgptap.BgpTap()
    m1 = bgp_msg(bgp.UPDATE, clean_update())
    tap.feed_packet(frame_v4(m1, seq=1000))
    # jump the sequence forward (lost segment) and send a clean message
    m2 = bgp_msg(bgp.KEEPALIVE, b"")
    got = tap.feed_packet(frame_v4(m2, seq=1000 + len(m1) + 5000))
    _eq(len(got), 1, "should resync on the marker and emit the clean message")
    assert tap.stats.resyncs >= 1


@check("tap: bogus length field is skipped without emitting")
def t_tap_bogus_len():
    bad = bgp.MARKER + struct.pack("!HB", 9, 2) + b"\x00" * 10
    good = bgp_msg(bgp.KEEPALIVE, b"")
    tap = bgptap.BgpTap()
    got = tap.feed_packet(frame_v4(bad + good))
    _eq([m.msg_type for m in got], [bgp.KEEPALIVE])


@check("tap: RST clears stream state")
def t_tap_rst():
    tap = bgptap.BgpTap()
    msg = bgp_msg(bgp.UPDATE, clean_update())
    tap.feed_packet(frame_v4(msg[:25], seq=1000))
    tap.feed_packet(eth(ipv4(tcp(b"", seq=1025, flags=0x04)), 0x0800))
    _eq(len(tap.streams), 0)


# --------------------------------------------------------------------------- #
# negative cases -- clean traffic must stay silent
# --------------------------------------------------------------------------- #
@check("clean IPv4 UPDATE produces no findings")
def t_clean_v4():
    _eq(bgpcve.inspect_message(bgp.UPDATE, clean_update()), [])


@check("clean MP_REACH IPv6 UPDATE produces no findings")
def t_clean_v6_nlri():
    nh = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    mp = bgp.encode_mp_reach(2, 1, nh, ["2001:db8:abcd::/48"])
    body = update_body(attrs=clean_attrs() + attr(0x80, 14, mp))
    _eq(bgpcve.inspect_message(bgp.UPDATE, body), [])


@check("clean MP_REACH with RFC 2545 global+link-local next hop is silent")
def t_clean_v6_2545():
    nh = (socket.inet_pton(socket.AF_INET6, "2001:db8::1")
          + socket.inet_pton(socket.AF_INET6, "fe80::1"))
    mp = bgp.encode_mp_reach(2, 1, nh, ["2001:db8:abcd::/48"])
    body = update_body(attrs=clean_attrs() + attr(0x80, 14, mp))
    _eq(bgpcve.inspect_message(bgp.UPDATE, body), [])


@check("conformant IPv4 EOR (4-byte body) is silent")
def t_clean_eor():
    _eq(bgpcve.inspect_message(bgp.UPDATE, update_body()), [])


@check("clean OPEN produces no findings")
def t_clean_open():
    body = bgp.build_open(64512, 90, "10.0.0.1")[bgp.HDR_LEN:]
    _eq(bgpcve.inspect_message(bgp.OPEN, body), [])


@check("clean withdrawal-only UPDATE is silent")
def t_clean_withdraw():
    body = update_body(withdrawn=bgp.encode_prefix("203.0.113.0/24"))
    _eq(bgpcve.inspect_message(bgp.UPDATE, body), [])


@check("clean IPv6 extended communities (multiple of 20) is silent")
def t_clean_extcomm():
    comm = (struct.pack("!H", 0x0002)
            + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
            + struct.pack("!H", 42))
    _eq(len(comm), 20)
    body = update_body(attrs=clean_attrs() + attr(0x80, 25, comm * 2))
    _eq(bgpcve.inspect_message(bgp.UPDATE, body), [])


# --------------------------------------------------------------------------- #
# detectors
# --------------------------------------------------------------------------- #
def tunnel_tlv(ttype, subtlvs: bytes) -> bytes:
    """RFC 9012 s2: Tunnel TLV is [2B Tunnel Type][2B Length][Value]."""
    return struct.pack("!HH", ttype, len(subtlvs)) + subtlvs


def encap_sub(t, v: bytes) -> bytes:
    """RFC 9012 s1.4: sub-TLV length is 1 octet for type<128, 2 for type>=128."""
    if t >= 128:
        return bytes([t]) + struct.pack("!H", len(v)) + v
    return bytes([t, len(v)]) + v


@check("PW-BGP-001: malformed Tunnel Encapsulation sub-TLV (2023-38802/2024-30395)")
def t_d001():
    # sub-TLV declares 200 bytes inside a correctly framed tunnel TLV
    inner = bytes([12, 200]) + b"\x00" * 3
    body = update_body(attrs=clean_attrs() + attr(0x80, 23, tunnel_tlv(15, inner)))
    f = bgpcve.inspect_message(bgp.UPDATE, body)
    assert "PW-BGP-001" in codes(f), codes(f)
    hit = [x for x in f if x.code == "PW-BGP-001"][0]
    assert "CVE-2023-38802" in hit.cves and "CVE-2024-30395" in hit.cves


@check("PW-BGP-001: well-formed tunnel encap is silent")
def t_d001_clean():
    val = tunnel_tlv(15, encap_sub(12, b"\x00" * 6))
    body = update_body(attrs=clean_attrs() + attr(0x80, 23, val))
    assert "PW-BGP-001" not in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-001: Tunnel TLV length field overrunning is caught")
def t_d001_tunnel_len():
    val = struct.pack("!HH", 15, 900) + b"\x00" * 4
    body = update_body(attrs=clean_attrs() + attr(0x80, 23, val))
    f = [x for x in bgpcve.inspect_message(bgp.UPDATE, body)
         if x.code == "PW-BGP-001"]
    assert f and "CVE-2024-44070" in f[0].cves


@check("PW-BGP-001: a large multi-sub-TLV tunnel attribute is NOT flagged")
def t_d001_large_clean():
    # >255 octets of sub-TLVs: only parseable with the 2-octet Tunnel TLV
    # length of RFC 9012. A 1-octet misread desynchronises and manufactures
    # a finding on wholly legitimate traffic.
    subs = b"".join(encap_sub(12, b"\x00" * 6) for _ in range(50))
    val = tunnel_tlv(15, subs)
    assert len(val) > 255
    body = update_body(attrs=clean_attrs() + attr(0x90, 23, val))
    _eq(codes(bgpcve.inspect_message(bgp.UPDATE, body)), [],
        "legitimate large tunnel attribute must stay silent:")


@check("PW-BGP-001: attribute 22 (PMSI_TUNNEL) is out of scope, never flagged")
def t_d001_pmsi_not_flagged():
    # RFC 6514 PMSI_TUNNEL: [1B flags][1B tunnel type][3B label][identifier].
    # Structurally unrelated to Tunnel TLVs; firing here would be a false
    # positive on ordinary MVPN/EVPN traffic.
    pmsi = bytes([0x00, 0x06]) + b"\x00\x01\x01" + b"\x0a\x00\x00\x01"
    body = update_body(attrs=clean_attrs() + attr(0xC0, 22, pmsi))
    _eq(codes(bgpcve.inspect_message(bgp.UPDATE, body)), [],
        "PMSI_TUNNEL must not be parsed as a tunnel-encapsulation attribute:")


@check("PW-BGP-002: NLRI present with zero-length attributes (2023-41358)")
def t_d002():
    body = update_body(attrs=b"", nlri=bgp.encode_prefix("203.0.113.0/24"))
    assert "PW-BGP-002" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-003: MP_UNREACH + trailing NLRI missing mandatory attrs (2023-47234)")
def t_d003():
    mp = bgp.encode_mp_unreach(2, 1, ["2001:db8:abcd::/48"])
    body = update_body(attrs=attr(0x80, 15, mp),
                       nlri=bgp.encode_prefix("203.0.113.0/24"))
    assert "PW-BGP-003" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-003: MP_UNREACH with mandatory attrs present is silent")
def t_d003_clean():
    mp = bgp.encode_mp_unreach(2, 1, ["2001:db8:abcd::/48"])
    body = update_body(attrs=clean_attrs() + attr(0x80, 15, mp),
                       nlri=bgp.encode_prefix("203.0.113.0/24"))
    assert "PW-BGP-003" not in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-004: EOR-shaped UPDATE with malformed attributes (2023-47235)")
def t_d004():
    # EOR shape (no withdrawn, no NLRI) but the attribute overruns
    bad = struct.pack("!BBB", 0x40, 1, 50) + b"\x00" * 2
    body = update_body(attrs=bad)
    assert "PW-BGP-004" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-005: Prefix-SID TLV overrun (2024-31948)")
def t_d005():
    val = struct.pack("!BH", 1, 400) + b"\x00" * 4
    body = update_body(attrs=clean_attrs() + attr(0xC0, 40, val))
    assert "PW-BGP-005" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-005: Prefix-SID with non-conformant flags (RFC 8669)")
def t_d005_flags():
    val = struct.pack("!BH", 1, 4) + b"\x00" * 4
    body = update_body(attrs=clean_attrs() + attr(0x80, 40, val))  # not transitive
    f = [x for x in bgpcve.inspect_message(bgp.UPDATE, body)
         if x.code == "PW-BGP-005"]
    assert f and f[0].confidence == "medium"


@check("PW-BGP-005: conformant Prefix-SID is silent")
def t_d005_clean():
    val = struct.pack("!BH", 1, 4) + b"\x00" * 4
    body = update_body(attrs=clean_attrs() + attr(0xC0, 40, val))
    assert "PW-BGP-005" not in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-006: FlowSpec operator-value boundary (2026-37457)")
def t_d006():
    # component type 1, operator declaring a 4-byte value with 1 byte left
    comp = bytes([1]) + bytes([0x90]) + b"\x00"
    nlri = bytes([len(comp)]) + comp
    mp = struct.pack("!HBB", 1, 133, 0) + b"\x00" + nlri
    body = update_body(attrs=clean_attrs() + attr(0x80, 14, mp))
    assert "PW-BGP-006" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-006: well-formed FlowSpec is silent")
def t_d006_clean():
    comp = bytes([1]) + bytes([0x81]) + b"\x06"     # end-of-list, 1-byte value
    nlri = bytes([len(comp)]) + comp
    mp = struct.pack("!HBB", 1, 133, 0) + b"\x00" + nlri
    body = update_body(attrs=clean_attrs() + attr(0x80, 14, mp))
    assert "PW-BGP-006" not in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-007: MP_REACH next-hop length exceeds attribute (2026-37458)")
def t_d007():
    mp = struct.pack("!HBB", 2, 1, 250) + b"\x00" * 4
    body = update_body(attrs=clean_attrs() + attr(0x80, 14, mp))
    assert "PW-BGP-007" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-007: MP_REACH NLRI prefix walk overrun, IPv6")
def t_d007_nlri():
    nh = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    # prefix length 128 but only 2 bytes of prefix supplied
    mp = struct.pack("!HBB", 2, 1, 16) + nh + b"\x00" + bytes([128]) + b"\x20\x01"
    body = update_body(attrs=clean_attrs() + attr(0x80, 14, mp))
    f = [x for x in bgpcve.inspect_message(bgp.UPDATE, body)
         if x.code == "PW-BGP-007"]
    assert f and f[0].afi == 2


@check("PW-BGP-007: truncated MP_REACH attribute")
def t_d007_short():
    body = update_body(attrs=clean_attrs() + attr(0x80, 14, b"\x00\x02"))
    assert "PW-BGP-007" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-007: non-prefix-shaped SAFIs are never prefix-walked")
def t_d007_not_prefix_shaped():
    """SR Policy (73), BGP-LS (71), labeled unicast (4) and EVPN (70) all carry
    their own NLRI encoding. Prefix-walking them overruns instantly and would
    report a malformation on entirely legitimate traffic -- the exact class of
    permanent false positive this suite rejects detectors for."""
    import socket
    nh = socket.inet_aton("10.0.0.1")

    def mp(afi, safi, nlri):
        return struct.pack("!HBB", afi, safi, len(nh)) + nh + b"\x00" + nlri

    cases = {
        "SR Policy v4": mp(1, 73, bytes([96]) + b"\x00" * 12),
        "SR Policy v6": mp(2, 73, bytes([192]) + b"\x00" * 24),
        "BGP-LS": mp(16388, 71, struct.pack("!HH", 1, 9) + b"\x02" + b"\x00" * 8),
        "labeled unicast": mp(1, 4, b"\x38\x00\x00\x10\xcb\x00\x71"),
        "EVPN": mp(25, 70, b"\x02\x19" + b"\x00" * 25),
    }
    for label, val in cases.items():
        body = update_body(attrs=clean_attrs() + attr(0x80, 14, val))
        got = codes(bgpcve.inspect_message(bgp.UPDATE, body))
        assert "PW-BGP-007" not in got, f"{label} false positive: {got}"


@check("PW-BGP-007: a genuine unicast NLRI overrun is still caught")
def t_d007_unicast_still_works():
    import socket
    nh = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    val = (struct.pack("!HBB", 2, 1, 16) + nh + b"\x00"
           + bytes([128]) + b"\x20\x01")      # /128 with 2 octets supplied
    body = update_body(attrs=clean_attrs() + attr(0x80, 14, val))
    assert "PW-BGP-007" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-008: NHC TLV length below minimum underflows (2026-37459)")
def t_d008():
    val = struct.pack("!BH", 1, 1)        # declared length 1 < MIN_LEN 3
    body = update_body(attrs=clean_attrs() + attr(0x80, 39, val))
    f = bgpcve.inspect_message(bgp.UPDATE, body)
    assert "PW-BGP-008" in codes(f), codes(f)


@check("PW-BGP-008: honours a configured NHC attribute code point")
def t_d008_configurable():
    val = struct.pack("!BH", 1, 1)
    body = update_body(attrs=clean_attrs() + attr(0x80, 41, val))
    assert "PW-BGP-008" not in codes(bgpcve.inspect_message(bgp.UPDATE, body))
    assert "PW-BGP-008" in codes(
        bgpcve.inspect_message(bgp.UPDATE, body, nhc_type=41))


@check("PW-BGP-009: IPv6 ext communities not a multiple of 20 (2026-37461)")
def t_d009():
    body = update_body(attrs=clean_attrs() + attr(0x80, 25, b"\x00" * 25))
    f = [x for x in bgpcve.inspect_message(bgp.UPDATE, body)
         if x.code == "PW-BGP-009"]
    assert f and f[0].afi == 2
    assert "CVE-2026-37461" in f[0].cves


@check("PW-BGP-010: declared attribute length exceeds body (2026-37462)")
def t_d010():
    body = update_body(attrs=clean_attrs(), alen=9999)
    assert "PW-BGP-010" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


@check("PW-BGP-010: declared withdrawn length exceeds body")
def t_d010_withdrawn():
    body = update_body(withdrawn=b"\x18\xcb\x00\x71", wlen=9999)
    assert "PW-BGP-010" in codes(bgpcve.inspect_message(bgp.UPDATE, body))


# --------------------------------------------------------------------------- #
# PW-BGP-013 / 014 -- CVE-2026-93345, labelled-VPN NLRI (SAFI 128)
#
# RFC 8277 s2: the NLRI Length octet counts BITS and covers the label bits as
# well as the prefix bits; for SAFI 128 the prefix is at least 64 bits (the
# RD). One label + RD = 88 bits before any address bit exists, so a declared
# length below 88 describes a negative-length address portion. Both VPNv4
# (AFI 1) and VPNv6 (AFI 2) are exercised -- the advisory names both.
# --------------------------------------------------------------------------- #
_VPN_FILL = (b"\x00\x01\x01"                      # one label, S bit set
             + b"\x00\x00\x00\x64\x0a\x00\x00\x01"  # 8-octet RD
             + b"\xcb\x00\x71\x01" * 8)             # address bytes


def vpn_nlri(bits, nbytes=None) -> bytes:
    """One SAFI 128 NLRI record with a given length octet (in bits)."""
    n = (bits + 7) // 8 if nbytes is None else nbytes
    return bytes([bits]) + _VPN_FILL[:n]


def vpn_mp(afi=1, nlri=b"", safi=128, attr_type=14) -> bytes:
    """MP_REACH/MP_UNREACH value carrying labelled-VPN NLRI. The VPN next hop
    is an 8-octet RD plus the address (12 octets v4, 24 v6), per RFC 4364."""
    if attr_type == 15:
        return struct.pack("!HB", afi, safi) + nlri
    nh = (b"\x00" * 8 + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
          if afi == 2 else b"\x00" * 8 + socket.inet_aton("10.0.0.1"))
    return struct.pack("!HBB", afi, safi, len(nh)) + nh + b"\x00" + nlri


def vpn_update(afi=1, bits=87, nbytes=None, safi=128, attr_type=14) -> bytes:
    return update_body(attrs=clean_attrs() + attr(
        0x80, attr_type, vpn_mp(afi, vpn_nlri(bits, nbytes), safi, attr_type)))


@check("PW-BGP-013: VPNv4 NLRI length below the 88-bit floor (2026-93345)")
def t_d013_v4():
    f = [x for x in bgpcve.inspect_message(bgp.UPDATE, vpn_update(1, 87))
         if x.code == "PW-BGP-013"]
    assert f, "87 bits must fire"
    _eq(f[0].confidence, "high")
    _eq(f[0].afi, 1)
    assert "CVE-2026-93345" in f[0].cves
    assert "-1 bits" in f[0].detail, f[0].detail


@check("PW-BGP-013: VPNv6 NLRI length below the 88-bit floor")
def t_d013_v6():
    f = [x for x in bgpcve.inspect_message(bgp.UPDATE, vpn_update(2, 40))
         if x.code == "PW-BGP-013"]
    assert f and f[0].afi == 2, "VPNv6 must fire with AFI stamped"
    assert "VPNv6" in f[0].detail


@check("PW-BGP-013: the 87/88-bit boundary is exact, both families")
def t_d013_boundary():
    for afi in (1, 2):
        assert "PW-BGP-013" in codes(
            bgpcve.inspect_message(bgp.UPDATE, vpn_update(afi, 87))), \
            f"AFI {afi}: 87 bits must fire"
        assert "PW-BGP-013" not in codes(
            bgpcve.inspect_message(bgp.UPDATE, vpn_update(afi, 88))), \
            f"AFI {afi}: 88 bits is a valid /0 and must stay silent"


@check("PW-BGP-013: legitimate VPN prefix lengths are all silent")
def t_d013_valid_silent():
    # v4: /0 /24 /32 ; v6: /0 /64 /128  (88 + address bits)
    for afi, lengths in ((1, (88, 112, 120)), (2, (88, 152, 216))):
        for bits in lengths:
            got = codes(bgpcve.inspect_message(bgp.UPDATE,
                                               vpn_update(afi, bits)))
            _eq(got, [], f"AFI {afi} length {bits} must be silent:")


@check("PW-BGP-013: capability-independent -- a two-label stack stays silent")
def t_d013_multi_label():
    """With the Multiple Labels Capability the floor rises to 48+64=112, but
    the 88-bit absolute floor still holds, so no capability state is needed
    and a legitimately deeper stack must not fire."""
    for afi in (1, 2):
        _eq(codes(bgpcve.inspect_message(bgp.UPDATE, vpn_update(afi, 112))),
            [], f"AFI {afi}: two labels + /0 is valid:")


@check("PW-BGP-013: MP_UNREACH withdrawal path is checked too")
def t_d013_unreach():
    for afi in (1, 2):
        f = codes(bgpcve.inspect_message(
            bgp.UPDATE, vpn_update(afi, 70, attr_type=15)))
        assert "PW-BGP-013" in f, f"AFI {afi} MP_UNREACH: {f}"


@check("PW-BGP-013: NLRI length overrunning the attribute is medium confidence")
def t_d013_overrun():
    f = [x for x in bgpcve.inspect_message(
        bgp.UPDATE, vpn_update(1, 120, nbytes=4)) if x.code == "PW-BGP-013"]
    assert f and f[0].confidence == "medium", f
    assert "overrun" in f[0].title.lower()


@check("PW-BGP-013: other SAFIs are untouched")
def t_d013_other_safis():
    for safi in (1, 4, 71, 73):
        got = codes(bgpcve.inspect_message(bgp.UPDATE,
                                           vpn_update(1, 20, safi=safi)))
        assert "PW-BGP-013" not in got, f"SAFI {safi} must not fire: {got}"


@check("PW-BGP-013: SAFI 129 off by default, available by config")
def t_d013_safi129():
    from bgpcve import d013_labelled_vpn_nlri, walk_update
    u = walk_update(vpn_update(1, 70, safi=129))
    _eq(d013_labelled_vpn_nlri(u), [])
    assert d013_labelled_vpn_nlri(u, vpn_safis=(128, 129))


@check("PW-BGP-014: trigger then teardown with no NOTIFICATION is confirmed")
def t_d014_correlated():
    tr = bgpcve.BgpCveTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    f = bgpcve.inspect_message(bgp.UPDATE, vpn_update(1, 87))
    tr.note_message(flow, bgp.UPDATE, f, ts=100.0)
    out = tr.note_teardown(flow, ts=102.0)
    _eq(codes(out), ["PW-BGP-014"])
    assert "CVE-2026-93345" in out[0].cves
    _eq(out[0].afi, 1)


@check("PW-BGP-014: finding is self-stamped with flow context")
def t_d014_self_stamped():
    """The correlation fires at teardown, with no message in hand to carry
    src/dst/family, so the tracker must stamp them itself rather than leave an
    unstamped finding as the easy mistake for any caller."""
    tr = bgpcve.BgpCveTracker()
    flow = ("10.9.9.1", 50000, "10.9.9.2", 179)
    f = bgpcve.inspect_message(bgp.UPDATE, vpn_update(2, 70))
    for x in f:
        x.family = 6                     # as the tap would have stamped it
    tr.note_message(flow, bgp.UPDATE, f, ts=100.0)
    out = tr.note_teardown(flow, ts=101.0)
    _eq(out[0].src, "10.9.9.1")
    _eq(out[0].dst, "10.9.9.2")
    _eq(out[0].family, 6, "transport family must survive to the correlation:")
    _eq(out[0].afi, 2)


@check("PW-BGP-014: silent when a NOTIFICATION was sent")
def t_d014_notification():
    tr = bgpcve.BgpCveTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.note_message(flow, bgp.UPDATE,
                    bgpcve.inspect_message(bgp.UPDATE, vpn_update(1, 87)),
                    ts=100.0)
    tr.note_message(flow, bgp.NOTIFICATION, [], ts=101.0)
    _eq(tr.note_teardown(flow, ts=102.0), [],
        "a graceful NOTIFICATION close is not the CVE's artifact:")


@check("PW-BGP-014: an ordinary reset with no trigger is silent")
def t_d014_no_trigger():
    tr = bgpcve.BgpCveTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.note_message(flow, bgp.UPDATE,
                    bgpcve.inspect_message(bgp.UPDATE, clean_update()),
                    ts=100.0)
    _eq(tr.note_teardown(flow, ts=101.0), [],
        "abnormal closes are ordinary on their own and must not alert:")


@check("PW-BGP-014: teardown outside the window is silent")
def t_d014_window():
    tr = bgpcve.BgpCveTracker(window_s=30.0)
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.note_message(flow, bgp.UPDATE,
                    bgpcve.inspect_message(bgp.UPDATE, vpn_update(1, 87)),
                    ts=100.0)
    _eq(tr.note_teardown(flow, ts=200.0), [])


@check("PW-BGP-014: flows are isolated")
def t_d014_isolation():
    tr = bgpcve.BgpCveTracker()
    a = ("10.0.0.1", 50000, "10.0.0.2", 179)
    b = ("10.0.0.3", 50001, "10.0.0.4", 179)
    tr.note_message(a, bgp.UPDATE,
                    bgpcve.inspect_message(bgp.UPDATE, vpn_update(1, 87)),
                    ts=100.0)
    _eq(tr.note_teardown(b, ts=101.0), [], "other flow must not inherit:")
    assert tr.note_teardown(a, ts=101.0)


@check("PW-BGP-014: end-to-end through the tap's RST teardown hook")
def t_d014_via_tap():
    for fam in (4, 6):
        tr = bgpcve.BgpCveTracker()
        fired = []
        tap = bgptap.BgpTap(
            on_teardown=lambda flow, src, dst, f, _tr=tr, _o=fired:
                _o.extend(_tr.note_teardown(flow)))
        msg = bgp_msg(bgp.UPDATE, vpn_update(2, 50))
        mk = frame_v4 if fam == 4 else frame_v6
        for m in tap.feed_packet(mk(msg, seq=1000)):
            tr.note_message(m.flow, m.msg_type,
                            bgpcve.inspect_tap_message(m))
        # session dies without a NOTIFICATION
        rst = (eth(ipv4(tcp(b"", seq=1000 + len(msg), flags=0x04)), 0x0800)
               if fam == 4 else
               eth(ipv6(tcp(b"", seq=1000 + len(msg), flags=0x04)), 0x86DD))
        tap.feed_packet(rst)
        _eq(codes(fired), ["PW-BGP-014"], f"fam v{fam}:")


@check("PARITY: 013 fires identically for VPNv4 and VPNv6 over all transports")
def t_d013_parity():
    results = {}
    for afi in (1, 2):
        body = vpn_update(afi, 60)
        for name, fam, eh in (("v4", 4, ()), ("v6", 6, ()),
                              ("v6+hbh", 6, [(0, b"")]),
                              ("v6+rt+ah", 6, [(43, b""), (51, b"\x00" * 12)])):
            tap = bgptap.BgpTap()
            mk = (frame_v4(bgp_msg(bgp.UPDATE, body)) if fam == 4
                  else frame_v6(bgp_msg(bgp.UPDATE, body), ext_headers=eh))
            got = tap.feed_packet(mk)
            _eq(len(got), 1, f"AFI {afi} {name}: not framed")
            f = [x for x in bgpcve.inspect_tap_message(got[0])
                 if x.code == "PW-BGP-013"]
            assert f, f"AFI {afi} {name}: 013 did not fire"
            _eq(f[0].afi, afi, f"AFI {afi} {name}: AFI stamp:")
            _eq(f[0].family, fam, f"AFI {afi} {name}: family stamp:")
            results[(afi, name)] = codes(
                bgpcve.inspect_tap_message(got[0]))
        base = results[(afi, "v4")]
        for (a, name), got in results.items():
            if a == afi:
                _eq(got, base, f"AFI {afi} parity break on {name}:")


@check("PW-BGP-011: OPEN with RFC 9072 extended optional parameter (2022-40302)")
def t_d011():
    # OPEN: version, my_as, hold, bgp_id, opt_len, then a 0xFF param
    parm = bytes([0xFF]) + struct.pack("!H", 2) + b"\x02\x00"
    body = struct.pack("!BHH", 4, 64512, 90) + socket.inet_aton("10.0.0.1")
    body += bytes([len(parm)]) + parm
    assert "PW-BGP-011" in codes(bgpcve.inspect_message(bgp.OPEN, body))


@check("PW-BGP-011: extended parameter with overrunning length is high confidence")
def t_d011_overrun():
    parm = bytes([0xFF]) + struct.pack("!H", 900) + b"\x02\x00"
    body = struct.pack("!BHH", 4, 64512, 90) + socket.inet_aton("10.0.0.1")
    body += bytes([len(parm)]) + parm
    f = [x for x in bgpcve.inspect_message(bgp.OPEN, body)
         if x.code == "PW-BGP-011"]
    assert f and f[0].confidence == "high"


@check("PW-BGP-012: OPEN ending exactly at opt-parm-len octet (2022-43681)")
def t_d012():
    body = struct.pack("!BHH", 4, 64512, 90) + socket.inet_aton("10.0.0.1")
    _eq(len(body), 9)
    assert "PW-BGP-012" in codes(bgpcve.inspect_message(bgp.OPEN, body))


@check("PW-BGP-012: opt_parm_len exceeding message")
def t_d012_overrun():
    body = struct.pack("!BHH", 4, 64512, 90) + socket.inet_aton("10.0.0.1")
    body += bytes([200])
    assert "PW-BGP-012" in codes(bgpcve.inspect_message(bgp.OPEN, body))


# --------------------------------------------------------------------------- #
# robustness -- detectors must survive what they are written to find
# --------------------------------------------------------------------------- #
@check("detectors never raise on fuzzed bodies")
def t_fuzz():
    import random
    rnd = random.Random(1337)
    for _ in range(600):
        n = rnd.randint(0, 80)
        body = bytes(rnd.randrange(256) for _ in range(n))
        for mt in (bgp.UPDATE, bgp.OPEN, bgp.KEEPALIVE, bgp.NOTIFICATION):
            bgpcve.inspect_message(mt, body)     # must not raise


@check("tap never raises on fuzzed frames")
def t_fuzz_frames():
    import random
    rnd = random.Random(99)
    tap = bgptap.BgpTap()
    for _ in range(400):
        n = rnd.randint(0, 120)
        tap.feed_packet(bytes(rnd.randrange(256) for _ in range(n)))


@check("iter_attributes reports overrun instead of raising")
def t_iter_overrun():
    attrs = struct.pack("!BBB", 0x40, 1, 200) + b"\x00" * 3
    got = list(bgpcve.iter_attributes(attrs))
    assert got and got[-1].overrun


# --------------------------------------------------------------------------- #
# dual-stack parity
# --------------------------------------------------------------------------- #
@check("PARITY: identical findings over IPv4, IPv6, and IPv6+EH transport")
def t_parity():
    val = struct.pack("!HB", 1, 200) + b"\x00" * 3       # malformed attr 23
    body = update_body(attrs=clean_attrs() + attr(0x80, 23, val))
    msg = bgp_msg(bgp.UPDATE, body)

    results = {}
    for name, frame in [
        ("v4", frame_v4(msg)),
        ("v6", frame_v6(msg)),
        ("v6+hbh", frame_v6(msg, ext_headers=[(0, b"")])),
        ("v6+hbh+dst", frame_v6(msg, ext_headers=[(0, b""), (60, b"")])),
        ("v6+rt+ah", frame_v6(msg, ext_headers=[(43, b""), (51, b"\x00" * 8)])),
    ]:
        tap = bgptap.BgpTap()
        msgs = tap.feed_packet(frame)
        _eq(len(msgs), 1, f"{name}: message not framed")
        f = bgpcve.inspect_tap_message(msgs[0])
        results[name] = codes(f)
        fam = msgs[0].family
        _eq(fam, 4 if name == "v4" else 6, f"{name}: transport family")
        assert all(x.family == fam for x in f), f"{name}: family not stamped"

    baseline = results["v4"]
    assert baseline == ["PW-BGP-001"], baseline
    for name, got in results.items():
        _eq(got, baseline, f"parity break on {name}:")


@check("PARITY: IPv6-only detector fires identically over both transports")
def t_parity_v6_detector():
    body = update_body(attrs=clean_attrs() + attr(0x80, 25, b"\x00" * 25))
    msg = bgp_msg(bgp.UPDATE, body)
    out = {}
    for name, frame in [("v4", frame_v4(msg)),
                        ("v6+eh", frame_v6(msg, ext_headers=[(0, b"")]))]:
        tap = bgptap.BgpTap()
        m = tap.feed_packet(frame)[0]
        out[name] = codes(bgpcve.inspect_tap_message(m))
    _eq(out["v4"], ["PW-BGP-009"])
    _eq(out["v6+eh"], ["PW-BGP-009"])


@check("PARITY: BPF filter admits IPv6 with extension headers")
def t_parity_bpf():
    # The default filter must not be the naive 'tcp port 179', which cannot
    # traverse an IPv6 EH chain and silently drops those packets.
    assert bgptap.BPF_DUAL_STACK != "tcp port 179"
    assert "ip6[6] != 6" in bgptap.BPF_DUAL_STACK, \
        "default filter must admit IPv6 packets whose next-header is not TCP"


@check("registry covers 15 CVEs across 14 codes")
def t_registry():
    all_cves = set()
    for cves, cvss in bgpcve.REGISTRY.values():
        all_cves.update(cves)
        assert cvss >= 6.5, f"{cves} below the 6.5 bar"
    _eq(len(bgpcve.REGISTRY), 14)
    _eq(len(all_cves), 15)


# --------------------------------------------------------------------------- #
def run() -> bool:
    passed = failed = 0
    for name, fn in _checks:
        try:
            fn()
            passed += 1
            print(f"  ok   {name}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {name}: {e}")
    total = passed + failed
    print(f"\n{passed}/{total} passing" + (f", {failed} FAILED" if failed else ""))
    return failed == 0


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
