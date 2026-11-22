#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hand-rolled wire builders for pimwatch fixtures.

These are deliberately INDEPENDENT of the parser in pimwatch.py: they lay
bytes out from the RFC field order, they do not reuse any parser helper, and
nothing here imports a parse_* function. That keeps the builder/parser pair
honest-ish -- but a shared misreading of an RFC would still pass (suite
LESSON A), which is why the cross-check tier drives scapy and tshark as
independent oracles.

Everything produced here is a byte string handed to handle_frame(), so every
fixture crosses the bytes->parse boundary that real captured traffic crosses
(suite LESSON AG). Nothing here transmits.
"""

import ipaddress
import socket
import struct

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD


def _csum(data):
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def _a4(s):
    return socket.inet_pton(socket.AF_INET, s)


def _a6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def _apack(s):
    return _a6(s) if ":" in s else _a4(s)


def _afi(s):
    return 2 if ":" in s else 1


# ---------------------------------------------------------------- framing

def eth(payload, ethertype, src="02:00:00:00:00:01",
        dst="01:00:5e:00:00:0d", vlans=()):
    out = _mac(dst) + _mac(src)
    for v in vlans:
        out += struct.pack("!HH", 0x8100, v & 0x0FFF)
    out += struct.pack("!H", ethertype)
    return out + payload


def ipv4(payload, src, dst, proto, ttl=1):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, ttl, proto, 0)
    hdr += _a4(src) + _a4(dst)
    c = _csum(hdr)
    hdr = hdr[:10] + struct.pack("!H", c) + hdr[12:]
    return hdr + payload


def ah_header(next_header, spi, seq, icv_len=12):
    """RFC 4302 AH. payload_len field = (total/4) - 2."""
    total = 12 + icv_len
    assert total % 4 == 0
    return (struct.pack("!BBH", next_header, (total // 4) - 2, 0)
            + struct.pack("!II", spi, seq) + b"\xaa" * icv_len)


def ext_header(next_header, kind, body_len=6, len_byte=0):
    """Generic 8-byte-multiple extension header (DestOpt/HopByHop/Routing).

    len_byte overrides the second octet. For a Fragment header that octet is
    RESERVED and conformant senders set it to zero -- which makes the correct
    fixed-8 advance and an incorrect (len+1)*8 advance give the same answer,
    so a fixture with a zero there cannot distinguish the two. An injector is
    under no such obligation, so the adversarial fixture sets it."""
    body = b"\x00" * body_len
    return struct.pack("!BB", next_header, len_byte) + body


def ipv6(payload, src, dst, nh, hlim=1, exts=()):
    """exts is an ordered list of ('ah', spi, seq) or ('ext', type) tuples
    placed between the fixed header and the payload."""
    chain = b""
    nexts = []
    for e in exts:
        nexts.append(e)
    # build from the back so each header points at the one after it
    cur_nh = nh
    parts = []
    for e in reversed(nexts):
        if e[0] == "ah":
            parts.insert(0, ah_header(cur_nh, e[1], e[2]))
            cur_nh = 51
        else:
            len_byte = e[2] if len(e) > 2 else 0
            parts.insert(0, ext_header(cur_nh, e[1], len_byte=len_byte))
            cur_nh = e[1]
    chain = b"".join(parts)
    body = chain + payload
    hdr = struct.pack("!IHBB", 0x60000000, len(body), cur_nh, hlim)
    hdr += _a6(src) + _a6(dst)
    return hdr + body


def udp(payload, sport, dport):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(payload, sport, dport, seq=1, flags=0x18, md5=False):
    opts = b""
    if md5:
        opts = struct.pack("!BB", 19, 18) + b"\x11" * 16
    while len(opts) % 4:
        opts += b"\x01"
    doff = (20 + len(opts)) // 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0,
                      (doff << 4), flags, 8192, 0, 0)
    return hdr + opts + payload


# ---------------------------------------------- PIM encoded address forms

def enc_unicast(addr):
    return struct.pack("!BB", _afi(addr), 0) + _apack(addr)


def enc_group(addr, masklen=None, bidir=False):
    if masklen is None:
        masklen = 128 if ":" in addr else 32
    flags = 0x80 if bidir else 0x00
    return struct.pack("!BBBB", _afi(addr), 0, flags, masklen) + _apack(addr)


def enc_source(addr, masklen=None, sparse=True, wildcard=False, rpt=False):
    if masklen is None:
        masklen = 128 if ":" in addr else 32
    flags = (0x04 if sparse else 0) | (0x02 if wildcard else 0) | (0x01 if rpt else 0)
    return struct.pack("!BBBB", _afi(addr), 0, flags, masklen) + _apack(addr)


# ---------------------------------------------------------- PIM messages

def pim_wrap(ptype, body, version=2, src=None, dst=None, bad_checksum=False,
             checksum_len=None, flags=0):
    """Assemble header + body and fill the checksum.

    src/dst must be given for IPv6, which checksums over a pseudo-header.
    checksum_len limits the covered span (the 8-byte Register convention).
    """
    msg = struct.pack("!BBH", (version << 4) | ptype, flags, 0) + body
    span = msg if checksum_len is None else msg[:checksum_len]
    if src and ":" in src:
        ph = (_a6(src) + _a6(dst)
              + struct.pack("!IBBBB", len(span), 0, 0, 0, 103))
        c = _csum(ph + span)
    else:
        c = _csum(span)
    if bad_checksum:
        c = (c ^ 0xFFFF) & 0xFFFF
    return msg[:2] + struct.pack("!H", c) + msg[4:]


def hello_body(holdtime=105, dr_priority=1, gen_id=0x11223344,
               bidir=False, state_refresh=None, lan_prune_delay=None,
               t_bit=False, address_list=(), unknown_opt=None,
               omit_holdtime=False):
    out = b""
    if not omit_holdtime:
        out += struct.pack("!HHH", 1, 2, holdtime)
    if lan_prune_delay is not None:
        raw = (0x8000 if t_bit else 0) | (lan_prune_delay & 0x7FFF)
        out += struct.pack("!HHHH", 2, 4, raw, 2500)
    if dr_priority is not None:
        out += struct.pack("!HHI", 19, 4, dr_priority)
    if gen_id is not None:
        out += struct.pack("!HHI", 20, 4, gen_id)
    if state_refresh is not None:
        out += struct.pack("!HHBBH", 21, 4, 1, state_refresh, 0)
    if bidir:
        out += struct.pack("!HH", 22, 0)
    if address_list:
        v = b"".join(enc_unicast(a) for a in address_list)
        out += struct.pack("!HH", 24, len(v)) + v
    if unknown_opt is not None:
        out += struct.pack("!HH", unknown_opt, 0)
    return out


def register_body(inner_src, inner_group, border=False, null=False,
                  inner_payload=b"\x00" * 8):
    flags = (0x80000000 if border else 0) | (0x40000000 if null else 0)
    out = struct.pack("!I", flags)
    if ":" in inner_group:
        inner = struct.pack("!IHBB", 0x60000000, len(inner_payload), 17, 64)
        inner += _a6(inner_src) + _a6(inner_group) + inner_payload
    else:
        total = 20 + len(inner_payload)
        ih = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 17, 0)
        ih += _a4(inner_src) + _a4(inner_group)
        inner = ih + inner_payload
    return out + inner


def register_stop_body(group, source):
    return enc_group(group) + enc_unicast(source)


def join_prune_body(upstream, groups, holdtime=210, attributes=b"",
                    force_num_groups=None):
    """groups: list of (group_addr, [join_source_tuples], [prune_source_tuples])
    where each source tuple is (addr, wildcard, rpt)."""
    out = enc_unicast(upstream)
    ng = len(groups) if force_num_groups is None else force_num_groups
    out += struct.pack("!BBH", 0, ng, holdtime)
    for gaddr, joins, prunes in groups:
        out += enc_group(gaddr)
        out += struct.pack("!HH", len(joins), len(prunes))
        for a, w, r in joins:
            out += enc_source(a, wildcard=w, rpt=r)
        for a, w, r in prunes:
            out += enc_source(a, wildcard=w, rpt=r)
    return out + attributes


def jp_attribute(atype, value, last=True):
    return struct.pack("!BB", (0x40 if last else 0) | (atype & 0x3F),
                       len(value)) + value


def rpf_vector_attr(addr, last=True):
    return jp_attribute(0, enc_unicast(addr), last=last)


def assert_body(group, source, metric_pref=110, metric=10, rpt=False):
    out = enc_group(group) + enc_unicast(source)
    pref = (0x80000000 if rpt else 0) | (metric_pref & 0x7FFFFFFF)
    return out + struct.pack("!II", pref, metric)


def bootstrap_body(bsr, group_sets, fragment_tag=1, hash_mask_len=30,
                   bsr_priority=64):
    out = struct.pack("!HBB", fragment_tag, hash_mask_len, bsr_priority)
    out += enc_unicast(bsr)
    for gaddr, masklen, rps in group_sets:
        out += enc_group(gaddr, masklen)
        out += struct.pack("!BBH", len(rps), len(rps), 0)
        for rp_addr, holdtime, priority in rps:
            out += enc_unicast(rp_addr)
            out += struct.pack("!HBB", holdtime, priority, 0)
    return out


def cand_rp_body(rp, groups, priority=192, holdtime=150):
    out = struct.pack("!BBH", len(groups), priority, holdtime)
    out += enc_unicast(rp)
    for gaddr, masklen in groups:
        out += enc_group(gaddr, masklen)
    return out


def state_refresh_body(group, source, originator, metric_pref=110, metric=10,
                       masklen=32, ttl=16, interval=60, prune_indicator=True):
    out = enc_group(group) + enc_unicast(source) + enc_unicast(originator)
    out += struct.pack("!II", metric_pref, metric)
    flags = 0x80 if prune_indicator else 0
    out += struct.pack("!BBBB", masklen, ttl, flags, interval)
    return out


def df_election_body(rp, metric_pref=110, metric=10,
                     target=None, target_pref=0, target_metric=0):
    """RFC 5015: the body starts at the RP address. The subtype is carried
    in the PIM header's second octet, so callers pass df_flags() to pim4/
    pim6 alongside this body."""
    out = enc_unicast(rp)
    out += struct.pack("!II", metric_pref, metric)
    if target is not None:
        out += enc_unicast(target)
        out += struct.pack("!II", target_pref, target_metric)
    return out


def df_flags(subtype):
    """The PIM header octet that carries a DF Election subtype."""
    return (subtype & 0x0F) << 4


# ---------------------------------------------------------------- Auto-RP

def autorp_body(ptype, rps, holdtime=180, version=1):
    """rps: list of (rp_addr, [(group, masklen, negative)])"""
    out = struct.pack("!BBH", (version << 4) | ptype, len(rps), holdtime)
    out += b"\x00" * 4
    for rp_addr, groups in rps:
        out += _a4(rp_addr) + struct.pack("!BB", 2, len(groups))
        for gaddr, masklen, negative in groups:
            out += struct.pack("!BB", 1 if negative else 0, masklen)
            out += _a4(gaddr)
    return out


# ------------------------------------------------------------------ MSDP

def msdp_sa(rp, entries, encapsulated=b""):
    """entries: list of (group, source)"""
    body = struct.pack("!B", len(entries)) + _a4(rp)
    for g, s in entries:
        body += b"\x00\x00\x00" + struct.pack("!B", 32) + _a4(g) + _a4(s)
    body += encapsulated
    return struct.pack("!BH", 1, 3 + len(body)) + body


def msdp_sa_bad_count(rp, entries, declared):
    body = struct.pack("!B", declared) + _a4(rp)
    for g, s in entries:
        body += b"\x00\x00\x00" + struct.pack("!B", 32) + _a4(g) + _a4(s)
    return struct.pack("!BH", 1, 3 + len(body)) + body


def msdp_keepalive():
    return struct.pack("!BH", 4, 3)


def msdp_sa_request(group):
    body = b"\x00" + _a4(group)
    return struct.pack("!BH", 2, 3 + len(body)) + body


# ------------------------------------------------- whole-frame shortcuts

def pim4(ptype, body, src, dst="224.0.0.13", ttl=1, smac="02:00:00:00:00:01",
         bad_checksum=False, version=2, vlans=(), checksum_len=None, flags=0):
    msg = pim_wrap(ptype, body, version=version, bad_checksum=bad_checksum,
                   checksum_len=checksum_len, flags=flags)
    return eth(ipv4(msg, src, dst, 103, ttl=ttl), ETH_P_IPV4,
               src=smac, vlans=vlans)


def pim6(ptype, body, src, dst="ff02::d", hlim=1, smac="02:00:00:00:00:01",
         bad_checksum=False, exts=(), version=2, vlans=(), checksum_len=None,
         flags=0):
    msg = pim_wrap(ptype, body, version=version, src=src, dst=dst,
                   bad_checksum=bad_checksum, checksum_len=checksum_len,
                   flags=flags)
    return eth(ipv6(msg, src, dst, 103, hlim=hlim, exts=exts), ETH_P_IPV6,
               src=smac, dst="33:33:00:00:00:0d", vlans=vlans)


def autorp4(ptype, rps, src, dst="224.0.1.39", holdtime=180):
    body = autorp_body(ptype, rps, holdtime=holdtime)
    return eth(ipv4(udp(body, 496, 496), src, dst, 17, ttl=10), ETH_P_IPV4)


def msdp4(payload, src, dst, sport=50001, dport=639, flags=0x18, md5=False,
          seq=1):
    return eth(ipv4(tcp(payload, sport, dport, seq=seq, flags=flags, md5=md5),
                    src, dst, 6, ttl=64), ETH_P_IPV4,
               dst="02:00:00:00:00:fe")
