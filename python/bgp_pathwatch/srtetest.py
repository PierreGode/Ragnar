#!/usr/bin/env python3
"""
srtetest.py -- offline tests for the SR Policy (BGP-SRTE) + BGP-LS tier.

No packets sent, no NIC touched. SR Policy NLRI (AFI 1 and 2 / SAFI 73),
Tunnel Encapsulation tunnel type 15 with segment lists, and BGP-LS NLRI
(AFI 16388 / SAFI 71) plus attribute 29 are synthesized byte-for-byte from
RFC 9830 / RFC 9552 / RFC 9085 and fed through the real tap.

Dual-stack is asserted, not assumed. Both families have genuinely distinct
v4/v6 parse paths, so parity is checked at three levels: NLRI (SR endpoint
4 vs 16 octets; BGP-LS prefix NLRI type 3 vs 4), payload (Segment Type A
SR-MPLS label vs Type B SRv6 SID; descriptor TLVs 259/260 vs 261/262;
Router-ID TLVs 1028/1030 vs 1029/1031), and transport (v4 / v6 / v6+EH).

Run: python3 srtetest.py
"""

from __future__ import annotations

import socket
import struct
import sys

import bgp
import bgpsrte as S
import bgptap
import taptest as T

_checks = []


def check(name):
    def deco(fn):
        _checks.append((name, fn))
        return fn
    return deco


def _eq(a, b, msg=""):
    assert a == b, f"{msg} expected {b!r} got {a!r}"


def codes(fs):
    return sorted({f.code for f in fs})


# --------------------------------------------------------------------------- #
# builders
# --------------------------------------------------------------------------- #
def mp_reach_raw(afi, safi, nh: bytes, nlri: bytes) -> bytes:
    """Raw MP_REACH value: SR Policy and BGP-LS NLRI are not prefix-shaped, so
    bgp.encode_mp_reach cannot build them."""
    return struct.pack("!HBB", afi, safi, len(nh)) + nh + b"\x00" + nlri


def mp_unreach_raw(afi, safi, nlri: bytes) -> bytes:
    return struct.pack("!HB", afi, safi) + nlri


def sr_nlri(afi=1, dist=1, color=100, endpoint=None, length_bits=None) -> bytes:
    if afi == S.AFI_IPV6:
        ep = socket.inet_pton(socket.AF_INET6, endpoint or "2001:db8::1")
        bits = 192
    else:
        ep = socket.inet_aton(endpoint or "10.0.0.1")
        bits = 96
    body = struct.pack("!II", dist, color) + ep
    return bytes([length_bits if length_bits is not None else bits]) + body


def sub8(t, v: bytes) -> bytes:
    """tunnel-encaps sub-TLV: 1B type, 1B length (type < 128)."""
    return bytes([t, len(v)]) + v


def sub16(t, v: bytes) -> bytes:
    """tunnel-encaps sub-TLV: 1B type, 2B length (type >= 128)."""
    return bytes([t]) + struct.pack("!H", len(v)) + v


def seg_a(label=16000, declared_len=None) -> bytes:
    v = b"\x00\x00" + struct.pack("!I", label << 12)
    body = bytes([S.SEG_TYPE_A, declared_len if declared_len is not None
                  else len(v)]) + v
    return body


def seg_b(sid="2001:db8::5", declared_len=None, extra=b"") -> bytes:
    v = b"\x00\x00" + socket.inet_pton(socket.AF_INET6, sid) + extra
    return bytes([S.SEG_TYPE_B, declared_len if declared_len is not None
                  else len(v)]) + v


def seg_raw(stype, v=b"\x00\x00\x00\x00") -> bytes:
    return bytes([stype, len(v)]) + v


def segment_list(segs: bytes, weight=None) -> bytes:
    body = b""
    if weight is not None:
        body += sub8(S.SEG_WEIGHT, b"\x00\x00" + struct.pack("!I", weight))
    body += segs
    return sub16(S.SR_SUBTLV_SEGMENT_LIST, body)


def tunnel_encap(subtlvs: bytes, ttype=15) -> bytes:
    """Tunnel Encapsulation attribute value.

    RFC 9012 s2: Tunnel TLV is [2B Tunnel Type][2B Length][Value]. The 2-octet
    length is what lets a real segment list exceed 255 octets at all.
    """
    return struct.pack("!HH", ttype, len(subtlvs)) + subtlvs


def sr_policy_attrs(afi=1, segs=None, weight=None, pref=100,
                    extra_sub=b"", ttype=15):
    """ORIGIN + MP_REACH(SAFI 73) + Tunnel Encaps(type 15)."""
    segs = seg_a() if segs is None else segs
    sub = sub8(S.SR_SUBTLV_PREFERENCE, b"\x00\x00" + struct.pack("!I", pref))
    sub += segment_list(segs, weight=weight) if segs else b""
    sub += extra_sub
    nh = (socket.inet_pton(socket.AF_INET6, "2001:db8::1") if afi == 2
          else socket.inet_aton("10.0.0.1"))
    return (T.attr(0x40, 1, b"\x00")
            + T.attr(0x80, 14, mp_reach_raw(afi, S.SAFI_SR_POLICY, nh,
                                            sr_nlri(afi)))
            + T.attr(0x90 if len(tunnel_encap(sub, ttype)) > 255 else 0x80,
                      23, tunnel_encap(sub, ttype=ttype)))


def sr_update(afi=1, **kw) -> bytes:
    return T.update_body(attrs=sr_policy_attrs(afi, **kw))


def ls_tlv(t, v: bytes) -> bytes:
    return struct.pack("!HH", t, len(v)) + v


def node_desc(as_num=64500, router_id=b"\x01\x02\x03\x04") -> bytes:
    inner = b""
    if as_num is not None:
        inner += ls_tlv(S.LS_SUB_AS, struct.pack("!I", as_num))
    if router_id is not None:
        inner += ls_tlv(S.LS_SUB_IGP_ROUTER_ID, router_id)
    return ls_tlv(S.LS_TLV_LOCAL_NODE, inner)


def ls_nlri(nlri_type=1, proto=2, identifier=0, descriptors=None,
            total_len=None, with_local=True, as_num=64500,
            router_id=b"\x01\x02\x03\x04") -> bytes:
    body = bytes([proto]) + struct.pack("!Q", identifier)
    if with_local:
        body += node_desc(as_num, router_id)
    if descriptors:
        body += descriptors
    return struct.pack("!HH", nlri_type,
                       total_len if total_len is not None else len(body)) + body


def ls_update(nlri_type=1, attr_tlvs=b"", safi=71, **kw) -> bytes:
    nh = socket.inet_aton("10.0.0.1")
    a = (T.attr(0x40, 1, b"\x00")
         + T.attr(0x80, 14, mp_reach_raw(S.AFI_BGP_LS, safi, nh,
                                         ls_nlri(nlri_type, **kw))))
    if attr_tlvs:
        a += T.attr(0x80, 29, attr_tlvs)
    return T.update_body(attrs=a)


def mp_cap(afi, safi) -> bytes:
    return struct.pack("!HBB", afi, 0, safi)


def open_body(families=(), my_as=64512, bgp_id="10.0.0.1") -> bytes:
    capblob = b"".join(bytes([1, 4]) + mp_cap(a, s) for a, s in families)
    parm = bytes([2, len(capblob)]) + capblob if capblob else b""
    b = struct.pack("!BHH", 4, my_as, 90) + socket.inet_aton(bgp_id)
    return b + bytes([len(parm)]) + parm


def tap_once(mt, body, fam=4, eh=(), tracker=None, sport=50000):
    msg = T.bgp_msg(mt, body)
    tap = bgptap.BgpTap()
    fr = (T.frame_v4(msg, sport=sport) if fam == 4
          else T.frame_v6(msg, ext_headers=eh, sport=sport))
    got = tap.feed_packet(fr)
    assert len(got) == 1, f"message did not frame (fam={fam})"
    return S.inspect_tap_message(got[0], tracker=tracker)


# --------------------------------------------------------------------------- #
# SR Policy NLRI
# --------------------------------------------------------------------------- #
@check("SR NLRI: decodes AFI 1 (12-octet, 96-bit) correctly")
def t_sr_nlri_v4():
    got = S.parse_sr_policy_nlri(sr_nlri(1, 7, 100, "10.1.2.3"), 1)
    _eq(len(got), 1)
    p = got[0]
    _eq(p.problems, [])
    _eq(p.length_bits, 96)
    _eq((p.distinguisher, p.color, p.endpoint), (7, 100, "10.1.2.3"))


@check("SR NLRI: decodes AFI 2 (24-octet, 192-bit) correctly")
def t_sr_nlri_v6():
    got = S.parse_sr_policy_nlri(sr_nlri(2, 9, 200, "2001:db8::abcd"), 2)
    _eq(len(got), 1)
    p = got[0]
    _eq(p.problems, [])
    _eq(p.length_bits, 192)
    _eq((p.distinguisher, p.color, p.endpoint), (9, 200, "2001:db8::abcd"))


@check("SR NLRI: multiple policies in one NLRI run, both families")
def t_sr_nlri_multi():
    for afi in (1, 2):
        run = sr_nlri(afi, 1, 10) + sr_nlri(afi, 2, 20)
        got = S.parse_sr_policy_nlri(run, afi)
        _eq(len(got), 2, f"AFI {afi}:")
        assert all(not p.problems for p in got)


@check("SRTE-001: clean SR Policy yields posture inventory, both families")
def t_sr_clean():
    for afi in (1, 2):
        f = S.inspect_message(bgp.UPDATE, sr_update(afi))
        _eq(codes(f), ["SRTE-001"], f"AFI {afi}:")
        _eq([x for x in f if x.code == "SRTE-001"][0].afi, afi)


@check("SRTE-002: NLRI length field wrong for the AFI, both families")
def t_sr_badlen():
    for afi, wrong in ((1, 192), (2, 96)):
        nh = (socket.inet_pton(socket.AF_INET6, "2001:db8::1") if afi == 2
              else socket.inet_aton("10.0.0.1"))
        body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + T.attr(
            0x80, 14, mp_reach_raw(afi, 73, nh,
                                   sr_nlri(afi, length_bits=wrong))))
        f = S.inspect_message(bgp.UPDATE, body)
        assert "SRTE-002" in codes(f), f"AFI {afi}: {codes(f)}"


@check("SRTE-004: colour zero flagged, both families")
def t_sr_color_zero():
    for afi in (1, 2):
        nh = (socket.inet_pton(socket.AF_INET6, "2001:db8::1") if afi == 2
              else socket.inet_aton("10.0.0.1"))
        body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + T.attr(
            0x80, 14, mp_reach_raw(afi, 73, nh, sr_nlri(afi, color=0))))
        f = S.inspect_message(bgp.UPDATE, body)
        assert "SRTE-004" in codes(f), f"AFI {afi}: {codes(f)}"


@check("SR NLRI: SAFI other than 73 is ignored")
def t_sr_other_safi():
    nh = socket.inet_aton("10.0.0.1")
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + T.attr(
        0x80, 14, mp_reach_raw(1, 1, nh, bgp.encode_prefix("203.0.113.0/24"))))
    _eq(S.inspect_message(bgp.UPDATE, body), [])


# --------------------------------------------------------------------------- #
# segment lists -- the v4/v6 analogues
# --------------------------------------------------------------------------- #
@check("segments: Type A (SR-MPLS) decodes label")
def t_seg_a():
    sl = S.parse_segment_list(sub16(128, seg_a(16001))[3:])
    _eq(len(sl.segments), 1)
    _eq(sl.segments[0].seg_type, S.SEG_TYPE_A)
    _eq(sl.segments[0].label, 16001)
    _eq(sl.segments[0].problems, [])


@check("segments: Type B (SRv6) decodes 128-bit SID at codepoint 13")
def t_seg_b():
    sl = S.parse_segment_list(sub16(128, seg_b("2001:db8::99"))[3:])
    _eq(len(sl.segments), 1)
    _eq(sl.segments[0].seg_type, 13)
    _eq(sl.segments[0].sid, "2001:db8::99")
    _eq(sl.segments[0].problems, [])


@check("segments: Type B with the 26-octet SRv6 behaviour structure is clean")
def t_seg_b_26():
    sl = S.parse_segment_list(
        sub16(128, seg_b(extra=b"\x00" * 8))[3:])
    _eq(sl.segments[0].problems, [])
    _eq(sl.segments[0].length, 26)


@check("segments: weight sub-TLV decoded, not mistaken for a segment")
def t_seg_weight():
    sl = S.parse_segment_list(
        segment_list(seg_a(), weight=5)[3:])
    _eq(sl.weight, 5)
    _eq(len(sl.segments), 1)


@check("SRTE-022: deprecated segment codepoint 2")
def t_seg_deprecated():
    f = S.inspect_message(bgp.UPDATE,
                          sr_update(1, segs=seg_raw(S.SEG_TYPE_DEPRECATED)))
    assert "SRTE-022" in codes(f), codes(f)


@check("SRTE-023: unassigned segment type")
def t_seg_unknown():
    f = S.inspect_message(bgp.UPDATE, sr_update(1, segs=seg_raw(99)))
    assert "SRTE-023" in codes(f), codes(f)


@check("SRTE-023: extension types C-K are known, not flagged unknown")
def t_seg_ext_known():
    for st in sorted(S.SEG_TYPES_EXT):
        f = S.inspect_message(bgp.UPDATE, sr_update(1, segs=seg_raw(st)))
        assert "SRTE-023" not in codes(f), f"type {st} should be known"


@check("SRTE-024: Type A wrong length")
def t_seg_a_badlen():
    bad = bytes([S.SEG_TYPE_A, 4]) + b"\x00" * 4
    f = S.inspect_message(bgp.UPDATE, sr_update(1, segs=bad))
    assert "SRTE-024" in codes(f), codes(f)


@check("SRTE-024: Type A reserved MPLS label")
def t_seg_a_reserved():
    f = S.inspect_message(bgp.UPDATE, sr_update(1, segs=seg_a(label=3)))
    f2 = [x for x in f if x.code == "SRTE-024"]
    assert f2 and "reserved" in f2[0].detail


@check("SRTE-025: Type B wrong length")
def t_seg_b_badlen():
    bad = bytes([S.SEG_TYPE_B, 10]) + b"\x00" * 10
    f = S.inspect_message(bgp.UPDATE, sr_update(1, segs=bad))
    assert "SRTE-025" in codes(f), codes(f)


@check("SRTE-020: tunnel type 15 with no Segment List")
def t_no_seglist():
    f = S.inspect_message(bgp.UPDATE, sr_update(1, segs=b""))
    assert "SRTE-020" in codes(f), codes(f)


@check("SRTE-021: Segment List with no segments")
def t_empty_seglist():
    sub = sub8(S.SR_SUBTLV_PREFERENCE, b"\x00\x00\x00\x00\x00\x64")
    sub += sub16(S.SR_SUBTLV_SEGMENT_LIST, b"")
    nh = socket.inet_aton("10.0.0.1")
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00")
                         + T.attr(0x80, 14, mp_reach_raw(1, 73, nh, sr_nlri(1)))
                         + T.attr(0x80, 23, tunnel_encap(sub)))
    assert "SRTE-021" in codes(S.inspect_message(bgp.UPDATE, body))


@check("SRTE-027: implausibly deep segment list")
def t_deep_seglist():
    f = S.inspect_message(bgp.UPDATE, sr_update(1, segs=seg_a() * 60))
    assert "SRTE-027" in codes(f), codes(f)


@check("SRTE-027: a realistic 6-segment stack is silent")
def t_normal_depth():
    f = S.inspect_message(bgp.UPDATE, sr_update(1, segs=seg_a() * 6))
    assert "SRTE-027" not in codes(f)


@check("SRTE-026: malformed Binding SID length")
def t_binding_sid():
    extra = sub8(S.SR_SUBTLV_BINDING_SID, b"\x00" * 7)
    f = S.inspect_message(bgp.UPDATE, sr_update(1, extra_sub=extra))
    assert "SRTE-026" in codes(f), codes(f)


@check("SRTE-026: valid Binding SID lengths are silent")
def t_binding_sid_ok():
    for ln in (2, 6, 18):
        extra = sub8(S.SR_SUBTLV_BINDING_SID, b"\x00" * ln)
        f = S.inspect_message(bgp.UPDATE, sr_update(1, extra_sub=extra))
        assert "SRTE-026" not in codes(f), f"len {ln}: {codes(f)}"


@check("tunnel type other than 15 is not treated as SR Policy")
def t_other_tunnel_type():
    f = S.inspect_message(bgp.UPDATE, sr_update(1, ttype=2))
    assert "SRTE-020" not in codes(f)
    assert "SRTE-021" not in codes(f)


@check("CVE-tier overlap: this tier emits no generic malformed-attr-23 finding")
def t_no_double_alert():
    import bgpcve
    # a sub-TLV length that overruns -- PW-BGP-001's territory
    bad = struct.pack("!HB", 15, 200) + b"\x00" * 3
    nh = socket.inet_aton("10.0.0.1")
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00")
                         + T.attr(0x80, 14, mp_reach_raw(1, 73, nh, sr_nlri(1)))
                         + T.attr(0x80, 23, bad))
    cve = bgpcve.inspect_message(bgp.UPDATE, body)
    srte = S.inspect_message(bgp.UPDATE, body)
    assert "PW-BGP-001" in codes(cve), "CVE tier must own the malformation"
    assert "SRTE-026" not in codes(srte), \
        "SR tier must not double-alert on attribute-level malformation"


# --------------------------------------------------------------------------- #
# BGP-LS NLRI
# --------------------------------------------------------------------------- #
@check("BGP-LS NLRI: Node decodes protocol, identifier, AS, router-id")
def t_ls_node():
    got = S.parse_ls_nlri(ls_nlri(1, proto=2, as_num=64500))
    _eq(len(got), 1)
    o = got[0]
    _eq(o.problems, [])
    _eq(o.nlri_type, 1)
    _eq(o.proto_id, 2)
    _eq(o.local_as, 64500)
    _eq(o.igp_router_id, b"\x01\x02\x03\x04")


@check("BGPLS-001: all four NLRI types decode cleanly")
def t_ls_all_types():
    for t, name in S.LS_NLRI_NAMES.items():
        f = S.inspect_message(bgp.UPDATE, ls_update(nlri_type=t))
        _eq(codes(f), ["BGPLS-001"], f"{name}:")
        assert name in [x for x in f if x.code == "BGPLS-001"][0].detail


@check("BGPLS-001: IPv4 and IPv6 topology prefix NLRI are distinct paths")
def t_ls_prefix_families():
    for t in (S.LS_NLRI_PREFIX_V4, S.LS_NLRI_PREFIX_V6):
        reach = (ls_tlv(S.LS_TLV_IP_REACH, bytes([24]) + b"\xcb\x00\x71")
                 if t == 3 else
                 ls_tlv(S.LS_TLV_IP_REACH, bytes([48]) + b"\x20\x01\x0d\xb8\xab\xcd"))
        f = S.inspect_message(bgp.UPDATE,
                              ls_update(nlri_type=t, descriptors=reach))
        _eq(codes(f), ["BGPLS-001"], f"NLRI type {t}:")


@check("BGP-LS: IPv4 and IPv6 link descriptor TLVs both decode")
def t_ls_link_desc():
    v4 = (ls_tlv(S.LS_TLV_IPV4_IFACE, socket.inet_aton("10.0.0.1"))
          + ls_tlv(S.LS_TLV_IPV4_NEIGH, socket.inet_aton("10.0.0.2")))
    v6 = (ls_tlv(S.LS_TLV_IPV6_IFACE,
                 socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
          + ls_tlv(S.LS_TLV_IPV6_NEIGH,
                   socket.inet_pton(socket.AF_INET6, "2001:db8::2")))
    for label, desc, want in (("v4", v4, [S.LS_TLV_IPV4_IFACE,
                                          S.LS_TLV_IPV4_NEIGH]),
                              ("v6", v6, [S.LS_TLV_IPV6_IFACE,
                                          S.LS_TLV_IPV6_NEIGH])):
        got = S.parse_ls_nlri(ls_nlri(2, descriptors=desc))
        _eq(got[0].problems, [], f"{label}:")
        for w in want:
            assert w in got[0].descriptors, f"{label}: TLV {w} not seen"


@check("BGPLS-002: unassigned Link-State NLRI type")
def t_ls_bad_type():
    f = S.inspect_message(bgp.UPDATE, ls_update(nlri_type=9))
    assert "BGPLS-002" in codes(f), codes(f)


@check("BGPLS-003: NLRI total length overruns")
def t_ls_overrun():
    f = S.inspect_message(bgp.UPDATE, ls_update(nlri_type=1, total_len=900))
    assert "BGPLS-003" in codes(f), codes(f)


@check("BGPLS-003: unassigned protocol-ID")
def t_ls_bad_proto():
    f = S.inspect_message(bgp.UPDATE, ls_update(nlri_type=1, proto=200))
    assert "BGPLS-003" in codes(f), codes(f)


@check("BGPLS-003: missing mandatory Local Node Descriptors (256)")
def t_ls_no_local():
    f = S.inspect_message(bgp.UPDATE, ls_update(nlri_type=1, with_local=False))
    hit = [x for x in f if x.code == "BGPLS-003"]
    assert hit and "256" in hit[0].detail, codes(f)


@check("BGPLS-020: BGP-LS attribute without BGP-LS NLRI")
def t_ls_attr_orphan():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00")
                         + T.attr(0x80, 29, ls_tlv(1026, b"rtr")))
    assert "BGPLS-020" in codes(S.inspect_message(bgp.UPDATE, body))


@check("BGPLS-021: malformed BGP-LS attribute TLV")
def t_ls_attr_bad():
    bad = struct.pack("!HH", 1026, 900) + b"\x00" * 4
    f = S.inspect_message(bgp.UPDATE, ls_update(nlri_type=1, attr_tlvs=bad))
    assert "BGPLS-021" in codes(f), codes(f)


@check("BGP-LS: IPv4 and IPv6 Router-ID attribute TLVs both carried cleanly")
def t_ls_router_ids():
    v4 = (ls_tlv(S.LS_ATTR_ROUTER_ID_V4_LOCAL, socket.inet_aton("10.0.0.1"))
          + ls_tlv(S.LS_ATTR_ROUTER_ID_V4_REMOTE,
                   socket.inet_aton("10.0.0.2")))
    v6 = (ls_tlv(S.LS_ATTR_ROUTER_ID_V6_LOCAL,
                 socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
          + ls_tlv(S.LS_ATTR_ROUTER_ID_V6_REMOTE,
                   socket.inet_pton(socket.AF_INET6, "2001:db8::2")))
    for label, tlvs in (("v4", v4), ("v6", v6)):
        f = S.inspect_message(bgp.UPDATE,
                              ls_update(nlri_type=1, attr_tlvs=tlvs))
        _eq(codes(f), ["BGPLS-001"], f"{label} router-ids should be clean:")


@check("BGPLS-022: SRGB base in the reserved label range")
def t_srgb_reserved():
    rng = b"\x00\x00" + (8000).to_bytes(3, "big") + ls_tlv(1161, (3).to_bytes(3, "big"))
    f = S.inspect_message(bgp.UPDATE,
                          ls_update(nlri_type=1,
                                    attr_tlvs=ls_tlv(S.LS_ATTR_SR_CAPS, rng)))
    assert "BGPLS-022" in codes(f), codes(f)


@check("BGPLS-022: SRGB range running past the 20-bit label maximum")
def t_srgb_overflow():
    rng = (b"\x00\x00" + (900000).to_bytes(3, "big")
           + ls_tlv(1161, (500000).to_bytes(3, "big")))
    f = S.inspect_message(bgp.UPDATE,
                          ls_update(nlri_type=1,
                                    attr_tlvs=ls_tlv(S.LS_ATTR_SR_CAPS, rng)))
    hit = [x for x in f if x.code == "BGPLS-022"]
    assert hit and "20-bit" in hit[0].detail, codes(f)


@check("BGPLS-022: a sane SRGB (16000, 8000) is silent")
def t_srgb_ok():
    rng = (b"\x00\x00" + (8000).to_bytes(3, "big")
           + ls_tlv(1161, (16000).to_bytes(3, "big")))
    for tlv_t in (S.LS_ATTR_SR_CAPS, S.LS_ATTR_SRLB):
        f = S.inspect_message(bgp.UPDATE,
                              ls_update(nlri_type=1,
                                        attr_tlvs=ls_tlv(tlv_t, rng)))
        assert "BGPLS-022" not in codes(f), f"TLV {tlv_t}: {codes(f)}"


@check("BGP-LS VPN SAFI 72 route distinguisher is skipped correctly")
def t_ls_vpn():
    body = ls_nlri(1, with_local=True)
    # rebuild with an RD prepended, as SAFI 72 carries
    inner = bytes([2]) + struct.pack("!Q", 0) + node_desc()
    vpn = struct.pack("!HH", 1, 8 + len(inner)) + b"\x00" * 8 + inner
    got = S.parse_ls_nlri(vpn, safi=72)
    _eq(got[0].problems, [])
    _eq(got[0].local_as, 64500)


# --------------------------------------------------------------------------- #
# stateful: negotiation, eBGP posture, conflicts
# --------------------------------------------------------------------------- #
@check("SRTE-010: SR Policy NLRI on a session that never negotiated SAFI 73")
def t_sr_unnegotiated():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 1)], my_as=64512))
    f = tr.observe_update(flow, sr_update(1))
    assert "SRTE-010" in codes(f), codes(f)


@check("SRTE-010: silent when SAFI 73 was negotiated")
def t_sr_negotiated():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 73)], my_as=64512))
    f = tr.observe_update(flow, sr_update(1))
    assert "SRTE-010" not in codes(f), codes(f)


@check("BGPLS-010: BGP-LS NLRI on a session that never negotiated it")
def t_ls_unnegotiated():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 1)], my_as=64512))
    f = tr.observe_update(flow, ls_update(1))
    assert "BGPLS-010" in codes(f), codes(f)


@check("SRTE-011: SR Policy on an eBGP session (both OPENs seen)")
def t_sr_ebgp():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 73)], my_as=64512))
    tr.observe_open(flow, open_body([(1, 73)], my_as=64513))
    f = tr.observe_update(flow, sr_update(1))
    assert "SRTE-011" in codes(f), codes(f)


@check("SRTE-011: iBGP session (same AS both ends) is silent")
def t_sr_ibgp():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 73)], my_as=64512))
    tr.observe_open(flow, open_body([(1, 73)], my_as=64512))
    f = tr.observe_update(flow, sr_update(1))
    assert "SRTE-011" not in codes(f), codes(f)


@check("SRTE-011: undetermined with only one OPEN seen -- no guess")
def t_sr_one_open():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 73)], my_as=64512))
    f = tr.observe_update(flow, sr_update(1))
    assert "SRTE-011" not in codes(f), "must not assume eBGP from one OPEN"


@check("SRTE-012: conflicting segment lists for the same colour+endpoint")
def t_sr_conflict():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 73)], my_as=64512))
    tr.observe_update(flow, sr_update(1, segs=seg_a(16001)))
    f = tr.observe_update(flow, sr_update(1, segs=seg_a(16999)))
    assert "SRTE-012" in codes(f), codes(f)


@check("SRTE-012: re-advertising the same segment list is silent")
def t_sr_no_conflict():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 73)], my_as=64512))
    tr.observe_update(flow, sr_update(1, segs=seg_a(16001)))
    f = tr.observe_update(flow, sr_update(1, segs=seg_a(16001)))
    assert "SRTE-012" not in codes(f), codes(f)


@check("SRTE-012: reported once, not on every repeat")
def t_sr_conflict_once():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(1, 73)], my_as=64512))
    tr.observe_update(flow, sr_update(1, segs=seg_a(16001)))
    first = tr.observe_update(flow, sr_update(1, segs=seg_a(16999)))
    second = tr.observe_update(flow, sr_update(1, segs=seg_a(17777)))
    assert "SRTE-012" in codes(first)
    assert "SRTE-012" not in codes(second), "must not re-alert every update"


@check("BGPLS-011: node descriptor claims an AS unrelated to the eBGP session")
def t_ls_as_mismatch():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(S.AFI_BGP_LS, 71)], my_as=64512))
    tr.observe_open(flow, open_body([(S.AFI_BGP_LS, 71)], my_as=64513))
    f = tr.observe_update(flow, ls_update(1, as_num=65999))
    assert "BGPLS-011" in codes(f), codes(f)


@check("BGPLS-011: an AS matching a session endpoint is silent")
def t_ls_as_ok():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(S.AFI_BGP_LS, 71)], my_as=64512))
    tr.observe_open(flow, open_body([(S.AFI_BGP_LS, 71)], my_as=64513))
    f = tr.observe_update(flow, ls_update(1, as_num=64513))
    assert "BGPLS-011" not in codes(f), codes(f)


@check("BGPLS-012: same IGP Router-ID advertised under two different ASes")
def t_ls_node_conflict():
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_body([(S.AFI_BGP_LS, 71)], my_as=64512))
    rid = b"\x0a\x0b\x0c\x0d"
    tr.observe_update(flow, ls_update(1, as_num=64512, router_id=rid))
    f = tr.observe_update(flow, ls_update(1, as_num=64599, router_id=rid))
    assert "BGPLS-012" in codes(f), codes(f)


@check("tracker: sessions isolated per flow")
def t_flow_isolation():
    tr = S.SrteTracker()
    a = ("10.0.0.1", 50000, "10.0.0.2", 179)
    b = ("10.0.0.3", 50001, "10.0.0.4", 179)
    tr.observe_open(a, open_body([(1, 1)], my_as=64512))
    # b has no OPEN, so no negotiated set -- must not inherit a's
    assert "SRTE-010" not in codes(tr.observe_update(b, sr_update(1)))
    assert "SRTE-010" in codes(tr.observe_update(a, sr_update(1)))


# --------------------------------------------------------------------------- #
# robustness
# --------------------------------------------------------------------------- #
@check("never raises on fuzzed UPDATE bodies")
def t_fuzz():
    import random
    rnd = random.Random(90210)
    for _ in range(700):
        body = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 120)))
        for mt in (bgp.UPDATE, bgp.OPEN, bgp.KEEPALIVE):
            S.inspect_message(mt, body)


@check("never raises on fuzzed NLRI and segment payloads")
def t_fuzz_payloads():
    import random
    rnd = random.Random(1234)
    for _ in range(700):
        blob = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 80)))
        S.parse_sr_policy_nlri(blob, 1)
        S.parse_sr_policy_nlri(blob, 2)
        S.parse_ls_nlri(blob)
        S.parse_ls_nlri(blob, safi=72)
        S.parse_segment_list(blob)
        S.parse_sr_policy_tunnel(blob)
        S._check_sr_range(blob)


@check("tracker never raises on fuzzed traffic")
def t_fuzz_tracker():
    import random
    rnd = random.Random(555)
    tr = S.SrteTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    for _ in range(300):
        blob = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 70)))
        tr.observe_open(flow, blob)
        tr.observe_update(flow, blob)


@check("passive boundary: module performs no I/O")
def t_passive():
    src = open("bgpsrte.py").read()
    for mod in ("requests", "urllib", "http.client", "subprocess"):
        assert f"\nimport {mod}" not in src, f"must not import {mod}"
    # socket is imported for inet_ntop address formatting only -- never bound
    for banned in ("socket.socket(", ".connect(", ".sendto(", ".bind("):
        assert banned not in src, f"must not call {banned}"


@check("clean non-SR/non-LS UPDATE is silent")
def t_clean_ordinary():
    _eq(S.inspect_message(bgp.UPDATE, T.clean_update()), [])
    _eq(S.inspect_message(bgp.UPDATE, T.update_body()), [])


# --------------------------------------------------------------------------- #
# dual-stack parity
# --------------------------------------------------------------------------- #
@check("PARITY: SR Policy structural detectors fire for AFI 1 and AFI 2 alike")
def t_parity_sr_afi():
    cases = {
        "SRTE-020": dict(segs=b""),
        "SRTE-022": dict(segs=seg_raw(S.SEG_TYPE_DEPRECATED)),
        "SRTE-023": dict(segs=seg_raw(99)),
        "SRTE-024": dict(segs=seg_a(label=3)),
        "SRTE-025": dict(segs=bytes([S.SEG_TYPE_B, 10]) + b"\x00" * 10),
        "SRTE-027": dict(segs=seg_a() * 60),
    }
    for code, kw in cases.items():
        for afi in (1, 2):
            f = [x for x in S.inspect_message(bgp.UPDATE, sr_update(afi, **kw))
                 if x.code == code]
            assert f, f"{code} did not fire for AFI {afi}"
            _eq(f[0].afi, afi, f"{code} AFI stamp:")


@check("PARITY: segment Type A and Type B both decode and both validate")
def t_parity_segment_types():
    # clean cases silent for both
    for segs in (seg_a(16001), seg_b("2001:db8::7")):
        for afi in (1, 2):
            f = S.inspect_message(bgp.UPDATE, sr_update(afi, segs=segs))
            _eq(codes(f), ["SRTE-001"], f"AFI {afi}:")
    # malformed cases flagged for both, each under its own code
    bad_a = bytes([S.SEG_TYPE_A, 4]) + b"\x00" * 4
    bad_b = bytes([S.SEG_TYPE_B, 10]) + b"\x00" * 10
    assert "SRTE-024" in codes(S.inspect_message(bgp.UPDATE,
                                                 sr_update(1, segs=bad_a)))
    assert "SRTE-025" in codes(S.inspect_message(bgp.UPDATE,
                                                 sr_update(1, segs=bad_b)))


@check("PARITY: BGP-LS v4 and v6 prefix NLRI and descriptors both clean")
def t_parity_ls():
    v4 = ls_tlv(S.LS_TLV_IP_REACH, bytes([24]) + b"\xcb\x00\x71")
    v6 = ls_tlv(S.LS_TLV_IP_REACH,
                bytes([48]) + b"\x20\x01\x0d\xb8\xab\xcd")
    for t, desc in ((S.LS_NLRI_PREFIX_V4, v4), (S.LS_NLRI_PREFIX_V6, v6)):
        f = S.inspect_message(bgp.UPDATE,
                              ls_update(nlri_type=t, descriptors=desc))
        _eq(codes(f), ["BGPLS-001"], f"NLRI type {t}:")


@check("PARITY: identical findings over v4, v6 and v6+EH transport")
def t_parity_transport():
    body = sr_update(2, segs=seg_raw(S.SEG_TYPE_DEPRECATED))
    results = {}
    for name, fam, eh in (("v4", 4, ()),
                          ("v6", 6, ()),
                          ("v6+hbh", 6, [(0, b"")]),
                          ("v6+hbh+dst", 6, [(0, b""), (60, b"")]),
                          ("v6+rt+ah", 6, [(43, b""), (51, b"\x00" * 12)])):
        f = tap_once(bgp.UPDATE, body, fam=fam, eh=eh)
        results[name] = codes(f)
        assert all(x.family == fam for x in f), f"{name}: family not stamped"
        assert all(x.afi == 2 for x in f), f"{name}: AFI not stamped"
    base = results["v4"]
    assert "SRTE-022" in base, base
    for name, got in results.items():
        _eq(got, base, f"parity break on {name}:")


@check("PARITY: BGP-LS findings identical over both transports")
def t_parity_ls_transport():
    body = ls_update(nlri_type=9)
    out = {}
    for fam, eh in ((4, ()), (6, [(0, b"")])):
        f = tap_once(bgp.UPDATE, body, fam=fam, eh=eh)
        out[fam] = codes(f)
        assert all(x.family == fam for x in f)
    _eq(out[4], out[6])
    assert "BGPLS-002" in out[4]


@check("PARITY: stateful detection works identically over both transports")
def t_parity_stateful():
    for fam in (4, 6):
        tr = S.SrteTracker()
        tap_once(bgp.OPEN, open_body([(1, 1)], my_as=64512), fam=fam,
                 tracker=tr, sport=50000 + fam)
        f = tap_once(bgp.UPDATE, sr_update(1), fam=fam, tracker=tr,
                     sport=50000 + fam)
        assert "SRTE-010" in codes(f), f"fam v{fam}: {codes(f)}"
        assert all(x.family == fam for x in f)


@check("registry: 23 codes, none carrying a CVE identifier")
def t_registry():
    _eq(len(S.REGISTRY), 23)
    seen = set()
    for body in (sr_update(1, segs=seg_raw(99)), ls_update(nlri_type=9)):
        for f in S.inspect_message(bgp.UPDATE, body):
            seen.add(f.code)
            _eq(f.cves, ())
            _eq(f.cvss, 0.0)
            assert "no CVE" in f.note
    assert seen, "expected findings to check"


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
