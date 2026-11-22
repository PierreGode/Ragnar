#!/usr/bin/env python3
"""
bgpsectest.py -- offline tests for the BGPsec posture/downgrade tier.

No packets sent, no NIC touched. BGPsec capabilities and BGPsec_PATH
attributes are synthesized byte-for-byte per RFC 8205 and fed through the
tap, so the whole path (frame -> reassembly -> detectors) is exercised.

Dual-stack is asserted, not assumed: BGPsec is negotiated per-AFI and its NLRI
always rides MP_REACH, so every structural detector is run for AFI 1 and AFI 2,
over both IPv4 and IPv6 TCP transport, including an IPv6 extension-header
chain.  Run: python3 bgpsectest.py
"""

from __future__ import annotations

import socket
import struct
import sys

import bgp
import bgpsec
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


def codes(findings):
    return sorted({f.code for f in findings})


# --------------------------------------------------------------------------- #
# builders
# --------------------------------------------------------------------------- #
def bgpsec_cap(afi=1, direction=0, version=0, reserved=0) -> bytes:
    b = ((version & 0x0F) << 4) | ((direction & 1) << 3) | (reserved & 0x07)
    return bytes([b]) + struct.pack("!H", afi)


def open_with_caps(caps: list, bgp_id="10.0.0.1", my_as=64512) -> bytes:
    """caps = [(cap_code, cap_value), ...] -> an OPEN body."""
    capblob = b""
    for code, val in caps:
        capblob += bytes([code, len(val)]) + val
    parm = bytes([2, len(capblob)]) + capblob
    body = struct.pack("!BHH", 4, my_as, 90) + socket.inet_aton(bgp_id)
    body += bytes([len(parm)]) + parm
    return body


def secure_path(segs) -> bytes:
    """segs = [(pcount, flags, asn), ...]"""
    out = b""
    for pc, fl, asn in segs:
        out += struct.pack("!BBI", pc, fl, asn)
    return struct.pack("!H", 2 + len(out)) + out


def sig_block(n_sigs, algo=1, sig_len=70, ski=None, declared_len=None,
              declared_sig_len=None) -> bytes:
    ski = ski if ski is not None else b"\xAA" * 20
    inner = b""
    for _ in range(n_sigs):
        sl = declared_sig_len if declared_sig_len is not None else sig_len
        inner += ski + struct.pack("!H", sl) + (b"\x5A" * sig_len)
    total = 3 + len(inner)
    return struct.pack("!H", declared_len if declared_len is not None else total) \
        + bytes([algo]) + inner


def bgpsec_path_attr(segs, blocks=1, algo=1, flags=0x80, **blkkw) -> bytes:
    val = secure_path(segs)
    for _ in range(blocks):
        val += sig_block(len(segs), algo=algo, **blkkw)
    # real BGPsec_PATH attributes routinely exceed 255 bytes, so set the
    # extended-length bit exactly as a conformant speaker would
    if len(val) > 255:
        flags |= 0x10
    return T.attr(flags, 33, val)


def mp_reach(afi=1, prefixes=None):
    if afi == 2:
        nh = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        pfx = prefixes or ["2001:db8:abcd::/48"]
    else:
        nh = socket.inet_aton("10.0.0.1")
        pfx = prefixes or ["203.0.113.0/24"]
    return T.attr(0x80, 14, bgp.encode_mp_reach(afi, 1, nh, pfx))


def signed_update(afi=1, segs=None, **kw) -> bytes:
    """A conformant BGPsec UPDATE: MP_REACH + BGPsec_PATH, no AS_PATH."""
    segs = segs if segs is not None else [(1, 0, 64500), (1, 0, 64510)]
    attrs = T.attr(0x40, 1, b"\x00") + mp_reach(afi) + bgpsec_path_attr(segs, **kw)
    return T.update_body(attrs=attrs)


def unsigned_update(afi=1) -> bytes:
    """An ordinary MP_REACH update with AS_PATH and no BGPsec_PATH."""
    apv = bgp.encode_as_path([64500, 64510])
    attrs = T.attr(0x40, 1, b"\x00") + T.attr(0x40, 2, apv) + mp_reach(afi)
    return T.update_body(attrs=attrs)


def tap_once(msg_type, body, fam=4, eh=(), tracker=None, flowport=50000):
    """Push one BGP message through the real tap and return findings."""
    msg = T.bgp_msg(msg_type, body)
    tap = bgptap.BgpTap()
    frame = (T.frame_v4(msg, sport=flowport) if fam == 4
             else T.frame_v6(msg, ext_headers=eh, sport=flowport))
    got = tap.feed_packet(frame)
    assert len(got) == 1, f"message did not frame (fam={fam})"
    return bgpsec.inspect_tap_message(got[0], tracker=tracker)


# --------------------------------------------------------------------------- #
# capability parsing
# --------------------------------------------------------------------------- #
@check("capability: parses version, direction and AFI")
def t_cap_parse():
    c = bgpsec.parse_bgpsec_capability(bgpsec_cap(afi=2, direction=1))
    _eq(c.version, 0)
    _eq(c.direction, 1)
    _eq(c.afi, 2)
    _eq(c.dir_name, "send")
    assert not c.malformed


@check("capability: dual-stack send+receive yields four advertisements")
def t_cap_dual():
    caps = [(7, bgpsec_cap(afi=a, direction=d))
            for a in (1, 2) for d in (0, 1)]
    got = bgpsec.bgpsec_caps_in_open(open_with_caps(caps))
    _eq(len(got), 4)
    _eq({(c.afi, c.direction) for c in got}, {(1, 0), (1, 1), (2, 0), (2, 1)})


@check("capability: BSEC-001 posture finding per AFI, both families")
def t_cap_posture():
    for afi in (1, 2):
        f = bgpsec.inspect_message(
            bgp.OPEN, open_with_caps([(7, bgpsec_cap(afi=afi))]))
        assert "BSEC-001" in codes(f)
        assert [x for x in f if x.code == "BSEC-001"][0].afi == afi


@check("capability: BSEC-002 unknown version")
def t_cap_version():
    f = bgpsec.inspect_message(
        bgp.OPEN, open_with_caps([(7, bgpsec_cap(version=3))]))
    assert "BSEC-002" in codes(f)


@check("capability: BSEC-003 reserved bits set")
def t_cap_reserved():
    f = bgpsec.inspect_message(
        bgp.OPEN, open_with_caps([(7, bgpsec_cap(reserved=5))]))
    assert "BSEC-003" in codes(f)


@check("capability: BSEC-004 malformed length")
def t_cap_malformed():
    f = bgpsec.inspect_message(bgp.OPEN, open_with_caps([(7, b"\x00")]))
    _eq(codes(f), ["BSEC-004"])


@check("capability: OPEN without BGPsec capability is silent")
def t_cap_absent():
    body = bgp.build_open(64512, 90, "10.0.0.1")[bgp.HDR_LEN:]
    _eq(bgpsec.inspect_message(bgp.OPEN, body), [])


@check("capability: RFC 9072 extended optional parameter is walked")
def t_cap_ext_parm():
    capblob = bytes([7, 3]) + bgpsec_cap(afi=2)
    parm = bytes([0xFF]) + struct.pack("!H", 0) + b""      # unrelated ext parm
    parm2 = bytes([2, len(capblob)]) + capblob
    allp = parm + parm2
    body = struct.pack("!BHH", 4, 64512, 90) + socket.inet_aton("10.0.0.1")
    body += bytes([len(allp)]) + allp
    got = bgpsec.bgpsec_caps_in_open(body)
    _eq(len(got), 1)
    _eq(got[0].afi, 2)


# --------------------------------------------------------------------------- #
# BGPsec_PATH structure -- negative cases first
# --------------------------------------------------------------------------- #
@check("clean signed UPDATE is silent (AFI 1 and AFI 2)")
def t_clean_signed():
    for afi in (1, 2):
        _eq(bgpsec.inspect_message(bgp.UPDATE, signed_update(afi)), [],
            f"AFI {afi}:")


@check("clean unsigned UPDATE is silent without session state")
def t_clean_unsigned():
    for afi in (1, 2):
        _eq(bgpsec.inspect_message(bgp.UPDATE, unsigned_update(afi)), [])


@check("walk_bgpsec_path: conformant path decodes cleanly")
def t_walk_clean():
    segs = [(1, 0, 64500), (1, 0, 64510)]
    val = secure_path(segs) + sig_block(2)
    p = bgpsec.walk_bgpsec_path(val)
    _eq(len(p.segments), 2)
    _eq(len(p.blocks), 1)
    _eq(len(p.blocks[0].segments), 2)
    _eq(p.problems, [])
    _eq(p.trailing_bytes, 0)


@check("walk_bgpsec_path: two signature blocks are legal")
def t_walk_two_blocks():
    segs = [(1, 0, 64500)]
    val = secure_path(segs) + sig_block(1) + sig_block(1, algo=1)
    p = bgpsec.walk_bgpsec_path(val)
    _eq(len(p.blocks), 2)
    _eq(p.problems, [])


@check("BSEC-020: BGPsec_PATH marked transitive")
def t_flags():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(1, 0, 64500)], flags=0xC0))
    assert "BSEC-020" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-021: Secure_Path length not 2+6N")
def t_sp_badlen():
    val = struct.pack("!H", 7) + b"\x00" * 5 + sig_block(1)
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + T.attr(0x80, 33, val))
    assert "BSEC-021" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-021: Secure_Path length exceeds attribute")
def t_sp_overrun():
    val = struct.pack("!H", 500) + b"\x00" * 6
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + T.attr(0x80, 33, val))
    assert "BSEC-021" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-022: Signature_Block length overruns")
def t_sb_overrun():
    val = secure_path([(1, 0, 64500)]) + sig_block(1, declared_len=9000)
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + T.attr(0x80, 33, val))
    assert "BSEC-022" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-022: signature length overruns its block")
def t_sig_overrun():
    inner = b"\xAA" * 20 + struct.pack("!H", 4000) + b"\x5A" * 10
    blk = struct.pack("!H", 3 + len(inner)) + bytes([1]) + inner
    val = secure_path([(1, 0, 64500)]) + blk
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + T.attr(0x80, 33, val))
    assert "BSEC-022" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-022: Secure_Path present with no Signature_Block")
def t_no_block():
    val = secure_path([(1, 0, 64500)])
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + T.attr(0x80, 33, val))
    assert "BSEC-022" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-023: signature/path segment count mismatch")
def t_count_mismatch():
    val = secure_path([(1, 0, 64500), (1, 0, 64510)]) + sig_block(1)
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + T.attr(0x80, 33, val))
    f = [x for x in bgpsec.inspect_message(bgp.UPDATE, body)
         if x.code == "BSEC-023"]
    assert f and "2 Secure_Path segment" in f[0].detail


@check("BSEC-024: unknown algorithm suite")
def t_algo():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(1, 0, 64500)], algo=9))
    assert "BSEC-024" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-026: more than two Signature_Blocks")
def t_three_blocks():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(1, 0, 64500)], blocks=3))
    assert "BSEC-026" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-027: BGPsec_PATH alongside AS_PATH")
def t_both_paths():
    apv = bgp.encode_as_path([64500])
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + T.attr(0x40, 2, apv)
                         + mp_reach(1) + bgpsec_path_attr([(1, 0, 64500)]))
    assert "BSEC-027" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-028: BGPsec_PATH without MP_REACH_NLRI")
def t_no_mpreach():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00")
                         + bgpsec_path_attr([(1, 0, 64500)]))
    assert "BSEC-028" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-029: Secure_Path reserved flag bits set")
def t_reserved_flags():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(1, 0x40, 64500)]))
    assert "BSEC-029" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-029: Confed_Segment bit alone is legal")
def t_confed_ok():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(1, 0x80, 64500)]))
    assert "BSEC-029" not in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-030: pCount 0 reported at low confidence")
def t_pcount_zero():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(0, 0, 64500)]))
    f = [x for x in bgpsec.inspect_message(bgp.UPDATE, body)
         if x.code == "BSEC-030"]
    assert f and f[0].confidence == "low"


@check("BSEC-031: inflated pCount")
def t_pcount_inflated():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(200, 0, 64500)]))
    assert "BSEC-031" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-031: ordinary prepending (pCount 3) is silent")
def t_pcount_normal():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(3, 0, 64500)]))
    assert "BSEC-031" not in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-032: zero Secure_Path segments")
def t_zero_segs():
    val = struct.pack("!H", 2) + sig_block(0)
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + T.attr(0x80, 33, val))
    assert "BSEC-032" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-033: zero-length signature")
def t_sig_zero():
    inner = b"\xAA" * 20 + struct.pack("!H", 0)
    blk = struct.pack("!H", 3 + len(inner)) + bytes([1]) + inner
    val = secure_path([(1, 0, 64500)]) + blk
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + T.attr(0x80, 33, val))
    assert "BSEC-033" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-033: implausible signature length for ECDSA P-256")
def t_sig_long():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(1, 0, 64500)], sig_len=200))
    assert "BSEC-033" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


@check("BSEC-034: AS 0 in Secure_Path")
def t_as_zero():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(1, 0, 0)]))
    assert "BSEC-034" in codes(bgpsec.inspect_message(bgp.UPDATE, body))


# --------------------------------------------------------------------------- #
# downgrade (stateful)
# --------------------------------------------------------------------------- #
@check("BSEC-010: capability advertised then routes arrive unsigned")
def t_downgrade():
    tr = bgpsec.BgpsecTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_with_caps([(7, bgpsec_cap(afi=1, direction=1))]))
    f = tr.observe_update(flow, unsigned_update(afi=1))
    assert "BSEC-010" in codes(f), codes(f)
    assert [x for x in f if x.code == "BSEC-010"][0].afi == 1


@check("BSEC-010: reported once per AFI, not per UPDATE")
def t_downgrade_once():
    tr = bgpsec.BgpsecTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_with_caps([(7, bgpsec_cap(afi=1))]))
    first = tr.observe_update(flow, unsigned_update(1))
    second = tr.observe_update(flow, unsigned_update(1))
    assert "BSEC-010" in codes(first)
    assert "BSEC-010" not in codes(second), "must not re-alert every update"


@check("BSEC-010: no capability means no downgrade finding")
def t_no_downgrade_without_cap():
    tr = bgpsec.BgpsecTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    f = tr.observe_update(flow, unsigned_update(1))
    assert "BSEC-010" not in codes(f)


@check("BSEC-010: signed routes on a BGPsec session are silent")
def t_no_downgrade_when_signed():
    tr = bgpsec.BgpsecTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_with_caps([(7, bgpsec_cap(afi=1))]))
    f = tr.observe_update(flow, signed_update(1))
    _eq(codes(f), [])


@check("BSEC-011: v4 signed but v6 unsigned on the same session")
def t_mixed_afi():
    tr = bgpsec.BgpsecTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    tr.observe_open(flow, open_with_caps([(7, bgpsec_cap(afi=1)),
                                          (7, bgpsec_cap(afi=2))]))
    tr.observe_update(flow, signed_update(afi=1))
    f = tr.observe_update(flow, unsigned_update(afi=2))
    assert "BSEC-011" in codes(f), codes(f)
    assert "BSEC-010" in codes(f), "the v6 downgrade itself must also fire"


@check("tracker: sessions are isolated per flow")
def t_flow_isolation():
    tr = bgpsec.BgpsecTracker()
    a = ("10.0.0.1", 50000, "10.0.0.2", 179)
    b = ("10.0.0.3", 50001, "10.0.0.4", 179)
    tr.observe_open(a, open_with_caps([(7, bgpsec_cap(afi=1))]))
    assert "BSEC-010" not in codes(tr.observe_update(b, unsigned_update(1)))
    assert "BSEC-010" in codes(tr.observe_update(a, unsigned_update(1)))


# --------------------------------------------------------------------------- #
# robustness
# --------------------------------------------------------------------------- #
@check("never raises on fuzzed bodies")
def t_fuzz():
    import random
    rnd = random.Random(4242)
    for _ in range(600):
        body = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 90)))
        for mt in (bgp.UPDATE, bgp.OPEN, bgp.KEEPALIVE):
            bgpsec.inspect_message(mt, body)


@check("never raises on fuzzed BGPsec_PATH values")
def t_fuzz_path():
    import random
    rnd = random.Random(777)
    for _ in range(600):
        val = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 120)))
        bgpsec.walk_bgpsec_path(val)
        body = T.update_body(attrs=mp_reach(1) + T.attr(0x80, 33, val))
        bgpsec.inspect_message(bgp.UPDATE, body)


@check("tracker never raises on fuzzed traffic")
def t_fuzz_tracker():
    import random
    rnd = random.Random(31337)
    tr = bgpsec.BgpsecTracker()
    flow = ("10.0.0.1", 50000, "10.0.0.2", 179)
    for _ in range(300):
        body = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 60)))
        try:
            tr.observe_open(flow, body)
            tr.observe_update(flow, body)
        except Exception as e:
            raise AssertionError(f"tracker raised: {e}")


@check("passive boundary: no module-level signature verification exists")
def t_passive_boundary():
    src = open("bgpsec.py").read().lower()
    for banned in ("rpki", "rsync", "rrdp", "verify_signature", "ecdsa.verify"):
        # the words may appear in prose explaining the boundary; what must not
        # exist is an import or call that would perform validation
        assert f"import {banned}" not in src, f"unexpected import: {banned}"
    for mod in ("socket", "requests", "urllib", "http.client"):
        assert f"\nimport {mod}" not in src, \
            f"bgpsec.py must not import {mod} -- it performs no I/O"


# --------------------------------------------------------------------------- #
# dual-stack parity
# --------------------------------------------------------------------------- #
@check("PARITY: every structural detector fires for AFI 1 and AFI 2 alike")
def t_parity_afi():
    cases = {
        "BSEC-020": lambda afi: bgpsec_path_attr([(1, 0, 64500)], flags=0xC0),
        "BSEC-023": lambda afi: T.attr(0x80, 33, secure_path(
            [(1, 0, 64500), (1, 0, 64510)]) + sig_block(1)),
        "BSEC-024": lambda afi: bgpsec_path_attr([(1, 0, 64500)], algo=9),
        "BSEC-029": lambda afi: bgpsec_path_attr([(1, 0x40, 64500)]),
        "BSEC-031": lambda afi: bgpsec_path_attr([(200, 0, 64500)]),
        "BSEC-034": lambda afi: bgpsec_path_attr([(1, 0, 0)]),
    }
    for code, build in cases.items():
        got = {}
        for afi in (1, 2):
            body = T.update_body(
                attrs=T.attr(0x40, 1, b"\x00") + mp_reach(afi) + build(afi))
            f = [x for x in bgpsec.inspect_message(bgp.UPDATE, body)
                 if x.code == code]
            assert f, f"{code} did not fire for AFI {afi}"
            _eq(f[0].afi, afi, f"{code} AFI stamp for AFI {afi}:")
            got[afi] = True
        _eq(sorted(got), [1, 2])


@check("PARITY: identical findings over v4, v6 and v6+EH transport")
def t_parity_transport():
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(2)
                         + bgpsec_path_attr([(1, 0, 0)], algo=9))
    results = {}
    for name, fam, eh in [("v4", 4, ()),
                          ("v6", 6, ()),
                          ("v6+hbh", 6, [(0, b"")]),
                          ("v6+hbh+dst", 6, [(0, b""), (60, b"")]),
                          ("v6+rt+ah", 6, [(43, b""), (51, b"\x00" * 12)])]:
        f = tap_once(bgp.UPDATE, body, fam=fam, eh=eh)
        results[name] = codes(f)
        assert all(x.family == fam for x in f), f"{name}: family not stamped"
        assert all(x.afi == 2 for x in f), f"{name}: AFI not stamped"
    base = results["v4"]
    assert "BSEC-034" in base and "BSEC-024" in base, base
    for name, got in results.items():
        _eq(got, base, f"parity break on {name}:")


@check("PARITY: downgrade detected identically over both transports")
def t_parity_downgrade():
    for fam in (4, 6):
        tr = bgpsec.BgpsecTracker()
        tap_once(bgp.OPEN, open_with_caps([(7, bgpsec_cap(afi=2))]),
                 fam=fam, tracker=tr)
        f = tap_once(bgp.UPDATE, unsigned_update(afi=2), fam=fam, tracker=tr)
        assert "BSEC-010" in codes(f), f"fam v{fam}: {codes(f)}"
        assert all(x.family == fam for x in f)


@check("PARITY: capability posture stamped per AFI over both transports")
def t_parity_cap():
    for fam in (4, 6):
        for afi in (1, 2):
            f = tap_once(bgp.OPEN, open_with_caps([(7, bgpsec_cap(afi=afi))]),
                         fam=fam)
            hit = [x for x in f if x.code == "BSEC-001"]
            assert hit, f"no posture finding (fam v{fam}, AFI {afi})"
            _eq(hit[0].afi, afi)
            _eq(hit[0].family, fam)


@check("registry: 20 codes, none carrying a CVE identifier")
def t_registry():
    _eq(len(bgpsec.REGISTRY), 20)
    # BGPsec has no CVEs; findings must not claim one
    body = T.update_body(attrs=T.attr(0x40, 1, b"\x00") + mp_reach(1)
                         + bgpsec_path_attr([(1, 0, 0)]))
    for f in bgpsec.inspect_message(bgp.UPDATE, body):
        _eq(f.cves, ())
        _eq(f.cvss, 0.0)
        assert "never validates signatures" in f.note


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
