#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pimwatch self-test tier.

Every scenario feeds raw frame bytes through handle_frame(), which is the
same entry point the live capture callback uses, so each fixture crosses the
bytes->parse boundary real traffic crosses.

The tier ends with four structural gates:
  * clean-set      -- benign traffic raises no attack-class finding
  * non-vacuity    -- every declared code is either exercised or explicitly
                      listed as not exercised here, with a reason
  * AST transmit   -- the module contains no send path of any kind
  * AST shadowing  -- no module-level name is defined twice
"""

import ast
import os
import sys

import pimwatch as P
import pimwatch_fixtures as F

CHECKS = []


def ck(cond, label, extra=""):
    CHECKS.append((bool(cond), label, extra))
    return bool(cond)


def W(armed=True, **cfg):
    clock = {"t": 1000.0}
    w = P.PimWatch(config=cfg, now=lambda: clock["t"], armed=armed)
    w._clock_dict = clock
    return w


def feed(w, frames, t0=1000.0, step=0.01):
    t = t0
    for f in frames:
        w.handle_frame(f, ts=t)
        t += step
    return w


def codes(w):
    return {f["code"] for f in w.findings}


def detail_for(w, code):
    for f in w.findings:
        if f["code"] == code:
            return f["detail"]
    return {}


ALL_FIRED = set()


def record(w):
    ALL_FIRED.update(codes(w))
    return w


# --------------------------------------------------------------------------
# Baseline helpers
# --------------------------------------------------------------------------

NB1 = "10.0.0.1"
NB2 = "10.0.0.2"
NB3 = "10.0.0.3"
RP1 = "10.9.9.1"
RP2 = "10.9.9.2"
BSR1 = "10.8.8.1"
BSR2 = "10.8.8.2"
G1 = "239.1.1.1"
SRC1 = "192.0.2.10"
SSM_G = "232.1.1.1"
NB6_1 = "fe80::1"
NB6_2 = "fe80::2"
RP6 = "2001:db8:9::1"


def learn_neighbors(w, addrs=(NB1, NB2), af=4, t0=1000.0):
    frames = []
    for i, a in enumerate(addrs):
        mac = "02:00:00:00:00:%02x" % (i + 1)
        if af == 4:
            frames.append(F.pim4(P.PIM_HELLO, F.hello_body(dr_priority=1 + i),
                                 a, smac=mac))
        else:
            frames.append(F.pim6(P.PIM_HELLO, F.hello_body(dr_priority=1 + i),
                                 a, smac=mac))
    return feed(w, frames, t0=t0)


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

def s_hello_basics():
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1)])
    ck("PMW-001" in codes(w), "hello: neighbour learned during learning window")
    ck("PMW-040" not in codes(w), "hello: no rogue-neighbour code while learning")
    record(w)

    w = W(armed=True)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1)])
    ck("PMW-040" in codes(w), "hello: new neighbour after arming is PMW-040")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(omit_holdtime=True), NB1)])
    ck("PMW-006" in codes(w), "hello: missing holdtime option")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(holdtime=0), NB1)])
    ck("PMW-044" in codes(w), "hello: zero holdtime is a goodbye")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(holdtime=2), NB1)])
    ck("PMW-050" in codes(w), "hello: flap-inducing holdtime")
    ck("PMW-044" not in codes(w), "hello: holdtime 2 is not a goodbye")
    record(w)

    # Generation ID churn only matters once armed.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(gen_id=1), NB1),
             F.pim4(P.PIM_HELLO, F.hello_body(gen_id=2), NB1)])
    ck("PMW-041" not in codes(w), "hello: genid change ignored while learning")
    w = W(armed=True)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(gen_id=1), NB1),
             F.pim4(P.PIM_HELLO, F.hello_body(gen_id=2), NB1)])
    ck("PMW-041" in codes(w), "hello: genid change after arming")
    record(w)

    # Two MACs claiming one router address.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1, smac="02:00:00:00:00:aa"),
             F.pim4(P.PIM_HELLO, F.hello_body(), NB1, smac="02:00:00:00:00:bb")])
    ck("PMW-047" in codes(w), "hello: one neighbour address from two MACs")
    record(w)

    # T-bit / LAN prune delay change, state-refresh and bidir advertisements.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(lan_prune_delay=500, t_bit=False), NB1),
             F.pim4(P.PIM_HELLO, F.hello_body(lan_prune_delay=500, t_bit=True), NB1),
             F.pim4(P.PIM_HELLO, F.hello_body(state_refresh=60), NB2),
             F.pim4(P.PIM_HELLO, F.hello_body(bidir=True), NB3)])
    ck("PMW-046" in codes(w), "hello: T-bit change")
    ck("PMW-049" in codes(w), "hello: state-refresh-capable advertised")
    ck("PMW-048" in codes(w), "hello: bidir-capable advertised")
    record(w)

    # Bidir from a neighbour that appears after arming is PMW-145.
    w = W(armed=True)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(bidir=True), NB3)])
    ck("PMW-145" in codes(w), "hello: bidir-capable from a post-arming neighbour")
    record(w)

    # Hello flood.
    w = W(armed=True, hello_rate_max=3, hello_rate_window=10.0)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1) for _ in range(6)])
    ck("PMW-045" in codes(w), "hello: rate anomaly")
    ck(P.DEFAULTS["hello_rate_max"] == 12,
       "hello: shipped rate ceiling constant is 12")
    record(w)


def s_dr_election():
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(dr_priority=250), NB1,
                    smac="02:00:00:00:00:01")], t0=1100.0)
    c = codes(w)
    ck("PMW-042" in c, "DR: priority escalation flagged")
    ck("PMW-043" in c, "DR: DR change flagged")
    d = detail_for(w, "PMW-043")
    ck(d.get("new_dr") == NB1 and d.get("old_dr") == NB2,
       "DR: change names the right incumbent and challenger", str(d))
    record(w)


def s_header_hygiene():
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1, bad_checksum=True)])
    ck("PMW-003" in codes(w), "header: bad checksum detected")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1)])
    ck("PMW-003" not in codes(w), "header: good checksum accepted (IPv4)")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1)])
    ck("PMW-003" not in codes(w),
       "header: good checksum accepted (IPv6 pseudo-header)")
    ck("PMW-001" in codes(w), "header: IPv6 neighbour learned")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1, bad_checksum=True)])
    ck("PMW-003" in codes(w), "header: bad IPv6 checksum detected")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1, version=1)])
    ck("PMW-002" in codes(w), "header: PIMv1 flagged and not parsed as v2")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(12, b"\x00" * 8, NB1)])
    ck("PMW-009" in codes(w), "header: unknown message type")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1, dst="239.9.9.9", ttl=9)])
    c = codes(w)
    ck("PMW-010" in c, "header: link-local message to the wrong group")
    ck("PMW-007" in c, "header: link-local message with TTL > 1")
    record(w)


def s_join_prune():
    # Unknown upstream after arming.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body("10.0.0.99", [(G1, [(SRC1, False, False)], [])]),
                    NB1)], t0=1100.0)
    ck("PMW-060" in codes(w), "J/P: upstream is not a learned neighbour")
    ck("PMW-005" in codes(w), "J/P: sparse mode recorded on the link")
    record(w)

    # Known upstream raises nothing.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]),
                    NB1)], t0=1100.0)
    ck("PMW-060" not in codes(w), "J/P: known upstream is clean")
    record(w)

    # Zero holdtime.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [], [(SRC1, False, False)])],
                                      holdtime=0), NB1)], t0=1100.0)
    ck("PMW-062" in codes(w), "J/P: zero holdtime")
    record(w)

    # SPT switchover and RPT prune.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [(RP1, True, True)], [])]), NB1),
             F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)],
                                             [(SRC1, False, True)])]), NB1)],
         t0=1100.0)
    c = codes(w)
    ck("PMW-063" in c, "J/P: SPT switchover observed")
    ck("PMW-064" in c, "J/P: (S,G,rpt) prune observed")
    record(w)

    # Prune rate.
    w = W(armed=False, prune_rate_max=3, prune_rate_window=10.0)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [], [(SRC1, False, False)])]),
                    NB1) for _ in range(6)], t0=1100.0)
    ck("PMW-061" in codes(w), "J/P: prune rate anomaly")
    record(w)

    # Prune from a non-neighbour after arming.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [], [(SRC1, False, False)])]),
                    "10.0.0.77")], t0=1100.0)
    ck("PMW-070" in codes(w), "J/P: prune from an unexpected sender")
    record(w)

    # State-growth guard, driven from a lowered ceiling.
    w = W(armed=False, jp_source_max=2)
    learn_neighbors(w, (NB1, NB2))
    srcs = [("192.0.2.%d" % i, False, False) for i in range(1, 6)]
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, srcs, [])]), NB1)], t0=1100.0)
    ck("PMW-066" in codes(w), "J/P: implausible source count")
    ck(P.DEFAULTS["jp_source_max"] == 1024 and P.DEFAULTS["jp_group_max"] == 512,
       "J/P: shipped state-growth ceilings are 1024 sources / 512 groups")
    record(w)

    # Group never seen during learning.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [("239.5.5.5", [(SRC1, False, False)], [])]),
                    NB1)], t0=1100.0)
    ck("PMW-065" in codes(w), "J/P: join for a group outside the baseline")
    record(w)


def s_rpf_vector():
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    attr = F.rpf_vector_attr(NB2)
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])],
                                      attributes=attr), NB1)], t0=1100.0)
    c = codes(w)
    ck("PMW-067" in c, "RPF vector: attribute parsed")
    ck("PMW-068" not in c, "RPF vector: a known neighbour is not flagged")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    attr = F.rpf_vector_attr("203.0.113.9")
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])],
                                      attributes=attr), NB1)], t0=1100.0)
    ck("PMW-068" in codes(w), "RPF vector: off-fabric vector flagged")
    record(w)

    # Malformed attribute value.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    bad = F.jp_attribute(0, b"\x09\x00\x01")
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])],
                                      attributes=bad), NB1)], t0=1100.0)
    ck("PMW-004" in codes(w), "RPF vector: malformed attribute reported")
    record(w)


def s_assert():
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_ASSERT, F.assert_body(G1, SRC1), NB1)], t0=1100.0)
    ck("PMW-080" in codes(w), "assert: observed")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_ASSERT, F.assert_body(G1, SRC1, metric_pref=0,
                                                metric=0), NB1)], t0=1100.0)
    ck("PMW-082" in codes(w), "assert: zero metric flagged")
    record(w)

    # The R bit is the top bit of the metric-preference word and must be
    # masked out of the value. Without a fixture that sets it, a parser that
    # forgets the mask reads identically (suite LESSON X).
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_ASSERT,
                    F.assert_body(G1, SRC1, metric_pref=110, metric=10,
                                  rpt=True), NB1)], t0=1100.0)
    d = detail_for(w, "PMW-080")
    ck(d.get("rpt") is True and d.get("metric_pref") == 110,
       "assert: the R bit is reported and masked out of the preference",
       str(d))
    ck("PMW-082" not in codes(w),
       "assert: an RPT assert with a normal metric is not a zero-metric "
       "finding", str(sorted(codes(w))))
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_ASSERT, F.assert_body(G1, SRC1), "10.0.0.88")],
         t0=1100.0)
    ck("PMW-084" in codes(w), "assert: from a non-neighbour")
    record(w)

    w = W(armed=False, assert_churn_max=2, assert_churn_window=30.0)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_ASSERT, F.assert_body(G1, SRC1), NB1)
             for _ in range(5)], t0=1100.0)
    ck("PMW-081" in codes(w), "assert: contention churn")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_ASSERT, F.assert_body(G1, SRC1, metric_pref=110), NB1),
             F.pim4(P.PIM_ASSERT, F.assert_body(G1, SRC1, metric_pref=20), NB2)],
         t0=1100.0)
    ck("PMW-083" in codes(w), "assert: winner change after arming")
    record(w)


def s_bsr_rp():
    w = W(armed=False)
    gs = [(G1, 32, [(RP1, 150, 192)])]
    feed(w, [F.pim4(P.PIM_BOOTSTRAP, F.bootstrap_body(BSR1, gs), NB1)])
    c = codes(w)
    ck("PMW-101" in c, "BSR: learned")
    ck("PMW-100" in c, "BSR: RP learned from the bootstrap RP set")
    record(w)

    # Higher-priority BSR takeover vs an address change at equal priority.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_BOOTSTRAP, F.bootstrap_body(BSR1, gs, bsr_priority=64), NB1)])
    w.arm()
    feed(w, [F.pim4(P.PIM_BOOTSTRAP, F.bootstrap_body(BSR2, gs, bsr_priority=200), NB1)],
         t0=1100.0)
    ck("PMW-102" in codes(w), "BSR: higher-priority takeover")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_BOOTSTRAP, F.bootstrap_body(BSR1, gs, bsr_priority=64), NB1)])
    w.arm()
    feed(w, [F.pim4(P.PIM_BOOTSTRAP, F.bootstrap_body(BSR2, gs, bsr_priority=10), NB1)],
         t0=1100.0)
    ck("PMW-103" in codes(w), "BSR: address change without priority gain")
    record(w)

    # Hash mask length change.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_BOOTSTRAP, F.bootstrap_body(BSR1, gs, hash_mask_len=30), NB1)])
    w.arm()
    feed(w, [F.pim4(P.PIM_BOOTSTRAP, F.bootstrap_body(BSR1, gs, hash_mask_len=24), NB1)],
         t0=1100.0)
    ck("PMW-112" in codes(w), "BSR: hash mask length change")
    record(w)

    # Fragment tag churn.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_BOOTSTRAP, F.bootstrap_body(BSR1, gs, fragment_tag=1), NB1)])
    w.arm()
    feed(w, [F.pim4(P.PIM_BOOTSTRAP,
                    F.bootstrap_body(BSR1, gs, fragment_tag=t), NB1)
             for t in range(2, 14)], t0=1100.0)
    ck("PMW-117" in codes(w), "BSR: fragment tag churn")
    record(w)

    # The RP set for a range changes after arming.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_BOOTSTRAP,
                    F.bootstrap_body(BSR1, [(G1, 32, [(RP1, 150, 192),
                                                      (RP2, 150, 192)])]), NB1)])
    w.arm()
    feed(w, [F.pim4(P.PIM_BOOTSTRAP,
                    F.bootstrap_body(BSR1, [(G1, 32, [(RP1, 150, 192)])]), NB1)],
         t0=1100.0)
    ck("PMW-105" in codes(w), "BSR: RP set for a range changed")
    d = detail_for(w, "PMW-105")
    ck(d.get("removed") == [RP2], "BSR: the withdrawn RP is named", str(d))
    record(w)

    # One group range, two RPs.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_BOOTSTRAP,
                    F.bootstrap_body(BSR1, [(G1, 32, [(RP1, 150, 192)])]), NB1),
             F.pim4(P.PIM_BOOTSTRAP,
                    F.bootstrap_body(BSR1, [(G1, 32, [(RP2, 150, 192)])]), NB1)])
    ck("PMW-106" in codes(w), "RP: one group range mapped to two RPs")
    record(w)

    # SSM range inside an RP mapping.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_BOOTSTRAP,
                    F.bootstrap_body(BSR1, [(SSM_G, 32, [(RP1, 150, 192)])]), NB1)])
    ck("PMW-164" in codes(w), "RP: SSM range present in an RP mapping")
    record(w)

    # Candidate-RP from an unknown RP, then a priority escalation.
    w = W(armed=True)
    feed(w, [F.pim4(P.PIM_CAND_RP_ADV, F.cand_rp_body(RP2, [(G1, 32)]), RP2)])
    ck("PMW-104" in codes(w), "RP: candidate-RP advertisement from an unknown RP")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_CAND_RP_ADV,
                    F.cand_rp_body(RP1, [(G1, 32)], priority=192), RP1)])
    w.arm()
    feed(w, [F.pim4(P.PIM_CAND_RP_ADV,
                    F.cand_rp_body(RP1, [(G1, 32)], priority=1), RP1)], t0=1100.0)
    ck("PMW-118" in codes(w), "RP: candidate-RP priority escalation")
    record(w)


def s_register():
    # Learning window records the RP; after arming an unknown RP is flagged.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_REGISTER, F.register_body(SRC1, G1), NB1, dst=RP1,
                    ttl=64)])
    ck("PMW-100" in codes(w), "register: RP learned from a Register")
    record(w)

    w = W(armed=True)
    feed(w, [F.pim4(P.PIM_REGISTER, F.register_body(SRC1, G1), NB1, dst=RP1,
                    ttl=64)])
    ck("PMW-110" in codes(w), "register: Register to an unlearned RP")
    record(w)

    # SSM group registered to an RP.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_REGISTER, F.register_body(SRC1, SSM_G), NB1, dst=RP1,
                    ttl=64)])
    ck("PMW-162" in codes(w), "register: SSM group registered to an RP")
    record(w)

    # Register-Stop from an unexpected RP.
    w = W(armed=True)
    feed(w, [F.pim4(P.PIM_REGISTER_STOP, F.register_stop_body(G1, SRC1),
                    "10.9.9.44", dst=NB1, ttl=64)])
    ck("PMW-111" in codes(w), "register: Register-Stop from an unexpected RP")
    record(w)

    # RFC 4610 Anycast-RP: RP-to-RP Register.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_REGISTER, F.register_body(SRC1, G1), NB1, dst=RP1,
                    ttl=64),
             F.pim4(P.PIM_REGISTER, F.register_body(SRC1, G1), RP1, dst=RP2,
                    ttl=64)])
    ck("PMW-113" in codes(w), "register: RP-to-RP Anycast-RP relay observed")
    record(w)

    # 8-byte Register checksum convention is accepted.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_REGISTER, F.register_body(SRC1, G1), NB1, dst=RP1,
                    ttl=64, checksum_len=8)])
    ck("PMW-003" not in codes(w),
       "register: 8-byte checksum convention accepted")
    record(w)


def s_ssm_and_embedded_rp():
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(SSM_G, [(RP1, True, True)], [])]),
                    NB1)], t0=1100.0)
    c = codes(w)
    ck("PMW-160" in c, "SSM: range group observed")
    ck("PMW-161" in c, "SSM: (*,G) join inside the SSM range")
    record(w)

    # The accepted SSM-mapping effect code: source changes for one channel.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(SSM_G, [("198.51.100.1", False, False)], [])]),
                    NB1),
             F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(SSM_G, [("198.51.100.1", False, False)], [])]),
                    NB1)], t0=1100.0)
    ck("PMW-163" not in codes(w), "SSM: a stable channel source is not flagged")
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(SSM_G, [("203.0.113.5", False, False)], [])]),
                    NB1)], t0=1200.0)
    ck("PMW-163" in codes(w), "SSM: channel source change against baseline")
    record(w)

    # Embedded-RP (RFC 3956): ff7e:0140:2001:db8:9::1234 carries 2001:db8:9::/64
    grp = "ff7e:140:2001:db8:9:0:0:1234"
    rp = P.embedded_rp_address(grp)
    ck(rp is not None and rp.startswith("2001:db8:9"),
       "embedded-RP: RP extracted from the group address", str(rp))
    w = W(armed=False)
    learn_neighbors(w, (NB6_1, NB6_2), af=6)
    feed(w, [F.pim6(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB6_2, [(grp, [("2001:db8:1::5", False, False)], [])]),
                    NB6_1)], t0=1100.0)
    ck("PMW-115" in codes(w), "embedded-RP: group observed")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB6_1, NB6_2), af=6)
    # Learn a DIFFERENT v6 RP, so the address embedded in the group below
    # genuinely disagrees with what this fabric advertises.
    feed(w, [F.pim6(P.PIM_REGISTER, F.register_body("2001:db8:1::5", "ff0e::9"),
                    NB6_1, dst="2001:db8:9::99", hlim=64)], t0=1100.0)
    w.arm()
    feed(w, [F.pim6(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB6_2, [(grp, [("2001:db8:1::5", False, False)], [])]),
                    NB6_1)], t0=1200.0)
    ck("PMW-116" in codes(w),
       "embedded-RP: embedded address disagrees with the learned RP set")
    record(w)

    # IPv6 SSM range.
    w = W(armed=False)
    ck(P.is_ssm_group("ff3e::1234") and not P.is_ssm_group("ff0e::1"),
       "SSM: IPv6 ff3x::/32 recognised, other scopes are not")
    ck(P.is_ssm_group("232.1.2.3") and not P.is_ssm_group("239.1.2.3"),
       "SSM: IPv4 232/8 recognised, 239/8 is not")


def s_dense_mode():
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_GRAFT,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]),
                    NB1)], t0=1100.0)
    ck("PMW-120" in codes(w), "DM: dense mode observed")
    record(w)

    # Dense mode appearing on a link already carrying sparse mode.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]),
                    NB1)], t0=1100.0)
    w.arm()
    feed(w, [F.pim4(P.PIM_GRAFT,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]),
                    NB1)], t0=1200.0)
    ck("PMW-125" in codes(w), "DM: dense mode on a sparse-only link")
    record(w)

    # Graft flood.
    w = W(armed=False, graft_rate_max=2)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_GRAFT,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]),
                    NB1) for _ in range(5)], t0=1100.0)
    ck("PMW-121" in codes(w), "DM: graft rate anomaly")
    record(w)

    # Graft-Ack with no matching Graft.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_GRAFT_ACK,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]),
                    NB2)], t0=1100.0)
    ck("PMW-124" in codes(w), "DM: Graft-Ack without a matching Graft")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_GRAFT,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]), NB1),
             F.pim4(P.PIM_GRAFT_ACK,
                    F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]), NB2)],
         t0=1100.0)
    ck("PMW-124" not in codes(w), "DM: a paired Graft/Graft-Ack is clean")
    record(w)

    # State refresh from a forged originator, and TTL/interval anomaly.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_STATE_REFRESH,
                    F.state_refresh_body(G1, SRC1, "10.0.0.66"), NB1)],
         t0=1100.0)
    ck("PMW-122" in codes(w), "DM: state refresh from an unknown originator")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_STATE_REFRESH,
                    F.state_refresh_body(G1, SRC1, NB2, ttl=0, interval=200),
                    NB1)], t0=1100.0)
    ck("PMW-123" in codes(w), "DM: state refresh TTL/interval anomaly")
    record(w)


def s_bidir():
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_DF_ELECTION, F.df_election_body(RP1), NB1,
                    flags=F.df_flags(P.DF_OFFER))],
         t0=1100.0)
    ck("PMW-140" in codes(w), "BiDir: DF election observed")
    record(w)

    w = W(armed=False, df_offer_max=2)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_DF_ELECTION, F.df_election_body(RP1), NB1,
                    flags=F.df_flags(P.DF_OFFER))
             for _ in range(5)], t0=1100.0)
    ck("PMW-141" in codes(w), "BiDir: DF offer flood")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_DF_ELECTION, F.df_election_body(RP1), NB1,
                    flags=F.df_flags(P.DF_WINNER)),
             F.pim4(P.PIM_DF_ELECTION, F.df_election_body(RP1), NB2,
                    flags=F.df_flags(P.DF_WINNER))],
         t0=1100.0)
    ck("PMW-142" in codes(w), "BiDir: DF winner change")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_DF_ELECTION, F.df_election_body(RP1), "10.0.0.55",
                    flags=F.df_flags(P.DF_WINNER))], t0=1100.0)
    ck("PMW-143" in codes(w), "BiDir: DF message from a non-neighbour")
    record(w)

    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    w.arm()
    feed(w, [F.pim4(P.PIM_DF_ELECTION, F.df_election_body(RP1, target="10.0.0.44"), NB1,
                    flags=F.df_flags(P.DF_PASS))],
         t0=1100.0)
    ck("PMW-144" in codes(w), "BiDir: DF Pass to an unknown target")
    record(w)

    # Backoff carries the same target fields and must parse.
    w = W(armed=False)
    learn_neighbors(w, (NB1, NB2))
    feed(w, [F.pim4(P.PIM_DF_ELECTION, F.df_election_body(RP1, target=NB2), NB1,
                    flags=F.df_flags(P.DF_BACKOFF))],
         t0=1100.0)
    ck(w.stats["parse_errors"] == 0, "BiDir: Backoff subtype parses cleanly",
       w.stats.get("last_parse_error", ""))
    record(w)


def s_autorp():
    w = W(armed=False)
    feed(w, [F.autorp4(1, [(RP1, [(G1, 32, False)])], NB1)])
    c = codes(w)
    ck("PMW-109" in c, "Auto-RP: observed and marked unauthenticated")
    ck("PMW-100" in c, "Auto-RP: RP learned")
    record(w)

    w = W(armed=False)
    feed(w, [F.autorp4(1, [(RP1, [(G1, 32, False)])], NB1)])
    w.arm()
    feed(w, [F.autorp4(1, [(RP2, [(G1, 32, False)])], NB1)], t0=1100.0)
    ck("PMW-107" in codes(w), "Auto-RP: announcement for an unknown RP")
    record(w)

    w = W(armed=False)
    feed(w, [F.autorp4(2, [(RP1, [(G1, 32, False)])], NB1, dst="224.0.1.40")])
    w.arm()
    feed(w, [F.autorp4(2, [(RP1, [(G1, 32, False)])], NB2, dst="224.0.1.40")],
         t0=1100.0)
    ck("PMW-108" in codes(w), "Auto-RP: mapping agent change")
    record(w)


def s_msdp():
    PEER_A, PEER_B = "10.7.7.1", "10.7.7.2"

    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_keepalive(), PEER_A, PEER_B)])
    c = codes(w)
    ck("PMW-180" in c, "MSDP: session observed")
    ck("PMW-190" in c, "MSDP: session without TCP-MD5")
    record(w)

    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_keepalive(), PEER_A, PEER_B, md5=True)])
    ck("PMW-190" not in codes(w), "MSDP: TCP-MD5 session is not flagged")
    ck("PMW-180" in codes(w), "MSDP: MD5 session still recorded")
    record(w)

    # SA learned during the window, then an unknown originating RP once armed.
    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_sa(RP1, [(G1, SRC1)]), PEER_A, PEER_B)])
    c = codes(w)
    ck("PMW-181" in c, "MSDP: Source-Active observed")
    ck("PMW-100" in c, "MSDP: originating RP learned during the window")
    record(w)

    w = W(armed=True)
    feed(w, [F.msdp4(F.msdp_sa(RP1, [(G1, SRC1)]), PEER_A, PEER_B)])
    ck("PMW-182" in codes(w), "MSDP: originating RP outside the learned set")
    ck("PMW-187" in codes(w), "MSDP: peer outside the learned peer set")
    record(w)

    # SSM group inside an SA.
    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_sa(RP1, [(SSM_G, SRC1)]), PEER_A, PEER_B)])
    ck("PMW-183" in codes(w), "MSDP: SA for an SSM-range group")
    record(w)

    # Conflicting originating RPs for one group.
    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_sa(RP1, [(G1, SRC1)]), PEER_A, PEER_B),
             F.msdp4(F.msdp_sa(RP2, [(G1, SRC1)]), PEER_A, PEER_B, seq=100)])
    ck("PMW-185" in codes(w), "MSDP: conflicting originating RPs for one group")
    record(w)

    # SA storm.
    w = W(armed=True, sa_rate_max=2)
    frames = [F.msdp4(F.msdp_sa(RP1, [(G1, SRC1)]), PEER_A, PEER_B, seq=i)
              for i in range(6)]
    feed(w, frames)
    ck("PMW-184" in codes(w), "MSDP: SA storm")
    ck(P.DEFAULTS["sa_rate_max"] == 500, "MSDP: shipped SA ceiling is 500")
    record(w)

    # Data-encapsulated SA.
    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_sa(RP1, [(G1, SRC1)], encapsulated=b"\x45" + b"\x00" * 30),
                     PEER_A, PEER_B)])
    ck("PMW-191" in codes(w), "MSDP: data-encapsulated SA")
    record(w)

    # Declared entry count larger than the TLV can hold.
    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_sa_bad_count(RP1, [(G1, SRC1)], declared=5),
                     PEER_A, PEER_B)])
    ck("PMW-192" in codes(w), "MSDP: entry count inconsistent with TLV length")
    record(w)

    # SA-Request.
    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_sa_request(G1), PEER_A, PEER_B)])
    ck("PMW-188" in codes(w), "MSDP: SA-Request observed")
    record(w)

    # Session reset.
    w = W(armed=False)
    feed(w, [F.msdp4(b"", PEER_A, PEER_B, flags=0x04)])
    ck("PMW-186" in codes(w), "MSDP: session reset")
    record(w)

    # Malformed TLV length.
    w = W(armed=False)
    # Valid TLV head (type 1, length 6) whose SA body cannot hold the
    # fixed RP + count fields -- it anchors, then fails inside the parser.
    bad = bytes([1, 0, 6]) + b"\x00" * 3
    feed(w, [F.msdp4(bad, PEER_A, PEER_B)])
    ck("PMW-189" in codes(w), "MSDP: malformed TLV reported")
    record(w)

    # Reassembly: one SA split across three TCP segments.
    w = W(armed=False)
    sa = F.msdp_sa(RP1, [(G1, SRC1), ("239.2.2.2", "192.0.2.20")])
    parts = [sa[:4], sa[4:11], sa[11:]]
    seq = 1
    frames = []
    for p in parts:
        frames.append(F.msdp4(p, PEER_A, PEER_B, seq=seq))
        seq += len(p)
    feed(w, frames)
    ck("PMW-181" in codes(w), "MSDP: SA reassembled across three segments")
    d = detail_for(w, "PMW-181")
    ck(d.get("entries") == 2, "MSDP: both SA entries recovered after reassembly",
       str(d))
    record(w)

    # Both Anycast-RP mechanisms for one RP address.
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_REGISTER, F.register_body(SRC1, G1), NB1, dst=RP1,
                    ttl=64),
             F.pim4(P.PIM_REGISTER, F.register_body(SRC1, G1), RP1, dst=RP1,
                    ttl=64),
             F.msdp4(F.msdp_sa(RP1, [(G1, SRC1)]), PEER_A, PEER_B)])
    ck("PMW-114" in codes(w),
       "MSDP: PIM Anycast-RP and MSDP Anycast-RP both active for one RP")
    record(w)


def s_ipv6_ah():
    # AH present, then absent, then a changed SPI.
    w = W(armed=False)
    feed(w, [F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1,
                    exts=[("ah", 0xAABBCCDD, 1)])])
    ck("PMW-020" in codes(w), "AH: protection observed")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1,
                    exts=[("ah", 0xAABBCCDD, 1)]),
             F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1,
                    exts=[("ah", 0x11223344, 2)])])
    ck("PMW-023" in codes(w), "AH: SPI change")
    record(w)

    w = W(armed=False)
    feed(w, [F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1,
                    exts=[("ah", 0xAABBCCDD, 1)]),
             F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1)])
    c = codes(w)
    ck("PMW-021" in c, "AH: protection lost for a speaker")
    ck("PMW-022" in c, "AH: mixed protected and unprotected PIM on one link")
    record(w)

    # Extension-header chain in front of the PIM header.
    w = W(armed=False)
    feed(w, [F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1,
                    exts=[("ext", 60), ("ah", 0x55667788, 3)])])
    c = codes(w)
    ck("PMW-001" in c, "IPv6: PIM reached behind DestOpt + AH")
    ck("PMW-020" in c, "IPv6: AH found after a DestOpt header")
    ck(w.stats["parse_errors"] == 0, "IPv6: EH chain walked without error",
       w.stats.get("last_parse_error", ""))
    record(w)

    # Hop-by-hop in front, hop limit wrong.
    w = W(armed=False)
    feed(w, [F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1, hlim=64,
                    exts=[("ext", 0)])])
    ck("PMW-007" in codes(w), "IPv6: hop limit other than 1 on a link-local type")
    record(w)

    # Full IPv6 parity on the routing plane, not just Hello.
    w = W(armed=False)
    learn_neighbors(w, (NB6_1, NB6_2), af=6)
    feed(w, [F.pim6(P.PIM_JOIN_PRUNE,
                    F.join_prune_body(NB6_2, [("ff0e::1234",
                                               [("2001:db8:1::5", False, False)], [])]),
                    NB6_1),
             F.pim6(P.PIM_ASSERT, F.assert_body("ff0e::1234", "2001:db8:1::5"),
                    NB6_1),
             F.pim6(P.PIM_BOOTSTRAP,
                    F.bootstrap_body(RP6, [("ff0e::1234", 128, [(RP6, 150, 1)])]),
                    NB6_1),
             F.pim6(P.PIM_DF_ELECTION, F.df_election_body(RP6), NB6_1,
                    flags=F.df_flags(P.DF_WINNER))], t0=1100.0)
    c = codes(w)
    ck(w.stats["parse_errors"] == 0, "IPv6: J/P, Assert, Bootstrap, DF parse",
       w.stats.get("last_parse_error", ""))
    ck({"PMW-080", "PMW-101", "PMW-140"} <= c,
       "IPv6: assert, bootstrap and DF findings fire on the v6 plane",
       str(sorted(c)))
    record(w)

    # VLAN-tagged IPv6 PIM.
    w = W(armed=False)
    feed(w, [F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1, vlans=(412,))])
    ck("PMW-001" in codes(w), "IPv6: PIM found behind an 802.1Q tag")
    record(w)


def s_endpoint_rendering():
    ep = P.fmt_ep("2001:db8::9", 51000)
    ck(ep == "[2001:db8::9]:51000", "endpoint: IPv6 literal is bracketed", ep)
    host, port = P.split_ep(ep)
    ck(host == "2001:db8::9" and port == 51000,
       "endpoint: IPv6 endpoint round-trips back to host and port")
    ep4 = P.fmt_ep("10.0.0.1", 639)
    ck(ep4 == "10.0.0.1:639", "endpoint: IPv4 rendering unchanged", ep4)
    h4, p4 = P.split_ep(ep4)
    ck(h4 == "10.0.0.1" and p4 == 639, "endpoint: IPv4 endpoint round-trips")

    # Every MSDP finding that carries an endpoint must round-trip.
    w = W(armed=False)
    feed(w, [F.msdp4(F.msdp_keepalive(), "10.7.7.1", "10.7.7.2")])
    bad = []
    for f in w.findings:
        for k, v in f["detail"].items():
            if k.startswith("peer") and isinstance(v, str) and ":" in v:
                try:
                    P.split_ep(v)
                except Exception as e:                     # noqa: BLE001
                    bad.append((k, v, str(e)))
    ck(not bad, "endpoint: every emitted peer endpoint re-parses", str(bad))


def s_af_tagging():
    w = W(armed=False)
    feed(w, [F.pim4(P.PIM_HELLO, F.hello_body(), NB1),
             F.pim6(P.PIM_HELLO, F.hello_body(), NB6_1),
             F.msdp4(F.msdp_keepalive(), "10.7.7.1", "10.7.7.2")])
    afs = {f["af"] for f in w.findings}
    ck(afs == {4, 6}, "af: every finding carries an address family", str(afs))
    v6 = [f for f in w.findings if f["af"] == 6]
    ck(v6 and all(f["code"] in P.FINDINGS for f in v6),
       "af: IPv6 findings use declared codes")


def s_rate_gating():
    """Every rate-based detector is attack-class and must stay silent until
    the module arms. Found by the sealed lab: six of them did not."""
    bursts = [
        ("PMW-045", dict(hello_rate_max=2),
         [F.pim4(P.PIM_HELLO, F.hello_body(), NB1) for _ in range(6)]),
        ("PMW-061", dict(prune_rate_max=2),
         [F.pim4(P.PIM_JOIN_PRUNE,
                 F.join_prune_body(NB2, [(G1, [], [(SRC1, False, False)])]),
                 NB1) for _ in range(6)]),
        ("PMW-121", dict(graft_rate_max=2),
         [F.pim4(P.PIM_GRAFT,
                 F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]),
                 NB1) for _ in range(6)]),
        ("PMW-081", dict(assert_churn_max=2),
         [F.pim4(P.PIM_ASSERT, F.assert_body(G1, SRC1), NB1)
          for _ in range(6)]),
        ("PMW-141", dict(df_offer_max=2),
         [F.pim4(P.PIM_DF_ELECTION, F.df_election_body(RP1), NB1,
                 flags=F.df_flags(P.DF_OFFER)) for _ in range(6)]),
        ("PMW-184", dict(sa_rate_max=2),
         [F.msdp4(F.msdp_sa(RP1, [(G1, SRC1)]), "10.7.7.1", "10.7.7.2", seq=i)
          for i in range(6)]),
    ]
    for code, cfg, frames in bursts:
        quiet = W(armed=False, **cfg)
        learn_neighbors(quiet, (NB1, NB2))
        feed(quiet, frames, t0=1100.0)
        ck(code not in codes(quiet),
           "rate gating: %s stays silent during the learning window" % code,
           str(sorted(codes(quiet))))

        loud = W(armed=False, **cfg)
        learn_neighbors(loud, (NB1, NB2))
        loud.arm()
        feed(loud, frames, t0=1100.0)
        ck(code in codes(loud),
           "rate gating: ...and %s still fires once armed" % code,
           str(sorted(codes(loud))))


def s_clean_set():
    """A healthy sparse-mode fabric must raise no attack-class finding."""
    w = W(armed=False)
    frames = []
    for i, a in enumerate((NB1, NB2, NB3)):
        frames.append(F.pim4(P.PIM_HELLO,
                             F.hello_body(dr_priority=10 + i,
                                          lan_prune_delay=500),
                             a, smac="02:00:00:00:00:%02x" % (i + 1)))
    frames.append(F.pim4(P.PIM_BOOTSTRAP,
                         F.bootstrap_body(BSR1, [(G1, 32, [(RP1, 150, 192)])]),
                         NB1))
    frames.append(F.pim4(P.PIM_JOIN_PRUNE,
                         F.join_prune_body(NB2, [(G1, [(RP1, True, True)], [])]),
                         NB1))
    frames.append(F.pim4(P.PIM_REGISTER, F.register_body(SRC1, G1), NB1,
                         dst=RP1, ttl=64))
    frames.append(F.pim4(P.PIM_ASSERT, F.assert_body(G1, SRC1), NB1))
    feed(w, frames)
    w.arm()
    # the same healthy traffic repeated after arming
    feed(w, frames, t0=2000.0)
    attack = codes(w) & P.attack_class_codes()
    ck(not attack, "clean set: healthy sparse fabric raises no attack-class code",
       str(sorted(attack)))
    ck(w.stats["parse_errors"] == 0 and w.stats["internal_errors"] == 0,
       "clean set: no parse or internal errors",
       "%s %s" % (w.stats.get("last_parse_error"),
                  w.stats.get("last_internal_error")))

    # Non-vacuity: the clean set is not silent -- it must produce posture.
    ck(codes(w) & P.posture_class_codes(),
       "clean set: posture findings still produced (the gate is not vacuous)")


def s_robustness():
    """Truncation and garbage must never raise out of handle_frame."""
    w = W(armed=False)
    good = F.pim4(P.PIM_JOIN_PRUNE,
                  F.join_prune_body(NB2, [(G1, [(SRC1, False, False)], [])]),
                  NB1)
    for n in range(1, len(good)):
        w.handle_frame(good[:n], ts=1000.0)
    ck(w.stats["internal_errors"] == 0,
       "robustness: every truncation prefix handled as a parse error",
       w.stats.get("last_internal_error", ""))

    w2 = W(armed=False)
    for seed in range(64):
        blob = bytes((seed * 37 + i * 13) & 0xFF for i in range(seed + 20))
        w2.handle_frame(F.eth(F.ipv4(blob, NB1, "224.0.0.13", 103),
                              F.ETH_P_IPV4), ts=1000.0)
    ck(w2.stats["internal_errors"] == 0,
       "robustness: pseudo-random PIM bodies handled",
       w2.stats.get("last_internal_error", ""))

    # A declared-but-absent group count must not be read as real groups.
    w3 = W(armed=False)
    body = F.join_prune_body(NB2, [(G1, [], [])], force_num_groups=40)
    w3.handle_frame(F.pim4(P.PIM_JOIN_PRUNE, body, NB1), ts=1000.0)
    ck(w3.stats["parse_errors"] == 1,
       "robustness: over-declared group count is rejected, not invented")

    # Finding rate cap.
    w4 = W(armed=False, max_findings_per_code=3, hello_rate_max=100000)
    feed(w4, [F.pim4(P.PIM_HELLO, F.hello_body(omit_holdtime=True), NB1)
              for _ in range(10)])
    n006 = sum(1 for f in w4.findings if f["code"] == "PMW-006")
    ck(n006 == 3, "robustness: per-code finding cap holds", str(n006))
    ck(w4.suppressed.get("PMW-006", 0) == 7,
       "robustness: suppressed count is reported")

    # An undeclared code must be impossible to emit.
    w5 = W(armed=False)
    raised = False
    try:
        w5.finding("PMW-999", 1000.0, {})
    except KeyError:
        raised = True
    ck(raised, "robustness: undeclared finding codes are rejected")


def s_registry_invariants():
    ck(all(m["severity"] in P.SEVERITY_ORDER for m in P.FINDINGS.values()),
       "registry: every severity is declared")
    ck(all(m["class"] in ("posture", "attack", "info")
           for m in P.FINDINGS.values()), "registry: every class is declared")
    ck(set(P.CODE_PROTO) == set(P.FINDINGS),
       "registry: every code has a protocol assignment")
    ck(P.attack_class_codes() & P.posture_class_codes() == set(),
       "registry: attack and posture classes are disjoint")

    # The class comes from the registry, never from the code string. Prove it
    # by checking that the two bands actually interleave numerically -- a
    # lexicographic or >= band test would therefore give a different answer.
    att = sorted(int(c.split("-")[1]) for c in P.attack_class_codes())
    pos = sorted(int(c.split("-")[1]) for c in P.posture_class_codes())
    interleaved = any(p > min(att) for p in pos) and any(a > min(pos) for a in att)
    ck(interleaved,
       "registry: attack and posture codes interleave, so no numeric band "
       "test could substitute for the registry class")

    msdp_attack = P.attack_class_codes("msdp")
    ck(msdp_attack and all(P.CODE_PROTO[c] == "msdp" for c in msdp_attack),
       "registry: per-protocol filtering returns only that protocol's codes")
    ck("PMW-040" not in msdp_attack,
       "registry: a PIM code never leaks into the MSDP band")


def s_bpf_filter():
    """LESSON AE: only a bare ip6 term admits IPv6 behind extension headers."""
    f = P.BPF_FILTER
    terms = [t.strip() for t in f.split(" or ")]
    ck(any(t == "ip6" for t in terms),
       "BPF: filter contains a bare ip6 term", f)
    ck("ip proto 103" in f, "BPF: IPv4 PIM admitted", f)
    ck("udp port 496" in f, "BPF: Auto-RP admitted", f)
    ck("tcp port 639" in f, "BPF: MSDP admitted", f)
    ck("ip6 and" not in f and "and ip6" not in f,
       "BPF: no narrowed ip6 clause that cannot walk an EH chain", f)

    # The bare ip6 admit makes the software gate the only rejector of
    # non-PIM IPv6. That gate needs its own negative test.
    w = W(armed=False)
    payload = b"\x00" * 32
    frame = F.eth(F.ipv6(F.udp(payload, 12345, 53), NB6_1, "2001:db8::2", 17,
                         hlim=64), F.ETH_P_IPV6)
    w.handle_frame(frame, ts=1000.0)
    ck(not w.findings,
       "BPF: unrelated IPv6 admitted by the bare term is dropped in software",
       str(codes(w)))
    ck(w.stats["internal_errors"] == 0, "BPF: software gate raises nothing")

    # ...and an IPv6 ESP packet is counted, not decoded.
    w2 = W(armed=False)
    w2.handle_frame(F.eth(F.ipv6(b"\x00" * 24, NB6_1, "ff02::d", 50, hlim=1),
                          F.ETH_P_IPV6), ts=1000.0)
    ck(w2.stats["esp_packets"] == 1 and not w2.findings,
       "BPF: encrypted PIM (ESP) is counted but produces no decode")


def s_ast_guards():
    """Static guards over the module source."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "pimwatch.py")
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src)

    # (1) No transmit path. Split by AST SHAPE, not by name, so the guard
    # cannot collide with the harness that proves it (suite LESSON D).
    banned_names = {"send", "sendp", "sr", "sr1", "srp", "srp1", "sendpfast",
                    "pcap_sendpacket", "srloop", "sendto"}
    banned_attrs = {("os", "system"), ("subprocess", "run"),
                    ("subprocess", "Popen"), ("subprocess", "call"),
                    ("subprocess", "check_output"), ("socket", "sendto"),
                    ("socket", "send")}
    violations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in banned_names:
            violations.append("bare call %s() at line %d" % (fn.id, node.lineno))
        elif isinstance(fn, ast.Attribute):
            recv = fn.value
            rname = recv.id if isinstance(recv, ast.Name) else None
            if rname and (rname, fn.attr) in banned_attrs:
                violations.append("%s.%s() at line %d"
                                  % (rname, fn.attr, node.lineno))
            if fn.attr in banned_names and rname not in (None, "self"):
                violations.append("%s.%s() at line %d"
                                  % (rname, fn.attr, node.lineno))
    ck(not violations, "AST: no transmit or shell-out path in the module",
       "; ".join(violations))

    # Non-vacuity for that guard: it must fire on a planted violation.
    planted = ast.parse("sendp(x)\nimport subprocess\nsubprocess.run(['x'])\n")
    found = 0
    for node in ast.walk(planted):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in banned_names:
                found += 1
            elif isinstance(fn, ast.Attribute):
                recv = fn.value
                rname = recv.id if isinstance(recv, ast.Name) else None
                if rname and (rname, fn.attr) in banned_attrs:
                    found += 1
    ck(found == 2, "AST: transmit guard fires on planted violations", str(found))

    # (2) No module-level name defined twice (suite LESSON G).
    seen, dupes = {}, []
    for node in tree.body:
        names = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        for n in names:
            if n in seen and not n.startswith("_"):
                dupes.append("%s (lines %d and %d)" % (n, seen[n], node.lineno))
            seen[n] = node.lineno
    ck(not dupes, "AST: no module-level name is defined twice", "; ".join(dupes))

    # (3) scapy is imported only inside the capture function (LESSON C).
    top_imports = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = getattr(node, "module", None) or ""
            names = [a.name for a in node.names]
            if "scapy" in mod or any("scapy" in n for n in names):
                top_imports.append(node.lineno)
    ck(not top_imports,
       "AST: scapy is not imported at module scope", str(top_imports))

    inside = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "run_capture":
            for sub in ast.walk(node):
                if isinstance(sub, ast.ImportFrom) and "scapy" in (sub.module or ""):
                    inside.append(sub.lineno)
    ck(inside, "AST: scapy is imported inside run_capture")

    # (4) Every finding code string used in the module is declared.
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.startswith("PMW-") and len(node.value) == 7:
                used.add(node.value)
    undeclared = {c for c in used if c not in P.FINDINGS} - {"PMW-999"}
    ck(not undeclared, "AST: every PMW- code used in the module is declared",
       str(sorted(undeclared)))

    # Emission sites. Codes reach finding() in three shapes: a literal, a
    # Name bound to a literal, and a Name bound to a conditional expression.
    # An extractor that handles only literals silently under-reports and
    # makes this check vacuous (suite LESSON M), so all three are resolved,
    # with Name lookup scoped to the enclosing function (suite LESSON Y).
    def _literals(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.IfExp):
            return _literals(node.body) | _literals(node.orelse)
        return set()

    emitted = set()
    resolved_by_name = 0
    for fndef in ast.walk(tree):
        if not isinstance(fndef, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        binds = {}
        for sub in ast.walk(fndef):
            if isinstance(sub, ast.Assign):
                for t in sub.targets:
                    if isinstance(t, ast.Name):
                        vals = _literals(sub.value)
                        if vals:
                            binds.setdefault(t.id, set()).update(vals)
        for sub in ast.walk(fndef):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "finding" and sub.args):
                a0 = sub.args[0]
                lits = _literals(a0)
                if lits:
                    emitted |= lits
                elif isinstance(a0, ast.Name) and a0.id in binds:
                    emitted |= binds[a0.id]
                    resolved_by_name += 1
    ck(resolved_by_name >= 3,
       "AST: the emission extractor resolves non-literal code arguments",
       str(resolved_by_name))
    never = set(P.FINDINGS) - emitted
    ck(not never, "AST: every declared code has an emission site in the module",
       str(sorted(never)))


# Codes that this tier does not exercise, each with the reason. The coverage
# gate below compares against this list, so adding a code without a fixture
# fails the tier rather than silently lowering coverage.
NOT_COVERED_HERE = {}


def s_coverage():
    declared = set(P.FINDINGS)
    missing = declared - ALL_FIRED - set(NOT_COVERED_HERE)
    ck(not missing, "coverage: every declared code is exercised here",
       str(sorted(missing)))
    stale = set(NOT_COVERED_HERE) & ALL_FIRED
    ck(not stale, "coverage: the not-covered list has no stale entries",
       str(sorted(stale)))
    ck(ALL_FIRED <= declared,
       "coverage: nothing fired that is not declared",
       str(sorted(ALL_FIRED - declared)))


SCENARIOS = [
    s_hello_basics, s_dr_election, s_header_hygiene, s_join_prune,
    s_rpf_vector, s_assert, s_bsr_rp, s_register, s_ssm_and_embedded_rp,
    s_dense_mode, s_bidir, s_autorp, s_msdp, s_ipv6_ah,
    s_endpoint_rendering, s_af_tagging, s_rate_gating, s_clean_set,
    s_robustness,
    s_registry_invariants, s_bpf_filter, s_ast_guards, s_coverage,
]


def run_self_test(verbose=True):
    for fn in SCENARIOS:
        try:
            fn()
        except Exception as e:                      # noqa: BLE001
            CHECKS.append((False, "scenario %s raised" % fn.__name__,
                           "%s: %s" % (type(e).__name__, e)))
    failed = [c for c in CHECKS if not c[0]]
    if verbose:
        for ok, label, extra in CHECKS:
            if not ok:
                print("FAIL  %s%s" % (label, ("  [%s]" % extra) if extra else ""))
    print("%d/%d checks passed" % (len(CHECKS) - len(failed), len(CHECKS)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run_self_test())
