#!/usr/bin/env python3
# icmpwatch_selftest.py — Scapy self-test harness for icmpwatch.
#
# Crafts ICMP Redirect (and ARP) packets in-memory and runs them through the
# detector, asserting on the emitted findings. No interface, no wire traffic.
# Mirrors the self-test style used across the Ragnar suite.

import sys
import logging

# Scapy warns about missing IPv6 routes when building link-local test packets.
# The harness never transmits, so the warnings are noise.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import Ether, IP, ICMP, UDP, TCP, ARP, IPv6, conf
from scapy.layers.inet6 import (
    ICMPv6ND_Redirect, ICMPv6ND_NS, ICMPv6ND_NA,
    ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr, ICMPv6NDOptRedirectedHdr,
)

from icmpwatch import (
    ICMPRedirectDetector, packet_to_event, arp_packet_to_obs,
    ndp_packet_to_obs, _build_filter,
    SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL,
)

conf.verb = 0

# ---- shared lab config ----------------------------------------------------
# Segment 192.168.10.0/24 with two legitimate gateways: .1 (GW_MAC) and
# .2 (GW2_MAC). Everything else on-segment is an endpoint.
GW_MAC = "de:ad:be:ef:00:01"
GW2_MAC = "de:ad:be:ef:00:02"
ATTACKER_MAC = "00:11:22:33:44:55"

CONFIG = {
    "segments": [
        {
            "cidr": "192.168.10.0/24",
            "gateways": [
                {"ip": "192.168.10.1", "mac": GW_MAC},
                {"ip": "192.168.10.2", "mac": GW2_MAC},
            ],
            "routers": [],
        }
    ],
    "thresholds": {"window_seconds": 10.0, "burst_per_src": 5, "dest_diversity": 4},
    "enable_ttl_heuristic": True,
    "expected_local_ttls": [64, 255],
    "ttl_slack": 2,
    "arp_correlation": {"enabled": True, "conflict_window_seconds": 300.0},
}

# gateways declared without a MAC — ARP is expected to supply it
CONFIG_NOMAC = {
    "segments": [
        {
            "cidr": "192.168.10.0/24",
            "gateways": [{"ip": "192.168.10.1"}, {"ip": "192.168.10.2"}],
            "routers": [],
        }
    ],
    "thresholds": CONFIG["thresholds"],
    "arp_correlation": {"enabled": True, "conflict_window_seconds": 300.0},
}

# stale config MAC on .1, ARP preferred
CONFIG_PREFER = {
    "segments": [
        {
            "cidr": "192.168.10.0/24",
            "gateways": [
                {"ip": "192.168.10.1", "mac": "aa:aa:aa:aa:aa:99"},
                {"ip": "192.168.10.2", "mac": GW2_MAC},
            ],
            "routers": [],
        }
    ],
    "thresholds": CONFIG["thresholds"],
    "arp_correlation": {"enabled": True, "prefer_arp_over_config": True,
                        "conflict_window_seconds": 300.0},
}

# a genuinely multi-MAC first hop (GLBP hands out up to four vMACs for one VIP)
GLBP_MACS = [
    "00:07:b4:00:01:01",
    "00:07:b4:00:01:02",
    "00:07:b4:00:01:03",
    "00:07:b4:00:01:04",
]
CONFIG_GLBP = {
    "segments": [
        {
            "cidr": "192.168.10.0/24",
            "gateways": [
                {"ip": "192.168.10.1", "expected_macs": GLBP_MACS},
                {"ip": "192.168.10.2", "mac": GW2_MAC},
            ],
            "routers": [],
        }
    ],
    "thresholds": CONFIG["thresholds"],
    "arp_correlation": {"enabled": True, "conflict_window_seconds": 300.0},
}

VICTIM = "192.168.10.50"
DEST = "8.8.8.8"
ATTACKER = "192.168.10.66"

# ---- IPv6 lab -------------------------------------------------------------
# Routers are declared by link-local address, as IPv6 requires. Note these sit
# in fe80::/10 and therefore OUTSIDE the segment prefix 2001:db8::/64 — the
# config model must resolve them anyway.
GW_LL = "fe80::1"
R2_LL = "fe80::2"
V6_VICTIM = "2001:db8::50"
V6_DEST = "2001:db8::99"
V6_ATTACKER_LL = "fe80::66"

CONFIG_V6 = {
    "segments": [
        {
            "cidr": "2001:db8::/64",
            "gateways": [
                {"ip": GW_LL, "mac": GW_MAC},
                {"ip": R2_LL, "mac": GW2_MAC},
            ],
            "routers": [],
        }
    ],
    "thresholds": CONFIG["thresholds"],
    "ipv6": {"enabled": True},
    "arp_correlation": {"enabled": True, "conflict_window_seconds": 300.0},
}


CONFIG_DUAL = {
    "segments": (CONFIG["segments"] + CONFIG_V6["segments"]),
    "thresholds": CONFIG["thresholds"],
    "ipv6": {"enabled": True},
    "arp_correlation": {"enabled": True, "conflict_window_seconds": 300.0},
}


def _redirect6(src, tgt, dst, *, src_mac=GW_MAC, hlim=255, code=0,
               tlla=None, victim=V6_VICTIM, drop_inner=False):
    p = (Ether(src=src_mac)
         / IPv6(src=src, dst=victim, hlim=hlim)
         / ICMPv6ND_Redirect(tgt=tgt, dst=dst, code=code))
    if tlla:
        p = p / ICMPv6NDOptDstLLAddr(lladdr=tlla)
    if not drop_inner:
        p = p / ICMPv6NDOptRedirectedHdr(
            pkt=IPv6(src=victim, dst=dst) / UDP())
    return Ether(bytes(p))   # round-trip so options parse as on the wire


def _na(tgt, lladdr, *, override=True, src="fe80::66"):
    return Ether(bytes(
        Ether(src=lladdr) / IPv6(src=src, dst="ff02::1", hlim=255)
        / ICMPv6ND_NA(tgt=tgt, O=1 if override else 0)
        / ICMPv6NDOptDstLLAddr(lladdr=lladdr)))


def _ns(src, lladdr, tgt="fe80::50"):
    return Ether(bytes(
        Ether(src=lladdr) / IPv6(src=src, dst="ff02::1:ff00:50", hlim=255)
        / ICMPv6ND_NS(tgt=tgt) / ICMPv6NDOptSrcLLAddr(lladdr=lladdr)))


def _redirect(src_ip, new_gw, *, src_mac=GW_MAC, code=1, ttl=64,
              inner_src=VICTIM, inner_dst=DEST, drop_inner=False,
              dst_ip=VICTIM):
    pkt = (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
           / IP(src=src_ip, dst=dst_ip, ttl=ttl)
           / ICMP(type=5, code=code, gw=new_gw))
    if not drop_inner:
        pkt = pkt / IP(src=inner_src, dst=inner_dst) / UDP(sport=1234, dport=53)
    return pkt


def _arp(psrc, hwsrc, *, op=2, gratuitous=False):
    pdst = psrc if gratuitous else "192.168.10.254"
    return Ether(src=hwsrc) / ARP(op=op, psrc=psrc, hwsrc=hwsrc,
                                  pdst=pdst, hwdst="ff:ff:ff:ff:ff:ff")


class Runner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name, cond, extra=""):
        if cond:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}   {extra}")

    def fresh(self):
        return ICMPRedirectDetector(CONFIG)


def _checks(findings):
    return {f.check for f in findings}


def _sev(findings, name):
    for f in findings:
        if f.check == name:
            return f.severity
    return None


def _detail(findings, name, key):
    for f in findings:
        if f.check == name:
            return f.details.get(key)
    return None


_ORDER = {SEV_INFO: 0, SEV_LOW: 1, SEV_MEDIUM: 2, SEV_HIGH: 3, SEV_CRITICAL: 4}


def _max(findings):
    if not findings:
        return SEV_INFO
    return max((f.severity for f in findings), key=lambda s: _ORDER[s])


def _ge(a, b):
    return _ORDER[a] >= _ORDER[b]


def run_self_test():
    r = Runner()
    print("icmpwatch self-test")
    print("=" * 60)

    # --- packet parsing ---------------------------------------------------
    print("[parse]")
    p = _redirect("192.168.10.1", "192.168.10.2")
    ev = packet_to_event(p, ts=1000.0)
    r.check("parse: recognizes redirect", ev is not None)
    r.check("parse: src_ip", ev.src_ip == "192.168.10.1")
    r.check("parse: src_mac", ev.src_mac == GW_MAC)
    r.check("parse: new_gw extracted", ev.new_gw == "192.168.10.2")
    r.check("parse: code", ev.icmp_code == 1)
    r.check("parse: inner_src (victim)", ev.inner_src == VICTIM)
    r.check("parse: inner_dst", ev.inner_dst == DEST)
    r.check("parse: ttl", ev.ip_ttl == 64)
    non_redirect = Ether() / IP() / ICMP(type=8)
    r.check("parse: ignores non-redirect ICMP",
            packet_to_event(non_redirect) is None)
    non_icmp = Ether() / IP() / TCP()
    r.check("parse: ignores non-ICMP", packet_to_event(non_icmp) is None)

    # --- legitimate redirect ---------------------------------------------
    print("[legit]")
    det = r.fresh()
    f = det.analyze(packet_to_event(_redirect("192.168.10.1", "192.168.10.2"),
                                    ts=1000.0))
    r.check("legit: no HIGH/CRITICAL", _max(f) in (SEV_INFO, SEV_LOW),
            extra=str(_checks(f)))
    r.check("legit: observed_redirect logged", "observed_redirect" in _checks(f))
    r.check("legit: source_not_gateway absent",
            "source_not_gateway" not in _checks(f))
    r.check("legit: mac_mismatch absent",
            "gateway_mac_mismatch" not in _checks(f))

    # --- source not a gateway --------------------------------------------
    print("[source_not_gateway]")
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect(ATTACKER, "192.168.10.66", src_mac=ATTACKER_MAC), ts=1000.0))
    r.check("rogue source: fires source_not_gateway",
            "source_not_gateway" in _checks(f))
    r.check("rogue source: severity HIGH+", _ge(_max(f), SEV_HIGH),
            extra=str(_checks(f)))

    # --- gateway IP spoof (MAC mismatch, config-sourced) -----------------
    print("[gateway_mac_mismatch]")
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=ATTACKER_MAC),
        ts=1000.0))
    r.check("mac spoof: fires gateway_mac_mismatch",
            "gateway_mac_mismatch" in _checks(f))
    r.check("mac spoof: CRITICAL", _sev(f, "gateway_mac_mismatch") == SEV_CRITICAL)
    r.check("mac spoof: expected_source is config",
            _detail(f, "gateway_mac_mismatch", "expected_source") == "config")
    r.check("mac spoof: not flagged as rogue source",
            "source_not_gateway" not in _checks(f))
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=1000.0))
    r.check("matching mac: no mismatch", "gateway_mac_mismatch" not in _checks(f))

    # --- new gateway off-subnet ------------------------------------------
    print("[new_gw_off_subnet]")
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "10.99.99.99"), ts=1000.0))
    r.check("off-subnet gw: fires new_gw_off_subnet",
            "new_gw_off_subnet" in _checks(f))
    r.check("off-subnet gw: HIGH", _sev(f, "new_gw_off_subnet") == SEV_HIGH)

    # --- new gateway is arbitrary host (MITM signature) ------------------
    print("[new_gw_not_router]")
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", ATTACKER), ts=1000.0))
    r.check("attacker gw: fires new_gw_not_router",
            "new_gw_not_router" in _checks(f))
    r.check("attacker gw: HIGH+", _ge(_max(f), SEV_HIGH))
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2"), ts=1000.0))
    r.check("known router gw: new_gw_not_router absent",
            "new_gw_not_router" not in _checks(f))

    # --- degenerate targets ----------------------------------------------
    print("[degenerate]")
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.1"), ts=1000.0))
    r.check("gw==source: fires", "new_gw_equals_source" in _checks(f))
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", VICTIM), ts=1000.0))
    r.check("gw==victim: fires", "new_gw_equals_victim" in _checks(f))

    # --- invalid code -----------------------------------------------------
    print("[invalid_code]")
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", code=7), ts=1000.0))
    r.check("code 7: fires invalid_code", "invalid_code" in _checks(f))
    for c in (0, 1, 2, 3):
        det = r.fresh()
        f = det.analyze(packet_to_event(
            _redirect("192.168.10.1", "192.168.10.2", code=c), ts=1000.0))
        r.check(f"code {c}: valid, no invalid_code",
                "invalid_code" not in _checks(f))

    # --- malformed / missing inner ---------------------------------------
    print("[malformed]")
    det = r.fresh()
    ev = packet_to_event(_redirect("192.168.10.1", "192.168.10.2",
                                   drop_inner=True), ts=1000.0)
    r.check("no inner: parses without crash", ev is not None)
    f = det.analyze(ev)
    r.check("no inner: fires malformed", "malformed_redirect" in _checks(f))

    # --- TTL heuristic ----------------------------------------------------
    print("[ttl_heuristic]")
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", ttl=64), ts=1000.0))
    r.check("ttl 64 (local): no ttl finding",
            "ttl_suggests_remote" not in _checks(f))
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", ttl=45), ts=1000.0))
    r.check("ttl 45 (remote): fires ttl_suggests_remote",
            "ttl_suggests_remote" in _checks(f))
    det2 = ICMPRedirectDetector({**CONFIG, "enable_ttl_heuristic": False})
    f = det2.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", ttl=45), ts=1000.0))
    r.check("ttl disabled: no ttl finding",
            "ttl_suggests_remote" not in _checks(f))

    # --- rate burst -------------------------------------------------------
    print("[rate_burst]")
    det = r.fresh()
    last = []
    for i in range(5):
        last = det.analyze(packet_to_event(
            _redirect("192.168.10.1", "192.168.10.2"), ts=1000.0 + i))
    r.check("burst: 5th within window fires redirect_burst",
            "redirect_burst" in _checks(last))
    det = r.fresh()
    for i in range(5):
        last = det.analyze(packet_to_event(
            _redirect("192.168.10.1", "192.168.10.2"), ts=1000.0 + i * 100))
    r.check("spread: no burst when outside window",
            "redirect_burst" not in _checks(last))

    # --- destination sweep -----------------------------------------------
    print("[dest_sweep]")
    det = r.fresh()
    for i, d in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]):
        last = det.analyze(packet_to_event(
            _redirect("192.168.10.1", "192.168.10.2", inner_dst=d),
            ts=1000.0 + i))
    r.check("sweep: 4 distinct dsts fires redirect_dest_sweep",
            "redirect_dest_sweep" in _checks(last))

    # --- victim outside known segments -----------------------------------
    print("[unknown_victim]")
    det = r.fresh()
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", ATTACKER, inner_src="172.16.0.5"), ts=1000.0))
    r.check("unknown victim: still evaluates new_gw_not_router",
            "new_gw_not_router" in _checks(f))

    # --- no-config degraded mode -----------------------------------------
    print("[no_config]")
    det = ICMPRedirectDetector({})
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2"), ts=1000.0))
    r.check("no config: does not raise, logs observed_redirect",
            "observed_redirect" in _checks(f))
    r.check("no config: suppresses gateway-dependent checks",
            "source_not_gateway" not in _checks(f))

    # ====================  ARP CORRELATION  ==============================

    # --- ARP packet parsing ----------------------------------------------
    print("[arp_parse]")
    obs = arp_packet_to_obs(_arp("192.168.10.1", GW_MAC))
    r.check("arp parse: extracts (ip,mac,grat)",
            obs == ("192.168.10.1", GW_MAC, False))
    obs = arp_packet_to_obs(_arp("192.168.10.1", GW_MAC, gratuitous=True))
    r.check("arp parse: flags gratuitous", obs == ("192.168.10.1", GW_MAC, True))
    r.check("arp parse: ignores non-ARP",
            arp_packet_to_obs(Ether() / IP() / TCP()) is None)

    # --- MAC learned from ARP fills in for absent config MAC -------------
    print("[arp_mac_from_wire]")
    det = ICMPRedirectDetector(CONFIG_NOMAC)
    det.observe_arp("192.168.10.1", GW_MAC, ts=900.0)
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=ATTACKER_MAC),
        ts=1000.0))
    r.check("arp mac: mismatch fires when packet MAC != learned",
            "gateway_mac_mismatch" in _checks(f))
    r.check("arp mac: expected_source is arp",
            _detail(f, "gateway_mac_mismatch", "expected_source") == "arp")
    det = ICMPRedirectDetector(CONFIG_NOMAC)
    det.observe_arp("192.168.10.1", GW_MAC, ts=900.0)
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=1000.0))
    r.check("arp mac: no mismatch when packet MAC == learned",
            "gateway_mac_mismatch" not in _checks(f))

    # --- config MAC stays authoritative by default -----------------------
    print("[arp_config_authoritative]")
    det = r.fresh()
    det.observe_arp("192.168.10.1", GW_MAC, ts=900.0)
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=1000.0))
    r.check("config auth: clean packet stays clean",
            "gateway_mac_mismatch" not in _checks(f)
            and "gateway_arp_conflict" not in _checks(f))

    # --- prefer_arp_over_config ------------------------------------------
    print("[arp_prefer]")
    det = ICMPRedirectDetector(CONFIG_PREFER)
    det.observe_arp("192.168.10.1", GW_MAC, ts=900.0)  # wire says GW_MAC
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=1000.0))
    r.check("prefer arp: packet matching wire MAC is clean",
            "gateway_mac_mismatch" not in _checks(f))
    det = ICMPRedirectDetector(CONFIG_PREFER)
    det.observe_arp("192.168.10.1", GW_MAC, ts=900.0)
    f = det.analyze(packet_to_event(  # packet uses the stale config MAC
        _redirect("192.168.10.1", "192.168.10.2",
                  src_mac="aa:aa:aa:aa:aa:99"), ts=1000.0))
    r.check("prefer arp: stale config MAC now flagged",
            "gateway_mac_mismatch" in _checks(f))

    # --- gateway ARP binding contested (poison-then-redirect) ------------
    print("[gateway_arp_conflict]")
    det = r.fresh()
    det.observe_arp("192.168.10.1", GW_MAC, ts=800.0)              # real
    det.observe_arp("192.168.10.1", ATTACKER_MAC, ts=810.0,
                    gratuitous=True)                               # poison
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=900.0))
    r.check("arp conflict: fires gateway_arp_conflict",
            "gateway_arp_conflict" in _checks(f))
    r.check("arp conflict: CRITICAL",
            _sev(f, "gateway_arp_conflict") == SEV_CRITICAL)
    r.check("arp conflict: reason is arp_conflict",
            _detail(f, "gateway_arp_conflict", "reason") == "arp_conflict")

    # --- a foreign MAC ages out of the window ----------------------------
    print("[arp_conflict_window]")
    det = r.fresh()  # .1 config MAC = GW_MAC, so GW_MAC is the legitimate set
    det.observe_arp("192.168.10.1", ATTACKER_MAC, ts=100.0)  # foreign, transient
    det.observe_arp("192.168.10.1", GW_MAC, ts=500.0)        # legit, current
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=501.0))
    r.check("conflict window: aged-out foreign MAC no longer conflicts",
            "gateway_arp_conflict" not in _checks(f))
    # and while both are live, it does conflict
    det = r.fresh()
    det.observe_arp("192.168.10.1", GW_MAC, ts=400.0)
    det.observe_arp("192.168.10.1", ATTACKER_MAC, ts=450.0)
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=500.0))
    r.check("conflict window: foreign MAC live within window conflicts",
            "gateway_arp_conflict" in _checks(f))

    # --- declared multi-MAC gateway (GLBP) is not a conflict -------------
    print("[arp_expected_macs]")
    det = ICMPRedirectDetector(CONFIG_GLBP)
    for i, m in enumerate(GLBP_MACS):
        det.observe_arp("192.168.10.1", m, ts=800.0 + i)  # all four vMACs live
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GLBP_MACS[0]),
        ts=900.0))
    r.check("glbp: all declared vMACs live is not a conflict",
            "gateway_arp_conflict" not in _checks(f))
    r.check("glbp: redirect from a declared vMAC is not a mismatch",
            "gateway_mac_mismatch" not in _checks(f))
    # a MAC outside the declared set, even one live alongside the vMACs, trips it
    det = ICMPRedirectDetector(CONFIG_GLBP)
    for i, m in enumerate(GLBP_MACS):
        det.observe_arp("192.168.10.1", m, ts=800.0 + i)
    det.observe_arp("192.168.10.1", ATTACKER_MAC, ts=805.0)  # foreign
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GLBP_MACS[1]),
        ts=900.0))
    r.check("glbp: a MAC outside the declared set conflicts",
            "gateway_arp_conflict" in _checks(f))
    r.check("glbp: redirect from an undeclared MAC is a mismatch",
            "gateway_mac_mismatch" in _checks(
                ICMPRedirectDetector(CONFIG_GLBP).analyze(packet_to_event(
                    _redirect("192.168.10.1", "192.168.10.2",
                              src_mac=ATTACKER_MAC), ts=900.0))))

    # --- an FHRP OUI grants no immunity (evasion hole closed) ------------
    print("[arp_no_evasion]")
    det = r.fresh()  # single-MAC gateway .1 (GW_MAC); no OUI allowlist anymore
    det.observe_arp("192.168.10.1", GW_MAC, ts=800.0)
    det.observe_arp("192.168.10.1", "00:00:5e:00:01:0a", ts=810.0)  # VRRP-OUI
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=900.0))
    r.check("no evasion: a VRRP-OUI MAC outside the set still conflicts",
            "gateway_arp_conflict" in _checks(f))

    # --- redirect pointing at a poisoned gateway -------------------------
    print("[redirect_via_poisoned_gw]")
    det = r.fresh()
    det.observe_arp("192.168.10.2", GW2_MAC, ts=800.0)             # real
    det.observe_arp("192.168.10.2", ATTACKER_MAC, ts=810.0)        # contender
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=900.0))
    r.check("poisoned target: fires redirect_via_poisoned_gw",
            "redirect_via_poisoned_gw" in _checks(f))
    r.check("poisoned target: CRITICAL",
            _sev(f, "redirect_via_poisoned_gw") == SEV_CRITICAL)
    # config-drift variant: single clean-but-wrong MAC on the target gateway
    det = r.fresh()
    det.observe_arp("192.168.10.2", ATTACKER_MAC, ts=800.0)
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=GW_MAC), ts=900.0))
    r.check("target drift: current MAC != configured fires poisoned_gw",
            "redirect_via_poisoned_gw" in _checks(f))

    # --- ARP snapshot ingest (e.g. from arp_guard) -----------------------
    print("[arp_snapshot]")
    det = ICMPRedirectDetector(CONFIG_NOMAC)
    det.load_arp_snapshot({"192.168.10.1": GW_MAC}, ts=900.0)
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=ATTACKER_MAC),
        ts=1000.0))
    r.check("snapshot: ingested MAC drives mismatch",
            "gateway_mac_mismatch" in _checks(f))

    # --- ARP correlation disabled degrades cleanly -----------------------
    print("[arp_disabled]")
    det = ICMPRedirectDetector({**CONFIG_NOMAC,
                                "arp_correlation": {"enabled": False}})
    det.observe_arp("192.168.10.1", GW_MAC, ts=900.0)  # ignored
    f = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2", src_mac=ATTACKER_MAC),
        ts=1000.0))
    r.check("disabled: no ARP-derived mismatch",
            "gateway_mac_mismatch" not in _checks(f))
    r.check("disabled: no ARP conflict findings",
            "gateway_arp_conflict" not in _checks(f)
            and "redirect_via_poisoned_gw" not in _checks(f))

    # ====================  ICMPv6 / NEIGHBOR DISCOVERY  ==================

    # --- v6 parsing -------------------------------------------------------
    print("[v6_parse]")
    ev = packet_to_event(_redirect6(GW_LL, R2_LL, V6_DEST), ts=1000.0)
    r.check("v6 parse: recognizes redirect", ev is not None)
    r.check("v6 parse: family is 6", ev.family == 6)
    r.check("v6 parse: src is router link-local", ev.src_ip == GW_LL)
    r.check("v6 parse: Target -> new_gw", ev.new_gw == R2_LL)
    r.check("v6 parse: Destination -> inner_dst", ev.inner_dst == V6_DEST)
    r.check("v6 parse: victim from Redirected Header",
            ev.inner_src == V6_VICTIM)
    r.check("v6 parse: hop limit", ev.ip_ttl == 255)
    ev2 = packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, tlla=GW2_MAC), ts=1000.0)
    r.check("v6 parse: Target LLA option", ev2.target_lla == GW2_MAC)
    # Redirected Header is SHOULD, not MUST — absence is not malformed
    ev3 = packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, drop_inner=True), ts=1000.0)
    r.check("v6 parse: missing Redirected Header is not malformed",
            ev3 is not None and not ev3.malformed)
    r.check("v6 parse: victim falls back to L3 destination",
            ev3.inner_src is None and ev3.dst_ip == V6_VICTIM)
    r.check("v6 parse: v4 redirect still parses as family 4",
            packet_to_event(_redirect("192.168.10.1", "192.168.10.2"),
                            ts=1000.0).family == 4)

    # --- legitimate v6 redirect ------------------------------------------
    print("[v6_legit]")
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST), ts=1000.0))
    r.check("v6 legit: no HIGH/CRITICAL", _max(f) in (SEV_INFO, SEV_LOW),
            extra=str(_checks(f)))
    # the trap: a link-local Target is outside the victim's GUA prefix by
    # design, so the IPv4 subnet rule must not be applied to v6
    r.check("v6 legit: new_gw_off_subnet suppressed for link-local Target",
            "new_gw_off_subnet" not in _checks(f))
    r.check("v6 legit: link-local gateway resolves despite prefix mismatch",
            "source_not_gateway" not in _checks(f))
    r.check("v6 legit: known link-local router accepted as Target",
            "new_gw_not_router" not in _checks(f))

    # --- RFC 4861 hop limit 255 ------------------------------------------
    print("[v6_hop_limit]")
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, hlim=64), ts=1000.0))
    r.check("v6 hlim 64: fires nd_hop_limit_invalid",
            "nd_hop_limit_invalid" in _checks(f))
    r.check("v6 hlim 64: HIGH", _sev(f, "nd_hop_limit_invalid") == SEV_HIGH)
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, hlim=255), ts=1000.0))
    r.check("v6 hlim 255: clean",
            "nd_hop_limit_invalid" not in _checks(f))
    # the v4 TTL heuristic must not double-fire on v6
    det = ICMPRedirectDetector({**CONFIG_V6, "enable_ttl_heuristic": True,
                                "expected_local_ttls": [64]})
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, hlim=255), ts=1000.0))
    r.check("v6: IPv4 TTL heuristic suppressed",
            "ttl_suggests_remote" not in _checks(f))

    # --- source must be link-local ---------------------------------------
    print("[v6_source_link_local]")
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6("2001:db8::7", R2_LL, V6_DEST), ts=1000.0))
    r.check("v6 GUA source: fires nd_source_not_link_local",
            "nd_source_not_link_local" in _checks(f))
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST), ts=1000.0))
    r.check("v6 link-local source: no finding",
            "nd_source_not_link_local" not in _checks(f))

    # --- Target address validity (RFC 4861 §8.1) -------------------------
    print("[v6_target_valid]")
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, "2001:db8::66", V6_DEST), ts=1000.0))
    r.check("v6 GUA target != dest: fires nd_target_invalid",
            "nd_target_invalid" in _checks(f))
    # on-link form: Target == Destination is legitimate per RFC 4861
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, V6_DEST, V6_DEST), ts=1000.0))
    r.check("v6 on-link form: nd_target_invalid suppressed",
            "nd_target_invalid" not in _checks(f))
    r.check("v6 on-link form: new_gw_not_router suppressed (Target is a host)",
            "new_gw_not_router" not in _checks(f))
    r.check("v6 on-link form: no HIGH/CRITICAL", _max(f) in (SEV_INFO, SEV_LOW),
            extra=str(_checks(f)))

    # --- Target Link-Layer Address correlation ---------------------------
    print("[v6_target_lla]")
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, tlla=ATTACKER_MAC), ts=1000.0))
    r.check("v6 bad TLLA: fires nd_target_lla_mismatch",
            "nd_target_lla_mismatch" in _checks(f))
    r.check("v6 bad TLLA: CRITICAL",
            _sev(f, "nd_target_lla_mismatch") == SEV_CRITICAL)
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, tlla=GW2_MAC), ts=1000.0))
    r.check("v6 correct TLLA: no mismatch",
            "nd_target_lla_mismatch" not in _checks(f))

    # --- v6 code must be 0 ------------------------------------------------
    print("[v6_code]")
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, code=0), ts=1000.0))
    r.check("v6 code 0: valid", "invalid_code" not in _checks(f))
    det = ICMPRedirectDetector(CONFIG_V6)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, code=1), ts=1000.0))
    r.check("v6 code 1: invalid (valid in v4, not v6)",
            "invalid_code" in _checks(f))

    # --- NDP binding parsing ---------------------------------------------
    print("[v6_ndp_parse]")
    r.check("ndp: NA with Override -> gratuitous binding",
            ndp_packet_to_obs(_na(GW_LL, ATTACKER_MAC, override=True))
            == (GW_LL, ATTACKER_MAC, True))
    r.check("ndp: NA without Override -> non-gratuitous",
            ndp_packet_to_obs(_na(GW_LL, GW_MAC, override=False))
            == (GW_LL, GW_MAC, False))
    r.check("ndp: NS -> sender binding",
            ndp_packet_to_obs(_ns(GW_LL, GW_MAC)) == (GW_LL, GW_MAC, False))
    dad = Ether(bytes(Ether(src=GW_MAC) / IPv6(src="::", dst="ff02::1:ff00:50",
                                               hlim=255)
                      / ICMPv6ND_NS(tgt="fe80::50")))
    r.check("ndp: DAD (unspecified source) is not a binding",
            ndp_packet_to_obs(dad) is None)
    # a redirect's own Target LLA must never be a learning source, or a forged
    # redirect would validate itself
    r.check("ndp: Redirect is not a learning source",
            ndp_packet_to_obs(
                _redirect6(GW_LL, R2_LL, V6_DEST, tlla=ATTACKER_MAC)) is None)
    r.check("ndp: ignores ARP",
            ndp_packet_to_obs(_arp("192.168.10.1", GW_MAC)) is None)

    # --- v6 NDP correlation ----------------------------------------------
    print("[v6_ndp_correlation]")
    det = ICMPRedirectDetector(CONFIG_V6)
    for pkt in (_na(GW_LL, GW_MAC, override=False),
                _na(GW_LL, ATTACKER_MAC, override=True)):
        ip, mac, ov = ndp_packet_to_obs(pkt)
        det.observe_arp(ip, mac, ts=800.0, gratuitous=ov)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, V6_ATTACKER_LL, V6_DEST, src_mac=ATTACKER_MAC),
        ts=900.0))
    r.check("v6 poison-then-redirect: gateway_arp_conflict",
            "gateway_arp_conflict" in _checks(f))
    r.check("v6 poison-then-redirect: gateway_mac_mismatch",
            "gateway_mac_mismatch" in _checks(f))
    r.check("v6 poison-then-redirect: new_gw_not_router",
            "new_gw_not_router" in _checks(f))
    r.check("v6 poison-then-redirect: CRITICAL", _max(f) == SEV_CRITICAL)
    # clean NDP traffic leaves a legitimate redirect clean
    det = ICMPRedirectDetector(CONFIG_V6)
    ip, mac, ov = ndp_packet_to_obs(_na(GW_LL, GW_MAC, override=False))
    det.observe_arp(ip, mac, ts=800.0, gratuitous=ov)
    f = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST), ts=900.0))
    r.check("v6 clean NDP: legitimate redirect stays clean",
            _max(f) in (SEV_INFO, SEV_LOW), extra=str(_checks(f)))

    # --- ipv6 disabled: capture scope, not comprehension -----------------
    print("[v6_disabled]")
    d_off = ICMPRedirectDetector({**CONFIG_DUAL, "ipv6": {"enabled": False}})
    r.check("v6 disabled: v4 traffic unaffected",
            "observed_redirect" in _checks(d_off.analyze(packet_to_event(
                _redirect("192.168.10.1", "192.168.10.2"), ts=1000.0))))
    # The flag gates what the BPF filter captures, not what analyze()
    # understands. A v6 event fed in directly is still evaluated — failing
    # open here would hide an attack rather than merely narrow capture.
    f = d_off.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST, hlim=64), ts=1001.0))
    r.check("v6 disabled: a v6 event fed directly is still analyzed",
            "nd_hop_limit_invalid" in _checks(f))

    # --- dual-stack coexistence ------------------------------------------
    print("[dual_stack]")
    det = ICMPRedirectDetector(CONFIG_DUAL)
    f4 = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2"), ts=1000.0))
    f6 = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST), ts=1001.0))
    r.check("dual: legitimate v4 redirect clean",
            _max(f4) in (SEV_INFO, SEV_LOW), extra=str(_checks(f4)))
    r.check("dual: legitimate v6 redirect clean",
            _max(f6) in (SEV_INFO, SEV_LOW), extra=str(_checks(f6)))
    # one binding table serves both families; v4 and v6 keys never collide
    det = ICMPRedirectDetector(CONFIG_DUAL)
    det.observe_arp("192.168.10.1", ATTACKER_MAC, ts=800.0)   # v4 poison
    ip, mac, ov = ndp_packet_to_obs(_na(GW_LL, GW_MAC, override=False))
    det.observe_arp(ip, mac, ts=800.0, gratuitous=ov)         # v6 clean
    f4 = det.analyze(packet_to_event(
        _redirect("192.168.10.1", "192.168.10.2"), ts=900.0))
    f6 = det.analyze(packet_to_event(
        _redirect6(GW_LL, R2_LL, V6_DEST), ts=901.0))
    r.check("dual: v4 poison detected", "gateway_arp_conflict" in _checks(f4))
    r.check("dual: v6 unaffected by the v4 poison",
            "gateway_arp_conflict" not in _checks(f6))

    # --- BPF filter composition ------------------------------------------
    print("[v6_filter]")
    filt = _build_filter(ICMPRedirectDetector(CONFIG_V6))
    r.check("filter: includes v4 redirects", "icmp[icmptype] == 5" in filt)
    r.check("filter: includes ND redirect (137)", "ip6[40] == 137" in filt)
    r.check("filter: includes NS/NA (135/136) when correlation is on",
            "ip6[40] == 135" in filt and "ip6[40] == 136" in filt)
    d_v4 = ICMPRedirectDetector({**CONFIG_V6, "ipv6": {"enabled": False}})
    r.check("filter: v6 off reproduces the v4-only filter",
            _build_filter(d_v4) == "icmp[icmptype] == 5 or arp")
    fn = _build_filter(ICMPRedirectDetector(
        {**CONFIG_V6, "arp_correlation": {"enabled": False}}))
    r.check("filter: no NS/NA when correlation is off",
            "ip6[40] == 137" in fn and "ip6[40] == 135" not in fn)

    print("=" * 60)
    total = r.passed + r.failed
    print(f"{r.passed}/{total} self-tests passed")
    return r.failed == 0


if __name__ == "__main__":
    sys.exit(0 if run_self_test() else 1)
