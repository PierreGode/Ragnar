#!/usr/bin/env python3
# icmpwatch_selftest.py — Scapy self-test harness for icmpwatch.
#
# Crafts ICMP Redirect (and ARP) packets in-memory and runs them through the
# detector, asserting on the emitted findings. No interface, no wire traffic.
# Mirrors the self-test style used across the Ragnar suite.

import sys
from scapy.all import Ether, IP, ICMP, UDP, TCP, ARP

from icmpwatch import (
    ICMPRedirectDetector, packet_to_event, arp_packet_to_obs,
    SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL,
)

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

    print("=" * 60)
    total = r.passed + r.failed
    print(f"{r.passed}/{total} self-tests passed")
    return r.failed == 0


if __name__ == "__main__":
    sys.exit(0 if run_self_test() else 1)
