#!/usr/bin/env python3
# icmpwatch.py — passive ICMP Redirect (Type 5) security monitor
#
# Part of the Ragnar network engineering toolbox.
# Design philosophy: passive-first, detection-only. No packets are ever
# emitted onto the wire by this module. It observes ICMP Redirect traffic on
# a mirror/SPAN port or inline bridge tap and flags route-hijack attempts.
#
# Threat model
# ------------
# ICMP Redirect (RFC 792) lets a first-hop gateway tell a host "for
# destination D, use gateway B instead of me." An attacker on the local
# segment can forge these to install themselves as B — a silent L3 MITM that
# needs no ARP poisoning and leaves the victim's ARP table untouched.
#
# RFC 1122 §3.2.2.2 constrains when a *host* may honor a redirect:
#   - it must originate from the gateway currently in use for that destination
#   - the new gateway must be on a directly-connected network
#   - hosts (not routers) may accept them; routers must not
# Linux enforces a subset via secure_redirects/accept_redirects, but plenty of
# gear on a shared segment (IoT, embedded, legacy medical endpoints, some
# Windows builds) still honors redirects unconditionally. icmpwatch externalizes
# the RFC 1122 acceptance rules and watches the wire for violations on behalf
# of every host on the segment, including the ones that would never check.
#
# Platform note (Pi Zero 2W): redirects are low-volume, and the BPF prefilter
# (icmp[icmptype]==5) drops everything else in-kernel, so userspace load stays
# trivial even on the A53. Use promiscuous capture on the SPAN-fed USB NIC.

import argparse
import ipaddress
import json
import logging
import sys
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Optional

SEV_INFO = "INFO"
SEV_LOW = "LOW"
SEV_MEDIUM = "MEDIUM"
SEV_HIGH = "HIGH"
SEV_CRITICAL = "CRITICAL"

_SEV_ORDER = {SEV_INFO: 0, SEV_LOW: 1, SEV_MEDIUM: 2, SEV_HIGH: 3, SEV_CRITICAL: 4}

ICMP_REDIRECT = 5
VALID_REDIRECT_CODES = {0, 1, 2, 3}  # net, host, ToS+net, ToS+host


@dataclass
class Finding:
    check: str
    severity: str
    message: str
    details: dict = field(default_factory=dict)


@dataclass
class RedirectEvent:
    """Normalized view of one observed ICMP Redirect."""
    ts: float
    src_ip: Optional[str]       # who sent the redirect
    src_mac: Optional[str]
    dst_ip: Optional[str]       # who it was aimed at (the victim host)
    dst_mac: Optional[str]
    ip_ttl: Optional[int]
    icmp_code: Optional[int]
    new_gw: Optional[str]       # gateway the redirect wants installed
    inner_src: Optional[str]    # original datagram source (the affected host)
    inner_dst: Optional[str]    # destination being redirected
    inner_proto: Optional[int]
    malformed: bool = False


@dataclass
class ArpEntry:
    mac: str
    first_seen: float
    last_seen: float
    macs: dict = field(default_factory=dict)   # mac -> last_seen ts
    prev_mac: Optional[str] = None
    last_change_ts: float = 0.0
    last_change_gratuitous: bool = False


class ArpTable:
    """Passive IP->MAC binding tracker with contention awareness.

    Deliberately NOT a full ARP IDS (that is arp_guard's job). It answers only
    what icmpwatch needs when a redirect arrives:
      - what MAC currently backs this gateway IP?  (mac_for)
      - is that binding trustworthy right now, or contested?  (suspect)

    Contention is judged against the gateway's declared legitimate MAC set
    (config ground truth). Any live MAC outside that set is a conflict; when no
    set is declared, two or more live claimants are required before the
    ambiguity itself counts. This lets a genuinely multi-MAC first hop (GLBP, or
    use-bia HSRP) be declared explicitly, rather than blanket-trusting an OUI
    range an attacker on a VRRP segment could simply borrow.
    """

    def __init__(self, window_seconds=300.0):
        self.window = float(window_seconds)
        self.entries = {}

    def observe(self, ip, mac, ts, gratuitous=False):
        if ip is None or mac is None:
            return
        mac = mac.lower()
        e = self.entries.get(ip)
        if e is None:
            self.entries[ip] = ArpEntry(mac=mac, first_seen=ts, last_seen=ts,
                                        macs={mac: ts})
            return
        e.macs[mac] = ts
        if mac != e.mac:
            e.prev_mac = e.mac
            e.mac = mac
            e.last_change_ts = ts
            e.last_change_gratuitous = gratuitous
        e.last_seen = ts

    def load_snapshot(self, mapping, ts=None):
        """Ingest an authoritative IP->MAC map (e.g. pushed from arp_guard)."""
        ts = time.time() if ts is None else ts
        for ip, mac in mapping.items():
            self.observe(ip, mac, ts)

    def mac_for(self, ip):
        e = self.entries.get(ip)
        return e.mac if e else None

    def competing_macs(self, ip, now, expected=None):
        """Live in-window MACs for this IP that are not in the legitimate set."""
        e = self.entries.get(ip)
        if not e:
            return set()
        expected = expected or set()
        cutoff = now - self.window
        live = {mac for mac, seen in e.macs.items() if seen >= cutoff}
        return live - expected

    def suspect(self, ip, now, expected=None):
        """Return (reason, details) if this IP's L2 binding is untrustworthy.

        `expected` is the config-declared legitimate MAC set (ground truth).
        When it is known, any live MAC outside it is a conflict — a single
        foreign claimant is enough, since we know what belongs. When it is
        empty, we have no ground truth, so two or more live claimants are
        required before the ambiguity itself counts as a conflict.
        """
        e = self.entries.get(ip)
        if not e:
            return None
        expected = expected or set()
        foreign = self.competing_macs(ip, now, expected)
        if expected:
            if foreign:
                return ("arp_conflict",
                        {"competing_macs": sorted(foreign),
                         "expected_macs": sorted(expected)})
        elif len(foreign) >= 2:
            return ("arp_conflict", {"competing_macs": sorted(foreign)})
        # a gratuitous ARP that flipped an established binding to a MAC that is
        # not legitimate — catches a silent overwrite the conflict rule misses
        # when the displaced host goes quiet
        if (e.last_change_gratuitous and e.prev_mac is not None
                and (now - e.last_change_ts) <= self.window
                and (not expected or e.mac not in expected)):
            return ("gratuitous_overwrite",
                    {"old_mac": e.prev_mac, "new_mac": e.mac})
        return None


class ICMPRedirectDetector:
    """Stateful analyzer. Feed it RedirectEvents (or Scapy packets via
    analyze_packet) and it returns a list[Finding] per event."""

    def __init__(self, config: dict):
        cfg = config or {}
        self.segments = []
        self._gw_expected = {}   # ip -> set of legitimate MACs (config truth)
        for seg in cfg.get("segments", []):
            net = ipaddress.ip_network(seg["cidr"], strict=False)
            gws = {}
            for gw in seg.get("gateways", []):
                ip = gw["ip"]
                gw_mac = gw.get("mac")
                gws[ip] = gw_mac.lower() if gw_mac else None
                # a gateway's legitimate MAC set: expected_macs if declared (for
                # multi-MAC first hops — GLBP, use-bia HSRP), else the single
                # mac, else empty (learned from the wire at runtime)
                exp = gw.get("expected_macs")
                if exp:
                    self._gw_expected[ip] = {m.lower() for m in exp}
                elif gw_mac:
                    self._gw_expected[ip] = {gw_mac.lower()}
                else:
                    self._gw_expected[ip] = set()
            routers = {r.lower() if r else r for r in seg.get("routers", [])}
            # every configured gateway is implicitly also a legitimate router
            routers |= set(gws.keys())
            self.segments.append({"net": net, "gateways": gws, "routers": routers})

        thr = cfg.get("thresholds", {})
        self.window = float(thr.get("window_seconds", 10.0))
        self.burst_per_src = int(thr.get("burst_per_src", 5))
        self.dest_diversity = int(thr.get("dest_diversity", 4))
        self.enable_ttl_heuristic = bool(cfg.get("enable_ttl_heuristic", False))
        # initial TTLs we'd expect from a directly-connected gateway (0 hops)
        self.local_ttls = set(cfg.get("expected_local_ttls", [64, 255, 128]))
        self.ttl_slack = int(cfg.get("ttl_slack", 2))  # allow a couple hops of slack

        # sliding-window history: (ts, src_ip, inner_dst)
        self._hist = deque()

        # ---- ARP correlation ----
        arp_cfg = cfg.get("arp_correlation", {})
        self.arp_enabled = bool(arp_cfg.get("enabled", True))
        self.arp_prefer = bool(arp_cfg.get("prefer_arp_over_config", False))
        self.arp = ArpTable(
            window_seconds=float(arp_cfg.get("conflict_window_seconds", 300.0)),
        )

    # ---- ARP correlation helpers ----------------------------------------

    def observe_arp(self, ip, mac, ts=None, gratuitous=False):
        if not self.arp_enabled:
            return
        ts = time.time() if ts is None else ts
        self.arp.observe(ip, mac, ts, gratuitous=gratuitous)

    def load_arp_snapshot(self, mapping, ts=None):
        if not self.arp_enabled:
            return
        self.arp.load_snapshot(mapping, ts=ts)

    def _arp_suspect(self, ip, now):
        if not self.arp_enabled or ip is None:
            return None
        return self.arp.suspect(ip, now, self._contention_expected(ip))

    def _config_expected(self, ip):
        """Config-declared legitimate MAC set for a gateway IP (ground truth)."""
        return set(self._gw_expected.get(ip, ()))

    def _contention_expected(self, ip):
        """Ground truth for ARP contention. Empty when prefer_arp_over_config is
        set (config MACs are then declared unreliable) or when none is declared —
        either way contention drops back to the two-live-claimants rule."""
        if self.arp_prefer:
            return set()
        return self._config_expected(ip)

    def _expected_macs(self, ip):
        """Return (macs, source): the set the redirect's source MAC should be a
        member of. Config is authoritative unless prefer_arp_over_config is set;
        a learned ARP binding fills in when config declares no MAC at all."""
        cfg = self._config_expected(ip)
        learned = self.arp.mac_for(ip) if self.arp_enabled else None
        if self.arp_prefer and learned:
            return {learned}, "arp"
        if cfg:
            return cfg, "config"
        if learned:
            return {learned}, "arp"
        return set(), None

    # ---- segment helpers -------------------------------------------------

    def _segment_of(self, ip: Optional[str]):
        if not ip:
            return None
        addr = ipaddress.ip_address(ip)
        for seg in self.segments:
            if addr in seg["net"]:
                return seg
        return None

    def _is_known_gateway(self, ip):
        seg = self._segment_of(ip)
        return bool(seg and ip in seg["gateways"])

    def _is_known_router(self, ip):
        seg = self._segment_of(ip)
        return bool(seg and ip in seg["routers"])

    # ---- core analysis ---------------------------------------------------

    def analyze(self, ev: RedirectEvent) -> list:
        findings = []

        if ev.malformed or ev.icmp_code is None or ev.new_gw is None:
            findings.append(Finding(
                "malformed_redirect", SEV_MEDIUM,
                "ICMP Redirect could not be fully parsed",
                {"src_ip": ev.src_ip, "code": ev.icmp_code, "new_gw": ev.new_gw},
            ))
            # still record for rate accounting if we have a source
            self._record(ev)
            return findings

        # 1) valid redirect code
        if ev.icmp_code not in VALID_REDIRECT_CODES:
            findings.append(Finding(
                "invalid_code", SEV_MEDIUM,
                f"ICMP Redirect with reserved/invalid code {ev.icmp_code}",
                {"src_ip": ev.src_ip, "code": ev.icmp_code},
            ))

        # The victim host that would honor this is the inner datagram source.
        # Fall back to the redirect's L3 destination if the inner header is thin.
        victim = ev.inner_src or ev.dst_ip

        # 2) source must be a gateway the segment actually uses (RFC 1122)
        if self.segments:
            if not self._is_known_gateway(ev.src_ip):
                findings.append(Finding(
                    "source_not_gateway", SEV_HIGH,
                    "Redirect from a host that is not a configured gateway "
                    "for its segment",
                    {"src_ip": ev.src_ip, "victim": victim, "new_gw": ev.new_gw},
                ))
            else:
                # 3) source IP is a known gateway — verify its L2 identity to
                #    catch a spoofer forging the gateway IP from a different NIC.
                #    Expected MAC comes from config, or (config absent / ARP
                #    preferred) the learned ARP binding — but an ARP-derived
                #    value is only trusted when that binding is not itself
                #    contested (a poisoned binding is handled by check 5b).
                expected, exp_src = self._expected_macs(ev.src_ip)
                arp_clean = (exp_src != "arp"
                             or self._arp_suspect(ev.src_ip, ev.ts) is None)
                if (expected and ev.src_mac and arp_clean
                        and ev.src_mac.lower() not in expected):
                    findings.append(Finding(
                        "gateway_mac_mismatch", SEV_CRITICAL,
                        "Redirect claims a known gateway IP but the source MAC "
                        "is not among its expected MACs — likely IP spoofing / "
                        "impersonation",
                        {"src_ip": ev.src_ip, "src_mac": ev.src_mac,
                         "expected_macs": sorted(expected),
                         "expected_source": exp_src},
                    ))

        # 4) new gateway must be directly connected to the victim's segment
        vseg = self._segment_of(victim)
        if vseg is not None:
            if ipaddress.ip_address(ev.new_gw) not in vseg["net"]:
                findings.append(Finding(
                    "new_gw_off_subnet", SEV_HIGH,
                    "Redirect points to a new gateway outside the victim's "
                    "subnet — violates RFC 1122 directly-connected rule",
                    {"victim": victim, "new_gw": ev.new_gw,
                     "victim_subnet": str(vseg["net"])},
                ))

        # 5) new gateway should be a known router, not an arbitrary host.
        #    This is the classic MITM signature: redirect victim -> attacker.
        if self.segments and not self._is_known_router(ev.new_gw):
            sev = SEV_HIGH
            msg = ("Redirect installs a new gateway that is not a known router "
                   "— endpoint being redirected to an unrecognized host")
            findings.append(Finding(
                "new_gw_not_router", sev, msg,
                {"victim": victim, "new_gw": ev.new_gw, "src_ip": ev.src_ip},
            ))

        # 5b) ARP correlation — is the L2 identity of either party contested?
        #     Ties the redirect to ARP-layer poisoning: a redirect issued by, or
        #     pointing at, a gateway whose MAC is contested is the poison-then-
        #     redirect MITM sequence.
        if self.arp_enabled:
            # source gateway's binding contested
            if self._is_known_gateway(ev.src_ip):
                s = self._arp_suspect(ev.src_ip, ev.ts)
                if s:
                    reason, adet = s
                    findings.append(Finding(
                        "gateway_arp_conflict", SEV_CRITICAL,
                        "Redirect source is a gateway whose ARP binding is "
                        f"contested ({reason}) — its L2 identity may be poisoned",
                        {"src_ip": ev.src_ip, "reason": reason, "arp": adet},
                    ))
            # the gateway the victim is being pointed at
            sg = self._arp_suspect(ev.new_gw, ev.ts)
            if sg:
                reason, adet = sg
                findings.append(Finding(
                    "redirect_via_poisoned_gw", SEV_CRITICAL,
                    "Redirect points to a gateway whose ARP binding is "
                    f"contested ({reason}) — victim likely steered to poisoner",
                    {"new_gw": ev.new_gw, "reason": reason, "arp": adet},
                ))
            else:
                # new gateway is a known one, but its live MAC is not among the
                # MACs configured as legitimate for it
                exp = self._contention_expected(ev.new_gw)
                learned = self.arp.mac_for(ev.new_gw)
                if exp and learned and learned not in exp:
                    findings.append(Finding(
                        "redirect_via_poisoned_gw", SEV_CRITICAL,
                        "Redirect points to a known gateway whose current ARP "
                        "MAC is not among its configured MACs",
                        {"new_gw": ev.new_gw,
                         "configured_macs": sorted(exp),
                         "current_mac": learned},
                    ))

        # 6) degenerate targets
        if ev.new_gw == ev.src_ip:
            findings.append(Finding(
                "new_gw_equals_source", SEV_LOW,
                "Redirect new gateway equals the source (no-op / malformed)",
                {"src_ip": ev.src_ip, "new_gw": ev.new_gw},
            ))
        if victim and ev.new_gw == victim:
            findings.append(Finding(
                "new_gw_equals_victim", SEV_MEDIUM,
                "Redirect points the victim at itself as gateway",
                {"victim": victim, "new_gw": ev.new_gw},
            ))

        # 7) TTL heuristic — a redirect from a directly-connected gateway has
        #    made 0 hops, so its TTL should still be near a known initial value.
        #    Off by more than a hop or two suggests it was relayed/spoofed from
        #    beyond the segment. Heuristic; OS-dependent; opt-in.
        if self.enable_ttl_heuristic and ev.ip_ttl is not None:
            if not self._ttl_plausibly_local(ev.ip_ttl):
                findings.append(Finding(
                    "ttl_suggests_remote", SEV_LOW,
                    "Redirect TTL is inconsistent with a directly-connected "
                    "origin",
                    {"src_ip": ev.src_ip, "ttl": ev.ip_ttl,
                     "expected_near": sorted(self.local_ttls)},
                ))

        # 8) rate + destination diversity (mass redirect / route sweep)
        self._record(ev)
        rate_findings = self._rate_checks(ev)
        findings.extend(rate_findings)

        # 9) if nothing above fired, this is still a redirect worth logging —
        #    most managed hosts should never see one.
        if not findings:
            findings.append(Finding(
                "observed_redirect", SEV_INFO,
                "ICMP Redirect observed (no anomaly triggered)",
                {"src_ip": ev.src_ip, "victim": victim, "new_gw": ev.new_gw,
                 "code": ev.icmp_code},
            ))

        return findings

    def _ttl_plausibly_local(self, ttl: int) -> bool:
        for base in self.local_ttls:
            if base - self.ttl_slack <= ttl <= base:
                return True
        return False

    # ---- sliding-window rate state --------------------------------------

    def _record(self, ev: RedirectEvent):
        if ev.src_ip is None:
            return
        self._hist.append((ev.ts, ev.src_ip, ev.inner_dst))
        cutoff = ev.ts - self.window
        while self._hist and self._hist[0][0] < cutoff:
            self._hist.popleft()

    def _rate_checks(self, ev: RedirectEvent) -> list:
        out = []
        if ev.src_ip is None:
            return out
        same_src = [h for h in self._hist if h[1] == ev.src_ip]
        count = len(same_src)
        if count >= self.burst_per_src:
            out.append(Finding(
                "redirect_burst", SEV_HIGH,
                f"{count} redirects from {ev.src_ip} within {self.window:.0f}s",
                {"src_ip": ev.src_ip, "count": count,
                 "window_s": self.window},
            ))
        distinct_dsts = {h[2] for h in same_src if h[2] is not None}
        if len(distinct_dsts) >= self.dest_diversity:
            out.append(Finding(
                "redirect_dest_sweep", SEV_HIGH,
                f"{ev.src_ip} redirected {len(distinct_dsts)} distinct "
                f"destinations within {self.window:.0f}s (route sweep)",
                {"src_ip": ev.src_ip, "distinct_destinations": len(distinct_dsts)},
            ))
        return out

    # ---- Scapy adapter ---------------------------------------------------

    def analyze_packet(self, pkt, ts: Optional[float] = None) -> list:
        ev = packet_to_event(pkt, ts=ts)
        if ev is None:
            return []
        return self.analyze(ev)


def packet_to_event(pkt, ts: Optional[float] = None) -> Optional[RedirectEvent]:
    """Convert a Scapy packet to a RedirectEvent. Returns None for non-redirects."""
    from scapy.all import IP, ICMP, Ether  # local import; keeps import light

    if ICMP not in pkt:
        return None
    icmp = pkt[ICMP]
    if int(icmp.type) != ICMP_REDIRECT:
        return None

    ts = time.time() if ts is None else ts
    src_mac = pkt[Ether].src if Ether in pkt else None
    dst_mac = pkt[Ether].dst if Ether in pkt else None
    outer = pkt[IP] if IP in pkt else None

    new_gw = getattr(icmp, "gw", None)
    inner_src = inner_dst = inner_proto = None
    malformed = False

    # embedded original datagram lives in the ICMP payload
    inner = icmp.payload
    try:
        if inner is not None and inner.haslayer(IP):
            iip = inner[IP]
            inner_src = iip.src
            inner_dst = iip.dst
            inner_proto = int(iip.proto)
        else:
            malformed = True
    except Exception:
        malformed = True

    return RedirectEvent(
        ts=ts,
        src_ip=outer.src if outer else None,
        src_mac=src_mac,
        dst_ip=outer.dst if outer else None,
        dst_mac=dst_mac,
        ip_ttl=int(outer.ttl) if outer else None,
        icmp_code=int(icmp.code),
        new_gw=str(new_gw) if new_gw else None,
        inner_src=inner_src,
        inner_dst=inner_dst,
        inner_proto=inner_proto,
        malformed=malformed,
    )


def arp_packet_to_obs(pkt):
    """Extract (sender_ip, sender_mac, is_gratuitous) from an ARP packet.
    Returns None for non-ARP or unusable frames (e.g. 0.0.0.0 probes)."""
    from scapy.all import ARP

    if ARP not in pkt:
        return None
    arp = pkt[ARP]
    psrc = getattr(arp, "psrc", None)
    hwsrc = getattr(arp, "hwsrc", None)
    if not psrc or not hwsrc or psrc == "0.0.0.0":
        return None
    pdst = getattr(arp, "pdst", None)
    gratuitous = bool(pdst) and psrc == pdst   # announcement form
    return (psrc, hwsrc, gratuitous)


# ---- runtime / logging ---------------------------------------------------

def _max_sev(findings):
    if not findings:
        return SEV_INFO
    return max((f.severity for f in findings), key=lambda s: _SEV_ORDER[s])


def _emit(findings, ev, logger, json_out):
    if not findings:
        return
    sev = _max_sev(findings)
    level = {
        SEV_INFO: logging.INFO, SEV_LOW: logging.INFO,
        SEV_MEDIUM: logging.WARNING, SEV_HIGH: logging.ERROR,
        SEV_CRITICAL: logging.CRITICAL,
    }[sev]
    if json_out:
        rec = {
            "ts": ev.ts, "severity": sev,
            "src_ip": ev.src_ip, "src_mac": ev.src_mac,
            "victim": ev.inner_src or ev.dst_ip, "new_gw": ev.new_gw,
            "code": ev.icmp_code,
            "findings": [asdict(f) for f in findings],
        }
        logger.log(level, json.dumps(rec, sort_keys=True))
    else:
        head = (f"[{sev}] redirect src={ev.src_ip} victim="
                f"{ev.inner_src or ev.dst_ip} new_gw={ev.new_gw}")
        logger.log(level, head)
        for f in findings:
            logger.log(level, f"    - {f.check} ({f.severity}): {f.message}")


def run_live(config, iface, json_out):
    from scapy.all import sniff
    det = ICMPRedirectDetector(config)
    logger = logging.getLogger("icmpwatch")

    def _cb(pkt):
        # ARP frames feed the correlation table and produce no events of
        # their own; redirects are analyzed with the table as context.
        if det.arp_enabled:
            obs = arp_packet_to_obs(pkt)
            if obs is not None:
                ip, mac, gratuitous = obs
                det.observe_arp(ip, mac, gratuitous=gratuitous)
                return
        ev = packet_to_event(pkt)
        if ev is None:
            return
        findings = det.analyze(ev)
        _emit(findings, ev, logger, json_out)

    filt = ("icmp[icmptype] == 5 or arp" if det.arp_enabled
            else "icmp[icmptype] == 5")
    logger.info("icmpwatch live on %s (filter: %s)", iface, filt)
    sniff(iface=iface, filter=filt, store=0, prn=_cb)


def load_config(path):
    if not path:
        return {}
    with open(path) as fh:
        text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # optional
            return yaml.safe_load(text)
        except ImportError:
            raise SystemExit("config is not valid JSON and PyYAML is not installed")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Passive ICMP Redirect monitor (Ragnar)")
    ap.add_argument("-i", "--iface", help="capture interface (SPAN/mirror or bridge)")
    ap.add_argument("-c", "--config", help="JSON/YAML config with segments+gateways")
    ap.add_argument("--json", action="store_true", help="emit JSON events")
    ap.add_argument("--self-test", action="store_true", help="run built-in test suite")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s icmpwatch %(levelname)s %(message)s",
    )

    if args.self_test:
        from icmpwatch_selftest import run_self_test
        return 0 if run_self_test() else 1

    if not args.iface:
        ap.error("live mode requires --iface (or use --self-test)")
    cfg = load_config(args.config)
    try:
        run_live(cfg, args.iface, args.json)
    except PermissionError:
        raise SystemExit("need CAP_NET_RAW / root to capture")
    return 0


if __name__ == "__main__":
    sys.exit(main())
