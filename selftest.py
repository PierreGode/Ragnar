#!/usr/bin/env python3
"""Self-test harness for igmpwatch.

Crafts IGMPv1/v2/v3 frames with Scapy, pushes them through the real decode +
pipeline, and asserts the expected detections fire. No interface or root needed.
"""
import copy
import sys
import time

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, IPOption_Router_Alert
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq, IGMPv3mr, IGMPv3gr

from igmpwatch import config as configmod
from igmpwatch.decode import decode
from igmpwatch.pipeline import Pipeline
from igmpwatch.storage import Storage
from igmpwatch.alerting import Alerter

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {extra}")


# --------------------------------------------------------------------------
# packet builders
# --------------------------------------------------------------------------
def wire(pkt, ts):
    p = Ether(bytes(pkt))
    p.time = ts
    return p


def v2_query_general(src="10.0.0.1", mac="00:11:22:00:00:01", ts=0.0, ra=True, ttl=1):
    igmp = IGMP(type=0x11, mrcode=100, gaddr="0.0.0.0")
    if ra:
        return wire(Ether(src=mac, dst="01:00:5e:00:00:01") /
                    IP(src=src, dst="224.0.0.1", ttl=ttl,
                       options=[IPOption_Router_Alert()]) / igmp, ts)
    # scapy auto-inserts the Router Alert option whenever an IGMP layer is
    # attached to IP, so the no-RA case is built with the message as a raw
    # payload — that yields a genuine ihl=5 header with no option space.
    from scapy.packet import Raw
    return wire(Ether(src=mac, dst="01:00:5e:00:00:01") /
                IP(src=src, dst="224.0.0.1", ttl=ttl, proto=2) /
                Raw(bytes(igmp)), ts)


def v2_query_group(group, src="10.0.0.1", mac="00:11:22:00:00:01", ts=0.0):
    return wire(Ether(src=mac, dst="01:00:5e:7f:00:01") /
                IP(src=src, dst=group, ttl=1, options=[IPOption_Router_Alert()]) /
                IGMP(type=0x11, mrcode=100, gaddr=group), ts)


def v2_report(group, src="10.0.0.5", mac="aa:bb:cc:00:00:05", ts=0.0, ttl=1, bad_cksum=False):
    ig = IGMP(type=0x16, gaddr=group)
    if bad_cksum:
        ig.chksum = 0x1234
    return wire(Ether(src=mac, dst="01:00:5e:0a:00:05") /
                IP(src=src, dst=group, ttl=ttl, options=[IPOption_Router_Alert()]) / ig, ts)


def v2_leave(group, src="10.0.0.5", mac="aa:bb:cc:00:00:05", ts=0.0):
    return wire(Ether(src=mac, dst="01:00:5e:00:00:02") /
                IP(src=src, dst="224.0.0.2", ttl=1, options=[IPOption_Router_Alert()]) /
                IGMP(type=0x17, gaddr=group), ts)


def v1_report(group, src="10.0.0.7", mac="aa:bb:cc:00:00:07", ts=0.0):
    return wire(Ether(src=mac, dst="01:00:5e:0a:00:07") /
                IP(src=src, dst=group, ttl=1) / IGMP(type=0x12, gaddr=group), ts)


def v3_report(records, src="10.0.0.6", mac="aa:bb:cc:00:00:06", ts=0.0):
    grs = [IGMPv3gr(rtype=rt, maddr=g, srcaddrs=srcs) for rt, g, srcs in records]
    return wire(Ether(src=mac, dst="01:00:5e:00:00:16") /
                IP(src=src, dst="224.0.0.22", ttl=1, options=[IPOption_Router_Alert()]) /
                IGMPv3(type=0x22)/IGMPv3mr(records=grs), ts)


def v3_query_group(group, src="10.0.0.1", mac="00:11:22:00:00:01", ts=0.0):
    return wire(Ether(src=mac, dst="01:00:5e:7f:00:01") /
                IP(src=src, dst=group, ttl=1, options=[IPOption_Router_Alert()]) /
                IGMPv3(type=0x11)/IGMPv3mq(gaddr=group), ts)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def make_cfg(**over):
    cfg = copy.deepcopy(configmod.DEFAULTS)
    cfg["db_path"] = ":memory:"
    cfg["log_path"] = "-"
    cfg["alerting"]["stdout"] = False
    cfg["alerting"]["min_severity"] = "INFO"
    cfg["alerting"]["cooldown"] = 0
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


def new_pipeline(cfg, now=0.0):
    storage = Storage(":memory:")
    alerter = Alerter(cfg, storage)
    return Pipeline(cfg, storage=storage, alerter=alerter, now=now)


def rules(fired):
    return {a.rule for a in fired}


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------
def test_decode():
    print("[decode]")
    ev = decode(v2_report("239.10.0.5", ts=1.0))
    check("v2 report version", ev.version == 2)
    check("v2 report group", ev.group == "239.10.0.5")
    check("v2 report checksum ok", ev.checksum_ok is True)
    check("v2 report router-alert", ev.router_alert is True)
    check("v2 report is a join", ev.joined_groups() == [("239.10.0.5", [])])

    ev = decode(v2_report("239.10.0.5", ts=1.0, bad_cksum=True))
    check("bad checksum detected", ev.checksum_ok is False)

    ev = decode(v2_report("239.10.0.5", ts=1.0, ttl=5))
    check("ttl carried through", ev.ttl == 5)

    ev = decode(v2_leave("239.10.0.5", ts=1.0))
    check("v2 leave parsed", ev.left_groups() == ["239.10.0.5"])

    ev = decode(v1_report("239.10.0.7", ts=1.0))
    check("v1 report version", ev.version == 1)

    ev = decode(v2_query_general(ts=1.0))
    check("v2 general query", ev.msg_type.name == "QUERY_GENERAL")

    ev = decode(v2_query_group("239.9.9.9", ts=1.0))
    check("v2 group query", ev.msg_type.name == "QUERY_GROUP" and ev.group == "239.9.9.9")

    ev = decode(v3_report([(4, "239.100.0.1", []), (1, "232.1.2.3", ["198.51.100.9"])], ts=1.0))
    check("v3 report version", ev.version == 3)
    check("v3 two records", len(ev.records) == 2)
    check("v3 join extraction",
          ("239.100.0.1", []) in ev.joined_groups()
          and ("232.1.2.3", ["198.51.100.9"]) in ev.joined_groups())

    ev = decode(v3_query_group("239.5.5.5", ts=1.0))
    check("v3 group query", ev.msg_type.name == "QUERY_GROUP" and ev.group == "239.5.5.5")


def test_anomaly():
    print("[anomaly]")
    p = new_pipeline(make_cfg())
    f = p.process_event(decode(v2_report("239.10.0.5", ts=1.0, bad_cksum=True)))
    check("bad checksum alert", "anomaly.bad_checksum" in rules(f))

    p = new_pipeline(make_cfg())
    f = p.process_event(decode(v2_report("239.10.0.5", ts=1.0, ttl=64)))
    check("bad ttl alert", "anomaly.bad_ttl" in rules(f))

    p = new_pipeline(make_cfg())
    f = p.process_event(decode(v2_report("224.0.0.1", ts=1.0)))
    check("reserved-group report alert", "anomaly.reserved_group_report" in rules(f))

    p = new_pipeline(make_cfg())
    f = p.process_event(decode(v2_report("10.9.9.9", ts=1.0)))
    check("non-multicast group alert", "anomaly.non_multicast_group" in rules(f))

    p = new_pipeline(make_cfg())
    # v2 general query without router alert
    f = p.process_event(decode(v2_query_general(ts=1.0, ra=False)))
    check("no router-alert alert", "anomaly.no_router_alert" in rules(f))

    # downgrade: establish v3, then a v2 general query
    p = new_pipeline(make_cfg(learning_period=0))
    p.process_event(decode(v3_report([(4, "239.1.1.1", [])], ts=1.0)))
    f = p.process_event(decode(v2_query_general(src="10.0.0.1", ts=2.0)))
    check("version downgrade alert", "anomaly.version_downgrade" in rules(f))


def test_recon():
    print("[recon]")
    cfg = make_cfg(learning_period=0)
    p = new_pipeline(cfg)
    # baseline querier = 10.0.0.10
    p.process_event(decode(v2_query_general(src="10.0.0.10", ts=1.0)))
    # higher-IP source issuing general queries -> non-querier recon
    f = p.process_event(decode(v2_query_general(src="10.0.0.90", mac="00:11:22:00:00:99", ts=2.0)))
    check("non-querier query alert", "recon.nonquerier_query" in rules(f))

    p = new_pipeline(cfg)
    p.process_event(decode(v2_query_general(src="10.0.0.10", ts=1.0)))
    # lower-IP source -> querier takeover
    f = p.process_event(decode(v2_query_general(src="10.0.0.1", mac="00:11:22:00:00:aa", ts=2.0)))
    check("querier takeover alert", "recon.querier_takeover" in rules(f))

    p = new_pipeline(cfg)
    f = p.process_event(decode(v2_query_general(src="0.0.0.0", ts=1.0)))
    check("spoofed (0.0.0.0) querier alert", "recon.spoofed_querier" in rules(f))

    # group enumeration scan
    p = new_pipeline(make_cfg(learning_period=0, recon={"scan_distinct_groups": 6, "scan_window": 15,
                                                        "alert_nonquerier_query": True}))
    fired = set()
    for i in range(6):
        f = p.process_event(decode(v2_query_group(f"239.7.0.{i+1}", src="10.0.0.66", ts=1.0 + i * 0.1)))
        fired |= rules(f)
    check("group-scan recon alert", "recon.group_scan" in fired)


def test_flood():
    print("[flood]")
    cfg = make_cfg(flood={"window": 10, "report_rate": 5, "leave_rate": 30,
                          "query_rate": 3, "global_rate": 20, "flap_transitions": 4})
    p = new_pipeline(cfg)
    fired = set()
    for i in range(8):
        f = p.process_event(decode(v2_report("239.2.2.2", src="10.0.0.5",
                                              mac="aa:bb:cc:00:00:05", ts=1.0 + i * 0.1)))
        fired |= rules(f)
    check("report storm alert", "flood.report_storm" in fired)

    p = new_pipeline(cfg)
    fired = set()
    for i in range(6):
        f = p.process_event(decode(v2_query_general(src="10.0.0.10", ts=1.0 + i * 0.1)))
        fired |= rules(f)
    check("query storm alert", "flood.query_storm" in fired)

    # join/leave flapping
    p = new_pipeline(cfg)
    fired = set()
    ts = 1.0
    for i in range(12):
        if i % 2 == 0:
            f = p.process_event(decode(v2_report("239.3.3.3", ts=ts)))
        else:
            f = p.process_event(decode(v2_leave("239.3.3.3", ts=ts)))
        fired |= rules(f)
        ts += 0.1
    check("join/leave flap alert", "flood.join_leave_flap" in fired)

    # global storm (mixed sources)
    p = new_pipeline(cfg)
    fired = set()
    for i in range(25):
        f = p.process_event(decode(v2_report(f"239.4.0.{i%50}", src=f"10.0.1.{i%50}",
                                              mac=f"aa:bb:cc:01:00:{i%50:02x}", ts=1.0 + i * 0.05)))
        fired |= rules(f)
    check("multicast storm (global) alert", "flood.multicast_storm" in fired)


def test_policy():
    print("[policy]")
    # enforce: unauthorized join
    cfg = make_cfg(policy={"mode": "enforce", "allow_link_local": True, "benign_groups": [],
                           "sensitive_groups": [], "allow": [], "flag_unknown_group": True,
                           "ssm_source_allow": []})
    p = new_pipeline(cfg)
    f = p.process_event(decode(v2_report("239.50.0.1", mac="de:ad:be:ef:00:01", ts=1.0)))
    check("unauthorized join alert", "policy.unauthorized_join" in rules(f))

    # enforce: allowlisted host+group is permitted
    cfg = make_cfg(policy={"mode": "enforce", "allow_link_local": True, "benign_groups": [],
                           "sensitive_groups": [], "flag_unknown_group": True, "ssm_source_allow": [],
                           "allow": [{"mac": "de:ad:be:ef:*", "groups": ["239.50.0.0/16"]}]})
    p = new_pipeline(cfg)
    f = p.process_event(decode(v2_report("239.50.0.1", mac="de:ad:be:ef:00:01", ts=1.0)))
    check("allowlisted join permitted", "policy.unauthorized_join" not in rules(f))

    # sensitive group flagged even in learn mode
    cfg = make_cfg(policy={"mode": "learn", "allow_link_local": True, "benign_groups": [],
                           "sensitive_groups": ["239.100.0.0/24"], "flag_unknown_group": True,
                           "allow": [], "ssm_source_allow": []})
    p = new_pipeline(cfg)
    f = p.process_event(decode(v2_report("239.100.0.7", mac="de:ad:be:ef:00:02", ts=1.0)))
    check("sensitive group join alert", "policy.sensitive_group_join" in rules(f))

    # link-local join is benign (no policy alert)
    p = new_pipeline(make_cfg(policy={"mode": "enforce", "allow_link_local": True,
                                      "benign_groups": [], "sensitive_groups": [], "allow": [],
                                      "flag_unknown_group": True, "ssm_source_allow": []}))
    f = p.process_event(decode(v2_report("224.0.0.251", mac="de:ad:be:ef:00:03", ts=1.0)))
    check("link-local (mDNS) join suppressed",
          not any(r.startswith("policy.") for r in rules(f)))

    # new group in learn mode -> INFO baseline
    p = new_pipeline(make_cfg(policy={"mode": "learn", "allow_link_local": True,
                                      "benign_groups": [], "sensitive_groups": [], "allow": [],
                                      "flag_unknown_group": True, "ssm_source_allow": []}))
    f = p.process_event(decode(v2_report("239.222.0.9", mac="de:ad:be:ef:00:04", ts=1.0)))
    check("new-group baseline alert", "policy.new_group" in rules(f))

    # SSM source policy
    p = new_pipeline(make_cfg(policy={"mode": "learn", "allow_link_local": True, "benign_groups": [],
                                      "sensitive_groups": [], "allow": [], "flag_unknown_group": False,
                                      "ssm_source_allow": ["198.51.100.0/24"]}))
    f = p.process_event(decode(v3_report([(1, "232.1.2.3", ["203.0.113.9"])], ts=1.0)))
    check("SSM disallowed source alert", "policy.ssm_source_denied" in rules(f))


def _ctr(rx_packets=0, multicast=0, rx_dropped=0, rx_bytes=0):
    return {"rx_packets": rx_packets, "multicast": multicast,
            "rx_dropped": rx_dropped, "rx_bytes": rx_bytes}


def test_dataplane():
    print("[dataplane]")

    # priming sample never alerts
    p = new_pipeline(make_cfg())
    primed = p.poll_dataplane(now=100.0, counters=_ctr(rx_packets=1000, multicast=100))
    check("first sample primes silently", primed == [])

    # multicast storm on the wire (>2000 pps over 5s)
    fired = rules(p.poll_dataplane(now=105.0,
                  counters=_ctr(rx_packets=17000, multicast=15100)))
    check("data-plane multicast storm alert", "dataplane.mcast_storm" in fired)

    # multicast with ZERO subscribed data groups -> flood-to-unsubscribed
    p2 = new_pipeline(make_cfg())
    p2.poll_dataplane(now=0.0, counters=_ctr(rx_packets=0, multicast=0))
    fired = rules(p2.poll_dataplane(now=5.0,
                  counters=_ctr(rx_packets=1200, multicast=1000)))
    check("multicast flood with no members alert",
          "dataplane.mcast_flood_no_members" in fired)

    # same rate but a data group IS joined -> flood rule suppressed
    p3 = new_pipeline(make_cfg())
    p3.process_event(decode(v2_report("239.9.9.9", ts=1.0)))
    p3.poll_dataplane(now=0.0, counters=_ctr(rx_packets=0, multicast=0))
    fired = rules(p3.poll_dataplane(now=5.0,
                  counters=_ctr(rx_packets=1200, multicast=1000)))
    check("no-member flood suppressed when a group is joined",
          "dataplane.mcast_flood_no_members" not in fired)

    # capture-path drops climbing (ring buffer overrun / storm symptom)
    p4 = new_pipeline(make_cfg())
    p4.poll_dataplane(now=0.0, counters=_ctr(rx_packets=100, rx_dropped=0))
    fired = rules(p4.poll_dataplane(now=5.0,
                  counters=_ctr(rx_packets=200, rx_dropped=1000)))
    check("rx drop-rate alert", "dataplane.rx_drops" in fired)

    # multicast dominates the link -> ratio alert (group joined to isolate rule)
    p5 = new_pipeline(make_cfg())
    p5.process_event(decode(v2_report("239.9.9.9", ts=1.0)))
    p5.poll_dataplane(now=0.0, counters=_ctr(rx_packets=0, multicast=0))
    fired = rules(p5.poll_dataplane(now=5.0,
                  counters=_ctr(rx_packets=5000, multicast=4800)))
    check("multicast ratio alert", "dataplane.mcast_ratio" in fired)

    # counter reset / iface bounce -> re-prime, never alert
    p6 = new_pipeline(make_cfg())
    p6.poll_dataplane(now=0.0, counters=_ctr(rx_packets=999999, multicast=999999))
    fired = rules(p6.poll_dataplane(now=5.0,
                  counters=_ctr(rx_packets=10, multicast=5)))
    check("counter reset re-primes without alert", fired == set())


def _snap(ifaces=None, groups=None, supported=False):
    from igmpwatch.snmp import SnmpSnapshot, IfaceCounters
    s = SnmpSnapshot(group_table_supported=supported)
    for idx, (name, im, om) in (ifaces or {}).items():
        s.ifaces[str(idx)] = IfaceCounters(str(idx), name, im, om)
    for g, (ifidxs, rep) in (groups or {}).items():
        s.groups[g] = {"ifindices": set(str(i) for i in ifidxs), "reporter": rep}
    return s


def _snmp_cfg(**snmp_over):
    base = {"enable": True, "host": "192.0.2.10", "iface_mcast_pps": 3000}
    base.update(snmp_over)
    return make_cfg(snmp=base)


def test_snmp():
    print("[snmp]")

    # disabled by default -> no poller, no-op
    p0 = new_pipeline(make_cfg())
    check("snmp off by default is a no-op",
          p0.snmp is None and p0.poll_snmp(now=1.0, snapshot=_snap()) == [])

    # per-interface multicast storm from switch counters
    p = new_pipeline(_snmp_cfg())
    p.poll_snmp(now=0.0, snapshot=_snap(ifaces={10: ("Gi1/0/1", 0, 0)}))
    fired = rules(p.poll_snmp(now=5.0,
                  snapshot=_snap(ifaces={10: ("Gi1/0/1", 20000, 0)})))
    check("per-interface multicast storm alert", "snmp.iface_mcast_storm" in fired)

    # iface counter reset -> no storm
    p.poll_snmp(now=10.0, snapshot=_snap(ifaces={10: ("Gi1/0/1", 5, 0)}))
    fired = rules(p.poll_snmp(now=15.0,
                  snapshot=_snap(ifaces={10: ("Gi1/0/1", 6, 0)})))
    check("iface counter reset yields no storm",
          "snmp.iface_mcast_storm" not in fired)

    # switch forwards a group igmpwatch never saw a join for
    p2 = new_pipeline(_snmp_cfg())
    fired = rules(p2.poll_snmp(now=1.0, snapshot=_snap(
        groups={"239.5.5.5": ([12], "10.0.0.9")}, supported=True)))
    check("unsubscribed-forwarding cross-ref alert",
          "snmp.unsubscribed_forwarding" in fired)

    # ...but not once igmpwatch has actually seen that join
    p3 = new_pipeline(_snmp_cfg())
    p3.process_event(decode(v2_report("239.5.5.5", ts=1.0)))
    fired = rules(p3.poll_snmp(now=2.0, snapshot=_snap(
        groups={"239.5.5.5": ([12], "10.0.0.9")}, supported=True)))
    check("known join suppresses unsubscribed-forwarding",
          "snmp.unsubscribed_forwarding" not in fired)

    # benign/link-local forwarded groups are never flagged
    p4 = new_pipeline(_snmp_cfg())
    fired = rules(p4.poll_snmp(now=1.0, snapshot=_snap(groups={
        "239.255.255.250": ([1], None),   # SSDP (benign)
        "224.0.0.251": ([1], None),        # mDNS (link-local)
    }, supported=True)))
    check("benign/link-local forwarding not flagged",
          "snmp.unsubscribed_forwarding" not in fired)

    # opt-in: igmpwatch saw a join the switch table doesn't list (post-learning)
    p5 = new_pipeline(_snmp_cfg(flag_census_not_forwarded=True), now=0.0)
    p5.process_event(decode(v2_report("239.7.7.7", ts=1.0)))
    fired = rules(p5.poll_snmp(now=300.0, snapshot=_snap(
        groups={"239.9.9.9": ([2], None)}, supported=True)))
    check("census-not-forwarded alert (opt-in)",
          "snmp.census_not_forwarded" in fired)

    # unsupported group table -> cross-ref silently skipped
    p6 = new_pipeline(_snmp_cfg())
    fired = rules(p6.poll_snmp(now=1.0, snapshot=_snap(
        ifaces={1: ("Gi1/0/1", 0, 0)}, supported=False)))
    check("no group MIB -> cross-ref skipped", fired == set())

    # --- platform probe ---
    from igmpwatch.snmp import probe, format_probe, OID_IF_NAME, OID_IGMP_CACHE

    class _FakeClient:
        def __init__(self, data):
            self.data = data
        def walk(self, oid):
            return self.data.get(oid)

    scfg = _snmp_cfg()["snmp"]
    full = _FakeClient({
        OID_IF_NAME: {"10": "Gi1/0/1"},
        "1.3.6.1.2.1.31.1.1.1.2": {"10": "123"},
        "1.3.6.1.2.1.31.1.1.1.4": {"10": "45"},
        OID_IGMP_CACHE: {"239.1.2.3.10": "10.0.0.5"},
    })
    rep = probe(full, scfg)
    check("probe reports all four targets", len(rep) == 4)
    check("probe marks group table reachable",
          any(r["is_group"] and r["reachable"] and r["rows"] == 1 for r in rep))
    txt = format_probe(rep, scfg)
    check("probe summary: full cross-reference", "full cross-reference" in txt)
    check("probe decodes group@if in sample", "239.1.2.3@if10" in txt)

    iface_only = _FakeClient({
        OID_IF_NAME: {"10": "Gi1/0/1"},
        "1.3.6.1.2.1.31.1.1.1.2": {"10": "123"},
        "1.3.6.1.2.1.31.1.1.1.4": {"10": "45"},
        OID_IGMP_CACHE: {},                       # populated-but-empty
    })
    txt = format_probe(probe(iface_only, scfg), scfg)
    check("probe summary: group table empty", "group table empty" in txt)

    dead = _FakeClient({})                         # nothing answers
    rep = probe(dead, scfg)
    check("probe: unreachable marks all MISS",
          all(not r["reachable"] for r in rep))
    check("probe summary: no response", "no response" in format_probe(rep, scfg))

    # --- capability cache ---
    from igmpwatch.snmp import CapabilityCache, collect_snapshot
    from igmpwatch.storage import Storage

    class _CountingClient:
        """Counts group-table walks so we can prove they're actually skipped."""
        def __init__(self, group_rows):
            self.group_rows = group_rows
            self.group_walks = 0
        def walk(self, oid):
            if oid == OID_IGMP_CACHE:
                self.group_walks += 1
                return dict(self.group_rows)
            if oid == OID_IF_NAME:
                return {"10": "Gi1/0/1"}
            return {"10": "5"}

    ccfg = dict(scfg); ccfg["host"] = "sw-a"

    # empty walks: below the strike threshold the walk keeps happening
    st = Storage(":memory:")
    caps = CapabilityCache(st, ttl=1000.0, strikes=3)
    cl = _CountingClient({})
    collect_snapshot(cl, ccfg, caps=caps, now=1.0)
    collect_snapshot(cl, ccfg, caps=caps, now=2.0)
    check("empty walk below strike threshold still walks", cl.group_walks == 2)
    check("no verdict recorded before threshold",
          (st.get_snmp_capability("sw-a") or {}).get("group_table") is None)

    # third strike -> marked unsupported -> subsequent walks skipped
    collect_snapshot(cl, ccfg, caps=caps, now=3.0)
    check("third empty walk marks group table unsupported",
          st.get_snmp_capability("sw-a")["group_table"] == 0)
    snap = collect_snapshot(cl, ccfg, caps=caps, now=4.0)
    check("known-empty group walk is skipped", cl.group_walks == 3)
    check("skipped walk is flagged on the snapshot", snap.group_walk_skipped)
    check("skipped snapshot still carries iface counters", len(snap.ifaces) == 1)

    # TTL expiry forces a re-check, and a now-populated table re-enables
    cl.group_rows = {"239.1.2.3.10": "10.0.0.5"}
    snap = collect_snapshot(cl, ccfg, caps=caps, now=1100.0)
    check("TTL expiry re-checks the group table", cl.group_walks == 4)
    check("re-check re-enables a populated group table",
          st.get_snmp_capability("sw-a")["group_table"] == 1
          and snap.group_table_supported)

    # unreachable walk is never a strike (transport problem, not a verdict)
    st2 = Storage(":memory:")
    caps2 = CapabilityCache(st2, ttl=1000.0, strikes=1)
    class _DeadClient:
        def walk(self, oid):
            return None
    collect_snapshot(_DeadClient(), dict(scfg, host="sw-b"), caps=caps2, now=1.0)
    check("unreachable walk records no verdict",
          st2.get_snmp_capability("sw-b") is None)

    # cache is per-host: sw-a's verdict must not mute sw-c
    cl2 = _CountingClient({})
    collect_snapshot(cl2, dict(ccfg, host="sw-c"), caps=caps, now=5.0)
    check("capability verdicts are per-switch", cl2.group_walks == 1)

    # no cache configured -> always walks
    cl3 = _CountingClient({})
    collect_snapshot(cl3, ccfg, caps=None, now=6.0)
    collect_snapshot(cl3, ccfg, caps=None, now=7.0)
    check("no cache -> group walk always runs", cl3.group_walks == 2)


def _wire_pad(pkt, ts=1.0, extra=b"", zero_iplen=False):
    """Frame as the kernel delivers it: padded to the 60B minimum, .original set.
    ``extra`` appends trailing bytes (smuggling); ``zero_iplen`` blanks the IP
    total-length field to simulate a NIC that offloaded and zeroed it."""
    b = bytearray(bytes(pkt))
    if zero_iplen:
        b[16:18] = b"\x00\x00"          # l3=14, IP total-length at +2
    b += extra
    if len(b) < 60:
        b += b"\x00" * (60 - len(b))
    p = Ether(bytes(b)); p.original = bytes(b); p.time = ts
    return p


def test_padding():
    print("[padding/framing]")

    def v2rep(mac="aa:bb:cc:00:00:05", grp="239.1.2.3"):
        return (Ether(src=mac, dst="01:00:5e:01:02:03") /
                IP(src="10.0.0.5", dst=grp, ttl=1, options=[IPOption_Router_Alert()]) /
                IGMP(type=0x16, gaddr=grp))

    # 1. short report padded to 60B with zeros: no false bad_checksum, no trailing
    ev = decode(_wire_pad(v2rep()))
    check("padded short report: checksum still valid",
          ev is not None and ev.checksum_ok)
    check("all-zero padding is not flagged", ev.trailing_nonzero == 0)

    fired = rules(new_pipeline(make_cfg()).process_event(ev))
    check("padded report fires no bad_checksum", "anomaly.bad_checksum" not in fired)
    check("padded report fires no trailing_data", "anomaly.trailing_data" not in fired)

    # 2. non-zero bytes smuggled in the padding region -> surfaced
    ev = decode(_wire_pad(v2rep(), extra=b"SMUGGLE!"))
    check("smuggled trailing bytes counted", ev.trailing_nonzero > 0)
    fired = rules(new_pipeline(make_cfg()).process_event(ev))
    check("smuggled trailing data alert", "anomaly.trailing_data" in fired)
    check("smuggled frame is not a false checksum failure",
          "anomaly.bad_checksum" not in fired)

    # 3. v3 report padded: exactly the real records, no phantoms from padding
    gr = IGMPv3gr(rtype=4, maddr="239.20.0.1")
    v3 = (Ether(src="aa:bb:cc:00:00:06", dst="01:00:5e:00:00:16") /
          IP(src="10.0.0.6", dst="224.0.0.22", ttl=1, options=[IPOption_Router_Alert()]) /
          (IGMPv3(type=0x22)/IGMPv3mr(records=[gr])))
    ev = decode(_wire_pad(v3))
    check("padded v3: one real record, no phantoms", len(ev.records) == 1)
    check("padded v3: not falsely truncated", not ev.truncated)
    check("padded v3: checksum valid", ev.checksum_ok)

    # 4. offload (ip.len == 0): fallback bounds by IGMP structure, no padding leak
    ev = decode(_wire_pad(v2rep(), zero_iplen=True))
    check("offload ip.len=0: checksum still valid (no padding in msg)",
          ev is not None and ev.checksum_ok)
    fired = rules(new_pipeline(make_cfg()).process_event(ev))
    check("offload path fires no bad_checksum", "anomaly.bad_checksum" not in fired)

    # 5. a captured 4-byte FCS tail is not mistaken for smuggling
    big = Ether(bytes(v2rep()) + b"\x00" * 24)   # >=60B core, no padding needed
    p = Ether(bytes(big) + b"\xAA\xBB\xCC\xDD")
    p.original = bytes(p); p.time = 1.0
    ev = decode(p)
    check("4-byte FCS tail not flagged as trailing data", ev.trailing_nonzero == 0)


def _mld_wire(icmp, src="fe80::1", dst="ff02::16", hlim=1, ra=True, ts=0.0,
              extra=b"", frag=False):
    from scapy.layers.inet6 import (IPv6, IPv6ExtHdrHopByHop, RouterAlert,
                                    IPv6ExtHdrFragment)
    base = Ether(src="33:33:00:00:00:16", dst="33:33:00:00:00:16") / \
        IPv6(src=src, dst=dst, hlim=hlim)
    if ra:
        base = base / IPv6ExtHdrHopByHop(options=[RouterAlert(value=0)])
    if frag:
        base = base / IPv6ExtHdrFragment(m=1, id=1)
    b = bytes(base / icmp) + extra
    p = Ether(b); p.original = b; p.time = ts
    return p


def test_mld():
    print("[mld]")
    from scapy.layers.inet6 import (ICMPv6MLQuery, ICMPv6MLReport, ICMPv6MLDone,
                                    ICMPv6MLQuery2, ICMPv6MLReport2, ICMPv6MLDMultAddrRec)

    # decode basics + IPv6 checksum (pseudo-header) validation
    ev = decode(_mld_wire(ICMPv6MLReport(mladdr="ff15::1234"), ts=1.0))
    check("MLDv1 report decodes as IPv6 join",
          ev.family == 6 and ev.checksum_ok and ev.joined_groups() == [("ff15::1234", [])])

    ev = decode(_mld_wire(ICMPv6MLDone(mladdr="ff15::1234"), ts=1.0))
    check("MLDv1 done decodes as leave", ev.left_groups() == ["ff15::1234"])

    ev = decode(_mld_wire(ICMPv6MLReport2(records=[
        ICMPv6MLDMultAddrRec(rtype=4, dst="ff15::1", sources=[]),
        ICMPv6MLDMultAddrRec(rtype=1, dst="ff3e::8000:9", sources=["2001:db8::9"]),
    ]), ts=1.0))
    check("MLDv2 report parses all records", len(ev.records) == 2 and not ev.truncated)
    check("MLDv2 SSM sources captured",
          ("ff3e::8000:9", ["2001:db8::9"]) in ev.joined_groups())

    # corrupt ICMPv6 checksum -> bad_checksum, not silently trusted
    p = _mld_wire(ICMPv6MLReport(mladdr="ff15::1234"), ts=1.0)
    b = bytearray(p.original); b[50] ^= 0xFF
    p2 = Ether(bytes(b)); p2.original = bytes(b); p2.time = 1.0
    fired = rules(new_pipeline(make_cfg()).process_event(decode(p2)))
    check("MLD bad checksum flagged", "anomaly.bad_checksum" in fired)

    # hop-limit != 1 -> off-link injection
    fired = rules(new_pipeline(make_cfg()).process_event(
        decode(_mld_wire(ICMPv6MLReport(mladdr="ff15::1"), hlim=64, ts=1.0))))
    check("MLD bad hop-limit flagged", "anomaly.bad_ttl" in fired)

    # query without Router Alert -> anomaly
    fired = rules(new_pipeline(make_cfg()).process_event(
        decode(_mld_wire(ICMPv6MLQuery2(mladdr="::"), ra=False, ts=1.0))))
    check("MLD query without Router Alert flagged", "anomaly.no_router_alert" in fired)

    # MLD version downgrade: MLDv1 general query after MLDv2 seen on-segment
    p = new_pipeline(make_cfg())
    p.process_event(decode(_mld_wire(ICMPv6MLReport2(records=[
        ICMPv6MLDMultAddrRec(rtype=4, dst="ff15::1", sources=[])]), ts=1.0)))
    fired = rules(p.process_event(
        decode(_mld_wire(ICMPv6MLQuery(mladdr="::"), src="fe80::2", ts=2.0))))
    check("MLD version downgrade flagged", "anomaly.version_downgrade" in fired)

    # membership report to a reserved control group (ff02::1) -> anomaly
    fired = rules(new_pipeline(make_cfg()).process_event(
        decode(_mld_wire(ICMPv6MLReport(mladdr="ff02::1"), ts=1.0))))
    check("MLD reserved-group report flagged", "anomaly.reserved_group_report" in fired)

    # family isolation: an IGMPv3 (IPv4) report must NOT arm MLD downgrade
    p = new_pipeline(make_cfg())
    p.process_event(decode(v3_report([(4, "239.9.9.9", [])], ts=1.0)))  # IPv4 v3
    fired = rules(p.process_event(
        decode(_mld_wire(ICMPv6MLQuery(mladdr="::"), ts=2.0))))          # IPv6 v1 query
    check("IPv4 v3 does not trigger IPv6 downgrade",
          "anomaly.version_downgrade" not in fired)

    # spoofed querier from :: (IPv6 unspecified)
    fired = rules(new_pipeline(make_cfg()).process_event(
        decode(_mld_wire(ICMPv6MLQuery(mladdr="::"), src="::", ts=1.0))))
    check("MLD spoofed querier (::) flagged", "recon.spoofed_querier" in fired)


def test_cve():
    print("[cve]")
    from scapy.contrib.igmpv3 import IGMPv3mq
    from scapy.layers.inet6 import (IPv6ExtHdrFragment, ICMPv6MLQuery2,
                                    ICMPv6MLReport2, ICMPv6MLDMultAddrRec,
                                    ICMPv6MLReport)

    def v4_rec_report(rtype, grp="239.1.2.3"):
        return wire(Ether(src="aa:bb:cc:00:00:05") /
                    IP(src="10.0.0.5", dst="224.0.0.22", ttl=1,
                       options=[IPOption_Router_Alert()]) /
                    (IGMPv3(type=0x22)/IGMPv3mr(records=[
                        IGMPv3gr(rtype=rtype, maddr=grp)])), ts=1.0)

    # --- IGMPW-001 / CVE-2025-50681: out-of-range group record type ---
    fired = rules(new_pipeline(make_cfg()).process_event(decode(v4_rec_report(7))))
    check("IGMPW-001 invalid record type (IGMPv3)",
          "cve.invalid_record_type" in fired)
    fired = rules(new_pipeline(make_cfg()).process_event(decode(v4_rec_report(0))))
    check("IGMPW-001 rtype 0 flagged", "cve.invalid_record_type" in fired)
    for ok in (1, 2, 3, 4, 5, 6):
        f = rules(new_pipeline(make_cfg()).process_event(decode(v4_rec_report(ok))))
        if "cve.invalid_record_type" in f:
            break
    else:
        ok = None
    check("IGMPW-001 no false positive on valid rtypes 1-6", ok is None)

    ev6 = decode(_mld_wire(ICMPv6MLReport2(records=[
        ICMPv6MLDMultAddrRec(rtype=9, dst="ff15::1", sources=[])]), ts=1.0))
    check("IGMPW-001 invalid record type (MLDv2 parity)",
          "cve.invalid_record_type" in rules(
              new_pipeline(make_cfg()).process_event(ev6)))

    # --- IGMPW-002 / CVE-2026-53275: query declares more sources than carried ---
    over4 = wire(Ether(src="aa:bb:cc:00:00:09") /
                 IP(src="10.0.0.9", dst="239.1.2.3", ttl=1,
                    options=[IPOption_Router_Alert()]) /
                 (IGMPv3(type=0x11)/IGMPv3mq(gaddr="239.1.2.3",
                                               numsrc=50, srcaddrs=[])), ts=1.0)
    check("IGMPW-002 query source overrun (IGMPv3)",
          "cve.query_source_overrun" in rules(
              new_pipeline(make_cfg()).process_event(decode(over4))))

    honest4 = wire(Ether(src="aa:bb:cc:00:00:09") /
                   IP(src="10.0.0.9", dst="239.1.2.3", ttl=1,
                      options=[IPOption_Router_Alert()]) /
                   (IGMPv3(type=0x11)/IGMPv3mq(gaddr="239.1.2.3",
                                                 srcaddrs=["10.1.1.1", "10.1.1.2"])),
                   ts=1.0)
    check("IGMPW-002 no false positive on honest source list",
          "cve.query_source_overrun" not in rules(
              new_pipeline(make_cfg()).process_event(decode(honest4))))

    ev6 = decode(_mld_wire(ICMPv6MLQuery2(mladdr="ff15::1", sources_number=100,
                                          sources=[]), dst="ff02::1", ts=1.0))
    check("IGMPW-002 query source overrun (MLDv2 parity)",
          "cve.query_source_overrun" in rules(
              new_pipeline(make_cfg()).process_event(ev6)))

    # --- IGMPW-003 / CVE-2019-5608: fragmented membership message ---
    frag4 = wire(Ether(src="aa:bb:cc:00:00:05") /
                 IP(src="10.0.0.5", dst="239.1.2.3", ttl=1, flags="MF",
                    options=[IPOption_Router_Alert()]) /
                 IGMP(type=0x16, gaddr="239.1.2.3"), ts=1.0)
    check("IGMPW-003 fragmented membership (IGMP)",
          "cve.fragmented_membership" in rules(
              new_pipeline(make_cfg()).process_event(decode(frag4))))

    ev = decode(wire(Ether(src="aa:bb:cc:00:00:05") /
                     IP(src="10.0.0.5", dst="239.1.2.3", ttl=1,
                        options=[IPOption_Router_Alert()]) /
                     IGMP(type=0x16, gaddr="239.1.2.3"), ts=1.0))
    check("IGMPW-003 no false positive on unfragmented IGMP",
          "cve.fragmented_membership" not in rules(
              new_pipeline(make_cfg()).process_event(ev)))

    frag6 = _mld_wire(ICMPv6MLQuery2(mladdr="::"), ts=1.0,
                      frag=True)
    check("IGMPW-003 fragmented membership (MLD parity)",
          "cve.fragmented_membership" in rules(
              new_pipeline(make_cfg()).process_event(decode(frag6))))

    # a non-first fragment is a message TAIL: no header, so content rules must
    # not run on it (otherwise every fragment tail fires bad_checksum)
    tail = wire(Ether(src="aa:bb:cc:00:00:05") /
                IP(src="10.0.0.5", dst="239.1.2.3", ttl=1, proto=2,
                   frag=3, flags=0) / (b"\x41" * 16), ts=1.0)
    ev = decode(tail)
    check("non-first fragment marked as tail", ev is not None and ev.frag_nonfirst)
    f = rules(new_pipeline(make_cfg()).process_event(ev))
    check("fragment tail does not fire bad_checksum",
          "anomaly.bad_checksum" not in f)
    check("fragment tail still reports IGMPW-003",
          "cve.fragmented_membership" in f)

    # --- config gating ---
    cfg = make_cfg(cve={"flag_invalid_record_type": False,
                        "flag_query_source_overrun": False,
                        "flag_fragmented_membership": False})
    check("CVE rules are individually disableable",
          "cve.invalid_record_type" not in rules(
              new_pipeline(cfg).process_event(decode(v4_rec_report(7)))))


def test_posture():
    print("[posture]")
    from scapy.layers.inet6 import (ICMPv6MLReport, ICMPv6MLDone,
                                    ICMPv6MLReport2, ICMPv6MLDMultAddrRec)

    def v2rep(grp):
        return wire(Ether(src="aa:bb:cc:00:00:05") /
                    IP(src="10.0.0.5", dst=grp, ttl=1,
                       options=[IPOption_Router_Alert()]) /
                    IGMP(type=0x16, gaddr=grp), ts=1.0)

    def fire(pkt):
        return rules(new_pipeline(make_cfg()).process_event(decode(pkt)))

    # IGMPW-P01 / RFC 4604: pre-v3 membership in the SSM range
    check("P01 IGMPv2 report in 232/8 flagged",
          "posture.ssm_version_mismatch" in fire(v2rep("232.1.1.1")))

    leave = wire(Ether(src="aa:bb:cc:00:00:05") /
                 IP(src="10.0.0.5", dst="224.0.0.2", ttl=1,
                    options=[IPOption_Router_Alert()]) /
                 IGMP(type=0x17, gaddr="232.1.1.1"), ts=1.0)
    check("P01 IGMPv2 leave in 232/8 flagged",
          "posture.ssm_version_mismatch" in fire(leave))

    v1 = wire(Ether(src="aa:bb:cc:00:00:05") /
              IP(src="10.0.0.5", dst="232.1.1.1", ttl=1,
                 options=[IPOption_Router_Alert()]) /
              IGMP(type=0x12, gaddr="232.1.1.1"), ts=1.0)
    check("P01 IGMPv1 report in 232/8 flagged",
          "posture.ssm_version_mismatch" in fire(v1))

    check("P01 MLDv1 report in ff3x::/32 flagged (parity)",
          "posture.ssm_version_mismatch" in fire(
              _mld_wire(ICMPv6MLReport(mladdr="ff3e::8000:1"), ts=1.0)))
    check("P01 MLDv1 done in ff3x::/32 flagged (parity)",
          "posture.ssm_version_mismatch" in fire(
              _mld_wire(ICMPv6MLDone(mladdr="ff3e::8000:1"), ts=1.0)))

    # every IPv6 SSM scope nibble (ff30::/12) counts, not just ff3e
    for g in ("ff30::1", "ff35::1", "ff3e::1", "ff3f::1"):
        if "posture.ssm_version_mismatch" not in fire(
                _mld_wire(ICMPv6MLReport(mladdr=g), ts=1.0)):
            bad = g
            break
    else:
        bad = None
    check("P01 covers the whole ff3x::/32 range", bad is None)

    # negatives: correct version, or group outside SSM
    check("P01 silent on IGMPv3 report in 232/8",
          "posture.ssm_version_mismatch" not in fire(wire(
              Ether(src="aa:bb:cc:00:00:05") /
              IP(src="10.0.0.5", dst="224.0.0.22", ttl=1,
                 options=[IPOption_Router_Alert()]) /
              (IGMPv3(type=0x22)/IGMPv3mr(records=[
                  IGMPv3gr(rtype=1, maddr="232.1.1.1",
                           srcaddrs=["10.9.9.9"])])), ts=1.0)))
    check("P01 silent on MLDv2 report in ff3x::/32",
          "posture.ssm_version_mismatch" not in fire(
              _mld_wire(ICMPv6MLReport2(records=[ICMPv6MLDMultAddrRec(
                  rtype=1, dst="ff3e::8000:1",
                  sources=["2001:db8::1"])]), ts=1.0)))
    check("P01 silent on IGMPv2 report outside SSM",
          "posture.ssm_version_mismatch" not in fire(v2rep("239.1.1.1")))
    check("P01 silent on MLDv1 report outside SSM",
          "posture.ssm_version_mismatch" not in fire(
              _mld_wire(ICMPv6MLReport(mladdr="ff15::1"), ts=1.0)))

    # config gate
    cfg = make_cfg(posture={"flag_ssm_version_mismatch": False})
    check("P01 is disableable",
          "posture.ssm_version_mismatch" not in rules(
              new_pipeline(cfg).process_event(decode(v2rep("232.1.1.1")))))


def test_passivity():
    print("[passivity]")
    # The tool must never construct/transmit IGMP. Verify no send APIs are referenced.
    import igmpwatch.main as m
    import igmpwatch.pipeline as pl
    import igmpwatch.dataplane as dpmod
    import inspect
    src = inspect.getsource(m) + inspect.getsource(pl) + inspect.getsource(dpmod)
    check("no scapy send() in hot path", "send(" not in src and "sendp(" not in src)
    from igmpwatch.main import build_filter
    f_igmp = build_filter({"mld": {"enable": False}, "capture_filter": ""})
    f_both = build_filter({"mld": {"enable": True}, "capture_filter": ""})
    check("bpf restricts to IGMP when MLD off", f_igmp == "ip proto 2")
    check("bpf adds icmp6 (MLD) when enabled",
          "ip proto 2" in f_both and "icmp6" in f_both)
    check("capture_filter override honored",
          build_filter({"capture_filter": "ip proto 2 and host 10.0.0.1"})
          == "ip proto 2 and host 10.0.0.1")
    dp_src = inspect.getsource(dpmod)
    check("dataplane only reads sysfs counters",
          "/sys/class/net/" in dp_src and "import socket" not in dp_src)
    import igmpwatch.snmp as snmpmod
    snmp_src = inspect.getsource(snmpmod)
    check("snmp is management-plane only (no segment TX)",
          "sendp(" not in snmp_src and "scapy" not in snmp_src
          and "AsyncSniffer" not in snmp_src)


def main():
    print("igmpwatch self-test\n" + "=" * 40)
    for t in (test_decode, test_anomaly, test_recon, test_flood, test_policy,
              test_dataplane, test_snmp, test_padding, test_mld, test_cve, test_posture,
              test_passivity):
        t()
    print("=" * 40)
    total = PASS + FAIL
    print(f"{PASS}/{total} passing" + ("" if FAIL == 0 else f"  ({FAIL} FAILED)"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
