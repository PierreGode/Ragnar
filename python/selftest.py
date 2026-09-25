#!/usr/bin/env python3
"""selftest.py — offline self-test for the igmpwatch package (no root, no NIC,
no Scapy). Builds raw IGMP frames in pure Python and drives every module:
decode, the four detector families, shared state, the data-plane sampler, the
SNMP evaluators + capability cache, storage, and config. Two checks assert the
data-plane and SNMP modules import no socket library.

Run:  python3 selftest.py   (or  python3 -m igmpwatch --self-test)
"""

import os
import struct
import subprocess
import sys

# The igmpwatch package lives in the repo root (this file is under python/).
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from igmpwatch import decode, detectors, dataplane, snmp, storage, config
from igmpwatch import state as st
from igmpwatch.alert import Alert, Deduper


# --------------------------------------------------------------------------
# Pure-Python frame builders
# --------------------------------------------------------------------------
def _ipb(ip):
    return bytes(int(x) for x in ip.split('.'))


def _macb(m):
    return bytes(int(x, 16) for x in m.split(':'))


def eth(payload, src='aa:bb:cc:00:00:01', dst='01:00:5e:00:00:01', tagged=False, pad=0):
    f = _macb(dst) + _macb(src)
    if tagged:
        f += struct.pack('!H', 0x8100) + b'\x00\x64'
    f += struct.pack('!H', 0x0800) + payload
    if pad and len(f) < pad:
        f += b'\xff' * (pad - len(f))
    return f


def ipv4(payload, src='10.0.0.5', dst='239.1.1.1', ttl=1, router_alert=False):
    opts = b'\x94\x04\x00\x00' if router_alert else b''
    ihl = (20 + len(opts)) // 4
    total = 20 + len(opts) + len(payload)
    hdr = struct.pack('!BBHHHBBH', 0x40 | ihl, 0, total, 1, 0, ttl, 2, 0)
    hdr += _ipb(src) + _ipb(dst) + opts
    return hdr + payload


def _cksum(b):
    cs = decode._checksum(b)
    return b[:2] + struct.pack('!H', cs) + b[4:]


def igmp_v2(mtype, group, maxresp=100):
    return _cksum(struct.pack('!BB', mtype, maxresp) + b'\x00\x00' + _ipb(group))


def igmp_v3_report(records):
    recs = b''
    for rtype, group, sources in records:
        recs += struct.pack('!BBH', rtype, 0, len(sources)) + _ipb(group)
        for s in sources:
            recs += _ipb(s)
    b = struct.pack('!BBHHH', 0x22, 0, 0, 0, len(records)) + recs
    return _cksum(b)


def igmp_v3_query(group='0.0.0.0', sources=()):
    b = (struct.pack('!BB', 0x11, 100) + b'\x00\x00' + _ipb(group)
         + b'\x00\x00' + struct.pack('!H', len(sources)))
    for s in sources:
        b += _ipb(s)
    return _cksum(b)


def report(group, mac='aa:bb:cc:00:00:01', src='10.0.0.5', ttl=1, v=2):
    t = 0x16 if v == 2 else 0x12
    return eth(ipv4(igmp_v2(t, group), src=src, dst=group, ttl=ttl), src=mac)


def leave(group, mac='aa:bb:cc:00:00:01', src='10.0.0.5'):
    return eth(ipv4(igmp_v2(0x17, group), src=src, dst='224.0.0.2'), src=mac)


def query(src='10.0.0.1', group='0.0.0.0', router_alert=True, mac='aa:bb:cc:00:00:09'):
    return eth(ipv4(igmp_v2(0x11, group), src=src, dst='224.0.0.1',
                    router_alert=router_alert), src=mac)


# --------------------------------------------------------------------------
class H:
    def __init__(self, verbose):
        self.n = 0
        self.fail = 0
        self.verbose = verbose

    def ck(self, name, cond):
        self.n += 1
        ok = bool(cond)
        if not ok:
            self.fail += 1
        if self.verbose:
            print('  [{}] {}'.format('PASS' if ok else 'FAIL', name))


def _rules(det, state, raw, now=0.0):
    m = decode.decode_frame(raw)
    return {a.rule for a in det.evaluate(m, state, now)}, m


def run(verbose=True):
    h = H(verbose)

    # ---- decode -----------------------------------------------------------
    m = decode.decode_frame(report('239.1.1.1'))
    h.ck('decode v2 report kind', m and m['kind'] == 'report')
    h.ck('decode v2 report group', m and m['group'] == '239.1.1.1')
    h.ck('decode v2 report version', m and m['version'] == 2)
    h.ck('decode checksum ok', m and m['checksum_ok'] is True)
    h.ck('decode src_mac', m and m['src_mac'] == 'aa:bb:cc:00:00:01')
    m = decode.decode_frame(leave('239.1.1.1'))
    h.ck('decode v2 leave kind', m and m['kind'] == 'leave')
    m = decode.decode_frame(query())
    h.ck('decode v2 query general (group None)', m and m['kind'] == 'query' and m['group'] is None)
    m = decode.decode_frame(query(group='239.1.1.1'))
    h.ck('decode group-specific query', m and m['group'] == '239.1.1.1')
    m = decode.decode_frame(eth(ipv4(igmp_v2(0x16, '239.1.1.1'), ttl=64)))
    h.ck('decode ttl carried', m and m['ttl'] == 64)
    m = decode.decode_frame(eth(ipv4(igmp_v2(0x11, '0.0.0.0'), dst='224.0.0.1', router_alert=True)))
    h.ck('decode router_alert', m and m['router_alert'] is True)
    m = decode.decode_frame(eth(ipv4(igmp_v3_report([(4, '239.2.2.2', [])]), dst='224.0.0.22')))
    h.ck('decode v3 join (exclude{})', m and m['kind'] == 'report' and m['group'] == '239.2.2.2')
    m = decode.decode_frame(eth(ipv4(igmp_v3_report([(3, '239.2.2.2', [])]), dst='224.0.0.22')))
    h.ck('decode v3 leave (to_include{})', m and m['kind'] == 'leave')
    m = decode.decode_frame(eth(ipv4(igmp_v3_report([(1, '239.5.5.5', ['10.0.0.9'])]), dst='224.0.0.22')))
    h.ck('decode v3 SSM include sources', m and m.get('sources') == ['10.0.0.9'])
    m = decode.decode_frame(eth(ipv4(igmp_v3_report([(4, '239.1.1.1', []), (4, '239.2.2.2', [])]), dst='224.0.0.22')))
    h.ck('decode v3 multi-record', m and len(m.get('records', [])) == 2)
    # truncated v3: claim 3 records, ship 1
    bad = struct.pack('!BBHHH', 0x22, 0, 0, 0, 3) + struct.pack('!BBH', 4, 0, 0) + _ipb('239.1.1.1')
    bad = _cksum(bad)
    m = decode.decode_frame(eth(ipv4(bad, dst='224.0.0.22')))
    h.ck('decode truncated v3 -> malformed', m and m['malformed'])
    # bad checksum
    b = igmp_v2(0x16, '239.1.1.1')
    b = b[:2] + b'\xde\xad' + b[4:]
    m = decode.decode_frame(eth(ipv4(b)))
    h.ck('decode bad checksum flagged', m and m['checksum_ok'] is False)
    # non-IP
    h.ck('decode non-IP -> None', decode.decode_frame(_macb('11:22:33:44:55:66') * 2 + b'\x08\x06' + b'\x00' * 40) is None)
    # 802.1Q tagged
    m = decode.decode_frame(eth(ipv4(igmp_v2(0x16, '239.7.7.7'), dst='239.7.7.7'), tagged=True))
    h.ck('decode 802.1Q tagged', m and m['group'] == '239.7.7.7')
    # padding-safe: pad to 64B, group still parses, not malformed
    m = decode.decode_frame(report('239.1.1.1')[:60] + b'\xff' * 20 if False else eth(ipv4(igmp_v2(0x16, '239.1.1.1'), dst='239.1.1.1'), pad=64))
    h.ck('decode padding-safe (min-frame pad ignored)', m and m['group'] == '239.1.1.1' and not m['malformed'])

    # ---- flood ------------------------------------------------------------
    d = detectors.Detectors({'report_storm_count': 40}); s = st.SharedState()
    hit = set()
    for i in range(45):
        r, _ = _rules(d, s, report('239.1.1.1'), i * 0.1); hit |= r
    h.ck('flood report_storm', 'report_storm' in hit)
    d = detectors.Detectors({'query_storm_count': 10}); s = st.SharedState()
    hit = set()
    for i in range(12):
        r, _ = _rules(d, s, query(), i * 0.1); hit |= r
    h.ck('flood query_storm', 'query_storm' in hit)
    d = detectors.Detectors({'leave_storm_count': 30}); s = st.SharedState()
    hit = set()
    for i in range(35):
        r, _ = _rules(d, s, leave('239.3.3.3'), i * 0.1); hit |= r
    h.ck('flood leave_storm', 'leave_storm' in hit)
    d = detectors.Detectors({'multicast_storm_count': 50}); s = st.SharedState()
    hit = set()
    for i in range(55):
        r, _ = _rules(d, s, report('239.1.1.1'), i * 0.01); hit |= r
    h.ck('flood multicast_storm', 'multicast_storm' in hit)
    d = detectors.Detectors({'flap_count': 6}); s = st.SharedState()
    hit = set()
    for i in range(8):
        raw = report('239.4.4.4') if i % 2 == 0 else leave('239.4.4.4')
        r, _ = _rules(d, s, raw, i * 0.1); hit |= r
    h.ck('flood join_leave_flap', 'join_leave_flap' in hit)
    d = detectors.Detectors(); s = st.SharedState()
    r, _ = _rules(d, s, report('239.1.1.1'))
    h.ck('flood quiet on single report', 'report_storm' not in r and 'multicast_storm' not in r)

    # ---- anomaly ----------------------------------------------------------
    d = detectors.Detectors(); s = st.SharedState()
    r, _ = _rules(d, s, eth(ipv4(igmp_v2(0x16, '239.1.1.1'), ttl=64)))
    h.ck('anomaly bad_ttl', 'bad_ttl' in r)
    d = detectors.Detectors(); s = st.SharedState()
    b = igmp_v2(0x16, '239.1.1.1'); b = b[:2] + b'\xde\xad' + b[4:]
    r, _ = _rules(d, s, eth(ipv4(b)))
    h.ck('anomaly bad_checksum', 'bad_checksum' in r)
    d = detectors.Detectors(); s = st.SharedState()
    r, _ = _rules(d, s, query(router_alert=False))
    h.ck('anomaly no_router_alert', 'no_router_alert' in r)
    d = detectors.Detectors(); s = st.SharedState()
    r, _ = _rules(d, s, query(router_alert=True))
    h.ck('anomaly no_router_alert quiet with RA', 'no_router_alert' not in r)
    d = detectors.Detectors(); s = st.SharedState()
    r, _ = _rules(d, s, eth(ipv4(igmp_v2(0x16, '10.0.0.9'), dst='10.0.0.9')))
    h.ck('anomaly non_multicast_group', 'non_multicast_group' in r)
    d = detectors.Detectors(); s = st.SharedState()
    r, _ = _rules(d, s, eth(ipv4(igmp_v2(0x16, '224.0.0.1'), dst='224.0.0.1')))
    h.ck('anomaly reserved_group_report', 'reserved_group_report' in r)
    d = detectors.Detectors(); s = st.SharedState()
    m3 = decode.decode_frame(eth(ipv4(igmp_v3_report([(4, '239.2.2.2', [])]), dst='224.0.0.22')))
    d.evaluate(m3, s, 0.0); s.apply(m3, 0.0)
    r, _ = _rules(d, s, query(group='0.0.0.0'), 1.0)
    h.ck('anomaly version_downgrade', 'version_downgrade' in r)
    d = detectors.Detectors(); s = st.SharedState()
    r, m = _rules(d, s, eth(ipv4(bad if False else _cksum(struct.pack('!BBHHH', 0x22, 0, 0, 0, 3) + struct.pack('!BBH', 4, 0, 0) + _ipb('239.1.1.1')), dst='224.0.0.22')))
    h.ck('anomaly truncated_v3', 'truncated_v3' in r)

    # ---- recon ------------------------------------------------------------
    d = detectors.Detectors(); s = st.SharedState()
    r, _ = _rules(d, s, query(src='0.0.0.0'))
    h.ck('recon spoofed_querier', 'spoofed_querier' in r)
    d = detectors.Detectors(); s = st.SharedState()
    q1 = decode.decode_frame(query(src='10.0.0.5'))
    d.evaluate(q1, s, 0.0); s.apply(q1, 0.0)
    r, _ = _rules(d, s, query(src='10.0.0.1'), 1.0)
    h.ck('recon querier_takeover', 'querier_takeover' in r)
    d = detectors.Detectors(); s = st.SharedState()
    q1 = decode.decode_frame(query(src='10.0.0.1'))
    d.evaluate(q1, s, 0.0); s.apply(q1, 0.0)
    r, _ = _rules(d, s, query(src='10.0.0.9'), 1.0)
    h.ck('recon nonquerier_query', 'nonquerier_query' in r)
    d = detectors.Detectors({'querier_contention_sources': 3}); s = st.SharedState()
    hit = set()
    for i, ip in enumerate(('10.0.0.1', '10.0.0.2', '10.0.0.3')):
        r, _ = _rules(d, s, query(src=ip), i * 0.1); hit |= r
    h.ck('recon querier_contention', 'querier_contention' in hit)
    d = detectors.Detectors({'group_scan_count': 20}); s = st.SharedState()
    hit = set()
    for i in range(25):
        r, _ = _rules(d, s, report('239.0.0.%d' % (i + 1)), i * 0.05); hit |= r
    h.ck('recon group_scan', 'group_scan' in hit)

    # ---- policy -----------------------------------------------------------
    d = detectors.Detectors({'sensitive_groups': ['239.9.9.9'], 'learn_window_s': 0}); s = st.SharedState()
    r, _ = _rules(d, s, report('239.9.9.9'), 1.0)
    h.ck('policy sensitive_group_join', 'sensitive_group_join' in r)
    d = detectors.Detectors({'mode': 'enforce', 'learn_window_s': 0}); s = st.SharedState()
    r, _ = _rules(d, s, report('239.8.8.8'), 1.0)
    h.ck('policy unauthorized_join (enforce)', 'unauthorized_join' in r)
    d = detectors.Detectors({'mode': 'enforce', 'learn_window_s': 0,
                             'allowlist': {'aa:bb:cc:00:00:01': ['239.8.8.8']}}); s = st.SharedState()
    r, _ = _rules(d, s, report('239.8.8.8'), 1.0)
    h.ck('policy allowlist suppresses unauthorized', 'unauthorized_join' not in r)
    d = detectors.Detectors({'learn_window_s': 100}); s = st.SharedState()
    r, _ = _rules(d, s, report('239.7.7.7'), 1.0)
    h.ck('policy new_group (learn)', 'new_group' in r)
    d = detectors.Detectors({'learn_window_s': 0, 'ssm_allowed': {'239.5.5.5': ['10.0.0.1']}}); s = st.SharedState()
    raw = eth(ipv4(igmp_v3_report([(1, '239.5.5.5', ['10.9.9.9'])]), dst='224.0.0.22'))
    r, _ = _rules(d, s, raw, 1.0)
    h.ck('policy ssm_source_denied', 'ssm_source_denied' in r)

    # ---- state ------------------------------------------------------------
    s = st.SharedState()
    s.apply(decode.decode_frame(report('239.1.1.1', mac='aa:bb:cc:00:00:01')))
    h.ck('state membership recorded', 'aa:bb:cc:00:00:01' in s.group_members('239.1.1.1'))
    s.apply(decode.decode_frame(leave('239.1.1.1', mac='aa:bb:cc:00:00:01')))
    h.ck('state leave removes member', 'aa:bb:cc:00:00:01' not in s.group_members('239.1.1.1'))
    s = st.SharedState()
    s.apply(decode.decode_frame(query(src='10.0.0.9')))
    s.apply(decode.decode_frame(query(src='10.0.0.2')))
    h.ck('state querier election (lowest IP)', s.elected_querier() == '10.0.0.2')
    s = st.SharedState()
    s.apply(decode.decode_frame(eth(ipv4(igmp_v3_report([(4, '239.2.2.2', [])]), dst='224.0.0.22'))))
    h.ck('state v3_seen', s.v3_seen() is True)
    s = st.SharedState()
    s.apply(decode.decode_frame(report('224.0.0.251')))       # mDNS (benign)
    s.apply(decode.decode_frame(report('239.1.2.3')))
    dg = s.data_groups()
    h.ck('state data_groups excludes benign', '224.0.0.251' not in dg and '239.1.2.3' in dg)

    # ---- dataplane --------------------------------------------------------
    A = lambda p, c, dt, g, cfg=None: {x.rule for x in dataplane.evaluate(p, c, dt, g, cfg)}
    h.ck('dp priming read empty', A(None, {'rx_packets': 1, 'multicast': 1, 'rx_dropped': 0}, 5, 0) == set())
    prev = {'rx_packets': 1000, 'multicast': 100, 'rx_dropped': 0}
    cur = {'rx_packets': 1100, 'multicast': 100 + 6000, 'rx_dropped': 0}
    h.ck('dp mcast_storm', 'mcast_storm' in A(prev, cur, 5.0, 3, {'mcast_storm_pps': 1000}))
    cur2 = {'rx_packets': 1000 + 600, 'multicast': 100 + 600, 'rx_dropped': 0}
    h.ck('dp mcast_flood_no_members', 'mcast_flood_no_members' in A(prev, cur2, 5.0, 0, {'flood_no_members_pps': 50}))
    h.ck('dp flood_no_members quiet with members', 'mcast_flood_no_members' not in A(prev, cur2, 5.0, 2, {'flood_no_members_pps': 50}))
    cur3 = {'rx_packets': 1000 + 1000, 'multicast': 100 + 800, 'rx_dropped': 0}
    h.ck('dp mcast_ratio', 'mcast_ratio' in A(prev, cur3, 5.0, 3, {'mcast_ratio': 0.6, 'mcast_ratio_floor_pps': 10}))
    cur4 = {'rx_packets': 1100, 'multicast': 110, 'rx_dropped': 50}
    h.ck('dp rx_drops', 'rx_drops' in A(prev, cur4, 5.0, 3))
    reset = {'rx_packets': 5, 'multicast': 1, 'rx_dropped': 0}
    h.ck('dp counter reset re-primes', A(prev, reset, 5.0, 0) == set())

    # ---- snmp evaluators + cache ------------------------------------------
    pi = {'2': {'in': 1000, 'out': 1000}}
    ci = {'2': {'in': 1000 + 8000, 'out': 1000}}
    h.ck('snmp iface_mcast_storm', 'iface_mcast_storm' in {a.rule for a in snmp.evaluate_ifaces(pi, ci, 5.0, {'iface_mcast_storm_pps': 1000})})
    h.ck('snmp iface monitor whitelist', snmp.evaluate_ifaces(pi, ci, 5.0, {'iface_mcast_storm_pps': 1000, 'monitor_ifaces': [99]}) == [])
    h.ck('snmp unsubscribed_forwarding', 'unsubscribed_forwarding' in {a.rule for a in snmp.evaluate_groups(['239.9.9.9'], set())})
    h.ck('snmp unsubscribed quiet if joined', snmp.evaluate_groups(['239.9.9.9'], {'239.9.9.9'}) == [])
    h.ck('snmp link-local excluded', snmp.evaluate_groups(['224.0.0.5'], set()) == [])
    h.ck('snmp census_not_forwarded opt-in off', snmp.evaluate_groups(['239.1.1.1'], {'239.2.2.2'}, {'census_not_forwarded': False}) and all(a.rule != 'census_not_forwarded' for a in snmp.evaluate_groups(['239.1.1.1'], {'239.2.2.2'}, {'census_not_forwarded': False})))
    h.ck('snmp census_not_forwarded opt-in on', 'census_not_forwarded' in {a.rule for a in snmp.evaluate_groups(['239.1.1.1'], {'239.2.2.2'}, {'census_not_forwarded': True})})
    cache = snmp.CapabilityCache(strikes=3, ttl=3600)
    cache.record_walk('sw1', reachable=True, nonempty=False, now=0)
    cache.record_walk('sw1', reachable=True, nonempty=False, now=1)
    h.ck('cache still supported after 2 strikes', cache.supported('sw1', now=2) is True)
    cache.record_walk('sw1', reachable=True, nonempty=False, now=2)
    h.ck('cache unsupported after 3 strikes', cache.supported('sw1', now=3) is False)
    h.ck('cache TTL re-check', cache.supported('sw1', now=3 + 3601) is True)
    cache2 = snmp.CapabilityCache(strikes=3)
    cache2.record_walk('sw2', reachable=False, nonempty=False, now=0)
    h.ck('cache unreachable records nothing', cache2._get('sw2') is None)
    cache2.seed('sw3', supported=True)
    h.ck('cache seed authoritative', cache2.supported('sw3') is True)
    cache3 = snmp.CapabilityCache(strikes=2)
    cache3.record_walk('sw4', True, False, 0); cache3.record_walk('sw4', True, False, 1)
    cache3.record_walk('sw4', True, True, 2)
    h.ck('cache nonempty walk resets', cache3.supported('sw4', now=3) is True)

    # ---- storage ----------------------------------------------------------
    store = storage.Storage(':memory:')
    store.record_event(Alert('anomaly', 'bad_ttl', 'HIGH', 'x', identity='m'))
    h.ck('storage record_event', store.event_count() == 1)
    store.set('sw9', {'supported': False, 'strikes': 3, 'ts': 1.0})
    h.ck('storage cap store roundtrip', store.get('sw9')['supported'] is False)
    s2 = st.SharedState(); s2.apply(decode.decode_frame(report('239.1.1.1')))
    store.persist_state(s2)
    h.ck('storage persist_state memberships',
         store.db.execute('SELECT COUNT(*) FROM memberships').fetchone()[0] == 1)
    store.close()

    # ---- config -----------------------------------------------------------
    cfg, note = config.load(None)
    h.ck('config defaults load', cfg['mode'] == 'learn' and 'detectors' in cfg)
    merged = config._deep_merge({'a': {'x': 1, 'y': 2}}, {'a': {'y': 9}})
    h.ck('config deep_merge', merged['a'] == {'x': 1, 'y': 9})
    cfg2, _ = config.load(None)
    h.ck('config mode mirrored into detectors', cfg2['detectors']['mode'] == cfg2['mode'])

    # ---- alert dedup ------------------------------------------------------
    dd = Deduper(window=10)
    a1 = Alert('anomaly', 'bad_ttl', 'HIGH', 'x', identity='m', ts=0)
    a2 = Alert('anomaly', 'bad_ttl', 'HIGH', 'x', identity='m', ts=1)
    a3 = Alert('anomaly', 'bad_ttl', 'HIGH', 'x', identity='m', ts=20)
    h.ck('dedup admits first', dd.admit(a1) is a1)
    h.ck('dedup suppresses within window', dd.admit(a2) is None)
    out = dd.admit(a3)
    h.ck('dedup re-emits after window with rollup', out is a3 and out.suppressed == 1)

    # ---- import isolation (subprocess) ------------------------------------
    def _no_socket(mod):
        r = subprocess.run(
            [sys.executable, '-c',
             'import {}, sys; print("socket" in sys.modules)'.format(mod)],
            capture_output=True, text=True, cwd=REPO)
        return r.stdout.strip() == 'False'
    h.ck('dataplane imports no socket', _no_socket('igmpwatch.dataplane'))
    h.ck('snmp imports no socket', _no_socket('igmpwatch.snmp'))

    total = h.n
    passed = total - h.fail
    print('igmpwatch self-test: {}/{} {}'.format(
        passed, total, 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


if __name__ == '__main__':
    sys.exit(run(verbose=True))
