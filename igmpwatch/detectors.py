"""The four control-plane detector families: flood, anomaly, recon, policy.

evaluate() is read-only against SharedState (the pipeline mutates state only
afterwards); the engine keeps its own rolling windows and learn baseline. Every
rule returns Alert objects; the pipeline dedups and persists them.
"""

import time
from collections import defaultdict, deque

from .alert import Alert
from .state import is_multicast, is_link_local

DEFAULTS = {
    'window_s': 10.0,
    'multicast_storm_count': 100,   # segment IGMP msgs in the window
    'report_storm_count': 40,       # per-source reports in the window
    'query_storm_count': 10,        # per-source queries
    'leave_storm_count': 30,        # per-source leaves
    'flap_count': 6,                # (host, group) report<->leave toggles
    'group_scan_count': 20,         # distinct groups probed by one source
    'querier_contention_sources': 3,
    'learn_window_s': 180,
    'mode': 'learn',                # 'learn' | 'enforce'
    'sensitive_groups': [],         # restricted groups (any unlisted join alerts)
    'allowlist': {},                # mac -> [groups] explicitly permitted
    'ssm_allowed': {},              # group -> [permitted sources]
}

RESERVED_GROUPS = {'224.0.0.1', '224.0.0.2'}


class Detectors:
    def __init__(self, config=None, start=None):
        cfg = dict(DEFAULTS)
        cfg.update(config or {})
        self.cfg = cfg
        self.w = float(cfg['window_s'])
        self._start = start
        # rolling windows
        self._all = deque()                          # ts of every msg
        self._by_src_kind = defaultdict(deque)       # (mac, kind) -> ts
        self._flap = defaultdict(deque)              # (mac, group) -> (ts, kind)
        self._scan = defaultdict(deque)              # mac -> (ts, group)
        self._qsrc = deque()                         # (ts, ip) query sources
        # learn baseline (the engine's own memory, not shared state)
        self._learned_pairs = set()                  # (mac, group)
        self._learned_groups = set()
        for mac, groups in (cfg.get('allowlist') or {}).items():
            for g in groups:
                self._learned_pairs.add((mac, g))

    def _trim(self, dq, now, keyed=False):
        while dq and now - (dq[0][0] if keyed else dq[0]) > self.w:
            dq.popleft()

    def _learning(self, now):
        if self._start is None:
            self._start = now
        return (self.cfg['mode'] == 'learn'
                and (now - self._start) < float(self.cfg['learn_window_s']))

    # -----------------------------------------------------------------------
    def evaluate(self, msg, state, now=None):
        if now is None:
            now = time.time()
        if self._start is None:
            self._start = now
        out = []
        mac = msg.get('src_mac')
        learning = self._learning(now)

        out += self._flood(msg, mac, now)
        out += self._anomaly(msg, state, now)
        out += self._recon(msg, mac, state, now)
        out += self._policy(msg, mac, learning, now)
        return out

    # -- flood ---------------------------------------------------------------
    def _flood(self, msg, mac, now):
        out = []
        self._all.append(now)
        self._trim(self._all, now)
        if len(self._all) >= self.cfg['multicast_storm_count']:
            out.append(Alert('flood', 'multicast_storm', 'HIGH',
                             'segment IGMP rate {} msgs/{:.0f}s'.format(len(self._all), self.w)))
        kind = msg.get('kind')
        if mac and kind in ('report', 'query', 'leave'):
            dq = self._by_src_kind[(mac, kind)]
            dq.append(now)
            self._trim(dq, now)
            thr = {'report': 'report_storm_count', 'query': 'query_storm_count',
                   'leave': 'leave_storm_count'}[kind]
            rule = {'report': 'report_storm', 'query': 'query_storm',
                    'leave': 'leave_storm'}[kind]
            sev = 'MED' if kind == 'leave' else 'HIGH'
            if len(dq) >= self.cfg[thr]:
                out.append(Alert('flood', rule, sev,
                                 '{} sent {} {}s in {:.0f}s'.format(mac, len(dq), kind, self.w),
                                 identity=mac))
        # join/leave flap per (mac, group)
        for g, k, _s in _records(msg):
            if not g or k not in ('report', 'leave'):
                continue
            dq = self._flap[(mac, g)]
            dq.append((now, k))
            self._trim(dq, now, keyed=True)
            kinds = {kk for _t, kk in dq}
            if kinds == {'report', 'leave'} and len(dq) >= self.cfg['flap_count']:
                out.append(Alert('flood', 'join_leave_flap', 'MED',
                                 '{} toggled {} {}x in {:.0f}s'.format(mac, g, len(dq), self.w),
                                 identity=mac, group=g))
        return out

    # -- anomaly -------------------------------------------------------------
    def _anomaly(self, msg, state, now):
        out = []
        mac = msg.get('src_mac')
        if msg.get('malformed'):
            if 'numgrp' in msg['malformed'] or 'exceeds' in msg['malformed']:
                out.append(Alert('anomaly', 'truncated_v3', 'MED',
                                 'v3 length/count mismatch: ' + msg['malformed'],
                                 identity=mac))
            return out                                       # don't trust the rest
        if msg.get('checksum_ok') is False:
            out.append(Alert('anomaly', 'bad_checksum', 'HIGH',
                             'corrupt/crafted IGMP checksum', identity=mac))
        if msg.get('ttl') is not None and msg['ttl'] != 1:
            out.append(Alert('anomaly', 'bad_ttl', 'HIGH',
                             'IGMP arrived with TTL {} (must be 1) — off-link injection'
                             .format(msg['ttl']), identity=mac))
        if msg['kind'] == 'query' and not msg.get('router_alert'):
            out.append(Alert('anomaly', 'no_router_alert', 'MED',
                             'v{} query without the Router Alert option'.format(msg.get('version')),
                             identity=mac))
        for g, k, _s in _records(msg):
            if g and not is_multicast(g):
                out.append(Alert('anomaly', 'non_multicast_group', 'HIGH',
                                 '{} for non-multicast address {}'.format(k, g),
                                 identity=mac, group=g))
            elif g in RESERVED_GROUPS and k == 'report':
                out.append(Alert('anomaly', 'reserved_group_report', 'HIGH',
                                 'membership report for reserved group {}'.format(g),
                                 identity=mac, group=g))
        if msg['kind'] == 'query' and msg.get('version') in (1, 2) and state.v3_seen():
            out.append(Alert('anomaly', 'version_downgrade', 'HIGH',
                             'v{} query after v3 seen — defeats SSM source filtering'
                             .format(msg['version']), identity=mac))
        return out

    # -- recon ---------------------------------------------------------------
    def _recon(self, msg, mac, state, now):
        out = []
        if msg['kind'] == 'query':
            src = msg.get('ip_src')
            if src == '0.0.0.0':
                out.append(Alert('recon', 'spoofed_querier', 'HIGH',
                                 'query sourced from 0.0.0.0', identity=mac))
            elected = state.elected_querier()
            general = msg.get('group') is None
            if general and elected and src and src != elected:
                if _ip_lt(src, elected):
                    out.append(Alert('recon', 'querier_takeover', 'HIGH',
                                     '{} would win querier election over {}'.format(src, elected),
                                     identity=mac))
                else:
                    out.append(Alert('recon', 'nonquerier_query', 'HIGH',
                                     'general query from non-elected {} (querier is {})'
                                     .format(src, elected), identity=mac))
            if src and src != '0.0.0.0':
                self._qsrc.append((now, src))
                self._trim(self._qsrc, now, keyed=True)
                distinct = {ip for _t, ip in self._qsrc}
                if len(distinct) >= self.cfg['querier_contention_sources']:
                    out.append(Alert('recon', 'querier_contention', 'MED',
                                     '{} distinct query sources in {:.0f}s: {}'
                                     .format(len(distinct), self.w, sorted(distinct))))
        # group scan: one source probing many distinct groups
        for g, k, _s in _records(msg):
            if not g or k != 'report':
                continue
            dq = self._scan[mac]
            dq.append((now, g))
            self._trim(dq, now, keyed=True)
            if len({gg for _t, gg in dq}) >= self.cfg['group_scan_count']:
                out.append(Alert('recon', 'group_scan', 'HIGH',
                                 '{} probed {} distinct groups in {:.0f}s (enumeration)'
                                 .format(mac, len({gg for _t, gg in dq}), self.w),
                                 identity=mac))
        return out

    # -- policy --------------------------------------------------------------
    def _policy(self, msg, mac, learning, now):
        out = []
        sensitive = set(self.cfg.get('sensitive_groups') or [])
        ssm_allowed = self.cfg.get('ssm_allowed') or {}
        for g, k, sources in _records(msg):
            if not g or k != 'report' or is_link_local(g):
                if k == 'report' and g and g not in self._learned_groups and learning:
                    self._learned_groups.add(g)
                continue
            first_seen = g not in self._learned_groups
            if learning:
                self._learned_pairs.add((mac, g))
                if first_seen:
                    self._learned_groups.add(g)
                    out.append(Alert('policy', 'new_group', 'INFO',
                                     'first observation of group {}'.format(g),
                                     identity=mac, group=g))
                continue
            self._learned_groups.add(g)
            allowed = (mac, g) in self._learned_pairs
            if g in sensitive and not allowed:
                out.append(Alert('policy', 'sensitive_group_join', 'HIGH',
                                 '{} joined restricted group {}'.format(mac, g),
                                 identity=mac, group=g))
            elif self.cfg['mode'] == 'enforce' and not allowed:
                out.append(Alert('policy', 'unauthorized_join', 'HIGH',
                                 '{} joined {} outside the allowlist/baseline'.format(mac, g),
                                 identity=mac, group=g))
            # SSM source policy (IGMPv3 INCLUDE sources)
            if sources and g in ssm_allowed:
                permitted = set(ssm_allowed[g])
                denied = [s for s in sources if s not in permitted]
                if denied:
                    out.append(Alert('policy', 'ssm_source_denied', 'MED',
                                     '{} requested SSM sources {} for {} outside allowed set'
                                     .format(mac, denied, g), identity=mac, group=g))
        return out


def _records(msg):
    if msg.get('records'):
        for r in msg['records']:
            yield r['group'], r['kind'], r.get('sources') or []
    elif msg.get('kind') in ('report', 'leave') and msg.get('group'):
        yield msg['group'], msg['kind'], msg.get('sources') or []


def _ip_lt(a, b):
    import ipaddress
    try:
        return ipaddress.ip_address(a) < ipaddress.ip_address(b)
    except ValueError:
        return False
