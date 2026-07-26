#!/usr/bin/env python3
"""incident_engine.py — cross-signal correlation for Ragnar's alert streams.

Ragnar has many sharp point detectors (arp_guard, ndpwatch, wifiwatch, certwatch,
the L2/L3 Watch suite, the Network Integrity Monitor …), and Watchtower already
gathers their alerts into one normalized feed. But a flat feed is still a pile of
dots: a deauth here, a rogue RA there, a cert name-mismatch somewhere else. The
value an enterprise NDR sells is **fusion** — recognising that those three dots
are one campaign against one victim, and saying so.

This engine consumes Watchtower-normalized alerts and does two things:

1. **Entity clustering.** Alerts that share a network entity (a MAC, IP, BSSID,
   or SSID) inside a sliding window are joined into one *incident*, transitively.
   Three detectors implicating the same attacker MAC is one story, not three.

2. **Attack-chain recognition.** Each alert maps to an abstract *signal category*
   (wifi_recon, l2_spoof, tls_intercept, …), robust to individual code churn. An
   incident's accumulated categories are matched against a small library of named
   campaigns (evil-twin handshake capture, ARP MITM with TLS interception, rogue
   first-hop takeover, routing hijack …). A named match raises the incident's
   confidence and severity above any single alert.

It is pure analysis over already-collected alerts — no capture, no I/O of its
own. Fully offline-testable: ``python3 incident_engine.py --self-test``.
"""

import collections
import ipaddress
import json
import re
import sys
import time

MODULE = 'incident_engine'

SEV_ORDER = ('info', 'low', 'medium', 'high', 'critical')
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

_MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$', re.I)

# Entities that appear across many unrelated alerts and would collapse everything
# into one giant incident if used as a correlation key.
_MAC_SKIP = {'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'}


# --------------------------------------------------------------------------
# Entity extraction + classification
# --------------------------------------------------------------------------

def _classify(value):
    """('mac'|'ip'|'ssid'|None, canonical_value) for a candidate entity."""
    if value is None:
        return None, None
    v = str(value).strip()
    if not v:
        return None, None
    low = v.lower()
    if _MAC_RE.match(low):
        if low in _MAC_SKIP:
            return None, None
        return 'mac', low
    # IP (v4/v6). Skip unspecified / loopback / all-nodes multicast.
    try:
        ip = ipaddress.ip_address(v.split('%')[0])
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
            return None, None
        return 'ip', ip.compressed
    except ValueError:
        pass
    # An SSID only counts as an entity when the alert is about SSID identity
    # (evil twin / PNL); the caller tags those, so here we accept the raw string.
    return 'ssid', v


# Raw-record keys worth mining for entities beyond the normalized src/target.
_ENTITY_KEYS = ('src', 'target', 'station', 'bssid', 'sender_ip', 'server_ip',
                'system', 'saddr', 'daddr', 'victim', 'gateway')
_SSID_KEYS = ('ssid',)


def extract_entities(alert):
    """Set of (kind, value) entities an alert is *about*. MAC/IP are strong
    correlation keys; SSID is included only for wifi-identity detectors."""
    ents = set()
    raw = alert.get('raw') or {}
    for k in _ENTITY_KEYS:
        for src in (alert, raw):
            kind, val = _classify(src.get(k))
            if kind in ('mac', 'ip'):
                ents.add((kind, val))
    # SSID entities: only from the detectors where the SSID *is* the target of
    # the attack (evil twin / PNL / downgrade), else a shared SSID over-merges.
    cats = categorize(alert)
    if cats & {'wifi_recon', 'wifi_rogue_ap', 'wifi_downgrade'}:
        for k in _SSID_KEYS:
            for src in (alert, raw):
                v = src.get(k)
                if v:
                    ents.add(('ssid', str(v)))
    return ents


# --------------------------------------------------------------------------
# Signal categorization  (detector code -> abstract category)
# --------------------------------------------------------------------------
# Categories are what the attack-chain patterns are written against, so a change
# to any single detector's code list never breaks the patterns.

# Exact detector/code -> category.
_CODE_CAT = {
    # wifiwatch
    'pnl_leak': 'wifi_recon',
    'evil_twin': 'wifi_rogue_ap', 'karma_mana': 'wifi_rogue_ap',
    'beacon_flood': 'wifi_rogue_ap',
    'deauth_flood': 'wifi_dos',
    'handshake_harvest': 'wifi_handshake', 'pmkid_harvest': 'wifi_handshake',
    'wpa_downgrade': 'wifi_downgrade', 'wpa3_transition': 'wifi_downgrade',
    # arp_guard
    'binding_flap': 'l2_spoof', 'binding_conflict': 'l2_spoof',
    'garp_subnet_poison': 'l2_spoof', 'garp_rate_flood': 'l2_spoof',
    'gw_mac_change': 'l2_spoof',
}

# Substring / prefix rules for coded families and free-text verdicts.
_CAT_RULES = (
    ('ndp', ('NDP-001', 'NDP-002', 'NDP-003', 'NDP-005'), 'l2_spoof'),     # NA spoof
    ('ndp', ('NDP-006', 'NDP-007', 'NDP-008', 'NDP-009', 'NDP-020'), 'rogue_gateway'),
    ('ndp', ('NDP-010',), 'dns_hijack'),                                   # RDNSS
    ('ndp', ('NDP-016',), 'redirect'),
    ('certwatch', ('NAME_MISMATCH', 'SELF_SIGNED'), 'tls_intercept'),
)

# Free-text verdict keywords (Network Integrity Monitor + tcpdump watchers).
_VERDICT_CAT = (
    ('rogue-ra', 'rogue_gateway'), ('rogue-router', 'routing_inject'),
    ('starvation', 'dhcp_rogue'), ('rogue', 'dhcp_rogue'),
    ('spoof', 'l2_spoof'), ('poison', 'l2_spoof'),
    ('hijack', 'dns_hijack'), ('injection', 'routing_inject'),
    ('redirect', 'redirect'), ('relay', 'tls_intercept'),
    ('coercion', 'tls_intercept'), ('downgrade', 'wifi_downgrade'),
)


def categorize(alert):
    """Set of abstract signal categories an alert contributes."""
    cats = set()
    source = (alert.get('source') or '').lower()
    codes = alert.get('codes') or []
    title = (alert.get('title') or '').lower()
    for c in codes:
        if c in _CODE_CAT:
            cats.add(_CODE_CAT[c])
    for src_hint, code_set, cat in _CAT_RULES:
        if src_hint in source and any(c in code_set for c in codes):
            cats.add(cat)
    # certwatch by-code even when the source is folded into a code list.
    for c in codes:
        if c in ('NAME_MISMATCH', 'SELF_SIGNED') and 'cert' in source:
            cats.add('tls_intercept')
    # Free-text fallback for verdicts that arrive without stable codes.
    hay = title + ' ' + ' '.join(str(c).lower() for c in codes)
    for kw, cat in _VERDICT_CAT:
        if kw in hay:
            cats.add(cat)
    return cats


# --------------------------------------------------------------------------
# Attack-chain pattern library  (written against categories)
# --------------------------------------------------------------------------
# `all_of`: every listed category must be present. `any_of`: at least one from
# each listed group. Most-specific (highest `rank`) matching pattern wins.

PATTERNS = [
    {'name': 'evil_twin_handshake_capture',
     'label': 'Evil-twin WPA handshake capture',
     'technique': 'Rogue AP → forced deauth → 4-way/PMKID capture',
     'any_of': [{'wifi_rogue_ap'}, {'wifi_dos'}], 'all_of': {'wifi_handshake'},
     'severity': 'critical', 'rank': 5},
    {'name': 'wifi_handshake_harvest',
     'label': 'Forced-reconnect WPA handshake harvest',
     'technique': 'Deauth → 4-way handshake capture',
     'all_of': {'wifi_dos', 'wifi_handshake'},
     'severity': 'critical', 'rank': 4},
    {'name': 'pnl_impersonation',
     'label': 'PNL-driven network impersonation',
     'technique': 'Probe/PNL harvest → rogue AP for a saved SSID',
     'all_of': {'wifi_recon', 'wifi_rogue_ap'},
     'severity': 'high', 'rank': 3},
    {'name': 'l2_mitm_tls',
     'label': 'ARP/L2 MITM with TLS interception',
     'technique': 'ARP spoof → traffic redirect → cert substitution',
     'all_of': {'l2_spoof', 'tls_intercept'},
     'severity': 'critical', 'rank': 5},
    {'name': 'ipv6_mitm',
     'label': 'IPv6 SLAAC/ND MITM',
     'technique': 'Rogue RA / NA spoof → DNS or TLS interception',
     'any_of': [{'rogue_gateway', 'l2_spoof'}, {'dns_hijack', 'tls_intercept', 'redirect'}],
     'severity': 'critical', 'rank': 5},
    {'name': 'rogue_first_hop',
     'label': 'Rogue first-hop / gateway takeover',
     'technique': 'Rogue DHCP or RA → DNS hijack / redirect',
     'any_of': [{'dhcp_rogue', 'rogue_gateway'}, {'dns_hijack', 'redirect'}],
     'severity': 'critical', 'rank': 4},
    {'name': 'routing_hijack',
     'label': 'Routing-plane hijack',
     'technique': 'OSPF/EIGRP/IS-IS/BGP injection → path diversion',
     'all_of': {'routing_inject'},
     'severity': 'high', 'rank': 2},
]


def match_pattern(cats):
    """Best (most specific) pattern whose category requirements `cats` meets."""
    best = None
    for p in PATTERNS:
        if not p.get('all_of', set()) <= cats:
            continue
        if not all(grp & cats for grp in p.get('any_of', [])):
            continue
        if best is None or p['rank'] > best['rank']:
            best = p
    return best


# --------------------------------------------------------------------------
# Incident engine
# --------------------------------------------------------------------------

class Incident:
    __slots__ = ('id', 'opened_ts', 'last_ts', 'entities', 'sources', 'cats',
                 'alerts', 'pattern', 'max_rank')

    def __init__(self, iid, ts):
        self.id = iid
        self.opened_ts = ts
        self.last_ts = ts
        self.entities = set()        # (kind, value)
        self.sources = set()
        self.cats = set()
        self.alerts = []             # compact alert refs
        self.pattern = None
        self.max_rank = 0

    def confidence(self):
        """0-100: distinct sources + distinct categories + a named pattern."""
        score = 22 * max(0, len(self.sources) - 1) + 12 * len(self.cats)
        if self.pattern:
            score += 40
        return max(0, min(100, score))

    def severity(self):
        base = SEV_ORDER[self.max_rank]
        if self.pattern:
            return _sev_max(base, self.pattern['severity'])
        # An un-named cluster spanning ≥2 sources is worth at least 'high'.
        if len(self.sources) >= 2:
            return _sev_max(base, 'high')
        return base

    def to_dict(self):
        ents = collections.defaultdict(list)
        for kind, val in sorted(self.entities):
            ents[kind].append(val)
        return {
            'id': self.id, 'opened_ts': self.opened_ts, 'last_ts': self.last_ts,
            'severity': self.severity(), 'confidence': self.confidence(),
            'pattern': (self.pattern or {}).get('name'),
            'label': (self.pattern or {}).get('label') or self._fallback_label(),
            'technique': (self.pattern or {}).get('technique'),
            'entities': dict(ents), 'sources': sorted(self.sources),
            'categories': sorted(self.cats), 'alert_count': len(self.alerts),
            'alerts': self.alerts[-12:],
        }

    def _fallback_label(self):
        if len(self.sources) >= 2:
            return 'Multi-detector activity on a shared entity'
        return 'Correlated activity'


def _sev_max(a, b):
    return a if SEV_RANK.get(a, 0) >= SEV_RANK.get(b, 0) else b


class IncidentEngine:
    """Fuse a stream of Watchtower-normalized alerts into correlated incidents."""

    def __init__(self, window_s=600.0, max_incidents=200):
        self.window_s = float(window_s)
        self.max_incidents = int(max_incidents)
        self._incidents = collections.OrderedDict()   # id -> Incident
        self._next_id = 1

    def _expired(self, inc, now):
        return (now - inc.last_ts) > self.window_s

    def ingest(self, alert):
        """Fold one alert into the incident set. Returns the affected Incident,
        or None if the alert carried no correlatable entity."""
        ts = float(alert.get('ts') or time.time())
        ents = extract_entities(alert)
        if not ents:
            return None
        cats = categorize(alert)
        rank = SEV_RANK.get(alert.get('severity'), 0)

        # Find every live incident that shares an entity, then union them so a
        # bridging alert (A shares with X, also shares with Y) fuses X and Y.
        hits = [inc for inc in self._incidents.values()
                if not self._expired(inc, ts) and (inc.entities & ents)]
        if hits:
            target = hits[0]
            for other in hits[1:]:
                self._absorb(target, other)
                self._incidents.pop(other.id, None)
        else:
            target = Incident(self._next_id, ts)
            self._incidents[self._next_id] = target
            self._next_id += 1

        target.entities |= ents
        target.cats |= cats
        target.sources.add(alert.get('source') or alert.get('module') or '?')
        target.last_ts = max(target.last_ts, ts)
        target.max_rank = max(target.max_rank, rank)
        target.alerts.append({
            'ts': ts, 'source': alert.get('source'),
            'severity': alert.get('severity'),
            'codes': alert.get('codes') or [],
            'title': alert.get('title'),
        })
        target.pattern = match_pattern(target.cats) or target.pattern

        self._evict(ts)
        return target

    @staticmethod
    def _absorb(dst, src):
        dst.entities |= src.entities
        dst.cats |= src.cats
        dst.sources |= src.sources
        dst.alerts.extend(src.alerts)
        dst.opened_ts = min(dst.opened_ts, src.opened_ts)
        dst.last_ts = max(dst.last_ts, src.last_ts)
        dst.max_rank = max(dst.max_rank, src.max_rank)
        dst.pattern = match_pattern(dst.cats) or dst.pattern or src.pattern

    def _evict(self, now):
        if len(self._incidents) <= self.max_incidents:
            return
        # Drop the oldest-touched incidents first.
        for iid in sorted(self._incidents,
                          key=lambda i: self._incidents[i].last_ts)[:-self.max_incidents]:
            self._incidents.pop(iid, None)

    def incidents(self, min_severity=None, active_within=None, now=None):
        now = now if now is not None else time.time()
        floor = SEV_RANK.get(min_severity, 0) if min_severity else 0
        out = []
        for inc in self._incidents.values():
            if SEV_RANK.get(inc.severity(), 0) < floor:
                continue
            if active_within is not None and (now - inc.last_ts) > active_within:
                continue
            out.append(inc.to_dict())
        out.sort(key=lambda d: (SEV_RANK.get(d['severity'], 0), d['confidence'],
                                d['last_ts']), reverse=True)
        return out

    def summary(self, now=None):
        incs = self.incidents(now=now)
        by_sev = collections.Counter(i['severity'] for i in incs)
        named = [i for i in incs if i['pattern']]
        return {
            'total': len(incs),
            'by_severity': {s: by_sev.get(s, 0) for s in SEV_ORDER},
            'named': len(named),
            'worst': (incs[0]['severity'] if incs else None),
            'top': incs[0] if incs else None,
        }


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def _alert(source, codes, ts, severity='high', src=None, target=None,
           title=None, **raw):
    a = {'source': source, 'module': source, 'codes': list(codes), 'ts': ts,
         'severity': severity, 'src': src, 'target': target,
         'title': title or ','.join(codes), 'raw': dict(raw)}
    return a


def _self_test():
    checks = []

    def ck(name, cond):
        checks.append((name, bool(cond)))

    # categorization
    ck('deauth -> wifi_dos', 'wifi_dos' in categorize(_alert('wifiwatch', ['deauth_flood'], 1)))
    ck('pmkid -> wifi_handshake',
       'wifi_handshake' in categorize(_alert('wifiwatch', ['pmkid_harvest'], 1)))
    ck('rogue RA -> rogue_gateway',
       'rogue_gateway' in categorize(_alert('ndpwatch', ['NDP-006'], 1)))
    ck('cert name-mismatch -> tls_intercept',
       'tls_intercept' in categorize(_alert('certwatch', ['NAME_MISMATCH'], 1)))
    ck('arp binding_flap -> l2_spoof',
       'l2_spoof' in categorize(_alert('arp_guard', ['binding_flap'], 1)))
    ck('dns verdict text -> dns_hijack',
       'dns_hijack' in categorize(_alert('netintegrity', [], 1, title='DNS hijacked')))

    # entity extraction + skip lists
    e = extract_entities(_alert('arp_guard', ['binding_flap'], 1, src='10.0.0.9'))
    ck('extract ipv4 entity', ('ip', '10.0.0.9') in e)
    ck('broadcast MAC not an entity',
       not extract_entities(_alert('x', [], 1, src='ff:ff:ff:ff:ff:ff')))
    ck('unspecified IP not an entity',
       not extract_entities(_alert('x', ['NDP-001'], 1, src='::')))

    # 1) evil-twin handshake capture chain (3 wifi signals, shared BSSID) -----
    eng = IncidentEngine()
    bssid = 'aa:bb:cc:00:00:01'
    eng.ingest(_alert('wifiwatch', ['pnl_leak'], 100, station='de:ad:00:00:00:09',
                      bssid=bssid, title='PNL leak'))
    eng.ingest(_alert('wifiwatch', ['evil_twin'], 101, bssid=bssid, ssid='HomeNet'))
    eng.ingest(_alert('wifiwatch', ['deauth_flood'], 102, bssid=bssid, severity='critical'))
    inc = eng.ingest(_alert('wifiwatch', ['handshake_harvest'], 103, bssid=bssid,
                            station='de:ad:00:00:00:09', severity='critical'))
    incs = eng.incidents()
    ck('evil-twin chain -> one incident', len(incs) == 1)
    ck('evil-twin chain named', incs[0]['pattern'] == 'evil_twin_handshake_capture')
    ck('evil-twin chain critical', incs[0]['severity'] == 'critical')
    ck('evil-twin chain high confidence', incs[0]['confidence'] >= 60)

    # 2) L2 MITM + TLS interception on a shared victim IP --------------------
    eng = IncidentEngine()
    eng.ingest(_alert('arp_guard', ['binding_flap'], 200, src='192.168.1.1',
                      target='192.168.1.50', severity='critical'))
    inc = eng.ingest(_alert('certwatch', ['NAME_MISMATCH'], 205,
                            server_ip='192.168.1.50', severity='critical',
                            title='name mismatch'))
    incs = eng.incidents()
    ck('L2+TLS -> one incident (shared victim IP)', len(incs) == 1)
    ck('L2+TLS named l2_mitm_tls', incs[0]['pattern'] == 'l2_mitm_tls')
    ck('L2+TLS two sources', len(incs[0]['sources']) == 2)

    # 3) rogue first-hop: rogue DHCP + DNS hijack, shared gateway IP ---------
    eng = IncidentEngine()
    eng.ingest(_alert('netintegrity', [], 300, src='192.168.1.254',
                      title='rogue DHCP server', severity='critical'))
    eng.ingest(_alert('netintegrity', [], 305, src='192.168.1.254',
                      title='DNS hijacked', severity='critical'))
    incs = eng.incidents()
    ck('rogue first-hop -> one incident', len(incs) == 1)
    ck('rogue first-hop named', incs[0]['pattern'] == 'rogue_first_hop')

    # 4) negative: unrelated alerts on different entities stay separate ------
    eng = IncidentEngine()
    eng.ingest(_alert('wifiwatch', ['deauth_flood'], 400, bssid='11:11:11:11:11:11'))
    eng.ingest(_alert('certwatch', ['EXPIRED'], 401, server_ip='8.8.8.8'))
    incs = eng.incidents()
    ck('unrelated alerts -> two incidents', len(incs) == 2)
    ck('lone expired cert not named', all(i['pattern'] is None for i in incs))

    # 5) window expiry: same entity but far apart -> two incidents -----------
    eng = IncidentEngine(window_s=60)
    eng.ingest(_alert('arp_guard', ['binding_flap'], 500, src='10.0.0.9'))
    eng.ingest(_alert('arp_guard', ['binding_flap'], 700, src='10.0.0.9'))  # +200s
    ck('stale alert opens a fresh incident', len(eng.incidents()) == 2)

    # 6) bridging alert fuses two incidents ---------------------------------
    eng = IncidentEngine()
    eng.ingest(_alert('arp_guard', ['binding_flap'], 600, src='10.0.0.9',
                      severity='critical'))
    eng.ingest(_alert('certwatch', ['NAME_MISMATCH'], 601, server_ip='10.0.0.50',
                      severity='critical', title='mismatch'))
    ck('two separate incidents before bridge', len(eng.incidents()) == 2)
    # an alert naming both entities merges them
    eng.ingest(_alert('arp_guard', ['garp_subnet_poison'], 602, src='10.0.0.9',
                      target='10.0.0.50', severity='critical'))
    incs = eng.incidents()
    ck('bridging alert fuses to one incident', len(incs) == 1)
    ck('fused incident is l2_mitm_tls', incs[0]['pattern'] == 'l2_mitm_tls')

    # 7) summary shape ------------------------------------------------------
    s = eng.summary()
    ck('summary total', s['total'] == 1)
    ck('summary names the chain', s['named'] == 1)

    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        if not ok:
            print('  [FAIL] %s' % name)
    print('incident-engine self-test: %d/%d %s'
          % (passed, len(checks), 'OK' if passed == len(checks) else 'FAILED'))
    return 0 if passed == len(checks) else 1


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Ragnar cross-signal correlation engine')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--replay', help='replay a Watchtower JSON-lines file and print incidents')
    ap.add_argument('--window', type=float, default=600.0)
    ap.add_argument('--min-severity', default=None, choices=SEV_ORDER)
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.replay:
        eng = IncidentEngine(window_s=args.window)
        with open(args.replay) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    eng.ingest(json.loads(line))
                except (ValueError, KeyError):
                    continue
        for inc in eng.incidents(min_severity=args.min_severity):
            print('[%s %d%%] %s :: %s :: sources=%s entities=%s' % (
                inc['severity'], inc['confidence'], inc['label'],
                inc['technique'] or '-', ','.join(inc['sources']),
                ';'.join('%s=%s' % (k, ','.join(v)) for k, v in inc['entities'].items())))
        return 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(_main(sys.argv[1:]))
