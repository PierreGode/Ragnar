#!/usr/bin/env python3
"""watchtower.py — unified alert aggregator for Ragnar's standalone watchers.

Ragnar ships a family of deep, continuous passive monitors that each run as their
own daemon and write their own JSON-lines log: arp_guard, ndpwatch, wifiwatch,
certwatch, snmpwatch, isiswatch, igmpwatch (and any future one). They are the
suite's best detectors, but they were invisible — no single pane, no single
notification path. Watchtower is that single pane: it tails every watcher's
JSON-lines output, normalizes the heterogeneous records into one common alert
shape, and exposes a rolling, deduped stream for the web UI and Pushover.

It is *read only* over the log files — it never captures a packet or sends one.
The watchers stay the sensors; Watchtower is the aggregator.

Design notes
------------
* **One key-aware normalizer, not seven adapters.** The watchers disagree on
  everything: severity is ``severity`` (``critical``/``high``/…) or ``status``
  (``CRIT``/``WARN``/``INFO``/``OK``) or ``sev`` (``INFO``/``LOW``/``MED``/
  ``HIGH``); the timestamp is epoch-float or ISO-8601; the finding id is
  ``codes[]`` or ``code`` or ``detector`` or ``rule`` or ``findings[].code``.
  ``normalize()`` searches a priority-ordered set of keys for each field, so a
  new watcher that emits JSON lines with *any* recognisable severity field shows
  up with zero code changes.
* **tail -f semantics.** On first sight of a file we skip to its end (``tail_only``)
  so a restart does not re-ingest — and re-page — the whole backlog. Rotation and
  truncation are detected by inode + size and re-read from the top.
* **Records that aren't alerts are dropped.** An ``OK``/``clean`` status
  normalizes to no severity and is skipped, so certwatch inventory noise never
  reaches the pane.

Self-test (no root, no daemons, no wire): ``python3 watchtower.py --self-test``.
"""

import collections
import glob
import json
import os
import sys
import time

MODULE = 'watchtower'

# Canonical severity ladder, highest first. Everything a watcher emits is mapped
# onto one of these; anything that maps to None is not an alert (OK/clean).
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

# Every severity token any watcher (or a plausible future one) emits, lowercased,
# mapped onto the canonical ladder. None means "not an alert" — skip the record.
_SEV_MAP = {
    'critical': 'critical', 'crit': 'critical', 'emergency': 'critical',
    'emerg': 'critical', 'fatal': 'critical', 'alert': 'critical',
    'high': 'high', 'error': 'high', 'err': 'high', 'severe': 'high',
    'medium': 'medium', 'med': 'medium', 'moderate': 'medium',
    'warning': 'medium', 'warn': 'medium',
    'low': 'low', 'minor': 'low', 'notice': 'low',
    'info': 'info', 'informational': 'info', 'inventory': 'info',
    'debug': 'info',
    'ok': None, 'clean': None, 'none': None, 'pass': None, 'good': None,
    'normal': None,
}

# Known watchers and where they log by default. `paths` is tried in order; the
# first that exists is tailed. Anything dropped as `<name>.jsonl` into a watched
# directory (DEFAULT_DIRS) is picked up automatically without an entry here.
DEFAULT_SOURCES = {
    'arp_guard': {'label': 'ARP Guard',
                  'paths': ['/var/log/ragnar/arp_guard.jsonl',
                            '/var/log/arp_guard/alerts.jsonl']},
    'ndpwatch':  {'label': 'NDP Watch (IPv6)',
                  'paths': ['/var/log/ragnar/ndpwatch.jsonl',
                            '/var/log/ndpwatch/alerts.jsonl']},
    'wifiwatch': {'label': 'Wi-Fi Watch',
                  'paths': ['/var/log/ragnar/wifiwatch.jsonl',
                            '/var/lib/ragnar/wifiwatch/events.jsonl',
                            '/var/log/wifiwatch/alerts.jsonl']},
    'certwatch': {'label': 'Cert Watch',
                  'paths': ['/var/log/ragnar/certwatch.jsonl',
                            '/var/log/certwatch/alerts.jsonl']},
    'snmpwatch': {'label': 'SNMP Watch',
                  'paths': ['/var/log/ragnar/snmpwatch.jsonl',
                            '/var/log/snmpwatch/alerts.jsonl']},
    'isiswatch': {'label': 'IS-IS Watch',
                  'paths': ['/var/log/ragnar/isiswatch.jsonl',
                            '/var/log/isiswatch/alerts.jsonl']},
    'igmpwatch': {'label': 'IGMP Watch',
                  'paths': ['/var/log/ragnar/igmpwatch.jsonl',
                            '/var/log/igmpwatch/alerts.jsonl']},
}

# Directories globbed for `*.jsonl`; the basename becomes the source name. This is
# the "drop a file in and it appears" path and the recommended common log dir.
DEFAULT_DIRS = ('/var/log/ragnar',)


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------

def canon_severity(value):
    """Map any watcher's severity/status token onto the canonical ladder.
    Returns None for OK/clean (i.e. "not an alert"), or 'medium' for a present
    but unrecognised token — an unknown severity is worth surfacing, not dropping."""
    if value is None:
        return None
    token = str(value).strip().lower()
    if not token:
        return None
    if token in _SEV_MAP:
        return _SEV_MAP[token]
    return 'medium'


def _first(raw, *keys):
    for k in keys:
        v = raw.get(k)
        if v not in (None, '', [], {}):
            return v
    return None


def _to_epoch(value):
    """Coerce a ts field (epoch number or ISO-8601 string) to epoch seconds."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        s = value.strip().replace('Z', '+00:00')
        try:
            from datetime import datetime
            return datetime.fromisoformat(s).timestamp()
        except (ValueError, OverflowError):
            return None
    return None


def _codes(raw):
    """Pull the finding id(s) out of whatever field this watcher used."""
    v = raw.get('codes')
    if isinstance(v, list):
        return [str(x) for x in v if x not in (None, '')]
    findings = raw.get('findings')
    if isinstance(findings, list):
        cs = [str(f.get('code')) for f in findings
              if isinstance(f, dict) and f.get('code')]
        if cs:
            return cs
    for k in ('code', 'detector', 'rule', 'signal'):
        val = raw.get(k)
        if val not in (None, ''):
            return [str(val)]
    return []


def normalize(raw, source):
    """Turn one watcher record (a dict) into the common alert shape, or None if
    it isn't an alert (OK/clean, or unparseable)."""
    if not isinstance(raw, dict):
        return None
    severity = canon_severity(_first(raw, 'severity', 'sev', 'status',
                                     'level', 'priority'))
    if severity is None:
        return None
    ts = _to_epoch(_first(raw, 'ts', 'timestamp', 'time'))
    if ts is None:
        ts = time.time()
    codes = _codes(raw)
    title = _first(raw, 'summary', 'reason', 'detail', 'message', 'msg',
                   'signal', 'sni', 'subject_cn')
    if not title:
        title = ', '.join(codes) if codes else source
    src = _first(raw, 'src', 'sender_ip', 'server_ip', 'saddr', 'source_ip',
                 'identity', 'system')
    target = _first(raw, 'target', 'dst', 'group', 'victim', 'server_port')
    module = raw.get('module') or source
    # Dedup key: same source + finding + endpoints = the same standing condition.
    key = '|'.join([source, ','.join(codes) or str(title),
                    str(src or ''), str(target or '')])
    return {
        'ts': float(ts),
        'source': source,
        'module': module,
        'severity': severity,
        'rank': SEV_RANK[severity],
        'title': str(title),
        'codes': codes,
        'src': (str(src) if src is not None else None),
        'target': (str(target) if target is not None else None),
        'key': key,
        'raw': raw,
    }


# --------------------------------------------------------------------------
# Aggregator
# --------------------------------------------------------------------------

class Watchtower:
    """Tails a set of watcher JSON-lines files and keeps a bounded, normalized,
    newest-last ring of alerts. `poll()` returns only the alerts new since the
    last call, so the caller can page/persist just the delta."""

    def __init__(self, sources=None, dirs=None, max_alerts=1000, tail_only=True):
        self.sources = sources if sources is not None else DEFAULT_SOURCES
        self.dirs = list(dirs) if dirs is not None else list(DEFAULT_DIRS)
        self.max_alerts = int(max_alerts)
        self.tail_only = bool(tail_only)
        self._pos = {}        # resolved path -> {'inode', 'offset'}
        self._alerts = collections.deque(maxlen=self.max_alerts)

    # -- source/file resolution --------------------------------------------

    def _file_map(self):
        """Resolve {path: (source_name, label)} for every readable log file:
        the first existing `paths` entry per known source, plus every `*.jsonl`
        in the watched dirs."""
        out = {}
        for name, meta in self.sources.items():
            for p in meta.get('paths', []):
                if os.path.exists(p):
                    out[p] = (name, meta.get('label', name))
                    break
        for d in self.dirs:
            try:
                found = glob.glob(os.path.join(d, '*.jsonl'))
            except OSError:
                continue
            for p in sorted(found):
                if p in out:
                    continue
                base = os.path.basename(p)[:-len('.jsonl')]
                meta = self.sources.get(base, {})
                out[p] = (base, meta.get('label', base))
        return out

    # -- reading -----------------------------------------------------------

    def _read_file(self, path, name, label):
        try:
            st = os.stat(path)
        except OSError:
            return []
        pos = self._pos.get(path)
        if pos is None:
            # First sight. Skip to EOF so a restart doesn't replay/​re-page the
            # backlog — unless tail_only is off (tests, or an explicit backfill).
            offset = st.st_size if self.tail_only else 0
            self._pos[path] = {'inode': st.st_ino, 'offset': offset}
            if self.tail_only:
                return []
        elif pos['inode'] != st.st_ino or st.st_size < pos['offset']:
            offset = 0          # rotated or truncated -> re-read from the top
        else:
            offset = pos['offset']

        try:
            with open(path, 'rb') as f:
                f.seek(offset)
                data = f.read()
        except OSError:
            return []
        last_nl = data.rfind(b'\n')
        if last_nl == -1:
            self._pos[path] = {'inode': st.st_ino, 'offset': offset}
            return []           # only a partial line so far; wait for the newline
        consumed = data[:last_nl + 1]
        self._pos[path] = {'inode': st.st_ino, 'offset': offset + len(consumed)}

        out = []
        for line in consumed.split(b'\n'):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line.decode('utf-8', 'replace'))
            except (ValueError, UnicodeDecodeError):
                continue
            a = normalize(raw, name)
            if a is not None:
                a['label'] = label
                out.append(a)
        return out

    def poll(self):
        """Read every watched file forward from its last offset. Returns the new
        alerts (oldest first); also appends them to the internal ring."""
        new = []
        for path, (name, label) in self._file_map().items():
            new.extend(self._read_file(path, name, label))
        new.sort(key=lambda a: a['ts'])
        for a in new:
            self._alerts.append(a)
        return new

    # -- views -------------------------------------------------------------

    def recent(self, limit=100, min_severity=None):
        """Newest-first alerts, optionally floored at a canonical severity."""
        floor = SEV_RANK.get(min_severity, 0) if min_severity else 0
        items = [a for a in self._alerts if a['rank'] >= floor]
        items = list(reversed(items))
        return items[:limit] if limit else items

    def load(self, alerts):
        """Seed the display ring from persisted alerts (does not affect offsets)."""
        for a in alerts:
            if isinstance(a, dict) and 'severity' in a and 'ts' in a:
                a.setdefault('rank', SEV_RANK.get(a['severity'], 0))
                self._alerts.append(a)

    def summary(self):
        by_sev = collections.Counter(a['severity'] for a in self._alerts)
        by_src = collections.Counter(a['source'] for a in self._alerts)
        fmap = self._file_map()
        present = {name for name, _ in fmap.values()}
        sources = []
        known = set(self.sources) | present
        for name in sorted(known):
            label = self.sources.get(name, {}).get('label', name)
            path = next((p for p, (n, _) in fmap.items() if n == name), None)
            sources.append({'name': name, 'label': label,
                            'present': name in present, 'path': path,
                            'alerts': by_src.get(name, 0)})
        newest = max((a['ts'] for a in self._alerts), default=None)
        worst = max((a['rank'] for a in self._alerts), default=-1)
        return {
            'total': len(self._alerts),
            'by_severity': {s: by_sev.get(s, 0) for s in SEVERITIES},
            'by_source': dict(by_src),
            'worst': (SEVERITIES[4 - worst] if worst >= 0 else None),
            'newest_ts': newest,
            'sources': sources,
        }


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def _self_test():
    import tempfile
    checks = []

    def ck(name, cond):
        checks.append((name, bool(cond)))

    # 1) normalizer across every watcher schema ----------------------------
    ndp = normalize({'ts': 1000.0, 'module': 'ndpwatch', 'severity': 'critical',
                     'type': 'NA', 'src': 'fe80::66', 'target': '2001:db8::5',
                     'codes': ['NDP-001', 'NDP-003'], 'summary': 'cache poison'},
                    'ndpwatch')
    ck('ndp severity', ndp['severity'] == 'critical')
    ck('ndp codes', ndp['codes'] == ['NDP-001', 'NDP-003'])
    ck('ndp epoch ts', ndp['ts'] == 1000.0)

    arp = normalize({'ts': 1001, 'severity': 'high', 'sender_ip': '10.0.0.9',
                     'codes': ['binding_flap'], 'summary': 'IP flapping MACs'},
                    'arp_guard')
    ck('arp src', arp['src'] == '10.0.0.9')

    wifi = normalize({'ts': '2026-07-17T10:00:00+00:00', 'module': 'wifiwatch',
                      'detector': 'deauth_flood', 'severity': 'critical',
                      'bssid': 'aa:bb'}, 'wifiwatch')
    ck('wifi iso ts', wifi is not None and wifi['ts'] > 1_700_000_000)
    ck('wifi detector->codes', wifi['codes'] == ['deauth_flood'])

    cert_crit = normalize({'status': 'CRIT', 'type': 'cert', 'module': 'certwatch',
                           'sni': 'idrac.lan', 'server_ip': '10.0.0.5',
                           'findings': [{'code': 'EXPIRED'}]}, 'certwatch')
    ck('cert status->critical', cert_crit['severity'] == 'critical')
    ck('cert findings->codes', cert_crit['codes'] == ['EXPIRED'])
    ck('cert title falls back to sni', cert_crit['title'] == 'idrac.lan')

    cert_ok = normalize({'status': 'OK', 'type': 'inventory', 'sni': 'x'},
                        'certwatch')
    ck('cert OK is not an alert', cert_ok is None)

    igmp = normalize({'ts': 1002, 'module': 'igmpwatch', 'rule': 'querier_spoof',
                      'sev': 'HIGH', 'signal': 'rogue querier', 'identity': '10.0.0.2'},
                     'igmpwatch')
    ck('igmp sev HIGH->high', igmp['severity'] == 'high')
    ck('igmp rule->codes', igmp['codes'] == ['querier_spoof'])
    ck('igmp signal as title', igmp['title'] == 'rogue querier')

    snmp = normalize({'module': 'snmpwatch', 'severity': 'CRITICAL',
                      'src': '10.0.0.7', 'dst': '10.0.0.1', 'reason': 'SNMP write'},
                     'snmpwatch')
    ck('snmp CRITICAL->critical', snmp['severity'] == 'critical')
    ck('snmp reason as title', snmp['title'] == 'SNMP write')

    ck('unknown severity surfaces as medium',
       canon_severity('weird') == 'medium')
    ck('empty severity is None', canon_severity('') is None)

    # dedup key stability
    a1 = normalize({'severity': 'high', 'codes': ['X'], 'src': '1.1.1.1'}, 's')
    a2 = normalize({'severity': 'high', 'codes': ['X'], 'src': '1.1.1.1',
                    'ts': 999}, 's')
    ck('dedup key stable across ts', a1['key'] == a2['key'])

    # 2) tailer over real files -------------------------------------------
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'ndpwatch.jsonl')
        with open(p, 'w') as f:
            f.write(json.dumps({'ts': 1, 'severity': 'high', 'codes': ['A'],
                                'summary': 'one'}) + '\n')
            f.write(json.dumps({'ts': 2, 'status': 'OK', 'summary': 'skip'}) + '\n')
        wt = Watchtower(sources={}, dirs=[d], tail_only=False)
        first = wt.poll()
        ck('tailer reads real lines', len(first) == 1)
        ck('tailer drops OK record', all(a['title'] != 'skip' for a in first))
        ck('tailer names source from filename', first[0]['source'] == 'ndpwatch')

        # incremental: only new lines on the next poll
        with open(p, 'a') as f:
            f.write(json.dumps({'ts': 3, 'severity': 'critical',
                                'codes': ['B'], 'summary': 'two'}) + '\n')
        second = wt.poll()
        ck('tailer incremental delta', len(second) == 1 and second[0]['codes'] == ['B'])

        # partial line held until its newline arrives
        with open(p, 'a') as f:
            f.write('{"ts": 4, "severity": "low", "codes": ["C"]')  # no newline
        ck('tailer holds partial line', wt.poll() == [])
        with open(p, 'a') as f:
            f.write(', "summary": "three"}\n')
        ck('tailer completes partial line', len(wt.poll()) == 1)

        # truncation/rotation -> re-read from the top
        with open(p, 'w') as f:
            f.write(json.dumps({'ts': 5, 'severity': 'high', 'codes': ['D'],
                                'summary': 'rot'}) + '\n')
        ck('tailer handles truncation', len(wt.poll()) == 1)

        # tail_only skips the existing backlog on first sight
        wt2 = Watchtower(sources={}, dirs=[d], tail_only=True)
        ck('tail_only skips backlog', wt2.poll() == [])

        summ = wt.summary()
        ck('summary counts alerts', summ['total'] >= 4)
        ck('summary worst is critical', summ['worst'] == 'critical')
        ck('summary lists source present', any(
            s['name'] == 'ndpwatch' and s['present'] for s in summ['sources']))

        rec = wt.recent(limit=2, min_severity='high')
        ck('recent floors by severity', all(a['rank'] >= SEV_RANK['high'] for a in rec))
        ck('recent is newest-first', len(rec) <= 2)

    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        if not ok:
            print('  [FAIL] %s' % name)
    print('watchtower self-test: %d/%d %s'
          % (passed, len(checks), 'OK' if passed == len(checks) else 'FAILED'))
    return 0 if passed == len(checks) else 1


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Ragnar unified watcher-alert aggregator')
    ap.add_argument('--self-test', action='store_true', help='run offline self-test')
    ap.add_argument('--dir', action='append', default=None,
                    help='directory to glob for <name>.jsonl (repeatable)')
    ap.add_argument('--once', action='store_true',
                    help='poll once (from the start) and print current alerts')
    ap.add_argument('--follow', action='store_true', help='poll forever')
    ap.add_argument('--min-severity', default=None, choices=SEVERITIES)
    ap.add_argument('--interval', type=float, default=5.0)
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    wt = Watchtower(dirs=args.dir, tail_only=not args.once)
    if args.once:
        wt.poll()
        for a in wt.recent(min_severity=args.min_severity):
            print('[%s] %-12s %s :: %s' % (a['severity'], a['source'],
                                           ','.join(a['codes']) or '-', a['title']))
        print('--- %s' % json.dumps(wt.summary()['by_severity']))
        return 0
    if args.follow:
        try:
            while True:
                for a in wt.poll():
                    if args.min_severity and a['rank'] < SEV_RANK[args.min_severity]:
                        continue
                    print('[%s] %-12s %s :: %s' % (a['severity'], a['source'],
                          ','.join(a['codes']) or '-', a['title']))
                time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(_main(sys.argv[1:]))
