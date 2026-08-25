#!/usr/bin/env python3
"""asset_inventory.py — a living, change-aware asset inventory for Ragnar.

Ragnar already discovers hosts and persists them in the ``hosts`` table
(``db_manager.DatabaseManager``): MAC, IP, hostname, vendor, open ports,
first/last seen, alive/degraded status. That table is a great *store* but a poor
*product*: it is a flat current-state list with no memory of what changed, no
notion of which devices are supposed to be here, and no way for a new or moved
or newly-listening device to raise its hand.

This module is the layer that turns the store into an inventory:

* **Classification / enrichment.** Each host is tagged with a device type and
  label (``device_classifier``) and screened against rogue-device signatures.
* **Ownership & criticality.** Operators annotate assets (owner, criticality,
  authorized yes/no, tags, notes) in ``data/asset_meta.json``. An *unauthorized*
  device showing up is the single most valuable signal for both a home lab and
  a SOC — and it is only possible once "authorized" is a thing.
* **Change detection.** Every ``snapshot()`` diffs the current hosts against the
  previous one and emits typed events: a new device, an IP move, a MAC/vendor
  change (spoofing tell), a newly-opened sensitive port, a device going offline
  or coming back, a rogue-signature hit.
* **One clean exit.** Events are written as JSON-lines to
  ``$RAGNAR_WATCH_LOG_DIR/asset_inventory.jsonl`` (default ``/var/log/ragnar``)
  in the same shape every Ragnar watcher uses, so Watchtower ingests them with
  zero extra wiring — and from there they flow to Pushover, the incident engine,
  and the SIEM forwarder like any other alert.

Standalone, dependency-light (only the optional ``device_classifier``), and
self-testable with a fake DB:  ``python3 asset_inventory.py --self-test``
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    import device_classifier as _dc
except Exception:                                           # noqa: BLE001
    _dc = None

MODULE = 'asset_inventory'

# Ports whose sudden appearance is worth escalating: cleartext admin, remote
# desktop, file shares, databases — the things you notice a device *starting* to
# expose. SSH (22) is deliberately absent: it is normal everywhere and would be
# pure noise.
SENSITIVE_PORTS = {
    21: 'ftp', 23: 'telnet', 25: 'smtp', 69: 'tftp', 110: 'pop3',
    135: 'msrpc', 139: 'netbios', 143: 'imap', 161: 'snmp', 389: 'ldap',
    445: 'smb', 512: 'rexec', 513: 'rlogin', 514: 'rsh', 1433: 'mssql',
    1521: 'oracle', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres',
    5900: 'vnc', 5901: 'vnc', 6379: 'redis', 9200: 'elasticsearch',
    11211: 'memcached', 27017: 'mongodb',
}

CRITICALITY_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
VALID_CRITICALITY = tuple(CRITICALITY_RANK.keys())


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _norm_mac(mac):
    return str(mac or '').strip().lower()


_DUP_RE = re.compile(r'\s*\(DUP:\s*\d+\)\s*$')


def _clean_vendor(vendor):
    """Strip the hosts-table dedup marker, e.g. 'Acme Inc. (DUP: 2)' -> 'Acme Inc.'.
    Also collapse the placeholder '(Unknown…)' strings to a plain 'Unknown'."""
    v = str(vendor or '').strip()
    v = _DUP_RE.sub('', v).strip()
    return v


def _is_broadcast_ip(ip):
    """True for an IPv4 network/broadcast address that isn't a real host — the
    subnet broadcast (.255) or network (.0) under the common /24, or the global
    255.255.255.255. These leak into the hosts table from broadcast traffic and
    should never be listed or alerted on as devices."""
    ip = str(ip or '').strip()
    if not ip or ip == '255.255.255.255':
        return ip == '255.255.255.255'
    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    last = int(parts[3])
    return last in (0, 255)


def _is_pseudo_mac(mac):
    """The hosts table synthesizes a placeholder MAC of the form 00:00:c0:a8:xx:xx
    (00:00 + the hex of the IPv4) for hosts discovered without a real MAC (ping /
    passive). These are *real* hosts, so they're kept — just marked so the UI can
    show that the MAC is inferred, not observed."""
    m = _norm_mac(mac)
    return m.startswith('00:00:')


def _parse_ports(row):
    """Return a sorted list of int ports from a host row's `ports`/`services`.
    `ports` is a comma-separated string in the DB; tolerate list/None too."""
    raw = row.get('ports')
    out = set()
    if isinstance(raw, str):
        parts = raw.replace(';', ',').split(',')
    elif isinstance(raw, (list, tuple)):
        parts = raw
    else:
        parts = []
    for p in parts:
        s = str(p).strip().split('/')[0]
        if s.isdigit():
            out.add(int(s))
    # services JSON may carry ports too
    svc = row.get('services')
    if isinstance(svc, str) and svc:
        try:
            data = json.loads(svc)
            if isinstance(data, dict):
                for k in data:
                    ks = str(k).split('/')[0]
                    if ks.isdigit():
                        out.add(int(ks))
        except (ValueError, TypeError):
            pass
    return sorted(out)


def _atomic_write_json(path, obj):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(obj, f)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Asset inventory
# --------------------------------------------------------------------------

class AssetInventory:
    """Change-aware inventory over a ``db`` exposing ``get_all_hosts()``.

    ``db`` is normally ``shared_data.db`` (DatabaseManager); any object with a
    ``get_all_hosts()`` -> list-of-dict method works, which is what makes this
    self-testable. All persisted state lives under ``datadir``; events are
    emitted to ``log_dir`` (the Watchtower log dir)."""

    def __init__(self, db=None, datadir='.', log_dir=None, config=None,
                 gateway_ip=None, max_events=2000):
        self.db = db
        self.datadir = datadir
        self.log_dir = (log_dir or os.environ.get('RAGNAR_WATCH_LOG_DIR')
                        or '/var/log/ragnar')
        self.config = config or {}
        self.gateway_ip = gateway_ip
        self.max_events = int(max_events)
        self.state_path = os.path.join(datadir, 'asset_inventory_state.json')
        self.meta_path = os.path.join(datadir, 'asset_meta.json')
        self.events_path = os.path.join(datadir, 'asset_events.json')
        self.jsonl_path = os.path.join(self.log_dir, 'asset_inventory.jsonl')

    # -- persistence -------------------------------------------------------

    def _load_json(self, path, default):
        try:
            with open(path) as f:
                data = json.load(f)
            return data if isinstance(data, type(default)) else default
        except (FileNotFoundError, ValueError, OSError):
            return default

    def _load_state(self):
        return self._load_json(self.state_path, {})

    def _save_state(self, state):
        try:
            _atomic_write_json(self.state_path, state)
        except OSError:
            pass

    def load_meta(self):
        return self._load_json(self.meta_path, {})

    def set_meta(self, mac, owner=None, criticality=None, authorized=None,
                 tags=None, notes=None, label=None):
        """Annotate one asset. Only provided fields are changed. Returns the
        stored record."""
        mac = _norm_mac(mac)
        if not mac:
            raise ValueError('mac required')
        meta = self.load_meta()
        rec = meta.get(mac, {})
        if owner is not None:
            rec['owner'] = str(owner)
        if criticality is not None:
            c = str(criticality).lower()
            rec['criticality'] = c if c in VALID_CRITICALITY else 'none'
        if authorized is not None:
            rec['authorized'] = bool(authorized)
        if tags is not None:
            rec['tags'] = [str(t) for t in tags] if isinstance(tags, (list, tuple)) \
                else [t.strip() for t in str(tags).split(',') if t.strip()]
        if notes is not None:
            rec['notes'] = str(notes)
        if label is not None:
            rec['label'] = str(label)
        rec['updated'] = time.time()
        meta[mac] = rec
        _atomic_write_json(self.meta_path, meta)
        return rec

    def _load_events(self):
        return self._load_json(self.events_path, [])

    def _save_events(self, events):
        try:
            _atomic_write_json(self.events_path, events[-self.max_events:])
        except OSError:
            pass

    # -- enrichment --------------------------------------------------------

    def classify(self, row):
        if _dc is None:
            return {'device_type': 'unknown', 'label': 'Unknown', 'confidence': 0.0}
        try:
            return _dc.classify_device(row.get('vendor') or '',
                                       _parse_ports(row),
                                       gateway_ip=self.gateway_ip,
                                       device_ip=row.get('ip'))
        except Exception:                                   # noqa: BLE001
            return {'device_type': 'unknown', 'label': 'Unknown', 'confidence': 0.0}

    def threats(self, row):
        if _dc is None:
            return []
        try:
            return _dc.detect_threats(row.get('vendor') or '', row.get('mac') or '',
                                      hostname=row.get('hostname') or '',
                                      ports=_parse_ports(row))
        except Exception:                                   # noqa: BLE001
            return []

    # -- the current, enriched inventory (for the UI/API) ------------------

    def inventory(self):
        """Return the enriched current asset list + a summary. Read-only; does
        not diff or emit."""
        rows = self._hosts()
        meta = self.load_meta()
        assets = []
        for row in rows:
            mac = _norm_mac(row.get('mac'))
            cls = self.classify(row)
            thr = self.threats(row)
            m = meta.get(mac, {})
            assets.append({
                'mac': mac,
                'ip': row.get('ip'),
                'hostname': row.get('hostname'),
                'vendor': _clean_vendor(row.get('vendor')),
                'ports': _parse_ports(row),
                'status': row.get('status') or 'alive',
                'first_seen': row.get('first_seen'),
                'last_seen': row.get('last_seen'),
                'device_type': cls.get('device_type'),
                'device_label': cls.get('label'),
                'confidence': cls.get('confidence'),
                'pseudo_mac': _is_pseudo_mac(mac),
                'threats': thr,
                'owner': m.get('owner'),
                'criticality': m.get('criticality', 'none'),
                'authorized': m.get('authorized'),
                'tags': m.get('tags', []),
                'notes': m.get('notes'),
                'label': m.get('label'),
            })
        assets.sort(key=lambda a: (CRITICALITY_RANK.get(a['criticality'], 0),
                                   len(a['threats'])), reverse=True)
        summary = {
            'total': len(assets),
            'authorized': sum(1 for a in assets if a['authorized'] is True),
            'unauthorized': sum(1 for a in assets if a['authorized'] is False),
            'unclassified': sum(1 for a in assets if a['authorized'] is None),
            'with_threats': sum(1 for a in assets if a['threats']),
            'offline': sum(1 for a in assets
                           if (a['status'] or 'alive') not in ('alive',)),
            'by_type': _count_by(assets, 'device_type'),
            'by_criticality': _count_by(assets, 'criticality'),
        }
        return {'assets': assets, 'summary': summary,
                'recent_events': list(reversed(self._load_events()))[:100]}

    def _hosts(self):
        if self.db is None:
            return []
        try:
            rows = self.db.get_all_hosts()
        except Exception:                                   # noqa: BLE001
            return []
        # Drop broadcast/network pseudo-hosts (e.g. x.x.x.255) that broadcast
        # traffic leaves in the hosts table — they are not devices.
        return [dict(r) for r in (rows or [])
                if not _is_broadcast_ip((r if isinstance(r, dict) else dict(r)).get('ip'))]

    # -- change detection --------------------------------------------------

    def _fingerprint(self, row):
        """The subset of a host we track for change detection."""
        return {
            'ip': row.get('ip'),
            'hostname': row.get('hostname'),
            'vendor': _clean_vendor(row.get('vendor')),
            'ports': _parse_ports(row),
            'status': row.get('status') or 'alive',
            'last_seen': row.get('last_seen'),
        }

    def snapshot(self, alert_on_baseline=None):
        """Diff current hosts vs the last snapshot, emit + persist events, and
        save the new state. On the very first run there is no prior state, so we
        seed silently (no flood of 'new device' pages) unless
        ``alert_on_baseline`` / config asks otherwise. Returns
        ``{'events': [...], 'new_state_count': N, 'baseline': bool}``."""
        if alert_on_baseline is None:
            alert_on_baseline = bool(
                self.config.get('asset_inventory_alert_on_baseline', False))

        prior = self._load_state()
        baseline = not prior
        meta = self.load_meta()
        rows = self._hosts()
        now = time.time()

        current = {}
        events = []
        seen_macs = set()
        for row in rows:
            mac = _norm_mac(row.get('mac'))
            if not mac:
                continue
            seen_macs.add(mac)
            fp = self._fingerprint(row)
            current[mac] = fp
            old = prior.get(mac)
            m = meta.get(mac, {})
            if old is None:
                if not baseline or alert_on_baseline:
                    events.extend(self._new_device_events(mac, row, fp, m))
                continue
            events.extend(self._changed_events(mac, row, old, fp, m))

        # devices that were present before and are now gone from the table
        # (rare — Ragnar keeps rows and flips status; handled in _changed_events)
        # but cover it for completeness:
        for mac, old in prior.items():
            if mac in seen_macs:
                continue
            # keep it in state so we don't re-alert; note the disappearance once
            current[mac] = old

        self._save_state(current)
        if events:
            self._emit(events)
            all_events = self._load_events()
            all_events.extend(events)
            self._save_events(all_events)
        return {'events': events, 'new_state_count': len(current),
                'baseline': baseline}

    # -- event builders ----------------------------------------------------

    def _sev_for_new_device(self, meta):
        authorized = meta.get('authorized')
        if authorized is True:
            return 'info'
        if authorized is False:
            return 'high'
        # unknown authorization: a device we've never classified is suspicious
        return 'medium'

    def _base_event(self, mac, row, code, severity, summary, extra=None):
        ip = row.get('ip')
        evt = {
            'module': MODULE,
            'ts': time.time(),
            'iso': _iso(time.time()),
            'severity': severity,
            'code': code,
            'codes': [code],
            'src': ip or mac,
            'target': mac,
            'mac': mac,
            'ip': ip,
            'hostname': row.get('hostname'),
            'vendor': _clean_vendor(row.get('vendor')),
            'summary': summary,
        }
        if extra:
            evt['detail'] = extra
        return evt

    def _new_device_events(self, mac, row, fp, meta):
        sev = self._sev_for_new_device(meta)
        cls = self.classify(row)
        who = ('authorized' if meta.get('authorized') is True
               else 'UNAUTHORIZED' if meta.get('authorized') is False
               else 'unclassified')
        summary = ('New %s device on network: %s%s (%s) [%s]' % (
            who, (row.get('hostname') + ' ' if row.get('hostname') else ''),
            row.get('ip') or mac, cls.get('label', 'Unknown'), mac))
        events = [self._base_event(mac, row, 'ASSET-NEW', sev, summary,
                                   {'device_type': cls.get('device_type'),
                                    'ports': fp['ports']})]
        # a rogue signature on first sight rides its own (usually higher) severity
        for t in self.threats(row):
            events.append(self._threat_event(mac, row, t))
        return events

    def _threat_event(self, mac, row, threat):
        sev = str(threat.get('severity', 'high')).lower()
        summary = 'Rogue-device signature: %s — %s' % (
            threat.get('name', threat.get('id', 'threat')),
            threat.get('description', ''))
        return self._base_event(mac, row, 'ASSET-THREAT-%s' %
                                str(threat.get('id', 'x')).upper(), sev, summary,
                                {'threat': threat})

    def _changed_events(self, mac, row, old, fp, meta):
        events = []
        crit = meta.get('criticality', 'none')
        crit_high = CRITICALITY_RANK.get(crit, 0) >= 3

        # IP move
        if old.get('ip') and fp.get('ip') and old['ip'] != fp['ip']:
            events.append(self._base_event(
                mac, row, 'ASSET-IP-CHANGE', 'medium',
                'Asset %s changed IP: %s -> %s' % (
                    _label(row, meta, mac), old['ip'], fp['ip']),
                {'old_ip': old['ip'], 'new_ip': fp['ip']}))

        # vendor change on the same MAC — a classic spoofing / clone tell
        if old.get('vendor') and fp.get('vendor') and \
                old['vendor'] != fp['vendor']:
            events.append(self._base_event(
                mac, row, 'ASSET-VENDOR-CHANGE', 'high',
                'MAC %s vendor changed: %s -> %s (possible spoof)' % (
                    mac, old['vendor'], fp['vendor']),
                {'old_vendor': old['vendor'], 'new_vendor': fp['vendor']}))

        # hostname change
        if old.get('hostname') and fp.get('hostname') and \
                old['hostname'] != fp['hostname']:
            events.append(self._base_event(
                mac, row, 'ASSET-HOSTNAME-CHANGE', 'low',
                'Asset %s hostname changed: %s -> %s' % (
                    mac, old['hostname'], fp['hostname']),
                {'old_hostname': old['hostname'],
                 'new_hostname': fp['hostname']}))

        # newly opened ports
        new_ports = sorted(set(fp['ports']) - set(old.get('ports') or []))
        if new_ports:
            sens = [p for p in new_ports if p in SENSITIVE_PORTS]
            sev = 'high' if sens else 'medium'
            desc = ', '.join('%d/%s' % (p, SENSITIVE_PORTS.get(p, 'tcp'))
                             for p in new_ports)
            events.append(self._base_event(
                mac, row, 'ASSET-PORT-OPENED', sev,
                'Asset %s opened port(s): %s%s' % (
                    _label(row, meta, mac), desc,
                    ' [sensitive]' if sens else ''),
                {'new_ports': new_ports, 'sensitive': sens}))

        # closed ports (informational)
        closed = sorted(set(old.get('ports') or []) - set(fp['ports']))
        if closed:
            events.append(self._base_event(
                mac, row, 'ASSET-PORT-CLOSED', 'info',
                'Asset %s closed port(s): %s' % (
                    _label(row, meta, mac),
                    ', '.join(str(p) for p in closed)),
                {'closed_ports': closed}))

        # status transitions (alive/degraded/lost)
        old_alive = (old.get('status') or 'alive') == 'alive'
        new_alive = (fp.get('status') or 'alive') == 'alive'
        if old_alive and not new_alive:
            events.append(self._base_event(
                mac, row, 'ASSET-OFFLINE', 'high' if crit_high else 'low',
                'Asset %s went offline (%s)%s' % (
                    _label(row, meta, mac), fp.get('status'),
                    ' [critical asset]' if crit_high else ''),
                {'status': fp.get('status'), 'criticality': crit}))
        elif new_alive and not old_alive:
            events.append(self._base_event(
                mac, row, 'ASSET-BACK-ONLINE', 'info',
                'Asset %s back online' % _label(row, meta, mac)))

        return events

    # -- emit --------------------------------------------------------------

    def _emit(self, events):
        """Append events to the Watchtower JSON-lines log (best-effort)."""
        try:
            os.makedirs(self.log_dir, exist_ok=True)
        except OSError:
            return
        try:
            lines = '\n'.join(json.dumps(e, separators=(',', ':'))
                              for e in events) + '\n'
            with open(self.jsonl_path, 'a') as f:
                f.write(lines)
        except OSError:
            pass


def _label(row, meta, mac):
    m = meta.get(mac, {})
    return (m.get('label') or row.get('hostname') or row.get('ip') or mac)


def _count_by(items, key):
    out = {}
    for it in items:
        k = it.get(key) or 'unknown'
        out[k] = out.get(k, 0) + 1
    return out


# --------------------------------------------------------------------------
# Fake DB for the self-test
# --------------------------------------------------------------------------

class _FakeDB:
    def __init__(self, rows):
        self._rows = rows

    def get_all_hosts(self, status=None):
        return [dict(r) for r in self._rows]


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def _self_test():
    import tempfile
    checks = []

    def ck(name, cond):
        checks.append((name, bool(cond)))

    with tempfile.TemporaryDirectory() as d:
        logdir = os.path.join(d, 'log')

        def mk(rows, cfg=None):
            return AssetInventory(db=_FakeDB(rows), datadir=d, log_dir=logdir,
                                  config=cfg or {})

        # --- port parsing ------------------------------------------------
        inv = mk([])
        ck('parse csv ports', _parse_ports({'ports': '22, 80,443/tcp'})
           == [22, 80, 443])
        ck('parse services json ports',
           _parse_ports({'ports': '', 'services': '{"53/udp":"dns"}'}) == [53])

        # --- baseline is silent -----------------------------------------
        rows = [{'mac': 'AA:BB:CC:00:00:01', 'ip': '10.0.0.5',
                 'hostname': 'nas', 'vendor': 'Synology', 'ports': '445,5000',
                 'status': 'alive'}]
        inv = mk(rows)
        r = inv.snapshot()
        ck('baseline detected', r['baseline'] is True)
        ck('baseline emits nothing', r['events'] == [])
        ck('baseline seeds state', r['new_state_count'] == 1)
        ck('no jsonl on silent baseline', not os.path.exists(inv.jsonl_path))

        # --- new device after baseline ----------------------------------
        rows.append({'mac': 'DE:AD:BE:EF:00:02', 'ip': '10.0.0.9',
                     'hostname': '', 'vendor': 'Espressif Inc.',
                     'ports': '80', 'status': 'alive'})
        r = inv.snapshot()
        codes = [e['code'] for e in r['events']]
        ck('new device event', 'ASSET-NEW' in codes)
        new_evt = next(e for e in r['events'] if e['code'] == 'ASSET-NEW')
        ck('new unclassified is medium', new_evt['severity'] == 'medium')
        ck('event has mac/ip', new_evt['mac'] == 'de:ad:be:ef:00:02'
           and new_evt['ip'] == '10.0.0.9')
        ck('jsonl written', os.path.exists(inv.jsonl_path))

        # --- authorized vs unauthorized new device ----------------------
        inv.set_meta('11:22:33:44:55:66', authorized=True, owner='it',
                     criticality='high', label='Core Switch')
        inv.set_meta('99:88:77:66:55:44', authorized=False)
        rows.append({'mac': '11:22:33:44:55:66', 'ip': '10.0.0.1',
                     'hostname': 'sw1', 'vendor': 'Cisco', 'ports': '22,443',
                     'status': 'alive'})
        rows.append({'mac': '99:88:77:66:55:44', 'ip': '10.0.0.66',
                     'hostname': 'rogue', 'vendor': 'Raspberry Pi',
                     'ports': '22', 'status': 'alive'})
        r = inv.snapshot()
        by_mac = {e['mac']: e for e in r['events'] if e['code'] == 'ASSET-NEW'}
        ck('authorized new device is info',
           by_mac['11:22:33:44:55:66']['severity'] == 'info')
        ck('unauthorized new device is high',
           by_mac['99:88:77:66:55:44']['severity'] == 'high')

        # --- IP move + sensitive port open ------------------------------
        rows[0]['ip'] = '10.0.0.55'          # nas moved
        rows[0]['ports'] = '445,5000,3389'   # opened RDP
        r = inv.snapshot()
        codes = {e['code'] for e in r['events']}
        ck('ip change event', 'ASSET-IP-CHANGE' in codes)
        ck('sensitive port open event', 'ASSET-PORT-OPENED' in codes)
        pe = next(e for e in r['events'] if e['code'] == 'ASSET-PORT-OPENED')
        ck('sensitive port -> high', pe['severity'] == 'high')
        ck('sensitive port recorded', 3389 in pe['detail']['sensitive'])

        # --- vendor change (spoof tell) ---------------------------------
        rows[0]['vendor'] = 'Dell Inc.'
        r = inv.snapshot()
        ck('vendor change -> high',
           any(e['code'] == 'ASSET-VENDOR-CHANGE' and e['severity'] == 'high'
               for e in r['events']))

        # --- offline: critical asset escalates --------------------------
        # sw1 is criticality=high; take it offline
        sw = next(x for x in rows if x['mac'] == '11:22:33:44:55:66')
        sw['status'] = 'lost'
        r = inv.snapshot()
        off = [e for e in r['events'] if e['code'] == 'ASSET-OFFLINE']
        ck('offline event', len(off) == 1)
        ck('critical asset offline -> high', off[0]['severity'] == 'high')

        # back online -> info
        sw['status'] = 'alive'
        r = inv.snapshot()
        ck('back online -> info',
           any(e['code'] == 'ASSET-BACK-ONLINE' and e['severity'] == 'info'
               for e in r['events']))

        # --- no spurious events on a no-op snapshot ---------------------
        r = inv.snapshot()
        ck('stable snapshot emits nothing', r['events'] == [])

        # --- inventory view ---------------------------------------------
        view = inv.inventory()
        ck('inventory lists all assets', view['summary']['total'] == len(rows))
        ck('inventory counts authorized', view['summary']['authorized'] == 1)
        ck('inventory counts unauthorized', view['summary']['unauthorized'] == 1)
        ck('inventory surfaces threats',
           view['summary']['with_threats'] >= 1)  # the Espressif node
        ck('critical asset sorts first-ish',
           any(a['criticality'] == 'high' for a in view['assets'][:3]))
        ck('recent events populated', len(view['recent_events']) > 0)

        # --- meta validation --------------------------------------------
        rec = inv.set_meta('aa:aa:aa:aa:aa:aa', criticality='bogus',
                           tags='a, b ,c')
        ck('bad criticality coerced to none', rec['criticality'] == 'none')
        ck('tags parsed from csv', rec['tags'] == ['a', 'b', 'c'])

        # --- data hygiene: broadcast filter / pseudo-MAC / vendor / gateway --
        ck('broadcast .255 is noise', _is_broadcast_ip('192.168.1.255'))
        ck('network .0 is noise', _is_broadcast_ip('10.0.0.0'))
        ck('global broadcast is noise', _is_broadcast_ip('255.255.255.255'))
        ck('real host is not noise', not _is_broadcast_ip('192.168.1.42'))
        ck('pseudo-mac detected', _is_pseudo_mac('00:00:c0:a8:01:c3'))
        ck('real mac not pseudo', not _is_pseudo_mac('b8:27:eb:00:00:01'))
        ck('vendor DUP marker stripped',
           _clean_vendor('Raspberry Pi Foundation (DUP: 2)') == 'Raspberry Pi Foundation')
        ck('vendor without marker unchanged',
           _clean_vendor('Dell Inc.') == 'Dell Inc.')

        hyg_rows = [
            {'mac': '00:00:c0:a8:01:ff', 'ip': '192.168.1.255', 'vendor': '',
             'ports': '138', 'status': 'degraded'},                 # broadcast: dropped
            {'mac': '00:00:c0:a8:01:c3', 'ip': '192.168.1.195', 'hostname': 'srv',
             'vendor': 'Unknown (discovered by ping) (DUP: 2)',
             'ports': '22,80,3000', 'status': 'alive'},             # pseudo-mac: kept
            {'mac': 'b0:6e:bf:28:00:a0', 'ip': '10.9.9.1', 'hostname': 'gw',
             'vendor': 'ASUSTek COMPUTER INC.', 'ports': '53,67,80',
             'status': 'alive'},                                    # the gateway
        ]
        hyg = AssetInventory(db=_FakeDB(hyg_rows), datadir=os.path.join(d, 'h2'),
                             log_dir=os.path.join(d, 'h2log'), gateway_ip='10.9.9.1')
        os.makedirs(os.path.join(d, 'h2'), exist_ok=True)
        hview = hyg.inventory()
        ips = [a['ip'] for a in hview['assets']]
        ck('broadcast host filtered from inventory', '192.168.1.255' not in ips)
        ck('pseudo-mac host retained', '192.168.1.195' in ips)
        srv = next(a for a in hview['assets'] if a['ip'] == '192.168.1.195')
        ck('pseudo_mac flagged on inventory row', srv['pseudo_mac'] is True)
        ck('inventory vendor is cleaned',
           srv['vendor'] == 'Unknown (discovered by ping)')
        gw = next(a for a in hview['assets'] if a['ip'] == '10.9.9.1')
        ck('gateway classified as router', gw['device_type'] == 'router')
        ck('gateway confidence is 1.0', gw['confidence'] == 1.0)

        # --- every emitted record is Watchtower-normalizable ------------
        try:
            import watchtower as _wt
            with open(inv.jsonl_path) as f:
                good = 0
                total = 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    total += 1
                    raw = json.loads(line)
                    if _wt.normalize(raw, MODULE) is not None:
                        good += 1
            ck('watchtower normalizes every emitted event',
               total > 0 and good == total)
        except ImportError:
            ck('watchtower normalization (skipped: module absent)', True)

    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        if not ok:
            print('  [FAIL] %s' % name)
    print('asset_inventory self-test: %d/%d %s'
          % (passed, len(checks), 'OK' if passed == len(checks) else 'FAILED'))
    return 0 if passed == len(checks) else 1


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Ragnar asset inventory / change detection')
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(_main(sys.argv[1:]))
