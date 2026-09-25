"""SNMP poller — per-interface and per-group multicast state read from the
switch's management address, tied back to the IGMP census.

Out-of-band, not segment traffic: it polls the switch over SNMP, sends nothing on
the mirrored segment, transmits no IGMP, and joins no group — so it never becomes
the recon signature the packet detectors watch for. Credentialed network I/O, so
it is disabled by default. Transport shells out to net-snmp (`snmpbulkwalk`) — no
fragile Python SNMP dependency; absent binary / unreachable switch degrade to a
silent no-op. The evaluation logic is pure and injected-snapshot driven. There is
deliberately no packet-transmit path here (the self-test asserts no socket import).
"""

import shutil
import subprocess
import threading
import time

from .alert import Alert
from .state import is_link_local, BENIGN_GROUPS

DEFAULTS = {
    'enable': False,
    'host': None,
    'community': 'public',
    'interval': 30.0,
    'iface_mcast_storm_pps': 1000.0,
    'monitor_ifaces': [],          # ifIndex whitelist ([] = all)
    'census_not_forwarded': False,  # opt-in LOW rule
    'cache_capabilities': True,
    'capability_strikes': 3,
    'capability_ttl': 3600.0,
    'oids': {},                    # overrides
}

OIDS = {
    'ifName': '1.3.6.1.2.1.31.1.1.1.1',
    'ifHCInMulticastPkts': '1.3.6.1.2.1.31.1.1.1.2',
    'ifHCOutMulticastPkts': '1.3.6.1.2.1.31.1.1.1.4',
    'igmpCacheLastReporter': '1.3.6.1.2.1.85.1.2.1.4',
}


def have_snmp():
    return shutil.which('snmpbulkwalk') is not None


def bulkwalk(host, community, oid, timeout=8):
    """Return {index_suffix: value} for an OID subtree, or None on any failure
    (missing binary, unreachable host, error) — never raises."""
    if not have_snmp() or not host:
        return None
    try:
        r = subprocess.run(
            ['snmpbulkwalk', '-v2c', '-c', community, '-On', '-Oq', '-t', '2', '-r', '1',
             host, oid],
            capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    out = {}
    prefix = '.' + oid + '.'
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or ' ' not in line:
            continue
        name, _, val = line.partition(' ')
        if name.startswith(prefix):
            out[name[len(prefix):]] = val.strip()
        elif name.startswith(oid + '.'):
            out[name[len(oid) + 1:]] = val.strip()
    return out


# -- pure evaluation ---------------------------------------------------------
def evaluate_ifaces(prev, cur, dt, cfg=None):
    """Per-interface multicast pps from ifXTable deltas. prev/cur are
    {ifIndex: {'in': n, 'out': n}}. Returns alerts."""
    c = dict(DEFAULTS)
    c.update(cfg or {})
    if not prev or not cur or dt <= 0:
        return []
    monitor = set(str(i) for i in (c.get('monitor_ifaces') or []))
    out = []
    for idx, cv in cur.items():
        if monitor and idx not in monitor:
            continue
        pv = prev.get(idx)
        if not pv:
            continue
        for direction in ('in', 'out'):
            d = cv.get(direction, 0) - pv.get(direction, 0)
            if d < 0:                              # counter reset/wrap
                continue
            pps = d / dt
            if pps >= c['iface_mcast_storm_pps']:
                out.append(Alert('snmp', 'iface_mcast_storm', 'HIGH',
                                 'ifIndex {} {}-multicast {:.0f} pps'.format(idx, direction, pps),
                                 identity='if{}'.format(idx)))
    return out


def evaluate_groups(switch_groups, census_groups, cfg=None, learned=True):
    """Cross-reference the switch group table against the IGMP census.
    switch_groups: iterable of group IPs the switch is forwarding.
    census_groups: set of groups igmpwatch saw a join for."""
    c = dict(DEFAULTS)
    c.update(cfg or {})
    out = []
    sw = set(switch_groups or [])
    census = set(census_groups or [])
    for g in sorted(sw):
        if is_link_local(g) or g in BENIGN_GROUPS:
            continue
        if g not in census:
            out.append(Alert('snmp', 'unsubscribed_forwarding', 'HIGH',
                             'switch forwards {} with no join seen on the monitored port'.format(g),
                             group=g))
    if c.get('census_not_forwarded') and learned and sw:
        for g in sorted(census):
            if is_link_local(g) or g in BENIGN_GROUPS:
                continue
            if g not in sw:
                out.append(Alert('snmp', 'census_not_forwarded', 'LOW',
                                 'join seen for {} but switch group table omits it'.format(g),
                                 group=g))
    return out


class CapabilityCache:
    """Per-switch verdict on whether the group table is answered, with strikes +
    TTL. Backed by a get/set store (storage layer) so verdicts survive restarts.
    Strikes: N consecutive reachable-but-empty walks required before marking
    unsupported. Unreachable never records a verdict. TTL forces re-check."""

    def __init__(self, store=None, strikes=3, ttl=3600.0):
        self.store = store            # {get(host)->rec, set(host, rec)} or None
        self.strikes = int(strikes)
        self.ttl = float(ttl)
        self._mem = {}

    def _get(self, host):
        if self.store:
            return self.store.get(host)
        return self._mem.get(host)

    def _set(self, host, rec):
        if self.store:
            self.store.set(host, rec)
        else:
            self._mem[host] = rec

    def supported(self, host, now=None):
        """Should we walk the group table for this host now?"""
        now = now if now is not None else time.time()
        rec = self._get(host)
        if not rec:
            return True
        if now - rec.get('ts', 0) >= self.ttl:
            return True                            # re-check after TTL
        return rec.get('supported', True)

    def record_walk(self, host, reachable, nonempty, now=None):
        """Update the verdict from one walk. reachable=False records nothing."""
        now = now if now is not None else time.time()
        if not reachable:
            return
        rec = self._get(host) or {'supported': True, 'strikes': 0, 'ts': now}
        if nonempty:
            rec = {'supported': True, 'strikes': 0, 'ts': now}
        else:
            strikes = rec.get('strikes', 0) + 1
            rec = {'supported': strikes < self.strikes, 'strikes': strikes, 'ts': now}
        self._set(host, rec)

    def seed(self, host, supported, now=None):
        """A deliberate --snmp-probe verdict is authoritative (no strikes)."""
        now = now if now is not None else time.time()
        self._set(host, {'supported': bool(supported), 'strikes': 0, 'ts': now})


def probe(host, community, cfg=None):
    """One-shot capability probe: which target OIDs answer + a sample. No root,
    no capture iface. Returns a dict; seeds nothing itself (caller seeds cache)."""
    c = dict(DEFAULTS)
    c.update(cfg or {})
    oids = dict(OIDS)
    oids.update(c.get('oids') or {})
    result = {'host': host, 'have_snmp': have_snmp(), 'oids': {}}
    for name, oid in oids.items():
        table = bulkwalk(host, community, oid)
        result['oids'][name] = {
            'reachable': table is not None,
            'rows': (len(table) if table else 0),
            'sample': (dict(list(table.items())[:2]) if table else {}),
        }
    grp = result['oids'].get('igmpCacheLastReporter', {})
    result['group_table_supported'] = bool(grp.get('reachable') and grp.get('rows'))
    return result


def _group_from_index(idx):
    """igmpCacheEntry index is <group>.<ifIndex>; the group is the first 4 dotted
    octets of the numeric OID suffix."""
    parts = idx.split('.')
    if len(parts) >= 4:
        return '.'.join(parts[:4])
    return None


class SnmpPoller(threading.Thread):
    """Own thread; SNMP round-trip happens outside the pipeline lock, only the
    census snapshot + emit are locked (by the emit callback). Reads ifXTable and
    (capability-permitting) igmpCacheTable, cross-references the census."""

    def __init__(self, state, emit, cfg, storage=None, stop_event=None):
        super().__init__(daemon=True, name='igmpwatch-snmp')
        self.state = state
        self.emit = emit
        self.cfg = dict(DEFAULTS)
        self.cfg.update(cfg or {})
        self.oids = dict(OIDS)
        self.oids.update(self.cfg.get('oids') or {})
        self._stop = stop_event or threading.Event()
        store = storage if (storage and self.cfg.get('cache_capabilities')) else None
        self.cache = CapabilityCache(store, self.cfg['capability_strikes'],
                                     self.cfg['capability_ttl'])
        self._prev_if = None
        self._last = None
        self.walks_skipped = 0

    def _read_ifaces(self):
        host, comm = self.cfg['host'], self.cfg['community']
        inb = bulkwalk(host, comm, self.oids['ifHCInMulticastPkts'])
        outb = bulkwalk(host, comm, self.oids['ifHCOutMulticastPkts'])
        if inb is None and outb is None:
            return None
        cur = {}
        for idx, v in (inb or {}).items():
            cur.setdefault(idx, {})['in'] = _int(v)
        for idx, v in (outb or {}).items():
            cur.setdefault(idx, {})['out'] = _int(v)
        return cur

    def _read_groups(self, now):
        host, comm = self.cfg['host'], self.cfg['community']
        if not self.cache.supported(host, now):
            self.walks_skipped += 1
            return None
        table = bulkwalk(host, comm, self.oids['igmpCacheLastReporter'])
        reachable = table is not None
        nonempty = bool(table)
        self.cache.record_walk(host, reachable, nonempty, now)
        if not table:
            return None
        return {g for g in (_group_from_index(i) for i in table) if g}

    def run(self):
        self._last = time.time()
        while not self._stop.is_set():
            self._stop.wait(self.cfg['interval'])
            if self._stop.is_set():
                break
            now = time.time()
            dt = now - self._last
            cur_if = self._read_ifaces()
            if cur_if is not None:
                for a in evaluate_ifaces(self._prev_if, cur_if, dt, self.cfg):
                    self.emit(a)
                self._prev_if = cur_if
            sw_groups = self._read_groups(now)
            if sw_groups is not None:
                census = self.state.data_groups()
                for a in evaluate_groups(sw_groups, census, self.cfg):
                    self.emit(a)
            self._last = now

    def stop(self):
        self._stop.set()


def _int(v):
    try:
        return int(str(v).split()[-1])
    except (ValueError, IndexError):
        return 0

