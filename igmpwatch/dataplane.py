"""Data-plane rate sampler — reads the NIC's kernel counters from
/sys/class/net/<iface>/statistics, turns successive reads into rates, and
cross-references them against the live IGMP subscriber census.

Still passive: it only reads counters the kernel already keeps. It opens no
network handle and — by design — imports no socket library (the self-test
asserts this). The evaluation logic is pure and injected-snapshot driven so it
tests with no NIC.
"""

import os
import threading
import time

from .alert import Alert

DEFAULTS = {
    'interval': 5.0,
    'mcast_storm_pps': 1000.0,     # received multicast pps
    'mcast_ratio': 0.6,            # multicast fraction of total rx
    'mcast_ratio_floor_pps': 100.0,   # ignore ratio on an idle link
    'flood_no_members_pps': 50.0,     # mcast pps that counts as "on the wire"
}

_FIELDS = ('rx_packets', 'multicast', 'rx_dropped')


def read_counters(iface):
    """Return {rx_packets, multicast, rx_dropped} from sysfs, or None."""
    base = '/sys/class/net/{}/statistics'.format(iface)
    out = {}
    try:
        for f in _FIELDS:
            with open(os.path.join(base, f)) as fh:
                out[f] = int(fh.read().strip())
    except (OSError, ValueError):
        return None
    return out


def evaluate(prev, cur, dt, data_group_count, cfg=None):
    """Pure: turn two counter snapshots into alerts. Returns [] on the priming
    read, a counter reset (iface bounce / 32-bit wrap), or dt <= 0."""
    c = dict(DEFAULTS)
    c.update(cfg or {})
    if not prev or not cur or dt <= 0:
        return []
    # Counter reset / wrap: any field went backwards -> re-prime silently.
    if any(cur.get(f, 0) < prev.get(f, 0) for f in _FIELDS):
        return []
    d_rx = cur['rx_packets'] - prev['rx_packets']
    d_mc = cur['multicast'] - prev['multicast']
    d_drop = cur['rx_dropped'] - prev['rx_dropped']
    mc_pps = d_mc / dt
    rx_pps = d_rx / dt
    out = []
    if mc_pps >= c['mcast_storm_pps']:
        out.append(Alert('dataplane', 'mcast_storm', 'HIGH',
                         'received multicast {:.0f} pps'.format(mc_pps)))
    if mc_pps >= c['flood_no_members_pps'] and data_group_count == 0:
        out.append(Alert('dataplane', 'mcast_flood_no_members', 'HIGH',
                         'multicast {:.0f} pps on the wire with 0 subscribed data groups '
                         '(unregistered flooding / snooping failure / injection)'
                         .format(mc_pps)))
    if rx_pps >= c['mcast_ratio_floor_pps'] and d_rx > 0:
        ratio = d_mc / d_rx
        if ratio >= c['mcast_ratio']:
            out.append(Alert('dataplane', 'mcast_ratio', 'MED',
                             'multicast is {:.0f}% of rx ({:.0f}/{:.0f} pps)'
                             .format(ratio * 100, mc_pps, rx_pps)))
    if d_drop > 0:
        out.append(Alert('dataplane', 'rx_drops', 'MED',
                         'rx_dropped climbing (+{} in {:.0f}s) — ring overrun / storm symptom'
                         .format(d_drop, dt)))
    return out


class DataPlaneSampler(threading.Thread):
    """Own thread; reads counters outside the pipeline lock, locks only the
    census snapshot + emit."""

    def __init__(self, iface, state, emit, cfg=None, stop_event=None):
        super().__init__(daemon=True, name='igmpwatch-dataplane')
        self.iface = iface
        self.state = state
        self.emit = emit
        self.cfg = dict(DEFAULTS)
        self.cfg.update(cfg or {})
        self._stop = stop_event or threading.Event()

    def run(self):
        prev = read_counters(self.iface)
        last = time.time()
        while not self._stop.is_set():
            self._stop.wait(self.cfg['interval'])
            if self._stop.is_set():
                break
            cur = read_counters(self.iface)
            now = time.time()
            dt = now - last
            groups = len(self.state.data_groups())
            for a in evaluate(prev, cur, dt, groups, self.cfg):
                self.emit(a)
            if cur is not None:
                prev, last = cur, now

    def stop(self):
        self._stop.set()
