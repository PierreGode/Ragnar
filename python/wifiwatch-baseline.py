#!/usr/bin/env python3
"""wifiwatch-baseline.py — profile ambient RF and size wifiwatch thresholds.

Runs the same passive capture + raw parser as wifiwatch, but instead of detecting
it measures your neighbourhood — distinct APs, locally-administered-MAC ratio, the
p95/max new-BSSID-per-window and background deauth-per-window, and busiest
channels — then prints a `thresholds` block sized above the measured ambient
(real attacks run 10–100x higher, so the headroom is free).

Capture during a representative, ATTACK-FREE period; you're measuring normal.
Like the detector, it excludes the opening census (warmup) so it measures
steady-state churn, not the boot spike.

  sudo python3 wifiwatch-baseline.py --iface wlan1 --minutes 15
  python3 wifiwatch-baseline.py --replay ambient.pcap
"""

import argparse
import json
import math
import sys
import time
from collections import defaultdict, deque

import wifiwatch as w


def _pct(vals, p):
    if not vals:
        return 0
    s = sorted(vals)
    k = min(len(s) - 1, int(math.ceil(p / 100.0 * len(s)) - 1))
    return s[max(0, k)]


class Profiler:
    def __init__(self, warmup=30.0, beacon_window=8.0, deauth_window=5.0):
        self.warmup = warmup
        self.beacon_window = beacon_window
        self.deauth_window = deauth_window
        self.start = None
        self.census = set()
        self.first_seen = {}
        self.bssids = set()
        self.la_bssids = set()
        self._nb = deque()               # (ts, bssid) post-warmup
        self._da = deque()               # ts of deauth/disassoc
        self.nb_samples = []
        self.da_samples = []
        self.channels = defaultdict(int)
        self.frames = 0

    def handle(self, raw, ts):
        f = w.parse_frame(raw)
        if f is None:
            return
        if self.start is None:
            self.start = ts
        self.frames += 1
        warm = (ts - self.start) < self.warmup
        if f['channel'] is not None:
            self.channels[f['channel']] += 1
        st = f['subtype']
        if st == 8:                      # beacon
            b = f['bssid']
            self.bssids.add(b)
            if w.is_locally_administered(b):
                self.la_bssids.add(b)
            if b not in self.first_seen:
                self.first_seen[b] = ts
                if warm:
                    self.census.add(b)
                else:
                    self._nb.append((ts, b))
            while self._nb and ts - self._nb[0][0] > self.beacon_window:
                self._nb.popleft()
            if not warm:
                self.nb_samples.append(len({x for _t, x in self._nb}))
        elif st in (10, 12):             # deauth/disassoc
            self._da.append(ts)
            while self._da and ts - self._da[0] > self.deauth_window:
                self._da.popleft()
            self.da_samples.append(len(self._da))

    def report(self):
        n_bssid = len(self.bssids)
        la_ratio = (len(self.la_bssids) / n_bssid) if n_bssid else 0.0
        nb_p95, nb_max = _pct(self.nb_samples, 95), (max(self.nb_samples) if self.nb_samples else 0)
        da_p95, da_max = _pct(self.da_samples, 95), (max(self.da_samples) if self.da_samples else 0)
        busiest = sorted(self.channels.items(), key=lambda kv: -kv[1])[:6]
        # Size thresholds comfortably above the measured ambient maxima.
        rec = {
            'beacon_new_bssid_burst': max(18, nb_max * 2 + 4),
            'beacon_window': self.beacon_window,
            'beacon_la_ratio': 0.5,
            'deauth_broadcast_burst': max(6, da_max + 4),
            'deauth_per_bssid_burst': max(25, da_max * 2 + 5),
            'deauth_per_target_burst': max(12, da_max + 6),
        }
        print('# wifiwatch ambient profile (%d frames)' % self.frames, file=sys.stderr)
        print('#   distinct APs: %d  (LA ratio %.0f%%)' % (n_bssid, la_ratio * 100), file=sys.stderr)
        print('#   new-BSSID/%.0fs window  p95=%d max=%d' % (self.beacon_window, nb_p95, nb_max), file=sys.stderr)
        print('#   deauth/%.0fs window     p95=%d max=%d' % (self.deauth_window, da_p95, da_max), file=sys.stderr)
        print('#   busiest channels: %s' % ', '.join('%d(%d)' % (c, n) for c, n in busiest), file=sys.stderr)
        print(json.dumps({'thresholds': rec}, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(description='Profile ambient RF and size wifiwatch thresholds.')
    ap.add_argument('-i', '--iface', help='monitor-mode interface (live)')
    ap.add_argument('--replay', help='profile a pcap instead of live')
    ap.add_argument('--minutes', type=float, default=15.0, help='live capture minutes (default 15)')
    ap.add_argument('--config', help='(read warmup/window from this config if present)')
    args = ap.parse_args(argv)

    warmup, bw, dw = 30.0, 8.0, 5.0
    if args.config:
        try:
            c = json.load(open(args.config))
            warmup = c.get('beacon_warmup_sec', warmup)
            bw = c.get('beacon_window', bw)
            dw = c.get('deauth_broadcast_window', dw)
        except Exception:
            pass
    prof = Profiler(warmup, bw, dw)

    if args.replay:
        from scapy.all import PcapReader
        with PcapReader(args.replay) as pr:
            for pkt in pr:
                prof.handle(bytes(pkt), float(getattr(pkt, 'time', 0)) or time.time())
    elif args.iface:
        import os
        if os.geteuid() != 0:
            sys.stderr.write('error: live capture needs root.\n')
            return 2
        from scapy.all import sniff
        deadline = time.time() + args.minutes * 60
        sniff(iface=args.iface, store=False,
              prn=lambda p: prof.handle(bytes(p), float(getattr(p, 'time', 0)) or time.time()),
              stop_filter=lambda p: time.time() >= deadline)
    else:
        ap.error('one of --iface or --replay is required')
    prof.report()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
