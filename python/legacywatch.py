#!/usr/bin/env python3
"""legacywatch.py — passive 802.11 legacy-PHY, cipher-downgrade and airtime
attribution detector (Ragnar passive network security suite).

Answers the operational question ordinary Wi-Fi tooling does not: *which
specific station is making this cell slow, by MAC (and name), and by how much* —
plus the encryption/PHY posture that caps the whole BSS.

Detection-only and receive-only. It never transmits — no probes, assoc or
deauth — and never touches radio state (no monitor-mode set, no channel set, no
hop). You prepare the interface; it opens it read-only. The 802.11 + radiotap
parsing is raw-byte (no Scapy dissectors), so `--self-test` and `--replay` of a
pcap run with no radio and the self-test needs no Scapy at all; Scapy is used
purely as the live-capture front-end.

Three detection layers, cheapest first:
  1. The AP confesses (beacon): ERP protection, HT Protection = Non-HT Mixed,
     a basic-rate set that still admits 802.11b, cipher downgrade (WEP/TKIP
     disable HT rates), MFP absent.
  2. Per-station capability: declared from (re)assoc/probe requests (HT element
     present/absent is definitive) — far stronger than guessing from rates.
  3. Airtime attribution per MAC, BOTH directions (ToDS + FromDS), preamble-
     accurate, reported as airtime-share vs byte-share disproportion.

See docs/legacywatch.md. Run `python3 legacywatch.py --self-test`.
"""

import argparse
import json
import os
import re
import struct
import sys
import time
from collections import defaultdict, deque, OrderedDict
from datetime import datetime, timezone

MODULE = 'legacywatch'
VERSION = '1.0.0'

# Spec severity -> Watchtower severity bucket {info,warning,critical}.
SEV_RANK = {'INFO': 'info', 'LOW': 'info', 'MEDIUM': 'warning',
            'HIGH': 'warning', 'CRITICAL': 'critical'}

# Finding code -> (spec severity, name).
CODES = {
    'LEG-001': ('HIGH', 'NONERP_STA_PRESENT'),
    'LEG-002': ('HIGH', 'ERP_PROTECTION_ACTIVE'),
    'LEG-003': ('MEDIUM', 'BARKER_PREAMBLE_REQUIRED'),
    'LEG-004': ('HIGH', 'HT_PROTECTION_MIXED'),
    'LEG-006': ('MEDIUM', 'BSS_ADMITS_11B'),
    'LEG-007': ('HIGH', 'BSS_NO_HT_CAPABILITY'),
    'LEG-008': ('MEDIUM', 'LONG_SLOT_TIME'),
    'LEG-010': ('HIGH', 'BSS_OPEN'),
    'LEG-011': ('CRITICAL', 'BSS_WEP'),
    'LEG-012': ('HIGH', 'BSS_WPA1_ONLY'),
    'LEG-013': ('HIGH', 'GROUP_CIPHER_TKIP'),
    'LEG-014': ('MEDIUM', 'PAIRWISE_TKIP_OFFERED'),
    'LEG-015': ('MEDIUM', 'WPA_WPA2_MIXED'),
    'LEG-016': ('LOW', 'MFP_ABSENT'),
    'LEG-020': ('HIGH', 'CLIENT_11B_ONLY'),
    'LEG-021': ('MEDIUM', 'CLIENT_11G_ONLY'),
    'LEG-022': ('MEDIUM', 'CLIENT_LEGACY_RATE_STUCK'),
    'LEG-023': ('HIGH', 'CLIENT_AIRTIME_DISPROPORTIONATE'),
    'LEG-024': ('MEDIUM', 'CLIENT_HIGH_RETRY_LEGACY'),
    'LEG-025': ('LOW', 'CLIENT_NO_AGGREGATION'),
    'LEG-026': ('INFO', 'CLIENT_IDENTITY_DISCLOSED'),
    'LEG-027': ('MEDIUM', 'CLIENT_TABLE_PRESSURE'),
}

BROADCAST = 'ff:ff:ff:ff:ff:ff'
_DSSS_RATES = {1.0, 2.0, 5.5, 11.0}
_CIPHER_NAMES = {1: 'WEP-40', 2: 'TKIP', 4: 'CCMP-128', 5: 'WEP-104',
                 8: 'GCMP-128', 9: 'GCMP-256', 10: 'CCMP-256'}
# HT MCS 0-7 base rate (Mbps) at 20 MHz, 800 ns GI, one spatial stream.
_HT_MCS20 = [6.5, 13, 19.5, 26, 39, 52, 58.5, 65]


# ===========================================================================
# Radiotap (raw) — freq, signal, PHY rate (legacy Rate or HT MCS)
# ===========================================================================
# bit -> (align, size). Enough to reach MCS (bit 19).
_RT_FIELDS = {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1),
              6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1),
              12: (1, 1), 13: (1, 1), 14: (2, 2), 15: (2, 2), 16: (1, 1),
              17: (1, 1), 18: (4, 8), 19: (1, 3), 20: (4, 8), 21: (2, 12)}


def _u16(b, i):
    return b[i] | (b[i + 1] << 8)


def _u32(b, i):
    return struct.unpack_from('<I', b, i)[0]


def _s8(v):
    return v - 256 if v > 127 else v


def _mcs_rate(idx, bw40, sgi):
    """Approximate HT PHY rate (Mbps) from an MCS index + bandwidth/GI flags."""
    base = _HT_MCS20[idx % 8]
    streams = idx // 8 + 1
    rate = base * streams
    if bw40:
        rate *= 2.077
    if sgi:
        rate *= 1.111
    return round(rate, 1)


def parse_radiotap(buf):
    """Return dict(freq, signal, rate_mbps, hdrlen). Best-effort; missing fields
    stay None. rate_mbps comes from legacy Rate (bit 2) or, absent that, MCS
    (bit 19)."""
    out = {'freq': None, 'signal': None, 'rate_mbps': None, 'hdrlen': 0}
    if len(buf) < 8 or buf[0] != 0:
        return out
    hdrlen = _u16(buf, 2)
    if hdrlen < 8 or hdrlen > len(buf):
        return out
    out['hdrlen'] = hdrlen
    present = _u32(buf, 4)
    off = 8
    p = present
    while p & 0x80000000 and off + 4 <= hdrlen:      # presence extensions
        p = _u32(buf, off)
        off += 4
    pos = off
    for bit in range(22):
        if not (present & (1 << bit)):
            continue
        if bit not in _RT_FIELDS:
            break
        a, sz = _RT_FIELDS[bit]
        pos = (pos + a - 1) & ~(a - 1)
        if pos + sz > hdrlen:
            break
        if bit == 2:
            out['rate_mbps'] = buf[pos] * 0.5
        elif bit == 3:
            out['freq'] = _u16(buf, pos)
        elif bit == 5:
            out['signal'] = _s8(buf[pos])
        elif bit == 19 and out['rate_mbps'] is None:
            known, flags, idx = buf[pos], buf[pos + 1], buf[pos + 2]
            bw40 = (known & 0x01) and (flags & 0x03) == 1
            sgi = (known & 0x04) and (flags & 0x04)
            out['rate_mbps'] = _mcs_rate(idx, bw40, sgi)
        pos += sz
    return out


def band_of(freq):
    if freq is None:
        return None
    if 2400 <= freq < 2500:
        return '2.4'
    if 5150 <= freq < 5895:
        return '5'
    if freq >= 5925:
        return '6'
    return None


# ===========================================================================
# 802.11 header + information elements (raw)
# ===========================================================================
def _mac(b, i):
    return ':'.join('%02x' % x for x in b[i:i + 6])


def is_locally_administered(mac):
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


def _is_group(mac):
    try:
        return bool(int(mac.split(':')[0], 16) & 0x01)
    except (ValueError, IndexError, AttributeError):
        return True


def parse_dot11(b):
    """Parse the 802.11 MAC header. Returns a dict or None. Resolves the
    station (non-AP endpoint) and BSSID from the ToDS/FromDS bits so airtime can
    be attributed to the client in BOTH directions."""
    if len(b) < 10:
        return None
    fc0, fc1 = b[0], b[1]
    ftype = (fc0 >> 2) & 0x03
    subtype = (fc0 >> 4) & 0x0f
    to_ds, from_ds = bool(fc1 & 0x01), bool(fc1 & 0x02)
    retry = bool(fc1 & 0x08)
    protected = bool(fc1 & 0x40)
    d = {'type': ftype, 'subtype': subtype, 'to_ds': to_ds, 'from_ds': from_ds,
         'retry': retry, 'protected': protected, 'len': len(b)}
    a1 = _mac(b, 4) if len(b) >= 10 else None
    a2 = _mac(b, 10) if len(b) >= 16 else None
    a3 = _mac(b, 16) if len(b) >= 22 else None
    d['addr1'], d['addr2'], d['addr3'] = a1, a2, a3
    # Station / BSSID resolution.
    if ftype == 1:                                   # control frames: no STA
        d['sta'], d['bssid'] = None, None
    elif to_ds and not from_ds:
        d['sta'], d['bssid'] = a2, a1
    elif from_ds and not to_ds:
        d['sta'], d['bssid'] = a1, a2
    elif not to_ds and not from_ds:
        d['sta'], d['bssid'] = a2, a3
    else:
        d['sta'], d['bssid'] = None, a3 or a1
    return d


def _mgmt_body_offset(d):
    """Byte offset of the tagged-parameter list within a management frame body
    (after the 24-byte MAC header + fixed fields)."""
    st = d['subtype']
    if st == 8 or st == 5:        # beacon / probe response: 12 fixed bytes
        return 24 + 12
    if st == 0:                   # assoc request: cap(2)+listen(2)
        return 24 + 4
    if st == 2:                   # reassoc request: cap(2)+listen(2)+current AP(6)
        return 24 + 10
    if st == 4:                   # probe request: no fixed fields
        return 24
    return 24


def _cap_info(b):
    """Capability Information field: 2 bytes after the 24-byte MAC header + the
    8-byte timestamp + 2-byte beacon interval (offset 34)."""
    return _u16(b, 34) if len(b) >= 36 else 0


def parse_ies(b, start):
    """Walk tagged parameters from `start`, returning {eid: [values...]} plus a
    convenience decode of the elements legacywatch cares about."""
    out = {'ssid': None, 'rates': [], 'basic_cck': False, 'has_ht': False,
           'has_vht': False, 'has_he': False, 'erp': None, 'ht_prot': None,
           'rsn': None, 'wpa1': False, 'wsc_name': None, 'wsc_model': None,
           'wsc_manuf': None, 'p2p_name': None}
    n = len(b)
    i = start
    while i + 2 <= n:
        eid, elen = b[i], b[i + 1]
        i += 2
        if i + elen > n:
            break
        val = b[i:i + elen]
        i += elen
        if eid == 0:
            try:
                out['ssid'] = val.decode('utf-8', 'replace')
            except Exception:
                out['ssid'] = ''
        elif eid in (1, 50):
            for x in val:
                r = (x & 0x7f) * 0.5
                out['rates'].append(r)
                if (x & 0x80) and r in _DSSS_RATES:
                    out['basic_cck'] = True
        elif eid == 42 and elen >= 1:
            out['erp'] = val[0]
        elif eid == 45:
            out['has_ht'] = True
        elif eid == 61 and elen >= 2:
            out['ht_prot'] = val[1] & 0x03
        elif eid == 191:
            out['has_vht'] = True
        elif eid == 255 and elen >= 1 and val[0] == 35:
            out['has_he'] = True
        elif eid == 48:
            out['rsn'] = _parse_rsn(val)
        elif eid == 221:
            _parse_vendor(val, out)
    return out


def _parse_rsn(v):
    """Extract group/pairwise ciphers, AKM suites and PMF bits from RSN body."""
    r = {'group': None, 'pairwise': set(), 'akms': [], 'mfpc': False, 'mfpr': False}
    try:
        i = 2
        r['group'] = v[i + 3]; i += 4
        pcnt = _u16(v, i); i += 2
        for k in range(pcnt):
            r['pairwise'].add(v[i + 3]); i += 4
        acnt = _u16(v, i); i += 2
        for k in range(acnt):
            r['akms'].append(v[i + 3]); i += 4
        caps = _u16(v, i) if i + 2 <= len(v) else 0
        r['mfpc'] = bool(caps & 0x80)
        r['mfpr'] = bool(caps & 0x40)
    except (IndexError, TypeError):
        pass
    return r


def _wsc_attrs(data):
    """Yield (attr_id, value) from a WSC (0x1xxx) big-endian TLV blob."""
    i, n = 0, len(data)
    while i + 4 <= n:
        aid = (data[i] << 8) | data[i + 1]
        ln = (data[i + 2] << 8) | data[i + 3]
        i += 4
        if i + ln > n:
            break
        yield aid, data[i:i + ln]
        i += ln


def _parse_vendor(v, out):
    """Vendor-specific element: WPA1 (00:50:F2:01), WSC/WPS names (00:50:F2:04)
    and P2P device name (50:6F:9A:09)."""
    if len(v) < 4:
        return
    oui, otype = v[:3], v[3]
    if oui == b'\x00\x50\xf2' and otype == 1:
        out['wpa1'] = True
    elif oui == b'\x00\x50\xf2' and otype == 4:      # WSC / WPS
        for aid, val in _wsc_attrs(v[4:]):
            if aid == 0x1011:                        # Device Name
                out['wsc_name'] = val.decode('utf-8', 'replace')
            elif aid == 0x1023:                      # Model Name
                out['wsc_model'] = val.decode('utf-8', 'replace')
            elif aid == 0x1021:                      # Manufacturer
                out['wsc_manuf'] = val.decode('utf-8', 'replace')
    elif oui == b'\x50\x6f\x9a' and otype == 9:      # Wi-Fi P2P
        # P2P attributes are 1B id + 2B LE len + val; Device Info (0x0d) carries
        # the device name near its tail (attr 0x1011 inside). Best-effort scan.
        m = re.search(b'\x10\x11..([ -~]{2,32})', v[4:])
        if m:
            out['p2p_name'] = m.group(1).decode('utf-8', 'replace')


# ===========================================================================
# Airtime + PHY classification
# ===========================================================================
def frame_airtime_us(nbytes, rate_mbps):
    """Measured PPDU on-air time (us): PHY preamble + data-symbol time. The
    preamble dominates for legacy frames (192 us DSSS long preamble)."""
    rate = rate_mbps or 6.0
    if rate <= 11.0:
        preamble = 192.0
    elif rate <= 54.0:
        preamble = 20.0
    else:
        preamble = 40.0
    return preamble + (nbytes * 8) / rate


def classify_phy(declared_ht, rate_min, rate_max):
    """(label, is_pre_n_legacy, confidence). Declared capability wins over
    observed rates (a modern client at the cell edge sends only low rates)."""
    if declared_ht is True:
        return ('n+', False, 'declared')
    if declared_ht is False:
        if rate_max is not None and rate_max <= 11.0:
            return ('b', True, 'declared')
        return ('g', True, 'declared')
    if rate_min is None:
        return (None, False, None)
    if rate_max <= 11.0 and rate_min in _DSSS_RATES:
        return ('b', True, 'observed')
    if rate_max <= 54.0:
        return ('g', True, 'observed')
    return ('n+', False, 'observed')


# ===========================================================================
# MAC canonicalization (colon / dash / cisco-dotted / bare)
# ===========================================================================
def canon_mac(s):
    """Normalize any common MAC literal to aa:bb:cc:dd:ee:ff, or None."""
    if not isinstance(s, str):
        return None
    hexs = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(hexs) != 12:
        return None
    return ':'.join(hexs[i:i + 2] for i in range(0, 12, 2)).lower()


def canon_mac_list(seq, label='mac'):
    out = set()
    for s in seq or []:
        m = canon_mac(s)
        if m:
            out.add(m)
        else:
            sys.stderr.write('legacywatch: dropping invalid %s %r\n' % (label, s))
    return out


# ===========================================================================
# OUI vendor lookup (optional IEEE registry CSV: MA-L /24, MA-M /28, MA-S /36)
# ===========================================================================
class OuiDB:
    def __init__(self, path=None):
        self.by_len = {6: {}, 7: {}, 9: {}}          # hex-prefix len -> {prefix: vendor}
        if path:
            self.load(path)

    def load(self, path):
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    parts = line.strip().split(',', 1)
                    if len(parts) != 2:
                        continue
                    pfx = re.sub(r'[^0-9a-fA-F]', '', parts[0]).lower()
                    if len(pfx) in self.by_len:
                        self.by_len[len(pfx)][pfx] = parts[1].strip().strip('"')
        except OSError as e:
            sys.stderr.write('legacywatch: OUI CSV: %s\n' % e)

    def lookup(self, mac):
        h = re.sub(r'[^0-9a-f]', '', (mac or '').lower())
        for plen in (9, 7, 6):                        # longest prefix first
            if h[:plen] in self.by_len[plen]:
                return self.by_len[plen][h[:plen]]
        return None


# ===========================================================================
# 3-segment station table (detection logic, not memory hygiene)
# ===========================================================================
class StationTable:
    """probation (first sighting, LRU) -> protected (promoted on 2nd sighting or
    legacy classification, LRU) -> pinned (operator, never evicted). A plain LRU
    would let anyone mint throwaway MACs and push the real legacy station out."""

    def __init__(self, probation_max, protected_max, pinned_max, pinned):
        self.probation = OrderedDict()
        self.protected = OrderedDict()
        self.pinned = {}
        self.probation_max = probation_max
        self.protected_max = protected_max
        self.pinned_max = pinned_max
        self.pinned_names = set(pinned or [])
        self.evictions = 0
        self.protected_evictions = 0

    def get(self, mac, factory):
        if mac in self.pinned:
            return self.pinned[mac]
        if mac in self.protected:
            self.protected.move_to_end(mac)
            return self.protected[mac]
        if mac in self.probation:
            rec = self.probation.pop(mac)            # 2nd sighting -> promote
            self._add_protected(mac, rec)
            return rec
        rec = factory()
        if mac in self.pinned_names:
            if len(self.pinned) < self.pinned_max:
                self.pinned[mac] = rec
            else:
                sys.stderr.write('legacywatch: pinned table full; %s not pinned\n' % mac)
                self._add_probation(mac, rec)
        else:
            self._add_probation(mac, rec)
        return rec

    def promote(self, mac):
        if mac in self.probation:
            rec = self.probation.pop(mac)
            self._add_protected(mac, rec)

    def _add_probation(self, mac, rec):
        self.probation[mac] = rec
        if len(self.probation) > self.probation_max:
            self.probation.popitem(last=False)
            self.evictions += 1

    def _add_protected(self, mac, rec):
        self.protected[mac] = rec
        if len(self.protected) > self.protected_max:
            self.protected.popitem(last=False)
            self.protected_evictions += 1
            self.evictions += 1

    def all_records(self):
        yield from self.pinned.items()
        yield from self.protected.items()
        yield from self.probation.items()


# ===========================================================================
# Config
# ===========================================================================
DEFAULTS = {
    'iface': None, 'bssid': None, 'ssid': None,
    'airtime_report_s': 60, 'airtime_disproportion': 4.0, 'airtime_min_share': 0.05,
    'retry_ratio_warn': 0.25, 'retry_min_frames': 200,
    'legacy_rate_stuck_ratio': 0.8, 'legacy_rate_min_frames': 100,
    'min_frames_for_client_finding': 5,
    'suppress_s': 900, 'suppress_max': 8192,
    'probation_max': 4096, 'protected_max': 2048, 'pinned_max': 512,
    'pinned_clients': [], 'baseline_legacy': [],
    'oui_csv': None, 'inventory_csv': None,
}


class Config:
    def __init__(self, d=None):
        d = dict(d or {})
        for k in d:
            if k not in DEFAULTS:
                sys.stderr.write('legacywatch: unknown config key %r dropped\n' % k)
        self.v = dict(DEFAULTS)
        self.v.update({k: d[k] for k in d if k in DEFAULTS})
        self.v['bssid'] = canon_mac(self.v['bssid']) if self.v['bssid'] else None
        self.pinned = canon_mac_list(self.v['pinned_clients'], 'pinned_clients')
        self.baseline = canon_mac_list(self.v['baseline_legacy'], 'baseline_legacy')

    def __getitem__(self, k):
        return self.v[k]

    @staticmethod
    def load(path):
        with open(path) as f:
            return Config(json.load(f))


# ===========================================================================
# Identity resolution (inventory > wps > p2p > oui)
# ===========================================================================
def load_inventory(path):
    inv = {}
    if not path:
        return inv
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 2:
                    continue
                mac = canon_mac(parts[0])
                if mac:
                    inv[mac] = {'hostname': parts[1], 'note': parts[2] if len(parts) > 2 else ''}
    except OSError as e:
        sys.stderr.write('legacywatch: inventory CSV: %s\n' % e)
    return inv


# ===========================================================================
# The detector
# ===========================================================================
class LegacyWatch:
    def __init__(self, cfg=None, emit=None, oui=None, inventory=None):
        self.cfg = cfg if isinstance(cfg, Config) else Config(cfg)
        self.emit = emit or (lambda a: None)
        self.oui = oui or OuiDB()
        self.inv = inventory or {}
        self.frames = 0
        self.stats = defaultdict(int)
        self.bss = {}                                # bssid -> posture dict
        self.stations = StationTable(
            self.cfg['probation_max'], self.cfg['protected_max'],
            self.cfg['pinned_max'], self.cfg['pinned_clients'] and
            canon_mac_list(self.cfg['pinned_clients']))
        self._suppress = OrderedDict()               # code|subject -> last_ts
        self._last_report = None

    # ---- suppression -----------------------------------------------------
    def _suppressed(self, code, subject, ts):
        key = '%s|%s' % (code, subject)
        last = self._suppress.get(key)
        win = self.cfg['suppress_s']
        if last is not None and ts - last < win:
            return True
        self._suppress[key] = ts
        self._suppress.move_to_end(key)
        while len(self._suppress) > self.cfg['suppress_max']:
            self._suppress.popitem(last=False)
        return False

    def _fire(self, code, subject, summary, detail, ts):
        if self._suppressed(code, subject, ts):
            return
        sev, name = CODES[code]
        self.stats[code] += 1
        self.emit({
            'ts': datetime.fromtimestamp(ts, timezone.utc).isoformat(),
            'module': MODULE, 'severity': SEV_RANK[sev], 'level': sev,
            'codes': [code], 'type': name, 'subject': subject,
            'summary': summary, 'detail': detail,
        })

    # ---- identity --------------------------------------------------------
    def _identity(self, mac, rec):
        if mac in self.inv:
            return self.inv[mac]['hostname'], 'inventory'
        if rec.get('wsc_name'):
            return rec['wsc_name'], 'wps'
        if rec.get('p2p_name'):
            return rec['p2p_name'], 'p2p'
        v = self.oui.lookup(mac)
        if v:
            return v, 'oui'
        return None, None

    # ---- main entry ------------------------------------------------------
    def process_packet(self, raw, ts=None):
        ts = ts if ts is not None else time.time()
        self.frames += 1
        rt = parse_radiotap(raw)
        body = raw[rt['hdrlen']:]
        d = parse_dot11(body)
        if d is None:
            return
        # Scope filter.
        if self.cfg['bssid'] and d.get('bssid') and d['bssid'] != self.cfg['bssid']:
            return
        if d['type'] == 0 and d['subtype'] in (5, 8):
            self._on_beacon(body, d, ts)
        if d['type'] == 0 and d['subtype'] in (0, 2, 4):
            self._on_capability(body, d, ts, rt)
        if d['type'] in (0, 2):
            self._on_airtime(d, ts, rt)
        # Periodic airtime rollup + client findings.
        rep = self.cfg['airtime_report_s']
        if self._last_report is None:
            self._last_report = ts
        elif ts - self._last_report >= rep:
            self._report(ts)
            self._last_report = ts

    # ---- beacon posture (LEG-001..016) -----------------------------------
    def _on_beacon(self, body, d, ts):
        bssid = d['bssid']
        if not bssid:
            return
        ie = parse_ies(body, _mgmt_body_offset(d))
        cap = _cap_info(body)
        b = self.bss.setdefault(bssid, {})
        b['ssid'] = ie['ssid']
        b['freq'] = None
        name = ie['ssid'] or bssid
        subj = bssid

        # ERP protection group (2.4 GHz only).
        erp = ie['erp']
        if erp is not None:
            if erp & 0x01:
                self._fire('LEG-001', subj, '%s: a non-ERP (802.11b) station is present' % name,
                           {'bssid': bssid, 'ssid': ie['ssid']}, ts)
            if erp & 0x02:
                self._fire('LEG-002', subj,
                           '%s: ERP protection ON — every OFDM frame pays CTS-to-Self overhead' % name,
                           {'bssid': bssid, 'ssid': ie['ssid'],
                            'protection_tax_us_per_frame': 212}, ts)
            if erp & 0x04:
                self._fire('LEG-003', subj, '%s: Barker (long) preamble required' % name,
                           {'bssid': bssid}, ts)
        # HT Protection = Non-HT Mixed.
        if ie['ht_prot'] == 3:
            self._fire('LEG-004', subj, '%s: HT Protection = Non-HT Mixed (a pre-11n STA is associated)' % name,
                       {'bssid': bssid}, ts)
        # Basic-rate set still admits 802.11b.
        if ie['basic_cck']:
            self._fire('LEG-006', subj, '%s: basic-rate set includes CCK — 802.11b clients can still associate' % name,
                       {'bssid': bssid}, ts)
        # AP itself has no HT/VHT/HE capability.
        if not (ie['has_ht'] or ie['has_vht'] or ie['has_he']):
            self._fire('LEG-007', subj, '%s: AP advertises no HT/VHT/HE capability (pre-802.11n AP)' % name,
                       {'bssid': bssid}, ts)
        # Long slot time (short-slot capability bit clear). Gated on the ERP
        # element being present, which only appears on 2.4 GHz where slot time
        # matters — avoids firing on 5/6 GHz APs that never set the bit.
        if ie['erp'] is not None and not (cap & 0x0400):
            self._fire('LEG-008', subj, '%s: long slot time (20 us) in use' % name,
                       {'bssid': bssid}, ts)
        # Cipher posture.
        rsn, wpa1, privacy = ie['rsn'], ie['wpa1'], bool(cap & 0x0010)
        if not rsn and not wpa1 and not privacy:
            self._fire('LEG-010', subj, '%s: open BSS (no encryption)' % name, {'bssid': bssid}, ts)
        elif not rsn and not wpa1 and privacy:
            self._fire('LEG-011', subj, '%s: WEP — broken cipher AND no HT rates (capped at 54 Mbps)' % name,
                       {'bssid': bssid}, ts)
        elif wpa1 and not rsn:
            self._fire('LEG-012', subj, '%s: WPA1-only (TKIP) — capped at 54 Mbps' % name, {'bssid': bssid}, ts)
        if rsn:
            if rsn['group'] == 2:
                self._fire('LEG-013', subj, '%s: group cipher TKIP — 802.11n disabled for group frames BSS-wide' % name,
                           {'bssid': bssid, 'group_cipher': 'TKIP'}, ts)
            if 2 in rsn['pairwise']:
                self._fire('LEG-014', subj, '%s: TKIP offered in pairwise list — a client selecting it caps at 54 Mbps' % name,
                           {'bssid': bssid,
                            'pairwise': sorted(_CIPHER_NAMES.get(c, hex(c)) for c in rsn['pairwise'])}, ts)
            if wpa1:
                self._fire('LEG-015', subj, '%s: WPA/WPA2 transitional (both advertised)' % name, {'bssid': bssid}, ts)
            if not rsn['mfpc']:
                self._fire('LEG-016', subj, '%s: management frame protection (PMF) absent' % name, {'bssid': bssid}, ts)

    # ---- declared capability from (re)assoc/probe requests ---------------
    def _on_capability(self, body, d, ts, rt):
        sta = d['sta']
        if not sta or _is_group(sta):
            return
        ie = parse_ies(body, _mgmt_body_offset(d))
        rec = self.stations.get(sta, self._new_station)
        declared = ie['has_ht'] or ie['has_vht'] or ie['has_he']
        if declared:
            rec['declared_ht'] = True
        elif rec.get('declared_ht') is None:
            rec['declared_ht'] = False
        # Identity disclosure (LEG-026) — names on an encrypted BSS.
        for key in ('wsc_name', 'wsc_model', 'wsc_manuf', 'p2p_name'):
            if ie[key] and not rec.get(key):
                rec[key] = ie[key]
                if key in ('wsc_name', 'p2p_name'):
                    self._fire('LEG-026', sta, '%s disclosed a device name: %s' % (sta, ie[key]),
                               {'station': sta, 'name': ie[key], 'source': key}, ts)

    # ---- per-station airtime (both directions) ---------------------------
    def _on_airtime(self, d, ts, rt):
        sta = d['sta']
        if not sta or _is_group(sta) or sta == d.get('bssid'):
            return
        rec = self.stations.get(sta, self._new_station)
        rec['frames'] += 1
        rec['bssid'] = rec['bssid'] or d.get('bssid')
        rec['airtime_us'] += frame_airtime_us(d['len'], rt['rate_mbps'])
        if d['retry']:
            rec['retries'] += 1
        if d['type'] == 2:                           # data frames only for PHY
            rec['data_bytes'] += d['len']
            if rt['rate_mbps']:
                rec['rate_min'] = min(rec['rate_min'], rt['rate_mbps']) if rec['rate_min'] else rt['rate_mbps']
                rec['rate_max'] = max(rec['rate_max'] or 0, rt['rate_mbps'])
                rec['rate_frames'] += 1
                if rt['rate_mbps'] <= 11.0:
                    rec['legacy_rate_frames'] += 1

    def _new_station(self):
        return {'frames': 0, 'retries': 0, 'airtime_us': 0.0, 'data_bytes': 0,
                'rate_min': None, 'rate_max': None, 'rate_frames': 0,
                'legacy_rate_frames': 0, 'declared_ht': None, 'bssid': None}

    # ---- airtime rollup + client findings (LEG-020..027) -----------------
    def _report(self, ts):
        recs = list(self.stations.all_records())
        total_air = sum(r['airtime_us'] for _, r in recs) or 1.0
        total_bytes = sum(r['data_bytes'] for _, r in recs) or 1
        minf = self.cfg['min_frames_for_client_finding']
        for mac, r in recs:
            if r['frames'] < minf:
                continue
            baselined = mac in self.cfg.baseline
            phy, legacy, conf = classify_phy(r['declared_ht'], r['rate_min'], r['rate_max'])
            name, src = self._identity(mac, r)
            air_share = r['airtime_us'] / total_air
            byte_share = r['data_bytes'] / total_bytes
            disp = (air_share / byte_share) if byte_share > 0 else None
            base = {'station': mac, 'name': name, 'name_source': src,
                    'phy': phy, 'confidence': conf, 'bssid': r['bssid'],
                    'airtime_share': round(air_share, 4), 'byte_share': round(byte_share, 4),
                    'frames': r['frames']}
            who = ('%s (%s)' % (name, mac)) if name else mac
            if not baselined and legacy:
                if phy == 'b':
                    self._fire('LEG-020', mac, '%s is 802.11b-only (%s)' % (who, conf), base, ts)
                    self._fire('LEG-025', mac, '%s: no frame aggregation (pre-802.11n)' % who, base, ts)
                elif phy == 'g':
                    self._fire('LEG-021', mac, '%s is 802.11a/g-only, pre-802.11n (%s)' % (who, conf), base, ts)
            # HT-capable but stuck on legacy rates => RF problem, not inventory.
            if (not baselined and r['declared_ht'] is True and r['rate_frames'] >= self.cfg['legacy_rate_min_frames']
                    and r['legacy_rate_frames'] / r['rate_frames'] >= self.cfg['legacy_rate_stuck_ratio']):
                self._fire('LEG-022', mac, '%s is HT-capable but stuck on legacy rates (coverage/RF)' % who,
                           dict(base, legacy_rate_ratio=round(r['legacy_rate_frames'] / r['rate_frames'], 2)), ts)
            # Airtime disproportion — the culprit.
            if (not baselined and disp is not None and disp >= self.cfg['airtime_disproportion']
                    and air_share >= self.cfg['airtime_min_share']):
                self._fire('LEG-023', mac,
                           '%s eats %.0f%% airtime for %.0f%% of bytes (%.1fx)'
                           % (who, air_share * 100, byte_share * 100, disp),
                           dict(base, disproportion=round(disp, 1)), ts)
            # High retries at legacy rates.
            if (not baselined and r['frames'] >= self.cfg['retry_min_frames']
                    and r['retries'] / r['frames'] >= self.cfg['retry_ratio_warn'] and legacy):
                self._fire('LEG-024', mac, '%s: high retry rate at legacy rates (coverage)' % who,
                           dict(base, retry_ratio=round(r['retries'] / r['frames'], 2)), ts)
        # Table pressure.
        if self.stations.evictions:
            self._fire('LEG-027', 'station_table',
                       'station table under eviction pressure (%d evictions, %d protected)'
                       % (self.stations.evictions, self.stations.protected_evictions),
                       {'evictions': self.stations.evictions,
                        'protected_evictions': self.stations.protected_evictions}, ts)

    def final_report(self):
        """Force a rollup at shutdown so a short run still emits client findings."""
        self._report(time.time())


# ===========================================================================
# Live capture / replay / emitter
# ===========================================================================
def make_emitter(out_fh, echo):
    def emit(a):
        if out_fh:
            out_fh.write(json.dumps(a) + '\n')
            out_fh.flush()
        if echo:
            sys.stderr.write('  !! [%s] %s :: %s\n'
                             % (a['level'], ','.join(a['codes']), a['summary']))
    return emit


def run_live(iface, watch):
    from scapy.all import sniff

    def cb(p):
        watch.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time())
    sniff(iface=iface, prn=cb, store=False, monitor=True)


def run_replay(path, watch):
    from scapy.all import PcapReader
    with PcapReader(path) as pr:
        for p in pr:
            watch.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time())
    watch.final_report()


def main(argv=None):
    ap = argparse.ArgumentParser(prog='legacywatch',
                                 description='Passive 802.11 legacy-PHY / cipher-downgrade / airtime detector (detection-only).')
    ap.add_argument('-i', '--iface', help='live monitor-mode interface')
    ap.add_argument('--replay', help='replay a radiotap pcap instead of live capture')
    ap.add_argument('-c', '--config', help='JSON config')
    ap.add_argument('-o', '--jsonl', help="JSON-lines output path ('-' = stdout)")
    ap.add_argument('--oui-csv', help='IEEE OUI registry CSV (mac-prefix,vendor)')
    ap.add_argument('--enrich', help='inventory CSV: mac,hostname[,note]')
    ap.add_argument('--echo', action='store_true', help='echo alerts to stderr')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--list-findings', action='store_true')
    ap.add_argument('--version', action='store_true')
    args = ap.parse_args(argv)

    if args.version:
        print('%s %s' % (MODULE, VERSION))
        return 0
    if args.list_findings:
        for code in sorted(CODES):
            sev, name = CODES[code]
            print('%s  %-8s %s' % (code, sev, name))
        return 0
    if args.self_test:
        import legacywatch_selftest
        return legacywatch_selftest.run(verbose=True)

    cfg = Config.load(args.config) if args.config else Config()
    oui = OuiDB(args.oui_csv or cfg['oui_csv'])
    inv = load_inventory(args.enrich or cfg['inventory_csv'])
    out_fh = sys.stdout if args.jsonl == '-' else (open(args.jsonl, 'a') if args.jsonl else None)
    watch = LegacyWatch(cfg, emit=make_emitter(out_fh, args.echo or not args.jsonl),
                        oui=oui, inventory=inv)

    if args.replay:
        run_replay(args.replay, watch)
    elif args.iface:
        if os.geteuid() != 0:
            sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
            return 2
        try:
            run_live(args.iface, watch)
        except KeyboardInterrupt:
            pass
        watch.final_report()
    else:
        ap.error('one of --iface, --replay or --self-test is required')
    sys.stderr.write('legacywatch: %d frames, findings %s\n' % (watch.frames, dict(watch.stats)))
    if out_fh and out_fh is not sys.stdout:
        out_fh.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
