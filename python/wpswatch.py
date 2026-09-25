#!/usr/bin/env python3
"""wpswatch.py — passive WPS / Wi-Fi Simple Config posture and attack detector
(Ragnar passive network security suite).

Answers two questions ordinary Wi-Fi tooling does not: **can this AP be enrolled
by someone in range, and is anyone trying right now.**

Detection-only and receive-only. It never transmits, derives no PINs, recovers
no nonces, and completes no enrollment. Raw-byte parsing (no Scapy dissectors)
so `--self-test` and `--replay` run with no radio; Scapy is only the live
front-end.

Two evidence sources:
  * AP posture, from beacons/probe responses — the WSC element an AP advertises
    describes its own enrollment surface in plaintext. The single most important
    signal is the ABSENCE of a Version2 subelement (=> WSC 1.0, no mandatory PIN
    lockout, so an online brute force runs to completion). The Version attribute
    (0x104A) is NOT a substitute — nearly every AP advertises 0x10 there.
  * Live sessions, from EAP-WSC (M1..M8) — WPS runs over EAPOL BEFORE any key
    material exists, so the exchange is readable on a WPA2 BSS by a keyless
    sensor. Message-type accounting separates online brute force (high rate +
    NACKs dominating) from offline nonce harvest (few M1-M3 abandoned before M4).

This module deliberately shares the low-level radiotap/802.11 parsers with
legacywatch (same suite, same monitor interface). See docs/wpswatch.md. Run
`python3 wpswatch.py --self-test`.
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

import legacywatch as L                              # shared raw parsers + helpers

MODULE = 'wpswatch'
VERSION = '1.0.0'
SEV_RANK = L.SEV_RANK

CODES = {
    'WPS-001': ('MEDIUM', 'WPS_ENABLED'),
    'WPS-002': ('HIGH', 'WPS_PIN_METHOD_AVAILABLE'),
    'WPS-003': ('HIGH', 'WPS_AP_NOT_LOCKED'),
    'WPS-004': ('HIGH', 'WPS_STATE_NOT_CONFIGURED'),
    'WPS-005': ('HIGH', 'WPS_VERSION_1'),
    'WPS-006': ('CRITICAL', 'WPS_WEAK_NONCE_FAMILY'),
    'WPS-007': ('HIGH', 'WPS_MAC_DERIVED_PIN_FAMILY'),
    'WPS-008': ('MEDIUM', 'WPS_REGISTRAR_ACTIVE'),
    'WPS-009': ('MEDIUM', 'WPS_UUID_MAC_DERIVED'),
    'WPS-010': ('LOW', 'WPS_AP_INFO_DISCLOSURE'),
    'WPS-011': ('INFO', 'WPS_PUSHBUTTON_ONLY'),
    'WPS-012': ('INFO', 'WPS_AP_LOCKED'),
    'WPS-013': ('MEDIUM', 'WPS_LOCK_STATE_CHANGED'),
    'WPS-014': ('LOW', 'WPS_POSTURE_CHANGED'),
    'WPS-020': ('INFO', 'WPS_SESSION_OBSERVED'),
    'WPS-021': ('CRITICAL', 'WPS_BRUTE_FORCE_IN_PROGRESS'),
    'WPS-022': ('HIGH', 'WPS_NACK_FLOOD'),
    'WPS-023': ('HIGH', 'WPS_NONCE_HARVEST'),
    'WPS-024': ('HIGH', 'WPS_AUTH_FAILURE_BURST'),
    'WPS-025': ('MEDIUM', 'WPS_UNKNOWN_ENROLLEE'),
    'WPS-026': ('MEDIUM', 'WPS_ENROLLMENT_COMPLETED'),
    'WPS-027': ('MEDIUM', 'WPS_SESSION_TABLE_PRESSURE'),
}

# WSC attribute IDs (big-endian TLV).
A_STATE, A_LOCKED, A_CFGM, A_SEL_REG = 0x1044, 0x1057, 0x1008, 0x1041
A_VENDOR_EXT, A_MANUF, A_MODEL, A_DEVNAME = 0x1049, 0x1021, 0x1023, 0x1011
A_SERIAL, A_UUID_E, A_MSG_TYPE = 0x1042, 0x1047, 0x1022
CFG_PIN = 0x0004 | 0x0008 | 0x0100                   # Label|Display|Keypad
CFG_PBC = 0x0080

# WSC message types (attr 0x1022) — the exchange is M1..M8 then ACK/NACK/DONE.
MSG = {0x04: 'M1', 0x05: 'M2', 0x06: 'M2D', 0x07: 'M3', 0x08: 'M4', 0x09: 'M5',
       0x0a: 'M6', 0x0b: 'M7', 0x0c: 'M8', 0x0d: 'ACK', 0x0e: 'NACK', 0x0f: 'DONE'}

# Model families with documented weak WSC nonce generation (screening aid, not
# an authority — a match means "verify against current firmware"). Extended by
# config `vuln_families`.
_WEAK_FAMILIES = [
    (re.compile(r'ralink|rt\d{4}', re.I), 'Ralink reference (static/weak nonce)'),
    (re.compile(r'broadcom.*(bcm4)', re.I), 'some Broadcom (weak nonce)'),
    (re.compile(r'realtek|rtl8', re.I), 'some Realtek (weak nonce)'),
]
_MAC_PIN_FAMILIES = [
    (re.compile(r'd-?link|dir-\d', re.I), 'D-Link (factory PIN derived from BSSID on some models)'),
]


def _wsc_attrs(data):
    i, n = 0, len(data)
    while i + 4 <= n:
        aid = (data[i] << 8) | data[i + 1]
        ln = (data[i + 2] << 8) | data[i + 3]
        i += 4
        if i + ln > n:
            break
        yield aid, data[i:i + ln]
        i += ln


def parse_wsc(data):
    """Parse a WSC element/EAP body into a posture dict. Reads only plaintext
    self-description — no keys, no PIN math."""
    w = {'present': True, 'configured': None, 'locked': None, 'pin_method': False,
         'pushbutton': False, 'selected_registrar': False, 'version2': False,
         'manuf': None, 'model': None, 'devname': None, 'serial': None,
         'uuid_e': None, 'msg_type': None}
    for aid, val in _wsc_attrs(data):
        if aid == A_STATE and val:
            w['configured'] = val[0] == 2
        elif aid == A_LOCKED and val:
            w['locked'] = val[0] == 1
        elif aid == A_CFGM and len(val) >= 2:
            m = (val[0] << 8) | val[1]
            w['pin_method'] = bool(m & CFG_PIN)
            w['pushbutton'] = bool(m & CFG_PBC)
        elif aid == A_SEL_REG and val:
            w['selected_registrar'] = val[0] == 1
        elif aid == A_VENDOR_EXT and len(val) >= 4 and val[:3] == b'\x00\x37\x2a':
            j = 3
            while j + 2 <= len(val):
                sid, slen = val[j], val[j + 1]
                j += 2
                if sid == 0x00 and slen >= 1:
                    w['version2'] = True
                j += slen
        elif aid == A_MANUF and val:
            w['manuf'] = val.decode('utf-8', 'replace')
        elif aid == A_MODEL and val:
            w['model'] = val.decode('utf-8', 'replace')
        elif aid == A_DEVNAME and val:
            w['devname'] = val.decode('utf-8', 'replace')
        elif aid == A_SERIAL and val:
            w['serial'] = val.decode('utf-8', 'replace')
        elif aid == A_UUID_E and len(val) == 16:
            w['uuid_e'] = val
        elif aid == A_MSG_TYPE and val:
            w['msg_type'] = val[0]
    return w


def extract_wsc_ie(body, start):
    """Find the WSC vendor element (00:50:F2:04) in a beacon/proberesp and
    return its parsed posture, or None."""
    b, n, i = body, len(body), start
    while i + 2 <= n:
        eid, elen = b[i], b[i + 1]
        i += 2
        if i + elen > n:
            break
        val = b[i:i + elen]
        i += elen
        if eid == 221 and val[:4] == b'\x00\x50\xf2\x04':
            return parse_wsc(val[4:])
    return None


# ---- EAP-WSC over EAPOL in a data frame -----------------------------------
_SNAP_EAPOL = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e'


def data_header_len(d):
    """Byte length of the 802.11 data-frame MAC header (QoS + WDS aware)."""
    ln = 24
    if d['to_ds'] and d['from_ds']:
        ln += 6                                       # addr4 (WDS)
    if d['subtype'] & 0x08:                           # QoS data
        ln += 2
    return ln


def parse_eap_wsc(body, d):
    """If the frame is an EAP-WSC packet, return (eap_code, wsc_posture) where
    wsc_posture carries msg_type; else None. eap_code: 1=req 2=resp 3=success
    4=failure."""
    hl = data_header_len(d)
    p = body[hl:]
    if p[:8] != _SNAP_EAPOL:
        return None
    e = p[8:]
    if len(e) < 4 or e[1] != 0:                        # EAPOL type 0 = EAP packet
        return None
    eap = e[4:]
    if len(eap) < 4:
        return None
    code = eap[0]
    if code in (3, 4):                                 # EAP Success / Failure (4 bytes)
        return (code, None)
    if len(eap) < 5 or eap[4] != 254:                  # not Expanded type
        return (code, None)
    # Expanded: type(1)+vendor-id(3)+vendor-type(4)=8, then opcode(1)+flags(1).
    exp = eap[4:]
    if len(exp) < 10 or exp[1:4] != b'\x00\x37\x2a':
        return (code, None)
    wsc_tlvs = exp[10:]
    return (code, parse_wsc(wsc_tlvs))


# ===========================================================================
# Config
# ===========================================================================
DEFAULTS = {
    'iface': None, 'bssid': None, 'ssid': None, 'inventory_csv': None,
    'report_s': 300, 'brute_force_attempts': 20, 'brute_force_window_s': 60,
    'nack_flood_threshold': 30, 'nack_flood_window_s': 60, 'nonce_harvest_cycles': 3,
    'auth_failure_burst': 5, 'suppress_s': 900, 'suppress_max': 8192,
    'probation_max': 2048, 'protected_max': 1024, 'pinned_max': 256,
    'pinned_stations': [], 'known_enrollees': [], 'baseline_wps_aps': [],
    'vuln_families': [], 'report_good_posture': True,
}


class Config:
    def __init__(self, d=None):
        d = dict(d or {})
        for k in d:
            if k not in DEFAULTS:
                sys.stderr.write('wpswatch: unknown config key %r dropped\n' % k)
        self.v = dict(DEFAULTS)
        self.v.update({k: d[k] for k in d if k in DEFAULTS})
        self.v['bssid'] = L.canon_mac(self.v['bssid']) if self.v['bssid'] else None
        self.baseline = L.canon_mac_list(self.v['baseline_wps_aps'], 'baseline_wps_aps')
        self.known = L.canon_mac_list(self.v['known_enrollees'], 'known_enrollees')
        self.pinned = L.canon_mac_list(self.v['pinned_stations'], 'pinned_stations')
        self.vuln = []
        for pair in self.v['vuln_families']:
            try:
                self.vuln.append((re.compile(pair[0], re.I), pair[1]))
            except (re.error, IndexError, TypeError):
                sys.stderr.write('wpswatch: invalid vuln_families entry %r dropped\n' % (pair,))

    def __getitem__(self, k):
        return self.v[k]

    @staticmethod
    def load(path):
        with open(path) as f:
            return Config(json.load(f))


class RateWindow:
    """Event count within a time window, bounded by count as well as time so a
    flood can't grow it without bound."""
    def __init__(self, window_s, cap=4096):
        self.window_s = window_s
        self.cap = cap
        self.dq = deque()

    def add(self, ts):
        self.dq.append(ts)
        cutoff = ts - self.window_s
        while self.dq and self.dq[0] < cutoff:
            self.dq.popleft()
        while len(self.dq) > self.cap:
            self.dq.popleft()
        return len(self.dq)


# ===========================================================================
# The detector
# ===========================================================================
class WpsWatch:
    def __init__(self, cfg=None, emit=None, inventory=None):
        self.cfg = cfg if isinstance(cfg, Config) else Config(cfg)
        self.emit = emit or (lambda a: None)
        self.inv = inventory or {}
        self.frames = 0
        self.stats = defaultdict(int)
        self.aps = {}                                # bssid -> last posture
        self.sessions = OrderedDict()                # sta -> session dict
        self._suppress = OrderedDict()
        self.evictions = 0

    # ---- suppression -----------------------------------------------------
    def _suppressed(self, code, subject, ts):
        key = '%s|%s' % (code, subject)
        last = self._suppress.get(key)
        if last is not None and ts - last < self.cfg['suppress_s']:
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

    def _name(self, mac):
        rec = self.inv.get(mac)
        return rec['hostname'] if rec else None

    # ---- main entry ------------------------------------------------------
    def process_packet(self, raw, ts=None):
        ts = ts if ts is not None else time.time()
        self.frames += 1
        rt = L.parse_radiotap(raw)
        body = raw[rt['hdrlen']:]
        d = L.parse_dot11(body)
        if d is None:
            return
        if self.cfg['bssid'] and d.get('bssid') and d['bssid'] != self.cfg['bssid']:
            return
        if d['type'] == 0 and d['subtype'] in (5, 8):
            wsc = extract_wsc_ie(body, L._mgmt_body_offset(d))
            if wsc:
                self._on_posture(d['bssid'], wsc, ts)
        elif d['type'] == 2 and (d['subtype'] & 0x08 or d['subtype'] == 0):
            res = parse_eap_wsc(body, d)
            if res is not None:
                self._on_session(d, res, ts)

    # ---- AP posture (WPS-001..014) --------------------------------------
    def _on_posture(self, bssid, w, ts):
        if not bssid:
            return
        baselined = bssid in self.cfg.baseline
        name = bssid
        subj = bssid
        prev = self.aps.get(bssid)
        self.aps[bssid] = w

        # Lock-state transition — fires EVEN for a baselined AP (self-locking is
        # evidence of an attack in progress).
        if prev is not None and prev.get('locked') is not None and w.get('locked') is not None \
                and prev['locked'] != w['locked']:
            direction = '0->1 (AP locked itself — PIN method was being hammered)' if w['locked'] \
                else '1->0 (enrollment surface reopened)'
            self._fire('WPS-013', subj, '%s WPS lock state changed %s' % (name, direction),
                       {'bssid': bssid, 'locked': w['locked']}, ts)
        if prev is not None and not baselined:
            for k in ('pin_method', 'configured', 'selected_registrar', 'version2'):
                if prev.get(k) != w.get(k):
                    self._fire('WPS-014', subj, '%s WPS posture changed (%s)' % (name, k),
                               {'bssid': bssid, 'field': k}, ts)
                    break

        if baselined:
            return

        self._fire('WPS-001', subj, '%s has WPS enabled' % name, {'bssid': bssid}, ts)
        if w['pin_method']:
            self._fire('WPS-002', subj, '%s offers the WPS PIN method (external-registrar M3/M4 path)' % name,
                       {'bssid': bssid}, ts)
            if w.get('locked') is not True:              # absent != unlocked; require explicit clear/None handled below
                if w.get('locked') is False:
                    self._fire('WPS-003', subj, '%s: PIN method offered AND AP not locked — brute-forceable' % name,
                               {'bssid': bssid}, ts)
        if w.get('configured') is False:
            self._fire('WPS-004', subj, '%s: WPS state Not Configured — out-of-box enrollment open' % name,
                       {'bssid': bssid}, ts)
        if not w['version2']:
            self._fire('WPS-005', subj, '%s: WSC 1.0 (no Version2 subelement) — no mandatory PIN lockout' % name,
                       {'bssid': bssid}, ts)
        # Weak / MAC-derived firmware family screen (a hint, carries its caveat).
        blob = ' '.join(filter(None, [w.get('manuf'), w.get('model'), w.get('devname')]))
        for rx, note in _WEAK_FAMILIES + self.cfg.vuln:
            if blob and rx.search(blob):
                self._fire('WPS-006', subj, '%s: model matches a weak-nonce family — verify firmware' % name,
                           {'bssid': bssid, 'family_note': note,
                            'note': 'screening match on the model string; confirm against current firmware'}, ts)
                break
        for rx, note in _MAC_PIN_FAMILIES:
            if blob and rx.search(blob):
                self._fire('WPS-007', subj, '%s: family with BSSID-derived factory PIN — confirm PIN was changed' % name,
                           {'bssid': bssid, 'family_note': note}, ts)
                break
        if w.get('selected_registrar'):
            self._fire('WPS-008', subj, '%s: a registrar is active now (enrollment window open)' % name,
                       {'bssid': bssid}, ts)
        if w.get('uuid_e') and bssid:
            tail = bytes(int(x, 16) for x in bssid.split(':'))
            if w['uuid_e'][-6:] == tail:
                self._fire('WPS-009', subj, '%s: UUID-E embeds the BSSID (fingerprint/PIN-recovery aid)' % name,
                           {'bssid': bssid}, ts)
        if w.get('serial'):
            self._fire('WPS-010', subj, '%s: serial number disclosed in beacon' % name,
                       {'bssid': bssid, 'disclosed': 'serial'}, ts)
        # Good-posture inventory records.
        if self.cfg['report_good_posture']:
            if w['pushbutton'] and not w['pin_method']:
                self._fire('WPS-011', subj, '%s: pushbutton-only WPS (good posture)' % name, {'bssid': bssid}, ts)
            if w.get('locked') is True:
                self._fire('WPS-012', subj, '%s: WPS locked (good posture)' % name, {'bssid': bssid}, ts)

    # ---- live sessions (WPS-020..027) -----------------------------------
    def _on_session(self, d, res, ts):
        code, w = res
        sta = d['sta']
        bssid = d.get('bssid')
        if not sta or L._is_group(sta):
            return
        s = self.sessions.get(sta)
        if s is None:
            s = {'bssid': bssid, 'attempts': 0, 'nacks': 0, 'auth_fail': 0,
                 'm1_m3': 0, 'm4': 0, 'done': False, 'first': ts,
                 'bf': RateWindow(self.cfg['brute_force_window_s']),
                 'nf': RateWindow(self.cfg['nack_flood_window_s']),
                 'announced': False, 'protected': False}
            self.sessions[sta] = s
        else:
            self.sessions.move_to_end(sta)
        # Promote / evict (probation vs protected via a simple 2-tier cap).
        cap = self.cfg['probation_max'] + self.cfg['protected_max']
        while len(self.sessions) > cap:
            self.sessions.popitem(last=False)
            self.evictions += 1

        msg = MSG.get(w['msg_type']) if w and w.get('msg_type') is not None else None
        if not s['announced']:
            s['announced'] = True
            self._fire('WPS-020', sta, '%s: a WPS enrollment session was observed' % sta,
                       {'station': sta, 'bssid': bssid, 'randomized': L.is_locally_administered(sta)}, ts)

        if msg in ('M1', 'M2', 'M3'):
            if msg == 'M1':
                s['attempts'] += 1
                n = s['bf'].add(ts)
            s['m1_m3'] += 1
        elif msg == 'M4':
            s['m4'] += 1
        elif msg == 'NACK':
            s['nacks'] += 1
            s['bf'].add(ts)
            nf = self._bss_nack(bssid, ts)
            if nf >= self.cfg['nack_flood_threshold']:
                self._fire('WPS-022', bssid or sta, '%s: WPS NACK flood on the BSS' % (bssid or sta),
                           {'bssid': bssid, 'nacks_in_window': nf}, ts)
        elif msg == 'DONE':
            s['done'] = True
        if code == 4:                                # EAP-Failure
            s['auth_fail'] += 1
            if s['auth_fail'] >= self.cfg['auth_failure_burst']:
                self._fire('WPS-024', sta, '%s: burst of WPS authentication failures' % sta,
                           {'station': sta, 'auth_failures': s['auth_fail']}, ts)
        if code == 3 and s.get('m4'):                # EAP-Success after key exchange
            self._enrollment_done(sta, s, ts)
        if msg == 'DONE':
            self._enrollment_done(sta, s, ts)

        # Online brute force: high attempt rate AND NACKs dominating.
        attempts_w = len(s['bf'].dq)
        if attempts_w >= self.cfg['brute_force_attempts'] and s['nacks'] >= max(1, s['attempts'] // 2):
            self._fire('WPS-021', sta, '%s: WPS online brute force in progress' % sta,
                       {'station': sta, 'bssid': bssid, 'attempts_in_window': attempts_w,
                        'nacks_in_window': s['nacks'],
                        'randomized': L.is_locally_administered(sta)}, ts)
        # Offline nonce harvest: repeated M1-M3 abandoned before M4.
        if s['m1_m3'] >= self.cfg['nonce_harvest_cycles'] * 3 and s['m4'] == 0:
            self._fire('WPS-023', sta, '%s: WPS nonce harvest (M1-M3 abandoned before M4)' % sta,
                       {'station': sta, 'bssid': bssid, 'm1_m3': s['m1_m3'], 'm4': 0}, ts)

    def _bss_nack(self, bssid, ts):
        """BSS-keyed NACK window so an attacker rotating source MACs is caught."""
        w = getattr(self, '_nack_by_bss', None)
        if w is None:
            w = self._nack_by_bss = {}
        rw = w.get(bssid)
        if rw is None:
            rw = w[bssid] = RateWindow(self.cfg['nack_flood_window_s'])
        return rw.add(ts)

    def _enrollment_done(self, sta, s, ts):
        if s.get('done_fired'):
            return
        s['done_fired'] = True
        self._fire('WPS-026', sta, '%s: WPS enrollment completed (station now holds the key)' % sta,
                   {'station': sta, 'bssid': s['bssid']}, ts)
        if self.cfg.known and sta not in self.cfg.known:
            self._fire('WPS-025', sta, '%s: enrollment from a station not in known_enrollees' % sta,
                       {'station': sta, 'bssid': s['bssid']}, ts)

    def final_report(self):
        if self.evictions:
            self._fire('WPS-027', 'session_table',
                       'WPS session table under eviction pressure (%d evictions)' % self.evictions,
                       {'evictions': self.evictions}, time.time())


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
    sniff(iface=iface, store=False, monitor=True,
          prn=lambda p: watch.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time()))


def run_replay(path, watch):
    from scapy.all import PcapReader
    with PcapReader(path) as pr:
        for p in pr:
            watch.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time())
    watch.final_report()


def main(argv=None):
    ap = argparse.ArgumentParser(prog='wpswatch',
                                 description='Passive WPS / Wi-Fi Simple Config posture + attack detector (detection-only).')
    ap.add_argument('-i', '--iface', help='live monitor-mode interface')
    ap.add_argument('--replay', help='replay a radiotap pcap instead')
    ap.add_argument('-c', '--config', help='JSON config')
    ap.add_argument('-o', '--jsonl', help="JSON-lines output ('-' = stdout)")
    ap.add_argument('--enrich', help='inventory CSV: mac,name')
    ap.add_argument('--echo', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--list-findings', action='store_true')
    ap.add_argument('--crack', action='store_true',
                    help='documented no-op: wpswatch derives no PINs and recovers no nonces')
    ap.add_argument('--version', action='store_true')
    args = ap.parse_args(argv)

    if args.version:
        print('%s %s' % (MODULE, VERSION)); return 0
    if args.crack:
        sys.stderr.write('wpswatch is detection-only: no PIN derivation, no nonce recovery, no enrollment.\n')
        return 0
    if args.list_findings:
        for c in sorted(CODES):
            sev, name = CODES[c]
            print('%s  %-8s %s' % (c, sev, name))
        return 0
    if args.self_test:
        import wpswatch_selftest
        return wpswatch_selftest.run(verbose=True)

    cfg = Config.load(args.config) if args.config else Config()
    inv = L.load_inventory(args.enrich or cfg['inventory_csv'])
    out_fh = sys.stdout if args.jsonl == '-' else (open(args.jsonl, 'a') if args.jsonl else None)
    watch = WpsWatch(cfg, emit=make_emitter(out_fh, args.echo or not args.jsonl), inventory=inv)

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
    sys.stderr.write('wpswatch: %d frames, findings %s\n' % (watch.frames, dict(watch.stats)))
    if out_fh and out_fh is not sys.stdout:
        out_fh.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
