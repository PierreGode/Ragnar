#!/usr/bin/env python3
"""wifiwatch.py — passive 802.11 attack monitor (Ragnar).

Passive-only (RX-only) wireless IDS: it never transmits — no probes, no assoc,
no deauth. It sniffs 802.11 management frames (and EAPOL data frames) in monitor
mode and flags:
  * deauth/disassoc floods, beacon (fake-AP) floods, evil twins, KARMA/MANA;
  * WPA client/handshake attacks — a PMKID-bearing EAPOL M1 (clientless harvest)
    and a full 4-way handshake right after a deauth (deauth-and-capture);
  * WPA3 downgrade — a transition-mode AP offering SAE+PSK together, or a known
    WPA3 SSID reappearing WPA2-PSK-only (an evil twin stripping WPA3);
  * PNL leak — a client broadcasting its saved-network list in directed probes,
    the input an evil-twin/KARMA rig needs.

The 802.11 + radiotap parsing is raw-byte (no Scapy dissectors), so `--self-test`
and `--replay` of a pcap run with no radio and the self-test needs no Scapy at
all. Scapy is used purely as the live-capture front-end. Detectors key off each
frame's *capture* timestamp (not wall clock), so replay timing matches the
original capture. See docs/wifiwatch.md.
"""

import argparse
import json
import os
import struct
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

MODULE = 'wifiwatch'
SEV_RANK = {'info': 0, 'warning': 1, 'critical': 2}

# ===========================================================================
# Radiotap (raw) — extract channel frequency + signal
# ===========================================================================
# bit -> (align, size) for the standard low fields (enough to reach Channel/dBm).
_RT_FIELDS = {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2), 5: (1, 1),
              6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (2, 2), 10: (1, 1), 11: (1, 1),
              12: (1, 1), 13: (1, 1), 14: (2, 2)}


def _u16(b, i):
    return b[i] | (b[i + 1] << 8)


def _u32(b, i):
    return struct.unpack_from('<I', b, i)[0]


def _be16(b, i):
    """Big-endian u16 — EAPOL-Key fields are network byte order, unlike the
    little-endian radiotap/802.11 fields _u16 reads."""
    return (b[i] << 8) | b[i + 1]


def _s8(v):
    return v - 256 if v > 127 else v


def parse_radiotap(buf):
    """Return (freq_mhz, signal_dbm, header_len). Best-effort; unknown high
    fields are fine because Channel (bit 3) and dBm signal (bit 5) precede them."""
    if len(buf) < 8 or buf[0] != 0:
        return None, None, 0
    hdrlen = _u16(buf, 2)
    if hdrlen < 8 or hdrlen > len(buf):
        return None, None, 0
    present = _u32(buf, 4)
    off = 8
    p = present
    while p & 0x80000000 and off + 4 <= hdrlen:      # presence extensions
        p = _u32(buf, off)
        off += 4
    freq = signal = None
    pos = off
    for bit in range(15):
        if not (present & (1 << bit)):
            continue
        a, sz = _RT_FIELDS[bit]
        pos = (pos + a - 1) & ~(a - 1)                # align from radiotap start
        if pos + sz > hdrlen:
            break
        if bit == 3:
            freq = _u16(buf, pos)
        elif bit == 5:
            signal = _s8(buf[pos])
        pos += sz
    return freq, signal, hdrlen


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


def channel_of(freq):
    if freq is None:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if band_of(freq) == '6':
        return (freq - 5950) // 5
    if freq >= 5000:
        return (freq - 5000) // 5
    return None


# ===========================================================================
# 802.11 management frame (raw)
# ===========================================================================
BROADCAST = 'ff:ff:ff:ff:ff:ff'


def _mac(b, i):
    return ':'.join('%02x' % x for x in b[i:i + 6])


def is_locally_administered(mac):
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


def _parse_ies(b, i, out):
    """Walk tagged params from offset i; fill SSID and RSN (MFP/AKM)."""
    n = len(b)
    while i + 2 <= n:
        eid = b[i]
        elen = b[i + 1]
        i += 2
        if i + elen > n:
            break
        val = b[i:i + elen]
        if eid == 0:                                 # SSID
            try:
                out['ssid'] = val.decode('utf-8', 'replace') if val else ''
            except Exception:
                out['ssid'] = ''
        elif eid == 48 and elen >= 8:                # RSN
            out['rsn'] = _parse_rsn(val)
        i += elen


def _parse_rsn(v):
    """Extract AKM suites + PMF (MFPC/MFPR) from an RSN element body."""
    try:
        i = 2 + 4                                    # version + group cipher
        pcnt = _u16(v, i); i += 2 + 4 * pcnt         # pairwise ciphers
        acnt = _u16(v, i); i += 2
        # An AKM suite is OUI(3) + type(1); the selector is the *last* byte
        # (00-0F-AC <type>), not the first — reading it little-endian & 0xff
        # would yield the OUI byte 0x00 for every suite.
        akms = [v[i + 4 * k + 3] for k in range(acnt) if i + 4 * k + 3 < len(v)]
        i += 4 * acnt
        caps = _u16(v, i) if i + 2 <= len(v) else 0
        return {'akms': akms, 'mfpc': bool(caps & 0x80), 'mfpr': bool(caps & 0x40)}
    except Exception:
        return {'akms': [], 'mfpc': False, 'mfpr': False}


def _parse_eapol(body):
    """Given the 802.11 data-frame payload (after the MAC header), return the
    4-way-handshake message info if it is an EAPOL-Key frame, else None.

    Layout: LLC/SNAP (AA AA 03 00 00 00) + ethertype 0x888E, then EAPOL header
    (version, type, length), then — for type 3, EAPOL-Key — the Key Descriptor.
    The message number falls out of the Key Information bits, and M1 may carry a
    PMKID KDE in its key data (the clientless-harvest handle)."""
    if len(body) < 8 or body[:6] != b'\xaa\xaa\x03\x00\x00\x00':
        return None
    if body[6:8] != b'\x88\x8e':                     # not EAPOL
        return None
    e = body[8:]
    if len(e) < 4 or e[1] != 3:                      # EAPOL type 3 = EAPOL-Key
        return None
    k = e[4:]                                        # Key Descriptor
    if len(k) < 3:
        return None
    info = _be16(k, 1)                               # Key Information (network order)
    mic = bool(info & 0x0100)
    secure = bool(info & 0x0200)
    ack = bool(info & 0x0080)
    install = bool(info & 0x0040)
    pairwise = bool(info & 0x0008)
    if ack and not mic:
        msg = 1
    elif mic and not ack and not secure:
        msg = 2
    elif ack and mic and secure:
        msg = 3
    elif mic and not ack and secure:
        msg = 4
    else:
        msg = 0
    pmkid = False
    # Key Data Length sits at a fixed offset; M1's key data may hold a PMKID KDE
    # (DD <len> 00-0F-AC 04 <16-byte PMKID>).
    if len(k) >= 97:
        kdl = _be16(k, 93)                           # Key Data Length (network order)
        kd = k[95:95 + kdl]
        i = 0
        while i + 6 <= len(kd):
            if kd[i] == 0xdd and kd[i + 2:i + 5] == b'\x00\x0f\xac' and kd[i + 5] == 0x04:
                pmkid = True
                break
            i += 2 + (kd[i + 1] if i + 1 < len(kd) else 0)
    return {'msg': msg, 'pmkid': pmkid, 'pairwise': pairwise}


def _data_hdrlen(fc0, fc1):
    """MAC-header length for a data frame: 24 base, +6 for a 4-address (WDS)
    frame, +2 for the QoS control field on a QoS-data subtype."""
    to_ds = bool(fc1 & 0x01)
    from_ds = bool(fc1 & 0x02)
    subtype = (fc0 >> 4) & 0xf
    n = 24
    if to_ds and from_ds:
        n += 6
    if subtype & 0x08:                               # QoS data
        n += 2
    return n, to_ds, from_ds


def parse_dot11(buf):
    """Parse an 802.11 management or data frame (no radiotap). Returns a dict or
    None. Management frames carry SSID/RSN/reason; data frames are parsed only
    far enough to surface an EAPOL 4-way-handshake message."""
    if len(buf) < 24:
        return None
    fc0, fc1 = buf[0], buf[1]
    ftype = (fc0 >> 2) & 0x3
    subtype = (fc0 >> 4) & 0xf
    if ftype == 0:                                   # management
        out = {'ftype': 0, 'subtype': subtype, 'protected': bool(fc1 & 0x40),
               'da': _mac(buf, 4), 'sa': _mac(buf, 10), 'bssid': _mac(buf, 16),
               'ssid': None, 'reason': None, 'rsn': None, 'eapol': None}
        body = buf[24:]
        if subtype in (8, 5):                        # beacon / probe-resp
            _parse_ies(body, 12, out)                # skip fixed params
        elif subtype == 4:                           # probe-req
            _parse_ies(body, 0, out)
        elif subtype in (10, 12):                    # disassoc / deauth
            if len(body) >= 2:
                out['reason'] = _u16(body, 0)
        return out
    if ftype == 2:                                   # data — EAPOL only
        if subtype & 0x04 and not (subtype & 0x08):  # Null data: no payload
            return None
        hdrlen, to_ds, from_ds = _data_hdrlen(fc0, fc1)
        if len(buf) < hdrlen:
            return None
        a1, a2, a3 = _mac(buf, 4), _mac(buf, 10), _mac(buf, 16)
        # Resolve station/BSSID/direction from the DS bits.
        if to_ds and not from_ds:                    # STA -> AP
            bssid, sa, da, to_ap = a1, a2, a3, True
        elif from_ds and not to_ds:                  # AP -> STA
            bssid, sa, da, to_ap = a2, a3, a1, False
        else:                                        # IBSS / WDS
            bssid, sa, da, to_ap = a3, a2, a1, None
        out = {'ftype': 2, 'subtype': subtype, 'protected': bool(fc1 & 0x40),
               'da': da, 'sa': sa, 'bssid': bssid, 'to_ap': to_ap,
               'ssid': None, 'reason': None, 'rsn': None, 'eapol': None}
        if not out['protected']:                     # 4-way handshake is unencrypted
            out['eapol'] = _parse_eapol(buf[hdrlen:])
        return out
    return None                                      # control frames ignored


def parse_frame(raw):
    """Radiotap + 802.11 → normalized event dict, or None."""
    freq, signal, hdrlen = parse_radiotap(raw)
    d11 = parse_dot11(raw[hdrlen:]) if hdrlen else parse_dot11(raw)
    if d11 is None:
        return None
    d11['freq'] = freq
    d11['signal'] = signal
    d11['band'] = band_of(freq)
    d11['channel'] = channel_of(freq)
    return d11


# ===========================================================================
# Detector engine
# ===========================================================================
DEFAULTS = {
    'deauth_broadcast_burst': 6, 'deauth_broadcast_window': 5.0,
    'deauth_per_bssid_burst': 25, 'deauth_per_bssid_window': 5.0,
    'deauth_per_target_burst': 12, 'deauth_per_target_window': 5.0,
    'beacon_new_bssid_burst': 18, 'beacon_window': 8.0,
    'beacon_warmup_sec': 30.0, 'beacon_la_ratio': 0.5,
    'karma_ssid_min': 5,
    # -- client / handshake protection (gap: WPA harvest, downgrade, PNL leak) --
    'handshake_deauth_window': 10.0,  # deauth->handshake correlation window (s)
    'handshake_msg_min': 2,           # distinct EAPOL msgs after a deauth to flag
    'pnl_min_ssids': 4,               # distinct SSIDs a client leaks before flagging
    'pnl_window': 300.0,              # PNL leak accounting window (s)
    'refractory_sec': 5.0,
    'allowlist': {},                                 # ssid -> [bssids]
}
SUBTYPE_NAME = {4: 'probe_req', 5: 'probe_resp', 8: 'beacon', 10: 'disassoc',
                12: 'deauth'}

# RSN AKM suite selectors (last byte of the 00-0F-AC OUI+type).
AKM_PSK = {2, 6}                          # WPA2-Personal (PSK, PSK-SHA256)
AKM_SAE = {8, 9, 24}                      # WPA3-Personal (SAE, FT-SAE, SAE-EXT)
AKM_ENTERPRISE = {1, 3, 5, 11, 12, 13}   # 802.1X variants


class WifiWatch:
    def __init__(self, config=None, emit=None):
        c = dict(DEFAULTS)
        c.update(config or {})
        self.cfg = c
        self.emit = emit or (lambda ev: None)
        self.allow = {s.lower(): {b.lower() for b in v}
                      for s, v in (c.get('allowlist') or {}).items()}
        self.start_ts = None
        self.census = set()                          # BSSIDs seen during warmup
        self.first_seen = {}                         # bssid -> ts
        self._new_bssids = deque()                   # (ts, bssid) post-warmup
        self._deauth_bcast = deque()                 # ts
        self._deauth_bssid = defaultdict(deque)      # bssid -> ts
        self._deauth_target = defaultdict(deque)     # dst -> ts
        self._ap_ssids = defaultdict(set)            # bssid -> ssids answered
        self._beaconed = defaultdict(set)            # bssid -> ssids beaconed
        self._probe_reqs = deque()                   # (ts, ssid) directed probes
        self._refractory = {}                        # (detector, scope) -> ts
        # client / handshake protection state
        self._recent_deauth = {}                     # station -> last deauth ts
        self._handshake = defaultdict(dict)          # station -> {msg: ts}
        self._ssid_akm = defaultdict(set)            # ssid -> AKM suites ever seen
        self._pnl = defaultdict(lambda: deque())     # station -> deque((ts, ssid))
        self.frames = 0
        self.stats = defaultdict(int)

    # -- helpers -------------------------------------------------------------
    def _warm(self, ts):
        return (ts - self.start_ts) < self.cfg['beacon_warmup_sec']

    @staticmethod
    def _trim(dq, ts, window, keyed=False):
        while dq and ts - (dq[0][0] if keyed else dq[0]) > window:
            dq.popleft()

    def _fire(self, detector, scope, sev, ev_fields, ts):
        """Emit unless within the per-scope refractory window (every frame is
        still counted; only the alert is rate-limited)."""
        key = (detector, scope)
        last = self._refractory.get(key)
        if last is not None and ts - last < self.cfg['refractory_sec']:
            return
        self._refractory[key] = ts
        ev = {'ts': datetime.fromtimestamp(ts, timezone.utc).isoformat(),
              'module': MODULE, 'detector': detector, 'severity': sev}
        ev.update(ev_fields)
        self.stats[detector] += 1
        self.emit(ev)

    # -- main path (live, replay, and self-test all call this) ---------------
    def handle(self, raw, ts=None, freq=None):
        f = parse_frame(raw)
        if f is None:
            return
        if ts is None:
            ts = time.time()
        if self.start_ts is None:
            self.start_ts = ts
        self.frames += 1
        if freq is not None and f['freq'] is None:
            f['freq'] = freq
            f['band'] = band_of(freq)
            f['channel'] = channel_of(freq)
        if f.get('ftype') == 2:                      # data frame → EAPOL only
            if f.get('eapol'):
                self._on_eapol(f, ts)
            return
        st = f['subtype']
        if st == 8:
            self._on_beacon(f, ts)
        elif st == 5:
            self._on_probe_resp(f, ts)
        elif st == 4:
            self._on_probe_req(f, ts)
        elif st in (10, 12):
            self._on_deauth(f, ts)

    # -- beacon flood + evil twin -------------------------------------------
    def _on_beacon(self, f, ts):
        bssid = f['bssid']
        ssid = f.get('ssid')
        if ssid:
            self._beaconed[bssid].add(ssid)
            self._ap_ssids[bssid].add(ssid)
        if bssid not in self.first_seen:
            self.first_seen[bssid] = ts
            if self._warm(ts):
                self.census.add(bssid)
            else:
                self._new_bssids.append((ts, bssid))
        self._eval_beacon_flood(f, ts)
        self._eval_evil_twin(f, ts, ssid, bssid)
        self._eval_downgrade(f, ts, ssid, bssid)

    def _eval_beacon_flood(self, f, ts):
        self._trim(self._new_bssids, ts, self.cfg['beacon_window'], keyed=True)
        burst = [b for _t, b in self._new_bssids]
        if len(set(burst)) < self.cfg['beacon_new_bssid_burst']:
            return
        uniq = set(burst)
        la = sum(1 for b in uniq if is_locally_administered(b))
        la_ratio = la / len(uniq)
        sev = 'critical' if la_ratio >= self.cfg['beacon_la_ratio'] else 'warning'
        self._fire('beacon_flood', 'segment', sev, {
            'band': f['band'], 'channel': f['channel'], 'bssid': f['bssid'],
            'ssid': f.get('ssid'), 'signal_dbm': f['signal'],
            'summary': '%d new BSSIDs in %.0fs (LA ratio %.0f%%) — fake-AP storm'
                       % (len(uniq), self.cfg['beacon_window'], la_ratio * 100),
            'detail': {'new_bssids': len(uniq), 'la_bssids': la,
                       'la_ratio': round(la_ratio, 2),
                       'window_sec': self.cfg['beacon_window']}}, ts)

    def _eval_evil_twin(self, f, ts, ssid, bssid):
        if not ssid:
            return
        trusted = self.allow.get(ssid.lower())
        if trusted is not None:
            if bssid not in trusted:
                self._fire('evil_twin', ssid, 'critical', {
                    'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                    'ssid': ssid, 'signal_dbm': f['signal'],
                    'summary': "SSID '%s' beaconed from un-allowlisted BSSID %s "
                               '(evil twin)' % (ssid, bssid),
                    'detail': {'reason': 'unauthorized_bssid',
                               'trusted': sorted(trusted)}}, ts)
        else:
            aps = {b for b, s in self._ap_ssids.items() if ssid in s}
            if len(aps) >= 2:
                self._fire('evil_twin', ssid, 'info', {
                    'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                    'ssid': ssid, 'signal_dbm': f['signal'],
                    'summary': "SSID '%s' seen from %d BSSIDs (unlisted; allowlist "
                               'it to confirm)' % (ssid, len(aps)),
                    'detail': {'reason': 'multi_bssid_unlisted',
                               'bssids': sorted(aps)}}, ts)

    # -- KARMA / MANA --------------------------------------------------------
    def _on_probe_resp(self, f, ts):
        bssid = f['bssid']
        ssid = f.get('ssid')
        if ssid:
            self._ap_ssids[bssid].add(ssid)
        n = len(self._ap_ssids[bssid])
        if n >= self.cfg['karma_ssid_min']:
            self._fire('karma_mana', bssid, 'critical', {
                'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                'ssid': ssid, 'signal_dbm': f['signal'],
                'summary': '%s answered %d different SSIDs — KARMA/MANA rogue AP'
                           % (bssid, n),
                'detail': {'ssid_count': n,
                           'ssids': sorted(self._ap_ssids[bssid])[:12]}}, ts)
        self._eval_evil_twin(f, ts, ssid, bssid)
        self._eval_downgrade(f, ts, ssid, bssid)

    def _on_probe_req(self, f, ts):
        ssid = f.get('ssid')
        if ssid:                                     # directed probe (has SSID)
            self._probe_reqs.append((ts, ssid))
            self._trim(self._probe_reqs, ts, 30.0, keyed=True)
            self._eval_pnl_leak(f, ts, ssid)

    # -- PNL leak: a client broadcasting its saved-network list ---------------
    def _eval_pnl_leak(self, f, ts, ssid):
        """A device that directs probe requests at named SSIDs is broadcasting
        its Preferred Network List — the exact input an evil-twin/KARMA rig
        needs. Track distinct leaked SSIDs per client and flag once it exposes
        enough of its PNL to be worth impersonating."""
        sta = f['sa']
        if sta == BROADCAST or is_locally_administered(sta):
            return                                   # randomized MAC — not a stable device
        dq = self._pnl[sta]
        if not any(s == ssid for _t, s in dq):
            dq.append((ts, ssid))
        while dq and ts - dq[0][0] > self.cfg['pnl_window']:
            dq.popleft()
        ssids = sorted({s for _t, s in dq})
        if len(ssids) >= self.cfg['pnl_min_ssids']:
            self._fire('pnl_leak', sta, 'warning', {
                'band': f['band'], 'channel': f['channel'], 'bssid': None,
                'station': sta, 'ssid': ssid, 'signal_dbm': f['signal'],
                'summary': '%s is leaking its saved-network list: %d SSIDs (%s) — '
                           'evil-twin bait' % (sta, len(ssids),
                           ', '.join(ssids[:6]) + ('…' if len(ssids) > 6 else '')),
                'detail': {'station': sta, 'ssid_count': len(ssids),
                           'ssids': ssids[:16],
                           'window_sec': self.cfg['pnl_window']}}, ts)

    # -- WPA3 downgrade / transition-mode exposure ---------------------------
    def _eval_downgrade(self, f, ts, ssid, bssid):
        """Two WPA3-era exposures, both read from the advertised RSN AKM suites:

        * transition mode — one BSSID offering SAE *and* PSK together. A WPA3
          client can be steered down to WPA2-PSK, whose handshake cracks offline.
          Informational: it is a property of the real AP's config.
        * active downgrade — an SSID we have seen offer SAE now appearing from a
          BSSID that offers *only* PSK (no SAE). That is an evil twin stripping
          WPA3, i.e. a live downgrade attack. Critical."""
        rsn = f.get('rsn')
        if not ssid or not rsn:
            return
        akms = set(rsn.get('akms') or [])
        if not akms:
            return
        has_sae = bool(akms & AKM_SAE)
        has_psk = bool(akms & AKM_PSK)
        self._ssid_akm[ssid] |= akms
        if has_sae and has_psk:
            self._fire('wpa3_transition', ssid, 'info', {
                'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                'ssid': ssid, 'signal_dbm': f['signal'],
                'summary': "SSID '%s' (%s) offers WPA3-SAE and WPA2-PSK together — "
                           'downgradeable transition mode' % (ssid, bssid),
                'detail': {'akms': sorted(akms), 'mfpr': rsn.get('mfpr'),
                           'reason': 'transition_mode'}}, ts)
        elif has_psk and not has_sae and (self._ssid_akm[ssid] & AKM_SAE):
            # This SSID has been seen as SAE elsewhere but this BSSID is PSK-only.
            self._fire('wpa_downgrade', ssid, 'critical', {
                'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                'ssid': ssid, 'signal_dbm': f['signal'],
                'summary': "SSID '%s' is WPA3-SAE elsewhere but %s offers WPA2-PSK "
                           'only — WPA3-strip downgrade / evil twin' % (ssid, bssid),
                'detail': {'akms': sorted(akms), 'reason': 'wpa3_stripped'}}, ts)

    # -- WPA handshake / PMKID harvest ---------------------------------------
    def _on_eapol(self, f, ts):
        """4-way-handshake exposure. Passively we cannot see a silent sniffer,
        but we can see the two things that put a crackable handshake on the air:
        an M1 carrying a PMKID (clientless-harvest handle), and a full handshake
        that follows a deauth to the same client (deauth-and-capture)."""
        eap = f['eapol']
        msg = eap.get('msg')
        # The station is the non-AP side of the exchange.
        sta = f['sa'] if f.get('to_ap') else f['da']
        bssid = f['bssid']
        if msg == 1 and eap.get('pmkid'):
            self._fire('pmkid_harvest', bssid, 'critical', {
                'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                'station': sta, 'ssid': None, 'signal_dbm': f['signal'],
                'summary': '%s sent an EAPOL M1 with a PMKID — WPA/WPA2 PMKID is '
                           'harvestable (offline-crackable) from %s' % (bssid, bssid),
                'detail': {'msg': 1, 'pmkid': True, 'station': sta}}, ts)
        if not msg:
            return
        hs = self._handshake[sta]
        hs[msg] = ts
        for m in list(hs):                           # forget a stale, partial handshake
            if ts - hs[m] > self.cfg['handshake_deauth_window']:
                del hs[m]
        deauth_ts = self._recent_deauth.get(sta)
        if (deauth_ts is not None
                and ts - deauth_ts <= self.cfg['handshake_deauth_window']
                and len(hs) >= self.cfg['handshake_msg_min']):
            self._fire('handshake_harvest', sta, 'critical', {
                'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                'station': sta, 'ssid': None, 'signal_dbm': f['signal'],
                'summary': '%s was deauthed then completed %d/4 EAPOL messages — '
                           'forced-reconnect handshake capture' % (sta, len(hs)),
                'detail': {'station': sta, 'msgs': sorted(hs),
                           'deauth_lead_s': round(ts - deauth_ts, 2)}}, ts)

    # -- deauth / disassoc flood --------------------------------------------
    def _on_deauth(self, f, ts):
        kind = SUBTYPE_NAME[f['subtype']]
        bssid = f['bssid']
        dst = f['da']
        protected = f['protected']
        reason = f.get('reason')
        # Remember a client that was just deauthed — a 4-way handshake arriving
        # for it shortly after is the classic deauth-and-capture harvest.
        if dst != BROADCAST:
            self._recent_deauth[dst] = ts
        common = {'band': f['band'], 'channel': f['channel'], 'bssid': bssid,
                  'ssid': None, 'signal_dbm': f['signal']}
        if dst == BROADCAST:
            dq = self._deauth_bcast
            dq.append(ts)
            self._trim(dq, ts, self.cfg['deauth_broadcast_window'])
            if len(dq) >= self.cfg['deauth_broadcast_burst']:
                self._fire('deauth_flood', 'broadcast:' + bssid, 'critical', dict(
                    common, summary='Broadcast %s flood from %s: %d frames/%.0fs '
                    'to all clients (reason %s)' % (kind, bssid, len(dq),
                    self.cfg['deauth_broadcast_window'], reason),
                    detail={'kind': kind, 'scope': 'broadcast', 'count': len(dq),
                            'window_sec': self.cfg['deauth_broadcast_window'],
                            'reason': reason, 'protected': protected}), ts)
        else:
            dq = self._deauth_target[dst]
            dq.append(ts)
            self._trim(dq, ts, self.cfg['deauth_per_target_window'])
            if len(dq) >= self.cfg['deauth_per_target_burst']:
                self._fire('deauth_flood', 'target:' + dst, 'warning', dict(
                    common, summary='Directed %s flood at %s from %s: %d frames/%.0fs'
                    % (kind, dst, bssid, len(dq), self.cfg['deauth_per_target_window']),
                    detail={'kind': kind, 'scope': 'targeted', 'target': dst,
                            'count': len(dq), 'reason': reason,
                            'protected': protected}), ts)
        # per-BSSID (deauth + disassoc combined)
        bq = self._deauth_bssid[bssid]
        bq.append(ts)
        self._trim(bq, ts, self.cfg['deauth_per_bssid_window'])
        if len(bq) >= self.cfg['deauth_per_bssid_burst']:
            self._fire('deauth_flood', 'bssid:' + bssid, 'critical', dict(
                common, summary='%s: %d deauth/disassoc frames/%.0fs — DoS'
                % (bssid, len(bq), self.cfg['deauth_per_bssid_window']),
                detail={'kind': kind, 'scope': 'per_bssid', 'count': len(bq),
                        'reason': reason, 'protected': protected}), ts)


# ===========================================================================
# Live capture / replay (scapy, lazy)
# ===========================================================================
def run_replay(path, watch, replay_freq=None):
    from scapy.all import PcapReader
    with PcapReader(path) as pr:
        for pkt in pr:
            raw = bytes(pkt)
            ts = float(getattr(pkt, 'time', 0)) or time.time()
            watch.handle(raw, ts=ts, freq=replay_freq)


def run_live(iface, watch, hopper=None):
    from scapy.all import sniff

    def cb(pkt):
        watch.handle(bytes(pkt), ts=float(getattr(pkt, 'time', 0)) or time.time())
    sys.stderr.write('wifiwatch: passive on %s (monitor) — Ctrl-C to stop\n' % iface)
    if hopper:
        hopper.start()
    sniff(iface=iface, prn=cb, store=False)


# ===========================================================================
# Output
# ===========================================================================
def make_emitter(out_fh, echo, min_sev, pushover=None):
    floor = SEV_RANK.get(min_sev, 1)

    def emit(ev):
        line = json.dumps(ev)
        if out_fh:
            out_fh.write(line + '\n')
            out_fh.flush()
        if echo:
            sys.stderr.write('  [%s] %s/%s %s\n' % (ev['severity'], ev['detector'],
                             ev.get('bssid') or '', ev.get('summary', '')))
        if pushover and SEV_RANK.get(ev['severity'], 0) >= floor:
            pushover(ev)
    return emit


# ===========================================================================
# CLI
# ===========================================================================
def _load_config(path):
    if not path:
        return {}
    with open(path) as f:
        return json.load(f)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='wifiwatch',
                                 description='Passive 802.11 attack monitor (RX-only).')
    ap.add_argument('-i', '--iface', help='monitor-mode capture interface')
    ap.add_argument('--replay', help='replay a pcap instead of live capture')
    ap.add_argument('--replay-freq', type=int, help='force a channel freq (MHz) for replay')
    ap.add_argument('-c', '--config', help='JSON config path')
    ap.add_argument('--jsonl', '-o', help="JSON-lines output path ('-' = stdout)")
    ap.add_argument('--echo', action='store_true', help='echo events to stderr')
    ap.add_argument('--min-alert-severity', default='warning',
                    choices=['info', 'warning', 'critical'])
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args(argv)

    if args.self_test:
        import wifiwatch_selftest
        return wifiwatch_selftest.run(verbose=True)

    cfg = _load_config(args.config)
    out_fh = None
    if args.jsonl == '-':
        out_fh = sys.stdout
    elif args.jsonl:
        os.makedirs(os.path.dirname(args.jsonl) or '.', exist_ok=True)
        out_fh = open(args.jsonl, 'a')
    emit = make_emitter(out_fh, args.echo or not args.jsonl, args.min_alert_severity)
    watch = WifiWatch(cfg, emit=emit)

    if args.replay:
        run_replay(args.replay, watch, replay_freq=args.replay_freq)
    elif args.iface:
        if os.geteuid() != 0:
            sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
            return 2
        try:
            run_live(args.iface, watch)
        except KeyboardInterrupt:
            pass
    else:
        ap.error('one of --iface, --replay or --self-test is required')
    sys.stderr.write('wifiwatch: %d frames, alerts %s\n' % (watch.frames, dict(watch.stats)))
    if out_fh and out_fh is not sys.stdout:
        out_fh.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
