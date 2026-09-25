#!/usr/bin/env python3
"""wifiwatch_selftest.py — offline self-test (no radio, no Scapy).

Builds real radiotap + 802.11 frame bytes in pure Python and drives them through
the same WifiWatch.handle() path live capture and replay use. Includes negative
controls (stable AP, sparse deauths, honest probe-responder) and a dense-boot
warmup test. Run via `python3 wifiwatch.py --self-test`.
"""

import struct
import sys

import wifiwatch as w


def _mac(s):
    return bytes(int(x, 16) for x in s.split(':'))


def radiotap(freq=2437, sig=-50):
    present = (1 << 3) | (1 << 5)                     # Channel + dBm signal
    return struct.pack('<BBHI', 0, 0, 13, present) + struct.pack('<HHb', freq, 0, sig)


def _dot11(subtype, a1, a2, a3, body=b'', protected=False):
    fc0 = (subtype << 4)                              # type 0 = management
    fc1 = 0x40 if protected else 0
    return bytes([fc0, fc1, 0, 0]) + _mac(a1) + _mac(a2) + _mac(a3) + b'\x00\x00' + body


def _ie(eid, data):
    return bytes([eid, len(data)]) + data


def beacon(bssid, ssid, freq=2437, sig=-50):
    body = b'\x00' * 8 + b'\x64\x00' + b'\x01\x00' + _ie(0, ssid.encode())
    return radiotap(freq, sig) + _dot11(8, 'ff:ff:ff:ff:ff:ff', bssid, bssid, body)


def proberesp(bssid, ssid):
    body = b'\x00' * 8 + b'\x64\x00' + b'\x01\x00' + _ie(0, ssid.encode())
    return radiotap() + _dot11(5, '00:11:22:33:44:55', bssid, bssid, body)


def probereq(ssid, src='00:11:22:33:44:55'):
    return radiotap() + _dot11(4, 'ff:ff:ff:ff:ff:ff', src,
                               'ff:ff:ff:ff:ff:ff', _ie(0, ssid.encode()))


def deauth(src, dst, reason=7, protected=False, subtype=12):
    return radiotap() + _dot11(subtype, dst, src, src, struct.pack('<H', reason), protected)


def _rsn(akm_types, mfpc=False, mfpr=False):
    """RSN element body: CCMP group+pairwise, the given AKM suites, PMF caps."""
    caps = (0x80 if mfpc else 0) | (0x40 if mfpr else 0)
    body = b'\x01\x00'                                # version
    body += b'\x00\x0f\xac\x04'                       # group cipher CCMP
    body += b'\x01\x00' + b'\x00\x0f\xac\x04'         # 1 pairwise cipher CCMP
    body += struct.pack('<H', len(akm_types))
    for t in akm_types:
        body += b'\x00\x0f\xac' + bytes([t])          # 00-0F-AC AKM suites
    body += struct.pack('<H', caps)
    return body


def beacon_rsn(bssid, ssid, akm_types, freq=2437, mfpc=False, mfpr=False):
    body = (b'\x00' * 8 + b'\x64\x00' + b'\x01\x00' + _ie(0, ssid.encode())
            + _ie(48, _rsn(akm_types, mfpc, mfpr)))
    return radiotap(freq) + _dot11(8, 'ff:ff:ff:ff:ff:ff', bssid, bssid, body)


def _data(a1, a2, a3, payload, to_ds, from_ds, qos=False, protected=False):
    subtype = 8 if qos else 0
    fc0 = (2 << 2) | (subtype << 4)                   # type 2 = data
    fc1 = (0x01 if to_ds else 0) | (0x02 if from_ds else 0) | (0x40 if protected else 0)
    hdr = bytes([fc0, fc1, 0, 0]) + _mac(a1) + _mac(a2) + _mac(a3) + b'\x00\x00'
    if qos:
        hdr += b'\x00\x00'
    return hdr


# EAPOL Key Information bits (network order).
_KI = {'mic': 0x0100, 'secure': 0x0200, 'ack': 0x0080, 'install': 0x0040,
       'pairwise': 0x0008}


def eapol(bssid, station, msg, pmkid=False, from_ap=None):
    """Build a data frame carrying EAPOL-Key message `msg` (1-4). M1/M3 flow
    AP->STA, M2/M4 STA->AP. Key Information is big-endian on the wire."""
    if from_ap is None:
        from_ap = msg in (1, 3)
    info = _KI['pairwise']
    if msg == 1:
        info |= _KI['ack']
    elif msg == 2:
        info |= _KI['mic']
    elif msg == 3:
        info |= _KI['ack'] | _KI['mic'] | _KI['secure'] | _KI['install']
    elif msg == 4:
        info |= _KI['mic'] | _KI['secure']
    kd = b''
    if pmkid:
        kd = bytes([0xdd, 0x14]) + b'\x00\x0f\xac\x04' + b'\x11' * 16   # PMKID KDE
    # Key Descriptor: type(1) info(2,BE) keylen(2) replay(8) nonce(32) iv(16)
    # rsc(8) reserved(8) mic(16) key_data_len(2,BE) key_data(N)
    k = (bytes([2]) + struct.pack('>H', info) + b'\x00\x10' + b'\x00' * 8
         + b'\x00' * 32 + b'\x00' * 16 + b'\x00' * 8 + b'\x00' * 8 + b'\x00' * 16
         + struct.pack('>H', len(kd)) + kd)
    eap = bytes([2, 3]) + struct.pack('>H', len(k)) + k                # EAPOL-Key
    payload = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e' + eap                # LLC/SNAP + EAPOL
    if from_ap:                                                       # AP -> STA
        hdr = _data(station, bssid, bssid, payload, to_ds=False, from_ds=True, qos=True)
    else:                                                            # STA -> AP
        hdr = _data(bssid, station, bssid, payload, to_ds=True, from_ds=False, qos=True)
    return radiotap() + hdr + payload


class H:
    def __init__(self, verbose):
        self.n = self.fail = 0
        self.verbose = verbose

    def ck(self, name, cond):
        self.n += 1
        if not cond:
            self.fail += 1
        if self.verbose:
            print('  [%s] %s' % ('PASS' if cond else 'FAIL', name))


def _watch(cfg=None):
    evs = []
    return w.WifiWatch(cfg or {}, emit=evs.append), evs


def _rules(evs):
    return {e['detector'] for e in evs}


def run(verbose=True):
    h = H(verbose)

    # ---- raw parse --------------------------------------------------------
    f = w.parse_frame(beacon('aa:bb:cc:dd:ee:ff', 'HomeNet'))
    h.ck('parse beacon subtype', f and f['subtype'] == 8)
    h.ck('parse beacon bssid', f and f['bssid'] == 'aa:bb:cc:dd:ee:ff')
    h.ck('parse beacon ssid', f and f['ssid'] == 'HomeNet')
    h.ck('parse radiotap freq/band/channel', f and f['band'] == '2.4' and f['channel'] == 6)
    h.ck('parse radiotap signal', f and f['signal'] == -50)
    f = w.parse_frame(deauth('aa:bb:cc:00:00:01', 'ff:ff:ff:ff:ff:ff', reason=7))
    h.ck('parse deauth subtype/reason', f and f['subtype'] == 12 and f['reason'] == 7)
    h.ck('parse deauth broadcast dst', f and f['da'] == w.BROADCAST)
    f = w.parse_frame(deauth('a', 'b', protected=True) if False else
                      deauth('aa:bb:cc:00:00:01', 'cc:cc:cc:00:00:09', protected=True))
    h.ck('parse deauth protected bit', f and f['protected'] is True)
    f = w.parse_frame(beacon('00:11:22:33:44:55', 'Net5', freq=5220))
    h.ck('parse 5GHz band/channel', f and f['band'] == '5' and f['channel'] == 44)
    f = w.parse_frame(beacon('00:11:22:33:44:55', 'Net6', freq=5975))
    h.ck('parse 6GHz band', f and f['band'] == '6')

    # ---- deauth flood -----------------------------------------------------
    wt, evs = _watch()
    for i in range(6):
        wt.handle(deauth('aa:bb:cc:00:00:01', w.BROADCAST), ts=100 + i * 0.1)
    bc = [e for e in evs if e['detector'] == 'deauth_flood']
    h.ck('broadcast deauth flood fires', bc and bc[0]['severity'] == 'critical')
    h.ck('broadcast deauth scope', bc and bc[0]['detail']['scope'] == 'broadcast')
    h.ck('broadcast deauth reason in detail', bc and bc[0]['detail']['reason'] == 7)
    wt, evs = _watch()
    for i in range(3):
        wt.handle(deauth('aa:bb:cc:00:00:01', w.BROADCAST), ts=100 + i * 0.1)
    h.ck('sparse broadcast deauth quiet', not evs)
    # targeted
    wt, evs = _watch()
    for i in range(12):
        wt.handle(deauth('aa:bb:cc:00:00:01', 'cc:cc:cc:00:00:09'), ts=200 + i * 0.1)
    tg = [e for e in evs if e['detector'] == 'deauth_flood']
    h.ck('targeted deauth flood fires (warning)', tg and tg[0]['severity'] == 'warning')
    h.ck('targeted deauth scope', tg and tg[0]['detail']['scope'] == 'targeted')
    # per-BSSID deauth+disassoc combined
    wt, evs = _watch()
    for i in range(25):
        st = 12 if i % 2 == 0 else 10                # mix deauth + disassoc
        wt.handle(deauth('aa:bb:cc:00:00:01', 'cc:cc:cc:00:%02x:09' % i, subtype=st),
                  ts=300 + i * 0.1)
    pb = [e for e in evs if e['detail'].get('scope') == 'per_bssid']
    h.ck('per-BSSID deauth+disassoc flood fires', pb and pb[0]['severity'] == 'critical')
    # protected posture carried
    wt, evs = _watch()
    for i in range(6):
        wt.handle(deauth('aa:bb:cc:00:00:01', w.BROADCAST, protected=False), ts=400 + i * 0.1)
    h.ck('deauth protected=false in detail',
         any(e['detail'].get('protected') is False for e in evs))

    # ---- beacon flood -----------------------------------------------------
    cfg = {'beacon_warmup_sec': 0, 'beacon_new_bssid_burst': 18}
    wt, evs = _watch(cfg)
    for i in range(20):                              # randomized (LA) BSSIDs
        wt.handle(beacon('de:ad:be:%02x:%02x:01' % (i // 256, i % 256), 'FAKE_%d' % i),
                  ts=1 + i * 0.1)
    bf = [e for e in evs if e['detector'] == 'beacon_flood']
    h.ck('beacon flood (LA burst) -> critical', bf and bf[-1]['severity'] == 'critical')
    h.ck('beacon flood la_ratio reported', bf and bf[-1]['detail']['la_ratio'] >= 0.5)
    wt, evs = _watch(cfg)
    for i in range(20):                              # global (burned-in) MACs
        wt.handle(beacon('00:1a:2b:%02x:%02x:00' % (i // 256, i % 256), 'Nbr_%d' % i),
                  ts=1 + i * 0.1)
    bf = [e for e in evs if e['detector'] == 'beacon_flood']
    h.ck('beacon flood (global MACs) -> warning', bf and bf[-1]['severity'] == 'warning')
    # warmup: dense boot is absorbed as census; a real post-warmup flood still trips
    cfg2 = {'beacon_warmup_sec': 30, 'beacon_new_bssid_burst': 18}
    wt, evs = _watch(cfg2)
    for i in range(40):                              # 40 ambient APs at boot (t<30)
        wt.handle(beacon('de:ad:00:%02x:%02x:01' % (i // 256, i % 256), 'Amb_%d' % i),
                  ts=0 + i * 0.05)
    h.ck('dense boot raises no false flood (warmup)',
         not any(e['detector'] == 'beacon_flood' for e in evs))
    for i in range(20):                              # real flood after warmup (t>30)
        wt.handle(beacon('ba:ad:be:%02x:%02x:01' % (i // 256, i % 256), 'Storm_%d' % i),
                  ts=40 + i * 0.1)
    h.ck('post-warmup flood still trips',
         any(e['detector'] == 'beacon_flood' for e in evs))
    # negative: a stable single AP beaconing 50x is not a flood
    wt, evs = _watch({'beacon_warmup_sec': 0})
    for i in range(50):
        wt.handle(beacon('aa:aa:aa:00:00:01', 'HomeNet'), ts=1 + i * 0.1)
    h.ck('stable single AP is not a flood',
         not any(e['detector'] == 'beacon_flood' for e in evs))

    # ---- evil twin --------------------------------------------------------
    cfg = {'beacon_warmup_sec': 0, 'allowlist': {'HomeNet': ['aa:aa:aa:00:00:01']}}
    wt, evs = _watch(cfg)
    wt.handle(beacon('99:99:99:99:99:99', 'HomeNet'), ts=1)
    et = [e for e in evs if e['detector'] == 'evil_twin']
    h.ck('evil twin (un-allowlisted BSSID) -> critical', et and et[0]['severity'] == 'critical')
    wt, evs = _watch(cfg)
    wt.handle(beacon('aa:aa:aa:00:00:01', 'HomeNet'), ts=1)
    h.ck('allowlisted BSSID -> no evil twin',
         not any(e['detector'] == 'evil_twin' and e['severity'] == 'critical' for e in evs))

    # ---- KARMA / MANA -----------------------------------------------------
    wt, evs = _watch({'beacon_warmup_sec': 0})
    for s in ['Starbucks', 'attwifi', 'HomeNet', 'xfinitywifi', 'TP-LINK', 'Netgear']:
        wt.handle(proberesp('ba:ad:ba:ad:00:01', s), ts=1)
    km = [e for e in evs if e['detector'] == 'karma_mana']
    h.ck('KARMA fires (one BSSID, many SSIDs)', km and km[0]['severity'] == 'critical')
    h.ck('KARMA ssid_count in detail', km and km[0]['detail']['ssid_count'] >= 5)
    # honest AP probe-responding for its own SSID only -> no KARMA
    wt, evs = _watch({'beacon_warmup_sec': 0})
    for _ in range(6):
        wt.handle(proberesp('cc:cc:cc:00:00:01', 'HomeNet'), ts=1)
    h.ck('honest single-SSID responder -> no KARMA',
         not any(e['detector'] == 'karma_mana' for e in evs))

    # ---- refractory: sustained flood is rate-limited ----------------------
    wt, evs = _watch({'refractory_sec': 5.0})
    for i in range(60):                              # 60 frames over 30s
        wt.handle(deauth('aa:bb:cc:00:00:01', w.BROADCAST), ts=500 + i * 0.5)
    n_alerts = sum(1 for e in evs if e['detector'] == 'deauth_flood')
    h.ck('refractory rate-limits alerts (not one per frame)', 1 <= n_alerts <= 8)

    # ---- EAPOL parser -----------------------------------------------------
    f = w.parse_frame(eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 1))
    h.ck('parse data frame ftype', f and f['ftype'] == 2)
    h.ck('parse EAPOL M1', f and f['eapol'] and f['eapol']['msg'] == 1)
    f2 = w.parse_frame(eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 2))
    h.ck('parse EAPOL M2 (STA->AP)', f2 and f2['eapol']['msg'] == 2 and f2['to_ap'] is True)
    f3 = w.parse_frame(eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 3))
    h.ck('parse EAPOL M3', f3 and f3['eapol']['msg'] == 3)
    f4 = w.parse_frame(eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 4))
    h.ck('parse EAPOL M4', f4 and f4['eapol']['msg'] == 4)
    fp = w.parse_frame(eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 1, pmkid=True))
    h.ck('parse PMKID KDE in M1', fp and fp['eapol']['pmkid'] is True)
    h.ck('no PMKID false-positive on plain M1', f and f['eapol']['pmkid'] is False)

    # ---- PMKID harvest ----------------------------------------------------
    wt, evs = _watch({'beacon_warmup_sec': 0})
    wt.handle(eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 1, pmkid=True), ts=1)
    ph = [e for e in evs if e['detector'] == 'pmkid_harvest']
    h.ck('PMKID M1 -> pmkid_harvest critical', ph and ph[0]['severity'] == 'critical')
    # a normal M1 without a PMKID must not trip it
    wt, evs = _watch({'beacon_warmup_sec': 0})
    wt.handle(eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 1), ts=1)
    h.ck('plain M1 -> no pmkid_harvest',
         not any(e['detector'] == 'pmkid_harvest' for e in evs))

    # ---- deauth-and-capture handshake harvest -----------------------------
    sta = 'dd:ee:ff:00:00:09'
    wt, evs = _watch({'beacon_warmup_sec': 0})
    wt.handle(deauth('aa:bb:cc:00:00:01', sta), ts=100)            # forced reconnect
    for m in (1, 2, 3, 4):
        wt.handle(eapol('aa:bb:cc:00:00:01', sta, m), ts=100.5 + m * 0.1)
    hh = [e for e in evs if e['detector'] == 'handshake_harvest']
    h.ck('deauth then 4-way -> handshake_harvest critical', hh and hh[0]['severity'] == 'critical')
    h.ck('handshake_harvest reports messages', hh and len(hh[0]['detail']['msgs']) >= 2)
    # a handshake with no preceding deauth is normal roaming -> quiet
    wt, evs = _watch({'beacon_warmup_sec': 0})
    for m in (1, 2, 3, 4):
        wt.handle(eapol('aa:bb:cc:00:00:01', sta, m), ts=200 + m * 0.1)
    h.ck('handshake without deauth -> no harvest alert',
         not any(e['detector'] == 'handshake_harvest' for e in evs))
    # deauth long before the handshake is outside the window -> quiet
    wt, evs = _watch({'beacon_warmup_sec': 0, 'handshake_deauth_window': 10.0})
    wt.handle(deauth('aa:bb:cc:00:00:01', sta), ts=300)
    for m in (1, 2, 3, 4):
        wt.handle(eapol('aa:bb:cc:00:00:01', sta, m), ts=320 + m * 0.1)
    h.ck('stale deauth outside window -> no harvest',
         not any(e['detector'] == 'handshake_harvest' for e in evs))

    # ---- WPA3 downgrade / transition --------------------------------------
    wt, evs = _watch({'beacon_warmup_sec': 0})
    wt.handle(beacon_rsn('aa:aa:aa:00:00:01', 'SecureNet', [8, 2]), ts=1)   # SAE+PSK
    tr = [e for e in evs if e['detector'] == 'wpa3_transition']
    h.ck('SAE+PSK beacon -> wpa3_transition info', tr and tr[0]['severity'] == 'info')
    # SSID seen as SAE, then a PSK-only BSSID appears -> active downgrade
    wt, evs = _watch({'beacon_warmup_sec': 0})
    wt.handle(beacon_rsn('aa:aa:aa:00:00:01', 'SecureNet', [8], mfpc=True, mfpr=True), ts=1)
    wt.handle(beacon_rsn('66:66:66:66:66:66', 'SecureNet', [2]), ts=2)      # PSK-only twin
    dg = [e for e in evs if e['detector'] == 'wpa_downgrade']
    h.ck('WPA3 SSID reappearing PSK-only -> wpa_downgrade critical',
         dg and dg[0]['severity'] == 'critical')
    # a pure WPA3 network is not a downgrade
    wt, evs = _watch({'beacon_warmup_sec': 0})
    wt.handle(beacon_rsn('aa:aa:aa:00:00:01', 'PureWPA3', [8], mfpc=True, mfpr=True), ts=1)
    h.ck('pure SAE network -> no downgrade/transition alert',
         not any(e['detector'] in ('wpa_downgrade', 'wpa3_transition') for e in evs))

    # ---- PNL leak ---------------------------------------------------------
    wt, evs = _watch({'beacon_warmup_sec': 0, 'pnl_min_ssids': 4})
    for s in ['HomeNet', 'Office', 'Starbucks', 'AirportFree', 'Hotel']:
        wt.handle(probereq(s, src='11:22:33:44:55:66'), ts=1)
    pl = [e for e in evs if e['detector'] == 'pnl_leak']
    h.ck('client leaking 5 SSIDs -> pnl_leak', pl and pl[0]['severity'] == 'warning')
    h.ck('pnl_leak lists the SSIDs', pl and pl[0]['detail']['ssid_count'] >= 4)
    h.ck('pnl_leak names the station', pl and pl[0]['station'] == '11:22:33:44:55:66')
    # a device probing for just one saved net is normal
    wt, evs = _watch({'beacon_warmup_sec': 0, 'pnl_min_ssids': 4})
    for _ in range(6):
        wt.handle(probereq('HomeNet', src='11:22:33:44:55:66'), ts=1)
    h.ck('single-SSID probe -> no pnl_leak',
         not any(e['detector'] == 'pnl_leak' for e in evs))
    # a randomized (locally-administered) MAC is not tracked as a device
    wt, evs = _watch({'beacon_warmup_sec': 0, 'pnl_min_ssids': 4})
    for s in ['A', 'B', 'C', 'D', 'E']:
        wt.handle(probereq(s, src='02:11:22:33:44:55'), ts=1)   # LA bit set
    h.ck('randomized-MAC probes -> no pnl_leak (privacy MAC)',
         not any(e['detector'] == 'pnl_leak' for e in evs))

    total = h.n
    passed = total - h.fail
    print('wifiwatch self-test: %d/%d %s' % (passed, total, 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


if __name__ == '__main__':
    sys.exit(run(verbose=True))
