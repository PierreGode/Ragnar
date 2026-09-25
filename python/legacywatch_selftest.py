#!/usr/bin/env python3
"""legacywatch_selftest.py — offline self-test (no root, no Scapy, no radio).

Builds raw radiotap + 802.11 frame bytes in pure Python and drives them through
LegacyWatch.process_packet() — the exact path the live sniffer uses — exercising
the BSS-posture, cipher and per-station finding codes, plus negative controls
(a modern client that probes at 1 Mbps, a baselined legacy station) that must
stay silent. Run via `python3 legacywatch.py --self-test`.
"""

import struct
import sys

import legacywatch as L


# ---- frame builders (pure bytes) ------------------------------------------
def _macb(s):
    return bytes(int(x, 16) for x in s.split(':'))


def radiotap(rate_mbps=None, mcs=None, signal=-50):
    """Minimal radiotap with dBm signal (bit 5) and either legacy Rate (bit 2)
    or an MCS field (bit 19)."""
    present = (1 << 5)
    fields = b''
    if rate_mbps is not None:
        present |= (1 << 2)
    if mcs is not None:
        present |= (1 << 19)
    # Emit in bit order: bit2 Rate (u8), bit5 signal (s8), bit19 MCS (3 bytes).
    body = b''
    if rate_mbps is not None:
        body += struct.pack('B', int(rate_mbps * 2))          # 500 kbps units
    body += struct.pack('b', signal)
    if mcs is not None:
        body += struct.pack('BBB', 0x00, 0x00, mcs)           # known=0, flags=0, mcs
    hdrlen = 8 + len(body)
    return struct.pack('<BBH I', 0, 0, hdrlen, present) + body


def _fc(ftype, subtype, to_ds=0, from_ds=0, retry=0, protected=0):
    fc0 = (ftype << 2) | (subtype << 4)
    fc1 = to_ds | (from_ds << 1) | (retry << 3) | (protected << 6)
    return bytes([fc0, fc1])


def _hdr(fc, a1, a2, a3):
    return fc + b'\x00\x00' + _macb(a1) + _macb(a2) + _macb(a3) + b'\x00\x00'


def ie(eid, val):
    return bytes([eid, len(val)]) + val


def rsn_ie(group=4, pairwise=(4,), akms=(2,), mfpc=False):
    v = struct.pack('<H', 1)
    v += b'\x00\x0f\xac' + bytes([group])
    v += struct.pack('<H', len(pairwise)) + b''.join(b'\x00\x0f\xac' + bytes([c]) for c in pairwise)
    v += struct.pack('<H', len(akms)) + b''.join(b'\x00\x0f\xac' + bytes([a]) for a in akms)
    v += struct.pack('<H', 0x0080 if mfpc else 0x0000)
    return ie(48, v)


def beacon(bssid, ssid='HomeNet', cap=0x0431, elements=b''):
    body = _hdr(_fc(0, 8), L.BROADCAST, bssid, bssid)
    body += b'\x00' * 8 + struct.pack('<H', 100) + struct.pack('<H', cap)  # ts, interval, cap
    body += ie(0, ssid.encode()) + elements
    return radiotap(rate_mbps=1.0) + body


def probe_req(sta, elements=b'', rate=1.0, mcs=None):
    body = _hdr(_fc(0, 4), L.BROADCAST, sta, L.BROADCAST)
    body += ie(0, b'') + elements
    return radiotap(rate_mbps=rate, mcs=mcs) + body


def data(sta, bssid, nbytes, rate=None, mcs=None, downlink=False, retry=0):
    if downlink:
        fc = _fc(2, 0, from_ds=1, retry=retry)
        hdr = _hdr(fc, sta, bssid, bssid)
    else:
        fc = _fc(2, 0, to_ds=1, retry=retry)
        hdr = _hdr(fc, bssid, sta, bssid)
    pad = b'\x00' * max(0, nbytes - len(hdr))
    return radiotap(rate_mbps=rate, mcs=mcs) + hdr + pad


# ---- harness --------------------------------------------------------------
def run(verbose=False):
    results = []

    def check(name, cond, extra=''):
        results.append((name, bool(cond)))
        if verbose:
            sys.stderr.write('  [%s] %s%s\n' % ('PASS' if cond else 'FAIL', name,
                             '' if cond else '  <<< ' + str(extra)))

    def collect(frames, cfg=None, **kw):
        got = []
        w = L.LegacyWatch(cfg or {}, emit=lambda a: got.append(a), **kw)
        t = 1000.0
        for f in frames:
            w.process_packet(f, t)
            t += 0.001
        w.final_report()
        return got, w

    def codes(alerts):
        return {a['type'] for a in alerts}

    AP = 'aa:bb:cc:00:00:0a'
    PLUG = '20:30:40:00:00:02'
    PHONE = '10:20:30:00:00:09'

    # --- radiotap / dot11 parse ---
    rt = L.parse_radiotap(radiotap(rate_mbps=1.0, signal=-60))
    check('radiotap: legacy rate parsed', rt['rate_mbps'] == 1.0 and rt['signal'] == -60)
    rt2 = L.parse_radiotap(radiotap(mcs=7))
    check('radiotap: MCS 7 => ~65 Mbps', rt2['rate_mbps'] and rt2['rate_mbps'] > 60)
    d = L.parse_dot11(data(PLUG, AP, 400, rate=1.0)[L.parse_radiotap(data(PLUG, AP, 400, rate=1.0))['hdrlen']:])
    check('dot11: ToDS station = addr2', d['sta'] == PLUG and d['bssid'] == AP)
    d2raw = data(PLUG, AP, 400, rate=1.0, downlink=True)
    d2 = L.parse_dot11(d2raw[L.parse_radiotap(d2raw)['hdrlen']:])
    check('dot11: FromDS station = addr1', d2['sta'] == PLUG and d2['bssid'] == AP)

    # --- airtime / PHY units ---
    check('airtime: 1500B @ 1 Mbps ~= 12192 us', abs(L.frame_airtime_us(1500, 1.0) - 12192) < 1)
    check('phy: declared HT beats low rates', L.classify_phy(True, 1.0, 1.0) == ('n+', False, 'declared'))
    check('phy: observed CCK => 11b', L.classify_phy(None, 1.0, 11.0) == ('b', True, 'observed'))
    check('mac canon: cisco-dotted', L.canon_mac('aabb.cc00.1122') == 'aa:bb:cc:00:11:22')
    check('mac canon: invalid dropped', L.canon_mac('nope') is None)

    # --- BSS posture: legacy 2.4 GHz, ERP protection, WEP-ish, admits 11b ---
    erp = ie(42, bytes([0x03]))                        # NonERP + Use_Protection
    rates = ie(1, bytes([0x82, 0x84, 0x8b, 0x96]))     # basic 1/2/5.5/11 (CCK)
    htop = ie(61, bytes([6, 0x03, 0, 0, 0]))           # HT Protection = Mixed
    b_open = [beacon(AP, cap=0x0021, elements=erp + rates)]   # no privacy, no short-slot
    a, _ = collect(b_open * 2)
    c = codes(a)
    check('LEG-001 non-ERP present', 'NONERP_STA_PRESENT' in c)
    check('LEG-002 ERP protection active', 'ERP_PROTECTION_ACTIVE' in c)
    check('LEG-006 BSS admits 11b (basic CCK)', 'BSS_ADMITS_11B' in c)
    check('LEG-007 AP no HT capability', 'BSS_NO_HT_CAPABILITY' in c)
    check('LEG-008 long slot time', 'LONG_SLOT_TIME' in c)
    check('LEG-010 open BSS', 'BSS_OPEN' in c)

    # WEP: privacy bit, no RSN.
    a, _ = collect([beacon(AP, cap=0x0431, elements=rates)] * 2)
    check('LEG-011 WEP', 'BSS_WEP' in codes(a))

    # HT Protection mixed + a modern (HT) AP.
    a, _ = collect([beacon(AP, cap=0x0431, elements=htop + ie(45, b'\x00' * 26))] * 2)
    check('LEG-004 HT protection mixed', 'HT_PROTECTION_MIXED' in codes(a))

    # TKIP group + pairwise, WPA/WPA2 mixed, MFP absent.
    wpa1 = ie(221, b'\x00\x50\xf2\x01\x01\x00' + b'\x00\x50\xf2\x02' + b'\x01\x00' + b'\x00\x50\xf2\x02')
    tk = rsn_ie(group=2, pairwise=(4, 2), akms=(2,), mfpc=False)
    a, _ = collect([beacon(AP, cap=0x0431, elements=ie(45, b'\x00' * 26) + tk + wpa1)] * 2)
    c = codes(a)
    check('LEG-013 group cipher TKIP', 'GROUP_CIPHER_TKIP' in c)
    check('LEG-014 pairwise TKIP offered', 'PAIRWISE_TKIP_OFFERED' in c)
    check('LEG-015 WPA/WPA2 mixed', 'WPA_WPA2_MIXED' in c)
    check('LEG-016 MFP absent', 'MFP_ABSENT' in c)

    # --- per-station: legacy plug (both directions) vs modern phone ---
    frames = [beacon(AP, elements=erp + rates + ie(45, b'\x00' * 26))]
    # phone: HT-declared probe + a 1 Mbps probe (the trap) + fast data
    frames.append(probe_req(PHONE, elements=ie(45, b'\x00' * 26), rate=6.0))
    frames.append(probe_req(PHONE, rate=1.0))
    frames += [data(PHONE, AP, 1500, mcs=7) for _ in range(200)]
    # plug: 40 up + 40 down at 1 Mbps
    frames += [data(PLUG, AP, 400, rate=1.0) for _ in range(40)]
    frames += [data(PLUG, AP, 400, rate=1.0, downlink=True) for _ in range(40)]
    a, w = collect(frames)
    c = codes(a)
    plug = dict(w.stations.all_records()).get(PLUG)
    phone = dict(w.stations.all_records()).get(PHONE)
    check('station: plug counts BOTH directions (80 frames)', plug and plug['frames'] == 80)
    check('station: phone declared HT (not legacy)', phone and phone['declared_ht'] is True)
    check('LEG-020 plug is 802.11b-only', 'CLIENT_11B_ONLY' in c)
    check('LEG-023 plug airtime disproportionate', 'CLIENT_AIRTIME_DISPROPORTIONATE' in c)
    check('LEG-025 plug no aggregation', 'CLIENT_NO_AGGREGATION' in c)
    check('neg: phone NOT flagged legacy',
          not any(a2['type'] in ('CLIENT_11B_ONLY', 'CLIENT_11G_ONLY') and a2['subject'] == PHONE
                  for a2 in a))

    # --- identity disclosure (LEG-026) via WSC device name ---
    wsc = ie(221, b'\x00\x50\xf2\x04' + b'\x10\x11\x00\x08scanner1')
    a, _ = collect([beacon(AP, elements=erp + rates), probe_req(PLUG, elements=wsc, rate=1.0)])
    check('LEG-026 identity disclosed', 'CLIENT_IDENTITY_DISCLOSED' in codes(a))

    # --- baseline suppresses client findings ---
    a, _ = collect(frames, cfg={'baseline_legacy': [PLUG]})
    check('baseline: plug client findings suppressed',
          not any(x['subject'] == PLUG and x['type'].startswith('CLIENT_') for x in a))

    # --- suppression: a repeated beacon posture fires once in the window ---
    a, _ = collect([beacon(AP, cap=0x0021, elements=erp + rates)] * 5)
    check('suppression: ERP protection fires once per window',
          sum(1 for x in a if x['type'] == 'ERP_PROTECTION_ACTIVE') == 1)

    # --- identity precedence + OUI ---
    oui = L.OuiDB()
    oui.by_len[6]['203040'] = 'AcmeCorp'
    w = L.LegacyWatch({}, emit=lambda a: None, oui=oui,
                      inventory={PLUG: {'hostname': 'plug-1', 'note': ''}})
    name, srcp = w._identity(PLUG, {})
    check('identity: inventory wins', name == 'plug-1' and srcp == 'inventory')
    name, srcp = w._identity('20:30:40:aa:bb:cc', {})
    check('identity: OUI fallback', name == 'AcmeCorp' and srcp == 'oui')

    # --- all codes present in the table / list-findings integrity ---
    check('codes: 22 finding codes defined', len(L.CODES) == 22)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    sys.stderr.write('legacywatch selftest: %d/%d checks pass%s\n'
                     % (passed, total, ' — OK' if passed == total else ' — FAIL'))
    return 0 if passed == total else 1


if __name__ == '__main__':
    raise SystemExit(run(verbose=True))
