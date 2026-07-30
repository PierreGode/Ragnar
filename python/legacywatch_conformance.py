#!/usr/bin/env python3
"""legacywatch_conformance.py — broad conformance matrix for legacywatch.

Goes beyond the in-module self-test: asserts every finding code fires on a
positive case AND stays silent on a matched negative, exercises all four
ToDS/FromDS address combinations, MAC-canonicalization forms, cipher-suite
combinations, malformed/truncated frames (must not crash), and the
declared-vs-observed confidence split. Run: `python3 legacywatch_conformance.py`.
"""

import sys

import legacywatch as L
import legacywatch_selftest as S       # reuse the pure-Python frame builders


def run(verbose=False):
    results = []

    def check(name, cond, extra=''):
        results.append((name, bool(cond)))
        if verbose and not cond:
            sys.stderr.write('  [FAIL] %s  <<< %s\n' % (name, extra))

    def collect(frames, cfg=None, **kw):
        got = []
        w = L.LegacyWatch(cfg or {}, emit=lambda a: got.append(a), **kw)
        t = 1000.0
        for f in frames:
            w.process_packet(f, t)
            t += 0.001
        w.final_report()
        return got, w

    def types(a):
        return {x['type'] for x in a}

    AP = 'aa:bb:cc:00:00:0a'
    PLUG = '20:30:40:00:00:02'
    PHONE = '10:20:30:00:00:09'
    erp = S.ie(42, bytes([0x03]))
    cck = S.ie(1, bytes([0x82, 0x84, 0x8b, 0x96]))
    ofdm = S.ie(1, bytes([0x8c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]))  # basic 6, +OFDM
    ht_cap = S.ie(45, b'\x00' * 26)

    # ---- 1. all four ToDS/FromDS combinations resolve the station -----------
    def sta_of(frame):
        raw = frame
        d = L.parse_dot11(raw[L.parse_radiotap(raw)['hdrlen']:])
        return d['sta'], d['bssid']
    check('dir: ToDS uplink -> addr2', sta_of(S.data(PLUG, AP, 300, rate=1.0)) == (PLUG, AP))
    check('dir: FromDS downlink -> addr1', sta_of(S.data(PLUG, AP, 300, rate=1.0, downlink=True)) == (PLUG, AP))
    # IBSS (no DS): addr2 is STA, addr3 BSSID — build manually.
    import struct
    fc = S._fc(2, 0)
    ibss = S.radiotap(rate_mbps=1.0) + fc + b'\x00\x00' + S._macb('ff:ff:ff:ff:ff:ff') + S._macb(PLUG) + S._macb(AP) + b'\x00\x00'
    check('dir: no-DS -> addr2 STA / addr3 BSSID', sta_of(ibss) == (PLUG, AP))
    wds = S.radiotap(rate_mbps=1.0) + S._fc(2, 0, to_ds=1, from_ds=1) + b'\x00\x00' + S._macb(AP) + S._macb(AP) + S._macb(AP) + b'\x00\x00'
    d = L.parse_dot11(wds[L.parse_radiotap(wds)['hdrlen']:])
    check('dir: WDS (both DS) -> no single STA', d['sta'] is None)

    # ---- 2. every BSS-posture code: positive + negative ---------------------
    a, _ = collect([S.beacon(AP, cap=0x0021, elements=erp + cck)] * 2)          # open, 2.4, admits 11b, no HT
    t = types(a)
    for code in ('NONERP_STA_PRESENT', 'ERP_PROTECTION_ACTIVE', 'BSS_ADMITS_11B',
                 'BSS_NO_HT_CAPABILITY', 'LONG_SLOT_TIME', 'BSS_OPEN'):
        check('pos: %s' % code, code in t, sorted(t))
    # negative: modern WPA2/CCMP HT AP on OFDM, short slot, PMF -> none of those
    clean = S.beacon(AP, cap=0x0431, elements=ofdm + ht_cap + S.rsn_ie(group=4, pairwise=(4,), akms=(2,), mfpc=True))
    a, _ = collect([clean] * 2)
    t = types(a)
    for code in ('NONERP_STA_PRESENT', 'ERP_PROTECTION_ACTIVE', 'BSS_ADMITS_11B',
                 'BSS_NO_HT_CAPABILITY', 'BSS_OPEN', 'BSS_WEP', 'GROUP_CIPHER_TKIP',
                 'PAIRWISE_TKIP_OFFERED', 'MFP_ABSENT'):
        check('neg: clean AP silent on %s' % code, code not in t, sorted(t))

    # ---- 3. cipher matrix ---------------------------------------------------
    cases = {
        'BSS_WEP': (0x0431, cck),                                        # privacy, no RSN
        'GROUP_CIPHER_TKIP': (0x0431, ht_cap + S.rsn_ie(group=2, pairwise=(4,), mfpc=True)),
        'PAIRWISE_TKIP_OFFERED': (0x0431, ht_cap + S.rsn_ie(group=4, pairwise=(4, 2), mfpc=True)),
        'MFP_ABSENT': (0x0431, ht_cap + S.rsn_ie(group=4, pairwise=(4,), mfpc=False)),
    }
    for code, (cap, elems) in cases.items():
        a, _ = collect([S.beacon(AP, cap=cap, elements=elems)] * 2)
        check('cipher: %s' % code, code in types(a), sorted(types(a)))

    # ---- 4. per-station declared vs observed --------------------------------
    # declared modern: HT probe then only low-rate data -> LEG-022 stuck, not LEG-020
    frames = [S.beacon(AP, elements=erp + cck + ht_cap)]
    frames.append(S.probe_req(PHONE, elements=ht_cap, rate=6.0))
    frames += [S.data(PHONE, AP, 800, rate=1.0) for _ in range(120)]
    a, _ = collect(frames)
    t = types(a)
    check('confidence: HT-declared + legacy rates => LEG-022 not LEG-020',
          'CLIENT_LEGACY_RATE_STUCK' in t and 'CLIENT_11B_ONLY' not in t, sorted(t))
    # observed-only 11b (no capability frame)
    frames = [S.beacon(AP, elements=erp + cck)]
    frames += [S.data(PLUG, AP, 400, rate=1.0) for _ in range(30)]
    a, w = collect(frames)
    rec = dict(w.stations.all_records()).get(PLUG)
    check('confidence: observed-only CCK => 11b observed',
          rec and L.classify_phy(rec['declared_ht'], rec['rate_min'], rec['rate_max']) == ('b', True, 'observed'))

    # ---- 5. high-retry legacy + no-aggregation ------------------------------
    frames = [S.beacon(AP, elements=erp + cck)]
    frames += [S.data(PLUG, AP, 400, rate=1.0, retry=1) for _ in range(250)]
    a, _ = collect(frames)
    t = types(a)
    check('LEG-024 high retry legacy', 'CLIENT_HIGH_RETRY_LEGACY' in t, sorted(t))
    check('LEG-025 no aggregation', 'CLIENT_NO_AGGREGATION' in t)

    # ---- 6. MAC canonicalization forms --------------------------------------
    for form in ('aa:bb:cc:00:11:22', 'AA-BB-CC-00-11-22', 'aabb.cc00.1122', 'AABBCC001122'):
        check('canon: %s' % form, L.canon_mac(form) == 'aa:bb:cc:00:11:22')
    check('canon: baseline set matches formatted output',
          'aa:bb:cc:00:11:22' in L.Config({'baseline_legacy': ['AA-BB-CC-00-11-22']}).baseline)

    # ---- 7. malformed / truncated frames must not crash ---------------------
    crashed = False
    try:
        for bad in (b'', b'\x00', b'\x00' * 3, S.radiotap(rate_mbps=1.0),
                    S.radiotap() + b'\x80\x00', S.beacon(AP)[:30],
                    S.beacon(AP, elements=bytes([48, 200]) + b'\x00' * 4),   # RSN len overruns
                    S.beacon(AP, elements=bytes([221, 3]) + b'\x00\x50\xf2')):
            L.LegacyWatch({}, emit=lambda a: None).process_packet(bad, 1000.0)
    except Exception as e:  # noqa
        crashed = True
    check('robustness: malformed frames do not crash the parser', not crashed)

    # ---- 8. baseline + suppression ------------------------------------------
    frames = [S.beacon(AP, elements=erp + cck)] + [S.data(PLUG, AP, 400, rate=1.0) for _ in range(30)]
    a, _ = collect(frames, cfg={'baseline_legacy': [PLUG]})
    check('baseline: client findings suppressed for baselined STA',
          not any(x['subject'] == PLUG and x['type'].startswith('CLIENT_') for x in a))
    check('baseline: BSS-level findings survive baseline',
          any(x['type'] == 'ERP_PROTECTION_ACTIVE' for x in a))

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    sys.stderr.write('legacywatch conformance: %d/%d checks pass%s\n'
                     % (passed, total, ' — OK' if passed == total else ' — FAIL'))
    return 0 if passed == total else 1


if __name__ == '__main__':
    raise SystemExit(run(verbose=True))
