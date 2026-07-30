#!/usr/bin/env python3
"""wpswatch_conformance.py — broad conformance matrix for wpswatch.

Beyond the self-test: every posture and session code positive + a matched
negative, the Version2 / Version-attribute confusion regression, baseline
behaviour (posture suppressed but lock-transition survives), brute-force vs
retrying-client discrimination, and malformed-frame robustness. Run:
`python3 wpswatch_conformance.py`.
"""

import sys

import wpswatch as W
import wpswatch_selftest as S


def run(verbose=False):
    results = []

    def check(name, cond, extra=''):
        results.append((name, bool(cond)))
        if verbose and not cond:
            sys.stderr.write('  [FAIL] %s  <<< %s\n' % (name, extra))

    def collect(frames, cfg=None, **kw):
        got = []
        w = W.WpsWatch(cfg or {}, emit=lambda a: got.append(a), **kw)
        t = 1000.0
        for f in frames:
            w.process_packet(f, t)
            t += 0.01
        w.final_report()
        return got, w

    def types(a):
        return {x['type'] for x in a}

    AP = 'aa:bb:cc:00:00:0a'
    STA = '10:20:30:00:00:09'

    # ---- posture: positives -------------------------------------------------
    a, _ = collect([S.beacon(AP, wsc=S.wsc_ie(state=1, locked=False, cfg=0x0100))])
    for code in ('WPS_ENABLED', 'WPS_PIN_METHOD_AVAILABLE', 'WPS_AP_NOT_LOCKED',
                 'WPS_STATE_NOT_CONFIGURED', 'WPS_VERSION_1'):
        check('pos: %s' % code, code in types(a), sorted(types(a)))

    # ---- the Version2 vs Version-attribute (0x104A) confusion regression ----
    # An AP that advertises Version 0x10 (attr 0x104A) but NO Version2 subelement
    # is still WSC 1.0. We must fire WPS_VERSION_1 (0x104A is not a substitute).
    wsc_v10_with_version_attr = S.wsc_ie(state=2, locked=False, cfg=0x0100) + b''  # no version2
    # inject a bare 0x104A Version attribute = 0x10 to try to fool the detector
    body = S.wsc_attr(0x104A, bytes([0x10])) + S.wsc_ie(state=2, locked=False, cfg=0x0100)[6:]
    beacon_v10 = S.beacon(AP, wsc=S.ie(221, b'\x00\x50\xf2\x04' + body))
    a, _ = collect([beacon_v10])
    check('regression: Version attr 0x10 does NOT satisfy Version2 (still WSC 1.0)',
          'WPS_VERSION_1' in types(a), sorted(types(a)))

    # ---- posture: negatives (good posture) ----------------------------------
    a, _ = collect([S.beacon(AP, wsc=S.wsc_ie(state=2, locked=True, cfg=0x0080, version2=True))])
    t = types(a)
    check('neg: good posture silent on PIN/version1/not-locked',
          not ({'WPS_PIN_METHOD_AVAILABLE', 'WPS_VERSION_1', 'WPS_AP_NOT_LOCKED'} & t), sorted(t))
    check('pos: good posture records pushbutton + locked',
          {'WPS_PUSHBUTTON_ONLY', 'WPS_AP_LOCKED'} <= t)
    # report_good_posture=false drops the inventory records
    a, _ = collect([S.beacon(AP, wsc=S.wsc_ie(state=2, locked=True, cfg=0x0080, version2=True))],
                   cfg={'report_good_posture': False})
    check('cfg: report_good_posture=false drops WPS-011/012',
          not ({'WPS_PUSHBUTTON_ONLY', 'WPS_AP_LOCKED'} & types(a)))

    # ---- family screen: positive + negative ---------------------------------
    a, _ = collect([S.beacon(AP, wsc=S.wsc_ie(state=2, cfg=0x0100, version2=True, model='Ralink RT5350'))])
    check('pos: WPS_WEAK_NONCE_FAMILY (Ralink)', 'WPS_WEAK_NONCE_FAMILY' in types(a))
    a, _ = collect([S.beacon(AP, wsc=S.wsc_ie(state=2, cfg=0x0100, version2=True, model='Aruba AP-635'))])
    check('neg: unknown model not flagged weak-family', 'WPS_WEAK_NONCE_FAMILY' not in types(a))
    # operator vuln_families extends the built-in screen
    a, _ = collect([S.beacon(AP, wsc=S.wsc_ie(state=2, cfg=0x0100, version2=True, model='Aruba AP-635'))],
                   cfg={'vuln_families': [['aruba', 'test note']]})
    check('cfg: vuln_families extends the screen', 'WPS_WEAK_NONCE_FAMILY' in types(a))

    # ---- lock-state transition survives baseline ----------------------------
    frames = [S.beacon(AP, wsc=S.wsc_ie(state=2, locked=False, cfg=0x0100, version2=True)),
              S.beacon(AP, wsc=S.wsc_ie(state=2, locked=True, cfg=0x0100, version2=True))]
    a, _ = collect(frames, cfg={'baseline_wps_aps': [AP]})
    t = types(a)
    check('baseline: WPS_LOCK_STATE_CHANGED fires despite baseline', 'WPS_LOCK_STATE_CHANGED' in t)
    check('baseline: posture suppressed', 'WPS_PIN_METHOD_AVAILABLE' not in t)

    # ---- session: brute force vs retrying legit client ----------------------
    # attacker: many M1 + NACKs -> WPS-021
    frames = [S.eap_wsc(STA, AP, msg_type=0x04) for _ in range(25)]
    frames += [S.eap_wsc(STA, AP, msg_type=0x0e) for _ in range(25)]
    a, _ = collect(frames, cfg={'suppress_s': 0})
    check('pos: WPS_BRUTE_FORCE_IN_PROGRESS (rate + NACKs)', 'WPS_BRUTE_FORCE_IN_PROGRESS' in types(a))
    # retrying legit client: many M1 but almost no NACK -> NOT brute force
    frames = [S.eap_wsc(STA, AP, msg_type=0x04) for _ in range(25)]
    a, _ = collect(frames, cfg={'suppress_s': 0})
    check('neg: retrying client (no NACKs) is NOT brute force',
          'WPS_BRUTE_FORCE_IN_PROGRESS' not in types(a))

    # ---- session: nonce harvest vs completed enrollment ---------------------
    frames = []
    for _ in range(4):
        for mt in (0x04, 0x05, 0x07):
            frames.append(S.eap_wsc(STA, AP, msg_type=mt))
    a, _ = collect(frames, cfg={'suppress_s': 0})
    check('pos: WPS_NONCE_HARVEST (M1-M3, no M4)', 'WPS_NONCE_HARVEST' in types(a))
    # completed enrollment reaches M4 -> not harvest
    frames = [S.eap_wsc(STA, AP, msg_type=mt) for mt in (0x04, 0x05, 0x07, 0x08, 0x0f)]
    a, _ = collect(frames)
    t = types(a)
    check('neg: completed enrollment is not harvest', 'WPS_NONCE_HARVEST' not in t)
    check('pos: WPS_ENROLLMENT_COMPLETED', 'WPS_ENROLLMENT_COMPLETED' in t)

    # ---- unknown-enrollee gate ----------------------------------------------
    a, _ = collect([S.eap_wsc(STA, AP, msg_type=0x08), S.eap_wsc(STA, AP, msg_type=0x0f)])
    check('neg: empty known_enrollees disables WPS-025', 'WPS_UNKNOWN_ENROLLEE' not in types(a))
    a, _ = collect([S.eap_wsc(STA, AP, msg_type=0x08), S.eap_wsc(STA, AP, msg_type=0x0f)],
                   cfg={'known_enrollees': [STA]})
    check('neg: known enrollee not flagged', 'WPS_UNKNOWN_ENROLLEE' not in types(a))

    # ---- EAP-WSC parser: message types + success/failure --------------------
    import legacywatch as L
    for mt, expect in ((0x04, 0x04), (0x08, 0x08), (0x0e, 0x0e)):
        f = S.eap_wsc(STA, AP, msg_type=mt)
        d = L.parse_dot11(f[L.parse_radiotap(f)['hdrlen']:])
        r = W.parse_eap_wsc(f[L.parse_radiotap(f)['hdrlen']:], d)
        check('parse: msg 0x%02x' % mt, r and r[1] and r[1]['msg_type'] == expect)
    for code in (3, 4):
        f = S.eap_wsc(STA, AP, code=code)
        d = L.parse_dot11(f[L.parse_radiotap(f)['hdrlen']:])
        check('parse: EAP code %d' % code, W.parse_eap_wsc(f[L.parse_radiotap(f)['hdrlen']:], d) == (code, None))

    # ---- malformed frames must not crash ------------------------------------
    crashed = False
    try:
        for bad in (b'', b'\x00' * 4, S.radiotap(), S.beacon(AP)[:26],
                    S.beacon(AP, wsc=S.ie(221, b'\x00\x50\xf2\x04\x10\x44')),   # truncated WSC TLV
                    S.eap_wsc(STA, AP, msg_type=0x04)[:40]):
            W.WpsWatch({}, emit=lambda a: None).process_packet(bad, 1000.0)
    except Exception:
        crashed = True
    check('robustness: malformed frames do not crash', not crashed)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    sys.stderr.write('wpswatch conformance: %d/%d checks pass%s\n'
                     % (passed, total, ' — OK' if passed == total else ' — FAIL'))
    return 0 if passed == total else 1


if __name__ == '__main__':
    raise SystemExit(run(verbose=True))
