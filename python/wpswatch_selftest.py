#!/usr/bin/env python3
"""wpswatch_selftest.py — offline self-test (no root, no Scapy, no radio).

Builds raw radiotap + 802.11 beacons carrying WSC elements, and EAP-WSC frames
over EAPOL, and drives them through WpsWatch.process_packet() — the exact live
path — exercising the posture and session/attack codes plus negative controls
(pushbutton-only + Version2 = good posture, a baselined AP) that must stay
silent for the real findings. Run via `python3 wpswatch.py --self-test`.
"""

import struct
import sys

import wpswatch as W
import legacywatch as L


def _macb(s):
    return bytes(int(x, 16) for x in s.split(':'))


def radiotap():
    present = (1 << 5)
    return struct.pack('<BBHI', 0, 0, 9, present) + struct.pack('b', -50)


def _fc(ftype, subtype, to_ds=0, from_ds=0):
    return bytes([(ftype << 2) | (subtype << 4), to_ds | (from_ds << 1)])


def ie(eid, val):
    return bytes([eid, len(val)]) + val


def wsc_attr(aid, val):
    return bytes([aid >> 8, aid & 0xff, len(val) >> 8, len(val) & 0xff]) + val


def wsc_ie(**kw):
    """Build a WSC (0x0050f2:04) vendor element body from keyword parts."""
    data = b''
    if 'state' in kw:
        data += wsc_attr(0x1044, bytes([kw['state']]))
    if 'locked' in kw:
        data += wsc_attr(0x1057, bytes([1 if kw['locked'] else 0]))
    if 'cfg' in kw:
        data += wsc_attr(0x1008, struct.pack('>H', kw['cfg']))
    if kw.get('sel_reg'):
        data += wsc_attr(0x1041, bytes([1]))
    if kw.get('version2'):
        data += wsc_attr(0x1049, b'\x00\x37\x2a\x00\x01\x20')
    for aid, key in ((0x1021, 'manuf'), (0x1023, 'model'), (0x1011, 'devname'),
                     (0x1042, 'serial')):
        if kw.get(key):
            data += wsc_attr(aid, kw[key].encode())
    if 'uuid_e' in kw:
        data += wsc_attr(0x1047, kw['uuid_e'])
    return ie(221, b'\x00\x50\xf2\x04' + data)


def beacon(bssid, ssid='HomeNet', wsc=b''):
    body = _fc(0, 8) + b'\x00\x00' + _macb(L.BROADCAST) + _macb(bssid) + _macb(bssid) + b'\x00\x00'
    body += b'\x00' * 8 + struct.pack('<H', 100) + struct.pack('<H', 0x0011)
    body += ie(0, ssid.encode()) + wsc
    return radiotap() + body


def eap_wsc(sta, bssid, msg_type=None, code=2, uplink=True):
    """Build an EAP-WSC data frame. code: 1=req 2=resp 3=success 4=failure."""
    if uplink:
        hdr = _fc(2, 0, to_ds=1) + b'\x00\x00' + _macb(bssid) + _macb(sta) + _macb(bssid) + b'\x00\x00'
    else:
        hdr = _fc(2, 0, from_ds=1) + b'\x00\x00' + _macb(sta) + _macb(bssid) + _macb(bssid) + b'\x00\x00'
    if code in (3, 4):
        eap = bytes([code, 1, 0, 4])
    else:
        tlvs = wsc_attr(0x1022, bytes([msg_type])) if msg_type is not None else b''
        expanded = bytes([254]) + b'\x00\x37\x2a' + b'\x00\x00\x00\x01' + b'\x04\x00' + tlvs
        eaplen = 4 + len(expanded)
        eap = bytes([code, 1, (eaplen >> 8) & 0xff, eaplen & 0xff]) + expanded
    eapol = bytes([2, 0, (len(eap) >> 8) & 0xff, len(eap) & 0xff]) + eap
    return radiotap() + hdr + W._SNAP_EAPOL + eapol


def run(verbose=False):
    results = []

    def check(name, cond, extra=''):
        results.append((name, bool(cond)))
        if verbose:
            sys.stderr.write('  [%s] %s%s\n' % ('PASS' if cond else 'FAIL', name,
                             '' if cond else '  <<< ' + str(extra)))

    def collect(frames, cfg=None, **kw):
        got = []
        w = W.WpsWatch(cfg or {}, emit=lambda a: got.append(a), **kw)
        t = 1000.0
        for f in frames:
            w.process_packet(f, t)
            t += 0.01
        w.final_report()
        return got, w

    def codes(a):
        return {x['type'] for x in a}

    AP = 'aa:bb:cc:00:00:0a'
    STA = '10:20:30:00:00:09'

    # --- WSC parse ---
    p = W.parse_wsc(wsc_ie(state=1, locked=False, cfg=0x0100)[6:])  # strip eid/len/oui/type -> body
    # (extract_wsc_ie is the real path; parse posture through a beacon below)

    # --- posture: PIN method, unlocked, unconfigured, WSC 1.0 ---
    b_open = beacon(AP, wsc=wsc_ie(state=1, locked=False, cfg=0x0100))   # keypad, unlocked, unconfigured
    a, _ = collect([b_open])
    c = codes(a)
    check('WPS-001 enabled', 'WPS_ENABLED' in c)
    check('WPS-002 PIN method available', 'WPS_PIN_METHOD_AVAILABLE' in c)
    check('WPS-003 AP not locked', 'WPS_AP_NOT_LOCKED' in c)
    check('WPS-004 state not configured', 'WPS_STATE_NOT_CONFIGURED' in c)
    check('WPS-005 WSC 1.0 (no Version2)', 'WPS_VERSION_1' in c)

    # --- good posture: pushbutton only + Version2 + locked ---
    b_good = beacon(AP, wsc=wsc_ie(state=2, locked=True, cfg=0x0080, version2=True))
    a, _ = collect([b_good])
    c = codes(a)
    check('WPS-011 pushbutton-only', 'WPS_PUSHBUTTON_ONLY' in c)
    check('WPS-012 locked', 'WPS_AP_LOCKED' in c)
    check('neg: no PIN/version1 finding on good posture',
          not ({'WPS_PIN_METHOD_AVAILABLE', 'WPS_AP_NOT_LOCKED', 'WPS_VERSION_1'} & c))

    # --- registrar active, serial disclosure, weak family, uuid embeds bssid ---
    tail = bytes(int(x, 16) for x in AP.split(':'))
    uuid = b'\x00' * 10 + tail
    b_x = beacon(AP, wsc=wsc_ie(state=2, locked=False, cfg=0x0100, sel_reg=True,
                                version2=True, model='Ralink RT5350', serial='SN123',
                                uuid_e=uuid))
    a, _ = collect([b_x])
    c = codes(a)
    check('WPS-008 registrar active', 'WPS_REGISTRAR_ACTIVE' in c)
    check('WPS-006 weak-nonce family (Ralink)', 'WPS_WEAK_NONCE_FAMILY' in c)
    check('WPS-009 UUID-E embeds BSSID', 'WPS_UUID_MAC_DERIVED' in c)
    check('WPS-010 serial disclosed', 'WPS_AP_INFO_DISCLOSURE' in c)

    # --- lock-state transition fires even when baselined ---
    frames = [beacon(AP, wsc=wsc_ie(state=2, locked=False, cfg=0x0100, version2=True)),
              beacon(AP, wsc=wsc_ie(state=2, locked=True, cfg=0x0100, version2=True))]
    a, _ = collect(frames, cfg={'baseline_wps_aps': [AP]})
    check('WPS-013 lock-state change fires despite baseline', 'WPS_LOCK_STATE_CHANGED' in codes(a))
    check('baseline: posture findings suppressed', 'WPS_PIN_METHOD_AVAILABLE' not in codes(a))

    # --- session: online brute force (many M1 + NACKs) ---
    frames = [beacon(AP, wsc=wsc_ie(state=1, locked=False, cfg=0x0100))]
    for _ in range(25):
        frames.append(eap_wsc(STA, AP, msg_type=0x04))   # M1
        frames.append(eap_wsc(STA, AP, msg_type=0x0e))   # NACK
    a, _ = collect(frames, cfg={'suppress_s': 0, 'nack_flood_threshold': 20})
    c = codes(a)
    check('WPS-020 session observed', 'WPS_SESSION_OBSERVED' in c)
    check('WPS-021 brute force in progress', 'WPS_BRUTE_FORCE_IN_PROGRESS' in c)
    check('WPS-022 NACK flood', 'WPS_NACK_FLOOD' in c)

    # --- session: offline nonce harvest (M1-M3 repeated, no M4) ---
    frames = []
    for _ in range(4):
        for mt in (0x04, 0x05, 0x07):                    # M1, M2, M3
            frames.append(eap_wsc(STA, AP, msg_type=mt))
    a, _ = collect(frames, cfg={'suppress_s': 0})
    check('WPS-023 nonce harvest', 'WPS_NONCE_HARVEST' in codes(a))

    # --- session: auth-failure burst + enrollment completed + unknown enrollee ---
    frames = [eap_wsc(STA, AP, code=4) for _ in range(5)]
    a, _ = collect(frames, cfg={'suppress_s': 0})
    check('WPS-024 auth failure burst', 'WPS_AUTH_FAILURE_BURST' in codes(a))

    frames = [eap_wsc(STA, AP, msg_type=0x08),           # M4 (so success is meaningful)
              eap_wsc(STA, AP, msg_type=0x0f)]           # DONE
    a, _ = collect(frames, cfg={'known_enrollees': ['00:11:22:33:44:55']})
    c = codes(a)
    check('WPS-026 enrollment completed', 'WPS_ENROLLMENT_COMPLETED' in c)
    check('WPS-025 unknown enrollee (not in known list)', 'WPS_UNKNOWN_ENROLLEE' in c)

    # --- known enrollee does NOT raise WPS-025 ---
    a, _ = collect([eap_wsc(STA, AP, msg_type=0x08), eap_wsc(STA, AP, msg_type=0x0f)],
                   cfg={'known_enrollees': [STA]})
    check('neg: known enrollee not flagged', 'WPS_UNKNOWN_ENROLLEE' not in codes(a))

    # --- EAP-WSC parser directly ---
    f = eap_wsc(STA, AP, msg_type=0x04)
    d = L.parse_dot11(f[L.parse_radiotap(f)['hdrlen']:])
    res = W.parse_eap_wsc(f[L.parse_radiotap(f)['hdrlen']:], d)
    check('parse_eap_wsc: M1 decoded', res and res[1] and res[1]['msg_type'] == 0x04)
    fs = eap_wsc(STA, AP, code=3)
    ds = L.parse_dot11(fs[L.parse_radiotap(fs)['hdrlen']:])
    check('parse_eap_wsc: EAP-Success decoded',
          W.parse_eap_wsc(fs[L.parse_radiotap(fs)['hdrlen']:], ds) == (3, None))

    check('codes: 22 finding codes defined', len(W.CODES) == 22)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    sys.stderr.write('wpswatch selftest: %d/%d checks pass%s\n'
                     % (passed, total, ' — OK' if passed == total else ' — FAIL'))
    return 0 if passed == total else 1


if __name__ == '__main__':
    raise SystemExit(run(verbose=True))
