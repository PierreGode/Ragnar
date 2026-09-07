"""wifiwatch client/handshake-layer detectors folded into a deep defense scan.

Drives REAL radiotap+802.11 frames (built by python/wifiwatch_selftest) through
wifi_defense's wifiwatch integration, so it proves the two agree end to end
without any radio."""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "python"))   # wifiwatch_selftest does `import wifiwatch`

import wifi_defense as wd                    # noqa: E402
import wifiwatch_selftest as sf              # raw-frame builders  # noqa: E402


def _run(frames):
    """Feed (raw, ts) frames through a fresh wifiwatch and return mapped dets."""
    watch = wd._new_wifiwatch()
    assert watch is not None
    for raw, ts in frames:
        watch.handle(raw, ts)
    return wd._wifiwatch_detections(watch._ragnar_alerts)


def test_new_wifiwatch_available():
    assert wd._new_wifiwatch() is not None


def test_pmkid_harvest_folds_in():
    dets = _run([(sf.eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 1,
                           pmkid=True), 1.0)])
    d = [x for x in dets if x['type'] == 'pmkid_harvest']
    assert d and d[0]['severity'] == 'pmkid'
    assert d[0]['bssid'] == 'aa:bb:cc:00:00:01'


def test_plain_m1_not_flagged():
    dets = _run([(sf.eapol('aa:bb:cc:00:00:01', 'dd:ee:ff:00:00:09', 1), 1.0)])
    assert not [x for x in dets if x['type'] == 'pmkid_harvest']


def test_handshake_after_deauth_folds_in():
    sta = 'dd:ee:ff:00:00:09'
    frames = [(sf.deauth('aa:bb:cc:00:00:01', sta), 100.0)]
    for m in (1, 2, 3, 4):
        frames.append((sf.eapol('aa:bb:cc:00:00:01', sta, m), 100.5 + m * 0.1))
    d = [x for x in _run(frames) if x['type'] == 'handshake_harvest']
    assert d and d[0]['severity'] == 'handshake' and d[0]['station'] == sta


def test_handshake_without_deauth_is_quiet():
    sta = 'dd:ee:ff:00:00:09'
    frames = [(sf.eapol('aa:bb:cc:00:00:01', sta, m), 200 + m * 0.1)
              for m in (1, 2, 3, 4)]
    assert not [x for x in _run(frames) if x['type'] == 'handshake_harvest']


def test_pnl_leak_folds_in():
    src = '11:22:33:44:55:66'
    frames = [(sf.probereq(s, src=src), 1.0)
              for s in ['HomeNet', 'Office', 'Starbucks', 'AirportFree', 'Hotel']]
    d = [x for x in _run(frames) if x['type'] == 'pnl_leak']
    assert d and d[0]['severity'] == 'pnl_leak' and d[0]['station'] == src
    assert d[0].get('ssids')


def test_overlapping_detectors_are_dropped():
    # AP/RF detectors overlap analyze() and must NOT be re-emitted as detections.
    alerts = [{'detector': 'deauth_flood', 'severity': 'critical', 'bssid': 'x'},
              {'detector': 'beacon_flood', 'severity': 'warning'},
              {'detector': 'evil_twin', 'severity': 'critical'},
              {'detector': 'karma_mana', 'severity': 'critical'},
              {'detector': 'wpa_downgrade', 'severity': 'critical'},
              {'detector': 'pmkid_harvest', 'severity': 'critical',
               'bssid': 'y', 'summary': 's'}]
    dets = wd._wifiwatch_detections(alerts)
    assert [d['type'] for d in dets] == ['pmkid_harvest']


def test_threat_level_includes_new_severities():
    assert wd._threat_level([{'severity': 'pmkid'}]) == 'critical'
    assert wd._threat_level([{'severity': 'handshake'}]) == 'critical'
    assert wd._threat_level([{'severity': 'pnl_leak'}]) == 'warning'
    assert wd._threat_level([]) == 'clear'
