"""WPA3-strip downgrade detection in wifi_defense.analyze().

Only a genuine evil-twin clone (a WPA3 SSID re-advertised PSK-only from a
foreign/randomized BSSID) is flagged. Plain transition mode and same-vendor
mixed-mode are configuration, not attacks, and must stay silent."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wifi_defense as wd            # noqa: E402


def _beacon(bssid, ssid, security):
    return {"kind": "beacon", "src": bssid, "ssid": ssid, "security": security}


def _downgrade(res, sev="wpa3_strip"):
    return [d for d in res["detections"]
            if d["type"] == "wpa3_downgrade" and (sev is None or d["severity"] == sev)]


def test_wpa3_strip_from_foreign_oui_detected():
    # Real WPA3 net on one vendor; a DIFFERENT-OUI BSSID clones it as WPA2-only.
    events = [_beacon("00:11:22:00:00:01", "CorpWiFi", "WPA3")] * 2 \
        + [_beacon("66:77:88:00:00:09", "CorpWiFi", "WPA2")] * 2
    res = wd.analyze(events)
    strip = _downgrade(res)
    assert strip, res["detections"]
    assert "66:77:88:00:00:09" in strip[0]["rogue_bssids"]
    assert res["threat"] == "critical"


def test_wpa3_strip_from_randomized_bssid_detected():
    # Evil twin re-advertising as WPA2 from a locally-administered (randomized) MAC.
    events = [_beacon("00:11:22:00:00:01", "CorpWiFi", "WPA3"),
              _beacon("02:00:00:00:00:09", "CorpWiFi", "WPA2")]
    res = wd.analyze(events)
    assert _downgrade(res)


def test_transition_mode_not_flagged():
    # WPA2/3 transition mode is the default on most routers — not an attack.
    res = wd.analyze([_beacon("aa:aa:aa:00:00:01", "HomeNet", "WPA2/3")] * 2)
    assert not _downgrade(res, sev=None)
    assert res["threat"] != "critical"


def test_same_vendor_mixed_mode_not_flagged():
    # One operator's gear: WPA3 on one radio, WPA2 SSID of the same name on a
    # sibling BSSID sharing the OUI => band-steering, not a clone.
    events = [_beacon("00:11:22:00:00:01", "MyNet", "WPA3"),
              _beacon("00:11:22:00:00:02", "MyNet", "WPA2")]
    res = wd.analyze(events)
    assert not _downgrade(res, sev=None)


def test_trusted_baseline_psk_bssid_not_flagged():
    # If both BSSIDs are trusted, a mixed-mode pairing is a known-good deployment.
    events = [_beacon("00:11:22:00:00:01", "CorpWiFi", "WPA3"),
              _beacon("66:77:88:00:00:09", "CorpWiFi", "WPA2")]
    baseline = {"CorpWiFi": ["00:11:22:00:00:01", "66:77:88:00:00:09"]}
    res = wd.analyze(events, baseline=baseline)
    assert not _downgrade(res, sev=None)


def test_clean_wpa3_only_no_downgrade():
    res = wd.analyze([_beacon("00:11:22:00:00:01", "SecureNet", "WPA3")] * 3)
    assert not _downgrade(res, sev=None)


def test_plain_wpa2_network_not_flagged():
    res = wd.analyze([_beacon("00:11:22:00:00:01", "OldNet", "WPA2")] * 3)
    assert not _downgrade(res, sev=None)
