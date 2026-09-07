"""WPA3 downgrade / transition-mode detection in wifi_defense.analyze()."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wifi_defense as wd            # noqa: E402


def _beacon(bssid, ssid, security):
    return {"kind": "beacon", "src": bssid, "ssid": ssid, "security": security}


def _downgrade(res, sev=None):
    return [d for d in res["detections"]
            if d["type"] == "wpa3_downgrade" and (sev is None or d["severity"] == sev)]


def test_wpa3_strip_evil_twin_detected():
    # Real WPA3 net on one vendor; a DIFFERENT-OUI BSSID clones it as WPA2-only.
    events = [_beacon("00:11:22:00:00:01", "CorpWiFi", "WPA3")] * 2 \
        + [_beacon("66:77:88:00:00:09", "CorpWiFi", "WPA2")] * 2
    res = wd.analyze(events)
    strip = _downgrade(res, "wpa3_strip")
    assert strip, res["detections"]
    assert "66:77:88:00:00:09" in strip[0]["rogue_bssids"]
    assert res["threat"] == "critical"


def test_transition_mode_is_informational():
    res = wd.analyze([_beacon("aa:aa:aa:00:00:01", "HomeNet", "WPA2/3")] * 2)
    trans = _downgrade(res, "wpa3_transition")
    assert trans and trans[0]["bssid"] == "aa:aa:aa:00:00:01"
    # Transition mode alone is not critical (config choice, not an attack).
    assert res["threat"] != "critical"
    # And a lone transition AP is NOT a strip.
    assert not _downgrade(res, "wpa3_strip")


def test_same_vendor_mixed_mode_not_flagged_critical():
    # One vendor's gear: WPA3 SSID on one BSSID, a WPA2 SSID of the same name on
    # a sibling BSSID sharing the OUI => mixed-mode, not an evil twin.
    events = [_beacon("00:11:22:00:00:01", "MyNet", "WPA3"),
              _beacon("00:11:22:00:00:02", "MyNet", "WPA2")]
    res = wd.analyze(events)
    assert _downgrade(res, "wpa3_mixed")
    assert not _downgrade(res, "wpa3_strip")


def test_clean_wpa3_only_no_downgrade():
    res = wd.analyze([_beacon("aa:aa:aa:00:00:01", "SecureNet", "WPA3")] * 3)
    assert not _downgrade(res)


def test_plain_wpa2_network_not_flagged():
    # No SAE ever advertised => nothing to strip, no finding.
    res = wd.analyze([_beacon("aa:aa:aa:00:00:01", "OldNet", "WPA2")] * 3)
    assert not _downgrade(res)
