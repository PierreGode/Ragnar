"""A swarm of identical low-confidence rogue-AP detections (e.g. a Pineapple SSID
pool: 'bloop21'..'bloop31' each on many BSSIDs) must not stack into a verdict."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import halehound_watch as hh          # noqa: E402
import pineap_watch as pa             # noqa: E402


def _dups(n, start=21):
    return [{"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "bloop%d" % i}
            for i in range(start, start + n)]


def test_halehound_duplicate_ssid_not_scored():
    # duplicate_ssid is not an ESP32-multitool tell — contributes nothing.
    assert hh.score({"wifi": _dups(20)})["verdict"] == "none"


def test_halehound_pool_swarm_plus_stray_deauth_not_possible():
    v = hh.score({"wifi": _dups(10) + [{"type": "deauth", "severity": "seen"}]})
    assert v["verdict"] in ("none", "trace") and v["score"] < 25


def test_halehound_wifi_signals_deduped_by_severity():
    # Ten spoofed BSSIDs (a beacon-flood shape) count once, not ten times.
    ten = [{"type": "rogue_ap", "severity": "spoofed_bssid", "bssid": "02:0:0:0:0:%d" % i}
           for i in range(10)]
    v = hh.score({"wifi": ten})
    assert v["domain_scores"]["wifi"] == 20   # one spoofed_bssid weight, not 200


def test_pineap_duplicate_swarm_without_spoof_stays_low():
    v = pa.score({"rf": _dups(10)})
    assert "rogue_ap:xbssid_pool" not in v["signals"]
    assert v["score"] < 25


def test_pineap_swarm_with_spoof_is_xbssid_pool():
    rf = _dups(5) + [{"type": "rogue_ap", "severity": "spoofed_bssid",
                      "ssid": "bloop21", "bssid": "02:00:00:00:00:01"}]
    assert "rogue_ap:xbssid_pool" in pa.score({"rf": rf})["signals"]


def test_pineap_messy_env_below_incident_threshold():
    # Dozens of duplicate SSIDs + one evil twin + a stray deauth (no spoofed BSSID)
    # stays under the >=50 Watchtower-incident threshold.
    rf = _dups(30) + [{"type": "rogue_ap", "severity": "evil_twin", "ssid": "X"},
                      {"type": "deauth", "severity": "seen"}]
    assert pa.score({"rf": rf})["score"] < 50
