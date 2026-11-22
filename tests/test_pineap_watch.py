"""Wi-Fi Pineapple / PineAP-family detection & scoring tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pineap_watch as pa            # noqa: E402
import wifi_defense as wd            # noqa: E402
import device_classifier as dc       # noqa: E402


def test_module_selftest_passes():
    r = pa.selftest()
    assert r["pass"], [x for x in r["results"] if not x["pass"]]


def test_clean_signals_none():
    assert pa.score({})["verdict"] == "none"


def test_large_pool_likely_but_not_confirmed_alone():
    v = pa.score({"rf": [{"type": "karma", "severity": "karma",
                          "bssid": "00:13:37:00:00:01", "ssid_count": 22}]})
    # A big pool is a strong RF tell but, alone, could be any KARMA rig — must not
    # reach 'confirmed' without the mgmt name, a LAN host, or a second signal.
    assert v["verdict"] in ("possible", "likely")
    assert v["score"] < 75


def test_management_ssid_confirms():
    v = pa.score({"rf": [{"type": "rogue_ap", "severity": "attack_tool_ssid",
                          "ssid": "WiFi Pineapple", "bssid": "00:c0:ca:00:00:01"}]})
    assert v["verdict"] == "confirmed"


def test_non_pineapple_attack_tool_name_stays_weak():
    v = pa.score({"rf": [{"type": "rogue_ap", "severity": "attack_tool_ssid",
                          "ssid": "Marauder", "bssid": "00:00:00:00:00:02"}]})
    assert v["verdict"] == "trace"


def test_lan_management_host_floored_to_likely():
    v = pa.score({"lan": ["wifi_pineapple"]})
    assert v["score"] >= 60 and v["verdict"] in ("likely", "confirmed")


def test_lan_host_plus_pool_confirms():
    v = pa.score({"lan": ["wifi_pineapple"],
                  "rf": [{"type": "karma", "severity": "karma",
                          "bssid": "00:13:37:00:00:01", "ssid_count": 20}]})
    assert v["verdict"] == "confirmed"
    assert len(v["domains"]) >= 2


def test_randomized_mac_cross_bssid_pool():
    # Pager-style: pool smeared across many spoofed BSSIDs defeats the single
    # BSSID karma test; the cross-BSSID metric is the fallback.
    dets = [{"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": s}
            for s in ("Home", "attwifi", "xfinitywifi", "Guest")]
    dets.append({"type": "rogue_ap", "severity": "spoofed_bssid", "ssid": "Home",
                 "bssid": "02:00:00:00:00:01"})
    v = pa.score({"rf": dets})
    assert "rogue_ap:xbssid_pool" in v["signals"]


def test_duplicate_ssids_without_spoof_do_not_trip_pool():
    v = pa.score({"rf": [
        {"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "Home"},
        {"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "Guest"},
    ]})
    assert "rogue_ap:xbssid_pool" not in v["signals"]
    assert v["score"] < 25


def test_lone_companion_alert_does_not_confirm():
    v = pa.score({"companion": [{"type": "pineap"}]})
    assert v["score"] < 50


def test_device_classifier_has_pineapple_signature():
    # The rule is AND-logic: a 'pineapple' hostname AND a management port (the
    # web UI on 1471/8080) — both are required to flag a LAN Pineapple.
    ids = [m["id"] for m in dc.detect_threats("Hak5", "00:C0:CA:00:00:01",
                                              hostname="pineapple", ports=[1471])]
    assert "wifi_pineapple" in ids


def test_wifi_defense_karma_pool_end_to_end():
    """Real wifi_defense.analyze() on a synthesized PineAP pool must produce a
    karma detection that pineap_watch scores as an alert — proves the two modules
    agree on the detection shape, not just hand-built dicts."""
    # One BSSID answering probe requests for many different SSIDs = a PineAP pool.
    pool = ["corp-wifi", "attwifi", "xfinitywifi", "Starbucks", "GoogleGuest",
            "HomeNet", "eduroam", "United_Wi-Fi", "Boingo", "Marriott_WiFi",
            "linksys", "NETGEAR", "TelenorWiFi", "SBB-FREE", "_The_Cloud",
            "Delta-WiFi", "hotel-guest"]
    events = [{"kind": "probe_resp", "src": "00:13:37:ab:cd:ef",
               "dst": "aa:bb:cc:00:00:%02x" % i, "ssid": s}
              for i, s in enumerate(pool)]
    res = wd.analyze(events)
    karma = next((d for d in res["detections"] if d["type"] == "karma"), None)
    assert karma and karma["ssid_count"] >= pa._POOL_LARGE

    v = pa.assess(wifi=res)
    assert v["verdict"] in ("possible", "likely", "confirmed")
    assert "karma:pool_large" in v["signals"]
    assert any(s.get("kind") == "ssid_pool" for s in v["suspects"])


def test_assess_end_to_end_confirmed():
    v = pa.assess(
        wifi={"detections": [
            {"type": "karma", "severity": "karma", "bssid": "00:13:37:00:00:01",
             "ssid_count": 25, "ssids": ["corp", "guest"]},
            {"type": "deauth", "severity": "flood"},
        ]},
        assets={"assets": [
            {"mac": "00:C0:CA:00:00:01", "ip": "172.16.42.1", "hostname": "pineapple",
             "threats": [{"id": "wifi_pineapple", "name": "Hak5 WiFi Pineapple"}]},
        ]},
        companion_alerts=[{"type": "pineap"}],
    )
    assert v["verdict"] == "confirmed"
    assert set(v["domains"]) >= {"rf", "lan", "companion"}
    alert = pa.to_alert(v)
    assert alert["source"] == "pineap" and alert["codes"] == ["PA-CONFIRM"]
