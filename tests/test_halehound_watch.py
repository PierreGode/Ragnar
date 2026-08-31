"""HaleHound-CYD detection & correlation tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import halehound_watch as hh          # noqa: E402
import device_classifier as dc        # noqa: E402
import wifi_defense as wd             # noqa: E402


def test_module_selftest_passes():
    r = hh.selftest()
    assert r["pass"], [x for x in r["results"] if not x["pass"]]


def test_single_domain_capped_below_likely():
    v = hh.score({"wifi": [
        {"type": "auth_flood", "severity": "flood"},
        {"type": "rogue_ap", "severity": "evil_twin"},
    ]})
    assert v["verdict"] in ("possible", "trace")


def test_multi_domain_escalates():
    v = hh.score({
        "wifi": [{"type": "auth_flood", "severity": "flood"}],
        "lan": ["rogue_espressif"],
        "ble": [{"type": "swiftpair_spam"}],
    })
    assert v["verdict"] in ("likely", "confirmed")
    assert len(v["domains"]) >= 3


def test_named_host_floored_to_likely():
    v = hh.score({"lan": ["halehound_cyd"]})
    assert v["score"] >= 60 and v["verdict"] in ("likely", "confirmed")


def test_clean_signals_none():
    assert hh.score({})["verdict"] == "none"


def test_ble_findmy_flood_and_calm_room():
    flood = [{"mac": "C0:00:00:00:00:%02x" % i, "company_key": 0x004C,
              "addr_type": "random"} for i in range(8)]
    assert any(a["type"] == "apple_ble_flood" for a in hh.detect_ble_attacks(flood))
    calm = [{"mac": "3C:22:FB:00:00:01", "company_key": 0x004C, "addr_type": "public"}]
    assert hh.detect_ble_attacks(calm) == []


def test_garmr_portal_fingerprint():
    fp = hh.fingerprint_portal(["10.0.0.1"] * 4, http_status=302,
                               redirect_host="10.0.0.1", ap_ip="10.0.0.1")
    assert fp["confirmed"]
    real = hh.fingerprint_portal(["1.1.1.1", "8.8.8.8", "9.9.9.9"], http_status=200)
    assert not real["confirmed"]


def test_device_classifier_halehound_signature():
    ids = [m["id"] for m in dc.detect_threats("Espressif Inc.", "AC:67:B2:00:00:01",
                                              hostname="HaleHound-CYD")]
    assert "halehound_cyd" in ids
    ids2 = [m["id"] for m in dc.detect_threats("Espressif Inc.", "AC:67:B2:00:00:01",
                                               hostname="", ports=[80])]
    assert "halehound_cyd" not in ids2 and "rogue_espressif" in ids2


def test_wifi_defense_auth_flood_detected():
    auths = [{"kind": "auth", "src": "02:%02x:%02x:00:aa:bb" % (i, i),
              "dst": "aa:bb:cc:00:00:01"} for i in range(40)]
    res = wd.analyze(auths)
    af = next((d for d in res["detections"] if d["type"] == "auth_flood"), None)
    assert af and af["severity"] == "flood"


def test_assess_end_to_end_confirmed():
    v = hh.assess(
        wifi={"detections": [{"type": "rogue_ap", "severity": "evil_twin"},
                             {"type": "deauth", "severity": "flood"}]},
        assets={"assets": [{"mac": "AC:67:B2:00:00:01", "hostname": "halehound",
                            "threats": [{"id": "halehound_cyd"}]}]},
        ble_devices=[{"mac": "C0:00:00:00:00:%02x" % i, "company_key": 0x004C,
                      "addr_type": "random"} for i in range(8)],
        portal_obs={"dns_answers": ["10.0.0.1"] * 4, "http_status": 302,
                    "redirect_host": "10.0.0.1", "ap_ip": "10.0.0.1"})
    assert v["verdict"] == "confirmed"
    alert = hh.to_alert(v)
    assert alert["source"] == "halehound" and alert["codes"] == ["HH-CONFIRM"]


def test_generalizes_to_sibling_esp32_tools():
    # A named ESP32 Marauder / deauther / Flipper on the LAN scores like a named
    # HaleHound — this is a general ESP32 attack-tool detector, not HaleHound-only.
    for tid in ("esp32_marauder", "esp_deauther", "flipper_wifi"):
        v = hh.score({"lan": [tid]})
        assert v["score"] >= 60 and v["verdict"] in ("likely", "confirmed"), (tid, v)
    # And a Marauder's Wi-Fi behaviour alone (no name) still fuses like any tool.
    v = hh.score({"wifi": [{"type": "beacon_flood", "severity": "flood"}],
                  "lan": ["rogue_espressif"],
                  "ble": [{"type": "ble_advert_flood"}]})
    assert len(v["domains"]) >= 3


def test_alert_title_names_the_class_not_just_halehound():
    v = hh.score({"lan": ["esp32_marauder"], "ble": [{"type": "swiftpair_spam"}],
                  "wifi": [{"type": "auth_flood", "severity": "flood"}]})
    title = hh.to_alert(v)["title"]
    assert "ESP32" in title and "Marauder" in title


def test_quiet_esp32_iot_never_alerts():
    # A home full of unknown ESP32 IoT (smart plugs/sensors) must score zero —
    # no stacking, no verdict, no alert. This is the key false-positive guard.
    for n in (1, 3, 6, 12):
        v = hh.score({"lan": ["rogue_espressif"] * n})
        assert v["verdict"] == "none" and v["score"] == 0, (n, v)


def test_unknown_esp32_needs_attack_grade_corroboration():
    # Ambient signals (a few stray deauths, a dense airspace) must NOT let an
    # unknown ESP32 tip into an emitting verdict...
    for weak in ({"type": "deauth", "severity": "seen"},
                 {"type": "beacon_flood", "severity": "beacon_warn"}):
        v = hh.score({"lan": ["rogue_espressif"], "wifi": [weak]})
        assert v["score"] < 25, (weak, v)
    # ...but a real flood does corroborate.
    v = hh.score({"lan": ["rogue_espressif"],
                  "wifi": [{"type": "auth_flood", "severity": "flood"}]})
    assert v["domain_scores"]["lan"] > 0 and v["score"] >= 25, v


def test_portal_observation_parse_and_signature_match():
    page = ("<html><head><title>GARMR Sign In</title></head><body>"
            "<form><input name='username'><input name='password'></form>"
            "<!-- garmr --></body></html>")
    obs = hh.parse_portal_observation(page, {"Server": "ESP32-HTTPD"}, 200)
    assert obs["title"] == "GARMR Sign In"
    assert obs["form_fields"] == ["password", "username"]
    assert obs["server"] == "ESP32-HTTPD" and len(obs["html_sha256"]) == 64
    # Empty production table => never matches (no false positive).
    assert hh.match_portal_signature(obs) is None
    # A supplied signature matches.
    synth = [{"name": "GARMR test", "title_contains": "garmr",
              "form_fields": ["username", "password"], "html_markers": ["garmr"]}]
    assert hh.match_portal_signature(obs, synth)["name"] == "GARMR test"


def test_matched_signature_confirms_without_dns_hijack():
    # A matched GARMR signature alone floors the verdict to confirmed.
    matched = {"garmr_signature": "GARMR test", "signature_confidence": "confirmed",
               "confirmed": True}
    assert hh.score({"portal": matched})["verdict"] == "confirmed"
    # Empty table + a benign page => no confirm, no alert.
    obs = hh.parse_portal_observation("<html><title>Login</title></html>", {}, 200)
    fp = hh.fingerprint_portal([], observed=obs)
    assert not fp["confirmed"] and fp["garmr_signature"] is None
