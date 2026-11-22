"""Active PineAP probe-response test — pure/injected-dep tests (no radio)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pineap_active as pact         # noqa: E402
import pineap_watch as pa            # noqa: E402


def test_module_selftest_passes():
    r = pact.selftest()
    assert r["pass"], [x for x in r["results"] if not x["pass"]]


def test_random_ssids_and_mac():
    ss = pact.random_ssids(5, 10)
    assert len(ss) == 5 and len(set(ss)) == 5 and all(len(s) == 10 for s in ss)
    mac = pact.random_la_mac()
    first = int(mac.split(":")[0], 16)
    assert (first & 0x02) and not (first & 0x01)   # locally-administered, unicast


def test_evaluate_flags_answered_random_ssid():
    dets = pact.evaluate(["Zx9Qk2Vw7Lp1"],
                         [("Zx9Qk2Vw7Lp1", "00:13:37:00:00:01")])
    assert len(dets) == 1
    assert dets[0]["severity"] == "answers_random_probe"
    assert dets[0]["bssid"] == "00:13:37:00:00:01"


def test_evaluate_ignores_unsolicited_and_clean_air():
    # A response for an SSID we never probed is not a hit.
    assert pact.evaluate(["Rnd1"], [("Starbucks", "aa:bb:cc:00:00:01")]) == []
    # Nothing answered our random probe.
    assert pact.evaluate(["Rnd1"], []) == []


def test_run_detects_impersonate_all_pineapple():
    sent_log = []

    def fake_send(mon, ssid, src_mac, count=2):
        sent_log.append(ssid)

    def fake_sniff_all(mon, seconds):
        return [(s, "00:c0:ca:00:00:01") for s in sent_log[-pact._SSIDS_PER_ROUND:]]

    res = pact.run("wlan1", rounds=1, listen_seconds=1,
                   _resolve=lambda i, auto_enable=True: "ragmon0",
                   _tune=lambda m, c: None, _send=fake_send, _sniff=fake_sniff_all)
    assert res["ok"] and res["answered"] >= 1
    # Feeds straight into the scorer as a confirm.
    v = pa.assess(wifi={"detections": res["detections"]})
    assert v["verdict"] == "confirmed"


def test_run_clean_air_no_detection():
    res = pact.run("wlan1", rounds=2, listen_seconds=1,
                   _resolve=lambda i, auto_enable=True: "ragmon0",
                   _tune=lambda m, c: None, _send=lambda *a, **k: None,
                   _sniff=lambda m, s: [])
    assert res["ok"] and res["answered"] == 0
    v = pa.assess(wifi={"detections": res["detections"]})
    assert v["verdict"] == "none"


def test_run_returns_monitor_error_without_raising():
    res = pact.run("wlan1", _resolve=lambda i, auto_enable=True: {"error": "no monitor"})
    assert res.get("error") == "no monitor"


def test_run_reports_transmit_failure_gracefully():
    def boom(*a, **k):
        raise OSError("cannot send")
    res = pact.run("wlan1", rounds=1, listen_seconds=1,
                   _resolve=lambda i, auto_enable=True: "ragmon0",
                   _tune=lambda m, c: None, _send=boom, _sniff=lambda m, s: [])
    assert "error" in res and "transmit failed" in res["error"]
