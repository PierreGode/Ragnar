"""KARMA aggregation must ignore invalid (group/multicast) BSSIDs, and a lone
SSID pool must stay a 'possible' PineAP verdict (below the incident threshold)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wifi_defense as wd            # noqa: E402
import pineap_watch as pa            # noqa: E402


def _presp(src, ssid):
    return {"kind": "probe_resp", "src": src, "ssid": ssid}


def _karma(res):
    return [d for d in res["detections"] if d["type"] == "karma"]


def test_global_bssid_pool_flagged_as_karma():
    ev = [_presp("00:11:22:33:44:55", "net%d" % i) for i in range(6)]
    res = wd.analyze(ev)
    assert _karma(res) and _karma(res)[0]["bssid"] == "00:11:22:33:44:55"


def test_group_bit_bssid_not_aggregated_into_karma():
    # 0x7b has the I/G (group) bit set — an invalid AP address. It must NOT form
    # a KARMA pool (it's surfaced as spoofed_bssid instead).
    ev = [_presp("7b:f0:c7:25:69:96", "net%d" % i) for i in range(6)]
    res = wd.analyze(ev)
    assert not _karma(res), res["detections"]
    assert any(d["severity"] == "spoofed_bssid" for d in res["detections"])


def test_locally_administered_unicast_pool_still_flagged():
    # 0x06 is locally-administered but UNICAST (not group) — a randomized rig can
    # still be a real Pineapple, so KARMA still fires at the detection level.
    ev = [_presp("06:13:37:ad:b8:d4", "net%d" % i) for i in range(6)]
    res = wd.analyze(ev)
    assert _karma(res)


def test_lone_pool_is_possible_not_pageable():
    # A single small pool scores 'possible' (< 50), so it shows in the card but
    # does NOT cross the >=50 Watchtower-incident threshold.
    res = wd.analyze([_presp("06:13:37:ad:b8:d4", "net%d" % i) for i in range(6)])
    v = pa.assess(wifi=res)
    assert v["verdict"] == "possible" and v["score"] < 50


def test_large_lone_pool_also_below_incident_threshold():
    res = wd.analyze([_presp("06:13:37:ad:b8:d4", "net%d" % i) for i in range(20)])
    v = pa.assess(wifi=res)
    assert v["score"] < 50   # even a big lone pool won't page without corroboration
