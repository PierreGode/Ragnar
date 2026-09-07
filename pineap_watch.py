"""pineap_watch.py — Wi-Fi Pineapple / PineAP-family detection & scoring.

This is a **behavioural** detector for the Hak5 Wi-Fi Pineapple family — Mark VII
(and AC), Enterprise, and Pager (the "v8" PineAP engine). It does NOT sniff
frames itself: it *scores* signals other Ragnar subsystems already produce
(``wifi_defense.analyze()`` passive WIDS output, the LAN asset inventory, and an
optional HuginnESP ESP32 companion), fusing them into a
``possible → likely → confirmed`` verdict — the same way ``halehound_watch.py``
scores the ESP32-attack-multitool class. Everything here is passive analysis;
this module transmits nothing.

WHY THE FAMILY SHARES ONE SIGNATURE
-----------------------------------
PineAP is the same rogue-AP engine across Mark VII / Enterprise / Pager (Pager's
"v8" is a performance rewrite, not a new attack surface). Detection therefore
targets *behaviour*, not a fixed hardware fingerprint — exactly how RayHunter
finds cell-site simulators. The tells, in decreasing strength:

  * **SSID pool from one BSSID** — a single BSSID answering many distinct SSIDs
    (Karma/Dogma/"PineAP pool"). This is ``wifi_defense``'s ``karma`` detection.
    The larger the pool, the more PineAP-consistent (a home VAP router tops out
    at 2-4 SSIDs; even a dense enterprise controller rarely exceeds ~8 per BSSID
    — a recon-fed PineAP pool runs to dozens).
  * **The ``wifipineapple`` management SSID** — the Pineapple's own default
    management AP. A near-certain, Hak5-specific tell (a *name* match, so it is
    trivially defeated by renaming — its absence proves nothing).
  * **A Pineapple management host on the LAN** — the web UI on tcp/1471 or
    tcp/8080, or a ``pineapple`` hostname (``device_classifier`` id
    ``wifi_pineapple``).
  * **Cross-BSSID pool** — the SAME set of unusual SSIDs appearing under several
    BSSIDs at once. This is the fallback for the randomized-BSSID mode (newest
    PineAP, esp. Pager) that defeats the single-BSSID pool test: the pool is
    still there, just smeared across many spoofed MACs.
  * **Spoofed / locally-administered BSSID** advertising SSIDs (randomized rig).
  * **Deauthentication activity** — PineAP commonly deauths to force clients to
    reconnect into the pool. Corroborating, not decisive.

WHAT THIS CAN AND CANNOT DO
---------------------------
You cannot *uniquely* fingerprint a Pineapple, nor cleanly tell PineAP apart
from other KARMA/MANA rigs (hostapd-mana, an ESP32 Marauder in KARMA mode): they
produce the same "one BSSID, many SSIDs" shape. So this module scores a
**PineAP-family / Pineapple-class** verdict, not "that is a Mark VII". What
raises confidence toward the Pineapple specifically is pool *magnitude*, the
``wifipineapple`` management name, and a management host on the LAN — otherwise a
strong pool honestly reads as "KARMA/PineAP-class rogue AP".

Blind spots (honest, like halehound_watch): a purely **passive** Pineapple (pool
off, not answering probes) emits almost nothing to see; **MAC randomization**
defeats the single-BSSID pool test (the cross-BSSID metric is the partial
answer); and a Pi Zero 2W's onboard radio is 2.4 GHz-only and **cannot do
monitor mode at all** (brcmfmac), so the passive-RF path needs an external
monitor adapter or the HuginnESP companion — 5/6 GHz Enterprise/Pager activity
is invisible without dual-band hardware.
"""

import re
import time

# --------------------------------------------------------------------------
# Verdict tiers keyed on the final 0-100 score. Mirrors halehound_watch tiers
# so Watchtower renders both detectors consistently.
# --------------------------------------------------------------------------
_TIERS = (
    (75, "confirmed", "critical", "PA-CONFIRM"),
    (50, "likely", "high", "PA-LIKELY"),
    (25, "possible", "medium", "PA-POSSIBLE"),
    (1, "trace", "low", "PA-TRACE"),
    (0, "none", "info", "PA-NONE"),
)

# Pool-size bands (distinct SSIDs answered by ONE BSSID). _POOL_MIN mirrors
# wifi_defense._KARMA_SSID_MIN — below it wifi_defense emits no karma detection.
# _POOL_LARGE is set ABOVE what a legitimate enterprise multi-SSID controller
# puts on a single BSSID (~8 max), so a large pool is PineAP-consistent, not VAP.
_POOL_MIN = 5
_POOL_LARGE = 15

# Cross-BSSID pool: how many distinct SSIDs must each appear under >= 2 BSSIDs
# before we call it a smeared (randomized-MAC) pool rather than one mesh SSID.
_XBSSID_POOL_MIN = 4

# The Pineapple's own default management-AP SSID (name match, normalized).
_PINEAPPLE_MGMT_SSIDS = {"wifipineapple", "pineap", "pineapple"}

# RF-domain signal weights (0-100 additive, then domain-capped). Keyed by the
# (type, severity) of a wifi_defense.analyze() detection, except the two derived
# signals ("karma","pool_large"/"pool_small" and the cross-BSSID pool) which this
# module computes from the raw detections.
_RF_WEIGHTS = {
    ("karma", "pool_large"): 34,   # >=15 SSIDs from one BSSID — past any VAP
    ("karma", "pool_small"): 25,   # 5-14 SSIDs from one BSSID — KARMA/PineAP shape
    ("rogue_ap", "pineapple_name"): 40,   # 'WiFi Pineapple' mgmt AP — Hak5-specific
    ("rogue_ap", "attack_tool_ssid"): 10,  # some OTHER attack-tool name (weak for PineAP)
    ("rogue_ap", "xbssid_pool"): 20,      # same pool smeared across many BSSIDs
    ("rogue_ap", "evil_twin"): 16,
    ("rogue_ap", "duplicate_ssid"): 8,
    ("rogue_ap", "spoofed_bssid"): 14,    # LA/multicast BSSID = randomized rig
    ("deauth", "flood"): 12,              # reaping clients into the pool
    ("deauth", "seen"): 3,
    ("beacon_flood", "flood"): 8,
}

# LAN: a Hak5 Pineapple management interface on the wire (device_classifier id).
_LAN_WEIGHTS = {"wifi_pineapple": 40}

# Companion (HuginnESP ESP32): a pineap/evil-twin alert relayed over serial.
_COMPANION_WEIGHTS = {"pineap": 20, "evil_twin": 12}

# Per-domain caps. RF caps at 66 so even a strong passive pool cannot reach
# 'confirmed' (75) on its own — a KARMA rig that is not a Pineapple produces the
# same RF shape. Confirmation needs the management name, a LAN host, the ESP
# companion, or coincident multi-domain activity. LAN/companion are corroboration
# capped below 'confirmed' alone.
_DOMAIN_CAP = {"rf": 66, "lan": 45, "companion": 26}

# Coincidence bonus — the RayHunter principle: several independent indicators
# firing at once is the confidence, not any one signal. Keyed by how many
# DISTINCT tells fired (across all domains).
_MULTI_SIGNAL_BONUS = {2: 10, 3: 16, 4: 22, 5: 26}

# A weak RF signal (a few stray deauths) must not let a LAN/companion hint tip
# into a verdict; corroboration has to be attack-grade.
_CORROBORATION_MIN = 12


def _norm_ssid(ssid):
    """Lowercase an SSID and strip spaces/_/- for name matching (matches
    wifi_defense._norm_ssid so the two agree on 'WiFi Pineapple')."""
    if not ssid:
        return ""
    return re.sub(r"[\s_\-]+", "", str(ssid).strip().lower())


def _tier(score):
    for floor, name, sev, code in _TIERS:
        if score >= floor:
            return name, sev, code
    return "none", "info", "PA-NONE"


# --------------------------------------------------------------------------
# RF-signal extraction — turn wifi_defense detections into weighted PineAP tells
# --------------------------------------------------------------------------

def _rf_tells(detections):
    """Yield ``(key, weight, detail)`` PineAP tells from wifi_defense detections.

    ``detections`` is the ``detections`` list of a ``wifi_defense.analyze()``
    result. This is where a raw ``karma`` detection becomes a pool_small/large
    band, an ``attack_tool_ssid`` whose name is the Pineapple mgmt AP becomes the
    high-confidence ``pineapple_name`` tell, and a run of ``duplicate_ssid``
    detections becomes the cross-BSSID (randomized-pool) tell.
    """
    tells = []
    dup_ssids = set()          # for the cross-BSSID pool metric
    spoofed_present = False

    for d in detections or []:
        dtype = d.get("type")
        sev = d.get("severity")

        if dtype == "karma":
            n = int(d.get("ssid_count") or len(d.get("ssids") or []) or 0)
            if n < _POOL_MIN:
                continue
            band = "pool_large" if n >= _POOL_LARGE else "pool_small"
            w = _RF_WEIGHTS[("karma", band)]
            tells.append(("karma:" + band, w,
                          f"{d.get('bssid')} answered {n} distinct SSIDs — "
                          + ("large PineAP-class pool (past any legit multi-SSID AP)"
                             if band == "pool_large"
                             else "KARMA/PineAP-class SSID pool")))
            continue

        if dtype == "rogue_ap":
            if sev == "attack_tool_ssid":
                # Split the generic attack-tool name from the Pineapple-specific
                # management SSID — the latter is a near-certain Hak5 tell.
                if _norm_ssid(d.get("ssid")) in _PINEAPPLE_MGMT_SSIDS:
                    tells.append(("rogue_ap:pineapple_name",
                                  _RF_WEIGHTS[("rogue_ap", "pineapple_name")],
                                  f"SSID '{d.get('ssid')}' is the Wi-Fi Pineapple's "
                                  "default management AP name"))
                else:
                    tells.append(("rogue_ap:attack_tool_ssid",
                                  _RF_WEIGHTS[("rogue_ap", "attack_tool_ssid")],
                                  d.get("detail", "attack-tool SSID name")))
                continue
            if sev == "duplicate_ssid" and d.get("ssid"):
                dup_ssids.add(d.get("ssid"))
            if sev == "spoofed_bssid":
                spoofed_present = True
            w = _RF_WEIGHTS.get(("rogue_ap", sev))
            if w:
                tells.append(("rogue_ap:" + sev, w, d.get("detail", "")))
            continue

        w = _RF_WEIGHTS.get((dtype, sev))
        if w:
            tells.append((f"{dtype}:{sev}", w, d.get("detail", "")))

    # Derived: a cross-BSSID pool. Several distinct SSIDs each appearing under
    # multiple BSSIDs is the shape of a randomized-MAC PineAP pool (Pager) that
    # the single-BSSID karma test can't catch. Require a spoofed/LA BSSID too, so
    # a couple of ordinary duplicate SSIDs (mesh a baseline hasn't cleared) don't
    # trip it.
    if len(dup_ssids) >= _XBSSID_POOL_MIN and spoofed_present:
        tells.append(("rogue_ap:xbssid_pool",
                      _RF_WEIGHTS[("rogue_ap", "xbssid_pool")],
                      f"{len(dup_ssids)} SSIDs each advertised by multiple "
                      "BSSIDs alongside a spoofed BSSID — randomized-MAC PineAP "
                      "pool (Pager-style)"))
    return tells


# --------------------------------------------------------------------------
# Scoring (pure)
# --------------------------------------------------------------------------

def score(signals):
    """Fuse PineAP signals into a scored verdict (pure — no I/O).

    ``signals`` (all optional):
        rf:        list of ``wifi_defense.analyze()`` detection dicts.
        lan:       list of LAN threat ids (e.g. ``['wifi_pineapple']``).
        companion: list of HuginnESP alert dicts (``{'type': 'pineap'|'evil_twin', ...}``).

    Returns a verdict dict: score, verdict, severity, code, domains,
    domain_scores, reasons.
    """
    signals = signals or {}
    reasons = []
    domain_raw = {"rf": 0, "lan": 0, "companion": 0}
    fired = set()          # distinct tell keys, for the coincidence bonus
    mgmt_name_seen = False

    for key, w, detail in _rf_tells(signals.get("rf")):
        domain_raw["rf"] += w
        fired.add(key)
        if key == "rogue_ap:pineapple_name":
            mgmt_name_seen = True
        reasons.append({"domain": "rf", "signal": key, "weight": w, "detail": detail})

    # LAN — a Pineapple management interface on the wire. Deduped so N sightings
    # of one host don't stack.
    lan_ids = signals.get("lan", []) or []
    lan_host_seen = False
    for tid in dict.fromkeys(lan_ids):
        w = _LAN_WEIGHTS.get(tid)
        if not w:
            continue
        domain_raw["lan"] += w
        fired.add("lan:" + tid)
        lan_host_seen = True
        reasons.append({"domain": "lan", "signal": tid, "weight": w,
                        "detail": f"'{tid}' — Hak5 Pineapple management host on the LAN"})

    # Companion (ESP32) alerts — corroboration only; capped low because the ESP's
    # own pineapple heuristic is coarse.
    for alert in signals.get("companion", []) or []:
        w = _COMPANION_WEIGHTS.get(alert.get("type"))
        if not w:
            continue
        domain_raw["companion"] += w
        fired.add("companion:" + alert.get("type"))
        reasons.append({"domain": "companion", "signal": alert.get("type"),
                        "weight": w, "detail": alert.get("detail",
                        "HuginnESP companion flagged pineapple/evil-twin activity")})

    capped = {d: min(v, _DOMAIN_CAP[d]) for d, v in domain_raw.items()}
    base = sum(capped.values())

    active_domains = [d for d, v in capped.items() if v > 0]

    # Coincidence bonus on the count of DISTINCT tells (not domains): the tell
    # that several indicators fire at once. A lone strong pool gets no bonus.
    bonus = _MULTI_SIGNAL_BONUS.get(min(len(fired), 5), 0)
    if bonus:
        reasons.append({"domain": "correlation", "signal": "multi_signal",
                        "weight": bonus,
                        "detail": f"{len(fired)} independent PineAP indicators "
                                  "coincident — positive-identification threshold"})

    total = min(100, base + bonus)

    # Floor 1: the Wi-Fi Pineapple's own management-AP SSID is a Hak5-specific
    # near-certain tell — never rank it below 'confirmed'.
    if mgmt_name_seen and total < 75:
        total = 75
        reasons.append({"domain": "rf", "signal": "mgmt_name_floor", "weight": 0,
                        "detail": "Pineapple management-AP name present — floored "
                                  "to 'confirmed'"})

    # Floor 2: a Pineapple management host on the LAN is high-confidence on its
    # own — floor to 'likely'; any real RF pool then lifts it to 'confirmed'.
    if lan_host_seen and total < 60:
        total = 60
        reasons.append({"domain": "lan", "signal": "lan_host_floor", "weight": 0,
                        "detail": "Pineapple management host on the LAN — floored "
                                  "to 'likely'"})

    tier_name, sev, code = _tier(total)
    return {
        "score": total,
        "verdict": tier_name,
        "severity": sev,
        "code": code,
        "domains": active_domains,
        "domain_scores": capped,
        "signals": sorted(fired),
        "reasons": reasons,
    }


# --------------------------------------------------------------------------
# Adapters — pull signals out of existing subsystem outputs
# --------------------------------------------------------------------------

def _lan_pineapple_from_assets(assets):
    """Collect the ``wifi_pineapple`` threat id + the hosts carrying it."""
    ids = []
    suspects = []
    for a in (assets or []):
        for t in (a.get("threats") or []):
            if t.get("id") == "wifi_pineapple":
                ids.append("wifi_pineapple")
                suspects.append({"mac": a.get("mac"), "ip": a.get("ip"),
                                 "hostname": a.get("hostname"),
                                 "threat": "wifi_pineapple"})
    return ids, suspects


def _companion_alerts(alerts):
    """Normalize wardriving ESP alert buffers into companion signals.

    ``alerts`` is a list of ``companion.esp_alert_buffer``-shaped dicts
    (``{'type': 'pineap'|'evil_twin'|'skimmer', 'bssid':..., 'ssids':...}``).
    Skimmer alerts are not a PineAP signal and are dropped.
    """
    out = []
    for a in alerts or []:
        t = a.get("type")
        if t in _COMPANION_WEIGHTS:
            out.append(a)
    return out


def _rf_suspects(detections):
    """Pull the BSSIDs/SSIDs worth naming in the alert from the RF detections."""
    suspects = []
    for d in detections or []:
        if d.get("type") == "karma":
            suspects.append({"bssid": d.get("bssid"), "kind": "ssid_pool",
                             "ssid_count": d.get("ssid_count"),
                             "ssids": (d.get("ssids") or [])[:8]})
        elif d.get("type") == "rogue_ap" and d.get("severity") in (
                "attack_tool_ssid", "spoofed_bssid", "evil_twin"):
            suspects.append({"bssid": d.get("bssid"), "ssid": d.get("ssid"),
                             "kind": d.get("severity")})
    return suspects


def assess(wifi=None, assets=None, companion_alerts=None):
    """One-shot PineAP assessment from live subsystem outputs.

    Args:
        wifi: a ``wifi_defense.analyze()`` result (uses ``detections``) or a bare
              list of detection dicts.
        assets: an ``asset_inventory.inventory()`` result (uses ``assets``) or a
                bare list of asset dicts.
        companion_alerts: a list of HuginnESP ``esp_alert_buffer`` dicts.

    Returns the ``score`` verdict enriched with ``suspects``.
    """
    if isinstance(wifi, dict):
        rf_dets = wifi.get("detections", []) or []
    elif isinstance(wifi, list):
        rf_dets = wifi
    else:
        rf_dets = []

    asset_list = assets.get("assets") if isinstance(assets, dict) else (assets or [])
    lan_ids, lan_suspects = _lan_pineapple_from_assets(asset_list)

    verdict = score({
        "rf": rf_dets,
        "lan": lan_ids,
        "companion": _companion_alerts(companion_alerts),
    })
    verdict["suspects"] = _rf_suspects(rf_dets) + lan_suspects
    return verdict


def to_alert(verdict, suspects=None):
    """Render a verdict as a Watchtower-style alert dict (source 'pineap')."""
    suspects = suspects if suspects is not None else verdict.get("suspects", [])
    _cls = "Wi-Fi Pineapple / PineAP-family rogue AP"
    title = {
        "confirmed": _cls + " CONFIRMED",
        "likely": _cls + " likely present",
        "possible": "Possible " + _cls,
        "trace": "Trace of PineAP-class activity",
        "none": "No PineAP activity",
    }.get(verdict.get("verdict"), "PineAP assessment")
    return {
        "source": "pineap",
        "title": title,
        "severity": verdict.get("severity", "info"),
        "codes": [verdict.get("code", "PA-NONE")],
        "score": verdict.get("score", 0),
        "domains": verdict.get("domains", []),
        "suspects": suspects,
        "detail": "; ".join(r["detail"] for r in verdict.get("reasons", [])
                            if r.get("detail")),
        "ts": time.time(),
    }


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, cond, detail=""):
        results.append({"name": name, "pass": bool(cond), "detail": detail})

    import json

    # --- Core pool signal ---
    big_pool = score({"rf": [{"type": "karma", "severity": "karma",
                              "bssid": "00:13:37:00:00:01", "ssid_count": 22,
                              "ssids": ["a", "b", "c"]}]})
    check("large pool alone => at least 'likely', capped below 'confirmed'",
          big_pool["score"] >= 34 and big_pool["verdict"] in ("possible", "likely")
          and big_pool["score"] < 75, json.dumps(big_pool))
    small_pool = score({"rf": [{"type": "karma", "severity": "karma",
                                "bssid": "00:13:37:00:00:01", "ssid_count": 6}]})
    check("small pool alone stays 'possible' (enterprise VAP can do ~8)",
          small_pool["verdict"] == "possible" and small_pool["score"] < 50,
          json.dumps(small_pool))

    # --- The Pineapple management-AP name => confirmed floor ---
    mgmt = score({"rf": [{"type": "rogue_ap", "severity": "attack_tool_ssid",
                          "ssid": "WiFi Pineapple", "bssid": "00:c0:ca:00:00:01"}]})
    check("'WiFi Pineapple' mgmt SSID => confirmed", mgmt["verdict"] == "confirmed",
          json.dumps(mgmt))
    # A DIFFERENT attack-tool name is NOT the Pineapple => stays weak.
    other = score({"rf": [{"type": "rogue_ap", "severity": "attack_tool_ssid",
                           "ssid": "Marauder", "bssid": "00:00:00:00:00:02"}]})
    check("a non-Pineapple attack-tool name stays a trace",
          other["verdict"] == "trace", json.dumps(other))

    # --- LAN management host floors to 'likely'; pool lifts to 'confirmed' ---
    lan = score({"lan": ["wifi_pineapple"]})
    check("Pineapple LAN host alone => at least 'likely'",
          lan["verdict"] in ("likely", "confirmed") and lan["score"] >= 60,
          json.dumps(lan))
    lan_dup = score({"lan": ["wifi_pineapple", "wifi_pineapple"]})
    check("duplicate LAN sightings don't stack past the cap",
          lan_dup["domain_scores"]["lan"] <= _DOMAIN_CAP["lan"], json.dumps(lan_dup))
    lan_plus_pool = score({"lan": ["wifi_pineapple"],
                           "rf": [{"type": "karma", "severity": "karma",
                                   "bssid": "00:13:37:00:00:01", "ssid_count": 20}]})
    check("LAN host + RF pool => confirmed (two domains)",
          lan_plus_pool["verdict"] == "confirmed"
          and len(lan_plus_pool["domains"]) >= 2, json.dumps(lan_plus_pool))

    # --- Coincidence: several tells => positive ID (RayHunter principle) ---
    multi = score({"rf": [
        {"type": "karma", "severity": "karma", "bssid": "00:13:37:00:00:01",
         "ssid_count": 12},
        {"type": "rogue_ap", "severity": "spoofed_bssid", "bssid": "03:00:00:00:00:01",
         "ssid": "Starbucks"},
        {"type": "deauth", "severity": "flood"},
    ]})
    check("pool + spoofed BSSID + deauth flood => likely+ with a bonus",
          multi["score"] >= 50
          and any(r["signal"] == "multi_signal" for r in multi["reasons"]),
          json.dumps({"s": multi["score"], "v": multi["verdict"]}))

    # --- Randomized-MAC (Pager) cross-BSSID pool fallback ---
    xb = score({"rf": [
        {"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "Home"},
        {"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "attwifi"},
        {"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "xfinitywifi"},
        {"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "Guest"},
        {"type": "rogue_ap", "severity": "spoofed_bssid", "ssid": "Home",
         "bssid": "02:00:00:00:00:01"},
    ]})
    check("cross-BSSID pool + spoofed BSSID => xbssid_pool tell fires",
          "rogue_ap:xbssid_pool" in xb["signals"] and xb["score"] >= 25,
          json.dumps(xb["signals"]))
    # Two ordinary duplicate SSIDs with no spoofed BSSID must NOT trip it.
    dup_only = score({"rf": [
        {"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "Home"},
        {"type": "rogue_ap", "severity": "duplicate_ssid", "ssid": "Guest"},
    ]})
    check("a couple of duplicate SSIDs (no spoof) => no xbssid pool, stays low",
          "rogue_ap:xbssid_pool" not in dup_only["signals"]
          and dup_only["score"] < 25, json.dumps(dup_only))

    # --- FP guards: quiet air / weak corroboration ---
    check("no signals => none", score({})["verdict"] == "none")
    stray = score({"rf": [{"type": "deauth", "severity": "seen"}]})
    check("a few stray deauths alone => below alert threshold",
          stray["score"] < 25, json.dumps(stray))
    # A lone ESP companion 'pineap' alert (coarse heuristic) must not confirm.
    comp = score({"companion": [{"type": "pineap"}]})
    check("lone ESP companion alert stays below 'likely'",
          comp["score"] < 50, json.dumps(comp))
    # ESP companion + a real RF pool corroborate up.
    comp_corr = score({"companion": [{"type": "pineap"}],
                       "rf": [{"type": "karma", "severity": "karma",
                               "bssid": "00:13:37:00:00:01", "ssid_count": 18}]})
    check("ESP companion corroborates a real pool => likely+",
          comp_corr["score"] >= 50, json.dumps(comp_corr))

    # --- assess() adapter over subsystem-shaped inputs ---
    v = assess(
        wifi={"detections": [
            {"type": "karma", "severity": "karma", "bssid": "00:13:37:00:00:01",
             "ssid_count": 25, "ssids": ["corp", "guest", "attwifi"]},
            {"type": "deauth", "severity": "flood"},
        ]},
        assets={"assets": [
            {"mac": "00:C0:CA:00:00:01", "ip": "172.16.42.1",
             "hostname": "pineapple",
             "threats": [{"id": "wifi_pineapple", "name": "Hak5 WiFi Pineapple"}]},
        ]},
        companion_alerts=[{"type": "pineap", "bssid": "00:13:37:00:00:01"}],
    )
    check("assess() fuses RF + LAN + companion => confirmed",
          v["verdict"] == "confirmed" and set(v["domains"]) >= {"rf", "lan", "companion"},
          json.dumps({"v": v["verdict"], "s": v["score"], "d": v["domains"]}))
    check("assess() surfaces the Pineapple management host",
          any(s.get("hostname") == "pineapple" for s in v["suspects"]),
          json.dumps(v["suspects"]))
    check("assess() surfaces the SSID-pool BSSID",
          any(s.get("kind") == "ssid_pool" for s in v["suspects"]))

    alert = to_alert(v)
    check("to_alert emits a pineap Watchtower alert",
          alert["source"] == "pineap" and alert["codes"] == ["PA-CONFIRM"],
          json.dumps({"src": alert["source"], "codes": alert["codes"]}))

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


if __name__ == "__main__":
    r = selftest()
    print("PASS" if r["pass"] else "FAIL", r["passed"], "/", r["total"])
    for x in r["results"]:
        if not x["pass"]:
            print("  FAIL:", x["name"], "::", x.get("detail", ""))
