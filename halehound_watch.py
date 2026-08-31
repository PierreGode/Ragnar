"""halehound_watch.py — HaleHound-CYD detection & multi-domain correlation.

HaleHound-CYD (https://github.com/JesseCHale/HaleHound-CYD) is an ESP32 "Cheap
Yellow Display" attack multitool: 40+ modules across Wi-Fi (deauth, beacon spam,
auth flood, evil-twin "GARMR" captive portal, KARMA), BLE (Fast Pair spam,
FindMy/AirTag flood, tracker spoofing), 2.4 GHz NRF24, SubGHz CC1101 and NFC.

WHAT THIS CAN AND CANNOT DO
---------------------------
You cannot *uniquely* fingerprint HaleHound. It runs on the same ESP32 silicon
and uses the same techniques as ESP32 Marauder, Bruce and Ghost ESP, and it
randomizes its source MACs during floods. So this module does NOT claim "that is
HaleHound". It scores how strongly the *observed behaviour* matches a HaleHound-
class CYD multitool, fusing signals across domains:

  * Wi-Fi  — auth flood / evil-twin / beacon flood / KARMA / deauth
             (from ``wifi_defense.analyze()``)
  * LAN    — an Espressif host flagged ``halehound_cyd`` / ``rogue_espressif``
             (from ``device_classifier.detect_threats`` via asset inventory)
  * BLE    — Fast Pair spam / FindMy flood / advertisement flood
             (from a ``bt_scanner`` device snapshot, via ``detect_ble_attacks``)
  * Portal — a GARMR-style DNS-hijack captive portal (``fingerprint_portal``)

The correlation is deliberately multi-domain: a single noisy domain is capped so
it can only reach a "possible" verdict on its own, while behaviour spanning two
or three RF domains at once — the CYD's signature — escalates to "likely" /
"confirmed". Everything here is passive analysis of signals other subsystems
already produce; this module transmits nothing.

Radios Ragnar has no receiver for (NRF24 MouseJack, SubGHz replay, NFC cloning)
are out of scope — they are reported as blind spots rather than faked.
"""

import json
import time

# --------------------------------------------------------------------------
# Signal weights (0-100 additive, then clamped). Per-domain caps below stop any
# one domain from reaching a high verdict alone — the CYD tell is multi-domain.
# --------------------------------------------------------------------------
_WIFI_WEIGHTS = {
    ("auth_flood", "flood"): 24,
    ("auth_flood", "auth_warn"): 8,
    ("rogue_ap", "evil_twin"): 20,
    ("rogue_ap", "duplicate_ssid"): 8,
    ("karma", "karma"): 18,
    ("beacon_flood", "flood"): 14,
    ("beacon_flood", "beacon_warn"): 6,
    ("deauth", "flood"): 10,
    ("deauth", "seen"): 3,
}
_LAN_WEIGHTS = {"halehound_cyd": 40, "rogue_espressif": 12}
_BLE_WEIGHTS = {"findmy_flood": 18, "fastpair_spam": 16, "ble_advert_flood": 12}
_PORTAL_WEIGHT = 30

# A domain cannot contribute more than this on its own.
_DOMAIN_CAP = {"wifi": 45, "lan": 45, "ble": 34, "portal": 30}

# Multi-domain bonus: coincident attacks across RF domains are the CYD signature.
_MULTI_DOMAIN_BONUS = {2: 10, 3: 18, 4: 24}

# Verdict tiers keyed on the final 0-100 score.
_TIERS = (
    (75, "confirmed", "critical", "HH-CONFIRM"),
    (50, "likely", "high", "HH-LIKELY"),
    (25, "possible", "medium", "HH-POSSIBLE"),
    (1, "trace", "low", "HH-TRACE"),
    (0, "none", "info", "HH-NONE"),
)

# BLE-attack detection thresholds (per scan snapshot).
_FINDMY_MIN = 6        # distinct Apple/FindMy random advertisers => Phantom Flood
_FASTPAIR_MIN = 6      # distinct Google/Fast Pair advertisers => pairing spam
_ADVERT_FLOOD_MIN = 25  # distinct random-address advertisers => advertisement flood

# CYD-family threat ids we treat as HaleHound-consistent on the LAN.
_CYD_THREAT_IDS = ("halehound_cyd", "rogue_espressif")


# --------------------------------------------------------------------------
# BLE attack detection (#4) — pure, over a bt_scanner device snapshot
# --------------------------------------------------------------------------

def _is_random_addr(dev):
    """True if a BLE device advertises from a random/private address."""
    at = (dev.get("addr_type") or "").lower()
    if at:
        return "random" in at
    if dev.get("is_random") is not None:
        return bool(dev["is_random"])
    # Fall back to the LE-random address rule: two MSBs of the first octet.
    mac = (dev.get("mac") or "").replace("-", ":")
    try:
        first = int(mac.split(":")[0], 16)
        return (first & 0xC0) in (0xC0, 0x00)  # static-random or resolvable/NRPA
    except (ValueError, IndexError):
        return False


def detect_ble_attacks(devices, thresholds=None):
    """Flag HaleHound-class BLE attacks from a snapshot of advertisers.

    ``devices`` is a list of bt_scanner device dicts: ``{mac, company_key,
    addr_type|is_random, name}``. Pure function. Returns a list of attack dicts
    ``{type, count, detail}``. The BLE Spoofer / WhisperPair / Lunatic Fringe
    modules all churn many random-address adverts at once — real rooms hold only
    a handful of trackers/phones, so a burst is the tell.
    """
    th = thresholds or {}
    findmy_min = int(th.get("findmy_min", _FINDMY_MIN))
    fastpair_min = int(th.get("fastpair_min", _FASTPAIR_MIN))
    flood_min = int(th.get("advert_flood_min", _ADVERT_FLOOD_MIN))

    apple_random = set()
    google = set()
    random_adv = set()
    for d in devices or []:
        mac = (d.get("mac") or "").upper()
        if not mac:
            continue
        ck = d.get("company_key")
        rnd = _is_random_addr(d)
        if rnd:
            random_adv.add(mac)
        # Apple FindMy/AirTag adverts ride company id 0x004C from random addrs.
        if ck == 0x004C and rnd:
            apple_random.add(mac)
        # Google Fast Pair uses company id 0x00E0.
        if ck == 0x00E0:
            google.add(mac)

    attacks = []
    if len(apple_random) >= findmy_min:
        attacks.append({
            "type": "findmy_flood", "count": len(apple_random),
            "detail": f"{len(apple_random)} distinct Apple/FindMy random-address "
                      "advertisers — FindMy/AirTag phantom flood or tracker spoof",
        })
    if len(google) >= fastpair_min:
        attacks.append({
            "type": "fastpair_spam", "count": len(google),
            "detail": f"{len(google)} distinct Google/Fast Pair advertisers — "
                      "BLE pairing-popup spam (Fast Pair)",
        })
    if len(random_adv) >= flood_min:
        attacks.append({
            "type": "ble_advert_flood", "count": len(random_adv),
            "detail": f"{len(random_adv)} distinct random-address BLE advertisers "
                      "— advertisement flood / pairing spam",
        })
    return attacks


# --------------------------------------------------------------------------
# GARMR captive-portal fingerprint (#3) — pure over observed DNS/HTTP behaviour
# --------------------------------------------------------------------------

def fingerprint_portal(dns_answers, http_status=None, redirect_host=None,
                       ap_ip=None):
    """Decide whether observed behaviour matches a GARMR-style evil-twin portal.

    HaleHound's Captive Portal (GARMR) is a fake AP + DNS hijack + credential
    page: *every* DNS query resolves to the AP's own IP, and HTTP is redirected
    to a harvest page. This is a PURE decision over already-collected
    observations — associating with a suspect AP to collect them is an active,
    hardware-dependent step left to the caller (and unvalidated here).

    Args:
        dns_answers: list of resolved IPs for several DISTINCT probe domains.
        http_status: HTTP status seen for a plain request (e.g. 302, 200).
        redirect_host: Location/host a redirect pointed at, if any.
        ap_ip: the AP's/gateway IP, if known.

    Returns ``{dns_hijack, captive_portal, confirmed, detail}``.
    """
    ips = [a for a in (dns_answers or []) if a]
    uniq = set(ips)
    # DNS hijack: many distinct domains all collapsing to a single IP.
    dns_hijack = len(ips) >= 3 and len(uniq) == 1
    hijack_ip = next(iter(uniq)) if dns_hijack else None
    if dns_hijack and ap_ip and hijack_ip != ap_ip:
        # Still a hijack, but note it does not point at the known AP IP.
        pass

    # Captive portal: a redirect to the hijack/AP IP, or an intercept status.
    captive_portal = False
    if http_status in (301, 302, 303, 307, 308):
        if redirect_host and (redirect_host == hijack_ip or redirect_host == ap_ip):
            captive_portal = True
        elif dns_hijack:
            captive_portal = True
    elif http_status == 200 and dns_hijack:
        # Portal answering everything with a page is the classic walled garden.
        captive_portal = True

    confirmed = dns_hijack and captive_portal
    bits = []
    if dns_hijack:
        bits.append(f"all DNS → {hijack_ip} (hijack)")
    if captive_portal:
        bits.append(f"HTTP {http_status} → captive portal")
    detail = ("GARMR-style evil-twin captive portal — " + ", ".join(bits)
              if bits else "no captive-portal signature")
    return {"dns_hijack": dns_hijack, "captive_portal": captive_portal,
            "confirmed": confirmed, "hijack_ip": hijack_ip, "detail": detail}


# --------------------------------------------------------------------------
# Correlation / scoring (#6) — the "HaleHound-class multitool" verdict
# --------------------------------------------------------------------------

def _tier(score):
    for floor, name, sev, code in _TIERS:
        if score >= floor:
            return name, sev, code
    return "none", "info", "HH-NONE"


def score(signals):
    """Fuse per-domain signals into a scored HaleHound-class verdict (pure).

    ``signals`` (all optional):
        wifi:   list of ``wifi_defense.analyze()`` detection dicts
                (``{type, severity, ...}``)
        lan:    list of threat ids seen on Espressif LAN hosts
                (e.g. ``['halehound_cyd']``)
        ble:    list of ``detect_ble_attacks`` dicts
        portal: a ``fingerprint_portal`` result dict

    Returns a verdict dict with score, tier, severity, per-domain breakdown and
    an explainable reason list.
    """
    signals = signals or {}
    reasons = []
    domain_raw = {"wifi": 0, "lan": 0, "ble": 0, "portal": 0}

    for det in signals.get("wifi", []) or []:
        w = _WIFI_WEIGHTS.get((det.get("type"), det.get("severity")))
        if w:
            domain_raw["wifi"] += w
            reasons.append({"domain": "wifi", "signal": det.get("type"),
                            "weight": w, "detail": det.get("detail", "")})

    for tid in signals.get("lan", []) or []:
        w = _LAN_WEIGHTS.get(tid)
        if w:
            domain_raw["lan"] += w
            reasons.append({"domain": "lan", "signal": tid, "weight": w,
                            "detail": f"Espressif host flagged '{tid}'"})

    for atk in signals.get("ble", []) or []:
        w = _BLE_WEIGHTS.get(atk.get("type"))
        if w:
            domain_raw["ble"] += w
            reasons.append({"domain": "ble", "signal": atk.get("type"),
                            "weight": w, "detail": atk.get("detail", "")})

    portal = signals.get("portal") or {}
    if portal.get("confirmed"):
        domain_raw["portal"] += _PORTAL_WEIGHT
        reasons.append({"domain": "portal", "signal": "garmr_portal",
                        "weight": _PORTAL_WEIGHT, "detail": portal.get("detail", "")})
    elif portal.get("dns_hijack"):
        domain_raw["portal"] += _PORTAL_WEIGHT // 2
        reasons.append({"domain": "portal", "signal": "dns_hijack",
                        "weight": _PORTAL_WEIGHT // 2, "detail": portal.get("detail", "")})

    # Apply per-domain caps, then sum.
    capped = {d: min(v, _DOMAIN_CAP[d]) for d, v in domain_raw.items()}
    base = sum(capped.values())

    active_domains = [d for d, v in capped.items() if v > 0]
    bonus = _MULTI_DOMAIN_BONUS.get(len(active_domains), 0)
    if bonus:
        reasons.append({"domain": "correlation", "signal": "multi_domain",
                        "weight": bonus,
                        "detail": f"coincident activity across {len(active_domains)} "
                                  f"domains ({', '.join(active_domains)}) — CYD signature"})

    total = min(100, base + bonus)

    # Floor: a hostname-confirmed HaleHound device on the LAN is high-confidence
    # on its own — never rank a named match below "likely".
    lan = signals.get("lan", []) or []
    if "halehound_cyd" in lan and total < 60:
        total = 60
        reasons.append({"domain": "lan", "signal": "name_match",
                        "weight": 0,
                        "detail": "hostname/name match to HaleHound/GARMR — verdict "
                                  "floored to 'likely'"})

    tier_name, sev, code = _tier(total)
    return {
        "score": total,
        "verdict": tier_name,
        "severity": sev,
        "code": code,
        "domains": active_domains,
        "domain_scores": capped,
        "reasons": reasons,
    }


# --------------------------------------------------------------------------
# Adapters — pull signals out of existing subsystem outputs
# --------------------------------------------------------------------------

def _lan_threats_from_assets(assets):
    """Collect CYD-consistent threat ids + the hosts carrying them."""
    ids = []
    suspects = []
    for a in (assets or []):
        for t in (a.get("threats") or []):
            tid = t.get("id")
            if tid in _CYD_THREAT_IDS:
                ids.append(tid)
                suspects.append({"mac": a.get("mac"), "ip": a.get("ip"),
                                 "hostname": a.get("hostname"), "threat": tid})
    return ids, suspects


def assess(wifi=None, assets=None, ble_devices=None, portal_obs=None,
           ble_thresholds=None):
    """One-shot HaleHound assessment from live subsystem outputs.

    Args:
        wifi: a ``wifi_defense.analyze()`` result (uses its ``detections``).
        assets: an ``asset_inventory.inventory()`` result (uses ``assets``) OR a
                bare list of asset dicts.
        ble_devices: a list of bt_scanner device dicts (snapshot).
        portal_obs: a dict of observed portal behaviour to pass through
                    ``fingerprint_portal`` (keys: dns_answers, http_status,
                    redirect_host, ap_ip), or an already-built fingerprint.

    Returns the ``score`` verdict enriched with ``suspects`` and ``blind_spots``.
    """
    wifi_dets = []
    if isinstance(wifi, dict):
        wifi_dets = wifi.get("detections", []) or []
    elif isinstance(wifi, list):
        wifi_dets = wifi

    asset_list = assets.get("assets") if isinstance(assets, dict) else (assets or [])
    lan_ids, suspects = _lan_threats_from_assets(asset_list)

    ble_attacks = detect_ble_attacks(ble_devices, ble_thresholds) if ble_devices else []

    portal = None
    if portal_obs:
        if "confirmed" in portal_obs or "dns_hijack" in portal_obs:
            portal = portal_obs  # already a fingerprint
        else:
            portal = fingerprint_portal(
                portal_obs.get("dns_answers"), portal_obs.get("http_status"),
                portal_obs.get("redirect_host"), portal_obs.get("ap_ip"))

    verdict = score({"wifi": wifi_dets, "lan": lan_ids,
                     "ble": ble_attacks, "portal": portal})
    verdict["suspects"] = suspects

    # Honest blind spots — radios Ragnar cannot receive on.
    verdict["blind_spots"] = [
        "NRF24 2.4 GHz (MouseJack, WLAN/BLE jammer) — needs an NRF24 receiver",
        "SubGHz 300-439 MHz (CC1101 replay/brute, Tesla) — needs an SDR/CC1101",
        "NFC/RFID cloning — no reader on this node",
    ]
    return verdict


def to_alert(verdict, suspects=None):
    """Render a verdict as a Watchtower-style alert dict (source 'halehound')."""
    suspects = suspects if suspects is not None else verdict.get("suspects", [])
    domains = verdict.get("domains", [])
    title = {
        "confirmed": "HaleHound-class attack multitool CONFIRMED",
        "likely": "HaleHound-class attack multitool likely present",
        "possible": "Possible HaleHound-class attack multitool",
        "trace": "Trace of HaleHound-class attack activity",
        "none": "No HaleHound activity",
    }.get(verdict.get("verdict"), "HaleHound assessment")
    return {
        "source": "halehound",
        "title": title,
        "severity": verdict.get("severity", "info"),
        "codes": [verdict.get("code", "HH-NONE")],
        "score": verdict.get("score", 0),
        "domains": domains,
        "suspects": suspects,
        "detail": "; ".join(r["detail"] for r in verdict.get("reasons", []) if r.get("detail")),
        "ts": time.time(),
    }


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, cond, detail=""):
        results.append({"name": name, "pass": bool(cond), "detail": detail})

    # --- BLE attack detection ---
    apple = [{"mac": "C0:11:22:33:44:%02x" % i, "company_key": 0x004C,
              "addr_type": "random"} for i in range(8)]
    ble = detect_ble_attacks(apple)
    check("FindMy/AirTag phantom flood detected",
          any(a["type"] == "findmy_flood" for a in ble), json.dumps(ble))
    google = [{"mac": "AA:BB:CC:00:00:%02x" % i, "company_key": 0x00E0,
               "addr_type": "public"} for i in range(7)]
    check("Fast Pair spam detected",
          any(a["type"] == "fastpair_spam" for a in detect_ble_attacks(google)))
    flood = [{"mac": "D0:00:00:00:%02x:%02x" % (i // 256, i % 256),
              "company_key": None, "addr_type": "random"} for i in range(30)]
    check("BLE advertisement flood detected",
          any(a["type"] == "ble_advert_flood" for a in detect_ble_attacks(flood)))
    calm = [{"mac": "3C:22:FB:00:00:01", "company_key": 0x004C, "addr_type": "public"},
            {"mac": "AC:DE:48:00:00:02", "company_key": 0x0075, "addr_type": "public"}]
    check("calm BLE room => no attack", detect_ble_attacks(calm) == [],
          json.dumps(detect_ble_attacks(calm)))

    # --- GARMR captive portal fingerprint ---
    fp = fingerprint_portal(["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1"],
                            http_status=302, redirect_host="10.0.0.1",
                            ap_ip="10.0.0.1")
    check("GARMR captive portal (DNS hijack + redirect) confirmed",
          fp["confirmed"] and fp["dns_hijack"], json.dumps(fp))
    real = fingerprint_portal(["142.250.1.1", "104.16.2.3", "13.107.4.5"],
                              http_status=200)
    check("real internet (varied DNS) => not a portal",
          not real["confirmed"] and not real["dns_hijack"], json.dumps(real))

    # --- Scoring / correlation ---
    # Single domain (Wi-Fi only, even a strong evil twin) is capped at "possible".
    wifi_only = score({"wifi": [
        {"type": "auth_flood", "severity": "flood", "detail": "auth flood"},
        {"type": "rogue_ap", "severity": "evil_twin", "detail": "evil twin"},
    ]})
    check("single-domain Wi-Fi attack capped below 'likely'",
          wifi_only["verdict"] in ("possible", "trace") and wifi_only["score"] < 50,
          json.dumps(wifi_only))

    # Multi-domain: Wi-Fi + LAN + BLE coincident => confirmed.
    multi = score({
        "wifi": [{"type": "auth_flood", "severity": "flood", "detail": "af"},
                 {"type": "karma", "severity": "karma", "detail": "karma"}],
        "lan": ["rogue_espressif"],
        "ble": [{"type": "fastpair_spam", "count": 7, "detail": "fp"}],
    })
    check("multi-domain (wifi+lan+ble) => confirmed/likely",
          multi["verdict"] in ("confirmed", "likely") and len(multi["domains"]) >= 3,
          json.dumps({"v": multi["verdict"], "s": multi["score"], "d": multi["domains"]}))
    check("multi-domain bonus applied",
          any(r["signal"] == "multi_domain" for r in multi["reasons"]))

    # Named HaleHound host on the LAN alone => floored to at least 'likely'.
    named = score({"lan": ["halehound_cyd"]})
    check("named HaleHound LAN host => at least 'likely'",
          named["verdict"] in ("likely", "confirmed") and named["score"] >= 60,
          json.dumps(named))

    # Nothing => none.
    check("no signals => verdict none", score({})["verdict"] == "none")

    # --- assess() adapter over subsystem-shaped inputs ---
    wifi_res = {"detections": [
        {"type": "rogue_ap", "severity": "evil_twin", "detail": "evil twin"},
        {"type": "deauth", "severity": "flood", "detail": "deauth flood"},
    ]}
    inv = {"assets": [
        {"mac": "AC:67:B2:00:00:01", "ip": "10.0.0.9", "hostname": "halehound",
         "threats": [{"id": "halehound_cyd", "name": "HaleHound-CYD"}]},
    ]}
    v = assess(wifi=wifi_res, assets=inv,
               ble_devices=[{"mac": "C0:11:22:33:44:%02x" % i,
                             "company_key": 0x004C, "addr_type": "random"}
                            for i in range(8)],
               portal_obs={"dns_answers": ["10.0.0.1"] * 4, "http_status": 302,
                           "redirect_host": "10.0.0.1", "ap_ip": "10.0.0.1"})
    check("assess() fuses all four domains => confirmed",
          v["verdict"] == "confirmed" and set(v["domains"]) >= {"wifi", "lan", "ble", "portal"},
          json.dumps({"v": v["verdict"], "s": v["score"], "d": v["domains"]}))
    check("assess() surfaces the suspect host",
          any(s.get("hostname") == "halehound" for s in v["suspects"]),
          json.dumps(v["suspects"]))
    check("assess() reports RF blind spots honestly", len(v["blind_spots"]) >= 3)

    alert = to_alert(v)
    check("to_alert emits a halehound Watchtower alert",
          alert["source"] == "halehound" and alert["codes"] == ["HH-CONFIRM"],
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
