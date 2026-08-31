"""halehound_watch.py — ESP32 attack-tool detection & multi-domain correlation.

This is a general **ESP32 attack-multitool** detector — HaleHound-CYD included,
but by no means only it. HaleHound-CYD
(https://github.com/JesseCHale/HaleHound-CYD) is an ESP32 attack multitool: 40+
modules across Wi-Fi (deauth, beacon spam, auth flood, evil-twin "GARMR" captive
portal, KARMA), BLE (Fast Pair spam, FindMy/AirTag flood, tracker spoofing),
2.4 GHz NRF24, SubGHz CC1101 and NFC. ESP32 Marauder, Bruce and Ghost ESP run
the same silicon and the same techniques.

WHAT THIS CAN AND CANNOT DO
---------------------------
You cannot *uniquely* fingerprint HaleHound — nor tell it apart from Marauder /
Bruce / Ghost ESP: same silicon, same techniques, and it randomizes its source
MACs during floods. So this module does NOT claim "that is HaleHound". It scores
how strongly the *observed behaviour* matches an ESP32 attack multitool of that
class (HaleHound, Marauder, Bruce, …), fusing signals across domains:

  * Wi-Fi  — auth flood / evil-twin / beacon flood / KARMA / deauth
             (from ``wifi_defense.analyze()``) — tool-agnostic behaviour
  * LAN    — an Espressif host flagged as a known attack tool (``halehound_cyd``,
             ``esp32_marauder``, ``esp_deauther``, ``flipper_wifi``) or an unknown
             ESP32 (``rogue_espressif``) — from ``device_classifier.detect_threats``
  * BLE    — Apple (0x004C) FindMy/pairing flood, Microsoft Swift Pair spam,
             advertisement flood (from a ``bt_scanner`` snapshot, manufacturer
             data only — via ``detect_ble_attacks``)
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
# Named ESP32 attack tools (hostname-matched signatures) score high; an unknown
# ESP32 (rogue_espressif) is weaker corroboration.
_LAN_WEIGHTS = {"halehound_cyd": 40, "esp32_marauder": 34, "esp_deauther": 34,
                "flipper_wifi": 34, "rogue_espressif": 12}
# The named-tool ids — a match to any is high-confidence on its own.
_NAMED_TOOL_IDS = ("halehound_cyd", "esp32_marauder", "esp_deauther", "flipper_wifi")
_BLE_WEIGHTS = {"apple_ble_flood": 18, "swiftpair_spam": 14, "ble_advert_flood": 12}
_PORTAL_WEIGHT = 30

# A domain cannot contribute more than this on its own.
_DOMAIN_CAP = {"wifi": 45, "lan": 45, "ble": 34, "portal": 30}

# Minimum attack-grade contribution from a behaviour domain before an UNKNOWN
# Espressif host (common IoT) is allowed to corroborate. A real flood/rogue/
# evil-twin/BLE-flood clears this; a few stray deauths ("seen"=3) or a dense
# airspace ("beacon_warn"=6) does not.
_CORROBORATION_MIN = 10

# Multi-domain bonus: coincident attacks across RF domains are the tell.
_MULTI_DOMAIN_BONUS = {2: 10, 3: 18, 4: 24}

# Verdict tiers keyed on the final 0-100 score.
_TIERS = (
    (75, "confirmed", "critical", "HH-CONFIRM"),
    (50, "likely", "high", "HH-LIKELY"),
    (25, "possible", "medium", "HH-POSSIBLE"),
    (1, "trace", "low", "HH-TRACE"),
    (0, "none", "info", "HH-NONE"),
)

# BLE-attack detection thresholds (per scan snapshot). NOTE: bt_scanner parses
# manufacturer-specific data (the 16-bit company id) only — NOT service-data
# UUIDs. So we detect the manufacturer-data pairing/tracker spam (Apple 0x004C,
# Microsoft 0x0006); Google Fast Pair (service-data UUID 0xFE2C) is a blind spot.
_APPLE_CID = 0x004C     # Apple — FindMy/AirTag + Continuity proximity-pairing
_MS_CID = 0x0006        # Microsoft — Swift Pair
_APPLE_MIN = 6          # distinct Apple 0x004C random advertisers => flood/spam
_SWIFTPAIR_MIN = 6      # distinct Microsoft 0x0006 advertisers => Swift Pair spam
_ADVERT_FLOOD_MIN = 25  # distinct random-address advertisers => advertisement flood

# ESP32 attack-tool threat ids we fuse from the LAN (HaleHound + its siblings:
# Marauder, ESP-deauther, Flipper Wi-Fi board — plus any unknown ESP32).
_CYD_THREAT_IDS = ("halehound_cyd", "esp32_marauder", "esp_deauther",
                   "flipper_wifi", "rogue_espressif")


# --------------------------------------------------------------------------
# BLE attack detection (#4) — pure, over a bt_scanner device snapshot
# --------------------------------------------------------------------------

def _is_random_addr(dev):
    """True if a BLE device advertises from a random/private address.

    The controller-reported address type (bt_scanner's ``addr_type``) is
    authoritative and used first. The address bits alone CANNOT distinguish a
    public address from a non-resolvable-private one, so the fallback is
    conservative: only the unambiguous random forms (static-random 0b11,
    resolvable-private 0b01 in the top two bits of the MSB octet) count.
    """
    at = (dev.get("addr_type") or "").lower()
    if at:
        return "random" in at
    if dev.get("is_random") is not None:
        return bool(dev["is_random"])
    mac = (dev.get("mac") or "").replace("-", ":")
    try:
        first = int(mac.split(":")[0], 16)
        return (first & 0xC0) in (0xC0, 0x40)  # static-random or resolvable-private
    except (ValueError, IndexError):
        return False


def detect_ble_attacks(devices, thresholds=None):
    """Flag ESP32-attack-tool BLE spam from a snapshot of advertisers.

    ``devices`` is a list of bt_scanner device dicts: ``{mac, company_key,
    addr_type|is_random, name}``. Pure function. Returns a list of attack dicts
    ``{type, count, detail}``.

    IMPORTANT — what is and isn't observable here: bt_scanner parses only
    *manufacturer-specific data* (the 16-bit company id), so this sees the
    Apple-Continuity (0x004C) and Microsoft Swift-Pair (0x0006) pairing/tracker
    spam that churns many random-address adverts at once. It does NOT see Google
    Fast Pair (advertised as service-data UUID 0xFE2C) or GATT-level attacks
    (BLE Predator honeypot, Airoha RACE, SkeletonKey) — those are separate blind
    spots, reported by ``assess()`` rather than guessed at. Real rooms hold only
    a handful of trackers/phones, so a burst of many is the tell.
    """
    th = thresholds or {}
    apple_min = int(th.get("apple_min", _APPLE_MIN))
    swiftpair_min = int(th.get("swiftpair_min", _SWIFTPAIR_MIN))
    flood_min = int(th.get("advert_flood_min", _ADVERT_FLOOD_MIN))

    apple_random = set()
    microsoft = set()
    random_adv = set()
    for d in devices or []:
        mac = (d.get("mac") or "").upper()
        if not mac:
            continue
        ck = d.get("company_key")
        rnd = _is_random_addr(d)
        if rnd:
            random_adv.add(mac)
        # Apple FindMy/AirTag + Continuity proximity-pairing ride company 0x004C
        # from random addresses.
        if ck == _APPLE_CID and rnd:
            apple_random.add(mac)
        # Microsoft Swift Pair rides company 0x0006.
        elif ck == _MS_CID:
            microsoft.add(mac)

    attacks = []
    if len(apple_random) >= apple_min:
        attacks.append({
            "type": "apple_ble_flood", "count": len(apple_random),
            "detail": f"{len(apple_random)} distinct Apple (0x004C) random-address "
                      "advertisers — FindMy/AirTag phantom flood or Apple "
                      "proximity-pairing (Continuity) spam",
        })
    if len(microsoft) >= swiftpair_min:
        attacks.append({
            "type": "swiftpair_spam", "count": len(microsoft),
            "detail": f"{len(microsoft)} distinct Microsoft (0x0006) advertisers — "
                      "Swift Pair pairing-popup spam",
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

    # LAN scored last so it can see whether any *behaviour* was observed.
    # Two false-positive guards, because ESP32 is one of the most common IoT
    # chips (smart plugs, sensors, bulbs — a home can hold a dozen):
    #  1) DEDUPE — a threat id scores once no matter how many hosts carry it, so
    #     N quiet ESP32s never stack into a verdict.
    #  2) rogue_espressif (an UNKNOWN ESP32 — no attack-tool hostname) is pure
    #     CORROBORATION: it adds weight only when real attack behaviour was seen
    #     elsewhere (Wi-Fi/BLE/portal) or a *named* tool is present. On its own,
    #     any number of unknown ESP32s scores zero — no alert.
    lan_ids = signals.get("lan", []) or []
    # Corroboration must be ATTACK-GRADE, not ambient: a weak/warn signal (a few
    # stray deauth frames, a dense-but-not-flooding airspace) shouldn't let a
    # smart plug tip into a verdict. Require a real flood/rogue-strength hit.
    behaviour_seen = any(domain_raw[d] >= _CORROBORATION_MIN
                         for d in ("wifi", "ble", "portal"))
    named_seen = any(t in _NAMED_TOOL_IDS for t in lan_ids)
    for tid in dict.fromkeys(lan_ids):          # unique, order-preserving
        w = _LAN_WEIGHTS.get(tid)
        if not w:
            continue
        if tid == "rogue_espressif" and not (behaviour_seen or named_seen):
            reasons.append({"domain": "lan", "signal": tid, "weight": 0,
                            "detail": "unknown Espressif host(s) present — no "
                                      "attack behaviour, so not scored (ESP32 is "
                                      "common IoT; corroboration only)"})
            continue
        domain_raw["lan"] += w
        reasons.append({"domain": "lan", "signal": tid, "weight": w,
                        "detail": f"Espressif host flagged '{tid}'"})

    # Apply per-domain caps, then sum.
    capped = {d: min(v, _DOMAIN_CAP[d]) for d, v in domain_raw.items()}
    base = sum(capped.values())

    active_domains = [d for d, v in capped.items() if v > 0]
    bonus = _MULTI_DOMAIN_BONUS.get(len(active_domains), 0)
    if bonus:
        reasons.append({"domain": "correlation", "signal": "multi_domain",
                        "weight": bonus,
                        "detail": f"coincident activity across {len(active_domains)} "
                                  f"domains ({', '.join(active_domains)}) — "
                                  "ESP32-multitool signature"})

    total = min(100, base + bonus)

    # Floor: a hostname-confirmed ESP32 attack tool (HaleHound, Marauder,
    # ESP-deauther, Flipper Wi-Fi board) on the LAN is high-confidence on its own
    # — never rank a named match below "likely".
    lan = signals.get("lan", []) or []
    named = [t for t in _NAMED_TOOL_IDS if t in lan]
    if named and total < 60:
        total = 60
        reasons.append({"domain": "lan", "signal": "name_match",
                        "weight": 0,
                        "detail": "hostname/name match to a known ESP32 attack tool "
                                  f"({', '.join(named)}) — verdict floored to 'likely'"})

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

    # Honest blind spots — attack surfaces this node cannot observe.
    verdict["blind_spots"] = [
        "NRF24 2.4 GHz (MouseJack, WLAN/BLE jammer) — needs an NRF24 receiver",
        "SubGHz 300-439 MHz (CC1101 replay/brute, Tesla) — needs an SDR/CC1101",
        "NFC/RFID cloning — no reader on this node",
        "Google Fast Pair (BLE service-data UUID 0xFE2C) — scan reads "
        "manufacturer data only",
        "GATT-level BLE (BLE Predator honeypot, Airoha RACE, SkeletonKey) — "
        "passive advertisement scan can't see connections",
    ]
    return verdict


def to_alert(verdict, suspects=None):
    """Render a verdict as a Watchtower-style alert dict (source 'halehound')."""
    suspects = suspects if suspects is not None else verdict.get("suspects", [])
    domains = verdict.get("domains", [])
    _cls = "ESP32 attack multitool (HaleHound / Marauder / Bruce-class)"
    title = {
        "confirmed": _cls + " CONFIRMED",
        "likely": _cls + " likely present",
        "possible": "Possible " + _cls,
        "trace": "Trace of ESP32 attack-tool activity",
        "none": "No ESP32 attack-tool activity",
    }.get(verdict.get("verdict"), "ESP32 attack-tool assessment")
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
    check("Apple FindMy/pairing flood detected (0x004C random burst)",
          any(a["type"] == "apple_ble_flood" for a in ble), json.dumps(ble))
    ms = [{"mac": "AA:BB:CC:00:00:%02x" % i, "company_key": 0x0006,
           "addr_type": "public"} for i in range(7)]
    check("Microsoft Swift Pair spam detected (0x0006 burst)",
          any(a["type"] == "swiftpair_spam" for a in detect_ble_attacks(ms)))
    # Public-address Apple devices (e.g. a real Mac) must NOT trip the flood.
    apple_public = [{"mac": "3C:22:FB:00:00:%02x" % i, "company_key": 0x004C,
                     "addr_type": "public"} for i in range(8)]
    check("public-address Apple devices => no Apple flood",
          not any(a["type"] == "apple_ble_flood"
                  for a in detect_ble_attacks(apple_public)))
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
        "ble": [{"type": "swiftpair_spam", "count": 7, "detail": "sp"}],
    })
    check("multi-domain (wifi+lan+ble) => confirmed/likely",
          multi["verdict"] in ("confirmed", "likely") and len(multi["domains"]) >= 3,
          json.dumps({"v": multi["verdict"], "s": multi["score"], "d": multi["domains"]}))
    check("multi-domain bonus applied",
          any(r["signal"] == "multi_domain" for r in multi["reasons"]))

    # --- False-positive guards (ESP32 is common IoT) ---
    # A room full of quiet, unknown ESP32 devices (smart plugs/sensors) must NOT
    # score at all — no stacking, no verdict, no alert.
    quiet_esp = score({"lan": ["rogue_espressif"] * 6})
    check("6 quiet unknown ESP32s => none (no stacking, no alert)",
          quiet_esp["verdict"] == "none" and quiet_esp["score"] == 0,
          json.dumps(quiet_esp))
    # An unknown ESP32 + only an AMBIENT signal (a few stray deauths) must stay a
    # trace, not tip into an emitting 'possible'.
    ambient = score({"lan": ["rogue_espressif"],
                     "wifi": [{"type": "deauth", "severity": "seen"}]})
    check("unknown ESP32 + ambient deauth => below alert threshold",
          ambient["score"] < 25, json.dumps(ambient))
    # But an unknown ESP32 DOES corroborate real attack-grade behaviour.
    corrob = score({"lan": ["rogue_espressif"],
                    "wifi": [{"type": "auth_flood", "severity": "flood"}]})
    check("unknown ESP32 corroborates a real flood",
          corrob["domain_scores"]["lan"] > 0 and corrob["score"] >= 25,
          json.dumps(corrob))

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
