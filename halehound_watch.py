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
_BLE_WEIGHTS = {"apple_ble_flood": 18, "swiftpair_spam": 14,
                "fastpair_spam": 16, "ble_advert_flood": 12}
# SubGHz (RTL-SDR via rtl_433): a replay/brute burst is an attack on its own;
# 'seen' is bare ISM telemetry (corroboration-weight only).
_SUBGHZ_WEIGHTS = {("subghz_replay", "flood"): 22, ("subghz_brute", "flood"): 22,
                   ("subghz_active", "seen"): 6}
_PORTAL_WEIGHT = 30

# A domain cannot contribute more than this on its own.
_DOMAIN_CAP = {"wifi": 45, "lan": 45, "ble": 34, "portal": 30, "subghz": 30}

# Minimum attack-grade contribution from a behaviour domain before an UNKNOWN
# Espressif host (common IoT) is allowed to corroborate. A real flood/rogue/
# evil-twin/BLE-flood clears this; a few stray deauths ("seen"=3) or a dense
# airspace ("beacon_warn"=6) does not.
_CORROBORATION_MIN = 10

# Multi-domain bonus: coincident attacks across RF domains are the tell.
_MULTI_DOMAIN_BONUS = {2: 10, 3: 18, 4: 24, 5: 30}

# Verdict tiers keyed on the final 0-100 score.
_TIERS = (
    (75, "confirmed", "critical", "HH-CONFIRM"),
    (50, "likely", "high", "HH-LIKELY"),
    (25, "possible", "medium", "HH-POSSIBLE"),
    (1, "trace", "low", "HH-TRACE"),
    (0, "none", "info", "HH-NONE"),
)

# BLE-attack detection thresholds (per scan snapshot). bt_scanner parses both
# manufacturer-specific data (the 16-bit company id) AND service-data UUIDs, so
# we detect the manufacturer-data pairing/tracker spam (Apple 0x004C, Microsoft
# 0x0006) AND Google Fast Pair (service-data UUID 0xFE2C).
_APPLE_CID = 0x004C     # Apple — FindMy/AirTag + Continuity proximity-pairing
_MS_CID = 0x0006        # Microsoft — Swift Pair
_FASTPAIR_SVC = 0xFE2C  # Google Fast Pair — BLE SERVICE-data UUID (not company id)
_APPLE_MIN = 6          # distinct Apple 0x004C random advertisers => flood/spam
_SWIFTPAIR_MIN = 6      # distinct Microsoft 0x0006 advertisers => Swift Pair spam
_FASTPAIR_MIN = 6       # distinct 0xFE2C random advertisers => Fast Pair spam
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

    IMPORTANT — what is and isn't observable here: bt_scanner parses both
    *manufacturer-specific data* (the 16-bit company id) AND *service-data*
    UUIDs, so this sees the Apple-Continuity (0x004C) and Microsoft Swift-Pair
    (0x0006) manufacturer-data spam AND Google Fast Pair (service-data UUID
    0xFE2C) pairing/tracker floods that churn many random-address adverts at
    once. It still does NOT see GATT-level attacks (BLE Predator honeypot,
    Airoha RACE, SkeletonKey) — those need an active connection and remain a
    blind spot reported by ``assess()``. Real rooms hold only a handful of
    trackers/phones, so a burst of many is the tell.
    """
    th = thresholds or {}
    apple_min = int(th.get("apple_min", _APPLE_MIN))
    swiftpair_min = int(th.get("swiftpair_min", _SWIFTPAIR_MIN))
    flood_min = int(th.get("advert_flood_min", _ADVERT_FLOOD_MIN))

    fastpair_min = int(th.get("fastpair_min", _FASTPAIR_MIN))

    apple_random = set()
    microsoft = set()
    fastpair = set()
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
        # Google Fast Pair rides SERVICE-data UUID 0xFE2C (not manufacturer data),
        # from random addresses — now that bt_scanner parses service_uuids we can
        # finally see the WhisperPair/Fast Pair popup spam that was a blind spot.
        if _FASTPAIR_SVC in (d.get("service_uuids") or []) and rnd:
            fastpair.add(mac)

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
    if len(fastpair) >= fastpair_min:
        attacks.append({
            "type": "fastpair_spam", "count": len(fastpair),
            "detail": f"{len(fastpair)} distinct random-address Google Fast Pair "
                      "(service-data 0xFE2C) advertisers — Fast Pair / WhisperPair "
                      "pairing-popup spam",
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

# --------------------------------------------------------------------------
# GARMR captive-portal SIGNATURE table  (active "ask the portal" confirm)
# --------------------------------------------------------------------------
# HaleHound exposes no management API — the ONLY fetchable surface it ever
# presents is the GARMR evil-twin captive portal, and only while it is actively
# running that attack. When Ragnar (or the operator) associates with the rogue
# SSID, it can GET the portal page and match it here for a HIGH-CONFIDENCE,
# HaleHound-specific confirm — far stronger than the generic DNS-hijack tell.
#
# This table is intentionally EMPTY: drop in the real GARMR fingerprints once
# they are known (e.g. from the tool's author). Each entry is a dict; every
# present key must match (AND), entries are OR'd. Recognized keys:
#   name           str   — label shown when it matches (required)
#   confidence     str   — "confirmed" | "likely" (default "likely")
#   title_contains str   — case-insensitive substring of the page <title>
#   server_contains str  — case-insensitive substring of the HTTP Server header
#   form_fields    [str] — all of these <input name=...> must be present
#   html_markers   [str] — all of these substrings must appear in the body
#   html_sha256    str   — exact hex digest of the normalized body (whitespace-
#                          collapsed, lowercased) — the strongest single match
#
# Example (commented — replace with the real values):
#   {"name": "GARMR default portal", "confidence": "confirmed",
#    "title_contains": "sign in", "server_contains": "esp",
#    "form_fields": ["username", "password"],
#    "html_markers": ["garmr"], "html_sha256": None},
_GARMR_SIGNATURES = []


def _normalize_html(html):
    """Whitespace-collapsed, lowercased body — stable input for hashing."""
    import re as _re
    return _re.sub(r"\s+", " ", (html or "")).strip().lower()


def parse_portal_observation(html=None, headers=None, http_status=None):
    """Extract the matchable fields from a fetched captive-portal response (pure).

    Returns ``{status, server, title, form_fields, html_sha256, html}`` — the
    shape ``match_portal_signature`` and ``fingerprint_portal(observed=...)``
    expect. ``headers`` is any mapping of HTTP response headers.
    """
    import hashlib
    import re as _re
    html = html or ""
    headers = headers or {}
    server = ""
    for k, v in dict(headers).items():
        if str(k).lower() == "server":
            server = str(v)
            break
    m = _re.search(r"<title[^>]*>(.*?)</title>", html, _re.I | _re.S)
    title = (m.group(1).strip() if m else "")
    form_fields = sorted({n.lower() for n in
                          _re.findall(r"<input[^>]*\bname\s*=\s*[\"']([^\"']+)",
                                      html, _re.I)})
    norm = _normalize_html(html)
    return {
        "status": http_status,
        "server": server,
        "title": title,
        "form_fields": form_fields,
        "html_sha256": hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest(),
        "html": html,
    }


def match_portal_signature(observed, signatures=None):
    """Return the first GARMR signature matching an observation, or None (pure).

    ``observed`` is a ``parse_portal_observation`` result (or a compatible dict).
    Every present criterion in a signature must match; a signature with no usable
    criteria never matches (so an empty table can't false-positive).
    """
    if not observed:
        return None
    sigs = _GARMR_SIGNATURES if signatures is None else signatures
    title = (observed.get("title") or "").lower()
    server = (observed.get("server") or "").lower()
    fields = {str(f).lower() for f in (observed.get("form_fields") or [])}
    html = (observed.get("html") or "").lower()
    digest = (observed.get("html_sha256") or "").lower()
    for sig in sigs:
        criteria = 0
        ok = True
        if sig.get("title_contains"):
            criteria += 1
            ok = ok and sig["title_contains"].lower() in title
        if sig.get("server_contains"):
            criteria += 1
            ok = ok and sig["server_contains"].lower() in server
        if sig.get("form_fields"):
            criteria += 1
            ok = ok and {f.lower() for f in sig["form_fields"]} <= fields
        if sig.get("html_markers"):
            criteria += 1
            ok = ok and all(mk.lower() in html for mk in sig["html_markers"])
        if sig.get("html_sha256"):
            criteria += 1
            ok = ok and sig["html_sha256"].lower() == digest
        if ok and criteria > 0:
            return {"name": sig.get("name", "GARMR portal"),
                    "confidence": sig.get("confidence", "likely")}
    return None


def fingerprint_portal(dns_answers, http_status=None, redirect_host=None,
                       ap_ip=None, observed=None):
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

    # Active confirm: does the fetched page match a known GARMR signature? A
    # positive match is HaleHound-specific and definitive — it confirms the
    # portal regardless of the (behavioural) DNS-hijack heuristics.
    sig = match_portal_signature(observed) if observed else None

    captive_portal = captive_portal or bool(sig)
    confirmed = (dns_hijack and captive_portal) or bool(sig)
    bits = []
    if sig:
        bits.append(f"matched GARMR signature '{sig['name']}'")
    if dns_hijack:
        bits.append(f"all DNS → {hijack_ip} (hijack)")
    if captive_portal and http_status:
        bits.append(f"HTTP {http_status} → captive portal")
    detail = ("GARMR-style evil-twin captive portal — " + ", ".join(bits)
              if bits else "no captive-portal signature")
    return {"dns_hijack": dns_hijack, "captive_portal": captive_portal,
            "confirmed": confirmed, "hijack_ip": hijack_ip,
            "garmr_signature": (sig["name"] if sig else None),
            "signature_confidence": (sig["confidence"] if sig else None),
            "detail": detail}


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
    domain_raw = {"wifi": 0, "lan": 0, "ble": 0, "portal": 0, "subghz": 0}

    for det in signals.get("wifi", []) or []:
        w = _WIFI_WEIGHTS.get((det.get("type"), det.get("severity")))
        if w:
            domain_raw["wifi"] += w
            reasons.append({"domain": "wifi", "signal": det.get("type"),
                            "weight": w, "detail": det.get("detail", "")})

    for det in signals.get("subghz", []) or []:
        w = _SUBGHZ_WEIGHTS.get((det.get("type"), det.get("severity")))
        if w:
            domain_raw["subghz"] += w
            reasons.append({"domain": "subghz", "signal": det.get("type"),
                            "weight": w, "detail": det.get("detail", "")})

    for atk in signals.get("ble", []) or []:
        w = _BLE_WEIGHTS.get(atk.get("type"))
        if w:
            domain_raw["ble"] += w
            reasons.append({"domain": "ble", "signal": atk.get("type"),
                            "weight": w, "detail": atk.get("detail", "")})

    portal = signals.get("portal") or {}
    if portal.get("garmr_signature"):
        domain_raw["portal"] += _PORTAL_WEIGHT
        reasons.append({"domain": "portal", "signal": "garmr_signature",
                        "weight": _PORTAL_WEIGHT,
                        "detail": "active portal fetch matched GARMR signature "
                                  f"'{portal['garmr_signature']}' — "
                                  "HaleHound-specific confirm"})
    elif portal.get("confirmed"):
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
                         for d in ("wifi", "ble", "portal", "subghz"))
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

    # An active GARMR portal-signature match is a HaleHound-specific ID — floor to
    # 'confirmed' if the signature itself is high-confidence, else 'likely'.
    if portal.get("garmr_signature"):
        floor = 75 if portal.get("signature_confidence") == "confirmed" else 60
        if total < floor:
            total = floor
            reasons.append({"domain": "portal", "signal": "signature_floor",
                            "weight": 0,
                            "detail": "GARMR portal signature match — verdict "
                                      f"floored to '{_tier(floor)[0]}'"})

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


def _blind_spots(caps=None, subghz=None):
    """Build the honest 'what this node can't see' list, AWARE of the hardware
    actually attached.

    ``caps`` is a capability dict from the caller: ``{sdr, bt, nrf24, nfc}``
    (all bool). A radio that IS present but simply isn't wired into a decoder is
    reported differently from one that is genuinely absent — "needs an SDR" is a
    lie when an RTL-SDR is on the bus. ``subghz`` is a SubGHz scan result; when
    it actually ran, SubGHz stops being a blind spot at all.
    """
    caps = caps or {}
    sdr = bool(caps.get("sdr"))
    bt = bool(caps.get("bt"))
    nrf24 = bool(caps.get("nrf24"))
    nfc = bool(caps.get("nfc"))
    spots = []

    if not nrf24:
        spots.append("NRF24 2.4 GHz (MouseJack, WLAN/BLE jammer) — no NRF24 "
                     "receiver on this node")

    if subghz and subghz.get("scanned"):
        pass                                  # covered — SubGHz is a live domain
    elif sdr:
        spots.append("SubGHz 300-439 MHz (CC1101 replay/brute, Tesla) — RTL-SDR "
                     "present but no SubGHz capture this pass (enable the SubGHz "
                     "scan)")
    else:
        spots.append("SubGHz 300-439 MHz (CC1101 replay/brute, Tesla) — needs an "
                     "SDR (RTL-SDR is fine) or CC1101")

    if not nfc:
        spots.append("NFC/RFID cloning — no reader on this node")

    # Fast Pair rides BLE service-data UUID 0xFE2C, which the BLE radio CAN see
    # (bt_scanner now parses it) — so it's only a blind spot with no BLE receiver.
    if not bt:
        spots.append("Google Fast Pair (BLE service-data UUID 0xFE2C) — no BLE "
                     "receiver on this node")

    # GATT-level attacks need an active connection — a method limit of passive
    # scanning, independent of which radio is attached.
    spots.append("GATT-level BLE (BLE Predator honeypot, Airoha RACE, "
                 "SkeletonKey) — passive advertisement scan can't see connections")
    return spots


def assess(wifi=None, assets=None, ble_devices=None, portal_obs=None,
           ble_thresholds=None, capabilities=None, subghz=None):
    """One-shot HaleHound assessment from live subsystem outputs.

    Args:
        wifi: a ``wifi_defense.analyze()`` result (uses its ``detections``).
        assets: an ``asset_inventory.inventory()`` result (uses ``assets``) OR a
                bare list of asset dicts.
        ble_devices: a list of bt_scanner device dicts (snapshot).
        portal_obs: a dict of observed portal behaviour to pass through
                    ``fingerprint_portal`` (keys: dns_answers, http_status,
                    redirect_host, ap_ip; plus optional html/headers or a
                    pre-parsed ``observed`` for GARMR-signature matching), or an
                    already-built fingerprint.

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
            # An active fetch may include the page itself (html/headers) or a
            # pre-parsed observation, for GARMR-signature matching.
            observed = portal_obs.get("observed")
            if observed is None and (portal_obs.get("html") is not None
                                     or portal_obs.get("headers")):
                observed = parse_portal_observation(
                    portal_obs.get("html"), portal_obs.get("headers"),
                    portal_obs.get("http_status"))
            portal = fingerprint_portal(
                portal_obs.get("dns_answers"), portal_obs.get("http_status"),
                portal_obs.get("redirect_host"), portal_obs.get("ap_ip"),
                observed=observed)

    # SubGHz (RTL-SDR): fold a scan result into the fusion as its own domain.
    subghz_dets = subghz.get("detections") if isinstance(subghz, dict) else None

    verdict = score({"wifi": wifi_dets, "lan": lan_ids,
                     "ble": ble_attacks, "portal": portal,
                     "subghz": subghz_dets})
    verdict["suspects"] = suspects

    # Capabilities default: BT is present if we were handed a BLE snapshot; the
    # rest only when the caller (which can see the USB bus) says so.
    caps = dict(capabilities or {})
    caps.setdefault("bt", ble_devices is not None)
    verdict["blind_spots"] = _blind_spots(caps, subghz)
    if isinstance(subghz, dict):
        verdict["subghz"] = {"scanned": bool(subghz.get("scanned")),
                             "events": subghz.get("events", 0),
                             "reason": subghz.get("reason"),
                             "freqs": subghz.get("freqs")}
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
    # Google Fast Pair spam (service-data 0xFE2C) — now visible, was a blind spot.
    fastpair = [{"mac": "5E:00:00:00:00:%02x" % i, "addr_type": "random",
                 "service_uuids": [0xFE2C]} for i in range(7)]
    check("Fast Pair (service-data 0xFE2C) spam detected",
          any(a["type"] == "fastpair_spam" for a in detect_ble_attacks(fastpair)),
          json.dumps(detect_ble_attacks(fastpair)))
    check("a couple of legit Fast Pair devices => no spam",
          not any(a["type"] == "fastpair_spam"
                  for a in detect_ble_attacks(fastpair[:2])))
    check("public-address Fast Pair (not random) => not counted as spam",
          not any(a["type"] == "fastpair_spam" for a in detect_ble_attacks(
              [{"mac": "3C:22:FB:00:00:%02x" % i, "addr_type": "public",
                "service_uuids": [0xFE2C]} for i in range(8)])))

    # --- SubGHz domain (RTL-SDR) scoring ---
    sg_replay = score({"subghz": [{"type": "subghz_replay", "severity": "flood"}]})
    check("SubGHz replay alone scores (>= possible)",
          sg_replay["score"] >= 22 and "subghz" in sg_replay["domains"],
          json.dumps({"s": sg_replay["score"], "d": sg_replay["domains"]}))
    sg_seen = score({"subghz": [{"type": "subghz_active", "severity": "seen"}]})
    check("bare SubGHz telemetry ('seen') stays low (corroboration weight)",
          sg_seen["score"] < 25, json.dumps({"s": sg_seen["score"]}))
    # An unknown ESP32 + a SubGHz replay (attack-grade) => corroboration kicks in.
    sg_corr = score({"subghz": [{"type": "subghz_replay", "severity": "flood"}],
                     "lan": ["rogue_espressif"]})
    check("SubGHz replay lets an unknown ESP32 corroborate",
          any(r["signal"] == "rogue_espressif" and r["weight"] > 0
              for r in sg_corr["reasons"]), json.dumps(sg_corr["reasons"]))
    # Wi-Fi flood + SubGHz brute => two RF domains => multi-domain bonus.
    sg_multi = score({"wifi": [{"type": "auth_flood", "severity": "flood"}],
                      "subghz": [{"type": "subghz_brute", "severity": "flood"}]})
    check("Wi-Fi + SubGHz => multi-domain fusion (>= likely)",
          sg_multi["score"] >= 50 and {"wifi", "subghz"} <= set(sg_multi["domains"]),
          json.dumps({"s": sg_multi["score"], "d": sg_multi["domains"]}))

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

    # --- Active GARMR portal-signature machinery (empty table can't FP) ---
    page = ("<html><head><title>GARMR Sign In</title></head><body>"
            "<form><input name='username'><input name='password'></form>"
            "<!-- garmr --></body></html>")
    obs = parse_portal_observation(page, {"Server": "ESP32-HTTPD"}, 200)
    check("parse_portal_observation extracts title/fields/server",
          obs["title"] == "GARMR Sign In" and obs["form_fields"] == ["password", "username"]
          and obs["server"] == "ESP32-HTTPD" and len(obs["html_sha256"]) == 64,
          json.dumps({k: obs[k] for k in ("title", "form_fields", "server")}))
    # Empty production table never matches (no false confirm).
    check("empty GARMR signature table => no match",
          match_portal_signature(obs) is None)
    # A supplied (synthetic) signature matches, and fingerprint_portal confirms
    # off it even with NO DNS hijack.
    synth = [{"name": "GARMR test", "confidence": "confirmed",
              "title_contains": "garmr", "server_contains": "esp",
              "form_fields": ["username", "password"], "html_markers": ["garmr"]}]
    check("supplied GARMR signature matches an observation",
          match_portal_signature(obs, synth)["name"] == "GARMR test")
    fp_sig = fingerprint_portal([], observed=obs)
    fp_sig2 = dict(fp_sig)  # behavioural path had no signature (empty table)
    check("fingerprint_portal(observed) with empty table => not confirmed",
          not fp_sig2["confirmed"] and fp_sig2["garmr_signature"] is None)
    # Signature match floors the verdict to 'confirmed' even alone.
    matched_portal = {"garmr_signature": "GARMR test",
                      "signature_confidence": "confirmed", "confirmed": True}
    sv = score({"portal": matched_portal})
    check("matched GARMR signature alone => confirmed",
          sv["verdict"] == "confirmed", json.dumps({"v": sv["verdict"], "s": sv["score"]}))

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

    # Hardware-aware blind spots: wording must track the attached radios.
    bare = _blind_spots({"sdr": False, "bt": False})
    check("bare node: SubGHz says 'needs an SDR'",
          any("needs an SDR" in s for s in bare), json.dumps(bare))
    check("bare node: Fast Pair is a blind spot (no BLE receiver)",
          any("Fast Pair" in s for s in bare), json.dumps(bare))
    withhw = _blind_spots({"sdr": True, "bt": True})
    check("SDR present: no longer says 'needs an SDR'",
          not any("needs an SDR" in s for s in withhw)
          and any("RTL-SDR present" in s for s in withhw), json.dumps(withhw))
    check("BLE present: Fast Pair is NOT a blind spot (service-data parsed)",
          not any("Fast Pair" in s for s in withhw), json.dumps(withhw))
    ran = _blind_spots({"sdr": True, "bt": True},
                       subghz={"scanned": True, "detections": []})
    check("SubGHz scan ran: SubGHz drops off the blind-spot list",
          not any("SubGHz" in s for s in ran), json.dumps(ran))
    check("GATT stays a blind spot regardless of hardware (passive limit)",
          any("GATT" in s for s in withhw) and any("GATT" in s for s in ran), "")

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
