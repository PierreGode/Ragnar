#!/usr/bin/env python3
"""
zigbee_overlay.py — Zigbee / 802.15.4 activity overlay for the spectrum analyzer.

The Zigbee sibling of :mod:`bt_scanner`. Where the Bluetooth overlay maps BT/BLE
device activity onto the Wi-Fi analyzer's 2.4 GHz axis, this maps **Zigbee /
Thread / raw 802.15.4** activity — another real 2.4 GHz Wi-Fi interference source
that shares the band.

Data source — Huginn, not a local radio
---------------------------------------
The Pi has no 802.15.4 radio. A **HuginnESP companion** (ESP32-C5/C6/H2) sniffs
802.15.4 while hopping channels 11–26 and streams every detected device over
USB-serial as JSON
(``{"type":"ZIGBEE","panid":…,"channel":15,"rssi":-72,"lqi":…,"proto":…}``).
:mod:`zigbee_scan` drives that on demand — it sends the ``zigbee`` command to the
Huginn, reads the stream for a few seconds, and hands the parsed rows here.

This module is the thin, *pure* layer on top: it shapes those rows into the same
overlay payload the Bluetooth view uses — per-channel markers, a per-Wi-Fi-channel
interference estimate, and a device list. It performs **no I/O and drives no
hardware**, so it is fully unit-testable offline.

What it is — and isn't
----------------------
Huginn is a **packet sniffer**, so this is device-activity (which Zigbee devices
are transmitting, on which channel, how strong) — not a per-channel energy sweep.
And because one ESP32-C5 can't do Wi-Fi and 802.15.4 at once, an on-demand scan
briefly puts the Huginn in zigbee mode; the web layer gates the toggle on a
Huginn being present.

Channel plan
------------
2.4 GHz 802.15.4 uses 16 channels, 11–26, 5 MHz apart:
``centre = 2405 + 5*(ch-11)`` MHz → 2405 (ch11) … 2480 (ch26). Zigbee channels
15/20/25/26 famously fall in the gaps between Wi-Fi 1/6/11.
"""

import re
import time

# --------------------------------------------------------------------------
# 802.15.4 / Zigbee channel plan (2.4 GHz)
# --------------------------------------------------------------------------

ZIGBEE_CH_MIN = 11
ZIGBEE_CH_MAX = 26

# Wi-Fi 2.4 GHz channel centre frequencies we score interference against.
_WIFI_24_CENTERS = {1: 2412, 6: 2437, 11: 2462, 13: 2472}

_STRONG_RSSI = -70          # dBm; at/above this a device is "close" and hurts more

# A few common 802.15.4 EUI-64 OUIs, used when the system OUI DB misses them.
_ZB_OUI_FALLBACK = {
    "00:12:4b": "Texas Instruments/SiLabs", "00:0d:6f": "Ember/SiLabs",
    "28:6d:97": "Samsung SmartThings", "00:15:8d": "Xiaomi/Aqara",
    "54:ef:44": "Lumi/Aqara", "00:17:88": "Philips Hue/Signify",
    "ec:1b:bd": "Signify (Hue)", "00:0b:57": "Silicon Labs",
    "84:2e:14": "Silicon Labs", "68:0a:e2": "Bosch",
}


def channel_to_freq(ch):
    """Centre frequency (MHz) of a 2.4 GHz 802.15.4 channel (11–26)."""
    return 2405 + 5 * (int(ch) - ZIGBEE_CH_MIN)


def _norm_mac_prefix(addr):
    """First three octets of an EUI-64/short address as 'xx:xx:xx', or None."""
    if not addr:
        return None
    hexs = re.sub(r"[^0-9a-fA-F]", "", str(addr))
    if len(hexs) < 6:
        return None
    return ":".join(hexs[i:i + 2] for i in (0, 2, 4)).lower()


def _vendor_for(addr):
    """Maker of a Zigbee device from its EUI-64 OUI (best-effort)."""
    pfx = _norm_mac_prefix(addr)
    if not pfx:
        return None
    try:
        import wifi_analyzer
        v = wifi_analyzer._load_oui().get(pfx.replace(":", ""))
        if v:
            return v
    except Exception:
        pass
    return _ZB_OUI_FALLBACK.get(pfx)


def _proto_label(proto):
    p = (proto or "").lower()
    return {"zigbee": "Zigbee", "thread": "Thread"}.get(p, "802.15.4")


# --------------------------------------------------------------------------
# Device shaping + interference model
# --------------------------------------------------------------------------

def _shape(row):
    """Normalise one zigbee_devices DB row into an overlay device dict."""
    ch = row.get("channel") or 0
    rssi = row.get("rssi")
    if rssi is None:
        rssi = row.get("best_rssi")
    addr = row.get("addr") or row.get("short_addr") or ""
    return {
        "addr": addr,
        "panid": row.get("panid") or "",
        "short_addr": row.get("short_addr") or "",
        "channel": int(ch) if ch else None,
        "freq_mhz": channel_to_freq(ch) if ZIGBEE_CH_MIN <= (ch or 0) <= ZIGBEE_CH_MAX else None,
        "rssi": rssi,
        "lqi": row.get("lqi"),
        "proto": _proto_label(row.get("proto")),
        "device_type": row.get("device_type") or "",
        "vendor": _vendor_for(addr),
        "last_seen": row.get("last_seen"),
    }


def analyze_interference(devices):
    """Model the Zigbee footprint across 2.4 GHz.

    Returns per-Zigbee-channel markers (occupancy weighted by device count and
    best RSSI) and an estimated per-Wi-Fi-channel pressure for 1/6/11/13 — the
    Zigbee equivalent of the Bluetooth interference model. Heuristic, and clearly
    an activity estimate rather than measured energy.
    """
    strong = sum(1 for d in devices if d.get("rssi") is not None
                 and d["rssi"] >= _STRONG_RSSI)

    # Per-channel aggregation.
    per_ch = {}
    for d in devices:
        ch = d.get("channel")
        if ch is None or not (ZIGBEE_CH_MIN <= ch <= ZIGBEE_CH_MAX):
            continue
        e = per_ch.setdefault(ch, {"count": 0, "best_rssi": None})
        e["count"] += 1
        r = d.get("rssi")
        if r is not None and (e["best_rssi"] is None or r > e["best_rssi"]):
            e["best_rssi"] = r

    markers = []
    for ch in sorted(per_ch):
        e = per_ch[ch]
        # Intensity 0-100 from device count + a boost for a close, loud device.
        boost = 0
        if e["best_rssi"] is not None:
            boost = max(0, min(40, (e["best_rssi"] + 95)))  # -95..-55 -> 0..40
        intensity = min(100, e["count"] * 20 + boost)
        markers.append({"channel": ch, "freq_mhz": channel_to_freq(ch),
                        "count": e["count"], "best_rssi": e["best_rssi"],
                        "intensity": intensity})

    # Per-Wi-Fi-channel pressure: a Zigbee channel presses a Wi-Fi channel it
    # overlaps (within ~11 MHz of the Wi-Fi centre — a 20 MHz Wi-Fi channel and
    # the 2 MHz Zigbee channel share spectrum), scaled by that channel's
    # intensity. Zigbee doesn't hop mid-network, so there's no band-wide term.
    channels = []
    for wch, wf in sorted(_WIFI_24_CENTERS.items()):
        pressure = 0.0
        overlaps = 0
        for m in markers:
            if abs(m["freq_mhz"] - wf) <= 11:
                overlaps += 1
                pressure += m["intensity"] * 0.5
        pressure = min(100, round(pressure, 1))
        level = "low" if pressure < 20 else "moderate" if pressure < 55 else "high"
        channels.append({"wifi_channel": wch, "pressure": pressure,
                        "level": level, "zigbee_overlap": overlaps})

    return {
        "device_count": len(devices),
        "channel_count": len(markers),
        "strong_count": strong,
        "markers": markers,
        "wifi_channels": channels,
        "note": ("Device-activity estimate from a Huginn 802.15.4 sniffer, not "
                 "measured RF energy. Zigbee 2.4 GHz uses channels 11–26 "
                 "(2405–2480 MHz); 15/20/25/26 sit in the Wi-Fi 1/6/11 gaps."),
    }


def build_overlay(rows, source=None):
    """Build the full Zigbee overlay payload from recent zigbee_devices rows.

    `rows` are the already-freshness-filtered DB rows (dicts). Sorted strongest
    first so the device table and any selection mirror the Bluetooth overlay.
    """
    devices = [_shape(r) for r in (rows or [])]
    devices.sort(key=lambda d: (d.get("rssi") is None, -(d.get("rssi") or -999)))
    interference = analyze_interference(devices)
    return {
        "timestamp": int(time.time()),
        "source": source,
        "device_count": len(devices),
        "devices": devices,
        "interference": interference,
        "companion_note": ("Zigbee comes from an on-demand sniff by a HuginnESP "
                           "companion (ESP32-C5/C6/H2). One radio can't do Wi-Fi "
                           "+ 802.15.4 at once, so the scan briefly switches the "
                           "Huginn into zigbee mode, then stops it."),
    }


# --------------------------------------------------------------------------
# Self-test (pure — no DB, no hardware)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    # --- channel plan ---
    check("channel 11 -> 2405 MHz", channel_to_freq(11) == 2405)
    check("channel 26 -> 2480 MHz", channel_to_freq(26) == 2480)
    check("channel 15 -> 2425 MHz (Wi-Fi 1/6 gap)", channel_to_freq(15) == 2425)

    # --- OUI prefix + vendor fallback ---
    check("mac prefix from EUI-64 hex", _norm_mac_prefix("00124b0001a2b3c4") == "00:12:4b")
    check("mac prefix from colon form", _norm_mac_prefix("00:15:8D:00:11:22:33:44") == "00:15:8d")
    check("vendor fallback resolves Aqara OUI",
          _vendor_for("00158d0001020304") in ("Xiaomi/Aqara",) or
          _vendor_for("00158d0001020304") is not None)

    # --- proto label ---
    check("proto zigbee -> Zigbee", _proto_label("zigbee") == "Zigbee")
    check("proto thread -> Thread", _proto_label("thread") == "Thread")
    check("proto unknown -> 802.15.4", _proto_label("") == "802.15.4")

    # --- shape ---
    d = _shape({"addr": "00124b0001a2b3c4", "panid": "0x1A62", "channel": 20,
                "rssi": -55, "lqi": 200, "proto": "zigbee", "device_type": "router"})
    check("shape: channel -> freq", d["freq_mhz"] == channel_to_freq(20))
    check("shape: proto labelled", d["proto"] == "Zigbee")
    check("shape: out-of-range channel -> None freq",
          _shape({"channel": 99})["freq_mhz"] is None)
    check("shape: rssi falls back to best_rssi",
          _shape({"channel": 15, "best_rssi": -80})["rssi"] == -80)

    # --- interference model ---
    devs = [
        {"channel": 15, "rssi": -50, "proto": "Zigbee"},   # Wi-Fi 6 gap-ish
        {"channel": 15, "rssi": -65, "proto": "Zigbee"},
        {"channel": 25, "rssi": -75, "proto": "Zigbee"},   # near Wi-Fi 11
    ]
    intf = analyze_interference(devs)
    check("interference: two channels occupied", intf["channel_count"] == 2,
          str(intf["channel_count"]))
    check("interference: ch15 marker aggregates 2 devices",
          any(m["channel"] == 15 and m["count"] == 2 for m in intf["markers"]))
    check("interference: strong count (>=-70) = 2", intf["strong_count"] == 2,
          str(intf["strong_count"]))
    check("interference: some Wi-Fi channel shows pressure",
          any(c["pressure"] > 0 for c in intf["wifi_channels"]))
    check("interference: pressure capped at 100",
          all(c["pressure"] <= 100 for c in intf["wifi_channels"]))
    check("interference: empty -> zero pressure",
          all(c["pressure"] == 0 for c in analyze_interference([])["wifi_channels"]))

    # --- build_overlay sorting ---
    ov = build_overlay([{"channel": 11, "rssi": -80, "addr": "a"},
                        {"channel": 20, "rssi": -40, "addr": "b"}])
    check("overlay: strongest device first", ov["devices"][0]["rssi"] == -40)
    check("overlay: device_count", ov["device_count"] == 2)

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import json
    if argv and argv[0] == "selftest":
        r = selftest()
        for item in r["results"]:
            print("  [%s] %s%s" % ("PASS" if item["pass"] else "FAIL", item["name"],
                                   "" if item["pass"] else "  (%s)" % item["detail"]))
        print("\n%d/%d checks pass — %s" %
              (r["passed"], r["total"], "OK" if r["pass"] else "FAILURES"))
        return 0 if r["pass"] else 1
    print("usage: zigbee_overlay.py selftest")
    print("(live Zigbee data comes from the wardriving engine's zigbee_devices "
          "table via the /api/net/zigbee/* web routes)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
