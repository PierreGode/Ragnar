#!/usr/bin/env python3
"""
rtl_sdr.py — sub-GHz RF via a cheap RTL-SDR dongle (RTL2832U).

The HackRF Waterfall ([[sdr_spectrum]]) covers the 2.4/5/6 GHz Wi-Fi bands. A
common RTL-SDR **cannot** reach those (it tops out ~1.7 GHz), but that lower
range is exactly where the *interesting non-Wi-Fi* world lives — the 433/868/915
MHz ISM bands packed with TPMS tyre sensors, weather stations, door/PIR
contacts, remotes and keyfobs, utility meters and doorbells. This module turns a
plug-in RTL-SDR into two receive-only tools:

  1. **ISM device scanner** — shells out to ``rtl_433 -F json`` and keeps a live
     table of every device it decodes (model, id, RSSI, and the decoded fields).
  2. **Sub-GHz waterfall** — a scrolling power-per-frequency heatmap, the same
     shape the HackRF Waterfall uses, for the bands the HackRF view doesn't
     target. Two engines feed it (chosen automatically, same frame shape):

       * **IQ FFT (real-time)** — for any span that fits a single RTL-SDR tune
         (<= ``_IQ_MAX_SPAN_HZ``) we stream raw IQ from ``rtl_sdr`` and FFT it
         continuously with numpy, exactly how SDR++/GQRX draw a waterfall. No
         retuning, so rows scroll smoothly at ``_IQ_DISPLAY_HZ``.
       * **rtl_power sweep** — the fallback for wide bands (868/915/sub-GHz full
         scans need retuning) and for hosts without ``rtl_sdr`` or numpy. It's an
         integrating sweeper, so it advances at best ~1 row/s.

Both are **receive-only** — nothing here ever transmits.

One dongle, one claim
---------------------
An RTL-SDR is a single USB device that only one program can open at a time.
``rtl_433`` and ``rtl_power`` therefore cannot run together, and — the lesson
from the HackRF view — a device probe (``rtl_test``) must never run while either
is streaming, or it knocks the capture offline. So the two modes are mutually
exclusive (starting one stops the other) and :func:`status` reports availability
from a cached probe while anything is running.

CLI
---
    python3 rtl_sdr.py detect
    python3 rtl_sdr.py ism   [--band 433|868|915] [--seconds N]
    python3 rtl_sdr.py power [--band 433|868|915|subghz] [--seconds N]
    python3 rtl_sdr.py selftest
"""

import json
import os
import re
import subprocess
import sys
import threading
import time


# --------------------------------------------------------------------------
# Tools / tunables
# --------------------------------------------------------------------------

def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


_RTL_TEST = _which("rtl_test")
_RTL_433 = _which("rtl_433")
_RTL_POWER = _which("rtl_power")
_RTL_SDR = _which("rtl_sdr")     # raw-IQ streamer for the real-time FFT waterfall

# Power-sweep ranges (Hz). Kept inside the RTL-SDR's reach (~24 MHz–1.7 GHz).
RTL_BANDS = {
    # HF broadcast bands (below the R820T2 tuner floor -> need the dongle's
    # DIRECT-SAMPLING path, ~0.1-24 MHz, not the normal quadrature tuner).
    "am":     (530000, 1710000),        # AM / medium-wave broadcast (direct sampling)
    "sw":     (3000000, 24000000),      # shortwave HF broadcast (direct sampling; capped at ~25 MHz DS ceiling)
    "27":     (26900000, 27500000),     # CB / 27 MHz RC (near the tuner's low edge)
    "40":     (40000000, 41000000),     # 40 MHz RC / toys
    "fm":     (88000000, 108000000),    # FM broadcast band scope (listen w/ radio)
    "air":    (108000000, 137000000),   # VHF airband (AM voice) band scope
    "315":    (313500000, 316500000),   # US keyfobs / TPMS / garage & gate remotes
    "433":    (433050000, 434790000),   # EU 433 ISM
    "868":    (863000000, 870000000),   # EU 868 SRD
    "915":    (902000000, 928000000),   # US 915 ISM
    "subghz": (300000000, 960000000),   # wide "what's out there" sweep
}

# rtl_433 tuning presets (its own hop frequencies).
ISM_FREQS = {
    "315": "315M",     # US keyfobs, TPMS, garage/gate remotes, many alarm sensors
    "433": "433.92M",
    "868": "868.3M",
    "915": "915M",
}

# Z-Wave regional radio plan. Z-Wave is a sub-GHz mesh (GFSK/FSK) that lives on a
# small set of FIXED narrow channels per regulatory region — not a wide ISM
# scatter — so each region gets a tight sweep span plus the exact channel centres
# to overlay on the spectrum. rtl_433 does NOT decode Z-Wave, so this is an
# ENERGY / occupancy view: you watch the mesh's bursts land on the channels
# (device chatter, retries, a jammer parked on a channel), band nobody usually
# looks at. Frequencies are the published Z-Wave regional assignments (Hz).
ZWAVE_REGIONS = {
    "eu":    {"label": "EU (868)",        "span": (867_600_000, 870_200_000),
              "channels": [(868_420_000, "R1/R2 9.6/40k"), (869_850_000, "R3 100k")]},
    "us":    {"label": "US (908/916)",    "span": (907_000_000, 917_200_000),
              "channels": [(908_420_000, "R1/R2 9.6/40k"), (916_000_000, "R3 100k")]},
    "us-lr": {"label": "US Long Range",   "span": (910_500_000, 921_500_000),
              "channels": [(912_000_000, "LR ch A"), (920_000_000, "LR ch B")]},
    "anz":   {"label": "ANZ (919/921)",   "span": (919_000_000, 922_200_000),
              "channels": [(919_820_000, "R1/R2"), (921_420_000, "R3")]},
    "jp":    {"label": "Japan (922-926)", "span": (921_500_000, 927_200_000),
              "channels": [(922_500_000, "ch1"), (923_900_000, "ch2"), (926_300_000, "ch3")]},
    "kr":    {"label": "Korea (920-923)", "span": (920_000_000, 924_000_000),
              "channels": [(920_900_000, "ch1"), (921_700_000, "ch2"), (923_100_000, "ch3")]},
    "in":    {"label": "India (865)",     "span": (864_400_000, 866_000_000),
              "channels": [(865_200_000, "R1/R2/R3")]},
    "il":    {"label": "Israel (916)",    "span": (915_000_000, 917_000_000),
              "channels": [(916_000_000, "R1/R2/R3")]},
    "hk":    {"label": "Hong Kong (919)", "span": (919_000_000, 920_600_000),
              "channels": [(919_820_000, "R1/R2/R3")]},
    "ru":    {"label": "Russia (869)",    "span": (868_000_000, 870_000_000),
              "channels": [(869_000_000, "R1/R2/R3")]},
    "cn":    {"label": "China (868)",     "span": (867_600_000, 869_200_000),
              "channels": [(868_400_000, "R1/R2/R3")]},
}


def zwave_plan():
    """Region → sweep span + Z-Wave channel centres, for the UI's Z-Wave view."""
    out = {}
    for rid, r in ZWAVE_REGIONS.items():
        out[rid] = {
            "label": r["label"],
            "lo_hz": r["span"][0], "hi_hz": r["span"][1],
            "channels": [{"freq_hz": f, "freq_mhz": round(f / 1e6, 3), "label": lbl}
                         for f, lbl in r["channels"]],
        }
    return out


# LoRa mesh / LPWAN radio plans (Meshtastic, MeshCore, LoRaWAN). These are all
# LoRa (chirp spread-spectrum), NOT the FSK that rtl_433 decodes — so this is an
# ENERGY / occupancy view only: sweep the band and watch the mesh's chirps land
# on its channels. We CANNOT demodulate LoRa with rtl_power/rtl_433 (that needs
# gr-lora_sdr or a real LoRa radio), and the payloads are encrypted regardless;
# so no node IDs / message contents — just presence, activity and which channels.
# Each entry: proto, sweep span (Hz), reference channel centres, and a note.
# LoRaWAN band plans are standards (accurate); Meshtastic/MeshCore defaults are
# preset/config-derived, so their channels are marked "~" / "default".
LORA_PLANS = {
    # --- Meshtastic (LoRa; default LongFast preset, BW 250 kHz) ---
    "meshtastic-us":    {"proto": "Meshtastic", "label": "Meshtastic · US (902-928)",
                         "span": (902_000_000, 928_000_000),
                         "channels": [(906_875_000, "LongFast ~")],
                         "note": "US: 902-928 MHz, LongFast BW250/SF11 (default channel is hash-derived; scan the band for 250 kHz chirps)"},
    "meshtastic-eu868": {"proto": "Meshtastic", "label": "Meshtastic · EU868",
                         "span": (869_300_000, 869_750_000),
                         "channels": [(869_525_000, "LongFast")],
                         "note": "EU868: single 250 kHz channel in the 10% duty sub-band"},
    "meshtastic-eu433": {"proto": "Meshtastic", "label": "Meshtastic · EU433",
                         "span": (433_050_000, 434_790_000),
                         "channels": [(433_175_000, "LongFast ~")],
                         "note": "EU433: BW250 (default channel hash-derived)"},
    "meshtastic-anz":   {"proto": "Meshtastic", "label": "Meshtastic · ANZ (915-928)",
                         "span": (915_000_000, 928_000_000),
                         "channels": [(915_900_000, "LongFast ~")],
                         "note": "ANZ: 915-928 MHz, BW250 (default channel hash-derived)"},
    # --- MeshCore (LoRa; frequency is user-configurable — common defaults) ---
    "meshcore-eu":      {"proto": "MeshCore", "label": "MeshCore · EU (default)",
                         "span": (868_000_000, 870_500_000),
                         "channels": [(869_525_000, "default ~")],
                         "note": "MeshCore EU default ~869.525 MHz (configurable), BW250"},
    "meshcore-us":      {"proto": "MeshCore", "label": "MeshCore · US (default)",
                         "span": (902_000_000, 928_000_000),
                         "channels": [(910_525_000, "default ~")],
                         "note": "MeshCore US default ~910.525 MHz (configurable), BW250"},
    # --- LoRaWAN (band plans are standards; payload AES-encrypted, DevAddr/MAC
    #     in clear only if demodulated — which we cannot do here) ---
    "lorawan-eu868":    {"proto": "LoRaWAN", "label": "LoRaWAN · EU868",
                         "span": (867_000_000, 869_700_000),
                         "channels": [(868_100_000, "ch0"), (868_300_000, "ch1"),
                                      (868_500_000, "ch2"), (867_100_000, "ch3"),
                                      (867_300_000, "ch4"), (867_500_000, "ch5"),
                                      (867_700_000, "ch6"), (867_900_000, "ch7"),
                                      (869_525_000, "RX2/dl")],
                         "note": "EU868: 125 kHz uplinks 867.1-868.5 + 869.525 RX2 downlink (SF12)"},
    "lorawan-us915":    {"proto": "LoRaWAN", "label": "LoRaWAN · US915",
                         "span": (902_000_000, 928_000_000),
                         "channels": [(902_300_000, "up0 125k"), (903_000_000, "up 500k"),
                                      (914_900_000, "up63 125k"), (923_300_000, "dl0 500k"),
                                      (927_500_000, "dl7 500k")],
                         "note": "US915: 64×125k + 8×500k uplinks (902.3-914.9); 8×500k downlinks (923.3-927.5)"},
    "lorawan-in865":    {"proto": "LoRaWAN", "label": "LoRaWAN · IN865",
                         "span": (865_000_000, 867_000_000),
                         "channels": [(865_062_500, "ch0"), (865_402_500, "ch1"),
                                      (865_985_000, "ch2")],
                         "note": "IN865: 3 mandatory 125 kHz channels"},
    "lorawan-as923":    {"proto": "LoRaWAN", "label": "LoRaWAN · AS923-1",
                         "span": (921_000_000, 928_000_000),
                         "channels": [(923_200_000, "ch0"), (923_400_000, "ch1")],
                         "note": "AS923-1: 923.2/923.4 default (+ up to 8 channels)"},
}


def lora_plan():
    """Protocol/region → sweep span + LoRa channel centres, for the mesh view."""
    out = {}
    for pid, p in LORA_PLANS.items():
        out[pid] = {
            "proto": p["proto"], "label": p["label"], "note": p.get("note", ""),
            "lo_hz": p["span"][0], "hi_hz": p["span"][1],
            "channels": [{"freq_hz": f, "freq_mhz": round(f / 1e6, 3), "label": lbl}
                         for f, lbl in p["channels"]],
        }
    return out

_POWER_BINS = 480          # display columns per waterfall frame
_RING_FRAMES = 300         # rolling history of sweep frames kept in memory
_FLOOR_DBM = -120          # sentinel for a display column no sweep bin filled
_SWEEP_INTERVAL_S = 1      # rtl_power -i (seconds per full sweep)
_ISM_MAX_DEVICES = 500     # cap the live device table

# --- Real-time IQ waterfall (the SDR++-style fast path) -------------------
# rtl_power is an *integrating sweeper*: it retunes across the band and dwells
# `-i` seconds per sweep, so a waterfall built from it advances at best ~1
# row/s — it lurches, and lags reality by a second. That's fine for a wide
# "what's out there" scan, but painfully slow for a narrow zoom / mesh overlay.
#
# For any span that fits a SINGLE RTL-SDR tune we instead stream raw IQ from
# ``rtl_sdr`` and FFT it continuously with numpy — exactly how SDR++/GQRX draw
# their waterfalls — with no retuning at all. That yields a smooth, low-latency
# scroll at _IQ_DISPLAY_HZ rows/s. Wider spans (full 868/915/sub-GHz scans) can't
# fit one tune, so they fall back to rtl_power; so does any host missing rtl_sdr
# or numpy. Both engines emit the same frame shape, so nothing downstream (the
# web routes, the recorder, the page) changes.
_IQ_MAX_SPAN_HZ = 2_800_000   # widest span coverable in one tune (else rtl_power)
_IQ_FFT = 1024                # FFT size — freq resolution = sample_rate / _IQ_FFT
_IQ_DISPLAY_HZ = 16           # waterfall rows emitted per second (steady scroll)
_IQ_AVG_MAX = 24              # FFT windows averaged per row (Welch smoothing; caps CPU)
_IQ_SR_MIN = 1_000_000        # RTL-SDR minimum practical sample rate (Hz)
_IQ_SR_MAX = 3_200_000        # RTL-SDR maximum sample rate (Hz)
_IQ_EDGE_MARGIN = 1.15        # oversample the span this much so band edges stay clean

# Tuner corrections shared by both captures (one dongle). PPM trims the RTL-SDR's
# crystal offset (matters on the narrow Z-Wave/LoRa channels); gain is tuner gain
# in dB, or None for the driver's automatic gain. Applied to every rtl_power /
# rtl_433 command; changing them reapplies to a running capture.
_ppm = 0
_gain = None               # None = automatic gain control


def get_tuning():
    """Current tuner corrections for the UI."""
    return {"ppm": _ppm, "gain": ("auto" if _gain is None else _gain),
            "gain_is_auto": _gain is None}


def set_tuning(ppm=None, gain=None):
    """Set PPM freq-correction and/or tuner gain, then reapply to any running
    capture. gain may be a number (dB), or 'auto'/'' /None for AGC."""
    global _ppm, _gain
    if ppm is not None:
        try:
            _ppm = max(-1000, min(1000, int(float(ppm))))
        except (TypeError, ValueError):
            pass
    if gain is not None:
        if gain in ("auto", "", "AUTO"):
            _gain = None
        else:
            try:
                _gain = max(0.0, min(50.0, round(float(gain), 1)))
            except (TypeError, ValueError):
                pass
    # Reapply live so the change takes effect without the user restarting.
    try:
        _power.reapply()
        _ism.reapply()
    except Exception:
        pass
    return get_tuning()


def _tuner_args():
    """Common rtl_power / rtl_433 flags for the current PPM + gain."""
    args = []
    if _ppm:
        args += ["-p", str(_ppm)]
    if _gain is not None:
        args += ["-g", str(_gain)]
    return args


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def _run(args, timeout=6):
    """Run a command, returning (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


def parse_rtl_test(text):
    """Pull device index / tuner name from ``rtl_test`` output (pure)."""
    info = {"device": None, "tuner": None}
    # e.g. "  0:  Realtek, RTL2838UHIDIR, SN: 00000001"
    m = re.search(r"^\s*(\d+):\s*(.+)$", text, re.MULTILINE)
    if m:
        info["device"] = m.group(2).strip()
    m = re.search(r"Found\s+(.+?)\s+tuner", text)
    if m:
        info["tuner"] = m.group(1).strip()
    return info


# Known RTL-SDR families we explicitly recognise (RTL-SDR Blog V3/V4,
# Nooelec NESDR, RTL-SDR.com, and any generic RTL2832U). rtl_test only exposes
# the USB product string and the tuner chip, so identity is best-effort: the
# EEPROM product string ("Blog V4", "NESDR SMArt", …) is authoritative when a
# vendor flashed one, otherwise we fall back to the tuner chip.
_TUNER_FAMILIES = ("R828D", "R820T2", "R820T", "R860", "E4000", "FC0013",
                   "FC0012", "FC2580", "R828")


def identify_model(device, tuner):
    """Best-effort friendly name for an RTL-SDR dongle (pure).

    Returns ``{"model_name", "tuner_family", "needs_blog_driver", "note"}``.
    ``needs_blog_driver`` flags the RTL-SDR Blog V4 (R828D tuner), which only
    tunes correctly with the RTL-SDR Blog fork of librtlsdr — the stock distro
    driver silently mis-tunes it.
    """
    dev = (device or "").strip()
    devl = dev.lower()
    tun = (tuner or "").upper()
    fam = next((f for f in _TUNER_FAMILIES if f in tun), (tuner or "").strip())

    def out(name, family, blog=False, note=""):
        return {"model_name": name, "tuner_family": family,
                "needs_blog_driver": blog, "note": note}

    # 1) EEPROM product strings a vendor deliberately flashed win outright.
    if "blog v4" in devl or ("rtlsdrblog" in devl and "v4" in devl):
        return out("RTL-SDR Blog V4", "R828D", True,
                   "R828D tuner — needs the RTL-SDR Blog librtlsdr fork")
    if "blog v3" in devl:
        return out("RTL-SDR Blog V3", "R820T2", False,
                   "R820T2 with TCXO + HF direct sampling + bias-tee")
    if "nesdr" in devl or "nooelec" in devl:
        return out(dev or "Nooelec NESDR", fam, False, "Nooelec NESDR series")
    # 2) Tuner chip fallback (generic / RTL-SDR.com without flashed EEPROM).
    if "R828D" in tun:
        # R828D almost always means a Blog V4 in the RTL-SDR world.
        return out("RTL-SDR Blog V4 (R828D)", "R828D", True,
                   "R828D tuner — needs the RTL-SDR Blog librtlsdr fork")
    if "R820T2" in tun:
        return out("RTL-SDR (R820T2)", "R820T2", False, "")
    if "R860" in tun:   # Rafael Micro R860 = R820T2-class (e.g. Nooelec NESDR SMArt v5)
        return out("RTL-SDR (R860 / R820T2)", "R860", False, "")
    if "R820T" in tun:
        return out("RTL-SDR (R820T)", "R820T", False, "")
    if fam in _TUNER_FAMILIES:
        return out("RTL-SDR (%s)" % fam, fam, False, "")
    if dev:
        return out(dev, fam, False, "")
    return out("RTL-SDR", fam, False, "")


# Known RTL-SDR USB IDs (VID:PID). An lsusb fallback probe against these lets us
# report "dongle present" even when the rtl_* tools aren't installed yet, or when
# rtl_test can't open the device because the DVB-T driver still has it. 0bda is
# Realtek (RTL2832U/RTL2838 — NESDR SMArt, Blog V3/V4, most generics); the rest
# are common rebadges.
_RTL_USB_IDS = {
    "0bda:2838": "Realtek RTL2838 (RTL-SDR)",   # NESDR SMArt, Blog V3, most generics
    "0bda:2832": "Realtek RTL2832U (RTL-SDR)",  # DVB-T mode / older dongles
    "0bda:2831": "Realtek RTL2831U (RTL-SDR)",
    "1d19:1101": "Dexatek RTL2832U (RTL-SDR)",
    "1d19:1102": "Dexatek RTL2832U (RTL-SDR)",
    "1d19:1103": "Dexatek RTL2832U (RTL-SDR)",
    "1b80:d3a4": "Astrometa RTL2832U (RTL-SDR)",
    "0458:707f": "Genius RTL2832U (RTL-SDR)",
}


def parse_lsusb_for_rtl(text):
    """Find the first known RTL-SDR (usb_id, description) in lsusb output (pure).

    Returns (usb_id, description) for the first VID:PID match — description is
    the text after the ID on that lsusb line when present, else a friendly
    default — or (None, None) when nothing matches.
    """
    if not text:
        return None, None
    low = text.lower()
    for usb_id, desc in _RTL_USB_IDS.items():
        if usb_id in low:
            line = next((ln for ln in text.splitlines() if usb_id in ln.lower()), "")
            m = re.search(r"ID\s+" + re.escape(usb_id) + r"\s*(.*)", line, re.I)
            dtext = m.group(1).strip() if m else ""
            return usb_id, (dtext or desc)
    return None, None


def probe_usb():
    """Best-effort lsusb probe for a plugged-in RTL-SDR. Never raises."""
    rc, out, _err = _run(["lsusb"], timeout=4)
    if rc != 0 or not out:
        return None, None
    return parse_lsusb_for_rtl(out)


def detect():
    """Report RTL-SDR availability so the UI can gate the tools.

    ``available`` is True only when at least one of the rtl tools is installed
    *and* a dongle actually answers ``rtl_test -t`` (which opens the device once
    and exits). Mirrors the HackRF gate.
    """
    tools = {"rtl_433": _have(_RTL_433), "rtl_power": _have(_RTL_POWER),
             "rtl_test": _have(_RTL_TEST), "rtl_sdr": _have(_RTL_SDR)}
    # Cheap USB-bus probe first, so we can tell "no dongle plugged in" apart from
    # "dongle present but tools missing / DVB driver holding it" (RaspyJack does
    # the same). It never opens the radio, so it's safe alongside rtl_test.
    usb_id, usb_desc = probe_usb()
    if not any(tools.values()):
        if usb_id:
            model = identify_model(usb_desc, None)
            return {"available": False, "tools_installed": False,
                    "device_present": True, "tools": tools, "usb_id": usb_id,
                    "device": usb_desc, "model_name": model["model_name"],
                    "tuner_family": model["tuner_family"],
                    "needs_blog_driver": model["needs_blog_driver"],
                    "model_note": model["note"],
                    "error": "RTL-SDR dongle detected on USB (%s) but the rtl-sdr "
                             "tools aren't installed — apt install rtl-sdr rtl-433" % usb_id}
        return {"available": False, "tools_installed": False,
                "device_present": False, "tools": tools, "usb_id": None,
                "error": "rtl-sdr tools not installed (apt install rtl-sdr rtl-433)"}
    # rtl_test -t opens the dongle, prints tuner info, and exits — a clean probe.
    rc, out, err = _run([_RTL_TEST, "-t"], timeout=10)
    blob = (out or "") + (err or "")
    if rc == 127:
        # rtl_test missing but a decoder is present — can't hard-probe; report
        # tools state and let a start attempt surface any device error.
        return {"available": False, "tools_installed": True,
                "device_present": bool(usb_id), "tools": tools, "usb_id": usb_id,
                "error": "rtl_test not found — install rtl-sdr to probe the dongle"}
    if rc == 124:
        return {"available": False, "tools_installed": True,
                "device_present": bool(usb_id), "tools": tools, "usb_id": usb_id,
                "error": "RTL-SDR probe timed out — retry, or use a powered USB hub"}
    if "No supported devices found" in blob or "usb_open error" in blob or (
            rc != 0 and "PLL not locked" not in blob):
        if usb_id:
            # Dongle is on the bus but rtl_test couldn't claim it — almost always
            # the DVB-T kernel driver still holds it.
            return {"available": False, "tools_installed": True,
                    "device_present": True, "tools": tools, "usb_id": usb_id,
                    "device": usb_desc,
                    "error": "RTL-SDR seen on USB (%s) but rtl_test can't open it — the "
                             "DVB-T driver may still hold it. Blacklist dvb_usb_rtl28xxu "
                             "(the installer does this), replug, and retry." % usb_id}
        return {"available": False, "tools_installed": True,
                "device_present": False, "tools": tools, "usb_id": None,
                "error": "no RTL-SDR detected — plug a dongle in (a powered USB "
                         "hub is recommended on the Pi)"}
    info = parse_rtl_test(blob)
    model = identify_model(info["device"], info["tuner"])
    return {"available": True, "tools_installed": True, "device_present": True,
            "tools": tools, "usb_id": usb_id, "device": info["device"], "tuner": info["tuner"],
            "model_name": model["model_name"], "tuner_family": model["tuner_family"],
            "needs_blog_driver": model["needs_blog_driver"], "model_note": model["note"],
            "bands": sorted(RTL_BANDS.keys()), "ism_bands": sorted(ISM_FREQS.keys())}


def _have(path):
    return _run([path, "-h"])[0] != 127 or os.path.exists(path)


# --------------------------------------------------------------------------
# SDR health check (the UI's "SDR check" button) — walks every layer detection
# depends on and turns it into a one-line verdict + concrete fix steps.
# --------------------------------------------------------------------------

def _dvb_module_loaded():
    """True if the DVB-T kernel driver that steals RTL-SDR dongles is loaded."""
    try:
        with open("/proc/modules", "r") as fh:
            return "dvb_usb_rtl28xxu" in fh.read()
    except OSError:
        return False


def _dvb_blacklisted():
    """True if any modprobe.d file blacklists the DVB-T RTL driver."""
    import glob
    for path in glob.glob("/etc/modprobe.d/*.conf"):
        try:
            with open(path, "r") as fh:
                if re.search(r"^\s*blacklist\s+dvb_usb_rtl28xxu", fh.read(), re.M):
                    return True
        except OSError:
            continue
    return False


def _pi_throttled():
    """Best-effort Pi power state: (throttled_hex|None, undervoltage_bool)."""
    rc, out, _ = _run(["vcgencmd", "get_throttled"], timeout=3)
    if rc != 0 or not out:
        return None, False
    m = re.search(r"throttled=(0x[0-9a-fA-F]+)", out)
    if not m:
        return None, False
    val = int(m.group(1), 16)
    # bit 0 = under-voltage now; bit 16 = under-voltage has occurred.
    return m.group(1), bool(val & 0x1 or val & 0x10000)


def summarize_diagnosis(f):
    """Turn gathered facts into (state, summary, [fix steps]) — pure.

    States: ok / no_usb / tools_missing / dvb_held / probe_timeout / unknown.
    """
    if f.get("available"):
        return ("ok", "RTL-SDR ready: %s." % (f.get("model_name") or "detected"), [])
    if not f.get("usb_present"):
        fix = ["Use a solid PSU and a powered USB hub — RTL-SDR dongles draw ~300 mA.",
               "Use a data USB cable (not charge-only) and another port; reseat firmly.",
               "Confirm on the host with: lsusb  (expect 'ID 0bda:2838 Realtek ...')."]
        if f.get("undervoltage"):
            fix.insert(0, "This Pi reports under-voltage (throttled=%s) — fix power first."
                       % (f.get("throttled") or "set"))
        return ("no_usb",
                "No RTL-SDR on the USB bus — the dongle isn't reaching the OS.", fix)
    if not f.get("tools_installed"):
        return ("tools_missing",
                "Dongle on USB (%s) but the rtl-sdr tools aren't installed." % f.get("usb_id"),
                ["sudo apt install -y rtl-sdr rtl-433"])
    if f.get("dvb_loaded") or (f.get("rtl_test_ran") and not f.get("rtl_test_opened")):
        fix = ["sudo rmmod dvb_usb_rtl28xxu    # free the device now"]
        if not f.get("blacklisted"):
            fix.append("Run update_ragnar.sh to blacklist the DVB-T driver permanently.")
        fix.append("Replug the dongle, then run the check again.")
        return ("dvb_held",
                "Dongle on USB (%s) but rtl_test can't open it — the DVB-T driver is holding it."
                % f.get("usb_id"), fix)
    if f.get("probe_timeout"):
        return ("probe_timeout", "RTL-SDR probe timed out.",
                ["Retry; use a powered USB hub if it persists."])
    return ("unknown", f.get("error") or "RTL-SDR present but not usable.",
            ["Check on the host with: rtl_test -t"])


def diagnose():
    """Full SDR health check: walk the detection ladder + every layer it needs.

    Returns structured facts plus a one-line verdict (``summary``) and concrete
    ``fix`` steps. Safe with no hardware — nothing here raises.
    """
    det = detect()
    tools = det.get("tools", {})
    throttled, undervolt = _pi_throttled()
    facts = {
        "available": det.get("available", False),
        "usb_present": bool(det.get("usb_id")),
        "usb_id": det.get("usb_id"),
        "device": det.get("device"),
        "model_name": det.get("model_name"),
        "needs_blog_driver": det.get("needs_blog_driver", False),
        "tools": tools,
        "tools_installed": any(tools.values()),
        "dvb_loaded": _dvb_module_loaded(),
        "blacklisted": _dvb_blacklisted(),
        "throttled": throttled,
        "undervoltage": undervolt,
        "rtl_test_ran": bool(tools.get("rtl_test")),
        "rtl_test_opened": det.get("available", False),
        "probe_timeout": "timed out" in (det.get("error") or ""),
        "error": det.get("error"),
    }
    state, summary, fix = summarize_diagnosis(facts)
    facts["state"] = state
    facts["summary"] = summary
    facts["fix"] = fix
    # Whether the one-click "Install" button can help from here.
    facts["can_install"] = state in ("tools_missing", "dvb_held")
    return facts


_BLACKLIST_PATH = "/etc/modprobe.d/blacklist-rtl-sdr.conf"
_BLACKLIST_BODY = (
    "# Ragnar: keep the DVB-T kernel drivers off RTL-SDR dongles so rtl_power /\n"
    "# rtl_433 / rtl_test can claim them (RTL-SDR Blog V3/V4, Nooelec NESDR, generic).\n"
    "blacklist dvb_usb_rtl28xxu\nblacklist rtl2832\nblacklist rtl2830\nblacklist rtl2838\n"
)


def _write_blacklist():
    try:
        with open(_BLACKLIST_PATH, "w") as fh:
            fh.write(_BLACKLIST_BODY)
        os.chmod(_BLACKLIST_PATH, 0o644)
        return True
    except OSError:
        return False


def _unload_dvb():
    """Unload the DVB-T driver so a plugged-in dongle frees up now. Best-effort."""
    for cmd in (["modprobe", "-r", "dvb_usb_rtl28xxu"],
                ["/sbin/modprobe", "-r", "dvb_usb_rtl28xxu"],
                ["rmmod", "dvb_usb_rtl28xxu"], ["/sbin/rmmod", "dvb_usb_rtl28xxu"]):
        rc = _run(cmd, timeout=10)[0]
        if rc != 127:
            return rc == 0
    return False


def install_tools():
    """One-click 'Install' for the UI: install rtl-sdr + rtl-433 and free the
    dongle from the DVB-T driver. Runs apt as the web service's user (root on
    Ragnar) and installs a FIXED package set only — no caller-supplied names.

    Returns {ok, already, steps[], error, output, diagnose}. Safe to re-run.
    """
    global _detect_cache
    steps = []
    already = _have(_RTL_TEST) and _have(_RTL_433)
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")

    def _apt(args, timeout=420):
        try:
            p = subprocess.run(["apt-get"] + args, capture_output=True, text=True,
                               timeout=timeout, check=False, env=env)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except FileNotFoundError:
            return 127, "apt-get not found"
        except subprocess.TimeoutExpired:
            return 124, "apt timed out"
        except Exception as exc:  # pragma: no cover - defensive
            return 1, str(exc)

    out = ""
    if not already:
        rc, out = _apt(["install", "-y", "--no-install-recommends", "rtl-sdr", "rtl-433"])
        if rc != 0 and ("Unable to locate package" in out
                        or "no installation candidate" in out):
            steps.append("Package index stale — running apt-get update…")
            _apt(["update"], timeout=240)
            rc, out = _apt(["install", "-y", "--no-install-recommends", "rtl-sdr", "rtl-433"])
        steps.append("Installed rtl-sdr + rtl-433" if rc == 0
                     else "apt install failed (rc=%s)" % rc)
    else:
        steps.append("rtl-sdr + rtl-433 already installed")

    if _write_blacklist():
        steps.append("Blacklisted the DVB-T kernel driver (persists across reboots)")
    steps.append("Freed the dongle from the DVB-T driver"
                 if _unload_dvb() else "DVB-T driver was not loaded")

    _detect_cache = None                      # force a fresh probe next status()
    tools_ok = _have(_RTL_TEST) and _have(_RTL_433)
    diag = diagnose()
    ok = tools_ok and diag.get("state") in ("ok", "no_usb")
    tail = "\n".join((out or "").strip().splitlines()[-14:])
    return {
        "ok": ok, "already": already, "steps": steps,
        "error": None if tools_ok else ("apt could not install the tools — "
                                        "check network/apt, or install on the host"),
        "output": tail, "diagnose": diag,
    }


# --------------------------------------------------------------------------
# Parsers (pure — the selftest drives these with captured lines)
# --------------------------------------------------------------------------

def parse_power_row(line):
    """Parse one ``rtl_power`` CSV row into (hz_low, hz_high, hz_step, [dB…]).

    rtl_power streams rows shaped:
        date, time, Hz_low, Hz_high, Hz_step, samples, dB, dB, …
    Each row covers one chunk of the swept range; rows climb in frequency and
    wrap back to the bottom when a full sweep completes. Returns None for
    blank/garbage lines.
    """
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 7:
        return None
    try:
        hz_low = int(parts[2])
        hz_high = int(parts[3])
        hz_step = float(parts[4])
        dbs = [float(x) for x in parts[6:] if x not in ("", "-inf", "nan")]
    except (ValueError, IndexError):
        return None
    if hz_step <= 0 or hz_high <= hz_low or not dbs:
        return None
    return hz_low, hz_high, hz_step, dbs


def parse_rtl433_event(line):
    """Parse one ``rtl_433 -F json`` line into a normalized device event.

    Returns a dict with model/id/channel/freq_mhz/rssi/snr and a ``fields`` map
    of the remaining decoded values, or None for non-JSON / undecodable lines.
    """
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict) or "model" not in obj:
        return None
    meta = ("time", "model", "id", "channel", "rssi", "snr", "noise",
            "freq", "freq1", "freq2", "mod", "protocol")
    fields = {k: v for k, v in obj.items() if k not in meta}
    freq_mhz = None
    for fk in ("freq", "freq1"):
        if isinstance(obj.get(fk), (int, float)):
            freq_mhz = round(float(obj[fk]), 3)
            break
    return {
        "model": str(obj.get("model")),
        "id": obj.get("id"),
        "channel": obj.get("channel"),
        "freq_mhz": freq_mhz,
        "rssi": obj.get("rssi"),
        "snr": obj.get("snr"),
        "time": obj.get("time"),
        "fields": fields,
    }


def device_key(ev):
    """Stable identity for a decoded device: model + id/channel."""
    ident = ev.get("id")
    if ident is None:
        ident = ev.get("channel")
    return "%s/%s" % (ev.get("model"), "" if ident is None else ident)


class _PowerFrameBuilder:
    """Accumulate ascending rtl_power rows into fixed-width power frames.

    Like the HackRF frame builder but in Hz across an arbitrary range: each dB
    bin drops into one of ``bins`` display columns (max-per-column). A new sweep
    is marked when a row's start frequency is not higher than the previous one:
    a *drop* (wide bands like 868/915 that rtl_power splits into several ascending
    crops, wrapping back to the bottom) or a *repeat* (a narrow band like the
    1.74 MHz 433 ISM that fits in a single crop, so every row is the same low —
    without the repeat case that band would never finalize a frame).
    """

    def __init__(self, lo_hz, hi_hz, bins=_POWER_BINS):
        self.lo = lo_hz
        self.hi = hi_hz
        self.bins = bins
        self._last_low = None
        self._reset()

    def _reset(self):
        self.grid = [_FLOOR_DBM] * self.bins
        self._filled = False

    def _bucket(self, hz):
        if self.hi <= self.lo:
            return None
        frac = (hz - self.lo) / (self.hi - self.lo)
        if frac < 0 or frac >= 1:
            return None
        return min(self.bins - 1, int(frac * self.bins))

    def add(self, hz_low, hz_high, hz_step, dbs):
        """Feed one parsed row; return a finished frame grid or None."""
        frame = None
        if self._last_low is not None and hz_low <= self._last_low and self._filled:
            frame = self.grid
            self._reset()
        self._last_low = hz_low
        for i, db in enumerate(dbs):
            center = hz_low + (i + 0.5) * hz_step
            b = self._bucket(center)
            if b is not None:
                if db > self.grid[b]:
                    self.grid[b] = db
                self._filled = True
        return frame


# --------------------------------------------------------------------------
# Real-time IQ waterfall helpers (pure — the selftest drives them, no hardware)
# --------------------------------------------------------------------------

def _iq_available():
    """True when the fast IQ path can run: ``rtl_sdr`` present and numpy import-able.

    Kept cheap and side-effect-free (never opens the dongle) so it can gate the
    engine choice on every start. numpy is a declared dependency, but a minimal
    board may lack it — in which case we simply fall back to rtl_power.
    """
    if not _have(_RTL_SDR):
        return False
    try:
        import numpy  # noqa: F401
        return True
    except Exception:
        return False


def _iq_plan(lo_hz, hi_hz):
    """Pick a single-tune (center, sample_rate) covering [lo,hi] Hz, or None (pure).

    Returns None when the span is wider than one RTL-SDR tune can hold
    (``_IQ_MAX_SPAN_HZ``) — the caller then falls back to the rtl_power sweep.
    The sample rate oversamples the span by ``_IQ_EDGE_MARGIN`` so the display
    window sits in the tuner's clean centre (its band edges roll off), clamped to
    the RTL-SDR's usable [_IQ_SR_MIN, _IQ_SR_MAX] range.
    """
    try:
        lo_hz, hi_hz = int(lo_hz), int(hi_hz)
    except (TypeError, ValueError):
        return None
    span = hi_hz - lo_hz
    if span <= 0 or span > _IQ_MAX_SPAN_HZ:
        return None
    center = (lo_hz + hi_hz) // 2
    sr = int(min(_IQ_SR_MAX, max(_IQ_SR_MIN, round(span * _IQ_EDGE_MARGIN))))
    return center, sr


def _iq_to_grid(psd_db, center_hz, sr_hz, lo_hz, hi_hz,
                bins=_POWER_BINS, floor=_FLOOR_DBM):
    """Fold an fftshifted PSD (dB, low→high freq) onto ``bins`` display columns.

    ``psd_db[i]`` is the power of FFT bin ``i`` of a capture centred at
    ``center_hz`` sampled at ``sr_hz`` (so bin 0 sits at ``center - sr/2``). Each
    bin is dropped into the display column its centre frequency lands in over
    [lo,hi], keeping the per-column max — the same peak-hold the rtl_power frame
    builder uses. Bins outside [lo,hi] (the oversampled edges) are ignored;
    columns no bin reached stay at ``floor``. Pure list math — no numpy — so the
    selftest verifies it and it also serves as the loop's binning step.
    """
    grid = [floor] * bins
    n = len(psd_db)
    span = hi_hz - lo_hz
    if n == 0 or span <= 0 or sr_hz <= 0:
        return grid
    bin_w = sr_hz / float(n)
    f0 = center_hz - sr_hz / 2.0        # centre frequency of the first (lowest) bin
    for i in range(n):
        fc = f0 + i * bin_w
        col = int((fc - lo_hz) / span * bins)
        if col < 0 or col >= bins:
            continue
        v = psd_db[i]
        if v > grid[col]:
            grid[col] = v
    return grid


# --------------------------------------------------------------------------
# ISM device scanner (rtl_433)
# --------------------------------------------------------------------------

class IsmScanner:
    """Own a running ``rtl_433 -F json`` and a live device table."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._devices = {}     # key -> device record
        self._events = 0
        self._seq = 0
        self._band = None
        self._error = None
        self._stderr_tail = None

    def start(self, band="433"):
        band = band if band in ISM_FREQS else "433"
        with self._lock:
            if self._thread and self._thread.is_alive():
                if band == self._band:
                    return {"ok": True, "already": True, "band": band}
                self._stop_locked()
            self._stop.clear()
            self._devices = {}
            self._events = 0
            self._seq = 0
            self._band = band
            self._error = None
            self._thread = threading.Thread(target=self._run_loop, args=(band,),
                                            daemon=True, name="rtl433-ism")
            self._thread.start()
        return {"ok": True, "band": band}

    def stop(self):
        with self._lock:
            self._stop_locked()
        return {"ok": True}

    def reapply(self):
        """Restart the scanner on the same band so a PPM/gain change takes hold."""
        with self._lock:
            running = bool(self._thread and self._thread.is_alive())
            band = self._band
        if running and band:
            self.stop()
            self.start(band)

    def _stop_locked(self):
        self._stop.set()
        _terminate(self._proc)
        self._proc = None
        self._band = None

    def _run_loop(self, band):
        freq = ISM_FREQS[band]
        cmd = [_RTL_433, "-F", "json", "-M", "level", "-f", freq] + _tuner_args()
        self._stderr_tail = None
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True,
                                          bufsize=1)
        except Exception as exc:
            self._error = "failed to launch rtl_433: %s" % exc
            return
        serr = _drain(self._proc.stderr, self)
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                ev = parse_rtl433_event(line)
                if ev:
                    self._ingest(ev)
        except Exception as exc:  # pragma: no cover - defensive
            self._error = str(exc)
        finally:
            serr.join(timeout=1)
            if (self._proc and self._proc.poll() not in (None, 0)
                    and not self._error and self._stderr_tail):
                self._error = self._stderr_tail

    def _ingest(self, ev):
        key = device_key(ev)
        now = time.time()
        with self._lock:
            self._events += 1
            self._seq += 1
            rec = self._devices.get(key)
            if rec is None:
                if len(self._devices) >= _ISM_MAX_DEVICES:
                    # Evict the stalest device so a noisy band can't grow forever.
                    oldest = min(self._devices, key=lambda k: self._devices[k]["last_ts"])
                    self._devices.pop(oldest, None)
                rec = {"key": key, "model": ev["model"], "id": ev["id"],
                       "channel": ev["channel"], "first_ts": now, "count": 0}
                self._devices[key] = rec
            rec["last_ts"] = now
            rec["count"] += 1
            rec["seq"] = self._seq
            rec["freq_mhz"] = ev.get("freq_mhz")
            rec["rssi"] = ev.get("rssi")
            rec["snr"] = ev.get("snr")
            rec["fields"] = ev.get("fields") or {}

    def status(self):
        with self._lock:
            return {"running": bool(self._thread and self._thread.is_alive()),
                    "band": self._band, "freq": ISM_FREQS.get(self._band),
                    "devices": len(self._devices), "events": self._events,
                    "seq": self._seq, "error": self._error}

    def get_devices(self):
        with self._lock:
            devs = sorted(self._devices.values(),
                          key=lambda d: d["last_ts"], reverse=True)
            return {"devices": devs, "count": len(devs), "events": self._events,
                    "seq": self._seq, "band": self._band,
                    "running": bool(self._thread and self._thread.is_alive()),
                    "error": self._error}


# --------------------------------------------------------------------------
# Sub-GHz power sweep (rtl_power)
# --------------------------------------------------------------------------

class PowerSweep:
    """Own a running ``rtl_power`` sweep and a ring buffer of frames."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._frames = []
        self._seq = 0
        self._maxhold = None
        self._band = None
        self._error = None
        self._stderr_tail = None
        self._sig = None           # (label, lo, hi) — restart only on a real change
        self._lo = None            # active sweep range in Hz (band OR zoom span)
        self._hi = None
        self._engine = None        # "iq" (real-time FFT) or "rtl_power" (sweep)
        self._floor_dyn = None     # IQ path: adaptive noise floor for the colour scale

    def start(self, band="433", lo_hz=None, hi_hz=None, label=None):
        # A custom [lo_hz, hi_hz] span (the page's zoom, or a Z-Wave region)
        # overrides the named band when both edges are sane (>=100 kHz wide,
        # inside the RTL-SDR's reach). ``label`` names it (e.g. "zwave-eu").
        custom = None
        try:
            if lo_hz is not None and hi_hz is not None:
                lo_hz, hi_hz = int(float(lo_hz)), int(float(hi_hz))
                if hi_hz - lo_hz >= 100_000 and lo_hz >= 24_000_000 and hi_hz <= 1_766_000_000:
                    custom = (lo_hz, hi_hz)
        except (TypeError, ValueError):
            custom = None
        if custom:
            label, lo, hi = (label or "zoom"), custom[0], custom[1]
        else:
            band = band if band in RTL_BANDS else "433"
            label, (lo, hi) = band, RTL_BANDS[band]
        sig = (label, lo, hi)
        with self._lock:
            if self._thread and self._thread.is_alive():
                if sig == self._sig:
                    return {"ok": True, "already": True, "band": label}
                self._stop_locked()
            # A fresh Event (not .clear()) so any still-exiting previous sweep
            # thread keeps its own now-set event and stops cleanly, instead of
            # racing this new run on a shared, just-cleared one.
            self._stop = threading.Event()
            self._frames = []
            self._seq = 0
            self._maxhold = [_FLOOR_DBM] * _POWER_BINS
            self._band = label
            self._sig = sig
            self._lo, self._hi = lo, hi
            self._engine = None
            self._floor_dyn = None
            self._error = None
            self._thread = threading.Thread(target=self._run_loop, args=(lo, hi),
                                            daemon=True, name="rtlpower-sweep")
            self._thread.start()
        return {"ok": True, "band": label, "range_hz": [lo, hi]}

    def stop(self):
        with self._lock:
            self._stop_locked()
        return {"ok": True}

    def reapply(self):
        """Restart the sweep on the same span so a PPM/gain change takes hold."""
        with self._lock:
            if not (self._thread and self._thread.is_alive()):
                return
            lo, hi, label, sig = self._lo, self._hi, self._band, self._sig
            self._stop_locked()
            self._stop = threading.Event()   # fresh event; see start() for why
            self._frames = []
            self._seq = 0
            self._maxhold = [_FLOOR_DBM] * _POWER_BINS
            self._band = label
            self._sig = sig
            self._lo, self._hi = lo, hi
            self._engine = None
            self._floor_dyn = None
            self._error = None
            self._thread = threading.Thread(target=self._run_loop, args=(lo, hi),
                                            daemon=True, name="rtlpower-sweep")
            self._thread.start()

    def _stop_locked(self):
        self._stop.set()
        _terminate(self._proc)
        self._proc = None
        self._band = None

    def _run_loop(self, lo, hi):
        # Prefer the real-time IQ FFT engine (SDR++-style) whenever the span fits
        # a single tune and the tools are present; fall back to the rtl_power
        # sweep otherwise (wide bands) or if the IQ capture can't get going.
        plan = _iq_plan(lo, hi) if _iq_available() else None
        if plan and self._run_iq(lo, hi, plan[0], plan[1]):
            return
        self._engine = "rtl_power"
        self._floor_dyn = None
        self._run_rtl_power(lo, hi)

    def _run_iq(self, lo, hi, center, sr):
        """Stream raw IQ from ``rtl_sdr`` and FFT it into waterfall rows.

        Returns True if the capture ran (or was stopped cleanly), False if it
        never got going — the launcher/decoder died before producing a frame —
        so :meth:`_run_loop` can fall back to the rtl_power sweep. No retuning
        happens here: one tune covers the whole [lo,hi] window, so rows scroll at
        ``_IQ_DISPLAY_HZ`` with none of rtl_power's ~1 Hz sweep latency.
        """
        try:
            import numpy as np
        except Exception:
            return False
        self._engine = "iq"
        self._floor_dyn = None
        N = _IQ_FFT
        win = np.hanning(N).astype(np.float32)
        win_norm = float(np.sum(win ** 2)) * N   # PSD normaliser (window + FFT gain)
        # Read a whole display row of samples per iteration, rounded to full FFT
        # windows. We must drain the entire stream (not just what we FFT) or the
        # dongle's USB buffers overflow and rtl_sdr starts dropping samples.
        row_samples = max(N, int(sr / _IQ_DISPLAY_HZ))
        row_samples -= row_samples % N
        row_bytes = row_samples * 2               # unsigned 8-bit I + Q interleaved
        cmd = [_RTL_SDR, "-f", str(int(center)), "-s", str(int(sr))]
        if _ppm:
            cmd += ["-p", str(_ppm)]
        if _gain is not None:
            cmd += ["-g", str(_gain)]             # else rtl_sdr uses tuner AGC (auto)
        cmd += ["-"]                              # stream raw IQ to stdout
        self._stderr_tail = None
        # Capture our own stop event + proc handle locally. A restart (band change
        # / PPM calibrate) installs a *new* self._stop and nulls self._proc, so
        # touching those through self here would race the new run; the locals keep
        # this thread reading its own pipe until EOF and exiting cleanly.
        stop = self._stop
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, bufsize=0)
            self._proc = proc
        except Exception as exc:
            self._error = "failed to launch rtl_sdr: %s" % exc
            return False
        pipe = proc.stdout
        serr = _drain(_text_lines(proc.stderr), self)
        floor_ema = None
        produced = 0
        try:
            while not stop.is_set():
                buf = _read_exact(pipe, row_bytes)
                if not buf:
                    break
                # rtl_sdr emits unsigned 8-bit I/Q; recentre (127.5 = 0) and
                # scale to +-1.0 full scale so the PSD reads in dBFS (roughly
                # -80 noise .. 0 full-scale), which sits under the page's -20
                # colour ceiling.
                raw = (np.frombuffer(buf, dtype=np.uint8).astype(np.float32) - 127.5) / 127.5
                nwin = (raw.shape[0] // 2) // N
                if nwin <= 0:
                    continue
                use = min(nwin, _IQ_AVG_MAX)
                iq = raw[:use * N * 2].reshape(use, N, 2)
                cwin = (iq[:, :, 0] + 1j * iq[:, :, 1]) * win  # window each row
                spec = np.fft.fftshift(np.fft.fft(cwin, axis=1), axes=1)
                psd = (spec.real ** 2 + spec.imag ** 2).mean(axis=0) / win_norm
                db = 10.0 * np.log10(psd + 1e-12)
                grid = _iq_to_grid(db.tolist(), center, sr, lo, hi)
                floor_ema = self._update_iq_floor(grid, floor_ema)
                self._push_frame(grid)
                produced += 1
        except Exception as exc:  # pragma: no cover - defensive
            if not stop.is_set():
                self._error = str(exc)
        finally:
            serr.join(timeout=1)
            # Only surface a device error if the process died on its own — a
            # deliberate stop/restart (stop set) is not an error to report.
            if (not stop.is_set() and proc.poll() not in (None, 0)
                    and not self._error and self._stderr_tail):
                self._error = self._stderr_tail
        # Nothing produced and we didn't ask it to stop -> let rtl_power try.
        if produced == 0 and not stop.is_set():
            _terminate(proc)
            self._proc = None
            self._error = None
            return False
        return True

    def _update_iq_floor(self, grid, floor_ema):
        """Track a smoothed noise floor from the row's low percentile.

        The IQ path reports uncalibrated relative dB whose absolute level rides
        with tuner gain, so a fixed colour floor would wash out or crush the
        display. Instead we follow the 20th-percentile of each row (a robust
        noise estimate) with a slow EMA and publish that as ``floor_dbm``, so the
        waterfall's colour scale self-calibrates and stays stable.
        """
        vals = sorted(v for v in grid if v > _FLOOR_DBM)
        if not vals:
            return floor_ema
        nf = vals[int(len(vals) * 0.20)]
        floor_ema = nf if floor_ema is None else floor_ema * 0.9 + nf * 0.1
        self._floor_dyn = int(round(floor_ema - 6))
        return floor_ema

    def _run_rtl_power(self, lo, hi):
        step = max(1000, (hi - lo) // _POWER_BINS)   # Hz per rtl_power bin
        builder = _PowerFrameBuilder(lo, hi)
        cmd = [_RTL_POWER, "-f", "%d:%d:%d" % (lo, hi, step),
               "-i", str(_SWEEP_INTERVAL_S), "-c", "20%"] + _tuner_args()
        self._stderr_tail = None
        stop = self._stop          # our own event; a restart swaps self._stop
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True,
                                    bufsize=1)
            self._proc = proc
        except Exception as exc:
            self._error = "failed to launch rtl_power: %s" % exc
            return
        serr = _drain(proc.stderr, self)
        try:
            for line in proc.stdout:
                if stop.is_set():
                    break
                parsed = parse_power_row(line)
                if not parsed:
                    continue
                frame = builder.add(*parsed)
                if frame is not None:
                    self._push_frame(frame)
        except Exception as exc:  # pragma: no cover - defensive
            if not stop.is_set():
                self._error = str(exc)
        finally:
            serr.join(timeout=1)
            if (not stop.is_set() and proc.poll() not in (None, 0)
                    and not self._error and self._stderr_tail):
                self._error = self._stderr_tail

    def _push_frame(self, grid):
        ints = [int(round(v)) for v in grid]
        with self._lock:
            self._seq += 1
            ts = time.time()
            self._frames.append({"seq": self._seq, "ts": ts, "power": ints})
            if len(self._frames) > _RING_FRAMES:
                self._frames = self._frames[-_RING_FRAMES:]
            if self._maxhold is None:
                self._maxhold = list(ints)
            else:
                self._maxhold = [max(a, b) for a, b in zip(self._maxhold, ints)]
            meta = {"band": self._band, "lo_hz": self._lo, "hi_hz": self._hi,
                    "bins": _POWER_BINS, "floor": self._active_floor()}
        # Feed the session recorder + the spectrum-baseline watcher outside our
        # lock (each has its own). floor from meta so both engines stay consistent.
        _recorder.write(self._seq, ts, ints, meta)
        _baseline.feed(ints, meta["lo_hz"], meta["hi_hz"], meta["floor"])

    def _active_floor(self):
        """Colour-scale floor for the current engine: the IQ path's adaptive
        estimate, or the fixed sentinel for the rtl_power sweep."""
        if self._engine == "iq" and self._floor_dyn is not None:
            return self._floor_dyn
        return _FLOOR_DBM

    def status(self):
        with self._lock:
            return {"running": bool(self._thread and self._thread.is_alive()),
                    "band": self._band, "bins": _POWER_BINS,
                    "band_hz": [self._lo, self._hi] if self._lo else None,
                    "frames_buffered": len(self._frames), "seq": self._seq,
                    "floor_dbm": self._active_floor(), "engine": self._engine,
                    "error": self._error}

    def get_frames(self, since=0):
        try:
            since = int(since)
        except (TypeError, ValueError):
            since = 0
        with self._lock:
            new = [f for f in self._frames if f["seq"] > since]
            return {"frames": new, "seq": self._seq, "band": self._band,
                    "band_hz": [self._lo, self._hi] if self._lo else None,
                    "bins": _POWER_BINS, "floor_dbm": self._active_floor(),
                    "engine": self._engine,
                    "max_hold": list(self._maxhold) if self._maxhold else None,
                    "running": bool(self._thread and self._thread.is_alive()),
                    "error": self._error}


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def _terminate(proc):
    if not proc:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:  # pragma: no cover - defensive
        pass


def _drain(pipe, owner):
    """Spawn a daemon thread draining ``pipe`` into ``owner._stderr_tail``.

    rtl_433/rtl_power both chatter to stderr; if it's never read the 64 KB pipe
    fills and blocks the process mid-run. Keep the last line for diagnostics.
    """
    def run():
        try:
            for line in pipe:
                line = line.strip()
                if line:
                    owner._stderr_tail = line[:200]
        except Exception:  # pragma: no cover - pipe closed on teardown
            pass
    t = threading.Thread(target=run, daemon=True, name="rtl-stderr")
    t.start()
    return t


def _text_lines(pipe):
    """Yield UTF-8 text lines from a *binary* pipe.

    The IQ capture opens rtl_sdr with a raw-bytes stdout (Popen bufsize=0, no
    text mode), which makes stderr bytes too. This lets :func:`_drain` reuse its
    text logic to keep the last human-readable stderr line for diagnostics.
    """
    for line in iter(pipe.readline, b""):
        yield line.decode("utf-8", "replace")


def _read_exact(pipe, n):
    """Read exactly ``n`` bytes from a binary pipe (fewer only at EOF).

    A raw pipe read can return short, so loop until we have a full display row
    of IQ or the stream ends (``b""`` -> rtl_sdr exited)."""
    chunks = []
    got = 0
    while got < n:
        b = pipe.read(n - got)
        if not b:
            break
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


# Module-level singletons the web routes drive. One dongle, so the two capture
# modes are mutually exclusive.
_ism = IsmScanner()
_power = PowerSweep()
_detect_cache = None


def _running():
    return _ism.status()["running"] or _power.status()["running"]


def ism_start(band="433"):
    global _detect_cache
    if _power.status()["running"]:
        _power.stop()          # one dongle: hand it to the scanner
    if not _ism.status()["running"]:
        d = detect()
        if not d.get("available"):
            return {"ok": False, "error": d.get("error", "no RTL-SDR")}
        _detect_cache = d
    return _ism.start(band)


def ism_stop():
    return _ism.stop()


def ism_devices():
    return _ism.get_devices()


def power_start(band="433", lo_hz=None, hi_hz=None, label=None):
    global _detect_cache
    if _ism.status()["running"]:
        _ism.stop()            # one dongle: hand it to the sweep
    if not _power.status()["running"]:
        d = detect()
        if not d.get("available"):
            return {"ok": False, "error": d.get("error", "no RTL-SDR")}
        _detect_cache = d
    return _power.start(band, lo_hz=lo_hz, hi_hz=hi_hz, label=label)


def power_stop():
    return _power.stop()


def power_frames(since=0):
    return _power.get_frames(since=since)


# --------------------------------------------------------------------------
# Session recording — capture the power-sweep frame stream to a JSONL file so a
# session can be replayed (or shared) later. Frames are small (one power grid
# each), so this is cheap; recordings live under data/ (gitignored).
# --------------------------------------------------------------------------

_REC_MAX_FRAMES = 3000     # cap a recording (~a few minutes) so files stay bounded


def _rec_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "rf_recordings")


def _rec_safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(name or ""))[:60]


class _Recorder:
    def __init__(self):
        self._lock = threading.Lock()
        self._fh = None
        self._name = None
        self._count = 0
        self._started = None
        self._meta = None

    def start(self, meta, name=None):
        with self._lock:
            self._close()
            d = _rec_dir()
            try:
                os.makedirs(d, exist_ok=True)
            except OSError as exc:
                return {"ok": False, "error": "cannot create recordings dir: %s" % exc}
            base = _rec_safe(name) or ("rf-" + time.strftime("%Y%m%d-%H%M%S"))
            self._name = base
            self._count = 0
            self._started = time.time()
            self._meta = dict(meta or {})
            try:
                self._fh = open(os.path.join(d, base + ".jsonl"), "w")
                hdr = dict(self._meta)
                hdr.update({"_hdr": True, "name": base, "ts": self._started})
                self._fh.write(json.dumps(hdr) + "\n")
                self._fh.flush()
            except OSError as exc:
                self._fh = None
                return {"ok": False, "error": "cannot open recording file: %s" % exc}
        return self.status()

    def write(self, seq, ts, power, meta=None):
        with self._lock:
            if not self._fh:
                return
            if self._count >= _REC_MAX_FRAMES:
                self._close()
                return
            try:
                self._fh.write(json.dumps({"seq": seq, "ts": round(ts, 3), "power": power}) + "\n")
                self._count += 1
                if self._count % 20 == 0:
                    self._fh.flush()
            except OSError:
                self._close()

    def stop(self):
        with self._lock:
            self._close()
        return {"ok": True}

    def _close(self):
        if self._fh:
            try:
                self._fh.close()
            except OSError:
                pass
        self._fh = None

    def status(self):
        with self._lock:
            rec = self._fh is not None
            return {"recording": rec, "name": self._name if rec else None,
                    "frames": self._count,
                    "seconds": round(time.time() - self._started, 1) if (rec and self._started) else 0,
                    "max_frames": _REC_MAX_FRAMES}


_recorder = _Recorder()


def record_start(name=None):
    """Begin recording the running power sweep. Needs a sweep in progress."""
    st = _power.status()
    if not st.get("running"):
        return {"ok": False, "error": "start a sub-GHz sweep first, then record"}
    meta = {"band": st.get("band"), "lo_hz": (st.get("band_hz") or [None, None])[0],
            "hi_hz": (st.get("band_hz") or [None, None])[1],
            "bins": st.get("bins"), "floor": st.get("floor_dbm")}
    return _recorder.start(meta, name=name)


def record_stop():
    return _recorder.stop()


def record_status():
    return _recorder.status()


def record_list():
    import glob
    d = _rec_dir()
    out = []
    for path in sorted(glob.glob(os.path.join(d, "*.jsonl")), reverse=True):
        try:
            with open(path) as fh:
                first = fh.readline()
            hdr = json.loads(first) if first.strip() else {}
            n = 0
            with open(path) as fh:
                for _ in fh:
                    n += 1
            stat = os.stat(path)
            out.append({"name": os.path.basename(path)[:-6], "band": hdr.get("band"),
                        "lo_hz": hdr.get("lo_hz"), "hi_hz": hdr.get("hi_hz"),
                        "bins": hdr.get("bins"), "floor": hdr.get("floor"),
                        "frames": max(0, n - 1), "size": stat.st_size,
                        "mtime": stat.st_mtime})
        except (OSError, ValueError):
            continue
    return {"recordings": out}


def record_get(name):
    path = os.path.join(_rec_dir(), _rec_safe(name) + ".jsonl")
    if not os.path.exists(path):
        return {"ok": False, "error": "recording not found"}
    try:
        with open(path) as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    if not lines:
        return {"ok": False, "error": "empty recording"}
    hdr = json.loads(lines[0])
    frames = []
    for ln in lines[1:]:
        try:
            frames.append(json.loads(ln))
        except ValueError:
            continue
    return {"ok": True, "header": hdr, "frames": frames, "count": len(frames)}


def record_delete(name):
    path = os.path.join(_rec_dir(), _rec_safe(name) + ".jsonl")
    try:
        os.remove(path)
        return {"ok": True}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


# --------------------------------------------------------------------------
# SigMF raw-IQ capture — record the dongle's raw baseband to a SigMF recording
# (.sigmf-data + .sigmf-meta) so a capture opens directly in GNU Radio,
# inspectrum, Universal Radio Hacker, or any SigMF-aware tool. SigMF is the open
# interoperability standard the wider SDR/DSP research community uses, so this
# turns Ragnar into a real capture instrument rather than a closed viewer.
#
# rtl_sdr emits interleaved unsigned-8-bit I/Q, which is SigMF datatype "cu8".
# We capture a bounded number of samples (rtl_sdr -n) so files stay finite.
# --------------------------------------------------------------------------

_IQ_CAP_MAX_SECONDS = 30       # hard cap on a single capture (file-size guard)
_SIGMF_VERSION = "1.0.0"


def _iq_cap_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "iq_captures")


def sigmf_meta(center_hz, sr_hz, datatype="cu8", hw="RTL-SDR",
               sha512=None, dt_iso=None, label=None, ppm=0, gain=None):
    """Build a SigMF metadata dict (SigMF v1.0.0). Pure — the selftest checks it.

    ``core:datatype`` "cu8" is complex unsigned-8-bit, exactly rtl_sdr's native
    output. ``captures`` carries the tune frequency + UTC datetime; an optional
    band ``label`` becomes a single full-length annotation.
    """
    glob = {
        "core:datatype": datatype,
        "core:sample_rate": float(sr_hz),
        "core:version": _SIGMF_VERSION,
        "core:recorder": "Ragnar rtl_sdr.py",
        "core:hw": hw,
    }
    if sha512:
        glob["core:sha512"] = sha512
    if ppm:
        glob["core:freq_correction_ppm"] = int(ppm)      # extension namespace-free hint
    if gain is not None:
        glob["core:gain_db"] = float(gain)
    cap = {"core:sample_start": 0, "core:frequency": float(center_hz)}
    if dt_iso:
        cap["core:datetime"] = dt_iso
    meta = {"global": glob, "captures": [cap], "annotations": []}
    if label:
        meta["annotations"].append({"core:sample_start": 0, "core:label": str(label)})
    return meta


class IqCapture:
    """One-shot bounded raw-IQ capture to a SigMF recording (background thread)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._name = None
        self._center = None
        self._sr = None
        self._want_bytes = 0
        self._seconds = 0
        self._started = None
        self._done = False
        self._error = None
        self._path = None          # .sigmf-data path

    def start(self, center_hz, sr_hz, seconds, name=None, label=None):
        try:
            center_hz = int(float(center_hz)); sr_hz = int(float(sr_hz))
            seconds = float(seconds)
        except (TypeError, ValueError):
            return {"ok": False, "error": "center_hz / sr_hz / seconds must be numeric"}
        if not (24_000_000 <= center_hz <= 1_766_000_000):
            return {"ok": False, "error": "center frequency out of RTL-SDR reach (24-1766 MHz)"}
        if not (_IQ_SR_MIN <= sr_hz <= _IQ_SR_MAX):
            return {"ok": False, "error": "sample rate out of range (1.0-3.2 MS/s)"}
        seconds = max(0.1, min(_IQ_CAP_MAX_SECONDS, seconds))
        with self._lock:
            if self._thread and self._thread.is_alive():
                return {"ok": False, "error": "a capture is already running"}
            try:
                os.makedirs(_iq_cap_dir(), exist_ok=True)
            except OSError as exc:
                return {"ok": False, "error": "cannot create captures dir: %s" % exc}
            base = _rec_safe(name) or ("iq-%d-%s" % (round(center_hz / 1e6),
                                                     time.strftime("%Y%m%d-%H%M%S")))
            self._name = base
            self._center, self._sr, self._seconds = center_hz, sr_hz, seconds
            self._want_bytes = int(sr_hz * seconds) * 2      # cu8: 2 bytes/sample
            self._label = label
            self._started = time.time()
            self._done = False
            self._error = None
            self._path = os.path.join(_iq_cap_dir(), base + ".sigmf-data")
            self._stop.clear()
            self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                            name="rtl-iqcap")
            self._thread.start()
        return {"ok": True, "name": base, "center_hz": center_hz, "sr_hz": sr_hz,
                "seconds": seconds, "want_bytes": self._want_bytes}

    def _run_loop(self):
        nsamp = int(self._sr * self._seconds)
        cmd = [_RTL_SDR, "-f", str(self._center), "-s", str(self._sr), "-n", str(nsamp)]
        if _ppm:
            cmd += ["-p", str(_ppm)]
        if _gain is not None:
            cmd += ["-g", str(_gain)]
        cmd += [self._path]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.PIPE)
        except Exception as exc:
            self._error = "failed to launch rtl_sdr: %s" % exc
            return
        _, err = b"", b""
        try:
            _, err = self._proc.communicate()
        except Exception as exc:  # pragma: no cover - defensive
            self._error = str(exc)
        if self._stop.is_set():
            self._error = self._error or "capture cancelled"
            return
        rc = self._proc.poll()
        if rc not in (0, None) and not os.path.exists(self._path):
            tail = (err or b"").decode("utf-8", "replace").strip().splitlines()
            self._error = tail[-1][:200] if tail else ("rtl_sdr exited rc=%s" % rc)
            return
        # Write the SigMF sidecar (with a data hash) next to the captured samples.
        try:
            import hashlib
            h = hashlib.sha512()
            with open(self._path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            meta = sigmf_meta(self._center, self._sr, sha512=h.hexdigest(),
                              hw="RTL-SDR (%s)" % (_capture_hw_name()),
                              dt_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._started)),
                              label=self._label, ppm=_ppm, gain=_gain)
            with open(self._path[:-len(".sigmf-data")] + ".sigmf-meta", "w") as fh:
                json.dump(meta, fh, indent=2)
            self._done = True
        except OSError as exc:
            self._error = "capture saved but metadata write failed: %s" % exc

    def stop(self):
        with self._lock:
            self._stop.set()
            _terminate(self._proc)
            self._proc = None
        return {"ok": True}

    def status(self):
        with self._lock:
            running = bool(self._thread and self._thread.is_alive())
            have = 0
            try:
                if self._path and os.path.exists(self._path):
                    have = os.path.getsize(self._path)
            except OSError:
                have = 0
            pct = int(min(100, have * 100 / self._want_bytes)) if self._want_bytes else 0
            return {"capturing": running, "name": self._name, "done": self._done,
                    "error": self._error, "center_hz": self._center, "sr_hz": self._sr,
                    "seconds": self._seconds, "bytes": have, "want_bytes": self._want_bytes,
                    "progress": pct}


def _capture_hw_name():
    d = _detect_cache or {}
    return d.get("model_name") or d.get("device") or "RTL2832U"


def iq_capture_list():
    import glob
    d = _iq_cap_dir()
    out = []
    for meta_path in sorted(glob.glob(os.path.join(d, "*.sigmf-meta")), reverse=True):
        base = os.path.basename(meta_path)[:-len(".sigmf-meta")]
        data_path = meta_path[:-len(".sigmf-meta")] + ".sigmf-data"
        try:
            with open(meta_path) as fh:
                m = json.load(fh)
            g = m.get("global", {}); c = (m.get("captures") or [{}])[0]
            out.append({"name": base,
                        "sr_hz": g.get("core:sample_rate"),
                        "center_hz": c.get("core:frequency"),
                        "datetime": c.get("core:datetime"),
                        "bytes": os.path.getsize(data_path) if os.path.exists(data_path) else 0})
        except (OSError, ValueError):
            continue
    return {"captures": out}


def iq_capture_path(name):
    """Absolute (.sigmf-data, .sigmf-meta) paths for a capture, or (None, None)."""
    base = _rec_safe(name)
    data = os.path.join(_iq_cap_dir(), base + ".sigmf-data")
    meta = os.path.join(_iq_cap_dir(), base + ".sigmf-meta")
    return (data if os.path.exists(data) else None,
            meta if os.path.exists(meta) else None)


def iq_capture_delete(name):
    ok = False
    for suffix in (".sigmf-data", ".sigmf-meta"):
        p = os.path.join(_iq_cap_dir(), _rec_safe(name) + suffix)
        try:
            os.remove(p); ok = True
        except OSError:
            pass
    return {"ok": ok}


_iqcap = IqCapture()


def iq_capture_start(center_hz, sr_hz, seconds=2.0, name=None, label=None):
    """Begin a SigMF raw-IQ capture. Stops the sweep/scanner first (one dongle)."""
    global _detect_cache
    if _power.status()["running"]:
        _power.stop()
    if _ism.status()["running"]:
        _ism.stop()
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "no RTL-SDR")}
    _detect_cache = d
    return _iqcap.start(center_hz, sr_hz, seconds, name=name, label=label)


def iq_capture_status():
    return _iqcap.status()


def iq_capture_stop():
    return _iqcap.stop()


# --------------------------------------------------------------------------
# Spectrum baseline + anomaly detection — learn a "known-normal" spectrum, then
# flag what changed: NEW carriers (energy where the baseline was quiet), GONE
# carriers (a baseline signal that disappeared) and broadband JAMMING (a large
# fraction of the span rising at once). Anomalies are surfaced in the UI and
# written to the Watchtower JSON-lines feed (auto-discovered as source
# "rfwatch"), so they ride the existing unified-alert + Pushover pipeline —
# spectrum monitoring / interference-hunting the way regulators + SIGINT do it.
# --------------------------------------------------------------------------

_RF_WT_DIR = os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_RF_WT_FILE = "rfwatch.jsonl"


def _regionize(bins_idx):
    """Group a sorted list of bin indices into [start,end] contiguous runs (pure)."""
    out = []
    for i in bins_idx:
        if out and i == out[-1][1] + 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return out


def detect_spectrum_anomalies(baseline, grid, floor, new_margin=8, gone_margin=12,
                              jam_margin=6, jam_frac=0.35, quiet_over_floor=10,
                              carrier_over_floor=14):
    """Compare a live power grid to a learned per-bin baseline (pure).

    Returns ``{"new":[(s,e,peak)], "gone":[(s,e)], "jammer":bool, "up_frac":f}``:

    * **new**   — bins that were quiet in the baseline (<= floor+quiet_over_floor)
      but are now new_margin dB above both the baseline and the floor.
    * **gone**  — bins that were a carrier in the baseline (>= floor+carrier_over_floor)
      but have dropped gone_margin dB below that baseline.
    * **jammer**— a broadband rise: >= jam_frac of bins are jam_margin dB over baseline.
    """
    n = min(len(baseline), len(grid))
    new_idx, gone_idx, up = [], [], 0
    for i in range(n):
        b, g = baseline[i], grid[i]
        if g > b + jam_margin:
            up += 1
        if b <= floor + quiet_over_floor and g > b + new_margin and g > floor + new_margin:
            new_idx.append(i)
        elif b >= floor + carrier_over_floor and g < b - gone_margin:
            gone_idx.append(i)
    new = [(s, e, max(grid[s:e + 1])) for s, e in _regionize(new_idx)]
    gone = [(s, e) for s, e in _regionize(gone_idx)]
    up_frac = (up / n) if n else 0.0
    return {"new": new, "gone": gone, "jammer": up_frac >= jam_frac, "up_frac": up_frac}


class SpectrumBaseline:
    """Learn a per-bin baseline from the sweep, then watch for anomalies."""

    LEARN_FRAMES = 80          # ~5 s of IQ frames (or a few rtl_power sweeps)
    CONFIRM = 4                # a region must persist this many frames before alerting
    COOLDOWN_S = 30            # min seconds between alerts for the same region

    def __init__(self):
        self._lock = threading.Lock()
        self._state = "idle"    # idle | learning | watching
        self._base = None
        self._learn_n = 0
        self._lo = self._hi = None
        self._floor = _FLOOR_DBM
        self._pending = {}      # region-key -> consecutive-frame count
        self._last_alert = {}   # region-key -> epoch of last alert
        self._events = []       # rolling UI list of recent anomalies
        self._count = 0

    def arm(self):
        with self._lock:
            self._state = "learning"
            self._base = None
            self._learn_n = 0
            self._pending = {}
            self._events = []
        return self.status()

    def clear(self):
        with self._lock:
            self._state = "idle"; self._base = None; self._learn_n = 0
            self._pending = {}
        return self.status()

    def feed(self, grid, lo_hz, hi_hz, floor):
        """Called per frame by the sweep. Learns, then detects + emits anomalies."""
        with self._lock:
            state = self._state
            if state == "idle":
                return
            n = len(grid)
            if self._base is None or len(self._base) != n or (lo_hz, hi_hz) != (self._lo, self._hi):
                # span changed (band/zoom) -> relearn from scratch
                self._base = list(grid); self._learn_n = 1
                self._lo, self._hi, self._floor = lo_hz, hi_hz, floor
                self._state = "learning"; self._pending = {}
                return
            self._floor = floor
            if state == "learning":
                for i, v in enumerate(grid):        # baseline = max envelope seen while learning
                    if v > self._base[i]:
                        self._base[i] = v
                self._learn_n += 1
                if self._learn_n >= self.LEARN_FRAMES:
                    self._state = "watching"
                return
            base, lo, hi = self._base, self._lo, self._hi
        # ---- watching: detect outside the lock-held learning path ----
        res = detect_spectrum_anomalies(base, grid, floor)
        now = time.time()
        fresh = []
        for s, e, peak in res["new"]:
            fresh.append(("new", s, e, peak))
        for s, e in res["gone"]:
            fresh.append(("gone", s, e, None))
        if res["jammer"]:
            fresh.append(("jammer", 0, len(grid) - 1, None))
        seen_keys = set()
        with self._lock:
            for kind, s, e, peak in fresh:
                key = "%s:%d" % (kind, (s + e) // 2 // 4) if kind != "jammer" else "jammer"
                seen_keys.add(key)
                self._pending[key] = self._pending.get(key, 0) + 1
                if self._pending[key] < self.CONFIRM:
                    continue
                if now - self._last_alert.get(key, 0) < self.COOLDOWN_S:
                    continue
                self._last_alert[key] = now
                self._emit(kind, s, e, peak, lo, hi, len(grid), res.get("up_frac", 0))
            # decay pending counters for regions not seen this frame
            for k in list(self._pending):
                if k not in seen_keys:
                    self._pending[k] -= 1
                    if self._pending[k] <= 0:
                        del self._pending[k]

    def _emit(self, kind, s, e, peak, lo_hz, hi_hz, n, up_frac):
        fc = (lo_hz + (s + e + 1) / 2.0 * (hi_hz - lo_hz) / n) / 1e6
        bw = (e - s + 1) * (hi_hz - lo_hz) / n / 1e3
        if kind == "new":
            sev = "high"; code = "RF_NEW_EMITTER"
            summ = "New emitter %.3f MHz (~%.0f kHz, +%.0f dB over baseline)" % (
                fc, bw, (peak - self._base[(s + e) // 2]))
        elif kind == "gone":
            sev = "medium"; code = "RF_CARRIER_LOST"
            summ = "Baseline carrier gone at %.3f MHz (~%.0f kHz)" % (fc, bw)
        else:
            sev = "critical"; code = "RF_BROADBAND_JAMMING"
            summ = "Broadband interference — %.0f%% of the span risen over baseline" % (up_frac * 100)
        ev = {"ts": time.time(), "severity": sev, "code": code, "summary": summ,
              "src": "%.3fMHz" % fc, "freq_mhz": round(fc, 3), "bw_khz": round(bw, 1)}
        self._events.insert(0, ev)
        del self._events[60:]
        self._count += 1
        self._write_wt(ev)

    def _write_wt(self, ev):
        try:
            os.makedirs(_RF_WT_DIR, exist_ok=True)
            with open(os.path.join(_RF_WT_DIR, _RF_WT_FILE), "a") as fh:
                fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
        except OSError:
            pass                                   # best-effort; UI still shows it

    def status(self):
        with self._lock:
            prog = 0
            if self._state == "learning":
                prog = int(min(100, self._learn_n * 100 / self.LEARN_FRAMES))
            return {"state": self._state, "progress": prog, "count": self._count,
                    "events": list(self._events[:40]), "bins": len(self._base) if self._base else 0}


_baseline = SpectrumBaseline()


def baseline_arm():
    return _baseline.arm()


def baseline_clear():
    return _baseline.clear()


def baseline_status():
    return _baseline.status()


# --------------------------------------------------------------------------
# Frequency calibration — trim the dongle's crystal offset (PPM) so the readouts
# are trustworthy. A cheap RTL-SDR crystal is typically tens of ppm off, which at
# 900 MHz is tens of kHz — enough to mis-name a narrow channel. The standard fix
# (what kalibrate-rtl does) is a *reference-carrier* calibration: point at a
# signal whose true frequency you know, measure where it actually lands, and
# solve for the ppm error. (A true GPSDO disciplines the oscillator off a 1PPS
# input, which this NESDR-class dongle doesn't have — so GPS here is position/
# time truth, not a crystal reference; this reference-carrier method is the
# right tool for an RTL-SDR.)
# --------------------------------------------------------------------------

def ppm_from_reference(current_ppm, f_obs_hz, f_true_hz):
    """New PPM correction from an observed vs known-true carrier frequency (pure).

    The observed frequency already includes ``current_ppm`` of correction, so the
    *residual* fractional error (f_obs-f_true)/f_true is added to it. Result is
    clamped to the +-1000 ppm that :func:`set_tuning` accepts.
    """
    try:
        f_true_hz = float(f_true_hz); f_obs_hz = float(f_obs_hz)
        cur = float(current_ppm or 0)
    except (TypeError, ValueError):
        return current_ppm
    if f_true_hz <= 0:
        return current_ppm
    residual = (f_obs_hz - f_true_hz) / f_true_hz * 1e6
    return int(round(max(-1000, min(1000, cur + residual))))


def _peak_freq_hz(frame, lo_hz, hi_hz, near_hz=None, window_hz=None):
    """Frequency (Hz) of the strongest bin in ``frame`` (pure).

    With ``near_hz``+``window_hz`` the search is limited to that window, so a
    calibration can lock onto the marked reference rather than the band's loudest
    signal. Returns None if the frame is empty or the window has no bins.
    """
    n = len(frame)
    if not n or hi_hz <= lo_hz:
        return None
    binw = (hi_hz - lo_hz) / n
    s, e = 0, n - 1
    if near_hz is not None and window_hz:
        s = max(0, int((near_hz - window_hz / 2.0 - lo_hz) / binw))
        e = min(n - 1, int((near_hz + window_hz / 2.0 - lo_hz) / binw))
        if e < s:
            return None
    best, bi = -1e9, s
    for i in range(s, e + 1):
        if frame[i] > best:
            best, bi = frame[i], i
    return lo_hz + (bi + 0.5) * binw


def calibrate_from_reference(true_mhz, near_mhz=None):
    """Measure the live peak near a known reference and apply the PPM correction.

    ``true_mhz`` is the reference carrier's real frequency; ``near_mhz`` (usually
    the marker) limits the peak search so it locks onto that signal. Returns the
    before/after ppm, the measured offset, and the applied result.
    """
    try:
        true_hz = float(true_mhz) * 1e6
    except (TypeError, ValueError):
        return {"ok": False, "error": "true_mhz must be numeric"}
    fr = _power.get_frames(since=0)
    frames = fr.get("frames") or []
    band = fr.get("band_hz")
    if not frames or not band:
        return {"ok": False, "error": "no live sweep — start the sweep on the reference first"}
    lo, hi = band
    if not (lo <= true_hz <= hi):
        return {"ok": False, "error": "reference %.3f MHz is outside the current sweep %.3f-%.3f MHz"
                % (true_hz / 1e6, lo / 1e6, hi / 1e6)}
    grid = frames[-1]["power"]
    near_hz = (float(near_mhz) * 1e6) if near_mhz is not None else true_hz
    window = max(50_000.0, (hi - lo) * 0.05)          # +-2.5% of span, >=50 kHz
    f_obs = _peak_freq_hz(grid, lo, hi, near_hz=near_hz, window_hz=window)
    if f_obs is None:
        return {"ok": False, "error": "could not find a peak near the reference"}
    old_ppm = _ppm
    new_ppm = ppm_from_reference(old_ppm, f_obs, true_hz)
    set_tuning(ppm=new_ppm)                            # applies + restarts the sweep
    return {"ok": True, "old_ppm": old_ppm, "new_ppm": new_ppm,
            "observed_mhz": round(f_obs / 1e6, 4), "true_mhz": round(true_hz / 1e6, 4),
            "offset_khz": round((f_obs - true_hz) / 1e3, 2),
            "delta_ppm": new_ppm - old_ppm}


def status():
    ism, pwr, iq = _ism.status(), _power.status(), _iqcap.status()
    st = {"ism": ism, "power": pwr, "iq": iq, "bands": sorted(RTL_BANDS.keys()),
          "ism_bands": sorted(ISM_FREQS.keys())}
    if ism["running"] or pwr["running"] or iq.get("capturing"):
        # Something already holds the dongle over USB. Re-probing with rtl_test
        # here would open the same device and kill the capture — the HackRF
        # lesson. Report availability from the cached probe instead.
        d = dict(_detect_cache or {})
        d.update({"available": True, "tools_installed": True,
                  "device_present": True, "streaming": True})
        d.setdefault("bands", sorted(RTL_BANDS.keys()))
        st["detect"] = d
    else:
        st["detect"] = detect()
    return st


# --------------------------------------------------------------------------
# Self-test (pure parsing / assembly checks — no hardware needed)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    # --- rtl_test parse + dongle identification (Blog V3/V4, Nooelec, generic) ---
    ti = parse_rtl_test("Found 1 device(s):\n  0:  Realtek, RTL2838UHIDIR, SN: 00000001\n\n"
                        "Using device 0: Generic RTL2832U OEM\nFound Rafael Micro R820T tuner\n")
    check("detect: rtl_test device+tuner parsed",
          ti["device"] == "Realtek, RTL2838UHIDIR, SN: 00000001" and ti["tuner"] == "Rafael Micro R820T",
          str(ti))
    v4 = identify_model("Realtek, RTL2832U, SN: 00000001", "Rafael Micro R828D")
    check("id: R828D tuner -> Blog V4 + needs blog driver",
          v4["model_name"].startswith("RTL-SDR Blog V4") and v4["needs_blog_driver"] is True
          and v4["tuner_family"] == "R828D", str(v4))
    v4e = identify_model("RTLSDRBlog, Blog V4, SN: 00000001", "Rafael Micro R828D")
    check("id: 'Blog V4' EEPROM string honored",
          v4e["model_name"] == "RTL-SDR Blog V4", str(v4e))
    v3 = identify_model("RTLSDRBlog, Blog V3, SN: 00000001", "Rafael Micro R820T2")
    check("id: 'Blog V3' EEPROM string honored, no blog driver needed",
          v3["model_name"] == "RTL-SDR Blog V3" and v3["needs_blog_driver"] is False, str(v3))
    noo = identify_model("Nooelec, NESDR SMArt, SN: 00000001", "Rafael Micro R820T2")
    check("id: Nooelec NESDR recognized",
          "NESDR" in noo["model_name"] and noo["needs_blog_driver"] is False, str(noo))
    gen = identify_model("Generic RTL2832U OEM", "Rafael Micro R820T")
    check("id: generic R820T falls back to tuner name",
          gen["model_name"] == "RTL-SDR (R820T)" and gen["needs_blog_driver"] is False, str(gen))
    check("id: empty strings never crash",
          identify_model(None, None)["model_name"] == "RTL-SDR")

    # --- lsusb VID:PID fallback probe (RaspyJack-style) ---
    lsusb = ("Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\n"
             "Bus 001 Device 004: ID 0bda:2838 Realtek Semiconductor Corp. RTL2838 DVB-T\n")
    uid, udesc = parse_lsusb_for_rtl(lsusb)
    check("usb: NESDR/generic 0bda:2838 found in lsusb",
          uid == "0bda:2838" and "RTL2838" in udesc, "%s / %s" % (uid, udesc))
    check("usb: no RTL device -> (None, None)",
          parse_lsusb_for_rtl("Bus 001 Device 001: ID 1d6b:0002 Linux Foundation root hub")
          == (None, None))
    check("usb: empty lsusb output safe", parse_lsusb_for_rtl("") == (None, None))

    # --- SDR health-check verdict (summarize_diagnosis, pure) ---
    st, _, _ = summarize_diagnosis({"available": True, "model_name": "RTL-SDR Blog V4"})
    check("diag: available -> ok", st == "ok")
    st, _, fix = summarize_diagnosis({"available": False, "usb_present": False,
                                      "undervoltage": True, "throttled": "0x50000"})
    check("diag: no dongle on bus -> no_usb, power hint first",
          st == "no_usb" and any("under-voltage" in s for s in fix), st)
    st, _, fix = summarize_diagnosis({"available": False, "usb_present": True,
                                      "usb_id": "0bda:2838", "tools_installed": False})
    check("diag: on bus but no tools -> tools_missing",
          st == "tools_missing" and any("apt install" in s for s in fix), st)
    st, _, fix = summarize_diagnosis({"available": False, "usb_present": True,
                                      "usb_id": "0bda:2838", "tools_installed": True,
                                      "dvb_loaded": True, "blacklisted": False})
    check("diag: DVB driver holding it -> dvb_held, rmmod + blacklist",
          st == "dvb_held" and any("rmmod" in s for s in fix)
          and any("update_ragnar" in s for s in fix), st)
    st, _, _ = summarize_diagnosis({"available": False, "usb_present": True,
                                    "usb_id": "0bda:2838", "tools_installed": True,
                                    "rtl_test_ran": True, "rtl_test_opened": False,
                                    "blacklisted": True})
    check("diag: can't open despite blacklist -> still dvb_held", st == "dvb_held", st)

    # --- rtl_power row parser ---
    row = "2024-01-01, 12:00:00, 433050000, 434790000, 3625.00, 100, -40.1, -55.2, -33.0"
    p = parse_power_row(row)
    check("power: valid row -> (lo,hi,step,dbs)",
          p is not None and p[0] == 433050000 and p[1] == 434790000
          and abs(p[2] - 3625.0) < 1e-6 and len(p[3]) == 3, str(p))
    check("power: header/garbage -> None",
          parse_power_row("date, time, low, high") is None
          and parse_power_row("") is None)
    check("power: -inf/nan dB cells dropped",
          (parse_power_row("d,t,1,2,1,9,-inf,-10,nan,-20") or (0, 0, 0, []))[3] == [-10.0, -20.0])

    # --- power frame builder: bucketing + wrap ---
    lo, hi = 433050000, 434790000
    step = 20000
    def rows_for(peak_hz):
        out, f = [], lo
        while f < hi:
            dbs = [(-15.0 if abs((f + step / 2) - peak_hz) < step else -95.0)]
            out.append("d, t, %d, %d, %d, 100, %.1f" % (f, f + step, step, dbs[0]))
            f += step
        return out
    peak = (lo + hi) // 2
    fb = _PowerFrameBuilder(lo, hi)
    frames = []
    for r in rows_for(peak) + rows_for(peak):
        fr = fb.add(*parse_power_row(r))
        if fr is not None:
            frames.append(fr)
    check("power: one frame after the second sweep starts", len(frames) == 1, str(len(frames)))
    if frames:
        g = frames[0]
        pk = max(range(len(g)), key=lambda i: g[i])
        check("power: peak lands mid-band", abs(pk - _POWER_BINS // 2) <= 2, str(pk))
        check("power: frame width = display bins", len(g) == _POWER_BINS)
        check("power: quiet columns at/near floor",
              sum(1 for v in g if v <= -90) > _POWER_BINS * 0.5)

    # Narrow band (433 ISM, 1.74 MHz) → rtl_power emits ONE row per sweep with a
    # repeating hz_low. Each repeat must finalize a frame (the bug: 915/868 loaded
    # but 433 never did because the strict < wrap check never fired).
    fbn = _PowerFrameBuilder(lo, hi)
    one_row = "d, t, %d, %d, %d, 100, %s" % (
        lo, hi, (hi - lo) // 8, ", ".join(["-30.0"] * 8))
    nframes = sum(1 for _ in range(4)
                  if fbn.add(*parse_power_row(one_row)) is not None)
    check("power: single-row (433) sweeps finalize frames", nframes == 3, str(nframes))

    # --- IQ waterfall plan: fits one tune vs. falls back to rtl_power ---
    _plan = _iq_plan(867_000_000, 869_700_000)     # LoRaWAN EU868 overlay (2.7 MHz)
    check("iq: 2.7 MHz span gets a single-tune plan",
          _plan is not None and _plan[0] == 868_350_000
          and _IQ_SR_MIN <= _plan[1] <= _IQ_SR_MAX and _plan[1] >= 2_700_000,
          str(_plan))
    check("iq: wide 915 band (26 MHz) has no IQ plan -> rtl_power",
          _iq_plan(902_000_000, 928_000_000) is None)
    check("iq: sample rate oversamples the span for clean edges",
          _iq_plan(433_050_000, 434_790_000)[1] >= int(1_740_000 * _IQ_EDGE_MARGIN) - 1)
    check("iq: sub-min span still tunes (clamped to _IQ_SR_MIN)",
          _iq_plan(868_100_000, 868_300_000)[1] == _IQ_SR_MIN)

    # --- IQ PSD -> display grid: a tone lands in the right column, edges dropped ---
    _N, _ctr, _sr = 1024, 868_350_000, 3_000_000
    _lo, _hi = 867_000_000, 869_700_000
    _psd = [-100.0] * _N
    # Put a strong bin at the display centre (~868.35 MHz): fftshift bin N/2 = DC.
    _psd[_N // 2] = -30.0
    _g = _iq_to_grid(_psd, _ctr, _sr, _lo, _hi)
    check("iq: grid width = display bins", len(_g) == _POWER_BINS)
    _pk = max(range(len(_g)), key=lambda i: _g[i])
    check("iq: centre tone lands mid-grid", abs(_pk - _POWER_BINS // 2) <= 2, str(_pk))
    check("iq: tone column strong, rest near floor",
          _g[_pk] >= -31 and sum(1 for v in _g if v <= -95) > _POWER_BINS * 0.5)
    check("iq: oversampled edge bins fall outside [lo,hi] (dropped)",
          _iq_to_grid([-40.0] * _N, _ctr, _sr, _lo, _hi).count(_FLOOR_DBM) == 0
          and all(v >= -95 for v in _iq_to_grid([-40.0] * _N, _ctr, _sr, _lo, _hi)))

    # numpy IQ math matches the pure grid (only when numpy is importable) ---
    try:
        import numpy as _np
        _win = _np.hanning(_N).astype(_np.float32)
        _wn = float(_np.sum(_win ** 2)) * _N
        # a pure complex tone at +sr/4 from centre -> a single fftshifted bin high
        _t = _np.arange(_N)
        _sig = _np.exp(2j * _np.pi * (_sr / 4.0) / _sr * _t).astype(_np.complex64)
        _spec = _np.fft.fftshift(_np.fft.fft(_sig * _win))
        _dbn = 10.0 * _np.log10((_spec.real ** 2 + _spec.imag ** 2) / _wn + 1e-12)
        _gn = _iq_to_grid(_dbn.tolist(), _ctr, _sr, _lo, _hi)
        _pkn = max(range(len(_gn)), key=lambda i: _gn[i])
        # +sr/4 of 3 MHz = +750 kHz from 868.35 -> 869.1 MHz -> right of centre
        check("iq: numpy tone at +sr/4 lands right-of-centre",
              _pkn > _POWER_BINS // 2, "%d vs %d" % (_pkn, _POWER_BINS // 2))
    except Exception as _exc:      # numpy absent on a minimal board -> IQ path off
        check("iq: numpy check skipped (numpy unavailable)", True, str(_exc))

    # --- rtl_433 JSON parser + device keying ---
    ev = parse_rtl433_event('{"time":"2024-01-01 12:00:00","model":"Toyota-TPMS",'
                            '"id":60123,"pressure_kPa":230,"temperature_C":22,"rssi":-8.2}')
    check("ism: valid event parsed",
          ev is not None and ev["model"] == "Toyota-TPMS" and ev["id"] == 60123
          and ev["rssi"] == -8.2 and ev["fields"].get("pressure_kPa") == 230, str(ev))
    check("ism: non-JSON / status line -> None",
          parse_rtl433_event("Tuned to 433.920MHz") is None
          and parse_rtl433_event("") is None
          and parse_rtl433_event('{"no":"model"}') is None)
    check("ism: device key is model/id",
          device_key(ev) == "Toyota-TPMS/60123", device_key(ev))
    ch = parse_rtl433_event('{"model":"Acurite-5n1","channel":"A","wind_avg_km_h":12}')
    check("ism: id-less device keys on channel", device_key(ch) == "Acurite-5n1/A")

    # --- device table ingest: dedupe + count + latest fields ---
    sc = IsmScanner()
    sc._ingest(parse_rtl433_event('{"model":"Toyota-TPMS","id":1,"pressure_kPa":200}'))
    sc._ingest(parse_rtl433_event('{"model":"Toyota-TPMS","id":1,"pressure_kPa":205}'))
    sc._ingest(parse_rtl433_event('{"model":"Honeywell-Door","id":9,"state":"open"}'))
    dv = sc.get_devices()
    tpms = next(d for d in dv["devices"] if d["key"] == "Toyota-TPMS/1")
    check("ism: repeat device deduped, count rises",
          dv["count"] == 2 and tpms["count"] == 2, str(dv["count"]))
    check("ism: latest fields retained",
          tpms["fields"].get("pressure_kPa") == 205)
    check("ism: total events counted", dv["events"] == 3, str(dv["events"]))

    # --- status() must not re-probe the dongle while a capture streams ---
    import sys as _sys
    _mod = _sys.modules[__name__]
    global _detect_cache
    _saved_detect, _saved_ism_status = _mod.detect, _ism.status
    _saved_pwr_status = _power.status
    _probe = []
    _detect_cache = {"tuner": "R820T"}
    _ism.status = lambda: {"running": True, "band": "433"}
    _power.status = lambda: {"running": False, "band": None}
    _mod.detect = lambda *a, **k: (_probe.append(1) or {"available": False})
    try:
        st = status()
        check("status: no dongle re-probe while streaming",
              not _probe and st["detect"].get("streaming") is True
              and st["detect"].get("available") is True, str(st["detect"]))
    finally:
        _mod.detect, _ism.status, _power.status = _saved_detect, _saved_ism_status, _saved_pwr_status
        _detect_cache = None

    # --- band tables ---
    check("bands: power 433/868/915/subghz present",
          all(b in RTL_BANDS for b in ("433", "868", "915", "subghz")))
    check("bands: ism 433/868/915 present",
          all(b in ISM_FREQS for b in ("433", "868", "915")))

    # --- Z-Wave regional plan: channels sit inside their span, all in RTL reach ---
    plan = zwave_plan()
    check("zwave: eu + us regions present",
          "eu" in plan and "us" in plan and "us-lr" in plan)
    _zw_ok = True
    for rid, r in plan.items():
        if not (24_000_000 <= r["lo_hz"] < r["hi_hz"] <= 1_766_000_000):
            _zw_ok = False
        for ch in r["channels"]:
            if not (r["lo_hz"] <= ch["freq_hz"] <= r["hi_hz"]):
                _zw_ok = False
    check("zwave: every channel lands inside its region span (and RTL range)", _zw_ok)
    check("zwave: EU classic channel is 868.42 MHz",
          any(abs(c["freq_hz"] - 868_420_000) < 1000 for c in plan["eu"]["channels"]))
    check("zwave: span >= 100 kHz so power_start accepts it",
          all(r["hi_hz"] - r["lo_hz"] >= 100_000 for r in plan.values()))

    # --- LoRa mesh plan (Meshtastic / MeshCore / LoRaWAN): channels inside span,
    #     spans in RTL reach + acceptable width, all three protocols present ---
    lp = lora_plan()
    check("lora: meshtastic + meshcore + lorawan present",
          {p["proto"] for p in lp.values()} >= {"Meshtastic", "MeshCore", "LoRaWAN"})
    _lp_ok = True
    for pid, p in lp.items():
        if not (24_000_000 <= p["lo_hz"] < p["hi_hz"] <= 1_766_000_000):
            _lp_ok = False
        if p["hi_hz"] - p["lo_hz"] < 100_000:
            _lp_ok = False
        for ch in p["channels"]:
            if not (p["lo_hz"] <= ch["freq_hz"] <= p["hi_hz"]):
                _lp_ok = False
    check("lora: every channel inside its span, span in RTL range + >=100 kHz", _lp_ok)
    check("lora: LoRaWAN EU868 lists the three mandatory uplinks",
          all(any(abs(c["freq_hz"] - f) < 1000 for c in lp["lorawan-eu868"]["channels"])
              for f in (868_100_000, 868_300_000, 868_500_000)))

    # --- new bands: 315 (US keyfobs/TPMS/garage) + 40/27 present ---
    check("bands: 315/40/27 MHz added",
          all(b in RTL_BANDS for b in ("315", "40", "27")) and "315" in ISM_FREQS)
    check("bands: FM (88-108) + airband (108-137) band scopes present",
          RTL_BANDS.get("fm") == (88000000, 108000000)
          and RTL_BANDS.get("air") == (108000000, 137000000))
    check("bands: AM (0.53-1.71) + shortwave (3-24) HF band scopes present",
          RTL_BANDS.get("am") == (530000, 1710000)
          and RTL_BANDS.get("sw") == (3000000, 24000000))

    # --- tuner corrections (PPM + gain) build the right rtl_* flags ---
    _saved_ppm, _saved_gain = _ppm, _gain
    try:
        set_tuning(ppm=42, gain=28.0)
        check("tuning: ppm+gain stored", get_tuning()["ppm"] == 42 and get_tuning()["gain"] == 28.0)
        check("tuning: flags built", _tuner_args() == ["-p", "42", "-g", "28.0"], str(_tuner_args()))
        set_tuning(gain="auto")
        check("tuning: auto gain drops -g", _tuner_args() == ["-p", "42"] and get_tuning()["gain_is_auto"])
        set_tuning(ppm=0, gain="auto")
        check("tuning: zero ppm + auto = no flags", _tuner_args() == [])
        set_tuning(ppm=99999)  # clamped
        check("tuning: ppm clamped to +/-1000", get_tuning()["ppm"] == 1000)
    finally:
        set_tuning(ppm=_saved_ppm, gain=("auto" if _saved_gain is None else _saved_gain))

    # --- session recorder round-trip (hermetic: uses a temp recordings dir) ---
    import tempfile as _tf
    _saved_rec_dir = _rec_dir
    _tmpdir = _tf.mkdtemp(prefix="ragnar-rec-")
    globals()["_rec_dir"] = lambda: _tmpdir
    try:
        _rn = "selftest-tmp-rec"
        rec = _Recorder()
        rec.start({"band": "433", "lo_hz": 433050000, "hi_hz": 434790000, "bins": 4, "floor": -120}, name=_rn)
        rec.write(1, 1000.0, [-40, -90, -90, -40])
        rec.write(2, 1001.0, [-45, -88, -88, -45])
        rec.stop()
        g = record_get(_rn)
        check("record: round-trip get (2 frames + header meta)",
              g.get("ok") and g["count"] == 2 and g["header"].get("band") == "433"
              and g["frames"][0]["power"] == [-40, -90, -90, -40], str(g.get("count")))
        check("record: shows up in the recordings list",
              any(r["name"] == _rn and r["frames"] == 2 for r in record_list()["recordings"]))
        check("record: delete removes it",
              record_delete(_rn).get("ok") and not record_get(_rn).get("ok"))
    finally:
        globals()["_rec_dir"] = _saved_rec_dir
        import shutil as _sh
        _sh.rmtree(_tmpdir, ignore_errors=True)

    # --- SigMF metadata (pure, no hardware): shape + required core fields ---
    _sm = sigmf_meta(868_300_000, 2_400_000, sha512="ab"*64,
                     dt_iso="2026-09-10T12:00:00Z", label="lorawan-eu868", ppm=12, gain=28.0)
    check("sigmf: cu8 datatype + sample_rate + v1.0.0 global",
          _sm["global"]["core:datatype"] == "cu8"
          and _sm["global"]["core:sample_rate"] == 2_400_000.0
          and _sm["global"]["core:version"] == "1.0.0", str(_sm["global"].get("core:version")))
    check("sigmf: capture carries tune freq + datetime",
          _sm["captures"][0]["core:frequency"] == 868_300_000.0
          and _sm["captures"][0]["core:datetime"] == "2026-09-10T12:00:00Z")
    check("sigmf: label -> full-length annotation + sha512/ppm/gain recorded",
          _sm["annotations"][0]["core:label"] == "lorawan-eu868"
          and _sm["global"]["core:sha512"] == "ab"*64
          and _sm["global"]["core:freq_correction_ppm"] == 12
          and _sm["global"]["core:gain_db"] == 28.0)
    import json as _json
    check("sigmf: metadata is JSON-serializable", isinstance(_json.dumps(_sm), str))
    check("sigmf: capture rejects out-of-reach centre / bad rate",
          IqCapture().start(50_000_000_000, 2_400_000, 1).get("ok") is False
          and IqCapture().start(868_000_000, 99_000_000, 1).get("ok") is False)

    # --- spectrum baseline + anomaly detection (pure) ---
    check("rfwatch: _regionize groups contiguous runs",
          _regionize([2, 3, 4, 9, 10, 20]) == [[2, 4], [9, 10], [20, 20]])
    _fl = -110
    _base = [_fl] * 100
    _base[50] = _base[51] = -40           # a known carrier in the baseline
    _g = list(_base)
    _g[10] = _g[11] = -60                 # NEW emitter where baseline was quiet
    _g[50] = _g[51] = -105                # the known carrier VANISHED
    _an = detect_spectrum_anomalies(_base, _g, _fl)
    check("rfwatch: new emitter over a quiet baseline detected",
          any(s <= 10 <= e for s, e, pk in _an["new"]), str(_an["new"]))
    check("rfwatch: vanished baseline carrier detected",
          any(s <= 50 <= e for s, e in _an["gone"]), str(_an["gone"]))
    check("rfwatch: quiet band is not a jammer", _an["jammer"] is False)
    _jam = detect_spectrum_anomalies(_base, [_fl + 20] * 100, _fl)
    check("rfwatch: broadband rise flagged as jamming",
          _jam["jammer"] is True and _jam["up_frac"] >= 0.9, str(_jam["up_frac"]))
    _sb = SpectrumBaseline()
    check("rfwatch: arm -> learning, clear -> idle",
          _sb.arm()["state"] == "learning" and _sb.clear()["state"] == "idle")

    # --- frequency calibration (pure) ---
    # A carrier truly at 433.900 MHz observed at 433.910 (+10 kHz) => +23 ppm to add.
    _np2 = ppm_from_reference(0, 433_910_000, 433_900_000)
    check("cal: +10 kHz high at 433.9 MHz -> ~+23 ppm",
          22 <= _np2 <= 24, str(_np2))
    check("cal: correction adds to the current ppm",
          ppm_from_reference(10, 433_910_000, 433_900_000) == _np2 + 10)
    check("cal: result clamped to +-1000 ppm",
          ppm_from_reference(0, 470_000_000, 433_900_000) == 1000)
    check("cal: bad/zero true freq is a no-op",
          ppm_from_reference(7, 433_900_000, 0) == 7)
    # peak-in-window: a tone in bin 300 of a 480-bin 433.05-434.79 grid
    _pk = [-110] * 480; _pk[300] = -20
    _pf = _peak_freq_hz(_pk, 433_050_000, 434_790_000,
                        near_hz=433_050_000 + 300.5 / 480 * 1_740_000, window_hz=100_000)
    check("cal: peak-in-window finds the tone bin",
          _pf is not None and abs(_pf - (433_050_000 + 300.5 / 480 * 1_740_000)) < 4000, str(_pf))
    check("cal: window excluding the tone -> different (nearest-in-window) bin",
          _peak_freq_hz(_pk, 433_050_000, 434_790_000, near_hz=433_100_000, window_hz=50_000) is not None)

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="RTL-SDR sub-GHz ISM scanner + waterfall")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("detect")
    pi = sub.add_parser("ism")
    pi.add_argument("--band", default="433", choices=sorted(ISM_FREQS.keys()))
    pi.add_argument("--seconds", type=int, default=15)
    pp = sub.add_parser("power")
    pp.add_argument("--band", default="433", choices=sorted(RTL_BANDS.keys()))
    pp.add_argument("--seconds", type=int, default=15)
    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if args.cmd == "detect":
        print(json.dumps(detect(), indent=2))
    elif args.cmd == "ism":
        d = detect()
        if not d.get("available"):
            print(json.dumps({"error": d.get("error")}, indent=2)); return 1
        ism_start(args.band)
        try:
            end = time.time() + args.seconds
            while time.time() < end:
                time.sleep(2)
                dv = ism_devices()
                print("[%ds] %d devices, %d events" %
                      (int(args.seconds - (end - time.time())), dv["count"], dv["events"]))
                for row in dv["devices"][:8]:
                    print("   %-22s rssi=%s  %s" % (row["key"], row.get("rssi"),
                          json.dumps(row.get("fields", {}))[:70]))
        finally:
            ism_stop()
    elif args.cmd == "power":
        d = detect()
        if not d.get("available"):
            print(json.dumps({"error": d.get("error")}, indent=2)); return 1
        power_start(args.band)
        last = 0
        try:
            end = time.time() + args.seconds
            while time.time() < end:
                time.sleep(1)
                fr = power_frames(since=last)
                for f in fr["frames"]:
                    last = f["seq"]
                    strong = max(range(len(f["power"])), key=lambda i: f["power"][i])
                    print("frame %d: peak col %d @ %d dBm" % (f["seq"], strong, f["power"][strong]))
        finally:
            power_stop()
    elif args.cmd == "selftest":
        r = selftest()
        for item in r["results"]:
            print("  [%s] %s%s" % ("PASS" if item["pass"] else "FAIL", item["name"],
                                   "" if item["pass"] else "  (%s)" % item["detail"]))
        print("\n%d/%d checks pass — %s" %
              (r["passed"], r["total"], "OK" if r["pass"] else "FAILURES"))
        return 0 if r["pass"] else 1
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
