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
  2. **Sub-GHz waterfall** — shells out to ``rtl_power`` sweeps and assembles a
     scrolling power-per-frequency heatmap, the same shape the HackRF Waterfall
     uses, but for the bands the HackRF view doesn't target.

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

# Power-sweep ranges (Hz). Kept inside the RTL-SDR's reach (~24 MHz–1.7 GHz).
RTL_BANDS = {
    "27":     (26900000, 27500000),     # CB / 27 MHz RC (near the tuner's low edge)
    "40":     (40000000, 41000000),     # 40 MHz RC / toys
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
_TUNER_FAMILIES = ("R828D", "R820T2", "R820T", "E4000", "FC0013", "FC0012",
                   "FC2580", "R828")


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
             "rtl_test": _have(_RTL_TEST)}
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
            self._stop.clear()
            self._frames = []
            self._seq = 0
            self._maxhold = [_FLOOR_DBM] * _POWER_BINS
            self._band = label
            self._sig = sig
            self._lo, self._hi = lo, hi
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
            self._stop.clear()
            self._frames = []
            self._seq = 0
            self._maxhold = [_FLOOR_DBM] * _POWER_BINS
            self._band = label
            self._sig = sig
            self._lo, self._hi = lo, hi
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
        step = max(1000, (hi - lo) // _POWER_BINS)   # Hz per rtl_power bin
        builder = _PowerFrameBuilder(lo, hi)
        cmd = [_RTL_POWER, "-f", "%d:%d:%d" % (lo, hi, step),
               "-i", str(_SWEEP_INTERVAL_S), "-c", "20%"] + _tuner_args()
        self._stderr_tail = None
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True,
                                          bufsize=1)
        except Exception as exc:
            self._error = "failed to launch rtl_power: %s" % exc
            return
        serr = _drain(self._proc.stderr, self)
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                parsed = parse_power_row(line)
                if not parsed:
                    continue
                frame = builder.add(*parsed)
                if frame is not None:
                    self._push_frame(frame)
        except Exception as exc:  # pragma: no cover - defensive
            self._error = str(exc)
        finally:
            serr.join(timeout=1)
            if (self._proc and self._proc.poll() not in (None, 0)
                    and not self._error and self._stderr_tail):
                self._error = self._stderr_tail

    def _push_frame(self, grid):
        ints = [int(round(v)) for v in grid]
        with self._lock:
            self._seq += 1
            self._frames.append({"seq": self._seq, "ts": time.time(),
                                 "power": ints})
            if len(self._frames) > _RING_FRAMES:
                self._frames = self._frames[-_RING_FRAMES:]
            if self._maxhold is None:
                self._maxhold = list(ints)
            else:
                self._maxhold = [max(a, b) for a, b in zip(self._maxhold, ints)]

    def status(self):
        with self._lock:
            return {"running": bool(self._thread and self._thread.is_alive()),
                    "band": self._band, "bins": _POWER_BINS,
                    "band_hz": [self._lo, self._hi] if self._lo else None,
                    "frames_buffered": len(self._frames), "seq": self._seq,
                    "floor_dbm": _FLOOR_DBM, "error": self._error}

    def get_frames(self, since=0):
        try:
            since = int(since)
        except (TypeError, ValueError):
            since = 0
        with self._lock:
            new = [f for f in self._frames if f["seq"] > since]
            return {"frames": new, "seq": self._seq, "band": self._band,
                    "band_hz": [self._lo, self._hi] if self._lo else None,
                    "bins": _POWER_BINS, "floor_dbm": _FLOOR_DBM,
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


def status():
    ism, pwr = _ism.status(), _power.status()
    st = {"ism": ism, "power": pwr, "bands": sorted(RTL_BANDS.keys()),
          "ism_bands": sorted(ISM_FREQS.keys())}
    if ism["running"] or pwr["running"]:
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
