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
import math
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
    # --- Zigbee Suzi: the sub-GHz feature of Zigbee 4.0 / Zigbee PRO 2023 (CSA,
    #     certification from 2026), on IEEE 802.15.4 sub-GHz radios in the 868 MHz
    #     (Europe) and 915 MHz (North America) bands. The CSA's channel plan is
    #     not public, so the markers are IEEE 802.15.4's own published sub-GHz
    #     channels — a reference grid, not a claim about Suzi's. Energy view only. ---
    "suzi-eu868": {"proto": "Zigbee Suzi", "label": "Zigbee Suzi · EU 868 (863-870)",
                         "span": (863_000_000, 870_000_000),
                         "channels": [(868_300_000, "802.15.4 ch0")],
                         "note": "Zigbee sub-GHz (Suzi), Europe 868 MHz band. Suzi's own channel plan is in the CSA spec (not public); the marker is IEEE 802.15.4's 868.3 MHz channel 0 for reference — read the real channel from where the energy lands"},
    "suzi-na915": {"proto": "Zigbee Suzi", "label": "Zigbee Suzi · NA 915 (902-928)",
                         "span": (902_000_000, 928_000_000),
                         "channels": [
                                      (906000000, "ch1"),
                                      (908000000, "ch2"),
                                      (910000000, "ch3"),
                                      (912000000, "ch4"),
                                      (914000000, "ch5"),
                                      (916000000, "ch6"),
                                      (918000000, "ch7"),
                                      (920000000, "ch8"),
                                      (922000000, "ch9"),
                                      (924000000, "ch10")],
                         "note": "Zigbee sub-GHz (Suzi), North America 915 MHz band. Suzi's own channel plan is in the CSA spec (not public); markers are IEEE 802.15.4's 915 MHz channels 1-10 (906-924 MHz, 2 MHz apart) for reference"},
    # --- Wi-Fi HaLow (IEEE 802.11ah): sub-GHz Wi-Fi, 1-16 MHz OFDM channels.
    #     A higher-bandwidth alternative to LoRaWAN. Energy view only here —
    #     the OFDM is not demodulated and the traffic is WPA3-encrypted anyway. ---
    "halow-us": {"proto": "Wi-Fi HaLow", "label": "Wi-Fi HaLow · US (902-928)",
                         "span": (902000000, 928000000),
                         "channels": [
                                      (903000000, "ch2"),
                                      (905000000, "ch6"),
                                      (907000000, "ch10"),
                                      (909000000, "ch14"),
                                      (911000000, "ch18"),
                                      (913000000, "ch22"),
                                      (915000000, "ch26"),
                                      (917000000, "ch30"),
                                      (919000000, "ch34"),
                                      (921000000, "ch38"),
                                      (923000000, "ch42"),
                                      (925000000, "ch46"),
                                      (927000000, "ch50")],
                         "note": "802.11ah US (FCC): 902-928 MHz, 1/2/4/8/16 MHz OFDM channels; markers = the 13 x 2 MHz channels (802.11ah numbering, centre = 902 + 0.5*n MHz)"},
    "halow-eu": {"proto": "Wi-Fi HaLow", "label": "Wi-Fi HaLow · EU (863-868)",
                         "span": (863000000, 868000000),
                         "channels": [
                                      (863500000, "ch1"),
                                      (864000000, "ch2 2M"),
                                      (864500000, "ch3"),
                                      (865500000, "ch5"),
                                      (866000000, "ch6 2M"),
                                      (866500000, "ch7"),
                                      (867500000, "ch9")],
                         "note": "802.11ah Europe (ETSI SRD): 863-868 MHz, 1 and 2 MHz OFDM channels; centre = 863 + 0.5*n MHz"},
    "halow-anz": {"proto": "Wi-Fi HaLow", "label": "Wi-Fi HaLow · AU/NZ (915-928)",
                         "span": (915000000, 928000000),
                         "channels": [
                                      (917000000, "ch30"),
                                      (919000000, "ch34"),
                                      (921000000, "ch38"),
                                      (923000000, "ch42"),
                                      (925000000, "ch46"),
                                      (927000000, "ch50")],
                         "note": "802.11ah Australia / New Zealand: 915-928 MHz, US channel numbering; markers = the 2 MHz channels in band"},
    "halow-jp": {"proto": "Wi-Fi HaLow", "label": "Wi-Fi HaLow · Japan (916.5-927.5)",
                         "span": (916500000, 927500000),
                         "channels": [
                                      (917000000, "917"),
                                      (918000000, "918"),
                                      (919000000, "919"),
                                      (920000000, "920"),
                                      (921000000, "921"),
                                      (922000000, "922"),
                                      (923000000, "923"),
                                      (924000000, "924"),
                                      (925000000, "925"),
                                      (926000000, "926"),
                                      (927000000, "927")],
                         "note": "802.11ah Japan (ARIB T108): 916.5-927.5 MHz, 1 MHz channels; markers = 1 MHz raster"},
    "halow-kr": {"proto": "Wi-Fi HaLow", "label": "Wi-Fi HaLow · Korea (917.5-923.5)",
                         "span": (917500000, 923500000),
                         "channels": [
                                      (918000000, "918"),
                                      (919000000, "919"),
                                      (920000000, "920"),
                                      (921000000, "921"),
                                      (922000000, "922"),
                                      (923000000, "923")],
                         "note": "802.11ah Korea: 917.5-923.5 MHz, 1/2/4 MHz channels; markers = 1 MHz raster"},
    "halow-cn": {"proto": "Wi-Fi HaLow", "label": "Wi-Fi HaLow · China (779-787)",
                         "span": (779000000, 787000000),
                         "channels": [
                                      (780000000, "780"),
                                      (782000000, "782"),
                                      (784000000, "784"),
                                      (786000000, "786")],
                         "note": "802.11ah China: 779-787 MHz (1/2/4/8 MHz channels; 755-779 MHz is low-power only); markers = 2 MHz raster"},
    "halow-in": {"proto": "Wi-Fi HaLow", "label": "Wi-Fi HaLow · India (865-868)",
                         "span": (865000000, 868000000),
                         "channels": [
                                      (865500000, "865.5"),
                                      (866500000, "866.5"),
                                      (867500000, "867.5")],
                         "note": "802.11ah India: 865-868 MHz, 1 MHz channels"},
    "halow-sg": {"proto": "Wi-Fi HaLow", "label": "Wi-Fi HaLow · Singapore (920-925)",
                         "span": (920000000, 925000000),
                         "channels": [
                                      (920500000, "920.5"),
                                      (921500000, "921.5"),
                                      (922500000, "922.5"),
                                      (923500000, "923.5"),
                                      (924500000, "924.5")],
                         "note": "802.11ah Singapore: 920-925 MHz (also 866-869 MHz), 1/2/4 MHz channels; markers = 1 MHz raster"},
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
_DC_HALF_HZ = 35_000          # half-width of the RTL-SDR centre hump that gets filled in
_DC_CLEAR_HZ = 60_000         # tune this far past the band edge to keep the hump out of it
_DC_SR_CAP = 2_400_000        # highest rate we raise to for that (drop-free on a Pi)
_DC_SHIFT_MAX = 300_000       # how far off the band centre the tuner moves on wide spans

# Tuner corrections shared by both captures (one dongle). PPM trims the RTL-SDR's
# crystal offset (matters on the narrow Z-Wave/LoRa channels); gain is tuner gain
# in dB, or None for the driver's automatic gain. Applied to every rtl_power /
# rtl_433 command; changing them reapplies to a running capture.
_ppm = 0
# Shipped gain default. The dongle's own AGC is NOT the default: on an R820T it
# routinely drives the 8-bit ADC into clipping near any strong signal, and a
# clipped capture invents harmonics and intermodulation that look like real
# transmitters. Instead we start at a sensible gain and manage it from the
# measured headroom (see agc_step) — which adapts to the antenna and the site
# rather than hoping one number suits everyone.
_gain = 25.4               # dB, an R820T notch just past the sensitivity knee
_agc = True                # manage the gain from the measured headroom

# Resolution + hardware extras, shared by every capture on the one dongle.
_FFT_SIZES = (256, 512, 1024, 2048, 4096, 8192, 16384, 32768)
_WINDOWS = ("hann", "blackman-harris", "flattop", "rect")
_BIN_CHOICES = (240, 480, 960, 1920)
# Detectors. An FFT produces far more bins than the display has columns, so each
# column has to combine several bins, and WHICH rule is used changes every level
# the page prints. Professional analysers make this an explicit choice because
# there is no universally right answer: peak finds signals, rms measures them.
_DETECTORS = ("peak", "rms", "avg", "sample", "min")
_DIRECT_MAX_HZ = 28_800_000   # direct sampling covers ~0.5-28.8 MHz (HF)
_fft = 0                   # FFT size; 0 = auto (enough bins for the display at any zoom)
_avg = _IQ_AVG_MAX         # FFT windows averaged per row (more = smoother, slower to react)
_window = "hann"           # FFT window (flattop = amplitude-accurate, rect = sharpest/leakiest)
_bins = _POWER_BINS        # display columns per frame
# Measured on a real dongle: with auto FFT sizing (>=2 bins per display column)
# an RMS detector costs about 0.5 dB of visible SNR against peak, and in return
# every level, channel power and noise figure is a true power measurement
# instead of one biased high. So RMS ships as the default and peak is one click
# away for hunting very narrow signals at wide spans.
_detector = "rms"          # how the bins inside one display column are combined
_bias_t = False            # 4.5 V on the antenna port (RTL-SDR Blog V3/V4) to power an LNA
_direct = "auto"           # direct sampling: "auto" (on below 28.8 MHz), "on", "off"
_conv_hz = 0               # up/down-converter LO: hardware freq = RF freq + _conv_hz
# Every RTL-SDR shows a hump of its own at the frequency it is tuned to (DC
# offset + LO leakage + 1/f noise): measured on this dongle at 2 MS/s it is
# ~14 dB above the floor and about +-20 kHz wide — a steady "beam" in the
# middle of the band that is not a signal. With this on, the tuner is placed
# so the hump lands outside the band, or where it can't, away from the band
# centre with its few bins filled in from the noise either side.
_hide_dc = True


# The R820T's discrete tuner gains (dB). Asking for anything else gets the
# nearest of these, so the managed loop steps through them directly.
_R820T_GAINS = (0.0, 0.9, 1.4, 2.7, 3.7, 7.7, 8.7, 12.5, 14.4, 15.7, 16.6,
                19.7, 20.7, 22.9, 25.4, 28.0, 29.7, 32.8, 33.8, 36.4, 37.2,
                38.6, 40.2, 42.1, 43.4, 43.9, 44.5, 48.0, 49.6)
_AGC_HEADROOM_MIN = 10.0    # below this, the next burst clips -> come down
_AGC_HEADROOM_MAX = 25.0    # above this we are wasting sensitivity -> go up
_AGC_GAIN_MIN = 7.7         # below this the ADC's own noise starts to dominate
_AGC_GAIN_MAX = 38.6        # above this an R820T mostly amplifies its own noise
_AGC_INTERVAL_S = 12.0      # a gain change restarts the capture: do it rarely
_agc_last_t = 0.0
_agc_log = []               # recent adjustments, for the UI to explain itself


def _nearest_gain(v):
    """The supported tuner gain closest to ``v`` (pure)."""
    return min(_R820T_GAINS, key=lambda g: abs(g - v))


def agc_step(level, headroom_db, gain, lo=_AGC_GAIN_MIN, hi=_AGC_GAIN_MAX):
    """Decide the next tuner gain from the measured front-end health (pure).

    Returns ``(new_gain, reason)`` or ``(None, reason)`` when nothing should
    change. One step at a time, and only outside the target headroom band, so
    the loop settles instead of hunting — each change restarts the capture, and
    restarting a capture repeatedly is what wedges an RTL-SDR.

    Coming down on clipping is urgent (the samples are already wrong); going up
    for sensitivity is not, so it only happens when there is a lot of headroom
    going spare.
    """
    try:
        gain = float(gain)
    except (TypeError, ValueError):
        return None, "no manual gain to adjust"
    steps = [g for g in _R820T_GAINS if lo - 1e-9 <= g <= hi + 1e-9] or list(_R820T_GAINS)
    cur = _nearest_gain(gain)
    idx = steps.index(cur) if cur in steps else None
    if idx is None:
        return _nearest_gain(max(lo, min(hi, gain))), "gain outside the managed range"
    if level == "overload":
        if idx == 0:
            return None, "clipping at the lowest usable gain — the signal is too strong for this front end"
        return steps[idx - 1], "clipping"
    if headroom_db is None:
        return None, "no measurement yet"
    if headroom_db < _AGC_HEADROOM_MIN:
        if idx == 0:
            return None, "little headroom left, already at the lowest usable gain"
        return steps[idx - 1], "only %.1f dB of headroom" % headroom_db
    if headroom_db > _AGC_HEADROOM_MAX:
        if idx >= len(steps) - 1:
            return None, "plenty of headroom, already at the highest useful gain"
        return steps[idx + 1], "%.1f dB of headroom going spare" % headroom_db
    return None, "headroom %.1f dB is in band" % headroom_db


def agc_status():
    """What the managed gain has been doing, for the UI."""
    return {"managed": bool(_agc and _gain is not None),
            "gain": _gain, "log": list(_agc_log[-6:]),
            "band_db": [_AGC_HEADROOM_MIN, _AGC_HEADROOM_MAX],
            "range_db": [_AGC_GAIN_MIN, _AGC_GAIN_MAX]}


def _settings_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "data", "rf_settings.json")


_SETTINGS_KEYS = ("ppm", "gain", "agc", "fft", "avg", "window", "bins",
                  "bias_t", "direct", "conv_hz", "detector", "hide_dc")
_SETTINGS_KEYS_G = tuple("_" + k for k in _SETTINGS_KEYS)


_no_persist = False        # the selftest drives set_tuning(); it must not save


def _save_settings():
    """Remember the tuner settings across restarts (best effort, never raises).

    Without this a restart silently threw away the gain, the detector and the
    converter offset and went back to the shipped defaults — which is how you
    end up measuring with settings you did not choose.
    """
    if _no_persist:
        return False
    try:
        d = {"ppm": _ppm, "gain": _gain, "agc": _agc, "fft": _fft, "avg": _avg,
             "window": _window, "bins": _bins, "bias_t": _bias_t,
             "direct": _direct, "conv_hz": _conv_hz, "detector": _detector,
             "hide_dc": _hide_dc}
        path = _settings_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(d, fh, indent=2)
        os.replace(tmp, path)               # never leave a half-written file
        return True
    except OSError:
        return False


def _load_settings():
    """Apply the saved settings at import. A fresh install has none, and gets
    the shipped defaults."""
    global _ppm, _gain, _agc, _fft, _avg, _window, _bins, _bias_t, _direct
    global _conv_hz, _detector, _hide_dc
    try:
        with open(_settings_path()) as fh:
            d = json.load(fh)
        if not isinstance(d, dict):
            return False
    except (OSError, ValueError):
        return False
    try:
        if "ppm" in d:
            _ppm = int(d["ppm"])
        if "gain" in d:
            _gain = None if d["gain"] is None else float(d["gain"])
        if "agc" in d:
            _agc = bool(d["agc"])
        if d.get("fft") in _FFT_SIZES or d.get("fft") == 0:
            _fft = int(d["fft"])
        if "avg" in d:
            _avg = max(1, min(64, int(d["avg"])))
        if d.get("window") in _WINDOWS:
            _window = d["window"]
        if d.get("bins") in _BIN_CHOICES:
            _bins = int(d["bins"])
        if "bias_t" in d:
            _bias_t = bool(d["bias_t"])
        if d.get("direct") in ("auto", "on", "off"):
            _direct = d["direct"]
        if "conv_hz" in d:
            _conv_hz = int(d["conv_hz"])
        if d.get("detector") in _DETECTORS:
            _detector = d["detector"]
        if "hide_dc" in d:
            _hide_dc = bool(d["hide_dc"])
        return True
    except (TypeError, ValueError):
        return False


def get_tuning():
    """Current tuner corrections + resolution/hardware settings for the UI."""
    return {"ppm": _ppm, "gain": ("auto" if _gain is None else _gain),
            "gain_is_auto": _gain is None, "agc": bool(_agc),
            "agc_status": agc_status(),
            "fft": _fft, "avg": _avg, "window": _window, "bins": _bins,
            "bias_t": _bias_t, "direct": _direct, "conv_hz": _conv_hz,
            "detector": _detector, "hide_dc": bool(_hide_dc),
            "fft_sizes": list(_FFT_SIZES), "windows": list(_WINDOWS),
            "bin_choices": list(_BIN_CHOICES), "detectors": list(_DETECTORS)}


def set_tuning(ppm=None, gain=None, fft=None, avg=None, window=None, bins=None,
               bias_t=None, direct=None, conv_hz=None, detector=None, agc=None,
               hide_dc=None):
    """Set PPM freq-correction, tuner gain and the resolution / hardware extras,
    then reapply to any running capture. gain may be a number (dB), or
    'auto'/'' /None for AGC. Invalid values are ignored (the setting is kept)."""
    global _ppm, _gain, _fft, _avg, _window, _bins, _bias_t, _direct, _conv_hz
    global _detector, _agc, _hide_dc
    if ppm is not None:
        try:
            _ppm = max(-1000, min(1000, int(float(ppm))))
        except (TypeError, ValueError):
            pass
    if agc is not None:
        _agc = str(agc).lower() in ("1", "true", "on", "yes", "managed")
    if gain is not None:
        if str(gain).lower() in ("managed", "auto-managed"):
            _agc = True
            if _gain is None:
                _gain = 25.4
        elif gain in ("auto", "", "AUTO"):
            _gain = None            # the dongle's own AGC: explicit opt-in
            _agc = False
        else:
            try:
                _gain = max(0.0, min(50.0, round(float(gain), 1)))
            except (TypeError, ValueError):
                pass
    if fft is not None:
        try:
            v = int(float(fft))
            if v == 0 or v in _FFT_SIZES:
                _fft = v
        except (TypeError, ValueError):
            if str(fft).lower() == "auto":
                _fft = 0
    if avg is not None:
        try:
            _avg = max(1, min(64, int(float(avg))))
        except (TypeError, ValueError):
            pass
    if window is not None and str(window).lower() in _WINDOWS:
        _window = str(window).lower()
    if bins is not None:
        try:
            v = int(float(bins))
            if v in _BIN_CHOICES:
                _bins = v
        except (TypeError, ValueError):
            pass
    if detector is not None and str(detector).lower() in _DETECTORS:
        _detector = str(detector).lower()
    if bias_t is not None:
        _bias_t = str(bias_t).lower() in ("1", "true", "on", "yes")
    if hide_dc is not None:
        _hide_dc = str(hide_dc).lower() in ("1", "true", "on", "yes")
    if direct is not None and str(direct).lower() in ("auto", "on", "off"):
        _direct = str(direct).lower()
    if conv_hz is not None:
        try:
            _conv_hz = max(-12_000_000_000, min(12_000_000_000, int(float(conv_hz))))
        except (TypeError, ValueError):
            pass
    _save_settings()          # the choice survives a restart
    # Reapply live so the change takes effect without the user restarting.
    try:
        _power.reapply()
        _ism.reapply()
    except Exception:
        pass
    return get_tuning()


def reset_tuning():
    """Put every tuner setting back to what a fresh install ships with."""
    globals().update(_DEFAULTS)
    _save_settings()
    try:
        _power.reapply()
        _ism.reapply()
    except Exception:
        pass
    return get_tuning()


def _settings_sig():
    """Everything that changes a capture's output — a start() with a new value
    restarts the sweep even on the same span."""
    return (_hide_dc, _ppm, _gain, _fft, _avg, _window, _bins, _bias_t, _direct,
            _conv_hz, _detector)


def _parse_hz(txt):
    """'433.92M' / '868.3M' / '315000000' -> Hz (pure)."""
    t = str(txt).strip().upper()
    mult = 1.0
    if t.endswith("G"):
        mult, t = 1e9, t[:-1]
    elif t.endswith("M"):
        mult, t = 1e6, t[:-1]
    elif t.endswith("K"):
        mult, t = 1e3, t[:-1]
    return int(round(float(t) * mult))


def _direct_on(hw_lo, hw_hi):
    """Should this hardware window use direct sampling? (pure given settings)"""
    if _direct == "on":
        return True
    if _direct == "off":
        return False
    return hw_hi <= _DIRECT_MAX_HZ          # auto: HF (below the tuner's ~24 MHz floor)


def _hw_range_ok(hw_lo, hw_hi):
    """Is [lo,hi] (hardware Hz) receivable: tuner 24-1766 MHz, or HF via direct sampling."""
    if _direct_on(hw_lo, hw_hi):
        return 500_000 <= hw_lo and hw_hi <= _DIRECT_MAX_HZ
    return 24_000_000 <= hw_lo and hw_hi <= 1_766_000_000


_biast_state = False        # what we last told the bias tee (it's off at power-up)


def _set_biast(on):
    """rtl_sdr has no -T flag: switch the RTL-SDR Blog bias tee with rtl_biast
    before a raw-IQ capture opens the dongle. Only runs when the state has to
    change (it briefly opens the dongle, so not on every start). No-op when the
    tool is missing. Generic RTL2832U dongles have no bias tee; it does nothing."""
    global _biast_state
    on = bool(on)
    if on == _biast_state:
        return True
    tool = _which("rtl_biast")
    if not tool:
        return False
    try:
        subprocess.run([tool, "-b", "1" if on else "0"], capture_output=True, timeout=5, check=False)
        _biast_state = on
        return True
    except Exception:
        return False


_WIN_RTLPOWER = {"hann": "hamming", "blackman-harris": "blackman-harris",
                 "flattop": "blackman-harris", "rect": "rectangle"}


def _fft_window(n):
    """FFT window samples for the current setting (numpy)."""
    import numpy as np
    if _window == "rect":
        return np.ones(n, dtype=np.float32)
    k = np.arange(n) / float(n - 1)
    if _window == "blackman-harris":
        a = (0.35875, 0.48829, 0.14128, 0.01168)
    elif _window == "flattop":
        a = (0.21557895, 0.41663158, 0.277263158, 0.083578947, 0.006947368)
    else:
        return np.hanning(n).astype(np.float32)
    w = np.zeros(n)
    for i, ai in enumerate(a):
        w += ((-1) ** i) * ai * np.cos(2 * np.pi * i * k)
    return w.astype(np.float32)


def _auto_fft(sr_hz, lo_hz, hi_hz, bins):
    """FFT size giving >= 2 FFT bins per display column across [lo,hi] (pure)."""
    span = max(1, hi_hz - lo_hz)
    need = 2.0 * bins * sr_hz / span
    n = 512
    while n < need and n < _FFT_SIZES[-1]:
        n *= 2
    return n


def _tuner_args(tool="rtl_433", hw_lo=None, hw_hi=None):
    """Common flags for the current PPM + gain, plus (rtl_power only) bias-T,
    direct sampling and the FFT window. rtl_433 uses -T for its run time, so it
    never gets the bias-T flag."""
    args = []
    if _ppm:
        args += ["-p", str(_ppm)]
    if _gain is not None:
        args += ["-g", str(_gain)]
    if tool == "rtl_power":
        if _bias_t:
            args += ["-T"]
        if hw_lo is not None and _direct_on(hw_lo, hw_hi):
            args += ["-D"]
        args += ["-w", _WIN_RTLPOWER.get(_window, "hamming")]
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
    heal = f.get("heal") or {}
    if heal.get("state") == "flapping" or (heal.get("drops_10min") or 0) >= _FLAP_DROPS:
        why = "; ".join((heal.get("kernel_hints") or [])[:3]) or "repeated USB disconnects"
        return ("usb_flapping",
                "The RTL-SDR keeps dropping off USB (%d times in 10 min: %s). Ragnar recovers it "
                "automatically, but this is a cable, port or dongle fault."
                % (heal.get("drops_10min") or 0, why),
                list(heal.get("advice") or []))
    if not f.get("usb_present") and heal.get("state") in ("recovering", "failed"):
        return ("usb_stuck", heal.get("message") or
                "The RTL-SDR is plugged in but not answering on USB — Ragnar is power-cycling its port.",
                list(heal.get("advice") or []) or
                ["Wait a moment — Ragnar power-cycles the port with increasing gaps.",
                 "If it never comes back, replug it by hand and try another cable."])
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
        "heal": heal_status(),
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
        self._acc = [None] * self.bins      # per-column bin values, detector applied on finish
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
                if self._acc[b] is None:
                    self._acc[b] = [db]
                else:
                    self._acc[b].append(db)
                self._filled = True
        # Apply the detector as we go, so a frame read out mid-sweep is still
        # consistent with a finished one.
        for b, vals in enumerate(self._acc):
            if vals:
                self.grid[b] = _combine_db(vals, _detector)
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


def _iq_plan(lo_hz, hi_hz, hide_dc=False):
    """Pick a single-tune (center, sample_rate, notch_hz) covering [lo,hi] Hz, or None (pure).

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
    if hide_dc:
        # Narrow band: tune just past its top edge so the hump is not in it at all.
        need = int(round(2 * (span + _DC_CLEAR_HZ) * _IQ_EDGE_MARGIN))
        if need <= _DC_SR_CAP:
            return hi_hz + _DC_CLEAR_HZ, max(_IQ_SR_MIN, need), None
        # Wide band: move the tuner off the band centre (433.92 MHz is where the
        # remotes are) as far as the rate allows, and fill the hump in there.
        shift = int(min(_DC_SHIFT_MAX, _DC_SR_CAP / (2.0 * _IQ_EDGE_MARGIN) - span / 2.0))
        if shift > 2 * _DC_HALF_HZ:
            sr = int(min(_IQ_SR_MAX, max(_IQ_SR_MIN,
                                         round(2 * (span / 2.0 + shift) * _IQ_EDGE_MARGIN))))
            return center + shift, sr, center + shift
        sr = int(min(_IQ_SR_MAX, max(_IQ_SR_MIN, round(span * _IQ_EDGE_MARGIN))))
        return center, sr, center
    sr = int(min(_IQ_SR_MAX, max(_IQ_SR_MIN, round(span * _IQ_EDGE_MARGIN))))
    return center, sr, None


def _fill_dc(db, center_hz, sr_hz, notch_hz, half_hz=_DC_HALF_HZ):
    """Fill the FFT bins within ``half_hz`` of ``notch_hz`` with a straight line
    between the noise just either side (pure; ``db`` is fftshifted, low->high).

    Returns the list, changed in place. Only ever the tuner's own hump: anything
    real there is lost, which is why the plan keeps it off the band centre.
    """
    n = len(db)
    if not n or notch_hz is None or sr_hz <= 0:
        return db
    bw = sr_hz / float(n)
    k0 = (notch_hz - (center_hz - sr_hz / 2.0)) / bw
    a = max(0, int(k0 - half_hz / bw))
    b = min(n - 1, int(k0 + half_hz / bw) + 1)
    if b <= a:
        return db
    side = max(2, int(8000 / bw))                      # ~8 kHz of noise either side
    left = db[max(0, a - side):a] or db[b + 1:b + 1 + side]
    right = db[b + 1:b + 1 + side] or left
    if not left:
        return db
    lv = sorted(left)[len(left) // 2]                  # medians: a signal beside it
    rv = sorted(right)[len(right) // 2]                # does not become the fill
    for i in range(a, b + 1):
        db[i] = lv + (rv - lv) * (i - a + 1) / float(b - a + 2)
    return db


_CLIP_WARN_FRAC = 1e-4     # >0.01% of samples pinned at the rail = overloading
_HEADROOM_WARN_DB = 3.0    # closer than this to full scale = about to clip


def adc_health(clip_frac, peak_fs):
    """Grade the front end from a block of raw samples (pure).

    ``clip_frac`` is the fraction of 8-bit samples sitting on a rail (0 or 255),
    ``peak_fs`` the largest sample magnitude as a fraction of full scale. An
    RTL-SDR that is driven too hard does not simply read high: the ADC clips, and
    clipping generates harmonics and intermodulation products that look exactly
    like real transmitters. Every level in an overloaded capture is suspect, so
    this is reported rather than silently corrected.

    Returns ``(level, headroom_db)`` where level is ok / near / overload.
    """
    try:
        clip_frac = max(0.0, float(clip_frac))
        peak_fs = max(1e-6, min(1.0, float(peak_fs)))
    except (TypeError, ValueError):
        return "ok", None
    headroom = -20.0 * math.log10(peak_fs)          # dB below full scale
    if clip_frac > _CLIP_WARN_FRAC:
        return "overload", headroom
    if headroom < _HEADROOM_WARN_DB:
        return "near", headroom
    return "ok", headroom


def _detector_name(detector=None):
    """Normalise a detector name, falling back to the global setting (pure)."""
    d = str(detector or _detector or "peak").strip().lower()
    return d if d in _DETECTORS else "peak"


def _combine_db(vals, detector="peak"):
    """Combine the dB values of the FFT bins that share one display column (pure).

    * ``peak``   — positive-peak: the largest bin. Finds every signal, including
      one narrower than a column, but reads a noise floor several dB high because
      it keeps the largest of several noisy samples. The right detector for
      *looking*, the wrong one for *measuring*.
    * ``rms``    — averages in the power domain. The correct detector for a level,
      channel-power or noise measurement: it reports the true average power in the
      column regardless of how many bins fall in it.
    * ``avg``    — averages in dB (log / "video" average). Steadier than rms and
      reads noise about 2.5 dB lower, which is why a log-averaged floor must not
      be quoted as a power figure.
    * ``sample`` — the single bin nearest the column centre. No smoothing at all;
      shows the trace as the FFT actually produced it, and can miss a narrow
      signal that falls between samples.
    * ``min``    — negative-peak: the smallest bin. Digs the true noise floor out
      from under bursty traffic.
    """
    if not vals:
        return None
    det = _detector_name(detector)
    if det == "rms":
        return 10.0 * math.log10(
            sum(10.0 ** (v / 10.0) for v in vals) / len(vals) + 1e-30)
    if det == "avg":
        return sum(vals) / float(len(vals))
    if det == "sample":
        return vals[len(vals) // 2]
    if det == "min":
        return min(vals)
    return max(vals)


def _iq_to_grid(psd_db, center_hz, sr_hz, lo_hz, hi_hz,
                bins=_POWER_BINS, floor=_FLOOR_DBM, detector=None):
    """Fold an fftshifted PSD (dB, low->high freq) onto ``bins`` display columns.

    ``psd_db[i]`` is the power of FFT bin ``i`` of a capture centred at
    ``center_hz`` sampled at ``sr_hz`` (so bin 0 sits at ``center - sr/2``). Each
    bin is dropped into the display column its centre frequency lands in over
    [lo,hi], and the bins sharing a column are combined by the selected detector
    (see :func:`_combine_db`). Bins outside [lo,hi] (the oversampled edges) are
    ignored; columns no bin reached stay at ``floor``. Pure list math — no numpy —
    so the selftest verifies it and it also serves as the loop's binning step.
    """
    det = _detector_name(detector)
    grid = [floor] * bins
    n = len(psd_db)
    span = hi_hz - lo_hz
    if n == 0 or span <= 0 or sr_hz <= 0:
        return grid
    bin_w = sr_hz / float(n)
    f0 = center_hz - sr_hz / 2.0        # centre frequency of the first (lowest) bin
    col_w = span / float(bins)
    cnt = [0] * bins
    acc = [0.0] * bins
    near = [None] * bins                # sample detector: distance to column centre
    for i in range(n):
        fc = f0 + i * bin_w
        col = int((fc - lo_hz) / span * bins)
        if col < 0 or col >= bins:
            continue
        v = psd_db[i]
        c = cnt[col]
        if det == "rms":
            acc[col] += 10.0 ** (v / 10.0)
        elif det == "avg":
            acc[col] += v
        elif det == "sample":
            d = abs(fc - (lo_hz + (col + 0.5) * col_w))
            if near[col] is None or d < near[col]:
                near[col], acc[col] = d, v
        elif det == "min":
            acc[col] = v if not c else min(acc[col], v)
        else:
            acc[col] = v if not c else max(acc[col], v)
        cnt[col] = c + 1
    for c in range(bins):
        if not cnt[c]:
            continue
        if det == "rms":
            grid[c] = 10.0 * math.log10(acc[c] / cnt[c] + 1e-30)
        elif det == "avg":
            grid[c] = acc[c] / cnt[c]
        else:
            grid[c] = acc[c]
    # Fewer FFT bins than columns (a narrow zoom): interpolate the columns no bin
    # landed in, instead of leaving dead floor-level stripes. Only between
    # filled columns, so a genuinely uncovered edge still reads as floor.
    filled = [c for c in range(bins) if cnt[c]]
    if filled and len(filled) < bins:
        for a, b in zip(filled, filled[1:]):
            if b - a > 1:
                va, vb = grid[a], grid[b]
                for c in range(a + 1, b):
                    grid[c] = va + (vb - va) * (c - a) / float(b - a)
        # edge columns inside the captured bandwidth take the nearest bin's value
        cap_lo, cap_hi = center_hz - sr_hz / 2.0, center_hz + sr_hz / 2.0
        for c in list(range(0, filled[0])) + list(range(filled[-1] + 1, bins)):
            fc = lo_hz + (c + 0.5) * span / bins
            if cap_lo <= fc <= cap_hi:
                grid[c] = grid[filled[0]] if c < filled[0] else grid[filled[-1]]
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
        if _conv_hz:
            freq = str(int(_parse_hz(freq) + _conv_hz))
        cmd = [_RTL_433, "-F", "json", "-M", "level", "-f", freq] + _tuner_args("rtl_433")
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
        self._overload = None      # {"clip_frac":..,"headroom_db":..,"level":..}
        self._agc_pending = None   # a gain the managed loop wants applied
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
                if hi_hz - lo_hz >= 100_000 and _hw_range_ok(lo_hz + _conv_hz, hi_hz + _conv_hz):
                    custom = (lo_hz, hi_hz)
        except (TypeError, ValueError):
            custom = None
        if custom:
            label, lo, hi = (label or "zoom"), custom[0], custom[1]
        else:
            band = band if band in RTL_BANDS else "433"
            label, (lo, hi) = band, RTL_BANDS[band]
        sig = (label, lo, hi, _settings_sig())
        prev = None
        with self._lock:
            if self._thread and self._thread.is_alive():
                if sig == self._sig:
                    return {"ok": True, "already": True, "band": label}
                self._stop_locked()
                prev = self._thread
        # Let the previous capture actually finish before a new one opens the
        # dongle. Two rtl_sdr processes racing for the same device is what turns
        # a burst of retunes into a wedged USB device.
        if prev is not None:
            prev.join(timeout=_TERM_GRACE_S + 1.0)
        with self._lock:
            # A fresh Event (not .clear()) so any still-exiting previous sweep
            # thread keeps its own now-set event and stops cleanly, instead of
            # racing this new run on a shared, just-cleared one.
            self._stop = threading.Event()
            self._frames = []
            self._seq = 0
            self._maxhold = [_FLOOR_DBM] * _bins
            self._band = label
            self._sig = sig
            self._lo, self._hi = lo, hi
            self._engine = None
            self._floor_dyn = None
            self._error = None
            self._rbw = None
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
            self._maxhold = [_FLOOR_DBM] * _bins
            self._band = label
            self._sig = (sig[0], sig[1], sig[2], _settings_sig())
            self._lo, self._hi = lo, hi
            self._engine = None
            self._floor_dyn = None
            self._error = None
            self._rbw = None
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
        # lo/hi are RF; the radio is tuned to RF + the converter offset.
        lo, hi = lo + _conv_hz, hi + _conv_hz
        _usb_settle(self._stop)                 # don't reopen the dongle the instant it closed
        if self._stop.is_set():
            return
        plan = _iq_plan(lo, hi, _hide_dc) if _iq_available() else None
        # The managed gain restarts the capture here rather than through
        # set_tuning(), so it never reaches into this thread's own lifecycle.
        while plan and not self._stop.is_set():
            ok = self._run_iq(lo, hi, plan[0], plan[1], plan[2])
            want = self._agc_pending
            if want is not None and not self._stop.is_set():
                self._agc_pending = None
                global _gain
                _gain = want
                _save_settings()
                _usb_settle(self._stop)
                continue
            if ok:
                return
            break
        # A quick restart can find the dongle still held by the previous capture;
        # give the IQ engine one more try before settling for the slow sweep.
        stop = self._stop
        _usb_settle(stop)
        if plan and not stop.wait(0.8) and self._run_iq(lo, hi, plan[0], plan[1], plan[2]):
            return
        if stop.is_set():
            return
        self._engine = "rtl_power"
        self._floor_dyn = None
        self._overload = None        # the sweep engine never sees raw samples
        self._run_rtl_power(lo, hi)

    def _run_iq(self, lo, hi, center, sr, notch=None):
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
        bins = _bins
        N = _fft or _auto_fft(sr, lo, hi, bins)
        self._rbw = sr / float(N)
        self._detector = _detector
        win = _fft_window(N)
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
        if _direct_on(lo, hi):
            cmd += ["-D"]                         # HF: direct sampling
        _set_biast(_bias_t)                       # rtl_sdr has no -T; set the GPIO first
        cmd += ["-"]                              # stream raw IQ to stdout
        self._stderr_tail = None
        old = self._proc
        if old is not None and old.poll() is None:
            _terminate(old)              # never launch on top of our own capture
            self._proc = None
            _usb_settle(self._stop)
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
                u8 = np.frombuffer(buf, dtype=np.uint8)
                # Front-end health, measured on the samples as the ADC delivered
                # them: how many sit on a rail, and how close the loudest gets.
                clip = float(np.count_nonzero((u8 == 0) | (u8 == 255))) / max(1, u8.size)
                raw = (u8.astype(np.float32) - 127.5) / 127.5
                self._note_overload(clip, float(np.abs(raw).max()))
                nwin = (raw.shape[0] // 2) // N
                if nwin <= 0:
                    continue
                use = min(nwin, _avg)
                iq = raw[:use * N * 2].reshape(use, N, 2)
                cwin = (iq[:, :, 0] + 1j * iq[:, :, 1]) * win  # window each row
                spec = np.fft.fftshift(np.fft.fft(cwin, axis=1), axes=1)
                psd = (spec.real ** 2 + spec.imag ** 2).mean(axis=0) / win_norm
                db = 10.0 * np.log10(psd + 1e-12)
                dbl = db.tolist()
                if notch is not None:
                    _fill_dc(dbl, center, sr, notch)
                grid = _iq_to_grid(dbl, center, sr, lo, hi, bins=bins)
                floor_ema = self._update_iq_floor(grid, floor_ema)
                self._push_frame(grid)
                if self._agc_pending is not None:
                    break                 # restart this capture at the new gain
                # Same row the page draws, same samples it was made from: the
                # trigger sees exactly what you see, and keeps the moment before.
                try:
                    _trigger.feed(buf, grid, lo - _conv_hz, hi - _conv_hz,
                                  center - _conv_hz, sr)
                except Exception as exc:      # never let it break the waterfall
                    _trigger._error = str(exc)
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
        # A managed-gain change restarts this capture, so the old rtl_sdr has to
        # be closed here: leaving it running would hold the device and the
        # relaunch would fail (and a device left half-open is how one gets
        # wedged). The stop path does its own termination.
        if self._agc_pending is not None:
            _terminate(proc)
            self._proc = None
            return True
        # Nothing produced and we didn't ask it to stop -> let rtl_power try.
        if produced == 0 and not stop.is_set():
            _terminate(proc)
            self._proc = None
            self._error = None
            return False
        return True

    def _note_overload(self, clip_frac, peak_fs):
        """Record front-end health for the UI (called once per waterfall row).

        This is also where the managed gain gets its measurement. It asks for a
        change at most every _AGC_INTERVAL_S, and only when the headroom is
        outside the target band, because applying one restarts the capture.
        """
        global _agc_last_t
        level, headroom = adc_health(clip_frac, peak_fs)
        self._overload = {"level": level, "clip_frac": round(clip_frac, 6),
                          "headroom_db": (round(headroom, 1)
                                          if headroom is not None else None),
                          "gain": ("auto" if _gain is None else _gain),
                          "managed": bool(_agc and _gain is not None)}
        if not (_agc and _gain is not None) or self._agc_pending is not None:
            return
        now = time.time()
        if now - _agc_last_t < _AGC_INTERVAL_S:
            return
        new, why = agc_step(level, headroom, _gain)
        if new is None or abs(new - _gain) < 1e-6:
            return
        _agc_last_t = now
        _agc_log.append({"ts": now, "from": _gain, "to": new, "why": why})
        del _agc_log[:-20]
        self._agc_pending = new

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
        bins = _bins
        step = max(1000, (hi - lo) // bins)   # Hz per rtl_power bin
        self._rbw = float(step)
        builder = _PowerFrameBuilder(lo, hi, bins=bins)
        cmd = [_RTL_POWER, "-f", "%d:%d:%d" % (lo, hi, step),
               "-i", str(_SWEEP_INTERVAL_S), "-c", "20%"] + _tuner_args("rtl_power", lo, hi)
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

    def begin_external(self, lo_hz, hi_hz, engine="iq-capture"):
        """Hand the waterfall over to another capture (e.g. a raw-IQ recording).

        One dongle serves one job, so while a recording runs the sweep can't.
        Rather than leaving the waterfall frozen, the recording feeds its own
        FFT rows through here and the page keeps scrolling — showing exactly
        what is being written to the file."""
        with self._lock:
            self._frames = []
            self._seq = 0
            self._maxhold = [_FLOOR_DBM] * _bins
            self._lo, self._hi = int(lo_hz), int(hi_hz)
            self._band = engine
            self._engine = engine
            self._error = None
            self._floor_dyn = None

    def end_external(self):
        with self._lock:
            self._band = None

    def feed_external(self, grid):
        """Publish one externally-produced row (same shape as a sweep frame)."""
        if self._thread and self._thread.is_alive():
            return                              # a real sweep owns the ring
        self._floor_dyn = self._update_iq_floor(grid, self._floor_dyn) if grid else self._floor_dyn
        self._push_frame(grid)

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
                    "bins": len(ints), "floor": self._active_floor()}
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
                    "band": self._band, "bins": _bins,
                    "band_hz": [self._lo, self._hi] if self._lo else None,
                    "frames_buffered": len(self._frames), "seq": self._seq,
                    "floor_dbm": self._active_floor(), "engine": self._engine,
                    "detector": _detector, "overload": self._overload,
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
                    "bins": _bins, "floor_dbm": self._active_floor(),
                    "engine": self._engine,
                    "rbw_hz": round(self._rbw, 1) if getattr(self, "_rbw", None) else None,
                    "conv_hz": _conv_hz, "detector": _detector,
                    "overload": self._overload,
                    "max_hold": list(self._maxhold) if self._maxhold else None,
                    "running": bool(self._thread and self._thread.is_alive()),
                    "error": self._error}


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

# The USB dongle needs a moment between one capture closing it and the next one
# opening it. librtlsdr cancels its async transfers on SIGTERM and closes the
# device; SIGKILL skips that and can leave the RTL2832U wedged until it is
# physically replugged. So: always ask politely first, wait long enough for the
# handler to run, and never reopen the device immediately after a close.
_USB_RELEASE_S = 0.45          # settle time after a capture process exits
_TERM_GRACE_S = 4.0            # how long rtl_sdr/rtl_power gets to close cleanly
_last_close_t = 0.0


def _terminate(proc, grace=_TERM_GRACE_S):
    """Stop a capture process cleanly and record when the device was released."""
    global _last_close_t
    if not proc:
        return
    try:
        if proc.poll() is None:
            proc.terminate()                      # SIGTERM -> rtlsdr_cancel_async + close
            try:
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                proc.kill()                       # last resort; may wedge the dongle
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
    except Exception:  # pragma: no cover - defensive
        pass
    _last_close_t = time.time()


def _usb_settle(stop=None):
    """Wait out the release window before reopening the dongle (interruptible)."""
    left = _USB_RELEASE_S - (time.time() - _last_close_t)
    if left <= 0:
        return
    if stop is not None:
        stop.wait(left)
    else:
        time.sleep(left)


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
# Snapshot what a fresh install runs with, BEFORE any saved file is applied, so
# "reset to defaults" and the selftest both have something honest to refer to.
_DEFAULTS = {k: globals()[k] for k in
             ("_ppm", "_gain", "_agc", "_fft", "_avg", "_window", "_bins",
              "_bias_t", "_direct", "_conv_hz", "_detector", "_hide_dc")}
_load_settings()          # a saved configuration wins over the shipped defaults
_detect_cache = None


_USB_IDS = (("0bda", "2838"), ("0bda", "2832"), ("0bda", "2834"), ("0bda", "2837"))
_USBDEVFS_RESET = (ord("U") << 8) | 20


def _usb_device_path():
    """Path of the RTL-SDR under /dev/bus/usb, from sysfs (pure-ish, no lsusb)."""
    root = "/sys/bus/usb/devices"
    try:
        names = os.listdir(root)
    except OSError:
        return None
    for name in sorted(names):
        d = os.path.join(root, name)
        try:
            with open(os.path.join(d, "idVendor")) as fh:
                vid = fh.read().strip().lower()
            with open(os.path.join(d, "idProduct")) as fh:
                pid = fh.read().strip().lower()
            if (vid, pid) not in _USB_IDS:
                continue
            with open(os.path.join(d, "busnum")) as fh:
                bus = int(fh.read().strip())
            with open(os.path.join(d, "devnum")) as fh:
                dev = int(fh.read().strip())
        except (OSError, ValueError):
            continue
        return "/dev/bus/usb/%03d/%03d" % (bus, dev)
    return None


def usb_reset():
    """Power-cycle the RTL-SDR over USB, the way replugging it does.

    An RTL2832U can end up in a state where it still enumerates and still opens
    — ``rtl_test`` is happy — but never delivers a single sample. Repeated
    open/close cycles are what puts it there. Until now the only cure was
    walking to the box and pulling the dongle out; this does the same thing from
    software (USBDEVFS_RESET), which is what the kernel does on a replug.

    Stops anything using the device first, because resetting the bus underneath
    a running capture is how you get a *second* wedged device.
    """
    path = _usb_device_path()
    if not path:
        return {"ok": False, "error": "no RTL-SDR found on USB"}
    was = _power.status()
    resume = ([was.get("band_hz"), was.get("band")] if was.get("running") else None)
    try:
        power_stop()
    except Exception:
        pass
    try:
        _ism.stop()
    except Exception:
        pass
    _usb_settle()
    try:
        import fcntl
        fd = os.open(path, os.O_WRONLY)
        try:
            fcntl.ioctl(fd, _USBDEVFS_RESET, 0)
        finally:
            os.close(fd)
    except PermissionError:
        return {"ok": False, "path": path,
                "error": "no permission to reset the USB device — run the web UI "
                         "as root, or replug the dongle by hand"}
    except OSError as exc:
        return {"ok": False, "path": path, "error": "USB reset failed: %s" % exc}
    time.sleep(2.0)                       # the device re-enumerates
    global _detect_cache
    _detect_cache = None                  # force a fresh probe next status()
    out = {"ok": True, "path": path,
           "note": "the dongle was re-enumerated, as if it had been replugged"}
    if resume and resume[0]:
        try:
            time.sleep(1.0)
            r = power_start(resume[1] or "433", lo_hz=resume[0][0], hi_hz=resume[0][1])
            out["resumed"] = bool(r.get("ok"))
        except Exception:
            out["resumed"] = False
    return out


# ---------------------------------------------------------------------------
# USB self-healing
# ---------------------------------------------------------------------------
#
# An RTL2832U dongle fails in three ways, and until now each one needed a person
# to walk over and replug it:
#
#   * wedged  — still enumerated, still opens, but never delivers a sample;
#   * stuck   — the port sees it connected, but it never finishes enumerating
#               (kernel: "device not accepting address", "error -71",
#               "Cannot enable. Maybe the USB cable is bad?"), and stays there;
#   * gone    — nothing on the port at all.
#
# Wedged is cleared by a USB reset. Stuck is cleared by cutting the port's 5 V
# for a few seconds — a real replug — which uhubctl can do on the Pi's root
# ports ("ppps": per-port power switching). Gone is a person's job: nothing
# here power-cycles a port that shows no device, so an unplugged dongle is left
# alone. Attempts back off, the sweep that was running is resumed afterwards,
# and when the dongle keeps dropping out the kernel's own evidence is reported
# rather than a generic "check your power supply".

_UHUBCTL = "/usr/sbin/uhubctl"
_HEAL_INTERVAL_S = 5.0
_HEAL_BACKOFF_S = (0, 15, 45, 120, 300)
_HEAL_MAX_ATTEMPTS = 8               # per incident; then wait for a person
_HEAL_STABLE_S = 600                 # healthy this long -> the incident is over
_WEDGE_SILENT_S = 20.0               # sweep running, no new rows this long = wedged
_FLAP_WINDOW_S = 600
_FLAP_DROPS = 3                      # disconnects in the window = flapping
_CYCLE_OFF_S = 3                     # port power off time (2 s was not always enough)
_RTL_PIDS = ("2838", "2832", "2834", "2837")
_KERNEL_HINTS = (
    ("Maybe the USB cable is bad", "the kernel suspects the USB cable"),
    ("over-current", "the port reported over-current"),
    ("error -71", "USB protocol errors (-71): signal or power trouble on the cable/port"),
    ("error -110", "the dongle stopped answering (timeout -110)"),
    ("not accepting address", "the dongle would not take a USB address"),
    ("unable to enumerate", "the kernel gave up enumerating the dongle"),
)


def parse_uhubctl(text):
    """uhubctl's status listing -> [{hub, port, status, powered, connected, device}] (pure).

    ``device`` is None for an empty port, "" for a port that reports a connection
    but has no enumerated device ("connect []" — the stuck state), otherwise the
    "vid:pid description" of the device.
    """
    ports, hub = [], None
    for ln in (text or "").splitlines():
        m = re.match(r"\s*Current status for hub (\S+)", ln)
        if m:
            hub = m.group(1)
            continue
        m = re.match(r"\s*Port (\d+): ([0-9a-fA-F]{4})\s*(.*)$", ln)
        if not m or hub is None:
            continue
        rest = m.group(3)
        flags = rest.split("[")[0].split()
        dev = None
        if "[" in rest:
            inner = rest[rest.index("[") + 1:]
            dev = inner[:inner.rindex("]")] if "]" in inner else inner
            dev = dev.strip()
        ports.append({"hub": hub, "port": int(m.group(1)), "status": m.group(2).lower(),
                      "powered": "off" not in flags, "connected": "connect" in flags,
                      "device": dev})
    return ports


def rtl_ports(ports):
    """(ports with an enumerated RTL-SDR, ports stuck connected-but-unenumerated) (pure)."""
    present, stuck = [], []
    for pt in ports:
        dev = (pt.get("device") or "").lower()
        if dev:
            vid, _, pid = dev.split()[0].partition(":")
            if vid == "0bda" and pid in _RTL_PIDS:
                present.append(pt)
        elif pt.get("connected") and pt.get("device") == "":
            stuck.append(pt)
    return present, stuck


def usb_target(devname):
    """sysfs device name -> (uhubctl hub location, port) (pure).

    "2-1" -> ("2", 1): port 1 of root hub 2.  "1-1.4" -> ("1-1", 4): port 4 of
    the external hub at 1-1.
    """
    bus, _, path = str(devname).partition("-")
    parts = path.split(".")
    port = int(parts[-1])
    hub = bus if len(parts) == 1 else bus + "-" + ".".join(parts[:-1])
    return hub, port


def usb_devname(hub, port):
    """(uhubctl hub location, port) -> sysfs device name (pure). ("2", 1) -> "2-1"."""
    hub = str(hub)
    return ("%s-%d" % (hub, int(port))) if "-" not in hub else ("%s.%d" % (hub, int(port)))


def _kernel_ts(line):
    """Timestamp of a `dmesg --time-format iso` line, as epoch seconds, or None."""
    import datetime
    head = line.split(" ", 1)[0]
    try:
        return datetime.datetime.fromisoformat(head.replace(",", ".")).timestamp()
    except ValueError:
        return None


def parse_kernel_usb(lines, devname, now, window_s=_FLAP_WINDOW_S):
    """Disconnect count and plain-language hints for one USB port (pure).

    ``lines`` are `dmesg --time-format iso` lines; only those inside the window
    that name the port (``usb 2-1:``, ``usb2-port1:``) count.
    """
    if not devname:
        return 0, []
    bus, _, path = str(devname).partition("-")
    tags = ["usb %s:" % devname]                 # "usb 2-1: USB disconnect ..."
    if "." not in path:                          # root port: "usb usb2-port1: Cannot enable ..."
        tags.append("usb%s-port%s:" % (bus, path))
    drops, hints = 0, []
    for ln in lines or ():
        t = _kernel_ts(ln)
        if t is None or now - t > window_s or t > now + 5:
            continue
        if not any(tag in ln for tag in tags):
            continue
        if "USB disconnect" in ln:
            drops += 1
        for needle, text in _KERNEL_HINTS:
            if needle in ln and text not in hints:
                hints.append(text)
    return drops, hints


def plan_heal(present, wedged, stuck_port, attempts, since_last_s, have_uhubctl):
    """Next recovery step (pure). Returns (action, reason).

    Actions: none, wait, usb_reset, power_cycle, rebind, unplugged, give_up.
    A port is only ever power-cycled when there is evidence something is on it —
    a wedged dongle or a stuck connection — never just because nothing answers.
    """
    if present and not wedged:
        return "none", "healthy"
    if attempts >= _HEAL_MAX_ATTEMPTS:
        return "give_up", "recovery tried %d times" % attempts
    if not present and not stuck_port:
        return "unplugged", "nothing is connected to any USB port"
    delay = _HEAL_BACKOFF_S[min(attempts, len(_HEAL_BACKOFF_S) - 1)]
    if since_last_s < delay:
        return "wait", "next attempt in %d s" % int(delay - since_last_s)
    if present and wedged and attempts == 0:
        return "usb_reset", "open but sending nothing"
    reason = ("open but sending nothing" if present
              else "plugged in but not answering on USB")
    return ("power_cycle" if have_uhubctl else "rebind"), reason


def _usb_rtl_devname():
    """sysfs name ("2-1", "1-1.4") of the attached RTL-SDR, or None."""
    root = "/sys/bus/usb/devices"
    try:
        names = os.listdir(root)
    except OSError:
        return None
    for name in sorted(names):
        if ":" in name or name.startswith("usb"):
            continue
        d = os.path.join(root, name)
        try:
            with open(os.path.join(d, "idVendor")) as fh:
                vid = fh.read().strip().lower()
            with open(os.path.join(d, "idProduct")) as fh:
                pid = fh.read().strip().lower()
        except OSError:
            continue
        if (vid, pid) in _USB_IDS:
            return name
    return None


def _usb_controller(bus):
    """Platform controller (e.g. "xhci-hcd.0") that owns USB bus ``bus``."""
    try:
        real = os.path.realpath("/sys/bus/usb/devices/usb%s" % bus)
    except OSError:
        return None
    parent = os.path.basename(os.path.dirname(real))
    return parent or None


class SdrHealer:
    """Watch the RTL-SDR and put it back when it falls over."""

    def __init__(self):
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.enabled = True
        self.state = "starting"
        self.message = ""
        self.present = False
        self.port = None                 # last sysfs name the dongle was seen on
        self.attempts = 0
        self.last_attempt_t = 0.0
        self.healthy_since = None
        self.history = []
        self.drops = 0
        self.hints = []
        self._stuck_prev = None
        self._last_seq = None
        self._last_seq_t = None
        self._last_sweep = None          # (band, lo, hi, t) of the last running sweep
        self._resume = None
        self._dmesg_t = 0.0

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="sdr-healer", daemon=True)
            self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # pragma: no cover - never let the watcher die
                self.message = "self-heal check failed: %s" % exc
            wait = _HEAL_INTERVAL_S if self.state != "unplugged" else 15.0
            self._stop.wait(wait)

    # -- facts -------------------------------------------------------------
    def _uhub_ports(self):
        if not _have(_UHUBCTL):
            return None
        # With a stuck dongle every query waits out the kernel's own failing
        # re-enumeration of that port (~11 s here), so the timeout is generous.
        rc, out, _err = _run([_UHUBCTL], timeout=40)
        return parse_uhubctl(out) if rc == 0 else None

    def _kernel(self, now):
        # dmesg is re-read at most every 20 s; it is only evidence, not a trigger
        if now - self._dmesg_t < 20 or not self.port:
            return
        self._dmesg_t = now
        rc, out, _err = _run(["dmesg", "--time-format", "iso"], timeout=6)
        if rc == 0 and out:
            self.drops, self.hints = parse_kernel_usb(out.splitlines()[-600:], self.port, now)

    def _wedged(self, now):
        st = _power.status()
        if not st.get("running"):
            self._last_seq = None
            return False
        self._last_sweep = (st.get("band") or "433", (st.get("band_hz") or [None, None])[0],
                            (st.get("band_hz") or [None, None])[1], now)
        seq = st.get("seq")
        if seq != self._last_seq:
            self._last_seq, self._last_seq_t = seq, now
            return False
        return (now - (self._last_seq_t or now)) > _WEDGE_SILENT_S

    # -- one pass ----------------------------------------------------------
    def tick(self, now=None, confirm=True):
        now = now or time.time()
        if not self.enabled:
            self.state, self.message = "disabled", "self-healing is switched off"
            return
        dev = _usb_rtl_devname()
        self.present = bool(dev)
        if dev:
            self.port = dev
        wedged = self._wedged(now) if dev else False
        stuck_port = None
        seen_stuck = False
        if not dev or wedged:
            ports = self._uhub_ports()
            if ports is not None and not dev:
                _pres, stuck = rtl_ports(ports)
                # Only a connection that stays stuck across two checks counts —
                # a dongle is briefly "connected, not enumerated" while it plugs in.
                keys = sorted("%s:%d" % (p["hub"], p["port"]) for p in stuck)
                seen_stuck = bool(keys)
                if keys and not self.port:        # never seen yet: that port is where it is
                    h0, _, p0 = keys[0].partition(":")
                    self.port = usb_devname(h0, p0)
                if keys and (keys == self._stuck_prev or not confirm):
                    prefer = None
                    if self.port:
                        try:
                            prefer = "%s:%d" % usb_target(self.port)
                        except (ValueError, IndexError):
                            prefer = None
                    stuck_port = prefer if prefer in keys else keys[0]
                self._stuck_prev = keys
        self._kernel(now)
        if dev and not wedged:
            if self.healthy_since is None:
                self.healthy_since = now
            if self.attempts and now - self.healthy_since > _HEAL_STABLE_S:
                self.attempts = 0            # incident over
            self._resume_sweep()
            self.state = "flapping" if self.drops >= _FLAP_DROPS else "ok"
            self.message = self._flap_text() if self.state == "flapping" else "RTL-SDR on USB %s" % dev
            return
        self.healthy_since = None
        if self._resume is None and self._last_sweep and now - self._last_sweep[3] < 60:
            self._resume = self._last_sweep
        action, reason = plan_heal(bool(dev), wedged, stuck_port, self.attempts,
                                   now - self.last_attempt_t, _have(_UHUBCTL))
        if action == "none":
            return
        if action == "wait":
            what = "plugged in but not answering" if not dev else "open but silent"
            self.state, self.message = "recovering", "Recovering the RTL-SDR (%s) — %s." % (what, reason)
            return
        if action == "unplugged":
            if seen_stuck:
                self.state = "recovering"
                self.message = ("The RTL-SDR is connected on USB but not answering — confirming "
                                "before power-cycling its port.")
            else:
                self.state, self.message = "unplugged", "No RTL-SDR on any USB port — it looks unplugged."
            return
        if action == "give_up":
            self.state = "failed"
            self.message = ("Ragnar tried to recover the RTL-SDR %d times without success — it needs "
                            "replugging by hand." % self.attempts) + (" " + self._flap_text() if self.drops else "")
            return
        self._act(action, reason, dev, stuck_port, now)

    def _act(self, action, reason, dev, stuck_port, now):
        self.attempts += 1
        self.last_attempt_t = now
        self.state = "recovering"
        target = stuck_port or (("%s:%d" % usb_target(dev)) if dev else None)
        try:
            power_stop()                     # close cleanly before touching the port
        except Exception:
            pass
        try:
            _ism.stop()
        except Exception:
            pass
        ok, detail = False, ""
        if action == "usb_reset":
            r = usb_reset()
            ok, detail = bool(r.get("ok")), r.get("error") or r.get("note", "")
        elif action == "power_cycle" and target:
            hub, _, port = target.partition(":")
            rc, out, err = _run([_UHUBCTL, "-l", hub, "-p", port, "-a", "cycle",
                                 "-d", str(_CYCLE_OFF_S)], timeout=30)
            ok = rc == 0
            detail = "power-cycled USB port %s (%d s off)" % (target, _CYCLE_OFF_S) if ok else (err or out).strip()[-160:]
        elif action == "rebind" and target:
            bus = target.split(":")[0].split("-")[0]
            ctl = _usb_controller(bus)
            ok = False
            if ctl:
                drv = "/sys/bus/platform/drivers/%s" % ctl.rsplit(".", 1)[0]
                try:
                    with open(drv + "/unbind", "w") as fh:
                        fh.write(ctl)
                    time.sleep(2)
                    with open(drv + "/bind", "w") as fh:
                        fh.write(ctl)
                    ok, detail = True, "reset USB controller %s" % ctl
                except OSError as exc:
                    detail = "controller reset failed: %s" % exc
        global _detect_cache
        _detect_cache = None
        # wait for it to come back
        back = None
        for _ in range(25):                  # a flaky dongle can take ~20 s to enumerate
            time.sleep(1.0)
            back = _usb_rtl_devname()
            if back:
                break
        entry = {"ts": now, "action": action, "target": target, "reason": reason,
                 "ok": bool(ok), "back": bool(back), "detail": detail}
        self.history.append(entry)
        del self.history[:-20]
        if back:
            self.port = back
            if ok:
                self.message = "Recovered the RTL-SDR: %s." % detail
            else:
                # the step itself failed, but the dongle re-enumerated anyway —
                # say that, rather than "recovered: ... failed"
                self.message = ("The RTL-SDR is back on USB %s — it re-enumerated by itself while "
                                "Ragnar was recovering it (%s: %s)." % (back, action.replace("_", " "), detail))
            self._resume_sweep()
        else:
            self.message = "Recovery attempt %d (%s) did not bring it back yet — %s." % (
                self.attempts, action.replace("_", " "), detail or reason)
        try:
            _log_watchtower("RF_SDR_SELFHEAL", "info" if back else "warning",
                            "RTL-SDR %s: %s -> %s" % (reason, action, "recovered" if back else "still absent"),
                            {"port": target, "attempt": self.attempts})
        except Exception:
            pass

    def _resume_sweep(self):
        r = self._resume
        if not r:
            return
        self._resume = None
        if _power.status().get("running") or _ism.status().get("running"):
            return
        try:
            if r[1] and r[2]:
                power_start(r[0], lo_hz=r[1], hi_hz=r[2])
            else:
                power_start(r[0])
        except Exception:
            pass

    def _flap_text(self):
        why = "; ".join(self.hints[:3]) if self.hints else "no kernel detail"
        return ("The RTL-SDR dropped off USB %d times in the last 10 minutes (%s). Ragnar recovers it, "
                "but this is a cable, port or dongle fault." % (self.drops, why))

    # -- report ------------------------------------------------------------
    def status(self):
        advice = []
        if self.state in ("flapping", "failed") or (self.drops >= _FLAP_DROPS):
            advice = ["Try a different USB cable — short and data-rated; avoid extension leads.",
                      "Plug the dongle straight into the Pi (not through a hub) and try another port.",
                      "If it drops on every cable and port, the dongle itself may be failing "
                      "(NESDR SMArt dongles run hot — give it air)."]
        if not _have(_UHUBCTL):
            advice.append("Install uhubctl (sudo apt install uhubctl) so Ragnar can power-cycle a "
                          "stuck dongle — without it recovery falls back to resetting the whole USB controller.")
        return {"enabled": self.enabled, "state": self.state, "message": self.message,
                "present": self.present, "port": self.port, "attempts": self.attempts,
                "drops_10min": self.drops, "kernel_hints": list(self.hints),
                "uhubctl": _have(_UHUBCTL), "history": list(self.history[-8:]),
                "advice": advice}


def _log_watchtower(code, severity, msg, extra=None):
    """Append one event to the RF Watchtower feed (best effort)."""
    d = "/var/log/ragnar"
    if not os.path.isdir(d):
        return
    ev = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "module": "rfwatch", "code": code,
          "severity": severity, "msg": msg}
    if extra:
        ev.update(extra)
    with open(os.path.join(d, "rfwatch.jsonl"), "a") as fh:
        fh.write(json.dumps(ev) + "\n")


_healer = SdrHealer()


def start_healer(enabled=True):
    """Start the background self-healer (idempotent)."""
    _healer.enabled = bool(enabled)
    _healer.start()
    return _healer.status()


def heal_status():
    return _healer.status()


def heal_now():
    """Run the recovery ladder once, immediately, ignoring the backoff."""
    _healer.last_attempt_t = 0.0
    if _healer.attempts >= _HEAL_MAX_ATTEMPTS:
        _healer.attempts = _HEAL_MAX_ATTEMPTS - 1     # a person asked: one more go
    _healer._stuck_prev = None
    _healer._dmesg_t = 0.0
    _healer.tick(confirm=False)       # a person asked: one observation is enough
    return _healer.status()


def set_heal_enabled(on):
    _healer.enabled = bool(on)
    return _healer.status()


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


# A recording that does not say where and when it was made is an anecdote. This
# module owns no GPS, so the app registers a provider and every capture written
# here carries the fix if there is one.
_pos_provider = None


def set_position_provider(fn):
    """Register a callable returning {'lat','lon',...} (or None) for captures."""
    global _pos_provider
    _pos_provider = fn if callable(fn) else None


def current_position():
    """This unit's position for a capture, or None. Never raises."""
    try:
        if _pos_provider is None:
            return None
        p = _pos_provider()
        if not p or p.get("lat") is None or p.get("lon") is None:
            return None
        out = {"lat": float(p["lat"]), "lon": float(p["lon"]),
               "source": p.get("source") or "gps"}
        for k in ("alt", "satellites", "hdop", "fix"):
            if p.get(k) is not None:
                out[k] = p[k]
        return out
    except Exception:
        return None


def geojson_point(pos):
    """SigMF core:geolocation for a position dict (pure), or None.

    SigMF carries geolocation as a GeoJSON Point, coordinates [lon, lat, alt] —
    longitude FIRST, which is the opposite order to how everyone says it.
    """
    if not pos:
        return None
    try:
        lon, lat = float(pos["lon"]), float(pos["lat"])
    except (KeyError, TypeError, ValueError):
        return None
    coords = [lon, lat]
    if pos.get("alt") is not None:
        try:
            coords.append(float(pos["alt"]))
        except (TypeError, ValueError):
            pass
    return {"type": "Point", "coordinates": coords}


def sigmf_meta(center_hz, sr_hz, datatype="cu8", hw="RTL-SDR",
               sha512=None, dt_iso=None, label=None, ppm=0, gain=None,
               position=None, detector=None):
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
    geo = geojson_point(position)
    if geo:
        glob["core:geolocation"] = geo
        # Where the fix came from matters: a live GPS fix and a position typed in
        # last week are not the same evidence.
        glob["ragnar:position_source"] = position.get("source", "gps")
        for k in ("satellites", "hdop"):
            if position.get(k) is not None:
                glob["ragnar:gps_" + k] = position[k]
    if detector:
        glob["ragnar:detector"] = str(detector)
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
        hw = center_hz + _conv_hz
        if not _hw_range_ok(hw - sr_hz // 2, hw + sr_hz // 2) and not (24_000_000 <= hw <= 1_766_000_000):
            return {"ok": False, "error": "center frequency out of RTL-SDR reach (24-1766 MHz, or HF with direct sampling)"}
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

    def _pump(self, nsamp):
        """Copy the capture to disk, and FFT some of it for the live waterfall.

        Writing the file always wins: rows are only computed when there is time
        (at most _IQ_DISPLAY_HZ per second), so the recording can never be
        starved or dropped for the sake of the display.
        """
        want = nsamp * 2                                   # cu8: 2 bytes per sample
        lo_hz, hi_hz = self._center - self._sr // 2, self._center + self._sr // 2
        np = None
        try:
            import numpy as _np
            np = _np
        except Exception:
            np = None
        N = _fft or 1024
        win = _fft_window(N) if np is not None else None
        win_norm = float(np.sum(win ** 2)) * N if np is not None else 1.0
        chunk = max(N * 2, int(self._sr / _IQ_DISPLAY_HZ)) * 2
        chunk -= chunk % (N * 2)
        got, last_row = 0, 0.0
        if np is not None:
            _power.begin_external(lo_hz - _conv_hz, hi_hz - _conv_hz)   # report RF, not hardware
        try:
            with open(self._path, "wb", buffering=1 << 18) as fh:
                pipe = self._proc.stdout
                while got < want and not self._stop.is_set():
                    buf = pipe.read(min(chunk, want - got))
                    if not buf:
                        break
                    fh.write(buf)                          # the file first, always
                    got += len(buf)
                    now = time.time()
                    if np is None or (now - last_row) < 1.0 / _IQ_DISPLAY_HZ or len(buf) < N * 2:
                        continue
                    last_row = now
                    raw = (np.frombuffer(buf[:(len(buf) // (N * 2)) * N * 2], dtype=np.uint8)
                           .astype(np.float32) - 127.5) / 127.5
                    nwin = min((raw.shape[0] // 2) // N, _avg)
                    if nwin <= 0:
                        continue
                    iq = raw[:nwin * N * 2].reshape(nwin, N, 2)
                    spec = np.fft.fftshift(np.fft.fft((iq[:, :, 0] + 1j * iq[:, :, 1]) * win, axis=1), axes=1)
                    psd = (spec.real ** 2 + spec.imag ** 2).mean(axis=0) / win_norm
                    db = 10.0 * np.log10(psd + 1e-12)
                    _power.feed_external(_iq_to_grid(db.tolist(), self._center, self._sr,
                                                     lo_hz, hi_hz, bins=_bins))
        finally:
            if np is not None:
                _power.end_external()

    def _run_loop(self):
        nsamp = int(self._sr * self._seconds)
        hw = self._center + _conv_hz              # tune the radio; SigMF keeps the RF frequency
        cmd = [_RTL_SDR, "-f", str(hw), "-s", str(self._sr), "-n", str(nsamp)]
        if _ppm:
            cmd += ["-p", str(_ppm)]
        if _gain is not None:
            cmd += ["-g", str(_gain)]
        if _direct_on(hw - self._sr // 2, hw + self._sr // 2):
            cmd += ["-D"]
        _set_biast(_bias_t)
        _usb_settle(self._stop)
        cmd += ["-"]                              # stream to us: file + live waterfall
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, bufsize=0)
        except Exception as exc:
            self._error = "failed to launch rtl_sdr: %s" % exc
            return
        err = b""
        serr = _drain(_text_lines(self._proc.stderr), self)
        try:
            self._pump(nsamp)
        except Exception as exc:  # pragma: no cover - defensive
            self._error = self._error or str(exc)
        finally:
            serr.join(timeout=1)
            err = (self._stderr_tail or "").encode()
            _terminate(self._proc)
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
                              label=self._label, ppm=_ppm, gain=_gain,
                              position=current_position(), detector=_detector)
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


def iq_capture_rename(name, new):
    """Rename a SigMF capture (both sidecars). Sanitises the new name; refuses to
    clobber an existing capture."""
    old = _rec_safe(name)
    dst = _rec_safe(new)
    if not dst:
        return {"ok": False, "error": "invalid new name"}
    if dst == old:
        return {"ok": True, "name": dst}
    d = _iq_cap_dir()
    src_data = os.path.join(d, old + ".sigmf-data")
    if not os.path.exists(src_data):
        return {"ok": False, "error": "capture not found"}
    if os.path.exists(os.path.join(d, dst + ".sigmf-data")):
        return {"ok": False, "error": "a capture named '%s' already exists" % dst}
    try:
        for suffix in (".sigmf-data", ".sigmf-meta"):
            s = os.path.join(d, old + suffix)
            if os.path.exists(s):
                os.rename(s, os.path.join(d, dst + suffix))
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "name": dst}


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



# --------------------------------------------------------------------------
# Frequency-mask trigger with pre-trigger capture
# --------------------------------------------------------------------------
#
# Free-running recording is a bet: press record and hope the burst happens while
# the file is open. A real-time analyser instead *arms* a condition and keeps a
# rolling buffer of raw samples, so when the condition fires the recording starts
# BEFORE the event — the part that is normally missed, and the part a decoder
# needs (preamble, rise time, the first bit).
#
# Here the condition is a frequency mask: a level, or a per-column limit line,
# inside a frequency window. It is evaluated on the same waterfall row the page
# draws, so what arms the trigger is exactly what you see.

_TRIG_PRE_MAX_S = 5.0        # cap the rolling buffer (2 MS/s cu8 = 4 MB/s)
_TRIG_POST_MAX_S = 30.0


def mask_cross(grid, mask, lo_hz, hi_hz, f0_hz=None, f1_hz=None, margin_db=0.0):
    """Find where a waterfall row crosses its mask (pure).

    ``mask`` is either a single level in dB or a per-column limit line (any
    length — it is stretched onto the row). ``f0_hz``/``f1_hz`` narrow the test
    to a frequency window, so a trigger can watch one channel and ignore the
    rest of the span. Returns the strongest crossing as a dict, or None.
    """
    n = len(grid or ())
    if not n or hi_hz <= lo_hz:
        return None
    span = hi_hz - lo_hz
    c0, c1 = 0, n - 1
    if f0_hz is not None:
        c0 = max(0, int((f0_hz - lo_hz) / span * n))
    if f1_hz is not None:
        c1 = min(n - 1, int((f1_hz - lo_hz) / span * n))
    if c1 < c0:
        return None
    flat = not isinstance(mask, (list, tuple))
    m = len(mask) if not flat else 0
    best = None
    for c in range(c0, c1 + 1):
        lim = (float(mask) if flat
               else float(mask[min(m - 1, int(c * m / float(n)))]))
        lim += margin_db
        v = grid[c]
        if v is None or v <= lim:
            continue
        exc = v - lim
        if best is None or exc > best["excess_db"]:
            best = {"col": c, "freq_hz": lo_hz + (c + 0.5) * span / n,
                    "level_db": round(v, 1), "limit_db": round(lim, 1),
                    "excess_db": round(exc, 1)}
    return best


class SignalTrigger:
    """Watch live rows for a mask crossing and write a SigMF capture around it.

    Fed from the IQ engine's loop: every block of raw samples goes into a rolling
    pre-trigger buffer, and every waterfall row is tested against the mask. On a
    crossing the buffer is flushed to a new capture and recording continues for
    ``post_s``, so the file contains the event *and* the moment before it.

    Never blocks the capture loop: writes are plain file writes on the same
    thread, and the buffer is bounded in bytes rather than in blocks.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        self._armed = False
        self._cfg = {}
        self._pre = []             # [(ts, bytes)] most recent last
        self._pre_bytes = 0
        self._rec = None           # {"fh","path","name","bytes","want","ts","hit"}
        self._events = []
        self._last_fire = 0.0
        self._error = None

    # -- control -----------------------------------------------------------
    def arm(self, mask=None, level_db=None, f0_hz=None, f1_hz=None, pre_s=1.0,
            post_s=2.0, max_events=10, min_gap_s=3.0, margin_db=0.0, name=None):
        """Arm the trigger. ``mask`` (a limit line) wins over a flat ``level_db``."""
        if mask is None and level_db is None:
            return {"ok": False, "error": "give a mask or a level to trigger on"}
        try:
            pre_s = max(0.0, min(_TRIG_PRE_MAX_S, float(pre_s or 0)))
            post_s = max(0.1, min(_TRIG_POST_MAX_S, float(post_s or 2.0)))
            max_events = max(1, min(500, int(max_events or 10)))
            min_gap_s = max(0.0, min(3600.0, float(min_gap_s or 0)))
            margin_db = float(margin_db or 0.0)
            if mask is not None:
                mask = [float(v) for v in mask]
                if not mask:
                    return {"ok": False, "error": "empty mask"}
            else:
                mask = float(level_db)
            f0_hz = int(f0_hz) if f0_hz not in (None, "") else None
            f1_hz = int(f1_hz) if f1_hz not in (None, "") else None
        except (TypeError, ValueError) as exc:
            return {"ok": False, "error": "bad trigger settings: %s" % exc}
        with self._lock:
            self._close_locked(abort=True)
            self.reset()
            self._cfg = {"mask": mask, "f0_hz": f0_hz, "f1_hz": f1_hz,
                         "pre_s": pre_s, "post_s": post_s, "margin_db": margin_db,
                         "max_events": max_events, "min_gap_s": min_gap_s,
                         "name": _rec_safe(name or "trig"),
                         "flat": not isinstance(mask, list)}
            self._armed = True
        return self.status()

    def disarm(self):
        with self._lock:
            self._close_locked(abort=True)
            self._armed = False
            self._pre, self._pre_bytes = [], 0
        return self.status()

    def status(self):
        with self._lock:
            c = dict(self._cfg)
            c.pop("mask", None)
            return {"armed": self._armed, "recording": bool(self._rec),
                    "config": c, "events": list(self._events),
                    "pre_buffered_s": round(self._pre_span(), 2),
                    "count": len(self._events), "error": self._error}

    # -- feed from the capture loop ---------------------------------------
    def _pre_span(self):
        if len(self._pre) < 2:
            return 0.0
        return max(0.0, self._pre[-1][0] - self._pre[0][0])

    def feed(self, buf, grid, lo_hz, hi_hz, center_hz, sr_hz, ts=None):
        """One block of raw samples + the row computed from it. Cheap when idle."""
        if not self._armed and not self._rec:
            return
        ts = ts or time.time()
        with self._lock:
            if not self._armed and not self._rec:
                return
            if self._rec:
                self._write_locked(buf)
                return
            # keep the rolling pre-trigger buffer bounded in BYTES, not blocks,
            # so a sample-rate change can't blow memory up
            keep = int(self._cfg["pre_s"] * sr_hz * 2)
            if keep > 0:
                self._pre.append((ts, buf))
                self._pre_bytes += len(buf)
                while self._pre and self._pre_bytes - len(self._pre[0][1]) >= keep:
                    self._pre_bytes -= len(self._pre.pop(0)[1])
            else:
                self._pre, self._pre_bytes = [], 0
            if ts - self._last_fire < self._cfg["min_gap_s"]:
                return
            hit = mask_cross(grid, self._cfg["mask"], lo_hz, hi_hz,
                             self._cfg["f0_hz"], self._cfg["f1_hz"],
                             self._cfg["margin_db"])
            if hit:
                self._fire_locked(hit, center_hz, sr_hz, ts)

    def _fire_locked(self, hit, center_hz, sr_hz, ts):
        name = "%s-%s" % (self._cfg["name"], time.strftime("%Y%m%d-%H%M%S",
                                                           time.localtime(ts)))
        path = os.path.join(_iq_cap_dir(), name + ".sigmf-data")
        try:
            os.makedirs(_iq_cap_dir(), exist_ok=True)
            fh = open(path, "wb", buffering=1 << 18)
        except OSError as exc:
            self._error = "could not open %s: %s" % (path, exc)
            self._armed = False
            return
        pre_bytes = sum(len(b) for _, b in self._pre)
        want = pre_bytes + int(self._cfg["post_s"] * sr_hz * 2)
        self._rec = {"fh": fh, "path": path, "name": name, "bytes": 0,
                     "want": want, "pre_bytes": pre_bytes, "sr": sr_hz,
                     "center": center_hz, "ts": ts, "hit": hit}
        self._last_fire = ts
        for _, b in self._pre:                       # the moment before the event
            self._write_locked(b)
        self._pre, self._pre_bytes = [], 0

    def _write_locked(self, buf):
        r = self._rec
        if not r:
            return
        try:
            r["fh"].write(buf)
        except OSError as exc:
            self._error = str(exc)
            self._close_locked(abort=True)
            return
        r["bytes"] += len(buf)
        if r["bytes"] >= r["want"]:
            self._close_locked()

    def _close_locked(self, abort=False):
        r = self._rec
        self._rec = None
        if not r:
            return
        try:
            r["fh"].close()
        except OSError:
            pass
        if abort and r["bytes"] < r["pre_bytes"]:
            try:
                os.unlink(r["path"])
            except OSError:
                pass
            return
        ev = {"name": r["name"], "ts": r["ts"], "freq_hz": round(r["hit"]["freq_hz"]),
              "level_db": r["hit"]["level_db"], "limit_db": r["hit"]["limit_db"],
              "excess_db": r["hit"]["excess_db"], "seconds": round(r["bytes"] / (2.0 * r["sr"]), 3),
              "pre_s": round(r["pre_bytes"] / (2.0 * r["sr"]), 3),
              "bytes": r["bytes"], "center_hz": r["center"], "sr_hz": r["sr"]}
        try:
            import hashlib
            h = hashlib.sha512()
            with open(r["path"], "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            meta = sigmf_meta(r["center"], r["sr"], sha512=h.hexdigest(),
                              hw="RTL-SDR (%s)" % _capture_hw_name(),
                              dt_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["ts"])),
                              label="trigger %.4f MHz %+0.1f dB over the mask" % (
                                  r["hit"]["freq_hz"] / 1e6, r["hit"]["excess_db"]),
                              ppm=_ppm, gain=_gain,
                              position=current_position(), detector=_detector)
            # Mark where the trigger actually fired, so the analyzer can show the
            # pre-trigger lead-in as lead-in rather than as part of the event.
            meta["annotations"].append({
                "core:sample_start": int(r["pre_bytes"] / 2),
                "core:label": "trigger point",
                "core:freq_lower_edge": float(r["hit"]["freq_hz"]) - 5000.0,
                "core:freq_upper_edge": float(r["hit"]["freq_hz"]) + 5000.0})
            with open(r["path"][:-len(".sigmf-data")] + ".sigmf-meta", "w") as fh:
                json.dump(meta, fh, indent=2)
        except OSError as exc:
            self._error = "capture saved but metadata write failed: %s" % exc
        self._events.append(ev)
        self._write_wt(ev)
        if len(self._events) >= self._cfg.get("max_events", 10):
            self._armed = False

    def _write_wt(self, ev):
        """Log the event to the Watchtower feed, like the other RF alerts."""
        try:
            line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ev["ts"])),
                    "module": "rfwatch", "code": "RF_TRIGGER_CAPTURE",
                    "severity": "info",
                    "msg": "mask trigger at %.4f MHz (%+0.1f dB over the mask) -> %s"
                           % (ev["freq_hz"] / 1e6, ev["excess_db"], ev["name"]),
                    "freq_mhz": round(ev["freq_hz"] / 1e6, 4),
                    "capture": ev["name"], "seconds": ev["seconds"]}
            d = "/var/log/ragnar"
            if os.path.isdir(d):
                with open(os.path.join(d, "rfwatch.jsonl"), "a") as fh:
                    fh.write(json.dumps(line) + "\n")
        except Exception:
            pass


_trigger = SignalTrigger()


def trigger_arm(**kw):
    """Arm the frequency-mask trigger (see :meth:`SignalTrigger.arm`)."""
    return _trigger.arm(**kw)


def trigger_disarm():
    return _trigger.disarm()


def trigger_status():
    return _trigger.status()


def _sigmf_hash_ok(path, meta):
    """True when a capture's bytes still match the core:sha512 in its sidecar."""
    want = (meta.get("global") or {}).get("core:sha512")
    if not want:
        return False
    import hashlib
    h = hashlib.sha512()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest() == want


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


# --------------------------------------------------------------------------
# Unattended spectrum survey — visit a list of bands for a dwell time each
# (one round, or continuously), and write a report: per band the noise floor
# and overall occupancy, and every emitter found (frequency, bandwidth, peak,
# how much of the time it was on, first / last seen). The sweep runs through
# the normal PowerSweep, so the RF Waterfall page shows what's being surveyed.
# --------------------------------------------------------------------------

def survey_stats(frames, lo_hz, hi_hz, thr_db=10.0, occ_min=0.05, t0=None, t1=None):
    """Summarise one band's frames (pure; selftested).

    ``frames``: list of power rows (dB, same width) or dicts with ``power`` + ``ts``.
    A bin is *busy* in a row when it's ``thr_db`` over that row's noise floor
    (30th percentile). Contiguous bins busy in >= ``occ_min`` of the rows form an
    emitter. Returns the band summary + emitters sorted by frequency.
    """
    rows, ts = [], []
    for f in frames or []:
        p = f.get("power") if isinstance(f, dict) else f
        if p:
            rows.append(p)
            ts.append(f.get("ts") if isinstance(f, dict) else None)
    if not rows:
        return {"rows": 0, "emitters": [], "occupancy_pct": 0.0, "noise_db": None}
    n = min(len(r) for r in rows)
    busy = [0] * n
    peak = [-1e9] * n
    first = [None] * n
    last = [None] * n
    floors = []
    for k, r in enumerate(rows):
        srt = sorted(r[:n])
        nf = srt[int(n * 0.30)]
        floors.append(nf)
        for i in range(n):
            v = r[i]
            if v > peak[i]:
                peak[i] = v
            if v >= nf + thr_db:
                busy[i] += 1
                t = ts[k]
                if t is not None:
                    if first[i] is None:
                        first[i] = t
                    last[i] = t
    R = float(len(rows))
    occ = [b / R for b in busy]
    binw = (hi_hz - lo_hz) / float(n)
    emitters = []
    i = 0
    while i < n:
        if occ[i] >= occ_min:
            j = i
            while j + 1 < n and occ[j + 1] >= occ_min:
                j += 1
            pk = max(range(i, j + 1), key=lambda q: peak[q])
            fs = [first[q] for q in range(i, j + 1) if first[q] is not None]
            ls = [last[q] for q in range(i, j + 1) if last[q] is not None]
            emitters.append({"freq_mhz": round((lo_hz + (pk + 0.5) * binw) / 1e6, 4),
                             "bw_khz": round((j - i + 1) * binw / 1e3, 1),
                             "peak_db": round(peak[pk], 1),
                             "occupancy_pct": round(100.0 * max(occ[q] for q in range(i, j + 1)), 1),
                             "first_seen": min(fs) if fs else None, "last_seen": max(ls) if ls else None})
            i = j + 1
        else:
            i += 1
    floors.sort()
    return {"rows": len(rows), "bins": n, "noise_db": round(floors[len(floors) // 2], 1),
            "occupancy_pct": round(100.0 * sum(1 for o in occ if o >= occ_min) / n, 1),
            "emitters": emitters, "t0": t0, "t1": t1,
            "lo_mhz": round(lo_hz / 1e6, 4), "hi_mhz": round(hi_hz / 1e6, 4)}


def _survey_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "rf_surveys")


class SpectrumSurvey:
    MAX_DWELL_S = 3600

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop = threading.Event()
        self._state = "idle"
        self._plan = None
        self._cur = None
        self._round = 0
        self._report = None
        self._name = None
        self._error = None

    def start(self, bands, dwell_s=30, rounds=1, label=None):
        bl = []
        for b in bands or []:
            if isinstance(b, dict):
                try:
                    lo, hi = int(float(b["lo_hz"])), int(float(b["hi_hz"]))
                except (KeyError, TypeError, ValueError):
                    continue
                if hi - lo >= 100_000:
                    bl.append({"id": str(b.get("label") or "%.3f-%.3f" % (lo / 1e6, hi / 1e6))[:40], "lo_hz": lo, "hi_hz": hi})
            elif str(b) in RTL_BANDS:
                lo, hi = RTL_BANDS[str(b)]
                bl.append({"id": str(b), "lo_hz": lo, "hi_hz": hi})
        if not bl:
            return {"ok": False, "error": "no valid bands"}
        try:
            dwell_s = max(5, min(self.MAX_DWELL_S, int(float(dwell_s))))
            rounds = max(0, min(1000, int(float(rounds))))
        except (TypeError, ValueError):
            return {"ok": False, "error": "dwell / rounds must be numbers"}
        with self._lock:
            if self._thread and self._thread.is_alive():
                return {"ok": False, "error": "a survey is already running"}
            self._stop = threading.Event()
            self._plan = {"bands": bl, "dwell_s": dwell_s, "rounds": rounds}
            self._name = _rec_safe(label) or time.strftime("survey-%Y%m%d-%H%M%S")
            self._report = {"name": self._name, "started": time.time(), "finished": None,
                            "dwell_s": dwell_s, "rounds_planned": rounds, "bands": [], "status": "running",
                            "device": (_detect_cache or {}).get("model_name") if isinstance(_detect_cache, dict) else None}
            self._state, self._round, self._error = "running", 0, None
            self._thread = threading.Thread(target=self._run, daemon=True, name="rf-survey")
            self._thread.start()
        return {"ok": True, "name": self._name, "bands": [b["id"] for b in bl], "dwell_s": dwell_s, "rounds": rounds}

    def stop(self):
        self._stop.set()
        return {"ok": True}

    def _run(self):
        plan, stop = self._plan, self._stop
        try:
            while not stop.is_set():
                self._round += 1
                for b in plan["bands"]:
                    if stop.is_set():
                        break
                    self._cur = {"band": b["id"], "since": time.time()}
                    r = power_start(b["id"] if b["id"] in RTL_BANDS else "433",
                                    lo_hz=None if b["id"] in RTL_BANDS else b["lo_hz"],
                                    hi_hz=None if b["id"] in RTL_BANDS else b["hi_hz"], label="survey")
                    if not r.get("ok"):
                        self._error = r.get("error", "sweep failed")
                        stop.set()
                        break
                    t0, seq, frames = time.time(), 0, []
                    while not stop.is_set() and time.time() - t0 < plan["dwell_s"]:
                        stop.wait(0.5)
                        fr = power_frames(since=seq)
                        for f in fr.get("frames", []):
                            seq = max(seq, f["seq"])
                            frames.append({"power": f["power"], "ts": f.get("ts")})
                        if len(frames) > 20000:
                            frames = frames[-20000:]
                    stats = survey_stats(frames, b["lo_hz"], b["hi_hz"], t0=t0, t1=time.time())
                    stats.update({"band": b["id"], "round": self._round, "engine": fr.get("engine") if frames else None,
                                  "rbw_hz": fr.get("rbw_hz") if frames else None})
                    with self._lock:
                        self._report["bands"].append(stats)
                    self._save()
                if plan["rounds"] and self._round >= plan["rounds"]:
                    break
        except Exception as exc:  # pragma: no cover - defensive
            self._error = str(exc)
        finally:
            self._cur = None
            try:
                power_stop()
            except Exception:
                pass
            with self._lock:
                self._report["finished"] = time.time()
                self._report["status"] = "error" if self._error else ("stopped" if stop.is_set() else "done")
                if self._error:
                    self._report["error"] = self._error
                self._state = "idle"
            self._save()

    def _save(self):
        try:
            os.makedirs(_survey_dir(), exist_ok=True)
            with self._lock:
                rep = json.dumps(self._report)
            with open(os.path.join(_survey_dir(), self._name + ".json"), "w") as fh:
                fh.write(rep)
        except OSError:
            pass

    def status(self):
        with self._lock:
            cur = dict(self._cur) if self._cur else None
            plan = self._plan or {}
            done = len(self._report["bands"]) if self._report else 0
        if cur:
            cur["elapsed_s"] = round(time.time() - cur["since"], 1)
        return {"state": self._state, "name": self._name, "current": cur, "round": self._round,
                "bands_done": done, "plan": {"bands": [b["id"] for b in plan.get("bands", [])],
                                             "dwell_s": plan.get("dwell_s"), "rounds": plan.get("rounds")},
                "error": self._error}


_survey = SpectrumSurvey()


def survey_list():
    import glob
    out = []
    for path in sorted(glob.glob(os.path.join(_survey_dir(), "*.json")), reverse=True):
        try:
            with open(path) as fh:
                r = json.load(fh)
            out.append({"name": r.get("name"), "started": r.get("started"), "finished": r.get("finished"),
                        "status": r.get("status"), "bands": len(r.get("bands", [])),
                        "emitters": sum(len(b.get("emitters", [])) for b in r.get("bands", []))})
        except (OSError, ValueError):
            continue
    return {"surveys": out[:100]}


def survey_report(name):
    path = os.path.join(_survey_dir(), _rec_safe(name) + ".json")
    try:
        with open(path) as fh:
            return {"ok": True, "report": json.load(fh)}
    except (OSError, ValueError):
        return {"ok": False, "error": "no such survey"}


def survey_csv(name):
    """Emitters of a survey report as CSV text (pure over the saved report)."""
    r = survey_report(name)
    if not r.get("ok"):
        return None
    lines = ["band,round,freq_mhz,bw_khz,peak_db,occupancy_pct,first_seen_utc,last_seen_utc"]
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else ""
    for b in r["report"].get("bands", []):
        for e in b.get("emitters", []):
            lines.append("%s,%s,%.4f,%.1f,%.1f,%.1f,%s,%s" % (b.get("band"), b.get("round"), e["freq_mhz"], e["bw_khz"],
                                                           e["peak_db"], e["occupancy_pct"], iso(e.get("first_seen")), iso(e.get("last_seen"))))
    return "\n".join(lines) + "\n"


def survey_delete(name):
    path = os.path.join(_survey_dir(), _rec_safe(name) + ".json")
    try:
        os.remove(path)
        return {"ok": True}
    except OSError:
        return {"ok": False, "error": "no such survey"}

# --------------------------------------------------------------------------
# Mesh direction finding (RSSI). Every Ragnar with an RTL-SDR can report the
# level of a signal at a frequency, with its position; the unit that asked
# combines them into a location estimate. RSSI ranging is coarse — antenna,
# cable and gain differences between units and multipath all bias it — so the
# result carries an uncertainty radius and the geometry that produced it.
# --------------------------------------------------------------------------

def level_from_frames(frames, lo_hz, hi_hz, f_hz, bw_hz=25_000):
    """Signal level + noise at ``f_hz`` over a set of rows (pure; selftested).

    Per row: the peak within +/- bw/2 of f, and the row's noise floor (30th
    percentile). Returns medians so a single burst or dropout doesn't skew it."""
    peaks, floors = [], []
    for fr in frames or []:
        p = fr.get("power") if isinstance(fr, dict) else fr
        if not p:
            continue
        n = len(p)
        binw = (hi_hz - lo_hz) / float(n)
        i0 = int((f_hz - bw_hz / 2.0 - lo_hz) / binw)
        i1 = int((f_hz + bw_hz / 2.0 - lo_hz) / binw)
        i0, i1 = max(0, i0), min(n - 1, max(i1, i0))
        if i0 >= n or i1 < 0:
            continue
        peaks.append(max(p[i0:i1 + 1]))
        floors.append(sorted(p)[int(n * 0.30)])
    if not peaks:
        return None
    peaks.sort(); floors.sort()
    lv, nf = peaks[len(peaks) // 2], floors[len(floors) // 2]
    return {"level_db": round(lv, 1), "noise_db": round(nf, 1), "snr_db": round(lv - nf, 1), "rows": len(peaks)}


def measure_level(freq_hz, bw_hz=25_000, secs=2.0):
    """Measure the level at freq_hz on this unit's RTL-SDR.

    Uses the running sweep if it already covers the frequency (non-intrusive).
    Otherwise, if the dongle is idle, runs a short 1 MHz real-time capture around
    it and stops again. If the dongle is busy with something else (another
    sweep, a survey, decoding, radio) it reports "busy" rather than hijacking it.
    """
    try:
        f = int(float(freq_hz)); bw = max(1_000, int(float(bw_hz or 25_000)))
        secs = max(0.5, min(10.0, float(secs or 2.0)))
    except (TypeError, ValueError):
        return {"ok": False, "error": "freq_hz / bw_hz / secs must be numbers"}
    st = _power.status()
    band = st.get("band_hz") or [None, None]
    covers = st.get("running") and band[0] and band[0] <= f - bw / 2 and f + bw / 2 <= band[1]
    started = False
    if not covers:
        if st.get("running") or _ism.status().get("running") or _survey.status().get("state") == "running":
            return {"ok": False, "error": "busy — this unit's dongle is in use"}
        r = power_start("433", lo_hz=f - 500_000, hi_hz=f + 500_000, label="df")
        if not r.get("ok"):
            return {"ok": False, "error": r.get("error", "could not start the SDR")}
        started = True
        time.sleep(1.5 + secs)              # let the capture settle, then measure
    try:
        fr = power_frames(since=0)
        now = time.time()
        rows = [x for x in fr.get("frames", []) if (x.get("ts") or 0) >= now - secs]
        lo, hi = (fr.get("band_hz") or [None, None])
        if not rows or not lo:
            return {"ok": False, "error": "no data from the SDR"}
        m = level_from_frames(rows, lo, hi, f, bw)
        if not m:
            return {"ok": False, "error": "frequency outside the capture"}
        m.update({"ok": True, "freq_hz": f, "bw_hz": bw, "engine": fr.get("engine"), "rbw_hz": fr.get("rbw_hz"),
                  "gain": "auto" if _gain is None else _gain, "ts": now, "borrowed": not started})
        return m
    finally:
        if started:
            power_stop()


def image_verdict(peak_a_hz, peak_b_hz, center_a_hz, center_b_hz,
                  tol_hz=8_000, dc_tol_hz=6_000):
    """Decide whether a peak seen at two different tuner centres is real (pure).

    A receiver does not only show what is on the air. A mixer also produces
    *images* — a signal from the other side of the local oscillator folded into
    the passband — and the RTL-SDR has a permanent DC spike at whatever it is
    tuned to. Both look like transmitters, and both will happily be measured,
    named by the band plan and recorded.

    The test: look at the same radio frequency through two different tuner
    centres. A real transmitter does not move — its RF is its RF. An image moves,
    because it is defined by its distance from the LO, not by the air. The DC
    spike does not move relative to the tuner at all, so it sits at the centre of
    both windows.

    ``tol_hz`` is how far the two measurements may disagree and still count as
    the same signal (RBW plus tuner error).
    """
    if peak_a_hz is None or peak_b_hz is None:
        return {"verdict": "absent", "moved_hz": None,
                "detail": "nothing above the noise in one of the two captures"}
    da = abs(peak_a_hz - center_a_hz)
    db = abs(peak_b_hz - center_b_hz)
    moved = abs(peak_a_hz - peak_b_hz)
    if da <= dc_tol_hz and db <= dc_tol_hz:
        return {"verdict": "dc-spike", "moved_hz": round(moved, 1),
                "detail": "the peak stays at the tuner centre in both captures — "
                          "this is the receiver's own DC offset, not a signal"}
    if moved <= tol_hz:
        return {"verdict": "real", "moved_hz": round(moved, 1),
                "detail": "the peak holds the same radio frequency through two "
                          "different tuner centres"}
    return {"verdict": "image", "moved_hz": round(moved, 1),
            "detail": "the peak moved with the tuner — a mixer image or an "
                      "alias, not a transmitter on this frequency"}


def _peek_window(center_hz, f_hz, bw_hz, secs):
    """Tune a short capture around ``center_hz`` and find the peak near ``f_hz``.

    Returns (peak_hz, level_db) or (None, None). Intrusive by design: the caller
    has already established the dongle is free.
    """
    r = power_start("433", lo_hz=center_hz - 500_000, hi_hz=center_hz + 500_000,
                    label="image-check")
    if not r.get("ok"):
        return None, None
    try:
        time.sleep(1.5 + secs)
        fr = power_frames(since=0)
        now = time.time()
        rows = [x for x in fr.get("frames", []) if (x.get("ts") or 0) >= now - secs]
        lo, hi = (fr.get("band_hz") or [None, None])
        if not rows or not lo:
            return None, None
        # average the rows so a single noisy frame can't set the verdict
        n = len(rows[-1]["power"])
        avg = [sum(row["power"][i] for row in rows) / float(len(rows))
               for i in range(n)]
        m = level_from_frames(rows, lo, hi, f_hz, bw_hz)
        pk = _peak_freq_hz(avg, lo, hi, near_hz=f_hz, window_hz=max(bw_hz * 4, 200_000))
        if m and (m.get("snr_db") or 0) < 6:
            return None, None            # nothing convincing in this capture
        return pk, (m or {}).get("level_db")
    finally:
        power_stop()


_HW_TUNE_MIN_HZ = 24_000_000      # RTL-SDR R820T practical tuning range
_HW_TUNE_MAX_HZ = 1_766_000_000


def harmonic_plan(f0_hz, n=4, lo_hz=_HW_TUNE_MIN_HZ, hi_hz=_HW_TUNE_MAX_HZ):
    """Which harmonics of ``f0_hz`` this receiver can actually look at (pure).

    Returns [(n, freq_hz, reachable)] for 2f0..nf0. A harmonic past the tuner's
    range is reported as out of reach rather than silently dropped — "no
    harmonic found" and "could not look" are different answers.
    """
    out = []
    try:
        f0 = float(f0_hz)
    except (TypeError, ValueError):
        return out
    for k in range(2, max(2, int(n or 4)) + 1):
        f = f0 * k
        out.append((k, f, bool(lo_hz <= f <= hi_hz)))
    return out


def harmonics(freq_hz, bw_hz=50_000, n=4, secs=1.2):
    """Measure the harmonics of a carrier, one tune at a time.

    Each harmonic gets its own short capture centred on it, so this is slow and
    intrusive by design — it is a deliberate measurement, not something the
    display does continuously. Levels are reported in dBc: relative to the
    fundamental measured the same way, which cancels most of the tuner's gain.
    """
    try:
        f0 = int(float(freq_hz))
        bw = max(5_000, int(float(bw_hz or 50_000)))
        secs = max(0.5, min(5.0, float(secs or 1.2)))
    except (TypeError, ValueError):
        return {"ok": False, "error": "freq_hz must be a number"}
    if (_ism.status().get("running")
            or _survey.status().get("state") == "running"):
        return {"ok": False, "error": "busy — this unit's dongle is in use"}
    was = _power.status()
    resume = ([was.get("band_hz"), was.get("band")] if was.get("running") else None)
    plan = harmonic_plan(f0, n)
    out, skipped = [], 0
    pk0, lvl0 = _peek_window(f0, f0, bw, secs)
    if lvl0 is None:
        if resume and resume[0]:
            power_start(resume[1] or "433", lo_hz=resume[0][0], hi_hz=resume[0][1])
        return {"ok": False, "error": "could not hear the fundamental — measure it first"}
    for k, f, ok in plan:
        if not ok:
            skipped += 1
            out.append({"n": k, "freq_hz": f, "heard": False,
                        "reason": "outside this receiver's tuning range"})
            continue
        _usb_settle()
        _pk, lvl = _peek_window(int(f), int(f), bw * k, secs)
        if lvl is None:
            out.append({"n": k, "freq_hz": f, "heard": False,
                        "reason": "nothing above the noise"})
        else:
            out.append({"n": k, "freq_hz": f, "heard": True,
                        "level_db": round(lvl, 1), "dbc": round(lvl - lvl0, 1)})
    if resume and resume[0]:
        try:
            power_start(resume[1] or "433", lo_hz=resume[0][0], hi_hz=resume[0][1])
        except Exception:
            pass
    heard = [h for h in out if h.get("heard")]
    note = "%d of %d measured" % (len(heard), len(out))
    if skipped:
        note += ", %d out of tuning range" % skipped
    return {"ok": True, "freq_hz": f0, "fundamental_db": round(lvl0, 1),
            "harmonics": out, "note": note,
            "caveat": "a harmonic can also be made inside the receiver — check "
                      "it is still there with the gain turned down"}


def image_check(freq_hz, bw_hz=50_000, secs=1.5):
    """Prove a peak is a real transmitter and not an image or the DC spike.

    Measures the frequency twice with the tuner deliberately placed on either
    side of it, and compares (see :func:`image_verdict`). Takes a few seconds and
    needs the dongle, so it refuses rather than interrupting other work.
    """
    try:
        f = int(float(freq_hz))
        bw = max(1_000, int(float(bw_hz or 50_000)))
        secs = max(0.5, min(5.0, float(secs or 1.5)))
    except (TypeError, ValueError):
        return {"ok": False, "error": "freq_hz / bw_hz must be numbers"}
    if (_ism.status().get("running")
            or _survey.status().get("state") == "running"):
        return {"ok": False, "error": "busy — this unit's dongle is in use"}
    was = _power.status()
    resume = ([was.get("band_hz"), was.get("band")] if was.get("running") else None)
    # Offset the tuner by a quarter of the capture either way, so the signal sits
    # well clear of DC in both passes and the two LOs are 500 kHz apart.
    off = 250_000
    a_c, b_c = f - off, f + off
    pa, la = _peek_window(a_c, f, bw, secs)
    _usb_settle()
    pb, lb = _peek_window(b_c, f, bw, secs)
    out = image_verdict(pa, pb, a_c, b_c)
    out.update({"ok": True, "freq_hz": f, "bw_hz": bw,
                "peaks_hz": [pa, pb], "levels_db": [la, lb],
                "centers_hz": [a_c, b_c]})
    if resume and resume[0]:
        try:
            power_start(resume[1] or "433", lo_hz=resume[0][0], hi_hz=resume[0][1])
            out["resumed"] = True
        except Exception:
            pass
    return out


def _enu(lat, lon, lat0, lon0):
    """Local east/north metres from a reference point (equirectangular, fine for a few km)."""
    import math
    k = 111_320.0
    return (lon - lon0) * k * math.cos(math.radians(lat0)), (lat - lat0) * k


def df_locate(meas, n=2.5, grid=121):
    """Estimate a transmitter's position from RSSI at several positioned units (pure).

    ``meas``: [{unit, lat, lon, level_db}]. Log-distance model
    level_i = P0 - 10 n log10(d_i): a grid search over the area, with P0 solved in
    closed form at each point. Returns the best-fit position, a 1-sigma radius
    (bootstrapped with ~3 dB of per-unit error), the P0/n
    used and per-unit residuals. With 2 units: a power-weighted point on the
    line between them. With 1: that unit's position (nearest). Never raises."""
    import math
    pts = [m for m in (meas or []) if m.get("lat") is not None and m.get("lon") is not None and m.get("level_db") is not None]
    if not pts:
        return {"ok": False, "error": "no positioned measurements"}
    if len(pts) == 1:
        return {"ok": True, "method": "nearest", "lat": pts[0]["lat"], "lon": pts[0]["lon"], "radius_m": None,
                "note": "only one unit heard it — the transmitter is somewhere around it"}
    lat0 = sum(p["lat"] for p in pts) / len(pts); lon0 = sum(p["lon"] for p in pts) / len(pts)
    xy = [_enu(p["lat"], p["lon"], lat0, lon0) for p in pts]
    L = [float(p["level_db"]) for p in pts]
    if len(pts) == 2:
        w = [10 ** (v / 20.0) for v in L]                      # amplitude-weighted towards the louder unit
        x = (xy[0][0] * w[0] + xy[1][0] * w[1]) / (w[0] + w[1]); y = (xy[0][1] * w[0] + xy[1][1] * w[1]) / (w[0] + w[1])
        k = 111_320.0
        return {"ok": True, "method": "two-unit weighted", "lat": lat0 + y / k, "lon": lon0 + x / (k * math.cos(math.radians(lat0))),
                "radius_m": round(math.hypot(xy[0][0] - xy[1][0], xy[0][1] - xy[1][1]) / 2.0),
                "note": "two units only give a rough point on the line between them — add a third for a real fix"}
    xs = [a for a, _ in xy]; ys = [b for _, b in xy]
    ext = max(200.0, max(xs) - min(xs), max(ys) - min(ys))
    box = (min(xs) - ext, max(xs) + ext, min(ys) - ext, max(ys) + ext)

    def _fit(levels, g):
        x0, x1, y0, y1 = box
        best = None
        for gi in range(g):
            gx = x0 + (x1 - x0) * gi / (g - 1.0)
            for gj in range(g):
                gy = y0 + (y1 - y0) * gj / (g - 1.0)
                r = [lv + 10.0 * n * math.log10(max(10.0, math.hypot(gx - ux, gy - uy))) for (ux, uy), lv in zip(xy, levels)]
                p0 = sum(r) / len(r)
                err = sum((q - p0) ** 2 for q in r)
                if best is None or err < best[0]:
                    best = (err, gx, gy, p0)
        return best

    err_b, bx, by, p0 = _fit(L, grid)
    # Uncertainty: a Monte-Carlo bootstrap of THIS estimator — refit with ~3 dB
    # of random per-unit error added, and take the RMS scatter of the fixes.
    # (The misfit surface alone is misleading: with the transmit power unknown
    # it has long flat valleys, so its extent overstates the error ~10x.)
    import random as _rnd
    rng = _rnd.Random(1234)
    sc = []
    for _ in range(24):
        _e, sx, sy, _p = _fit([v + rng.gauss(0.0, 3.0) for v in L], 51)
        sc.append((sx - bx) ** 2 + (sy - by) ** 2)
    sc.sort()
    rad = math.sqrt(sc[int(len(sc) * 0.68)])       # 68th percentile: robust to the odd far fit
    k = 111_320.0
    lat = lat0 + by / k; lon = lon0 + bx / (k * math.cos(math.radians(lat0)))
    res = []
    for (ux, uy), lv, pt in zip(xy, L, pts):
        d = max(10.0, math.hypot(bx - ux, by - uy))
        res.append({"unit": pt.get("unit"), "dist_m": round(d), "residual_db": round(lv - (p0 - 10 * n * math.log10(d)), 1)})
    return {"ok": True, "method": "multilateration", "lat": round(lat, 6), "lon": round(lon, 6),
            "radius_m": round(rad), "p0_db": round(p0, 1), "n": n, "rms_db": round(math.sqrt(err_b / len(pts)), 1),
            "units": res, "note": "RSSI-based: accuracy depends on matched antennas / gains (calibrate units) and multipath"}


# Limit-line / mask alarms from the RF Waterfall page (pass/fail spectrum
# monitoring). The page evaluates each row against the user's limit and posts
# when a violation starts; we log it to the Watchtower feed, rate-limited per
# panel so a wobbling signal can't flood it.
_LIMIT_MIN_GAP_S = 10.0
_limit_last = {}


def limit_alarm(panel, freq_mhz, level, limit, unit="dB", kind="level", span=None, now=None):
    """Record a limit-line violation as a Watchtower event (rate-limited per panel).

    Returns the event dict, or None when rate-limited / invalid."""
    now = time.time() if now is None else now
    try:
        f = float(freq_mhz); lv = float(level); lim = float(limit)
    except (TypeError, ValueError):
        return None
    panel = str(panel or "rf")[:32]
    if now - _limit_last.get(panel, 0) < _LIMIT_MIN_GAP_S:
        return None
    _limit_last[panel] = now
    unit = "dBm" if str(unit).strip() == "dBm" else "dB"
    what = "mask" if kind == "mask" else "limit line"
    ev = {"ts": now, "severity": "high", "code": "RF_LIMIT_EXCEEDED",
          "summary": "%s: %.3f MHz at %.1f %s, %.1f dB over the %s" % (panel, f, lv, unit, lv - lim, what),
          "src": "%.3fMHz" % f, "freq_mhz": round(f, 3), "level": round(lv, 1), "limit": round(lim, 1),
          "unit": unit, "panel": panel}
    if span and len(span) == 2:
        ev["span_mhz"] = [round(float(span[0]), 4), round(float(span[1]), 4)]
    _baseline._write_wt(ev)
    return ev


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
    st["heal"] = heal_status()
    return st


# --------------------------------------------------------------------------
# Self-test (pure parsing / assembly checks — no hardware needed)
# --------------------------------------------------------------------------

def selftest():
    global _no_persist
    _no_persist = True                      # never write the user's settings
    _saved_globals = {k: globals()[k] for k in
                      ("_ppm", "_gain", "_agc", "_fft", "_avg", "_window",
                       "_bins", "_bias_t", "_direct", "_conv_hz", "_detector")}
    try:
        return _selftest_body(_saved_globals)
    finally:
        globals().update(_saved_globals)    # the tests change settings; undo that
        _no_persist = False


def _selftest_body(_saved_globals=None):
    _saved_globals = _saved_globals or {k: globals()[k] for k in
                                        ("_gain", "_agc", "_detector")}
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
    # --- hide the tuner's own centre hump ---
    _n = _iq_plan(868_100_000, 868_300_000, True)
    check("dc: a narrow band is tuned past its edge — the hump is not in it",
          _n[2] is None and _n[0] - (_n[1] / (2 * _IQ_EDGE_MARGIN)) <= 868_100_000
          and _n[0] >= 868_300_000 + _DC_HALF_HZ)
    _w = _iq_plan(433_050_000, 434_790_000, True)
    check("dc: a wide band moves the tuner off 433.92 MHz and notches it there",
          _w[2] == _w[0] and abs(_w[0] - 433_920_000) > 4 * _DC_HALF_HZ
          and _w[1] <= _DC_SR_CAP
          and _w[0] - _w[1] / (2 * _IQ_EDGE_MARGIN) <= 433_050_000 + 1
          and _w[0] + _w[1] / (2 * _IQ_EDGE_MARGIN) >= 434_790_000 - 1)
    check("dc: off, the plan is unchanged", _iq_plan(433_050_000, 434_790_000)[2] is None
          and _iq_plan(433_050_000, 434_790_000)[0] == 433_920_000)
    _db = [-70.0] * 1024
    for _i in range(500, 525):
        _db[_i] = -55.0
    _db[300] = -30.0                                    # a real signal elsewhere
    _fill_dc(_db, 1_000_000, 1_024_000, 1_000_000 + 0)  # hump at bin 512
    check("dc: the hump is filled from the noise beside it, a real signal kept",
          max(_db[480:545]) < -69.0 and _db[300] == -30.0)
    check("dc: no notch is a no-op", _fill_dc([1.0, 2.0], 0, 1, None) == [1.0, 2.0])

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
    check("iq: tone column strong, rest near floor (peak detector)",
          _iq_to_grid(_psd, _ctr, _sr, _lo, _hi, detector="peak")[_pk] >= -31
          and sum(1 for v in _g if v <= -95) > _POWER_BINS * 0.5)
    check("iq: the shipped RMS detector keeps the tone well clear of the floor",
          _iq_to_grid(_psd, _ctr, _sr, _lo, _hi, detector="rms")[_pk] >= -40,
          "%.1f" % _iq_to_grid(_psd, _ctr, _sr, _lo, _hi, detector="rms")[_pk])
    check("iq: oversampled edge bins fall outside [lo,hi] (dropped)",
          _iq_to_grid([-40.0] * _N, _ctr, _sr, _lo, _hi).count(_FLOOR_DBM) == 0
          and all(v >= -95 for v in _iq_to_grid([-40.0] * _N, _ctr, _sr, _lo, _hi)))

    # --- detectors: same bins, different (and predictable) answers -----------
    _dv = [-100.0, -100.0, -70.0, -100.0]
    check("detector: peak takes the largest bin", _combine_db(_dv, "peak") == -70.0)
    check("detector: min takes the smallest", _combine_db(_dv, "min") == -100.0)
    check("detector: avg is the mean in dB",
          abs(_combine_db(_dv, "avg") - (-92.5)) < 1e-6)
    # rms averages power: one bin 30 dB up over four -> 10*log10((3*1e-10+1e-7)/4)
    _rms = _combine_db(_dv, "rms")
    check("detector: rms averages in the power domain, above avg and below peak",
          -76.5 < _rms < -75.5 and _rms > _combine_db(_dv, "avg") and _rms < -70.0,
          "%.2f" % _rms)
    check("detector: rms >= avg for any spread (Jensen)",
          all(_combine_db(v, "rms") >= _combine_db(v, "avg") - 1e-9
              for v in ([-90, -80, -70], [-100] * 5, [-50, -95])))
    check("detector: unknown name falls back to peak",
          _combine_db(_dv, "nonsense") == -70.0 and _combine_db([], "rms") is None)
    # ... and through the real binning path: a noisy floor reads high on peak
    _noise = [(-100.0 + (i * 37 % 11)) for i in range(_N)]
    _gp = _iq_to_grid(_noise, _ctr, _sr, _lo, _hi, detector="peak")
    _gr = _iq_to_grid(_noise, _ctr, _sr, _lo, _hi, detector="rms")
    _gm = _iq_to_grid(_noise, _ctr, _sr, _lo, _hi, detector="min")
    _mid = _POWER_BINS // 2
    check("detector: on noise, peak reads above rms reads above min",
          _gp[_mid] > _gr[_mid] > _gm[_mid],
          "peak %.1f rms %.1f min %.1f" % (_gp[_mid], _gr[_mid], _gm[_mid]))
    _tone = dict((_d, max(_iq_to_grid(_psd, _ctr, _sr, _lo, _hi, detector=_d)))
                 for _d in _DETECTORS)
    check("detector: peak and rms both hold a tone that shares its column",
          _tone["peak"] >= -30.1 and _tone["rms"] > -40.0,
          "peak %.1f rms %.1f" % (_tone["peak"], _tone["rms"]))
    check("detector: the ordering peak >= rms >= avg >= min always holds",
          _tone["peak"] >= _tone["rms"] >= _tone["avg"] >= _tone["min"],
          str({_k: round(_v, 1) for _k, _v in _tone.items()}))
    check("detector: min is a floor detector — it drops a narrow tone on purpose",
          _tone["min"] <= -95.0, "%.1f" % _tone["min"])
    check("detector: setting round-trips and is part of the restart signature",
          set_tuning(detector="rms")["detector"] == "rms"
          and _settings_sig()[-1] == "rms"
          and set_tuning(detector="bogus")["detector"] == "rms"
          and set_tuning(detector="peak")["detector"] == "peak")

    # --- frequency-mask trigger ---------------------------------------------
    _row = [-100.0] * 100
    _row[40] = -50.0
    check("mask: a flat level is crossed where the signal is",
          mask_cross(_row, -70.0, 433_000_000, 434_000_000)["col"] == 40)
    check("mask: a quiet row does not fire",
          mask_cross([-100.0] * 100, -70.0, 433_000_000, 434_000_000) is None)
    check("mask: the frequency window is respected",
          mask_cross(_row, -70.0, 433_000_000, 434_000_000,
                     f0_hz=433_600_000, f1_hz=433_900_000) is None
          and mask_cross(_row, -70.0, 433_000_000, 434_000_000,
                         f0_hz=433_300_000, f1_hz=433_600_000) is not None)
    check("mask: a per-column mask is stretched onto the row",
          mask_cross(_row, [-40.0] * 10, 433_000_000, 434_000_000) is None
          and mask_cross(_row, [-40.0] * 4 + [-60.0] * 6,
                         433_000_000, 434_000_000)["excess_db"] == 10.0)
    check("mask: margin raises the whole mask",
          mask_cross(_row, -70.0, 433_000_000, 434_000_000, margin_db=30.0) is None)
    check("mask: the crossing reports the right frequency",
          abs(mask_cross(_row, -70.0, 433_000_000, 434_000_000)["freq_hz"]
              - 433_405_000) < 6000)
    check("mask: bad input returns nothing rather than raising",
          mask_cross([], -70.0, 1, 0) is None and mask_cross(None, -70.0, 0, 1) is None)

    # end-to-end: pre-trigger buffer, file, sidecar and trigger-point annotation
    _sr = 100_000                       # cu8 at 100 kS/s = 200 kB of file per second
    _blk = b"\x7f" * _sr                # one block = 0.5 s of samples
    _tg = SignalTrigger()
    _tga = _tg.arm(level_db=-70.0, pre_s=1.0, post_s=1.0, min_gap_s=0,
                   max_events=1, name="selftest")
    check("trigger: arms and reports its settings",
          _tga["armed"] and _tga["config"]["pre_s"] == 1.0)
    check("trigger: refuses to arm with nothing to trigger on",
          SignalTrigger().arm()["ok"] is False)
    for _i in range(4):                 # 2 s of quiet -> only the last 1 s is kept
        _tg.feed(_blk, [-100.0] * 100, 433_000_000, 434_000_000, 433_500_000, _sr)
    check("trigger: the pre-buffer is bounded to the armed lead-in",
          _tg._pre_bytes <= int(1.0 * _sr * 2) + len(_blk),
          "%d bytes" % _tg._pre_bytes)
    _hot = [-100.0] * 100
    _hot[40] = -50.0
    for _i in range(4):                 # the event, then enough to fill post_s
        _tg.feed(_blk, _hot, 433_000_000, 434_000_000, 433_500_000, _sr)
    _st = _tg.status()
    check("trigger: fires once and disarms at max_events",
          _st["count"] == 1 and not _st["armed"] and not _st["recording"],
          json.dumps(_st["events"])[:120])
    _ev = _st["events"][0] if _st["events"] else {}
    check("trigger: the capture holds the lead-in AND the event",
          abs(_ev.get("pre_s", 0) - 1.0) < 0.51 and _ev.get("seconds", 0) >= 1.9,
          "pre %.2fs total %.2fs" % (_ev.get("pre_s", 0), _ev.get("seconds", 0)))
    check("trigger: the event names the frequency that crossed",
          abs(_ev.get("freq_hz", 0) - 433_405_000) < 6000 and _ev.get("excess_db") == 20.0)
    _tp = os.path.join(_iq_cap_dir(), _ev.get("name", "x") + ".sigmf-data")
    _tm = _tp[:-len(".sigmf-data")] + ".sigmf-meta"
    _ok = os.path.exists(_tp) and os.path.exists(_tm)
    check("trigger: writes a SigMF pair the analyzer can open", _ok)
    if _ok:
        _mj = json.load(open(_tm))
        _ann = [a for a in _mj.get("annotations", []) if a.get("core:label") == "trigger point"]
        check("trigger: the sidecar marks where the trigger fired",
              len(_ann) == 1 and abs(_ann[0]["core:sample_start"] - _sr) < _sr * 0.6,
              str(_ann))
        check("trigger: the data hash matches the file", _sigmf_hash_ok(_tp, _mj))
        check("trigger: file length matches the event's own figures",
              os.path.getsize(_tp) == _ev["bytes"])
    for _f in (_tp, _tm):            # never leave test captures behind
        try:
            os.unlink(_f)
        except OSError:
            pass
    check("trigger: disarm clears everything",
          SignalTrigger().disarm()["armed"] is False)

    # --- front-end health: clipping is reported, not silently measured -------
    check("adc: a clean capture with headroom is ok",
          adc_health(0.0, 0.25)[0] == "ok")
    check("adc: headroom is dB below full scale",
          abs(adc_health(0.0, 0.5)[1] - 6.0) < 0.1)
    check("adc: samples on the rail = overload",
          adc_health(0.01, 1.0)[0] == "overload")
    check("adc: no clipping yet but nearly full scale = near",
          adc_health(0.0, 0.95)[0] == "near")
    check("adc: bad input never raises", adc_health(None, "x")[0] == "ok")

    # --- shipped defaults + managed gain -------------------------------------
    check("defaults: the dongle's own AGC is not what ships",
          _DEFAULTS["_gain"] == 25.4 and _DEFAULTS["_agc"] is True,
          str(_DEFAULTS["_gain"]))
    check("defaults: RMS is the shipped detector", _DEFAULTS["_detector"] == "rms")
    check("defaults: a saved setting overrides the shipped default, not the reverse",
          set(_DEFAULTS) == set(_SETTINGS_KEYS_G))
    check("agc: clipping steps the gain down one notch",
          agc_step("overload", 0.0, 25.4)[0] == 22.9)
    check("agc: too little headroom steps down",
          agc_step("ok", 4.0, 25.4)[0] == 22.9)
    check("agc: plenty of headroom steps up",
          agc_step("ok", 30.0, 25.4)[0] == 28.0)
    check("agc: in-band headroom changes nothing (no hunting)",
          agc_step("ok", 15.0, 25.4)[0] is None
          and agc_step("ok", _AGC_HEADROOM_MIN + 0.1, 25.4)[0] is None
          and agc_step("ok", _AGC_HEADROOM_MAX - 0.1, 25.4)[0] is None)
    check("agc: one step at a time, never a jump",
          all(abs(_R820T_GAINS.index(_nearest_gain(agc_step("overload", 0.0, g)[0]))
                  - _R820T_GAINS.index(_nearest_gain(g))) == 1
              for g in (12.5, 20.7, 28.0, 36.4)))
    check("agc: it stays inside the useful gain range",
          agc_step("ok", 40.0, _AGC_GAIN_MAX)[0] is None
          and agc_step("overload", 0.0, _AGC_GAIN_MIN)[0] is None)
    check("agc: clipping at the lowest gain is reported, not silently ignored",
          "too strong" in agc_step("overload", 0.0, _AGC_GAIN_MIN)[1])
    check("agc: with no measurement yet it does nothing",
          agc_step("ok", None, 24.0)[0] is None)
    check("agc: hardware AGC (gain None) is left alone",
          agc_step("overload", 0.0, None)[0] is None)
    check("agc: a gain between notches is pulled onto a supported one",
          _nearest_gain(23.5) == 22.9 and _nearest_gain(0.2) == 0.0)
    _conv = 25.4
    for _i in range(12):            # a loud site: it must settle, not oscillate
        _n, _ = agc_step("overload" if _conv > 15.7 else "ok",
                         2.0 if _conv > 15.7 else 14.0, _conv)
        if _n is None:
            break
        _conv = _n
    check("agc: converges and then stops", _conv == 15.7 and _i < 11,
          "settled at %s after %d steps" % (_conv, _i))

    # --- settings survive a restart ------------------------------------------
    import tempfile as _tf
    _sdir = _tf.mkdtemp()
    _sp = globals()["_settings_path"]
    globals()["_settings_path"] = lambda: os.path.join(_sdir, "rf_settings.json")
    _np_was = _no_persist
    try:
        globals()["_no_persist"] = False
        globals()["_detector"], globals()["_gain"], globals()["_conv_hz"] = "min", 33.8, 125_000_000
        check("settings: saving writes a file", _save_settings() is True
              and os.path.exists(_settings_path()))
        globals()["_detector"], globals()["_gain"], globals()["_conv_hz"] = "peak", None, 0
        check("settings: loading restores what was saved",
              _load_settings() is True and _detector == "min" and _gain == 33.8
              and _conv_hz == 125_000_000)
        with open(_settings_path(), "w") as _fh:
            _fh.write("{not json")
        check("settings: a corrupt file is ignored, not fatal",
              _load_settings() is False)
        os.unlink(_settings_path())
        check("settings: a fresh install has no file and keeps the defaults",
              _load_settings() is False)
        globals()["_no_persist"] = True
        check("settings: the selftest never writes the real file",
              _save_settings() is False)
    finally:
        globals()["_settings_path"] = _sp
        globals()["_no_persist"] = _np_was
        import shutil as _sh
        _sh.rmtree(_sdir, ignore_errors=True)

    # --- USB self-healing -----------------------------------------------------
    _uh = """Current status for hub 2 [1d6b:0002 Linux xhci-hcd xHCI Host Controller xhci-hcd.0, USB 2.00, 2 ports, ppps]
  Port 1: 0101 power connect []
  Port 2: 0100 power
Current status for hub 4 [1d6b:0002 Linux xhci-hcd, USB 2.00, 2 ports, ppps]
  Port 1: 0503 power highspeed enable connect [0bda:2838 Nooelec NESDR SMArt v5 75881080]
  Port 2: 0000 off
Current status for hub 1-1 [2109:3431 USB2.0 Hub, USB 2.10, 4 ports, ppps]
  Port 4: 0103 power enable connect [046d:c52b Logitech USB Receiver]"""
    _up = parse_uhubctl(_uh)
    check("heal: uhubctl listing parses every port",
          len(_up) == 5 and _up[0] == {"hub": "2", "port": 1, "status": "0101", "powered": True,
                                       "connected": True, "device": ""})
    check("heal: an unpowered port and an external hub are understood",
          _up[3]["powered"] is False and _up[4]["hub"] == "1-1" and _up[4]["port"] == 4)
    _pr, _st = rtl_ports(_up)
    check("heal: finds the enumerated RTL-SDR and the stuck (connect, no device) port",
          [(p["hub"], p["port"]) for p in _pr] == [("4", 1)]
          and [(p["hub"], p["port"]) for p in _st] == [("2", 1)])
    check("heal: another device on a port is neither RTL nor stuck",
          all(p["port"] != 4 or p["hub"] != "1-1" for p in _pr + _st))
    check("heal: sysfs names map to uhubctl targets and back",
          usb_target("2-1") == ("2", 1) and usb_target("1-1.4") == ("1-1", 4)
          and usb_devname("2", 1) == "2-1" and usb_devname("1-1", 4) == "1-1.4")
    _now = 1_790_000_000.0
    def _kl(dt, txt):
        import datetime
        return datetime.datetime.fromtimestamp(_now - dt).astimezone().isoformat().replace(".", ",") + " " + txt
    _lines = [_kl(900, "usb 2-1: USB disconnect, device number 3"),       # outside the window
              _kl(300, "usb 2-1: USB disconnect, device number 12"),
              _kl(200, "usb 2-1: device descriptor read/64, error -71"),
              _kl(150, "usb usb2-port1: Cannot enable. Maybe the USB cable is bad?"),
              _kl(100, "usb 2-1: USB disconnect, device number 20"),
              _kl(50, "usb 4-1: USB disconnect, device number 2")]        # another port
    _d, _h = parse_kernel_usb(_lines, "2-1", _now)
    check("heal: counts this port's disconnects inside the window only", _d == 2, str(_d))
    check("heal: turns the kernel's messages into plain hints",
          any("cable" in x for x in _h) and any("-71" in x for x in _h), str(_h))
    check("heal: no port known -> no evidence, not a crash", parse_kernel_usb(_lines, None, _now) == (0, []))
    # the decision table
    check("heal: a healthy dongle is left alone", plan_heal(True, False, None, 0, 999, True)[0] == "none")
    check("heal: NOTHING on any port is never power-cycled (it is unplugged)",
          plan_heal(False, False, None, 0, 999, True)[0] == "unplugged")
    check("heal: open-but-silent gets a USB reset first",
          plan_heal(True, True, None, 0, 999, True)[0] == "usb_reset")
    check("heal: ...and a port power-cycle if that did not help",
          plan_heal(True, True, None, 1, 999, True)[0] == "power_cycle")
    check("heal: a stuck port is power-cycled",
          plan_heal(False, False, "2:1", 0, 999, True)[0] == "power_cycle")
    check("heal: without uhubctl it falls back to a controller reset",
          plan_heal(False, False, "2:1", 0, 999, False)[0] == "rebind")
    check("heal: attempts back off (15 s after the first)",
          plan_heal(False, False, "2:1", 1, 5, True)[0] == "wait"
          and plan_heal(False, False, "2:1", 1, 16, True)[0] == "power_cycle"
          and plan_heal(False, False, "2:1", 3, 100, True)[0] == "wait")
    check("heal: it stops and asks for a person after the attempt limit",
          plan_heal(False, False, "2:1", _HEAL_MAX_ATTEMPTS, 999, True)[0] == "give_up")

    # --- USB recovery --------------------------------------------------------
    _up = _usb_device_path()
    check("usb: the dongle is found by its sysfs ids (or absent, cleanly)",
          _up is None or (_up.startswith("/dev/bus/usb/") and len(_up.split("/")) == 6),
          str(_up))
    check("usb: the reset path names a device node that exists",
          _up is None or os.path.exists(_up), str(_up))
    check("usb: the known RTL vendor/product ids are all Realtek",
          all(v == "0bda" for v, _pid in _USB_IDS) and ("0bda", "2838") in _USB_IDS)

    # --- geolocation on captures --------------------------------------------
    check("geo: SigMF geolocation is a GeoJSON point, longitude first",
          geojson_point({"lat": 57.7, "lon": 11.97})
          == {"type": "Point", "coordinates": [11.97, 57.7]})
    check("geo: altitude is included when known",
          geojson_point({"lat": 57.7, "lon": 11.97, "alt": 42.0})["coordinates"][2] == 42.0)
    check("geo: no fix -> no geolocation, not a zero-zero fix",
          geojson_point(None) is None and geojson_point({"lat": None, "lon": 1}) is None)
    _gm = sigmf_meta(433_920_000, 2_000_000,
                     position={"lat": 57.7, "lon": 11.97, "source": "gps", "satellites": 9},
                     detector="rms")
    check("geo: a capture carries the fix, its source and the detector used",
          _gm["global"]["core:geolocation"]["coordinates"] == [11.97, 57.7]
          and _gm["global"]["ragnar:position_source"] == "gps"
          and _gm["global"]["ragnar:gps_satellites"] == 9
          and _gm["global"]["ragnar:detector"] == "rms")
    check("geo: a capture without a fix carries no geolocation key",
          "core:geolocation" not in sigmf_meta(433_920_000, 2_000_000)["global"])
    check("geo: no provider registered -> no position, no exception",
          current_position() is None)
    set_position_provider(lambda: {"lat": 1.5, "lon": 2.5, "alt": 3.0, "source": "manual"})
    check("geo: a registered provider is used",
          current_position()["lat"] == 1.5 and current_position()["source"] == "manual")
    set_position_provider(lambda: (_ for _ in ()).throw(RuntimeError("gps died")))
    check("geo: a provider that raises is not allowed to break a capture",
          current_position() is None)
    set_position_provider(None)

    # --- harmonics ----------------------------------------------------------
    _hp = harmonic_plan(433_920_000, 4)
    check("harmonics: plans 2x..nx the carrier",
          [h[0] for h in _hp] == [2, 3, 4]
          and _hp[0][1] == 867_840_000 and _hp[2][1] == 1_735_680_000)
    check("harmonics: a harmonic past the tuner is marked out of reach, not dropped",
          [h[2] for h in harmonic_plan(600_000_000, 4)] == [True, False, False]
          and len(harmonic_plan(600_000_000, 4)) == 3)
    check("harmonics: bad input returns an empty plan", harmonic_plan(None) == [])

    # --- image / DC-spike check ---------------------------------------------
    _ca, _cb = 433_670_000, 434_170_000
    check("image: a peak that holds its frequency is real",
          image_verdict(433_920_100, 433_919_500, _ca, _cb)["verdict"] == "real")
    check("image: a peak that moves with the tuner is an image",
          image_verdict(433_920_000, 434_420_000, _ca, _cb)["verdict"] == "image")
    check("image: a peak pinned to the tuner centre is the DC spike",
          image_verdict(_ca + 900, _cb - 700, _ca, _cb)["verdict"] == "dc-spike")
    check("image: nothing heard is reported as absent, not as real",
          image_verdict(None, 433_920_000, _ca, _cb)["verdict"] == "absent")

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
    _hl = {k: v for k, v in lp.items() if v["proto"] == "Wi-Fi HaLow"}
    check("halow: US, EU and other regions present",
          {"halow-us", "halow-eu", "halow-jp", "halow-kr", "halow-cn",
           "halow-anz", "halow-in", "halow-sg"} <= set(_hl))
    check("halow: US grid is 13 x 2 MHz channels, 903..927 MHz",
          len(_hl["halow-us"]["channels"]) == 13
          and _hl["halow-us"]["channels"][0]["freq_hz"] == 903_000_000
          and _hl["halow-us"]["channels"][-1]["freq_hz"] == 927_000_000)
    check("halow: EU 1 MHz channels sit on 863 + 0.5*n (863.5 .. 867.5)",
          {c["freq_hz"] for c in _hl["halow-eu"]["channels"]}
          >= {863_500_000, 865_500_000, 867_500_000})
    _sz = {k: v for k, v in lp.items() if v["proto"] == "Zigbee Suzi"}
    check("suzi: EU 868 and NA 915 presets present", {"suzi-eu868", "suzi-na915"} <= set(_sz))
    check("suzi: NA markers are 802.15.4 channels 1-10, 906..924 MHz, 2 MHz apart",
          [c["freq_hz"] for c in _sz["suzi-na915"]["channels"]]
          == [(906 + 2 * k) * 1_000_000 for k in range(10)])
    check("suzi: the EU reference marker is 802.15.4 channel 0 at 868.3 MHz",
          [c["freq_hz"] for c in _sz["suzi-eu868"]["channels"]] == [868_300_000])
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

    # --- resolution + hardware settings (pure) ---
    # narrow zoom: 1 MS/s capture, 250 kHz window -> only ~256 of 1024 FFT bins
    # land in 480 columns; the gaps are interpolated, not left at the floor
    _nb = [-60.0] * 1024
    _gz = _iq_to_grid(_nb, 433_920_000, 1_000_000, 433_795_000, 434_045_000)
    check("grid: narrow zoom has no dead (floor) columns",
          _gz.count(_FLOOR_DBM) == 0 and len(_gz) == _POWER_BINS, str(_gz.count(_FLOOR_DBM)))
    _nb2 = [-90.0] * 1024; _nb2[512] = -30.0
    _gz2 = _iq_to_grid(_nb2, 433_920_000, 1_000_000, 433_795_000, 434_045_000)
    check("grid: interpolation keeps the tone as the peak", max(_gz2) == -30.0)
    check("fft: auto size gives >= 2 bins per column when zoomed",
          _auto_fft(1_000_000, 433_795_000, 434_045_000, 480) * 250_000 / 1_000_000 >= 960
          and _auto_fft(1_000_000, 433_795_000, 434_045_000, 480) in _FFT_SIZES)
    check("fft: wide span keeps a small FFT", _auto_fft(3_200_000, 433_000_000, 435_800_000, 480) <= 2048)
    _saved = get_tuning()
    try:
        set_tuning(bias_t=True, direct="auto", window="flattop")
        check("flags: rtl_power gets -T (bias-T) + window", "-T" in _tuner_args("rtl_power", 433_000_000, 434_000_000)
              and "-w" in _tuner_args("rtl_power", 433_000_000, 434_000_000))
        check("flags: rtl_433 never gets -T (it means run-time there)", "-T" not in _tuner_args("rtl_433"))
        check("direct: auto on for HF, off for VHF/UHF",
              _direct_on(7_000_000, 7_300_000) and not _direct_on(433_000_000, 434_000_000))
        check("direct: HF reachable only via direct sampling",
              _hw_range_ok(7_000_000, 7_300_000) and not _hw_range_ok(10_000_000, 30_000_000))
        set_tuning(direct="off")
        check("direct: off -> HF rejected", not _hw_range_ok(7_000_000, 7_300_000))
        set_tuning(fft=3000, bins=777, window="nope", avg=999)
        t = get_tuning()
        check("settings: invalid FFT / bins / window ignored, avg clamped",
              t["fft"] == _saved["fft"] and t["bins"] == _saved["bins"] and t["window"] == "flattop" and t["avg"] == 64)
        check("parse: rtl_433 freq strings", _parse_hz("433.92M") == 433_920_000 and _parse_hz("315000000") == 315_000_000)
        _w = _fft_window(1024)
        check("window: flattop is ~1 at centre, tiny at the edges", 0.95 < float(_w[512]) < 1.05 and abs(float(_w[0])) < 0.01)
    except Exception as _e:
        check("settings block ran", False, str(_e))
    finally:
        set_tuning(ppm=_saved["ppm"], gain=_saved["gain"], fft=_saved["fft"], avg=_saved["avg"], window=_saved["window"],
                   bins=_saved["bins"], bias_t=_saved["bias_t"], direct=_saved["direct"], conv_hz=_saved["conv_hz"])

    # --- unattended survey: band statistics (pure) ---
    _fr = []
    for _k in range(100):
        _row = [-60.0 + ((_k * 7 + _i * 13) % 5) for _i in range(200)]    # noise ~-60..-56
        for _i in range(40, 44):
            _row[_i] = -20.0                                               # constant carrier
        if _k % 10 == 0:
            for _i in range(150, 160):
                _row[_i] = -30.0                                           # 10% duty burst
        _fr.append({"power": _row, "ts": 1000.0 + _k})
    _ss = survey_stats(_fr, 433_000_000, 435_000_000)
    _em = {round(e["freq_mhz"], 2): e for e in _ss["emitters"]}
    check("survey: constant carrier found, 100% occupancy, right freq",
          any(abs(f - 433.42) < 0.03 and e["occupancy_pct"] == 100.0 for f, e in _em.items()), str(_em)[:200])
    check("survey: 10% burst found with its duty + first/last seen",
          any(abs(f - 434.55) < 0.06 and abs(e["occupancy_pct"] - 10.0) < 0.5 and e["first_seen"] == 1000.0 and e["last_seen"] == 1090.0
              for f, e in _em.items()), str(_em)[:200])
    check("survey: exactly the two emitters, noise floor measured",
          len(_ss["emitters"]) == 2 and -61 < _ss["noise_db"] < -55, str(len(_ss["emitters"])) + " " + str(_ss["noise_db"]))
    check("survey: bad band list rejected", _survey.start(["nope"], 10)["ok"] is False)
    # report round-trip: save -> list -> report -> CSV -> delete (temp dir)
    global _survey_dir
    _sd_old = _survey_dir
    _sd_tmp = _tf2 = None
    try:
        import tempfile as _tf2
        _sd_tmp = _tf2.mkdtemp(prefix="rfsv-")
        _survey_dir = lambda: _sd_tmp
        _t = SpectrumSurvey(); _t._name = "unit-test"
        _t._report = {"name": "unit-test", "started": 1000.0, "finished": 1100.0, "status": "done",
                      "bands": [dict(_ss, band="433", round=1)]}
        _t._save()
        _li = survey_list()["surveys"]
        check("survey: saved report is listed with its emitter count",
              len(_li) == 1 and _li[0]["name"] == "unit-test" and _li[0]["emitters"] == 2, str(_li))
        _csv = survey_csv("unit-test").splitlines()
        check("survey: CSV has a header + one line per emitter",
              _csv[0].startswith("band,round,freq_mhz") and len(_csv) == 3 and _csv[1].startswith("433,1,"), str(_csv[:2]))
        check("survey: report + delete", survey_report("unit-test")["ok"] and survey_delete("unit-test")["ok"]
              and survey_list()["surveys"] == [])
    finally:
        _survey_dir = _sd_old

    # --- mesh direction finding (pure parts) ---
    _lf = level_from_frames([[-60.0] * 100 for _ in range(5)] + [[-60.0] * 50 + [-20.0] + [-60.0] * 49 for _ in range(6)],
                            433_000_000, 434_000_000, 433_505_000, 20_000)
    check("df: level at a frequency (median over rows) + SNR", _lf and _lf["level_db"] == -20.0 and _lf["snr_db"] == 40.0, str(_lf))
    import math as _m
    _tx = (59.3300, 18.0700)                                   # a transmitter
    _units = [(59.3350, 18.0600, "A"), (59.3260, 18.0620, "B"), (59.3310, 18.0850, "C"), (59.3240, 18.0780, "D")]
    _meas = []
    for _la, _lo, _nm in _units:
        _ex, _ny = _enu(_la, _lo, _tx[0], _tx[1]); _d = _m.hypot(_ex, _ny)
        _meas.append({"unit": _nm, "lat": _la, "lon": _lo, "level_db": -30.0 - 25.0 * _m.log10(_d)})
    _loc = df_locate(_meas)
    _ex, _ny = _enu(_loc["lat"], _loc["lon"], _tx[0], _tx[1])
    check("df: 4 units, ideal path loss -> fix within 60 m", _loc["method"] == "multilateration" and _m.hypot(_ex, _ny) < 60,
          "%.0f m off" % _m.hypot(_ex, _ny))
    _meas2 = [dict(x, level_db=x["level_db"] + (3.0 if i % 2 else -3.0)) for i, x in enumerate(_meas)]
    _loc2 = df_locate(_meas2)
    _ex2, _ny2 = _enu(_loc2["lat"], _loc2["lon"], _tx[0], _tx[1])
    check("df: adversarial +/-3 dB unit bias -> within the 2-sigma radius",
          _m.hypot(_ex2, _ny2) <= max(2 * _loc2["radius_m"], 60), "%.0f m off, radius %s" % (_m.hypot(_ex2, _ny2), _loc2["radius_m"]))
    check("df: 2 units -> rough weighted point, 1 unit -> nearest, 0 -> error",
          df_locate(_meas[:2])["method"] == "two-unit weighted" and df_locate(_meas[:1])["method"] == "nearest"
          and df_locate([])["ok"] is False)

    # --- limit-line alarms -> Watchtower feed (rate-limited per panel) ---
    import tempfile as _tf
    global _RF_WT_DIR
    _old_dir = _RF_WT_DIR
    _RF_WT_DIR = _tf.mkdtemp(prefix="rfwt-")
    try:
        _limit_last.clear()
        e1 = limit_alarm("RTL-SDR", 433.92, -40.0, -55.0, "dBm", "level", [433.0, 435.0], now=1000.0)
        e2 = limit_alarm("RTL-SDR", 433.95, -38.0, -55.0, "dBm", now=1003.0)
        e3 = limit_alarm("RTL-SDR", 433.95, -38.0, -55.0, "dBm", now=1011.0)
        with open(os.path.join(_RF_WT_DIR, _RF_WT_FILE)) as _fh:
            _lines = [json.loads(x) for x in _fh if x.strip()]
        check("limit: violation logged to the Watchtower feed",
              e1 and e1["code"] == "RF_LIMIT_EXCEEDED" and "15.0 dB over" in e1["summary"] and _lines[0]["unit"] == "dBm", str(e1))
        check("limit: rate-limited per panel (10 s)", e2 is None and e3 is not None and len(_lines) == 2)
        check("limit: bad input ignored", limit_alarm("x", "nope", 1, 2) is None)
    finally:
        _RF_WT_DIR = _old_dir
        _limit_last.clear()

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
