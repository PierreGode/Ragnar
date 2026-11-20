#!/usr/bin/env python3
"""
sdr_spectrum.py — True-RF spectrum + waterfall capture via a HackRF SDR.

The third pillar of the Ragnar RF suite. Where :mod:`wifi_analyzer` renders the
*beacon* view (what Access Points announce) and :mod:`bt_scanner` the *Bluetooth
device* view, this measures the **actual radio energy on the air** — regardless
of protocol — with a Software Defined Radio, and feeds the web UI's Waterfall.

Unlike the Wi-Fi Bar/Dome views (two drawings of the same passive beacon scan),
this is a wholly separate data source: a HackRF sweeping the band and reporting
**power per frequency bin**. That is what lets it see things nothing else here
can — microwave ovens, drones, analog cameras, jammers, and the true noise
floor — not just devices that speak Wi-Fi or Bluetooth.

Why HackRF
----------
The common (cheap) RTL-SDR only tunes to ~1.7 GHz and physically cannot see
2.4/5 GHz. The **HackRF One** (1 MHz–6 GHz) covers both Wi-Fi bands, and its
bundled ``hackrf_sweep`` already emits ready-to-plot power-per-bin CSV as it
retunes across a range — exactly the shape a waterfall wants.

Capture model
-------------
``hackrf_sweep -f LO:HI`` streams CSV rows, each covering one FFT tune step:

    date, time, hz_low, hz_high, hz_bin_width, num_samples, dB, dB, dB, …

The rows climb in frequency across the band; when the frequency wraps back to
the bottom, one full **sweep frame** is complete. We accumulate each sweep into
a fixed-width power grid (``_GRID_BINS`` buckets, max-per-bucket), keep a rolling
ring buffer of recent frames plus a cumulative **max-hold** trace, and hand
them to the web layer to scroll as a time × frequency × power heatmap.

Everything here is **receive-only** — an SDR sweep never transmits.

CLI
---
    python3 sdr_spectrum.py detect
    python3 sdr_spectrum.py sweep [--band 2.4|5] [--frames N]
    python3 sdr_spectrum.py selftest
"""

import os
import re
import subprocess
import sys
import threading
import time


# --------------------------------------------------------------------------
# Constants / tunables
# --------------------------------------------------------------------------

def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


_HACKRF_INFO = _which("hackrf_info")
_HACKRF_SWEEP = _which("hackrf_sweep")
_HACKRF_TRANSFER = _which("hackrf_transfer")

# TX pilot-tone state (used only by transmit_tone / tx_tone_stop, below). The
# HackRF transmits a single CW carrier the TCXO-less ESP-SDR locks onto to trim
# its crystal — see transmit_tone().
_TX_PROC = None
_TX_FILE = None

# Named bands (MHz). Wi-Fi 6 GHz is within HackRF's range but its edges vary by
# region; 2.4 and 5 cover the common troubleshooting cases.
BANDS = {
    # HF / sub-GHz band scopes. The HackRF reaches 1 MHz-6 GHz, so it can sweep
    # everything the RTL-SDR can (mirrors rtl_sdr.RTL_BANDS) -- except the bottom
    # of the AM band, which sits below HackRF's 1 MHz floor (clamped here).
    "am":  (1.0, 1.71),        # AM / medium-wave (only the top is above 1 MHz)
    "sw":  (3.0, 24.0),        # shortwave HF broadcast
    "fm":  (88.0, 108.0),      # FM broadcast
    "air": (108.0, 137.0),     # VHF airband (AM voice)
    "27":  (26.9, 27.5),       # CB / 27 MHz RC
    "40":  (40.0, 41.0),       # 40 MHz RC / toys
    "315": (313.5, 316.5),     # US keyfobs / TPMS / garage & gate remotes
    "433": (433.05, 434.79),   # EU 433 ISM
    "868": (863.0, 870.0),     # EU 868 SRD
    "915": (902.0, 928.0),     # US 915 ISM
    "2.4": (2400, 2500),
    "5":   (5150, 5895),
    "6":   (5925, 6425),
}

# hackrf_sweep needs a window at least a couple of int-MHz wide (it captures
# ~20 MHz per tune and wants max>min after MHz truncation). Narrow band scopes
# (AM/27/40) and 1-2 MHz zoom spans get symmetrically widened to this for the
# sweep command; the display still bins to the requested [lo, hi].
_MIN_SWEEP_MHZ = 2.0


def sweep_cmd(lo, hi, lna, vga, amp=False, antenna=False, bin_hz=None, bins=None):
    """hackrf_sweep argv for [lo,hi] MHz (pure, selftested).

    ``bin_hz`` (resolution bandwidth) defaults to finer than a display column so
    a narrow zoom has no floor streaks; an explicit value is clamped to
    hackrf_sweep's 2445 Hz - 5 MHz. ``amp`` enables the RX RF amplifier (+~11 dB,
    for weak signals — overloads on strong ones); ``antenna`` powers the antenna
    port (bias, 3.3 V) for an active antenna / LNA.
    """
    bins = bins or _GRID_BINS
    if bin_hz:
        bin_hz = max(2445, min(5_000_000, int(bin_hz)))
    else:
        span_hz = (hi - lo) * 1_000_000
        bin_hz = int(span_hz / (bins * 2)) or _BIN_WIDTH_HZ
        bin_hz = max(2500, min(_BIN_WIDTH_HZ, bin_hz))
    cmd = [_HACKRF_SWEEP, "-f", "%d:%d" % (int(lo), int(hi) + 1),
           "-w", str(bin_hz), "-l", str(lna), "-g", str(vga)]
    if amp:
        cmd += ["-a", "1"]
    if antenna:
        cmd += ["-p", "1"]
    return cmd, bin_hz


def _widen_span(lo, hi):
    """Widen a too-narrow [lo, hi] MHz window symmetrically to _MIN_SWEEP_MHZ.

    Below ~_GRID_BINS * (hackrf_sweep's ~2.5 kHz FFT floor) ~= 1.3 MHz, a span
    can't feed every display column, so narrow requests (small zoom, a manual
    tune, a 0.45 MHz mesh overlay) are widened. Pure so selftest can exercise it.
    """
    if hi - lo < _MIN_SWEEP_MHZ:
        c = (lo + hi) / 2.0
        lo = max(1.0, c - _MIN_SWEEP_MHZ / 2.0)
        hi = min(7250.0, lo + _MIN_SWEEP_MHZ)
    return lo, hi

_GRID_BINS = 512          # display columns per frame (band binned into this many)
_RING_FRAMES = 600        # rolling history of sweep frames kept in memory
_FLOOR_DBM = -120         # sentinel for a bucket no sweep bin landed in
# FFT resolution must stay finer than one display column or some columns get no
# raw bin and paint a permanent floor streak. 512 columns over the 100 MHz 2.4
# band is ~195 kHz/column, so 150 kHz keeps every column fed (~667 raw bins ->
# 512 buckets) while sweeps stay fast enough for the steady cadence below.
_BIN_WIDTH_HZ = 150000    # hackrf_sweep FFT resolution (finer than a display column)
_DEFAULT_LNA = 24         # HackRF LNA gain (0-40, 8 dB steps)
_DEFAULT_VGA = 20         # HackRF VGA/baseband gain (0-62, 2 dB steps)
# hackrf_sweep finishes a full band far faster (and far more irregularly) than a
# waterfall wants to scroll: for a 100 MHz band it can complete 20-30 sweeps a
# second, then briefly stall on a USB hiccup or a retune. Emitting every raw
# sweep as its own row makes the display lurch — a burst of rows jumps in at
# once, then it freezes with nothing new. Instead we time-integrate raw sweeps
# (max-hold) into rows produced at a fixed cadence, the way a real spectrum-
# analyzer waterfall dwells. That yields a smooth, steady scroll and, as a
# bonus, each row now catches bursty transmitters that fired between frames.
# 20 rows/s matches the feel of the RTL-SDR's IQ engine (~16/s); the 2.4 GHz band
# completes a sweep every ~17 ms, so each row still max-holds ~3 sweeps.
_DISPLAY_HZ = 20          # waterfall rows emitted per second (steady scroll rate)
_DISPLAY_INTERVAL = 1.0 / _DISPLAY_HZ


def _dwell_tick(next_push, now, interval=None):
    """Row scheduler for one completed sweep (pure, selftested).

    Returns ``(push, stamp, next_push)``. Rows sit on a fixed grid of
    ``interval`` seconds, so the average rate is exactly ``_DISPLAY_HZ``.
    Timing each wait from the moment of the previous push instead lost up to
    one whole sweep per row (measured 9.2 rows/s at a nominal 10). Each row is
    stamped with its grid time — at most one sweep earlier than the sweep that
    completed it — so the page, which plays rows back at their own timestamps,
    scrolls at an even cadence. When sweeps are slower than the grid (a wide
    5/6 GHz span) every sweep becomes a row, stamped when it completed, and
    the grid restarts from there rather than bursting to catch up.
    """
    interval = _DISPLAY_INTERVAL if interval is None else interval
    if now < next_push:
        return False, None, next_push
    if now - next_push < interval:          # on the grid
        return True, next_push, next_push + interval
    return True, now, now + interval        # behind the grid: one row now, re-anchor


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


def parse_hackrf_info(text):
    """Pull board name / serial / firmware from ``hackrf_info`` output (pure)."""
    info = {"serial": None, "firmware": None, "board": None}
    m = re.search(r"Serial number:\s*(\S+)", text)
    if m:
        info["serial"] = m.group(1)
    m = re.search(r"Firmware Version:\s*(.+)", text)
    if m:
        info["firmware"] = m.group(1).strip()
    m = re.search(r"Board ID Number:\s*\d+\s*\((.+)\)", text)
    if m:
        info["board"] = m.group(1).strip()
    return info


def detect():
    """Report SDR availability so the UI can gate the Waterfall view.

    Returns a dict with ``available`` True only when the hackrf tools are
    installed *and* a board actually answers — the exact condition under which
    the web UI un-greys the Waterfall button.
    """
    # Probe the board exactly ONCE. hackrf_info opens the USB device; opening it
    # twice back-to-back (as this used to) often makes the second open fail with
    # "hackrf_open() failed" because libusb hasn't released the first claim yet —
    # which then reads as "no HackRF" and greys the Waterfall out on a board that
    # is actually fine. hackrf_sweep -h only prints usage (no device open), so we
    # use it purely to tell "tools missing" apart from "device problem".
    if _run([_HACKRF_SWEEP, "-h"])[0] == 127:
        return {"available": False, "tools_installed": False,
                "device_present": False,
                "error": "hackrf tools not installed (apt install hackrf)"}
    # First enumeration after boot / on a busy USB bus can be slow, so give the
    # single probe generous headroom and treat a timeout as its own case rather
    # than silently reporting the board absent.
    rc, out, err = _run([_HACKRF_INFO], timeout=12)
    blob = (out or "") + (err or "")
    if rc == 127:
        return {"available": False, "tools_installed": False,
                "device_present": False,
                "error": "hackrf tools not installed (apt install hackrf)"}
    if rc == 124:
        return {"available": False, "tools_installed": True,
                "device_present": False,
                "error": "HackRF probe timed out — retry, or use a powered USB "
                         "hub (the Pi's port may be under-powering the board)"}
    if rc != 0 or "No HackRF boards found" in blob or "hackrf_open" in blob:
        return {"available": False, "tools_installed": True,
                "device_present": False,
                "error": "no HackRF detected — plug one in (a powered USB hub is "
                         "recommended on the Pi)"}
    info = parse_hackrf_info(out)
    return {"available": True, "tools_installed": True, "device_present": True,
            "serial": info["serial"], "firmware": info["firmware"],
            "board": info["board"], "bands": sorted(BANDS.keys())}


# --------------------------------------------------------------------------
# hackrf_sweep parsing
# --------------------------------------------------------------------------

def parse_sweep_line(line):
    """Parse one ``hackrf_sweep`` CSV row into (hz_low, hz_high, bin_hz, [dB…]).

    Returns None for header/blank/garbage lines. Pure — the selftest drives it
    with captured rows so the frame assembler is verifiable offline.
    """
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 7:
        return None
    try:
        hz_low = int(parts[2])
        hz_high = int(parts[3])
        bin_hz = float(parts[4])
        dbs = [float(x) for x in parts[6:] if x != ""]
    except (ValueError, IndexError):
        return None
    if bin_hz <= 0 or not dbs:
        return None
    return hz_low, hz_high, bin_hz, dbs


def _merge_max(accum, frame):
    """Fold ``frame`` into ``accum`` in place (bucket-wise max), returning accum.

    This is the time-integration of the waterfall dwell: every raw sweep that
    lands inside one display interval keeps the strongest reading per bucket, so
    a short burst between frames still paints a row instead of being dropped.
    Passing ``accum=None`` starts a fresh dwell from a copy of ``frame``.
    """
    if accum is None:
        return list(frame)
    for i, v in enumerate(frame):
        if v > accum[i]:
            accum[i] = v
    return accum


class _FrameBuilder:
    """Accumulate ascending sweep rows into fixed-width power frames.

    A HackRF sweep climbs in frequency across [lo, hi]; when a row's start
    frequency drops below the previous row's, the band has wrapped and the
    accumulated grid is a complete frame. Each dB bin is placed into one of
    ``_GRID_BINS`` display buckets, keeping the max (peak-hold within a sweep).
    """

    def __init__(self, lo_mhz, hi_mhz, bins=_GRID_BINS):
        self.lo = lo_mhz * 1_000_000
        self.hi = hi_mhz * 1_000_000
        self.bins = bins
        self._reset()
        self._last_low = None

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

    def add(self, hz_low, hz_high, bin_hz, dbs):
        """Feed one parsed row; returns a finished frame grid or None.

        The frame emitted is the one that was *just completed* by the wrap this
        row represents — the current row starts the next frame.
        """
        frame = None
        if self._last_low is not None and hz_low < self._last_low and self._filled:
            frame = self.grid
            self._reset()
        self._last_low = hz_low
        for i, db in enumerate(dbs):
            # Fill every display column this raw FFT bin covers, not just the one
            # its centre lands in. On a narrow span the raw bins (>=2500 Hz, the
            # hackrf_sweep FFT floor) are wider than a column, so centre-only
            # bucketing would skip columns and paint floor streaks; on a wide
            # span both edges map to one column, so this stays a single fill.
            lo_edge = max(hz_low + i * bin_hz, self.lo)
            hi_edge = min(hz_low + (i + 1) * bin_hz, self.hi)
            if hi_edge <= lo_edge:
                continue                    # this bin lies outside [lo, hi]
            b0 = self._bucket(lo_edge)
            b1 = self._bucket(hi_edge - 1)
            if b0 is None or b1 is None:
                continue
            for b in range(b0, b1 + 1):
                if db > self.grid[b]:
                    self.grid[b] = db
            self._filled = True
        return frame


# --------------------------------------------------------------------------
# Live capture manager (background hackrf_sweep + ring buffer)
# --------------------------------------------------------------------------

class SweepCapture:
    """Own a running ``hackrf_sweep`` subprocess and a ring buffer of frames."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._frames = []          # list of {seq, ts, power:[int]}
        self._seq = 0
        self._maxhold = None
        self._band = None
        self._error = None
        self._lna = _DEFAULT_LNA
        self._vga = _DEFAULT_VGA
        self._stderr_tail = None   # last stderr line, kept for exit diagnostics
        self._detect_cache = None  # last good detect(), reused while streaming
        self._sig = None           # (label, lo, hi) — restart only on a real change
        self._lo_mhz = None        # active sweep range (band OR custom zoom span)
        self._hi_mhz = None

    # -- lifecycle ---------------------------------------------------------
    def start(self, band="2.4", lna=None, vga=None, lo_mhz=None, hi_mhz=None,
              amp=None, antenna=None, bin_hz=None):
        # A custom [lo_mhz, hi_mhz] span (the page's zoom, a manual tune, or a
        # mesh/LoRa overlay) overrides the named band when both edges are sane:
        # >=0.1 MHz wide, inside 1-7250 MHz. Narrow spans (e.g. a 0.45 MHz
        # Meshtastic-EU868 overlay) are widened below to a usable window.
        custom = None
        try:
            if lo_mhz is not None and hi_mhz is not None:
                lo_mhz, hi_mhz = float(lo_mhz), float(hi_mhz)
                if hi_mhz - lo_mhz >= 0.1 and lo_mhz >= 1 and hi_mhz <= 7250:
                    custom = (lo_mhz, hi_mhz)
        except (TypeError, ValueError):
            custom = None
        if custom:
            label, lo, hi = "zoom", custom[0], custom[1]
        else:
            band = band if band in BANDS else "2.4"
            label, (lo, hi) = band, BANDS[band]
        # Widen a too-narrow window so hackrf_sweep gets a sane range and every
        # display column receives a raw FFT bin (no floor streaks). Widens BOTH
        # sweep and display together -- the frame's band_mhz reports [lo, hi], so
        # the page's ruler matches what's actually drawn.
        lo, hi = _widen_span(lo, hi)
        lna_v = _clamp(lna, 0, 40, _DEFAULT_LNA)
        lna_v -= lna_v % 8                                  # hackrf LNA: 8 dB steps
        vga_v = _clamp(vga, 0, 62, _DEFAULT_VGA)
        vga_v -= vga_v % 2                                  # VGA: 2 dB steps
        amp_v = str(amp).lower() in ("1", "true", "on", "yes")
        ant_v = str(antenna).lower() in ("1", "true", "on", "yes")
        try:
            bin_v = int(float(bin_hz)) if bin_hz not in (None, "", "auto", 0, "0") else None
        except (TypeError, ValueError):
            bin_v = None
        sig = (label, round(lo, 3), round(hi, 3), lna_v, vga_v, amp_v, ant_v, bin_v)
        with self._lock:
            if self._thread and self._thread.is_alive():
                if sig == self._sig:
                    return {"ok": True, "already": True, "band": label}
                self._stop_locked()   # band / zoom change: restart cleanly
            self._stop.clear()
            self._frames = []
            self._seq = 0
            self._maxhold = [_FLOOR_DBM] * _GRID_BINS
            self._band = label
            self._sig = sig
            self._lo_mhz, self._hi_mhz = lo, hi
            self._error = None
            self._lna, self._vga = lna_v, vga_v
            self._amp, self._antenna, self._bin_req = amp_v, ant_v, bin_v
            self._thread = threading.Thread(target=self._run_loop, args=(lo, hi),
                                            daemon=True, name="hackrf-sweep")
            self._thread.start()
        return {"ok": True, "band": label, "range_mhz": [lo, hi]}

    def stop(self):
        with self._lock:
            self._stop_locked()
        return {"ok": True}

    def _stop_locked(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            except Exception:
                pass
        self._proc = None
        self._band = None

    # -- capture thread ----------------------------------------------------
    def _run_loop(self, lo, hi):
        # Keep the FFT bin finer than a display column so a narrow zoom span
        # doesn't leave floor-streak gaps; clamp to hackrf_sweep's sane range.
        builder = _FrameBuilder(lo, hi)           # [lo, hi] already widened in start()
        # +1 on the top edge so hackrf_sweep always sees max > min after MHz
        # truncation (the span is >= _MIN_SWEEP_MHZ, so this never inverts).
        cmd, bin_hz = sweep_cmd(lo, hi, self._lna, self._vga, getattr(self, "_amp", False),
                                getattr(self, "_antenna", False), getattr(self, "_bin_req", None))
        self._rbw = bin_hz
        self._stderr_tail = None
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, text=True,
                                          bufsize=1)
        except Exception as exc:
            self._error = "failed to launch hackrf_sweep: %s" % exc
            return
        # hackrf_sweep prints a stats line to stderr every second. If we only
        # read stdout, that stderr pipe (64 KB) fills over a long session and
        # hackrf_sweep blocks writing to it — the stream stalls mid-run. Drain
        # stderr continuously on its own thread, keeping the last line so an
        # early-exit reason is still reportable.
        def _drain_stderr(pipe):
            try:
                for eline in pipe:
                    eline = eline.strip()
                    if eline:
                        self._stderr_tail = eline[:200]
            except Exception:  # pragma: no cover - pipe closed on teardown
                pass
        serr_thread = threading.Thread(target=_drain_stderr,
                                       args=(self._proc.stderr,),
                                       daemon=True, name="hackrf-stderr")
        serr_thread.start()
        # Coalesce however many raw sweeps arrive into one display row every
        # _DISPLAY_INTERVAL seconds, so the waterfall scrolls at a steady rate
        # no matter how fast (or how burstily) hackrf_sweep retunes the band.
        accum = None
        next_push = time.time() + _DISPLAY_INTERVAL
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                parsed = parse_sweep_line(line)
                if not parsed:
                    continue
                frame = builder.add(*parsed)
                if frame is None:
                    continue
                accum = _merge_max(accum, frame)
                push, stamp, next_push = _dwell_tick(next_push, time.time())
                if push:
                    self._push_frame(accum, ts=stamp)
                    accum = None
        except Exception as exc:  # pragma: no cover - defensive
            self._error = str(exc)
        finally:
            # Surface a device error hackrf_sweep printed to stderr on early exit.
            # The drain thread already has it; give it a moment to catch the last
            # line the process wrote as it died.
            serr_thread.join(timeout=1)
            if (self._proc and self._proc.poll() not in (None, 0)
                    and not self._error and self._stderr_tail):
                self._error = self._stderr_tail

    def _push_frame(self, grid, ts=None):
        ints = [int(round(v)) for v in grid]
        with self._lock:
            self._seq += 1
            self._frames.append({"seq": self._seq,
                                 "ts": time.time() if ts is None else ts,
                                 "power": ints})
            if len(self._frames) > _RING_FRAMES:
                self._frames = self._frames[-_RING_FRAMES:]
            if self._maxhold is None:
                self._maxhold = list(ints)
            else:
                self._maxhold = [max(a, b) for a, b in zip(self._maxhold, ints)]

    # -- readers -----------------------------------------------------------
    def status(self):
        with self._lock:
            running = bool(self._thread and self._thread.is_alive())
            return {"running": running, "band": self._band,
                    "frames_buffered": len(self._frames), "seq": self._seq,
                    "bins": _GRID_BINS, "lna": self._lna, "vga": self._vga,
                    "amp": getattr(self, "_amp", False), "antenna": getattr(self, "_antenna", False),
                    "bin_hz": getattr(self, "_bin_req", None), "rbw_hz": getattr(self, "_rbw", None),
                    "error": self._error,
                    "band_mhz": [self._lo_mhz, self._hi_mhz] if self._lo_mhz else None,
                    "floor_dbm": _FLOOR_DBM}

    def get_frames(self, since=0):
        try:
            since = int(since)
        except (TypeError, ValueError):
            since = 0
        with self._lock:
            new = [f for f in self._frames if f["seq"] > since]
            return {"frames": new, "seq": self._seq, "band": self._band,
                    "band_mhz": [self._lo_mhz, self._hi_mhz] if self._lo_mhz else None,
                    "bins": _GRID_BINS, "floor_dbm": _FLOOR_DBM,
                    "rbw_hz": getattr(self, "_rbw", None),
                    "max_hold": list(self._maxhold) if self._maxhold else None,
                    "running": bool(self._thread and self._thread.is_alive()),
                    "error": self._error}


def _clamp(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


# Module-level singleton the web routes drive.
_capture = SweepCapture()


def start(band="2.4", lna=None, vga=None, lo_mhz=None, hi_mhz=None,
          amp=None, antenna=None, bin_hz=None):
    if _iqcap.busy():
        return {"ok": False, "error": "a raw-IQ capture is using the HackRF — the sweep "
                                      "resumes when it finishes"}
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "no SDR")}
    _capture._detect_cache = d
    return _capture.start(band, lna=lna, vga=vga, lo_mhz=lo_mhz, hi_mhz=hi_mhz,
                          amp=amp, antenna=antenna, bin_hz=bin_hz)


def stop():
    return _capture.stop()


def status():
    st = _capture.status()
    if st.get("running"):
        # A sweep already holds the HackRF over USB. Calling detect() here runs
        # hackrf_info, which opens the *same* device concurrently and knocks the
        # streaming sweep offline within seconds — the "dies after ~7s" bug, hit
        # whenever the UI's 15s status poll landed mid-capture. While streaming,
        # report availability from the last known-good probe instead of touching
        # the bus.
        d = dict(_capture._detect_cache or {})
        d.update({"available": True, "tools_installed": True,
                  "device_present": True, "streaming": True})
        d.setdefault("bands", sorted(BANDS.keys()))
        st["detect"] = d
    elif _iqcap.busy() or tx_active():
        # A raw-IQ capture or the TX pilot tone holds the radio: same rule —
        # never open it with hackrf_info underneath them.
        d = dict(_capture._detect_cache or {})
        d.update({"available": True, "tools_installed": True,
                  "device_present": True, "streaming": False})
        d.setdefault("bands", sorted(BANDS.keys()))
        st["detect"] = d
    else:
        st["detect"] = detect()
    st["iq_capturing"] = _iqcap.busy()
    return st


def get_frames(since=0):
    return _capture.get_frames(since)


# --------------------------------------------------------------------------
# TX pilot tone — transmit a single CW carrier so the TCXO-less ESP-SDR can
# cross-calibrate its crystal against the HackRF's accurate reference. The
# HackRF tunes to ``rf_hz - offset_hz`` and we feed it an interleaved cs8 IQ
# buffer of a complex sinusoid at ``+offset_hz``, so the emitted carrier sits
# exactly at ``rf_hz`` while the LO stays clear of the DC/LO-leakage spike. A
# short buffer is looped with ``-R``. Very low power, meant for a receiver a
# few cm away — not a transmitter for anything over the air.
# --------------------------------------------------------------------------

def tone_iq_cs8(offset_hz, fs_hz, dur_s=0.25, amp=100):
    """Interleaved signed-8-bit IQ (bytes) of a complex tone at ``offset_hz``.

    The buffer holds a whole number of cycles so looping it is phase-seamless.
    Pure — selftested without hardware."""
    import numpy as np
    n = max(64, int(fs_hz * dur_s))
    cycles = max(1, int(round(offset_hz * n / float(fs_hz))))   # integer cycles → seamless loop
    k = 2.0 * np.pi * cycles / n
    t = np.arange(n)
    a = max(1, min(127, int(amp)))
    i = np.clip(np.round(np.cos(k * t) * a), -127, 127).astype(np.int8)
    q = np.clip(np.round(np.sin(k * t) * a), -127, 127).astype(np.int8)
    iq = np.empty(2 * n, dtype=np.int8)
    iq[0::2] = i
    iq[1::2] = q
    return iq.tobytes(), int(round(cycles * fs_hz / float(n)))   # (bytes, actual emitted offset Hz)


def transmit_tone(rf_hz, offset_hz=2_000_000, fs_hz=8_000_000, tx_vga=30, amp=False):
    """Start transmitting a CW tone at ``rf_hz`` (loops until tx_tone_stop()).

    Frees the device from any running RX sweep first. ``tx_vga`` is the TX VGA
    gain 0..47 dB (kept modest — the ESP is centimetres away); ``amp`` enables
    the +~11 dB PA (off by default). Returns {ok, ...} or {ok:False, error}.
    """
    global _TX_PROC, _TX_FILE
    if _run([_HACKRF_TRANSFER, "-h"])[0] == 127 and not os.path.exists(_HACKRF_TRANSFER):
        return {"ok": False, "error": "hackrf_transfer not installed (apt install hackrf)"}
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "no HackRF")}
    tx_tone_stop()                      # clear any previous tone
    stop()                              # a running sweep holds the device — free it
    import tempfile
    rf_hz = int(rf_hz)
    lo = int(rf_hz - offset_hz)
    try:
        iq, emitted_off = tone_iq_cs8(offset_hz, fs_hz)
        fd, path = tempfile.mkstemp(suffix=".cs8", prefix="esp_tone_")
        with os.fdopen(fd, "wb") as fh:
            fh.write(iq)
    except Exception as exc:            # pragma: no cover - defensive
        return {"ok": False, "error": "could not build the tone buffer: %s" % exc}
    txv = max(0, min(47, int(tx_vga)))
    args = [_HACKRF_TRANSFER, "-t", path, "-f", str(lo), "-s", str(int(fs_hz)),
            "-x", str(txv), "-a", "1" if amp else "0", "-R"]
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
    except Exception as exc:
        try:
            os.unlink(path)
        except OSError:
            pass
        return {"ok": False, "error": "failed to launch hackrf_transfer: %s" % exc}
    time.sleep(0.4)                     # catch an immediate failure (device busy / bad args)
    if proc.poll() is not None:
        err = ""
        try:
            err = (proc.stderr.read() or "").strip()[:200]
        except Exception:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        return {"ok": False, "error": "hackrf_transfer exited immediately: %s" % (err or "unknown")}
    _TX_PROC = proc
    _TX_FILE = path
    return {"ok": True, "rf_hz": rf_hz, "lo_hz": lo, "offset_hz": int(emitted_off),
            "fs_hz": int(fs_hz), "tx_vga": txv, "amp": bool(amp)}


def tx_tone_stop():
    """Stop the pilot tone and clean up its buffer. Safe to call when idle."""
    global _TX_PROC, _TX_FILE
    p = _TX_PROC
    if p is not None:
        try:
            p.terminate()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.kill()
        except Exception:               # pragma: no cover - defensive
            pass
    _TX_PROC = None
    if _TX_FILE:
        try:
            os.unlink(_TX_FILE)
        except OSError:
            pass
        _TX_FILE = None
    return {"ok": True}


def tx_active():
    """True while a pilot tone is transmitting."""
    return _TX_PROC is not None and _TX_PROC.poll() is None


# --------------------------------------------------------------------------
# Raw-IQ capture to SigMF (for the Signal Analyzer)
# --------------------------------------------------------------------------
# hackrf_sweep reports only power per bin; the Signal Analyzer needs raw IQ.
# hackrf_transfer -r records interleaved signed 8-bit I/Q — SigMF "ci8", which
# sigmf_analyzer decodes natively — into data/iq_captures/, next to the RTL-SDR's
# captures, so the same Sessions list, rename, delete, download and Analyzer
# links serve both radios. Sweep and capture share one radio: a capture pauses
# the sweep, and the page resumes it when the capture is done.
#
# Offset tuning: the HackRF has a strong DC / LO-leakage spike at its tuned
# centre. Tuning straight onto a signal buries it under that spike, so the LO
# sits above the target (iq_plan). SigMF core:frequency records the real LO, so
# the analyzer's frequency axis stays true; an annotation marks the window asked
# for.

_IQ_SR_MIN = 2_000_000          # hackrf_transfer sample-rate range
_IQ_SR_MAX = 20_000_000
_IQ_MAX_BYTES = 200_000_000     # one capture (ci8 = 2 B/sample): 20 MS/s -> 5 s
_IQ_MAX_SECONDS = 30.0
_IQ_SPAN_FACTOR = 3.0           # sample rate = 3x the span asked for...
_IQ_LO_OFFSET = 0.2             # ...with the LO 0.2 x sample rate above the target


def _iq_cap_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "iq_captures")


def _iq_safe(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "")).strip("._")[:80]


def iq_plan(target_hz, span_hz=None):
    """Sample rate, LO and the usable window for a capture around ``target_hz``
    (pure, selftested).

    The HackRF's baseband filter defaults to 0.75 x the sample rate, so only
    LO +/- 0.375 sr is clean. The target goes at LO - 0.2 sr: the requested
    span (sr / 3 wide) then runs from LO - 0.367 sr to LO - 0.033 sr — inside
    the filter on one side, clear of the DC spike on the other. At the 20 MS/s
    ceiling that is the target +/- ~3.3 MHz; a wider view than that cannot be
    recorded in one tune, so the window is centred on the target instead.
    """
    target_hz = int(float(target_hz))
    try:
        span = float(span_hz) if span_hz not in (None, "") else 0.0
    except (TypeError, ValueError):
        span = 0.0
    sr = int(min(_IQ_SR_MAX, max(_IQ_SR_MIN, round(span * _IQ_SPAN_FACTOR))))
    sr -= sr % 1000                                      # tidy kHz-step rate
    off = int(round(sr * _IQ_LO_OFFSET))
    half = sr / (2.0 * _IQ_SPAN_FACTOR)                  # usable half-window
    return {"lo_hz": target_hz + off, "sr_hz": sr, "offset_hz": off,
            "target_hz": target_hz,
            "want_lo_hz": int(target_hz - half), "want_hi_hz": int(target_hz + half)}


class HackrfIqCapture:
    """One-shot bounded raw-IQ capture to a SigMF recording (background thread)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._reset()

    def _reset(self):
        self._name = None
        self._plan = None
        self._nsamp = 0
        self._want_bytes = 0
        self._seconds = 0.0
        self._started = None
        self._done = False
        self._error = None
        self._warning = None
        self._path = None

    def busy(self):
        return bool(self._thread and self._thread.is_alive())

    def start(self, target_hz, span_hz=None, seconds=2.0, name=None, label=None,
              lna=None, vga=None, amp=None, antenna=None):
        try:
            target_hz = int(float(target_hz))
            seconds = float(seconds)
        except (TypeError, ValueError):
            return {"ok": False, "error": "center_hz / seconds must be numeric"}
        if not (1_000_000 <= target_hz <= 6_000_000_000):
            return {"ok": False, "error": "centre frequency out of HackRF reach (1 MHz - 6 GHz)"}
        if not os.path.exists(_HACKRF_TRANSFER):
            return {"ok": False, "error": "hackrf_transfer not installed (apt install hackrf)"}
        if tx_active():
            return {"ok": False, "error": "the HackRF is transmitting a pilot tone — stop it first"}
        plan = iq_plan(target_hz, span_hz)
        seconds = max(0.1, min(_IQ_MAX_SECONDS, seconds,
                               _IQ_MAX_BYTES / (2.0 * plan["sr_hz"])))
        # Default to the sweep's own gains (0 dB is a valid setting, so no `or`).
        lna_v = _clamp(lna if lna is not None else _capture._lna, 0, 40, _DEFAULT_LNA)
        lna_v -= lna_v % 8
        vga_v = _clamp(vga if vga is not None else _capture._vga, 0, 62, _DEFAULT_VGA)
        vga_v -= vga_v % 2
        if amp is None:
            amp = getattr(_capture, "_amp", False)
        if antenna is None:
            antenna = getattr(_capture, "_antenna", False)
        amp_v = str(amp).lower() in ("1", "true", "on", "yes")
        ant_v = str(antenna).lower() in ("1", "true", "on", "yes")
        with self._lock:
            if self.busy():
                return {"ok": False, "error": "a capture is already running"}
            try:
                os.makedirs(_iq_cap_dir(), exist_ok=True)
            except OSError as exc:
                return {"ok": False, "error": "cannot create captures dir: %s" % exc}
            self._reset()
            base = _iq_safe(name) or ("hackrf-%d-%s" % (round(target_hz / 1e6),
                                                        time.strftime("%Y%m%d-%H%M%S")))
            self._name, self._plan, self._seconds = base, plan, seconds
            self._nsamp = int(plan["sr_hz"] * seconds)
            self._want_bytes = self._nsamp * 2                    # ci8: 2 bytes/sample
            self._label = label
            self._gains = {"lna": lna_v, "vga": vga_v, "amp": amp_v, "antenna": ant_v}
            self._path = os.path.join(_iq_cap_dir(), base + ".sigmf-data")
            self._started = time.time()
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="hackrf-iqcap")
            self._thread.start()
        return {"ok": True, "name": base, "center_hz": plan["lo_hz"],
                "target_hz": target_hz, "sr_hz": plan["sr_hz"],
                "offset_hz": plan["offset_hz"], "seconds": round(seconds, 3),
                "want_bytes": self._want_bytes,
                "window_hz": [plan["want_lo_hz"], plan["want_hi_hz"]]}

    def _run(self):
        plan, g = self._plan, self._gains
        stop()                                # the sweep holds the radio — free it
        cmd = [_HACKRF_TRANSFER, "-r", self._path, "-f", str(plan["lo_hz"]),
               "-s", str(plan["sr_hz"]), "-n", str(self._nsamp),
               "-l", str(g["lna"]), "-g", str(g["vga"]),
               "-a", "1" if g["amp"] else "0", "-p", "1" if g["antenna"] else "0"]
        err, t0 = "", None
        # libusb needs a moment to release the sweep's claim; retry a busy open.
        for attempt in range(4):
            if self._stop.wait(0.5 if attempt == 0 else 0.8):
                break
            t0 = time.time()
            try:
                self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                              stderr=subprocess.PIPE, text=True)
                _, err = self._proc.communicate()
            except Exception as exc:
                self._error = "failed to launch hackrf_transfer: %s" % exc
                return
            rc = self._proc.returncode
            if rc == 0 or self._stop.is_set():
                break
            if not re.search(r"busy|hackrf_open", err or "", re.I):
                break
        elapsed = (time.time() - t0) if t0 else 0.0
        if self._stop.is_set():
            self._error = "capture cancelled"
            self._discard()
            return
        have = os.path.getsize(self._path) if os.path.exists(self._path) else 0
        if self._proc is None or self._proc.returncode != 0 or have == 0:
            lines = [ln.strip() for ln in (err or "").splitlines() if ln.strip()]
            bad = [ln for ln in lines if re.search(r"fail|error|not found|busy", ln, re.I)]
            self._error = ((bad or lines or ["hackrf_transfer exited rc=%s" % (
                self._proc.returncode if self._proc else "?")])[-1])[:200]
            self._discard()
            return
        # hackrf_transfer always writes the full sample count; a disk that cannot
        # keep up shows as a capture that took much longer than it should.
        if elapsed > self._seconds * 1.3 + 1.5:
            self._warning = ("took %.1f s for %.1f s of samples — the disk may not have kept "
                             "up; try a lower sample rate (zoom in)" % (elapsed, self._seconds))
        try:
            self._write_meta(have)
            self._done = True
        except OSError as exc:
            self._error = "capture saved but metadata write failed: %s" % exc

    def _write_meta(self, nbytes):
        import hashlib
        import json
        plan, g = self._plan, self._gains
        h = hashlib.sha512()
        with open(self._path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        dt_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._started))
        try:                                   # share the RTL-SDR's SigMF writer + GPS fix
            import rtl_sdr as _rtl
            meta = _rtl.sigmf_meta(plan["lo_hz"], plan["sr_hz"], datatype="ci8",
                                   hw="HackRF One", sha512=h.hexdigest(), dt_iso=dt_iso,
                                   label=self._label, position=_rtl.current_position())
        except Exception:
            cap = {"core:sample_start": 0, "core:frequency": float(plan["lo_hz"]),
                   "core:datetime": dt_iso}
            meta = {"global": {"core:datatype": "ci8", "core:sample_rate": float(plan["sr_hz"]),
                               "core:version": "1.0.0", "core:hw": "HackRF One",
                               "core:sha512": h.hexdigest()},
                    "captures": [cap], "annotations": []}
            if self._label:
                meta["annotations"].append({"core:sample_start": 0, "core:label": str(self._label)})
        glob = meta["global"]
        glob["core:recorder"] = "Ragnar sdr_spectrum.py (hackrf_transfer)"
        glob["ragnar:hackrf_lna_db"] = g["lna"]
        glob["ragnar:hackrf_vga_db"] = g["vga"]
        glob["ragnar:hackrf_amp"] = g["amp"]
        glob["ragnar:hackrf_antenna_power"] = g["antenna"]
        glob["ragnar:target_hz"] = plan["target_hz"]
        glob["ragnar:lo_offset_hz"] = plan["offset_hz"]
        meta["annotations"].append({
            "core:sample_start": 0, "core:sample_count": nbytes // 2,
            "core:freq_lower_edge": float(plan["want_lo_hz"]),
            "core:freq_upper_edge": float(plan["want_hi_hz"]),
            "core:label": "requested window (LO tuned %d kHz above the target to keep "
                          "the DC spike off it)" % round(plan["offset_hz"] / 1e3)})
        with open(self._path[:-len(".sigmf-data")] + ".sigmf-meta", "w") as fh:
            json.dump(meta, fh, indent=2)

    def _discard(self):
        try:
            if self._path and os.path.exists(self._path):
                os.remove(self._path)
        except OSError:
            pass

    def stop(self):
        self._stop.set()
        p = self._proc
        if p is not None and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
        return {"ok": True}

    def status(self):
        with self._lock:
            have = 0
            try:
                if self._path and os.path.exists(self._path):
                    have = os.path.getsize(self._path)
            except OSError:
                have = 0
            plan = self._plan or {}
            pct = int(min(100, have * 100 / self._want_bytes)) if self._want_bytes else 0
            return {"capturing": self.busy(), "name": self._name, "done": self._done,
                    "error": self._error, "warning": self._warning,
                    "center_hz": plan.get("lo_hz"), "target_hz": plan.get("target_hz"),
                    "sr_hz": plan.get("sr_hz"), "seconds": self._seconds,
                    "bytes": have, "want_bytes": self._want_bytes, "progress": pct}


_iqcap = HackrfIqCapture()


def iq_capture_start(center_hz, span_hz=None, seconds=2.0, name=None, label=None,
                     lna=None, vga=None, amp=None, antenna=None):
    """Record raw IQ around ``center_hz`` to SigMF. Pauses the sweep (one radio)."""
    return _iqcap.start(center_hz, span_hz=span_hz, seconds=seconds, name=name,
                        label=label, lna=lna, vga=vga, amp=amp, antenna=antenna)


def iq_capture_status():
    return _iqcap.status()


def iq_capture_stop():
    return _iqcap.stop()


# --------------------------------------------------------------------------
# Self-test (pure parsing / frame-assembly checks — no hardware needed)
# --------------------------------------------------------------------------

def _sweep_rows(lo_hz, hi_hz, step_hz, bin_hz, dbfn):
    """Synthesize ascending hackrf_sweep rows for one full band sweep."""
    rows = []
    f = lo_hz
    while f < hi_hz:
        n = int(step_hz // bin_hz)
        dbs = [dbfn(f + (i + 0.5) * bin_hz) for i in range(n)]
        rows.append("2024-01-01, 00:00:00.0, %d, %d, %.2f, 20, %s" %
                    (f, f + step_hz, bin_hz, ", ".join("%.1f" % x for x in dbs)))
        f += step_hz
    return rows


def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    # --- line parser ---
    row = "2024-01-01, 12:00:00.0, 2400000000, 2405000000, 250000.00, 20, -55.1, -60.2, -48.9"
    p = parse_sweep_line(row)
    check("parse: valid row -> (lo,hi,binhz,dbs)",
          p is not None and p[0] == 2400000000 and p[1] == 2405000000
          and abs(p[2] - 250000.0) < 1e-6 and len(p[3]) == 3, str(p))
    check("parse: header/garbage -> None",
          parse_sweep_line("date, time, hz_low, hz_high") is None
          and parse_sweep_line("") is None)
    check("parse: too-few dB columns -> None",
          parse_sweep_line("d, t, 2400000000, 2405000000, 250000, 20") is None)

    # --- frame builder bucketing + wrap detection ---
    lo, hi = 2400, 2500
    # A single tone at 2450 MHz should light exactly one display bucket high.
    def db_tone(hz):
        return -20.0 if abs(hz - 2_450_000_000) < 250000 else -95.0
    rows = (_sweep_rows(2400_000000, 2500_000000, 5_000000, 250000, db_tone)
            + _sweep_rows(2400_000000, 2500_000000, 5_000000, 250000, db_tone))
    fb = _FrameBuilder(lo, hi)
    frames = []
    for r in rows:
        fr = fb.add(*parse_sweep_line(r))
        if fr is not None:
            frames.append(fr)
    check("frame: one full frame emitted after the second sweep starts",
          len(frames) == 1, str(len(frames)))
    if frames:
        g = frames[0]
        peak_bin = max(range(len(g)), key=lambda i: g[i])
        # 2450 is the middle of 2400-2500 -> bucket ~ half of _GRID_BINS.
        check("frame: tone lands in the mid band bucket",
              abs(peak_bin - _GRID_BINS // 2) <= 2, str(peak_bin))
        check("frame: tone bucket is strong, elsewhere at/near floor",
              g[peak_bin] >= -25 and sum(1 for v in g if v <= -90) > _GRID_BINS * 0.5)
        check("frame: grid width = display bins", len(g) == _GRID_BINS)

    # --- empty band edges stay at floor ---
    fb2 = _FrameBuilder(2400, 2500)
    for r in (_sweep_rows(2400_000000, 2500_000000, 5_000000, 250000, lambda h: -100.0)
              + _sweep_rows(2400_000000, 2500_000000, 5_000000, 250000, lambda h: -100.0)):
        fb2.add(*parse_sweep_line(r))
    check("frame: bucket out of band ignored", fb2._bucket(2_600_000_000) is None)
    check("frame: bucket at band low = 0", fb2._bucket(2_400_000_000) == 0)

    # --- TX pilot-tone IQ buffer (pure; no device) ---
    try:
        import numpy as _np
        raw, emitted = tone_iq_cs8(2_000_000, 8_000_000, dur_s=0.05)
        buf = _np.frombuffer(raw, dtype=_np.int8)
        check("tone: interleaved IQ is 2 int8 per sample", len(buf) % 2 == 0 and len(buf) > 0)
        iqc = buf[0::2].astype(_np.float32) + 1j * buf[1::2].astype(_np.float32)
        # the dominant FFT bin must sit at the requested +2 MHz of 8 MS/s
        sp = _np.fft.fftshift(_np.abs(_np.fft.fft(iqc)))
        fb = _np.fft.fftshift(_np.fft.fftfreq(len(iqc), 1.0 / 8_000_000))
        peak_hz = float(fb[int(_np.argmax(sp))])
        check("tone: spectral peak at +2 MHz offset", abs(peak_hz - 2_000_000) < 60_000,
              "%.0f Hz" % peak_hz)
        check("tone: emitted offset within 1%% of requested", abs(emitted - 2_000_000) < 20_000,
              "%d Hz" % emitted)
        check("tone: amplitude within int8 range", int(buf.max()) <= 127 and int(buf.min()) >= -127)
    except Exception as _exc:   # pragma: no cover - numpy always present in app
        check("tone: IQ buffer generation", False, str(_exc))

    # --- hackrf_info parser ---
    info = parse_hackrf_info(
        "hackrf_info version: 2024.02.1\nBoard ID Number: 2 (HackRF One)\n"
        "Firmware Version: 2024.02.1 (API:1.08)\nSerial number: 0000abcd12345678")
    check("info: serial parsed", info["serial"] == "0000abcd12345678", str(info))
    check("info: board parsed", info["board"] == "HackRF One", str(info["board"]))
    check("info: firmware parsed", "2024.02.1" in (info["firmware"] or ""))
    # sweep command: gains, amp / antenna power, resolution override
    c, bw = sweep_cmd(2400, 2500, 24, 20)
    check("cmd: default has gains, no amp/antenna power",
          c[c.index("-l") + 1] == "24" and c[c.index("-g") + 1] == "20" and "-a" not in c and "-p" not in c)
    c, bw = sweep_cmd(2400, 2500, 32, 40, amp=True, antenna=True, bin_hz=100000)
    check("cmd: amp + antenna power + explicit RBW", "-a" in c and "-p" in c and bw == 100000)
    check("cmd: RBW clamped to hackrf_sweep range", sweep_cmd(2400, 2500, 0, 0, bin_hz=5)[1] == 2445)
    check("cmd: auto RBW finer than a display column",
          sweep_cmd(433, 435, 24, 20)[1] <= (2e6 / _GRID_BINS))

    # --- max-hold accumulation ---
    cap = SweepCapture()
    cap._maxhold = None
    cap._push_frame([-90] * _GRID_BINS)
    cap._push_frame([-90] * (_GRID_BINS - 1) + [-30])
    check("maxhold: peak retained across frames",
          cap._maxhold[-1] == -30 and cap._maxhold[0] == -90)
    check("maxhold: two frames buffered with rising seq",
          len(cap._frames) == 2 and cap._frames[1]["seq"] == 2)
    fr = cap.get_frames(since=1)
    check("frames: since-filter returns only newer", len(fr["frames"]) == 1
          and fr["frames"][0]["seq"] == 2)

    # --- display-dwell coalescing (max-hold across sweeps in one frame) ---
    acc = _merge_max(None, [-90, -90, -90])
    check("coalesce: None seed copies the frame",
          acc == [-90, -90, -90] and acc is not None)
    acc = _merge_max(acc, [-90, -30, -90])
    acc = _merge_max(acc, [-40, -95, -90])
    check("coalesce: keeps the per-bucket peak across sweeps",
          acc == [-40, -30, -90], str(acc))

    # --- row scheduler: exact rate on a fast band, one row per slow sweep ---
    def _sim(period, secs, interval=0.05):
        t, nxt, stamps, comp = 1000.0, 1000.0 + interval, [], []
        while t < 1000.0 + secs:
            t += period
            push, stamp, nxt = _dwell_tick(nxt, t, interval)
            if push:
                stamps.append(stamp); comp.append(t)
        return stamps, comp
    st, cp = _sim(0.0166, 10.0)            # 2.4 GHz band: a sweep every ~16.6 ms
    gaps = [round(b - a, 6) for a, b in zip(st, st[1:])]
    check("dwell: fast band emits exactly 20 rows/s", 198 <= len(st) <= 200, str(len(st)))
    check("dwell: fast-band rows evenly stamped", set(gaps) == {0.05}, str(sorted(set(gaps))[:5]))
    check("dwell: stamp within one sweep of the sweep that completed it",
          all(0 <= c - s < 0.0166 + 1e-9 for s, c in zip(st, cp)))
    st, cp = _sim(0.12, 3.0)               # wide 5/6 GHz span: slower than the grid
    check("dwell: slow sweeps give one row each, stamped at completion, no burst",
          len(st) == len(cp) == 25 and st == cp, str(len(st)))
    check("dwell: no row before the grid tick", _dwell_tick(10.0, 9.99, 0.05)[0] is False)

    # --- raw-IQ capture plan: span kept inside the baseband filter, off DC ---
    p = iq_plan(433_920_000, 2_000_000)
    check("iqplan: 2 MHz span -> 6 MS/s, LO 1.2 MHz above the target",
          p["sr_hz"] == 6_000_000 and p["lo_hz"] == 435_120_000, str(p))
    check("iqplan: whole span inside LO +/- 0.375 sr (default baseband filter)",
          p["want_lo_hz"] >= p["lo_hz"] - 0.375 * p["sr_hz"]
          and p["want_hi_hz"] <= p["lo_hz"] + 0.375 * p["sr_hz"], str(p))
    check("iqplan: DC spike (the LO) outside the requested window",
          not (p["want_lo_hz"] <= p["lo_hz"] <= p["want_hi_hz"])
          and p["lo_hz"] - p["want_hi_hz"] >= 0.03 * p["sr_hz"], str(p))
    check("iqplan: span covered", p["want_hi_hz"] - p["want_lo_hz"] >= 2_000_000, str(p))
    p = iq_plan(2_440_000_000, 100_000_000)
    check("iqplan: wide view clamps to 20 MS/s around the target",
          p["sr_hz"] == 20_000_000 and p["want_lo_hz"] < 2_440_000_000 < p["want_hi_hz"], str(p))
    p = iq_plan(915_000_000, None)
    check("iqplan: no span -> 2 MS/s floor", p["sr_hz"] == 2_000_000, str(p))
    check("iqplan: capture names are path-safe", _iq_safe("../../etc/x y") == "etc_x_y",
          _iq_safe("../../etc/x y"))

    # --- status() must not re-probe the HackRF while a sweep is streaming ---
    # Opening hackrf_info over USB during a live sweep knocks it offline a few
    # seconds in; status() must report availability from cache instead. Fake a
    # running capture and assert detect() is never called.
    import sys as _sys
    _mod = _sys.modules[__name__]
    _saved_status, _saved_detect = _capture.status, _mod.detect
    _probe_calls = []
    _capture._detect_cache = {"board": "HackRF One"}
    _capture.status = lambda: {"running": True, "band": "2.4", "error": None}
    _mod.detect = lambda *a, **k: (_probe_calls.append(1) or {"available": False})
    try:
        _st = status()
        check("status: no HackRF re-probe while streaming",
              not _probe_calls and _st["detect"].get("streaming") is True
              and _st["detect"].get("available") is True, str(_st["detect"]))
    finally:
        _capture.status, _mod.detect = _saved_status, _saved_detect
        _capture._detect_cache = None

    # --- band table ---
    check("bands: 2.4 and 5 present", "2.4" in BANDS and "5" in BANDS)
    check("bands: sub-GHz scopes mirrored from RTL (fm/air/433/915)",
          all(b in BANDS for b in ("am", "sw", "fm", "air", "27", "40",
                                   "315", "433", "868", "915")))
    check("bands: AM clamped to HackRF's 1 MHz floor", BANDS["am"][0] >= 1.0)

    # --- narrow-span widening (mesh overlays / manual tune) ---
    _wlo, _whi = _widen_span(869.3, 869.75)     # 0.45 MHz Meshtastic-EU868
    check("widen: narrow span grown to >= min sweep",
          _whi - _wlo >= _MIN_SWEEP_MHZ - 1e-9 and _wlo >= 1.0)
    check("widen: wide span left untouched", _widen_span(2400.0, 2500.0) == (2400.0, 2500.0))
    check("widen: stays above the 1 MHz floor", _widen_span(1.0, 1.71)[0] >= 1.0)

    # --- no floor streaks: a widened narrow span fills every display column ---
    _fb = _FrameBuilder(100.0, 102.0)           # 2 MHz display window
    _bw = 2500                                  # hackrf_sweep FFT floor (Hz/bin)
    _segs = [(95_000_000, 100_000_000), (100_000_000, 105_000_000)]  # 2 lines/sweep
    def _sweep():
        _f = None
        for _slo, _shi in _segs:
            _r = _fb.add(_slo, _shi, _bw, [-50.0] * ((_shi - _slo) // _bw))
            if _r is not None:
                _f = _r
        return _f
    _sweep()                                    # first sweep fills the grid
    _frame = _sweep()                           # wrap completes + returns frame 1
    check("fill: widened narrow span leaves no floor-streak columns",
          _frame is not None and all(v > _FLOOR_DBM for v in _frame))

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import argparse
    import json
    ap = argparse.ArgumentParser(description="HackRF true-RF spectrum / waterfall")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("detect")
    ps = sub.add_parser("sweep")
    ps.add_argument("--band", default="2.4", choices=sorted(BANDS.keys()))
    ps.add_argument("--frames", type=int, default=5)
    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if args.cmd == "detect":
        print(json.dumps(detect(), indent=2))
    elif args.cmd == "sweep":
        d = detect()
        if not d.get("available"):
            print(json.dumps({"error": d.get("error")}, indent=2))
            return 1
        start(args.band)
        seen = 0
        last = 0
        try:
            while seen < args.frames:
                time.sleep(0.4)
                fr = get_frames(since=last)
                for f in fr["frames"]:
                    last = f["seq"]
                    seen += 1
                    strong = max(range(len(f["power"])), key=lambda i: f["power"][i])
                    print("frame %d: peak bucket %d @ %d dBm" %
                          (f["seq"], strong, f["power"][strong]))
        finally:
            stop()
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
