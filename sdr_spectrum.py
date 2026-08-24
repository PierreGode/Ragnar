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
_DISPLAY_HZ = 10          # waterfall rows emitted per second (steady scroll rate)
_DISPLAY_INTERVAL = 1.0 / _DISPLAY_HZ


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
    def start(self, band="2.4", lna=None, vga=None, lo_mhz=None, hi_mhz=None):
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
        sig = (label, round(lo, 3), round(hi, 3))
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
            self._lna = _clamp(lna, 0, 40, _DEFAULT_LNA)
            self._vga = _clamp(vga, 0, 62, _DEFAULT_VGA)
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
        span_hz = (hi - lo) * 1_000_000
        bin_hz = int(span_hz / (_GRID_BINS * 2)) or _BIN_WIDTH_HZ
        bin_hz = max(2500, min(_BIN_WIDTH_HZ, bin_hz))
        builder = _FrameBuilder(lo, hi)           # [lo, hi] already widened in start()
        # +1 on the top edge so hackrf_sweep always sees max > min after MHz
        # truncation (the span is >= _MIN_SWEEP_MHZ, so this never inverts).
        cmd = [_HACKRF_SWEEP, "-f", "%d:%d" % (int(lo), int(hi) + 1),
               "-w", str(bin_hz), "-l", str(self._lna),
               "-g", str(self._vga)]
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
        last_push = time.time()
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
                now = time.time()
                if now - last_push >= _DISPLAY_INTERVAL:
                    self._push_frame(accum)
                    accum = None
                    last_push = now
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

    # -- readers -----------------------------------------------------------
    def status(self):
        with self._lock:
            running = bool(self._thread and self._thread.is_alive())
            return {"running": running, "band": self._band,
                    "frames_buffered": len(self._frames), "seq": self._seq,
                    "bins": _GRID_BINS, "lna": self._lna, "vga": self._vga,
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


def start(band="2.4", lna=None, vga=None, lo_mhz=None, hi_mhz=None):
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "no SDR")}
    _capture._detect_cache = d
    return _capture.start(band, lna=lna, vga=vga, lo_mhz=lo_mhz, hi_mhz=hi_mhz)


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
    else:
        st["detect"] = detect()
    return st


def get_frames(since=0):
    return _capture.get_frames(since)


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

    # --- hackrf_info parser ---
    info = parse_hackrf_info(
        "hackrf_info version: 2024.02.1\nBoard ID Number: 2 (HackRF One)\n"
        "Firmware Version: 2024.02.1 (API:1.08)\nSerial number: 0000abcd12345678")
    check("info: serial parsed", info["serial"] == "0000abcd12345678", str(info))
    check("info: board parsed", info["board"] == "HackRF One", str(info["board"]))
    check("info: firmware parsed", "2024.02.1" in (info["firmware"] or ""))

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
