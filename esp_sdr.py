#!/usr/bin/env python3
"""
esp_sdr.py — True-RF spectrum + waterfall capture via an ESP-SDR node.

The fourth radio behind Ragnar's Waterfall. Where :mod:`sdr_spectrum` drives a
HackRF (``hackrf_sweep``) and :mod:`rtl_sdr` an RTL-SDR (``rtl_power``), this
talks to an **ESP32 running the ESP-SDR firmware** (https://espargos.net/espsdr/).

ESP-SDR exploits an undocumented debug path in the ESP32's Wi-Fi radio to dump
raw I/Q, and the firmware can fold it into **on-chip FFT power spectra** that it
streams over the chip's native USB Serial/JTAG link. That is exactly the shape a
waterfall wants — power per frequency bin — so this module speaks the firmware's
``SPEC`` protocol and hands the web layer the same frame contract the HackRF and
RTL backends use (``power`` per bin, ``band_mhz``, ``floor_dbm``).

Unlike the HackRF (which sweeps a wide range) the ESP captures one fixed FFT
*window* at a time — centre = ``FREQ``, span = the sample rate (16/40/80 MHz).
A named band selects a centre; a zoom narrows the span and drops to a lower
sample rate for finer resolution. On an ESP32-S3 the useful reception band is
roughly 2.2–2.7 GHz (the 2.4 GHz ISM band), with software tuning attempts
accepted 100–6000 MHz.

Everything here is **receive-only** — the firmware implements reception only.

Serial protocol (newline ASCII commands, binary ``SPC1`` frames)
----------------------------------------------------------------
    RELEASE                 -> OK          (claim the single-client lease)
    INFO                    -> "<chip> <proto> <mode> <maxsamples>"
    CAPS                    -> "CAPS ... SPEC SPECCAPS ..."
    SPECINFO?               -> "SPECINFO <json profiles>"
    LIMITS?/RANGE?          -> gain/bandwidth/rate limits, tuning range
    FREQ <MHz> / BANDWIDTH <MHz> / GAIN HARDWARE|MANUAL <i>
    SPEC <ms> <stride> <units> <detector> <rate_code> <fft_bins>
        ms=0 streams until a stop byte; start reply:
        "SPEC <bins> <sample_rate_hz> <unit_pairs> <centre_MHz>"
    <SPC1 binary frames...>  then on a stop byte: "SPECEND <12 fields>"

Each ``SPC1`` frame: ``SPC1`` magic, seq, sample index, flags, log2(bins),
a dB-code multiplier, then one power code per bin, then a CRC32. A power code
is ``20*log10`` in the normalised Q15 FFT domain; the ESP-WebSDR viewer maps it
to dBFS as ``code/mult - 84.3`` with the firmware bin for display column ``j``
at ``(bins/2 - j + bins) % bins`` (an fftshift plus the I/Q axis flip). We do
the same so the trace reads low→high frequency, DC in the middle.

CLI
---
    python3 esp_sdr.py detect
    python3 esp_sdr.py spectrum [--band 2.4] [--freq 2442] [--seconds N]
    python3 esp_sdr.py selftest
"""

import json
import os
import struct
import sys
import threading
import time
import zlib

try:                                    # pyserial is the only hard dependency
    import serial
    from serial.tools import list_ports
    _SERIAL_ERR = None
except Exception as _exc:               # pragma: no cover - import guard
    serial = None
    list_ports = None
    _SERIAL_ERR = str(_exc)


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
_ESP_VID = 0x303A                       # Espressif USB JTAG/serial debug unit
_BAUD = 2_000_000                       # native USB ignores it; UART uses 2 Mbaud
_FFT_BINS = 512                         # display columns per frame (RBW = fs/N)
_RING_FRAMES = 600                      # rolling history kept in memory
_FLOOR_DBFS = -85                       # colour-scale bottom: just below code 0 (-84.3 dBFS)
_DBFS_OFFSET = 84.3                     # ESP-WebSDR normalisation: dBFS = code/mult - 84.3
_DETECTOR = 1                           # 1 = per-frame max-hold (0 = mean)
# The firmware streams on-chip FFTs at hundreds of frames/s on a fixed window
# (no retuning), so unlike the sweeping HackRF/RTL backends (~10/s) the ESP can
# scroll near the browser's ~60 fps refresh ceiling. Push at this rate,
# max-holding the few firmware frames that land in each row so bursts still show.
_DISPLAY_HZ = 50                        # waterfall rows emitted per second
_DISPLAY_INTERVAL = 1.0 / _DISPLAY_HZ

# Sample-rate code -> nominal Hz (ESP32-S3 advertises 80/40/16 MS/s).
_RATES = {0: 80_000_000, 1: 40_000_000, 6: 16_000_000}

# Named bands -> (centre MHz, rate code). Zoom overrides both. The S3 receives
# well across ~2.2-2.7 GHz; wider attempts are accepted but uncalibrated.
BANDS = {
    "2.4":  (2442, 0),      # 80 MS/s -> 2402-2482, the whole 2.4 GHz ISM band
    "2.45": (2450, 1),      # 40 MS/s -> 2430-2470, finer RBW mid-band
    "2.3":  (2300, 1),      # 40 MS/s lower-edge probe
    "2.6":  (2600, 1),      # 40 MS/s (LTE band 7 downlink)
}
_DEFAULT_BAND = "2.4"

# Fallback stride / units_per_frame when SPECINFO can't be read (offline tests).
# The firmware's SPECINFO is authoritative and used when present.
_STRIDE_UNITS = {
    (6, 256): (2, 1), (6, 512): (2, 2), (6, 1024): (2, 4), (6, 2048): (3, 7),
    (1, 256): (5, 3), (1, 512): (5, 5), (1, 1024): (5, 9), (1, 2048): (7, 17),
    (0, 256): (10, 6), (0, 512): (12, 10), (0, 1024): (14, 19), (0, 2048): (18, 36),
}

_LEASE_TIMEOUT = 5.0                    # seconds to acquire the serial lease
_CMD_TIMEOUT = 2.0                      # seconds to read a text reply

# Frequency trim (FOFS). The ESP32 has no TCXO; its crystal runs a few ppm off
# and drifts with temperature. The S3/S31 firmware accepts `FOFS <kHz>` — a PLL
# offset applied at the LO (verified 1:1 in kHz: +FOFS shifts the spectrum up by
# that many kHz). We null the drift against the ever-present 2.4 GHz Wi-Fi
# channel centres (1/6/11 = 2412/2437/2462 MHz), which also tracks temperature.
_WIFI_CH = {1: 2412.0, 6: 2437.0, 11: 2462.0}   # non-overlapping 2.4 GHz centres (MHz)
_FOFS_LIMIT = 2000                      # clamp |FOFS| to +-2 MHz (crystal is <<100 kHz)
_FOFS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "data", "esp_sdr_fofs.json")


def _load_fofs():
    """Last calibrated FOFS (kHz), persisted across restarts. 0 if unknown."""
    try:
        with open(_FOFS_FILE) as f:
            return int(json.load(f).get("fofs_khz", 0))
    except Exception:
        return 0


def _save_fofs(khz):
    try:
        os.makedirs(os.path.dirname(_FOFS_FILE), exist_ok=True)
        with open(_FOFS_FILE, "w") as f:
            json.dump({"fofs_khz": int(khz)}, f)
    except Exception:
        pass


def _fofs_supported(ident):
    """FOFS is implemented on the S3 and S31 burst firmware."""
    return bool(ident) and str(ident.get("chip", "")).upper().startswith("S3")


def _resample(power, lo_mhz, hi_mhz, g_lo, g_hi, m):
    """Linear-interpolate power[] (over [lo,hi] MHz) onto m points over [g_lo,g_hi]."""
    n = len(power)
    span = hi_mhz - lo_mhz
    gstep = (g_hi - g_lo) / m
    out = [0.0] * m
    for k in range(m):
        x = (g_lo + (k + 0.5) * gstep - lo_mhz) / span * n - 0.5    # fractional bin
        if x <= 0:
            out[k] = power[0]
        elif x >= n - 1:
            out[k] = power[n - 1]
        else:
            i = int(x)
            t = x - i
            out[k] = power[i] * (1 - t) + power[i + 1] * t
    return out


def _xcorr_offset(a, a_lo, a_hi, b, b_lo, b_hi, max_khz=300.0, g_khz=25.0):
    """Frequency offset (kHz) of spectrum `a` relative to reference `b`.

    Both are resampled onto a common grid over their overlap and cross-correlated
    (mean-removed, normalised). The lag of peak correlation is where `a` shows a
    feature that `b` (the truth, e.g. a TCXO HackRF) has `offset` lower — i.e.
    `offset = a_apparent − b_true`, the same convention as `_wifi_offset`. Returns
    {offset_khz, corr, overlap_mhz} (`corr` is the peak coefficient, −1..1) or None.
    """
    c_lo = max(a_lo, b_lo) + 1.0
    c_hi = min(a_hi, b_hi) - 1.0
    if c_hi - c_lo < 20.0:
        return None
    m = int((c_hi - c_lo) * 1000.0 / g_khz)
    if m < 32:
        return None
    ag = _resample(a, a_lo, a_hi, c_lo, c_hi, m)
    bg = _resample(b, b_lo, b_hi, c_lo, c_hi, m)
    # Equalise resolution: a cross-correlation shift is only unbiased when both
    # spectra have the same effective bin width. Box-smooth both to the coarser
    # radio's resolution (the HackRF's bins are wider than the ESP's).
    a_bw = (a_hi - a_lo) / len(a) * 1000.0
    b_bw = (b_hi - b_lo) / len(b) * 1000.0
    w = int(round(max(a_bw, b_bw) / g_khz))
    if w >= 2:
        def _box(v, k):
            h = k // 2
            pre = [0.0]
            for x in v:
                pre.append(pre[-1] + x)
            return [(pre[min(len(v), i + h + 1)] - pre[max(0, i - h)]) /
                    (min(len(v), i + h + 1) - max(0, i - h)) for i in range(len(v))]
        ag = _box(ag, w)
        bg = _box(bg, w)
    ma, mb = sum(ag) / m, sum(bg) / m
    ag = [x - ma for x in ag]
    bg = [x - mb for x in bg]
    na = sum(x * x for x in ag) ** 0.5
    nb = sum(x * x for x in bg) ** 0.5
    if na == 0 or nb == 0:
        return None
    maxlag = int(max_khz / g_khz)
    coeffs = {}
    best_lag, best_c = 0, -2.0
    for lag in range(-maxlag, maxlag + 1):
        s = 0.0
        lo_k = max(0, lag)
        hi_k = min(m, m + lag)
        for k in range(lo_k, hi_k):
            s += ag[k] * bg[k - lag]
        c = s / (na * nb)
        coeffs[lag] = c
        if c > best_c:
            best_c, best_lag = c, lag
    sub = float(best_lag)                               # parabolic sub-bin peak
    if -maxlag < best_lag < maxlag:
        y0, y1, y2 = coeffs[best_lag - 1], coeffs[best_lag], coeffs[best_lag + 1]
        denom = y0 - 2 * y1 + y2
        if denom != 0:
            sub = best_lag + 0.5 * (y0 - y2) / denom
    return {"offset_khz": sub * g_khz, "corr": round(best_c, 3),
            "overlap_mhz": round(c_hi - c_lo, 1)}


def _wifi_offset(power, lo_mhz, hi_mhz):
    """Median frequency offset (kHz) of the 2.4 GHz Wi-Fi channels in view.

    The whole spectrum shifts uniformly with crystal error, so each occupied
    20 MHz channel's measured centre sits off its nominal centre by that error.
    We take the midpoint of the channel's −18 dB edges (robust to asymmetric
    traffic on a filled channel) and median across the channels present.
    Returns {offset_khz, channels, n} or None if nothing usable is in view.
    """
    n = len(power)
    if n < 16 or not (hi_mhz > lo_mhz):
        return None
    span = hi_mhz - lo_mhz
    freq = lambda i: lo_mhz + (i + 0.5) * span / n
    floor = sorted(power)[n // 5]                        # global 20th-pct noise floor
    found = []
    for ch, fc in _WIFI_CH.items():
        if fc < lo_mhz + 12 or fc > hi_mhz - 12:        # whole +-11 MHz window must fit (skip edge channels)
            continue
        win = [i for i in range(n) if abs(freq(i) - fc) <= 11.0]
        if len(win) < 8:
            continue
        peak = max(power[i] for i in win)
        if peak - floor < 12:                           # channel not clearly occupied
            continue
        # -10 dB edges of the strong central plateau. On an AVERAGED spectrum the
        # noise floor is low and stable, so a peak-relative threshold catches the
        # channel's ~20 MHz occupancy while rejecting lower adjacent-channel
        # bleed; its edges cross near +-10 MHz and the midpoint is the centre.
        thr = peak - 10.0
        wi = sorted(win)                                # ascending freq
        # Interpolate the exact edge crossings for sub-bin centre precision.
        left = right = None
        for k in range(1, len(wi)):
            if power[wi[k]] >= thr and power[wi[k - 1]] < thr:
                p0, p1 = power[wi[k - 1]], power[wi[k]]
                t = (thr - p0) / (p1 - p0) if p1 != p0 else 0.5
                left = freq(wi[k - 1]) + t * (freq(wi[k]) - freq(wi[k - 1]))
                break
        for k in range(len(wi) - 2, -1, -1):
            if power[wi[k]] >= thr and power[wi[k + 1]] < thr:
                p0, p1 = power[wi[k]], power[wi[k + 1]]
                t = (thr - p0) / (p1 - p0) if p1 != p0 else 0.5
                right = freq(wi[k]) + t * (freq(wi[k + 1]) - freq(wi[k]))
                break
        if left is None or right is None:
            continue
        width = right - left
        if not (15.0 <= width <= 24.0):                 # not a clean ~20 MHz channel (contaminated/partial)
            continue
        off = ((left + right) / 2.0 - fc) * 1000.0      # kHz
        if abs(off) <= 250:                             # sanity: crystal error is < ~100 kHz
            found.append((ch, off, round(width, 1)))
    if not found:
        return None
    vals = sorted(o[1] for o in found)
    spread = vals[-1] - vals[0]
    median = vals[len(vals) // 2]
    # Trust the measurement ONLY when at least two channels agree closely and the
    # result is within the physical crystal limit (~+-100 kHz at 2.44 GHz / ~40
    # ppm). A single channel can be skewed by an overlapping neighbour, so never
    # apply a correction off one — congested 2.4 GHz is easily contaminated.
    confident = (len(found) >= 2 and spread <= 40.0 and abs(median) <= 100.0)
    return {"offset_khz": median, "channels": [o[0] for o in found],
            "widths_mhz": [o[2] for o in found], "spread_khz": round(spread, 1),
            "n": len(found), "confident": confident}


# --------------------------------------------------------------------------
# Low-level serial helpers
# --------------------------------------------------------------------------
def _esp_ports():
    """Return candidate serial devices, Espressif-VID first, env override at the front."""
    ports = []
    env = os.environ.get("RAGNAR_ESP_SDR_PORT")
    if env:
        ports.append(env)
    if list_ports is not None:
        for p in list_ports.comports():
            if p.device in ports:
                continue
            if (p.vid == _ESP_VID) or (p.device and "ttyACM" in p.device):
                ports.append(p.device)
    return ports


def _open(dev, timeout=_CMD_TIMEOUT):
    """Open a port without touching DTR/RTS (toggling them resets the ESP32)."""
    port = serial.Serial(port=None, baudrate=_BAUD, timeout=timeout)
    port.dtr = False
    port.rts = False
    port.port = dev
    try:
        port.exclusive = True           # keep other clients off while we own it
    except Exception:
        pass
    port.open()
    return port


def _sync_lease(port, timeout=_LEASE_TIMEOUT):
    """Claim the firmware's single-client lease; True once it answers OK.

    Each ``RELEASE`` also serves as a SPEC stop byte, so a few writes both end
    any stream a crashed client left running and release the lease. A short
    timeout keeps discovery from stalling on a non-SDR Espressif port (e.g. a
    GPS node) that never answers OK.
    """
    old = port.timeout
    port.timeout = 0.2
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            try:
                # The leading newlines double as SPEC stop bytes, so this also
                # ends a stream a crashed/killed client left running. flush()
                # makes sure the stop byte goes out ahead of a big backlog. A
                # half-closed CDC endpoint can raise on read ("readiness but no
                # data"); keep nudging it until it drains and answers OK.
                port.write(b"\n\nRELEASE\n")
                try:
                    port.flush()
                except Exception:
                    pass
                if port.readline().strip() == b"OK":
                    return True
            except serial.SerialException:
                time.sleep(0.15)
        return False
    finally:
        port.timeout = old
        try:
            port.reset_input_buffer()
        except Exception:
            pass


def _drain_quiet(port, quiet=0.12, max_time=1.2):
    """Read and discard until the link goes quiet, settling a just-stopped stream.

    After a wedged SPEC stream is stopped, residual frame/debug bytes keep
    arriving for a moment and corrupt the next INFO read; drain them first.
    """
    old = port.timeout
    port.timeout = quiet
    end = time.monotonic() + max_time
    try:
        while time.monotonic() < end:
            try:
                if not port.read(4096):
                    return
            except serial.SerialException:
                time.sleep(0.05)
    finally:
        port.timeout = old


def _cmd(port, text):
    """Send one newline-terminated command and return the stripped text reply."""
    try:
        port.reset_input_buffer()
    except Exception:
        pass
    port.write((text + "\n").encode("ascii"))
    return port.readline().decode("ascii", "replace").strip()


def _is_esp_sdr(info, caps):
    """An ESP-SDR node answers INFO with an 'SDR' identity and advertises SPEC."""
    return ("SDR" in (info or "")) and ("SPEC" in (caps or "").split())


def _probe_once(dev):
    """One probe attempt on a fresh port. Returns an identity dict or None."""
    port = None
    try:
        port = _open(dev, timeout=_CMD_TIMEOUT)
        if not _sync_lease(port, timeout=3.0):
            return None
        _drain_quiet(port)                      # settle a just-stopped stream
        info = _cmd(port, "INFO")
        caps = _cmd(port, "CAPS")
        if not _is_esp_sdr(info, caps):
            # Residual bytes from a wedged stream can spoil the first INFO; a
            # fresh lease sync + drain settles it, still on this same open port.
            if not _sync_lease(port, timeout=3.0):
                return None
            _drain_quiet(port)
            info = _cmd(port, "INFO")
            caps = _cmd(port, "CAPS")
            if not _is_esp_sdr(info, caps):
                return None
        rng = _cmd(port, "RANGE?")
        lim = _cmd(port, "LIMITS?")
        spec = _cmd(port, "SPECINFO?")
        _cmd(port, "RELEASE")
        out = {"port": dev, "info": info, "caps": caps.split()}
        parts = info.split()
        out["chip"] = parts[0] if parts else "ESP-SDR"
        try:
            lo, hi = rng.split()[1:3]
            out["range_mhz"] = [int(lo), int(hi)]
        except Exception:
            out["range_mhz"] = [100, 6000]
        try:
            out["limits"] = json.loads(lim.split(" ", 1)[1])
        except Exception:
            out["limits"] = None
        try:
            out["profiles"] = json.loads(spec.split(" ", 1)[1]).get("profiles", [])
        except Exception:
            out["profiles"] = []
        return out
    except Exception:
        return None
    finally:
        if port is not None:
            try:
                port.close()
            except Exception:
                pass


def _probe(dev, attempts=2):
    """Probe a device for ESP-SDR firmware, reopening between tries.

    The first open right after another process released the port can land on a
    not-yet-ready link whose lease sync fails; a fresh reopen a moment later
    succeeds, so detection doesn't flicker 'not connected' for one poll.
    """
    for i in range(attempts):
        ident = _probe_once(dev)
        if ident:
            return ident
        if i + 1 < attempts:
            time.sleep(0.25)
    return None


# --------------------------------------------------------------------------
# Frame decoding
# --------------------------------------------------------------------------
def decode_spc1(frame, bins):
    """Decode one ``SPC1`` frame body into a display-ordered dBFS list.

    ``frame`` is the full ``SPC1`` + payload + CRC32 (``bins + 32`` bytes).
    Returns ``(dbfs_list, ok, ffts)`` — ``ok`` is the CRC verdict.
    """
    if len(frame) != bins + 32 or frame[:4] != b"SPC1":
        return None, False, 0
    crc_ok = zlib.crc32(frame[:-4]) == struct.unpack("<I", frame[-4:])[0]
    ffts = struct.unpack("<H", frame[20:22])[0]
    mult = frame[27] or 2               # dB-code multiplier (always 2 in practice)
    codes = frame[28:28 + bins]
    half = bins // 2
    inv = 1.0 / mult
    out = [_FLOOR_DBFS] * bins
    for j in range(bins):
        fb = (half - j + bins) % bins   # fftshift + I/Q axis flip (ESP-WebSDR order)
        v = codes[fb] * inv - _DBFS_OFFSET
        out[j] = v if v > _FLOOR_DBFS else float(_FLOOR_DBFS)
    return out, crc_ok, ffts


# --------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------
class EspCapture:
    """Own the ESP-SDR serial link, a ``SPEC`` stream, and a ring of frames."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop = threading.Event()
        self._frames = []               # list of {seq, ts, power:[int]}
        self._seq = 0
        self._maxhold = None
        self._error = None
        self._sig = None                # restart only on a real config change
        self._band = None
        self._center_mhz = None
        self._fs = None
        self._bins = _FFT_BINS
        self._rate_code = 0
        self._lo_mhz = None
        self._hi_mhz = None
        self._rbw_hz = None
        self._identity = None           # last good _probe() result
        self._port_dev = None
        self._running = False
        self._fofs = _load_fofs()       # frequency trim (kHz) sent on every start
        self._fofs_ok = False           # does the connected chip support FOFS?
        self._last_start = (_DEFAULT_BAND, None, None, None)  # for re-applying FOFS
        self._trim = None               # last auto-trim result

    # -- config resolution -------------------------------------------------
    def _resolve(self, band, lo_mhz, hi_mhz):
        """Map a band/zoom request to (label, centre MHz, rate_code)."""
        try:
            if lo_mhz is not None and hi_mhz is not None:
                lo_mhz, hi_mhz = float(lo_mhz), float(hi_mhz)
                if hi_mhz - lo_mhz >= 0.1 and 100 <= lo_mhz and hi_mhz <= 6000:
                    span = hi_mhz - lo_mhz
                    rate = 6 if span <= 16 else (1 if span <= 40 else 0)
                    center = round((lo_mhz + hi_mhz) / 2)
                    return "zoom", center, rate
        except (TypeError, ValueError):
            pass
        band = band if band in BANDS else _DEFAULT_BAND
        center, rate = BANDS[band]
        return band, center, rate

    # -- lifecycle ---------------------------------------------------------
    def start(self, band=_DEFAULT_BAND, lo_mhz=None, hi_mhz=None, fft_bins=None):
        if serial is None:
            return {"ok": False, "error": "pyserial not installed (%s)" % _SERIAL_ERR}
        # On a retune (zoom/band change) we were just streaming from this node,
        # so reuse the known identity and skip a full re-probe — that keeps the
        # restart fast. Only discover from scratch when we don't know the device.
        ident = self._identity or _probe_first()
        if not ident:
            return {"ok": False, "error": "no ESP-SDR node detected"}
        label, center, rate = self._resolve(band, lo_mhz, hi_mhz)
        try:
            bins = int(fft_bins) if fft_bins else _FFT_BINS
        except (TypeError, ValueError):
            bins = _FFT_BINS
        if bins not in (256, 512, 1024, 2048):
            bins = _FFT_BINS
        # FOFS is part of the signature, so applying a new trim forces a restart.
        sig = (ident["port"], label, center, rate, bins, self._fofs)
        with self._lock:
            self._last_start = (band, lo_mhz, hi_mhz, fft_bins)
            self._fofs_ok = _fofs_supported(ident)
            if self._thread and self._thread.is_alive():
                if sig == self._sig:
                    return {"ok": True, "already": True, "band": label}
                self._stop_locked()
            self._identity = ident
            self._port_dev = ident["port"]
            self._stop.clear()
            self._frames = []
            self._seq = 0
            self._band = label
            self._center_mhz = center
            self._rate_code = rate
            self._bins = bins
            self._fs = _RATES.get(rate, 80_000_000)
            self._lo_mhz = center - self._fs / 2 / 1e6
            self._hi_mhz = center + self._fs / 2 / 1e6
            self._rbw_hz = self._fs / bins
            self._maxhold = [_FLOOR_DBFS] * bins
            self._error = None
            self._sig = sig
            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                            name="esp-sdr-spec")
            self._thread.start()
        return {"ok": True, "band": label, "center_mhz": center,
                "range_mhz": [self._lo_mhz, self._hi_mhz], "rate_hz": self._fs}

    def stop(self):
        with self._lock:
            self._stop_locked()
        return {"ok": True}

    def _stop_locked(self):
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            self._lock.release()
            try:
                t.join(timeout=4)
            finally:
                self._lock.acquire()
        self._thread = None
        self._running = False
        self._band = None

    # -- capture thread ----------------------------------------------------
    def _profile_for(self, port, rate, bins):
        """Pick (stride, units_per_frame) for this (rate, bins) from SPECINFO."""
        try:
            line = _cmd(port, "SPECINFO?")
            profiles = json.loads(line.split(" ", 1)[1]).get("profiles", [])
            for p in profiles:
                if len(p) >= 5 and int(p[1]) == rate and int(p[2]) == bins:
                    return int(p[3]), int(p[4])
        except Exception:
            pass
        return _STRIDE_UNITS.get((rate, bins), (bins // 256, bins // 256))

    def _read_exact(self, port, n):
        """Read exactly n bytes, yielding to the stop flag between reads."""
        buf = bytearray()
        while len(buf) < n:
            if self._stop.is_set():
                return None
            chunk = port.read(n - len(buf))
            if chunk:
                buf.extend(chunk)
        return bytes(buf)

    def _run_loop(self):
        port = None
        try:
            port = _open(self._port_dev, timeout=0.2)
            if not _sync_lease(port):
                self._error = "ESP-SDR did not grant the serial lease"
                return
            _drain_quiet(port)                   # settle any residual stream
            if self._fofs_ok:                    # apply the frequency trim (ignored if unsupported)
                _cmd(port, "FOFS %d" % self._fofs)
            _cmd(port, "FREQ %d" % self._center_mhz)
            _cmd(port, "BANDWIDTH 0")            # widest analog filter
            _cmd(port, "GAIN HARDWARE")          # hardware AGC
            stride, units = self._profile_for(port, self._rate_code, self._bins)
            try:
                port.reset_input_buffer()
            except Exception:
                pass
            port.write(("SPEC 0 %d %d %d %d %d\n" % (
                stride, units, _DETECTOR, self._rate_code, self._bins)).encode("ascii"))
            hdr = port.readline().decode("ascii", "replace").strip().split()
            if len(hdr) < 2 or hdr[0] != "SPEC":
                self._error = "ESP-SDR refused SPEC: %s" % (" ".join(hdr) or "no reply")
                return
            try:                                 # trust the firmware's reported centre/fs
                self._fs = int(hdr[2])
                center = float(hdr[4]) if len(hdr) > 4 else self._center_mhz
                self._lo_mhz = center - self._fs / 2 / 1e6
                self._hi_mhz = center + self._fs / 2 / 1e6
                self._rbw_hz = self._fs / self._bins
            except (ValueError, IndexError):
                pass
            self._stream(port)
        except Exception as exc:                 # pragma: no cover - defensive
            self._error = str(exc)
        finally:
            if port is not None:
                try:
                    # Clean stop: a short lease sync writes the stop byte and
                    # waits for OK, so the SPEC stream is *confirmed* stopped (an
                    # unverified stop occasionally left it streaming -> wedged).
                    # 1 s is plenty for an idle/ending stream (~0.6 s typical) and
                    # keeps the thread exiting well inside stop()'s join window, so
                    # the exclusive port lock frees promptly for a fast retune.
                    # Anything left over is settled by the next start's own sync.
                    _sync_lease(port, timeout=1.0)
                    _drain_quiet(port, max_time=0.3)
                except Exception:
                    pass
                try:
                    port.close()
                except Exception:
                    pass
            self._running = False

    def _stream(self, port):
        bins = self._bins
        accum = None
        last_push = time.time()
        while not self._stop.is_set():
            magic = self._read_exact(port, 4)
            if magic is None:
                break
            if magic == b"SPC1":
                body = self._read_exact(port, bins + 28)
                if body is None:
                    break
                dbfs, ok, ffts = decode_spc1(magic + body, bins)
                if not ok or not dbfs:
                    continue
                accum = dbfs if accum is None else [a if a > b else b
                                                    for a, b in zip(accum, dbfs)]
            elif magic == b"SPS1":
                if self._read_exact(port, 36) is None:  # stats frame; discard
                    break
                continue
            elif magic == b"SPEC":
                self._error = None                 # SPECEND: stream ended host-side
                break
            else:
                continue                           # resync on the next magic
            now = time.time()
            if accum is not None and now - last_push >= _DISPLAY_INTERVAL:
                self._push_frame(accum)
                accum = None
                last_push = now

    def _push_frame(self, grid):
        ints = [int(round(v)) for v in grid]
        with self._lock:
            self._seq += 1
            self._frames.append({"seq": self._seq, "ts": time.time(), "power": ints})
            if len(self._frames) > _RING_FRAMES:
                self._frames = self._frames[-_RING_FRAMES:]
            if self._maxhold is None:
                self._maxhold = list(ints)
            else:
                self._maxhold = [max(a, b) for a, b in zip(self._maxhold, ints)]

    # -- readers -----------------------------------------------------------
    def _fofs_ppm(self, fofs=None):
        """ppm equivalent of a FOFS (kHz) at the current centre (or 2442 MHz)."""
        fofs = self._fofs if fofs is None else fofs
        center = self._center_mhz or 2442
        return round(fofs * 1000.0 / (center * 1e6) * 1e6, 2)

    def trim_state(self):
        with self._lock:
            return {"fofs_khz": self._fofs, "fofs_ppm": self._fofs_ppm(),
                    "supported": self._fofs_ok, "last": self._trim}

    def status(self):
        with self._lock:
            running = bool(self._thread and self._thread.is_alive())
            return {"running": running, "band": self._band,
                    "frames_buffered": len(self._frames), "seq": self._seq,
                    "bins": self._bins, "center_mhz": self._center_mhz,
                    "rate_hz": self._fs, "rbw_hz": self._rbw_hz,
                    "band_mhz": [self._lo_mhz, self._hi_mhz] if self._lo_mhz else None,
                    "floor_dbm": _FLOOR_DBFS, "error": self._error,
                    "fofs_khz": self._fofs, "fofs_ppm": self._fofs_ppm(),
                    "fofs_supported": self._fofs_ok, "trim": self._trim}

    def get_frames(self, since=0):
        try:
            since = int(since)
        except (TypeError, ValueError):
            since = 0
        with self._lock:
            new = [f for f in self._frames if f["seq"] > since]
            return {"frames": new, "seq": self._seq, "band": self._band,
                    "band_mhz": [self._lo_mhz, self._hi_mhz] if self._lo_mhz else None,
                    "bins": self._bins, "floor_dbm": _FLOOR_DBFS,
                    "rbw_hz": self._rbw_hz, "detector": "peak",
                    "max_hold": list(self._maxhold) if self._maxhold else None,
                    "running": bool(self._thread and self._thread.is_alive()),
                    "error": self._error, "fofs_khz": self._fofs}

    # -- frequency trim (FOFS) --------------------------------------------
    def set_fofs(self, khz):
        """Set the LO frequency trim (kHz) and re-apply it to a live capture."""
        try:
            khz = int(round(float(khz)))
        except (TypeError, ValueError):
            return {"ok": False, "error": "invalid FOFS value"}
        khz = max(-_FOFS_LIMIT, min(_FOFS_LIMIT, khz))
        with self._lock:
            self._fofs = khz
            running = bool(self._thread and self._thread.is_alive())
            args = self._last_start
        _save_fofs(khz)
        if running:
            # FOFS is in the start signature, so this restarts with the new trim.
            self.start(args[0], lo_mhz=args[1], hi_mhz=args[2], fft_bins=args[3])
        return {"ok": True, "fofs_khz": khz, "fofs_ppm": self._fofs_ppm(khz)}

    def auto_trim(self, settle=6.0):
        """Null the crystal drift against the 2.4 GHz Wi-Fi channel centres.

        Reconfigures to a high-resolution full-band 2.4 GHz sweep, averages a few
        seconds of spectra (a clean, stable noise floor — better than max-hold
        for locating channel centres), measures the Wi-Fi channel-centre offset,
        and applies the FOFS correction ONLY when the measurement is confident
        (the channels agree and show a clean ~20 MHz shape). Then restores the
        previous view. Blocks for ~`settle` seconds — it's a calibration action.
        """
        with self._lock:
            supported = self._fofs_ok
            saved = self._last_start
            fofs = self._fofs
            have_device = bool(self._identity) or bool(self._thread and self._thread.is_alive())
        if serial is None or not have_device:
            return {"ok": False, "error": "no ESP-SDR node detected"}
        if not supported:
            return {"ok": False, "error": "this ESP chip has no FOFS trim (S3/S31 only)"}
        # High-res full-2.4-GHz measurement sweep (2048 bins = ~39 kHz/bin).
        r = self.start(band="2.4", fft_bins=2048)
        if not r.get("ok"):
            return {"ok": False, "error": r.get("error", "could not start measurement sweep")}
        time.sleep(max(2.0, settle))                    # accumulate so bursty channels fill
        with self._lock:
            lo, hi = self._lo_mhz, self._hi_mhz
            mh = list(self._maxhold) if self._maxhold else None
        # Max-hold fills a bursty channel's full 20 MHz; the peak-relative edge in
        # _wifi_offset catches only each channel's strong plateau (so lower
        # adjacent-channel bleed is excluded), and the width + agreement guards
        # reject anything contaminated. See _wifi_offset.
        meas = _wifi_offset(mh, lo, hi) if (mh and lo is not None) else None
        result = None
        if meas and meas.get("confident"):
            new_fofs = max(-_FOFS_LIMIT, min(_FOFS_LIMIT, int(round(fofs - meas["offset_khz"]))))
            with self._lock:
                self._fofs = new_fofs
            _save_fofs(new_fofs)
            result = {"ok": True, "offset_khz": round(meas["offset_khz"], 1),
                      "channels": meas["channels"], "widths_mhz": meas["widths_mhz"],
                      "spread_khz": meas["spread_khz"], "old_fofs": fofs, "fofs_khz": new_fofs,
                      "fofs_ppm": self._fofs_ppm(new_fofs), "ts": time.time()}
            with self._lock:
                self._trim = result
        # Restore the previous view (carries the new FOFS via the start signature).
        self.start(saved[0], lo_mhz=saved[1], hi_mhz=saved[2], fft_bins=saved[3])
        if result:
            return result
        if meas:                                        # measured, but not confident enough to apply
            chans = "/".join(str(c) for c in meas["channels"])
            if meas["n"] < 2:
                why = "only ch %s had a clean lock — need two agreeing channels (ch 6 and 11)" % chans
            elif abs(meas["offset_khz"]) > 100:
                why = "offset %+d kHz exceeds the crystal's physical range (likely a mis-read)" % int(meas["offset_khz"])
            else:
                why = "ch %s disagreed by %d kHz" % (chans, int(meas["spread_khz"]))
            return {"ok": False, "offset_khz": round(meas["offset_khz"], 1),
                    "spread_khz": meas["spread_khz"], "channels": meas["channels"],
                    "error": "no confident Wi-Fi lock — %s. 2.4 GHz is too congested here; "
                             "use manual trim or the HackRF reference." % why}
        return {"ok": False, "error": "no clean 2.4 GHz Wi-Fi channel to lock onto — "
                "needs ch 1/6/11 traffic; try again near an access point"}

    def calibrate_vs_reference(self, ref_power, ref_lo, ref_hi, label="HackRF", settle=5.0):
        """Calibrate FOFS against a TCXO reference spectrum of the same band.

        `ref_power` is a reference radio's max-hold over [ref_lo, ref_hi] MHz (a
        HackRF — accurate TCXO). We capture the ESP's own max-hold over the 2.4
        band and cross-correlate the two band shapes: both radios see the same
        ambient RF, so the lag that aligns them is the ESP's frequency error,
        and overlapping-channel contamination cancels (it's in both). Robust and
        signal-agnostic — far better than the ambient-Wi-Fi lock. Blocks ~`settle`
        seconds while the ESP max-hold fills; restores the previous view after.
        """
        with self._lock:
            supported = self._fofs_ok
            saved = self._last_start
            fofs = self._fofs
            have_device = bool(self._identity) or bool(self._thread and self._thread.is_alive())
        if serial is None or not have_device:
            return {"ok": False, "error": "no ESP-SDR node detected"}
        if not supported:
            return {"ok": False, "error": "this ESP chip has no FOFS trim (S3/S31 only)"}
        if not ref_power or ref_lo is None or ref_hi is None or (ref_hi - ref_lo) < 20:
            return {"ok": False, "error": "HackRF reference capture too small"}
        # Measure the ESP over the SAME window as the reference (a narrow ~40 MHz
        # window gives both radios fine-enough resolution for an accurate lag; the
        # full 80 MHz band's coarse HackRF bins bias the correlation low).
        center = (ref_lo + ref_hi) / 2.0
        half = min(40.0, (ref_hi - ref_lo) / 2.0)
        r = self.start(band=None, lo_mhz=center - half, hi_mhz=center + half, fft_bins=2048)
        if not r.get("ok"):
            return {"ok": False, "error": r.get("error", "could not start measurement sweep")}
        time.sleep(max(2.0, settle))
        with self._lock:
            mh = list(self._maxhold) if self._maxhold else None
            lo, hi = self._lo_mhz, self._hi_mhz
        xc = _xcorr_offset(mh, lo, hi, ref_power, ref_lo, ref_hi) if (mh and lo is not None) else None
        result = None
        if xc and xc["corr"] >= 0.5 and abs(xc["offset_khz"]) <= 150:
            new_fofs = max(-_FOFS_LIMIT, min(_FOFS_LIMIT, int(round(fofs - xc["offset_khz"]))))
            with self._lock:
                self._fofs = new_fofs
            _save_fofs(new_fofs)
            result = {"ok": True, "offset_khz": round(xc["offset_khz"], 1), "corr": xc["corr"],
                      "overlap_mhz": xc["overlap_mhz"], "old_fofs": fofs, "fofs_khz": new_fofs,
                      "fofs_ppm": self._fofs_ppm(new_fofs), "ref": label, "ts": time.time()}
            with self._lock:
                self._trim = result
        self.start(saved[0], lo_mhz=saved[1], hi_mhz=saved[2], fft_bins=saved[3])
        if result:
            return result
        if xc and xc["corr"] < 0.5:
            return {"ok": False, "corr": xc["corr"],
                    "error": "weak correlation with the HackRF (%.2f) — not enough common signal; "
                             "aim both at an active band and retry" % xc["corr"]}
        if xc:
            return {"ok": False, "offset_khz": round(xc["offset_khz"], 1),
                    "error": "measured offset %+d kHz exceeds the crystal's range — check both radios "
                             "are on 2.4 GHz" % int(xc["offset_khz"])}
        return {"ok": False, "error": "could not correlate the ESP against the HackRF reference"}


# --------------------------------------------------------------------------
# Module-level singleton + detection cache the web routes drive
# --------------------------------------------------------------------------
_capture = EspCapture()
_detect_cache = {"ident": None, "ts": 0.0}
_DETECT_TTL = 8.0                       # re-scan at most this often while idle


def _probe_first():
    """Find the ESP-SDR node, preferring the last-known-good port. Cached."""
    now = time.time()
    cached = _detect_cache["ident"]
    if cached and (now - _detect_cache["ts"]) < _DETECT_TTL:
        return cached
    order = []
    if cached:
        order.append(cached["port"])
    for dev in _esp_ports():
        if dev not in order:
            order.append(dev)
    for dev in order:
        ident = _probe(dev)
        if ident:
            _detect_cache["ident"] = ident
            _detect_cache["ts"] = now
            return ident
    _detect_cache["ident"] = None
    _detect_cache["ts"] = now
    return None


def detect():
    """Report whether an ESP-SDR node is present, without disturbing a capture."""
    if serial is None:
        return {"available": False, "error": "pyserial not installed (%s)" % _SERIAL_ERR}
    if _capture._running and _capture._identity:
        ident = _capture._identity
        return {"available": True, "streaming": True, "port": ident["port"],
                "model_name": ident.get("chip", "ESP-SDR"),
                "board": ident.get("chip", "ESP-SDR"),
                "bands": sorted(BANDS.keys()), "range_mhz": ident.get("range_mhz")}
    ident = _probe_first()
    if not ident:
        _capture._identity = None   # device gone: don't let start() reuse a dead port
        ports = _esp_ports()
        if not ports:
            err = "No Espressif serial device found on USB"
        else:
            err = "Espressif device present but not running ESP-SDR firmware"
        return {"available": False, "error": err, "ports_seen": ports}
    _capture._identity = ident      # keep the known device fresh for fast retunes
    return {"available": True, "port": ident["port"],
            "model_name": ident.get("chip", "ESP-SDR"),
            "board": ident.get("chip", "ESP-SDR"),
            "bands": sorted(BANDS.keys()), "range_mhz": ident.get("range_mhz"),
            "info": ident.get("info")}


def start(band=_DEFAULT_BAND, lo_mhz=None, hi_mhz=None, fft_bins=None):
    return _capture.start(band=band, lo_mhz=lo_mhz, hi_mhz=hi_mhz, fft_bins=fft_bins)


def stop():
    return _capture.stop()


def status():
    st = _capture.status()
    st["detect"] = detect()
    return st


def get_frames(since=0):
    return _capture.get_frames(since)


def set_fofs(khz):
    return _capture.set_fofs(khz)


def auto_trim(settle=6.0):
    return _capture.auto_trim(settle=settle)


def calibrate_vs_reference(ref_power, ref_lo, ref_hi, label="HackRF", settle=5.0):
    return _capture.calibrate_vs_reference(ref_power, ref_lo, ref_hi, label=label, settle=settle)


def trim_state():
    return _capture.trim_state()


# --------------------------------------------------------------------------
# Self-test (pure decode / config checks — no hardware needed)
# --------------------------------------------------------------------------
def _make_spc1(codes, mult=2):
    """Build a well-formed SPC1 frame carrying the given power codes."""
    n = len(codes)
    log2n = n.bit_length() - 1
    head = bytearray(28)
    head[0:4] = b"SPC1"
    head[20:22] = struct.pack("<H", 4)          # completed FFTs
    head[26] = log2n
    head[27] = mult
    body = bytes(head) + bytes(codes)
    return body + struct.pack("<I", zlib.crc32(body))


def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    check("pyserial present", serial is not None, _SERIAL_ERR or "")

    # A single tone one bin right of DC must land just right of centre after the
    # fftshift + axis flip, and decode to its dBFS value.
    n = 512
    codes = [10] * n
    tone_fb = (1) % n                               # firmware bin 1 (DC + 1)
    codes[tone_fb] = 200
    dbfs, ok, ffts = decode_spc1(_make_spc1(codes), n)
    check("SPC1 CRC verifies", ok)
    check("decoded length matches bins", dbfs and len(dbfs) == n, str(len(dbfs or [])))
    # display column for firmware bin fb solves (n/2 - j) % n == fb  ->  j = n/2 - fb
    j_tone = (n // 2 - tone_fb) % n
    peak = max(range(n), key=lambda i: dbfs[i]) if dbfs else -1
    check("tone maps to expected column", peak == j_tone, "peak=%d expected=%d" % (peak, j_tone))
    check("dBFS conversion correct", dbfs and abs(dbfs[peak] - (200 / 2 - _DBFS_OFFSET)) < 1e-6,
          "%.2f" % (dbfs[peak] if dbfs else 0))
    # Code 0 is the quantization floor (-84.3 dBFS); nothing decodes below floor_dbm.
    codes0 = [0] * n
    dbfs0, _, _ = decode_spc1(_make_spc1(codes0), n)
    check("code 0 -> quantization floor", dbfs0 and abs(dbfs0[0] - (-_DBFS_OFFSET)) < 1e-6,
          "%.2f" % (dbfs0[0] if dbfs0 else 0))
    check("no value below floor_dbm", dbfs0 and min(dbfs0) >= float(_FLOOR_DBFS),
          "min=%.1f floor=%d" % (min(dbfs0) if dbfs0 else 0, _FLOOR_DBFS))

    # Corrupt CRC must be rejected.
    bad = bytearray(_make_spc1(codes))
    bad[-1] ^= 0xFF
    _, ok_bad, _ = decode_spc1(bytes(bad), n)
    check("corrupt CRC rejected", not ok_bad)

    # Config resolution: band + zoom.
    cap = EspCapture()
    lbl, c, r = cap._resolve("2.4", None, None)
    check("band 2.4 -> 2442/80MS", lbl == "2.4" and c == 2442 and r == 0, "%s %d %d" % (lbl, c, r))
    lbl, c, r = cap._resolve(None, 2437e6 / 1e6, 2437e6 / 1e6 + 10)  # 10 MHz zoom
    check("narrow zoom -> 16 MS/s", r == 6, "rate=%d" % r)
    lbl, c, r = cap._resolve(None, 2400, 2460)                      # 60 MHz zoom
    check("wide zoom -> 80 MS/s", r == 0, "rate=%d" % r)

    # Wi-Fi offset estimator: build a 2.4 band with ch6/ch11 shifted -30 kHz.
    nb = 2048
    tr = [-80.0] * nb
    frq = lambda i: 2402.0 + (i + 0.5) * 80.0 / nb
    for ctr in (2437.0 - 0.030, 2462.0 - 0.030):
        for i in range(nb):
            if abs(frq(i) - ctr) <= 10.0:
                tr[i] = -20.0
    wo = _wifi_offset(tr, 2402.0, 2482.0)
    check("wifi offset detects shift", wo and abs(wo["offset_khz"] - (-30)) < 45,
          "%.0f kHz" % (wo["offset_khz"] if wo else 0))
    check("wifi offset confident when channels agree", wo and wo["confident"],
          "spread %.0f" % (wo["spread_khz"] if wo else -1))
    check("wifi offset None on empty band", _wifi_offset([-80.0] * nb, 2402.0, 2482.0) is None)
    # disagreement -> not confident (won't apply)
    tr2 = [-80.0] * nb
    for ctr in (2437.0 - 0.030, 2462.0 + 0.090):
        for i in range(nb):
            if abs(frq(i) - ctr) <= 10.0:
                tr2[i] = -20.0
    wo2 = _wifi_offset(tr2, 2402.0, 2482.0)
    check("wifi offset not confident when channels disagree", wo2 and not wo2["confident"],
          "spread %.0f" % (wo2["spread_khz"] if wo2 else -1))

    # Cross-correlation: a +60 kHz-shifted copy recovers the shift at high corr.
    nb = 1600
    rlo, rhi = 2420.0, 2460.0
    rf = lambda i: rlo + (i + 0.5) * (rhi - rlo) / nb
    def _spec(shift):
        s = [-90.0] * nb
        for i in range(nb):
            for ctr in (2432.0, 2437.0, 2448.0):
                d = abs(rf(i) - (ctr + shift))
                if d <= 5:
                    s[i] = max(s[i], -30.0 - max(0.0, (d - 3.0)) * 10.0)
        return s
    xc = _xcorr_offset(_spec(0.060), rlo, rhi, _spec(0.0), rlo, rhi)
    check("xcorr recovers +60 kHz shift", xc and abs(xc["offset_khz"] - 60) < 25,
          "%.0f kHz" % (xc["offset_khz"] if xc else 0))
    check("xcorr high correlation", xc and xc["corr"] > 0.9, "corr %.2f" % (xc["corr"] if xc else 0))
    check("xcorr None on noise", _xcorr_offset([-90.0] * nb, rlo, rhi, [-90.0] * 512, rlo, rhi) is None)

    ok_all = all(x["ok"] for x in results)
    return {"ok": ok_all, "checks": results,
            "passed": sum(1 for x in results if x["ok"]), "total": len(results)}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="ESP-SDR spectrum/waterfall backend")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("detect")
    sp = sub.add_parser("spectrum")
    sp.add_argument("--band", default=_DEFAULT_BAND)
    sp.add_argument("--freq", type=float, default=None, help="centre MHz (overrides band)")
    sp.add_argument("--seconds", type=float, default=5.0)
    sub.add_parser("selftest")
    args = ap.parse_args(argv)

    if args.cmd == "detect" or not args.cmd:
        print(json.dumps(detect(), indent=2))
        return 0
    if args.cmd == "selftest":
        r = selftest()
        for c in r["checks"]:
            print(("  ok  " if c["ok"] else " FAIL ") + c["name"] +
                  (("  — " + c["detail"]) if c["detail"] else ""))
        print("%d/%d passed" % (r["passed"], r["total"]))
        return 0 if r["ok"] else 1
    if args.cmd == "spectrum":
        lo = hi = None
        if args.freq:
            lo, hi = args.freq - 40, args.freq + 40
        res = start(band=args.band, lo_mhz=lo, hi_mhz=hi)
        print("start:", json.dumps(res))
        if not res.get("ok"):
            return 1
        try:
            seq = 0
            deadline = time.time() + args.seconds
            while time.time() < deadline:
                time.sleep(0.5)
                d = get_frames(since=seq)
                for f in d["frames"]:
                    seq = f["seq"]
                    p = f["power"]
                    peak = max(range(len(p)), key=lambda i: p[i])
                    lo_m, hi_m = d["band_mhz"]
                    fmhz = lo_m + (hi_m - lo_m) * peak / len(p)
                    print("frame %4d  peak %6.1f dBFS @ %.1f MHz  floor %d" %
                          (seq, p[peak], fmhz, d["floor_dbm"]))
        finally:
            stop()
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
