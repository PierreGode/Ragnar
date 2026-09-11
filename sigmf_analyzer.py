#!/usr/bin/env python3
"""sigmf_analyzer.py — on-box analysis of the RF Waterfall's SigMF IQ captures.

The RF Waterfall's ``⤓ SigMF`` button ([[rtl_sdr]] IqCapture) writes raw IQ
recordings (``data/iq_captures/<name>.sigmf-data`` + ``.sigmf-meta``). Desktop
tools (inspectrum / URH / GNU Radio) analyse those on a laptop; this module does
it **on the Pi** so the "Open in Analyzer" page works straight from a phone.

Everything heavy runs here in numpy/scipy and the page is just a viewer that
requests windows:

  * :func:`summary`     — center/rate/duration, measured noise floor, peak
    offset, occupied bandwidth, burst count.
  * :func:`spectrogram` — a zoomable time x frequency power grid for any
    [t0,t1] x [f0,f1] window, returned as a compact base64 uint8 image the page
    colours with the waterfall palette.
  * :func:`psd`         — averaged power spectrum over a time range.
  * :func:`envelope`    — amplitude-over-time (for AM/OOK + burst spotting).
  * :func:`bursts`      — automatic on/off packet detection (start/end/BW/level).
  * :func:`demod`       — shift/filter/demodulate a chosen signal (AM-OOK or
    FM-FSK), estimate the symbol rate and recover a bitstream.

SigMF datatype ``cu8`` (interleaved unsigned-8 I/Q — the RTL-SDR's native form)
is the primary format; ``cs8`` is also accepted. Pure DSP helpers are
selftested against a synthesised capture (a tone + an OOK burst), no hardware.
"""

import base64
import json
import os
import struct
import time


def _cap_dir():
    # Mirror rtl_sdr._iq_cap_dir() without a hard import dependency.
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "iq_captures")


def _safe(name):
    import re
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(name or ""))[:80]


# --------------------------------------------------------------------------
# Loading (cached by name + mtime so repeated window requests are cheap)
# --------------------------------------------------------------------------

_CACHE = {}          # name -> (mtime, iq(complex64), fs, fc, meta)
_CACHE_MAX = 3       # keep only a few captures resident (they can be tens of MB)


def _paths(name):
    base = os.path.join(_cap_dir(), _safe(name))
    return base + ".sigmf-data", base + ".sigmf-meta"


def load(name):
    """Return (iq complex64, fs Hz, fc Hz, meta) for a capture, or raise ValueError."""
    import numpy as np
    data_p, meta_p = _paths(name)
    if not os.path.exists(data_p) or not os.path.exists(meta_p):
        raise ValueError("capture not found")
    mtime = os.path.getmtime(data_p)
    hit = _CACHE.get(name)
    if hit and hit[0] == mtime:
        return hit[1], hit[2], hit[3], hit[4]
    with open(meta_p) as fh:
        meta = json.load(fh)
    g = meta.get("global", {})
    cap0 = (meta.get("captures") or [{}])[0]
    fs = float(g.get("core:sample_rate") or 0) or 1.0
    fc = float(cap0.get("core:frequency") or 0)
    dtype = (g.get("core:datatype") or "cu8").lower()
    raw = np.fromfile(data_p, dtype=np.uint8)
    raw = raw[: (raw.size // 2) * 2]                 # whole I/Q pairs only
    if dtype.startswith("cs8"):                       # signed 8-bit
        s = raw.astype(np.int8).astype(np.float32)
        iq = (s[0::2] + 1j * s[1::2]) / 128.0
    else:                                             # cu8 (default): unsigned 8-bit
        f = raw.astype(np.float32) - 127.5
        iq = (f[0::2] + 1j * f[1::2]) / 127.5
    iq = iq.astype(np.complex64)
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[name] = (mtime, iq, fs, fc, meta)
    return iq, fs, fc, meta


def list_captures():
    """Every capture in the dir with both sidecars, **newest first** (by mtime)."""
    import glob
    rows = []
    for meta_p in glob.glob(os.path.join(_cap_dir(), "*.sigmf-meta")):
        base = os.path.basename(meta_p)[:-len(".sigmf-meta")]
        data_p = meta_p[:-len(".sigmf-meta")] + ".sigmf-data"
        if not os.path.exists(data_p):
            continue
        try:
            m = json.load(open(meta_p))
            g, c = m.get("global", {}), (m.get("captures") or [{}])[0]
            fs = float(g.get("core:sample_rate") or 0)
            nbytes = os.path.getsize(data_p)
            mtime = os.path.getmtime(data_p)
            rows.append((mtime, {"name": base, "sr_hz": fs,
                                 "center_hz": c.get("core:frequency"),
                                 "datetime": c.get("core:datetime"),
                                 "bytes": nbytes, "mtime": mtime,
                                 "duration_s": round(nbytes / 2 / fs, 3) if fs else None}))
        except (OSError, ValueError):
            continue
    rows.sort(key=lambda r: r[0], reverse=True)      # newest capture first
    return {"captures": [r[1] for r in rows]}


# --------------------------------------------------------------------------
# Pure DSP helpers (numpy) — selftested on synthetic signals
# --------------------------------------------------------------------------

def _noise_floor_db(psd_db):
    import numpy as np
    return float(np.percentile(psd_db, 30))


def welch_psd(iq, fs, nfft=4096, reduce="mean"):
    """Power spectrum (fftshifted), returns (freqs_hz, db). ``reduce`` is
    ``"mean"`` (averaged / Welch) or ``"max"`` (max-hold across time — reveals
    intermittent carriers a mean would bury). Pure-ish."""
    import numpy as np
    n = len(iq)
    if n < nfft:
        nfft = 1 << max(6, int(np.log2(max(2, n))))
    win = np.hanning(nfft).astype(np.float32)
    ncol = max(1, (n - nfft) // (nfft // 2) + 1)
    ncol = min(ncol, 400)
    starts = np.linspace(0, max(0, n - nfft), ncol).astype(int)
    acc = None
    for s in starts:
        seg = iq[s:s + nfft] * win
        S = np.fft.fftshift(np.fft.fft(seg))
        p = (S.real ** 2 + S.imag ** 2)
        if acc is None:
            acc = p.astype(np.float64)
        elif reduce == "max":
            np.maximum(acc, p, out=acc)
        else:
            acc += p
    if reduce != "max":
        acc /= len(starts)
    db = 10.0 * np.log10(acc / (nfft * float(np.sum(win ** 2))) + 1e-12)
    freqs = np.fft.fftshift(np.fft.fftfreq(nfft, 1.0 / fs))
    return freqs, db


def occupied_bw(freqs, db, frac=0.99):
    """99%-power occupied bandwidth around the strongest bin (Hz). Pure."""
    import numpy as np
    lin = 10.0 ** (db / 10.0)
    pk = int(np.argmax(lin))
    tot = float(lin.sum())
    if tot <= 0:
        return 0.0
    acc, lo = 0.0, pk
    for i in range(pk, -1, -1):
        acc += lin[i]
        lo = i
        if acc >= tot * (1 - frac) / 2:
            break
    acc, hi = 0.0, pk
    for i in range(pk, len(lin)):
        acc += lin[i]
        hi = i
        if acc >= tot * (1 - frac) / 2:
            break
    return abs(float(freqs[hi] - freqs[lo]))


def _pool_max(a, out):
    """Downsample a 1-D array to length ``out`` by block-max (keeps thin peaks)."""
    import numpy as np
    n = len(a)
    if out >= n:
        idx = np.clip((np.arange(out) * n / out).astype(int), 0, n - 1)
        return a[idx]
    edges = (np.arange(out + 1) * n / out).astype(int)
    return np.array([a[edges[i]:max(edges[i] + 1, edges[i + 1])].max() for i in range(out)])


def stft_grid(iq, fs, fc, t0, t1, f0, f1, w=900, h=360, nfft=1024):
    """A time x frequency power grid over [t0,t1] s x [f0,f1] Hz.

    Returns (grid uint8 [h,w], floor_db, ceil_db, actual t0,t1,f0,f1). Rows are
    frequency (top = high), cols are time. Values are dB clipped to
    [floor,ceil] and mapped 0..255 for the page's palette LUT. Pure numpy.
    """
    import numpy as np
    n = len(iq)
    i0 = max(0, int(t0 * fs)); i1 = min(n, int(t1 * fs))
    if i1 - i0 < nfft:
        i1 = min(n, i0 + nfft)
        i0 = max(0, i1 - nfft)
    seg = iq[i0:i1]
    win = np.hanning(nfft).astype(np.float32)
    ncol = max(1, (len(seg) - nfft) // nfft + 1)          # non-overlapping frames
    ncol = min(ncol, 4000)
    starts = np.linspace(0, max(0, len(seg) - nfft), ncol).astype(int)
    frames = np.stack([seg[s:s + nfft] for s in starts]) * win           # (T, nfft)
    S = np.fft.fftshift(np.fft.fft(frames, axis=1), axes=1)
    P = (S.real ** 2 + S.imag ** 2) / (nfft * float(np.sum(win ** 2)))
    db = (10.0 * np.log10(P + 1e-12)).T                                  # (freq, time)
    fbins = np.fft.fftshift(np.fft.fftfreq(nfft, 1.0 / fs)) + fc         # absolute Hz
    # crop to [f0,f1]
    lo = np.searchsorted(fbins, f0); hi = np.searchsorted(fbins, f1)
    lo = max(0, min(lo, nfft - 1)); hi = max(lo + 1, min(hi, nfft))
    db = db[lo:hi, :]
    fmin, fmax = float(fbins[lo]), float(fbins[hi - 1])
    # resize: freq rows -> h (max-pool), time cols -> w
    if db.shape[0] != h:
        db = np.stack([_pool_max(db[:, c], h) for c in range(db.shape[1])], axis=1) \
            if db.shape[1] <= h * 4 else \
            np.apply_along_axis(lambda col: _pool_max(col, h), 0, db)
    if db.shape[1] != w:
        db = np.apply_along_axis(lambda row: _pool_max(row, w), 1, db)
    db = db[::-1, :]                                        # top row = high freq
    floor = float(np.percentile(db, 25)) - 4.0
    ceil = float(np.percentile(db, 99.9)) + 2.0
    if ceil - floor < 12:
        ceil = floor + 12
    g = np.clip((db - floor) / (ceil - floor), 0, 1)
    grid = (g * 255).astype(np.uint8)
    tt0 = i0 / fs + starts[0] / fs
    tt1 = i0 / fs + (starts[-1] + nfft) / fs
    return grid, floor, ceil, tt0, tt1, fmin, fmax


# --------------------------------------------------------------------------
# Public API (dicts for the web layer)
# --------------------------------------------------------------------------

def summary(name):
    import numpy as np
    iq, fs, fc, meta = load(name)
    n = len(iq)
    freqs, db = welch_psd(iq, fs)
    nf = _noise_floor_db(db)
    pk = int(np.argmax(db))
    obw = occupied_bw(freqs, db)
    b = bursts(name).get("bursts", [])
    return {"ok": True, "name": name, "samples": n, "duration_s": round(n / fs, 4),
            "sr_hz": fs, "center_hz": fc, "span_hz": fs,
            "noise_db": round(nf, 1), "peak_db": round(float(db[pk]), 1),
            "peak_offset_hz": round(float(freqs[pk]), 1),
            "peak_hz": round(fc + float(freqs[pk]), 1),
            "snr_db": round(float(db[pk]) - nf, 1),
            "occupied_bw_hz": round(obw, 1), "bursts": len(b),
            "datetime": (meta.get("captures") or [{}])[0].get("core:datetime")}


def spectrogram(name, t0=None, t1=None, f0=None, f1=None, w=900, h=360, nfft=1024):
    iq, fs, fc, _ = load(name)
    dur = len(iq) / fs
    t0 = 0.0 if t0 is None else max(0.0, float(t0))
    t1 = dur if t1 is None else min(dur, float(t1))
    f0 = fc - fs / 2 if f0 is None else float(f0)
    f1 = fc + fs / 2 if f1 is None else float(f1)
    w = int(max(64, min(1600, w))); h = int(max(64, min(720, h)))
    nfft = int(max(128, min(8192, nfft)))
    grid, floor, ceil, tt0, tt1, fmin, fmax = stft_grid(iq, fs, fc, t0, t1, f0, f1, w, h, nfft)
    return {"ok": True, "w": grid.shape[1], "h": grid.shape[0],
            "t0": tt0, "t1": tt1, "f0": fmin, "f1": fmax,
            "floor_db": round(floor, 1), "ceil_db": round(ceil, 1),
            "data": base64.b64encode(grid.tobytes()).decode("ascii")}


def psd(name, t0=None, t1=None, n=900, mode="avg"):
    """Power spectrum over [t0,t1]. ``mode`` = "avg" (Welch) or "max" (max-hold)."""
    import numpy as np
    iq, fs, fc, _ = load(name)
    i0 = 0 if t0 is None else max(0, int(float(t0) * fs))
    i1 = len(iq) if t1 is None else min(len(iq), int(float(t1) * fs))
    reduce = "max" if str(mode).lower().startswith("max") else "mean"
    freqs, db = welch_psd(iq[i0:i1] if i1 > i0 else iq, fs, reduce=reduce)
    n = int(max(64, min(1600, n)))
    fr = (freqs + fc) / 1e6
    if len(db) > n:
        db = _pool_max(db, n)
        fr = fr[np.linspace(0, len(fr) - 1, n).astype(int)]
    return {"ok": True, "mode": reduce, "freqs_mhz": [round(x, 4) for x in fr.tolist()],
            "db": [round(x, 1) for x in db.tolist()],
            "noise_db": round(_noise_floor_db(db), 1)}


def measure(name, t0, t1, f0, f1):
    """Measure a time×frequency box: channel power, peak (freq+level), mean, span.

    Integrates the Welch PSD of the [t0,t1] slice over [f0,f1] (absolute Hz).
    Relative dB (consistent, not absolute dBm), matching the rest of the tool.
    """
    import numpy as np
    iq, fs, fc, _ = load(name)
    dur = len(iq) / fs
    t0 = max(0.0, float(t0)); t1 = min(dur, float(t1))
    i0, i1 = int(t0 * fs), int(t1 * fs)
    if i1 - i0 < 16:
        return {"ok": False, "error": "time selection too short"}
    freqs, db = welch_psd(iq[i0:i1], fs)
    absf = freqs + fc
    f0, f1 = float(min(f0, f1)), float(max(f0, f1))
    mask = (absf >= f0) & (absf <= f1)
    if not mask.any():
        return {"ok": False, "error": "frequency selection outside the capture"}
    lin = 10.0 ** (db[mask] / 10.0)
    sub = db[mask]; subf = absf[mask]
    pk = int(np.argmax(sub))
    return {"ok": True, "t0": round(t0, 5), "t1": round(t1, 5),
            "f0": round(f0, 1), "f1": round(f1, 1),
            "dt_ms": round((t1 - t0) * 1000, 3), "span_khz": round((f1 - f0) / 1e3, 2),
            "channel_power_db": round(float(10.0 * np.log10(lin.sum() + 1e-12)), 1),
            "peak_db": round(float(sub[pk]), 1),
            "peak_hz": round(float(subf[pk]), 1),
            "mean_db": round(float(10.0 * np.log10(lin.mean() + 1e-12)), 1),
            "bins": int(mask.sum())}


def envelope(name, t0=None, t1=None, n=1200):
    """Amplitude (dB) over time — the AM/OOK view + what bursts() thresholds."""
    import numpy as np
    iq, fs, fc, _ = load(name)
    dur = len(iq) / fs
    i0 = 0 if t0 is None else max(0, int(float(t0) * fs))
    i1 = len(iq) if t1 is None else min(len(iq), int(float(t1) * fs))
    seg = iq[i0:i1] if i1 > i0 else iq
    mag = np.abs(seg)
    n = int(max(64, min(4000, n)))
    if len(mag) > n:                                   # block-mean then to dB
        edges = (np.arange(n + 1) * len(mag) / n).astype(int)
        mag = np.array([mag[edges[i]:max(edges[i] + 1, edges[i + 1])].mean() for i in range(n)])
    db = 20.0 * np.log10(mag + 1e-6)
    t = (i0 / fs) + np.linspace(0, (len(seg)) / fs, len(db))
    return {"ok": True, "t": [round(x, 5) for x in t.tolist()],
            "db": [round(x, 1) for x in db.tolist()]}


def _merge_runs(on, gap, min_len):
    """Boolean 'on' -> list of (start,end) sample runs, bridging gaps < ``gap``
    samples and dropping runs shorter than ``min_len``. Pure (numpy).

    Gap-bridging is what turns a *pulse train* (an OOK/FSK packet is many short
    pulses) into one burst per transmission, and a held/continuous carrier into a
    single long burst — instead of hundreds of per-pulse fragments or nothing.
    """
    import numpy as np
    if not on.any():
        return []
    d = np.diff(on.astype(np.int8))
    starts = list(np.where(d == 1)[0] + 1)
    ends = list(np.where(d == -1)[0] + 1)
    if on[0]:
        starts = [0] + starts
    if on[-1]:
        ends = ends + [len(on)]
    runs = list(zip(starts, ends))
    merged = []
    for s, e in runs:
        if merged and s - merged[-1][1] < gap:
            merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    return [(s, e) for s, e in merged if e - s >= min_len]


def bursts(name, thresh_db=8.0, min_ms=1.0, gap_ms=25.0):
    """Detect transmissions (bursts/packets) from the amplitude envelope.

    A press of an OOK/FSK remote is a *train* of short pulses; ``gap_ms`` bridges
    the inter-pulse gaps so each transmission is one burst (not one per pulse),
    while ``min_ms`` rejects lone noise spikes. A near-100%-duty carrier collapses
    to a single long burst. The noise floor is a low percentile so a busy band
    still yields a sane threshold.
    """
    import numpy as np
    iq, fs, fc, _ = load(name)
    mag = np.abs(iq)
    step = max(1, len(mag) // 200000)          # coarse envelope; cheap on long files
    env = mag[::step]
    env_fs = fs / step
    edb = 20.0 * np.log10(env + 1e-6)
    nf = float(np.percentile(edb, 20))
    on = edb > (nf + thresh_db)
    gap = int(gap_ms / 1000.0 * env_fs)
    min_len = max(1, int(min_ms / 1000.0 * env_fs))
    out = []
    for s, e in _merge_runs(on, gap, min_len):
        seg = iq[s * step: e * step]
        if len(seg) < 8:
            continue
        fr, db = welch_psd(seg, fs, nfft=min(2048, 1 << int(np.log2(max(2, len(seg))))))
        pk = int(np.argmax(db))
        # duty: fraction of the merged span actually above threshold (packet vs CW)
        duty = float(on[s:e].mean()) if e > s else 1.0
        out.append({"t0": round(s / env_fs, 5), "t1": round(e / env_fs, 5),
                    "dur_ms": round((e - s) / env_fs * 1000, 2),
                    "f_mhz": round((fc + float(fr[pk])) / 1e6, 4),
                    "bw_khz": round(occupied_bw(fr, db) / 1e3, 1),
                    "duty": round(duty, 2),
                    "peak_db": round(float(db[pk]), 1)})
    return {"ok": True, "bursts": out[:200], "count": len(out)}


def _slice_bits(level, fs, max_bits=512):
    """Turn a boolean decision stream into (baud, bit-string) via run lengths. Pure."""
    import numpy as np
    lvl = level.astype(np.int8)
    if lvl.size < 4:
        return 0.0, ""
    chg = np.where(np.diff(lvl) != 0)[0] + 1
    bounds = np.concatenate([[0], chg, [len(lvl)]])
    runs = np.diff(bounds)
    real = runs[runs >= 2]
    if real.size == 0:
        return 0.0, ""
    ui = float(np.percentile(real, 10))               # shortest symbol ~ unit interval
    if ui < 1:
        return 0.0, ""
    baud = fs / ui
    nb = min(max_bits, int(len(lvl) / ui))
    centers = (np.arange(nb) + 0.5) * ui
    idx = np.clip(centers.astype(int), 0, len(lvl) - 1)
    bits = lvl[idx]
    return baud, "".join("1" if b else "0" for b in bits)


def demod(name, mode="ook", f_offset_hz=0.0, bw_hz=None, t0=None, t1=None):
    """Shift to f_offset, low-pass to bw, demodulate (ook/am or fsk/fm), recover bits.

    Returns the estimated symbol rate, a recovered bitstream, and a downsampled
    waveform (dB envelope for OOK/AM, instantaneous frequency for FSK/FM) to plot.
    """
    import numpy as np
    from scipy import signal as sig
    iq, fs, fc, _ = load(name)
    dur = len(iq) / fs
    i0 = 0 if t0 is None else max(0, int(float(t0) * fs))
    i1 = len(iq) if t1 is None else min(len(iq), int(float(t1) * fs))
    x = iq[i0:i1] if i1 > i0 else iq
    if len(x) < 16:
        return {"ok": False, "error": "selection too short"}
    foff = float(f_offset_hz or 0.0)
    bw = float(bw_hz) if bw_hz else min(fs / 4, 200e3)
    bw = max(1e3, min(bw, fs / 2))
    n = np.arange(len(x))
    x = x * np.exp(-2j * np.pi * (foff / fs) * n)     # mix the signal down to DC
    dec = int(max(1, fs // (bw * 2)))                  # decimate to ~2*bw
    if dec > 1:
        x = sig.decimate(x, dec, ftype="fir")
    nfs = fs / dec
    mode = (mode or "ook").lower()
    if mode in ("fsk", "fm"):
        inst = np.angle(x[1:] * np.conj(x[:-1])) * nfs / (2 * np.pi)   # Hz
        wave = inst
        level = inst > np.median(inst)
        ylabel = "inst. freq (Hz)"
    else:                                              # ook / am
        env = np.abs(x)
        env = env / (env.max() + 1e-9)
        wave = 20.0 * np.log10(env + 1e-4)
        thr = 0.5 * (float(np.percentile(env, 90)) + float(np.percentile(env, 10)))
        level = env > thr
        ylabel = "envelope (dB)"
    baud, bits = _slice_bits(level, nfs)
    # downsample the waveform for transport/plot
    m = 1600
    if len(wave) > m:
        edges = (np.arange(m + 1) * len(wave) / m).astype(int)
        wave = np.array([wave[edges[i]:max(edges[i] + 1, edges[i + 1])].mean() for i in range(m)])
    return {"ok": True, "mode": mode, "sample_rate_hz": round(nfs, 1),
            "baud": round(baud, 1), "n_bits": len(bits), "bits": bits,
            "ylabel": ylabel,
            "wave": [round(float(v), 3) for v in wave.tolist()],
            "t0": i0 / fs, "t1": i1 / fs, "bw_hz": bw, "f_offset_hz": foff}


def _parse_rtl433_lines(text):
    """Parse rtl_433 -F json output into deduped device records (pure)."""
    _meta = ("time", "mod", "freq", "freq1", "freq2", "rssi", "snr", "noise",
             "model", "id", "channel")
    agg = {}
    events = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict) or "model" not in obj:
            continue
        events += 1
        key = "%s/%s/%s" % (obj.get("model"), obj.get("id"), obj.get("channel"))
        fields = {k: v for k, v in obj.items() if k not in _meta}
        rec = agg.get(key)
        if rec:
            rec["count"] += 1; rec["fields"] = fields
            if obj.get("rssi") is not None:
                rec["rssi"] = obj.get("rssi")
        else:
            agg[key] = {"model": str(obj.get("model")), "id": obj.get("id"),
                        "channel": obj.get("channel"), "rssi": obj.get("rssi"),
                        "fields": fields, "count": 1}
    return list(agg.values()), events


def decode433(name):
    """Offline-decode a capture with rtl_433 to *name* known ISM devices.

    rtl_433 reads the raw file directly (``-r`` + ``-s`` sample rate), so this
    names TPMS / weather / remotes / doorbells straight from a recording. The
    ``.sigmf-data`` is symlinked to a ``.cu8`` name so rtl_433 detects the format.
    """
    import subprocess
    import tempfile
    data_p, meta_p = _paths(name)
    if not os.path.exists(data_p):
        raise ValueError("capture not found")
    meta = {}
    if os.path.exists(meta_p):
        try:
            meta = json.load(open(meta_p))
        except ValueError:
            meta = {}
    g = meta.get("global", {}); c = (meta.get("captures") or [{}])[0]
    sr = int(g.get("core:sample_rate") or 0)
    fc = int(c.get("core:frequency") or 0)
    rtl433 = "/usr/bin/rtl_433" if os.path.exists("/usr/bin/rtl_433") else "rtl_433"
    dur = (os.path.getsize(data_p) / 2 / sr) if sr else 2.0
    tmpd = tempfile.mkdtemp(prefix="rtl433-")
    link = os.path.join(tmpd, "capture.cu8")
    try:
        os.symlink(os.path.abspath(data_p), link)
        cmd = [rtl433, "-r", link, "-F", "json", "-M", "level"]
        if sr:
            cmd += ["-s", str(sr)]
        if fc:
            cmd += ["-f", str(fc)]
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=max(30, int(dur * 15)))
        devices, events = _parse_rtl433_lines(p.stdout)
        return {"ok": True, "tool": "rtl_433", "devices": devices, "events": events,
                "sr_hz": sr, "center_hz": fc}
    except FileNotFoundError:
        return {"ok": False, "error": "rtl_433 not installed (apt install rtl-433)"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "rtl_433 timed out on this capture"}
    finally:
        import shutil
        shutil.rmtree(tmpd, ignore_errors=True)


# --------------------------------------------------------------------------
# Self-test — synthesise a cu8 capture (tone + OOK burst) and check the DSP
# --------------------------------------------------------------------------

def _write_synth(path_base, fs=1_000_000.0, fc=433_900_000.0):
    """Write a synthetic cu8 SigMF capture: a CW tone at +150 kHz for the whole
    record, plus an OOK burst at +150 kHz (on/off keyed) in the middle."""
    import numpy as np
    dur = 0.2
    n = int(fs * dur)
    t = np.arange(n) / fs
    tone = 0.25 * np.exp(2j * np.pi * 150_000 * t)          # CW carrier at +150 kHz
    # OOK: 2000 baud square keying gating a +150 kHz carrier, only mid-record
    baud = 2000.0
    key = ((t * baud).astype(int) % 2).astype(np.float32)   # 1010...
    gate = ((t > 0.08) & (t < 0.12)).astype(np.float32)
    ook = 0.5 * key * gate * np.exp(2j * np.pi * 150_000 * t)
    noise = (np.random.randn(n) + 1j * np.random.randn(n)) * 0.02
    x = tone + ook + noise
    i = np.clip(np.round(x.real * 127.5 + 127.5), 0, 255).astype(np.uint8)
    q = np.clip(np.round(x.imag * 127.5 + 127.5), 0, 255).astype(np.uint8)
    inter = np.empty(2 * n, dtype=np.uint8); inter[0::2] = i; inter[1::2] = q
    inter.tofile(path_base + ".sigmf-data")
    meta = {"global": {"core:datatype": "cu8", "core:sample_rate": fs,
                       "core:version": "1.0.0"},
            "captures": [{"core:sample_start": 0, "core:frequency": fc,
                          "core:datetime": "2026-01-01T00:00:00Z"}],
            "annotations": []}
    json.dump(meta, open(path_base + ".sigmf-meta", "w"))


def selftest():
    import tempfile
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    try:
        import numpy  # noqa
        import scipy  # noqa
    except Exception as exc:
        return {"pass": False, "passed": 0, "total": 1,
                "results": [{"name": "deps: numpy+scipy import", "pass": False, "detail": str(exc)}]}

    tmp = tempfile.mkdtemp(prefix="sigmf-st-")
    saved = globals()["_cap_dir"]
    globals()["_cap_dir"] = lambda: tmp
    try:
        _write_synth(os.path.join(tmp, "synth"))
        s = summary("synth")
        check("summary: peak near +150 kHz of a 433.9 MHz capture",
              abs(s["peak_offset_hz"] - 150_000) < 8000, str(s.get("peak_offset_hz")))
        check("summary: duration ~0.2 s @ 1 MS/s", abs(s["duration_s"] - 0.2) < 0.01, str(s["duration_s"]))
        check("summary: SNR positive (tone over noise)", s["snr_db"] > 15, str(s["snr_db"]))
        sp = spectrogram("synth", w=200, h=120)
        raw = base64.b64decode(sp["data"])
        check("spectrogram: grid is h*w uint8 bytes",
              len(raw) == sp["w"] * sp["h"] and sp["w"] == 200 and sp["h"] == 120, str((sp["w"], sp["h"], len(raw))))
        check("spectrogram: dynamic range present (floor<ceil)", sp["ceil_db"] > sp["floor_db"])
        b = bursts("synth")
        check("bursts: the OOK train merges into one burst (not per-pulse)",
              1 <= b["count"] <= 3 and any(0.07 < x["t0"] < 0.12 for x in b["bursts"]), str(b["count"]))
        check("bursts: burst carries a duty-cycle", b["bursts"] and "duty" in b["bursts"][0])
        # _merge_runs: bridge small gaps into one run, drop short spikes
        import numpy as np
        onarr = np.array([1,1,0,1,1,0,0,0,0,0,0,0,0,0,0,1] + [0]*20, dtype=bool)
        mr = _merge_runs(onarr, gap=3, min_len=2)     # first two runs merge (gap 1), lone tail spike dropped
        check("merge: bridges small gaps, drops short spikes",
              len(mr) == 1 and mr[0][0] == 0 and mr[0][1] == 5, str(mr))
        d = demod("synth", mode="ook", f_offset_hz=150_000, bw_hz=60_000, t0=0.08, t1=0.12)
        check("demod: OOK recovers ~2000 baud",
              d["ok"] and abs(d["baud"] - 2000) < 400, str(d.get("baud")))
        check("demod: recovers a bitstream", d["ok"] and d["n_bits"] > 8 and set(d["bits"]) <= {"0", "1"},
              str(d.get("n_bits")))
        e = envelope("synth", n=300)
        check("envelope: returns matched t/db arrays", len(e["t"]) == len(e["db"]) > 0)
        p = psd("synth", n=256)
        check("psd: freqs+db aligned, noise below peak",
              len(p["freqs_mhz"]) == len(p["db"]) and max(p["db"]) - p["noise_db"] > 15)
        pm = psd("synth", n=256, mode="max")
        check("psd: max-hold >= average at the peak and is labelled",
              pm["mode"] == "max" and max(pm["db"]) >= max(p["db"]) - 0.5)
        # measure a box around the +150 kHz tone
        mb = measure("synth", 0.0, 0.2, 433_900_000 + 130_000, 433_900_000 + 170_000)
        check("measure: box power + peak near +150 kHz tone",
              mb["ok"] and abs(mb["peak_hz"] - (433_900_000 + 150_000)) < 8000
              and mb["channel_power_db"] > mb["mean_db"], str(mb.get("peak_hz")))
        check("list: the synth capture is listed",
              any(c["name"] == "synth" for c in list_captures()["captures"]))
        # pure bit slicer on a clean square wave
        import numpy as np
        sq = (np.arange(1000) // 10) % 2
        baud, bits = _slice_bits(sq.astype(bool), 10000.0)
        check("bits: clean 10-sample square -> ~1000 baud", abs(baud - 1000) < 120, str(baud))
        # rtl_433 JSON parser: dedupe by model/id, keep fields + count
        devs, ev = _parse_rtl433_lines(
            '{"time":"..","model":"Acurite-Tower","id":42,"temperature_C":21.5,"rssi":-8}\n'
            'noise line\n'
            '{"time":"..","model":"Acurite-Tower","id":42,"temperature_C":21.7,"rssi":-7}\n'
            '{"model":"Nexus-TH","id":9,"channel":1,"humidity":55}')
        check("rtl433: parses + dedupes device events",
              ev == 3 and len(devs) == 2
              and any(d["model"] == "Acurite-Tower" and d["count"] == 2
                      and d["fields"].get("temperature_C") == 21.7 for d in devs)
              and any(d["model"] == "Nexus-TH" and d["channel"] == 1 for d in devs), str(devs))
        d433 = decode433("synth")     # a tone+OOK synth won't match a real protocol
        check("rtl433: runs on a capture, returns a clean (empty) device list",
              d433.get("ok") is True and isinstance(d433.get("devices"), list), str(d433)[:120])
    finally:
        globals()["_cap_dir"] = saved
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        _CACHE.clear()

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="On-box SigMF IQ analyzer")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("selftest")
    sub.add_parser("list")
    ps = sub.add_parser("summary"); ps.add_argument("name")
    args = ap.parse_args(argv)
    if args.cmd == "selftest":
        r = selftest()
        for it in r["results"]:
            print("  [%s] %s%s" % ("PASS" if it["pass"] else "FAIL", it["name"],
                                   "" if it["pass"] else "  (%s)" % it["detail"]))
        print("\n%d/%d checks pass — %s" % (r["passed"], r["total"], "OK" if r["pass"] else "FAIL"))
        return 0 if r["pass"] else 1
    if args.cmd == "list":
        print(json.dumps(list_captures(), indent=2)); return 0
    if args.cmd == "summary":
        print(json.dumps(summary(args.name), indent=2)); return 0
    ap.print_help(); return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
