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
# Segment 3 — modulation analysis: IQ constellation, instantaneous
# amplitude/frequency/phase, and automatic modulation classification.
# --------------------------------------------------------------------------

def _prep_selection(name, f_offset_hz, bw_hz, t0, t1):
    """Load, mix the chosen signal to DC and decimate to ~2*bw. Returns (x, nfs)."""
    import numpy as np
    from scipy import signal as sig
    iq, fs, fc, _ = load(name)
    dur = len(iq) / fs
    i0 = 0 if t0 is None else max(0, int(float(t0) * fs))
    i1 = len(iq) if t1 is None else min(len(iq), int(float(t1) * fs))
    x = iq[i0:i1] if i1 > i0 else iq
    if len(x) < 16:
        return np.zeros(0, dtype=np.complex64), fs
    foff = float(f_offset_hz or 0.0)
    bw = float(bw_hz) if bw_hz else min(fs / 4, 200e3)
    bw = max(1e3, min(bw, fs / 2))
    n = np.arange(len(x))
    x = x * np.exp(-2j * np.pi * (foff / fs) * n)
    dec = int(max(1, fs // (bw * 2)))
    if dec > 1:
        x = sig.decimate(x, dec, ftype="fir")
    return x.astype(np.complex64), fs / dec


def _classify_signal(x, nfs):
    """Heuristic automatic modulation classification from DSP features (pure).

    Returns {label, confidence, symbol_rate_hz, features}. Not ML — a feature
    decision tree over envelope variance, instantaneous-frequency spread &
    bimodality, spectral occupancy and phase jumps. Honest, explainable, good
    enough to guess the common ISM cases (CW / OOK-ASK / FSK / FM / chirp-spread).
    """
    import numpy as np
    out = {"label": "unknown", "confidence": 0.0, "symbol_rate_hz": 0.0, "features": {}}
    if x is None or len(x) < 64:
        out["label"] = "too short"; return out
    a = np.abs(x)
    amean = float(a.mean())
    if amean < 1e-4:
        out["label"] = "no signal / noise"; return out
    an = a / amean
    env_var = float(np.var(an))                                   # amplitude modulation
    ifr = np.angle(x[1:] * np.conj(x[:-1])) * nfs / (2 * np.pi)    # inst freq (Hz)
    ifr_n = ifr / (nfs / 2.0)
    ifr_std = float(np.std(ifr_n))
    # spectral occupancy: fraction of bins within 10 dB of the peak (wideband-ness).
    # Max-hold over the whole selection so a swept chirp shows its full band.
    _fr, ps = welch_psd(x, nfs, nfft=min(2048, 1 << int(np.log2(max(2, len(x))))), reduce="max")
    occ = float((ps > ps.max() - 10).mean())
    # FSK bimodality: split inst-freq at its median, compare inter-cluster gap to spread
    med = np.median(ifr)
    lo, hi = ifr[ifr <= med], ifr[ifr > med]
    bimod = 0.0
    if len(lo) > 8 and len(hi) > 8:
        sep = abs(float(hi.mean()) - float(lo.mean()))
        spread = float(lo.std() + hi.std()) + 1e-9
        bimod = sep / spread
    # phase jumps (PSK tell): count large sample-to-sample phase steps
    dphi = np.abs(np.angle(x[1:] * np.conj(x[:-1])))
    phase_jumps = float((dphi > 1.2).mean())
    f = {"env_var": round(env_var, 4), "ifr_std": round(ifr_std, 4),
         "occupancy": round(occ, 3), "bimodality": round(bimod, 2),
         "phase_jumps": round(phase_jumps, 4)}
    out["features"] = f
    # symbol rate via run-length of the thresholded feature (robust for random
    # data, where autocorrelation has no clear peak) — reuse the demod's slicer.
    if env_var > 0.05:
        lvl = an > 0.5 * (float(np.percentile(an, 90)) + float(np.percentile(an, 10)))
    else:
        lvl = ifr_n > float(np.median(ifr_n))
    _baud, _ = _slice_bits(lvl, nfs)
    out["symbol_rate_hz"] = round(_baud, 1)
    # --- decision tree ---
    if occ > 0.55 and ifr_std > 0.15 and env_var < 0.25:
        out["label"] = "chirp / spread (LoRa-like or wideband)"; out["confidence"] = round(min(1.0, occ), 2)
    elif env_var > 0.3 and bimod < 2.0:
        out["label"] = "OOK / ASK (on-off / amplitude)"; out["confidence"] = round(min(1.0, env_var), 2)
    elif bimod > 3.0 and ifr_std > 0.02:
        out["label"] = "FSK (frequency-shift keying)"; out["confidence"] = round(min(1.0, bimod / 6.0), 2)
    elif ifr_std > 0.08:
        out["label"] = "FM (frequency modulation)"; out["confidence"] = round(min(1.0, ifr_std * 3), 2)
    elif phase_jumps > 0.02 and env_var < 0.2:
        out["label"] = "PSK (phase-shift keying)"; out["confidence"] = round(min(1.0, phase_jumps * 8), 2)
    else:
        out["label"] = "CW carrier (unmodulated)"; out["confidence"] = round(max(0.4, 1.0 - ifr_std * 5 - env_var), 2)
    return out


def constellation(name, f_offset_hz=0.0, bw_hz=None, t0=None, t1=None, n=2000):
    """IQ scatter (normalised) for the selected signal — PSK/QAM structure."""
    import numpy as np
    x, nfs = _prep_selection(name, f_offset_hz, bw_hz, t0, t1)
    if len(x) < 16:
        return {"ok": False, "error": "selection too short"}
    rms = float(np.sqrt(np.mean(np.abs(x) ** 2))) or 1.0
    x = x / rms
    n = int(max(200, min(4000, n)))
    if len(x) > n:
        x = x[np.linspace(0, len(x) - 1, n).astype(int)]
    return {"ok": True, "sample_rate_hz": round(nfs, 1),
            "i": [round(float(v), 3) for v in x.real.tolist()],
            "q": [round(float(v), 3) for v in x.imag.tolist()]}


def instantaneous(name, f_offset_hz=0.0, bw_hz=None, t0=None, t1=None, n=1500):
    """Instantaneous amplitude (dB), frequency (Hz) and phase (deg) over time."""
    import numpy as np
    x, nfs = _prep_selection(name, f_offset_hz, bw_hz, t0, t1)
    if len(x) < 16:
        return {"ok": False, "error": "selection too short"}
    amp = np.abs(x); amp = amp / (amp.max() + 1e-9)
    ampdb = 20 * np.log10(amp + 1e-4)
    freq = np.concatenate([[0.0], np.angle(x[1:] * np.conj(x[:-1])) * nfs / (2 * np.pi)])
    phase = np.degrees(np.unwrap(np.angle(x)))
    n = int(max(200, min(4000, n)))
    def ds(v):
        return v[np.linspace(0, len(v) - 1, n).astype(int)] if len(v) > n else v
    ampdb, freq, phase = ds(ampdb), ds(freq), ds(phase)
    t = np.linspace(0, len(x) / nfs, len(ampdb))
    return {"ok": True, "sample_rate_hz": round(nfs, 1),
            "t": [round(float(v), 6) for v in t.tolist()],
            "amp_db": [round(float(v), 2) for v in ampdb.tolist()],
            "freq_hz": [round(float(v), 1) for v in freq.tolist()],
            "phase_deg": [round(float(v), 1) for v in phase.tolist()]}


def classify(name, f_offset_hz=0.0, bw_hz=None, t0=None, t1=None):
    """Automatic modulation classification for the selected signal."""
    x, nfs = _prep_selection(name, f_offset_hz, bw_hz, t0, t1)
    r = _classify_signal(x, nfs)
    r["ok"] = True
    r["sample_rate_hz"] = round(nfs, 1)
    return r


# --------------------------------------------------------------------------
# Segment 4 — protocol framework: line coding, preamble/sync detection,
# repeated-frame alignment (fixed code vs rolling bits) and a CRC/checksum
# scanner. All pure string/int math — the demodulator recovers the bits, this
# gives them structure. Selftested on synthetic bitstreams, no hardware.
# --------------------------------------------------------------------------

def line_decode(bits, scheme):
    """Decode a raw bitstream by its line coding (pure).

    ``manchester``  — 01->1, 10->0 (IEEE; the common ISM convention);
    ``manchester_ieee`` alias. ``diff_manchester`` — a transition at the start of
    a bit period = 0, none = 1. ``nrzi`` — a transition = 1, none = 0.
    Unknown/``raw`` returns the bits unchanged. Returns the decoded bit string.
    """
    b = bits or ""
    s = (scheme or "raw").lower()
    if s in ("manchester", "manchester_ieee"):
        out = []
        for i in range(0, len(b) - 1, 2):
            p = b[i:i + 2]
            out.append("1" if p == "01" else ("0" if p == "10" else "?"))
        return "".join(out)
    if s in ("nrzi", "diff_manchester"):
        out = []
        prev = b[0] if b else "0"
        for i in range(1, len(b)):
            trans = b[i] != prev
            out.append("1" if trans else "0")
            prev = b[i]
        return "".join(out)
    return b


def _preamble(bits):
    """Length of a leading alternating (0101…/1010…) run — the classic preamble."""
    n = 1
    while n < len(bits) and bits[n] != bits[n - 1]:
        n += 1
    return n if n >= 4 else 0


def _repeat_period(bits, min_p=8):
    """Best repeated-frame period in a bitstream, or 0 (pure, numpy).

    A remote/sensor usually sends the same frame back-to-back; the period is the
    lag (>= min_p) at which the ±1-mapped bit sequence best autocorrelates. Only
    accepts a period with a strong, clear peak so noise-like data returns 0.
    """
    import numpy as np
    n = len(bits)
    if n < min_p * 2:
        return 0
    s = np.frombuffer(bits.encode(), dtype=np.uint8).astype(np.float32)
    s = np.where(s == ord("1"), 1.0, -1.0)
    s -= s.mean()
    if s.std() < 1e-6:
        return 0
    energy = float(np.dot(s, s)) / n + 1e-9
    hi = n // 2
    corr = {}
    best = 0.0
    for lag in range(min_p, hi + 1):
        a, b = s[:-lag], s[lag:]
        c = float(np.dot(a, b) / len(a)) / energy       # normalised [~ -1..1]
        corr[lag] = c
        if c > best:
            best = c
    if best <= 0.5:
        return 0
    # Autocorrelation also peaks at multiples of the true period; take the
    # SMALLEST lag whose correlation is within 90% of the best (the fundamental).
    for lag in range(min_p, hi + 1):
        if corr[lag] >= 0.9 * best:
            return lag
    return 0


def _period_candidates(bits, min_p=8, topk=6, floor=0.2):
    """Ranked candidate frame periods from autocorrelation (pure, numpy).

    Unlike :func:`_repeat_period` (which gates hard and returns one fundamental),
    this returns *several* plausible periods even when the top peak is weak — so
    a jittery real bitstream still offers frame lengths to try. Harmonics of an
    already-listed candidate are collapsed to the fundamental.
    """
    import numpy as np
    n = len(bits)
    if n < min_p * 2:
        return []
    s = np.frombuffer(bits.encode(), dtype=np.uint8).astype(np.float32)
    s = np.where(s == ord("1"), 1.0, -1.0)
    s -= s.mean()
    if s.std() < 1e-6:
        return []
    energy = float(np.dot(s, s)) / n + 1e-9
    hi = n // 2
    scored = []
    for lag in range(min_p, hi + 1):
        a, b = s[:-lag], s[lag:]
        scored.append((float(np.dot(a, b) / len(a)) / energy, lag))
    scored = [x for x in scored if x[0] >= floor]
    scored.sort(reverse=True)                       # strongest correlation first
    out = []
    for c, lag in scored:
        # collapse harmonics: skip a lag that's ~an integer multiple of one kept
        if any(abs(lag - k * p) <= 1 for p in out for k in range(1, lag // p + 1)):
            continue
        out.append(lag)
        if len(out) >= topk:
            break
    return out


def _eval_period(bits, period, skip=0):
    """Align a bitstream into frames of ``period`` (optionally after a ``skip``
    preamble), build a consensus + stability map, and CRC-scan it (pure)."""
    import numpy as np
    body = bits[skip:]
    nrep = len(body) // period
    if period < 8 or nrep < 2:
        return None
    frames = [body[i * period:(i + 1) * period] for i in range(nrep)]
    arr = np.array([[1 if ch == "1" else 0 for ch in f] for f in frames])
    agree = arr.mean(axis=0)
    consensus = "".join("1" if a >= 0.5 else "0" for a in agree)
    stable = np.array([1.0 - 2 * min(a, 1 - a) for a in agree])
    varying = [i for i, st in enumerate(stable) if st < 0.85]
    crc = crc_scan(consensus)
    return {"period_bits": period, "skip_bits": skip, "repeats": nrep,
            "consensus_bits": consensus, "consensus_hex": _to_hex(consensus),
            "varying_positions": varying[:200],
            "stable_fraction": round(float((stable >= 0.85).mean()), 3),
            "identical": len(varying) == 0,
            "crc_matches": crc["matches"]}


def _to_hex(bits):
    """Group a bit string into hex bytes (MSB first); trailing <8 bits appended."""
    out = []
    for i in range(0, len(bits) - 7, 8):
        out.append("%02x" % int(bits[i:i + 8], 2))
    rem = len(bits) % 8
    s = " ".join(out)
    if rem:
        s += (" " if s else "") + "+" + bits[len(bits) - rem:]
    return s


def frame_analysis(bits, period=None):
    """Structure a recovered bitstream: preamble, repeated-frame period(s), a
    per-bit stability map (fixed code vs rolling bits), and CRC per candidate.

    Aligning the repeated frames a remote transmits is *the* reverse-engineering
    move. Beyond the single best autocorrelation period, this returns a ranked
    list of **candidate frame lengths** — each aligned (optionally after the
    preamble), consensus-built and **CRC-scanned** — so a jittery real bitstream
    still offers frame boundaries to try, and a length whose trailer validates a
    CRC rises to the top. Pass ``period`` to force a specific frame length.
    """
    bits = "".join(c for c in (bits or "") if c in "01")
    if len(bits) < 8:
        return {"ok": False, "error": "need at least 8 bits"}
    pre = _preamble(bits)

    # Build ranked candidate periods: the explicit one, the autocorr peaks, and
    # a few common byte-aligned lengths — each evaluated aligned from 0 AND after
    # the preamble, keeping whichever alignment reads better.
    cand_periods = []
    if period:
        try:
            cand_periods.append(int(period))
        except (TypeError, ValueError):
            pass
    cand_periods += _period_candidates(bits)
    for p in (24, 32, 40, 48, 64):                     # common ISM frame lengths
        if 8 <= p <= len(bits) // 2:
            cand_periods.append(p)
    seen, evals = set(), []
    for p in cand_periods:
        if p in seen or p < 8:
            continue
        seen.add(p)
        best_e = None
        for skip in (0, pre if pre >= 4 else 0):
            e = _eval_period(bits, p, skip)
            if e and (best_e is None
                      or (len(e["crc_matches"]), e["stable_fraction"])
                      > (len(best_e["crc_matches"]), best_e["stable_fraction"])):
                best_e = e
        if best_e:
            evals.append(best_e)
    # rank: CRC match first, then most-stable, then most repeats
    evals.sort(key=lambda e: (len(e["crc_matches"]) > 0, e["stable_fraction"], e["repeats"]),
               reverse=True)
    candidates = evals[:6]

    result = {"ok": True, "n_bits": len(bits), "preamble_bits": pre,
              "candidates": candidates}
    # Headline pick: an explicit period, else a CRC-validated candidate, else the
    # gated autocorr fundamental, else the whole blob (unchanged default).
    forced = _eval_period(bits, int(period), 0) if period else None
    crc_winner = next((e for e in candidates if e["crc_matches"]), None)
    auto = _repeat_period(bits)
    head = forced or crc_winner
    if head is None and auto >= 8:
        head = _eval_period(bits, auto, 0)
    if head:
        result["period_bits"] = head["period_bits"]
        for k in ("repeats", "consensus_bits", "consensus_hex",
                  "varying_positions", "stable_fraction", "identical"):
            result[k] = head[k]
        result["crc"] = {"checked": True, "matches": head["crc_matches"]}
    else:
        result["period_bits"] = 0
        result.update({"repeats": 1, "consensus_bits": bits,
                       "consensus_hex": _to_hex(bits), "varying_positions": [],
                       "stable_fraction": 1.0, "identical": True})
        result["crc"] = crc_scan(bits)
    return result


# --- CRC / checksum library (common ISM/embedded polynomials) ---

def _crc8(data, poly, init=0, xorout=0):
    c = init
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFF if (c & 0x80) else (c << 1) & 0xFF
    return c ^ xorout


def _crc16(data, poly, init, xorout=0, refin=False, refout=False):
    def rev(x, n):
        r = 0
        for _ in range(n):
            r = (r << 1) | (x & 1); x >>= 1
        return r
    c = init
    for b in data:
        if refin:
            b = rev(b, 8)
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFFFF if (c & 0x8000) else (c << 1) & 0xFFFF
    if refout:
        c = rev(c, 16)
    return c ^ xorout


def crc_scan(bits):
    """Try common CRC/checksum algorithms over a frame's bytes; report matches.

    Assumes the trailing 1 (8-bit) or 2 (16-bit) bytes are the check value over
    the bytes before them — the usual ISM/embedded layout — and reports any
    algorithm whose computed value matches. Pure; the selftest appends a known
    CRC-8 and asserts it's found.
    """
    bits = "".join(c for c in (bits or "") if c in "01")
    nbytes = len(bits) // 8
    if nbytes < 2:
        return {"checked": True, "matches": []}
    data = [int(bits[i * 8:i * 8 + 8], 2) for i in range(nbytes)]
    matches = []
    algos8 = [("CRC-8", 0x07, 0x00, 0x00),
              ("CRC-8/MAXIM-DOW", 0x31, 0x00, 0x00),
              ("CRC-8/CCITT", 0x07, 0x00, 0x00)]
    # 8-bit check over all preceding bytes
    payload8, chk8 = data[:-1], data[-1]
    for name, poly, init, xor in algos8:
        if _crc8(payload8, poly, init, xor) == chk8:
            matches.append({"algo": name, "width": 8, "over_bytes": len(payload8)})
    if _sum8(payload8) == chk8:
        matches.append({"algo": "checksum-8 (sum)", "width": 8, "over_bytes": len(payload8)})
    if _xor8(payload8) == chk8:
        matches.append({"algo": "XOR-8", "width": 8, "over_bytes": len(payload8)})
    # 16-bit check over all preceding bytes (big-endian trailer)
    if nbytes >= 3:
        payload16 = data[:-2]
        chk16 = (data[-2] << 8) | data[-1]
        algos16 = [("CRC-16/CCITT-FALSE", 0x1021, 0xFFFF, 0x0000, False, False),
                   ("CRC-16/XMODEM", 0x1021, 0x0000, 0x0000, False, False),
                   ("CRC-16/ARC (IBM)", 0x8005, 0x0000, 0x0000, True, True),
                   ("CRC-16/MODBUS", 0x8005, 0xFFFF, 0x0000, True, True)]
        for name, poly, init, xor, ri, ro in algos16:
            if _crc16(payload16, poly, init, xor, ri, ro) == chk16:
                matches.append({"algo": name, "width": 16, "over_bytes": len(payload16)})
    return {"checked": True, "matches": matches}


def _sum8(data):
    return sum(data) & 0xFF


def _xor8(data):
    x = 0
    for b in data:
        x ^= b
    return x


def frames(name=None, bits=None, line=None, period=None):
    """Web entry: analyse a bitstream (raw or line-decoded) into frame structure.

    Pass ``bits`` directly (the demod output the page holds); ``line`` optionally
    line-decodes first (manchester / nrzi / diff_manchester); ``period`` forces a
    specific frame length (from clicking a candidate).
    """
    if not bits:
        return {"ok": False, "error": "no bits — demodulate a signal first"}
    b = line_decode(bits, line) if line and line != "raw" else bits
    try:
        period = int(period) if period else None
    except (TypeError, ValueError):
        period = None
    r = frame_analysis(b, period=period)
    r["line"] = (line or "raw")
    r["decoded_bits"] = b
    return r


# --------------------------------------------------------------------------
# AI agent actions — the assistant may propose analyzer actions (tune, demod,
# classify, …) as a JSON block; this parses/validates them into a safe,
# allowlisted list the page executes against its existing controls. All actions
# are read-only DSP on the local capture (no transmit, nothing destructive).
# Pure; selftested.
# --------------------------------------------------------------------------

# name -> {param: (caster, allowed-set-or-None)} ; params absent are dropped.
_AI_ACTION_SCHEMA = {
    "tune":      {"f_mhz": (float, None), "bw_khz": (float, None),
                  "mode": (str, {"ook", "fsk"})},
    "zoom":      {"t0": (float, None), "t1": (float, None),
                  "f0_mhz": (float, None), "f1_mhz": (float, None)},
    "demod":     {"mode": (str, {"ook", "fsk"}), "bw_khz": (float, None)},
    "classify":  {},
    "frames":    {"line": (str, {"raw", "manchester", "nrzi"}), "period_bits": (int, None)},
    "decode433": {},
    "reset":     {},
}
_AI_ACTION_MAX = 8


def _coerce_action(a):
    """Validate one action dict against the schema; return a clean dict or None."""
    if not isinstance(a, dict):
        return None
    name = str(a.get("action") or a.get("type") or "").strip().lower()
    schema = _AI_ACTION_SCHEMA.get(name)
    if schema is None:
        return None
    out = {"action": name}
    for key, (caster, allowed) in schema.items():
        if key not in a or a[key] is None:
            continue
        try:
            v = caster(a[key])
        except (TypeError, ValueError):
            continue
        if caster is str:
            v = v.strip().lower()
            if allowed and v not in allowed:
                continue
        out[key] = v
    return out


def parse_ai_actions(text):
    """Split an AI reply into (clean_text, actions[]) (pure).

    The assistant may append a fenced ```json {"actions":[…]} ``` block (or a bare
    trailing object containing "actions"). We extract + validate it against
    :data:`_AI_ACTION_SCHEMA`, strip it from the visible text, and return the
    allowlisted actions. Malformed / unknown actions are dropped, not executed.
    """
    import re
    if not text:
        return {"text": "", "actions": []}
    raw = None
    m = None
    for mm in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S):
        m = mm                                          # keep the last fenced block
    if m:
        raw = m.group(1)
        clean = (text[:m.start()] + text[m.end():]).strip()
    else:
        # bare trailing object that mentions "actions"
        m2 = re.search(r"(\{[^{}]*\"actions\"[^{}]*\[.*?\][^{}]*\})\s*$", text, re.S)
        if m2:
            raw = m2.group(1)
            clean = text[:m2.start()].strip()
        else:
            return {"text": text.strip(), "actions": []}
    try:
        obj = json.loads(raw)
        items = obj.get("actions") if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        return {"text": text.strip(), "actions": []}
    if not isinstance(items, list):
        return {"text": clean, "actions": []}
    actions = []
    for a in items:
        c = _coerce_action(a)
        if c:
            actions.append(c)
        if len(actions) >= _AI_ACTION_MAX:
            break
    return {"text": clean, "actions": actions}


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
        # --- modulation classification on synthetic baseband signals ---
        import numpy as np
        _nfs = 100000.0; _N = 40000; _t = np.arange(_N) / _nfs
        noise = lambda: (np.random.randn(_N) + 1j * np.random.randn(_N)) * 0.01
        cw = np.exp(2j * np.pi * 2000 * _t) + noise()
        _sym = (np.random.rand((_t * 1000).astype(int).max() + 1) > 0.5).astype(float)
        keyc = _sym[(_t * 1000).astype(int)]           # random 0/1 symbols @ 1000 baud
        ook = keyc * np.exp(2j * np.pi * 2000 * _t) + noise()
        ftone = np.where((_t * 1000).astype(int) % 2 == 0, 4000.0, -4000.0)
        fsk = np.exp(2j * np.pi * np.cumsum(ftone) / _nfs) + noise()
        sweep = np.linspace(-45000, 45000, _N)
        chirp = np.exp(2j * np.pi * np.cumsum(sweep) / _nfs) + noise()
        cl = lambda x: _classify_signal(x.astype(np.complex64), _nfs)["label"]
        rcw, rook, rfsk, rch = cl(cw), cl(ook), cl(fsk), cl(chirp)
        check("classify: CW carrier", "CW" in rcw, rcw)
        check("classify: OOK/ASK", "OOK" in rook or "ASK" in rook, rook)
        check("classify: FSK", "FSK" in rfsk, rfsk)
        check("classify: chirp/spread", "chirp" in rch or "spread" in rch, rch)
        check("classify: OOK symbol rate ~1000 baud",
              abs(_classify_signal(ook.astype(np.complex64), _nfs)["symbol_rate_hz"] - 1000) < 200,
              str(_classify_signal(ook.astype(np.complex64), _nfs)["symbol_rate_hz"]))
        # --- Segment 4: line coding, frame analysis, CRC scan (pure) ---
        check("line: Manchester 01/10 -> 1/0",
              line_decode("0110", "manchester") == "10")
        check("line: NRZI transition=1",
              line_decode("0" + "0110", "nrzi") == "0101")
        # a fixed frame repeated 5x with a preamble, plus a rolling last byte
        fixed = "10101010" + "11000011" + "01011010"   # preamble + code
        _roll = ["00000001", "01000010", "10000011", "11000100", "00100101"]
        fr_frames = "".join(fixed + _roll[i] for i in range(5))
        fa = frame_analysis(fr_frames)
        check("frame: repeated-frame period detected (=frame length)",
              fa["ok"] and fa["period_bits"] == len(fixed) + 8, str(fa.get("period_bits")))
        check("frame: fixed bits stable, rolling byte flagged varying",
              fa["repeats"] == 5 and any(p >= len(fixed) for p in fa["varying_positions"])
              and fa["stable_fraction"] < 1.0, str(fa.get("varying_positions"))[:60])
        # candidate periods offered (incl. the true 32) + explicit period forcing
        check("frame: candidate list offered incl. the true period",
              any(c["period_bits"] == len(fixed) + 8 for c in fa["candidates"]),
              str([c["period_bits"] for c in fa["candidates"]]))
        check("frame: explicit period is honoured",
              frame_analysis(fr_frames, period=len(fixed) + 8)["period_bits"] == len(fixed) + 8)
        # a repeated 4-byte frame with a per-frame CRC-8 -> that length ranks first
        # (its trailer validates a CRC) and is CRC-flagged in the candidate list.
        one = [0x12, 0x34, 0x56]
        one = one + [_crc8(one, 0x07)]
        fbits = "".join(format(b, "08b") for b in one) * 6      # 32-bit frame ×6
        fc2 = frame_analysis(fbits)
        check("frame: CRC-validated frame length wins the headline",
              fc2["period_bits"] == 32 and fc2["crc"]["matches"], str(fc2.get("period_bits")))
        check("frame: a candidate carries its own CRC match",
              any(c["period_bits"] == 32 and c["crc_matches"] for c in fc2["candidates"]))
        # CRC-8 appended over a known payload is recovered
        payload = [0xDE, 0xAD, 0xBE, 0xEF]
        crcv = _crc8(payload, 0x07)
        pbits = "".join(format(b, "08b") for b in payload + [crcv])
        cs = crc_scan(pbits)
        check("crc: appended CRC-8 is detected",
              any(m["algo"] == "CRC-8" and m["width"] == 8 for m in cs["matches"]), str(cs))
        # a checksum-8 (sum) trailer is recovered too
        pay2 = [0x10, 0x20, 0x33]
        cbits = "".join(format(b, "08b") for b in pay2 + [_sum8(pay2)])
        check("crc: checksum-8 (sum) detected",
              any("sum" in m["algo"] for m in crc_scan(cbits)["matches"]))
        check("frames: web wrapper line-decodes + analyses",
              frames(bits="0110" * 8, line="manchester").get("ok") is True)
        # --- AI agent action parsing (allowlist + coerce + strip) ---
        pa = parse_ai_actions('Set it to OOK.\n```json\n{"actions":[{"action":"tune","f_mhz":"433.92","bw_khz":60},'
                              '{"action":"demod","mode":"OOK"},{"action":"nuke","f_mhz":1}]}\n```')
        acts = pa["actions"]
        check("ai-act: fenced block stripped from visible text",
              "```" not in pa["text"] and pa["text"].startswith("Set it to OOK"))
        check("ai-act: tune coerced (f_mhz float, bw kept)",
              acts and acts[0]["action"] == "tune" and abs(acts[0]["f_mhz"] - 433.92) < 1e-6
              and acts[0]["bw_khz"] == 60.0, str(acts))
        check("ai-act: demod mode lowercased + validated",
              any(a["action"] == "demod" and a.get("mode") == "ook" for a in acts))
        check("ai-act: unknown action dropped",
              not any(a["action"] == "nuke" for a in acts))
        check("ai-act: no block -> empty actions, text intact",
              parse_ai_actions("just prose")["actions"] == []
              and parse_ai_actions("just prose")["text"] == "just prose")
        check("ai-act: bad mode value rejected",
              "mode" not in (parse_ai_actions('```json\n{"actions":[{"action":"demod","mode":"psk"}]}\n```')["actions"][0]))
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
