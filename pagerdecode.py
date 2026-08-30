#!/usr/bin/env python3
"""
pager.py — POCSAG / FLEX / Motorola QCII pager decode via RTL-SDR.

Pagers are still everywhere — hospitals, industrial SCADA, alarm/telemetry,
on-call teams — and POCSAG/FLEX are transmitted **in the clear**. An RTL-SDR
tuned to a pager channel, FM-demodulated by ``rtl_fm`` and decoded by
``multimon-ng``, recovers the messages: capcode (address), function bits, and
the alphanumeric/numeric text.

Motorola **Quick Call II** (QCII) is the classic two-tone sequential paging
format still used by fire/EMS dispatch: a ~1 s "A" tone then a ~3 s "B" tone,
each from a standard Motorola tone set, whose pair addresses one pager (which
then unmutes for the voice dispatch that follows). multimon-ng has no QCII
decoder, so we detect the two audio tones ourselves (FFT peak + duration
gating over the ``rtl_fm`` audio) — see ``qcii_detect``. It is its own capture
mode (one dongle), selected alongside the POCSAG/FLEX mode.

This is passive, receive-only reception. Pager traffic is unencrypted by design,
but it is frequently *sensitive* (patient data, security callouts), so decoding
third-party traffic is regulated in many places — use it lawfully.

One dongle, one claim
---------------------
This uses ``rtl_fm`` (the whole RTL-SDR), so it is mutually exclusive with the
sub-GHz sweep / ISM decoder and ADS-B — the web layer stops the others first.

CLI
---
    python3 pagerdecode.py detect
    python3 pagerdecode.py run --freq 153.350M [--seconds N]
    python3 pagerdecode.py selftest
"""

import os
import re
import subprocess
import sys
import threading
import time

try:
    import numpy as np                 # QCII tone decode is DSP; POCSAG/FLEX don't need it
except Exception:                       # pragma: no cover - numpy is a base dep here
    np = None


def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


_RTL_FM = _which("rtl_fm")
_MULTIMON = _which("multimon-ng")
_MSG_RING = 500

# POCSAG has three on-air baud rates (512 / 1200 / 2400) — each is a *separate*
# multimon-ng demodulator. FLEX is one demodulator that auto-detects its speed
# (1600 / 3200 / 6400 baud, 2- or 4-level) from the sync frame, so a single
# "FLEX" toggle covers all FLEX speeds. Letting the user pick *which* demods run
# is the "baud rate setting": on a FLEX-only channel, leaving the POCSAG demods
# on makes multimon slice noise into garbage POCSAG pages, so narrowing to just
# the protocol actually on the channel is the main cure for gibberish output.
POCSAG_FLEX_DEMODS = ("POCSAG512", "POCSAG1200", "POCSAG2400", "FLEX", "FLEX_NEXT")
_DEFAULT_DEMODS = ("POCSAG512", "POCSAG1200", "POCSAG2400", "FLEX")


def _clean_demods(demods):
    """Normalise a requested demod list to the supported set, order preserved.

    Accepts a list/tuple or comma/space string of demod names (case-insensitive).
    Unknown names are dropped; an empty/None request falls back to the default
    POCSAG-512/1200/2400 + FLEX set so the decoder is never launched with no
    demodulators (which multimon rejects)."""
    if demods is None:
        return list(_DEFAULT_DEMODS)
    if isinstance(demods, str):
        demods = re.split(r"[,\s]+", demods.strip())
    allow = {d.upper(): d for d in POCSAG_FLEX_DEMODS}
    out, seen = [], set()
    for d in demods:
        key = str(d).strip().upper()
        if key in allow and key not in seen:
            seen.add(key)
            out.append(allow[key])
    return out or list(_DEFAULT_DEMODS)

# Common pager channels (label -> Hz). Regional and non-exhaustive; the UI also
# accepts a free-form frequency. POCSAG runs on scattered VHF/UHF channels.
PAGER_PRESETS = {
    "153.350 (UK POCSAG)": 153_350_000,
    "153.275 (UK POCSAG)": 153_275_000,
    "148.4375 (US)":       148_437_500,
    "152.0075 (US medical)": 152_007_500,
    "466.075 (UK POCSAG)": 466_075_000,
    "439.9875 (ham POCSAG)": 439_987_500,
    "929.6625 (US FLEX)":  929_662_500,
    "931.9375 (US FLEX)":  931_937_500,
    "154.265 (US fire QCII)": 154_265_000,
    "155.340 (US EMS QCII)":  155_340_000,
    "460.500 (US UHF QCII)":  460_500_000,
}


def _run(args, timeout=6):
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


def _have(path):
    return _run([path, "-h"])[0] != 127 or os.path.exists(path)


def detect():
    """Report pager-decode capability.

    ``available`` covers the POCSAG/FLEX path (rtl_fm + multimon-ng + a dongle).
    ``qcii_available`` covers the Motorola QCII tone path, which needs only
    rtl_fm + numpy + a dongle (no multimon-ng) — so it can be usable even when
    multimon-ng isn't installed.
    """
    tools = {"rtl_fm": _have(_RTL_FM), "multimon_ng": _have(_MULTIMON),
             "numpy": np is not None}
    usb = None
    try:
        import rtl_sdr
        usb = rtl_sdr.probe_usb()[0]
    except Exception:
        usb = None
    device = usb is not None
    qcii_ok = tools["rtl_fm"] and tools["numpy"] and device
    base = {"tools": tools, "device_present": device, "usb_id": usb,
            "presets": PAGER_PRESETS, "qcii_available": qcii_ok,
            "demods": list(POCSAG_FLEX_DEMODS), "default_demods": list(_DEFAULT_DEMODS),
            "tools_installed": tools["multimon_ng"] and tools["rtl_fm"]}
    if not tools["rtl_fm"]:
        base.update(available=False, error="rtl_fm not installed (apt install rtl-sdr)")
    elif not tools["multimon_ng"]:
        # POCSAG/FLEX needs multimon; QCII may still be available.
        base.update(available=False,
                    error="multimon-ng not installed (apt install multimon-ng)"
                          + ("" if not qcii_ok else " — QCII tone decode still available"))
    elif not device:
        base.update(available=False, error="no RTL-SDR on the USB bus — plug a dongle in")
    else:
        base.update(available=True, error=None)
    return base


# --------------------------------------------------------------------------
# multimon-ng output parser — pure, drives the selftest
# --------------------------------------------------------------------------

_POCSAG_RE = re.compile(
    r"^(POCSAG\d+):\s*Address:\s*(\d+)\s*Function:\s*(\d+)"
    r"(?:\s*(Alpha|Numeric):\s*(.*))?", re.I)
_FLEX_RE = re.compile(r"^FLEX[:|].*?\[(\d+)\][^A-Za-z0-9]*([A-Z]{3})?\s*(.*)$")


def parse_multimon(line):
    """Parse one multimon-ng output line into a pager message dict, or None.

    Handles POCSAG512/1200/2400 (Address/Function/Alpha|Numeric) and FLEX
    (capcode in [..] + trailing text). Returns
    {protocol, capcode, function, kind, text} for a decoded page.
    """
    if not line:
        return None
    s = line.strip()
    m = _POCSAG_RE.match(s)
    if m:
        proto, addr, func, kind, text = m.groups()
        text = (text or "").strip()
        return {"protocol": proto.upper(), "capcode": addr,
                "function": int(func), "kind": (kind or "").capitalize() or None,
                "text": text or None}
    if s.upper().startswith("FLEX"):
        m = _FLEX_RE.match(s)
        if m:
            cap, kind, text = m.groups()
            return {"protocol": "FLEX", "capcode": cap, "function": None,
                    "kind": kind, "text": (text or "").strip() or None}
    return None


# --------------------------------------------------------------------------
# Motorola Quick Call II (QCII) two-tone sequential decode
#
# QCII addresses a pager with two sequential audio tones: an "A" tone held
# ~1 s, then a "B" tone held ~3 s, each drawn from a standard Motorola tone
# set (~290-1600 Hz). A "group call" uses a single long tone (A == B, or one
# ~8 s tone). We recover the tones straight from the FM-demodulated audio:
# per-frame FFT dominant-tone tracking, then duration gating for the A-then-B
# shape. The *measured* Hz is authoritative; we additionally snap each tone to
# the nearest standard Motorola tone (best-effort label) when it's within
# tolerance. This is receive-only reception of an in-the-clear signal.
# --------------------------------------------------------------------------

# Motorola "Standard" tone set (Hz). Best-effort reference for labelling a
# detected tone; the measured frequency is what the decode reports as truth.
QCII_STD_TONES = (
    330.5, 349.0, 368.5, 389.0, 410.8, 433.7, 457.9, 483.5, 510.5, 539.0,
    569.1, 600.9, 634.5, 669.9, 707.3, 746.8, 788.5, 832.5, 879.0, 928.1,
    980.0, 1034.7, 1092.4, 1153.4, 1217.8, 1285.8, 1357.6, 1433.4, 1513.5, 1598.0,
    600.0, 741.0, 882.0, 1023.0, 1164.0, 1305.0, 1446.0, 1587.0, 1728.0, 1869.0,
)

_QCII_N = 2048          # FFT window (~93 ms at 22050 Hz -> ~10.8 Hz bins, sub-Hz w/ interp)
_QCII_HOP = 512         # 75% overlap
_QCII_LO_HZ = 250.0     # tone search band
_QCII_HI_HZ = 3000.0
_QCII_TONALITY = 0.40   # peak-energy / band-energy floor to call a frame "a tone"
_QCII_MERGE_HZ = 9.0    # frames within this of a run's mean extend the run
# A-then-B duration windows (seconds), generous across Motorola variants.
_QCII_A_MIN, _QCII_A_MAX = 0.5, 1.9
_QCII_B_MIN, _QCII_B_MAX = 1.8, 5.5
_QCII_GAP_MAX = 0.30    # max silence between the A and B tones


def _qcii_frame_tone(frame, sr):
    """Dominant tone (Hz) + tonality [0..1] in one frame, or (None, 0.0).

    Parabolic interpolation on the FFT peak gives ~1 Hz resolution; tonality is
    the fraction of in-band energy concentrated at the peak (rejects noise).
    """
    n = len(frame)
    w = np.hanning(n)
    spec = np.abs(np.fft.rfft(frame * w))
    if spec.size < 3:
        return None, 0.0
    binhz = sr / n
    lo = max(1, int(_QCII_LO_HZ / binhz))
    hi = min(spec.size - 1, int(_QCII_HI_HZ / binhz))
    if hi <= lo:
        return None, 0.0
    k = lo + int(np.argmax(spec[lo:hi]))
    band_e = float(np.sum(spec[lo:hi] ** 2)) + 1e-12
    peak_e = float(np.sum(spec[k - 1:k + 2] ** 2))
    tonality = peak_e / band_e
    a, b, c = spec[k - 1], spec[k], spec[k + 1]
    denom = a - 2 * b + c
    delta = (0.5 * (a - c) / denom) if denom != 0 else 0.0
    return (k + delta) * binhz, tonality


def qcii_detect(samples, sr):
    """Find Motorola QCII two-tone pages in a mono float audio buffer.

    Returns a list of {a_hz, b_hz, a_s, b_s, group} dicts (one per page). Pure
    and hardware-free, so the selftest drives it with synthesised tones.
    """
    if np is None or samples is None or len(samples) < _QCII_N:
        return []
    x = np.asarray(samples, dtype=np.float64)
    if x.size == 0:
        return []
    peak = float(np.max(np.abs(x))) or 1.0
    x = x / peak
    # per-frame dominant tone
    frames = []
    for start in range(0, len(x) - _QCII_N + 1, _QCII_HOP):
        hz, ton = _qcii_frame_tone(x[start:start + _QCII_N], sr)
        frames.append(hz if (hz is not None and ton >= _QCII_TONALITY) else None)
    if not frames:
        return []
    ft = _QCII_HOP / sr                 # seconds per frame step
    # run-length encode stable-tone runs
    runs = []                           # (mean_hz, start_s, end_s)
    cur, csum, cn, cstart = None, 0.0, 0, 0
    for i, hz in enumerate(frames + [None]):
        mean = (csum / cn) if cn else None
        if hz is not None and mean is not None and abs(hz - mean) <= _QCII_MERGE_HZ:
            csum += hz; cn += 1
        else:
            if cn:
                runs.append((csum / cn, cstart * ft, i * ft))
            if hz is not None:
                cur, csum, cn, cstart = hz, hz, 1, i
            else:
                cur, csum, cn = None, 0.0, 0
    # A(~1 s) immediately followed by a different B(~3 s)  ->  a page
    pages = []
    for j in range(len(runs) - 1):
        a_hz, a0, a1 = runs[j]
        b_hz, b0, b1 = runs[j + 1]
        adur, bdur, gap = a1 - a0, b1 - b0, b0 - a1
        if (_QCII_A_MIN <= adur <= _QCII_A_MAX and _QCII_B_MIN <= bdur <= _QCII_B_MAX
                and 0 <= gap <= _QCII_GAP_MAX and abs(a_hz - b_hz) > _QCII_MERGE_HZ):
            pages.append({"a_hz": round(a_hz, 1), "b_hz": round(b_hz, 1),
                          "a_s": round(adur, 2), "b_s": round(bdur, 2),
                          "group": False})
    # group/all-call: a single long steady tone
    for a_hz, a0, a1 in runs:
        if (a1 - a0) >= 6.0:
            pages.append({"a_hz": round(a_hz, 1), "b_hz": round(a_hz, 1),
                          "a_s": round(a1 - a0, 2), "b_s": 0.0, "group": True})
    return pages


def _qcii_snap(hz, tol=3.0):
    """Nearest standard Motorola tone within ``tol`` Hz, or None."""
    best, bd = None, tol
    for t in QCII_STD_TONES:
        d = abs(hz - t)
        if d <= bd:
            best, bd = t, d
    return best


def qcii_message(page):
    """Turn a qcii_detect page into a pager-message dict for the shared feed."""
    a, b = page["a_hz"], page["b_hz"]
    sa, sb = _qcii_snap(a), _qcii_snap(b)
    if page.get("group"):
        cap = "%.1f" % a
        text = "Group/all-call — single tone %.1f Hz (%.2fs)" % (a, page["a_s"])
    else:
        cap = "%.1f/%.1f" % (a, b)
        std = []
        if sa:
            std.append("A~%.1f" % sa)
        if sb:
            std.append("B~%.1f" % sb)
        tail = ("  [std %s]" % ", ".join(std)) if std else ""
        text = "Two-tone page — A %.1f Hz (%.2fs) · B %.1f Hz (%.2fs)%s" % (
            a, page["a_s"], b, page["b_s"], tail)
    return {"protocol": "QCII", "capcode": cap, "function": None,
            "kind": "Group" if page.get("group") else "Tone", "text": text}


# --------------------------------------------------------------------------
# Live decoder (rtl_fm | multimon-ng)
# --------------------------------------------------------------------------

class PagerDecoder:
    def __init__(self):
        self._lock = threading.Lock()
        self._fm = None
        self._mm = None
        self._thread = None
        self._stop = threading.Event()
        self._msgs = []
        self._count = 0
        self._freq = None
        self._error = None
        self._started = None
        self._mode = "pocsag_flex"
        self._demods = list(_DEFAULT_DEMODS)
        self._invert = False
        self._qcii_recent = {}

    def status(self):
        with self._lock:
            return {"running": bool(self._thread and self._thread.is_alive()),
                    "freq_hz": self._freq, "messages": self._count,
                    "error": self._error, "mode": self._mode,
                    "demods": list(self._demods), "invert": self._invert,
                    "seconds": round(time.time() - self._started, 1) if self._started else 0}

    def messages(self, since=0):
        with self._lock:
            try:
                since = int(since)
            except (TypeError, ValueError):
                since = 0
            new = [m for m in self._msgs if m["seq"] > since]
            return {"messages": new, "seq": self._count, "freq_hz": self._freq,
                    "running": bool(self._thread and self._thread.is_alive()),
                    "mode": self._mode, "demods": list(self._demods),
                    "invert": self._invert, "error": self._error}

    # rtl_fm audio rate. multimon-ng's raw demodulators require exactly 22050 Hz
    # 16-bit mono (see rtl_fm's own `-s 22050 | multimon` example); the QCII
    # tone path reuses the same stream. Do NOT change this without re-checking
    # multimon — a different rate is a classic cause of garbage decodes.
    _QCII_SR = 22050
    _RATE = 22050

    def start(self, freq_hz, mode="pocsag_flex", demods=None, invert=False):
        try:
            freq_hz = int(float(freq_hz))
        except (TypeError, ValueError):
            return {"ok": False, "error": "bad frequency"}
        if not (24_000_000 <= freq_hz <= 1_766_000_000):
            return {"ok": False, "error": "frequency out of RTL-SDR range"}
        mode = "qcii" if str(mode).lower() == "qcii" else "pocsag_flex"
        if mode == "qcii" and np is None:
            return {"ok": False, "error": "QCII decode needs numpy"}
        demods = _clean_demods(demods)
        invert = bool(invert)
        with self._lock:
            if self._thread and self._thread.is_alive():
                self._stop_locked()
            self._stop.clear()
            self._msgs = []
            self._count = 0
            self._qcii_recent = {}
            self._freq = freq_hz
            self._mode = mode
            self._demods = demods
            self._invert = invert
            self._error = None
            self._started = time.time()
            ppm = 0
            gain = None
            try:
                import rtl_sdr
                t = rtl_sdr.get_tuning()
                ppm = t.get("ppm", 0)
                gain = None if t.get("gain_is_auto") else t.get("gain")
            except Exception:
                pass
            # -F 9 enables rtl_fm's low-leakage downsample FIR — noticeably
            # cleaner narrowband FM than the default roll-off, which is exactly
            # what marginal POCSAG/FLEX needs to slice symbols correctly.
            fm_cmd = [_RTL_FM, "-f", str(freq_hz), "-M", "fm",
                      "-s", str(self._RATE), "-F", "9", "-l", "0", "-p", str(ppm or 0)]
            if gain is not None:
                fm_cmd += ["-g", str(gain)]
            fm_cmd += ["-"]
            # Only the demods the user selected (default: all POCSAG + FLEX).
            # -u prunes statistically unlikely POCSAG decodes (kills a lot of
            # noise-into-garbage). -i inverts the bitstream — multimon's own
            # advice "try this if decoding fails" for a mis-polarised channel.
            mm_cmd = [_MULTIMON]
            for d in self._demods:
                mm_cmd += ["-a", d]
            mm_cmd += ["-f", "alpha", "-t", "raw", "-u"]
            if invert:
                mm_cmd += ["-i"]
            mm_cmd += ["-"]
            try:
                self._fm = subprocess.Popen(fm_cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL)
                if mode == "qcii":
                    self._mm = None          # tones are decoded in-process, no multimon
                    target = self._qcii_loop
                else:
                    self._mm = subprocess.Popen(mm_cmd, stdin=self._fm.stdout,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.DEVNULL, text=True)
                    self._fm.stdout.close()   # allow rtl_fm to get SIGPIPE if mm exits
                    target = self._read_loop
            except Exception as exc:
                self._error = "failed to launch rtl_fm%s: %s" % (
                    "" if mode == "qcii" else "|multimon-ng", exc)
                self._stop_locked()
                return {"ok": False, "error": self._error}
            self._thread = threading.Thread(target=target, daemon=True,
                                            name="pager-decode")
            self._thread.start()
        return {"ok": True, "freq_hz": freq_hz, "mode": mode}

    def _read_loop(self):
        try:
            for line in self._mm.stdout:
                if self._stop.is_set():
                    break
                rec = parse_multimon(line)
                if not rec:
                    continue
                with self._lock:
                    self._count += 1
                    rec["seq"] = self._count
                    rec["ts"] = time.time()
                    self._msgs.append(rec)
                    if len(self._msgs) > _MSG_RING:
                        self._msgs = self._msgs[-_MSG_RING:]
        except Exception as exc:  # pragma: no cover - defensive
            with self._lock:
                self._error = str(exc)

    def _qcii_loop(self):  # pragma: no cover - hardware audio path
        """Read rtl_fm PCM, keep a rolling window, and decode QCII two-tone pages."""
        sr = self._QCII_SR
        win = int(sr * 7.0)                     # analysis window: A(~1s)+B(~3s)+margin
        hop_s = 1.0                             # re-run the detector this often
        chunk = int(sr * 0.25) * 2              # ~0.25 s of int16 per read
        buf = np.zeros(0, dtype=np.float32)
        pending = b""
        next_run = time.time() + hop_s
        try:
            raw = self._fm.stdout
            while not self._stop.is_set():
                data = raw.read(chunk)
                if not data:
                    break
                pending += data
                nfull = len(pending) // 2
                if nfull:
                    arr = (np.frombuffer(pending[:nfull * 2], dtype=np.int16)
                           .astype(np.float32) / 32768.0)
                    pending = pending[nfull * 2:]
                    buf = np.concatenate([buf, arr])[-win:]
                if time.time() < next_run:
                    continue
                next_run = time.time() + hop_s
                now = time.time()
                for pg in qcii_detect(buf, sr):
                    # the same page shows up in several overlapping windows; snap
                    # the tones to ~2 Hz and suppress re-emits for a few seconds.
                    key = (round(pg["a_hz"] / 2) * 2, round(pg["b_hz"] / 2) * 2, pg["group"])
                    if now - self._qcii_recent.get(key, 0) < 9.0:
                        continue
                    self._qcii_recent[key] = now
                    rec = qcii_message(pg)
                    with self._lock:
                        self._count += 1
                        rec["seq"] = self._count
                        rec["ts"] = now
                        self._msgs.append(rec)
                        if len(self._msgs) > _MSG_RING:
                            self._msgs = self._msgs[-_MSG_RING:]
                self._qcii_recent = {k: v for k, v in self._qcii_recent.items()
                                     if now - v < 12.0}
        except Exception as exc:
            with self._lock:
                self._error = str(exc)

    def _stop_locked(self):
        self._stop.set()
        for proc in (self._mm, self._fm):
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        self._mm = None
        self._fm = None

    def stop(self):
        with self._lock:
            self._stop_locked()
        return {"ok": True}


_decoder = PagerDecoder()


def start(freq_hz=None, mode="pocsag_flex", demods=None, invert=False):
    d = detect()
    mode = "qcii" if str(mode).lower() == "qcii" else "pocsag_flex"
    if mode == "qcii":
        if not d.get("qcii_available"):
            need = "numpy" if not d["tools"].get("numpy") else (
                "rtl_fm" if not d["tools"].get("rtl_fm") else "an RTL-SDR")
            return {"ok": False, "error": "QCII decode needs %s" % need}
    elif not d.get("available"):
        return {"ok": False, "error": d.get("error", "pager decode unavailable")}
    if freq_hz is None:
        freq_hz = list(PAGER_PRESETS.values())[0]
    return _decoder.start(freq_hz, mode=mode, demods=demods, invert=invert)


def stop():
    return _decoder.stop()


def status():
    st = _decoder.status()
    st["detect"] = detect()
    return st


def messages(since=0):
    return _decoder.messages(since=since)


def install():
    """One-click install of multimon-ng (apt — it IS in the Debian repos)."""
    if _have(_MULTIMON):
        return {"ok": True, "already": True, "detect": detect()}
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    out = ""
    for attempt in range(2):
        try:
            p = subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", "multimon-ng"],
                               capture_output=True, text=True, timeout=300, check=False, env=env)
            out = (p.stdout or "") + (p.stderr or "")
        except Exception as exc:
            return {"ok": False, "error": str(exc), "detect": detect()}
        if _have(_MULTIMON):
            break
        if "Unable to locate package" in out and attempt == 0:
            try:
                subprocess.run(["apt-get", "update"], capture_output=True, text=True,
                               timeout=180, check=False, env=env)
            except Exception:
                pass
    ok = _have(_MULTIMON)
    return {"ok": ok, "detect": detect(), "output": "\n".join(out.strip().splitlines()[-10:]),
            "error": None if ok else "apt could not install multimon-ng (check network/apt)"}


# --------------------------------------------------------------------------
# Selftest (pure parser, no hardware)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    a = parse_multimon("POCSAG1200: Address:  1234567  Function: 3  Alpha:   Call maintenance to ward 4")
    check("pocsag: alpha message parsed",
          a and a["protocol"] == "POCSAG1200" and a["capcode"] == "1234567"
          and a["function"] == 3 and a["kind"] == "Alpha"
          and a["text"] == "Call maintenance to ward 4", str(a))
    n = parse_multimon("POCSAG512: Address:  0980809  Function: 0  Numeric:  1234-5678")
    check("pocsag: numeric message parsed",
          n and n["protocol"] == "POCSAG512" and n["capcode"] == "0980809"
          and n["kind"] == "Numeric" and n["text"] == "1234-5678", str(n))
    b = parse_multimon("POCSAG1200: Address:  0421337  Function: 1")
    check("pocsag: address-only (no text) parsed",
          b and b["capcode"] == "0421337" and b["function"] == 1 and b["text"] is None, str(b))
    f = parse_multimon("FLEX: 2009-01-01 12:00:00 1600/2/K/A 12.345 [0891234] ALN Test page hello")
    check("flex: capcode + text parsed",
          f and f["protocol"] == "FLEX" and f["capcode"] == "0891234"
          and "Test page hello" in (f["text"] or ""), str(f))
    check("parse: noise / status lines -> None",
          parse_multimon("Enabled demodulators: POCSAG1200") is None
          and parse_multimon("") is None and parse_multimon("garbage line") is None)

    # ring ingest via the parser
    dec = PagerDecoder()
    for ln in ("POCSAG1200: Address:  111  Function: 0  Alpha:   one",
               "POCSAG1200: Address:  222  Function: 0  Alpha:   two"):
        rec = parse_multimon(ln)
        with dec._lock:
            dec._count += 1
            rec["seq"] = dec._count
            rec["ts"] = 0
            dec._msgs.append(rec)
    got = dec.messages(since=1)
    check("ring: since-cursor returns only newer messages",
          got["seq"] == 2 and len(got["messages"]) == 1 and got["messages"][0]["capcode"] == "222",
          str(got))
    check("presets: common pager channels present",
          any("POCSAG" in k for k in PAGER_PRESETS) and all(24e6 <= v <= 1766e6 for v in PAGER_PRESETS.values()))

    # --- demod / baud selector normalisation ---
    check("demods: None -> default POCSAG+FLEX set",
          _clean_demods(None) == list(_DEFAULT_DEMODS), str(_clean_demods(None)))
    check("demods: FLEX-only request kept as-is",
          _clean_demods(["FLEX"]) == ["FLEX"], str(_clean_demods(["FLEX"])))
    check("demods: case-insensitive + comma string + dedupe",
          _clean_demods("flex, pocsag1200, POCSAG1200") == ["FLEX", "POCSAG1200"],
          str(_clean_demods("flex, pocsag1200, POCSAG1200")))
    check("demods: unknown names dropped, empty -> default",
          _clean_demods(["bogus", "NOTAREAL"]) == list(_DEFAULT_DEMODS),
          str(_clean_demods(["bogus"])))

    # --- Motorola QCII two-tone decode (synthesised audio, no hardware) ---
    if np is not None:
        sr = PagerDecoder._QCII_SR
        def _tone(f, secs):
            t = np.arange(int(sr * secs)) / sr
            return 0.6 * np.sin(2 * np.pi * f * t)
        rng = np.random.default_rng(1)
        def _noise(secs):
            return 0.02 * rng.standard_normal(int(sr * secs))
        # classic A(1s @1153.4)->B(3s @1285.8) page, with lead-in/out silence
        page = np.concatenate([_noise(0.4), _tone(1153.4, 1.0) + _noise(1.0),
                               _tone(1285.8, 3.0) + _noise(3.0), _noise(0.4)])
        pgs = qcii_detect(page, sr)
        check("qcii: A->B two-tone page detected",
              len(pgs) == 1 and abs(pgs[0]["a_hz"] - 1153.4) < 4
              and abs(pgs[0]["b_hz"] - 1285.8) < 4
              and abs(pgs[0]["a_s"] - 1.0) < 0.25 and abs(pgs[0]["b_s"] - 3.0) < 0.3,
              str(pgs))
        check("qcii: page renders a pager message",
              (lambda m: m["protocol"] == "QCII" and "/" in m["capcode"]
               and "1153" in m["text"])(qcii_message(pgs[0])) if pgs else False)
        # a single long tone -> group/all-call
        grp = qcii_detect(np.concatenate([_noise(0.3), _tone(600.9, 7.0) + _noise(7.0)]), sr)
        check("qcii: single long tone -> group call",
              any(p["group"] and abs(p["a_hz"] - 600.9) < 4 for p in grp), str(grp))
        # pure noise -> nothing
        check("qcii: noise floor yields no false pages",
              qcii_detect(_noise(6.0), sr) == [])
        check("qcii: tone snaps to nearest standard Motorola tone",
              _qcii_snap(1153.9) == 1153.4 and _qcii_snap(1300.0) is None)

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


def _main(argv):
    import json
    cmd = argv[1] if len(argv) > 1 else "detect"
    if cmd == "detect":
        print(json.dumps(detect(), indent=2))
    elif cmd == "selftest":
        r = selftest()
        for x in r["results"]:
            print("  [%s] %s%s" % ("PASS" if x["pass"] else "FAIL", x["name"],
                                   "" if x["pass"] else "  -> " + x["detail"]))
        print("\n%d/%d checks pass — %s" % (r["passed"], r["total"],
                                            "OK" if r["pass"] else "FAILURES"))
        return 0 if r["pass"] else 1
    elif cmd == "run":
        freq = 153_350_000
        if "--freq" in argv:
            fv = argv[argv.index("--freq") + 1].upper().replace("M", "e6").replace("K", "e3")
            freq = int(float(fv))
        secs = 30
        if "--seconds" in argv:
            secs = int(argv[argv.index("--seconds") + 1])
        print(start(freq))
        t0 = time.time()
        try:
            while time.time() - t0 < secs:
                time.sleep(2)
                print("messages=%d" % status()["messages"])
        finally:
            stop()
    else:
        print("usage: pagerdecode.py [detect|run|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
