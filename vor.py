#!/usr/bin/env python3
"""
vor.py — decode a live VOR radial from an RTL-SDR (the bearing FROM the station).

A VOR (VHF Omnidirectional Range, 108.00-117.95 MHz) is a ground navigation
beacon. Every VOR transmits two 30 Hz signals whose phase relationship encodes
compass bearing:

  * a **reference** 30 Hz — FM-modulated onto a 9960 Hz subcarrier (+/-480 Hz),
    the same phase in every direction;
  * a **variable** 30 Hz — amplitude-modulated directly by the station's
    rotating antenna pattern, so its phase, as heard by a receiver, equals the
    magnetic bearing from the station to that receiver.

The phase difference between the two 30 Hz tones IS the **radial** you are on.
An aircraft's VOR receiver does exactly this; so can an RTL-SDR: AM-demodulate
the station (``rtl_fm -M am``) and recover both 30 Hz tones from the composite
audio. This is passive, receive-only reception of an unencrypted aviation aid.

Decode (see ``vor_decode``):
  variable phase  = DFT of the composite audio at 30 Hz
  reference phase = FM-demod the 9960 Hz subcarrier, then DFT that at 30 Hz
  radial          = (reference_phase - variable_phase)  mod 360   (+ calibration)

CLI
---
    python3 vor.py detect
    python3 vor.py run --freq 113.600M [--seconds N]
    python3 vor.py selftest
"""

import os
import subprocess
import sys
import threading
import time

try:
    import numpy as np
except Exception:                       # pragma: no cover - numpy is a base dep here
    np = None


def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


_RTL_FM = _which("rtl_fm")
_SR = 44100                 # AM audio rate: covers the 9960+/-480 Hz subcarrier
_SUBCARRIER = 9960.0
_DEVIATION = 480.0
_TONE = 30.0                # both nav tones are 30 Hz
_LOCK_MIN = 0.02            # min per-tone amplitude (of normalised audio) to trust a fix

# A few example VOR frequencies to get started; VORs are local, so the UI also
# takes a free-form frequency. VOR channels are 108.00-117.95 MHz (108-112 on
# the even-tenths .x0/.x5 that aren't ILS localiser pairs).
VOR_PRESETS = {
    "108.20": 108_200_000,
    "110.60": 110_600_000,
    "113.60": 113_600_000,
    "114.10": 114_100_000,
    "115.80": 115_800_000,
    "117.30": 117_300_000,
}


# --------------------------------------------------------------------------
# DSP core — pure, drives the selftest with a synthesised composite
# --------------------------------------------------------------------------

def _bandpass(x, sr, f1, f2):
    """Zero-phase brick-wall band-pass via rFFT (fine for fixed analysis frames)."""
    n = len(x)
    spec = np.fft.rfft(x)
    freqs = np.fft.rfftfreq(n, 1.0 / sr)
    spec[(freqs < f1) | (freqs > f2)] = 0.0
    return np.fft.irfft(spec, n=n)


def _analytic(x):
    """Analytic signal (numpy Hilbert) — no scipy dependency."""
    n = len(x)
    X = np.fft.fft(x)
    h = np.zeros(n)
    if n % 2 == 0:
        h[0] = h[n // 2] = 1.0
        h[1:n // 2] = 2.0
    else:
        h[0] = 1.0
        h[1:(n + 1) // 2] = 2.0
    return np.fft.ifft(X * h)


def _phasor_at(x, sr, f):
    """Complex DFT coefficient of x at exactly f Hz (phase + amplitude)."""
    n = len(x)
    t = np.arange(n) / sr
    return np.sum(x * np.exp(-2j * np.pi * f * t)) * 2.0 / n


def _fm_demod_ref(comp, sr):
    """Recover the reference 30 Hz tone by FM-demodulating the 9960 Hz subcarrier."""
    sub = _bandpass(comp, sr, _SUBCARRIER - _DEVIATION - 120, _SUBCARRIER + _DEVIATION + 120)
    ana = _analytic(sub)
    inst = np.diff(np.unwrap(np.angle(ana))) * sr / (2 * np.pi)   # instantaneous freq
    return inst - np.mean(inst)                                   # the 30 Hz AC part


def vor_decode(am_audio, sr=_SR, cal_deg=0.0):
    """Decode the VOR radial from AM-demodulated composite audio.

    Returns {radial_deg, ref_amp, var_amp, quality, locked}. Pure and
    hardware-free, so the selftest drives it with a synthesised composite.
    ``cal_deg`` is an optional fixed offset (receiver/site calibration).
    """
    if np is None or am_audio is None:
        return {"locked": False, "error": "numpy unavailable"}
    x = np.asarray(am_audio, dtype=np.float64)
    # use a whole number of 30 Hz cycles for a leakage-free phase estimate
    cyc = int(sr / _TONE)
    ncyc = len(x) // cyc
    if ncyc < 4:
        return {"locked": False, "radial_deg": None,
                "ref_amp": 0.0, "var_amp": 0.0, "quality": 0.0}
    x = x[:ncyc * cyc]
    x = x - np.mean(x)
    norm = float(np.sqrt(np.mean(x ** 2))) or 1.0
    x = x / norm
    # variable 30 Hz: straight from the composite (isolated to <~40 Hz)
    var = _bandpass(x, sr, 15.0, 45.0)
    var_ph = _phasor_at(var, sr, _TONE)
    # reference 30 Hz: FM-demod of the 9960 subcarrier
    ref_sig = _fm_demod_ref(x, sr)
    ref_ph = _phasor_at(ref_sig[:len(var)], sr, _TONE)
    # radial = reference phase minus variable phase
    radial = (np.degrees(np.angle(ref_ph) - np.angle(var_ph)) + cal_deg) % 360.0
    var_amp = float(np.abs(var_ph))
    ref_amp = float(np.abs(ref_ph)) / _DEVIATION     # normalise the demod scale
    quality = float(min(var_amp, ref_amp * 4.0))
    locked = var_amp >= _LOCK_MIN and ref_amp > 0 and quality > 0
    return {"radial_deg": round(radial, 1) if locked else None,
            "ref_amp": round(ref_amp, 4), "var_amp": round(var_amp, 4),
            "quality": round(quality, 4), "locked": bool(locked)}


def synth_vor(radial_deg, secs=0.5, sr=_SR, ident_hz=1020.0, noise=0.0, seed=0):
    """Synthesise a VOR composite for a known radial — for tests and the demo."""
    n = int(sr * secs)
    t = np.arange(n) / sr
    th = np.radians(radial_deg)
    variable = 0.30 * np.cos(2 * np.pi * _TONE * t - th)          # AM, phase = bearing
    beta = _DEVIATION / _TONE                                     # FM index = 16
    subcarrier = 0.30 * np.cos(2 * np.pi * _SUBCARRIER * t + beta * np.sin(2 * np.pi * _TONE * t))
    ident = 0.05 * np.sin(2 * np.pi * ident_hz * t)              # 1020 Hz Morse tone
    comp = 1.0 + variable + subcarrier + ident
    if noise:
        rng = np.random.default_rng(seed)
        comp = comp + noise * rng.standard_normal(n)
    return comp


# --------------------------------------------------------------------------
# Detect + live decoder
# --------------------------------------------------------------------------

def _have(path):
    try:
        return subprocess.run([path, "-h"], capture_output=True, text=True,
                              timeout=4).returncode != 127 or os.path.exists(path)
    except FileNotFoundError:
        return os.path.exists(path)
    except Exception:
        return os.path.exists(path)


def detect():
    """Report whether VOR decode is usable (rtl_fm + numpy + a dongle)."""
    tools = {"rtl_fm": _have(_RTL_FM), "numpy": np is not None}
    usb = None
    try:
        import rtl_sdr
        usb = rtl_sdr.probe_usb()[0]
    except Exception:
        usb = None
    device = usb is not None
    ok = tools["rtl_fm"] and tools["numpy"] and device
    err = None
    if not tools["numpy"]:
        err = "numpy not available"
    elif not tools["rtl_fm"]:
        err = "rtl_fm not installed (apt install rtl-sdr)"
    elif not device:
        err = "no RTL-SDR on the USB bus — plug a dongle in"
    return {"available": ok, "tools": tools, "device_present": device,
            "usb_id": usb, "presets": VOR_PRESETS, "error": err}


class VorDecoder:
    def __init__(self):
        self._lock = threading.Lock()
        self._fm = None
        self._thread = None
        self._stop = threading.Event()
        self._freq = None
        self._error = None
        self._started = None
        self._fix = None
        self._cal = 0.0

    def status(self):
        with self._lock:
            return {"running": bool(self._thread and self._thread.is_alive()),
                    "freq_hz": self._freq, "error": self._error, "cal_deg": self._cal,
                    "fix": self._fix,
                    "seconds": round(time.time() - self._started, 1) if self._started else 0}

    def start(self, freq_hz, cal_deg=0.0):
        try:
            freq_hz = int(float(freq_hz))
        except (TypeError, ValueError):
            return {"ok": False, "error": "bad frequency"}
        if not (108_000_000 <= freq_hz <= 118_000_000):
            return {"ok": False, "error": "VOR band is 108.00-117.95 MHz"}
        if np is None:
            return {"ok": False, "error": "VOR decode needs numpy"}
        with self._lock:
            if self._thread and self._thread.is_alive():
                self._stop_locked()
            self._stop.clear()
            self._freq = freq_hz
            self._error = None
            self._fix = None
            try:
                self._cal = float(cal_deg)
            except (TypeError, ValueError):
                self._cal = 0.0
            self._started = time.time()
            ppm = 0
            try:
                import rtl_sdr
                ppm = rtl_sdr.get_tuning().get("ppm", 0) or 0
            except Exception:
                ppm = 0
            cmd = [_RTL_FM, "-f", str(freq_hz), "-M", "am", "-s", str(_SR),
                   "-l", "0", "-p", str(ppm), "-"]
            try:
                self._fm = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL)
            except Exception as exc:
                self._error = "failed to launch rtl_fm: %s" % exc
                self._stop_locked()
                return {"ok": False, "error": self._error}
            self._thread = threading.Thread(target=self._loop, daemon=True,
                                            name="vor-decode")
            self._thread.start()
        return {"ok": True, "freq_hz": freq_hz}

    def _loop(self):  # pragma: no cover - hardware audio path
        win = int(_SR * 0.5)                    # 0.5 s = 15 clean 30 Hz cycles
        chunk = int(_SR * 0.1) * 2
        buf = np.zeros(0, dtype=np.float32)
        pending = b""
        next_run = time.time() + 0.3
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
                if time.time() < next_run or len(buf) < win:
                    continue
                next_run = time.time() + 0.3
                fix = vor_decode(buf, _SR, cal_deg=self._cal)
                fix["ts"] = time.time()
                with self._lock:
                    self._fix = fix
        except Exception as exc:
            with self._lock:
                self._error = str(exc)

    def _stop_locked(self):
        self._stop.set()
        if self._fm:
            try:
                self._fm.terminate()
                self._fm.wait(timeout=2)
            except Exception:
                try:
                    self._fm.kill()
                except Exception:
                    pass
        self._fm = None

    def stop(self):
        with self._lock:
            self._stop_locked()
        return {"ok": True}


_decoder = VorDecoder()


def start(freq_hz=None, cal_deg=0.0):
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "VOR decode unavailable")}
    if freq_hz is None:
        freq_hz = list(VOR_PRESETS.values())[0]
    return _decoder.start(freq_hz, cal_deg=cal_deg)


def stop():
    return _decoder.stop()


def status():
    st = _decoder.status()
    st["detect"] = detect()
    return st


# --------------------------------------------------------------------------
# Selftest (pure DSP, no hardware)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    if np is None:
        check("numpy available", False, "numpy missing")
    else:
        # recover several known radials from a clean synthesised composite
        errs = []
        for radial in (0.0, 45.0, 90.0, 137.0, 213.5, 300.0, 359.0):
            fix = vor_decode(synth_vor(radial, secs=0.5), _SR)
            if not fix["locked"] or fix["radial_deg"] is None:
                errs.append((radial, "no lock"))
                continue
            d = abs((fix["radial_deg"] - radial + 180) % 360 - 180)
            errs.append((radial, round(d, 2)))
        oknum = [e[1] for e in errs if isinstance(e[1], (int, float))]
        worst = max(oknum) if oknum else None
        check("vor: radials recovered within 2 deg (clean signal)",
              len(oknum) == len(errs) and all(e < 2.0 for e in oknum),
              "worst err=%s  %s" % (worst, errs))

        # radial recovered under noise
        fix = vor_decode(synth_vor(88.0, secs=0.5, noise=0.05, seed=3), _SR)
        dn = abs((fix["radial_deg"] - 88.0 + 180) % 360 - 180) if fix["locked"] else 999
        check("vor: radial recovered under noise (<5 deg)", fix["locked"] and dn < 5.0,
              "err=%s fix=%s" % (round(dn, 2) if dn != 999 else dn, fix))

        # calibration offset applied
        base = vor_decode(synth_vor(100.0, secs=0.5), _SR)["radial_deg"]
        cald = vor_decode(synth_vor(100.0, secs=0.5), _SR, cal_deg=10.0)["radial_deg"]
        check("vor: calibration offset shifts the radial",
              abs(((cald - base) - 10.0 + 180) % 360 - 180) < 0.5,
              "base=%s cal=%s" % (base, cald))

        # no signal / too short -> no lock, no crash
        check("vor: silence yields no lock",
              vor_decode(np.zeros(int(_SR * 0.5)), _SR)["locked"] is False)
        check("vor: too-short buffer handled",
              vor_decode(np.zeros(100), _SR)["locked"] is False)

        # presets sane
        check("vor: presets inside the VOR band",
              all(108_000_000 <= v <= 118_000_000 for v in VOR_PRESETS.values()))

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
        freq = 113_600_000
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
                time.sleep(1)
                st = status()
                fix = st.get("fix") or {}
                print("radial=%s locked=%s q=%s" % (fix.get("radial_deg"),
                      fix.get("locked"), fix.get("quality")))
        finally:
            stop()
    else:
        print("usage: vor.py [detect|run|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
