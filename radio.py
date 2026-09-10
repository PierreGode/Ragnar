#!/usr/bin/env python3
"""
radio.py — listen to broadcast/utility radio via RTL-SDR (rtl_fm) in the browser.

Demodulates FM/AM with ``rtl_fm`` and streams the audio to the web UI as a live
WAV stream an <audio> element plays. Modes:

  * WFM — wideband FM broadcast (88-108 MHz)
  * NFM — narrowband FM (PMR/ham/airband-FM, marine)
  * AM  — amplitude modulation (airband 108-137 MHz; MW/SW below 24 MHz via the
          dongle's direct-sampling mode, best-effort)

Receive-only. This uses ``rtl_fm`` (the whole RTL-SDR), so it is mutually
exclusive with the sub-GHz sweep / ISM decoder / ADS-B / pager / ACARS — the web
layer stops the others when you start listening.

CLI
---
    python3 radio.py detect
    python3 radio.py selftest
"""

import os
import struct
import subprocess
import sys
import threading
import time


def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


_RTL_FM = _which("rtl_fm")
_FFMPEG = _which("ffmpeg")   # transcodes the PCM to MP3 for broad browser support
_AUDIO_RATE = 48000          # output sample rate (mono, s16le)
_MP3_BITRATE = "128k"        # MP3 bitrate when transcoding

# iOS Safari (and most mobile browsers) will NOT play an open-ended streaming
# WAV — its media loader wants a range-able/finite resource. A chunked MP3
# (audio/mpeg) is what web-radio streams use and it plays everywhere, desktop
# and phone. So when ffmpeg is present we transcode rtl_fm's PCM to live MP3;
# without it we fall back to the raw streaming WAV (desktop-only).

# Band presets (label -> (freq_hz, mode)). Broadcast FM stations are local, so
# these are representative anchors; the UI also takes any frequency.
RADIO_PRESETS = {
    "FM 88.0 (broadcast)":  (88_000_000,  "wfm"),
    "FM 98.0 (broadcast)":  (98_000_000,  "wfm"),
    "FM 104.0 (broadcast)": (104_000_000, "wfm"),
    "Airband 118.0 (AM)":   (118_000_000, "am"),
    "Airband 121.5 (AM emerg)": (121_500_000, "am"),
    "Marine 156.8 ch16 (NFM)": (156_800_000, "nfm"),
    "PMR446 446.0 (NFM)":   (446_006_250, "nfm"),
    "MW 900 kHz (AM, direct)": (900_000, "am"),
}

_MODES = ("wfm", "nfm", "am")


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
    """Report whether radio listening is usable (rtl_fm + a dongle)."""
    if not _have(_RTL_FM):
        return {"available": False, "tools_installed": False, "device_present": False,
                "error": "rtl_fm not installed (apt install rtl-sdr)"}
    usb = None
    try:
        import rtl_sdr
        usb = rtl_sdr.probe_usb()[0]
    except Exception:
        usb = None
    if usb is None:
        return {"available": False, "tools_installed": True, "device_present": False,
                "error": "no RTL-SDR on the USB bus — plug a dongle in"}
    return {"available": True, "tools_installed": True, "device_present": True,
            "usb_id": usb, "presets": RADIO_PRESETS, "modes": list(_MODES),
            "rate": _AUDIO_RATE, "format": ("mp3" if transcodes() else "wav"),
            "mimetype": media_mimetype()}


def wav_header(rate=_AUDIO_RATE, channels=1, bits=16):
    """A streaming-WAV header (unknown length) for a live mono s16le stream.

    Uses a max data-chunk size so browsers keep playing indefinitely — pure, so
    the selftest can check the RIFF/‘fmt ’/‘data’ layout.
    """
    byte_rate = rate * channels * bits // 8
    block_align = channels * bits // 8
    data_size = 0xFFFFFFFF - 36          # effectively "streaming / unknown"
    return b"RIFF" + struct.pack("<I", 0xFFFFFFFF) + b"WAVE" + \
        b"fmt " + struct.pack("<IHHIIHH", 16, 1, channels, rate, byte_rate, block_align, bits) + \
        b"data" + struct.pack("<I", data_size)


def rtl_fm_cmd(freq_hz, mode, ppm=0, gain=None):
    """Build the rtl_fm command for a frequency + mode (pure, selftested).

    WFM uses a wide 200 kHz window + FM de-emphasis; NFM/AM use a narrow 12 kHz
    window. Below 24 MHz we add direct-sampling for MW/SW AM.
    """
    mode = (mode or "wfm").lower()
    if mode not in _MODES:
        mode = "wfm"
    cmd = [_RTL_FM, "-f", str(int(freq_hz))]
    if mode == "wfm":
        cmd += ["-M", "fm", "-s", "200000", "-A", "fast", "-E", "deemp"]
    elif mode == "nfm":
        cmd += ["-M", "fm", "-s", "12000"]
    else:  # am
        cmd += ["-M", "am", "-s", "12000"]
    cmd += ["-r", str(_AUDIO_RATE), "-l", "0"]
    if int(freq_hz) < 24_000_000:
        cmd += ["-E", "direct"]          # MW/SW: direct sampling
    if ppm:
        cmd += ["-p", str(int(ppm))]
    if gain is not None:
        cmd += ["-g", str(gain)]
    cmd += ["-"]
    return cmd


def ffmpeg_mp3_cmd(rate=_AUDIO_RATE, bitrate=_MP3_BITRATE):
    """ffmpeg argv: read mono s16le PCM on stdin, stream live MP3 to stdout (pure).

    ``-flush_packets 1`` keeps latency low for live listening; ``pipe:0``/``pipe:1``
    are stdin/stdout so it slots straight onto rtl_fm's output.
    """
    return [_FFMPEG, "-hide_banner", "-loglevel", "error",
            "-f", "s16le", "-ar", str(rate), "-ac", "1", "-i", "pipe:0",
            "-c:a", "libmp3lame", "-b:a", str(bitrate),
            "-flush_packets", "1", "-f", "mp3", "pipe:1"]


def transcodes():
    """True when ffmpeg is available to serve MP3 (phone-friendly) vs raw WAV."""
    return _have(_FFMPEG)


def media_mimetype():
    """Content-Type for the stream: audio/mpeg when transcoding, else audio/wav."""
    return "audio/mpeg" if transcodes() else "audio/wav"


class RadioTuner:
    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None        # rtl_fm
        self._enc = None         # ffmpeg (MP3), when transcoding
        self._freq = None
        self._mode = None
        self._started = None

    def status(self):
        with self._lock:
            running = bool(self._proc and self._proc.poll() is None)
            return {"running": running, "freq_hz": self._freq if running else None,
                    "mode": self._mode if running else None,
                    "seconds": round(time.time() - self._started, 1) if (running and self._started) else 0}

    def stop(self):
        with self._lock:
            self._stop_locked()
        return {"ok": True}

    def _stop_locked(self):
        for attr in ("_enc", "_proc"):        # encoder first, then rtl_fm
            p = getattr(self, attr, None)
            if p:
                try:
                    p.terminate()
                    p.wait(timeout=2)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
            setattr(self, attr, None)
        self._freq = None
        self._mode = None

    def stream(self, freq_hz, mode):  # pragma: no cover - hardware path
        """Generator: start rtl_fm for freq/mode and yield a live WAV stream.

        Killing rtl_fm is tied to the generator's lifetime — when the browser
        <audio> disconnects, the WSGI server closes the generator and the
        ``finally`` stops the process. One dongle, so we stop any prior tune and
        the other RTL captures first.
        """
        try:
            freq_hz = int(float(freq_hz))
        except (TypeError, ValueError):
            return
        ppm = 0
        gain = None
        try:
            import rtl_sdr
            t = rtl_sdr.get_tuning()
            ppm = t.get("ppm", 0) or 0
            gain = None if t.get("gain_is_auto") else t.get("gain")
        except Exception:
            pass
        with self._lock:
            self._stop_locked()
            cmd = rtl_fm_cmd(freq_hz, mode, ppm=ppm, gain=gain)
            try:
                self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                              stderr=subprocess.DEVNULL)
            except Exception:
                self._proc = None
                return
            # With ffmpeg, transcode the PCM to live MP3 (phone-friendly). rtl_fm's
            # stdout feeds ffmpeg's stdin; we read MP3 off ffmpeg's stdout. Without
            # ffmpeg, stream the raw WAV (desktop-only) as before.
            src = self._proc
            if transcodes():
                try:
                    self._enc = subprocess.Popen(ffmpeg_mp3_cmd(), stdin=self._proc.stdout,
                                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    self._proc.stdout.close()   # parent drops its copy -> EOF reaches ffmpeg if rtl_fm dies
                    src = self._enc
                except Exception:
                    self._enc = None            # fall back to WAV passthrough
            self._freq = freq_hz
            self._mode = (mode or "wfm").lower()
            self._started = time.time()
            proc, enc, pipe = self._proc, self._enc, src.stdout
        if enc is None:
            yield wav_header()                  # raw WAV path needs the RIFF header
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                yield chunk
        finally:
            with self._lock:
                if self._proc is proc:
                    self._stop_locked()


_tuner = RadioTuner()


def stream(freq_hz, mode="wfm"):
    return _tuner.stream(freq_hz, mode)


def stop():
    return _tuner.stop()


def status():
    st = _tuner.status()
    st["detect"] = detect()
    return st


def install():
    """rtl_fm ships in the rtl-sdr package (already installed for the sweep), so
    this is just a convenience if only rtl_fm is missing."""
    if _have(_RTL_FM):
        return {"ok": True, "already": True, "detect": detect()}
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    out = ""
    try:
        p = subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", "rtl-sdr"],
                           capture_output=True, text=True, timeout=300, check=False, env=env)
        out = (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return {"ok": False, "error": str(exc), "detect": detect()}
    ok = _have(_RTL_FM)
    return {"ok": ok, "detect": detect(), "output": "\n".join(out.strip().splitlines()[-8:]),
            "error": None if ok else "apt could not install rtl-sdr"}


# --------------------------------------------------------------------------
# Selftest (pure command/header builders, no hardware)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    w = rtl_fm_cmd(98_000_000, "wfm", ppm=2)
    check("cmd: WFM has wide window + deemp + rate + freq",
          "200000" in w and "deemp" in w and "48000" in w and "98000000" in w and "-p" in w, str(w))
    n = rtl_fm_cmd(446_006_250, "nfm")
    check("cmd: NFM narrow window", "-M" in n and "fm" in n and "12000" in n, str(n))
    a = rtl_fm_cmd(118_000_000, "am")
    check("cmd: AM mode", "am" in a and "12000" in a, str(a))
    mw = rtl_fm_cmd(900_000, "am")
    check("cmd: MW (<24 MHz) adds direct sampling",
          "direct" in mw, str(mw))
    check("cmd: unknown mode falls back to WFM", "200000" in rtl_fm_cmd(90e6, "zzz"))
    g = rtl_fm_cmd(98_000_000, "wfm", gain=30.0)
    check("cmd: explicit gain passed", "-g" in g and "30.0" in g, str(g))

    h = wav_header(48000, 1, 16)
    check("wav: RIFF/WAVE/fmt/data header, 44 bytes",
          len(h) == 44 and h[:4] == b"RIFF" and h[8:12] == b"WAVE"
          and h[12:16] == b"fmt " and h[36:40] == b"data", str(len(h)))
    rate = struct.unpack("<I", h[24:28])[0]
    check("wav: sample rate encoded (48000)", rate == 48000, str(rate))

    check("presets: FM + airband present + all valid modes",
          any(v[1] == "wfm" for v in RADIO_PRESETS.values())
          and all(v[1] in _MODES for v in RADIO_PRESETS.values()))

    # MP3 transcode (the iOS fix): correct ffmpeg pipe command + matching mimetype
    fc = ffmpeg_mp3_cmd()
    check("mp3: ffmpeg reads s16le pipe:0 -> libmp3lame mp3 pipe:1",
          "s16le" in fc and "libmp3lame" in fc and "pipe:0" in fc and "pipe:1" in fc
          and "48000" in fc, str(fc))
    check("mp3: mimetype matches transcode availability",
          media_mimetype() == ("audio/mpeg" if transcodes() else "audio/wav"))

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
    else:
        print("usage: radio.py [detect|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
