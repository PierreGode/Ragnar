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

_MODES = ("wfm", "nfm", "am", "usb", "lsb", "cw")
_CW_PITCH_HZ = 700              # CW = USB tuned this far below the carrier -> a 700 Hz tone


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


def rtl_fm_cmd(freq_hz, mode, ppm=0, gain=None, squelch=0, bias_t=False,
               direct="auto", conv_hz=0):
    """Build the rtl_fm command for a frequency + mode (pure, selftested).

    WFM uses a wide 200 kHz window + FM de-emphasis; NFM/AM a narrow 12 kHz one;
    USB/LSB demodulate single-sideband (ham/marine/aviation HF voice); CW is USB
    tuned ``_CW_PITCH_HZ`` below the carrier so Morse is heard as a steady tone.
    ``squelch`` (0 = open) mutes audio below that level. ``conv_hz`` is an
    up/down-converter LO: the dongle tunes RF + conv. Direct sampling is used
    for HF (below 24 MHz) unless ``direct`` forces it on/off; ``bias_t`` powers
    an LNA on RTL-SDR Blog V3/V4 dongles.
    """
    mode = (mode or "wfm").lower()
    if mode not in _MODES:
        mode = "wfm"
    hw = int(freq_hz) + int(conv_hz or 0)
    if mode == "cw":
        hw -= _CW_PITCH_HZ
    cmd = [_RTL_FM, "-f", str(hw)]
    if mode == "wfm":
        cmd += ["-M", "fm", "-s", "200000", "-A", "fast", "-E", "deemp"]
    elif mode == "nfm":
        cmd += ["-M", "fm", "-s", "12000"]
    elif mode in ("usb", "lsb", "cw"):
        cmd += ["-M", "lsb" if mode == "lsb" else "usb", "-s", "12000"]
    else:  # am
        cmd += ["-M", "am", "-s", "12000"]
    try:
        sq = max(0, min(1000, int(float(squelch or 0))))
    except (TypeError, ValueError):
        sq = 0
    if mode == "wfm":
        cmd += ["-r", str(_AUDIO_RATE)]   # 200 kHz -> 48 kHz (rtl_fm only resamples DOWN)
    cmd += ["-l", str(sq)]
    if direct == "on" or (direct != "off" and hw < 24_000_000):
        cmd += ["-E", "direct"]          # MW/SW/HF: direct sampling
    if bias_t:
        cmd += ["-T"]
    if ppm:
        cmd += ["-p", str(int(ppm))]
    if gain is not None:
        cmd += ["-g", str(gain)]
    cmd += ["-"]
    return cmd


def pump_with_silence(src, write, rate, stop, tick=0.1):
    """Copy PCM from ``src`` (a pipe) to ``write``; while nothing arrives, write
    zeros (silence) at ``rate`` so the stream keeps flowing (pure-ish; selftested
    with an os.pipe). rtl_fm outputs NOTHING while its squelch is closed, which
    otherwise starves the encoder and stalls the browser's <audio>. Returns when
    ``src`` hits EOF, ``stop`` is set, or ``write`` fails (client gone)."""
    import select
    fd = src.fileno()
    last = time.time()
    while not stop.is_set():
        r, _, _ = select.select([fd], [], [], tick)
        now = time.time()
        try:
            if r:
                chunk = os.read(fd, 8192)
                if not chunk:
                    return
                write(chunk)
                last = now
            elif now - last >= tick:
                n = int(rate * (now - last)) * 2           # s16le mono: 2 bytes/sample
                if n > 0:
                    write(b"\x00" * n)
                last = now
        except (OSError, ValueError, BrokenPipeError):
            return


def audio_rate(mode):
    """The PCM rate rtl_fm really outputs for a mode (pure).

    rtl_fm's ``-r`` only resamples *down*: WFM (-s 200k -r 48k) comes out at
    48 kHz, but the narrow modes (-s 12k) come out at 12 kHz whatever -r says.
    Labelling that 48 kHz played it 4x too fast (and starved the MP3 stream)."""
    return _AUDIO_RATE if (mode or "wfm").lower() == "wfm" else 12000


def ffmpeg_mp3_cmd(rate=_AUDIO_RATE, bitrate=_MP3_BITRATE):
    """ffmpeg argv: read mono s16le PCM at ``rate`` on stdin, stream live 48 kHz
    MP3 to stdout (pure). Narrow modes (12 kHz) are resampled up to 48 kHz.

    ``-flush_packets 1`` keeps latency low for live listening; ``pipe:0``/``pipe:1``
    are stdin/stdout so it slots straight onto rtl_fm's output.
    """
    return [_FFMPEG, "-hide_banner", "-loglevel", "error",
            "-f", "s16le", "-ar", str(rate), "-ac", "1", "-i", "pipe:0",
            "-ar", str(_AUDIO_RATE), "-c:a", "libmp3lame", "-b:a", str(bitrate),
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

    def stream(self, freq_hz, mode, squelch=0):  # pragma: no cover - hardware path
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
        extra = {}
        try:
            import rtl_sdr
            t = rtl_sdr.get_tuning()
            ppm = t.get("ppm", 0) or 0
            gain = None if t.get("gain_is_auto") else t.get("gain")
            extra = {"bias_t": bool(t.get("bias_t")), "direct": t.get("direct", "auto"),
                     "conv_hz": int(t.get("conv_hz") or 0)}
        except Exception:
            pass
        with self._lock:
            self._stop_locked()
            cmd = rtl_fm_cmd(freq_hz, mode, ppm=ppm, gain=gain, squelch=squelch, **extra)
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
            try:
                squelched = int(float(squelch or 0)) > 0
            except (TypeError, ValueError):
                squelched = False
            self._pump_stop = threading.Event()
            if transcodes():
                try:
                    if squelched:
                        # squelch: rtl_fm goes silent when closed -> pump silence in
                        self._enc = subprocess.Popen(ffmpeg_mp3_cmd(audio_rate(mode)), stdin=subprocess.PIPE,
                                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                        enc_in, rtl_out = self._enc.stdin, self._proc.stdout

                        def _w(b, _f=enc_in):
                            _f.write(b); _f.flush()
                        threading.Thread(target=pump_with_silence, daemon=True, name="radio-squelch-pump",
                                         args=(rtl_out, _w, audio_rate(mode), self._pump_stop)).start()
                    else:
                        self._enc = subprocess.Popen(ffmpeg_mp3_cmd(audio_rate(mode)), stdin=self._proc.stdout,
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
            yield wav_header(audio_rate(self._mode))   # raw WAV path: RIFF header at the true rate
            if squelched:                               # WAV + squelch: pad the gaps ourselves
                import queue
                q = queue.Queue(maxsize=64)
                threading.Thread(target=pump_with_silence, daemon=True, name="radio-squelch-pump",
                                 args=(pipe, q.put, audio_rate(self._mode), self._pump_stop)).start()
                try:
                    while proc.poll() is None:
                        try:
                            yield q.get(timeout=1.0)
                        except queue.Empty:
                            continue
                finally:
                    self._pump_stop.set()
                    with self._lock:
                        if self._proc is proc:
                            self._stop_locked()
                return
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                yield chunk
        finally:
            self._pump_stop.set()
            with self._lock:
                if self._proc is proc:
                    self._stop_locked()


_tuner = RadioTuner()


def stream(freq_hz, mode="wfm", squelch=0):
    return _tuner.stream(freq_hz, mode, squelch)


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
    u = rtl_fm_cmd(14_200_000, "usb")
    check("cmd: USB = single sideband + direct sampling on HF", "usb" in u and "direct" in u, str(u))
    check("cmd: LSB", "lsb" in rtl_fm_cmd(7_100_000, "lsb"))
    cw = rtl_fm_cmd(7_030_000, "cw")
    check("cmd: CW = USB tuned 700 Hz below the carrier",
          "usb" in cw and str(7_030_000 - _CW_PITCH_HZ) in cw, str(cw))
    sq = rtl_fm_cmd(446_006_250, "nfm", squelch=120)
    check("cmd: squelch level passed", sq[sq.index("-l") + 1] == "120", str(sq))
    check("cmd: bias-T flag", "-T" in rtl_fm_cmd(1_090_000_000, "am", bias_t=True))
    cv = rtl_fm_cmd(7_100_000, "lsb", conv_hz=125_000_000)
    check("cmd: upconverter -> tunes RF + LO, no direct sampling", "132100000" in cv and "direct" not in cv, str(cv))
    check("cmd: direct sampling can be forced off", "direct" not in rtl_fm_cmd(7_100_000, "lsb", direct="off"))

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
    check("rate: WFM 48 kHz, narrow modes 12 kHz (what rtl_fm really outputs)",
          audio_rate("wfm") == 48000 and audio_rate("nfm") == 12000 and audio_rate("usb") == 12000)
    check("cmd: narrow modes don't ask rtl_fm to upsample (-r)", "-r" not in rtl_fm_cmd(446_006_250, "nfm"))
    # squelch gap filler: an idle pipe produces silence at the audio rate
    _r, _wfd = os.pipe()
    _src = os.fdopen(_r, "rb")
    _buf = bytearray(); _ev = threading.Event()
    _t = threading.Thread(target=pump_with_silence, args=(_src, _buf.extend, 12000, _ev, 0.05))
    _t.start(); time.sleep(0.4); os.write(_wfd, b"\x01\x02" * 10); time.sleep(0.15); _ev.set(); _t.join(2)
    os.close(_wfd); _src.close()
    _zeros = len(_buf) - 20
    check("squelch: idle pipe is padded with silence (~rate x 2 B/s), real audio passed through",
          9000 < _zeros < 14000 and bytes(_buf).count(b"\x01\x02") == 10, str(len(_buf)))
    f12 = ffmpeg_mp3_cmd(12000)
    check("mp3: 12 kHz input resampled to 48 kHz output",
          f12[f12.index("-ar") + 1] == "12000" and f12.count("-ar") == 2 and "48000" in f12, str(f12))
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
