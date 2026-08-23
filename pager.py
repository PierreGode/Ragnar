#!/usr/bin/env python3
"""
pager.py — POCSAG / FLEX pager decode via RTL-SDR (rtl_fm | multimon-ng).

Pagers are still everywhere — hospitals, industrial SCADA, alarm/telemetry,
on-call teams — and POCSAG/FLEX are transmitted **in the clear**. An RTL-SDR
tuned to a pager channel, FM-demodulated by ``rtl_fm`` and decoded by
``multimon-ng``, recovers the messages: capcode (address), function bits, and
the alphanumeric/numeric text.

This is passive, receive-only reception. Pager traffic is unencrypted by design,
but it is frequently *sensitive* (patient data, security callouts), so decoding
third-party traffic is regulated in many places — use it lawfully.

One dongle, one claim
---------------------
This uses ``rtl_fm`` (the whole RTL-SDR), so it is mutually exclusive with the
sub-GHz sweep / ISM decoder and ADS-B — the web layer stops the others first.

CLI
---
    python3 pager.py detect
    python3 pager.py run --freq 153.350M [--seconds N]
    python3 pager.py selftest
"""

import os
import re
import subprocess
import sys
import threading
import time


def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


_RTL_FM = _which("rtl_fm")
_MULTIMON = _which("multimon-ng")
_MSG_RING = 500

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
    """Report whether pager decode is usable (rtl_fm + multimon-ng + a dongle)."""
    tools = {"rtl_fm": _have(_RTL_FM), "multimon_ng": _have(_MULTIMON)}
    if not tools["multimon_ng"]:
        return {"available": False, "tools_installed": False, "tools": tools,
                "device_present": False,
                "error": "multimon-ng not installed (apt install multimon-ng)"}
    if not tools["rtl_fm"]:
        return {"available": False, "tools_installed": False, "tools": tools,
                "device_present": False,
                "error": "rtl_fm not installed (apt install rtl-sdr)"}
    usb = None
    try:
        import rtl_sdr
        usb = rtl_sdr.probe_usb()[0]
    except Exception:
        usb = None
    if usb is None:
        return {"available": False, "tools_installed": True, "tools": tools,
                "device_present": False,
                "error": "no RTL-SDR on the USB bus — plug a dongle in"}
    return {"available": True, "tools_installed": True, "tools": tools,
            "device_present": True, "usb_id": usb,
            "presets": PAGER_PRESETS}


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

    def status(self):
        with self._lock:
            return {"running": bool(self._thread and self._thread.is_alive()),
                    "freq_hz": self._freq, "messages": self._count,
                    "error": self._error,
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
                    "error": self._error}

    def start(self, freq_hz):
        try:
            freq_hz = int(float(freq_hz))
        except (TypeError, ValueError):
            return {"ok": False, "error": "bad frequency"}
        if not (24_000_000 <= freq_hz <= 1_766_000_000):
            return {"ok": False, "error": "frequency out of RTL-SDR range"}
        with self._lock:
            if self._thread and self._thread.is_alive():
                self._stop_locked()
            self._stop.clear()
            self._msgs = []
            self._count = 0
            self._freq = freq_hz
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
            fm_cmd = [_RTL_FM, "-f", str(freq_hz), "-M", "fm", "-s", "22050", "-l", "0", "-p", str(ppm or 0)]
            if gain is not None:
                fm_cmd += ["-g", str(gain)]
            fm_cmd += ["-"]
            mm_cmd = [_MULTIMON, "-a", "POCSAG512", "-a", "POCSAG1200",
                      "-a", "POCSAG2400", "-a", "FLEX", "-f", "alpha", "-t", "raw", "-"]
            try:
                self._fm = subprocess.Popen(fm_cmd, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL)
                self._mm = subprocess.Popen(mm_cmd, stdin=self._fm.stdout,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, text=True)
                self._fm.stdout.close()  # allow rtl_fm to get SIGPIPE if mm exits
            except Exception as exc:
                self._error = "failed to launch rtl_fm|multimon-ng: %s" % exc
                self._stop_locked()
                return {"ok": False, "error": self._error}
            self._thread = threading.Thread(target=self._read_loop, daemon=True,
                                            name="pager-decode")
            self._thread.start()
        return {"ok": True, "freq_hz": freq_hz}

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


def start(freq_hz=None):
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "pager decode unavailable")}
    if freq_hz is None:
        freq_hz = list(PAGER_PRESETS.values())[0]
    return _decoder.start(freq_hz)


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
        print("usage: pager.py [detect|run|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
