#!/usr/bin/env python3
"""
acars.py — ACARS (aircraft datalink) messages via RTL-SDR + acarsdec.

ACARS is the VHF text-messaging system airliners use for ops: position reports,
OOOI (out/off/on/in) times, weather requests, free-text crew<->ops messages,
CPDLC, load sheets, and maintenance data. It is **transmitted in the clear** on
a handful of VHF channels around 131 MHz, so an RTL-SDR feeding ``acarsdec``
recovers the messages: aircraft registration, flight id, label, and the text.

This pairs with the ADS-B radar: ADS-B gives position, ACARS gives the datalink
traffic — matched by tail registration / flight number. Receive-only.

One dongle, one claim
---------------------
acarsdec uses the whole RTL-SDR, so it is mutually exclusive with the sub-GHz
sweep / ISM decoder / ADS-B / pager decode. The web layer stops the others.

CLI
---
    python3 acars.py detect
    python3 acars.py run [--seconds N]
    python3 acars.py selftest
"""

import json
import os
import subprocess
import sys
import threading
import time


def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


_ACARSDEC = _which("acarsdec")
_MSG_RING = 500

# Default VHF ACARS channels (MHz). acarsdec tunes several at once around a
# center frequency; these are the common worldwide assignments.
ACARS_CHANNELS_MHZ = [131.550, 131.725, 130.025, 130.425, 131.475, 131.525]

# ACARS label -> human meaning (the busiest labels; unknown ones pass through).
ACARS_LABELS = {
    "SA": "Media advisory (link test)",
    "5Z": "Airline-defined / ops",
    "Q0": "Link test", "_d": "Ground data",
    "H1": "Message to/from terminal (free text)",
    "10": "Airline-defined", "80": "Airline-defined",
    "B9": "Request oceanic clearance", "BA": "Oceanic clearance",
    "15": "Position report", "16": "Position report",
    "5U": "Weather request", "12": "Weather / ATIS",
    "44": "Flight plan", "83": "Load sheet",
    "22": "Departure/arrival (OOOI)", "2Z": "OOOI times",
    "C1": "CPDLC uplink", "AA": "CPDLC downlink",
    "SQ": "Squitter (position)", "RA": "Response",
    "20": "Ops control", "30": "Ops control",
    "51": "Ground station", "57": "ATC",
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
    return _run([path, "--help"])[0] != 127 or os.path.exists(path)


def detect():
    """Report whether ACARS decode is usable (acarsdec + a dongle)."""
    if not _have(_ACARSDEC):
        return {"available": False, "tools_installed": False, "device_present": False,
                "error": "acarsdec not installed — build it from source "
                         "(the in-app Install button does this)"}
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
            "usb_id": usb, "channels_mhz": ACARS_CHANNELS_MHZ}


def label_meaning(label):
    """Human meaning for an ACARS label, or None."""
    return ACARS_LABELS.get((label or "").strip())


def normalize_acars(obj):
    """Normalize one acarsdec JSON object into a flat message record (pure).

    acarsdec ``-o 5`` (or ``--output json``) emits one JSON object per message.
    Field names vary a little by version, so read defensively. Returns
    {tail, flight, label, block_id, msgno, mode, text, freq_mhz, level, ...}.
    """
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except (ValueError, TypeError):
            return None
    if not isinstance(obj, dict):
        return None
    # acarsdec nests the actual message under "vdl2"/"acars" on some builds.
    a = obj.get("acars") if isinstance(obj.get("acars"), dict) else obj
    tail = (a.get("tail") or a.get("registration") or "").strip() or None
    flight = (a.get("flight") or a.get("fid") or a.get("flightId") or "").strip() or None
    label = (a.get("label") or "").strip() or None
    text = a.get("text")
    if text is None and isinstance(a.get("data"), str):
        text = a["data"]
    if isinstance(text, str):
        text = text.replace("\r", "\n").strip() or None
    freq = a.get("freq") or obj.get("freq")
    try:
        freq_mhz = round(float(freq), 3) if freq is not None else None
        # acarsdec sometimes reports Hz
        if freq_mhz and freq_mhz > 1000:
            freq_mhz = round(freq_mhz / 1e6, 3)
    except (TypeError, ValueError):
        freq_mhz = None
    return {
        "tail": tail,
        "flight": flight,
        "label": label,
        "label_meaning": label_meaning(label),
        "block_id": (a.get("blk_id") or a.get("block_id") or "").strip() or None,
        "msgno": (a.get("msgno") or a.get("msg_no") or "").strip() or None,
        "mode": (a.get("mode") or "").strip() or None,
        "ack": a.get("ack"),
        "text": text,
        "freq_mhz": freq_mhz,
        "level": a.get("level") or a.get("sig_level"),
        "ts": a.get("timestamp") or obj.get("timestamp") or time.time(),
    }


class AcarsDecoder:
    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._thread = None
        self._stop = threading.Event()
        self._msgs = []
        self._count = 0
        self._error = None
        self._started = None

    def status(self):
        with self._lock:
            return {"running": bool(self._thread and self._thread.is_alive()),
                    "messages": self._count, "error": self._error,
                    "seconds": round(time.time() - self._started, 1) if self._started else 0}

    def messages(self, since=0):
        with self._lock:
            try:
                since = int(since)
            except (TypeError, ValueError):
                since = 0
            new = [m for m in self._msgs if m["seq"] > since]
            return {"messages": new, "seq": self._count,
                    "running": bool(self._thread and self._thread.is_alive()),
                    "error": self._error}

    def start(self):  # pragma: no cover - hardware path
        with self._lock:
            if self._thread and self._thread.is_alive():
                return {"ok": True, "already": True}
            if not _have(_ACARSDEC):
                return {"ok": False, "error": "acarsdec not installed"}
            self._stop.clear()
            self._msgs = []
            self._count = 0
            self._error = None
            self._started = time.time()
            ppm = 0
            try:
                import rtl_sdr
                ppm = rtl_sdr.get_tuning().get("ppm", 0)
            except Exception:
                pass
            # acarsdec: RTL device 0, JSON to stdout, all default channels.
            cmd = [_ACARSDEC, "-o", "5", "-p", str(ppm or 0), "-r", "0"] + \
                  ["%.3f" % f for f in ACARS_CHANNELS_MHZ]
            try:
                self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                              stderr=subprocess.DEVNULL, text=True)
            except Exception as exc:
                self._error = "failed to launch acarsdec: %s" % exc
                return {"ok": False, "error": self._error}
            self._thread = threading.Thread(target=self._read_loop, daemon=True,
                                            name="acars-decode")
            self._thread.start()
        return {"ok": True}

    def _read_loop(self):  # pragma: no cover - hardware path
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                line = line.strip()
                if not line or line[0] != "{":
                    continue
                rec = normalize_acars(line)
                if not rec:
                    continue
                with self._lock:
                    self._count += 1
                    rec["seq"] = self._count
                    self._msgs.append(rec)
                    if len(self._msgs) > _MSG_RING:
                        self._msgs = self._msgs[-_MSG_RING:]
        except Exception as exc:
            with self._lock:
                self._error = str(exc)

    def stop(self):
        with self._lock:
            self._stop.set()
            if self._proc:
                try:
                    self._proc.terminate()
                    self._proc.wait(timeout=2)
                except Exception:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass
                self._proc = None
        return {"ok": True}


_decoder = AcarsDecoder()


def start():
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "acars unavailable")}
    return _decoder.start()


def stop():
    return _decoder.stop()


def status():
    st = _decoder.status()
    st["detect"] = detect()
    return st


def messages(since=0):
    return _decoder.messages(since=since)


def install():
    """One-click install of acarsdec. Not in apt, so build from source via the
    shared helper script."""
    if _have(_ACARSDEC):
        return {"ok": True, "already": True, "detect": detect()}
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "scripts", "install_acarsdec.sh")
    if not os.path.exists(script):
        return {"ok": False, "error": "install_acarsdec.sh missing (update Ragnar)",
                "detect": detect()}
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        p = subprocess.run(["bash", script], capture_output=True, text=True,
                           timeout=1200, check=False, env=env)
        out = (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return {"ok": False, "error": "bash not found", "detect": detect()}
    except subprocess.TimeoutExpired:
        return {"ok": _have(_ACARSDEC), "error": "install timed out (source build is slow — retry)",
                "detect": detect()}
    ok = _have(_ACARSDEC)
    tail = "\n".join((out or "").strip().splitlines()[-14:])
    return {"ok": ok, "output": tail, "detect": detect(),
            "error": None if ok else "could not build acarsdec (needs internet + build tools). See output."}


# --------------------------------------------------------------------------
# Selftest (pure normalization, no hardware)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    m = normalize_acars('{"tail":"G-EUUU","flight":"BA282","label":"15",'
                        '"blk_id":"7","msgno":"M12A","mode":"2","text":"POS N51.2 W002.3 380 M0.82",'
                        '"freq":131.725,"level":-18.5,"timestamp":1700000000}')
    check("acars: core fields parsed",
          m and m["tail"] == "G-EUUU" and m["flight"] == "BA282" and m["label"] == "15"
          and "POS" in m["text"] and m["freq_mhz"] == 131.725, str(m))
    check("acars: label meaning resolved",
          m and m["label_meaning"] == "Position report", str(m and m["label_meaning"]))
    m2 = normalize_acars({"acars": {"registration": "N12345", "fid": "UAL55",
                                    "label": "H1", "data": "FUEL 8500 KG\r\nETA 1830"}})
    check("acars: nested 'acars' + registration/fid/data read",
          m2 and m2["tail"] == "N12345" and m2["flight"] == "UAL55"
          and "FUEL" in m2["text"] and "\n" in m2["text"], str(m2))
    check("acars: Hz frequency normalized to MHz",
          (normalize_acars('{"tail":"X","freq":131550000}') or {}).get("freq_mhz") == 131.55)
    check("acars: junk -> None",
          normalize_acars("not json") is None and normalize_acars(42) is None
          and normalize_acars("{}") is not None)  # empty obj is a valid (empty) record

    dec = AcarsDecoder()
    for raw in ('{"tail":"AAA","flight":"F1","label":"SA","text":"one"}',
                '{"tail":"BBB","flight":"F2","label":"15","text":"two"}'):
        r = normalize_acars(raw)
        with dec._lock:
            dec._count += 1
            r["seq"] = dec._count
            dec._msgs.append(r)
    got = dec.messages(since=1)
    check("acars: since-cursor returns only newer",
          got["seq"] == 2 and len(got["messages"]) == 1 and got["messages"][0]["tail"] == "BBB", str(got))
    check("acars: channels are VHF ~131 MHz",
          all(129 <= f <= 137 for f in ACARS_CHANNELS_MHZ) and 131.55 in ACARS_CHANNELS_MHZ)

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


def _main(argv):
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
        secs = 30
        if "--seconds" in argv:
            secs = int(argv[argv.index("--seconds") + 1])
        print(start())
        t0 = time.time()
        try:
            while time.time() - t0 < secs:
                time.sleep(2)
                print("messages=%d" % status()["messages"])
        finally:
            stop()
    else:
        print("usage: acars.py [detect|run|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
