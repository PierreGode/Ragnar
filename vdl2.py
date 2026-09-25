#!/usr/bin/env python3
"""
vdl2.py — VDL Mode 2 / ATN datalink via RTL-SDR + dumpvdl2 (+ libacars).

VDL Mode 2 is the modern successor to plain VHF ACARS. Instead of the old
character-oriented ACARS on ~131 MHz, VDL2 is a 31.5 kbit/s D8PSK link on a
handful of 136 MHz channels, carrying AVLC frames. Those frames carry three
kinds of payload:

  * **ACARS-over-AVLC** — the same ops messages (position, OOOI, weather, load
    sheets, free text) but riding VDL2 instead of the legacy VHF link.
  * **CPDLC** (Controller-Pilot Data Link Communications) — the ATN/OSI
    controller<->pilot text: clearances, level/heading/speed instructions,
    "MONITOR <freq>", "CONTACT <unit>", logon/handoff. This is the ATN part.
  * **ADS-C** (Automatic Dependent Surveillance - Contract) — aircraft sending
    contracted position/intent reports to an ATC ground system.

``dumpvdl2`` demodulates the 136 MHz channels; when it is built against
``libacars`` it decodes the CPDLC and ADS-C payloads too. Everything is
transmitted in the clear. Receive-only.

This pairs with the ADS-B radar and the legacy ACARS panel: ADS-B gives the
position, VDL2/ATN gives the modern datalink — matched by tail / ICAO / flight.

One dongle, one claim
---------------------
dumpvdl2 uses the whole RTL-SDR (136 MHz, ~2.1 Msps), so it is mutually
exclusive with the sub-GHz sweep / ISM decoder / ADS-B / pager / ACARS / radio.
The web layer stops the others before starting VDL2.

CLI
---
    python3 vdl2.py detect
    python3 vdl2.py run [--seconds N]
    python3 vdl2.py selftest
"""

import json
import os
import subprocess
import sys
import threading
import time


def _which(name):
    for p in ("/usr/local/bin/%s" % name, "/usr/bin/%s" % name):
        if os.path.exists(p):
            return p
    return name


_DUMPVDL2 = _which("dumpvdl2")
_MSG_RING = 500

# VDL Mode 2 channels (Hz). 136.975 is the worldwide Common Signalling Channel;
# the others are the busiest data channels. dumpvdl2 tunes all of these inside
# one ~2.1 Msps window (they span 250 kHz around 136.85). Tunable, but this set
# balances coverage against CPU on a Pi.
VDL2_CHANNELS_HZ = [136725000, 136775000, 136800000, 136825000, 136975000]

# ACARS label -> human meaning (shared vocabulary with the legacy ACARS panel;
# unknown labels pass through untouched).
ACARS_LABELS = {
    "SA": "Media advisory (link test)", "5Z": "Airline-defined / ops",
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
    # dumpvdl2 --help exits non-zero on some builds but still runs; a 127 (not
    # found) is the only reliable "missing" signal.
    return _run([path, "--help"])[0] != 127 or os.path.exists(path)


def detect():
    """Report whether VDL2 decode is usable (dumpvdl2 + a dongle)."""
    if not _have(_DUMPVDL2):
        return {"available": False, "tools_installed": False, "device_present": False,
                "error": "dumpvdl2 not installed — build it from source "
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
            "usb_id": usb, "channels_mhz": [round(f / 1e6, 3) for f in VDL2_CHANNELS_HZ]}


def label_meaning(label):
    """Human meaning for an ACARS label, or None."""
    return ACARS_LABELS.get((label or "").strip())


# --------------------------------------------------------------------------
# Nested-tree helpers — dumpvdl2/libacars JSON nests CPDLC/ADS-C deep inside
# avlc -> x25 -> clnp -> cotp -> ... , and the exact depth varies by version.
# We locate payloads by key rather than by a fixed path.
# --------------------------------------------------------------------------

def _find(obj, key):
    """First value for `key` found anywhere in a nested dict/list (DFS)."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = _find(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _find(v, key)
            if r is not None:
                return r
    return None


def _collect_scalars(obj, keys, out, limit=40):
    """Collect (key, scalar) pairs for any key in `keys`, anywhere in the tree."""
    if len(out) >= limit:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and not isinstance(v, (dict, list)) and v not in (None, ""):
                out.append((k, v))
            else:
                _collect_scalars(v, keys, out, limit)
    elif isinstance(obj, list):
        for v in obj:
            _collect_scalars(v, keys, out, limit)


def _cpdlc_summary(cpdlc):
    """Human one-liner for a libacars CPDLC object (uplink or downlink)."""
    direction = None
    if _find(cpdlc, "atc_uplink_message") is not None:
        direction = "uplink"     # ground -> aircraft (a controller instruction)
    elif _find(cpdlc, "atc_downlink_message") is not None:
        direction = "downlink"   # aircraft -> ground (a pilot reply/request)
    bits = []
    # Free text is the most human-legible field when present.
    for fkey in ("freetext", "free_text", "text"):
        ft = _find(cpdlc, fkey)
        if isinstance(ft, str) and ft.strip():
            bits.append(ft.strip())
            break
    # Otherwise summarise from the message-element choices libacars names.
    if not bits:
        choices = []
        _collect_scalars(cpdlc, {"choice", "choice_label", "type"}, choices, limit=6)
        seen = []
        for _, v in choices:
            s = str(v).replace("_", " ").strip()
            if s and s not in seen and not s.isdigit():
                seen.append(s)
        if seen:
            bits.append("; ".join(seen[:4]))
    mid = _find(cpdlc, "msg_id")
    txt = " · ".join(bits) if bits else "CPDLC message"
    return direction, (("[#%s] " % mid) if mid not in (None, "") else "") + txt


def _adsc_summary(adsc):
    """Human one-liner for a libacars ADS-C object (contract / report)."""
    pos = []
    _collect_scalars(adsc, {"lat", "lon", "alt", "alt_ft", "altitude"}, pos, limit=8)
    d = {}
    for k, v in pos:
        d.setdefault(k, v)
    lat = d.get("lat")
    lon = d.get("lon")
    alt = d.get("alt") or d.get("alt_ft") or d.get("altitude")
    if lat is not None and lon is not None:
        s = "POS %.4f %.4f" % (float(lat), float(lon)) if _isnum(lat) and _isnum(lon) \
            else "POS %s %s" % (lat, lon)
        if alt is not None:
            s += " / %s ft" % alt
        return s
    tag = _find(adsc, "tag") or _find(adsc, "contract_type")
    return "ADS-C report" + ((" (%s)" % tag) if tag else "")


def _isnum(v):
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


def normalize_vdl2(obj):
    """Normalize one dumpvdl2 JSON object into a flat message record (pure).

    dumpvdl2 ``--output decoded:json:file:path=-`` emits one JSON object per
    line, wrapped as ``{"vdl2": {...}}``. Inside is an ``avlc`` frame with
    ``src``/``dst`` addresses and, depending on the payload, a nested ``acars``
    block or a libacars-decoded ``cpdlc`` / ``adsc`` tree. Read defensively and
    classify the message. Returns a flat record or None for junk.
    """
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except (ValueError, TypeError):
            return None
    if not isinstance(obj, dict):
        return None
    v = obj.get("vdl2") if isinstance(obj.get("vdl2"), dict) else obj
    if not isinstance(v, dict):
        return None
    avlc = v.get("avlc") if isinstance(v.get("avlc"), dict) else {}

    # Frequency (dumpvdl2 reports Hz) and signal level.
    freq = v.get("freq")
    try:
        freq_mhz = round(float(freq) / 1e6, 3) if freq is not None else None
    except (TypeError, ValueError):
        freq_mhz = None
    level = v.get("sig_level")

    # Timestamp: {"t":{"sec":..,"usec":..}} or a plain epoch.
    ts = None
    t = v.get("t")
    if isinstance(t, dict) and t.get("sec") is not None:
        try:
            ts = float(t["sec"]) + float(t.get("usec", 0)) / 1e6
        except (TypeError, ValueError):
            ts = None
    if ts is None:
        ts = time.time()

    src = avlc.get("src") if isinstance(avlc.get("src"), dict) else {}
    dst = avlc.get("dst") if isinstance(avlc.get("dst"), dict) else {}
    src_addr = (src.get("addr") or "").strip() or None
    dst_addr = (dst.get("addr") or "").strip() or None
    src_type = (src.get("type") or "").strip() or None
    frame_type = (avlc.get("frame_type") or avlc.get("type") or "").strip() or None
    # ICAO is the aircraft's AVLC address when the source is an aircraft.
    icao = src_addr if (src_type or "").lower().startswith("aircraft") else None

    rec = {
        "type": "AVLC", "icao": icao, "src": src_addr, "dst": dst_addr,
        "src_type": src_type, "frame_type": frame_type,
        "reg": None, "flight": None, "label": None, "label_meaning": None,
        "text": None, "direction": None,
        "freq_mhz": freq_mhz, "level": level, "ts": ts,
    }

    # --- ACARS-over-AVLC -------------------------------------------------
    acars = _find(v, "acars")
    if isinstance(acars, dict):
        rec["type"] = "ACARS"
        reg = (acars.get("reg") or acars.get("registration") or "").strip()
        rec["reg"] = reg.lstrip(".") or None    # dumpvdl2 prefixes a padding dot
        rec["flight"] = (acars.get("flight") or acars.get("fid") or "").strip() or None
        label = (acars.get("label") or "").strip() or None
        rec["label"] = label
        rec["label_meaning"] = label_meaning(label)
        txt = acars.get("msg_text")
        if txt is None:
            txt = acars.get("text")
        if isinstance(txt, str):
            rec["text"] = txt.replace("\r", "\n").strip() or None
        rec["msg_num"] = (acars.get("msg_num") or acars.get("msgno") or "").strip() or None
        rec["block_id"] = (acars.get("blk_id") or acars.get("block_id") or "").strip() or None
        rec["direction"] = "downlink" if icao else "uplink"
        return rec

    # --- CPDLC (ATN controller<->pilot) ----------------------------------
    cpdlc = _find(v, "cpdlc")
    if isinstance(cpdlc, dict):
        rec["type"] = "CPDLC"
        direction, summary = _cpdlc_summary(cpdlc)
        rec["direction"] = direction or ("downlink" if icao else "uplink")
        rec["text"] = summary
        return rec

    # --- ADS-C (contracted surveillance) ---------------------------------
    adsc = _find(v, "adsc")
    if isinstance(adsc, dict):
        rec["type"] = "ADS-C"
        rec["direction"] = "downlink"      # ADS-C reports flow aircraft -> ground
        rec["text"] = _adsc_summary(adsc)
        return rec

    # --- Bare AVLC / X.25 control frame ----------------------------------
    if _find(v, "x25") is not None:
        rec["type"] = "X.25"
    # Supervisory/unnumbered frames carry no payload; keep them for link context
    # but give the panel something to show.
    if not rec["text"]:
        ft = {"I": "Information", "S": "Supervisory", "U": "Unnumbered"}.get(
            (frame_type or "")[:1].upper(), frame_type or "link")
        rec["text"] = "%s frame" % ft
    return rec


class Vdl2Decoder:
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
            if not _have(_DUMPVDL2):
                return {"ok": False, "error": "dumpvdl2 not installed"}
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
            # dumpvdl2: RTL device 0, JSON lines to stdout, all default channels.
            cmd = [_DUMPVDL2, "--rtlsdr", "0", "--correction", str(int(ppm or 0)),
                   "--output", "decoded:json:file:path=-"] + \
                  [str(f) for f in VDL2_CHANNELS_HZ]
            try:
                self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                              stderr=subprocess.DEVNULL, text=True)
            except Exception as exc:
                self._error = "failed to launch dumpvdl2: %s" % exc
                return {"ok": False, "error": self._error}
            self._thread = threading.Thread(target=self._read_loop, daemon=True,
                                            name="vdl2-decode")
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
                rec = normalize_vdl2(line)
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


_decoder = Vdl2Decoder()


def start():
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "vdl2 unavailable")}
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
    """One-click install of dumpvdl2 (+ libacars). Not in apt, so build from
    source via the shared helper script."""
    if _have(_DUMPVDL2):
        return {"ok": True, "already": True, "detect": detect()}
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "scripts", "install_dumpvdl2.sh")
    if not os.path.exists(script):
        return {"ok": False, "error": "install_dumpvdl2.sh missing (update Ragnar)",
                "detect": detect()}
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        p = subprocess.run(["bash", script], capture_output=True, text=True,
                           timeout=1800, check=False, env=env)
        out = (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return {"ok": False, "error": "bash not found", "detect": detect()}
    except subprocess.TimeoutExpired:
        return {"ok": _have(_DUMPVDL2), "error": "install timed out (source build is slow — retry)",
                "detect": detect()}
    ok = _have(_DUMPVDL2)
    tail = "\n".join((out or "").strip().splitlines()[-16:])
    return {"ok": ok, "output": tail, "detect": detect(),
            "error": None if ok else "could not build dumpvdl2 (needs internet + build tools). See output."}


# --------------------------------------------------------------------------
# Selftest (pure normalization, no hardware)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    # 1. ACARS-over-VDL2
    acars_msg = {"vdl2": {"freq": 136975000, "sig_level": -24.5,
                          "t": {"sec": 1700000000, "usec": 500000},
                          "avlc": {"src": {"addr": "3C6DA4", "type": "Aircraft", "status": "Airborne"},
                                   "dst": {"addr": "111153", "type": "Ground station"},
                                   "cr": "Command", "frame_type": "I",
                                   "acars": {"reg": ".D-AIMA", "flight": "DLH8LX",
                                             "label": "15", "msg_num": "M12A", "blk_id": "3",
                                             "msg_text": "POS N51.2 E007.1 FL360 M0.79"}}}}
    m = normalize_vdl2(acars_msg)
    check("vdl2: ACARS payload flattened",
          m and m["type"] == "ACARS" and m["reg"] == "D-AIMA" and m["flight"] == "DLH8LX"
          and m["icao"] == "3C6DA4" and "POS" in m["text"] and m["freq_mhz"] == 136.975, str(m))
    check("vdl2: ACARS label meaning + downlink direction",
          m and m["label_meaning"] == "Position report" and m["direction"] == "downlink", str(m))
    check("vdl2: padding dot stripped from reg",
          m and not m["reg"].startswith("."))
    check("vdl2: timestamp from t.sec/usec",
          m and abs(m["ts"] - 1700000000.5) < 0.001, str(m and m["ts"]))

    # 2. CPDLC uplink with free text (nested deep like libacars output).
    # Built from a JSON string so the deep libacars nesting can't be miscounted.
    cpdlc_msg = json.loads('{"vdl2":{"freq":136725000,"avlc":{'
        '"src":{"addr":"1080C4","type":"Ground station"},'
        '"dst":{"addr":"3C6DA4","type":"Aircraft"},"frame_type":"I",'
        '"x25":{"clnp":{"cotp":{"data":{"cpdlc":{'
        '"atc_uplink_message":{"header":{"msg_id":7},'
        '"atc_uplink_msg_element_id":{"choice":"contact",'
        '"data":{"freetext":"CONTACT LONDON 128.075"}}}}}}}}}}}')
    c = normalize_vdl2(cpdlc_msg)
    check("vdl2: CPDLC detected + classified uplink",
          c and c["type"] == "CPDLC" and c["direction"] == "uplink", str(c))
    check("vdl2: CPDLC free text surfaced",
          c and "CONTACT LONDON 128.075" in (c["text"] or ""), str(c and c["text"]))
    check("vdl2: CPDLC msg_id in summary",
          c and "#7" in (c["text"] or ""), str(c and c["text"]))

    # 3. CPDLC downlink summarised from element choices (no free text)
    cpdlc_dl = json.loads('{"vdl2":{"freq":136775000,"avlc":{'
        '"src":{"addr":"406B2A","type":"Aircraft"},'
        '"dst":{"addr":"1080C4","type":"Ground station"},'
        '"x25":{"clnp":{"cotp":{"data":{"cpdlc":{'
        '"atc_downlink_message":{"header":{"msg_id":3},'
        '"atc_downlink_msg_element_id":{"choice":"wilco"}}}}}}}}}}')
    c2 = normalize_vdl2(cpdlc_dl)
    check("vdl2: CPDLC downlink choice summarised",
          c2 and c2["type"] == "CPDLC" and c2["direction"] == "downlink"
          and "wilco" in (c2["text"] or "").lower(), str(c2 and c2["text"]))

    # 4. ADS-C position report
    adsc_msg = json.loads('{"vdl2":{"freq":136800000,"avlc":{'
        '"src":{"addr":"7C6B2D","type":"Aircraft"},'
        '"dst":{"addr":"1080C4","type":"Ground station"},'
        '"x25":{"clnp":{"cotp":{"data":{"adsc":{"tags":['
        '{"basic_report":{"lat":-33.9461,"lon":151.1772,"alt":38000}}]}}}}}}}}')
    a = normalize_vdl2(adsc_msg)
    check("vdl2: ADS-C detected + position summarised",
          a and a["type"] == "ADS-C" and a["direction"] == "downlink"
          and "POS" in (a["text"] or "") and "-33.9" in (a["text"] or ""), str(a and a["text"]))

    # 5. Bare supervisory frame -> link context, not dropped
    s = normalize_vdl2({"vdl2": {"freq": 136975000, "avlc": {
        "src": {"addr": "111153", "type": "Ground station"},
        "dst": {"addr": "3C6DA4", "type": "Aircraft"}, "frame_type": "S"}}})
    check("vdl2: supervisory frame kept with link text",
          s and s["type"] == "AVLC" and s["frame_type"] == "S" and "Supervisory" in s["text"], str(s))

    # 6. Junk / robustness
    check("vdl2: junk -> None",
          normalize_vdl2("not json") is None and normalize_vdl2(42) is None
          and normalize_vdl2("{}") is not None)

    # 7. since-cursor
    dec = Vdl2Decoder()
    for raw in (acars_msg, cpdlc_msg):
        r = normalize_vdl2(raw)
        with dec._lock:
            dec._count += 1
            r["seq"] = dec._count
            dec._msgs.append(r)
    got = dec.messages(since=1)
    check("vdl2: since-cursor returns only newer",
          got["seq"] == 2 and len(got["messages"]) == 1 and got["messages"][0]["type"] == "CPDLC", str(got))

    # 8. Channels are 136 MHz VDL2 band
    check("vdl2: channels in 136 MHz band incl. CSC 136.975",
          all(136000000 <= f <= 137000000 for f in VDL2_CHANNELS_HZ) and 136975000 in VDL2_CHANNELS_HZ)

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
        print("usage: vdl2.py [detect|run|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
