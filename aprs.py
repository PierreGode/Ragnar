#!/usr/bin/env python3
"""
aprs.py — APRS receive + messaging for Ragnar (SDR off-air + APRS-IS Internet).

APRS (Automatic Packet Reporting System) is the ham-radio packet network: 1200
baud AFSK AX.25 on a regional VHF calling frequency (144.390 MHz in North
America, 144.800 in Europe, 145.175 in Australia, …). Stations beacon their
position, weather, telemetry, and short **messages** to each other. **IGates**
bridge the RF world to **APRS-IS**, a global TCP network, so a packet heard in
one town is visible worldwide.

Two sources, one feed:
  * **RF (SDR)** — ``rtl_fm`` FM-demodulates the local APRS channel and
    ``multimon-ng -a AFSK1200`` recovers the AX.25 frames. Receive-only; no
    licence needed to listen.
  * **APRS-IS (Internet)** — a TCP client to the global network. A read-only
    login (no licence) streams **any region** via a server-side filter; with
    your own callsign + passcode you get write access to **send messages**,
    which IGates deliver to the recipient (over the Internet and, near them,
    over RF).

What this does NOT do: transmit on RF. RTL-SDR can't transmit, and HackRF TX is
a licensed, hardware-careful path we deliberately leave out — APRS-IS carries
real messaging without it. Sending on APRS-IS still injects under your callsign,
so only licensed operators should send.

CLI
---
    python3 aprs.py detect
    python3 aprs.py parse 'SRC>APRS,WIDE1-1:=5132.07N/00007.24W-hello'
    python3 aprs.py selftest
"""

import os
import re
import socket
import subprocess
import sys
import threading
import time


def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


_RTL_FM = _which("rtl_fm")
_MULTIMON = _which("multimon-ng")
_MSG_RING = 800
_STATION_MAX = 4000

# Regional APRS calling frequency (Hz) + a sensible default APRS-IS area filter.
# Non-exhaustive but spans every continent; the UI also takes a free-form MHz
# and a free-form APRS-IS filter.
APRS_REGIONS = {
    "North America (144.390)":   {"rf_hz": 144_390_000, "is_filter": "r/39.8/-98.6/3000"},
    "Europe (144.800)":          {"rf_hz": 144_800_000, "is_filter": "r/50/10/3000"},
    "UK & Ireland (144.800)":    {"rf_hz": 144_800_000, "is_filter": "r/54/-3/1500"},
    "Australia (145.175)":       {"rf_hz": 145_175_000, "is_filter": "r/-25/135/4000"},
    "New Zealand (144.575)":     {"rf_hz": 144_575_000, "is_filter": "r/-41/174/1500"},
    "Japan (144.640)":           {"rf_hz": 144_640_000, "is_filter": "r/36/138/2000"},
    "South Korea (144.620)":     {"rf_hz": 144_620_000, "is_filter": "r/36/128/800"},
    "China (144.640)":           {"rf_hz": 144_640_000, "is_filter": "r/35/103/4000"},
    "Brazil (145.570)":          {"rf_hz": 145_570_000, "is_filter": "r/-14/-52/4000"},
    "Argentina & Chile (144.930)": {"rf_hz": 144_930_000, "is_filter": "r/-35/-65/3000"},
    "Southern Africa (144.800)": {"rf_hz": 144_800_000, "is_filter": "r/-26/28/3000"},
    "Thailand (145.525)":        {"rf_hz": 145_525_000, "is_filter": "r/15/101/1500"},
    "Russia (144.800)":          {"rf_hz": 144_800_000, "is_filter": "r/56/38/5000"},
}

APRS_IS_HOST = "rotate.aprs2.net"
APRS_IS_PORT = 14580            # the filtered/full-feed port


# --------------------------------------------------------------------------
# APRS-IS passcode — the well-known callsign hash (write access)
# --------------------------------------------------------------------------

def aprs_passcode(callsign):
    """The standard APRS-IS passcode for a base callsign (SSID stripped)."""
    call = (callsign or "").split("-")[0].upper()
    code = 0x73E2
    i = 0
    while i < len(call):
        code ^= ord(call[i]) << 8
        if i + 1 < len(call):
            code ^= ord(call[i + 1])
        i += 2
    return code & 0x7FFF


def valid_passcode(callsign, passcode):
    try:
        return int(passcode) == aprs_passcode(callsign)
    except (TypeError, ValueError):
        return False


# --------------------------------------------------------------------------
# Parser — pure, drives the selftest
# --------------------------------------------------------------------------

def _b91(s):
    v = 0
    for ch in s:
        v = v * 91 + (ord(ch) - 33)
    return v


def _lat_uncomp(s):          # "4903.50N"
    if len(s) < 8:
        return None
    try:
        deg = int(s[0:2])
        minutes = float((s[2:7].replace(" ", "0")) or "0")
    except ValueError:
        return None
    val = deg + minutes / 60.0
    return -val if s[7] in "Ss" else val


def _lon_uncomp(s):          # "07201.75W"
    if len(s) < 9:
        return None
    try:
        deg = int(s[0:3])
        minutes = float((s[3:8].replace(" ", "0")) or "0")
    except ValueError:
        return None
    val = deg + minutes / 60.0
    return -val if s[8] in "Ww" else val


_ALT_RE = re.compile(r"/A=(-?\d{6})")
_CSE_RE = re.compile(r"^(\d{3})/(\d{3})")     # course/speed at start of comment
_WX_TEMP = re.compile(r"t(-?\d{2,3})")
_WX_WDIR = re.compile(r"c(\d{3})")
_WX_WSPD = re.compile(r"s(\d{3})")


def _extract_extra(comment):
    """Pull course/speed, altitude and (best-effort) weather out of a comment."""
    out = {}
    c = comment or ""
    m = _CSE_RE.match(c)
    if m:
        out["course"] = int(m.group(1))
        out["speed_kt"] = int(m.group(2))
        c = c[7:]
    a = _ALT_RE.search(comment or "")
    if a:
        out["altitude_ft"] = int(a.group(1))
    # weather packets pack cNNNsNNNgNNNtNNN… into the comment
    if _WX_TEMP.search(comment or "") and (_WX_WSPD.search(comment or "") or "g" in (comment or "")):
        wt = _WX_TEMP.search(comment or "")
        wd = _WX_WDIR.search(comment or "")
        ws = _WX_WSPD.search(comment or "")
        wx = {}
        if wt:
            wx["temp_f"] = int(wt.group(1))
        if wd:
            wx["wind_dir"] = int(wd.group(1))
        if ws:
            wx["wind_mph"] = int(ws.group(1))
        if wx:
            out["weather"] = wx
    out["comment"] = c.strip()
    return out


def _parse_position(info):
    """Position body after the data-type id (and any timestamp). Returns dict."""
    if not info:
        return {}
    c = info[0]
    if c.isdigit():                                  # uncompressed
        if len(info) < 19:
            return {}
        lat = _lat_uncomp(info[0:8]); lon = _lon_uncomp(info[9:18])
        if lat is None or lon is None:
            return {}
        out = {"lat": round(lat, 6), "lon": round(lon, 6), "symbol": info[8] + info[18]}
        out.update(_extract_extra(info[19:]))
        return out
    if c in "/\\" or ("A" <= c <= "Z") or ("a" <= c <= "j"):   # compressed
        if len(info) < 13:
            return {}
        try:
            lat = 90 - _b91(info[1:5]) / 380926.0
            lon = -180 + _b91(info[5:9]) / 190463.0
        except Exception:
            return {}
        out = {"lat": round(lat, 6), "lon": round(lon, 6), "symbol": info[0] + info[9]}
        out.update(_extract_extra(info[13:]))
        return out
    return {}


def _parse_mice(dest, info):
    """Mic-E: latitude+flags from the destination, longitude+speed/course from info."""
    if len(dest) < 6 or len(info) < 9:
        return {}
    digits = ""; ns = "S"; ew = "E"; lonoff = 0; msgbits = []
    for i, ch in enumerate(dest[:6]):
        o = ord(ch)
        if 48 <= o <= 57:
            d, b = o - 48, 0
        elif 65 <= o <= 74:
            d, b = o - 65, 1
        elif 80 <= o <= 89:
            d, b = o - 80, 1
        elif o == 90:
            d, b = 0, 1
        else:
            d, b = None, 0                           # K/L ambiguity
        digits += (str(d) if d is not None else " ")
        if i < 3:
            msgbits.append(b)
        elif i == 3:
            ns = "N" if o >= 80 else "S"
        elif i == 4:
            lonoff = 100 if o >= 80 else 0
        elif i == 5:
            ew = "W" if o >= 80 else "E"
    try:
        lat = int(digits[0:2]) + float(digits[2:4] + "." + digits[4:6]) / 60.0
    except ValueError:
        return {}
    if ns == "S":
        lat = -lat
    d = ord(info[1]) - 28 + lonoff
    if 180 <= d <= 189:
        d -= 80
    elif 190 <= d <= 199:
        d -= 190
    m = ord(info[2]) - 28
    if m >= 60:
        m -= 60
    h = ord(info[3]) - 28
    lon = d + (m + h / 100.0) / 60.0
    if ew == "W":
        lon = -lon
    sp = ord(info[4]) - 28; dc = ord(info[5]) - 28; se = ord(info[6]) - 28
    speed = sp * 10 + dc // 10
    if speed >= 800:
        speed -= 800
    course = (dc % 10) * 100 + se
    if course >= 400:
        course -= 400
    out = {"lat": round(lat, 6), "lon": round(lon, 6), "symbol": info[8] + info[7],
           "course": course, "speed_kt": speed, "mice": True}
    out.update(_extract_extra(info[9:]))
    return out


def _parse_message(info):
    """`:ADDRESSEE:text{msgno`  ·  ack/rej.  info starts with ':'."""
    m = re.match(r":([^:]{1,9})\s*:(.*)", info)
    if not m:
        return {}
    addr = m.group(1).strip(); rest = m.group(2)
    am = re.match(r"(ack|rej)([A-Za-z0-9]+)\s*$", rest)
    if am:
        return {"addressee": addr, "text": None, "msgno": am.group(2), "msgkind": am.group(1)}
    msgno = None; text = rest
    mm = re.search(r"\{([A-Za-z0-9]+)\s*$", rest)
    if mm:
        msgno = mm.group(1); text = rest[:mm.start()]
    return {"addressee": addr, "text": text, "msgno": msgno, "msgkind": "message"}


def parse_aprs(line):
    """Parse a TNC2 APRS line into a structured dict, or None.

    ``SOURCE>DEST,PATH1,PATH2:INFORMATION`` — handles uncompressed & compressed
    positions (with/without timestamp), Mic-E, messages/acks, objects, status,
    and best-effort weather. Returns at least {source, dest, path, type, raw}.
    """
    if not line:
        return None
    line = line.strip()
    # multimon prefixes decoded frames; APRS-IS does not
    for pre in ("APRS: ", "AFSK1200: "):
        if line.startswith(pre):
            line = line[len(pre):].strip()
    if line.startswith("#") or ">" not in line or ":" not in line:
        return None
    head, info = line.split(":", 1)
    if ">" not in head:
        return None
    src, rest = head.split(">", 1)
    parts = rest.split(",")
    dest = parts[0].strip()
    path = [p.strip() for p in parts[1:] if p.strip()]
    rec = {"source": src.strip().upper(), "dest": dest.upper(), "path": path,
           "raw": line, "type": "other", "info": info}
    if not info:
        return rec
    t = info[0]
    try:
        if t in ("`", "'", "\x1c", "\x1d"):          # Mic-E
            pos = _parse_mice(dest, info)
            if pos:
                rec.update(pos); rec["type"] = "position"
        elif t in ("!", "="):                         # position, no timestamp
            pos = _parse_position(info[1:])
            if pos:
                rec.update(pos); rec["type"] = "position"
        elif t in ("@", "/"):                         # position, with timestamp
            rec["timestamp"] = info[1:8]
            pos = _parse_position(info[8:])
            if pos:
                rec.update(pos); rec["type"] = "position"
        elif t == ":":                                # message / ack
            msg = _parse_message(info)
            if msg:
                rec.update(msg)
                rec["type"] = "ack" if msg["msgkind"] in ("ack", "rej") else "message"
        elif t == ";":                                # object
            rec["object"] = info[1:10].strip()
            rec["object_live"] = (len(info) > 10 and info[10] == "*")
            pos = _parse_position(info[18:]) if len(info) > 18 else {}
            if pos:
                rec.update(pos)
            rec["type"] = "object"
        elif t == ">":                                # status
            rec["type"] = "status"; rec["comment"] = info[1:].strip()
        elif t == "_":                                # positionless weather
            rec["type"] = "weather"
            rec.update(_extract_extra(info))
        elif t == "T":                                # telemetry
            rec["type"] = "telemetry"; rec["comment"] = info[1:].strip()
        else:
            rec["comment"] = info.strip()
    except Exception:
        pass
    return rec


# --------------------------------------------------------------------------
# Live hub — RF decoder + APRS-IS client feeding one packet/station/message set
# --------------------------------------------------------------------------

class AprsHub:
    def __init__(self):
        self._lock = threading.Lock()
        self._packets = []
        self._stations = {}
        self._messages = []
        self._seq = 0
        # RF
        self._fm = None; self._mm = None
        self._rf_thread = None; self._rf_stop = threading.Event()
        self._rf_freq = None; self._rf_err = None
        # APRS-IS
        self._sock = None
        self._is_thread = None; self._is_stop = threading.Event()
        self._is_connected = False; self._is_err = None
        self._call = "N0CALL"; self._pass = -1; self._filter = ""
        self._write = False

    # -- ingest -----------------------------------------------------------
    def _ingest(self, rec, source):
        if not rec:
            return
        with self._lock:
            self._seq += 1
            rec = dict(rec)
            rec["seq"] = self._seq
            rec["ts"] = time.time()
            rec["src_kind"] = source              # 'rf' | 'is' | 'tx'
            self._packets.append(rec)
            if len(self._packets) > _MSG_RING:
                self._packets = self._packets[-_MSG_RING:]
            if rec.get("lat") is not None and rec.get("lon") is not None:
                self._stations[rec["source"]] = {
                    "call": rec["source"], "lat": rec["lat"], "lon": rec["lon"],
                    "symbol": rec.get("symbol"), "comment": rec.get("comment"),
                    "course": rec.get("course"), "speed_kt": rec.get("speed_kt"),
                    "altitude_ft": rec.get("altitude_ft"), "ts": rec["ts"],
                    "src_kind": source}
                if len(self._stations) > _STATION_MAX:
                    old = sorted(self._stations.items(), key=lambda kv: kv[1]["ts"])
                    for k, _ in old[:len(self._stations) - _STATION_MAX]:
                        self._stations.pop(k, None)
            if rec["type"] in ("message", "ack"):
                self._messages.append(rec)
                if len(self._messages) > _MSG_RING:
                    self._messages = self._messages[-_MSG_RING:]

    # -- RF (rtl_fm | multimon-ng) ---------------------------------------
    def start_rf(self, freq_hz):
        try:
            freq_hz = int(float(freq_hz))
        except (TypeError, ValueError):
            return {"ok": False, "error": "bad frequency"}
        if not (24_000_000 <= freq_hz <= 1_766_000_000):
            return {"ok": False, "error": "frequency out of RTL-SDR range"}
        with self._lock:
            self._stop_rf_locked()
            self._rf_stop.clear()
            self._rf_freq = freq_hz; self._rf_err = None
            ppm = 0; gain = None
            try:
                import rtl_sdr
                tun = rtl_sdr.get_tuning()
                ppm = tun.get("ppm", 0) or 0
                gain = None if tun.get("gain_is_auto") else tun.get("gain")
            except Exception:
                pass
            fm = [_RTL_FM, "-f", str(freq_hz), "-M", "fm", "-s", "22050", "-l", "0", "-p", str(ppm)]
            if gain is not None:
                fm += ["-g", str(gain)]
            fm += ["-"]
            mm = [_MULTIMON, "-a", "AFSK1200", "-A", "-t", "raw", "-"]
            try:
                self._fm = subprocess.Popen(fm, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                self._mm = subprocess.Popen(mm, stdin=self._fm.stdout, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, text=True)
                self._fm.stdout.close()
            except Exception as exc:
                self._rf_err = "failed to launch rtl_fm|multimon-ng: %s" % exc
                self._stop_rf_locked()
                return {"ok": False, "error": self._rf_err}
            self._rf_thread = threading.Thread(target=self._rf_loop, daemon=True, name="aprs-rf")
            self._rf_thread.start()
        return {"ok": True, "freq_hz": freq_hz}

    def _rf_loop(self):  # pragma: no cover - hardware path
        try:
            for line in self._mm.stdout:
                if self._rf_stop.is_set():
                    break
                if "APRS" not in line and ">" not in line:
                    continue
                rec = parse_aprs(line)
                if rec:
                    self._ingest(rec, "rf")
        except Exception as exc:
            self._rf_err = str(exc)

    def _stop_rf_locked(self):
        self._rf_stop.set()
        for p in (self._mm, self._fm):
            if p:
                try:
                    p.terminate(); p.wait(timeout=2)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
        self._mm = None; self._fm = None

    def stop_rf(self):
        with self._lock:
            self._stop_rf_locked()
            self._rf_freq = None
        return {"ok": True}

    # -- APRS-IS ----------------------------------------------------------
    def connect_is(self, callsign=None, passcode=None, filter_str=None, igate=False):
        call = (callsign or "N0CALL").strip().upper()
        try:
            pc = int(passcode) if passcode not in (None, "") else -1
        except (TypeError, ValueError):
            pc = -1
        write = valid_passcode(call, pc) and call != "N0CALL"
        with self._lock:
            self._stop_is_locked()
            self._is_stop.clear()
            self._call = call; self._pass = pc
            self._filter = (filter_str or "").strip(); self._write = write
            self._igate = bool(igate) and write
            self._is_err = None
            self._is_thread = threading.Thread(target=self._is_loop, daemon=True, name="aprs-is")
            self._is_thread.start()
        return {"ok": True, "write": write, "callsign": call}

    def _is_loop(self):  # pragma: no cover - network path
        try:
            s = socket.create_connection((APRS_IS_HOST, APRS_IS_PORT), timeout=15)
            s.settimeout(30)
            self._sock = s
            login = "user %s pass %s vers RagnarAPRS 1.0" % (self._call, self._pass)
            if self._filter:
                login += " filter %s" % self._filter
            s.sendall((login + "\r\n").encode("ascii", "replace"))
            self._is_connected = True
            buf = b""
            while not self._is_stop.is_set():
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    try:
                        s.sendall(b"# keepalive\r\n")
                    except Exception:
                        break
                    continue
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.decode("utf-8", "replace").strip("\r")
                    if not line or line.startswith("#"):
                        continue
                    rec = parse_aprs(line)
                    if rec:
                        self._ingest(rec, "is")
        except Exception as exc:
            self._is_err = str(exc)
        finally:
            self._is_connected = False
            try:
                if self._sock:
                    self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _stop_is_locked(self):
        self._is_stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = None
        self._is_connected = False

    def disconnect_is(self):
        with self._lock:
            self._stop_is_locked()
        return {"ok": True}

    def send_message(self, to, text):
        with self._lock:
            if not (self._sock and self._is_connected and self._write):
                return {"ok": False, "error": "APRS-IS write access required (valid callsign + passcode)"}
            to = (to or "").strip().upper()[:9]
            text = (text or "").strip()
            if not to or not text:
                return {"ok": False, "error": "recipient and message required"}
            text = text.replace("|", " ").replace("~", " ").replace("{", "(")[:67]
            self._seq += 1
            msgno = self._seq % 100000
            frame = "%s>APRS,TCPIP*::%-9s:%s{%d" % (self._call, to, text, msgno)
            try:
                self._sock.sendall((frame + "\r\n").encode("ascii", "replace"))
            except Exception as exc:
                return {"ok": False, "error": "send failed: %s" % exc}
        # log the outbound message into the feed
        self._ingest({"source": self._call, "dest": "APRS", "path": ["TCPIP*"],
                      "type": "message", "addressee": to, "text": text,
                      "msgno": str(msgno), "msgkind": "message", "raw": frame,
                      "outbound": True}, "tx")
        return {"ok": True, "to": to, "msgno": msgno}

    # -- read models ------------------------------------------------------
    def status(self):
        with self._lock:
            return {
                "rf_running": bool(self._rf_thread and self._rf_thread.is_alive()),
                "rf_freq_hz": self._rf_freq, "rf_error": self._rf_err,
                "is_connected": self._is_connected, "is_error": self._is_err,
                "is_write": self._write, "callsign": self._call, "filter": self._filter,
                "packets": self._seq, "stations": len(self._stations),
                "messages": len(self._messages),
            }

    def packets(self, since=0, limit=200):
        try:
            since = int(since)
        except (TypeError, ValueError):
            since = 0
        with self._lock:
            new = [p for p in self._packets if p["seq"] > since]
            return {"packets": new[-limit:], "seq": self._seq}

    def stations(self):
        with self._lock:
            return {"stations": list(self._stations.values()), "count": len(self._stations)}

    def messages(self, since=0):
        try:
            since = int(since)
        except (TypeError, ValueError):
            since = 0
        with self._lock:
            return {"messages": [m for m in self._messages if m["seq"] > since], "seq": self._seq}

    def stop_all(self):
        with self._lock:
            self._stop_rf_locked(); self._stop_is_locked(); self._rf_freq = None
        return {"ok": True}


_hub = AprsHub()


# --------------------------------------------------------------------------
# Detect + module API
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
    """Report RF-decode capability (rtl_fm + multimon-ng + a dongle).

    APRS-IS needs only a network connection, so it's usable even when the RF
    tools/dongle aren't present — reported via ``is_available``.
    """
    tools = {"rtl_fm": _have(_RTL_FM), "multimon_ng": _have(_MULTIMON)}
    usb = None
    try:
        import rtl_sdr
        usb = rtl_sdr.probe_usb()[0]
    except Exception:
        usb = None
    device = usb is not None
    rf_ok = tools["rtl_fm"] and tools["multimon_ng"] and device
    err = None
    if not tools["multimon_ng"]:
        err = "multimon-ng not installed (apt install multimon-ng)"
    elif not tools["rtl_fm"]:
        err = "rtl_fm not installed (apt install rtl-sdr)"
    elif not device:
        err = "no RTL-SDR on the USB bus — plug a dongle in"
    return {"available": rf_ok, "rf_available": rf_ok, "is_available": True,
            "tools": tools, "device_present": device, "usb_id": usb,
            "regions": {k: v["rf_hz"] for k, v in APRS_REGIONS.items()},
            "region_filters": {k: v["is_filter"] for k, v in APRS_REGIONS.items()},
            "tools_installed": tools["multimon_ng"] and tools["rtl_fm"], "error": err}


def start_rf(freq_hz=None):
    d = detect()
    if not d.get("rf_available"):
        return {"ok": False, "error": d.get("error", "APRS RF decode unavailable")}
    if freq_hz is None:
        freq_hz = APRS_REGIONS["North America (144.390)"]["rf_hz"]
    return _hub.start_rf(freq_hz)


def stop_rf():
    return _hub.stop_rf()


def connect_is(callsign=None, passcode=None, filter_str=None, igate=False):
    return _hub.connect_is(callsign, passcode, filter_str, igate)


def disconnect_is():
    return _hub.disconnect_is()


def send_message(to, text):
    return _hub.send_message(to, text)


def stop():
    return _hub.stop_rf()          # only RF holds the dongle; leave APRS-IS running


def stop_all():
    return _hub.stop_all()


def status():
    st = _hub.status()
    st["detect"] = detect()
    return st


def packets(since=0):
    return _hub.packets(since=since)


def stations():
    return _hub.stations()


def messages(since=0):
    return _hub.messages(since=since)


def install():
    """multimon-ng is in the apt repos (also powers Pager Decode)."""
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
    return {"ok": ok, "detect": detect(),
            "output": "\n".join(out.strip().splitlines()[-10:]),
            "error": None if ok else "apt could not install multimon-ng"}


# --------------------------------------------------------------------------
# Selftest (pure parser + passcode, no hardware/network)
# --------------------------------------------------------------------------

def _mice_encode(lat, lon, course, speed):
    """Minimal Mic-E encoder — selftest only (values chosen to avoid offset ranges)."""
    ns = "N" if lat >= 0 else "S"; ew = "W" if lon < 0 else "E"
    alat = abs(lat); latd = int(alat); latm = (alat - latd) * 60
    digs = ("%02d%05.2f" % (latd, latm)).replace(".", "")      # DDMMmm -> 6 digits
    alon = abs(lon); lond = int(alon); lonm = (alon - lond) * 60
    lonoff = 100 if lond >= 100 else 0
    dest = ""
    for i, dch in enumerate(digs[:6]):
        v = int(dch)
        one = (i == 3 and ns == "N") or (i == 4 and lonoff) or (i == 5 and ew == "W")
        dest += chr((80 if one else 48) + v)
    b1 = chr(lond - lonoff + 28); b2 = chr(int(lonm) + 28)
    b3 = chr(int(round((lonm - int(lonm)) * 100)) + 28)
    b4 = chr(speed // 10 + 28); b5 = chr((speed % 10) * 10 + course // 100 + 28); b6 = chr(course % 100 + 28)
    info = "`" + b1 + b2 + b3 + b4 + b5 + b6 + ">/" + "test"
    return dest, info


def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    # header + uncompressed position
    p = parse_aprs("G0TEST-9>APRS,WIDE1-1,WIDE2-1:=5132.07N/00007.24W-Ragnar test")
    check("parse: uncompressed position + header",
          p and p["source"] == "G0TEST-9" and p["type"] == "position"
          and abs(p["lat"] - 51.5345) < 0.001 and abs(p["lon"] - (-0.1207)) < 0.001
          and p["path"] == ["WIDE1-1", "WIDE2-1"], str(p))

    # position with timestamp + course/speed + altitude in comment
    p = parse_aprs("N0CALL>APRS,TCPIP*:@092345z4903.50N/07201.75W>088/036/A=001234moving")
    check("parse: timestamped position + course/speed/altitude",
          p and abs(p["lat"] - 49.0583) < 0.001 and abs(p["lon"] - (-72.0292)) < 0.001
          and p.get("course") == 88 and p.get("speed_kt") == 36 and p.get("altitude_ft") == 1234, str(p))

    # compressed position
    p = parse_aprs("M0XER>APRS:=/5L!!<*e7> sT")
    check("parse: compressed position decodes to a sane lat/lon",
          p and p.get("lat") is not None and -90 <= p["lat"] <= 90
          and -180 <= p["lon"] <= 180 and p["type"] == "position", str(p))

    # message
    p = parse_aprs("N0CALL-7>APRS,WIDE1-1::WB2OSZ   :Hello there{003")
    check("parse: message to addressee + msgno",
          p and p["type"] == "message" and p["addressee"] == "WB2OSZ"
          and p["text"] == "Hello there" and p["msgno"] == "003", str(p))

    # ack
    p = parse_aprs("WB2OSZ>APRS::N0CALL-7 :ack003")
    check("parse: message ack",
          p and p["type"] == "ack" and p["addressee"] == "N0CALL-7" and p["msgno"] == "003", str(p))

    # status
    p = parse_aprs("N0CALL>APRS:>Net control tonight 8pm")
    check("parse: status", p and p["type"] == "status" and "Net control" in p["comment"], str(p))

    # Mic-E round trip (33.4273N, 12.147W, course 251, speed 20 kt)
    dest, info = _mice_encode(33.427333, -12.147, 251, 20)
    p = parse_aprs("VK2XYZ-9>%s,WIDE1-1:%s" % (dest, info))
    check("parse: Mic-E position + course/speed round-trips",
          p and p.get("mice") and abs(p["lat"] - 33.4273) < 0.01
          and abs(p["lon"] - (-12.147)) < 0.01 and p["course"] == 251 and p["speed_kt"] == 20,
          str(p))

    # object
    p = parse_aprs("N0CALL>APRS:;LEADER   *092345z4903.50N/07201.75W>Team leader")
    check("parse: object with position",
          p and p["type"] == "object" and p["object"] == "LEADER"
          and abs(p["lat"] - 49.0583) < 0.001, str(p))

    # noise / server lines rejected
    check("parse: junk and server comments -> None",
          parse_aprs("# aprsc 2.1.10") is None and parse_aprs("") is None
          and parse_aprs("not a packet") is None)

    # passcode: deterministic, in range, and matches the known algorithm
    pc = aprs_passcode("N0CALL")
    check("passcode: deterministic + valid range",
          0 <= pc <= 0x7FFF and aprs_passcode("n0call-7") == pc
          and valid_passcode("N0CALL", pc) and not valid_passcode("N0CALL", pc + 1), "pc=%d" % pc)

    # regions cover every continent + sane RF freqs
    check("regions: multi-continent presets in the 2 m band",
          len(APRS_REGIONS) >= 10
          and all(144_000_000 <= v["rf_hz"] <= 146_000_000 for v in APRS_REGIONS.values()), "")

    # hub ingest / station map without hardware
    hub = AprsHub()
    hub._ingest(parse_aprs("G0TEST>APRS:=5132.07N/00007.24W-hi"), "is")
    hub._ingest(parse_aprs("N0CALL>APRS::G0TEST   :ping{1"), "is")
    check("hub: ingest builds station map + message feed",
          hub.stations()["count"] == 1 and len(hub.messages()["messages"]) == 1
          and hub.status()["packets"] == 2, str(hub.status()))

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


def _main(argv):
    import json
    cmd = argv[1] if len(argv) > 1 else "detect"
    if cmd == "detect":
        print(json.dumps(detect(), indent=2))
    elif cmd == "parse":
        print(json.dumps(parse_aprs(argv[2] if len(argv) > 2 else ""), indent=2))
    elif cmd == "passcode":
        print(aprs_passcode(argv[2] if len(argv) > 2 else "N0CALL"))
    elif cmd == "selftest":
        r = selftest()
        for x in r["results"]:
            print("  [%s] %s%s" % ("PASS" if x["pass"] else "FAIL", x["name"],
                                   "" if x["pass"] else "  -> " + x["detail"]))
        print("\n%d/%d checks pass — %s" % (r["passed"], r["total"],
                                            "OK" if r["pass"] else "FAILURES"))
        return 0 if r["pass"] else 1
    else:
        print("usage: aprs.py [detect|parse <tnc2>|passcode <call>|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
