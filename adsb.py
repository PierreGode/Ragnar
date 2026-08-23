#!/usr/bin/env python3
"""
adsb.py — live aircraft (ADS-B, 1090 MHz) via an RTL-SDR + dump1090.

The RTL-SDR's other famous trick: at 1090 MHz it hears the ADS-B position
broadcasts every airliner (and most GA) transmits in the clear — ICAO address,
callsign, latitude/longitude, altitude, speed and heading. This module drives
``dump1090`` (any common fork: dump1090-fa / dump1090-mutability / plain
dump1090), reads its BaseStation (SBS) stream on TCP 30003, and keeps a live
aircraft table the web UI renders as a **radar / PPI screen**.

Receive-only — nothing here transmits. ADS-B is unauthenticated and unencrypted
by design, so this is straightforward passive reception (the same data every
flight-tracking site shows).

One dongle, one claim
---------------------
1090 MHz ADS-B uses the whole RTL-SDR, so it is mutually exclusive with the
sub-GHz sweep / ISM decoder (rtl_sdr.py). The web layer stops one before
starting the other.

CLI
---
    python3 adsb.py detect
    python3 adsb.py run [--seconds N]
    python3 adsb.py selftest
"""

import math
import os
import socket
import subprocess
import sys
import threading
import time


def _which(name):
    p = "/usr/bin/%s" % name
    return p if os.path.exists(p) else name


# dump1090 ships under several binary names; take whichever exists.
_DUMP_CANDIDATES = ("dump1090-fa", "dump1090-mutability", "dump1090")
_SBS_HOST = "127.0.0.1"
_SBS_PORT = 30003          # dump1090 --net BaseStation (SBS) output
_STALE_S = 60              # drop an aircraft not heard from in this long
_MAX_AIRCRAFT = 500


def _dump_bin():
    for name in _DUMP_CANDIDATES:
        p = _which(name)
        if os.path.exists(p) or _run([p, "--help"])[0] != 127:
            return p
    return None


def _run(args, timeout=5):
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


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def detect():
    """Report whether ADS-B is available (dump1090 present + RTL-SDR reachable).

    We don't hard-probe the dongle here (that would need rtl_test, which fights
    for the device); we report tool availability and let a start attempt surface
    any device error. RTL-SDR presence is confirmed cheaply via lsusb.
    """
    dump = _dump_bin()
    if not dump:
        return {"available": False, "tools_installed": False, "device_present": False,
                "error": "dump1090 not installed (apt install dump1090-fa or dump1090-mutability)"}
    # Reuse rtl_sdr's lsusb probe when available so we can say "no dongle".
    usb = None
    try:
        import rtl_sdr
        usb = rtl_sdr.probe_usb()[0]
    except Exception:
        usb = None
    if usb is None:
        return {"available": False, "tools_installed": True, "device_present": False,
                "dump1090": dump,
                "error": "no RTL-SDR on the USB bus — plug a dongle in (powered hub recommended)"}
    return {"available": True, "tools_installed": True, "device_present": True,
            "dump1090": dump, "usb_id": usb}


# --------------------------------------------------------------------------
# SBS (BaseStation) parser — pure, drives the selftest
# --------------------------------------------------------------------------

def parse_sbs(line):
    """Parse one dump1090 SBS/BaseStation CSV line into a partial aircraft dict.

    SBS 'MSG' rows are comma-separated with fixed columns; different message
    types populate different columns, so each line carries a subset. Returns a
    dict with 'icao' plus whatever fields are present (callsign/alt/gs/track/
    lat/lon/vert), or None for non-MSG / unparseable lines.
    """
    if not line:
        return None
    p = line.strip().split(",")
    if len(p) < 22 or p[0] != "MSG":
        return None
    icao = (p[4] or "").strip().upper()
    if not icao:
        return None

    def val(i, cast):
        try:
            s = p[i].strip()
            return cast(s) if s != "" else None
        except (ValueError, IndexError):
            return None

    rec = {"icao": icao}
    cs = p[10].strip()
    if cs:
        rec["callsign"] = cs
    for key, idx, cast in (("alt", 11, int), ("gs", 12, float), ("track", 13, float),
                           ("lat", 14, float), ("lon", 15, float), ("vert", 16, int)):
        v = val(idx, cast)
        if v is not None:
            rec[key] = v
    return rec


# Airline designators: ICAO 3-letter callsign prefix -> (IATA 2-letter, name).
# A curated set of the busiest carriers worldwide — covers the large majority of
# flights seen; unknown prefixes just fall back to the raw callsign. ADS-B
# callsigns carry the ICAO code (e.g. "RYR123"); we derive IATA ("FR123") + name.
AIRLINES = {
    "AAL": ("AA", "American Airlines"), "UAL": ("UA", "United Airlines"),
    "DAL": ("DL", "Delta Air Lines"), "SWA": ("WN", "Southwest"),
    "JBU": ("B6", "JetBlue"), "ASA": ("AS", "Alaska Airlines"),
    "FFT": ("F9", "Frontier"), "NKS": ("NK", "Spirit"), "SKW": ("OO", "SkyWest"),
    "AAY": ("G4", "Allegiant"), "HAL": ("HA", "Hawaiian"),
    "ACA": ("AC", "Air Canada"), "WJA": ("WS", "WestJet"), "JZA": ("QK", "Jazz"),
    "BAW": ("BA", "British Airways"), "SHT": ("BA", "British Airways (Shuttle)"),
    "VIR": ("VS", "Virgin Atlantic"), "EZY": ("U2", "easyJet"),
    "EXS": ("LS", "Jet2"), "TOM": ("BY", "TUI Airways"),
    "RYR": ("FR", "Ryanair"), "RUK": ("FR", "Ryanair UK"),
    "DLH": ("LH", "Lufthansa"), "CLH": ("CL", "Lufthansa CityLine"),
    "AFR": ("AF", "Air France"), "KLM": ("KL", "KLM"), "BEL": ("SN", "Brussels Airlines"),
    "SWR": ("LX", "SWISS"), "AUA": ("OS", "Austrian"), "EWG": ("EW", "Eurowings"),
    "IBE": ("IB", "Iberia"), "IBS": ("I2", "Iberia Express"), "VLG": ("VY", "Vueling"),
    "AEA": ("UX", "Air Europa"), "TAP": ("TP", "TAP Air Portugal"),
    "ITY": ("AZ", "ITA Airways"), "SAS": ("SK", "SAS"), "NAX": ("DY", "Norwegian"),
    "NSZ": ("DY", "Norwegian"), "FIN": ("AY", "Finnair"), "ICE": ("FI", "Icelandair"),
    "AFL": ("SU", "Aeroflot"), "THY": ("TK", "Turkish Airlines"),
    "PGT": ("PC", "Pegasus"), "AEE": ("A3", "Aegean"), "LOT": ("LO", "LOT Polish"),
    "CSA": ("OK", "Czech Airlines"), "WZZ": ("W6", "Wizz Air"), "TVF": ("TO", "Transavia France"),
    "TRA": ("HV", "Transavia"), "EIN": ("EI", "Aer Lingus"),
    "UAE": ("EK", "Emirates"), "ETD": ("EY", "Etihad"), "QTR": ("QR", "Qatar Airways"),
    "SVA": ("SV", "Saudia"), "MSR": ("MS", "EgyptAir"), "ELY": ("LY", "El Al"),
    "RJA": ("RJ", "Royal Jordanian"), "ABY": ("G9", "Air Arabia"), "FDB": ("FZ", "flydubai"),
    "GFA": ("GF", "Gulf Air"), "KAC": ("KU", "Kuwait Airways"), "OMA": ("WY", "Oman Air"),
    "SIA": ("SQ", "Singapore Airlines"), "CPA": ("CX", "Cathay Pacific"),
    "CCA": ("CA", "Air China"), "CES": ("MU", "China Eastern"), "CSN": ("CZ", "China Southern"),
    "HDA": ("UO", "HK Express"), "ANA": ("NH", "All Nippon"), "JAL": ("JL", "Japan Airlines"),
    "KAL": ("KE", "Korean Air"), "AAR": ("OZ", "Asiana"), "CAL": ("CI", "China Airlines"),
    "EVA": ("BR", "EVA Air"), "THA": ("TG", "Thai Airways"), "AXM": ("AK", "AirAsia"),
    "MAS": ("MH", "Malaysia Airlines"), "GIA": ("GA", "Garuda"), "PAL": ("PR", "Philippine"),
    "VJC": ("VJ", "VietJet"), "HVN": ("VN", "Vietnam Airlines"), "IGO": ("6E", "IndiGo"),
    "AIC": ("AI", "Air India"), "VTI": ("UK", "Vistara"), "QFA": ("QF", "Qantas"),
    "JST": ("JQ", "Jetstar"), "VOZ": ("VA", "Virgin Australia"), "ANZ": ("NZ", "Air New Zealand"),
    "AMX": ("AM", "Aeromexico"), "VOI": ("Y4", "Volaris"),
    "TAM": ("JJ", "LATAM Brasil"), "LAN": ("LA", "LATAM"), "GLO": ("G3", "Gol"),
    "AZU": ("AD", "Azul"), "ARG": ("AR", "Aerolineas Argentinas"), "AVA": ("AV", "Avianca"),
    "CMP": ("CM", "Copa"), "ETH": ("ET", "Ethiopian"), "KQA": ("KQ", "Kenya Airways"),
    "SAA": ("SA", "South African"), "MAU": ("MK", "Air Mauritius"), "RAM": ("AT", "Royal Air Maroc"),
    "DLA": ("D0", "DHL"), "GEC": ("LH", "Lufthansa Cargo"), "FDX": ("FX", "FedEx"),
    "UPS": ("5X", "UPS"), "CLX": ("CV", "Cargolux"), "GTI": ("5Y", "Atlas Air"),
    "BOX": ("BX", "AeroLogic"), "ABW": ("RU", "AirBridgeCargo"),
}


def airline_from_callsign(cs):
    """Derive airline (ICAO+IATA+name) and the IATA flight number from a callsign.

    ADS-B callsigns are the ICAO airline designator + flight number ("RYR123").
    Returns {icao, iata, name, flight_icao, flight_iata} or None (e.g. for tail
    numbers like N12345, or unknown prefixes).
    """
    if not cs:
        return None
    s = cs.strip().upper()
    if len(s) < 3 or not s[:3].isalpha():
        return None
    pfx, rest = s[:3], s[3:].strip()
    info = AIRLINES.get(pfx)
    if not info:
        return None
    iata, name = info
    return {"icao": pfx, "iata": iata, "name": name, "flight_icao": s,
            "flight_iata": (iata + rest) if rest else iata}


# ICAO 24-bit address country blocks (start, end inclusive, hex) -> country.
# A trimmed set of the busiest allocations; the block also lets us pick the right
# tail-registration scheme. Ranges are the official ICAO assignments.
_ICAO_BLOCKS = [
    (0xA00000, 0xAFFFFF, "United States", "US"),
    (0xC00000, 0xC3FFFF, "Canada", "CA"),
    (0x400000, 0x43FFFF, "United Kingdom", "GB"),
    (0x3C0000, 0x3FFFFF, "Germany", "DE"),
    (0x380000, 0x3BFFFF, "France", "FR"),
    (0x300000, 0x33FFFF, "Italy", "IT"),
    (0x340000, 0x37FFFF, "Spain", "ES"),
    (0x480000, 0x4BFFFF, "Netherlands", "NL"),
    (0x4A0000, 0x4AFFFF, "Sweden", "SE"),
    (0x460000, 0x467FFF, "Finland", "FI"),
    (0x458000, 0x45FFFF, "Denmark", "DK"),
    (0x478000, 0x47FFFF, "Norway", "NO"),
    (0x440000, 0x447FFF, "Austria", "AT"),
    (0x4B0000, 0x4B7FFF, "Switzerland", "CH"),
    (0x448000, 0x44FFFF, "Belgium", "BE"),
    (0x490000, 0x497FFF, "Portugal", "PT"),
    (0x468000, 0x46FFFF, "Greece", "GR"),
    (0x500000, 0x5FFFFF, "Europe (other)", None),
    (0x140000, 0x1FFFFF, "Russia", "RU"),
    (0x4B8000, 0x4BFFFF, "Turkey", "TR"),
    (0x896000, 0x896FFF, "United Arab Emirates", "AE"),
    (0x760000, 0x767FFF, "India", "IN"),
    (0x780000, 0x7BFFFF, "China", "CN"),
    (0x840000, 0x87FFFF, "Japan", "JP"),
    (0x718000, 0x71FFFF, "South Korea", "KR"),
    (0x750000, 0x757FFF, "Singapore", "SG"),
    (0x8A0000, 0x8A7FFF, "Indonesia", "ID"),
    (0x7C0000, 0x7FFFFF, "Australia", "AU"),
    (0xC80000, 0xC87FFF, "New Zealand", "NZ"),
    (0x0A0000, 0x0A7FFF, "South Africa", "ZA"),
    (0xE00000, 0xE3FFFF, "Argentina/Brazil region", None),
    (0xE40000, 0xE7FFFF, "Brazil", "BR"),
    (0x0D0000, 0x0D7FFF, "Mexico", "MX"),
]

# US N-number decoder alphabet (no I or O — they look like 1/0).
_NCHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ"       # 24 letters used in registrations
_NALL = _NCHARS + "0123456789"             # last-position char set (34)
# Bucket sizes for the FAA N-number <-> ICAO base encoding (exact, canonical).
_NSUFFIX = len(_NCHARS) * len(_NCHARS) + len(_NCHARS) + 1     # 601  ("" + 24 + 576)
_NB4 = len(_NCHARS) + 10 + 1                                   # 35
_NB3 = _NB4 * 10 + _NSUFFIX                                    # 951
_NB2 = _NB3 * 10 + _NSUFFIX                                    # 10111
_NB1 = _NB2 * 10 + _NSUFFIX                                    # 101711


def _n_suffix(off):
    """One/two-letter (or blank) N-number suffix for a bucket offset 0.._NSUFFIX-1."""
    if off == 0:
        return ""
    off -= 1
    if off < len(_NCHARS):
        return _NCHARS[off]
    off -= len(_NCHARS)
    return _NCHARS[off // len(_NCHARS)] + _NCHARS[off % len(_NCHARS)]


def _icao_country(hexaddr):
    for lo, hi, name, cc in _ICAO_BLOCKS:
        if lo <= hexaddr <= hi:
            return name, cc
    return None, None


def _us_nnumber(addr):
    """US tail 'N-number' from an ICAO 24-bit address (algorithmic, exact).

    The FAA maps hex addresses to N-numbers by a fixed base encoding starting at
    0xA00001 = N1. Returns e.g. 'N172SP' / 'N1' / 'N100', or None outside the US
    block. Canonical bucket algorithm (matches the FAA registry).
    """
    if not (0xA00001 <= addr <= 0xADF7C7):
        return None
    off = addr - 0xA00001
    out = "N"
    d1 = off // _NB1
    r1 = off % _NB1
    out += str(d1 + 1)                 # digit1: 1..9
    if r1 < _NSUFFIX:
        return out + _n_suffix(r1)
    r1 -= _NSUFFIX
    out += str(r1 // _NB2)             # digit2: 0..9
    r2 = r1 % _NB2
    if r2 < _NSUFFIX:
        return out + _n_suffix(r2)
    r2 -= _NSUFFIX
    out += str(r2 // _NB3)             # digit3
    r3 = r2 % _NB3
    if r3 < _NSUFFIX:
        return out + _n_suffix(r3)
    r3 -= _NSUFFIX
    out += str(r3 // _NB4)             # digit4
    r4 = r3 % _NB4
    if r4 == 0:                        # digit5 position: nothing, a letter, or a digit
        return out
    return out + _NALL[r4 - 1]


def registration_from_icao(hexaddr):
    """Best-effort tail registration + country from an ICAO 24-bit hex address.

    Returns {country, country_code, tail} — tail is exact for US (N-numbers),
    None elsewhere (most countries aren't a simple algorithm), country covers the
    major allocations.
    """
    try:
        addr = int(str(hexaddr), 16)
    except (TypeError, ValueError):
        return None
    country, cc = _icao_country(addr)
    tail = _us_nnumber(addr) if cc == "US" else None
    if not country and tail is None:
        return None
    return {"country": country, "country_code": cc, "tail": tail}


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance in km (pure)."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def bearing_deg(lat1, lon1, lat2, lon2):
    """Initial bearing from point 1 to point 2, degrees 0-360 (pure)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


# --------------------------------------------------------------------------
# Live aircraft tracker (drives dump1090 + reads its SBS stream)
# --------------------------------------------------------------------------

class AdsbTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._reader = None
        self._stop = threading.Event()
        self._planes = {}          # icao -> record (+ _seen ts)
        self._error = None
        self._msgs = 0
        self._started = None

    def status(self):
        with self._lock:
            running = bool(self._reader and self._reader.is_alive())
            self._prune()
            return {"running": running, "aircraft": len(self._planes),
                    "messages": self._msgs, "error": self._error,
                    "since": self._started}

    def _prune(self):
        now = time.time()
        for icao in [k for k, v in self._planes.items() if now - v["_seen"] > _STALE_S]:
            del self._planes[icao]

    def aircraft(self):
        with self._lock:
            self._prune()
            now = time.time()
            out = []
            for r in self._planes.values():
                a = {k: v for k, v in r.items() if not k.startswith("_")}
                a["seen"] = round(now - r["_seen"], 1)
                al = airline_from_callsign(a.get("callsign"))
                if al:
                    a["airline"] = al["name"]
                    a["iata"] = al["iata"]
                    a["op_icao"] = al["icao"]
                    a["flight_iata"] = al["flight_iata"]
                reg = registration_from_icao(a.get("icao"))
                if reg:
                    if reg.get("tail"):
                        a["tail"] = reg["tail"]
                    if reg.get("country"):
                        a["country"] = reg["country"]
                        a["country_code"] = reg["country_code"]
                out.append(a)
            out.sort(key=lambda a: a.get("callsign") or a["icao"])
            return {"aircraft": out, "count": len(out), "messages": self._msgs,
                    "running": bool(self._reader and self._reader.is_alive()),
                    "error": self._error}

    def _ingest(self, rec):
        if not rec:
            return
        with self._lock:
            self._msgs += 1
            cur = self._planes.get(rec["icao"])
            if cur is None:
                if len(self._planes) >= _MAX_AIRCRAFT:
                    return
                cur = {"icao": rec["icao"]}
                self._planes[rec["icao"]] = cur
            for k, v in rec.items():
                cur[k] = v
            cur["_seen"] = time.time()

    def start(self):
        with self._lock:
            if self._reader and self._reader.is_alive():
                return {"ok": True, "already": True}
            dump = _dump_bin()
            if not dump:
                return {"ok": False, "error": "dump1090 not installed"}
            self._stop.clear()
            self._planes = {}
            self._msgs = 0
            self._error = None
            self._started = time.time()
            try:
                # --net turns on the SBS (30003) server; --quiet keeps stdout clean.
                self._proc = subprocess.Popen(
                    [dump, "--net", "--quiet"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            except Exception as exc:
                self._error = "failed to launch dump1090: %s" % exc
                return {"ok": False, "error": self._error}
            self._reader = threading.Thread(target=self._read_loop, daemon=True,
                                            name="adsb-sbs")
            self._reader.start()
        return {"ok": True}

    def _read_loop(self):
        # dump1090 needs a moment to open the device and bind :30003.
        sock = None
        deadline = time.time() + 15
        while not self._stop.is_set() and time.time() < deadline:
            try:
                sock = socket.create_connection((_SBS_HOST, _SBS_PORT), timeout=3)
                break
            except OSError:
                if self._proc and self._proc.poll() is not None:
                    self._error = "dump1090 exited (device busy? no RTL-SDR?)"
                    return
                time.sleep(0.5)
        if sock is None:
            self._error = "could not connect to dump1090 SBS port 30003"
            return
        sock.settimeout(1.0)
        buf = ""
        try:
            while not self._stop.is_set():
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                buf += data.decode("ascii", "replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    rec = parse_sbs(line)
                    if rec:
                        self._ingest(rec)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def stop(self):
        with self._lock:
            self._stop.set()
            if self._proc:
                try:
                    self._proc.terminate()
                    self._proc.wait(timeout=3)
                except Exception:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass
                self._proc = None
        return {"ok": True}


_tracker = AdsbTracker()


def start():
    return _tracker.start()


def stop():
    return _tracker.stop()


def status():
    st = _tracker.status()
    st["detect"] = detect()
    return st


def aircraft():
    return _tracker.aircraft()


def install():
    """One-click install of dump1090 for the radar's 'not installed' state.

    dump1090-fa lives only in FlightAware's apt repo and dump1090-mutability was
    dropped after Debian buster, so a plain ``apt install`` usually reports "can't
    find the package". We delegate to scripts/install_dump1090.sh, which tries apt
    first and then BUILDS FlightAware's dump1090 from source (self-contained, no
    third-party repo). Runs as the service user (root on Ragnar). This can take a
    couple of minutes on first build.
    """
    if _dump_bin():
        return {"ok": True, "already": True, "detect": detect()}
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "scripts", "install_dump1090.sh")
    if not os.path.exists(script):
        return {"ok": False, "error": "install_dump1090.sh missing (update Ragnar)",
                "detect": detect()}
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        p = subprocess.run(["bash", script], capture_output=True, text=True,
                           timeout=900, check=False, env=env)
        out = (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return {"ok": False, "error": "bash not found", "detect": detect()}
    except subprocess.TimeoutExpired:
        return {"ok": _dump_bin() is not None, "error": "install timed out (source build is slow — retry)",
                "detect": detect()}
    ok = _dump_bin() is not None
    tail = "\n".join((out or "").strip().splitlines()[-14:])
    return {"ok": ok, "output": tail, "detect": detect(),
            "error": None if ok else ("could not install dump1090 — apt has no package and the "
                                      "source build failed (needs internet + build tools). See output.")}


# --------------------------------------------------------------------------
# Selftest (pure parsers + geo, no hardware)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    # A position message (MSG,3) carries alt + lat/lon.
    pos = "MSG,3,1,1,4CA87C,1,2024/01/01,12:00:00.000,2024/01/01,12:00:00.000,,38000,,,53.3498,-6.2603,,,,,,0"
    r = parse_sbs(pos)
    check("sbs: MSG,3 -> icao+alt+lat+lon",
          r is not None and r["icao"] == "4CA87C" and r["alt"] == 38000
          and abs(r["lat"] - 53.3498) < 1e-4 and abs(r["lon"] + 6.2603) < 1e-4, str(r))
    # A callsign message (MSG,1) carries the flight id.
    ident = "MSG,1,1,1,4CA87C,1,2024/01/01,12:00:00.000,2024/01/01,12:00:00.000,RYR123 ,,,,,,,,,,,"
    ri = parse_sbs(ident)
    check("sbs: MSG,1 -> callsign", ri is not None and ri.get("callsign") == "RYR123", str(ri))
    # A velocity message (MSG,4) carries groundspeed + track + vertical rate.
    vel = "MSG,4,1,1,4CA87C,1,2024/01/01,12:00:00.000,2024/01/01,12:00:00.000,,,450,270,,,-64,,,,,"
    rv = parse_sbs(vel)
    check("sbs: MSG,4 -> gs+track+vert",
          rv is not None and rv["gs"] == 450 and rv["track"] == 270 and rv["vert"] == -64, str(rv))
    check("sbs: non-MSG / short lines -> None",
          parse_sbs("STA,,1,1,4CA87C,1,,,,,,,,,,,,,,,,") is None
          and parse_sbs("") is None and parse_sbs("garbage") is None)
    check("sbs: empty hexident rejected",
          parse_sbs("MSG,3,1,1,,1,,,,,,38000,,,53.3,-6.2,,,,,,0") is None)

    # Table merge: fields from different message types accumulate on one icao.
    t = AdsbTracker()
    t._ingest(parse_sbs(pos)); t._ingest(parse_sbs(ident)); t._ingest(parse_sbs(vel))
    ac = t.aircraft()
    check("track: one aircraft, merged fields",
          ac["count"] == 1 and ac["aircraft"][0]["callsign"] == "RYR123"
          and ac["aircraft"][0]["alt"] == 38000 and ac["aircraft"][0]["gs"] == 450, str(ac))
    check("track: message counter", ac["messages"] == 3)

    # Airline code derivation: ICAO callsign prefix -> IATA + name + flight nums.
    al = airline_from_callsign("RYR123")
    check("airline: RYR123 -> Ryanair FR / FR123",
          al and al["iata"] == "FR" and al["name"] == "Ryanair"
          and al["flight_iata"] == "FR123" and al["flight_icao"] == "RYR123", str(al))
    check("airline: unknown prefix + tail numbers -> None",
          airline_from_callsign("ZZZ99") is None and airline_from_callsign("N12345") is None
          and airline_from_callsign("") is None)
    ac2 = AdsbTracker()
    ac2._ingest(parse_sbs(ident))   # RYR123
    a0 = ac2.aircraft()["aircraft"][0]
    check("airline: aircraft record carries iata + airline + flight_iata",
          a0.get("iata") == "FR" and a0.get("airline") == "Ryanair" and a0.get("flight_iata") == "FR123", str(a0))

    # Tail registration + country from ICAO 24-bit address.
    check("reg: 0xA00001 -> N1 (US block start)",
          (registration_from_icao("A00001") or {}).get("tail") == "N1",
          str(registration_from_icao("A00001")))
    r_us = registration_from_icao("A12345")
    check("reg: US hex -> N-number + United States",
          r_us and r_us["country"] == "United States" and r_us["tail"]
          and r_us["tail"].startswith("N"), str(r_us))
    r_gb = registration_from_icao("400123")
    check("reg: UK hex -> United Kingdom, no algorithmic tail",
          r_gb and r_gb["country"] == "United Kingdom" and r_gb["tail"] is None, str(r_gb))
    check("reg: unknown/garbage hex -> None",
          registration_from_icao("ZZZZZZ") is None and registration_from_icao(None) is None)
    ac3 = AdsbTracker()
    ac3._ingest(parse_sbs("MSG,3,1,1,A12345,1,,,,,,38000,,,40.0,-74.0,,,,,,0"))
    a3 = ac3.aircraft()["aircraft"][0]
    check("reg: aircraft record carries tail + country",
          a3.get("tail", "").startswith("N") and a3.get("country") == "United States", str(a3))

    # Geo helpers: Dublin -> London ~ 464 km, bearing ~ 118 deg.
    d = haversine_km(53.3498, -6.2603, 51.5074, -0.1278)
    b = bearing_deg(53.3498, -6.2603, 51.5074, -0.1278)
    check("geo: haversine Dublin-London ~464 km", abs(d - 464) < 15, "%.1f" % d)
    check("geo: bearing Dublin-London ~118 deg", abs(b - 118) < 8, "%.1f" % b)

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


def _main(argv):
    cmd = argv[1] if len(argv) > 1 else "detect"
    if cmd == "detect":
        import json
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
        secs = 20
        if "--seconds" in argv:
            secs = int(argv[argv.index("--seconds") + 1])
        print(start())
        t0 = time.time()
        try:
            while time.time() - t0 < secs:
                time.sleep(2)
                a = aircraft()
                print("aircraft=%d messages=%d" % (a["count"], a["messages"]))
        finally:
            stop()
    else:
        print("usage: adsb.py [detect|run|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
