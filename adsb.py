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

import json
import math
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request


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


# Airline cross-reference: ICAO 3-letter designator -> (IATA 2-letter, name).
# ICAO and IATA are DIFFERENT organisations with independent, unrelated code
# systems — there's no formula between them, so this is a lookup table, not a
# derivation. ADS-B callsigns carry the ICAO airline designator (e.g. "RYR123");
# we look up the matching IATA code + name here. A curated set of the busiest
# carriers worldwide; unknown prefixes just fall back to the raw callsign.
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
    # --- extended coverage: more mainline, low-cost, regional & cargo ---
    "RPA": ("YX", "Republic Airways"), "EDV": ("9E", "Endeavor Air"),
    "ENY": ("MQ", "Envoy Air"), "ASH": ("YV", "Mesa Airlines"),
    "PDT": ("PT", "Piedmont"), "JIA": ("OH", "PSA Airlines"), "QXE": ("QX", "Horizon Air"),
    "GJS": ("ZW", "GoJet"), "UCA": ("C5", "CommutAir"),
    "SCX": ("SY", "Sun Country"), "AWI": ("ZW", "Air Wisconsin"),
    "TSC": ("TS", "Air Transat"), "FLE": ("F8", "Flair Airlines"), "SWG": ("WG", "Sunwing"),
    "POE": ("PD", "Porter Airlines"), "WEN": ("WR", "WestJet Encore"),
    "CFG": ("DE", "Condor"), "TUI": ("X3", "TUI fly"), "SXS": ("XQ", "SunExpress"),
    "EJA": ("1I", "NetJets"), "VOE": ("V7", "Volotea"),
    "BTI": ("BT", "airBaltic"), "LGL": ("LG", "Luxair"),
    "CTN": ("OU", "Croatia Airlines"), "ROT": ("RO", "TAROM"),
    "DAH": ("AH", "Air Algerie"), "TAR": ("TU", "Tunisair"), "AMC": ("KM", "Air Malta"),
    "CYP": ("CY", "Cyprus Airways"), "MEA": ("ME", "Middle East Airlines"),
    "IRA": ("IR", "Iran Air"), "IAW": ("IA", "Iraqi Airways"),
    "UZB": ("HY", "Uzbekistan Airways"), "AZG": ("7L", "Silk Way West"),
    "KZR": ("KC", "Air Astana"), "JZR": ("J9", "Jazeera Airways"),
    "FAD": ("F3", "flyadeal"), "XAX": ("D7", "AirAsia X"), "BKP": ("PG", "Bangkok Airways"),
    "AKJ": ("QP", "Akasa Air"), "SEJ": ("SG", "SpiceJet"),
    "CQH": ("9C", "Spring Airlines"), "CHH": ("HU", "Hainan Airlines"),
    "CXA": ("MF", "XiamenAir"), "CSC": ("3U", "Sichuan Airlines"), "CDG": ("SC", "Shandong"),
    "CSZ": ("ZH", "Shenzhen Airlines"), "HKE": ("UO", "HK Express"),
    "CRK": ("HX", "Hong Kong Airlines"), "SKY": ("BC", "Skymark"), "SNJ": ("6J", "Solaseed"),
    "APJ": ("MM", "Peach"), "JJP": ("GK", "Jetstar Japan"),
    "TWB": ("TW", "T'way Air"), "JNA": ("LJ", "Jin Air"), "ABL": ("BX", "Air Busan"),
    "ESR": ("ZE", "Eastar Jet"), "SLK": ("MI", "SilkAir"), "TGW": ("TR", "Scoot"),
    "LNI": ("JT", "Lion Air"), "CTV": ("QG", "Citilink"), "BTK": ("ID", "Batik Air"),
    "CEB": ("5J", "Cebu Pacific"), "ALK": ("UL", "SriLankan"),
    "BBC": ("BG", "Biman Bangladesh"), "PIA": ("PK", "Pakistan Intl"),
    "RXA": ("ZL", "Rex"), "FJI": ("FJ", "Fiji Airways"), "ANG": ("PX", "Air Niugini"),
    "TAI": ("TA", "TACA/Avianca"), "ONE": ("O6", "Avianca Brasil"),
    "VIV": ("VB", "VivaAerobus"), "SKU": ("H2", "Sky Airline"),
    "RWD": ("WB", "RwandAir"), "MSC": ("SM", "Air Cairo"), "NOS": ("NO", "Neos"),
    "LAM": ("TM", "LAM Mozambique"), "CXI": ("XC", "Corendon"),
    "WUK": ("W9", "Wizz Air UK"), "WMT": ("8Z", "Wizz Air Malta"),
    "FHY": ("FH", "Freebird"), "OHY": ("8Q", "Onur Air"),
    "CKS": ("K4", "Kalitta Air"), "PAC": ("PO", "Polar Air Cargo"),
    "NCA": ("KZ", "Nippon Cargo"), "TAY": ("3V", "ASL Airlines"),
}


def airline_from_callsign(cs):
    """Look up the airline (ICAO designator, IATA code, name) + IATA flight no.

    ADS-B callsigns are the ICAO airline designator + flight number ("RYR123").
    The IATA code is a separate code system, so it comes from the AIRLINES
    cross-reference table (not computed from ICAO). Returns
    {icao, iata, name, flight_icao, flight_iata} or None (e.g. tail numbers like
    N12345, or an ICAO designator not in the table).
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
# Flight-route enrichment (callsign -> origin/destination airports)
#
# ADS-B carries the live position but NOT the filed route, so the origin and
# destination airports come from a lookup keyed on the callsign. We use
# adsbdb.com (free, no API key) and cache every answer to data/adsb_routes.json
# so repeat sightings are instant and known routes still render with no
# connectivity. The live position/track never need the network; only the first
# look-up of a given callsign does. Look-ups are on-demand (when the operator
# clicks an aircraft), not a background poll, to stay light on the free service.
# --------------------------------------------------------------------------

_ADSBDB_BASE = "https://api.adsbdb.com/v0"
_ROUTE_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "data", "adsb_routes.json")
_ROUTE_TTL = 12 * 3600          # a callsign's route is a per-day fact (callsigns
                                # are reused across legs) — a stored copy older
                                # than ~half a day is suspect; refetch when online.
                                # Past this we still serve the cache OFFLINE only.
_ROUTE_NEG_TTL = 6 * 3600       # retry "unknown" callsigns after a while
_HTTP_TIMEOUT = 6
_route_lock = threading.Lock()
_route_cache = None             # lazy-loaded {callsign: {route, fetched}}


def _airport_from_adsbdb(d):
    """Normalize one adsbdb airport object to our compact shape (pure)."""
    if not isinstance(d, dict):
        return None
    try:
        lat = float(d.get("latitude"))
        lon = float(d.get("longitude"))
    except (TypeError, ValueError):
        return None
    return {"iata": d.get("iata_code") or "", "icao": d.get("icao_code") or "",
            "name": d.get("name") or "", "municipality": d.get("municipality") or "",
            "country": d.get("country_name") or "", "lat": lat, "lon": lon}


def parse_adsbdb_route(payload):
    """Parse an adsbdb /v0/callsign response into a normalized route (pure).

    Returns {callsign, callsign_iata, origin, destination} with origin/destination
    each a compact airport dict, or None when the callsign is unknown or the
    payload lacks both endpoints. Never raises on malformed input.
    """
    if not isinstance(payload, dict):
        return None
    resp = payload.get("response")
    if not isinstance(resp, dict):
        return None                      # "unknown callsign" comes back as a string
    fr = resp.get("flightroute")
    if not isinstance(fr, dict):
        return None
    origin = _airport_from_adsbdb(fr.get("origin"))
    dest = _airport_from_adsbdb(fr.get("destination"))
    if not origin and not dest:
        return None
    return {"callsign": fr.get("callsign") or fr.get("callsign_icao") or "",
            "callsign_iata": fr.get("callsign_iata") or "",
            "origin": origin, "destination": dest}


def great_circle_points(lat1, lon1, lat2, lon2, n=48):
    """Sample n points along the great circle from 1 to 2 (pure).

    Spherical interpolation so a long route draws as the true curved arc a plane
    flies, not a straight line on the map. Returns [[lat, lon], ...].
    """
    n = max(2, int(n))
    p1, l1 = math.radians(lat1), math.radians(lon1)
    p2, l2 = math.radians(lat2), math.radians(lon2)
    d = 2 * math.asin(min(1.0, math.sqrt(
        math.sin((p2 - p1) / 2) ** 2
        + math.cos(p1) * math.cos(p2) * math.sin((l2 - l1) / 2) ** 2)))
    if d == 0:
        return [[lat1, lon1], [lat2, lon2]]
    out = []
    for i in range(n):
        f = i / (n - 1)
        a = math.sin((1 - f) * d) / math.sin(d)
        b = math.sin(f * d) / math.sin(d)
        x = a * math.cos(p1) * math.cos(l1) + b * math.cos(p2) * math.cos(l2)
        y = a * math.cos(p1) * math.sin(l1) + b * math.cos(p2) * math.sin(l2)
        z = a * math.sin(p1) + b * math.sin(p2)
        out.append([math.degrees(math.atan2(z, math.sqrt(x * x + y * y))),
                    math.degrees(math.atan2(y, x))])
    return out


def route_progress(route_rec, lat, lon, gs=None):
    """Great-circle geometry + progress for a route given the live position (pure).

    progress is flown / (flown + remaining) — robust to a plane slightly off the
    filed track or past the destination. eta_min uses ground speed (knots) when
    supplied. Returns None unless both endpoints are known.
    """
    if not route_rec:
        return None
    o, d = route_rec.get("origin"), route_rec.get("destination")
    if not (o and d):
        return None
    total = haversine_km(o["lat"], o["lon"], d["lat"], d["lon"])
    out = {"total_km": round(total, 1),
           "arc": great_circle_points(o["lat"], o["lon"], d["lat"], d["lon"])}
    if lat is not None and lon is not None:
        flown = haversine_km(o["lat"], o["lon"], lat, lon)
        remaining = haversine_km(lat, lon, d["lat"], d["lon"])
        denom = flown + remaining
        out["flown_km"] = round(flown, 1)
        out["remaining_km"] = round(remaining, 1)
        out["progress"] = round(flown / denom, 3) if denom > 0 else 0.0
        try:
            g = float(gs)
            if g > 20:
                out["eta_min"] = round(remaining / (g * 1.852) * 60)
        except (TypeError, ValueError):
            pass
    return out


def _bearing(lat1, lon1, lat2, lon2):
    """Initial great-circle bearing from point 1 to point 2, degrees 0-360."""
    a1, b1, a2, b2 = map(math.radians, (lat1, lon1, lat2, lon2))
    dl = b2 - b1
    y = math.sin(dl) * math.cos(a2)
    x = math.cos(a1) * math.sin(a2) - math.sin(a1) * math.cos(a2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0


def _ang_diff(a, b):
    """Smallest absolute angle between two bearings (0-180 degrees)."""
    d = abs(a - b) % 360.0
    return d if d <= 180.0 else 360.0 - d


def route_live_match(route_rec, lat, lon, track):
    """Sanity-check a *filed* route against the aircraft's REAL live heading.

    adsbdb keys routes on callsign, which is the *scheduled* route. But a callsign
    is reused across legs/days, so the live aircraft flying it right now may be on
    a different (or the return) leg — adsbdb then hands back a confidently-wrong
    destination. We already have the live position + track, so we can catch this:
    if the plane is well en-route yet heading *away* from the filed destination,
    the route is almost certainly stale.

    Returns None when it can't judge (missing data, or too close to the
    destination where approach turns make heading unreliable); otherwise
    {"ok": bool, "delta": deg} where delta is |track − bearing-to-destination|.
    """
    if not route_rec or lat is None or lon is None or track is None:
        return None
    d = route_rec.get("destination")
    if not (d and d.get("lat") is not None and d.get("lon") is not None):
        return None
    # Within ~60 km of the destination the aircraft may be turning onto approach;
    # heading is no longer a reliable "am I going there" signal.
    if haversine_km(lat, lon, d["lat"], d["lon"]) < 60:
        return None
    delta = _ang_diff(float(track), _bearing(lat, lon, d["lat"], d["lon"]))
    # >100 deg off = flying away from the filed destination -> stale route.
    return {"ok": delta <= 100.0, "delta": round(delta)}


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
        self._connected = False    # SBS socket connected to dump1090
        self._sbs_lines = 0        # raw lines received on 30003 (reception proof)
        self._stderr_tail = ""     # last bit of dump1090 stderr (device errors)

    def _diag(self):
        """A human hint distinguishing 'no reception' from a real fault."""
        if not (self._reader and self._reader.is_alive()):
            return None
        if not self._connected:
            return "starting dump1090 / connecting to SBS 30003…"
        elapsed = time.time() - (self._started or time.time())
        if self._sbs_lines == 0:
            if elapsed > 15:
                return ("dump1090 running but no 1090 MHz messages — check the "
                        "antenna (needs a 1090 MHz / ADS-B antenna), placement, and "
                        "that aircraft are overhead")
            return "listening for aircraft…"
        return None

    def status(self):
        with self._lock:
            running = bool(self._reader and self._reader.is_alive())
            self._prune()
            return {"running": running, "aircraft": len(self._planes),
                    "messages": self._msgs, "sbs_lines": self._sbs_lines,
                    "connected": self._connected, "error": self._error,
                    "hint": self._diag(),
                    "stderr": (self._stderr_tail or "").strip()[-300:],
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
                    "sbs_lines": self._sbs_lines, "connected": self._connected,
                    "hint": self._diag(),
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
            self._connected = False
            self._sbs_lines = 0
            self._stderr_tail = ""
            self._started = time.time()
            # --net enables the SBS BaseStation server; force its port to 30003
            # explicitly so it doesn't matter what a given fork defaults to.
            # (No --quiet: not all forks accept it, and stdout is discarded anyway.)
            # Force MAX tuner gain: ADS-B is weak/bursty and dump1090's default
            # varies by fork (some use AGC, which is worse here). 49.6 dB is the
            # top R820T2/R860 step; PPM correction from the shared tuner config.
            ppm = 0
            gain = None
            try:
                import rtl_sdr
                _t = rtl_sdr.get_tuning()
                ppm = _t.get("ppm", 0) or 0
                gain = None if _t.get("gain_is_auto") else _t.get("gain")
            except Exception:
                pass
            cmd = [dump, "--net", "--net-sbs-port", str(_SBS_PORT),
                   "--gain", (str(gain) if gain is not None else "49.6")]
            if ppm:
                cmd += ["--ppm", str(ppm)]
            try:
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            except Exception as exc:
                self._error = "failed to launch dump1090: %s" % exc
                return {"ok": False, "error": self._error}
            # Drain stderr so dump1090 can't block on a full pipe, and keep a tail
            # for diagnostics (device-open errors, gain warnings).
            threading.Thread(target=self._drain_stderr, daemon=True,
                             name="adsb-stderr").start()
            self._reader = threading.Thread(target=self._read_loop, daemon=True,
                                            name="adsb-sbs")
            self._reader.start()
        return {"ok": True}

    def _drain_stderr(self):  # pragma: no cover - hardware path
        proc = self._proc
        if not (proc and proc.stderr):
            return
        try:
            for line in proc.stderr:
                if self._stop.is_set():
                    break
                with self._lock:
                    self._stderr_tail = (self._stderr_tail + line)[-1000:]
        except Exception:
            pass

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
                    tail = (self._stderr_tail or "").strip().splitlines()
                    self._error = ("dump1090 exited (device busy / held by another "
                                   "capture, or no RTL-SDR)"
                                   + (" — " + tail[-1] if tail else ""))
                    return
                time.sleep(0.5)
        if sock is None:
            self._error = ("could not connect to dump1090 SBS port 30003"
                           + (" — " + self._stderr_tail.strip().splitlines()[-1]
                              if self._stderr_tail.strip() else ""))
            return
        with self._lock:
            self._connected = True
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
                    if line.strip():
                        with self._lock:
                            self._sbs_lines += 1   # reception proof (any SBS line)
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
    d = _tracker.aircraft()
    enrich_types(d.get("aircraft") or [])       # fill ICAO type (A320/B738) from adsb.lol, cached
    return d


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
# Route look-up + cache (stateful; the only part that touches the network)
# --------------------------------------------------------------------------

def _route_cache_get():
    global _route_cache
    if _route_cache is None:
        try:
            with open(_ROUTE_CACHE, "r") as f:
                _route_cache = json.load(f)
            if not isinstance(_route_cache, dict):
                _route_cache = {}
        except (OSError, ValueError):
            _route_cache = {}
    return _route_cache


def _route_cache_put(cs, entry):
    with _route_lock:
        cache = _route_cache_get()
        cache[cs] = entry
        try:
            os.makedirs(os.path.dirname(_ROUTE_CACHE), exist_ok=True)
            tmp = _ROUTE_CACHE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(cache, f)
            os.replace(tmp, _ROUTE_CACHE)
        except OSError:
            pass


def _adsbdb_fetch(cs):
    """Query adsbdb for a callsign; return a parsed route or None (network)."""
    url = "%s/callsign/%s" % (_ADSBDB_BASE, urllib.parse.quote(cs))
    req = urllib.request.Request(url, headers={"User-Agent": "Ragnar-ADSB/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as r:
            payload = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None                      # offline / 404 / timeout -> just no route
    return parse_adsbdb_route(payload)


def _cache_route(entry):
    """Shape a cache entry into a returnable route tagged source='cache' (pure)."""
    r = dict(entry["route"])
    r["source"], r["fetched"] = "cache", entry.get("fetched", 0)
    return r


def route_lookup(callsign, use_network=True, prefer_fresh=False):
    """Resolve a callsign to its filed route, cache-first (see module note).

    Returns {origin, destination, ..., source, fetched} or None. A fresh-enough
    cache hit is served without touching the network; a miss (or a stale entry)
    consults adsbdb when use_network, and the answer is cached — including a
    short-lived negative so unknown callsigns aren't re-hammered.

    prefer_fresh forces a network refresh even when a cache entry is still within
    TTL. Use it for a live/clicked aircraft: adsbdb keys routes on the callsign
    (a per-day fact — callsigns are reused across legs), so a stored copy can name
    a confidently-wrong destination; a live click should reflect the network's
    current answer, with the cache kept only as the offline/failure fallback.
    """
    if not callsign:
        return None
    cs = str(callsign).strip().upper()
    if not cs:
        return None
    now = time.time()
    with _route_lock:
        entry = _route_cache_get().get(cs)
    # Serve a fresh-enough cache hit unless the caller asked for a live refresh.
    if entry and not (prefer_fresh and use_network):
        age = now - entry.get("fetched", 0)
        if entry.get("route") and age < _ROUTE_TTL:
            return _cache_route(entry)
        if not entry.get("route") and age < _ROUTE_NEG_TTL:
            return None                  # cached "unknown", still fresh
    if not use_network:
        # Offline: fall back to whatever we have, even past TTL — a stale route
        # still draws, and is honestly tagged source='cache'.
        return _cache_route(entry) if (entry and entry.get("route")) else None
    fetched = _adsbdb_fetch(cs)
    if fetched:
        _route_cache_put(cs, {"route": fetched, "fetched": now})
        r = dict(fetched)
        r["source"], r["fetched"] = "adsbdb", now
        return r
    # Network fetch failed. Prefer a cached route (even stale) so the map still
    # draws; only record a fresh negative when we have nothing to fall back on
    # (never clobber a good cached route with a transient failure).
    if entry and entry.get("route"):
        return _cache_route(entry)
    _route_cache_put(cs, {"route": None, "fetched": now})
    return None


def route(callsign, lat=None, lon=None, gs=None, use_network=True, track=None):
    """Public: filed route + live progress for a callsign (drives the map view)."""
    # A live position means this is a clicked/tracked aircraft — get adsbdb's
    # current answer, not a possibly-stale stored copy (cache is the fallback).
    prefer_fresh = lat is not None and lon is not None
    r = route_lookup(callsign, use_network=use_network, prefer_fresh=prefer_fresh)
    cs = (callsign or "").strip().upper()
    if not r:
        return {"callsign": cs, "route": None, "progress": None}
    return {"callsign": r.get("callsign") or cs, "route": r,
            "route_match": route_live_match(r, lat, lon, track),
            "progress": route_progress(r, lat, lon, gs)}


# --------------------------------------------------------------------------
# Live global feed (adsb.lol) — real positions + aircraft TYPE
#
# ADS-B doesn't broadcast the aircraft type (A320/B738), and a local receiver
# only sees its own bubble. adsb.lol is a free, no-key global aggregator whose
# live records carry lat/lon/alt/gs/track PLUS the ICAO type ('t') and
# registration ('r'). We use it three ways: to fill the **type** column for our
# own (dump1090) contacts, to place a clicked flight at its **real** live
# position on the route map (so the marker matches reality), and — when there is
# no SDR but there is internet (demo) — to show the **real** aircraft near you.
# --------------------------------------------------------------------------

_ADSBLOL_BASE = "https://api.adsb.lol/v2/"
_TYPE_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "data", "adsb_types.json")
_TYPE_NEG_TTL = 900            # retry a hex whose type we couldn't resolve
_type_cache = None
_type_pending = set()
_type_lock = threading.Lock()
_type_worker_started = False


def _fnum(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_adsblol_ac(a):
    """Normalize one adsb.lol aircraft record to our contact shape (pure)."""
    if not isinstance(a, dict):
        return None
    hexid = (a.get("hex") or "").strip().upper().lstrip("~")
    if not hexid:
        return None
    alt = a.get("alt_baro")
    if alt == "ground":
        alt = 0
    cs = (a.get("flight") or "").strip() or None
    return {"icao": hexid, "callsign": cs, "lat": _fnum(a.get("lat")),
            "lon": _fnum(a.get("lon")), "alt": _fnum(alt), "gs": _fnum(a.get("gs")),
            "track": _fnum(a.get("track")), "type": (a.get("t") or None),
            "tail": (a.get("r") or None), "seen": _fnum(a.get("seen")) or 0}


def _adsblol_get(path):
    req = urllib.request.Request(_ADSBLOL_BASE + path,
                                 headers={"User-Agent": "Ragnar-ADSB/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def live_lookup(hexid, callsign=None):
    """Real live record for one aircraft from adsb.lol (by hex, then callsign)."""
    d = _adsblol_get("hex/%s" % urllib.parse.quote((hexid or "").strip())) if hexid else None
    ac = (d or {}).get("ac") or []
    if not ac and callsign:
        d = _adsblol_get("callsign/%s" % urllib.parse.quote(callsign.strip()))
        ac = (d or {}).get("ac") or []
    return parse_adsblol_ac(ac[0]) if ac else None


def nearby(lat, lon, dist_nm=60):
    """Real aircraft near a point (adsb.lol) — the demo/no-SDR live feed."""
    la, lo = _fnum(lat), _fnum(lon)
    if la is None or lo is None:
        return {"aircraft": [], "error": "need lat/lon", "running": False}
    dn = max(1, min(int(_fnum(dist_nm) or 60), 250))
    d = _adsblol_get("lat/%s/lon/%s/dist/%d" % (la, lo, dn))
    if d is None:
        return {"aircraft": [], "error": "adsb.lol unreachable (offline?)",
                "source": "adsb.lol", "running": False}
    out = []
    for a in (d.get("ac") or []):
        r = parse_adsblol_ac(a)
        if not r or r["lat"] is None:
            continue
        al = airline_from_callsign(r.get("callsign"))
        if al:
            r["airline"] = al["name"]; r["iata"] = al["iata"]
            r["op_icao"] = al["icao"]; r["flight_iata"] = al["flight_iata"]
        if not r.get("tail"):
            reg = registration_from_icao(r["icao"])
            if reg and reg.get("tail"):
                r["tail"] = reg["tail"]
        out.append(r)
    out.sort(key=lambda a: a.get("callsign") or a["icao"])
    return {"aircraft": out, "count": len(out), "source": "adsb.lol", "running": True}


def flight(hexid, callsign, lat=None, lon=None, gs=None, use_network=True):
    """Filed route (adsbdb) + REAL live position/type (adsb.lol) + progress.

    Progress and the map marker use adsb.lol's authoritative live position when
    available (so the plane matches reality), falling back to the position the
    caller passed (our own receiver).
    """
    cs = (callsign or "").strip().upper()
    # Clicked live aircraft: prefer adsbdb's current answer over a stored copy.
    r = route_lookup(cs, use_network=use_network, prefer_fresh=use_network) if cs else None
    live = live_lookup(hexid, cs) if use_network else None
    plat = live["lat"] if (live and live.get("lat") is not None) else lat
    plon = live["lon"] if (live and live.get("lon") is not None) else lon
    pgs = live["gs"] if (live and live.get("gs") is not None) else gs
    ptrk = live.get("track") if live else None
    ac = None
    if live and (live.get("type") or live.get("tail")):
        ac = {"type": live.get("type"), "tail": live.get("tail")}
    return {"callsign": (r or {}).get("callsign") or cs, "route": r, "live": live,
            "aircraft": ac, "route_match": route_live_match(r, plat, plon, ptrk),
            "progress": route_progress(r, plat, plon, pgs) if r else None}


# NOTE: IP geolocation was removed on purpose. It could put the receiver hundreds
# of km from its true position (ISPs register address ranges centrally), which
# silently plotted aircraft at the wrong place. Receiver location now comes only
# from GPS or manual entry; with neither, the radar self-centers on the aircraft
# it actually receives (they are all within radio range) — see the web UI.


# ---- aircraft-type enrichment for our own contacts (background, cached) ----

def _type_cache_get():
    global _type_cache
    if _type_cache is None:
        try:
            with open(_TYPE_CACHE) as f:
                _type_cache = json.load(f)
            if not isinstance(_type_cache, dict):
                _type_cache = {}
        except (OSError, ValueError):
            _type_cache = {}
    return _type_cache


def _type_cache_save():
    try:
        os.makedirs(os.path.dirname(_TYPE_CACHE), exist_ok=True)
        tmp = _TYPE_CACHE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_type_cache, f)
        os.replace(tmp, _TYPE_CACHE)
    except OSError:
        pass


def _type_worker():
    while True:
        hexid = None
        with _type_lock:
            if _type_pending:
                hexid = _type_pending.pop()
        if not hexid:
            time.sleep(0.5); continue
        live = live_lookup(hexid)
        with _type_lock:
            _type_cache_get()[hexid] = {"type": (live or {}).get("type"),
                                        "tail": (live or {}).get("tail"), "t": time.time()}
            _type_cache_save()
        time.sleep(0.8)                # rate-limit — be nice to the free service


def _ensure_type_worker():
    global _type_worker_started
    if not _type_worker_started:
        _type_worker_started = True
        threading.Thread(target=_type_worker, daemon=True).start()


def enrich_types(aclist):
    """Attach cached ICAO type (+tail) to contacts; queue unknowns for lookup."""
    if not aclist:
        return aclist
    _ensure_type_worker()
    cache = _type_cache_get()
    now = time.time()
    for a in aclist:
        h = a.get("icao")
        if not h:
            continue
        e = cache.get(h)
        if e:
            if e.get("type") and not a.get("type"):
                a["type"] = e["type"]
            if e.get("tail") and not a.get("tail"):
                a["tail"] = e["tail"]
            if e.get("type") or (now - e.get("t", 0) < _TYPE_NEG_TTL):
                continue              # resolved, or a fresh "unknown" — don't re-queue
        with _type_lock:
            if len(_type_pending) < 300:
                _type_pending.add(h)
    return aclist


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

    # Airline cross-reference: ICAO callsign designator -> IATA + name (lookup).
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

    # Route enrichment: parse an adsbdb payload (pure, no network).
    sample = {"response": {"flightroute": {
        "callsign": "RYR123", "callsign_iata": "FR123",
        "origin": {"iata_code": "DUB", "icao_code": "EIDW", "name": "Dublin",
                   "country_name": "Ireland", "latitude": 53.4213, "longitude": -6.2701},
        "destination": {"iata_code": "STN", "icao_code": "EGSS", "name": "Stansted",
                        "country_name": "United Kingdom", "latitude": 51.885, "longitude": 0.235}}}}
    pr = parse_adsbdb_route(sample)
    check("route: adsbdb payload -> DUB->STN",
          pr and pr["origin"]["iata"] == "DUB" and pr["destination"]["icao"] == "EGSS"
          and abs(pr["origin"]["lat"] - 53.4213) < 1e-3, str(pr))
    check("route: unknown/garbage payload -> None",
          parse_adsbdb_route({"response": "unknown callsign"}) is None
          and parse_adsbdb_route({}) is None and parse_adsbdb_route(None) is None)
    # Great-circle midpoint of the route reads ~50% flown.
    mid = great_circle_points(pr["origin"]["lat"], pr["origin"]["lon"],
                              pr["destination"]["lat"], pr["destination"]["lon"], 3)[1]
    prog = route_progress(pr, mid[0], mid[1], gs=420)
    check("route: midpoint progress ~0.5",
          prog and abs(prog["progress"] - 0.5) < 0.05 and prog.get("eta_min", 0) > 0, str(prog))
    check("route: great-circle arc keeps its endpoints",
          len(prog["arc"]) >= 2
          and abs(prog["arc"][0][0] - pr["origin"]["lat"]) < 1e-6
          and abs(prog["arc"][-1][0] - pr["destination"]["lat"]) < 1e-6, str(prog["arc"][:1]))
    # Offline path: no cache + no network -> None, and never raises.
    check("route: lookup offline w/o cache -> None",
          route_lookup("ZZZRAGNARTEST", use_network=False) is None)

    # adsb.lol live record -> our contact shape (pure), incl. ICAO type.
    la = parse_adsblol_ac({"hex": "48c2b2", "flight": "RYR7VK  ", "t": "B38M",
                           "r": "SP-RZT", "lat": 51.39, "lon": -1.05, "alt_baro": 27925,
                           "gs": 471.8, "track": 95})
    check("live: adsb.lol ac -> icao/callsign/type/pos",
          la and la["icao"] == "48C2B2" and la["callsign"] == "RYR7VK"
          and la["type"] == "B38M" and la["tail"] == "SP-RZT"
          and abs(la["lat"] - 51.39) < 1e-6 and la["alt"] == 27925, str(la))
    check("live: adsb.lol 'ground' alt -> 0, empty/garbage -> None",
          parse_adsblol_ac({"hex": "abc", "alt_baro": "ground"})["alt"] == 0
          and parse_adsblol_ac({"hex": ""}) is None and parse_adsblol_ac(None) is None)

    # bearing/angle helpers (pure geometry).
    check("bearing: due north / due east",
          abs(_bearing(0, 0, 1, 0) - 0) < 1 and abs(_bearing(0, 0, 0, 1) - 90) < 1)
    check("ang_diff: wraps across 0/360",
          _ang_diff(350, 10) == 20 and _ang_diff(10, 350) == 20 and _ang_diff(0, 180) == 180)
    # route_live_match: a plane heading AT vs AWAY from the filed destination.
    # dest far north (lat 60); track 0 (north) agrees, track 180 (south) is stale.
    rr = {"destination": {"lat": 60.0, "lon": 10.0}}
    mok = route_live_match(rr, 50.0, 10.0, 0)
    mbad = route_live_match(rr, 50.0, 10.0, 180)
    check("route_match: heading toward dest -> ok, away -> stale",
          mok and mok["ok"] is True and mbad and mbad["ok"] is False, str((mok, mbad)))
    check("route_match: None when near dest or missing track/data",
          route_live_match(rr, 59.9, 10.0, 180) is None      # within 60km of dest
          and route_live_match(rr, 50.0, 10.0, None) is None
          and route_live_match(None, 50.0, 10.0, 0) is None)

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
    elif cmd == "route":
        cs = argv[2] if len(argv) > 2 else ""
        if not cs:
            print("usage: adsb.py route <CALLSIGN>   (e.g. RYR123)")
            return 1
        print(json.dumps(route(cs), indent=2))
    elif cmd == "flight":
        print(json.dumps(flight(argv[2] if len(argv) > 2 else None,
                                argv[3] if len(argv) > 3 else None), indent=2))
    elif cmd == "nearby":
        print(json.dumps(nearby(argv[2] if len(argv) > 2 else None,
                                argv[3] if len(argv) > 3 else None,
                                argv[4] if len(argv) > 4 else 60), indent=2))
    else:
        print("usage: adsb.py [detect|run|selftest|route <CS>|flight <HEX> <CS>|nearby <lat> <lon> [nm]]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
