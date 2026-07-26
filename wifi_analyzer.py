#!/usr/bin/env python3
"""
wifi_analyzer.py — Passive tri-band Wi-Fi spectrum analyzer & troubleshooter.

A software "Ekahau Sidekick"-style RF troubleshooter for Ragnar. Everything here
is *strictly passive*: we only ever run ``iw dev <iface> scan -u passive`` which
listens for beacons and never transmits a probe request to any AP, and we read
the radio's channel table with ``iw phy``. No frame is ever injected. (``-u``
only changes how results are *printed* — iw hex-dumps IEs it can't decode,
which is how Wi-Fi 7 EHT IEs are recognised until iw grows an EHT printer.)

Capabilities
------------
* Tri-band survey (2.4 / 5 / 6 GHz) of every beaconing BSS: SSID, BSSID, RSSI
  (dBm), primary channel + band, channel width (20/40/80/160/320 MHz from the
  HT/VHT/HE/EHT operation IEs), security, and the AP-advertised **channel
  utilisation** (BSS-Load IE) which is a real, passive interference metric.
* Spectrum / congestion analysis: co-channel and adjacent-channel (overlap)
  interference, the classic 2.4 GHz 1/6/11 crowding picture, and a per-channel
  congestion score with "least congested channel" recommendations.
* DFS / radar awareness: the set of radar/DFS channels is read *live* from the
  radio's own channel table (``iw phy <phy> channels``) rather than hardcoded,
  and any BSS parked on a radar channel is flagged.
* Signal-radius estimate for a chosen AP using a log-distance path-loss model,
  producing coverage-ring radii (VoIP / data / edge thresholds) plus an estimate
  of your current distance from the AP — the data the web UI draws as rings.
* Heatmap sample store: drop (x, y, rssi) samples on a floorplan; the web layer
  interpolates (IDW) them into a coverage heatmap.

Tuned for the Alfa AWUS036AXM (MediaTek MT7921AU, ``mt7921u`` driver — a Wi-Fi
6E 2.4/5/6 GHz dongle) on a Raspberry Pi Zero 2 W, but band support is detected
per-radio from ``iw phy`` so it also runs on the Pi's onboard brcmfmac radio.

CLI
---
    python3 wifi_analyzer.py interfaces
    python3 wifi_analyzer.py scan [--interface wlan0] [--band 2.4|5|6|all]
    python3 wifi_analyzer.py radius --interface wlan0 --bssid <mac>
    python3 wifi_analyzer.py selftest
"""

import json
import math
import os
import re
import subprocess
import sys
import time

# --------------------------------------------------------------------------
# Constants / tunables
# --------------------------------------------------------------------------

_IW = "/usr/sbin/iw"
if not os.path.exists(_IW):
    _IW = "iw"  # fall back to PATH

_SCAN_TIMEOUT = 20          # seconds; a passive scan of all channels is slow
_HEATMAP_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "wifi_heatmap.json"
)
_SURVEYS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "wifi_surveys.json"
)

# Coverage thresholds (dBm) used for the signal-radius rings.
_RADIUS_THRESHOLDS = [
    ("voice", -67, "VoIP / seamless roaming"),
    ("data", -72, "reliable data / video"),
    ("edge", -80, "usable edge of coverage"),
]

# Default path-loss model parameters (overridable per request).
_DEFAULT_TX_DBM = 20.0      # assumed AP EIRP; consumer APs are ~17-23 dBm
_DEFAULT_PLE = 3.0          # path-loss exponent: 2.0 free space, ~3.0 indoor
# Plausible AP conducted/EIRP transmit power. Anything outside this window in the
# advertised TPC report is a misconfigured/garbage value (some APs advertise e.g.
# 63 dBm ≈ 2 kW) and must NOT be trusted as "measured" — it wrecks the range model.
_TX_PLAUSIBLE_MIN = 0.0
_TX_PLAUSIBLE_MAX = 36.0    # 36 dBm EIRP = outdoor standard-power ceiling (6 GHz)

# 2.4 GHz channels overlap unless spaced >= 5 apart (1/6/11 are the non-overlap set).
_NON_OVERLAP_24 = [1, 6, 11]


# --------------------------------------------------------------------------
# iw plumbing
# --------------------------------------------------------------------------

def _run(args, timeout=_SCAN_TIMEOUT):
    """Run an iw command, returning (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "iw not found"
    except subprocess.TimeoutExpired:
        return 124, "", "iw timed out"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


def _valid_iface(iface):
    return bool(iface) and re.match(r"^[A-Za-z0-9_.-]{1,32}$", iface) is not None


def _valid_bssid(mac):
    return bool(mac) and re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac or "") is not None


def _iface_is_up(iface):
    """True if the interface's admin state is up (has IFF_UP flag)."""
    try:
        with open("/sys/class/net/%s/flags" % iface) as f:
            return bool(int(f.read().strip(), 16) & 0x1)  # IFF_UP
    except Exception:
        return True  # assume up if we can't tell; don't block on it


def _bring_iface_up(iface):
    """Bring the link up (needed to scan a freshly-plugged, DOWN dongle).

    Non-destructive: only sets the link admin-up, never associates. Requires
    root; the webapp runs as root so this succeeds in production.
    """
    _run(["/usr/bin/rfkill", "unblock", "all"], timeout=5)
    rc, _, _ = _run(["ip", "link", "set", iface, "up"], timeout=5)
    return rc == 0


# --------------------------------------------------------------------------
# Frequency <-> channel <-> band
# --------------------------------------------------------------------------

def freq_to_channel(freq_mhz):
    """Return (band, channel) for a centre frequency in MHz. band in {'2.4','5','6'}."""
    f = int(round(float(freq_mhz)))
    if f == 2484:
        return "2.4", 14
    if 2400 <= f < 2500:
        return "2.4", (f - 2407) // 5
    if f == 5935:
        return "6", 2
    if f >= 5925:
        return "6", (f - 5950) // 5
    if 5000 <= f < 5925:
        return "5", (f - 5000) // 5
    # Below 5 GHz but not 2.4 (shouldn't happen for Wi-Fi) -> best effort
    return "5", (f - 5000) // 5


def channel_to_freq(channel, band):
    """Inverse of freq_to_channel for a primary/centre channel number."""
    ch = int(channel)
    if band == "2.4":
        return 2484 if ch == 14 else 2407 + ch * 5
    if band == "6":
        return 5935 if ch == 2 else 5950 + ch * 5
    return 5000 + ch * 5


# --------------------------------------------------------------------------
# Radio capability / DFS map  (iw phy <phy> channels)
# --------------------------------------------------------------------------

def _phy_for_iface(iface):
    rc, out, _ = _run([_IW, "dev"], timeout=5)
    if rc != 0:
        return None
    cur_phy = None
    for line in out.splitlines():
        m = re.match(r"^(phy#\d+)", line)
        if m:
            cur_phy = m.group(1).replace("#", "")
            continue
        m = re.match(r"^\s*Interface\s+(\S+)", line)
        if m and m.group(1) == iface:
            return cur_phy
    return None


def radio_capabilities(iface):
    """Parse ``iw phy <phy> channels`` into supported bands + DFS/radar channel set.

    Returns dict: {phy, bands: {'2.4':[chans], '5':[...], '6':[...]},
                   radar_channels: {band: set(ch)}, disabled: {band: set(ch)}}.
    """
    phy = _phy_for_iface(iface)
    caps = {
        "phy": phy,
        "bands": {"2.4": [], "5": [], "6": []},
        "radar_channels": {"2.4": set(), "5": set(), "6": set()},
        "disabled": {"2.4": set(), "5": set(), "6": set()},
    }
    if not phy:
        return caps
    rc, out, _ = _run([_IW, "phy", phy, "channels"], timeout=8)
    if rc != 0:
        return caps
    cur = None  # (band, ch, disabled)
    for raw in out.splitlines():
        m = re.search(r"\*\s*(\d+)\s*MHz\s*\[(\d+)\]\s*(\(disabled\))?", raw)
        if m:
            if cur:
                _commit_channel(caps, cur)
            band, ch = freq_to_channel(int(m.group(1)))
            cur = {"band": band, "ch": ch, "disabled": bool(m.group(3)), "radar": False}
            continue
        if cur and re.search(r"[Rr]adar detection", raw):
            cur["radar"] = True
    if cur:
        _commit_channel(caps, cur)
    for b in caps["bands"]:
        caps["bands"][b] = sorted(set(caps["bands"][b]))
    # Band *support* is more reliably read from `iw phy info`, which lists every
    # frequency the radio can do regardless of whether the interface is up or a
    # channel is regulatory-disabled. This keeps the band labels correct for a
    # freshly-plugged, still-down dongle (channels would otherwise be empty).
    rc2, info, _ = _run([_IW, "phy", phy, "info"], timeout=8)
    if rc2 == 0:
        for m in re.finditer(r"\*\s*(\d+)(?:\.\d+)?\s*MHz\s*\[(\d+)\]", info):
            band, ch = freq_to_channel(int(m.group(1)))
            if band in caps["bands"] and ch not in caps["bands"][band]:
                caps["bands"][band].append(ch)
        for b in caps["bands"]:
            caps["bands"][b] = sorted(set(caps["bands"][b]))
    return caps


def _commit_channel(caps, cur):
    band, ch = cur["band"], cur["ch"]
    if band not in caps["bands"]:
        return
    if not cur["disabled"]:
        caps["bands"][band].append(ch)
    else:
        caps["disabled"][band].add(ch)
    if cur["radar"]:
        caps["radar_channels"][band].add(ch)


def _sysfs_wifi_interfaces():
    """Every wireless netdev in /sys/class/net (nl80211 *and* wext dongles)."""
    names = set()
    try:
        for name in os.listdir("/sys/class/net/"):
            base = "/sys/class/net/" + name
            if os.path.exists(base + "/wireless") or os.path.exists(base + "/phy80211"):
                names.add(name)
    except Exception:
        pass
    return names


def list_wifi_interfaces():
    """Return [{iface, phy, type, bands:[...]}] for every wireless interface.

    Interfaces are enumerated from BOTH ``iw dev`` (nl80211) and
    ``/sys/class/net`` so a dongle still shows up if it reports an unusual
    interface type or uses a wext-only driver that ``iw dev`` doesn't list.
    We deliberately do NOT filter by interface type — the only entries ``iw
    dev`` omits from a name are the "Unnamed/non-netdev" P2P-device stanzas,
    which never carry an ``Interface <name>`` line in the first place.
    """
    by_name = {}
    order = []
    rc, out, _ = _run([_IW, "dev"], timeout=5)
    if rc == 0:
        cur_phy = None
        cur = None
        for line in out.splitlines():
            m = re.match(r"^(phy#\d+)", line)
            if m:
                cur_phy = m.group(1).replace("#", "")
                continue
            m = re.match(r"^\s*Interface\s+(\S+)", line)
            if m:
                cur = {"iface": m.group(1), "phy": cur_phy, "type": None, "bands": []}
                by_name[cur["iface"]] = cur
                order.append(cur["iface"])
                continue
            if cur:
                mt = re.match(r"^\s*type\s+(\S+)", line)
                if mt:
                    cur["type"] = mt.group(1)
    # Union with sysfs so wext-only / oddly-typed dongles are never hidden.
    for name in sorted(_sysfs_wifi_interfaces()):
        if name not in by_name:
            entry = {"iface": name, "phy": _phy_for_iface(name), "type": None, "bands": []}
            by_name[name] = entry
            order.append(name)
    ifaces = [by_name[n] for n in order]
    for i in ifaces:
        caps = radio_capabilities(i["iface"])
        i["bands"] = [b for b in ("2.4", "5", "6") if caps["bands"].get(b)]
    return ifaces


# --------------------------------------------------------------------------
# Channel-width extraction from an iw scan BSS block
# --------------------------------------------------------------------------

def _parse_width(block):
    """Return (width_mhz, center_channel_or_None) from HT/VHT/HE operation lines."""
    width = 20
    center_ch = None

    # VHT operation: 'channel width: N (X MHz)' + 'center freq segment 1: C'
    mv = re.search(r"VHT operation:.*?channel width:\s*(\d+)", block, re.S)
    if mv:
        code = int(mv.group(1))
        if code == 1:
            width = max(width, 80)
        elif code in (2, 3):
            width = max(width, 160)
        mc = re.search(r"center freq segment 1:\s*(\d+)", block)
        if mc and int(mc.group(1)) > 0:
            center_ch = int(mc.group(1))

    # HE operation (802.11ax / 6 GHz): look for an explicit MHz width token
    if re.search(r"HE operation", block):
        for w in (320, 160, 80, 40):
            if re.search(r"HE operation.*?(\b%d MHz\b|channel width:\s*%d)" % (w, w),
                         block, re.S):
                width = max(width, w)
                break
        mhe = re.search(r"HE operation.*?(?:center freq|centre freq|channel center).*?(\d+)",
                        block, re.S)
        if mhe and center_ch is None and int(mhe.group(1)) > 0:
            center_ch = int(mhe.group(1))

    # HT operation: secondary channel offset above/below => 40 MHz
    mh = re.search(r"secondary channel offset:\s*(above|below)", block)
    if mh and width < 40:
        width = 40

    # EHT Operation as a raw -u hex dump (iw <= 6.9 can't decode ext ID 106):
    # byte0 = params (bit0: operation-info present), bytes1-4 = basic MCS/NSS,
    # byte5 = control (bits0-2: width code, 4 => 320 MHz), byte6/7 = CCFS0/1.
    meht = re.search(r"Unknown Extension ID \(106\):((?:\s+[0-9a-f]{2})+)",
                     block, re.I)
    if meht:
        b = [int(x, 16) for x in meht.group(1).split()]
        if len(b) >= 8 and (b[0] & 0x01):
            w = {0: 20, 1: 40, 2: 80, 3: 160, 4: 320}.get(b[5] & 0x07)
            if w:
                width = max(width, w)
            # CCFS1 is the wide-channel centre for 160/320; CCFS0 otherwise.
            cc = b[7] if (w or 0) >= 160 and b[7] else b[6]
            if cc:
                center_ch = cc

    # Explicit 'channel width: N (X MHz)' operation lines from any IE. Must be
    # anchored to a channel-width line: capability blocks contain width tokens
    # too ('short GI (80 MHz)') that say nothing about the operating width.
    for w in (320, 160, 80, 40):
        if re.search(r"channel width:[^\n]*\(%d MHz\)" % w, block):
            width = max(width, w)
            break
    return width, center_ch


# --------------------------------------------------------------------------
# Per-AP enrichment  (802.11 generation, streams, vendor, security, roaming …)
# --------------------------------------------------------------------------

# Vendor OUI lookup: prefer the system IEEE/nmap databases, fall back to a small
# curated map of common Wi-Fi AP makers. Loaded once, lazily.
_OUI_CACHE = None
_OUI_FALLBACK = {
    "00:0b:86": "Aruba", "6c:f3:7f": "Aruba", "d8:c7:c8": "Aruba",
    "00:1a:1e": "Aruba", "00:24:6c": "Aruba",
    "00:0c:29": "VMware", "00:1b:0c": "Cisco", "00:1e:14": "Cisco",
    "00:1e:bd": "Cisco", "58:97:bd": "Cisco", "e0:cb:bc": "Cisco",
    "00:18:0a": "Meraki", "88:15:44": "Meraki", "e0:55:3d": "Meraki",
    "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti", "fc:ec:da": "Ubiquiti",
    "68:d7:9a": "Ubiquiti", "b4:fb:e4": "Ubiquiti", "e0:63:da": "Ubiquiti",
    "00:13:92": "Ruckus", "c0:c5:20": "Ruckus", "2c:c5:d3": "Ruckus",
    "00:24:b2": "Netgear", "a0:40:a0": "Netgear", "b0:7f:b9": "Netgear",
    "50:c7:bf": "TP-Link", "00:25:86": "TP-Link", "60:32:b1": "TP-Link",
    "4c:5e:0c": "TP-Link", "c4:6e:1f": "TP-Link",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "24:0a:c4": "Espressif", "a4:cf:12": "Espressif", "7c:9e:bd": "Espressif",
    "3c:71:bf": "Espressif", "84:0d:8e": "Espressif",
    "00:03:93": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
    "00:09:5b": "Netgear", "48:8f:5a": "Mikrotik", "cc:2d:e0": "Mikrotik",
    "dc:2c:6e": "Mikrotik", "18:fd:74": "Mikrotik", "d4:ca:6d": "Mikrotik",
}
_OUI_FILES = ("/usr/share/nmap/nmap-mac-prefixes",
              "/usr/share/ieee-data/oui.txt")


def _load_oui():
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE
    table = {}
    # nmap format: "AABBCC Vendor Name" (one per line).
    try:
        with open("/usr/share/nmap/nmap-mac-prefixes") as f:
            for line in f:
                if line.startswith("#") or len(line) < 8:
                    continue
                pfx, _, name = line.partition(" ")
                if len(pfx) == 6:
                    table[pfx.lower()] = name.strip()
    except Exception:
        pass
    # IEEE oui.txt fallback: "AA-BB-CC   (hex)\t\tVendor".
    if not table:
        try:
            with open("/usr/share/ieee-data/oui.txt") as f:
                for line in f:
                    m = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})"
                                 r"\s+\(hex\)\s+(.+)$", line)
                    if m:
                        table[(m.group(1) + m.group(2) + m.group(3)).lower()] = m.group(4).strip()
        except Exception:
            pass
    if not table:
        table = {k.replace(":", ""): v for k, v in _OUI_FALLBACK.items()}
    _OUI_CACHE = table
    return table


def _oui_lookup(bssid):
    """Vendor for a BSSID, or 'Randomized' for a locally-administered MAC."""
    if not bssid or len(bssid) < 8:
        return None
    try:
        first = int(bssid[:2], 16)
    except ValueError:
        return None
    if first & 0x02:                       # locally-administered bit
        return "Randomized/private"
    pfx = bssid.replace(":", "")[:6].lower()
    return _load_oui().get(pfx) or _OUI_FALLBACK.get(bssid[:8])


def _parse_generation(block, band):
    """(standard label, phy_mode) from the capability IEs present.

    EHT is matched two ways: the decoded section headers (future iw versions)
    and the raw extension IDs a -u scan exposes when iw can't decode them —
    106 = EHT Operation, 107 = Multi-Link, 108 = EHT Capabilities."""
    if (re.search(r"\bEHT (capabilities|Operation)", block, re.I)
            or re.search(r"Unknown Extension ID \((?:106|107|108)\)", block)):
        return ("Wi-Fi 7", "be")
    if re.search(r"\bHE (capabilities|operation)", block):
        return ("Wi-Fi 6E" if band == "6" else "Wi-Fi 6", "ax")
    if "VHT capabilities" in block or "VHT Capabilities" in block:
        return ("Wi-Fi 5", "ac")
    if "HT capabilities" in block:
        return ("Wi-Fi 4", "n")
    return ("legacy", "abg")


def _parse_nss(block):
    """Best-effort spatial-stream count from MCS/NSS sets."""
    nss = None
    # VHT/HE print 'N streams: MCS 0-9' — the highest supported N is the NSS.
    streams = [int(m.group(1)) for m in
               re.finditer(r"(\d+) streams: MCS", block)]
    if streams:
        nss = max(streams)
    # HT: 'HT RX MCS rate indexes supported: 0-31' -> (31+1)/8 streams.
    mh = re.search(r"HT RX MCS rate indexes supported:\s*0-(\d+)", block)
    if mh:
        nss = max(nss or 0, (int(mh.group(1)) + 1) // 8)
    return nss or None


# Approximate top PHY rate (Mbps) per spatial stream at 20 MHz, short-GI, top MCS.
_PHY_BASE = {"n": 72.2, "ac": 86.7, "ax": 143.4, "be": 172.1, "abg": 54.0}
_WIDTH_MULT = {20: 1.0, 40: 2.08, 80: 4.5, 160: 9.0, 320: 18.0}


def _estimate_max_phy(phy_mode, width, nss):
    """Rough 'up to' PHY rate — width x streams x per-stream base. Estimate only."""
    if not nss:
        return None
    base = _PHY_BASE.get(phy_mode)
    if base is None:
        return None
    return int(round(base * _WIDTH_MULT.get(width, 1.0) * nss))


def _parse_security(block, hdr):
    """Detailed security posture: mode, AKM, PMF, enterprise, WPS."""
    has_rsn = "RSN:" in block
    has_wpa = "WPA:" in block
    privacy = "Privacy" in (hdr or "")
    akms = ""
    m = re.search(r"Authentication suites:\s*(.+)", block)
    if m:
        akms = m.group(1)
    sae = "SAE" in akms
    owe = "OWE" in akms
    dot1x = "802.1X" in akms or "8021X" in akms.replace(".", "").replace(" ", "")
    ft = "FT/" in akms or "FT over" in block or "Mobility Domain" in block
    enterprise = dot1x
    # PMF / 802.11w
    if re.search(r"MFP-required", block):
        pmf = "required"
    elif re.search(r"MFP-capable", block):
        pmf = "capable"
    else:
        pmf = "disabled"
    # Mode label
    if owe:
        mode = "OWE"
    elif sae and has_rsn:
        mode = "WPA3-Enterprise" if enterprise else "WPA3"
    elif has_rsn:
        mode = "WPA2-Enterprise" if enterprise else "WPA2"
    elif has_wpa:
        mode = "WPA"
    elif privacy:
        mode = "WEP"
    else:
        mode = "Open"
    wps = "WPS:" in block
    wps_ver = None
    if wps:
        mv = re.search(r"WPS:\s*\*\s*Version:\s*([\d.]+)", block)
        wps_ver = mv.group(1) if mv else None
    return {
        "security": mode,
        "akm": akms.strip() or None,
        "pmf": pmf,
        "enterprise": enterprise,
        "wps": wps,
        "wps_version": wps_ver,
        "ft": ft,
    }


def _security_findings(bss):
    """Weak-posture flags for one AP (list of short strings)."""
    out = []
    sec = bss.get("security")
    if sec == "Open":
        out.append("open (no encryption)")
    elif sec == "WEP":
        out.append("WEP (broken)")
    elif sec == "WPA":
        out.append("WPA/TKIP (legacy)")
    if bss.get("wps"):
        out.append("WPS enabled")
    if bss.get("pmf") == "disabled" and sec not in ("Open", "WEP", None):
        out.append("PMF off (deauth-exposed)")
    return out


def _parse_roaming(block):
    """802.11k / v / r assisted-roaming support."""
    k = "RM enabled capabilities" in block
    v = "BSS Transition" in block
    r = ("Mobility Domain" in block) or ("FT/" in block) or ("FT over" in block)
    return {"k": k, "v": v, "r": r}


def _enrich(block, hdr, bss):
    """Attach the enterprise-grade fields to a parsed BSS dict (in place)."""
    band = bss["band"]
    bss["vendor"] = _oui_lookup(bss["bssid"])
    bss["standard"], phy = _parse_generation(block, band)
    bss["phy_mode"] = phy
    bss["nss"] = _parse_nss(block)
    bss["max_phy_mbps"] = _estimate_max_phy(phy, bss.get("width", 20), bss["nss"])
    sec = _parse_security(block, hdr)
    bss.update(sec)
    bss["security_findings"] = _security_findings(bss)
    bss["roaming"] = _parse_roaming(block)
    m = re.search(r"TPC report: TX power:\s*(-?\d+)", block)
    _tx = int(m.group(1)) if m else None
    # Only trust the advertised TX power if it's physically plausible; some APs
    # advertise garbage (e.g. 63 dBm) which would blow up the coverage model.
    if _tx is not None and not (_TX_PLAUSIBLE_MIN <= _tx <= _TX_PLAUSIBLE_MAX):
        _tx = None
    bss["tx_power_dbm"] = _tx
    m = re.search(r"Country:\s*([A-Z]{2})", block)
    bss["country"] = m.group(1) if m else None
    m = re.search(r"beacon interval:\s*(\d+)", block)
    bss["beacon_interval"] = int(m.group(1)) if m else None
    m = re.search(r"DTIM Period\s*(\d+)", block)
    bss["dtim"] = int(m.group(1)) if m else None
    return bss


# --------------------------------------------------------------------------
# iw scan parser
# --------------------------------------------------------------------------

_BSS_HDR = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})\b(.*)$")


def parse_scan(text):
    """Parse ``iw scan`` output into a list of BSS dicts.

    Pure function (no I/O) so it is unit-testable against captured output.
    """
    blocks = []
    cur = None
    for line in text.splitlines():
        m = _BSS_HDR.match(line)
        if m:
            if cur is not None:
                blocks.append(cur)
            cur = {"bssid": m.group(1).lower(), "_hdr": m.group(2), "_lines": []}
            continue
        if cur is not None:
            cur["_lines"].append(line)
    if cur is not None:
        blocks.append(cur)

    results = []
    for b in blocks:
        block = "\n".join(b["_lines"])
        bss = {"bssid": b["bssid"]}

        m = re.search(r"^\s*freq:\s*([\d.]+)", block, re.M)
        if not m:
            continue
        freq = float(m.group(1))
        band, channel = freq_to_channel(freq)
        bss["freq"] = freq
        bss["band"] = band
        bss["channel"] = channel

        m = re.search(r"^\s*signal:\s*(-?[\d.]+)\s*dBm", block, re.M)
        bss["signal"] = round(float(m.group(1)), 1) if m else None

        m = re.search(r"^[ \t]*SSID:[ \t]*(.*)$", block, re.M)
        ssid = m.group(1) if m else ""
        # Strip nul-padded / whitespace SSIDs; hidden APs advertise empty/\x00
        ssid = ssid.replace("\\x00", "").strip()
        bss["ssid"] = ssid
        bss["hidden"] = ssid == ""

        width, center_ch = _parse_width(block)
        bss["width"] = width
        if center_ch:
            bss["center_freq"] = channel_to_freq(center_ch, band)
        else:
            bss["center_freq"] = freq

        # BSS-Load IE: the AP's own advertised medium utilisation + client count.
        m = re.search(r"channel util[il]s?ation:\s*(\d+)/255", block)
        bss["channel_util"] = round(int(m.group(1)) / 255.0 * 100.0, 1) if m else None
        m = re.search(r"station count:\s*(\d+)", block)
        bss["stations"] = int(m.group(1)) if m else None

        m = re.search(r"last seen:\s*(\d+)\s*ms ago", block)
        bss["last_seen_ms"] = int(m.group(1)) if m else None

        # Enterprise enrichment: generation, streams, vendor, security depth,
        # roaming (11k/v/r), tx-power, country, DTIM.
        _enrich(block, b["_hdr"], bss)

        results.append(bss)
    return results


# --------------------------------------------------------------------------
# Spectrum / interference analysis
# --------------------------------------------------------------------------

def _channels_covered(channel, width, band, center_freq=None):
    """Set of 20 MHz channel indices a BSS occupies given its width.

    For 5/6 GHz the occupied 20 MHz sub-channels are centred on the operating
    *centre* frequency (the primary channel is only one edge of a wide channel),
    so we walk 20 MHz steps across [centre - width/2, centre + width/2].
    """
    if band == "2.4":
        # 2.4 GHz channels overlap; model +/- (width/2) MHz spread in freq.
        span = width // 2
        prim = channel_to_freq(channel, band)
        chans = set()
        for f in range(int(prim - span), int(prim + span) + 1, 5):
            _, c = freq_to_channel(f)
            if 1 <= c <= 14:
                chans.add(c)
        return chans
    n = max(1, width // 20)
    c = center_freq if center_freq else channel_to_freq(channel, band)
    first = c - (width / 2.0) + 10  # centre of the lowest 20 MHz sub-channel
    chans = set()
    for i in range(n):
        _, ch = freq_to_channel(first + i * 20)
        chans.add(ch)
    return chans


def analyze_spectrum(bss_list, caps=None):
    """Build per-band congestion picture + channel recommendations."""
    caps = caps or {"radar_channels": {"2.4": set(), "5": set(), "6": set()}}
    radar = caps.get("radar_channels", {})
    out = {}
    for band in ("2.4", "5", "6"):
        aps = [b for b in bss_list if b["band"] == band]
        if not aps:
            continue
        # occupancy[ch] = list of (rssi, is_primary)
        occupancy = {}
        for ap in aps:
            covered = _channels_covered(ap["channel"], ap["width"], band,
                                        ap.get("center_freq"))
            for ch in covered:
                occupancy.setdefault(ch, []).append(
                    (ap.get("signal"), ch == ap["channel"], ap.get("channel_util"))
                )
        channels = []
        for ch in sorted(occupancy):
            entries = occupancy[ch]
            signals = [s for s, _p, _u in entries if s is not None]
            utils = [u for _s, _p, u in entries if u is not None]
            primaries = sum(1 for _s, p, _u in entries if p)
            # Congestion score: co-channel APs weighted by relative power +
            # advertised utilisation. Higher = worse.
            score = 0.0
            for s, is_primary, _u in entries:
                w = 1.0 if is_primary else 0.5  # overlap counts half of co-channel
                # louder neighbours hurt more; map -30..-90 dBm -> 1.0..0.1
                if s is not None:
                    w *= max(0.1, min(1.0, (s + 95) / 65.0))
                score += w
            if utils:
                score += (sum(utils) / len(utils)) / 100.0 * 2.0
            channels.append({
                "channel": ch,
                "ap_count": len(entries),
                "primary_count": primaries,
                "max_signal": max(signals) if signals else None,
                "avg_util": round(sum(utils) / len(utils), 1) if utils else None,
                "score": round(score, 2),
                "radar": ch in radar.get(band, set()),
            })
        # Recommendations: least-congested channels (for 2.4, restrict to 1/6/11)
        candidates = channels
        if band == "2.4":
            cand = [c for c in channels if c["channel"] in _NON_OVERLAP_24]
            # include unused 1/6/11 as zero-score candidates
            seen = {c["channel"] for c in cand}
            for ch in _NON_OVERLAP_24:
                if ch not in seen:
                    cand.append({"channel": ch, "ap_count": 0, "score": 0.0,
                                 "radar": False, "max_signal": None,
                                 "avg_util": None, "primary_count": 0})
            candidates = cand
        recommend = sorted(candidates, key=lambda c: (c["score"], c["ap_count"]))[:3]
        # Overall band rating
        prim_aps = len(aps)
        total_score = sum(c["score"] for c in channels)
        if total_score < 3:
            rating = "clear"
        elif total_score < 8:
            rating = "moderate"
        else:
            rating = "congested"
        # Width advice: dense bands should narrow their channels so more
        # non-overlapping channels exist; empty bands can go wide.
        if band == "2.4":
            width_advice = (20, "2.4 GHz only has 3 non-overlapping channels — "
                                "use 20 MHz and stick to 1/6/11")
        else:
            avg_w = sum(a["width"] for a in aps) / len(aps)
            if prim_aps >= 12:
                width_advice = (40, "dense band — 40 MHz keeps enough clear "
                                    "channels")
            elif prim_aps >= 6:
                width_advice = (80, "80 MHz is a good balance here")
            else:
                width_advice = (160, "few APs — 160 MHz is viable for peak speed")
            width_advice = (width_advice[0],
                            width_advice[1] + f" (APs average {int(avg_w)} MHz now)")
        out[band] = {
            "ap_count": prim_aps,
            "channels": channels,
            "recommend": [c["channel"] for c in recommend],
            "rating": rating,
            "score": round(total_score, 2),
            "width_advice": {"mhz": width_advice[0], "reason": width_advice[1]},
        }
    return out


def _mac_prefix(bssid, octets=5):
    return ":".join(bssid.split(":")[:octets])


def group_aps(bss_list):
    """Collapse the flat BSS list into two enterprise views:

    * **networks** — one entry per SSID (an ESS): how many BSSIDs serve it,
      which bands it spans, its security/best signal. The "how many APs is this
      network on" view.
    * **devices** — physical radios: BSSIDs that share their top-5 MAC octets
      (an enterprise AP hands out consecutive BSSIDs per SSID/band) collapsed
      into one logical AP.
    """
    networks = {}
    for a in bss_list:
        if a.get("hidden") or not a.get("ssid"):
            continue
        n = networks.setdefault(a["ssid"], {
            "ssid": a["ssid"], "bssids": [], "bands": set(),
            "security": a.get("security"), "best_signal": None,
            "vendor": a.get("vendor"), "standard": a.get("standard")})
        n["bssids"].append(a["bssid"])
        n["bands"].add(a["band"])
        if a.get("signal") is not None and (n["best_signal"] is None
                                            or a["signal"] > n["best_signal"]):
            n["best_signal"] = a["signal"]
    net_list = []
    for n in networks.values():
        n["bands"] = sorted(n["bands"])
        n["ap_count"] = len(n["bssids"])
        net_list.append(n)
    net_list.sort(key=lambda n: -(n["best_signal"] or -999))

    devices = {}
    for a in bss_list:
        key = _mac_prefix(a["bssid"])
        d = devices.setdefault(key, {
            "mac_prefix": key, "bssids": [], "ssids": set(), "bands": set(),
            "vendor": a.get("vendor"), "best_signal": None})
        d["bssids"].append(a["bssid"])
        if a.get("ssid"):
            d["ssids"].add(a["ssid"])
        d["bands"].add(a["band"])
        if a.get("signal") is not None and (d["best_signal"] is None
                                            or a["signal"] > d["best_signal"]):
            d["best_signal"] = a["signal"]
    dev_list = []
    for d in devices.values():
        d["ssids"] = sorted(d["ssids"])
        d["bands"] = sorted(d["bands"])
        d["radio_count"] = len(d["bssids"])
        dev_list.append(d)
    dev_list.sort(key=lambda d: -(d["best_signal"] or -999))

    return {
        "networks": net_list,
        "network_count": len(net_list),
        "devices": dev_list,
        "device_count": len(dev_list),
    }


def find_interference(bss_list):
    """Return co-channel and adjacent-channel (overlap) interference groups."""
    co = {}
    for ap in bss_list:
        key = (ap["band"], ap["channel"])
        co.setdefault(key, []).append(ap)
    co_channel = []
    for (band, ch), aps in co.items():
        if len(aps) >= 2:
            co_channel.append({
                "band": band, "channel": ch,
                "ssids": sorted({a["ssid"] or "<hidden>" for a in aps}),
                "count": len(aps),
            })
    # Adjacent/overlap (mainly a 2.4 GHz problem)
    overlap = []
    aps24 = [a for a in bss_list if a["band"] == "2.4"]
    for i, a in enumerate(aps24):
        acov = _channels_covered(a["channel"], a["width"], "2.4", a.get("center_freq"))
        for b in aps24[i + 1:]:
            if a["channel"] == b["channel"]:
                continue
            bcov = _channels_covered(b["channel"], b["width"], "2.4", b.get("center_freq"))
            if acov & bcov:
                overlap.append({
                    "band": "2.4",
                    "a": {"ssid": a["ssid"] or "<hidden>", "channel": a["channel"]},
                    "b": {"ssid": b["ssid"] or "<hidden>", "channel": b["channel"]},
                })
    return {"co_channel": sorted(co_channel, key=lambda x: -x["count"]),
            "adjacent_overlap": overlap}


# --------------------------------------------------------------------------
# Signal-radius estimate (log-distance path-loss model)
# --------------------------------------------------------------------------

def _rssi_at_1m(freq_mhz, tx_dbm):
    """Reference RSSI at 1 m = TxPower - free-space path loss at 1 m."""
    fspl_1m = 20 * math.log10(freq_mhz) - 27.55  # d=1m => 20log10(1)=0
    return tx_dbm - fspl_1m


def calibrate_ple(d1, rssi1, d2, rssi2):
    """Two-point calibration of the log-distance model.

    Given two measured (distance_m, RSSI) points, solve for the path-loss
    exponent and the reference RSSI at 1 m so the model matches *this* site/
    adapter rather than a textbook assumption.
        rssi = rssi0 - 10*n*log10(d)
        n    = (rssi1 - rssi2) / (10 * (log10(d2) - log10(d1)))
        rssi0 = rssi1 + 10*n*log10(d1)
    """
    try:
        d1, rssi1, d2, rssi2 = float(d1), float(rssi1), float(d2), float(rssi2)
    except (TypeError, ValueError):
        return {"error": "two (distance, rssi) points required"}
    if d1 <= 0 or d2 <= 0:
        return {"error": "distances must be > 0 m"}
    if d1 == d2:
        return {"error": "the two distances must differ"}
    denom = 10.0 * (math.log10(d2) - math.log10(d1))
    if denom == 0:
        return {"error": "the two distances must differ"}
    ple = (rssi1 - rssi2) / denom
    rssi0 = rssi1 + 10.0 * ple * math.log10(d1)
    return {"path_loss_exponent": round(ple, 3), "rssi_at_1m": round(rssi0, 2),
            "points": [{"d": d1, "rssi": rssi1}, {"d": d2, "rssi": rssi2}]}


def estimate_radius(bss, tx_dbm=None, ple=_DEFAULT_PLE, rssi_offset=0.0,
                    antenna_gain=0.0, cable_loss=0.0, rssi0_override=None):
    """Coverage rings + your current distance for one BSS (from its measured RSSI).

    Uses the AP's *advertised* TX power (TPC report IE) when it published one, so
    the model is measured rather than assumed; falls back to `tx_dbm` / the
    default otherwise.

    Calibration knobs:
      * ``rssi_offset``  — per-adapter correction added to every measured RSSI
        (e.g. an Alfa that reads 3 dB low → +3).
      * ``antenna_gain`` / ``cable_loss`` — receive-chain EIRP correction (dBi /
        dB) folded into the reference level.
      * ``rssi0_override`` — a reference RSSI@1m from :func:`calibrate_ple`,
        which (with a calibrated ``ple``) replaces the TX/FSPL derivation.
    """
    rssi_offset = float(rssi_offset or 0.0)
    antenna_gain = float(antenna_gain or 0.0)
    cable_loss = float(cable_loss or 0.0)
    tx_measured = bss.get("tx_power_dbm")
    tx_source = "measured" if tx_measured is not None else "assumed"
    if tx_dbm is None:
        tx_dbm = tx_measured if tx_measured is not None else _DEFAULT_TX_DBM
    freq = bss.get("center_freq") or bss.get("freq")
    if rssi0_override is not None:
        rssi0 = float(rssi0_override)
        tx_source = "calibrated"
    else:
        # antenna gain raises the effective reference level; cable loss lowers it
        rssi0 = _rssi_at_1m(freq, tx_dbm) + antenna_gain - cable_loss

    def dist_for(rssi):
        # rssi = rssi0 - 10*n*log10(d)  =>  d = 10^((rssi0-rssi)/(10n))
        return round(10 ** ((rssi0 - rssi) / (10.0 * ple)), 2)

    rings = [
        {"name": name, "threshold_dbm": thr, "label": label, "radius_m": dist_for(thr)}
        for name, thr, label in _RADIUS_THRESHOLDS
    ]
    cur = None
    sig = bss.get("signal")
    sig_adj = None
    if sig is not None:
        sig_adj = sig + rssi_offset
        cur = dist_for(sig_adj)
    return {
        "bssid": bss.get("bssid"),
        "ssid": bss.get("ssid"),
        "band": bss.get("band"),
        "channel": bss.get("channel"),
        "signal": sig,
        "signal_adjusted": sig_adj,
        "assumptions": {"tx_dbm": tx_dbm, "tx_source": tx_source,
                        "path_loss_exponent": ple, "rssi_at_1m": round(rssi0, 1),
                        "rssi_offset": rssi_offset, "antenna_gain": antenna_gain,
                        "cable_loss": cable_loss},
        "current_distance_m": cur,
        "rings": rings,
    }


# --------------------------------------------------------------------------
# Top-level scan orchestration
# --------------------------------------------------------------------------

_DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "data", "wifi_analyzer_db.json")
_DB_HISTORY_CAP = 60      # RSSI samples kept per BSSID
_WEAKENED_DROP = 18       # dB below an AP's own max => "weakened"


def _db_load():
    try:
        with open(_DB_FILE) as f:
            return json.load(f)
    except Exception:
        return {"aps": {}, "last_bssids": []}


def _db_save(db):
    os.makedirs(os.path.dirname(_DB_FILE), exist_ok=True)
    tmp = _DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f)
    os.replace(tmp, _DB_FILE)


def _db_update(aps):
    """Persist per-BSSID history, annotate each AP with it, and diff against the
    previous scan to surface new / disappeared / weakened APs."""
    db = _db_load()
    recs = db.get("aps", {})
    now = int(time.time())
    prev = set(db.get("last_bssids", []))
    cur = set()
    new_aps, weakened = [], []
    for a in aps:
        b = a["bssid"]
        cur.add(b)
        r = recs.get(b)
        if r is None:
            r = recs[b] = {"first_seen": now, "seen_count": 0,
                           "max_rssi": a.get("signal"), "min_rssi": a.get("signal"),
                           "history": []}
            if b not in prev:
                new_aps.append({"bssid": b, "ssid": a.get("ssid"),
                                "vendor": a.get("vendor"), "band": a.get("band"),
                                "channel": a.get("channel"), "signal": a.get("signal")})
        r["seen_count"] += 1
        r["last_seen"] = now
        r["ssid"] = a.get("ssid")
        r["vendor"] = a.get("vendor")
        s = a.get("signal")
        if s is not None:
            r["max_rssi"] = max(r.get("max_rssi") or s, s)
            r["min_rssi"] = min(r.get("min_rssi") if r.get("min_rssi") is not None else s, s)
            r["history"] = (r.get("history", []) + [[now, s, a.get("channel_util")]])[-_DB_HISTORY_CAP:]
            if (r["max_rssi"] - s) >= _WEAKENED_DROP and r["seen_count"] > 2:
                weakened.append({"bssid": b, "ssid": a.get("ssid"),
                                 "band": a.get("band"), "channel": a.get("channel"),
                                 "signal": s, "rssi_max": r["max_rssi"],
                                 "drop": r["max_rssi"] - s})
        # Annotate the live AP with its tracked history
        a["first_seen"] = r["first_seen"]
        a["seen_count"] = r["seen_count"]
        a["is_new"] = b not in prev and r["seen_count"] <= 1
        a["rssi_history"] = [h[1] for h in r.get("history", [])]
        a["rssi_max"] = r.get("max_rssi")
        a["rssi_min"] = r.get("min_rssi")
    gone = [{"bssid": b, "ssid": recs.get(b, {}).get("ssid")}
            for b in (prev - cur)]
    db["aps"] = recs
    db["last_bssids"] = sorted(cur)
    _db_save(db)
    return {"new_aps": new_aps, "gone_aps": gone, "weakened": weakened}


def db_get():
    return _db_load().get("aps", {})


def db_reset():
    _db_save({"aps": {}, "last_bssids": []})
    return {"ok": True}


def _survey_noise(interface):
    """Return {freq_mhz: noise_dbm} from `iw survey dump` (best-effort; some
    drivers, incl. brcmfmac, don't report a noise floor)."""
    rc, out, _ = _run([_IW, "dev", interface, "survey", "dump"], timeout=8)
    if rc != 0:
        return {}
    noise = {}
    cur_freq = None
    for line in out.splitlines():
        m = re.search(r"frequency:\s*(\d+)\s*MHz", line)
        if m:
            cur_freq = int(m.group(1))
            continue
        m = re.search(r"noise:\s*(-?\d+)\s*dBm", line)
        if m and cur_freq is not None:
            noise[cur_freq] = int(m.group(1))
    return noise


def do_scan(interface="wlan0", band="all", passive=True):
    """Run a passive scan and return the full analysed survey."""
    if not _valid_iface(interface):
        return {"error": "invalid interface"}
    # A freshly-plugged dongle is usually admin-down; you can't scan a down
    # radio. Bring the link up first (link-up only, never associates).
    if not _iface_is_up(interface):
        _bring_iface_up(interface)
    caps = radio_capabilities(interface)
    # -u makes iw hex-dump IEs it can't decode. iw <= 6.9 has no scan-side EHT
    # printer, so a Wi-Fi 7 beacon's EHT/Multi-Link IEs only surface as
    # "Unknown Extension ID (106/107/108)" lines — without -u they vanish and
    # every 802.11be AP would be mislabelled Wi-Fi 6/6E from its HE IEs.
    args = [_IW, "dev", interface, "scan", "-u"]
    if passive:
        args.append("passive")
    rc, out, err = _run(args)
    if rc != 0 and re.search(r"not ready|network is down|no such device", err or "", re.I):
        # Down/asleep radio: try once more after forcing the link up.
        if _bring_iface_up(interface):
            rc, out, err = _run(args)
    if rc != 0:
        # 'Device or resource busy' / 'Operation not permitted' are common
        hint = (err or "scan failed").strip()
        low = hint.lower()
        if "busy" in low:
            hint += " — the radio is mid-scan or connecting; retry in a moment."
        elif "not permitted" in low or "operation not permitted" in low:
            hint += " — passive scan needs root (the Ragnar service runs as root)."
        elif "down" in low or "not ready" in low:
            hint += " — bring the interface up: sudo ip link set %s up" % interface
        return {"error": hint, "rc": rc,
                "interface": interface, "supported_bands": caps["bands"]}
    bss_list = parse_scan(out)
    noise = _survey_noise(interface)
    noise_floor = round(sum(noise.values()) / len(noise), 1) if noise else None
    # Flag radar/DFS occupancy + compute SNR from the noise floor where known.
    for b in bss_list:
        b["dfs"] = b["channel"] in caps["radar_channels"].get(b["band"], set())
        nf = noise.get(int(round(b["freq"])))
        if nf is None and noise_floor is not None:
            nf = noise_floor
        b["noise"] = nf
        b["snr"] = (round(b["signal"] - nf, 1)
                    if (b.get("signal") is not None and nf is not None) else None)
    if band in ("2.4", "5", "6"):
        bss_list = [b for b in bss_list if b["band"] == band]
    bss_list.sort(key=lambda b: (b["band"], b["channel"], -(b["signal"] or -999)))
    changes = _db_update(bss_list)
    spectrum = analyze_spectrum(bss_list, caps)
    interference = find_interference(bss_list)
    groups = group_aps(bss_list)
    return {
        "interface": interface,
        "phy": caps["phy"],
        "timestamp": int(time.time()),
        "passive": passive,
        "supported_bands": {b: bool(caps["bands"].get(b)) for b in ("2.4", "5", "6")},
        "radar_channels": {b: sorted(caps["radar_channels"].get(b, set()))
                           for b in ("2.4", "5", "6")},
        "noise_floor": noise_floor,
        "ap_count": len(bss_list),
        "aps": bss_list,
        "spectrum": spectrum,
        "interference": interference,
        "groups": groups,
        "changes": changes,
    }


def fast_signal_poll(interface, freqs, timeout=10):
    """Quick passive scan restricted to `freqs` (MHz); returns
    {bssid: signal_dbm} for every BSS heard fresh on those channels.

    Dwelling on a handful of known channels takes well under a second (a full
    all-band sweep takes several), so callers can refresh the signal of APs
    they already know about near-live between full discovery scans. Results
    the kernel merely cached from an earlier sweep (stale last-seen) are
    dropped so a bar never freezes on an old reading."""
    if not _valid_iface(interface) or not freqs:
        return {}
    args = [_IW, "dev", interface, "scan", "freq"]
    args += [str(int(round(f))) for f in freqs]
    args.append("passive")
    rc, out, _err = _run(args, timeout=timeout)
    if rc != 0:
        return {}
    sig = {}
    for b in parse_scan(out):
        if b.get("signal") is None:
            continue
        last = b.get("last_seen_ms")
        if last is not None and last > 15000:
            continue
        sig[b["bssid"]] = b["signal"]
    return sig


def radius_from_fields(fields, tx_dbm=None, ple=_DEFAULT_PLE, rssi_offset=0.0,
                       antenna_gain=0.0, cable_loss=0.0, rssi0_override=None):
    """Compute the coverage rings from an AP's already-known scan fields — no
    re-scan. The frontend hands back the row it's showing (signal/freq/…), so the
    estimate stays consistent with the table and never races a fresh scan."""
    freq = fields.get("center_freq") or fields.get("freq")
    if fields.get("signal") is None or not freq:
        return {"error": "missing signal/freq for radius estimate"}
    tx_meas = fields.get("tx_power_dbm")
    # Re-validate the advertised TX power (client could be stale/tampered).
    if tx_meas is not None and not (_TX_PLAUSIBLE_MIN <= tx_meas <= _TX_PLAUSIBLE_MAX):
        tx_meas = None
    bss = {
        "bssid": fields.get("bssid"), "ssid": fields.get("ssid"),
        "band": fields.get("band"), "channel": fields.get("channel"),
        "freq": fields.get("freq") or freq, "center_freq": freq,
        "signal": fields.get("signal"), "tx_power_dbm": tx_meas,
    }
    return estimate_radius(bss, tx_dbm=tx_dbm, ple=ple, rssi_offset=rssi_offset,
                           antenna_gain=antenna_gain, cable_loss=cable_loss,
                           rssi0_override=rssi0_override)


def do_radius(interface, bssid, tx_dbm=None, ple=_DEFAULT_PLE, rssi_offset=0.0,
              antenna_gain=0.0, cable_loss=0.0, rssi0_override=None):
    """Passive scan then compute the signal radius for one BSSID. tx_dbm=None
    lets estimate_radius use the AP's advertised TX power when it has one.
    Calibration knobs are forwarded to estimate_radius."""
    if not _valid_bssid(bssid):
        return {"error": "invalid bssid"}
    survey = do_scan(interface=interface, band="all")
    if "error" in survey:
        return survey
    for b in survey["aps"]:
        if b["bssid"] == bssid.lower():
            return estimate_radius(b, tx_dbm=tx_dbm, ple=ple,
                                   rssi_offset=rssi_offset, antenna_gain=antenna_gain,
                                   cable_loss=cable_loss, rssi0_override=rssi0_override)
    return {"error": "bssid not found in latest scan — rescan and try again",
            "bssid": bssid}


# --------------------------------------------------------------------------
# Heatmap sample store (interpolation happens client-side)
# --------------------------------------------------------------------------

def _heatmap_load():
    try:
        with open(_HEATMAP_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        data = {"floorplan": None, "target_bssid": None, "target_ssid": None,
                "samples": []}
    # Predictive-design layer (walls + modelled AP nodes) lives alongside the
    # survey. `predict_aps` is a list so you can plan a whole mesh; a legacy
    # single `predict_ap` is migrated into it.
    data.setdefault("walls", [])
    # Structural columns / pillars — round point-obstacles that shadow signal.
    data.setdefault("columns", [])
    data.setdefault("predict_ap", None)
    if "predict_aps" not in data:
        data["predict_aps"] = [data["predict_ap"]] if data.get("predict_ap") else []
    # Mesh survey: registry of the nodes (BSSIDs) seen for the surveyed SSID.
    data.setdefault("mesh_nodes", {})
    return data


def _heatmap_save(data):
    os.makedirs(os.path.dirname(_HEATMAP_FILE), exist_ok=True)
    tmp = _HEATMAP_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, _HEATMAP_FILE)


def heatmap_get():
    return _heatmap_load()


def heatmap_set_floorplan(floorplan_data_uri, target_bssid=None, target_ssid=None):
    data = _heatmap_load()
    data["floorplan"] = floorplan_data_uri
    data["target_bssid"] = target_bssid
    data["target_ssid"] = target_ssid
    data["samples"] = []  # new floorplan => reset survey
    _heatmap_save(data)
    return data


# Common building-material attenuation at 5 GHz (dB per wall). Rough industry
# figures; users pick the material when drawing a wall.
_WALL_MATERIALS = {
    "drywall": 3, "wood": 4, "glass": 6, "brick": 10,
    "concrete": 15, "metal": 20,
}


def heatmap_set_walls(walls):
    """Persist the drawn walls (list of {x1,y1,x2,y2 in 0..1, loss_db})."""
    data = _heatmap_load()
    clean = []
    for w in walls or []:
        try:
            clean.append({
                "x1": float(w["x1"]), "y1": float(w["y1"]),
                "x2": float(w["x2"]), "y2": float(w["y2"]),
                "loss_db": float(w.get("loss_db", 5)),
                "material": w.get("material") or "wall",
            })
        except (KeyError, TypeError, ValueError):
            continue
    data["walls"] = clean
    _heatmap_save(data)
    return data


def heatmap_set_columns(columns):
    """Persist structural columns/pillars (list of {x,y in 0..1 centre,
    radius_m, loss_db, material}). A column shadows any AP→point line that
    passes through it — the classic open-floor coverage killer."""
    data = _heatmap_load()
    clean = []
    for c in columns or []:
        try:
            clean.append({
                "x": float(c["x"]), "y": float(c["y"]),
                "radius_m": max(0.05, float(c.get("radius_m", 0.3))),
                "loss_db": float(c.get("loss_db", _WALL_MATERIALS["concrete"])),
                "material": c.get("material") or "concrete",
            })
        except (KeyError, TypeError, ValueError):
            continue
    data["columns"] = clean
    _heatmap_save(data)
    return data


def _clean_predict_ap(ap):
    """Validate + normalize one modelled AP, or None if it's malformed.
    `width_m`/`height_m` give the floorplan's real size so normalized distances
    become metres for the path-loss model."""
    try:
        return {
            "x": float(ap["x"]), "y": float(ap["y"]),
            "tx_dbm": float(ap.get("tx_dbm", _DEFAULT_TX_DBM)),
            "freq": float(ap.get("freq", 5200)),
            "ple": float(ap.get("ple", _DEFAULT_PLE)),
            "width_m": float(ap.get("width_m", 10.0)),
            "height_m": float(ap.get("height_m", 10.0)),
        }
    except (KeyError, TypeError, ValueError):
        return None


def heatmap_set_predict_aps(aps):
    """Persist the list of modelled AP nodes for predictive coverage (a planned
    mesh). Empty list clears them. Keeps a legacy single `predict_ap` in sync."""
    data = _heatmap_load()
    clean = []
    for ap in aps or []:
        c = _clean_predict_ap(ap)
        if c is None:
            return {"error": "invalid predict AP"}
        clean.append(c)
    data["predict_aps"] = clean
    data["predict_ap"] = clean[0] if clean else None  # back-compat
    _heatmap_save(data)
    return data


def heatmap_set_predict_ap(ap):
    """Persist a single modelled AP (or None to clear). Back-compat wrapper over
    heatmap_set_predict_aps."""
    return heatmap_set_predict_aps([] if ap is None else [ap])


# --- Predictive-coverage geometry (mirrored client-side in ragnar_modern.js) ---

def _ccw(ax, ay, bx, by, cx, cy):
    return (cy - ay) * (bx - ax) > (by - ay) * (cx - ax)


def _segments_cross(a, b, c, d):
    """True if segment a-b intersects segment c-d (a=(x,y), …)."""
    return (_ccw(*a, *c, *d) != _ccw(*b, *c, *d)
            and _ccw(*a, *b, *c) != _ccw(*a, *b, *d))


def _seg_circle_hit(ax, ay, bx, by, cx, cy, r):
    """True if segment (ax,ay)-(bx,by) passes within `r` of centre (cx,cy).
    All coordinates in the same units (metres). Used to shadow a round column."""
    dx, dy = bx - ax, by - ay
    len2 = dx * dx + dy * dy
    t = (((cx - ax) * dx + (cy - ay) * dy) / len2) if len2 else 0.0
    t = max(0.0, min(1.0, t))
    return math.hypot(cx - (ax + t * dx), cy - (ay + t * dy)) <= r


def predict_point_rssi(px, py, ap, walls, columns=None):
    """Predicted RSSI (dBm) at normalized point (px,py) from a modelled AP,
    using log-distance path loss plus the summed loss of every wall the straight
    AP→point line crosses, plus every structural column it passes through.
    Pure + unit-tested; the JS renderer mirrors it."""
    width_m = ap.get("width_m", 10.0)
    height_m = ap.get("height_m", 10.0)
    rssi0 = _rssi_at_1m(ap.get("freq", 5200), ap.get("tx_dbm", _DEFAULT_TX_DBM))
    ple = ap.get("ple", _DEFAULT_PLE)
    dx = (px - ap["x"]) * width_m
    dy = (py - ap["y"]) * height_m
    d = max(0.5, math.hypot(dx, dy))
    rssi = rssi0 - 10 * ple * math.log10(d)
    a, b = (ap["x"], ap["y"]), (px, py)
    for w in walls or []:
        if _segments_cross(a, b, (w["x1"], w["y1"]), (w["x2"], w["y2"])):
            rssi -= w.get("loss_db", 5)
    # Columns: test the AP→point line in metres against each pillar's radius.
    for c in columns or []:
        if _seg_circle_hit(ap["x"] * width_m, ap["y"] * height_m,
                           px * width_m, py * height_m,
                           c["x"] * width_m, c["y"] * height_m,
                           c.get("radius_m", 0.3)):
            rssi -= c.get("loss_db", _WALL_MATERIALS["concrete"])
    return round(rssi, 1)


def predict_point_rssi_multi(px, py, aps, walls, columns=None):
    """Predicted RSSI at (px,py) from a set of modelled AP nodes: the BEST
    signal any node delivers (each spot served by its strongest node), matching
    real mesh behaviour. None if no nodes. Mirrored in the JS renderer."""
    if not aps:
        return None
    return round(max(predict_point_rssi(px, py, ap, walls, columns) for ap in aps), 1)


# --------------------------------------------------------------------------
# Active throughput / latency measurement (Ekahau-style active survey leg)
# --------------------------------------------------------------------------

def _parse_ping(text):
    """Pull avg latency (ms), jitter (mdev), and loss (%) out of `ping` output."""
    out = {"latency_ms": None, "jitter_ms": None, "loss_pct": None}
    m = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", text)
    if m:
        out["loss_pct"] = float(m.group(1))
    # rtt min/avg/max/mdev = 1.2/3.4/5.6/0.7 ms
    m = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+/([\d.]+)\s*ms", text)
    if m:
        out["latency_ms"] = float(m.group(1))
        out["jitter_ms"] = float(m.group(2))
    return out


def _ping_stats(target, count=5, timeout=10):
    try:
        p = subprocess.run(["ping", "-n", "-c", str(count), "-w", str(timeout), target],
                           capture_output=True, text=True, timeout=timeout + 3)
        return _parse_ping(p.stdout)
    except Exception:
        return {"latency_ms": None, "jitter_ms": None, "loss_pct": None}


def _parse_iperf3(js):
    """Return Mbits/s from an iperf3 --json result (sum_received preferred)."""
    try:
        end = js.get("end", {})
        r = end.get("sum_received") or end.get("sum_sent") or {}
        bps = r.get("bits_per_second")
        return round(bps / 1e6, 2) if bps else None
    except Exception:
        return None


def _iperf3(server, seconds=5, reverse=False, port=None):
    """One iperf3 run against `server`; reverse=True measures download."""
    args = ["iperf3", "-c", server, "-t", str(int(seconds)), "-J", "-i", "0"]
    if reverse:
        args.append("-R")
    if port:
        args += ["-p", str(int(port))]
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=int(seconds) + 10)
        js = json.loads(p.stdout or "{}")
        if js.get("error"):
            return {"error": js["error"]}
        return {"mbps": _parse_iperf3(js)}
    except Exception as exc:
        return {"error": f"iperf3 failed: {exc}"}


def _http_download_mbps(url, max_secs=6, max_bytes=50 * 1024 * 1024):
    """WAN throughput fallback: stream a URL, measure bytes/sec (download only).
    Sends a browser User-Agent — some speed-test endpoints 403 the default one."""
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Ragnar WiFi Analyzer)",
            "Accept": "*/*"})
        t0 = time.time()
        got = 0
        with urllib.request.urlopen(req, timeout=max_secs + 6) as resp:
            while time.time() - t0 < max_secs and got < max_bytes:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                got += len(chunk)
        dt = time.time() - t0
        if dt <= 0 or got == 0:
            return {"error": "no data received"}
        return {"mbps": round(got * 8 / dt / 1e6, 2), "bytes": got, "secs": round(dt, 2)}
    except Exception as exc:
        return {"error": f"download failed: {exc}"}


# A small, CDN-hosted test file used only when no iperf3 server is configured.
_DEFAULT_SPEEDTEST_URL = "https://speed.cloudflare.com/__down?bytes=25000000"


def measure_throughput(iperf_server=None, url=None, seconds=5, ping_target=None):
    """Active-survey measurement at the current spot: latency + up/down throughput.

    Uses an iperf3 server when given (best — measures both directions on the LAN);
    otherwise falls back to an HTTP download speed test (download-only, WAN)."""
    result = {"method": None, "down_mbps": None, "up_mbps": None,
              "latency_ms": None, "jitter_ms": None, "loss_pct": None}
    # Latency: ping the gateway (LAN health) when no explicit target is given.
    target = ping_target or _default_gateway() or "1.1.1.1"
    result.update({k: v for k, v in _ping_stats(target).items()})
    result["ping_target"] = target
    if iperf_server:
        result["method"] = "iperf3"
        result["server"] = iperf_server
        down = _iperf3(iperf_server, seconds, reverse=True)
        up = _iperf3(iperf_server, seconds, reverse=False)
        result["down_mbps"] = down.get("mbps")
        result["up_mbps"] = up.get("mbps")
        errs = [d.get("error") for d in (down, up) if d.get("error")]
        if errs:
            result["error"] = errs[0]
    else:
        result["method"] = "http"
        dl = _http_download_mbps(url or _DEFAULT_SPEEDTEST_URL, max_secs=seconds)
        result["down_mbps"] = dl.get("mbps")
        result["url"] = url or _DEFAULT_SPEEDTEST_URL
        if dl.get("error"):
            result["error"] = dl["error"]
    return result


def _default_gateway():
    try:
        p = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=4)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", p.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def heatmap_add_sample(x, y, rssi, bssid=None, ssid=None,
                       snr=None, noise=None, band=None, channel=None,
                       throughput=None):
    data = _heatmap_load()
    sample = {
        "x": float(x), "y": float(y), "rssi": float(rssi),
        "bssid": bssid, "ssid": ssid, "t": int(time.time()),
    }
    if snr is not None:
        sample["snr"] = float(snr)
    if noise is not None:
        sample["noise"] = float(noise)
    if band is not None:
        sample["band"] = band
    if channel is not None:
        sample["channel"] = channel
    if throughput:
        # flatten the active-survey metrics onto the sample for the heatmap
        for k in ("down_mbps", "up_mbps", "latency_ms", "jitter_ms", "loss_pct"):
            if throughput.get(k) is not None:
                sample[k] = throughput[k]
        sample["tp_method"] = throughput.get("method")
    data["samples"].append(sample)
    _heatmap_save(data)
    return data


def heatmap_sample_live(interface, x, y, bssid, active=False,
                        iperf_server=None, url=None, seconds=5):
    """Take a live passive reading of `bssid` at (x, y). When `active`, also run
    an Ekahau-style throughput/latency measurement and store it on the sample."""
    survey = do_scan(interface=interface, band="all")
    if "error" in survey:
        return survey
    match = next((b for b in survey["aps"] if b["bssid"] == (bssid or "").lower()), None)
    if not match:
        return {"error": "target bssid not heard in this reading", "bssid": bssid}
    tp = None
    if active:
        tp = measure_throughput(iperf_server=iperf_server, url=url, seconds=seconds)
    return heatmap_add_sample(
        x, y, match["signal"], match["bssid"], match["ssid"],
        snr=match.get("snr"), noise=match.get("noise_floor") or survey.get("noise_floor"),
        band=match.get("band"), channel=match.get("channel"), throughput=tp)


def _mesh_nodes_from_scan(aps, ssid):
    """Every BSSID advertising `ssid` (an ESS / mesh), with the strongest as the
    'serving' node — what a client at this spot would associate with. Pure."""
    ssid = (ssid or "")
    nodes = [{"bssid": a["bssid"], "rssi": a.get("signal"),
              "snr": a.get("snr"), "band": a.get("band"), "channel": a.get("channel")}
             for a in aps if (a.get("ssid") or "") == ssid and a.get("signal") is not None]
    nodes.sort(key=lambda n: -(n["rssi"] if n["rssi"] is not None else -999))
    serving = nodes[0] if nodes else None
    return nodes, serving


def heatmap_sample_mesh_live(interface, x, y, ssid, active=False,
                             iperf_server=None, url=None, seconds=5):
    """Mesh survey: record the RSSI of EVERY node (BSSID) of `ssid` at (x, y),
    tag the serving (strongest) node, and register the nodes so the UI can map
    serving-node coverage and hand-off zones. Optional active throughput too."""
    survey = do_scan(interface=interface, band="all")
    if "error" in survey:
        return survey
    nodes, serving = _mesh_nodes_from_scan(survey["aps"], ssid)
    if not serving:
        return {"error": "no node of that SSID heard here", "ssid": ssid}
    tp = None
    if active:
        tp = measure_throughput(iperf_server=iperf_server, url=url, seconds=seconds)
    data = _heatmap_load()
    sample = {
        "x": float(x), "y": float(y), "t": int(time.time()),
        "ssid": ssid, "rssi": serving["rssi"],           # best-of-nodes = coverage
        "serving": serving["bssid"], "snr": serving.get("snr"),
        "band": serving.get("band"), "channel": serving.get("channel"),
        "nodes": {n["bssid"]: n["rssi"] for n in nodes},
    }
    if tp:
        for k in ("down_mbps", "up_mbps", "latency_ms", "jitter_ms", "loss_pct"):
            if tp.get(k) is not None:
                sample[k] = tp[k]
        sample["tp_method"] = tp.get("method")
    data["samples"].append(sample)
    # Register/refresh node metadata (band/channel) for stable colours + labels.
    reg = data.setdefault("mesh_nodes", {})
    for n in nodes:
        reg[n["bssid"]] = {"band": n["band"], "channel": n["channel"], "ssid": ssid}
    _heatmap_save(data)
    return data


def heatmap_clear():
    data = _heatmap_load()
    data["samples"] = []
    data["mesh_nodes"] = {}
    _heatmap_save(data)
    return data


# --------------------------------------------------------------------------
# Named surveys — save / restore a completed floorplan+samples set so several
# sites (or before/after changes) can be kept and compared.
# --------------------------------------------------------------------------

def _surveys_load():
    try:
        with open(_SURVEYS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _surveys_save(data):
    os.makedirs(os.path.dirname(_SURVEYS_FILE), exist_ok=True)
    tmp = _SURVEYS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, _SURVEYS_FILE)


def survey_list():
    """Return survey names with light metadata (no floorplan payload)."""
    surveys = _surveys_load()
    out = []
    for name, s in surveys.items():
        out.append({
            "name": name,
            "samples": len(s.get("samples", [])),
            "target_ssid": s.get("target_ssid"),
            "has_floorplan": bool(s.get("floorplan")),
            "saved": s.get("saved"),
        })
    out.sort(key=lambda x: x.get("saved") or 0, reverse=True)
    return {"surveys": out}


def survey_save(name):
    """Snapshot the current heatmap under `name` — including the whole design
    layer (walls, columns, planned AP nodes, mesh nodes), not just samples."""
    name = (name or "").strip()
    if not name:
        return {"error": "survey name required"}
    cur = _heatmap_load()
    if not cur.get("samples") and not cur.get("floorplan"):
        return {"error": "nothing to save — capture a floorplan/samples first"}
    surveys = _surveys_load()
    surveys[name] = {
        "floorplan": cur.get("floorplan"),
        "target_bssid": cur.get("target_bssid"),
        "target_ssid": cur.get("target_ssid"),
        "samples": cur.get("samples", []),
        "walls": cur.get("walls", []),
        "columns": cur.get("columns", []),
        "predict_aps": cur.get("predict_aps", []),
        "predict_ap": cur.get("predict_ap"),
        "mesh_nodes": cur.get("mesh_nodes", {}),
        "saved": int(time.time()),
    }
    _surveys_save(surveys)
    return survey_list()


def survey_load(name):
    """Restore a saved survey into the active heatmap store, design layer and all."""
    surveys = _surveys_load()
    s = surveys.get(name)
    if s is None:
        return {"error": "no such survey", "name": name}
    _heatmap_save({
        "floorplan": s.get("floorplan"),
        "target_bssid": s.get("target_bssid"),
        "target_ssid": s.get("target_ssid"),
        "samples": s.get("samples", []),
        "walls": s.get("walls", []),
        "columns": s.get("columns", []),
        "predict_aps": s.get("predict_aps", []),
        "predict_ap": s.get("predict_ap"),
        "mesh_nodes": s.get("mesh_nodes", {}),
    })
    return _heatmap_load()


def survey_delete(name):
    surveys = _surveys_load()
    if name in surveys:
        del surveys[name]
        _surveys_save(surveys)
    return survey_list()


# --------------------------------------------------------------------------
# Self-test (synthetic iw output => parser + analyzer assertions)
# --------------------------------------------------------------------------

_SELFTEST_SCAN = r"""BSS aa:bb:cc:00:00:01(on wlan0) -- associated
	freq: 2412.0
	signal: -45.00 dBm
	SSID: HomeNet
	last seen: 0 ms ago
	beacon interval: 100 TUs
	TIM: DTIM Count 0 DTIM Period 2
	Country: SE	Environment: Indoor/Outdoor
	TPC report: TX power: 20 dBm
	RSN:	 * Version: 1
		 * Authentication suites: PSK
		 * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)
	WPS:	 * Version: 1.0
	BSS Load:
		 * station count: 4
		 * channel utilisation: 128/255
	HT capabilities:
		HT RX MCS rate indexes supported: 0-15
	HT operation:
		 * primary channel: 1
		 * secondary channel offset: no secondary
	RM enabled capabilities:
	Extended capabilities:
		 * BSS Transition
BSS aa:bb:cc:00:00:02(on wlan0)
	freq: 2412.0
	signal: -70.00 dBm
	SSID: Neighbour
	HT capabilities:
	HT operation:
		 * primary channel: 1
		 * secondary channel offset: above
BSS aa:bb:cc:00:00:03(on wlan0)
	freq: 5260.0
	signal: -55.00 dBm
	SSID: HomeNet_5G
	RSN:	 * Version: 1
		 * Authentication suites: SAE
		 * Capabilities: MFP-required 16-PTKSA-RC (0x00cc)
	Mobility Domain:
		 * MDID: 0x1234
	HT operation:
		 * primary channel: 52
		 * secondary channel offset: above
	VHT capabilities:
	VHT operation:
		 * channel width: 1 (80 MHz)
		 * center freq segment 1: 58
	VHT RX MCS set:
		1 streams: MCS 0-9
		2 streams: MCS 0-9
		3 streams: MCS 0-9
		4 streams: MCS 0-9
BSS aa:bb:cc:00:00:04(on wlan0)
	freq: 5955.0
	signal: -60.00 dBm
	SSID: HomeNet_6G
	RSN:	 * Version: 1
		 * Authentication suites: IEEE 802.1X
		 * Capabilities: MFP-capable (0x0080)
	HE capabilities:
		HE RX MCS and NSS set <= 80 MHz
			1 streams: MCS 0-11
			2 streams: MCS 0-11
	HE operation
		 * primary channel: 1
		 * channel width: 160
BSS aa:bb:cc:00:00:05(on wlan0)
	freq: 2437.0
	signal: -80.00 dBm
	SSID:
	HT operation:
		 * primary channel: 6
		 * secondary channel offset: no secondary
BSS aa:bb:cc:00:00:06(on wlan0)
	freq: 6115.0
	signal: -58.00 dBm
	SSID: HomeNet_7
	RSN:	 * Version: 1
		 * Authentication suites: SAE
		 * Capabilities: MFP-required 16-PTKSA-RC (0x00cc)
	HE capabilities:
		HE RX MCS and NSS set <= 80 MHz
			1 streams: MCS 0-11
			2 streams: MCS 0-11
	HE operation
		 * primary channel: 33
		 * channel width: 160
	EHT capabilities:
		EHT MAC Capabilities (0x0102):
		EHT PHY Capabilities: (0x0c1b):
	EHT Operation:
		 * channel width: 3 (320 MHz)
BSS aa:bb:cc:00:00:07(on wlan0)
	freq: 6135.0
	signal: -52.00 dBm
	SSID: HomeNet_7_raw
	RSN:	 * Version: 1
		 * Authentication suites: SAE
		 * Capabilities: MFP-required 16-PTKSA-RC (0x00cc)
	HE capabilities:
		HE RX MCS and NSS set <= 80 MHz
			1 streams: MCS 0-11
			2 streams: MCS 0-11
	HE operation
		 * primary channel: 37
		 * channel width: 160
	Unknown Extension ID (108): 82 01 ec 01 01 60 20 e7 00 02 00 22 22 22
	Unknown Extension ID (106): 01 44 44 44 44 04 2f 1f
	Unknown Extension ID (107): 30 01 0b 62 7f f0 1f a4 80 00 00 80 07
"""


def selftest():
    results = []

    def check(name, cond, detail=""):
        results.append({"name": name, "pass": bool(cond), "detail": detail})

    aps = parse_scan(_SELFTEST_SCAN)
    check("parses all 7 BSS", len(aps) == 7, f"got {len(aps)}")

    by_id = {a["bssid"]: a for a in aps}
    a1 = by_id.get("aa:bb:cc:00:00:01", {})
    check("2.4GHz ch1 detected", a1.get("band") == "2.4" and a1.get("channel") == 1,
          f"{a1.get('band')}/{a1.get('channel')}")
    check("RSSI parsed", a1.get("signal") == -45.0, str(a1.get("signal")))
    check("channel util % from BSS load", a1.get("channel_util") == 50.2,
          str(a1.get("channel_util")))
    check("station count parsed", a1.get("stations") == 4, str(a1.get("stations")))
    check("WPA2 (RSN/PSK) security", a1.get("security") == "WPA2", a1.get("security"))

    a3 = by_id.get("aa:bb:cc:00:00:03", {})
    check("5GHz ch52 detected", a3.get("band") == "5" and a3.get("channel") == 52,
          f"{a3.get('band')}/{a3.get('channel')}")
    check("VHT 80MHz width", a3.get("width") == 80, str(a3.get("width")))
    check("WPA3 (SAE) security", a3.get("security") == "WPA3", a3.get("security"))
    check("center freq from segment", a3.get("center_freq") == channel_to_freq(58, "5"),
          str(a3.get("center_freq")))

    a4 = by_id.get("aa:bb:cc:00:00:04", {})
    check("6GHz ch1 detected", a4.get("band") == "6" and a4.get("channel") == 1,
          f"{a4.get('band')}/{a4.get('channel')}")
    check("HE 160MHz width", a4.get("width") == 160, str(a4.get("width")))

    a5 = by_id.get("aa:bb:cc:00:00:05", {})
    check("hidden SSID flagged", a5.get("hidden") is True, str(a5.get("hidden")))

    # Wi-Fi 7 (802.11be), decoded form: EHT IEs must win over the HE IEs the
    # same AP also advertises; 320 MHz comes from the textual-width fallback.
    a6 = by_id.get("aa:bb:cc:00:00:06", {})
    check("Wi-Fi 7 label from EHT IEs (over HE)",
          a6.get("standard") == "Wi-Fi 7" and a6.get("phy_mode") == "be",
          f"{a6.get('standard')}/{a6.get('phy_mode')}")
    check("6GHz ch33 detected for be AP",
          a6.get("band") == "6" and a6.get("channel") == 33,
          f"{a6.get('band')}/{a6.get('channel')}")
    check("EHT 320MHz width", a6.get("width") == 320, str(a6.get("width")))
    check("be PHY rate uses 320MHz multiplier",
          (a6.get("max_phy_mbps") or 0) > 5000, str(a6.get("max_phy_mbps")))

    # Wi-Fi 7, raw form: iw <= 6.9 has no scan-side EHT printer, so with -u the
    # EHT/Multi-Link IEs appear only as 'Unknown Extension ID (106/107/108)'
    # hex dumps. This is what every real 802.11be AP looks like today — it must
    # still be labelled Wi-Fi 7, and 320 MHz must come from the EHT Operation
    # hex (the HE Operation IE caps out at 160 MHz).
    a7 = by_id.get("aa:bb:cc:00:00:07", {})
    check("Wi-Fi 7 label from raw -u ext IDs",
          a7.get("standard") == "Wi-Fi 7" and a7.get("phy_mode") == "be",
          f"{a7.get('standard')}/{a7.get('phy_mode')}")
    check("320MHz width from raw EHT Operation hex",
          a7.get("width") == 320, str(a7.get("width")))
    check("320MHz centre from EHT Operation CCFS1",
          a7.get("center_freq") == channel_to_freq(31, "6"),
          str(a7.get("center_freq")))

    # Width/channel conversions
    check("freq_to_channel 2484 -> ch14", freq_to_channel(2484) == ("2.4", 14))
    check("freq_to_channel 5180 -> 5/36", freq_to_channel(5180) == ("5", 36))
    check("freq_to_channel 5955 -> 6/1", freq_to_channel(5955) == ("6", 1))
    check("channel_to_freq roundtrip 5/149",
          freq_to_channel(channel_to_freq(149, "5")) == ("5", 149))

    # Spectrum analysis
    caps = {"radar_channels": {"2.4": set(), "5": {52}, "6": set()}}
    spec = analyze_spectrum(aps, caps)
    check("2.4GHz band present in spectrum", "2.4" in spec)
    check("ch1 shows 2 co-channel APs",
          any(c["channel"] == 1 and c["primary_count"] == 2
              for c in spec.get("2.4", {}).get("channels", [])),
          json.dumps(spec.get("2.4", {}).get("channels", [])))
    check("2.4 recommends from 1/6/11",
          set(spec.get("2.4", {}).get("recommend", [])) <= set(_NON_OVERLAP_24),
          str(spec.get("2.4", {}).get("recommend")))
    check("5GHz ch52 flagged radar in spectrum",
          any(c["channel"] == 52 and c["radar"]
              for c in spec.get("5", {}).get("channels", [])))

    # Interference
    inter = find_interference(aps)
    check("co-channel interference on ch1",
          any(g["channel"] == 1 and g["count"] == 2 for g in inter["co_channel"]),
          json.dumps(inter["co_channel"]))

    # Radius model — should use the AP's advertised TX power (a1 has TPC 20 dBm)
    rad = estimate_radius(a3)
    check("radius rings computed (3 thresholds)", len(rad["rings"]) == 3)
    check("closer threshold => smaller radius",
          rad["rings"][0]["radius_m"] < rad["rings"][2]["radius_m"],
          str([r["radius_m"] for r in rad["rings"]]))
    check("current distance positive", (rad["current_distance_m"] or 0) > 0,
          str(rad["current_distance_m"]))
    rad1 = estimate_radius(a1)
    check("radius uses measured TX power",
          rad1["assumptions"]["tx_source"] == "measured"
          and rad1["assumptions"]["tx_dbm"] == 20,
          json.dumps(rad1["assumptions"]))
    # An implausible advertised TX power (e.g. 63 dBm ≈ 2 kW) must be rejected so
    # it can't blow up the range model — falls back to the assumed default.
    bogus = parse_scan(
        "BSS de:ad:be:ef:00:01(on wlan0)\n\tfreq: 5180\n\tsignal: -46.00 dBm\n"
        "\tSSID: Bogus\n\tTPC report: TX power: 63 dBm, link margin: 0 dB\n")[0]
    check("implausible advertised TX power is rejected",
          bogus.get("tx_power_dbm") is None, str(bogus.get("tx_power_dbm")))
    rad_bogus = estimate_radius(bogus)
    check("radius falls back to assumed TX when advertised is garbage",
          rad_bogus["assumptions"]["tx_source"] == "assumed"
          and rad_bogus["assumptions"]["tx_dbm"] == _DEFAULT_TX_DBM
          and rad_bogus["current_distance_m"] < 20,
          json.dumps({"src": rad_bogus["assumptions"]["tx_source"],
                      "d": rad_bogus["current_distance_m"]}))
    # radius_from_fields: compute from a known row without re-scanning, and it
    # must apply the same TX-power plausibility guard.
    rf = radius_from_fields({"bssid": "a0:0:0:0:0:1", "band": "5", "channel": 36,
                             "freq": 5180, "center_freq": 5180, "signal": -46,
                             "tx_power_dbm": 63})
    check("radius_from_fields ignores garbage advertised TX",
          rf["assumptions"]["tx_source"] == "assumed" and rf["current_distance_m"] < 20,
          json.dumps({"src": rf["assumptions"]["tx_source"], "d": rf["current_distance_m"]}))
    check("radius_from_fields needs signal+freq",
          "error" in radius_from_fields({"bssid": "x", "freq": 5180}))

    # --- Path-loss calibration (Tier 4) ---
    cal = calibrate_ple(1, -40, 10, -70)   # 30 dB over a decade => n=3.0
    check("two-point calibration solves n from a decade",
          abs(cal["path_loss_exponent"] - 3.0) < 1e-6
          and abs(cal["rssi_at_1m"] - (-40)) < 1e-6, json.dumps(cal))
    check("calibration rejects equal distances",
          "error" in calibrate_ple(5, -40, 5, -70))
    rad_off = estimate_radius(a3, rssi_offset=5)
    check("rssi offset shifts adjusted signal",
          rad_off["signal_adjusted"] == a3["signal"] + 5)
    rad_cal = estimate_radius(a3, ple=cal["path_loss_exponent"],
                              rssi0_override=cal["rssi_at_1m"])
    check("rssi0 override marks model calibrated",
          rad_cal["assumptions"]["tx_source"] == "calibrated"
          and abs(rad_cal["assumptions"]["rssi_at_1m"] - (-40)) < 1e-6,
          json.dumps(rad_cal["assumptions"]))

    # --- Enterprise enrichment (Tier 1) ---
    check("802.11 generation: Wi-Fi 4/5/6E",
          a1.get("standard") == "Wi-Fi 4" and a3.get("standard") == "Wi-Fi 5"
          and a4.get("standard") == "Wi-Fi 6E",
          f"{a1.get('standard')}/{a3.get('standard')}/{a4.get('standard')}")
    check("spatial streams (NSS) parsed",
          a1.get("nss") == 2 and a3.get("nss") == 4 and a4.get("nss") == 2,
          f"{a1.get('nss')}/{a3.get('nss')}/{a4.get('nss')}")
    check("max PHY rate estimated", (a3.get("max_phy_mbps") or 0) > 1000,
          str(a3.get("max_phy_mbps")))
    check("security depth: WPA2 / WPA3 / WPA2-Enterprise",
          a1.get("security") == "WPA2" and a3.get("security") == "WPA3"
          and a4.get("security") == "WPA2-Enterprise",
          f"{a1.get('security')}/{a3.get('security')}/{a4.get('security')}")
    check("PMF parsed (disabled/required/capable)",
          a1.get("pmf") == "disabled" and a3.get("pmf") == "required"
          and a4.get("pmf") == "capable",
          f"{a1.get('pmf')}/{a3.get('pmf')}/{a4.get('pmf')}")
    check("enterprise (802.1X) flagged", a4.get("enterprise") is True,
          str(a4.get("enterprise")))
    check("WPS enabled detected", a1.get("wps") is True and not a3.get("wps"),
          f"{a1.get('wps')}/{a3.get('wps')}")
    check("weak-security findings (WPS + PMF-off on a1)",
          "WPS enabled" in a1.get("security_findings", [])
          and any("PMF off" in f for f in a1.get("security_findings", [])),
          str(a1.get("security_findings")))
    check("roaming 11k/v on a1, 11r on a3",
          a1["roaming"]["k"] and a1["roaming"]["v"] and a3["roaming"]["r"],
          f"{a1.get('roaming')} / {a3.get('roaming')}")
    check("country + DTIM + beacon parsed",
          a1.get("country") == "SE" and a1.get("dtim") == 2
          and a1.get("beacon_interval") == 100,
          f"{a1.get('country')}/{a1.get('dtim')}/{a1.get('beacon_interval')}")
    check("locally-administered MAC => Randomized",
          a1.get("vendor") == "Randomized/private", str(a1.get("vendor")))
    check("OUI vendor lookup (TP-Link)",
          _oui_lookup("00:25:86:11:22:33") in ("TP-Link", "TP-Link Technologies",
                                               "Tp-Link Technologies Co.,Ltd."),
          str(_oui_lookup("00:25:86:11:22:33")))

    # --- Grouping + width advice (Tier 2) ---
    grp = group_aps(aps)
    homenet = next((n for n in grp["networks"] if n["ssid"] == "HomeNet"), None)
    check("networks grouped by SSID", grp["network_count"] >= 4, str(grp["network_count"]))
    check("device grouping by MAC prefix", grp["device_count"] >= 1,
          str(grp["device_count"]))
    check("width advice present per band",
          "width_advice" in spec.get("5", {})
          and spec["2.4"]["width_advice"]["mhz"] == 20,
          json.dumps(spec.get("5", {}).get("width_advice")))

    # --- AP history DB + change detection (Tier 3) — temp file, no real state ---
    global _DB_FILE
    _orig_db, _DB_FILE = _DB_FILE, __import__("tempfile").mktemp(suffix=".json")
    try:
        db_reset()
        base = {"bssid": "a0:00:00:00:00:01", "ssid": "H", "channel_util": 10,
                "band": "2.4", "channel": 1, "vendor": None}
        first = dict(base, signal=-40)
        c1 = _db_update([first])
        check("new AP detected on first sighting",
              any(n["bssid"] == base["bssid"] for n in c1["new_aps"])
              and first.get("is_new") is True)
        check("rssi history annotated", first.get("rssi_history") == [-40])
        _db_update([dict(base, signal=-70)])
        weak = dict(base, signal=-70)
        c3 = _db_update([weak])
        check("weakened AP detected (>=18 dB below its max)",
              any(w["bssid"] == base["bssid"] for w in c3["weakened"]),
              json.dumps(c3["weakened"]))
        c4 = _db_update([])       # AP vanished this scan
        check("disappeared AP detected",
              any(g["bssid"] == base["bssid"] for g in c4["gone_aps"]))
    finally:
        try:
            os.unlink(_DB_FILE)
        except OSError:
            pass
        _DB_FILE = _orig_db

    # --- Named surveys save/load (Tier 3) — temp files, no real state ---
    global _HEATMAP_FILE, _SURVEYS_FILE
    _oh, _os_ = _HEATMAP_FILE, _SURVEYS_FILE
    import tempfile as _tf
    _HEATMAP_FILE = _tf.mktemp(suffix=".json")
    _SURVEYS_FILE = _tf.mktemp(suffix=".json")
    try:
        heatmap_add_sample(0.5, 0.5, -55, "b0:00:00:00:00:01", "SurveyNet",
                           snr=25, noise=-90, band="5", channel=36)
        check("survey save requires a name", "error" in survey_save(""))
        survey_save("siteA")
        lst = survey_list()
        check("saved survey listed with sample count",
              any(s["name"] == "siteA" and s["samples"] == 1 for s in lst["surveys"]),
              json.dumps(lst))
        # A survey must also snapshot the whole design layer, not just samples.
        heatmap_set_walls([{"x1": 0.1, "y1": 0.1, "x2": 0.9, "y2": 0.1,
                            "loss_db": 15, "material": "concrete"}])
        heatmap_set_columns([{"x": 0.5, "y": 0.5, "material": "metal"}])
        heatmap_set_predict_aps([{"x": 0.2, "y": 0.2}, {"x": 0.8, "y": 0.8}])
        survey_save("siteB")
        heatmap_clear()
        check("heatmap cleared before load", len(_heatmap_load()["samples"]) == 0)
        loaded = survey_load("siteA")
        check("survey load restores samples (with snr)",
              len(loaded["samples"]) == 1 and loaded["samples"][0].get("snr") == 25)
        # Load the design-heavy survey and confirm every layer round-trips.
        lb = survey_load("siteB")
        check("survey restores walls", len(lb.get("walls", [])) == 1
              and lb["walls"][0]["material"] == "concrete", json.dumps(lb.get("walls")))
        check("survey restores columns", len(lb.get("columns", [])) == 1
              and lb["columns"][0]["material"] == "metal", json.dumps(lb.get("columns")))
        check("survey restores planned AP nodes",
              len(lb.get("predict_aps", [])) == 2, json.dumps(lb.get("predict_aps")))
        survey_delete("siteB")
        survey_delete("siteA")
        check("survey delete removes it",
              not any(s["name"] == "siteA" for s in survey_list()["surveys"]))
    finally:
        for _f in (_HEATMAP_FILE, _SURVEYS_FILE):
            try:
                os.unlink(_f)
            except OSError:
                pass
        _HEATMAP_FILE, _SURVEYS_FILE = _oh, _os_

    # --- Active-survey parsers (Tier: active throughput) ---
    ping_out = ("5 packets transmitted, 5 received, 0% packet loss, time 4005ms\n"
                "rtt min/avg/max/mdev = 1.111/2.222/3.333/0.444 ms")
    ps = _parse_ping(ping_out)
    check("ping parse: latency/jitter/loss",
          ps["latency_ms"] == 2.222 and ps["jitter_ms"] == 0.444 and ps["loss_pct"] == 0.0,
          json.dumps(ps))
    lossy = _parse_ping("10 packets transmitted, 7 received, 30% packet loss")
    check("ping parse: loss with no rtt line", lossy["loss_pct"] == 30.0
          and lossy["latency_ms"] is None, json.dumps(lossy))
    iperf_json = {"end": {"sum_received": {"bits_per_second": 943000000.0}}}
    check("iperf3 parse: Mbps from sum_received",
          _parse_iperf3(iperf_json) == 943.0, str(_parse_iperf3(iperf_json)))
    check("iperf3 parse: missing data => None", _parse_iperf3({}) is None)
    # throughput fields flatten onto a heatmap sample (_HEATMAP_FILE already
    # declared global above in this function)
    _oh2, _HEATMAP_FILE = _HEATMAP_FILE, __import__("tempfile").mktemp(suffix=".json")
    try:
        d = heatmap_add_sample(0.5, 0.5, -55, "aa:bb:cc:00:00:01", "TP",
                               throughput={"method": "iperf3", "down_mbps": 500.0,
                                           "up_mbps": 120.0, "latency_ms": 8.0})
        s = d["samples"][-1]
        check("throughput flattened onto sample",
              s.get("down_mbps") == 500.0 and s.get("up_mbps") == 120.0
              and s.get("latency_ms") == 8.0 and s.get("tp_method") == "iperf3",
              json.dumps(s))
    finally:
        try:
            os.unlink(_HEATMAP_FILE)
        except OSError:
            pass
        _HEATMAP_FILE = _oh2

    # --- Predictive coverage geometry (Tier: design/planning) ---
    check("segments cross detected",
          _segments_cross((0, 0), (1, 1), (0, 1), (1, 0)) is True)
    check("parallel segments do not cross",
          _segments_cross((0, 0), (1, 0), (0, 1), (1, 1)) is False)
    ap_pred = {"x": 0.5, "y": 0.5, "tx_dbm": 20, "freq": 5200, "ple": 3.0,
               "width_m": 20.0, "height_m": 20.0}
    r_near = predict_point_rssi(0.55, 0.5, ap_pred, [])
    r_far = predict_point_rssi(0.95, 0.5, ap_pred, [])
    check("predicted RSSI weakens with distance", r_far < r_near, f"{r_near} vs {r_far}")
    wall = {"x1": 0.7, "y1": 0.0, "x2": 0.7, "y2": 1.0, "loss_db": 15}
    r_nowall = predict_point_rssi(0.95, 0.5, ap_pred, [])
    r_wall = predict_point_rssi(0.95, 0.5, ap_pred, [wall])
    check("a crossed wall subtracts its loss (15 dB)",
          abs((r_nowall - r_wall) - 15) < 0.01, f"{r_nowall} - {r_wall}")
    r_sidewall = predict_point_rssi(0.6, 0.5, ap_pred, [wall])  # point before the wall
    check("a wall not crossed has no effect",
          abs(r_sidewall - predict_point_rssi(0.6, 0.5, ap_pred, [])) < 0.01)

    # --- Structural columns (round pillars that shadow signal) ---
    # AP at centre-left, column dead-centre, point on the far right => the
    # AP→point line runs straight through the pillar and must lose its dB.
    ap_l = dict(ap_pred, x=0.1, y=0.5)
    col = {"x": 0.5, "y": 0.5, "radius_m": 0.5, "loss_db": 15}
    r_clear = predict_point_rssi(0.9, 0.5, ap_l, [])
    r_shadow = predict_point_rssi(0.9, 0.5, ap_l, [], [col])
    check("a column in the line of sight subtracts its loss",
          abs((r_clear - r_shadow) - 15) < 0.01, f"{r_clear} - {r_shadow}")
    # A point off to the side (line misses the pillar) is unaffected.
    r_side = predict_point_rssi(0.5, 0.05, ap_l, [], [col])
    check("a column not in the path has no effect",
          abs(r_side - predict_point_rssi(0.5, 0.05, ap_l, [])) < 0.01)
    check("seg-circle hit true when line passes through centre",
          _seg_circle_hit(0, 0, 10, 0, 5, 0, 0.5) is True)
    check("seg-circle miss when line clears the radius",
          _seg_circle_hit(0, 0, 10, 0, 5, 2, 0.5) is False)
    # Columns compose with the mesh best-node combine.
    two_col = predict_point_rssi_multi(0.9, 0.5, [ap_l], [], [col])
    check("column loss flows through the mesh combine",
          two_col == r_shadow, f"{two_col} vs {r_shadow}")

    # --- Multi-node predictive coverage (planned mesh: best node wins) ---
    ap_a = dict(ap_pred, x=0.1, y=0.5)
    ap_b = dict(ap_pred, x=0.9, y=0.5)
    check("no nodes => no prediction",
          predict_point_rssi_multi(0.5, 0.5, [], []) is None)
    # A point near node B must be served by B (single-node A would be far/weak).
    near_b = predict_point_rssi_multi(0.85, 0.5, [ap_a, ap_b], [])
    check("mesh coverage = best of all nodes (near B served by B)",
          near_b == predict_point_rssi(0.85, 0.5, ap_b, [])
          and near_b > predict_point_rssi(0.85, 0.5, ap_a, []),
          f"{near_b}")
    # A second node lifts coverage where one node was weak.
    one = predict_point_rssi_multi(0.85, 0.5, [ap_a], [])
    two = predict_point_rssi_multi(0.85, 0.5, [ap_a, ap_b], [])
    check("adding a node never lowers predicted coverage", two >= one, f"{one}->{two}")
    # Persistence round-trips a list and keeps legacy predict_ap in sync.
    _oh3, _HEATMAP_FILE = _HEATMAP_FILE, _tf.mktemp(suffix=".json")
    try:
        heatmap_set_predict_aps([ap_a, ap_b])
        hd = heatmap_get()
        check("predict_aps persists the full node list",
              len(hd.get("predict_aps", [])) == 2)
        check("legacy predict_ap kept in sync with first node",
              hd.get("predict_ap", {}).get("x") == 0.1)
        heatmap_set_predict_aps([])
        check("clearing nodes empties predict_aps and predict_ap",
              heatmap_get().get("predict_aps") == []
              and heatmap_get().get("predict_ap") is None)
        heatmap_set_columns([{"x": 0.4, "y": 0.6, "material": "concrete"}])
        hc = heatmap_get().get("columns", [])
        check("columns persist with radius/loss defaults",
              len(hc) == 1 and hc[0]["radius_m"] == 0.3
              and hc[0]["loss_db"] == _WALL_MATERIALS["concrete"],
              json.dumps(hc))
        heatmap_set_columns([])
        check("clearing columns empties them", heatmap_get().get("columns") == [])
    finally:
        try:
            os.unlink(_HEATMAP_FILE)
        except OSError:
            pass
        _HEATMAP_FILE = _oh3

    # --- Mesh survey node selection (serving node = strongest of the ESS) ---
    mesh_aps = [
        {"bssid": "aa:00:00:00:00:01", "ssid": "MeshNet", "signal": -70, "band": "2.4", "channel": 6, "snr": 20},
        {"bssid": "aa:00:00:00:00:02", "ssid": "MeshNet", "signal": -52, "band": "5", "channel": 36, "snr": 40},
        {"bssid": "bb:00:00:00:00:03", "ssid": "OtherNet", "signal": -40, "band": "5", "channel": 44, "snr": 45},
    ]
    m_nodes, m_serving = _mesh_nodes_from_scan(mesh_aps, "MeshNet")
    check("mesh: only same-SSID nodes included", len(m_nodes) == 2, str(len(m_nodes)))
    check("mesh: serving node is the strongest",
          m_serving["bssid"] == "aa:00:00:00:00:02" and m_serving["rssi"] == -52,
          json.dumps(m_serving))
    check("mesh: no node => no serving",
          _mesh_nodes_from_scan(mesh_aps, "Nonexistent")[1] is None)

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Passive tri-band Wi-Fi spectrum analyzer")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("interfaces")
    ps = sub.add_parser("scan")
    ps.add_argument("--interface", default="wlan0")
    ps.add_argument("--band", default="all", choices=["all", "2.4", "5", "6"])
    ps.add_argument("--active", action="store_true", help="(NOT passive) send probes")
    pr = sub.add_parser("radius")
    pr.add_argument("--interface", default="wlan0")
    pr.add_argument("--bssid", required=True)
    pr.add_argument("--tx", type=float, default=_DEFAULT_TX_DBM)
    pr.add_argument("--ple", type=float, default=_DEFAULT_PLE)
    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if args.cmd == "interfaces":
        print(json.dumps(list_wifi_interfaces(), indent=2))
    elif args.cmd == "scan":
        print(json.dumps(do_scan(args.interface, args.band, passive=not args.active),
                         indent=2))
    elif args.cmd == "radius":
        print(json.dumps(do_radius(args.interface, args.bssid, args.tx, args.ple),
                         indent=2))
    elif args.cmd == "selftest":
        r = selftest()
        for item in r["results"]:
            print(f"  [{'PASS' if item['pass'] else 'FAIL'}] {item['name']}"
                  + (f"  ({item['detail']})" if not item["pass"] else ""))
        print(f"\n{r['passed']}/{r['total']} checks pass — "
              f"{'OK' if r['pass'] else 'FAILURES'}")
        return 0 if r["pass"] else 1
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
