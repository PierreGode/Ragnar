#!/usr/bin/env python3
"""
wifi_defense.py — Passive 802.11 frame monitor / Wireless IDS for Ragnar.

Listens on a **monitor-mode** adapter for 802.11 management frames and flags the
classic wireless attacks a defender cares about:

* **Deauth / disassoc flood** — the 802.11 deauthentication DoS (aireplay/mdk4):
  spoofed deauth/disassoc frames knock clients off an AP.
* **Beacon flood** — a storm of fake APs (mdk4 beacon mode): many bogus SSIDs /
  BSSIDs appearing at once to drown the airspace or bait clients.
* **Rogue AP / evil twin** — a *known* SSID advertised from a BSSID that isn't in
  the trusted baseline (a look-alike AP set up to harvest clients), or one SSID
  suddenly served by two BSSIDs.
* **KARMA / MANA** — an AP that answers probe requests for *many different* SSIDs
  from a single BSSID (it pretends to be every network a client has ever joined).

Everything here only **receives** — it never transmits a frame, never deauths
anyone back. It's detection-only (a WIDS), not an attack tool.

Monitor mode is set up with plain `iw` (no aircrack-ng needed): where the driver
allows it a *separate* monitor vif is added so the box keeps its normal Wi-Fi
link; otherwise the adapter itself is switched to monitor. Tuned for the Alfa
AWUS036AXM (mt7921u) which supports a concurrent monitor vif; the Pi's onboard
brcmfmac radio does not do monitor mode at all.

CLI:
    python3 wifi_defense.py interfaces
    python3 wifi_defense.py monitor --interface wlan1 --enable
    python3 wifi_defense.py scan --interface wlan1 --seconds 15 [--channel 6]
    python3 wifi_defense.py monitor --interface wlan1 --disable
    python3 wifi_defense.py selftest
"""

import errno
import json
import os
import re
import subprocess
import sys
import threading
import time

_IW = "/usr/sbin/iw" if os.path.exists("/usr/sbin/iw") else "iw"
_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "data", "wifi_defense.json")

# Build marker — bump on every monitor-lifecycle change and mirror the value in
# the web UI (WIFIDEF_BUILD in ragnar_modern.js). The UI compares them and warns
# if the running (long-lived) webapp still has an OLD wifi_defense module loaded,
# i.e. the service wasn't restarted after a git pull. Kills stale-service guesswork.
_BUILD = "20260902-halehound-esp32-oui"

# Detection thresholds (per capture window)
_DEAUTH_FLOOD_MIN = 15      # deauth+disassoc frames => flood
# Beacon flood. There is no reliable "shape" signal that separates a flood from a
# dense neighbourhood passively: raw SSID/BSSID counts scale with how crowded the
# airspace is, and randomized/locally-administered BSSIDs are ALSO used by ordinary
# multi-SSID routers (guest/IoT VAPs derive their BSSID by setting the 0x02 bit),
# so a block full of them trips any LA-based rule. The only robust lever is the raw
# distinct-SSID/BSSID count with a threshold the user calibrates to their own RF
# environment — a real mdk3/mdk4/ESP32 flood produces hundreds, far above any home.
_BEACON_FLOOD_SSIDS = 100         # distinct beaconed SSIDs => flood (tunable)
_BEACON_FLOOD_BSSIDS = 150        # distinct beaconing BSSIDs => flood (tunable)
_BEACON_LA_BSSID_MIN = 18         # burst of distinct BSSIDs to consider LA-ratio
_BEACON_LA_RATIO = 0.5            # LA (randomized) BSSID fraction => fake-AP storm
_KARMA_SSID_MIN = 5               # distinct SSIDs answered by ONE bssid => KARMA

# Auth-frame flood (802.11 authentication DoS — HaleHound "Auth Flood", mdk4
# 'a' mode, ESP32 Marauder/Bruce). The tool sprays authentication-request frames
# from many spoofed/random source MACs at ONE AP to exhaust its client table.
# The tells: a burst of auth frames all aimed at one BSSID, sourced from a large
# number of DISTINCT MACs, most of them locally-administered (randomized). Real
# roaming/association produces auth frames too, but from a handful of burned-in
# client MACs — never dozens of randomized ones at once.
_AUTH_FLOOD_MIN = 30        # auth frames at one BSSID => candidate flood
_AUTH_FLOOD_SRCS = 12       # distinct source MACs at one BSSID => flood
_AUTH_LA_RATIO = 0.5        # LA (randomized) source fraction => spoofed flood

# Channels the hopper cycles when no fixed channel is requested (2.4 GHz + the
# common U-NII-1/3 5 GHz set). Kept short so each channel gets real dwell time.
_HOP_CHANNELS = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]

# 6 GHz (Wi-Fi 6E) preferred-scanning channels, as *frequencies* in MHz — 6 GHz
# must be tuned by freq (channel numbers collide with 2.4/5 GHz) and only works
# with a correct regulatory domain + a 6E-capable radio. Opt-in (see six_ghz).
# freq = 5950 + 5*chan; these are the PSC (preferred scanning) channels.
_HOP_6GHZ_FREQS = [5975, 6055, 6135, 6215, 6295, 6375, 6455, 6535,
                   6615, 6695, 6775, 6855, 6935, 7015, 7095]

# Broadcast / unspecified receiver addresses (auth/deauth targeting logic).
_BCAST_ADDRS = {"ff:ff:ff:ff:ff:ff", None}

# 802.11 management subtype -> event kind
_MGMT_SUBTYPES = {
    0: "assoc_req", 1: "assoc_resp", 2: "reassoc_req", 3: "reassoc_resp",
    4: "probe_req", 5: "probe_resp", 8: "beacon", 10: "disassoc",
    11: "auth", 12: "deauth",
}


# --------------------------------------------------------------------------
# Subprocess plumbing
# --------------------------------------------------------------------------

def _run(args, timeout=10):
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{args[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as exc:  # pragma: no cover
        return 1, "", str(exc)


def _valid_iface(iface):
    return bool(iface) and re.match(r"^[A-Za-z0-9_.-]{1,32}$", iface or "") is not None


# --------------------------------------------------------------------------
# Interface / monitor-mode management  (plain iw, no aircrack-ng)
# --------------------------------------------------------------------------

def _phy_for_iface(iface):
    rc, out, _ = _run([_IW, "dev"], timeout=5)
    cur = None
    for line in out.splitlines():
        m = re.match(r"^(phy#\d+)", line)
        if m:
            cur = m.group(1).replace("#", "")
        m = re.match(r"^\s*Interface\s+(\S+)", line)
        if m and m.group(1) == iface:
            return cur
    return None


def _phy_supports_monitor(phy):
    if not phy:
        return False
    rc, out, _ = _run([_IW, "phy", phy, "info"], timeout=8)
    if rc != 0:
        return False
    block = re.search(r"Supported interface modes:(.*?)(?:\n\s*\n|\n\tband|\Z)",
                      out, re.S)
    return bool(block and re.search(r"\*\s*monitor", block.group(1)))


def _iw_dev_list():
    """Return {iface: {phy, type}} for every wireless interface."""
    rc, out, _ = _run([_IW, "dev"], timeout=5)
    devs = {}
    cur_phy, cur = None, None
    for line in out.splitlines():
        m = re.match(r"^(phy#\d+)", line)
        if m:
            cur_phy = m.group(1).replace("#", "")
            continue
        m = re.match(r"^\s*Interface\s+(\S+)", line)
        if m:
            cur = m.group(1)
            devs[cur] = {"phy": cur_phy, "type": None}
            continue
        if cur:
            mt = re.match(r"^\s*type\s+(\S+)", line)
            if mt:
                devs[cur]["type"] = mt.group(1)
    return devs


def _iface_exists(name):
    """True if a network interface by this name is currently present."""
    return bool(name) and os.path.exists("/sys/class/net/" + name)


def _resolve_monitor(interface, auto_enable=True):
    """Return a live monitor interface name for `interface`, or {"error": ...}.

    The persisted mon_iface can go stale after a reboot / service restart / the
    dongle being re-plugged — the vif named in the state file no longer exists,
    and sniffing it raises ENODEV ("Errno 19 no such device"). Validate that the
    persisted interface is actually present; if not, drop the stale state and
    re-enable monitor mode from scratch.
    """
    state = _load_state()
    mon = state.get("mon_iface")
    if mon and _iface_exists(mon):
        return mon
    # A dedicated (boot-managed) monitor should still be present; if it vanished
    # (adapter re-plugged), re-claim the same interface in dedicated switch-mode
    # rather than adding a vif.
    if state.get("mode") == "dedicated" and mon:
        res = dedicate_monitor(mon, six_ghz=state.get("six_ghz", False))
        return res["mon_iface"] if "error" not in res else res
    # Stale or absent — clear the dead bookkeeping (keeps baseline/thresholds).
    if mon:
        _save_state({})
    if not auto_enable:
        return {"error": "monitor mode not enabled"}
    res = enable_monitor(interface)
    if "error" in res:
        return res
    return res["mon_iface"]


def list_monitor_capable():
    """Wireless interfaces whose radio can do monitor mode, plus current state."""
    devs = _iw_dev_list()
    state = _load_state()
    out = []
    seen_phys = {}
    mon_name = _mon_name(None)
    for iface, info in devs.items():
        # Our own monitor vif (ragmon0) is not a selectable *base* adapter — hide
        # it so the UI/tools never try to enable/disable monitor "on ragmon0".
        if iface == mon_name and info["type"] == "monitor":
            continue
        phy = info["phy"]
        if phy not in seen_phys:
            seen_phys[phy] = _phy_supports_monitor(phy)
        out.append({
            "iface": iface, "phy": phy, "type": info["type"],
            "monitor_capable": seen_phys[phy],
            "is_monitor": info["type"] == "monitor",
        })
    # Only advertise a monitor the kernel still knows about — a stale mon_iface
    # (vif gone after reboot/replug) would otherwise show as "active" in the UI
    # yet fail every capture with ENODEV.
    active = state.get("mon_iface")
    if active and not _iface_exists(active):
        active = None
    return {"interfaces": out, "active_monitor": active,
            "base_iface": state.get("base_iface"),
            "mode": state.get("mode") if active else None,
            "dedicated": state.get("mode") == "dedicated" and active is not None,
            "build": _BUILD}


def _mon_name(base):
    # Deterministic, short, and unlikely to collide with a user's naming.
    return "ragmon0"


def _monitor_ready(mon):
    """Bring a freshly-created monitor vif up on a known channel and confirm both
    that the kernel made it a monitor AND that we can actually TUNE it. The
    channel set is the real test: on a shared-radio adapter (e.g. mt7921u) a
    managed vif that is still up holds the channel, so `iw set channel` returns
    EBUSY (-16) and the monitor hears nothing. If we can't set the channel the
    vif is useless for capture."""
    if not _iface_exists(mon):
        return False
    _run(["ip", "link", "set", mon, "up"], timeout=5)
    rc, _, _ = _run([_IW, "dev", mon, "set", "channel", "6"], timeout=5)
    is_monitor = _iw_dev_list().get(mon, {}).get("type") == "monitor"
    return is_monitor and rc == 0


def _release_iface(iface):
    """Stop NetworkManager / wpa_supplicant / dhclient from managing `iface` so
    they don't re-up it under us (which re-grabs the channel → EBUSY). Targets
    only processes bound to THIS interface. All best-effort and silent where the
    tool/service isn't present."""
    _run(["nmcli", "device", "set", iface, "managed", "no"], timeout=5)
    # wpa_supplicant/dhclient bound to this iface hold the radio; drop only the
    # instances tied to it (leave the management link's supplicant alone).
    _run(["pkill", "-f", f"wpa_supplicant.*{iface}"], timeout=5)
    _run(["pkill", "-f", f"dhclient.*{iface}"], timeout=5)


def _restore_iface(iface):
    """Hand `iface` back to NetworkManager so normal Wi-Fi resumes after monitor."""
    _run(["nmcli", "device", "set", iface, "managed", "yes"], timeout=5)


def set_regdomain(domain):
    """Set the wireless regulatory domain (e.g. 'US', 'SE'). Required for 5 GHz
    DFS and 6 GHz channels to become available. No-op for a falsy/blank domain."""
    domain = (domain or "").strip().upper()
    if not re.match(r"^[A-Z]{2}$", domain):
        return {"error": "regdomain must be a 2-letter ISO code (e.g. US)"}
    rc, _, err = _run([_IW, "reg", "set", domain], timeout=5)
    return {"ok": rc == 0, "regdomain": domain, "error": (err or "").strip() or None}


def enable_monitor(iface):
    """Put a monitor interface up for `iface`'s radio.

    Prefers adding a *separate* monitor vif (keeps the managed link alive on
    drivers that allow it, e.g. mt7921u). Falls back to switching the interface
    itself into monitor mode. Returns {mon_iface, mode, warning?} or {error}.
    """
    if not _valid_iface(iface):
        return {"error": "invalid interface"}
    # Never run monitor *on* our own monitor vif. A caller (a stale UI selection,
    # a diagnostic) can hand us 'ragmon0'; map it back to the real managed base,
    # otherwise disabling (which deletes ragmon0) makes the next enable fail with
    # "radio (None) does not support monitor mode".
    if iface == _mon_name(iface):
        base = _load_state().get("base_iface")
        if base and base != iface:
            iface = base
        else:
            return {"error": f"'{iface}' is the monitor interface, not an adapter — "
                             "select the adapter's managed interface (e.g. wlan1)"}
    phy = _phy_for_iface(iface)
    if not _phy_supports_monitor(phy):
        return {"error": f"{iface}'s radio ({phy}) does not support monitor mode"}
    _run(["/usr/bin/rfkill", "unblock", "all"], timeout=5)
    mon = _mon_name(iface)

    # Stop NetworkManager (and wpa_supplicant) from fighting us: an interface they
    # manage gets brought back UP moments after we down it, which re-grabs the
    # channel and brings the EBUSY straight back. No-ops where they aren't present.
    _release_iface(iface)

    # Always rebuild a FRESH vif. A ragmon0 left over from a previous
    # enable/disable cycle can exist yet be in a half-dead state that captures
    # nothing — so tear any lingering one down and recreate, letting the driver
    # settle in between (the del→add race is what breaks mt7921u re-enables).
    if mon in _iw_dev_list():
        _run(["ip", "link", "set", mon, "down"], timeout=5)
        _run([_IW, "dev", mon, "del"], timeout=8)
        time.sleep(0.3)

    # Free the radio: a shared-PHY managed interface that stays UP holds the
    # channel, so the monitor vif can't be tuned (`iw set channel` => EBUSY) and
    # captures nothing. Take the managed base down while we monitor — this is what
    # makes capture reliable on mt7921u and friends. disable_monitor restores it.
    _run(["ip", "link", "set", iface, "down"], timeout=5)

    # Try a concurrent monitor vif first.
    rc, _, err = _run([_IW, "phy", phy, "interface", "add", mon,
                       "type", "monitor"], timeout=8)
    if rc == 0 and _monitor_ready(mon):
        # Confirm the vif SURVIVES a beat. On a USB adapter (mt7921u) the churn
        # of down/up + vif add can trigger a device reset that silently removes
        # ragmon0 right after we make it — reporting "on" then would give the
        # ENODEV-on-first-scan the tester saw after a re-enable.
        time.sleep(0.4)
        if _iface_exists(mon) and _iw_dev_list().get(mon, {}).get("type") == "monitor":
            _save_state({"mon_iface": mon, "base_iface": iface, "mode": "vif"})
            return {"mon_iface": mon, "mode": "vif"}
    # Half-created / not-a-monitor / un-tunable / vanished vif — clean up first.
    if mon in _iw_dev_list():
        _run([_IW, "dev", mon, "del"], timeout=8)

    # Fallback: switch the interface itself to monitor (disrupts its link).
    _run(["ip", "link", "set", iface, "down"], timeout=5)
    rc2, _, err2 = _run([_IW, "dev", iface, "set", "type", "monitor"], timeout=8)
    _run(["ip", "link", "set", iface, "up"], timeout=5)
    if rc2 == 0:
        _save_state({"mon_iface": iface, "base_iface": iface, "mode": "switch"})
        return {"mon_iface": iface, "mode": "switch",
                "warning": "switched the adapter to monitor — its normal Wi-Fi "
                           "link is down until you disable monitor mode."}
    return {"error": f"could not enable monitor: {(err or err2 or '').strip()}"}


def disable_monitor(mon_iface=None):
    """Tear down monitor mode, restoring the managed interface."""
    state = _load_state()
    mon = mon_iface or state.get("mon_iface")
    mode = state.get("mode")
    base = state.get("base_iface")
    if not mon:
        return {"ok": True, "note": "no active monitor"}
    if mode == "vif" or (mon in _iw_dev_list() and _iw_dev_list().get(mon, {}).get("type") == "monitor" and mon == _mon_name(base)):
        _run(["ip", "link", "set", mon, "down"], timeout=5)
        _run([_IW, "dev", mon, "del"], timeout=8)
        time.sleep(0.3)  # let the delete settle so a quick re-enable doesn't race
        # Hand the managed base interface back to NetworkManager and bring it up
        # (we took it down + unmanaged it to free the radio) so Wi-Fi resumes.
        if base and base != mon:
            _restore_iface(base)
            _run(["ip", "link", "set", base, "up"], timeout=5)
    else:
        # We switched the base iface itself into monitor (switch / dedicated
        # mode); switch it back to managed and re-manage it.
        _run(["ip", "link", "set", mon, "down"], timeout=5)
        _run([_IW, "dev", mon, "set", "type", "managed"], timeout=8)
        _restore_iface(mon)
        _run(["ip", "link", "set", mon, "up"], timeout=5)
    _save_state({})
    return {"ok": True, "restored": base or mon}


def dedicate_monitor(iface, regdomain=None, init_freq=None, six_ghz=False):
    """Claim `iface` as a *dedicated* passive monitor (switch-mode: the whole
    interface becomes type=monitor). Meant to run once at boot for a sensor that
    owns the adapter — no runtime enable/disable dance, no shared-radio vif, so
    none of the EBUSY / 'ragmon0 disappeared' failure modes apply. Sets the
    regulatory domain (needed for DFS/6 GHz), releases NM/wpa_supplicant/dhclient
    on the iface, then switches it to monitor and parks a frequency."""
    if not _valid_iface(iface):
        return {"error": "invalid interface"}
    phy = _phy_for_iface(iface)
    if not _phy_supports_monitor(phy):
        return {"error": f"{iface}'s radio ({phy}) does not support monitor mode"}
    _run(["/usr/bin/rfkill", "unblock", "all"], timeout=5)
    if regdomain:
        set_regdomain(regdomain)
    _release_iface(iface)
    _run(["ip", "link", "set", iface, "down"], timeout=5)
    rc, _, err = _run([_IW, "dev", iface, "set", "type", "monitor"], timeout=8)
    _run(["ip", "link", "set", iface, "up"], timeout=5)
    if rc != 0 or _iw_dev_list().get(iface, {}).get("type") != "monitor":
        return {"error": f"driver rejected monitor mode on {iface}: {(err or '').strip()}"}
    if init_freq:
        _set_freq(iface, init_freq)
    _save_state({"mon_iface": iface, "base_iface": iface, "mode": "dedicated",
                 "six_ghz": bool(six_ghz)})
    return {"mon_iface": iface, "mode": "dedicated", "regdomain": regdomain,
            "six_ghz": bool(six_ghz)}


def _set_channel(mon_iface, channel):
    _run([_IW, "dev", mon_iface, "set", "channel", str(int(channel))], timeout=5)


def _set_freq(mon_iface, freq_mhz):
    _run([_IW, "dev", mon_iface, "set", "freq", str(int(freq_mhz))], timeout=5)


def _hop_targets(six_ghz=False):
    """Ordered tune targets for the channel hopper: ('chan', N) for 2.4/5 GHz and
    ('freq', MHz) for 6 GHz (which must be tuned by frequency)."""
    targets = [("chan", c) for c in _HOP_CHANNELS]
    if six_ghz:
        targets += [("freq", f) for f in _HOP_6GHZ_FREQS]
    return targets


def _tune(mon_iface, target):
    kind, val = target
    if kind == "freq":
        _set_freq(mon_iface, val)
    else:
        _set_channel(mon_iface, val)


# --------------------------------------------------------------------------
# State (trusted-AP baseline + monitor bookkeeping)
# --------------------------------------------------------------------------

def _load_state():
    try:
        with open(_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(extra):
    old = _load_state()
    # Replace bookkeeping (mon_iface/base_iface/mode) but PRESERVE the persistent
    # user data (trusted baseline + tuned thresholds) across monitor start/stop.
    state = dict(extra)
    for key in ("baseline", "thresholds"):
        if key in old and key not in state:
            state[key] = old[key]
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    tmp = _STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, _STATE_FILE)


def get_baseline():
    return _load_state().get("baseline") or {}


def _write_baseline(baseline):
    state = _load_state()
    state["baseline"] = baseline
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    tmp = _STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, _STATE_FILE)
    return baseline


def set_baseline(ssid_bssids, merge=True):
    """Persist the trusted SSID->[BSSID] map.

    A single capture window can never hear every BSSID of every SSID (dual-band
    radios, mesh nodes and band-steering all publish the same SSID from several
    BSSIDs, and channel-hopping only samples each channel briefly). Replacing the
    baseline each time therefore leaves most legitimate BSSIDs "untrusted" and
    they get flagged as evil twins on the next scan. So by default we **merge**
    (union BSSIDs per SSID) rather than overwrite, letting the baseline build up
    a complete picture across repeated Trust actions."""
    if merge:
        base = get_baseline()
        for ssid, bssids in (ssid_bssids or {}).items():
            have = base.setdefault(ssid, [])
            for b in bssids:
                b = (b or "").lower()
                if b and b not in have:
                    have.append(b)
        ssid_bssids = base
    else:
        ssid_bssids = {s: sorted({(b or "").lower() for b in bs if b})
                       for s, bs in (ssid_bssids or {}).items()}
    return _write_baseline(ssid_bssids)


def clear_baseline():
    return _write_baseline({})


def get_thresholds():
    """User-tunable beacon-flood thresholds (persisted), with sane defaults."""
    st = _load_state().get("thresholds") or {}
    return {
        "beacon_ssids": int(st.get("beacon_ssids", _BEACON_FLOOD_SSIDS)),
        "beacon_bssids": int(st.get("beacon_bssids", _BEACON_FLOOD_BSSIDS)),
    }


def set_thresholds(beacon_ssids=None, beacon_bssids=None):
    cur = get_thresholds()
    if beacon_ssids is not None:
        cur["beacon_ssids"] = max(10, min(2000, int(beacon_ssids)))
    if beacon_bssids is not None:
        cur["beacon_bssids"] = max(10, min(2000, int(beacon_bssids)))
    state = _load_state()
    state["thresholds"] = cur
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    tmp = _STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, _STATE_FILE)
    return cur


def _aps_to_mapping(aps):
    """SSID -> [BSSID] from an AP inventory list (skips hidden/empty SSIDs)."""
    mapping = {}
    for ap in aps or []:
        ssid = ap.get("ssid")
        bssid = (ap.get("bssid") or "").lower()
        if ssid and bssid:
            mapping.setdefault(ssid, [])
            if bssid not in mapping[ssid]:
                mapping[ssid].append(bssid)
    return mapping


# --------------------------------------------------------------------------
# Frame parsing  (Scapy Dot11 -> normalized event dict)
# --------------------------------------------------------------------------

def _frame_to_event(pkt):
    """Normalize one Scapy 802.11 packet into an event dict, or None if it isn't
    a management frame we care about. Pure w.r.t. Scapy objects."""
    from scapy.all import Dot11, Dot11Elt  # lazy import
    if not pkt.haslayer(Dot11):
        return None
    d = pkt.getlayer(Dot11)
    if d.type != 0:                      # 0 = management
        return None
    kind = _MGMT_SUBTYPES.get(d.subtype)
    if kind is None:
        return None
    ev = {
        "kind": kind,
        "src": (d.addr2 or "").lower() or None,     # transmitter
        "dst": (d.addr1 or "").lower() or None,     # receiver
        "bssid": (d.addr3 or "").lower() or None,
        "ssid": None,
        "channel": None,
        "rssi": None,
        "reason": None,
        # 802.11 Protected Frame bit (FC field 0x40). On PMF/802.11w networks a
        # genuine teardown is protected; an unprotected deauth is a spoof attempt.
        "protected": bool(int(getattr(d, "FCfield", 0)) & 0x40),
        "ts": float(getattr(pkt, "time", 0) or 0),
    }
    # SSID from the first SSID element (ID 0); note RSN (48) / WPA (221 vendor)
    # elements in the same pass so we can label security. Empty SSID = hidden.
    el = pkt.getlayer(Dot11Elt)
    have_ssid = False
    has_rsn = has_wpa = False
    while el is not None and isinstance(el, Dot11Elt):
        if el.ID == 0 and not have_ssid:
            try:
                ev["ssid"] = el.info.decode(errors="replace")
            except Exception:
                ev["ssid"] = None
            have_ssid = True
        elif el.ID == 48:
            has_rsn = True                      # RSN (WPA2/WPA3)
        elif el.ID == 221 and bytes(el.info)[:4] == b"\x00\x50\xf2\x01":
            has_wpa = True                      # Microsoft WPA1 vendor IE
        el = el.payload.getlayer(Dot11Elt)
    # Security label for beacons / probe-resps: an EvilPortal-style open lure has
    # privacy=0 and no RSN/WPA element. Only "Open" is asserted with confidence;
    # anything encrypted is left as its coarse label (detail doesn't matter here).
    if kind in ("beacon", "probe_resp"):
        cap = 0
        for lname in ("Dot11Beacon", "Dot11ProbeResp"):
            lyr = pkt.getlayer(lname)
            if lyr is not None:
                try:
                    cap = int(lyr.cap)
                except Exception:
                    cap = 0
                break
        privacy = bool(cap & 0x10)              # capability Privacy bit
        if has_rsn:
            ev["security"] = "WPA2/3"
        elif has_wpa:
            ev["security"] = "WPA"
        elif privacy:
            ev["security"] = "WEP"
        else:
            ev["security"] = "Open"
    # Reason code for deauth/disassoc
    if kind in ("deauth", "disassoc"):
        for lname in ("Dot11Deauth", "Dot11Disas"):
            lyr = pkt.getlayer(lname)
            if lyr is not None:
                ev["reason"] = getattr(lyr, "reason", None)
                break
    # RSSI + channel from RadioTap, if present
    try:
        from scapy.all import RadioTap
        if pkt.haslayer(RadioTap):
            rt = pkt.getlayer(RadioTap)
            ev["rssi"] = getattr(rt, "dBm_AntSignal", None)
            freq = getattr(rt, "ChannelFrequency", None)
            if freq:
                ev["channel"] = _freq_to_channel(int(freq))
    except Exception:
        pass
    return ev


def _is_locally_administered(mac):
    """True if a MAC is locally-administered (the 0x02 bit of the first octet) —
    i.e. randomized/spoofed rather than a vendor-assigned (global) address. Real
    APs almost always use global OUIs; beacon-flood tools use random MACs."""
    if not mac:
        return False
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _is_blank_ssid(ssid):
    """True for a hidden/cloaked/wildcard SSID that isn't a real network identity.

    A hidden AP still beacons an SSID element, but it's either absent or
    length>0 filled with NUL bytes — which decodes to a truthy string that only
    *looks* empty. Several unrelated hidden APs (different vendors/OUIs) all
    beacon this way, so grouping them under one blank key and calling it a
    duplicate/evil twin is meaningless: an evil twin clones a *named* SSID to
    lure clients, and a blank SSID has no name to impersonate. Exclude it."""
    if not ssid:
        return True
    return ssid.strip("\x00 \t\r\n\x1c\x1d\x1e\x1f") == ""


def _is_multicast_bssid(mac):
    """True if a BSSID has the I/G (group/multicast) bit set — bit 0x01 of the
    first octet. A real AP's BSSID is ALWAYS an individual (unicast) address, so
    a beacon sourced from a group address is invalid 802.11 and a strong sign of
    a spoofed/rogue AP (some evil-twin tools randomize the BSSID without clearing
    this bit). Low false-positive: legitimate hardware never does this."""
    if not mac:
        return False
    try:
        return bool(int(mac.split(":")[0], 16) & 0x01)
    except (ValueError, IndexError):
        return False


# Common "free/open Wi-Fi" names an evil-twin lure impersonates to get victims to
# associate (HaleHound GARMR, Wifiphisher, etc.). Matching one on an OPEN AP is a
# LOW-confidence hint only — real venues use these names too — so it never alerts.
_LURE_SSIDS = {
    "free wifi", "freewifi", "free_wifi", "free-wifi", "wifi", "public wifi",
    "guest wifi", "guest", "airport wifi", "airport_free_wifi", "hotel wifi",
    "starbucks wifi", "attwifi", "xfinitywifi", "google starbucks",
    "free internet", "free public wifi", "linksys", "netgear", "default",
}


def _is_lure_ssid(ssid):
    """True if an SSID matches a common open-Wi-Fi lure name (normalized)."""
    if not ssid:
        return False
    return ssid.strip().lower() in _LURE_SSIDS


# Default/branded SSIDs shipped by ESP32 & handheld attack multitools and their
# captive-portal payloads. Unlike _LURE_SSIDS (benign-looking names real venues
# also use), these names are to all intents never legitimate — seeing one on
# the air is a HIGH-confidence "an attack tool is running here" signal, secured
# or open. Matched on the SSID normalized to lowercase with spaces/_/- removed,
# so "Evil Portal", "evil_portal" and "EvilPortal" all hit "evilportal".
_ATTACK_TOOL_SSIDS = {
    "evilportal", "eviltwin", "eviltwins", "pineapple", "wifipineapple",
    "marauder", "esp32marauder", "ghostesp", "ghost", "bruce", "garmr",
    "halehound", "deauther", "spacehuhn", "pwnagotchi", "flipperzero",
    "freewifiportal", "captiveportal", "wifiphisher", "fluxion",
}


def _norm_ssid(ssid):
    """Lowercase an SSID and strip spaces/underscores/dashes for name matching."""
    if not ssid:
        return ""
    return re.sub(r"[\s_\-]+", "", ssid.strip().lower())


def _is_attack_tool_ssid(ssid):
    """True if an SSID is a known attack-tool / captive-portal default name."""
    return _norm_ssid(ssid) in _ATTACK_TOOL_SSIDS


# Espressif OUIs — an ESP32/ESP8266 is the radio behind EvilPortal, Marauder,
# Ghost ESP, Bruce, GARMR, … . Renaming the SSID or hiding it doesn't change the
# chip's burned-in MAC, so an OPEN AP from an Espressif OUI is a name-independent
# tell of an ESP32 soft-AP. A curated fallback set covers a minimal install with
# no IEEE oui.txt; when present we defer to the analyzer's full oui.txt lookup.
_ESPRESSIF_OUIS = {
    "24:0a:c4", "24:6f:28", "24:b2:de", "24:d7:eb", "2c:3a:e8", "2c:bc:bb",
    "30:ae:a4", "30:c6:f7", "34:85:18", "34:94:54", "34:ab:95", "34:b4:72",
    "3c:61:05", "3c:71:bf", "3c:8a:1f", "40:22:d8", "40:91:51", "44:17:93",
    "48:31:b7", "48:3f:da", "48:55:19", "4c:11:ae", "4c:75:25", "4c:eb:d6",
    "50:02:91", "54:32:04", "54:0e:00", "58:bf:25", "5c:cf:7f", "60:01:94",
    "68:67:25", "68:b6:b3", "6c:b4:57", "70:04:1d", "70:b8:f6",
    "78:21:84", "78:e3:6d", "7c:9e:bd", "7c:df:a1", "80:64:6f", "80:7d:3a",
    "84:0d:8e", "84:cc:a8", "84:f3:eb", "84:fc:e6", "88:13:bf", "8c:4b:14",
    "8c:aa:b5", "90:38:0c", "94:3c:c6", "94:b5:55", "94:b9:7e", "98:cd:ac",
    "98:f4:ab", "9c:9c:1f", "a0:20:a6", "a0:76:4e", "a0:b7:65", "a4:7b:9d",
    "a4:cf:12", "a8:03:2a", "ac:0b:fb", "ac:67:b2", "b0:a7:32", "b4:8a:0a",
    "b4:e6:2d", "b8:d6:1a", "b8:f0:09", "bc:dd:c2", "bc:ff:4d", "c4:4f:33",
    "c4:5b:be", "c4:dd:57", "c8:2b:96", "c8:c9:a3", "c8:f0:9e", "cc:50:e3",
    "cc:db:a7", "d8:a0:1d", "d8:bc:38", "d8:f1:5b", "dc:4f:22", "dc:54:75",
    "e0:5a:1b", "e0:98:06", "e0:e2:e6", "e8:31:cd", "e8:68:e7", "e8:9f:6d",
    "e8:db:84", "ec:64:c9", "ec:da:3b", "ec:fa:bc", "f0:08:d1", "f4:12:fa",
    "f4:cf:a2", "f8:b3:b7", "fc:b4:67", "fc:f5:c4",
}


def _is_espressif(mac):
    """True if a BSSID belongs to Espressif (ESP32/ESP8266)."""
    oui = _oui(mac)
    if not oui:
        return False
    if oui in _ESPRESSIF_OUIS:
        return True
    # Defer to the analyzer's full IEEE oui.txt lookup when it's importable.
    try:
        import wifi_analyzer
        v = wifi_analyzer._oui_lookup(mac) or ""
        return "espressif" in v.lower()
    except Exception:
        return False


def _oui(mac):
    """The 24-bit OUI (first three octets, lower-cased) of a MAC, or None."""
    if not mac:
        return None
    parts = mac.split(":")
    if len(parts) < 3:
        return None
    return ":".join(parts[:3]).lower()


def _is_band_steering(bssids):
    """True if a set of BSSIDs advertising one SSID looks like ONE physical AP /
    vendor mesh rather than an evil twin.

    Band-steering routers and mesh systems put the same SSID on several radios
    (2.4/5/6 GHz) or nodes, all from the SAME vendor OUI — a tri-band adapter now
    sees these as 2-3 BSSIDs for one real network. An evil twin, by contrast,
    clones the SSID from a DIFFERENT (often randomized/locally-administered)
    radio, so its BSSID won't share the victim AP's global OUI. Require every
    BSSID to be a global (vendor-assigned) address sharing one OUI."""
    bssids = [b for b in bssids if b]
    if len(bssids) < 2:
        return False
    if any(_is_locally_administered(b) for b in bssids):
        return False
    ouis = {_oui(b) for b in bssids}
    return len(ouis) == 1 and None not in ouis


def _freq_to_channel(freq):
    if 2412 <= freq <= 2484:
        return 14 if freq == 2484 else (freq - 2407) // 5
    if freq >= 5955:
        return (freq - 5950) // 5
    if 5000 <= freq < 5925:
        return (freq - 5000) // 5
    return None


def parse_pcap(path):
    """Read a pcap of 802.11 frames into event dicts (for tests / offline runs)."""
    from scapy.all import rdpcap
    return [e for e in (_frame_to_event(p) for p in rdpcap(path)) if e]


# --------------------------------------------------------------------------
# Airtime / retry / roaming analysis (passive link-quality diagnostics)
# --------------------------------------------------------------------------

# Rough HT/VHT MCS 0-7 base rates at 20 MHz, 800 ns GI, 1 spatial stream (Mbps).
_HT_MCS20 = [6.5, 13, 19.5, 26, 39, 52, 58.5, 65]


def _frame_rate_mbps(rt):
    """Best-effort PHY rate (Mbps) from a RadioTap layer: legacy Rate, else MCS."""
    rate = getattr(rt, "Rate", None)
    if rate:
        return round(rate * 0.5, 1)          # radiotap Rate is in 500 kbps units
    mcs = getattr(rt, "MCS_index", None)
    if mcs is not None:
        base = _HT_MCS20[mcs % 8]
        streams = mcs // 8 + 1
        bw = getattr(rt, "MCS_bandwidth", 0)
        factor = 2.07 if bw == 1 else 1.0    # 40 MHz ~2.07x
        return round(base * streams * factor, 1)
    return None


# RSN AKM suite selectors (last byte of the 00-0F-AC OUI suite) worth naming.
_AKM_SAE = {8, 9, 24}                    # WPA3-Personal (SAE / FT-SAE)
_AKM_1X = {1, 3, 5, 11, 12, 13}          # 802.1X / enterprise
_AKM_OWE = {18}                          # Opportunistic Wireless Encryption


def _parse_rsn_akm(info):
    """Return the set of AKM suite selector bytes from an RSN element body."""
    akms = set()
    try:
        i = 2                            # skip version
        i += 4                           # group cipher suite
        n_pw = info[i] | (info[i + 1] << 8); i += 2
        i += 4 * n_pw                    # pairwise cipher suites
        n_akm = info[i] | (info[i + 1] << 8); i += 2
        for _ in range(n_akm):
            akms.add(info[i + 3])        # 4th byte = suite type
            i += 4
    except (IndexError, TypeError):
        pass
    return akms


def _classify_security(privacy, rsn_info, has_wpa1):
    """Map beacon capability + RSN/WPA elements to a security label."""
    if rsn_info is not None:
        akms = _parse_rsn_akm(rsn_info)
        if akms & _AKM_OWE:
            return "OWE"
        if akms & _AKM_SAE:
            # SAE + PSK together = WPA2/WPA3 transition mode.
            return "WPA2/3" if 2 in akms or 6 in akms else "WPA3"
        if akms & _AKM_1X:
            return "WPA2-Ent"
        return "WPA2"
    if has_wpa1:
        return "WPA"
    if privacy:
        return "WEP"
    return "Open"


# RSN/WSC cipher suite selectors (last byte of the 00-0F-AC suite).
_CIPHER_NAMES = {1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 5: "WEP-104",
                 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256"}


def _parse_rsn_ciphers(info):
    """(group_cipher_type, {pairwise_cipher_types}) from an RSN element body."""
    try:
        i = 2                                  # version
        group = info[i + 3]; i += 4            # group cipher suite (4th byte = type)
        n_pw = info[i] | (info[i + 1] << 8); i += 2
        pw = set()
        for _ in range(n_pw):
            pw.add(info[i + 3]); i += 4
        return group, pw
    except (IndexError, TypeError):
        return None, set()


# WSC (Wi-Fi Simple Config / WPS) attribute IDs, big-endian TLV.
_WSC_STATE = 0x1044          # 1=Not Configured, 2=Configured
_WSC_LOCKED = 0x1057         # AP Setup Locked: 1=locked
_WSC_CONFIG_METHODS = 0x1008 # bitmask
_WSC_SEL_REGISTRAR = 0x1041  # a registrar is active now
_WSC_VENDOR_EXT = 0x1049     # WFA vendor extension; carries Version2
# Config Methods bits that indicate the external-registrar PIN path (the
# brute-forceable M3/M4 method), vs pushbutton which needs physical presence.
_WSC_PIN_METHODS = 0x0004 | 0x0008 | 0x0100   # Label | Display | Keypad
_WSC_PUSHBUTTON = 0x0080


def _parse_wsc(data):
    """Parse a WSC (WPS) element body into an AP-posture dict, or None.

    Reads only the plaintext attributes an AP advertises about its own
    enrollment surface — no association, no keys. The single most important
    signal is the *absence* of a Version2 subelement (=> WSC 1.0, which has no
    mandatory PIN-attempt lockout, so an online brute force runs to completion)."""
    wps = {"present": True, "configured": None, "locked": None,
           "pin_method": False, "pushbutton": False, "selected_registrar": False,
           "version2": False}
    i, n = 0, len(data)
    while i + 4 <= n:
        aid = (data[i] << 8) | data[i + 1]
        ln = (data[i + 2] << 8) | data[i + 3]
        i += 4
        if i + ln > n:
            break
        val = data[i:i + ln]
        i += ln
        if aid == _WSC_STATE and ln >= 1:
            wps["configured"] = val[0] == 2
        elif aid == _WSC_LOCKED and ln >= 1:
            wps["locked"] = val[0] == 1
        elif aid == _WSC_CONFIG_METHODS and ln >= 2:
            m = (val[0] << 8) | val[1]
            wps["pin_method"] = bool(m & _WSC_PIN_METHODS)
            wps["pushbutton"] = bool(m & _WSC_PUSHBUTTON)
        elif aid == _WSC_SEL_REGISTRAR and ln >= 1:
            wps["selected_registrar"] = val[0] == 1
        elif aid == _WSC_VENDOR_EXT and ln >= 4 and val[:3] == b"\x00\x37\x2a":
            # WFA vendor extension: subelements (1B id, 1B len, val). id 0=Version2.
            j = 3
            while j + 2 <= len(val):
                sid, slen = val[j], val[j + 1]
                j += 2
                if sid == 0x00 and slen >= 1:
                    wps["version2"] = True
                j += slen
    return wps


def _classify_ap_phy(ht, vht, he, eht, rates, is_2ghz):
    """802.11 generation from a beacon's capability IEs (+ rate set for a/b/g)."""
    if eht:
        return "802.11be (Wi-Fi 7)"
    if he:
        return "802.11ax (Wi-Fi 6)"
    if vht:
        return "802.11ac (Wi-Fi 5)"
    if ht:
        return "802.11n (Wi-Fi 4)"
    # No HT/VHT/HE => legacy. Split by band + rate set.
    if not is_2ghz:
        return "802.11a (OFDM)"
    has_ofdm = any(r > 11.0 for r in rates)     # 6/9/12/.. Mbps => ERP-OFDM
    return "802.11g (OFDM)" if has_ofdm else "802.11b (DSSS)"


def _airtime_event(pkt):
    """Normalize ANY 802.11 frame for airtime/retry/roaming stats (or None)."""
    from scapy.all import Dot11, Dot11Elt
    if not pkt.haslayer(Dot11):
        return None
    d = pkt.getlayer(Dot11)
    fc = int(getattr(d, "FCfield", 0) or 0)
    to_ds, from_ds = bool(fc & 0x01), bool(fc & 0x02)
    a1 = (d.addr1 or "").lower() or None
    a2 = (d.addr2 or "").lower() or None
    a3 = (d.addr3 or "").lower() or None
    ev = {
        "type": int(d.type), "subtype": int(d.subtype),
        "retry": bool(fc & 0x08),
        "to_ds": to_ds, "from_ds": from_ds,
        "src": a2, "dst": a1,
        "bytes": len(bytes(d)),
        "rate_mbps": None, "rssi": None,
    }
    # Resolve the *station* (non-AP endpoint) and the BSSID from the DS bits,
    # so airtime is attributed to the client in BOTH directions — counting only
    # addr2 (uplink) understates a legacy station's real cost by ~half and
    # misfiles its downlink airtime onto the AP.
    #   ToDS  (STA->AP):  a1=BSSID a2=STA  a3=DA
    #   FromDS(AP->STA):  a1=STA   a2=BSSID a3=SA
    #   neither (IBSS/mgmt): a2=SA(STA) a1=DA  a3=BSSID
    if to_ds and not from_ds:
        ev["sta"], ev["bssid"] = a2, a1
    elif from_ds and not to_ds:
        ev["sta"], ev["bssid"] = a1, a2
    elif not to_ds and not from_ds:
        ev["sta"], ev["bssid"] = a2, a3
    else:                                    # WDS/mesh (both APs) — no single STA
        ev["sta"], ev["bssid"] = None, a3 or a1
    # Beacons / probe responses describe the BSS: SSID, ERP protection, the
    # security suite (Open/WEP/WPA/WPA2/WPA3) and the 802.11 generation — all
    # read straight from the management IEs, no active probing.
    if d.type == 0 and d.subtype in (5, 8):
        rsn_info = None
        has_wpa1 = False
        ht = vht = he = eht = False
        rates = []
        basic_cck = False
        ds_channel = None
        wsc_data = b""
        el = pkt.getlayer(Dot11Elt)
        while el is not None and isinstance(el, Dot11Elt):
            eid, info = el.ID, (el.info or b"")
            if eid == 0 and "ssid" not in ev:
                try:
                    ev["ssid"] = info.decode(errors="replace") or None
                except Exception:
                    pass
            elif eid == 42 and info:
                # ERP Information (1 byte): bit0 NonERP_Present, bit1 Use_Protection.
                ev["erp_nonerp"] = bool(info[0] & 0x01)
                ev["erp_protection"] = bool(info[0] & 0x02)
            elif eid in (1, 50):                 # (Extended) Supported Rates
                for b in info:
                    r = (b & 0x7f) * 0.5
                    rates.append(r)
                    if (b & 0x80) and r in _DSSS_RATES:   # basic-rate bit + CCK
                        basic_cck = True
            elif eid == 3 and info:              # DS Parameter Set = primary channel
                ds_channel = info[0]
            elif eid == 61 and len(info) >= 2:   # HT Operation
                # HT Protection = bits 0-1 of the HT Operation Information field
                # (octet 1). Value 3 = Non-HT Mixed (a pre-11n STA is associated).
                ev["ht_protection"] = info[1] & 0x03
            elif eid == 48:                      # RSN => WPA2/WPA3
                rsn_info = info
            elif eid == 221 and info[:4] == b"\x00\x50\xf2\x01":
                has_wpa1 = True                  # Microsoft WPA v1 vendor element
            elif eid == 221 and info[:4] == b"\x00\x50\xf2\x04":
                wsc_data = info[4:]              # WFA WSC (WPS) vendor element
            elif eid == 45:
                ht = True
            elif eid == 191:
                vht = True
            elif eid == 255 and info:            # Element ID Extension
                ext = info[0]
                if ext in (35, 36):              # HE Capabilities / Operation
                    he = True
                elif ext in (106, 108):          # EHT Operation / Capabilities
                    eht = True
            el = el.payload.getlayer(Dot11Elt)
        privacy = False
        try:
            from scapy.all import Dot11Beacon, Dot11ProbeResp
            mgmt = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
            if mgmt is not None:
                privacy = bool(int(mgmt.cap) & 0x0010)
        except Exception:
            pass
        is_2ghz = ds_channel is None or ds_channel <= 14
        ev["security"] = _classify_security(privacy, rsn_info, has_wpa1)
        ev["ap_phy"] = _classify_ap_phy(ht, vht, he, eht, rates, is_2ghz)
        ev["basic_cck"] = basic_cck              # BSS still admits 802.11b
        if rsn_info is not None:
            g, pw = _parse_rsn_ciphers(rsn_info)
            ev["group_cipher"] = _CIPHER_NAMES.get(g)
            ev["pairwise_ciphers"] = sorted(_CIPHER_NAMES.get(p, f"0x{p:02x}") for p in pw)
        if wsc_data:
            ev["wps"] = _parse_wsc(wsc_data)
    # A station's own (re)assoc/probe REQUEST declares its capability directly:
    # an HT Capabilities element (45) present => 802.11n+ for certain; absent =>
    # a genuine pre-802.11n station. This "declared" signal is far stronger than
    # guessing PHY from observed rates (a modern client at the cell edge sends
    # only low rates and would otherwise look legacy).
    elif d.type == 0 and d.subtype in (0, 2, 4):
        has_ht = has_vht = has_he = False
        el = pkt.getlayer(Dot11Elt)
        while el is not None and isinstance(el, Dot11Elt):
            if el.ID == 45:
                has_ht = True
            elif el.ID == 191:
                has_vht = True
            elif el.ID == 255 and el.info and el.info[0] == 35:
                has_he = True
            el = el.payload.getlayer(Dot11Elt)
        ev["declared_ht"] = has_ht or has_vht or has_he
    try:
        from scapy.all import RadioTap
        if pkt.haslayer(RadioTap):
            rt = pkt.getlayer(RadioTap)
            ev["rate_mbps"] = _frame_rate_mbps(rt)
            ev["rssi"] = getattr(rt, "dBm_AntSignal", None)
    except Exception:
        pass
    return ev


def _frame_airtime_us(ev):
    """Measured on-air (PPDU) time of a frame in microseconds: PHY preamble +
    data-symbol time. Preamble depends on the PHY, which dominates for legacy
    frames — a 1 Mbps DSSS frame carries a 192 µs long preamble, so a flat
    overhead constant materially understates the legacy airtime tax.

      DSSS/CCK (<=11 Mbps): 192 µs long preamble  (1500B@1M => 12192 µs)
      OFDM (<=54 Mbps):      20 µs L-preamble+SIG
      HT/VHT/HE (>54):      ~40 µs preamble
    Unknown rate => assume a slow 6 Mbps OFDM floor."""
    rate = ev.get("rate_mbps") or 6.0
    if rate <= 11.0:
        preamble = 192.0
    elif rate <= 54.0:
        preamble = 20.0
    else:
        preamble = 40.0
    return preamble + (ev.get("bytes", 0) * 8) / rate


# The DSSS/CCK rate set — a station transmitting only these is 802.11b, the
# legacy client that forces ERP protection on the whole BSS.
_DSSS_RATES = {1.0, 2.0, 5.5, 11.0}


def _classify_phy(rate_min, rate_max):
    """Best-effort PHY generation from a client's observed PHY-rate spread.
    Returns a short label; None when we saw no rates."""
    if rate_min is None:
        return None
    if rate_max <= 11.0 and rate_min in _DSSS_RATES:
        return "802.11b (DSSS/CCK)"       # the airtime tax
    if rate_max <= 54.0:
        return "802.11a/g (OFDM)"
    return "802.11n+ (HT/VHT/HE)"


def _classify_client_phy(declared_ht, rate_min, rate_max):
    """Classify a station's PHY generation, preferring its *declared* capability
    (HT/VHT/HE element present in its assoc/probe request) over rates observed
    on the air. Returns (label, is_pre_n_legacy, confidence).

    Declared is definitive; observed is weaker because a modern station at the
    cell edge transmits only low rates and can look legacy from rates alone."""
    if declared_ht is True:
        return ("802.11n+ (HT/VHT/HE)", False, "declared")
    if declared_ht is False:
        # Genuinely pre-802.11n. Split 11b (CCK) from 11a/g (OFDM) by data rates.
        if rate_max is not None and rate_max <= 11.0:
            return ("802.11b (DSSS/CCK)", True, "declared")
        return ("802.11a/g (OFDM, pre-n)", True, "declared")
    # No capability frame seen — fall back to observed data rates (weaker).
    if rate_min is None:
        return (None, False, None)
    if rate_max <= 11.0 and rate_min in _DSSS_RATES:
        return ("802.11b (DSSS/CCK)", True, "observed")
    if rate_max <= 54.0:
        return ("802.11a/g (OFDM)", True, "observed")
    return ("802.11n+ (HT/VHT/HE)", False, "observed")


# Management subtypes that indicate a client (re)joining / roaming.
_ROAM_SUBTYPES = {0: "assoc", 2: "reassoc", 11: "auth"}


def analyze_airtime(events, seconds=None):
    """Per-AP airtime %, retry rate and PHY-rate spread, plus roaming churn."""
    import statistics
    seconds = seconds or 1
    aps = {}
    roam = {}
    clients = {}                             # per-transmitter (addr2) airtime
    for e in events:
        b = e.get("bssid")
        # Airtime/retry keyed on the AP (BSSID) for data + mgmt frames.
        if b:
            ap = aps.setdefault(b, {"bssid": b, "ssid": None, "frames": 0,
                                    "retries": 0, "airtime_us": 0.0, "rates": [],
                                    "rssi": None, "data_frames": 0,
                                    "erp_protection": False, "erp_nonerp": False,
                                    "security": None, "ap_phy": None,
                                    "group_cipher": None, "pairwise_ciphers": None,
                                    "ht_protection": None, "basic_cck": False,
                                    "wps": None})
            ap["frames"] += 1
            if e.get("ssid"):
                ap["ssid"] = e["ssid"]
            if e.get("security"):
                ap["security"] = e["security"]
            if e.get("ap_phy"):
                ap["ap_phy"] = e["ap_phy"]
            if e.get("group_cipher"):
                ap["group_cipher"] = e["group_cipher"]
            if e.get("pairwise_ciphers"):
                ap["pairwise_ciphers"] = e["pairwise_ciphers"]
            if e.get("ht_protection") is not None:
                ap["ht_protection"] = e["ht_protection"]
            if e.get("basic_cck"):
                ap["basic_cck"] = True
            if e.get("wps"):
                ap["wps"] = e["wps"]
            if e.get("retry"):
                ap["retries"] += 1
            if e["type"] == 2:               # data
                ap["data_frames"] += 1
            ap["airtime_us"] += _frame_airtime_us(e)
            if e.get("rate_mbps"):
                ap["rates"].append(e["rate_mbps"])
            if e.get("rssi") is not None:
                ap["rssi"] = e["rssi"]
            # ERP is latched: once the AP announces protection in the window,
            # a legacy client was present even if later beacons clear the bit.
            if e.get("erp_protection"):
                ap["erp_protection"] = True
            if e.get("erp_nonerp"):
                ap["erp_nonerp"] = True
        # Per-client airtime attribution keyed on the STATION (both directions),
        # never the AP. Airtime counts every data/mgmt frame the station is an
        # endpoint of; but PHY-rate observation uses DATA frames ONLY — mgmt and
        # control frames are sent at basic rates even by modern clients, so
        # mixing them in would mislabel a Wi-Fi 6 phone as 802.11b.
        sta = e.get("sta")
        if sta and not _is_group_mac(sta) and sta != e.get("bssid") and e["type"] in (0, 2):
            c = clients.setdefault(sta, {"client": sta, "bssid": e.get("bssid"),
                                         "frames": 0, "airtime_us": 0.0,
                                         "data_bytes": 0, "rates": [], "rssi": None,
                                         "declared_ht": None, "retries": 0})
            c["frames"] += 1
            if not c["bssid"]:
                c["bssid"] = e.get("bssid")
            c["airtime_us"] += _frame_airtime_us(e)
            if e.get("retry"):
                c["retries"] += 1
            if e["type"] == 2:                       # data frames only for PHY
                c["data_bytes"] += e.get("bytes", 0)
                if e.get("rate_mbps"):
                    c["rates"].append(e["rate_mbps"])
            dh = e.get("declared_ht")                # capability from (re)assoc/probe req
            if dh is True:
                c["declared_ht"] = True              # HT present wins definitively
            elif dh is False and c["declared_ht"] is None:
                c["declared_ht"] = False
            if e.get("rssi") is not None:
                c["rssi"] = e["rssi"]
        # Roaming: a client (src) sending assoc/reassoc/auth frames.
        if e["type"] == 0 and e["subtype"] in _ROAM_SUBTYPES and e.get("src"):
            r = roam.setdefault(e["src"], {"client": e["src"], "assoc": 0,
                                           "reassoc": 0, "auth": 0})
            r[_ROAM_SUBTYPES[e["subtype"]]] += 1

    ap_list = []
    for ap in aps.values():
        rates = ap.pop("rates")
        ap["retry_pct"] = round(ap["retries"] / ap["frames"] * 100, 1) if ap["frames"] else 0
        ap["airtime_pct"] = round(ap["airtime_us"] / (seconds * 1e6) * 100, 1)
        ap["rate_min"] = min(rates) if rates else None
        ap["rate_med"] = round(statistics.median(rates), 1) if rates else None
        ap["rate_max"] = max(rates) if rates else None
        ap["airtime_us"] = round(ap["airtime_us"])
        ap_list.append(ap)
    ap_list.sort(key=lambda a: -a["airtime_pct"])

    # Map each BSSID to its SSID so clients can show the network they're on.
    ssid_by_bssid = {a["bssid"]: a["ssid"] for a in ap_list if a.get("ssid")}

    client_list = []
    total_air = sum(c["airtime_us"] for c in clients.values()) or 1.0
    total_bytes = sum(c["data_bytes"] for c in clients.values()) or 1
    for c in clients.values():
        rates = c.pop("rates")
        c["airtime_pct"] = round(c["airtime_us"] / (seconds * 1e6) * 100, 1)
        c["rate_min"] = min(rates) if rates else None
        c["rate_med"] = round(statistics.median(rates), 1) if rates else None
        c["rate_max"] = max(rates) if rates else None
        c["phy"], c["legacy"], c["confidence"] = _classify_client_phy(
            c["declared_ht"], c["rate_min"], c["rate_max"])
        c["is_11b"] = bool(c["phy"] and c["phy"].startswith("802.11b"))
        c["retry_pct"] = round(c["retries"] / c["frames"] * 100, 1) if c["frames"] else 0
        # Airtime-vs-bytes disproportion — the number that settles "who is
        # making the cell slow": a station carrying few bytes but eating lots
        # of airtime is the culprit. share_air / share_bytes.
        air_share = c["airtime_us"] / total_air
        byte_share = c["data_bytes"] / total_bytes
        c["airtime_share_pct"] = round(air_share * 100, 1)
        c["byte_share_pct"] = round(byte_share * 100, 1)
        c["disproportion"] = round(air_share / byte_share, 1) if byte_share > 0 else None
        c["ssid"] = ssid_by_bssid.get(c.get("bssid"))
        c["airtime_us"] = round(c["airtime_us"])
        client_list.append(c)
    client_list.sort(key=lambda c: -c["airtime_pct"])

    # Roaming churn = a client re-associating/authing repeatedly.
    roam_list = [r for r in roam.values() if (r["reassoc"] + r["auth"]) >= 3]
    roam_list.sort(key=lambda r: -(r["reassoc"] + r["auth"]))

    findings = []
    # BSS-wide "why is it slow": ERP protection turned on = a legacy DSSS client
    # is imposing RTS/CTS overhead on every station in the cell.
    for ap in ap_list:
        if ap.get("security") in ("Open", "WEP"):
            name = ap["ssid"] or ap["bssid"]
            findings.append({"type": "weak_security", "bssid": ap["bssid"],
                             "detail": f"{name} is {ap['security']} — "
                                       + ("no encryption" if ap["security"] == "Open"
                                          else "WEP is broken, treat as open")})
        if ap.get("erp_protection"):
            name = ap["ssid"] or ap["bssid"]
            findings.append({"type": "erp_protection", "bssid": ap["bssid"],
                             "detail": f"{name} has ERP protection ON — a legacy "
                                       "802.11b client is taxing the whole BSS "
                                       "(RTS/CTS overhead on every frame)"})
        if ap.get("ht_protection") == 3:
            name = ap["ssid"] or ap["bssid"]
            findings.append({"type": "ht_protection_mixed", "bssid": ap["bssid"],
                             "detail": f"{name} HT Protection = Non-HT Mixed — a "
                                       "pre-802.11n station is associated, so 11n "
                                       "rates are protected BSS-wide"})
        if ap.get("group_cipher") == "TKIP":
            name = ap["ssid"] or ap["bssid"]
            findings.append({"type": "cipher_tkip_group", "bssid": ap["bssid"],
                             "detail": f"{name} group cipher is TKIP — 802.11n "
                                       "rates are disabled for group-addressed "
                                       "frames BSS-wide (a throughput cap, not just "
                                       "a security issue)"})
        elif ap.get("pairwise_ciphers") and "TKIP" in ap["pairwise_ciphers"]:
            name = ap["ssid"] or ap["bssid"]
            findings.append({"type": "cipher_tkip_pairwise", "bssid": ap["bssid"],
                             "detail": f"{name} offers TKIP pairwise — any client "
                                       "selecting it is hard-capped at 54 Mbps"})
        # WPS posture — the 1-button / PIN enrollment surface.
        w = ap.get("wps")
        if w and w.get("present"):
            name = ap["ssid"] or ap["bssid"]
            if w.get("pin_method") and w.get("locked") is not True:
                sev = "WSC 1.0 (no lockout — fully brute-forceable)" if not w.get("version2") \
                    else "PIN method, not locked"
                findings.append({"type": "wps_pin_open", "bssid": ap["bssid"],
                                 "detail": f"{name} WPS PIN enrollment is exposed "
                                           f"[{sev}] — an attacker in range can "
                                           "brute-force the 8-digit PIN; disable WPS "
                                           "or use pushbutton-only"})
            elif w.get("pin_method") and not w.get("version2"):
                findings.append({"type": "wps_v1", "bssid": ap["bssid"],
                                 "detail": f"{name} advertises WSC 1.0 with the PIN "
                                           "method — no mandatory attempt lockout"})
            else:
                findings.append({"type": "wps_enabled", "bssid": ap["bssid"],
                                 "detail": f"{name} has WPS enabled"
                                           + (" (pushbutton-only)" if w.get("pushbutton")
                                              and not w.get("pin_method") else "")})
            if w.get("configured") is False:
                findings.append({"type": "wps_unconfigured", "bssid": ap["bssid"],
                                 "detail": f"{name} WPS state is Not Configured — "
                                           "out-of-box enrollment is open"})
    # Pinpoint the culprit: an 802.11b (CCK) station eating airtime out of all
    # proportion to the bytes it moves is what makes the cell slow. Disproportion
    # (airtime share ÷ byte share) is the number that settles the argument.
    for c in client_list:
        if c["is_11b"] and (c["airtime_pct"] >= 5 or c["frames"] >= 20):
            disp = f", {c['disproportion']}× its byte share" if c.get("disproportion") else ""
            findings.append({"type": "slow_client", "client": c["client"],
                             "detail": f"{c['client']} is 802.11b @ "
                                       f"{c['rate_min']}–{c['rate_max']} Mbps "
                                       f"({c['confidence']}), ~{c['airtime_pct']}% airtime"
                                       f"{disp} — the airtime tax; "
                                       "move it to its own SSID or 5 GHz"})
        # Outdated but not the CCK tax: a/g (pre-802.11n) OFDM stations.
        elif c["legacy"] and not c["is_11b"] and (c["airtime_pct"] >= 5 or c["frames"] >= 20):
            findings.append({"type": "legacy_client", "client": c["client"],
                             "detail": f"{c['client']} is {c['phy']} ({c['confidence']}) "
                                       f"— pre-802.11n, ~{c['airtime_pct']}% airtime"})
    for ap in ap_list:
        if ap["retry_pct"] >= 30 and ap["frames"] >= 20:
            findings.append({"type": "high_retry", "bssid": ap["bssid"],
                             "detail": f"{ap['bssid']} retry rate {ap['retry_pct']}% "
                                       f"({ap['retries']}/{ap['frames']}) — poor link"})
        if ap["airtime_pct"] >= 50:
            findings.append({"type": "airtime_hog", "bssid": ap["bssid"],
                             "detail": f"{ap['bssid']} using ~{ap['airtime_pct']}% airtime"})
    for r in roam_list:
        findings.append({"type": "roaming_churn", "client": r["client"],
                         "detail": f"{r['client']} re-joined {r['reassoc'] + r['auth']}× "
                                   "(reassoc/auth) — roaming instability"})

    return {"aps": ap_list, "clients": client_list, "roaming": roam_list,
            "findings": findings, "frames": len(events), "seconds": seconds}


def enrich_identity(clients, host_map=None, vendor_lookup=None):
    """Join network-layer identity onto the radio-layer per-client rows by MAC.

    The monitor radio sees WHO is 802.11b (by MAC); the connected radio's host
    inventory knows WHAT each MAC is (ip / hostname / vendor / device type).
    This fuses the two so a legacy client reads as e.g. "HP printer
    (HP-LaserJet, 192.168.1.42)" instead of a bare MAC.

    Pure: the caller supplies ``host_map`` (mac→record from the hosts DB) and an
    optional ``vendor_lookup(mac)->str`` OUI fallback for MACs not yet in the
    inventory. Mutates and returns ``clients``."""
    host_map = host_map or {}
    for c in clients:
        mac = (c.get("client") or "").lower()
        rec = host_map.get(mac) or {}
        c["ip"] = rec.get("ip") or None
        c["hostname"] = rec.get("hostname") or None
        vendor = rec.get("vendor")
        if not vendor and vendor_lookup:
            try:
                v = vendor_lookup(mac)
                vendor = v if v and v != "Randomized" else None
            except Exception:
                vendor = None
        c["vendor"] = vendor or None
        c["device_type"] = rec.get("device_type") or None
        c["device_label"] = rec.get("device_label") or None
        # A device we could actually name from the network side.
        c["identified"] = bool(c["hostname"] or c["ip"])
    return clients


# --------------------------------------------------------------------------
# Client-isolation observer  (passive AP/mesh peer-traffic audit)
# --------------------------------------------------------------------------
# Infers whether an AP (or a whole mesh/ESS) enforces client isolation purely
# from the cleartext 802.11 data-frame headers — encryption hides the payload,
# but the DS bits + addr1/2/3 always reveal WHO the AP is relaying frames FOR:
#   ToDS   (STA->AP):  addr1=BSSID, addr2=SA (the wireless client), addr3=DA
#   FromDS (AP->STA):  addr1=DA (the wireless client), addr2=BSSID, addr3=SA
# If the AP transmits a FromDS frame whose SA is one of its own wireless
# clients, it just relayed intra-BSS traffic — client isolation is OFF.

def _is_group_mac(mac):
    """True for broadcast/multicast (group) addresses — the 0x01 bit."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x01)
    except (AttributeError, ValueError, IndexError):
        return False


def _iso_event(pkt):
    """Normalize a frame for the isolation observer (or None). Keeps beacons
    (they name the BSS so the report can group a mesh by SSID) and data frames
    with their DS bits + addresses."""
    from scapy.all import Dot11, Dot11Elt
    if not pkt.haslayer(Dot11):
        return None
    d = pkt.getlayer(Dot11)
    if d.type == 0 and d.subtype == 8:           # beacon -> BSSID/SSID naming
        ev = {"kind": "beacon", "bssid": (d.addr3 or "").lower() or None,
              "ssid": None}
        el = pkt.getlayer(Dot11Elt)
        while el is not None and isinstance(el, Dot11Elt):
            if el.ID == 0:
                try:
                    ev["ssid"] = el.info.decode(errors="replace")
                except Exception:
                    ev["ssid"] = None
                break
            el = el.payload.getlayer(Dot11Elt)
        return ev
    if d.type != 2:                              # 2 = data
        return None
    fc = int(getattr(d, "FCfield", 0) or 0)
    tods, fromds = bool(fc & 0x01), bool(fc & 0x02)
    a1 = (d.addr1 or "").lower() or None
    a2 = (d.addr2 or "").lower() or None
    a3 = (d.addr3 or "").lower() or None
    if tods and fromds:                          # 4-address = WDS/mesh backhaul
        return {"kind": "wds", "ta": a2, "ra": a1}
    if tods:
        return {"kind": "tods", "bssid": a1, "sa": a2, "da": a3}
    if fromds:
        return {"kind": "fromds", "bssid": a2, "sa": a3, "da": a1}
    return None                                  # IBSS frames aren't AP-relayed


def parse_pcap_iso(path):
    """Read a pcap into isolation-observer events (for tests / offline runs)."""
    from scapy.all import rdpcap
    return [e for e in (_iso_event(p) for p in rdpcap(path)) if e]


def analyze_isolation(events, seconds=None):
    """Per-BSS client-isolation verdict from passively observed frames. Pure.

    Evidence, weakest to strongest:
    - bcast_sent:   a client sent a broadcast up (ARP etc.) — a working,
                    non-isolated AP re-broadcasts these into the cell;
    - attempts:     a client addressed a ToDS frame at ANOTHER wireless client
                    of the same BSS (someone is trying to reach a WLAN peer);
    - bcast_relays: the AP re-broadcast a client-originated broadcast;
    - relays:       the AP forwarded unicast client->client traffic.
    Verdicts: 'open' (unicast relays seen — isolation OFF), 'broadcast_open'
    (client broadcasts forwarded, no unicast peer traffic observed),
    'isolating' (peer attempts and/or repeated client broadcasts, yet the AP
    relayed nothing back — it is filtering), 'no_evidence' otherwise."""
    seconds = seconds or 0
    names = {}                                   # bssid -> ssid (from beacons)
    bss = {}
    wds_frames = 0

    def _rec(b):
        return bss.setdefault(b, {"clients": set(), "attempts": 0, "relays": 0,
                                  "bcast_sent": 0, "bcast_relays": 0,
                                  "frames": 0, "pairs": {}})

    # Pass 1: name BSSes and learn each one's wireless clients. A STA proves it
    # is a wireless client by transmitting ToDS, or by being the unicast RA of
    # a FromDS frame (the AP only airs FromDS to associated wireless STAs).
    for e in events:
        k = e.get("kind")
        if k == "beacon":
            if e.get("bssid") and e.get("ssid"):
                names[e["bssid"]] = e["ssid"]
            continue
        if k == "wds":
            wds_frames += 1
            continue
        b = e.get("bssid")
        if not b or _is_group_mac(b):
            continue
        r = _rec(b)
        r["frames"] += 1
        if k == "tods" and e.get("sa"):
            r["clients"].add(e["sa"])
        elif k == "fromds":
            da = e.get("da")
            if da and da != b and not _is_group_mac(da):
                r["clients"].add(da)

    # Pass 2: with the client sets complete, classify every data frame.
    for e in events:
        k = e.get("kind")
        b = e.get("bssid")
        if k not in ("tods", "fromds") or b not in bss:
            continue
        r = bss[b]
        sa, da = e.get("sa"), e.get("da")
        if k == "tods":
            if da and _is_group_mac(da):
                r["bcast_sent"] += 1
            elif sa and da and da != sa and da != b and da in r["clients"]:
                r["attempts"] += 1
        else:                                    # fromds — what the AP relayed
            if not sa or sa == b or sa not in r["clients"]:
                continue                         # upstream/wired source: normal
            if da and _is_group_mac(da):
                r["bcast_relays"] += 1
            elif da and da != sa and da in r["clients"]:
                r["relays"] += 1
                key = tuple(sorted((sa, da)))
                r["pairs"][key] = r["pairs"].get(key, 0) + 1

    bss_list = []
    for b, r in bss.items():
        if r["relays"]:
            verdict = "open"
        elif r["bcast_relays"]:
            verdict = "broadcast_open"
        elif r["attempts"] or (r["bcast_sent"] >= 3 and len(r["clients"]) >= 1):
            verdict = "isolating"
        else:
            verdict = "no_evidence"
        pairs = sorted(r["pairs"].items(), key=lambda kv: -kv[1])[:8]
        bss_list.append({
            "bssid": b, "ssid": names.get(b),
            "clients": len(r["clients"]),
            "client_list": sorted(r["clients"])[:24],
            "attempts": r["attempts"], "relays": r["relays"],
            "bcast_sent": r["bcast_sent"], "bcast_relays": r["bcast_relays"],
            "frames": r["frames"], "verdict": verdict,
            "pairs": [[a, c, n] for (a, c), n in pairs],
        })
    bss_list.sort(key=lambda x: -x["frames"])

    # ESS/mesh view: group nodes by SSID. Cross-node relays = a node forwarding
    # traffic sourced from a client that only ever appeared on a SIBLING node.
    ess_list = []
    by_ssid = {}
    for x in bss_list:
        if x["ssid"]:
            by_ssid.setdefault(x["ssid"], []).append(x)
    for ssid, nodes in by_ssid.items():
        if len(nodes) < 2:
            continue
        node_set = {n["bssid"] for n in nodes}
        clients_elsewhere = {}
        for n in nodes:
            for c in n["client_list"]:
                clients_elsewhere.setdefault(c, set()).add(n["bssid"])
        cross = 0
        for e in events:
            if e.get("kind") != "fromds" or e.get("bssid") not in node_set:
                continue
            sa = e.get("sa")
            homes = clients_elsewhere.get(sa)
            if homes and e["bssid"] not in homes:
                cross += 1
        verdicts = {n["verdict"] for n in nodes}
        if "open" in verdicts or cross:
            verdict = "open"
        elif "broadcast_open" in verdicts:
            verdict = "broadcast_open"
        elif "isolating" in verdicts:
            verdict = "isolating"
        else:
            verdict = "no_evidence"
        ess_list.append({"ssid": ssid, "nodes": sorted(node_set),
                         "node_count": len(nodes),
                         "clients": len(clients_elsewhere),
                         "cross_relays": cross, "verdict": verdict})
    ess_list.sort(key=lambda x: -x["node_count"])

    data_frames = sum(x["frames"] for x in bss_list)
    return {"bss": bss_list, "ess": ess_list, "wds_frames": wds_frames,
            "frames": data_frames, "seconds": seconds}


# --------------------------------------------------------------------------
# Live capture
# --------------------------------------------------------------------------

def _capture_error(mon_iface, exc):
    """Friendly, actionable message for a sniff failure. ENODEV (the monitor vif
    vanished) is flagged so callers can rebuild it and retry."""
    enodev = isinstance(exc, OSError) and getattr(exc, "errno", None) == errno.ENODEV
    # Some scapy/libpcap builds surface ENODEV as a plain error string, not OSError.
    if not enodev and re.search(r"No such device|errno 19|\[Errno 19\]", str(exc), re.I):
        enodev = True
    if enodev:
        return {"error": f"capture failed: monitor interface '{mon_iface}' "
                         "disappeared (Errno 19). The adapter may have been "
                         "unplugged or reset — rebuilding monitor mode.",
                "enodev": True}
    return {"error": f"capture failed: {exc}"}


def _refresh_scapy_ifaces():
    """Drop scapy's cached interface table so it re-reads the live ifindex.

    scapy caches a NetworkInterface object (with a fixed .index) per name at
    import time and binds its AF_PACKET/monitor socket using that. When we
    delete+recreate the monitor vif — a disable→re-enable, or an ENODEV rebuild —
    ragmon0 comes back with a NEW ifindex, but scapy keeps the stale cached one
    and every sniff() then fails with ENODEV. A fresh process rebuilds this cache,
    which is exactly why 'systemctl restart ragnar' heals it while a runtime
    re-enable does not. Reload it ourselves so the running service self-heals too
    (scapy's own resolve_iface() does the same reload as its miss fallback)."""
    try:
        from scapy.all import conf
        conf.ifaces.reload()
    except Exception:
        pass


def _capture_recover(capture_fn, interface, seconds, channel, auto_enable):
    """Resolve a live monitor, capture, and — if the vif dies around capture time
    (ENODEV) — rebuild it once and retry. Returns an events list, or an
    {"error": …} dict. This is what makes 'ragmon0 is gone again' self-heal for
    both the WIDS scan and the airtime/link-quality capture."""
    mon = _resolve_monitor(interface, auto_enable=auto_enable)
    if isinstance(mon, dict):
        return mon
    _refresh_scapy_ifaces()                   # pick up the current ifindex of `mon`
    events = capture_fn(mon, seconds, channel=channel)
    if isinstance(events, dict) and events.get("enodev") and auto_enable:
        _save_state({})                       # drop the dead vif bookkeeping
        mon = _resolve_monitor(interface, auto_enable=True)   # force a rebuild
        if isinstance(mon, dict):
            return mon
        _refresh_scapy_ifaces()               # the rebuild gave `mon` a new ifindex
        events = capture_fn(mon, seconds, channel=channel)
    return events


def _capture(mon_iface, seconds, channel=None):
    """Sniff management frames on `mon_iface` for `seconds`, hopping channels
    unless a fixed `channel` is given. Returns a list of event dicts."""
    from scapy.all import sniff
    events = []

    def _cb(pkt):
        ev = _frame_to_event(pkt)
        if ev:
            events.append(ev)

    stop = threading.Event()
    if channel:
        _set_channel(mon_iface, channel)
    else:
        targets = _hop_targets(_load_state().get("six_ghz", False))
        def _hopper():
            i = 0
            while not stop.is_set():
                _tune(mon_iface, targets[i % len(targets)])
                i += 1
                stop.wait(0.35)
        threading.Thread(target=_hopper, daemon=True).start()

    # Only management frames (type 0) — keeps the sniffer cheap.
    try:
        sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False,
              filter="type mgt", monitor=True)
    except Exception:
        # Some drivers reject the BPF/monitor kwarg; retry unfiltered.
        try:
            sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False)
        except Exception as exc:
            stop.set()
            return _capture_error(mon_iface, exc)
    stop.set()
    return events


def _capture_all(mon_iface, seconds, channel=None):
    """Sniff ALL 802.11 frames (data + mgmt) for airtime/retry analysis. Best on
    a FIXED channel — airtime % is only meaningful when we dwell on one channel."""
    from scapy.all import sniff
    events = []

    def _cb(pkt):
        ev = _airtime_event(pkt)
        if ev:
            events.append(ev)

    stop = threading.Event()
    if channel:
        _set_channel(mon_iface, channel)
    else:
        targets = _hop_targets(_load_state().get("six_ghz", False))
        def _hopper():
            i = 0
            while not stop.is_set():
                _tune(mon_iface, targets[i % len(targets)])
                i += 1
                stop.wait(0.35)
        threading.Thread(target=_hopper, daemon=True).start()
    try:
        sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False, monitor=True)
    except Exception:
        try:
            sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False)
        except Exception as exc:
            stop.set()
            return _capture_error(mon_iface, exc)
    stop.set()
    return events


def _capture_iso(mon_iface, seconds, channel=None):
    """Sniff data frames + beacons for the client-isolation observer. Best on
    a FIXED channel — catching both a peer attempt and the AP's relay of it
    needs to dwell where the BSS lives."""
    from scapy.all import sniff
    events = []

    def _cb(pkt):
        ev = _iso_event(pkt)
        if ev:
            events.append(ev)

    stop = threading.Event()
    if channel:
        _set_channel(mon_iface, channel)
    else:
        targets = _hop_targets(_load_state().get("six_ghz", False))
        def _hopper():
            i = 0
            while not stop.is_set():
                _tune(mon_iface, targets[i % len(targets)])
                i += 1
                stop.wait(0.35)
        threading.Thread(target=_hopper, daemon=True).start()
    try:
        sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False, monitor=True)
    except Exception:
        try:
            sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False)
        except Exception as exc:
            stop.set()
            return _capture_error(mon_iface, exc)
    stop.set()
    return events


def do_isolation(interface, seconds=20, channel=None, auto_enable=True):
    """Ensure monitor mode, observe a window of data frames, and report each
    BSS's client-isolation behaviour (plus a mesh/ESS rollup). Receive-only."""
    if not _valid_iface(interface):
        return {"error": "invalid interface"}
    seconds = max(5, min(120, int(seconds)))
    events = _capture_recover(_capture_iso, interface, seconds, channel, auto_enable)
    if isinstance(events, dict) and "error" in events:
        return events
    mon = _load_state().get("mon_iface")
    result = analyze_isolation(events, seconds=seconds)
    result.update({"interface": interface, "monitor": mon, "channel": channel,
                   "hopping": channel is None, "timestamp": int(time.time())})
    return result


def do_airtime(interface, seconds=10, channel=None, auto_enable=True):
    """Ensure monitor mode, capture a window (ideally on a fixed channel), and
    return per-AP airtime/retry/rate + roaming-churn diagnostics."""
    if not _valid_iface(interface):
        return {"error": "invalid interface"}
    seconds = max(3, min(60, int(seconds)))
    events = _capture_recover(_capture_all, interface, seconds, channel, auto_enable)
    if isinstance(events, dict) and "error" in events:
        return events
    mon = _load_state().get("mon_iface")
    result = analyze_airtime(events, seconds=seconds)
    result.update({"interface": interface, "monitor": mon, "channel": channel,
                   "hopping": channel is None, "timestamp": int(time.time())})
    return result


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def analyze(events, baseline=None, window_secs=None, thresholds=None):
    """Classify a list of frame events into WIDS detections. Pure function."""
    baseline = baseline or {}
    th = thresholds or {}
    beacon_ssid_max = int(th.get("beacon_ssids", _BEACON_FLOOD_SSIDS))
    beacon_bssid_max = int(th.get("beacon_bssids", _BEACON_FLOOD_BSSIDS))
    deauths = [e for e in events if e["kind"] in ("deauth", "disassoc")]
    beacons = [e for e in events if e["kind"] == "beacon"]
    presp = [e for e in events if e["kind"] == "probe_resp"]

    detections = []

    # --- Deauth / disassoc flood ---
    if deauths:
        pairs = {}
        for e in deauths:
            key = (e.get("src") or "?", e.get("dst") or "?")
            pairs[key] = pairs.get(key, 0) + 1
        top = sorted(pairs.items(), key=lambda kv: -kv[1])[:5]
        sev = "flood" if len(deauths) >= _DEAUTH_FLOOD_MIN else "seen"
        # Scope: broadcast (to all clients — the classic mdk4 signature) vs
        # targeted. And the Protected-Frame posture: an all-unprotected burst is a
        # spoof, and on a PMF/6 GHz network it's an (ineffective but anomalous)
        # bypass attempt worth surfacing.
        _bcast = {"ff:ff:ff:ff:ff:ff", None}
        bcast_n = sum(1 for e in deauths if e.get("dst") in _bcast)
        unprotected = sum(1 for e in deauths if e.get("protected") is False)
        reasons = {}
        for e in deauths:
            if e.get("reason") is not None:
                reasons[e["reason"]] = reasons.get(e["reason"], 0) + 1
        dom_reason = max(reasons, key=reasons.get) if reasons else None
        scope = "broadcast" if bcast_n >= max(1, len(deauths) * 0.5) else "targeted"
        detail = f"{len(deauths)} deauth/disassoc frames"
        if sev == "flood":
            detail += f" — {scope} flood/DoS in progress"
        if dom_reason is not None:
            detail += f" (reason {dom_reason})"
        if unprotected == len(deauths) and len(deauths) >= _DEAUTH_FLOOD_MIN:
            detail += " — all unprotected (spoofed; PMF-bypass attempt on 802.11w nets)"
        detections.append({
            "type": "deauth", "severity": sev, "count": len(deauths),
            "scope": scope, "broadcast": bcast_n, "unprotected": unprotected,
            "reason": dom_reason,
            "attackers": [{"src": k[0], "dst": k[1], "count": n} for k, n in top],
            "detail": detail,
        })

    # --- Beacon flood ---
    # A real flood produces hundreds of distinct SSIDs/BSSIDs — far above any home
    # or apartment block. The threshold is user-tunable so it can be calibrated to
    # the local RF density (see get/set_thresholds). The live counts are always
    # reported (below, in `airspace`) so the user can see where they sit.
    if beacons:
        la_ratio_min = float(th.get("beacon_la_ratio", _BEACON_LA_RATIO))
        la_bssid_min = int(th.get("beacon_la_bssid_min", _BEACON_LA_BSSID_MIN))
        ssids = {e["ssid"] for e in beacons if e.get("ssid")}
        bssids = {e["src"] for e in beacons if e.get("src")}
        rnd_bssids = {b for b in bssids if _is_locally_administered(b)}
        la_ratio = (len(rnd_bssids) / len(bssids)) if bssids else 0.0
        reasons = []
        if len(ssids) >= beacon_ssid_max:
            reasons.append(f"{len(ssids)} distinct SSIDs (≥{beacon_ssid_max})")
        if len(bssids) >= beacon_bssid_max:
            reasons.append(f"{len(bssids)} distinct BSSIDs (≥{beacon_bssid_max})")
        # Randomized-BSSID burst: mdk4's beacon mode emits random (locally-
        # administered) MACs, so a burst of high-LA BSSIDs is a fake-AP storm even
        # BELOW the absolute count threshold — while ordinary neighbourhood density
        # uses burned-in (global) MACs (~0% LA) and stays quiet. This is what makes
        # detection robust in dense RF instead of guessing an absolute count.
        la_burst = len(bssids) >= la_bssid_min and la_ratio >= la_ratio_min
        if la_burst:
            reasons.append(f"{len(rnd_bssids)}/{len(bssids)} BSSIDs randomized "
                           f"(LA ratio {la_ratio:.0%} ≥ {la_ratio_min:.0%})")
        if reasons:
            # Critical when the burst is randomized (mdk4 signature); a dense but
            # non-randomized airspace over the absolute threshold is a warning.
            sev = "flood" if (la_burst or la_ratio >= la_ratio_min) else "beacon_warn"
            detections.append({
                "type": "beacon_flood", "severity": sev,
                "ssids": len(ssids), "bssids": len(bssids),
                "random_bssids": len(rnd_bssids), "la_ratio": round(la_ratio, 2),
                "detail": "fake-AP/beacon flood — " + ", ".join(reasons),
            })

    # --- Auth-frame flood (client-table exhaustion) ---
    # HaleHound "Auth Flood" / mdk4 'a' / Marauder: many random-MAC auth requests
    # aimed at one AP. Group auth frames by target BSSID (dst = addr1); flag any
    # target hit by a burst from many distinct sources. A high locally-administered
    # source ratio is the spoof signature that separates it from real roaming.
    auths = [e for e in events if e["kind"] == "auth"]
    if auths:
        auth_min = int(th.get("auth_flood_frames", _AUTH_FLOOD_MIN))
        src_min = int(th.get("auth_flood_srcs", _AUTH_FLOOD_SRCS))
        la_min = float(th.get("auth_la_ratio", _AUTH_LA_RATIO))
        by_target = {}
        for e in auths:
            dst = e.get("dst")
            if not dst or dst in _BCAST_ADDRS:
                continue
            t = by_target.setdefault(dst, {"frames": 0, "srcs": set()})
            t["frames"] += 1
            if e.get("src"):
                t["srcs"].add(e["src"])
        for bssid, t in sorted(by_target.items(), key=lambda kv: -kv[1]["frames"]):
            n_src = len(t["srcs"])
            if t["frames"] < auth_min or n_src < src_min:
                continue
            rnd = {s for s in t["srcs"] if _is_locally_administered(s)}
            la_ratio = (len(rnd) / n_src) if n_src else 0.0
            spoofed = la_ratio >= la_min
            sev = "flood" if spoofed else "auth_warn"
            detail = (f"{t['frames']} auth frames at {bssid} from {n_src} "
                      f"distinct MACs — authentication flood / client-table "
                      f"exhaustion")
            if spoofed:
                detail += (f" ({len(rnd)}/{n_src} sources randomized, "
                           f"LA ratio {la_ratio:.0%} — spoofed)")
            detections.append({
                "type": "auth_flood", "severity": sev, "bssid": bssid,
                "count": t["frames"], "sources": n_src,
                "random_sources": len(rnd), "la_ratio": round(la_ratio, 2),
                "detail": detail,
            })

    # --- KARMA / MANA: one BSSID answering many SSIDs ---
    by_ap = {}
    for e in presp + beacons:
        src = e.get("src")
        if src and e.get("ssid"):
            by_ap.setdefault(src, set()).add(e["ssid"])
    karma = [{"bssid": b, "ssids": sorted(s), "count": len(s)}
             for b, s in by_ap.items() if len(s) >= _KARMA_SSID_MIN]
    for k in sorted(karma, key=lambda x: -x["count"]):
        detections.append({
            "type": "karma", "severity": "karma", "bssid": k["bssid"],
            "ssid_count": k["count"], "ssids": k["ssids"][:12],
            "detail": f"{k['bssid']} answered {k['count']} different SSIDs — "
                      "KARMA/MANA rogue AP",
        })

    # --- Rogue AP / evil twin: SSID from an unexpected BSSID ---
    seen = {}
    for e in beacons + presp:
        # Skip hidden/cloaked SSIDs (blank or NUL-filled): several unrelated
        # hidden APs share the same empty name and would false-flag as a
        # duplicate/evil twin, which is meaningless — nothing to impersonate.
        if e.get("ssid") and e.get("src") and not _is_blank_ssid(e["ssid"]):
            seen.setdefault(e["ssid"], set()).add(e["src"])
    for ssid, bssids in seen.items():
        trusted = set(baseline.get(ssid, []))
        if trusted:
            rogue = bssids - trusted
            if rogue:
                detections.append({
                    "type": "rogue_ap", "severity": "evil_twin", "ssid": ssid,
                    "rogue_bssids": sorted(rogue), "trusted_bssids": sorted(trusted),
                    "detail": f"SSID '{ssid}' seen from untrusted BSSID(s) "
                              + ", ".join(sorted(rogue)),
                })
        elif len(bssids) >= 2:
            # A tri-band router / vendor mesh legitimately puts one SSID on
            # several radios from the SAME global OUI. Down-rank that to an
            # informational 'band_steering' note so it stops reading as a
            # possible evil twin (and stops feeding the HaleHound trace score).
            # An evil twin clones from a different / randomized BSSID, so its
            # OUIs won't cohere — that still surfaces as 'duplicate_ssid'.
            if _is_band_steering(bssids):
                detections.append({
                    "type": "rogue_ap", "severity": "band_steering", "ssid": ssid,
                    "bssids": sorted(bssids), "oui": _oui(sorted(bssids)[0]),
                    "detail": f"SSID '{ssid}' on {len(bssids)} BSSIDs sharing one "
                              f"vendor OUI ({_oui(sorted(bssids)[0])}) — "
                              "band-steering/mesh, not an evil twin",
                })
            else:
                detections.append({
                    "type": "rogue_ap", "severity": "duplicate_ssid", "ssid": ssid,
                    "bssids": sorted(bssids),
                    "detail": f"SSID '{ssid}' advertised by {len(bssids)} BSSIDs "
                              "(possible evil twin — set a baseline to confirm)",
                })

    # --- Attack-tool SSID: a beacon whose name is a known ESP32/handheld attack
    # multitool or captive-portal default (EvilPortal, Marauder, Ghost ESP, GARMR,
    # …). These names are never legitimate, so this is a HIGH-confidence flag on
    # its own — the lone-lure captive-portal case the passive WIDS otherwise can't
    # see without a real AP to clone. Fires open OR secured. ---
    _attack_seen = set()
    for e in beacons:
        ssid, src = e.get("ssid"), e.get("src")
        if ssid and src and src not in _attack_seen and _is_attack_tool_ssid(ssid):
            _attack_seen.add(src)
            detections.append({
                "type": "rogue_ap", "severity": "attack_tool_ssid",
                "ssid": ssid, "bssid": src,
                "detail": f"SSID '{ssid}' is a known attack-tool / captive-portal "
                          "default name (EvilPortal/Marauder/Ghost ESP/GARMR class)"
                          " — an ESP32/handheld attack multitool is beaconing here",
            })

    # --- ESP32 open soft-AP (NAME-INDEPENDENT): an open AP whose BSSID is an
    # Espressif radio. EvilPortal/Marauder/Ghost ESP/GARMR all run on an ESP32,
    # and renaming or hiding the SSID doesn't change the chip's burned-in MAC —
    # so this catches a captive-portal lure even when it's called "Testt". Only
    # a WARNING on its own (a benign ESP32 IoT gadget in setup mode is also an
    # open Espressif AP); it turns critical when it co-occurs with an attack
    # SSID / spoofed BSSID / duplicate, or an active portal probe confirms. ---
    _esp_seen = set()
    for e in beacons:
        src, ssid = e.get("src"), e.get("ssid")
        if (src and src not in _esp_seen and e.get("security") == "Open"
                and _is_espressif(src)):
            _esp_seen.add(src)
            detections.append({
                "type": "rogue_ap", "severity": "esp32_open_ap",
                "ssid": ssid, "bssid": src,
                "detail": f"open AP '{ssid or '<hidden>'}' is an Espressif (ESP32) "
                          "radio — the chip behind EvilPortal/Marauder/Ghost ESP/"
                          "GARMR. Name-independent; probe the portal to confirm vs. "
                          "an IoT device in setup mode",
            })

    # --- Spoofed BSSID: a beacon/probe-resp sourced from a group (multicast)
    # address is invalid 802.11 — no real AP does it. Catches an evil twin whose
    # randomized BSSID left the I/G bit set (the lone-lure case a duplicate/
    # baseline check can't see: one new SSID, no real AP to clone, no deauth). ---
    _anomaly_seen = set()
    for e in beacons + presp:
        src = e.get("src")
        if src and src not in _anomaly_seen and _is_multicast_bssid(src):
            _anomaly_seen.add(src)
            detections.append({
                "type": "rogue_ap", "severity": "spoofed_bssid",
                "ssid": e.get("ssid"), "bssid": src,
                "detail": f"BSSID {src} has the group/multicast (I/G) bit set — "
                          "invalid for a real AP; spoofed/rogue BSSID"
                          + (f" advertising '{e.get('ssid')}'" if e.get("ssid") else ""),
            })

    # --- Open rogue-lure: an OPEN AP using a common free-Wi-Fi name is the shape
    # of an evil-twin captive-portal lure. LOW confidence (real venues use these
    # names) — informational, never an alert; a nudge to run a portal probe. ---
    _open_sec = {"Open", None}
    _lure_seen = set()
    for e in beacons:
        ssid, src = e.get("ssid"), e.get("src")
        if (ssid and src and src not in _lure_seen and _is_lure_ssid(ssid)
                and e.get("security") in _open_sec):
            _lure_seen.add(src)
            detections.append({
                "type": "rogue_ap", "severity": "rogue_lure",
                "ssid": ssid, "bssid": src,
                "detail": f"open AP '{ssid}' matches a common free-Wi-Fi lure name "
                          "— possible evil-twin captive portal; probe it to confirm",
            })

    # Access-point inventory (for the UI table + baseline building)
    aps = {}
    for e in beacons:
        src = e.get("src")
        if not src:
            continue
        ap = aps.setdefault(src, {"bssid": src, "ssid": e.get("ssid"),
                                  "channel": e.get("channel"), "rssi": e.get("rssi"),
                                  "beacons": 0})
        ap["beacons"] += 1
        if e.get("rssi") is not None:
            ap["rssi"] = e["rssi"]
        if e.get("channel") is not None:
            ap["channel"] = e["channel"]

    sev_rank = {"flood": 3, "evil_twin": 3, "karma": 3, "spoofed_bssid": 3,
                "attack_tool_ssid": 3,
                "duplicate_ssid": 2, "beacon_warn": 2, "auth_warn": 2,
                "esp32_open_ap": 2,
                "band_steering": 1, "rogue_lure": 1, "seen": 1}
    threat = "clear"
    if detections:
        worst = max(sev_rank.get(d["severity"], 1) for d in detections)
        threat = "critical" if worst >= 3 else "warning"

    # Live airspace stats so the UI can show where the capture sits relative to
    # the beacon-flood threshold (for calibration).
    b_ssids = {e["ssid"] for e in beacons if e.get("ssid")}
    b_bssids = {e["src"] for e in beacons if e.get("src")}
    _b_rnd = len({b for b in b_bssids if _is_locally_administered(b)})
    airspace = {
        "ssids": len(b_ssids), "bssids": len(b_bssids),
        "random_bssids": _b_rnd,
        "la_ratio": round(_b_rnd / len(b_bssids), 2) if b_bssids else 0.0,
        "beacon_ssid_threshold": beacon_ssid_max,
        "beacon_bssid_threshold": beacon_bssid_max,
    }

    return {
        "threat": threat,
        "frames": len(events),
        "counts": {"deauth": len(deauths), "beacon": len(beacons),
                   "auth": sum(1 for e in events if e["kind"] == "auth"),
                   "probe_resp": len(presp),
                   "probe_req": sum(1 for e in events if e["kind"] == "probe_req")},
        "airspace": airspace,
        "detections": detections,
        "aps": sorted(aps.values(), key=lambda a: -(a.get("rssi") or -999)),
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def do_scan(interface, seconds=15, channel=None, auto_enable=True):
    """Ensure monitor mode, capture a window, and analyze it."""
    if not _valid_iface(interface):
        return {"error": "invalid interface"}
    seconds = max(3, min(120, int(seconds)))
    events = _capture_recover(_capture, interface, seconds, channel, auto_enable)
    if isinstance(events, dict) and "error" in events:
        return events
    mon = _load_state().get("mon_iface")
    result = analyze(events, baseline=get_baseline(), window_secs=seconds,
                     thresholds=get_thresholds())
    result.update({"interface": interface, "monitor": mon,
                   "seconds": seconds, "channel": channel,
                   "timestamp": int(time.time())})
    return result


def learn_baseline(interface, seconds=20, channel=None, merge=True):
    """Capture, then merge every SSID->BSSID mapping seen into the trusted
    baseline. Merges by default so repeated captures accumulate all the BSSIDs a
    single window can't hear at once (see set_baseline)."""
    res = do_scan(interface, seconds=seconds, channel=channel)
    if "error" in res:
        return res
    mapping = _aps_to_mapping(res.get("aps", []))
    baseline = set_baseline(mapping, merge=merge)
    return {"ok": True, "baseline": baseline, "ssids": len(baseline),
            "added": len(mapping)}


def trust_aps(aps, merge=True):
    """Trust an already-captured AP inventory (what the user is looking at) —
    no re-capture, so 'Trust current APs' trusts exactly what's on screen and
    accumulates into the baseline."""
    mapping = _aps_to_mapping(aps)
    if not mapping:
        return {"error": "no APs with SSIDs to trust — run a scan first"}
    baseline = set_baseline(mapping, merge=merge)
    return {"ok": True, "baseline": baseline, "ssids": len(baseline),
            "added": len(mapping)}


# --------------------------------------------------------------------------
# Self-test  (craft real Dot11 frames -> pcap -> parse -> analyze)
# --------------------------------------------------------------------------

def _selftest_pcap(path):
    from scapy.all import (RadioTap, Dot11, Dot11Auth, Dot11Beacon, Dot11Deauth,
                           Dot11Elt, Dot11ProbeResp, wrpcap)
    pkts = []

    def beacon(bssid, ssid, ch=6, rssi=-50):
        return (RadioTap(dBm_AntSignal=rssi, ChannelFrequency=2437) /
                Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                      addr2=bssid, addr3=bssid) /
                Dot11Beacon() / Dot11Elt(ID=0, info=ssid.encode()))

    def deauth(src, dst):
        return (RadioTap() /
                Dot11(type=0, subtype=12, addr1=dst, addr2=src, addr3=src) /
                Dot11Deauth(reason=7))

    def proberesp(bssid, ssid):
        return (RadioTap() /
                Dot11(type=0, subtype=5, addr1="00:11:22:33:44:55",
                      addr2=bssid, addr3=bssid) /
                Dot11ProbeResp() / Dot11Elt(ID=0, info=ssid.encode()))

    def authreq(src, bssid):
        # subtype 11 = authentication, from a client (src) to an AP (addr1=bssid)
        return (RadioTap() /
                Dot11(type=0, subtype=11, addr1=bssid, addr2=src, addr3=bssid) /
                Dot11Auth(seqnum=1))

    # Legit home AP
    pkts += [beacon("aa:aa:aa:00:00:01", "HomeNet")] * 3
    # Auth flood (HaleHound Auth Flood): 40 auth frames from randomized (locally-
    # administered) source MACs at the home AP — client-table exhaustion.
    for i in range(40):
        pkts.append(authreq("02:%02x:%02x:%02x:aa:bb" % (i, (i * 7) & 0xff, i),
                            "aa:aa:aa:00:00:01"))
    # Deauth flood (20 frames) against it
    pkts += [deauth("aa:aa:aa:00:00:01", "cc:cc:cc:00:00:09") for _ in range(20)]
    # Beacon flood: 35 distinct fake SSIDs
    pkts += [beacon(f"de:ad:be:ef:%02x:00" % i, f"FAKE_{i}") for i in range(35)]
    # KARMA AP answering 6 different SSIDs from one BSSID
    for s in ["Starbucks", "attwifi", "HomeNet", "xfinitywifi", "TP-LINK", "Netgear"]:
        pkts.append(proberesp("ba:ad:ba:ad:00:01", s))
    # Evil twin: HomeNet also from an untrusted BSSID
    pkts.append(beacon("98:99:99:99:99:99", "HomeNet"))
    wrpcap(path, pkts)


def selftest():
    import tempfile
    results = []

    def check(name, cond, detail=""):
        results.append({"name": name, "pass": bool(cond), "detail": detail})

    try:
        from scapy.all import Dot11  # noqa: F401
    except Exception as e:
        return {"pass": False, "passed": 0, "total": 1,
                "results": [{"name": "scapy import", "pass": False, "detail": str(e)}]}

    tmp = os.path.join(tempfile.mkdtemp(), "cap.pcap")
    try:
        _selftest_pcap(tmp)
        events = parse_pcap(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    check("frames parsed from pcap", len(events) > 50, f"{len(events)} events")
    kinds = {e["kind"] for e in events}
    check("beacon/deauth/probe_resp all parsed",
          {"beacon", "deauth", "probe_resp"} <= kinds, str(sorted(kinds)))
    check("SSID extracted from beacon",
          any(e["kind"] == "beacon" and e["ssid"] == "HomeNet" for e in events))
    check("deauth reason code parsed",
          any(e["kind"] == "deauth" and e["reason"] == 7 for e in events))

    res = analyze(events, baseline={"HomeNet": ["aa:aa:aa:00:00:01"]})
    types = {d["type"]: d for d in res["detections"]}

    check("deauth flood detected",
          types.get("deauth", {}).get("severity") == "flood",
          json.dumps(types.get("deauth", {})))
    check("deauth attacker identified",
          any(a["src"] == "aa:aa:aa:00:00:01" for a in
              types.get("deauth", {}).get("attackers", [])))
    # The 35 fake APs use randomized (locally-administered) BSSIDs — the mdk4
    # signature. Even below the absolute 100-SSID threshold, the LA-ratio burst
    # detector flags this as a randomized-BSSID fake-AP storm (critical). This is
    # the improvement: robust in dense RF without guessing an absolute count.
    bf = types.get("beacon_flood", {})
    check("beacon flood flagged via randomized-BSSID burst (35 LA MACs)",
          bf.get("severity") == "flood", json.dumps(bf))
    check("beacon flood reports la_ratio", bf.get("la_ratio", 0) >= 0.5, json.dumps(bf))
    check("airspace counts + la_ratio reported for calibration",
          res["airspace"]["ssids"] >= 35 and res["airspace"]["la_ratio"] >= 0.5
          and res["airspace"]["beacon_ssid_threshold"] == _BEACON_FLOOD_SSIDS,
          json.dumps(res["airspace"]))
    # A dense-but-legit airspace (many SSIDs from GLOBAL/vendor MACs, ~0% LA) must
    # NOT trip beacon flood — this is the dense-RF false positive the LA-ratio
    # split is designed to avoid.
    dense = [{"kind": "beacon", "src": "00:1a:2b:%02x:%02x:00" % (i // 256, i % 256),
              "ssid": "Neighbour_%d" % i} for i in range(60)]
    dense_res = analyze(dense, baseline={})
    check("dense legit airspace (global MACs) is NOT a beacon flood",
          not any(d["type"] == "beacon_flood" for d in dense_res["detections"]),
          json.dumps([d["detail"] for d in dense_res["detections"]]))
    # A dense airspace over the absolute threshold but with global MACs is a
    # WARNING (unusually dense), not a critical randomized storm.
    dense2 = [{"kind": "beacon", "src": "00:1a:2b:%02x:%02x:00" % (i // 256, i % 256),
               "ssid": "Neighbour_%d" % i} for i in range(120)]
    dense2_res = analyze(dense2, thresholds={"beacon_bssids": 100})
    bf2 = next((d for d in dense2_res["detections"] if d["type"] == "beacon_flood"), {})
    check("dense global-MAC airspace over abs threshold is warning not critical",
          bf2.get("severity") == "beacon_warn", json.dumps(bf2))
    # Deauth scope + protected posture on the (targeted, unprotected) flood.
    dd = types.get("deauth", {})
    check("deauth scope = targeted", dd.get("scope") == "targeted", json.dumps(dd))
    check("deauth reports unprotected count", dd.get("unprotected") == dd.get("count"),
          json.dumps(dd))
    check("deauth dominant reason parsed", dd.get("reason") == 7, json.dumps(dd))
    # Broadcast deauth flood is recognized as broadcast scope.
    bdeauth = [{"kind": "deauth", "src": "aa:aa:aa:00:00:01",
                "dst": "ff:ff:ff:ff:ff:ff", "reason": 7, "protected": False}
               for _ in range(20)]
    bres = analyze(bdeauth)
    bd = next((d for d in bres["detections"] if d["type"] == "deauth"), {})
    check("broadcast deauth flood scope = broadcast", bd.get("scope") == "broadcast",
          json.dumps(bd))
    check("KARMA detected", "karma" in types and types["karma"]["ssid_count"] >= 5,
          str(types.get("karma")))
    # Auth flood (HaleHound Auth Flood): 40 randomized-MAC auth frames at one AP.
    af = types.get("auth_flood", {})
    check("auth flood detected (client-table exhaustion)",
          af.get("severity") == "flood", json.dumps(af))
    check("auth flood identifies target BSSID + randomized sources",
          af.get("bssid") == "aa:aa:aa:00:00:01" and af.get("la_ratio", 0) >= 0.5
          and af.get("sources", 0) >= _AUTH_FLOOD_SRCS, json.dumps(af))
    check("auth frame count surfaced for calibration",
          res["counts"].get("auth", 0) >= 40, json.dumps(res["counts"]))
    # Legit roaming: a handful of auth frames from a few BURNED-IN client MACs must
    # NOT trip the flood (this is the normal-association false positive we avoid).
    roam = [{"kind": "auth", "src": "3c:22:fb:aa:00:%02x" % i,
             "dst": "aa:aa:aa:00:00:01"} for i in range(4) for _ in range(5)]
    roam_res = analyze(roam, baseline={})
    check("legit roaming (few global-MAC clients) is NOT an auth flood",
          not any(d["type"] == "auth_flood" for d in roam_res["detections"]),
          json.dumps([d.get("detail") for d in roam_res["detections"]]))
    check("evil twin detected against baseline",
          types.get("rogue_ap", {}).get("severity") == "evil_twin"
          and "98:99:99:99:99:99" in types.get("rogue_ap", {}).get("rogue_bssids", []),
          str(types.get("rogue_ap")))
    check("overall threat = critical", res["threat"] == "critical", res["threat"])

    # --- Band-steering / mesh vs evil twin (tri-band false-positive guard) ---
    # One SSID on three BSSIDs sharing ONE global vendor OUI = a band-steering
    # router / mesh seen across 2.4/5/6 GHz. Must down-rank to informational
    # 'band_steering', NOT a possible evil twin, and NOT raise the threat level.
    steer = [{"kind": "beacon", "src": "3c:22:fb:11:22:%02x" % (0x30 + i),
              "ssid": "Proxima B"} for i in range(3) for _ in range(4)]
    steer_res = analyze(steer, baseline={})
    steer_d = next((d for d in steer_res["detections"]
                    if d["type"] == "rogue_ap"), {})
    check("multi-BSSID same-OUI SSID = band_steering (not evil twin)",
          steer_d.get("severity") == "band_steering", json.dumps(steer_d))
    check("band steering does not raise threat above clear/warning",
          steer_res["threat"] in ("clear", "warning"), steer_res["threat"])
    # But a clone from a DIFFERENT vendor OUI still surfaces as duplicate_ssid.
    twin = ([{"kind": "beacon", "src": "3c:22:fb:11:22:30", "ssid": "Proxima B"}] * 4
            + [{"kind": "beacon", "src": "de:ad:be:ef:00:01", "ssid": "Proxima B"}] * 4)
    twin_res = analyze(twin, baseline={})
    twin_d = next((d for d in twin_res["detections"]
                   if d["type"] == "rogue_ap"), {})
    check("cross-OUI duplicate SSID still flags duplicate_ssid",
          twin_d.get("severity") == "duplicate_ssid", json.dumps(twin_d))
    # A locally-administered (randomized) BSSID among them defeats the guard too.
    rnd = ([{"kind": "beacon", "src": "3c:22:fb:11:22:30", "ssid": "Proxima B"}] * 4
           + [{"kind": "beacon", "src": "3e:22:fb:11:22:31", "ssid": "Proxima B"}] * 4)
    rnd_d = next((d for d in analyze(rnd, baseline={})["detections"]
                  if d["type"] == "rogue_ap"), {})
    check("randomized-BSSID clone is NOT treated as band steering",
          rnd_d.get("severity") == "duplicate_ssid", json.dumps(rnd_d))

    # --- Hidden/cloaked SSID must NOT flag as duplicate/evil twin ---
    # Three unrelated hidden APs (different vendor OUIs) all beacon a NUL-filled
    # SSID that decodes to a truthy-but-blank string. They share the empty key
    # but are not one network — must produce no rogue_ap detection at all.
    hidden = ([{"kind": "beacon", "src": "3c:22:fb:00:00:01", "ssid": "\x00\x00\x00\x00"}] * 4
              + [{"kind": "beacon", "src": "de:ad:be:00:00:02", "ssid": "\x00\x00\x00\x00"}] * 4
              + [{"kind": "beacon", "src": "00:11:22:00:00:03", "ssid": ""}] * 4)
    hidden_res = analyze(hidden, baseline={})
    check("hidden/blank SSID does not flag as duplicate/evil twin",
          not any(d["type"] == "rogue_ap" for d in hidden_res["detections"]),
          json.dumps([d.get("detail") for d in hidden_res["detections"]]))
    check("_is_blank_ssid: NUL-filled + empty are blank, real name is not",
          _is_blank_ssid("\x00\x00") and _is_blank_ssid("") and _is_blank_ssid("   ")
          and not _is_blank_ssid("Proxima B"), "")

    # --- Spoofed BSSID (group/multicast I/G bit) — the lone-lure evil twin ---
    # HaleHound GARMR case: one new open SSID, no real AP, no deauth. BSSID
    # 99:... has the I/G bit set (0x99 is odd) — invalid for a real AP.
    lure_ap = [{"kind": "beacon", "src": "99:fa:9b:77:96:ff", "ssid": "FreeWiFi",
                "security": "Open"}] * 4
    lure_res = analyze(lure_ap, baseline={})
    types_l = {d["severity"]: d for d in lure_res["detections"]
               if d["type"] == "rogue_ap"}
    check("spoofed BSSID (multicast I/G bit) flagged as rogue",
          "spoofed_bssid" in types_l, json.dumps(lure_res["detections"]))
    check("open lure SSID ('FreeWiFi') flagged (low-confidence)",
          "rogue_lure" in types_l, json.dumps(lure_res["detections"]))
    check("spoofed BSSID raises threat to critical",
          lure_res["threat"] == "critical", lure_res["threat"])
    check("_is_multicast_bssid: 0x99 set, 0x00 clear",
          _is_multicast_bssid("99:fa:9b:77:96:ff")
          and not _is_multicast_bssid("00:11:22:33:44:55"))
    # A normal open AP with an ordinary name and a unicast BSSID => no rogue flag.
    normal_open = [{"kind": "beacon", "src": "3c:22:fb:00:00:01",
                    "ssid": "MyHomeAP", "security": "Open"}] * 4
    n_types = {d["severity"] for d in analyze(normal_open, baseline={})["detections"]
               if d["type"] == "rogue_ap"}
    check("ordinary open AP (unicast BSSID, non-lure name) => no rogue flag",
          not ({"spoofed_bssid", "rogue_lure"} & n_types), str(n_types))
    # A lure NAME but WPA2-secured (real venue) must not trip the open-lure hint.
    secured_lure = [{"kind": "beacon", "src": "3c:22:fb:00:00:02",
                     "ssid": "attwifi", "security": "WPA2"}] * 4
    check("secured AP with a lure name => no rogue_lure (open-only)",
          not any(d.get("severity") == "rogue_lure"
                  for d in analyze(secured_lure, baseline={})["detections"]))

    # Clean traffic => no detections
    from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt
    clean = []
    for p in [(RadioTap(dBm_AntSignal=-40, ChannelFrequency=2437) /
               Dot11(type=0, subtype=8, addr2="aa:aa:aa:00:00:01",
                     addr3="aa:aa:aa:00:00:01") /
               Dot11Beacon() / Dot11Elt(ID=0, info=b"HomeNet"))] * 3:
        ev = _frame_to_event(p)
        if ev:
            clean.append(ev)
    clean_res = analyze(clean, baseline={"HomeNet": ["aa:aa:aa:00:00:01"]})
    check("clean traffic => no detections", clean_res["threat"] == "clear",
          json.dumps(clean_res["detections"]))

    # --- Baseline merge/accumulate (the trust fix) — temp state file ---
    global _STATE_FILE
    _orig_state, _STATE_FILE = _STATE_FILE, os.path.join(__import__("tempfile").mkdtemp(), "state.json")
    try:
        clear_baseline()
        # First trust: HomeNet on its 2.4 GHz BSSID (one capture window).
        set_baseline({"HomeNet": ["aa:aa:aa:00:00:01"]})
        # Second trust later sees the SAME SSID from its 5 GHz BSSID.
        set_baseline({"HomeNet": ["aa:aa:aa:00:00:02"]})
        base = get_baseline()
        check("baseline merges BSSIDs across trusts (multi-band SSID)",
              set(base.get("HomeNet", [])) == {"aa:aa:aa:00:00:01", "aa:aa:aa:00:00:02"},
              json.dumps(base))
        # A later scan seeing both trusted BSSIDs must NOT flag an evil twin.
        seen_events = [
            {"kind": "beacon", "src": "aa:aa:aa:00:00:01", "ssid": "HomeNet"},
            {"kind": "beacon", "src": "aa:aa:aa:00:00:02", "ssid": "HomeNet"},
        ]
        r_ok = analyze(seen_events, baseline=get_baseline())
        check("no evil-twin false positive once both BSSIDs are trusted",
              not any(d["type"] == "rogue_ap" for d in r_ok["detections"]),
              json.dumps(r_ok["detections"]))
        # trust_aps trusts a shown inventory (case-insensitive) without capture.
        trust_aps([{"ssid": "Cafe", "bssid": "BB:BB:BB:00:00:01"}])
        check("trust_aps stores shown APs lowercased",
              get_baseline().get("Cafe") == ["bb:bb:bb:00:00:01"],
              json.dumps(get_baseline().get("Cafe")))
        check("clear_baseline empties it", clear_baseline() == {} and get_baseline() == {})
        # Tunable thresholds persist and survive a baseline clear.
        set_thresholds(beacon_ssids=250)
        check("threshold persists and is clamped/read back",
              get_thresholds()["beacon_ssids"] == 250)
        set_baseline({"X": ["aa:bb:cc:dd:ee:ff"]})
        check("threshold survives a later baseline write",
              get_thresholds()["beacon_ssids"] == 250)
        # --- ENODEV fix: monitor bookkeeping writes must not drop persistent data,
        # and a stale mon_iface (vif gone after reboot/replug) must be detected. ---
        _save_state({"mon_iface": "ragmon0", "base_iface": "wlan0", "mode": "vif"})
        check("monitor bookkeeping write preserves baseline + thresholds",
              get_thresholds()["beacon_ssids"] == 250
              and get_baseline().get("X") == ["aa:bb:cc:dd:ee:ff"],
              json.dumps({"th": get_thresholds(), "base": get_baseline()}))
        # ragmon0 does not exist on this box → _resolve_monitor must reject it
        # (auto_enable=False) rather than hand a dead iface to sniff() → ENODEV.
        check("_iface_exists is False for a phantom vif",
              not _iface_exists("ragmon0__nope"))
        stale = _resolve_monitor("wlan0__nope", auto_enable=False)
        check("_resolve_monitor rejects stale mon_iface instead of returning it",
              isinstance(stale, dict) and "error" in stale, json.dumps(stale))
        check("_resolve_monitor cleared the stale bookkeeping",
              _load_state().get("mon_iface") is None)
        check("clearing stale monitor still kept baseline + thresholds",
              get_thresholds()["beacon_ssids"] == 250
              and get_baseline().get("X") == ["aa:bb:cc:dd:ee:ff"])
        # ENODEV during capture yields a friendly message flagged for recovery.
        enod = _capture_error("ragmon0", OSError(errno.ENODEV, "No such device"))
        check("ENODEV capture error is friendly + flagged for rebuild",
              "Errno 19" in enod["error"] and enod.get("enodev") is True,
              json.dumps(enod))
        # ENODEV surfaced as a plain string (some libpcap builds) is still caught.
        enod_str = _capture_error("ragmon0", RuntimeError("[Errno 19] No such device exists"))
        check("ENODEV detected even from a string error", enod_str.get("enodev") is True)
        # _capture_recover: a vif that dies once (ENODEV) is rebuilt and retried.
        _save_state({"mon_iface": "ragmonX", "base_iface": "wlan0", "mode": "vif"})
        calls = {"n": 0}
        def _flaky(mon, seconds, channel=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"error": "capture failed: … (Errno 19)", "enodev": True}
            return [{"kind": "beacon", "src": "aa:aa:aa:00:00:01", "ssid": "OK"}]
        _orig_resolve = _resolve_monitor
        _orig_refresh = _refresh_scapy_ifaces
        refreshes = {"n": 0}
        try:
            globals()["_resolve_monitor"] = lambda interface, auto_enable=True: "ragmon0"
            globals()["_refresh_scapy_ifaces"] = lambda: refreshes.__setitem__("n", refreshes["n"] + 1)
            rec = _capture_recover(_flaky, "wlan0", 5, None, True)
            check("_capture_recover rebuilds + retries after one ENODEV",
                  isinstance(rec, list) and len(rec) == 1 and calls["n"] == 2,
                  json.dumps({"calls": calls["n"], "rec": rec}))
            # scapy's stale iface cache is refreshed before the initial capture AND
            # after the rebuild — the fix for ENODEV-until-service-restart.
            check("_capture_recover refreshes scapy ifaces on capture + rebuild",
                  refreshes["n"] == 2, json.dumps({"refreshes": refreshes["n"]}))
            # With auto_enable off it must NOT retry — surfaces the error once.
            calls["n"] = 0
            rec2 = _capture_recover(_flaky, "wlan0", 5, None, False)
            check("_capture_recover does not retry when auto_enable is off",
                  isinstance(rec2, dict) and rec2.get("enodev") and calls["n"] == 1,
                  json.dumps({"calls": calls["n"]}))
        finally:
            globals()["_resolve_monitor"] = _orig_resolve
            globals()["_refresh_scapy_ifaces"] = _orig_refresh

        # --- Robust re-enable: a lingering vif is torn down, rebuilt, primed
        #     on a channel, and verified — the disable→re-enable "comes back but
        #     detects nothing" fix. Stub the shell primitives. ---
        _names = ("_run", "_iw_dev_list", "_iface_exists", "_phy_for_iface",
                  "_phy_supports_monitor", "_set_channel", "_valid_iface")
        _saved_fns = {n: globals()[n] for n in _names}
        _real_sleep = time.sleep
        try:
            devs = {"wlan9": {"phy": "phy9", "type": "managed"},
                    "ragmon0": {"phy": "phy9", "type": "monitor"}}  # stale leftover
            cmds = []

            def _fake_run(args, **kw):
                cmds.append(list(args))
                a = list(args)
                if len(a) >= 6 and a[1] == "phy" and a[3] == "interface" and a[4] == "add":
                    devs[a[5]] = {"phy": "phy9", "type": "monitor"}
                if len(a) >= 4 and a[0] == _IW and a[1] == "dev" and a[3] == "del":
                    devs.pop(a[2], None)
                # iw dev <if> set type <t>  → reflect the new type
                if (len(a) >= 6 and a[0] == _IW and a[1] == "dev"
                        and a[3] == "set" and a[4] == "type" and a[2] in devs):
                    devs[a[2]]["type"] = a[5]
                return (0, "", "")

            globals().update(
                _run=_fake_run, _iw_dev_list=lambda: {k: dict(v) for k, v in devs.items()},
                _iface_exists=lambda n: n in devs, _phy_for_iface=lambda i: "phy9",
                _phy_supports_monitor=lambda p: True, _set_channel=lambda m, c: None,
                _valid_iface=lambda i: True)
            time.sleep = lambda *_a, **_k: None
            res = enable_monitor("wlan9")
            check("re-enable yields a working vif monitor",
                  res.get("mon_iface") == "ragmon0" and res.get("mode") == "vif",
                  json.dumps(res))
            check("re-enable tears the stale vif down before recreating (fresh)",
                  any(c[0] == _IW and c[1:2] == ["dev"] and c[-1] == "del" for c in cmds))
            check("re-enable re-adds the vif and primes a channel",
                  any(len(c) >= 5 and c[4] == "add" for c in cmds)
                  and _load_state().get("mon_iface") == "ragmon0")
            check("enable frees the radio by bringing the managed base down",
                  any(c[:3] == ["ip", "link", "set"] and c[3] == "wlan9"
                      and c[-1] == "down" for c in cmds),
                  json.dumps([c for c in cmds if "wlan9" in c]))
            # The monitor vif (ragmon0) must never be offered as a selectable base.
            check("list_monitor_capable hides our own monitor vif",
                  not any(i["iface"] == "ragmon0"
                          for i in list_monitor_capable()["interfaces"]),
                  json.dumps([i["iface"] for i in list_monitor_capable()["interfaces"]]))
            # enable_monitor must refuse to run monitor *on* ragmon0 (no base to map to).
            _base_keep = _load_state().get("base_iface")
            _save_state({"mode": "vif"})  # no base_iface
            _guard = enable_monitor("ragmon0")
            check("enable_monitor refuses the monitor vif (ragmon0) as a base",
                  isinstance(_guard, dict) and "error" in _guard, json.dumps(_guard))
            _save_state({"mon_iface": "ragmon0", "base_iface": _base_keep or "wlan9", "mode": "vif"})
            # _monitor_ready must reject an un-tunable vif (set channel EBUSY).
            def _busy_run(args, **kw):
                a = list(args)
                if a[0] == _IW and len(a) >= 5 and a[3] == "set" and a[4] == "channel":
                    return (240, "", "command failed: Device or resource busy (-16)")
                return (0, "", "")
            globals()["_run"] = _busy_run
            check("_monitor_ready fails when the channel can't be set (EBUSY)",
                  _monitor_ready("ragmon0") is False)
            # disable brings the managed base back up.
            globals()["_run"] = _fake_run
            _save_state({"mon_iface": "ragmon0", "base_iface": "wlan9", "mode": "vif"})
            cmds.clear()
            disable_monitor()
            check("disable restores the managed base (brought back up)",
                  any(c[:3] == ["ip", "link", "set"] and c[3] == "wlan9"
                      and c[-1] == "up" for c in cmds),
                  json.dumps([c for c in cmds if "wlan9" in c]))

            # --- Regdomain, targeted release, 6 GHz, dedicated boot-time mode ---
            check("set_regdomain rejects a non-ISO code",
                  "error" in set_regdomain("USA"))
            cmds.clear()
            check("set_regdomain issues `iw reg set` for a valid code",
                  set_regdomain("us").get("regdomain") == "US"
                  and any(c[:3] == [_IW, "reg", "set"] and c[3] == "US" for c in cmds))
            cmds.clear()
            _release_iface("wlan9")
            check("_release_iface kills wpa_supplicant/dhclient bound to the iface",
                  any(c[0] == "pkill" and "wpa_supplicant" in c[-1] for c in cmds)
                  and any(c[0] == "pkill" and "dhclient" in c[-1] for c in cmds),
                  json.dumps(cmds))
            check("6 GHz hop targets are freq-tuned and opt-in",
                  ("freq", 5975) in _hop_targets(True)
                  and all(t[0] == "chan" for t in _hop_targets(False)))
            # Dedicated (switch-mode) boot claim.
            devs["wlan9"]["type"] = "managed"
            cmds.clear()
            ded = dedicate_monitor("wlan9", regdomain="US", init_freq=2437, six_ghz=True)
            check("dedicate_monitor claims the whole iface as monitor",
                  ded.get("mode") == "dedicated" and ded.get("mon_iface") == "wlan9"
                  and devs["wlan9"]["type"] == "monitor", json.dumps(ded))
            check("dedicate_monitor set regdomain + type monitor + init freq",
                  any(c[:3] == [_IW, "reg", "set"] for c in cmds)
                  and any(c[3:6] == ["set", "type", "monitor"] for c in cmds if len(c) >= 6)
                  and any(c[3:5] == ["set", "freq"] for c in cmds if len(c) >= 5))
            check("dedicated state persists mode + six_ghz",
                  _load_state().get("mode") == "dedicated"
                  and _load_state().get("six_ghz") is True)
            # _resolve_monitor re-claims a dedicated monitor if the iface reappears.
            check("_resolve_monitor returns the live dedicated monitor",
                  _resolve_monitor("wlan9") == "wlan9")
        finally:
            time.sleep = _real_sleep
            globals().update(_saved_fns)
    finally:
        try:
            os.unlink(_STATE_FILE)
        except OSError:
            pass
        _STATE_FILE = _orig_state

    # --- Airtime / retry / roaming analysis (passive diagnostics) ---
    at_events = []
    # AP1: 100 data frames, 40 retries (poor link), rate 6 Mbps
    for i in range(100):
        at_events.append({"type": 2, "subtype": 0, "retry": i < 40,
                          "src": "cc:cc:cc:00:00:01", "dst": "11:11:11:11:11:11",
                          "bssid": "cc:cc:cc:00:00:01", "bytes": 1500,
                          "rate_mbps": 6.0, "rssi": -55})
    # AP2: 20 clean data frames, fast
    for i in range(20):
        at_events.append({"type": 2, "subtype": 0, "retry": False,
                          "src": "dd:dd:dd:00:00:02", "dst": "22:22:22:22:22:22",
                          "bssid": "dd:dd:dd:00:00:02", "bytes": 1500,
                          "rate_mbps": 300.0, "rssi": -45})
    # A roaming client: 4 reassoc frames
    for i in range(4):
        at_events.append({"type": 0, "subtype": 2, "retry": False,
                          "src": "ab:cd:ef:00:00:99", "dst": "cc:cc:cc:00:00:01",
                          "bssid": "cc:cc:cc:00:00:01", "bytes": 60, "rate_mbps": 6.0})
    at = analyze_airtime(at_events, seconds=10)
    ap1 = next(a for a in at["aps"] if a["bssid"] == "cc:cc:cc:00:00:01")
    check("airtime: retry_pct computed", ap1["retries"] == 40
          and ap1["retry_pct"] == 38.5, json.dumps(ap1))
    check("airtime: high-retry finding raised",
          any(f["type"] == "high_retry" for f in at["findings"]),
          json.dumps(at["findings"]))
    check("airtime: rate spread captured",
          ap1["rate_min"] == 6.0 and ap1["rate_max"] == 6.0)
    check("airtime: roaming churn detected",
          any(f["type"] == "roaming_churn" for f in at["findings"]))
    check("airtime: rate parse legacy (radiotap Rate=12 => 6 Mbps)",
          _frame_rate_mbps(type("R", (), {"Rate": 12, "MCS_index": None})()) == 6.0)

    # --- Airtime starvation: per-client attribution + ERP protection ---
    star = []
    STAR_AP = "aa:bb:cc:00:00:0a"
    FAST = "10:20:30:00:00:01"                    # unicast, Wi-Fi 6
    PLUG = "20:30:40:00:00:02"                    # unicast, legacy 802.11b

    def _up(sta, **kw):                           # STA -> AP (ToDS)
        e = {"type": 2, "subtype": 0, "retry": False, "to_ds": True,
             "from_ds": False, "src": sta, "dst": STAR_AP, "sta": sta,
             "bssid": STAR_AP, "rssi": -50}
        e.update(kw); return e

    def _down(sta, **kw):                          # AP -> STA (FromDS)
        e = {"type": 2, "subtype": 0, "retry": False, "to_ds": False,
             "from_ds": True, "src": STAR_AP, "dst": sta, "sta": sta,
             "bssid": STAR_AP, "rssi": -50}
        e.update(kw); return e

    # AP beacons announcing ERP protection ON (a legacy DSSS client is present).
    for _ in range(10):
        star.append({"type": 0, "subtype": 8, "retry": False, "src": STAR_AP,
                     "dst": "ff:ff:ff:ff:ff:ff", "sta": None, "bssid": STAR_AP,
                     "bytes": 120, "rate_mbps": 6.0, "rssi": -40, "ssid": "HomeNet",
                     "erp_protection": True, "erp_nonerp": True})
    # Fast client: 300 big uplink frames at 130 Mbps, and — the fix-B trap — a
    # handful of probe requests sent at 1 Mbps CCK. Those must NOT drag its PHY.
    star.append({"type": 0, "subtype": 4, "retry": False, "to_ds": False,
                 "from_ds": False, "src": FAST, "dst": "ff:ff:ff:ff:ff:ff",
                 "sta": FAST, "bssid": "ff:ff:ff:ff:ff:ff", "bytes": 60,
                 "rate_mbps": 1.0, "declared_ht": True, "rssi": -45})
    for _ in range(300):
        star.append(_up(FAST, bytes=1500, rate_mbps=130.0))
    # Legacy plug: 40 uplink + 40 downlink frames at 1 Mbps. Counting uplink
    # only (the old bug) would halve its measured airtime.
    for _ in range(40):
        star.append(_up(PLUG, bytes=400, rate_mbps=1.0))
    for _ in range(40):
        star.append(_down(PLUG, bytes=400, rate_mbps=1.0))
    st = analyze_airtime(star, seconds=10)
    plug = next((c for c in st["clients"] if c["client"] == PLUG), None)
    fast = next((c for c in st["clients"] if c["client"] == FAST), None)
    check("starvation: legacy client classified 802.11b",
          plug is not None and plug["is_11b"]
          and plug["phy"] == "802.11b (DSSS/CCK)", json.dumps(plug))
    check("starvation(fix B): fast client NOT mislabeled from 1 Mbps probe req",
          fast is not None and not fast["legacy"] and fast["confidence"] == "declared",
          json.dumps(fast))
    check("starvation(fix A): plug airtime counts BOTH directions (80 frames)",
          plug["frames"] == 80)
    check("starvation: legacy plug eats more airtime than fast client despite fewer frames",
          plug["airtime_pct"] > fast["airtime_pct"] and plug["frames"] < fast["frames"])
    check("starvation: disproportion computed (airtime ≫ bytes for the plug)",
          plug["disproportion"] is not None and plug["disproportion"] > fast["disproportion"])
    check("starvation: ERP protection latched on AP",
          any(a["bssid"] == STAR_AP and a["erp_protection"] for a in st["aps"]))
    check("starvation: erp_protection finding raised",
          any(f["type"] == "erp_protection" for f in st["findings"]),
          json.dumps(st["findings"]))
    check("starvation: slow_client finding names the culprit",
          any(f["type"] == "slow_client" and f.get("client") == PLUG
              for f in st["findings"]))
    check("starvation: AP not counted as its own client",
          all(c["client"] != STAR_AP for c in st["clients"]))
    check("starvation: client tagged with its AP's SSID",
          plug is not None and plug.get("ssid") == "HomeNet")
    # Declared-capability classifier (fix C).
    check("phy classifier: declared HT wins over low observed rates",
          _classify_client_phy(True, 1.0, 1.0)[0].startswith("802.11n")
          and _classify_client_phy(True, 1.0, 1.0)[2] == "declared")
    check("phy classifier: declared no-HT => pre-n legacy",
          _classify_client_phy(False, 6.0, 54.0)[1] is True
          and _classify_client_phy(False, None, None)[0].startswith("802.11a/g"))
    check("phy classifier: observed CCK => 11b at observed confidence",
          _classify_client_phy(None, 1.0, 11.0) == ("802.11b (DSSS/CCK)", True, "observed"))

    # --- Airtime PPDU model: legacy long preamble dominates ---
    check("airtime: 1500B @ 1 Mbps CCK ~= 12192 us (long preamble)",
          abs(_frame_airtime_us({"bytes": 1500, "rate_mbps": 1.0}) - 12192) < 1)
    check("airtime: 1500B @ 54 Mbps OFDM ~= 242 us",
          abs(_frame_airtime_us({"bytes": 1500, "rate_mbps": 54.0}) - 242) < 2)

    # --- Cipher-as-throughput (fix E) ---
    rsn_tkip_group = (bytes([1, 0]) + b"\x00\x0f\xac\x02"      # group = TKIP(2)
                      + bytes([2, 0]) + b"\x00\x0f\xac\x04" + b"\x00\x0f\xac\x02"
                      + bytes([1, 0]) + b"\x00\x0f\xac\x02" + bytes([0, 0]))
    g, pw = _parse_rsn_ciphers(rsn_tkip_group)
    check("cipher: RSN group=TKIP, pairwise={CCMP,TKIP} parsed",
          g == 2 and pw == {4, 2})
    tk_ev = {"type": 0, "subtype": 8, "retry": False, "src": "c0:00:00:00:00:01",
             "dst": "ff:ff:ff:ff:ff:ff", "sta": None, "bssid": "c0:00:00:00:00:01",
             "bytes": 100, "ssid": "TkipNet", "security": "WPA2",
             "group_cipher": "TKIP", "pairwise_ciphers": ["CCMP-128", "TKIP"]}
    tk = analyze_airtime([tk_ev], seconds=1)
    check("cipher: TKIP group cipher raises throughput-cap finding",
          any(f["type"] == "cipher_tkip_group" for f in tk["findings"]))

    # --- HT Protection Non-HT Mixed (fix F) ---
    htp_ev = {"type": 0, "subtype": 8, "retry": False, "src": "c1:00:00:00:00:01",
              "dst": "ff:ff:ff:ff:ff:ff", "sta": None, "bssid": "c1:00:00:00:00:01",
              "bytes": 100, "ssid": "MixedNet", "ht_protection": 3, "basic_cck": True}
    htp = analyze_airtime([htp_ev], seconds=1)
    check("ht: Non-HT Mixed protection raises finding",
          any(f["type"] == "ht_protection_mixed" for f in htp["findings"]))

    # --- WPS posture (the 1-button / PIN surface) ---
    def _wsc(aid, val):
        return bytes([aid >> 8, aid & 0xff, len(val) >> 8, len(val) & 0xff]) + val
    # PIN method (keypad), not locked, Not Configured, no Version2 => WSC 1.0
    wsc_open = (_wsc(0x1044, bytes([1])) + _wsc(0x1057, bytes([0]))
                + _wsc(0x1008, bytes([0x01, 0x00])))
    p_open = _parse_wsc(wsc_open)
    check("wps: parse PIN-method/unlocked/unconfigured/WSC1.0",
          p_open["pin_method"] and p_open["locked"] is False
          and p_open["configured"] is False and p_open["version2"] is False)
    # PushButton only + Version2 present => good posture
    wsc_pbc = (_wsc(0x1044, bytes([2])) + _wsc(0x1057, bytes([1]))
               + _wsc(0x1008, bytes([0x00, 0x80]))
               + _wsc(0x1049, b"\x00\x37\x2a\x00\x01\x20"))
    p_pbc = _parse_wsc(wsc_pbc)
    check("wps: parse pushbutton-only + Version2 (good posture)",
          p_pbc["pushbutton"] and not p_pbc["pin_method"]
          and p_pbc["version2"] and p_pbc["locked"] is True)
    wps_ev = {"type": 0, "subtype": 8, "retry": False, "src": "c2:00:00:00:00:01",
              "dst": "ff:ff:ff:ff:ff:ff", "sta": None, "bssid": "c2:00:00:00:00:01",
              "bytes": 100, "ssid": "WpsNet", "wps": p_open}
    wr = analyze_airtime([wps_ev], seconds=1)
    check("wps: exposed PIN enrollment raises wps_pin_open (+ unconfigured)",
          any(f["type"] == "wps_pin_open" for f in wr["findings"])
          and any(f["type"] == "wps_unconfigured" for f in wr["findings"]))

    check("starvation: PHY classifier boundaries",
          _classify_phy(1.0, 11.0) == "802.11b (DSSS/CCK)"
          and _classify_phy(6.0, 54.0) == "802.11a/g (OFDM)"
          and _classify_phy(6.5, 130.0) == "802.11n+ (HT/VHT/HE)"
          and _classify_phy(None, None) is None)

    # --- Encryption + AP PHY generation parsed from beacon IEs ---
    rsn_psk = (bytes([1, 0]) + b"\x00\x0f\xac\x04" + bytes([1, 0])
               + b"\x00\x0f\xac\x04" + bytes([1, 0]) + b"\x00\x0f\xac\x02" + bytes([0, 0]))
    rsn_sae = (bytes([1, 0]) + b"\x00\x0f\xac\x04" + bytes([1, 0])
               + b"\x00\x0f\xac\x04" + bytes([1, 0]) + b"\x00\x0f\xac\x08" + bytes([0, 0]))
    check("security: RSN PSK => WPA2",
          _classify_security(True, rsn_psk, False) == "WPA2")
    check("security: RSN SAE => WPA3",
          _classify_security(True, rsn_sae, False) == "WPA3")
    check("security: privacy bit only => WEP",
          _classify_security(True, None, False) == "WEP")
    check("security: no privacy => Open",
          _classify_security(False, None, False) == "Open")
    check("security: WPA1 vendor element => WPA",
          _classify_security(True, None, True) == "WPA")
    check("ap_phy: HT => 802.11n, VHT => ac, HE => ax, EHT => be",
          _classify_ap_phy(True, False, False, False, [], True).startswith("802.11n")
          and _classify_ap_phy(False, True, False, False, [], True).startswith("802.11ac")
          and _classify_ap_phy(False, False, True, False, [], True).startswith("802.11ax")
          and _classify_ap_phy(False, False, False, True, [], True).startswith("802.11be"))
    check("ap_phy: legacy 2.4 split b vs g by rate set",
          _classify_ap_phy(False, False, False, False, [1.0, 2.0, 5.5, 11.0], True) == "802.11b (DSSS)"
          and _classify_ap_phy(False, False, False, False, [1.0, 11.0, 24.0], True) == "802.11g (OFDM)"
          and _classify_ap_phy(False, False, False, False, [], False) == "802.11a (OFDM)")
    # --- Identity fusion (MAC-join of radio PHY + network host inventory) ---
    _cl = [{"client": "20:30:40:00:00:02", "legacy": True},
           {"client": "aa:bb:cc:dd:ee:ff", "legacy": False}]
    _hosts = {"20:30:40:00:00:02": {"ip": "192.168.1.42", "hostname": "HP-LaserJet",
                                    "vendor": "Hewlett Packard",
                                    "device_type": "printer", "device_label": "Printer"}}
    enrich_identity(_cl, _hosts, lambda m: "AcmeVendor")
    check("identity: known MAC gets hostname/ip/type from host map",
          _cl[0]["hostname"] == "HP-LaserJet" and _cl[0]["ip"] == "192.168.1.42"
          and _cl[0]["device_type"] == "printer" and _cl[0]["identified"] is True)
    check("identity: unknown MAC falls back to OUI vendor, stays unidentified",
          _cl[1]["vendor"] == "AcmeVendor" and _cl[1]["hostname"] is None
          and _cl[1]["identified"] is False)
    _cl2 = [{"client": "de:ad:be:ef:00:01", "legacy": True}]
    enrich_identity(_cl2, {}, lambda m: "Randomized")
    check("identity: randomized OUI is not used as a vendor name",
          _cl2[0]["vendor"] is None)

    check("security: weak_security finding raised for Open BSS",
          any(f["type"] == "weak_security"
              for f in analyze_airtime(
                  [{"type": 0, "subtype": 8, "retry": False, "src": "aa:00:00:00:00:01",
                    "dst": "ff:ff:ff:ff:ff:ff", "bssid": "aa:00:00:00:00:01",
                    "bytes": 100, "ssid": "OpenNet", "security": "Open",
                    "ap_phy": "802.11g (OFDM)"}], seconds=1)["findings"]))

    # --- Client-isolation observer (passive AP/mesh peer-traffic audit) ---
    from scapy.all import wrpcap
    C1, C2 = "12:34:56:00:00:01", "12:34:56:00:00:02"
    C3, C4 = "12:34:56:00:00:03", "12:34:56:00:00:04"
    C5, C6 = "12:34:56:00:00:05", "12:34:56:00:00:06"
    AP_OPEN, AP_ISO = "aa:aa:aa:00:00:01", "ac:ac:ac:00:00:02"
    MESH_A, MESH_B = "ee:ee:ee:00:00:0a", "ee:ee:ee:00:00:0b"
    GW = "0a:0a:0a:00:00:fe"                     # wired-side gateway MAC
    BCAST = "ff:ff:ff:ff:ff:ff"

    def data(fc, a1, a2, a3):
        return RadioTap() / Dot11(type=2, subtype=0, FCfield=fc,
                                  addr1=a1, addr2=a2, addr3=a3)

    def nbeacon(bssid, ssid):
        return (RadioTap() / Dot11(type=0, subtype=8, addr1=BCAST,
                                   addr2=bssid, addr3=bssid) /
                Dot11Beacon() / Dot11Elt(ID=0, info=ssid.encode()))

    iso_pkts = [nbeacon(AP_OPEN, "OpenNet"), nbeacon(AP_ISO, "IsoNet"),
                nbeacon(MESH_A, "MeshNet"), nbeacon(MESH_B, "MeshNet")]
    # OpenNet: C1 addresses C2 and the AP relays it back out => isolation OFF.
    # (fc=1 -> ToDS: addr1=BSSID,addr2=SA,addr3=DA; fc=2 -> FromDS:
    #  addr1=DA,addr2=BSSID,addr3=SA)
    iso_pkts += [data(1, AP_OPEN, C2, GW)]                       # C2 is a client
    iso_pkts += [data(1, AP_OPEN, C1, C2)] * 3                   # peer attempts
    iso_pkts += [data(2, C2, AP_OPEN, C1)] * 3                   # AP relays C1->C2
    # IsoNet: peer attempts + client broadcasts, but the AP relays NOTHING back
    # (only normal upstream traffic from the wired gateway) => isolating.
    iso_pkts += [data(1, AP_ISO, C4, GW)]                        # C4 is a client
    iso_pkts += [data(1, AP_ISO, C3, C4)] * 5                    # blocked attempts
    iso_pkts += [data(1, AP_ISO, C3, BCAST)] * 4                 # ARP-ish bcasts
    iso_pkts += [data(2, C3, AP_ISO, GW)] * 6                    # upstream, normal
    # MeshNet: C5 lives on node A; node B relays C5's traffic to its client C6
    # => cross-node forwarding, mesh-wide isolation OFF (per-node evidence alone
    # would miss it).
    iso_pkts += [data(1, MESH_A, C5, GW)]                        # C5 on node A
    iso_pkts += [data(1, MESH_B, C6, GW)]                        # C6 on node B
    iso_pkts += [data(2, C6, MESH_B, C5)] * 2                    # B airs SA=C5
    iso_pkts += [data(3, MESH_B, MESH_A, MESH_A)]                # 4-addr backhaul
    tmp_iso = os.path.join(tempfile.mkdtemp(), "iso.pcap")
    try:
        wrpcap(tmp_iso, iso_pkts)
        iso_events = parse_pcap_iso(tmp_iso)
    finally:
        try:
            os.unlink(tmp_iso)
        except OSError:
            pass
    check("isolation: DS bits + addresses parsed from pcap",
          {"beacon", "tods", "fromds", "wds"} <=
          {e["kind"] for e in iso_events}, f"{len(iso_events)} events")
    iso = analyze_isolation(iso_events, seconds=20)
    by_bssid = {x["bssid"]: x for x in iso["bss"]}
    op, isod = by_bssid.get(AP_OPEN, {}), by_bssid.get(AP_ISO, {})
    check("isolation: relayed peer traffic => verdict open",
          op.get("verdict") == "open" and op.get("relays") == 3,
          json.dumps(op))
    check("isolation: talking pair identified",
          op.get("pairs") and sorted(op["pairs"][0][:2]) == sorted([C1, C2]),
          json.dumps(op.get("pairs")))
    check("isolation: blocked attempts => verdict isolating",
          isod.get("verdict") == "isolating" and isod.get("attempts") == 5
          and isod.get("relays") == 0 and isod.get("bcast_sent") == 4,
          json.dumps(isod))
    check("isolation: upstream (wired-source) frames never count as relays",
          isod.get("relays") == 0 and isod.get("clients") == 2,
          json.dumps(isod))
    mesh = next((x for x in iso["ess"] if x["ssid"] == "MeshNet"), {})
    check("isolation: mesh grouped by SSID with cross-node forwarding => open",
          mesh.get("node_count") == 2 and mesh.get("cross_relays", 0) >= 2
          and mesh.get("verdict") == "open", json.dumps(mesh))
    check("isolation: WDS/mesh backhaul frames counted",
          iso["wds_frames"] == 1, str(iso["wds_frames"]))

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="802.11 frame monitor / WIDS")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("interfaces")
    pm = sub.add_parser("monitor")
    pm.add_argument("--interface", required=True)
    pm.add_argument("--enable", action="store_true")
    pm.add_argument("--disable", action="store_true")
    ps = sub.add_parser("scan")
    ps.add_argument("--interface", required=True)
    ps.add_argument("--seconds", type=int, default=15)
    ps.add_argument("--channel", type=int, default=None)
    pb = sub.add_parser("baseline")
    pb.add_argument("--interface", required=True)
    pb.add_argument("--seconds", type=int, default=20)
    pi = sub.add_parser("isolation")
    pi.add_argument("--interface", required=True)
    pi.add_argument("--seconds", type=int, default=20)
    pi.add_argument("--channel", type=int, default=None)
    # Boot-time dedicated monitor: claim the whole interface (switch-mode) once,
    # e.g. from a systemd ExecStartPre. See scripts/wifidef_dedicate.sh.
    pd = sub.add_parser("dedicate")
    pd.add_argument("--interface", required=True)
    pd.add_argument("--regdomain", default=None, help="e.g. US, SE — unlocks DFS/6 GHz")
    pd.add_argument("--init-freq", type=int, default=None, dest="init_freq")
    pd.add_argument("--six-ghz", action="store_true", dest="six_ghz",
                    help="also hop 6 GHz (needs a 6E radio + correct regdomain)")
    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if args.cmd == "interfaces":
        print(json.dumps(list_monitor_capable(), indent=2))
    elif args.cmd == "monitor":
        if args.disable:
            print(json.dumps(disable_monitor(), indent=2))
        else:
            print(json.dumps(enable_monitor(args.interface), indent=2))
    elif args.cmd == "dedicate":
        r = dedicate_monitor(args.interface, regdomain=args.regdomain,
                             init_freq=args.init_freq, six_ghz=args.six_ghz)
        print(json.dumps(r, indent=2))
        return 0 if "error" not in r else 1
    elif args.cmd == "scan":
        print(json.dumps(do_scan(args.interface, args.seconds, args.channel), indent=2))
    elif args.cmd == "baseline":
        print(json.dumps(learn_baseline(args.interface, args.seconds), indent=2))
    elif args.cmd == "isolation":
        print(json.dumps(do_isolation(args.interface, args.seconds, args.channel),
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
