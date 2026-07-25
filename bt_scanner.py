#!/usr/bin/env python3
"""
bt_scanner.py — Passive Bluetooth / BLE presence scanner for the 2.4 GHz overlay.

The companion to :mod:`wifi_analyzer`. Where the Wi-Fi analyzer surveys 802.11
beacons, this discovers **Bluetooth Classic (BR/EDR) and Bluetooth Low Energy**
devices in range and maps their 2.4 GHz footprint onto the *same* band the
Wi-Fi analyzer draws — so you can see, in one picture, the BT/BLE energy that
shares the 2.4 GHz ISM band with (and interferes with) Wi-Fi channels 1/6/11.

What this is — and isn't
------------------------
This is a **device-discovery + activity overlay**, not a calibrated RF spectrum
sweep. We do not sample raw energy per Hz (that needs an SDR). We ask the
Bluetooth controller — via BlueZ ``bluetoothctl`` — which devices it can hear,
their RSSI, address type, class and advertised company ID, and from that we
model where their energy lands in 2.4 GHz:

* **BLE advertising** rides three fixed channels — 37/38/39 at **2402 / 2426 /
  2480 MHz** — deliberately placed in the gaps around Wi-Fi 1/6/11. We draw
  those as fixed markers.
* **BLE data** (37 channels) and **Classic BT** (79 channels) frequency-hop
  across the whole band, so we model a band-wide "hopping activity" load
  proportional to how many active devices we hear and how strong they are.

Everything here is **receive-only**: we run device *discovery* (passive listen +
the controller's own inquiry/scan), never pairing, connecting, or transmitting
data to any device.

Capture path
------------
``bluetoothctl`` talks to the already-running ``bluetoothd`` over D-Bus, which is
far more reliable than contending for the raw HCI mgmt socket (``btmgmt``). We:

1. run ``bluetoothctl --timeout N scan on`` and parse the streaming
   ``[NEW]/[CHG] Device …`` events for live RSSI + manufacturer data, then
2. enrich each discovered address with one ``bluetoothctl info <mac>`` call for
   address type (public/random), device class, icon, name and TX power.

Controller selection
--------------------
When the tri-band Alfa (BT 5.2 combo) is plugged in, its controller enumerates
on the **USB** bus while the Pi's onboard radio is **UART**. We prefer a USB
controller so the overlay uses the same adapter as the Wi-Fi capture; callers
can override with an explicit ``hciN``.

CLI
---
    python3 bt_scanner.py controllers
    python3 bt_scanner.py scan [--controller hci1] [--duration 12]
    python3 bt_scanner.py selftest
"""

import json
import os
import re
import subprocess
import sys
import time

# --------------------------------------------------------------------------
# Constants / tunables
# --------------------------------------------------------------------------

_BTCTL = "/usr/bin/bluetoothctl"
if not os.path.exists(_BTCTL):
    _BTCTL = "bluetoothctl"  # fall back to PATH

_DEFAULT_DURATION = 12       # seconds of discovery per scan
_MAX_DURATION = 30
_INFO_TIMEOUT = 6            # per-device `info` enrichment
# Cold-start grace: hciconfig lists a freshly-powered USB controller (an Alfa
# just plugged/unblocked) a moment before bluetoothd exports its D-Bus object.
# Wait this long for the *chosen* adapter to appear rather than scanning a
# different radio — see _discover_dbus.
_DBUS_ADAPTER_WAIT = 4.0
_STRONG_RSSI = -70          # dBm; at/above this a device is "close" and hurts more

# BLE advertising channels: the three fixed 2 MHz channels every advertiser
# uses, placed in the gaps around Wi-Fi 1/6/11.
BLE_ADV_CHANNELS = {37: 2402, 38: 2426, 39: 2480}

# The full 2.4 GHz occupancy of frequency-hopping traffic (BLE data + Classic).
_BT_BAND_LO_MHZ = 2402
_BT_BAND_HI_MHZ = 2480

# Wi-Fi 2.4 GHz channel centre frequencies (the ones the analyzer cares about).
_WIFI_24_CENTERS = {1: 2412, 6: 2437, 11: 2462, 13: 2472}

# A small, high-confidence slice of the Bluetooth SIG "Company Identifiers"
# assigned-numbers list, used to name the maker of a device that hides behind a
# randomised (LE privacy) address where the OUI is useless.
_COMPANY_IDS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x00E0: "Google",
    0x0075: "Samsung",
    0x0087: "Garmin",
    0x0059: "Nordic Semiconductor",
    0x000F: "Broadcom",
    0x000A: "CSR / Qualcomm",
    0x012D: "Sony",
    0x038F: "Xiaomi",
    0x0499: "Ruuvi",
    0x0157: "Huami (Amazfit)",
}

# Bluetooth "Major Device Class" (bits 8-12 of the class-of-device word).
_MAJOR_CLASS = {
    0: "Miscellaneous",
    1: "Computer",
    2: "Phone",
    3: "Network AP",
    4: "Audio/Video",
    5: "Peripheral",
    6: "Imaging",
    7: "Wearable",
    8: "Toy",
    9: "Health",
    31: "Uncategorized",
}


# --------------------------------------------------------------------------
# subprocess plumbing
# --------------------------------------------------------------------------

def _run(args, timeout=_INFO_TIMEOUT):
    """Run a command, returning (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "bluetoothctl not found"
    except subprocess.TimeoutExpired as exc:
        # A timed scan is *expected* to be killed by our timeout; return what it
        # printed up to that point rather than losing the whole capture.
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 0, out, "timed out"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text):
    return _ANSI.sub("", text or "")


def _valid_controller(ctrl):
    return bool(ctrl) and re.match(r"^hci\d{1,3}$", ctrl or "") is not None


# --------------------------------------------------------------------------
# Controller enumeration + selection
# --------------------------------------------------------------------------

def _controller_bus(hci):
    """'usb', 'uart' or None for an hciN, read from sysfs.

    The Alfa combo dongle's BT enumerates on USB; the Pi's onboard radio is on
    a UART. We prefer USB so the overlay uses the same adapter as Wi-Fi.
    """
    try:
        target = os.path.realpath("/sys/class/bluetooth/%s/device" % hci)
    except Exception:
        return None
    low = target.lower()
    if "usb" in low:
        return "usb"
    if "serial" in low or "uart" in low or "tty" in low:
        return "uart"
    return None


def _parse_controllers(text):
    """Parse ``bluetoothctl list`` into [{address, name, is_default}] (pure)."""
    out = []
    for line in _strip_ansi(text).splitlines():
        m = re.match(r"\s*Controller\s+([0-9A-Fa-f:]{17})\s+(.*?)\s*(\[default\])?\s*$",
                     line)
        if m:
            out.append({
                "address": m.group(1).upper(),
                "name": m.group(2).strip(),
                "is_default": bool(m.group(3)),
            })
    return out


def _parse_hciconfig(text):
    """Parse ``hciconfig`` into {hci: {address, bus}} (pure).

    The kernel doesn't expose a sysfs ``address`` file on every platform (the
    Pi's onboard radio has none), so hciconfig is the reliable address↔hci map.
    Its 'Bus:' line also names USB vs UART directly.
    """
    out = {}
    cur = None
    for line in _strip_ansi(text).splitlines():
        m = re.match(r"^(hci\d+):\s*.*?Bus:\s*(\w+)", line)
        if m:
            cur = m.group(1)
            out[cur] = {"address": None, "bus": m.group(2).lower()}
            continue
        if cur:
            ma = re.search(r"BD Address:\s*([0-9A-Fa-f:]{17})", line)
            if ma:
                out[cur]["address"] = ma.group(1).upper()
    return out


def list_controllers():
    """Every Bluetooth controller: [{hci, address, name, bus, is_default}].

    Enumerated from ``hciconfig`` (the reliable hci↔address↔bus source), with
    the friendly name and [default] flag joined in from ``bluetoothctl list``.
    Sorted USB-first so the natural default is the Alfa combo dongle when it's
    present, falling back to the onboard (UART) radio.
    """
    rc, hc_out, _ = _run(["hciconfig"], timeout=5)
    hcimap = _parse_hciconfig(hc_out) if rc == 0 else {}
    # Names / default flag come from bluetoothctl, keyed by address.
    rc2, bt_out, _ = _run([_BTCTL, "list"], timeout=5)
    by_addr = {c["address"]: c for c in (_parse_controllers(bt_out) if rc2 == 0
                                         else [])}
    ctrls = []
    for hci, meta in sorted(hcimap.items()):
        addr = meta.get("address")
        bt = by_addr.get(addr, {})
        bus = meta.get("bus") or _controller_bus(hci)
        ctrls.append({
            "hci": hci,
            "address": addr,
            "name": bt.get("name") or "",
            "bus": bus,
            "is_default": bool(bt.get("is_default")),
        })
    # If hciconfig was unavailable, fall back to whatever bluetoothctl knew.
    if not ctrls and by_addr:
        for c in by_addr.values():
            c.setdefault("hci", None)
            c.setdefault("bus", None)
            ctrls.append(c)
    # USB (Alfa) first, then default flag, then hci name for stability.
    ctrls.sort(key=lambda c: (0 if c.get("bus") == "usb" else 1,
                              0 if c.get("is_default") else 1,
                              c.get("hci") or ""))
    return ctrls


def _pick_controller(controller=None):
    """Resolve the controller to use: an explicit hciN, else USB-first pick."""
    ctrls = list_controllers()
    if controller and _valid_controller(controller):
        for c in ctrls:
            if c.get("hci") == controller:
                return c
    return ctrls[0] if ctrls else None


# --------------------------------------------------------------------------
# Address / vendor / class helpers
# --------------------------------------------------------------------------

def _addr_is_random(mac):
    """True if the two most-significant bits mark a static/private random addr.

    A public BD address is a real IEEE OUI; a *random* address is either an LE
    static random or a resolvable/non-resolvable private (rotating) address —
    the OUI is meaningless and the maker can only come from company-ID AD data.
    """
    try:
        return bool(int(mac[:2], 16) & 0x02)  # locally-administered bit
    except (ValueError, TypeError):
        return False


def _company_name(key):
    """Maker name for a 16-bit Bluetooth SIG company identifier, or None."""
    if key is None:
        return None
    return _COMPANY_IDS.get(key)


def _decode_class(cls):
    """(major_class_label, service_flags[]) from a class-of-device integer."""
    if not cls:
        return (None, [])
    major = (cls >> 8) & 0x1F
    label = _MAJOR_CLASS.get(major)
    services = []
    svc = cls >> 13   # service-class bits 13-23 of the class-of-device word
    for bit, name in ((3, "Positioning"), (4, "Networking"), (5, "Rendering"),
                      (6, "Capturing"), (7, "Object Transfer"), (8, "Audio"),
                      (9, "Telephony"), (10, "Information")):
        if svc & (1 << bit):
            services.append(name)
    return (label, services)


def _vendor_for(mac, company_key, is_random=None):
    """Best maker attribution: OUI for public MACs, company-ID for random ones."""
    if is_random is None:
        is_random = _addr_is_random(mac)
    if is_random:
        name = _company_name(company_key)
        return name or "Randomized/private"
    # Public address — reuse the Wi-Fi analyzer's OUI database if importable.
    try:
        import wifi_analyzer
        v = wifi_analyzer._oui_lookup(mac)
        if v and v != "Randomized/private":
            return v
    except Exception:
        pass
    return _company_name(company_key)


# --------------------------------------------------------------------------
# bluetoothctl output parsers (pure functions — unit-testable)
# --------------------------------------------------------------------------

_DEV_LINE = re.compile(
    r"\[\s*(NEW|CHG|DEL)\s*\]\s*Device\s+([0-9A-Fa-f:]{17})\s+(.*)$")


def parse_scan_stream(text):
    """Parse streaming ``bluetoothctl scan on`` output into {mac: {...}}.

    Accumulates, per device, the friendly name, the last-reported RSSI, and any
    manufacturer company ID seen — from the interleaved [NEW]/[CHG] events.
    Pure: no I/O, so the selftest can drive it with captured output.
    """
    devices = {}
    for raw in _strip_ansi(text).splitlines():
        m = _DEV_LINE.search(raw)
        if not m:
            continue
        event, mac, rest = m.group(1), m.group(2).upper(), m.group(3).strip()
        d = devices.setdefault(mac, {"mac": mac, "name": None, "rssi": None,
                                     "company_key": None})
        # `RSSI: 0xffffffc3 (-61)` — take the signed decimal in the parens.
        mr = re.search(r"RSSI:\s*(?:0x[0-9a-fA-F]+\s*)?\((-?\d+)\)", rest)
        if mr:
            d["rssi"] = int(mr.group(1))
        # `ManufacturerData.Key: 0x004c (76)`
        mk = re.search(r"ManufacturerData\.Key:\s*(0x[0-9a-fA-F]+)", rest)
        if mk:
            d["company_key"] = int(mk.group(1), 16)
        # A [NEW] line's trailing token is the name/alias (often the MAC dashed).
        if event == "NEW" and rest and "RSSI" not in rest and ":" not in rest:
            if rest.replace("-", ":").upper() != mac:
                d["name"] = rest
        mn = re.search(r"Name:\s*(.+)$", rest)
        if mn:
            d["name"] = mn.group(1).strip()
    return devices


def parse_info(text):
    """Parse ``bluetoothctl info <mac>`` into a dict (pure)."""
    t = _strip_ansi(text)
    info = {"addr_type": None, "name": None, "rssi": None, "cls": None,
            "icon": None, "company_key": None, "tx_power": None}
    m = re.search(r"Device\s+[0-9A-Fa-f:]{17}\s*\((public|random)\)", t)
    if m:
        info["addr_type"] = m.group(1)
    m = re.search(r"^\s*Name:\s*(.+)$", t, re.M)
    if m:
        info["name"] = m.group(1).strip()
    elif re.search(r"^\s*Alias:\s*(.+)$", t, re.M):
        info["name"] = re.search(r"^\s*Alias:\s*(.+)$", t, re.M).group(1).strip()
    m = re.search(r"^\s*Class:\s*(0x[0-9a-fA-F]+)", t, re.M)
    if m:
        info["cls"] = int(m.group(1), 16)
    m = re.search(r"^\s*Icon:\s*(.+)$", t, re.M)
    if m:
        info["icon"] = m.group(1).strip()
    m = re.search(r"^\s*RSSI:\s*(?:0x[0-9a-fA-F]+\s*)?\((-?\d+)\)", t, re.M)
    if m:
        info["rssi"] = int(m.group(1))
    m = re.search(r"ManufacturerData\.Key:\s*(0x[0-9a-fA-F]+)", t)
    if m:
        info["company_key"] = int(m.group(1), 16)
    m = re.search(r"^\s*TxPower:\s*(?:0x[0-9a-fA-F]+\s*)?\(?(-?\d+)\)?", t, re.M)
    if m:
        info["tx_power"] = int(m.group(1))
    return info


# --------------------------------------------------------------------------
# 2.4 GHz interference model
# --------------------------------------------------------------------------

def _classify(dev):
    """Attach kind (le/classic/dual), vendor and decoded class to a device."""
    cls = dev.get("cls")
    # Prefer the controller-reported AddressType (D-Bus/info) over the MAC-bit
    # heuristic; fall back to the bit when it wasn't reported.
    at = dev.get("addr_type")
    is_random = (at == "random") if at in ("public", "random") \
        else _addr_is_random(dev["mac"])
    major, services = _decode_class(cls)
    # A class-of-device word is a Classic (BR/EDR) construct; a random address is
    # an LE privacy construct. Presence of both => dual-mode.
    if cls and is_random:
        kind = "dual"
    elif cls:
        kind = "classic"
    else:
        kind = "le"
    dev["kind"] = kind
    dev["vendor"] = _vendor_for(dev["mac"], dev.get("company_key"), is_random)
    dev["major_class"] = major
    dev["services"] = services
    dev["randomized"] = is_random
    return dev


def analyze_interference(devices):
    """Model where the discovered BT/BLE energy lands across 2.4 GHz.

    Returns the fixed advertising-channel markers (with an occupancy intensity
    driven by how many advertisers we heard) plus an estimated per-Wi-Fi-channel
    "BT pressure" for 1/6/11/13 — the band-wide hopping load plus the advertising
    overlap that channel catches. Heuristic and clearly labelled as an estimate.
    """
    active = len(devices)
    strong = sum(1 for d in devices if d.get("rssi") is not None
                 and d["rssi"] >= _STRONG_RSSI)
    classic = sum(1 for d in devices if d.get("kind") in ("classic", "dual"))
    le = sum(1 for d in devices if d.get("kind") == "le")

    # Band-wide hopping load (0-100): every active device hops across the band;
    # close ones and Classic (higher duty, wider channels) weigh more.
    hopping = min(100, active * 4 + strong * 6 + classic * 8)

    # Advertising markers: intensity scales with the LE advertiser count, since
    # every BLE device beacons on all three of these channels.
    adv_intensity = min(100, (le + strong) * 8)
    adv_markers = [
        {"adv_channel": ch, "freq_mhz": f, "intensity": adv_intensity}
        for ch, f in sorted(BLE_ADV_CHANNELS.items())
    ]

    # Which Wi-Fi channel each advertising channel bleeds into (>= half-overlap
    # of a 20 MHz Wi-Fi channel, i.e. within ~11 MHz of its centre).
    adv_hits = {1: 0, 6: 0, 11: 0, 13: 0}
    for _ch, f in BLE_ADV_CHANNELS.items():
        for wch, wf in _WIFI_24_CENTERS.items():
            if abs(f - wf) <= 11:
                adv_hits[wch] += 1

    channels = []
    for wch in (1, 6, 11, 13):
        overlap = adv_hits[wch] * adv_intensity * 0.15
        pressure = min(100, round(hopping * 0.5 + overlap, 1))
        if pressure < 20:
            level = "low"
        elif pressure < 55:
            level = "moderate"
        else:
            level = "high"
        channels.append({"wifi_channel": wch, "pressure": pressure,
                         "level": level, "adv_overlap": adv_hits[wch]})

    return {
        "device_count": active,
        "le_count": le,
        "classic_count": classic,
        "strong_count": strong,
        "hopping_pressure": hopping,
        "adv_markers": adv_markers,
        "wifi_channels": channels,
        "note": ("Device-activity estimate, not measured RF energy. BLE beacons "
                 "on 37/38/39 (2402/2426/2480 MHz); BLE data + Classic hop the "
                 "whole band. A true energy sweep needs an SDR."),
    }


# --------------------------------------------------------------------------
# Top-level scan orchestration
# --------------------------------------------------------------------------

def _dbus_int(v):
    """Coerce a dbus numeric (Int16/UInt32/…) to a plain Python int, or None."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _adapter_present(objs, adapter_path):
    """The requested adapter's object path if BlueZ exposes it, else None.

    Strict: it matches the chosen adapter only — never substitutes a different
    controller — so a scan can't silently run on the wrong (e.g. onboard) radio
    while the intended one is still registering. ``objs`` is
    ObjectManager.GetManagedObjects().
    """
    ifaces = objs.get(adapter_path)
    if ifaces and "org.bluez.Adapter1" in ifaces:
        return adapter_path
    return None


def _discover_dbus(hci, duration):
    """Primary capture: drive a BlueZ discovery over D-Bus and snapshot every
    in-range device with RSSI + address type + class + company ID.

    BlueZ populates ``Device1.RSSI`` only while a device is *currently in range*
    during discovery and clears it afterwards, so filtering on RSSI-present
    gives a clean "here right now" roster rather than bluetoothd's whole cache.

    Returns (devices, None) on success or (None, reason) so the caller can fall
    back to the ``bluetoothctl`` text path if python-dbus/BlueZ isn't available.
    """
    try:
        import dbus
    except Exception as exc:
        return None, "python3-dbus not available (%s)" % exc
    try:
        bus = dbus.SystemBus()
        mgr = dbus.Interface(bus.get_object("org.bluez", "/"),
                             "org.freedesktop.DBus.ObjectManager")
        # Resolve strictly to the adapter we were asked to use. Earlier this
        # silently fell back to the *first* adapter BlueZ exposed when the
        # chosen one wasn't on D-Bus yet — so the very first overlay scan after
        # a USB controller powered up would run on the onboard hci0 (slow, and
        # on a flaky board mislabelled as hci1) until bluetoothd caught up.
        # Instead wait briefly for the chosen adapter, since hciconfig sees a
        # fresh controller before its D-Bus object is exported.
        adapter_path = "/org/bluez/%s" % hci
        objs = mgr.GetManagedObjects()
        waited = 0.0
        while _adapter_present(objs, adapter_path) is None and waited < _DBUS_ADAPTER_WAIT:
            time.sleep(0.25)
            waited += 0.25
            objs = mgr.GetManagedObjects()
        adapter_path = _adapter_present(objs, adapter_path)
        if not adapter_path:
            # Don't scan a different radio than the caller chose; let do_scan
            # fall back to the bluetoothctl path (which targets this hci too).
            return None, "%s not on D-Bus yet (bluetoothd still registering it)" % hci
        adapter = dbus.Interface(bus.get_object("org.bluez", adapter_path),
                                 "org.bluez.Adapter1")
        try:
            adapter.StartDiscovery()
        except dbus.DBusException as exc:
            # 'InProgress' just means discovery is already running — fine.
            if "InProgress" not in str(exc):
                return None, "StartDiscovery failed: %s" % exc
        time.sleep(duration)
        objs = mgr.GetManagedObjects()
        try:
            adapter.StopDiscovery()
        except dbus.DBusException:
            pass
    except dbus.DBusException as exc:
        return None, "BlueZ D-Bus error: %s" % exc
    except Exception as exc:  # pragma: no cover - defensive
        return None, str(exc)

    devices = []
    for path, ifaces in objs.items():
        d = ifaces.get("org.bluez.Device1")
        if not d:
            continue
        rssi = _dbus_int(d.get("RSSI"))
        if rssi is None:
            continue  # not in range during this discovery — skip stale cache
        md = d.get("ManufacturerData")
        company_key = None
        if md:
            keys = [_dbus_int(k) for k in md.keys()]
            keys = [k for k in keys if k is not None]
            if keys:
                company_key = min(keys)  # stable pick when several are present
        devices.append({
            "mac": str(d.get("Address", "")).upper(),
            "name": str(d["Name"]) if d.get("Name") else None,
            "rssi": rssi,
            "addr_type": str(d["AddressType"]) if d.get("AddressType") else None,
            "cls": _dbus_int(d.get("Class")),
            "icon": str(d["Icon"]) if d.get("Icon") else None,
            "tx_power": _dbus_int(d.get("TxPower")),
            "company_key": company_key,
        })
    return devices, None


def _scan_stream(controller_hci, duration):
    """Fallback capture: run a timed ``bluetoothctl`` discovery, return raw text."""
    args = [_BTCTL, "--timeout", str(int(duration)), "scan", "on"]
    rc, out, _ = _run(args, timeout=duration + 6)
    return out


def _enrich(mac):
    """Per-device ``bluetoothctl info`` enrichment (fallback path)."""
    rc, out, _ = _run([_BTCTL, "info", mac], timeout=_INFO_TIMEOUT)
    if rc != 0 or not out:
        return {}
    return parse_info(out)


def _scan_bluetoothctl(hci, duration):
    """Fallback roster: bluetoothctl stream + per-device info enrichment."""
    found = parse_scan_stream(_scan_stream(hci, duration))
    devices = []
    for mac, d in found.items():
        info = _enrich(mac)
        if d.get("rssi") is None and info.get("rssi") is not None:
            d["rssi"] = info["rssi"]
        for k in ("addr_type", "cls", "icon", "tx_power"):
            if info.get(k) is not None:
                d[k] = info[k]
        if not d.get("name") and info.get("name"):
            d["name"] = info["name"]
        if d.get("company_key") is None and info.get("company_key") is not None:
            d["company_key"] = info["company_key"]
        devices.append(d)
    return devices


def do_scan(controller=None, duration=_DEFAULT_DURATION, enrich=True):
    """Discover BT/BLE devices and build the 2.4 GHz overlay payload."""
    try:
        duration = max(4, min(_MAX_DURATION, int(duration)))
    except (TypeError, ValueError):
        duration = _DEFAULT_DURATION

    ctrl = _pick_controller(controller)
    if not ctrl or not ctrl.get("hci"):
        return {"error": "no Bluetooth controller found — is bluetoothd running "
                         "and the adapter unblocked (rfkill unblock bluetooth)?",
                "controllers": list_controllers()}

    # Primary: BlueZ D-Bus (clean in-range snapshot with RSSI); fall back to the
    # bluetoothctl text path if python-dbus/BlueZ isn't usable.
    devices, err = _discover_dbus(ctrl["hci"], duration)
    capture = "dbus"
    if devices is None:
        capture = "bluetoothctl"
        devices = _scan_bluetoothctl(ctrl["hci"], duration)

    for d in devices:
        _classify(d)

    # Strongest first; unknown-RSSI devices sink to the bottom.
    devices.sort(key=lambda d: (d.get("rssi") is None, -(d.get("rssi") or -999)))
    interference = analyze_interference(devices)

    return {
        "controller": ctrl["hci"],
        "controller_bus": ctrl.get("bus"),
        "controller_address": ctrl.get("address"),
        "capture": capture,
        "capture_note": err if (capture == "bluetoothctl" and err) else None,
        "timestamp": int(time.time()),
        "duration": duration,
        "device_count": len(devices),
        "devices": devices,
        "interference": interference,
        "coexistence_note": (
            "Bluetooth and 2.4 GHz Wi-Fi share the band. On a combo chip the two "
            "radios time-share the RF front-end, so running BT discovery and "
            "Wi-Fi monitor capture at full tilt can cost frames on both — this "
            "overlay is best-effort and duty-cycled."),
    }


# --------------------------------------------------------------------------
# Self-test (pure parsing/model checks — no hardware needed)
# --------------------------------------------------------------------------

_SAMPLE_STREAM = """\
[NEW] Device FC:70:2E:B6:3E:8A Tv Hub 2
[NEW] Device 4A:AE:49:C9:5F:2B 4A-AE-49-C9-5F-2B
[CHG] Device 40:CB:C0:E4:DE:CF RSSI: 0xffffffc3 (-61)
[CHG] Device 4A:AE:49:C9:5F:2B ManufacturerData.Key: 0x004c (76)
[NEW] Device 40:CB:C0:E4:DE:CF 40-CB-C0-E4-DE-CF
[CHG] Device FC:70:2E:B6:3E:8A Name: Tv Hub 2
"""

_SAMPLE_INFO_CLASSIC = """\
Device FC:70:2E:B6:3E:8A (public)
\tName: Tv Hub 2
\tAlias: Tv Hub 2
\tClass: 0x003c0420 (3933216)
\tIcon: audio-card
\tPaired: no
\tConnected: no
"""

_SAMPLE_INFO_LE = """\
Device 4A:AE:49:C9:5F:2B (random)
\tAlias: 4A-AE-49-C9-5F-2B
\tManufacturerData.Key: 0x004c (76)
\tRSSI: 0xffffffb0 (-80)
"""

_SAMPLE_LIST = """\
Controller 88:A2:9E:5E:B4:E2 raspberry [default]
Controller 00:11:22:33:44:55 alfa-bt
"""

_SAMPLE_HCICONFIG = """\
hci1:\tType: Primary  Bus: USB
\tBD Address: 00:11:22:33:44:55  ACL MTU: 1021:8  SCO MTU: 64:1
\tUP RUNNING
hci0:\tType: Primary  Bus: UART
\tBD Address: 88:A2:9E:5E:B4:E2  ACL MTU: 1021:8  SCO MTU: 64:1
\tUP RUNNING
"""


def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    # --- stream parser ---
    st = parse_scan_stream(_SAMPLE_STREAM)
    check("stream: all three devices parsed", len(st) == 3, str(len(st)))
    check("stream: signed RSSI extracted from hex+parens",
          st.get("40:CB:C0:E4:DE:CF", {}).get("rssi") == -61,
          str(st.get("40:CB:C0:E4:DE:CF")))
    check("stream: company id captured",
          st.get("4A:AE:49:C9:5F:2B", {}).get("company_key") == 0x004C)
    check("stream: real name kept, dashed-MAC alias ignored",
          st.get("FC:70:2E:B6:3E:8A", {}).get("name") == "Tv Hub 2"
          and st.get("40:CB:C0:E4:DE:CF", {}).get("name") is None,
          str(st.get("40:CB:C0:E4:DE:CF", {}).get("name")))

    # --- info parser ---
    ic = parse_info(_SAMPLE_INFO_CLASSIC)
    check("info: public address type", ic["addr_type"] == "public")
    check("info: class-of-device parsed", ic["cls"] == 0x003C0420, hex(ic["cls"] or 0))
    il = parse_info(_SAMPLE_INFO_LE)
    check("info: random address type", il["addr_type"] == "random")
    check("info: RSSI from info", il["rssi"] == -80, str(il["rssi"]))

    # --- class decode ---
    major, svcs = _decode_class(0x003C0420)
    check("class: major = Audio/Video", major == "Audio/Video", str(major))
    check("class: service bits decoded", "Audio" in svcs and "Rendering" in svcs,
          str(svcs))
    check("class: empty class => no label", _decode_class(0) == (None, []))

    # --- address type / vendor ---
    check("addr: 0x4A is locally-administered (random)",
          _addr_is_random("4A:AE:49:C9:5F:2B") is True)
    check("addr: 0xFC is not random-bit set",
          _addr_is_random("FC:70:2E:B6:3E:8A") is False)
    check("vendor: random addr resolves via company id",
          _vendor_for("4A:AE:49:C9:5F:2B", 0x004C) == "Apple")
    check("vendor: unknown random company => Randomized/private",
          _vendor_for("4A:AE:49:C9:5F:2B", 0x9999) == "Randomized/private")

    # --- classify ---
    d_classic = _classify({"mac": "FC:70:2E:B6:3E:8A", "cls": 0x003C0420})
    check("classify: public + class => classic", d_classic["kind"] == "classic")
    d_le = _classify({"mac": "4A:AE:49:C9:5F:2B", "company_key": 0x004C})
    check("classify: random + no class => le", d_le["kind"] == "le")
    d_dual = _classify({"mac": "4A:AE:49:C9:5F:2B", "cls": 0x001C0000})
    check("classify: random + class => dual", d_dual["kind"] == "dual")

    # --- controllers ---
    cs = _parse_controllers(_SAMPLE_LIST)
    check("controllers: two parsed", len(cs) == 2, str(len(cs)))
    check("controllers: default flag detected",
          cs[0]["is_default"] and not cs[1]["is_default"])
    hc = _parse_hciconfig(_SAMPLE_HCICONFIG)
    check("hciconfig: hci mapped to bus + address",
          hc.get("hci0", {}).get("bus") == "uart"
          and hc.get("hci0", {}).get("address") == "88:A2:9E:5E:B4:E2",
          str(hc.get("hci0")))
    check("hciconfig: usb controller bus detected",
          hc.get("hci1", {}).get("bus") == "usb", str(hc.get("hci1")))

    # --- interference model ---
    devs = [
        {"mac": "4A:AE:49:C9:5F:2B", "rssi": -55, "kind": "le"},
        {"mac": "40:CB:C0:E4:DE:CF", "rssi": -61, "kind": "le"},
        {"mac": "FC:70:2E:B6:3E:8A", "rssi": -75, "kind": "classic"},
    ]
    intf = analyze_interference(devs)
    check("interference: counts split le/classic",
          intf["le_count"] == 2 and intf["classic_count"] == 1)
    check("interference: three advertising markers",
          len(intf["adv_markers"]) == 3
          and [m["adv_channel"] for m in intf["adv_markers"]] == [37, 38, 39])
    check("interference: adv 37 (2402) overlaps Wi-Fi ch1",
          any(c["wifi_channel"] == 1 and c["adv_overlap"] >= 1
              for c in intf["wifi_channels"]))
    check("interference: adv 39 (2480) overlaps Wi-Fi ch13",
          any(c["wifi_channel"] == 13 and c["adv_overlap"] >= 1
              for c in intf["wifi_channels"]))
    check("interference: pressure never exceeds 100",
          all(c["pressure"] <= 100 for c in intf["wifi_channels"]))
    check("interference: empty scan => zero pressure",
          all(c["pressure"] == 0 for c in
              analyze_interference([])["wifi_channels"]))

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Passive Bluetooth/BLE 2.4 GHz scanner")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("controllers")
    ps = sub.add_parser("scan")
    ps.add_argument("--controller", default=None, help="hciN (default: USB-first)")
    ps.add_argument("--duration", type=int, default=_DEFAULT_DURATION)
    ps.add_argument("--no-enrich", action="store_true",
                    help="skip per-device `info` enrichment (faster)")
    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if args.cmd == "controllers":
        print(json.dumps(list_controllers(), indent=2))
    elif args.cmd == "scan":
        print(json.dumps(do_scan(args.controller, args.duration,
                                 enrich=not args.no_enrich), indent=2))
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
