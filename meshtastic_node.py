#!/usr/bin/env python3
"""
meshtastic_node.py — enumerate a real Meshtastic mesh via a USB companion node.

The RF Waterfall's mesh overlay (rtl_sdr.py) can only see LoRa **energy** — it
can't demodulate the chirps. To actually *identify* a mesh you need a radio that
does the LoRa demod in hardware. A cheap Meshtastic device (Heltec / RAK / LILYGO
T-Beam / etc.) plugged into USB is exactly that: the Meshtastic Python API talks
to it over serial and hands us the decoded mesh — the node list (ids, names, hw
model, role, SNR, hops, battery, GPS position) and text messages on channels the
device holds the key for (the **public** channel key is well-known, so its
traffic is readable; private channels stay encrypted).

This is the honest counterpart to the spectrum overlay: the overlay shows *where*
a mesh is on the band; this shows *who is on it*.

Receive-only in spirit — this module never sends mesh messages; it only reads the
node DB and listens. (The device itself still beacons as a normal mesh node.)

CLI
---
    python3 meshtastic_node.py detect
    python3 meshtastic_node.py nodes [--seconds N]
    python3 meshtastic_node.py selftest
"""

import glob
import os
import subprocess
import sys
import threading
import time


# Common USB-serial chips used by Meshtastic boards (VID:PID) — for detection
# without the meshtastic package present.
_MESH_USB_IDS = {
    "10c4:ea60": "CP2102 (Heltec/others)",
    "1a86:7523": "CH340 (generic)",
    "1a86:55d4": "CH9102 (LILYGO/others)",
    "303a:1001": "ESP32-S3 native USB",
    "303a:0002": "ESP32-S2 native USB",
    "239a:": "Adafruit/RAK nRF52 (any PID)",
    "1915:": "Nordic nRF52 (any PID)",
}

_MSG_RING = 200            # keep the last N decoded text messages


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


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def _have_meshtastic():
    try:
        import meshtastic  # noqa: F401
        return True
    except Exception:
        return False


def parse_lsusb_for_mesh(text):
    """First known Meshtastic USB-serial (usb_id, description) in lsusb (pure)."""
    if not text:
        return None, None
    low = text.lower()
    for usb_id, desc in _MESH_USB_IDS.items():
        key = usb_id.lower()
        if key.endswith(":"):            # VID-only match (nRF52 boards)
            if (" " + key) in (" " + low) or ("id " + key) in low:
                return usb_id, desc
        elif key in low:
            return usb_id, desc
    return None, None


def _serial_ports():
    """Candidate serial device paths (pure-ish; just globs /dev)."""
    return sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))


def detect():
    """Report whether a Meshtastic companion node is usable.

    ``available`` needs the meshtastic Python package AND a serial device that
    looks like a node. Mirrors the other SDR gates.
    """
    have_pkg = _have_meshtastic()
    usb_id, usb_desc = None, None
    rc, out, _ = _run(["lsusb"], timeout=4)
    if rc == 0 and out:
        usb_id, usb_desc = parse_lsusb_for_mesh(out)
    ports = _serial_ports()
    device_present = bool(usb_id) or bool(ports)
    if not have_pkg:
        return {"available": False, "tools_installed": False,
                "device_present": device_present, "usb_id": usb_id,
                "ports": ports,
                "error": "meshtastic Python package not installed "
                         "(pip install meshtastic)"}
    if not device_present:
        return {"available": False, "tools_installed": True,
                "device_present": False, "usb_id": None, "ports": [],
                "error": "no Meshtastic device on USB — plug a node in "
                         "(Heltec / RAK / T-Beam …) via USB"}
    return {"available": True, "tools_installed": True, "device_present": True,
            "usb_id": usb_id, "usb_desc": usb_desc, "ports": ports}


# --------------------------------------------------------------------------
# Node normalization — pure, drives the selftest
# --------------------------------------------------------------------------

def normalize_node(raw, my_num=None):
    """Normalize one raw Meshtastic node dict (as from iface.nodes) → flat record.

    The library's node shape is nested and version-dependent, so we read it
    defensively. Returns id/num/names/hw/role/snr/hops/battery/position/heard.
    """
    if not isinstance(raw, dict):
        return None
    user = raw.get("user") or {}
    pos = raw.get("position") or {}
    metrics = raw.get("deviceMetrics") or {}
    num = raw.get("num")
    nid = user.get("id")
    if nid is None and num is not None:
        nid = "!%08x" % (num & 0xFFFFFFFF)
    lat = pos.get("latitude")
    lon = pos.get("longitude")
    # some firmwares expose scaled ints (1e-7 deg)
    if lat is None and isinstance(pos.get("latitudeI"), (int, float)):
        lat = pos["latitudeI"] / 1e7
    if lon is None and isinstance(pos.get("longitudeI"), (int, float)):
        lon = pos["longitudeI"] / 1e7
    return {
        "id": nid,
        "num": num,
        "long_name": user.get("longName"),
        "short_name": user.get("shortName"),
        "hw_model": user.get("hwModel"),
        "role": user.get("role"),
        "snr": raw.get("snr"),
        "hops": raw.get("hopsAway"),
        "battery": metrics.get("batteryLevel"),
        "voltage": metrics.get("voltage"),
        "lat": lat, "lon": lon,
        "altitude": pos.get("altitude"),
        "last_heard": raw.get("lastHeard"),
        "is_self": (num is not None and num == my_num),
    }


def normalize_nodes(nodes, my_num=None):
    """Normalize a {key: rawnode} dict into a sorted list of records."""
    out = []
    for raw in (nodes or {}).values():
        n = normalize_node(raw, my_num=my_num)
        if n and (n["id"] or n["num"] is not None):
            out.append(n)
    # self first, then by last_heard desc, then name
    out.sort(key=lambda n: (not n["is_self"], -(n["last_heard"] or 0),
                            (n["long_name"] or n["id"] or "")))
    return out


# --------------------------------------------------------------------------
# Live connector (lazy-imports the meshtastic package)
# --------------------------------------------------------------------------

class MeshLink:
    def __init__(self):
        self._lock = threading.Lock()
        self._iface = None
        self._thread = None
        self._stop = threading.Event()
        self._nodes = []
        self._messages = []
        self._my_num = None
        self._info = {}
        self._error = None
        self._connected = False

    def status(self):
        with self._lock:
            return {"running": self._connected,
                    "nodes": len(self._nodes),
                    "messages": len(self._messages),
                    "my_num": self._my_num,
                    "info": self._info,
                    "error": self._error}

    def nodes(self):
        with self._lock:
            return {"nodes": list(self._nodes), "count": len(self._nodes),
                    "my_num": self._my_num, "connected": self._connected,
                    "error": self._error}

    def messages(self):
        with self._lock:
            return {"messages": list(self._messages), "count": len(self._messages)}

    def _on_receive(self, packet=None, interface=None):  # pragma: no cover - hw
        try:
            dec = (packet or {}).get("decoded") or {}
            if dec.get("portnum") not in ("TEXT_MESSAGE_APP", 1):
                return
            text = dec.get("text")
            if text is None and isinstance(dec.get("payload"), (bytes, bytearray)):
                text = dec["payload"].decode("utf-8", "replace")
            rec = {"from": packet.get("fromId") or packet.get("from"),
                   "to": packet.get("toId") or packet.get("to"),
                   "channel": packet.get("channel", 0),
                   "snr": packet.get("rxSnr"), "rssi": packet.get("rxRssi"),
                   "text": text, "ts": time.time()}
            with self._lock:
                self._messages.append(rec)
                if len(self._messages) > _MSG_RING:
                    self._messages = self._messages[-_MSG_RING:]
        except Exception:
            pass

    def _refresh_nodes(self):  # pragma: no cover - hw
        try:
            raw = getattr(self._iface, "nodes", None) or {}
            nn = normalize_nodes(raw, my_num=self._my_num)
            with self._lock:
                self._nodes = nn
        except Exception as exc:
            with self._lock:
                self._error = "node refresh failed: %s" % exc

    def start(self, port=None):  # pragma: no cover - hardware path
        with self._lock:
            if self._connected:
                return {"ok": True, "already": True}
        if not _have_meshtastic():
            return {"ok": False, "error": "meshtastic package not installed"}
        try:
            import meshtastic
            import meshtastic.serial_interface
            from pubsub import pub
        except Exception as exc:
            return {"ok": False, "error": "meshtastic import failed: %s" % exc}
        self._stop.clear()
        self._error = None
        try:
            self._iface = meshtastic.serial_interface.SerialInterface(devPath=port)
        except Exception as exc:
            self._iface = None
            return {"ok": False, "error": "could not open Meshtastic node: %s" % exc}
        # our own node number + basic info
        try:
            mine = getattr(self._iface, "myInfo", None)
            self._my_num = getattr(mine, "my_node_num", None) if mine else None
            meta = getattr(self._iface, "metadata", None)
            self._info = {"firmware": getattr(meta, "firmware_version", None) if meta else None}
        except Exception:
            pass
        try:
            pub.subscribe(self._on_receive, "meshtastic.receive")
        except Exception:
            pass
        self._connected = True
        self._refresh_nodes()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="mesh-link")
        self._thread.start()
        return {"ok": True}

    def _loop(self):  # pragma: no cover - hardware path
        while not self._stop.is_set():
            time.sleep(5)
            if self._stop.is_set():
                break
            self._refresh_nodes()

    def stop(self):
        self._stop.set()
        try:
            if self._iface:
                self._iface.close()
        except Exception:
            pass
        with self._lock:
            self._iface = None
            self._connected = False
        return {"ok": True}


_link = MeshLink()


def start(port=None):
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "meshtastic unavailable")}
    return _link.start(port=port)


def stop():
    return _link.stop()


def status():
    st = _link.status()
    st["detect"] = detect()
    return st


def nodes():
    return _link.nodes()


def messages():
    return _link.messages()


def install():
    """One-click install of the meshtastic Python package (pip). Fixed name."""
    if _have_meshtastic():
        return {"ok": True, "already": True, "detect": detect()}
    out = ""
    # Ensure pip3 exists (fresh Pi OS images sometimes ship without it).
    if _run(["pip3", "--version"], timeout=10)[0] == 127:
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        try:
            subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", "python3-pip"],
                           capture_output=True, text=True, timeout=300, check=False, env=env)
        except Exception:
            pass
    for args in (["pip3", "install", "--break-system-packages", "meshtastic"],
                 ["pip3", "install", "meshtastic"]):
        rc, o, e = _run(args, timeout=600)
        out = (o or "") + (e or "")
        if rc == 0 and _have_meshtastic():
            return {"ok": True, "detect": detect(),
                    "output": "\n".join(out.strip().splitlines()[-10:])}
    return {"ok": _have_meshtastic(), "detect": detect(),
            "output": "\n".join((out or "").strip().splitlines()[-10:]),
            "error": None if _have_meshtastic()
            else "pip could not install meshtastic — check network/pip3, or run: pip3 install meshtastic"}


# --------------------------------------------------------------------------
# Selftest (pure normalization + parsers, no hardware)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    raw = {
        "!7c5b2a10": {
            "num": 2086892048,
            "user": {"id": "!7c5b2a10", "longName": "Base Camp",
                     "shortName": "BASE", "hwModel": "HELTEC_V3", "role": "ROUTER"},
            "position": {"latitude": 59.3293, "longitude": 18.0686, "altitude": 30},
            "snr": 9.5, "hopsAway": 0, "lastHeard": 1700000000,
            "deviceMetrics": {"batteryLevel": 92, "voltage": 4.05},
        },
        "!a1b2c3d4": {
            "num": 2712847316,
            "user": {"id": "!a1b2c3d4", "longName": "Trail Node", "shortName": "TRL",
                     "hwModel": "RAK4631", "role": "CLIENT"},
            "position": {"latitudeI": 593400000, "longitudeI": 180800000},
            "snr": -6.0, "hopsAway": 2, "lastHeard": 1700000200,
        },
    }
    ns = normalize_nodes(raw, my_num=2086892048)
    check("node: two nodes normalized", len(ns) == 2, str(len(ns)))
    base = next((n for n in ns if n["id"] == "!7c5b2a10"), None)
    check("node: names/hw/role/snr/battery read",
          base and base["long_name"] == "Base Camp" and base["short_name"] == "BASE"
          and base["hw_model"] == "HELTEC_V3" and base["role"] == "ROUTER"
          and base["snr"] == 9.5 and base["battery"] == 92, str(base))
    check("node: self flagged + sorted first", ns[0]["is_self"] and ns[0]["num"] == 2086892048)
    trail = next((n for n in ns if n["id"] == "!a1b2c3d4"), None)
    check("node: scaled latI/lonI decoded to degrees",
          trail and abs(trail["lat"] - 59.34) < 1e-4 and abs(trail["lon"] - 18.08) < 1e-4, str(trail))
    check("node: hops away read", trail and trail["hops"] == 2)
    check("node: id synthesized from num when user.id missing",
          normalize_node({"num": 0x11223344, "user": {}})["id"] == "!11223344")
    check("node: junk -> None", normalize_node(None) is None and normalize_node(42) is None)

    # lsusb USB-id probe
    lsu = ("Bus 001 Device 004: ID 10c4:ea60 Silicon Labs CP210x UART Bridge\n"
           "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation root hub\n")
    uid, _ = parse_lsusb_for_mesh(lsu)
    check("usb: CP2102 (10c4:ea60) recognized", uid == "10c4:ea60", str(uid))
    check("usb: nRF52 VID-only match", parse_lsusb_for_mesh(
        "Bus 001 Device 003: ID 239a:8029 Adafruit")[0] == "239a:")
    check("usb: nothing -> None", parse_lsusb_for_mesh("ID 1d6b:0002 root hub") == (None, None))

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
    elif cmd == "nodes":
        secs = 20
        if "--seconds" in argv:
            secs = int(argv[argv.index("--seconds") + 1])
        print(start())
        t0 = time.time()
        try:
            while time.time() - t0 < secs:
                time.sleep(3)
                n = nodes()
                print("nodes=%d" % n["count"])
        finally:
            stop()
    else:
        print("usage: meshtastic_node.py [detect|nodes|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
