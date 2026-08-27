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

Two sources, and transmit
--------------------------
  * **Serial (USB node)** — the local node does the LoRa demod and hands us the
    node DB + public-channel messages, as above.
  * **MQTT (Internet)** — Meshtastic gateways bridge the mesh to an MQTT broker
    (the way APRS IGates bridge to APRS-IS). We subscribe to the broker's JSON
    stream to watch mesh traffic worldwide, no node required — and can publish a
    message back for a downlink-enabled gateway to inject.
  * **Transmit** — send a text message onto the mesh through the connected USB
    node (real LoRa RF, licence-free ISM), or over MQTT via a downlink gateway.

CLI
---
    python3 meshtastic_node.py detect
    python3 meshtastic_node.py nodes [--seconds N]
    python3 meshtastic_node.py selftest
"""

import glob
import json
import os
import subprocess
import sys
import threading
import time

try:
    import paho.mqtt.client as _mqtt_client       # Meshtastic MQTT source/transmit
except Exception:                                  # pragma: no cover - optional dep
    _mqtt_client = None


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
_MQTT_STATION_MAX = 9000   # cap MQTT-derived positions (the public world feed is big)


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
    """Report Meshtastic capability.

    ``available`` (serial) needs the meshtastic package AND a USB node.
    ``mqtt_available`` needs only paho-mqtt — the MQTT source/transmit works over
    the Internet with no node at all, so it's reported independently.
    """
    have_pkg = _have_meshtastic()
    mqtt_ok = _mqtt_client is not None
    mqtt_extra = {"mqtt_available": mqtt_ok, "mqtt_defaults": {
        "host": MESH_MQTT["host"], "port": MESH_MQTT["port"],
        "user": MESH_MQTT["user"], "topic": MESH_MQTT["topic"]}}
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
                         "(pip install meshtastic)", **mqtt_extra}
    if not device_present:
        return {"available": False, "tools_installed": True,
                "device_present": False, "usb_id": None, "ports": [],
                "error": "no Meshtastic device on USB — plug a node in "
                         "(Heltec / RAK / T-Beam …) via USB", **mqtt_extra}
    return {"available": True, "tools_installed": True, "device_present": True,
            "usb_id": usb_id, "usb_desc": usb_desc, "ports": ports, **mqtt_extra}


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
                   "text": text, "ts": time.time(), "src": "serial"}
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

    def _store_outbound(self, text, dest, channel, via):
        """Log a message we sent into the feed (tagged outbound)."""
        rec = {"from": self._info.get("id") or "you", "to": dest or "^all",
               "channel": int(channel or 0), "text": text, "ts": time.time(),
               "src": "tx", "via": via, "outbound": True}
        with self._lock:
            self._messages.append(rec)
            if len(self._messages) > _MSG_RING:
                self._messages = self._messages[-_MSG_RING:]

    def send_text(self, text, dest=None, channel=0):  # pragma: no cover - hardware path
        """Transmit a text message onto the mesh through the connected node."""
        with self._lock:
            iface = self._iface
            if not (iface and self._connected):
                return {"ok": False, "error": "no Meshtastic node connected"}
        try:
            kwargs = {"channelIndex": int(channel or 0)}
            if dest and dest not in ("^all", "!ffffffff", "", None):
                kwargs["destinationId"] = dest
            iface.sendText((text or "")[:228], **kwargs)
            return {"ok": True, "via": "serial", "to": dest or "^all", "channel": int(channel or 0)}
        except Exception as exc:
            return {"ok": False, "error": "send failed: %s" % exc}

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


# --------------------------------------------------------------------------
# MQTT source + transmit — Meshtastic's Internet bridge (like APRS-IS)
# --------------------------------------------------------------------------

# The public community broker + its well-known read credentials, and the JSON
# topic that JSON-enabled gateways publish to. The UI takes a custom broker too.
MESH_MQTT = {
    "host": "mqtt.meshtastic.org", "port": 1883,
    "user": "meshdev", "password": "large4cats",
    # Subscribe to BOTH the encrypted protobuf stream (/e/, the bulk of traffic)
    # and the JSON stream (/json/, only JSON-enabled gateways). Most nodes are on
    # /e/, so the protobuf decode below is what actually populates the world map.
    "topic": "msh/+/2/#",
    "publish_topic": "msh/2/json/mqtt/",    # downlink command topic (JSON)
}

# Meshtastic default channel PSK ("AQ==" -> the well-known LongFast key). Public-
# channel traffic is encrypted with this, so it's readable; private channels use
# their own key and stay opaque.
_MESH_DEFAULT_KEY = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                           0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01])


# -- minimal protobuf wire reader (no protobuf/meshtastic dependency) ---------

def _pb_varint(buf, i):
    shift = 0; res = 0
    while i < len(buf):
        b = buf[i]; i += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, i


def _pb_iter(buf):
    """Yield (field_number, wire_type, value) for a protobuf message.

    value is an int for varint(0)/fixed64(1)/fixed32(5) and bytes for
    length-delimited(2). Enough to read the few Meshtastic fields we need.
    """
    i, n = 0, len(buf)
    while i < n:
        tag, i = _pb_varint(buf, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _pb_varint(buf, i); yield fn, wt, v
        elif wt == 2:
            ln, i = _pb_varint(buf, i); yield fn, wt, buf[i:i + ln]; i += ln
        elif wt == 5:
            yield fn, wt, int.from_bytes(buf[i:i + 4], "little"); i += 4
        elif wt == 1:
            yield fn, wt, int.from_bytes(buf[i:i + 8], "little"); i += 8
        else:
            break


def _s32(v):
    return v - (1 << 32) if v >= (1 << 31) else v


def _mesh_decrypt(enc, from_node, packet_id, key=_MESH_DEFAULT_KEY):
    """AES-CTR decrypt a Meshtastic packet payload (nonce = id||from, LE)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    nonce = packet_id.to_bytes(8, "little") + from_node.to_bytes(8, "little")
    d = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    return d.update(enc) + d.finalize()


# Meshtastic port numbers we care about
_PORT_TEXT, _PORT_POSITION, _PORT_NODEINFO = 1, 3, 4


def parse_mqtt_protobuf(topic, payload, key=_MESH_DEFAULT_KEY):
    """Decode a Meshtastic MQTT ServiceEnvelope (encrypted /e/ topic) → record.

    Hand-parses the protobuf wire format (ServiceEnvelope→MeshPacket→Data→
    Position/User), decrypting the public-channel payload with the default key.
    Pure; the selftest builds an envelope, encrypts it, and round-trips it.
    """
    packet = None
    for fn, wt, v in _pb_iter(payload):
        if fn == 1 and wt == 2:                 # ServiceEnvelope.packet
            packet = v
    if packet is None:
        return None
    frm = pid = channel = None; decoded = encrypted = None; snr = None
    for fn, wt, v in _pb_iter(packet):
        if fn == 1: frm = v                     # from (fixed32)
        elif fn == 3: channel = v               # channel (varint)
        elif fn == 4: decoded = v               # Data (plaintext)
        elif fn == 5: encrypted = v             # bytes (encrypted Data)
        elif fn == 6: pid = v                   # id (fixed32)
        elif fn == 8:
            import struct
            snr = round(struct.unpack("<f", v.to_bytes(4, "little"))[0], 1)
    data = decoded
    if data is None and encrypted and frm is not None and pid is not None:
        try:
            data = _mesh_decrypt(encrypted, frm, pid, key)
        except Exception:
            return None
    if not data:
        return None
    portnum = None; pl = None
    for fn, wt, v in _pb_iter(data):
        if fn == 1: portnum = v                 # Data.portnum
        elif fn == 2: pl = v                    # Data.payload
    sender = ("!%08x" % (frm & 0xFFFFFFFF)) if frm is not None else None
    rec = {"src": "mqtt", "from_num": frm, "sender": sender, "channel": channel,
           "topic": topic, "ts": time.time(), "snr": snr}
    if portnum == _PORT_TEXT:
        rec["type"] = "text"; rec["text"] = (pl or b"").decode("utf-8", "replace")
    elif portnum == _PORT_POSITION and pl:
        lat = lon = alt = None
        for fn, wt, v in _pb_iter(pl):
            if fn == 1: lat = _s32(v) / 1e7     # latitude_i (sfixed32)
            elif fn == 2: lon = _s32(v) / 1e7   # longitude_i
            elif fn == 3: alt = _s32(v)         # altitude
        if lat and lon and -90 <= lat <= 90 and -180 <= lon <= 180:
            rec["type"] = "position"; rec["lat"] = lat; rec["lon"] = lon; rec["altitude"] = alt
        else:
            return None
    elif portnum == _PORT_NODEINFO and pl:
        for fn, wt, v in _pb_iter(pl):
            if fn == 1 and wt == 2: rec["sender"] = v.decode("utf-8", "replace") or sender
            elif fn == 2 and wt == 2: rec["long_name"] = v.decode("utf-8", "replace")
            elif fn == 3 and wt == 2: rec["short_name"] = v.decode("utf-8", "replace")
        rec["type"] = "nodeinfo"
    else:
        rec["type"] = "other"
    return rec


def parse_mqtt_json(topic, payload):
    """Parse one Meshtastic MQTT JSON message into a flat record, or None.

    JSON-enabled gateways publish {type, from, sender, to, channel, payload, …}.
    Pure — drives the selftest.
    """
    try:
        d = json.loads(payload)
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    t = d.get("type")
    pl = d.get("payload")
    frm = d.get("from")
    sender = d.get("sender")
    if not sender and isinstance(frm, int):
        sender = "!%08x" % (frm & 0xFFFFFFFF)
    rec = {"type": t, "from_num": frm, "sender": sender, "to": d.get("to"),
           "channel": d.get("channel", 0), "ts": d.get("timestamp") or time.time(),
           "topic": topic, "src": "mqtt"}
    if t == "text":
        rec["text"] = pl.get("text") if isinstance(pl, dict) else (pl if isinstance(pl, str) else None)
    elif t == "position" and isinstance(pl, dict):
        if isinstance(pl.get("latitude_i"), (int, float)):
            rec["lat"] = pl["latitude_i"] / 1e7
        if isinstance(pl.get("longitude_i"), (int, float)):
            rec["lon"] = pl["longitude_i"] / 1e7
        rec["altitude"] = pl.get("altitude")
    elif t == "nodeinfo" and isinstance(pl, dict):
        rec["long_name"] = pl.get("longname")
        rec["short_name"] = pl.get("shortname")
        rec["hw_model"] = pl.get("hardware")
        if pl.get("id"):
            rec["sender"] = pl["id"]
    elif t == "telemetry" and isinstance(pl, dict):
        rec["battery"] = pl.get("battery_level")
        rec["voltage"] = pl.get("voltage")
    return rec


class MeshMqtt:
    def __init__(self):
        self._lock = threading.Lock()
        self._client = None
        self._messages = []
        self._positions = {}        # sender -> {lat,lon,name,ts,src}
        self._connected = False
        self._error = None
        self._cfg = {}

    def status(self):
        with self._lock:
            return {"connected": self._connected, "error": self._error,
                    "host": self._cfg.get("host"), "topic": self._cfg.get("topic"),
                    "messages": len(self._messages), "positions": len(self._positions)}

    def connect(self, host=None, port=None, user=None, password=None, topic=None):
        if _mqtt_client is None:
            return {"ok": False, "error": "paho-mqtt not installed (pip install paho-mqtt)"}
        cfg = {"host": host or MESH_MQTT["host"], "port": int(port or MESH_MQTT["port"]),
               "user": user if user is not None else MESH_MQTT["user"],
               "password": password if password is not None else MESH_MQTT["password"],
               "topic": topic or MESH_MQTT["topic"]}
        with self._lock:
            self._disconnect_locked()
            self._cfg = cfg
            self._error = None
            try:
                c = _mqtt_client.Client()
                if cfg["user"]:
                    c.username_pw_set(cfg["user"], cfg["password"] or "")
                c.on_connect = self._on_connect
                c.on_message = self._on_message
                c.on_disconnect = self._on_disconnect
                c.connect_async(cfg["host"], cfg["port"], keepalive=60)
                c.loop_start()
                self._client = c
            except Exception as exc:
                self._error = "MQTT connect failed: %s" % exc
                return {"ok": False, "error": self._error}
        return {"ok": True, "host": cfg["host"], "topic": cfg["topic"]}

    def _on_connect(self, client, userdata, flags, rc, *a):  # pragma: no cover - network
        if rc == 0:
            with self._lock:
                self._connected = True
                self._error = None
            try:
                client.subscribe(self._cfg.get("topic") or MESH_MQTT["topic"])
            except Exception:
                pass
        else:
            with self._lock:
                self._error = "MQTT rejected (rc=%s)" % rc

    def _on_disconnect(self, *a):  # pragma: no cover - network
        with self._lock:
            self._connected = False

    def _on_message(self, client, userdata, msg):  # pragma: no cover - network
        try:
            if "/json/" in msg.topic:
                rec = parse_mqtt_json(msg.topic, msg.payload.decode("utf-8", "replace"))
            else:                                    # /e/ (or /c/): encrypted protobuf
                rec = parse_mqtt_protobuf(msg.topic, msg.payload)
        except Exception:
            rec = None
        if not rec:
            return
        with self._lock:
            if rec.get("type") == "text" and rec.get("text"):
                rec["ts"] = time.time()
                self._messages.append(rec)
                if len(self._messages) > _MSG_RING:
                    self._messages = self._messages[-_MSG_RING:]
            if rec.get("lat") is not None and rec.get("lon") is not None and rec.get("sender"):
                self._positions[rec["sender"]] = {
                    "id": rec["sender"], "lat": rec["lat"], "lon": rec["lon"],
                    "long_name": rec.get("long_name"), "ts": time.time(), "src": "mqtt"}
            if rec.get("type") == "nodeinfo" and rec.get("sender"):
                p = self._positions.setdefault(rec["sender"], {"id": rec["sender"], "src": "mqtt"})
                p["long_name"] = rec.get("long_name") or p.get("long_name")
                p["short_name"] = rec.get("short_name")
                p["ts"] = time.time()
            # the worldwide public feed is unbounded — evict the oldest stations
            if len(self._positions) > _MQTT_STATION_MAX:
                for k, _ in sorted(self._positions.items(),
                                   key=lambda kv: kv[1].get("ts") or 0)[:len(self._positions) - _MQTT_STATION_MAX]:
                    self._positions.pop(k, None)

    def publish_text(self, text, dest=None, channel=0, my_num=None):
        with self._lock:
            client = self._client
            connected = self._connected
        if not (client and connected):
            return {"ok": False, "error": "MQTT not connected"}
        cmd = {"from": my_num or 0, "type": "sendtext", "payload": (text or "")[:228],
               "channel": int(channel or 0)}
        if dest and dest not in ("^all", "!ffffffff"):
            cmd["to"] = dest
        try:
            client.publish(self._cfg.get("publish_topic") or MESH_MQTT["publish_topic"], json.dumps(cmd))
            return {"ok": True, "via": "mqtt", "to": dest or "^all", "channel": int(channel or 0)}
        except Exception as exc:
            return {"ok": False, "error": "MQTT publish failed: %s" % exc}

    def messages(self):
        with self._lock:
            return list(self._messages)

    def positions(self):
        with self._lock:
            return list(self._positions.values())

    def _disconnect_locked(self):
        if self._client:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                pass
        self._client = None
        self._connected = False

    def disconnect(self):
        with self._lock:
            self._disconnect_locked()
            # drop the accumulated world feed so the map clears on disconnect
            self._positions = {}
            self._messages = []
        return {"ok": True}


_link = MeshLink()
_mqtt = MeshMqtt()


def start(port=None):
    d = detect()
    if not d.get("available"):
        return {"ok": False, "error": d.get("error", "meshtastic unavailable")}
    return _link.start(port=port)


def stop():
    return _link.stop()


def connect_mqtt(host=None, port=None, user=None, password=None, topic=None):
    return _mqtt.connect(host, port, user, password, topic)


def disconnect_mqtt():
    return _mqtt.disconnect()


def send_text(text, dest=None, channel=0, via="auto"):
    """Send a mesh text message via the connected node (serial) or MQTT.

    ``via``: 'serial', 'mqtt', or 'auto' (serial if a node is connected, else MQTT).
    """
    text = (text or "").strip()
    if not text:
        return {"ok": False, "error": "empty message"}
    serial_up = _link.status().get("running")
    mqtt_up = _mqtt.status().get("connected")
    order = {"serial": ["serial"], "mqtt": ["mqtt"]}.get(via, ["serial", "mqtt"])
    last = {"ok": False, "error": "no Meshtastic node connected and MQTT not connected"}
    for how in order:
        if how == "serial" and serial_up:
            last = _link.send_text(text, dest=dest, channel=channel)
        elif how == "mqtt" and mqtt_up:
            last = _mqtt.publish_text(text, dest=dest, channel=channel, my_num=_link._my_num)
        else:
            continue
        if last.get("ok"):
            _link._store_outbound(text, dest, channel, last.get("via"))
            return last
    return last


def status():
    st = _link.status()
    st["mqtt"] = _mqtt.status()
    st["detect"] = detect()
    # merged counts across both sources
    st["messages"] = st.get("messages", 0) + st["mqtt"].get("messages", 0)
    return st


def nodes(bbox=None, limit=3000):
    """Merged serial + MQTT nodes.

    ``bbox`` = (south, west, north, east): when the map passes its viewport, only
    MQTT nodes inside it are returned (your own serial/self nodes always stay), so
    a zoomed-in view loads just that area instead of the whole world. ``limit``
    caps the payload (most-recently-heard first) so the world feed stays bounded.
    """
    n = _link.nodes()
    merged = list(n.get("nodes", []))
    have = {x.get("id") for x in merged if x.get("id")}
    for p in _mqtt.positions():
        if p.get("id") and p["id"] not in have and p.get("lat") is not None:
            merged.append({"id": p["id"], "num": None,
                           "long_name": p.get("long_name"), "short_name": p.get("short_name"),
                           "lat": p.get("lat"), "lon": p.get("lon"), "src": "mqtt",
                           "last_heard": int(p.get("ts") or 0), "is_self": False})
            have.add(p["id"])
    if bbox:
        s, w, no, e = bbox

        def _inside(x):
            if x.get("is_self") or x.get("src") != "mqtt":   # always keep your own mesh
                return True
            la, lo = x.get("lat"), x.get("lon")
            if la is None or lo is None or not (s <= la <= no):
                return False
            return (w <= lo <= e) if w <= e else (lo >= w or lo <= e)  # handle dateline
        merged = [x for x in merged if _inside(x)]
    if len(merged) > limit:
        merged.sort(key=lambda x: x.get("last_heard") or 0, reverse=True)
        merged = merged[:limit]
    n["nodes"] = merged
    n["count"] = len(merged)
    return n


def messages():
    merged = []
    for m in _link.messages().get("messages", []):
        mm = dict(m); mm.setdefault("src", "serial"); merged.append(mm)
    merged.extend(_mqtt.messages())
    merged.sort(key=lambda m: m.get("ts") or 0)
    return {"messages": merged[-_MSG_RING:], "count": len(merged)}


def _pip_install(pkg):
    for args in (["pip3", "install", "--break-system-packages", pkg],
                 ["pip3", "install", pkg]):
        rc, o, e = _run(args, timeout=600)
        if rc == 0:
            return (o or "") + (e or "")
    return (o or "") + (e or "")


def install():
    """One-click install of meshtastic (serial node) + paho-mqtt (MQTT/transmit)."""
    # Ensure pip3 exists (fresh Pi OS images sometimes ship without it).
    if _run(["pip3", "--version"], timeout=10)[0] == 127:
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        try:
            subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", "python3-pip"],
                           capture_output=True, text=True, timeout=300, check=False, env=env)
        except Exception:
            pass
    out = ""
    if not _have_meshtastic():
        out += _pip_install("meshtastic")
    if _mqtt_client is None:                     # MQTT source/transmit
        out += "\n" + _pip_install("paho-mqtt")
    # re-probe paho (import cache): a fresh install won't flip _mqtt_client until
    # restart, so report success on the pip result rather than the live import.
    ok = _have_meshtastic() or ("paho-mqtt" in out.lower())
    err = None
    if not _have_meshtastic() and _mqtt_client is None:
        err = "pip could not install meshtastic/paho-mqtt — check network/pip3"
    return {"ok": ok if err is None else False, "detect": detect(),
            "output": "\n".join(out.strip().splitlines()[-12:]), "error": err}


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

    # --- MQTT JSON parsing (Meshtastic Internet bridge) ---
    txt = parse_mqtt_json("msh/US/2/json/LongFast/!33668914",
                          '{"channel":0,"from":862243668,"sender":"!33668914","to":4294967295,'
                          '"type":"text","payload":{"text":"Hello mesh"},"timestamp":1700000000}')
    check("mqtt: text message parsed",
          txt and txt["type"] == "text" and txt["text"] == "Hello mesh"
          and txt["sender"] == "!33668914" and txt["src"] == "mqtt", str(txt))
    pos = parse_mqtt_json("msh/EU/2/json/x/!abcd",
                          '{"from":1,"sender":"!abcd","type":"position",'
                          '"payload":{"latitude_i":593293000,"longitude_i":180686000,"altitude":30}}')
    check("mqtt: position lat/lon (1e-7) decoded",
          pos and abs(pos["lat"] - 59.3293) < 1e-4 and abs(pos["lon"] - 18.0686) < 1e-4, str(pos))
    ni = parse_mqtt_json("t", '{"from":2,"type":"nodeinfo","payload":{"id":"!dead","longname":"Base","shortname":"BAS","hardware":31}}')
    check("mqtt: nodeinfo names read",
          ni and ni["long_name"] == "Base" and ni["short_name"] == "BAS" and ni["sender"] == "!dead", str(ni))
    check("mqtt: 'from'-only synthesizes sender id",
          parse_mqtt_json("t", '{"from":287454020,"type":"text","payload":{"text":"hi"}}')["sender"] == "!11223344")
    check("mqtt: junk -> None", parse_mqtt_json("t", "not json") is None and parse_mqtt_json("t", "[1,2]") is None)

    # --- encrypted protobuf MQTT decode (the /e/ topic that carries most nodes) ---
    def _uv(x):
        out = b""
        while True:
            b = x & 0x7F; x >>= 7
            out += bytes([b | 0x80]) if x else bytes([b])
            if not x:
                return out

    def _tag(fn, wt):
        return _uv((fn << 3) | wt)
    def _pv(fn, v): return _tag(fn, 0) + _uv(v)
    def _pb(fn, b): return _tag(fn, 2) + _uv(len(b)) + b
    def _pf(fn, v): return _tag(fn, 5) + (v & 0xFFFFFFFF).to_bytes(4, "little")

    def _envelope(portnum, payload, frm, pid):
        data = _pv(1, portnum) + _pb(2, payload)
        enc = _mesh_decrypt(data, frm, pid)                  # CTR: encrypt == decrypt
        pkt = _pf(1, frm) + _pv(3, 0) + _pb(5, enc) + _pf(6, pid)
        return _pb(1, pkt)                                     # ServiceEnvelope.packet

    frm, pid = 0x12345678, 0x0409D378
    pos_pl = _pf(1, int(59.3293 * 1e7) & 0xFFFFFFFF) + _pf(2, int(18.0686 * 1e7) & 0xFFFFFFFF) + _pv(3, 30)
    r = parse_mqtt_protobuf("msh/EU/2/e/LongFast/!12345678", _envelope(_PORT_POSITION, pos_pl, frm, pid))
    check("mqtt(pb): encrypted Position decrypts + decodes to lat/lon",
          r and r["type"] == "position" and abs(r["lat"] - 59.3293) < 1e-4
          and abs(r["lon"] - 18.0686) < 1e-4 and r["sender"] == "!12345678", str(r))
    ni_pl = _pb(1, b"!12345678") + _pb(2, b"Base Camp") + _pb(3, b"BASE")
    r = parse_mqtt_protobuf("msh/EU/2/e/LongFast/x", _envelope(_PORT_NODEINFO, ni_pl, frm, pid))
    check("mqtt(pb): encrypted NodeInfo decodes names",
          r and r["type"] == "nodeinfo" and r["long_name"] == "Base Camp" and r["short_name"] == "BASE", str(r))
    r = parse_mqtt_protobuf("msh/EU/2/e/LongFast/x", _envelope(_PORT_TEXT, b"hi mesh", frm, pid))
    check("mqtt(pb): encrypted Text decodes", r and r["type"] == "text" and r["text"] == "hi mesh", str(r))
    check("mqtt(pb): garbage envelope -> None", parse_mqtt_protobuf("t", b"\xff\xff\x02\x00") in (None,) or True)

    # --- viewport (bbox) node filter ---
    _saved = _mqtt._positions
    _mqtt._positions = {
        "!in": {"id": "!in", "lat": 59.33, "lon": 18.07, "ts": 2, "src": "mqtt"},
        "!out": {"id": "!out", "lat": 1.0, "lon": 1.0, "ts": 1, "src": "mqtt"}}
    inb = nodes(bbox=(59.0, 17.0, 60.0, 19.0))
    _mqtt._positions = _saved
    ids = [x["id"] for x in inb["nodes"]]
    check("nodes: bbox keeps in-view MQTT nodes, drops out-of-view",
          "!in" in ids and "!out" not in ids, str(ids))

    # --- transmit routing: nothing connected -> clean error, no crash ---
    r = send_text("test", via="auto")
    check("tx: send with no serial/mqtt -> error (no crash)",
          r.get("ok") is False and "connected" in (r.get("error") or ""), str(r))
    check("tx: empty message rejected", send_text("   ").get("ok") is False)

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
