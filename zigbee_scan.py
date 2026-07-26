#!/usr/bin/env python3
"""
zigbee_scan.py — On-demand Zigbee / 802.15.4 capture from a HuginnESP companion.

The capture half of the Zigbee overlay (the shaping/interference model lives in
:mod:`zigbee_overlay`). It does **not** need wardriving to be running — it talks
to a USB-connected Huginn directly, the same way a terminal would:

    1. find the Huginn serial port (an Espressif USB device),
    2. open it at 115200 and send the ``zigbee`` command,
    3. read the streamed ``{"type":"ZIGBEE",…}`` JSON lines for a few seconds
       while Huginn hops channels 11–26 sniffing 802.15.4,
    4. send ``stop``, dedupe by address, and hand the rows to
       :func:`zigbee_overlay.build_overlay`.

Receive-only: 802.15.4 sniffing never transmits. One ESP32-C5 can't do Wi-Fi and
802.15.4 at once, so this briefly puts the Huginn in zigbee mode; a board without
an 802.15.4 radio answers the ``zigbee`` command with a "not compiled in" error,
which we surface rather than hang.

If wardriving is already running it owns the serial port — the web layer checks
that and gates the button, so we don't fight it for the port.

CLI
---
    python3 zigbee_scan.py detect
    python3 zigbee_scan.py scan [--port /dev/ttyACM0] [--duration 8]
    python3 zigbee_scan.py selftest
"""

import glob
import json
import os
import re
import time

import zigbee_overlay

_BAUD = 115200
_DEFAULT_DURATION = 8
_MAX_DURATION = 25


# --------------------------------------------------------------------------
# Port discovery
# --------------------------------------------------------------------------

def _port_is_espressif(port):
    """True iff udev reports an Espressif device on `port` (reuses the same
    check GPS/wardriving use to tell an ESP32 companion from other serial)."""
    try:
        import gps_manager
        return gps_manager._port_is_espressif(port)
    except Exception:
        pass
    try:
        import subprocess
        r = subprocess.run(["udevadm", "info", "-a", port],
                           capture_output=True, text=True, timeout=3)
        return r.returncode == 0 and "espressif" in r.stdout.lower()
    except Exception:
        return False


def find_huginn_ports():
    """Candidate Huginn serial ports (Espressif USB devices), by-id preferred."""
    seen = set()
    ports = []
    by_id = "/dev/serial/by-id"
    if os.path.isdir(by_id):
        for link in sorted(glob.glob(by_id + "/*")):
            real = os.path.realpath(link)
            if real in seen:
                continue
            if _port_is_espressif(real):
                seen.add(real)
                ports.append(link)
    for pat in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        for dev in sorted(glob.glob(pat)):
            real = os.path.realpath(dev)
            if real in seen:
                continue
            if _port_is_espressif(dev):
                seen.add(real)
                ports.append(dev)
    return ports


def detect():
    """Light detection for gating — lists Huginn ports without opening them.

    ``available`` True just means a Huginn-class port is present; whether it can
    actually be opened (or is held by wardriving) is resolved at scan time.
    """
    try:
        import serial  # noqa: F401
        have_serial = True
    except Exception:
        have_serial = False
    ports = find_huginn_ports() if have_serial else []
    if not have_serial:
        return {"available": False, "ports": [], "error": "pyserial not installed"}
    if not ports:
        return {"available": False, "ports": [],
                "error": "no HuginnESP companion found on USB serial"}
    return {"available": True, "ports": ports}


# --------------------------------------------------------------------------
# Line parsing (pure — unit-testable)
# --------------------------------------------------------------------------

def parse_zigbee_lines(lines):
    """Parse Huginn serial output into deduped 802.15.4 device rows.

    Keeps the strongest RSSI per address, and reports whether the board said it
    lacks an 802.15.4 radio. Pure so the selftest can drive it with captured
    output. Returns (rows, capability_error_or_None).
    """
    by_addr = {}
    cap_error = None
    for raw in lines:
        line = (raw or "").strip()
        if not line:
            continue
        if '"error"' in line and "Zigbee not compiled" in line:
            cap_error = "this Huginn has no 802.15.4 radio (needs an ESP32-C5/C6/H2)"
            continue
        if '"type":"ZIGBEE"' not in line.replace(" ", ""):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        addr = obj.get("addr") or obj.get("short") or ""
        if not addr:
            continue
        rssi = obj.get("rssi")
        row = {
            "addr": addr,
            "panid": obj.get("panid") or "",
            "short_addr": obj.get("short") or "",
            "channel": obj.get("channel"),
            "rssi": rssi,
            "lqi": obj.get("lqi"),
            "proto": obj.get("proto") or "zigbee",
            "device_type": obj.get("ftype") or "",
        }
        prev = by_addr.get(addr)
        if prev is None or (rssi is not None and
                            (prev.get("rssi") is None or rssi > prev["rssi"])):
            by_addr[addr] = row
    return list(by_addr.values()), cap_error


# --------------------------------------------------------------------------
# On-demand serial capture
# --------------------------------------------------------------------------

def _valid_port(port):
    return bool(port) and re.match(r"^/dev/[A-Za-z0-9_./-]{1,60}$", port or "") is not None


def scan(port=None, duration=_DEFAULT_DURATION):
    """Run one on-demand Zigbee capture and return the overlay payload."""
    try:
        duration = max(3, min(_MAX_DURATION, int(duration)))
    except (TypeError, ValueError):
        duration = _DEFAULT_DURATION

    try:
        import serial as pyserial
    except Exception:
        return {"error": "pyserial not installed"}

    if port is not None and not _valid_port(port):
        return {"error": "invalid port"}
    if port is None:
        ports = find_huginn_ports()
        if not ports:
            return {"error": "no HuginnESP companion found on USB serial"}
        port = ports[0]

    try:
        ser = pyserial.Serial(port, _BAUD, timeout=0.3)
    except Exception as exc:
        msg = str(exc)
        if "could not open" in msg.lower() or "busy" in msg.lower() or \
                "resource" in msg.lower() or "permission" in msg.lower():
            msg += " — the port may be in use (stop wardriving to scan on demand)"
        return {"error": "cannot open %s: %s" % (port, msg)}

    lines = []
    try:
        try:
            ser.reset_input_buffer()
        except Exception:
            pass
        # Kick off a Zigbee sweep and collect for `duration` seconds.
        ser.write(b"zigbee\n")
        ser.flush()
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                raw = ser.readline().decode("utf-8", "replace")
            except Exception:
                break
            if raw:
                lines.append(raw)
        # Politely stop the sweep so the board isn't left in zigbee mode.
        try:
            ser.write(b"stop\n")
            ser.flush()
        except Exception:
            pass
    finally:
        try:
            ser.close()
        except Exception:
            pass

    rows, cap_error = parse_zigbee_lines(lines)
    if cap_error and not rows:
        return {"error": cap_error, "port": port}
    payload = zigbee_overlay.build_overlay(rows, source="huginn:%s" % os.path.basename(port))
    payload["port"] = port
    payload["duration"] = duration
    if cap_error:
        payload["warning"] = cap_error
    return payload


# --------------------------------------------------------------------------
# Self-test (pure line-parsing — no hardware)
# --------------------------------------------------------------------------

_SAMPLE_LINES = [
    '[ZIGBEE] 802.15.4 radio ready (promiscuous)',
    '{"type":"ZIGBEE","panid":"0x1A62","addr":"00124b0001a2b3c4","channel":15,"rssi":-58,"lqi":210,"ftype":"Data","proto":"zigbee"}',
    '{"type":"ZIGBEE","panid":"0x1A62","addr":"00124b0001a2b3c4","channel":15,"rssi":-49,"lqi":230,"ftype":"Data","proto":"zigbee"}',
    '{"type":"ZIGBEE","panid":"0xFFFF","short":"0x1234","channel":25,"rssi":-77,"lqi":90,"ftype":"Beacon","proto":"thread"}',
    '[CYCLE] zigbee phase: 2 device(s) this sweep, 2 total',
]

_SAMPLE_NO_RADIO = ['{"error":"Zigbee not compiled in (needs 802.15.4 radio, e.g. ESP32-C5)"}']


def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    rows, cap = parse_zigbee_lines(_SAMPLE_LINES)
    check("parse: two unique devices (deduped by addr)", len(rows) == 2, str(len(rows)))
    by = {r["addr"]: r for r in rows}
    check("parse: strongest RSSI kept per device",
          by.get("00124b0001a2b3c4", {}).get("rssi") == -49,
          str(by.get("00124b0001a2b3c4", {}).get("rssi")))
    check("parse: short-addr device captured with its channel",
          any(r["short_addr"] == "0x1234" and r["channel"] == 25 for r in rows))
    check("parse: thread proto preserved",
          any(r["proto"] == "thread" for r in rows))
    check("parse: non-JSON status/cycle lines ignored", len(rows) == 2)
    check("parse: no capability error on a normal sweep", cap is None)

    rows2, cap2 = parse_zigbee_lines(_SAMPLE_NO_RADIO)
    check("parse: 'not compiled in' surfaces as capability error",
          rows2 == [] and cap2 is not None, str(cap2))

    check("port: valid device path accepted", _valid_port("/dev/ttyACM0"))
    check("port: injection attempt rejected", not _valid_port("/dev/tty; rm -rf /"))

    # End-to-end shaping through zigbee_overlay.
    ov = zigbee_overlay.build_overlay(rows, source="test")
    check("overlay: builds from parsed rows", ov["device_count"] == 2)
    check("overlay: ch15 mapped to 2425 MHz marker",
          any(m["channel"] == 15 and m["freq_mhz"] == 2425
              for m in ov["interference"]["markers"]))

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="On-demand Zigbee capture from HuginnESP")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("detect")
    ps = sub.add_parser("scan")
    ps.add_argument("--port", default=None)
    ps.add_argument("--duration", type=int, default=_DEFAULT_DURATION)
    sub.add_parser("selftest")

    args = ap.parse_args(argv)
    if args.cmd == "detect":
        print(json.dumps(detect(), indent=2))
    elif args.cmd == "scan":
        print(json.dumps(scan(port=args.port, duration=args.duration), indent=2))
    elif args.cmd == "selftest":
        r = selftest()
        for item in r["results"]:
            print("  [%s] %s%s" % ("PASS" if item["pass"] else "FAIL", item["name"],
                                   "" if item["pass"] else "  (%s)" % item["detail"]))
        print("\n%d/%d checks pass — %s" %
              (r["passed"], r["total"], "OK" if r["pass"] else "FAILURES"))
        return 0 if r["pass"] else 1
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
