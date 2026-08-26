#!/usr/bin/env python3
"""roomscan_bridge.py — USB-serial bridge between Ragnar and the RoomScan device
(Waveshare ESP32-S3-Touch-LCD-4B running roomscan_s3_lcd firmware).

Two directions over one USB cable (115200 baud, line protocol):
  Ragnar -> device : push the current Wi-Fi scan as an AP list the operator can
                     place on the sketched floor-plan.
  device -> Ragnar : pull the finished map (room outline + placed AP positions)
                     and hand it to the Coverage Heatmap.

Serial I/O is POLL-based, never select/readline: the Ragnar process runs with
700+ open file descriptors and pyserial's select() path raises
"filedescriptor out of range in select()" once an FD exceeds 1024
(same landmine wardriving.py:_serial_listener already documents).

Opening this board's native USB-Serial-JTAG does NOT reset it, so pushing/pulling
does not disturb a map already drawn on the device.
"""

import os
import re
import glob
import time
import json
import select

_BAUD = 115200
_PORT_RE = re.compile(r'^/dev/tty[A-Za-z0-9]+$')


def _import_serial():
    try:
        import serial as pyserial  # noqa
        return pyserial
    except Exception:
        return None


# ── Port discovery ───────────────────────────────────────────────────────────
def detect_port():
    """Return the first Espressif USB-serial device, or None.

    Prefers the stable /dev/serial/by-id path (survives ttyACM renumbering);
    falls back to a plain ttyACM*/ttyUSB* glob.
    """
    for link in sorted(glob.glob('/dev/serial/by-id/*')):
        low = link.lower()
        if 'espressif' in low or 'jtag' in low or '303a' in low:
            try:
                return os.path.realpath(link)
            except Exception:
                return link
    cands = sorted(glob.glob('/dev/ttyACM*')) + sorted(glob.glob('/dev/ttyUSB*'))
    return cands[0] if cands else None


def _valid_port(port):
    return bool(port) and bool(_PORT_RE.match(port))


# ── Low-level serial helpers (poll-based) ────────────────────────────────────
class _Link:
    def __init__(self, ser):
        self.ser = ser
        self.poller = select.poll()
        self.poller.register(ser.fileno(), select.POLLIN)
        self._buf = b''

    def write_line(self, s):
        self.ser.write((s + '\n').encode('utf-8', 'replace'))
        try:
            self.ser.flush()
        except Exception:
            pass

    def read_line(self, deadline):
        """Return the next '\\n'-terminated line (str, stripped) or None by deadline."""
        while True:
            nl = self._buf.find(b'\n')
            if nl >= 0:
                line = self._buf[:nl]
                self._buf = self._buf[nl + 1:]
                return line.decode('utf-8', 'replace').rstrip('\r')
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            events = self.poller.poll(min(remaining, 0.5) * 1000)
            if not events:
                continue
            try:
                chunk = self.ser.read(4096)
            except Exception:
                return None
            if chunk:
                self._buf += chunk

    def drain(self, secs=0.3):
        end = time.time() + secs
        while time.time() < end:
            events = self.poller.poll(50)
            if events:
                try:
                    self.ser.read(4096)
                except Exception:
                    break
        self._buf = b''


def _open(port):
    pyserial = _import_serial()
    if pyserial is None:
        raise RuntimeError('pyserial not installed')
    if not _valid_port(port):
        raise ValueError('invalid serial port')
    # timeout=0 -> non-blocking; we drive I/O with select.poll (see module docstring)
    ser = pyserial.Serial(port, _BAUD, timeout=0, write_timeout=2)
    return _Link(ser)


def _sanitize(s):
    """Strip tab/newline (our field/line delimiters) from a string."""
    return (s or '').replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')


# ── Public API ───────────────────────────────────────────────────────────────
def ping(port=None):
    port = port or detect_port()
    if not _valid_port(port):
        return {'ok': False, 'error': 'no device'}
    try:
        link = _open(port)
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    try:
        link.drain(0.3)
        link.write_line('PING')
        deadline = time.time() + 3.5
        repinged = False
        while True:
            line = link.read_line(min(deadline, time.time() + 1.2))
            if line is None:
                if time.time() >= deadline:
                    return {'ok': False, 'error': 'no PONG', 'port': port}
                if not repinged:          # cold-open race: the first PING can be
                    link.write_line('PING')  # lost before the CDC is listening
                    repinged = True
                continue
            if line == 'PONG':
                return {'ok': True, 'port': port}
            if line.startswith('{"type":"roomscan_hello"'):
                return {'ok': True, 'port': port, 'hello': line}
    finally:
        try:
            link.ser.close()
        except Exception:
            pass


def push_aps(aps, port=None):
    """Push a list of AP dicts to the device.

    Each ap: {ssid, bssid, signal|rssi, band, channel|ch}. Fields map to the
    firmware's tab-delimited AP\\t<i>\\t<ssid>\\t<bssid>\\t<rssi>\\t<band>\\t<ch> line.
    """
    port = port or detect_port()
    if not _valid_port(port):
        return {'ok': False, 'error': 'no device'}
    try:
        link = _open(port)
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    try:
        link.drain(0.3)
        link.write_line('APCLEAR')
        n = 0
        for ap in aps:
            ssid = _sanitize(str(ap.get('ssid', '')))
            bssid = _sanitize(str(ap.get('bssid', '')))
            rssi = ap.get('signal', ap.get('rssi', 0))
            try:
                rssi = int(round(float(rssi))) if rssi is not None else 0
            except Exception:
                rssi = 0
            band = _sanitize(str(ap.get('band', '')))
            ch = ap.get('channel', ap.get('ch', 0)) or 0
            link.write_line(f'AP\t{n}\t{ssid}\t{bssid}\t{rssi}\t{band}\t{ch}')
            n += 1
            if n % 8 == 0:
                time.sleep(0.02)   # let the device drain its RX
        link.write_line('APDONE')
        link.write_line('PING')
        deadline = time.time() + 3.0
        while True:
            line = link.read_line(deadline)
            if line is None:
                # APs were sent; PONG confirmation is best-effort
                return {'ok': True, 'pushed': n, 'port': port, 'confirmed': False}
            if line == 'PONG':
                return {'ok': True, 'pushed': n, 'port': port, 'confirmed': True}
    finally:
        try:
            link.ser.close()
        except Exception:
            pass


def pull_map(port=None, timeout=6.0):
    """Ask the device for its current map; return the parsed dict."""
    port = port or detect_port()
    if not _valid_port(port):
        return {'ok': False, 'error': 'no device'}
    try:
        link = _open(port)
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    try:
        link.drain(0.3)
        link.write_line('SEND')
        deadline = time.time() + timeout
        while True:
            line = link.read_line(deadline)
            if line is None:
                return {'ok': False, 'error': 'no map (timeout)', 'port': port}
            if line.startswith('{"type":"ragnar_roomscan"'):
                try:
                    m = json.loads(line)
                except Exception as e:
                    return {'ok': False, 'error': f'bad json: {e}', 'raw': line}
                return {'ok': True, 'map': m, 'port': port}
    finally:
        try:
            link.ser.close()
        except Exception:
            pass


# ── CLI for manual testing ───────────────────────────────────────────────────
if __name__ == '__main__':
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'ping'
    if cmd == 'ping':
        print(json.dumps(ping()))
    elif cmd == 'push':
        demo = [
            {'ssid': 'HomeNet', 'bssid': 'aa:bb:cc:11:22:33', 'signal': -42, 'band': '2.4', 'channel': 6},
            {'ssid': 'HomeNet_5G', 'bssid': 'aa:bb:cc:11:22:34', 'signal': -55, 'band': '5', 'channel': 44},
            {'ssid': 'Neighbor', 'bssid': 'de:ad:be:ef:00:01', 'signal': -71, 'band': '2.4', 'channel': 11},
        ]
        print(json.dumps(push_aps(demo)))
    elif cmd == 'pull':
        print(json.dumps(pull_map(), indent=2))
    else:
        print('usage: roomscan_bridge.py [ping|push|pull]')
