#!/usr/bin/env python3
"""cyd_serial_bridge.py — USB-serial link between Ragnar and a cabled CYD node.

When a CYD hybrid node is flashed with CYD_TRANSPORT_SERIAL=1 it is wired to the
Pi and speaks newline-delimited JSON over USB instead of joining WiFi:

  node -> Pi : {"t":"in", <2.4 GHz sensor counts>}    (sensor report)
               {"t":"ac","node":..,"action":".."}      (operator tapped a button)
  Pi -> node : {"t":"st", <compact status>}            (dashboard refresh, ~2 s)

This bridge is the Pi end of that link. It is a self-managing daemon thread:
it only opens a port while enabled AND a device is present, and reconnects on
unplug/error — so it is safe to leave running whether or not a CYD is attached.

Serial I/O is POLL-based (in_waiting + read), never readline()/select(): the
Ragnar process runs with 700+ open FDs and pyserial's select() path raises
"filedescriptor out of range in select()" once an FD exceeds 1024 — the same
landmine roomscan_bridge.py documents.
"""

import os
import glob
import json
import time
import threading


def _import_serial():
    try:
        import serial as pyserial  # noqa
        return pyserial
    except Exception:
        return None


def detect_port():
    """First CP210x/USB-UART style device a CYD presents, or None.

    Prefers the stable /dev/serial/by-id path; falls back to a ttyUSB*/ttyACM*
    glob. CYDs ship a CP2102 (Silicon Labs), so match those hints but stay
    permissive."""
    for link in sorted(glob.glob('/dev/serial/by-id/*')):
        low = link.lower()
        if any(h in low for h in ('cp210', 'silicon', 'uart', 'ch340', 'usb')):
            try:
                return os.path.realpath(link)
            except Exception:
                return link
    cands = sorted(glob.glob('/dev/ttyUSB*')) + sorted(glob.glob('/dev/ttyACM*'))
    return cands[0] if cands else None


class CydSerialBridge:
    """Background thread bridging a cabled CYD node to Ragnar's CYD registry.

    Callbacks (all optional-safe):
      build_status() -> dict   : the compact status dict pushed to the node
      on_ingest(payload: dict) : a sensor report arrived
      on_action(node, action)  : the node requested an allowlisted action
      enabled() -> bool        : master on/off (usually a config flag)
    """

    def __init__(self, build_status, on_ingest, on_action, enabled,
                 baud=115200, status_interval=2.0, port=None):
        self._build_status = build_status
        self._on_ingest = on_ingest
        self._on_action = on_action
        self._enabled = enabled
        self._baud = baud
        self._status_interval = status_interval
        self._forced_port = port
        self._thread = None
        self._stop = threading.Event()
        # Observable state for the UI / API.
        self.port = None
        self.connected = False
        self.last_rx = 0.0
        self.last_error = None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name='cyd-serial-bridge',
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def status(self):
        return {
            'enabled': bool(self._safe_enabled()),
            'port': self.port,
            'connected': self.connected,
            'last_rx': int(self.last_rx) if self.last_rx else None,
            'error': self.last_error,
        }

    # ── internals ────────────────────────────────────────────────────────────
    def _safe_enabled(self):
        try:
            return bool(self._enabled())
        except Exception:
            return False

    def _run(self):
        pyserial = _import_serial()
        if pyserial is None:
            self.last_error = 'pyserial not installed'
            return
        while not self._stop.is_set():
            if not self._safe_enabled():
                self._teardown(None)
                time.sleep(1.0)
                continue
            port = self._forced_port or detect_port()
            if not port:
                self._teardown('no CYD device found')
                time.sleep(2.0)
                continue
            try:
                ser = pyserial.Serial(port, self._baud, timeout=0)
            except Exception as exc:
                self._teardown(f'open failed: {exc}')
                time.sleep(2.0)
                continue
            self.port, self.connected, self.last_error = port, True, None
            try:
                self._session(ser)
            except Exception as exc:
                self.last_error = f'session error: {exc}'
            finally:
                try:
                    ser.close()
                except Exception:
                    pass
                self.connected = False
        self._teardown(None)

    def _teardown(self, err):
        self.connected = False
        self.port = None
        if err is not None:
            self.last_error = err

    def _session(self, ser):
        """Read reports + push status until disabled, unplugged, or stopped."""
        buf = bytearray()
        next_status = 0.0
        while not self._stop.is_set() and self._safe_enabled():
            # ── inbound: drain available bytes, split on newline ──────────────
            try:
                n = ser.in_waiting
            except Exception:
                break  # device went away
            if n:
                try:
                    buf.extend(ser.read(n))
                except Exception:
                    break
                while b'\n' in buf:
                    line, _, rest = buf.partition(b'\n')
                    buf = bytearray(rest)
                    self._handle_line(line.decode('utf-8', 'replace').strip())
            # ── outbound: push a status frame on the interval ─────────────────
            now = time.time()
            if now >= next_status:
                next_status = now + self._status_interval
                self._push_status(ser)
            time.sleep(0.05)

    def _handle_line(self, line):
        if not line or line[0] != '{':
            return
        try:
            msg = json.loads(line)
        except Exception:
            return
        if not isinstance(msg, dict):
            return
        self.last_rx = time.time()
        t = msg.get('t')
        if t == 'in':
            try:
                self._on_ingest(msg)
            except Exception:
                pass
        elif t == 'ac':
            try:
                self._on_action(msg.get('node') or 'cyd-node', msg.get('action') or '')
            except Exception:
                pass

    def _push_status(self, ser):
        try:
            st = dict(self._build_status() or {})
        except Exception:
            return
        st['t'] = 'st'
        try:
            ser.write((json.dumps(st, separators=(',', ':')) + '\n').encode('utf-8'))
        except Exception:
            raise  # surfaces as a session error -> reconnect
