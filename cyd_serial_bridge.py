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


# by-id name fragments of the USB-UART bridges CYD boards ship with: Silicon
# Labs CP210x ("..._CP2102_USB_to_UART_Bridge...") and QinHeng CH340/CH9102
# (vendor 1a86). Deliberately NOT a bare "usb" - every by-id link starts with
# "usb-", so that matched a u-blox GPS puck and the bridge stole its port.
_CYD_BYID_HINTS = ('cp210', 'silicon_labs', 'uart_bridge', 'ch340', 'ch341', 'ch910', '1a86', 'qinheng')
# Receivers that are never a CYD: GPS pucks (u-blox, BU-353 on Prolific).
_NOT_CYD_HINTS = ('prolific', 'pl2303')

# Identify-before-write. An AUTO-detected port is only a guess (CYDs ship with
# generic CP210x / CH340 bridges, and so do many other things — including USB
# console cables wired to a switch, where every newline-terminated frame we
# sent would land on the device's login prompt). So on an auto-detected port
# the bridge stays SILENT until the far end sends a genuine CYD frame; if none
# arrives within IDENTIFY_S the port is handed back and ignored for
# NOT_CYD_BACKOFF_S. A CYD pushes an ingest frame every sync cycle (at most
# ~13 s: 2.5 s sync + 6 s sniff + BLE), so 30 s is over two cycles of margin.
# An explicitly configured port is the operator's assertion and is trusted.
IDENTIFY_S = 30.0
NOT_CYD_BACKOFF_S = 600.0
_CYD_FRAME_TYPES = frozenset(('in', 'ac', 'wr', 'mr', 'wsr', 'wc'))


def _gps_keywords():
    try:
        from gps_manager import GPS_BYID_KEYWORDS
        return GPS_BYID_KEYWORDS
    except Exception:
        return ('gps', 'u-blox', 'ublox', 'nmea', 'gnss', 'bn-', 'vk-')


def _foreign_ports():
    """Ports other Ragnar components hold right now (see serial_claims.py).

    Wardriving companion listeners are not counted: wardriving yields a port
    to the CYD (its USB monitor drops ports the CYD publishes), so the CYD
    must still be able to take one the monitor grabbed first."""
    try:
        import serial_claims
        return serial_claims.claimed(exclude_owner=('cyd', 'wardrive-companions'))
    except Exception:
        return set()


def detect_port(exclude=None):
    """First CP210x/CH340-style device a CYD presents, or None.

    Prefers the stable /dev/serial/by-id path and only accepts the USB-UART
    bridges CYDs ship with - never anything that names itself a GPS, nor a
    port in ``exclude`` (held by another component, e.g. a Meshtastic Heltec
    V3 on the same CP2102 chip). The bare ttyUSB*/ttyACM* fallback only
    considers ports with NO by-id link (an identified device that didn't
    match above is somebody else's port)."""
    exclude = set(exclude or ())
    gps_kw = _gps_keywords()
    identified = set()
    for link in sorted(glob.glob('/dev/serial/by-id/*')):
        try:
            real = os.path.realpath(link)
        except Exception:
            real = link
        identified.add(real)
        low = os.path.basename(link).lower()
        if any(h in low for h in gps_kw) or any(h in low for h in _NOT_CYD_HINTS):
            continue
        if real in exclude:
            continue
        if any(h in low for h in _CYD_BYID_HINTS):
            return real
    cands = sorted(glob.glob('/dev/ttyUSB*')) + sorted(glob.glob('/dev/ttyACM*'))
    for c in cands:
        real = os.path.realpath(c)
        if real not in identified and real not in exclude:
            return c
    return None


class CydSerialBridge:
    """Background thread bridging a cabled CYD node to Ragnar's CYD registry.

    Callbacks (all optional-safe):
      build_status() -> dict   : the compact status dict pushed to the node
      on_ingest(payload: dict) : a sensor report arrived
      on_action(node, action)  : the node requested an allowlisted action
      enabled() -> bool        : master on/off (usually a config flag)
    """

    def __init__(self, build_status, on_ingest, on_action, enabled,
                 baud=115200, status_interval=2.0, port=None, get_port=None,
                 on_wf_request=None, get_wf=None,
                 get_mesh=None, get_wifi=None, on_wifi_connect=None,
                 publish_port=None, write_timeout=1.5):
        self._build_status = build_status
        self._on_ingest = on_ingest
        self._on_action = on_action
        self._enabled = enabled
        self._on_wf_request = on_wf_request   # (band, on) -> None
        self._get_wf = get_wf                  # () -> row dict or None
        self._get_mesh = get_mesh              # () -> roster dict (pushed while on)
        self._get_wifi = get_wifi              # () -> wifi-list dict (pushed while on)
        self._on_wifi_connect = on_wifi_connect  # (ssid, pw) -> None
        self._publish_port = publish_port        # (port_or_None) -> None
        self._mesh_on = False
        self._wifi_on = False
        self._identified = False  # auto-detected port confirmed as a CYD (see IDENTIFY_S)
        self._not_cyd = {}        # realpath -> ignore-until epoch (auto ports that never answered)
        self._mesh_kick = False   # push a mesh frame ASAP after an 'mr on' request
        self._wifi_kick = False   # push a wifi frame ASAP after a 'wsr on' request
        self._dbg = {'in': 0, 'ac': 0, 'wr': 0, 'mr': 0, 'wsr': 0, 'wc': 0,
                     'wf_sent': 0, 'wf_none': 0, 'wf_bytes': 0, 'wf_err': '',
                     'me_sent': 0, 'wl_sent': 0, 'tx_drop': 0}
        self._baud = baud
        # Bound every write. Over USB the CH340 + usb-serial driver buffer deeply,
        # so a write never blocks; over the direct GPIO UART (a ~32-byte FIFO, no
        # flow control) a write STALLS the whole single-threaded loop whenever the
        # ESP is mid-sniff/BLE/render and not draining — that's the "GPIO gets
        # stuck, statuses don't update". A finite write_timeout turns that stall
        # into a dropped frame we recover from instead of a hang.
        self._write_timeout = write_timeout
        self._status_interval = status_interval
        self._forced_port = port          # static override (tests)
        self._get_port = get_port          # dynamic override (a config getter)
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
        cfg = self._configured_port()
        return {
            'enabled': bool(self._safe_enabled()),
            'port': self.port,                 # the port actually open (None if not)
            'configured_port': cfg,            # the override, or None = auto-detect USB
            'connected': self.connected,
            'last_rx': int(self.last_rx) if self.last_rx else None,
            'error': self.last_error,
            'dbg': dict(getattr(self, '_dbg', {})),   # live counters (diagnostics)
        }

    # ── internals ────────────────────────────────────────────────────────────
    def _safe_enabled(self):
        try:
            return bool(self._enabled())
        except Exception:
            return False

    def _configured_port(self):
        """The port override: static, else the config getter, else None (auto)."""
        if self._forced_port:
            return self._forced_port
        if self._get_port:
            try:
                p = (self._get_port() or '').strip()
                return p or None
            except Exception:
                return None
        return None

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
            # A configured port (e.g. /dev/serial0 for the GPIO-UART wiring) wins;
            # otherwise auto-detect a USB device.
            configured = self._configured_port()
            now = time.time()
            self._not_cyd = {k: v for k, v in self._not_cyd.items() if v > now}
            port = configured or detect_port(exclude=_foreign_ports() | set(self._not_cyd))
            if not port:
                ignored = ', '.join(sorted(self._not_cyd))
                self._teardown('no port (set one, or plug in a USB CYD)' + (
                    '; ignoring %s - it never answered as a CYD' % ignored if ignored else ''))
                time.sleep(2.0)
                continue
            try:
                ser = pyserial.Serial(port, self._baud, timeout=0,
                                      write_timeout=self._write_timeout)
            except Exception as exc:
                self._teardown(f'open failed: {exc}')
                time.sleep(2.0)
                continue
            self.port, self.connected, self.last_error = port, True, None
            self._identified = bool(configured)   # explicit port: trusted; auto: prove it
            self._publish(port)          # let others (e.g. GPS probe) avoid this port
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
                self._publish(None)
        self._teardown(None)

    def _publish(self, port):
        if self._publish_port:
            try:
                self._publish_port(port)
            except Exception:
                pass

    def _teardown(self, err):
        self.connected = False
        self.port = None
        self._publish(None)
        if err is not None:
            self.last_error = err

    def _send(self, ser, frame):
        """Write one frame; NEVER hang the loop on a slow link. A write that
        exceeds write_timeout (a backed-up GPIO UART) raises — we clear the
        partially-queued bytes and drop this frame; the next interval retries.
        Returns True if the frame went out, False if it was dropped."""
        data = (json.dumps(frame, separators=(',', ':')) + '\n').encode('utf-8')
        try:
            ser.write(data)
            return True
        except Exception:
            # Timeout / transient: flush the half-written frame so the next one
            # starts clean, and keep looping (reading stays alive). A truly dead
            # device is caught by the read side (in_waiting raises -> reconnect).
            try:
                ser.reset_output_buffer()
            except Exception:
                pass
            self._dbg['tx_drop'] = self._dbg.get('tx_drop', 0) + 1
            return False

    def _link_backed_up(self, ser):
        """True if the output buffer is piling up (the far end isn't draining).
        Used to skip the heavy waterfall stream instead of queueing rows that
        can't go out — on USB out_waiting stays ~0 so this never trips."""
        try:
            return ser.out_waiting > 512
        except Exception:
            return False

    def _session(self, ser):
        """Read reports + push status until disabled, unplugged, or stopped."""
        buf = bytearray()
        next_status = 0.0
        next_wf = 0.0
        next_mesh = 0.0
        next_wifi = 0.0
        opened_on = self.port
        next_claim_check = 0.0
        identify_deadline = time.time() + IDENTIFY_S
        while not self._stop.is_set() and self._safe_enabled():
            # If the operator points us at a different explicit port, drop this
            # session so _run reopens on the new one.
            cfg = self._configured_port()
            if cfg and cfg != opened_on:
                break
            # An auto-detected port that another component has since reserved
            # (e.g. the Meshtastic link pinned to it) is not ours - hand it back.
            if not cfg and time.time() >= next_claim_check:
                next_claim_check = time.time() + 2.0
                if os.path.realpath(opened_on or '') in _foreign_ports():
                    self.last_error = 'port reserved by another device (set the CYD port explicitly)'
                    break
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
            # ── identify-before-write gate (auto-detected ports only) ──────────
            now = time.time()
            if not self._identified:
                if now >= identify_deadline:
                    real = os.path.realpath(opened_on or '')
                    self._not_cyd[real] = now + NOT_CYD_BACKOFF_S
                    self.last_error = ('no CYD answered on %s within %ds - not a CYD? '
                                       'Ignoring it for %d min (set the CYD port explicitly '
                                       'to force it)' % (opened_on, int(IDENTIFY_S),
                                                         int(NOT_CYD_BACKOFF_S // 60)))
                    break
                time.sleep(0.05)
                continue                  # silent: nothing is written until identified
            # ── outbound: push a status frame on the interval ─────────────────
            if now >= next_status:
                next_status = now + self._status_interval
                self._push_status(ser)
            # ── outbound: waterfall rows while the CYD asks for them ──────────
            # Skip a row if the link is already backed up (slow GPIO UART) — piling
            # 8 rows/s onto a stalled buffer is what starves the status frames.
            if self._get_wf and now >= next_wf and not self._link_backed_up(ser):
                next_wf = now + 0.12          # ~8 rows/s (was 0.3 ≈ 3/s)
                try:
                    row = self._get_wf()
                except Exception as exc:
                    row = None; self._dbg['wf_err'] = str(exc)[:40]
                if row:
                    frame = dict(row, t='wf')
                    self._send(ser, frame)
                    self._dbg['wf_sent'] += 1
                    self._dbg['wf_bytes'] = len(json.dumps(frame, separators=(',', ':')))
                else:
                    self._dbg['wf_none'] += 1
            # ── outbound: mesh roster + wifi list while their screens are open ──
            if self._mesh_kick:
                self._mesh_kick = False; next_mesh = 0.0
            if self._wifi_kick:
                self._wifi_kick = False; next_wifi = 0.0
            if self._mesh_on and self._get_mesh and now >= next_mesh:
                next_mesh = now + 3.0
                try:
                    self._send(ser, dict(self._get_mesh(), t='me'))
                    self._dbg['me_sent'] += 1
                except Exception:
                    pass
            if self._wifi_on and self._get_wifi and now >= next_wifi:
                next_wifi = now + 3.0
                try:
                    self._send(ser, dict(self._get_wifi(), t='wl'))
                    self._dbg['wl_sent'] += 1
                except Exception:
                    pass
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
        if t in _CYD_FRAME_TYPES:
            self._identified = True
        if t in self._dbg:                 # count every known inbound frame type
            self._dbg[t] += 1
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
        elif t == 'wr':                       # waterfall stream request
            if self._on_wf_request:
                try:
                    self._on_wf_request(msg.get('band'), bool(msg.get('on')))
                except Exception:
                    pass
        elif t == 'mr':                       # mesh roster stream request
            on = bool(msg.get('on'))
            if on and not self._mesh_on:
                self._mesh_kick = True         # first frame goes out immediately
            self._mesh_on = on
        elif t == 'wsr':                      # wifi-list stream request
            on = bool(msg.get('on'))
            if on and not self._wifi_on:
                self._wifi_kick = True
            self._wifi_on = on
        elif t == 'wc':                       # wifi connect (scan index + password)
            if self._on_wifi_connect:
                try:
                    self._on_wifi_connect(msg.get('idx'), msg.get('pw') or '')
                except Exception:
                    pass

    def _push_status(self, ser):
        try:
            st = dict(self._build_status() or {})
        except Exception:
            return
        st['t'] = 'st'
        # Drop-on-stall (see _send): a slow GPIO UART must never hang the push
        # loop. Device-gone is detected on the read side instead of here.
        self._send(ser, st)
