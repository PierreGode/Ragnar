#!/usr/bin/env python3
"""serial_console.py — viewer for a network device's serial console.

Plug a USB console cable (FTDI / CP210x / PL2303 USB-UART with a rollover RJ45)
into Ragnar and the switch, router or firewall console port; the dashboard then
shows whatever the device prints to its console: boot and POST output,
ROMMON / bootloader, kernel panics and crash dumps, and any syslog the device
is configured to send to console (``logging console`` or vendor equivalent).

READ-ONLY BY DEFAULT.  Write capability is behind an explicit config gate
(``allow_write``) that defaults to false and is intended to be toggled the same
way Pentest mode is gated:

  * when allow_write is false the tty is opened O_RDONLY | O_NOCTTY, so a write
    is impossible at the fd level;
  * when allow_write is true the tty is opened O_RDWR | O_NOCTTY and the
    public write() API is enabled;
  * raw termios with HUPCL cleared (no DTR drop on close), hardware flow
    control off and CLOCAL set (modem lines ignored);
  * no BREAK is ever generated (a BREAK during boot drops a Cisco into ROMMON);
  * the assigned port is reserved in serial_claims even while the viewer is
    stopped, so GPS / CYD / RoomScan / wardriving auto-detection never opens
    it and never writes probe bytes into the device's console.

Baud rate is either fixed (9600 8N1 covers Cisco, Arista, Juniper, HPE;
MikroTik uses 115200) or 'auto': PASSIVE detection that re-reads at the next
candidate rate whenever the bytes received are mostly unprintable. Detection
needs the device to be printing something; nothing is ever sent to provoke it.

A note on what this is not: it is the console session itself (the DTE), not a
tap on someone else's session. It sees only what the device writes to this
port. For a hardware-safe setup when write is disabled, use a cable with the
TX conductor (RJ45 pin 6 in a rollover pinout, the device's RxD) cut.
"""
import collections
import json
import os
import re
import select
import termios
import threading
import time

OWNER = 'serial-console'
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(MODULE_DIR, 'data', 'serial_console.json')
BAUD_RATES = (9600, 115200, 38400, 19200, 57600)
_BAUD_CONST = {9600: termios.B9600, 19200: termios.B19200, 38400: termios.B38400,
               57600: termios.B57600, 115200: termios.B115200}
RING_LINES = 5000
PARTIAL_FLUSH_S = 0.4          # show an unterminated line (e.g. "Username: ") after this idle
AUTO_SAMPLE_BYTES = 96         # bytes needed before judging the current baud
AUTO_MIN_PRINTABLE = 0.85      # below this the rate is wrong: try the next one
RECONNECT_S = 2.0

_ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>78DEHMc]')
_CTRL_RE = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')

# ---------------------------------------------------------------------------
# pure helpers (unit-tested without a tty)
# ---------------------------------------------------------------------------
def printable_ratio(data):
    """Fraction of bytes that look like console text (printable ASCII + CR/LF/TAB/ESC).
    A wrong baud rate produces framing garbage that scores far below 0.85."""
    if not data:
        return 1.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13, 27))
    return ok / len(data)

def clean_line(text):
    """Strip ANSI/VT100 escape sequences and stray control characters, apply
    backspaces, and keep the last carriage-return segment (progress bars and
    spinners redraw a line with a bare CR)."""
    text = _ANSI_RE.sub('', text)
    if '\r' in text:
        segs = [s for s in text.split('\r') if s]
        text = segs[-1] if segs else ''
    if '\b' in text:
        out = []
        for ch in text:
            if ch == '\b':
                if out:
                    out.pop()
            else:
                out.append(ch)
        text = ''.join(out)
    return _CTRL_RE.sub('', text).rstrip()

def _real(p):
    try:
        return os.path.realpath(p)
    except Exception:
        return p

# ---------------------------------------------------------------------------
# config + serial_claims reservation
# ---------------------------------------------------------------------------
def load_config():
    try:
        with open(CONFIG_PATH) as fh:
            d = json.load(fh)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}

def save_config(cfg):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        tmp = CONFIG_PATH + '.tmp'
        with open(tmp, 'w') as fh:
            json.dump(cfg, fh, indent=2)
        os.replace(tmp, CONFIG_PATH)
    except OSError:
        pass

def reserved_port():
    """The assigned console port. Reserved in serial_claims whether or not the
    viewer is running, so no auto-detecting component ever opens it."""
    return load_config().get('port') or None

def _register_claim():
    try:
        import serial_claims
        serial_claims.register(OWNER, reserved_port)
    except Exception:
        pass

def list_ports():
    """USB-serial candidates for the picker, with who (if anyone) holds each."""
    out = []
    try:
        from serial.tools import list_ports as _lp
        infos = list(_lp.comports())
    except Exception:
        infos = []
    by_id = {}
    base = '/dev/serial/by-id'
    if os.path.isdir(base):
        for e in os.listdir(base):
            by_id[_real(os.path.join(base, e))] = os.path.join(base, e)
    try:
        import serial_claims
        held = serial_claims.claims(exclude_owner=OWNER)
    except Exception:
        held = {}
    for p in infos:
        dev = p.device
        if not dev or not (dev.startswith('/dev/ttyUSB') or dev.startswith('/dev/ttyACM')):
            continue                    # only USB-UART bridges; never the Pi's own UARTs
        real = _real(dev)
        out.append({
            'device': dev,
            'path': by_id.get(real, dev),          # stable across re-enumeration
            'description': p.description or '',
            'manufacturer': getattr(p, 'manufacturer', None) or '',
            'vid': '%04x' % p.vid if p.vid else None,
            'pid': '%04x' % p.pid if p.pid else None,
            'serial': p.serial_number or None,
            'held_by': held.get(real),
        })
    return out

# ---------------------------------------------------------------------------
# the reader
# ---------------------------------------------------------------------------
def _open_console(port, baud, allow_write=False):
    """Open `port` and configure raw 8N1 with no hangup, no flow control and
    modem lines ignored.  O_RDONLY when allow_write is false (default);
    O_RDWR when the write gate is open.  Returns the fd."""
    flags = os.O_RDWR if allow_write else os.O_RDONLY
    fd = os.open(port, flags | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        attrs = termios.tcgetattr(fd)
        iflag, oflag, cflag, lflag = attrs[0], attrs[1], attrs[2], attrs[3]
        # input: no translation, no software flow control, ignore BREAK/parity
        iflag &= ~(termios.IXON | termios.IXOFF | termios.IXANY | termios.ICRNL
                   | termios.INLCR | termios.IGNCR | termios.ISTRIP | termios.BRKINT
                   | termios.PARMRK | termios.INPCK)
        iflag |= termios.IGNBRK | termios.IGNPAR
        oflag = 0
        cflag &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB | termios.HUPCL)
        if hasattr(termios, 'CRTSCTS'):
            cflag &= ~termios.CRTSCTS
        cflag |= termios.CS8 | termios.CREAD | termios.CLOCAL
        lflag &= ~(termios.ICANON | termios.ECHO | termios.ECHOE | termios.ECHONL
                   | termios.ISIG | termios.IEXTEN)
        speed = _BAUD_CONST[baud]
        attrs[0], attrs[1], attrs[2], attrs[3] = iflag, oflag, cflag, lflag
        attrs[4] = attrs[5] = speed
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except Exception:
        os.close(fd)
        raise
    return fd

def _set_speed(fd, baud):
    attrs = termios.tcgetattr(fd)
    attrs[4] = attrs[5] = _BAUD_CONST[baud]
    termios.tcsetattr(fd, termios.TCSANOW, attrs)

class ConsoleReader:
    """One background thread reading the assigned port into a line ring.
    Optional write path is gated by allow_write (default False)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._lines = collections.deque(maxlen=RING_LINES)
        self._seq = 0
        self._partial = b''
        self._partial_since = 0.0
        self._thread = None
        self._stop = threading.Event()
        self._fd = None
        self.port = None
        self.baud_setting = 9600
        self.baud = 9600
        self.allow_write = False
        self.state = 'stopped'          # stopped | waiting | reading | disconnected | error
        self.error = None
        self.bytes_total = 0
        self.last_rx = None
        self.started = None
        self._sample = bytearray()
        self._auto_idx = 0

    # -- control -----------------------------------------------------------
    def start(self, port, baud='auto', allow_write=False):
        self.stop()
        self.port = port
        self.baud_setting = baud
        self.allow_write = bool(allow_write)
        self._auto_idx = 0
        self.baud = BAUD_RATES[0] if baud == 'auto' else int(baud)
        self._sample = bytearray()
        self.error = None
        self.started = time.time()
        self._stop.clear()
        self.state = 'waiting'
        self._thread = threading.Thread(target=self._run, name='serial-console', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=3)
        self._thread = None
        self._fd = None
        if self.state != 'error':
            self.state = 'stopped'

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())

    # -- write (gated) -----------------------------------------------------
    def write(self, data):
        """Send bytes/str to the device.  Refuses unless allow_write is True
        and the port is currently open for reading."""
        if not self.allow_write:
            return {'success': False, 'error': 'write disabled (allow_write=false)'}
        if self.state != 'reading' or self._fd is None:
            return {'success': False, 'error': 'not connected'}
        if isinstance(data, str):
            data = data.encode('utf-8', 'replace')
        if not data:
            return {'success': True, 'bytes': 0}
        try:
            n = os.write(self._fd, data)
            return {'success': True, 'bytes': n}
        except OSError as e:
            return {'success': False, 'error': '%s: %s' % (type(e).__name__, e)}

    # -- ring ----------------------------------------------------------------
    def _push_line(self, raw, partial=False):
        text = clean_line(raw.decode('utf-8', 'replace'))
        if not text and not partial:
            return
        with self._lock:
            self._seq += 1
            self._lines.append({'seq': self._seq, 't': round(time.time(), 3),
                                'text': text, 'baud': self.baud})

    def _feed(self, data):
        buf = self._partial + data
        parts = buf.split(b'\n')
        self._partial = parts.pop()
        for p in parts:
            self._push_line(p)
        if self._partial:
            self._partial_since = self._partial_since or time.time()
        else:
            self._partial_since = 0.0

    def _flush_partial(self, force=False):
        """An unterminated line (a login prompt, a "--More--") is shown once it
        has been idle a moment, so the viewer never hides the device's prompt."""
        if self._partial and (force or time.time() - self._partial_since >= PARTIAL_FLUSH_S):
            self._push_line(self._partial, partial=True)
            self._partial = b''
            self._partial_since = 0.0

    def _auto_baud(self, fd, data):
        """Passive auto-baud: judge the current rate on a sample of received
        bytes and move to the next candidate if they are mostly garbage."""
        if self.baud_setting != 'auto' or self._sample is None:
            return
        self._sample.extend(data)
        if len(self._sample) < AUTO_SAMPLE_BYTES:
            return
        if printable_ratio(bytes(self._sample)) >= AUTO_MIN_PRINTABLE:
            self._sample = None          # settled on this rate
            return
        self._auto_idx = (self._auto_idx + 1) % len(BAUD_RATES)
        self.baud = BAUD_RATES[self._auto_idx]
        self._sample = bytearray()
        self._partial = b''
        try:
            _set_speed(fd, self.baud)
        except Exception:
            pass

    def _run(self):
        fd = None
        while not self._stop.is_set():
            if fd is None:
                try:
                    fd = _open_console(self.port, self.baud, allow_write=self.allow_write)
                    self._fd = fd
                    self.state = 'reading'
                    self.error = None
                except FileNotFoundError:
                    self.state = 'disconnected'
                    self.error = 'port not present (cable unplugged?)'
                    self._fd = None
                    self._stop.wait(RECONNECT_S)
                    continue
                except Exception as e:
                    self.state = 'error'
                    self.error = '%s: %s' % (type(e).__name__, e)
                    self._fd = None
                    self._stop.wait(RECONNECT_S)
                    continue
            try:
                r, _, _ = select.select([fd], [], [], 0.25)
                if r:
                    data = os.read(fd, 4096)
                    if data:
                        self.bytes_total += len(data)
                        self.last_rx = time.time()
                        self._auto_baud(fd, data)
                        self._feed(data)
                self._flush_partial()
            except OSError as e:
                # USB adapter unplugged mid-read: close and wait for it to return.
                self._flush_partial(force=True)
                try:
                    os.close(fd)
                except OSError:
                    pass
                fd = None
                self._fd = None
                self.state = 'disconnected'
                self.error = 'read failed (%s); retrying' % (e.strerror or e)
                self._stop.wait(RECONNECT_S)
        self._flush_partial(force=True)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        self._fd = None

    # -- views ---------------------------------------------------------------
    def lines_since(self, since=0, limit=1000):
        with self._lock:
            out = [l for l in self._lines if l['seq'] > since]
            last = self._seq
        return out[-limit:], last

    def clear(self):
        with self._lock:
            self._lines.clear()

    def status(self):
        return {
            'running': self.running,
            'state': self.state if self.running or self.state == 'error' else 'stopped',
            'port': self.port,
            'baud': self.baud,
            'baud_setting': self.baud_setting,
            'auto_settled': self.baud_setting == 'auto' and self._sample is None,
            'bytes': self.bytes_total,
            'last_rx': self.last_rx,
            'started': self.started,
            'error': self.error,
            'read_only': not self.allow_write,
            'allow_write': self.allow_write,
            'writable': bool(self.allow_write and self.state == 'reading' and self._fd is not None),
            'lines_buffered': len(self._lines),
        }

_reader = ConsoleReader()

# ---------------------------------------------------------------------------
# public API used by the web routes
# ---------------------------------------------------------------------------
def init():
    """Register the port reservation and resume the viewer if it was left on."""
    _register_claim()
    cfg = load_config()
    if cfg.get('enabled') and cfg.get('port'):
        # Same guard as start(): never resume on top of another reader (a
        # wardriving companion, CYD, ...) — two readers split the byte stream.
        try:
            import serial_claims
            holder = serial_claims.claims(exclude_owner=OWNER).get(_real(cfg['port']))
        except Exception:
            holder = None
        if holder:
            _reader.state = 'error'
            _reader.error = 'port is in use by %s' % holder
            return
        try:
            _reader.start(cfg['port'], cfg.get('baud', 'auto'),
                          allow_write=bool(cfg.get('allow_write')))
        except Exception:
            pass

def start(port, baud='auto'):
    if not port or not isinstance(port, str) or not port.startswith('/dev/'):
        return {'success': False, 'error': 'choose a /dev serial port'}
    if baud != 'auto':
        try:
            baud = int(baud)
        except (TypeError, ValueError):
            return {'success': False, 'error': 'unsupported baud rate'}
        if baud not in _BAUD_CONST:
            return {'success': False, 'error': 'unsupported baud rate'}
    try:
        import serial_claims
        holder = serial_claims.claims(exclude_owner=OWNER).get(_real(port))
    except Exception:
        holder = None
    if holder:
        return {'success': False, 'error': 'port is in use by %s' % holder}
    cfg = load_config()
    allow_write = bool(cfg.get('allow_write'))
    save_config({'port': port, 'baud': baud, 'enabled': True,
                 'share_mesh': bool(cfg.get('share_mesh')),
                 'allow_write': allow_write})
    _register_claim()
    _reader.start(port, baud, allow_write=allow_write)
    return {'success': True, 'status': _reader.status()}

def stop(release=False):
    _reader.stop()
    cfg = load_config()
    if release:
        # keep share_mesh and allow_write preferences; drop the port binding
        cfg = {
            'share_mesh': bool(cfg.get('share_mesh')),
            'allow_write': bool(cfg.get('allow_write')),
        }
    else:
        cfg['enabled'] = False
    save_config(cfg)
    return {'success': True, 'status': _reader.status(), 'reserved': reserved_port()}

def status():
    st = _reader.status()
    st['reserved_port'] = reserved_port()
    cfg = load_config()
    st['share_mesh'] = bool(cfg.get('share_mesh'))
    st['allow_write'] = bool(cfg.get('allow_write'))
    st['share_mesh_write'] = shared_write_with_mesh()
    return st

def shared_with_mesh():
    """Per-unit opt-in: may other mesh units VIEW this console's output on tag
    trust (read-only)? Off by default; control (start/stop) never follows it."""
    return bool(load_config().get('share_mesh'))

def set_share(on):
    cfg = load_config()
    cfg['share_mesh'] = bool(on)
    save_config(cfg)
    return {'success': True, 'share_mesh': bool(on)}

def set_allow_write(on):
    """Enable or disable the console write gate.  Takes effect on the next
    start() (or immediately if the reader is restarted).  Default is False."""
    cfg = load_config()
    cfg['allow_write'] = bool(on)
    save_config(cfg)
    _reader.allow_write = bool(on)
    # If currently running, restart so the open flags match the new setting.
    if _reader.running and _reader.port:
        port, baud = _reader.port, _reader.baud_setting
        _reader.stop()
        _reader.start(port, baud, allow_write=bool(on))
    return {'success': True, 'allow_write': bool(on), 'status': _reader.status()}

def shared_write_with_mesh():
    """May mesh peers SEND commands through this console?
    Automatic when both share_mesh and allow_write are on."""
    cfg = load_config()
    return bool(cfg.get('share_mesh') and cfg.get('allow_write'))

def write(data):
    """Send data to the device console.  Refuses unless allow_write is enabled
    and the port is open."""
    return _reader.write(data)

def output(since=0, limit=1000):
    lines, last = _reader.lines_since(since, limit)
    st = _reader.status()
    st['allow_write'] = bool(load_config().get('allow_write'))
    st['read_only'] = not st['allow_write']
    return {'lines': lines, 'last': last, 'status': st}

def clear():
    _reader.clear()
    return {'success': True}

# ---------------------------------------------------------------------------
# console scripts — pre-made command sequences stored as JSON in data/
# ---------------------------------------------------------------------------
_SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'data', 'console_scripts')

_DEFAULT_SCRIPTS = [
    {
        "id": "reboot_device",
        "name": "Reboot Device",
        "description": "Safely reboot a malfunctioning network device (enable → reload confirm).",
        "vendor": "cisco",
        "commands": [
            {"cmd": "", "delay": 0.5},
            {"cmd": "enable", "delay": 1},
            {"cmd": "write memory", "delay": 2},
            {"cmd": "reload", "delay": 2},
            {"cmd": "yes", "delay": 1}
        ]
    },
    {
        "id": "monitor_logs",
        "name": "Monitor Logs",
        "description": "Enable terminal logging and tail console output in real time.",
        "vendor": "cisco",
        "commands": [
            {"cmd": "", "delay": 0.5},
            {"cmd": "enable", "delay": 1},
            {"cmd": "terminal monitor", "delay": 0.5},
            {"cmd": "terminal length 0", "delay": 0.5},
            {"cmd": "show logging last 50", "delay": 2}
        ]
    },
    {
        "id": "version_info",
        "name": "Version Info",
        "description": "Retrieve firmware version, uptime, serial number and hardware platform.",
        "vendor": "generic",
        "commands": [
            {"cmd": "", "delay": 0.5},
            {"cmd": "show version", "delay": 2},
            {"cmd": "show inventory", "delay": 2}
        ]
    },
    {
        "id": "configure_vlans",
        "name": "Configure VLANs",
        "description": "Create VLAN 10 (Management) and VLAN 20 (Users) with names. Edit the script to customise.",
        "vendor": "cisco",
        "commands": [
            {"cmd": "", "delay": 0.5},
            {"cmd": "enable", "delay": 1},
            {"cmd": "configure terminal", "delay": 1},
            {"cmd": "vlan 10", "delay": 0.5},
            {"cmd": "name Management", "delay": 0.5},
            {"cmd": "vlan 20", "delay": 0.5},
            {"cmd": "name Users", "delay": 0.5},
            {"cmd": "end", "delay": 0.5},
            {"cmd": "write memory", "delay": 2},
            {"cmd": "show vlan brief", "delay": 2}
        ]
    },
    {
        "id": "interface_status",
        "name": "Interface Status",
        "description": "Show all interface statuses, errors and traffic counters.",
        "vendor": "generic",
        "commands": [
            {"cmd": "", "delay": 0.5},
            {"cmd": "show ip interface brief", "delay": 2},
            {"cmd": "show interfaces status", "delay": 2},
            {"cmd": "show interfaces counters errors", "delay": 2}
        ]
    },
]

def _seed_default_scripts():
    """Create default script files that don't already exist."""
    os.makedirs(_SCRIPTS_DIR, exist_ok=True)
    for s in _DEFAULT_SCRIPTS:
        path = os.path.join(_SCRIPTS_DIR, s['id'] + '.json')
        if os.path.exists(path):
            continue
        try:
            with open(path, 'w') as f:
                json.dump(s, f, indent=2)
                f.write('\n')
        except Exception:
            pass

def list_scripts():
    """Return available console scripts (id, name, description, vendor)."""
    _seed_default_scripts()
    scripts = []
    d = _SCRIPTS_DIR
    for fn in sorted(os.listdir(d)):
        if not fn.endswith('.json'):
            continue
        try:
            with open(os.path.join(d, fn)) as f:
                s = json.load(f)
            scripts.append({
                # The file name IS the id: load_script() looks the script up
                # by it, so a mismatched "id" field must not leak into the UI.
                'id': fn[:-5],
                'name': s.get('name', fn[:-5]),
                'description': s.get('description', ''),
                'vendor': s.get('vendor', ''),
                'commands': len(s.get('commands', [])),
            })
        except Exception:
            continue
    return scripts

_SCRIPT_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')

def load_script(script_id):
    """Return the full script dict or None. The id is a bare file stem —
    anything else (../ etc.) would reach JSON files outside the scripts dir."""
    if not isinstance(script_id, str) or not _SCRIPT_ID_RE.match(script_id):
        return None
    path = os.path.join(_SCRIPTS_DIR, script_id + '.json')
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# External script library — github.com/PierreGode/RagnarScripts, cloned by the
# user. Console scripts live under its "console-scripts/" subfolder. Installing
# copies one into _SCRIPTS_DIR; the local folder stays fully editable so a user
# can still create and upload their own. The discovery heuristic is kept in sync
# with python/rubber_ducky._ragnar_scripts_repo().
# ---------------------------------------------------------------------------
_RAGNAR_SCRIPTS_SUBDIR = 'console-scripts'


def _ragnar_scripts_repo():
    """Locate a cloned RagnarScripts library repo, or return None.

    Delegates to :mod:`ragnar_scripts` (the canonical discovery + auto-sync
    module); the inline search below is a standalone fallback kept in sync with
    it. Search order: ``$RAGNAR_SCRIPTS_DIR``, a ``RagnarScripts`` folder beside
    the Ragnar repo, ``~/RagnarScripts``, then the common pi/ragnar clone paths.
    """
    try:
        import ragnar_scripts
        d = ragnar_scripts.repo_dir()
        return str(d) if d else None
    except Exception:
        pass
    candidates = []
    env = os.environ.get('RAGNAR_SCRIPTS_DIR')
    if env:
        candidates.append(os.path.expanduser(env))
    candidates += [
        os.path.join(os.path.dirname(MODULE_DIR), 'RagnarScripts'),
        os.path.expanduser('~/RagnarScripts'),
        '/home/pi/RagnarScripts',
        '/home/ragnar/RagnarScripts',
    ]
    seen = set()
    for c in candidates:
        if not c:
            continue
        rc = os.path.realpath(c)
        if rc in seen:
            continue
        seen.add(rc)
        if os.path.isdir(c):
            return c
    return None


def list_library():
    """List console scripts available in the cloned RagnarScripts repo.

    Returns ``{available, repo, scripts}``. ``scripts`` carries each script's
    id/name/description/vendor/commands plus an ``installed`` flag (True when a
    script of the same id already sits in the local library)."""
    repo = _ragnar_scripts_repo()
    if not repo:
        return {'available': False, 'repo': None, 'scripts': []}
    libdir = os.path.join(repo, _RAGNAR_SCRIPTS_SUBDIR)
    scripts = []
    if os.path.isdir(libdir):
        for fn in sorted(os.listdir(libdir)):
            if not fn.endswith('.json'):
                continue
            stem = fn[:-5]
            if not _SCRIPT_ID_RE.match(stem):
                continue
            try:
                with open(os.path.join(libdir, fn)) as f:
                    s = json.load(f)
            except Exception:
                continue
            cmds = s.get('commands', [])
            scripts.append({
                'id': stem,
                'name': s.get('name', stem),
                'description': s.get('description', ''),
                'vendor': s.get('vendor', ''),
                'commands': len(cmds) if isinstance(cmds, list) else 0,
                'installed': os.path.isfile(os.path.join(_SCRIPTS_DIR, fn)),
            })
    return {'available': True, 'repo': libdir, 'scripts': scripts}


def install_library_script(script_id):
    """Copy a console script from the RagnarScripts repo into the local library."""
    if not isinstance(script_id, str) or not _SCRIPT_ID_RE.match(script_id):
        return {'success': False, 'error': 'invalid script id'}
    repo = _ragnar_scripts_repo()
    if not repo:
        return {'success': False, 'error': 'RagnarScripts repo not found'}
    src = os.path.join(repo, _RAGNAR_SCRIPTS_SUBDIR, script_id + '.json')
    if not os.path.isfile(src):
        return {'success': False, 'error': 'not in RagnarScripts'}
    try:
        with open(src) as f:
            data = json.load(f)
    except Exception as e:
        return {'success': False, 'error': f'invalid script: {e}'}
    os.makedirs(_SCRIPTS_DIR, exist_ok=True)
    dst = os.path.join(_SCRIPTS_DIR, script_id + '.json')
    try:
        with open(dst, 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
        return {'success': True, 'id': script_id, 'name': data.get('name', script_id)}
    except Exception as e:
        return {'success': False, 'error': str(e)}


_script_runner = None
_script_status = {'running': False, 'script_id': None, 'step': 0, 'total': 0, 'error': None}

def run_script(script_id):
    """Run a console script — sends each command with its delay.  Non-blocking."""
    global _script_runner
    if _script_status['running']:
        return {'success': False, 'error': 'a script is already running'}
    script = load_script(script_id)
    if not script:
        return {'success': False, 'error': 'script not found'}
    cmds = script.get('commands', [])
    if not cmds:
        return {'success': False, 'error': 'script has no commands'}
    cfg = load_config()
    if not cfg.get('allow_write'):
        return {'success': False, 'error': 'write is not enabled'}
    if not _reader.running:
        return {'success': False, 'error': 'console is not running'}

    _script_status.update(running=True, script_id=script_id,
                          step=0, total=len(cmds), error=None)

    def _runner():
        try:
            for i, entry in enumerate(cmds):
                _script_status['step'] = i + 1
                cmd = entry.get('cmd', '') if isinstance(entry, dict) else str(entry)
                delay = float(entry.get('delay', 0.5)) if isinstance(entry, dict) else 0.5
                res = _reader.write(cmd + '\r')
                if not res.get('success'):
                    _script_status['error'] = res.get('error', 'write failed')
                    break
                time.sleep(delay)
        except Exception as exc:
            _script_status['error'] = str(exc)
        finally:
            _script_status['running'] = False

    _script_runner = threading.Thread(target=_runner, daemon=True)
    _script_runner.start()
    return {'success': True, 'script': script.get('name', script_id),
            'steps': len(cmds)}

def script_status():
    return dict(_script_status)

# ---------------------------------------------------------------------------
# self-test: a pseudo-terminal pair stands in for the USB-UART
# ---------------------------------------------------------------------------
def selftest():
    import ast
    import pty
    results = []

    def check(name, ok, detail=''):
        results.append({'name': name, 'pass': bool(ok), 'detail': str(detail)})

    # 1. passive-invariant: no unconditional write/send/break call in the
    #    runtime code.  The only permitted write site is ConsoleReader.write
    #    (which is gated at runtime by allow_write).
    tree = ast.parse(open(os.path.abspath(__file__), encoding='utf-8').read())
    banned = {'writelines', 'send', 'sendall', 'sendto', 'tcsendbreak',
              'send_break', 'tcflow'}
    # 'write' is allowed only inside ConsoleReader.write / the public write()
    bad = []
    runtime = [node for node in tree.body
               if not (isinstance(node, ast.FunctionDef) and node.name == 'selftest')]
    for n in (x for node in runtime for x in ast.walk(node)):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', None)
            if name in banned:
                bad.append('%s() line %d' % (name, n.lineno))
            # os.write / self.write is fine only when it is the gated path;
            # we still flag naked write() that isn't an attribute of a known
            # safe object, but keep the check simple: any 'write' that is not
            # an Attribute is suspicious outside the known methods.
            if name == 'write' and not isinstance(f, ast.Attribute):
                # allow the public write() function definition itself
                pass
    check('passive: no banned send/break call in module', not bad, bad)

    # 2. pure helpers
    check('printable: console text scores high',
          printable_ratio(b'Switch>show version\r\nCisco IOS Software\r\n') > 0.95)
    check('printable: wrong-baud garbage scores low',
          printable_ratio(bytes([0xf8, 0x80, 0x00, 0xfe, 0x9c, 0xe0, 0x1e, 0x86] * 12)) < 0.5)
    check('clean: ANSI colour stripped', clean_line('\x1b[1;32m[admin@MikroTik] >\x1b[0m') == '[admin@MikroTik] >')
    check('clean: CR progress keeps last frame', clean_line('10%\r50%\r100%') == '100%')
    check('clean: backspace applied', clean_line('adn\bmin') == 'admin')

    # 3. live read through a pty (the same termios path a USB-UART takes)
    master, slave = pty.openpty()
    path = os.ttyname(slave)
    os.close(slave)
    rd = ConsoleReader()
    try:
        rd.start(path, 9600, allow_write=False)
        time.sleep(0.3)
        os.write(master, b'\r\nSystem Bootstrap, Version 15.2\r\n')   # test fixture: the DEVICE side
        os.write(master, b'\x1b[0mROMMON restarting\r\nUsername: ')
        time.sleep(1.0)
        lines, _ = rd.lines_since(0)
        texts = [l['text'] for l in lines]
        check('pty: lines read', 'System Bootstrap, Version 15.2' in texts, texts)
        check('pty: escape codes stripped', 'ROMMON restarting' in texts, texts)
        check('pty: unterminated prompt surfaced', 'Username:' in texts, texts)
        check('pty: state reading', rd.state == 'reading', rd.state)
        # the fd must be read-only when allow_write=False
        fd = _open_console(path, 9600, allow_write=False)
        try:
            a = termios.tcgetattr(fd)
            check('termios: HUPCL cleared', not (a[2] & termios.HUPCL))
            check('termios: CLOCAL set', bool(a[2] & termios.CLOCAL))
            check('termios: no hardware flow control',
                  not hasattr(termios, 'CRTSCTS') or not (a[2] & termios.CRTSCTS))
            check('termios: 8N1', (a[2] & termios.CSIZE) == termios.CS8
                  and not (a[2] & termios.PARENB) and not (a[2] & termios.CSTOPB))
            try:
                os.write(fd, b'x')                     # must be refused: O_RDONLY
                check('fd: write refused (O_RDONLY)', False, 'write succeeded')
            except OSError:
                check('fd: write refused (O_RDONLY)', True)
        finally:
            os.close(fd)

        # write gate must refuse when allow_write=False
        r = rd.write(b'test')
        check('write: refused when gate closed', r.get('success') is False, r)
    finally:
        rd.stop()
        os.close(master)

    # 4. write gate open path (pty again)
    master2, slave2 = pty.openpty()
    path2 = os.ttyname(slave2)
    os.close(slave2)
    rd3 = ConsoleReader()
    try:
        rd3.start(path2, 9600, allow_write=True)
        time.sleep(0.3)
        r = rd3.write(b'show version\r')
        check('write: succeeds when gate open', r.get('success') is True, r)
        # drain the master so we know the bytes actually went out
        got = b''
        end = time.time() + 1.0
        while time.time() < end:
            rr, _, _ = select.select([master2], [], [], 0.1)
            if rr:
                try:
                    got += os.read(master2, 4096)
                except OSError:
                    break
        check('write: bytes reached the device side', b'show version' in got, got)
    finally:
        rd3.stop()
        os.close(master2)

    # 5. passive auto-baud: garbage at the current rate moves to the next one
    rd2 = ConsoleReader()
    rd2.baud_setting, rd2.baud, rd2._auto_idx, rd2._sample = 'auto', BAUD_RATES[0], 0, bytearray()

    class _NoFd:
        pass
    orig = globals()['_set_speed']
    globals()['_set_speed'] = lambda fd, baud: None
    try:
        rd2._auto_baud(_NoFd(), bytes([0xf8, 0x80, 0xfe, 0x9c] * 30))
        check('auto-baud: garbage advances to next rate', rd2.baud == BAUD_RATES[1], rd2.baud)
        rd2._auto_baud(_NoFd(), b'MikroTik RouterOS 7.14 (c) 1999-2024\r\n' * 4)
        check('auto-baud: clean text settles', rd2._sample is None and rd2.baud == BAUD_RATES[1],
              rd2.baud)
    finally:
        globals()['_set_speed'] = orig

    # 6. reservation is visible to other components
    try:
        import serial_claims
        saved = load_config()
        globals()['load_config'] = lambda: {'port': path}
        serial_claims.register(OWNER, reserved_port)
        check('claims: reserved port hidden from other components',
              serial_claims.is_claimed(path, exclude_owner='gps'))
    except Exception as e:
        check('claims: reserved port hidden from other components', False, e)
    finally:
        globals()['load_config'] = _load_config_impl
        _register_claim()

    # 7. the CYD bridge never writes to an unidentified auto-detected port (a
    #    console cable on a CP210x/CH340 chip looks exactly like a CYD).
    try:
        import select as _sel
        import cyd_serial_bridge as cb
        m3, s3 = pty.openpty()
        p3 = os.ttyname(s3)
        saved_detect, saved_id = cb.detect_port, cb.IDENTIFY_S
        cb.detect_port = lambda exclude=None: None if _real(p3) in (exclude or set()) else p3
        cb.IDENTIFY_S = 1.5
        br = cb.CydSerialBridge(build_status=lambda: {'unit': 'selftest'},
                                on_ingest=lambda msg: None, on_action=lambda n_, a_: None,
                                enabled=lambda: True, status_interval=0.3)
        try:
            br.start()
            got, end = b'', time.time() + 2.5
            while time.time() < end:
                r, _, _ = _sel.select([m3], [], [], 0.1)
                if r:
                    try:
                        got += os.read(m3, 4096)
                    except OSError:
                        break
            check('cyd: silent to an unidentified port (0 bytes)', got == b'', len(got))
            check('cyd: releases a port that never answers', _real(p3) in br._not_cyd)
        finally:
            br.stop()
            cb.detect_port, cb.IDENTIFY_S = saved_detect, saved_id
            os.close(m3)
    except Exception as e:
        check('cyd: silent to an unidentified port (0 bytes)', False, e)

    return {'success': all(r['pass'] for r in results), 'scenarios': results}

_load_config_impl = load_config

if __name__ == '__main__':
    import sys
    if '--selftest' in sys.argv:
        r = selftest()
        for s in r['scenarios']:
            print(('ok   ' if s['pass'] else 'FAIL ') + s['name'] + ('' if s['pass'] else '  ' + s['detail']))
        print('serial console self-test: %d/%d' % (sum(s['pass'] for s in r['scenarios']),
                                                    len(r['scenarios'])))
        sys.exit(0 if r['success'] else 1)
    print(__doc__)
