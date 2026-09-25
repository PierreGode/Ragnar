#!/usr/bin/env python3
"""serial_console.py — read-only viewer for a network device's serial console.

Plug a USB console cable (FTDI / CP210x / PL2303 USB-UART with a rollover RJ45)
into Ragnar and the switch, router or firewall console port; the dashboard then
shows whatever the device prints to its console: boot and POST output,
ROMMON / bootloader, kernel panics and crash dumps, and any syslog the device
is configured to send to console (``logging console`` or vendor equivalent).

READ-ONLY BY CONSTRUCTION. Ragnar never sends a byte to the device:

  * the tty is opened O_RDONLY | O_NOCTTY, so a write is impossible at the fd
    level, and this module contains no write call at all (the self-test AST
    guard fails the build if one appears);
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
port. For a hardware-safe setup, use a cable with the TX conductor (RJ45 pin 6
in a rollover pinout, the device's RxD) cut.
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
def _open_readonly(port, baud):
    """Open `port` read-only and configure raw 8N1 with no hangup, no flow
    control and modem lines ignored. Returns the fd."""
    fd = os.open(port, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
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
    """One background thread reading the assigned port into a line ring."""

    def __init__(self):
        self._lock = threading.Lock()
        self._lines = collections.deque(maxlen=RING_LINES)
        self._seq = 0
        self._partial = b''
        self._partial_since = 0.0
        self._thread = None
        self._stop = threading.Event()
        self.port = None
        self.baud_setting = 9600
        self.baud = 9600
        self.state = 'stopped'          # stopped | waiting | reading | disconnected | error
        self.error = None
        self.bytes_total = 0
        self.last_rx = None
        self.started = None
        self._sample = bytearray()
        self._auto_idx = 0

    # -- control -----------------------------------------------------------
    def start(self, port, baud='auto'):
        self.stop()
        self.port = port
        self.baud_setting = baud
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
        if self.state != 'error':
            self.state = 'stopped'

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())

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
                    fd = _open_readonly(self.port, self.baud)
                    self.state = 'reading'
                    self.error = None
                except FileNotFoundError:
                    self.state = 'disconnected'
                    self.error = 'port not present (cable unplugged?)'
                    self._stop.wait(RECONNECT_S)
                    continue
                except Exception as e:
                    self.state = 'error'
                    self.error = '%s: %s' % (type(e).__name__, e)
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
                self.state = 'disconnected'
                self.error = 'read failed (%s); retrying' % (e.strerror or e)
                self._stop.wait(RECONNECT_S)
        self._flush_partial(force=True)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

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
            'running': self.running, 'state': self.state if self.running or self.state == 'error' else 'stopped',
            'port': self.port, 'baud': self.baud, 'baud_setting': self.baud_setting,
            'auto_settled': self.baud_setting == 'auto' and self._sample is None,
            'bytes': self.bytes_total, 'last_rx': self.last_rx, 'started': self.started,
            'error': self.error, 'read_only': True,
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
        try:
            _reader.start(cfg['port'], cfg.get('baud', 'auto'))
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
    save_config({'port': port, 'baud': baud, 'enabled': True})
    _register_claim()
    _reader.start(port, baud)
    return {'success': True, 'status': _reader.status()}


def stop(release=False):
    _reader.stop()
    cfg = load_config()
    if release:
        cfg = {}
    else:
        cfg['enabled'] = False
    save_config(cfg)
    return {'success': True, 'status': _reader.status(), 'reserved': reserved_port()}


def status():
    st = _reader.status()
    st['reserved_port'] = reserved_port()
    return st


def output(since=0, limit=1000):
    lines, last = _reader.lines_since(since, limit)
    return {'lines': lines, 'last': last, 'status': _reader.status()}


def clear():
    _reader.clear()
    return {'success': True}


# ---------------------------------------------------------------------------
# self-test: a pseudo-terminal pair stands in for the USB-UART
# ---------------------------------------------------------------------------
def selftest():
    import ast
    import pty
    results = []

    def check(name, ok, detail=''):
        results.append({'name': name, 'pass': bool(ok), 'detail': str(detail)})

    # 1. passive-invariant: no write/send call anywhere in this module.
    tree = ast.parse(open(os.path.abspath(__file__), encoding='utf-8').read())
    banned = {'write', 'writelines', 'send', 'sendall', 'sendto', 'tcsendbreak',
              'send_break', 'tcflow'}
    bad = []
    # Scan the runtime code only: the self-test itself writes to the pty MASTER
    # to play the device, which is test fixture, not the reader.
    runtime = [node for node in tree.body
               if not (isinstance(node, ast.FunctionDef) and node.name == 'selftest')]
    for n in (x for node in runtime for x in ast.walk(node)):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, 'id', None)
            if name in banned:
                bad.append('%s() line %d' % (name, n.lineno))
    check('passive: no write/send/break call in module', not bad, bad)

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
        rd.start(path, 9600)
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
        # the fd must be read-only: termios flags as configured
        fd = _open_readonly(path, 9600)
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
    finally:
        rd.stop()
        os.close(master)

    # 4. passive auto-baud: garbage at the current rate moves to the next one
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

    # 5. reservation is visible to other components
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

    # 6. the CYD bridge never writes to an unidentified auto-detected port (a
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
