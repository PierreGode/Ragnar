# piglet_sync.py
# Pull solo-drive CSV logs off a Piglet over its USB serial port and import
# each one as a Ragnar wardriving session.
#
# Piglet streams rows live while it is plugged into Ragnar, but a drive done
# standalone only exists on Piglet's SD card. Piglet firmware with SerialSync
# (v2.60+) answers a small line protocol on the same USB port:
#
#   @PIGLET HELLO      -> @PH <fw> <chip> <mac> sd=<0|1>
#   @PIGLET LIST       -> @PL BEGIN / @PL F <path>\t<size>\t<active> / @PL END <n>
#   @PIGLET GET <path> -> @PG BEGIN <path> <size> / @PG D <seq> <b64> /
#                         @PG END <path> <size> <crc32>   (or @PG ERR <why>)
#
# Other output (boot log, the live CSV mirror) can interleave between those
# lines; it is handed to `on_other` so live wardriving keeps flowing. Every
# file is checked against its size and CRC32 before import, and imports are
# remembered per Piglet (by MAC) and file name — Piglet moves a file from
# /logs to /uploaded after it uploads it, so the name, not the path, is the
# identity. The file Piglet is currently writing is skipped: its rows reach
# Ragnar through the live stream.

import base64
import csv
import io
import json
import logging
import os
import time
import zlib
from datetime import datetime, timezone

logger = logging.getLogger("PigletSync")

STATE_FILE = 'piglet_imports.json'
HELLO_RETRY_S = 1.0
IDLE_TIMEOUT_S = 8.0          # max silence while a reply is in flight


class PigletSyncError(Exception):
    pass


class PigletLink:
    """Protocol client over a line transport.

    write(bytes)            — send to the device
    readline(timeout_s)     — one line as bytes (b'' on timeout)
    on_other(str)           — receives every non-protocol line (optional)
    """

    def __init__(self, write, readline, on_other=None):
        self._write = write
        self._readline = readline
        self._on_other = on_other or (lambda line: None)

    def _send(self, cmd):
        self._write((cmd + '\n').encode())

    def _next(self, prefixes, timeout_s):
        """Next line starting with one of `prefixes`; others go to on_other.
        Returns None after `timeout_s` without a matching line."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            raw = self._readline(max(0.05, deadline - time.time()))
            if not raw:
                continue
            line = raw.decode('utf-8', errors='replace').strip()
            if not line:
                continue
            if line.startswith(prefixes):
                return line
            try:
                self._on_other(line)
            except Exception as e:                       # never break the sync
                logger.debug(f"on_other failed: {e}")
        return None

    def hello(self, wait_s=20.0):
        """Piglet identity, or None for firmware without SerialSync. Retries
        while the device is still booting (opening the port resets it)."""
        deadline = time.time() + wait_s
        while time.time() < deadline:
            self._send('@PIGLET HELLO')
            line = self._next(('@PH ',), HELLO_RETRY_S)
            if line:
                parts = line.split()
                return {'fw': parts[1] if len(parts) > 1 else '',
                        'chip': parts[2] if len(parts) > 2 else '',
                        'mac': parts[3] if len(parts) > 3 else '',
                        'sd': line.endswith('sd=1')}
        return None

    def list_files(self):
        self._send('@PIGLET LIST')
        if self._next(('@PL BEGIN',), IDLE_TIMEOUT_S) is None:
            raise PigletSyncError('no reply to LIST')
        files = []
        while True:
            line = self._next(('@PL F ', '@PL END'), IDLE_TIMEOUT_S)
            if line is None:
                raise PigletSyncError('LIST reply cut off')
            if line.startswith('@PL END'):
                return files
            fields = line[len('@PL F '):].split('\t')
            if len(fields) >= 3:
                try:
                    files.append({'path': fields[0], 'size': int(fields[1]),
                                  'active': fields[2] == '1'})
                except ValueError:
                    continue

    MAX_RESUMES = 8

    def get_file(self, path):
        """Download one file. Every chunk carries its own CRC32; a damaged or
        missing chunk (or a stalled link) resumes the transfer at the last good
        byte instead of failing the whole file."""
        data = bytearray()
        size = None
        for attempt in range(self.MAX_RESUMES + 1):
            try:
                size = self._get_part(path, data)
                return bytes(data)
            except _ResumableError as e:
                logger.info(f"{path}: {e} — resuming at byte {len(data)} "
                            f"(attempt {attempt + 1}/{self.MAX_RESUMES})")
                self._drain()
        raise PigletSyncError(f'{path}: gave up after {self.MAX_RESUMES} resumes '
                              f'({len(data)}/{size if size is not None else "?"} bytes)')

    def _drain(self):
        """Swallow the rest of an abandoned reply so the next GET starts clean."""
        self._next(('@PG END', '@PG ERR'), 2.0)

    def _get_part(self, path, data):
        """Fetch from len(data) to the end, appending verified chunks to `data`.
        Returns the file size; raises _ResumableError on a recoverable fault."""
        offset = len(data)
        self._send(f'@PIGLET GET {path} {offset}' if offset else f'@PIGLET GET {path}')
        line = self._next(('@PG BEGIN', '@PG ERR'), IDLE_TIMEOUT_S)
        if line is None:
            raise _ResumableError('no reply to GET')
        if line.startswith('@PG ERR'):
            raise PigletSyncError(f'{path}: {line[8:]}')
        parts = line.split()
        size = int(parts[3]) if len(parts) > 3 else None
        expect = offset // CHUNK
        while True:
            line = self._next(('@PG D ', '@PG END', '@PG ERR'), IDLE_TIMEOUT_S)
            if line is None:
                raise _ResumableError(f'stalled after chunk {expect}')
            if line.startswith('@PG ERR'):
                raise _ResumableError(line[8:])
            if line.startswith('@PG END'):
                if size is None or len(data) != size:
                    raise _ResumableError(f'ended at {len(data)} of {size} bytes')
                return size
            try:
                _, _, seq, crc, b64 = line.split(' ', 4)
                chunk = base64.b64decode(b64, validate=True)
                ok = int(seq) == expect and f'{zlib.crc32(chunk) & 0xFFFFFFFF:08X}' == crc.upper()
            except (ValueError, base64.binascii.Error):
                ok = False
            if not ok:
                raise _ResumableError(f'damaged chunk at {expect}')
            data.extend(chunk)
            expect += 1


class _ResumableError(Exception):
    pass


CHUNK = 144          # bytes per data line, fixed by the firmware


# ── import ───────────────────────────────────────────────────────────────────

def _state_path(data_dir):
    return os.path.join(data_dir, 'wardriving', STATE_FILE)


def load_state(data_dir):
    try:
        with open(_state_path(data_dir)) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(data_dir, state):
    path = _state_path(data_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, path)


def csv_summary(data):
    """(first valid FirstSeen as aware UTC datetime or None, data rows,
    rows with a real position). Piglet logs before GPS time/fix as
    1970-01-01 and 0,0 — those count as neither."""
    text = data.decode('utf-8', errors='replace')
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith('WigleWifi')]
    if not lines:
        return None, 0, 0
    header = [h.strip().lower() for h in lines[0].split(',')]
    def col(*names):
        return next((i for i, h in enumerate(header) if h in names), None)
    c_time = col('firstseen', 'first_seen', 'time')
    c_lat = col('currentlatitude', 'latitude', 'lat')
    c_lon = col('currentlongitude', 'longitude', 'lon')
    first, located, rows = None, 0, 0
    for row in csv.reader(lines[1:]):
        rows += 1
        if first is None and c_time is not None and c_time < len(row):
            try:
                dt = datetime.strptime(row[c_time].strip()[:19], '%Y-%m-%d %H:%M:%S')
                if dt.year >= 2015:
                    first = dt.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        if c_lat is not None and c_lon is not None and max(c_lat, c_lon) < len(row):
            try:
                if abs(float(row[c_lat])) > 1e-6 or abs(float(row[c_lon])) > 1e-6:
                    located += 1
            except ValueError:
                pass
    return first, rows, located


def import_csv_bytes(data, data_dir, source):
    """Import one Piglet CSV as a new session. Returns (session_id, result),
    or (None, reason) when the file has no data rows."""
    from wardriving import WardrivingSession
    import sqlite3

    first, rows, located = csv_summary(data)
    if rows <= 0:
        return None, 'no data rows'
    if located <= 0:
        return None, 'no GPS positions'
    stamp = (first.astimezone() if first else datetime.now()).strftime('%Y%m%d_%H%M%S')
    wd = os.path.join(data_dir, 'wardriving')
    sid, n = f'{stamp}_piglet', 2
    while os.path.exists(os.path.join(wd, f'session_{sid}.db')):
        sid, n = f'{stamp}_piglet{n}', n + 1
    session = WardrivingSession(data_dir, session_id=sid)
    result = session.import_wigle_csv(io.StringIO(data.decode('utf-8', errors='replace')))
    with sqlite3.connect(session.db_path) as conn:
        first_seen, last_seen = conn.execute(
            "SELECT MIN(first_seen), MAX(last_seen) FROM networks").fetchone()
        for key, value in (('start_time', first_seen), ('end_time', last_seen),
                           ('source', source)):
            if value:
                conn.execute("INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                             (key, value))
    return sid, result


def sync(link, data_dir, hello_wait_s=20.0):
    """Pull and import every finished CSV this Piglet has that Ragnar hasn't.
    Returns a summary dict. Safe to call on every connect."""
    info = link.hello(hello_wait_s)
    if not info:
        return {'supported': False}
    summary = {'supported': True, 'piglet': info, 'imported': [], 'skipped': 0,
               'errors': []}
    if not info['sd']:
        summary['errors'].append('Piglet SD card not ready')
        return summary
    state = load_state(data_dir)
    done = state.setdefault(info['mac'] or 'unknown', {})
    for f in link.list_files():
        name = os.path.basename(f['path'])
        if f['active'] or name in done:
            summary['skipped'] += 1
            continue
        try:
            data = link.get_file(f['path'])
            sid, result = import_csv_bytes(data, data_dir, f"piglet {info['mac']} {f['path']}")
        except Exception as e:
            summary['errors'].append(str(e))
            logger.warning(f"Piglet sync: {e}")
            continue
        done[name] = {'size': f['size'], 'session_id': sid, 'at': time.time()}
        if not sid:
            done[name]['skipped'] = result          # e.g. 'no GPS positions'
            summary['skipped'] += 1
        save_state(data_dir, state)
        if sid:
            summary['imported'].append({'file': name, 'session_id': sid,
                                        'networks': (result or {}).get('imported_wifi', 0)})
            logger.info(f"Piglet sync: imported {name} as session {sid}")
    return summary


def sync_port(port, data_dir, hello_wait_s=20.0):
    """Open `port` directly (when the wardriving engine isn't running) and sync."""
    import serial
    with serial.Serial(port, 115200, timeout=0.2, write_timeout=2) as ser:
        def readline(timeout_s):
            ser.timeout = min(timeout_s, 1.0)
            return ser.readline()
        return sync(PigletLink(ser.write, readline), data_dir, hello_wait_s)
