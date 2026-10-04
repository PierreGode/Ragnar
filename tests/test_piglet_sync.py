"""Piglet USB serial sync: protocol client + import of solo-drive CSVs.

A fake Piglet answers the SerialSync line protocol (with the boot log and the
live CSV mirror interleaved, as on real hardware); the import must turn each
finished CSV into its own session with the drive's real times, skip GPS-less
and active files, and never import the same file twice.
"""

import base64
import sqlite3
import zlib

import piglet_sync as ps

HDR = ("WigleWifi-1.6,appRelease=v2.60,model=Xiao-ESP32C5,release=1,device=Piglet-Wardriver\n"
       "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,"
       "AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type\n")


def _row(mac, t, lat, lon):
    return f'{mac},"net",WPA2,{t},6,2437,-60,{lat:.6f},{lon:.6f},20.0,5.0,,0,WIFI\n'


DRIVE = (HDR + _row('AA:00:00:00:00:01', '1970-01-01 00:00:25', 0, 0)      # before GPS
         + _row('AA:00:00:00:00:02', '2026-10-03 12:00:00', 59.30, 18.02)
         + _row('AA:00:00:00:00:03', '2026-10-03 12:00:30', 59.31, 18.03)).encode()
NO_GPS = (HDR + _row('BB:00:00:00:00:01', '1970-01-01 00:00:25', 0, 0)).encode()


class FakePiglet:
    def __init__(self, files, active='/logs/WiGLE_3_C.csv', corrupt=(), stall_at=None,
                 mtimes=None, read_error_at=None):
        self.files = files
        self.active = active
        self.mtimes = mtimes or {}
        self.read_error_at = read_error_at
        self.corrupt = set(corrupt)
        self.stall_at = stall_at
        self.out = [b'[BOOT] Reset reason: 1\n']
        self.gets = []

    def write(self, data):
        cmd = data.decode().strip()
        o = self.out
        if cmd == '@PIGLET HELLO':
            o.append(b'@PH v2.60 ESP32-C5 38:44:BE:BA:16:84 sd=1\n')
        elif cmd == '@PIGLET LIST':
            o.append(b'@PL BEGIN\n')
            for p, d in self.files.items():
                o.append(f'@PL F {p}\t{len(d)}\t{int(p == self.active)}\t{self.mtimes.get(p, 0)}\n'.encode())
                o.append(b'AA:BB:CC:DD:EE:FF,"live",WPA2,2026-10-03 13:00:00,1,2412,-70,0,0,0,0,,0,WIFI\n')
            o.append(f'@PL END {len(self.files)}\n'.encode())
        elif cmd.startswith('@PIGLET GET '):
            rest = cmd[12:].split(' ')
            p, off = rest[0], int(rest[1]) if len(rest) > 1 else 0
            self.gets.append((p, off))
            d = self.files[p]
            o.append(f'@PG BEGIN {p} {len(d)} {off}\n'.encode())
            for i in range(off, len(d), 144):
                piece = d[i:i + 144]
                crc = zlib.crc32(piece)
                if self.corrupt and i // 144 in self.corrupt:
                    self.corrupt.discard(i // 144)      # damaged once, then fine
                    crc ^= 1
                if self.read_error_at is not None and i // 144 == self.read_error_at:
                    o.append(f'@PG ERR read-error {i}\n'.encode())
                    return
                if self.stall_at is not None and i // 144 == self.stall_at:
                    self.stall_at = None                # link drops, reply stops
                    return
                o.append(f'@PG D {i // 144} {crc & 0xFFFFFFFF:08X} '
                         f'{base64.b64encode(piece).decode()}\n'.encode())
            o.append(f'@PG END {p} {len(d)} {len(d)}\n'.encode())

    def readline(self, timeout):
        return self.out.pop(0) if self.out else b''


def _link(dev, other=None):
    return ps.PigletLink(dev.write, dev.readline, other)


def test_sync_imports_finished_located_files_once(tmp_path):
    dev = FakePiglet({'/logs/WiGLE_1_A.csv': DRIVE, '/logs/WiGLE_2_B.csv': NO_GPS,
                      '/logs/WiGLE_3_C.csv': DRIVE})
    live = []
    s = ps.sync(_link(dev, live.append), str(tmp_path), hello_wait_s=1)
    assert s['supported'] and s['piglet']['mac'] == '38:44:BE:BA:16:84'
    assert [i['file'] for i in s['imported']] == ['WiGLE_1_A.csv']
    assert s['skipped'] == 2                      # GPS-less + active file
    assert all(p != '/logs/WiGLE_3_C.csv' for p, _ in dev.gets)  # active never fetched
    assert live and live[0].startswith('[BOOT]')  # other lines passed through

    sid = s['imported'][0]['session_id']
    db = tmp_path / 'wardriving' / f'session_{sid}.db'
    with sqlite3.connect(db) as c:
        rows = dict(c.execute("SELECT bssid, first_seen FROM networks").fetchall())
        track = c.execute("SELECT COUNT(*) FROM gps_track").fetchone()[0]
        info = dict(c.execute("SELECT key, value FROM session_info").fetchall())
        nulls = c.execute("SELECT COUNT(*) FROM networks WHERE latitude IS NULL").fetchone()[0]
    assert rows['AA:00:00:00:00:02'].startswith('2026-10-03T12:00:00')
    # The pre-GPS row takes the file's first valid time, not the import time.
    assert rows['AA:00:00:00:00:01'].startswith('2026-10-03T12:00:00')
    assert nulls == 1                             # 0,0 stored as "no position"
    assert track == 2
    assert info['start_time'].startswith('2026-10-03T12:00:00')
    assert info['end_time'].startswith('2026-10-03T12:00:30')

    # Piglet later moves the file to /uploaded: same name, not imported again.
    dev2 = FakePiglet({'/uploaded/WiGLE_1_A.csv': DRIVE})
    s2 = ps.sync(_link(dev2), str(tmp_path), hello_wait_s=1)
    assert s2['imported'] == [] and dev2.gets == []


BIG = (HDR + ''.join(_row(f'AA:00:00:00:{i // 256:02X}:{i % 256:02X}', '2026-10-03 12:00:00',
                         59.3, 18.0) for i in range(60))).encode()


def test_damaged_chunk_resumes_at_that_chunk(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, 'IDLE_TIMEOUT_S', 0.2)
    dev = FakePiglet({'/logs/WiGLE_1_A.csv': BIG}, corrupt={5})
    assert ps.PigletLink(dev.write, dev.readline).get_file('/logs/WiGLE_1_A.csv') == BIG
    assert dev.gets == [('/logs/WiGLE_1_A.csv', 0), ('/logs/WiGLE_1_A.csv', 5 * 144)]


def test_stalled_link_resumes(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, 'IDLE_TIMEOUT_S', 0.2)
    dev = FakePiglet({'/logs/WiGLE_1_A.csv': BIG}, stall_at=9)
    assert ps.PigletLink(dev.write, dev.readline).get_file('/logs/WiGLE_1_A.csv') == BIG
    assert dev.gets[-1] == ('/logs/WiGLE_1_A.csv', 9 * 144)


def test_hopeless_transfer_fails_and_is_retried_after_backoff(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, 'IDLE_TIMEOUT_S', 0.2)
    dev = FakePiglet({'/logs/WiGLE_1_A.csv': DRIVE}, corrupt={0})
    dev.corrupt = type('Always', (set,), {'discard': lambda self, x: None})({0})
    s = ps.sync(_link(dev), str(tmp_path), hello_wait_s=1)
    assert s['imported'] == [] and 'no progress' in s['errors'][0]
    good = FakePiglet({'/logs/WiGLE_1_A.csv': DRIVE})
    assert ps.sync(_link(good), str(tmp_path), hello_wait_s=1)['imported'] == []  # backing off
    st = ps.load_state(str(tmp_path))
    st['_failed']['38:44:BE:BA:16:84']['WiGLE_1_A.csv']['last'] = 0             # 6 h later
    ps.save_state(str(tmp_path), st)
    s = ps.sync(_link(FakePiglet({'/logs/WiGLE_1_A.csv': DRIVE})), str(tmp_path), hello_wait_s=1)
    assert len(s['imported']) == 1
    assert 'WiGLE_1_A.csv' not in ps.load_state(str(tmp_path))['_failed']['38:44:BE:BA:16:84']


def test_old_firmware_without_serial_sync(tmp_path):
    class Silent:
        def write(self, data):
            pass

        def readline(self, timeout):
            return b'AA:BB,"x",WPA2,2026-10-03 13:00:00,1,2412,-70,0,0,0,0,,0,WIFI\n'
    s = ps.sync(ps.PigletLink(Silent().write, Silent().readline), str(tmp_path), hello_wait_s=0.3)
    assert s == {'supported': False}


def _drive(i):
    return (HDR + _row(f'CC:00:00:00:00:{i:02X}', f'2026-10-0{i} 12:00:00', 59.3, 18.0)).encode()


def test_newest_drive_first_and_previous_failures_last(tmp_path):
    files = {f'/logs/WiGLE_{i}_X.csv': _drive(i) for i in (1, 2, 3)}
    mtimes = {'/logs/WiGLE_1_X.csv': 1790000000, '/logs/WiGLE_2_X.csv': 1790900000,
              '/logs/WiGLE_3_X.csv': 0}                    # unknown time
    state = {'_failed': {'38:44:BE:BA:16:84': {'WiGLE_2_X.csv': {'count': 1, 'last': 0}}}}
    ps.save_state(str(tmp_path), state)
    dev = FakePiglet(files, active=None, mtimes=mtimes)
    ps.sync(_link(dev), str(tmp_path), hello_wait_s=1)
    # newest known time first, unknown next, the one that failed before last
    assert [p for p, _ in dev.gets] == ['/logs/WiGLE_1_X.csv', '/logs/WiGLE_3_X.csv',
                                        '/logs/WiGLE_2_X.csv']


def test_sd_read_error_is_not_retried_and_backs_off(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, 'IDLE_TIMEOUT_S', 0.2)
    dev = FakePiglet({'/logs/WiGLE_1_A.csv': BIG}, active=None, read_error_at=3)
    s = ps.sync(_link(dev), str(tmp_path), hello_wait_s=1)
    assert 'SD read error' in s['errors'][0] and len(dev.gets) == 1   # no resume loop
    # Failed recently: the next sync leaves it alone…
    dev = FakePiglet({'/logs/WiGLE_1_A.csv': BIG}, active=None)
    s = ps.sync(_link(dev), str(tmp_path), hello_wait_s=1)
    assert dev.gets == [] and s['skipped'] == 1
    # …retries it once the back-off has passed, and gives up after 3 failures.
    st = ps.load_state(str(tmp_path))
    st['_failed']['38:44:BE:BA:16:84']['WiGLE_1_A.csv'].update(count=3, last=0)
    ps.save_state(str(tmp_path), st)
    s = ps.sync(_link(dev), str(tmp_path), hello_wait_s=1)
    assert dev.gets == [] and s['unreadable'] == ['WiGLE_1_A.csv']


def test_no_progress_gives_up_fast(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, 'IDLE_TIMEOUT_S', 0.2)

    class Stuck(FakePiglet):
        def write(self, data):
            if data.startswith(b'@PIGLET GET'):
                self.stall_at = 4                         # dies at the same chunk every time
            super().write(data)
    dev = Stuck({'/logs/WiGLE_1_A.csv': BIG}, active=None)
    try:
        ps.PigletLink(dev.write, dev.readline).get_file('/logs/WiGLE_1_A.csv')
        assert False, 'should give up'
    except ps.PigletSyncError as e:
        assert 'no progress' in str(e)
    assert len(dev.gets) == ps.PigletLink.MAX_STUCK + 1   # first try + resumes stuck at one byte


def test_plug_watcher_syncs_once_per_plug_in(tmp_path, monkeypatch):
    byid = tmp_path / 'by-id'
    byid.mkdir()
    dev = tmp_path / 'ttyACM0'
    dev.write_text('')
    link = byid / 'usb-Espressif_USB_JTAG_serial_debug_unit_38:44-if00'
    link.symlink_to(dev)
    (byid / 'usb-1a86_USB_Serial-if00').symlink_to(dev)      # CH340 board: never probed
    monkeypatch.setattr(ps.PlugWatcher, 'BY_ID', str(byid))
    runs, busy, enabled = [], {'v': True}, {'v': True}
    w = ps.PlugWatcher(enabled=lambda: enabled['v'], busy=lambda p: busy['v'],
                       run=lambda p: runs.append(p) or {'supported': True})
    w.tick()
    assert runs == []                     # busy (e.g. wardriving holds it): wait
    busy['v'] = False
    w.tick(); w.tick()
    assert runs == [str(dev)]             # once, not on every tick
    link.unlink(); w.tick()               # unplugged…
    link.symlink_to(dev); w.tick()        # …and plugged in again
    assert runs == [str(dev), str(dev)]
    enabled['v'] = False
    link.unlink(); w.tick(); link.symlink_to(dev); w.tick()
    assert len(runs) == 2                 # switched off: nothing


def test_reset_reason_parsed_and_only_real_crashes_warn(caplog):
    class Dev:
        def __init__(self, rst): self.rst, self.out = rst, []
        def write(self, d): self.out.append(f'@PH v2.63 ESP32-C5 38:44:BE:BA:16:84 rst={self.rst} up=12 sd=1\n'.encode())
        def readline(self, t): return self.out.pop(0) if self.out else b''
    import logging
    for rst, warns in ((7, False), (8, False), (1, False), (4, True), (9, True)):
        caplog.clear()
        d = Dev(rst)
        with caplog.at_level(logging.WARNING, logger='PigletSync'):
            info = ps.PigletLink(d.write, d.readline).hello(1)
        assert info['reset_reason'] == rst and info['uptime_s'] == 12 and info['sd']
        assert any('last rebooted' in r.message for r in caplog.records) is warns
