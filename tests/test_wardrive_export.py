"""WiGLE CSV export shape + the session-finished hook (wardriving.py).

Wardrift rebuilds the drive route from the CSV and rejects a file whose trail
"has a few jumps". The export must therefore contain only GPS-pinned rows,
timed to when the drive was at their position, in one time-ordered list, with
standard CSV quoting (an SSID containing a comma used to be written as '\\,'
and split the row).
"""

import csv
import io
import math
import sqlite3
import types
from datetime import datetime, timezone

import pytest

import wardriving

T0 = datetime(2026, 9, 23, 16, 37, 44, tzinfo=timezone.utc).timestamp()


def _iso(t):
    return datetime.fromtimestamp(T0 + t, timezone.utc).isoformat()


def _pos(t):  # driving east at 50 km/h
    return 59.30, 18.00 + (t * 50 / 3.6) / (111320 * math.cos(math.radians(59.3)))


def _epoch(s):
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()


@pytest.fixture
def session(tmp_path):
    s = wardriving.WardrivingSession(str(tmp_path), session_id='t')
    c = sqlite3.connect(s.db_path)
    for t in range(0, 600, 5):
        if t < 200 or t >= 400:                       # GPS fix lost between 200-400 s
            la, lo = _pos(t)
            c.execute("INSERT INTO gps_track (timestamp, latitude, longitude) VALUES (?,?,?)", (T0 + t, la, lo))

    def net(bssid, ssid, first, peak, backfilled=0, located=True):
        la, lo = _pos(peak) if located else (None, None)
        c.execute("INSERT INTO networks (bssid, ssid, first_seen, last_seen, best_rssi, best_lat, best_lon, "
                  "gps_backfilled) VALUES (?,?,?,?,?,?,?,?)",
                  (bssid, ssid, _iso(first), _iso(peak + 5), -60, la, lo, backfilled))

    net('aa:00:00:00:00:01', 'own phone', 0, 450)            # first seen at start, strongest late
    net('aa:00:00:00:00:02', 'Familjerum.v,', 100, 100)       # comma in the SSID
    net('aa:00:00:00:00:03', 'say "hi"', 150, 150)
    net('aa:00:00:00:00:04', 'estimated', 300, 300, backfilled=1)
    net('aa:00:00:00:00:05', 'no fix', 50, 50, located=False)
    net('aa:00:00:00:00:06', 'in the gap', 300, 300)          # position not on any fix
    la, lo = _pos(20)
    c.execute("INSERT INTO bluetooth_devices (mac, name, first_seen, last_seen, latitude, longitude) "
              "VALUES ('bb:00:00:00:00:01','bt',?,?,?,?)", (_iso(20), _iso(20), la, lo))
    c.commit()
    c.close()
    return s


def _rows(s):
    return list(csv.reader(io.StringIO(s.export_wigle_csv())))[2:]


def test_only_gps_pinned_rows(session):
    names = {r[1] for r in _rows(session)}
    assert names == {'own phone', 'Familjerum.v,', 'say "hi"', 'bt'}


def test_rows_are_one_timeline_matching_their_position(session):
    rows = _rows(session)
    times = [_epoch(r[3]) for r in rows]
    assert times == sorted(times)                      # WiFi and BT interleaved, no rewind
    for r in rows:
        t = _epoch(r[3]) - T0
        la, lo = _pos(t)
        assert abs(float(r[7]) - lo) * 111320 * math.cos(math.radians(59.3)) < 40   # at that moment, there


def test_standard_csv_quoting_and_wigle_time(session):
    out = session.export_wigle_csv()
    assert '"Familjerum.v,"' in out and '"say ""hi"""' in out and '\\,' not in out
    assert all(len(r) == 11 for r in _rows(session))
    assert all(len(r[3]) == 19 and r[3][10] == ' ' for r in _rows(session))   # YYYY-MM-DD HH:MM:SS


def test_session_without_track_keeps_located_rows(tmp_path):
    s = wardriving.WardrivingSession(str(tmp_path), session_id='imported')
    c = sqlite3.connect(s.db_path)
    c.execute("INSERT INTO networks (bssid, ssid, first_seen, last_seen, best_lat, best_lon) "
              "VALUES ('aa:00:00:00:00:09','x','2026-09-23 10:00:00','2026-09-23 10:00:00',59.3,18.0)")
    c.commit()
    c.close()
    assert [r[1] for r in _rows(s)] == ['x']


def test_stop_runs_session_finished_hooks():
    seen = []
    eng = wardriving.WardrivingEngine.__new__(wardriving.WardrivingEngine)
    eng._running, eng._starting, eng._gps = True, False, None
    eng.session = types.SimpleNamespace(session_id='S1', close=lambda: None, get_stats=lambda: {})
    saved = list(wardriving.SESSION_FINISHED_HOOKS)
    wardriving.SESSION_FINISHED_HOOKS[:] = [seen.append, lambda sid: 1 / 0]   # a broken hook is contained
    try:
        assert eng.stop()['success'] is True
    finally:
        wardriving.SESSION_FINISHED_HOOKS[:] = saved
    assert seen == ['S1']
