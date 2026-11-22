"""Setting the clock from GPS, and repairing a session when the clock steps.

A Pi has no RTC. Booted away from Wi-Fi it runs on the last saved time until
NTP or GPS corrects it; a field session was stamped 2 h 38 min early that
way. GPSManager sets the clock from GPS time (only while NTP isn't synced),
and the wardriving engine shifts the running session's earlier timestamps
when the wall clock steps forward.
"""

import sqlite3
import time
from datetime import datetime, timezone
from unittest.mock import patch

import gps_manager
import wardriving
from gps_manager import GPSManager


def _mgr():
    return GPSManager(port='/dev/ttyACM0')


def test_rmc_epoch_parses_time_and_date():
    line = '$GPRMC,123519.50,A,4807.038,N,01131.000,E,022.4,084.4,300926,003.1,W*6A'
    want = datetime(2026, 9, 30, 12, 35, 19, tzinfo=timezone.utc).timestamp() + 0.5
    assert gps_manager._rmc_epoch(line) == want
    assert gps_manager._rmc_epoch('$GPRMC,,V,,,,,,,,,,N*53') is None


def test_clock_set_after_three_consistent_samples_when_unsynced():
    m = _mgr()
    now = time.time()
    with patch('gps_assist.clock_is_synced', return_value=False), \
            patch('gps_manager.time.clock_settime') as cs:
        for _ in range(2):
            m._maybe_set_clock(time.time() + 9491.8)
        assert not cs.called                       # needs 3 agreeing fixes
        m._maybe_set_clock(time.time() + 9491.8)
    assert cs.call_count == 1
    assert abs(cs.call_args.args[1] - (now + 9491.8)) < 5
    assert m.clock_set['changed'] and abs(m.clock_set['delta'] - 9491.8) < 1
    with patch('gps_manager.time.clock_settime') as cs2:   # once per reader run
        m._maybe_set_clock(time.time() + 50)
    assert not cs2.called


def test_clock_left_alone_when_ntp_synced_or_disabled_or_bogus():
    m = _mgr()
    with patch('gps_assist.clock_is_synced', return_value=True), \
            patch('gps_manager.time.clock_settime') as cs:
        for _ in range(5):
            m._maybe_set_clock(time.time() + 600)
    assert not cs.called and m.clock_set is None
    m = GPSManager(port='/dev/ttyACM0', set_clock=False)
    with patch('gps_manager.time.clock_settime') as cs:
        for _ in range(5):
            m._maybe_set_clock(time.time() + 600)
    assert not cs.called
    m = _mgr()
    with patch('gps_assist.clock_is_synced', return_value=False), \
            patch('gps_manager.time.clock_settime') as cs:
        for _ in range(5):
            m._maybe_set_clock(946684800.0)          # year 2000: receiver default
    assert not cs.called


def test_inconsistent_gps_time_is_not_trusted():
    m = _mgr()
    with patch('gps_assist.clock_is_synced', return_value=False), \
            patch('gps_manager.time.clock_settime') as cs:
        for d in (600, 900, 600):
            m._maybe_set_clock(time.time() + d)
    assert not cs.called


def test_session_shift_times_moves_only_pre_step_rows(tmp_path):
    s = wardriving.WardrivingSession(str(tmp_path), session_id='20260930_111732')
    s.upsert_network('aa:bb:cc:dd:ee:01', 'old', 'WPA2', 6, 2437, -60,
                     59.3, 18.0, 20.0, 0.0, 1.0, 'wlan0')
    s.log_gps_track(59.3, 18.0, 20.0, 0.0, 7, 1.0)
    cutoff = time.time() + 1
    step = 9491.8
    new_iso = datetime.fromtimestamp(cutoff + step + 5, timezone.utc).isoformat()
    with sqlite3.connect(s.db_path) as c:
        before = c.execute("SELECT first_seen FROM networks").fetchone()[0]
        c.execute("INSERT INTO networks (bssid, ssid, security, channel, frequency, rssi, "
                  "first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:02','new','WPA2',6,2437,-60,?,?)",
                  (new_iso, new_iso))
        track_before = c.execute("SELECT timestamp FROM gps_track").fetchone()[0]
    s.shift_times(step, cutoff)
    with sqlite3.connect(s.db_path) as c:
        rows = dict(c.execute("SELECT ssid, first_seen FROM networks").fetchall())
        track = c.execute("SELECT timestamp FROM gps_track").fetchone()[0]
        steps = c.execute("SELECT value FROM session_info WHERE key='clock_steps'").fetchone()[0]
    shifted = datetime.fromisoformat(rows['old']).timestamp() - datetime.fromisoformat(before).timestamp()
    assert abs(shifted - step) < 0.01
    assert rows['new'] == new_iso                       # post-step row untouched
    assert abs(track - track_before - step) < 0.01
    assert '+9491.8s' in steps
