"""Session list must show when a drive actually happened.

WardrivingSession._init_db() runs every time a session is opened (viewing,
export, upload, backfill). It used to INSERT OR REPLACE start_time = now, so
opening an old drive restamped it with the current time and it appeared in the
web list under the wrong date — users took such sessions for lost.
"""

import os
import sqlite3
import types

import wardriving


def _session(tmp_path, sid):
    s = wardriving.WardrivingSession(str(tmp_path), session_id=sid)
    s.upsert_network('aa:bb:cc:dd:ee:01', 'net', 'WPA2', 6, 2437, -60,
                     59.3, 18.0, 20.0, 0.0, 1.0, 'wlan0')
    return s


def _info(s, key):
    with sqlite3.connect(s.db_path) as c:
        return c.execute("SELECT value FROM session_info WHERE key=?", (key,)).fetchone()[0]


def _list(tmp_path):
    engine = types.SimpleNamespace(data_dir=str(tmp_path))
    return wardriving.WardrivingEngine.get_session_list(engine)


def test_reopening_a_session_keeps_its_start_time(tmp_path):
    s = _session(tmp_path, '20260930_111732')
    original = _info(s, 'start_time')
    wardriving.WardrivingSession(str(tmp_path), session_id='20260930_111732')
    assert _info(s, 'start_time') == original


def test_list_recovers_clobbered_start_and_missing_end_from_data(tmp_path):
    s = _session(tmp_path, '20260930_111732')
    with sqlite3.connect(s.db_path) as c:
        first, last = c.execute("SELECT first_seen, last_seen FROM networks").fetchone()
        # What older builds left behind: start restamped hours later, no end
        # (power cut before a clean stop).
        c.execute("UPDATE session_info SET value='2099-01-01T00:00:00+00:00' WHERE key='start_time'")
    (row,) = _list(tmp_path)
    assert row['start_time'] == first
    assert row['end_time'] == last
    assert row['total_networks'] == 1


def test_list_skips_never_written_empty_db(tmp_path):
    _session(tmp_path, '20260930_111732')
    open(os.path.join(tmp_path, 'wardriving', 'session_20260927_171409.db'), 'w').close()
    assert [r['session_id'] for r in _list(tmp_path)] == ['20260930_111732']
