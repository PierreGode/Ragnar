"""Phone GPS: the mobile app feeds the phone's location to a unit that has no
GPS receiver (POST /api/wardriving/gps/phone -> engine.phone_gps_fix ->
GPSManager.update_external_fix).

Covered here: a phone fix becomes the unit's position, a receiver with a fresh
fix of its own wins, bad input is refused, the fix goes stale like any other
source, and the engine routes fixes to the right manager (session reader while
a drive runs, a receiver-less manager between drives).
"""
import os
import sys
import time
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import wardriving
from gps_manager import GPSManager


def _mgr():
    return GPSManager()


def test_phone_fix_becomes_the_position():
    m = _mgr()
    assert m.update_external_fix(59.3293, 18.0686, 22.0, speed_kmh=38.2, source='phone',
                                 course=62.0, accuracy_m=5.2)
    assert m.has_fix()
    pos = m.get_position()
    assert (pos['lat'], pos['lon'], pos['alt']) == (59.3293, 18.0686, 22.0)
    assert pos['speed_kmh'] == 38.2 and pos['course'] == 62.0
    st = m.get_status()
    assert st['source'] == 'phone' and st['accuracy_m'] == 5.2 and st['connected']


def test_bad_positions_are_refused():
    m = _mgr()
    assert not m.update_external_fix(None, 18.0)
    assert not m.update_external_fix('x', 18.0)
    assert not m.update_external_fix(0.0, 0.0)           # the "no fix" sentinel
    assert not m.update_external_fix(91.0, 18.0)
    assert not m.update_external_fix(59.0, 181.0)
    assert not m.has_fix()


def test_phone_fix_goes_stale_after_ten_seconds():
    m = _mgr()
    m.update_external_fix(59.3293, 18.0686, source='phone')
    assert m.has_fix()
    m.last_update -= 11
    assert not m.has_fix()
    assert m.get_position() is None


def test_local_receiver_with_a_fresh_fix_wins():
    m = _mgr()
    m._serial = object()                 # a receiver is attached...
    m.latitude, m.longitude = 10.0, 20.0
    m.fix_quality = 1
    m.last_update = time.time()          # ...and fixed a moment ago
    assert not m.update_external_fix(59.3293, 18.0686, source='phone')
    assert (m.latitude, m.longitude) == (10.0, 20.0)
    # Receiver loses its fix (nothing for 5 s): the phone takes over.
    m.last_update -= 6
    assert m.update_external_fix(59.3293, 18.0686, source='phone')
    assert m.get_status()['source'] == 'phone'
    # And back-to-back phone fixes must not block each other.
    assert m.update_external_fix(59.3294, 18.0687, source='phone')
    assert m.latitude == 59.3294


def test_accuracy_is_only_reported_for_an_external_source():
    m = _mgr()
    m.update_external_fix(59.3293, 18.0686, source='phone', accuracy_m=7)
    assert m.get_status()['accuracy_m'] == 7.0
    m._external_source = None            # a local receiver produced a fix
    assert m.get_status()['accuracy_m'] is None


def test_phone_fix_time_goes_through_the_clock_rules():
    m = _mgr()
    with patch.object(m, '_maybe_set_clock') as clock:
        m.update_external_fix(59.3293, 18.0686, source='phone', epoch=1794768955.1)
        m.update_external_fix(59.3293, 18.0686, source='phone')      # keep-alive: no time
    clock.assert_called_once_with(1794768955.1)


class _SD:
    def __init__(self):
        self.config = {}


def _engine(tmp_path):
    e = wardriving.WardrivingEngine.__new__(wardriving.WardrivingEngine)
    e.shared_data = _SD()
    e.data_dir = str(tmp_path)
    e._gps = None
    e._standby_gps = None
    e._phone_gps = None
    e._phone_gps_last = 0.0
    e._running = False
    e._starting = False
    return e


def test_engine_accepts_a_phone_fix_between_drives(tmp_path):
    e = _engine(tmp_path)
    assert e.current_gps() is None
    assert e.phone_gps_fix(59.3293, 18.0686, accuracy_m=10)
    gps = e.current_gps()
    assert gps is e._phone_gps and gps.has_fix()
    st = gps.get_status()
    assert st['source'] == 'phone' and st['hdop'] == 2.0      # accuracy / 5 m
    # Once the phone has been silent for a while it is no longer "the GPS".
    e._phone_gps_last -= e.PHONE_GPS_FRESH_SECONDS + 1
    assert e.current_gps() is None


def test_engine_feeds_the_session_reader_while_a_drive_runs(tmp_path):
    e = _engine(tmp_path)
    e._gps = GPSManager()                # start() keeps a manager even with no receiver
    e._running = True
    assert e.phone_gps_fix(59.3293, 18.0686, speed_kmh=40, course=90, accuracy_m=4)
    assert e._phone_gps is None          # no second manager while a session has one
    pos = e._gps.get_position()          # what the scan loop pins networks to
    assert (pos['lat'], pos['lon']) == (59.3293, 18.0686)
    assert e.current_gps() is e._gps


def test_engine_ignores_a_stale_session_manager_when_idle(tmp_path):
    # A manager left over from a finished drive must not swallow fixes.
    e = _engine(tmp_path)
    e._gps = GPSManager()
    assert e.phone_gps_fix(59.3293, 18.0686)
    assert e._phone_gps is not None and not e._gps.has_fix()
