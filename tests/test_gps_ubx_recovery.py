"""Tests for the u-blox UBX-binary-mode auto-recovery in gps_manager.

The cheap u-blox 7 USB pucks have no battery-backed RAM or flash, so the
NMEA-enable config is lost on every power cycle and the receiver comes back
emitting only UBX binary. _recover_from_ubx() must therefore work reliably,
unattended, on exactly those receivers:

* the frames it sends must stay byte-identical to scripts/gps_set_nmea.py
  (the path proven on real hardware),
* the frames must be written individually with the same pacing the script
  uses — applying CFG-PRT can reinitialize the port and clones drop bytes
  that arrive during it,
* a replug must re-arm the recovery (fresh attempts, cleared counters),
* binary noise that decodes to a leading '$' must not count as NMEA, since
  one such fluke would permanently disarm the recovery.
"""

import importlib.util
import os
import threading
from unittest.mock import MagicMock, patch

import pytest

import gps_manager
from gps_manager import GPSManager, _NMEA_SHAPE, ubx_enable_nmea_frames


def _load_manual_script():
    """Import scripts/gps_set_nmea.py (not a package) as a module."""
    path = os.path.join(os.path.dirname(__file__), '..',
                        'scripts', 'gps_set_nmea.py')
    spec = importlib.util.spec_from_file_location('gps_set_nmea', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def mgr():
    m = GPSManager(port='/dev/ttyACM0')
    m._serial = MagicMock()
    return m


def test_frames_match_manual_script():
    """Auto-recovery must send the exact bytes the proven script sends."""
    script = _load_manual_script()
    frames = ubx_enable_nmea_frames()

    assert frames[0] == script.cfg_prt_usb()
    # GGA, GSA, GSV, RMC — the sentences Ragnar's parser consumes.
    for frame, msg_id in zip(frames[1:-1], (0x00, 0x02, 0x03, 0x04)):
        assert frame == script.cfg_msg(0xF0, msg_id, 1)
    assert frames[-1] == script.cfg_save()


def test_recovery_writes_frames_individually_with_pacing(mgr):
    frames = ubx_enable_nmea_frames()
    with patch('gps_manager.time.sleep') as sleep:
        mgr._recover_from_ubx()

    written = [c.args[0] for c in mgr._serial.write.call_args_list]
    assert written == frames

    delays = [c.args[0] for c in sleep.call_args_list]
    assert len(delays) == len(frames)
    assert delays[0] >= 0.3          # CFG-PRT may reinitialize the port
    assert all(d >= 0.05 for d in delays[1:])

    assert mgr._ubx_fix_attempts == 1
    assert 'gps_set_nmea.py' in mgr.error


def test_recovery_attempts_are_capped(mgr):
    frames = ubx_enable_nmea_frames()
    with patch('gps_manager.time.sleep'):
        for _ in range(5):
            mgr._recover_from_ubx(max_attempts=3)

    assert mgr._ubx_fix_attempts == 3
    assert mgr._serial.write.call_count == 3 * len(frames)


def test_recovery_write_failure_names_manual_script(mgr):
    mgr._serial.write.side_effect = OSError('device reports readiness errors')
    with patch('gps_manager.time.sleep'):
        mgr._recover_from_ubx()

    assert 'automatic fix' in mgr.error
    assert 'gps_set_nmea.py' in mgr.error


def test_reconnect_rearms_recovery(mgr):
    """A replugged no-NVM puck reverts to UBX-only; stale counters from
    before the replug must not block the recovery from running again."""
    mgr._running = True
    mgr._ubx_seen = 120
    mgr._nmea_seen = 500
    mgr._ubx_fix_attempts = 3

    fake_serial = MagicMock()
    fake_serial.Serial.return_value = MagicMock()
    with patch.dict('sys.modules', {'serial': fake_serial}), \
         patch('gps_manager.time.sleep'):
        mgr._reconnect()

    assert mgr.connected is True
    assert mgr._ubx_seen == 0
    assert mgr._nmea_seen == 0
    assert mgr._ubx_fix_attempts == 0


def test_nmea_shape_accepts_real_sentences():
    for line in (
        '$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47',
        '$GNRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A',
        '$GPGSV,3,1,11,03,03,111,00,04,15,270,00,06,01,010,00,13,06,292,00*74',
        '$PUBX,00,081350.00,4717.113210,N,00833.915187,E,546.589,G3,2.1,2.0*5B',
    ):
        assert _NMEA_SHAPE.match(line), line


def test_nmea_shape_rejects_binary_noise():
    """UBX payload bytes decoded with errors='ignore' can start with '$' —
    that must not register as NMEA flowing."""
    noise = [
        '$',
        '$\x12\x01 binary tail',
        '$5b\x00\x07',
        '$G',                      # too short to be a sentence header
        '$gpgga,lowercase,fake',   # NMEA talkers are upper-case
    ]
    for line in noise:
        assert not _NMEA_SHAPE.match(line), repr(line)


def test_read_loop_noise_does_not_disarm_recovery(mgr):
    """End-to-end through _read_loop: 19 UBX chunks, one '$'-leading binary
    fluke, then the 20th UBX chunk must still trigger the recovery write."""
    chunks = [b'\xb5\x62\x01\x06junk\n'] * 19 + [b'$\x12\x01fluke\n',
                                                 b'\xb5\x62\x01\x06junk\n']
    reads = iter(chunks)

    def readline():
        try:
            return next(reads)
        except StopIteration:
            mgr._running = False
            return b''

    mgr._running = True
    mgr._serial.is_open = True
    mgr._serial.readline.side_effect = lambda: readline()
    with patch('gps_manager.time.sleep'):
        mgr._read_loop()

    assert mgr._ubx_fix_attempts == 1
    assert mgr._serial.write.call_count == len(ubx_enable_nmea_frames())
