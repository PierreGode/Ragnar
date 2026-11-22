"""Tests for cyd_serial_bridge.detect_port — the CYD USB-serial auto-detect.

The bridge used to accept any /dev/serial/by-id link containing "usb", and
every by-id link starts with "usb-". With the CYD bridge enabled it claimed a
u-blox GPS puck, opened it at 115200 and published it as the CYD port, which
wardriving and the GPS probe then deliberately skip, so the UI showed
"GPS: no" even with a green fix LED.
"""

from unittest.mock import patch

import pytest

import cyd_serial_bridge

UBLOX = 'usb-u-blox_AG_-_www.u-blox.com_u-blox_7_-_GPS_GNSS_Receiver-if00'
BU353 = 'usb-Prolific_Technology_Inc._USB-Serial_Controller_D-if00-port0'
CP2102 = 'usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0'
CH340 = 'usb-1a86_USB_Serial-if00-port0'


def _detect(by_id, ttys):
    """Run detect_port against a fake /dev: by_id maps link name -> real tty."""
    links = {f'/dev/serial/by-id/{k}': v for k, v in by_id.items()}

    def fake_glob(pattern):
        if pattern.startswith('/dev/serial/by-id'):
            return list(links)
        prefix = pattern.rstrip('*')
        return [t for t in ttys if t.startswith(prefix)]

    with patch.object(cyd_serial_bridge.glob, 'glob', side_effect=fake_glob), \
         patch.object(cyd_serial_bridge.os.path, 'realpath', side_effect=lambda p: links.get(p, p)):
        return cyd_serial_bridge.detect_port()


@pytest.mark.parametrize('name', [UBLOX, BU353])
def test_gps_puck_alone_is_never_claimed(name):
    assert _detect({name: '/dev/ttyACM0'}, ['/dev/ttyACM0']) is None


@pytest.mark.parametrize('cyd', [CP2102, CH340])
def test_cyd_found_next_to_gps(cyd):
    by_id = {UBLOX: '/dev/ttyACM0', cyd: '/dev/ttyUSB0'}
    assert _detect(by_id, ['/dev/ttyACM0', '/dev/ttyUSB0']) == '/dev/ttyUSB0'


def test_unidentified_tty_still_used_as_fallback():
    assert _detect({}, ['/dev/ttyUSB0']) == '/dev/ttyUSB0'


def test_fallback_skips_ports_that_by_id_identified_as_something_else():
    by_id = {UBLOX: '/dev/ttyACM0'}
    assert _detect(by_id, ['/dev/ttyACM0', '/dev/ttyUSB3']) == '/dev/ttyUSB3'


def test_gps_keywords_shared_with_gps_manager():
    import gps_manager
    assert cyd_serial_bridge._gps_keywords() == gps_manager.GPS_BYID_KEYWORDS
