"""GPS serial baud: the reader must open a port at the rate NMEA was heard at.

The CardputerZero Cap's GNSS talks at 115200; auto-detection found it there
and the reader then opened the port at the 9600 default and read noise."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gps_manager as gm  # noqa: E402

NMEA = b"$GNGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*59\r\n"


class FakeSerialModule:
    """pyserial stand-in: each port talks NMEA at exactly one baud."""

    def __init__(self, ports):
        self.ports = ports            # path -> baud it talks at (None = silent)
        self.opened = []

    def Serial(self, dev, baud, timeout=None):
        self.opened.append((dev, baud))
        if dev not in self.ports:
            raise OSError("no such port")
        data = NMEA * 4 if self.ports[dev] == baud else b"\x00\xf8\x80\x00" * 8
        port = types.SimpleNamespace(read=lambda n: data, close=lambda: None,
                                     readline=lambda: b"", in_waiting=0)
        port.__enter__ = lambda *a: port
        port.__exit__ = lambda *a: None

        class Ctx:
            def __enter__(s):
                return port

            def __exit__(s, *a):
                return False

            read = staticmethod(port.read)
            readline = staticmethod(port.readline)
            close = staticmethod(port.close)
            in_waiting = 0
        return Ctx()


@pytest.fixture
def serial_mod(monkeypatch):
    def install(ports):
        mod = FakeSerialModule(ports)
        monkeypatch.setitem(sys.modules, "serial", mod)
        monkeypatch.setattr(gm, "_PROBED_BAUD", {})
        monkeypatch.setattr(os.path, "realpath", lambda p: p)
        return mod
    return install


def test_probe_reports_the_baud_and_remembers_it(serial_mod):
    serial_mod({"/dev/ttyS0": 115200})
    assert gm.probe_nmea_baud("/dev/ttyS0") == 115200
    assert gm.probed_baud("/dev/ttyS0") == 115200
    assert gm._probe_nmea("/dev/ttyS0") is True


def test_silent_port_is_not_a_gps(serial_mod):
    serial_mod({"/dev/ttyS0": None})
    assert gm.probe_nmea_baud("/dev/ttyS0") is None
    assert gm._probe_nmea("/dev/ttyS0") is False
    assert gm.probed_baud("/dev/ttyS0") is None


def manager(port):
    m = gm.GPSManager.__new__(gm.GPSManager)
    m.port, m.baudrate = port, 9600
    return m


def test_reader_uses_the_baud_auto_detection_found(serial_mod):
    mod = serial_mod({"/dev/ttyS0": 115200})
    gm.probe_nmea_baud("/dev/ttyS0")
    mod.opened.clear()
    m = manager("/dev/ttyS0")
    assert m._baud_for("/dev/ttyS0") == 115200 and m.baudrate == 115200
    assert mod.opened == []                       # no second probe


def test_a_board_uart_given_by_name_is_probed_once(serial_mod):
    mod = serial_mod({"/dev/ttyS0": 115200})
    m = manager("/dev/ttyS0")
    assert m._baud_for("/dev/ttyS0") == 115200
    count = len(mod.opened)
    assert m._baud_for("/dev/ttyS0") == 115200
    assert len(mod.opened) == count


def test_usb_receivers_keep_the_configured_baud_without_a_probe(serial_mod):
    mod = serial_mod({"/dev/ttyACM0": 9600})
    m = manager("/dev/ttyACM0")
    assert m._baud_for("/dev/ttyACM0") == 9600
    assert mod.opened == []


def test_a_silent_board_uart_falls_back_to_the_configured_baud(serial_mod):
    serial_mod({"/dev/ttyAMA0": None})
    m = manager("/dev/ttyAMA0")
    assert m._baud_for("/dev/ttyAMA0") == 9600


@pytest.mark.parametrize("dev,native", [("/dev/ttyS0", True), ("/dev/ttyAMA0", True),
                                        ("/dev/ttyACM0", False), ("/dev/ttyUSB1", False)])
def test_native_uart_names(dev, native, monkeypatch):
    monkeypatch.setattr(os.path, "realpath", lambda p: p)
    assert gm.is_native_uart(dev) is native


def test_the_reader_opens_the_port_at_the_detected_baud(serial_mod):
    mod = serial_mod({"/dev/ttyS0": 115200})
    gm.probe_nmea_baud("/dev/ttyS0")
    mod.opened.clear()
    m = manager("/dev/ttyS0")
    m._read_loop = lambda: None
    assert m._start_serial() is True
    assert mod.opened == [("/dev/ttyS0", 115200)]
    assert m.connected and m.baudrate == 115200


def test_no_serial_open_bypasses_the_detected_baud():
    """Both the first open and the reconnect must go through _baud_for."""
    import re
    source = open(gm.__file__).read()
    opens = re.findall(r"pyserial\.Serial\((?:self\.)?port, ([^,]+),", source)
    assert opens and all("_baud_for" in arg for arg in opens), opens
