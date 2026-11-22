"""The CYD bridge must not hog a serial port no CYD is on.

With CYD-over-USB enabled the bridge opens every free CP210x/CH340 port and
listens for a first CYD frame. It used to publish that port as a hard 'cyd'
claim, so a Bluefruit LE Sniffer (CP2104) or a Heltec Meshtastic node (CP2102)
was "held by cyd" with no CYD plugged in. A configured port was trusted outright
and written to. Now the listening claim is soft ('cyd-probe'): blewatch /
Meshtastic take() the port and the bridge hands it back. Only a port a CYD has
answered on is held hard.
"""

import threading
import time
from unittest.mock import patch

import pytest

import cyd_serial_bridge
import serial_claims

PORT = '/dev/ttyUSB7'


class FakeSerial:
    def __init__(self, *a, **k):
        self.rx = bytearray()
        self.writes = []
        self.closed = False
        FakeSerial.last = self

    @property
    def in_waiting(self):
        if self.closed:
            raise OSError('closed')
        return len(self.rx)

    def read(self, n):
        out, self.rx = bytes(self.rx[:n]), self.rx[n:]
        return out

    def write(self, data):
        self.writes.append(data)

    def close(self):
        self.closed = True


class FakePyserial:
    Serial = FakeSerial


@pytest.fixture
def bridge():
    saved = dict(serial_claims._providers)
    serial_claims._providers.clear()
    serial_claims._reservations.clear()
    cfg = {'port': None}
    b = cyd_serial_bridge.CydSerialBridge(
        build_status=lambda: {'s': 1}, on_ingest=lambda p: None,
        on_action=lambda n, a: None, enabled=lambda: True,
        get_port=lambda: cfg['port'], status_interval=0.05)
    b.cfg = cfg
    serial_claims.register(cyd_serial_bridge.CLAIM_OWNER, lambda: b.held_port(True))
    serial_claims.register(cyd_serial_bridge.PROBE_OWNER, lambda: b.held_port(False))
    patches = [patch.object(cyd_serial_bridge, '_import_serial', return_value=FakePyserial),
               patch.object(cyd_serial_bridge, 'detect_port',
                            side_effect=lambda exclude=None: None if PORT in (exclude or ()) else PORT)]
    for p in patches:
        p.start()
    yield b
    b.stop()
    time.sleep(0.15)
    for p in patches:
        p.stop()
    serial_claims._providers.clear()
    serial_claims._providers.update(saved)
    serial_claims._reservations.clear()


def _wait(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_listening_claim_is_soft_and_handed_back(bridge):
    bridge.start()
    assert _wait(lambda: serial_claims.claims().get(PORT) == 'cyd-probe')
    ser = FakeSerial.last
    # A hard-claim picker (GPS, blewatch's _claimed_ports) does not see it as held.
    assert PORT not in serial_claims.claims(exclude_owner=serial_claims.SOFT_OWNERS)
    assert serial_claims.take(PORT, 'ble-watch', wait=2.0) is None
    assert ser.closed and not ser.writes            # never written, now closed
    assert serial_claims.claims() == {PORT: 'ble-watch'}
    serial_claims.release(PORT, 'ble-watch')
    assert serial_claims.claims() == {}
    assert PORT in bridge._not_cyd                   # left alone for a while after


def test_configured_port_is_not_trusted_until_a_cyd_answers(bridge):
    bridge.cfg['port'] = PORT
    bridge.start()
    assert _wait(lambda: serial_claims.claims().get(PORT) == 'cyd-probe')
    time.sleep(0.2)
    assert not FakeSerial.last.writes               # silent while unidentified
    assert serial_claims.take(PORT, 'meshtastic', wait=2.0) is None
    assert _wait(lambda: 'in use by meshtastic' in (bridge.status()['error'] or ''))
    serial_claims.release(PORT, 'meshtastic')


def test_a_real_cyd_keeps_its_port(bridge):
    bridge.start()
    assert _wait(lambda: serial_claims.claims().get(PORT) == 'cyd-probe')
    FakeSerial.last.rx += b'{"t":"in","node":"cyd1"}\n'
    assert _wait(lambda: serial_claims.claims().get(PORT) == 'cyd')
    assert _wait(lambda: FakeSerial.last.writes)    # now it talks to the CYD
    assert serial_claims.take(PORT, 'ble-watch', wait=0.3) == 'cyd'
    assert serial_claims.claims() == {PORT: 'cyd'}  # no reservation left behind


def test_take_waits_out_a_soft_holder_only():
    held = {'p': PORT}
    serial_claims.register('cyd-probe', lambda: held['p'])
    serial_claims.register('gps', lambda: '/dev/ttyACM0')
    try:
        threading.Timer(0.2, lambda: held.update(p=None)).start()
        assert serial_claims.take(PORT, 'ble-watch', wait=2.0) is None
        assert serial_claims.take('/dev/ttyACM0', 'ble-watch', wait=0.2) == 'gps'
        serial_claims.release(PORT, 'ble-watch')
    finally:
        serial_claims.unregister('cyd-probe')
        serial_claims.unregister('gps')
        serial_claims._reservations.clear()
