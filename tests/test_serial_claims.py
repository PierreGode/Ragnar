"""Serial-port ownership between the GPS, CYD bridge, wardriving companions
and the Meshtastic link (serial_claims.py).

Two readers on one tty split its byte stream: the GPS goes silent, the CYD
screen garbles, a Meshtastic handshake times out. Every component publishes
the ports it holds, and everyone else's auto-detect must skip them.
"""

from unittest.mock import patch

import pytest

import cyd_serial_bridge
import meshtastic_node
import serial_claims


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(serial_claims._providers)
    serial_claims._providers.clear()
    yield
    serial_claims._providers.clear()
    serial_claims._providers.update(saved)


def _nopath(p):
    return p


# --------------------------------------------------------------- registry ---

def test_claims_collects_providers_and_excludes_owner():
    serial_claims.register('cyd', lambda: '/dev/ttyUSB0')
    serial_claims.register('wardrive-gps', lambda: ['/dev/ttyACM0', None])
    serial_claims.register('wardrive-companions', lambda: [])
    serial_claims.register('meshtastic', lambda: None)
    with patch.object(serial_claims.os.path, 'realpath', side_effect=_nopath):
        assert serial_claims.claims() == {'/dev/ttyUSB0': 'cyd', '/dev/ttyACM0': 'wardrive-gps'}
        assert serial_claims.claimed('cyd') == {'/dev/ttyACM0'}
        assert serial_claims.claimed('wardrive-*') == {'/dev/ttyUSB0'}
        assert serial_claims.claimed(('cyd', 'wardrive-gps')) == set()


def test_broken_provider_is_ignored():
    serial_claims.register('boom', lambda: 1 / 0)
    serial_claims.register('cyd', lambda: '/dev/ttyUSB0')
    with patch.object(serial_claims.os.path, 'realpath', side_effect=_nopath):
        assert serial_claims.claimed() == {'/dev/ttyUSB0'}


def test_meshtastic_module_publishes_its_port():
    serial_claims.register('meshtastic', meshtastic_node.claimed_port)
    link = meshtastic_node.link()
    with patch.object(link, '_port', '/dev/ttyACM1'):
        assert serial_claims.claimed('cyd') == {'/dev/ttyACM1'}
    with patch.object(link, '_port', None), patch.object(link, '_reserved', '/dev/ttyACM2'):
        assert serial_claims.claimed() == {'/dev/ttyACM2'}


# ------------------------------------------------------- meshtastic picker ---

HELTEC_V4 = ('/dev/ttyACM1', 0x303A, 'Espressif USB JTAG/serial debug unit')
HELTEC_V3 = ('/dev/ttyUSB1', 0x10C4, 'Silicon Labs CP2102 USB to UART Bridge Controller')
UBLOX = ('/dev/ttyACM0', 0x1546, 'u-blox AG - www.u-blox.com u-blox 7 - GPS/GNSS Receiver')
BU353 = ('/dev/ttyUSB2', 0x067B, 'Prolific Technology Inc. USB-Serial Controller')
FTDI = ('/dev/ttyUSB3', 0x0403, 'FTDI FT232R USB UART')


def test_picker_never_offers_a_gps():
    with patch.object(meshtastic_node.os.path, 'realpath', side_effect=_nopath):
        cands, skipped = meshtastic_node.classify_mesh_candidates([UBLOX, BU353, HELTEC_V4], {})
    assert cands == ['/dev/ttyACM1']
    assert dict(skipped) == {'/dev/ttyACM0': 'GPS receiver', '/dev/ttyUSB2': 'GPS receiver'}


def test_picker_skips_ports_held_by_others():
    held = {'/dev/ttyUSB1': 'cyd', '/dev/ttyACM1': 'wardrive-companions'}
    with patch.object(meshtastic_node.os.path, 'realpath', side_effect=_nopath):
        cands, skipped = meshtastic_node.classify_mesh_candidates([HELTEC_V3, HELTEC_V4, FTDI], held)
    assert cands == []
    assert dict(skipped)['/dev/ttyUSB1'] == 'in use by cyd'
    assert dict(skipped)['/dev/ttyUSB3'] == 'not a Meshtastic USB chip'


def test_auto_pick_refuses_to_guess_between_two_esp32s():
    huginn = ('/dev/ttyACM2', 0x303A, 'Espressif USB JTAG/serial debug unit')
    with patch.object(meshtastic_node, '_list_usb_serial', return_value=[HELTEC_V4, huginn, UBLOX]), \
         patch.object(meshtastic_node, '_foreign_ports', return_value={}):
        port, err = meshtastic_node.pick_serial_port()
    assert port is None and 'several' in err


def test_auto_pick_single_node():
    with patch.object(meshtastic_node, '_list_usb_serial', return_value=[HELTEC_V4, UBLOX]), \
         patch.object(meshtastic_node, '_foreign_ports', return_value={}):
        assert meshtastic_node.pick_serial_port() == ('/dev/ttyACM1', None)


@pytest.mark.parametrize('host,want', [
    ('192.168.1.50', ('192.168.1.50', 4403)),
    ('meshnode.local:4404', ('meshnode.local', 4404)),
    ('[fe80::1]:4403', ('fe80::1', 4403)),
    ('http://x', (None, None)),
    ('1.2.3.4:99999', (None, None)),
    ('', (None, None)),
])
def test_parse_host(host, want):
    assert meshtastic_node.parse_host(host) == want


# ------------------------------------------------------------ CYD bridge ---

def test_cyd_auto_detect_skips_a_claimed_cp2102():
    by_id = {'/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0':
             '/dev/ttyUSB1'}

    def fake_glob(pattern):
        return list(by_id) if 'by-id' in pattern else []

    with patch.object(cyd_serial_bridge.glob, 'glob', side_effect=fake_glob), \
         patch.object(cyd_serial_bridge.os.path, 'realpath', side_effect=lambda p: by_id.get(p, p)):
        assert cyd_serial_bridge.detect_port() == '/dev/ttyUSB1'
        assert cyd_serial_bridge.detect_port(exclude={'/dev/ttyUSB1'}) is None


def test_cyd_still_outranks_wardriving_companions():
    serial_claims.register('wardrive-companions', lambda: ['/dev/ttyUSB0'])
    serial_claims.register('meshtastic', lambda: '/dev/ttyUSB1')
    serial_claims.register('wardrive-gps', lambda: ['/dev/ttyACM0'])
    with patch.object(serial_claims.os.path, 'realpath', side_effect=_nopath):
        assert cyd_serial_bridge._foreign_ports() == {'/dev/ttyUSB1', '/dev/ttyACM0'}


# ----------------------------------------------------------- wardriving ---

def test_wardriving_skips_everyone_but_itself():
    from wardriving import WardrivingEngine
    serial_claims.register('cyd', lambda: '/dev/ttyUSB0')
    serial_claims.register('meshtastic', lambda: '/dev/ttyACM1')
    serial_claims.register('wardrive-gps', lambda: ['/dev/ttyACM0'])
    serial_claims.register('wardrive-companions', lambda: ['/dev/ttyACM2'])
    with patch.object(serial_claims.os.path, 'realpath', side_effect=_nopath):
        assert WardrivingEngine._foreign_ports() == {'/dev/ttyUSB0', '/dev/ttyACM1'}


# ------------------------------------------------------ local node report ---

class _FakeIface:
    nodes = {
        '!aa': {'num': 1, 'user': {'id': '!00000001', 'longName': 'Roof', 'hwModel': 'HELTEC_V4'},
                'position': {'latitude': 59.3, 'longitude': 18.0},
                'deviceMetrics': {'batteryLevel': 87, 'voltage': 4.1, 'channelUtilization': 5.0,
                                  'airUtilTx': 1.0, 'uptimeSeconds': 900}},
        '!bb': {'num': 2, 'lastHeard': 0},
    }


def test_local_report_prefers_local_stats():
    link = meshtastic_node.MeshLink()
    link._iface, link._my_num, link._connected = _FakeIface(), 1, True
    rep = link.local_report()
    assert rep['node_id'] == '!00000001' and rep['battery_level'] == 87
    assert rep['uptime_seconds'] == 900 and rep['num_packets_tx'] is None
    assert rep['num_total_nodes'] == 1 and rep['num_online_nodes'] == 0
    link._take_local_stats({'from': 1, 'decoded': {'portnum': 'TELEMETRY_APP', 'telemetry': {
        'localStats': {'uptimeSeconds': 960, 'channelUtilization': 7.5, 'numPacketsTx': 40,
                       'numOnlineNodes': 5, 'numTotalNodes': 9}}}})
    rep = link.local_report()
    assert rep['uptime_seconds'] == 960 and rep['channel_utilization'] == 7.5
    assert rep['num_packets_tx'] == 40 and rep['num_online_nodes'] == 5 and rep['num_total_nodes'] == 9


def test_local_stats_from_other_nodes_are_ignored():
    link = meshtastic_node.MeshLink()
    link._iface, link._my_num, link._connected = _FakeIface(), 1, True
    link._take_local_stats({'from': 2, 'decoded': {'portnum': 'TELEMETRY_APP',
                                                    'telemetry': {'localStats': {'numPacketsTx': 999}}}})
    assert link.local_report()['num_packets_tx'] is None
