"""AP mode must not be attempted on a Wi-Fi adapter whose driver cannot be an
access point (issue #1048): the hotspot never came up, but Wi-Fi had already
been dropped, and nothing told the user why."""

import subprocess
import types
from unittest.mock import MagicMock, patch

import pytest

# `iw phy phy0 info` from a Raspberry Pi 5 built-in radio (brcmfmac), trimmed.
PHY_WITH_AP = """Wiphy phy0
	wiphy index: 0
	max # scan SSIDs: 10
	Supported Ciphers:
		* WEP40 (00-0f-ac:1)
		* CCMP-128 (00-0f-ac:4)
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * P2P-client
		 * P2P-GO
		 * P2P-device
	Band 1:
		Capabilities: 0x1062
"""

# A station/monitor-only USB dongle driver. "AP/VLAN" style near-misses and the
# word AP elsewhere in the dump must not count.
PHY_WITHOUT_AP = """Wiphy phy1
	wiphy index: 1
	Supported interface modes:
		 * managed
		 * monitor
	Band 1:
		Capabilities: 0x1862
	Supported commands:
		 * new_interface
		 * start_ap
	valid interface combinations:
		 * #{ managed } <= 1, #{ AP } <= 1,
"""

PHY_AP_VLAN_ONLY = """Wiphy phy2
	Supported interface modes:
		 * managed
		 * AP/VLAN
		 * monitor
	Band 1:
"""

DEV_INFO = "Interface {iface}\n\tifindex 4\n\twdev 0x1\n\taddr 88:a2:9e:00:00:01\n\ttype managed\n\twiphy {phy}\n"


def fake_run(phys, calls=None, iw_missing=False):
    """subprocess.run stand-in. `phys` maps interface -> (phy index, phy dump)."""
    def run(cmd, **kw):
        if calls is not None:
            calls.append(list(cmd))
        if cmd[0] == 'iw':
            if iw_missing:
                raise FileNotFoundError('iw')
            if cmd[1] == 'dev' and cmd[3] == 'info':
                if cmd[2] not in phys:
                    return subprocess.CompletedProcess(cmd, 237, '', 'No such device')
                return subprocess.CompletedProcess(cmd, 0, DEV_INFO.format(iface=cmd[2], phy=phys[cmd[2]][0]), '')
            if cmd[1] == 'phy':
                for idx, dump in phys.values():
                    if cmd[2] == f'phy{idx}':
                        return subprocess.CompletedProcess(cmd, 0, dump, '')
                return subprocess.CompletedProcess(cmd, 1, '', 'not found')
        return subprocess.CompletedProcess(cmd, 0, '', '')
    return run


@pytest.fixture
def wm():
    from wifi_manager import WiFiManager
    shared = MagicMock()
    shared.config = {'wifi_ap_ssid': 'Ragnar', 'wifi_ap_password': 'x',
                     'wifi_default_interface': 'auto'}
    shared.storage_manager = None
    shared.currentdir = '/tmp'
    with patch('wifi_manager.detect_wifi_interface', return_value='wlan0'), \
         patch('wifi_manager.get_db', return_value=None), \
         patch.object(WiFiManager, 'setup_ap_logger'), \
         patch.object(WiFiManager, 'load_wifi_config'):
        m = WiFiManager(shared)
    m.ap_logger = MagicMock()
    m.logger = MagicMock()
    m.wifi_connected = True
    m.disconnect_wifi = MagicMock()
    m.scan_networks = MagicMock(return_value=[])
    m._ensure_radios_unblocked = MagicMock()
    m._create_hostapd_config = MagicMock(return_value=True)
    m._create_dnsmasq_config = MagicMock(return_value=True)
    m._configure_ap_interface = MagicMock(return_value=True)
    m._start_ap_services = MagicMock(return_value=True)
    m._cleanup_ap_mode = MagicMock()
    return m


def _touched_the_radio(m):
    return (m.disconnect_wifi.called or m._configure_ap_interface.called
            or m._start_ap_services.called or m._create_hostapd_config.called)


# ── parsing ─────────────────────────────────────────────────────────────────

def test_interface_modes_are_read_from_their_own_section_only():
    from wifi_manager import WiFiManager
    parse = WiFiManager._parse_iw_interface_modes
    assert 'AP' in parse(PHY_WITH_AP)
    assert parse(PHY_WITHOUT_AP) == {'managed', 'monitor'}      # "start_ap" / "#{ AP }" ignored
    assert 'AP' not in parse(PHY_AP_VLAN_ONLY)
    assert parse('Wiphy phy9\n\tBand 1:\n') is None             # section missing: unknown
    assert parse('') is None


@pytest.mark.parametrize('dump,expected', [(PHY_WITH_AP, True), (PHY_WITHOUT_AP, False),
                                           (PHY_AP_VLAN_ONLY, False)])
def test_support_follows_the_driver(wm, dump, expected):
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (0, dump)})):
        assert wm.interface_supports_ap('wlan0') is expected


def test_support_is_unknown_when_it_cannot_be_asked(wm):
    with patch('wifi_manager.subprocess.run', fake_run({}, iw_missing=True)):
        assert wm.interface_supports_ap('wlan0') is None
    wm._ap_support_cache.clear()
    with patch('wifi_manager.subprocess.run', fake_run({})):     # interface gone
        assert wm.interface_supports_ap('wlan0') is None


# ── the issue: wrong adapter ────────────────────────────────────────────────

def test_start_is_refused_with_a_message_and_wifi_is_left_alone(wm):
    calls = []
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (1, PHY_WITHOUT_AP)}, calls)), \
         patch('wifi_manager.gather_wifi_interfaces', return_value=[{'name': 'wlan0'}]):
        assert wm.start_ap_mode() is False
    assert not wm.ap_mode_active
    assert not _touched_the_radio(m=wm)
    assert not wm.scan_networks.called
    assert all(c[0] == 'iw' for c in calls), calls              # nothing but read-only queries ran
    assert 'wlan0' in wm.ap_last_error
    assert 'does not support Access Point mode' in wm.ap_last_error
    assert 'left untouched' in wm.ap_last_error


def test_web_button_no_longer_drops_wifi_first(wm):
    """enable_ap_mode_from_web() used to disconnect, then fail to start."""
    wm.endless_loop_active = True
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (1, PHY_WITHOUT_AP)})), \
         patch('wifi_manager.gather_wifi_interfaces', return_value=[{'name': 'wlan0'}]):
        assert wm.enable_ap_mode_from_web() is False
    assert not wm.disconnect_wifi.called
    assert not _touched_the_radio(wm)
    assert wm.ap_last_error


def test_message_points_at_an_adapter_that_can_do_it(wm):
    phys = {'wlan1': (1, PHY_WITHOUT_AP), 'wlan0': (0, PHY_WITH_AP)}
    wm.ap_interface = 'wlan1'
    with patch('wifi_manager.subprocess.run', fake_run(phys)), \
         patch('wifi_manager.gather_wifi_interfaces', return_value=[{'name': 'wlan0'}, {'name': 'wlan1'}]):
        msg = wm.ap_mode_blocker()
    assert 'wlan1' in msg and 'wlan0 does support it' in msg
    assert 'wifi_default_interface' in msg


def test_message_names_the_driver_when_known(wm):
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (1, PHY_WITHOUT_AP)})), \
         patch('wifi_manager.gather_wifi_interfaces', return_value=[]), \
         patch.object(type(wm), '_interface_driver', staticmethod(lambda iface: 'r8188eu')):
        assert '(driver r8188eu)' in wm.ap_mode_blocker()


def test_wardrive_ap_hands_the_radio_back_without_dropping_wifi(wm):
    engine = MagicMock()
    engine.lend_interface_for_ap.return_value = 'wlan0'
    wm._wardriving_engine = MagicMock(return_value=engine)
    wm._find_wardrive_ap_interface = MagicMock(return_value=None)
    wm.shared_data.wardrive_ap_active = False
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (1, PHY_WITHOUT_AP)})), \
         patch('wifi_manager.gather_wifi_interfaces', return_value=[{'name': 'wlan0'}]):
        assert wm.start_wardrive_ap() is False
    engine.reclaim_interface_from_ap.assert_called_once_with('wlan0')
    assert not wm.disconnect_wifi.called and not _touched_the_radio(wm)
    assert wm.ap_last_error


# ── nothing changes for adapters that work, or when we cannot tell ──────────

@pytest.mark.parametrize('phys,iw_missing', [({'wlan0': (0, PHY_WITH_AP)}, False), ({}, True)])
def test_capable_or_unknown_adapters_start_as_before(wm, phys, iw_missing):
    with patch('wifi_manager.subprocess.run', fake_run(phys, iw_missing=iw_missing)):
        assert wm.start_ap_mode() is True
    assert wm.ap_mode_active and wm._start_ap_services.called
    assert wm.ap_last_error is None


def test_a_later_success_clears_the_old_error(wm):
    wm.ap_last_error = 'stale'
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (0, PHY_WITH_AP)})):
        assert wm.start_ap_mode() is True
    assert wm.ap_last_error is None


def test_other_start_failures_also_leave_a_reason(wm):
    wm._start_ap_services.return_value = False
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (0, PHY_WITH_AP)})):
        assert wm.start_ap_mode() is False
    assert 'could not be started on wlan0' in wm.ap_last_error


def test_web_button_reports_failure_when_the_loop_could_not_start_the_ap(wm):
    """It used to answer success whatever hostapd did."""
    wm.endless_loop_active = True
    wm.wifi_connected = False
    wm._start_ap_services.return_value = False
    wm._endless_loop_wifi_search = MagicMock()
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (0, PHY_WITH_AP)})), \
         patch('wifi_manager.time.sleep'):
        assert wm.enable_ap_mode_from_web() is False
    wm._start_ap_services.return_value = True
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (0, PHY_WITH_AP)})):
        assert wm.enable_ap_mode_from_web() is True


def test_status_carries_capability_and_error(wm):
    wm.check_network_connectivity = MagicMock(return_value=True)
    wm.check_wifi_connection = MagicMock(return_value=True)
    wm.get_current_ssid = MagicMock(return_value='home')
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (1, PHY_WITHOUT_AP)})):
        status = wm.get_status()
    assert status['ap_supported'] is False and status['ap_interface'] == 'wlan0'
    assert status['ap_error'] is None


# ── web API ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('route', ['/api/wifi/ap/enable', '/api/wifi/ap/start', '/api/wifi/disconnect'])
def test_endpoints_return_the_reason(wm, monkeypatch, route):
    try:
        import webapp_modern as webapp
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip("webapp_modern unimportable here: %s" % exc)
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    monkeypatch.setattr(webapp.shared_data, "ragnar_instance",
                        types.SimpleNamespace(wifi_manager=wm), raising=False)
    wm.ap_timeout, wm.ap_cycle_enabled = 180, True
    with patch('wifi_manager.subprocess.run', fake_run({'wlan0': (1, PHY_WITHOUT_AP)})), \
         patch('wifi_manager.gather_wifi_interfaces', return_value=[{'name': 'wlan0'}]):
        resp = webapp.app.test_client().post(route)
    data = resp.get_json()
    assert resp.status_code == 200 and data['success'] is False
    assert 'does not support Access Point mode' in data['error']
    assert data['message'] == data['error'] and data['ap_supported'] is False
    assert not wm.disconnect_wifi.called
