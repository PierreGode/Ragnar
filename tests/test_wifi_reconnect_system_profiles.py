"""try_connect_known_networks() must fall back to saved NetworkManager profiles.

Most units never populate Ragnar's own wifi_known_networks — their Wi-Fi was
added by the Pi Imager / nmcli and lives only as NM profiles. The LCD/e-Paper
"reconnect" key calls try_connect_known_networks(), which with an empty Ragnar
list used to log "No known networks configured" and do nothing.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

# name -> (ssid, mode, priority, iface, last_used)
PROFILES = {
    'skynet': ('skynet', 'infrastructure', '0', 'wlan0', '1790660000'),
    'internal99': ('internal99', 'infrastructure', '0', 'wlan0', '1700000000'),
    'LosSuecos': ('LosSuecos', 'infrastructure', '5', 'wlan0', '0'),
    'LosSuecos_5G': ('LosSuecos_5G', 'infrastructure', '9', 'wlan1', '0'),  # dongle unplugged
    'Ragnar AP': ('Ragnar', 'ap', '99', '', '0'),
    'Cafe: 2nd': ('Cafe: 2nd', 'infrastructure', '1', '', '0'),
}


def _run(visible, up_ok=('skynet', 'LosSuecos', 'Cafe: 2nd'), calls=None):
    def fake(cmd, **kw):
        if calls is not None:
            calls.append(cmd)
        out, rc = '', 0
        if cmd[:3] == ['nmcli', '-t', '-f'] and cmd[3] == 'NAME,TYPE':
            out = '\n'.join(f"{n.replace(':', chr(92) + ':')}:802-11-wireless"
                            for n in PROFILES) + '\nlo:loopback'
        elif cmd[:3] == ['nmcli', '-t', '-f'] and 'connection' in cmd and 'show' in cmd:
            ssid, mode, prio, iface, used = PROFILES[cmd[-1]]
            out = (f"802-11-wireless.ssid:{ssid.replace(':', chr(92) + ':')}\n"
                   f"802-11-wireless.mode:{mode}\n"
                   f"connection.autoconnect-priority:{prio}\n"
                   f"connection.timestamp:{used}\n"
                   f"connection.interface-name:{iface or '--'}")
        elif 'list' in cmd:
            out = '\n'.join(s.replace(':', chr(92) + ':') for s in visible)
        elif 'up' in cmd:
            rc = 0 if cmd[-1] in up_ok else 4
        return subprocess.CompletedProcess(cmd, rc, out, 'err')
    return fake


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
    m.known_networks = []
    m.ap_mode_active = False
    m.get_current_ssid = MagicMock(return_value=None)
    return m


def _isdir(path):
    return not path.endswith('/wlan1')


def test_empty_ragnar_list_brings_up_best_visible_nm_profile(wm):
    calls = []
    with patch('wifi_manager.subprocess.run', side_effect=_run({'skynet', 'LosSuecos', 'Ragnar'}, calls=calls)), \
            patch('wifi_manager.os.path.isdir', side_effect=_isdir), \
            patch('wifi_manager.time.sleep'):
        assert wm.try_connect_known_networks() is True
    ups = [c for c in calls if 'up' in c]
    # Highest-priority profile in range wins; the AP profile and the one pinned
    # to the unplugged dongle are never tried.
    assert ups == [['sudo', 'nmcli', '--wait', '25', 'connection', 'up', 'id', 'LosSuecos']]


def test_falls_through_to_next_profile_on_failure(wm):
    calls = []
    with patch('wifi_manager.subprocess.run',
               side_effect=_run({'skynet', 'LosSuecos'}, up_ok=('skynet',), calls=calls)), \
            patch('wifi_manager.os.path.isdir', side_effect=_isdir), \
            patch('wifi_manager.time.sleep'):
        assert wm.try_connect_known_networks() is True
    assert [c[-1] for c in calls if 'up' in c] == ['LosSuecos', 'skynet']


def test_nothing_in_range_returns_false_without_connecting(wm):
    calls = []
    with patch('wifi_manager.subprocess.run', side_effect=_run({'Neighbour'}, calls=calls)), \
            patch('wifi_manager.os.path.isdir', side_effect=_isdir), \
            patch('wifi_manager.time.sleep'):
        assert wm.try_connect_known_networks() is False
    assert not [c for c in calls if 'up' in c]


def test_escaped_colon_profile_name(wm):
    calls = []
    with patch('wifi_manager.subprocess.run', side_effect=_run({'Cafe: 2nd'}, calls=calls)), \
            patch('wifi_manager.os.path.isdir', side_effect=_isdir), \
            patch('wifi_manager.time.sleep'):
        assert wm.try_connect_known_networks() is True
    assert [c[-1] for c in calls if 'up' in c] == ['Cafe: 2nd']


def test_already_on_a_system_profile_network_is_success(wm):
    wm.get_current_ssid = MagicMock(return_value='skynet')
    calls = []
    with patch('wifi_manager.subprocess.run', side_effect=_run({'skynet'}, calls=calls)):
        assert wm.try_connect_known_networks() is True
    assert not [c for c in calls if 'up' in c]


def test_equal_priority_prefers_most_recently_used(wm):
    calls = []
    with patch('wifi_manager.subprocess.run',
               side_effect=_run({'internal99', 'skynet'}, calls=calls)), \
            patch('wifi_manager.os.path.isdir', side_effect=_isdir), \
            patch('wifi_manager.time.sleep'):
        assert wm.try_connect_known_networks() is True
    assert [c[-1] for c in calls if 'up' in c] == ['skynet']
