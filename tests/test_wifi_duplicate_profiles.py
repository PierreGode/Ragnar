"""Several NetworkManager profiles with the same name must not split a network.

Reproduced live: the web connect flow pre-saved its profile after checking
`nmcli -t -f NAME con show <ssid>`, which NetworkManager rejects ("invalid field
'NAME'") for a single profile. The check always failed, so each connect added
another profile named "Hobnet". With nine of them,
`nmcli -g 802-11-wireless.ssid connection show Hobnet` printed the SSID nine
times, and get_current_ssid() handed "Hobnet\\n\\nHobnet..." to the storage
manager, which created a new "hobnet_hobnet_..." network store each time.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from wifi_manager import find_wifi_profile_uuid

# uuid -> (type, ssid, mode)
PROFILES = {
    'u-ap': ('802-11-wireless', 'Hobnet', 'ap'),
    'u-eth': ('802-3-ethernet', None, None),
    'u-home': ('802-11-wireless', 'Hobnet', 'infrastructure'),
    'u-cafe': ('802-11-wireless', 'Cafe: 2nd', 'infrastructure'),
}


def _nmcli(calls=None, extra=None):
    # PROFILES values: (type, ssid, mode[, bound interface])
    def run(cmd, *a, **k):
        if calls is not None:
            calls.append(cmd)
        if extra:
            res = extra(cmd)
            if res is not None:
                return res
        if cmd[:4] == ['nmcli', '-t', '-f', 'UUID,TYPE']:
            out = '\n'.join(f'{u}:{p[0]}' for u, p in PROFILES.items())
            return subprocess.CompletedProcess(cmd, 0, out + '\n', '')
        if cmd[:3] == ['nmcli', '-t', '-f'] and cmd[-2] == 'uuid':
            _, ssid, mode = PROFILES[cmd[-1]][:3]
            bound = PROFILES[cmd[-1]][3] if len(PROFILES[cmd[-1]]) > 3 else ''
            out = (f"802-11-wireless.ssid:{ssid.replace(':', chr(92) + ':')}\n"
                   f"802-11-wireless.mode:{mode}\n"
                   f"connection.interface-name:{bound}\n")
            return subprocess.CompletedProcess(cmd, 0, out, '')
        return subprocess.CompletedProcess(cmd, 0, '', '')
    return run


def test_profile_found_by_ssid_skipping_ap_and_other_types():
    with patch('wifi_manager.subprocess.run', side_effect=_nmcli()):
        assert find_wifi_profile_uuid('Hobnet') == 'u-home'
        assert find_wifi_profile_uuid('Cafe: 2nd') == 'u-cafe'
        assert find_wifi_profile_uuid('Elsewhere') is None
        assert find_wifi_profile_uuid('') is None


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
    m.ap_mode_active = False
    return m


def test_shared_profile_name_resolves_to_one_ssid(wm):
    nine = '\n\n'.join(['Hobnet'] * 9) + '\n'
    with patch('wifi_manager.subprocess.run',
               return_value=subprocess.CompletedProcess([], 0, nine, '')):
        assert wm._ssid_of_connection('Hobnet') == 'Hobnet'


def test_connect_reuses_existing_profile_by_uuid(wm):
    calls = []
    with patch('wifi_manager.subprocess.run', side_effect=_nmcli(calls)), \
         patch('wifi_manager.time.sleep'), \
         patch.object(type(wm), 'check_wifi_connection', return_value=False):
        wm.connect_to_network('Hobnet', 'secret')

    assert ['sudo', 'nmcli', 'con', 'modify', 'uuid', 'u-home', 'wifi-sec.psk', 'secret'] in calls
    assert ['sudo', 'nmcli', 'con', 'up', 'uuid', 'u-home'] in calls
    assert not any(c[:5] == ['sudo', 'nmcli', 'dev', 'wifi', 'connect'] for c in calls)


def test_connect_creates_profile_only_when_none_matches(wm):
    calls = []
    with patch('wifi_manager.subprocess.run', side_effect=_nmcli(calls)), \
         patch('wifi_manager.time.sleep'), \
         patch.object(type(wm), 'check_wifi_connection', return_value=False):
        wm.connect_to_network('Elsewhere', 'secret')

    assert ['sudo', 'nmcli', 'dev', 'wifi', 'connect', 'Elsewhere', 'password', 'secret'] in calls


def test_web_presave_modifies_existing_profile_instead_of_adding():
    try:
        import webapp_modern as webapp
    except Exception as exc:  # heavy import; skip where its deps are missing
        pytest.skip(f"webapp_modern unimportable here: {exc}")
    calls = []
    run = _nmcli(calls)
    with patch('wifi_manager.subprocess.run', side_effect=run), \
         patch.object(webapp.subprocess, 'run', side_effect=run):
        assert webapp._save_wifi_profile('Hobnet', 'secret') is True

    assert not any('add' in c for c in calls)
    assert ['sudo', 'nmcli', 'con', 'modify', 'uuid', 'u-home',
            'connection.autoconnect', 'yes'] in calls


def _active_on(device):
    """GENERAL.DEVICES for any profile: active on ``device`` ('' = inactive)."""
    def extra(cmd):
        if cmd[:3] == ['nmcli', '-g', 'GENERAL.DEVICES']:
            return subprocess.CompletedProcess(cmd, 0, device + '\n', '')
        if cmd[:3] == ['sudo', 'nmcli', '-s']:
            return subprocess.CompletedProcess(cmd, 0, 'savedpsk\n', '')
        return None
    return extra


def test_interface_lookup_only_matches_profiles_bound_to_it():
    with patch.dict(PROFILES, {'u-w1': ('802-11-wireless', 'Hobnet', 'infrastructure', 'wlan1')}), \
         patch('wifi_manager.subprocess.run', side_effect=_nmcli()):
        assert find_wifi_profile_uuid('Hobnet', 'wlan1') == 'u-w1'
        assert find_wifi_profile_uuid('Hobnet', 'wlan0') is None
        assert find_wifi_profile_uuid('Hobnet') == 'u-home'   # unbound preferred


def test_connect_on_second_radio_adds_bound_copy_and_leaves_first_alone(wm):
    """Reported live: picking wlan1 re-activated Hobnet on wlan2 and said 'connected'."""
    calls = []
    with patch('wifi_manager.subprocess.run', side_effect=_nmcli(calls, _active_on('wlan2'))), \
         patch('wifi_manager.time.sleep'), \
         patch.object(type(wm), '_interface_has_profile_up', return_value=False):
        wm.connect_to_network('Hobnet', None, interface='wlan1')

    adds = [c for c in calls if c[:4] == ['sudo', 'nmcli', 'con', 'add']]
    assert len(adds) == 1
    add = adds[0]
    assert add[add.index('ifname') + 1] == 'wlan1'
    assert add[add.index('wifi-sec.psk') + 1] == 'savedpsk'     # creds from the shared profile
    assert not any(c[:4] == ['sudo', 'nmcli', 'con', 'up'] and 'u-home' in c for c in calls)


def test_connect_on_radio_reuses_shared_profile_when_idle(wm):
    calls = []
    with patch('wifi_manager.subprocess.run', side_effect=_nmcli(calls, _active_on(''))), \
         patch('wifi_manager.time.sleep'), \
         patch.object(type(wm), '_interface_has_profile_up', return_value=False):
        wm.connect_to_network('Hobnet', None, interface='wlan1')

    assert ['sudo', 'nmcli', 'con', 'up', 'uuid', 'u-home', 'ifname', 'wlan1'] in calls
    assert not any(c[:4] == ['sudo', 'nmcli', 'con', 'add'] for c in calls)


def test_interface_ssid_comes_from_profile_not_its_name():
    """Reported live: 'DamselflyCreative (wlan2)' became a 'damselflycreative_wlan2' store."""
    import wifi_interfaces

    def run(cmd, *a, **k):
        if cmd[:4] == ['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE,CON-UUID,CONNECTION']:
            out = ('wlan0:wifi:connected:u0:netplan-wlan0-Damselfly\n'
                   'wlan2:wifi:connected:u2:Damselfly (wlan2)\n')
            return subprocess.CompletedProcess(cmd, 0, out, '')
        if cmd[:3] == ['nmcli', '-g', '802-11-wireless.ssid']:
            return subprocess.CompletedProcess(cmd, 0, 'Damselfly\n', '')
        return subprocess.CompletedProcess(cmd, 1, '', '')   # iw/iwgetid/ip all miss

    with patch('wifi_interfaces.subprocess.run', side_effect=run):
        found = {i['name']: i for i in wifi_interfaces.gather_wifi_interfaces('wlan0')}

    assert found['wlan0']['connected_ssid'] == 'Damselfly'
    assert found['wlan2']['connected_ssid'] == 'Damselfly'
    assert found['wlan2']['connection'] == 'Damselfly (wlan2)'
