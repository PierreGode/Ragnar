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
    def run(cmd, *a, **k):
        if calls is not None:
            calls.append(cmd)
        if extra:
            res = extra(cmd)
            if res is not None:
                return res
        if cmd[:4] == ['nmcli', '-t', '-f', 'UUID,TYPE']:
            out = '\n'.join(f'{u}:{t}' for u, (t, _, _) in PROFILES.items())
            return subprocess.CompletedProcess(cmd, 0, out + '\n', '')
        if cmd[:3] == ['nmcli', '-t', '-f'] and cmd[-2] == 'uuid':
            _, ssid, mode = PROFILES[cmd[-1]]
            out = (f"802-11-wireless.ssid:{ssid.replace(':', chr(92) + ':')}\n"
                   f"802-11-wireless.mode:{mode}\n")
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
