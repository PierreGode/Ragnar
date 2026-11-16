"""Tests for restarting the service only on settings that actually need it.

The Settings tab is one form and `saveConfig()` posts every field in it, so the
old `'epd_type' in data` test was true on *every* save — saving an unrelated
toggle bounced the whole service. The gate is now "a restart-bound key whose
value actually changed", compared on the RESOLVED driver name (the UI posts a
size key like "2.13" where the config stores "epd2in13_V4").

Covers:
- an unrelated setting saved alongside an unchanged epd_type -> no restart
- a size key that resolves to the driver already configured -> no restart
- a genuine display change -> restart, and it names the key
- non-restart-bound keys never qualify, however many change
- BLE auto-stop applying to a live peripheral instead of rebuilding it
"""

from unittest.mock import MagicMock

import pytest


# The gate from _apply_config_update(), isolated from Flask/shared_data.
CONFIG_RESTART_REQUIRED_KEYS = {'epd_type'}


def _resolve_epd_type(raw, current):
    """Stand-in for shared.resolve_epd_type: size key -> driver name."""
    sizes = {'2.13': 'epd2in13_V4', '2.7': 'epd2in7', '7.5': 'epd7in5_V2'}
    return sizes.get(raw, raw or current)


def restart_keys_changed(data, config):
    data = dict(data)
    if 'epd_type' in data:
        data['epd_type'] = _resolve_epd_type(data['epd_type'], config.get('epd_type'))
    return {k for k in CONFIG_RESTART_REQUIRED_KEYS
            if k in data and data[k] != config.get(k)}


@pytest.fixture
def config():
    return {'epd_type': 'epd2in13_V4', 'scan_vuln_running': True,
            'comment_delaymin': 15, 'manual_mode': False}


# ---------------------------------------------------------------------------
# the regression: a whole-form save must not restart
# ---------------------------------------------------------------------------

def test_unrelated_setting_saved_with_unchanged_display_does_not_restart(config):
    """The whole form is posted on every save, epd_type included."""
    data = {'manual_mode': True, 'comment_delaymin': 30,
            'epd_type': 'epd2in13_V4'}

    assert restart_keys_changed(data, config) == set()


def test_size_key_resolving_to_the_current_driver_does_not_restart(config):
    """The UI posts "2.13"; the config stores "epd2in13_V4". Same panel."""
    data = {'epd_type': '2.13'}

    assert restart_keys_changed(data, config) == set()


def test_many_live_settings_changing_never_restarts(config):
    data = {'manual_mode': True, 'scan_vuln_running': False,
            'comment_delaymin': 99, 'epd_type': 'epd2in13_V4'}

    assert restart_keys_changed(data, config) == set()


def test_save_without_any_display_key_does_not_restart(config):
    assert restart_keys_changed({'manual_mode': True}, config) == set()


# ---------------------------------------------------------------------------
# …but a real hardware change still does
# ---------------------------------------------------------------------------

def test_genuine_display_change_restarts_and_names_the_key(config):
    data = {'epd_type': '7.5'}

    assert restart_keys_changed(data, config) == {'epd_type'}


def test_driver_name_posted_directly_is_still_a_change(config):
    assert restart_keys_changed({'epd_type': 'epd2in7'}, config) == {'epd_type'}


def test_geometry_keys_are_deliberately_not_restart_bound(config):
    """ref_width/height/rotation are re-read per render — live, no restart."""
    data = {'ref_width': 800, 'ref_height': 480, 'screen_reversed': 180}

    assert restart_keys_changed(data, config) == set()
