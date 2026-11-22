"""Tests for SSID-change debounce in WiFiManager._set_current_ssid.

A transient SSID misread (roaming, dual-band flap, brief disconnect) used
to propagate immediately to shared_data.set_active_network(), which calls
mark_all_hosts_degraded() and wipes every alive host to offline. The
debounce requires the NEW SSID to persist for N seconds before switching.
"""

import time
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def manager():
    """A minimal WiFiManager with side-effecting init paths stubbed."""
    from wifi_manager import WiFiManager

    shared = MagicMock()
    shared.config = {
        'wifi_ssid_change_debounce_seconds': 30,
        'wifi_ap_ssid': 'Ragnar',
        'wifi_ap_password': 'ragnarconnect',
        'wifi_default_interface': 'auto',
    }
    shared.active_network_ssid = None
    # No storage manager: these tests exercise the debounce itself, reading the
    # active SSID from shared_data. The durable storage_manager source (issue
    # #818) is covered in test_multi_interface_context.py.
    shared.storage_manager = None
    shared.currentdir = '/tmp'

    with patch('wifi_manager.detect_wifi_interface', return_value='wlan0'), \
         patch('wifi_manager.get_db', return_value=None), \
         patch.object(WiFiManager, 'setup_ap_logger'), \
         patch.object(WiFiManager, 'load_wifi_config'):
        wm = WiFiManager(shared)
    return wm


# ---------------------------------------------------------------------------
# Fresh establishment: propagate immediately
# ---------------------------------------------------------------------------

def test_first_ssid_after_boot_propagates_immediately(manager):
    """No active network yet → switching is non-destructive, fire now."""
    manager.shared_data.active_network_ssid = None

    manager._set_current_ssid('HomeNet')

    manager.shared_data.set_active_network.assert_called_once_with('HomeNet')


def test_same_ssid_as_active_does_not_propagate(manager):
    """If the new value equals the storage's active SSID — no-op."""
    manager.shared_data.active_network_ssid = 'HomeNet'

    manager._set_current_ssid('HomeNet')

    manager.shared_data.set_active_network.assert_not_called()


# ---------------------------------------------------------------------------
# Debounced switch: new SSID must persist
# ---------------------------------------------------------------------------

def test_transient_ssid_misread_does_not_propagate(manager):
    """Single flap to a different SSID inside the debounce window → no call."""
    manager.shared_data.active_network_ssid = 'HomeNet'
    manager.ssid_change_debounce_s = 30

    manager._set_current_ssid('NeighborWifi')   # first observation
    manager._set_current_ssid('NeighborWifi')   # immediate repeat
    manager._set_current_ssid('NeighborWifi')   # still in window

    manager.shared_data.set_active_network.assert_not_called()


def test_consistent_ssid_after_window_propagates(manager):
    """Same NEW SSID observed across the debounce window → propagate."""
    manager.shared_data.active_network_ssid = 'HomeNet'
    manager.ssid_change_debounce_s = 1  # 1 second for fast test

    manager._set_current_ssid('CafeWifi')
    assert manager.shared_data.set_active_network.call_count == 0

    time.sleep(1.1)
    manager._set_current_ssid('CafeWifi')

    manager.shared_data.set_active_network.assert_called_once_with('CafeWifi')


def test_ssid_change_reverting_aborts_pending(manager):
    """A new SSID seen, then reverting back to original → pending cleared."""
    manager.shared_data.active_network_ssid = 'HomeNet'
    manager.ssid_change_debounce_s = 30

    manager._set_current_ssid('NeighborWifi')   # start debounce
    assert manager._pending_ssid_change == 'NeighborWifi'

    manager._set_current_ssid('HomeNet')        # revert
    assert manager._pending_ssid_change is None
    manager.shared_data.set_active_network.assert_not_called()


def test_pending_ssid_reset_when_target_changes(manager):
    """Pending SSID-A then observing SSID-B resets the timer."""
    manager.shared_data.active_network_ssid = 'HomeNet'
    manager.ssid_change_debounce_s = 30

    manager._set_current_ssid('SsidA')
    first_seen_a = manager._pending_ssid_first_seen

    time.sleep(0.01)
    manager._set_current_ssid('SsidB')

    assert manager._pending_ssid_change == 'SsidB'
    assert manager._pending_ssid_first_seen > first_seen_a


def test_propagation_failure_does_not_raise(manager):
    """set_active_network raising should not break the manager."""
    manager.shared_data.active_network_ssid = None
    manager.shared_data.set_active_network.side_effect = RuntimeError('boom')

    # Should NOT raise.
    manager._set_current_ssid('HomeNet')


def test_current_ssid_updates_even_during_debounce(manager):
    """self.current_ssid should reflect the live observation immediately."""
    manager.shared_data.active_network_ssid = 'HomeNet'
    manager.ssid_change_debounce_s = 30

    manager._set_current_ssid('OtherNet')

    # current_ssid mirrors latest observation even though storage isn't switched.
    assert manager.current_ssid == 'OtherNet'
    manager.shared_data.set_active_network.assert_not_called()
