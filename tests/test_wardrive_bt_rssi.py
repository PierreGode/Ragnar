"""Wardriving records the signal strength BlueZ measured for each Bluetooth
device — not a fixed number — and only devices heard in that scan."""
from unittest.mock import patch

import bt_scanner
from wardriving import WardrivingEngine

FOUND = [
    {'mac': 'AA:BB:CC:00:00:01', 'name': 'Headset', 'rssi': -47, 'cls': 0x240404},
    {'mac': 'AA:BB:CC:00:00:02', 'name': None, 'rssi': -91, 'cls': None},
    {'mac': '', 'name': 'no address', 'rssi': -60, 'cls': None},
]


def test_measured_rssi_and_type_come_from_bluez():
    with patch.object(bt_scanner, '_pick_controller', return_value={'hci': 'hci0'}), \
         patch.object(bt_scanner, '_discover_dbus', return_value=(FOUND, None)) as disc:
        got = WardrivingEngine._scan_bluetooth_dbus()
    disc.assert_called_once_with('hci0', 5)
    assert got == [
        {'mac': 'AA:BB:CC:00:00:01', 'name': 'Headset', 'rssi': -47, 'type': 'Classic'},
        {'mac': 'AA:BB:CC:00:00:02', 'name': '', 'rssi': -91, 'type': 'BLE'},
    ]


def test_scan_uses_the_measured_result_without_running_the_text_tools():
    with patch.object(WardrivingEngine, '_scan_bluetooth_dbus', return_value=[{'mac': 'X', 'name': '', 'rssi': -52, 'type': 'BLE'}]), \
         patch('wardriving.subprocess.run') as run:
        got = WardrivingEngine._scan_bluetooth(WardrivingEngine.__new__(WardrivingEngine))
    assert got[0]['rssi'] == -52
    assert all('bluetoothctl' not in c.args[0] and 'hcitool' not in c.args[0] for c in run.call_args_list)


def test_no_dbus_or_no_controller_means_fall_back():
    with patch.object(bt_scanner, '_pick_controller', return_value=None):
        assert WardrivingEngine._scan_bluetooth_dbus() is None
    with patch.object(bt_scanner, '_pick_controller', return_value={'hci': 'hci0'}), \
         patch.object(bt_scanner, '_discover_dbus', return_value=(None, 'python3-dbus not available')):
        assert WardrivingEngine._scan_bluetooth_dbus() is None
