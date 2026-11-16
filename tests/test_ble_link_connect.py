"""The link's start-up housekeeping: fast advertising, old phone pairings."""
import os

import ble_peripheral as bp

ADAPTER = '/org/bluez/hci0'


def _debugfs(tmp_path, lo, hi):
    d = tmp_path / 'hci0'
    d.mkdir()
    (d / 'adv_min_interval').write_text(f'{lo}\n')
    (d / 'adv_max_interval').write_text(f'{hi}\n')
    return d


def test_fast_advertising_writes_both_intervals(tmp_path):
    d = _debugfs(tmp_path, 2048, 2048)
    assert bp.set_fast_advertising('hci0', root=str(tmp_path)) is True
    assert (d / 'adv_min_interval').read_text() == '160'
    assert (d / 'adv_max_interval').read_text() == '240'


def test_fast_advertising_raises_max_first_when_min_would_exceed_it(tmp_path, monkeypatch):
    _debugfs(tmp_path, 32, 32)
    order = []
    real_open = open

    def spy(path, mode='r', *a, **k):
        if 'w' in mode:
            order.append(os.path.basename(path))
        return real_open(path, mode, *a, **k)

    monkeypatch.setattr('builtins.open', spy)
    assert bp.set_fast_advertising('hci0', root=str(tmp_path)) is True
    assert order == ['adv_max_interval', 'adv_min_interval']


def test_fast_advertising_reports_a_missing_debugfs(tmp_path):
    assert bp.set_fast_advertising('hci0', root=str(tmp_path)) is False


def test_phone_class():
    assert bp.is_phone_class(0x5A020C)       # phone / tablet
    assert bp.is_phone_class(0x0C010C)       # computer
    assert not bp.is_phone_class(0x240404)   # audio
    assert not bp.is_phone_class(None)


def test_only_paired_phones_under_this_adapter_are_stale():
    dev = 'org.bluez.Device1'
    objects = {
        f'{ADAPTER}/dev_AA': {dev: {'Paired': True, 'Class': 0x5A020C, 'Alias': 'Tablet'}},
        f'{ADAPTER}/dev_BB': {dev: {'Paired': True, 'Alias': 'LE controller'}},          # LE only: no Class
        f'{ADAPTER}/dev_CC': {dev: {'Paired': False, 'Class': 0x5A020C, 'Alias': 'Seen phone'}},
        f'{ADAPTER}/dev_DD': {dev: {'Paired': True, 'Class': 0x240404, 'Alias': 'Speaker'}},
        '/org/bluez/hci1/dev_EE': {dev: {'Paired': True, 'Class': 0x5A020C, 'Alias': 'Other adapter'}},
        ADAPTER: {'org.bluez.Adapter1': {}},
    }
    assert bp.stale_phone_pairings(objects, ADAPTER) == [(f'{ADAPTER}/dev_AA', 'Tablet')]


def test_answer_frames_leave_headroom_under_the_mtu():
    import ble_link
    # 3 bytes of notification header plus room for BlueZ's per-value length
    # field: a frame that fills the MTU is never sent, nor anything after it.
    assert ble_link.answer_frame_size(517) == 505
    assert ble_link.answer_frame_size(185) == 173
    assert ble_link.answer_frame_size(4096) == 505
    for bad in (23, 0, None, 'x'):
        assert ble_link.answer_frame_size(bad) == 20
