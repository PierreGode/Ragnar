"""Tests for how the BLE provisioning peripheral shapes its advertisement.

Background: a user's box reported

    Enabled, but not advertising:
    RegisterAdvertisement: org.bluez.Error.Failed: Failed to register advertisement

on hardware where the same build advertises fine here. That error is BlueZ
relaying a *controller-level* rejection, so it is box-specific — the controller
either does not support something the advertisement asked for (tx-power is the
usual one; a radio that cannot report its LE advertising TX power does not
offer it), or it will not take another advertisement right now.

So the peripheral asks only for what the controller says it supports and, if it
is refused anyway, steps down a ladder of smaller advertisements rather than
leaving the box silent. The service UUID must survive every rung — the mobile
app scans filtered by it, so an advertisement without it is useless.
"""

import io
import re

import pytest

import ble_provisioning as bp


# --- what to ask a given controller for ------------------------------------

def test_txpower_asked_for_when_the_controller_offers_it():
    caps = {'known': True, 'includes': ['tx-power', 'appearance', 'local-name']}
    assert bp.wanted_includes(caps) == ['tx-power']


def test_txpower_dropped_when_the_controller_does_not_offer_it():
    # This is the box the bug report came from: BlueZ lists includes without
    # tx-power, and asking for it anyway gets the whole advertisement refused.
    caps = {'known': True, 'includes': ['local-name']}
    assert bp.wanted_includes(caps) == []


def test_txpower_still_asked_for_when_capabilities_are_unknown():
    # Probing failed (old BlueZ, D-Bus hiccup). Keep the richer advertisement;
    # the ladder recovers if the controller refuses it.
    assert bp.wanted_includes({'known': False, 'includes': []}) == ['tx-power']
    assert bp.wanted_includes({}) == ['tx-power']


# --- the fallback ladder ----------------------------------------------------

def test_ladder_retries_the_same_advertisement_once_before_degrading():
    ladder = bp.adv_ladder(['tx-power'])
    assert ladder[0] == ladder[1] == (['tx-power'], True)


def test_ladder_drops_txpower_then_the_name():
    ladder = bp.adv_ladder(['tx-power'])
    assert ladder[2] == ([], True)
    assert ladder[-1] == ([], False)


def test_ladder_has_no_pointless_rung_without_txpower():
    # Nothing to drop, so no duplicate 'no tx-power' rung — just the retry and
    # the bare advertisement.
    ladder = bp.adv_ladder([])
    assert ladder == [([], True), ([], True), ([], False)]


def test_ladder_ends_but_never_loops():
    for includes in (['tx-power'], []):
        ladder = bp.adv_ladder(includes)
        assert 3 <= len(ladder) <= 4
        # Each rung is (includes, include_name).
        assert all(isinstance(i, list) and isinstance(n, bool) for i, n in ladder)


def test_ladder_input_is_not_mutated():
    includes = ['tx-power']
    bp.adv_ladder(includes)
    assert includes == ['tx-power']


def test_describe_adv_reads_as_a_log_line():
    assert bp.describe_adv((['tx-power'], True)) == 'service UUID + name + tx-power'
    assert bp.describe_adv(([], True)) == 'service UUID + name'
    assert bp.describe_adv(([], False)) == 'service UUID'


# --- the advertisement BlueZ actually reads --------------------------------

def _advertisement(includes, include_name):
    """An Advertisement with no D-Bus registration — get_properties() is pure."""
    pytest.importorskip('dbus')
    pytest.importorskip('gi')
    bp._ensure_classes()

    class _P:
        local_name = 'Ragnar-b4e2'

    adv = object.__new__(bp._Advertisement)
    adv.providers = _P()
    adv.includes = list(includes)
    adv.include_name = include_name
    adv.adv_type = 'peripheral'
    return adv.get_properties()[bp.LE_ADVERTISEMENT]


def test_service_uuid_is_in_every_rung():
    for includes, with_name in bp.adv_ladder(['tx-power']):
        props = _advertisement(includes, with_name)
        assert [str(u) for u in props['ServiceUUIDs']] == [bp.SERVICE_UUID]


def test_optional_fields_are_absent_not_empty():
    # BlueZ reads the properties it is given; an empty Includes array is not
    # the same as omitting it, and an empty LocalName would advertise a blank
    # name rather than none.
    props = _advertisement([], False)
    assert 'Includes' not in props
    assert 'LocalName' not in props


def test_full_rung_carries_name_and_txpower():
    props = _advertisement(['tx-power'], True)
    assert str(props['LocalName']) == 'Ragnar-b4e2'
    assert [str(i) for i in props['Includes']] == ['tx-power']


def test_every_rung_stays_connectable():
    # 'broadcast' is diagnostic only: a phone cannot connect to it, so GATT
    # provisioning would be impossible. Degrading must never reach for it.
    for includes, with_name in bp.adv_ladder(['tx-power']):
        assert str(_advertisement(includes, with_name)['Type']) == 'peripheral'


# --- the reason bluetoothd logs behind the opaque D-Bus error ---------------

def test_hint_calls_out_a_controller_with_no_peripheral_role():
    hint = bp.adv_failure_hint('', {'roles': ['central']}, 'hci1')
    assert 'peripheral role' in hint
    assert 'hci1' in hint


def test_hint_maps_the_mgmt_status_to_a_cause():
    caps = {'roles': ['central', 'peripheral']}
    assert 'ControllerMode' in bp.adv_failure_hint('Rejected (0x0b)', caps, 'hci0')
    assert 'btmgmt --index hci0 le on' in bp.adv_failure_hint('Rejected (0x0b)', caps, 'hci0')
    assert 'BT 4.0+' in bp.adv_failure_hint('Not Supported (0x0c)', caps, 'hci0')
    assert 'dmesg' in bp.adv_failure_hint('Invalid Parameters (0x0d)', caps, 'hci0')
    assert 'scanning' in bp.adv_failure_hint('Busy (0x0a)', caps, 'hci0')


def test_hint_falls_back_when_nothing_is_known():
    hint = bp.adv_failure_hint('', {}, 'hci0')
    assert 'doctor' in hint


def test_bluetoothd_adv_failure_parses_the_logged_status(monkeypatch):
    log = (
        'Jul 25 15:06:58 pi bluetoothd[763]: src/advertising.c:add_client_complete() '
        'Failed to add advertisement: Rejected (0x0b)\n'
        'Jul 25 15:06:59 pi bluetoothd[763]: src/advertising.c:add_client_complete() '
        'Failed to add advertisement: Invalid Parameters (0x0d)\n'
    )
    monkeypatch.setattr(bp, '_run', lambda *a, **k: log)
    # The *last* failure is ours; earlier ones may be from another client.
    assert bp.bluetoothd_adv_failure() == 'Invalid Parameters (0x0d)'


def test_bluetoothd_adv_failure_is_quiet_without_a_journal(monkeypatch):
    monkeypatch.setattr(bp, '_run', lambda *a, **k: '')
    assert bp.bluetoothd_adv_failure() == ''


# --- the scan BlueZ can't see: raw-HCI tools from the BLE pentest path -------

def _fake_proc(monkeypatch, procs):
    """Stub /proc so raw_hci_scanners sees exactly `procs` ({pid: [argv]})."""
    monkeypatch.setattr(bp.os, 'getpid', lambda: 1)
    monkeypatch.setattr(bp.os, 'listdir',
                        lambda p: [str(pid) for pid in procs] if p == '/proc' else [])

    import builtins
    real_open = builtins.open

    def fake_open(path, *a, **k):
        m = re.match(r'/proc/(\d+)/cmdline$', str(path))
        if m and int(m.group(1)) in procs:
            argv = procs[int(m.group(1))]
            return io.BytesIO(b'\x00'.join(s.encode() for s in argv) + b'\x00')
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, 'open', fake_open)


def test_detects_hcitool_lescan_below_bluez(monkeypatch):
    _fake_proc(monkeypatch, {100: ['/usr/bin/hcitool', 'lescan']})
    found = bp.raw_hci_scanners()
    assert len(found) == 1
    assert found[0]['name'] == 'hcitool'
    assert found[0]['pid'] == 100
    assert found[0]['hci'] is None


def test_reads_the_pinned_adapter_from_dash_i(monkeypatch):
    _fake_proc(monkeypatch, {101: ['hcidump', '-i', 'hci1', '--raw']})
    assert bp.raw_hci_scanners()[0]['hci'] == 'hci1'


def test_pinned_tool_on_another_adapter_is_filtered_out(monkeypatch):
    _fake_proc(monkeypatch, {102: ['btmon', '-i', 'hci1']})
    assert bp.raw_hci_scanners('hci0') == []          # not our radio
    assert len(bp.raw_hci_scanners('hci1')) == 1      # is our radio


def test_unpinned_tool_counts_against_any_adapter(monkeypatch):
    # A bare `hcitool lescan` uses whatever controller it opened, so it must
    # not be filtered away when we ask about a specific hci.
    _fake_proc(monkeypatch, {103: ['hcitool', 'lescan']})
    assert len(bp.raw_hci_scanners('hci0')) == 1


def test_the_timeout_wrapper_process_is_not_double_counted(monkeypatch):
    # actions/ble.py runs `timeout 1 hcitool lescan`: two processes exist, the
    # timeout wrapper and the real hcitool child. Only the child (argv[0] =
    # hcitool) counts; the wrapper (argv[0] = timeout) is ignored.
    _fake_proc(monkeypatch, {
        200: ['timeout', '1', 'hcitool', 'lescan'],
        201: ['hcitool', 'lescan'],
    })
    found = bp.raw_hci_scanners()
    assert [f['pid'] for f in found] == [201]


def test_unrelated_processes_are_ignored(monkeypatch):
    _fake_proc(monkeypatch, {
        300: ['/usr/bin/python3', 'webapp_modern.py'],
        301: ['bluetoothd'],
    })
    assert bp.raw_hci_scanners() == []


def test_raw_hci_note_names_the_tool_and_the_fix():
    note = bp._raw_hci_note([{'name': 'hcitool', 'pid': 42, 'cmd': 'hcitool lescan',
                              'hci': None}])
    assert 'hcitool' in note
    assert 'BlueZ' in note
    assert 'pentest' in note.lower() or 'scan' in note.lower()


def test_raw_hci_note_empty_when_nothing_holds_the_radio():
    assert bp._raw_hci_note([]) == ''


def test_hint_prioritises_the_raw_hci_scan_over_the_mgmt_status():
    # Even with a mgmt status present, a raw-HCI holder is the actionable
    # cause and the hint must name it.
    caps = {'roles': ['central', 'peripheral'],
            'raw_hci': [{'name': 'btmon', 'pid': 7, 'cmd': 'btmon', 'hci': None}]}
    hint = bp.adv_failure_hint('Busy (0x0a)', caps, 'hci0')
    assert 'btmon' in hint


def test_hint_for_invalid_parameters_points_at_radio_not_content():
    hint = bp.adv_failure_hint('Invalid Parameters (0x0d)',
                               {'roles': ['central', 'peripheral']}, 'hci0')
    assert 'built-in' in hint
    assert 'Experimental = true' in hint
    assert 'dmesg' in hint


# --- BlueZ's own advertiser: the "is it us or the controller?" tie-breaker --

def test_bluez_can_advertise_true_on_registered(monkeypatch):
    monkeypatch.setattr(bp, '_run', lambda cmd, **k: (
        'bluetoothctl' if cmd[:1] == ['which'] else 'Advertising object registered\n'))
    assert bp.bluez_can_advertise() is True


def test_bluez_can_advertise_false_on_refusal(monkeypatch):
    monkeypatch.setattr(bp, '_run', lambda cmd, **k: (
        'bluetoothctl' if cmd[:1] == ['which']
        else 'Failed to register advertisement: Invalid Parameters\n'))
    assert bp.bluez_can_advertise() is False


def test_bluez_can_advertise_none_without_bluetoothctl(monkeypatch):
    monkeypatch.setattr(bp, '_run', lambda cmd, **k: '')  # `which` finds nothing
    assert bp.bluez_can_advertise() is None


def test_bluez_can_advertise_none_on_unparseable_output(monkeypatch):
    monkeypatch.setattr(bp, '_run', lambda cmd, **k: (
        'bluetoothctl' if cmd[:1] == ['which'] else 'Agent registered\n'))
    assert bp.bluez_can_advertise() is None


def test_caps_summary_lists_raw_hci_tools():
    summary = bp._caps_summary('hci0', {
        'known': False,
        'raw_hci': [{'name': 'hcidump', 'pid': 9, 'cmd': 'hcidump', 'hci': None}],
    })
    assert 'raw-HCI: hcidump' in summary


# --- diagnostics carried in the failure message -----------------------------

def test_caps_summary_carries_what_differs_between_boxes():
    summary = bp._caps_summary('hci0', {
        'known': True,
        'includes': ['local-name'],
        'supported_instances': 1,
        'active_instances': 1,
        'max_adv_len': 31,
        'discovering': True,
    })
    assert 'hci0' in summary
    assert 'instances 1/1' in summary
    assert 'includes local-name' in summary
    assert 'max adv len 31' in summary
    assert 'scan is running' in summary


def test_caps_summary_survives_an_unprobed_controller():
    assert bp._caps_summary('hci1', {'known': False}) == 'hci1'
    assert bp._caps_summary('hci1', {}) == 'hci1'


def test_adapter_capabilities_never_raises_on_a_bogus_adapter():
    caps = bp.adapter_capabilities('hcidoesnotexist')
    assert caps['known'] is False
    assert caps['includes'] == []
    assert caps['supported_instances'] is None
