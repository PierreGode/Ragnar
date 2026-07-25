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
