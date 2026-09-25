"""The overlay scan must run on the controller it chose — not a stand-in.

Background: the first Bluetooth overlay scan after a USB controller powered up
was slow and ran on the wrong radio. `hciconfig` lists a freshly-enumerated
controller (a just-plugged/unblocked Alfa) a moment before `bluetoothd` exports
its D-Bus object, so `_discover_dbus("hci1")` found hci1 missing from
ObjectManager and silently fell back to the *first* adapter it saw — the
onboard hci0. On a box whose onboard radio is flaky/undervolting that first
scan was both slow and mislabelled (reported as hci1 while scanning hci0);
every later scan, once hci1 was registered, was correct and fast.

The fix is `_adapter_present`: resolve strictly to the requested adapter, never
a substitute. `_discover_dbus` then waits briefly for it to appear and, failing
that, reports it rather than scanning a different radio.
"""

import bt_scanner


def _objs(*hcis):
    """A fake GetManagedObjects() exposing the given adapters (plus a device,
    to prove non-adapter objects are ignored)."""
    objs = {"/org/bluez/%s/dev_AA_BB_CC_DD_EE_FF" % hcis[0] if hcis else "x":
            {"org.bluez.Device1": {}}}
    for hci in hcis:
        objs["/org/bluez/%s" % hci] = {"org.bluez.Adapter1": {}}
    return objs


def test_resolves_the_requested_adapter_when_present():
    objs = _objs("hci0", "hci1")
    assert bt_scanner._adapter_present(objs, "/org/bluez/hci1") == "/org/bluez/hci1"


def test_returns_none_rather_than_substituting_another_radio():
    # hci1 not yet on D-Bus — must NOT resolve to hci0. This is the whole bug.
    objs = _objs("hci0")
    assert bt_scanner._adapter_present(objs, "/org/bluez/hci1") is None


def test_none_when_no_adapters_at_all():
    assert bt_scanner._adapter_present({}, "/org/bluez/hci0") is None


def test_a_non_adapter_object_at_the_path_does_not_count():
    # A device object living under the path is not an adapter.
    objs = {"/org/bluez/hci1": {"org.bluez.Device1": {}}}
    assert bt_scanner._adapter_present(objs, "/org/bluez/hci1") is None
