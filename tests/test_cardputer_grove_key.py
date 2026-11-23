"""fn + Backspace (the key's "del" legend) switches the Grove port's 5 V pin."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cardputer_caps as caps  # noqa: E402
import cardputer_input as ci  # noqa: E402

BKSP_I2C = ci.matrix_code(*ci.KEY_MATRIX["Bksp"])
F_I2C = ci.matrix_code(*ci.KEY_MATRIX["F"])
FN_I2C = ci.I2C_FN_CODE
KEY_DELETE, KEY_BACKSPACE = 111, 14


@pytest.fixture
def kbd(monkeypatch):
    monkeypatch.setattr(ci, "_KEYMAP_FILE", "/nonexistent/cardputer_keymap.json")
    rail = {"on": True, "sets": []}
    monkeypatch.setattr(caps, "allow_expander", lambda cfg=None: True)
    monkeypatch.setattr(caps, "grove5v_state", lambda path=None: rail["on"])

    def set_rail(on, path=None):
        rail["sets"].append(on)
        if rail["on"] is not None and not rail.get("stuck"):
            rail["on"] = bool(on)
        return True

    monkeypatch.setattr(caps, "set_grove5v", set_rail)
    saved = []
    shared = types.SimpleNamespace(screen_reversed=0, config={}, datadir="/nonexistent",
                                   save_config=lambda: saved.append(dict(shared.config)))
    lst = ci.CardputerInputListener(shared)
    lst.rail, lst.saved = rail, saved

    def source(name):
        lst._source = name
        lst._keymap = dict(ci.DEFAULT_EVDEV_KEYMAP if name == "evdev" else ci.DEFAULT_KEYMAP)
    lst.source = source
    return lst


def tap(lst, code):
    lst._handle_event(code, True)
    lst._handle_event(code, False)


def test_del_from_the_kernel_keyboard_toggles_grove_and_saves_it(kbd):
    kbd.source("evdev")
    tap(kbd, KEY_DELETE)
    assert kbd.rail["on"] is False and kbd.saved[-1]["cardputer_grove_power"] is False
    assert kbd.last_key[1] == "Grove 5V off" and kbd.key_label(kbd.last_key[0]) == "Del"
    tap(kbd, KEY_DELETE)
    assert kbd.rail["on"] is True and kbd.saved[-1]["cardputer_grove_power"] is True
    assert kbd.last_key[1] == "Grove 5V on"


def test_plain_backspace_still_flips_the_screen(kbd):
    for name, code in (("evdev", KEY_BACKSPACE), ("i2c", BKSP_I2C)):
        kbd.source(name)
        kbd.shared_data.screen_reversed = 0
        tap(kbd, code)
        assert kbd.shared_data.screen_reversed == 180
    assert kbd.rail["sets"] == []


def test_fn_backspace_on_the_direct_keyboard_path(kbd):
    kbd.source("i2c")
    kbd._handle_event(FN_I2C, True)
    kbd._handle_event(BKSP_I2C, True)
    assert kbd.rail["on"] is False and kbd.shared_data.screen_reversed == 0
    assert kbd.key_label(kbd.last_key[0]) == "Del" and kbd.last_key[1] == "Grove 5V off"
    # fn let go before Backspace: the release still belongs to the Grove press.
    kbd._handle_event(FN_I2C, False)
    kbd._handle_event(BKSP_I2C, False)
    assert kbd.shared_data.screen_reversed == 0 and kbd._down == {} and kbd._press_times == {}
    tap(kbd, BKSP_I2C)                                   # and plain Backspace is back
    assert kbd.shared_data.screen_reversed == 180 and kbd.rail["sets"] == [False]


def test_fn_with_an_arrow_key_is_still_the_arrow(kbd):
    kbd.source("i2c")
    seen = []
    kbd._dispatch = lambda name, gesture: seen.append(name)
    kbd._handle_event(FN_I2C, True)
    tap(kbd, F_I2C)
    kbd._handle_event(FN_I2C, False)
    assert seen == ["up"] and kbd.rail["sets"] == []


def test_it_works_on_the_camera_screen_and_leaves_it_open(kbd):
    kbd.source("evdev")
    kbd.camera_mode = True
    tap(kbd, KEY_DELETE)
    assert kbd.rail["on"] is False and kbd.camera_mode is True


def test_a_board_without_the_switch_says_so_and_saves_nothing(kbd):
    kbd.source("evdev")
    kbd.rail["on"] = None
    tap(kbd, KEY_DELETE)
    assert kbd.last_key[1] == "Grove: no switch" and kbd.saved == [] and kbd.rail["sets"] == []


def test_a_switch_that_does_not_move_is_reported_not_saved(kbd):
    kbd.source("evdev")
    kbd.rail["stuck"] = True
    tap(kbd, KEY_DELETE)
    assert kbd.last_key[1] == "Grove 5V: no change" and kbd.saved == []


def test_a_failure_does_not_break_the_keyboard(kbd, monkeypatch):
    kbd.source("evdev")
    monkeypatch.setattr(caps, "grove5v_state", lambda path=None: 1 / 0)
    tap(kbd, KEY_DELETE)
    assert kbd.last_key[1] == "Grove 5V: failed"
    tap(kbd, KEY_BACKSPACE)
    assert kbd.shared_data.screen_reversed == 180


def test_holding_del_does_not_repeat_or_fire_anything_else(kbd, monkeypatch):
    kbd.source("evdev")
    kbd._handle_event(KEY_DELETE, True)
    kbd._press_times["grove"] -= 10                      # held a long time
    kbd._check_holds()
    kbd._handle_event(KEY_DELETE, False)
    assert kbd.rail["sets"] == [False]


def test_the_echo_on_screen_names_the_result():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_cardputer_zero import cz_display
    from PIL import Image
    import time
    lc, sd, d = cz_display()
    d.button_listener = types.SimpleNamespace(last_key=(111, "Grove 5V off", time.monotonic()),
                                              key_label=lambda code: "Del")
    img = Image.new("RGB", (320, 170), (0, 0, 0))
    d._cardputer_overlays(img)
    box = img.crop((2, 153, 130, 168))
    assert sum(1 for p in box.getdata() if p == lc.display._WD_COLORS["title"]) > 500
