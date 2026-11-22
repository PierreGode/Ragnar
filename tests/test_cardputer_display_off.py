"""The "0" key blanks the CardputerZero LCD (manual, no auto-off) and wakes it.

Covers the keyboard mapping (both input paths), the st7789v2 backlight switch,
and the display loop's off/idle/on cycle. No CardputerZero in CI, so the panel
is faked the same way test_cardputer_zero.py does.
"""
import os
import sys
import threading
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cardputer_input as ci  # noqa: E402
from resources.waveshare_epd import st7789v2 as drv  # noqa: E402

ZERO_I2C = ci.matrix_code(*ci.KEY_MATRIX["0"])   # direct-I2C code for the "0" key
KEY_0 = 11                                        # Linux KEY_0, the evdev path
F_I2C = ci.matrix_code(*ci.KEY_MATRIX["F"])


@pytest.fixture
def kbd(monkeypatch):
    monkeypatch.setattr(ci, "_KEYMAP_FILE", "/nonexistent/cardputer_keymap.json")
    shared = types.SimpleNamespace(screen_reversed=0, config={}, datadir="/nonexistent",
                                   save_config=lambda: None)
    lst = ci.CardputerInputListener(shared)

    def source(name):
        lst._source = name
        lst._keymap = dict(ci.DEFAULT_EVDEV_KEYMAP if name == "evdev" else ci.DEFAULT_KEYMAP)
    lst.source = source
    return lst


def tap(lst, code):
    lst._handle_event(code, True)
    lst._handle_event(code, False)


# ── Keyboard mapping ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,code", [("evdev", KEY_0), ("i2c", ZERO_I2C)])
def test_zero_toggles_the_display_flag_and_echoes(kbd, name, code):
    kbd.source(name)
    assert kbd.display_off is False
    seq0 = kbd.display_seq
    tap(kbd, code)
    assert kbd.display_off is True and kbd.display_seq == seq0 + 1
    assert kbd.last_key[1] == "Display off" and kbd.key_label(kbd.last_key[0]) == "0"
    tap(kbd, code)
    assert kbd.display_off is False and kbd.display_seq == seq0 + 2
    assert kbd.last_key[1] == "Display on"


def test_zero_does_not_touch_rotation_or_grove(kbd):
    kbd.source("evdev")
    tap(kbd, KEY_0)
    assert kbd.shared_data.screen_reversed == 0          # not the Backspace key
    assert "cardputer_grove_power" not in kbd.shared_data.config


def test_release_and_hold_of_zero_do_not_reach_the_base_layer(kbd):
    kbd.source("evdev")
    seen = []
    kbd._dispatch = lambda nm, gesture: seen.append(nm)   # base-class page driver
    kbd._handle_event(KEY_0, True)
    kbd._press_times["display"] = kbd._press_times.get("display", time.monotonic()) - 10
    kbd._check_holds()                                    # long-press must do nothing
    kbd._handle_event(KEY_0, False)
    assert seen == [] and kbd.display_off is True


def test_other_keys_still_work_after_a_blank(kbd):
    kbd.source("i2c")
    tap(kbd, ZERO_I2C)                                    # blank
    assert kbd.display_off is True
    seen = []
    kbd._dispatch = lambda nm, gesture: seen.append(nm)
    tap(kbd, F_I2C)                                       # the up arrow still fires
    assert seen == ["up"]


# ── Driver backlight switch ──────────────────────────────────────────────────

def _fb(tmp_path, monkeypatch):
    from test_cardputer_zero import make_fb
    _, sysdir = make_fb(tmp_path, monkeypatch)
    bl = tmp_path / "backlight" / "lcd"
    bl.mkdir(parents=True)
    (bl / "brightness").write_text("255\n")
    (bl / "max_brightness").write_text("255\n")
    return sysdir, bl


def test_set_backlight_off_blanks_and_zeroes_brightness(tmp_path, monkeypatch):
    sysdir, bl = _fb(tmp_path, monkeypatch)
    epd = drv.EPD()
    epd.init()
    assert epd.set_backlight(False) is True
    assert (sysdir / "blank").read_text().strip() == "1"
    assert (bl / "brightness").read_text().strip() == "0"
    # Back on: unblanked and relit.
    assert epd.set_backlight(True) is True
    assert (sysdir / "blank").read_text().strip() == "0"
    assert (bl / "brightness").read_text().strip() == "255"


def test_set_backlight_is_a_noop_before_init(tmp_path, monkeypatch):
    _fb(tmp_path, monkeypatch)
    assert drv.EPD().set_backlight(False) is False


def test_spi_backlight_uses_the_expander(monkeypatch):
    calls = []
    ioe = types.SimpleNamespace(available=True,
                                backlight_on=lambda: calls.append("on") or True,
                                backlight_off=lambda: calls.append("off") or True)
    epd = drv.EPD()
    epd._transport = "spi"
    epd._initialized = True
    epd._ioe = ioe
    assert epd.set_backlight(False) is True and epd.set_backlight(True) is True
    assert calls == ["off", "on"]


# ── Display loop cycle ───────────────────────────────────────────────────────

class _FakeEpd:
    def __init__(self):
        self.calls = []

    def set_backlight(self, on):
        self.calls.append(bool(on))
        return True


def _display():
    lc = pytest.importorskip("test_cardputer_zero")
    _, _, d = lc.cz_display()
    d.shared_data.display_should_exit = False
    return d


def test_run_display_off_switches_off_then_idles_then_back_on():
    d = _display()
    epd = _FakeEpd()
    d.epd_helper = types.SimpleNamespace(epd=epd)
    bl = types.SimpleNamespace(display_off=True)
    d.button_listener = bl
    assert d._cardputer_display_off() is True

    # Another "0" press clears the flag while we are idling.
    threading.Timer(0.1, lambda: setattr(bl, "display_off", False)).start()
    d._run_display_off()
    assert epd.calls == [False, True]            # off on entry, on on exit


def test_run_display_off_relights_on_shutdown():
    d = _display()
    epd = _FakeEpd()
    d.epd_helper = types.SimpleNamespace(epd=epd)
    d.button_listener = types.SimpleNamespace(display_off=True)
    threading.Timer(0.1, lambda: setattr(d.shared_data, "display_should_exit", True)).start()
    d._run_display_off()
    assert epd.calls == [False, True]


def test_backlight_keepalive_reasserts_on_a_cadence():
    """If the expander drops the backlight, the render loop re-asserts it every
    few seconds so the screen cannot stay black — but not on every frame."""
    d = _display()
    epd = _FakeEpd()
    d.epd_helper = types.SimpleNamespace(epd=epd)
    d.config = {"epd_type": "st7789v2"}
    d._cardputer_backlight_keepalive()                      # first pass drives it on
    assert epd.calls == [True]
    d._cardputer_backlight_keepalive()                      # within the interval: nothing
    assert epd.calls == [True]
    d._cardputer_bl_keepalive_at -= d._CARDPUTER_BL_KEEPALIVE + 1    # interval elapsed
    d._cardputer_backlight_keepalive()
    assert epd.calls == [True, True]


def test_backlight_keepalive_is_a_noop_off_cardputer():
    d = _display()
    epd = _FakeEpd()
    d.epd_helper = types.SimpleNamespace(epd=epd)
    d.config = {"epd_type": "epd2in13_V4"}
    d._cardputer_backlight_keepalive()
    assert epd.calls == []


def test_no_display_off_flag_on_other_boards():
    d = _display()
    d.button_listener = types.SimpleNamespace()          # LCD HAT: no such flag
    assert d._cardputer_display_off() is False
    d.button_listener = None
    assert d._cardputer_display_off() is False
