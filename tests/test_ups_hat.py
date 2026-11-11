"""Waveshare INA219 UPS HAT battery monitor (issue #1049): register decoding,
detection, smoothing, charge state, failure handling and the three places the
reading surfaces (colour LCD header, 1-bit header, /api/system/status)."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('RAGNAR_HEADLESS', '1')

import ups_hat  # noqa: E402


def bus_raw(volts):
    return int(round(volts / 0.004)) << 3


def shunt_raw(mv):
    return int(round(mv / 0.01)) & 0xFFFF


class FakeIna:
    """An INA219 as the monitor sees it: two readable registers."""

    def __init__(self, volts=3.9, shunt_mv=-3.0):
        self.volts, self.shunt_mv = volts, shunt_mv
        self.fail = False
        self.closed = False
        self.reads = []

    def read_word(self, register):
        self.reads.append(register)
        if self.fail:
            raise OSError(121, 'Remote I/O error')
        return {ups_hat.REG_BUS_VOLTAGE: bus_raw(self.volts),
                ups_hat.REG_SHUNT_VOLTAGE: shunt_raw(self.shunt_mv)}[register]

    def close(self):
        self.closed = True


def monitor(devices, **cfg):
    """A monitor whose I2C bus holds `devices` ({address: FakeIna})."""
    def opener(bus, address):
        if address not in devices:
            raise OSError(121, 'Remote I/O error')
        return devices[address]
    sd = types.SimpleNamespace(config=dict(cfg))
    return ups_hat.UpsHatMonitor(sd, opener=opener)


# ── decoding ────────────────────────────────────────────────────────────────

def test_bus_voltage_register_decodes_like_the_waveshare_demo():
    # Demo: (read(0x02) >> 3) * 0.004. The low 3 bits are flags, not voltage.
    assert ups_hat.decode_bus_voltage((975 << 3) | 0b010) == pytest.approx(3.9)


def test_shunt_register_is_signed():
    assert ups_hat.decode_shunt_mv(300) == pytest.approx(3.0)
    assert ups_hat.decode_shunt_mv(0x10000 - 300) == pytest.approx(-3.0)


@pytest.mark.parametrize('volts,cells,pct', [
    (4.2, 1, 100), (3.0, 1, 0), (3.6, 1, 50), (4.35, 1, 100), (2.8, 1, 0),
    (8.4, 2, 100), (7.2, 2, 50), (6.0, 2, 0),
])
def test_percent_is_waveshares_linear_formula(volts, cells, pct):
    assert ups_hat.percent_from_voltage(volts, cells) == pytest.approx(pct)


# ── detection ───────────────────────────────────────────────────────────────

def test_hat_c_is_detected_at_0x43():
    m = monitor({0x43: FakeIna(3.9)})
    assert m.probe() and m.poll()
    assert m.available
    assert m.get_model() == 'Waveshare UPS HAT (C)'
    assert m.get_battery_level() == pytest.approx(75.0)
    assert m.get_battery_voltage() == pytest.approx(3.9)


def test_two_cell_hat_is_detected_at_0x42():
    m = monitor({0x42: FakeIna(7.8)})
    assert m.probe() and m.poll()
    assert m.get_model() == 'Waveshare UPS HAT (B)'
    assert m.get_battery_level() == pytest.approx(75.0)


def test_no_device_means_not_available():
    m = monitor({})
    assert not m.probe()
    assert not m.available and m.get_battery_level() is None
    assert m.is_charging() is None and m.get_battery_voltage() is None


@pytest.mark.parametrize('volts', [0.0, 1.2, 5.1, 12.0])
def test_a_chip_that_is_not_a_battery_is_rejected(volts):
    """Something else on 0x43 (or a HAT with no cell fitted) must not put a
    bogus 0% / 100% on the screen."""
    dev = FakeIna(volts)
    m = monitor({0x43: dev})
    assert not m.probe()
    assert dev.closed and not m.available


def test_monitor_never_writes_to_the_chip():
    dev = FakeIna()
    assert not hasattr(dev, 'write_word')      # the fake has no write path at all
    m = monitor({0x43: dev})
    m.probe(); m.poll()
    assert set(dev.reads) == {ups_hat.REG_BUS_VOLTAGE, ups_hat.REG_SHUNT_VOLTAGE}
    assert not hasattr(ups_hat.I2CDevice, 'write_word')


def test_disabled_in_config_does_not_start():
    dev = FakeIna()
    m = monitor({0x43: dev}, ups_hat_monitor=False)
    m.start()
    assert m._thread is None and not dev.reads and not m.available


# ── charge state ────────────────────────────────────────────────────────────

@pytest.mark.parametrize('shunt_mv,plugged', [
    (-3.0, False),    # 300 mA out of the cell: on battery
    (-1.2, False),    # idle Pi Zero
    (4.0, True),      # charging
    (0.0, True),      # full, charger holding: still on external power
    (-0.1, True),     # noise around zero
])
def test_external_power_comes_from_the_shunt_sign(shunt_mv, plugged):
    m = monitor({0x43: FakeIna(3.9, shunt_mv)})
    m.probe(); m.poll()
    assert m.is_charging() is plugged


def test_current_sign_matches_waveshare_negative_is_discharging():
    m = monitor({0x43: FakeIna(3.9, -3.0)})
    m.probe(); m.poll()
    assert m.get_current_ma() == pytest.approx(-300.0)


# ── smoothing + failures ────────────────────────────────────────────────────

def test_level_is_a_moving_average_so_load_steps_do_not_flicker():
    dev = FakeIna(4.0)
    m = monitor({0x43: dev})
    m.probe()
    for _ in range(ups_hat.SMOOTH_SAMPLES - 1):
        m.poll()
    dev.volts = 3.7                        # a scan starts, the cell sags
    m.poll()
    expected = (4.0 * (ups_hat.SMOOTH_SAMPLES - 1) + 3.7) / ups_hat.SMOOTH_SAMPLES
    assert m.get_battery_voltage() == pytest.approx(expected)
    for _ in range(ups_hat.SMOOTH_SAMPLES):
        m.poll()
    assert m.get_battery_voltage() == pytest.approx(3.7)   # old samples aged out


def test_one_bad_read_keeps_the_last_value_but_a_dead_bus_drops_it():
    dev = FakeIna(3.9)
    m = monitor({0x43: dev})
    m.probe(); m.poll()
    dev.fail = True
    assert not m.poll()
    assert m.available and m.get_battery_level() == pytest.approx(75.0)
    for _ in range(ups_hat.MAX_FAILURES):
        m.poll()
    assert not m.available and m.get_battery_level() is None
    dev.fail = False                       # HAT answers again (loose pogo pins)
    assert m.poll()
    assert m.available and m.get_battery_level() == pytest.approx(75.0)


# ── source selection ────────────────────────────────────────────────────────

class Src:
    def __init__(self, available, level=50):
        self.available, self._level = available, level

    def get_battery_level(self):
        return self._level

    def is_charging(self):
        return False

    def get_battery_voltage(self):
        return 3.8

    def get_model(self):
        return 'src'


def _shared(pisugar=None, hat=None):
    inst = types.SimpleNamespace(pisugar_listener=pisugar, ups_hat_monitor=hat)
    return types.SimpleNamespace(ragnar_instance=inst)


def test_battery_source_picks_whatever_is_live():
    hat, sugar = Src(True, 40), Src(True, 90)
    assert ups_hat.battery_source(_shared(None, hat)) is hat
    assert ups_hat.battery_source(_shared(Src(False), hat)) is hat
    assert ups_hat.battery_source(_shared(sugar, hat)) is sugar
    assert ups_hat.battery_source(_shared(Src(False), Src(False))) is None
    assert ups_hat.battery_source(types.SimpleNamespace(ragnar_instance=None)) is None
    # A Ragnar instance from before this feature has no ups_hat_monitor attribute.
    assert ups_hat.battery_source(types.SimpleNamespace(
        ragnar_instance=types.SimpleNamespace(pisugar_listener=None))) is None


def test_mock_mode_reports_a_battery(monkeypatch):
    monkeypatch.setenv('UPS_HAT_MOCK', '1')
    m = ups_hat.UpsHatMonitor(types.SimpleNamespace(config={}))
    m.start()
    assert m.available and 0 <= m.get_battery_level() <= 100
    assert 'UPS HAT (C)' in m.get_model()


# ── on screen ───────────────────────────────────────────────────────────────

def _px(img):
    return img.get_flattened_data() if hasattr(img, 'get_flattened_data') else list(img.getdata())


def _lcd():
    return pytest.importorskip('test_lcd_color', reason='display test helpers')


def _render(hat, **cfg):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    lcd = _lcd()
    sd = lcd._sd()
    sd.ragnar_instance = types.SimpleNamespace(pisugar_listener=None, ups_hat_monitor=hat)
    return lcd._main_screen(lcd._display(sd, **cfg))


def _header_strip(img):
    """Top-right corner of the header, where the battery text is drawn."""
    return _px(img.crop((98, 0, 128, 14)).convert('RGB'))


@pytest.mark.parametrize('cfg', [{}, {'lcd_color': False}])
def test_battery_percentage_is_drawn_in_the_display_header(cfg):
    m = monitor({0x43: FakeIna(3.9)})
    m.probe(); m.poll()
    without = _render(None, **cfg)
    with_hat = _render(m, **cfg)
    assert _header_strip(without) != _header_strip(with_hat)
    # Only the header changed. (The animated sprite in the bottom-right picks a
    # random frame per render, so that corner is left out of the comparison.)
    box = (0, 16, 80, 128)
    assert _px(without.crop(box).convert('RGB')) == _px(with_hat.crop(box).convert('RGB'))


def test_header_text_follows_level_and_charge_state():
    low = monitor({0x43: FakeIna(3.12, -3.0)}); low.probe(); low.poll()      # 10%
    full = monitor({0x43: FakeIna(4.2, 2.0)}); full.probe(); full.poll()     # 100%+
    assert _header_strip(_render(low)) != _header_strip(_render(full))


def test_an_undetected_hat_draws_nothing():
    m = monitor({})
    m.probe()
    assert _header_strip(_render(m)) == _header_strip(_render(None))


# ── web API ─────────────────────────────────────────────────────────────────

def _status(monkeypatch, hat):
    try:
        import webapp_modern as webapp
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip("webapp_modern unimportable here: %s" % exc)
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    monkeypatch.setattr(webapp.shared_data, "ragnar_instance",
                        types.SimpleNamespace(pisugar_listener=None, ups_hat_monitor=hat),
                        raising=False)
    resp = webapp.app.test_client().get("/api/system/status")
    assert resp.status_code == 200
    return resp.get_json()


def test_system_status_reports_the_hat_battery(monkeypatch):
    m = monitor({0x43: FakeIna(3.9, -3.0)})
    m.probe(); m.poll()
    battery = _status(monkeypatch, m)['battery']
    assert battery == {'level': 75.0, 'charging': False, 'voltage': 3.9,
                       'model': 'Waveshare UPS HAT (C)'}


def test_system_status_has_no_battery_without_a_hat(monkeypatch):
    assert _status(monkeypatch, monitor({}))['battery'] is None
