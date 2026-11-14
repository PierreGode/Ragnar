"""Built-in battery (kernel power-supply class / BQ27220), on simulated hardware.

The sysfs layout is the one the bq27xxx driver publishes on the M5Stack
CardputerZero; the I2C words are the BQ27220's standard commands."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sysfs_battery as sb  # noqa: E402
import ups_hat  # noqa: E402


def supply(root, name, **files):
    d = root / name
    d.mkdir(parents=True)
    for key, value in files.items():
        (d / key).write_text(f"{value}\n")
    return d


def gauge(root, name="bq27220-0", capacity=76, status="Discharging", **extra):
    fields = dict(type="Battery", present=1, capacity=capacity, status=status,
                  voltage_now=3912000, current_now=-180000, temp=291)
    fields.update(extra)
    return supply(root, name, **fields)


def monitor(root, epd_type="st7789v2", opener=None, **cfg):
    shared = types.SimpleNamespace(config=dict({"epd_type": epd_type}, **cfg))

    def no_i2c():
        raise OSError(16, "Device or resource busy")

    return sb.SysfsBatteryMonitor(shared, root=str(root), i2c_opener=opener or no_i2c)


def test_reads_the_gauge_the_kernel_publishes(tmp_path):
    gauge(tmp_path)
    m = monitor(tmp_path)
    assert m.probe() and m.poll()
    assert m.available
    assert m.get_battery_level() == 76
    assert m.get_battery_voltage() == pytest.approx(3.912)
    assert m.is_charging() is False
    assert "BQ27220" in m.get_model()


@pytest.mark.parametrize("status,charging", [
    ("Charging", True), ("Full", True), ("Discharging", False),
    ("Not charging", False), ("Unknown", False)])
def test_charging_follows_the_kernel_status(tmp_path, status, charging):
    gauge(tmp_path, status=status)
    m = monitor(tmp_path)
    assert m.probe() and m.poll()
    assert m.is_charging() is charging


def test_mains_adapter_and_usb_supplies_are_not_batteries(tmp_path):
    supply(tmp_path, "AC", type="Mains", online=1)
    supply(tmp_path, "usb", type="USB", online=1, capacity=100)
    assert sb.find_power_supply(str(tmp_path)) is None
    m = monitor(tmp_path)
    assert not m.probe()
    assert m.get_battery_level() is None and not m.available


def test_gauge_is_preferred_over_another_battery(tmp_path):
    gauge(tmp_path, name="BAT0", capacity=11)
    gauge(tmp_path, name="bq27220-0", capacity=64)
    assert sb.find_power_supply(str(tmp_path)).endswith("bq27220-0")


def test_absent_cell_gives_no_reading(tmp_path):
    gauge(tmp_path, present=0)
    assert not monitor(tmp_path).probe()


@pytest.mark.parametrize("capacity", [-1, 101, 255])
def test_out_of_range_percentage_is_rejected(tmp_path, capacity):
    gauge(tmp_path, capacity=capacity)
    assert not monitor(tmp_path).probe()


def test_reading_is_dropped_when_the_gauge_goes_away(tmp_path):
    d = gauge(tmp_path)
    m = monitor(tmp_path)
    assert m.probe() and m.poll()
    (d / "capacity").unlink()
    for _ in range(sb.MAX_FAILURES):
        assert not m.poll()
    assert not m.available and m.get_battery_level() is None
    (d / "capacity").write_text("40\n")
    assert m.poll() and m.get_battery_level() == 40


def test_monitor_can_be_switched_off(tmp_path):
    gauge(tmp_path)
    m = monitor(tmp_path, builtin_battery_monitor=False)
    m.start()
    assert m._thread is None and not m.available


# ── BQ27220 over I2C (no kernel driver) ──────────────────────────────────────

class FakeGauge(sb.Bq27220Reader):
    """The real reader's decoding on top of a register map instead of an fd."""

    def __init__(self, words):
        self.words = words
        self.closed = False

    def _word(self, command):
        return self.words[command]

    def close(self):
        self.closed = True


def words(soc=58, mv=3850, ma=-210):
    return {sb.BQ_CMD_SOC: soc, sb.BQ_CMD_VOLTAGE: mv,
            sb.BQ_CMD_CURRENT: ma & 0xFFFF}


def test_i2c_gauge_is_used_when_the_kernel_has_no_driver(tmp_path):
    m = monitor(tmp_path, opener=lambda: FakeGauge(words()))
    assert m.probe() and m.poll()
    assert m.get_battery_level() == 58
    assert m.get_battery_voltage() == pytest.approx(3.85)
    assert m.is_charging() is False


def test_i2c_current_is_signed(tmp_path):
    m = monitor(tmp_path, opener=lambda: FakeGauge(words(ma=320)))
    assert m.probe() and m.poll()
    assert m.is_charging() is True


def test_i2c_is_only_probed_on_a_cardputer(tmp_path):
    opened = []

    def opener():
        opened.append(True)
        return FakeGauge(words())

    assert not monitor(tmp_path, epd_type="epd2in13_V4", opener=opener).probe()
    assert opened == []


@pytest.mark.parametrize("bad", [words(soc=140), words(mv=0), words(mv=5200), words(mv=0xFFFF)])
def test_another_chip_on_the_address_is_not_taken_for_a_battery(tmp_path, bad):
    g = FakeGauge(bad)
    m = monitor(tmp_path, opener=lambda: g)
    assert not m.probe()
    assert g.closed


def test_kernel_gauge_wins_over_i2c(tmp_path):
    gauge(tmp_path, capacity=91)
    m = monitor(tmp_path, opener=lambda: FakeGauge(words(soc=5)))
    assert m.probe() and m.poll()
    assert m.get_battery_level() == 91


# ── the shared battery slot ──────────────────────────────────────────────────

def test_battery_slot_falls_through_to_the_built_in_gauge(tmp_path):
    gauge(tmp_path)
    m = monitor(tmp_path)
    assert m.probe() and m.poll()
    idle = types.SimpleNamespace(available=False)
    live = types.SimpleNamespace(available=True)
    inst = types.SimpleNamespace(pisugar_listener=idle, ups_hat_monitor=idle, builtin_battery=m)
    assert ups_hat.battery_source(types.SimpleNamespace(ragnar_instance=inst)) is m
    inst.ups_hat_monitor = live
    assert ups_hat.battery_source(types.SimpleNamespace(ragnar_instance=inst)) is live


def test_ragnar_starts_and_stops_the_monitor():
    text = open(os.path.join(os.path.dirname(sb.__file__), "Ragnar.py")).read()
    assert "SysfsBatteryMonitor(shared_data)" in text
    assert "self.builtin_battery.start()" in text
    assert "self.builtin_battery.stop()" in text
