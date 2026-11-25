"""HackerGadgets Pwnagotchi HAT battery monitor: register decoding, identity
masking, detection, failure handling, low-battery shutdown and where the
reading surfaces (battery_source order, the USB-mode extra)."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('RAGNAR_HEADLESS', '1')

import hg_hat  # noqa: E402
import ups_hat  # noqa: E402

# Captured from a real HAT: 4.235 V, charging, USB hub, 53 %, charger present.
REAL_BLOCK = [0x10, 0x8B, 0x00, 0x00, 0x35, 0x01]


def block(mv=3800, charging=False, usb_otg=False, soc=60, adapter=False):
    return [(mv >> 8) & 0xFF, mv & 0xFF, 0 if charging else 1,
            1 if usb_otg else 0, soc, 1 if adapter else 0]


class FakeBus:
    """I2C bus 1 as the monitor sees it: the HAT's controller at 0x50."""

    def __init__(self, signature=0x6C, power=None):
        self.signature = signature
        self.power = list(power if power is not None else block())
        self.fail = False
        self.closed = False
        self.writes = []

    def read(self, address, register, length):
        if self.fail or address != hg_hat.HAT_ADDRESS:
            raise OSError(121, 'Remote I/O error')
        if register == hg_hat.REG_SIGNATURE and length == 1:
            return [self.signature]
        if register == hg_hat.REG_POWER_BLOCK and length == 6:
            return list(self.power)
        raise OSError(5, 'Input/output error')

    def close(self):
        self.closed = True


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def monitor(bus, clock=None, **cfg):
    calls = []
    sd = types.SimpleNamespace(config=dict(cfg))
    mon = hg_hat.HgHatMonitor(sd, opener=lambda _bus: bus,
                              poweroff=lambda: calls.append('poweroff'),
                              clock=clock or Clock())
    return mon, calls


# ── decoding ────────────────────────────────────────────────────────────────

def test_real_hat_block_decodes():
    r = hg_hat.decode_power_block(REAL_BLOCK)
    assert r == {'voltage': pytest.approx(4.235), 'charging': True, 'usb_mode': 'hub',
                 'soc': 53, 'adapter': True}


def test_charge_flag_zero_means_charging_and_usb_one_means_otg():
    r = hg_hat.decode_power_block(block(charging=False, usb_otg=True))
    assert r['charging'] is False and r['usb_mode'] == 'otg'


@pytest.mark.parametrize('bad', [
    [0x10, 0x8B, 0x02, 0x00, 0x35, 0x01],   # charge flag not 0/1
    [0x10, 0x8B, 0x00, 0x05, 0x35, 0x01],   # USB mode not 0/1
    [0x10, 0x8B, 0x00, 0x00, 0x65, 0x01],   # 101 %
    [0x10, 0x8B, 0x00, 0x00, 0x35, 0x07],   # adapter not 0/1
    [0x00, 0x10, 0x00, 0x00, 0x35, 0x01],   # 0.016 V: not a Li-ion cell
    [0xFF, 0xFF, 0x00, 0x00, 0x35, 0x01],   # 65 V
    [0x10, 0x8B, 0x00, 0x00, 0x35],         # short read
])
def test_implausible_blocks_are_rejected(bad):
    assert hg_hat.decode_power_block(bad) is None


@pytest.mark.parametrize('sig,ok', [(0x6C, True), (0xEC, True), (0x6D, False), (0x00, False), (0xFF, False)])
def test_identity_tolerates_the_clock_stretch_bit(sig, ok):
    # The real board reads 0x6C one moment and 0xEC the next: the Pi's I2C
    # hardware can read bit 7 of the first byte as 1 after clock stretching.
    assert hg_hat.signature_ok(sig) is ok


def test_voltage_high_byte_tolerates_the_clock_stretch_bit():
    # Captured from the real HAT: 0x90D1 is 0x10D1 = 4.305 V with bit 7 misread.
    r = hg_hat.decode_power_block([0x90, 0xD1, 0x00, 0x00, 0x60, 0x01])
    assert r is not None and r['voltage'] == pytest.approx(4.305) and r['soc'] == 96


# ── detection ───────────────────────────────────────────────────────────────

def test_detect_finds_the_hat_and_closes_the_bus():
    bus = FakeBus(power=REAL_BLOCK)
    assert hg_hat.detect(opener=lambda _b: bus) is True
    assert bus.closed


def test_detect_rejects_a_foreign_chip_on_0x50():
    # e.g. an EEPROM: wrong identity byte
    assert hg_hat.detect(opener=lambda _b: FakeBus(signature=0x12)) is False
    # right byte by chance, but the power block is nonsense
    assert hg_hat.detect(opener=lambda _b: FakeBus(power=[0xFF] * 6)) is False


def test_detect_survives_an_empty_bus():
    bus = FakeBus()
    bus.fail = True
    assert hg_hat.detect(opener=lambda _b: bus) is False


def test_probe_then_poll_fills_the_getters():
    mon, _ = monitor(FakeBus(power=REAL_BLOCK))
    assert mon.probe() and mon.poll()
    assert mon.available
    assert mon.get_battery_level() == 53.0
    assert mon.get_battery_voltage() == pytest.approx(4.235)
    assert mon.is_charging() is True          # charger connected
    assert mon.get_usb_mode() == 'hub'
    assert mon.get_model() == 'HackerGadgets Pwnagotchi HAT'


def test_on_battery_reads_not_charging():
    mon, _ = monitor(FakeBus(power=block(adapter=False, charging=False, soc=70)))
    mon.probe(), mon.poll()
    assert mon.is_charging() is False


def test_reading_is_dropped_after_repeated_failures_only():
    bus = FakeBus()
    mon, _ = monitor(bus)
    mon.probe(), mon.poll()
    bus.fail = True
    for _ in range(hg_hat.MAX_FAILURES - 1):
        assert mon.poll() is False
    assert mon.available                      # a few glitches keep the last value
    mon.poll()
    assert not mon.available and mon.get_battery_level() is None


def test_getters_are_none_before_any_reading():
    mon, _ = monitor(FakeBus())
    assert mon.get_battery_level() is None and mon.is_charging() is None


# ── config ──────────────────────────────────────────────────────────────────

def test_disabled_by_config_and_on_cardputer():
    assert monitor(FakeBus(), hg_hat_monitor=False)[0].enabled() is False
    assert monitor(FakeBus(), epd_type='st7789v2')[0].enabled() is False
    assert monitor(FakeBus())[0].enabled() is True


def test_threshold_defaults_clamps_and_turns_off():
    assert monitor(FakeBus())[0].lowbatt_threshold() == 10
    assert monitor(FakeBus(), hg_hat_lowbatt_percent=80)[0].lowbatt_threshold() == 50
    assert monitor(FakeBus(), hg_hat_lowbatt_percent=1)[0].lowbatt_threshold() == 3
    assert monitor(FakeBus(), hg_hat_lowbatt_percent='x')[0].lowbatt_threshold() == 10
    assert monitor(FakeBus(), hg_hat_lowbatt_shutdown=False)[0].lowbatt_threshold() is None


# ── low-battery shutdown ────────────────────────────────────────────────────

def run_samples(mon, clock, seconds, step=5):
    end = clock.t + seconds
    while clock.t < end:
        mon.poll()
        clock.t += step


def test_low_battery_on_battery_shuts_down_after_a_full_minute_once():
    clock = Clock()
    mon, calls = monitor(FakeBus(power=block(soc=8)), clock=clock)
    mon.probe()
    run_samples(mon, clock, 55)
    assert calls == []                        # not yet: needs 60 s
    run_samples(mon, clock, 30)
    assert calls == ['poweroff']
    run_samples(mon, clock, 120)
    assert calls == ['poweroff']              # fires once


def test_charger_connected_never_shuts_down():
    clock = Clock()
    mon, calls = monitor(FakeBus(power=block(soc=2, adapter=True, charging=True)), clock=clock)
    mon.probe()
    run_samples(mon, clock, 300)
    assert calls == []


def test_above_threshold_never_shuts_down():
    clock = Clock()
    mon, calls = monitor(FakeBus(power=block(soc=10)), clock=clock)   # threshold is < 10
    mon.probe()
    run_samples(mon, clock, 300)
    assert calls == []


def test_recovering_or_plugging_in_restarts_the_window():
    clock = Clock()
    bus = FakeBus(power=block(soc=8))
    mon, calls = monitor(bus, clock=clock)
    mon.probe()
    run_samples(mon, clock, 45)
    bus.power = block(soc=8, adapter=True)    # charger plugged in briefly
    run_samples(mon, clock, 10)
    bus.power = block(soc=8)
    run_samples(mon, clock, 45)
    assert calls == []                        # 45 s since unplugging, not 60
    run_samples(mon, clock, 20)
    assert calls == ['poweroff']


def test_a_long_gap_between_samples_restarts_the_window():
    clock = Clock()
    mon, calls = monitor(FakeBus(power=block(soc=8)), clock=clock)
    mon.probe()
    run_samples(mon, clock, 40)
    clock.t += 300                            # bus stalled / suspended
    run_samples(mon, clock, 40)
    assert calls == []


def test_low_battery_shutdown_can_be_switched_off():
    clock = Clock()
    mon, calls = monitor(FakeBus(power=block(soc=4)), clock=clock, hg_hat_lowbatt_shutdown=False)
    mon.probe()
    run_samples(mon, clock, 300)
    assert calls == []


def test_guard_alone():
    g = hg_hat.LowBatteryGuard(10, confirm=60, max_gap=20)
    low = {'adapter': False, 'charging': False, 'soc': 5}
    assert g.observe(low, 0) is False
    assert g.observe(low, 59) is False        # a 59 s gap (> 20) restarts the window here
    assert g.observe(low, 75) is False        # only 16 s since the restart
    assert g.observe(low, 79) is False        # 20 s
    g2 = hg_hat.LowBatteryGuard(10, confirm=60, max_gap=20)
    fired = [g2.observe(low, t) for t in range(0, 61, 5)]
    assert fired[-1] is True and fired.count(True) == 1
    assert g2.observe(low, 70) is False       # latched


# ── surfaces ────────────────────────────────────────────────────────────────

def _src(available):
    return types.SimpleNamespace(available=available)


def test_battery_source_order_puts_the_hat_after_waveshare():
    inst = types.SimpleNamespace(pisugar_listener=None, ups_hat_monitor=_src(False),
                                 hg_hat_monitor=_src(True), builtin_battery=_src(True))
    sd = types.SimpleNamespace(ragnar_instance=inst)
    assert ups_hat.battery_source(sd) is inst.hg_hat_monitor
    inst.ups_hat_monitor = _src(True)
    assert ups_hat.battery_source(sd) is inst.ups_hat_monitor


def test_mock_mode_gives_a_full_reading(monkeypatch):
    monkeypatch.setenv('HG_HAT_MOCK', '1')
    mon = hg_hat.HgHatMonitor(types.SimpleNamespace(config={}))
    mon.start()
    assert mon.available
    assert 0 <= mon.get_battery_level() <= 100
    assert mon.get_usb_mode() == 'hub'
