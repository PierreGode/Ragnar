#!/usr/bin/env python3
# ups_hat.py
"""
Battery monitor for Waveshare INA219-based UPS HATs.

Supported boards (all carry an INA219 voltage/current monitor on I2C bus 1):

  0x43  UPS HAT (C)  - Pi Zero pogo-pin board, one 3.7 V Li-po cell
  0x42  UPS HAT / UPS HAT (B) - two 18650 cells in series (8.4 V pack)

The percentage is Waveshare's own formula from their demo (`INA219.py`):
linear between 3.0 V (0 %) and 4.2 V (100 %) per cell, so the number on
Ragnar's screen matches what their tool prints.

Design notes
  * Read-only. The chip powers up in continuous 12-bit mode, so the bus and
    shunt voltage registers can be read without writing a calibration or
    config value. Nothing is ever written to the device, which keeps the
    auto-probe harmless if something else answers on the same address.
  * No extra dependency: I2C is done with a plain ioctl on /dev/i2c-N.
  * A background thread samples every few seconds and the display/web read
    the cached value, so a slow or stuck I2C bus can never stall a frame.

The public getters mirror PiSugarButtonListener (`available`,
get_battery_level, is_charging, get_battery_voltage, get_model) so every
battery slot in the UI works with either source: see battery_source().

CLI:  python3 ups_hat.py          one reading (exit 1 when no HAT answers)
      UPS_HAT_MOCK=1 ...          simulated battery for UI testing
"""

import logging
import math
import os
import sys
import threading
import time
from collections import deque

try:
    from logger import Logger
    logger = Logger(name="ups_hat.py", level=logging.INFO)
except Exception:  # standalone / CLI use
    logger = logging.getLogger("ups_hat")

I2C_SLAVE = 0x0703          # ioctl: select the slave address for read()/write()

REG_SHUNT_VOLTAGE = 0x01    # signed, 10 uV per bit
REG_BUS_VOLTAGE = 0x02      # bits 15..3, 4 mV per bit

# address -> (model, cells in series)
PROFILES = {
    0x43: ("Waveshare UPS HAT (C)", 1),
    0x42: ("Waveshare UPS HAT (B)", 2),
}

CELL_EMPTY_V = 3.0          # Waveshare demo: p = (v - 3) / 1.2 * 100 per cell
CELL_FULL_V = 4.2
# A reading outside this per-cell window is not a Li-ion pack: either another
# chip lives on the address or no battery is fitted.
CELL_MIN_PLAUSIBLE_V = 2.4
CELL_MAX_PLAUSIBLE_V = 4.5

# UPS HAT (C) schematic: R9 (0.01 ohm, 1 %) sits between the charger's BATT
# pin (INA219 IN+) and the cell (IN-). So the bus voltage is the battery
# voltage, and the shunt reads positive while charging and negative while the
# battery feeds the Pi. A0=SDA, A1=GND strap the chip to 0x43.
SHUNT_OHMS = 0.01
# A running Pi Zero pulls well over 100 mA from the cell (>= 1 mV across the
# shunt). Anything less negative than this means external power is present,
# including the "full, trickle at ~0 mA" state.
ON_BATTERY_SHUNT_MV = -0.5

POLL_SECONDS = 5
SMOOTH_SAMPLES = 6          # ~30 s moving average: load steps wobble the voltage
MAX_FAILURES = 6            # consecutive bad polls before the reading is dropped


def percent_from_voltage(voltage, cells=1):
    """Waveshare's linear estimate, clamped to 0..100."""
    per_cell = voltage / max(1, cells)
    pct = (per_cell - CELL_EMPTY_V) / (CELL_FULL_V - CELL_EMPTY_V) * 100.0
    return max(0.0, min(100.0, pct))


def decode_bus_voltage(raw):
    """INA219 bus voltage register -> volts."""
    return (raw >> 3) * 0.004


def decode_shunt_mv(raw):
    """INA219 shunt voltage register (two's complement) -> millivolts."""
    if raw > 0x7FFF:
        raw -= 0x10000
    return raw * 0.01


class I2CDevice:
    """Minimal register reader over /dev/i2c-N (no smbus dependency)."""

    def __init__(self, bus, address):
        import fcntl
        self._fd = os.open(f"/dev/i2c-{bus}", os.O_RDWR)
        try:
            fcntl.ioctl(self._fd, I2C_SLAVE, address)
        except Exception:
            os.close(self._fd)
            self._fd = None
            raise

    def read_word(self, register):
        """Read a big-endian 16-bit register."""
        os.write(self._fd, bytes([register]))
        data = os.read(self._fd, 2)
        if len(data) != 2:
            raise OSError("short I2C read")
        return (data[0] << 8) | data[1]

    def close(self):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


def _open_device(bus, address):
    return I2CDevice(bus, address)


class UpsHatMonitor:
    """Polls a Waveshare UPS HAT and caches battery level / voltage / state."""

    MOCK_ENV = 'UPS_HAT_MOCK'   # "1" simulates a HAT for UI testing

    def __init__(self, shared_data=None, bus=1, opener=None):
        self.shared_data = shared_data
        self.bus = bus
        self._opener = opener or _open_device
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._dev = None
        self._address = None
        self._model = None
        self._cells = 1
        self._voltages = deque(maxlen=SMOOTH_SAMPLES)
        self._shunt_mv = None
        self._failures = 0
        self.available = False
        self._mock = os.environ.get(self.MOCK_ENV, '') == '1'
        self._mock_start = time.time()

    # ── lifecycle ──────────────────────────────────────────────────────

    def enabled(self):
        cfg = getattr(self.shared_data, 'config', None) or {}
        # The CardputerZero has its own fuel gauge (sysfs_battery.py), and its
        # LoRa Cap puts an I/O expander on 0x43, the UPS HAT (C)'s address.
        # Never probe there: a stray answer must not be read as a battery.
        if cfg.get('epd_type') == 'st7789v2':
            return False
        return bool(cfg.get('ups_hat_monitor', True))

    def start(self):
        if self._mock:
            self.available = True
            self._model = PROFILES[0x43][0] + " (Mock)"
            logger.info("UPS HAT MOCK mode active (UPS_HAT_MOCK=1)")
            return
        if not self.enabled():
            logger.info("UPS HAT monitor disabled (ups_hat_monitor=false)")
            return
        self._thread = threading.Thread(target=self._run, name="ups-hat", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._close()

    def _close(self):
        dev, self._dev = self._dev, None
        if dev is not None:
            try:
                dev.close()
            except Exception:
                pass

    # ── detection + sampling ───────────────────────────────────────────

    def probe(self):
        """Find a HAT. Returns True when one answers with a plausible pack voltage."""
        for address, (model, cells) in PROFILES.items():
            dev = None
            try:
                dev = self._opener(self.bus, address)
                voltage = decode_bus_voltage(dev.read_word(REG_BUS_VOLTAGE))
            except Exception:
                if dev is not None:
                    try:
                        dev.close()
                    except Exception:
                        pass
                continue
            per_cell = voltage / cells
            if not (CELL_MIN_PLAUSIBLE_V <= per_cell <= CELL_MAX_PLAUSIBLE_V):
                logger.debug(f"I2C 0x{address:02x} answered with {voltage:.2f} V - not a {model} battery")
                dev.close()
                continue
            self._dev, self._address, self._model, self._cells = dev, address, model, cells
            return True
        return False

    def poll(self):
        """Take one sample. Returns True on success."""
        if self._dev is None:
            return False
        try:
            voltage = decode_bus_voltage(self._dev.read_word(REG_BUS_VOLTAGE))
            shunt_mv = decode_shunt_mv(self._dev.read_word(REG_SHUNT_VOLTAGE))
        except Exception as e:
            self._failures += 1
            if self._failures >= MAX_FAILURES and self.available:
                logger.warning(f"UPS HAT stopped answering ({e}) - battery reading dropped")
                with self._lock:
                    self.available = False
                    self._voltages.clear()
                    self._shunt_mv = None
            return False
        self._failures = 0
        with self._lock:
            self._voltages.append(voltage)
            self._shunt_mv = shunt_mv
            self.available = True
        return True

    def _run(self):
        # The HAT is fixed hardware: if it is not there shortly after boot it
        # is not going to appear, so give up after a few tries instead of
        # probing the bus forever.
        for attempt in range(4):
            if self._stop_event.is_set():
                return
            if self.probe():
                break
            self._stop_event.wait(5 * (attempt + 1))
        else:
            logger.info("No Waveshare UPS HAT detected on I2C - battery monitor idle")
            return
        self.poll()
        logger.info(f"{self._model} detected at 0x{self._address:02x}: "
                    f"{self.get_battery_voltage():.2f} V, {self.get_battery_level():.0f}%")
        while not self._stop_event.wait(POLL_SECONDS):
            self.poll()

    # ── mock (drains then charges over ~2 min) ─────────────────────────

    def _mock_level(self):
        return 55 + 40 * math.sin((time.time() - self._mock_start) * math.pi / 60)

    def _mock_charging(self):
        return math.cos((time.time() - self._mock_start) * math.pi / 60) > 0

    # ── public getters (same shape as PiSugarButtonListener) ───────────

    def get_battery_voltage(self):
        """Smoothed pack voltage in volts, or None."""
        if self._mock:
            return CELL_EMPTY_V + self._mock_level() / 100.0 * (CELL_FULL_V - CELL_EMPTY_V)
        with self._lock:
            if not self.available or not self._voltages:
                return None
            return sum(self._voltages) / len(self._voltages)

    def get_battery_level(self):
        """Battery percentage 0..100, or None."""
        if self._mock:
            return self._mock_level()
        voltage = self.get_battery_voltage()
        if voltage is None:
            return None
        return percent_from_voltage(voltage, self._cells)

    def is_charging(self):
        """True while external power is connected (charging or topped up)."""
        if self._mock:
            return self._mock_charging()
        with self._lock:
            if not self.available or self._shunt_mv is None:
                return None
            return self._shunt_mv > ON_BATTERY_SHUNT_MV

    def get_current_ma(self):
        """Battery current in mA (negative = discharging), or None."""
        if self._mock:
            return 180.0 if self._mock_charging() else -240.0
        with self._lock:
            if not self.available or self._shunt_mv is None:
                return None
            return self._shunt_mv / SHUNT_OHMS

    def get_model(self):
        return self._model


def battery_source(shared_data):
    """The battery telemetry source that is live right now, or None.

    PiSugar wins when several answer (it also owns the hardware button), then
    a Waveshare UPS HAT, then a built-in fuel gauge (sysfs_battery.py, e.g.
    the CardputerZero's). All expose the same getters.
    """
    inst = getattr(shared_data, 'ragnar_instance', None)
    if inst is None:
        return None
    for name in ('pisugar_listener', 'ups_hat_monitor', 'builtin_battery'):
        src = getattr(inst, name, None)
        if src is not None and getattr(src, 'available', False):
            return src
    return None


def main():
    mon = UpsHatMonitor()
    if mon._mock:
        mon.start()
    elif not (mon.probe() and mon.poll()):
        print("No Waveshare UPS HAT found on I2C bus 1 (is I2C enabled and a battery fitted?)")
        return 1
    state = "external power" if mon.is_charging() else "on battery"
    print(f"{mon.get_model()}: {mon.get_battery_level():.0f}% "
          f"({mon.get_battery_voltage():.2f} V, {mon.get_current_ma():+.0f} mA, {state})")
    mon.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
