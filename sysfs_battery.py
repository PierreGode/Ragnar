#!/usr/bin/env python3
# sysfs_battery.py
"""
Battery monitor for boards with a built-in fuel gauge.

The M5Stack CardputerZero carries a TI BQ27220 gauge (I2C 0x55 on bus 1) for
its 1750 mAh cell. Two ways to read it, tried in this order:

  1. The kernel's power-supply class. M5Stack's image loads the bq27xxx
     driver, which publishes the gauge under /sys/class/power_supply/<name>/
     (type "Battery", with `capacity` in percent and `status`). This path is
     not CardputerZero-specific: any board whose kernel exposes a battery
     there is picked up.
  2. The gauge itself over I2C, for a kernel without that driver. Only tried
     on a CardputerZero (epd_type st7789v2), because 0x55 is a common address
     and a blind probe on other boards could mistake another chip for it.
     Read-only: the standard commands are read, nothing is written to the
     gauge's configuration.

The percentage is the gauge's own state of charge, so it matches what the
stock launcher shows.

A background thread samples every few seconds and the display/web read the
cached value. The public getters mirror PiSugarButtonListener and
UpsHatMonitor (`available`, get_battery_level, is_charging,
get_battery_voltage, get_model), so every battery slot in the UI works with
it: see ups_hat.battery_source().

CLI:  python3 sysfs_battery.py        one reading (exit 1 when none is found)
"""

import logging
import os
import sys
import threading

try:
    from logger import Logger
    logger = Logger(name="sysfs_battery.py", level=logging.INFO)
except Exception:  # standalone / CLI use
    logger = logging.getLogger("sysfs_battery")

POWER_SUPPLY_ROOT = "/sys/class/power_supply"

POLL_SECONDS = 10
MAX_FAILURES = 6            # consecutive bad polls before the reading is dropped
PROBE_ATTEMPTS = 6          # the driver can bind a little after we start at boot

# --- BQ27220 standard commands (little-endian 16-bit words) --------------------
BQ27220_ADDR = 0x55
BQ27220_BUS = 1
BQ_CMD_VOLTAGE = 0x08       # mV
BQ_CMD_CURRENT = 0x0C       # signed mA, negative while discharging
BQ_CMD_SOC = 0x2C           # state of charge, percent
I2C_SLAVE = 0x0703

# A single Li-ion cell outside this window is not a battery reading.
CELL_MIN_PLAUSIBLE_V = 2.5
CELL_MAX_PLAUSIBLE_V = 4.6
# Gauge current above this (mA) means the charger is feeding the cell.
CHARGING_CURRENT_MA = 5

BUILT_IN_GAUGE_PANELS = {"st7789v2"}    # boards we may probe on I2C


def _read_text(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _read_int(path):
    text = _read_text(path)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def find_power_supply(root=POWER_SUPPLY_ROOT):
    """Directory of the kernel's battery, or None.

    A supply qualifies when its type is "Battery" and it reports `capacity`.
    A bq27xxx gauge wins over anything else, then the first one by name."""
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return None
    fallback = None
    for name in names:
        path = os.path.join(root, name)
        if (_read_text(os.path.join(path, "type")) or "").lower() != "battery":
            continue
        if _read_int(os.path.join(path, "capacity")) is None:
            continue
        if "bq27" in name.lower():
            return path
        if fallback is None:
            fallback = path
    return fallback


class SysfsReader:
    """Reads a /sys/class/power_supply battery directory."""

    def __init__(self, path):
        self.path = path
        self.model = self._model()

    def _model(self):
        name = os.path.basename(self.path)
        if "bq27220" in name.lower():
            return "BQ27220 fuel gauge"
        return f"Battery ({name})"

    def read(self):
        """One sample: dict(level, voltage, charging), or None."""
        if _read_int(os.path.join(self.path, "present")) == 0:
            return None
        level = _read_int(os.path.join(self.path, "capacity"))
        if level is None or not 0 <= level <= 100:
            return None
        micro_v = _read_int(os.path.join(self.path, "voltage_now"))
        status = (_read_text(os.path.join(self.path, "status")) or "").lower()
        # "Full" means the charger topped the cell up and is still attached.
        return {
            "level": float(level),
            "voltage": micro_v / 1e6 if micro_v else None,
            "charging": status in ("charging", "full"),
        }

    def close(self):
        pass


class Bq27220Reader:
    """Reads a BQ27220 directly over /dev/i2c-N (no smbus dependency)."""

    model = "BQ27220 fuel gauge (I2C)"

    def __init__(self, bus=BQ27220_BUS, address=BQ27220_ADDR):
        import fcntl
        self._fd = os.open(f"/dev/i2c-{bus}", os.O_RDWR)
        try:
            fcntl.ioctl(self._fd, I2C_SLAVE, address)
        except Exception:
            self.close()
            raise

    def _word(self, command):
        os.write(self._fd, bytes([command]))
        data = os.read(self._fd, 2)
        if len(data) != 2:
            raise OSError("short I2C read")
        return data[0] | (data[1] << 8)

    def read(self):
        """One sample: dict(level, voltage, charging), or None when the answer
        is not a plausible single-cell gauge reading."""
        level = self._word(BQ_CMD_SOC)
        voltage = self._word(BQ_CMD_VOLTAGE) / 1000.0
        current = self._word(BQ_CMD_CURRENT)
        if current > 0x7FFF:
            current -= 0x10000
        if not 0 <= level <= 100:
            return None
        if not CELL_MIN_PLAUSIBLE_V <= voltage <= CELL_MAX_PLAUSIBLE_V:
            return None
        return {"level": float(level), "voltage": voltage,
                "charging": current > CHARGING_CURRENT_MA}

    def close(self):
        fd, self._fd = getattr(self, "_fd", None), None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


class SysfsBatteryMonitor:
    """Polls the built-in battery and caches level / voltage / charging."""

    def __init__(self, shared_data=None, root=POWER_SUPPLY_ROOT, i2c_opener=None):
        self.shared_data = shared_data
        self.root = root
        self._i2c_opener = i2c_opener or Bq27220Reader
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._reader = None
        self._sample = None
        self._failures = 0
        self.available = False

    # ── lifecycle ──────────────────────────────────────────────────────

    def enabled(self):
        cfg = getattr(self.shared_data, 'config', None) or {}
        return bool(cfg.get('builtin_battery_monitor', True))

    def start(self):
        if not self.enabled():
            logger.info("Built-in battery monitor disabled (builtin_battery_monitor=false)")
            return
        self._thread = threading.Thread(target=self._run, name="sysfs-battery", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._close()

    def _close(self):
        reader, self._reader = self._reader, None
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    # ── detection + sampling ───────────────────────────────────────────

    def _i2c_allowed(self):
        cfg = getattr(self.shared_data, 'config', None) or {}
        return cfg.get('epd_type') in BUILT_IN_GAUGE_PANELS

    def probe(self):
        """Find a battery. True when one answers with a valid reading."""
        path = find_power_supply(self.root)
        if path:
            reader = SysfsReader(path)
            if reader.read() is not None:
                self._reader = reader
                return True
        if self._i2c_allowed():
            reader = None
            try:
                reader = self._i2c_opener()
                if reader.read() is not None:
                    self._reader = reader
                    return True
            except Exception as e:
                # EBUSY here just means the kernel driver owns the gauge.
                logger.debug(f"BQ27220 not readable over I2C: {e}")
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
        return False

    def poll(self):
        """Take one sample. Returns True on success."""
        if self._reader is None:
            return False
        try:
            sample = self._reader.read()
        except Exception as e:
            logger.debug(f"battery read failed: {e}")
            sample = None
        if sample is None:
            self._failures += 1
            if self._failures >= MAX_FAILURES and self.available:
                logger.warning("Built-in battery stopped answering - reading dropped")
                with self._lock:
                    self.available = False
                    self._sample = None
            return False
        self._failures = 0
        with self._lock:
            self._sample = sample
            self.available = True
        return True

    def _run(self):
        # Fixed hardware: if it is not there shortly after boot it is not
        # going to appear, so stop looking instead of probing forever.
        for attempt in range(PROBE_ATTEMPTS):
            if self._stop_event.is_set():
                return
            if self.probe():
                break
            self._stop_event.wait(5 * (attempt + 1))
        else:
            logger.info("No built-in battery found - battery monitor idle")
            return
        self.poll()
        logger.info(f"{self.get_model()} detected: {self.get_battery_level():.0f}%"
                    f"{' (charging)' if self.is_charging() else ''}")
        while not self._stop_event.wait(POLL_SECONDS):
            self.poll()

    # ── public getters (same shape as PiSugarButtonListener) ───────────

    def _get(self, key):
        with self._lock:
            if not self.available or self._sample is None:
                return None
            return self._sample.get(key)

    def get_battery_level(self):
        """Battery percentage 0..100, or None."""
        return self._get("level")

    def get_battery_voltage(self):
        """Cell voltage in volts, or None."""
        return self._get("voltage")

    def is_charging(self):
        """True while the charger is feeding or holding the cell."""
        return self._get("charging")

    def get_model(self):
        return getattr(self._reader, "model", None)


def main():
    cfg = {"epd_type": "st7789v2"} if "--i2c" in sys.argv else {}
    mon = SysfsBatteryMonitor(type("S", (), {"config": cfg})())
    if not (mon.probe() and mon.poll()):
        print("No battery found under /sys/class/power_supply "
              "(add --i2c to also try a BQ27220 at 0x55 on I2C bus 1)")
        return 1
    voltage = mon.get_battery_voltage()
    state = "charging" if mon.is_charging() else "on battery"
    print(f"{mon.get_model()}: {mon.get_battery_level():.0f}% "
          f"({'%.2f V, ' % voltage if voltage else ''}{state})")
    mon.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
