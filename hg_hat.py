#!/usr/bin/env python3
# hg_hat.py
"""
Battery monitor for the HackerGadgets Pwnagotchi HAT (UPS, GPS, AC Wi-Fi, USB
hub and RTC on one board for the Raspberry Pi Zero family).

The HAT's power controller answers on I2C bus 1 at 0x50:

  0x08        identity: 0x6C
  0x00..0x05  battery millivolts (high, low), charge flag (0 = charging), USB
              mode (0 = hub, 1 = OTG), state of charge in %, charger present (1)

The controller holds the I2C clock (clock stretching) before it answers, and the
Pi's I2C hardware samples the first bit of that first byte too early: bit 7 of
the first byte read in a transaction sometimes comes back as 1 (0xEC for 0x6C,
0x90 for a 0x10 voltage byte). Neither first byte can legitimately have bit 7
set - the identity is 0x6C and the battery's high millivolt byte is at most 0x12
- so that one bit is masked; every other byte is still checked strictly.

The percentage is the controller's own fuel-gauge figure. The board's RTC
(PCF85063A) sits next to it at 0x51 and is handled by the kernel driver that
scripts/hg_hat_setup.sh enables (dtoverlay=i2c-rtc,pcf85063a).

Design notes
  * Read-only. Ragnar never writes to the controller from here. Cutting the
    HAT's power after a clean shutdown is done by the system-shutdown hook that
    scripts/hg_hat_setup.sh installs, which runs once the file systems are
    read-only, so the SD card is always safe when the power goes.
  * Low battery: on battery (no charger) below `hg_hat_lowbatt_percent` for a
    full minute, Ragnar shuts the system down cleanly. The hook then has the
    HAT switch off, so the halted Pi does not drain the cell.
  * No extra dependency: I2C is a combined write+read (I2C_RDWR) on
    /dev/i2c-1, the same transaction smbus uses, without needing smbus.
  * A background thread samples every few seconds; the display and web read
    the cached values, so a slow I2C bus never stalls a frame.

The public getters mirror PiSugarButtonListener / UpsHatMonitor (`available`,
get_battery_level, is_charging, get_battery_voltage, get_model), so every
battery slot in the UI works with it: see ups_hat.battery_source().

CLI:  python3 hg_hat.py            one reading (exit 1 when no HAT answers)
      python3 hg_hat.py --detect   exit 0 when the HAT is present (for scripts)
      HG_HAT_MOCK=1 ...            simulated HAT for UI testing
"""

import ctypes
import logging
import math
import os
import subprocess
import sys
import threading
import time

try:
    from logger import Logger
    logger = Logger(name="hg_hat.py", level=logging.INFO)
except Exception:  # standalone / CLI use
    logger = logging.getLogger("hg_hat")

MODEL = "HackerGadgets Pwnagotchi HAT"

HAT_ADDRESS = 0x50
RTC_ADDRESS = 0x51
REG_POWER_BLOCK = 0x00      # 6 bytes, see the module docstring
REG_SIGNATURE = 0x08
SIGNATURE = 0x6C
FIRST_BYTE_MASK = 0x7F      # Pi I2C clock-stretch artifact on the first byte, see above

# A cell outside this window is not a Li-ion battery behind this controller.
MIN_PLAUSIBLE_V = 2.5
MAX_PLAUSIBLE_V = 4.6

POLL_SECONDS = 5
MAX_FAILURES = 6            # consecutive bad polls before the reading is dropped

DEFAULT_LOWBATT_PERCENT = 10
LOWBATT_CONFIRM_SECONDS = 60
LOWBATT_MAX_SAMPLE_GAP = 20  # a gap this long restarts the confirmation window

I2C_RDWR = 0x0707
I2C_M_RD = 0x0001

SETUP_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'scripts', 'hg_hat_setup.sh')
POWEROFF_HOOK = '/usr/lib/systemd/system-shutdown/ragnar-hg-hat-poweroff'


class _I2cMsg(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint16), ("flags", ctypes.c_uint16),
                ("len", ctypes.c_uint16), ("buf", ctypes.POINTER(ctypes.c_uint8))]


class _I2cRdwr(ctypes.Structure):
    _fields_ = [("msgs", ctypes.POINTER(_I2cMsg)), ("nmsgs", ctypes.c_uint32)]


class I2CBus:
    """Combined register reads over /dev/i2c-N (no smbus dependency)."""

    def __init__(self, bus=1):
        self._fd = os.open(f"/dev/i2c-{bus}", os.O_RDWR)

    def read(self, address, register, length):
        import fcntl
        wbuf = (ctypes.c_uint8 * 1)(register)
        rbuf = (ctypes.c_uint8 * length)()
        msgs = (_I2cMsg * 2)(_I2cMsg(address, 0, 1, wbuf),
                             _I2cMsg(address, I2C_M_RD, length, rbuf))
        fcntl.ioctl(self._fd, I2C_RDWR, _I2cRdwr(msgs, 2))
        data = list(rbuf)
        if data:
            data[0] &= FIRST_BYTE_MASK
        return data

    def close(self):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


def _open_bus(bus):
    return I2CBus(bus)


def signature_ok(value):
    return (value & FIRST_BYTE_MASK) == SIGNATURE


def decode_power_block(block):
    """The controller's 6-byte power block -> dict, or None when implausible."""
    if len(block) != 6 or any(not 0 <= b <= 0xFF for b in block):
        return None
    high, low, charge_raw, usb_mode, soc, adapter_raw = block
    high &= FIRST_BYTE_MASK     # clock-stretch artifact; a real value is <= 0x12
    voltage = ((high << 8) | low) / 1000.0
    if (charge_raw not in (0, 1) or usb_mode not in (0, 1) or adapter_raw not in (0, 1)
            or not 0 <= soc <= 100 or not MIN_PLAUSIBLE_V <= voltage <= MAX_PLAUSIBLE_V):
        return None
    return {
        'voltage': voltage,
        'charging': charge_raw == 0,
        'usb_mode': 'otg' if usb_mode == 1 else 'hub',
        'soc': soc,
        'adapter': adapter_raw == 1,
    }


def detect(bus=1, opener=None):
    """True when the HAT's controller answers with its identity and a sane block."""
    dev = None
    try:
        dev = (opener or _open_bus)(bus)
        if not signature_ok(dev.read(HAT_ADDRESS, REG_SIGNATURE, 1)[0]):
            return False
        return decode_power_block(dev.read(HAT_ADDRESS, REG_POWER_BLOCK, 6)) is not None
    except Exception:
        return False
    finally:
        if dev is not None:
            try:
                dev.close()
            except Exception:
                pass


class LowBatteryGuard:
    """Decides when a low battery should shut the system down.

    Only on battery (no charger, not charging), below the threshold, and only
    after LOWBATT_CONFIRM_SECONDS of consecutive fresh samples. Fires once.
    """

    def __init__(self, threshold, confirm=LOWBATT_CONFIRM_SECONDS,
                 max_gap=LOWBATT_MAX_SAMPLE_GAP):
        self.threshold = threshold
        self.confirm = confirm
        self.max_gap = max_gap
        self._since = None
        self._last = None
        self.fired = False

    def observe(self, reading, now):
        if self.fired:
            return False
        low = (reading is not None and not reading['adapter'] and not reading['charging']
               and reading['soc'] < self.threshold)
        if not low:
            self._since = self._last = None
            return False
        if self._last is None or now < self._last or now - self._last > self.max_gap:
            self._since = now
        self._last = now
        if now - self._since >= self.confirm:
            self.fired = True
            return True
        return False


class HgHatMonitor:
    """Polls the HackerGadgets Pwnagotchi HAT and caches its battery state."""

    MOCK_ENV = 'HG_HAT_MOCK'    # "1" simulates the HAT for UI testing

    def __init__(self, shared_data=None, bus=1, opener=None, poweroff=None, clock=None):
        self.shared_data = shared_data
        self.bus = bus
        self._opener = opener or _open_bus
        self._poweroff = poweroff or self._system_poweroff
        self._clock = clock or time.monotonic
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._dev = None
        self._reading = None
        self._failures = 0
        self._guard = None
        self.available = False
        self._mock = os.environ.get(self.MOCK_ENV, '') == '1'
        self._mock_start = time.time()

    # ── config ─────────────────────────────────────────────────────────

    def _cfg(self):
        return getattr(self.shared_data, 'config', None) or {}

    def enabled(self):
        cfg = self._cfg()
        # The CardputerZero has its own fuel gauge and a busy I2C bus of its own.
        if cfg.get('epd_type') == 'st7789v2':
            return False
        return bool(cfg.get('hg_hat_monitor', True))

    def lowbatt_threshold(self):
        """Shutdown threshold in %, or None when low-battery shutdown is off."""
        cfg = self._cfg()
        if not cfg.get('hg_hat_lowbatt_shutdown', True):
            return None
        try:
            pct = int(cfg.get('hg_hat_lowbatt_percent', DEFAULT_LOWBATT_PERCENT))
        except (TypeError, ValueError):
            pct = DEFAULT_LOWBATT_PERCENT
        return max(3, min(50, pct))

    # ── lifecycle ──────────────────────────────────────────────────────

    def start(self):
        if self._mock:
            self.available = True
            logger.info("HackerGadgets HAT MOCK mode active (HG_HAT_MOCK=1)")
            return
        if not self.enabled():
            logger.info("HackerGadgets HAT monitor disabled (hg_hat_monitor=false)")
            return
        self._thread = threading.Thread(target=self._run, name="hg-hat", daemon=True)
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
        """True when the HAT answers. Keeps the bus open for polling."""
        dev = None
        try:
            dev = self._opener(self.bus)
            if signature_ok(dev.read(HAT_ADDRESS, REG_SIGNATURE, 1)[0]) \
                    and decode_power_block(dev.read(HAT_ADDRESS, REG_POWER_BLOCK, 6)) is not None:
                self._dev = dev
                return True
        except Exception:
            pass
        if dev is not None:
            try:
                dev.close()
            except Exception:
                pass
        return False

    def poll(self):
        """Take one sample. Returns True on success."""
        if self._dev is None:
            return False
        reading = None
        try:
            reading = decode_power_block(self._dev.read(HAT_ADDRESS, REG_POWER_BLOCK, 6))
        except Exception as e:
            reading = None
            err = e
        else:
            err = "implausible power block"
        if reading is None:
            self._failures += 1
            if self._failures >= MAX_FAILURES and self.available:
                logger.warning(f"HackerGadgets HAT stopped answering ({err}) - battery reading dropped")
                with self._lock:
                    self.available = False
                    self._reading = None
            return False
        self._failures = 0
        with self._lock:
            self._reading = reading
            self.available = True
        self._check_low_battery(reading)
        return True

    def _check_low_battery(self, reading):
        threshold = self.lowbatt_threshold()
        if threshold is None:
            self._guard = None
            return
        if self._guard is None or self._guard.threshold != threshold:
            self._guard = LowBatteryGuard(threshold)
        if self._guard.observe(reading, self._clock()):
            logger.critical(
                f"Battery at {reading['soc']}% ({reading['voltage']:.2f} V) on battery power for "
                f"{LOWBATT_CONFIRM_SECONDS} s, below {threshold}% - shutting down cleanly")
            try:
                self._poweroff()
            except Exception as e:
                logger.error(f"Low-battery shutdown failed: {e}")

    @staticmethod
    def _system_poweroff():
        subprocess.run(['systemctl', 'poweroff'], timeout=60, check=False)

    def _ensure_system_setup(self):
        """First sighting on this box: install the RTC overlay and power-off hook.

        Covers fresh installs, where I2C only comes up after the installer's
        reboot, so the installer itself could not see the HAT yet.
        """
        if self._mock or os.path.exists(POWEROFF_HOOK) or not os.path.isfile(SETUP_SCRIPT):
            return
        if os.geteuid() != 0:
            return
        try:
            out = subprocess.run(['bash', SETUP_SCRIPT], capture_output=True, text=True, timeout=120)
            for line in (out.stdout or '').splitlines():
                if line.strip():
                    logger.info(line.strip())
        except Exception as e:
            logger.warning(f"HackerGadgets HAT system setup did not run: {e}")

    def _run(self):
        # Fixed hardware: if it is not there shortly after boot it is not coming.
        for attempt in range(4):
            if self._stop_event.is_set():
                return
            if self.probe():
                break
            self._stop_event.wait(5 * (attempt + 1))
        else:
            logger.info("No HackerGadgets Pwnagotchi HAT on I2C - its battery monitor is idle")
            return
        self.poll()
        r = self.get_reading()
        if r:
            logger.info(f"{MODEL} detected at 0x{HAT_ADDRESS:02x}: {r['voltage']:.2f} V, {r['soc']}%, "
                        f"{'charger connected' if r['adapter'] else 'on battery'}, USB {r['usb_mode']}")
        self._ensure_system_setup()
        while not self._stop_event.wait(POLL_SECONDS):
            self.poll()

    # ── mock (drains then charges over ~2 min) ─────────────────────────

    def _mock_reading(self):
        t = time.time() - self._mock_start
        soc = int(round(55 + 40 * math.sin(t * math.pi / 60)))
        adapter = math.cos(t * math.pi / 60) > 0
        return {'voltage': 3.3 + soc / 100.0 * 0.9, 'charging': adapter and soc < 100,
                'usb_mode': 'hub', 'soc': soc, 'adapter': adapter}

    # ── public getters (same shape as PiSugarButtonListener) ───────────

    def get_reading(self):
        if self._mock:
            return self._mock_reading()
        with self._lock:
            return dict(self._reading) if self.available and self._reading else None

    def get_battery_voltage(self):
        """Battery voltage in volts, or None."""
        r = self.get_reading()
        return r['voltage'] if r else None

    def get_battery_level(self):
        """The controller's state of charge, 0..100, or None."""
        r = self.get_reading()
        return float(r['soc']) if r else None

    def is_charging(self):
        """True while a charger is connected (charging or topped up)."""
        r = self.get_reading()
        return r['adapter'] if r else None

    def get_usb_mode(self):
        """'hub' or 'otg' (the HAT's USB slide switch), or None."""
        r = self.get_reading()
        return r['usb_mode'] if r else None

    def get_model(self):
        return MODEL


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if '--detect' in argv:
        return 0 if detect() else 1
    mon = HgHatMonitor()
    if mon._mock:
        mon.start()
    elif not (mon.probe() and mon.poll()):
        print("No HackerGadgets Pwnagotchi HAT found on I2C bus 1 (is I2C enabled?)")
        return 1
    r = mon.get_reading()
    state = "charger connected" if r['adapter'] else "on battery"
    if r['adapter'] and r['charging']:
        state += ", charging"
    print(f"{MODEL}: {r['soc']}% ({r['voltage']:.2f} V, {state}, USB {r['usb_mode']})")
    mon.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
