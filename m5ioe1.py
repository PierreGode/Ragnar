# m5ioe1.py — minimal driver for the M5Stack M5IOE1 I2C I/O expander.
#
# On the CardputerZero the built-in 1.9" LCD's **reset** and **backlight** lines
# are not on Pi GPIOs — they hang off M5Stack's M5IOE1 expander (a small MCU with
# a fixed register-map firmware). This helper implements just enough of that
# register protocol to (1) pulse the LCD reset and (2) drive the backlight PWM,
# so the native-SPI display path in resources/waveshare_epd/st7789v2.py can do a
# real hardware reset and guarantee the panel is lit, instead of relying on a
# software reset + whatever the power-on backlight default happens to be.
#
# Board wiring (from the CardputerZero schematic C154 V0.6.1):
#   M5IOE1 I2C address .......... 0x4F  (on I2C bus 1: SDA=GPIO2, SCL=GPIO3)
#   LCD backlight (PYG10_BL_PWM)  expander IO10  -> PWM channel 4
#   LCD reset     (PYG12_LCD_RST) expander IO12  -> GPIO, active-low
#
# Note: the generic M5IOE1 chip manual lists 0x6F-0x76 as its configurable
# address range, but the CardputerZero board and its docs pin this unit at 0x4F.
#
# Everything is overridable via env vars (RAGNAR_M5IOE1_*) so a board revision
# that moves a pin can be corrected without a code change. If the expander does
# not ACK, every method is a harmless no-op and the caller falls back to its own
# software path — so this module can never make the display *worse* than before.
#
# Register map (M5IOE1 Chip User Manual, firmware SW:A):
#   0x03 GPIO_M_L  / 0x04 GPIO_M_H   direction   (1 = output)
#   0x05 GPIO_O_L  / 0x06 GPIO_O_H   output level (valid when direction = output)
#   0x13 GPIO_DRV_L/ 0x14 GPIO_DRV_H drive mode  (0 = push-pull, 1 = open-drain)
#   0x1B..0x22                       PWM1_L..PWM4_H (2 regs/channel from 0x1B)
#   0x25 PWM_FREQ_L/ 0x26 PWM_FREQ_H global PWM frequency (Hz, 16-bit)
#   PWMx_H bits: 7 = EN, 6 = POL (1 = active-low), [3:0] = DUTY[11:8]

import logging
import os
import time

logger = logging.getLogger(__name__)

# --- Register addresses -------------------------------------------------------
REG_GPIO_M_L   = 0x03
REG_GPIO_M_H   = 0x04
REG_GPIO_O_L   = 0x05
REG_GPIO_O_H   = 0x06
REG_GPIO_DRV_L = 0x13
REG_GPIO_DRV_H = 0x14
REG_PWM_BASE   = 0x1B   # PWM1_L; channel c (1..4) low byte at 0x1B + (c-1)*2
REG_PWM_FREQ_L = 0x25
REG_PWM_FREQ_H = 0x26

# PWMx_H bit fields
PWM_EN  = 0x80
PWM_POL = 0x40          # 1 = active-low output

# --- Board defaults (CardputerZero), all env-overridable ----------------------
DEFAULT_ADDR    = 0x4F
DEFAULT_BUS     = 1
DEFAULT_BL_PWM  = 4     # IO10 -> PWM channel 4
DEFAULT_RST_IO  = 12    # IO12, active-low
DEFAULT_BL_DUTY = 0xFFF # 12-bit, full brightness
DEFAULT_PWM_HZ  = 500


def _env_int(name, default, base=10):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw, 0) if base == 0 else int(raw, base)
    except ValueError:
        logger.warning("M5IOE1: bad %s=%r, using default %r", name, raw, default)
        return default


class M5IOE1:
    """Best-effort control of the CardputerZero LCD reset + backlight over the
    M5IOE1 expander. Constructing it probes the device; check .available."""

    def __init__(self):
        self.addr    = _env_int("RAGNAR_M5IOE1_ADDR", DEFAULT_ADDR, base=0)
        self.bus_num = _env_int("RAGNAR_M5IOE1_BUS", DEFAULT_BUS)
        self.bl_pwm  = _env_int("RAGNAR_M5IOE1_BL_PWM", DEFAULT_BL_PWM)
        self.rst_io  = _env_int("RAGNAR_M5IOE1_RST_IO", DEFAULT_RST_IO)
        self.bl_duty = _env_int("RAGNAR_M5IOE1_BL_DUTY", DEFAULT_BL_DUTY, base=0)
        self.pwm_hz  = _env_int("RAGNAR_M5IOE1_PWM_HZ", DEFAULT_PWM_HZ)
        self._bus = None
        self.available = False
        self._probe()

    # ------------------------------------------------------------------
    def _probe(self):
        try:
            import smbus2
            self._bus = smbus2.SMBus(self.bus_num)
            # UID_L (0x00) is a read-only factory id — a clean way to confirm the
            # expander is really answering at this address before we poke it.
            self._bus.read_byte_data(self.addr, 0x00)
            self.available = True
            logger.info("M5IOE1: expander present at 0x%02X on i2c-%d "
                        "(backlight PWM%d, reset IO%d)",
                        self.addr, self.bus_num, self.bl_pwm, self.rst_io)
        except FileNotFoundError:
            logger.info("M5IOE1: i2c-%d not available — LCD reset/backlight via "
                        "expander disabled", self.bus_num)
        except ImportError:
            logger.info("M5IOE1: smbus2 not installed — expander control disabled")
        except OSError as e:
            logger.info("M5IOE1: no ACK at 0x%02X (%s) — falling back to software "
                        "reset + power-on backlight", self.addr, e)
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("M5IOE1: probe failed: %s", e)

    # --- low-level helpers -------------------------------------------------
    @staticmethod
    def _gpio_regs(io):
        """Return (dir_reg, out_reg, drv_reg, bit) for expander pin IO<io>."""
        if 1 <= io <= 8:
            return REG_GPIO_M_L, REG_GPIO_O_L, REG_GPIO_DRV_L, io - 1
        if 9 <= io <= 14:
            return REG_GPIO_M_H, REG_GPIO_O_H, REG_GPIO_DRV_H, io - 9
        raise ValueError(f"M5IOE1 IO out of range: {io}")

    def _update_bit(self, reg, bit, value):
        """Read-modify-write a single bit — crucial, since these registers also
        hold the state of the board's *other* expander pins (power, peripheral
        resets). We must never clobber them."""
        cur = self._bus.read_byte_data(self.addr, reg)
        new = (cur | (1 << bit)) if value else (cur & ~(1 << bit))
        if new != cur:
            self._bus.write_byte_data(self.addr, reg, new & 0xFF)

    def _set_gpio(self, io, level):
        dir_reg, out_reg, drv_reg, bit = self._gpio_regs(io)
        self._update_bit(drv_reg, bit, False)   # push-pull (0), not open-drain
        self._update_bit(dir_reg, bit, True)    # direction = output
        self._update_bit(out_reg, bit, bool(level))

    # --- public API --------------------------------------------------------
    def reset_lcd(self):
        """Pulse the LCD reset line (active-low): high -> low -> high with the
        ST7789 datasheet-recommended settle delays. No-op if unavailable."""
        if not self.available:
            return False
        try:
            self._set_gpio(self.rst_io, 1)   # idle deasserted
            time.sleep(0.010)
            self._set_gpio(self.rst_io, 0)   # assert reset
            time.sleep(0.010)
            self._set_gpio(self.rst_io, 1)   # release
            time.sleep(0.120)
            return True
        except Exception as e:
            logger.warning("M5IOE1: LCD reset failed: %s", e)
            return False

    def backlight_on(self, duty=None):
        """Enable the backlight PWM at `duty` (0..0xFFF; default = configured
        brightness). No-op if unavailable."""
        if not self.available:
            return False
        duty = self.bl_duty if duty is None else max(0, min(0xFFF, int(duty)))
        try:
            # Global PWM frequency (shared by all channels).
            self._bus.write_byte_data(self.addr, REG_PWM_FREQ_L, self.pwm_hz & 0xFF)
            self._bus.write_byte_data(self.addr, REG_PWM_FREQ_H, (self.pwm_hz >> 8) & 0xFF)
            lo = REG_PWM_BASE + (self.bl_pwm - 1) * 2
            hi = lo + 1
            self._bus.write_byte_data(self.addr, lo, duty & 0xFF)
            # active-high (POL=0), enabled, high nibble of the 12-bit duty
            self._bus.write_byte_data(self.addr, hi, PWM_EN | ((duty >> 8) & 0x0F))
            return True
        except Exception as e:
            logger.warning("M5IOE1: backlight enable failed: %s", e)
            return False

    def backlight_off(self):
        if not self.available:
            return False
        try:
            hi = REG_PWM_BASE + (self.bl_pwm - 1) * 2 + 1
            cur = self._bus.read_byte_data(self.addr, hi)
            self._bus.write_byte_data(self.addr, hi, cur & ~PWM_EN & 0xFF)
            return True
        except Exception as e:
            logger.warning("M5IOE1: backlight off failed: %s", e)
            return False

    def close(self):
        try:
            if self._bus is not None:
                self._bus.close()
        except Exception:
            pass
        self._bus = None
        self.available = False
