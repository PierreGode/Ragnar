# st7789v2.py
# Driver for the M5Stack CardputerZero's built-in 1.9" ST7789V3 LCD (170x320,
# used in landscape as 320x170; the module name keeps the historical "v2" —
# V2/V3 share the register set this driver uses). Exposes the same interface as the Waveshare
# e-Paper drivers so it integrates transparently with EPDHelper and the rest of
# Ragnar:
#   width, height, init(), Clear(), getbuffer(image), display(buf),
#   displayPartial(buf), sleep()
#
# The CardputerZero is a Raspberry Pi Compute Module Zero (BCM2837) box, so
# Ragnar runs on it like any other Pi. Only the built-in display and 46-key
# keyboard are board-specific; the keyboard is handled separately by
# cardputer_input.py (TCA8418 I2C matrix), not here.
#
# ─────────────────────────────────────────────────────────────────────────────
# Two transports, tried in order by init():
#
#   1. Linux framebuffer (PRIMARY).  M5Stack ships the CardputerZero as "a
#      pocket Linux computer", so its image drives the LCD as a framebuffer
#      device (typically /dev/fb1, or /dev/fb0 on a headless-image variant).
#      When one is found at ~16bpp we blit RGB565 frames straight to it. This
#      sidesteps the board's awkward wiring entirely (see below), so it is the
#      preferred path and the one most likely to work out of the box.
#
#   2. Native SPI (FALLBACK).  If no usable framebuffer exists we talk to the
#      ST7789V2 directly over SPI, the same way st7735s.py does. This path has
#      real caveats on this board and is best-effort:
#
#        * The panel CS is on GPIO25 and DC on GPIO8 (BCM). GPIO8 is SPI0's
#          hardware CE0, so we must NOT let spidev drive chip-select — we run
#          with no_cs and assert CS manually on GPIO25.
#        * RST and the backlight are behind M5Stack's M5IOE1 I2C I/O expander,
#          not on direct GPIO. We drive them through m5ioe1.py (LCD reset on
#          expander IO12, backlight on IO10/PWM4 — see the schematic): a real
#          hardware reset before the init sequence, and backlight explicitly on.
#          If the expander does not answer (e.g. framebuffer-only image), we fall
#          back to a software reset (SWRESET) and rely on the power-on backlight.
#
# Wiring (CardputerZero, BCM numbering — from M5Stack's schematic C154 V0.6.1):
#   MOSI → GPIO10 (SPI0)      SCLK → GPIO11 (SPI0)
#   CS   → GPIO25             DC   → GPIO8
#   TE   → GPIO5              RST  → M5IOE1 IO12 (PYG12_LCD_RST, active-low)
#   BL   → M5IOE1 IO10 / PWM4 (PYG10_BL_PWM)
#
# NOTE: unvalidated on real CardputerZero hardware. Offsets/MADCTL below follow
# the standard ST7789 170-wide panel geometry and may need on-device tuning.

import logging
import os
import struct
import time

logger = logging.getLogger(__name__)

# Landscape geometry used by Ragnar. Native panel is 170(w) x 320(h) portrait;
# we rotate 90° via MADCTL so the wide edge (over the keyboard) is horizontal.
LCD_WIDTH  = 320
LCD_HEIGHT = 170

# A 170-pixel-wide panel is centred in the ST7789's 240-column RAM, so its
# native column window starts at (240 - 170) / 2 = 35. Rotated into landscape
# that offset lands on the row (short) axis; the long axis fills 0..319.
NATIVE_SHORT_OFFSET = 35
NATIVE_LONG_OFFSET  = 0

CS_PIN = 25   # BCM — manual chip-select (GPIO8/CE0 is taken by DC)
DC_PIN = 8    # BCM

SPI_BUS    = 0
SPI_DEVICE = 0
SPI_MAX_HZ = 40_000_000

# MADCTL (0x36): MV|MX → 90° rotation to landscape, RGB colour order. The exact
# flip may need adjusting on hardware (try 0xA0 / 0x00 / 0xC0 if mirrored).
MADCTL = 0x60

# Framebuffer devices to probe, in order. Override with RAGNAR_CARDPUTER_FB.
_FB_CANDIDATES = ("/dev/fb1", "/dev/fb0")

# Only auto-adopt a framebuffer whose resolution matches the CardputerZero LCD
# (either orientation). Without this guard we'd happily blit Ragnar over a
# 1920x1080 HDMI console (/dev/fb0), which is exactly what we must not do. An
# explicit RAGNAR_CARDPUTER_FB override skips this check — the user knows.
_LCD_RES = frozenset({(320, 170), (170, 320)})


class EPD:
    """CardputerZero ST7789V2 LCD with an EPD-compatible interface.

    Prefers the Linux framebuffer M5Stack's image exposes; falls back to
    driving the panel directly over SPI.
    """

    def __init__(self):
        self.width  = LCD_WIDTH
        self.height = LCD_HEIGHT
        self._transport = None          # 'fb' | 'spi' | None
        # framebuffer state
        self._fb_path = None
        self._fb_w = None
        self._fb_h = None
        self._fb_bpp = 16
        # spi state
        self._spi  = None
        self._gpio = {}
        self._ioe  = None   # M5IOE1 expander (LCD reset + backlight), lazy
        self._initialized = False

    # ------------------------------------------------------------------
    # Public EPD-compatible interface
    # ------------------------------------------------------------------

    def init(self, *args):
        """Pick a transport and initialise it. Idempotent: called every
        display-loop iteration, so the one-time setup only runs once."""
        if self._initialized:
            return
        if self._init_framebuffer():
            self._transport = "fb"
            logger.info("CardputerZero: using framebuffer %s (%dx%d %dbpp)",
                        self._fb_path, self._fb_w, self._fb_h, self._fb_bpp)
        elif self._init_spi():
            self._transport = "spi"
            logger.info("CardputerZero: using native SPI (%dx%d)",
                        self.width, self.height)
        else:
            raise RuntimeError(
                "CardputerZero display: no framebuffer and SPI init failed")
        self._initialized = True

    def Clear(self, color=0xFFFF):
        """Fill the whole display with a solid RGB565 colour (default white)."""
        if not self._initialized:
            self.init()
        hi, lo = (color >> 8) & 0xFF, color & 0xFF
        buf = bytes([hi, lo]) * (self.width * self.height)
        self._blit(buf)
        logger.info("CardputerZero display cleared")

    def getbuffer(self, image):
        """Convert a PIL image (any mode) to packed RGB565 bytes at panel size."""
        img = image.convert("RGB")
        if img.width != self.width or img.height != self.height:
            logger.debug("CardputerZero: resizing %dx%d → %dx%d",
                         img.width, img.height, self.width, self.height)
            img = img.resize((self.width, self.height))

        buf = bytearray(self.width * self.height * 2)
        idx = 0
        for r, g, b in img.getdata():
            rgb565 = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
            buf[idx]     = (rgb565 >> 8) & 0xFF
            buf[idx + 1] = rgb565 & 0xFF
            idx += 2
        return bytes(buf)

    def display(self, buf):
        """Write a full-screen RGB565 buffer to the display."""
        if not self._initialized:
            self.init()
        self._blit(buf)

    def displayPartial(self, buf):
        """TFT supports instant full-frame updates; same as display()."""
        self.display(buf)

    def sleep(self):
        """Best-effort power-down. Harmless on the framebuffer path."""
        if self._transport == "spi":
            try:
                self._write_cmd(0x28)   # DISPOFF
                self._write_cmd(0x10)   # SLPIN
                time.sleep(0.005)
            except Exception:
                pass
        logger.info("CardputerZero display sleeping")

    # ------------------------------------------------------------------
    # Blit dispatch
    # ------------------------------------------------------------------

    def _blit(self, buf):
        if self._transport == "fb":
            self._fb_write(buf)
        else:
            self._spi_write_frame(buf)

    # ------------------------------------------------------------------
    # Framebuffer transport
    # ------------------------------------------------------------------

    def _init_framebuffer(self):
        override = os.environ.get("RAGNAR_CARDPUTER_FB")
        candidates = ([override] if override else []) + list(_FB_CANDIDATES)

        for path in candidates:
            if not path or not os.path.exists(path):
                continue
            geom = self._read_fb_geometry(path)
            if not geom:
                continue
            fb_w, fb_h, bpp = geom
            forced = (path == override)
            if bpp != 16:
                # We only pack RGB565; a 32bpp console fb would need BGRA
                # conversion. Skip rather than paint garbage.
                logger.info("CardputerZero: %s is %dbpp, not 16 — skipping", path, bpp)
                continue
            if not forced and (fb_w, fb_h) not in _LCD_RES:
                # Almost certainly an HDMI/console framebuffer, not the LCD —
                # never blit over it. Point users at the override if their LCD
                # fb reports a size we don't recognise.
                logger.info("CardputerZero: %s is %dx%d, not the 1.9\" LCD — "
                            "skipping (set RAGNAR_CARDPUTER_FB to force)",
                            path, fb_w, fb_h)
                continue
            self._fb_path, self._fb_w, self._fb_h, self._fb_bpp = path, fb_w, fb_h, bpp
            # Render at the framebuffer's own dimensions so no scaling is needed.
            self.width, self.height = fb_w, fb_h
            return True
        return False

    @staticmethod
    def _read_fb_geometry(path):
        """Return (width, height, bpp) for /dev/fbN via its sysfs attributes."""
        node = os.path.basename(path)
        base = f"/sys/class/graphics/{node}"
        try:
            with open(f"{base}/virtual_size") as f:
                w, h = (int(v) for v in f.read().strip().split(","))
            with open(f"{base}/bits_per_pixel") as f:
                bpp = int(f.read().strip())
            return (w, h, bpp)
        except Exception as e:
            logger.debug("CardputerZero: cannot read geometry for %s: %s", path, e)
            return None

    def _fb_write(self, buf):
        try:
            with open(self._fb_path, "wb") as fb:
                fb.write(buf)
        except Exception as e:
            logger.error("CardputerZero framebuffer write failed: %s", e)
            raise

    # ------------------------------------------------------------------
    # Native SPI transport (fallback)
    # ------------------------------------------------------------------

    def _init_spi(self):
        if not self._setup_spi_hardware():
            return False
        try:
            self._reset_panel()
            self._send_init_sequence()
            self._backlight_on()
            return True
        except Exception as e:
            logger.error("CardputerZero SPI init sequence failed: %s", e)
            return False

    def _ensure_ioe(self):
        """Lazily open the M5IOE1 expander (LCD reset + backlight). Returns the
        handle or None; failures are non-fatal (we fall back to SWRESET)."""
        if self._ioe is None:
            try:
                from m5ioe1 import M5IOE1
                self._ioe = M5IOE1()
            except Exception as e:
                logger.info("CardputerZero: M5IOE1 expander unavailable (%s); "
                            "using software reset + power-on backlight", e)
                self._ioe = False   # sentinel: tried and failed, don't retry
        return self._ioe or None

    def _reset_panel(self):
        """Hardware reset via the M5IOE1 expander if present, else SWRESET."""
        ioe = self._ensure_ioe()
        if ioe is not None and ioe.reset_lcd():
            return
        self._software_reset()

    def _backlight_on(self):
        ioe = self._ensure_ioe()
        if ioe is not None:
            ioe.backlight_on()

    def _setup_spi_hardware(self):
        if self._spi is not None:
            return True
        try:
            import spidev
            import gpiozero

            spi = spidev.SpiDev()
            spi.open(SPI_BUS, SPI_DEVICE)
            spi.max_speed_hz = SPI_MAX_HZ
            spi.mode = 0
            # DC sits on GPIO8/CE0, so spidev must not drive chip-select. We
            # assert CS ourselves on GPIO25. Not every kernel honours no_cs;
            # if it doesn't, the CE0 toggle would fight DC and this board needs
            # the framebuffer path instead.
            try:
                spi.no_cs = True
            except Exception as e:
                logger.warning("CardputerZero: spidev no_cs unsupported (%s); "
                               "SPI path may conflict with DC on CE0", e)
            self._spi = spi

            self._gpio["dc"] = gpiozero.LED(DC_PIN)
            self._gpio["cs"] = gpiozero.LED(CS_PIN)
            self._gpio["cs"].on()   # CS idle high (active-low)
            return True
        except Exception as e:
            logger.info("CardputerZero: SPI hardware unavailable: %s", e)
            return False

    def _cs_low(self):
        if "cs" in self._gpio:
            self._gpio["cs"].off()

    def _cs_high(self):
        if "cs" in self._gpio:
            self._gpio["cs"].on()

    def _software_reset(self):
        # No GPIO reset line (RST is behind the I2C expander), so use SWRESET.
        self._write_cmd(0x01)
        time.sleep(0.15)

    def _write_cmd(self, cmd):
        self._cs_low()
        self._gpio["dc"].off()
        self._spi.writebytes([cmd])
        self._cs_high()

    def _write_data(self, data):
        self._cs_low()
        self._gpio["dc"].on()
        if isinstance(data, int):
            self._spi.writebytes([data])
        else:
            self._spi.writebytes(list(data))
        self._cs_high()

    def _set_window(self, x0, y0, x1, y1):
        # Landscape: the 35px short-axis offset lands on the row (y) axis.
        cx0, cx1 = x0 + NATIVE_LONG_OFFSET,  x1 + NATIVE_LONG_OFFSET
        ry0, ry1 = y0 + NATIVE_SHORT_OFFSET, y1 + NATIVE_SHORT_OFFSET
        self._write_cmd(0x2A)   # CASET
        self._write_data(struct.pack(">HH", cx0, cx1))
        self._write_cmd(0x2B)   # RASET
        self._write_data(struct.pack(">HH", ry0, ry1))
        self._write_cmd(0x2C)   # RAMWR

    def _spi_write_frame(self, buf):
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._cs_low()
        self._gpio["dc"].on()
        chunk = 4096
        view = memoryview(buf)
        for i in range(0, len(view), chunk):
            self._spi.writebytes2(view[i:i + chunk])
        self._cs_high()

    def _send_init_sequence(self):
        """Minimal ST7789V2 power-on sequence (portrait-native, rotated by MADCTL)."""
        self._write_cmd(0x11)   # SLPOUT
        time.sleep(0.12)

        self._write_cmd(0x36)   # MADCTL — rotation / scan direction
        self._write_data(MADCTL)

        self._write_cmd(0x3A)   # COLMOD — 16-bit/pixel (RGB565)
        self._write_data(0x05)

        self._write_cmd(0x21)   # INVON — ST7789 panels are normally-inverted

        self._write_cmd(0x13)   # NORON — normal display mode
        time.sleep(0.01)
        self._write_cmd(0x29)   # DISPON
        time.sleep(0.02)
