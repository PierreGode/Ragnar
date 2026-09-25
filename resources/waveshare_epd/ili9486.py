# ili9486.py
# Driver for generic 3.5" SPI TFT panels built on the ILI9486 (and, optionally,
# the ILI9488) controller — e.g. the Waveshare 3.5" RPi LCD (C), the red
# "MHS-3.5"/"XPT2046" boards, and most 320x480 SPI TFT HATs.
#
# It exposes the same interface as the Waveshare e-Paper drivers so it plugs
# transparently into EPDHelper and the rest of Ragnar:
#   width, height, init(), Clear(), getbuffer(image), display(buf),
#   displayPartial(buf), sleep()
#
# Ragnar renders its dashboard as a 1-bit ('1') PIL image; getbuffer() converts
# that to the panel's native pixel format (RGB565 for ILI9486, RGB666 for
# ILI9488), so the classic black-on-white character screen shows up on the TFT.
#
# ─────────────────────────────────────────────────────────────────────────────
# IMPORTANT — which 3.5" board do you have?
#   This is a *pure userspace SPI* driver. It works on boards where the ILI9486
#   is reachable directly over SPI0 with RST/DC/BL GPIOs (Waveshare 3.5" "C",
#   MHS-3.5, most generic ILI9486/ILI9488 HATs).
#
#   The older Waveshare 3.5" RPi LCD (A/B) drives the ILI9486 through a
#   16-bit shift-register arrangement and can ONLY be used via the vendor
#   fbtft/LCD-show framebuffer overlay (/dev/fb1) — this SPI driver will show a
#   blank or garbled panel on those. For that board, install LCD-show and point
#   a framebuffer/kiosk at the TFT instead.
#
# ─────────────────────────────────────────────────────────────────────────────
# Wiring (Raspberry Pi 40-pin header — matches most 3.5" SPI TFT HATs):
#   VCC  → 5V (most 3.5" HATs are 5V-powered with an onboard regulator)
#   GND  → GND
#   DIN  → GPIO10 / MOSI  (SPI0, pin 19)
#   CLK  → GPIO11 / SCLK  (SPI0, pin 23)
#   CS   → GPIO8  / CE0   (pin 24)
#   DC   → GPIO24         (pin 18)   [override: RAGNAR_TFT_DC_PIN]
#   RST  → GPIO25         (pin 22)   [override: RAGNAR_TFT_RST_PIN]
#   BL   → GPIO18         (pin 12)   [override: RAGNAR_TFT_BL_PIN, -1 = none]
#
# Every board wires DC/RST/BL slightly differently. If the panel stays dark or
# shows noise, the pins are the first thing to check — override them with the
# environment variables noted above (also settable in Ragnar's .env), no code
# edit required. Other tunables:
#   RAGNAR_TFT_CONTROLLER  ili9486 (default) | ili9488
#   RAGNAR_TFT_WIDTH       panel width  (default 320)
#   RAGNAR_TFT_HEIGHT      panel height (default 480)
#   RAGNAR_TFT_MADCTL      memory-access/scan byte (default 0x48; try 0x28/0x88/0xE8)
#   RAGNAR_TFT_SPI_HZ      SPI clock in Hz (default 16000000; lower if unstable)
#   RAGNAR_TFT_INVERT      1 = INVON, 0 = INVOFF (default 0)

import logging
import os
import time
import struct

logger = logging.getLogger(__name__)


def _env_int(name, default):
    """Read an integer env override, accepting 0x-prefixed hex. Falls back to
    `default` on anything unparseable so a typo never crashes the driver."""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(str(raw).strip(), 0)
    except (TypeError, ValueError):
        logger.warning("Ignoring bad %s=%r, using default %r", name, raw, default)
        return default


CONTROLLER = (os.environ.get("RAGNAR_TFT_CONTROLLER") or "ili9486").strip().lower()

LCD_WIDTH  = _env_int("RAGNAR_TFT_WIDTH", 320)
LCD_HEIGHT = _env_int("RAGNAR_TFT_HEIGHT", 480)

RST_PIN = _env_int("RAGNAR_TFT_RST_PIN", 25)
DC_PIN  = _env_int("RAGNAR_TFT_DC_PIN", 24)
BL_PIN  = _env_int("RAGNAR_TFT_BL_PIN", 18)   # -1 disables backlight control

SPI_BUS    = 0
SPI_DEVICE = 0
SPI_MAX_HZ = _env_int("RAGNAR_TFT_SPI_HZ", 16_000_000)

# MADCTL (0x36): memory access control / scan direction + colour order. 0x48 is
# portrait (MX set) with BGR order, correct for most 320x480 ILI9486 HATs.
MADCTL = _env_int("RAGNAR_TFT_MADCTL", 0x48)
INVERT = _env_int("RAGNAR_TFT_INVERT", 0)


class EPD:
    """ILI9486/ILI9488 3.5\" 320x480 SPI TFT driver with an EPD-compatible interface."""

    def __init__(self):
        self.width  = LCD_WIDTH
        self.height = LCD_HEIGHT
        self.controller = CONTROLLER if CONTROLLER in ("ili9486", "ili9488") else "ili9486"
        # ILI9488 cannot do 16-bit pixels over SPI — it needs 18-bit RGB666
        # (3 bytes/pixel). ILI9486 uses 16-bit RGB565 (2 bytes/pixel).
        self._bpp = 3 if self.controller == "ili9488" else 2
        self._spi  = None
        self._gpio = {}
        self._initialized = False

    # ------------------------------------------------------------------
    # Public EPD-compatible interface
    # ------------------------------------------------------------------

    def init(self, *args):
        """Initialise SPI, GPIO and the TFT controller.

        Called every display-loop iteration for e-Paper partial-update
        compatibility, so the full reset + init sequence only runs once to
        avoid re-flashing the panel on every frame.
        """
        if self._initialized:
            return
        self._setup_hardware()
        self._reset()
        self._send_init_sequence()
        self._initialized = True
        logger.info("%s initialised (%dx%d, %d bpp)",
                    self.controller.upper(), self.width, self.height, self._bpp * 8)

    def Clear(self, color=0xFFFF):
        """Fill the entire display with a solid colour (default white)."""
        if not self._initialized:
            self.init()
        if self._bpp == 2:
            px = bytes([(color >> 8) & 0xFF, color & 0xFF])
        else:
            # RGB666: expand the 565 fill to three 6-bit channels.
            r = ((color >> 11) & 0x1F) << 3
            g = ((color >> 5) & 0x3F) << 2
            b = (color & 0x1F) << 3
            px = bytes([r & 0xFC, g & 0xFC, b & 0xFC])
        buf = px * (self.width * self.height)
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._write_data_bulk(buf)
        logger.info("%s cleared", self.controller.upper())

    def getbuffer(self, image):
        """Convert a PIL image (any mode) to the panel's packed pixel bytes.

        Ragnar renders 1-bit ('1') PIL images internally; this converts any PIL
        mode to RGB565 (ILI9486) or RGB666 (ILI9488), resizing to the panel
        size if needed. Uses numpy when available for speed (320x480 is ~154k
        pixels — a pure-Python loop is the fallback)."""
        img = image.convert("RGB")

        if img.width != self.width or img.height != self.height:
            logger.warning(
                "Image size %dx%d → resizing to %dx%d",
                img.width, img.height, self.width, self.height,
            )
            img = img.resize((self.width, self.height))

        try:
            import numpy as np
            arr = np.asarray(img, dtype=np.uint16)  # (H, W, 3)
            r = arr[:, :, 0]
            g = arr[:, :, 1]
            b = arr[:, :, 2]
            if self._bpp == 2:
                rgb565 = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
                out = np.empty((rgb565.size, 2), dtype=np.uint8)
                out[:, 0] = (rgb565 >> 8).ravel() & 0xFF
                out[:, 1] = rgb565.ravel() & 0xFF
                return out.tobytes()
            # RGB666 — high 6 bits of each channel, one byte each.
            out = np.empty((r.size, 3), dtype=np.uint8)
            out[:, 0] = r.ravel().astype(np.uint8) & 0xFC
            out[:, 1] = g.ravel().astype(np.uint8) & 0xFC
            out[:, 2] = b.ravel().astype(np.uint8) & 0xFC
            return out.tobytes()
        except Exception:
            pass  # numpy missing or failed — fall back to the pure-Python path

        pixels = img.getdata()
        buf = bytearray(self.width * self.height * self._bpp)
        idx = 0
        if self._bpp == 2:
            for r, g, b in pixels:
                rgb565 = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
                buf[idx]     = (rgb565 >> 8) & 0xFF
                buf[idx + 1] = rgb565 & 0xFF
                idx += 2
        else:
            for r, g, b in pixels:
                buf[idx]     = r & 0xFC
                buf[idx + 1] = g & 0xFC
                buf[idx + 2] = b & 0xFC
                idx += 3
        return bytes(buf)

    def display(self, buf):
        """Write a full-screen pixel buffer to the display."""
        if not self._initialized:
            self.init()
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._write_data_bulk(buf)

    def displayPartial(self, buf):
        """TFT supports instant full-frame updates; treated same as display()."""
        self.display(buf)

    def sleep(self):
        """Enter sleep mode and turn off the backlight."""
        try:
            self._write_cmd(0x28)   # DISPOFF
            self._write_cmd(0x10)   # SLPIN
            time.sleep(0.005)
        except Exception:
            pass
        if "bl" in self._gpio:
            self._gpio["bl"].off()
        logger.info("%s sleeping", self.controller.upper())

    # ------------------------------------------------------------------
    # Hardware helpers
    # ------------------------------------------------------------------

    def _setup_hardware(self):
        if self._spi is not None:
            # init() runs every display-loop iteration; don't reclaim GPIO pins
            # already held by gpiozero from the first call.
            return
        try:
            import spidev
            import gpiozero

            self._spi = spidev.SpiDev()
            self._spi.open(SPI_BUS, SPI_DEVICE)
            self._spi.max_speed_hz = SPI_MAX_HZ
            self._spi.mode = 0

            self._gpio["rst"] = gpiozero.LED(RST_PIN)
            self._gpio["dc"]  = gpiozero.LED(DC_PIN)
            if BL_PIN is not None and BL_PIN >= 0:
                self._gpio["bl"] = gpiozero.LED(BL_PIN)
                self._gpio["bl"].on()
        except Exception as e:
            logger.error("%s hardware setup failed: %s", self.controller.upper(), e)
            raise

    def _reset(self):
        self._gpio["rst"].on()
        time.sleep(0.02)
        self._gpio["rst"].off()
        time.sleep(0.02)
        self._gpio["rst"].on()
        time.sleep(0.15)

    def _write_cmd(self, cmd):
        self._gpio["dc"].off()
        self._spi.writebytes([cmd])

    def _write_data(self, data):
        self._gpio["dc"].on()
        if isinstance(data, int):
            self._spi.writebytes([data])
        else:
            self._spi.writebytes(list(data))

    def _write_data_bulk(self, data):
        """Write large payloads in chunks to avoid spidev buffer limits."""
        self._gpio["dc"].on()
        chunk = 4096
        view = memoryview(data) if not isinstance(data, memoryview) else data
        for i in range(0, len(view), chunk):
            self._spi.writebytes2(view[i : i + chunk])

    def _set_window(self, x0, y0, x1, y1):
        self._write_cmd(0x2A)   # CASET (column)
        self._write_data(struct.pack(">HH", x0, x1))
        self._write_cmd(0x2B)   # PASET (page/row)
        self._write_data(struct.pack(">HH", y0, y1))
        self._write_cmd(0x2C)   # RAMWR

    def _send_init_sequence(self):
        """ILI9486/ILI9488 power-on initialisation.

        Common sequence proven against Waveshare 3.5" (C) and generic
        ILI9486/9488 SPI HATs. COLMOD and the gamma tables differ per
        controller; everything else is shared.
        """
        self._write_cmd(0x11)   # SLPOUT
        time.sleep(0.02)

        # COLMOD — pixel format. 0x55 = 16-bit (ILI9486); 0x66 = 18-bit (ILI9488).
        self._write_cmd(0x3A)
        self._write_data(0x66 if self.controller == "ili9488" else 0x55)

        self._write_cmd(0xC0)   # Power Control 1
        self._write_data([0x0E, 0x0E])
        self._write_cmd(0xC1)   # Power Control 2
        self._write_data([0x41, 0x00])
        self._write_cmd(0xC5)   # VCOM Control
        self._write_data([0x00, 0x22, 0x80])

        self._write_cmd(0x36)   # MADCTL — memory access / scan direction
        self._write_data(MADCTL)

        self._write_cmd(0xB1)   # Frame rate
        self._write_data([0xB0, 0x11])
        self._write_cmd(0xB4)   # Display inversion control
        self._write_data(0x02)
        self._write_cmd(0xB6)   # Display function control
        self._write_data([0x02, 0x02, 0x3B])

        if self.controller == "ili9488":
            self._write_cmd(0xE0)   # Positive gamma (ILI9488)
            self._write_data([0x00, 0x03, 0x09, 0x08, 0x16, 0x0A, 0x3F, 0x78,
                              0x4C, 0x09, 0x0A, 0x08, 0x16, 0x1A, 0x0F])
            self._write_cmd(0xE1)   # Negative gamma (ILI9488)
            self._write_data([0x00, 0x16, 0x19, 0x03, 0x0F, 0x05, 0x32, 0x45,
                              0x46, 0x04, 0x0E, 0x0D, 0x35, 0x37, 0x0F])
        else:
            self._write_cmd(0xE0)   # Positive gamma (ILI9486)
            self._write_data([0x0F, 0x1F, 0x1C, 0x0C, 0x0F, 0x08, 0x48, 0x98,
                              0x37, 0x0A, 0x13, 0x04, 0x11, 0x0D, 0x00])
            self._write_cmd(0xE1)   # Negative gamma (ILI9486)
            self._write_data([0x0F, 0x32, 0x2E, 0x0B, 0x0D, 0x05, 0x47, 0x75,
                              0x37, 0x06, 0x10, 0x03, 0x24, 0x20, 0x00])

        self._write_cmd(0x21 if INVERT else 0x20)   # INVON / INVOFF

        self._write_cmd(0x11)   # SLPOUT
        time.sleep(0.15)
        self._write_cmd(0x29)   # DISPON
        time.sleep(0.02)
