# st7735s.py
# Driver for the Waveshare 1.44" LCD HAT — ST7735S 128x128 RGB TFT LCD.
#
# Exposes the same interface as the Waveshare e-Paper drivers so it integrates
# transparently with EPDHelper and the rest of Ragnar:
#   width, height, init(), Clear(), getbuffer(image), display(buf),
#   displayPartial(buf), sleep()
#
# The HAT also carries 3 push buttons and a 5-way joystick; those are handled
# separately by lcdhat_input.py, not here.
#
# Wiring (Raspberry Pi 40-pin header — fixed by the HAT):
#   VCC  → 3.3V
#   GND  → GND
#   DIN  → GPIO10 / MOSI  (SPI0)
#   CLK  → GPIO11 / SCLK  (SPI0)
#   CS   → GPIO8  / CE0
#   DC   → GPIO25
#   RST  → GPIO27
#   BL   → GPIO24 (backlight)
#
# The ST7735S RAM is 132x162; the 1.44" panel shows a 128x128 window offset by
# (1, 2), so the visible area maps to the correct RAM location.

import logging
import os
import time
import struct

logger = logging.getLogger(__name__)

LCD_WIDTH  = 128
LCD_HEIGHT = 128

# Visible-window offset into the ST7735S 132x162 RAM for this panel. The 128x128
# visible area sits a few pixels into the larger RAM, so the window must be
# shifted or the panel's far edges show unwritten RAM as a band of coloured
# noise. The right value depends on the panel batch and the MADCTL scan
# direction; override per panel with RAGNAR_ST7735S_COL_OFFSET /
# RAGNAR_ST7735S_ROW_OFFSET (decimal or 0x-hex).
def _env_int(name, default):
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw, 0)
    except (TypeError, ValueError):
        logger.warning("Invalid %s=%r; using %d", name, raw, default)
        return default


COL_OFFSET = _env_int("RAGNAR_ST7735S_COL_OFFSET", 3)
ROW_OFFSET = _env_int("RAGNAR_ST7735S_ROW_OFFSET", 3)

RST_PIN = 27
DC_PIN  = 25
BL_PIN  = 24

SPI_BUS    = 0
SPI_DEVICE = 0
SPI_MAX_HZ = 24_000_000

# MADCTL (0x36): memory access control — the scan-direction bits (MY|MX = 0xC0)
# that orient the 128x128 window. The panel's red/blue swap is handled in the
# pixel packing (see RB_SWAP), not here, because this panel ignores the MADCTL
# colour-order bit (0x08). Override per panel with RAGNAR_ST7735S_MADCTL (e.g.
# 0x08/0x48/0x88/0xE8 to change rotation/mirroring); accepts decimal or 0x-hex.
def _env_madctl(default=0xC0):
    raw = os.environ.get("RAGNAR_ST7735S_MADCTL")
    if not raw:
        return default
    try:
        return int(raw, 0) & 0xFF
    except (TypeError, ValueError):
        logger.warning("Invalid RAGNAR_ST7735S_MADCTL=%r; using 0x%02X", raw, default)
        return default


MADCTL = _env_madctl()


# Some ST7735S 1.44" panels swap red and blue no matter what the MADCTL
# colour-order bit says, so a blonde viking comes out blue. When that happens,
# swap the channels in the pixel packing instead (see getbuffer). Default on for
# this panel; set RAGNAR_ST7735S_RB_SWAP=0 for a panel that does honour MADCTL.
def _env_bool(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


RB_SWAP = _env_bool("RAGNAR_ST7735S_RB_SWAP", True)


class EPD:
    """ST7735S 1.44\" 128x128 TFT LCD driver with an EPD-compatible interface."""

    def __init__(self):
        self.width  = LCD_WIDTH
        self.height = LCD_HEIGHT
        self._spi  = None
        self._gpio = {}
        self._initialized = False

    # ------------------------------------------------------------------
    # Public EPD-compatible interface
    # ------------------------------------------------------------------

    def init(self, *args):
        """Initialise SPI, GPIO and the ST7735S controller.

        Called every display-loop iteration for e-Paper partial-update
        compatibility, so the full reset + init sequence only runs once to
        avoid a blank flash on every frame.
        """
        if self._initialized:
            return
        self._setup_hardware()
        self._reset()
        self._send_init_sequence()
        self._initialized = True
        logger.info("ST7735S initialised (%dx%d)", self.width, self.height)

    def Clear(self, color=0xFFFF):
        """Fill the entire display with a solid RGB565 colour (default white)."""
        if not self._initialized:
            self.init()
        hi = (color >> 8) & 0xFF
        lo = color & 0xFF
        buf = bytes([hi, lo]) * (self.width * self.height)
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._write_data_bulk(buf)
        logger.info("ST7735S cleared")

    def getbuffer(self, image):
        """Convert a PIL image (any mode) to a packed RGB565 byte string.

        Ragnar renders 1-bit ('1') PIL images internally; this converts any PIL
        mode to 16-bit RGB565 for the TFT, resizing to the panel size if needed.
        """
        img = image.convert("RGB")

        if img.width != self.width or img.height != self.height:
            logger.warning(
                "Image size %dx%d → resizing to %dx%d",
                img.width, img.height, self.width, self.height,
            )
            img = img.resize((self.width, self.height))

        pixels = img.getdata()
        buf = bytearray(self.width * self.height * 2)
        idx = 0
        if RB_SWAP:
            # This panel swaps red and blue regardless of the MADCTL colour-order
            # bit, so do it in the pixel packing: blue into the high (red) field,
            # red into the low (blue) field. See RB_SWAP.
            for r, g, b in pixels:
                rgb565 = ((b & 0xF8) << 8) | ((g & 0xFC) << 3) | (r >> 3)
                buf[idx]     = (rgb565 >> 8) & 0xFF
                buf[idx + 1] = rgb565 & 0xFF
                idx += 2
        else:
            for r, g, b in pixels:
                rgb565 = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
                buf[idx]     = (rgb565 >> 8) & 0xFF
                buf[idx + 1] = rgb565 & 0xFF
                idx += 2
        return bytes(buf)

    def display(self, buf):
        """Write a full-screen RGB565 buffer to the display."""
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
        logger.info("ST7735S sleeping")

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
            self._gpio["bl"]  = gpiozero.LED(BL_PIN)

            self._gpio["bl"].on()
        except Exception as e:
            logger.error("ST7735S hardware setup failed: %s", e)
            raise

    def _reset(self):
        self._gpio["rst"].on()
        time.sleep(0.1)
        self._gpio["rst"].off()
        time.sleep(0.1)
        self._gpio["rst"].on()
        time.sleep(0.12)

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
        self._write_data(struct.pack(">HH", x0 + COL_OFFSET, x1 + COL_OFFSET))
        self._write_cmd(0x2B)   # RASET (row)
        self._write_data(struct.pack(">HH", y0 + ROW_OFFSET, y1 + ROW_OFFSET))
        self._write_cmd(0x2C)   # RAMWR

    def _send_init_sequence(self):
        """ST7735S power-on initialisation (Waveshare 1.44" LCD HAT sequence)."""
        # Frame rate
        self._write_cmd(0xB1)
        self._write_data([0x01, 0x2C, 0x2D])
        self._write_cmd(0xB2)
        self._write_data([0x01, 0x2C, 0x2D])
        self._write_cmd(0xB3)
        self._write_data([0x01, 0x2C, 0x2D, 0x01, 0x2C, 0x2D])

        self._write_cmd(0xB4)   # Column inversion
        self._write_data(0x07)

        # Power sequence
        self._write_cmd(0xC0)
        self._write_data([0xA2, 0x02, 0x84])
        self._write_cmd(0xC1)
        self._write_data(0xC5)
        self._write_cmd(0xC2)
        self._write_data([0x0A, 0x00])
        self._write_cmd(0xC3)
        self._write_data([0x8A, 0x2A])
        self._write_cmd(0xC4)
        self._write_data([0x8A, 0xEE])
        self._write_cmd(0xC5)   # VCOM
        self._write_data(0x0E)

        self._write_cmd(0x36)   # MADCTL — memory access / scan direction
        self._write_data(MADCTL)

        # Positive gamma
        self._write_cmd(0xE0)
        self._write_data([0x0F, 0x1A, 0x0F, 0x18, 0x2F, 0x28, 0x20, 0x22,
                          0x1F, 0x1B, 0x23, 0x37, 0x00, 0x07, 0x02, 0x10])
        # Negative gamma
        self._write_cmd(0xE1)
        self._write_data([0x0F, 0x1B, 0x0F, 0x17, 0x33, 0x2C, 0x29, 0x2E,
                          0x30, 0x30, 0x39, 0x3F, 0x00, 0x07, 0x03, 0x10])

        self._write_cmd(0xF0)   # Enable test command
        self._write_data(0x01)
        self._write_cmd(0xF6)   # Disable RAM power-save mode
        self._write_data(0x00)

        self._write_cmd(0x3A)   # COLMOD — 16-bit/pixel (RGB565)
        self._write_data(0x05)

        self._write_cmd(0x11)   # SLPOUT
        time.sleep(0.12)
        self._write_cmd(0x29)   # DISPON
        time.sleep(0.02)
