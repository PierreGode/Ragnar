# whisplay.py
# Driver for the PiSugar Whisplay HAT: 1.69" ST7789 240x280 colour TFT LCD
# with an RGB status LED and a push button.
#
# Exposes the same interface as Waveshare e-Paper drivers so it integrates
# transparently with EPDHelper and the rest of Ragnar:
#   width, height, init(), Clear(), getbuffer(image), display(buf),
#   displayPartial(buf), sleep()
#
# Wiring is fixed by the HAT (BCM numbering):
#   SPI0: MOSI GPIO10 (pin 19), SCLK GPIO11 (pin 23), CS GPIO8 / CE0 (pin 24)
#   DC   GPIO27 (pin 13)
#   RST  GPIO4  (pin 7)
#   BL   GPIO22 (pin 15)  — active LOW
#   RGB LED: R GPIO25 (pin 22), G GPIO24 (pin 18), B GPIO23 (pin 16) — active LOW
#   Button: GPIO17 (pin 11) — not used by this driver
#
# The ST7789 controller RAM is 240x320; the 280-line panel occupies rows
# 20..299 in this orientation, hence the +20 row offset in _set_window.

import logging
import time
import struct

logger = logging.getLogger(__name__)

EPD_WIDTH  = 240
EPD_HEIGHT = 280
ROW_OFFSET = 20

RST_PIN   = 4
DC_PIN    = 27
CS_PIN    = 8
BL_PIN    = 22   # active low
LED_R_PIN = 25   # active low
LED_G_PIN = 24   # active low
LED_B_PIN = 23   # active low

SPI_BUS    = 0
SPI_DEVICE = 0
SPI_MAX_HZ = 40_000_000


class EPD:
    """Whisplay HAT 1.69\" ST7789 240x280 TFT LCD driver with EPD-compatible interface."""

    def __init__(self):
        self.width  = EPD_WIDTH
        self.height = EPD_HEIGHT
        self._spi  = None
        self._gpio = {}
        self._rgb  = {}
        self._initialized = False

    # ------------------------------------------------------------------
    # Public EPD-compatible interface
    # ------------------------------------------------------------------

    def init(self, *args):
        """Initialise SPI, GPIO and the ST7789 controller.

        This is called every display loop iteration for e-Paper partial-update
        compatibility.  We only run the full hardware setup + reset sequence
        once to avoid the blank flash that a reset causes on every frame.
        """
        if self._initialized:
            return  # Already running — skip reset/reinit entirely
        self._setup_hardware()
        self._reset()
        self._send_init_sequence()
        self._initialized = True
        logger.info("Whisplay ST7789 initialised (%dx%d)", self.width, self.height)

    def Clear(self, color=0xFFFF):
        """Fill the entire display with a solid RGB565 colour (default white)."""
        if not self._initialized:
            self.init()
        hi = (color >> 8) & 0xFF
        lo = color & 0xFF
        buf = bytes([hi, lo]) * (self.width * self.height)
        self._set_window(0, 0, self.width - 1, self.height - 1)
        self._write_data_bulk(buf)
        logger.info("Whisplay cleared")

    def getbuffer(self, image):
        """Convert a PIL image (any mode) to a packed RGB565 byte string.

        Ragnar renders 1-bit ('1') PIL images internally.  This converts
        any PIL mode to 16-bit RGB565 for the TFT.
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
        """Enter sleep mode and turn off backlight."""
        self._write_cmd(0x10)   # SLPIN
        time.sleep(0.005)
        if "bl" in self._gpio:
            self._gpio["bl"].off()
        logger.info("Whisplay sleeping")

    def set_rgb(self, r, g, b):
        """Set the HAT's RGB status LED (0-255 per channel). Best-effort."""
        try:
            for name, val in (("r", r), ("g", g), ("b", b)):
                led = self._rgb.get(name)
                if led is not None:
                    led.value = max(0, min(255, val)) / 255.0
        except Exception as e:
            logger.debug("Whisplay RGB LED set failed: %s", e)

    # ------------------------------------------------------------------
    # Hardware helpers
    # ------------------------------------------------------------------

    def _setup_hardware(self):
        if self._spi is not None:
            # Already initialised — don't try to reclaim GPIO pins that are
            # still held by gpiozero from the first call.  init() is called
            # every display loop iteration (for e-Paper partial update compat)
            # so we must guard against double-setup here.
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
            # Backlight is active-low on the Whisplay HAT
            self._gpio["bl"]  = gpiozero.LED(BL_PIN, active_high=False)
            self._gpio["bl"].on()
        except Exception as e:
            logger.error("Whisplay hardware setup failed: %s", e)
            raise

        # RGB status LED (active low). Purely cosmetic — never let a failure
        # here (pin claimed, no PWM support, ...) take the display down.
        try:
            import gpiozero
            self._rgb["r"] = gpiozero.PWMLED(LED_R_PIN, active_high=False)
            self._rgb["g"] = gpiozero.PWMLED(LED_G_PIN, active_high=False)
            self._rgb["b"] = gpiozero.PWMLED(LED_B_PIN, active_high=False)
            self.set_rgb(0, 0, 0)
        except Exception as e:
            self._rgb = {}
            logger.debug("Whisplay RGB LED unavailable: %s", e)

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
        self._write_cmd(0x2A)   # CASET
        self._write_data(struct.pack(">HH", x0, x1))
        self._write_cmd(0x2B)   # RASET — panel starts at row 20 of controller RAM
        self._write_data(struct.pack(">HH", y0 + ROW_OFFSET, y1 + ROW_OFFSET))
        self._write_cmd(0x2C)   # RAMWR

    def _send_init_sequence(self):
        """ST7789 power-on initialisation sequence (from the PiSugar
        WhisPlayBoard reference driver)."""
        self._write_cmd(0x11)   # SLPOUT
        time.sleep(0.12)

        self._write_cmd(0x36)   # MADCTL — memory access / scan direction
        self._write_data(0xC0)  # portrait (240 wide x 280 tall), RGB order

        self._write_cmd(0x3A)   # COLMOD — pixel format
        self._write_data(0x05)  # 16-bit RGB565

        self._write_cmd(0xB2)   # Porch setting
        self._write_data([0x0C, 0x0C, 0x00, 0x33, 0x33])

        self._write_cmd(0xB7)   # Gate control
        self._write_data(0x35)

        self._write_cmd(0xBB)   # VCOM setting
        self._write_data(0x32)

        self._write_cmd(0xC2)   # VDV and VRH command enable
        self._write_data(0x01)

        self._write_cmd(0xC3)   # VRH set
        self._write_data(0x15)

        self._write_cmd(0xC4)   # VDV set
        self._write_data(0x20)

        self._write_cmd(0xC6)   # Frame rate control
        self._write_data(0x0F)

        self._write_cmd(0xD0)   # Power control 1
        self._write_data([0xA4, 0xA1])

        self._write_cmd(0xE0)   # Positive gamma
        self._write_data([0xD0, 0x08, 0x0E, 0x09, 0x09, 0x05, 0x31,
                          0x33, 0x48, 0x17, 0x14, 0x15, 0x31, 0x34])

        self._write_cmd(0xE1)   # Negative gamma
        self._write_data([0xD0, 0x08, 0x0E, 0x09, 0x09, 0x15, 0x31,
                          0x33, 0x48, 0x17, 0x14, 0x15, 0x31, 0x34])

        self._write_cmd(0x21)   # INVON
        self._write_cmd(0x29)   # DISPON
        time.sleep(0.02)
