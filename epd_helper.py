# epd_helper.py

import errno
import importlib
import logging
import os
import time

logger = logging.getLogger(__name__)

# Known EPD types to try during auto-detection (most common first)
KNOWN_EPD_TYPES = [
    "epd2in13_V4",
    "epd2in13_V3",
    "epd2in13_V2",
    "epd2in7_V2",
    "epd2in7",
    "epd2in13",
    "epd2in9_V2",
    "epd3in7",
    "epd4in26",
    "gc9a01",
    "st7735s",
    "whisplay",
    "ssd1306",
    "max7219_4panel",
    "max7219_8panel",
]

# Kernel drivers that may legitimately own spi0.0 for an e-paper HAT.
_SPIDEV_DRIVERS = {"spidev"}


def spi_bus_conflict(bus_dev="spi0.0"):
    """Describe a kernel driver that owns the e-paper SPI device, or None.

    A TFT overlay (e.g. ``dtoverlay=tft35a`` for the MPI3501) binds fbtft to
    spi0.0 and claims the RST/DC/BUSY GPIOs the e-paper HAT uses, so every EPD
    driver fails with 'GPIO busy'. Returns None when the bus is free or the
    board has no such SPI device (non-Pi hosts).
    """
    driver_link = f"/sys/bus/spi/devices/{bus_dev}/driver"
    try:
        driver = os.path.basename(os.readlink(driver_link))
    except OSError:
        return None
    if driver in _SPIDEV_DRIVERS:
        return None
    return (
        f"{bus_dev} is owned by kernel driver '{driver}' (a TFT/LCD overlay in "
        "/boot/firmware/config.txt, e.g. dtoverlay=tft35a). Remove the overlay "
        "(scripts/uninstall_tft35_kiosk.sh does this for the MPI3501) and reboot "
        "to use an e-paper display."
    )


def is_resource_error(exc):
    """True when an EPD load failed because the kernel reports the GPIO/SPI
    lines as held by another driver (EBUSY). Probing other drivers cannot
    succeed in that state. gpiozero's in-process "already in use" is not
    counted: it can come from our own earlier probe."""
    if isinstance(exc, OSError) and exc.errno == errno.EBUSY:
        return True
    text = str(exc).lower()
    return "gpio busy" in text or "resource busy" in text


class EPDHelper:
    def __init__(self, epd_type):
        self.epd_type = epd_type
        self.epd = self._load_epd_module()

    def _load_epd_module(self):
        try:
            epd_module_name = f'resources.waveshare_epd.{self.epd_type}'
            epd_module = importlib.import_module(epd_module_name)
            return epd_module.EPD()
        except ImportError as e:
            logger.error(f"EPD module {self.epd_type} not found: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading EPD module {self.epd_type}: {e}")
            raise

    def init_full_update(self):
        try:
            if hasattr(self.epd, 'FULL_UPDATE'):
                self.epd.init(self.epd.FULL_UPDATE)
            elif hasattr(self.epd, 'lut_full_update'):
                self.epd.init(self.epd.lut_full_update)
            else:
                self.epd.init()
            logger.info("EPD full update initialization complete.")
        except Exception as e:
            logger.error(f"Error initializing EPD for full update: {e}")
            raise

    def init_partial_update(self):
        try:
            if hasattr(self.epd, 'PART_UPDATE'):
                self.epd.init(self.epd.PART_UPDATE)
            elif hasattr(self.epd, 'lut_partial_update'):
                self.epd.init(self.epd.lut_partial_update)
            else:
                self.epd.init()
            logger.info("EPD partial update initialization complete.")
        except Exception as e:
            logger.error(f"Error initializing EPD for partial update: {e}")
            raise

    def display_partial(self, image):
        try:
            imw, imh = image.size
            epd_w, epd_h = self.epd.width, self.epd.height

            # Ensure image matches EPD dimensions before sending to driver
            # Allow swapped dimensions (90°/270° rotation) — getbuffer handles both orientations
            if (imw != epd_w or imh != epd_h) and (imw != epd_h or imh != epd_w):
                logger.warning(f"Image size {imw}x{imh} != EPD size {epd_w}x{epd_h}, resizing")
                image = image.resize((epd_w, epd_h))

            buf = self.epd.getbuffer(image)

            if hasattr(self.epd, 'displayPartial'):
                self.epd.displayPartial(buf)
            elif hasattr(self.epd, 'display_Partial'):
                import inspect
                sig = inspect.signature(self.epd.display_Partial)
                if len(sig.parameters) >= 5:
                    # V2-style: display_Partial(image, Xstart, Ystart, Xend, Yend)
                    self.epd.display_Partial(buf, 0, 0, epd_w, epd_h)
                else:
                    self.epd.display_Partial(buf)
            else:
                self.epd.display(buf)
            logger.info("Partial display update complete.")
        except Exception as e:
            logger.error(f"Error during partial display update: {e} (image={image.size if hasattr(image,'size') else '?'}, epd={self.epd.width}x{self.epd.height}, buf_len={len(buf) if 'buf' in dir() else '?'})")
            raise

    def clear(self):
        try:
            self.epd.Clear()
            logger.info("EPD cleared.")
        except Exception as e:
            logger.error(f"Error clearing EPD: {e}")
            raise

    def display_full(self, image):
        """Display image on EPD using full update."""
        try:
            self.epd.display(self.epd.getbuffer(image))
            logger.info("Full display update complete.")
        except Exception as e:
            logger.error(f"Error during full display update: {e}")
            raise

    def sleep(self):
        """Put EPD to sleep mode."""
        try:
            self.epd.sleep()
            logger.info("EPD sleep mode activated.")
        except Exception as e:
            logger.error(f"Error putting EPD to sleep: {e}")
            raise

    @staticmethod
    def auto_detect(known_types=None):
        """Try each known EPD driver and return the first that initializes successfully.

        Returns:
            tuple: (epd_type_string, width, height) on success, or None if no display detected.
        """
        if known_types is None:
            known_types = KNOWN_EPD_TYPES

        conflict = spi_bus_conflict()
        if conflict:
            logger.error(f"Auto-detect skipped: {conflict}")
            return None

        for epd_type in known_types:
            try:
                logger.info(f"Auto-detect: trying {epd_type}...")
                helper = EPDHelper(epd_type)
                helper.epd.init()
                w, h = helper.epd.width, helper.epd.height
                try:
                    helper.epd.sleep()
                except Exception:
                    pass
                time.sleep(0.3)
                logger.info(f"Auto-detect: found {epd_type} ({w}x{h})")
                return (epd_type, w, h)
            except Exception as e:
                logger.debug(f"Auto-detect: {epd_type} failed: {e}")
                try:
                    helper.epd.sleep()
                except Exception:
                    pass
                if is_resource_error(e):
                    # Every other driver would hit the same held lines.
                    logger.error(f"Auto-detect aborted: e-paper GPIO/SPI lines are in use ({e})")
                    return None
                time.sleep(0.3)
        logger.warning("Auto-detect: no e-paper display detected")
        return None