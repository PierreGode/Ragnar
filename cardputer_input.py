# cardputer_input.py — 46-key keyboard for the M5Stack CardputerZero.
#
# The CardputerZero's keyboard is a matrix behind a TCA8418 I2C keypad
# controller (address 0x34, INT on GPIO27), not a GPIO joystick like the 1.44"
# LCD HAT. This listener reads key events off the TCA8418 and feeds them into
# the exact same page / wardriving / net-diag state machine the LCD HAT uses, so
# every on-device control Ragnar already has works from the keyboard.
#
# It subclasses LCDHATInputListener to reuse all of that layer logic and only
# changes two things:
#   1. the input source — a TCA8418 poll loop instead of gpiozero Buttons;
#   2. _visual_dir is made an identity map — the LCD HAT remaps directions
#      because its joystick is mounted 90° off, but keyboard arrows already point
#      the way the user reads them.
#
# Logical inputs handed to the base class (same names as the LCD HAT):
#   up / down / left / right / press / key1 / key2 / key3
# Default key mapping (see DEFAULT_KEYMAP) — arrows navigate, Enter = press,
# and three letter/edge keys stand in for KEY1..KEY3 (the mode/rotate/AP keys).
#
# ── Matrix codes are board-specific ──────────────────────────────────────────
# The TCA8418 reports a raw key number (1..80 = row*10 + col + 1), and M5Stack
# has not published which physical key sits at which matrix position for the
# CardputerZero. So DEFAULT_KEYMAP is a best guess and this module is written to
# be *calibratable without code changes*:
#   * every unmapped key press is logged at INFO with its raw code, so you can
#     read the log, press each key you want, and note its number;
#   * drop those into config/cardputer_keymap.json as {"<code>": "<action>"}
#     (actions: up/down/left/right/press/key1/key2/key3) — it overrides the
#     defaults at startup. No restart-to-recompile loop.
#
# UNVALIDATED on real CardputerZero hardware.

import json
import logging
import os
import threading
import time

from lcdhat_input import LCDHATInputListener
from epd_button import NETDIAG_HOLD_TIME

logger = logging.getLogger(__name__)

# --- TCA8418 keypad controller -------------------------------------------------
TCA8418_ADDR       = 0x34
I2C_BUS            = 1        # Pi/CM0 default user I2C bus

REG_CFG            = 0x01     # bit0 KE_IEN: key-event interrupt/FIFO enable
REG_INT_STAT       = 0x02
REG_KEY_LCK_EC     = 0x03     # low nibble = queued key events
REG_KEY_EVENT_A    = 0x04     # FIFO head: bit7 press(1)/release(0), [6:0] code
REG_KP_GPIO1       = 0x1D     # rows R0-R7 into the keypad matrix
REG_KP_GPIO2       = 0x1E     # cols C0-C7 into the keypad matrix
REG_KP_GPIO3       = 0x1F     # cols C8-C9 into the keypad matrix

POLL_INTERVAL = 0.02          # 50 Hz — also the resolution of long-press timing

# Raw TCA8418 key code → logical action. Best-effort default; override per board
# via config/cardputer_keymap.json. Codes here are placeholders for the arrow
# cluster + Enter and three edge keys and are expected to need calibration.
DEFAULT_KEYMAP = {
    # arrow cluster (guess: bottom-right of the CardputerZero keyboard)
    "31": "up",
    "41": "down",
    "40": "left",
    "42": "right",
    "43": "press",   # Enter / OK
    # edge keys standing in for the HAT's three buttons
    "1":  "key1",    # ` / Esc  → mode toggle (net-diag / exit wardriving)
    "11": "key2",    # Tab      → rotate screen / reconnect WiFi
    "30": "key3",    # Fn/Shift → next page (long: restart) / toggle AP
}

_VALID_ACTIONS = {"up", "down", "left", "right", "press", "key1", "key2", "key3"}
_KEYMAP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "config", "cardputer_keymap.json")


class CardputerInputListener(LCDHATInputListener):
    """TCA8418 keyboard listener for the CardputerZero, reusing the LCD HAT's
    page / wardriving / net-diag layers."""

    def __init__(self, shared_data):
        super().__init__(shared_data)
        self._bus = None
        self._keymap = dict(DEFAULT_KEYMAP)
        self._press_times = {}     # logical name -> monotonic time of press
        self._fired_hold = set()   # names whose long-press already fired
        self._stop = False

    # --- Lifecycle --------------------------------------------------------

    def start(self):
        """Open I2C, initialise the TCA8418, start the poll + autoscroll loops."""
        self._load_keymap_override()
        try:
            import smbus2
            self._bus = smbus2.SMBus(I2C_BUS)
            self._init_tca8418()
        except FileNotFoundError:
            logger.info("CardputerZero keyboard: I2C bus %d not available "
                        "(is I2C enabled?) — keyboard disabled", I2C_BUS)
            return
        except OSError as e:
            logger.warning("CardputerZero keyboard: TCA8418 not responding at "
                           "0x%02X (%s) — keyboard disabled", TCA8418_ADDR, e)
            return
        except ImportError:
            logger.info("CardputerZero keyboard: smbus2 not installed — "
                        "keyboard disabled")
            return
        except Exception as e:
            logger.warning("CardputerZero keyboard init failed: %s", e)
            return

        self.available = True
        self._start_autoscroll_thread()
        threading.Thread(target=self._poll_loop, name="cardputer-kbd",
                         daemon=True).start()
        logger.info("CardputerZero keyboard listener started (TCA8418 @ 0x%02X)",
                    TCA8418_ADDR)

    def _load_keymap_override(self):
        """Merge config/cardputer_keymap.json over the defaults, if present."""
        try:
            if not os.path.exists(_KEYMAP_FILE):
                return
            with open(_KEYMAP_FILE) as f:
                override = json.load(f)
            applied = 0
            for code, action in override.items():
                if action in _VALID_ACTIONS and str(code).isdigit():
                    self._keymap[str(int(code))] = action
                    applied += 1
                else:
                    logger.warning("CardputerZero keymap: ignoring %r -> %r "
                                   "(bad code or action)", code, action)
            logger.info("CardputerZero keymap: applied %d override(s) from %s",
                        applied, _KEYMAP_FILE)
        except Exception as e:
            logger.warning("CardputerZero keymap override load failed: %s", e)

    def _init_tca8418(self):
        # Enrol the whole 8x10 matrix as keypad, then enable key-event FIFO.
        self._bus.write_byte_data(TCA8418_ADDR, REG_KP_GPIO1, 0xFF)
        self._bus.write_byte_data(TCA8418_ADDR, REG_KP_GPIO2, 0xFF)
        self._bus.write_byte_data(TCA8418_ADDR, REG_KP_GPIO3, 0x03)
        self._bus.write_byte_data(TCA8418_ADDR, REG_CFG, 0x01)
        # Drain any stale events and clear the interrupt latch.
        self._drain_fifo()
        try:
            self._bus.write_byte_data(TCA8418_ADDR, REG_INT_STAT, 0x0F)
        except OSError:
            pass

    def _drain_fifo(self):
        for _ in range(64):
            if (self._read(REG_KEY_LCK_EC) & 0x0F) == 0:
                break
            self._read(REG_KEY_EVENT_A)

    def _read(self, reg):
        return self._bus.read_byte_data(TCA8418_ADDR, reg)

    # --- Poll loop --------------------------------------------------------

    def _poll_loop(self):
        while not self._stop:
            try:
                self._drain_events()
                self._check_holds()
            except OSError as e:
                logger.debug("CardputerZero keyboard read error: %s", e)
            except Exception as e:
                logger.debug("CardputerZero keyboard loop error: %s", e)
            time.sleep(POLL_INTERVAL)

    def _drain_events(self):
        count = self._read(REG_KEY_LCK_EC) & 0x0F
        for _ in range(count):
            ev = self._read(REG_KEY_EVENT_A)
            if ev == 0:
                continue
            pressed = bool(ev & 0x80)
            code = ev & 0x7F
            self._handle_event(code, pressed)
        # Clear the key-event interrupt so INT deasserts.
        try:
            self._bus.write_byte_data(TCA8418_ADDR, REG_INT_STAT, 0x01)
        except OSError:
            pass

    def _handle_event(self, code, pressed):
        name = self._keymap.get(str(code))
        if name is None:
            if pressed:
                logger.info("CardputerZero keyboard: unmapped key code %d "
                            "(add to config/cardputer_keymap.json to use it)",
                            code)
            return
        if pressed:
            self._press_times[name] = time.monotonic()
            self._fired_hold.discard(name)
            self._on_input_press(name)
        else:
            self._press_times.pop(name, None)
            self._on_input_release(name)

    def _check_holds(self):
        """Emulate gpiozero's when_held: fire a long-press once a still-held key
        passes NETDIAG_HOLD_TIME. Only keys that resolve short-vs-long care (see
        the base class _defers), but firing for all held keys is harmless."""
        now = time.monotonic()
        for name, t0 in list(self._press_times.items()):
            if name in self._fired_hold:
                continue
            if now - t0 >= NETDIAG_HOLD_TIME:
                self._fired_hold.add(name)
                self._on_input_held(name)

    # --- Orientation ------------------------------------------------------

    def _visual_dir(self, name):
        """Keyboard arrows already point the way the user reads them — no 90°
        joystick remap (unlike the LCD HAT)."""
        return name

    def stop(self):
        self._stop = True
