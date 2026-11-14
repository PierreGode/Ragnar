# cardputer_input.py — 46-key keyboard for the M5Stack CardputerZero.
#
# The CardputerZero's keyboard is a matrix behind a TCA8418 keypad controller
# (I2C address 0x34, INT on GPIO27), not a GPIO joystick like the 1.44" LCD HAT.
# This listener feeds key events into the exact same page / wardriving / net-diag
# state machine the LCD HAT uses, so every on-device control Ragnar already has
# works from the keyboard.
#
# It subclasses LCDHATInputListener to reuse all of that layer logic and only
# changes two things:
#   1. the input source — a keyboard reader instead of gpiozero Buttons;
#   2. _visual_dir is made an identity map — the LCD HAT remaps directions
#      because its joystick is mounted 90° off, but keyboard arrows already point
#      the way the user reads them.
# Backspace also only flips the screen between its two landscape ways up.
#
# Arrows: the F / X / Z / C keys carry the up / down / left / right legends.
# M5Stack's key guide asks apps to treat the plain letters as arrows when no
# text is being typed, so both the plain keys and their Fn-layer arrow codes
# are mapped. They page through the screens in every layer.
#
# Logical inputs handed to the base class (same names as the LCD HAT):
#   up / down / left / right / press / key1 / key2 / key3
#
# ── Two sources, tried in order ──────────────────────────────────────────────
#   1. evdev. The stock M5Stack image binds the TCA8418 to a kernel driver, so
#      the chip is busy on I2C and the keyboard is a normal Linux input device.
#      DEFAULT_EVDEV_KEYMAP uses Linux KEY_* codes and matches a layout already
#      in use on this board. Events are read as raw input_event structs, so no
#      python-evdev dependency is needed.
#   2. Direct I2C. For a plain kernel with no keypad driver (a stock Raspberry
#      Pi OS or Kali image). The chip reports each key as row * 10 + column + 1.
#      DEFAULT_KEYMAP uses the board's own matrix: the schematic's 5 x 10 grid
#      and the row / column of every key in M5Stack's device tree.
#
# Either map can be replaced without code changes: every unmapped key press is
# logged at INFO with its code, and config/cardputer_keymap.json holds
# {"<code>": "<action>"} overrides using the codes of the active source (actions:
# up/down/left/right/press/key1/key2/key3).

import glob
import json
import logging
import os
import select
import struct
import threading
import time

from lcdhat_input import LCDHATInputListener
from epd_button import PAGE_MAIN
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

# --- The key matrix -------------------------------------------------------------
# (row, column) of every key, from the linux,keymap table in M5Stack's device
# tree for this board (m5stack-linux-dtoverlays, cardputerzero-v5-overlay.dts).
# Rows 0-3 are the four main rows, columns 0-9 left to right; row 4 holds the
# keys at the left edge of each row plus Esc and Tab.
#   Esc                                       Tab
#   1    2 3 4 5 6 7 8 9 0   Backspace
#   sym  Q W E R T Y U I O P
#   shift A S D F G H J K L  Enter
#   fn   ctrl alt Z X C V B N M  Space
KEY_MATRIX = {
    "Esc": (4, 0), "Tab": (4, 9),
    "1": (4, 4), "2": (0, 0), "3": (0, 1), "4": (0, 2), "5": (0, 3), "6": (0, 4),
    "7": (0, 5), "8": (0, 6), "9": (0, 7), "0": (0, 8), "Bksp": (0, 9),
    "sym": (4, 3), "Q": (1, 0), "W": (1, 1), "E": (1, 2), "R": (1, 3), "T": (1, 4),
    "Y": (1, 5), "U": (1, 6), "I": (1, 7), "O": (1, 8), "P": (1, 9),
    "shift": (4, 1), "A": (2, 0), "S": (2, 1), "D": (2, 2), "F": (2, 3), "G": (2, 4),
    "H": (2, 5), "J": (2, 6), "K": (2, 7), "L": (2, 8), "OK": (2, 9),
    "fn": (4, 2), "ctrl": (3, 0), "alt": (3, 1), "Z": (3, 2), "X": (3, 3), "C": (3, 4),
    "V": (3, 5), "B": (3, 6), "N": (3, 7), "M": (3, 8), "Space": (3, 9),
}


def matrix_code(row, col):
    """The key code the TCA8418 reports for a matrix position."""
    return row * 10 + col + 1


# TCA8418 code -> name printed on the key, for the direct I2C path.
I2C_KEY_NAMES = {matrix_code(r, c): name for name, (r, c) in KEY_MATRIX.items()}
# Linux KEY_* code -> name, for the kernel input device.
EVDEV_KEY_NAMES = {
    1: "Esc", 15: "Tab", 14: "Bksp", 28: "OK", 57: "Space", 42: "shift", 29: "ctrl",
    56: "alt", 0x185: "fn", 0x17f: "sym",
    2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9", 11: "0",
    16: "Q", 17: "W", 18: "E", 19: "R", 20: "T", 21: "Y", 22: "U", 23: "I", 24: "O", 25: "P",
    30: "A", 31: "S", 32: "D", 33: "F", 34: "G", 35: "H", 36: "J", 37: "K", 38: "L",
    44: "Z", 45: "X", 46: "C", 47: "V", 48: "B", 49: "N", 50: "M",
    103: "fn+F", 108: "fn+X", 105: "fn+Z", 106: "fn+C",
}

# What each key does, by the name printed on it. Both sources use this.
#   F / X / Z / C  the arrow keys: the joystick's up / down / left / right
#   OK (Enter)     the joystick's centre press. On the Ragnar screens it opens
#                  the diagnostic screens; inside them it runs / selects.
#   Esc            back: out of the diagnostic or wardriving screens, else to
#                  the main screen
#   Space          KEY1 (diagnostic mode on / off)
#   Backspace      KEY2      Tab  KEY3      A  page autoscroll on / off
KEY_ACTIONS = {"F": "up", "X": "down", "Z": "left", "C": "right", "OK": "press",
               "Esc": "back", "Space": "key1", "Bksp": "key2", "Tab": "key3",
               "A": "auto"}

# Raw TCA8418 key code -> logical action, used only on the direct I2C path.
DEFAULT_KEYMAP = {str(matrix_code(*KEY_MATRIX[name])): action
                  for name, action in KEY_ACTIONS.items()}
# fn and sym report as ordinary keys on this path: held, never an action.
I2C_MODIFIER_CODES = {matrix_code(*KEY_MATRIX[n]) for n in ("fn", "sym", "shift", "ctrl", "alt")}

# --- Kernel input device -------------------------------------------------------
EVDEV_BY_PATH = "/dev/input/by-path/platform-3f804000.i2c-event"
EVDEV_BY_PATH_GLOB = "/dev/input/by-path/platform-*.i2c-event*"
# Substrings of the input device name the keypad driver registers under.
_KEYBOARD_NAME_TAGS = ("tca8418", "cardputer", "m5stack")
_SYS_INPUT = "/sys/class/input"
_EVENT_FORMAT = "llHHi"       # struct input_event: sec, usec, type, code, value
_EVENT_SIZE = struct.calcsize(_EVENT_FORMAT)
EV_KEY = 1
EV_PRESS = 1
EV_RELEASE = 0                # value 2 is autorepeat, which we ignore

EVDEV_WAIT_SECONDS = 60       # the device node can appear after we start at boot
EVDEV_RETRY_SECONDS = 2
EVDEV_RESCAN_SECONDS = 5      # how often to look for further keyboards

# Linux KEY_* code → logical action.
DEFAULT_EVDEV_KEYMAP = {
    # Fn-layer arrows
    "103": "up",     # KEY_UP
    "108": "down",   # KEY_DOWN
    "105": "left",   # KEY_LEFT
    "106": "right",  # KEY_RIGHT
    # Unshifted arrow cluster
    "33": "up",      # F
    "45": "down",    # X
    "44": "left",    # Z
    "46": "right",   # C
    "28": "press",   # Enter / OK
    "1":  "back",    # Esc
    "57": "key1",    # Space     → diagnostic mode on / off
    "14": "key2",    # Backspace → flip screen / reconnect WiFi
    "15": "key3",    # Tab       → next page (long: restart) / toggle AP
    "30": "auto",    # A         → page autoscroll on / off
}

# The board's fn and sym keys report as KEY_DVD (0x185) and KEY_CD (0x17f).
_MODIFIER_CODES = {0x185, 0x17f, 464, 42, 54, 29, 97, 56, 100, 125, 126, 127}

_VALID_ACTIONS = {"up", "down", "left", "right", "press", "key1", "key2", "key3",
                  "back", "auto"}
_KEYMAP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "config", "cardputer_keymap.json")


# A device counts as a keyboard when it reports these keys (F, Z, Enter): the
# built-in keypad does, a power switch or an HDMI-CEC remote does not.
_KEYBOARD_PROBE_KEYS = (33, 44, 28)


def _reports_keys(caps_text, codes=_KEYBOARD_PROBE_KEYS):
    """True if a sysfs capabilities/key bitmap has every code in `codes`. The
    kernel prints the bitmap as hex words, most significant first, one
    machine word each (as seen by the reading process)."""
    words = caps_text.split()
    if not words:
        return False
    bits = struct.calcsize("l") * 8
    try:
        value = 0
        for word in words:
            value = (value << bits) | int(word, 16)
    except ValueError:
        return False
    return all(value >> code & 1 for code in codes)


def find_keyboard_devices():
    """Every /dev/input node Ragnar should read keys from, best match first.

    The built-in keypad comes first (fixed path, then by driver name), then
    any other device that reports letter keys, so a USB keyboard works too.
    Reading them all also means a wrong guess about which node is the keypad
    cannot leave the keys dead."""
    override = os.environ.get("RAGNAR_CARDPUTER_KBD")
    if override:
        return [override] if os.path.exists(override) else []
    found = []

    def add(path):
        if not path or not os.path.exists(path):
            return
        real = os.path.realpath(path)
        if real not in [os.path.realpath(p) for p in found]:
            found.append(path)

    add(EVDEV_BY_PATH)
    named, generic = [], []
    for name_path in sorted(glob.glob(f"{_SYS_INPUT}/event*/device/name")):
        device_dir = os.path.dirname(name_path)
        event = os.path.basename(os.path.dirname(device_dir))
        try:
            with open(name_path) as f:
                name = f.read()
        except OSError:
            continue
        if any(tag in name.lower() for tag in _KEYBOARD_NAME_TAGS):
            named.append(f"/dev/input/{event}")
            continue
        try:
            with open(os.path.join(device_dir, "capabilities", "key")) as f:
                if _reports_keys(f.read()):
                    generic.append(f"/dev/input/{event}")
        except OSError:
            continue
    for path in named:
        add(path)
    # A kernel that names the node differently still hangs it off the I2C bus.
    for path in sorted(glob.glob(EVDEV_BY_PATH_GLOB)):
        add(path)
    for path in generic:
        add(path)
    return found


def find_keyboard_device():
    """The best-matching keyboard node, or None if there is none yet."""
    devices = find_keyboard_devices()
    return devices[0] if devices else None


class CardputerInputListener(LCDHATInputListener):
    """Keyboard listener for the CardputerZero, reusing the LCD HAT's
    page / wardriving / net-diag layers."""

    def __init__(self, shared_data):
        super().__init__(shared_data)
        self._bus = None
        self._ev_fd = None         # the built-in keypad (best match)
        self._extra_fds = {}       # fd -> path of any other keyboard
        self._ev_paths = set()     # real paths currently open
        self._next_rescan = 0.0
        self._source = None        # 'evdev' | 'i2c'
        # Last key seen, for the on-screen echo: (code, action or None, time).
        # key_seq is bumped on every press so the display can redraw at once.
        self.last_key = None
        self.key_seq = 0
        self._keymap = dict(DEFAULT_EVDEV_KEYMAP)
        self._press_times = {}     # logical name -> monotonic time of press
        self._fired_hold = set()   # names whose long-press already fired
        self._stop = False

    # --- Lifecycle --------------------------------------------------------

    def start(self):
        """Attach to the keyboard and start the read + autoscroll loops."""
        if self._open_evdev():
            self._run_source("evdev")
        elif self._open_i2c():
            self._run_source("i2c")
        else:
            threading.Thread(target=self._wait_for_keyboard,
                             name="cardputer-kbd-wait", daemon=True).start()

    def _wait_for_keyboard(self):
        """Neither source was ready. The kernel device can appear late at boot,
        so keep looking for a while before giving up."""
        deadline = time.monotonic() + EVDEV_WAIT_SECONDS
        while not self._stop and time.monotonic() < deadline:
            time.sleep(EVDEV_RETRY_SECONDS)
            if self._open_evdev():
                self._run_source("evdev")
                return
        if not self._stop:
            logger.warning("CardputerZero keyboard: no input device appeared "
                           "after %ds — keyboard disabled", EVDEV_WAIT_SECONDS)

    def _run_source(self, source):
        self._source = source
        self._keymap = dict(DEFAULT_EVDEV_KEYMAP if source == "evdev"
                            else DEFAULT_KEYMAP)
        self._load_keymap_override()
        self.available = True
        self._start_autoscroll_thread()
        target = self._evdev_loop if source == "evdev" else self._poll_loop
        threading.Thread(target=target, name="cardputer-kbd",
                         daemon=True).start()
        logger.info("CardputerZero keyboard listener started (%s)", source)

    def _open_evdev(self):
        """Open every keyboard not already open. True if at least one is."""
        for path in find_keyboard_devices():
            real = os.path.realpath(path)
            if real in self._ev_paths:
                continue
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            except OSError as e:
                logger.warning("CardputerZero keyboard: cannot open %s (%s)", path, e)
                continue
            self._ev_paths.add(real)
            if self._ev_fd is None:
                self._ev_fd = fd
            else:
                self._extra_fds[fd] = real
            logger.info("CardputerZero keyboard: reading %s", path)
        return self._ev_fd is not None

    def _open_i2c(self):
        try:
            import smbus2
            self._bus = smbus2.SMBus(I2C_BUS)
            self._init_tca8418()
            return True
        except FileNotFoundError:
            logger.info("CardputerZero keyboard: I2C bus %d not available "
                        "(is I2C enabled?)", I2C_BUS)
        except OSError as e:
            logger.info("CardputerZero keyboard: TCA8418 not reachable at "
                        "0x%02X (%s)", TCA8418_ADDR, e)
        except ImportError:
            logger.info("CardputerZero keyboard: smbus2 not installed")
        except Exception as e:
            logger.warning("CardputerZero keyboard init failed: %s", e)
        self._bus = None
        return False

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

    # --- evdev loop -------------------------------------------------------

    def _evdev_loop(self):
        while not self._stop:
            try:
                fds = [self._ev_fd] + list(self._extra_fds)
                ready, _, _ = select.select(fds, [], [], POLL_INTERVAL)
                for fd in ready:
                    if fd == self._ev_fd:
                        self._read_events(fd)
                    else:
                        self._read_extra(fd)
                self._check_holds()
                self._rescan()
            except OSError as e:
                logger.warning("CardputerZero keyboard: device lost (%s)", e)
                if not self._reopen_evdev():
                    return
            except Exception as e:
                logger.warning("CardputerZero keyboard loop error: %s", e)
                time.sleep(POLL_INTERVAL)
        self._close_evdev()

    def _read_extra(self, fd):
        """A secondary keyboard (e.g. USB) going away must not disturb the
        built-in one: just drop it."""
        try:
            self._read_events(fd)
        except OSError:
            self._ev_paths.discard(self._extra_fds.pop(fd, None))
            try:
                os.close(fd)
            except OSError:
                pass

    def _rescan(self):
        """Pick up keyboards that appear after start (late driver, hot-plug)."""
        now = time.monotonic()
        if now < self._next_rescan:
            return
        self._next_rescan = now + EVDEV_RESCAN_SECONDS
        self._open_evdev()

    def _read_events(self, fd=None):
        fd = self._ev_fd if fd is None else fd
        try:
            data = os.read(fd, _EVENT_SIZE * 32)
        except BlockingIOError:
            return
        if not data:
            raise OSError("end of input device")
        usable = len(data) - (len(data) % _EVENT_SIZE)
        for _, _, ev_type, code, value in struct.iter_unpack(_EVENT_FORMAT,
                                                             data[:usable]):
            if ev_type == EV_KEY and value in (EV_PRESS, EV_RELEASE):
                self._handle_event(code, value == EV_PRESS)

    def _close_evdev(self):
        for fd in [self._ev_fd] + list(self._extra_fds):
            if fd is None:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
        self._ev_fd = None
        self._extra_fds = {}
        self._ev_paths = set()

    def _reopen_evdev(self):
        self._close_evdev()
        self._press_times.clear()
        self._fired_hold.clear()
        deadline = time.monotonic() + EVDEV_WAIT_SECONDS
        while not self._stop and time.monotonic() < deadline:
            if self._open_evdev():
                return True
            time.sleep(EVDEV_RETRY_SECONDS)
        return False

    # --- I2C poll loop ----------------------------------------------------

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

    # --- Shared event handling --------------------------------------------

    def key_label(self, code):
        """The name printed on the key a code belongs to, for the echo."""
        names = I2C_KEY_NAMES if self._source == "i2c" else EVDEV_KEY_NAMES
        return names.get(code, f"key {code}")

    def _is_modifier(self, code):
        return code in (I2C_MODIFIER_CODES if self._source == "i2c" else _MODIFIER_CODES)

    def _handle_event(self, code, pressed):
        name = self._keymap.get(str(code))
        if pressed and not self._is_modifier(code):
            # For the on-screen echo (display.py) and for diagnosis: every
            # press is recorded and logged, mapped or not.
            self.last_key = (code, name, time.monotonic())
            self.key_seq += 1
        if name is None:
            if pressed and not self._is_modifier(code):
                logger.info("CardputerZero keyboard: unmapped key code %d "
                            "(add to config/cardputer_keymap.json to use it)",
                            code)
            return
        if pressed:
            logger.info("CardputerZero keyboard: key %d (%s) -> %s", code,
                        self.key_label(code), name)
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

    # --- Keyboard-specific keys -------------------------------------------

    def _on_input_press(self, name):
        if name == "back":
            self._go_back()
        elif name == "auto":
            # Autoscroll belongs to the Ragnar pages; the other layers have
            # their own cycling.
            if not self._netdiag_active() and not self._wardrive_view():
                self._toggle_autoscroll()
        else:
            super()._on_input_press(name)

    def _go_back(self):
        """Esc: one step out. Diagnostic screens: close a result, else leave
        them. Wardriving screens: back to the Ragnar pages. Otherwise home."""
        if self._netdiag_active():
            self.netdiag_seq += 1
            if self.netdiag_result is not None:
                self.netdiag_result = None
            elif self.netdiag_view == "menu":
                self.netdiag_view = "card"
            else:
                self._set_netdiag(False)
        elif self._wardrive_view():
            self._wardrive_exit_to_ragnar()
        else:
            self.autoscroll = False
            self.current_page = PAGE_MAIN
            logger.info("CardputerZero Esc: main screen")

    def _default_input(self, name, gesture="short"):
        """On the Ragnar pages OK opens the diagnostic screens (the LCD HAT
        starts page autoscroll with its centre press; that is the A key
        here). Everything else is the LCD HAT's default layer."""
        if name == "press":
            self._set_netdiag(True)
            return
        super()._default_input(name, gesture)

    # --- Orientation ------------------------------------------------------

    def _on_key2(self):
        """Backspace (KEY2): turn the screen upside down and back. The LCD
        HAT steps through all four rotations, but this board is a keyboard
        with a wide screen above it, so only the two landscape ways up make
        sense. The choice is saved, so it survives a restart."""
        try:
            current = int(getattr(self.shared_data, 'screen_reversed', 0) or 0) % 360
        except (TypeError, ValueError):
            current = 0
        new_rotation = 0 if current == 180 else 180
        self.shared_data.screen_reversed = new_rotation
        try:
            self.shared_data.config['screen_reversed'] = new_rotation
            self.shared_data.save_config()
        except Exception as e:
            logger.warning("CardputerZero: could not save the rotation (%s)", e)
        logger.info("CardputerZero Backspace: display rotation set to %d°", new_rotation)


    def _visual_dir(self, name):
        """Keyboard arrows already point the way the user reads them — no 90°
        joystick remap (unlike the LCD HAT)."""
        return name

    def stop(self):
        self._stop = True


def _key_test():
    """`python3 cardputer_input.py`: show which devices are read and print
    every key as it arrives. Ctrl+C to stop."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    devices = find_keyboard_devices()
    if not devices:
        print("No keyboard found under /dev/input. Devices present:")
        for name_path in sorted(glob.glob(f"{_SYS_INPUT}/event*/device/name")):
            event = os.path.basename(os.path.dirname(os.path.dirname(name_path)))
            try:
                print(f"  /dev/input/{event}: {open(name_path).read().strip()}")
            except OSError:
                pass
        return 1
    fds = {}
    for path in devices:
        try:
            fds[os.open(path, os.O_RDONLY | os.O_NONBLOCK)] = path
            print(f"reading {path}")
        except OSError as e:
            print(f"cannot open {path}: {e} (run with sudo?)")
    if not fds:
        return 1
    print("Press keys (F X Z C should say up/down/left/right). Ctrl+C to stop.")
    try:
        while True:
            ready, _, _ = select.select(list(fds), [], [], 1.0)
            for fd in ready:
                try:
                    data = os.read(fd, _EVENT_SIZE * 32)
                except (BlockingIOError, OSError):
                    continue
                usable = len(data) - (len(data) % _EVENT_SIZE)
                for _, _, ev_type, code, value in struct.iter_unpack(
                        _EVENT_FORMAT, data[:usable]):
                    if ev_type == EV_KEY and value == EV_PRESS:
                        action = DEFAULT_EVDEV_KEYMAP.get(str(code), "not mapped")
                        label = EVDEV_KEY_NAMES.get(code, "?")
                        print(f"  key code {code:<4} {label:<6} -> {action:<10} ({fds[fd]})")
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(_key_test())
