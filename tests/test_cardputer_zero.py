"""CardputerZero support, exercised against simulated hardware.

There is no CardputerZero in CI, so these fake the parts of the board Ragnar
touches: sysfs + framebuffer files, spidev + GPIO, the kernel input device (a
real pipe carrying binary input_event structs) and the stock image's filesystem.
The expected values come from M5Stack's published pin map and developer docs,
and from software already running on the board.
"""
import json
import os
import re
import struct
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from resources.waveshare_epd import st7789v2 as drv  # noqa: E402
import cardputer_input as ci  # noqa: E402
import epd_helper  # noqa: E402


# ── Framebuffer ──────────────────────────────────────────────────────────────

def make_fb(tmp_path, monkeypatch, node="fb1", name="st7789v_m5st", size=(320, 170),
            bpp=16, stride=None):
    """Create a fake /sys/class/graphics/<node> plus its device file."""
    sysdir = tmp_path / "graphics" / node
    sysdir.mkdir(parents=True)
    (sysdir / "name").write_text(name + "\n")
    (sysdir / "virtual_size").write_text(f"{size[0]},{size[1]}\n")
    (sysdir / "bits_per_pixel").write_text(f"{bpp}\n")
    (sysdir / "blank").write_text("1\n")
    if stride is not None:
        (sysdir / "stride").write_text(f"{stride}\n")
    dev = tmp_path / node
    dev.write_bytes(b"\0" * (size[0] * size[1] * 4))
    monkeypatch.setattr(drv, "_SYS_GRAPHICS", str(tmp_path / "graphics"))
    monkeypatch.setattr(drv, "_SYS_BACKLIGHT", str(tmp_path / "backlight"))
    monkeypatch.setattr(drv, "_FB_CANDIDATES", ())
    real_exists = os.path.exists
    monkeypatch.setattr(drv.os.path, "exists",
                        lambda p: real_exists(str(p).replace("/dev/", f"{tmp_path}/")))
    real_open = open
    monkeypatch.setattr(drv, "open",
                        lambda p, *a, **k: real_open(str(p).replace("/dev/", f"{tmp_path}/"), *a, **k),
                        raising=False)
    return dev, sysdir


def test_finds_lcd_by_kernel_driver_name(tmp_path, monkeypatch):
    make_fb(tmp_path, monkeypatch, node="fb0")
    epd = drv.EPD()
    epd.init()
    assert epd._transport == "fb"
    assert epd._fb_path == "/dev/fb0"
    assert (epd.width, epd.height) == (320, 170)


def test_named_lcd_with_taller_virtual_size_is_adopted(tmp_path, monkeypatch):
    make_fb(tmp_path, monkeypatch, size=(320, 340))
    epd = drv.EPD()
    epd.init()
    assert (epd.width, epd.height) == (320, 170)


def test_framebuffer_pixels_are_little_endian_rgb565(tmp_path, monkeypatch):
    dev, _ = make_fb(tmp_path, monkeypatch)
    epd = drv.EPD()
    epd.init()
    red = Image.new("RGB", (320, 170), (255, 0, 0))
    epd.display(epd.getbuffer(red))
    data = dev.read_bytes()
    # RGB565 red is 0xF800, so a little-endian framebuffer holds 00 F8.
    assert data[:2] == b"\x00\xF8"
    assert data[320 * 170 * 2 - 2:320 * 170 * 2] == b"\x00\xF8"


def test_framebuffer_write_matches_native_rgb565_packing(tmp_path, monkeypatch):
    dev, _ = make_fb(tmp_path, monkeypatch)
    epd = drv.EPD()
    epd.init()
    colour = (18, 52, 200)
    epd.display(epd.getbuffer(Image.new("RGB", (320, 170), colour)))
    r, g, b = colour
    expected = struct.pack("<H", ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3))
    assert dev.read_bytes()[:2] == expected


def test_framebuffer_honours_stride(tmp_path, monkeypatch):
    dev, _ = make_fb(tmp_path, monkeypatch, stride=660)
    epd = drv.EPD()
    epd.init()
    epd.display(epd.getbuffer(Image.new("RGB", (320, 170), (255, 255, 255))))
    data = dev.read_bytes()
    assert data[638:640] == b"\xFF\xFF"
    assert data[640:660] == b"\0" * 20
    assert data[660:662] == b"\xFF\xFF"


def test_unnamed_hdmi_framebuffer_is_never_adopted(tmp_path, monkeypatch):
    dev, _ = make_fb(tmp_path, monkeypatch, name="vc4drmfb", size=(1920, 1080))
    monkeypatch.setattr(drv, "_FB_CANDIDATES", ("/dev/fb1",))
    monkeypatch.setattr(drv.EPD, "_init_spi", lambda self: False)
    with pytest.raises(RuntimeError):
        drv.EPD().init()
    assert set(dev.read_bytes()) == {0}


def test_wakes_a_blanked_panel_with_backlight_off(tmp_path, monkeypatch):
    _, sysdir = make_fb(tmp_path, monkeypatch)
    bl = tmp_path / "backlight" / "lcd"
    bl.mkdir(parents=True)
    (bl / "brightness").write_text("0\n")
    (bl / "max_brightness").write_text("255\n")
    drv.EPD().init()
    assert (sysdir / "blank").read_text().strip() == "0"
    assert (bl / "brightness").read_text().strip() == "255"


def test_keeps_a_brightness_the_user_already_set(tmp_path, monkeypatch):
    make_fb(tmp_path, monkeypatch)
    bl = tmp_path / "backlight" / "lcd"
    bl.mkdir(parents=True)
    (bl / "brightness").write_text("80\n")
    (bl / "max_brightness").write_text("255\n")
    drv.EPD().init()
    assert (bl / "brightness").read_text().strip() == "80"


@pytest.mark.parametrize("corner", ["rotated"])
def test_portrait_canvas_is_rotated_not_squashed(corner):
    """Screen rotation 90/270 hands the driver a portrait canvas."""
    epd = drv.EPD()
    canvas = Image.new("RGB", (170, 320), (0, 0, 0))
    canvas.paste((255, 255, 255), (0, 0, 170, 10))      # bright band along the top
    buf = epd.getbuffer(canvas)
    pixel = lambda x, y: buf[(y * 320 + x) * 2:(y * 320 + x) * 2 + 2]
    # A squash would keep the band horizontal; a rotation makes it a vertical
    # edge running the full panel height.
    assert pixel(315, 0) == b"\xFF\xFF" and pixel(315, 169) == b"\xFF\xFF"
    assert pixel(100, 85) == b"\x00\x00"


# ── Native SPI ───────────────────────────────────────────────────────────────

class FakeLED:
    made = []

    def __init__(self, pin):
        self.pin, self.state = pin, None
        FakeLED.made.append(self)

    def on(self):
        self.state = 1

    def off(self):
        self.state = 0


class FakeSpi:
    last = None

    def __init__(self):
        self.calls, self.opened, self.closed = [], None, False
        FakeSpi.last = self

    def open(self, bus, dev):
        self.opened = (bus, dev)

    def close(self):
        self.closed = True

    def writebytes(self, data):
        self.calls.append(list(data))

    def writebytes2(self, data):
        self.calls.append(bytes(data))


class FakeExpander:
    def __init__(self, available=True):
        self.available = available
        self.resets, self.lit = 0, 0

    def reset_lcd(self):
        self.resets += 1
        return self.available

    def backlight_on(self):
        self.lit += 1


@pytest.fixture
def fake_spi_stack(monkeypatch):
    FakeLED.made = []
    monkeypatch.setitem(sys.modules, "spidev", types.SimpleNamespace(SpiDev=FakeSpi))
    monkeypatch.setitem(sys.modules, "gpiozero", types.SimpleNamespace(LED=FakeLED))
    monkeypatch.setattr(drv.EPD, "_init_framebuffer", lambda self: False)
    monkeypatch.setattr(drv.time, "sleep", lambda s: None)
    monkeypatch.delenv("RAGNAR_CARDPUTER_SPI", raising=False)


def test_spi_uses_published_pins(fake_spi_stack, monkeypatch):
    """M5Stack's pin map: DC is GPIO25, CS is SPI0 CE0 (GPIO8)."""
    monkeypatch.setattr(drv.EPD, "_ensure_ioe", lambda self: FakeExpander())
    epd = drv.EPD()
    epd.init()
    assert epd._transport == "spi"
    assert [led.pin for led in FakeLED.made] == [25]
    assert FakeSpi.last.opened == (0, 0)
    assert not getattr(FakeSpi.last, "no_cs", False)


def test_spi_addresses_the_170_row_window(fake_spi_stack, monkeypatch):
    monkeypatch.setattr(drv.EPD, "_ensure_ioe", lambda self: FakeExpander())
    epd = drv.EPD()
    epd.init()
    FakeSpi.last.calls.clear()
    epd.display(epd.getbuffer(Image.new("RGB", (320, 170), "white")))
    calls = FakeSpi.last.calls
    assert calls[0] == [0x2A] and calls[1] == list(struct.pack(">HH", 0, 319))
    assert calls[2] == [0x2B] and calls[3] == list(struct.pack(">HH", 35, 204))
    assert calls[4] == [0x2C]
    assert sum(len(c) for c in calls[5:]) == 320 * 170 * 2


def test_spi_is_not_claimed_without_the_board_expander(fake_spi_stack, monkeypatch):
    """No read-back on SPI: without this check any Pi with SPI 'has' this panel."""
    monkeypatch.setattr(drv.EPD, "_ensure_ioe", lambda self: FakeExpander(available=False))
    with pytest.raises(RuntimeError):
        drv.EPD().init()
    assert FakeLED.made == []


def test_spi_override_skips_the_expander_check(fake_spi_stack, monkeypatch):
    monkeypatch.setattr(drv.EPD, "_ensure_ioe", lambda self: None)
    monkeypatch.setenv("RAGNAR_CARDPUTER_SPI", "1")
    epd = drv.EPD()
    epd.init()
    assert epd._transport == "spi"


def test_failed_gpio_claim_closes_the_spi_handle(fake_spi_stack, monkeypatch):
    def busy(pin):
        raise RuntimeError("GPIO busy")
    monkeypatch.setitem(sys.modules, "gpiozero", types.SimpleNamespace(LED=busy))
    monkeypatch.setattr(drv.EPD, "_ensure_ioe", lambda self: FakeExpander())
    with pytest.raises(RuntimeError):
        drv.EPD().init()
    assert FakeSpi.last.closed


def test_auto_detect_does_not_report_this_panel_on_another_board(monkeypatch):
    monkeypatch.setattr(drv.EPD, "_init_framebuffer", lambda self: False)
    monkeypatch.setattr(drv.EPD, "_ensure_ioe", lambda self: FakeExpander(available=False))
    monkeypatch.setattr(epd_helper.time, "sleep", lambda s: None)
    assert epd_helper.EPDHelper.auto_detect(["st7789v2"]) is None


def test_epd_helper_drives_the_driver_end_to_end(tmp_path, monkeypatch):
    dev, _ = make_fb(tmp_path, monkeypatch)
    helper = epd_helper.EPDHelper("st7789v2")
    helper.init_partial_update()
    helper.display_partial(Image.new("1", (320, 170), 255))
    helper.display_partial(Image.new("1", (170, 320), 255))
    helper.clear()
    assert dev.read_bytes()[:2] == b"\xFF\xFF"


# ── Keyboard ─────────────────────────────────────────────────────────────────

EVENT = struct.Struct("llHHi")


def key(code, value):
    return EVENT.pack(0, 0, 1, code, value)


def noise():
    return EVENT.pack(0, 0, 0, 0, 0)     # EV_SYN report


@pytest.fixture
def listener(monkeypatch):
    monkeypatch.setattr(ci, "_KEYMAP_FILE", "/nonexistent/cardputer_keymap.json")
    monkeypatch.setattr(ci.CardputerInputListener, "_start_autoscroll_thread",
                        lambda self: None)
    shared = types.SimpleNamespace(screen_reversed=0, config={})
    lst = ci.CardputerInputListener(shared)
    actions = []
    monkeypatch.setattr(lst, "_on_input_press", lambda n: actions.append(("press", n)))
    monkeypatch.setattr(lst, "_on_input_release", lambda n: actions.append(("release", n)))
    monkeypatch.setattr(lst, "_on_input_held", lambda n: actions.append(("held", n)))
    lst.actions = actions
    lst.test_fds = []
    yield lst
    # Stop the reader before closing anything, or its fd number gets reused by
    # the next test's pipe and the old thread steals those events.
    lst._stop = True
    time.sleep(ci.POLL_INTERVAL * 5)
    for fd in lst.test_fds:
        try:
            os.close(fd)
        except OSError:
            pass


def wait_for(predicate, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def attach_pipe(lst, monkeypatch):
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    lst.test_fds.append(write_fd)

    def fake_open():
        lst._ev_fd = read_fd
        return True

    monkeypatch.setattr(lst, "_open_evdev", fake_open)
    lst.start()
    assert lst._source == "evdev"
    return write_fd


def test_evdev_is_preferred_and_decodes_binary_events(listener, monkeypatch):
    w = attach_pipe(listener, monkeypatch)
    os.write(w, key(28, 1) + noise() + key(28, 0) + noise())
    assert wait_for(lambda: len(listener.actions) == 2)
    assert listener.actions == [("press", "press"), ("release", "press")]


def test_evdev_wins_when_both_sources_answer(listener, monkeypatch):
    """I2C must never be touched while the kernel owns the keyboard."""
    opened = []

    class Chip:
        def __init__(self, bus):
            opened.append(bus)

        def write_byte_data(self, *a):
            pass

        def read_byte_data(self, *a):
            return 0

    monkeypatch.setitem(sys.modules, "smbus2", types.SimpleNamespace(SMBus=Chip))
    attach_pipe(listener, monkeypatch)
    assert listener._source == "evdev"
    assert opened == []


@pytest.mark.parametrize("code,action", [
    (103, "up"), (108, "down"), (105, "left"), (106, "right"),
    (33, "up"), (45, "down"), (44, "left"), (46, "right"),
    (28, "press"), (57, "key1"), (14, "key2"), (15, "key3"), (1, "key3"),
])
def test_evdev_keymap_matches_the_field_tested_layout(listener, monkeypatch, code, action):
    w = attach_pipe(listener, monkeypatch)
    os.write(w, key(code, 1))
    assert wait_for(lambda: listener.actions)
    assert listener.actions[0] == ("press", action)


def test_evdev_ignores_autorepeat(listener, monkeypatch):
    w = attach_pipe(listener, monkeypatch)
    os.write(w, key(33, 1) + key(33, 2) + key(33, 2) + key(33, 0))
    assert wait_for(lambda: len(listener.actions) >= 2)
    time.sleep(0.05)
    assert listener.actions == [("press", "up"), ("release", "up")]


def test_holding_a_key_fires_a_long_press(listener, monkeypatch):
    monkeypatch.setattr(ci, "NETDIAG_HOLD_TIME", 0.05)
    w = attach_pipe(listener, monkeypatch)
    os.write(w, key(15, 1))
    assert wait_for(lambda: ("held", "key3") in listener.actions)
    time.sleep(0.1)
    assert listener.actions.count(("held", "key3")) == 1


def test_unmapped_key_logs_its_code(listener, caplog):
    listener._source = "evdev"
    with caplog.at_level("INFO", logger="cardputer_input"):
        listener._handle_event(30, True)
    assert "unmapped key code 30" in caplog.text
    assert listener.actions == []


def test_keymap_file_overrides_the_active_source(listener, monkeypatch, tmp_path):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"30": "press", "99": "bogus", "x": "up"}))
    monkeypatch.setattr(ci, "_KEYMAP_FILE", str(path))
    w = attach_pipe(listener, monkeypatch)
    assert listener._keymap["30"] == "press"
    assert "99" not in listener._keymap
    assert listener._keymap["28"] == "press"


def test_device_loss_reopens_the_keyboard(listener, monkeypatch):
    monkeypatch.setattr(ci, "EVDEV_RETRY_SECONDS", 0.01)
    w = attach_pipe(listener, monkeypatch)
    r2, w2 = os.pipe()
    os.set_blocking(r2, False)

    def reopen():
        listener._ev_fd = r2
        return True

    monkeypatch.setattr(listener, "_open_evdev", reopen)
    os.close(w)                         # the device goes away
    listener.test_fds.append(w2)
    assert wait_for(lambda: listener._ev_fd == r2)
    os.write(w2, key(57, 1))
    assert wait_for(lambda: ("press", "key1") in listener.actions)


def test_keyboard_that_appears_late_is_picked_up(listener, monkeypatch):
    monkeypatch.setattr(ci, "EVDEV_RETRY_SECONDS", 0.01)
    monkeypatch.setattr(listener, "_open_i2c", lambda: False)
    state = {"tries": 0}
    r, w = os.pipe()
    os.set_blocking(r, False)

    def late():
        state["tries"] += 1
        if state["tries"] < 3:
            return False
        listener._ev_fd = r
        return True

    monkeypatch.setattr(listener, "_open_evdev", late)
    listener.start()
    assert wait_for(lambda: listener._source == "evdev")
    listener.test_fds.append(w)
    os.write(w, key(28, 1))
    assert wait_for(lambda: listener.actions)


def test_kernel_owned_chip_does_not_crash_i2c_fallback(listener, monkeypatch):
    """With the kernel driver bound, the chip reports EBUSY on I2C."""
    class Busy:
        def __init__(self, bus):
            pass

        def write_byte_data(self, *a):
            raise OSError(16, "Device or resource busy")

    monkeypatch.setitem(sys.modules, "smbus2", types.SimpleNamespace(SMBus=Busy))
    assert listener._open_i2c() is False
    assert listener._bus is None


def test_i2c_fallback_uses_the_matrix_keymap(listener, monkeypatch):
    class Chip:
        def __init__(self, bus):
            self.writes = []

        def write_byte_data(self, addr, reg, value):
            self.writes.append((addr, reg, value))

        def read_byte_data(self, addr, reg):
            return 0

    monkeypatch.setitem(sys.modules, "smbus2", types.SimpleNamespace(SMBus=Chip))
    monkeypatch.setattr(listener, "_open_evdev", lambda: False)
    listener.start()
    assert listener._source == "i2c"
    assert listener._keymap == ci.DEFAULT_KEYMAP


def test_device_found_by_sysfs_name(tmp_path, monkeypatch):
    node = tmp_path / "event4" / "device"
    node.mkdir(parents=True)
    (node / "name").write_text("tca8418_keypad_m5stack\n")
    monkeypatch.setattr(ci, "_SYS_INPUT", str(tmp_path))
    monkeypatch.setattr(ci, "EVDEV_BY_PATH", str(tmp_path / "absent"))
    monkeypatch.delenv("RAGNAR_CARDPUTER_KBD", raising=False)
    assert ci.find_keyboard_device() == "/dev/input/event4"


def test_real_page_navigation_from_keys(monkeypatch):
    """Through the real LCD HAT state machine, not stubs."""
    monkeypatch.setattr(ci, "_KEYMAP_FILE", "/nonexistent/cardputer_keymap.json")
    shared = types.SimpleNamespace(screen_reversed=0, config={})
    lst = ci.CardputerInputListener(shared)
    monkeypatch.setattr(lst, "_netdiag_active", lambda: False)
    monkeypatch.setattr(lst, "_is_wardriving_active", lambda: False)
    lst._keymap = dict(ci.DEFAULT_EVDEV_KEYMAP)
    start = lst.current_page
    lst._handle_event(46, True)
    lst._handle_event(46, False)
    assert lst.current_page == start + 1
    lst._handle_event(44, True)
    lst._handle_event(44, False)
    assert lst.current_page == start


# ── Stock-image takeover ─────────────────────────────────────────────────────

TAKEOVER = ROOT / "scripts" / "cardputer_takeover.sh"
BIN_REL = "usr/share/APPLaunch/bin/M5CardputerZero-APPLaunch"


def stock_image(root, launcher=True, lcd=True):
    (root / "boot/firmware").mkdir(parents=True)
    (root / "boot/firmware/cmdline.txt").write_text(
        "console=serial0,115200 console=tty1 root=PARTUUID=1 rootwait\n")
    if launcher:
        path = root / BIN_REL
        path.parent.mkdir(parents=True)
        path.write_text("real launcher")
    if lcd:
        node = root / "sys/class/graphics/fb1"
        node.mkdir(parents=True)
        (node / "name").write_text("st7789v_m5st\n")


def stub_commands(tmp_path):
    bindir = tmp_path / "stubbin"
    bindir.mkdir()
    log = tmp_path / "commands.log"
    for name in ("systemctl", "sudo", "chown"):
        stub = bindir / name
        stub.write_text(f'#!/bin/bash\necho "{name} $*" >> "{log}"\n')
        stub.chmod(0o755)
    return bindir, log


def takeover(tmp_path, root, action):
    bindir, log = stub_commands(tmp_path) if not (tmp_path / "stubbin").exists() \
        else (tmp_path / "stubbin", tmp_path / "commands.log")
    env = dict(os.environ, RAGNAR_CARDPUTER_ROOT=str(root),
               PATH=f"{bindir}:{os.environ['PATH']}")
    result = subprocess.run(["bash", str(TAKEOVER), action], env=env,
                            capture_output=True, text=True)
    return result, log


def test_takeover_replaces_launcher_and_console(tmp_path):
    root = tmp_path / "root"
    stock_image(root)
    result, log = takeover(tmp_path, root, "apply")
    assert result.returncode == 0, result.stderr
    binary = root / BIN_REL
    assert binary.is_symlink() and os.readlink(binary) == "/usr/bin/sleep"
    assert Path(f"{binary}.real").read_text() == "real launcher"
    cmdline = (root / "boot/firmware/cmdline.txt").read_text()
    assert "console=tty1" not in cmdline
    assert "console=serial0,115200" in cmdline
    assert cmdline.strip().endswith("fbcon=map:99")
    assert cmdline.count("\n") == 1
    assert "disable getty@tty1.service" in log.read_text()


def test_takeover_is_idempotent(tmp_path):
    root = tmp_path / "root"
    stock_image(root)
    takeover(tmp_path, root, "apply")
    takeover(tmp_path, root, "apply")
    assert Path(f"{root / BIN_REL}.real").read_text() == "real launcher"
    assert (root / "boot/firmware/cmdline.txt").read_text().count("fbcon=map:99") == 1


def test_takeover_revert_restores_the_stock_image(tmp_path):
    root = tmp_path / "root"
    stock_image(root)
    original = (root / "boot/firmware/cmdline.txt").read_text()
    takeover(tmp_path, root, "apply")
    result, _ = takeover(tmp_path, root, "revert")
    assert result.returncode == 0, result.stderr
    binary = root / BIN_REL
    assert not binary.is_symlink() and binary.read_text() == "real launcher"
    assert not Path(f"{binary}.real").exists()
    assert (root / "boot/firmware/cmdline.txt").read_text() == original


def test_takeover_leaves_other_boards_untouched(tmp_path):
    root = tmp_path / "root"
    stock_image(root, launcher=False, lcd=False)
    original = (root / "boot/firmware/cmdline.txt").read_text()
    result, log = takeover(tmp_path, root, "apply")
    assert result.returncode == 0
    assert "not a CardputerZero" in result.stdout
    assert (root / "boot/firmware/cmdline.txt").read_text() == original
    assert not log.exists()


@pytest.mark.parametrize("launcher,lcd,expected", [
    (True, True, "stock launcher active"),
    (False, True, "no launcher installed"),
    (False, False, "not a CardputerZero"),
])
def test_takeover_status(tmp_path, launcher, lcd, expected):
    root = tmp_path / "root"
    stock_image(root, launcher=launcher, lcd=lcd)
    result, _ = takeover(tmp_path, root, "status")
    assert result.stdout.strip() == expected


# ── Install + config wiring ──────────────────────────────────────────────────

def pi_menu_cases():
    text = (ROOT / "install_ragnar.sh").read_text()
    block = text[text.index('if [ "$is_pi" = true ]; then\n            case $profile_choice in'):]
    block = block[:block.index("esac")]
    return re.findall(r"^ {16}(\S+)\)$", block, re.M), block


def test_installer_cases_are_unique_and_docker_stays_reachable():
    labels, block = pi_menu_cases()
    assert sorted(labels) == ["*", "1", "2", "3", "4", "5", "6", "7"]
    assert "deploy_docker" in block.split("                6)\n")[1].split(";;")[0]
    assert "CARDPUTER_MODE=true" in block.split("                7)\n")[1].split(";;")[0]


def test_installer_menu_matches_dispatch():
    text = (ROOT / "install_ragnar.sh").read_text()
    assert '7)${CYAN} M5Stack CardputerZero' in text
    assert '6)${CYAN} Docker container' in text


def test_every_entry_point_runs_the_takeover():
    for script in ("install_ragnar.sh", "update_ragnar.sh", "installhead.sh",
                   "scripts/set_display_mode.sh"):
        assert "cardputer_takeover.sh" in (ROOT / script).read_text(), script
    assert os.access(TAKEOVER, os.X_OK)


def test_driver_is_accepted_everywhere_panels_are_listed():
    assert '"st7789v2"' in (ROOT / "epd_helper.py").read_text()
    assert "'st7789v2'" in (ROOT / "webapp_modern.py").read_text()
    assert 'value="st7789v2"' in (ROOT / "web" / "captive_portal.html").read_text()
    assert '"st7789v2|' in (ROOT / "installhead.sh").read_text()
    assert " st7789v2 " in (ROOT / "install_ragnar.sh").read_text()


def init_failing_panel(monkeypatch, epd_type):
    """Run the real init path with a panel whose init fails."""
    import shared
    detected, saved = [], []

    class Helper:
        def __init__(self, name):
            self.epd = types.SimpleNamespace(width=320, height=170)

        def init_full_update(self):
            raise RuntimeError("panel not ready")

        @staticmethod
        def auto_detect():
            detected.append(True)
            return ("epd2in13_V4", 122, 250)

    monkeypatch.setattr(shared, "EPDHelper", Helper)
    data = shared.SharedData.__new__(shared.SharedData)
    data.config = {"epd_type": epd_type}
    data._pager_mode = data._headless_mode = False
    data.save_config = lambda: saved.append(data.config["epd_type"])
    data.apply_display_profile = lambda name: True
    data.initialize_epd_display()
    return data, detected, saved


def test_failed_lcd_init_never_replaces_the_built_in_panel(monkeypatch):
    data, detected, saved = init_failing_panel(monkeypatch, "st7789v2")
    assert detected == [] and saved == []
    assert data.config["epd_type"] == "st7789v2"
    assert data.epd_helper is None
    assert (data.width, data.height) == (320, 170)


def test_other_panels_keep_their_auto_detect_fallback(monkeypatch):
    _, detected, _ = init_failing_panel(monkeypatch, "st7735s")
    assert detected == [True]


def test_display_profile_resolves_from_the_web_size_key():
    import shared
    assert shared.resolve_epd_type("1in9_cardputer") == "st7789v2"
    assert shared.DISPLAY_PROFILES["st7789v2"]["ref_width"] == 320
    assert shared.DISPLAY_PROFILES["st7789v2"]["ref_height"] == 170
