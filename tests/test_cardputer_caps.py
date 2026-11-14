"""CardputerZero expansion header, Caps and camera detection, on simulated
hardware. Pin numbers, addresses and the power sequence come from M5Stack's
own Cap apps (github.com/CardputerZero) and the board's device tree."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cardputer_caps as cc  # noqa: E402

GGA = b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\r\n"


# ── the header ───────────────────────────────────────────────────────────────

def test_header_matches_the_label_on_the_case():
    labels = [p[0] for p in cc.HEADER_PINS]
    assert labels == ["G26", "G23", "G22", "G11", "G10", "G9", "G7",
                      "5V IN", "GND", "5V OUT", "G2", "G3", "G14", "G15"]
    gpios = {p[0]: p[1] for p in cc.HEADER_PINS}
    assert gpios["G14"] == 14 and gpios["G15"] == 15 and gpios["5V OUT"] is None
    # The LCD's own lines (CS G8, DC G25) are not on the header.
    assert not {8, 25} & {p[1] for p in cc.HEADER_PINS}


@pytest.mark.parametrize("line,expected", [
    ("26: op dh pd | hi // GPIO26 = output", ("op", 1)),
    ("23: ip    pu | lo // GPIO23 = input", ("ip", 0)),
    ("14: a5    pn | hi // GPIO14 = TXD1", ("a5", 1)),
    ("", (None, None)), ("garbage", (None, None))])
def test_pinctrl_output_is_parsed(line, expected):
    assert cc.parse_pinctrl(line) == expected


# ── power rail ───────────────────────────────────────────────────────────────

def test_rail_is_switched_on_and_reported(tmp_path, monkeypatch):
    rail = tmp_path / "brightness"
    rail.write_text("0\n")
    monkeypatch.setattr(cc, "EXT5V_PATH", str(rail))
    pins = []
    monkeypatch.setattr(cc, "set_gpio", lambda gpio, high: pins.append((gpio, high)) or True)
    assert cc.ext5v_state() is False
    assert cc.power_on_cap() is True
    assert rail.read_text().strip() == "1"
    assert pins == [(26, True)]


def test_a_rail_already_on_is_left_alone(tmp_path, monkeypatch):
    rail = tmp_path / "brightness"
    rail.write_text("255\n")
    monkeypatch.setattr(cc, "EXT5V_PATH", str(rail))
    monkeypatch.setattr(cc, "set_gpio", lambda gpio, high: True)
    assert cc.power_on_cap() is True
    assert rail.read_text().strip() == "255"


def test_board_without_a_rail_is_not_touched(tmp_path, monkeypatch):
    monkeypatch.setattr(cc, "EXT5V_PATH", str(tmp_path / "missing"))
    pins = []
    monkeypatch.setattr(cc, "set_gpio", lambda gpio, high: pins.append(gpio))
    assert cc.power_on_cap() is None
    assert pins == []


def test_nothing_in_this_module_turns_the_rail_off():
    """Cutting a plugged-in Cap's supply can freeze the LCD it shares SPI with."""
    source = open(cc.__file__).read()
    assert "set_ext5v(False" not in source and "set_ext5v(0" not in source


# ── Cap detection ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ident,found", [(0xA2, True), (0xA0, True), (0xBE, True),
                                         (0x00, False), (0xFF, False), (None, False),
                                         (0x40, False)])
def test_lora_cap_is_recognised_by_the_expander_id(ident, found):
    assert cc.probe_lora_cap(lambda addr, reg: ident if (addr, reg) == (0x43, 0x01) else None) is found


@pytest.mark.parametrize("part,version,found", [(0x00, 0x14, 0x14), (0x00, 0x04, 0x04),
                                                (0x00, 0x00, None), (0xFF, 0xFF, None),
                                                (0x80, 0x14, None)])
def test_cc1101_is_recognised_by_partnum_and_version(part, version, found):
    def transfer(device, data):
        assert device == "/dev/spidev0.1"
        return [0x0F, part if data[0] == cc.CC1101_PARTNUM else version]
    assert cc.probe_cc1101(transfer) == found


def test_cc1101_probe_survives_a_missing_spi_node():
    assert cc.probe_cc1101(lambda device, data: None) is None


def fake_board(monkeypatch, tmp_path, lora=False, cc1101=None, console=False, getty=None,
               nmea=0, camera="0 : imx219 [3280x2464 10-bit RGGB] (/base/soc/i2c0mux/i2c@1/imx219@10)"):
    rail = tmp_path / "brightness"
    rail.write_text("0\n")
    monkeypatch.setattr(cc, "EXT5V_PATH", str(rail))
    monkeypatch.setattr(cc, "_identity", None)
    monkeypatch.setattr(cc, "set_gpio", lambda gpio, high: True)
    monkeypatch.setattr(cc, "probe_lora_cap", lambda: lora)
    monkeypatch.setattr(cc, "probe_cc1101", lambda: cc1101)
    monkeypatch.setattr(cc, "serial_console_on", lambda: console)
    held = [console if getty is None else getty]
    monkeypatch.setattr(cc, "serial_getty_active", lambda *a, **k: held[0])
    monkeypatch.setattr(cc, "free_gnss_uart",
                        lambda *a, **k: (held.__setitem__(0, False), (True, "freed"))[1])
    monkeypatch.setattr(cc, "lora_daemon_state",
                        lambda *a, **k: {"installed": False, "configured": False, "active": False})
    monkeypatch.setattr(cc, "probe_gnss", lambda: nmea)
    monkeypatch.setattr(cc, "detect_camera", lambda: cc.parse_camera_list(camera))
    return rail


def test_lora_gnss_cap_is_detected(monkeypatch, tmp_path):
    rail = fake_board(monkeypatch, tmp_path, lora=True, nmea=3)
    info = cc.detect()
    assert info["board"] and info["ext5v"] is True and rail.read_text().strip() == "1"
    assert info["cap"] == "lora_gnss"
    assert info["pins"]["irq"] == 23 and info["pins"]["reset"] == 26 and info["pins"]["busy"] == 22
    assert info["gnss"] == {"port": "/dev/ttyS0", "baud": 115200, "sentences": 3,
                            "console_conflict": False, "kernel_console": False, "freed": None}
    assert info["lora"] == {"installed": False, "configured": False, "active": False}
    assert info["camera"] == {"present": True, "model": "imx219", "modes": "3280x2464"}


def test_gnss_is_not_opened_while_the_console_owns_the_uart(monkeypatch, tmp_path):
    fake_board(monkeypatch, tmp_path, lora=True, console=True, nmea=99)
    info = cc.detect()
    assert info["gnss"]["console_conflict"] is True and info["gnss"]["sentences"] == 0


def test_kernel_console_alone_does_not_block_the_gnss(monkeypatch, tmp_path):
    # Only the login prompt reads the port. console= without it is harmless.
    fake_board(monkeypatch, tmp_path, lora=True, console=True, getty=False, nmea=3)
    info = cc.detect()
    assert info["gnss"]["console_conflict"] is False and info["gnss"]["sentences"] == 3
    assert info["gnss"]["kernel_console"] is True


def test_detect_frees_the_uart_when_asked(monkeypatch, tmp_path):
    fake_board(monkeypatch, tmp_path, lora=True, console=True, nmea=3)
    info = cc.detect(free_uart=True)
    assert info["gnss"]["console_conflict"] is False and info["gnss"]["sentences"] == 3
    assert info["gnss"]["freed"] == "freed"


def test_detect_leaves_the_uart_alone_without_the_gnss_cap(monkeypatch, tmp_path):
    fake_board(monkeypatch, tmp_path, cc1101=0x14, console=True)
    monkeypatch.setattr(cc, "free_gnss_uart", lambda *a, **k: pytest.fail("no GNSS Cap fitted"))
    assert cc.detect(free_uart=True)["gnss"] is None


# ── freeing the UART ─────────────────────────────────────────────────────────

class FakeSystemd:
    def __init__(self, active=True, stoppable=True):
        self.active, self.stoppable, self.calls = active, stoppable, []

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "is-active":
            return (0, "active") if self.active else (3, "inactive")
        if args[0] == "stop" and self.stoppable:
            self.active = False
        return 0, ""


@pytest.mark.parametrize("before,after", [
    ("console=serial0,115200 console=tty1 root=PARTUUID=1-02 rootwait",
     "console=tty1 root=PARTUUID=1-02 rootwait"),
    ("console=tty1 console=ttyS0,115200 quiet", "console=tty1 quiet"),
    ("console=tty1 root=/dev/mmcblk0p2", "console=tty1 root=/dev/mmcblk0p2"),
    ("console=ttyS01,9600 console=serial0", "console=ttyS01,9600"),
])
def test_strip_serial_console(before, after):
    assert cc.strip_serial_console(before, "/dev/ttyS0") == after


def test_free_gnss_uart_stops_the_prompt_and_edits_cmdline(tmp_path):
    boot = tmp_path / "boot" / "firmware"
    boot.mkdir(parents=True)
    cmdline = boot / "cmdline.txt"
    cmdline.write_text("console=serial0,115200 console=tty1 root=PARTUUID=1-02 rootwait\n")
    systemd = FakeSystemd()
    ok, message = cc.free_gnss_uart("/dev/ttyS0", root=str(tmp_path), runner=systemd)
    assert ok and "stopped" in message and "cmdline.txt" in message
    assert cmdline.read_text() == "console=tty1 root=PARTUUID=1-02 rootwait\n"
    assert (boot / "cmdline.txt.ragnar-bak").read_text().startswith("console=serial0,115200")
    assert ["stop", "serial-getty@ttyS0.service"] in systemd.calls
    assert ["mask", "serial-getty@ttyS0.service"] in systemd.calls
    # Again: nothing left to do, and the first backup is not overwritten.
    ok, message = cc.free_gnss_uart("/dev/ttyS0", root=str(tmp_path), runner=systemd)
    assert ok and message == "the port was already free"
    assert (boot / "cmdline.txt.ragnar-bak").read_text().startswith("console=serial0,115200")


def test_free_gnss_uart_reports_a_prompt_it_cannot_stop(tmp_path):
    ok, message = cc.free_gnss_uart("/dev/ttyS0", root=str(tmp_path),
                                    runner=FakeSystemd(stoppable=False))
    assert not ok and "serial-getty@ttyS0.service" in message


def test_restore_serial_console_puts_cmdline_back(tmp_path):
    boot = tmp_path / "boot" / "firmware"
    boot.mkdir(parents=True)
    original = "console=serial0,115200 console=tty1 root=x\n"
    (boot / "cmdline.txt").write_text(original)
    systemd = FakeSystemd()
    cc.free_gnss_uart("/dev/ttyS0", root=str(tmp_path), runner=systemd)
    ok, _ = cc.restore_serial_console("/dev/ttyS0", root=str(tmp_path), runner=systemd)
    assert ok and (boot / "cmdline.txt").read_text() == original
    assert ["unmask", "serial-getty@ttyS0.service"] in systemd.calls


# ── camera diagnosis ─────────────────────────────────────────────────────────

def camera_root(tmp_path, overlay=True, sensor=True):
    boot = tmp_path / "boot" / "firmware"
    boot.mkdir(parents=True)
    (boot / "config.txt").write_text("camera_auto_detect=0\n" + ("dtoverlay=imx219\n" if overlay else
                                                                 "#dtoverlay=imx219\n"))
    driver = tmp_path / "sys" / "bus" / "i2c" / "drivers" / "imx219"
    driver.mkdir(parents=True)
    (driver / "bind").write_text("")
    if sensor:
        (driver / "10-0010").mkdir()
    return str(tmp_path)


@pytest.mark.parametrize("overlay,sensor,tool,code", [
    (False, False, True, "overlay"), (True, False, True, "sensor"),
    (True, True, False, "tools"), (True, True, True, "libcamera"),
])
def test_camera_diagnosis_names_the_first_thing_missing(tmp_path, overlay, sensor, tool, code):
    found = cc.camera_diagnosis(camera_root(tmp_path, overlay, sensor), tool=tool)
    assert found["code"] == code and found["reason"] and found["fix"]


def test_detect_camera_explains_an_empty_list(tmp_path):
    found = cc.detect_camera(lambda: "No cameras available!\n", root=camera_root(tmp_path, overlay=False))
    assert found["present"] is False and found["code"] == "overlay"
    listed = "Available cameras\n0 : imx219 [3280x2464 10-bit RGGB] (/base/soc/i2c0mux/i2c@1/imx219@10)\n"
    assert cc.detect_camera(lambda: listed, root=str(tmp_path)) == {
        "present": True, "model": "imx219", "modes": "3280x2464"}


def test_subghz_nfc_cap_is_detected(monkeypatch, tmp_path):
    fake_board(monkeypatch, tmp_path, cc1101=0x14)
    monkeypatch.setattr(cc, "NFC_SPI_DEV", str(tmp_path / "spidev0.2"))
    info = cc.detect()
    assert info["cap"] == "subghz_nfc" and info["cc1101_version"] == 0x14
    assert info["pins"]["gdo0"] == 15 and info["pins"]["rf_switch"] == 14
    assert info["nfc_spi"] is False and info["gnss"] is None


def test_empty_header(monkeypatch, tmp_path):
    fake_board(monkeypatch, tmp_path, camera="No cameras available!")
    info = cc.detect()
    assert info["cap"] == "none" and info["radios"] == [] and info["cap_name"] is None
    assert info["camera"]["present"] is False


def test_other_boards_are_left_completely_alone(monkeypatch, tmp_path):
    monkeypatch.setattr(cc, "EXT5V_PATH", str(tmp_path / "missing"))
    monkeypatch.setattr(cc, "_read_text", lambda path: None)
    touched = []
    for name in ("power_on_cap", "probe_lora_cap", "probe_cc1101", "probe_gnss", "detect_camera"):
        monkeypatch.setattr(cc, name, lambda *a, _n=name, **k: touched.append(_n))
    info = cc.detect({"epd_type": "epd2in13_V4"})
    assert info["board"] is False and touched == []


# ── GNSS ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("line,ok", [
    (GGA, True),
    (b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*48\r\n", False),
    (b"\xff\xfe garbage", False), (b"$GPGGA,no,checksum\r\n", False), (b"", False)])
def test_nmea_checksum(line, ok):
    assert cc.nmea_valid(line) is ok


def test_gnss_probe_counts_sentences_and_never_writes():
    class Port:
        def __init__(self):
            self.lines = [b"noise\r\n", GGA, GGA, GGA, GGA]
            self.written = []
            self.closed = False

        def readline(self):
            return self.lines.pop(0) if self.lines else b""

        def write(self, data):
            self.written.append(data)

        def close(self):
            self.closed = True

    port = Port()
    assert cc.probe_gnss(seconds=1.0, opener=lambda: port) == 3
    assert port.written == [] and port.closed


def test_gnss_probe_on_a_silent_or_missing_port():
    silent = types.SimpleNamespace(readline=lambda: b"", close=lambda: None)
    assert cc.probe_gnss(seconds=0.2, opener=lambda: silent) == 0

    def broken():
        raise OSError("no such device")
    assert cc.probe_gnss(seconds=0.2, opener=broken) == 0


@pytest.mark.parametrize("cmdline,conflict", [
    ("console=serial0,115200 console=tty1 root=/dev/mmcblk0p2", True),
    ("console=ttyS0,115200 root=/dev/mmcblk0p2", True),
    ("console=tty1 root=/dev/mmcblk0p2 fbcon=map:99", False)])
def test_serial_console_conflict(tmp_path, cmdline, conflict):
    path = tmp_path / "cmdline"
    path.write_text(cmdline)
    assert cc.serial_console_on("/dev/ttyS0", str(path)) is conflict


# ── LoRa RF switch ───────────────────────────────────────────────────────────

def test_rf_switch_touches_only_bit_zero():
    regs = {0x05: 0b10100000, 0x03: 0b01000000, 0x07: 0b11111111}
    writes = []

    def write(addr, reg, value):
        assert addr == 0x43
        writes.append(reg)
        regs[reg] = value
        return True

    assert cc.enable_lora_rf_switch(write, lambda addr, reg: regs[reg])
    assert regs == {0x05: 0b10100001, 0x03: 0b01000001, 0x07: 0b11111110}
    assert writes == [0x05, 0x03, 0x07]            # level before direction: no glitch low


def test_rf_switch_reports_a_missing_expander():
    assert cc.enable_lora_rf_switch(lambda *a: True, lambda addr, reg: None) is False


# ── camera ───────────────────────────────────────────────────────────────────

def test_camera_list_parsing():
    out = ("Available cameras\n-----------------\n"
           "0 : imx219 [3280x2464 10-bit RGGB] (/base/soc/i2c0mux/i2c@1/imx219@10)\n"
           "    Modes: 'SRGGB10_CSI2P' : 640x480 [103.33 fps - (1000, 752)/1280x960 crop]\n")
    assert cc.parse_camera_list(out) == {"present": True, "model": "imx219", "modes": "3280x2464"}
    assert cc.parse_camera_list("No cameras available!\n")["present"] is False
    assert cc.detect_camera(lambda: (_ for _ in ()).throw(OSError("boom")))["present"] is False


# ── LoRa Cap as a Meshtastic node ────────────────────────────────────────────

def test_meshtasticd_config_uses_the_caps_wiring():
    cfg = cc.MESHTASTICD_CONFIG
    for line in ("Module: sx1262", "IRQ: 23", "Busy: 22", "Reset: 26", "gpiochip: 0",
                 "DIO2_AS_RF_SWITCH: true", "DIO3_TCXO_VOLTAGE: 3.0", "spidev: spidev0.1"):
        assert f"  {line}\n" in cfg, line
    yaml = pytest.importorskip("yaml")
    lora = yaml.safe_load(cfg)["Lora"]
    assert lora["Reset"] == 26
    # The kernel owns chip-select 1 through spidev0.1; naming it as a GPIO
    # makes meshtasticd fail to claim the pin and never find the radio.
    assert "CS" not in lora


def test_lora_daemon_state(tmp_path):
    systemd = lambda args: (0, "active")   # noqa: E731
    conf = tmp_path / "etc" / "meshtasticd" / "config.d"
    conf.mkdir(parents=True)
    state = cc.lora_daemon_state(root=str(tmp_path), runner=systemd)
    assert state["configured"] is False and state["active"] is True
    (conf / cc.MESHTASTICD_CONFIG_NAME).write_text(cc.MESHTASTICD_CONFIG)
    assert cc.lora_daemon_state(root=str(tmp_path), runner=lambda a: (3, "inactive")) == {
        "installed": state["installed"], "configured": True, "active": False}


@pytest.mark.parametrize("rail,cap,switch,ok,word", [
    (True, True, True, True, "RF switch on"),
    (None, True, True, False, "no Cap power rail"),
    (False, True, True, False, "did not switch on"),
    (True, False, True, False, "0x43"),
    (True, True, False, False, "RF switch")])
def test_prepare_lora_reports_each_failure(monkeypatch, rail, cap, switch, ok, word):
    monkeypatch.setattr(cc, "power_on_cap", lambda: rail)
    monkeypatch.setattr(cc, "probe_lora_cap", lambda: cap)
    monkeypatch.setattr(cc, "enable_lora_rf_switch", lambda: switch)
    result, message = cc.prepare_lora()
    assert result is ok and word in message


def lora_script(tmp_path, action, daemon=True):
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, RAGNAR_CARDPUTER_ROOT=str(tmp_path))
    if daemon:
        env["RAGNAR_FAKE_MESHTASTICD"] = "1"
    else:
        env["PATH"] = str(tmp_path / "emptybin") + ":/usr/bin:/bin"
        (tmp_path / "emptybin").mkdir(exist_ok=True)
        (tmp_path / "emptybin" / "apt-get").write_text("#!/bin/sh\nexit 1\n")
        (tmp_path / "emptybin" / "apt-get").chmod(0o755)
    return subprocess.run(["bash", os.path.join(root, "scripts", "cardputer_lora_meshtastic.sh"), action],
                          capture_output=True, text=True, env=env)


def test_lora_setup_writes_config_and_power_dropin_then_removes_them(tmp_path):
    out = lora_script(tmp_path, "install")
    conf = tmp_path / "etc/meshtasticd/config.d/ragnar-cardputerzero-cap-lora.yaml"
    dropin = tmp_path / "etc/systemd/system/meshtasticd.service.d/ragnar-cap.conf"
    assert conf.read_text() == cc.MESHTASTICD_CONFIG, out.stdout + out.stderr
    assert "ExecStartPre=/usr/bin/python3" in dropin.read_text()
    assert "cardputer_caps.py --prepare-lora" in dropin.read_text()
    assert "cap config: present" in lora_script(tmp_path, "status").stdout
    lora_script(tmp_path, "remove")
    assert not conf.exists() and not dropin.exists()


def test_lora_setup_without_the_daemon_changes_nothing(tmp_path):
    if os.path.exists("/usr/bin/meshtasticd") or os.path.exists("/usr/sbin/meshtasticd"):
        pytest.skip("meshtasticd is installed here")
    out = lora_script(tmp_path, "install", daemon=False)
    assert out.returncode != 0 and "meshtastic.org" in out.stdout
    assert not (tmp_path / "etc").exists()


def test_local_meshtastic_daemon_counts_as_a_node(monkeypatch):
    mn = pytest.importorskip("meshtastic_node")
    monkeypatch.setattr(mn, "_have_meshtastic", lambda: True)
    monkeypatch.setattr(mn, "_run", lambda *a, **k: (1, "", ""))
    monkeypatch.setattr(mn, "_serial_ports", lambda: [])
    monkeypatch.setattr(mn, "local_daemon", lambda: True)
    assert mn.detect()["available"] is True and mn.detect()["local_daemon"] is True
    started = []
    monkeypatch.setattr(mn._link, "start", lambda **kw: started.append(kw) or {"ok": True})
    assert mn.start() == {"ok": True}
    assert started == [{"host": "127.0.0.1:4403", "owner": "user"}]
    # No daemon and no USB node: still "plug a node in".
    monkeypatch.setattr(mn, "local_daemon", lambda: False)
    assert mn.detect()["available"] is False


# ── Cap rail without M5Stack's kernel drivers ────────────────────────────────

class FakeExpander:
    """m5ioe1.M5IOE1 stand-in holding the two register bytes the rail uses."""
    available = True
    addr = 0x4F
    regs = {}

    def __init__(self):
        outer = self

        class Bus:
            def read_byte_data(self, addr, reg):
                return FakeExpander.regs.get(reg, 0)
        self._bus = Bus()

    @staticmethod
    def _gpio_regs(io):
        assert io == 13
        return 0x10, 0x11, 0x12, 4

    def _set_gpio(self, io, level):
        FakeExpander.regs[0x10] = FakeExpander.regs.get(0x10, 0) | 0x10
        FakeExpander.regs[0x11] = (FakeExpander.regs.get(0x11, 0) & ~0x10) | (0x10 if level else 0)

    def close(self):
        pass


@pytest.fixture
def plain_kernel(monkeypatch, tmp_path):
    monkeypatch.setattr(cc, "EXT5V_PATH", str(tmp_path / "missing"))
    FakeExpander.regs = {0x10: 0x03, 0x11: 0x01}          # other pins in use
    monkeypatch.setitem(sys.modules, "m5ioe1", types.SimpleNamespace(M5IOE1=FakeExpander))
    monkeypatch.setattr(cc, "set_gpio", lambda gpio, high: True)
    yield
    cc.allow_expander(None)


def test_rail_is_switched_through_the_expander_on_a_plain_kernel(plain_kernel):
    cc.allow_expander({"epd_type": "st7789v2"})
    assert cc.ext5v_state() is False
    assert cc.power_on_cap() is True
    assert FakeExpander.regs == {0x10: 0x13, 0x11: 0x11}   # only IO13's bits changed


def test_expander_is_never_touched_on_another_board(plain_kernel):
    """0x4F is a common temperature-sensor address: writing there elsewhere
    could reconfigure someone's sensor."""
    cc.allow_expander({"epd_type": "epd2in13_V4"})
    before = dict(FakeExpander.regs)
    assert cc.ext5v_state() is None and cc.power_on_cap() is None
    assert cc.set_ext5v(True) is False
    assert FakeExpander.regs == before


def test_kernel_rail_control_wins_over_the_expander(monkeypatch, tmp_path, plain_kernel):
    rail = tmp_path / "brightness"
    rail.write_text("0\n")
    monkeypatch.setattr(cc, "EXT5V_PATH", str(rail))
    cc.allow_expander({"epd_type": "st7789v2"})
    before = dict(FakeExpander.regs)
    assert cc.power_on_cap() is True and rail.read_text().strip() == "1"
    assert FakeExpander.regs == before


# ── Caps are not hot-swappable: identify once per start ──────────────────────

def counting_probes(monkeypatch, lora=False, cc1101=None):
    calls = {"lora": 0, "cc1101": 0}
    state = {"lora": lora, "cc1101": cc1101}

    def probe_lora():
        calls["lora"] += 1
        return state["lora"]

    def probe_cc():
        calls["cc1101"] += 1
        return state["cc1101"]

    monkeypatch.setattr(cc, "_identity", None)
    monkeypatch.setattr(cc, "probe_lora_cap", probe_lora)
    monkeypatch.setattr(cc, "probe_cc1101", probe_cc)
    return calls, state


def test_a_found_cap_is_never_probed_again(monkeypatch):
    calls, state = counting_probes(monkeypatch, lora=True)
    assert cc.identify_cap() == ("lora_gnss", None)
    state["lora"] = False                      # even if the bus stops answering
    for force in (False, True, True):
        assert cc.identify_cap(force=force) == ("lora_gnss", None)
    assert calls == {"lora": 1, "cc1101": 0}


def test_cc1101_cap_identity_is_kept_too(monkeypatch):
    calls, state = counting_probes(monkeypatch, cc1101=0x14)
    assert cc.identify_cap() == ("subghz_nfc", 0x14)
    state["cc1101"] = None
    assert cc.identify_cap(force=True) == ("subghz_nfc", 0x14)
    assert calls == {"lora": 1, "cc1101": 1}


def test_an_empty_header_is_only_looked_at_again_when_asked(monkeypatch):
    calls, state = counting_probes(monkeypatch)
    assert cc.identify_cap() == ("none", None)
    assert cc.identify_cap() == ("none", None)
    assert calls == {"lora": 1, "cc1101": 1}           # no background re-probing
    state["lora"] = True
    assert cc.identify_cap(force=True) == ("lora_gnss", None)


def test_detect_reuses_the_identity(monkeypatch, tmp_path):
    fake_board(monkeypatch, tmp_path, lora=True, nmea=1)
    calls, _ = counting_probes(monkeypatch, lora=True)
    for _ in range(3):
        assert cc.detect()["cap"] == "lora_gnss"
    assert calls["lora"] == 1
