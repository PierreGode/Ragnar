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


def fake_board(monkeypatch, tmp_path, lora=False, cc1101=None, console=False,
               nmea=0, camera="0 : imx219 [3280x2464 10-bit RGGB] (/base/soc/i2c0mux/i2c@1/imx219@10)"):
    rail = tmp_path / "brightness"
    rail.write_text("0\n")
    monkeypatch.setattr(cc, "EXT5V_PATH", str(rail))
    monkeypatch.setattr(cc, "set_gpio", lambda gpio, high: True)
    monkeypatch.setattr(cc, "probe_lora_cap", lambda: lora)
    monkeypatch.setattr(cc, "probe_cc1101", lambda: cc1101)
    monkeypatch.setattr(cc, "serial_console_on", lambda: console)
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
                            "console_conflict": False}
    assert info["camera"] == {"present": True, "model": "imx219", "modes": "3280x2464"}


def test_gnss_is_not_opened_while_the_console_owns_the_uart(monkeypatch, tmp_path):
    fake_board(monkeypatch, tmp_path, lora=True, console=True, nmea=99)
    info = cc.detect()
    assert info["gnss"]["console_conflict"] is True and info["gnss"]["sentences"] == 0


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
    for line in ("Module: sx1262", "CS: 7", "IRQ: 23", "Busy: 22", "Reset: 26",
                 "DIO2_AS_RF_SWITCH: true", "DIO3_TCXO_VOLTAGE: 3.0", "spidev: spidev0.1"):
        assert f"  {line}\n" in cfg, line
    yaml = pytest.importorskip("yaml")
    assert yaml.safe_load(cfg)["Lora"]["Reset"] == 26


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
