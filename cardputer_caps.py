#!/usr/bin/env python3
# cardputer_caps.py
"""
The M5Stack CardputerZero's expansion header, the "Cap" modules that plug
into it, and the built-in camera.

The header is the 14-pin socket on the top edge. A Cap is powered from the
board's switched 5 V rail and shares SPI0 with the LCD:

    G26   G23   G22   G11   G10   G9    G7
    5VIN  GND   5VOUT G2    G3    G14   G15
                      SDA   SCL   TX    RX

Caps this module knows (pins as M5Stack's own apps drive them):

  LoRa + GNSS   SX1262 on SPI0 CS1 (/dev/spidev0.1), IRQ G23, RESET G26,
                BUSY G22, RF switch on a PI4IOE5V6408 expander (I2C 0x43,
                P0 high). ATGM336H GNSS on the UART (/dev/ttyS0, 115200).
  Sub-GHz + NFC CC1101 on SPI0 CS1 (/dev/spidev0.1), GDO0 G15, RF switch
                G14, POWER_EN G26. ST25R3916 NFC on SPI0 CS2 (G22, needs the
                spi0-spidev2-gpio22 overlay), IRQ G23.

The SPI, I2C and UART lines pass through level shifters that are powered
from the Cap rail, so with the rail off the header is electrically dead.

Power. A Cap gets 5 V only while /sys/class/leds/ext_5v_out/brightness is
non-zero (the kernel exposes the rail switch as an LED). Ragnar turns the
rail on and LEAVES it on: a Cap shares SPI with the LCD, and cutting its
supply while it is plugged in can freeze the panel.

Detection is read-only apart from that rail and G26 (driven high: it is the
CC1101 Cap's power enable and the SX1262's reset, and high is the working
state for both). Nothing is transmitted.

CLI:  sudo python3 cardputer_caps.py                 what is attached
      sudo python3 cardputer_caps.py --json
      sudo python3 cardputer_caps.py --prepare-lora  power + RF switch for meshtasticd
"""

import glob
import json
import logging
import os
import shutil
import subprocess
import sys
import time

try:
    from logger import Logger
    logger = Logger(name="cardputer_caps.py", level=logging.INFO)
except Exception:  # standalone / CLI use
    logger = logging.getLogger("cardputer_caps")

# ── The header ───────────────────────────────────────────────────────────────
# (label printed on the case, BCM GPIO or None, usual function)
HEADER_PINS = [
    # top row, left to right
    # G26/G23 reach the header through a switch that can route USB D+/D-
    # there instead (expander pin PYG1_HAT_SW; low = GPIO, the default).
    ("G26", 26, "GPIO / Cap power enable (or USB D+)"),
    ("G23", 23, "GPIO / Cap IRQ (or USB D-)"),
    ("G22", 22, "GPIO / SPI0 CS2 with overlay"),
    ("G11", 11, "SPI0 SCLK (shared with the LCD)"),
    ("G10", 10, "SPI0 MOSI (shared with the LCD)"),
    ("G9", 9, "SPI0 MISO"),
    ("G7", 7, "SPI0 CS1"),
    # bottom row, left to right
    ("5V IN", None, "5 V input"),
    ("GND", None, "Ground"),
    ("5V OUT", None, "Switched 5 V output (ext_5v_out)"),
    ("G2", 2, "I2C1 SDA (shared with on-board chips)"),
    ("G3", 3, "I2C1 SCL (shared with on-board chips)"),
    ("G14", 14, "UART TX"),
    ("G15", 15, "UART RX"),
]
# Pins nothing on the board itself uses: free for plain GPIO work.
FREE_GPIOS = (26, 23, 22, 7, 14, 15)

EXT5V_PATH = os.environ.get("RAGNAR_CAP_EXT5V", "/sys/class/leds/ext_5v_out/brightness")
CAP_POWER_GPIO = 26
I2C_BUS = 1
CAP_SPI_DEV = "/dev/spidev0.1"
NFC_SPI_DEV = "/dev/spidev0.2"
NFC_OVERLAY = "spi0-spidev2-gpio22-overlay"
GNSS_PORT = os.environ.get("RAGNAR_CAP_GNSS_PORT", "/dev/ttyS0")
GNSS_BAUD = 115200

# PI4IOE5V6408 I/O expander on the LoRa Cap
PI4IOE_ADDR = 0x43
PI4IOE_REG_ID = 0x01          # bits 7..5 manufacturer (101), 4..2 firmware rev
PI4IOE_MANUFACTURER = 0b101
I2C_SLAVE = 0x0703

# CC1101 status registers, read with the burst bit set
CC1101_PARTNUM = 0x30 | 0xC0
CC1101_VERSION = 0x31 | 0xC0
CC1101_VERSIONS = (0x04, 0x14, 0x17, 0x18)   # chip revisions seen in the field

CAP_NONE = "none"
CAP_LORA_GNSS = "lora_gnss"
CAP_SUBGHZ_NFC = "subghz_nfc"

CAP_INFO = {
    CAP_LORA_GNSS: {
        "name": "Cap LoRa-1262 + GNSS",
        "radios": ["SX1262 LoRa 868-923 MHz", "ATGM336H GNSS"],
        "pins": {"spi": CAP_SPI_DEV, "irq": 23, "reset": 26, "busy": 22,
                 "expander": "I2C 0x43", "gnss": f"{GNSS_PORT} @ {GNSS_BAUD}"},
    },
    CAP_SUBGHZ_NFC: {
        "name": "Cap CC1101 Sub-GHz + NFC",
        "radios": ["CC1101 315-915 MHz", "ST25R3916 NFC"],
        "pins": {"spi": CAP_SPI_DEV, "gdo0": 15, "rf_switch": 14, "power_enable": 26,
                 "nfc_spi": NFC_SPI_DEV, "nfc_irq": 23},
    },
}


# ── Small I/O helpers (each replaceable in tests) ────────────────────────────

def _read_text(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def is_cardputer_zero(config=None):
    """True on a CardputerZero: the configured panel, the Cap power rail the
    board's device tree creates, or the model string."""
    if config and config.get("epd_type") == "st7789v2":
        return True
    if os.path.exists(EXT5V_PATH):
        return True
    model = (_read_text("/proc/device-tree/model") or "").lower()
    return "cardputer" in model


# Without M5Stack's kernel drivers there is no ext_5v_out control file. The
# rail is then switched directly: it is pin IO13 (HAT_EN) of the board's
# M5IOE1 I/O expander, the chip m5ioe1.py already drives for the screen.
EXT5V_EXPANDER_IO = 13
_use_expander = False        # set by detect()/power_on_cap() on a known CardputerZero


def _expander():
    """The M5IOE1 expander, or None when it cannot be used (not allowed for
    this board, not answering, or owned by the kernel driver)."""
    if not _use_expander:
        return None
    try:
        import m5ioe1
        exp = m5ioe1.M5IOE1()
        return exp if exp.available else None
    except Exception as e:
        logger.debug(f"M5IOE1 expander unavailable: {e}")
        return None


def _expander_rail_state(exp):
    direction_reg, out_reg, _, bit = exp._gpio_regs(EXT5V_EXPANDER_IO)
    is_output = exp._bus.read_byte_data(exp.addr, direction_reg) >> bit & 1
    level = exp._bus.read_byte_data(exp.addr, out_reg) >> bit & 1
    return bool(is_output and level)


def ext5v_state(path=None):
    """True/False for the Cap 5 V rail, None when the board has no such rail."""
    value = _read_text(path or EXT5V_PATH)
    if value is None:
        exp = _expander()
        if exp is None:
            return None
        try:
            return _expander_rail_state(exp)
        except Exception as e:
            logger.debug(f"Cap power: expander read failed: {e}")
            return None
        finally:
            exp.close()
    try:
        return int(value) > 0
    except ValueError:
        return None


def set_ext5v(on, path=None):
    """Switch the Cap 5 V rail. Returns True when the rail reports the state."""
    path = path or EXT5V_PATH
    if not os.path.exists(path):
        exp = _expander()
        if exp is None:
            return False
        try:
            exp._set_gpio(EXT5V_EXPANDER_IO, bool(on))
            return _expander_rail_state(exp) is bool(on)
        except Exception as e:
            logger.warning(f"Cap power: expander write failed: {e}")
            return False
        finally:
            exp.close()
    try:
        with open(path, "w") as f:
            f.write("1\n" if on else "0\n")
    except OSError as e:
        logger.warning(f"Cap power: cannot write {path}: {e}")
        return False
    return ext5v_state(path) is bool(on)


def saved_config():
    """Ragnar's saved settings (for the CLI, which has no SharedData)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "shared_config.json")
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def set_gpio(gpio, high):
    """Drive a header GPIO as an output with `pinctrl` (raspi-utils), as
    M5Stack's Cap apps do. Returns True on success."""
    tool = shutil.which("pinctrl")
    if not tool:
        return False
    try:
        result = subprocess.run([tool, "set", str(gpio), "op", "dh" if high else "dl"],
                                capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception as e:
        logger.debug(f"pinctrl set {gpio} failed: {e}")
        return False


def read_gpio(gpio):
    """(function, level) of a header GPIO from `pinctrl get`, e.g. ('op', 1),
    ('ip', 0), ('a0', 1); (None, None) when it cannot be read."""
    tool = shutil.which("pinctrl")
    if not tool:
        return None, None
    try:
        out = subprocess.run([tool, "get", str(gpio)], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        return None, None
    return parse_pinctrl(out)


def parse_pinctrl(line):
    """Parse one `pinctrl get N` line: '26: op dh pd | hi // GPIO26 = output'."""
    try:
        left, _, right = line.partition("|")
        fields = left.split(":", 1)[1].split()
        function = fields[0] if fields else None
        level = None
        state = right.split("//")[0].strip().lower()
        if state.startswith("hi"):
            level = 1
        elif state.startswith("lo"):
            level = 0
        return function, level
    except (IndexError, AttributeError):
        return None, None


def i2c_read_byte(address, register, bus=I2C_BUS):
    """One register byte from an I2C device, or None if it does not answer."""
    try:
        import fcntl
        fd = os.open(f"/dev/i2c-{bus}", os.O_RDWR)
    except OSError:
        return None
    try:
        fcntl.ioctl(fd, I2C_SLAVE, address)
        os.write(fd, bytes([register]))
        data = os.read(fd, 1)
        return data[0] if len(data) == 1 else None
    except OSError:
        return None
    finally:
        os.close(fd)


def i2c_write_byte(address, register, value, bus=I2C_BUS):
    try:
        import fcntl
        fd = os.open(f"/dev/i2c-{bus}", os.O_RDWR)
    except OSError:
        return False
    try:
        fcntl.ioctl(fd, I2C_SLAVE, address)
        os.write(fd, bytes([register, value & 0xFF]))
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def spi_transfer(device, data, speed_hz=500000):
    """One SPI transaction on a spidev node; the reply bytes, or None."""
    try:
        import spidev
    except ImportError:
        return None
    try:
        bus, cs = os.path.basename(device).replace("spidev", "").split(".")
        spi = spidev.SpiDev()
        spi.open(int(bus), int(cs))
    except Exception:
        return None
    try:
        spi.max_speed_hz = speed_hz
        spi.mode = 0
        return spi.xfer2(list(data))
    except Exception:
        return None
    finally:
        try:
            spi.close()
        except Exception:
            pass


# ── Detection ────────────────────────────────────────────────────────────────

def probe_lora_cap(read_byte=i2c_read_byte):
    """The LoRa Cap answers on I2C 0x43 with the PI4IOE5V6408's ID. The ID is
    checked because 0x43 is a common address (a Waveshare UPS HAT's INA219
    lives there too)."""
    ident = read_byte(PI4IOE_ADDR, PI4IOE_REG_ID)
    return ident is not None and (ident >> 5) == PI4IOE_MANUFACTURER


def probe_cc1101(transfer=spi_transfer):
    """The CC1101 answers PARTNUM 0x00 and a known VERSION. A floating bus
    reads 0x00 or 0xFF for both, which is rejected."""
    part = transfer(CAP_SPI_DEV, [CC1101_PARTNUM, 0x00])
    version = transfer(CAP_SPI_DEV, [CC1101_VERSION, 0x00])
    if not part or not version or len(part) < 2 or len(version) < 2:
        return None
    if part[1] == 0x00 and version[1] in CC1101_VERSIONS:
        return version[1]
    return None


def serial_console_on(port=None, cmdline_path="/proc/cmdline"):
    """True when the kernel console owns the UART the GNSS receiver uses."""
    cmdline = _read_text(cmdline_path) or ""
    name = os.path.basename(port or GNSS_PORT)
    return f"console={name}" in cmdline or "console=serial0" in cmdline


def probe_gnss(port=None, baud=GNSS_BAUD, seconds=2.0, opener=None):
    """Listen for NMEA on the UART. Returns the number of valid sentences
    seen (0 = silent). Never writes to the port."""
    port = port or GNSS_PORT
    if opener is None:
        try:
            import serial
        except ImportError:
            return 0
        if not os.path.exists(port):
            return 0

        def opener():
            return serial.Serial(port, baud, timeout=0.3)
    try:
        ser = opener()
    except Exception as e:
        logger.debug(f"GNSS probe: cannot open {port}: {e}")
        return 0
    seen = 0
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            line = ser.readline()
            if line and nmea_valid(line):
                seen += 1
                if seen >= 3:
                    break
    except Exception as e:
        logger.debug(f"GNSS probe read failed: {e}")
    finally:
        try:
            ser.close()
        except Exception:
            pass
    return seen


def nmea_valid(line):
    """True for a '$..*hh' NMEA sentence whose checksum matches."""
    if isinstance(line, bytes):
        try:
            line = line.decode("ascii")
        except UnicodeDecodeError:
            return False
    line = line.strip()
    if not line.startswith("$") or "*" not in line:
        return False
    body, _, checksum = line[1:].rpartition("*")
    value = 0
    for ch in body:
        value ^= ord(ch)
    try:
        return value == int(checksum[:2], 16)
    except ValueError:
        return False


def detect_camera(runner=None):
    """The camera libcamera sees, e.g. {'present': True, 'model': 'imx219',
    'modes': '3280x2464'}; present False when there is none or no tool."""
    tool = shutil.which("rpicam-hello") or shutil.which("libcamera-hello")
    if runner is None:
        if not tool:
            return {"present": False, "reason": "rpicam-apps not installed"}

        def runner():
            return subprocess.run([tool, "--list-cameras"], capture_output=True,
                                  text=True, timeout=20).stdout
    try:
        out = runner() or ""
    except Exception as e:
        return {"present": False, "reason": str(e)}
    return parse_camera_list(out)


def parse_camera_list(out):
    """Parse `rpicam-hello --list-cameras` output."""
    import re
    match = re.search(r"^\s*\d+\s*:\s*(\S+)\s*\[(\d+x\d+)", out, re.M)
    if not match:
        return {"present": False, "reason": "no camera reported"}
    return {"present": True, "model": match.group(1), "modes": match.group(2)}


def allow_expander(config=None):
    """Let the Cap rail be switched through the M5IOE1 expander. Only for a
    unit whose settings say it is a CardputerZero: the expander's address is
    also used by common temperature sensors on other boards."""
    global _use_expander
    _use_expander = bool(config and config.get("epd_type") == "st7789v2")
    return _use_expander


def power_on_cap():
    """Bring a plugged-in Cap up: 5 V rail on, G26 high. Idempotent, and the
    rail is never switched back off (see the module docstring). Returns the
    rail state afterwards (None = this board has no rail)."""
    state = ext5v_state()
    if state is None:
        return None
    if not state:
        set_ext5v(True)
        time.sleep(0.15)          # let the Cap's regulators settle
    set_gpio(CAP_POWER_GPIO, True)
    time.sleep(0.05)
    return ext5v_state()


def enable_lora_rf_switch(write_byte=i2c_write_byte, read_byte=i2c_read_byte):
    """Set expander P0 as an output driven high: the LoRa Cap's RF path.
    Only bit 0 of each register is touched."""
    ok = True
    for register, set_bit in ((0x05, True),    # output state: P0 high
                              (0x03, True),    # direction: P0 output
                              (0x07, False)):  # high-impedance: P0 driven
        current = read_byte(PI4IOE_ADDR, register)
        if current is None:
            return False
        value = (current | 0x01) if set_bit else (current & ~0x01)
        if value != current:
            ok = write_byte(PI4IOE_ADDR, register, value) and ok
    return ok


# ── LoRa: Meshtastic on the Cap's SX1262 ─────────────────────────────────────
# meshtasticd (the Linux-native Meshtastic daemon) drives the radio; Ragnar
# talks to it over TCP like any other node. Values are the ones M5Stack's LoRa
# app uses: DIO2 switches the antenna, the TCXO runs from DIO3 at 3.0 V.
MESHTASTICD_CONFIG_NAME = "ragnar-cardputerzero-cap-lora.yaml"
MESHTASTICD_CONFIG = """\
# Written by Ragnar (scripts/cardputer_lora_meshtastic.sh).
# M5Stack CardputerZero + Cap LoRa-1262: SX1262 on SPI0 CS1.
Lora:
  Module: sx1262
  CS: 7
  IRQ: 23
  Busy: 22
  Reset: 26
  DIO2_AS_RF_SWITCH: true
  DIO3_TCXO_VOLTAGE: 3.0
  spidev: spidev0.1
"""


def prepare_lora():
    """Power the Cap and close its RF path, ready for meshtasticd to open the
    SX1262. Run before the daemon starts (systemd ExecStartPre). Returns
    (ok, message)."""
    rail = power_on_cap()
    if rail is None:
        return False, "no Cap power rail on this board"
    if not rail:
        return False, "the Cap power rail did not switch on"
    if not probe_lora_cap():
        return False, "no LoRa Cap on the header (I2C 0x43 does not answer)"
    if not enable_lora_rf_switch():
        return False, "could not set the Cap's RF switch (I2C 0x43)"
    return True, "LoRa Cap powered, RF switch on"


def detect(config=None, power=True, probe_serial=True, camera=True):
    """What is on the header and whether the camera answers.

    Returns a dict: board, ext5v, cap ('none' / 'lora_gnss' / 'subghz_nfc'),
    cap_name, radios, pins, gnss (sentences heard, console conflict), nfc_spi,
    camera. With power=True the Cap rail is switched on first, because an
    unpowered Cap cannot answer. probe_serial=False skips listening on the
    UART (pass it when the GPS reader already has the port open: two readers
    would each get half the bytes); camera=False skips the camera query."""
    allow_expander(config)
    result = {"board": is_cardputer_zero(config), "ext5v": None, "cap": CAP_NONE,
              "cap_name": None, "radios": [], "pins": {}, "gnss": None,
              "nfc_spi": None, "camera": None, "checked": time.time()}
    if not result["board"]:
        return result
    result["ext5v"] = power_on_cap() if power else ext5v_state()
    if probe_lora_cap():
        result["cap"] = CAP_LORA_GNSS
    else:
        version = probe_cc1101()
        if version is not None:
            result["cap"] = CAP_SUBGHZ_NFC
            result["cc1101_version"] = version
    info = CAP_INFO.get(result["cap"])
    if info:
        result["cap_name"] = info["name"]
        result["radios"] = list(info["radios"])
        result["pins"] = dict(info["pins"])
    if result["cap"] == CAP_LORA_GNSS:
        console = serial_console_on()
        heard = 0 if (console or not probe_serial) else probe_gnss()
        result["gnss"] = {"port": GNSS_PORT, "baud": GNSS_BAUD,
                          "sentences": heard, "console_conflict": console}
    if result["cap"] == CAP_SUBGHZ_NFC:
        result["nfc_spi"] = os.path.exists(NFC_SPI_DEV)
    result["camera"] = detect_camera() if camera else None
    return result


def header_state():
    """Live function and level of every GPIO on the header."""
    rows = []
    for label, gpio, role in HEADER_PINS:
        function, level = read_gpio(gpio) if gpio is not None else (None, None)
        rows.append({"label": label, "gpio": gpio, "role": role,
                     "function": function, "level": level})
    return rows


def main():
    config = saved_config()
    allow_expander(config)
    if "--prepare-lora" in sys.argv:
        ok, message = prepare_lora()
        print(message)
        return 0 if ok else 1
    if "--meshtasticd-config" in sys.argv:
        sys.stdout.write(MESHTASTICD_CONFIG)
        return 0
    info = detect(config)
    if "--json" in sys.argv:
        info["header"] = header_state()
        print(json.dumps(info, indent=2))
        return 0
    if not info["board"]:
        print("Not a CardputerZero (no Cap power rail, panel or model string).")
        return 1
    rail = {True: "on", False: "off", None: "not present"}[info["ext5v"]]
    print(f"Cap 5 V rail: {rail}")
    print(f"Cap: {info['cap_name'] or 'none detected'}")
    for radio in info["radios"]:
        print(f"  - {radio}")
    if info["gnss"]:
        g = info["gnss"]
        if g["console_conflict"]:
            print(f"  GNSS: {g['port']} is the serial console; remove console=serial0 "
                  "from cmdline.txt and reboot")
        else:
            print(f"  GNSS: {g['sentences']} NMEA sentence(s) heard on {g['port']}")
    if info["cap"] == CAP_SUBGHZ_NFC and not info["nfc_spi"]:
        print(f"  NFC: {NFC_SPI_DEV} missing; add dtoverlay={NFC_OVERLAY} to config.txt and reboot")
    cam = info["camera"] or {}
    print("Camera: " + (f"{cam.get('model')} ({cam.get('modes')})" if cam.get("present")
                        else f"not found ({cam.get('reason', 'unknown')})"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
