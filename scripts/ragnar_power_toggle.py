#!/usr/bin/env python3
"""
Pi5 power-button mode toggle for an all-in-one Ragnar box.

A single short press of the Raspberry Pi 5 on-board power button flips between
Ragnar (recon suite, dashboard on :8000) and the built-in Pwnagotchi mode
(bettercap + pwnagotchi, web UI on :8080). Ragnar and Pwnagotchi never run at
the same time, so one button is enough to toggle: the listener checks which is
active and runs the opposite swap.

This complements scripts/ragnar_swap_button.py (GPIO KEY1 / PiSugar, which only
swaps Pwnagotchi -> Ragnar). This listener runs in BOTH modes and swaps either
direction, using the Pi 5's dedicated power button.

Mechanics:
  * The power button is the kernel "pwr_button" input device
    (/dev/input/by-path/platform-pwr_button-event), which emits a KEY_POWER
    event. systemd-logind must be set HandlePowerKey=ignore (the installer
    writes /etc/systemd/logind.conf.d/ragnar-power-toggle.conf) so the press no
    longer powers the Pi off. A long-hold (~10s) still triggers the firmware
    hard power-off, which is left intact as an emergency off.
  * Events are read straight from the evdev node with the standard library only
    (no python3-evdev dependency).
  * Swaps are launched with systemd-run transient units so the stop/start
    sequence survives this process being torn down with the cgroup it stops,
    exactly as ragnar_swap_button.py does.

Installed by scripts/install_power_button.sh (symlinked to
/usr/local/bin/ragnar-power-toggle) and managed by ragnar-power-toggle.service.
"""

import glob
import logging
import os
import struct
import subprocess
import sys
import time

logging.basicConfig(level=logging.INFO, format="[ragnar-power] %(message)s")
log = logging.getLogger()

# struct input_event on 64-bit Linux:
#   struct timeval { long tv_sec; long tv_usec; }  -> 16 bytes
#   __u16 type; __u16 code; __s32 value            ->  8 bytes
EV_FORMAT = "llHHi"
EV_SIZE = struct.calcsize(EV_FORMAT)  # 24
EV_KEY = 0x01
KEY_POWER = 116

# Seconds between accepted presses. This debounce is a hard safety rail:
# rapidly toggling the Wi-Fi adapter between managed and monitor mode can wedge
# the driver and knock the box off the network, so presses inside the window
# are refused rather than queued.
COOLDOWN = 20

BYPATH = "/dev/input/by-path/platform-pwr_button-event"


def find_power_device():
    """Return the evdev node for the pwr_button, resiliently."""
    if os.path.exists(BYPATH):
        return os.path.realpath(BYPATH)
    # Fallback: scan /proc/bus/input/devices for the pwr_button handler.
    try:
        with open("/proc/bus/input/devices") as f:
            block = ""
            for line in f:
                if line.strip() == "":
                    if "pwr_button" in block:
                        for tok in block.split():
                            if tok.startswith("event"):
                                return "/dev/input/" + tok
                    block = ""
                else:
                    block += line
    except OSError:
        pass
    for ev in sorted(glob.glob("/dev/input/event*")):
        return ev
    return "/dev/input/event0"


def current_mode():
    """'ragnar' if ragnar.service is active, else 'pwn'."""
    r = subprocess.run(
        ["systemctl", "is-active", "ragnar.service"],
        capture_output=True, text=True,
    )
    return "ragnar" if r.stdout.strip() == "active" else "pwn"


def run_swap(unit, cmd):
    """Launch a swap as a transient systemd unit so it outlives this process."""
    subprocess.run(["systemctl", "reset-failed", unit],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(
        ["systemd-run", "--no-block", "--collect", "--unit=" + unit,
         "bash", "-c", cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def toggle():
    if current_mode() == "ragnar":
        log.info("Power button: Ragnar -> Pwnagotchi")
        run_swap(
            "ragnar-to-pwn-swap",
            "systemctl stop ragnar.service && sleep 3 "
            "&& systemctl start bettercap.service && sleep 3 "
            "&& systemctl start pwnagotchi.service",
        )
    else:
        log.info("Power button: Pwnagotchi -> Ragnar")
        run_swap(
            "pwn-to-ragnar-swap",
            "systemctl stop pwnagotchi.service "
            "&& systemctl stop bettercap.service && sleep 2 "
            "&& systemctl start ragnar.service",
        )


def main():
    dev = find_power_device()
    log.info("Listening on %s for KEY_POWER (short press = toggle mode)", dev)
    last = 0.0
    while True:
        try:
            with open(dev, "rb") as f:
                while True:
                    data = f.read(EV_SIZE)
                    if len(data) < EV_SIZE:
                        continue
                    _sec, _usec, etype, code, value = struct.unpack(EV_FORMAT, data)
                    if etype == EV_KEY and code == KEY_POWER and value == 1:
                        log.info("power key pressed")
                        now = time.time()
                        if now - last < COOLDOWN:
                            log.info("ignored (cooldown %ss)", COOLDOWN)
                            continue
                        last = now
                        toggle()
        except FileNotFoundError:
            log.error("power device %s missing; retrying in 5s", dev)
            time.sleep(5)
            dev = find_power_device()
        except Exception as e:  # keep the listener alive no matter what
            log.error("listener error: %s; reopening in 5s", e)
            time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
