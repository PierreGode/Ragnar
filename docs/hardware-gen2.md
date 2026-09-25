# Ragnar Gen 2 — Minimal Hardware Requirements

> In collaboration with [Solarflere](https://www.instagram.com/solarflere?igsh=MXR6bjMyMmRzZzE4dg==).

The **Gen 2** reference build is a compact, self-contained Ragnar node: a headless
Pi Zero 2 W with an on-board status display, wired networking, and a Wi-Fi 6E
monitor-mode radio. It is the smallest hardware set that runs the full Ragnar
stack — web UI, recon tooling, the WiFi Spectrum Analyzer, and WiFi Defense
(802.11 WIDS) — without a laptop attached.

## Bill of Materials

| # | Component | Purpose | Notes |
|---|-----------|---------|-------|
| 1 | **Raspberry Pi Zero 2 W** | Main compute (quad-core, 512 MB) | 64-bit Raspberry Pi OS (Trixie / kernel 6.6+). The whole node runs on this. |
| 2 | **Waveshare 1.44" LCD Display HAT** | On-device status display + controls | ST7735S panel, **3 keys + joystick**. Set `"epd_type": "st7735s"`. Drives the SPECTRUM / status cards on-device. |
| 3 | **Waveshare Ethernet/USB HAT** | Wired uplink + extra USB | Gives the Zero a stable RJ45 management link (no reliance on the on-board Wi-Fi) and a USB-A port for the dongle. |
| 4 | **Alfa AWUS036AXM** | Wi-Fi 6E monitor/scan radio | `mt7921u` driver, tri-band **2.4 / 5 / 6 GHz**. Powers the WiFi Analyzer and WiFi Defense monitor mode. Appears as `wlan1`. |

### Why these parts

- **Pi Zero 2 W** — the target platform Ragnar's ARM/PiWheels path and hardware
  auto-detection are tuned for. The quad-core A53 handles the passive scan +
  IDW heatmap workloads that the original single-core Zero could not.
- **1.44" LCD HAT** — unlike the e-Paper HATs, it refreshes fast enough for the
  live WiFi Spectrum Analyzer card and has a joystick for menu navigation. The
  key/joystick map is in [Display Buttons & Joystick Reference](DISPLAY_CONTROLS.md).
- **Ethernet/USB HAT** — the Zero 2 W has no RJ45 and only one micro-USB data
  port. This HAT provides a wired management plane (so the monitoring Wi-Fi radio
  can stay in monitor mode without dropping your SSH/web session) plus the
  full-size USB-A port the Alfa dongle plugs into.
- **Alfa AWUS036AXM** — the reference radio for Ragnar's tri-band features. It is
  the only adapter in the current lineup validated for 6 GHz passive scanning and
  monitor-mode capture. See [WiFi Analyzer](wifi-analyzer.md) and
  [WiFi Defense](wifi-defense.md).

## Assembly notes

1. Stack the **Ethernet/USB HAT** on the Pi's 40-pin header (it passes the header
   through), then mount the **1.44" LCD HAT** on top. Confirm both share the GPIO
   pins cleanly — the LCD HAT uses SPI + a handful of GPIOs for its keys/joystick.
   Connect the included micro USB bridge to the data micro USB port on the Pi and right
   above it to the micro USB port on the Ethernet/USB hat. 
3. Plug the **Alfa AWUS036AXM** into the Ethernet/USB HAT's USB-A port.
4. Connect the RJ45 to your management network for the initial install and SSH.
5. Enable **SPI** and **I2C** via `raspi-config` (needed for the LCD HAT), then
   run the installer — see [INSTALL.md](INSTALL.md).

## Software configuration

- Display: set `"epd_type": "st7735s"` in the config, or pick it from the web UI
  under **Display settings** (auto-detects and restarts the service).
- Wi-Fi radio: the Alfa comes up as `wlan1`; monitor mode is set up with plain
  `iw` (a separate `ragmon0` vif where the driver allows). No aircrack-ng needed.
- Everything else is handled by `install_ragnar.sh` — the installer detects the
  Pi Zero 2 W hardware profile automatically.

## Power

- Budget for the Zero 2 W **plus** the Alfa AWUS036AXM, which is a power-hungry
  tri-band radio. Use a **5 V / 2.5 A+** supply. Under-powering shows up as the
  dongle dropping off the bus mid-scan.
- Optional: a [PiSugar UPS](https://www.pisugar.com/) adds battery power,
  battery telemetry, and the hardware-button mode switch.

---

For the full install walkthrough see [INSTALL.md](INSTALL.md). For the display
controls on the 1.44" HAT see [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md).
