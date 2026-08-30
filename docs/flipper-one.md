# Ragnar on the Flipper One — Feasibility & Porting Notes

> Status: **Feasibility assessment only.** The Flipper One is an actively developed,
> community open-hardware project ([how to join](https://docs.flipper.net/one/how-to-join));
> no shipping hardware exists to validate against yet. Nothing here has been run on a
> real device. This document scopes the work so it can start the moment hardware (or a
> board image / QEMU target) is available.

## TL;DR

The Flipper One is, for our purposes, **an ARM64 Linux single-board computer** — a
Rockchip RK3576 running mainline-class Linux with 8 GB RAM. That is the same class of
target Ragnar already supports on aarch64 Raspberry Pi hardware. **Running Ragnar in
headless / web-UI mode is very likely feasible with little-to-no core code change.**
The only genuinely new work is (1) driving the tiny MCU-owned LCD, which we should
*not* attempt — use headless mode — and (2) confirming the distro's package manager
and the Wi-Fi driver's monitor-mode support once an image exists.

## What the Flipper One actually is

| Aspect | Flipper One | Relevance to Ragnar |
|---|---|---|
| Main SoC | Rockchip **RK3576**, 8-core (4× Cortex-A72 + 4× A53), up to 2.2 GHz | ARM64 / `aarch64` — Ragnar already targets this arch |
| RAM | **8 GB LPDDR5** | Removes every RAM gate (Nuclei/ZAP guards, Pi-Zero limits) |
| Storage | 64 GB UFS 2.2 + microSD | Ample for logs, pcaps, nuclei-templates |
| Co-processor | Raspberry Pi **RP2350B** MCU | Owns the LCD, buttons, power, boot — **not** Linux-facing |
| Display | **256×144 monochrome LCD, 6-bit grayscale**, driven *by the MCU* | Not a Linux SPI/framebuffer e-Paper — our display drivers don't apply |
| Wi-Fi/BT | **MediaTek MT7921AUN** Wi-Fi 6E (2.4/5/6 GHz, 2×2), BT 5.2 | `mt76`/`mt7921` mainline driver **supports monitor mode + injection** |
| Wired | **2× Gigabit Ethernet** | Excellent for the netdiag / L2 watcher suite (DTP/VTP/CDP/OSPF/…) |
| Ports | USB-C ×2 (USB 3.1, one host-only), USB-A (host), HDMI 2.1, M.2 Type-B | USB host = Alfa/HackRF/RTL-SDR/Huginn/GPS dongles all attach |
| OS | Linux + custom "Flipper OS" layer (distro base TBD) | The one real unknown — see below |

Sources: [tech specs](https://docs.flipper.net/one/general/tech-specs),
[CNX Software](https://www.cnx-software.com/2026/05/21/flipper-one-a-rockchip-rk3576-powered-portable-arm-linux-computer-and-networking-multi-tool/),
[Tom's Hardware](https://www.tomshardware.com/networking/flipper-one-computing-multitool-bristles-with-network-gpio-and-m-2-connectivity-new-keychain-device-is-also-a-fully-open-arm-linux-computer).

## The recommended install shape: headless + web UI

Ragnar already has a first-class headless path (`headlessRagnar.py`, `RAGNAR_HEADLESS=1`,
`shared.py` skips all EPD init). This is exactly the right mode for the Flipper One:

- The 256×144 mono LCD is rendered by the **RP2350 MCU firmware**, not by Linux. There is
  no Linux-side SPI/framebuffer e-Paper panel for our `EPDHelper`/`display.py` drivers to
  bind to, so we do **not** port a display driver. Run headless.
- Reach the UI over either Ethernet port or the MT7921 Wi-Fi — the same web dashboard
  Ragnar serves on a Pi. HDMI 2.1 is also available if a local screen is ever wanted.
- 8 GB RAM means none of the small-board gates (Nuclei ≥950 MB, ZAP ≥8 GB, Pi-Zero
  degradations) throttle it — it will run the full suite comfortably.

An optional stretch goal, *not* required for a working install, is a small companion that
renders a Ragnar status glyph to the MCU LCD via whatever host↔MCU channel Flipper OS
exposes (likely a serial/HID protocol, à la our ESP32 bridges). Treat this the way we
treat Huginn/RoomScan bridges — additive, not on the critical path.

## What Ragnar's installer already gets right

`install_ragnar.sh` is not Pi-locked; the aarch64 groundwork is present:

- **Arch detection** — `uname -m` maps `arm*|aarch64` → `IS_ARM=true` (`install_ragnar.sh:224`).
- **Non-Pi hosts are a supported branch** — it distinguishes real Pi hardware
  (`/proc/cpuinfo` / device-tree) from "any other Linux host" and *skips* GPIO/SPI/e-Paper
  steps accordingly (`:230`, `:1178`, `:1024`). A Flipper One is exactly "another aarch64
  Linux host."
- **Debian family package manager** — `apt-get` path keyed off `debian|ubuntu|raspbian`
  (`:241`). **This is the main thing to confirm** on real Flipper OS (see risks).
- **PiWheels** is used for `aarch64` to speed Python wheels (`:1032`) — harmless/beneficial.
- **Headless variant menu** already exists (`select_headless_variant`, `:1782`).

So the pragmatic port is small: teach detection to *recognize* a Flipper One, add a
third headless variant ("Flipper One"), and confirm the apt/driver assumptions.

## Concrete work items (when an image/hardware exists)

1. **Confirm the distro & package manager.** If Flipper OS's Linux is Debian/Ubuntu-based
   with `apt`, the existing installer path largely works. If it's Yocto/Buildroot with no
   `apt`, we need a package-mapping shim (or ship deps in a container — see Docker below).
2. **Recognize the device.** Add an RK3576 / Flipper One match (device-tree `model`,
   `/proc/device-tree/compatible` contains `rockchip,rk3576`) so the installer labels it
   and picks the right defaults without pretending it's a Pi.
3. **Add a "Flipper One (headless)" variant** to `select_headless_variant` →
   `HEADLESS_VARIANT="flipper_one"`, entrypoint `headlessRagnar.py`. Follow the
   fixes-in-install-AND-update rule: mirror it into `update_ragnar.sh`.
4. **Wi-Fi monitor mode.** Verify `mt7921` exposes monitor mode + injection on the shipped
   kernel (it does on mainline). This unlocks wardriving, WiFi Defense/WIDS, wifiwatch,
   and the spectrum analyzer. Ethernet-only features work regardless.
5. **Vendored native binaries.** Anything not pure-Python needs an `aarch64` build present:
   the **RuSense** Rust binary and any `pager_bin`/`bin/` artifacts. Audit `bin/`,
   `pager_bin/`, `rusense_flasher/` for arch-specific blobs and confirm aarch64 variants.
6. **GPIO-dependent features off by default.** PiSugar/UPS, e-Paper buttons, LCD-HAT input,
   and SPI displays should stay disabled — the installer already gates these on real Pi
   hardware, so mainly verify nothing hard-fails at import on this board.
7. **Docker fallback.** If the native distro fights us, the existing headless Docker image
   (`docs/DOCKER.md`, host networking) is a clean escape hatch on an 8 GB box — build/run
   an `arm64` image and skip host package wrangling entirely.

## Risks / open questions

- **Distro base is the single biggest unknown.** No `apt` ⇒ real work. Resolve by reading
  the Flipper OS Linux build repo, or just target the Docker path first.
- **Kernel driver maturity** for MT7921 monitor mode and RK3576 USB host on the shipped
  kernel — verify on-device; mainline support exists but board kernels lag.
- **Hardware doesn't exist yet.** Everything above is unvalidated. First validation target
  should be a Flipper OS board image under QEMU (aarch64) or the earliest dev unit.
- **MCU LCD is out of scope** for a functional install; only pursue the status-glyph bridge
  as a clearly-additive follow-up.

## Bottom line

Feasibility: **high**, for the headless + web-UI configuration. The Flipper One is squarely
inside Ragnar's existing aarch64-Linux support envelope, with more RAM and better wired
networking than a Pi. The port is mostly *confirmation and a small installer variant*, not
new subsystems — gated on (a) the distro's package manager and (b) a device/image to test.
