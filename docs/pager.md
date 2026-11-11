# 🍍 WiFi Pineapple Pager

Ragnar can be deployed to the WiFi Pineapple Pager as a native payload with a
full-color LCD display, button controls, and LED status indicators.

> **Attribution.** The WiFi Pineapple Pager port of Ragnar is based on the
> original work of **brAinphreAk** — the developer who first ported Bjorn to the
> Pineapple Pager as [PagerBjorn /
> Loki](https://github.com/pineapple-pager-projects/pineapple_pager_loki). The
> pager adaptation layer (display system, hardware control wrapper, MIPS-compiled
> binaries and libraries) originated in that project. Full credit and thanks to
> brAinphreAk for making pager hardware support possible.

---

## Prerequisites

- Firmware 1.0.7+
- PAGERCTL payload installed (provides `libpagerctl.so`)
- SSH access from your workstation
- Python 3 + nmap (auto-installed on first run)
- MIPS-compiled Python libraries bundled in `pager_lib/` (or sourced from the
  PAGERCTL payload)

## Features on the Pager

- Full-color 480×222 LCD with Viking-themed status display
- Physical button controls (navigate menus, pause/resume, adjust brightness)
- LED indicators (blue = idle, cyan = scanning, red = brute force, yellow = stealing)
- Graphical startup menu with interface selection and Web UI toggle
- Auto-dim for battery saving and payload handoff support

---

## Installation

**Option A — from the main installer (select option 3):**

```bash
sudo ./install_ragnar.sh
# Choose: 3. Install on WiFi Pineapple Pager
```

**Option B — direct deployment:**

```bash
./scripts/install_pineapple_pager.sh [pager-ip]
```

If you omit the IP, the installer offers the Pager it detects on this machine's
USB network (the `172.16.<N>.1` of whichever `172.16.<N>.0/24` you have an
address on — `N` differs between units, e.g. `42` or `52`).

## Troubleshooting install

- **"No SSH service reachable at …:22".** The Pager is not plugged in, not
  powered, or you passed the wrong IP. Check with `ip -4 addr | grep 172.16.` —
  the Pager is the `.1` of the subnet you see there, and the installer prints
  the detected address to try.
- **Key auth fails.** The installer falls back to the Pager's root password and
  asks for it once (connections are multiplexed). To avoid the prompt entirely:
  `ssh-copy-id root@<pager-ip>`.
- **"Payload package is incomplete".** The installer refuses to deploy a broken
  payload (it used to silently ship an empty one). It means the Ragnar checkout
  it found is incomplete — run it from a full clone, not a tarball/partial copy.
- **Python / nmap install.** The installer prefers the Pager's own `opkg`
  (needs internet on the Pager). With no internet it downloads the current
  `mipsel_24kc` Python packages on your workstation and streams them over; it
  never pins a package version, so it will not 404 when the OpenWrt feed rolls
  forward. If both fail, it prints the one-line `opkg` command to run on the
  Pager yourself, then re-run the installer.

## Usage

1. Launch from the Pager menu: **Reconnaissance > PagerRagnar**
2. Press **GREEN** to confirm the splash screen
3. Select the network interface and toggle the Web UI on/off
4. Press **GREEN** on "Start Ragnar" to begin scanning
5. Press **RED** while running to open the pause menu
