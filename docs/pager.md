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

## Usage

1. Launch from the Pager menu: **Reconnaissance > PagerRagnar**
2. Press **GREEN** to confirm the splash screen
3. Select the network interface and toggle the Web UI on/off
4. Press **GREEN** on "Start Ragnar" to begin scanning
5. Press **RED** while running to open the pause menu
