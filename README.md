## Ragnar     <img width="105" height="150" alt="image" src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" />

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/J3J2EARPK)
![GitHub stars](https://img.shields.io/github/stars/PierreGode/Ragnar)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/78Ybx52dU)

<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/3bed08a1-b6cf-4014-9661-85350dc5becc" width="200"/></td>
    <td><img src="https://github.com/user-attachments/assets/88345794-edfc-49e8-90ab-48d72b909e86" width="800"/></td>
  </tr>
</table>

Ragnar is a fork of the awesome [Bjorn](https://github.com/infinition/Bjorn) project — a Tamagotchi-like autonomous network scanning, vulnerability assessment, and offensive security tool. It runs on a **Raspberry Pi** with a 2.13-inch e-Paper HAT, as a **headless server** on Debian-based systems (AMD64/ARM/ARM64) with Ethernet-first connectivity, or on the **WiFi Pineapple Pager** with full-color LCD display. On servers with 8GB+ RAM, Ragnar unlocks advanced capabilities including enhanced vulnerability scanning and parallel scanning.

> [!IMPORTANT]
> **For educational and authorized testing purposes only.**

This README is a map, not a manual — each feature gets a couple of sentences and a link to its full guide in [`docs/`](docs). Start with the [documentation index](docs/README.md) if you'd rather browse.

---

## Quick Install

```bash
wget https://raw.githubusercontent.com/PierreGode/Ragnar/main/install_ragnar.sh
sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh
# On Raspberry Pi: choose e-Paper HAT, TFT LCD, server/headless, Pineapple Pager, or Docker container.
# On other hardware: choose server install, Pineapple Pager, or Docker container.
# It may take a while as many packages and modules will be installed. Reboot when it finishes.
```

Prefer containers? Run the headless web UI on any Linux host with `docker compose up -d --build`, then open **http://<host-ip>:8000**. Pi-only hardware (e-Paper, GPS, SDR, Wi-Fi monitor mode) isn't available in a container — see the [Docker Guide](docs/DOCKER.md).

More: [Install Guide](docs/INSTALL.md) · [AP Mode / getting on a network](docs/RagnarAP.md) · [Updating Ragnar](docs/updates.md) · [Release Notes](docs/RELEASE_NOTES.md).

---

## 🌐 Web Interface

Access Ragnar's dashboard at `http://<ragnar-ip>:8000` — real-time discovery and vulnerability scanning, a multi-source threat-intel dashboard, file management, system monitoring, and hardware profile auto-detection (Pi Zero 2W, Pi 4, Pi 5).

**WiFi Configuration Portal** — when Ragnar can't reach a known network it raises a hotspot: connect to WiFi `Ragnar` (password `ragnarconnect`), open `http://192.168.4.1:8000`, and enter your credentials via the mobile-friendly portal. It supports scanning with signal strength, hidden-SSID entry, known-network management, and one-tap reconnection, then exits AP mode once configured. (The web UI is down during a wardrive with no AP or WiFi connection.)

---

## 🌟 Features

Every feature below has a full guide in [`docs/`](docs). Short version here, details behind the link.

### Core scanning & offense
- **Network scanning, vulnerability assessment & attacks** — the autonomous scan-and-act loop : host/port discovery (with a per-host **Ignore** blacklist), Nmap-based vulnerability assessment Every nmap run is logged. See [Scanning & Attacks](docs/scanning-and-attacks.md).
- **Advanced vulnerability scanning** — the **Adv Scan** tab: Nuclei, Nikto, SQLMap, WhatWeb and Nmap vuln scripts run on any board with `nmap`; OWASP ZAP and parallel scanning need 8GB+ RAM. RAM-gated scanners are **delegated to a capable mesh peer** instead of dead-ending. See [Advanced Vulnerability Scanning](docs/adv-scan.md).
- **Multi-source threat intelligence** — real-time fusion from CISA KEV, NVD CVE, AlienVault OTX, and MITRE ATT&CK, used to prioritize findings. See [Scanning & Attacks](docs/scanning-and-attacks.md#multi-source-threat-intelligence).
- **AI-powered analysis** — security summaries, vulnerability prioritization and remediation advice, with support for **self-hosted / OpenAI-compatible** endpoints (Ollama, LocalAI, vLLM, LM Studio) so inference can stay on your hardware. See [AI Integration](docs/AI_INTEGRATION.md).
- **Traffic analysis** — live `tcpdump` capture with top-talkers, protocol mix, DNS logging, and detection of port scans, DNS tunnelling and C2 beacons; also drives passive host discovery. Detection-only; runs on any board (Pi Zero 2W included). See [Traffic Analysis](docs/traffic-analysis.md).

### Network defense & authority verification
- **Authority Verification across the stack** — is the claimed root bridge / gateway / DNS resolver / DHCP server / routing neighbour / SMB server genuine or an impostor? A network engineer's toolbox (Diagnostics, Switch & L2/L3, Interfaces) plus a **detection-only passive watcher suite spanning L2→L7** (STP/DTP/CDP/VTP/LACP/BFD/PTP/SR-MPLS/FHRP/OSPF/EIGRP/IS-IS/BGP/SMB/Relay/RPC/LDAP/SSH/Telnet/IGMP-MLD/NDP/ICMP/NTP/SNMP/TLS/Cert — most dual-stack IPv4+IPv6), a scheduled Network Integrity Monitor, and IPv6 RA Guard. Co-authored by [Solarflere](https://www.instagram.com/solarflere). Full details in the [Authority Verification Guide](docs/nettools.md).
- **Watchtower** — unifies the standalone watcher daemons into one normalized, deduped alert feed with a single Pushover path. See [Watchtower](docs/watchtower.md).
- **Asset Inventory & SIEM forwarding** — turns the flat hosts table into a change-aware inventory (new device / IP move / OUI change / offline, with owner/criticality/authorized tags and rogue-device signatures) and ships every alert to syslog/CEF/LEEF, Splunk HEC, Elasticsearch/OpenSearch, or a JSON/Slack webhook. See [Asset Inventory](docs/asset-inventory.md) and [SIEM Forwarding](docs/siem.md).
- **Incident correlation** — fuses the alert stream into named cross-site attack-chain incidents. See [Incident Correlation](docs/incident-correlation.md).

### Wireless & RF
- **WiFi Spectrum Analyzer** — a passive tri-band (2.4/5/6 GHz, up to Wi-Fi 7) RF troubleshooter: interactive spectrum graph, per-AP inspector, interference/DFS flags, coverage rings, a walk-around heatmap, printable survey report, plus Bluetooth/Zigbee overlays and a HackRF true-RF waterfall. See [WiFi Analyzer](docs/wifi-analyzer.md) and the [RoomScan](docs/roomscan.md) floor-plan tracer.
- **WiFi Defense (802.11 WIDS)** — passive wireless intrusion detection: deauth/disassoc & beacon floods, rogue APs / evil twins, KARMA/MANA, and a client-isolation observer, with a printable WIDS incident report. Receive-only. Its daemon sibling [wifiwatch](docs/wifiwatch.md) extends this to the WPA handshake layer (PMKID, downgrade, PNL leakage). See [WiFi Defense](docs/wifi-defense.md).
- **Wardriving with GPS recovery** — logs WiFi/BLE/cell with GPS positions, exports WiGLE CSV / KML and a printable A–F security-graded survey, and backfills missing positions with speed-aware interpolation. Includes a deep [Diagnostics panel](docs/diagnostics.md) (radios/power/GPS sky view + [Starview observatory](docs/diagnostics.md#ragnar-starview--the-observatory-mode)), [cellular modem](docs/cell.md) capture, and a [power badge](docs/power.md). See [Wardriving](docs/wardriving.md).

### Sensing & smart home
- **RuSense — camera-free surveillance** — ESP32 nodes read WiFi Channel State Information (CSI) to report presence, motion, people-count, and (with a trained model) coarse pose and resting vital signs — in the dark, through walls, no images. Browser flashing, calibration wizard, offline mesh. Powered by [RuView](https://github.com/ruvnet/ruview) (ruvnet). See [RuSense](docs/rusense.md).
- **Home Assistant integration** — a HACS custom integration (in-repo under `custom_components/ragnar/`) surfacing RuSense presence/vitals, Watchtower alerts + incidents, connectivity, and mesh fleet health as native HA entities. Read-only local polling. See [Home Assistant](docs/homeassistant.md).

### Mesh & fleet
- **Ragnar Mesh — a Viking army, not a box** — links units over [Tailscale](https://tailscale.com) with **no controller**: each unit is born with a Viking name, publishes its own report and reads its peers', and is reachable by a stable private address through any NAT. The Mesh tab shows per-unit health, undervoltage, worst alert and a "degraded" state; peer API calls are authenticated by WireGuard identity (no shared secret). Includes Fleet Config export/import and unit-to-unit **file transfer**. See the [Ragnar Mesh Guide](docs/mesh.md) and [Mesh Share & File Transfer](docs/mesh-share.md).

### Hardware, displays & interfaces
- **Displays** — 2.13" e-Paper HAT; color TFT/OLED (GC9A01 1.28" round, ST7735S 1.44" HAT with keys + joystick, 3.5" SPI TFT ILI9486/9488, SSD1306 OLED); and MAX7219 8×8 LED matrix arrays. The 1.44" HAT's joystick drives [On-Screen Network Diagnostic Mode](docs/nettools.md#-on-screen-network-diagnostic-mode) and a wardriving carousel. Full mappings: [Display Buttons & Joystick Reference](docs/DISPLAY_CONTROLS.md).
- **On-Screen Kiosk** (Pi server only) — drives an attached HDMI/DSI screen as a fullscreen Chromium dashboard, with a handheld escape hatch (Hackberry Pi CM5). Needs 2GB+ RAM. See [Kiosk Mode](docs/kiosk.md).
- **WiFi Pineapple Pager** — deploy Ragnar to the Pager as a native payload with a full-color LCD, buttons and LED status. Based on **brAinphreAk**'s [PagerBjorn / Loki](https://github.com/pineapple-pager-projects/pineapple_pager_loki). See [Pager Guide](docs/pager.md).
- **PiSugar 3 button** — physical button to swap between Ragnar and Pwnagotchi modes (see below).

### Platform, safety & storage
- **LAN-first connectivity & smart WiFi** — prefers Ethernet when present, manages WiFi as fallback, auto-connects to known networks and falls back to AP mode with a captive portal.
- **Hardware-bound authentication** — optional login with full database encryption at rest. See [Security & Authentication](docs/SECURITY.md).
- **Vault — encrypted file store** — a password-protected, AES-256-GCM store in the **Files** tab (contents *and* index are ciphertext on disk; scrypt-derived key; auto-locks; no recovery). See [Vault](docs/vault.md).
- **Web Terminal** — optional in-dashboard shell (xterm.js ↔ PTY over Socket.IO) as the non-root `ragnar` user; off by default and login-gated — enable only on trusted networks.
- **Kill Switch** — `/api/kill` wipes all databases, logs and data. See [Kill Switch](docs/KILL_SWITCH.md).

<p align="center">
  <img width="150" height="300" alt="image" src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" />
</p>

<img width="1092" height="902" alt="image" src="https://github.com/user-attachments/assets/cafed68d-de62-4041-aa36-c1fcccacc9ea" />

---

## 📌 Supported Platforms & Prerequisites

### Raspberry Pi (Zero W2 / 3B(+) / 4 / 5)

- 64-bit Raspberry Pi OS (Debian Trixie, kernel 6.12+)
- Username and hostname set to `ragnar`
- 2.13-inch e-Paper HAT connected to GPIO pins (for display mode)
- For 32-bit systems, use Ragnar's predecessor [Bjorn](https://github.com/infinition/Bjorn)

**Recommendation:** Edit `~/.config/labwc/autostart` and comment out `/usr/bin/lwrespawn /usr/bin/wf-panel-pi &` to free up resources, or run `sudo pkill wf-panel-pi` temporarily.

#### Ragnar Gen 2 — reference build

The compact, self-contained reference node: a headless Pi Zero 2 W with an on-board status display, wired networking, and a Wi-Fi 6E monitor-mode radio. In collaboration with [Solarflere](https://www.instagram.com/solarflere?igsh=MXR6bjMyMmRzZzE4dg==) — **Raspberry Pi Zero 2 W** + **Waveshare 1.44" LCD Display HAT** (ST7735S) + **Waveshare Ethernet/USB HAT** + **Alfa AWUS036AXM** (Wi-Fi 6E, `mt7921u`). See [Gen 2 Hardware Requirements](docs/hardware-gen2.md) for the full BOM, assembly, and setup notes.

### Debian-based server / headless

- Debian 11+ or Ubuntu 20.04+ (AMD64, ARM64, or ARMv7)
- Minimum: 2GB RAM, 2 CPU cores, 10GB free disk
- Recommended: 8GB+ RAM for the heaviest features (OWASP ZAP and parallel scanning). The rest of the Adv Scan tab and Traffic Analysis run on any board — the CLI scanners just need `nmap`, Traffic Analysis needs only `tcpdump`.

### WiFi Pineapple Pager

Firmware 1.0.7+, PAGERCTL payload, SSH access, Python3 + nmap. See [Pager Guide](docs/pager.md).

### Hackberry Pi CM5 (community port)

A community wrapper runs Ragnar in headless/server mode on the [Hackberry Pi CM5](https://github.com/ZitaoTech/HackberryPiCM5) handheld cyberdeck — a 720×720 touch panel with a BlackBerry-style keyboard. It installs Ragnar **unmodified** (vendored as a dependency), adds a touch dashboard and keyboard control panel, and keeps everything off system Python via an isolated virtualenv. See [**DezusAZ/ragnar-cyberdeck**](https://github.com/DezusAZ/ragnar-cyberdeck).

### Flipper One (feasibility / planned)

The [Flipper One](https://docs.flipper.net/one/how-to-join) is an ARM64 Linux multi-tool — the same class of `aarch64` host Ragnar already supports, so the **headless / web-UI** configuration looks highly feasible with little core change. Still a community-development project with no shipping hardware to validate against yet. See the [Flipper One feasibility & porting notes](docs/flipper-one.md).

---

## 🔨 Installation Details

The installer auto-detects your platform and configures everything — distro detection (apt/dnf/pacman/zypper), architecture support (AMD64/ARM64/ARMv7/ARMv8), install profiles (Pi + e-Paper, Server/Headless, Pineapple Pager, Docker), automatic advanced tools on 8GB+ boards, and smart resource management that skips heavy tools on a Pi Zero 2W. Full walkthrough: [Install Guide](docs/INSTALL.md); updating an existing box: [Updating Ragnar](docs/updates.md).

---

## 🖥️ Server Mode: Advanced Features (8GB+ RAM)

On 8GB+ systems Ragnar automatically unlocks OWASP ZAP and parallel scanning. The rest of the Adv Scan tab (Nuclei, Nikto, SQLMap, WhatWeb, Nmap vuln scripts) and Traffic Analysis run on any board — see [Advanced Vulnerability Scanning](docs/adv-scan.md) for the full breakdown of what runs where, RAM gating, and mesh delegation. Fresh 8GB+ installs get the advanced tools automatically; on an existing box:

```bash
cd /home/ragnar/Ragnar
sudo ./scripts/install_advanced_tools.sh
sudo systemctl restart ragnar
```

---

## 📡 RuSense — Camera-Free Surveillance

RuSense turns ordinary 2.4 GHz WiFi into a **no-camera surveillance** system. ESP32 nodes read WiFi Channel State Information (CSI) — the tiny distortions a moving body imprints on radio waves — and a bundled engine reports presence, motion, people-count, and (with a trained model) coarse pose and resting vital signs. No images are ever captured; it works in the dark and through walls.

- **Flash a node from your browser** — no toolchain: **[RuSense Flasher](https://pierregode.github.io/Ragnar/)** (ESP32-S3 DevKitC / Seeed XIAO ESP32S3 & Plus / AMOLED / C6, Chrome/Edge).
- **Install the backend:** `sudo ./scripts/install_sensing.sh` (runs as `ragnar-sensing.service`).
- **View it** under the RuSense tabs at `http://<ragnar-ip>:8000`.

Powered by [RuView](https://github.com/ruvnet/ruview) (by ruvnet). Full details: **[RuSense Guide](docs/rusense.md)**.

---

## 🐝 Ragnar + Pwnagotchi Side by Side

A bundled helper (`sudo ./scripts/install_pwnagotchi.sh`) plus dashboard controls make swapping between Ragnar and Pwnagotchi painless — the script clones [pwnagotchiworking](https://github.com/PierreGode/pwnagotchiworking), installs dependencies, and drops a disabled `pwnagotchi.service`. Switch from the web UI (**Config → Pwnagotchi Bridge**), the PiSugar 3 button, or a reboot-recovery script. Pwnagotchi web UI: `http://<same-ip>:8080` (`ragnar`/`ragnar`). Needs a monitor-mode USB adapter (wlan1) and a Waveshare 2.13" e-Paper HAT V4. Full setup, config, mode-switching and troubleshooting: **[Pwnagotchi Bridge Guide](docs/PWNAGOTCHI.md)**.

---

## 🍍 WiFi Pineapple Pager

Ragnar deploys to the WiFi Pineapple Pager as a native payload with a full-color 480×222 LCD, button controls and LED status indicators. The pager port is based on the original work of **brAinphreAk** ([PagerBjorn / Loki](https://github.com/pineapple-pager-projects/pineapple_pager_loki)) — full credit and thanks for making pager hardware support possible. Install it from the main installer (option 3) or `./scripts/install_pineapple_pager.sh [pager-ip]`. Full prerequisites, features and usage: **[Pager Guide](docs/pager.md)**.

---

## 🤝 Contributing

The project welcomes contributions in new attack modules, bug fixes, documentation, and feature improvements.

See [Contributing Docs](docs/CONTRIBUTING.md) and [Code of Conduct](docs/CODE_OF_CONDUCT.md).

## 📫 Contact

- **Report Issues**: Via [GitHub Issues](https://github.com/PierreGode/Ragnar/issues)
- **Author**: PierreGode — [PierreGode/Ragnar](https://github.com/PierreGode/Ragnar)

---

## 🙏 Credits & Attribution

Ragnar is built on the shoulders of great work by others:

| Project | Author | Role in Ragnar |
|---|---|---|
| [Bjorn](https://github.com/infinition/Bjorn) | infinition | Original project that Ragnar is forked from |
| [PagerBjorn / Loki](https://github.com/pineapple-pager-projects/pineapple_pager_loki) | [brAinphreAk](https://github.com/brainphreak) | WiFi Pineapple Pager adaptation layer — display system, hardware control wrapper (`pagerctl.py`), pager menu UI, and all MIPS-compiled binaries and libraries |
| [Pwnagotchi](https://github.com/jayofelony/pwnagotchi) | jayofelony | side by side Ragnar Pwnagotchi install with swap function |
| [RuView](https://github.com/ruvnet/ruview) | ruvnet | WiFi-CSI sensing engine and ESP32 CSI-node firmware behind [RuSense](docs/rusense.md) — camera-free presence, motion, people-count, pose and vital-sign sensing. Ragnar vendors bins from the [PierreGode/RuView](https://github.com/PierreGode/RuView) fork |
| Networking and more | [Solarflere](https://www.instagram.com/solarflere) | Co-author of the [Authority Verification](docs/nettools.md) suite (Diagnostics, Switch & L2/L3, Interfaces) |

---

## 📜 License

2025- - Ragnar is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.
