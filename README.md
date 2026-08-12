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

---

## Quick Install

```bash
wget https://raw.githubusercontent.com/PierreGode/Ragnar/main/install_ragnar.sh
sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh
# On Raspberry Pi: choose between e-Paper HAT, server/headless, or Pineapple Pager deployment.
# On other hardware: choose between server install or Pineapple Pager deployment.
# It may take a while as many packages and modules will be installed. Reboot when it finishes.
```

For detailed information see the [Install Guide](docs/INSTALL.md). To get the box onto a network — including moving it somewhere new — see [Ragnar AP Mode](docs/RagnarAP.md). See [Release Notes](docs/RELEASE_NOTES.md) for what's new. Keeping a box current — from the web UI or the terminal, and what to do when an update complains — is covered in [Updating Ragnar](docs/updates.md).

---

## 🌐 Web Interface

Access Ragnar's dashboard at `http://<ragnar-ip>:8000`

- Real-time network discovery and vulnerability scanning
- Multi-source threat intelligence dashboard
- File management with image gallery
- System monitoring and configuration
- Hardware profile auto-detection (Pi Zero 2W, Pi 4, Pi 5)

**WiFi Configuration Portal** — When Ragnar can't connect to a known network, it creates a WiFi hotspot:
1. Connect to WiFi network `Ragnar` (password: `ragnarconnect`)
2. Navigate to `http://192.168.4.1:8000`
3. Configure your WiFi credentials via the mobile-friendly interface
4. Ragnar will automatically retry known WiFi after some time if the AP is unused
5. Once configured, Ragnar exits AP mode and connects to your network

The portal supports network scanning with signal strength, manual entry for hidden SSIDs, known network management, and one-tap reconnection.

web will be down during wardrive without ap or wifi connection.



## 🌟 Features

- **Ragnar Mesh — a Viking army, not a box** — Links Ragnar units over [Tailscale](https://tailscale.com) so every one of them is reachable by a stable private address regardless of NAT, CGNAT or the firewall in front of it. **There is no controller**: every unit publishes its own report and reads its peers', so there is no master to configure and no collector whose failure blinds the rest. Units are individuals — each is **born with a Viking name** derived from its own machine identity (`Bjorn Ironside`, `Freydis Ravenwing`), keeps that name across reinstalls, and carries an operator-assigned unit number, so incidents are discussed by name instead of by IP. The Mesh tab shows what the Tailscale console cannot: per-unit CPU/memory/disk, uptime, **undervoltage** (the classic remote-Pi killer), worst current alert severity, open incidents, and a **degraded** state for the case that matters most — the unit answers WireGuard but Ragnar itself is down, which is the difference between restarting a service and flying someone to site. Alerts are pulled from every peer into each unit's own [incident engine](docs/incident-correlation.md), scoped so site-local addresses never fuse on coincidence while a public IP or MAC seen at two sites correctly becomes **one** cross-site campaign. Peer-to-peer API calls are authenticated by **WireGuard identity, not a shared secret** — no token to mint, ship, rotate or leak — and are `GET`-only, tag-gated and fail-closed. Deploy unattended by dropping a pre-authorized key on the boot partition (the technician plugs in power and ethernet, nothing else), during install, or later from the web UI; subnet-route advertisement turns a unit into a way into the whole far-side LAN, and **Tailscale SSH** plus **Raspberry Pi Connect** give two independent ways back in when the web UI is wedged. For bringing several units up the same way, the **Fleet Config** card (*Config tab*) exports one unit's settings to a JSON file and imports them on the rest — the same switches turned on everywhere, with secrets and per-unit state stripped and display/hardware keys applied only when you opt in. **Full details in the [Ragnar Mesh Guide](docs/mesh.md).**

- **RuSense — Camera-Free Surveillance** — Turns ordinary 2.4 GHz WiFi into a no-camera sensor: ESP32 nodes read Channel State Information (CSI) to report presence, motion, people-count, and — with a trained model — coarse pose and resting vital signs (breathing / heart rate). Works in the dark and through walls, with security & health modes, a calibration wizard, browser flashing, and a multi-node offline mesh. See [RuSense](#-rusense--camera-free-surveillance)

- **Home Assistant integration** — A [HACS](https://hacs.xyz/) custom integration (shipped in-repo under `custom_components/ragnar/`) that surfaces a unit's **RuSense presence / people-count / vitals**, **Watchtower security alerts + incidents**, **Wi-Fi / Ethernet connectivity**, and **Ragnar Mesh fleet health** as native Home Assistant entities — occupancy, safety, connectivity and problem `binary_sensor`s, `sensor`s for heart/breathing rate, connected SSID, reachable mesh nodes and alert/incident/vulnerability counts, and an `event` entity that fires per new security alert — so Ragnar can drive HA automations (presence-triggered lighting, phone push on an evil-twin alert, a nudge when a mesh node drops) and dashboards. It is a read-only **local-polling** client against Ragnar's existing web API; auth reuses Ragnar's session-cookie login (or none, on an open unit). A config-flow UI handles setup. See [Home Assistant integration](docs/homeassistant.md)
  
- **Authority Verification Across the Stack** — A built-in engine for verifying authority at every layer — is the claimed root bridge / default gateway / DNS resolver / DHCP server / routing neighbour / name responder / SMB server genuine, or an impostor? — plus a network engineer's toolbox, in the web UI across three tabs. **Diagnostics:** ping, traceroute, MTR, WHOIS, internet speed test, DNS Doctor, ARP-poisoning / MITM detection, MAC Watch, Path-MTU / black-hole probe, captive-portal check, iperf3 throughput, Live Flow Telemetry, PTP-timing detection, and **IPv6 RA Guard** (audits + one-click hardens the host's IPv6 first-hop settings — ICMPv6-redirect and rogue-RA-preference exposure) — plus an opt-in **Network Integrity Monitor** that reruns the DNS-poison / ARP-spoof / rogue-DHCP / RA-Guard checks on a schedule and, with **extended monitoring**, round-robins the entire passive-scanner suite (STP/DTP/CDP/VTP/FHRP/OSPF/EIGRP/IS-IS/BGP/SMB/Relay/LDAP/IGMP/IPv6/NDP/ICMP/NTP/SNMP/Cert/TLS) through the background poller, Pushover-alerting on any regression — capture-based scanners default to a **link-up wired port** (pinnable per config), so a sensor plugged into a switch but managed over WiFi watches the cable, not `wlan0`. A **[Watchtower](docs/watchtower.md)** pane then unifies the deep *standalone* watcher daemons (arp_guard · ndpwatch · wifiwatch · certwatch · snmpwatch · isiswatch · igmpwatch) — tailing each one's JSON-lines log into a single normalized, deduped feed with one Pushover path. **Switch & L2/L3:** LLDP/CDP/EDP/FDP/SONMP switch discovery with PoE, ARP host scan, DHCP Guardian (with an inline DHCP-snooping mode), L2 link health, plus a **detection-only passive security-scanner suite spanning L2→L7** — **IGMP · IPv6 First-Hop · NDP (IPv6 neighbor-cache poisoning) · NTP · ICMP · SNMP · STP/BPDU · DTP · CDP (Cisco Discovery flood/spoof/leak) · VTP (VTP-bomb / VLAN-DB wipe) · SMB (SMBv1 + LLMNR/NBT-NS/mDNS poisoning + Kerberos downgrade/roasting) · Relay/Coercion (NTLM relay + PetitPotam/PrinterBug/DFSCoerce) · LDAP (Active Directory — cleartext binds, StartTLS strip, enumeration, filter injection, CLDAP reflection) · FHRP (HSRP/VRRP/CARP + GLBP AVG *and* AVF forwarder-plane hijack) · EIGRP · IS-IS · OSPF · BGP** Watch and a **receive-only BGP collector + path-asymmetry** correlator — a **TLS Watch** passive TLS/QUIC handshake observer (JA4/JA4_r + JA3/JA3S fingerprints, SNI/ALPN, SNI↔cert mismatch, QUIC v1/v2 Initial recovery), the active **Cert Watch** certificate/hygiene checker (plus a passive, standalone **[certwatch](docs/certwatch.md)** that triages observed X.509 certs off a tap/SPAN — expiry, name-mismatch, weak-sig/key — and inventories TLS 1.3 flows whose cert is encrypted), a PCAP analyzer, and Locate Port. Every scanner learns a baseline, ships a CLI, and self-tests (Scapy / local-handshake end-to-end). **Interfaces:** link speed/duplex/auto-neg, DHCP-vs-static + VLAN, DNS/gateway identity, per-interface public-IP / ISP-ASN lookup, and a VPN-egress check. Missing CLI tools install with one click. Co-authored by [Solarflere](https://www.instagram.com/solarflere). **Full details in the [Authority Verification Guide](docs/nettools.md).**


- **WiFi Spectrum Analyzer** — A passive, tri-band (2.4/5/6 GHz) Wi-Fi RF troubleshooter in the web UI (**Network → WiFi Analyzer**), a software take on the [Ekahau Sidekick](https://www.ekahau.com/products/sidekick/). **Strictly passive** — it only listens for beacons (`iw scan -u passive`) and never transmits a probe to any AP. Labels every generation up to **Wi-Fi 7 (802.11be)** — EHT/Multi-Link IEs are recognised from their raw extension IDs (with 320 MHz width from the EHT Operation element), since `iw` itself can't decode them in scan results yet. A big center spectrum graph with two views — **Bar** (bar per AP, width = channel width, height = RSSI) and **Cone/Dome** (the classic filled bell-curve per AP) — shows every BSS with RSSI, channel + width, SSID, security and AP-advertised channel utilisation. The graph is **interactive**: hover a signal to identify it (SSID/BSSID/vendor/RSSI/security tooltip) with a live channel·frequency·level cursor readout, click it to inspect. **⛶ Full screen** opens a survey console that gives the whole viewport to a large hit-testable spectrum, the sortable AP list, and an **inspector showing every field the survey holds** for the selected AP — radio detail (frequency/centre freq, generation, PHY mode, spatial streams, max PHY rate, Tx power, country, DFS), load & timing (channel utilisation, stations, beacon interval, DTIM, last beacon), full security (PMF, 802.1X, WPS, 802.11k/v/r, findings), RSSI history and the modelled coverage rings — plus interference, since-last-scan changes, live BT/Zigbee device lists, clickable band chips and keyboard shortcuts (`↑↓` walk the list, `s` scan, `b`/`d` view, `a/2/5/6` band, `Esc` exit). Flags **co-/adjacent-channel interference** with 1/6/11 recommendations, shades **DFS/radar** channels (read live from the radio), estimates an AP's **coverage radius** (log-distance path-loss rings), and builds a **walk-around coverage heatmap** (floorplan + IDW interpolation on a true-to-scale square plan with **metre rulers, adjustable floor size and zoom/pan** — from a 10 m² room to a 300+ m² office). A **📶 Bluetooth overlay** puts nearby **Bluetooth Classic + BLE** activity on the same 2.4 GHz axis — the BLE advertising channels (37/38/39 at 2402/2426/2480 MHz) drawn as markers in the Wi-Fi 1/6/11 gaps, a band-wide "hopping activity" strip, and a device table (RSSI, BLE/Classic, vendor, class-of-device) with an estimated per-channel BT interference level. **Receive-only** discovery over BlueZ (works on the onboard radio *or* the Alfa's built-in BT 5.2); it's a device-activity estimate, not a measured RF sweep. A **🐝 Zigbee overlay** puts nearby **Zigbee / Thread / 802.15.4** activity on the same 2.4 GHz axis via an on-demand sniff from a **HuginnESP companion** (ESP32-C5) — channel markers (Z11–Z26 at 2405–2480 MHz), a device table (address, proto, PAN ID, vendor, RSSI, clickable to highlight), and per-Wi-Fi-channel pressure; **no wardriving needed**, and the toggle greys out until a Huginn is on USB. For **measured** RF, a **📈 Waterfall view** adds a true-RF spectrum + scrolling waterfall from a **HackRF SDR** (`hackrf_sweep`) — a live spectrum line with max-hold over a time×frequency×power heatmap, Wi-Fi/BT markers overlaid, catching non-Wi-Fi interferers (microwaves, cameras, jammers) nothing else sees; **receive-only**, and the button stays **greyed out until Ragnar actually detects a HackRF** (RTL-SDR can't reach 2.4/5 GHz). Bands are detected per-radio; tuned for the **Alfa AWUS036AXM** (Wi-Fi 6E, `mt7921u`) on a Pi Zero 2 W. A one-click **📄 Report** button turns the current scan into a printable **spectrum & channel survey** (HTML → PDF): an RF-congestion verdict (CLEAR/MODERATE/CONGESTED), per-band recommended channels and width advice, a per-channel congestion histogram, co-/adjacent-channel interference counts, and network + strongest-AP tables — the site-survey deliverable an Ekahau/Acrylic workflow produces, generated on-device. See [WiFi Analyzer Guide](docs/wifi-analyzer.md)

- **WiFi Defense (802.11 WIDS)** — A passive **wireless intrusion-detection** monitor in its own web-UI tab. Listens on a **monitor-mode** adapter for 802.11 management frames and flags **deauth/disassoc floods** (the classic Wi-Fi DoS), **beacon floods** (fake-AP storms), **rogue APs / evil twins** (a known SSID from an untrusted BSSID, against a trusted baseline), and **KARMA/MANA** rogue APs (one BSSID answering many SSIDs). **Receive-only** — it never transmits a frame or deauths back. Monitor mode is set up with plain `iw` (a separate `ragmon0` vif where the driver allows, keeping your link up; else a mode switch) — **no aircrack-ng dependency**; Scapy captures with optional channel-hopping. Shows a CLEAR/WARNING/UNDER-ATTACK banner, a card per detection with attacker/BSSID detail, and an AP inventory — every flagged BSSID (and AP-table row) is clickable and **pivots into the WiFi Spectrum Analyzer**, where the rogue is pre-selected and marked with a red ⚠ WIDS locator in the spectrum until dismissed. Includes a passive **client-isolation observer**: from cleartext 802.11 headers alone it audits whether an AP or mesh actually enforces client isolation (guest/IoT WLANs) — flagging APs seen relaying client-to-client traffic (OPEN), silently filtering it (ISOLATING), plus mesh-wide **cross-node forwarding**. A standalone daemon-shaped sibling, **[wifiwatch](docs/wifiwatch.md)**, extends the same passive stance to the **WPA client/handshake layer** — **PMKID harvesting**, **forced 4-way-handshake capture** (deauth-and-capture), **WPA3→WPA2 downgrade** / SAE-strip evil twins, and **PNL leakage** (your own devices broadcasting saved SSIDs — the raw material for KARMA attacks). Needs a monitor-capable adapter (e.g. the Alfa AWUS036AXM). A one-click **📄 Report** button exports the latest capture as a printable **WIDS incident report** (HTML → PDF): a CLEAR/WARNING/CRITICAL threat verdict, a colour-coded detections table (deauth/beacon-flood/evil-twin/KARMA with detail), airspace posture (SSID/BSSID counts, randomized-MAC LA-ratio vs threshold), and the AP inventory — a shareable evidence artifact no Windows Wi-Fi analyzer produces. See [WiFi Defense Guide](docs/wifi-defense.md)

- **Wardriving with GPS recovery** — Logs WiFi networks, BLE devices, and cell towers with GPS positions while driving. Exports to WiGLE CSV / KML, plus a one-click **printable Wi-Fi survey report** (HTML → PDF) with an A–F security-posture grade, per-scheme encryption breakdown, band/channel distribution, an open-and-WEP "networks of concern" list, camera flags, per-adapter antenna coverage and GPS coverage — the site-survey deliverable a Windows analyzer like Acrylic produces, generated automatically on-device with no laptop. Most wardrivers log observations with GPS-at-scan-time and discard the rest; Ragnar logs a GPS breadcrumb track during the session and runs a post-pass that backfills missing positions for any observation seen within 5 minutes of a real GPS point. The interpolation is speed-aware — when endpoint speeds differ (slowing for a tunnel, accelerating out the far side), it uses constant-acceleration math instead of constant-velocity, shifting positions toward whichever endpoint the device actually spent more time near. A deep, read-only **[Diagnostics panel](docs/diagnostics.md)** (radios / power / GPS constellations + a live azimuth-elevation **GPS sky view** — expandable to a fullscreen planetarium with a real **starfield** behind the satellites — / feed-stall correlation) sits at the bottom of the tab, and cell-tower capture works with any **[ModemManager-supported cellular modem](docs/cell.md)**. A small **[power badge](docs/power.md)** on the main dashboard lights straight off the SoC throttle register when the board actually under-volts — an Alfa on a weak micro-USB supply is the classic cause — and clicking it breaks down what is drawing the power, board and peripherals, against the supply's headroom. See [Wardriving Guide](docs/wardriving.md)
    
- **Network Scanning** — Identifies live hosts and open ports; per-host **Ignore** button on the Network tab excludes a MAC/IP from future scans and automated actions (master switch: "Honor Scan Blacklists" in Settings)
- **Vulnerability Assessment** — Scans using Nmap and other tools
- **Multi-Source Threat Intelligence** — Real-time fusion from CISA KEV, NVD CVE, AlienVault OTX, and MITRE ATT&CK
- **AI-Powered Analysis** — GPT-5.4 Nano integration for security summaries, vulnerability prioritization, and remediation advice. Also supports **self-hosted / OpenAI-compatible endpoints** (Ollama, LocalAI, vLLM, LM Studio) so all inference can stay on hardware you control — the Pi remains a thin client. See [AI Integration Guide](docs/AI_INTEGRATION.md)
- **System Attacks** — Brute-force attacks on FTP, SSH, SMB, RDP, Telnet, SQL
- **File Stealing** — Extracts data from vulnerable services
- **Traffic Analysis** — Live `tcpdump` capture in its own web-UI tab: per-host bandwidth and top talkers, connection tracking, protocol mix, DNS logging, and detection of **port scans**, **DNS tunnelling** and **C2 beacons** (interval/size-regularity scoring). Also drives **passive host discovery** — firewalled hosts that never answer a scan still land in the hosts DB. **Detection-only**, it never sends a packet. Needs only `tcpdump`, so it runs on **any board**, Pi Zero 2W included (measured: 0.4% of one Pi 5 core and 18MB RSS at ~90 pkt/s); only the optional `tshark` JA3/IRC sidecars need a bigger board. See [Traffic Analysis](docs/traffic-analysis.md)
- **Advanced Vulnerability Scanning** — The **Adv Scan** tab runs on **any board** that has `nmap`: Nuclei, Nikto, SQLMap, WhatWeb, Nmap vuln scripts and CVE correlation. **OWASP ZAP** is the one exception — its Java daemon needs a server-class Ragnar (**8GB+ RAM**), so it greys out on smaller boards while the rest of the tab stays usable. Parallel scanning is likewise an 8GB+ feature. **Nuclei is gated at 900MB RAM** (ZAP at 8GB) — they load heavy template/Java engines that OOM a 512MB Pi Zero 2 W, so they **grey out** below their floor (a 1GB Pi 3 runs Nuclei fine) and the lighter scanners still work on the Zero. Instead of a dead end, a gated scanner is **enabled when any mesh unit can run it** — the scan is then **transparently delegated** to that unit and its live progress + findings relay back into the Zero's normal scan view. The operator just picks the scanner and scans as usual; a small "🛰️ Mesh ready — Nuclei → ylva" flag shows which peer is handling it. If the mesh only has a Nuclei-capable unit, ZAP simply stays greyed out. Discovery/auto-pick/relay ride the existing Tailscale peer-identity auth. (Needs 2+ units; single-unit boards just see the normal grey-out.) From 900MB up nuclei **auto-tunes to the board's RAM** — lower concurrency, a capped Go heap and high/critical templates on 1-2GB boards, full tilt on big ones — and on constrained boards it **refuses to start when free RAM is already too low** (reporting how much is free) rather than risk a lock-up. If the kernel memory cgroup is enabled it also wraps nuclei in a **hard memory cap** (`systemd-run`, swap off); enable it on a Pi with `cgroup_enable=memory cgroup_memory=1` in `/boot/firmware/cmdline.txt` + reboot. See [Server Mode](#-server-mode-advanced-features-8gb-ram)
- **LAN-First Connectivity** — Prefers Ethernet when present, manages WiFi as fallback
- **Smart WiFi Management** — Auto-connects to known networks, falls back to AP mode, captive portal for configuration
- **E-Paper Display** — Real-time status showing targets, vulnerabilities, credentials, and network info
- **Color TFT / OLED Displays** — GC9A01 1.28" round TFT, ST7735S 1.44" LCD HAT (128×128, with 3 keys + 5-way joystick), generic 3.5" SPI TFT (ILI9486/ILI9488, 320×480), and SSD1306 0.96" OLED. Selectable under Display settings. The 3.5" TFT shows the standard character dashboard scaled up to 320×480; see [3.5" SPI TFT setup](docs/DISPLAY_CONTROLS.md#35-spi-tft-ili9486--ili9488) for wiring and per-board tuning. The 1.44" HAT's joystick and keys drive [On-Screen Network Diagnostic Mode](docs/nettools.md#-on-screen-network-diagnostic-mode) as a standalone field tester (**KEY1** toggles it on/off). While wardriving, the same joystick pages a carousel of six wardriving screens (stats, live map, GPS detail, a polar GPS sky view, session totals, and a full-screen viking) with the keys mapped to Wi-Fi reconnect and the phone-access AP. Full key/joystick mappings for every HAT are in the [Display Buttons & Joystick Reference](docs/DISPLAY_CONTROLS.md).
- **On-Screen Kiosk (Ragnar Pi server only)** — Drives an attached HDMI/DSI screen as a fullscreen Chromium dashboard, auto-installed and relaunched on every boot (systemd unit on Pi OS Lite, XDG autostart inside an existing desktop session), with touchscreen and on-screen-keyboard detection. Chromium needs roughly 1GB resident, so the kiosk requires a Ragnar Pi server (**2GB+ RAM, 2+ cores**) — on a 512MB Pi Zero 2 W it would swap the whole box to a crawl, so the card is hidden and the installer refuses. See [Kiosk Mode](docs/kiosk.md)
- **MAX7219 LED Matrix Display** — Cascaded 8×8 LED panel arrays (4-panel 32×8 or 8-panel 64×8). Scrolls SSID, IP, targets, and status. SPI-connected: DIN→GPIO10, CS→GPIO8, CLK→GPIO11.
- **WiFi Pineapple Pager** — Full-color LCD display with button controls, LED indicators, and auto-dim. See [Pager section](#-wifi-pineapple-pager)
- **Hardware-Bound Authentication** — Optional login with full database encryption at rest. See [Security & Authentication](docs/SECURITY.md)
- **Vault — encrypted file store** — A password-protected store in the **Files** tab for keeping sensitive files encrypted at rest, organized in **subfolders** you can create, rename and browse (with Back/Up navigation). On first use you choose how much disk to reserve for it (in MB or GB) and set a password; every file is then encrypted with **AES-256-GCM** under a key derived from that password with **scrypt** — the key only ever lives in server memory while the Vault is unlocked, and both the file contents *and* the folder/file index are ciphertext on disk. Listing, previewing, downloading and adding files all require unlocking with the password, and the Vault auto-locks after 15 minutes idle (or on demand). A password-gated **Delete Vault** option resets it. **There is no recovery** — forget the password and the files stay encrypted forever. See [Vault](docs/vault.md)
- **PiSugar 3 Button** — Physical button to swap between Ragnar and Pwnagotchi modes
- **Web Terminal** — Optional interactive shell (xterm.js ↔ PTY over Socket.IO) in the dashboard, so you can manage the Pi without SSH. Runs as the non-root `ragnar` user in the Ragnar folder (`sudo` available), **off by default**, and gated by login — enable it in Config → Web Terminal only on trusted networks.
- **Kill Switch** — Built-in endpoint (`/api/kill`) to wipe all databases, logs, and data. See [Kill Switch](docs/KILL_SWITCH.md)
- **Comprehensive Logging** — All nmap commands and results logged to `data/logs/nmap.log`

<p align="center">
  <img width="150" height="300" alt="image" src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" />
</p>

<img width="1092" height="902" alt="image" src="https://github.com/user-attachments/assets/cafed68d-de62-4041-aa36-c1fcccacc9ea" />

---

## 📌 Supported Platforms & Prerequisites

### Raspberry Pi (Zero W2 /3B(+) / 4 / 5)

- 64-bit Raspberry Pi OS (Debian Trixie, kernel 6.12+)
- Username and hostname set to `ragnar`
- 2.13-inch e-Paper HAT connected to GPIO pins (for display mode)
- For 32-bit systems, use Ragnar's predecessor [Bjorn](https://github.com/infinition/Bjorn)

**Recommendation:** Edit `~/.config/labwc/autostart` and comment out `/usr/bin/lwrespawn /usr/bin/wf-panel-pi &` to free up resources, or run `sudo pkill wf-panel-pi` temporarily.

#### Ragnar Gen 2 — reference build

The compact, self-contained reference node: a headless Pi Zero 2 W with an
on-board status display, wired networking, and a Wi-Fi 6E monitor-mode radio.
In collaboration with [Solarflere](https://www.instagram.com/solarflere?igsh=MXR6bjMyMmRzZzE4dg==).

- **Raspberry Pi Zero 2 W** — main compute
- **Waveshare 1.44" LCD Display HAT** (ST7735S, 3 keys + joystick) — on-device display + controls
- **Waveshare Ethernet/USB HAT** — wired uplink + USB-A for the dongle
- **Alfa AWUS036AXM** (Wi-Fi 6E, `mt7921u`) — tri-band scan/monitor radio

See [Gen 2 Hardware Requirements](docs/hardware-gen2.md) for the full BOM, assembly, and setup notes.

### Debian-Based Server / Headless

- Debian 11+ or Ubuntu 20.04+ (AMD64, ARM64, or ARMv7)
- Minimum: 2GB RAM, 2 CPU cores, 10GB free disk
- Recommended: 8GB+ RAM for the heaviest features — **OWASP ZAP** and parallel scanning. The rest of the Adv Scan tab (Nuclei, Nikto, SQLMap, WhatWeb, Nmap) and Traffic Analysis run on any board; the CLI scanners just need `nmap`, and Traffic Analysis needs only `tcpdump`

### WiFi Pineapple Pager

- Firmware 1.0.7+
- PAGERCTL payload installed (provides libpagerctl.so)
- SSH access from your workstation
- Python3 + nmap (auto-installed on first run)
- MIPS-compiled Python libraries bundled in `pager_lib/` (or sourced from PAGERCTL payload)

---

## 🔨 Installation Details

The installer auto-detects your platform and configures everything:

- **Distro detection** — Supports apt, dnf, pacman, zypper
- **Architecture support** — AMD64, ARM64, ARMv7, ARMv8
- **Profiles** — Pi + e-Paper, Server/Headless, WiFi Pineapple Pager
- **Automatic advanced tools** — Systems with 8GB+ RAM get advanced features installed automatically
- **Smart resource management** — Pi Zero W2 automatically skip resource-intensive tools
- **ARM optimizations** — Uses PiWheels on ARM, retries mirrors, skips Pi-only steps on other hardware

For the full installation walkthrough see [Install Guide](docs/INSTALL.md). For updating an existing box, see [Updating Ragnar](docs/updates.md).

---

## 🖥️ Server Mode: Advanced Features (8GB+ RAM)

When deployed on systems with 8GB+ RAM, Ragnar automatically unlocks advanced security capabilities.

> **The Adv Scan tab is no longer 8GB-only.** The CLI scanners — Nuclei, Nikto,
> SQLMap, WhatWeb and Nmap vuln scripts — are light enough to run on any board
> that has `nmap`, so the tab shows up everywhere. **OWASP ZAP** is the sole
> exception: its Java daemon holds ~1GB+ resident, so it stays gated at **8GB+
> RAM** and greys out below that while the rest of the tab keeps working.
> Parallel scanning is also an 8GB+ feature.

> **Traffic Analysis is not one of them either.** It is a `tcpdump` pipe, not
> OpenVAS-class work, so it has its own much lower gate and runs on any board
> with `tcpdump` installed — see [Traffic Analysis](docs/traffic-analysis.md).
> Only its optional `tshark` JA3/IRC sidecars need a 4GB-class board.

> **Fresh installs:** The main installer detects 8GB+ RAM and installs advanced tools automatically.
>
> **Existing installs:** Run the advanced tools installer separately:
> ```bash
> cd /home/ragnar/Ragnar
> sudo ./scripts/install_advanced_tools.sh
> sudo systemctl restart ragnar
> ```

### Advanced Vulnerability Scanning
- **Pre-flight recon** — Optional reconnaissance phase before ZAP: **port discovery** (parallel TCP connect-scan of common web ports, each classified http/https via a TLS probe), TLS audit, passive DNS subdomain enumeration, and HTTP content discovery. In the handoff gate the operator ticks exactly which discovered `scheme://host:port` URLs, subdomains and paths get fed to ZAP — so a bare IP is scanned on the ports that are *actually* listening instead of blindly defaulting to :80/:443
- **OWASP ZAP** *(8GB+ RAM)* — Spider + AJAX spider + active scan with automatic browser detection; greys out on smaller boards. When you give a **bare host with no port**, ZAP now probes common web ports and scans whichever is actually listening (HTTPS-only or alt-port services included) instead of assuming :80 and failing — the same auto-resolution applies to **delegated mesh scans**, where the probe runs from the delegate's network vantage
- **Authenticated scanning** — 8 auth types: form-based, HTTP Basic, OAuth2, Bearer Token, API Key, Cookie, Script-based
- **Nuclei** — 5000+ vulnerability templates from ProjectDiscovery; if the binary isn't present the scanner card shows a **⤓ Install** button that fetches the right build for your board (templates download automatically after)
- **Nikto** — Comprehensive web server assessment
- **SQLMap** — Automated SQL injection detection
- **Parallel scanning** — Multi-threaded for faster results
- **CVE correlation** — Automatic correlation with NVD, CISA KEV, and threat feeds
- **Live progress** — Real-time log panel and animated progress bar
- **Web and API modes** — Scan web apps or API endpoints with OpenAPI spec import

### What Gets Installed
- **Traffic tools**: tcpdump, tshark, ngrep, iftop, nethogs
- **Vulnerability scanners**: Nuclei, Nikto, SQLMap, WhatWeb
- **Web app security**: OWASP ZAP (requires Java)
- **Nmap scripts**: vulners.nse, vulscan database

Ragnar auto-detects available tools and enables corresponding features in the web interface.

---

## 📡 RuSense — Camera-Free Surveillance

RuSense turns ordinary 2.4 GHz WiFi into a **no-camera surveillance** system for home,
office, and anywhere a lens is unwelcome. ESP32 sensor nodes read **WiFi Channel State
Information (CSI)** — the tiny distortions a moving body imprints on radio waves — and a
bundled sensing engine reports **presence, motion, people-count**, and (with a trained
model) **coarse pose and resting vital signs**. No images are ever captured; it works in
the dark and through walls.

- **Flash a sensor node from your browser** — no toolchain needed: **[RuSense Flasher](https://pierregode.github.io/Ragnar/)** (ESP32-S3 DevKitC / Seeed XIAO ESP32S3 & Plus / AMOLED / C6, Chrome/Edge).
- **Install the backend:** `sudo ./scripts/install_sensing.sh` (runs as `ragnar-sensing.service`).
- **View it** under the RuSense tabs in the web dashboard at `http://<ragnar-ip>:8000`.

Powered by [RuView](https://github.com/ruvnet/ruview) (by ruvnet). Full details: **[RuSense Guide](docs/rusense.md)**.

---

## 🐝 Ragnar + Pwnagotchi Side by Side

A bundled helper script plus dashboard controls make swapping between Ragnar and Pwnagotchi painless:

1. Run the installer:
   ```bash
   cd /home/ragnar/Ragnar
   sudo ./scripts/install_pwnagotchi.sh
   ```
   The script clones [pwnagotchiworking](https://github.com/PierreGode/pwnagotchiworking) into `/opt/pwnagotchi`, installs dependencies, writes `/etc/pwnagotchi/config.toml`, and drops a disabled `pwnagotchi.service`. Re-running is fast — it skips already-installed packages.

2. Open the web UI → **Config** tab → **Pwnagotchi Bridge** → click **Switch to Pwnagotchi**.

**Requirements:**
- USB WiFi adapter (wlan1) with monitor mode support
- Waveshare 2.13" e-Paper HAT V4 for the pwnagotchi face display

**Pwnagotchi web UI:** `http://<same-ip>:8080` (credentials: `ragnar` / `ragnar`)

**What the installer configures:**
- Monitor mode scripts (`/usr/bin/monstart`, `/usr/bin/monstop`)
- e-Paper display type (`waveshare213_v4`) and rotation
- Web UI on port 8080, Pwngrid disabled
- RSA keys, log directories, bettercap integration

**Swapping via PiSugar 3 button:**

| Button Action | While Ragnar is running | While Pwnagotchi is running |
|---------------|------------------------|---------------------------|
| Single tap | Toggle manual mode | — |
| Double tap | Switch to Pwnagotchi | Switch to Ragnar |
| Long press | Switch to Pwnagotchi | Switch to Ragnar |

A 10-second cooldown prevents accidental double triggers. If PiSugar is not connected, the listener is silently disabled.

**Static IP recommended:** When switching modes, WiFi may briefly reconnect with a different DHCP IP. Set a static IP:

```bash
sudo nmcli con mod "YOUR_WIFI_SSID" ipv4.method manual \
  ipv4.addresses "192.168.1.211/24" \
  ipv4.gateway "192.168.1.1" \
  ipv4.dns "192.168.1.1"
sudo nmcli con up "YOUR_WIFI_SSID"
```

Or set a DHCP reservation on your router. This only affects wlan0 — the monitor interface (wlan1/mon0) is not changed.

**Service recovery:** If Ragnar doesn't start after a reboot:
```bash
sudo /home/ragnar/Ragnar/scripts/fix_services.sh
```

---

## 🍍 WiFi Pineapple Pager

> **Attribution:** The WiFi Pineapple Pager port of Ragnar is based on the original work of **brAinphreAk** — the developer who first ported Bjorn to the Pineapple Pager as [PagerBjorn / Loki](https://github.com/pineapple-pager-projects/pineapple_pager_loki). The pager adaptation layer (display system, hardware control wrapper, MIPS-compiled binaries and libraries) originated in that project. Full credit and thanks to brAinphreAk for making pager hardware support possible.

Ragnar can be deployed to the WiFi Pineapple Pager as a native payload with full-color LCD display, button controls, and LED status indicators.

**Features on Pager:**
- Full-color 480x222 LCD with Viking-themed status display
- Physical button controls (navigate menus, pause/resume, adjust brightness)
- LED indicators (blue=idle, cyan=scanning, red=brute force, yellow=stealing)
- Graphical startup menu with interface selection and Web UI toggle
- Auto-dim for battery saving and payload handoff support

**Installation:**

Option A — From the main installer (select option 3):
```bash
sudo ./install_ragnar.sh
# Choose: 3. Install on WiFi Pineapple Pager
```

Option B — Direct deployment:
```bash
./scripts/install_pineapple_pager.sh [pager-ip]
```

**Usage:**
1. Launch from Pager menu: **Reconnaissance > PagerRagnar**
2. Press **GREEN** to confirm the splash screen
3. Select network interface and toggle Web UI on/off
4. Press **GREEN** on "Start Ragnar" to begin scanning
5. Press **RED** while running to open the pause menu

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
| [RuView](https://github.com/ruvnet/ruview) | ruvnet | WiFi-CSI sensing engine and ESP32 CSI-node firmware behind [RuSense](docs/rusense.md) — camera-free presence, motion, people-count, pose and vital-sign sensing. Ragnar vendors bins from the [PierreGode/RuView](https://github.com/PierreGode/RuView) fork |
| — | [Solarflere](https://www.instagram.com/solarflere) | Co-author of the [Authority Verification](docs/nettools.md) suite (Diagnostics, Switch & L2/L3, Interfaces) |

---

## 📜 License

2025- - Ragnar is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.
