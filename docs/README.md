# Ragnar Documentation

The full guides behind the [main README](../README.md). Start here if you'd rather
browse than search.

## Getting started
- [Install Guide](INSTALL.md) — the full installation walkthrough
- [Updating Ragnar](updates.md) — updating from the web UI or the terminal
- [Docker Guide](DOCKER.md) — headless web UI in a container
- [AP Mode](RagnarAP.md) — getting the box onto a network
- [Release Notes](RELEASE_NOTES.md) · [Upcoming](Upcoming.md)

## Core scanning & offense
- [Scanning & Attacks](scanning-and-attacks.md) — the core discovery / assess / brute-force / file-steal loop
- [Advanced Vulnerability Scanning](adv-scan.md) — Adv Scan tab: Nuclei / Nikto / SQLMap / ZAP, RAM gating, mesh delegation
- [Traffic Analysis](traffic-analysis.md) — passive `tcpdump` analyzer + C2 / scan / tunnel detection
- [AI Integration](AI_INTEGRATION.md) — hosted or self-hosted LLM analysis
- [IP Attribution](ip-intel.md) — geo / ASN / reputation, and what isn't knowable

## Network defense & watchers
- [Authority Verification & network tools](nettools.md) — Diagnostics, Switch & L2/L3, Interfaces + the detection-only L2→L7 watcher suite
- [Watchtower](watchtower.md) — unified, deduped alert feed with one Pushover path
- [Asset Inventory](asset-inventory.md) · [SIEM Forwarding](siem.md) · [Incident Correlation](incident-correlation.md)
- Standalone watcher daemons: [arp_guard](arp_guard.md) · [ndpwatch](ndpwatch.md) · [snmpwatch](snmpwatch.md) · [isiswatch](isiswatch.md) · [igmpwatch](igmpwatch.md) · [certwatch](certwatch.md) · [wifiwatch](wifiwatch.md) · [wpswatch](wpswatch.md) · [legacywatch](legacywatch.md)
- [EIGRP lab](eigrp_lab.md) — attack/adjacency test harness

## Wireless & RF
- [WiFi Analyzer](wifi-analyzer.md) — passive tri-band spectrum analyzer + coverage heatmap
- [RoomScan](roomscan.md) — touchscreen floor-plan tracer for the coverage heatmap
- [WiFi Defense (WIDS)](wifi-defense.md) — passive 802.11 intrusion detection
- [Wardriving](wardriving.md) — WiFi/BLE/cell logging with GPS recovery
- [Diagnostics panel](diagnostics.md) — radios / power / GPS sky view + Starview observatory
- [Cellular modem](cell.md) · [SDR / Sub-GHz](sdr-subghz.md) · [RF Waterfall](rf-waterfall.md) · [AirSnitch](airsnitch.md)

## Sensing & smart home
- [RuSense](rusense.md) — camera-free WiFi-CSI presence / motion / vitals sensing
- [Home Assistant integration](homeassistant.md) — native HA entities

## Mesh & fleet
- [Ragnar Mesh](mesh.md) — controller-free Tailscale unit mesh
- [Mesh Share & File Transfer](mesh-share.md)

## Hardware & displays
- [Display Buttons & Joystick Reference](DISPLAY_CONTROLS.md) — every HAT's key/joystick map
- [Kiosk Mode](kiosk.md) — fullscreen Chromium dashboard on an attached screen
- [Pager Guide](pager.md) — WiFi Pineapple Pager payload
- [Gen 2 Hardware](hardware-gen2.md) — reference-build BOM & assembly
- [Flipper One](flipper-one.md) — feasibility / porting notes
- [Pwnagotchi Bridge](PWNAGOTCHI.md) — side-by-side install & mode switching
- [BLE provisioning](ble_provisioning.md) · [Power badge](power.md) · [UPS integration](UPS_INTEGRATION.md)

## Platform & safety
- [Security & Authentication](SECURITY.md) — hardware-bound login, encryption at rest
- [Vault](vault.md) — encrypted file store
- [Kill Switch](KILL_SWITCH.md) — wipe all data

## Reference & project
- [System Specification](spec.md) — architecture & boot sequence
- [Comparative Grade](grade.md)
- [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md)
