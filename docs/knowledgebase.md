# Ragnar Knowledge Base

Short, verified answers to common questions. The chat assistant reads this page first.
Every answer names its source. The hidden proof line under each one is checked by
`tests/test_knowledgebase.py`, so a test fails if the source stops saying that.

## Finding things

### Where do I see the devices on my network?
On the **Network** tab, where discovery fills them in automatically. The **Discovered** tab holds captured credentials, not devices.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | the box discovers hosts -->

### What does the Discovered tab show?
The **Discovered** tab lists captured credentials. It does not list devices; those are on the **Network** tab.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Discovered Credentials -->

### Where are captured credentials shown?
In the **Discovered** tab.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Discovered Credentials -->

### Where is the Wi-Fi spectrum analyzer?
**Network → Signal Intelligence**, the sub-tab after Interfaces.
Source: wifi-analyzer.md
<!-- proof: docs/wifi-analyzer.md | Network → Signal Intelligence -->

### What is Signal Intelligence?
Ragnar's passive tri-band Wi-Fi spectrum analyzer and RF troubleshooter, at **Network → Signal Intelligence**.
Source: wifi-analyzer.md
<!-- proof: docs/wifi-analyzer.md | A passive, tri-band Wi-Fi RF troubleshooter -->

### Where is WiFi Defense?
It has its own top-level **WiFi Defense** tab, next to Network.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | its own top-level -->

### What is the Network Diagnostics section?
**Network → Diagnostics** holds about 70 network test modules and watchers, sorted by the OSI layer they mostly watch. It is not the Wardriving Diagnostics panel.
Source: nettools.md
<!-- proof: docs/nettools.md | With ~70 modules across the layers -->

### How do I find a module in Network Diagnostics?
Use the search box above the layer buttons. Type a protocol, vendor or CVE.
Source: nettools.md
<!-- proof: docs/nettools.md | sits above the layer buttons -->

### What is the Wardriving Diagnostics panel?
A read-only view of radios, power and GPS, at the bottom of the **Wardriving** tab.
Source: diagnostics.md
<!-- proof: docs/diagnostics.md | bottom of the **Wardriving** tab -->

### Where do I find Watchtower?
**Network → Diagnostics → Watchtower**.
Source: watchtower.md
<!-- proof: docs/watchtower.md | Diagnostics → *Watchtower* -->

### Where is the cellular uplink setting?
**Network → Interfaces → Cellular Uplink Fallback**.
Source: cellular-uplink.md
<!-- proof: docs/cellular-uplink.md | Network → Interfaces → Cellular Uplink Fallback -->

### Where is the Device Console?
On the **Dashboard** tab, below the Activity Log.
Source: serial-console.md
<!-- proof: docs/serial-console.md | Dashboard tab, below the Activity Log -->

### Where is the Rubber Ducky feature?
It is a card on the **Pentest** tab.
Source: rubber-ducky.md
<!-- proof: docs/rubber-ducky.md | A card on the **Pentest** tab -->

### Why can't I see the Pentest tab?
Pentest Mode must be enabled for the tab to appear.
Source: rubber-ducky.md
<!-- proof: docs/rubber-ducky.md | Pentest Mode must be enabled for the tab to appear -->

### Where is the reverse shell tool?
It is a card on the **Pentest** tab, shown when Pentest Mode is on.
Source: reverse-shell.md
<!-- proof: docs/reverse-shell.md | A Pentest-tab card -->

### Where do I run Nuclei?
In the **Adv Scan** tab.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | The CLI scanners -->

### Where do I run SQLMap?
In the **Adv Scan** tab.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | SQLMap** — automated SQL-injection detection -->

### Where do I run OWASP ZAP?
In the **Adv Scan** tab, on a board with 8GB+ RAM.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | OWASP ZAP** *(8GB+ RAM)* -->

### Where is the Vault?
In the **Files** tab. Its buttons are in the tab header, and once unlocked a Vault folder appears in Directories.
Source: vault.md
<!-- proof: docs/vault.md | The **Files** tab header has two Vault buttons -->

### Where do I connect Ragnar to a Wi-Fi network?
In the **Connect** tab, under Wi-Fi Management.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Available Networks -->

### Where do I change my password?
**Config > Security > Change Password**.
Source: SECURITY.md
<!-- proof: docs/SECURITY.md | Config > Security > Change Password -->

### Where do I turn AI on?
**Config → Integrations**, then tick **Enable AI Insights**.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Enable AI Insights -->

### Where do I set up push notifications?
**Config → Integrations → Push Notifications**.
Source: push-notifications.md
<!-- proof: docs/push-notifications.md | Config → Push Notifications -->

### Where do I update Ragnar from the web UI?
**Config → System → Update System**.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | update-btn-text -->

### How do I export my configuration?
**Config → System → Fleet Config → Export Config**.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Fleet Config -->

### Where do I see power problems?
A badge appears on the **Dashboard** on a real warning. The **System** tab has the full Power & Supply panel.
Source: power.md
<!-- proof: docs/power.md | hidden while the supply is healthy -->

### Does Ragnar show the battery of a Waveshare UPS HAT?
Yes. A UPS HAT (C) is detected over I2C at start and its percentage shows in the display header and the **System** tab Battery card.
Source: ups-hat.md
<!-- proof: docs/ups-hat.md | The card stays hidden when no battery is detected -->

### Where do I control the cooling fan?
In the **System** tab. It appears only when a fan driver exists.
Source: fan.md
<!-- proof: docs/fan.md | It appears only when a fan driver exists -->

### What port does the web UI use?
Port **8000** by default: `http://<ragnar-ip>:8000`.
Source: SECURITY.md
<!-- proof: docs/SECURITY.md | http://<ragnar-ip>:8000 -->

## Scanning

### How do I scan the network?
Discovery runs automatically on the **Network** tab. To sweep a range yourself, use the **IP Range Scan** card under Network → Hosts, or ask the chat to scan and click Run.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | the **IP Range Scan** card sweeps a whole -->

### What does the IP Range Scan do?
It finds live hosts in a range with a single `nmap -sn` sweep. It does not scan ports.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | *discovery only* -->

### How big a range can IP Range Scan cover?
Up to 1024 addresses, as a CIDR or a start-end range.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | bounded server-side to **1024 addresses** -->

### How fast does a host show as Offline on the Network tab?
Within about 10 seconds while a dashboard is open. With no dashboard open the check idles and takes about 30 seconds.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | Offline within about 10 seconds -->

### How does Ragnar know a host is online right now?
It sends each known host a unicast ARP request every 2 seconds, and pings a host that misses a reply before marking it Offline.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | Each known host gets a unicast ARP request -->

### Why does my phone show Offline when it is only asleep?
A device that stops answering for more than about 8 seconds shows Offline until it wakes. That is the trade-off of a 10 second verdict.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | shows Offline until it wakes -->

### What do the numbers on the Dashboard Targets card mean?
The large number is hosts Online right now, **Tot** is every known host, **Offline** is the difference, **New** is hosts first seen in the last 24 hours and **Lost** is hosts that went Offline in the last 24 hours.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | hosts first seen in the last 24 hours -->

### What does a deep scan do?
It is a TCP port scan of one host, covering the top 3000 ports. Results appear later.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | runs the existing deep scan (top 3000 ports) -->

### How do I exclude a host from scans?
Click **Ignore** on its row in the Network tab. This excludes it from future scans and automated actions.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | excludes a MAC/IP from future scans and automated actions -->

### What does Honor Scan Blacklists do?
It is the master switch for the per-host Ignore list.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | Honor Scan Blacklists -->

### Where are nmap commands logged?
In `data/logs/nmap.log`.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | data/logs/nmap.log -->

### Are brute-force attacks on by default?
No. They are off until you turn on **Enable Automatic Attacks** in **Config → Advanced**.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | Off unless enabled -->

### Which services can Ragnar brute force?
FTP, SSH, SMB, RDP, Telnet and SQL, once attacks are enabled.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | FTP, SSH, SMB, RDP, Telnet, SQL -->

### Which threat intelligence sources does Ragnar use?
CISA KEV, NVD CVE, AlienVault OTX and MITRE ATT&CK.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | Real-time fusion from -->

### What is file stealing in Ragnar?
It extracts data from services that authentication attacks open up, and stores it for review in the web UI.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | Extracts data from services that authentication attacks open up -->

### Why does a patched Debian or Ubuntu host show old CVEs?
The scan matches the upstream version, and distros backport fixes without changing it. Turn on **Distro-aware CVE Check** in **Config → General**: Ragnar then checks the Debian or Ubuntu security tracker and hides CVEs the distro already fixed. They stay tagged and can be expanded in **Threat Intel**.
Source: docs/scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | Distro-aware CVE check (Debian / Ubuntu) -->

## Advanced scanning

### What is the Adv Scan tab for?
It runs deeper web and vulnerability scanners: Nuclei, Nikto, SQLMap, WhatWeb, Nmap vuln scripts and OWASP ZAP.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | runs deeper web-application and vulnerability scanners -->

### How much RAM does ZAP need?
ZAP needs **8GB+ RAM** and greys out below that.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | stays gated at **8GB+ RAM** -->

### How much RAM does Nuclei need?
Nuclei is gated at **900MB RAM**.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | Nuclei is gated at 900MB RAM -->

### Does Nuclei run on a Pi Zero 2 W?
No, not locally. It greys out on a 512MB Pi Zero 2 W, but a mesh unit that can run it can take the scan.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | OOM a 512MB Pi Zero 2 W -->

### Does ZAP run on a Pi Zero?
No. ZAP needs 8GB+ RAM. A capable mesh unit can take the scan instead.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | stays gated at **8GB+ RAM** -->

### Does Nuclei run on a Raspberry Pi 3?
Yes. A 1GB Pi 3 runs it fine.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | a 1GB Pi 3 runs it fine -->

### Can a small board use a scanner it can't run?
Yes. If a mesh unit can run it, the scan is delegated to that peer and the results relay back.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | transparently delegated -->

### How do I install the advanced tools?
Run `sudo ./scripts/install_advanced_tools.sh` from the Ragnar folder, then `sudo systemctl restart ragnar`.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | sudo ./scripts/install_advanced_tools.sh -->

### What if Nuclei is not installed?
The Nuclei card shows an **Install** button that fetches the right build for your board.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | the card shows a -->

### What does parallel scanning need?
8GB+ RAM.
Source: adv-scan.md
<!-- proof: docs/adv-scan.md | **Parallel scanning** is likewise an 8GB+ feature -->

## Chat assistant

### Can the chat assistant run Nuclei?
No. It can only run a network scan, a vulnerability scan, a deep port scan, and turn Wi-Fi scanning on or off. Nuclei is in the **Adv Scan** tab.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | `run_network_scan` (ARP + nmap sweep) -->

### What actions can the chat assistant run?
A network scan, a vulnerability scan, a deep port scan of one host, and turning Wi-Fi scanning on or off.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | `start_wifi_scan`, `stop_wifi_scan` -->

### Does the chat assistant ask before running a scan?
Yes. Every action shows **Run** and **Cancel**, and nothing happens until you click Run.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | every action needs your approval -->

### How long is a Run or Cancel prompt valid?
5 minutes, and it works once.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | A prompt expires after 5 minutes and works once -->

### How do I hide the chat assistant?
Untick **Show chat assistant** under **Config → Integrations**. This also stops chat requests. AI Insights keep working.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | untick **Show chat assistant** -->

### Why don't I see the chat button?
AI must be enabled and **Show chat assistant** must be ticked in **Config → Integrations**. The button is on the Dashboard tab.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | When AI is enabled, a **floating chat button** -->

### How do I use a self-hosted AI model?
Set the endpoint under Self-Hosted / Custom Endpoint in **Config → Integrations**, click **Connect** to list models, then **Save Endpoint**.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | Then click **Save Endpoint** -->

### Which self-hosted AI servers work with Ragnar?
Any OpenAI-compatible server, such as Ollama, LocalAI, vLLM or LM Studio.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | any **OpenAI-compatible** server -->

### Does a self-hosted AI model need an API token?
The token is optional with a base URL, since most local servers accept any key.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | The API token becomes **optional** -->

## Wireless

### What is WiFi Defense?
A passive wireless intrusion-detection system. It listens on a monitor-mode adapter for 802.11 management frames and flags Wi-Fi attacks.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | A passive **wireless intrusion-detection system** -->

### Does WiFi Defense transmit anything?
No. It is receive-only and never transmits a frame.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | WiFi Defense never transmits a frame -->

### What hardware does WiFi Defense need?
A Wi-Fi adapter that supports monitor mode.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | **monitor-mode** adapter -->

### What attacks does WiFi Defense detect?
Classic Wi-Fi attacks, including deauth and disassoc floods and beacon floods.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | Deauth / disassoc flood -->

### What is the difference between WiFi Defense and Signal Intelligence?
Signal Intelligence surveys the spectrum. WiFi Defense watches for attacks.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | this tab watches for *attacks* -->

### Does Signal Intelligence transmit anything?
No. It is strictly passive and only listens for beacons.
Source: wifi-analyzer.md
<!-- proof: docs/wifi-analyzer.md | **Strictly passive.** -->

### What is AirSnitch?
A module that checks whether a Wi-Fi network really enforces client isolation.
Source: airsnitch.md
<!-- proof: docs/airsnitch.md | properly enforces **client isolation** -->

### How many Wi-Fi interfaces does AirSnitch need?
Two: one acting as the victim and one as the attacker.
Source: airsnitch.md
<!-- proof: docs/airsnitch.md | **two wireless interfaces** -->

### What is the RF Waterfall?
A spectrum page with an RTL-SDR panel and a HackRF panel. Both are receive-only.
Source: rf-waterfall-guide.md
<!-- proof: docs/rf-waterfall-guide.md | **receive-only** -->

### What frequencies does the RF Waterfall cover?
The RTL-SDR panel covers about 24 MHz to 1.7 GHz. The HackRF panel covers 1 MHz to 6 GHz.
Source: rf-waterfall-guide.md
<!-- proof: docs/rf-waterfall-guide.md | (~24 MHz–1.7 GHz) -->

### Can an RTL-SDR see Wi-Fi?
No. It tops out around 1.7 GHz, below the 2.4, 5 and 6 GHz Wi-Fi bands.
Source: sdr-subghz.md
<!-- proof: docs/sdr-subghz.md | tops out ~1.7 GHz -->

### Does the RF Waterfall transmit?
No. Both panels are receive-only.
Source: rf-waterfall-guide.md
<!-- proof: docs/rf-waterfall-guide.md | **receive-only** -->

### What is ADS-B in Ragnar?
An RTL-SDR tool that hears aircraft position broadcasts at 1090 MHz and shows them on the ADS-B Radar page.
Source: sdr-subghz.md
<!-- proof: docs/sdr-subghz.md | ## ADS-B radar (1090 MHz aircraft) -->

### Does Ragnar support Meshtastic?
Yes. It can read a USB Meshtastic node, including its node database, positions and messages.
Source: README.md
<!-- proof: README.md | read a USB Meshtastic node -->

### How do I connect to Ragnar when it has no network?
It raises its own access point named `Ragnar`. The password is `ragnarconnect`, and the setup page is `http://192.168.4.1:8000`.
Source: RagnarAP.md
<!-- proof: docs/RagnarAP.md | `ragnarconnect` -->

### Why does Start AP Mode say my Wi-Fi adapter does not support Access Point mode?
The adapter's driver cannot run a hotspot, so Ragnar does not try and leaves Wi-Fi connected. Use the Pi's built-in Wi-Fi or an AP-capable adapter.
Source: RagnarAP.md
<!-- proof: docs/RagnarAP.md | the AP is **not** attempted and the current Wi-Fi connection is left untouched -->

## Bluetooth

### What is BLE Watch?
A passive Bluetooth Low Energy attack monitor. An external sniffer captures the traffic and BLE Watch parses it.
Source: blewatch.md
<!-- proof: docs/blewatch.md | passive Bluetooth Low Energy attack monitor -->

### What hardware does BLE Watch need?
An external nRF sniffer: an nRF51 such as the Adafruit Bluefruit LE Sniffer, or an nRF52 such as the nRF52840 Dongle.
Source: blewatch.md
<!-- proof: docs/blewatch.md | **Both nRF Sniffer generations are supported:** -->

### Does BLE Watch transmit anything?
No. It is detection only and never transmits a BLE packet.
Source: blewatch.md
<!-- proof: docs/blewatch.md | it never transmits a BLE packet -->

### Where do I find BLE Watch?
**Network → Diagnostics → L2**, under Passive · Bluetooth LE. It can also be shown on the Signal Intelligence spectrum.
Source: blewatch.md
<!-- proof: docs/blewatch.md | Network → Diagnostics → L2 tab -->

## Alerts and reporting

### What is Watchtower?
One deduplicated feed of the alerts from Ragnar's passive watchers, with one notification path for new high and critical findings.
Source: watchtower.md
<!-- proof: docs/watchtower.md | shows them in one deduped feed -->

### Does Watchtower capture packets?
No. It only reads the watchers' log files. It never captures or sends a packet.
Source: watchtower.md
<!-- proof: docs/watchtower.md | it never captures a packet or sends one -->

### What is incident correlation?
It fuses related Watchtower alerts into attack-chain incidents. It only analyses alerts already collected.
Source: incident-correlation.md
<!-- proof: docs/incident-correlation.md | pure analysis over already-collected alerts -->

### How long is the incident correlation window?
600 seconds by default, set by `incident_window_s`.
Source: incident-correlation.md
<!-- proof: docs/incident-correlation.md | default 600 s -->

### Can Ragnar send alerts to a SIEM?
Yes. It forwards every normalized alert over syslog, Splunk HEC, Elasticsearch, webhook or Slack. Watchtower must be enabled.
Source: siem.md
<!-- proof: docs/siem.md | **Watchtower must be enabled** -->

### Which SIEM formats does Ragnar support?
Syslog with CEF, LEEF or plain text, Splunk HEC, Elasticsearch or OpenSearch, webhooks, and Slack-style messages.
Source: siem.md
<!-- proof: docs/siem.md | Supported collectors -->

### What is Asset Inventory?
The **Assets** view turns the host list into a classified inventory, lets you mark what belongs, and alerts when things change.
Source: asset-inventory.md
<!-- proof: docs/asset-inventory.md | **notices when things change** -->

### Does Asset Inventory send packets?
No. It is passive and read-only and sends no packets of its own.
Source: asset-inventory.md
<!-- proof: docs/asset-inventory.md | sends no packets of its own -->

### What is ARP Guard?
A detection-only ARP monitor. It never sends a corrective ARP, blocks traffic or intervenes.
Source: arp_guard.md
<!-- proof: docs/arp_guard.md | It never sends a corrective ARP -->

### How do push notifications work?
Ragnar sends alerts to Pushover, Slack or both. Set them up in **Config → Integrations → Push Notifications** and use **Send Test Notification**.
Source: push-notifications.md
<!-- proof: docs/push-notifications.md | every configured channel receives every -->

### What does the Pushover setup need?
A User Key and an application API Token from pushover.net.
Source: push-notifications.md
<!-- proof: docs/push-notifications.md | A User Key + an application API Token -->

## Traffic

### What does Traffic Analysis do?
It captures live packets with `tcpdump` and shows per-host bandwidth, connections, protocols and DNS. It also detects port scans, DNS tunnelling and C2 beacons.
Source: traffic-analysis.md
<!-- proof: docs/traffic-analysis.md | Live packet capture and passive network monitoring -->

### Does Traffic Analysis send packets?
No. It is detection-only and never sends a packet.
Source: traffic-analysis.md
<!-- proof: docs/traffic-analysis.md | It never sends a packet -->

### Does Traffic Analysis work on a Pi Zero 2 W?
Yes. It runs on any board that has `tcpdump`.
Source: traffic-analysis.md
<!-- proof: docs/traffic-analysis.md | any board Ragnar runs on -->

### Why is the Traffic tab missing?
`tcpdump` is missing. Install it with `sudo apt-get install tcpdump`.
Source: traffic-analysis.md
<!-- proof: docs/traffic-analysis.md | the Traffic tab is hidden -->

### How do I start a packet capture?
Use the **Traffic** tab, which captures live packets with `tcpdump`.
Source: traffic-analysis.md
<!-- proof: docs/traffic-analysis.md | Live packet capture and passive network monitoring -->

## RuSense

### What is RuSense?
Ragnar's camera-free surveillance system. It reads the distortions a moving body makes in ordinary 2.4 GHz Wi-Fi.
Source: rusense.md
<!-- proof: docs/rusense.md | RuSense is Ragnar's **no-camera surveillance** system -->

### Does RuSense use a camera?
No. No images are ever captured.
Source: rusense.md
<!-- proof: docs/rusense.md | No images are ever captured -->

### What does RuSense sense with?
Wi-Fi Channel State Information (CSI), captured by ESP32-S3 or ESP32-C6 sensor nodes on 2.4 GHz.
Source: rusense.md
<!-- proof: docs/rusense.md | An ESP32-S3 or ESP32-C6 running the RuSense CSI firmware -->

### What can RuSense detect?
Occupancy, motion and roughly how many people are present. With a trained model it also estimates coarse posture and vital signs at rest.
Source: rusense.md
<!-- proof: docs/rusense.md | roughly **how many people** -->

### Is RuSense a medical device?
No. It is wellness tracking, not a medical device.
Source: rusense.md
<!-- proof: docs/rusense.md | **not a medical device** -->

## Wardriving

### What is wardriving in Ragnar?
An engine that collects Wi-Fi networks, BLE devices, Zigbee devices and cell towers as you move, with GPS positions.
Source: wardriving.md
<!-- proof: docs/wardriving.md | wardriving engine collects WiFi networks, BLE devices -->

### What hardware do I need for wardriving?
A Raspberry Pi or PC with Wi-Fi. A USB GPS receiver adds positions, and HuginnESP or Piglet boards can add more radios.
Source: wardriving.md
<!-- proof: docs/wardriving.md | Optional USB GPS receiver -->

### Do I need a GPS for wardriving?
A USB GPS is optional and is auto-detected at startup, but it is what provides positions.
Source: wardriving.md
<!-- proof: docs/wardriving.md | Optional USB GPS receiver -->

### What formats can wardriving export?
WiGLE CSV and KML, plus a printable Wi-Fi survey report.
Source: README.md
<!-- proof: README.md | exports WiGLE CSV / KML -->

### Which modems work for cell tower capture?
A modem that ModemManager lists in QMI, MBIM or serial mode. Check it with `mmcli -L`.
Source: cell.md
<!-- proof: docs/cell.md | Confirm any device with `mmcli -L` -->

### Can a tethered hotspot capture cell towers?
No. A USB-tethered hotspot such as an Orbic Speed can't capture towers, but it can be a backup internet uplink.
Source: cell.md
<!-- proof: docs/cell.md | hotspot (e.g. Orbic Speed) -->

## Security and data

### Is login on by default?
No. Ragnar runs open on first start until you enable authentication in **Config → Security**.
Source: SECURITY.md
<!-- proof: docs/SECURITY.md | On first start, Ragnar runs open (no login) -->

### How do I turn on login for the dashboard?
In **Config → Security**, enter a username and password and click **Enable Authentication**. Save the recovery codes.
Source: SECURITY.md
<!-- proof: docs/SECURITY.md | click **Enable Authentication** -->

### How long does a login session last?
24 hours.
Source: SECURITY.md
<!-- proof: docs/SECURITY.md | Sessions last 24 hours -->

### What happens if I forget my login password?
On the login page, use **Forgot password? Use recovery code**. You get 10 one-time codes at setup.
Source: SECURITY.md
<!-- proof: docs/SECURITY.md | Forgot password? Use recovery code -->

### Is the database encrypted?
Once authentication is enabled, `ragnar.db` is encrypted at rest with AES-128 (Fernet) whenever you log out or Ragnar shuts down.
Source: SECURITY.md
<!-- proof: docs/SECURITY.md | encrypted with AES-128 (Fernet) -->

### What is the Vault?
A password-protected, size-capped encrypted store in the **Files** tab.
Source: vault.md
<!-- proof: docs/vault.md | password-protected, size-capped store -->

### What encryption does the Vault use?
AES-256-GCM.
Source: files.md
<!-- proof: docs/files.md | AES-256-GCM encrypted store -->

### How long until the Vault locks itself?
After 15 minutes of inactivity.
Source: vault.md
<!-- proof: docs/vault.md | auto-locks after 15 minutes of inactivity -->

### Can I recover a forgotten Vault password?
No. There is no password recovery for the Vault.
Source: vault.md
<!-- proof: docs/vault.md | There is no password recovery -->

### What does the kill switch do?
It permanently wipes databases and logs and erases the Ragnar installation, with an optional shutdown. It is for use after demonstrations.
Source: KILL_SWITCH.md
<!-- proof: docs/KILL_SWITCH.md | Erases the repository -->

### Can the chat assistant run the kill switch?
No. The chat assistant has no way to run it.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | curated allowlist -->

### What can the Files tab do?
It is a full file manager: create, upload, move, rename, delete and edit text files, across Ragnar's data folders.
Source: files.md
<!-- proof: docs/files.md | is a full file manager -->

### Is the web terminal on by default?
No. It is off by default and gated by login.
Source: README.md
<!-- proof: README.md | off by default and lo -->

## Install and update

### How do I install Ragnar?
Download `install_ragnar.sh`, make it executable and run it with sudo, then reboot at the end.
Source: INSTALL.md
<!-- proof: docs/INSTALL.md | sudo chmod +x install_ragnar.sh -->

### Which OS does Ragnar need?
Raspberry Pi OS Lite (64-bit), Debian Trixie, with no desktop.
Source: INSTALL.md
<!-- proof: docs/INSTALL.md | Use Raspberry Pi OS Lite (64-bit) Debian Trixie -->

### Which installer option is Docker?
On a Raspberry Pi it is option **6**. On other Linux hosts it is option **4**.
Source: install_ragnar.sh
<!-- proof: install_ragnar.sh | 6)${CYAN} Docker container -->

### Which installer option is the CardputerZero?
Option **7**, on a Raspberry Pi install.
Source: install_ragnar.sh
<!-- proof: install_ragnar.sh | 7)${CYAN} M5Stack CardputerZero -->

### Which installer option is the WiFi Pineapple Pager?
On a Raspberry Pi it is option **5**. On other Linux hosts it is option **3**.
Source: install_ragnar.sh
<!-- proof: install_ragnar.sh | 5)${CYAN} WiFi Pineapple Pager -->

### How do I update Ragnar?
Use **Config → System → Update System**, or run `sudo /home/ragnar/Ragnar/update_ragnar.sh`.
Source: updates.md
<!-- proof: docs/updates.md | sudo /home/ragnar/Ragnar/update_ragnar.sh -->

### How do I update the operating system packages?
**Config → System → OS Packages**. **Check for Updates** lists what apt can upgrade, security fixes first; **Upgrade All** installs them. Ragnar's own **Update System** button does not touch OS packages.
Source: updates.md
<!-- proof: docs/updates.md | **Config → System → OS Packages** updates everything apt manages -->

### How do I update Tailscale?
Use **Update Tailscale** in the banner on the **Ragnar Mesh** tab, or **Update Tailscale only** on **Config → System → OS Packages**. tailscaled restarts, so the mesh drops for a few seconds and then reconnects by itself.
Source: mesh.md
<!-- proof: docs/mesh.md | Both run `apt-get install --only-upgrade tailscale` -->

### Why does a package stay in the OS Packages list after Upgrade All?
It is held back: Upgrade All never removes a package, and upgrading this one would. The card lists it under **Held back** with what it removes and adds, and an **Upgrade anyway** button.
Source: updates.md
<!-- proof: docs/updates.md | lists them under **Held back** on the -->

### Why is rpd-common held back?
`rpd-common` 1.35 needs `pcmanfm` replaced by Raspberry Pi's `pcmanfm-pi`. Upgrade All never removes a package, so it waits for you to press **Upgrade anyway**. Ragnar doesn't use either package.
Source: updates.md
<!-- proof: docs/updates.md | `Breaks/Replaces: pcmanfm` -->

### Does updating Ragnar also update Tailscale?
No. `update_ragnar.sh` and **Update System** keep Tailscale installed but never upgrade it. Upgrade it from the Mesh tab or **Config → System → OS Packages**.
Source: mesh.md
<!-- proof: docs/mesh.md | `update_ragnar.sh` does **not** upgrade Tailscale -->

### What is Ragnar OS?
A prebuilt image: Raspberry Pi OS Lite with Ragnar already installed. Flash it, boot it and open the web UI.
Source: ragnar-os.md
<!-- proof: docs/ragnar-os.md | with Ragnar already installed -->

### What is Ulfberht?
The offensive, red-team edition of Ragnar OS, built on a Kali Linux ARM base. It is for authorized security testing only.
Source: ragnar-os-ulfberht.md
<!-- proof: docs/ragnar-os-ulfberht.md | is an offensive / red-team edition -->

### What are Engagements?
Playbooks that chain discovery, diagnostics, assessment and reporting into one report. They are exclusive to the official Ulfberht image.
Source: ulfberht-workflows.md
<!-- proof: docs/ulfberht-workflows.md | It is **exclusive to the official Ulfberht image** -->

### Can I run Ragnar in Docker?
Yes, on a Linux host. Docker gives you the dashboard, scanning engine and watchers without Pi hardware.
Source: DOCKER.md
<!-- proof: docs/DOCKER.md | Ragnar can run as a container on any Linux host -->

### Is Docker good for wardriving?
No. Wardriving, monitor mode, SDR, GPS and Bluetooth are best on a native Raspberry Pi install.
Source: DOCKER.md
<!-- proof: docs/DOCKER.md | **Native install on a Raspberry Pi** -->

### Can Ragnar run on a CardputerZero?
Yes. It is a real Raspberry Pi Compute Module Zero, so full Ragnar runs on it.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | **full Ragnar runs on it unchanged** -->

### Does the CardputerZero show its battery percentage?
Yes. Ragnar reads the built-in BQ27220 fuel gauge and draws a battery icon with the percentage in the top-right corner of every screen, plus the **System** tab Battery card. Check it with `python3 sysfs_battery.py`.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | draws a battery icon with the percentage in the top-right corner of every -->

### My CardputerZero screen is upside down. How do I turn it?
Press **Backspace** on a Ragnar screen. It flips the screen 180° and saves the choice. New installs start turned the right way.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | flips the screen between its two landscape positions and saves the -->

### Which keys change page on a CardputerZero?
`F`, `X`, `Z` and `C`, the keys with the arrow legends. `F`/`Z` go back and `X`/`C` go forward, with or without **fn**. OK (Enter) opens the diagnostic screens and Esc returns.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | `F` `X` `Z` `C` are the keys with the arrow legends -->

### How do I get the female avatar on a CardputerZero?
Set `mesh_viking_gender` to `female` (Mesh tab or `config/shared_config.json`). The shieldmaiden then shows in full colour.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | Set `mesh_viking_gender` to `female` for the shieldmaiden -->

### The arrow keys do nothing on my CardputerZero. How do I check them?
Press a key and watch the bottom-left corner of the screen: it names the key and its action for two seconds. If nothing shows, run `sudo python3 cardputer_input.py`, which prints every key it receives.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | the bottom-left corner names the -->

### Does Ragnar support the CardputerZero's Cap modules?
Yes for the LoRa + GNSS Cap and the CC1101 radio of the Sub-GHz Cap. The GNSS feeds Ragnar's GPS, the LoRa radio runs as a Meshtastic node, and the CC1101 sweeps sub-GHz bands on the RF Waterfall page. NFC is not supported yet.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | **NFC (ST25R3916).** Not supported yet. -->

### Can I swap CardputerZero Caps while it is running?
No. Caps are not hot-swappable. Power the CardputerZero off before fitting or removing one; Ragnar identifies the Cap once at start.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | **Caps are not hot-swappable.** -->

### How do I use the CardputerZero LoRa Cap with Meshtastic?
Run `sudo scripts/cardputer_lora_meshtastic.sh install`, then set your region once with `meshtastic --host 127.0.0.1 --set lora.region EU_868`. It needs `meshtasticd` installed.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | sudo scripts/cardputer_lora_meshtastic.sh install -->

### Does the CardputerZero camera work in Ragnar?
Yes. **System → Camera** has a live view and a **Take photo** button; photos are saved to `data/camera/`.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | **Take photo** saves a JPEG -->

### Does the GPS in the CardputerZero LoRa Cap need setting up?
No. Ragnar powers the Cap at start and its GPS auto-detection finds the receiver on `/dev/ttyS0` at 115200 baud.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | Ragnar's GPS auto-detection finds it -->

### Does the installer ask about PiSugar on a CardputerZero?
No. The board has its own battery, so option 7 skips the PiSugar question.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | the installer does not ask about a PiSugar on this board -->

### How do I get the stock launcher back on a CardputerZero?
Run `sudo scripts/cardputer_takeover.sh revert`, then reboot.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | cardputer_takeover.sh revert -->

### How do I add a screen to a headless install?
Run `sudo ./installhead.sh` and pick your screen.
Source: INSTALL.md
<!-- proof: docs/INSTALL.md | sudo ./installhead.sh -->

## Hardware and modes

### Which displays does Ragnar support?
e-Paper, TFT and OLED panels, MAX7219 LED matrices, the WiFi Pineapple Pager, and an HDMI kiosk.
Source: README.md
<!-- proof: README.md | 2.13" e-Paper HAT -->

### Can the 1.44" LCD HAT show colour?
Yes. Its main screen and wardriving screens use a dark colour theme with a full-colour viking. Set `lcd_color` to false to turn it off.
Source: DISPLAY_CONTROLS.md
<!-- proof: docs/DISPLAY_CONTROLS.md | The LCD HAT is a colour panel, and two kinds of screen use it -->

### Why is my e-Paper or TFT screen dark on Ragnar OS Ulfberht?
Units imaged before the fix lack SPI, the GPIO Python modules and the Pi 5 GPIO alias. Run Update, then reboot once.
Source: ragnar-os-ulfberht.md
<!-- proof: docs/ragnar-os-ulfberht.md | then **reboot once** so SPI and I2C come up -->

### What is kiosk mode?
It shows the Ragnar web UI fullscreen in Chromium on a screen attached to the Pi, and starts on every boot.
Source: kiosk.md
<!-- proof: docs/kiosk.md | comes up fullscreen in Chromium -->

### How much RAM does kiosk mode need?
2 GB or more, and at least 2 cores. It is not available on a Pi Zero 2 W.
Source: kiosk.md
<!-- proof: docs/kiosk.md | KIOSK_MIN_RAM_GB = 2.0 -->

### How do I turn on kiosk mode?
Turn on **On-screen Display** in **Config → System**, on supported boards.
Source: kiosk.md
<!-- proof: docs/kiosk.md | Turn on **On-screen Display** in the **Config** tab -->

### What is the Pwnagotchi swap?
It switches a device between running Ragnar and running Pwnagotchi. Only one can run at a time on a display build.
Source: PWNAGOTCHI.md
<!-- proof: docs/PWNAGOTCHI.md | swap between Ragnar and -->

### How do I switch to Pwnagotchi?
**Config → System → Pwnagotchi Bridge → Switch to Pwnagotchi**, or double-tap or long-press the PiSugar button.
Source: PWNAGOTCHI.md
<!-- proof: docs/PWNAGOTCHI.md | **Switch to Pwnagotchi** -->

### What is the Rubber Ducky feature?
It turns the Pi into a USB keyboard that types a script into the host it is plugged into, for authorised testing.
Source: rubber-ducky.md
<!-- proof: docs/rubber-ducky.md | turns the Pi into a USB keyboard -->

### What is the Device Console?
It streams a switch, router or firewall's serial console to the dashboard over a USB console cable. It is read-only until you tick Allow write.
Source: serial-console.md
<!-- proof: docs/serial-console.md | **Read-only by default.** -->

### What is the cellular uplink fallback?
A USB hotspot, phone or LTE modem becomes a backup internet path, used only when Ethernet and Wi-Fi are down. It is never scanned.
Source: cellular-uplink.md
<!-- proof: docs/cellular-uplink.md | **backup internet path** -->

### What is Ragnar Mesh?
It links Ragnar units over Tailscale so each is reachable and can see what the others see. There is no controller.
Source: mesh.md
<!-- proof: docs/mesh.md | **There is no controller.** -->

### Does Ragnar work with Home Assistant?
Yes. An integration brings RuSense presence and security alerts into Home Assistant as native entities.
Source: homeassistant.md
<!-- proof: docs/homeassistant.md | as native entities -->

### What is the WiFi Pineapple Pager version?
Ragnar deployed to the Pager as a native payload, with its LCD, buttons and LED status. It needs Pager firmware 1.0.7 or newer.
Source: pager.md
<!-- proof: docs/pager.md | Firmware 1.0.7+ -->

## Chat assistant

### Can the chat assistant change settings?
No. It can't change settings. Use the **Config** tab.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | curated allowlist -->

### Can the chat assistant delete my data?
No. It has no tool that deletes anything.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | curated allowlist -->

### Can the chat assistant start wardriving?
No. Start it from the **Wardriving** tab.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | curated allowlist -->

### What is the difference between AI Insights and the chat assistant?
AI Insights are summary cards on the Dashboard. The chat assistant answers questions and proposes actions that you approve with Run.
Source: AI_INTEGRATION.md
<!-- proof: docs/AI_INTEGRATION.md | AI insights appear automatically on the Dashboard tab -->

## Wardriving

### How do I start wardriving?
Click **Start** in the **Wardriving** tab.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | wd-toggle-btn -->

## Scanning

### What is Threat Intel?
Live threat data from CISA KEV, NVD CVE, AlienVault OTX and MITRE ATT&CK, used to add context to findings and prioritize them.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | used to prioritize findings -->

### Can Ragnar brute force SSH?
Yes, once attacks are enabled. They are off by default, and only for systems you are authorized to test.
Source: scanning-and-attacks.md
<!-- proof: docs/scanning-and-attacks.md | Credential attacks against common services -->

## Data and safety

### How do I delete my scan data?
Not from chat. Use **Reset Vulnerabilities** and **Reset Threat Intel** in **Config → System → Data Management**. Each asks first and can't be undone. Do not use the kill switch for this: it erases the whole Ragnar install.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Data Management -->

### How do I clear the vulnerability list?
Click **Reset Vulnerabilities** in **Config → System → Data Management**. It can't be undone.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Reset Vulnerabilities -->

### How do I wipe wardriving data?
Click **Wipe Data** under **Wipe All Wardriving Data** in **Config → Wardriving**. It can't be undone.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Wipe All Wardriving Data -->

### How do I use the kill switch?
Not from chat, and not to clear scan data, because it erases the whole Ragnar install. The assistant doesn't give out its command or token. Read `docs/KILL_SWITCH.md`.
Source: KILL_SWITCH.md
<!-- proof: docs/KILL_SWITCH.md | Erases the repository -->

## System control

### How do I reboot Ragnar?
Not from chat. Click **Reboot System** in **Config → System**.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | rebootSystem() -->

### How do I shut down Ragnar?
Not from chat. Click **Shutdown System** in **Config → System**.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | shutdownSystem() -->

### How do I restart the Ragnar service?
Not from chat. Click **Restart Service** in **Config → System**.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | restartService() -->

## Network control

### How do I block a device on my network?
Ragnar can't block devices. Do that on your router or firewall. The **Ignore** button on the **Network** tab only excludes a host from scanning and attacks.
Source: spec.md
<!-- proof: docs/spec.md | per-host **Ignore** button -->

### How do I open or forward a port on Ragnar?
Ragnar has no firewall or port settings. Do that on your router, or in the operating system of the unit.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Configuration -->

### Is Ragnar a firewall?
No. Ragnar watches and tests your network. It doesn't filter traffic, so blocking is done on your router or firewall.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | It is a detection tool -->

### How do I reach Ragnar when there is no Wi-Fi?
If Ragnar can't join a saved network within about a minute of booting, it starts its own access point. Join `Ragnar` with the password `ragnarconnect`, then open `http://192.168.4.1:8000`.
Source: INSTALL.md
<!-- proof: docs/INSTALL.md | it starts its own access point -->

## Hardware

### Does Ragnar need a Raspberry Pi?
No. It also runs in Docker on any Linux host, with the dashboard, scanning and watchers. Wardriving, Wi-Fi monitor mode, SDR, GPS, Bluetooth and e-Paper need a native install on a Raspberry Pi.
Source: DOCKER.md
<!-- proof: docs/DOCKER.md | without any Raspberry-Pi hardware -->

### Can I run Ragnar on a PC or server?
Yes, in Docker on a Linux host such as a server, VM or NAS. Radios and USB hardware need a native install on a Raspberry Pi.
Source: DOCKER.md
<!-- proof: docs/DOCKER.md | server, VM, NAS -->

### Can I run Ragnar on Windows or a Mac?
Docker runs there, but through a VM, so LAN scanning is crippled and radios effectively don't work. Use a Linux host or a native Pi.
Source: DOCKER.md
<!-- proof: docs/DOCKER.md | LAN scanning is crippled -->

## Attacks

### How do I turn on attacks or brute force?
Turn on **Enable Automatic Attacks** in **Config → Advanced**, in the General section. Use it only on systems you are authorized to test.
Source: web/scripts/ragnar_modern.js
<!-- proof: web/scripts/ragnar_modern.js | Enable Automatic Attacks -->

### What does Pentest Mode do?
Enabling Pentest Mode on the Dashboard reveals the **Pentest** tab, with manual attacks, Bluetooth pentests and the Lynis audit.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Enable Pentest Mode -->

### Can Ragnar deauth devices?
Not on the standard edition, and not from chat. WiFi Defense is receive-only: it detects deauth attacks and never sends them. The offensive Ulfberht edition has a Wireless WPA/WPS Audit engagement for networks you are authorized to test.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | does not deauth -->

### Does WiFi Defense send frames?
No. It is receive-only and never transmits a frame, so it can't deauth or inject.
Source: wifi-defense.md
<!-- proof: docs/wifi-defense.md | never transmits a frame -->

## Display

### How do I change the display type?
Not from chat. Set **EPD Type** in **Config → Advanced**, in the Display section.
Source: web/scripts/ragnar_modern.js
<!-- proof: web/scripts/ragnar_modern.js | label: "EPD Type" -->

### What is the Display tab for?
It shows the same content as the unit's physical screen, plus its current status. The tab only appears on units with a display.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | exact same content as your Ragnar device's physical display -->

## Chat assistant

### How do I turn off the chat assistant?
Not from chat. Untick **Show chat assistant** under **Config → Integrations**.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | Show chat assistant -->

## Hardware

### How do I install Ragnar on a CardputerZero?
Run the installer and pick **option 7**, or set `RAGNAR_PROFILE=cardputer`. It does a normal Raspberry Pi install pinned to the built-in screen.
Source: M5StackCardputerZero.md
<!-- proof: docs/M5StackCardputerZero.md | Run the installer and pick **option 7** -->

## Radio tools

### Where is the ADS-B Radar?
**Network → Signal Intelligence → ADS-B Radar**. It shows live aircraft and needs an RTL-SDR.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | id="wifi-adsb-btn" -->

### How do I see aircraft and planes?
Open **Network → Signal Intelligence → ADS-B Radar**. It needs an RTL-SDR.
Source: web/index_modern.html
<!-- proof: web/index_modern.html | id="wifi-adsb-btn" -->
