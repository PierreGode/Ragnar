# <img src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" alt="thumbnail_IMG_0546" width="33"> Ragnar

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)



<p align="center">
<img width="300" height="600" alt="image" src="https://github.com/user-attachments/assets/d79940c5-5076-430f-aa75-a4094a4d2910" />

</p>

Ragnar is a « Tamagotchi like » sophisticated, autonomous network scanning, vulnerability assessment, and offensive security tool designed to run on a Raspberry Pi equipped with a 2.13-inch e-Paper HAT. This document provides a detailed explanation of the project.

### 🌐 Web Interface & WiFi Management

**Modern Dashboard** - Access Ragnar's sleek web interface at `http://<ragnar-ip>:8000`:
- Real-time network discovery and vulnerability scanning
- Multi-source threat intelligence dashboard
- File management with image gallery
- System monitoring and configuration
- Hardware profile auto-detection (Pi Zero 2W, Pi 4, Pi 5)

**WiFi Configuration Portal** - When Ragnar can't connect to a known network, it automatically creates a WiFi hotspot:
1. **Connect** to WiFi network: `Ragnar` (password Ragnar)
2. **Navigate** to: `http://192.168.4.1/portal`
3. **Configure** your home WiFi credentials via the mobile-friendly interface
4. **Monitor** the countdown timer - Ragnar will automatically try to reconnect to kn wifi after som time if AP is unused.
5. **Done** - Ragnar exits AP mode and connects to your network

The AP portal features:
- Network scanning with signal strength indicators
- Manual network entry for hidden SSIDs
- Countdown timer showing when Ragnar will retry WiFi
- Known networks management
- One-tap connection to saved networks


## 📚 Table of Contents

- [Introduction](#-introduction)
- [Features](#-features)
- [Getting Started](#-getting-started)
  - [Prerequisites](#-prerequisites)
  - [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Example](#-usage-example)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

## 📄 Introduction

Ragnar is a fork from the awesome project [Bjorn](https://github.com/infinition/Bjorn)  and is rebuilt powerful tool designed to perform comprehensive network scanning, vulnerability assessment, and data ex-filtration. Its modular design and extensive configuration options allow for flexible and targeted operations. By combining different actions and orchestrating them intelligently, Ragnar can provide valuable insights into network security and help identify and mitigate potential risks.

Ragnar is built for 64-bit Raspberry Pi OS (Debian Trixie). 

**Key Improvements Over Bjorn:**
- **Smart WiFi Management**: Endless loop monitoring with automatic AP mode fallback
- **Modern Web UI**: Tailwind CSS dashboard with real-time WebSocket updates
- **Multi-Source Threat Intelligence**: Integration with CISA KEV, NVD, OTX, and MITRE ATT&CK
- **Mobile Configuration**: Captive portal for on-the-go WiFi setup via smartphone
- **Resource Optimization**: Hardware-specific profiles for Pi Zero 2W, Pi 4, and Pi 5
- **Enhanced Display**: IP address display on e-Paper screen

The e-Paper HAT display and web interface make it easy to monitor and interact with Ragnar, providing real-time updates and status information. With its extensible architecture and customizable actions, Ragnar can be adapted to suit a wide range of security testing and monitoring needs.

## 🌟 Features

- **Network Scanning**: Identifies live hosts and open ports on the network.
- **Vulnerability Assessment**: Performs vulnerability scans using Nmap and other tools.
- **Multi-Source Threat Intelligence**: Real-time threat intelligence fusion from CISA KEV, NVD CVE, AlienVault OTX, and MITRE ATT&CK.
- **System Attacks**: Conducts brute-force attacks on various services (FTP, SSH, SMB, RDP, Telnet, SQL).
- **File Stealing**: Extracts data from vulnerable services.
- **Smart WiFi Management**: 
  - Auto-connects to known networks on boot
  - Falls back to AP mode when no WiFi available
  - Captive portal at `http://192.168.4.1/portal` for easy mobile configuration
  - Automatic network reconnection with validation
- **Modern Web Interface**: 
  - Beautiful Tailwind CSS-based dashboard
  - Real-time updates via WebSocket
  - Comprehensive network visualization
  - Threat intelligence dashboard
  - File management and image gallery
  - System monitoring and configuration
  - Hardware profile auto-detection for optimal performance
- **E-Paper Display**: Real-time status display showing targets, vulnerabilities, credentials, and network info including IP address.
- **Comprehensive Logging**: All nmap commands and their results are automatically logged to `/var/log/nmap.log` (or `var/log/nmap.log` in the project directory on Windows) for audit trails and troubleshooting.

<p align="center">
  <img width="150" height="300" alt="image" src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" />
</p>
<img width="1423" height="905" alt="image" src="https://github.com/user-attachments/assets/13d9248a-c3e2-455c-92ed-0b3192b5905a" />


## 🚀 Getting Started

## 📌 Prerequisites

### 📋 Prerequisites for RPI zero W + W2 (64bits)

- Raspberry Pi OS installed. 
    - Stable:
      - System: 64-bit
      - Kernel version: 6.12
      - Debian version: Debian GNU/Linux 13 (trixie)'
- Username and hostname set to `ragnar`.
- 2.13-inch e-Paper HAT connected to GPIO pins.

Ragnar is built for 64 bit trixie and 
Waveshare 2.13inch E-Paper Display HAT V4 for 32 bit system i recommend using Ragnars little brother [Bjorn](https://github.com/infinition/Bjorn) 

### 🔨 Installation

The fastest way to install Ragnar is using the automatic installation script :

```bash
# Download and run the installer
wget https://raw.githubusercontent.com/PierreGode/Ragnar/main/install_ragnar.sh
sudo chmod +x install_Ragnar.sh && sudo ./install_Ragnar.sh
# Choose the choice 1 for automatic installation. It may take a while as a lot of packages and modules will be installed. You must reboot at the end.
```

For **detailed information** about **installation** process go to [Install Guide](INSTALL.md)

## ⚡ Quick Start


**Quick Installation**: you can use the fastest way to install **Ragnar** [Getting Started](#-getting-started)

## 💡 Usage Example

Here's a demonstration of how Ragnar autonomously hunts through your network like a Viking raider (fake demo for illustration):

```bash
# Boot Sequence - WiFi Management
[WiFiManager] Scanning for known networks...
[+] Found: HomeNetwork (Signal: -45dBm)
[WiFiManager] Auto-connecting to HomeNetwork...
[+] Connected! IP: 192.168.1.211
[Display] Showing: WiFi icon + .211

# If no WiFi found:
[WiFiManager] No known networks found after 60s
[WiFiManager] Starting AP mode: Ragnar-Setup
[+] AP Portal available at: http://192.168.4.1/portal
[+] Waiting for user configuration (3 minute timeout)

# Web Interface Starts
[Webapp] Modern dashboard available at http://192.168.1.211:8000
[+] Real-time threat intelligence dashboard active
[+] Hardware profile: Auto-detected Pi Zero 2W (512MB)

# Reconnaissance Phase
[NetworkScanner] Discovering alive hosts...
[+] Host found: 192.168.1.100
    ├── Ports: 22,80,445,3306
    └── MAC: 00:11:22:33:44:55

# Threat Intelligence Enrichment
[ThreatIntelligence] Enriching findings...
[+] Querying: CISA KEV, NVD, AlienVault OTX, MITRE ATT&CK
[+] CVE-2017-0144 found in CISA KEV (EternalBlue)
    ├── Severity: CRITICAL
    ├── EPSS Score: 97.5%
    └── MITRE Techniques: T1210 (Exploitation of Remote Services)

# Attack Sequence 
[NmapVulnScanner] Found vulnerabilities on 192.168.1.100
    ├── MySQL 5.5 < 5.7 - User Enumeration
    └── SMB - EternalBlue Candidate

[SSHBruteforce] Cracking credentials...
[+] Success! user:password123
[StealFilesSSH] Extracting sensitive data...

# Automated Data Exfiltration
[SQLBruteforce] Database accessed!
[StealDataSQL] Dumping tables...
[SMBBruteforce] Share accessible
[+] Found config files, credentials, backups...

# View Results
[+] Dashboard: http://192.168.1.211:8000
    ├── Threat Intel: 3 critical findings
    ├── Credentials: 5 cracked
    └── Files: 127 exfiltrated
```

This is just a demo output - actual results will vary based on your network and target configuration.

**Access Ragnar:**
- **Main Dashboard**: `http://<ragnar-ip>:8000` - Modern web interface with real-time updates
- **WiFi Portal**: `http://192.168.4.1/portal` - Mobile-friendly WiFi configuration (when in AP mode)
- **E-Paper Display**: Shows current status, IP address (.211), targets, vulnerabilities, and credentials

All discovered data is automatically organized in the `data/output/` directory, viewable through both the e-Paper display (as indicators) and web interface. Ragnar works tirelessly, expanding its network knowledge base and growing stronger with each discovery.

No constant monitoring needed - just deploy and let Ragnar do what it does best: hunt for vulnerabilities.

🔧 Expand Ragnar's Arsenal!
Ragnar is designed to be a community-driven weapon forge. Create and share your own attack modules!

⚠️ **For educational and authorized testing purposes only** ⚠️

## 🤝 Contributing

The project welcomes contributions in:

- New attack modules.
- Bug fixes.
- Documentation.
- Feature improvements.

For **detailed information** about **contributing** process go to [Contributing Docs](CONTRIBUTING.md), [Code Of Conduct](CODE_OF_CONDUCT.md) and [Development Guide](DEVELOPMENT.md).

## 📫 Contact

- **Report Issues**: Via GitHub.
- **Guidelines**:
  - Follow ethical guidelines.
  - Document reproduction steps.
  - Provide logs and context.

- **Author**: PierreGode & __infinition__
- **GitHub**: [PierreGode/Ragnar](https://github.com/PierreGode/Ragnar)

---

## 📜 License

2025 - Ragnar is distributed under the MIT License. For more details, please refer to the [LICENSE](LICENSE) file included in this repository.
