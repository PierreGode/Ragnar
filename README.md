## <img width="70" height="150" alt="image" src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" /> Ragnar

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/J3J2EARPK)
![GitHub stars](https://img.shields.io/github/stars/PierreGode/Ragnar)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/3bed08a1-b6cf-4014-9661-85350dc5becc" width="200"/></td>
    <td><img src="https://github.com/user-attachments/assets/88345794-edfc-49e8-90ab-48d72b909e86" width="800"/></td>
  </tr>
</table>
</p>

Ragnar is a « Tamagotchi like » sophisticated, autonomous network scanning, vulnerability assessment, and offensive security tool designed to run on a Raspberry Pi equipped with a 2.13-inch e-Paper HAT. This document provides a detailed explanation of the project.

The fastest way to install Ragnar is using the automatic installation script :

```bash
# Download and run the installer
wget https://raw.githubusercontent.com/PierreGode/Ragnar/main/install_ragnar.sh
sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh
# Choose the choice 1 for automatic installation. It may take a while as a lot of packages and modules will be installed. You must reboot at the end.
```


### 🔨 Installation



### 🌐 Web Interface & WiFi Management

**Modern Dashboard** - Access Ragnar's sleek web interface at `http://<ragnar-ip>:8000`:
[Images](WEB.md)
- Real-time network discovery and vulnerability scanning
- Multi-source threat intelligence dashboard
- File management with image gallery
- System monitoring and configuration
- Hardware profile auto-detection (Pi Zero 2W, Pi 4, Pi 5)

**WiFi Configuration Portal** - When Ragnar can't connect to a known network, it automatically creates a WiFi hotspot:
1. **Connect** to WiFi network: `Ragnar` (password ragnarconnect)
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

## 📄 Introduction

Ragnar is a fork from the awesome project [Bjorn](https://github.com/infinition/Bjorn)  and is rebuilt powerful tool designed to perform comprehensive network scanning, vulnerability assessment, and data ex-filtration. Its modular design and extensive configuration options allow for flexible and targeted operations. By combining different actions and orchestrating them intelligently, Ragnar can provide valuable insights into network security and help identify and mitigate potential risks.

Ragnar is built for 64-bit Raspberry Pi OS (Debian Trixie). 

The e-Paper HAT display and web interface make it easy to monitor and interact with Ragnar, providing real-time updates and status information. With its extensible architecture and customizable actions, Ragnar can be adapted to suit a wide range of security testing and monitoring needs.

## 🌟 Features

- **Network Scanning**: Identifies live hosts and open ports on the network.
- **Vulnerability Assessment**: Performs vulnerability scans using Nmap and other tools.
- **Multi-Source Threat Intelligence**: Real-time threat intelligence fusion from CISA KEV, NVD CVE, AlienVault OTX, and MITRE ATT&CK.
- **AI-Powered Analysis**: 🆕 GPT-5 Nano integration provides PWNAGOTCHI-style intelligent analysis:
  - Network security summaries
  - Vulnerability prioritization and remediation advice
  - Network weakness identification and attack vector analysis
  - See [AI Integration Guide](AI_INTEGRATION.md) for setup
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
  - AI-powered insights on dashboard
  - Threat intelligence dashboard
  - File management and image gallery
  - System monitoring and configuration
  - Hardware profile auto-detection for optimal performance
- **E-Paper Display**: Real-time status display showing targets, vulnerabilities, credentials, and network info including IP address.
- **Comprehensive Logging**: All nmap commands and their results are automatically logged to `data/logs/nmap.log` for audit trails and troubleshooting.

<p align="center">
  <img width="150" height="300" alt="image" src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" />
</p>

<img width="1092" height="902" alt="image" src="https://github.com/user-attachments/assets/cafed68d-de62-4041-aa36-c1fcccacc9ea" />



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

#### Reccomendation
- In nano, edit ~/.config/labwc/autostart and comment out the line
#/usr/bin/lwrespawn /usr/bin/wf-panel-pi &
(This disables the unneeded desktop panel that consumes resources.)
- Ot sudo pkill wf-panel-pi to kill itt temporary 

### 🔨 Installation

The fastest way to install Ragnar is using the automatic installation script :

```bash
# Download and run the installer
wget https://raw.githubusercontent.com/PierreGode/Ragnar/main/install_ragnar.sh
sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh
# Choose the choice 1 for automatic installation. It may take a while as a lot of packages and modules will be installed. You must reboot at the end.
```

For **detailed information** about **installation** process go to [Install Guide](INSTALL.md)

## ⚡ Quick Start


**Quick Installation**: you can use the fastest way to install **Ragnar** [Getting Started](#-getting-started)


**Access Ragnar:**
- **Main Dashboard**: `http://<ragnar-ip>:8000` - Modern web interface with real-time updates
- **WiFi Portal**: `http://192.168.4.1/portal` - Mobile-friendly WiFi configuration (when in AP mode)
- **E-Paper Display**: Shows current status, IP address (.211), targets, vulnerabilities, and credentials

All discovered data is automatically organized in the `data/output/` directory, viewable through both the e-Paper display (as indicators) and web interface. Ragnar works tirelessly, expanding its network knowledge base and growing stronger with each discovery.

No constant monitoring needed - just deploy and let Ragnar do what it does best: hunt for vulnerabilities.

🔧 Expand Ragnar's Arsenal!
Ragnar is designed to be a community-driven weapon forge. Create and share your own attack modules!

> [!IMPORTANT]  
> **For educational use only!**

> Ragnar includes a built-in kill switch endpoint (`/api/kill`) that completely wipes all databases, logs, This ensures no sensitive data remains after demonstrations or training sessions.
> If Ragnar is to be found without permission in a network anyone kan completely wipe all databases + delete the entire repository rendering Ragnar dead.
> **📖 Full Documentation:** See [kill switch doc](KILL_SWITCH.md) for complete usage instructions and safety guidelines.


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
