# <img src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" alt="thumbnail_IMG_0546" width="33"> Ragnar

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Status](https://img.shields.io/badge/Status-Development-blue.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)



<p align="center">
<img width="300" height="600" alt="image" src="https://github.com/user-attachments/assets/d79940c5-5076-430f-aa75-a4094a4d2910" />

</p>

Ragnar is a « Tamagotchi like » sophisticated, autonomous network scanning, vulnerability assessment, and offensive security tool designed to run on a Raspberry Pi equipped with a 2.13-inch e-Paper HAT. This document provides a detailed explanation of the project.


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
Ragnar is built for 64-bit Rasbian. 
Ragnar has also AP option making it easy to have on the go and easly from a phone just make Ragnar connect to a wifi network.

The e-Paper HAT display and web interface make it easy to monitor and interact with Ragnar, providing real-time updates and status information. With its extensible architecture and customizable actions, Ragnar can be adapted to suit a wide range of security testing and monitoring needs.

## 🌟 Features

- **Network Scanning**: Identifies live hosts and open ports on the network.
- **Vulnerability Assessment**: Performs vulnerability scans using Nmap and other tools.
- **System Attacks**: Conducts brute-force attacks on various services (FTP, SSH, SMB, RDP, Telnet, SQL).
- **File Stealing**: Extracts data from vulnerable services.
- **User Interface**: Real-time display on the e-Paper HAT and web interface for monitoring and interaction.
- **Comprehensive Logging**: All nmap commands and their results are automatically logged to `/var/log/nmap.log` (or `var/log/nmap.log` in the project directory on Windows) for audit trails and troubleshooting.
- complete new web interface
- <p align="center">
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
# Reconnaissance Phase
[NetworkScanner] Discovering alive hosts...
[+] Host found: 192.168.1.100
    ├── Ports: 22,80,445,3306
    └── MAC: 00:11:22:33:44:55

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
```

This is just a demo output - actual results will vary based on your network and target configuration.

All discovered data is automatically organized in the data/output/ directory, viewable through both the e-Paper display (as indicators) and web interface.
Ragnar works tirelessly, expanding its network knowledge base and growing stronger with each discovery.

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
