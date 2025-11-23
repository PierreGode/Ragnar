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

Ragnar is a « Tamagotchi like » sophisticated, autonomous network scanning, vulnerability assessment, and offensive security tool designed to run on a Raspberry Pi equipped with a 2.13-inch e-Paper HAT.

> [!IMPORTANT]  
> **For educational use only!**

> Ragnar includes a built-in kill switch endpoint (`/api/kill`) that completely wipes all databases, logs, This ensures no sensitive data remains after demonstrations or training sessions.
> If Ragnar is to be found without permission in a network anyone kan completely wipe all databases + delete the entire repository rendering Ragnar dead.
> **📖 Full Documentation:** See [Kill Switch Documentation](KILL_SWITCH.md) for complete usage instructions and safety guidelines.

## 📚 Documentation

- **[Features](FEATURES.md)** - Complete list of capabilities and features
- **[Prerequisites](PREREQUISITES.md)** - Hardware and software requirements
- **[Installation](INSTALL.md)** - Detailed installation instructions
- **[Usage](USAGE.md)** - Quick start and usage guide
- **[Web Interface](WEB_INTERFACE.md)** - Dashboard and WiFi portal guide
- **[AI Integration](AI_INTEGRATION.md)** - GPT-5 Nano setup and usage
- **[Kill Switch](KILL_SWITCH.md)** - Emergency data erasure
- **[Contributing](CONTRIBUTING.md)** - How to contribute
- **[Code of Conduct](CODE_OF_CONDUCT.md)** - Community guidelines

## 🔨 Installation

The fastest way to install Ragnar is using the automatic installation script:

```bash
# Download and run the installer
wget https://raw.githubusercontent.com/PierreGode/Ragnar/main/install_ragnar.sh
sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh
# Choose option 1 for automatic installation. It may take a while as many packages will be installed. Reboot required.
```

For detailed installation instructions, manual installation, and prerequisites, see the **[Installation Guide](INSTALL.md)**.

## ⚡ Quick Start

After installation, access Ragnar through:
- **Main Dashboard**: `http://<ragnar-ip>:8000` - Modern web interface
- **WiFi Portal**: `http://192.168.4.1/portal` - WiFi configuration (AP mode)
- **E-Paper Display**: Shows current status and IP address

For complete usage instructions, see the **[Usage Guide](USAGE.md)**.

For web interface details, see the **[Web Interface Guide](WEB_INTERFACE.md)**.

## 📄 About Ragnar

Ragnar is a fork from the awesome project [Bjorn](https://github.com/infinition/Bjorn) and is rebuilt as a powerful tool designed to perform comprehensive network scanning, vulnerability assessment, and data ex-filtration. Its modular design and extensive configuration options allow for flexible and targeted operations.

Built for 64-bit Raspberry Pi OS (Debian Trixie), Ragnar combines an e-Paper HAT display and modern web interface to provide real-time updates and status information. With its extensible architecture and customizable actions, Ragnar can be adapted to suit a wide range of security testing and monitoring needs.

For a complete list of features, see **[Features](FEATURES.md)**.

## 🤝 Contributing

Contributions are welcome! Whether you're adding new attack modules, fixing bugs, improving documentation, or enhancing features, your help makes Ragnar better.

See the **[Contributing Guide](CONTRIBUTING.md)** and **[Code of Conduct](CODE_OF_CONDUCT.md)** for details.

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
