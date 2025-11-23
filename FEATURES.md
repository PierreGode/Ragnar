# 🌟 Ragnar Features

Ragnar is a sophisticated, autonomous network scanning, vulnerability assessment, and offensive security tool with extensive capabilities.

## Core Features

### 🔍 Network Scanning
- Identifies live hosts and open ports on the network
- Comprehensive network discovery and mapping
- Real-time network visualization

### 🛡️ Vulnerability Assessment
- Performs vulnerability scans using Nmap and other tools
- Comprehensive security analysis of discovered hosts
- Automated vulnerability detection

### 📊 Multi-Source Threat Intelligence
Real-time threat intelligence fusion from multiple sources:
- CISA KEV (Known Exploited Vulnerabilities)
- NVD CVE (National Vulnerability Database)
- AlienVault OTX (Open Threat Exchange)
- MITRE ATT&CK framework

### 🤖 AI-Powered Analysis
GPT-5 Nano integration provides PWNAGOTCHI-style intelligent analysis:
- Network security summaries
- Vulnerability prioritization and remediation advice
- Network weakness identification and attack vector analysis
- See [AI Integration Guide](AI_INTEGRATION.md) for setup

### ⚔️ System Attacks
Conducts brute-force attacks on various services:
- FTP
- SSH
- SMB
- RDP
- Telnet
- SQL databases

### 📁 File Stealing
Extracts data from vulnerable services for security assessment purposes.

### 📡 Smart WiFi Management
- Auto-connects to known networks on boot
- Falls back to AP mode when no WiFi available
- Captive portal at `http://192.168.4.1/portal` for easy mobile configuration
- Automatic network reconnection with validation

### 🌐 Modern Web Interface
Beautiful Tailwind CSS-based dashboard featuring:
- Real-time updates via WebSocket
- Comprehensive network visualization
- AI-powered insights on dashboard
- Threat intelligence dashboard
- File management and image gallery
- System monitoring and configuration
- Hardware profile auto-detection for optimal performance (Pi Zero 2W, Pi 4, Pi 5)

Access at: `http://<ragnar-ip>:8000`

### 📺 E-Paper Display
Real-time status display showing:
- Current targets
- Discovered vulnerabilities
- Captured credentials
- Network information including IP address
- Live scanning status

Compatible with Waveshare 2.13-inch E-Paper HAT V4.

### 📝 Comprehensive Logging
All nmap commands and their results are automatically logged to `data/logs/nmap.log` for:
- Audit trails
- Troubleshooting
- Compliance reporting

### 🔒 Kill Switch
Built-in kill switch endpoint (`/api/kill`) that completely wipes:
- All databases
- Logs
- Sensitive data

This ensures no sensitive data remains after demonstrations or training sessions.

**📖 Full Documentation:** See [Kill Switch Documentation](KILL_SWITCH.md)

## Technical Capabilities

### Modular Architecture
- Extensible action system
- Customizable orchestration
- Plugin-friendly design

### Data Organization
All discovered data is automatically organized in the `data/output/` directory, viewable through:
- E-Paper display (as indicators)
- Web interface
- Log files

### Autonomous Operation
No constant monitoring needed - just deploy and let Ragnar work:
- Continuous network scanning
- Automatic vulnerability detection
- Self-sustaining operation

## Educational Use

> [!IMPORTANT]  
> **For educational use only!**

Ragnar is designed for:
- ✅ Cybersecurity training environments
- ✅ Penetration testing demonstrations
- ✅ CTF (Capture The Flag) competitions
- ✅ Research lab usage
- ✅ Authorized security testing

**NOT for:**
- ❌ Unauthorized network access
- ❌ Malicious activities
- ❌ Production environments without permission

⚠️ **For educational and authorized testing purposes only** ⚠️

## Extensibility

🔧 **Expand Ragnar's Arsenal!**

Ragnar is designed to be a community-driven weapon forge. Create and share your own attack modules!

See [Contributing Guide](CONTRIBUTING.md) for how to add new features.

---

For setup instructions, see [Installation Guide](INSTALL.md).

For usage information, see [Usage Guide](USAGE.md).
