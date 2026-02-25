# Ragnar Release Notes - Multi-Platform & Advanced Tools Support

## 🎯 Overview

This release brings comprehensive multi-platform support and intelligent automatic installation of advanced security tools based on hardware capabilities.

## 🆕 Major Features

### 1. **Full Debian-Based System Support**
- ✅ **AMD64/x86_64 Architecture**: Native support for standard x86-64 servers and workstations
- ✅ **ARM64/AArch64 Architecture**: Full support for ARM-based servers and high-performance SBCs
- ✅ **ARMv7/ARMv8 Architecture**: Support for 32-bit ARM systems including Pi 4/5
- ✅ **Multi-Distribution**: Debian 11+, Ubuntu 20.04+, Raspbian, and derivatives

### 2. **Automatic Advanced Tools Installation**
Fresh installations on capable hardware (8GB+ RAM, excluding Pi Zero) now automatically install:

#### 🔍 Real-Time Traffic Analysis
- **tcpdump**: Core packet capture
- **tshark**: Wireshark CLI for deep packet inspection
- **ngrep**: Network grep for pattern matching
- **iftop**: Real-time bandwidth monitoring
- **nethogs**: Per-process network usage tracking

#### 🛡️ Advanced Vulnerability Scanning
- **Nuclei**: Template-based vulnerability scanner (5000+ templates)
- **Nikto**: Web server security assessment
- **SQLMap**: Automated SQL injection detection and exploitation
- **WhatWeb**: Web technology fingerprinting
- **Hydra**: Network logon cracker
- **OWASP ZAP**: Web application security testing platform

#### 📦 Enhanced Nmap Capabilities
- **vulners.nse**: CVE vulnerability correlation script
- **vulscan**: Comprehensive vulnerability scanning database

### 3. **Intelligent Hardware Detection**

#### **Automatic Server Mode Detection**
```
Hardware Requirements Check:
├─ RAM ≥ 8GB + NOT Pi Zero → Install Advanced Tools (automatic)
├─ Pi Zero W/W2 → Skip Advanced Tools (resource protection)
└─ RAM < 8GB → Skip Advanced Tools (informational message)
```

#### **Protected Hardware**
- **Pi Zero W/W2**: Automatically excluded from resource-intensive tools
  - Skips OWASP ZAP installation
  - Logs clear reasoning for exclusions
  - Protects against system instability

### 4. **Improved E-Paper Auto-Detection**
- ✅ **GPIO Cleanup**: Proper pin release between detection attempts
- ✅ **Error Handling**: Graceful handling of "GPIO busy" errors
- ✅ **Reset Logic**: Automatic GPIO factory reset between attempts
- ✅ **Better Feedback**: Shows which display version is being tested
- ✅ **Enhanced Troubleshooting**: Improved error messages with specific guidance

## 🔧 Technical Improvements

### Installation Script Enhancements

#### **install_ragnar.sh**
- Added RAM detection with 7.5GB threshold (accounts for system overhead on 8GB systems)
- Integrated automatic advanced tools installation (Step 9 of 10)
- Enhanced logging with hardware qualification details
- Improved error messages and user feedback
- Total installation steps increased from 9 to 10

#### **install_advanced_tools.sh**
- Multi-distro package manager support (apt, dnf, yum, pacman)
- Architecture-aware Nuclei binary installation
- Intelligent Ragnar directory detection
- Pi Zero resource protection
- Comprehensive tool validation and status reporting

### System Compatibility Matrix

| Platform | RAM | Display | Advanced Tools | Auto-Install |
|----------|-----|---------|----------------|--------------|
| Pi Zero W/W2 | 512MB | e-Paper | ❌ Skipped | ❌ No |
| Pi 4/5 (4GB) | 4GB | e-Paper/Headless | ⚠️ Manual Only | ❌ No |
| Pi 4/5 (8GB) | 8GB | e-Paper/Headless | ✅ Full Suite | ✅ Yes |
| AMD64 Server (8GB+) | 8GB+ | Headless | ✅ Full Suite | ✅ Yes |
| ARM64 Server (8GB+) | 8GB+ | Headless | ✅ Full Suite | ✅ Yes |
| Debian Desktop (4GB) | 4GB | Headless | ⚠️ Manual Only | ❌ No |

## 📚 Documentation Updates

### README.md
- ✅ New comprehensive "Server Mode: Advanced Features" section
- ✅ Detailed feature descriptions for traffic analysis and vulnerability scanning
- ✅ Clear installation instructions for fresh vs. existing installations
- ✅ Hardware prerequisites and architecture support matrix
- ✅ Updated installer intelligence section with automatic installation details
- ✅ Enhanced troubleshooting guidance

### Installation Behavior Clarity
- **Fresh Installations**: Fully automatic, no prompts for advanced tools on qualifying hardware
- **Existing Installations**: Manual upgrade via `./install_advanced_tools.sh`
- **Resource-Constrained**: Clear messages explaining why tools are skipped

## 🚀 Usage Examples

### Fresh Installation (8GB+ System)
```bash
wget https://raw.githubusercontent.com/PierreGode/Ragnar/main/install_ragnar.sh
sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh
# Advanced tools automatically installed on capable hardware
# No user interaction required
```

### Existing Installation Upgrade
```bash
cd /home/ragnar/Ragnar
sudo ./install_advanced_tools.sh
sudo systemctl restart ragnar
```

### Manual Verification
```bash
# Check if advanced tools are available
python3 -c "from server_capabilities import get_server_capabilities; caps = get_server_capabilities(); print(f'Traffic Analysis: {caps.capabilities.traffic_analysis_enabled}'); print(f'Advanced Vuln: {caps.capabilities.advanced_vuln_enabled}')"
```

## 🔒 Security & Stability

### Resource Protection
- Pi Zero automatically excluded from memory-intensive operations
- Clear logging of hardware limitations
- Graceful degradation on resource-constrained systems

### GPIO Management
- Proper cleanup between e-Paper detection attempts
- Automatic recovery from "GPIO busy" errors
- Safe concurrent operation with other GPIO services

### Permissions
- Sudoers rules for traffic capture tools (tcpdump, tshark)
- Sudoers rules for vulnerability scanners (nikto, sqlmap, nuclei)
- User-specific permissions for the ragnar service account

## 🐛 Bug Fixes

1. **GPIO Busy Error**: Fixed e-Paper auto-detection failing on subsequent attempts
2. **Missing Module_Exit**: Added proper GPIO cleanup in detection loop
3. **Resource Detection**: Improved RAM calculation accounting for system overhead
4. **Package Fallbacks**: Enhanced multi-distro package name resolution

## ⚠️ Breaking Changes

None. All changes are backward compatible.

## 🔄 Migration Guide

### For Existing Ragnar Installations

**To enable advanced features:**
```bash
cd /home/ragnar/Ragnar
git pull  # Get latest code
sudo ./install_advanced_tools.sh
sudo systemctl restart ragnar
```

**Verify installation:**
```bash
# Check installed tools
which nuclei nikto sqlmap tcpdump tshark

# Check Ragnar capabilities
systemctl status ragnar
journalctl -u ragnar -n 50
```

## 📊 Performance Impact

### With Advanced Tools (8GB+ RAM)
- Initial installation time: +10-15 minutes (Nuclei templates download)
- Additional disk space: ~2GB (OWASP ZAP, Nuclei templates)
- Runtime memory overhead: ~200-500MB (depending on active scans)

### Without Advanced Tools (Pi Zero, <8GB RAM)
- Installation time: Same as before
- Disk space: No change
- Runtime memory: No change

## 🎯 Target Audience

### Ideal For
- **Security Professionals**: Comprehensive vulnerability assessment toolkit
- **Network Administrators**: Real-time traffic analysis and monitoring
- **Penetration Testers**: Full-featured offensive security platform
- **DevSecOps Teams**: Automated security testing in CI/CD pipelines

### Hardware Recommendations
- **Minimum**: Pi Zero W2 (basic scanning, no advanced tools)
- **Recommended**: Pi 4/5 8GB or AMD64/ARM64 server with 8GB+ RAM
- **Optimal**: Dedicated server with 16GB+ RAM for parallel operations

## 🤝 Contributing

We welcome contributions! Areas of interest:
- Additional traffic analysis tools
- New vulnerability scanner integrations
- Performance optimizations
- Multi-language support
- Documentation improvements

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/PierreGode/Ragnar/issues)
- **Discussions**: [GitHub Discussions](https://github.com/PierreGode/Ragnar/discussions)
- **Documentation**: [README.md](README.md) | [INSTALL.md](INSTALL.md)

## 🙏 Acknowledgments

- Inspired by [Bjorn](https://github.com/infinition/Bjorn)
- Built on tools from ProjectDiscovery, OWASP, Nmap Project, and many others
- Community feedback and contributions

---

**Version**: 2.0.0  
**Release Date**: February 1, 2026  
**License**: MIT  
**Author**: PierreGode
