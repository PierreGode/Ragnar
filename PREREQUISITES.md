# 📌 Prerequisites

## Hardware Requirements

### Raspberry Pi Models

Ragnar is optimized for:
- **Raspberry Pi Zero 2W** (64-bit) - Recommended for portable deployments
- **Raspberry Pi 4** - Better performance for larger networks
- **Raspberry Pi 5** - Best performance

### E-Paper Display

**Required:** Waveshare 2.13-inch E-Paper HAT

**Tested versions:**
- V2 ✅
- V4 ✅

**Expected to work:**
- V1 (not extensively tested)
- V3 (not extensively tested)

The E-Paper HAT must be connected to the GPIO pins.

## Software Requirements

### Operating System

**Required:** Raspberry Pi OS (64-bit)

**Recommended stable configuration:**
- **System:** 64-bit
- **Kernel version:** 6.12 (6.6 also works)
- **Debian version:** Debian GNU/Linux 13 (trixie)

### System Configuration

**Username and hostname:** Must be set to `ragnar`

This is important for the automatic installation scripts and service configurations.

### Installation Tool

Use Raspberry Pi Imager to install your OS: https://www.raspberrypi.com/software/

<p align="center">
   <img src="https://github.com/user-attachments/assets/e8d276be-4cb2-474d-a74d-b5b6704d22f5" alt="Raspberry Pi Imager" width="400"> 
</p>

## Performance Optimization (Optional)

### Desktop Panel Disable

To save resources on Raspberry Pi Zero 2W:

#### Permanent Solution
Edit `~/.config/labwc/autostart` and comment out:
```bash
#/usr/bin/lwrespawn /usr/bin/wf-panel-pi &
```

This disables the unneeded desktop panel that consumes resources.

#### Temporary Solution
Kill the panel temporarily:
```bash
sudo pkill wf-panel-pi
```

## Network Requirements

### WiFi Configuration
- Access to WiFi network for internet connectivity
- Ability to configure WiFi settings (Ragnar provides AP mode for easy setup)

### Network Access
- Target network for scanning (authorized access required)
- Internet access for threat intelligence updates and AI features

## Optional Requirements

### For AI Features
- OpenAI API token (for GPT-5 Nano integration)
- Internet connectivity for API access
- See [AI Integration Guide](AI_INTEGRATION.md)

### For USB Gadget Mode
- USB data cable (not just power cable)
- Host computer with USB network adapter support

## Compatibility Notes

### Architecture
Ragnar is built for **64-bit** systems only. For 32-bit Raspberry Pi systems, we recommend using Ragnar's predecessor [Bjorn](https://github.com/infinition/Bjorn).

### Hardware Interfaces
The installation process will enable:
- **SPI** (Serial Peripheral Interface) - for E-Paper display
- **I2C** (Inter-Integrated Circuit) - for additional sensors/displays

These will be configured automatically during installation.

## Legal Requirements

> [!IMPORTANT]  
> **Authorization Required**

Before using Ragnar, ensure you have:
- ✅ Written authorization to test the target network
- ✅ Understanding of local cybersecurity laws
- ✅ Compliance with organizational security policies
- ✅ Educational or research purposes only

**Never use Ragnar on networks you don't own or don't have explicit permission to test.**

---

Ready to install? See the [Installation Guide](INSTALL.md).

Once installed, see the [Usage Guide](USAGE.md) to get started.
