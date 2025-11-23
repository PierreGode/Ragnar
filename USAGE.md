# ⚡ Usage Guide

## Quick Start

### First Time Setup

After installation (see [Installation Guide](INSTALL.md)), Ragnar will start automatically on boot.

### Accessing Ragnar

Ragnar provides multiple interfaces for interaction:

#### 1. Main Web Dashboard
**URL:** `http://<ragnar-ip>:8000`

The modern web interface provides:
- Real-time network discovery and vulnerability scanning
- Multi-source threat intelligence dashboard
- AI-powered insights and analysis
- File management with image gallery
- System monitoring and configuration
- Hardware profile auto-detection

<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/3bed08a1-b6cf-4014-9661-85350dc5becc" width="200"/></td>
    <td><img src="https://github.com/user-attachments/assets/88345794-edfc-49e8-90ab-48d72b909e86" width="800"/></td>
  </tr>
</table>

<img width="1092" height="902" alt="Web Interface" src="https://github.com/user-attachments/assets/cafed68d-de62-4041-aa36-c1fcccacc9ea" />

For more details, see [Web Interface Guide](WEB_INTERFACE.md).

#### 2. E-Paper Display
The E-Paper HAT shows real-time status:
- Current IP address
- Active targets
- Discovered vulnerabilities
- Captured credentials
- Scanning status

<p align="center">
  <img width="150" height="300" alt="E-Paper Display" src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" />
</p>

#### 3. WiFi Configuration Portal
**URL:** `http://192.168.4.1/portal` (when in AP mode)

When Ragnar can't connect to a known network, it automatically creates a WiFi hotspot:

**Network Details:**
- **SSID:** `Ragnar`
- **Password:** `ragnarconnect`

**Configuration Steps:**
1. **Connect** to WiFi network: `Ragnar` (password: ragnarconnect)
2. **Navigate** to: `http://192.168.4.1/portal`
3. **Configure** your home WiFi credentials via the mobile-friendly interface
4. **Monitor** the countdown timer - Ragnar will automatically retry WiFi after some time if AP is unused
5. **Done** - Ragnar exits AP mode and connects to your network

**Portal Features:**
- Network scanning with signal strength indicators
- Manual network entry for hidden SSIDs
- Countdown timer showing when Ragnar will retry WiFi
- Known networks management
- One-tap connection to saved networks

## Operating Modes

### Autonomous Mode (Default)
Ragnar works autonomously:
- Continuously scans the network
- Discovers new targets
- Performs vulnerability assessments
- Logs all findings
- Updates displays in real-time

**No constant monitoring needed** - just deploy and let Ragnar do what it does best: hunt for vulnerabilities.

### Manual Mode
Use the web interface to:
- Manually trigger scans
- Configure specific targets
- Adjust scan parameters
- Review historical data

## Data Access

All discovered data is automatically organized in the `data/output/` directory:

### Directory Structure
```
data/
├── output/          # Scan results and discoveries
├── logs/           
│   └── nmap.log    # Detailed Nmap command logs
└── ragnar.db       # SQLite database with all findings
```

### Viewing Data

**Via Web Interface:**
- Navigate to `http://<ragnar-ip>:8000`
- Browse the dashboard for visual summaries
- Check the file management section for detailed logs

**Via E-Paper Display:**
- Real-time indicators of discoveries
- Summary statistics

**Via File System:**
- SSH into Ragnar
- Navigate to `/home/ragnar/Ragnar/data/`
- View logs and database directly

## AI Features (Optional)

If you've configured AI integration (see [AI Integration Guide](AI_INTEGRATION.md)):

### Accessing AI Insights
1. Navigate to the Dashboard tab
2. Scroll to the "AI Insights" section
3. View:
   - Network Security Summary
   - Vulnerability Assessment
   - Network Weaknesses

### Refreshing AI Analysis
Click the "Refresh" button to:
- Clear the cache
- Generate new analysis with latest data
- Get updated recommendations

## Common Operations

### Finding Ragnar's IP Address

**Method 1: E-Paper Display**
- The IP address is shown on the display (e.g., .211 for 192.168.1.211)

**Method 2: Router**
- Check your router's DHCP client list
- Look for hostname "ragnar"

**Method 3: Network Scanner**
```bash
# From another computer on the network
nmap -sn 192.168.1.0/24 | grep -i ragnar
```

**Method 4: Direct Connection (USB Gadget)**
- Connect via USB
- Access at `http://172.20.2.1:8000`

### Stopping Ragnar
```bash
sudo systemctl stop ragnar
```

### Starting Ragnar
```bash
sudo systemctl start ragnar
```

### Viewing Logs
```bash
# Service logs
sudo journalctl -u ragnar -f

# Application logs
tail -f /var/log/ragnar.log

# Nmap logs
tail -f /home/ragnar/Ragnar/data/logs/nmap.log
```

### Updating Ragnar
```bash
cd /home/ragnar/Ragnar
./update_ragnar.sh
```

## Educational Use Workflow

### 1. Demonstration Setup
- Power on Ragnar
- Wait for boot and network connection
- Access web interface
- Show real-time scanning

### 2. Training Session
- Demonstrate vulnerability discovery
- Explain AI insights
- Review threat intelligence
- Discuss remediation strategies

### 3. Post-Session Cleanup
Use the kill switch to wipe all data:

```bash
curl -X POST http://localhost:8000/api/kill \
  -H "Content-Type: application/json" \
  -d '{"confirmation": "ERASE_ALL_DATA"}'
```

See [Kill Switch Documentation](KILL_SWITCH.md) for complete details.

## Troubleshooting

### Ragnar Not Accessible
1. Check E-Paper display for IP address
2. Verify Ragnar is on the same network
3. Try AP mode (look for "Ragnar" WiFi network)

### No Network Scans
1. Verify network connectivity
2. Check that you're on the target network
3. Review logs for errors

### WiFi Issues
1. Connect to AP mode portal
2. Reconfigure WiFi credentials
3. Check signal strength
4. Review `/var/log/ragnar_wifi.log`

### Service Not Running
```bash
# Check service status
sudo systemctl status ragnar

# Restart service
sudo systemctl restart ragnar

# Check logs
sudo journalctl -u ragnar -n 50
```

## Best Practices

### Security
- Only use on authorized networks
- Regularly update Ragnar
- Use kill switch after demonstrations
- Secure web interface access

### Performance
- Limit scan scope for faster results
- Disable desktop panel on Pi Zero 2W
- Monitor resource usage via web interface

### Data Management
- Regular backups of important findings
- Periodic cleanup of old logs
- Use kill switch for complete wipe when needed

---

## Next Steps

- Explore [Features](FEATURES.md) for detailed capabilities
- Configure [AI Integration](AI_INTEGRATION.md) for intelligent analysis
- Review [Kill Switch](KILL_SWITCH.md) for data erasure
- Check [Web Interface](WEB_INTERFACE.md) for dashboard details

## Support

For issues or questions:
- Check [GitHub Issues](https://github.com/PierreGode/Ragnar/issues)
- Review [Contributing Guide](CONTRIBUTING.md)
- Read [Code of Conduct](CODE_OF_CONDUCT.md)

⚠️ **Remember: For educational and authorized testing purposes only** ⚠️
