# ragnar Wi-Fi Management System

This document describes the autonomous Wi-Fi management system for ragnar IoT device, which provides robust connectivity with automatic fallback to Access Point mode.

## Features

### 🔄 Autonomous Operation
- **Auto-connect** to known Wi-Fi networks on boot
- **Intelligent fallback** to AP mode if connection fails
- **Robust timing** - waits appropriate time before giving up
- **Connection monitoring** with automatic recovery
- **Graceful handling** of network changes and failures

### 📡 Access Point Mode
- **Automatic AP setup** when no connection available
- **Configurable SSID and password** via web interface
- **DHCP server** for client devices (192.168.4.2-192.168.4.20)
- **Web portal** accessible at 192.168.4.1:5000
- **Clean teardown** when connection restored

### 🌐 Web Management Interface
- **Network scanning** - discover available Wi-Fi networks
- **Connection management** - connect, disconnect, forget networks
- **Known networks** - manage saved network credentials
- **Real-time status** - monitor connection state via WebSocket
- **Manual controls** - force reconnection, toggle AP mode

### 🛠️ System Integration
- **NetworkManager integration** for reliable connections
- **Systemd service** for background operation
- **Shell utilities** for command-line management
- **Proper cleanup** on shutdown and errors

## Architecture

### Core Components

#### 1. WiFiManager Class (`wifi_manager.py`)
- **Connection Management**: Handles Wi-Fi scanning, connection, and monitoring
- **AP Mode Control**: Manages hostapd and dnsmasq for Access Point functionality
- **Configuration**: Loads/saves Wi-Fi settings from shared configuration
- **State Machine**: Tracks connection state and handles transitions

#### 2. ragnar Integration (`ragnar.py`)
- **Startup Sequence**: Initializes Wi-Fi manager during boot
- **Orchestrator Control**: Only starts when Wi-Fi connected
- **Clean Shutdown**: Properly stops Wi-Fi manager on exit

#### 3. Web Interface (`webapp_modern.py`)
- **REST API**: Endpoints for Wi-Fi management operations
- **Real-time Updates**: WebSocket notifications for status changes
- **User Interface**: Web pages for network configuration

#### 4. System Scripts
- **Setup Script** (`ragnar_wifi_setup.sh`): System installation and configuration
- **Service Script** (`wifi_manager_service.sh`): Manual Wi-Fi management utilities

## Installation

### Prerequisites
- Raspberry Pi Zero 2 W or similar with Wi-Fi capability
- Debian/Ubuntu based system
- Root access for system configuration

### Automatic Setup
```bash
# Run the setup script (as root)
sudo bash ragnar_wifi_setup.sh
```

This will:
- Install required packages (hostapd, dnsmasq, NetworkManager)
- Configure network services
- Set up systemd service
- Create utility scripts
- Configure permissions

### Manual Setup
If you prefer manual installation:

1. **Install packages**:
   ```bash
   sudo apt-get update
   sudo apt-get install hostapd dnsmasq network-manager wireless-tools wpasupplicant
   ```

2. **Configure NetworkManager**:
   ```bash
   sudo systemctl enable NetworkManager
   sudo systemctl start NetworkManager
   ```

3. **Disable conflicting services**:
   ```bash
   sudo systemctl disable hostapd
   sudo systemctl disable dnsmasq
   ```

## Configuration

### Wi-Fi Settings
Wi-Fi configuration is stored in the shared configuration file (`config/shared_config.json`):

```json
{
  "wifi_known_networks": [
    {
      "ssid": "MyNetwork",
      "password": "mypassword",
      "priority": 10,
      "added_date": "2024-01-01T12:00:00"
    }
  ],
  "wifi_ap_ssid": "ragnar-Setup",
  "wifi_ap_password": "ragnarpassword",
  "wifi_connection_timeout": 60,
  "wifi_max_attempts": 3,
  "wifi_scan_interval": 300,
  "wifi_monitor_enabled": true,
  "wifi_auto_ap_fallback": true
}
```

### Network Priority
Networks are prioritized by the `priority` field (higher = more preferred). The system will attempt to connect to networks in priority order.

## Operation

### Boot Sequence
1. **System startup** - ragnar starts and initializes Wi-Fi manager
2. **Startup delay** - Waits for system to stabilize (configurable)
3. **Connection attempts** - Tries to connect to known networks
4. **Fallback decision** - After timeout, starts AP mode if no connection
5. **Monitoring** - Continuously monitors connection status

### AP Mode
When no Wi-Fi connection is available:
- **SSID**: `ragnar-Setup` (configurable)
- **Password**: `ragnarpassword` (configurable)
- **IP Range**: 192.168.4.1/24
- **DHCP**: 192.168.4.2 - 192.168.4.20
- **Web Interface**: http://192.168.4.1:5000

### Connection Recovery
- **Monitoring**: Checks connection every 30 seconds
- **Recovery**: Attempts reconnection on failure
- **AP Shutdown**: Stops AP mode when connection restored
- **Persistence**: Maintains known network database

## Web Interface

### Dashboard
The main dashboard shows:
- Current Wi-Fi status
- Connected SSID (if any)
- AP mode status
- Connection statistics

### Wi-Fi Configuration Page
Access via `/wifi` or the navigation menu:
- **Available Networks**: Scan and view nearby networks
- **Known Networks**: Manage saved network credentials
- **Connection Status**: Real-time connection information
- **Manual Controls**: Connect, disconnect, start/stop AP

### API Endpoints

#### Status and Information
- `GET /api/wifi/status` - Get Wi-Fi manager status
- `GET /api/wifi/networks` - Get available and known networks

#### Network Management
- `POST /api/wifi/scan` - Trigger network scan
- `POST /api/wifi/connect` - Connect to network
- `POST /api/wifi/disconnect` - Disconnect from current network
- `POST /api/wifi/forget` - Remove known network

#### AP Mode Control
- `POST /api/wifi/ap/start` - Start Access Point mode
- `POST /api/wifi/ap/stop` - Stop Access Point mode

#### Utilities
- `POST /api/wifi/reconnect` - Force reconnection attempt

## Command Line Tools

After installation, several utility commands are available:

### ragnar-wifi-status
Shows comprehensive Wi-Fi status:
```bash
ragnar-wifi-status
```

### ragnar-wifi-connect
Connect to a Wi-Fi network:
```bash
# With password
ragnar-wifi-connect "MyNetwork" "mypassword"

# Open network
ragnar-wifi-connect "OpenNetwork"
```

### ragnar-wifi-ap
Control AP mode:
```bash
# Start AP mode
ragnar-wifi-ap start

# Stop AP mode
ragnar-wifi-ap stop
```

### wifi_manager_service.sh
Direct service control script:
```bash
# Start AP mode
sudo ./wifi_manager_service.sh start-ap

# Scan for networks
./wifi_manager_service.sh scan

# Check connection
./wifi_manager_service.sh check

# Show detailed status
./wifi_manager_service.sh status
```

## Troubleshooting

### Common Issues

#### Wi-Fi not connecting
1. **Check known networks**: Ensure SSID and password are correct
2. **Signal strength**: Verify network is in range
3. **Network compatibility**: Some enterprise networks may not work
4. **Interface status**: Check if wlan0 is up and managed

```bash
# Check interface
ip addr show wlan0

# Check NetworkManager
sudo systemctl status NetworkManager

# Check saved connections
nmcli con show
```

#### AP mode not starting
1. **Check hostapd**: Ensure hostapd is installed and configured
2. **Interface conflicts**: Make sure interface isn't managed by other services
3. **Permission issues**: Verify script runs with proper privileges

```bash
# Test hostapd manually
sudo hostapd /tmp/ragnar/hostapd.conf

# Check dnsmasq
sudo dnsmasq -C /tmp/ragnar/dnsmasq.conf --no-daemon
```

#### Web interface not accessible
1. **Service status**: Check if ragnar web server is running
2. **Firewall**: Ensure port 5000 is not blocked
3. **IP address**: Verify correct IP for AP mode (192.168.4.1)

```bash
# Check ragnar service
sudo systemctl status ragnar

# Check port binding
sudo netstat -tlnp | grep :5000
```

### Logs and Debugging

#### Application Logs
```bash
# ragnar main log
tail -f data/logs/temp_log.txt

# System Wi-Fi manager log
sudo journalctl -u ragnar-wifi -f
```

#### System Logs
```bash
# NetworkManager logs
sudo journalctl -u NetworkManager -f

# Kernel Wi-Fi messages
sudo dmesg | grep -i wifi
```

#### Debug Mode
Enable debug logging in configuration:
```json
{
  "debug_mode": true,
  "log_debug": true
}
```

### Reset and Recovery

#### Reset Wi-Fi configuration
```bash
# Remove all known networks
rm -f config/shared_config.json

# Restart ragnar to regenerate config
sudo systemctl restart ragnar
```

#### Reset NetworkManager
```bash
# Reset all connections
sudo rm -f /etc/NetworkManager/system-connections/*

# Restart NetworkManager
sudo systemctl restart NetworkManager
```

#### Factory reset Wi-Fi
```bash
# Uninstall Wi-Fi management
sudo ragnar-wifi-uninstall

# Reinstall fresh
sudo bash ragnar_wifi_setup.sh
```

## Advanced Configuration

### Custom AP Settings
Modify in `config/shared_config.json`:
```json
{
  "wifi_ap_ssid": "MyCustomAP",
  "wifi_ap_password": "mysecurepassword",
  "wifi_connection_timeout": 120,
  "wifi_max_attempts": 5
}
```

### Network Priorities
Higher priority networks are tried first:
```json
{
  "wifi_known_networks": [
    {
      "ssid": "HomeWiFi",
      "password": "password123",
      "priority": 10
    },
    {
      "ssid": "GuestWiFi", 
      "password": "guest123",
      "priority": 5
    }
  ]
}
```

### Monitoring Intervals
Adjust monitoring behavior:
```json
{
  "wifi_scan_interval": 300,      // Scan every 5 minutes
  "wifi_connection_timeout": 60,  // Wait 1 minute before AP
  "wifi_monitor_enabled": true    // Enable monitoring
}
```

## Security Considerations

### AP Mode Security
- **Strong password**: Use complex password for AP mode
- **Limited time**: AP mode only when necessary
- **Network isolation**: AP clients isolated from main network

### Credential Storage
- **File permissions**: Config files protected by filesystem permissions
- **No plaintext logs**: Passwords not logged in plaintext
- **Secure transmission**: Use HTTPS for web interface in production

### Network Security
- **WPA2/WPA3**: Only connect to secure networks when possible
- **Certificate validation**: Future enhancement for enterprise networks
- **MAC randomization**: Disable for stable connections

## Performance Notes

### Resource Usage
- **Memory**: Wi-Fi manager uses minimal memory (~10MB)
- **CPU**: Low CPU usage except during scans
- **Network**: Monitoring traffic is minimal

### Timing Considerations
- **Boot delay**: 60 second default timeout prevents premature AP mode
- **Scan intervals**: 5 minute default balances responsiveness and power
- **Connection timeout**: 30 second timeouts prevent hanging

### Power Management
- **Wi-Fi power save**: Disabled during monitoring for reliability
- **Scan frequency**: Reduced when stable connection established
- **AP shutdown**: Immediate when connection restored

## Future Enhancements

### Planned Features
- **Enterprise Wi-Fi**: Support for WPA-Enterprise networks
- **Captive portal**: Automated captive portal handling
- **Mesh networking**: Support for mesh network protocols
- **5GHz support**: Dual-band operation when hardware available

### Configuration Improvements
- **Web-based setup**: Complete setup via web interface
- **QR code setup**: Generate QR codes for easy mobile setup
- **Backup/restore**: Configuration backup and restore functionality

### Monitoring Enhancements
- **Signal quality**: Display signal strength and quality metrics
- **Connection history**: Track connection success/failure history
- **Network analytics**: Analyze network performance over time

## Support

For issues or questions:
1. Check this documentation
2. Review logs for error messages
3. Try troubleshooting steps
4. Reset configuration if needed
5. Create GitHub issue with logs and configuration details

The Wi-Fi management system is designed to be robust and self-healing, but complex network environments may require manual intervention or configuration adjustments.
