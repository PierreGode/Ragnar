# 🌐 Web Interface Guide

## Overview

Ragnar features a modern, responsive web interface built with Tailwind CSS, providing real-time network intelligence and system management capabilities.

**Access:** `http://<ragnar-ip>:8000`

## Main Features

### Real-Time Updates
- WebSocket-based live data streaming
- Automatic refresh of network status
- Live vulnerability feed
- Real-time system metrics

### Responsive Design
- Mobile-friendly interface
- Tablet-optimized layouts
- Desktop full-feature experience
- Cross-browser compatibility

### Hardware Detection
Automatic profile detection for optimal performance:
- Raspberry Pi Zero 2W
- Raspberry Pi 4
- Raspberry Pi 5

## Dashboard Sections

### Network Discovery
**Real-time network visualization showing:**
- Active hosts on the network
- Open ports and services
- Operating system detection
- Service version information
- Network topology

### Vulnerability Scanner
**Comprehensive security assessment:**
- Automated vulnerability detection
- CVE identification
- Severity ratings
- Exploit availability
- Remediation recommendations

### Threat Intelligence Dashboard
**Multi-source intelligence fusion from:**
- **CISA KEV** - Known Exploited Vulnerabilities
- **NVD CVE** - National Vulnerability Database  
- **AlienVault OTX** - Open Threat Exchange
- **MITRE ATT&CK** - Adversarial tactics and techniques

**Real-time updates on:**
- Latest CVEs
- Active threats
- Exploit trends
- Attack patterns

### AI-Powered Insights
**Intelligent analysis powered by GPT-5 Nano:**
- Network security summaries
- Vulnerability prioritization
- Attack vector identification
- Remediation advice

**Features:**
- One-click refresh
- Cached responses (5-minute TTL)
- Configurable analysis depth
- PWNAGOTCHI-style personality

See [AI Integration Guide](AI_INTEGRATION.md) for setup.

### File Management
**Comprehensive file operations:**
- Image gallery view
- File upload/download
- Directory browsing
- File metadata
- Quick preview

### System Monitoring
**Real-time system metrics:**
- CPU usage
- Memory utilization
- Disk space
- Network throughput
- Process monitoring
- Temperature sensors

### Configuration Panel
**System settings management:**
- Network configuration
- Scan parameters
- AI settings
- Display options
- Service controls

## WiFi Management Portal

When Ragnar can't connect to a known network, it creates a WiFi hotspot with a dedicated configuration portal.

### Access Details
- **URL:** `http://192.168.4.1/portal`
- **Network SSID:** `Ragnar`
- **Password:** `ragnarconnect`

### Portal Features

#### Network Scanner
- Automatic WiFi network discovery
- Signal strength indicators (RSSI)
- Security type display
- Channel information

#### Network Configuration
- One-tap connection to scanned networks
- Manual SSID entry for hidden networks
- Password management
- Connection status monitoring

#### Auto-Reconnect Timer
- Countdown display
- Shows time until WiFi retry
- Automatic AP mode exit
- Status notifications

#### Known Networks Management
- View saved networks
- One-click reconnect
- Network priority
- Connection history

### Mobile Optimization
The portal is specifically designed for mobile devices:
- Touch-friendly interface
- Large tap targets
- Simplified navigation
- Quick access to common tasks

## Screenshots

### Main Dashboard
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/3bed08a1-b6cf-4014-9661-85350dc5becc" width="200"/></td>
    <td><img src="https://github.com/user-attachments/assets/88345794-edfc-49e8-90ab-48d72b909e86" width="800"/></td>
  </tr>
</table>

### Detailed View
<img width="1092" height="902" alt="Web Interface Detailed View" src="https://github.com/user-attachments/assets/cafed68d-de62-4041-aa36-c1fcccacc9ea" />

For more images, see [WEB.md](WEB.md).

## API Endpoints

The web interface is powered by a comprehensive REST API:

### Network Endpoints
- `GET /api/network/status` - Network status
- `GET /api/network/targets` - Discovered targets
- `GET /api/network/vulnerabilities` - Found vulnerabilities

### System Endpoints
- `GET /api/system/stats` - System statistics
- `GET /api/system/config` - Configuration
- `POST /api/system/config` - Update configuration

### AI Endpoints
- `GET /api/ai/status` - AI service status
- `GET /api/ai/insights` - Comprehensive insights
- `GET /api/ai/network-summary` - Network summary
- `GET /api/ai/vulnerabilities` - Vulnerability analysis
- `GET /api/ai/weaknesses` - Weakness analysis
- `POST /api/ai/clear-cache` - Clear cache

### Kill Switch
- `POST /api/kill` - Emergency data wipe

See [Kill Switch Documentation](KILL_SWITCH.md) for details.

## Usage Tips

### Navigation
- Use the top menu bar for section navigation
- Click on cards for detailed views
- Use breadcrumbs to track your location
- Bookmark common views

### Performance
- Dashboard auto-refreshes every 30 seconds
- Manual refresh available for immediate updates
- Filter results to reduce data load
- Use pagination for large datasets

### Customization
- Adjust refresh intervals in Config
- Configure display preferences
- Set scan parameters
- Enable/disable features

### Data Export
- Download reports as JSON/CSV
- Export logs for analysis
- Generate PDF summaries
- Share findings securely

## Browser Compatibility

### Recommended Browsers
- **Chrome/Chromium** - Full support ✅
- **Firefox** - Full support ✅
- **Safari** - Full support ✅
- **Edge** - Full support ✅

### Mobile Browsers
- Chrome Mobile ✅
- Safari iOS ✅
- Firefox Mobile ✅
- Samsung Internet ✅

### Minimum Requirements
- JavaScript enabled
- WebSocket support
- CSS3 support
- HTML5 support

## Security Considerations

### Access Control
The web interface runs without authentication by default for ease of use in educational environments.

**For production use, consider:**
- Implementing authentication
- Using reverse proxy with SSL
- Restricting network access
- Enabling firewall rules

### Network Security
- Interface binds to all interfaces (0.0.0.0:8000)
- No encryption by default (HTTP)
- Consider VPN for remote access
- Use kill switch after demonstrations

### Data Protection
- Sensitive data displayed in interface
- Use HTTPS in production
- Clear data after use
- Regular backups of important findings

## Troubleshooting

### Cannot Access Dashboard
1. **Check IP Address**
   - Verify on E-Paper display
   - Use WiFi portal in AP mode
   
2. **Verify Service**
   ```bash
   sudo systemctl status ragnar
   ```

3. **Check Port**
   ```bash
   sudo lsof -i :8000
   ```

4. **Firewall**
   ```bash
   sudo ufw status
   ```

### WebSocket Connection Issues
1. Check browser console for errors
2. Verify network connectivity
3. Restart Ragnar service
4. Clear browser cache

### Slow Performance
1. Reduce auto-refresh interval
2. Limit scan scope
3. Disable unused features
4. Check system resources

### Missing Data
1. Wait for initial scan to complete
2. Check service logs
3. Verify network connectivity
4. Review configuration

## Advanced Features

### Custom Dashboards
Modify the interface to suit your needs:
- Edit `/home/ragnar/Ragnar/web/templates/`
- Customize CSS in static files
- Add custom JavaScript
- Create new visualizations

### API Integration
Build custom tools using Ragnar's API:
```python
import requests

# Get network status
response = requests.get('http://192.168.1.100:8000/api/network/status')
data = response.json()
```

### Webhook Integration
Configure webhooks for:
- New vulnerability alerts
- Target discovery notifications
- System health alerts
- Custom triggers

## Development

### Local Development
```bash
# Start development server
cd /home/ragnar/Ragnar
python3 webapp_modern.py
```

### File Locations
- **Templates:** `/home/ragnar/Ragnar/web/templates/`
- **Static Files:** `/home/ragnar/Ragnar/web/static/`
- **Main App:** `/home/ragnar/Ragnar/webapp_modern.py`

### Contributing
See [Contributing Guide](CONTRIBUTING.md) for:
- Code style guidelines
- Pull request process
- Testing requirements
- Documentation standards

---

## Related Documentation

- [Features](FEATURES.md) - Complete feature list
- [Usage Guide](USAGE.md) - Getting started
- [AI Integration](AI_INTEGRATION.md) - AI setup and usage
- [Kill Switch](KILL_SWITCH.md) - Emergency data wipe

---

⚠️ **Remember: For educational and authorized testing purposes only** ⚠️
