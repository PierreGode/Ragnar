# Wi-Fi Service Restart Improvements

This document summarizes the improvements made to the Wi-Fi manager to handle service restarts gracefully, particularly when the web interface triggers service updates.

## Problem Statement

When ragnar's web service restarts (e.g., during updates), the Wi-Fi manager would:
- Incorrectly treat the restart as a fresh boot
- Attempt to reconnect even if already connected
- Potentially start AP mode unnecessarily
- Cause temporary loss of connectivity

## Solution Overview

The Wi-Fi manager now includes sophisticated restart detection and connection state persistence to handle service restarts intelligently.

## Key Improvements

### 1. Restart Detection System

**Restart Marker Files**
- Creates `/tmp/ragnar_wifi_manager.pid` with PID and timestamp
- Detects if the service was recently running (within 5 minutes)
- Differentiates between fresh boot and service restart

**Boot Type Detection**
- Checks system uptime (`/proc/uptime`)
- Analyzes NetworkManager service start time
- Combines multiple indicators for accurate detection

### 2. Connection State Persistence

**State File System**
- Saves connection state to `/tmp/ragnar_wifi_state.json`
- Includes: timestamp, connection status, SSID, AP mode status
- Automatically expires old state (10 minutes)

**State Information Tracked**
```json
{
    "timestamp": 1234567890.123,
    "connected": true,
    "ssid": "MyNetwork",
    "ap_mode": false
}
```

### 3. Smart Startup Logic

**Fresh Boot Behavior** (unchanged)
- Full startup delay (30s default)
- Standard connection timeouts
- Normal AP mode fallback

**Service Restart Behavior** (optimized)
- Reduced startup delay (15s)
- Shorter connection timeouts
- Immediate reconnection to previous network
- Conservative AP mode activation

### 4. Enhanced Connection Detection

**Multi-Method Verification**
- nmcli active connection check
- iwconfig wireless interface status
- Ping connectivity test
- Multiple verification rounds

**Existing Connection Awareness**
- Checks for active connections before attempting new ones
- Preserves stable connections during restart
- Updates connection state immediately

## Implementation Details

### Modified Methods

1. **`start()` and `stop()`**
   - Create/cleanup restart markers
   - Save connection state on shutdown
   - Graceful service lifecycle management

2. **`_initial_connection_sequence()`**
   - Load previous connection state
   - Smart restart vs fresh boot handling
   - Prioritize reconnection to previous network

3. **`_is_fresh_boot()`**
   - Enhanced detection with restart markers
   - Multiple verification methods
   - Conservative fallback behavior

4. **`_monitoring_loop()`**
   - Periodic state persistence (every 2 minutes)
   - State updates on connection changes
   - Continuous monitoring without interference

### New Helper Methods

- `_save_connection_state()` - Persist current connection info
- `_load_connection_state()` - Restore previous connection info
- `_cleanup_connection_state()` - Clean up state files
- `_create_restart_marker()` - Create restart detection marker
- `_cleanup_restart_marker()` - Remove restart marker
- `_was_recently_running()` - Check for recent service activity

## Benefits

### Improved Reliability
- No unnecessary AP mode activation during restarts
- Faster reconnection to existing networks
- Reduced connection interruption time

### Better User Experience
- Seamless service updates via web interface
- Maintained connectivity during maintenance
- Predictable behavior across restart scenarios

### Resource Efficiency
- Shorter timeouts for known scenarios
- Reduced unnecessary connection attempts
- Optimized startup sequences

## Configuration Options

The system respects existing configuration settings:
- `startup_delay` - Fresh boot delay (default: 30s)
- `connection_timeout` - Maximum connection attempt time
- `wifi_auto_ap_fallback` - Whether to start AP mode on failure
- `connection_check_interval` - Monitoring frequency

## Logging Improvements

Enhanced logging provides clear visibility into:
- Boot type detection results
- Previous connection state information
- Restart detection triggers
- Connection state changes

Example log output:
```
[INFO] WiFi manager was recently running - treating as service restart
[INFO] Previous state: connected=True, ssid=MyNetwork, ap_mode=False
[INFO] Service restart detected - attempting to reconnect to previous network: MyNetwork
[INFO] Already connected to Wi-Fi network: MyNetwork
```

## Testing Scenarios

### Fresh Boot
1. System powers on
2. WiFi manager starts with full delays
3. Attempts connection to known networks
4. Falls back to AP mode if needed

### Service Restart (Connected)
1. Service restarts while connected to Wi-Fi
2. Detects existing connection immediately
3. Preserves connection without interruption
4. No AP mode activation

### Service Restart (Disconnected)
1. Service restarts while disconnected
2. Attempts reconnection to previous network
3. Reduced timeouts for faster recovery
4. Conservative AP mode decision

## File Locations

- Restart marker: `/tmp/ragnar_wifi_manager.pid`
- Connection state: `/tmp/ragnar_wifi_state.json`
- Main implementation: `wifi_manager.py`

## Future Enhancements

Potential improvements for future versions:
- Connection quality metrics persistence
- Network preference learning
- Advanced failure pattern detection
- Integration with system journal for boot detection
