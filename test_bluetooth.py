#!/usr/bin/env python3
"""
Test script for Bluetooth scanning on Windows
Run this to verify Bluetooth functionality
"""

import sys
import logging
from actions.ble import BluetoothManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    print("=" * 60)
    print("🔵 Ragnar Bluetooth Scanner Test (Windows Compatible)")
    print("=" * 60)
    print()
    
    # Create Bluetooth manager
    bt = BluetoothManager(logger)
    
    # Check availability
    print("1️⃣ Checking Bluetooth availability...")
    available, msg = bt.check_bluetooth_availability()
    print(f"   Status: {'✓ Available' if available else '✗ Not Available'}")
    print(f"   Message: {msg}")
    print()
    
    if not available:
        print("❌ Bluetooth is not available. Exiting.")
        return 1
    
    # Get status
    print("2️⃣ Getting Bluetooth status...")
    status = bt.get_status()
    print(f"   OS Type: {status.get('os_type', 'Unknown')}")
    print(f"   Enabled: {status.get('enabled', False)}")
    print(f"   Powered: {status.get('powered', False)}")
    print(f"   Name: {status.get('name', 'Unknown')}")
    print(f"   Scanning: {status.get('scanning', False)}")
    if status.get('error'):
        print(f"   Error: {status['error']}")
    print()
    
    # Start scan
    print("3️⃣ Starting Bluetooth scan...")
    success, message = bt.start_scan()
    print(f"   Status: {'✓ Success' if success else '✗ Failed'}")
    print(f"   Message: {message}")
    print()
    
    if not success:
        print("❌ Failed to start scan. Check logs above.")
        return 1
    
    # Wait and get devices
    import time
    print("4️⃣ Scanning for 15 seconds...")
    print("   Make sure nearby Bluetooth devices are turned on and discoverable!")
    print("   (e.g., put your phone in Bluetooth pairing mode)")
    print()
    
    for i in range(15, 0, -1):
        print(f"   Scanning... {i} seconds remaining", end='\r')
        time.sleep(1)
    print()
    print()
    
    # Get discovered devices
    print("5️⃣ Retrieving discovered devices...")
    devices = bt.get_discovered_devices()
    print(f"   Found {len(devices)} devices")
    print()
    
    if devices:
        print("📱 Discovered Devices:")
        print("-" * 60)
        for i, (addr, device) in enumerate(devices.items(), 1):
            print(f"\n{i}. {device['name']}")
            print(f"   Address: {addr}")
            print(f"   Type: {device.get('device_type', 'Unknown')}")
            print(f"   Paired: {'Yes' if device.get('paired') else 'No'}")
            print(f"   Connected: {'Yes' if device.get('connected') else 'No'}")
            if device.get('rssi'):
                print(f"   Signal Strength (RSSI): {device['rssi']} dBm")
            if device.get('windows_device_id'):
                print(f"   Windows Device ID: {device['windows_device_id'][:50]}...")
        print()
        print("-" * 60)
    else:
        print("⚠️  No devices found!")
        print()
        print("Troubleshooting tips:")
        print("  1. Make sure Bluetooth devices nearby are turned ON")
        print("  2. Put devices in pairing/discoverable mode")
        print("  3. Try with your phone - enable Bluetooth and make it discoverable")
        print("  4. Some devices only show up when actively searching for connections")
        print("  5. On Windows, you may need to enable Bluetooth in Settings first")
        print()
    
    # Stop scan
    print("6️⃣ Stopping Bluetooth scan...")
    success, message = bt.stop_scan()
    print(f"   Status: {'✓ Success' if success else '✗ Failed'}")
    print(f"   Message: {message}")
    print()
    
    # Run diagnostics
    print("7️⃣ Running diagnostics...")
    diagnosis = bt.diagnose_scanning()
    print(f"   Bluetooth Available: {diagnosis.get('bluetooth_available', False)}")
    print(f"   Bluetooth Enabled: {diagnosis.get('bluetooth_enabled', False)}")
    print(f"   Scanning Active: {diagnosis.get('scanning_active', False)}")
    
    if diagnosis.get('recommendations'):
        print()
        print("   Recommendations:")
        for rec in diagnosis['recommendations']:
            print(f"   - {rec}")
    print()
    
    print("=" * 60)
    print("✅ Test completed!")
    print("=" * 60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
