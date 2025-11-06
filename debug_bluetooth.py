#!/usr/bin/env python3
"""
Debug script to test Bluetooth device discovery
"""
import subprocess
import time
import json

def test_bluetoothctl_commands():
    print("🔍 Testing bluetoothctl commands...")
    
    # Test 1: Check current devices
    print("\n1. Current devices:")
    try:
        result = subprocess.run(['bluetoothctl', 'devices'], 
                              capture_output=True, text=True, timeout=10)
        print(f"Return code: {result.returncode}")
        print(f"Output: '{result.stdout.strip()}'")
        print(f"Error: '{result.stderr.strip()}'")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 2: Start scan
    print("\n2. Starting scan:")
    try:
        result = subprocess.run(['bluetoothctl', 'scan', 'on'], 
                              capture_output=True, text=True, timeout=10)
        print(f"Return code: {result.returncode}")
        print(f"Output: '{result.stdout.strip()}'")
        print(f"Error: '{result.stderr.strip()}'")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 3: Wait and check devices again
    print("\n3. Waiting 15 seconds...")
    time.sleep(15)
    
    print("\n4. Devices after scan:")
    try:
        result = subprocess.run(['bluetoothctl', 'devices'], 
                              capture_output=True, text=True, timeout=10)
        print(f"Return code: {result.returncode}")
        print(f"Output: '{result.stdout.strip()}'")
        print(f"Error: '{result.stderr.strip()}'")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 4: Check scan status
    print("\n5. Checking scan status:")
    try:
        result = subprocess.run(['bluetoothctl', 'show'], 
                              capture_output=True, text=True, timeout=10)
        print(f"Return code: {result.returncode}")
        lines = result.stdout.split('\n')
        for line in lines:
            if 'discover' in line.lower() or 'scan' in line.lower():
                print(f"Scan status: {line.strip()}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 5: Stop scan
    print("\n6. Stopping scan:")
    try:
        result = subprocess.run(['bluetoothctl', 'scan', 'off'], 
                              capture_output=True, text=True, timeout=10)
        print(f"Return code: {result.returncode}")
        print(f"Output: '{result.stdout.strip()}'")
        print(f"Error: '{result.stderr.strip()}'")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_bluetoothctl_commands()