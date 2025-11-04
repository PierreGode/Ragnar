#!/usr/bin/env python3
# test_nmap_logging.py
# Simple test script to verify that nmap logging is working correctly

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nmap_logger import nmap_logger

def test_nmap_logging():
    """Test the nmap logging functionality"""
    
    print("Testing nmap logging functionality...")
    
    # Test 1: Log a simple operation
    nmap_logger.log_scan_operation("Test operation", "Testing nmap logging setup")
    
    # Test 2: Log a command (without executing it)
    test_command = ["nmap", "-sn", "127.0.0.1"]
    nmap_logger.log_command(test_command, "Test command logging")
    
    # Test 3: Log a fake result
    nmap_logger.log_result(
        stdout="Starting Nmap 7.94 ( https://nmap.org )\nHost is up.",
        stderr="",
        returncode=0,
        context="Test result logging"
    )
    
    print(f"Nmap logging test completed. Check log file: {nmap_logger.log_file}")
    print(f"Log directory: {os.path.dirname(nmap_logger.log_file)}")
    
    # Check if log file was created
    if os.path.exists(nmap_logger.log_file):
        print("✓ Log file was created successfully")
        with open(nmap_logger.log_file, 'r') as f:
            content = f.read()
            if content:
                print("✓ Log file contains data")
                print("Last 5 lines of log file:")
                lines = content.strip().split('\n')
                for line in lines[-5:]:
                    print(f"  {line}")
            else:
                print("✗ Log file is empty")
    else:
        print("✗ Log file was not created")

if __name__ == "__main__":
    test_nmap_logging()