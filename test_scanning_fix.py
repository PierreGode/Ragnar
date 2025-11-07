#!/usr/bin/env python3
"""
Test script to verify that the scanning race condition fix works correctly.
This script checks that netkb.csv has properly populated Hostnames and Ports columns.
"""

import os
import sys
import csv
import time
import logging
from datetime import datetime

# Add the Ragnar directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from init_shared import shared_data
from actions.scanning import NetworkScanner
from logger import Logger

# Set up logging
logger = Logger(name="test_scanning_fix.py", level=logging.INFO)

def read_netkb_csv(filepath):
    """Read and parse the netkb CSV file."""
    if not os.path.exists(filepath):
        return []
    
    hosts = []
    try:
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                hosts.append(row)
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}")
        return []
    
    return hosts

def analyze_scan_results(hosts):
    """Analyze the scan results to check for the race condition."""
    total_hosts = len(hosts)
    alive_hosts = [h for h in hosts if h.get('Alive') == '1']
    hosts_with_hostnames = [h for h in alive_hosts if h.get('Hostnames', '').strip()]
    hosts_with_ports = [h for h in alive_hosts if h.get('Ports', '').strip()]
    
    logger.info(f"📊 Scan Results Analysis:")
    logger.info(f"   Total hosts: {total_hosts}")
    logger.info(f"   Alive hosts: {len(alive_hosts)}")
    logger.info(f"   Hosts with hostnames: {len(hosts_with_hostnames)}")
    logger.info(f"   Hosts with ports: {len(hosts_with_ports)}")
    
    # Check for the race condition symptoms
    hosts_missing_hostnames = [h for h in alive_hosts if not h.get('Hostnames', '').strip()]
    hosts_missing_ports = [h for h in alive_hosts if not h.get('Ports', '').strip()]
    
    if hosts_missing_hostnames:
        logger.warning(f"❌ Found {len(hosts_missing_hostnames)} alive hosts missing hostnames:")
        for host in hosts_missing_hostnames:
            ip = host.get('IPs', 'unknown')
            mac = host.get('MAC Address', 'unknown')
            logger.warning(f"   IP: {ip}, MAC: {mac}")
        return False
    
    if hosts_missing_ports:
        logger.warning(f"❌ Found {len(hosts_missing_ports)} alive hosts missing ports:")
        for host in hosts_missing_ports:
            ip = host.get('IPs', 'unknown')
            mac = host.get('MAC Address', 'unknown')
            logger.warning(f"   IP: {ip}, MAC: {mac}")
        return False
    
    logger.info("✅ No race condition detected - all alive hosts have hostnames and ports!")
    return True

def test_scanning_fix():
    """Test the scanning race condition fix."""
    logger.info("🔍 Testing scanning race condition fix...")
    logger.info("=" * 50)
    
    # Initialize scanner
    try:
        scanner = NetworkScanner(shared_data)
        logger.info("✅ NetworkScanner initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize NetworkScanner: {e}")
        return False
    
    # Run a network scan
    try:
        logger.info("🔍 Starting network scan...")
        start_time = time.time()
        scanner.scan()
        end_time = time.time()
        scan_duration = end_time - start_time
        logger.info(f"✅ Network scan completed in {scan_duration:.2f} seconds")
    except Exception as e:
        logger.error(f"❌ Network scan failed: {e}")
        return False
    
    # Wait a moment for file I/O to complete
    time.sleep(1)
    
    # Check the netkb.csv file
    netkb_file = shared_data.netkbfile
    logger.info(f"📄 Analyzing results in {netkb_file}")
    
    if not os.path.exists(netkb_file):
        logger.error(f"❌ netkb.csv file not found: {netkb_file}")
        return False
    
    # Read and analyze results
    hosts = read_netkb_csv(netkb_file)
    if not hosts:
        logger.warning("⚠️  No hosts found in netkb.csv")
        return True  # Not necessarily a failure
    
    # Analyze for race condition
    success = analyze_scan_results(hosts)
    
    # Show sample host data
    logger.info("📋 Sample host entries:")
    for i, host in enumerate(hosts[:3]):  # Show first 3 hosts
        ip = host.get('IPs', 'N/A')
        hostname = host.get('Hostnames', 'N/A')
        ports = host.get('Ports', 'N/A')
        alive = host.get('Alive', 'N/A')
        mac = host.get('MAC Address', 'N/A')
        
        logger.info(f"   Host {i+1}:")
        logger.info(f"     IP: {ip}")
        logger.info(f"     Hostname: {hostname}")
        logger.info(f"     Ports: {ports}")
        logger.info(f"     Alive: {alive}")
        logger.info(f"     MAC: {mac}")
    
    return success

def main():
    """Main test function."""
    logger.info("🧪 Ragnar Scanning Race Condition Fix Test")
    logger.info("=" * 60)
    logger.info(f"Test started at: {datetime.now()}")
    
    try:
        success = test_scanning_fix()
        
        if success:
            logger.info("=" * 60)
            logger.info("🎉 TEST PASSED: Race condition fix appears to work correctly!")
            logger.info("   All alive hosts have both hostnames and ports populated.")
            return 0
        else:
            logger.error("=" * 60)
            logger.error("💥 TEST FAILED: Race condition still present!")
            logger.error("   Some alive hosts are missing hostname or port data.")
            return 1
            
    except KeyboardInterrupt:
        logger.info("🛑 Test interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"💥 Test failed with exception: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)