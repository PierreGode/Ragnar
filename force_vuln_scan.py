#!/usr/bin/env python3
# force_vuln_scan.py
# Force vulnerability scan on all discovered hosts regardless of previous scan status

import sys
import os
import logging
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from shared import SharedData
from actions.nmap_vuln_scanner import NmapVulnScanner
from logger import Logger

logger = Logger(name="force_vuln_scan", level=logging.INFO)

def main():
    """Force scan all discovered hosts for vulnerabilities"""
    try:
        print("Ragnar Force Vulnerability Scanner")
        print("=" * 40)
        
        # Initialize shared data
        shared_data = SharedData()
        
        # Check current network data
        current_data = shared_data.read_data()
        if not current_data:
            print("❌ No network data found. Run network discovery first.")
            return
            
        alive_hosts = [row for row in current_data if row.get("Alive") == '1']
        print(f"📡 Found {len(alive_hosts)} alive hosts in network data")
        
        if not alive_hosts:
            print("❌ No alive hosts found to scan.")
            return
            
        # Display discovered hosts
        print("\n🎯 Discovered hosts:")
        for i, row in enumerate(alive_hosts, 1):
            ip = row.get("IPs", "Unknown")
            hostname = row.get("Hostnames", "")
            mac = row.get("MAC Address", "")
            prev_status = row.get("NmapVulnScanner", "not_scanned")
            print(f"  {i}. {ip} ({hostname}) - MAC: {mac} - Status: {prev_status}")
        
        # Ask for confirmation
        response = input(f"\n🔍 Force scan all {len(alive_hosts)} hosts? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            print("Scan cancelled.")
            return
            
        # Initialize vulnerability scanner
        vuln_scanner = NmapVulnScanner(shared_data)
        
        # Force scan all hosts
        print(f"\n🚀 Starting force vulnerability scan...")
        scanned_count = vuln_scanner.force_scan_all_hosts()
        
        print(f"\n✅ Force scan completed!")
        print(f"📊 Successfully scanned: {scanned_count}/{len(alive_hosts)} hosts")
        print(f"📋 Check /var/log/nmap.log for detailed scan results")
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Force scan error: {e}")

if __name__ == "__main__":
    main()