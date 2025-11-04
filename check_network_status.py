#!/usr/bin/env python3
# check_network_status.py
# Check current network discovery and vulnerability scan status

import sys
import os
import logging
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from shared import SharedData
from logger import Logger

logger = Logger(name="check_network_status", level=logging.INFO)

def main():
    """Check current network discovery status"""
    try:
        print("Ragnar Network Status Checker")
        print("=" * 40)
        
        # Initialize shared data
        shared_data = SharedData()
        
        # Check current network data
        current_data = shared_data.read_data()
        if not current_data:
            print("❌ No network data found.")
            print("💡 Try running network discovery first:")
            print("   python -m actions.scanning")
            return
            
        print(f"📊 Network Data Summary:")
        print(f"   Total entries: {len(current_data)}")
        
        alive_hosts = [row for row in current_data if row.get("Alive") == '1']
        dead_hosts = [row for row in current_data if row.get("Alive") != '1']
        
        print(f"   Alive hosts: {len(alive_hosts)}")
        print(f"   Dead hosts: {len(dead_hosts)}")
        
        if alive_hosts:
            print(f"\n🎯 Alive Hosts:")
            for i, row in enumerate(alive_hosts, 1):
                ip = row.get("IPs", "Unknown")
                hostname = row.get("Hostnames", "")
                mac = row.get("MAC Address", "")
                ports = row.get("Ports", "")
                vuln_status = row.get("NmapVulnScanner", "not_scanned")
                
                print(f"  {i}. {ip}")
                if hostname:
                    print(f"     Hostname: {hostname}")
                print(f"     MAC: {mac}")
                if ports:
                    print(f"     Ports: {ports}")
                print(f"     Vuln Status: {vuln_status}")
                print()
        
        # Check configuration
        print("⚙️  Configuration:")
        print(f"   Vulnerability scanning enabled: {shared_data.scan_vuln_running}")
        print(f"   Retry on success: {shared_data.retry_success_actions}")
        print(f"   Retry on failure: {shared_data.retry_failed_actions}")
        print(f"   Success retry delay: {shared_data.success_retry_delay}s")
        print(f"   Failed retry delay: {shared_data.failed_retry_delay}s")
        print(f"   Vuln scan interval: {shared_data.scan_vuln_interval}s")
        
        # Show last nmap log entries
        nmap_log_path = "/var/log/nmap.log"
        local_log_path = os.path.join(os.path.dirname(__file__), "var", "log", "nmap.log")
        
        log_file = None
        if os.path.exists(nmap_log_path):
            log_file = nmap_log_path
        elif os.path.exists(local_log_path):
            log_file = local_log_path
            
        if log_file:
            print(f"\n📋 Recent nmap activity (last 5 lines from {log_file}):")
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-5:]:
                        print(f"   {line.strip()}")
            except Exception as e:
                print(f"   Error reading log: {e}")
        else:
            print(f"\n📋 No nmap log file found")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Status check error: {e}")

if __name__ == "__main__":
    main()