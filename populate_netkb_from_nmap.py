#!/usr/bin/env python3
"""
Populate netkb.csv with hosts discovered from recent nmap logs
This is a utility script to manually sync nmap discoveries into the knowledge base
"""

import re
import csv
import os
from datetime import datetime

def parse_nmap_log(log_file="/var/log/nmap.log"):
    """Parse nmap.log to extract discovered hosts"""
    discovered_hosts = set()
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Look for "Host discovery completed - Found N hosts: IP1, IP2, ..."
                if "Host discovery completed" in line and "Found" in line:
                    # Extract IPs from the line
                    match = re.search(r'hosts: (.+)$', line)
                    if match:
                        ip_list = match.group(1).strip().split(', ')
                        discovered_hosts.update(ip_list)
        
        return sorted(list(discovered_hosts))
    except FileNotFoundError:
        print(f"❌ Log file not found: {log_file}")
        return []
    except Exception as e:
        print(f"❌ Error parsing log: {e}")
        return []

def ip_to_pseudo_mac(ip):
    """Convert IP address to pseudo-MAC format for tracking"""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"00:00:{int(parts[0]):02x}:{int(parts[1]):02x}:{int(parts[2]):02x}:{int(parts[3]):02x}"
    return "00:00:00:00:00:00"

def update_netkb(discovered_ips, netkb_file="data/netkb.csv"):
    """Update netkb.csv with discovered hosts"""
    
    if not os.path.exists(netkb_file):
        print(f"❌ NetKB file not found: {netkb_file}")
        return
    
    # Read existing netkb
    existing_entries = {}
    headers = []
    
    with open(netkb_file, 'r') as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        for row in reader:
            mac = row['MAC Address']
            existing_entries[mac] = row
    
    # Add new hosts
    added_count = 0
    updated_count = 0
    
    for ip in discovered_ips:
        pseudo_mac = ip_to_pseudo_mac(ip)
        
        if pseudo_mac in existing_entries:
            # Update existing entry to mark as alive
            if existing_entries[pseudo_mac]['Alive'] != '1':
                existing_entries[pseudo_mac]['Alive'] = '1'
                updated_count += 1
        else:
            # Add new entry
            new_entry = {
                'MAC Address': pseudo_mac,
                'IPs': ip,
                'Hostnames': ip,  # Use IP as hostname if unknown
                'Alive': '1',
                'Ports': ''
            }
            # Initialize all action columns to empty
            for header in headers:
                if header not in new_entry:
                    new_entry[header] = ''
            
            existing_entries[pseudo_mac] = new_entry
            added_count += 1
    
    # Write back to netkb
    with open(netkb_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        
        # Sort by IP for consistent ordering
        sorted_entries = sorted(
            existing_entries.values(),
            key=lambda x: [int(p) for p in x['IPs'].split('.')[0:4]] if '.' in x['IPs'] else [0, 0, 0, 0]
        )
        
        for entry in sorted_entries:
            writer.writerow(entry)
    
    print(f"✅ NetKB updated successfully!")
    print(f"   - Added: {added_count} new hosts")
    print(f"   - Updated: {updated_count} existing hosts")

def main():
    print("Ragnar NetKB Population Tool")
    print("=" * 50)
    
    # Parse nmap logs
    print("\n📋 Parsing nmap logs...")
    discovered_ips = parse_nmap_log()
    
    if not discovered_ips:
        print("❌ No hosts found in nmap logs")
        return
    
    print(f"✅ Found {len(discovered_ips)} unique hosts:")
    for ip in discovered_ips:
        print(f"   - {ip}")
    
    # Update netkb
    print("\n💾 Updating NetKB...")
    update_netkb(discovered_ips)
    
    print("\n🎯 You can now run: sudo python3 force_vuln_scan.py")

if __name__ == "__main__":
    main()
