#!/usr/bin/env python3
"""
Fix Alive Status in Network Knowledge Base
==========================================
Updates all discovered hosts (non-STANDALONE) to Alive='1' status.
This enables vulnerability scanning and other actions on discovered hosts.
"""

import csv
import os
import sys

def fix_alive_status():
    """Update all discovered hosts to alive status"""
    netkb_file = "data/netkb.csv"
    
    if not os.path.exists(netkb_file):
        print(f"❌ Error: {netkb_file} not found")
        return False
        
    print("🔧 Fixing alive status in network knowledge base...")
    print(f"📂 Reading from: {netkb_file}\n")
    
    # Read existing data
    rows = []
    headers = []
    updated_count = 0
    
    try:
        with open(netkb_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            
            for row in reader:
                mac = row.get('MAC Address', '')
                ip = row.get('IPs', '')
                alive = row.get('Alive', '0')
                
                # Skip STANDALONE entry
                if mac == 'STANDALONE' or ip == 'STANDALONE':
                    rows.append(row)
                    continue
                
                # Update alive status for discovered hosts
                if alive != '1':
                    print(f"  ✓ Marking {ip} ({mac}) as alive")
                    row['Alive'] = '1'
                    updated_count += 1
                else:
                    print(f"  ✓ {ip} ({mac}) already alive")
                    
                rows.append(row)
        
        # Write updated data back
        with open(netkb_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"\n✅ Successfully updated {updated_count} host(s) to alive status")
        print(f"📊 Total hosts in knowledge base: {len(rows)}")
        print(f"🎯 Ready for vulnerability scanning!")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = fix_alive_status()
    sys.exit(0 if success else 1)
