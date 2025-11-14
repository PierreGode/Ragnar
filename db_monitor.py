#!/usr/bin/env python3
# db_monitor.py - SQLite Database Monitor for Ragnar
# Usage: python3 db_monitor.py [command]
# Commands: stats, hosts, degraded, scans, watch

import os
import sys
import time
import argparse
from datetime import datetime, timedelta

# Add parent directory to path
parent_dir = os.path.dirname(os.path.abspath(__file__))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from db_manager import get_db

def print_separator(char='=', length=80):
    print(char * length)

def show_stats(db):
    """Show database statistics"""
    stats = db.get_stats()
    
    print_separator()
    print("📊 RAGNAR DATABASE STATISTICS")
    print_separator()
    print(f"Total Hosts:          {stats.get('total_hosts', 0)}")
    print(f"  ✅ Alive:           {stats.get('alive_hosts', 0)}")
    print(f"  ⚠️  Degraded:        {stats.get('degraded_hosts', 0)}")
    print(f"Hosts with Ports:     {stats.get('hosts_with_ports', 0)}")
    print(f"Hosts with Vulns:     {stats.get('hosts_with_vulns', 0)}")
    print(f"Total Scans:          {stats.get('total_scans', 0)}")
    print_separator()

def show_hosts(db, status=None):
    """Show all hosts or filtered by status"""
    hosts = db.get_all_hosts(status=status)
    
    if not hosts:
        print(f"No hosts found{' with status: ' + status if status else ''}")
        return
    
    print_separator()
    print(f"🖥️  HOSTS{' - ' + status.upper() if status else ''} ({len(hosts)} total)")
    print_separator()
    print(f"{'IP':<15} {'MAC':<17} {'Hostname':<25} {'Status':<10} {'Fails':<6} {'Ports':<30}")
    print_separator('-')
    
    for host in hosts:
        ip = host.get('ip', '')[:15]
        mac = host.get('mac', '')[:17]
        hostname = host.get('hostname', '')[:25]
        status = host.get('status', '')[:10]
        fails = str(host.get('failed_ping_count', 0))
        ports = host.get('ports', '')[:30]
        
        # Color coding
        status_icon = '✅' if status == 'alive' else '🔴'
        
        print(f"{ip:<15} {mac:<17} {hostname:<25} {status_icon}{status:<9} {fails:<6} {ports:<30}")
    
    print_separator()

def show_degraded(db):
    """Show degraded hosts (30+ failed pings)"""
    hosts = db.get_all_hosts(status='degraded')
    
    if not hosts:
        print("✅ No degraded hosts - all systems nominal!")
        return
    
    print_separator()
    print(f"🔴 DEGRADED HOSTS ({len(hosts)} total)")
    print_separator()
    print(f"{'IP':<15} {'MAC':<17} {'Hostname':<25} {'Failed Pings':<12} {'Last Seen':<20}")
    print_separator('-')
    
    for host in hosts:
        ip = host.get('ip', '')[:15]
        mac = host.get('mac', '')[:17]
        hostname = host.get('hostname', '')[:25]
        fails = str(host.get('failed_ping_count', 0))
        last_seen = host.get('last_seen', '')[:19]
        
        print(f"{ip:<15} {mac:<17} {hostname:<25} {fails:<12} {last_seen:<20}")
    
    print_separator()

def show_scans(db, limit=20):
    """Show recent scan history"""
    scans = db.get_scan_history(limit=limit)
    
    if not scans:
        print("No scan history found")
        return
    
    print_separator()
    print(f"📡 RECENT SCANS (last {limit})")
    print_separator()
    print(f"{'Time':<20} {'Type':<15} {'IP':<15} {'MAC':<17} {'Ports/Vulns':<30}")
    print_separator('-')
    
    for scan in scans:
        timestamp = scan.get('timestamp', '')[:19]
        scan_type = scan.get('scan_type', '')[:15]
        ip = scan.get('ip', '')[:15]
        mac = scan.get('mac', '')[:17]
        
        if scan_type == 'vuln_scan':
            detail = f"Vulns: {scan.get('vulnerabilities_found', 0)}"
        else:
            detail = scan.get('ports_found', '')[:30]
        
        print(f"{timestamp:<20} {scan_type:<15} {ip:<15} {mac:<17} {detail:<30}")
    
    print_separator()

def show_vulnerabilities(db):
    """Show hosts with vulnerabilities"""
    hosts = db.get_all_hosts()
    vuln_hosts = [h for h in hosts if h.get('vulnerabilities') and h.get('vulnerabilities').strip()]
    
    if not vuln_hosts:
        print("✅ No vulnerabilities found!")
        return
    
    print_separator()
    print(f"🔓 HOSTS WITH VULNERABILITIES ({len(vuln_hosts)} total)")
    print_separator()
    print(f"{'IP':<15} {'Hostname':<25} {'Vulnerabilities':<50}")
    print_separator('-')
    
    for host in vuln_hosts:
        ip = host.get('ip', '')[:15]
        hostname = host.get('hostname', '')[:25]
        vulns = host.get('vulnerabilities', '')[:50]
        
        print(f"{ip:<15} {hostname:<25} {vulns:<50}")
    
    print_separator()

def watch_db(db, interval=5):
    """Watch database changes in real-time"""
    print(f"👁️  Watching database (refresh every {interval}s, Ctrl+C to stop)...")
    print()
    
    try:
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print(f"🕐 Last update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print()
            show_stats(db)
            print()
            show_degraded(db)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n\n✋ Stopped watching")

def main():
    parser = argparse.ArgumentParser(
        description='Ragnar SQLite Database Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s stats           Show database statistics
  %(prog)s hosts           Show all hosts
  %(prog)s hosts alive     Show only alive hosts
  %(prog)s degraded        Show degraded hosts (30+ failed pings)
  %(prog)s scans           Show recent scan history
  %(prog)s vulns           Show hosts with vulnerabilities
  %(prog)s watch           Watch database in real-time
        """
    )
    
    parser.add_argument('command', 
                       choices=['stats', 'hosts', 'degraded', 'scans', 'vulns', 'watch'],
                       help='Command to execute')
    parser.add_argument('filter', nargs='?', 
                       help='Optional filter (e.g., "alive" for hosts command)')
    parser.add_argument('--limit', type=int, default=20,
                       help='Limit number of results (default: 20)')
    parser.add_argument('--interval', type=int, default=5,
                       help='Watch interval in seconds (default: 5)')
    
    args = parser.parse_args()
    
    # Initialize database
    currentdir = os.path.dirname(os.path.abspath(__file__))
    db = get_db(currentdir=currentdir)
    
    # Execute command
    if args.command == 'stats':
        show_stats(db)
    elif args.command == 'hosts':
        show_hosts(db, status=args.filter)
    elif args.command == 'degraded':
        show_degraded(db)
    elif args.command == 'scans':
        show_scans(db, limit=args.limit)
    elif args.command == 'vulns':
        show_vulnerabilities(db)
    elif args.command == 'watch':
        watch_db(db, interval=args.interval)

if __name__ == '__main__':
    main()
