#scanning.py
# This script performs a network scan to identify live hosts, their MAC addresses, and open ports.
# The results are saved to CSV files and displayed using Rich for enhanced visualization.

import os
import threading
import csv
import traceback
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import socket
import subprocess
import re
try:
    import netifaces_plus as netifaces
except ImportError:
    try:
        import netifaces
    except ImportError:
        netifaces = None
        print("Warning: Neither netifaces nor netifaces-plus found. Network discovery may be limited.")
import time
import glob
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import Progress
try:
    # Try the old import format first
    from getmac import get_mac_address as gma
except ImportError:
    try:
        # Try the new format
        import getmac
        gma = getmac.get_mac_address
    except (ImportError, AttributeError):
        # Final fallback
        def gma(*args, **kwargs):
            return "00:00:00:00:00:00"
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared import SharedData
from logger import Logger
import ipaddress
import nmap
from nmap_logger import nmap_logger

logger = Logger(name="scanning.py", level=logging.DEBUG)

b_class = "NetworkScanner"
b_module = "scanning"
b_status = "network_scanner"
b_port = None
b_parent = None
b_priority = 1

class NetworkScanner:
    """
    This class handles the entire network scanning process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.displaying_csv = shared_data.displaying_csv
        self.blacklistcheck = shared_data.blacklistcheck
        self.mac_scan_blacklist = shared_data.mac_scan_blacklist
        self.ip_scan_blacklist = shared_data.ip_scan_blacklist
        self.console = Console()
        self.lock = threading.Lock()
        self.currentdir = shared_data.currentdir
        # CRITICAL: Pi Zero W2 has limited resources - use conservative thread count
        # 512MB RAM, 4 cores @ 1GHz can only handle a few concurrent operations
        cpu_count = os.cpu_count() or 1
        # Limit concurrent socket operations aggressively on the Pi Zero 2 W
        self.port_scan_workers = max(2, min(6, cpu_count))
        self.host_scan_workers = max(2, min(6, cpu_count))
        self.semaphore = threading.Semaphore(min(4, max(1, cpu_count // 2 or 1)))
        self.nm = nmap.PortScanner()  # Initialize nmap.PortScanner()
        self.running = False
        self.arp_scan_interface = "wlan0"

    @staticmethod
    def _is_valid_mac(value):
        """Validate MAC address format."""
        if not value:
            return False
        return bool(re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", value.lower()))

    @staticmethod
    def _is_valid_ip(value):
        """Validate IPv4 address format."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def resolve_hostname(self, ip):
        """Resolve hostname for the given IP address."""
        try:
            if ip and self._is_valid_ip(ip):
                hostname, _, _ = socket.gethostbyaddr(ip)
                return hostname
        except (socket.herror, socket.gaierror):
            return ""
        except Exception as e:
            self.logger.debug(f"Error resolving hostname for {ip}: {e}")
        return ""

    def _parse_arp_scan_output(self, output):
        """Parse arp-scan output into a mapping of IP to metadata."""
        hosts = {}
        if not output:
            return hosts

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Interface:") or line.startswith("Starting") or line.startswith("Ending"):
                continue

            parts = re.split(r"\s+", line)
            if len(parts) < 2:
                continue

            ip_candidate, mac_candidate = parts[0], parts[1]
            if not (self._is_valid_ip(ip_candidate) and self._is_valid_mac(mac_candidate)):
                continue

            vendor = " ".join(parts[2:]).strip() if len(parts) > 2 else ""
            hosts[ip_candidate] = {
                "mac": mac_candidate.lower(),
                "vendor": vendor
            }

        return hosts

    def run_arp_scan(self):
        """Execute arp-scan to get MAC addresses and vendor information for local network hosts."""
        # Try both --localnet and explicit subnet scanning for comprehensive MAC discovery
        commands = [
            ['sudo', 'arp-scan', f'--interface={self.arp_scan_interface}', '--localnet'],
            ['sudo', 'arp-scan', f'--interface={self.arp_scan_interface}', '192.168.1.0/24']
        ]
        
        all_hosts = {}
        
        for command in commands:
            self.logger.info(f"Running arp-scan for MAC/vendor discovery: {' '.join(command)}")
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
                hosts = self._parse_arp_scan_output(result.stdout)
                self.logger.info(f"arp-scan command '{' '.join(command)}' discovered {len(hosts)} MACs")
                all_hosts.update(hosts)  # Merge results from both scans
            except FileNotFoundError:
                self.logger.error("arp-scan command not found. Install arp-scan or adjust configuration.")
                continue
            except subprocess.TimeoutExpired as e:
                self.logger.error(f"arp-scan timed out: {e}")
                hosts = self._parse_arp_scan_output(e.stdout or "")
                all_hosts.update(hosts)
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"arp-scan exited with code {e.returncode}: {e.stderr.strip() if e.stderr else 'no stderr'}")
                hosts = self._parse_arp_scan_output(e.stdout or "")
                all_hosts.update(hosts)
            except Exception as e:
                self.logger.error(f"Unexpected error running arp-scan: {e}")
                continue
        
        self.logger.info(f"📋 arp-scan complete: {len(all_hosts)} hosts with MAC addresses discovered")
        return all_hosts

    def run_nmap_network_scan(self, network_cidr, portstart, portend, extra_ports):
        """
        Use nmap to scan entire network for host discovery AND port scanning in one efficient sweep.
        This is much faster and more reliable than ping sweeps.
        Returns: dict of {ip: {'hostname': str, 'open_ports': [int]}}
        """
        self.logger.info(f"🚀 Starting nmap network-wide scan: {network_cidr}")
        
        # Most common ports - top 50 commonly used ports
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
            # Add extra_ports for custom services
            *( extra_ports or [] )
        ]
        
        # Remove duplicates while preserving order
        seen_ports = set()
        ordered_ports = []
        for port in common_ports:
            if port not in seen_ports:
                seen_ports.add(port)
                ordered_ports.append(port)
        
        port_list = ','.join(map(str, ordered_ports))
        
        # Nmap arguments for network-wide scan:
        # -Pn: Skip host discovery (treat all as online)
        # -sS: SYN scan (requires root, 10x faster than -sT)
        # --open: Only show open ports
        # --min-rate 5000: Send at least 5000 probes per second
        # --max-retries 1: No slow resends
        # --host-timeout 10s: Limit per-host time strictly
        # -v: Verbose output
        nmap_args = f"-Pn -sS -p{port_list} --open --min-rate 5000 --max-retries 1 --host-timeout 10s -v"
        
        nmap_command = f"nmap {nmap_args} {network_cidr}"
        self.logger.info(f"🔍 Executing: {nmap_command}")
        self.logger.info(f"   Scanning {len(ordered_ports)} ports across entire {network_cidr} network")
        
        nmap_results = {}
        
        try:
            scan_start = time.time()
            self.nm.scan(hosts=network_cidr, arguments=nmap_args)
            scan_duration = time.time() - scan_start
            
            all_hosts = self.nm.all_hosts()
            self.logger.info(f"✅ Network scan complete in {scan_duration:.2f}s - found {len(all_hosts)} hosts with open ports")
            
            for host in all_hosts:
                try:
                    hostname = self.nm[host].hostname() or ''
                    open_ports = []
                    
                    # Extract open TCP ports
                    if 'tcp' in self.nm[host]:
                        tcp_ports = self.nm[host]['tcp']
                        for port in tcp_ports:
                            if tcp_ports[port]['state'] == 'open':
                                open_ports.append(port)
                                self.logger.debug(f"   ✅ {host}: port {port}/tcp open ({tcp_ports[port].get('name', 'unknown')})")
                    
                    # Extract open UDP ports if scanned
                    if 'udp' in self.nm[host]:
                        udp_ports = self.nm[host]['udp']
                        for port in udp_ports:
                            if udp_ports[port]['state'] == 'open':
                                open_ports.append(port)
                                self.logger.debug(f"   ✅ {host}: port {port}/udp open")
                    
                    if open_ports:
                        nmap_results[host] = {
                            'hostname': hostname,
                            'open_ports': sorted(open_ports)
                        }
                        self.logger.info(f"📍 {host} ({hostname or 'no hostname'}): {len(open_ports)} open ports - {sorted(open_ports)}")
                    
                except Exception as e:
                    self.logger.warning(f"Error processing nmap results for {host}: {e}")
                    continue
            
            self.logger.info(f"🎉 NMAP NETWORK SCAN COMPLETE: {len(nmap_results)} hosts with open ports discovered")
            
        except Exception as e:
            self.logger.error(f"💥 Nmap network scan failed: {type(e).__name__}: {e}")
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")
        
        return nmap_results

    def _ping_sweep_missing_hosts(self, arp_hosts):
        """
        Ping sweep to find hosts that don't respond to arp-scan but are alive.
        Expands CIDR ranges like '192.168.1.0/24' into individual IPs.
        """
        ping_discovered = {}
        known_ips = set(arp_hosts.keys())
        
        # Define CIDRs to scan
        target_cidrs = ['192.168.1.0/24']
        
        # CRITICAL TARGET: Always ensure 192.168.1.192 is checked explicitly
        priority_targets = ['192.168.1.192']

        self.logger.info(f"🔍 Starting ping sweep - ARP found {len(arp_hosts)} hosts, checking {254} additional IPs")

        for cidr in target_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                self.logger.error(f"Invalid network {cidr}: {e}")
                continue

            # First, ping priority targets explicitly
            for priority_ip in priority_targets:
                if priority_ip in known_ips:
                    self.logger.info(f"✅ Priority target {priority_ip} already found by ARP scan")
                    continue
                
                self.logger.info(f"🎯 PRIORITY PING: Testing critical target {priority_ip}")
                try:
                    result = subprocess.run(
                        ['ping', '-c', '3', '-W', '3', priority_ip],  # 3 pings, 3 sec timeout
                        capture_output=True, text=True, timeout=10
                    )

                    if result.returncode == 0:
                        mac = self.get_mac_address(priority_ip, "")
                        if not mac or mac == "00:00:00:00:00:00":
                            ip_parts = priority_ip.split('.')
                            pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                            mac = pseudo_mac

                        ping_discovered[priority_ip] = {
                            "mac": mac,
                            "vendor": "Priority target (discovered by ping)"
                        }
                        self.logger.info(f"🎉 PRIORITY TARGET FOUND: {priority_ip} (MAC: {mac})")
                    else:
                        self.logger.warning(f"❌ Priority target {priority_ip} not responding to ping")

                except subprocess.TimeoutExpired:
                    self.logger.warning(f"⏰ Priority target {priority_ip} ping timed out")
                except Exception as e:
                    self.logger.error(f"💥 Priority target {priority_ip} ping failed: {e}")

            # Then scan the rest of the network
            for ip in network.hosts():  # skips network/broadcast
                ip_str = str(ip)
                if ip_str in known_ips or ip_str in priority_targets:
                    continue

                try:
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '2', ip_str],
                        capture_output=True, text=True, timeout=5
                    )

                    if result.returncode == 0:
                        mac = self.get_mac_address(ip_str, "")
                        if not mac or mac == "00:00:00:00:00:00":
                            ip_parts = ip_str.split('.')
                            pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                            mac = pseudo_mac

                        ping_discovered[ip_str] = {
                            "mac": mac,
                            "vendor": "Unknown (discovered by ping)"
                        }
                        self.logger.info(f"📡 Ping sweep found host: {ip_str} (MAC: {mac})")

                except subprocess.TimeoutExpired:
                    self.logger.debug(f"Ping sweep: {ip_str} timed out")
                except Exception as e:
                    self.logger.debug(f"Ping sweep: {ip_str} failed ({e})")
                    continue

        if ping_discovered:
            self.logger.info(f"🎊 PING SWEEP COMPLETE: Discovered {len(ping_discovered)} additional hosts not found by arp-scan")
            for ip, data in ping_discovered.items():
                self.logger.info(f"   📍 {ip} - MAC: {data['mac']} - {data['vendor']}")
        else:
            self.logger.warning(f"❌ Ping sweep found no additional hosts beyond ARP scan results")

        return ping_discovered

    def check_if_csv_scan_file_exists(self, csv_scan_file, csv_result_file, netkbfile):
        """
        Checks and prepares the necessary CSV files for the scan.
        """
        with self.lock:
            try:
                if not os.path.exists(os.path.dirname(csv_scan_file)):
                    os.makedirs(os.path.dirname(csv_scan_file))
                if not os.path.exists(os.path.dirname(netkbfile)):
                    os.makedirs(os.path.dirname(netkbfile))
                if os.path.exists(csv_scan_file):
                    os.remove(csv_scan_file)
                if os.path.exists(csv_result_file):
                    os.remove(csv_result_file)
                if not os.path.exists(netkbfile):
                    with open(netkbfile, 'w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports', 'Failed_Pings'])
            except Exception as e:
                self.logger.error(f"Error in check_if_csv_scan_file_exists: {e}")

    def get_current_timestamp(self):
        """
        Returns the current timestamp in a specific format.
        """
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def ip_key(self, ip):
        """
        Converts an IP address to a tuple of integers for sorting.
        """
        if ip == "STANDALONE":
            return (0, 0, 0, 0)
        try:
            return tuple(map(int, ip.split('.')))
        except ValueError as e:
            self.logger.error(f"Error in ip_key: {e}")
            return (0, 0, 0, 0)

    def sort_and_write_csv(self, csv_scan_file):
        """
        Sorts the CSV file based on IP addresses and writes the sorted content back to the file.
        """
        with self.lock:
            try:
                with open(csv_scan_file, 'r') as file:
                    lines = file.readlines()
                sorted_lines = [lines[0]] + sorted(lines[1:], key=lambda x: self.ip_key(x.split(',')[0]))
                with open(csv_scan_file, 'w') as file:
                    file.writelines(sorted_lines)
            except Exception as e:
                self.logger.error(f"Error in sort_and_write_csv: {e}")

    class GetIpFromCsv:
        """
        Helper class to retrieve IP addresses, hostnames, and MAC addresses from a CSV file.
        """
        def __init__(self, outer_instance, csv_scan_file):
            self.outer_instance = outer_instance
            self.csv_scan_file = csv_scan_file
            self.ip_list = []
            self.hostname_list = []
            self.mac_list = []
            self.get_ip_from_csv()

        def get_ip_from_csv(self):
            """
            Reads IP addresses, hostnames, and MAC addresses from the CSV file.
            """
            with self.outer_instance.lock:
                try:
                    with open(self.csv_scan_file, 'r') as csv_scan_file:
                        csv_reader = csv.reader(csv_scan_file)
                        next(csv_reader)
                        for row in csv_reader:
                            if row[0] == "STANDALONE" or row[1] == "STANDALONE" or row[2] == "STANDALONE":
                                continue
                            if not self.outer_instance.blacklistcheck or (row[2] not in self.outer_instance.mac_scan_blacklist and row[0] not in self.outer_instance.ip_scan_blacklist):
                                self.ip_list.append(row[0])
                                self.hostname_list.append(row[1])
                                self.mac_list.append(row[2])
                except Exception as e:
                    self.outer_instance.logger.error(f"Error in get_ip_from_csv: {e}")

    def update_netkb(self, netkbfile, netkb_data, alive_macs):
        """
        Updates the net knowledge base (netkb) file with the scan results.
        """
        with self.lock:
            try:
                netkb_entries = {}
                existing_action_columns = []

                # Read existing CSV file
                if os.path.exists(netkbfile):
                    with open(netkbfile, 'r') as file:
                        reader = csv.DictReader(file)
                        existing_headers = reader.fieldnames
                        existing_action_columns = [header for header in existing_headers if header not in ["MAC Address", "IPs", "Hostnames", "Alive", "Ports", "Failed_Pings"]]
                        for row in reader:
                            mac = row["MAC Address"]
                            ips = row["IPs"].split(';')
                            hostnames = row["Hostnames"].split(';')
                            alive = row["Alive"]
                            ports = row["Ports"].split(';')
                            failed_pings = int(row.get("Failed_Pings", "0"))  # Default to 0 if missing
                            netkb_entries[mac] = {
                                'IPs': set(ips) if ips[0] else set(),
                                'Hostnames': set(hostnames) if hostnames[0] else set(),
                                'Alive': alive,
                                'Ports': set(ports) if ports[0] else set(),
                                'Failed_Pings': failed_pings
                            }
                            for action in existing_action_columns:
                                netkb_entries[mac][action] = row.get(action, "")

                ip_to_mac = {}  # Dictionary to track IP to MAC associations

                for data in netkb_data:
                    mac, ip, hostname, ports = data
                    if not mac or mac == "STANDALONE" or ip == "STANDALONE" or hostname == "STANDALONE":
                        continue
                    
                    # For hosts with unknown MAC (00:00:00:00:00:00), use IP as unique identifier
                    # This allows tracking hosts across routers or when MAC can't be determined
                    if mac == "00:00:00:00:00:00":
                        # Create a pseudo-MAC from the IP for tracking purposes
                        # This ensures each IP is tracked separately even without MAC
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            # Convert IP to a unique MAC-like identifier: 00:00:ip1:ip2:ip3:ip4
                            pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                            mac = pseudo_mac
                            self.logger.debug(f"Created pseudo-MAC {mac} for IP {ip} (MAC address unavailable)")

                    if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                        continue

                    # Check if IP is already associated with a different MAC
                    if ip in ip_to_mac and ip_to_mac[ip] != mac:
                        # Mark the old MAC as having a failed ping instead of immediately dead
                        old_mac = ip_to_mac[ip]
                        if old_mac in netkb_entries:
                            max_failed_pings = self.shared_data.config.get('network_max_failed_pings', 15)
                            current_failures = netkb_entries[old_mac].get('Failed_Pings', 0) + 1
                            netkb_entries[old_mac]['Failed_Pings'] = current_failures
                            
                            # Only mark as dead after reaching failure threshold
                            if current_failures >= max_failed_pings:
                                netkb_entries[old_mac]['Alive'] = '0'
                                self.logger.info(f"Old MAC {old_mac} marked offline after {current_failures} consecutive failed pings (IP reassigned to {mac})")
                            else:
                                netkb_entries[old_mac]['Alive'] = '1'  # Keep alive per 15-ping rule
                                self.logger.debug(f"Old MAC {old_mac} failed ping {current_failures}/{max_failed_pings} due to IP reassignment - keeping alive")

                    # Update or create entry for the new MAC
                    ip_to_mac[ip] = mac
                    if mac in netkb_entries:
                        netkb_entries[mac]['IPs'].add(ip)
                        netkb_entries[mac]['Hostnames'].add(hostname)
                        netkb_entries[mac]['Alive'] = '1'
                        netkb_entries[mac]['Ports'].update(map(str, ports))
                        netkb_entries[mac]['Failed_Pings'] = 0  # Reset failures since host is responsive
                    else:
                        netkb_entries[mac] = {
                            'IPs': {ip},
                            'Hostnames': {hostname},
                            'Alive': '1',
                            'Ports': set(map(str, ports)),
                            'Failed_Pings': 0  # New hosts start with 0 failed pings
                        }
                        for action in existing_action_columns:
                            netkb_entries[mac][action] = ""

                # Update all existing entries - implement 15-failed-pings rule instead of immediate death
                max_failed_pings = self.shared_data.config.get('network_max_failed_pings', 15)
                for mac in netkb_entries:
                    if mac not in alive_macs:
                        # Host not found in current scan - increment failure count
                        current_failures = netkb_entries[mac].get('Failed_Pings', 0)
                        netkb_entries[mac]['Failed_Pings'] = current_failures + 1
                        
                        # Only mark as dead after reaching the failure threshold
                        if netkb_entries[mac]['Failed_Pings'] >= max_failed_pings:
                            netkb_entries[mac]['Alive'] = '0'
                            self.logger.info(f"Host {mac} marked offline after {netkb_entries[mac]['Failed_Pings']} consecutive failed pings")
                        else:
                            # Keep alive until threshold reached
                            netkb_entries[mac]['Alive'] = '1'  # Keep alive per 15-ping rule
                            self.logger.debug(f"Host {mac} failed ping {netkb_entries[mac]['Failed_Pings']}/{max_failed_pings} - keeping alive per {max_failed_pings}-ping rule")

                # Remove entries with multiple IP addresses for a single MAC address
                netkb_entries = {mac: data for mac, data in netkb_entries.items() if len(data['IPs']) == 1}

                sorted_netkb_entries = sorted(netkb_entries.items(), key=lambda x: self.ip_key(sorted(x[1]['IPs'])[0]))

                with open(netkbfile, 'w', newline='') as file:
                    writer = csv.writer(file)
                    # Ensure Failed_Pings is included in headers
                    if "Failed_Pings" not in existing_headers:
                        # Insert Failed_Pings after Ports column
                        headers_list = list(existing_headers)
                        if "Ports" in headers_list:
                            ports_index = headers_list.index("Ports")
                            headers_list.insert(ports_index + 1, "Failed_Pings")
                        else:
                            headers_list.append("Failed_Pings")
                        existing_headers = headers_list
                        existing_action_columns = [header for header in existing_headers if header not in ["MAC Address", "IPs", "Hostnames", "Alive", "Ports", "Failed_Pings"]]
                    
                    writer.writerow(existing_headers)  # Write updated headers
                    for mac, data in sorted_netkb_entries:
                        # Filter out empty strings from ports before sorting
                        valid_ports = [p for p in data['Ports'] if p]
                        row = [
                            mac,
                            ';'.join(sorted(data['IPs'], key=self.ip_key)),
                            ';'.join(sorted(data['Hostnames'])),
                            data['Alive'],
                            ';'.join(sorted(valid_ports, key=int)) if valid_ports else '',
                            str(data.get('Failed_Pings', 0))  # Add Failed_Pings column
                        ]
                        row.extend(data.get(action, "") for action in existing_action_columns)
                        writer.writerow(row)
            except Exception as e:
                self.logger.error(f"Error in update_netkb: {e}")

    def display_csv(self, file_path):
        """
        Displays the contents of the specified CSV file using Rich for enhanced visualization.
        """
        with self.lock:
            try:
                table = Table(title=f"Contents of {file_path}", show_lines=True)
                with open(file_path, 'r') as file:
                    reader = csv.reader(file)
                    headers = next(reader)
                    for header in headers:
                        table.add_column(header, style="cyan", no_wrap=True)
                    for row in reader:
                        formatted_row = [Text(cell, style="green bold") if cell else Text("", style="on red") for cell in row]
                        table.add_row(*formatted_row)
                self.console.print(table)
            except Exception as e:
                self.logger.error(f"Error in display_csv: {e}")

    def get_network(self):
        """
        Retrieves the network information including the default gateway and subnet.
        """
        try:
            if netifaces is None:
                # Fallback to a common private network range if netifaces is not available
                self.logger.warning("netifaces not available, using default network range")
                network = ipaddress.IPv4Network("192.168.1.0/24", strict=False)
                self.logger.info(f"Network (default): {network}")
                return network
                
            gws = netifaces.gateways()
            default_gateway = gws['default'][netifaces.AF_INET][1]
            iface = netifaces.ifaddresses(default_gateway)[netifaces.AF_INET][0]
            ip_address = iface['addr']
            netmask = iface['netmask']
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            network = ipaddress.IPv4Network(f"{ip_address}/{cidr}", strict=False)
            self.logger.info(f"Network: {network}")
            return network
        except Exception as e:
            self.logger.error(f"Error in get_network: {e}")

    def get_mac_address(self, ip, hostname):
        """
        Retrieves the MAC address for the given IP address and hostname.
        """
        try:
            mac = None
            retries = 5
            while not mac and retries > 0:
                mac = gma(ip=ip)
                if not mac:
                    time.sleep(2)  # Attendre 2 secondes avant de réessayer
                    retries -= 1
            if not mac:
                mac = f"{ip}_{hostname}" if hostname else f"{ip}_NoHostname"
            return mac
        except Exception as e:
            self.logger.error(f"Error in get_mac_address: {e}")
            return None

    class PortScanner:
        """
        Helper class to perform port scanning on a target IP using nmap.
        """
        def __init__(self, outer_instance, target, open_ports, portstart, portend, extra_ports):
            self.outer_instance = outer_instance
            self.logger = logger
            self.target = target
            self.open_ports = open_ports
            self.portstart = portstart
            self.portend = portend
            self.extra_ports = extra_ports

        def start(self):
            """
            Starts the port scanning process using nmap for reliable scanning.
            """
            scan_start_time = time.time()
            try:
                # Build port list to scan
                ports_to_scan = list(range(self.portstart, self.portend))
                extra_ports = self.extra_ports or []
                ports_to_scan.extend(extra_ports)
                
                # Remove duplicates while preserving order
                seen_ports = set()
                ordered_ports = []
                for port in ports_to_scan:
                    if port in seen_ports:
                        continue
                    seen_ports.add(port)
                    ordered_ports.append(port)

                self.logger.info(f"🎯 PORT SCAN STARTING: {self.target} - {len(ordered_ports)} ports (range: {self.portstart}-{self.portend}, extra: {len(extra_ports)} ports)")
                self.logger.debug(f"Port list preview for {self.target}: {sorted(ordered_ports)[:10]}{'...' if len(ordered_ports) > 10 else ''}")
                
                # Use nmap for more reliable port scanning
                port_list = ','.join(map(str, ordered_ports))
                
                # Nmap arguments: -Pn (skip ping), -sT (TCP connect), --host-timeout (per-host timeout)
                # Removed --open flag to see all port states (open, closed, filtered)
                nmap_args = f"-Pn -sT -p{port_list} --host-timeout 30s"
                
                self.logger.debug(f"🔍 Executing nmap command for {self.target}: nmap {nmap_args} {self.target}")
                
                try:
                    nmap_start_time = time.time()
                    # Use the nmap scanner from the outer instance
                    self.outer_instance.nm.scan(self.target, arguments=nmap_args)
                    nmap_duration = time.time() - nmap_start_time
                    
                    self.logger.debug(f"⏱️ Nmap scan completed for {self.target} in {nmap_duration:.2f}s")
                    
                    # Log detailed nmap results
                    all_hosts = self.outer_instance.nm.all_hosts()
                    self.logger.debug(f"📊 Nmap results for {self.target}: all_hosts={all_hosts}")
                    
                    if self.target in all_hosts:
                        host_data = self.outer_instance.nm[self.target]
                        self.logger.debug(f"📋 Host data keys for {self.target}: {list(host_data.keys())}")
                        
                        # Log scan info if available
                        if 'status' in host_data:
                            self.logger.debug(f"🔄 Host status for {self.target}: {host_data['status']}")
                        
                        # Check TCP ports
                        if 'tcp' in host_data:
                            tcp_ports = host_data['tcp']
                            self.logger.info(f"🔌 TCP scan results for {self.target}: {len(tcp_ports)} ports scanned")
                            open_count = 0
                            closed_count = 0
                            filtered_count = 0
                            for port in tcp_ports:
                                port_state = tcp_ports[port]['state']
                                port_service = tcp_ports[port].get('name', 'unknown')
                                
                                if port_state == 'open':
                                    self.open_ports[self.target].append(port)
                                    self.logger.info(f"✅ OPEN PORT: {port}/tcp on {self.target} ({port_service})")
                                    open_count += 1
                                elif port_state == 'closed':
                                    self.logger.debug(f"🚪 CLOSED PORT: {port}/tcp on {self.target} ({port_service})")
                                    closed_count += 1
                                elif port_state == 'filtered':
                                    self.logger.debug(f"🛡️ FILTERED PORT: {port}/tcp on {self.target} ({port_service})")
                                    filtered_count += 1
                                else:
                                    self.logger.debug(f"❓ UNKNOWN STATE: Port {port}/tcp = {port_state} on {self.target} ({port_service})")
                            
                            self.logger.info(f"📊 Port summary for {self.target}: {open_count} open, {closed_count} closed, {filtered_count} filtered")
                        else:
                            self.logger.warning(f"⚠️ No TCP results in nmap data for {self.target}")
                        
                        # Check UDP ports if scanned
                        if 'udp' in host_data:
                            udp_ports = host_data['udp']
                            self.logger.debug(f"🔌 UDP scan results for {self.target}: {len(udp_ports)} ports scanned")
                            for port in udp_ports:
                                port_state = udp_ports[port]['state']
                                if port_state == 'open':
                                    self.open_ports[self.target].append(port)
                                    self.logger.info(f"✅ OPEN UDP PORT: {port}/udp on {self.target}")
                    else:
                        self.logger.warning(f"❌ Target {self.target} not found in nmap results. Available hosts: {all_hosts}")
                    
                    # Summary logging
                    scan_duration = time.time() - scan_start_time
                    if self.open_ports[self.target]:
                        self.logger.info(f"🎉 SCAN SUCCESS: Found {len(self.open_ports[self.target])} open ports on {self.target} in {scan_duration:.2f}s: {sorted(self.open_ports[self.target])}")
                    else:
                        self.logger.warning(f"❌ SCAN COMPLETE: No open ports found on {self.target} in {scan_duration:.2f}s (scanned {len(ordered_ports)} ports)")
                        # Log sample of scanned ports for debugging
                        sample_ports = sorted(ordered_ports)[:5] if len(ordered_ports) <= 10 else sorted(ordered_ports)[:5] + ['...'] + sorted(ordered_ports)[-5:]
                        self.logger.debug(f"   Scanned ports: {sample_ports}")
                        
                except Exception as nmap_error:
                    scan_duration = time.time() - scan_start_time
                    self.logger.error(f"💥 NMAP SCAN FAILED for {self.target} after {scan_duration:.2f}s: {type(nmap_error).__name__}: {nmap_error}")
                    # Fallback to socket scanning with shorter timeout
                    self.logger.info(f"🔄 FALLBACK: Switching to socket scanning for {self.target}")
                    self._socket_scan_fallback(ordered_ports)
                    
            except Exception as e:
                scan_duration = time.time() - scan_start_time
                self.logger.error(f"💥 PORT SCAN ERROR for {self.target} after {scan_duration:.2f}s: {type(e).__name__}: {e}")
                import traceback
                self.logger.debug(f"Full traceback: {traceback.format_exc()}")

        def _socket_scan_fallback(self, ports_to_scan):
            """Fallback socket scanning with shorter timeout for when nmap fails"""
            fallback_start_time = time.time()
            self.logger.info(f"🔌 SOCKET FALLBACK: Scanning {self.target} with {len(ports_to_scan)} ports")
            
            initial_open_count = len(self.open_ports[self.target])
            
            with ThreadPoolExecutor(max_workers=min(4, self.outer_instance.port_scan_workers)) as executor:
                futures = [executor.submit(self._scan_port_socket, port) for port in ports_to_scan]
                completed_scans = 0
                failed_scans = 0
                
                for future in futures:
                    try:
                        future.result(timeout=5)  # 5 second timeout per port
                        completed_scans += 1
                    except Exception as e:
                        failed_scans += 1
                        self.logger.debug(f"Socket scan future failed: {e}")
            
            fallback_duration = time.time() - fallback_start_time
            final_open_count = len(self.open_ports[self.target])
            new_ports_found = final_open_count - initial_open_count
            
            if new_ports_found > 0:
                self.logger.info(f"🎉 SOCKET FALLBACK SUCCESS: Found {new_ports_found} additional open ports on {self.target} in {fallback_duration:.2f}s")
            else:
                self.logger.warning(f"❌ SOCKET FALLBACK COMPLETE: No additional ports found on {self.target} in {fallback_duration:.2f}s (completed: {completed_scans}, failed: {failed_scans})")
        
        def _scan_port_socket(self, port):
            """Fallback socket scanning method with aggressive timeout"""
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)  # Very short timeout for fallback
            try:
                s.connect((self.target, port))
                self.open_ports[self.target].append(port)
                self.logger.info(f"✅ SOCKET SUCCESS: Port {port} OPEN on {self.target} (socket fallback)")
            except socket.timeout:
                self.logger.debug(f"Socket timeout on {self.target}:{port}")
            except socket.error as e:
                self.logger.debug(f"Socket connection refused on {self.target}:{port}: {e}")
            except Exception as e:
                self.logger.warning(f"Unexpected socket scan error on {self.target}:{port}: {e}")
            finally:
                s.close()

    class ScanPorts:
        """
        Helper class to manage the overall port scanning process for a network.
        """
        def __init__(self, outer_instance, network, portstart, portend, extra_ports):
            self.outer_instance = outer_instance
            self.logger = logger
            self.progress = 0
            self.network = network
            self.portstart = portstart
            self.portend = portend
            self.extra_ports = extra_ports
            self.currentdir = outer_instance.currentdir
            self.scan_results_dir = outer_instance.shared_data.scan_results_dir
            self.timestamp = outer_instance.get_current_timestamp()
            self.csv_scan_file = os.path.join(self.scan_results_dir, f'scan_{network.network_address}_{self.timestamp}.csv')
            self.csv_result_file = os.path.join(self.scan_results_dir, f'result_{network.network_address}_{self.timestamp}.csv')
            self.netkbfile = outer_instance.shared_data.netkbfile
            self.ip_data = None
            self.open_ports = {}
            self.all_ports = []
            self.ip_hostname_list = []
            self.total_ips = 0
            self.arp_hosts = {}
            self.use_nmap_results = False

        def scan_network_and_write_to_csv(self):
            """
            Scans the network using nmap for host/port discovery and arp-scan for MAC addresses.
            Merges results to get complete host information (IP, MAC, hostname, ports).
            """
            self.outer_instance.check_if_csv_scan_file_exists(self.csv_scan_file, self.csv_result_file, self.netkbfile)
            with self.outer_instance.lock:
                try:
                    with open(self.csv_scan_file, 'a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(['IP', 'Hostname', 'MAC Address'])
                except Exception as e:
                    self.outer_instance.logger.error(f"Error in scan_network_and_write_to_csv (initial write): {e}")

            self.logger.info("🎯 Phase 1: Getting MAC addresses via arp-scan")
            # Get MAC addresses and vendor info from arp-scan
            self.arp_hosts = self.outer_instance.run_arp_scan()
            
            self.logger.info("🎯 Phase 2: Network-wide nmap scan for hosts and ports")
            # Run nmap network-wide scan for host discovery AND port scanning
            network_cidr = str(self.network)
            self.nmap_results = self.outer_instance.run_nmap_network_scan(
                network_cidr, 
                self.portstart, 
                self.portend, 
                self.extra_ports
            )
            
            # Merge results: nmap gives us IPs, hostnames, and ports; arp-scan gives us MACs
            self.logger.info(f"🔗 Merging results: {len(self.nmap_results)} nmap hosts + {len(self.arp_hosts)} arp MACs")
            
            all_ips = set(self.nmap_results.keys()) | set(self.arp_hosts.keys())
            self.logger.info(f"📋 Total unique hosts to process: {len(all_ips)}")
            
            # Store nmap port results for later use
            self.nmap_port_data = {ip: data['open_ports'] for ip, data in self.nmap_results.items()}
            
            # Process all discovered hosts
            for ip in sorted(all_ips, key=self.outer_instance.ip_key):
                # Get hostname from nmap results if available
                hostname = self.nmap_results.get(ip, {}).get('hostname', '')
                if not hostname:
                    hostname = self.outer_instance.resolve_hostname(ip)
                
                # Get MAC from arp-scan results if available
                mac = None
                if ip in self.arp_hosts:
                    mac = self.arp_hosts[ip].get('mac')
                
                if not mac:
                    # Try to get MAC address
                    mac = self.outer_instance.get_mac_address(ip, hostname)
                
                if not mac or mac == "00:00:00:00:00:00":
                    # Create pseudo-MAC for hosts without discoverable MAC
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                        self.logger.debug(f"Created pseudo-MAC {mac} for {ip}")
                
                mac = mac.lower() if mac else "00:00:00:00:00:00"
                
                # Write to CSV
                if not self.outer_instance.blacklistcheck or (mac not in self.outer_instance.mac_scan_blacklist and ip not in self.outer_instance.ip_scan_blacklist):
                    with self.outer_instance.lock:
                        with open(self.csv_scan_file, 'a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([ip, hostname, mac])
                            self.ip_hostname_list.append((ip, hostname, mac))
                    self.logger.debug(f"✅ Added to CSV: {ip} ({hostname}) - MAC: {mac}")

            self.outer_instance.sort_and_write_csv(self.csv_scan_file)
            self.logger.info(f"✅ Network scan complete: {len(self.ip_hostname_list)} hosts processed")

        def get_progress(self):
            """
            Returns the progress of the scanning process.
            """
            total = self.total_ips if self.total_ips else 1
            return (self.progress / total) * 100

        def start(self):
            """
            Starts the network and port scanning process using nmap for efficiency.
            """
            overall_start_time = time.time()
            
            self.logger.info("🚀 STARTING EFFICIENT NETWORK SCAN (nmap network-wide + arp-scan for MACs)")
            
            # Combined discovery and port scan phase
            self.logger.info("📡 Running combined host discovery and port scanning")
            scan_start = time.time()
            self.scan_network_and_write_to_csv()
            scan_duration = time.time() - scan_start
            
            time.sleep(1)
            self.ip_data = self.outer_instance.GetIpFromCsv(self.outer_instance, self.csv_scan_file)
            self.total_ips = len(self.ip_data.ip_list)
            self.logger.info(f"✅ Network scan complete: Found {self.total_ips} hosts in {scan_duration:.2f}s")
            
            if self.total_ips == 0:
                self.logger.warning("❌ No hosts found!")
                return self.ip_data, {}, [], self.csv_result_file, self.netkbfile, set()
            
            # Use nmap port results that were already collected during network scan
            self.logger.info(f"📊 Processing port data from nmap results")
            self.open_ports = {}
            
            for ip in self.ip_data.ip_list:
                # Get ports from nmap results collected during network scan
                if hasattr(self, 'nmap_port_data') and ip in self.nmap_port_data:
                    self.open_ports[ip] = self.nmap_port_data[ip]
                    if self.open_ports[ip]:
                        self.logger.info(f"✅ {ip}: {len(self.open_ports[ip])} open ports - {sorted(self.open_ports[ip])}")
                else:
                    self.open_ports[ip] = []
                    self.logger.debug(f"ℹ️ {ip}: No open ports detected")
            
            # Results summary
            self.all_ports = sorted(list(set(port for ports in self.open_ports.values() for port in ports)))
            total_open_ports = sum(len(ports) for ports in self.open_ports.values())
            hosts_with_ports = len([ip for ip, ports in self.open_ports.items() if ports])
            
            overall_duration = time.time() - overall_start_time
            
            self.logger.info(f"🎉 SCAN COMPLETE!")
            self.logger.info(f"   📈 Total duration: {overall_duration:.2f}s")
            self.logger.info(f"   🎯 Hosts discovered: {self.total_ips}")
            self.logger.info(f"   🔌 Total open ports found: {total_open_ports}")
            self.logger.info(f"   🏠 Hosts with open ports: {hosts_with_ports}")
            self.logger.info(f"   📋 Unique ports discovered: {len(self.all_ports)} - {self.all_ports}")
            
            alive_ips = set(self.ip_data.ip_list)
            return self.ip_data, self.open_ports, self.all_ports, self.csv_result_file, self.netkbfile, alive_ips

    class LiveStatusUpdater:
        """
        Helper class to update the live status of hosts and clean up scan results.
        """
        def __init__(self, source_csv_path, output_csv_path):
            self.logger = logger
            self.source_csv_path = source_csv_path
            self.output_csv_path = output_csv_path
            # Initialize default values in case of errors
            self.df = pd.DataFrame()
            self.total_open_ports = 0
            self.alive_hosts_count = 0
            self.all_known_hosts_count = 0

        def read_csv(self):
            """
            Reads the source CSV file into a DataFrame.
            """
            try:
                if not os.path.exists(self.source_csv_path):
                    self.logger.warning(f"Source CSV file does not exist: {self.source_csv_path}")
                    # Create an empty DataFrame with expected columns
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                
                # Check if file is empty
                if os.path.getsize(self.source_csv_path) == 0:
                    self.logger.warning(f"Source CSV file is empty: {self.source_csv_path}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                
                # Try to read the CSV, catching specific pandas errors
                try:
                    self.df = pd.read_csv(self.source_csv_path)
                except pd.errors.EmptyDataError:
                    self.logger.warning(f"Source CSV file has no data to parse: {self.source_csv_path}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                except Exception as read_error:
                    # Catch any other CSV reading errors (e.g., "No columns to parse from file")
                    self.logger.warning(f"Could not parse CSV file: {read_error}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                
                # Check if DataFrame is empty or missing required columns
                if self.df.empty:
                    self.logger.warning(f"Source CSV file has no data: {self.source_csv_path}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                
                # Ensure required columns exist
                required_columns = ['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive']
                missing_columns = [col for col in required_columns if col not in self.df.columns]
                if missing_columns:
                    self.logger.warning(f"Missing columns in CSV: {missing_columns}")
                    for col in missing_columns:
                        self.df[col] = '' if col != 'Alive' else '0'
                
                self.logger.debug(f"Successfully read {len(self.df)} rows from {self.source_csv_path}")
                
            except Exception as e:
                self.logger.error(f"Error in read_csv: {e}")
                # Create empty DataFrame on error
                self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])

        def calculate_open_ports(self):
            """
            Calculates the total number of open ports for alive hosts.
            """
            try:
                # Initialize default value
                self.total_open_ports = 0
                
                # Check if DataFrame is valid and has required columns
                if self.df.empty or 'Alive' not in self.df.columns or 'Ports' not in self.df.columns:
                    self.logger.warning("DataFrame is empty or missing required columns for port calculation")
                    return
                
                # The Alive column is persisted as strings ("1"/"0").
                # Convert to string and compare against "1" to ensure
                # compatibility with legacy data written by earlier
                # components.
                alive_mask = self.df['Alive'].astype(str).str.strip() == '1'
                alive_df = self.df[alive_mask].copy()
                
                if alive_df.empty:
                    self.logger.debug("No alive hosts found for port calculation")
                    return
                
                # Convert Ports column to string type to avoid pandas dtype warning
                alive_df = alive_df.copy()
                alive_df['Ports'] = alive_df['Ports'].fillna('').astype(str)
                # Count non-empty port entries (split by ';' and filter out empty strings)
                alive_df['Port Count'] = alive_df['Ports'].apply(
                    lambda x: len([p for p in x.split(';') if p.strip()]) if x else 0
                )
                self.total_open_ports = int(alive_df['Port Count'].sum())
                
                self.logger.debug(f"Calculated total open ports: {self.total_open_ports}")
                
            except Exception as e:
                self.logger.error(f"Error in calculate_open_ports: {e}")
                self.total_open_ports = 0

        def calculate_hosts_counts(self):
            """
            Calculates the total and alive host counts.
            """
            try:
                # Initialize default values
                self.all_known_hosts_count = 0
                self.alive_hosts_count = 0
                
                # Check if DataFrame is valid and has required columns
                if self.df.empty or 'MAC Address' not in self.df.columns or 'Alive' not in self.df.columns:
                    self.logger.warning("DataFrame is empty or missing required columns for host count calculation")
                    return
                
                # Count all hosts (excluding STANDALONE entries)
                self.all_known_hosts_count = self.df[self.df['MAC Address'] != 'STANDALONE'].shape[0]
                
                # Count alive hosts
                alive_mask = self.df['Alive'].astype(str).str.strip() == '1'
                self.alive_hosts_count = self.df[alive_mask].shape[0]
                
                self.logger.debug(f"Host counts - Total: {self.all_known_hosts_count}, Alive: {self.alive_hosts_count}")
                
            except Exception as e:
                self.logger.error(f"Error in calculate_hosts_counts: {e}")
                self.all_known_hosts_count = 0
                self.alive_hosts_count = 0

        def save_results(self):
            """
            Saves the calculated results to the output CSV file.
            """
            try:
                # Ensure all required attributes exist with default values
                if not hasattr(self, 'total_open_ports'):
                    self.total_open_ports = 0
                if not hasattr(self, 'alive_hosts_count'):
                    self.alive_hosts_count = 0
                if not hasattr(self, 'all_known_hosts_count'):
                    self.all_known_hosts_count = 0
                
                if not os.path.exists(self.output_csv_path):
                    self.logger.warning(f"Output CSV file does not exist: {self.output_csv_path}")
                    # Create a basic results file if it doesn't exist
                    results_df = pd.DataFrame({
                        'Total Open Ports': [self.total_open_ports],
                        'Alive Hosts Count': [self.alive_hosts_count],
                        'All Known Hosts Count': [self.all_known_hosts_count]
                    })
                    results_df.to_csv(self.output_csv_path, index=False)
                    self.logger.info(f"Created new results file: {self.output_csv_path}")
                    return
                
                # Check if output file is empty
                if os.path.getsize(self.output_csv_path) == 0:
                    self.logger.warning(f"Output CSV file is empty: {self.output_csv_path}")
                    results_df = pd.DataFrame({
                        'Total Open Ports': [self.total_open_ports],
                        'Alive Hosts Count': [self.alive_hosts_count],
                        'All Known Hosts Count': [self.all_known_hosts_count]
                    })
                    results_df.to_csv(self.output_csv_path, index=False)
                    return
                
                results_df = pd.read_csv(self.output_csv_path)
                
                # Ensure at least one row exists
                if results_df.empty:
                    results_df = pd.DataFrame({
                        'Total Open Ports': [self.total_open_ports],
                        'Alive Hosts Count': [self.alive_hosts_count],
                        'All Known Hosts Count': [self.all_known_hosts_count]
                    })
                else:
                    # Update existing data
                    if len(results_df) == 0:
                        results_df.loc[0] = [self.total_open_ports, self.alive_hosts_count, self.all_known_hosts_count]
                    else:
                        results_df.loc[0, 'Total Open Ports'] = self.total_open_ports
                        results_df.loc[0, 'Alive Hosts Count'] = self.alive_hosts_count
                        results_df.loc[0, 'All Known Hosts Count'] = self.all_known_hosts_count
                
                results_df.to_csv(self.output_csv_path, index=False)
                self.logger.debug(f"Successfully saved results to {self.output_csv_path}")
                
            except Exception as e:
                self.logger.error(f"Error in save_results: {e}")
                # Try to create a minimal results file as fallback
                try:
                    fallback_df = pd.DataFrame({
                        'Total Open Ports': [getattr(self, 'total_open_ports', 0)],
                        'Alive Hosts Count': [getattr(self, 'alive_hosts_count', 0)],
                        'All Known Hosts Count': [getattr(self, 'all_known_hosts_count', 0)]
                    })
                    fallback_df.to_csv(self.output_csv_path, index=False)
                    self.logger.info(f"Created fallback results file: {self.output_csv_path}")
                except Exception as fallback_error:
                    self.logger.error(f"Failed to create fallback results file: {fallback_error}")

        def update_livestatus(self):
            """
            Updates the live status of hosts and saves the results.
            """
            try:
                self.read_csv()
                self.calculate_open_ports()
                self.calculate_hosts_counts()
                self.save_results()
                self.logger.info("Livestatus updated")
                self.logger.info(f"Results saved to {self.output_csv_path}")
            except Exception as e:
                self.logger.error(f"Error in update_livestatus: {e}")
        
        def clean_scan_results(self, scan_results_dir):
            """
            Cleans up old scan result files, keeping only the most recent ones.
            """
            try:
                files = glob.glob(scan_results_dir + '/*')
                files.sort(key=os.path.getmtime)
                for file in files[:-20]:
                    os.remove(file)
                self.logger.info("Scan results cleaned up")
            except Exception as e:
                self.logger.error(f"Error in clean_scan_results: {e}")

    def scan(self):
        """
        Initiates the network scan, updates the netkb file, and displays the results.
        """
        try:
            self.shared_data.ragnarorch_status = "NetworkScanner"
            self.logger.info(f"Starting Network Scanner")
            network = self.get_network()
            self.shared_data.bjornstatustext2 = str(network)
            portstart = self.shared_data.portstart
            portend = self.shared_data.portend
            extra_ports = self.shared_data.portlist
            scanner = self.ScanPorts(self, network, portstart, portend, extra_ports)
            ip_data, open_ports, all_ports, csv_result_file, netkbfile, alive_ips = scanner.start()

            # Convert alive MACs to use pseudo-MACs for hosts without real MAC addresses
            alive_macs = set()
            for i, mac in enumerate(ip_data.mac_list):
                if mac == "00:00:00:00:00:00" and i < len(ip_data.ip_list):
                    # Convert to pseudo-MAC using the same logic as update_netkb
                    ip = ip_data.ip_list[i]
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                        alive_macs.add(pseudo_mac)
                        self.logger.debug(f"Added pseudo-MAC {pseudo_mac} to alive_macs for IP {ip}")
                else:
                    alive_macs.add(mac)

            table = Table(title="Scan Results", show_lines=True)
            table.add_column("IP", style="cyan", no_wrap=True)
            table.add_column("Hostname", style="cyan", no_wrap=True)
            table.add_column("Alive", style="cyan", no_wrap=True)
            table.add_column("MAC Address", style="cyan", no_wrap=True)
            for port in all_ports:
                table.add_column(f"{port}", style="green")

            netkb_data = []
            for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                    continue
                alive = '1' if mac in alive_macs else '0'
                row = [ip, hostname, alive, mac] + [Text(str(port), style="green bold") if port in ports else Text("", style="on red") for port in all_ports]
                table.add_row(*row)
                netkb_data.append([mac, ip, hostname, ports])

            with self.lock:
                with open(csv_result_file, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["IP", "Hostname", "Alive", "MAC Address"] + [str(port) for port in all_ports])
                    for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                        if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                            continue
                        alive = '1' if mac in alive_macs else '0'
                        writer.writerow([ip, hostname, alive, mac] + [str(port) if port in ports else '' for port in all_ports])

            self.update_netkb(netkbfile, netkb_data, alive_macs)

            if self.displaying_csv:
                self.display_csv(csv_result_file)

            source_csv_path = self.shared_data.netkbfile
            output_csv_path = self.shared_data.livestatusfile

            updater = self.LiveStatusUpdater(source_csv_path, output_csv_path)
            updater.update_livestatus()
            updater.clean_scan_results(self.shared_data.scan_results_dir)
        except Exception as e:
            self.logger.error(f"Error in scan: {e}")

    def start(self):
        """
        Starts the scanner in a separate thread.
        """
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.scan)
            self.thread.start()
            logger.info("NetworkScanner started.")

    def stop(self):
        """
        Stops the scanner.
        """
        if self.running:
            self.running = False
            if self.thread.is_alive():
                self.thread.join()
            logger.info("NetworkScanner stopped.")

if __name__ == "__main__":
    shared_data = SharedData()
    scanner = NetworkScanner(shared_data)
    scanner.scan()
