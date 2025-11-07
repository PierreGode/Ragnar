#scanning.py
# This script performs a network scan to identify live hosts, their MAC addresses, and open ports.
# The results are saved to CSV files and displayed using Rich for enhanced visualization.

import os
import threading
import csv
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
from shared import SharedData
from logger import Logger
import ipaddress
import nmap
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
        # ULTRA-CONSERVATIVE: Watchdog restarts if FDs > 200, so minimize concurrent operations
        # Each network scan can open multiple FDs (socket, DNS, nmap subprocess, etc.)
        self.port_scan_workers = 1  # Sequential port scanning to prevent FD exhaustion
        self.host_scan_workers = 2  # Max 2 concurrent host scans (down from 6)
        self.semaphore = threading.Semaphore(1)  # Only 1 concurrent scan operation
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
        """Execute arp-scan to quickly discover hosts on the local network."""
        # Try both --localnet and explicit subnet scanning for comprehensive discovery
        commands = [
            ['sudo', 'arp-scan', f'--interface={self.arp_scan_interface}', '--localnet'],
            ['sudo', 'arp-scan', f'--interface={self.arp_scan_interface}', '192.168.1.0/24']
        ]
        
        all_hosts = {}
        
        for command in commands:
            self.logger.info(f"Running arp-scan for host discovery: {' '.join(command)}")
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
                hosts = self._parse_arp_scan_output(result.stdout)
                self.logger.info(f"arp-scan command '{' '.join(command)}' discovered {len(hosts)} hosts")
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
        
        self.logger.info(f"Total unique hosts discovered by all arp-scan methods: {len(all_hosts)}")
        
        # Supplementary ping sweep for hosts that don't respond to ARP
        # This catches devices like 192.168.1.192 that may filter ARP but respond to ping
        ping_discovered = self._ping_sweep_missing_hosts(all_hosts)
        all_hosts.update(ping_discovered)
        
        self.logger.info(f"Final host count after arp-scan + ping sweep: {len(all_hosts)}")
        return all_hosts

    def _ping_sweep_missing_hosts(self, arp_hosts):
        """
        Ping sweep to find hosts that don't respond to arp-scan but are alive.
        Uses parallel execution and skips known-empty ranges for efficiency.
        """
        ping_discovered = {}
        known_ips = set(arp_hosts.keys())
        
        # Define CIDRs to scan with optimized ranges
        # Skip ranges that are typically empty to speed up scanning on Pi Zero W2
        target_cidrs = ['192.168.1.0/24']
        
        # Define ranges to skip (typically empty in home networks)
        # Adjust these based on your network - skip middle ranges that are rarely used
        skip_ranges = [
            (50, 99),   # Skip .50-.99 if typically empty
            (150, 199)  # Skip .150-.199 if typically empty
        ]

        def should_skip_ip(ip_str):
            """Check if IP should be skipped based on configured ranges"""
            try:
                last_octet = int(ip_str.split('.')[-1])
                for start, end in skip_ranges:
                    if start <= last_octet <= end:
                        return True
                return False
            except (ValueError, IndexError):
                return False

        def ping_host(ip_str):
            """Ping a single host and return result"""
            if ip_str in known_ips or should_skip_ip(ip_str):
                return None
                
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip_str],  # Reduced wait from 2s to 1s
                    capture_output=True, text=True, timeout=3  # Reduced timeout from 5s to 3s
                )

                if result.returncode == 0:
                    mac = self.get_mac_address(ip_str, "")
                    if not mac or mac == "00:00:00:00:00:00":
                        ip_parts = ip_str.split('.')
                        pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                        mac = pseudo_mac

                    self.logger.info(f"Ping sweep found host: {ip_str} (MAC: {mac})")
                    return (ip_str, {"mac": mac, "vendor": "Unknown (discovered by ping)"})
                    
            except subprocess.TimeoutExpired:
                self.logger.debug(f"Ping sweep: {ip_str} timed out")
            except Exception as e:
                self.logger.debug(f"Ping sweep: {ip_str} failed ({e})")
            
            return None

        # Build list of IPs to scan
        ips_to_scan = []
        for cidr in target_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                for ip in network.hosts():
                    ip_str = str(ip)
                    if ip_str not in known_ips and not should_skip_ip(ip_str):
                        ips_to_scan.append(ip_str)
            except ValueError as e:
                self.logger.error(f"Invalid network {cidr}: {e}")
                continue

        # Log optimization info
        total_possible = sum(ipaddress.ip_network(cidr, strict=False).num_addresses - 2 for cidr in target_cidrs)
        skipped = total_possible - len(ips_to_scan) - len(known_ips)
        self.logger.info(f"Ping sweep: scanning {len(ips_to_scan)} IPs (skipped {skipped} in empty ranges, {len(known_ips)} already known)")

        # Parallel ping sweep using ThreadPoolExecutor
        # ULTRA-CONSERVATIVE: Fixed at 2 workers to minimize file descriptor usage
        max_ping_workers = 2
        
        try:
            with ThreadPoolExecutor(max_workers=max_ping_workers) as executor:
                futures = {executor.submit(ping_host, ip): ip for ip in ips_to_scan}
                
                for future in futures:
                    try:
                        result = future.result(timeout=5)  # Overall future timeout
                        if result:
                            ip_str, host_data = result
                            ping_discovered[ip_str] = host_data
                    except Exception as e:
                        self.logger.debug(f"Ping sweep future failed: {e}")
        except RuntimeError as e:
            if "cannot schedule new futures after interpreter shutdown" in str(e):
                self.logger.warning(f"Ping sweep interrupted by interpreter shutdown (watchdog restart), discovered {len(ping_discovered)} hosts before interruption")
            else:
                raise

        if ping_discovered:
            self.logger.info(f"Ping sweep discovered {len(ping_discovered)} additional hosts not found by arp-scan")

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
                existing_headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports", "Failed_Pings"]

                # Read existing CSV file
                if os.path.exists(netkbfile):
                    with open(netkbfile, 'r') as file:
                        reader = csv.DictReader(file)
                        file_headers = reader.fieldnames or []

                        # Merge any existing headers with the defaults so we always
                        # have the core columns even if the CSV was empty or malformed.
                        for header in file_headers:
                            if header and header not in existing_headers:
                                existing_headers.append(header)

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
                        row = [
                            mac,
                            ';'.join(sorted(data['IPs'], key=self.ip_key)),
                            ';'.join(sorted(data['Hostnames'])),
                            data['Alive'],
                            ';'.join(sorted(data['Ports'], key=int)),
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
            Starts the port scanning process for the specified range and extra ports using nmap.
            """
            try:
                # Ensure target is in open_ports dict
                if self.target not in self.open_ports:
                    self.open_ports[self.target] = []
                
                # Fix port range - make portend inclusive
                ports_to_scan = list(range(self.portstart, self.portend + 1))
                extra_ports = self.extra_ports or []
                ports_to_scan.extend(extra_ports)
                
                # Remove duplicates and invalid ports
                seen_ports = set()
                ordered_ports = []
                for port in ports_to_scan:
                    if port in seen_ports or port < 1 or port > 65535:
                        continue
                    seen_ports.add(port)
                    ordered_ports.append(port)

                if not ordered_ports:
                    self.logger.error(f"No valid ports to scan for {self.target}! portstart={self.portstart}, portend={self.portend}")
                    return

                self.logger.info(f"Scanning {self.target}: {len(ordered_ports)} ports using nmap (range: {self.portstart}-{self.portend}, extra: {len(extra_ports)} ports)")
                
                # Use TCP connect scan (-sT) which works without root privileges
                port_spec = ','.join(map(str, ordered_ports))
                nmap_args = f"-Pn -sT -T4 --max-retries 1 -p {port_spec}"
                
                self.logger.info(f"Running nmap command: nmap {nmap_args} {self.target}")
                nmap_logger.log_scan_operation(f"Port scan: {self.target}", f"Arguments: {nmap_args}")
                
                try:
                    # Run nmap scan
                    self.outer_instance.nm.scan(hosts=self.target, arguments=nmap_args)
                    
                    # Debug: Show all discovered hosts
                    all_hosts = self.outer_instance.nm.all_hosts()
                    self.logger.debug(f"Nmap discovered hosts: {all_hosts}")
                    
                    if self.target in all_hosts:
                        self.logger.debug(f"Target {self.target} found in nmap results")
                        
                        # Get scan info for debugging
                        scan_info = self.outer_instance.nm[self.target]
                        self.logger.debug(f"Scan info for {self.target}: state={scan_info.state()}")
                        
                        # Process each protocol (usually 'tcp')
                        protocols = scan_info.all_protocols()
                        self.logger.debug(f"Protocols found: {protocols}")
                        
                        for proto in protocols:
                            ports = scan_info[proto].keys()
                            self.logger.debug(f"Ports scanned on {proto}: {sorted(ports)}")
                            
                            for port in ports:
                                port_info = scan_info[proto][port]
                                port_state = port_info['state']
                                self.logger.debug(f"Port {port}/{proto}: state={port_state}")
                                
                                if port_state == 'open':
                                    self.open_ports[self.target].append(port)
                                    self.logger.info(f"🔓 Port {port}/{proto} OPEN on {self.target}")
                    else:
                        self.logger.warning(f"Target {self.target} not found in nmap results. All hosts: {all_hosts}")
                        # Check if host was down
                        if self.target in self.outer_instance.nm._scan_result['scan']:
                            scan_data = self.outer_instance.nm._scan_result['scan'][self.target]
                            self.logger.debug(f"Scan data for {self.target}: {scan_data}")
                    
                    if self.open_ports[self.target]:
                        self.logger.info(f"✅ Found {len(self.open_ports[self.target])} open ports on {self.target}: {sorted(self.open_ports[self.target])}")
                        nmap_logger.log_scan_operation(f"Port scan completed: {self.target}", f"Found {len(self.open_ports[self.target])} open ports: {sorted(self.open_ports[self.target])}")
                    else:
                        self.logger.warning(f"❌ No open ports found on {self.target} (scanned {len(ordered_ports)} ports)")
                        nmap_logger.log_scan_operation(f"Port scan completed: {self.target}", f"No open ports found (scanned {len(ordered_ports)} ports)")
                        
                except Exception as nmap_error:
                    self.logger.error(f"Nmap port scan error for {self.target}: {nmap_error}")
                    nmap_logger.log_scan_operation(f"Port scan FAILED: {self.target}", f"Error: {nmap_error}")
                    # Try to get more error details
                    try:
                        import subprocess
                        test_result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
                        self.logger.debug(f"Nmap version check: {test_result.stdout.strip()}")
                    except Exception as version_error:
                        self.logger.error(f"Nmap not accessible: {version_error}")
                    
            except Exception as e:
                import traceback
                self.logger.error(f"Error during port scan of {self.target}: {e}\n{traceback.format_exc()}")

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
            Scans the network and writes the results to a CSV file.
            """
            self.outer_instance.check_if_csv_scan_file_exists(self.csv_scan_file, self.csv_result_file, self.netkbfile)
            with self.outer_instance.lock:
                try:
                    with open(self.csv_scan_file, 'a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(['IP', 'Hostname', 'MAC Address'])
                except Exception as e:
                    self.outer_instance.logger.error(f"Error in scan_network_and_write_to_csv (initial write): {e}")

            # Prefer arp-scan for host discovery
            self.arp_hosts = self.outer_instance.run_arp_scan()

            if self.arp_hosts:
                all_hosts = sorted(self.arp_hosts.keys(), key=self.outer_instance.ip_key)
                self.logger.info(f"Using arp-scan results for {len(all_hosts)} hosts")
            else:
                # Fallback to nmap host discovery if arp-scan failed
                nmap_logger.log_scan_operation("Host discovery scan (fallback)", f"Network: {self.network}, Arguments: -sn")
                self.outer_instance.nm.scan(hosts=str(self.network), arguments='-sn')
                all_hosts = self.outer_instance.nm.all_hosts()
                nmap_logger.log_scan_operation("Host discovery completed (nmap)", f"Found {len(all_hosts)} hosts: {', '.join(all_hosts)}")
                self.use_nmap_results = True

            try:
                with ThreadPoolExecutor(max_workers=self.outer_instance.host_scan_workers) as executor:
                    futures = [
                        executor.submit(self.scan_host, host, self.arp_hosts.get(host))
                        for host in all_hosts
                    ]
                    for future in futures:
                        future.result()
            except RuntimeError as e:
                if "cannot schedule new futures after interpreter shutdown" in str(e):
                    self.logger.warning(f"Host scan interrupted by interpreter shutdown (watchdog restart), scanned {len(all_hosts)} hosts before interruption")
                else:
                    raise

            self.outer_instance.sort_and_write_csv(self.csv_scan_file)

        def scan_host(self, ip, arp_entry=None):
            """
            Scans a specific host to check if it is alive and retrieves its hostname and MAC address.
            """
            if self.outer_instance.blacklistcheck and ip in self.outer_instance.ip_scan_blacklist:
                return
            try:
                hostname = ""
                mac = None

                if arp_entry:
                    mac = arp_entry.get("mac")

                if self.use_nmap_results:
                    try:
                        hostname = self.outer_instance.nm[ip].hostname() or ''
                        if not mac:
                            mac = self.outer_instance.nm[ip]['addresses'].get('mac')
                    except Exception as e:
                        self.outer_instance.logger.debug(f"No nmap data for {ip}: {e}")

                if not hostname:
                    hostname = self.outer_instance.resolve_hostname(ip)

                if not mac:
                    mac = self.outer_instance.get_mac_address(ip, hostname)

                if not mac:
                    mac = "00:00:00:00:00:00"
                else:
                    mac = mac.lower()

                if not self.outer_instance.blacklistcheck or mac not in self.outer_instance.mac_scan_blacklist:
                    with self.outer_instance.lock:
                        with open(self.csv_scan_file, 'a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([ip, hostname, mac])
                            self.ip_hostname_list.append((ip, hostname, mac))
            except Exception as e:
                self.outer_instance.logger.error(f"Error getting MAC address or writing to file for IP {ip}: {e}")
            self.progress += 1
            time.sleep(0.1)  # Adding a small delay to avoid overwhelming the network

        def get_progress(self):
            """
            Returns the progress of the scanning process.
            """
            total = self.total_ips if self.total_ips else 1
            return (self.progress / total) * 100

        def start(self):
            """
            Starts the network and port scanning process.
            """
            self.scan_network_and_write_to_csv()
            time.sleep(1)
            self.ip_data = self.outer_instance.GetIpFromCsv(self.outer_instance, self.csv_scan_file)
            self.total_ips = len(self.ip_data.ip_list)
            self.open_ports = {ip: [] for ip in self.ip_data.ip_list}
            
            self.logger.info(f"Starting port scan for {self.total_ips} IPs")
            
            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning IPs...", total=len(self.ip_data.ip_list))
                for ip in self.ip_data.ip_list:
                    progress.update(task, advance=1)
                    self.logger.debug(f"Creating PortScanner for {ip}")
                    port_scanner = self.outer_instance.PortScanner(self.outer_instance, ip, self.open_ports, self.portstart, self.portend, self.extra_ports)
                    port_scanner.start()

            self.logger.info(f"Port scanning completed. Total ports found across all hosts: {sum(len(ports) for ports in self.open_ports.values())}")
            self.all_ports = sorted(list(set(port for ports in self.open_ports.values() for port in ports)))
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
                
                alive_df.loc[:, 'Ports'] = alive_df['Ports'].fillna('')
                alive_df.loc[:, 'Port Count'] = alive_df['Ports'].apply(lambda x: len(x.split(';')) if x else 0)
                self.total_open_ports = alive_df['Port Count'].sum()
                
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
        except RuntimeError as e:
            if "cannot schedule new futures after interpreter shutdown" in str(e):
                self.logger.warning(f"Network scan interrupted by interpreter shutdown (watchdog restart): {e}")
            else:
                import traceback
                self.logger.error(f"Runtime error in scan: {e}\n{traceback.format_exc()}")
        except Exception as e:
            import traceback
            self.logger.error(f"Error in scan: {e}\n{traceback.format_exc()}")

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
