# scanning.py
# This script performs a network scan to identify live hosts, their MAC addresses, and open ports.
# The results are saved to CSV files and displayed using Rich for enhanced visualization.

import os
import threading
import csv
import pandas as pd
import socket
import netifaces
import time
import glob
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import Progress
from getmac import get_mac_address as gma
from shared import SharedData
from logger import Logger
import ipaddress
import nmap

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
        # Limit concurrent port-scan threads reasonably
        self.semaphore = threading.Semaphore(50)
        self.nm = nmap.PortScanner()
        self.running = False

    def check_if_csv_scan_file_exists(self, csv_scan_file, csv_result_file, netkbfile):
        """
        Checks and prepares the necessary CSV files for the scan.
        """
        with self.lock:
            try:
                scan_dir = os.path.dirname(csv_scan_file)
                netkb_dir = os.path.dirname(netkbfile)
                if scan_dir and not os.path.exists(scan_dir):
                    os.makedirs(scan_dir, exist_ok=True)
                if netkb_dir and not os.path.exists(netkb_dir):
                    os.makedirs(netkb_dir, exist_ok=True)
                if os.path.exists(csv_scan_file):
                    os.remove(csv_scan_file)
                if os.path.exists(csv_result_file):
                    os.remove(csv_result_file)
                # Ensure netkbfile exists with default headers
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
        except Exception as e:
            self.logger.error(f"Error in ip_key: {e}")
            return (0, 0, 0, 0)

    def sort_and_write_csv(self, csv_scan_file):
        """
        Sorts the CSV file based on IP addresses and writes the sorted content back to the file.
        """
        with self.lock:
            try:
                if not os.path.exists(csv_scan_file):
                    return
                with open(csv_scan_file, 'r') as file:
                    lines = file.readlines()
                if not lines:
                    return
                header = lines[0]
                body = lines[1:]
                sorted_body = sorted(body, key=lambda x: self.ip_key(x.split(',')[0].strip()))
                with open(csv_scan_file, 'w') as file:
                    file.write(header)
                    file.writelines(sorted_body)
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
                    if not os.path.exists(self.csv_scan_file):
                        return
                    with open(self.csv_scan_file, 'r') as csv_scan_file:
                        csv_reader = csv.reader(csv_scan_file)
                        try:
                            next(csv_reader)
                        except StopIteration:
                            return
                        for row in csv_reader:
                            if not row or len(row) < 3:
                                continue
                            ip, hostname, mac = row[0].strip(), row[1].strip(), row[2].strip()
                            if ip == "STANDALONE" or hostname == "STANDALONE" or mac == "STANDALONE":
                                continue
                            if not self.outer_instance.blacklistcheck or (mac not in self.outer_instance.mac_scan_blacklist and ip not in self.outer_instance.ip_scan_blacklist):
                                self.ip_list.append(ip)
                                self.hostname_list.append(hostname)
                                self.mac_list.append(mac)
                except Exception as e:
                    self.outer_instance.logger.error(f"Error in get_ip_from_csv: {e}")

    def update_netkb(self, netkbfile, netkb_data, alive_macs):
        """
        Updates the net knowledge base (netkb) file with the scan results.
        """
        with self.lock:
            try:
                netkb_entries = {}
                # Default headers in case the file is missing or malformed
                existing_headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports", "Failed_Pings"]
                existing_action_columns = []

                # Read existing CSV file
                if os.path.exists(netkbfile):
                    with open(netkbfile, 'r', newline='') as file:
                        reader = csv.DictReader(file)
                        file_headers = reader.fieldnames or []
                        # Merge any additional headers beyond defaults
                        for h in file_headers:
                            if h and h not in existing_headers:
                                existing_headers.append(h)
                        existing_action_columns = [header for header in existing_headers if header not in ["MAC Address", "IPs", "Hostnames", "Alive", "Ports", "Failed_Pings"]]
                        for row in reader:
                            mac = row.get("MAC Address", "").strip()
                            if not mac:
                                continue
                            ips = row.get("IPs", "").split(';') if row.get("IPs") else []
                            hostnames = row.get("Hostnames", "").split(';') if row.get("Hostnames") else []
                            alive = row.get("Alive", "0")
                            ports = row.get("Ports", "").split(';') if row.get("Ports") else []
                            failed_pings = int(row.get("Failed_Pings", "0")) if row.get("Failed_Pings", "").isdigit() else 0
                            netkb_entries[mac] = {
                                'IPs': set([p for p in ips if p]),
                                'Hostnames': set([h for h in hostnames if h]),
                                'Alive': alive,
                                'Ports': set([p for p in ports if p]),
                                'Failed_Pings': failed_pings
                            }
                            for action in existing_action_columns:
                                netkb_entries[mac][action] = row.get(action, "")

                ip_to_mac = {}

                for data in netkb_data:
                    mac, ip, hostname, ports = data
                    if not mac or mac == "STANDALONE" or ip == "STANDALONE" or hostname == "STANDALONE":
                        continue

                    # For hosts with unknown MAC (00:00:00:00:00:00), convert to pseudo-MAC
                    if mac == "00:00:00:00:00:00":
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4 and all(p.isdigit() for p in ip_parts):
                            pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                        else:
                            pseudo_mac = f"00:00:unknown:{ip.replace('.', ':')}"
                        self.logger.debug(f"Created pseudo-MAC {pseudo_mac} for IP {ip} (MAC unavailable)")
                        mac = pseudo_mac

                    if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                        continue

                    # Check if IP is associated with another MAC (IP reassigned)
                    if ip in ip_to_mac and ip_to_mac[ip] != mac:
                        old_mac = ip_to_mac[ip]
                        if old_mac in netkb_entries:
                            netkb_entries[old_mac]['Failed_Pings'] = netkb_entries[old_mac].get('Failed_Pings', 0) + 1
                            # Keep Alive logic: do not immediately mark offline; rely on Failed_Pings threshold (kept simple here)
                            if netkb_entries[old_mac]['Failed_Pings'] >= self.shared_data.config.get('network_max_failed_pings', 15):
                                netkb_entries[old_mac]['Alive'] = '0'
                            else:
                                netkb_entries[old_mac]['Alive'] = '1'

                    ip_to_mac[ip] = mac
                    if mac in netkb_entries:
                        netkb_entries[mac]['IPs'].add(ip)
                        netkb_entries[mac]['Hostnames'].add(hostname)
                        netkb_entries[mac]['Alive'] = '1'
                        netkb_entries[mac]['Ports'].update(map(str, ports))
                        netkb_entries[mac]['Failed_Pings'] = 0
                    else:
                        netkb_entries[mac] = {
                            'IPs': {ip},
                            'Hostnames': {hostname},
                            'Alive': '1',
                            'Ports': set(map(str, ports)),
                            'Failed_Pings': 0
                        }
                        for action in existing_action_columns:
                            netkb_entries[mac][action] = ""

                # Increment failed_pings for entries not seen this scan
                max_failed_pings = self.shared_data.config.get('network_max_failed_pings', 15)
                for mac, data in list(netkb_entries.items()):
                    if mac not in alive_macs:
                        current_failures = data.get('Failed_Pings', 0) + 1
                        netkb_entries[mac]['Failed_Pings'] = current_failures
                        if current_failures >= max_failed_pings:
                            netkb_entries[mac]['Alive'] = '0'
                            self.logger.info(f"Host {mac} marked offline after {current_failures} consecutive failed pings")
                        else:
                            netkb_entries[mac]['Alive'] = '1'

                # Remove entries with multiple IP addresses for a single MAC (keep single-IP mapping)
                netkb_entries = {mac: data for mac, data in netkb_entries.items() if len(data['IPs']) == 1}

                sorted_netkb_entries = sorted(netkb_entries.items(), key=lambda x: self.ip_key(sorted(x[1]['IPs'])[0]))

                # Ensure Failed_Pings header exists
                if "Failed_Pings" not in existing_headers:
                    if "Ports" in existing_headers:
                        idx = existing_headers.index("Ports")
                        existing_headers.insert(idx + 1, "Failed_Pings")
                    else:
                        existing_headers.append("Failed_Pings")
                    existing_action_columns = [header for header in existing_headers if header not in ["MAC Address", "IPs", "Hostnames", "Alive", "Ports", "Failed_Pings"]]

                with open(netkbfile, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(existing_headers)
                    for mac, data in sorted_netkb_entries:
                        # Safe port list: only digit strings
                        port_list = [p for p in map(str, data.get('Ports', [])) if p.isdigit()]
                        port_list_sorted = sorted(port_list, key=lambda x: int(x))
                        row = [
                            mac,
                            ';'.join(sorted(data['IPs'], key=self.ip_key)),
                            ';'.join(sorted(data['Hostnames'])),
                            data.get('Alive', '0'),
                            ';'.join(port_list_sorted),
                            str(data.get('Failed_Pings', 0))
                        ]
                        # Append any extra action columns (if any)
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
                if not os.path.exists(file_path):
                    self.logger.warning(f"File not found for display: {file_path}")
                    return
                table = Table(title=f"Contents of {file_path}", show_lines=True)
                with open(file_path, 'r') as file:
                    reader = csv.reader(file)
                    try:
                        headers = next(reader)
                    except StopIteration:
                        return
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
            # fallback
            network = ipaddress.IPv4Network("192.168.1.0/24", strict=False)
            return network

    def get_mac_address(self, ip, hostname):
        """
        Retrieves the MAC address for the given IP address and hostname.
        """
        try:
            mac = None
            retries = 5
            while not mac and retries > 0:
                try:
                    mac = gma(ip=ip)
                except Exception:
                    mac = None
                if not mac:
                    time.sleep(1)
                    retries -= 1
            if not mac:
                # return a deterministic pseudo mac so the same host maps to same identity in subsequent runs
                pseudo = f"{ip.replace('.', ':')}"
                mac = f"00:00:{pseudo}"
            mac = mac.lower()
            return mac
        except Exception as e:
            self.logger.error(f"Error in get_mac_address: {e}")
            return f"00:00:{ip.replace('.', ':')}"

    class PortScanner:
        """
        Helper class to perform port scanning on a target IP.
        """
        def __init__(self, outer_instance, target, open_ports, portstart, portend, extra_ports):
            self.outer_instance = outer_instance
            self.logger = logger
            self.target = target
            self.open_ports = open_ports
            self.portstart = portstart
            self.portend = portend
            self.extra_ports = extra_ports or []

        def scan_port(self, port):
            """
            Scans a specific port on the target IP using connect_ex for non-exception flow.
            """
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                ret = sock.connect_ex((self.target, port))
                if ret == 0:
                    # success -> open port
                    self.open_ports.setdefault(self.target, []).append(port)
                    self.logger.info(f"🔓 Port {port} open on {self.target}")
            except Exception as e:
                self.logger.debug(f"Port scan error {self.target}:{port} -> {e}")
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass

        def scan_with_semaphore(self, port):
            """
            Scans a port using a semaphore to limit concurrent threads.
            """
            with self.outer_instance.semaphore:
                self.scan_port(port)

        def start(self):
            """
            Starts the port scanning process for the specified range and extra ports.
            Spawns threads and joins them to ensure completion before returning.
            """
            threads = []
            try:
                # inclusive range
                for port in range(self.portstart, self.portend + 1):
                    t = threading.Thread(target=self.scan_with_semaphore, args=(port,))
                    t.daemon = True
                    t.start()
                    threads.append(t)
                for port in self.extra_ports:
                    try:
                        p = int(port)
                    except Exception:
                        continue
                    t = threading.Thread(target=self.scan_with_semaphore, args=(p,))
                    t.daemon = True
                    t.start()
                    threads.append(t)
            except Exception as e:
                self.logger.error(f"Error spawning port threads: {e}")

            # Wait for all threads to finish
            for t in threads:
                t.join(timeout=10)

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
            self.extra_ports = extra_ports or []
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

            # Use nmap -sn to detect hosts
            try:
                self.outer_instance.nm.scan(hosts=str(self.network), arguments='-sn')
            except Exception as e:
                self.outer_instance.logger.error(f"nmap host discovery failed: {e}")
                return

            host_threads = []
            for host in self.outer_instance.nm.all_hosts():
                t = threading.Thread(target=self.scan_host, args=(host,))
                t.daemon = True
                t.start()
                host_threads.append(t)

            # Wait for host scanning threads to finish (bounded wait)
            for t in host_threads:
                t.join(timeout=10)

            # Sort CSV file once hosts are written
            time.sleep(0.5)
            self.outer_instance.sort_and_write_csv(self.csv_scan_file)

        def scan_host(self, ip):
            """
            Scans a specific host to check if it is alive and retrieves its hostname and MAC address.
            """
            if self.outer_instance.blacklistcheck and ip in self.outer_instance.ip_scan_blacklist:
                return
            try:
                hostname = ''
                try:
                    nm_entry = self.outer_instance.nm[ip]
                    hostname = nm_entry.hostname() if hasattr(nm_entry, 'hostname') else ''
                    if not hostname:
                        # nmap may not provide hostname; fallback to reverse DNS
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            hostname = f"host-{ip.replace('.', '-')}"
                except Exception:
                    # safe fallback: try reverse DNS
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = f"host-{ip.replace('.', '-')}"

                mac = self.outer_instance.get_mac_address(ip, hostname)
                if not mac:
                    mac = "00:00:00:00:00:00"
                mac = mac.lower()

                if not (self.outer_instance.blacklistcheck and mac in self.outer_instance.mac_scan_blacklist):
                    with self.outer_instance.lock:
                        with open(self.csv_scan_file, 'a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([ip, hostname, mac])
                            self.ip_hostname_list.append((ip, hostname, mac))
            except Exception as e:
                self.outer_instance.logger.error(f"Error getting MAC address or writing to file for IP {ip}: {e}")
            finally:
                self.progress += 1
                time.sleep(0.05)

        def start(self):
            """
            Starts the network and port scanning process.
            """
            self.scan_network_and_write_to_csv()
            # Allow a small pause for file flush
            time.sleep(0.5)
            self.ip_data = self.outer_instance.GetIpFromCsv(self.outer_instance, self.csv_scan_file)
            # Prepare data structures for port scanning
            self.open_ports = {ip: [] for ip in self.ip_data.ip_list}

            # Port-scan each IP sequentially (per-host port threads are joined inside PortScanner.start)
            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning IPs...", total=len(self.ip_data.ip_list))
                for ip in self.ip_data.ip_list:
                    progress.update(task, advance=1)
                    self.logger.debug(f"Starting port scan for {ip}")
                    pscanner = self.outer_instance.PortScanner(self.outer_instance, ip, self.open_ports, self.portstart, self.portend, self.extra_ports)
                    pscanner.start()

            self.all_ports = sorted(list({p for ports in self.open_ports.values() for p in ports}))
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
            # initialize defaults
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
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                if os.path.getsize(self.source_csv_path) == 0:
                    self.logger.warning(f"Source CSV file is empty: {self.source_csv_path}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                try:
                    self.df = pd.read_csv(self.source_csv_path)
                except pd.errors.EmptyDataError:
                    self.logger.warning(f"Source CSV file has no data to parse: {self.source_csv_path}")
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                if self.df.empty:
                    self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])
                    return
                # ensure required columns
                for col in ['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive']:
                    if col not in self.df.columns:
                        self.df[col] = '' if col != 'Alive' else '0'
                self.logger.debug(f"Successfully read {len(self.df)} rows from {self.source_csv_path}")
            except Exception as e:
                self.logger.error(f"Error in read_csv: {e}")
                self.df = pd.DataFrame(columns=['MAC Address', 'IPs', 'Hostnames', 'Ports', 'Alive'])

        def calculate_open_ports(self):
            """
            Calculates the total number of open ports for alive hosts.
            """
            try:
                self.total_open_ports = 0
                if self.df.empty or 'Alive' not in self.df.columns or 'Ports' not in self.df.columns:
                    self.logger.warning("DataFrame is empty or missing required columns for port calculation")
                    return
                alive_mask = self.df['Alive'].astype(str).str.strip() == '1'
                alive_df = self.df[alive_mask].copy()
                if alive_df.empty:
                    return
                alive_df.loc[:, 'Ports'] = alive_df['Ports'].fillna('')
                alive_df.loc[:, 'Port Count'] = alive_df['Ports'].apply(lambda x: len([p for p in str(x).split(';') if p]))
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
                self.all_known_hosts_count = 0
                self.alive_hosts_count = 0
                if self.df.empty or 'MAC Address' not in self.df.columns or 'Alive' not in self.df.columns:
                    self.logger.warning("DataFrame is empty or missing required columns for host count calculation")
                    return
                self.all_known_hosts_count = self.df[self.df['MAC Address'] != 'STANDALONE'].shape[0]
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
                if not os.path.exists(os.path.dirname(self.output_csv_path) or ""):
                    os.makedirs(os.path.dirname(self.output_csv_path) or "", exist_ok=True)
                if os.path.exists(self.output_csv_path):
                    try:
                        results_df = pd.read_csv(self.output_csv_path)
                    except Exception:
                        results_df = pd.DataFrame(columns=['Total Open Ports', 'Alive Hosts Count', 'All Known Hosts Count'])
                    if results_df.empty:
                        results_df = pd.DataFrame({
                            'Total Open Ports': [self.total_open_ports],
                            'Alive Hosts Count': [self.alive_hosts_count],
                            'All Known Hosts Count': [self.all_known_hosts_count]
                        })
                    else:
                        if len(results_df.index) == 0:
                            results_df.loc[0] = [self.total_open_ports, self.alive_hosts_count, self.all_known_hosts_count]
                        else:
                            results_df.loc[0, 'Total Open Ports'] = self.total_open_ports
                            results_df.loc[0, 'Alive Hosts Count'] = self.alive_hosts_count
                            results_df.loc[0, 'All Known Hosts Count'] = self.all_known_hosts_count
                    results_df.to_csv(self.output_csv_path, index=False)
                else:
                    results_df = pd.DataFrame({
                        'Total Open Ports': [self.total_open_ports],
                        'Alive Hosts Count': [self.alive_hosts_count],
                        'All Known Hosts Count': [self.all_known_hosts_count]
                    })
                    results_df.to_csv(self.output_csv_path, index=False)
                self.logger.debug(f"Successfully saved results to {self.output_csv_path}")
            except Exception as e:
                self.logger.error(f"Error in save_results: {e}")
                # fallback minimal file
                try:
                    fallback_df = pd.DataFrame({
                        'Total Open Ports': [getattr(self, 'total_open_ports', 0)],
                        'Alive Hosts Count': [getattr(self, 'alive_hosts_count', 0)],
                        'All Known Hosts Count': [getattr(self, 'all_known_hosts_count', 0)]
                    })
                    fallback_df.to_csv(self.output_csv_path, index=False)
                    self.logger.info(f"Created fallback results file: {self.output_csv_path}")
                except Exception as fe:
                    self.logger.error(f"Failed to create fallback results file: {fe}")

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
                files = glob.glob(os.path.join(scan_results_dir, '*'))
                files.sort(key=os.path.getmtime)
                for file in files[:-20]:
                    try:
                        os.remove(file)
                    except Exception:
                        pass
                self.logger.info("Scan results cleaned up")
            except Exception as e:
                self.logger.error(f"Error in clean_scan_results: {e}")

    def scan(self):
        """
        Initiates the network scan, updates the netkb file, and displays the results.
        """
        try:
            self.shared_data.bjornorch_status = "NetworkScanner"
            self.logger.info("Starting Network Scanner")
            network = self.get_network()
            self.shared_data.bjornstatustext2 = str(network)
            portstart = self.shared_data.portstart
            portend = self.shared_data.portend
            extra_ports = self.shared_data.portlist
            scanner = self.ScanPorts(self, network, portstart, portend, extra_ports)
            ip_data, open_ports, all_ports, csv_result_file, netkbfile, alive_ips = scanner.start()

            # Create alive_macs with pseudo-MAC handling for 00:00:00:00:00:00
            alive_macs = set()
            for i, mac in enumerate(ip_data.mac_list):
                ip = ip_data.ip_list[i] if i < len(ip_data.ip_list) else None
                if mac == "00:00:00:00:00:00" and ip:
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4 and all(p.isdigit() for p in ip_parts):
                        pseudo_mac = f"00:00:{int(ip_parts[0]):02x}:{int(ip_parts[1]):02x}:{int(ip_parts[2]):02x}:{int(ip_parts[3]):02x}"
                    else:
                        pseudo_mac = f"00:00:{ip.replace('.', ':')}"
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

            # Write human-readable per-scan results CSV
            with self.lock:
                with open(csv_result_file, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["IP", "Hostname", "Alive", "MAC Address"] + [str(port) for port in all_ports])
                    for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                        if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                            continue
                        alive = '1' if mac in alive_macs else '0'
                        writer.writerow([ip, hostname, alive, mac] + [str(port) if port in ports else '' for port in all_ports])

            # Update the net knowledge base
            self.update_netkb(netkbfile, netkb_data, alive_macs)

            if self.displaying_csv:
                self.display_csv(csv_result_file)

            source_csv_path = self.shared_data.netkbfile
            output_csv_path = self.shared_data.livestatusfile

            updater = self.LiveStatusUpdater(source_csv_path, output_csv_path)
            updater.update_livestatus()
            updater.clean_scan_results(self.shared_data.scan_results_dir)
        except Exception as e:
            self.logger.error(f"Error in scan: {e}", exc_info=True)

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
