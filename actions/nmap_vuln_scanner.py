# nmap_vuln_scanner.py
# This script performs vulnerability scanning using Nmap on specified IP addresses.
# It scans for vulnerabilities on various ports and saves the results and progress.

import os
import re
import pandas as pd
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from shared import SharedData
from logger import Logger
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nmap_logger import nmap_logger

logger = Logger(name="nmap_vuln_scanner.py", level=logging.INFO)

b_class = "NmapVulnScanner"
b_module = "nmap_vuln_scanner"
b_status = "vuln_scan"
b_port = None
b_parent = None

class NmapVulnScanner:
    """
    This class handles the Nmap vulnerability scanning process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan_results = []
        self.summary_file = self.shared_data.vuln_summary_file
        self.create_summary_file()
        logger.debug("NmapVulnScanner initialized.")

    def create_summary_file(self):
        """
        Creates a summary file for vulnerabilities if it does not exist.
        """
        if not os.path.exists(self.summary_file):
            os.makedirs(self.shared_data.vulnerabilities_dir, exist_ok=True)
            df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
            df.to_csv(self.summary_file, index=False)

    def update_summary_file(self, ip, hostname, mac, port, vulnerabilities):
        """
        Updates the summary file with the scan results.
        """
        try:
            # Read existing data
            df = pd.read_csv(self.summary_file)
            
            # Create new data entry
            new_data = pd.DataFrame([{"IP": ip, "Hostname": hostname, "MAC Address": mac, "Port": port, "Vulnerabilities": vulnerabilities}])
            
            # Append new data
            df = pd.concat([df, new_data], ignore_index=True)
            
            # Remove duplicates based on IP and MAC Address, keeping the last occurrence
            df.drop_duplicates(subset=["IP", "MAC Address"], keep='last', inplace=True)
            
            # Save the updated data back to the summary file
            df.to_csv(self.summary_file, index=False)
        except Exception as e:
            logger.error(f"Error updating summary file: {e}")


    def scan_vulnerabilities(self, ip, hostname, mac, ports):
        combined_result = ""
        success = True  # Initialize to True, will become False if an error occurs
        try:
            self.shared_data.bjornstatustext2 = ip

            ports_to_scan = self.prepare_port_list(ports)
            if not ports_to_scan:
                logger.warning(f"No valid ports supplied for {ip}. Falling back to default vulnerability ports.")
                ports_to_scan = self.get_default_vulnerability_ports()

            logger.info(
                f"Scanning {ip} on ports {','.join(ports_to_scan)} for vulnerabilities with aggressivity {self.shared_data.nmap_scan_aggressivity}"
            )
            
            # Prepare nmap command
            nmap_command = [
                "nmap",
                self.shared_data.nmap_scan_aggressivity,
                "-sV",
                "--script",
                "vulners.nse",
                "-p",
                ",".join(ports_to_scan),
                ip,
            ]
            
            # Execute nmap command with logging
            result = nmap_logger.run_nmap_command(
                nmap_command,
                context=f"Vulnerability scan for {ip}",
                capture_output=True,
                text=True,
            )
            combined_result += result.stdout

            if result.returncode != 0:
                logger.warning(
                    f"nmap returned a non-zero exit code while scanning {ip}: {result.stderr.strip()}"
                )

            vulnerability_summary, port_vulnerabilities, port_services = self.parse_vulnerabilities(result.stdout)
            
            # Log parsing results for debugging
            logger.info(f"Parsed {len(port_vulnerabilities)} ports with vulnerabilities for {ip}")
            for port, vulns in port_vulnerabilities.items():
                logger.debug(f"Port {port}: {len(vulns)} vulnerabilities found")
            
            if not port_vulnerabilities or all(len(v) == 0 for v in port_vulnerabilities.values()):
                logger.warning(f"No vulnerabilities detected in scan output for {ip}")
            
            self.update_summary_file(ip, hostname, mac, ",".join(ports_to_scan), vulnerability_summary)
            self.update_netkb_vulnerabilities(mac, ip, port_vulnerabilities, port_services)

            # Feed vulnerabilities into network intelligence system
            self.feed_to_network_intelligence(ip, port_vulnerabilities, port_services)

        except Exception as e:
            logger.error(f"Error scanning {ip}: {e}")
            success = False  # Mark as failed if an error occurs

        return combined_result if success else None

    def execute(self, ip, row, status_key):
        """
        Executes the vulnerability scan for a given IP and row data.
        """
        self.shared_data.ragnarorch_status = "NmapVulnScanner"
        ports = row.get("Ports", "")
        scan_result = self.scan_vulnerabilities(ip, row["Hostnames"], row["MAC Address"], ports)

        if scan_result is not None:
            self.scan_results.append((ip, row["Hostnames"], row["MAC Address"]))
            self.save_results(row["MAC Address"], ip, scan_result)
            return 'success'
        else:
            return 'success' # considering failed as success as we just need to scan vulnerabilities once
            # return 'failed'

    def prepare_port_list(self, ports) -> List[str]:
        """Normalize port values from the NetKB row"""
        if isinstance(ports, (list, tuple, set)):
            raw_ports = list(ports)
        elif isinstance(ports, str):
            raw_ports = []
            for separator in [';', ',']:
                if separator in ports:
                    raw_ports = ports.split(separator)
                    break
            if not raw_ports:
                raw_ports = [ports]
        elif ports is None:
            raw_ports = []
        else:
            raw_ports = [str(ports)]

        normalized_ports: Set[str] = set()
        for port in raw_ports:
            if port is None:
                continue
            port = str(port).strip()
            if not port:
                continue
            if '-' in port:
                start, end = port.split('-', 1)
                if start.isdigit() and end.isdigit():
                    start_port, end_port = int(start), int(end)
                    if start_port <= end_port:
                        for value in range(start_port, end_port + 1):
                            normalized_ports.add(str(value))
                    continue
            if port.isdigit():
                normalized_ports.add(port)

        return sorted(normalized_ports, key=lambda x: int(x))

    def get_default_vulnerability_ports(self) -> List[str]:
        """Return default ports to scan when none are supplied"""
        default_ports = self.shared_data.config.get("default_vulnerability_ports")
        if isinstance(default_ports, (list, tuple, set)) and default_ports:
            valid_ports = [str(port) for port in default_ports if str(port).isdigit()]
            if valid_ports:
                return sorted(set(valid_ports), key=int)
        return ["22", "80", "443"]

    def parse_vulnerabilities(self, scan_result):
        """
        Parses the Nmap scan result to extract vulnerabilities per port and service.
        Returns a summary string, a mapping of ports to vulnerabilities, and detected services.
        """
        port_vulnerabilities: Dict[str, List[str]] = {}
        port_services: Dict[str, str] = {}
        summary_entries: Set[str] = set()

        current_port: Optional[str] = None
        current_service: str = "unknown"
        in_vulners_section = False

        for raw_line in scan_result.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Detect port lines (e.g., "22/tcp  open   ssh     OpenSSH 9.2p1")
            if "/tcp" in line and any(state in line for state in ["open", "closed", "filtered"]):
                parts = line.split()
                if parts:
                    port_info = parts[0]
                    current_port = port_info.split('/')[0]
                    # Extract service information (usually at index 2 or later)
                    if len(parts) >= 3:
                        current_service = parts[2]
                    elif len(parts) >= 2:
                        current_service = parts[1]
                    else:
                        current_service = "unknown"
                    port_services[current_port] = current_service
                    port_vulnerabilities.setdefault(current_port, [])
                    in_vulners_section = False
                continue

            if current_port is None:
                continue

            # Detect the start of vulners output section
            if line.startswith('|') and 'vulners:' in line.lower():
                in_vulners_section = True
                continue

            # Parse vulnerability lines (lines starting with |)
            if line.startswith('|'):
                cleaned_line = line.lstrip('|').strip()
                
                # Skip empty lines and section headers
                if not cleaned_line:
                    continue
                
                # Look for vulnerability indicators
                if any(keyword in cleaned_line for keyword in ("CVE-", "VULNERABLE", "*EXPLOIT*", 
                                                                "PACKETSTORM:", "cpe:/", "SNYK:",
                                                                "1337DAY-ID-", "SSV:", "CNVD-")):
                    port_vulnerabilities.setdefault(current_port, []).append(cleaned_line)
                    summary_entries.add(f"{current_port}/{current_service}: {cleaned_line}")
                    continue
                
                # Also capture lines with vulnerability scores (numeric patterns)
                score_pattern = re.search(r'\s+(\d+\.\d+|\d+)\s+https?://', cleaned_line)
                if score_pattern and in_vulners_section:
                    port_vulnerabilities.setdefault(current_port, []).append(cleaned_line)
                    summary_entries.add(f"{current_port}/{current_service}: {cleaned_line}")

        summary = "; ".join(sorted(summary_entries))
        return summary, port_vulnerabilities, port_services

    def determine_severity(self, vulnerability_text: str) -> Tuple[str, str]:
        """Determine severity and normalized description from vulnerability text"""
        normalized_text = vulnerability_text
        severity = "medium"

        cve_match = re.search(r"(CVE-\d{4}-\d+)", vulnerability_text)
        score_match = re.search(r"(\d+\.\d+|\d+)", vulnerability_text)

        if cve_match:
            normalized_text = cve_match.group(1)
            if score_match:
                normalized_text = f"{normalized_text} (Score: {score_match.group(1)})"
                try:
                    score_value = float(score_match.group(1))
                    if score_value >= 9.0:
                        severity = "critical"
                    elif score_value >= 7.0:
                        severity = "high"
                    elif score_value >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                except ValueError:
                    severity = "medium"
        elif "*EXPLOIT*" in vulnerability_text.upper():
            severity = "high"
        elif "VULNERABLE" in vulnerability_text.upper():
            severity = "medium"

        return severity, normalized_text

    def feed_to_network_intelligence(self, ip, port_vulnerabilities, port_services):
        """
        Feed vulnerability scan results to the network intelligence system
        """
        try:
            # Check if network intelligence is available
            if not hasattr(self.shared_data, 'network_intelligence') or not self.shared_data.network_intelligence:
                logger.debug("Network intelligence not available, skipping vulnerability feed")
                return
            
            for port_str, vulnerabilities in port_vulnerabilities.items():
                if not vulnerabilities:
                    continue

                service = port_services.get(port_str, "unknown")

                for vulnerability in vulnerabilities:
                    severity, normalized_text = self.determine_severity(vulnerability)

                    try:
                        self.shared_data.network_intelligence.add_vulnerability(
                            host=ip,
                            port=int(port_str),
                            service=service or "unknown",
                            vulnerability=normalized_text,
                            severity=severity,
                            details={
                                'raw_output': vulnerability,
                                'service': service or "unknown",
                                'port': int(port_str),
                            }
                        )
                        logger.debug(f"Added vulnerability to network intelligence: {ip}:{port_str} - {normalized_text}")
                    except Exception as e:
                        logger.warning(f"Failed to add vulnerability to network intelligence: {e}")

        except Exception as e:
            logger.error(f"Error feeding vulnerabilities to network intelligence: {e}")

    def update_netkb_vulnerabilities(self, mac, ip, port_vulnerabilities, port_services):
        """Persist vulnerability information back into the NetKB for UI consumption"""
        try:
            netkb_path = self.shared_data.netkbfile
            if not os.path.exists(netkb_path):
                return

            df = pd.read_csv(netkb_path)
            if df.empty or 'MAC Address' not in df.columns:
                return

            if 'Nmap Vulnerabilities' not in df.columns:
                df['Nmap Vulnerabilities'] = ''

            vulnerability_entries: List[str] = []
            for port_str, vulnerabilities in port_vulnerabilities.items():
                service = port_services.get(port_str, "unknown")
                for vulnerability in vulnerabilities:
                    _, normalized_text = self.determine_severity(vulnerability)
                    vulnerability_entries.append(f"{port_str}/{service}: {normalized_text}")

            if not vulnerability_entries:
                return

            summary_text = "; ".join(sorted(set(vulnerability_entries)))

            mask = df['MAC Address'] == mac
            if not mask.any() and 'IPs' in df.columns:
                mask = df['IPs'].astype(str) == str(ip)

            if not mask.any():
                return

            df.loc[mask, 'Nmap Vulnerabilities'] = summary_text

            if 'Ports' in df.columns:
                def merge_ports(existing_value):
                    existing_ports = set()
                    if isinstance(existing_value, str) and existing_value.strip():
                        existing_ports.update(part for part in existing_value.split(';') if part)
                    merged = existing_ports.union(port_vulnerabilities.keys())
                    if not merged:
                        return existing_value
                    return ';'.join(sorted({str(port) for port in merged}, key=int))

                df.loc[mask, 'Ports'] = df.loc[mask, 'Ports'].apply(merge_ports)

            df.to_csv(netkb_path, index=False)

        except Exception as e:
            logger.error(f"Error updating NetKB with vulnerabilities for {ip}: {e}")

    def save_results(self, mac_address, ip, scan_result):
        """
        Saves the detailed scan results to a file.
        """
        try:
            sanitized_mac_address = mac_address.replace(":", "")
            result_dir = self.shared_data.vulnerabilities_dir
            os.makedirs(result_dir, exist_ok=True)
            result_file = os.path.join(result_dir, f"{sanitized_mac_address}_{ip}_vuln_scan.txt")
            
            # Open the file in write mode to clear its contents if it exists, then close it
            if os.path.exists(result_file):
                open(result_file, 'w').close()
            
            # Write the new scan result to the file
            with open(result_file, 'w') as file:
                file.write(scan_result)
            
            logger.info(f"Results saved to {result_file}")
        except Exception as e:
            logger.error(f"Error saving scan results for {ip}: {e}")


    def save_summary(self):
        """
        Saves a summary of all scanned vulnerabilities to a final summary file.
        """
        try:
            final_summary_file = os.path.join(self.shared_data.vulnerabilities_dir, "final_vulnerability_summary.csv")
            df = pd.read_csv(self.summary_file)
            summary_data = df.groupby(["IP", "Hostname", "MAC Address"])["Vulnerabilities"].apply(lambda x: "; ".join(set("; ".join(x).split("; ")))).reset_index()
            summary_data.to_csv(final_summary_file, index=False)
            logger.info(f"Summary saved to {final_summary_file}")
        except Exception as e:
            logger.error(f"Error saving summary: {e}")

    def force_scan_all_hosts(self, real_time_callback=None):
        """
        Force scan all alive hosts in the NetKB regardless of previous scan status.
        This bypasses the retry delays and previous scan status checks.
        
        Args:
            real_time_callback: Optional callback function for real-time updates
        """
        try:
            # Read current network data
            current_data = self.shared_data.read_data()
            if not current_data:
                logger.warning("No network data available for vulnerability scanning")
                if real_time_callback:
                    real_time_callback("error", {"message": "No network data available"})
                return 0
            
            scanned_count = 0
            alive_hosts = [row for row in current_data if row.get("Alive") == '1']
            
            logger.info(f"Force scanning {len(alive_hosts)} alive hosts for vulnerabilities...")
            nmap_logger.log_scan_operation(f"Force vulnerability scan", f"Scanning {len(alive_hosts)} hosts")
            
            # Send initial progress update
            if real_time_callback:
                real_time_callback("scan_started", {
                    "total_hosts": len(alive_hosts),
                    "scanned": 0,
                    "current_ip": None
                })
            
            for i, row in enumerate(alive_hosts):
                ip = row.get("IPs", "")
                if not ip:
                    continue
                    
                try:
                    # Send progress update
                    if real_time_callback:
                        real_time_callback("scan_progress", {
                            "total_hosts": len(alive_hosts),
                            "scanned": i,
                            "current_ip": ip,
                            "current_host": row.get("Hostnames", ""),
                            "current_mac": row.get("MAC Address", ""),
                            "progress_percent": int((i / len(alive_hosts)) * 100)
                        })
                    
                    logger.info(f"Scanning {ip} ({i+1}/{len(alive_hosts)}) for vulnerabilities...")
                    result = self.execute(ip, row, "NmapVulnScanner")
                    
                    if result == 'success':
                        scanned_count += 1
                        # Update the status to force a fresh timestamp
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        row["NmapVulnScanner"] = f'success_{timestamp}'
                        
                        # Send real-time update with scan results
                        if real_time_callback:
                            self._send_host_update(real_time_callback, ip, row, "success")
                            
                    else:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        row["NmapVulnScanner"] = f'failed_{timestamp}'
                        
                        # Send real-time update for failed scan
                        if real_time_callback:
                            self._send_host_update(real_time_callback, ip, row, "failed")
                    
                    # Save data after each scan to ensure progress is persisted
                    self.shared_data.write_data(current_data)
                        
                except Exception as e:
                    logger.error(f"Error force scanning {ip}: {e}")
                    if real_time_callback:
                        real_time_callback("scan_error", {
                            "ip": ip,
                            "error": str(e)
                        })
            
            # Send completion update
            if real_time_callback:
                real_time_callback("scan_completed", {
                    "total_hosts": len(alive_hosts),
                    "scanned": scanned_count,
                    "success_count": scanned_count
                })
                    
            logger.info(f"Force scan completed. Successfully scanned {scanned_count} hosts.")
            return scanned_count
            
        except Exception as e:
            logger.error(f"Error in force_scan_all_hosts: {e}")
            if real_time_callback:
                real_time_callback("error", {"message": str(e)})
            return 0

    def _send_host_update(self, callback, ip, row, status):
        """Send real-time update for a scanned host"""
        try:
            # Get vulnerability data if available
            vulnerabilities = []
            if hasattr(self.shared_data, 'network_intelligence') and self.shared_data.network_intelligence:
                # Get vulnerabilities from network intelligence
                network_id = self.shared_data.network_intelligence.get_current_network_id()
                if network_id in self.shared_data.network_intelligence.active_vulnerabilities:
                    host_vulns = [v for v in self.shared_data.network_intelligence.active_vulnerabilities[network_id].values() 
                                 if v.get('host') == ip]
                    vulnerabilities = host_vulns
            
            host_data = {
                "ip": ip,
                "hostname": row.get("Hostnames", ""),
                "mac": row.get("MAC Address", ""),
                "ports": row.get("Ports", ""),
                "alive": row.get("Alive", "0"),
                "scan_status": status,
                "vulnerabilities": vulnerabilities,
                "last_scan": datetime.now().isoformat()
            }
            
            callback("host_updated", host_data)
            
        except Exception as e:
            logger.error(f"Error sending host update: {e}")

    def scan_single_host_realtime(self, ip, hostname="", mac="", ports="", callback=None):
        """
        Scan a single host in real-time and send updates via callback
        
        Args:
            ip: IP address to scan
            hostname: Hostname of the target
            mac: MAC address of the target
            ports: Ports to scan (string or list)
            callback: Function to call with real-time updates
        """
        try:
            if callback:
                callback("scan_started", {
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac
                })
            
            # Create a row object for compatibility
            row = {
                "IPs": ip,
                "Hostnames": hostname,
                "MAC Address": mac,
                "Ports": ports,
                "Alive": "1"
            }
            
            # Execute the scan
            result = self.execute(ip, row, "NmapVulnScanner")
            
            # Send completion update
            if callback:
                self._send_host_update(callback, ip, row, result)
                callback("scan_completed", {
                    "ip": ip,
                    "status": result,
                    "timestamp": datetime.now().isoformat()
                })
                
            return result
            
        except Exception as e:
            logger.error(f"Error in single host scan for {ip}: {e}")
            if callback:
                callback("scan_error", {
                    "ip": ip,
                    "error": str(e)
                })
            return "failed"

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        nmap_vuln_scanner = NmapVulnScanner(shared_data)
        logger.info("Starting vulnerability scans...")

        # Load the netkbfile and get the IPs to scan
        ips_to_scan = shared_data.read_data()  # Use your existing method to read the data

        # Execute the scan on each IP with concurrency
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.1f}%",
            console=Console()
        ) as progress:
            task = progress.add_task("Scanning vulnerabilities...", total=len(ips_to_scan))
            futures = []
            with ThreadPoolExecutor(max_workers=2) as executor:  # Adjust the number of workers for RPi Zero
                for row in ips_to_scan:
                    if row["Alive"] == '1':  # Check if the host is alive
                        ip = row["IPs"]
                        futures.append(executor.submit(nmap_vuln_scanner.execute, ip, row, b_status))

                for future in as_completed(futures):
                    progress.update(task, advance=1)

        nmap_vuln_scanner.save_summary()
        logger.info(f"Total scans performed: {len(nmap_vuln_scanner.scan_results)}")
        exit(len(nmap_vuln_scanner.scan_results))
    except Exception as e:
        logger.error(f"Error: {e}")
