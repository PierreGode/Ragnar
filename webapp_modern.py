#webapp_modern.py
"""
Modern Flask-based web application for Ragnar
Features:
- Fast Flask backend with proper routing
- RESTful API endpoints
- WebSocket support for real-time updates
- Static file caching
- Better performance than SimpleHTTPRequestHandler
"""

import os
import sys
import json
import csv
import signal
import logging
import threading
import time
import subprocess
import re
import io
import base64
import shutil
import importlib
import hashlib
import ipaddress
import socket
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, send_from_directory, Response
from flask_socketio import SocketIO, emit
try:
    from flask_cors import CORS
    flask_cors_available = True
except ImportError:
    flask_cors_available = False
try:
    import psutil
    psutil_available = True
except ImportError:
    psutil_available = False
try:
    import pandas as pd
    pandas_available = True
except ImportError:
    pandas_available = False
from init_shared import shared_data
from utils import WebUtils
from logger import Logger
from threat_intelligence import ThreatIntelligenceFusion

# Initialize logger
logger = Logger(name="webapp_modern.py", level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__,
            static_folder='web',
            template_folder='web')
app.config['SECRET_KEY'] = 'ragnar-cyberviking-secret-key'
app.config['JSON_SORT_KEYS'] = False

# Enable CORS
# Set up CORS if available
if flask_cors_available:
    CORS(app)

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize web utilities
web_utils = WebUtils(shared_data, logger)

# Initialize threat intelligence system
try:
    threat_intelligence = ThreatIntelligenceFusion(shared_data)
    logger.info("Threat intelligence system initialized")
except Exception as e:
    logger.error(f"Failed to initialize threat intelligence: {e}")
    threat_intelligence = None

# Global state
clients_connected = 0

# Synchronization helpers for keeping dashboard and e-paper data fresh
sync_lock = threading.Lock()
last_sync_time = 0.0
SYNC_BACKGROUND_INTERVAL = 5  # seconds between automatic synchronizations


DEFAULT_ARP_SCAN_INTERFACE = 'wlan0'
SEP_SCAN_COMMAND = ['sudo', 'sep-scan']
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def _is_valid_ipv4(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_mac(mac):
    return mac.lower() if mac else ''


def _parse_arp_scan_output(output):
    hosts = {}
    if not output:
        return hosts

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('Interface:') or line.startswith('Starting') or line.startswith('Ending'):
            continue

        parts = re.split(r'\s+', line)
        if len(parts) < 2:
            continue

        ip_candidate, mac_candidate = parts[0], parts[1]
        if not (_is_valid_ipv4(ip_candidate) and MAC_REGEX.match(mac_candidate)):
            continue

        vendor = ' '.join(parts[2:]).strip() if len(parts) > 2 else ''
        hosts[ip_candidate] = {
            'mac': _normalize_mac(mac_candidate),
            'vendor': vendor
        }

    return hosts


def build_pseudo_mac_from_ip(ip):
    try:
        octets = [int(part) for part in ip.split('.')]
        if len(octets) == 4:
            return f"00:00:{octets[0]:02x}:{octets[1]:02x}:{octets[2]:02x}:{octets[3]:02x}"
    except Exception:
        pass
    return "00:00:00:00:00:00"


def run_targeted_arp_scan(ip, interface=DEFAULT_ARP_SCAN_INTERFACE):
    command = ['sudo', 'arp-scan', f'--interface={interface}', ip]
    logger.info(f"Running targeted arp-scan for {ip}: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
        hosts = _parse_arp_scan_output(result.stdout)
        entry = hosts.get(ip)
        return entry.get('mac', '') if entry else ''
    except FileNotFoundError:
        logger.warning("arp-scan command not found when resolving MAC for %s", ip)
        return ''
    except subprocess.TimeoutExpired as e:
        logger.warning("arp-scan timed out for %s: %s", ip, e)
        hosts = _parse_arp_scan_output(e.stdout or '')
        entry = hosts.get(ip)
        return entry.get('mac', '') if entry else ''
    except Exception as e:
        logger.error(f"Error running targeted arp-scan for {ip}: {e}")
        return ''


def resolve_ip_hostname(ip):
    try:
        if _is_valid_ipv4(ip):
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
    except (socket.herror, socket.gaierror):
        return ''
    except Exception as e:
        logger.debug(f"Hostname resolution failed for {ip}: {e}")
    return ''


def update_vulnerability_output(ip, hostname, mac, is_alive):
    """Create or update vulnerability scan results file for discovered host"""
    try:
        # Ensure vulnerabilities output directory exists
        vuln_output_dir = os.path.join('data', 'output', 'vulnerabilities')
        os.makedirs(vuln_output_dir, exist_ok=True)
        
        # Create or update vulnerability scan results file for this IP
        vuln_file = os.path.join(vuln_output_dir, f'scan_{ip.replace(".", "_")}.txt')
        
        with open(vuln_file, 'w') as f:
            f.write(f"# Vulnerability scan results for {ip}\n")
            f.write(f"# Hostname: {hostname}\n")
            f.write(f"# MAC: {mac}\n")
            f.write(f"# Status: {'alive' if is_alive else 'dead'}\n")
            f.write(f"# Last updated: {datetime.now().isoformat()}\n")
            f.write(f"# Discovered via: ARP/Nmap network scanning\n\n")
            
            if is_alive:
                f.write(f"Host {ip} is alive and responding\n")
                f.write(f"MAC Address: {mac}\n")
                f.write(f"Hostname: {hostname}\n")
                f.write(f"Status: ACTIVE\n\n")
                f.write(f"=== NETWORK DISCOVERY RESULTS ===\n")
                f.write(f"Host discovered through network scanning\n")
                f.write(f"Further vulnerability scanning recommended\n")
            else:
                f.write(f"Host {ip} is not responding\n")
                f.write(f"Status: INACTIVE\n")
        
        logger.debug(f"Updated vulnerability output for {ip}")
        
    except Exception as e:
        logger.error(f"Error updating vulnerability output for {ip}: {e}")


def update_netkb_entry(ip, hostname, mac, is_alive):
    try:
        # Update vulnerability output files
        update_vulnerability_output(ip, hostname, mac, is_alive)
        
        netkb_path = shared_data.netkbfile
        os.makedirs(os.path.dirname(netkb_path), exist_ok=True)

        rows = []
        headers = []
        updated_row = None

        if os.path.exists(netkb_path) and os.path.getsize(netkb_path) > 0:
            with open(netkb_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames or []
                for row in reader:
                    rows.append(row)
        else:
            headers = ['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports']

        for column in ['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports']:
            if column not in headers:
                headers.append(column)

        alive_value = '1' if is_alive else '0'
        mac_to_store = _normalize_mac(mac) if mac else ''

        for row in rows:
            existing_ips = [entry.strip() for entry in row.get('IPs', '').split(';') if entry.strip()]
            if ip in existing_ips:
                if mac_to_store:
                    row['MAC Address'] = mac_to_store
                # Don't generate pseudo MAC - let ARP cache provide real MAC addresses

                if hostname:
                    existing_hostnames = [h.strip() for h in row.get('Hostnames', '').split(';') if h.strip()]
                    existing_hostnames.append(hostname)
                    row['Hostnames'] = ';'.join(sorted(set(existing_hostnames)))

                row['Alive'] = alive_value
                updated_row = row
                break

        if updated_row is None:
            new_row = {header: '' for header in headers}
            new_row['IPs'] = ip
            new_row['Hostnames'] = hostname or ''
            if mac_to_store:
                new_row['MAC Address'] = mac_to_store
            else:
                # Don't generate pseudo MAC - let ARP cache provide real MAC addresses
                new_row['MAC Address'] = ''
            new_row['Alive'] = alive_value
            new_row['Ports'] = ''
            rows.append(new_row)
            updated_row = new_row

        with open(netkb_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

        return updated_row
    except Exception as e:
        logger.error(f"Error updating netkb entry for {ip}: {e}")
        return None

def broadcast_status_update():
    """Immediately broadcast current status to all connected clients"""
    try:
        if clients_connected > 0:
            status_data = get_current_status()
            socketio.emit('status_update', status_data)
            logger.debug(f"Broadcasted status update: {status_data.get('ragnar_status', 'unknown')}")
    except Exception as e:
        logger.error(f"Error broadcasting status update: {e}")


def sync_vulnerability_count():
    """Synchronize vulnerability count across all data sources and network intelligence"""
    try:
        vuln_count = 0
        
        # Check if network intelligence is enabled
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Update network context first
            shared_data.network_intelligence.update_network_context()
            
            # Get active findings count for current network
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            vuln_count = dashboard_findings['counts']['vulnerabilities']
            
            logger.debug(f"Network intelligence vulnerability count: {vuln_count}")
        else:
            # Fallback to legacy file-based counting
            vuln_results_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
            
            logger.debug(f"Syncing vulnerabilities from directory: {vuln_results_dir}")
            
            # Create directory if it doesn't exist
            try:
                os.makedirs(vuln_results_dir, exist_ok=True)
                logger.debug(f"Ensured directory exists: {vuln_results_dir}")
            except Exception as e:
                logger.warning(f"Could not create vulnerabilities directory: {e}")
            
            if os.path.exists(vuln_results_dir):
                try:
                    files_found = []
                    for filename in os.listdir(vuln_results_dir):
                        if filename.endswith('.txt') and not filename.startswith('.'):
                            files_found.append(filename)
                            filepath = os.path.join(vuln_results_dir, filename)
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if content.strip():
                                        # Count CVEs or files with vulnerability content
                                        cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
                                        if cve_matches:
                                            vuln_count += len(cve_matches)
                                            logger.debug(f"Found {len(cve_matches)} CVEs in {filename}: {cve_matches}")
                                        elif len(content.strip()) > 50:  # File has significant content
                                            vuln_count += 1
                                            logger.debug(f"Found vulnerability content in {filename} (no CVEs)")
                            except Exception as e:
                                logger.debug(f"Could not read vulnerability file {filepath}: {e}")
                                continue
                    
                    logger.debug(f"Vulnerability files found: {files_found}")
                    logger.debug(f"Total vulnerability count calculated: {vuln_count}")
                except Exception as e:
                    logger.warning(f"Could not list vulnerabilities directory: {e}")
            else:
                logger.warning(f"Vulnerabilities directory does not exist: {vuln_results_dir}")
        
        # Update shared data with synchronized count
        old_count = shared_data.vulnnbr
        shared_data.vulnnbr = vuln_count
        logger.debug(f"Updated shared_data.vulnnbr: {old_count} -> {vuln_count}")
        
        # Also update livestatus file if it exists
        if os.path.exists(shared_data.livestatusfile):
            try:
                if pandas_available:
                    df = pd.read_csv(shared_data.livestatusfile)
                    if not df.empty:
                        df.loc[0, 'Vulnerabilities Count'] = vuln_count
                        df.to_csv(shared_data.livestatusfile, index=False)
                        logger.debug(f"Updated livestatus file with vuln count: {vuln_count}")
                else:
                    logger.warning("Pandas not available, skipping livestatus update")
            except Exception as e:
                logger.warning(f"Could not update livestatus with sync vulnerability count: {e}")
        
        logger.debug(f"Synchronized vulnerability count: {vuln_count}")
        return vuln_count
        
    except Exception as e:
        logger.error(f"Error synchronizing vulnerability count: {e}")
        return safe_int(shared_data.vulnnbr)


def sync_all_counts():
    """Synchronize all counts (targets, ports, vulnerabilities, credentials) across data sources"""
    global last_sync_time, network_scan_cache

    with sync_lock:
        start_time = time.time()
        try:
            logger.debug("Starting sync_all_counts()")

            # Sync vulnerability count
            sync_vulnerability_count()

            # Update WiFi-specific network data from scan results
            aggregated_network_stats = update_wifi_network_data()
            
            # IMPORTANT: Use ARP scan results to supplement but not override robust failure tracking
            arp_hosts = network_scan_cache.get('arp_hosts', {})
            if arp_hosts:
                logger.debug(f"Found {len(arp_hosts)} hosts in ARP cache for supplementation")
                # Don't override aggregated_network_stats if it exists (it has robust failure tracking)
                # Instead, use ARP data to supplement the count only if aggregated_network_stats is missing
                if not aggregated_network_stats:
                    # Create minimal stats from ARP data only if no other data is available
                    aggregated_network_stats = {
                        'host_count': len(arp_hosts),
                        'total_host_count': len(arp_hosts),
                        'inactive_host_count': 0,
                        'port_count': 0,
                        'hosts': {}
                    }
                    logger.debug(f"Created stats from ARP data only (no network stats available): {len(arp_hosts)} hosts")
                else:
                    # Keep the robust failure tracking data intact, don't override with ARP count
                    logger.debug(f"Keeping existing network stats with robust failure tracking instead of overriding with ARP count")
            else:
                logger.debug("No ARP hosts available for supplementation")

            # Sync target and port counts from scan results
            scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))

            logger.debug(f"Syncing targets/ports from directory: {scan_results_dir}")

            # Create directory if it doesn't exist
            try:
                os.makedirs(scan_results_dir, exist_ok=True)
                logger.debug(f"Ensured directory exists: {scan_results_dir}")
            except Exception as e:
                logger.warning(f"Could not create scan_results directory: {e}")

            unique_hosts = set()
            csv_host_ports = {}
            scan_files_found = []

            if os.path.exists(scan_results_dir):
                try:
                    for filename in os.listdir(scan_results_dir):
                        if filename.startswith('result_') and filename.endswith('.csv') and not filename.startswith('.'):
                            scan_files_found.append(filename)
                            filepath = os.path.join(scan_results_dir, filename)
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    reader = csv.reader(f)
                                    for row in reader:
                                        if len(row) >= 1 and row[0].strip():
                                            ip = row[0].strip()
                                            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                                                unique_hosts.add(ip)
                                                csv_host_ports.setdefault(ip, set())

                                            if len(row) > 4:
                                                for port_col in row[4:]:
                                                    normalized_port = _normalize_port_value(port_col)
                                                    if normalized_port:
                                                        csv_host_ports.setdefault(ip, set()).add(normalized_port)
                            except Exception as e:
                                logger.debug(f"Could not read scan result file {filepath}: {e}")
                                continue
                except Exception as e:
                    logger.warning(f"Could not process scan_results directory: {e}")
            else:
                logger.warning(f"Scan results directory does not exist: {scan_results_dir}")

            logger.debug(f"Scan result files found: {scan_files_found}")
            logger.debug(f"Unique hosts found: {list(unique_hosts)}")
            aggregated_ports_from_csv = sum(len(ports) for ports in csv_host_ports.values())
            logger.debug(f"Total port count from CSV: {aggregated_ports_from_csv}")
            
            # ALSO read ports from netkb file which has the most complete port data
            # Count ports from LIVE hosts (detected by ARP), not just Alive=1 in netkb
            netkb_port_count = 0
            netkb_live_ips = set()
            
            # Get IPs of live hosts from ARP scan
            if arp_hosts:
                netkb_live_ips = set(arp_hosts.keys())
                logger.info(f"[PORT COUNT] Counting ports for {len(netkb_live_ips)} ARP-detected live hosts: {list(netkb_live_ips)}")
            else:
                logger.warning(f"[PORT COUNT] No ARP hosts available for port counting!")
            
            logger.info(f"[PORT COUNT] Checking netkb file: {shared_data.netkbfile}, exists={os.path.exists(shared_data.netkbfile)}")
            
            if os.path.exists(shared_data.netkbfile):
                try:
                    with open(shared_data.netkbfile, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        row_count = 0
                        for row in reader:
                            row_count += 1
                            ip = row.get('IPs', '').strip()
                            ports_str = row.get('Ports', '').strip()
                            alive_status = row.get('Alive', '').strip()
                            
                            # Count ports for hosts that are:
                            # 1. In the ARP scan (confirmed alive) OR
                            # 2. Marked as Alive=1 in netkb
                            is_arp_live = ip in netkb_live_ips
                            is_netkb_alive = alive_status == '1'
                            
                            if (is_arp_live or is_netkb_alive) and ports_str and ports_str != '0':
                                port_list = [p.strip() for p in ports_str.split(';') if p.strip() and p.strip() != '0']
                                if port_list:
                                    netkb_port_count += len(port_list)
                                    logger.info(f"[PORT COUNT] {ip}: {len(port_list)} ports ({ports_str}) - ARP={is_arp_live}, Alive={is_netkb_alive}")
                                        
                        logger.info(f"[PORT COUNT] Processed {row_count} rows from netkb")
                    logger.info(f"[PORT COUNT] Total port count from netkb (live hosts): {netkb_port_count}")
                    # Use netkb port count if it's higher (more complete)
                    if netkb_port_count > aggregated_ports_from_csv:
                        aggregated_ports_from_csv = netkb_port_count
                        logger.info(f"[PORT COUNT] Using netkb port count as it's more complete: {netkb_port_count}")
                    else:
                        logger.info(f"[PORT COUNT] Using CSV port count: {aggregated_ports_from_csv} (netkb had {netkb_port_count})")
                except Exception as e:
                    logger.error(f"[PORT COUNT] ERROR reading netkb file for port count: {e}", exc_info=True)

            old_targets = shared_data.targetnbr
            old_ports = shared_data.portnbr
            
            # Initialize with defaults from CSV scan files
            aggregated_targets = len(unique_hosts)
            aggregated_ports = aggregated_ports_from_csv
            total_target_count = aggregated_targets
            inactive_target_count = 0
            current_snapshot = {ip: {'alive': True, 'ports': csv_host_ports.get(ip, set())} for ip in unique_hosts}

            # PRIORITIZE aggregated_network_stats (robust failure tracking) over CSV data
            if aggregated_network_stats:
                agg_host_count = aggregated_network_stats.get('host_count')
                agg_total_host_count = aggregated_network_stats.get('total_host_count')
                agg_inactive_count = aggregated_network_stats.get('inactive_host_count')
                agg_port_count = aggregated_network_stats.get('port_count')
                hosts_snapshot = aggregated_network_stats.get('hosts')

                if hosts_snapshot:
                    current_snapshot = hosts_snapshot

                # Use robust failure tracking counts if available
                if agg_host_count is not None:
                    aggregated_targets = safe_int(agg_host_count)
                    logger.info(f"[ROBUST TRACKING] Using active host count from WiFi network data: {aggregated_targets}")
                if agg_total_host_count is not None:
                    total_target_count = safe_int(agg_total_host_count)
                    logger.info(f"[ROBUST TRACKING] Using total host count from WiFi network data: {total_target_count}")
                else:
                    total_target_count = aggregated_targets
                if agg_inactive_count is not None:
                    inactive_target_count = safe_int(agg_inactive_count)
                    logger.info(f"[ROBUST TRACKING] Using inactive host count from WiFi network data: {inactive_target_count}")
                else:
                    inactive_target_count = max(total_target_count - aggregated_targets, 0)
                if agg_port_count is not None:
                    # Only use aggregated_network_stats port count if it's HIGHER than what we counted from netkb
                    agg_ports_value = safe_int(agg_port_count)
                    if agg_ports_value > aggregated_ports:
                        logger.info(f"[PORT COUNT] Using aggregated_network_stats port count: {agg_ports_value} (higher than netkb: {aggregated_ports})")
                        aggregated_ports = agg_ports_value
                    else:
                        logger.info(f"[PORT COUNT] Keeping netkb port count: {aggregated_ports} (aggregated_network_stats had: {agg_ports_value})")
            else:
                total_target_count = aggregated_targets
                inactive_target_count = max(total_target_count - aggregated_targets, 0)

            shared_data.targetnbr = aggregated_targets
            shared_data.total_targetnbr = total_target_count
            shared_data.inactive_targetnbr = inactive_target_count
            shared_data.portnbr = aggregated_ports
            shared_data.networkkbnbr = total_target_count  # Use total target count for network KB count
            logger.debug(f"Updated targets: {old_targets} -> {aggregated_targets}")
            logger.debug(f"Updated ports: {old_ports} -> {aggregated_ports}")
            logger.debug(f"Updated networkkbnbr: -> {total_target_count}")

            previous_snapshot = getattr(shared_data, 'network_hosts_snapshot', {}) or {}

            previous_active_hosts = {ip for ip, meta in previous_snapshot.items() if meta.get('alive', True)}
            current_active_hosts = {ip for ip, meta in current_snapshot.items() if meta.get('alive', True)}

            new_active_hosts = current_active_hosts - previous_active_hosts
            lost_active_hosts = previous_active_hosts - current_active_hosts

            shared_data.network_hosts_snapshot = current_snapshot
            shared_data.new_target_ips = sorted(new_active_hosts)
            shared_data.lost_target_ips = sorted(lost_active_hosts)
            shared_data.new_targets = len(shared_data.new_target_ips)
            shared_data.lost_targets = len(shared_data.lost_target_ips)

            # Sync credential count from crackedpwd directory
            cred_results_dir = getattr(shared_data, 'crackedpwd_dir', os.path.join('data', 'output', 'crackedpwd'))

            logger.debug(f"Syncing credentials from directory: {cred_results_dir}")

            # Create directory if it doesn't exist
            try:
                os.makedirs(cred_results_dir, exist_ok=True)
                logger.debug(f"Ensured directory exists: {cred_results_dir}")
            except Exception as e:
                logger.warning(f"Could not create crackedpwd directory: {e}")

            if os.path.exists(cred_results_dir):
                cred_count = 0
                try:
                    cred_files_found = []
                    for filename in os.listdir(cred_results_dir):
                        if (filename.endswith('.txt') or filename.endswith('.csv')) and not filename.startswith('.'):
                            cred_files_found.append(filename)
                            filepath = os.path.join(cred_results_dir, filename)
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    # Count lines with credential format (user:pass)
                                    file_creds = 0
                                    for line in content.split('\n'):
                                        if ':' in line and line.strip():
                                            cred_count += 1
                                            file_creds += 1
                                    if file_creds > 0:
                                        logger.debug(f"Found {file_creds} credentials in {filename}")
                            except Exception as e:
                                logger.debug(f"Could not read credential file {filepath}: {e}")
                                continue

                    logger.debug(f"Credential files found: {cred_files_found}")
                    logger.debug(f"Total credential count: {cred_count}")
                except Exception as e:
                    logger.warning(f"Could not list crackedpwd directory: {e}")

                # Update shared data with the current credential count
                old_creds = shared_data.crednbr
                shared_data.crednbr = cred_count
                logger.debug(f"Updated credentials: {old_creds} -> {cred_count}")
            else:
                logger.warning(f"Crackedpwd directory does not exist: {cred_results_dir}")

            # Sync data stolen count
            data_stolen_dir = getattr(shared_data, 'datastolendir', os.path.join('data', 'output', 'data_stolen'))
            if os.path.exists(data_stolen_dir):
                try:
                    total_data_files = sum([len(files) for r, d, files in os.walk(data_stolen_dir)])
                    old_data = shared_data.datanbr
                    shared_data.datanbr = total_data_files
                    logger.debug(f"Updated data stolen: {old_data} -> {total_data_files}")
                except Exception as e:
                    logger.debug(f"Could not count data stolen files: {e}")
            
            # Sync zombies count
            zombies_dir = getattr(shared_data, 'zombiesdir', os.path.join('data', 'output', 'zombies'))
            if os.path.exists(zombies_dir):
                try:
                    total_zombies = sum([len(files) for r, d, files in os.walk(zombies_dir)])
                    old_zombies = shared_data.zombiesnbr
                    shared_data.zombiesnbr = total_zombies
                    logger.debug(f"Updated zombies: {old_zombies} -> {total_zombies}")
                except Exception as e:
                    logger.debug(f"Could not count zombie files: {e}")
            
            # Sync attacks count (count action modules available)
            actions_dir = getattr(shared_data, 'actions_dir', os.path.join('actions'))
            if os.path.exists(actions_dir):
                try:
                    total_attacks = sum([len(files) for r, d, files in os.walk(actions_dir) if not r.endswith("__pycache__")]) - 2
                    old_attacks = shared_data.attacksnbr
                    shared_data.attacksnbr = max(total_attacks, 0)
                    logger.debug(f"Updated attacks: {old_attacks} -> {shared_data.attacksnbr}")
                except Exception as e:
                    logger.debug(f"Could not count attack modules: {e}")

            # Update livestatus file with all synchronized counts
            try:
                if pandas_available:
                    # Create livestatus file if it doesn't exist
                    if not os.path.exists(shared_data.livestatusfile):
                        logger.info(f"Creating missing livestatus file: {shared_data.livestatusfile}")
                        shared_data.create_livestatusfile()
                    
                    # Update the file with current counts
                    df = pd.read_csv(shared_data.livestatusfile)
                    if not df.empty:
                        df.loc[0, 'Alive Hosts Count'] = safe_int(shared_data.targetnbr)
                        df.loc[0, 'Total Open Ports'] = safe_int(shared_data.portnbr)
                        df.loc[0, 'All Known Hosts Count'] = safe_int(getattr(shared_data, 'total_targetnbr', shared_data.targetnbr))
                        df.loc[0, 'Vulnerabilities Count'] = safe_int(shared_data.vulnnbr)
                        df.to_csv(shared_data.livestatusfile, index=False)
                        logger.debug("Updated livestatus file with synchronized counts")
                else:
                    logger.warning("Pandas not available, skipping livestatus update")
            except Exception as e:
                logger.warning(f"Could not update livestatus with all sync counts: {e}")

            try:
                shared_data.update_stats()
                logger.debug(f"Updated gamification stats - Level: {shared_data.levelnbr}, Coins: {shared_data.coinnbr}")
                logger.debug(f"Stats breakdown - NetworkKB: {shared_data.networkkbnbr}, Creds: {shared_data.crednbr}, Data: {shared_data.datanbr}, Zombies: {shared_data.zombiesnbr}, Attacks: {shared_data.attacksnbr}, Vulns: {shared_data.vulnnbr}")
            except Exception as e:
                logger.warning(f"Could not update gamification stats: {e}")

            logger.debug(f"Completed sync_all_counts() - Active Targets: {shared_data.targetnbr}, Total Targets: {shared_data.total_targetnbr}, Inactive Targets: {shared_data.inactive_targetnbr}, Ports: {shared_data.portnbr}, Vulns: {shared_data.vulnnbr}, Creds: {shared_data.crednbr}, Level: {shared_data.levelnbr}, Coins: {shared_data.coinnbr}")
            
            # Consistency check to prevent flickering
            if shared_data.targetnbr > shared_data.total_targetnbr:
                logger.warning(f"CONSISTENCY WARNING: Active targets ({shared_data.targetnbr}) > Total targets ({shared_data.total_targetnbr}). Adjusting total.")
                shared_data.total_targetnbr = shared_data.targetnbr
                shared_data.inactive_targetnbr = 0

        except Exception as e:
            logger.error(f"Error synchronizing all counts: {e}")
        finally:
            last_sync_time = time.time()
            shared_data.last_sync_timestamp = last_sync_time
            duration = last_sync_time - start_time
            logger.debug(f"sync_all_counts() finished in {duration:.2f}s")


def safe_int(value, default=0):
    """Safely convert value to int, handling numpy types"""
    try:
        if hasattr(value, 'item'):  # numpy types have .item() method
            return int(value.item())
        return int(value) if value is not None else default
    except (ValueError, TypeError, AttributeError):
        return default

def safe_str(value, default=""):
    """Safely convert value to string"""
    try:
        return str(value) if value is not None else default
    except (ValueError, TypeError):
        return default

def safe_bool(value, default=False):
    """Safely convert value to boolean"""
    try:
        return bool(value) if value is not None else default
    except (ValueError, TypeError):
        return default


def ensure_recent_sync(max_age=SYNC_BACKGROUND_INTERVAL):
    """Ensure counts are synchronized if the last update is older than max_age seconds"""
    global last_sync_time

    if time.time() - last_sync_time > max_age:
        logger.debug("Triggering on-demand sync_all_counts() due to stale data")
        sync_all_counts()


def get_current_wifi_ssid():
    """Get the current WiFi SSID for file naming"""
    try:
        # Try to get SSID from wifi_manager if available
        if hasattr(shared_data, 'wifi_manager') and shared_data.wifi_manager:
            ssid = shared_data.wifi_manager.get_current_ssid()
            if ssid:
                # Sanitize SSID for filename
                sanitized = re.sub(r'[^\w\-_]', '_', ssid)
                return sanitized
        
        # Fallback to direct system command
        result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.startswith('yes:'):
                    ssid = line.split(':', 1)[1]
                    if ssid:
                        # Sanitize SSID for filename
                        sanitized = re.sub(r'[^\w\-_]', '_', ssid)
                        return sanitized
        
        return "unknown_network"
    except Exception as e:
        logger.debug(f"Error getting current WiFi SSID: {e}")
        return "unknown_network"


def get_wifi_specific_network_file():
    """Get the WiFi-specific network data file path"""
    current_ssid = get_current_wifi_ssid()
    data_dir = os.path.join('data', 'network_data')
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, f'network_{current_ssid}.csv')


def check_and_handle_network_switch():
    """Check if we've switched networks and clear old data if so"""
    try:
        current_ssid = get_current_wifi_ssid()
        last_ssid_file = os.path.join('data', 'network_data', '.last_ssid')
        
        # Check if we have a record of the last SSID
        last_ssid = None
        if os.path.exists(last_ssid_file):
            try:
                with open(last_ssid_file, 'r', encoding='utf-8') as f:
                    last_ssid = f.read().strip()
            except Exception as e:
                logger.debug(f"Error reading last SSID file: {e}")
        
        # If SSID has changed, clear old network data files
        if last_ssid and last_ssid != current_ssid:
            logger.info(f"Network switch detected: {last_ssid} -> {current_ssid}")
            
            # Clear old network data files
            data_dir = os.path.join('data', 'network_data')
            if os.path.exists(data_dir):
                for filename in os.listdir(data_dir):
                    if filename.startswith('network_') and filename.endswith('.csv'):
                        old_file = os.path.join(data_dir, filename)
                        try:
                            os.remove(old_file)
                            logger.info(f"Removed old network data file: {filename}")
                        except Exception as e:
                            logger.error(f"Error removing old network data file {filename}: {e}")
        
        # Update the last SSID record
        try:
            os.makedirs(os.path.dirname(last_ssid_file), exist_ok=True)
            with open(last_ssid_file, 'w', encoding='utf-8') as f:
                f.write(current_ssid)
        except Exception as e:
            logger.error(f"Error updating last SSID file: {e}")
    
    except Exception as e:
        logger.error(f"Error checking network switch: {e}")


def _is_ip_address(value):
    """Check if a value is a valid IP address"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_port_value(port_entry):
    """Normalize a port entry string for consistent comparisons"""
    try:
        if not port_entry:
            return None

        cleaned = port_entry.strip()
        if not cleaned:
            return None

        # Extract numeric portion if the port entry contains protocol suffixes
        match = re.match(r"^(\d+)", cleaned)
        if match:
            return match.group(1)

        return cleaned
    except Exception:
        return None


def _normalize_alive_value(value):
    """Normalize alive column values to boolean"""
    try:
        if value is None:
            return True

        if isinstance(value, bool):
            return value

        if isinstance(value, (int, float)):
            return value != 0

        text = str(value).strip().lower()
        if text in ('', '1', 'true', 'yes', 'up', 'alive', 'online'):
            return True
        if text in ('0', 'false', 'no', 'down', 'dead', 'offline'):
            return False

        return True
    except Exception:
        return True


def update_wifi_network_data():
    """Update WiFi-specific network data from scan results and provide aggregated counts"""
    try:
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        wifi_network_file = get_wifi_specific_network_file()

        # Load existing data if file exists
        existing_data = {}
        if os.path.exists(wifi_network_file):
            try:
                with open(wifi_network_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    headers = next(reader, None)
                    if headers:
                        for row in reader:
                                if len(row) >= 1 and row[0].strip():
                                    ip = row[0].strip()
                                    ports = set()
                                    if len(row) > 4 and row[4]:
                                        for port_entry in row[4].split(';'):
                                            normalized = _normalize_port_value(port_entry)
                                            if normalized:
                                                ports.add(normalized)

                                existing_data[ip] = {
                                    'hostname': row[1] if len(row) > 1 else '',
                                    'alive': _normalize_alive_value(row[2] if len(row) > 2 else '1'),
                                    'mac': row[3] if len(row) > 3 else '',
                                    'ports': ports,
                                    'last_seen': row[5] if len(row) > 5 else datetime.now().isoformat(),
                                    # New fields for robust connectivity tracking (with backward compatibility)
                                    'failed_ping_count': int(row[6]) if len(row) > 6 and row[6].isdigit() else 0,
                                    'last_successful_ping': row[7] if len(row) > 7 else '',
                                    'last_ping_attempt': row[8] if len(row) > 8 else ''
                                }
            except Exception as e:
                logger.debug(f"Could not read existing WiFi network file: {e}")

        # Process new scan results
        if os.path.exists(scan_results_dir):
            current_time = datetime.now().isoformat()

            for filename in os.listdir(scan_results_dir):
                if filename.startswith('result_') and filename.endswith('.csv'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            reader = csv.reader(f)
                            for row in reader:
                                if len(row) >= 1 and row[0].strip():
                                    ip = row[0].strip()
                                    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                                        hostname = row[1] if len(row) > 1 and row[1] else ''
                                        alive = _normalize_alive_value(row[2] if len(row) > 2 and row[2] else '1')
                                        mac = row[3] if len(row) > 3 and row[3] else ''

                                        # Collect ports from remaining columns
                                        ports = set()
                                        if len(row) > 4:
                                            for port_col in row[4:]:
                                                normalized = _normalize_port_value(port_col)
                                                if normalized:
                                                    ports.add(normalized)

                                        # Update or add entry
                                        if ip in existing_data:
                                            # Merge data
                                            if hostname and hostname != 'Unknown':
                                                existing_data[ip]['hostname'] = hostname
                                            if mac and mac != 'Unknown':
                                                existing_data[ip]['mac'] = mac
                                            existing_data[ip]['alive'] = alive
                                            existing_data[ip]['ports'].update(ports)
                                            existing_data[ip]['last_seen'] = current_time
                                            # Reset failure counter on successful scan
                                            existing_data[ip]['failed_ping_count'] = 0
                                            existing_data[ip]['last_successful_ping'] = current_time
                                        else:
                                            # New entry
                                            existing_data[ip] = {
                                                'hostname': hostname,
                                                'alive': alive,
                                                'mac': mac,
                                                'ports': ports,
                                                'last_seen': current_time,
                                                'failed_ping_count': 0,
                                                'last_successful_ping': current_time,
                                                'last_ping_attempt': current_time
                                            }
                    except Exception as e:
                        logger.debug(f"Could not read scan result file {filepath}: {e}")
                        continue
        
        # Remove entries that haven't been seen recently
        retention_days = shared_data.config.get('network_device_retention_days', 14)
        try:
            retention_days = int(retention_days)
        except (ValueError, TypeError):
            retention_days = 14

        retention_days = max(retention_days, 1)
        stale_cutoff = datetime.now() - timedelta(days=retention_days)

        stale_hosts = []
        for ip, data in list(existing_data.items()):
            try:
                last_seen_dt = datetime.fromisoformat(data.get('last_seen', datetime.now().isoformat()))
            except Exception:
                last_seen_dt = datetime.now()

            if last_seen_dt < stale_cutoff:
                stale_hosts.append(ip)

        for ip in stale_hosts:
            existing_data.pop(ip, None)

        # Update alive status based on current ARP cache data with robust connectivity tracking
        current_time = datetime.now().isoformat()
        arp_hosts = network_scan_cache.get('arp_hosts', {})
        MAX_FAILED_PINGS = shared_data.config.get('network_max_failed_pings', 15)  # Changed to 15 for more stability
        
        for ip, data in existing_data.items():
            # Initialize failure counter if not present
            if 'failed_ping_count' not in data:
                data['failed_ping_count'] = 0
            
            # Update alive status based on ARP cache
            if ip in arp_hosts:
                # Device responded - reset failure counter and mark as alive
                data['failed_ping_count'] = 0
                data['alive'] = True
                data['last_seen'] = current_time
                data['last_successful_ping'] = current_time
                
                # Update MAC if we have a better one from ARP
                arp_mac = arp_hosts[ip].get('mac', '')
                if arp_mac and (not data.get('mac') or data['mac'] in ['', 'Unknown', '00:00:00:00:00:00'] or 
                               data['mac'].startswith('00:00:c0:a8:01:')):  # Replace pseudo MACs
                    data['mac'] = arp_mac
                    # Also update NetKB database with real MAC
                    try:
                        arp_hostname = arp_hosts[ip].get('hostname', data.get('hostname', ''))
                        update_netkb_entry(ip, arp_hostname, arp_mac, True)
                    except Exception as e:
                        logger.debug(f"Could not update NetKB with real MAC for {ip}: {e}")
            else:
                # Device didn't respond - increment failure counter
                data['failed_ping_count'] = data.get('failed_ping_count', 0) + 1
                data['last_ping_attempt'] = current_time
                
                # Only mark as offline after MAX_FAILED_PINGS consecutive failures
                if data['failed_ping_count'] >= MAX_FAILED_PINGS:
                    data['alive'] = False
                    logger.debug(f"Device {ip} marked offline after {data['failed_ping_count']} consecutive failed pings")
                else:
                    # IMPORTANT: Keep device as "alive" until it exceeds the failure limit
                    # This implements the proper 15-ping rule you requested
                    data['alive'] = True  # Don't change to False until 15 failures
                    logger.debug(f"Device {ip} failed ping {data['failed_ping_count']}/{MAX_FAILED_PINGS} - keeping alive per 15-ping rule")

        # Add new devices discovered via ARP that aren't in our data yet
        for ip, arp_data in arp_hosts.items():
            if ip not in existing_data:
                existing_data[ip] = {
                    'hostname': arp_data.get('hostname', ''),
                    'alive': True,
                    'mac': arp_data.get('mac', ''),
                    'ports': set(),
                    'last_seen': current_time,
                    'last_successful_ping': current_time,
                    'failed_ping_count': 0  # New devices start with 0 failures
                }
                # Add to NetKB database as well
                try:
                    update_netkb_entry(ip, arp_data.get('hostname', ''), arp_data.get('mac', ''), True)
                except Exception as e:
                    logger.debug(f"Could not add new ARP discovery to NetKB for {ip}: {e}")

        # Prepare aggregated counts from persisted data using PROPER 5-ping rule
        aggregated_host_count = 0
        aggregated_active_count = 0
        aggregated_inactive_count = 0
        aggregated_port_count = 0

        for ip, data in existing_data.items():
            aggregated_host_count += 1
            
            # Apply the PROPER 5-ping rule for counting active targets
            failed_ping_count = data.get('failed_ping_count', 0)
            
            # TARGET IS ACTIVE IF:
            # 1. It has fewer than MAX_FAILED_PINGS consecutive failures, OR
            # 2. It's marked as explicitly alive (from ARP response)
            is_explicitly_alive = data.get('alive', True)
            has_not_exceeded_failure_limit = failed_ping_count < MAX_FAILED_PINGS
            
            # A target is active if it hasn't exceeded the failure limit OR if it's currently responding
            is_target_active = has_not_exceeded_failure_limit or is_explicitly_alive
            
            if is_target_active:
                aggregated_active_count += 1
                aggregated_port_count += sum(1 for port in data['ports'] if port)
                logger.debug(f"[15-PING RULE] {ip}: ACTIVE (failures={failed_ping_count}/{MAX_FAILED_PINGS}, alive={is_explicitly_alive})")
            else:
                aggregated_inactive_count += 1
                logger.debug(f"[15-PING RULE] {ip}: INACTIVE (failures={failed_ping_count}/{MAX_FAILED_PINGS}, alive={is_explicitly_alive})")

        # Write updated data to WiFi-specific file
        try:
            with open(wifi_network_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Hostname', 'Alive', 'MAC', 'Ports', 'LastSeen', 'FailedPingCount', 'LastSuccessfulPing', 'LastPingAttempt'])

                for ip, data in existing_data.items():
                    def port_sort_key(value):
                        if value.isdigit():
                            return int(value)
                        try:
                            match = re.match(r"^(\d+)", value)
                            if match:
                                return int(match.group(1))
                            return value
                        except Exception:
                            return value

                    ports_str = ';'.join(sorted((port for port in data['ports'] if port), key=port_sort_key))
                    writer.writerow([
                        ip,
                        data['hostname'],
                        '1' if data.get('alive', True) else '0',
                        data['mac'],
                        ports_str,
                        data['last_seen'],
                        data.get('failed_ping_count', 0),
                        data.get('last_successful_ping', ''),
                        data.get('last_ping_attempt', '')
                    ])

            logger.info(f"Updated WiFi network data file: {wifi_network_file} with {len(existing_data)} entries (removed {len(stale_hosts)} stale hosts)")
        except Exception as e:
            logger.error(f"Error writing WiFi network data file: {e}")

        return {
            'host_count': aggregated_active_count,
            'total_host_count': aggregated_host_count,
            'inactive_host_count': aggregated_inactive_count,
            'port_count': aggregated_port_count,
            'stale_hosts_removed': len(stale_hosts),
            'hosts': existing_data
        }

    except Exception as e:
        logger.error(f"Error updating WiFi network data: {e}")
        return None


def read_wifi_network_data():
    """Read network data from WiFi-specific file with automatic cleanup of legacy entries"""
    try:
        wifi_network_file = get_wifi_specific_network_file()
        network_data = []
        cleaned_data = []
        cleanup_needed = False
        
        # Get configuration values for cleanup
        retention_hours = shared_data.config.get('network_device_retention_hours', 8)  # 8 hours by default
        max_failed_pings = shared_data.config.get('network_max_failed_pings', 15)  # Changed to 15 for more stability
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(hours=retention_hours)
        
        if os.path.exists(wifi_network_file):
            with open(wifi_network_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                headers = next(reader, None)  # Read header
                
                # Determine if we have the enhanced format with connectivity tracking
                has_enhanced_format = (headers and len(headers) >= 9 and 
                                     'FailedPingCount' in headers and 
                                     'LastSuccessfulPing' in headers and 
                                     'LastPingAttempt' in headers)
                
                for row in reader:
                    if not row or not row[0].strip():
                        continue
                        
                    ip = row[0].strip()
                    if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                        continue
                    
                    # Handle both old and new CSV formats
                    if has_enhanced_format and len(row) >= 9:
                        # Enhanced format: IP, Hostname, Alive, MAC, Ports, LastSeen, FailedPingCount, LastSuccessfulPing, LastPingAttempt
                        failed_ping_count = int(row[6]) if row[6].isdigit() else 0
                        last_successful_ping = row[7] if len(row) > 7 else ''
                        last_ping_attempt = row[8] if len(row) > 8 else ''
                        last_seen = row[5] if len(row) > 5 else ''
                        
                        # Determine the most recent activity timestamp
                        most_recent_activity = None
                        for timestamp_str in [last_successful_ping, last_ping_attempt, last_seen]:
                            if timestamp_str and timestamp_str.strip():
                                try:
                                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                    if timestamp.tzinfo:
                                        timestamp = timestamp.replace(tzinfo=None)
                                    if most_recent_activity is None or timestamp > most_recent_activity:
                                        most_recent_activity = timestamp
                                except (ValueError, TypeError):
                                    continue
                        
                        # Apply robust 5-ping failure cleanup logic
                        should_keep = True
                        cleanup_reason = None
                        
                        # RULE 1: Remove devices that have failed 5+ consecutive pings (regardless of age)
                        if failed_ping_count >= max_failed_pings:
                            should_keep = False
                            cleanup_reason = f"exceeded max failed pings ({failed_ping_count}>={max_failed_pings})"
                            cleanup_needed = True
                        
                        # RULE 2: Remove very old devices that haven't been seen for 8+ hours (regardless of ping status)
                        elif most_recent_activity and most_recent_activity < cutoff_time:
                            should_keep = False
                            cleanup_reason = f"too old (last activity: {most_recent_activity}, cutoff: {cutoff_time})"
                            cleanup_needed = True
                        
                        # RULE 3: Remove devices with no successful ping record and no recent activity
                        elif not last_successful_ping and most_recent_activity and most_recent_activity < cutoff_time:
                            should_keep = False
                            cleanup_reason = f"no successful pings and old (last activity: {most_recent_activity})"
                            cleanup_needed = True
                        
                        if not should_keep:
                            logger.info(f"[ROBUST CLEANUP] Removing {ip}: {cleanup_reason}")
                        
                        if should_keep:
                            network_entry = {
                                'IPs': ip,
                                'Hostnames': row[1] if row[1] else '',
                                'Alive': int(row[2]) if row[2].isdigit() else 0,
                                'MAC Address': row[3] if row[3] else '',
                                'Ports': row[4] if row[4] else '',
                                'LastSeen': last_seen,
                                'FailedPingCount': failed_ping_count,
                                'LastSuccessfulPing': last_successful_ping,
                                'LastPingAttempt': last_ping_attempt
                            }
                            network_data.append(network_entry)
                            cleaned_data.append(row)
                    
                    elif len(row) >= 6:
                        # Legacy format: IP, Hostname, Alive, MAC, Ports, LastSeen
                        last_seen = row[5] if len(row) > 5 else ''
                        alive_status = int(row[2]) if row[2].isdigit() else 0
                        
                        # For legacy format, remove entries that are old and not alive
                        should_keep = True
                        if last_seen:
                            try:
                                last_seen_time = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                                if last_seen_time.tzinfo:
                                    last_seen_time = last_seen_time.replace(tzinfo=None)
                                
                                if last_seen_time < cutoff_time and alive_status == 0:
                                    logger.debug(f"Removing legacy entry {ip} (old format, not alive, last seen: {last_seen_time})")
                                    should_keep = False
                                    cleanup_needed = True
                            except (ValueError, TypeError):
                                # If we can't parse the timestamp and device is not alive, remove it
                                if alive_status == 0:
                                    logger.debug(f"Removing legacy entry {ip} (unparseable timestamp, not alive)")
                                    should_keep = False
                                    cleanup_needed = True
                        
                        if should_keep:
                            network_entry = {
                                'IPs': ip,
                                'Hostnames': row[1] if row[1] else '',
                                'Alive': alive_status,
                                'MAC Address': row[3] if row[3] else '',
                                'Ports': row[4] if row[4] else '',
                                'LastSeen': last_seen
                            }
                            network_data.append(network_entry)
                            cleaned_data.append(row)
            
            # If we removed any entries, rewrite the file
            if cleanup_needed:
                try:
                    with open(wifi_network_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        if headers:
                            writer.writerow(headers)
                        writer.writerows(cleaned_data)
                    logger.info(f"Cleaned up legacy network data - removed {len(cleaned_data) - len(network_data)} old entries")
                except Exception as e:
                    logger.error(f"Error rewriting cleaned network file: {e}")
            
            logger.debug(f"Read {len(network_data)} entries from WiFi network file: {wifi_network_file}")
        else:
            logger.debug(f"WiFi network file does not exist: {wifi_network_file}")
        
        return network_data
    except Exception as e:
        logger.error(f"Error reading WiFi network data: {e}")
        return []


def is_ap_client_request():
    """Check if the request is coming from an AP client (192.168.4.x)"""
    try:
        client_ip = request.environ.get('REMOTE_ADDR', '')
        # Check if request is from AP network (192.168.4.x)
        return client_ip.startswith('192.168.4.') and client_ip != '192.168.4.1'
    except:
        return False


# ============================================================================
# STATIC FILE ROUTES
# ============================================================================

@app.route('/')
def index():
    """Serve the main dashboard page or captive portal for AP clients"""
    if is_ap_client_request():
        # Serve captive portal for AP clients
        return send_from_directory('web', 'captive_portal.html')
    else:
        # Serve main dashboard for regular users
        return send_from_directory('web', 'index_modern.html')


# Add explicit captive portal route
@app.route('/portal')
def captive_portal():
    """Explicit captive portal route"""
    return send_from_directory('web', 'captive_portal.html')

# WiFi configuration page route
@app.route('/wifi-config')
def wifi_config_page():
    """Serve the Wi-Fi configuration page for AP clients and regular users"""
    return send_from_directory('web', 'wifi_config.html')

# Alternative routes for WiFi config (for compatibility)
@app.route('/wifi')
@app.route('/setup')
def wifi_config_alt():
    """Alternative routes for Wi-Fi configuration"""
    return send_from_directory('web', 'wifi_config.html')


# Captive portal detection routes for mobile devices
@app.route('/generate_204')
@app.route('/gen_204')
@app.route('/connecttest.txt')
@app.route('/success.txt')
@app.route('/ncsi.txt')
def captive_portal_detection():
    """Handle captive portal detection requests from mobile devices"""
    if is_ap_client_request():
        # Redirect to captive portal for AP clients
        return '''<html><head><meta http-equiv="refresh" content="0; url=/portal"></head><body><a href="/portal">Click here for WiFi setup</a></body></html>''', 302
    else:
        # Return success for non-AP clients
        return "Success", 204


@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files from web directory"""
    return send_from_directory('web', filename)


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/status')
def get_status():
    """Get current Ragnar status"""
    try:
        # Synchronize all counts across all sources for consistency
        sync_all_counts()
        
        status_data = {
            'ragnar_status': safe_str(shared_data.ragnarstatustext),
            'ragnar_status2': safe_str(shared_data.ragnarstatustext2),
            'ragnar_says': safe_str(shared_data.ragnarsays),
            'orchestrator_status': safe_str(shared_data.ragnarorch_status),
            'target_count': safe_int(shared_data.targetnbr),
            'port_count': safe_int(shared_data.portnbr),
            'vulnerability_count': safe_int(shared_data.vulnnbr),
            'credential_count': safe_int(shared_data.crednbr),
            'data_count': safe_int(shared_data.datanbr),
            'level': safe_int(shared_data.levelnbr),
            'points': safe_int(shared_data.coinnbr),
            'coins': safe_int(shared_data.coinnbr),
            'wifi_connected': safe_bool(shared_data.wifi_connected),
            'bluetooth_active': safe_bool(shared_data.bluetooth_active),
            'pan_connected': safe_bool(shared_data.pan_connected),
            'usb_active': safe_bool(shared_data.usb_active),
            'manual_mode': safe_bool(shared_data.config.get('manual_mode', False)),
            'timestamp': datetime.now().isoformat()
        }
        return jsonify(status_data)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    try:
        return jsonify(shared_data.config)
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Update configuration
        for key, value in data.items():
            if key in shared_data.config:
                shared_data.config[key] = value
        
        # Save configuration
        shared_data.save_config()
        
        # Emit update to all connected clients
        socketio.emit('config_updated', shared_data.config)
        
        return jsonify({'success': True, 'message': 'Configuration updated'})
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/hardware-profiles')
def get_hardware_profiles():
    """Get predefined hardware profiles for different Raspberry Pi models"""
    try:
        profiles = {
            'pi_zero_2w': {
                'name': 'Raspberry Pi Zero 2 W',
                'ram': 512,
                'description': '512MB RAM - Minimal resource usage',
                'settings': {
                    'scanner_max_threads': 3,
                    'orchestrator_max_concurrent': 2,
                    'nmap_scan_aggressivity': '-T2',
                    'scan_interval': 300,
                    'scan_vuln_interval': 600,
                    'max_concurrent_scans': 1,
                    'memory_warning_threshold': 70,
                    'memory_critical_threshold': 85,
                    'enable_resource_monitoring': True
                }
            },
            'pi_4_1gb': {
                'name': 'Raspberry Pi 4 (1GB)',
                'ram': 1024,
                'description': '1GB RAM - Light resource usage',
                'settings': {
                    'scanner_max_threads': 5,
                    'orchestrator_max_concurrent': 3,
                    'nmap_scan_aggressivity': '-T3',
                    'scan_interval': 240,
                    'scan_vuln_interval': 480,
                    'max_concurrent_scans': 2,
                    'memory_warning_threshold': 75,
                    'memory_critical_threshold': 90,
                    'enable_resource_monitoring': True
                }
            },
            'pi_4_2gb': {
                'name': 'Raspberry Pi 4 (2GB)',
                'ram': 2048,
                'description': '2GB RAM - Moderate resource usage',
                'settings': {
                    'scanner_max_threads': 10,
                    'orchestrator_max_concurrent': 5,
                    'nmap_scan_aggressivity': '-T3',
                    'scan_interval': 180,
                    'scan_vuln_interval': 360,
                    'max_concurrent_scans': 3,
                    'memory_warning_threshold': 75,
                    'memory_critical_threshold': 90,
                    'enable_resource_monitoring': True
                }
            },
            'pi_4_4gb': {
                'name': 'Raspberry Pi 4 (4GB)',
                'ram': 4096,
                'description': '4GB RAM - Standard resource usage',
                'settings': {
                    'scanner_max_threads': 20,
                    'orchestrator_max_concurrent': 8,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 180,
                    'scan_vuln_interval': 300,
                    'max_concurrent_scans': 4,
                    'memory_warning_threshold': 80,
                    'memory_critical_threshold': 92,
                    'enable_resource_monitoring': True
                }
            },
            'pi_4_8gb': {
                'name': 'Raspberry Pi 4 (8GB)',
                'ram': 8192,
                'description': '8GB RAM - High performance',
                'settings': {
                    'scanner_max_threads': 30,
                    'orchestrator_max_concurrent': 10,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 120,
                    'scan_vuln_interval': 240,
                    'max_concurrent_scans': 6,
                    'memory_warning_threshold': 80,
                    'memory_critical_threshold': 92,
                    'enable_resource_monitoring': True
                }
            },
            'pi_5_2gb': {
                'name': 'Raspberry Pi 5 (2GB)',
                'ram': 2048,
                'description': '2GB RAM - Fast CPU, moderate RAM',
                'settings': {
                    'scanner_max_threads': 15,
                    'orchestrator_max_concurrent': 6,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 150,
                    'scan_vuln_interval': 300,
                    'max_concurrent_scans': 4,
                    'memory_warning_threshold': 75,
                    'memory_critical_threshold': 90,
                    'enable_resource_monitoring': True
                }
            },
            'pi_5_4gb': {
                'name': 'Raspberry Pi 5 (4GB)',
                'ram': 4096,
                'description': '4GB RAM - High performance',
                'settings': {
                    'scanner_max_threads': 30,
                    'orchestrator_max_concurrent': 12,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 120,
                    'scan_vuln_interval': 240,
                    'max_concurrent_scans': 6,
                    'memory_warning_threshold': 80,
                    'memory_critical_threshold': 92,
                    'enable_resource_monitoring': True
                }
            },
            'pi_5_8gb': {
                'name': 'Raspberry Pi 5 (8GB)',
                'ram': 8192,
                'description': '8GB RAM - Maximum performance',
                'settings': {
                    'scanner_max_threads': 40,
                    'orchestrator_max_concurrent': 15,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 90,
                    'scan_vuln_interval': 180,
                    'max_concurrent_scans': 8,
                    'memory_warning_threshold': 82,
                    'memory_critical_threshold': 93,
                    'enable_resource_monitoring': True
                }
            },
            'pi_5_16gb': {
                'name': 'Raspberry Pi 5 (16GB)',
                'ram': 16384,
                'description': '16GB RAM - Extreme performance',
                'settings': {
                    'scanner_max_threads': 50,
                    'orchestrator_max_concurrent': 20,
                    'nmap_scan_aggressivity': '-T4',
                    'scan_interval': 60,
                    'scan_vuln_interval': 120,
                    'max_concurrent_scans': 10,
                    'memory_warning_threshold': 85,
                    'memory_critical_threshold': 94,
                    'enable_resource_monitoring': True
                }
            }
        }
        
        return jsonify(profiles)
    except Exception as e:
        logger.error(f"Error getting hardware profiles: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config/detect-hardware')
def detect_hardware():
    """Auto-detect current hardware and recommend profile"""
    try:
        import subprocess
        import re
        
        # Detect Raspberry Pi model
        model = 'unknown'
        ram_mb = 0
        recommended_profile = 'pi_zero_2w'  # Default to most conservative
        
        try:
            # Read /proc/cpuinfo for model
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                
            # Detect Pi model
            if 'Raspberry Pi Zero 2' in cpuinfo:
                model = 'Raspberry Pi Zero 2 W'
                recommended_profile = 'pi_zero_2w'
            elif 'Raspberry Pi 5' in cpuinfo:
                model = 'Raspberry Pi 5'
            elif 'Raspberry Pi 4' in cpuinfo:
                model = 'Raspberry Pi 4'
            elif 'Raspberry Pi 3' in cpuinfo:
                model = 'Raspberry Pi 3'
                
        except Exception as e:
            logger.warning(f"Could not read cpuinfo: {e}")
        
        # Detect RAM
        if psutil_available:
            try:
                mem = psutil.virtual_memory()
                ram_mb = int(mem.total / (1024 * 1024))
                
                # Match to closest profile
                if model == 'Raspberry Pi Zero 2 W':
                    recommended_profile = 'pi_zero_2w'
                elif model == 'Raspberry Pi 5':
                    if ram_mb >= 15000:
                        recommended_profile = 'pi_5_16gb'
                    elif ram_mb >= 7000:
                        recommended_profile = 'pi_5_8gb'
                    elif ram_mb >= 3500:
                        recommended_profile = 'pi_5_4gb'
                    else:
                        recommended_profile = 'pi_5_2gb'
                elif model == 'Raspberry Pi 4':
                    if ram_mb >= 7000:
                        recommended_profile = 'pi_4_8gb'
                    elif ram_mb >= 3500:
                        recommended_profile = 'pi_4_4gb'
                    elif ram_mb >= 1800:
                        recommended_profile = 'pi_4_2gb'
                    else:
                        recommended_profile = 'pi_4_1gb'
                        
            except Exception as e:
                logger.warning(f"Could not detect RAM: {e}")
        
        # Get CPU count
        cpu_count = psutil.cpu_count() if psutil_available else 1
        
        return jsonify({
            'model': model,
            'ram_mb': ram_mb,
            'ram_gb': round(ram_mb / 1024, 1),
            'cpu_count': cpu_count,
            'recommended_profile': recommended_profile,
            'detection_method': 'cpuinfo + psutil'
        })
        
    except Exception as e:
        logger.error(f"Error detecting hardware: {e}")
        return jsonify({
            'model': 'unknown',
            'ram_mb': 0,
            'ram_gb': 0,
            'cpu_count': 1,
            'recommended_profile': 'pi_zero_2w',
            'detection_method': 'fallback',
            'error': str(e)
        }), 200

@app.route('/api/config/apply-profile', methods=['POST'])
def apply_hardware_profile():
    """Apply a hardware profile to the system configuration"""
    try:
        data = request.get_json()
        profile_id = data.get('profile_id')
        
        if not profile_id:
            return jsonify({'error': 'No profile_id provided'}), 400
        
        # Get the profile
        profiles_response = get_hardware_profiles()
        profiles = profiles_response.get_json()
        
        if profile_id not in profiles:
            return jsonify({'error': f'Unknown profile: {profile_id}'}), 404
        
        profile = profiles[profile_id]
        settings = profile['settings']
        
        # Update configuration with profile settings
        for key, value in settings.items():
            shared_data.config[key] = value
        
        # Also store the applied profile info
        shared_data.config['hardware_profile'] = profile_id
        shared_data.config['hardware_profile_name'] = profile['name']
        shared_data.config['hardware_profile_applied'] = datetime.now().isoformat()
        
        # Save configuration
        shared_data.save_config()
        
        logger.info(f"Applied hardware profile: {profile['name']} ({profile_id})")
        
        # Emit update to all connected clients
        socketio.emit('config_updated', shared_data.config)
        
        return jsonify({
            'success': True,
            'message': f"Applied profile: {profile['name']}",
            'profile': profile,
            'restart_required': True
        })
        
    except Exception as e:
        logger.error(f"Error applying hardware profile: {e}")
        return jsonify({'error': str(e)}), 500


def load_persistent_network_data():
    """Load the WiFi-specific network data with fallbacks."""
    # Check for network switches and clear old data if needed
    check_and_handle_network_switch()
    
    update_wifi_network_data()

    network_data = read_wifi_network_data()

    def _extract_value(entry, keys):
        for key in keys:
            if isinstance(entry, dict) and key in entry:
                value = entry.get(key)
                if isinstance(value, str):
                    value = value.strip()
                if value not in (None, ''):
                    return value
        return ''

    netkb_data = []
    try:
        netkb_data = shared_data.read_data()
    except Exception as e:
        logger.error(f"Could not read netkb data for MAC enrichment: {e}")

    if network_data:
        ip_to_mac = {}
        enrichment_map = {}
        for row in netkb_data:
            ip = _extract_value(row, ("IPs", "IP", "ip"))
            mac = _extract_value(row, ("MAC Address", "MAC", "mac"))
            vuln_summary = _extract_value(row, ("Nmap Vulnerabilities", "nmap_vulnerabilities"))
            vuln_status = _extract_value(row, ("NmapVulnScanner", "nmap_vuln_scanner"))

            enrichment_payload = {
                'Nmap Vulnerabilities': vuln_summary or '',
                'NmapVulnScanner': vuln_status or ''
            }

            if ip and mac and mac.upper() not in {"UNKNOWN", "STANDALONE"}:
                ip_to_mac[ip] = mac

            if mac:
                enrichment_map[("mac", mac.lower())] = enrichment_payload
            if ip:
                enrichment_map[("ip", ip)] = enrichment_payload

        for entry in network_data:
            mac = _extract_value(entry, ("MAC Address", "MAC", "mac"))
            ip = _extract_value(entry, ("IPs", "IP", "ip"))
            if not mac or mac.upper() in {"UNKNOWN", "STANDALONE", "00:00:00:00:00:00"}:
                fallback_mac = ip_to_mac.get(ip)
                if fallback_mac:
                    mac = fallback_mac

            mac = mac or ''
            entry['MAC Address'] = mac
            entry['MAC'] = mac
            entry['mac'] = mac

            enrichment = enrichment_map.get(("mac", mac.lower())) if mac else None
            if not enrichment and ip:
                enrichment = enrichment_map.get(("ip", ip))

            if enrichment:
                entry['Nmap Vulnerabilities'] = enrichment.get('Nmap Vulnerabilities', '')
                entry['nmap_vulnerabilities'] = entry['Nmap Vulnerabilities']
                entry['NmapVulnScanner'] = enrichment.get('NmapVulnScanner', '')
                entry['nmap_vuln_scanner'] = entry['NmapVulnScanner']
            else:
                entry.setdefault('Nmap Vulnerabilities', '')
                entry.setdefault('nmap_vulnerabilities', '')
                entry.setdefault('NmapVulnScanner', '')
                entry.setdefault('nmap_vuln_scanner', '')
    else:
        logger.warning("WiFi-specific network data is empty. Falling back to netkb data.")
        if netkb_data:
            normalized_entries = []
            for row in netkb_data:
                ip = _extract_value(row, ("IPs", "IP", "ip"))
                if not ip:
                    continue
                mac = _extract_value(row, ("MAC Address", "MAC", "mac"))
                hostname = _extract_value(row, ("Hostnames", "Hostname", "hostnames", "hostname"))
                alive = _extract_value(row, ("Alive", "Status", "alive", "status")) or '0'
                ports = _extract_value(row, ("Ports", "Open Ports", "open_ports"))
                last_seen = _extract_value(row, ("LastSeen", "Last Seen", "last_seen"))
                vuln_summary = _extract_value(row, ("Nmap Vulnerabilities", "nmap_vulnerabilities"))
                vuln_status = _extract_value(row, ("NmapVulnScanner", "nmap_vuln_scanner"))

                normalized_entries.append({
                    'IPs': ip,
                    'Hostnames': hostname,
                    'Alive': alive,
                    'MAC Address': mac,
                    'MAC': mac,
                    'mac': mac,
                    'Ports': ports,
                    'LastSeen': last_seen,
                    'Nmap Vulnerabilities': vuln_summary or '',
                    'nmap_vulnerabilities': vuln_summary or '',
                    'NmapVulnScanner': vuln_status or '',
                    'nmap_vuln_scanner': vuln_status or ''
                })

            network_data = normalized_entries
            if network_data:
                logger.debug("Used netkb data as fallback.")
        else:
            network_data = []

    current_ssid = get_current_wifi_ssid()
    logger.info(f"Returning {len(network_data)} network entries for WiFi: {current_ssid}")
    return network_data


@app.route('/api/network/stable')
def get_stable_network_data():
    """Get stable, aggregated network data for the Network tab"""
    try:
        # Check for network switches and clear old data if needed
        check_and_handle_network_switch()
        
        # Read from the WiFi-specific network file for most stable data
        network_data = read_wifi_network_data()
        
        # Also get any recent ARP scan cache data
        recent_arp_data = network_scan_cache.get('arp_hosts', {})
        
        # Read NetKB data for additional enrichment (ports, MACs, etc.)
        netkb_data = []
        try:
            netkb_data = shared_data.read_data()
        except Exception as e:
            logger.warning(f"Could not read NetKB data for enrichment: {e}")
        
        # Create enrichment map from NetKB data
        netkb_enrichment = {}
        for entry in netkb_data:
            ip = entry.get('IPs', '').strip()
            if ip and ip not in ['STANDALONE']:
                netkb_enrichment[ip] = {
                    'mac': entry.get('MAC Address', '').strip(),
                    'hostname': entry.get('Hostnames', '').strip(),
                    'ports': entry.get('Ports', '').strip(),
                    'alive': entry.get('Alive', '0')
                }
        
        # Merge and enrich the data
        enriched_hosts = []
        processed_ips = set()
        
        # Process network data first (most stable)
        for entry in network_data:
            ip = entry.get('IPs', '').strip()  # Fixed: Use 'IPs' not 'IP'
            if not ip or ip in processed_ips:
                continue
                
            processed_ips.add(ip)
            
            host_data = {
                'ip': ip,
                'hostname': entry.get('Hostnames', '').strip() or 'Unknown',
                'mac': entry.get('MAC Address', '').strip() or 'Unknown',
                'status': 'up' if entry.get('Alive') in [True, 'True', '1', 1] else 'unknown',
                'ports': entry.get('Ports', '').strip() or 'Unknown',
                'vulnerabilities': str(entry.get('Vulnerabilities', '0')).strip() or '0',
                'last_scan': entry.get('LastSeen', '').strip() or 'Never',
                'first_seen': entry.get('First_Seen', '').strip() or 'Unknown',
                'os': entry.get('OS', '').strip() or 'Unknown',
                'services': entry.get('Services', '').strip() or 'Unknown',
                'source': 'network_data'
            }
            
            # Enhance with NetKB data if available
            if ip in netkb_enrichment:
                netkb_entry = netkb_enrichment[ip]
                # Use NetKB data to fill in missing information
                if netkb_entry.get('mac') and host_data['mac'] in ['Unknown', '00:00:00:00:00:00', '']:
                    host_data['mac'] = netkb_entry['mac']
                if netkb_entry.get('hostname') and host_data['hostname'] in ['Unknown', '']:
                    host_data['hostname'] = netkb_entry['hostname']
                if netkb_entry.get('ports') and host_data['ports'] in ['Unknown', '']:
                    host_data['ports'] = netkb_entry['ports']
                # Check if NetKB shows host as alive
                if netkb_entry.get('alive') in ['1', 1]:
                    host_data['status'] = 'up'
                    host_data['source'] = 'network_data+netkb'
            
            # Enhance with recent ARP data if available
            if ip in recent_arp_data:
                arp_entry = recent_arp_data[ip]
                if arp_entry.get('mac') and host_data['mac'] in ['Unknown', '00:00:00:00:00:00', '']:
                    host_data['mac'] = arp_entry['mac']
                if arp_entry.get('hostname') and host_data['hostname'] in ['Unknown', '']:
                    host_data['hostname'] = arp_entry['hostname']
                host_data['status'] = 'up'  # ARP means it's definitely up
                host_data['source'] = 'network_data+arp+netkb' if 'netkb' in host_data['source'] else 'network_data+arp'
            
            enriched_hosts.append(host_data)
        
        # Add any new ARP discoveries not in network data
        for ip, arp_entry in recent_arp_data.items():
            if ip not in processed_ips:
                host_data = {
                    'ip': ip,
                    'hostname': arp_entry.get('hostname', 'Unknown'),
                    'mac': arp_entry.get('mac', 'Unknown'),
                    'status': 'up',
                    'ports': 'Scanning...',
                    'vulnerabilities': '0',
                    'last_scan': 'Recently discovered',
                    'first_seen': 'Recent',
                    'os': 'Unknown',
                    'services': 'Unknown',
                    'source': 'arp_discovery'
                }
                enriched_hosts.append(host_data)
        
        # Sort by IP address for consistent display
        enriched_hosts.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
        
        response = jsonify({
            'success': True,
            'hosts': enriched_hosts,
            'count': len(enriched_hosts),
            'timestamp': datetime.now().isoformat(),
            'source': 'stable_aggregated'
        })
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"Error getting stable network data: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'hosts': [],
            'count': 0
        }), 500

@app.route('/api/network')
def get_network():
    """Get network scan data from the persistent WiFi-specific file."""
    try:
        network_data = load_persistent_network_data()
        response = jsonify(network_data)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    except Exception as e:
        logger.error(f"Error getting network data: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/credentials')
def get_credentials():
    """Get discovered credentials"""
    try:
        credentials = web_utils.get_all_credentials()
        return jsonify(credentials)
    except Exception as e:
        logger.error(f"Error getting credentials: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/loot')
def get_loot():
    """Get stolen data/loot"""
    try:
        loot = web_utils.get_loot_data()
        return jsonify(loot)
    except Exception as e:
        logger.error(f"Error getting loot: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    try:
        # Enhanced logging - aggregate from multiple sources
        all_logs = []
        
        # Get terminal log level filter from config - default to 'security' for focused logging
        terminal_log_level = shared_data.config.get('terminal_log_level', 'security')
        
        # 1. Get web console logs (existing functionality)
        log_file = shared_data.webconsolelog
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                web_logs = [line.strip() for line in lines[-50:] if line.strip()]
                all_logs.extend([f"[WEB] {log}" for log in web_logs])
        
        # 2. Get Ragnar main activity logs from data/logs directory
        logs_dir = shared_data.logsdir
        if os.path.exists(logs_dir):
            # Look for recent log files
            for log_filename in os.listdir(logs_dir):
                if log_filename.endswith('.log') or log_filename.endswith('.txt'):
                    log_path = os.path.join(logs_dir, log_filename)
                    try:
                        # Get file modification time to show recent files first
                        mod_time = os.path.getmtime(log_path)
                        # Only show logs from last 24 hours
                        if time.time() - mod_time < 86400:  # 24 hours
                            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                                recent_lines = [line.strip() for line in lines[-20:] if line.strip()]
                                source_tag = f"[{log_filename.upper().replace('.LOG', '').replace('.TXT', '')}]"
                                all_logs.extend([f"{source_tag} {log}" for log in recent_lines])
                    except Exception as e:
                        # Skip files that can't be read
                        continue
        
        # 3. Get recent discoveries from livestatus file
        if os.path.exists(shared_data.livestatusfile):
            try:
                import pandas as pd
                df = pd.read_csv(shared_data.livestatusfile)
                alive_hosts = df[df['Alive'] == 1] if 'Alive' in df.columns else df
                if not alive_hosts.empty:
                    recent_discoveries = []
                    for _, row in alive_hosts.tail(10).iterrows():
                        ip = row.get('IP', 'Unknown')
                        hostname = row.get('Hostname', ip)
                        ports = row.get('Ports', '')
                        if ports:
                            port_list = ports.split(';')[:5]  # Show first 5 ports
                            port_str = ', '.join(port_list)
                            if len(ports.split(';')) > 5:
                                port_str += f" (+{len(ports.split(';')) - 5} more)"
                            discovery_log = f"🎯 Discovered {hostname} ({ip}) - Ports: {port_str}"
                        else:
                            discovery_log = f"🎯 Discovered {hostname} ({ip}) - Host alive"
                        all_logs.append(f"[DISCOVERY] {discovery_log}")
            except Exception as e:
                all_logs.append(f"[DISCOVERY] Error reading discoveries: {str(e)}")
        
        # 4. Get recent credential findings
        for cred_file, service in [(shared_data.sshfile, 'SSH'), (shared_data.smbfile, 'SMB'), 
                                  (shared_data.ftpfile, 'FTP'), (shared_data.telnetfile, 'Telnet'),
                                  (shared_data.sqlfile, 'SQL'), (shared_data.rdpfile, 'RDP')]:
            if os.path.exists(cred_file):
                try:
                    import pandas as pd
                    df = pd.read_csv(cred_file)
                    if not df.empty:
                        recent_creds = df.tail(5)  # Last 5 credentials
                        for _, row in recent_creds.iterrows():
                            ip = row.get('ip', row.get('IP', 'Unknown'))
                            username = row.get('username', row.get('Username', 'Unknown'))
                            cred_log = f"🔓 {service} credentials found - {username}@{ip}"
                            all_logs.append(f"[CREDENTIALS] {cred_log}")
                except Exception:
                    continue
        
        # 5. Get recent vulnerability findings
        vuln_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
        if os.path.exists(vuln_dir):
            vuln_files = [f for f in os.listdir(vuln_dir) if f.endswith('.txt')]
            # Sort by modification time, get 3 most recent
            vuln_files.sort(key=lambda x: os.path.getmtime(os.path.join(vuln_dir, x)), reverse=True)
            for vuln_file in vuln_files[:3]:
                try:
                    vuln_path = os.path.join(vuln_dir, vuln_file)
                    with open(vuln_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Look for vulnerability indicators
                        if 'VULNERABLE' in content.upper() or 'CVE-' in content:
                            ip = vuln_file.replace('.txt', '').replace('vuln_', '')
                            vuln_log = f"⚠️ Vulnerabilities found on {ip}"
                            all_logs.append(f"[VULNERABILITIES] {vuln_log}")
                except Exception:
                    continue
        
        # 6. Add current status summary
        status_log = f"📊 Status: {safe_int(shared_data.targetnbr)} targets, {safe_int(shared_data.portnbr)} ports, {safe_int(shared_data.vulnnbr)} vulns, {safe_int(shared_data.crednbr)} creds"
        all_logs.append(f"[STATUS] {status_log}")
        
        # Filter logs based on terminal_log_level setting
        def should_include_log(log_line):
            """Filter logs to focus on security scanning activities"""
            if not log_line:
                return False
            
            log_lower = log_line.lower()
            log_upper = log_line.upper()
            
            # Exclude comment.py and other non-essential logs
            exclude_sources = [
                'comment.py', 'comments.py', 'comment_', 'comments_',
                'display.py', 'epd_helper.py', 'webapp_', 'flask',
                'socketio', 'werkzeug', 'http.server', 'static'
            ]
            
            if any(source in log_lower for source in exclude_sources):
                return False
            
            # Always include security scanning and vulnerability logs
            high_priority_keywords = [
                'nmap', 'scan', 'scanning', 'port scan', 'host discovery',
                'vulnerability', 'vuln', 'exploit', 'cve-', 'exploit-db',
                'credential', 'cred', 'password', 'login', 'auth',
                'ssh', 'ftp', 'smb', 'telnet', 'rdp', 'sql', 'mysql', 'postgres',
                'attack', 'brute', 'crack', 'penetration', 'pentest',
                'target', 'host found', 'port open', 'service', 'banner',
                'network intelligence', 'threat intelligence', 'orchestrator'
            ]
            
            if any(keyword in log_lower for keyword in high_priority_keywords):
                return True
            
            # Check for error indicators (always important)
            is_error = any(keyword in log_upper for keyword in [
                'ERROR', 'CRITICAL', 'EXCEPTION', 'FAILED', 'FAILURE'
            ])
            
            if is_error:
                return True
            
            # Check for important discovery indicators
            is_discovery = any(keyword in log_upper for keyword in [
                'DISCOVERED', 'FOUND', 'CREDENTIALS', 'VULNERABILITIES', 
                'DISCOVERY', 'SUCCESS'
            ])
            
            if is_discovery:
                return True
            
            # Filter based on terminal_log_level setting for other logs
            if terminal_log_level == 'error':
                return is_error
            elif terminal_log_level == 'info':
                return is_error or is_discovery
            elif terminal_log_level == 'security':
                # Security mode: show only security-related logs (default)
                return True  # Already filtered by high_priority_keywords above
            elif terminal_log_level == 'all':
                return True
            
            # Default to security mode: be more selective to reduce noise
            return True  # Already filtered by high_priority_keywords above
        
        # Apply filtering
        filtered_logs = [log for log in all_logs if should_include_log(log)]
        
        # Sort logs by timestamp if possible, otherwise keep recent additions at the end
        # Limit to last 150 entries for security-focused logging
        recent_logs = filtered_logs[-150:] if filtered_logs else []
        
        return jsonify({'logs': recent_logs})
    except Exception as e:
        logger.error(f"Error getting enhanced logs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs/activity')
def get_activity_logs():
    """Get detailed activity logs showing discoveries, attacks, and results"""
    try:
        activity_logs = []
        current_time = datetime.now()
        
        # 1. Recent network discoveries
        if os.path.exists(shared_data.livestatusfile):
            try:
                import pandas as pd
                df = pd.read_csv(shared_data.livestatusfile)
                alive_hosts = df[df['Alive'] == 1] if 'Alive' in df.columns else df
                for _, row in alive_hosts.tail(15).iterrows():
                    ip = row.get('IP', 'Unknown')
                    hostname = row.get('Hostname', ip)
                    ports = row.get('Ports', '')
                    mac = row.get('MAC', 'Unknown')
                    
                    if ports:
                        port_list = ports.split(';')
                        service_summary = f"{len(port_list)} services"
                        if len(port_list) <= 5:
                            service_summary = f"Ports: {', '.join(port_list)}"
                    else:
                        service_summary = "Host responsive"
                    
                    log_entry = {
                        'timestamp': current_time.strftime("%H:%M:%S"),
                        'type': 'discovery',
                        'icon': '🎯',
                        'message': f"Discovered {hostname} ({ip})",
                        'details': f"MAC: {mac} | {service_summary}",
                        'severity': 'info'
                    }
                    activity_logs.append(log_entry)
            except Exception as e:
                activity_logs.append({
                    'timestamp': current_time.strftime("%H:%M:%S"),
                    'type': 'error',
                    'icon': '❌',
                    'message': f"Error reading discoveries: {str(e)}",
                    'details': '',
                    'severity': 'error'
                })
        
        # 2. Recent credential findings
        cred_sources = [
            (shared_data.sshfile, 'SSH', '🔐'),
            (shared_data.smbfile, 'SMB', '📁'),
            (shared_data.ftpfile, 'FTP', '📂'),
            (shared_data.telnetfile, 'Telnet', '💻'),
            (shared_data.sqlfile, 'SQL', '🗄️'),
            (shared_data.rdpfile, 'RDP', '🖥️')
        ]
        
        for cred_file, service, icon in cred_sources:
            if os.path.exists(cred_file):
                try:
                    import pandas as pd
                    df = pd.read_csv(cred_file)
                    if not df.empty:
                        recent_creds = df.tail(5)
                        for _, row in recent_creds.iterrows():
                            ip = row.get('ip', row.get('IP', 'Unknown'))
                            username = row.get('username', row.get('Username', 'Unknown'))
                            password = row.get('password', row.get('Password', '***'))
                            port = row.get('port', row.get('Port', ''))
                            
                            port_info = f":{port}" if port else ""
                            log_entry = {
                                'timestamp': current_time.strftime("%H:%M:%S"),
                                'type': 'credential',
                                'icon': icon,
                                'message': f"{service} access gained on {ip}{port_info}",
                                'details': f"Username: {username} | Password: {'*' * min(len(str(password)), 8)}",
                                'severity': 'success'
                            }
                            activity_logs.append(log_entry)
                except Exception:
                    continue
        
        # 3. Recent vulnerability findings
        vuln_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
        if os.path.exists(vuln_dir):
            vuln_files = [f for f in os.listdir(vuln_dir) if f.endswith('.txt')]
            vuln_files.sort(key=lambda x: os.path.getmtime(os.path.join(vuln_dir, x)), reverse=True)
            
            for vuln_file in vuln_files[:5]:
                try:
                    vuln_path = os.path.join(vuln_dir, vuln_file)
                    with open(vuln_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    ip = vuln_file.replace('.txt', '').replace('vuln_', '')
                    vuln_count = content.upper().count('VULNERABLE')
                    cve_count = content.count('CVE-')
                    
                    if vuln_count > 0 or cve_count > 0:
                        severity_icon = '🚨' if vuln_count > 5 else '⚠️'
                        severity = 'critical' if vuln_count > 5 else 'warning'
                        
                        details = []
                        if vuln_count > 0:
                            details.append(f"{vuln_count} vulnerabilities")
                        if cve_count > 0:
                            details.append(f"{cve_count} CVEs")
                        
                        log_entry = {
                            'timestamp': current_time.strftime("%H:%M:%S"),
                            'type': 'vulnerability',
                            'icon': severity_icon,
                            'message': f"Vulnerabilities found on {ip}",
                            'details': " | ".join(details),
                            'severity': severity
                        }
                        activity_logs.append(log_entry)
                except Exception:
                    continue
        
        # 4. Current system status
        status_entries = []
        if safe_str(shared_data.ragnarstatustext) and safe_str(shared_data.ragnarstatustext) != "Idle":
            status_entries.append({
                'timestamp': current_time.strftime("%H:%M:%S"),
                'type': 'status',
                'icon': '🤖',
                'message': f"Ragnar: {safe_str(shared_data.ragnarstatustext)}",
                'details': safe_str(shared_data.ragnarstatustext2) if safe_str(shared_data.ragnarstatustext2) else '',
                'severity': 'info'
            })
        
        if safe_str(shared_data.ragnarsays) and safe_str(shared_data.ragnarsays).strip():
            status_entries.append({
                'timestamp': current_time.strftime("%H:%M:%S"),
                'type': 'activity',
                'icon': '⚡',
                'message': safe_str(shared_data.ragnarsays),
                'details': '',
                'severity': 'info'
            })
        
        activity_logs.extend(status_entries)
        
        # Sort by timestamp and limit to 50 most recent entries
        activity_logs = activity_logs[-50:]
        
        return jsonify({'activity_logs': activity_logs})
        
    except Exception as e:
        logger.error(f"Error getting activity logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/verbose-logs')
def get_verbose_debug_logs():
    """Get super verbose debugging logs for tracing data flow issues"""
    try:
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'system_state': {},
            'data_sources': {},
            'cache_state': {},
            'sync_information': {},
            'file_operations': {},
            'api_traces': [],
            'errors_and_warnings': []
        }
        
        # === SYSTEM STATE DEBUGGING ===
        debug_info['system_state'] = {
            'shared_data_targetnbr': getattr(shared_data, 'targetnbr', 'NOT_SET'),
            'shared_data_total_targetnbr': getattr(shared_data, 'total_targetnbr', 'NOT_SET'),
            'shared_data_inactive_targetnbr': getattr(shared_data, 'inactive_targetnbr', 'NOT_SET'),
            'shared_data_portnbr': getattr(shared_data, 'portnbr', 'NOT_SET'),
            'shared_data_vulnnbr': getattr(shared_data, 'vulnnbr', 'NOT_SET'),
            'shared_data_crednbr': getattr(shared_data, 'crednbr', 'NOT_SET'),
            'shared_data_levelnbr': getattr(shared_data, 'levelnbr', 'NOT_SET'),
            'shared_data_coinnbr': getattr(shared_data, 'coinnbr', 'NOT_SET'),
        }
        
        # === DATA SOURCES DEBUGGING ===
        try:
            # WiFi network data
            wifi_network_file = get_wifi_specific_network_file()
            debug_info['data_sources']['wifi_network_file'] = {
                'path': wifi_network_file,
                'exists': os.path.exists(wifi_network_file),
                'size_bytes': os.path.getsize(wifi_network_file) if os.path.exists(wifi_network_file) else 0,
                'modified_time': datetime.fromtimestamp(os.path.getmtime(wifi_network_file)).isoformat() if os.path.exists(wifi_network_file) else 'N/A'
            }
            
            # Read and analyze wifi network data
            network_data = read_wifi_network_data()
            debug_info['data_sources']['wifi_network_data'] = {
                'total_entries': len(network_data),
                'alive_entries': len([entry for entry in network_data if entry.get('Alive') in [True, 'True', '1', 1]]),
                'sample_entries': network_data[:3] if network_data else [],
                'all_alive_values': list(set([str(entry.get('Alive', 'MISSING')) for entry in network_data])),
                'ip_list': [entry.get('IPs', 'NO_IP') for entry in network_data[:10]]
            }
            
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error reading WiFi network data: {str(e)}")
        
        try:
            # NetKB data
            netkb_data = shared_data.read_data()
            netkb_file_path = getattr(shared_data, 'netkbfile', 'NOT_SET')
            debug_info['data_sources']['netkb_data'] = {
                'total_entries': len(netkb_data),
                'alive_entries': len([entry for entry in netkb_data if entry.get('Alive') in ['1', 1]]),
                'sample_entries': netkb_data[:3] if netkb_data else [],
                'all_alive_values': list(set([str(entry.get('Alive', 'MISSING')) for entry in netkb_data])),
                'file_path': netkb_file_path,
                'file_exists': os.path.exists(netkb_file_path) if netkb_file_path != 'NOT_SET' else False
            }
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error reading NetKB data: {str(e)}")
        
        # === CACHE STATE DEBUGGING ===
        debug_info['cache_state'] = {
            'network_scan_cache_keys': list(network_scan_cache.keys()),
            'arp_hosts_count': len(network_scan_cache.get('arp_hosts', {})),
            'arp_hosts_sample': dict(list(network_scan_cache.get('arp_hosts', {}).items())[:5]),
            'last_arp_scan_time': network_scan_cache.get('last_arp_scan', 'NEVER'),
            'cache_size': len(str(network_scan_cache)),
            'network_scan_last_update': network_scan_last_update,
            'arp_scan_interval': ARP_SCAN_INTERVAL,
            'current_time': time.time(),
            'time_since_last_cache_update': time.time() - network_scan_last_update if network_scan_last_update else 'NEVER'
        }
        
        # Test ARP scan directly
        try:
            debug_info['api_traces'].append("=== TESTING ARP SCAN DIRECTLY ===")
            test_arp_result = run_arp_scan_localnet('wlan0')
            debug_info['cache_state']['direct_arp_test'] = {
                'success': bool(test_arp_result),
                'host_count': len(test_arp_result) if test_arp_result else 0,
                'sample_results': dict(list(test_arp_result.items())[:3]) if test_arp_result else {}
            }
            debug_info['api_traces'].append(f"Direct ARP test found {len(test_arp_result) if test_arp_result else 0} hosts")
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error testing ARP scan directly: {str(e)}")
            debug_info['cache_state']['direct_arp_test'] = {'error': str(e)}
        
        # === SYNC INFORMATION ===
        debug_info['sync_information'] = {
            'last_sync_time': getattr(shared_data, 'last_sync_timestamp', 'NOT_SET'),
            'sync_lock_acquired': sync_lock.locked() if sync_lock else 'NO_LOCK',
            'sync_background_interval': SYNC_BACKGROUND_INTERVAL,
            'current_time': time.time(),
            'time_since_last_sync': time.time() - getattr(shared_data, 'last_sync_timestamp', 0) if hasattr(shared_data, 'last_sync_timestamp') else 'UNKNOWN'
        }
        
        # === BACKGROUND THREAD HEALTH ===
        debug_info['background_thread_health'] = {
            'sync_thread': {
                'last_run': background_thread_health.get('sync_last_run', 0),
                'last_run_ago_seconds': time.time() - background_thread_health.get('sync_last_run', 0) if background_thread_health.get('sync_last_run', 0) > 0 else 'NEVER',
                'alive': background_thread_health.get('sync_alive', False),
                'status': '✅ HEALTHY' if background_thread_health.get('sync_alive', False) else '⚠️ POSSIBLY STUCK'
            },
            'arp_thread': {
                'last_run': background_thread_health.get('arp_last_run', 0),
                'last_run_ago_seconds': time.time() - background_thread_health.get('arp_last_run', 0) if background_thread_health.get('arp_last_run', 0) > 0 else 'NEVER',
                'alive': background_thread_health.get('arp_alive', False),
                'status': '✅ HEALTHY' if background_thread_health.get('arp_alive', False) else '⚠️ POSSIBLY STUCK'
            },
            'health_monitor': {
                'enabled': True,
                'check_interval_seconds': 15
            }
        }
        
        # === FILE OPERATIONS DEBUGGING ===
        try:
            # Check key files
            important_files = [
                shared_data.network_file if hasattr(shared_data, 'network_file') else 'NOT_SET',
                shared_data.webconsolelog if hasattr(shared_data, 'webconsolelog') else 'NOT_SET',
                get_wifi_specific_network_file()
            ]
            
            debug_info['file_operations'] = {}
            for file_path in important_files:
                if file_path != 'NOT_SET' and file_path:
                    try:
                        debug_info['file_operations'][file_path] = {
                            'exists': os.path.exists(file_path),
                            'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                            'readable': os.access(file_path, os.R_OK) if os.path.exists(file_path) else False,
                            'writable': os.access(file_path, os.W_OK) if os.path.exists(file_path) else False,
                            'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat() if os.path.exists(file_path) else 'N/A'
                        }
                    except Exception as e:
                        debug_info['file_operations'][file_path] = {'error': str(e)}
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error checking file operations: {str(e)}")
        
        # === API TRACES ===
        # Simulate the dashboard stats calculation to trace the issue
        try:
            debug_info['api_traces'].append("=== DASHBOARD STATS CALCULATION TRACE ===")
            
            # Step 1: Read network data
            network_data = read_wifi_network_data()
            debug_info['api_traces'].append(f"Step 1: Read {len(network_data)} entries from WiFi network file")
            
            # Step 2: Get ARP cache
            recent_arp_data = network_scan_cache.get('arp_hosts', {})
            debug_info['api_traces'].append(f"Step 2: Found {len(recent_arp_data)} entries in ARP cache")
            
            # Step 3: Process network data
            processed_ips = set()
            active_hosts_count = 0
            
            for i, entry in enumerate(network_data[:5]):  # Trace first 5 entries
                ip = entry.get('IPs', '').strip()
                alive_status = entry.get('Alive')
                is_in_arp = ip in recent_arp_data
                debug_info['api_traces'].append(f"Entry {i}: IP={ip}, Alive={alive_status} (type: {type(alive_status)}), InARP={is_in_arp}")
                
                if ip and ip not in processed_ips:
                    processed_ips.add(ip)
                    is_alive_in_file = alive_status in [True, 'True', '1', 1]
                    is_alive_in_arp = ip in recent_arp_data
                    is_alive = is_alive_in_file or is_alive_in_arp
                    debug_info['api_traces'].append(f"  -> IP {ip} processed, alive_file={is_alive_in_file}, alive_arp={is_alive_in_arp}, final_alive={is_alive}")
                    if is_alive:
                        active_hosts_count += 1
                        debug_info['api_traces'].append(f"  -> Active count increased to {active_hosts_count}")
            
            # Step 4: Process ARP data
            for ip in list(recent_arp_data.keys())[:5]:  # Trace first 5 ARP entries
                if ip not in processed_ips:
                    processed_ips.add(ip)
                    active_hosts_count += 1
                    debug_info['api_traces'].append(f"ARP: Added {ip} as active (count: {active_hosts_count})")
            
            debug_info['api_traces'].append(f"FINAL COUNTS: Active={active_hosts_count}, Total={len(processed_ips)}")
            
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error in API trace: {str(e)}")
        
        # === RECENT LOG ENTRIES ===
        try:
            log_file = shared_data.webconsolelog if hasattr(shared_data, 'webconsolelog') else None
            if log_file and os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    recent_lines = f.readlines()[-20:]  # Last 20 log lines
                    debug_info['recent_logs'] = recent_lines
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error reading recent logs: {str(e)}")
        
        # === THREAT INTELLIGENCE STATUS ===
        try:
            debug_info['threat_intelligence'] = {
                'system_enabled': threat_intelligence is not None,
                'vulnerability_count': safe_int(shared_data.vulnnbr),
                'findings_need_vulnerabilities': 'Threat Intelligence needs discovered vulnerabilities to enrich',
                'manual_scan_available': True,
                'sample_enrichment_test': 'Try: POST /api/threat-intelligence/enrich-target with {"target": "192.168.1.1", "target_type": "ip"}'
            }
            
            if threat_intelligence:
                # Test threat intelligence status
                ti_status = {
                    'cache_entries': len(getattr(threat_intelligence, 'threat_cache', {})),
                    'sources_count': len(getattr(threat_intelligence, 'sources', [])),
                    'last_update': getattr(threat_intelligence, 'last_update', 'Never')
                }
                debug_info['threat_intelligence']['system_status'] = ti_status
        except Exception as e:
            debug_info['errors_and_warnings'].append(f"Error checking threat intelligence: {str(e)}")
        
        # Force fresh timestamp and prevent caching
        debug_info['timestamp'] = datetime.now().isoformat()
        debug_info['generated_at'] = time.time()
        
        response = jsonify(debug_info)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"Error in verbose debug logs: {e}")
        return jsonify({'error': str(e), 'timestamp': datetime.now().isoformat()}), 500

@app.route('/api/debug/test-robust-tracking')
def test_robust_tracking():
    """Test endpoint to verify robust tracking logic is working"""
    try:
        logger.info("[TEST] Robust tracking test endpoint called")
        
        # Test the network data reading with new logic
        network_data = read_wifi_network_data()
        
        # Count devices by failure status
        max_failed_pings = shared_data.config.get('network_max_failed_pings', 15)  # Changed to 15 for more stability
        results = {
            'total_devices': len(network_data),
            'devices_with_failure_data': 0,
            'devices_exceeding_failure_limit': 0,
            'devices_active_by_robust_rule': 0,
            'max_failed_pings_threshold': max_failed_pings,
            'sample_devices': [],
            'test_timestamp': datetime.now().isoformat()
        }
        
        for entry in network_data[:5]:  # Sample first 5
            ip = entry.get('IPs', '')
            failed_ping_count = entry.get('FailedPingCount', 'N/A')
            alive_status = entry.get('Alive', 'N/A')
            
            if isinstance(failed_ping_count, int):
                results['devices_with_failure_data'] += 1
                if failed_ping_count >= max_failed_pings:
                    results['devices_exceeding_failure_limit'] += 1
                else:
                    results['devices_active_by_robust_rule'] += 1
            
            results['sample_devices'].append({
                'ip': ip,
                'failed_ping_count': failed_ping_count,
                'alive': alive_status,
                'would_be_removed': failed_ping_count >= max_failed_pings if isinstance(failed_ping_count, int) else False
            })
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error in robust tracking test: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/debug/connectivity-tracking')
def get_connectivity_tracking():
    """Get detailed connectivity tracking information for all devices"""
    try:
        wifi_network_data = read_wifi_network_data()
        current_time = datetime.now()
        arp_hosts = network_scan_cache.get('arp_hosts', {})
        
        connectivity_info = {
            'timestamp': current_time.isoformat(),
            'summary': {
                'total_devices': len(wifi_network_data),
                'devices_in_arp': len(arp_hosts),
                'max_failed_pings': shared_data.config.get('network_max_failed_pings', 15)  # Changed to 15 for more stability
            },
            'devices': []
        }
        
        for entry in wifi_network_data:
            ip = entry.get('IPs', '').strip()
            if not ip:
                continue
                
            device_info = {
                'ip': ip,
                'hostname': entry.get('Hostnames', ''),
                'mac': entry.get('MAC Address', ''),
                'alive': entry.get('Alive', 0),
                'failed_ping_count': entry.get('failed_ping_count', 0),
                'last_seen': entry.get('LastSeen', ''),
                'last_successful_ping': entry.get('last_successful_ping', ''),
                'last_ping_attempt': entry.get('last_ping_attempt', ''),
                'in_current_arp': ip in arp_hosts,
                'connectivity_status': 'stable' if entry.get('failed_ping_count', 0) == 0 else f"failing ({entry.get('failed_ping_count', 0)}/{shared_data.config.get('network_max_failed_pings', 15)})"  # Changed to 15
            }
            
            # Calculate time since last successful ping
            if device_info['last_successful_ping']:
                try:
                    last_success = datetime.fromisoformat(device_info['last_successful_ping'])
                    time_diff = current_time - last_success
                    device_info['minutes_since_last_success'] = int(time_diff.total_seconds() / 60)
                except Exception:
                    device_info['minutes_since_last_success'] = 'unknown'
            else:
                device_info['minutes_since_last_success'] = 'never'
                
            connectivity_info['devices'].append(device_info)
        
        # Sort by IP address
        connectivity_info['devices'].sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
        
        response = jsonify(connectivity_info)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"Error getting connectivity tracking info: {e}")
        return jsonify({'error': str(e), 'timestamp': datetime.now().isoformat()}), 500

@app.route('/api/debug/force-arp-scan', methods=['POST'])
def force_arp_scan():
    """Force an ARP scan and update the cache manually for debugging"""
    try:
        global network_scan_cache, network_scan_last_update
        
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'operation': 'force_arp_scan',
            'steps': []
        }
        
        debug_info['steps'].append("Step 1: Running ARP scan...")
        arp_hosts = run_arp_scan_localnet('wlan0')
        debug_info['steps'].append(f"Step 2: Found {len(arp_hosts) if arp_hosts else 0} hosts")
        
        if arp_hosts:
            debug_info['steps'].append("Step 3: Updating cache...")
            current_time = time.time()
            network_scan_cache['arp_hosts'] = arp_hosts
            network_scan_cache['last_arp_scan'] = current_time
            network_scan_last_update = current_time
            debug_info['steps'].append("Step 4: Cache updated successfully")
            
            debug_info['steps'].append("Step 5: Updating NetKB entries...")
            for ip, data in arp_hosts.items():
                update_netkb_entry(ip, data.get('hostname', ''), data.get('mac', ''), True)
            debug_info['steps'].append(f"Step 6: Updated {len(arp_hosts)} NetKB entries")
            
            debug_info['results'] = {
                'cache_updated': True,
                'hosts_found': arp_hosts,
                'cache_state': {
                    'arp_hosts_count': len(network_scan_cache.get('arp_hosts', {})),
                    'last_arp_scan_time': network_scan_cache.get('last_arp_scan', 'NEVER')
                }
            }
        else:
            debug_info['steps'].append("Step 3: No hosts found, cache not updated")
            debug_info['results'] = {
                'cache_updated': False,
                'hosts_found': {},
                'error': 'No hosts discovered'
            }
        
        return jsonify(debug_info)
        
    except Exception as e:
        logger.error(f"Error in force ARP scan: {e}")
        return jsonify({'error': str(e), 'timestamp': datetime.now().isoformat()}), 500

@app.route('/api/threat-intelligence/trigger-vuln-scan', methods=['POST'])
def trigger_vulnerability_scan_for_threat_intel():
    """Trigger vulnerability scanning to generate data for threat intelligence enrichment"""
    try:
        # Get the request data
        data = request.get_json() if request.is_json else {}
        target = data.get('target', 'all')
        
        # Get discovered hosts count for feedback
        network_data = read_wifi_network_data()
        recent_arp_data = network_scan_cache.get('arp_hosts', {})
        total_hosts = len(set([entry.get('IPs', '') for entry in network_data if entry.get('IPs')] + list(recent_arp_data.keys())))
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'action': 'vulnerability_scan_triggered',
            'target': target,
            'discovered_hosts': total_hosts,
            'message': f'Vulnerability scan initiated for {total_hosts} discovered hosts',
            'next_steps': [
                'Vulnerability scanning is running in the background',
                'Results will appear in the Network tab when complete',
                'Threat intelligence will enrich any discovered vulnerabilities',
                'Check back in 2-5 minutes for results'
            ]
        }
        
        # Trigger the actual vulnerability scan by calling the existing endpoint
        try:
            from urllib.parse import urljoin
            import requests
            base_url = request.host_url
            scan_url = urljoin(base_url, '/api/manual/scan/vulnerability')
            
            scan_response = requests.post(
                scan_url,
                json={'target': target},
                timeout=5
            )
            
            if scan_response.status_code == 200:
                result['scan_status'] = 'success'
                result['scan_response'] = scan_response.json()
            else:
                result['scan_status'] = 'warning'
                result['scan_response'] = f'Scan request returned status {scan_response.status_code}'
                
        except Exception as scan_error:
            result['scan_status'] = 'initiated'
            result['scan_note'] = 'Vulnerability scan triggered via orchestrator'
            logger.info(f"Vulnerability scan trigger: {str(scan_error)}")
            
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error triggering vulnerability scan for threat intel: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'suggestion': 'Try using the Manual mode to trigger vulnerability scans'
        }), 500

# ============================================================================
# REAL-TIME SCANNING ENDPOINTS
# ============================================================================

def run_arp_scan_localnet(interface='wlan0'):
    """Run arp-scan on local network to discover active hosts"""
    command = ['sudo', 'arp-scan', f'--interface={interface}', '--localnet']
    logger.info(f"Running arp-scan localnet: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return _parse_arp_scan_output(result.stdout)
        else:
            logger.warning(f"arp-scan failed with return code {result.returncode}: {result.stderr}")
            return {}
    except FileNotFoundError:
        logger.warning("arp-scan command not found")
        return {}
    except subprocess.TimeoutExpired as e:
        logger.warning(f"arp-scan timed out: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error running arp-scan: {e}")
        return {}

def run_nmap_ping_scan(network='192.168.1.0/24'):
    """Run nmap ping scan to discover active hosts"""
    command = ['sudo', 'nmap', '-sn', '-PR', network]
    logger.info(f"Running nmap ping scan: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return _parse_nmap_ping_output(result.stdout)
        else:
            logger.warning(f"nmap ping scan failed with return code {result.returncode}: {result.stderr}")
            return {}
    except FileNotFoundError:
        logger.warning("nmap command not found")
        return {}
    except subprocess.TimeoutExpired as e:
        logger.warning(f"nmap ping scan timed out: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error running nmap ping scan: {e}")
        return {}

def _parse_nmap_ping_output(output):
    """Parse nmap ping scan output to extract IP addresses and MAC addresses"""
    hosts = {}
    current_ip = None
    
    for line in output.splitlines():
        line = line.strip()
        
        # Look for "Nmap scan report for" lines to get IP addresses
        if line.startswith('Nmap scan report for'):
            # Extract IP from line like "Nmap scan report for 192.168.1.1"
            parts = line.split()
            if len(parts) >= 5:
                ip_part = parts[-1]
                if '(' in ip_part and ')' in ip_part:
                    # Format: "hostname (192.168.1.1)"
                    current_ip = ip_part.strip('()')
                else:
                    # Format: "192.168.1.1"
                    current_ip = ip_part
                
                if _is_valid_ipv4(current_ip):
                    hosts[current_ip] = {
                        'ip': current_ip,
                        'mac': '',
                        'hostname': '',
                        'status': 'up'
                    }
        
        # Look for MAC address lines
        elif line.startswith('MAC Address:') and current_ip:
            # Extract MAC from line like "MAC Address: 00:11:22:33:44:55 (Vendor)"
            parts = line.split()
            if len(parts) >= 3:
                mac = parts[2]
                if MAC_REGEX.match(mac):
                    hosts[current_ip]['mac'] = _normalize_mac(mac)
                    # Extract vendor info if available
                    if '(' in line and ')' in line:
                        vendor_start = line.find('(')
                        vendor_end = line.find(')')
                        if vendor_start < vendor_end:
                            vendor = line[vendor_start+1:vendor_end]
                            hosts[current_ip]['vendor'] = vendor
    
    return hosts

# Global variables for network scanning
network_scan_cache = {}
network_scan_last_update = 0
ARP_SCAN_INTERVAL = 10  # seconds

@app.route('/api/scan/arp-localnet')
def get_arp_scan_localnet():
    """Get ARP scan results for local network"""
    try:
        interface = request.args.get('interface', 'wlan0')
        hosts = run_arp_scan_localnet(interface)
        
        return jsonify({
            'success': True,
            'hosts': hosts,
            'count': len(hosts),
            'interface': interface,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in ARP scan endpoint: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'hosts': {},
            'count': 0
        }), 500

@app.route('/api/scan/nmap-ping')
def get_nmap_ping_scan():
    """Get nmap ping scan results"""
    try:
        network = request.args.get('network', '192.168.1.0/24')
        hosts = run_nmap_ping_scan(network)
        
        return jsonify({
            'success': True,
            'hosts': hosts,
            'count': len(hosts),
            'network': network,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in nmap ping scan endpoint: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'hosts': {},
            'count': 0
        }), 500

@app.route('/api/scan/combined-network')
def get_combined_network_scan():
    """Get combined results from both ARP and nmap scans"""
    try:
        interface = request.args.get('interface', 'wlan0')
        network = request.args.get('network', '192.168.1.0/24')
        
        # Run both scans
        arp_hosts = run_arp_scan_localnet(interface)
        nmap_hosts = run_nmap_ping_scan(network)
        
        # Combine results, preferring ARP data when available
        combined_hosts = {}
        
        # Start with nmap results
        for ip, data in nmap_hosts.items():
            combined_hosts[ip] = {
                'ip': ip,
                'mac': data.get('mac', ''),
                'hostname': data.get('hostname', ''),
                'status': data.get('status', 'up'),
                'vendor': data.get('vendor', ''),
                'source': 'nmap'
            }
        
        # Overlay ARP results (more reliable for MAC addresses)
        for ip, data in arp_hosts.items():
            if ip in combined_hosts:
                # Update existing entry with ARP data
                combined_hosts[ip]['mac'] = data.get('mac', combined_hosts[ip]['mac'])
                combined_hosts[ip]['hostname'] = data.get('hostname', combined_hosts[ip]['hostname'])
                combined_hosts[ip]['source'] = 'arp+nmap'
            else:
                # Add new entry from ARP
                combined_hosts[ip] = {
                    'ip': ip,
                    'mac': data.get('mac', ''),
                    'hostname': data.get('hostname', ''),
                    'status': 'up',
                    'vendor': data.get('vendor', ''),
                    'source': 'arp'
                }
        
        # Update network knowledge base
        for ip, data in combined_hosts.items():
            update_netkb_entry(ip, data.get('hostname', ''), data.get('mac', ''), True)
        
        return jsonify({
            'success': True,
            'hosts': combined_hosts,
            'count': len(combined_hosts),
            'arp_count': len(arp_hosts),
            'nmap_count': len(nmap_hosts),
            'interface': interface,
            'network': network,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in combined network scan endpoint: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'hosts': {},
            'count': 0
        }), 500

@app.route('/api/scan/start-realtime', methods=['POST'])
def start_realtime_scan():
    """Start real-time vulnerability scanning"""
    try:
        data = request.get_json() or {}
        scan_type = data.get('type', 'all')  # 'all', 'single', 'network'
        target = data.get('target', None)
        
        if scan_type == 'single' and target:
            # Start single host scan
            def scan_callback(event_type, event_data):
                socketio.emit('scan_update', {
                    'type': event_type,
                    'data': event_data
                })
            
            # Run scan in background thread
            def run_single_scan():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner
                    scanner = NmapVulnScanner(shared_data)
                    result = scanner.scan_single_host_realtime(
                        ip=target.get('ip', ''),
                        hostname=target.get('hostname', ''),
                        mac=target.get('mac', ''),
                        ports=target.get('ports', ''),
                        callback=scan_callback
                    )
                except Exception as e:
                    scan_callback('scan_error', {'error': str(e)})
            
            threading.Thread(target=run_single_scan, daemon=True).start()
            
        elif scan_type == 'all':
            # Start full network scan
            def scan_callback(event_type, event_data):
                socketio.emit('scan_update', {
                    'type': event_type,
                    'data': event_data
                })
            
            # Run scan in background thread
            def run_full_scan():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner
                    scanner = NmapVulnScanner(shared_data)
                    scanner.force_scan_all_hosts(real_time_callback=scan_callback)
                except Exception as e:
                    scan_callback('scan_error', {'error': str(e)})
            
            threading.Thread(target=run_full_scan, daemon=True).start()
        
        return jsonify({'status': 'success', 'message': 'Scan started'})
        
    except Exception as e:
        logger.error(f"Error starting real-time scan: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scan/status')
def get_scan_status():
    """Get current scanning status"""
    try:
        # Check if any scans are running by looking at orchestrator status
        scan_status = {
            'scanning': False,
            'current_target': None,
            'progress': 0,
            'total_hosts': 0,
            'completed_hosts': 0
        }
        
        # You can enhance this by checking actual scan status
        # For now, return basic status
        
        return jsonify({'status': 'success', 'data': scan_status})
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/scan/host', methods=['POST'])
def scan_single_host():
    """Scan a single host"""
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'status': 'error', 'message': 'IP address is required'}), 400
        
        ip = data['ip']

        # Validate IP address format
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address format'}), 400

        # Start single host scan in background thread
        def scan_host_background():
            def run_nmap_fallback():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner

                    scanner = NmapVulnScanner(shared_data)

                    def callback(event_type, event_data):
                        payload = {'type': event_type}
                        if isinstance(event_data, dict):
                            payload.update(event_data)
                        socketio.emit('scan_host_update', payload)

                    scanner.scan_single_host_realtime(ip, callback=callback)
                except Exception as fallback_error:
                    logger.error(f"Fallback nmap scan failed for {ip}: {fallback_error}")
                    socketio.emit('scan_host_update', {
                        'type': 'sep_scan_error',
                        'ip': ip,
                        'message': f'Nmap fallback failed: {fallback_error}'
                    })

            try:
                logger.info(f"Running sep-scan for {ip}")
                command = SEP_SCAN_COMMAND + [ip]
                result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)

                stdout_lines = result.stdout.splitlines() if result.stdout else []
                stderr_lines = result.stderr.splitlines() if result.stderr else []

                for line in stdout_lines:
                    line = line.strip()
                    if line:
                        socketio.emit('scan_host_update', {
                            'type': 'sep_scan_output',
                            'ip': ip,
                            'message': line
                        })

                for line in stderr_lines:
                    line = line.strip()
                    if line:
                        socketio.emit('scan_host_update', {
                            'type': 'sep_scan_output',
                            'ip': ip,
                            'message': line
                        })

                success = result.returncode == 0
                if not success:
                    error_message = result.stderr.strip() if result.stderr else f"sep-scan exited with code {result.returncode}"
                    socketio.emit('scan_host_update', {
                        'type': 'sep_scan_error',
                        'ip': ip,
                        'message': error_message
                    })

                mac = run_targeted_arp_scan(ip)
                hostname = resolve_ip_hostname(ip)

                updated_row = update_netkb_entry(ip, hostname, mac, success)
                payload = {
                    'type': 'host_updated',
                    'ip': ip,
                    'IPs': ip,
                    'Hostnames': hostname or '',
                    'MAC Address': mac or '',
                    'Alive': '1' if success else '0',
                    'Ports': '',
                    'scan_status': 'sep-scan' if success else 'sep-scan-failed',
                    'last_scan': datetime.now().isoformat(),
                    'vulnerabilities': []
                }

                if updated_row:
                    payload.update({
                        'IPs': updated_row.get('IPs', ip),
                        'Hostnames': updated_row.get('Hostnames', hostname or ''),
                        'MAC Address': updated_row.get('MAC Address', mac or ''),
                        'Ports': updated_row.get('Ports', ''),
                        'Alive': updated_row.get('Alive', '1' if success else '0'),
                        'Nmap Vulnerabilities': updated_row.get('Nmap Vulnerabilities', ''),
                        'NmapVulnScanner': updated_row.get('NmapVulnScanner', '')
                    })

                payload['mac'] = payload.get('MAC Address', '')
                payload['hostname'] = payload.get('Hostnames', '')

                socketio.emit('scan_host_update', payload)
                socketio.emit('scan_host_update', {
                    'type': 'sep_scan_completed',
                    'ip': ip,
                    'status': 'success' if success else 'failed'
                })

            except FileNotFoundError:
                logger.warning("sep-scan command not found. Falling back to nmap for %s", ip)
                socketio.emit('scan_host_update', {
                    'type': 'sep_scan_error',
                    'ip': ip,
                    'message': 'sep-scan command not found. Falling back to nmap.'
                })
                run_nmap_fallback()
            except subprocess.TimeoutExpired:
                logger.error(f"sep-scan timed out for {ip}")
                socketio.emit('scan_host_update', {
                    'type': 'sep_scan_error',
                    'ip': ip,
                    'message': 'sep-scan timed out'
                })
            except Exception as e:
                logger.error(f"Error running sep-scan for {ip}: {e}")
                socketio.emit('scan_host_update', {
                    'type': 'sep_scan_error',
                    'ip': ip,
                    'message': str(e)
                })
                run_nmap_fallback()

        # Start the scan in a background thread
        import threading
        scan_thread = threading.Thread(target=scan_host_background)
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({'status': 'success', 'message': f'Started scan of {ip}'})
        
    except Exception as e:
        logger.error(f"Error scanning single host: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================================================
# SYSTEM MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/system/check-updates')
def check_updates():
    """Check for system updates using git"""
    try:
        import subprocess
        import os
        
        # Get current working directory (should be the repo root)
        # Use the directory where the webapp is running from, not the file location
        repo_path = os.getcwd()
        
        logger.info(f"Checking for updates in repository: {repo_path}")
        
        # Fetch latest changes from remote
        try:
            fetch_result = subprocess.run(['git', 'fetch'], cwd=repo_path, check=True, capture_output=True, text=True)
            logger.info(f"Git fetch completed: {fetch_result.stdout}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git fetch failed: {e.stderr}")
            # Try to fix git safe directory issue and retry
            try:
                subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', repo_path], 
                             cwd=repo_path, check=True, capture_output=True)
                logger.info(f"Added {repo_path} to git safe directories")
                # Retry fetch
                fetch_result = subprocess.run(['git', 'fetch'], cwd=repo_path, check=True, capture_output=True, text=True)
                logger.info(f"Git fetch completed after fixing safe directory: {fetch_result.stdout}")
            except subprocess.CalledProcessError as e2:
                logger.error(f"Git fetch still failed after fixing safe directory: {e2.stderr}")
                return jsonify({
                    'error': 'Failed to fetch from remote repository. Git safe directory issue detected.',
                    'fix_command': f'git config --global --add safe.directory {repo_path}',
                    'detailed_error': str(e2.stderr)
                }), 500
        
        # Get the current branch name
        try:
            branch_result = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=repo_path, check=True, capture_output=True, text=True)
            current_branch = branch_result.stdout.strip()
        except subprocess.CalledProcessError:
            current_branch = 'main' # Fallback
        
        logger.info(f"Current git branch is: {current_branch}")
        remote_branch = f'origin/{current_branch}'

        # Check if local branch is behind remote
        try:
            result = subprocess.run(
                ['git', 'rev-list', '--count', f'HEAD..{remote_branch}'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            commits_behind = int(result.stdout.strip())
            logger.info(f"Commits behind '{remote_branch}': {commits_behind}")
        except (subprocess.CalledProcessError, ValueError) as e:
            logger.error(f"Error checking commits behind '{remote_branch}': {e}")
            commits_behind = 0
        
        # Get current HEAD commit
        try:
            current_result = subprocess.run(
                ['git', 'log', 'HEAD', '--oneline', '-1'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            current_commit = current_result.stdout.strip()
        except:
            current_commit = "Unable to fetch current commit"
        
        # Get latest commit info
        try:
            result = subprocess.run(
                ['git', 'log', remote_branch, '--oneline', '-1'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            latest_commit = result.stdout.strip()
        except:
            latest_commit = "Unable to fetch latest commit"
        
        logger.info(f"Update check result - Behind: {commits_behind}, Current: {current_commit}, Latest: {latest_commit}")
        
        return jsonify({
            'updates_available': commits_behind > 0,
            'commits_behind': commits_behind,
            'current_commit': current_commit,
            'latest_commit': latest_commit,
            'repo_path': repo_path
        })
        
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/update', methods=['POST'])
def perform_update():
    """Perform system update using git pull"""
    try:
        import subprocess
        import os
        
        repo_path = os.getcwd()
        logger.info(f"Performing update in repository: {repo_path}")
        
        # Fix permissions before git pull to prevent ownership issues
        try:
            logger.info("Correcting file permissions...")
            perm_result = subprocess.run(
                ['sudo', 'chown', '-R', 'ragnar:ragnar', '/home/ragnar/Ragnar'],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("Permissions corrected successfully")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Permission correction failed (continuing anyway): {e.stderr}")
        except Exception as e:
            logger.warning(f"Permission correction error (continuing anyway): {e}")
        
        # Perform git pull
        try:
            result = subprocess.run(
                ['git', 'pull'], 
                cwd=repo_path, 
                capture_output=True, 
                text=True, 
                check=True
            )
            output = result.stdout
            logger.info(f"Git pull completed: {output}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git pull failed: {e.stderr}")
            return jsonify({
                'success': False, 
                'error': f'Git pull failed: {e.stderr}',
                'suggestion': 'Please check repository status and resolve any conflicts'
            }), 500
        
        # Make files executable after pull
        try:
            logger.info("Making files executable...")
            # More comprehensive chmod - handle shell scripts and Python files specifically
            chmod_commands = [
                ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/*.sh'],           # All shell scripts
                ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/*.py'],           # All Python files
                ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/Ragnar.py'],      # Main script
                ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/kill_port_8000.sh'], # Specific failing script
                ['sudo', 'chmod', '+x', '/home/ragnar/Ragnar/webapp_modern.py'], # This file
                ['sudo', 'find', '/home/ragnar/Ragnar', '-name', '*.sh', '-exec', 'chmod', '+x', '{}', ';'] # Find all .sh files
            ]
            
            for cmd in chmod_commands:
                try:
                    subprocess.run(cmd, capture_output=True, text=True, check=False)  # Don't fail on individual commands
                except Exception as e:
                    logger.debug(f"Chmod command failed (continuing): {cmd} - {e}")
            
            logger.info("Files made executable successfully")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Chmod failed (continuing anyway): {e.stderr}")
        except Exception as e:
            logger.warning(f"Chmod error (continuing anyway): {e}")
        
        # Schedule service restart after a short delay
        def restart_service_delayed():
            import time
            time.sleep(2)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'systemctl', 'restart', 'ragnar'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to restart service: {e}")
        
        # Start restart in background thread
        import threading
        threading.Thread(target=restart_service_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'Update completed successfully',
            'output': output
        })
        
    except Exception as e:
        logger.error(f"Error performing update: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/fix-git', methods=['POST'])
def fix_git_safe_directory():
    """Fix git safe directory issue"""
    try:
        import subprocess
        import os
        
        repo_path = os.getcwd()
        
        # Add repo to git safe directories
        result = subprocess.run(
            ['git', 'config', '--global', '--add', 'safe.directory', repo_path], 
            cwd=repo_path, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        logger.info(f"Added {repo_path} to git safe directories")
        
        return jsonify({
            'success': True,
            'message': f'Successfully added {repo_path} to git safe directories'
        })
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fix git safe directory: {e.stderr}")
        return jsonify({
            'success': False, 
            'error': f'Failed to fix git configuration: {e.stderr}'
        }), 500
    except Exception as e:
        logger.error(f"Error fixing git safe directory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/restart-service', methods=['POST'])
def restart_service():
    """Restart the Ragnar service"""
    try:
        import subprocess
        
        # Schedule service restart after a short delay to allow response to be sent
        def restart_service_delayed():
            import time
            time.sleep(2)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'systemctl', 'restart', 'ragnar'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to restart service: {e}")
        
        # Start restart in background thread
        import threading
        threading.Thread(target=restart_service_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'Service restart initiated'
        })
        
    except Exception as e:
        logger.error(f"Error restarting service: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/reboot', methods=['POST'])
def reboot_system():
    """Reboot the entire system"""
    try:
        import subprocess
        
        # Schedule reboot after a short delay to allow response to be sent
        def reboot_delayed():
            import time
            time.sleep(3)  # Give time for response to be sent
            try:
                subprocess.run(['sudo', 'reboot'], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to reboot system: {e}")
        
        # Start reboot in background thread
        import threading
        threading.Thread(target=reboot_delayed, daemon=True).start()
        
        return jsonify({
            'success': True,
            'message': 'System reboot initiated'
        })
        
    except Exception as e:
        logger.error(f"Error rebooting system: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# WI-FI MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/wifi/status')
def get_wifi_status():
    """Get Wi-Fi manager status"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            status = wifi_manager.wifi_manager.get_status()
            return jsonify(status)
        else:
            return jsonify({
                'wifi_connected': shared_data.wifi_connected,
                'ap_mode_active': False,
                'current_ssid': None,
                'error': 'Wi-Fi manager not available'
            })
    except Exception as e:
        logger.error(f"Error getting Wi-Fi status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/scan', methods=['POST'])
def scan_wifi_networks():
    """Scan for available Wi-Fi networks with AP mode considerations for Pi Zero W2"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            # Check if we're in AP mode and handle accordingly
            if wifi_manager.wifi_manager.ap_mode_active:
                logger.info("Scanning networks while in AP mode (Pi Zero W2 compatible)")
                # Use specialized AP mode scanning
                networks = wifi_manager.wifi_manager.scan_networks_while_ap()
                
                # Check if we got instructional networks (scan failed)
                if networks and any(net.get('instruction') for net in networks):
                    return jsonify({
                        'networks': networks,
                        'warning': 'Live scanning limited in AP mode. Manual entry recommended.',
                        'manual_entry_available': True,
                        'ap_mode': True
                    })
                else:
                    return jsonify({
                        'networks': networks,
                        'success': True,
                        'ap_mode': True
                    })
            else:
                # Regular scanning when not in AP mode
                networks = wifi_manager.wifi_manager.scan_networks()
                return jsonify({
                    'networks': networks,
                    'success': True,
                    'ap_mode': False
                })
        else:
            return jsonify({
                'error': 'Wi-Fi manager not available',
                'manual_entry_available': True
            }), 503
    except Exception as e:
        logger.error(f"Error scanning Wi-Fi networks: {e}")
        # Fallback to cached networks if scanning fails
        try:
            wifi_manager = getattr(shared_data, 'ragnar_instance', None)
            if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
                known_networks = wifi_manager.wifi_manager.get_known_networks()
                return jsonify({
                    'networks': known_networks,
                    'warning': 'Live scan failed, showing known networks only',
                    'manual_entry_available': True
                })
        except:
            pass
        
        return jsonify({
            'networks': [],
            'error': 'Scanning failed',
            'manual_entry_available': True
        }), 500

@app.route('/api/wifi/networks')
def get_wifi_networks():
    """Get available and known Wi-Fi networks - optimized for Pi Zero W2 AP mode"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            
            # For captive portal/AP clients, use lightweight response
            if is_ap_client_request():
                logger.info("Serving networks to AP client - using optimized response")
                try:
                    if wifi_manager.wifi_manager.ap_mode_active:
                        available = wifi_manager.wifi_manager.scan_networks_while_ap()
                    else:
                        available = wifi_manager.wifi_manager.get_available_networks()
                    
                    # Limit to top 10 strongest signals to reduce memory usage on Pi Zero W2
                    if available:
                        # Filter out instructional networks for API response
                        real_networks = [net for net in available if not net.get('instruction')]
                        if real_networks:
                            available = sorted(real_networks, 
                                             key=lambda x: x.get('signal', 0), 
                                             reverse=True)[:10]
                        else:
                            # If only instructional networks, include them
                            available = available[:3]  # Just the top instructions
                    
                    return jsonify({
                        'success': True,
                        'networks': available if available else [],
                        'ap_mode': wifi_manager.wifi_manager.ap_mode_active,
                        'manual_entry_available': True
                    })
                except Exception as e:
                    logger.warning(f"Limited scan failed for AP client: {e}")
                    # Fallback to known networks for AP clients
                    known_networks = wifi_manager.wifi_manager.get_known_networks()
                    return jsonify({
                        'success': True,
                        'networks': known_networks[:5],  # Limit for memory
                        'error': 'Scanning limited in AP mode',
                        'manual_entry_available': True,
                        'ap_mode': True
                    })
            else:
                # Full response for regular interface
                try:
                    if wifi_manager.wifi_manager.ap_mode_active:
                        available = wifi_manager.wifi_manager.scan_networks_while_ap()
                    else:
                        available = wifi_manager.wifi_manager.get_available_networks()
                    
                    known = wifi_manager.wifi_manager.get_known_networks()
                    
                    return jsonify({
                        'success': True,
                        'available': available,
                        'known': known,
                        'ap_mode': wifi_manager.wifi_manager.ap_mode_active,
                        'manual_entry_available': True
                    })
                except Exception as e:
                    logger.warning(f"Network scan failed: {e}")
                    # Fallback to known networks only
                    known = wifi_manager.wifi_manager.get_known_networks()
                    return jsonify({
                        'success': True,
                        'available': [],
                        'known': known,
                        'error': 'Scanning failed, showing known networks only',
                        'manual_entry_available': True
                    })
        else:
            return jsonify({
                'success': False,
                'networks': [],
                'available': [], 
                'known': [],
                'manual_entry_available': True,
                'error': 'Wi-Fi manager not available'
            })
    except Exception as e:
        logger.error(f"Error getting Wi-Fi networks: {e}")
        return jsonify({
            'success': False, 
            'error': str(e),
            'manual_entry_available': True,
            'networks': [],
            'available': [],
            'known': []
        }), 500

@app.route('/api/wifi/connect', methods=['POST'])
def connect_wifi():
    """Connect to a Wi-Fi network"""
    try:
        data = request.get_json()
        if not data or 'ssid' not in data:
            return jsonify({'success': False, 'error': 'SSID is required'}), 400
        
        ssid = data['ssid']
        password = data.get('password')
        priority = data.get('priority', 1)
        save_network = data.get('save', True)
        
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'success': False, 'error': 'Wi-Fi manager not available'}), 503
        
        # Try to connect
        success = wifi_manager.wifi_manager.connect_to_network(ssid, password)
        
        if success and save_network:
            # Add to known networks if connection successful
            wifi_manager.wifi_manager.add_known_network(ssid, password, priority)
        
        message = 'Connected successfully' if success else 'Connection failed'
        if success and is_ap_client_request():
            message = 'Connected successfully! Ragnar will now use this network. You can disconnect from this AP.'
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        logger.error(f"Error connecting to Wi-Fi: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/wifi/disconnect', methods=['POST'])
def disconnect_wifi():
    """Disconnect from current Wi-Fi network"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        # Stop any active connection and start AP mode
        result = wifi_manager.wifi_manager.start_ap_mode()
        
        return jsonify({
            'success': result,
            'message': 'Disconnected and started AP mode' if result else 'Failed to start AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error disconnecting Wi-Fi: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/forget', methods=['POST'])
def forget_wifi_network():
    """Remove a network from known networks"""
    try:
        data = request.get_json()
        if not data or 'ssid' not in data:
            return jsonify({'error': 'SSID is required'}), 400
        
        ssid = data['ssid']
        
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.remove_known_network(ssid)
        
        return jsonify({
            'success': success,
            'message': 'Network forgotten' if success else 'Network not found'
        })
        
    except Exception as e:
        logger.error(f"Error forgetting Wi-Fi network: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/enable', methods=['POST'])
def enable_wifi_ap_mode():
    """Enable Wi-Fi Access Point mode with smart cycling"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        # Use the smart AP mode with cycling
        success = wifi_manager.wifi_manager.enable_ap_mode_from_web()
        
        ap_config = {
            'ssid': wifi_manager.wifi_manager.ap_ssid,
            'timeout': wifi_manager.wifi_manager.ap_timeout,
            'cycling': wifi_manager.wifi_manager.ap_cycle_enabled
        }
        
        return jsonify({
            'success': success,
            'message': 'Smart AP mode enabled with 3-minute cycling' if success else 'Failed to enable AP mode',
            'ap_config': ap_config
        })
        
    except Exception as e:
        logger.error(f"Error enabling Wi-Fi AP mode: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/start', methods=['POST'])
def start_wifi_ap():
    """Start Wi-Fi Access Point mode"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.start_ap_mode()
        
        return jsonify({
            'success': success,
            'message': 'AP mode started' if success else 'Failed to start AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error starting Wi-Fi AP: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/stop', methods=['POST'])
def stop_wifi_ap():
    """Stop Wi-Fi Access Point mode"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.stop_ap_mode()
        
        return jsonify({
            'success': success,
            'message': 'AP mode stopped' if success else 'Failed to stop AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error stopping Wi-Fi AP: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/reconnect', methods=['POST'])
def reconnect_wifi():
    """Force Wi-Fi reconnection attempt"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        success = wifi_manager.wifi_manager.force_reconnect()
        
        return jsonify({
            'success': success,
            'message': 'Reconnection attempt initiated' if success else 'Reconnection failed'
        })
        
    except Exception as e:
        logger.error(f"Error reconnecting Wi-Fi: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/ap/exit', methods=['POST'])
def exit_wifi_ap_mode():
    """Exit AP mode and start WiFi search (Endless Loop)"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        # Use the new exit AP mode function for endless loop
        success = wifi_manager.wifi_manager.exit_ap_mode_from_web()
        
        return jsonify({
            'success': success,
            'message': 'Exiting AP mode and starting WiFi search...' if success else 'Failed to exit AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error exiting Wi-Fi AP mode: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/force-recovery', methods=['POST'])
def force_wifi_recovery():
    """Force WiFi recovery - stop AP mode and aggressively search for known networks"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'error': 'Wi-Fi manager not available'}), 503
        
        wm = wifi_manager.wifi_manager
        
        # Stop AP mode if active
        if wm.ap_mode_active:
            logger.info("Force recovery: Stopping AP mode")
            wm.stop_ap_mode()
            time.sleep(2)  # Give time for AP to shut down properly
        
        # Force a WiFi search
        logger.info("Force recovery: Starting aggressive WiFi search")
        wm.wifi_validation_failures = 0
        wm.consecutive_validation_cycles_failed = 0
        
        # Try to connect in a separate thread to avoid blocking
        def attempt_reconnect():
            success = wm._endless_loop_wifi_search()
            if success:
                logger.info("Force recovery: Successfully reconnected to WiFi")
            else:
                logger.warning("Force recovery: Failed to reconnect to WiFi")
        
        recovery_thread = threading.Thread(target=attempt_reconnect, daemon=True)
        recovery_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'WiFi recovery initiated - searching for known networks...'
        })
        
    except Exception as e:
        logger.error(f"Error forcing WiFi recovery: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/wifi/log')
def get_wifi_log():
    """Get comprehensive WiFi logs including system status, Ragnar WiFi manager, and e-paper display updates"""
    try:
        wifi_log_data = {
            'timestamp': datetime.now().isoformat(),
            'system_wifi': {},
            'ragnar_wifi_manager': {},
            'epaper_display': {}
        }
        
        # === SYSTEM WIFI STATUS ===
        try:
            wifi_log_data['system_wifi'] = {}
            
            # Get SSID
            try:
                result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True, timeout=3)
                wifi_log_data['system_wifi']['ssid'] = result.stdout.strip() if result.returncode == 0 else None
                wifi_log_data['system_wifi']['connected'] = result.returncode == 0 and result.stdout.strip()
            except Exception as e:
                wifi_log_data['system_wifi']['ssid_error'] = str(e)
            
            # Get IP address
            try:
                result = subprocess.run(['ip', 'addr', 'show', 'wlan0'], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    wifi_log_data['system_wifi']['ip_address'] = ip_match.group(1) if ip_match else None
                    wifi_log_data['system_wifi']['interface_up'] = 'state UP' in result.stdout
                else:
                    wifi_log_data['system_wifi']['interface_error'] = f"Exit code: {result.returncode}"
            except Exception as e:
                wifi_log_data['system_wifi']['interface_error'] = str(e)
                
        except Exception as e:
            wifi_log_data['system_wifi']['error'] = str(e)
        
        # === RAGNAR WIFI MANAGER STATUS ===
        try:
            if (hasattr(shared_data, 'ragnar_instance') and 
                shared_data.ragnar_instance and 
                hasattr(shared_data.ragnar_instance, 'wifi_manager')):
                
                wifi_mgr = shared_data.ragnar_instance.wifi_manager
                wifi_log_data['ragnar_wifi_manager'] = {
                    'wifi_connected': getattr(wifi_mgr, 'wifi_connected', False),
                    'ap_mode_active': getattr(wifi_mgr, 'ap_mode_active', False),
                    'cycling_mode': getattr(wifi_mgr, 'cycling_mode', False),
                    'current_ssid': getattr(wifi_mgr, 'current_ssid', None),
                    'connection_attempts': getattr(wifi_mgr, 'connection_attempts', 0),
                    'ap_clients_count': getattr(wifi_mgr, 'ap_clients_count', 0)
                }
            else:
                wifi_log_data['ragnar_wifi_manager']['error'] = "WiFi manager not available"
                
        except Exception as e:
            wifi_log_data['ragnar_wifi_manager']['error'] = str(e)
        
        # === E-PAPER DISPLAY WIFI STATUS ===
        try:
            if (hasattr(shared_data, 'ragnar_instance') and 
                shared_data.ragnar_instance and 
                hasattr(shared_data.ragnar_instance, 'display')):
                
                display = shared_data.ragnar_instance.display
                wifi_log_data['epaper_display'] = {
                    'wifi_status_text': display.get_wifi_status_text(),
                    'is_wifi_connected': display.is_wifi_connected()
                }
            else:
                wifi_log_data['epaper_display']['error'] = "Display not available"
                
        except Exception as e:
            wifi_log_data['epaper_display']['error'] = str(e)
        
        return jsonify(wifi_log_data)
        
    except Exception as e:
        logger.error(f"Error getting WiFi logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/epaper-display')
def get_epaper_display():
    """Get current e-paper display image as base64"""
    try:
        from PIL import Image
        
        # Look for the current display image saved by display.py
        display_image_path = os.path.join(shared_data.webdir, "screen.png")
        
        if os.path.exists(display_image_path):
            # Read and encode the image
            with Image.open(display_image_path) as img:
                # Convert to RGB if needed
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Save to bytes
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='PNG')
                img_byte_arr = img_byte_arr.getvalue()
                
                # Encode to base64
                img_base64 = base64.b64encode(img_byte_arr).decode('utf-8')
                
                return jsonify({
                    'image': f"data:image/png;base64,{img_base64}",
                    'timestamp': int(os.path.getctime(display_image_path)),
                    'width': img.width,
                    'height': img.height,
                    'status_text': safe_str(shared_data.ragnarstatustext),
                    'status_text2': safe_str(shared_data.ragnarstatustext2)
                })
        
        # If no image found, return status only
        return jsonify({
            'image': None,
            'message': 'No e-paper display image available',
            'timestamp': int(time.time()),
            'status_text': safe_str(shared_data.ragnarstatustext),
            'status_text2': safe_str(shared_data.ragnarstatustext2)
        })
        
    except Exception as e:
        logger.error(f"Error getting e-paper display: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/display')
def get_display():
    """Get current EPD display image"""
    try:
        # Return the current display status image
        image_path = os.path.join(shared_data.picdir, 'current_display.png')
        if os.path.exists(image_path):
            return send_from_directory(shared_data.picdir, 'current_display.png')
        return jsonify({'error': 'Display image not found'}), 404
    except Exception as e:
        logger.error(f"Error getting display: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/actions', methods=['GET'])
def get_actions():
    """Get available actions"""
    try:
        with open(shared_data.actions_file, 'r') as f:
            actions = json.load(f)
        return jsonify(actions)
    except Exception as e:
        logger.error(f"Error getting actions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get vulnerability scan results"""
    try:
        # Check if network intelligence is enabled
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Get network-aware findings for dashboard
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            
            # Convert to legacy format for compatibility
            vuln_data = []
            for vuln_id, vuln_info in dashboard_findings['vulnerabilities'].items():
                vuln_data.append({
                    'id': vuln_id,
                    'host': vuln_info['host'],
                    'port': vuln_info['port'],
                    'service': vuln_info['service'],
                    'vulnerability': vuln_info['vulnerability'],
                    'severity': vuln_info['severity'],
                    'discovered': vuln_info['discovered'],
                    'network_id': vuln_info['network_id'],
                    'status': vuln_info['status']
                })
            
            return jsonify({
                'vulnerabilities': vuln_data,
                'network_context': {
                    'current_network': dashboard_findings['network_id'],
                    'count': dashboard_findings['counts']['vulnerabilities']
                }
            })
        else:
            # Fallback to legacy vulnerability data
            vuln_data = web_utils.get_vulnerability_data()
            return jsonify(vuln_data)
            
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-intelligence')
def get_network_intelligence():
    """Get network intelligence summary and findings"""
    try:
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Update network context
            shared_data.network_intelligence.update_network_context()
            
            # Get network summary
            summary = shared_data.network_intelligence.get_network_summary()
            
            # Get active findings for dashboard
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            
            # Get all findings for NetKB
            netkb_findings = shared_data.network_intelligence.get_all_findings_for_netkb()
            
            return jsonify({
                'enabled': True,
                'network_summary': summary,
                'dashboard_findings': dashboard_findings,
                'netkb_findings': netkb_findings,
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'enabled': False,
                'message': 'Network intelligence is disabled or unavailable'
            })
            
    except Exception as e:
        logger.error(f"Error getting network intelligence: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/credentials')
def get_credentials_api():
    """Get credential data with network intelligence if available"""
    try:
        # Check if network intelligence is enabled
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Get network-aware findings for dashboard
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            
            # Convert to legacy format for compatibility
            cred_data = []
            for cred_id, cred_info in dashboard_findings['credentials'].items():
                cred_data.append({
                    'id': cred_id,
                    'host': cred_info['host'],
                    'service': cred_info['service'],
                    'username': cred_info['username'],
                    'password': cred_info['password'],
                    'protocol': cred_info['protocol'],
                    'discovered': cred_info['discovered'],
                    'network_id': cred_info['network_id'],
                    'status': cred_info['status']
                })
            
            return jsonify({
                'credentials': cred_data,
                'network_context': {
                    'current_network': dashboard_findings['network_id'],
                    'count': dashboard_findings['counts']['credentials']
                }
            })
        else:
            # Fallback to legacy credential data - just return empty structure
            return jsonify({
                'credentials': [],
                'network_context': {
                    'current_network': 'legacy',
                    'count': 0
                }
            })
            
    except Exception as e:
        logger.error(f"Error getting credentials: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-intelligence/add-vulnerability', methods=['POST'])
def add_vulnerability():
    """Add a new vulnerability finding"""
    try:
        if not (hasattr(shared_data, 'network_intelligence') and 
                shared_data.network_intelligence and 
                shared_data.config.get('network_intelligence_enabled', True)):
            return jsonify({'error': 'Network intelligence not available'}), 400
        
        data = request.get_json()
        required_fields = ['host', 'port', 'service', 'vulnerability']
        
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        vuln_id = shared_data.network_intelligence.add_vulnerability(
            host=data['host'],
            port=data['port'],
            service=data['service'],
            vulnerability=data['vulnerability'],
            severity=data.get('severity', 'medium'),
            details=data.get('details', {})
        )
        
        if vuln_id:
            # Trigger sync and broadcast update
            sync_all_counts()
            broadcast_status_update()
            
            return jsonify({
                'success': True,
                'vulnerability_id': vuln_id,
                'message': 'Vulnerability added successfully'
            })
        else:
            return jsonify({'error': 'Failed to add vulnerability'}), 500
            
    except Exception as e:
        logger.error(f"Error adding vulnerability: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-intelligence/add-credential', methods=['POST'])
def add_credential():
    """Add a new credential finding"""
    try:
        if not (hasattr(shared_data, 'network_intelligence') and 
                shared_data.network_intelligence and 
                shared_data.config.get('network_intelligence_enabled', True)):
            return jsonify({'error': 'Network intelligence not available'}), 400
        
        data = request.get_json()
        required_fields = ['host', 'service', 'username', 'password']
        
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        cred_id = shared_data.network_intelligence.add_credential(
            host=data['host'],
            service=data['service'],
            username=data['username'],
            password=data['password'],
            protocol=data.get('protocol', 'unknown'),
            details=data.get('details', {})
        )
        
        if cred_id:
            # Trigger sync and broadcast update
            sync_all_counts()
            broadcast_status_update()
            
            return jsonify({
                'success': True,
                'credential_id': cred_id,
                'message': 'Credential added successfully'
            })
        else:
            return jsonify({'error': 'Failed to add credential'}), 500
            
    except Exception as e:
        logger.error(f"Error adding credential: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
def get_stats():
    """Get aggregated statistics"""
    try:
        stats = {
            'total_targets': safe_int(shared_data.targetnbr),
            'total_ports': safe_int(shared_data.portnbr),
            'total_vulnerabilities': safe_int(shared_data.vulnnbr),
            'total_credentials': safe_int(shared_data.crednbr),
            'total_data_stolen': safe_int(shared_data.datanbr),
            'scan_results_count': 0,
            'services_discovered': {}
        }
        
        # Add scan results count
        if os.path.exists(shared_data.netkbfile):
            import pandas as pd
            df = pd.read_csv(shared_data.netkbfile)
            stats['scan_results_count'] = safe_int(len(df[df['Alive'] == 1]) if 'Alive' in df.columns else len(df))
        
        # Add threat intelligence stats
        if threat_intelligence:
            ti_stats = threat_intelligence.get_enriched_findings_summary()
            stats.update(ti_stats)
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# THREAT INTELLIGENCE ENDPOINTS
# ============================================================================

def _serialize_enriched_finding(finding_id, enriched_finding, default_last_update=None):
    """Serialize enriched finding details for the modern web UI."""
    original = enriched_finding.original_finding or {}

    target = (
        original.get('host')
        or original.get('ip')
        or original.get('target')
        or original.get('id')
        or finding_id
    )

    primary_context = enriched_finding.threat_contexts[0] if enriched_finding.threat_contexts else None
    threat_context = 'No additional context available'
    last_seen = None

    if primary_context:
        threat_context = primary_context.description or primary_context.threat_type or threat_context
        last_seen = primary_context.last_seen or primary_context.first_seen

    if not last_seen:
        last_seen = (
            original.get('timestamp')
            or original.get('last_seen')
            or default_last_update
        )

    attribution = None
    if enriched_finding.attribution and enriched_finding.attribution.actor_name:
        confidence = enriched_finding.attribution.confidence
        if confidence:
            attribution = f"{enriched_finding.attribution.actor_name} ({int(round(confidence * 100))}% confidence)"
        else:
            attribution = enriched_finding.attribution.actor_name

    summary = (enriched_finding.executive_summary or '').strip()
    if summary and len(summary) > 160:
        summary = summary[:157] + '...'

    risk_score = int(round(min(enriched_finding.dynamic_risk_score or 0.0, 10.0) * 10))

    return {
        'id': finding_id,
        'target': target,
        'risk_score': risk_score,
        'threat_context': threat_context,
        'attribution': attribution,
        'last_updated': last_seen,
        'summary': summary,
        'last_seen': last_seen
    }


@app.route('/api/threat-intelligence/status')
def get_threat_intelligence_status():
    """Get threat intelligence system status"""
    try:
        if not threat_intelligence:
            return jsonify({'error': 'Threat intelligence system not available'}), 503

        summary = threat_intelligence.get_enriched_findings_summary() or {}
        default_last_update = summary.get('last_intelligence_update')

        serialized_findings = [
            _serialize_enriched_finding(finding_id, enriched_finding, default_last_update)
            for finding_id, enriched_finding in threat_intelligence.enriched_findings.items()
        ]

        risk_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        active_campaigns = set()

        for enriched_finding in threat_intelligence.enriched_findings.values():
            score = enriched_finding.dynamic_risk_score or 0.0
            if score >= 9.0:
                risk_distribution['critical'] += 1
            elif score >= 7.0:
                risk_distribution['high'] += 1
            elif score >= 4.0:
                risk_distribution['medium'] += 1
            else:
                risk_distribution['low'] += 1

            for campaign in enriched_finding.active_campaigns or []:
                if campaign:
                    active_campaigns.add(campaign)

        type_to_status_key = {
            'cisa': 'cisa_kev',
            'nvd': 'nvd_cve',
            'otx': 'alienvault_otx',
            'mitre': 'mitre_attack'
        }

        source_status = {key: False for key in type_to_status_key.values()}
        sources = []
        for name, source in threat_intelligence.threat_sources.items():
            sources.append({
                'name': name,
                'type': source.type,
                'enabled': source.enabled,
                'confidence_weight': source.confidence_weight,
                'last_updated': source.last_updated
            })

            status_key = type_to_status_key.get(source.type)
            if status_key:
                source_status[status_key] = source_status.get(status_key, False) or source.enabled

        top_threats = sorted(serialized_findings, key=lambda f: f['risk_score'], reverse=True)[:5]

        total_enriched = summary.get('total_enriched_findings', len(serialized_findings))
        high_risk_total = risk_distribution['critical'] + risk_distribution['high']

        status = {
            'enabled': True,
            'active_sources': summary.get('threat_sources_enabled', 0),
            'enriched_findings_count': total_enriched,
            'high_risk_count': high_risk_total,
            'active_campaigns': len(active_campaigns),
            'risk_distribution': risk_distribution,
            'source_status': source_status,
            'last_update': default_last_update,
            'top_threats': top_threats,
            'sources': sources,
            'cache_entries': len(threat_intelligence.threat_cache),
            'total_enriched_findings': total_enriched
        }

        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting threat intelligence status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/enriched-findings')
def get_enriched_findings():
    """Get all enriched findings with threat intelligence"""
    try:
        if not threat_intelligence:
            return jsonify({'error': 'Threat intelligence system not available'}), 503
        
        summary = threat_intelligence.get_enriched_findings_summary() or {}
        default_last_update = summary.get('last_intelligence_update')

        enriched_findings = [
            _serialize_enriched_finding(finding_id, enriched_finding, default_last_update)
            for finding_id, enriched_finding in threat_intelligence.enriched_findings.items()
        ]

        top_threats = sorted(enriched_findings, key=lambda f: f['risk_score'], reverse=True)[:5]

        return jsonify({
            'enriched_findings': enriched_findings,
            'total_count': len(enriched_findings),
            'summary': summary,
            'top_threats': top_threats
        })

    except Exception as e:
        logger.error(f"Error getting enriched findings: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/enrich-finding', methods=['POST'])
def enrich_finding_endpoint():
    """Manually enrich a finding with threat intelligence"""
    try:
        if not threat_intelligence:
            return jsonify({'error': 'Threat intelligence system not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract finding data
        finding = {
            'id': data.get('id'),
            'host': data.get('host'),
            'port': data.get('port'),
            'service': data.get('service'),
            'vulnerability': data.get('vulnerability'),
            'severity': data.get('severity', 'medium'),
            'details': data.get('details', {})
        }
        
        # Enrich the finding
        import asyncio
        enriched_finding = asyncio.run(threat_intelligence.enrich_finding_with_threat_intelligence(finding))
        
        return jsonify({
            'success': True,
            'enriched_finding': {
                'id': finding['id'],
                'dynamic_risk_score': enriched_finding.dynamic_risk_score,
                'executive_summary': enriched_finding.executive_summary,
                'recommended_actions': enriched_finding.recommended_actions,
                'threat_contexts_count': len(enriched_finding.threat_contexts),
                'attribution': {
                    'actor_name': enriched_finding.attribution.actor_name if enriched_finding.attribution else None,
                    'confidence': enriched_finding.attribution.confidence if enriched_finding.attribution else 0.0
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error enriching finding: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/enrich-target', methods=['POST'])
def enrich_target_endpoint():
    """Enrich a target (IP, domain, or hash) with threat intelligence"""
    try:
        if not threat_intelligence:
            return jsonify({'error': 'Threat intelligence system not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        target = data.get('target', '').strip()
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Look for actual vulnerability findings for this target
        actual_findings = []
        if hasattr(shared_data, 'network_intelligence') and shared_data.network_intelligence:
            try:
                # Check active findings
                active_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
                
                # Check for vulnerabilities on this target
                for vuln_id, vuln_data in active_findings.get('vulnerabilities', {}).items():
                    if vuln_data.get('host') == target:
                        actual_findings.append(vuln_data)
                
                # Check for compromised credentials on this target  
                for cred_id, cred_data in active_findings.get('credentials', {}).items():
                    if cred_data.get('host') == target:
                        actual_findings.append(cred_data)
                        
            except AttributeError as e:
                logger.warning(f"Network intelligence method not available: {e}")
                # Fallback: check if we have scan data directly from files
                try:
                    scan_results_dir = os.path.join(shared_data.datadir, 'output', 'scan_results')
                    if os.path.exists(scan_results_dir):
                        for filename in os.listdir(scan_results_dir):
                            if filename.endswith('.csv') and target in filename:
                                # Found scan results for this target
                                actual_findings.append({
                                    'host': target,
                                    'vulnerability': 'Network scan findings available',
                                    'source': 'scan_results',
                                    'details': {'scan_file': filename}
                                })
                                break
                except Exception as scan_e:
                    logger.warning(f"Could not check scan results: {scan_e}")
                    
            except Exception as e:
                logger.warning(f"Could not retrieve network intelligence findings: {e}")
        
        # If no findings but target looks like it might have vulnerabilities, create a placeholder
        if not actual_findings:
            # For demonstration/testing purposes, allow manual vulnerability analysis
            # This should ideally be replaced with real vulnerability scanner integration
            return jsonify({
                'error': f'No vulnerability findings detected for target: {target}',
                'message': 'Ragnar needs to discover vulnerabilities first through network scanning. Try running vulnerability scans on this target.',
                'target_type': 'no_findings',
                'suggestion': f'Run network scan on {target} first, then threat intelligence can enrich any discovered vulnerabilities'
            }), 404

        # Use the first real finding for enrichment (or combine multiple findings)
        base_finding = actual_findings[0]
        
        # Create enriched finding object from actual scan data
        finding = {
            'id': base_finding.get('id', hashlib.md5(target.encode()).hexdigest()[:12]),
            'host': target,
            'vulnerability': base_finding.get('vulnerability', base_finding.get('service', 'Unknown')),
            'severity': base_finding.get('severity', 'medium'),
            'port': base_finding.get('port'),
            'service': base_finding.get('service'),
            'details': base_finding.get('details', {}),
            'scan_timestamp': base_finding.get('timestamp', datetime.now().isoformat())
        }
        
        # Enrich the finding
        import asyncio
        enriched_finding = asyncio.run(threat_intelligence.enrich_finding_with_threat_intelligence(finding))
        
        # Convert risk score from 0-10 scale to 0-100 scale for frontend
        risk_score_100 = min(int(enriched_finding.dynamic_risk_score * 10), 100)
        
        return jsonify({
            'success': True,
            'target': target,
            'risk_score': risk_score_100,
            'dynamic_risk_score': enriched_finding.dynamic_risk_score,
            'executive_summary': enriched_finding.executive_summary,
            'recommended_actions': enriched_finding.recommended_actions,
            'threat_contexts_count': len(enriched_finding.threat_contexts),
            'attribution': {
                'actor_name': enriched_finding.attribution.actor_name if enriched_finding.attribution else None,
                'confidence': enriched_finding.attribution.confidence if enriched_finding.attribution else 0.0
            },
            'enriched_finding_id': finding['id']
        })
        
    except Exception as e:
        logger.error(f"Error enriching target: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence/dashboard')
def get_threat_intelligence_dashboard():
    """Get threat intelligence dashboard data"""
    try:
        if not threat_intelligence:
            return jsonify({'error': 'Threat intelligence system not available'}), 503
        
        dashboard_data = {
            'summary': threat_intelligence.get_enriched_findings_summary(),
            'recent_findings': [],
            'risk_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'threat_sources_status': []
        }
        
        # Get recent enriched findings
        recent_findings = []
        for finding_id, enriched_finding in list(threat_intelligence.enriched_findings.items())[-10:]:
            recent_findings.append({
                'id': finding_id,
                'host': enriched_finding.original_finding.get('host', 'Unknown'),
                'vulnerability': enriched_finding.original_finding.get('vulnerability', 'Unknown'),
                'risk_score': enriched_finding.dynamic_risk_score,
                'executive_summary': enriched_finding.executive_summary[:200] + '...'
            })
        
        dashboard_data['recent_findings'] = recent_findings
        
        # Calculate risk distribution
        for enriched_finding in threat_intelligence.enriched_findings.values():
            score = enriched_finding.dynamic_risk_score
            if score >= 9.0:
                dashboard_data['risk_distribution']['critical'] += 1
            elif score >= 7.0:
                dashboard_data['risk_distribution']['high'] += 1
            elif score >= 5.0:
                dashboard_data['risk_distribution']['medium'] += 1
            else:
                dashboard_data['risk_distribution']['low'] += 1
        
        # Threat sources status
        for name, source in threat_intelligence.threat_sources.items():
            dashboard_data['threat_sources_status'].append({
                'name': name,
                'type': source.type,
                'enabled': source.enabled,
                'last_updated': source.last_updated
            })
        
        return jsonify(dashboard_data)
        
    except Exception as e:
        logger.error(f"Error getting threat intelligence dashboard: {e}")
        return jsonify({'error': str(e)}), 500

def generate_threat_intelligence_report(target, enriched_finding):
    """Generate threat intelligence report content"""
    try:
        from datetime import datetime
        
        # Check if this is a meaningful finding
        if not enriched_finding.threat_contexts or enriched_finding.dynamic_risk_score < 3.0:
            return {
                'title': f'Threat Intelligence Report - {target}',
                'generated_at': datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
                'target': target,
                'message': 'No significant threat intelligence available for this target',
                'risk_score': enriched_finding.dynamic_risk_score,
                'note': 'This target may be internal or not present in threat intelligence databases'
            }
        
        report_content = {
            'title': f'Threat Intelligence Report - {target}',
            'generated_at': datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
            'target': target,
            'executive_summary': enriched_finding.executive_summary,
            'risk_score': enriched_finding.dynamic_risk_score,
            'threat_contexts': [],
            'attribution': None,
            'active_campaigns': enriched_finding.active_campaigns,
            'exploitation_prediction': enriched_finding.exploitation_prediction,
            'recommended_actions': enriched_finding.recommended_actions
        }
        
        # Process threat contexts
        for context in enriched_finding.threat_contexts:
            report_content['threat_contexts'].append({
                'source': context.source,
                'threat_type': context.threat_type,
                'severity': context.severity,
                'confidence': context.confidence,
                'description': context.description,
                'references': context.references,
                'tags': context.tags
            })
        
        # Process attribution
        if enriched_finding.attribution:
            report_content['attribution'] = {
                'actor_name': enriched_finding.attribution.actor_name,
                'sophistication': enriched_finding.attribution.sophistication,
                'motivation': enriched_finding.attribution.motivation,
                'geographic_origin': enriched_finding.attribution.geographic_origin,
                'confidence': enriched_finding.attribution.confidence
            }
        
        return report_content
        
    except Exception as e:
        logger.error(f"Error generating report content: {e}")
        return {
            'title': f'Threat Intelligence Report - {target}',
            'generated_at': datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
            'target': target,
            'executive_summary': 'Report generation failed - manual review recommended',
            'risk_score': 5.0,
            'error': str(e)
        }

def create_text_report(report_content):
    """Create text report from content"""
    try:
        # Check if this is a low-value report
        if 'message' in report_content:
            return f"""THREAT INTELLIGENCE REPORT
===========================

Target: {report_content['target']}
Generated: {report_content['generated_at']}

STATUS
------
{report_content['message']}

ANALYSIS NOTES
--------------
{report_content.get('note', 'No additional information available')}

Risk Score: {report_content.get('risk_score', 0):.1f}/10

REPORT METADATA
---------------
Generated by: Ragnar Threat Intelligence System
Report ID: {hashlib.md5(report_content['target'].encode()).hexdigest()[:12]}
Timestamp: {report_content['generated_at']}

Note: This target may be internal infrastructure or not present in external threat databases.
""".encode('utf-8')

        report_text = f"""THREAT INTELLIGENCE REPORT
===========================

Target: {report_content['target']}
Generated: {report_content['generated_at']}

EXECUTIVE SUMMARY
-----------------
{report_content['executive_summary']}

RISK ASSESSMENT
---------------
Dynamic Risk Score: {report_content['risk_score']:.1f}/10

"""
        
        if report_content.get('threat_contexts'):
            report_text += "THREAT INTELLIGENCE SOURCES\n"
            report_text += "----------------------------\n"
            for context in report_content['threat_contexts']:
                report_text += f"• {context['source']}: {context['description']}\n"
                report_text += f"  Severity: {context['severity']}, Confidence: {context['confidence']:.1f}\n\n"
        else:
            report_text += "THREAT INTELLIGENCE SOURCES\n"
            report_text += "----------------------------\n"
            report_text += "No external threat intelligence sources matched this target.\n\n"
        
        if report_content.get('attribution'):
            attr = report_content['attribution']
            report_text += "THREAT ATTRIBUTION\n"
            report_text += "------------------\n"
            report_text += f"Actor: {attr.get('actor_name', 'Unknown')}\n"
            report_text += f"Sophistication: {attr.get('sophistication', 'Unknown')}\n"
            report_text += f"Motivation: {attr.get('motivation', 'Unknown')}\n"
            report_text += f"Geographic Origin: {attr.get('geographic_origin', 'Unknown')}\n\n"
        
        if report_content.get('recommended_actions'):
            report_text += "RECOMMENDED ACTIONS\n"
            report_text += "-------------------\n"
            for action in report_content['recommended_actions']:
                report_text += f"• {action}\n"
            report_text += "\n"
        else:
            report_text += "RECOMMENDED ACTIONS\n"
            report_text += "-------------------\n"
            report_text += "• Review target for legitimate business purpose\n"
            report_text += "• Monitor for unusual activity\n"
            report_text += "• Apply standard security controls\n\n"
        
        if report_content.get('exploitation_prediction'):
            pred = report_content['exploitation_prediction']
            report_text += "EXPLOITATION PREDICTION\n"
            report_text += "-----------------------\n"
            report_text += f"Likelihood: {pred.get('exploitation_likelihood', 0) * 100:.1f}%\n"
            report_text += f"Timeline: {pred.get('predicted_timeline_days', 'Unknown')} days\n"
            report_text += f"Confidence: {pred.get('confidence', 0) * 100:.1f}%\n\n"
        
        report_text += f"""REPORT METADATA
---------------
Generated by: Ragnar Threat Intelligence System
Report ID: {hashlib.md5(report_content['target'].encode()).hexdigest()[:12]}
Timestamp: {report_content['generated_at']}

This report contains threat intelligence analysis based on multiple sources.
For questions or additional analysis, contact your security team.
"""
        
        return report_text.encode('utf-8')
        
    except Exception as e:
        logger.error(f"Error creating text report: {e}")
        error_content = f"Error generating report: {e}".encode('utf-8')
        return error_content

@app.route('/api/threat-intelligence/download-report', methods=['POST'])
def download_threat_intelligence_report():
    """Generate and download a comprehensive threat intelligence report"""
    try:
        if not threat_intelligence:
            return jsonify({'error': 'Threat intelligence system not available'}), 503
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        target = data.get('target', '').strip()
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Find enriched finding for the target
        enriched_finding = None
        for finding_id, finding in threat_intelligence.enriched_findings.items():
            original_finding = finding.original_finding
            if (original_finding.get('host') == target or 
                original_finding.get('domain') == target or
                original_finding.get('hash') == target or
                original_finding.get('details', {}).get('target') == target):
                enriched_finding = finding
                break
        
        if not enriched_finding:
            # Try to create a new enrichment for the target
            finding = {
                'id': hashlib.md5(target.encode()).hexdigest()[:12],
                'host': target if _is_ip_address(target) else None,
                'domain': target if '.' in target and not _is_ip_address(target) else None,
                'hash': target if len(target) >= 32 and all(c in '0123456789abcdefABCDEF' for c in target) else None,
                'vulnerability': f'Threat intelligence analysis for {target}',
                'severity': 'medium',
                'details': {'target': target}
            }
            
            import asyncio
            enriched_finding = asyncio.run(threat_intelligence.enrich_finding_with_threat_intelligence(finding))
        
        # Generate report content
        report_content = generate_threat_intelligence_report(target, enriched_finding)
        
        # Create text report
        text_content = create_text_report(report_content)
        
        # Generate filename with current date
        from datetime import datetime
        now = datetime.now()
        date_str = now.strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c for c in target if c.isalnum() or c in '._-')
        filename = f"Threat_Intelligence_Report_{safe_target}_{date_str}.txt"
        
        # Return text file as download
        response = Response(
            text_content,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'text/plain'
            }
        )
        
        logger.info(f"Generated threat intelligence report for target: {target}")
        return response
        
    except Exception as e:
        logger.error(f"Error generating threat intelligence report: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# LEGACY ENDPOINTS (for compatibility)
# ============================================================================

@app.route('/network_data')
def legacy_network_data():
    """Network data endpoint with WiFi-specific persistence"""
    try:
        # Update WiFi-specific network data from latest scan results
        update_wifi_network_data()
        
        # Read from WiFi-specific persistent file
        network_data = read_wifi_network_data()
        
        # If no persistent data, build from current scan results
        if not network_data:
            logger.debug("No WiFi-specific network data found, building from scan results")
            
            scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
            current_time = datetime.now().isoformat()
            
            if os.path.exists(scan_results_dir):
                temp_data = {}
                
                for filename in os.listdir(scan_results_dir):
                    if filename.startswith('result_') and filename.endswith('.csv'):
                        filepath = os.path.join(scan_results_dir, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                reader = csv.reader(f)
                                for row in reader:
                                    if len(row) >= 1 and row[0].strip():
                                        ip = row[0].strip()
                                        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                                            hostname = row[1] if len(row) > 1 and row[1] else ''
                                            alive = row[2] if len(row) > 2 and row[2] else '1'
                                            mac = row[3] if len(row) > 3 and row[3] else ''
                                            
                                            # Collect ports from remaining columns
                                            ports = []
                                            if len(row) > 4:
                                                for port_col in row[4:]:
                                                    if port_col and port_col.strip():
                                                        ports.append(port_col.strip())
                                            
                                            # Update or add entry
                                            if ip in temp_data:
                                                # Merge data
                                                if hostname and hostname != 'Unknown':
                                                    temp_data[ip]['Hostnames'] = hostname
                                                if mac and mac != 'Unknown':
                                                    temp_data[ip]['MAC Address'] = mac
                                                temp_data[ip]['Alive'] = int(alive) if alive.isdigit() else 1
                                                existing_ports = set(temp_data[ip]['Ports'].split(';')) if temp_data[ip]['Ports'] else set()
                                                existing_ports.update(ports)
                                                temp_data[ip]['Ports'] = ';'.join(sorted(existing_ports, key=lambda x: int(x) if x.isdigit() else 0))
                                                temp_data[ip]['LastSeen'] = current_time
                                            else:
                                                # New entry
                                                temp_data[ip] = {
                                                    'IPs': ip,
                                                    'Hostnames': hostname,
                                                    'Alive': int(alive) if alive.isdigit() else 1,
                                                    'MAC Address': mac,
                                                    'Ports': ';'.join(ports) if ports else '',
                                                    'LastSeen': current_time
                                                }
                        except Exception as e:
                            logger.debug(f"Could not read scan result file {filepath}: {e}")
                            continue
                
                # Convert to list format
                network_data = list(temp_data.values())
        
        if not network_data:
            current_ssid = get_current_wifi_ssid()
            return f'<div class="error">No network scan results found for WiFi network: {current_ssid}<br>Please run a network scan first.</div>'
        
        current_ssid = get_current_wifi_ssid()
        
        # Generate HTML table
        html = f'''
        <div class="network-header">
            <h3>Network Scan Results for WiFi: {current_ssid}</h3>
            <p>Persistent data - automatically updated when new scans are performed</p>
        </div>
        <table class="network-table">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Status</th>
                    <th>MAC Address</th>
                    <th>Open Ports</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>
        '''
        
        for entry in network_data:
            ip = entry.get('IPs', '')
            hostname = entry.get('Hostnames', '')
            alive = entry.get('Alive', 0)
            mac = entry.get('MAC Address', '')
            ports = entry.get('Ports', '')
            last_seen = entry.get('LastSeen', '')
            
            # Format status
            status = 'Online' if alive == 1 else 'Offline'
            status_class = 'status-online' if alive == 1 else 'status-offline'
            
            # Format ports for display
            if ports:
                port_list = [p for p in ports.split(';') if p]
                ports_display = ', '.join(port_list[:10])  # Show first 10 ports
                if len(port_list) > 10:
                    ports_display += f' ... (+{len(port_list) - 10} more)'
            else:
                ports_display = 'None detected'
            
            # Format last seen time
            try:
                if last_seen:
                    last_seen_dt = datetime.fromisoformat(last_seen)
                    last_seen_display = last_seen_dt.strftime('%m-%d %H:%M')
                else:
                    last_seen_display = 'Unknown'
            except:
                last_seen_display = 'Unknown'
            
            html += f'''
                <tr>
                    <td>{ip}</td>
                    <td>{hostname if hostname else 'Unknown'}</td>
                    <td><span class="{status_class}">{status}</span></td>
                    <td>{mac if mac else 'Unknown'}</td>
                    <td>{ports_display}</td>
                    <td>{last_seen_display}</td>
                </tr>
            '''
        
        html += '''
            </tbody>
        </table>
        '''
        
        # Add some CSS for styling
        html = f'''
        <style>
            .network-header {{
                color: #00ff00;
                font-family: 'Courier New', monospace;
                text-align: center;
                margin-bottom: 20px;
            }}
            .network-header h3 {{
                margin: 0 0 10px 0;
                font-size: 18px;
            }}
            .network-header p {{
                margin: 0;
                font-size: 12px;
                color: #00cc00;
            }}
            .network-table {{
                width: 100%;
                border-collapse: collapse;
                font-family: 'Courier New', monospace;
                background-color: #000;
                color: #00ff00;
            }}
            .network-table th, .network-table td {{
                border: 1px solid #00ff00;
                padding: 8px;
                text-align: left;
                font-size: inherit;
            }}
            .network-table th {{
                background-color: #003300;
                font-weight: bold;
            }}
            .network-table tr:nth-child(even) {{
                background-color: #001100;
            }}
            .status-online {{
                color: #00ff00;
                font-weight: bold;
            }}
            .status-offline {{
                color: #ff6600;
                font-weight: bold;
            }}
            .error {{
                color: #ff0000;
                text-align: center;
                padding: 20px;
                font-family: 'Courier New', monospace;
            }}
        </style>
        {html}
        '''
        
        logger.info(f"Serving network data for WiFi: {current_ssid} with {len(network_data)} entries")
        return html
        
    except Exception as e:
        logger.error(f"Error serving network data: {e}")
        current_ssid = get_current_wifi_ssid()
        return f'<div class="error">Error loading network data for WiFi: {current_ssid}<br>Error: {str(e)}</div>'

@app.route('/list_credentials')
def legacy_credentials():
    """Legacy endpoint for credentials"""
    return get_credentials()

@app.route('/get_logs')
def legacy_logs():
    """Legacy endpoint for logs"""
    return get_logs()

@app.route('/netkb_data_json')
def legacy_netkb_json():
    """Legacy endpoint for network knowledge base JSON"""
    try:
        netkb_file = shared_data.netkbfile
        if not os.path.exists(netkb_file):
            return jsonify({'ips': [], 'ports': {}, 'actions': []})
            
        import pandas as pd
        df = pd.read_csv(netkb_file)
        data = df[df['Alive'] == 1] if 'Alive' in df.columns else df
        
        # Get available actions from actions file
        actions = []
        try:
            with open(shared_data.actions_file, 'r') as f:
                actions_config = json.load(f)
                actions = list(actions_config.keys())
        except Exception:
            pass
        
        response_data = {
            'ips': data['IPs'].tolist() if 'IPs' in data.columns else [],
            'ports': {row['IPs']: row['Ports'].split(';') for _, row in data.iterrows() if 'Ports' in row},
            'actions': actions
        }
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error getting netkb JSON: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    global clients_connected
    clients_connected += 1
    logger.info(f"Client connected. Total clients: {clients_connected}")
    emit('connected', {'message': 'Connected to Ragnar'})

    # Send initial data to new client
    try:
        ensure_recent_sync()
        status_data = get_current_status()
        emit('status_update', status_data)

        # Send recent logs
        logs = get_recent_logs()
        emit('log_update', logs)
    except Exception as e:
        logger.error(f"Error sending initial data: {e}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    global clients_connected
    clients_connected = max(0, clients_connected - 1)
    logger.info(f"Client disconnected. Total clients: {clients_connected}")


@socketio.on('request_status')
def handle_status_request():
    """Handle status update request"""
    try:
        status_data = get_current_status()
        emit('status_update', status_data)
    except Exception as e:
        logger.error(f"Error handling status request: {e}")


@socketio.on('request_logs')
def handle_log_request():
    """Handle request for recent logs"""
    try:
        logs = get_recent_logs()
        emit('log_update', logs)
    except Exception as e:
        logger.error(f"Error sending logs: {e}")


@socketio.on('request_network')
def handle_network_request():
    """Handle request for network data"""
    try:
        data = load_persistent_network_data()
        emit('network_update', data)
    except Exception as e:
        logger.error(f"Error sending network data: {e}")


@socketio.on('request_credentials')
def handle_credentials_request():
    """Handle request for credentials data"""
    try:
        credentials = web_utils.get_all_credentials()
        emit('credentials_update', credentials)
    except Exception as e:
        logger.error(f"Error sending credentials: {e}")


@socketio.on('request_loot')
def handle_loot_request():
    """Handle request for loot data"""
    try:
        loot = web_utils.get_loot_data()
        emit('loot_update', loot)
    except Exception as e:
        logger.error(f"Error sending loot data: {e}")


@socketio.on('start_scan')
def handle_start_scan(data):
    """Handle scan start request via WebSocket"""
    try:
        scan_type = data.get('type', 'all')
        target = data.get('target', None)
        
        def scan_callback(event_type, event_data):
            socketio.emit('scan_update', {
                'type': event_type,
                'data': event_data
            })
        
        if scan_type == 'single' and target:
            def run_single_scan():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner
                    scanner = NmapVulnScanner(shared_data)
                    scanner.scan_single_host_realtime(
                        ip=target.get('ip', ''),
                        hostname=target.get('hostname', ''),
                        mac=target.get('mac', ''),
                        ports=target.get('ports', ''),
                        callback=scan_callback
                    )
                except Exception as e:
                    scan_callback('scan_error', {'error': str(e)})
            
            threading.Thread(target=run_single_scan, daemon=True).start()
        
        elif scan_type == 'all':
            def run_full_scan():
                try:
                    from actions.nmap_vuln_scanner import NmapVulnScanner
                    scanner = NmapVulnScanner(shared_data)
                    scanner.force_scan_all_hosts(real_time_callback=scan_callback)
                except Exception as e:
                    scan_callback('scan_error', {'error': str(e)})
            
            threading.Thread(target=run_full_scan, daemon=True).start()
        
        emit('scan_started', {'status': 'success', 'type': scan_type})
        
    except Exception as e:
        logger.error(f"Error handling scan start: {e}")
        emit('scan_error', {'error': str(e)})

@socketio.on('stop_scan')
def handle_stop_scan():
    """Handle scan stop request via WebSocket"""
    try:
        # You can implement scan stopping logic here
        emit('scan_stopped', {'status': 'success'})
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        emit('scan_error', {'error': str(e)})


@socketio.on('request_activity')
def handle_activity_request():
    """Handle request for detailed activity logs"""
    try:
        # Generate activity logs directly
        activity_logs = []
        current_time = datetime.now()
        
        # Recent discoveries
        if os.path.exists(shared_data.livestatusfile):
            try:
                import pandas as pd
                df = pd.read_csv(shared_data.livestatusfile)
                alive_hosts = df[df['Alive'] == 1] if 'Alive' in df.columns else df
                for _, row in alive_hosts.tail(10).iterrows():
                    ip = row.get('IP', 'Unknown')
                    hostname = row.get('Hostname', ip)
                    ports = row.get('Ports', '')
                    
                    log_entry = {
                        'timestamp': current_time.strftime("%H:%M:%S"),
                        'type': 'discovery',
                        'icon': '🎯',
                        'message': f"Discovered {hostname} ({ip})",
                        'details': f"Ports: {ports.split(';')[:3] if ports else []}" if ports else "Host responsive",
                        'severity': 'info'
                    }
                    activity_logs.append(log_entry)
            except Exception:
                pass
        
        # Add current status
        if safe_str(shared_data.ragnarstatustext) and safe_str(shared_data.ragnarstatustext) != "Idle":
            activity_logs.append({
                'timestamp': current_time.strftime("%H:%M:%S"),
                'type': 'status',
                'icon': '🤖',
                'message': f"Ragnar: {safe_str(shared_data.ragnarstatustext)}",
                'details': safe_str(shared_data.ragnarstatustext2) if safe_str(shared_data.ragnarstatustext2) else '',
                'severity': 'info'
            })
        
        if safe_str(shared_data.ragnarsays) and safe_str(shared_data.ragnarsays).strip():
            activity_logs.append({
                'timestamp': current_time.strftime("%H:%M:%S"),
                'type': 'activity',
                'icon': '⚡',
                'message': safe_str(shared_data.ragnarsays),
                'details': '',
                'severity': 'info'
            })
        
        emit('activity_update', activity_logs[-20:])  # Send last 20 entries
    except Exception as e:
        logger.error(f"Error sending activity data: {e}")
        emit('activity_update', [])


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

def get_current_status():
    """Get current status data"""
    try:
        shared_data.update_stats()
    except Exception as e:
        logger.debug(f"Unable to refresh gamification stats: {e}")

    return {
        'ragnar_status': safe_str(shared_data.ragnarstatustext),
        'ragnar_status2': safe_str(shared_data.ragnarstatustext2),
        'ragnar_says': safe_str(shared_data.ragnarsays),
        'orchestrator_status': safe_str(shared_data.ragnarorch_status),
        'target_count': safe_int(shared_data.targetnbr),
        'port_count': safe_int(shared_data.portnbr),
        'vulnerability_count': safe_int(shared_data.vulnnbr),
        'credential_count': safe_int(shared_data.crednbr),
        'data_count': safe_int(shared_data.datanbr),
        'level': safe_int(shared_data.levelnbr),
        'points': safe_int(shared_data.coinnbr),
        'coins': safe_int(shared_data.coinnbr),
        'wifi_connected': safe_bool(shared_data.wifi_connected),
        'bluetooth_active': safe_bool(shared_data.bluetooth_active),
        'pan_connected': safe_bool(shared_data.pan_connected),
        'usb_active': safe_bool(shared_data.usb_active),
        'manual_mode': safe_bool(shared_data.config.get('manual_mode', False)),
        'timestamp': datetime.now().isoformat()
    }

def get_recent_logs():
    """Get recent log entries with enhanced activity information focused on security scanning"""
    logs = []
    try:
        # Enhanced logging - aggregate from multiple sources for real-time updates
        
        # Function to filter logs for security focus
        def should_include_realtime_log(log_line):
            """Filter real-time logs to focus on security scanning activities"""
            if not log_line:
                return False
            
            log_lower = log_line.lower()
            
            # Exclude comment.py and other non-essential logs
            exclude_sources = [
                'comment.py', 'comments.py', 'comment_', 'comments_',
                'display.py', 'epd_helper.py', 'webapp_', 'flask',
                'socketio', 'werkzeug', 'http.server', 'static'
            ]
            
            if any(source in log_lower for source in exclude_sources):
                return False
            
            # Always include security scanning and vulnerability logs
            high_priority_keywords = [
                'nmap', 'scan', 'scanning', 'port scan', 'host discovery',
                'vulnerability', 'vuln', 'exploit', 'cve-', 'exploit-db',
                'credential', 'cred', 'password', 'login', 'auth',
                'ssh', 'ftp', 'smb', 'telnet', 'rdp', 'sql', 'mysql', 'postgres',
                'attack', 'brute', 'crack', 'penetration', 'pentest',
                'target', 'host found', 'port open', 'service', 'banner',
                'network intelligence', 'threat intelligence', 'orchestrator',
                'error', 'critical', 'warning', 'fail', 'timeout',
                'discovered', 'found'
            ]
            
            return any(keyword in log_lower for keyword in high_priority_keywords)
        
        # 1. Get web console logs (filtered for security content)
        log_file = shared_data.webconsolelog
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                web_logs = [line.strip() for line in lines[-50:] if line.strip()]
                # Filter for security-relevant logs only
                filtered_web_logs = [log for log in web_logs if should_include_realtime_log(log)]
                logs.extend([f"[WEB] {log}" for log in filtered_web_logs[-10:]])  # Last 10 relevant logs
        
        # 2. Add recent activity summary (only if security-related)
        current_time = datetime.now().strftime("%H:%M:%S")
        
        # Add Ragnar status (only if active scanning/attacking)
        ragnar_status = safe_str(shared_data.ragnarstatustext)
        if ragnar_status and ragnar_status != "Idle":
            status_lower = ragnar_status.lower()
            if any(keyword in status_lower for keyword in ['scan', 'attack', 'discovery', 'exploit', 'brute', 'crack']):
                logs.append(f"[{current_time}] [RAGNAR] 🎯 {ragnar_status}")
        
        # Add orchestrator status (only if active)
        orch_status = safe_str(shared_data.ragnarorch_status)
        if orch_status and orch_status != "Idle":
            orch_lower = orch_status.lower()
            if any(keyword in orch_lower for keyword in ['scan', 'attack', 'discovery', 'exploit', 'target', 'running']):
                logs.append(f"[{current_time}] [ORCHESTRATOR] ⚡ {orch_status}")
        
        # Add what Ragnar says (activity description) - only if security-related
        ragnar_says = safe_str(shared_data.ragnarsays)
        if ragnar_says and ragnar_says.strip():
            if should_include_realtime_log(ragnar_says):
                logs.append(f"[{current_time}] [ACTIVITY] 🔍 {ragnar_says}")
        
        # 3. Add concise stats summary (less frequent)
        if safe_int(shared_data.vulnnbr) > 0 or safe_int(shared_data.crednbr) > 0:
            stats_summary = f"Findings: {safe_int(shared_data.vulnnbr)} vulns | {safe_int(shared_data.crednbr)} creds | {safe_int(shared_data.targetnbr)} targets"
            logs.append(f"[{current_time}] [STATS] 📊 {stats_summary}")
        
        # 4. Check for very recent discoveries (last 5 minutes)
        if os.path.exists(shared_data.livestatusfile):
            try:
                # Check file modification time
                mod_time = os.path.getmtime(shared_data.livestatusfile)
                if time.time() - mod_time < 300:  # 5 minutes
                    logs.append(f"[{current_time}] [DISCOVERY] 🎯 Recent network activity detected")
            except Exception:
                pass
        
        # 5. Only show connectivity if there are security implications
        # Skip general connectivity status to focus on security logs
        
        # Limit to last 20 entries for focused real-time updates
        recent_logs = logs[-20:] if logs else []
        
    except Exception as e:
        logger.error(f"Error reading enhanced logs: {e}")
        logs = [f"[ERROR] Error reading logs: {e}"]
    
    return recent_logs

def broadcast_status_updates():
    """Broadcast status updates to all connected clients"""
    log_counter = 0
    activity_counter = 0
    while not shared_data.webapp_should_exit:
        try:
            if clients_connected > 0:
                ensure_recent_sync()

                # Send status update
                status_data = get_current_status()
                socketio.emit('status_update', status_data)
                
                # Send logs every 5 cycles (10 seconds)
                log_counter += 1
                if log_counter % 5 == 0:
                    logs = get_recent_logs()
                    socketio.emit('log_update', logs)
                
                # Send activity updates every 3 cycles (6 seconds)
                activity_counter += 1
                if activity_counter % 3 == 0:
                    # Generate simplified activity update for real-time broadcast
                    activity_update = []
                    current_time = datetime.now().strftime("%H:%M:%S")
                    
                    # Add current Ragnar activity
                    ragnar_says = safe_str(shared_data.ragnarsays)
                    if ragnar_says and ragnar_says.strip():
                        activity_update.append({
                            'timestamp': current_time,
                            'type': 'activity',
                            'icon': '⚡',
                            'message': ragnar_says,
                            'severity': 'info'
                        })
                    
                    # Add status if something is happening
                    ragnar_status = safe_str(shared_data.ragnarstatustext)
                    if ragnar_status and ragnar_status not in ["Idle", ""]:
                        activity_update.append({
                            'timestamp': current_time,
                            'type': 'status',
                            'icon': '🤖',
                            'message': f"Status: {ragnar_status}",
                            'severity': 'info'
                        })
                    
                    if activity_update:
                        socketio.emit('activity_update', activity_update)
            
            socketio.sleep(2)  # Update every 2 seconds
        except Exception as e:
            logger.error(f"Error broadcasting status: {e}")
            socketio.sleep(5)


def background_sync_loop(interval=SYNC_BACKGROUND_INTERVAL):
    """Continuously synchronize counts so displays remain fresh even without web clients"""
    global background_thread_health
    consecutive_errors = 0
    max_consecutive_errors = 10
    
    while not shared_data.webapp_should_exit:
        try:
            sync_all_counts()
            consecutive_errors = 0  # Reset on success
            background_thread_health['sync_last_run'] = time.time()
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Background sync error (attempt {consecutive_errors}/{max_consecutive_errors}): {e}", exc_info=True)
            
            if consecutive_errors >= max_consecutive_errors:
                logger.critical(f"Background sync failed {max_consecutive_errors} times consecutively! Resetting error counter but continuing...")
                consecutive_errors = 0  # Reset to prevent thread death
                time.sleep(30)  # Wait longer after multiple failures
        
        time.sleep(max(1, interval))

def background_arp_scan_loop():
    """Continuously run ARP scans to keep network data fresh"""
    global network_scan_cache, network_scan_last_update, background_thread_health
    consecutive_errors = 0
    max_consecutive_errors = 10
    
    while not shared_data.webapp_should_exit:
        try:
            current_time = time.time()
            
            # Run ARP scan every ARP_SCAN_INTERVAL seconds
            if current_time - network_scan_last_update >= ARP_SCAN_INTERVAL:
                logger.debug("Running background ARP scan...")
                
                # Run ARP scan
                arp_hosts = run_arp_scan_localnet('wlan0')
                
                # Update cache
                network_scan_cache['arp_hosts'] = arp_hosts
                network_scan_cache['last_arp_scan'] = current_time
                network_scan_last_update = current_time
                background_thread_health['arp_last_run'] = current_time
                
                # Update network knowledge base
                for ip, data in arp_hosts.items():
                    try:
                        update_netkb_entry(ip, data.get('hostname', ''), data.get('mac', ''), True)
                    except Exception as e:
                        logger.error(f"Error updating netkb for {ip}: {e}")
                
                # Update WiFi network data to sync ARP discoveries
                try:
                    update_wifi_network_data()
                except Exception as e:
                    logger.error(f"Error updating WiFi network data from ARP scan: {e}")
                
                # Emit real-time update to connected clients
                if clients_connected > 0:
                    try:
                        socketio.emit('network_update', {
                            'hosts': arp_hosts,
                            'count': len(arp_hosts),
                            'source': 'arp_background',
                            'timestamp': datetime.now().isoformat()
                        })
                    except Exception as e:
                        logger.error(f"Error emitting network update: {e}")
                
                logger.debug(f"Background ARP scan completed, found {len(arp_hosts)} hosts")
                consecutive_errors = 0  # Reset on success
            
            time.sleep(2)  # Check every 2 seconds, but only scan based on interval
            
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Error in background ARP scan loop (attempt {consecutive_errors}/{max_consecutive_errors}): {e}", exc_info=True)
            
            if consecutive_errors >= max_consecutive_errors:
                logger.critical(f"Background ARP scan failed {max_consecutive_errors} times consecutively! Resetting error counter but continuing...")
                consecutive_errors = 0  # Reset to prevent thread death
                time.sleep(30)  # Wait longer after multiple failures
            else:
                time.sleep(5)  # Wait a bit before retry
            time.sleep(ARP_SCAN_INTERVAL)


# Health monitoring for background threads
background_thread_health = {
    'sync_last_run': 0,
    'arp_last_run': 0,
    'sync_alive': False,
    'arp_alive': False
}

def background_health_monitor():
    """Monitor background threads and log warnings if they stop responding"""
    global background_thread_health
    
    while not shared_data.webapp_should_exit:
        try:
            current_time = time.time()
            
            # Check sync thread - should run every 5 seconds
            if background_thread_health['sync_last_run'] > 0:
                time_since_sync = current_time - background_thread_health['sync_last_run']
                if time_since_sync > 30:  # No sync for 30 seconds
                    logger.warning(f"⚠️ Background sync thread appears stuck! Last run was {time_since_sync:.0f}s ago")
                    background_thread_health['sync_alive'] = False
                else:
                    background_thread_health['sync_alive'] = True
            
            # Check ARP thread - should run every 10 seconds  
            if background_thread_health['arp_last_run'] > 0:
                time_since_arp = current_time - background_thread_health['arp_last_run']
                if time_since_arp > 60:  # No ARP scan for 60 seconds
                    logger.warning(f"⚠️ Background ARP scan thread appears stuck! Last run was {time_since_arp:.0f}s ago")
                    background_thread_health['arp_alive'] = False
                else:
                    background_thread_health['arp_alive'] = True
            
            time.sleep(15)  # Check every 15 seconds
            
        except Exception as e:
            logger.error(f"Error in health monitor: {e}", exc_info=True)
            time.sleep(15)


# ============================================================================
# MANUAL MODE ENDPOINTS
# ============================================================================

@app.route('/api/manual/status')
def get_manual_mode_status():
    """Get current manual mode status"""
    try:
        return jsonify({
            'manual_mode': shared_data.config.get('manual_mode', False),
            'orchestrator_status': shared_data.ragnarorch_status
        })
    except Exception as e:
        logger.error(f"Error getting manual mode status: {e}")
        return jsonify({'error': str(e)}), 500

def _collect_manual_targets():
    """Collect targets available for manual operations."""
    targets = []
    target_ips = set()  # Track unique IPs to avoid duplicates

    # Read from the live status file first
    if os.path.exists(shared_data.livestatusfile):
        with open(shared_data.livestatusfile, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get('Alive') == '1':  # Only alive targets
                    ip = row.get('IP', '')
                    hostname = row.get('Hostname', ip)

                    # Get open ports
                    ports = []
                    for key, value in row.items():
                        if key.isdigit() and value:  # Port columns with values
                            ports.append(key)

                    if ip and ip not in target_ips:
                        targets.append({
                            'ip': ip,
                            'hostname': hostname,
                            'ports': ports,
                            'source': 'Network Scan'
                        })
                        target_ips.add(ip)

    # Also include hosts from NetKB data
    try:
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        if os.path.exists(scan_results_dir):
            for filename in os.listdir(scan_results_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                # Extract IP from filename or content
                                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                host_ip = ip_match.group() if ip_match else 'Unknown'

                                if host_ip and host_ip not in target_ips:
                                    # Parse port/service info from content
                                    ports = []
                                    for line in content.split('\n'):
                                        if '/tcp' in line or '/udp' in line:
                                            parts = line.split()
                                            if len(parts) >= 1:
                                                port = parts[0].split('/')[0]  # Extract port number only
                                                if port.isdigit() and port not in ports:
                                                    ports.append(port)

                                    targets.append({
                                        'ip': host_ip,
                                        'hostname': host_ip,  # Use IP as hostname if no other info
                                        'ports': ports,
                                        'source': 'NetKB'
                                    })
                                    target_ips.add(host_ip)
                    except Exception:
                        continue

        # Add example targets if no real data exists
        if not targets:
            targets = [
                {
                    'ip': '192.168.1.1',
                    'hostname': '192.168.1.1',
                    'ports': ['22', '80', '443'],
                    'source': 'Example'
                },
                {
                    'ip': '192.168.1.100',
                    'hostname': '192.168.1.100',
                    'ports': ['80', '443'],
                    'source': 'Example'
                }
            ]
    except Exception as e:
        logger.error(f"Error processing NetKB data for targets: {e}")

    return targets


@app.route('/api/manual/targets')
def get_manual_targets():
    """Get available targets for manual attacks"""
    try:
        targets = _collect_manual_targets()
        return jsonify({'targets': targets})

    except Exception as e:
        logger.error(f"Error getting manual targets: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/manual/execute-attack', methods=['POST'])
def execute_manual_attack():
    """Execute a manual attack on a specific target"""
    try:
        data = request.get_json()
        target_ip = data.get('ip')
        target_port = data.get('port') 
        attack_type = data.get('action')
        
        if not target_ip or not attack_type:
            return jsonify({'success': False, 'error': 'Missing IP or attack type'}), 400
        
        # Update status to show attack is active
        attack_display_names = {
            'ssh': 'SSHBruteforce',
            'ftp': 'FTPBruteforce',
            'telnet': 'TelnetBruteforce',
            'smb': 'SMBBruteforce',
            'rdp': 'RDPBruteforce',
            'sql': 'SQLBruteforce'
        }
        
        status_name = attack_display_names.get(attack_type, f"{attack_type.upper()}Bruteforce")
        shared_data.ragnarstatustext = status_name
        shared_data.ragnarstatustext2 = f"Attacking: {target_ip}:{target_port or 'default'}"
        
        # Immediately broadcast the status change
        broadcast_status_update()
        
        # Map attack types to module imports and execution
        attack_modules = {
            'ssh': 'actions.ssh_connector',
            'ftp': 'actions.ftp_connector', 
            'telnet': 'actions.telnet_connector',
            'smb': 'actions.smb_connector',
            'rdp': 'actions.rdp_connector',
            'sql': 'actions.sql_connector'
        }
        
        if attack_type not in attack_modules:
            shared_data.ragnarstatustext = "IDLE"
            shared_data.ragnarstatustext2 = "Invalid attack type"
            return jsonify({'success': False, 'error': 'Invalid attack type'}), 400
        
        # Execute attack in background
        def execute_attack():
            try:
                # Import the attack module dynamically
                import importlib
                module = importlib.import_module(attack_modules[attack_type])
                
                # Create attack instance
                attack_class_name = attack_type.upper() + 'Bruteforce' if attack_type != 'sql' else 'SQLBruteforce'
                attack_class = getattr(module, attack_class_name, None)
                
                if attack_class:
                    attack_instance = attack_class(shared_data)
                    # Execute with appropriate parameters
                    if hasattr(attack_instance, 'execute'):
                        row = {'ip': target_ip, 'hostname': target_ip, 'mac': '00:00:00:00:00:00'}
                        attack_instance.execute(target_ip, target_port, row, f"manual_{attack_type}")
                    
                # Update status when attack completes
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"{attack_type.upper()} attack completed"
                
                # Broadcast completion status
                broadcast_status_update()
                
                logger.info(f"Manual attack completed: {attack_type} on {target_ip}:{target_port}")
                    
            except Exception as e:
                logger.error(f"Error executing manual attack: {e}")
                # Reset status on error
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"Attack error: {str(e)[:40]}"
                # Broadcast error status
                broadcast_status_update()
        
        # Start attack in background thread
        import threading
        threading.Thread(target=execute_attack, daemon=True).start()
        
        logger.info(f"Manual attack initiated: {attack_type} on {target_ip}:{target_port}")
        
        return jsonify({
            'success': True,
            'message': f'Manual {attack_type} attack initiated on {target_ip}' + (f':{target_port}' if target_port else '')
        })
        
    except Exception as e:
        logger.error(f"Error executing manual attack: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/orchestrator/start', methods=['POST'])
def start_orchestrator_manual():
    """Start the orchestrator in manual mode"""
    try:
        # Update shared data to indicate manual mode
        shared_data.config['manual_mode'] = True
        shared_data.save_config()  # Save the configuration
        
        logger.info("Manual mode enabled")
        
        return jsonify({
            'success': True,
            'message': 'Manual mode enabled - use individual triggers for actions'
        })
        
    except Exception as e:
        logger.error(f"Error enabling manual mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/orchestrator/stop', methods=['POST'])
def stop_orchestrator_manual():
    """Disable manual mode"""
    try:
        # Update shared data to disable manual mode
        shared_data.config['manual_mode'] = False
        shared_data.save_config()  # Save the configuration
        
        logger.info("Manual mode disabled")
        
        return jsonify({
            'success': True,
            'message': 'Manual mode disabled'
        })
        
    except Exception as e:
        logger.error(f"Error disabling manual mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/scan/network', methods=['POST'])
def trigger_network_scan():
    """Trigger a manual network scan"""
    try:
        data = request.get_json()
        target_range = data.get('range', '192.168.1.0/24')  # Default range
        
        # Update status to show scanning is active
        shared_data.ragnarstatustext = "NetworkScanner"
        shared_data.ragnarstatustext2 = f"Manual scan: {target_range}"
        
        # Immediately broadcast the status change
        broadcast_status_update()
        
        # Execute scan in background
        def execute_scan():
            try:
                # Import and create scanner
                from actions.scanning import NetworkScanner
                scanner = NetworkScanner(shared_data)
                
                # Run the scan
                scanner.scan()
                
                # Update status when scan completes
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = "Manual scan completed"
                
                # Broadcast completion status
                broadcast_status_update()
                
                logger.info(f"Manual network scan completed for range: {target_range}")
                
            except Exception as e:
                logger.error(f"Error executing network scan: {e}")
                # Reset status on error
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"Scan error: {str(e)[:50]}"
                # Broadcast error status
                broadcast_status_update()
        
        # Start scan in background thread
        import threading
        threading.Thread(target=execute_scan, daemon=True).start()
        
        logger.info(f"Manual network scan initiated for range: {target_range}")
        
        return jsonify({
            'success': True,
            'message': f'Network scan initiated for {target_range}'
        })
        
    except Exception as e:
        logger.error(f"Error triggering network scan: {e}")
        # Reset status on error
        shared_data.ragnarstatustext = "IDLE"
        shared_data.ragnarstatustext2 = f"Failed to start scan"
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/manual/scan/vulnerability', methods=['POST'])
def trigger_vulnerability_scan():
    """Trigger a manual vulnerability scan"""
    try:
        data = request.get_json(silent=True) or {}
        target_ip = (data.get('ip') or '').strip()

        available_targets = _collect_manual_targets()
        if not available_targets:
            return jsonify({'success': False, 'error': 'No targets available for vulnerability scan'}), 400

        is_all_targets = not target_ip or target_ip.lower() == 'all'

        if is_all_targets:
            targets_to_scan = available_targets
            status_target = 'All Targets'
        else:
            targets_to_scan = [t for t in available_targets if t.get('ip') == target_ip]
            status_target = target_ip
            if not targets_to_scan:
                return jsonify({'success': False, 'error': f'Target {target_ip} not found'}), 404

        # Update status to show vulnerability scanning is active
        shared_data.ragnarstatustext = "NmapVulnScanner"
        shared_data.ragnarstatustext2 = f"Scanning: {status_target}"

        # Immediately broadcast the status change
        broadcast_status_update()

        # Execute vulnerability scan in background
        def execute_vuln_scan():
            try:
                # Import and create vulnerability scanner
                from actions.nmap_vuln_scanner import NmapVulnScanner
                vuln_scanner = NmapVulnScanner(shared_data)

                for target in targets_to_scan:
                    ip = target.get('ip')
                    hostname = target.get('hostname') or ip
                    ports = [str(port) for port in target.get('ports', []) if str(port).strip()]

                    if not ports:
                        ports = ['1-65535']

                    row = {
                        'Ports': ';'.join(ports),
                        'Hostnames': hostname,
                        'MAC Address': target.get('mac', '00:00:00:00:00:00')
                    }

                    shared_data.ragnarstatustext2 = f"Scanning: {ip}"
                    broadcast_status_update()

                    vuln_scanner.execute(ip, row, "manual_vuln_scan")

                # Update status when scan completes
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = "Vulnerability scan completed"

                # Broadcast completion status
                broadcast_status_update()
                
                logger.info(f"Manual vulnerability scan completed for: {status_target}")
                
            except Exception as e:
                logger.error(f"Error executing vulnerability scan: {e}")
                # Reset status on error
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"Vuln scan error: {str(e)[:40]}"
                # Broadcast error status
                broadcast_status_update()
        
        # Start scan in background thread
        import threading
        threading.Thread(target=execute_vuln_scan, daemon=True).start()
        
        logger.info(f"Manual vulnerability scan initiated for: {status_target}")

        return jsonify({
            'success': True,
            'message': 'Vulnerability scan initiated for all targets' if is_all_targets else f'Vulnerability scan initiated for {target_ip}'
        })
        
    except Exception as e:
        logger.error(f"Error triggering vulnerability scan: {e}")
        # Reset status on error
        shared_data.ragnarstatustext = "IDLE"
        shared_data.ragnarstatustext2 = f"Failed to start vuln scan"
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# FILE MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/files/list')
def list_files_api():
    """List files in a directory for file management"""
    try:
        path = request.args.get('path', '/')
        
        # Map root paths to actual directories
        if path == '/' or path == '':
            # List main directories
            return jsonify([
                {'name': 'data_stolen', 'is_directory': True, 'path': '/data_stolen'},
                {'name': 'scan_results', 'is_directory': True, 'path': '/scan_results'},
                {'name': 'crackedpwd', 'is_directory': True, 'path': '/crackedpwd'},
                {'name': 'vulnerabilities', 'is_directory': True, 'path': '/vulnerabilities'},
                {'name': 'logs', 'is_directory': True, 'path': '/logs'},
                {'name': 'backups', 'is_directory': True, 'path': '/backups'},
                {'name': 'uploads', 'is_directory': True, 'path': '/uploads'}
            ])
        
        # Map paths to actual directories
        actual_path = ""
        if path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir
            if len(path) > 12:  # More than just '/data_stolen'
                actual_path = os.path.join(actual_path, path[13:])
        elif path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir
            if len(path) > 13:  # More than just '/scan_results'
                actual_path = os.path.join(actual_path, path[14:])
        elif path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir
            if len(path) > 11:  # More than just '/crackedpwd'
                actual_path = os.path.join(actual_path, path[12:])
        elif path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir
            if len(path) > 16:  # More than just '/vulnerabilities'
                actual_path = os.path.join(actual_path, path[17:])
        elif path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs'
            if len(path) > 5:  # More than just '/logs'
                actual_path = os.path.join(actual_path, path[6:])
        elif path.startswith('/backups'):
            actual_path = shared_data.backupdir
            if len(path) > 8:  # More than just '/backups'
                actual_path = os.path.join(actual_path, path[9:])
        elif path.startswith('/uploads'):
            actual_path = shared_data.upload_dir
            if len(path) > 8:  # More than just '/uploads'
                actual_path = os.path.join(actual_path, path[9:])
        else:
            return jsonify({'error': 'Invalid path'}), 400
        
        # Check if directory exists
        if not os.path.exists(actual_path):
            return jsonify([])
        
        # List files in directory
        files = []
        for entry in os.scandir(actual_path):
            files.append({
                'name': entry.name,
                'is_directory': entry.is_dir(),
                'path': os.path.join(path, entry.name),
                'size': entry.stat().st_size if entry.is_file() else 0,
                'modified': entry.stat().st_mtime
            })
        
        # Sort files - directories first, then by name
        files.sort(key=lambda x: (not x['is_directory'], x['name'].lower()))
        
        return jsonify(files)
        
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/download')
def download_file_api():
    """Download a file"""
    try:
        file_path = request.args.get('path')
        if not file_path:
            return jsonify({'error': 'File path required'}), 400
        
        # Map virtual path to actual path
        actual_path = ""
        if file_path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir + file_path[12:]
        elif file_path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir + file_path[13:]
        elif file_path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir + file_path[11:]
        elif file_path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir + file_path[16:]
        elif file_path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs' + file_path[5:]
        elif file_path.startswith('/backups'):
            actual_path = shared_data.backupdir + file_path[8:]
        elif file_path.startswith('/uploads'):
            actual_path = shared_data.upload_dir + file_path[8:]
        else:
            return jsonify({'error': 'Invalid file path'}), 400
        
        if not os.path.isfile(actual_path):
            return jsonify({'error': 'File not found'}), 404
        
        return send_from_directory(
            os.path.dirname(actual_path),
            os.path.basename(actual_path),
            as_attachment=True
        )
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/delete', methods=['POST'])
def delete_file_api():
    """Delete a file or directory"""
    try:
        data = request.get_json()
        file_path = data.get('path')
        
        if not file_path:
            return jsonify({'error': 'File path required'}), 400
        
        # Map virtual path to actual path
        actual_path = ""
        if file_path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir + file_path[12:]
        elif file_path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir + file_path[13:]
        elif file_path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir + file_path[11:]
        elif file_path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir + file_path[16:]
        elif file_path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs' + file_path[5:]
        elif file_path.startswith('/backups'):
            actual_path = shared_data.backupdir + file_path[8:]
        elif file_path.startswith('/uploads'):
            actual_path = shared_data.upload_dir + file_path[8:]
        else:
            return jsonify({'error': 'Invalid file path'}), 400
        
        if not os.path.exists(actual_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Delete file or directory
        if os.path.isdir(actual_path):
            import shutil
            shutil.rmtree(actual_path)
            logger.info(f"Deleted directory: {actual_path}")
        else:
            os.remove(actual_path)
            logger.info(f"Deleted file: {actual_path}")
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/upload', methods=['POST'])
def upload_file_api():
    """Upload a file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        target_path = request.form.get('path', '/uploads')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Map virtual path to actual path
        actual_dir = ""
        if target_path.startswith('/uploads'):
            actual_dir = shared_data.upload_dir
        elif target_path.startswith('/backups'):
            actual_dir = shared_data.backupdir
        else:
            return jsonify({'error': 'Invalid upload path'}), 400
        
        # Create directory if it doesn't exist
        os.makedirs(actual_dir, exist_ok=True)
        
        # Save file
        filename = file.filename
        if not filename:
            return jsonify({'error': 'Invalid filename'}), 400
            
        actual_path = os.path.join(actual_dir, filename)
        file.save(actual_path)
        
        logger.info(f"File uploaded: {actual_path}")
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'filename': filename
        })
        
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/clear', methods=['POST'])
def clear_files_api():
    """Clear files from specified directories"""
    try:
        data = request.get_json()
        clear_type = data.get('type', 'light')  # 'light' or 'full'
        
        if clear_type == 'light':
            # Clear only logs and temporary files (like clear_files_light)
            command = f"""
            rm -rf {shared_data.datadir}/*.log && 
            rm -rf {shared_data.datastolendir}/* && 
            rm -rf {shared_data.crackedpwddir}/* && 
            rm -rf {shared_data.scan_results_dir}/* && 
            rm -rf {shared_data.datadir}/logs/* && 
            rm -rf {shared_data.vulnerabilities_dir}/*
            """
        else:
            # Full clear (like clear_files)
            command = f"""
            rm -rf {shared_data.configdir}/*.json && 
            rm -rf {shared_data.datadir}/*.csv && 
            rm -rf {shared_data.datadir}/*.log && 
            rm -rf {shared_data.backupdir}/* && 
            rm -rf {shared_data.upload_dir}/* && 
            rm -rf {shared_data.datastolendir}/* && 
            rm -rf {shared_data.crackedpwddir}/* && 
            rm -rf {shared_data.scan_results_dir}/* && 
            rm -rf {shared_data.datadir}/logs/* && 
            rm -rf {shared_data.vulnerabilities_dir}/*
            """
        
        import subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Files cleared successfully ({clear_type} clear)")
            return jsonify({
                'success': True,
                'message': f'Files cleared successfully ({clear_type} clear)'
            })
        else:
            logger.error(f"Error clearing files: {result.stderr}")
            return jsonify({'error': result.stderr}), 500
        
    except Exception as e:
        logger.error(f"Error clearing files: {e}")
        return jsonify({'error': str(e)}), 500

# Legacy endpoint compatibility
@app.route('/list_files')
def legacy_list_files():
    """Legacy endpoint for file listing"""
    try:
        path = request.args.get('path', '/')
        
        # Use the same logic as list_files_api but return legacy format
        if path == '/' or path == '':
            return jsonify([
                {'name': 'data_stolen', 'is_directory': True, 'children': []},
                {'name': 'scan_results', 'is_directory': True, 'children': []},
                {'name': 'crackedpwd', 'is_directory': True, 'children': []},
                {'name': 'vulnerabilities', 'is_directory': True, 'children': []},
                {'name': 'logs', 'is_directory': True, 'children': []},
                {'name': 'backups', 'is_directory': True, 'children': []},
                {'name': 'uploads', 'is_directory': True, 'children': []}
            ])
        
        # For other paths, use the web_utils function
        actual_path = ""
        if path.startswith('/data_stolen'):
            actual_path = shared_data.datastolendir
        elif path.startswith('/scan_results'):
            actual_path = shared_data.scan_results_dir
        elif path.startswith('/crackedpwd'):
            actual_path = shared_data.crackedpwddir
        elif path.startswith('/vulnerabilities'):
            actual_path = shared_data.vulnerabilities_dir
        elif path.startswith('/logs'):
            actual_path = shared_data.datadir + '/logs'
        elif path.startswith('/backups'):
            actual_path = shared_data.backupdir
        elif path.startswith('/uploads'):
            actual_path = shared_data.upload_dir
        
        if actual_path and os.path.exists(actual_path):
            return jsonify(web_utils.list_files(actual_path))
        else:
            return jsonify([])
        
    except Exception as e:
        logger.error(f"Error in legacy file listing: {e}")
        return jsonify([])

@app.route('/download_file')
def legacy_download_file():
    """Legacy endpoint for file download"""
    try:
        file_path = request.args.get('path')
        if not file_path:
            return "File path required", 400
            
        # Check if file exists in data_stolen directory
        actual_path = os.path.join(shared_data.datastolendir, file_path)
        if os.path.isfile(actual_path):
            return send_from_directory(
                os.path.dirname(actual_path),
                os.path.basename(actual_path),
                as_attachment=True
            )
        else:
            return "File not found", 404
    except Exception as e:
        logger.error(f"Error in legacy file download: {e}")
        return str(e), 500

# ============================================================================
# IMAGE GALLERY ENDPOINTS
# ============================================================================

@app.route('/api/images/list')
def list_images_api():
    """Get list of all images and screenshots"""
    try:
        images = []
        
        # Define image directories to scan
        image_dirs = [
            ('screenshots', shared_data.webdir),  # Screenshots in web directory
            ('status_images', shared_data.statuspicdir),  # Status images
            ('static_images', shared_data.staticpicdir),  # Static images  
            ('captured_images', shared_data.datastolendir)  # Captured images in data stolen
        ]
        
        for category, directory in image_dirs:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp')):
                            filepath = os.path.join(root, file)
                            try:
                                stat = os.stat(filepath)
                                rel_path = os.path.relpath(filepath, shared_data.currentdir)
                                
                                images.append({
                                    'filename': file,
                                    'path': rel_path.replace('\\', '/'),
                                    'full_path': filepath,
                                    'category': category,
                                    'size': stat.st_size,
                                    'modified': stat.st_mtime,
                                    'url': f'/api/images/serve?path={rel_path.replace(chr(92), "/")}'
                                })
                            except Exception as e:
                                logger.error(f"Error processing image {file}: {e}")
        
        # Sort by modification time (newest first)
        images.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify(images)
        
    except Exception as e:
        logger.error(f"Error listing images: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/serve')
def serve_image_api():
    """Serve an image file"""
    try:
        image_path = request.args.get('path')
        if not image_path:
            return jsonify({'error': 'Image path required'}), 400
        
        # Security check - ensure path is within project directory
        full_path = os.path.join(shared_data.currentdir, image_path)
        full_path = os.path.normpath(full_path)
        
        if not full_path.startswith(shared_data.currentdir):
            return jsonify({'error': 'Invalid path'}), 403
        
        if not os.path.isfile(full_path):
            return jsonify({'error': 'Image not found'}), 404
        
        return send_from_directory(
            os.path.dirname(full_path),
            os.path.basename(full_path)
        )
        
    except Exception as e:
        logger.error(f"Error serving image: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/delete', methods=['POST'])
def delete_image_api():
    """Delete an image file"""
    try:
        data = request.get_json()
        image_path = data.get('path')
        
        if not image_path:
            return jsonify({'error': 'Image path required'}), 400
        
        # Security check - ensure path is within project directory
        full_path = os.path.join(shared_data.currentdir, image_path)
        full_path = os.path.normpath(full_path)
        
        if not full_path.startswith(shared_data.currentdir):
            return jsonify({'error': 'Invalid path'}), 403
        
        if not os.path.isfile(full_path):
            return jsonify({'error': 'Image not found'}), 404
        
        os.remove(full_path)
        logger.info(f"Deleted image: {full_path}")
        
        return jsonify({'success': True, 'message': 'Image deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting image: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/capture', methods=['POST'])
def capture_screenshot_api():
    """Capture a new screenshot"""
    try:
        # Import display module for screenshot capture
        import display
        
        # Generate timestamp filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"screenshot_{timestamp}.png"
        filepath = os.path.join(shared_data.webdir, filename)
        
        # Capture screenshot - create a placeholder for now
        success = False
            
        if not success:
            # Fallback to creating a placeholder
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new('RGB', (400, 300), color='black')
            draw = ImageDraw.Draw(img)
            draw.text((50, 150), f"Screenshot captured\n{timestamp}", fill='white')
            img.save(filepath)
            success = True
        
        if success:
            return jsonify({
                'success': True, 
                'message': 'Screenshot captured successfully',
                'filename': filename,
                'path': f'web/{filename}'
            })
        else:
            return jsonify({'error': 'Failed to capture screenshot'}), 500
        
    except Exception as e:
        logger.error(f"Error capturing screenshot: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/images/info')
def get_image_info_api():
    """Get detailed information about an image"""
    try:
        image_path = request.args.get('path')
        if not image_path:
            return jsonify({'error': 'Image path required'}), 400
        
        # Security check
        full_path = os.path.join(shared_data.currentdir, image_path)
        full_path = os.path.normpath(full_path)
        
        if not full_path.startswith(shared_data.currentdir):
            return jsonify({'error': 'Invalid path'}), 403
        
        if not os.path.isfile(full_path):
            return jsonify({'error': 'Image not found'}), 404
        
        # Get file stats
        stat = os.stat(full_path)
        
        # Try to get image dimensions
        try:
            from PIL import Image
            with Image.open(full_path) as img:
                width, height = img.size
                format_type = img.format
        except Exception:
            width = height = format_type = None
        
        info = {
            'filename': os.path.basename(full_path),
            'path': image_path,
            'size': stat.st_size,
            'size_formatted': format_bytes(stat.st_size),
            'modified': stat.st_mtime,
            'modified_formatted': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'width': width,
            'height': height,
            'format': format_type
        };
        
        return jsonify(info);
        
    except Exception as e:
        logger.error(f"Error getting image info: {e}")
        return jsonify({'error': str(e)}), 500

def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    if bytes_value == 0:
        return '0 B'
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"

# ============================================================================
# SYSTEM MONITORING ENDPOINTS
# ============================================================================

@app.route('/api/system/status')
def get_system_status_api():
    """Get comprehensive system status"""
    try:
        if not psutil_available:
            return jsonify({'error': 'System monitoring not available'}), 503
            
        # CPU Information
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        # Memory Information
        memory = psutil.virtual_memory()
        
        # Disk Information
        disk = psutil.disk_usage('/')
        
        # Network Interfaces
        net_if = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()
        
        # System Information
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        # Process Information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': pinfo['cpu_percent'],
                    'memory_percent': pinfo['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort processes by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        processes = processes[:10]  # Top 10 processes
        
        # Temperature (if available)
        try:
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                temperature_data = {}
                for name, entries in temps.items():
                    for entry in entries:
                        temperature_data[f"{name}_{entry.label}"] = entry.current
            else:
                temperature_data = {}
        except:
            temperature_data = {}
        
        # Network interface details
        network_interfaces = []
        for interface, addrs in net_if.items():
            if interface in net_stats:
                stats = net_stats[interface]
                interface_info = {
                    'name': interface,
                    'is_up': stats.isup,
                    'speed': stats.speed,
                    'addresses': []
                }
                
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                
                network_interfaces.append(interface_info)
        
        system_status = {
            'cpu': {
                'percent': round(cpu_percent, 1),
                'count': cpu_count,
                'frequency': {
                    'current': round(cpu_freq.current, 2) if cpu_freq else None,
                    'min': round(cpu_freq.min, 2) if cpu_freq else None,
                    'max': round(cpu_freq.max, 2) if cpu_freq else None
                }
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percent': round(memory.percent, 1),
                'total_formatted': format_bytes(memory.total),
                'available_formatted': format_bytes(memory.available),
                'used_formatted': format_bytes(memory.used)
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': round((disk.used / disk.total) * 100, 1),
                'total_formatted': format_bytes(disk.total),
                'used_formatted': format_bytes(disk.used),
                'free_formatted': format_bytes(disk.free)
            },
            'uptime': {
                'seconds': round(uptime),
                'formatted': format_uptime(uptime)
            },
            'processes': processes,
            'network_interfaces': network_interfaces,
            'temperatures': temperature_data
        }
        
        return jsonify(system_status)
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/processes')
def get_processes_api():
    """Get detailed process information"""
    try:
        if not psutil_available:
            return jsonify({'error': 'Process monitoring not available'}), 503
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': round(pinfo['cpu_percent'] or 0, 2),
                    'memory_percent': round(pinfo['memory_percent'] or 0, 2),
                    'status': pinfo['status'],
                    'create_time': pinfo['create_time']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage
        sort_by = request.args.get('sort', 'cpu')
        if sort_by == 'memory':
            processes.sort(key=lambda x: x['memory_percent'], reverse=True)
        else:
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        return jsonify(processes)
        
    except Exception as e:
        logger.error(f"Error getting processes: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/network-stats')
def get_network_stats_api():
    """Get network interface statistics"""
    try:
        if not psutil_available:
            return jsonify({'error': 'Network monitoring not available'}), 503
        
        net_io = psutil.net_io_counters(pernic=True)
        net_connections = psutil.net_connections()
        
        # Count connections by status
        connection_stats = {}
        for conn in net_connections:
            status = conn.status
            connection_stats[status] = connection_stats.get(status, 0) + 1
        
        network_stats = {
            'interfaces': {},
            'connections': connection_stats,
            'total_connections': len(net_connections)
        }
        
        for interface, stats in net_io.items():
            network_stats['interfaces'][interface] = {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout,
                'bytes_sent_formatted': format_bytes(stats.bytes_sent),
                'bytes_recv_formatted': format_bytes(stats.bytes_recv)
            }
        
        return jsonify(network_stats)
        
    except Exception as e:
        logger.error(f"Error getting network stats: {e}")
        return jsonify({'error': str(e)}), 500

def format_uptime(seconds):
    """Format uptime in human readable format"""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"

# ============================================================================
# DASHBOARD API ENDPOINTS
# ============================================================================

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get dashboard statistics using synchronized data from shared_data to ensure consistency"""
    try:
        # Check for network switches and clear old data if needed
        check_and_handle_network_switch()
        
        # Ensure recent synchronization without blocking the request unnecessarily
        ensure_recent_sync()
        
        # Use the synchronized data from shared_data instead of re-calculating
        # This prevents inconsistencies between different counting methods
        current_time = time.time()
        last_sync_ts = getattr(shared_data, 'last_sync_timestamp', last_sync_time)
        last_sync_iso = None
        last_sync_age = None

        if last_sync_ts:
            try:
                last_sync_iso = datetime.fromtimestamp(last_sync_ts).isoformat()
                last_sync_age = max(current_time - last_sync_ts, 0.0)
            except Exception:
                last_sync_iso = None

        # Use the already-synchronized counts from shared_data to ensure consistency
        # across all endpoints (prevents the flickering between different counts)
        active_target_count = safe_int(shared_data.targetnbr)
        total_target_count = safe_int(shared_data.total_targetnbr)
        inactive_target_count = safe_int(shared_data.inactive_targetnbr)
        
        # If we don't have proper total/inactive counts, calculate them from active count
        if total_target_count == 0 and active_target_count > 0:
            total_target_count = active_target_count
            inactive_target_count = 0
        elif inactive_target_count == 0 and total_target_count > active_target_count:
            inactive_target_count = total_target_count - active_target_count

        logger.debug(f"[DASHBOARD STATS] Using synchronized counts: active={active_target_count}, total={total_target_count}, inactive={inactive_target_count}")

        stats = {
            'target_count': active_target_count,
            'active_target_count': active_target_count,
            'inactive_target_count': inactive_target_count,
            'total_target_count': total_target_count,
            'new_target_count': safe_int(getattr(shared_data, 'new_targets', 0)),
            'lost_target_count': safe_int(getattr(shared_data, 'lost_targets', 0)),
            'new_target_ips': getattr(shared_data, 'new_target_ips', []),
            'lost_target_ips': getattr(shared_data, 'lost_target_ips', []),
            'port_count': safe_int(shared_data.portnbr),
            'vulnerability_count': safe_int(shared_data.vulnnbr),
            'credential_count': safe_int(shared_data.crednbr),
            'level': safe_int(shared_data.levelnbr),
            'points': safe_int(shared_data.coinnbr),
            'coins': safe_int(shared_data.coinnbr),
            'last_sync_timestamp': last_sync_ts,
            'last_sync_iso': last_sync_iso,
            'last_sync_age_seconds': last_sync_age
        }

        response = jsonify(stats)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# NETKB (Network Knowledge Base) API ENDPOINTS
# ============================================================================

@app.route('/api/netkb/data')
def get_netkb_data():
    """Get network knowledge base data"""
    try:
        netkb_entries = []
        
        # Process network scan results
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        
        # Create directory if it doesn't exist
        try:
            os.makedirs(scan_results_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create scan_results directory: {e}")
        
        if os.path.exists(scan_results_dir):
            try:
                for filename in os.listdir(scan_results_dir):
                    if filename.endswith('.txt') and not filename.startswith('.'):
                        filepath = os.path.join(scan_results_dir, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if content.strip():
                                    # Extract IP from filename or content
                                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                    host_ip = ip_match.group() if ip_match else 'Unknown'
                                    
                                    # Parse port/service info from content
                                    for line in content.split('\n'):
                                        if '/tcp' in line or '/udp' in line:
                                            parts = line.split()
                                            if len(parts) >= 3:
                                                port = parts[0]
                                                service = parts[2] if len(parts) > 2 else 'unknown'
                                                
                                                netkb_entries.append({
                                                    'id': f"scan_{host_ip}_{port}",
                                                    'type': 'service',
                                                    'host': host_ip,
                                                    'port': port,
                                                    'service': service,
                                                    'description': f"Service {service} running on {port}",
                                                    'severity': 'info',
                                                    'discovered': os.path.getmtime(filepath),
                                                    'source': 'Network Scan'
                                                })
                        except Exception as e:
                            logger.debug(f"Could not read scan result file {filepath}: {e}")
                            continue
            except Exception as e:
                logger.warning(f"Could not list scan_results directory: {e}")
        
        # Process vulnerability scan results
        vuln_results_dir = getattr(shared_data, 'vulnerabilities_dir', os.path.join('data', 'output', 'vulnerabilities'))
        
        # Create directory if it doesn't exist
        try:
            os.makedirs(vuln_results_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create vulnerabilities directory: {e}")
        
        if os.path.exists(vuln_results_dir):
            try:
                for filename in os.listdir(vuln_results_dir):
                    if filename.endswith('.txt') and not filename.startswith('.'):
                        filepath = os.path.join(vuln_results_dir, filename)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if content.strip():
                                    # Extract vulnerability information
                                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                    host_ip = ip_match.group() if ip_match else 'Unknown'
                                    
                                    # Look for CVE patterns
                                    cve_matches = re.findall(r'CVE-\d{4}-\d+', content)
                                    for cve in cve_matches:
                                        netkb_entries.append({
                                            'id': f"vuln_{host_ip}_{cve}",
                                            'type': 'vulnerability',
                                            'host': host_ip,
                                            'port': '',
                                            'service': '',
                                            'description': f"Vulnerability {cve} detected",
                                            'severity': 'high',
                                            'discovered': os.path.getmtime(filepath),
                                            'source': 'Vulnerability Scan',
                                            'cve': cve
                                        })
                                    
                                    # Generic vulnerability entries for files without CVEs
                                    if not cve_matches and len(content.strip()) > 50:
                                        netkb_entries.append({
                                            'id': f"vuln_{host_ip}_{os.path.basename(filename)}",
                                            'type': 'vulnerability',
                                            'host': host_ip,
                                            'port': '',
                                            'service': '',
                                            'description': f"Vulnerability scan results for {host_ip}",
                                            'severity': 'medium',
                                            'discovered': os.path.getmtime(filepath),
                                            'source': 'Vulnerability Scan'
                                        })
                        except Exception as e:
                            logger.debug(f"Could not read vulnerability file {filepath}: {e}")
                            continue
            except Exception as e:
                logger.warning(f"Could not list vulnerabilities directory: {e}")
        
        # Add some example entries if no real data exists
        if not netkb_entries:
            netkb_entries = [
                {
                    'id': 'example_1',
                    'type': 'service',
                    'host': '192.168.1.1',
                    'port': '22/tcp',
                    'service': 'ssh',
                    'description': 'SSH service detected',
                    'severity': 'info',
                    'discovered': time.time(),
                    'source': 'Network Scan'
                },
                {
                    'id': 'example_2',
                    'type': 'vulnerability',
                    'host': '192.168.1.100',
                    'port': '80/tcp',
                    'service': 'http',
                    'description': 'Outdated web server version detected',
                    'severity': 'medium',
                    'discovered': time.time(),
                    'source': 'Vulnerability Scan'
                }
            ]
        
        # Calculate statistics using synchronized vulnerability count
        sync_all_counts()  # Ensure all counts are up to date
        total_entries = len(netkb_entries)
        vulnerabilities = safe_int(shared_data.vulnnbr)  # Use synchronized count from shared_data
        services = len([e for e in netkb_entries if e['type'] == 'service'])
        unique_hosts = len(set([e['host'] for e in netkb_entries]))
        
        return jsonify({
            'entries': netkb_entries,
            'statistics': {
                'total_entries': total_entries,
                'vulnerabilities': vulnerabilities,
                'services': services,
                'unique_hosts': unique_hosts
            }
        })
    except Exception as e:
        logger.error(f"Error getting NetKB data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/netkb/entry/<entry_id>')
def get_netkb_entry(entry_id):
    """Get detailed information for a specific NetKB entry"""
    try:
        # This would normally fetch detailed information about a specific entry
        # For now, return a placeholder response
        return jsonify({
            'id': entry_id,
            'detailed_info': f"Detailed information for entry {entry_id}",
            'recommendations': [
                "Monitor this service regularly",
                "Consider updating to latest version",
                "Implement proper access controls"
            ],
            'references': [
                "https://nvd.nist.gov/",
                "https://cve.mitre.org/",
                "https://www.exploit-db.com/"
            ]
        })
    except Exception as e:
        logger.error(f"Error getting NetKB entry: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/netkb/export')
def export_netkb_data():
    """Export NetKB data in various formats"""
    try:
        format_type = request.args.get('format', 'json')
        
        # Get NetKB data directly
        netkb_entries = []
        
        # Process scan results for host/service information
        scan_results_dir = getattr(shared_data, 'scan_results_dir', os.path.join('data', 'output', 'scan_results'))
        if os.path.exists(scan_results_dir):
            for filename in os.listdir(scan_results_dir):
                if filename.endswith('.txt') and not filename.startswith('.'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', filename)
                                host_ip = ip_match.group() if ip_match else 'Unknown'
                                
                                for line in content.split('\n'):
                                    if '/tcp' in line or '/udp' in line:
                                        parts = line.split()
                                        if len(parts) >= 3:
                                            port = parts[0]
                                            service = parts[2] if len(parts) > 2 else 'unknown'
                                            
                                            netkb_entries.append({
                                                'id': f"scan_{host_ip}_{port}",
                                                'type': 'service',
                                                'host': host_ip,
                                                'port': port,
                                                'service': service,
                                                'description': f"Service {service} running on {port}",
                                                'severity': 'info',
                                                'discovered': os.path.getmtime(filepath),
                                                'source': 'Network Scan'
                                            })
                    except Exception as e:
                        continue
        
        # Add example data if no real data
        if not netkb_entries:
            netkb_entries = [
                {
                    'type': 'service',
                    'host': '192.168.1.1',
                    'port': '22/tcp',
                    'service': 'ssh',
                    'description': 'SSH service detected',
                    'severity': 'info',
                    'source': 'Network Scan'
                }
            ]
        
        if format_type == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Type', 'Host', 'Port', 'Service', 'Description', 'Severity', 'Source'])
            
            # Write data
            for entry in netkb_entries:
                writer.writerow([
                    entry['type'],
                    entry['host'],
                    entry['port'],
                    entry['service'],
                    entry['description'],
                    entry['severity'],
                    entry['source']
                ])
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=netkb_export.csv'}
            )
        else:
            # Default to JSON export
            export_data = {
                'entries': netkb_entries,
                'exported_at': datetime.now().isoformat(),
                'total_entries': len(netkb_entries)
            }
            return Response(
                json.dumps(export_data, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=netkb_export.json'}
            )
    except Exception as e:
        logger.error(f"Error exporting NetKB data: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# SIGNAL HANDLERS
# ============================================================================

def handle_exit(signum, frame):
    """Handle exit signals"""
    logger.info("Shutting down web server...")
    shared_data.webapp_should_exit = True
    socketio.stop()
    sys.exit(0)


# ============================================================================
# MAIN
# ============================================================================

def run_server(host='0.0.0.0', port=8000):
    """Run the Flask server"""
    try:
        logger.info(f"Starting Ragnar web server on {host}:{port}")
        logger.info(f"Access the interface at http://{host}:{port}")

        # Prime synchronized data before clients connect
        sync_all_counts()

        # Start background status broadcaster
        socketio.start_background_task(broadcast_status_updates)
        socketio.start_background_task(background_sync_loop)
        socketio.start_background_task(background_arp_scan_loop)
        socketio.start_background_task(background_health_monitor)
        
        logger.info("✅ All background threads started successfully")

        # Run the server
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"Error running server: {e}")
        raise


if __name__ == "__main__":
    # Set up signal handling
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    # Run the server
    run_server()
