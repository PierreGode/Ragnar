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
import traceback
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from flask import Flask, render_template, jsonify, request, send_from_directory, Response, make_response
from flask_socketio import SocketIO, emit
try:
    from flask_cors import CORS  # type: ignore
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
from lynis_parser import parse_lynis_dat
from actions.lynis_pentest_ssh import LynisPentestSSH

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
SYNC_BACKGROUND_INTERVAL = 15  # seconds between automatic synchronizations (increased from 5s to reduce CPU load)

# Scan results caching to avoid reprocessing files every sync
scan_results_cache = {}
processed_scan_files = {}  # Track which files we've already processed: {filename: mtime}

DEFAULT_ARP_SCAN_INTERFACE = 'wlan0'
SEP_SCAN_COMMAND = ['sudo', 'sep-scan']
MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def _normalize_value(value, default='Unknown'):
    """Normalize a value, handling nan, None, empty strings, etc."""
    if value is None:
        return default
    
    # Convert to string
    str_value = str(value).strip()
    
    # Check for pandas nan or various empty representations
    if not str_value or str_value.lower() in ['nan', 'none', 'null', '']:
        return default
    
    return str_value


def _is_valid_ipv4(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_mac(mac):
    return mac.lower() if mac else ''


def _parse_attack_timestamp(value):
    if value is None:
        return None

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OSError):
            return None

    if isinstance(value, str):
        cleaned = value.strip()

        if cleaned.endswith('Z') and '+' not in cleaned:
            cleaned = cleaned[:-1] + '+00:00'

        parsers = (
            lambda v: datetime.fromisoformat(v),
            lambda v: datetime.strptime(v, '%Y-%m-%d %H:%M:%S'),
            lambda v: datetime.strptime(v, '%Y-%m-%dT%H:%M:%S'),
        )

        for parser in parsers:
            try:
                return parser(cleaned)
            except ValueError:
                continue

    return None


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
        logger.warning(f"arp-scan command not found when resolving MAC for {ip}")
        return ''
    except subprocess.TimeoutExpired as e:
        logger.warning(f"arp-scan timed out for {ip}: {e}")
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
        
    except Exception as e:
        logger.error(f"Error updating vulnerability output for {ip}: {e}")


def update_netkb_entry(ip, hostname, mac, is_alive):
    try:
        # Update vulnerability output files
        update_vulnerability_output(ip, hostname, mac, is_alive)
        
        netkb_path = shared_data.netkbfile
        os.makedirs(os.path.dirname(netkb_path), exist_ok=True)

        rows = []
        headers: list[str] = []
        updated_row = None

        if os.path.exists(netkb_path) and os.path.getsize(netkb_path) > 0:
            with open(netkb_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                headers = list(reader.fieldnames) if reader.fieldnames else []
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
                # CRITICAL: NEVER clear the Ports field here!
                # Ports are managed by scanning.py - we only update Alive/MAC/Hostname
                # Preserve existing ports to prevent data loss
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
            # CRITICAL: Don't set Ports to '' - preserve existing ports if they exist
            # The Ports field should only be updated by scanning.py during actual port scans
            # Leave it empty for new entries, but scanning.py will populate it
            new_row['Ports'] = new_row.get('Ports', '')  # Preserve if exists, empty if new
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
        vulnerable_hosts = set()

        def record_host(candidate):
            """Normalize and record a host value for vulnerable host counting"""
            if candidate is None:
                return

            if isinstance(candidate, (list, tuple, set)):
                for item in candidate:
                    record_host(item)
                return

            host_value = str(candidate).strip()
            if not host_value:
                return

            lowered = host_value.lower()
            if lowered in {'unknown', 'none', 'n/a', 'na', 'null'}:
                return

            vulnerable_hosts.add(host_value)

        # Check if network intelligence is enabled
        if (hasattr(shared_data, 'network_intelligence') and
            shared_data.network_intelligence and
            shared_data.config.get('network_intelligence_enabled', True)):

            # Update network context first
            shared_data.network_intelligence.update_network_context()

            # Get active findings count for current network
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            vuln_count = dashboard_findings['counts']['vulnerabilities']

            for vuln_info in dashboard_findings.get('vulnerabilities', {}).values():
                if isinstance(vuln_info, dict):
                    record_host(
                        vuln_info.get('host') or
                        vuln_info.get('ip') or
                        vuln_info.get('target') or
                        vuln_info.get('hostname')
                    )

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

            vuln_summary_file = getattr(shared_data, 'vuln_summary_file',
                                        os.path.join('data', 'output', 'vulnerabilities', 'vulnerability_summary.csv'))

            if os.path.exists(vuln_summary_file):
                try:
                    if pandas_available:
                        df = pd.read_csv(vuln_summary_file)
                        if not df.empty:
                            for _, row in df.iterrows():
                                vulnerabilities = safe_str(row.get('Vulnerabilities')).strip()
                                if vulnerabilities and vulnerabilities.lower() not in {'none', 'nan', 'na', '0'}:
                                    record_host(row.get('IP') or row.get('Hostname'))
                    else:
                        with open(vuln_summary_file, 'r', encoding='utf-8', errors='ignore') as summary_file:
                            reader = csv.DictReader(summary_file)
                            for row in reader:
                                vulnerabilities = (row.get('Vulnerabilities') or '').strip()
                                if vulnerabilities and vulnerabilities.lower() not in {'none', 'nan', 'na', '0'}:
                                    record_host(row.get('IP') or row.get('Hostname'))
                except Exception as e:
                    logger.debug(f"Could not parse vulnerability summary for host count: {e}")

        # Update shared data with synchronized count
        old_count = shared_data.vulnnbr
        shared_data.vulnnbr = vuln_count
        logger.debug(f"Updated shared_data.vulnnbr: {old_count} -> {vuln_count}")

        old_host_count = getattr(shared_data, 'vulnerable_host_count', 0)
        shared_data.vulnerable_host_count = len(vulnerable_hosts)
        logger.debug(f"Updated vulnerable host count: {old_host_count} -> {shared_data.vulnerable_host_count}")

        # SQLite is the primary source of truth - CSV livestatus file is deprecated
        logger.debug(f"Synchronized vulnerability count: {vuln_count}")
        return vuln_count
        
    except Exception as e:
        logger.error(f"Error synchronizing vulnerability count: {e}")
        return safe_int(shared_data.vulnnbr)


def sync_all_counts():
    """Synchronize all counts (targets, ports, vulnerabilities, credentials) across data sources.
    
    This function reads from SQLite database as the single source of truth and applies the
    30-ping failure rule to determine which hosts are considered active (alive vs degraded).
    """
    global last_sync_time, network_scan_cache

    with sync_lock:
        start_time = time.time()
        try:
            logger.debug("Starting sync_all_counts()")

            # Sync vulnerability count
            sync_vulnerability_count()

            # ==============================================================================
            # PRIMARY DATA SOURCE: Read from SQLite database
            # ==============================================================================
            
            aggregated_targets = 0
            aggregated_ports = 0  # Count total port instances across all hosts
            total_target_count = 0
            inactive_target_count = 0
            current_snapshot = {}
            discovered_macs = set()
            port_debug_info = []  # Track which hosts contribute to port count
            
            # Read from SQLite database
            try:
                from db_manager import DatabaseManager
                db = DatabaseManager()
                hosts = db.get_all_hosts()
                
                logger.info(f"[SQLITE SYNC] Reading from SQLite database")
                
                for host in hosts:
                    ip = host.get("ip", "").strip()
                    mac = host.get("mac", "").strip()
                    
                    # Skip standalone entries or entries without IP
                    if mac == "STANDALONE" or not ip:
                        continue
                    
                    # Get status from database (alive or degraded)
                    status = host.get("status", "alive")
                    failed_pings = host.get("failed_ping_count", 0)
                    
                    # Host is active if status is 'alive' (0-29 failed pings)
                    # Host is inactive/degraded if status is 'degraded' (30+ failed pings)
                    is_active = (status == 'alive')
                    
                    if mac:
                        discovered_macs.add(mac)

                    # Count all hosts for total
                    total_target_count += 1
                    
                    # Count active hosts
                    if is_active:
                        aggregated_targets += 1
                        
                        # Count all port instances - support both comma (SQLite) and semicolon (CSV) delimiters
                        ports_str = host.get('ports', '')
                        if ports_str and ports_str != '0':
                            # Check for comma first (SQLite format), else semicolon (CSV format)
                            if ',' in ports_str:
                                port_list = [p.strip() for p in ports_str.split(',') if p.strip() and p.strip() != '0']
                            else:
                                port_list = [p.strip() for p in ports_str.split(';') if p.strip() and p.strip() != '0']
                            
                            # Count valid numeric ports
                            valid_ports = [p for p in port_list if p.isdigit()]
                            aggregated_ports += len(valid_ports)
                            port_list = valid_ports  # Use only valid ports for snapshot
                            
                            # Track for debugging
                            if len(valid_ports) > 0:
                                hostname = host.get('hostname', '')
                                port_debug_info.append(f"{ip} ({hostname}): {len(valid_ports)} ports [{','.join(valid_ports)}]")
                        else:
                            port_list = []
                        
                        # Track in snapshot
                        current_snapshot[ip] = {
                            'alive': True,
                            'ports': set(port_list),
                            'failed_pings': failed_pings,
                            'source': 'sqlite',
                            'mac': mac
                        }
                    else:
                        inactive_target_count += 1
                        current_snapshot[ip] = {
                            'alive': False,
                            'ports': set(),
                            'failed_pings': failed_pings,
                            'source': 'sqlite',
                            'mac': mac
                        }
                
                logger.debug(f"[SYNC] ✅ Read data from SQLite database:")
                logger.debug(f"  - Total unique IPs: {total_target_count}")
                logger.debug(f"  - Active (alive): {aggregated_targets}")
                logger.debug(f"  - Inactive (degraded): {inactive_target_count}")
                logger.debug(f"  - Total open ports: {aggregated_ports}")
                

                if port_debug_info:
                    logger.debug(f"[PORT COUNT BREAKDOWN] Counting ports from {len(port_debug_info)} alive hosts with open ports:")
                    for info in port_debug_info[:10]:
                        logger.debug(f"    {info}")
                    if len(port_debug_info) > 10:
                        logger.debug(f"    ... and {len(port_debug_info) - 10} more hosts with ports")
                
            except Exception as e:
                logger.error(f"[SQLITE SYNC] ❌ Error reading from SQLite database: {e}")
                traceback.print_exc()

            old_targets = shared_data.targetnbr
            old_ports = shared_data.portnbr

            shared_data.targetnbr = aggregated_targets
            shared_data.total_targetnbr = total_target_count
            shared_data.inactive_targetnbr = inactive_target_count
            shared_data.portnbr = aggregated_ports
            shared_data.networkkbnbr = total_target_count
            
            if old_targets != aggregated_targets or old_ports != aggregated_ports:
                logger.info(f"✅ Updated counts from SQLite database:")
                logger.info(f"  - Targets: {old_targets} -> {aggregated_targets}")
                logger.info(f"  - Ports: {old_ports} -> {aggregated_ports}")
                logger.info(f"  - Total hosts: {total_target_count}")
                logger.info(f"  - Inactive hosts: {inactive_target_count}")
            else:
                logger.debug(f"Counts unchanged: targets={aggregated_targets}, ports={aggregated_ports}")

            # Track new and lost hosts
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

            if discovered_macs:
                new_mac_count, points_awarded = shared_data.process_discovered_macs(discovered_macs)
                if new_mac_count:
                    logger.info(
                        f"[GAMIFICATION] Registered {new_mac_count} new MAC(s), awarded {points_awarded} points"
                    )

            cred_results_dir = getattr(shared_data, 'crackedpwd_dir', os.path.join('data', 'output', 'crackedpwd'))

            logger.debug(f"Syncing credentials from directory: {cred_results_dir}")

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
                                    for line in content.split('\n'):
                                        if ':' in line and line.strip():
                                            cred_count += 1
                            except Exception as e:
                                logger.debug(f"Could not read credential file {filepath}: {e}")
                                continue

                    if cred_count > 0:
                        logger.debug(f"Total credential count: {cred_count} from {len(cred_files_found)} files")
                except Exception as e:
                    logger.warning(f"Could not list crackedpwd directory: {e}")

                old_creds = shared_data.crednbr
                shared_data.crednbr = cred_count
                logger.debug(f"Updated credentials: {old_creds} -> {cred_count}")
            else:
                logger.warning(f"Crackedpwd directory does not exist: {cred_results_dir}")

            data_stolen_dir = getattr(shared_data, 'datastolendir', os.path.join('data', 'output', 'data_stolen'))
            if os.path.exists(data_stolen_dir):
                try:
                    total_data_files = sum([len(files) for r, d, files in os.walk(data_stolen_dir)])
                    old_data = shared_data.datanbr
                    shared_data.datanbr = total_data_files
                    logger.debug(f"Updated data stolen: {old_data} -> {total_data_files}")
                except Exception as e:
                    logger.debug(f"Could not count data stolen files: {e}")
            
            zombies_dir = getattr(shared_data, 'zombiesdir', os.path.join('data', 'output', 'zombies'))
            if os.path.exists(zombies_dir):
                try:
                    total_zombies = sum([len(files) for r, d, files in os.walk(zombies_dir)])
                    old_zombies = shared_data.zombiesnbr
                    shared_data.zombiesnbr = total_zombies
                    logger.debug(f"Updated zombies: {old_zombies} -> {total_zombies}")
                except Exception as e:
                    logger.debug(f"Could not count zombie files: {e}")
            
            actions_dir = getattr(shared_data, 'actions_dir', os.path.join('actions'))
            if os.path.exists(actions_dir):
                try:
                    total_attacks = sum([len(files) for r, d, files in os.walk(actions_dir) if not r.endswith("__pycache__")]) - 2
                    old_attacks = shared_data.attacksnbr
                    shared_data.attacksnbr = max(total_attacks, 0)
                    logger.debug(f"Updated attacks: {old_attacks} -> {shared_data.attacksnbr}")
                except Exception as e:
                    logger.debug(f"Could not count attack modules: {e}")

            
            try:
                shared_data.update_stats()
                logger.debug(f"Updated gamification stats - Level: {shared_data.levelnbr}, Coins: {shared_data.coinnbr}")
                logger.debug(f"Stats breakdown - NetworkKB: {shared_data.networkkbnbr}, Creds: {shared_data.crednbr}, Data: {shared_data.datanbr}, Zombies: {shared_data.zombiesnbr}, Attacks: {shared_data.attacksnbr}, Vulns: {shared_data.vulnnbr}")
            except Exception as e:
                logger.warning(f"Could not update gamification stats: {e}")

            logger.debug(f"Completed sync_all_counts() - Active Targets: {shared_data.targetnbr}, Total Targets: {shared_data.total_targetnbr}, Inactive Targets: {shared_data.inactive_targetnbr}, Ports: {shared_data.portnbr}, Vulns: {shared_data.vulnnbr}, Creds: {shared_data.crednbr}, Level: {shared_data.levelnbr}, Coins: {shared_data.coinnbr}")
            
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
        if hasattr(value, 'item'):
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


_wifi_ssid_cache = {'ssid': None, 'timestamp': 0}
_WIFI_SSID_CACHE_TTL = 60

def get_current_wifi_ssid():
    """Get the current WiFi SSID for file naming"""
    global _wifi_ssid_cache
    
    current_timestamp = time.time()
    if _wifi_ssid_cache['ssid'] and (current_timestamp - _wifi_ssid_cache['timestamp']) < _WIFI_SSID_CACHE_TTL:
        return _wifi_ssid_cache['ssid']
    
    try:
        if hasattr(shared_data, 'wifi_manager') and getattr(shared_data, 'wifi_manager', None):
            wifi_manager = getattr(shared_data, 'wifi_manager')
            ssid = wifi_manager.get_current_ssid()
            if ssid:
                # Sanitize SSID for filename
                sanitized = re.sub(r'[^\w\-_]', '_', ssid)
                _wifi_ssid_cache['ssid'] = sanitized
                _wifi_ssid_cache['timestamp'] = current_timestamp
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
                        _wifi_ssid_cache['ssid'] = sanitized
                        _wifi_ssid_cache['timestamp'] = current_timestamp
                        return sanitized
        
        # Cache the default value too
        _wifi_ssid_cache['ssid'] = "unknown_network"
        _wifi_ssid_cache['timestamp'] = current_timestamp
        return "unknown_network"
    except Exception as e:
        logger.debug(f"Error getting current WiFi SSID: {e}")
        # Cache the error result
        _wifi_ssid_cache['ssid'] = "unknown_network"
        _wifi_ssid_cache['timestamp'] = current_timestamp
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
                                        # Parse ports from semicolon-separated list
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
                        
                        # Log loaded data for debugging
                        total_ports_loaded = sum(len(data['ports']) for data in existing_data.values())
                        logger.debug(f"[WIFI DATA LOAD] Loaded {len(existing_data)} hosts with {total_ports_loaded} total ports from {wifi_network_file}")
                        
                        # Log hosts with many ports (likely from deep scans)
                        for ip, data in existing_data.items():
                            if len(data['ports']) > 10:
                                logger.debug(f"[WIFI DATA LOAD] {ip} has {len(data['ports'])} ports (likely from deep scan)")
                                
            except Exception as e:
                logger.debug(f"Could not read existing WiFi network file: {e}")

        # Process new scan results (with caching to avoid reprocessing unchanged files)
        if os.path.exists(scan_results_dir):
            current_time = datetime.now().isoformat()
            global processed_scan_files
            
            files_to_process = []
            for filename in os.listdir(scan_results_dir):
                if filename.startswith('result_') and filename.endswith('.csv'):
                    filepath = os.path.join(scan_results_dir, filename)
                    try:
                        # Check if file has been modified since we last processed it
                        file_mtime = os.path.getmtime(filepath)
                        if filename not in processed_scan_files or processed_scan_files[filename] < file_mtime:
                            files_to_process.append((filename, filepath, file_mtime))
                    except Exception as e:
                        logger.debug(f"Could not check mtime for {filepath}: {e}")
                        
            # Log caching efficiency
            if len(files_to_process) == 0:
                logger.debug(f"[SCAN CACHE] All {len(processed_scan_files)} scan files already processed, skipping")
            elif len(files_to_process) < len(os.listdir(scan_results_dir)):
                logger.debug(f"[SCAN CACHE] Processing {len(files_to_process)} new/modified files, skipping {len(processed_scan_files) - len(files_to_process)} cached files")

            for filename, filepath, file_mtime in files_to_process:
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
                                        # Merge data - PRESERVE ALL EXISTING PORTS (including deep scan results)
                                        existing_ports_before = len(existing_data[ip]['ports'])
                                        
                                        if hostname and hostname != 'Unknown':
                                            existing_data[ip]['hostname'] = hostname
                                        if mac and mac != 'Unknown':
                                            existing_data[ip]['mac'] = mac
                                        existing_data[ip]['alive'] = alive
                                        
                                        # CRITICAL: Add new ports to existing set, don't replace
                                        existing_data[ip]['ports'].update(ports)
                                        
                                        existing_ports_after = len(existing_data[ip]['ports'])
                                        # Only log significant port changes to reduce noise
                                        if existing_ports_after > existing_ports_before and (existing_ports_after - existing_ports_before) >= 3:
                                            logger.info(f"[PORT PRESERVATION] {ip}: Added {existing_ports_after - existing_ports_before} new ports (total: {existing_ports_after})")
                                        
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
                    
                    # Mark file as processed
                    processed_scan_files[filename] = file_mtime
                    
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
        # IMPORTANT: Only update ping counters when we have fresh ARP data (within last ARP_SCAN_INTERVAL)
        current_time = datetime.now().isoformat()
        current_timestamp = time.time()
        arp_hosts = network_scan_cache.get('arp_hosts', {})
        last_arp_scan_time = network_scan_cache.get('last_arp_scan', 0)
        arp_data_is_fresh = (current_timestamp - last_arp_scan_time) < ARP_SCAN_INTERVAL + 2  # +2 for timing tolerance
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
                # Device didn't respond - only increment counter if we have fresh ARP data
                if arp_data_is_fresh:
                    data['failed_ping_count'] = data.get('failed_ping_count', 0) + 1
                    data['last_ping_attempt'] = current_time
                
                # Only mark as offline after MAX_FAILED_PINGS consecutive failures
                if data['failed_ping_count'] >= MAX_FAILED_PINGS:
                    data['alive'] = False
                    logger.info(f"Device {ip} marked offline after {data['failed_ping_count']} consecutive failed pings")
                else:
                    # IMPORTANT: Keep device as "alive" until it exceeds the failure limit
                    # This implements the proper 15-ping rule you requested
                    data['alive'] = True  # Don't change to False until 15 failures
                    # Only log devices approaching the failure threshold to reduce noise
                    if data['failed_ping_count'] >= MAX_FAILED_PINGS - 3:
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
                # Only log every 10th device or devices approaching failure threshold
                if aggregated_active_count % 10 == 1 or failed_ping_count >= MAX_FAILED_PINGS - 2:
                    logger.debug(f"[15-PING RULE] {ip}: ACTIVE (failures={failed_ping_count}/{MAX_FAILED_PINGS}, alive={is_explicitly_alive})")
            else:
                aggregated_inactive_count += 1
                logger.info(f"[15-PING RULE] {ip}: INACTIVE (failures={failed_ping_count}/{MAX_FAILED_PINGS}, alive={is_explicitly_alive})")

        # Write updated data to WiFi-specific file
        try:
            # Count ports before writing for debugging
            total_ports_to_write = sum(len(data['ports']) for data in existing_data.values())
            hosts_with_many_ports = sum(1 for data in existing_data.values() if len(data['ports']) > 10)
            
            logger.debug(f"[WIFI DATA WRITE] Writing {len(existing_data)} hosts with {total_ports_to_write} total ports ({hosts_with_many_ports} hosts with >10 ports)")
            
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
                    
                    # Log hosts with many ports being written
                    if len(data['ports']) > 10:
                        logger.debug(f"[WIFI DATA WRITE] {ip}: Writing {len(data['ports'])} ports to file")
                    
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

            logger.info(f"✅ Updated WiFi network data file: {wifi_network_file} with {len(existing_data)} entries (removed {len(stale_hosts)} stale hosts, preserved {total_ports_to_write} ports)")
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
    """Get current Ragnar status (optimized - uses cached data from background sync)"""
    try:
        # OPTIMIZATION: Don't call sync_all_counts() here - it's expensive!
        # Background thread handles syncing every SYNC_BACKGROUND_INTERVAL seconds
        # This endpoint now returns cached data instantly for fast dashboard loading
        
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
        
        # Add cache headers for quick responses
        response = jsonify(status_data)
        response.headers['Cache-Control'] = 'public, max-age=5'  # Cache for 5 seconds
        return response
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
        
        ai_reload_success = None
        ai_reload_error = None

        # Update configuration (allow new keys to be added)
        for key, value in data.items():
            # Skip private/internal keys that start with __
            if not key.startswith('__'):
                shared_data.config[key] = value
                # Also set as attribute on shared_data for immediate access
                setattr(shared_data, key, value)
        
        # Save configuration
        shared_data.save_config()
        
        # Reload AI service if ai_enabled was changed
        if 'ai_enabled' in data:
            ai_service = getattr(shared_data, 'ai_service', None)
            
            # If AI service doesn't exist and user enabled it, try to initialize
            if not ai_service and data['ai_enabled']:
                try:
                    shared_data.initialize_ai_service()
                    ai_service = shared_data.ai_service
                    if ai_service and ai_service.is_enabled():
                        ai_reload_success = True
                    else:
                        ai_reload_success = False
                        ai_reload_error = getattr(ai_service, 'initialization_error', 'Failed to initialize AI service') if ai_service else 'AI service creation failed'
                except Exception as e:
                    ai_reload_success = False
                    ai_reload_error = str(e)
            # If AI service exists, reload or disable it
            elif ai_service:
                if data['ai_enabled']:
                    ai_reload_success = ai_service.reload_token()
                    if not ai_reload_success:
                        ai_reload_error = getattr(ai_service, 'initialization_error', None)
                else:
                    ai_service.enabled = False
                    ai_service.client = None
                    ai_service.initialization_error = None
                    ai_reload_success = True
        
        # Emit update to all connected clients
        socketio.emit('config_updated', shared_data.config)
        
        response = {'success': True, 'message': 'Configuration updated'}
        if ai_reload_success is not None:
            response['ai_reload_success'] = ai_reload_success
            if ai_reload_error:
                response['ai_reload_error'] = ai_reload_error

        return jsonify(response)
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
                    'scan_interval': 400,
                    'scan_vuln_interval': 700,
                    'max_concurrent_scans': 1,
                    'memory_warning_threshold': 90,
                    'memory_critical_threshold': 99,
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
        if isinstance(profiles_response, tuple):
            return profiles_response
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
    """Get stable, aggregated network data for the Network tab from SQLite database"""
    try:
        from db_manager import DatabaseManager
        db = DatabaseManager()
        
        # Get all hosts from SQLite database
        hosts = db.get_all_hosts()
        
        # Also get any recent ARP scan cache data for real-time enrichment
        recent_arp_data = network_scan_cache.get('arp_hosts', {})
        
        logger.info(f"Loaded {len(hosts)} entries from SQLite database for stable API")
        
        # Merge and enrich the data
        enriched_hosts = []
        processed_ips = set()
        
        # Process SQLite hosts
        for host in hosts:
            ip = host.get('ip', '').strip()
            # Skip if empty, already processed, or is STANDALONE
            if not ip or ip in processed_ips or ip == 'STANDALONE':
                continue
                
            processed_ips.add(ip)
            
            # Parse ports from semicolon-separated string to list
            ports_str = host.get('ports', '')
            if ports_str:
                ports = [p.strip() for p in ports_str.split(';') if p.strip()]
            else:
                ports = []
            
            # Determine status based on SQLite status field
            status = host.get('status', 'unknown')
            if status == 'alive':
                host_status = 'up'
            elif status == 'degraded':
                host_status = 'degraded'
            else:
                host_status = 'unknown'
            
            host_data = {
                'ip': ip,
                'hostname': _normalize_value(host.get('hostname'), 'Unknown'),
                'mac': _normalize_value(host.get('mac'), 'Unknown'),
                'status': host_status,
                'ports': ';'.join(ports) if ports else 'Unknown',
                'vulnerabilities': _normalize_value(host.get('nmap_vuln_scanner'), '0'),
                'last_scan': _normalize_value(host.get('last_seen'), 'Never'),
                'first_seen': _normalize_value(host.get('first_seen'), 'Unknown'),
                'os': 'Unknown',  # TODO: Add OS detection to database
                'services': 'Unknown',  # TODO: Add services to database
                'failed_pings': host.get('failed_ping_count', 0),
                'source': 'sqlite'
            }
            
            # Enhance with recent ARP data if available
            if ip in recent_arp_data:
                arp_entry = recent_arp_data[ip]
                if arp_entry.get('mac') and host_data['mac'] in ['Unknown', '00:00:00:00:00:00', '']:
                    host_data['mac'] = arp_entry['mac']
                if arp_entry.get('hostname') and host_data['hostname'] in ['Unknown', '']:
                    host_data['hostname'] = arp_entry['hostname']
                if host_status != 'up':  # ARP means it's definitely up
                    host_data['status'] = 'up'
                host_data['source'] = 'sqlite+arp'
            
            enriched_hosts.append(host_data)
        
        # Add any new ARP discoveries not in database
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
                    'failed_pings': 0,
                    'source': 'arp_discovery'
                }
                enriched_hosts.append(host_data)
        
        logger.info(f"Returning {len(enriched_hosts)} enriched hosts from SQLite database")
        
        # Sort by IP address for consistent display
        def safe_ip_sort_key(host):
            ip = host.get('ip', '')
            try:
                # Try to parse as IP address
                return (0, tuple(map(int, ip.split('.'))))
            except (ValueError, AttributeError):
                # Non-IP values sort to the end
                return (1, ip)
        
        enriched_hosts.sort(key=safe_ip_sort_key)
        
        response = jsonify({
            'success': True,
            'hosts': enriched_hosts,
            'count': len(enriched_hosts),
            'timestamp': datetime.now().isoformat(),
            'source': 'sqlite_database'
        })
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
        
    except Exception as e:
        logger.error(f"Error getting stable network data from SQLite: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e),
            'hosts': [],
            'count': 0
        }), 500

@app.route('/api/network')
def get_network():
    """Get network scan data from SQLite database - returns ALL hosts (alive and degraded)."""
    try:
        # Get all hosts from SQLite database
        hosts = shared_data.db.get_all_hosts()
        
        logger.debug(f"[API /api/network] Retrieved {len(hosts)} total hosts from database")
        
        # Convert to format expected by frontend
        network_data = []
        alive_count = 0
        degraded_count = 0
        
        for host in hosts:
            # Parse ports from comma-separated string to list
            ports_str = host.get('ports', '')
            ports = [p.strip() for p in ports_str.split(',') if p.strip()] if ports_str else []
            
            status = host.get('status', 'unknown')
            if status == 'alive':
                alive_count += 1
            elif status == 'degraded':
                degraded_count += 1
            
            network_data.append({
                'mac': host.get('mac', ''),
                'ip': host.get('ip', ''),
                'hostname': host.get('hostname', ''),
                'status': status,
                'ports': ports,
                'failed_pings': host.get('failed_ping_count', 0),
                'last_seen': host.get('last_seen', ''),
                # Action statuses
                'scanner': host.get('scanner_status', ''),
                'network_profile': host.get('network_profile', ''),
                'ssh_connector': host.get('ssh_connector', ''),
                'rdp_connector': host.get('rdp_connector', ''),
                'ftp_connector': host.get('ftp_connector', ''),
                'smb_connector': host.get('smb_connector', ''),
                'telnet_connector': host.get('telnet_connector', ''),
                'sql_connector': host.get('sql_connector', ''),
                'steal_files_ssh': host.get('steal_files_ssh', ''),
                'steal_files_rdp': host.get('steal_files_rdp', ''),
                'steal_files_ftp': host.get('steal_files_ftp', ''),
                'steal_files_smb': host.get('steal_files_smb', ''),
                'steal_files_telnet': host.get('steal_files_telnet', ''),
                'steal_data_sql': host.get('steal_data_sql', ''),
                'nmap_vuln_scanner': host.get('nmap_vuln_scanner', ''),
                'notes': host.get('notes', '')
            })
        
        logger.info(f"[API /api/network] Returning {len(network_data)} hosts (alive: {alive_count}, degraded: {degraded_count})")
        
        response = jsonify(network_data)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    except Exception as e:
        logger.error(f"Error getting network data from SQLite: {e}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
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


@app.route('/api/vulnerability-report/<path:filename>')
def download_vulnerability_report(filename):
    """Stream a vulnerability report file while preventing directory traversal."""
    try:
        vuln_dir = os.path.abspath(os.path.join('data', 'output', 'vulnerabilities'))
        requested_path = os.path.normpath(os.path.join(vuln_dir, filename))

        if not requested_path.startswith(vuln_dir):
            logger.warning(f"Blocked traversal attempt for report: {filename}")
            return jsonify({'error': 'File not found'}), 404

        if not os.path.isfile(requested_path):
            return jsonify({'error': 'File not found'}), 404

        rel_path = os.path.relpath(requested_path, vuln_dir)
        return send_from_directory(vuln_dir, rel_path, as_attachment=True)
    except Exception as exc:
        logger.error(f"Error serving vulnerability report {filename}: {exc}")
        return jsonify({'error': 'Unable to download report'}), 500


@app.route('/api/vulnerability-intel')
def get_vulnerability_intel():
    """Get interesting intelligence from scan files (not vulnerabilities - those are in threat intel)"""
    try:
        vuln_dir = os.path.join('data', 'output', 'vulnerabilities')
        
        if not os.path.exists(vuln_dir):
            return jsonify({
                'scans': [],
                'statistics': {
                    'total_scanned': 0,
                    'interesting_hosts': 0,
                    'services_with_intel': 0,
                    'script_outputs': 0
                }
            })
        
        scans = []
        stats = {
            'total_scanned': 0,
            'interesting_hosts': 0,
            'services_with_intel': 0,
            'script_outputs': 0
        }

        def format_lynis_section(title, entries, limit=25):
            entries = list(entries or [])
            if not entries:
                return None

            lines = []
            for entry in entries[:limit]:
                parts = []
                code = entry.get('code') or entry.get('package') or title.upper()
                if code:
                    parts.append(f"[{code}]")
                message = entry.get('message') or entry.get('package') or entry.get('raw') or ''
                if message:
                    parts.append(message)
                detail = entry.get('detail') or entry.get('version') or ''
                if detail:
                    parts.append(detail)
                remediation = entry.get('remediation') or entry.get('reference') or ''
                if remediation:
                    parts.append(f"Fix: {remediation}")
                line = ' | '.join(part for part in parts if part)
                if line:
                    lines.append(line)

            if len(entries) > limit:
                lines.append(f"...and {len(entries) - limit} more")

            if not lines:
                return None

            return {
                'name': title,
                'output': '\n'.join(lines)
            }
        
        vuln_files = os.listdir(vuln_dir)

        # Process all scan files
        for filename in vuln_files:
            if filename.endswith('_vuln_scan.txt'):
                file_path = os.path.join(vuln_dir, filename)
                stats['total_scanned'] += 1
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Extract host information
                    parts = filename.split('_')
                    ip = parts[1] if len(parts) > 1 else 'Unknown'
                    
                    hostname = 'Unknown'
                    hostname_match = re.search(r'Nmap scan report for ([^\s]+)\s+\(([^\)]+)\)', content)
                    if hostname_match:
                        hostname = hostname_match.group(1)
                        ip = hostname_match.group(2)
                    else:
                        hostname_match = re.search(r'Nmap scan report for ([^\s]+)', content)
                        if hostname_match:
                            potential_host = hostname_match.group(1)
                            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', potential_host):
                                hostname = potential_host
                    
                    # Extract interesting service information
                    services = []
                    
                    # Parse port/service lines with version info
                    port_lines = re.findall(r'(\d+/tcp)\s+open\s+(\S+)(?:\s+(.+?))?(?=\n|$)', content)
                    
                    for port, service_name, version_info in port_lines:
                        service_data = {
                            'port': port,
                            'service': service_name,
                            'version': version_info.strip() if version_info else '',
                            'scripts': []
                        }
                        
                        # Look for script output after this port
                        # Find the section between this port and the next port or end
                        port_num = port.split('/')[0]
                        pattern = rf'{re.escape(port)}.*?(?=\n\d+/tcp|\nService Info:|\nNmap done:|$)'
                        port_section_match = re.search(pattern, content, re.DOTALL)
                        
                        if port_section_match:
                            port_section = port_section_match.group(0)
                            
                            # Extract script outputs (lines starting with |)
                            script_lines = re.findall(r'^\|(.+)$', port_section, re.MULTILINE)
                            
                            if script_lines:
                                # Filter out lines with PACKETSTORM, vulners, CVE, exploit references
                                filtered_lines = []
                                for line in script_lines:
                                    line_lower = line.lower()
                                    # Skip lines containing vulnerability/exploit references
                                    if any(keyword in line_lower for keyword in ['packetstorm', 'vulners.com', 'cve-', 'exploit', 'https://']):
                                        continue
                                    # Skip lines that look like vulnerability IDs or scores
                                    if re.search(r'\d+\.\d+\s+https?://', line):
                                        continue
                                    # Skip nmap footer messages
                                    if 'service detection performed' in line_lower:
                                        continue
                                    if 'please report any incorrect results' in line_lower:
                                        continue
                                    if 'nmap.org/submit' in line_lower:
                                        continue
                                    filtered_lines.append(line)
                                
                                script_lines = filtered_lines
                                
                                # Group script output by script name
                                current_script = None
                                script_content = []
                                
                                for line in script_lines:
                                    line = line.strip()
                                    
                                    # Check if this is a script name line (ends with :)
                                    if ':' in line and not line.startswith('_') and not line.startswith(' '):
                                        # Save previous script if exists
                                        if current_script and script_content:
                                            service_data['scripts'].append({
                                                'name': current_script,
                                                'output': '\n'.join(script_content)
                                            })
                                            stats['script_outputs'] += 1
                                        
                                        # Start new script
                                        script_name_match = re.match(r'^\s*(\S+?):\s*(.*)', line)
                                        if script_name_match:
                                            script_name = script_name_match.group(1)
                                            # Skip vulnerability-related scripts
                                            if script_name.lower() in ['vulners', 'vulns']:
                                                current_script = None
                                                script_content = []
                                                continue
                                            current_script = script_name
                                            first_content = script_name_match.group(2)
                                            script_content = [first_content] if first_content else []
                                    else:
                                        # Add to current script content
                                        if current_script:
                                            script_content.append(line)
                                
                                # Save last script
                                if current_script and script_content:
                                    service_data['scripts'].append({
                                        'name': current_script,
                                        'output': '\n'.join(script_content)
                                    })
                                    stats['script_outputs'] += 1
                        
                        # Only add service if it has interesting data (version info or script output)
                        if service_data['version'] or service_data['scripts']:
                            services.append(service_data)
                            stats['services_with_intel'] += 1
                    
                    # Only include hosts with interesting intelligence (not basic scans)
                    if services:
                        mod_time = os.path.getmtime(file_path)
                        scan_date = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
                        
                        scans.append({
                            'ip': ip,
                            'hostname': hostname,
                            'scan_date': scan_date,
                            'filename': filename,
                            'download_url': f"/api/vulnerability-report/{filename}",
                            'log_url': f"/api/vulnerability-report/{filename}",
                            'services': services,
                            'total_services': len(services)
                        })
                        
                        stats['interesting_hosts'] += 1
                    
                except Exception as e:
                    logger.error(f"Error parsing scan file {filename}: {e}")
                    continue

        # Process Lynis pentest reports
        lynis_pattern = re.compile(r'^lynis_(?P<ip>[^_]+)_(?P<ts>\d{8}_\d{6})_pentest\.txt$')

        for filename in vuln_files:
            match = lynis_pattern.match(filename)
            if not match:
                continue

            file_path = os.path.join(vuln_dir, filename)
            stats['total_scanned'] += 1

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as handle:
                    content = handle.read()

                ip = match.group('ip')
                timestamp_raw = match.group('ts')
                hostname = f"{ip} (Lynis)"

                mod_time = os.path.getmtime(file_path)
                scan_date = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')

                dat_filename = filename.replace('_pentest.txt', '.dat')
                dat_path = os.path.join(vuln_dir, dat_filename)
                parsed_report = {}
                if os.path.exists(dat_path):
                    with open(dat_path, 'r', encoding='utf-8', errors='ignore') as dat_handle:
                        parsed_report = parse_lynis_dat(dat_handle.read()) or {}

                findings = []
                for line in content.splitlines():
                    stripped = line.strip()
                    lowered = stripped.lower()
                    if not stripped:
                        continue
                    if lowered.startswith('warning[') or lowered.startswith('suggestion['):
                        findings.append(stripped)
                    elif 'hardening index' in lowered:
                        findings.append(stripped)

                if not findings:
                    snippet = content.strip().splitlines()[:40]
                    findings = snippet if snippet else ['No explicit warnings captured; see full report for details.']

                report_excerpt = '\n'.join(findings)
                if len(report_excerpt) > 8000:
                    report_excerpt = report_excerpt[:8000] + '\n...[truncated]'

                scripts = [{
                    'name': 'security_audit',
                    'output': report_excerpt
                }]

                warnings_section = format_lynis_section('warnings', parsed_report.get('warnings', []))
                if warnings_section:
                    scripts.append(warnings_section)

                suggestions_section = format_lynis_section('suggestions', parsed_report.get('suggestions', []))
                if suggestions_section:
                    scripts.append(suggestions_section)

                packages_section = format_lynis_section('packages', parsed_report.get('vulnerable_packages', []))
                if packages_section:
                    scripts.append(packages_section)

                hardening_index = None
                metadata = parsed_report.get('metadata') if isinstance(parsed_report, dict) else {}
                if isinstance(metadata, dict):
                    hardening_index = metadata.get('hardening_index')

                service_entry = {
                    'port': 'system',
                    'service': 'lynis pentest',
                    'version': f"Hardening index: {hardening_index} @ {timestamp_raw}" if hardening_index else timestamp_raw,
                    'scripts': scripts
                }

                stats['services_with_intel'] += 1
                stats['script_outputs'] += len(scripts)
                stats['interesting_hosts'] += 1

                download_target = dat_filename if os.path.exists(dat_path) else filename

                scans.append({
                    'ip': ip,
                    'hostname': hostname,
                    'scan_date': scan_date,
                    'filename': filename,
                    'download_url': f"/api/vulnerability-report/{download_target}",
                    'log_url': f"/api/vulnerability-report/{filename}",
                    'services': [service_entry],
                    'total_services': 1,
                    'scan_type': 'lynis'
                })

            except Exception as exc:
                logger.error(f"Error parsing Lynis report {filename}: {exc}")
                continue
        
        # Consolidate scans by IP address to prevent duplicates
        consolidated_scans = {}
        
        for scan in scans:
            ip = scan['ip']
            
            if ip not in consolidated_scans:
                # First scan for this IP - use as base
                consolidated_scans[ip] = scan.copy()
            else:
                # Merge services from additional scans for same IP
                existing_scan = consolidated_scans[ip]
                
                # Merge services, avoiding duplicates
                existing_services = {f"{svc['port']}_{svc['service']}": svc for svc in existing_scan['services']}
                
                for new_service in scan['services']:
                    service_key = f"{new_service['port']}_{new_service['service']}"
                    if service_key not in existing_services:
                        existing_scan['services'].append(new_service)
                    else:
                        # Merge scripts if service already exists
                        existing_service = existing_services[service_key]
                        for script in new_service.get('scripts', []):
                            if script not in existing_service.get('scripts', []):
                                existing_service.setdefault('scripts', []).append(script)
                
                # Update totals
                existing_scan['total_services'] = len(existing_scan['services'])
                
                # Use most recent scan date and filename
                if scan['scan_date'] > existing_scan['scan_date']:
                    existing_scan['scan_date'] = scan['scan_date']
                    existing_scan['filename'] = scan['filename']
                    existing_scan['download_url'] = scan['download_url']
                    existing_scan['log_url'] = scan['log_url']
                
                # Combine scan types if different
                if scan.get('scan_type') != existing_scan.get('scan_type'):
                    existing_types = existing_scan.get('scan_type', 'nmap').split('+')
                    new_type = scan.get('scan_type', 'nmap')
                    if new_type not in existing_types:
                        existing_types.append(new_type)
                        existing_scan['scan_type'] = '+'.join(sorted(existing_types))
        
        # Convert back to list and sort by interesting content
        final_scans = list(consolidated_scans.values())
        final_scans.sort(key=lambda x: (
            -x['total_services'],  # Most services first
            -sum(len(svc.get('scripts', [])) for svc in x['services']),  # Most scripts first
            x['scan_date']  # Then by date descending
        ), reverse=False)  # reverse=False because we're using negative values
        
        return jsonify({
            'scans': final_scans,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting vulnerability intelligence: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs')
def get_logs():
    """Get recent logs - prioritizing orchestrator.py output"""
    try:
        # Enhanced logging - aggregate from multiple sources
        all_logs = []
        
        # Get terminal log level filter from config - default to 'all' to show orchestrator output
        terminal_log_level = shared_data.config.get('terminal_log_level', 'all')
        
        # 1. PRIORITY: Get orchestrator.py logs (main scanning activity)
        orchestrator_log = os.path.join(shared_data.logsdir, 'orchestrator.py.log')
        if os.path.exists(orchestrator_log):
            with open(orchestrator_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Get last 100 lines of orchestrator logs
                orch_logs = [line.strip() for line in lines[-20:] if line.strip()]
                all_logs.extend(orch_logs)
        
        # 2. Get scanning.py logs (network scanning details)
        scanning_log = os.path.join(shared_data.logsdir, 'scanning.py.log')
        if os.path.exists(scanning_log):
            with open(scanning_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Get last 50 lines of scanning logs
                scan_logs = [line.strip() for line in lines[-10:] if line.strip()]
                all_logs.extend(scan_logs)
        
        # 3. Get nmap_vuln_scanner.py logs (vulnerability scanning)
        vuln_scanner_log = os.path.join(shared_data.logsdir, 'nmap_vuln_scanner.py.log')
        if os.path.exists(vuln_scanner_log):
            with open(vuln_scanner_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Get last 50 lines of vuln scanner logs
                vuln_logs = [line.strip() for line in lines[-10:] if line.strip()]
                all_logs.extend(vuln_logs)
        
        # 2. Get Ragnar main activity logs from data/logs directory
        logs_dir = shared_data.logsdir
        if os.path.exists(logs_dir):
            skip_console_logs = {
                'orchestrator.py.log',
                'scanning.py.log',
                'nmap_vuln_scanner.py.log',
                'comment.py.log'
            }
            # Look for recent log files from attack actions
            for log_filename in os.listdir(logs_dir):
                if log_filename.endswith('.log') or log_filename.endswith('.txt'):
                    # Skip files we've already processed or explicitly excluded
                    if log_filename in skip_console_logs:
                        continue
                    
                    log_path = os.path.join(logs_dir, log_filename)
                    try:
                        # Get file modification time to show recent files first
                        mod_time = os.path.getmtime(log_path)
                        # Only show logs from last 24 hours
                        if time.time() - mod_time < 86400:  # 24 hours
                            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                                recent_lines = [line.strip() for line in lines[-10:] if line.strip()]
                                all_logs.extend(recent_lines)
                    except Exception as e:
                        # Skip files that can't be read
                        continue
        
        noise_filters = (
            'comment.py - INFO - Comments loaded successfully from cache',
        )
        if noise_filters:
            all_logs = [
                log for log in all_logs
                if not any(noise in log for noise in noise_filters)
            ]

        # Sort logs chronologically if they have timestamps
        # Logs are in format: YYYY-MM-DD HH:MM:SS - filename - LEVEL - message
        def extract_timestamp(log_line):
            try:
                # Extract timestamp from log line (first 19 characters: YYYY-MM-DD HH:MM:SS)
                if len(log_line) >= 19 and log_line[4] == '-' and log_line[7] == '-':
                    timestamp_str = log_line[:19]
                    from datetime import datetime
                    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except:
                pass
            return datetime.min
        
        # Sort by timestamp
        try:
            from datetime import datetime
            all_logs.sort(key=extract_timestamp)
        except:
            pass  # If sorting fails, keep original order
        
        # Limit to last 200 entries to avoid overwhelming the UI
        recent_logs = all_logs[-200:] if all_logs else []
        
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


@app.route('/api/attack', methods=['GET', 'POST'])
def attack_logs():
    """
    Attack logs endpoint - Log and retrieve attack action outputs
    
    GET: Retrieve attack logs (optionally filtered by IP, action type, or timeframe)
    POST: Log a new attack output
    """
    if request.method == 'POST':
        try:
            # Log a new attack output
            data = request.get_json()
            
            # Extract attack details
            attack_type = data.get('attack_type', 'Unknown')
            target_ip = data.get('target_ip', 'Unknown')
            target_port = data.get('target_port', '')
            status = data.get('status', 'unknown')  # success, failed, timeout
            message = data.get('message', '')
            details = data.get('details', {})
            timestamp = data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            # Create attack log directory if it doesn't exist
            attack_log_dir = os.path.join(shared_data.logsdir, 'attacks')
            os.makedirs(attack_log_dir, exist_ok=True)
            
            # Create attack log file (one per day)
            log_date = datetime.now().strftime('%Y-%m-%d')
            attack_log_file = os.path.join(attack_log_dir, f'attacks_{log_date}.json')
            
            # Prepare log entry
            log_entry = {
                'timestamp': timestamp,
                'attack_type': attack_type,
                'target_ip': target_ip,
                'target_port': target_port,
                'status': status,
                'message': message,
                'details': details
            }
            
            # Load existing logs or create new list
            if os.path.exists(attack_log_file):
                try:
                    with open(attack_log_file, 'r', encoding='utf-8') as f:
                        attack_logs = json.load(f)
                except json.JSONDecodeError:
                    attack_logs = []
            else:
                attack_logs = []
            
            # Append new log entry
            attack_logs.append(log_entry)
            
            # Save updated logs
            with open(attack_log_file, 'w', encoding='utf-8') as f:
                json.dump(attack_logs, f, indent=2)
            
            # Also log to main logger for debugging
            logger.info(f"Attack logged: {attack_type} on {target_ip}:{target_port} - {status}")
            
            return jsonify({
                'success': True,
                'message': 'Attack output logged successfully',
                'log_entry': log_entry
            }), 201
            
        except Exception as e:
            logger.error(f"Error logging attack output: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    else:  # GET request
        try:
            # Retrieve attack logs with optional filtering
            ip_filter = request.args.get('ip', None)
            attack_type_filter = request.args.get('type', None)
            status_filter = request.args.get('status', None)
            limit = int(request.args.get('limit', 100))
            days_back = int(request.args.get('days', 7))
            
            attack_log_dir = os.path.join(shared_data.logsdir, 'attacks')

            if not os.path.exists(attack_log_dir):
                return jsonify({
                    'attack_logs': [],
                    'total_count': 0,
                    'message': 'No attack logs found'
                })

            # Collect logs from recent days
            all_logs = []
            latest_log_time_all = None
            cutoff_date = datetime.now() - timedelta(days=days_back)

            for log_file in os.listdir(attack_log_dir):
                if not log_file.startswith('attacks_') or not log_file.endswith('.json'):
                    continue
                
                # Check if log file is within date range
                try:
                    file_date_str = log_file.replace('attacks_', '').replace('.json', '')
                    file_date = datetime.strptime(file_date_str, '%Y-%m-%d')
                    
                    if file_date < cutoff_date:
                        continue
                except:
                    continue
                
                log_path = os.path.join(attack_log_dir, log_file)
                try:
                    with open(log_path, 'r', encoding='utf-8') as f:
                        logs = json.load(f)
                        all_logs.extend(logs)

                        for entry in logs:
                            parsed_time = _parse_attack_timestamp(entry.get('timestamp'))
                            if parsed_time and (latest_log_time_all is None or parsed_time > latest_log_time_all):
                                latest_log_time_all = parsed_time
                except Exception as e:
                    logger.error(f"Error reading attack log file {log_file}: {e}")
                    continue

            # Apply filters
            filtered_logs = all_logs

            if ip_filter:
                filtered_logs = [log for log in filtered_logs if log.get('target_ip') == ip_filter]
            
            if attack_type_filter:
                filtered_logs = [log for log in filtered_logs if log.get('attack_type') == attack_type_filter]
            
            if status_filter:
                filtered_logs = [log for log in filtered_logs if log.get('status') == status_filter]
            
            # Sort by timestamp (most recent first)
            filtered_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

            # Apply limit
            filtered_logs = filtered_logs[:limit]

            # Generate summary statistics
            total_count = len(all_logs)
            filtered_count = len(filtered_logs)
            success_count = len([log for log in filtered_logs if log.get('status') == 'success'])
            failed_count = len([log for log in filtered_logs if log.get('status') == 'failed'])

            filtered_latest = None
            for entry in filtered_logs:
                parsed_time = _parse_attack_timestamp(entry.get('timestamp'))
                if parsed_time and (filtered_latest is None or parsed_time > filtered_latest):
                    filtered_latest = parsed_time

            response_payload = {
                'attack_logs': filtered_logs,
                'total_count': total_count,
                'filtered_count': filtered_count,
                'success_count': success_count,
                'failed_count': failed_count,
                'filters_applied': {
                    'ip': ip_filter,
                    'type': attack_type_filter,
                    'status': status_filter,
                    'days': days_back,
                    'limit': limit
                }
            }

            etag_source = json.dumps({
                'attack_logs': filtered_logs,
                'total_count': total_count,
                'filtered_count': filtered_count,
                'success_count': success_count,
                'failed_count': failed_count
            }, sort_keys=True).encode('utf-8')

            etag_value = f'W/"attack-{hashlib.md5(etag_source).hexdigest()}"'

            last_modified_dt = filtered_latest or latest_log_time_all
            if last_modified_dt and last_modified_dt.tzinfo is None:
                last_modified_dt = last_modified_dt.replace(tzinfo=timezone.utc)

            if_none_match = request.headers.get('If-None-Match', '')
            if if_none_match:
                etag_matches = [tag.strip() for tag in if_none_match.split(',') if tag.strip()]
                if etag_value in etag_matches:
                    response = make_response('', 304)
                    response.headers['ETag'] = etag_value
                    response.headers['Cache-Control'] = 'no-cache'
                    if last_modified_dt:
                        response.headers['Last-Modified'] = format_datetime(last_modified_dt.astimezone(timezone.utc), usegmt=True)
                    return response

            response = jsonify(response_payload)
            response.headers['ETag'] = etag_value
            response.headers['Cache-Control'] = 'no-cache'
            if last_modified_dt:
                response.headers['Last-Modified'] = format_datetime(last_modified_dt.astimezone(timezone.utc), usegmt=True)

            return response

        except Exception as e:
            logger.error(f"Error retrieving attack logs: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500


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
                getattr(shared_data, 'network_file', 'NOT_SET'),
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


@app.route('/api/debug/orchestrator-status')
def get_orchestrator_diagnostic():
    """Comprehensive orchestrator diagnostic endpoint"""
    try:
        diagnostic = {
            'timestamp': datetime.now().isoformat(),
            'orchestrator_status': safe_str(shared_data.ragnarorch_status),
            'orchestrator_status2': safe_str(shared_data.ragnarstatustext2),
            'manual_mode': shared_data.config.get('manual_mode', False),
            'manual_mode_reason': 'Manual mode is ENABLED - orchestrator will not run automatic attacks' if shared_data.config.get('manual_mode', False) else 'Manual mode is DISABLED - orchestrator should run attacks',
            'wifi_connected': getattr(shared_data, 'wifi_connected', False),
            'orchestrator_should_exit': getattr(shared_data, 'orchestrator_should_exit', True),
            
            # Configuration checks
            'config': {
                'scan_vuln_running': shared_data.config.get('scan_vuln_running', True),
                'enable_attacks': shared_data.config.get('enable_attacks', True),
                'retry_success_actions': shared_data.config.get('retry_success_actions', True),
                'retry_failed_actions': shared_data.config.get('retry_failed_actions', True),
                'success_retry_delay': shared_data.config.get('success_retry_delay', 300),
                'failed_retry_delay': shared_data.config.get('failed_retry_delay', 180),
                'scan_interval': shared_data.config.get('scan_interval', 180),
                'scan_vuln_interval': shared_data.config.get('scan_vuln_interval', 300),
            },
            
            # Target information
            'targets': {
                'total_count': 0,
                'alive_count': 0,
                'alive_hosts': []
            },
            
            # Actions status
            'actions_available': False,
            'actions_pending': False,
            
            # Diagnosis
            'diagnosis': [],
            'recommendations': []
        }
        
        # Check netkb for targets
        try:
            if os.path.exists(shared_data.netkbfile):
                with open(shared_data.netkbfile, 'r') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                    diagnostic['targets']['total_count'] = len(rows)
                    
                    for row in rows:
                        if row.get('Alive') == '1':
                            diagnostic['targets']['alive_count'] += 1
                            ip = row.get('IPs', '')
                            hostname = row.get('Hostnames', '')
                            ports = row.get('Ports', '')
                            diagnostic['targets']['alive_hosts'].append({
                                'ip': ip,
                                'hostname': hostname,
                                'ports': ports,
                                'mac': row.get('MAC Address', '')
                            })
        except Exception as e:
            diagnostic['targets']['error'] = str(e)
        
        # Diagnose issues
        if diagnostic['manual_mode']:
            diagnostic['diagnosis'].append('🔴 MANUAL MODE IS ENABLED - This is why Ragnar is not performing attacks!')
            diagnostic['recommendations'].append('Disable manual mode in the Config tab to allow automatic attacks')
        
        if not diagnostic['wifi_connected']:
            diagnostic['diagnosis'].append('🔴 Wi-Fi is not connected')
            diagnostic['recommendations'].append('Connect to Wi-Fi to enable network scanning and attacks')
        
        if diagnostic['orchestrator_should_exit']:
            diagnostic['diagnosis'].append('🔴 Orchestrator exit flag is set')
            diagnostic['recommendations'].append('Restart the Ragnar service to clear the exit flag')
        
        if diagnostic['targets']['alive_count'] == 0:
            diagnostic['diagnosis'].append('⚠️ No alive targets found on the network')
            diagnostic['recommendations'].append('Wait for network scan to complete or manually trigger a scan')
            diagnostic['recommendations'].append('Check if you are connected to the correct network')
        else:
            diagnostic['diagnosis'].append(f'✅ Found {diagnostic["targets"]["alive_count"]} alive targets')
        
        if not diagnostic['config']['scan_vuln_running']:
            diagnostic['diagnosis'].append('⚠️ Vulnerability scanning is disabled')
            diagnostic['recommendations'].append('Enable vulnerability scanning in Config tab')
        
        if not diagnostic['config']['enable_attacks']:
            diagnostic['diagnosis'].append('⚠️ Attacks are disabled - Ragnar will only scan, not attack')
            diagnostic['recommendations'].append('Enable attacks in Config tab to allow SSH/FTP/SMB/SQL attacks')
        
        # Check if actions are available
        try:
            if os.path.exists(shared_data.actions_file):
                with open(shared_data.actions_file, 'r') as f:
                    actions_config = json.load(f)
                    diagnostic['actions_available'] = len(actions_config) > 0
                    diagnostic['actions_count'] = len(actions_config)
                    if not diagnostic['actions_available']:
                        diagnostic['diagnosis'].append('🔴 No actions configured in actions.json')
                        diagnostic['recommendations'].append('Check actions.json file for valid action configurations')
            else:
                diagnostic['diagnosis'].append('🔴 actions.json file not found')
                diagnostic['recommendations'].append('Restore actions.json file to enable attacks')
        except Exception as e:
            diagnostic['diagnosis'].append(f'🔴 Error loading actions: {str(e)}')
        
        # Summary
        if not diagnostic['diagnosis']:
            diagnostic['diagnosis'].append('✅ All systems appear normal')
            if diagnostic['targets']['alive_count'] > 0:
                diagnostic['diagnosis'].append(f'⚙️ Orchestrator should be running attacks on {diagnostic["targets"]["alive_count"]} targets')
            else:
                diagnostic['diagnosis'].append('⚙️ Waiting for network scan to discover targets')
        
        return jsonify(diagnostic)
        
    except Exception as e:
        logger.error(f"Error in orchestrator diagnostic: {e}")
        return jsonify({
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

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

@app.route('/api/debug/ai-service')
def get_ai_service_diagnostic():
    """Detailed AI service diagnostic information"""
    try:
        import traceback
        diagnostic = {
            'timestamp': datetime.now().isoformat(),
            'ai_service_exists': hasattr(shared_data, 'ai_service'),
            'ai_service_is_none': getattr(shared_data, 'ai_service', 'MISSING') is None,
            'config_ai_enabled': shared_data.config.get('ai_enabled', False),
            'env_file_exists': os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')),
        }
        
        # Try to get token from env
        try:
            from env_manager import EnvManager
            env_mgr = EnvManager()
            token = env_mgr.get_token()
            diagnostic['env_token_found'] = bool(token)
            diagnostic['env_token_preview'] = f"{token[:8]}...{token[-4:]}" if token and len(token) > 12 else None
        except Exception as e:
            diagnostic['env_manager_error'] = str(e)
            diagnostic['env_manager_traceback'] = traceback.format_exc()
        
        # Check AI service object
        ai_service = getattr(shared_data, 'ai_service', None)
        if ai_service:
            diagnostic['ai_service_details'] = {
                'enabled': getattr(ai_service, 'enabled', None),
                'model': getattr(ai_service, 'model', None),
                'api_token_set': bool(getattr(ai_service, 'api_token', None)),
                'client_exists': getattr(ai_service, 'client', None) is not None,
                'initialization_error': getattr(ai_service, 'initialization_error', None),
                'is_enabled_result': ai_service.is_enabled() if hasattr(ai_service, 'is_enabled') else 'NO_METHOD'
            }
        else:
            diagnostic['ai_service_details'] = 'SERVICE_IS_NONE'
            
            # Try to initialize it now
            diagnostic['initialization_attempt'] = {}
            try:
                diagnostic['initialization_attempt']['status'] = 'attempting'
                shared_data.initialize_ai_service()
                ai_service = getattr(shared_data, 'ai_service', None)
                if ai_service:
                    diagnostic['initialization_attempt']['status'] = 'success'
                    diagnostic['ai_service_details'] = {
                        'enabled': getattr(ai_service, 'enabled', None),
                        'model': getattr(ai_service, 'model', None),
                        'api_token_set': bool(getattr(ai_service, 'api_token', None)),
                        'client_exists': getattr(ai_service, 'client', None) is not None,
                        'initialization_error': getattr(ai_service, 'initialization_error', None),
                    }
                else:
                    diagnostic['initialization_attempt']['status'] = 'failed_still_none'
            except Exception as e:
                diagnostic['initialization_attempt']['status'] = 'exception'
                diagnostic['initialization_attempt']['error'] = str(e)
                diagnostic['initialization_attempt']['traceback'] = traceback.format_exc()
        
        # Try importing the module directly
        try:
            from ai_service import AIService
            diagnostic['ai_service_import'] = 'success'
        except Exception as e:
            diagnostic['ai_service_import'] = 'failed'
            diagnostic['ai_service_import_error'] = str(e)
            diagnostic['ai_service_import_traceback'] = traceback.format_exc()
        
        return jsonify(diagnostic)
        
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc(),
            'timestamp': datetime.now().isoformat()
        }), 500

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

@app.route('/api/vulnerability-scan/history', methods=['GET'])
def get_vulnerability_scan_history():
    """Get incremental scan history statistics"""
    try:
        # Access the nmap_vuln_scanner from shared_data
        vuln_scanner = getattr(shared_data, 'nmap_vuln_scanner', None)
        
        if not vuln_scanner:
            return jsonify({
                'error': 'Vulnerability scanner not initialized',
                'stats': {
                    'total_macs_tracked': 0,
                    'total_ports_scanned': 0,
                    'average_ports_per_mac': 0,
                    'mac_details': {}
                }
            }), 200
        
        stats = vuln_scanner.get_scan_history_stats()
        
        return jsonify({
            'success': True,
            'stats': stats,
            'message': f"Tracking {stats['total_macs_tracked']} MAC addresses with {stats['total_ports_scanned']} scanned ports"
        })
        
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerability-scan/history/reset', methods=['POST'])
def reset_vulnerability_scan_history():
    """Reset incremental scan history for specific MAC or all"""
    try:
        data = request.get_json() if request.is_json else {}
        mac = data.get('mac', None)
        
        # Access the nmap_vuln_scanner from shared_data
        vuln_scanner = getattr(shared_data, 'nmap_vuln_scanner', None)
        
        if not vuln_scanner:
            return jsonify({
                'error': 'Vulnerability scanner not initialized'
            }), 500
        
        success = vuln_scanner.reset_scan_history(mac)
        
        if mac:
            message = f"Reset scan history for MAC {mac}" if success else f"MAC {mac} not found in history"
        else:
            message = "Reset ALL scan history - next scan will be a full rescan"
        
        return jsonify({
            'success': success,
            'message': message,
            'mac': mac,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error resetting scan history: {e}")
        return jsonify({'error': str(e)}), 500

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
ARP_SCAN_INTERVAL = 60  # seconds

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
                logger.warning(f"sep-scan command not found. Falling back to nmap for {ip}")
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

@app.route('/api/scan/deep', methods=['POST'])
def deep_scan_host():
    """Perform a deep scan on a single host using TCP connect scan (-sT).

    Defaults to the curated top 3000 ports unless the caller explicitly requests a
    full-range sweep via mode/full flags.
    """
    try:
        # ===== REQUEST INTROSPECTION =====
        logger.info("🎯 DEEP SCAN API ENDPOINT CALLED")
        logger.info(f"   Method={request.method} Content-Type={request.content_type} Content-Length={request.content_length}")
        # Log a safe subset of headers
        try:
            hdr_subset = {k: v for k, v in request.headers.items() if k in ['User-Agent','Content-Type','Origin','Referer']}
            logger.debug(f"   Headers subset: {hdr_subset}")
        except Exception as e_hdr:
            logger.debug(f"   Could not log headers subset: {e_hdr}")

        raw_body = request.get_data(cache=False)  # bytes
        logger.debug(f"   Raw body repr: {raw_body!r}")

        data = {}
        # Robust JSON parsing with fallback to form/query
        if request.content_type and 'application/json' in request.content_type.lower():
            try:
                data = request.get_json(force=True, silent=True) or {}
            except Exception as json_err:
                logger.error(f"   JSON parse error: {json_err}")
                data = {}
        if not data:
            # Fallbacks
            form_dict = request.form.to_dict() if request.form else {}
            args_dict = request.args.to_dict() if request.args else {}
            data = {**args_dict, **form_dict}
        logger.info(f"   Parsed data: {data} (type={type(data).__name__})")

        ip = (data.get('ip') or '').strip()
        portstart_raw = data.get('portstart', 1)
        # ===== SECONDARY RAW BODY PARSING FALLBACK =====
        # If IP is still empty after initial structured parsing, attempt to extract it manually
        if not ip:
            try:
                raw_text = raw_body.decode('utf-8', errors='ignore').strip()
                logger.debug(f"   Fallback raw body text: {raw_text}")
                # Case 1: Proper JSON that get_json() failed to parse (malformed headers / PowerShell curl issues)
                if raw_text.startswith('{') and raw_text.endswith('}'):
                    import json as _json
                    try:
                        manual_json = _json.loads(raw_text)
                        ip = (manual_json.get('ip') or '').strip()
                        logger.debug(f"   Extracted IP from manual JSON fallback: [{ip}]")
                    except Exception as mj_err:
                        logger.debug(f"   Manual JSON decode failed: {mj_err}")
                # Case 2: application/x-www-form-urlencoded style: ip=192.168.1.192
                if not ip and ('=' in raw_text or '&' in raw_text):
                    import urllib.parse as _up
                    parsed_qs = _up.parse_qs(raw_text)
                    if 'ip' in parsed_qs and parsed_qs['ip']:
                        ip = (parsed_qs['ip'][0] or '').strip()
                        logger.debug(f"   Extracted IP from querystring style body: [{ip}]")
                # Case 3: Loose key:value or key=value pattern inside text
                if not ip:
                    import re as _re
                    m = _re.search(r'"?ip"?\s*[:=]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?', raw_text)
                    if m:
                        ip = m.group(1).strip()
                        logger.debug(f"   Extracted IP via regex heuristic: [{ip}]")
            except Exception as fb_err:
                logger.debug(f"   Raw body manual parse error: {fb_err}")
        # Log final IP extraction state before validation
        logger.debug(f"   Final extracted IP after fallbacks: [{ip}]")
        portend_raw = data.get('portend', 65535)
        try:
            portstart = int(portstart_raw)
        except (TypeError, ValueError):
            portstart = 1
        try:
            portend = int(portend_raw)
        except (TypeError, ValueError):
            portend = 65535

        if not ip:
            # Include a small, safe snippet of raw body to aid debugging (truncated to 120 chars)
            try:
                snippet = raw_body.decode('utf-8','ignore')[:120]
            except Exception:
                snippet = '<un-decodable>'
            logger.error(f"❌ Deep scan request missing IP after all parsing attempts. Raw snippet: {snippet!r}")
            return jsonify({'status': 'error', 'message': 'IP address is required', 'raw_snippet': snippet}), 400

        # Decide scan mode early so API response reflects reality
        mode_flag = (data.get('mode') or data.get('scan_mode') or '').lower()
        full_flag = str(data.get('full', '')).lower() in ['1','true','yes']
        use_top_ports = not (mode_flag in ['full','all','65535'] or full_flag)
        logger.info(
            f"🎯 DEEP SCAN PARAMETERS - IP=[{ip}] Ports={portstart}-{portend} mode={'top3000' if use_top_ports else 'full-range'}"
        )

        # Validate IP address format
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address format'}), 400

        # Start deep scan in background thread
        def deep_scan_background():
            try:
                # Import the scanner
                from actions.scanning import NetworkScanner
                
                # Create scanner instance
                scanner = NetworkScanner(shared_data)
                
                # Emit scan started event
                socketio.emit('deep_scan_update', {
                    'type': 'deep_scan_started',
                    'ip': ip,
                    'message': f'Starting deep scan on {ip} (ports {portstart}-{portend})...'
                })
                
                # Define progress callback to emit real-time updates
                def progress_callback(event_type, data):
                    socketio.emit('deep_scan_update', {
                        'type': 'deep_scan_progress',
                        'event': event_type,
                        'ip': ip,
                        'message': data.get('message', ''),
                        'port': data.get('port'),
                        'service': data.get('service')
                    })
                
                socketio.emit('deep_scan_update', {
                    'type': 'deep_scan_progress',
                    'ip': ip,
                    'message': f"Parameters accepted: ip={ip} mode={'top3000' if use_top_ports else 'full-range'} range={portstart}-{portend}"
                })

                # Perform the deep scan with progress callback
                result = scanner.deep_scan_host(ip, portstart, portend, progress_callback=progress_callback, use_top_ports=use_top_ports)
                
                # Emit final result
                if result['success']:
                    socketio.emit('deep_scan_update', {
                        'type': 'deep_scan_completed',
                        'ip': ip,
                        'open_ports': result['open_ports'],
                        'hostname': result['hostname'],
                        'port_details': result['port_details'],
                        'scan_duration': result['scan_duration'],
                        'message': result['message']
                    })
                    
                    # Also emit a network update to refresh the table
                    socketio.emit('network_update', {'refresh': True})
                else:
                    socketio.emit('deep_scan_update', {
                        'type': 'deep_scan_error',
                        'ip': ip,
                        'message': result['message']
                    })
                    
            except Exception as e:
                logger.error(f"Error in deep scan background task for {ip}: {e}")
                socketio.emit('deep_scan_update', {
                    'type': 'deep_scan_error',
                    'ip': ip,
                    'message': f'Deep scan error: {str(e)}'
                })

        # Start the deep scan in a background thread
        import threading
        scan_thread = threading.Thread(target=deep_scan_background)
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({
            'status': 'success',
            'message': f"Started deep scan of {ip} (mode={'top3000' if use_top_ports else 'full-range'})",
            'ip': ip,
            'portstart': portstart,
            'portend': portend,
            'mode': 'top3000' if use_top_ports else 'full-range'
        })
        
    except Exception as e:
        logger.error(f"Error initiating deep scan: {e}")
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

@app.route('/api/kill', methods=['POST'])
def kill_switch():
    """
    EDUCATIONAL KILL SWITCH - Complete data erasure endpoint
    
    This endpoint provides a secure way to completely wipe all data after educational
    demonstrations. Deletion order:
    1. Delete ragnar.db database file
    2. Delete entire data/ folder
    3. Delete entire Ragnar/ repository
    
    Security: Requires confirmation token to prevent accidental triggering
    """
    try:
        # Get confirmation from request
        data = request.get_json() or {}
        confirmation = data.get('confirmation', '')
        shutdown_after = data.get('shutdown', False)
        
        # Require explicit confirmation to prevent accidental wipes
        if confirmation != 'ERASE_ALL_DATA':
            logger.warning("Kill switch triggered without proper confirmation")
            return jsonify({
                'success': False,
                'error': 'Invalid confirmation token. Use "ERASE_ALL_DATA" to confirm.'
            }), 403
        
        logger.critical("=" * 80)
        logger.critical("KILL SWITCH ACTIVATED - INITIATING COMPLETE DATA ERASURE")
        logger.critical("=" * 80)
        
        results = {
            'database_deleted': False,
            'data_folder_deleted': False,
            'repository_deleted': False,
            'shutdown_scheduled': False,
            'errors': []
        }
        
        # Get the Ragnar directory path
        ragnar_dir = shared_data.currentdir
        home_dir = os.path.expanduser('~')
        ragnar_home_path = os.path.join(home_dir, 'Ragnar')
        
        # Use home path if it exists, otherwise use current directory
        if os.path.exists(ragnar_home_path):
            ragnar_dir = ragnar_home_path
        
        logger.critical(f"Target Ragnar directory: {ragnar_dir}")
        
        # STEP 1: Delete ragnar.db database file
        try:
            db_path = os.path.join(ragnar_dir, 'data', 'ragnar.db')
            logger.critical(f"Step 1/3: Deleting database file: {db_path}")
            
            if os.path.isfile(db_path):
                os.remove(db_path)
                logger.critical(f"✓ Deleted: {db_path}")
                results['database_deleted'] = True
            else:
                logger.warning(f"Database file not found: {db_path}")
                results['database_deleted'] = True  # Consider it success if file doesn't exist
            
        except Exception as e:
            error_msg = f"Error deleting database file: {str(e)}"
            logger.error(error_msg)
            results['errors'].append(error_msg)
        
        # STEP 2: Delete entire data/ folder
        try:
            data_dir = os.path.join(ragnar_dir, 'data')
            logger.critical(f"Step 2/3: Deleting data folder: {data_dir}")
            
            if os.path.exists(data_dir):
                shutil.rmtree(data_dir, ignore_errors=False)
                logger.critical(f"✓ Deleted: {data_dir}")
                results['data_folder_deleted'] = True
            else:
                logger.warning(f"Data folder not found: {data_dir}")
                results['data_folder_deleted'] = True  # Consider it success if folder doesn't exist
            
        except Exception as e:
            error_msg = f"Error deleting data folder: {str(e)}"
            logger.error(error_msg)
            results['errors'].append(error_msg)
        
        # STEP 3: Delete entire Ragnar/ repository
        # Use a background thread to allow response to be sent first
        def delete_repository():
            try:
                time.sleep(3)  # Wait 3 seconds for response to be sent
                logger.critical(f"Step 3/3: Deleting entire repository: {ragnar_dir}")
                
                if os.path.exists(ragnar_dir):
                    # Change to parent directory to avoid issues
                    parent_dir = os.path.dirname(ragnar_dir)
                    os.chdir(parent_dir)
                    
                    # Delete the entire Ragnar directory
                    shutil.rmtree(ragnar_dir, ignore_errors=False)
                    logger.critical(f"✓ Deleted: {ragnar_dir}")
                else:
                    logger.warning(f"Repository not found: {ragnar_dir}")
                    
            except Exception as e:
                logger.error(f"Error deleting repository: {str(e)}")
                logger.error(traceback.format_exc())
        
        # Start deletion thread
        deletion_thread = threading.Thread(target=delete_repository, daemon=True)
        deletion_thread.start()
        results['repository_deleted'] = True  # Marked as scheduled
        logger.critical(f"✓ Repository deletion scheduled in 3 seconds: {ragnar_dir}")
        
        # Optional shutdown
        if shutdown_after:
            try:
                logger.critical("Scheduling system shutdown in 60 seconds...")
                subprocess.Popen(['sudo', 'shutdown', '-h', '+1', 'Ragnar kill switch activated'],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True)
                results['shutdown_scheduled'] = True
            except Exception as e:
                error_msg = f"Error scheduling shutdown: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        logger.critical("=" * 80)
        logger.critical("KILL SWITCH EXECUTION COMPLETE")
        logger.critical(f"1. Database deleted: {results['database_deleted']}")
        logger.critical(f"2. Data folder deleted: {results['data_folder_deleted']}")
        logger.critical(f"3. Repository deletion scheduled: {results['repository_deleted']}")
        if shutdown_after:
            logger.critical(f"4. System shutdown scheduled: {results['shutdown_scheduled']}")
        logger.critical("=" * 80)
        
        # Return success response before repository is deleted
        return jsonify({
            'success': True,
            'message': 'Kill switch executed successfully. Repository will be deleted in 3 seconds.',
            'details': results,
            'ragnar_path': ragnar_dir,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Fatal error in kill switch: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

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
# DATA MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/data/reset-vulnerabilities', methods=['POST'])
def reset_vulnerabilities():
    """
    Reset all vulnerability data - removes all discovered vulnerabilities
    
    IMPORTANT: Network Intelligence is the SINGLE SOURCE OF TRUTH for vulnerabilities.
    - Vulnerabilities are cleared from Network Intelligence (in-memory + JSON files)
    - Legacy CSV files are also cleared for backward compatibility
    - If the same vulnerabilities are found in future scans, they will be 
      automatically re-added to Network Intelligence (auto-repopulation)
    """
    try:
        deleted_count = 0
        
        # SINGLE SOURCE OF TRUTH: Clear Network Intelligence vulnerabilities
        if hasattr(shared_data, 'network_intelligence') and shared_data.network_intelligence:
            try:
                # Count all vulnerabilities across all networks
                if hasattr(shared_data.network_intelligence, 'active_vulnerabilities'):
                    deleted_count = sum(len(vulns) for vulns in shared_data.network_intelligence.active_vulnerabilities.values())
                    shared_data.network_intelligence.active_vulnerabilities.clear()
                    
                    # Also clear resolved vulnerabilities
                    if hasattr(shared_data.network_intelligence, 'resolved_vulnerabilities'):
                        shared_data.network_intelligence.resolved_vulnerabilities.clear()
                    
                    shared_data.network_intelligence.save_intelligence_data()
                    logger.info(f"Cleared {deleted_count} vulnerabilities from Network Intelligence (single source of truth)")
            except Exception as e:
                logger.error(f"Error clearing network intelligence vulnerabilities: {e}")
        
        # Legacy CSV cleanup (DEPRECATED - kept for backward compatibility only)
        # TODO: Remove once all systems read from Network Intelligence
        vuln_summary = os.path.join('data', 'output', 'vulnerabilities', 'vulnerability_summary.csv')
        if os.path.exists(vuln_summary):
            try:
                import pandas as pd
                df = pd.DataFrame(columns=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                df.to_csv(vuln_summary, index=False)
                logger.debug("Reset legacy vulnerability summary CSV file")
            except Exception as e:
                logger.error(f"Error resetting vulnerability summary: {e}")
        
        # Clear individual vulnerability scan files (raw nmap output - kept for audit/forensics)
        vuln_dir = os.path.join('data', 'output', 'vulnerabilities')
        if os.path.exists(vuln_dir):
            try:
                for filename in os.listdir(vuln_dir):
                    if filename.startswith('scan_') and filename.endswith('.txt'):
                        file_path = os.path.join(vuln_dir, filename)
                        os.remove(file_path)
                logger.debug("Cleared individual vulnerability scan files")
            except Exception as e:
                logger.error(f"Error clearing vulnerability scan files: {e}")
        
        # CRITICAL: Clear scan history cache so all hosts will be rescanned
        scanned_ports_history_file = os.path.join('data', 'output', 'vulnerabilities', 'scanned_ports_history.json')
        if os.path.exists(scanned_ports_history_file):
            try:
                os.remove(scanned_ports_history_file)
                logger.info("✅ Cleared scan history cache - all hosts will be rescanned on next vulnerability scan")
            except Exception as e:
                logger.error(f"Error clearing scan history cache: {e}")
        
        # Reset vulnerability counter
        shared_data.vulnnbr = 0
        
        # Trigger sync
        sync_vulnerability_count()
        
        logger.info(f"Vulnerability reset complete: {deleted_count} entries removed from Network Intelligence")
        
        return jsonify({
            'success': True,
            'message': f'Vulnerabilities reset successfully. {deleted_count} entries removed.',
            'note': 'If the same vulnerabilities are detected in future scans, they will be automatically re-added.',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"Error resetting vulnerabilities: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/data/reset-threat-intel', methods=['POST'])
def reset_threat_intelligence():
    """Reset all threat intelligence data"""
    try:
        if not threat_intelligence:
            return jsonify({'success': False, 'error': 'Threat intelligence system not available'}), 400
        
        # Clear enriched findings
        findings_cleared = len(threat_intelligence.enriched_findings)
        threat_intelligence.enriched_findings.clear()
        
        # Clear threat cache
        cache_cleared = len(threat_intelligence.threat_cache)
        threat_intelligence.threat_cache.clear()
        
        # Save cleared state
        threat_intelligence.save_enriched_findings()
        threat_intelligence.save_threat_cache()
        
        logger.info(f"Threat intelligence reset: {findings_cleared} findings, {cache_cleared} cache entries cleared")
        
        return jsonify({
            'success': True,
            'message': 'Threat intelligence reset successfully',
            'findings_cleared': findings_cleared,
            'cache_cleared': cache_cleared
        })
        
    except Exception as e:
        logger.error(f"Error resetting threat intelligence: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# WI-FI MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/wifi/interfaces')
def get_wifi_interfaces():
    """Get available Wi-Fi interfaces"""
    try:
        interfaces = []
        
        # Try to get interfaces from system
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    # Look for wireless interfaces (wlan, wlp, etc.)
                    if re.search(r'^\d+:\s+(wlan\d+|wlp\w+|wlx\w+)', line):
                        match = re.search(r'^\d+:\s+(\S+):', line)
                        if match:
                            interface_name = match.group(1)
                            # Check if interface is up
                            state_match = re.search(r'state\s+(\w+)', line)
                            state = state_match.group(1) if state_match else 'UNKNOWN'
                            
                            interfaces.append({
                                'name': interface_name,
                                'state': state,
                                'is_default': interface_name == 'wlan0'
                            })
        except Exception as e:
            logger.warning(f"Failed to get interfaces via ip command: {e}")
            
        # If no interfaces found, add default
        if not interfaces:
            interfaces.append({
                'name': 'wlan0',
                'state': 'UNKNOWN',
                'is_default': True
            })
        
        return jsonify({
            'success': True,
            'interfaces': interfaces
        })
        
    except Exception as e:
        logger.error(f"Error getting Wi-Fi interfaces: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'interfaces': [{'name': 'wlan0', 'state': 'UNKNOWN', 'is_default': True}]
        })

@app.route('/api/wifi/status')
def get_wifi_status():
    """Get Wi-Fi manager status"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            status = wifi_manager.wifi_manager.get_status()
            logger.debug(f"Wi-Fi status from manager: {status}")
            return jsonify(status)
        else:
            # Fallback: try to get Wi-Fi status from system
            wifi_connected = getattr(shared_data, 'wifi_connected', False)
            current_ssid = get_current_wifi_ssid() if wifi_connected else None
            
            fallback_status = {
                'wifi_connected': wifi_connected,
                'ap_mode_active': False,
                'current_ssid': current_ssid,
                'ap_ssid': None,
                'error': 'Wi-Fi manager not available, using fallback'
            }
            logger.debug(f"Wi-Fi status fallback: {fallback_status}")
            return jsonify(fallback_status)
    except Exception as e:
        logger.error(f"Error getting Wi-Fi status: {e}")
        return jsonify({
            'error': str(e),
            'wifi_connected': False,
            'ap_mode_active': False,
            'current_ssid': None
        }), 500

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
        
        # Log the connection attempt
        logger.info(f"API: Attempting to connect to WiFi network: {ssid}")
        
        # Check if currently in AP mode
        was_in_ap_mode = wifi_manager.wifi_manager.ap_mode_active
        if was_in_ap_mode:
            logger.info(f"API: Currently in AP mode, will stop AP before connecting to {ssid}")
        
        # Try to connect
        success = wifi_manager.wifi_manager.connect_to_network(ssid, password)
        
        if success:
            logger.info(f"API: Successfully connected to {ssid}")
            # Add to known networks if connection successful and save requested
            if save_network:
                wifi_manager.wifi_manager.add_known_network(ssid, password, priority)
            
            message = 'Connected successfully'
            if is_ap_client_request():
                message = 'Connected successfully! Ragnar will now use this network. You can disconnect from this AP.'
        else:
            logger.error(f"API: Failed to connect to {ssid}")
            message = 'Connection failed. Please check the password and try again.'
            if was_in_ap_mode:
                message += ' Note: AP mode was stopped to attempt connection.'
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        logger.error(f"Error connecting to Wi-Fi: {e}")
        import traceback
        logger.error(traceback.format_exc())
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

@app.route('/api/wifi/exit-ap', methods=['POST'])
def exit_ap_mode():
    """Exit AP mode and reconnect to WiFi"""
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if not wifi_manager or not hasattr(wifi_manager, 'wifi_manager'):
            return jsonify({'success': False, 'error': 'Wi-Fi manager not available'}), 503
        
        # Use the existing method to exit AP mode from web interface
        result = wifi_manager.wifi_manager.exit_ap_mode_from_web()
        
        return jsonify({
            'success': result,
            'message': 'Exiting AP mode and reconnecting to WiFi' if result else 'Failed to exit AP mode'
        })
        
    except Exception as e:
        logger.error(f"Error exiting AP mode: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

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

# ============================================================================
# BLUETOOTH MANAGEMENT ENDPOINTS
# ============================================================================

# Import the Bluetooth manager
try:
    from actions.ble import BluetoothManager
    bluetooth_manager = BluetoothManager(logger)
    BLUETOOTH_AVAILABLE = True
    logger.info("Bluetooth manager loaded successfully")
except ImportError as e:
    logger.warning(f"Bluetooth manager not available: {e}")
    bluetooth_manager = None
    BLUETOOTH_AVAILABLE = False
except Exception as e:
    logger.error(f"Error initializing Bluetooth manager: {e}")
    bluetooth_manager = None
    BLUETOOTH_AVAILABLE = False

# Import the Bluetooth pentest module
try:
    from actions.ble_pentest import BluetoothPentest
    bluetooth_pentest = BluetoothPentest(logger)
    BLUETOOTH_PENTEST_AVAILABLE = True
    logger.info("Bluetooth pentest module loaded successfully")
except ImportError as e:
    logger.warning(f"Bluetooth pentest module not available: {e}")
    bluetooth_pentest = None
    BLUETOOTH_PENTEST_AVAILABLE = False
except Exception as e:
    logger.error(f"Error initializing Bluetooth pentest module: {e}")
    bluetooth_pentest = None
    BLUETOOTH_PENTEST_AVAILABLE = False

@app.route('/api/bluetooth/status')
def get_bluetooth_status():
    """Get current Bluetooth status"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'error': 'Bluetooth manager not available', 'enabled': False}), 503
            
        status = bluetooth_manager.get_status()
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting Bluetooth status: {e}")
        return jsonify({'error': str(e), 'enabled': False}), 500

@app.route('/api/bluetooth/enable', methods=['POST'])
def enable_bluetooth():
    """Enable Bluetooth"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.power_on()
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error enabling Bluetooth: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/disable', methods=['POST'])
def disable_bluetooth():
    """Disable Bluetooth"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.power_off()
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error disabling Bluetooth: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/discoverable/on', methods=['POST'])
def make_bluetooth_discoverable():
    """Make Bluetooth discoverable"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.set_discoverable(True)
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error making Bluetooth discoverable: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/discoverable/off', methods=['POST'])
def hide_bluetooth_device():
    """Hide Bluetooth device (make non-discoverable)"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.set_discoverable(False)
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error hiding Bluetooth device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/scan/start', methods=['POST'])
def start_bluetooth_scan():
    """Start Bluetooth device scan"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        data = request.get_json() or {}
        duration = data.get('duration', None)
        
        success, message = bluetooth_manager.start_scan(duration)
        
        if success:
            # Update shared data for compatibility
            shared_data.bluetooth_scan_active = True
            shared_data.bluetooth_scan_start_time = time.time()
        
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error starting Bluetooth scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/scan/stop', methods=['POST'])
def stop_bluetooth_scan():
    """Stop Bluetooth device scan"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        success, message = bluetooth_manager.stop_scan()
        
        if success:
            # Update shared data for compatibility
            shared_data.bluetooth_scan_active = False
        
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error stopping Bluetooth scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/devices')
def get_bluetooth_devices():
    """Get discovered Bluetooth devices"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'devices': [], 'error': 'Bluetooth manager not available'})
            
        devices = bluetooth_manager.get_discovered_devices()
        
        # Convert to list format for API compatibility
        device_list = list(devices.values())
        
        return jsonify({'devices': device_list})
        
    except Exception as e:
        logger.error(f"Error getting Bluetooth devices: {e}")
        return jsonify({'devices': [], 'error': str(e)})

@app.route('/api/bluetooth/pair', methods=['POST'])
def pair_bluetooth_device():
    """Pair with a Bluetooth device"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        data = request.get_json()
        address = data.get('address') if data else None
        
        if not address:
            return jsonify({'success': False, 'error': 'Device address required'}), 400
        
        success, message = bluetooth_manager.pair_device(address)
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error pairing Bluetooth device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/unpair', methods=['POST'])
def unpair_bluetooth_device():
    """Unpair a Bluetooth device"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        data = request.get_json()
        address = data.get('address') if data else None
        
        if not address:
            return jsonify({'success': False, 'error': 'Device address required'}), 400
        
        success, message = bluetooth_manager.unpair_device(address)
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        logger.error(f"Error unpairing Bluetooth device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/enumerate', methods=['POST'])
def enumerate_bluetooth_services():
    """Enumerate services on a Bluetooth device"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'success': False, 'error': 'Bluetooth manager not available'}), 503
            
        data = request.get_json()
        address = data.get('address') if data else None
        
        if not address:
            return jsonify({'success': False, 'error': 'Device address required'}), 400
        
        # Get detailed device info which includes services
        device_details = bluetooth_manager._get_device_details(address)
        services = device_details.get('services', [])
        
        return jsonify({'success': True, 'services': services})
        
    except Exception as e:
        logger.error(f"Error enumerating Bluetooth services: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bluetooth/diagnose', methods=['GET'])
def diagnose_bluetooth():
    """Diagnose Bluetooth scanning issues"""
    try:
        if not BLUETOOTH_AVAILABLE or bluetooth_manager is None:
            return jsonify({'error': 'Bluetooth manager not available'}), 503
            
        diagnosis = bluetooth_manager.diagnose_scanning()
        return jsonify(diagnosis)
        
    except Exception as e:
        logger.error(f"Error diagnosing Bluetooth: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# BLUETOOTH PENTEST ENDPOINTS
# ============================================================================

@app.route('/api/bluetooth/pentest/beacon-track', methods=['POST'])
def pentest_beacon_track():
    """Start beacon tracking"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        data = request.get_json() or {}
        duration = data.get('duration', 60)
        
        beacons = bluetooth_pentest.start_beacon_tracking(duration)
        
        return jsonify({
            'success': True,
            'beacons_found': len(beacons),
            'beacons': beacons
        })
        
    except Exception as e:
        logger.error(f"Error tracking beacons: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bluetooth/pentest/exfiltrate', methods=['POST'])
def pentest_exfiltrate():
    """Exfiltrate data from target device"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target MAC address required'}), 400
        
        result = bluetooth_pentest.exfiltrate_device_info(target)
        
        if result:
            return jsonify(result)
        else:
            return jsonify({'error': 'Exfiltration failed'}), 500
        
    except Exception as e:
        logger.error(f"Error exfiltrating data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bluetooth/pentest/blueborne-scan', methods=['POST'])
def pentest_blueborne():
    """Scan for BlueBorne vulnerabilities"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        data = request.get_json() or {}
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'Target MAC address required'}), 400
        
        result = bluetooth_pentest.blueborne_scan(target)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error scanning for BlueBorne: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bluetooth/pentest/track-movement', methods=['POST'])
def pentest_track_movement():
    """Track device movement via RSSI"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        data = request.get_json() or {}
        target = data.get('target')
        duration = data.get('duration', 300)
        
        if not target:
            return jsonify({'error': 'Target MAC address required'}), 400
        
        readings = bluetooth_pentest.track_device_movement(target, duration)
        
        return jsonify({
            'success': True,
            'target': target,
            'duration': duration,
            'readings': readings
        })
        
    except Exception as e:
        logger.error(f"Error tracking movement: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bluetooth/pentest/report', methods=['GET'])
def pentest_get_report():
    """Get comprehensive pentest report"""
    try:
        if not BLUETOOTH_PENTEST_AVAILABLE or bluetooth_pentest is None:
            return jsonify({'error': 'Bluetooth pentest module not available'}), 503
        
        report = bluetooth_pentest.generate_report()
        
        return jsonify(report)
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
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


@app.route('/api/vulnerabilities/grouped')
def get_vulnerabilities_grouped():
    """Get vulnerabilities grouped by IP address with summary statistics"""
    try:
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence and 
            shared_data.config.get('network_intelligence_enabled', True)):
            
            # Get network-aware findings for dashboard
            dashboard_findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            
            # Group vulnerabilities by host IP
            grouped = {}
            for vuln_id, vuln_info in dashboard_findings['vulnerabilities'].items():
                host = vuln_info['host']
                
                if host not in grouped:
                    grouped[host] = {
                        'ip': host,
                        'total_vulnerabilities': 0,
                        'severity_counts': {
                            'critical': 0,
                            'high': 0,
                            'medium': 0,
                            'low': 0
                        },
                        'affected_ports': set(),
                        'affected_services': set(),
                        'vulnerabilities': []
                    }
                
                # Increment counts
                grouped[host]['total_vulnerabilities'] += 1
                severity = vuln_info.get('severity', 'medium')
                if severity in grouped[host]['severity_counts']:
                    grouped[host]['severity_counts'][severity] += 1
                
                # Track ports and services
                grouped[host]['affected_ports'].add(vuln_info['port'])
                grouped[host]['affected_services'].add(vuln_info['service'])
                
                # Add vulnerability detail
                grouped[host]['vulnerabilities'].append({
                    'id': vuln_id,
                    'port': vuln_info['port'],
                    'service': vuln_info['service'],
                    'vulnerability': vuln_info['vulnerability'],
                    'severity': severity,
                    'discovered': vuln_info['discovered'],
                    'status': vuln_info['status']
                })
            
            # Convert sets to lists for JSON serialization
            for host_data in grouped.values():
                host_data['affected_ports'] = sorted(list(host_data['affected_ports']))
                host_data['affected_services'] = sorted(list(host_data['affected_services']))
                # Sort vulnerabilities by severity
                severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                host_data['vulnerabilities'].sort(
                    key=lambda v: severity_order.get(v['severity'], 4)
                )
            
            # Convert to list and sort by total vulnerability count
            grouped_list = sorted(
                grouped.values(),
                key=lambda x: x['total_vulnerabilities'],
                reverse=True
            )
            
            return jsonify({
                'grouped_vulnerabilities': grouped_list,
                'total_hosts': len(grouped_list),
                'total_vulnerabilities': dashboard_findings['counts']['vulnerabilities'],
                'network_context': {
                    'current_network': dashboard_findings['network_id'],
                    'network_name': dashboard_findings.get('network_name', 'Unknown')
                }
            })
        else:
            return jsonify({'error': 'Network intelligence not available'}), 503
            
    except Exception as e:
        logger.error(f"Error getting grouped vulnerabilities: {e}")
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
        # Get database stats
        db_stats = {}
        try:
            db_stats = shared_data.db.get_stats()
        except Exception as e:
            logger.warning(f"Could not get database stats: {e}")
        
        # Build comprehensive stats object with multiple naming conventions for frontend compatibility
        stats = {
            # Target counts (multiple naming conventions for compatibility)
            'active_target_count': safe_int(shared_data.targetnbr),
            'target_count': safe_int(shared_data.targetnbr),
            'total_targets': safe_int(shared_data.targetnbr),
            
            'inactive_target_count': safe_int(shared_data.inactive_targetnbr),
            'offline_target_count': safe_int(shared_data.inactive_targetnbr),
            
            'total_target_count': safe_int(shared_data.total_targetnbr),
            'all_targets': safe_int(shared_data.total_targetnbr),
            
            'new_target_count': safe_int(shared_data.new_targets),
            'new_targets': safe_int(shared_data.new_targets),
            'new_target_ips': shared_data.new_target_ips if hasattr(shared_data, 'new_target_ips') else [],
            
            'lost_target_count': safe_int(shared_data.lost_targets),
            'lost_targets': safe_int(shared_data.lost_targets),
            'lost_target_ips': shared_data.lost_target_ips if hasattr(shared_data, 'lost_target_ips') else [],
            
            # Port counts
            'port_count': safe_int(shared_data.portnbr),
            'open_port_count': safe_int(shared_data.portnbr),
            'total_ports': safe_int(shared_data.portnbr),
            
            # Vulnerability counts
            'vulnerability_count': safe_int(shared_data.vulnnbr),
            'vuln_count': safe_int(shared_data.vulnnbr),
            'total_vulnerabilities': safe_int(shared_data.vulnnbr),
            'vulnerable_hosts_count': safe_int(db_stats.get('vulnerable_hosts', 0)),
            'vulnerable_host_count': safe_int(db_stats.get('vulnerable_hosts', 0)),
            
            # Credential counts
            'credential_count': safe_int(shared_data.crednbr),
            'cred_count': safe_int(shared_data.crednbr),
            'total_credentials': safe_int(shared_data.crednbr),
            
            # Gamification
            'level': safe_int(shared_data.levelnbr),
            'levelnbr': safe_int(shared_data.levelnbr),
            'points': safe_int(shared_data.coinnbr),
            'coins': safe_int(shared_data.coinnbr),
            
            # Other counts
            'total_data_stolen': safe_int(shared_data.datanbr),
            'scan_results_count': safe_int(db_stats.get('alive_count', 0)),
            'services_discovered': {},
            
            # Last sync timestamp
            'last_sync': shared_data.last_sync_timestamp if hasattr(shared_data, 'last_sync_timestamp') else None
        }
        
        # Add threat intelligence stats
        if threat_intelligence:
            ti_stats = threat_intelligence.get_enriched_findings_summary()
            stats.update(ti_stats)
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        traceback.print_exc()
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
    """Legacy endpoint for network knowledge base JSON - now uses SQLite database"""
    try:
        # Get alive hosts from database
        hosts = shared_data.db.get_all_hosts()
        alive_hosts = [h for h in hosts if h.get('status') == 'alive']
        
        # Get available actions from actions file
        actions = []
        try:
            with open(shared_data.actions_file, 'r') as f:
                actions_config = json.load(f)
                actions = list(actions_config.keys())
        except Exception:
            pass
        
        # Build ports dict (ip -> list of ports)
        ports_dict = {}
        for host in alive_hosts:
            ip = host.get('ip', '')
            if ip:
                port_str = host.get('ports', '')
                ports_dict[ip] = port_str.split(',') if port_str else []
        
        response_data = {
            'ips': [h.get('ip', '') for h in alive_hosts if h.get('ip')],
            'ports': ports_dict,
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
        from db_manager import DatabaseManager
        db = DatabaseManager()
        data = db.get_all_hosts()
        emit('network_update', data)
    except Exception as e:
        logger.error(f"Error sending network data: {e}")
        traceback.print_exc()


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

    # Get WiFi status details from WiFi manager
    wifi_status = {}
    try:
        wifi_manager = getattr(shared_data, 'ragnar_instance', None)
        if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
            wifi_status = wifi_manager.wifi_manager.get_status()
    except Exception as e:
        logger.debug(f"Could not get WiFi status from manager: {e}")

    return {
        'ragnar_status': safe_str(shared_data.ragnarstatustext),
        'ragnar_status2': safe_str(shared_data.ragnarstatustext2),
        'ragnar_says': safe_str(shared_data.ragnarsays),
        'orchestrator_status': safe_str(shared_data.ragnarorch_status),
        'target_count': safe_int(shared_data.targetnbr),
        'port_count': safe_int(shared_data.portnbr),
        'vulnerability_count': safe_int(shared_data.vulnnbr),
        'vulnerable_hosts_count': safe_int(getattr(shared_data, 'vulnerable_host_count', 0)),
        'vulnerable_host_count': safe_int(getattr(shared_data, 'vulnerable_host_count', 0)),
        'credential_count': safe_int(shared_data.crednbr),
        'data_count': safe_int(shared_data.datanbr),
        'level': safe_int(shared_data.levelnbr),
        'points': safe_int(shared_data.coinnbr),
        'coins': safe_int(shared_data.coinnbr),
        'wifi_connected': wifi_status.get('wifi_connected', safe_bool(shared_data.wifi_connected)),
        'current_ssid': wifi_status.get('current_ssid'),
        'ap_mode_active': wifi_status.get('ap_mode_active', False),
        'ap_ssid': wifi_status.get('ap_ssid'),
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
                web_logs = [line.strip() for line in lines[-10:] if line.strip()]
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
            # Use a timeout thread to prevent infinite blocking
            import threading
            sync_thread = threading.Thread(target=sync_all_counts, daemon=True)
            sync_thread.start()
            sync_thread.join(timeout=60)  # 60 second timeout (reduced from 120s)
            
            if sync_thread.is_alive():
                logger.error("Background sync thread timed out after 60 seconds! Skipping this cycle.")
                consecutive_errors += 1
            else:
                consecutive_errors = 0  # Reset on success
                background_thread_health['sync_last_run'] = time.time()
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Background sync error (attempt {consecutive_errors}/{max_consecutive_errors}): {e}")
            
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
                
                # Run ARP scan with timeout protection
                import threading
                arp_hosts = {}
                
                def run_arp():
                    nonlocal arp_hosts
                    arp_hosts = run_arp_scan_localnet('wlan0')
                
                arp_thread = threading.Thread(target=run_arp, daemon=True)
                arp_thread.start()
                arp_thread.join(timeout=25)  # 25 second timeout (less than ARP_SCAN_INTERVAL)
                
                if arp_thread.is_alive():
                    logger.error("Background ARP scan timed out after 25 seconds! Skipping this cycle.")
                    consecutive_errors += 1
                    time.sleep(ARP_SCAN_INTERVAL)
                    continue
                
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
            logger.error(f"Error in background ARP scan loop (attempt {consecutive_errors}/{max_consecutive_errors}): {e}")
            
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
            
            # Check sync thread - should run every 15 seconds but may take up to 60s for large networks
            if background_thread_health['sync_last_run'] > 0:
                time_since_sync = current_time - background_thread_health['sync_last_run']
                if time_since_sync > 90:  # 60s timeout + 30s buffer
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
            logger.error(f"Error in health monitor: {e}")
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

    # Read from SQLite database (primary source)
    try:
        from db_manager import DatabaseManager
        db = DatabaseManager()
        all_hosts = db.get_all_hosts()
        
        for host in all_hosts:
            # Only include alive/up hosts
            if host.get('status') in ['alive', 'up']:
                ip = host.get('ip') or host.get('ip_address', '')
                hostname = host.get('hostname', ip) or ip
                
                # Parse ports from comma or semicolon-separated string
                ports_str = host.get('ports', '')
                ports = []
                if ports_str:
                    if ',' in ports_str:
                        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
                    else:
                        ports = [p.strip() for p in ports_str.split(';') if p.strip()]
                
                if ip and ip not in target_ips:
                    targets.append({
                        'ip': ip,
                        'hostname': hostname,
                        'ports': ports,
                        'mac': host.get('mac', '00:00:00:00:00:00'),
                        'source': 'Database'
                    })
                    target_ips.add(ip)
        
        logger.debug(f"Loaded {len(targets)} targets from SQLite database for manual attacks")
    except Exception as e:
        logger.error(f"Error reading targets from database: {e}")
    
    # Fallback: Read from CSV livestatus file if database is empty
    if not targets and os.path.exists(shared_data.livestatusfile):
        try:
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
                                'mac': row.get('MAC', row.get('MAC Address', '00:00:00:00:00:00')),
                                'source': 'CSV Fallback'
                            })
                            target_ips.add(ip)
            logger.debug(f"Loaded {len(targets)} targets from CSV fallback for manual attacks")
        except Exception as e:
            logger.error(f"Error reading CSV fallback: {e}")

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
                                        'mac': '00:00:00:00:00:00',  # Default MAC for NetKB entries
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
    """Trigger a manual vulnerability scan using the proper NmapVulnScanner method"""
    try:
        data = request.get_json(silent=True) or {}
        target_ip = (data.get('ip') or '').strip()

        available_targets = _collect_manual_targets()
        if not available_targets:
            return jsonify({'success': False, 'error': 'No targets available for vulnerability scan'}), 400

        is_all_targets = not target_ip or target_ip.lower() == 'all'

        if not is_all_targets:
            # Check if specific target exists
            target_found = any(t.get('ip') == target_ip for t in available_targets)
            if not target_found:
                return jsonify({'success': False, 'error': f'Target {target_ip} not found'}), 404

        status_target = 'All Targets' if is_all_targets else target_ip

        # Update status to show vulnerability scanning is active
        shared_data.ragnarstatustext = "NmapVulnScanner"
        shared_data.ragnarstatustext2 = f"Starting scan: {status_target}"

        # Immediately broadcast the status change
        broadcast_status_update()

        # Execute vulnerability scan in background using proper method
        def execute_vuln_scan():
            try:
                # Import and create vulnerability scanner
                from actions.nmap_vuln_scanner import NmapVulnScanner
                vuln_scanner = NmapVulnScanner(shared_data)

                def progress_callback(event_type, data):
                    """Real-time callback for vulnerability scan progress"""
                    try:
                        if event_type == "scan_started":
                            shared_data.ragnarstatustext2 = f"Scanning {data.get('total_hosts', 0)} hosts"
                            broadcast_status_update()
                        elif event_type == "scan_progress":
                            current_ip = data.get('current_ip', '')
                            scanned = data.get('scanned', 0)
                            total = data.get('total_hosts', 0)
                            progress = data.get('progress_percent', 0)
                            shared_data.ragnarstatustext2 = f"Scanning {current_ip} ({scanned}/{total}) - {progress}%"
                            broadcast_status_update()
                        elif event_type == "scan_completed":
                            scanned_count = data.get('scanned', 0)
                            shared_data.ragnarstatustext2 = f"Completed: {scanned_count} hosts scanned"
                            broadcast_status_update()
                        elif event_type == "scan_error":
                            error_ip = data.get('ip', 'unknown')
                            shared_data.ragnarstatustext2 = f"Error scanning {error_ip}"
                            broadcast_status_update()
                    except Exception as callback_error:
                        logger.error(f"Error in vulnerability scan callback: {callback_error}")

                if is_all_targets:
                    # Use force_scan_all_hosts for all targets - this is the proper method
                    scanned_count = vuln_scanner.force_scan_all_hosts(real_time_callback=progress_callback)
                    logger.info(f"Manual vulnerability scan completed: {scanned_count} hosts scanned")
                else:
                    # For single target, use scan_single_host_realtime method
                    target = next((t for t in available_targets if t.get('ip') == target_ip), None)
                    if target:
                        hostname = target.get('hostname', target_ip)
                        mac = target.get('mac', '00:00:00:00:00:00')
                        ports = target.get('ports', [])
                        ports_str = ';'.join([str(p) for p in ports]) if ports else ''
                        
                        result = vuln_scanner.scan_single_host_realtime(
                            ip=target_ip,
                            hostname=hostname,
                            mac=mac,
                            ports=ports_str,
                            callback=progress_callback
                        )
                        logger.info(f"Single host vulnerability scan completed for {target_ip}: {result}")

                # Update status when scan completes
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = "Vulnerability scan completed"
                broadcast_status_update()
                
            except Exception as e:
                logger.error(f"Error executing vulnerability scan: {e}")
                # Reset status on error
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = f"Vuln scan error: {str(e)[:40]}"
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


@app.route('/api/manual/pentest/lynis', methods=['POST'])
def run_manual_lynis_pentest():
    """Manually trigger a Lynis pentest for a specific host."""
    try:
        if not shared_data.config.get('manual_mode', False):
            return jsonify({'success': False, 'error': 'Enable Pentest Mode to run manual pentests'}), 400

        data = request.get_json(silent=True) or {}
        target_ip = (data.get('ip') or '').strip()
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''

        if not target_ip or not username or not password:
            return jsonify({'success': False, 'error': 'IP, username, and password are required'}), 400

        shared_data.ragnarstatustext = "LynisPentest"
        shared_data.ragnarstatustext2 = f"Manual pentest: {target_ip}"
        broadcast_status_update()

        def execute_manual_lynis():
            try:
                # Emit scan started event
                socketio.emit('lynis_update', {
                    'type': 'lynis_started',
                    'ip': target_ip,
                    'message': f'Starting Lynis security audit on {target_ip}...'
                })
                
                # Define progress callback to emit real-time updates
                def progress_callback(event_type, data):
                    socketio.emit('lynis_update', {
                        'type': 'lynis_progress',
                        'event': event_type,
                        'ip': target_ip,
                        'message': data.get('message', ''),
                        'stage': data.get('stage'),
                        'details': data.get('details')
                    })
                
                action = LynisPentestSSH(shared_data)
                status = action.run_manual(target_ip, username, password, progress_callback=progress_callback)
                success = status == 'success'
                
                # Emit final result
                if success:
                    socketio.emit('lynis_update', {
                        'type': 'lynis_completed',
                        'ip': target_ip,
                        'message': f'Lynis audit completed successfully for {target_ip}'
                    })
                else:
                    socketio.emit('lynis_update', {
                        'type': 'lynis_error',
                        'ip': target_ip,
                        'message': f'Lynis audit failed for {target_ip}'
                    })
                
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = (
                    "Lynis pentest completed" if success else "Lynis pentest failed"
                )
                broadcast_status_update()
                logger.info(f"Manual Lynis pentest finished for {target_ip} with status: {status}")
            except Exception as exc:
                logger.error(f"Error during manual Lynis pentest for {target_ip}: {exc}")
                socketio.emit('lynis_update', {
                    'type': 'lynis_error',
                    'ip': target_ip,
                    'message': f'Lynis audit error: {str(exc)}'
                })
                shared_data.ragnarstatustext = "IDLE"
                shared_data.ragnarstatustext2 = "Lynis pentest error"
                broadcast_status_update()

        threading.Thread(target=execute_manual_lynis, daemon=True).start()

        return jsonify({'success': True, 'message': f'Lynis pentest initiated for {target_ip}'})

    except Exception as e:
        logger.error(f"Error starting manual Lynis pentest: {e}")
        shared_data.ragnarstatustext = "IDLE"
        shared_data.ragnarstatustext2 = "Lynis pentest error"
        broadcast_status_update()
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
# (Image gallery endpoints removed)
# ============================================================================

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
                temps_func = getattr(psutil, 'sensors_temperatures')
                temps = temps_func()
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

@app.route('/api/dashboard/quick')
def get_dashboard_quick():
    """OPTIMIZED: Combined fast endpoint that returns all essential dashboard data in one call.
    This eliminates multiple round-trips and significantly speeds up dashboard loading on Pi Zero."""
    try:
        # OPTIMIZATION: Use cached data from background sync - no expensive operations here!
        # Background thread keeps data fresh every SYNC_BACKGROUND_INTERVAL seconds
        
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

        # Get all counts from cached shared_data (fast!)
        active_target_count = safe_int(shared_data.targetnbr)
        total_target_count = safe_int(shared_data.total_targetnbr)
        inactive_target_count = safe_int(shared_data.inactive_targetnbr)
        
        # If we don't have proper total/inactive counts, calculate them from active count
        if total_target_count == 0 and active_target_count > 0:
            total_target_count = active_target_count
            inactive_target_count = 0
        elif inactive_target_count == 0 and total_target_count > active_target_count:
            inactive_target_count = total_target_count - active_target_count

        # Get WiFi status (fast - from cache or quick check)
        wifi_status = {}
        try:
            wifi_manager = getattr(shared_data, 'ragnar_instance', None)
            if wifi_manager and hasattr(wifi_manager, 'wifi_manager'):
                wifi_status = wifi_manager.wifi_manager.get_status()
        except Exception:
            pass  # Silently fail - non-critical for dashboard

        # Combine stats and status in single response (eliminates separate /api/status call)
        combined_data = {
            # Stats
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
            'vulnerable_hosts_count': safe_int(getattr(shared_data, 'vulnerable_host_count', 0)),
            'vulnerable_host_count': safe_int(getattr(shared_data, 'vulnerable_host_count', 0)),
            'credential_count': safe_int(shared_data.crednbr),
            'level': safe_int(shared_data.levelnbr),
            'points': safe_int(shared_data.coinnbr),
            'coins': safe_int(shared_data.coinnbr),
            'data_count': safe_int(shared_data.datanbr),
            'last_sync_timestamp': last_sync_ts,
            'last_sync_iso': last_sync_iso,
            'last_sync_age_seconds': last_sync_age,
            
            # Status
            'ragnar_status': safe_str(shared_data.ragnarstatustext),
            'ragnar_status2': safe_str(shared_data.ragnarstatustext2),
            'ragnar_says': safe_str(shared_data.ragnarsays),
            'orchestrator_status': safe_str(shared_data.ragnarorch_status),
            'wifi_connected': wifi_status.get('wifi_connected', safe_bool(shared_data.wifi_connected)),
            'current_ssid': wifi_status.get('current_ssid'),
            'ap_mode_active': wifi_status.get('ap_mode_active', False),
            'ap_ssid': wifi_status.get('ap_ssid'),
            'bluetooth_active': safe_bool(shared_data.bluetooth_active),
            'pan_connected': safe_bool(shared_data.pan_connected),
            'usb_active': safe_bool(shared_data.usb_active),
            'manual_mode': safe_bool(shared_data.config.get('manual_mode', False)),
            'timestamp': datetime.now().isoformat()
        }

        response = jsonify(combined_data)
        # Cache for 3 seconds - balance between freshness and performance
        response.headers['Cache-Control'] = 'public, max-age=3'
        return response
    except Exception as e:
        logger.error(f"Error getting dashboard quick data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """Get dashboard statistics using synchronized data from shared_data to ensure consistency.
    DEPRECATED: Use /api/dashboard/quick for faster loading."""
    try:
        # OPTIMIZATION: Removed check_and_handle_network_switch() - not needed on every request
        # Background thread handles this periodically
        
        # OPTIMIZATION: Removed ensure_recent_sync() - background thread keeps data fresh
        # No need to block requests with sync operations
        
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
            'vulnerable_hosts_count': safe_int(getattr(shared_data, 'vulnerable_host_count', 0)),
            'vulnerable_host_count': safe_int(getattr(shared_data, 'vulnerable_host_count', 0)),
            'credential_count': safe_int(shared_data.crednbr),
            'level': safe_int(shared_data.levelnbr),
            'points': safe_int(shared_data.coinnbr),
            'coins': safe_int(shared_data.coinnbr),
            'last_sync_timestamp': last_sync_ts,
            'last_sync_iso': last_sync_iso,
            'last_sync_age_seconds': last_sync_age
        }

        response = jsonify(stats)
        # Cache for 3 seconds for better performance
        response.headers['Cache-Control'] = 'public, max-age=3'
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
# AI INSIGHTS ENDPOINTS
# ============================================================================

@app.route('/api/ai/status')
def get_ai_status():
    """Get AI service status and configuration"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        config_enabled = shared_data.config.get('ai_enabled', False)
        
        # If the AI service object isn't present but config says it should be enabled, try to initialize it
        if not ai_service and config_enabled:
            try:
                logger.info("AI service not found but config_enabled=true, attempting initialization...")
                shared_data.initialize_ai_service()
                ai_service = getattr(shared_data, 'ai_service', None)
            except Exception as e:
                logger.error(f"Failed to auto-initialize AI service: {e}")
        
        # If the AI service object still isn't present, report not available
        if not ai_service:
            return jsonify({
                'enabled': False,
                'available': True,  # Always assume SDK is installed
                'config_enabled': config_enabled,
                'configured': False,
                'message': 'AI service not initialized'
            })
        
        status = {
            'enabled': ai_service.is_enabled(),  # Runtime state - is it actually working?
            'config_enabled': config_enabled,  # User's intent from config
            'available': True,  # Always assume SDK is installed
            'model': getattr(ai_service, 'model', None),
            'capabilities': {
                'network_insights': getattr(ai_service, 'network_insights', False),
                'vulnerability_summaries': getattr(ai_service, 'vulnerability_summaries', False)
            },
            'configured': bool(getattr(ai_service, 'api_token', None))
        }
        
        # Include initialization error if present (but skip SDK-related ones)
        init_error = getattr(ai_service, 'initialization_error', None)
        if init_error and 'OpenAI SDK' not in str(init_error):
            status['error'] = init_error
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting AI status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/insights')
def get_ai_insights():
    """Get comprehensive AI-generated insights about the network"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service or not ai_service.is_enabled():
            return jsonify({
                'enabled': False,
                'message': 'AI service is not enabled. Configure OpenAI API token in settings.'
            })
        
        # Generate insights
        insights = ai_service.generate_insights()
        
        return jsonify(insights)
        
    except Exception as e:
        logger.error(f"Error getting AI insights: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/network-summary')
def get_ai_network_summary():
    """Get AI-generated network security summary"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service or not ai_service.is_enabled():
            return jsonify({
                'enabled': False,
                'message': 'AI service is not enabled'
            })
        
        # Get current network data
        network_data = {
            'target_count': safe_int(shared_data.targetnbr),
            'port_count': safe_int(shared_data.portnbr),
            'vulnerability_count': safe_int(shared_data.vulnnbr),
            'credential_count': safe_int(shared_data.crednbr)
        }
        
        # Get AI summary
        summary = ai_service.analyze_network_summary(network_data)
        
        return jsonify({
            'enabled': True,
            'summary': summary,
            'network_data': network_data
        })
        
    except Exception as e:
        logger.error(f"Error getting AI network summary: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/vulnerabilities')
def get_ai_vulnerability_analysis():
    """Get AI-generated vulnerability analysis"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service or not ai_service.is_enabled():
            return jsonify({
                'enabled': False,
                'message': 'AI service is not enabled'
            })
        
        # Get vulnerabilities from network intelligence
        vulnerabilities = []
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence):
            findings = shared_data.network_intelligence.get_active_findings_for_dashboard()
            vulnerabilities = list(findings.get('vulnerabilities', {}).values())
        
        if not vulnerabilities:
            return jsonify({
                'enabled': True,
                'analysis': None,
                'message': 'No vulnerabilities found to analyze'
            })
        
        # Get AI analysis
        analysis = ai_service.analyze_vulnerabilities(vulnerabilities)
        
        return jsonify({
            'enabled': True,
            'analysis': analysis,
            'vulnerability_count': len(vulnerabilities)
        })
        
    except Exception as e:
        logger.error(f"Error getting AI vulnerability analysis: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/weaknesses')
def get_ai_weakness_analysis():
    """Get AI-identified network weaknesses"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service or not ai_service.is_enabled():
            return jsonify({
                'enabled': False,
                'message': 'AI service is not enabled'
            })
        
        # Get network data
        network_data = {
            'target_count': safe_int(shared_data.targetnbr),
            'port_count': safe_int(shared_data.portnbr),
            'vulnerability_count': safe_int(shared_data.vulnnbr)
        }
        
        # Get findings
        findings = []
        if (hasattr(shared_data, 'network_intelligence') and 
            shared_data.network_intelligence):
            findings_data = shared_data.network_intelligence.get_active_findings_for_dashboard()
            vulnerabilities = list(findings_data.get('vulnerabilities', {}).values())
            credentials = list(findings_data.get('credentials', {}).values())
            findings = vulnerabilities + credentials
        
        # Get AI analysis
        analysis = ai_service.identify_network_weaknesses(network_data, findings)
        
        return jsonify({
            'enabled': True,
            'analysis': analysis,
            'findings_count': len(findings)
        })
        
    except Exception as e:
        logger.error(f"Error getting AI weakness analysis: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/clear-cache', methods=['POST'])
def clear_ai_cache():
    """Clear AI response cache"""
    try:
        ai_service = getattr(shared_data, 'ai_service', None)
        
        if not ai_service:
            return jsonify({
                'success': False,
                'message': 'AI service not available'
            })
        
        ai_service.clear_cache()
        
        return jsonify({
            'success': True,
            'message': 'AI cache cleared successfully'
        })
        
    except Exception as e:
        logger.error(f"Error clearing AI cache: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/token', methods=['GET'])
def get_ai_token():
    """Get OpenAI API token status (without revealing the actual token)"""
    try:
        from env_manager import EnvManager
        env_manager = EnvManager()
        
        token = env_manager.get_token()
        
        return jsonify({
            'configured': bool(token),
            'token_preview': f"{token[:8]}...{token[-4:]}" if token and len(token) > 12 else None
        })
        
    except Exception as e:
        logger.error(f"Error getting AI token status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/token', methods=['POST'])
def save_ai_token():
    """Save OpenAI API token to .env file"""
    try:
        from env_manager import EnvManager
        env_manager = EnvManager()
        
        data = request.get_json()
        if not data or 'token' not in data:
            return jsonify({'error': 'No token provided'}), 400
        
        token = data['token'].strip()
        
        # Log save attempt
        logger.info(f"Attempting to save AI token to {env_manager.env_file_path}")
        
        # Save token to .env file
        result = env_manager.save_token(token)
        
        if result['success']:
            auto_enabled = False
            if not shared_data.config.get('ai_enabled', False):
                shared_data.config['ai_enabled'] = True
                setattr(shared_data, 'ai_enabled', True)
                shared_data.save_config()
                socketio.emit('config_updated', shared_data.config)
                auto_enabled = True
                logger.info("AI Insights automatically enabled after saving API token")
            
            # Reinitialize AI service with new token
            ai_service = getattr(shared_data, 'ai_service', None)
            if ai_service:
                if ai_service.reload_token():
                    logger.info("AI service reloaded with new token")
                else:
                    logger.warning("AI service failed to reload with new token")
            
            return jsonify({
                'success': True,
                'message': result['message'],
                'configured': True,
                'ai_enabled': shared_data.config.get('ai_enabled', False),
                'auto_enabled': auto_enabled,
                'env_file': str(env_manager.env_file_path)
            })
        else:
            logger.error(f"Failed to save token to {env_manager.env_file_path}")
            return jsonify({
                'success': False,
                'message': result.get('message', 'Failed to save token. Check server logs for details.'),
                'env_file': str(env_manager.env_file_path)
            }), 500
        
    except Exception as e:
        logger.error(f"Error saving AI token: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/token', methods=['DELETE'])
def remove_ai_token():
    """Remove OpenAI API token from .env file"""
    try:
        from env_manager import EnvManager
        import os
        env_manager = EnvManager()
        
        # Remove the .env file
        if os.path.exists(env_manager.env_file_path):
            os.remove(env_manager.env_file_path)
            
            # Disable AI service
            ai_service = getattr(shared_data, 'ai_service', None)
            if ai_service:
                ai_service.api_token = ''
                ai_service.enabled = False
            
            return jsonify({
                'success': True,
                'message': 'Token removed from .env successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No token file found'
            }), 404
        
    except Exception as e:
        logger.error(f"Error removing AI token: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# SIGNAL HANDLERS
# ============================================================================

def handle_exit(signum, frame):
    """Handle exit signals with proper cleanup"""
    logger.info("Shutting down web server...")
    shared_data.webapp_should_exit = True
    
    # Stop all background tasks first
    try:
        socketio.stop()
    except Exception as e:
        logger.warning(f"Error stopping socketio: {e}")
    
    # Kill any running subprocesses
    try:
        if psutil_available:
            current_process = psutil.Process()
            children = current_process.children(recursive=True)
            
            if children:
                logger.info(f"Terminating {len(children)} child processes...")
                for child in children:
                    try:
                        child.terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Wait up to 3 seconds for graceful termination
                gone, alive = psutil.wait_procs(children, timeout=3)
                
                # Force kill any remaining processes
                for p in alive:
                    try:
                        logger.warning(f"Force killing process {p.pid} ({p.name()})")
                        p.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        else:
            # Fallback: try to kill common subprocess patterns
            logger.info("Attempting to clean up subprocesses (psutil not available)...")
            try:
                subprocess.run(['pkill', '-P', str(os.getpid())], timeout=2)
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Error cleaning up subprocesses: {e}")
    
    logger.info("Shutdown complete")
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
