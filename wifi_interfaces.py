"""Shared Wi-Fi interface discovery helpers for Ragnar."""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from typing import Dict, List, Optional

from logger import Logger

logger = Logger(name="wifi_interfaces", level=logging.INFO)

_WIFI_NAME_PATTERN = re.compile(r"^(wlan\d+|wlp[\w\d]+|wlx[\w\d]+)$")


def _get_interface_ipv4_details(interface_name: str) -> Dict[str, Optional[str]]:
    """Return IPv4 metadata (address, prefix, netmask, network) for an interface."""
    try:
        result = subprocess.run(
            ['ip', '-o', '-4', 'addr', 'show', interface_name],
            capture_output=True,
            text=True,
            timeout=3
        )
        if result.returncode != 0 or not result.stdout:
            return {
                'ip': None,
                'cidr': None,
                'netmask': None,
                'network': None,
            }
        match = re.search(r'inet\s+([0-9.]+)/([0-9]+)', result.stdout)
        if not match:
            return {
                'ip': None,
                'cidr': None,
                'netmask': None,
                'network': None,
            }
        ip_value = match.group(1)
        prefix = int(match.group(2))
        iface = ipaddress.IPv4Interface(f"{ip_value}/{prefix}")
        return {
            'ip': ip_value,
            'cidr': prefix,
            'netmask': str(iface.netmask),
            'network': str(iface.network),
        }
    except Exception as exc:
        logger.debug(f"Unable to read IP address for {interface_name}: {exc}")
        return {
            'ip': None,
            'cidr': None,
            'netmask': None,
            'network': None,
        }


def gather_wifi_interfaces(default_interface: str = 'wlan0') -> List[Dict]:
    """Collect Wi-Fi interface metadata using nmcli + ip link fallbacks."""
    interfaces: Dict[str, Dict] = {}

    try:
        nmcli_result = subprocess.run(
            ['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'dev', 'status'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if nmcli_result.returncode == 0:
            for line in nmcli_result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split(':', 3)
                if len(parts) < 4:
                    continue
                device, dev_type, state, connection = parts
                if dev_type != 'wifi':
                    continue
                normalized_connection = connection if connection and connection != '--' else None
                interfaces[device] = {
                    'name': device,
                    'state': state or 'UNKNOWN',
                    'is_default': device == default_interface,
                    'connected_ssid': normalized_connection,
                    'connection': normalized_connection,
                    'connected': (state or '').lower() == 'connected' and bool(normalized_connection),
                }
    except Exception as exc:
        logger.debug(f"nmcli dev status failed: {exc}")

    try:
        ip_result = subprocess.run(
            ['ip', '-o', 'link', 'show'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if ip_result.returncode == 0:
            for line in ip_result.stdout.strip().split('\n'):
                if not line:
                    continue
                name_match = re.match(r'\d+:\s+(\S+):', line)
                if not name_match:
                    continue
                iface_name = name_match.group(1)
                if not _WIFI_NAME_PATTERN.match(iface_name):
                    continue
                entry = interfaces.setdefault(iface_name, {
                    'name': iface_name,
                    'state': 'UNKNOWN',
                    'is_default': iface_name == default_interface,
                    'connected_ssid': None,
                    'connection': None,
                    'connected': False,
                })
                state_match = re.search(r'state\s+(\w+)', line)
                if state_match:
                    entry['state'] = state_match.group(1)
                mac_match = re.search(r'link/ether\s+([0-9a-f:]{17})', line)
                if mac_match:
                    entry['mac_address'] = mac_match.group(1)
    except Exception as exc:
        logger.debug(f"ip link show failed: {exc}")

    if not interfaces:
        interfaces[default_interface] = {
            'name': default_interface,
            'state': 'UNKNOWN',
            'is_default': True,
            'connected_ssid': None,
            'connection': None,
            'connected': False,
        }

    for iface in interfaces.values():
        ipv4 = _get_interface_ipv4_details(iface['name'])
        iface['ip_address'] = ipv4.get('ip')
        iface['cidr'] = ipv4.get('cidr')
        iface['netmask'] = ipv4.get('netmask')
        iface['network_cidr'] = ipv4.get('network')
        iface.setdefault('mac_address', None)

    return sorted(interfaces.values(), key=lambda entry: entry['name'])
