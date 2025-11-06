#!/usr/bin/env python3
"""
Bluetooth Low Energy (BLE) and Classic Bluetooth Management Module for Ragnar
Handles all Bluetooth operations including scanning, pairing, and device management
"""

import subprocess
import re
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
import json
import os

class BluetoothManager:
    """
    Comprehensive Bluetooth management class for Ragnar
    Supports both Classic Bluetooth and BLE operations
    """
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.scan_active = False
        self.scan_start_time = 0.0
        self.discovered_devices = {}
        self.paired_devices = {}
        
    def check_bluetooth_availability(self) -> Tuple[bool, str]:
        """
        Check if Bluetooth is available on the system
        Returns: (available, message)
        """
        try:
            result = subprocess.run(['bluetoothctl', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return True, "Bluetooth available"
            else:
                return False, "bluetoothctl not found or not working"
        except FileNotFoundError:
            return False, "bluetoothctl command not found"
        except subprocess.TimeoutExpired:
            return False, "bluetoothctl command timed out"
        except Exception as e:
            return False, f"Error checking Bluetooth: {str(e)}"
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive Bluetooth status
        Returns detailed status information
        """
        status = {
            'enabled': False,
            'discoverable': False,
            'pairable': False,
            'scanning': self.scan_active,
            'address': None,
            'name': None,
            'class': None,
            'powered': False,
            'error': None,
            'controller_info': {}
        }
        
        try:
            # Check if Bluetooth controller exists and get detailed info
            result = subprocess.run(['bluetoothctl', 'show'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse detailed controller information
                status['powered'] = 'Powered: yes' in output
                status['enabled'] = status['powered']  # For backwards compatibility
                status['discoverable'] = 'Discoverable: yes' in output
                status['pairable'] = 'Pairable: yes' in output
                
                # Check actual scanning status from bluetoothctl
                scan_status = self._check_scan_status()
                if scan_status is not None:
                    status['scanning'] = scan_status
                    self.scan_active = scan_status  # Update internal state
                
                # Extract controller details
                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith('Controller'):
                        status['address'] = line.split()[1] if len(line.split()) > 1 else None
                    elif line.startswith('Name:'):
                        status['name'] = line.replace('Name:', '').strip()
                    elif line.startswith('Class:'):
                        status['class'] = line.replace('Class:', '').strip()
                    elif line.startswith('Alias:'):
                        status['controller_info']['alias'] = line.replace('Alias:', '').strip()
                    elif line.startswith('Modalias:'):
                        status['controller_info']['modalias'] = line.replace('Modalias:', '').strip()
                        
            else:
                status['error'] = 'No Bluetooth controller found'
                self.logger.warning("No Bluetooth controller available")
                
        except subprocess.TimeoutExpired:
            status['error'] = 'Bluetooth status check timed out'
            self.logger.error("Bluetooth status check timed out")
        except Exception as e:
            status['error'] = f'Error checking Bluetooth status: {str(e)}'
            self.logger.error(f"Error checking Bluetooth status: {e}")
        
        return status
    
    def _check_scan_status(self) -> Optional[bool]:
        """
        Check if scanning is actually active by checking bluetoothctl status
        Returns: True if scanning, False if not scanning, None if unable to determine
        """
        try:
            result = subprocess.run(['bluetoothctl', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'discovering: yes' in output:
                    return True
                elif 'discovering: no' in output:
                    return False
        except Exception:
            pass
        return None
    
    def power_on(self) -> Tuple[bool, str]:
        """
        Enable/Power on Bluetooth
        Returns: (success, message)
        """
        try:
            self.logger.info("Enabling Bluetooth...")
            result = subprocess.run(['bluetoothctl', 'power', 'on'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                # Wait a moment for Bluetooth to stabilize
                time.sleep(2)
                
                # Verify it's actually enabled
                status = self.get_status()
                if status['enabled']:
                    self.logger.info("Bluetooth enabled successfully")
                    return True, "Bluetooth enabled successfully"
                else:
                    self.logger.warning("Bluetooth command succeeded but device not powered")
                    return False, "Bluetooth power on command succeeded but device not enabled"
            else:
                error_msg = result.stderr.strip() or 'Failed to enable Bluetooth'
                self.logger.error(f"Failed to enable Bluetooth: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            self.logger.error("Bluetooth enable command timed out")
            return False, "Enable Bluetooth command timed out"
        except Exception as e:
            self.logger.error(f"Error enabling Bluetooth: {e}")
            return False, f"Error enabling Bluetooth: {str(e)}"
    
    def power_off(self) -> Tuple[bool, str]:
        """
        Disable/Power off Bluetooth
        Returns: (success, message)
        """
        try:
            self.logger.info("Disabling Bluetooth...")
            
            # Stop scanning if active
            if self.scan_active:
                self.stop_scan()
            
            result = subprocess.run(['bluetoothctl', 'power', 'off'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info("Bluetooth disabled successfully")
                return True, "Bluetooth disabled successfully"
            else:
                error_msg = result.stderr.strip() or 'Failed to disable Bluetooth'
                self.logger.error(f"Failed to disable Bluetooth: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            self.logger.error("Bluetooth disable command timed out")
            return False, "Disable Bluetooth command timed out"
        except Exception as e:
            self.logger.error(f"Error disabling Bluetooth: {e}")
            return False, f"Error disabling Bluetooth: {str(e)}"
    
    def set_discoverable(self, discoverable: bool) -> Tuple[bool, str]:
        """
        Set Bluetooth discoverable mode
        Args:
            discoverable: True to make discoverable, False to hide
        Returns: (success, message)
        """
        try:
            mode = 'on' if discoverable else 'off'
            action = 'discoverable' if discoverable else 'hidden'
            
            self.logger.info(f"Setting Bluetooth {action}...")
            result = subprocess.run(['bluetoothctl', 'discoverable', mode], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                message = f"Bluetooth is now {action}"
                self.logger.info(message)
                return True, message
            else:
                error_msg = result.stderr.strip() or f'Failed to make Bluetooth {action}'
                self.logger.error(f"Failed to set discoverable mode: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, "Discoverable command timed out"
        except Exception as e:
            self.logger.error(f"Error setting discoverable mode: {e}")
            return False, f"Error setting discoverable mode: {str(e)}"
    
    def start_scan(self, duration: Optional[int] = None) -> Tuple[bool, str]:
        """
        Start Bluetooth device discovery scan
        Args:
            duration: Optional scan duration in seconds
        Returns: (success, message)
        """
        try:
            self.logger.info("Starting Bluetooth device scan...")
            
            # Ensure Bluetooth is powered on first
            status = self.get_status()
            if not status['enabled']:
                power_success, power_msg = self.power_on()
                if not power_success:
                    return False, f"Cannot start scan: {power_msg}"
            
            # Try multiple methods to start scanning
            methods_tried = []
            scan_started = False
            
            # Method 1: Standard bluetoothctl scan on
            try:
                result = subprocess.run(['bluetoothctl', 'scan', 'on'], 
                                      capture_output=True, text=True, timeout=10)
                methods_tried.append(f"bluetoothctl scan on: rc={result.returncode}")
                self.logger.info(f"Method 1 - bluetoothctl scan on: returncode={result.returncode}, stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'")
                
                if result.returncode == 0:
                    # Wait and verify
                    time.sleep(2)
                    actual_scan_status = self._check_scan_status()
                    if actual_scan_status is True:
                        scan_started = True
                        methods_tried.append("scan verified active")
                    else:
                        methods_tried.append("scan command ok but not active")
            except Exception as e:
                methods_tried.append(f"bluetoothctl scan on failed: {e}")
            
            # Method 2: If first method didn't work, try hcitool lescan (if available)
            if not scan_started:
                try:
                    result = subprocess.run(['timeout', '1', 'hcitool', 'lescan'], 
                                          capture_output=True, text=True, timeout=3)
                    methods_tried.append(f"hcitool lescan: rc={result.returncode}")
                    if result.returncode in [0, 124]:  # 124 is timeout exit code
                        scan_started = True
                        methods_tried.append("hcitool lescan working")
                except Exception as e:
                    methods_tried.append(f"hcitool lescan failed: {e}")
            
            # Method 3: Try using bluetoothctl interactively
            if not scan_started:
                try:
                    # Use echo to pipe commands to bluetoothctl
                    result = subprocess.run(['bash', '-c', 'echo "scan on" | bluetoothctl'], 
                                          capture_output=True, text=True, timeout=5)
                    methods_tried.append(f"interactive bluetoothctl: rc={result.returncode}")
                    
                    time.sleep(1)
                    actual_scan_status = self._check_scan_status()
                    if actual_scan_status is True:
                        scan_started = True
                        methods_tried.append("interactive method working")
                except Exception as e:
                    methods_tried.append(f"interactive method failed: {e}")
            
            # Update state and prepare response
            if scan_started:
                self.scan_active = True
                self.scan_start_time = time.time()
                
                message = "Bluetooth device scan started"
                if duration:
                    message += f" (will run for {duration} seconds)"
                message += ". Make sure nearby devices are in discoverable mode."
                
                self.logger.info(f"Scan started successfully. Methods tried: {', '.join(methods_tried)}")
                return True, message
            else:
                self.scan_active = False
                error_msg = f"Failed to start Bluetooth scan. Methods tried: {', '.join(methods_tried)}"
                self.logger.error(error_msg)
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, "Scan start command timed out"
        except Exception as e:
            self.logger.error(f"Error starting Bluetooth scan: {e}")
            return False, f"Error starting scan: {str(e)}"
    
    def stop_scan(self) -> Tuple[bool, str]:
        """
        Stop Bluetooth device discovery scan
        Returns: (success, message)
        """
        try:
            self.logger.info("Stopping Bluetooth device scan...")
            result = subprocess.run(['bluetoothctl', 'scan', 'off'], 
                                  capture_output=True, text=True, timeout=10)
            
            # bluetoothctl scan off sometimes returns non-zero even when successful
            success_indicators = [
                'success', 'Discovery stopped', 'Discovering: no', 
                'discovery stopped', 'stopped discovery'
            ]
            output_text = (result.stdout + result.stderr).lower()
            
            # Check for success indicators or determine if scan actually stopped
            scan_actually_stopped = False
            if result.returncode == 0:
                scan_actually_stopped = True
            elif any(indicator.lower() in output_text for indicator in success_indicators):
                scan_actually_stopped = True
            elif 'not available' not in output_text and 'failed' not in output_text and 'error' not in output_text:
                # If no clear error indicators, assume success
                scan_actually_stopped = True
            
            if scan_actually_stopped:
                self.scan_active = False
                self.logger.info("Bluetooth scan stopped successfully")
                return True, "Bluetooth scan stopped successfully"
            else:
                # Even if command failed, mark scan as inactive for safety
                self.scan_active = False
                error_msg = result.stderr.strip() or result.stdout.strip() or 'Failed to stop Bluetooth scan'
                self.logger.warning(f"Scan stop command may have failed, but marking as stopped: {error_msg}")
                return False, f"Scan stop completed with warning: {error_msg}"
                
        except subprocess.TimeoutExpired:
            # Mark scan as inactive even on timeout
            self.scan_active = False
            return False, "Scan stop command timed out"
        except Exception as e:
            # Mark scan as inactive even on error
            self.scan_active = False
            self.logger.error(f"Error stopping Bluetooth scan: {e}")
            return False, f"Error stopping scan: {str(e)}"
    
    def get_discovered_devices(self, refresh: bool = True) -> Dict[str, Dict[str, Any]]:
        """
        Get list of discovered Bluetooth devices
        Args:
            refresh: Whether to refresh device information
        Returns: Dictionary of devices keyed by MAC address
        """
        devices = {}
        
        try:
            # Method 1: Get known devices from bluetoothctl devices
            result = subprocess.run(['bluetoothctl', 'devices'], 
                                  capture_output=True, text=True, timeout=10)
            
            self.logger.info(f"bluetoothctl devices returned: returncode={result.returncode}, stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'")
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    self.logger.debug(f"Processing device line: '{line}'")
                    if line and line.startswith('Device '):
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            address = parts[1]
                            name = parts[2] if len(parts) > 2 else 'Unknown Device'
                            
                            self.logger.info(f"Found device: {address} - {name}")
                            
                            device_info = {
                                'address': address,
                                'name': name,
                                'rssi': None,
                                'device_class': None,
                                'device_type': 'Unknown',
                                'services': [],
                                'paired': False,
                                'connected': False,
                                'trusted': False,
                                'last_seen': time.time()
                            }
                            
                            # Get detailed device information if requested
                            if refresh:
                                detailed_info = self._get_device_details(address)
                                device_info.update(detailed_info)
                            
                            devices[address] = device_info
            else:
                self.logger.warning(f"bluetoothctl devices failed with return code {result.returncode}")
            
            # Method 2: If scanning is active, try to get scan results
            if self.scan_active or self._check_scan_status():
                self.logger.info("Scanning is active, attempting to get scan results...")
                scan_devices = self._get_scan_results()
                if scan_devices:
                    devices.update(scan_devices)
                    self.logger.info(f"Found {len(scan_devices)} additional devices from scan")
                            
            self.discovered_devices = devices
            self.logger.info(f"Total devices found: {len(devices)}")
            
        except subprocess.TimeoutExpired:
            self.logger.error("Device list command timed out")
        except Exception as e:
            self.logger.error(f"Error getting device list: {e}")
        
        return devices
    
    def _get_scan_results(self) -> Dict[str, Dict[str, Any]]:
        """
        Try to get devices discovered during active scanning using multiple methods
        This is a workaround since bluetoothctl devices might not show newly discovered devices
        """
        scan_devices = {}
        
        # Method 1: Try hcitool lescan output
        try:
            result = subprocess.run(['timeout', '3', 'hcitool', 'lescan'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode in [0, 124]:  # 124 is timeout exit code
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and ':' in line and len(line.split()) >= 2:
                        parts = line.split(None, 1)
                        if len(parts) >= 2:
                            address = parts[0]
                            name = parts[1] if len(parts) > 1 else 'Unknown Device'
                            
                            # Basic MAC address validation
                            if len(address.split(':')) == 6:
                                self.logger.info(f"Found device via hcitool: {address} - {name}")
                                
                                device_info = {
                                    'address': address,
                                    'name': name,
                                    'rssi': None,
                                    'device_class': None,
                                    'device_type': 'BLE Device',
                                    'services': [],
                                    'paired': False,
                                    'connected': False,
                                    'trusted': False,
                                    'last_seen': time.time(),
                                    'from_scan': True,
                                    'discovery_method': 'hcitool'
                                }
                                
                                scan_devices[address] = device_info
                                
        except Exception as e:
            self.logger.debug(f"hcitool lescan failed: {e}")
        
        # Method 2: Try bluetoothctl in batch mode (original method)
        try:
            # Try running bluetoothctl in batch mode to get scan results
            result = subprocess.run(['timeout', '3', 'bluetoothctl'], 
                                  input='scan on\ndevices\nexit\n',
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 or result.returncode == 124:  # 124 is timeout exit code
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and line.startswith('Device '):
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            address = parts[1]
                            name = parts[2] if len(parts) > 2 else 'Unknown Device'
                            
                            if address not in scan_devices:  # Don't overwrite hcitool results
                                self.logger.info(f"Found device via bluetoothctl batch: {address} - {name}")
                                
                                device_info = {
                                    'address': address,
                                    'name': name,
                                    'rssi': None,
                                    'device_class': None,
                                    'device_type': 'Unknown',
                                    'services': [],
                                    'paired': False,
                                    'connected': False,
                                    'trusted': False,
                                    'last_seen': time.time(),
                                    'from_scan': True,
                                    'discovery_method': 'bluetoothctl'
                                }
                                
                                scan_devices[address] = device_info
                                
        except Exception as e:
            self.logger.debug(f"bluetoothctl batch mode failed: {e}")
            
        return scan_devices
    
    def diagnose_scanning(self) -> Dict[str, Any]:
        """
        Diagnose why Bluetooth scanning might not be finding devices
        Returns diagnostic information
        """
        diagnosis = {
            'bluetooth_available': False,
            'bluetooth_enabled': False,
            'scanning_active': False,
            'controller_info': {},
            'recommendations': []
        }
        
        try:
            # Check basic availability
            available, msg = self.check_bluetooth_availability()
            diagnosis['bluetooth_available'] = available
            if not available:
                diagnosis['recommendations'].append(f"Bluetooth not available: {msg}")
                return diagnosis
            
            # Check status
            status = self.get_status()
            diagnosis['bluetooth_enabled'] = status.get('enabled', False)
            diagnosis['scanning_active'] = status.get('scanning', False)
            diagnosis['controller_info'] = status.get('controller_info', {})
            
            if not diagnosis['bluetooth_enabled']:
                diagnosis['recommendations'].append("Bluetooth is not enabled. Try enabling it first.")
            
            if not diagnosis['scanning_active']:
                diagnosis['recommendations'].append("Scanning is not active. Start a scan to discover devices.")
            
            # Check for paired devices as a baseline
            paired = self.get_paired_devices()
            diagnosis['paired_device_count'] = len(paired)
            
            if len(paired) == 0:
                diagnosis['recommendations'].append("No paired devices found. This might indicate Bluetooth setup issues.")
            
            # Test basic bluetoothctl functionality
            try:
                result = subprocess.run(['bluetoothctl', 'list'], 
                                      capture_output=True, text=True, timeout=5)
                diagnosis['controllers_found'] = result.returncode == 0 and len(result.stdout.strip()) > 0
                if not diagnosis['controllers_found']:
                    diagnosis['recommendations'].append("No Bluetooth controllers found. Check hardware.")
            except Exception:
                diagnosis['controllers_found'] = False
                diagnosis['recommendations'].append("Cannot communicate with bluetoothctl. Check installation.")
            
            # Add general recommendations
            if len(diagnosis['recommendations']) == 0:
                diagnosis['recommendations'].extend([
                    "Bluetooth appears to be working correctly.",
                    "Make sure nearby devices are in discoverable/pairable mode.",
                    "Try putting a phone or other device in Bluetooth pairing mode.",
                    "Some devices only show up when actively scanning from them."
                ])
            
        except Exception as e:
            diagnosis['error'] = str(e)
            diagnosis['recommendations'].append(f"Error during diagnosis: {e}")
        
        return diagnosis
    
    def _get_device_details(self, address: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific Bluetooth device
        Args:
            address: MAC address of the device
        Returns: Dictionary with detailed device information
        """
        details = {}
        
        try:
            result = subprocess.run(['bluetoothctl', 'info', address], 
                                  capture_output=True, text=True, timeout=8)
            
            if result.returncode == 0:
                info_output = result.stdout
                
                # Parse device information
                for line in info_output.split('\n'):
                    line = line.strip()
                    
                    # RSSI (signal strength)
                    if line.startswith('RSSI:'):
                        try:
                            details['rssi'] = int(line.split(':')[1].strip())
                        except (ValueError, IndexError):
                            pass
                    
                    # Device class
                    elif line.startswith('Class:'):
                        details['device_class'] = line.split(':', 1)[1].strip()
                    
                    # Device type/icon
                    elif line.startswith('Icon:'):
                        details['device_type'] = line.split(':', 1)[1].strip()
                    
                    # Connection status
                    elif line.startswith('Connected:'):
                        details['connected'] = 'yes' in line.lower()
                    
                    # Pairing status
                    elif line.startswith('Paired:'):
                        details['paired'] = 'yes' in line.lower()
                    
                    # Trust status
                    elif line.startswith('Trusted:'):
                        details['trusted'] = 'yes' in line.lower()
                    
                    # Services (UUIDs)
                    elif line.startswith('UUID:'):
                        if 'services' not in details:
                            details['services'] = []
                        
                        # Extract UUID and service name
                        uuid_part = line.split(':', 1)[1].strip()
                        if '(' in uuid_part and ')' in uuid_part:
                            uuid = uuid_part.split('(')[0].strip()
                            service_name = uuid_part.split('(')[1].replace(')', '').strip()
                            details['services'].append({
                                'uuid': uuid,
                                'name': service_name
                            })
                        else:
                            details['services'].append({
                                'uuid': uuid_part,
                                'name': 'Unknown Service'
                            })
                
        except Exception as e:
            self.logger.warning(f"Error getting device details for {address}: {e}")
        
        return details
    
    def pair_device(self, address: str) -> Tuple[bool, str]:
        """
        Pair with a Bluetooth device
        Args:
            address: MAC address of the device to pair
        Returns: (success, message)
        """
        try:
            self.logger.info(f"Attempting to pair with device {address}...")
            
            # First check if device is discoverable
            devices = self.get_discovered_devices(refresh=False)
            if address not in devices:
                return False, f"Device {address} not found. Start a scan first."
            
            result = subprocess.run(['bluetoothctl', 'pair', address], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 or 'Pairing successful' in result.stdout:
                self.logger.info(f"Successfully paired with {address}")
                return True, f"Successfully paired with {address}"
            else:
                error_msg = result.stderr.strip() or f'Failed to pair with {address}'
                if 'already paired' in error_msg.lower():
                    return True, f"Device {address} is already paired"
                
                self.logger.error(f"Failed to pair with {address}: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, f"Pairing with {address} timed out"
        except Exception as e:
            self.logger.error(f"Error pairing with {address}: {e}")
            return False, f"Error pairing with {address}: {str(e)}"
    
    def unpair_device(self, address: str) -> Tuple[bool, str]:
        """
        Unpair (remove) a Bluetooth device
        Args:
            address: MAC address of the device to unpair
        Returns: (success, message)
        """
        try:
            self.logger.info(f"Removing/unpairing device {address}...")
            result = subprocess.run(['bluetoothctl', 'remove', address], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully removed device {address}")
                return True, f"Successfully removed device {address}"
            else:
                error_msg = result.stderr.strip() or f'Failed to remove device {address}'
                self.logger.error(f"Failed to remove {address}: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, f"Remove device {address} command timed out"
        except Exception as e:
            self.logger.error(f"Error removing device {address}: {e}")
            return False, f"Error removing device {address}: {str(e)}"
    
    def connect_device(self, address: str) -> Tuple[bool, str]:
        """
        Connect to a paired Bluetooth device
        Args:
            address: MAC address of the device to connect
        Returns: (success, message)
        """
        try:
            self.logger.info(f"Connecting to device {address}...")
            result = subprocess.run(['bluetoothctl', 'connect', address], 
                                  capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0 or 'Connection successful' in result.stdout:
                self.logger.info(f"Successfully connected to {address}")
                return True, f"Successfully connected to {address}"
            else:
                error_msg = result.stderr.strip() or f'Failed to connect to {address}'
                self.logger.error(f"Failed to connect to {address}: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, f"Connection to {address} timed out"
        except Exception as e:
            self.logger.error(f"Error connecting to {address}: {e}")
            return False, f"Error connecting to {address}: {str(e)}"
    
    def disconnect_device(self, address: str) -> Tuple[bool, str]:
        """
        Disconnect from a Bluetooth device
        Args:
            address: MAC address of the device to disconnect
        Returns: (success, message)
        """
        try:
            self.logger.info(f"Disconnecting from device {address}...")
            result = subprocess.run(['bluetoothctl', 'disconnect', address], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully disconnected from {address}")
                return True, f"Successfully disconnected from {address}"
            else:
                error_msg = result.stderr.strip() or f'Failed to disconnect from {address}'
                self.logger.error(f"Failed to disconnect from {address}: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, f"Disconnect from {address} timed out"
        except Exception as e:
            self.logger.error(f"Error disconnecting from {address}: {e}")
            return False, f"Error disconnecting from {address}: {str(e)}"
    
    def get_paired_devices(self) -> Dict[str, Dict[str, Any]]:
        """
        Get list of paired Bluetooth devices
        Returns: Dictionary of paired devices keyed by MAC address
        """
        paired_devices = {}
        
        try:
            result = subprocess.run(['bluetoothctl', 'paired-devices'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('Device '):
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            address = parts[1]
                            name = parts[2] if len(parts) > 2 else 'Unknown Device'
                            
                            # Get detailed info
                            device_info = self._get_device_details(address)
                            device_info.update({
                                'address': address,
                                'name': name,
                                'paired': True
                            })
                            
                            paired_devices[address] = device_info
                            
        except Exception as e:
            self.logger.error(f"Error getting paired devices: {e}")
        
        return paired_devices
    
    def scan_for_time(self, duration: int) -> Dict[str, Dict[str, Any]]:
        """
        Perform a timed Bluetooth scan
        Args:
            duration: Scan duration in seconds
        Returns: Dictionary of discovered devices
        """
        self.logger.info(f"Starting {duration}-second Bluetooth scan...")
        
        # Start scan
        success, message = self.start_scan()
        if not success:
            self.logger.error(f"Failed to start scan: {message}")
            return {}
        
        # Wait for specified duration
        time.sleep(duration)
        
        # Get discovered devices
        devices = self.get_discovered_devices()
        
        # Stop scan
        self.stop_scan()
        
        self.logger.info(f"Scan completed. Found {len(devices)} devices.")
        return devices
    
    def export_devices_to_json(self, filepath: str) -> bool:
        """
        Export discovered devices to JSON file
        Args:
            filepath: Path to save the JSON file
        Returns: Success status
        """
        try:
            devices = self.get_discovered_devices()
            
            # Convert to serializable format
            export_data = {
                'timestamp': time.time(),
                'scan_duration': time.time() - self.scan_start_time if self.scan_start_time else 0,
                'device_count': len(devices),
                'devices': devices
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported {len(devices)} devices to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting devices to JSON: {e}")
            return False

# Convenience functions for easy usage
def quick_scan(duration: int = 10, logger=None) -> Dict[str, Dict[str, Any]]:
    """
    Perform a quick Bluetooth scan
    Args:
        duration: Scan duration in seconds
        logger: Optional logger instance
    Returns: Dictionary of discovered devices
    """
    bt_manager = BluetoothManager(logger)
    return bt_manager.scan_for_time(duration)

def get_bluetooth_info(logger=None) -> Dict[str, Any]:
    """
    Get basic Bluetooth system information
    Args:
        logger: Optional logger instance
    Returns: Bluetooth status and device information
    """
    bt_manager = BluetoothManager(logger)
    
    available, msg = bt_manager.check_bluetooth_availability()
    if not available:
        return {'available': False, 'error': msg}
    
    status = bt_manager.get_status()
    devices = bt_manager.get_discovered_devices() if status['enabled'] else {}
    paired = bt_manager.get_paired_devices() if status['enabled'] else {}
    
    return {
        'available': True,
        'status': status,
        'discovered_devices': devices,
        'paired_devices': paired,
        'device_counts': {
            'discovered': len(devices),
            'paired': len(paired)
        }
    }

if __name__ == "__main__":
    # Example usage and testing
    import logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    print("🔵 Testing Bluetooth Manager")
    print("=" * 40)
    
    # Create Bluetooth manager
    bt = BluetoothManager(logger)
    
    # Check availability
    available, msg = bt.check_bluetooth_availability()
    print(f"Bluetooth Available: {available} - {msg}")
    
    if available:
        # Get status
        status = bt.get_status()
        print(f"Bluetooth Status: {status}")
        
        # Test power on
        if not status['enabled']:
            success, msg = bt.power_on()
            print(f"Power On: {success} - {msg}")
        
        # Quick scan
        print("Starting 10-second scan...")
        devices = bt.scan_for_time(10)
        print(f"Found {len(devices)} devices:")
        
        for addr, device in devices.items():
            print(f"  • {device['name']} ({addr}) - RSSI: {device.get('rssi', 'N/A')}")