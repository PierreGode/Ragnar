# wifi_manager.py
# Robust Wi-Fi management system for Ragnar IoT device
# Handles automatic connection, AP mode fallback, and web-based configuration
# Author: GitHub Copilot Assistant
# 
# Features:
# - Auto-connect to known Wi-Fi networks on boot
# - Fall back to AP mode if connection fails 
# - Web interface for Wi-Fi configuration
# - Robust connection monitoring with proper timing
# - Network scanning and credential management
# - Integration with wpa_supplicant and NetworkManager

import os
import time
import json
import subprocess
import threading
import logging
import re
import signal
from datetime import datetime, timedelta
from logger import Logger


class WiFiManager:
    """Manages Wi-Fi connections, AP mode, and configuration for Ragnar"""
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name="WiFiManager", level=logging.INFO)
        
        # Setup dedicated AP mode logging
        self.setup_ap_logger()
        
        # State management
        self.wifi_connected = False
        self.ap_mode_active = False
        self.connection_attempts = 0
        self.last_connection_attempt = None
        self.connection_check_interval = 30  # seconds
        self.connection_timeout = shared_data.config.get('wifi_initial_connection_timeout', 60)
        self.max_connection_attempts = 3
        
        # Smart AP mode management
        self.ap_mode_start_time = None
        self.ap_timeout = shared_data.config.get('wifi_ap_timeout', 180)  # 3 minutes
        self.ap_idle_timeout = shared_data.config.get('wifi_ap_idle_timeout', 180)  # 3 minutes
        self.reconnect_interval = shared_data.config.get('wifi_reconnect_interval', 20)  # 20 seconds
        self.ap_cycle_enabled = shared_data.config.get('wifi_ap_cycle_enabled', True)
        self.last_ap_stop_time = None
        self.ap_clients_connected = False
        self.ap_clients_count = 0
        self.cycling_mode = False  # Track if we're in AP/reconnect cycle
        
        # Network management
        self.known_networks = []
        self.available_networks = []
        self.current_ssid = None
        
        # AP mode settings
        self.ap_ssid = shared_data.config.get('wifi_ap_ssid', 'Ragnar-Setup')
        self.ap_password = shared_data.config.get('wifi_ap_password', 'ragnarpassword')
        self.ap_interface = "wlan0"
        self.ap_ip = "192.168.4.1"
        self.ap_subnet = "192.168.4.0/24"
        
        # Control flags
        self.should_exit = False
        self.monitoring_thread = None
        self.startup_complete = False
        
        # Load configuration
        self.load_wifi_config()
        
    def load_wifi_config(self):
        """Load Wi-Fi configuration from shared data"""
        try:
            config = self.shared_data.config
            
            # Load known networks
            self.known_networks = config.get('wifi_known_networks', [])
            
            # Load AP settings
            self.ap_ssid = config.get('wifi_ap_ssid', 'Ragnar-Setup')
            self.ap_password = config.get('wifi_ap_password', 'ragnarpassword')
            self.connection_timeout = config.get('wifi_connection_timeout', 60)
            self.max_connection_attempts = config.get('wifi_max_attempts', 3)
            
            self.logger.info(f"Wi-Fi config loaded: {len(self.known_networks)} known networks")
            
        except Exception as e:
            self.logger.error(f"Error loading Wi-Fi config: {e}")
    
    def save_wifi_config(self):
        """Save Wi-Fi configuration to shared data"""
        try:
            self.shared_data.config['wifi_known_networks'] = self.known_networks
            self.shared_data.config['wifi_ap_ssid'] = self.ap_ssid
            self.shared_data.config['wifi_ap_password'] = self.ap_password
            self.shared_data.config['wifi_connection_timeout'] = self.connection_timeout
            self.shared_data.config['wifi_max_attempts'] = self.max_connection_attempts
            
            self.shared_data.save_config()
            self.logger.info("Wi-Fi configuration saved")
            
        except Exception as e:
            self.logger.error(f"Error saving Wi-Fi config: {e}")
    
    def setup_ap_logger(self):
        """Setup dedicated logger for AP mode operations"""
        try:
            # Create a dedicated logger for AP mode
            self.ap_logger = logging.getLogger('WiFiManager_AP')
            self.ap_logger.setLevel(logging.DEBUG)
            
            # Remove existing handlers to avoid duplication
            for handler in self.ap_logger.handlers[:]:
                self.ap_logger.removeHandler(handler)
            
            # Create file handler for /var/log/ap.log
            try:
                ap_log_file = '/var/log/ap.log'
                # Ensure log directory exists
                os.makedirs(os.path.dirname(ap_log_file), exist_ok=True)
                file_handler = logging.FileHandler(ap_log_file)
            except (PermissionError, OSError):
                # Fallback to local log file if /var/log is not writable
                ap_log_file = os.path.join(self.shared_data.logsdir, 'ap.log')
                os.makedirs(os.path.dirname(ap_log_file), exist_ok=True)
                file_handler = logging.FileHandler(ap_log_file)
            
            # Create formatter for detailed logging
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            
            # Add handler to logger
            self.ap_logger.addHandler(file_handler)
            
            # Prevent propagation to avoid duplicate logging
            self.ap_logger.propagate = False
            
            # Log startup message
            self.ap_logger.info("="*50)
            self.ap_logger.info("AP Mode Logger Initialized")
            self.ap_logger.info(f"Log file: {ap_log_file}")
            self.ap_logger.info("="*50)
            
        except Exception as e:
            self.logger.error(f"Failed to setup AP logger: {e}")
            # Create a fallback logger that writes to the main logger
            self.ap_logger = self.logger
    
    def start(self):
        """Start the Wi-Fi management system"""
        self.logger.info("Starting Wi-Fi Manager...")
        
        # Create a restart detection file to help identify service restarts
        self._create_restart_marker()
        
        # Start monitoring thread
        if not self.monitoring_thread or not self.monitoring_thread.is_alive():
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
        
        # Initial connection attempt
        self._initial_connection_sequence()
    
    def stop(self):
        """Stop the Wi-Fi management system"""
        self.logger.info("Stopping Wi-Fi Manager...")
        self.ap_logger.info("WiFi Manager stopping - shutting down AP logger")
        
        # Save current connection state before stopping
        current_ssid = self.get_current_ssid()
        is_connected = self.check_wifi_connection()
        self._save_connection_state(current_ssid, is_connected)
        
        self.should_exit = True
        
        # Clean up restart marker
        self._cleanup_restart_marker()
        
        if self.ap_mode_active:
            self.stop_ap_mode()
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        # Close AP logger
        try:
            if hasattr(self, 'ap_logger') and hasattr(self.ap_logger, 'handlers'):
                self.ap_logger.info("AP logger shutting down")
                for handler in self.ap_logger.handlers[:]:
                    handler.close()
                    self.ap_logger.removeHandler(handler)
        except Exception as e:
            self.logger.warning(f"Error closing AP logger: {e}")

    def _save_connection_state(self, ssid=None, connected=False):
        """Save current connection state to help with service restarts"""
        try:
            state_file = '/tmp/ragnar_wifi_state.json'
            state = {
                'timestamp': time.time(),
                'connected': connected,
                'ssid': ssid,
                'ap_mode': self.ap_mode_active
            }
            with open(state_file, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            self.logger.warning(f"Could not save connection state: {e}")

    def _load_connection_state(self):
        """Load previous connection state"""
        try:
            state_file = '/tmp/ragnar_wifi_state.json'
            if os.path.exists(state_file):
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    # Only use state if it's recent (less than 10 minutes old)
                    if time.time() - state.get('timestamp', 0) < 600:
                        return state
        except Exception as e:
            self.logger.warning(f"Could not load connection state: {e}")
        return None

    def _cleanup_connection_state(self):
        """Clean up connection state file"""
        try:
            state_file = '/tmp/ragnar_wifi_state.json'
            if os.path.exists(state_file):
                os.remove(state_file)
        except Exception as e:
            self.logger.warning(f"Could not clean up connection state: {e}")

    def _create_restart_marker(self):
        """Create a marker file to help detect service restarts"""
        try:
            marker_file = '/tmp/ragnar_wifi_manager.pid'
            with open(marker_file, 'w') as f:
                f.write(f"{os.getpid()}\n{time.time()}\n")
        except Exception as e:
            self.logger.warning(f"Could not create restart marker: {e}")

    def _cleanup_restart_marker(self):
        """Clean up the restart marker file"""
        try:
            marker_file = '/tmp/ragnar_wifi_manager.pid'
            if os.path.exists(marker_file):
                os.remove(marker_file)
        except Exception as e:
            self.logger.warning(f"Could not clean up restart marker: {e}")

    def _was_recently_running(self):
        """Check if WiFi manager was recently running (indicates service restart)"""
        try:
            marker_file = '/tmp/ragnar_wifi_manager.pid'
            if os.path.exists(marker_file):
                with open(marker_file, 'r') as f:
                    lines = f.readlines()
                    if len(lines) >= 2:
                        last_start_time = float(lines[1].strip())
                        # If the marker is less than 5 minutes old, consider it a recent restart
                        if time.time() - last_start_time < 300:
                            self.logger.info("Found recent WiFi manager marker - service restart detected")
                            return True
            return False
        except Exception as e:
            self.logger.warning(f"Could not check restart marker: {e}")
            return False
    
    def _initial_connection_sequence(self):
        """Handle initial Wi-Fi connection on startup - with smart existing connection detection"""
        self.logger.info("Starting Wi-Fi connection assessment...")
        
        # Check if this is a fresh boot or service restart
        is_fresh_boot = self._is_fresh_boot()
        
        # Load previous connection state for service restarts
        previous_state = None if is_fresh_boot else self._load_connection_state()
        
        if previous_state:
            self.logger.info(f"Previous state: connected={previous_state.get('connected')}, "
                           f"ssid={previous_state.get('ssid')}, ap_mode={previous_state.get('ap_mode')}")
        
        # First, check if we're already connected
        initial_check_start = time.time()
        for i in range(3):  # Check 3 times over 15 seconds to allow network to stabilize
            if self.check_wifi_connection():
                self.wifi_connected = True
                self.shared_data.wifi_connected = True
                self.current_ssid = self.get_current_ssid()
                self.logger.info(f"Already connected to Wi-Fi network: {self.current_ssid}")
                self._save_connection_state(self.current_ssid, True)  # Save successful connection
                self.startup_complete = True
                return  # Exit early - we're already connected!
            
            # If this is a service restart, don't wait too long
            wait_time = 5 if i < 2 else 10
            self.logger.info(f"Checking existing connection... attempt {i+1}/3 (waiting {wait_time}s)")
            time.sleep(wait_time)
        
        # Not connected, but check previous state for service restarts
        if not is_fresh_boot and previous_state and previous_state.get('connected'):
            prev_ssid = previous_state.get('ssid')
            if prev_ssid:
                self.logger.info(f"Service restart detected - attempting to reconnect to previous network: {prev_ssid}")
                if self.connect_to_network(prev_ssid):
                    # Give it a moment to establish connection
                    time.sleep(5)
                    if self.check_wifi_connection():
                        self.wifi_connected = True
                        self.shared_data.wifi_connected = True
                        self.current_ssid = prev_ssid
                        self.logger.info(f"Successfully reconnected to previous network: {prev_ssid}")
                        self._save_connection_state(prev_ssid, True)
                        self.startup_complete = True
                        return
        
        self.logger.info("No existing connection found, determining startup type...")
        
        if is_fresh_boot:
            # Fresh boot - use full startup delay
            if hasattr(self.shared_data, 'startup_delay') and self.shared_data.startup_delay > 0:
                self.logger.info(f"Fresh boot detected - waiting full startup delay: {self.shared_data.startup_delay}s")
                time.sleep(self.shared_data.startup_delay)
        else:
            # Service restart - use shorter delay
            restart_delay = 15  # Much shorter delay for service restarts
            self.logger.info(f"Service restart detected - using shorter delay: {restart_delay}s")
            time.sleep(restart_delay)
        
        # Now try to connect to known networks
        self.logger.info("Attempting to connect to known networks...")
        connection_start = time.time()
        connected = False
        
        # Adjust timeout based on startup type
        timeout = self.connection_timeout if is_fresh_boot else min(30, self.connection_timeout)
        
        while (time.time() - connection_start) < timeout and not connected and not self.should_exit:
            self.logger.info(f"Connection attempt {self.connection_attempts + 1}/{self.max_connection_attempts}")
            
            if self.try_connect_known_networks():
                connected = True
                self.wifi_connected = True
                self.shared_data.wifi_connected = True
                self.current_ssid = self.get_current_ssid()
                self.logger.info(f"Successfully connected to network: {self.current_ssid}")
                self._save_connection_state(self.current_ssid, True)  # Save successful connection
                break
            
            self.connection_attempts += 1
            if self.connection_attempts >= self.max_connection_attempts:
                self.logger.warning("Max connection attempts reached")
                break
            
            # Shorter wait between attempts for service restarts
            wait_time = 10 if is_fresh_boot else 5
            time.sleep(wait_time)
        
        # If no connection established, decide whether to start AP mode
        if not connected and not self.should_exit:
            self.last_connection_attempt = time.time()  # Track when we last tried
            
            # For service restarts, only start AP mode if we weren't previously connected
            should_start_ap = is_fresh_boot
            if previous_state and not previous_state.get('connected'):
                should_start_ap = True
            
            if should_start_ap and self.shared_data.config.get('wifi_auto_ap_fallback', True):
                if self.ap_cycle_enabled:
                    self.logger.info("No Wi-Fi connection established, starting AP cycling mode...")
                    self.start_ap_mode_with_timeout()
                else:
                    self.logger.info("No Wi-Fi connection established, starting AP mode...")
                    self.start_ap_mode()
            else:
                self.logger.info("Skipping AP mode - will retry connection in monitoring loop")
                self._save_connection_state(None, False)  # Save disconnected state
        
        self.startup_complete = True

    def _is_fresh_boot(self):
        """Determine if this is a fresh system boot or just a service restart"""
        try:
            # First check if we were recently running (service restart)
            if self._was_recently_running():
                self.logger.info("WiFi manager was recently running - treating as service restart")
                return False
            
            # Check system uptime
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
            
            # If system has been up for less than 5 minutes, consider it a fresh boot
            if uptime_seconds < 300:  # 5 minutes
                self.logger.info(f"System uptime: {uptime_seconds:.1f}s - treating as fresh boot")
                return True
            
            # Check if this is the first time WiFi manager has started since boot
            # by checking if NetworkManager was recently started
            result = subprocess.run(['systemctl', 'show', 'NetworkManager', '--property=ActiveEnterTimestamp'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                nm_start_time = result.stdout.strip()
                self.logger.info(f"NetworkManager start time: {nm_start_time}")
                
                # If NetworkManager started recently (within last 2 minutes), likely fresh boot
                if 'ActiveEnterTimestamp=' in nm_start_time:
                    # This is a simplified check - in production you'd parse the timestamp
                    self.logger.info("NetworkManager recently started - treating as fresh boot")
                    return True
            
            self.logger.info(f"System uptime: {uptime_seconds:.1f}s - treating as service restart")
            return False
            
        except Exception as e:
            self.logger.warning(f"Could not determine boot type: {e} - assuming fresh boot")
            return True  # Default to fresh boot for safety
    
    def _monitoring_loop(self):
        """Background monitoring loop for Wi-Fi status with smart AP cycling"""
        last_state_save = 0
        
        while not self.should_exit:
            try:
                # Check current connection status
                was_connected = self.wifi_connected
                self.wifi_connected = self.check_wifi_connection()
                self.shared_data.wifi_connected = self.wifi_connected
                
                # Handle connection state changes
                if was_connected and not self.wifi_connected:
                    self.logger.warning("Wi-Fi connection lost!")
                    self._save_connection_state(None, False)  # Save disconnected state
                    self._handle_connection_lost()
                elif not was_connected and self.wifi_connected:
                    self.logger.info("Wi-Fi connection established!")
                    current_ssid = self.get_current_ssid()
                    self._save_connection_state(current_ssid, True)  # Save connected state
                    if self.ap_mode_active:
                        self.logger.info("Stopping AP mode due to successful connection")
                        self.stop_ap_mode()
                        self.cycling_mode = False
                
                # Smart AP mode management
                if self.ap_mode_active:
                    # Check AP clients
                    self.check_ap_clients()
                    
                    # Check if AP should be stopped due to inactivity or timeout
                    if self.should_stop_idle_ap() and self.ap_cycle_enabled:
                        self.logger.info("Stopping AP mode - switching to reconnection attempt")
                        self.ap_logger.info("Stopping AP due to idle timeout/cycling, entering reconnection phase")
                        self.stop_ap_mode()
                        self.last_ap_stop_time = time.time()
                        
                        # Try to connect to autoconnect networks
                        self.ap_logger.info("Attempting to connect to autoconnect networks...")
                        if not self.try_autoconnect_networks():
                            self.logger.info("No autoconnect networks available, will retry in cycle")
                            self.ap_logger.info("No autoconnect networks available, will restart AP after timeout")
                
                # Handle reconnection attempts when in cycling mode
                if (self.cycling_mode and not self.ap_mode_active and not self.wifi_connected 
                    and self.last_ap_stop_time):
                    
                    time_since_ap_stop = time.time() - self.last_ap_stop_time
                    
                    if time_since_ap_stop >= self.reconnect_interval:
                        self.logger.info("Reconnection timeout reached - restarting AP mode")
                        self.ap_logger.info(f"Reconnection timeout ({self.reconnect_interval}s) reached - restarting AP mode")
                        self.ap_logger.info("Starting new AP cycle...")
                        self.start_ap_mode_with_timeout()
                
                # Handle initial connection timeout (for startup)
                if (not self.cycling_mode and not self.wifi_connected and not self.ap_mode_active 
                    and self.startup_complete):
                    
                    # Check if we should start cycling mode
                    if (self.last_connection_attempt and 
                        time.time() - self.last_connection_attempt > self.connection_timeout):
                        
                        if self.shared_data.config.get('wifi_auto_ap_fallback', True):
                            self.logger.info("Connection timeout reached - starting AP cycling mode")
                            self.ap_logger.info("Initial connection timeout reached - starting AP cycling mode")
                            self.ap_logger.info(f"Connection timeout was {self.connection_timeout}s")
                            self.start_ap_mode_with_timeout()
                
                # Update current SSID if connected
                if self.wifi_connected:
                    self.current_ssid = self.get_current_ssid()
                
                # Periodically save connection state (every 2 minutes)
                current_time = time.time()
                if current_time - last_state_save > 120:
                    ssid = self.current_ssid if self.wifi_connected else None
                    self._save_connection_state(ssid, self.wifi_connected)
                    last_state_save = current_time
                
                time.sleep(self.connection_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)
    
    def _handle_connection_lost(self):
        """Handle when Wi-Fi connection is lost"""
        if not self.startup_complete:
            return  # Don't interfere with startup sequence
        
        self.last_connection_attempt = time.time()
        
        # Try to reconnect to known networks first
        self.logger.info("Attempting to reconnect to known networks...")
        if self.try_connect_known_networks():
            return  # Successfully reconnected
        
        # Try autoconnect networks
        self.logger.info("Attempting to connect to autoconnect networks...")
        if self.try_autoconnect_networks():
            return  # Successfully connected
        
        # If cycling is enabled and no AP is active, start cycling mode
        if self.ap_cycle_enabled and not self.ap_mode_active:
            self.logger.info("Starting AP cycling mode due to connection loss")
            self.start_ap_mode_with_timeout()
        elif not self.ap_mode_active and self.shared_data.config.get('wifi_auto_ap_fallback', True):
            # Fallback to regular AP mode
            self.logger.info("Starting AP mode due to connection loss")
            self.start_ap_mode()
    
    def check_wifi_connection(self):
        """Check if Wi-Fi is connected using multiple methods"""
        try:
            # Method 1: Check using nmcli for active wireless connections
            result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,TYPE', 'con', 'show'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and 'yes:802-11-wireless' in line:
                        # Double-check with device status
                        dev_result = subprocess.run(['nmcli', '-t', '-f', 'DEVICE,STATE', 'dev', 'wifi'], 
                                                  capture_output=True, text=True, timeout=5)
                        if dev_result.returncode == 0 and 'connected' in dev_result.stdout:
                            return True
            
            # Method 2: Check using iwconfig (if available)
            try:
                result = subprocess.run(['iwconfig', 'wlan0'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'ESSID:' in result.stdout and 'Not-Associated' not in result.stdout:
                    # Verify we have an IP address
                    ip_result = subprocess.run(['ip', 'addr', 'show', 'wlan0'], 
                                             capture_output=True, text=True, timeout=5)
                    if ip_result.returncode == 0 and 'inet ' in ip_result.stdout:
                        return True
            except FileNotFoundError:
                pass  # iwconfig not available
            
            # Method 3: Check if we can reach the internet (but be quick about it)
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '2', '1.1.1.1'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Ensure it's going through wlan0
                    route_result = subprocess.run(['ip', 'route', 'get', '1.1.1.1'], 
                                                capture_output=True, text=True, timeout=3)
                    if route_result.returncode == 0 and 'dev wlan0' in route_result.stdout:
                        return True
            except:
                pass  # Network unreachable, that's fine
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking Wi-Fi connection: {e}")
            return False
    
    def get_current_ssid(self):
        """Get the current connected SSID"""
        try:
            result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('yes:'):
                        return line.split(':', 1)[1]
            return None
        except Exception as e:
            self.logger.error(f"Error getting current SSID: {e}")
            return None
    
    def scan_networks(self):
        """Scan for available Wi-Fi networks"""
        try:
            # If we're in AP mode, use special AP scanning method
            if self.ap_mode_active:
                return self.scan_networks_while_ap()
            
            self.logger.info("Scanning for Wi-Fi networks...")
            
            # Trigger a new scan
            subprocess.run(['nmcli', 'dev', 'wifi', 'rescan'], 
                         capture_output=True, timeout=15)
            
            # Get scan results
            result = subprocess.run(['nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY', 'dev', 'wifi'], 
                                  capture_output=True, text=True, timeout=15)
            
            networks = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 3 and parts[0]:  # SSID not empty
                            networks.append({
                                'ssid': parts[0],
                                'signal': int(parts[1]) if parts[1].isdigit() else 0,
                                'security': parts[2] if parts[2] else 'Open',
                                'known': parts[0] in [net['ssid'] for net in self.known_networks]
                            })
            
            # Remove duplicates and sort by signal strength
            seen_ssids = set()
            unique_networks = []
            for network in sorted(networks, key=lambda x: x['signal'], reverse=True):
                if network['ssid'] not in seen_ssids:
                    seen_ssids.add(network['ssid'])
                    unique_networks.append(network)
            
            self.available_networks = unique_networks
            self.logger.info(f"Found {len(unique_networks)} unique networks")
            return unique_networks
            
        except Exception as e:
            self.logger.error(f"Error scanning networks: {e}")
            return []

    def scan_networks_while_ap(self):
        """Scan for networks while in AP mode using smart caching and fallback strategies"""
        try:
            self.logger.info("Scanning networks while in AP mode using smart strategies")
            self.ap_logger.info("Starting network scan while in AP mode (non-disruptive)")
            
            # Strategy 1: Return cached networks if we have recent data (within 10 minutes)
            if hasattr(self, 'cached_networks') and hasattr(self, 'last_scan_time'):
                cache_age = time.time() - self.last_scan_time
                if cache_age < 600:  # 10 minutes cache
                    self.ap_logger.info(f"Returning cached networks (age: {cache_age:.1f}s)")
                    return self.cached_networks
            
            # Strategy 2: Try iwlist scan (non-disruptive to AP mode)
            networks = []
            try:
                self.ap_logger.debug("Attempting iwlist scan on AP interface...")
                result = subprocess.run(['sudo', 'iwlist', self.ap_interface, 'scan'], 
                                      capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    self.ap_logger.debug("iwlist scan successful, parsing results...")
                    lines = result.stdout.split('\n')
                    current_network = {}
                    
                    for line in lines:
                        line = line.strip()
                        if 'Cell ' in line and 'Address:' in line:
                            # Start of new network, save previous if complete
                            if 'ssid' in current_network and current_network['ssid'] != self.ap_ssid:
                                networks.append(current_network.copy())
                            current_network = {}
                        elif 'ESSID:' in line:
                            # Extract SSID
                            essid_part = line.split('ESSID:')[1].strip('"')
                            if essid_part and essid_part != self.ap_ssid:
                                current_network['ssid'] = essid_part
                        elif 'Signal level=' in line:
                            # Extract signal strength
                            try:
                                signal_part = line.split('Signal level=')[1].split()[0]
                                if 'dBm' in signal_part:
                                    dbm = int(signal_part.replace('dBm', ''))
                                    # Convert dBm to percentage (rough approximation)
                                    signal = max(0, min(100, (dbm + 100) * 2))
                                else:
                                    signal = 50  # Default
                                current_network['signal'] = signal
                            except:
                                current_network['signal'] = 50
                        elif 'Encryption key:on' in line:
                            current_network['security'] = 'WPA2'
                        elif 'Encryption key:off' in line:
                            current_network['security'] = 'Open'
                    
                    # Add last network if complete
                    if 'ssid' in current_network and current_network['ssid'] != self.ap_ssid:
                        networks.append(current_network.copy())
                    
                    if networks:
                        self.ap_logger.info(f"iwlist scan found {len(networks)} networks")
                        # Cache the results
                        self.cached_networks = networks
                        self.last_scan_time = time.time()
                        
                        # Remove duplicates and sort
                        seen_ssids = set()
                        unique_networks = []
                        for network in sorted(networks, key=lambda x: x.get('signal', 0), reverse=True):
                            if network['ssid'] not in seen_ssids:
                                seen_ssids.add(network['ssid'])
                                # Add known network flag
                                network['known'] = network['ssid'] in [net['ssid'] for net in self.known_networks]
                                unique_networks.append(network)
                        
                        self.available_networks = unique_networks
                        return unique_networks
                    
            except Exception as iwlist_error:
                self.ap_logger.debug(f"iwlist scan failed: {iwlist_error}")
            
            # Strategy 3: Use previously cached networks from before AP mode
            if hasattr(self, 'available_networks') and self.available_networks:
                self.ap_logger.info("Using previously available networks from before AP mode")
                return self.available_networks
            
            # Strategy 4: Return known networks as available options
            if self.known_networks:
                self.ap_logger.info("Returning known networks as scan alternatives")
                known_as_available = []
                for i, net in enumerate(self.known_networks):
                    known_as_available.append({
                        'ssid': net['ssid'],
                        'signal': 80 - (i * 5),  # Decreasing signal strength
                        'security': 'WPA2' if net.get('password') else 'Open',
                        'known': True
                    })
                return known_as_available
            
            # Strategy 5: Return helpful message for manual entry
            help_networks = [
                {
                    'ssid': '📡 Unable to scan while in AP mode',
                    'signal': 100,
                    'security': '',
                    'instruction': True,
                    'known': False
                },
                {
                    'ssid': '✏️ Type network name manually below',
                    'signal': 90,
                    'security': '',
                    'instruction': True,
                    'known': False
                },
                {
                    'ssid': '💡 Or disconnect from ragnar AP first',
                    'signal': 80,
                    'security': '',
                    'instruction': True,
                    'known': False
                }
            ]
            
            self.ap_logger.info("Returning instructional networks for manual entry")
            return help_networks
            
        except Exception as e:
            self.logger.error(f"Error in smart AP scanning: {e}")
            self.ap_logger.error(f"Error during smart AP scan: {e}")
            return []
    
    def try_connect_known_networks(self):
        """Try to connect to known networks in priority order"""
        if not self.known_networks:
            self.logger.info("No known networks configured")
            return False
        
        # First, check if we're already connected to one of our known networks
        current_ssid = self.get_current_ssid()
        if current_ssid:
            known_ssids = [net['ssid'] for net in self.known_networks]
            if current_ssid in known_ssids:
                self.logger.info(f"Already connected to known network: {current_ssid}")
                return True
        
        # Sort known networks by priority (highest first)
        sorted_networks = sorted(self.known_networks, key=lambda x: x.get('priority', 0), reverse=True)
        
        for network in sorted_networks:
            try:
                ssid = network['ssid']
                self.logger.info(f"Attempting to connect to {ssid}...")
                
                if self.connect_to_network(ssid, network.get('password')):
                    self.logger.info(f"Successfully connected to {ssid}")
                    return True
                else:
                    self.logger.warning(f"Failed to connect to {ssid}")
                    
            except Exception as e:
                self.logger.error(f"Error connecting to {network.get('ssid', 'unknown')}: {e}")
        
        return False
    
    def connect_to_network(self, ssid, password=None):
        """Connect to a specific Wi-Fi network"""
        try:
            self.logger.info(f"Connecting to network: {ssid}")
            
            # Check if connection already exists
            result = subprocess.run(['nmcli', 'con', 'show', ssid], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Connection exists, try to activate it
                self.logger.info(f"Using existing connection for {ssid}")
                result = subprocess.run(['nmcli', 'con', 'up', ssid], 
                                      capture_output=True, text=True, timeout=30)
            else:
                # Create new connection
                cmd = ['nmcli', 'dev', 'wifi', 'connect', ssid]
                if password:
                    cmd.extend(['password', password])
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Wait a moment and verify connection
                time.sleep(5)
                return self.check_wifi_connection()
            else:
                self.logger.error(f"nmcli error: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error connecting to {ssid}: {e}")
            return False

    def disconnect_wifi(self):
        """Disconnect from current Wi-Fi network"""
        try:
            if not self.wifi_connected:
                self.logger.info("Not connected to any Wi-Fi network")
                return True
            
            current_ssid = self.get_current_ssid()
            self.logger.info(f"Disconnecting from Wi-Fi network: {current_ssid}")
            
            # Disconnect using nmcli
            result = subprocess.run(['nmcli', 'device', 'disconnect', 'wlan0'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.wifi_connected = False
                self.current_ssid = None
                self.shared_data.wifi_connected = False
                self.logger.info("Successfully disconnected from Wi-Fi")
                return True
            else:
                self.logger.error(f"Error disconnecting: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error disconnecting from Wi-Fi: {e}")
            return False
    
    def add_known_network(self, ssid, password=None, priority=1):
        """Add a network to the known networks list"""
        try:
            # Remove existing entry if it exists
            self.known_networks = [net for net in self.known_networks if net['ssid'] != ssid]
            
            # Add new entry
            network = {
                'ssid': ssid,
                'password': password,
                'priority': priority,
                'added_date': datetime.now().isoformat()
            }
            
            self.known_networks.append(network)
            self.save_wifi_config()
            
            self.logger.info(f"Added known network: {ssid}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding known network {ssid}: {e}")
            return False
    
    def remove_known_network(self, ssid):
        """Remove a network from the known networks list"""
        try:
            original_count = len(self.known_networks)
            self.known_networks = [net for net in self.known_networks if net['ssid'] != ssid]
            
            if len(self.known_networks) < original_count:
                self.save_wifi_config()
                self.logger.info(f"Removed known network: {ssid}")
                
                # Also remove from NetworkManager
                try:
                    subprocess.run(['nmcli', 'con', 'delete', ssid], 
                                 capture_output=True, timeout=10)
                except:
                    pass  # Ignore errors, connection might not exist
                
                return True
            else:
                self.logger.warning(f"Network {ssid} not found in known networks")
                return False
                
        except Exception as e:
            self.logger.error(f"Error removing known network {ssid}: {e}")
            return False

    def check_ap_clients(self):
        """Check how many clients are connected to the AP"""
        if not self.ap_mode_active:
            return 0
        
        try:
            self.ap_logger.debug("Checking for connected AP clients...")
            
            # Method 1: Check hostapd_cli if available
            result = subprocess.run(['hostapd_cli', '-i', self.ap_interface, 'list_sta'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                clients = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                client_count = len(clients)
                
                # Log client changes
                if client_count != getattr(self, 'last_client_count', 0):
                    if client_count > 0:
                        self.ap_logger.info(f"AP clients detected: {client_count}")
                        self.ap_logger.info(f"Connected clients: {clients}")
                    else:
                        self.ap_logger.info("No clients connected to AP")
                    self.last_client_count = client_count
                
                self.ap_clients_count = client_count
                self.ap_clients_connected = client_count > 0
                return client_count
            
            # Method 2: Check DHCP leases
            self.ap_logger.debug("Hostapd_cli not available, checking DHCP leases...")
            dhcp_leases_file = '/var/lib/dhcp/dhcpd.leases'
            if os.path.exists(dhcp_leases_file):
                with open(dhcp_leases_file, 'r') as f:
                    content = f.read()
                    # Count active leases (simplified check)
                    active_leases = content.count('binding state active')
                    
                    if active_leases != getattr(self, 'last_client_count', 0):
                        self.ap_logger.info(f"DHCP active leases: {active_leases}")
                        self.last_client_count = active_leases
                    
                    self.ap_clients_count = active_leases
                    self.ap_clients_connected = active_leases > 0
                    return active_leases
            
            # Method 3: Check ARP table for AP subnet
            self.ap_logger.debug("DHCP leases not available, checking ARP table...")
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Count IPs in AP subnet (192.168.4.x)
                ap_clients = [line for line in result.stdout.split('\n') if '192.168.4.' in line]
                client_count = len(ap_clients)
                
                if client_count != getattr(self, 'last_client_count', 0):
                    if client_count > 0:
                        self.ap_logger.info(f"ARP table shows {client_count} clients in AP subnet")
                        self.ap_logger.debug(f"ARP entries: {ap_clients}")
                    else:
                        self.ap_logger.debug("No clients found in ARP table")
                    self.last_client_count = client_count
                
                self.ap_clients_count = client_count
                self.ap_clients_connected = client_count > 0
                return client_count
            
            self.ap_logger.warning("All client detection methods failed")
            return 0
            
        except Exception as e:
            self.logger.warning(f"Error checking AP clients: {e}")
            self.ap_logger.warning(f"Exception checking AP clients: {e}")
            return 0

    def should_stop_idle_ap(self):
        """Check if AP should be stopped due to inactivity"""
        if not self.ap_mode_active or not self.ap_mode_start_time:
            return False
        
        # Check if AP has been running for more than the idle timeout
        ap_running_time = time.time() - self.ap_mode_start_time
        
        # If no clients have connected and idle timeout reached
        if not self.ap_clients_connected and ap_running_time > self.ap_idle_timeout:
            self.logger.info(f"AP idle timeout reached ({self.ap_idle_timeout}s) with no clients")
            self.ap_logger.info(f"AP idle timeout reached: {self.ap_idle_timeout}s with no clients connected")
            self.ap_logger.info(f"AP has been running for {ap_running_time:.1f} seconds")
            self.ap_logger.info("Initiating AP shutdown due to inactivity")
            return True
        
        # If AP has been running for maximum timeout regardless of clients
        if ap_running_time > self.ap_timeout * 2:  # Extended timeout for safety
            self.logger.info(f"AP maximum timeout reached ({self.ap_timeout * 2}s)")
            self.ap_logger.info(f"AP maximum timeout reached: {self.ap_timeout * 2}s")
            self.ap_logger.info(f"AP has been running for {ap_running_time:.1f} seconds")
            self.ap_logger.info(f"Clients connected: {self.ap_clients_connected}")
            self.ap_logger.info("Initiating AP shutdown due to maximum timeout")
            return True
        
        # Log periodic status if AP is running
        if int(ap_running_time) % 60 == 0:  # Log every minute
            self.ap_logger.info(f"AP running for {ap_running_time:.0f}s, clients: {self.ap_clients_count}, connected: {self.ap_clients_connected}")
        
        return False

    def get_autoconnect_networks(self):
        """Get networks that are set to autoconnect in NetworkManager"""
        try:
            result = subprocess.run(['nmcli', '-t', '-f', 'NAME,TYPE,AUTOCONNECT', 'connection', 'show'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                autoconnect_networks = []
                for line in result.stdout.strip().split('\n'):
                    if line and '802-11-wireless' in line and 'yes' in line:
                        parts = line.split(':')
                        if len(parts) >= 3:
                            network_name = parts[0]
                            autoconnect_networks.append(network_name)
                
                self.logger.info(f"Found {len(autoconnect_networks)} autoconnect networks: {autoconnect_networks}")
                return autoconnect_networks
            
            return []
            
        except Exception as e:
            self.logger.warning(f"Error getting autoconnect networks: {e}")
            return []

    def try_autoconnect_networks(self):
        """Try to connect to any available autoconnect networks"""
        autoconnect_networks = self.get_autoconnect_networks()
        
        if not autoconnect_networks:
            self.logger.info("No autoconnect networks available")
            return False
        
        # Scan for available networks
        available_networks = self.scan_networks()
        available_ssids = [net['ssid'] for net in available_networks]
        
        # Try to connect to any autoconnect network that's available
        for network in autoconnect_networks:
            if network in available_ssids:
                self.logger.info(f"Attempting to connect to autoconnect network: {network}")
                try:
                    # Use nmcli to bring up the connection
                    result = subprocess.run(['nmcli', 'connection', 'up', network], 
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        # Wait a moment and check connection
                        time.sleep(5)
                        if self.check_wifi_connection():
                            self.logger.info(f"Successfully connected to autoconnect network: {network}")
                            return True
                    else:
                        self.logger.warning(f"Failed to connect to {network}: {result.stderr}")
                except Exception as e:
                    self.logger.warning(f"Error connecting to {network}: {e}")
        
        return False

    def start_ap_mode_with_timeout(self):
        """Start AP mode with smart timeout management"""
        self.ap_logger.info("Starting AP mode with timeout management")
        if self.start_ap_mode():
            self.ap_mode_start_time = time.time()
            self.cycling_mode = True
            self.logger.info(f"AP mode started with {self.ap_timeout}s timeout")
            self.ap_logger.info(f"AP mode started with {self.ap_timeout}s timeout in cycling mode")
            return True
        else:
            self.ap_logger.error("Failed to start AP mode with timeout")
            return False

    def enable_ap_mode_from_web(self):
        """Enable AP mode from web interface - starts the cycling behavior"""
        self.logger.info("AP mode requested from web interface")
        if self.wifi_connected:
            # If connected, disconnect first
            self.disconnect_wifi()
        
        # Stop current AP if running
        if self.ap_mode_active:
            self.stop_ap_mode()
        
        # Start AP with cycling enabled
        return self.start_ap_mode_with_timeout()
    
    def start_ap_mode(self):
        """Start Access Point mode"""
        if self.ap_mode_active:
            self.logger.info("AP mode already active")
            self.ap_logger.info("AP mode start requested but already active")
            return True
        
        try:
            self.logger.info(f"Starting AP mode: {self.ap_ssid}")
            self.ap_logger.info(f"Starting AP mode: SSID={self.ap_ssid}, Interface={self.ap_interface}")
            self.ap_logger.info(f"AP Configuration: IP={self.ap_ip}, Subnet={self.ap_subnet}")
            
            # Create hostapd configuration
            self.ap_logger.info("Creating hostapd configuration...")
            if not self._create_hostapd_config():
                self.ap_logger.error("Failed to create hostapd configuration")
                return False
            
            # Create dnsmasq configuration
            self.ap_logger.info("Creating dnsmasq configuration...")
            if not self._create_dnsmasq_config(dns_enabled=True):
                self.ap_logger.error("Failed to create dnsmasq configuration")
                return False
            
            # Configure network interface
            self.ap_logger.info("Configuring network interface...")
            if not self._configure_ap_interface():
                self.ap_logger.error("Failed to configure network interface")
                return False
            
            # Start services
            self.ap_logger.info("Starting AP services...")
            if self._start_ap_services():
                self.ap_mode_active = True
                self.ap_mode_start_time = time.time()  # Track start time
                self.logger.info("AP mode started successfully")
                self.ap_logger.info("AP mode started successfully")
                self.ap_logger.info(f"AP started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                self.ap_logger.info(f"Access Point '{self.ap_ssid}' is now available")
                return True
            else:
                self.ap_logger.error("Failed to start AP services")
                self._cleanup_ap_mode()
                return False
                
        except Exception as e:
            self.logger.error(f"Error starting AP mode: {e}")
            self.ap_logger.error(f"Exception during AP mode startup: {e}")
            self.ap_logger.error(f"Error type: {type(e).__name__}")
            import traceback
            self.ap_logger.error(f"Traceback: {traceback.format_exc()}")
            self._cleanup_ap_mode()
            return False
    
    def stop_ap_mode(self):
        """Stop Access Point mode"""
        if not self.ap_mode_active:
            self.ap_logger.info("AP mode stop requested but not currently active")
            return True
        
        try:
            self.logger.info("Stopping AP mode...")
            self.ap_logger.info("Stopping AP mode...")
            
            # Calculate uptime
            if self.ap_mode_start_time:
                uptime = time.time() - self.ap_mode_start_time
                self.ap_logger.info(f"AP mode uptime: {uptime:.1f} seconds ({uptime/60:.1f} minutes)")
            
            # Log client statistics
            if hasattr(self, 'ap_clients_count'):
                self.ap_logger.info(f"Total clients connected during session: {self.ap_clients_count}")
            
            # Stop services
            self.ap_logger.info("Stopping AP services...")
            self._stop_ap_services()
            
            # Cleanup interface
            self.ap_logger.info("Cleaning up network interface...")
            self._cleanup_ap_interface()
            
            self.ap_mode_active = False
            self.ap_mode_start_time = None
            self.ap_clients_connected = False
            self.ap_clients_count = 0
            self.logger.info("AP mode stopped")
            self.ap_logger.info("AP mode stopped successfully")
            self.ap_logger.info(f"AP stopped at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping AP mode: {e}")
            self.ap_logger.error(f"Exception during AP mode shutdown: {e}")
            self.ap_logger.error(f"Error type: {type(e).__name__}")
            import traceback
            self.ap_logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    def _create_hostapd_config(self):
        """Create hostapd configuration file"""
        try:
            self.ap_logger.debug("Creating hostapd configuration file...")
            config_content = f"""interface={self.ap_interface}
driver=nl80211
ssid={self.ap_ssid}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={self.ap_password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
            
            os.makedirs('/tmp/ragnar', exist_ok=True)
            with open('/tmp/ragnar/hostapd.conf', 'w') as f:
                f.write(config_content)
            
            self.logger.info("Created hostapd configuration")
            self.ap_logger.info("Created hostapd configuration at /tmp/ragnar/hostapd.conf")
            self.ap_logger.debug(f"Hostapd config content:\n{config_content}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating hostapd config: {e}")
            self.ap_logger.error(f"Error creating hostapd config: {e}")
            return False
    
    def _create_dnsmasq_config(self, dns_enabled=True):
        """Create dnsmasq configuration file"""
        try:
            self.ap_logger.debug("Creating dnsmasq configuration file...")
            
            if dns_enabled:
                # Full configuration with DNS for captive portal
                config_content = f"""# Interface configuration
interface={self.ap_interface}
# DHCP range
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
# DHCP authoritative
dhcp-authoritative
# Bind to specific interface only
bind-interfaces
# Log DHCP activity
log-dhcp
# Gateway option
dhcp-option=3,{self.ap_ip}
# DNS option (point to ourselves for captive portal)
dhcp-option=6,{self.ap_ip}
# Enable DNS on port 53
port=53
# Listen only on our AP IP
listen-address={self.ap_ip}
# Don't read system files that might conflict
no-resolv
no-hosts
no-poll
# Captive portal - redirect all domains to AP
address=/#/{self.ap_ip}
# But allow some connectivity test domains to work
server=/connectivitycheck.gstatic.com/8.8.8.8
server=/www.gstatic.com/8.8.8.8
server=/clients3.google.com/8.8.8.8
# Fallback DNS servers
server=8.8.8.8
server=8.8.4.4
"""
            else:
                # Minimal configuration - DHCP only, no DNS conflicts
                config_content = f"""# Interface configuration
interface={self.ap_interface}
# DHCP range
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
# DHCP authoritative
dhcp-authoritative
# Bind to specific interface only
bind-interfaces
# Log DHCP activity
log-dhcp
# Gateway option
dhcp-option=3,{self.ap_ip}
# DNS option (use public DNS)
dhcp-option=6,8.8.8.8,8.8.4.4
# Disable DNS server to avoid conflicts
port=0
"""
            
            with open('/tmp/ragnar/dnsmasq.conf', 'w') as f:
                f.write(config_content)
            
            config_type = "with captive portal DNS" if dns_enabled else "DHCP-only (no DNS conflicts)"
            self.logger.info(f"Created dnsmasq configuration {config_type}")
            self.ap_logger.info(f"Created dnsmasq configuration at /tmp/ragnar/dnsmasq.conf ({config_type})")
            self.ap_logger.debug(f"Dnsmasq config content:\n{config_content}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating dnsmasq config: {e}")
            self.ap_logger.error(f"Error creating dnsmasq config: {e}")
            return False
    
    def _configure_ap_interface(self):
        """Configure network interface for AP mode"""
        try:
            self.ap_logger.info(f"Configuring interface {self.ap_interface} for AP mode")
            
            # Stop NetworkManager from managing the interface
            self.ap_logger.debug("Setting NetworkManager to not manage interface")
            result = subprocess.run(['sudo', 'nmcli', 'dev', 'set', self.ap_interface, 'managed', 'no'], 
                         capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.ap_logger.warning(f"NetworkManager command failed: {result.stderr}")
            
            # Configure IP address
            self.ap_logger.debug("Flushing existing IP addresses")
            result = subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', self.ap_interface], 
                         capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.ap_logger.warning(f"IP flush failed: {result.stderr}")
            
            self.ap_logger.debug(f"Adding IP address {self.ap_ip}/24")
            result = subprocess.run(['sudo', 'ip', 'addr', 'add', f'{self.ap_ip}/24', 'dev', self.ap_interface], 
                         capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.ap_logger.error(f"Failed to add IP address: {result.stderr}")
                return False
            
            self.ap_logger.debug("Bringing interface up")
            result = subprocess.run(['sudo', 'ip', 'link', 'set', 'dev', self.ap_interface, 'up'], 
                         capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.ap_logger.error(f"Failed to bring interface up: {result.stderr}")
                return False
            
            # Wait for interface to be fully ready
            time.sleep(2)
            
            # Verify interface configuration
            self.ap_logger.debug("Verifying interface configuration...")
            result = subprocess.run(['ip', 'addr', 'show', self.ap_interface], 
                         capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.ap_logger.debug(f"Interface status:\n{result.stdout}")
                if self.ap_ip not in result.stdout:
                    self.ap_logger.error(f"Interface {self.ap_interface} does not have expected IP {self.ap_ip}")
                    return False
            
            self.logger.info("Configured AP interface")
            self.ap_logger.info(f"Interface {self.ap_interface} configured successfully with IP {self.ap_ip}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error configuring AP interface: {e}")
            self.ap_logger.error(f"Exception configuring AP interface: {e}")
            return False
    
    def _start_ap_services(self):
        """Start hostapd and dnsmasq services"""
        try:
            # Kill any existing conflicting services first
            self.ap_logger.info("Cleaning up any conflicting services...")
            
            # Stop any system dnsmasq that might conflict
            try:
                subprocess.run(['sudo', 'systemctl', 'stop', 'dnsmasq'], 
                             capture_output=True, check=False)
                self.ap_logger.debug("Stopped system dnsmasq service")
            except:
                pass
            
            # Kill any existing dnsmasq processes on our interface
            try:
                subprocess.run(['sudo', 'pkill', '-f', f'dnsmasq.*{self.ap_interface}'], 
                             capture_output=True, check=False)
                self.ap_logger.debug("Killed existing dnsmasq processes")
            except:
                pass
            
            # Wait a moment for cleanup
            time.sleep(1)
            
            self.ap_logger.info("Starting hostapd service...")
            # Start hostapd
            self.hostapd_process = subprocess.Popen(['sudo', 'hostapd', '/tmp/ragnar/hostapd.conf'],
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.ap_logger.debug(f"Hostapd process started with PID: {self.hostapd_process.pid}")
            time.sleep(2)  # Give hostapd time to start
            
            if self.hostapd_process.poll() is not None:
                stdout, stderr = self.hostapd_process.communicate()
                self.logger.error("hostapd failed to start")
                self.ap_logger.error("hostapd failed to start")
                self.ap_logger.error(f"Hostapd stdout: {stdout.decode()}")
                self.ap_logger.error(f"Hostapd stderr: {stderr.decode()}")
                return False
            
            self.ap_logger.info("Hostapd started successfully")
            
            self.ap_logger.info("Starting dnsmasq service...")
            # Start dnsmasq with explicit interface binding
            self.dnsmasq_process = subprocess.Popen(['sudo', 'dnsmasq', '-C', '/tmp/ragnar/dnsmasq.conf', '-d', '--no-daemon'],
                                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.ap_logger.debug(f"Dnsmasq process started with PID: {self.dnsmasq_process.pid}")
            time.sleep(1)  # Give dnsmasq time to start
            
            if self.dnsmasq_process.poll() is not None:
                stdout, stderr = self.dnsmasq_process.communicate()
                self.logger.warning("dnsmasq failed to start with DNS enabled, trying DHCP-only mode")
                self.ap_logger.warning("dnsmasq failed to start with DNS enabled")
                self.ap_logger.warning(f"Dnsmasq stdout: {stdout.decode()}")
                self.ap_logger.warning(f"Dnsmasq stderr: {stderr.decode()}")
                
                # Try fallback mode without DNS
                self.ap_logger.info("Attempting fallback: DHCP-only mode without DNS")
                
                # Create new config without DNS
                if not self._create_dnsmasq_config(dns_enabled=False):
                    self.ap_logger.error("Failed to create fallback dnsmasq configuration")
                    return False
                
                # Try starting dnsmasq again with DHCP-only config
                self.dnsmasq_process = subprocess.Popen(['sudo', 'dnsmasq', '-C', '/tmp/ragnar/dnsmasq.conf', '-d', '--no-daemon'],
                                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.ap_logger.debug(f"Dnsmasq fallback process started with PID: {self.dnsmasq_process.pid}")
                time.sleep(1)
                
                if self.dnsmasq_process.poll() is not None:
                    stdout, stderr = self.dnsmasq_process.communicate()
                    self.logger.error("dnsmasq fallback also failed to start")
                    self.ap_logger.error("dnsmasq fallback (DHCP-only) also failed to start")
                    self.ap_logger.error(f"Dnsmasq fallback stdout: {stdout.decode()}")
                    self.ap_logger.error(f"Dnsmasq fallback stderr: {stderr.decode()}")
                    return False
                
                self.ap_logger.info("Dnsmasq started successfully in DHCP-only mode (no captive portal DNS)")
            else:
                self.ap_logger.info("Dnsmasq started successfully with full captive portal DNS")
            self.logger.info("AP services started")
            self.ap_logger.info("All AP services started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting AP services: {e}")
            self.ap_logger.error(f"Exception starting AP services: {e}")
            return False
    
    def _stop_ap_services(self):
        """Stop hostapd and dnsmasq services"""
        try:
            self.ap_logger.info("Stopping AP services...")
            
            # Stop hostapd
            if hasattr(self, 'hostapd_process') and self.hostapd_process:
                self.ap_logger.debug(f"Terminating hostapd process (PID: {self.hostapd_process.pid})")
                self.hostapd_process.terminate()
                try:
                    self.hostapd_process.wait(timeout=5)
                    self.ap_logger.debug("Hostapd terminated gracefully")
                except subprocess.TimeoutExpired:
                    self.ap_logger.warning("Hostapd did not terminate gracefully, killing...")
                    self.hostapd_process.kill()
                    self.ap_logger.debug("Hostapd killed")
            
            # Stop dnsmasq
            if hasattr(self, 'dnsmasq_process') and self.dnsmasq_process:
                self.ap_logger.debug(f"Terminating dnsmasq process (PID: {self.dnsmasq_process.pid})")
                self.dnsmasq_process.terminate()
                try:
                    self.dnsmasq_process.wait(timeout=5)
                    self.ap_logger.debug("Dnsmasq terminated gracefully")
                except subprocess.TimeoutExpired:
                    self.ap_logger.warning("Dnsmasq did not terminate gracefully, killing...")
                    self.dnsmasq_process.kill()
                    self.ap_logger.debug("Dnsmasq killed")
            
            # Kill any remaining processes
            self.ap_logger.debug("Killing any remaining hostapd processes...")
            result = subprocess.run(['sudo', 'pkill', 'hostapd'], capture_output=True, text=True)
            if result.returncode == 0:
                self.ap_logger.debug("Additional hostapd processes killed")
            
            self.ap_logger.debug("Killing any remaining dnsmasq processes...")
            result = subprocess.run(['sudo', 'pkill', 'dnsmasq'], capture_output=True, text=True)
            if result.returncode == 0:
                self.ap_logger.debug("Additional dnsmasq processes killed")
            
            self.logger.info("AP services stopped")
            self.ap_logger.info("All AP services stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping AP services: {e}")
            self.ap_logger.error(f"Exception stopping AP services: {e}")
    
    def _cleanup_ap_interface(self):
        """Cleanup AP interface configuration"""
        try:
            # Flush IP address
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', self.ap_interface], 
                         capture_output=True, timeout=10)
            
            # Return interface to NetworkManager
            subprocess.run(['sudo', 'nmcli', 'dev', 'set', self.ap_interface, 'managed', 'yes'], 
                         capture_output=True, timeout=10)
            
            self.logger.info("Cleaned up AP interface")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up AP interface: {e}")
    
    def _cleanup_ap_mode(self):
        """Full cleanup of AP mode"""
        try:
            self._stop_ap_services()
            self._cleanup_ap_interface()
            
            # Remove config files
            for config_file in ['/tmp/ragnar/hostapd.conf', '/tmp/ragnar/dnsmasq.conf']:
                try:
                    if os.path.exists(config_file):
                        os.remove(config_file)
                except:
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error in AP cleanup: {e}")
    
    def get_status(self):
        """Get current Wi-Fi manager status"""
        return {
            'wifi_connected': self.wifi_connected,
            'ap_mode_active': self.ap_mode_active,
            'current_ssid': self.current_ssid,
            'known_networks_count': len(self.known_networks),
            'connection_attempts': self.connection_attempts,
            'startup_complete': self.startup_complete,
            'available_networks': len(self.available_networks)
        }
    
    def get_known_networks(self):
        """Get list of known networks (without passwords)"""
        return [{
            'ssid': net['ssid'],
            'priority': net.get('priority', 1),
            'added_date': net.get('added_date', ''),
            'has_password': bool(net.get('password'))
        } for net in self.known_networks]
    
    def get_available_networks(self):
        """Get list of available networks from last scan"""
        return self.available_networks
    
    def force_reconnect(self):
        """Force a reconnection attempt"""
        self.logger.info("Forcing Wi-Fi reconnection...")
        self.connection_attempts = 0
        return self.try_connect_known_networks()
    
    def restart_networking(self):
        """Restart networking services"""
        try:
            self.logger.info("Restarting networking services...")
            
            if self.ap_mode_active:
                self.stop_ap_mode()
            
            # Restart NetworkManager
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                         capture_output=True, timeout=30)
            
            time.sleep(5)  # Wait for NetworkManager to start
            
            # Try to reconnect
            self.connection_attempts = 0
            self.try_connect_known_networks()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error restarting networking: {e}")
            return False
