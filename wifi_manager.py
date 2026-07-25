# wifi_manager.py
# Features:
# - Auto-connect to known Wi-Fi networks on boot
# - Fall back to AP mode if connection fails 
# - Web interface for Wi-Fi configuration
# - Robust connection monitoring with proper timing
# - Network scanning and credential management
# - Integration with wpa_supplicant and NetworkManager
# - SQLite database caching for improved scan performance
# - Connection history tracking and analytics

import os
import time
import json
import subprocess
import threading
import logging
import re
import signal
from datetime import datetime, timedelta
from shared import detect_wifi_interface
from logger import Logger
from db_manager import get_db
from wifi_interfaces import gather_wifi_interfaces, get_active_ethernet_interface


class WiFiManager:
    """Manages Wi-Fi connections, AP mode, and configuration for Ragnar"""
    
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name="WiFiManager", level=logging.INFO)
        
        # Initialize database for WiFi caching and analytics
        try:
            self.db = get_db(currentdir=shared_data.currentdir)
            self.logger.info("WiFi database manager initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize WiFi database: {e}")
            self.db = None
        
        # Setup dedicated AP mode logging
        self.setup_ap_logger()
        
        # WiFi analytics tracking
        self.current_connection_id = None  # Track current connection for duration logging
        
        # State management
        self.wifi_connected = False
        self.ap_mode_active = False
        self.connection_attempts = 0
        self.last_connection_attempt = None
        self.connection_check_interval = 10  # Check every 10 seconds for responsive monitoring
        self.connection_timeout = shared_data.config.get('wifi_initial_connection_timeout', 120)  # 2 minutes initial wait
        self.max_connection_attempts = 3
        
        # Endless Loop Timing Configuration
        self.endless_loop_active = False
        self.endless_loop_start_time = None
        self.boot_completed_time = None
        self.wifi_search_timeout = 120  # 2 minutes to search for WiFi
        self.ap_mode_timeout = 180  # 3 minutes in AP mode
        self.wifi_validation_interval = 180  # 3 minutes between WiFi validations
        self.wifi_validation_retries = 5  # 5 validation attempts (changed from 3)
        self.wifi_validation_retry_interval = 10  # 10 seconds between validation retries
        # While parked in AP mode, how often to look for a known network again.
        # Tracked as "seconds since the last check" rather than by testing the
        # uptime against a multiple — the monitoring loop ticks on a ~10s sleep
        # plus however long the checks took, so it never lands on exact seconds.
        self.ap_reconnect_check_interval = 30
        self.last_ap_reconnect_check = 0.0
        # Settling time before an unattended box starts looking for its network
        # again. Short, because "unattended" is the whole precondition — the
        # case that needs protecting is a client connected to the AP, and that
        # is handled by its own check rather than by waiting out a clock.
        self.ap_recovery_grace = 30
        # Set by _check_known_networks_available: how many networks we could
        # rejoin at all, and when a non-disruptive scan last actually returned
        # results. Together they decide whether dropping the AP to hunt for a
        # network could ever pay off — see _handle_ap_mode_monitoring.
        self.known_networks_count = 0
        self.last_successful_scan = 0.0
        # How stale the last working scan must be before we stop trusting the
        # non-disruptive path and fall back to tearing the AP down to search.
        self.scan_trust_window = 300
        self.last_wifi_validation = None
        self.wifi_validation_failures = 0
        self.consecutive_validation_cycles_failed = 0  # Track consecutive full validation cycle failures
        
        # Smart AP mode management
        self.ap_mode_start_time = None
        self.ap_timeout = self.ap_mode_timeout  # Use endless loop timeout
        self.ap_idle_timeout = self.ap_mode_timeout  # 3 minutes in AP mode
        self.reconnect_interval = self.wifi_search_timeout  # 2 minutes to search for WiFi
        self.ap_cycle_enabled = True  # Always enable cycling for endless loop
        self.last_ap_stop_time = None
        self.ap_clients_connected = False
        self.ap_clients_count = 0
        self.cycling_mode = False  # Track if we're in AP/reconnect cycle
        self.user_connected_to_ap = False  # Track if user has connected to AP
        self.ap_user_connection_time = None  # When user connected to AP
        self.force_exit_ap_mode = False  # Flag to force exit AP mode from web interface
        
        # Network management
        self.known_networks = []
        self.available_networks = []
        self.default_wifi_interface = detect_wifi_interface(shared_data.config.get('wifi_default_interface', 'auto'))
        self.interface_scan_cache = {}
        self.interface_cache_time = {}
        self.last_scan_interface = None
        self.last_interface_reenable_time = 0
        self.interface_reenable_interval = shared_data.config.get('wifi_interface_reenable_interval', 30)
        self.current_ssid = None
        self._pending_ping_sweep_ssid = None
        self._ping_sweep_thread = None
        self._last_ping_sweep_time = 0
        self._last_ping_sweep_ssid = None
        self.ping_sweep_cooldown = shared_data.config.get('wifi_ping_sweep_cooldown', 120)

        # SSID-change debounce: a transient SSID misread (roaming, dual-band
        # flap, brief disconnect) used to flip the storage layer and trigger
        # mark_all_hosts_degraded(), wiping every alive host. Require the
        # NEW SSID to be observed consistently for this many seconds before
        # propagating to shared_data.set_active_network().
        self.ssid_change_debounce_s = shared_data.config.get(
            'wifi_ssid_change_debounce_seconds', 30)
        self._pending_ssid_change = None
        self._pending_ssid_first_seen = 0.0
        # Failsafe cycle tracking (cycles with no WiFi and no AP clients)
        # This counter tracks prolonged disconnections (>5 minutes each) to prevent endless loops
        # It will only trigger a reboot after many consecutive long-term failures
        self.no_connection_cycles = 0
        self.failsafe_cycle_limit = shared_data.config.get('wifi_failsafe_cycle_limit', 20)  # Increased from 10 to 20 for safety
        self.failsafe_disconnect_threshold = 300  # 5 minutes of disconnection before counting as a cycle
        
        # AP mode settings
        self.ap_ssid = shared_data.config.get('wifi_ap_ssid', 'Ragnar')
        self.ap_password = shared_data.config.get('wifi_ap_password', 'ragnarconnect')
        self.ap_interface = self.default_wifi_interface
        # Resolved lazily by _client_wifi_interface(); the built-in hosts the
        # AP and a dongle, when present, carries the client connection.
        self._client_iface_cache = None
        self._client_iface_cache_ts = 0.0
        self.ap_ip = "192.168.4.1"
        self.ap_subnet = "192.168.4.0/24"
        # Wardriving AP (KEY1 on the e-paper) — brought up on a spare/borrowed
        # adapter so wardriving keeps running. Track prior state for teardown.
        self._wardrive_ap_prev_interface = None
        self._wardrive_ap_lent_iface = None
        
        # Control flags
        self.should_exit = False
        self.monitoring_thread = None
        self.startup_complete = False

        # Connection tracking
        self.last_connection_type = None  # 'wifi', 'ethernet', or None
        self.last_ethernet_interface = None
        
        # Load configuration
        self.load_wifi_config()
        
    def load_wifi_config(self):
        """Load Wi-Fi configuration from shared data"""
        try:
            config = self.shared_data.config
            
            # Load known networks
            self.known_networks = config.get('wifi_known_networks', [])
            
            # Load AP settings
            self.ap_ssid = config.get('wifi_ap_ssid', 'Ragnar')
            self.ap_password = config.get('wifi_ap_password', 'ragnarconnect')
            self.connection_timeout = config.get('wifi_connection_timeout', 60)
            self.max_connection_attempts = config.get('wifi_max_attempts', 3)
            
            self.logger.info(f"Wi-Fi config loaded: {len(self.known_networks)} known networks")
            
        except Exception as e:
            self.logger.error(f"Error loading Wi-Fi config: {e}")

    def _resolve_scan_interface(self, interface=None):
        """Return a safe interface name for scanning commands."""
        if isinstance(interface, str):
            candidate = interface.strip()
            if candidate:
                return candidate
        return self.default_wifi_interface

    def _client_wifi_interface(self):
        """The radio that should carry the Wi-Fi *client* connection.

        With a USB dongle present the two jobs split across radios, and the
        assignment is deliberate:

          - the **AP stays on the built-in** radio. Not every USB dongle's
            driver supports AP mode at all, while the Pi's on-board chip
            reliably does, and 2.4 GHz is the band every phone can find.
          - the **client connection moves to the dongle**, which on a Pi Zero
            2 W is the only way to reach a 5 GHz network — the built-in radio
            is 2.4 GHz only.

        The payoff is that the AP never has to come down: hostapd keeps the
        built-in radio while the dongle joins, scans and roams independently.
        On a single-radio box this returns the same interface as the AP, and
        behaviour is unchanged.
        """
        # Cached briefly: this is consulted on every connection check, and the
        # underlying lookup shells out to nmcli.
        now = time.time()
        if self._client_iface_cache and (now - self._client_iface_cache_ts) < 10.0:
            return self._client_iface_cache
        iface = self._find_secondary_wifi_interface() or self.default_wifi_interface
        self._client_iface_cache = iface
        self._client_iface_cache_ts = now
        return iface

    def _has_dedicated_client_radio(self):
        """True when the client connection has a radio of its own, so bringing
        Wi-Fi up does not require tearing the AP down."""
        return self._client_wifi_interface() != self.ap_interface

    def _find_secondary_wifi_interface(self):
        """Find a WiFi interface that is NOT being used for AP mode.

        Returns the interface name (e.g. 'wlan1') or None if only one
        WiFi adapter is present.
        """
        try:
            interfaces = gather_wifi_interfaces(self.default_wifi_interface)
            for iface in interfaces:
                name = iface.get('name', '')
                if name and name != self.ap_interface:
                    self.logger.info(f"Secondary WiFi interface found: {name}")
                    return name
        except Exception as exc:
            self.logger.debug(f"Unable to detect secondary WiFi interface: {exc}")
        return None

    @staticmethod
    def _parse_nmcli_terse_line(line):
        """Parse a single nmcli terse-mode line, handling escaped colons (\\:) in field values."""
        parts = []
        current = ''
        i = 0
        while i < len(line):
            if line[i] == '\\' and i + 1 < len(line) and line[i + 1] == ':':
                current += ':'
                i += 2
            elif line[i] == ':':
                parts.append(current)
                current = ''
                i += 1
            else:
                current += line[i]
                i += 1
        parts.append(current)
        return parts

    def _cache_interface_networks(self, interface, networks):
        """Cache scan results per interface while preserving legacy attributes."""
        target_iface = self._resolve_scan_interface(interface)
        normalized = networks or []
        self.interface_scan_cache[target_iface] = normalized
        self.interface_cache_time[target_iface] = time.time()
        self.last_scan_interface = target_iface
        # Preserve legacy behavior for components that read the flat attribute
        self.available_networks = normalized

    def _get_cached_interface_networks(self, interface):
        target_iface = self._resolve_scan_interface(interface)
        return (
            self.interface_scan_cache.get(target_iface),
            self.interface_cache_time.get(target_iface)
        )

    def _get_known_ssids(self):
        """Return a deduplicated list of Ragnar-configured SSIDs."""
        known_ssids = []
        seen = set()
        try:
            for entry in self.known_networks or []:
                if isinstance(entry, dict):
                    ssid = entry.get('ssid')
                else:
                    ssid = str(entry).strip()
                if ssid and ssid not in seen:
                    known_ssids.append(ssid)
                    seen.add(ssid)
        except Exception as exc:
            self.logger.debug(f"Unable to enumerate known SSIDs: {exc}")
        return known_ssids

    def _run_iwlist_scan(self, interface, *, system_profiles=None, known_ssids=None, log_target=None):
        """Execute iwlist scan and return normalized network list."""
        logger_target = log_target or self.logger
        system_profiles = set(system_profiles or [])
        known_set = set(known_ssids or self._get_known_ssids())
        cmd = ['sudo', 'iwlist', interface, 'scan']
        logger_target.debug(f"Running iwlist scan on {interface}: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except FileNotFoundError:
            logger_target.warning("iwlist command not available; cannot perform fallback scan")
            return []
        except Exception as exc:
            logger_target.warning(f"iwlist scan execution failed: {exc}")
            return []

        if result.returncode != 0:
            stderr_snippet = (result.stderr or '').strip()
            logger_target.warning(f"iwlist scan returned code {result.returncode} on {interface}: {stderr_snippet}")
            return []

        parsed_networks = self._parse_iwlist_output(result.stdout or '') or []
        if not parsed_networks:
            logger_target.info(f"iwlist scan on {interface} returned no parseable networks")
            return []

        deduped = {}
        for network in parsed_networks:
            ssid = network.get('ssid')
            if not ssid or ssid == self.ap_ssid:
                continue
            try:
                signal = int(network.get('signal', 0) or 0)
            except (TypeError, ValueError):
                signal = 0
            existing = deduped.get(ssid)
            if not existing or signal > existing.get('signal', 0):
                enriched = {
                    'ssid': ssid,
                    'signal': signal,
                    'security': network.get('security', 'Unknown'),
                    'known': ssid in known_set or ssid in system_profiles,
                    'has_system_profile': ssid in system_profiles,
                    'scan_method': 'iwlist'
                }
                deduped[ssid] = enriched

        final_networks = sorted(deduped.values(), key=lambda x: x.get('signal', 0), reverse=True)
        logger_target.info(f"iwlist scan discovered {len(final_networks)} networks on {interface}")
        return final_networks

    def _set_current_ssid(self, ssid):
        """Update current SSID and propagate to storage with debounce.

        First-time establishment (no active network yet) propagates immediately
        so the per-network DB switches before the next scan cycle. Subsequent
        *changes* between known SSIDs are debounced: a transient misread of
        the SSID (common during roaming on Pi Zero) used to trip
        mark_all_hosts_degraded() and wipe the entire target list.
        """
        self.current_ssid = ssid

        if not hasattr(self.shared_data, 'set_active_network'):
            return

        active_ssid = getattr(self.shared_data, 'active_network_ssid', None)

        # Same SSID as what storage already considers active → clear pending.
        if ssid == active_ssid:
            if self._pending_ssid_change is not None:
                self.logger.debug(
                    f"SSID change to {self._pending_ssid_change} aborted "
                    f"(reverted to {active_ssid})")
            self._pending_ssid_change = None
            self._pending_ssid_first_seen = 0.0
            return

        # Fresh establishment from no active network → propagate immediately.
        if not active_ssid:
            self._propagate_active_network(ssid)
            return

        # Real change from one SSID to another → debounce.
        now = time.time()
        if self._pending_ssid_change != ssid:
            self._pending_ssid_change = ssid
            self._pending_ssid_first_seen = now
            self.logger.info(
                f"SSID change observed: {active_ssid!r} -> {ssid!r}, "
                f"debouncing {self.ssid_change_debounce_s}s before switching "
                f"network storage")
            return

        elapsed = now - self._pending_ssid_first_seen
        if elapsed < self.ssid_change_debounce_s:
            self.logger.debug(
                f"SSID {ssid!r} pending {elapsed:.1f}/"
                f"{self.ssid_change_debounce_s}s")
            return

        self.logger.info(
            f"SSID {ssid!r} confirmed after {elapsed:.1f}s — switching storage")
        self._propagate_active_network(ssid)
        self._pending_ssid_change = None
        self._pending_ssid_first_seen = 0.0

    def _propagate_active_network(self, ssid):
        try:
            self.shared_data.set_active_network(ssid)
        except Exception as exc:
            self.logger.warning(
                f"Failed to propagate network change to storage manager: {exc}")

    def _trigger_initial_ping_sweep(self, ssid):
        """Schedule a post-connection ping sweep to refresh network data."""
        if not ssid:
            self.logger.debug("Ping sweep trigger skipped - SSID unavailable")
            return

        now = time.time()
        cooldown = max(0, self.ping_sweep_cooldown or 0)

        if (self._last_ping_sweep_ssid == ssid and
                now - self._last_ping_sweep_time < cooldown):
            remaining = int(cooldown - (now - self._last_ping_sweep_time))
            self.logger.info(f"Ping sweep for {ssid} suppressed - cooldown {remaining}s remaining")
            return

        if self._ping_sweep_thread and self._ping_sweep_thread.is_alive():
            self.logger.info("Ping sweep already running - skipping additional trigger")
            return

        self.logger.info(f"Scheduling initial ping sweep for SSID '{ssid}'")
        self._last_ping_sweep_time = now
        self._last_ping_sweep_ssid = ssid
        self._ping_sweep_thread = threading.Thread(
            target=self._run_initial_ping_sweep,
            args=(ssid,),
            daemon=True
        )
        self._ping_sweep_thread.start()

    def _run_initial_ping_sweep(self, ssid):
        """Background worker that runs the lightweight NetworkScanner ping sweep."""
        try:
            from actions.scanning import NetworkScanner
        except ImportError as import_error:
            self.logger.error(f"Unable to import NetworkScanner for ping sweep: {import_error}")
            return

        try:
            scanner = NetworkScanner(self.shared_data)
            summary = scanner.run_initial_ping_sweep(include_arp_scan=True)
            if summary:
                total_hosts = summary.get('arp_hosts', 0) + summary.get('ping_hosts', 0)
                cidrs = ', '.join(summary.get('target_cidrs', []))
                self.logger.info(
                    f"Initial ping sweep for {ssid} completed - {total_hosts} hosts touched across {cidrs}"
                )
            else:
                self.logger.warning(f"Ping sweep for {ssid} finished without summary data")
        except Exception as exc:
            import traceback
            self.logger.error(f"Ping sweep thread failed: {exc}")
            self.logger.debug(traceback.format_exc())
    
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
        """Start the Wi-Fi management system with endless loop behavior"""
        self.logger.info("Starting Wi-Fi Manager with Endless Loop behavior...")

        # Mark boot completion time for endless loop timing
        self.boot_completed_time = time.time()

        # Create a restart detection file to help identify service restarts
        self._create_restart_marker()

        # Start monitoring thread
        if not self.monitoring_thread or not self.monitoring_thread.is_alive():
            self.monitoring_thread = threading.Thread(target=self._endless_loop_monitoring, daemon=True)
            self.monitoring_thread.start()

        # Start USB interface monitor to detect antenna/adapter disconnect events
        self._start_usb_interface_monitor()
        
        # Initial connection assessment and endless loop startup
        self._initial_endless_loop_sequence()
    
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
            if hasattr(self, 'ap_logger') and isinstance(self.ap_logger, logging.Logger):
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
    
    # ============================================================================
    # USB INTERFACE MONITOR — detect antenna/adapter hot-unplug events
    # ============================================================================

    def _get_wifi_interfaces_sysfs(self):
        """Return the set of WiFi interface names visible in /sys/class/net/."""
        ifaces = set()
        try:
            for name in os.listdir('/sys/class/net/'):
                base = f'/sys/class/net/{name}'
                if os.path.exists(f'{base}/wireless') or os.path.exists(f'{base}/phy80211'):
                    ifaces.add(name)
        except Exception:
            pass
        return ifaces

    def _start_usb_interface_monitor(self):
        """Start a background thread that watches for WiFi interface disappearance."""
        t = threading.Thread(
            target=self._usb_interface_monitor_loop,
            daemon=True,
            name="usb-iface-monitor",
        )
        t.start()

    def _usb_interface_monitor_loop(self):
        """Poll /sys/class/net/ every 5 s; trigger reconnect when a WiFi interface vanishes."""
        prev_ifaces = self._get_wifi_interfaces_sysfs()
        while not self.should_exit:
            time.sleep(5)
            try:
                current_ifaces = self._get_wifi_interfaces_sysfs()
                disappeared = prev_ifaces - current_ifaces
                if disappeared:
                    self.logger.warning(
                        f"WiFi interface(s) disappeared (unplugged?): {disappeared}"
                    )
                    if not self.wifi_connected and not self.ap_mode_active:
                        self.logger.info(
                            "USB antenna removed while disconnected — triggering WiFi reconnect"
                        )
                        threading.Thread(
                            target=self._endless_loop_wifi_search,
                            daemon=True,
                            name="wifi-reconnect-usb-unplug",
                        ).start()
                prev_ifaces = current_ifaces
            except Exception as e:
                self.logger.debug(f"USB interface monitor error: {e}")

    # ============================================================================
    # WARDRIVING / WEB PORTAL COORDINATION
    # ============================================================================

    def _is_wardriving_active(self):
        """Return True if the wardriving engine is currently running."""
        try:
            ragnar = getattr(self.shared_data, 'ragnar_instance', None)
            if ragnar and hasattr(ragnar, '_wd_engine'):
                return getattr(ragnar._wd_engine, '_running', False)
            import webapp_modern
            engine = getattr(webapp_modern, '_wardriving_engine', None)
            if engine:
                return getattr(engine, '_running', False)
        except Exception:
            pass
        return self.shared_data.config.get('wardriving_on_boot', False)

    def _sync_web_portal_for_wardriving(self):
        """Stop web portal when wardriving with no WiFi; restart when WiFi returns.

        Called every monitoring iteration so the portal state converges quickly
        regardless of how wardriving was started (boot flag, API call, etc.).
        """
        if not self._is_wardriving_active():
            return
        ragnar = getattr(self.shared_data, 'ragnar_instance', None)
        if not ragnar:
            return
        portal_active = getattr(self.shared_data, 'web_portal_active', True)
        if not self.wifi_connected and portal_active:
            threading.Thread(
                target=ragnar.stop_web_portal,
                daemon=True,
                name="web-portal-stopper",
            ).start()
        elif self.wifi_connected and not portal_active:
            threading.Thread(
                target=ragnar.start_web_portal,
                daemon=True,
                name="web-portal-starter",
            ).start()

    def _initial_endless_loop_sequence(self):
        """Handle initial Wi-Fi connection with endless loop behavior"""
        self.logger.info("Starting Endless Loop Wi-Fi management...")

        self._ensure_wifi_interfaces_up()
        
        # Wait 5 seconds after boot before starting the endless loop (reduced from 30s)
        if self.boot_completed_time:
            boot_wait_time = 5  # 5 seconds – interfaces are ready by now
            elapsed_since_boot = time.time() - self.boot_completed_time
            remaining_wait = boot_wait_time - elapsed_since_boot
            
            if remaining_wait > 0:
                self.logger.info(f"Waiting {remaining_wait:.1f}s more before starting endless loop (5 seconds after boot)")
                time.sleep(remaining_wait)
        
        # Check if we're already connected before starting the loop (Ethernet preferred)
        if self.check_network_connectivity():
            if self.last_connection_type == 'wifi':
                self.wifi_connected = True
                self.shared_data.wifi_connected = True
                self._set_current_ssid(self.get_current_ssid())
                self._trigger_initial_ping_sweep(self.current_ssid)
                self.logger.info(f"Already connected to Wi-Fi network: {self.current_ssid}")
                self._save_connection_state(self.current_ssid, True)
            elif self.last_connection_type == 'ethernet':
                self.wifi_connected = False
                self.shared_data.wifi_connected = False
                self.logger.info("Active Ethernet connection detected; using LAN as default and skipping Wi-Fi search.")
            self.last_wifi_validation = time.time()
            self.startup_complete = True
            self.endless_loop_active = True
            return
        # Start the endless loop
        self.endless_loop_start_time = time.time()
        self.startup_complete = True
        self.logger.info("Endless Loop started - beginning WiFi search phase")
        
        # Try to connect to known networks for 2 minutes
        self._endless_loop_wifi_search()

    def _endless_loop_wifi_search(self):
        """Search for and connect to known WiFi networks - simply enable WiFi and let system auto-reconnect"""
        # Don't fight the wardriving phone-access AP (KEY1): it deliberately
        # borrowed this radio, and reconnecting WiFi would set the interface
        # back to managed and collapse the AP. Resumes once the user stops it.
        if getattr(self.shared_data, 'wardrive_ap_active', False):
            self.logger.info("Endless Loop: WiFi search suppressed — wardriving phone-access AP is up")
            return False
        self.logger.info("Endless Loop: Starting WiFi search phase (1 minute)")
        search_start_time = time.time()

        self._ensure_wifi_interfaces_up()
        
        # First check if already connected
        if self.check_wifi_connection():
            self.wifi_connected = True
            self.shared_data.wifi_connected = True
            self._set_current_ssid(self.get_current_ssid())
            self.logger.info(f"Endless Loop: Already connected to {self.current_ssid}")
            self._save_connection_state(self.current_ssid, True)
            self.last_wifi_validation = time.time()
            self.consecutive_validation_cycles_failed = 0
            self._trigger_initial_ping_sweep(self.current_ssid)
            return True
        
        # Enable WiFi and let Linux/NetworkManager auto-reconnect to known networks
        self.logger.info("Endless Loop: Enabling WiFi mode - system will auto-reconnect to known networks")
        
        try:
            # Hand the CLIENT radio to NetworkManager. On a single-radio box
            # that is the AP interface being taken back out of AP mode; with a
            # dongle it is the dongle, and the AP interface is deliberately left
            # alone so hostapd keeps running on the built-in radio throughout.
            client_iface = self._client_wifi_interface()
            subprocess.run(['sudo', 'nmcli', 'dev', 'set', client_iface, 'managed', 'yes'],
                         capture_output=True, text=True, timeout=10)
            if client_iface != self.ap_interface:
                self.logger.info(
                    f"Endless Loop: connecting on {client_iface}; AP stays up on {self.ap_interface}")

            # Enable WiFi radio (equivalent to user toggling WiFi on)
            subprocess.run(['sudo', 'nmcli', 'radio', 'wifi', 'on'],
                         capture_output=True, text=True, timeout=10)
            
            self.logger.info("Endless Loop: WiFi enabled - waiting up to 60 seconds for auto-connection")
            
        except Exception as e:
            self.logger.error(f"Error enabling WiFi: {e}")
        
        # Wait up to 60 seconds for automatic connection (check every 5 seconds)
        timeout = 60  # 1 minute to connect
        check_interval = 5
        elapsed = 0
        
        while elapsed < timeout and not self.should_exit:
            time.sleep(check_interval)
            elapsed += check_interval
            
            if self.check_wifi_connection():
                self.wifi_connected = True
                self.shared_data.wifi_connected = True
                self._set_current_ssid(self.get_current_ssid())
                self.logger.info(f"Endless Loop: Successfully auto-connected to {self.current_ssid} after {elapsed}s")
                self._save_connection_state(self.current_ssid, True)
                self.last_wifi_validation = time.time()
                self.consecutive_validation_cycles_failed = 0
                self.no_connection_cycles = 0  # Reset failsafe counter on success
                self._trigger_initial_ping_sweep(self.current_ssid)
                return True
            else:
                self.logger.debug(f"Endless Loop: Waiting for auto-connection... ({elapsed}s/{timeout}s)")
        
        # Strengthened validation before AP fallback: perform a strong connectivity check (ping 8.8.8.8)
        self.logger.info("Endless Loop: Performing strong connectivity verification before AP fallback")
        if self._strong_wifi_presence_check():
            self.logger.info("Endless Loop: Strong check indicates WiFi connectivity; aborting AP fallback")
            self.wifi_connected = True
            self.shared_data.wifi_connected = True
            self._set_current_ssid(self.get_current_ssid())
            self._save_connection_state(self.current_ssid, True)
            self.last_wifi_validation = time.time()
            self.no_connection_cycles = 0
            self._trigger_initial_ping_sweep(self.current_ssid)
            return True

        # No WiFi connected after 1 minute, switch to AP mode
        self.logger.info(f"Endless Loop: No auto-connection established after {timeout}s, switching to AP mode")
        self._endless_loop_start_ap_mode()
        return False

    def _endless_loop_start_ap_mode(self):
        """Start AP mode as part of endless loop.

        Skipped for the two modes that own the radio themselves:

        - **Wardriving** needs wlan0 for scanning, and AP mode (hostapd) would
          take over the interface. Wardriving has its own phone-access AP,
          started deliberately with KEY1.
        - **On-Screen Network Diagnostic Mode** is a field test of the network
          the box is actually on. Silently converting the radio into an access
          point mid-test invalidates every reading on the screen.

        WiFi search itself is NOT suppressed by either — the box should keep
        trying to rejoin a known network. Only the AP fallback is skipped.
        """
        if self.shared_data.config.get('wardriving_enabled', False):
            self.logger.info("Endless Loop: AP mode skipped — wardriving is enabled")
            return

        if self.shared_data.config.get('network_diagnostic_mode', False):
            self.logger.info("Endless Loop: AP mode skipped — On-Screen Network Diagnostic Mode is active")
            return

        self.logger.info("Endless Loop: Starting AP mode (3 minutes)")
        
        if self.start_ap_mode():
            self.ap_mode_start_time = time.time()
            self.user_connected_to_ap = False
            self.ap_user_connection_time = None
            self.force_exit_ap_mode = False
            self.logger.info("Endless Loop: AP mode started, waiting for connections or timeout")
        else:
            self.logger.error("Endless Loop: Failed to start AP mode, retrying WiFi search")
            # If AP fails, try WiFi search again after short delay
            time.sleep(30)
            self._endless_loop_wifi_search()

    def _endless_loop_monitoring(self):
        """Main endless loop monitoring thread"""
        last_state_save = 0
        
        while not self.should_exit:
            try:
                current_time = time.time()
                
                # Wait for endless loop to be active
                if not self.endless_loop_active:
                    time.sleep(5)
                    continue
                
                # Check current connection status
                was_connected = self.wifi_connected
                self.wifi_connected = self.check_wifi_connection()
                self.shared_data.wifi_connected = self.wifi_connected
                
                # Handle WiFi connection state changes
                if was_connected and not self.wifi_connected:
                    self.logger.warning("Endless Loop: Wi-Fi connection lost!")
                    self._save_connection_state(None, False)
                    self.wifi_validation_failures = 0  # Reset validation failures
                    self._pending_ping_sweep_ssid = None
                    
                    # Only increment failsafe counter if we're in a problematic state:
                    # - Not in AP mode (as AP mode is the normal recovery mechanism)
                    # - Have been disconnected for an extended period (default: 5 minutes)
                    if not self.ap_mode_active:
                        # Only count this as a failure cycle if we've been disconnected for a while
                        # This prevents momentary connection blips from triggering failsafe
                        if not hasattr(self, '_disconnect_timestamp'):
                            self._disconnect_timestamp = current_time
                            self.logger.info("Endless Loop: Connection lost, starting disconnect timer")
                        else:
                            disconnect_duration = current_time - self._disconnect_timestamp
                            # Only count as a cycle failure if disconnected for more than threshold (default 5 minutes)
                            if disconnect_duration > self.failsafe_disconnect_threshold:
                                self.no_connection_cycles += 1
                                self.logger.warning(f"Failsafe counter increment (disconnected for {disconnect_duration:.0f}s): {self.no_connection_cycles}/{self.failsafe_cycle_limit}")
                                self._disconnect_timestamp = current_time  # Reset for next cycle
                                
                                if self.no_connection_cycles >= self.failsafe_cycle_limit:
                                    self.logger.error(f"Failsafe threshold reached ({self.failsafe_cycle_limit} cycles) - initiating reboot as last resort")
                                    self._failsafe_reboot()
                    
                    self._endless_loop_wifi_search()
                elif not was_connected and self.wifi_connected:
                    self.logger.info("Endless Loop: Wi-Fi connection established!")
                    current_ssid = self.get_current_ssid()
                    # Immediately propagate the SSID so the per-network
                    # database switches before the next scan cycle.
                    self._set_current_ssid(current_ssid)
                    self._save_connection_state(current_ssid, True)
                    self.last_wifi_validation = current_time
                    self.wifi_validation_failures = 0
                    self.no_connection_cycles = 0  # Reset failsafe counter on success
                    self._pending_ping_sweep_ssid = current_ssid
                    
                    # Clear disconnect timestamp when reconnected
                    if hasattr(self, '_disconnect_timestamp'):
                        delattr(self, '_disconnect_timestamp')
                    
                    if self.ap_mode_active and not getattr(self.shared_data, 'wardrive_ap_active', False):
                        self.logger.info("Endless Loop: Stopping AP mode due to successful WiFi connection")
                        self.stop_ap_mode()
                
                # Handle WiFi validation every 3 minutes when connected
                if (self.wifi_connected and self.last_wifi_validation and 
                    (current_time - self.last_wifi_validation) >= self.wifi_validation_interval):
                    self._perform_wifi_validation()
                
                # Handle AP mode timeout and user connection monitoring
                if self.ap_mode_active:
                    self._handle_ap_mode_monitoring(current_time)
                
                # Handle force exit AP mode from web interface
                if self.force_exit_ap_mode and self.ap_mode_active:
                    self.logger.info("Endless Loop: Force exit AP mode requested from web interface")
                    self.stop_ap_mode()
                    self.force_exit_ap_mode = False
                    self._endless_loop_wifi_search()
                
                # Update current SSID if connected
                if self.wifi_connected:
                    connected_ssid = self.get_current_ssid()
                    self._set_current_ssid(connected_ssid)
                    if self._pending_ping_sweep_ssid:
                        self._trigger_initial_ping_sweep(self._pending_ping_sweep_ssid)
                        self._pending_ping_sweep_ssid = None
                
                # Periodically save connection state (every 2 minutes)
                if current_time - last_state_save > 120:
                    ssid = self.current_ssid if self.wifi_connected else None
                    self._save_connection_state(ssid, self.wifi_connected)
                    last_state_save = current_time

                # Keep web portal in sync with wardriving + WiFi state
                self._sync_web_portal_for_wardriving()

                time.sleep(self.connection_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in endless loop monitoring: {e}")
                time.sleep(5)

    def _perform_wifi_validation(self):
        """Perform 5 WiFi validation checks, 10 seconds apart. All 5 must fail to trigger AP mode."""
        self.logger.info("Endless Loop: Starting WiFi validation (5 checks, 10s apart)")
        validation_failures = 0
        
        for i in range(self.wifi_validation_retries):
            if not self.check_wifi_connection():
                validation_failures += 1
                self.logger.warning(f"Endless Loop: WiFi validation failed ({validation_failures}/{self.wifi_validation_retries})")
            else:
                self.logger.info(f"Endless Loop: WiFi validation passed ({i+1}/{self.wifi_validation_retries})")
            
            # Don't wait after the last check
            if i < self.wifi_validation_retries - 1:
                time.sleep(self.wifi_validation_retry_interval)
        
        # Update validation time
        self.last_wifi_validation = time.time()
        
        # If ALL 5 validations failed, disconnect and start endless loop
        if validation_failures == self.wifi_validation_retries:
            self.consecutive_validation_cycles_failed += 1
            self.logger.warning(f"Endless Loop: All {self.wifi_validation_retries} WiFi validations failed! Switching to AP mode")
            self.wifi_connected = False
            self.shared_data.wifi_connected = False
            self.disconnect_wifi()  # Disconnect from current network
            self._endless_loop_start_ap_mode()
        else:
            # Reset consecutive failure counter if any check passed
            self.consecutive_validation_cycles_failed = 0
            self.logger.info(f"Endless Loop: WiFi validation completed - {self.wifi_validation_retries - validation_failures}/{self.wifi_validation_retries} passed")

    def _strong_wifi_presence_check(self):
        """Perform a strong connectivity check (ping external host) to verify real internet access"""
        try:
            self.logger.debug("Performing strong WiFi presence check (ping 8.8.8.8)")
            result = subprocess.run(['ping', '-c', '2', '-W', '3', '8.8.8.8'], 
                                  capture_output=True, timeout=8)
            if result.returncode == 0:
                self.logger.info("Strong check: Successfully pinged 8.8.8.8 - WiFi connected")
                return True
            else:
                self.logger.warning("Strong check: Failed to ping 8.8.8.8")
                return False
        except Exception as e:
            self.logger.error(f"Strong check error: {e}")
            return False

    def _failsafe_reboot(self):
        """Reboot the system as a last resort failsafe mechanism"""
        try:
            self.logger.critical("FAILSAFE: Initiating system reboot due to persistent connectivity issues")
            self.ap_logger.critical("FAILSAFE: System reboot triggered - persistent connectivity failures")
            
            # Save state before reboot
            self._save_connection_state(None, False)
            
            # Log the failsafe trigger
            try:
                with open('/var/log/ragnar_failsafe.log', 'a') as f:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"{timestamp} - Failsafe reboot triggered: {self.no_connection_cycles} consecutive connection failures\n")
            except:
                pass
            
            # Clean shutdown of services
            self.should_exit = True
            if self.ap_mode_active:
                self.stop_ap_mode()
            
            # Wait a moment for cleanup
            time.sleep(2)
            
            # Initiate reboot
            self.logger.critical("FAILSAFE: Executing reboot command")
            subprocess.run(['sudo', 'reboot'], timeout=5)
            
        except Exception as e:
            self.logger.error(f"Error during failsafe reboot: {e}")
            # Try alternative reboot method
            try:
                subprocess.run(['sudo', 'systemctl', 'reboot'], timeout=5)
            except:
                pass


    def _handle_ap_mode_monitoring(self, current_time):
        """Handle AP mode monitoring for endless loop with improved recovery"""
        if not self.ap_mode_active or not self.ap_mode_start_time:
            return
        # The wardriving phone-access AP (KEY1) is user-controlled and must not
        # be torn down by the endless loop's timeout / known-network recovery —
        # it stays up until the user presses KEY1 again.
        if getattr(self.shared_data, 'wardrive_ap_active', False):
            return

        ap_uptime = current_time - self.ap_mode_start_time
        
        # Check for client connections
        current_client_count = self.check_ap_clients()
        
        # Detect new user connection
        if current_client_count > 0 and not self.user_connected_to_ap:
            self.user_connected_to_ap = True
            self.ap_user_connection_time = current_time
            self.logger.info("Endless Loop: User connected to AP - monitoring user activity")
        
        # Look for a known network again so an unattended box can leave AP mode
        # on its own once its network is back.
        #
        # Gated on nobody being connected to the AP. Somebody connected is
        # somebody configuring the box, and this block used to tear the AP down
        # underneath them: the fixed 3-minute grace expired and from then on
        # every scan that saw the home SSID called stop_ap_mode() mid-setup —
        # and that SSID is essentially always visible, since being in range of
        # it is why the user is standing there. The user-connected branch below
        # owns that case and holds the AP for as long as they stay attached.
        # With that condition explicit, the wait before recovering no longer
        # has to protect anyone, so it drops from 3 minutes to a short settle.
        #
        # The cadence is measured as elapsed time since the last check. It used
        # to read `int(ap_uptime) % 30 == 0`, which required a tick to land on
        # an exact multiple of 30 — but the loop sleeps ~10s and then does real
        # work (client counts, scans), so ap_uptime drifts and int() lands on
        # 181, 191, 202… Simulated over two hours that fired 24 times instead
        # of 235: ~90% of recovery attempts skipped, leaving the box in AP mode
        # long after WiFi returned, at a rate that got worse the slower the board.
        due = (current_time - self.last_ap_reconnect_check) >= self.ap_reconnect_check_interval
        if current_client_count == 0 and ap_uptime >= self.ap_recovery_grace and due:
            self.last_ap_reconnect_check = current_time
            self.logger.info("Endless Loop: No AP clients — checking for known WiFi networks to rejoin...")
            if self._check_known_networks_available():
                self.logger.info("Endless Loop: Known WiFi network detected! Attempting to connect...")
                # With a dongle the client has its own radio, so the AP never
                # has to be interrupted — hostapd keeps the built-in while the
                # dongle joins. Only a single-radio box has to give the AP up,
                # because one chip cannot be a station and an AP at once.
                dedicated = self._has_dedicated_client_radio()
                if not dedicated:
                    self.stop_ap_mode()
                    time.sleep(2)  # Brief pause for clean transition
                if self._endless_loop_wifi_search():
                    self.logger.info("Endless Loop: Successfully reconnected to known WiFi from AP mode")
                    if dedicated:
                        # Connected, so the setup AP has done its job. Take it
                        # down rather than leave it broadcasting: the default
                        # key is published in the docs, and a box that is on the
                        # network is reachable through the dashboard instead.
                        self.logger.info(
                            "Endless Loop: connected on %s — stopping the setup AP on %s",
                            self._client_wifi_interface(), self.ap_interface)
                        self.stop_ap_mode()
                    return
                elif not dedicated:
                    # Single radio: the AP was taken down to try, so put it back.
                    self.logger.warning("Endless Loop: Failed to reconnect to WiFi, restarting AP mode")
                    self._endless_loop_start_ap_mode()
                    return
                else:
                    # Dual radio: nothing was torn down, so there is nothing to
                    # restore — just keep the AP up and try again next cycle.
                    self.logger.warning(
                        "Endless Loop: Failed to join known network on %s; AP still up",
                        self._client_wifi_interface())
                    return
        
        # Handle user-connected AP mode
        if self.user_connected_to_ap and self.ap_user_connection_time:
            user_connection_time = current_time - self.ap_user_connection_time
            
            # Check if user is still connected every 30 seconds
            if current_client_count == 0:
                self.logger.info("Endless Loop: User disconnected from AP - switching back to WiFi search")
                self.stop_ap_mode()
                self._endless_loop_wifi_search()
                return
            
            # After 3 minutes with user connected, validate user still connected
            if user_connection_time >= self.ap_mode_timeout:
                if current_client_count > 0:
                    self.logger.info("Endless Loop: User still connected after 3 minutes - continuing AP mode")
                    # Reset the timer to check again in 3 minutes
                    self.ap_user_connection_time = current_time
                else:
                    self.logger.info("Endless Loop: User no longer connected after 3 minutes - switching to WiFi search")
                    self.stop_ap_mode()
                    self._endless_loop_wifi_search()
                    return
        
        # Nobody connected. The AP used to be torn down here every 3 minutes to
        # go hunting for a network, then brought back ~60s later — so the
        # "Ragnar" SSID vanished for a minute out of every four. That is exactly
        # when someone is looking for it: unboxing a new Ragnar, or arriving at
        # a summer house and reaching for their phone. Keep the AP up and let
        # the non-disruptive scan above do the hunting; it hands over cleanly
        # within ~30s of a known network appearing, without the SSID flapping.
        #
        # Two cases still justify dropping it, because leaving it up would mean
        # never rejoining anything:
        #   - scanning is not working on this hardware (no scan has returned
        #     results recently), so the quiet path cannot spot a network; and
        #   - there is at least one known network to go back to. With none
        #     saved — a fresh install — there is nothing to search for, and the
        #     AP is the entire point, so it stays up indefinitely.
        elif not self.user_connected_to_ap and ap_uptime >= self.ap_mode_timeout:
            scan_working = (current_time - self.last_successful_scan) < self.scan_trust_window
            if self.known_networks_count and not scan_working:
                self.logger.info(
                    "Endless Loop: AP up %ds with no clients and no working scan — "
                    "dropping it to search for a known network", int(ap_uptime))
                self.stop_ap_mode()
                self._endless_loop_wifi_search()
            elif not self.known_networks_count:
                self.logger.debug(
                    "Endless Loop: keeping AP up — no saved networks to rejoin")
            else:
                self.logger.debug(
                    "Endless Loop: keeping AP up — scan is working, will hand over "
                    "when a known network appears")

    def get_system_wifi_profiles(self):
        """Get all WiFi connection profiles from NetworkManager (system-wide)"""
        try:
            result = subprocess.run(['nmcli', '-t', '-f', 'NAME,TYPE', 'con', 'show'], 
                                  capture_output=True, text=True, timeout=10)
            
            wifi_profiles = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2 and parts[1] == '802-11-wireless':
                            wifi_profiles.append(parts[0])
            
            self.logger.debug(f"Found {len(wifi_profiles)} system WiFi profiles: {wifi_profiles}")
            return wifi_profiles
            
        except Exception as e:
            self.logger.error(f"Error getting system WiFi profiles: {e}")
            return []

    def _check_known_networks_available(self):
        """Check if any known WiFi networks (Ragnar or system) are currently available without disrupting AP mode"""
        try:
            # Get both Ragnar's known networks AND system profiles
            ragnar_known = [net['ssid'] for net in self.known_networks]
            system_profiles = self.get_system_wifi_profiles()
            all_known = list(set(ragnar_known + system_profiles))  # Combine and deduplicate

            # Recorded so AP monitoring can tell "nothing to rejoin" apart from
            # "something to rejoin, just not in range right now".
            self.known_networks_count = len(all_known)
            if not all_known:
                return False

            # Strategy 1: Use secondary adapter for a reliable nmcli scan
            secondary = self._find_secondary_wifi_interface()
            if secondary:
                try:
                    subprocess.run(
                        ['nmcli', 'dev', 'wifi', 'rescan', 'ifname', secondary],
                        capture_output=True, text=True, timeout=15
                    )
                    time.sleep(1)
                    result = subprocess.run(
                        ['nmcli', '-t', '-f', 'SSID', 'dev', 'wifi', 'list', 'ifname', secondary],
                        capture_output=True, text=True, timeout=15
                    )
                    if result.returncode == 0:
                        available_ssids = [
                            line.strip() for line in result.stdout.strip().split('\n')
                            if line.strip()
                        ]
                        # Any result at all proves the scan path works here, so
                        # "found nothing" can be trusted as genuinely nothing.
                        if available_ssids:
                            self.last_successful_scan = time.time()
                        for known_ssid in all_known:
                            if known_ssid in available_ssids:
                                self.logger.info(f"Known network '{known_ssid}' detected via secondary adapter {secondary}")
                                return True
                except Exception as e:
                    self.logger.debug(f"Secondary adapter scan failed during known-network check: {e}")

            # Strategy 2: Try a quick scan using iwlist on AP interface (less disruptive)
            try:
                result = subprocess.run(['sudo', 'iwlist', self.ap_interface, 'scan'],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    available_ssids = []
                    for line in result.stdout.split('\n'):
                        if 'ESSID:' in line:
                            ssid = line.split('ESSID:')[1].strip('"')
                            if ssid and ssid != '<hidden>':
                                available_ssids.append(ssid)

                    if available_ssids:
                        self.last_successful_scan = time.time()

                    # Check if any known networks (Ragnar or system) are available
                    for known_ssid in all_known:
                        if known_ssid in available_ssids:
                            self.logger.info(f"Known network '{known_ssid}' detected while in AP mode")
                            return True
            except Exception as e:
                self.logger.debug(f"iwlist scan failed: {e}")

            return False

        except Exception as e:
            self.logger.error(f"Error checking for known networks: {e}")
            return False

    def exit_ap_mode_from_web(self):
        """Exit AP mode and start WiFi search (called from web interface)"""
        self.logger.info("Endless Loop: Exit AP mode requested from web interface")
        self.force_exit_ap_mode = True
        return True

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
    
    # ============================================================================
    # LEGACY METHODS - DEPRECATED (replaced by endless loop monitoring)
    # ============================================================================
    
    def _monitoring_loop(self):
        """DEPRECATED: Old monitoring loop - replaced by _endless_loop_monitoring"""
        self.logger.warning("DEPRECATED: _monitoring_loop called - this should not happen in endless loop mode")
        # Fallback to endless loop monitoring
        self._endless_loop_monitoring()
    
    def _handle_connection_lost(self):
        """DEPRECATED: Old connection loss handler - replaced by endless loop logic"""
        self.logger.warning("DEPRECATED: _handle_connection_lost called - this should not happen in endless loop mode")
        # In endless loop mode, connection loss is handled by the main monitoring thread
        if self.endless_loop_active:
            self.logger.info("Connection loss detected - endless loop will handle reconnection")
            return
        
        # Legacy fallback behavior
        if not self.startup_complete:
            return
        
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
    
    def check_network_connectivity(self):
        """Check for any usable network link, preferring Ethernet when present."""
        try:
            try:
                ethernet_iface = get_active_ethernet_interface()
            except Exception as exc:
                ethernet_iface = None
                self.logger.debug(f"Ethernet check failed: {exc}")

            self.last_ethernet_interface = ethernet_iface
            lan_active = bool(ethernet_iface)

            if lan_active:
                self.last_connection_type = 'ethernet'
                self.shared_data.lan_connected = True
                self.shared_data.lan_interface = ethernet_iface.get('name') if ethernet_iface else None
                self.shared_data.lan_ip = ethernet_iface.get('ip_address') if ethernet_iface else None
                self.shared_data.network_connected = True
                self.shared_data.wifi_connected = False
                return True

            # No LAN; fall back to Wi-Fi detection
            self.shared_data.lan_connected = False
            self.shared_data.lan_interface = None
            self.shared_data.lan_ip = None

            wifi_connected = self.check_wifi_connection()
            self.last_connection_type = 'wifi' if wifi_connected else None
            self.shared_data.network_connected = wifi_connected
            self.shared_data.wifi_connected = wifi_connected
            return wifi_connected
        except Exception as exc:
            self.logger.error(f"Error checking network connectivity: {exc}")
            self.shared_data.network_connected = False
            return False

    def check_wifi_connection(self):
        """Check if Wi-Fi is connected using multiple methods"""
        try:
            self._ensure_wifi_interfaces_up()
            # Method 1: Check using nmcli for active wireless connections
            result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,TYPE', 'con', 'show'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and 'yes:802-11-wireless' in line:
                        # Double-check with device status
                        dev_result = subprocess.run(['nmcli', '-t', '-f', 'DEVICE,STATE', 'dev', 'status'], 
                                                  capture_output=True, text=True, timeout=5)
                        if dev_result.returncode == 0 and 'connected' in dev_result.stdout:
                            return True
            
            # Methods 2 and 3 name an interface, so they must name the one
            # actually carrying the connection. With a dongle that is wlan1,
            # while the built-in is busy hosting the AP — checking the built-in
            # would report "not connected" for a perfectly good uplink.
            client_iface = self._client_wifi_interface()

            # Method 2: Check using iwconfig (if available)
            try:
                result = subprocess.run(['iwconfig', client_iface],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'ESSID:' in result.stdout and 'Not-Associated' not in result.stdout:
                    # Verify we have an IP address
                    ip_result = subprocess.run(['ip', 'addr', 'show', client_iface],
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
                    # Ensure it's going through the client radio
                    route_result = subprocess.run(['ip', 'route', 'get', '1.1.1.1'],
                                                capture_output=True, text=True, timeout=3)
                    if route_result.returncode == 0 and f'dev {client_iface}' in route_result.stdout:
                        return True
            except Exception:
                pass  # Network unreachable, that's fine
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking Wi-Fi connection: {e}")
            return False

    def _ensure_radios_unblocked(self):
        """Unblock soft-blocked WiFi radios so client and AP mode can start.

        A fresh OS image (no WiFi country set) or a newly plugged USB dongle
        leaves the radio soft-blocked by rfkill. In that state hostapd cannot
        bring the AP up, so start_ap_mode() fails silently and the endless
        loop never presents the fallback AP. The installer/updater install a
        persistent udev rule, but a device that has never run them (or cannot
        update because it has no network) needs this runtime self-heal.
        """
        try:
            result = subprocess.run(['rfkill', 'list', 'wifi'],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return
            if 'Hard blocked: yes' in result.stdout:
                self.logger.error(
                    "WiFi radio is HARD blocked (hardware switch) - "
                    "cannot unblock via software")
            if 'Soft blocked: yes' not in result.stdout:
                return
            self.logger.warning(
                "WiFi radio soft-blocked by rfkill - unblocking "
                "(required for both client and AP mode)")
            self.ap_logger.warning(
                "rfkill soft-block detected - running 'rfkill unblock all'")
            unblock = subprocess.run(['sudo', 'rfkill', 'unblock', 'all'],
                                     capture_output=True, text=True, timeout=5)
            if unblock.returncode == 0:
                self.logger.info("rfkill: all radios unblocked")
            else:
                self.logger.error(
                    f"rfkill unblock failed: "
                    f"{(unblock.stderr or unblock.stdout).strip()}")
        except FileNotFoundError:
            self.logger.debug("rfkill not installed - skipping radio unblock check")
        except Exception as exc:
            self.logger.debug(f"rfkill check failed: {exc}")

    def _ensure_wifi_interfaces_up(self):
        """Bring Wi-Fi interfaces up if they are down or unmanaged."""
        try:
            now = time.time()
            if now - self.last_interface_reenable_time < self.interface_reenable_interval:
                return
            self.last_interface_reenable_time = now

            self._ensure_radios_unblocked()

            interfaces = gather_wifi_interfaces(self.default_wifi_interface)
            for iface in interfaces:
                name = iface.get('name')
                state = (iface.get('state') or '').strip().upper()
                if not name or state not in ('DOWN', 'DISCONNECTED', 'UNAVAILABLE', 'UNMANAGED'):
                    continue
                # Skip secondary interfaces (e.g. wlan1) — they may be intentionally
                # unmanaged for monitor mode and forcing them managed disrupts wlan0.
                if name != self.default_wifi_interface:
                    self.logger.debug(f"Skipping non-default Wi-Fi interface {name} (state: {state})")
                    continue
                self.logger.info(f"Bringing up Wi-Fi interface {name} (state: {state})")

                link_result = subprocess.run(
                    ['sudo', 'ip', 'link', 'set', name, 'up'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if link_result.returncode != 0:
                    self.logger.warning(
                        f"Failed to set interface {name} up: "
                        f"{(link_result.stderr or link_result.stdout).strip()}"
                    )

                managed_result = subprocess.run(
                    ['sudo', 'nmcli', 'dev', 'set', name, 'managed', 'yes'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if managed_result.returncode != 0:
                    self.logger.warning(
                        f"Failed to mark interface {name} managed: "
                        f"{(managed_result.stderr or managed_result.stdout).strip()}"
                    )
        except Exception as exc:
            self.logger.debug(f"Unable to re-enable Wi-Fi interfaces: {exc}")
    
    def get_current_ssid(self):
        """Get the current connected SSID"""
        try:
            # Method 1: SSID from the active connection on the CLIENT radio —
            # the dongle when one is fitted, since the built-in may be hosting
            # the AP and would report the AP's own name instead.
            result = subprocess.run(['nmcli', '-t', '-f', 'GENERAL.CONNECTION', 'dev', 'show', self._client_wifi_interface()],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                # Extract connection name (which is usually the SSID for WiFi)
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('GENERAL.CONNECTION:'):
                        ssid = line.split(':', 1)[1].strip()
                        if ssid and ssid != '--':
                            return ssid
            
            # Method 2: Try using iwgetid as fallback
            try:
                result = subprocess.run(['iwgetid', '-r'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except FileNotFoundError:
                pass  # iwgetid not available
            
            # Method 3: Parse from nmcli connection show (active connections)
            result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,NAME,TYPE', 'con', 'show'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 3 and parts[0] == 'yes' and '802-11-wireless' in parts[2]:
                        return parts[1]
            
            return None
        except Exception as e:
            self.logger.error(f"Error getting current SSID: {e}")
            return None
    
    def scan_networks(self, interface=None):
        """Scan for available Wi-Fi networks and mark those with system profiles"""
        try:
            target_iface = self._resolve_scan_interface(interface)
            # If we're in AP mode, use special AP scanning method
            if self.ap_mode_active:
                return self.scan_networks_while_ap(interface=target_iface)
            
            # Check per-interface in-memory cache first (more accurate than DB cache)
            cached_networks, cache_time = self._get_cached_interface_networks(target_iface)
            if cached_networks is not None and cache_time:
                cache_age = time.time() - cache_time
                if cache_age < 120:  # 2 minutes
                    self.logger.info(f"Using {len(cached_networks)} cached WiFi networks for {target_iface} (age: {cache_age:.0f}s)")
                    return cached_networks
            
            self.logger.info(f"Scanning for Wi-Fi networks on {target_iface} (cache miss or expired)...")
            
            # Get system WiFi profiles to mark known networks
            system_profiles = self.get_system_wifi_profiles()
            ragnar_known = self._get_known_ssids()
            
            # Trigger a new scan
            rescan_cmd = ['nmcli', 'dev', 'wifi', 'rescan']
            if target_iface:
                rescan_cmd.extend(['ifname', target_iface])
            subprocess.run(rescan_cmd, capture_output=True, timeout=15)
            
            # Give the radio time to complete the scan
            time.sleep(3)
            
            # Get scan results (--rescan no since we already triggered one)
            list_cmd = ['nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY', 'dev', 'wifi', 'list', '--rescan', 'no']
            if target_iface:
                list_cmd.extend(['ifname', target_iface])
            result = subprocess.run(list_cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                self.logger.warning(f"nmcli scan command failed on {target_iface} with code {result.returncode}: {result.stderr}")
            
            networks = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue
                    parts = self._parse_nmcli_terse_line(line)
                    # Need at least SSID and SIGNAL (security may be empty for open networks)
                    if len(parts) >= 2 and parts[0]:
                        ssid = parts[0]
                        security = parts[2] if len(parts) > 2 and parts[2] else 'Open'
                        # Mark as known if EITHER in Ragnar's list OR has system profile
                        is_known = ssid in ragnar_known or ssid in system_profiles
                        networks.append({
                            'ssid': ssid,
                            'signal': int(parts[1]) if parts[1].isdigit() else 0,
                            'security': security,
                            'known': is_known,
                            'has_system_profile': ssid in system_profiles
                        })
            
            # Remove duplicates and sort by signal strength
            seen_ssids = set()
            unique_networks = []
            for network in sorted(networks, key=lambda x: x['signal'], reverse=True):
                if network['ssid'] not in seen_ssids:
                    seen_ssids.add(network['ssid'])
                    unique_networks.append(network)
            
            if not unique_networks:
                self.logger.warning(
                    f"nmcli reported zero networks on {target_iface}; attempting iwlist fallback"
                )
                fallback_networks = self._run_iwlist_scan(
                    target_iface,
                    system_profiles=system_profiles,
                    known_ssids=ragnar_known
                )
                if fallback_networks:
                    unique_networks = fallback_networks
                else:
                    self.logger.info(f"Fallback iwlist scan also returned zero networks on {target_iface}")
            
            self._cache_interface_networks(target_iface, unique_networks)
            self.logger.info(f"Found {len(unique_networks)} unique networks on {target_iface}")
            
            # Cache the scan results in database
            if self.db and unique_networks:
                try:
                    self.db.cache_wifi_scan(unique_networks)
                    self.logger.debug(f"Cached {len(unique_networks)} networks to database")
                except Exception as cache_err:
                    self.logger.warning(f"Failed to cache WiFi scan: {cache_err}")
            return unique_networks
            
        except Exception as e:
            self.logger.error(f"Error scanning networks: {e}")
            return []

    def _scan_via_secondary_interface(self, system_profiles=None, known_ssids=None):
        """Attempt a full nmcli scan using a secondary WiFi adapter (not the AP interface).

        Returns a list of network dicts or an empty list when no secondary
        adapter is available or the scan fails.
        """
        secondary = self._find_secondary_wifi_interface()
        if not secondary:
            return []

        self.ap_logger.info(f"Secondary adapter detected ({secondary}) – running live nmcli scan")
        system_profiles = set(system_profiles or [])
        known_set = set(known_ssids or self._get_known_ssids())

        try:
            # Ensure the secondary interface is managed and up
            subprocess.run(
                ['sudo', 'nmcli', 'dev', 'set', secondary, 'managed', 'yes'],
                capture_output=True, text=True, timeout=5
            )
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', secondary, 'up'],
                capture_output=True, text=True, timeout=5
            )

            # Trigger rescan
            subprocess.run(
                ['nmcli', 'dev', 'wifi', 'rescan', 'ifname', secondary],
                capture_output=True, text=True, timeout=15
            )
            # Short pause to let the radio collect results
            time.sleep(2)

            result = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,SIGNAL,SECURITY', 'dev', 'wifi', 'list', 'ifname', secondary],
                capture_output=True, text=True, timeout=15
            )

            if result.returncode != 0:
                self.ap_logger.warning(
                    f"nmcli scan on secondary {secondary} failed (rc={result.returncode}): {result.stderr}"
                )
                # Fall back to iwlist on the secondary adapter
                return self._run_iwlist_scan(
                    secondary,
                    system_profiles=system_profiles,
                    known_ssids=known_set,
                    log_target=self.ap_logger
                )

            networks = []
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = self._parse_nmcli_terse_line(line)
                if len(parts) >= 2 and parts[0]:
                    ssid = parts[0]
                    security = parts[2] if len(parts) > 2 and parts[2] else 'Open'
                    is_known = ssid in known_set or ssid in system_profiles
                    networks.append({
                        'ssid': ssid,
                        'signal': int(parts[1]) if parts[1].isdigit() else 0,
                        'security': security,
                        'known': is_known,
                        'has_system_profile': ssid in system_profiles,
                        'scan_method': 'secondary_nmcli'
                    })

            # Deduplicate and sort by signal
            seen = set()
            unique = []
            for net in sorted(networks, key=lambda x: x['signal'], reverse=True):
                if net['ssid'] not in seen:
                    seen.add(net['ssid'])
                    unique.append(net)

            if unique:
                self.ap_logger.info(f"Secondary adapter {secondary} found {len(unique)} networks (live scan)")
            return unique

        except Exception as exc:
            self.ap_logger.warning(f"Secondary adapter scan failed on {secondary}: {exc}")
            return []
        finally:
            # Restore wlan1 to unmanaged so NM doesn't add a competing default route
            # that steals traffic from wlan0.
            subprocess.run(
                ['sudo', 'nmcli', 'dev', 'set', secondary, 'managed', 'no'],
                capture_output=True, text=True, timeout=5
            )

    def scan_networks_while_ap(self, interface=None):
        """Scan for networks while in AP mode using smart caching and fallback strategies"""
        try:
            scan_iface = interface if interface else self.ap_interface
            target_iface = self._resolve_scan_interface(scan_iface)
            self.logger.info(f"Scanning networks while in AP mode using smart strategies on {target_iface}")
            self.ap_logger.info(f"Starting network scan while in AP mode (non-disruptive) on {target_iface}")

            # Get system WiFi profiles to mark known networks
            system_profiles = self.get_system_wifi_profiles()
            ragnar_known = [net['ssid'] for net in self.known_networks]

            # Strategy 1: Live scan via secondary WiFi adapter (if available)
            secondary_networks = self._scan_via_secondary_interface(
                system_profiles=system_profiles,
                known_ssids=ragnar_known
            )
            if secondary_networks:
                self.ap_logger.info(f"Using live scan from secondary adapter ({len(secondary_networks)} networks)")
                self._cache_interface_networks(target_iface, secondary_networks)
                return secondary_networks

            # Strategy 2: Return cached networks if we have recent data (within 5 minutes for fresher data)
            cached_networks, cache_timestamp = self._get_cached_interface_networks(target_iface)
            if cached_networks is not None and cache_timestamp is not None:
                cache_age = time.time() - cache_timestamp
                if cache_age < 300:  # 5 minutes cache for fresher data
                    self.ap_logger.info(
                        f"Returning cached networks for {target_iface} (age: {cache_age:.1f}s, count: {len(cached_networks)})"
                    )
                    return cached_networks

            # Strategy 3: Use networks scanned before AP mode started
            if hasattr(self, 'available_networks') and self.available_networks:
                real_networks = [n for n in self.available_networks if not n.get('instruction')]
                if real_networks:
                    self.ap_logger.info(f"Using pre-AP scan results ({len(real_networks)} networks)")
                    self._cache_interface_networks(target_iface, real_networks)
                    return real_networks

            # Strategy 4: Try iwlist scan on AP interface (non-disruptive to AP mode)
            fallback_networks = self._run_iwlist_scan(
                target_iface,
                system_profiles=system_profiles,
                known_ssids=ragnar_known,
                log_target=self.ap_logger
            )
            if fallback_networks:
                self._cache_interface_networks(target_iface, fallback_networks)
                return fallback_networks

            # Strategy 5: Return known networks as available options
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
                self._cache_interface_networks(target_iface, known_as_available)
                return known_as_available
            
            # Strategy 5: Return helpful message for manual entry
            help_networks = [
                {
                    'ssid': '📡 Cached networks may be available',
                    'signal': 100,
                    'security': '',
                    'instruction': True,
                    'known': False
                },
                {
                    'ssid': '✏️ Or type network name manually below',
                    'signal': 90,
                    'security': '',
                    'instruction': True,
                    'known': False
                },
                {
                    'ssid': '� Click refresh to try scanning again',
                    'signal': 80,
                    'security': '',
                    'instruction': True,
                    'known': False
                }
            ]
            
            self.ap_logger.info("Returning instructional networks for manual entry")
            self._cache_interface_networks(target_iface, help_networks)
            return help_networks
            
        except Exception as e:
            self.logger.error(f"Error in smart AP scanning: {e}")
            self.ap_logger.error(f"Error during smart AP scan: {e}")
            return []

    def _parse_iwlist_output(self, output):
        """Parse iwlist scan output into network list for Pi Zero W2 compatibility"""
        networks = []
        current_network = {}
        
        try:
            for line in output.split('\n'):
                line = line.strip()
                
                if 'Cell ' in line and 'Address:' in line:
                    if current_network.get('ssid'):
                        networks.append(current_network)
                    current_network = {}
                
                elif 'ESSID:' in line:
                    ssid = line.split('ESSID:')[1].strip('"')
                    if ssid and ssid != '<hidden>' and ssid != self.ap_ssid:
                        current_network['ssid'] = ssid
                
                elif 'Signal level=' in line:
                    try:
                        signal = re.search(r'Signal level=(-?\d+)', line)
                        if signal:
                            dbm = int(signal.group(1))
                            # Convert dBm to percentage (rough approximation)
                            percentage = max(0, min(100, (dbm + 100) * 2))
                            current_network['signal'] = percentage
                    except Exception as e:
                        self.logger.debug(f"Error parsing signal: {e}")
                        current_network['signal'] = 50
                
                elif 'Encryption key:' in line:
                    if 'on' in line:
                        current_network['security'] = 'WPA/WPA2'
                    else:
                        current_network['security'] = 'Open'
            
            # Add the last network if it's complete
            if current_network.get('ssid'):
                networks.append(current_network)
            
            # Add known network flags
            for network in networks:
                network['known'] = network['ssid'] in [net['ssid'] for net in self.known_networks]
            
            self.logger.debug(f"Parsed {len(networks)} networks from iwlist output")
            return networks
            
        except Exception as e:
            self.logger.error(f"Error parsing iwlist output: {e}")
            return []

    def _parse_nmcli_output(self, output):
        """Parse nmcli output into network list for Pi Zero W2 compatibility"""
        networks = []
        
        try:
            for line in output.strip().split('\n'):
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 3:
                        ssid = parts[0].strip()
                        signal = parts[1].strip()
                        security = parts[2].strip()
                        
                        if ssid and ssid != '--' and ssid != self.ap_ssid:
                            networks.append({
                                'ssid': ssid,
                                'signal': int(signal) if signal.isdigit() else 50,
                                'security': security if security else 'Open',
                                'known': ssid in [net['ssid'] for net in self.known_networks]
                            })
            
            self.logger.debug(f"Parsed {len(networks)} networks from nmcli output")
            return networks
            
        except Exception as e:
            self.logger.error(f"Error parsing nmcli output: {e}")
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
        """Connect to a specific Wi-Fi network - NEVER deletes existing system profiles"""
        try:
            self.logger.info(f"Connecting to network: {ssid}")
            if password:
                self.logger.info(f"Password provided: {'*' * len(password)} (length: {len(password)})")
            else:
                self.logger.info("No password provided (open network or will use saved credentials)")
            
            # CRITICAL: If in AP mode, stop it first before connecting to WiFi
            if self.ap_mode_active:
                self.logger.info("Stopping AP mode before connecting to WiFi network...")
                self.stop_ap_mode()
                time.sleep(2)  # Give system time to clean up AP mode
            
            # IMPORTANT: NEVER delete existing NetworkManager profiles!
            # Check if a connection profile already exists
            check_result = subprocess.run(['nmcli', 'con', 'show', ssid], 
                                         capture_output=True, text=True)
            profile_exists = check_result.returncode == 0
            
            if profile_exists:
                self.logger.info(f"Found existing connection profile for {ssid}")
                
                # If password is provided and profile exists, try to update the password
                if password:
                    self.logger.info(f"Updating password for existing profile {ssid}")
                    update_cmd = ['sudo', 'nmcli', 'con', 'modify', ssid, 'wifi-sec.psk', password]
                    subprocess.run(update_cmd, capture_output=True, text=True)
                
                # Try to activate the existing connection
                self.logger.info(f"Activating existing connection profile for {ssid}")
                cmd = ['sudo', 'nmcli', 'con', 'up', ssid]
            else:
                # No existing profile - create a new one
                self.logger.info(f"No existing profile found for {ssid}, creating new connection")
                cmd = ['sudo', 'nmcli', 'dev', 'wifi', 'connect', ssid]
                if password:
                    cmd.extend(['password', password])
            
            self.logger.info(f"Executing: {' '.join(cmd[:3])} {ssid} {'password ***' if password else ''}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Get signal strength if available
            signal_strength = None
            try:
                for net in self.available_networks:
                    if net['ssid'] == ssid:
                        signal_strength = net.get('signal')
                        break
            except:
                pass
            
            if result.returncode == 0:
                # Wait a moment and verify connection
                self.logger.info(f"Connection command succeeded, verifying connection...")
                time.sleep(5)
                connected = self.check_wifi_connection()
                
                # Log connection attempt to database
                if self.db:
                    try:
                        conn_id = self.db.log_wifi_connection_attempt(
                            ssid=ssid,
                            success=connected,
                            failure_reason=None if connected else "Verification failed",
                            signal_strength=signal_strength,
                            network_profile_existed=profile_exists,
                            from_ap_mode=self.ap_mode_active
                        )
                        if connected:
                            self.current_connection_id = conn_id
                    except Exception as db_err:
                        self.logger.warning(f"Failed to log connection attempt: {db_err}")
                
                if connected:
                    self.logger.info(f"Successfully connected to {ssid}")
                    # Immediately propagate the network change so the
                    # per-network database is switched before any scan
                    # cycle can write hosts into the wrong store.
                    self.wifi_connected = True
                    self.shared_data.wifi_connected = True
                    self._set_current_ssid(ssid)
                    self._trigger_initial_ping_sweep(ssid)
                else:
                    self.logger.warning(f"Connection command succeeded but verification failed for {ssid}")
                return connected
            else:
                error_msg = result.stderr.strip()
                self.logger.error(f"nmcli connection failed for {ssid}: {error_msg}")
                
                # Parse common errors
                failure_reason = error_msg
                if "Secrets were required, but not provided" in error_msg:
                    self.logger.error("Password was required but not provided or incorrect")
                    failure_reason = "Incorrect password"
                elif "No network with SSID" in error_msg:
                    self.logger.error(f"Network {ssid} not found in range")
                    failure_reason = "Network not in range"
                
                # Log failed connection attempt
                if self.db:
                    try:
                        self.db.log_wifi_connection_attempt(
                            ssid=ssid,
                            success=False,
                            failure_reason=failure_reason,
                            signal_strength=signal_strength,
                            network_profile_existed=profile_exists,
                            from_ap_mode=self.ap_mode_active
                        )
                    except Exception as db_err:
                        self.logger.warning(f"Failed to log connection failure: {db_err}")
                
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Connection attempt to {ssid} timed out after 30 seconds")
            if self.db:
                try:
                    self.db.log_wifi_connection_attempt(
                        ssid=ssid,
                        success=False,
                        failure_reason="Connection timeout",
                        network_profile_existed=profile_exists,
                        from_ap_mode=self.ap_mode_active
                    )
                except:
                    pass
            return False
        except Exception as e:
            self.logger.error(f"Error connecting to {ssid}: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            if self.db:
                try:
                    self.db.log_wifi_connection_attempt(
                        ssid=ssid,
                        success=False,
                        failure_reason=f"Exception: {str(e)}",
                        network_profile_existed=profile_exists,
                        from_ap_mode=self.ap_mode_active
                    )
                except:
                    pass
            return False

    def disconnect_wifi(self):
        """Disconnect from current Wi-Fi network"""
        try:
            if not self.wifi_connected:
                self.logger.info("Not connected to any Wi-Fi network")
                return True
            
            current_ssid = self.get_current_ssid()
            self.logger.info(f"Disconnecting from Wi-Fi network: {current_ssid}")
            
            # Log disconnection in database
            if self.db and current_ssid:
                try:
                    self.db.update_wifi_disconnection(ssid=current_ssid, connection_id=self.current_connection_id)
                    self.current_connection_id = None
                except Exception as db_err:
                    self.logger.warning(f"Failed to log disconnection: {db_err}")
            
            # Disconnect using nmcli
            result = subprocess.run(['nmcli', 'device', 'disconnect', self.default_wifi_interface], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.wifi_connected = False
                self._set_current_ssid(None)
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
        """Remove a network from Ragnar's known networks list AND delete the system NetworkManager profile"""
        try:
            removed_from_ragnar = False
            original_count = len(self.known_networks)
            self.known_networks = [net for net in self.known_networks if net['ssid'] != ssid]
            
            if len(self.known_networks) < original_count:
                self.save_wifi_config()
                self.logger.info(f"Removed {ssid} from Ragnar's known networks list")
                removed_from_ragnar = True
            else:
                self.logger.warning(f"Network {ssid} not found in Ragnar's known networks")
            
            # Also delete the NetworkManager system profile so it no longer shows as saved
            removed_from_nm = False
            try:
                result = subprocess.run(
                    ['sudo', 'nmcli', 'connection', 'delete', ssid],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    self.logger.info(f"Deleted NetworkManager profile for {ssid}")
                    removed_from_nm = True
                else:
                    self.logger.debug(f"No NetworkManager profile found for {ssid}: {result.stderr.strip()}")
            except Exception as nm_err:
                self.logger.debug(f"Could not delete NetworkManager profile for {ssid}: {nm_err}")
            
            # Invalidate the scan cache so the network list refreshes correctly
            for iface in list(self.interface_scan_cache.keys()):
                self.interface_scan_cache.pop(iface, None)
                self.interface_cache_time.pop(iface, None)
            
            return removed_from_ragnar or removed_from_nm
                
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
        """Enable AP mode from web interface - uses endless loop behavior"""
        self.logger.info("AP mode requested from web interface")
        if self.wifi_connected:
            # If connected, disconnect first
            self.disconnect_wifi()
        
        # Stop current AP if running
        if self.ap_mode_active:
            self.stop_ap_mode()
        
        # Start AP mode (endless loop will handle timeout management)
        if self.endless_loop_active:
            # Use endless loop AP mode
            self._endless_loop_start_ap_mode()
            return True
        else:
            # Fallback to regular AP mode if endless loop not active
            return self.start_ap_mode()
    
    def start_ap_mode(self, captive=True):
        """Start Access Point mode.

        captive=False starts an accessory AP that advertises no gateway and no
        DNS, so a phone joining it keeps using cellular for internet (see
        _dnsmasq_config_no_internet). Used by the wardriving phone-access AP.
        """
        if self.ap_mode_active:
            self.logger.info("AP mode already active")
            self.ap_logger.info("AP mode start requested but already active")
            return True
        
        try:
            self.logger.info(f"Starting AP mode: {self.ap_ssid}")
            self.ap_logger.info(f"Starting AP mode: SSID={self.ap_ssid}, Interface={self.ap_interface}")
            self.ap_logger.info(f"AP Configuration: IP={self.ap_ip}, Subnet={self.ap_subnet}")
            
            # Scan and cache WiFi networks before starting AP mode
            self.logger.info("Scanning for WiFi networks before starting AP mode...")
            self.ap_logger.info("Pre-AP scan: Scanning for available networks to cache")
            try:
                self.available_networks = self.scan_networks()
                cached_count = len([n for n in self.available_networks if not n.get('instruction')])
                self.logger.info(f"Cached {cached_count} networks before starting AP mode")
                self.ap_logger.info(f"Pre-AP scan complete: Cached {cached_count} networks")
            except Exception as scan_error:
                self.logger.warning(f"Pre-AP network scan failed: {scan_error}")
                self.ap_logger.warning(f"Pre-AP scan failed but continuing: {scan_error}")
                self.available_networks = []
            
            # Radio must not be rfkill-blocked or hostapd fails to start
            self._ensure_radios_unblocked()

            # Create hostapd configuration
            self.ap_logger.info("Creating hostapd configuration...")
            if not self._create_hostapd_config():
                self.ap_logger.error("Failed to create hostapd configuration")
                return False
            
            # Create dnsmasq configuration
            self.ap_logger.info("Creating dnsmasq configuration...")
            if not self._create_dnsmasq_config(dns_enabled=True, captive=captive):
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
    
    def _wardriving_engine(self):
        """Return the running wardriving engine instance, or None."""
        try:
            ragnar = getattr(self.shared_data, 'ragnar_instance', None)
            engine = getattr(ragnar, '_wd_engine', None) if ragnar else None
            if engine is not None and getattr(engine, '_running', False):
                return engine
        except Exception:
            pass
        return None

    def _find_wardrive_ap_interface(self):
        """Pick a WiFi adapter to host the KEY1 AP on.

        Preference order, so wardriving AND an active WiFi uplink keep running
        whenever the hardware allows:
          1. a radio used by neither wardriving nor the live WiFi connection;
          2. any radio not used by wardriving (may be the WiFi uplink — the
             caller drops that connection cleanly before taking it over);
          3. None — every radio is busy wardriving (caller pauses wardriving).
        """
        try:
            engine = self._wardriving_engine()
            busy = set(getattr(engine, 'interfaces', []) or []) if engine else set()
            station = self.default_wifi_interface if getattr(self, 'wifi_connected', False) else None
            names = [i.get('name', '') for i in gather_wifi_interfaces(self.default_wifi_interface)]
            free = [n for n in names if n and n not in busy]
            for name in free:
                if name != station:
                    return name
            if free:
                return free[0]
        except Exception as exc:
            self.logger.debug(f"Wardrive AP interface detection failed: {exc}")
        return None

    def start_wardrive_ap(self):
        """KEY1 toggle: bring up the phone-access AP that serves the minimal
        wardriving page, WITHOUT stopping wardriving.

        The AP runs on a spare adapter when one exists; otherwise it BORROWS a
        radio from wardriving's scan set (removing it so the scan loop's
        _prepare_interface won't force it back to managed and collapse the AP).
        Wardriving keeps running on its remaining adapters (or simply pauses
        scanning if that was the only radio — the engine, GPS, BT and
        companions stay alive). A second call tears the AP down and hands the
        radio back to wardriving. Safe to call from a button-handler thread.
        """
        if getattr(self.shared_data, 'wardrive_ap_active', False) or self.ap_mode_active:
            return self.stop_wardrive_ap()

        engine = self._wardriving_engine()
        self._wardrive_ap_lent_iface = None

        # 1) Prefer a genuine spare (multi-adapter rigs).
        iface = self._find_wardrive_ap_interface()
        # 2) Otherwise borrow one from wardriving's scan set — preferring the
        # built-in radio (the designed AP interface), so a premium USB scanner
        # like an Alfa keeps scanning and the AP lands on a radio that can
        # actually run hostapd.
        if iface is None and engine is not None:
            iface = engine.lend_interface_for_ap(prefer=self.default_wifi_interface)
            self._wardrive_ap_lent_iface = iface
        # 3) Last resort.
        if iface is None:
            iface = self.default_wifi_interface

        # If we're taking the live WiFi uplink, drop it cleanly first — a single
        # chip can't be both a station and an AP.
        if getattr(self, 'wifi_connected', False) and iface == self.default_wifi_interface:
            self.logger.info(f"Wardrive AP: reclaiming {iface} from the WiFi uplink (WiFi will drop)")
            try:
                self.disconnect_wifi()
            except Exception as e:
                self.logger.warning(f"Wardrive AP: disconnect_wifi failed: {e}")

        self._wardrive_ap_prev_interface = self.ap_interface
        self.ap_interface = iface
        self.logger.info(f"Wardrive AP: starting on {iface} (SSID={self.ap_ssid})")
        # captive=False: this AP is a viewer for the wardriving page, not an
        # internet path. Advertising no gateway/DNS keeps the phone's cellular
        # data working while it's joined (see _dnsmasq_config_no_internet).
        if self.start_ap_mode(captive=False):
            self.shared_data.wardrive_ap_active = True
            self.shared_data.wardrive_ap_url = f"{self.ap_ip}:8000"
            self.shared_data.wardrive_ap_iface = iface
            self.logger.info(
                f"Wardrive AP up: join '{self.ap_ssid}' then open http://{self.ap_ip}:8000/")
            return True

        # Start failed — restore prior interface and hand the radio back.
        self.ap_interface = self._wardrive_ap_prev_interface or self.default_wifi_interface
        if self._wardrive_ap_lent_iface and engine is not None:
            engine.reclaim_interface_from_ap(self._wardrive_ap_lent_iface)
        self._wardrive_ap_lent_iface = None
        self.logger.error("Wardrive AP: failed to start AP mode")
        return False

    def stop_wardrive_ap(self):
        """Tear down the wardriving AP and hand the radio back to wardriving,
        which automatically claims it for scanning again."""
        iface = getattr(self.shared_data, 'wardrive_ap_iface', '') or self.ap_interface
        try:
            self.stop_ap_mode()
        finally:
            if self._wardrive_ap_prev_interface:
                self.ap_interface = self._wardrive_ap_prev_interface
                self._wardrive_ap_prev_interface = None
            self.shared_data.wardrive_ap_active = False
            self.shared_data.wardrive_ap_url = ''
            self.shared_data.wardrive_ap_iface = ''
            engine = self._wardriving_engine()
            if engine is not None and iface:
                engine.reclaim_interface_from_ap(iface)
            self._wardrive_ap_lent_iface = None
        self.logger.info("Wardrive AP stopped")
        return True

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
    
    def _dnsmasq_config_no_internet(self):
        """dnsmasq profile for an accessory AP that must NOT become the client's
        internet path — used by the wardriving phone-access AP.

        Ragnar never routes for AP clients (there is no NAT, no ip_forward, and
        while wardriving the radio is usually borrowed so there's no uplink at
        all). Handing out a default route and a DNS server anyway is what made
        phones blackhole: iOS would put its default route on Wi-Fi, send every
        request at 192.168.4.1, get nothing back, and show "No Internet".

        So we hand out an address and deliberately nothing else:
          * `dhcp-option=3` with an empty value suppresses the router option, so
            the client installs only the on-link 192.168.4.0/24 route. The
            wardriving page stays reachable; everything else stays on cellular.
          * `dhcp-option=6` empty likewise suppresses DNS, leaving the phone's
            own (cellular) resolvers in place.
          * `port=0` turns the DNS server off entirely — no wildcard hijack, so
            iOS's captive-portal probe simply fails on this interface and the
            network is marked "no internet" instead of trapping traffic.
        """
        return f"""# Interface configuration
interface={self.ap_interface}
# DHCP range
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
# DHCP authoritative
dhcp-authoritative
# Bind to specific interface only
bind-interfaces
# Log DHCP activity
log-dhcp
# No gateway: empty option 3 suppresses the router option so clients keep
# their existing default route (cellular on a phone) for internet.
dhcp-option=3
# No DNS: empty option 6 leaves the client's own resolvers in place.
dhcp-option=6
# DNS server off entirely - no captive-portal hijack on this AP.
port=0
"""

    def _create_dnsmasq_config(self, dns_enabled=True, captive=True):
        """Create dnsmasq configuration file.

        captive=True  — the Wi-Fi-setup AP: hand out ourselves as gateway+DNS and
                        hijack every domain so the captive portal pops up.
        captive=False — an accessory AP (wardriving): hand out an address and
                        nothing else. See _create_dnsmasq_config_no_internet.
        """
        try:
            self.ap_logger.debug("Creating dnsmasq configuration file...")

            if not captive:
                config_content = self._dnsmasq_config_no_internet()
            elif dns_enabled:
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

            if not captive:
                config_type = "accessory AP (no gateway/DNS — clients keep their own internet)"
            else:
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
        """Get current Wi-Fi manager status with real-time SSID check.

        NOTE: This method is intentionally read-only with respect to the
        network storage layer.  It must NEVER call ``_set_current_ssid()``
        because that triggers ``set_active_network()`` which, on a transient
        Wi-Fi check failure, would call ``mark_all_hosts_degraded()`` and
        wipe every alive host to offline.  The endless-loop monitoring
        thread is the sole authority for SSID / network-context changes.
        """
        # Always get fresh connection status and SSID
        network_connected = self.check_network_connectivity()
        wifi_connected = self.check_wifi_connection()
        current_ssid = self.get_current_ssid() if wifi_connected else None

        # Update lightweight connectivity flags only – no storage-layer
        # side-effects (no _set_current_ssid / set_active_network calls).
        self.wifi_connected = wifi_connected
        self.shared_data.wifi_connected = wifi_connected
        self.shared_data.network_connected = network_connected
        
        status = {
            'wifi_connected': wifi_connected,
            'network_connected': network_connected,
            'connection_type': self.last_connection_type if self.last_connection_type else ('wifi' if wifi_connected else None),
            'lan_connected': bool(self.last_ethernet_interface),
            'lan_interface': self.last_ethernet_interface,
            'ap_mode_active': self.ap_mode_active,
            'current_ssid': current_ssid,
            'known_networks_count': len(self.known_networks),
            'connection_attempts': self.connection_attempts,
            'startup_complete': self.startup_complete,
            'available_networks': len(self.available_networks)
        }
        
        # Add AP mode timing information
        if self.ap_mode_active and self.ap_mode_start_time:
            current_time = time.time()
            ap_uptime = current_time - self.ap_mode_start_time
            
            # Calculate remaining time
            if self.user_connected_to_ap and self.ap_user_connection_time:
                # User is connected - show time since connection
                user_connection_time = current_time - self.ap_user_connection_time
                remaining_time = max(0, self.ap_mode_timeout - user_connection_time)
                status['ap_timer_type'] = 'user_connected'
                status['ap_user_connection_time'] = int(user_connection_time)
            else:
                # No user connected - show general AP timeout
                remaining_time = max(0, self.ap_mode_timeout - ap_uptime)
                status['ap_timer_type'] = 'waiting_for_connection'
                
            status['ap_time_remaining'] = int(remaining_time)
            status['ap_total_timeout'] = self.ap_mode_timeout
            status['ap_uptime'] = int(ap_uptime)
            status['user_connected_to_ap'] = self.user_connected_to_ap
            status['force_exit_requested'] = self.force_exit_ap_mode
        
        return status
    
    def get_known_networks(self):
        """Get list of known networks (without passwords)"""
        return [{
            'ssid': net['ssid'],
            'priority': net.get('priority', 1),
            'added_date': net.get('added_date', ''),
            'has_password': bool(net.get('password'))
        } for net in self.known_networks]
    
    def get_available_networks(self, interface=None):
        """Get list of available networks from last scan"""
        explicit_request = isinstance(interface, str) and interface.strip() != ''
        target_iface = self._resolve_scan_interface(interface)
        cached_networks, _ = self._get_cached_interface_networks(target_iface)
        if cached_networks is not None:
            return cached_networks
        if explicit_request:
            return self.scan_networks(interface=target_iface)
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
