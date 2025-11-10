# orchestrator.py
# Description:
# This file, orchestrator.py, is the heuristic Ragnar brain, and it is responsible for coordinating and executing various network scanning and offensive security actions 
# It manages the loading and execution of actions, handles retries for failed and successful actions, 
# and updates the status of the orchestrator.
#
# Key functionalities include:
# - Initializing and loading actions from a configuration file, including network and vulnerability scanners.
# - Managing the execution of actions on network targets, checking for open ports and handling retries based on success or failure.
# - Coordinating the execution of parent and child actions, ensuring actions are executed in a logical order.
# - Running the orchestrator cycle to continuously check for and execute actions on available network targets.
# - Handling and updating the status of the orchestrator, including scanning for new targets and performing vulnerability scans.
# - Implementing threading to manage concurrent execution of actions with a semaphore to limit active threads.
# - Logging events and errors to ensure maintainability and ease of debugging.
# - Handling graceful degradation by managing retries and idle states when no new targets are found.

import json
import importlib
import os
import time
import logging
import sys
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from actions.nmap_vuln_scanner import NmapVulnScanner
from init_shared import shared_data
from logger import Logger
from resource_monitor import resource_monitor

logger = Logger(name="orchestrator.py", level=logging.DEBUG)

class Orchestrator:
    def __init__(self):
        """Initialise the orchestrator"""
        self.shared_data = shared_data
        self.actions = []  # List of actions to be executed
        self.standalone_actions = []  # List of standalone actions to be executed
        self.failed_scans_count = 0  # Count the number of failed scans
        self.network_scanner = None
        self.last_vuln_scan_time = datetime.min  # Set the last vulnerability scan time to the minimum datetime value
        
        # Verify critical configuration attributes exist
        self._verify_config_attributes()
        
        self.load_actions()  # Load all actions from the actions file
        actions_loaded = [action.__class__.__name__ for action in self.actions + self.standalone_actions]  # Get the names of the loaded actions
        logger.info(f"Actions loaded: {actions_loaded}")
        
        # CRITICAL: Pi Zero W2 resource management - limit concurrent actions
        # Running too many actions simultaneously causes memory exhaustion and hangs
        self.semaphore = threading.Semaphore(2)  # Max 2 concurrent actions for Pi Zero W2
        
        # Thread pool executor for timeout-protected action execution
        self.executor = ThreadPoolExecutor(
            max_workers=2,  # Match semaphore limit for Pi Zero W2
            thread_name_prefix="RagnarAction"
        )
        
        # Default timeout for action execution (in seconds)
        self.action_timeout = getattr(self.shared_data, 'action_timeout', 300)  # 5 minutes default
        self.vuln_scan_timeout = getattr(self.shared_data, 'vuln_scan_timeout', 600)  # 10 minutes for vuln scans
    
    def _verify_config_attributes(self):
        """Verify that all required configuration attributes exist on shared_data."""
        required_attrs = {
            'retry_success_actions': True,
            'retry_failed_actions': True,
            'success_retry_delay': 300,
            'failed_retry_delay': 180,
            'scan_vuln_running': True,
            'enable_attacks': True,
            'scan_vuln_interval': 300,
            'scan_interval': 180,
            'action_timeout': 300,  # 5 minutes timeout for regular actions
            'vuln_scan_timeout': 600  # 10 minutes timeout for vulnerability scans
        }
        
        for attr, default_value in required_attrs.items():
            if not hasattr(self.shared_data, attr):
                logger.warning(f"Missing config attribute '{attr}', setting default value: {default_value}")
                setattr(self.shared_data, attr, default_value)

    def _should_retry(self, action_key, row, status_type='success'):
        """
        Check if an action should be retried based on its status and retry configuration.
        
        Args:
            action_key: The action name/key to check
            row: The data row containing action status
            status_type: Either 'success' or 'failed'
            
        Returns:
            tuple: (should_retry: bool, reason: str or None)
                   - (True, None) if action should proceed
                   - (False, reason_string) if action should be skipped with reason
        """
        action_status = row.get(action_key, "")
        
        if status_type == 'success':
            if 'success' not in action_status:
                return (True, None)
            
            retry_enabled = getattr(self.shared_data, 'retry_success_actions', True)
            if not retry_enabled:
                return (False, "success retry disabled")
            
            delay = getattr(self.shared_data, 'success_retry_delay', 300)
            status_prefix = 'success'
        elif status_type == 'failed':
            if 'failed' not in action_status:
                return (True, None)
            
            retry_enabled = getattr(self.shared_data, 'retry_failed_actions', True)
            if not retry_enabled:
                return (False, "failed retry disabled")
            
            delay = getattr(self.shared_data, 'failed_retry_delay', 180)
            status_prefix = 'failed'
        else:
            logger.error(f"Invalid status_type: {status_type}")
            return (True, None)
        
        # Parse timestamp from status string (format: status_YYYYMMDD_HHMMSS)
        try:
            parts = action_status.split('_')
            if len(parts) >= 3:
                timestamp_str = f"{parts[1]}_{parts[2]}"
                last_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                
                retry_time = last_time + timedelta(seconds=delay)
                if datetime.now() < retry_time:
                    retry_in_seconds = (retry_time - datetime.now()).seconds
                    formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                    return (False, f"{status_prefix} retry delay, retry possible in: {formatted_retry_in}")
        except (ValueError, IndexError) as e:
            logger.warning(f"Error parsing timestamp for {action_key}: {e}")
            # If we can't parse timestamp, allow retry
            return (True, None)
        
        return (True, None)
    
    def _update_action_status(self, row, action_key, result):
        """
        Update action status with timestamp.
        
        Args:
            row: The data row to update
            action_key: The action name/key
            result: 'success' or 'failed'
            
        Returns:
            str: The formatted status string
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        status = f"{result}_{timestamp}"
        row[action_key] = status
        return status
    
    def _execute_with_timeout(self, action_callable, timeout, action_name="unknown"):
        """
        Execute an action with a timeout to prevent hanging.
        
        Args:
            action_callable: Callable that executes the action
            timeout: Maximum execution time in seconds
            action_name: Name of the action for logging
            
        Returns:
            str: 'success', 'failed', or 'timeout'
        """
        try:
            future = self.executor.submit(action_callable)
            result = future.result(timeout=timeout)
            return result
        except FutureTimeoutError:
            logger.error(f"Action {action_name} timed out after {timeout} seconds")
            # Cancel the future to prevent resource leaks
            future.cancel()
            return 'timeout'
        except Exception as e:
            logger.error(f"Action {action_name} raised exception: {e}")
            return 'failed'

    def load_actions(self):
        """Load all actions from the actions file"""
        self.actions_dir = self.shared_data.actions_dir
        
        # Check if actions file exists
        if not os.path.exists(self.shared_data.actions_file):
            logger.error(f"Actions file not found at {self.shared_data.actions_file}")
            logger.error("Cannot load actions. Orchestrator may not function properly.")
            return
            
        try:
            with open(self.shared_data.actions_file, 'r') as file:
                actions_config = json.load(file)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse actions file: {e}")
            return
        except Exception as e:
            logger.error(f"Error reading actions file: {e}")
            return
            
        for action in actions_config:
            module_name = action.get("b_module")
            if not module_name:
                logger.warning(f"Action missing b_module field: {action}")
                continue
                
            try:
                if module_name == 'scanning':
                    self.load_scanner(module_name)
                elif module_name == 'nmap_vuln_scanner':
                    self.load_nmap_vuln_scanner(module_name)
                else:
                    self.load_action(module_name, action)
            except Exception as e:
                logger.error(f"Failed to load action {module_name}: {e}")

    def load_scanner(self, module_name):
        """Load the network scanner"""
        try:
            module = importlib.import_module(f'actions.{module_name}')
            b_class = getattr(module, 'b_class', None)
            if not b_class:
                logger.error(f"Module {module_name} missing 'b_class' attribute")
                return
            self.network_scanner = getattr(module, b_class)(self.shared_data)
            logger.info(f"Network scanner {b_class} loaded successfully")
        except ImportError as e:
            logger.error(f"Failed to import scanner module {module_name}: {e}")
        except Exception as e:
            logger.error(f"Error loading scanner {module_name}: {e}")

    def load_nmap_vuln_scanner(self, module_name):
        """Load the nmap vulnerability scanner"""
        try:
            self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)
            logger.info("Nmap vulnerability scanner loaded successfully")
        except Exception as e:
            logger.error(f"Error loading nmap vulnerability scanner: {e}")
            self.nmap_vuln_scanner = None

    def load_action(self, module_name, action):
        """Load an action from the actions file"""
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = action["b_class"]
            action_instance = getattr(module, b_class)(self.shared_data)
            action_instance.action_name = b_class
            action_instance.port = action.get("b_port")
            action_instance.b_parent_action = action.get("b_parent")
            if action_instance.port == 0:
                self.standalone_actions.append(action_instance)
            else:
                self.actions.append(action_instance)
        except AttributeError as e:
            logger.error(f"Module {module_name} is missing required attributes: {e}")

    def process_alive_ips(self, current_data):
        """Process all IPs with alive status set to 1"""
        any_action_executed = False
        action_executed_status = None

        for action in self.actions:
            for row in current_data:
                if row["Alive"] != '1':
                    continue
                ip, ports = row["IPs"], row["Ports"].split(';')
                action_key = action.action_name

                if action.b_parent_action is None:
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            action_executed_status = action_key
                            any_action_executed = True
                            self.shared_data.ragnarorch_status = action_executed_status

                            for child_action in self.actions:
                                if child_action.b_parent_action == action_key:
                                    with self.semaphore:
                                        if self.execute_action(child_action, ip, ports, row, child_action.action_name, current_data):
                                            action_executed_status = child_action.action_name
                                            self.shared_data.ragnarorch_status = action_executed_status
                                            break
                            break

        for child_action in self.actions:
            if child_action.b_parent_action:
                action_key = child_action.action_name
                for row in current_data:
                    ip, ports = row["IPs"], row["Ports"].split(';')
                    with self.semaphore:
                        if self.execute_action(child_action, ip, ports, row, action_key, current_data):
                            action_executed_status = child_action.action_name
                            any_action_executed = True
                            self.shared_data.ragnarorch_status = action_executed_status
                            break

        return any_action_executed


    def execute_action(self, action, ip, ports, row, action_key, current_data):
        """Execute an action on a target with timeout protection"""
        if hasattr(action, 'port') and str(action.port) not in ports:
            return False

        # Check if attacks are enabled (skip attack actions if disabled, but allow scanning)
        enable_attacks = getattr(self.shared_data, 'enable_attacks', True)
        attack_action_names = [
            'SSHBruteforce', 'FTPBruteforce', 'TelnetBruteforce', 
            'RDPBruteforce', 'SMBBruteforce', 'SQLBruteforce',
            'SSHConnector', 'FTPConnector', 'TelnetConnector', 
            'RDPConnector', 'SMBConnector', 'SQLConnector',
            'StealDataSQL', 'StealFilesFTP', 'StealFilesRDP', 
            'StealFilesSMB', 'StealFilesSSH', 'StealFilesTelnet'
        ]
        if not enable_attacks and action.action_name in attack_action_names:
            logger.debug(f"Skipping attack action {action.action_name} for {ip}:{action.port} - attacks are disabled")
            return False

        # Check parent action status
        if action.b_parent_action:
            parent_status = row.get(action.b_parent_action, "")
            if 'success' not in parent_status:
                return False  # Skip child action if parent action has not succeeded

        # Check success retry logic using helper
        should_retry, reason = self._should_retry(action_key, row, 'success')
        if not should_retry:
            logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to {reason}")
            return False

        # Check failed retry logic using helper
        should_retry, reason = self._should_retry(action_key, row, 'failed')
        if not should_retry:
            logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to {reason}")
            return False

        # CRITICAL: Check system resources before executing action (Pi Zero W2 protection)
        if not resource_monitor.can_start_operation(
            operation_name=f"action_{action.action_name}",
            min_memory_mb=30  # Require at least 30MB free memory
        ):
            logger.warning(
                f"Skipping action {action.action_name} for {ip}:{action.port} - "
                f"Insufficient system resources (preventing hang)"
            )
            return False

        try:
            logger.info(f"Executing action {action.action_name} for {ip}:{action.port}")
            self.shared_data.ragnarstatustext2 = ip
            
            # Execute action with timeout protection
            action_callable = lambda: action.execute(ip, str(action.port), row, action_key)
            result = self._execute_with_timeout(
                action_callable,
                timeout=self.action_timeout,
                action_name=f"{action.action_name}@{ip}:{action.port}"
            )
            
            # Update status using helper (timeout is treated as failed)
            if result == 'timeout':
                result_status = 'failed'
                logger.error(f"Action {action.action_name} for {ip}:{action.port} timed out")
            else:
                result_status = 'success' if result == 'success' else 'failed'
            
            self._update_action_status(row, action_key, result_status)
            
            if result == 'success':
                # Update stats immediately after successful action
                try:
                    self.shared_data.update_stats()
                    logger.debug(f"Updated stats after successful {action.action_name}")
                except Exception as stats_error:
                    logger.warning(f"Could not update stats: {stats_error}")
            
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Action {action.action_name} failed: {e}")
            self._update_action_status(row, action_key, 'failed')
            self.shared_data.write_data(current_data)
            return False

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone action with timeout protection"""
        row = next((r for r in current_data if r["MAC Address"] == "STANDALONE"), None)
        if not row:
            row = {
                "MAC Address": "STANDALONE",
                "IPs": "STANDALONE",
                "Hostnames": "STANDALONE",
                "Ports": "0",
                "Alive": "0"
            }
            current_data.append(row)

        action_key = action.action_name
        if action_key not in row:
            row[action_key] = ""

        # Check success retry logic using helper
        should_retry, reason = self._should_retry(action_key, row, 'success')
        if not should_retry:
            logger.warning(f"Skipping standalone action {action.action_name} due to {reason}")
            return False

        # Check failed retry logic using helper
        should_retry, reason = self._should_retry(action_key, row, 'failed')
        if not should_retry:
            logger.warning(f"Skipping standalone action {action.action_name} due to {reason}")
            return False

        try:
            logger.info(f"Executing standalone action {action.action_name}")
            
            # Execute action with timeout protection
            action_callable = lambda: action.execute()
            result = self._execute_with_timeout(
                action_callable,
                timeout=self.action_timeout,
                action_name=f"standalone_{action.action_name}"
            )
            
            # Update status using helper (timeout is treated as failed)
            if result == 'timeout':
                result_status = 'failed'
                logger.error(f"Standalone action {action.action_name} timed out")
            else:
                result_status = 'success' if result == 'success' else 'failed'
            
            self._update_action_status(row, action_key, result_status)
            
            if result == 'success':
                logger.info(f"Standalone action {action.action_name} executed successfully")
                # Update stats immediately after successful standalone action
                try:
                    self.shared_data.update_stats()
                    logger.debug(f"Updated stats after successful standalone {action.action_name}")
                except Exception as stats_error:
                    logger.warning(f"Could not update stats: {stats_error}")
            else:
                logger.error(f"Standalone action {action.action_name} failed")
            
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone action {action.action_name} failed: {e}")
            self._update_action_status(row, action_key, 'failed')
            self.shared_data.write_data(current_data)
            return False

    def run_vulnerability_scans(self):
        """Run vulnerability scans on all alive hosts with timeout protection"""
        scan_vuln_running = getattr(self.shared_data, 'scan_vuln_running', True)
        
        if not scan_vuln_running or not self.nmap_vuln_scanner:
            return
            
        try:
            current_data = self.shared_data.read_data()
            alive_hosts = [row for row in current_data if row.get("Alive") == '1']
            
            if not alive_hosts:
                logger.debug("No alive hosts found for vulnerability scanning")
                return
                
            logger.info(f"Starting vulnerability scans on {len(alive_hosts)} alive hosts...")
            scans_performed = 0
            
            for row in alive_hosts:
                ip = row.get("IPs", "")
                if not ip or ip == "STANDALONE":
                    continue
                
                action_key = "NmapVulnScanner"
                
                # Initialize action_key if not present
                if action_key not in row:
                    row[action_key] = ""
                
                # Check success retry logic using helper
                should_retry, reason = self._should_retry(action_key, row, 'success')
                if not should_retry:
                    continue
                
                # Check failed retry logic using helper
                should_retry, reason = self._should_retry(action_key, row, 'failed')
                if not should_retry:
                    continue
                
                # Check system resources
                if not resource_monitor.can_start_operation(
                    operation_name=f"vuln_scan_{ip}",
                    min_memory_mb=30
                ):
                    logger.warning(f"Insufficient resources to scan {ip} - skipping")
                    continue
                
                try:
                    logger.info(f"Vulnerability scanning {ip}...")
                    
                    # Execute vulnerability scan with timeout protection
                    scan_callable = lambda: self.nmap_vuln_scanner.execute(ip, row, action_key)
                    result = self._execute_with_timeout(
                        scan_callable,
                        timeout=self.vuln_scan_timeout,
                        action_name=f"NmapVulnScanner@{ip}"
                    )
                    
                    # Update status using helper (timeout is treated as failed)
                    if result == 'timeout':
                        result_status = 'failed'
                        logger.error(f"Vulnerability scan for {ip} timed out")
                    else:
                        result_status = 'success' if result == 'success' else 'failed'
                    
                    self._update_action_status(row, action_key, result_status)
                    
                    if result == 'success':
                        logger.info(f"Vulnerability scan successful for {ip}")
                    else:
                        logger.warning(f"Vulnerability scan failed for {ip}")
                    
                    self.shared_data.write_data(current_data)
                    scans_performed += 1
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")
                    self._update_action_status(row, action_key, 'failed')
                    self.shared_data.write_data(current_data)
            
            self.last_vuln_scan_time = datetime.now()
            if scans_performed > 0:
                logger.info(f"Completed {scans_performed} vulnerability scans")
            else:
                logger.debug("No vulnerability scans needed at this time")
                
        except Exception as e:
            logger.error(f"Error during vulnerability scanning cycle: {e}")

    def run(self):
        """
        Run the orchestrator cycle with proper scan order:
        1. ARP Ping Scan (fast host discovery)
        2. Nmap Port Scan (discover open ports)
        3. Nmap Vulnerability Scan (scan for vulnerabilities)
        4. Attacks (if enabled)
        5. Loop
        
        Scans ALWAYS run regardless of enable_attacks setting.
        Only attack actions respect the enable_attacks flag.
        """
        # Use getattr for safe config access
        scan_vuln_running = getattr(self.shared_data, 'scan_vuln_running', True)
        scan_vuln_interval = getattr(self.shared_data, 'scan_vuln_interval', 300)
        scan_interval = getattr(self.shared_data, 'scan_interval', 180)
        enable_attacks = getattr(self.shared_data, 'enable_attacks', True)
        
        # ====================================================================
        # PHASE 1: Initial ARP + Port Scan
        # ====================================================================
        logger.info("=" * 70)
        logger.info("ORCHESTRATOR STARTUP - PHASE 1: ARP + Port Scan")
        logger.info("=" * 70)
        
        if self.network_scanner:
            self.shared_data.ragnarorch_status = "NetworkScanner"
            self.shared_data.ragnarstatustext2 = "Initial scan..."
            self.network_scanner.scan()  # This does ARP ping scan + port scan
            self.shared_data.ragnarstatustext2 = ""
            logger.info("✓ Phase 1 complete: Network hosts and ports discovered")
        else:
            logger.error("Network scanner not initialized. Cannot start orchestrator.")
            return
        
        # ====================================================================
        # PHASE 2: Initial Vulnerability Scan
        # ====================================================================
        logger.info("=" * 70)
        logger.info("ORCHESTRATOR STARTUP - PHASE 2: Vulnerability Scan")
        logger.info("=" * 70)
        
        if scan_vuln_running and self.nmap_vuln_scanner:
            logger.info("Running initial vulnerability scan on all discovered hosts...")
            self.run_vulnerability_scans()
            logger.info("✓ Phase 2 complete: Vulnerability scan finished")
        else:
            logger.info("⊘ Phase 2 skipped: Vulnerability scanning disabled")
        
        # ====================================================================
        # PHASE 3: Attack Phase (if enabled)
        # ====================================================================
        logger.info("=" * 70)
        logger.info(f"ORCHESTRATOR STARTUP - PHASE 3: Attack Phase (enabled={enable_attacks})")
        logger.info("=" * 70)
        
        if enable_attacks:
            logger.info("Attack phase enabled - will execute attack actions in main loop")
        else:
            logger.info("⊘ Attack phase disabled - will skip attack actions")
        
        # Log initial system status
        resource_monitor.log_system_status()
        last_resource_log_time = time.time()
        last_vuln_scan_check = time.time()
        last_network_scan_time = time.time()
        cycle_count = 0
        
        logger.info("=" * 70)
        logger.info("ENTERING MAIN ORCHESTRATOR LOOP")
        logger.info("=" * 70)
        
        while not self.shared_data.orchestrator_should_exit:
            cycle_count += 1
            logger.info(f"\n{'=' * 70}")
            logger.info(f"ORCHESTRATOR CYCLE #{cycle_count}")
            logger.info(f"{'=' * 70}")
            
            # Periodically log resource status (every 5 minutes)
            if time.time() - last_resource_log_time > 300:
                resource_monitor.log_system_status()
                last_resource_log_time = time.time()
                
                # Force garbage collection if memory is high
                if resource_monitor.get_memory_usage() > 75:
                    logger.info("High memory usage detected - forcing garbage collection")
                    resource_monitor.force_garbage_collection()
            
            # ================================================================
            # CYCLE PHASE 1: Periodic Network Scan (ARP + Port Scan)
            # ================================================================
            current_time = time.time()
            scan_interval = getattr(self.shared_data, 'scan_interval', scan_interval)
            if current_time - last_network_scan_time >= scan_interval:
                logger.info(f"→ Cycle Phase 1: ARP + Port Scan (interval: {scan_interval}s)")
                if self.network_scanner:
                    self.shared_data.ragnarorch_status = "NetworkScanner"
                    self.network_scanner.scan()
                    last_network_scan_time = current_time
                    logger.info("✓ Network scan complete")
                else:
                    logger.warning("Network scanner not available")
            else:
                remaining = int(scan_interval - (current_time - last_network_scan_time))
                logger.debug(f"⊘ Network scan skipped (next in {remaining}s)")
            
            # ================================================================
            # CYCLE PHASE 2: Periodic Vulnerability Scan
            # ================================================================
            scan_vuln_running = getattr(self.shared_data, 'scan_vuln_running', scan_vuln_running)
            scan_vuln_interval = getattr(self.shared_data, 'scan_vuln_interval', scan_vuln_interval)
            if scan_vuln_running and (time.time() - last_vuln_scan_check >= scan_vuln_interval):
                logger.info(f"→ Cycle Phase 2: Vulnerability Scan (interval: {scan_vuln_interval}s)")
                self.run_vulnerability_scans()
                last_vuln_scan_check = time.time()
                logger.info("✓ Vulnerability scan complete")
            else:
                if scan_vuln_running:
                    remaining = int(scan_vuln_interval - (time.time() - last_vuln_scan_check))
                    logger.debug(f"⊘ Vulnerability scan skipped (next in {remaining}s)")
                else:
                    logger.debug("⊘ Vulnerability scanning disabled")
            
            # ================================================================
            # CYCLE PHASE 3: Attack Phase (only if enabled)
            # ================================================================
            enable_attacks = getattr(self.shared_data, 'enable_attacks', enable_attacks)
            if enable_attacks:
                logger.info("→ Cycle Phase 3: Attack Phase (executing attack actions)")
            else:
                logger.debug("⊘ Cycle Phase 3: Attack Phase (disabled - skipping all attacks)")
            
            # CRITICAL: Check system health before processing actions
            if not resource_monitor.is_system_healthy():
                logger.warning("System resources critical - pausing orchestrator for 30 seconds")
                resource_monitor.log_system_status()
                time.sleep(30)
                continue
            
            current_data = self.shared_data.read_data()
            any_action_executed = False
            action_retry_pending = False
            
            # Execute actions (only attack actions will be filtered by enable_attacks)
            any_action_executed = self.process_alive_ips(current_data)

            self.shared_data.write_data(current_data)

            if not any_action_executed:
                if enable_attacks:
                    logger.info("✓ No attack actions to execute at this time")
                else:
                    logger.debug("⊘ Attack actions skipped (disabled)")
                    
                self.shared_data.ragnarorch_status = "IDLE"
                self.shared_data.ragnarstatustext2 = ""
                
                # Check if we should run a network scan
                if current_time - last_network_scan_time >= scan_interval:
                    logger.info("No targets available - running network scan...")
                    if self.network_scanner:
                        self.shared_data.ragnarorch_status = "NetworkScanner"
                        self.network_scanner.scan()
                        last_network_scan_time = time.time()
                        # Re-read the updated data after the scan
                        current_data = self.shared_data.read_data()
                        if enable_attacks:
                            any_action_executed = self.process_alive_ips(current_data)
                    else:
                        logger.warning("No network scanner available.")
                
                self.failed_scans_count += 1
                if self.failed_scans_count >= 1:
                    for action in self.standalone_actions:
                        with self.semaphore:
                            if self.execute_standalone_action(action, current_data):
                                self.failed_scans_count = 0
                                break
                    
                    # Idle period before next cycle
                    idle_start_time = datetime.now()
                    idle_end_time = idle_start_time + timedelta(seconds=scan_interval)
                    while datetime.now() < idle_end_time:
                        if self.shared_data.orchestrator_should_exit:
                            break
                        remaining_time = (idle_end_time - datetime.now()).seconds
                        self.shared_data.ragnarorch_status = "IDLE"
                        self.shared_data.ragnarstatustext2 = ""
                        sys.stdout.write('\x1b[1A\x1b[2K')
                        logger.warning(f"Idle - Next cycle in: {remaining_time} seconds")
                        time.sleep(1)
                    self.failed_scans_count = 0
                    continue
            else:
                if enable_attacks:
                    logger.info("✓ Attack actions executed successfully")
                self.failed_scans_count = 0
                action_retry_pending = True

            if action_retry_pending:
                self.failed_scans_count = 0
            
            logger.info(f"{'=' * 70}")
            logger.info(f"END OF CYCLE #{cycle_count}")
            logger.info(f"{'=' * 70}\n")
    
    def shutdown(self):
        """Gracefully shutdown the orchestrator and cleanup resources"""
        logger.info("Shutting down orchestrator...")
        try:
            # Shutdown the executor and wait for running tasks to complete (max 30 seconds)
            self.executor.shutdown(wait=True, cancel_futures=False)
            logger.info("Thread pool executor shutdown complete")
        except Exception as e:
            logger.error(f"Error during executor shutdown: {e}")

if __name__ == "__main__":
    orchestrator = Orchestrator()
    try:
        orchestrator.run()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        orchestrator.shutdown()
