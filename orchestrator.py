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
            'scan_interval': 180
        }
        
        for attr, default_value in required_attrs.items():
            if not hasattr(self.shared_data, attr):
                logger.warning(f"Missing config attribute '{attr}', setting default value: {default_value}")
                setattr(self.shared_data, attr, default_value)

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
        """Execute an action on a target"""
        if hasattr(action, 'port') and str(action.port) not in ports:
            return False

        # Check if attacks are enabled (skip attack actions if disabled, but allow scanning)
        enable_attacks = getattr(self.shared_data, 'enable_attacks', True)
        attack_action_names = ['SSHConnector', 'FTPConnector', 'TelnetConnector', 'RDPConnector', 'SMBConnector', 'SQLConnector']
        if not enable_attacks and action.action_name in attack_action_names:
            logger.debug(f"Skipping attack action {action.action_name} for {ip}:{action.port} - attacks are disabled")
            return False

        # Check parent action status
        if action.b_parent_action:
            parent_status = row.get(action.b_parent_action, "")
            if 'success' not in parent_status:
                return False  # Skip child action if parent action has not succeeded

        # Check if the action is already successful and if retries are disabled for successful actions
        retry_success = getattr(self.shared_data, 'retry_success_actions', True)
        success_delay = getattr(self.shared_data, 'success_retry_delay', 300)
        
        if 'success' in row[action_key]:
            if not retry_success:
                return False
            else:
                try:
                    last_success_time = datetime.strptime(row[action_key].split('_')[1] + "_" + row[action_key].split('_')[2], "%Y%m%d_%H%M%S")
                    if datetime.now() < last_success_time + timedelta(seconds=success_delay):
                        retry_in_seconds = (last_success_time + timedelta(seconds=success_delay) - datetime.now()).seconds
                        formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                        logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to success retry delay, retry possible in: {formatted_retry_in}")
                        return False  # Skip if the success retry delay has not passed
                except ValueError as ve:
                    logger.error(f"Error parsing last success time for {action.action_name}: {ve}")

        retry_failed = getattr(self.shared_data, 'retry_failed_actions', True)
        failed_delay = getattr(self.shared_data, 'failed_retry_delay', 180)
        
        last_failed_time_str = row.get(action_key, "")
        if 'failed' in last_failed_time_str:
            if not retry_failed:
                return False  # Skip retrying failed actions if retry_failed_actions is disabled
            try:
                last_failed_time = datetime.strptime(last_failed_time_str.split('_')[1] + "_" + last_failed_time_str.split('_')[2], "%Y%m%d_%H%M%S")
                if datetime.now() < last_failed_time + timedelta(seconds=failed_delay):
                    retry_in_seconds = (last_failed_time + timedelta(seconds=failed_delay) - datetime.now()).seconds
                    formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                    logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to failed retry delay, retry possible in: {formatted_retry_in}")
                    return False  # Skip if the retry delay has not passed
            except ValueError as ve:
                logger.error(f"Error parsing last failed time for {action.action_name}: {ve}")

        try:
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
            
            logger.info(f"Executing action {action.action_name} for {ip}:{action.port}")
            self.shared_data.ragnarstatustext2 = ip
            result = action.execute(ip, str(action.port), row, action_key)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                # Update stats immediately after successful action
                try:
                    self.shared_data.update_stats()
                    logger.debug(f"Updated stats after successful {action.action_name}")
                except Exception as stats_error:
                    logger.warning(f"Could not update stats: {stats_error}")
            else:
                row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone action"""
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

        # Use getattr for safe config access
        retry_success = getattr(self.shared_data, 'retry_success_actions', True)
        success_delay = getattr(self.shared_data, 'success_retry_delay', 300)
        
        # Check if the action is already successful and if retries are disabled for successful actions
        if 'success' in row[action_key]:
            if not retry_success:
                return False
            else:
                try:
                    last_success_time = datetime.strptime(row[action_key].split('_')[1] + "_" + row[action_key].split('_')[2], "%Y%m%d_%H%M%S")
                    if datetime.now() < last_success_time + timedelta(seconds=success_delay):
                        retry_in_seconds = (last_success_time + timedelta(seconds=success_delay) - datetime.now()).seconds
                        formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                        logger.warning(f"Skipping standalone action {action.action_name} due to success retry delay, retry possible in: {formatted_retry_in}")
                        return False  # Skip if the success retry delay has not passed
                except ValueError as ve:
                    logger.error(f"Error parsing last success time for {action.action_name}: {ve}")

        retry_failed = getattr(self.shared_data, 'retry_failed_actions', True)
        failed_delay = getattr(self.shared_data, 'failed_retry_delay', 180)
        
        last_failed_time_str = row.get(action_key, "")
        if 'failed' in last_failed_time_str:
            if not retry_failed:
                return False  # Skip retrying failed actions if retry_failed_actions is disabled
            try:
                last_failed_time = datetime.strptime(last_failed_time_str.split('_')[1] + "_" + last_failed_time_str.split('_')[2], "%Y%m%d_%H%M%S")
                if datetime.now() < last_failed_time + timedelta(seconds=failed_delay):
                    retry_in_seconds = (last_failed_time + timedelta(seconds=failed_delay) - datetime.now()).seconds
                    formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                    logger.warning(f"Skipping standalone action {action.action_name} due to failed retry delay, retry possible in: {formatted_retry_in}")
                    return False  # Skip if the retry delay has not passed
            except ValueError as ve:
                logger.error(f"Error parsing last failed time for {action.action_name}: {ve}")

        try:
            logger.info(f"Executing standalone action {action.action_name}")
            result = action.execute()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                logger.info(f"Standalone action {action.action_name} executed successfully")
                # Update stats immediately after successful standalone action
                try:
                    self.shared_data.update_stats()
                    logger.debug(f"Updated stats after successful standalone {action.action_name}")
                except Exception as stats_error:
                    logger.warning(f"Could not update stats: {stats_error}")
            else:
                row[action_key] = f'failed_{timestamp}'
                logger.error(f"Standalone action {action.action_name} failed")
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_key] = f'failed_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def run(self):
        """Run the orchestrator cycle to execute actions"""
        # Use getattr for safe config access
        scan_vuln_running = getattr(self.shared_data, 'scan_vuln_running', True)
        scan_vuln_interval = getattr(self.shared_data, 'scan_vuln_interval', 300)
        scan_interval = getattr(self.shared_data, 'scan_interval', 180)
        retry_success = getattr(self.shared_data, 'retry_success_actions', True)
        retry_failed = getattr(self.shared_data, 'retry_failed_actions', True)
        success_delay = getattr(self.shared_data, 'success_retry_delay', 300)
        failed_delay = getattr(self.shared_data, 'failed_retry_delay', 180)
        
        #Run the scanner a first time to get the initial data
        if self.network_scanner:
            self.shared_data.ragnarorch_status = "NetworkScanner"
            self.shared_data.ragnarstatustext2 = "First scan..."
            self.network_scanner.scan()
            self.shared_data.ragnarstatustext2 = ""
            
            # Run initial vulnerability scan on startup if enabled
            if scan_vuln_running and self.nmap_vuln_scanner:
                try:
                    logger.info("Starting initial vulnerability scan on all discovered hosts...")
                    current_data = self.shared_data.read_data()
                    alive_hosts = [row for row in current_data if row.get("Alive") == '1']
                    
                    if alive_hosts:
                        logger.info(f"Found {len(alive_hosts)} alive hosts. Starting vulnerability scans...")
                        for row in alive_hosts:
                            ip = row.get("IPs", "")
                            if not ip:
                                continue
                            
                            try:
                                logger.info(f"Scanning {ip} for vulnerabilities...")
                                with self.semaphore:
                                    result = self.nmap_vuln_scanner.execute(ip, row, "NmapVulnScanner")
                                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                    if result == 'success':
                                        row["NmapVulnScanner"] = f'success_{timestamp}'
                                    else:
                                        row["NmapVulnScanner"] = f'failed_{timestamp}'
                                    self.shared_data.write_data(current_data)
                            except Exception as e:
                                logger.error(f"Error scanning {ip} on startup: {e}")
                        
                        self.last_vuln_scan_time = datetime.now()
                        logger.info("Initial vulnerability scan completed.")
                    else:
                        logger.info("No alive hosts found for initial vulnerability scan.")
                except Exception as e:
                    logger.error(f"Error during initial vulnerability scan: {e}")
        else:
            logger.error("Network scanner not initialized. Cannot start orchestrator.")
        
        # Log initial system status
        resource_monitor.log_system_status()
        last_resource_log_time = time.time()
        
        while not self.shared_data.orchestrator_should_exit:
            # Periodically log resource status (every 5 minutes)
            if time.time() - last_resource_log_time > 300:
                resource_monitor.log_system_status()
                last_resource_log_time = time.time()
                
                # Force garbage collection if memory is high
                if resource_monitor.get_memory_usage() > 75:
                    logger.info("High memory usage detected - forcing garbage collection")
                    resource_monitor.force_garbage_collection()
            
            # CRITICAL: Check system health before processing actions
            if not resource_monitor.is_system_healthy():
                logger.warning("System resources critical - pausing orchestrator for 30 seconds")
                resource_monitor.log_system_status()
                time.sleep(30)
                continue
            
            current_data = self.shared_data.read_data()
            any_action_executed = False
            action_retry_pending = False
            any_action_executed = self.process_alive_ips(current_data)

            self.shared_data.write_data(current_data)

            if not any_action_executed:
                self.shared_data.ragnarorch_status = "IDLE"
                self.shared_data.ragnarstatustext2 = ""
                logger.info("No available targets. Running network scan...")
                if self.network_scanner:
                    self.shared_data.ragnarorch_status = "NetworkScanner"
                    self.network_scanner.scan()
                     # Relire les données mises à jour après le scan
                    current_data = self.shared_data.read_data()
                    any_action_executed = self.process_alive_ips(current_data)
                    if scan_vuln_running and self.nmap_vuln_scanner:
                        current_time = datetime.now()
                        if current_time >= self.last_vuln_scan_time + timedelta(seconds=scan_vuln_interval):
                            try:
                                logger.info("Starting vulnerability scans...")
                                for row in current_data:
                                    if row["Alive"] == '1':
                                        ip = row["IPs"]
                                        scan_status = row.get("NmapVulnScanner", "")

                                        # Check success retry delay
                                        if 'success' in scan_status:
                                            last_success_time = datetime.strptime(scan_status.split('_')[1] + "_" + scan_status.split('_')[2], "%Y%m%d_%H%M%S")
                                            if not retry_success:
                                                logger.warning(f"Skipping vulnerability scan for {ip} because retry on success is disabled.")
                                                continue  # Skip if retry on success is disabled
                                            if datetime.now() < last_success_time + timedelta(seconds=success_delay):
                                                retry_in_seconds = (last_success_time + timedelta(seconds=success_delay) - datetime.now()).seconds
                                                formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                                                logger.warning(f"Skipping vulnerability scan for {ip} due to success retry delay, retry possible in: {formatted_retry_in}")
                                                # Skip if the retry delay has not passed
                                                continue

                                        # Check failed retry delay
                                        if 'failed' in scan_status:
                                            if not retry_failed:
                                                logger.warning(f"Skipping vulnerability scan for {ip} because retry on failure is disabled.")
                                                continue  # Skip if retry on failure is disabled
                                            last_failed_time = datetime.strptime(scan_status.split('_')[1] + "_" + scan_status.split('_')[2], "%Y%m%d_%H%M%S")
                                            if datetime.now() < last_failed_time + timedelta(seconds=failed_delay):
                                                retry_in_seconds = (last_failed_time + timedelta(seconds=failed_delay) - datetime.now()).seconds
                                                formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                                                logger.warning(f"Skipping vulnerability scan for {ip} due to failed retry delay, retry possible in: {formatted_retry_in}")
                                                continue

                                        with self.semaphore:
                                            result = self.nmap_vuln_scanner.execute(ip, row, "NmapVulnScanner")
                                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                            if result == 'success':
                                                row["NmapVulnScanner"] = f'success_{timestamp}'
                                            else:
                                                row["NmapVulnScanner"] = f'failed_{timestamp}'
                                            self.shared_data.write_data(current_data)
                                self.last_vuln_scan_time = current_time
                            except Exception as e:
                                logger.error(f"Error during vulnerability scan: {e}")


                else:
                    logger.warning("No network scanner available.")
                self.failed_scans_count += 1
                if self.failed_scans_count >= 1:
                    for action in self.standalone_actions:
                        with self.semaphore:
                            if self.execute_standalone_action(action, current_data):
                                self.failed_scans_count = 0
                                break
                    idle_start_time = datetime.now()
                    idle_end_time = idle_start_time + timedelta(seconds=scan_interval)
                    while datetime.now() < idle_end_time:
                        if self.shared_data.orchestrator_should_exit:
                            break
                        remaining_time = (idle_end_time - datetime.now()).seconds
                        self.shared_data.ragnarorch_status = "IDLE"
                        self.shared_data.ragnarstatustext2 = ""
                        sys.stdout.write('\x1b[1A\x1b[2K')
                        logger.warning(f"Scanner did not find any new targets. Next scan in: {remaining_time} seconds")
                        time.sleep(1)
                    self.failed_scans_count = 0
                    continue
            else:
                self.failed_scans_count = 0
                action_retry_pending = True

            if action_retry_pending:
                self.failed_scans_count = 0

if __name__ == "__main__":
    orchestrator = Orchestrator()
    orchestrator.run()
