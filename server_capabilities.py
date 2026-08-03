# server_capabilities.py
"""
Server Mode Detection and Advanced Feature Management for Ragnar

This module detects when Ragnar is running on a capable server (AMD64/ARM64 with 8GB+ RAM)
and unlocks advanced features that would be impossible on a Pi Zero W2.

Features unlocked in server mode:
- Advanced Vulnerability Assessment (OpenVAS, Nuclei, Nikto)
- Parallel scanning
- Large dictionary attacks
- Local AI/LLM integration

Not everything heavy-sounding belongs behind that bar. Two features have their
own, much lower gates because what they actually cost has nothing to do with
OpenVAS-class work:
- Traffic Analysis - a tcpdump pipe parsed in Python (see TRAFFIC_MIN_RAM_GB)
- The on-screen kiosk - one Chromium (see KIOSK_MIN_RAM_GB)
"""

import os
import platform
import subprocess
import threading
import logging
import json
import shutil
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

from logger import Logger

logger = Logger(name="server_capabilities", level=logging.INFO)


@dataclass
class SystemCapabilities:
    """Data class representing system hardware capabilities"""
    architecture: str = "unknown"
    cpu_cores: int = 1
    total_ram_gb: float = 0.0
    available_ram_gb: float = 0.0
    is_64bit: bool = False
    is_server_capable: bool = False
    is_pi_zero: bool = False
    kiosk_capable: bool = False
    kiosk_block_reason: str = ""
    traffic_capable: bool = False
    traffic_block_reason: str = ""
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    kernel_version: str = ""
    
    # Feature flags
    traffic_analysis_enabled: bool = False
    traffic_sidecars_enabled: bool = False
    advanced_vuln_enabled: bool = False
    zap_enabled: bool = False
    parallel_scanning_enabled: bool = False
    local_ai_enabled: bool = False
    large_dictionaries_enabled: bool = False
    
    # Tool availability
    available_tools: Dict[str, bool] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ServerCapabilities:
    """
    Detect system capabilities and manage server-mode features.
    
    Server mode is enabled when:
    - Architecture is AMD64 or ARM64 (or armv8l in 32-bit mode on 64-bit Pi)
    - System has at least 7.5GB RAM (allows for system reserved)
    - Not running on Pi Zero
    """
    
    # Minimum requirements for server mode
    # Use 7.5GB to account for system reserved memory on 8GB devices
    MIN_RAM_GB = 7.5
    MIN_CORES = 2
    # OWASP ZAP is a Java daemon that holds ~1GB+ resident on its own and
    # spikes well past that during an active scan. It is the one Advanced Vuln
    # scanner that genuinely needs a server-class box, so it keeps the 7.5GB
    # RAM floor even though the lighter CLI scanners no longer do. (8GB devices
    # report ~7.87GB after firmware/GPU reservations, hence 7.5 not 8.)
    ZAP_MIN_RAM_GB = 7.5
    # The on-screen kiosk drives a full Chromium, which needs ~1GB resident on
    # its own. A Pi Zero 2 W has 512MB total, so the kiosk there thrashes swap
    # and the whole box crawls — Ragnar's own scanning included. Chromium runs
    # fine from 2GB up, so the kiosk floor is its own bar rather than full
    # server mode (a 4GB Pi 4/5 with a screen is a perfectly good kiosk host).
    # 1.8 rather than 2.0 for the same reason MIN_RAM_GB is 7.5 rather than 8:
    # firmware/kernel reservations mean a real 2GB Pi 4 reports ~1.9GB.
    KIOSK_MIN_RAM_GB = 1.8
    KIOSK_MIN_CORES = 2
    # Traffic Analysis is a tcpdump pipe read line by line in Python. Measured
    # on a Pi 5 against a live LAN at ~90 packets/sec: 0.4% of one core, 18MB
    # RSS for the analyzer and 8MB for tcpdump. That is a Pi Zero 2 W workload,
    # not a server one - so it gets its own floor rather than server mode's
    # 7.5GB. Kept above zero only to fail closed when RAM cannot be read; a
    # 512MB Zero 2 W reports ~0.42GB after the GPU split.
    TRAFFIC_MIN_RAM_GB = 0.3
    TRAFFIC_MIN_CORES = 1
    # The JA3 and IRC sidecars are the exception: each spawns a full tshark
    # dissector (measured ~290MB RSS each, plus a ~155MB dumpcap child), so the
    # pair costs more than a Zero has in total. They stay a big-board feature
    # while the tcpdump core runs everywhere.
    TRAFFIC_SIDECAR_MIN_RAM_GB = 3.5
    # Include armv8l which is 32-bit userspace on 64-bit ARM (Pi 4/5 with 32-bit OS)
    SUPPORTED_ARCHS = ['x86_64', 'amd64', 'aarch64', 'arm64', 'armv8l', 'armv7l']
    
    # Tool definitions for advanced features
    TRAFFIC_ANALYSIS_TOOLS = {
        'tcpdump': {'package': 'tcpdump', 'critical': True},
        'tshark': {'package': 'tshark', 'critical': False},
        'ngrep': {'package': 'ngrep', 'critical': False},
        'iftop': {'package': 'iftop', 'critical': False},
        'nethogs': {'package': 'nethogs', 'critical': False},
        'ss': {'package': 'iproute2', 'critical': True},
    }
    
    VULN_ASSESSMENT_TOOLS = {
        'nmap': {'package': 'nmap', 'critical': True},
        'nuclei': {'package': 'nuclei', 'critical': False, 'install_cmd': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'},
        'nikto': {'package': 'nikto', 'critical': False},
        'sqlmap': {'package': 'sqlmap', 'critical': False},
        'hydra': {'package': 'hydra', 'critical': False},
        'whatweb': {'package': 'whatweb', 'critical': False},
    }
    
    def __init__(self, shared_data=None):
        self.shared_data = shared_data
        self.capabilities = SystemCapabilities()
        self._lock = threading.Lock()
        self._detection_complete = False
        
        # Detect capabilities on init
        self.detect_capabilities()
    
    def detect_capabilities(self) -> SystemCapabilities:
        """Detect system hardware and software capabilities"""
        with self._lock:
            try:
                self._detect_hardware()
                self._detect_os_info()
                self._check_tool_availability()
                self._determine_feature_flags()
                self._detection_complete = True
                
                logger.info(f"Server capabilities detected: arch={self.capabilities.architecture}, "
                           f"ram={self.capabilities.total_ram_gb:.1f}GB, cores={self.capabilities.cpu_cores}, "
                           f"server_capable={self.capabilities.is_server_capable}")
                
            except Exception as e:
                logger.error(f"Error detecting capabilities: {e}")
                
        return self.capabilities
    
    def _detect_hardware(self):
        """Detect CPU and memory specifications"""
        # Architecture
        arch = platform.machine().lower()
        self.capabilities.architecture = arch
        self.capabilities.is_64bit = platform.architecture()[0] == '64bit'
        
        # CPU cores
        try:
            self.capabilities.cpu_cores = os.cpu_count() or 1
        except Exception:
            self.capabilities.cpu_cores = 1
        
        # RAM detection
        try:
            import psutil
            mem = psutil.virtual_memory()
            self.capabilities.total_ram_gb = mem.total / (1024 ** 3)
            self.capabilities.available_ram_gb = mem.available / (1024 ** 3)
        except ImportError:
            # Fallback: read from /proc/meminfo
            self._detect_ram_from_proc()
        
        # Pi Zero detection
        self._detect_pi_zero()
        
        # Determine if server capable
        # Pi 5 with 8GB is definitely capable, Pi 4/5 with 4GB gets partial features
        self.capabilities.is_server_capable = (
            arch in self.SUPPORTED_ARCHS and
            self.capabilities.total_ram_gb >= self.MIN_RAM_GB and
            self.capabilities.cpu_cores >= self.MIN_CORES and
            not self.capabilities.is_pi_zero
        )
        
        # Log detailed capability info for debugging
        logger.debug(f"Capability check: arch={arch} (supported={arch in self.SUPPORTED_ARCHS}), "
                    f"ram={self.capabilities.total_ram_gb:.1f}GB (min={self.MIN_RAM_GB}GB), "
                    f"cores={self.capabilities.cpu_cores} (min={self.MIN_CORES}), "
                    f"is_pi_zero={self.capabilities.is_pi_zero}")
    
    def _detect_ram_from_proc(self):
        """Fallback RAM detection from /proc/meminfo"""
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        # Value is in kB
                        kb = int(line.split()[1])
                        self.capabilities.total_ram_gb = kb / (1024 ** 2)
                    elif line.startswith('MemAvailable:'):
                        kb = int(line.split()[1])
                        self.capabilities.available_ram_gb = kb / (1024 ** 2)
        except Exception as e:
            logger.warning(f"Could not read /proc/meminfo: {e}")
    
    def _detect_pi_zero(self):
        """Detect if running on Raspberry Pi Zero (vs Pi 4/5 which are server-capable)"""
        self.capabilities.is_pi_zero = False
        
        try:
            # Check device-tree model first - most reliable
            model_path = '/sys/firmware/devicetree/base/model'
            if os.path.exists(model_path):
                with open(model_path, 'r') as f:
                    model = f.read().lower().strip('\x00')
                    logger.debug(f"Detected device model: {model}")
                    
                    # Pi 4 and Pi 5 with sufficient RAM are server-capable
                    if 'raspberry pi 5' in model or 'raspberry pi 4' in model:
                        if self.capabilities.total_ram_gb >= 4.0:
                            logger.info(f"Detected capable Raspberry Pi: {model.strip()}")
                            self.capabilities.is_pi_zero = False
                            return
                    
                    # Only mark as Pi Zero if explicitly a Zero model
                    if 'zero' in model:
                        self.capabilities.is_pi_zero = True
                        return
            
            # Fallback: Check /proc/cpuinfo for Pi Zero signature
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    content = f.read().lower()
                    # BCM2835 is Pi Zero/1 - only flag if also low RAM
                    if 'bcm2835' in content and self.capabilities.total_ram_gb < 1.0:
                        self.capabilities.is_pi_zero = True
                        return
                        
        except Exception as e:
            logger.debug(f"Pi Zero detection error: {e}")
    
    def _detect_os_info(self):
        """Detect OS information"""
        self.capabilities.hostname = platform.node()
        self.capabilities.os_name = platform.system()
        self.capabilities.os_version = platform.release()
        self.capabilities.kernel_version = platform.version()
    
    def _check_tool_availability(self):
        """Check which security tools are available"""
        all_tools = {**self.TRAFFIC_ANALYSIS_TOOLS, **self.VULN_ASSESSMENT_TOOLS}
        
        for tool_name in all_tools:
            self.capabilities.available_tools[tool_name] = shutil.which(tool_name) is not None
    
    def _determine_feature_flags(self):
        """Determine which advanced features can be enabled"""
        caps = self.capabilities

        # Kiosk gate is independent of full server mode: it is a RAM/CPU
        # question about running Chromium, not about running OpenVAS.
        caps.kiosk_capable, caps.kiosk_block_reason = self._evaluate_kiosk_support()

        # Traffic Analysis is likewise its own gate: parsing tcpdump output is
        # cheap enough for a Pi Zero, so it is not tied to server mode.
        caps.traffic_capable, caps.traffic_block_reason = self._evaluate_traffic_support()
        caps.traffic_analysis_enabled = caps.traffic_capable
        # tshark sidecars (JA3 fingerprinting, IRC DPI) are the heavy part.
        caps.traffic_sidecars_enabled = (
            caps.traffic_capable
            and caps.total_ram_gb >= self.TRAFFIC_SIDECAR_MIN_RAM_GB
            and caps.available_tools.get('tshark', False)
        )

        # Advanced Vuln scanning splits into two tiers by memory cost:
        #   * nuclei / nikto / sqlmap / nmap / whatweb are light CLI tools -
        #     they run on any board that has them installed, a Pi Zero
        #     included, so the tab is no longer tied to server mode.
        #   * OWASP ZAP is the heavy exception (see ZAP_MIN_RAM_GB) and keeps
        #     its own RAM floor, so it greys out on smaller boards while the
        #     rest of the tab stays usable.
        # Advanced Vuln needs nmap, which Ragnar already uses.
        caps.advanced_vuln_enabled = caps.available_tools.get('nmap', False)
        caps.zap_enabled = caps.total_ram_gb >= self.ZAP_MIN_RAM_GB

        if caps.is_server_capable:
            # Parallel scanning: enabled on multi-core systems
            caps.parallel_scanning_enabled = caps.cpu_cores >= 4

            # Local AI: check for Ollama
            caps.local_ai_enabled = shutil.which('ollama') is not None

            # Large dictionaries: enabled on 7.5GB+ RAM (8GB devices report ~7.87GB)
            caps.large_dictionaries_enabled = caps.total_ram_gb >= 7.5
        else:
            # Server-class-only features stay off on Pi Zero / low-spec systems.
            # Advanced Vuln (minus ZAP) and Traffic Analysis are deliberately
            # not in this list - see above.
            caps.parallel_scanning_enabled = False
            caps.local_ai_enabled = False
            caps.large_dictionaries_enabled = False
    
    def _evaluate_kiosk_support(self) -> Tuple[bool, str]:
        """Can this box host the on-screen kiosk (Chromium fullscreen)?

        Returns (capable, reason). `reason` is empty when capable and is shown
        verbatim in the UI/installer otherwise, so it has to name the board's
        actual numbers - "not supported" alone sends people hunting.
        """
        caps = self.capabilities
        ram_gb = caps.total_ram_gb

        if caps.is_pi_zero:
            return False, (
                f"Kiosk needs a Ragnar Pi server. This is a Pi Zero class board "
                f"({ram_gb:.1f}GB RAM) and Chromium alone needs about 1GB."
            )
        # A RAM read of 0 means /proc/meminfo and psutil both failed. Don't hand
        # a kiosk to a box we know nothing about.
        if ram_gb <= 0:
            return False, "Kiosk needs a Ragnar Pi server. Could not read this system's RAM size."
        if ram_gb < self.KIOSK_MIN_RAM_GB:
            return False, (
                "Kiosk needs a Ragnar Pi server with at least 2GB RAM. "
                f"This board has {ram_gb:.1f}GB and Chromium alone needs about 1GB."
            )
        if caps.cpu_cores < self.KIOSK_MIN_CORES:
            return False, (
                f"Kiosk needs at least {self.KIOSK_MIN_CORES} CPU cores. "
                f"This board has {caps.cpu_cores}."
            )
        return True, ""

    def _evaluate_traffic_support(self) -> Tuple[bool, str]:
        """Can this box run Traffic Analysis (tcpdump capture + parsing)?

        Returns (capable, reason), same contract as _evaluate_kiosk_support:
        `reason` is empty when capable and is shown verbatim otherwise.

        Unlike the vulnerability scanners this needs no dictionaries, no
        parallel scan fleet and no dissector - just a tcpdump pipe - so a Pi
        Zero passes. The only hard requirement is tcpdump itself.
        """
        caps = self.capabilities
        ram_gb = caps.total_ram_gb

        if not caps.available_tools.get('tcpdump', False):
            return False, (
                "Traffic Analysis needs tcpdump, which is not installed. "
                "Install it with: sudo apt-get install tcpdump"
            )
        if caps.architecture not in self.SUPPORTED_ARCHS:
            return False, (
                f"Traffic Analysis does not support this architecture "
                f"({caps.architecture or 'unknown'})."
            )
        # A RAM read of 0 means psutil and /proc/meminfo both failed. Fail
        # closed rather than start a capture on a box we cannot measure.
        if ram_gb <= 0:
            return False, "Traffic Analysis could not read this system's RAM size."
        if ram_gb < self.TRAFFIC_MIN_RAM_GB:
            return False, (
                f"Traffic Analysis needs at least {self.TRAFFIC_MIN_RAM_GB:.1f}GB RAM. "
                f"This board reports {ram_gb:.2f}GB."
            )
        if caps.cpu_cores < self.TRAFFIC_MIN_CORES:
            return False, (
                f"Traffic Analysis needs at least {self.TRAFFIC_MIN_CORES} CPU core."
            )
        return True, ""

    def is_traffic_capable(self) -> bool:
        """Check if Traffic Analysis may run on this hardware"""
        return self.capabilities.traffic_capable

    def traffic_block_reason(self) -> str:
        """Why Traffic Analysis is unavailable ('' when it is available)"""
        return self.capabilities.traffic_block_reason

    def is_kiosk_capable(self) -> bool:
        """Check if the on-screen kiosk may run on this hardware"""
        return self.capabilities.kiosk_capable

    def kiosk_block_reason(self) -> str:
        """Why the kiosk is unavailable ('' when it is available)"""
        return self.capabilities.kiosk_block_reason

    def is_server_mode(self) -> bool:
        """Check if running in server mode"""
        return self.capabilities.is_server_capable
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get capabilities as dictionary for API"""
        return self.capabilities.to_dict()
    
    def get_feature_status(self) -> Dict[str, bool]:
        """Get status of all advanced features"""
        caps = self.capabilities
        return {
            'server_mode': caps.is_server_capable,
            'traffic_analysis': caps.traffic_analysis_enabled,
            'traffic_sidecars': caps.traffic_sidecars_enabled,
            'advanced_vuln_assessment': caps.advanced_vuln_enabled,
            'zap': caps.zap_enabled,
            'parallel_scanning': caps.parallel_scanning_enabled,
            'local_ai': caps.local_ai_enabled,
            'large_dictionaries': caps.large_dictionaries_enabled,
            'kiosk': caps.kiosk_capable,
            'wardriving_enabled': self.shared_data.config.get('wardriving_enabled', False) if self.shared_data else False,
        }
    
    def get_missing_tools(self, feature: str) -> List[str]:
        """Get list of missing tools for a feature"""
        if feature == 'traffic_analysis':
            tools = self.TRAFFIC_ANALYSIS_TOOLS
        elif feature == 'advanced_vuln':
            tools = self.VULN_ASSESSMENT_TOOLS
        else:
            return []
        
        missing = []
        for tool_name, info in tools.items():
            if not self.capabilities.available_tools.get(tool_name, False):
                if info.get('critical', False):
                    missing.insert(0, tool_name)  # Critical tools first
                else:
                    missing.append(tool_name)
        
        return missing
    
    def install_missing_tools(self, feature: str) -> Tuple[bool, str]:
        """Attempt to install missing tools for a feature"""
        # Traffic Analysis and the Advanced Vuln CLI scanners run on any board,
        # so their tools install on any board too (this is the path that
        # installs the missing tcpdump/nmap the gate complains about). ZAP is
        # not in either install set - it has its own RAM gate - so nothing here
        # is server-mode-only anymore.
        missing = self.get_missing_tools(feature)
        if not missing:
            return True, "All required tools are already installed"
        
        # Determine package manager
        pkg_cmd = None
        if shutil.which('apt-get'):
            pkg_cmd = ['sudo', 'apt-get', 'install', '-y']
        elif shutil.which('dnf'):
            pkg_cmd = ['sudo', 'dnf', 'install', '-y']
        elif shutil.which('yum'):
            pkg_cmd = ['sudo', 'yum', 'install', '-y']
        elif shutil.which('pacman'):
            pkg_cmd = ['sudo', 'pacman', '-S', '--noconfirm']
        
        if not pkg_cmd:
            return False, "No supported package manager found"
        
        installed = []
        failed = []
        
        for tool in missing:
            try:
                result = subprocess.run(
                    pkg_cmd + [tool],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    installed.append(tool)
                else:
                    failed.append(tool)
            except Exception as e:
                logger.error(f"Failed to install {tool}: {e}")
                failed.append(tool)
        
        # Re-check availability
        self._check_tool_availability()
        self._determine_feature_flags()
        
        if failed:
            return False, f"Installed: {installed}, Failed: {failed}"
        return True, f"Successfully installed: {installed}"


# Global instance
_server_capabilities: Optional[ServerCapabilities] = None


def get_server_capabilities(shared_data=None) -> ServerCapabilities:
    """Get or create the global ServerCapabilities instance"""
    global _server_capabilities
    if _server_capabilities is None:
        _server_capabilities = ServerCapabilities(shared_data)
    return _server_capabilities


def is_server_mode() -> bool:
    """Quick check if running in server mode"""
    return get_server_capabilities().is_server_mode()


def traffic_capability(shared_data=None) -> Tuple[bool, str]:
    """(capable, reason) for Traffic Analysis on this hardware.

    Never raises: a detection failure must not take the traffic API down, and a
    box we cannot measure is treated as capable=False with a stated reason.
    """
    try:
        caps = get_server_capabilities(shared_data)
        return caps.is_traffic_capable(), caps.traffic_block_reason()
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Traffic capability check failed: {exc}")
        return False, f"Could not determine hardware capability for Traffic Analysis: {exc}"


def kiosk_capability(shared_data=None) -> Tuple[bool, str]:
    """(capable, reason) for the on-screen kiosk on this hardware.

    Never raises: a detection failure must not take the kiosk API down, and a
    box we cannot measure is treated as capable=False with a stated reason.
    """
    try:
        caps = get_server_capabilities(shared_data)
        return caps.is_kiosk_capable(), caps.kiosk_block_reason()
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Kiosk capability check failed: {exc}")
        return False, f"Could not determine hardware capability for the kiosk: {exc}"
