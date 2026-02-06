# advanced_vuln_scanner.py
"""
Advanced Vulnerability Assessment Module for Ragnar Server Mode

This module provides enhanced vulnerability scanning capabilities
only available when running on a capable server (8GB+ RAM).

Features:
- Nuclei template-based scanning
- Nikto web server assessment
- SQLMap SQL injection testing
- OWASP ZAP web application scanning
- Parallel vulnerability scanning
- CVE correlation and enrichment
- Exploit suggestion engine
"""

import os
import re
import json
import time
import shutil
import threading
import subprocess
import tempfile
import logging
import urllib.request
import urllib.parse
import urllib.error
import socket
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty

from logger import Logger
from server_capabilities import get_server_capabilities, is_server_mode

logger = Logger(name="advanced_vuln_scanner", level=logging.INFO)


class VulnSeverity(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_string(cls, value: str) -> 'VulnSeverity':
        """Convert string to severity, with fallback"""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.INFO


class ScanType(Enum):
    """Types of vulnerability scans"""
    NUCLEI = "nuclei"
    NIKTO = "nikto"
    SQLMAP = "sqlmap"
    NMAP_VULN = "nmap_vuln"
    WHATWEB = "whatweb"
    ZAP_SPIDER = "zap_spider"
    ZAP_ACTIVE = "zap_active"
    ZAP_FULL = "zap_full"
    FULL = "full"


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding"""
    finding_id: str
    scanner: str
    host: str
    port: Optional[int]
    severity: VulnSeverity
    title: str
    description: str
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    matched_at: str = ""
    template_id: str = ""
    raw_output: str = ""
    details: Dict[str, Any] = field(default_factory=dict)  # Additional scanner-specific details
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'scanner': self.scanner,
            'host': self.host,
            'port': self.port,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'cve_ids': self.cve_ids,
            'cwe_ids': self.cwe_ids,
            'cvss_score': self.cvss_score,
            'evidence': self.evidence[:1000],  # Limit size
            'remediation': self.remediation,
            'references': self.references[:10],
            'tags': self.tags,
            'matched_at': self.matched_at,
            'template_id': self.template_id,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ScanProgress:
    """Progress tracking for a scan"""
    scan_id: str
    scan_type: ScanType
    target: str
    status: str  # pending, running, completed, failed
    progress_percent: int = 0
    findings_count: int = 0
    current_check: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: str = ""
    auth_type: str = ""  # Auth type used for this scan (cookie, bearer_token, etc.)
    auth_status: str = ""  # Auth validation status (applied, verified, failed)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_id': self.scan_id,
            'scan_type': self.scan_type.value,
            'target': self.target,
            'status': self.status,
            'progress_percent': self.progress_percent,
            'findings_count': self.findings_count,
            'current_check': self.current_check,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
            'auth_type': self.auth_type,
            'auth_status': self.auth_status,
            'duration_seconds': (
                (self.completed_at or datetime.now()) - self.started_at
            ).total_seconds() if self.started_at else 0
        }


class AdvancedVulnScanner:
    """
    Advanced vulnerability scanner for Ragnar server mode.

    Provides enterprise-grade vulnerability scanning using:
    - Nuclei for template-based scanning
    - Nikto for web server assessment
    - SQLMap for SQL injection testing
    - OWASP ZAP for web application security testing
    - Enhanced nmap vuln scripts
    """

    # Nuclei severity mapping
    NUCLEI_SEVERITY_MAP = {
        'info': VulnSeverity.INFO,
        'low': VulnSeverity.LOW,
        'medium': VulnSeverity.MEDIUM,
        'high': VulnSeverity.HIGH,
        'critical': VulnSeverity.CRITICAL,
    }

    # ZAP severity/risk mapping (ZAP uses 0-3 risk levels)
    ZAP_RISK_MAP = {
        0: VulnSeverity.INFO,       # Informational
        1: VulnSeverity.LOW,        # Low
        2: VulnSeverity.MEDIUM,     # Medium
        3: VulnSeverity.HIGH,       # High
    }

    # ZAP confidence levels
    ZAP_CONFIDENCE_MAP = {
        0: 'False Positive',
        1: 'Low',
        2: 'Medium',
        3: 'High',
        4: 'Confirmed',
    }

    # Default Nuclei templates (fast scan)
    NUCLEI_FAST_TEMPLATES = [
        'cves/', 'default-logins/', 'exposures/', 'misconfiguration/',
        'technologies/', 'takeovers/'
    ]

    # Full Nuclei templates
    NUCLEI_FULL_TEMPLATES = [
        'cves/', 'default-logins/', 'exposures/', 'misconfiguration/',
        'technologies/', 'takeovers/', 'vulnerabilities/', 'fuzzing/'
    ]

    # ZAP configuration
    ZAP_DEFAULT_PORT = 8090
    ZAP_API_KEY_LENGTH = 32
    ZAP_STARTUP_TIMEOUT = 60  # seconds to wait for ZAP to start
    ZAP_SCAN_POLICIES = ['Default Policy', 'Light', 'Medium', 'High']

    def __init__(self, shared_data=None):
        self.shared_data = shared_data
        self._lock = threading.Lock()

        # Scan tracking
        self.active_scans: Dict[str, ScanProgress] = {}
        self.scan_results: Dict[str, List[VulnerabilityFinding]] = {}
        self._scan_counter = 0

        # Scan history (deque for recent scans)
        from collections import deque
        self.scan_history: deque = deque(maxlen=100)

        # Thread pool for parallel scanning
        self._executor: Optional[ThreadPoolExecutor] = None
        self._max_workers = 4  # Configurable based on system

        # Tool paths
        self._tool_paths = {}
        self._detect_tools()

        # ZAP daemon management
        self._zap_process: Optional[subprocess.Popen] = None
        self._zap_port = self.ZAP_DEFAULT_PORT
        self._zap_api_key = self._generate_api_key()
        self._zap_base_url = f"http://127.0.0.1:{self._zap_port}"

        # Check capabilities
        caps = get_server_capabilities(shared_data)
        if caps.capabilities.parallel_scanning_enabled:
            self._max_workers = min(caps.capabilities.cpu_cores, 8)

        # Database manager reference
        self._db = None
        self._init_database()

        # Recover any interrupted scans on startup
        self._recover_interrupted_scans()

        # Auto-start ZAP daemon so it's always available
        if self._tool_paths.get('zap'):
            threading.Thread(target=self._auto_start_zap, daemon=True).start()

    def _init_database(self):
        """Initialize database connection for scan persistence"""
        try:
            from db_manager import get_db
            self._db = get_db()
            logger.info("Database connection initialized for scan persistence")
        except Exception as e:
            logger.warning(f"Database initialization failed (scans will not persist): {e}")
            self._db = None

    def _recover_interrupted_scans(self):
        """Mark interrupted scans and optionally recover them"""
        if not self._db:
            return

        try:
            interrupted = self._db.get_interrupted_scans()
            for scan in interrupted:
                scan_id = scan.get('scan_id')
                status = scan.get('status')

                if status == 'running':
                    # Mark as interrupted - it was running when system restarted
                    self._db.mark_scan_interrupted(scan_id)
                    logger.info(f"Marked scan {scan_id} as interrupted")

                    # Create a progress entry for UI display
                    progress = ScanProgress(
                        scan_id=scan_id,
                        scan_type=ScanType(scan.get('scan_type', 'nuclei')),
                        target=scan.get('target', ''),
                        status='interrupted',
                        progress_percent=scan.get('progress_percent', 0),
                        findings_count=scan.get('findings_count', 0),
                        current_check=scan.get('current_check', ''),
                        error_message='Scan interrupted by system restart'
                    )
                    if scan.get('started_at'):
                        try:
                            progress.started_at = datetime.fromisoformat(scan['started_at'].replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            pass

                    self.active_scans[scan_id] = progress
                    self.scan_history.append(progress)

                    # Load existing findings from database
                    findings_data = self._db.get_scan_findings(scan_id)
                    self.scan_results[scan_id] = [
                        self._dict_to_finding(f) for f in findings_data
                    ]

            logger.info(f"Recovered {len(interrupted)} interrupted scans")
        except Exception as e:
            logger.error(f"Error recovering interrupted scans: {e}")

    def _auto_start_zap(self):
        """Auto-start ZAP daemon in background so it's always available"""
        try:
            if not self._is_zap_running():
                logger.info("Auto-starting ZAP daemon...")
                if self.start_zap_daemon():
                    logger.info("ZAP daemon auto-started successfully")
                else:
                    logger.warning("Failed to auto-start ZAP daemon")
            else:
                logger.info("ZAP daemon already running")
        except Exception as e:
            logger.warning(f"ZAP auto-start error: {e}")

    def _dict_to_finding(self, data: Dict) -> VulnerabilityFinding:
        """Convert a dictionary (from DB) back to VulnerabilityFinding"""
        # Handle both 'reference_urls' (DB column) and 'references' (legacy/API)
        refs = data.get('reference_urls') or data.get('references', [])

        # Parse timestamp from DB (stored as ISO string)
        timestamp = datetime.now()
        if data.get('timestamp'):
            try:
                if isinstance(data['timestamp'], str):
                    timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
                elif isinstance(data['timestamp'], datetime):
                    timestamp = data['timestamp']
            except (ValueError, TypeError):
                pass

        return VulnerabilityFinding(
            finding_id=data.get('finding_id', ''),
            scanner=data.get('scanner', ''),
            host=data.get('host', ''),
            port=data.get('port'),
            severity=VulnSeverity.from_string(data.get('severity', 'info')),
            title=data.get('title', ''),
            description=data.get('description', ''),
            cve_ids=data.get('cve_ids', []) if data.get('cve_ids') else [],
            cwe_ids=data.get('cwe_ids', []) if data.get('cwe_ids') else [],
            cvss_score=data.get('cvss_score'),
            evidence=data.get('evidence', '') or '',
            remediation=data.get('remediation', '') or '',
            references=refs if refs else [],
            tags=data.get('tags', []) if data.get('tags') else [],
            matched_at=data.get('matched_at', '') or '',
            template_id=data.get('template_id', '') or '',
            raw_output=data.get('raw_output', '') or '',
            details=data.get('details', {}) if data.get('details') else {},
            timestamp=timestamp
        )

    def _save_scan_to_db(self, scan_id: str, progress: ScanProgress, options: Dict = None):
        """Save scan progress to database"""
        if not self._db:
            return

        try:
            self._db.save_scan_job(
                scan_id=scan_id,
                scan_type=progress.scan_type.value,
                target=progress.target,
                status=progress.status,
                progress_percent=progress.progress_percent,
                findings_count=progress.findings_count,
                current_check=progress.current_check,
                started_at=progress.started_at,
                completed_at=progress.completed_at,
                error_message=progress.error_message,
                options=options
            )
        except Exception as e:
            logger.debug(f"Error saving scan to DB: {e}")

    def _save_finding_to_db(self, finding: VulnerabilityFinding, scan_id: str):
        """Save a finding to the database"""
        if not self._db:
            return

        try:
            self._db.save_scan_finding(
                finding_id=finding.finding_id,
                scan_id=scan_id,
                scanner=finding.scanner,
                host=finding.host,
                port=finding.port,
                severity=finding.severity.value,
                title=finding.title,
                description=finding.description,
                cve_ids=finding.cve_ids,
                cwe_ids=finding.cwe_ids,
                cvss_score=finding.cvss_score,
                evidence=finding.evidence,
                remediation=finding.remediation,
                references=finding.references,
                tags=finding.tags,
                matched_at=finding.matched_at,
                template_id=finding.template_id,
                raw_output=finding.raw_output,
                details=finding.details
            )
        except Exception as e:
            logger.debug(f"Error saving finding to DB: {e}")

    def _update_progress(self, scan_id: str, progress_percent: int = None,
                         current_check: str = None, findings_count: int = None):
        """Update scan progress and persist to database (call periodically during scans)"""
        progress = self.active_scans.get(scan_id)
        if not progress:
            return

        if progress_percent is not None:
            progress.progress_percent = progress_percent
        if current_check is not None:
            progress.current_check = current_check
        if findings_count is not None:
            progress.findings_count = findings_count
        else:
            progress.findings_count = len(self.scan_results.get(scan_id, []))

        # Persist progress to database
        self._save_scan_to_db(scan_id, progress)

    def _generate_api_key(self) -> str:
        """Generate a random API key for ZAP"""
        import secrets
        return secrets.token_hex(self.ZAP_API_KEY_LENGTH // 2)
    
    def _detect_tools(self):
        """Detect available security tools"""
        tools = ['nuclei', 'nikto', 'sqlmap', 'nmap', 'whatweb']
        for tool in tools:
            path = shutil.which(tool)
            self._tool_paths[tool] = path
            if path:
                logger.info(f"Found {tool} at {path}")
            else:
                logger.debug(f"{tool} not found in PATH")

        # Detect ZAP - check multiple possible locations
        # Priority: Ragnar tools dir > /opt > standard locations > PATH
        ragnar_dir = os.path.dirname(os.path.abspath(__file__))
        import sys
        is_windows = sys.platform == 'win32'

        if is_windows:
            # Windows ZAP locations
            zap_paths = [
                # Ragnar's tools directory
                os.path.join(ragnar_dir, 'tools', 'zap', 'zap.bat'),
                # Standard Windows installation paths
                os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'OWASP', 'Zed Attack Proxy', 'zap.bat'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'OWASP', 'Zed Attack Proxy', 'zap.bat'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'ZAP', 'zap.bat'),
                # Also check for java-based invocation
                shutil.which('zap.bat'),
                shutil.which('zap'),
            ]
        else:
            # Linux/Mac ZAP locations
            zap_paths = [
                # Ragnar's tools directory (installed by install_advanced_tools.sh)
                os.path.join(ragnar_dir, 'tools', 'zap', 'zap.sh'),
                # Standard system locations
                '/opt/zaproxy/zap.sh',
                '/usr/share/zaproxy/zap.sh',
                '/usr/local/bin/zap.sh',
                # Homebrew on macOS
                '/opt/homebrew/bin/zap.sh',
                '/usr/local/Cellar/zap/*/zap.sh',
                # PATH lookups
                shutil.which('zap.sh'),
                shutil.which('zap'),
                shutil.which('zaproxy'),
            ]

        for zap_path in zap_paths:
            if zap_path and os.path.exists(zap_path):
                self._tool_paths['zap'] = zap_path
                logger.info(f"Found OWASP ZAP at {zap_path}")
                break
        else:
            self._tool_paths['zap'] = None
            logger.debug("OWASP ZAP not found")

    def is_available(self) -> bool:
        """Check if advanced vuln scanning is available"""
        return get_server_capabilities().capabilities.advanced_vuln_enabled

    def get_available_scanners(self) -> Dict[str, bool]:
        """Get status of available scanners"""
        zap_available = self._tool_paths.get('zap') is not None
        zap_running = self._is_zap_running() if zap_available else False
        return {
            'nuclei': self._tool_paths.get('nuclei') is not None,
            'nikto': self._tool_paths.get('nikto') is not None,
            'sqlmap': self._tool_paths.get('sqlmap') is not None,
            'nmap_vuln': self._tool_paths.get('nmap') is not None,
            'whatweb': self._tool_paths.get('whatweb') is not None,
            'zap': zap_available,
            'zap_running': zap_running,
        }
    
    def start_scan(self, target: str, scan_type: ScanType = ScanType.NUCLEI,
                   options: Dict = None) -> str:
        """Start a vulnerability scan"""
        if not self.is_available():
            raise RuntimeError("Advanced vulnerability scanning not available")

        options = options or {}

        with self._lock:
            self._scan_counter += 1
            scan_id = f"AVS-{self._scan_counter:06d}-{int(time.time())}"

        progress = ScanProgress(
            scan_id=scan_id,
            scan_type=scan_type,
            target=target,
            status='pending'
        )

        self.active_scans[scan_id] = progress
        self.scan_results[scan_id] = []
        self.scan_history.append(progress)

        # Save to database
        self._save_scan_to_db(scan_id, progress, options)

        # Start scan in thread pool
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self._max_workers)

        self._executor.submit(self._run_scan, scan_id, target, scan_type, options)

        logger.info(f"Started {scan_type.value} scan {scan_id} against {target}")
        return scan_id
    
    def _run_scan(self, scan_id: str, target: str, scan_type: ScanType, options: Dict):
        """Execute the vulnerability scan"""
        progress = self.active_scans.get(scan_id)
        if not progress:
            return

        progress.status = 'running'
        progress.started_at = datetime.now()

        # Save running status to database
        self._save_scan_to_db(scan_id, progress, options)

        try:
            if scan_type == ScanType.NUCLEI:
                self._run_nuclei_scan(scan_id, target, options)
            elif scan_type == ScanType.NIKTO:
                self._run_nikto_scan(scan_id, target, options)
            elif scan_type == ScanType.SQLMAP:
                self._run_sqlmap_scan(scan_id, target, options)
            elif scan_type == ScanType.NMAP_VULN:
                self._run_nmap_vuln_scan(scan_id, target, options)
            elif scan_type == ScanType.WHATWEB:
                self._run_whatweb_scan(scan_id, target, options)
            elif scan_type == ScanType.ZAP_SPIDER:
                self._run_zap_spider(scan_id, target, options)
            elif scan_type == ScanType.ZAP_ACTIVE:
                self._run_zap_active_scan(scan_id, target, options)
            elif scan_type == ScanType.ZAP_FULL:
                self._run_zap_full_scan(scan_id, target, options)
            elif scan_type == ScanType.FULL:
                self._run_full_scan(scan_id, target, options)

            progress.status = 'completed'
            progress.progress_percent = 100

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            progress.status = 'failed'
            progress.error_message = str(e)
        finally:
            progress.completed_at = datetime.now()
            progress.findings_count = len(self.scan_results.get(scan_id, []))
            # Save final status to database
            self._save_scan_to_db(scan_id, progress, options)
            # Save all findings to database
            for finding in self.scan_results.get(scan_id, []):
                self._save_finding_to_db(finding, scan_id)
    
    def _run_nuclei_scan(self, scan_id: str, target: str, options: Dict):
        """Run Nuclei template-based scan"""
        nuclei_path = self._tool_paths.get('nuclei')
        if not nuclei_path:
            raise RuntimeError("Nuclei not installed")
        
        progress = self.active_scans[scan_id]
        
        # Build command
        templates = options.get('templates', self.NUCLEI_FAST_TEMPLATES)
        severity_filter = options.get('severity', 'low,medium,high,critical')
        rate_limit = options.get('rate_limit', 150)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                nuclei_path,
                '-u', target,
                '-jsonl',
                '-o', output_path,
                '-severity', severity_filter,
                '-rate-limit', str(rate_limit),
                '-silent',
                '-no-color'
            ]
            
            # Add template filters if specified
            if templates:
                for t in templates[:5]:  # Limit templates
                    cmd.extend(['-t', t])

            # Add HTTP Basic Auth header if provided
            if options.get('http_basic_auth'):
                import base64
                auth_string = options['http_basic_auth']
                auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
                cmd.extend(['-H', f'Authorization: Basic {auth_bytes}'])

            # Add Bearer Token if provided
            if options.get('bearer_token'):
                cmd.extend(['-H', f'Authorization: Bearer {options["bearer_token"]}'])

            # Add API Key header if provided
            if options.get('api_key'):
                header_name = options.get('api_key_header', 'X-API-Key')
                cmd.extend(['-H', f'{header_name}: {options["api_key"]}'])

            # Add Cookie if provided
            if options.get('cookie_value'):
                cmd.extend(['-H', f'Cookie: {options["cookie_value"]}'])

            # Add custom headers if provided
            if options.get('headers'):
                for header in options['headers']:
                    cmd.extend(['-H', header])

            logger.debug(f"Running Nuclei: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Monitor progress
            while process.poll() is None:
                time.sleep(2)
                progress.current_check = "Scanning with Nuclei templates..."
                # Update findings count from output file
                if os.path.exists(output_path):
                    with open(output_path, 'r') as f:
                        lines = f.readlines()
                        progress.findings_count = len(lines)
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        try:
                            finding = self._parse_nuclei_result(line.strip(), scan_id)
                            if finding:
                                self.scan_results[scan_id].append(finding)
                        except json.JSONDecodeError:
                            continue
                            
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _parse_nuclei_result(self, json_line: str, scan_id: str) -> Optional[VulnerabilityFinding]:
        """Parse a Nuclei JSON output line"""
        try:
            data = json.loads(json_line)
            
            # Extract CVEs from tags or info
            cve_ids = []
            tags = data.get('info', {}).get('tags', [])
            for tag in tags:
                if tag.upper().startswith('CVE-'):
                    cve_ids.append(tag.upper())
            
            # Also check classification
            classification = data.get('info', {}).get('classification', {})
            if 'cve-id' in classification:
                cve_ids.extend(classification['cve-id'])
            
            severity_str = data.get('info', {}).get('severity', 'info')
            severity = self.NUCLEI_SEVERITY_MAP.get(severity_str, VulnSeverity.INFO)
            
            finding = VulnerabilityFinding(
                finding_id=f"{scan_id}-{len(self.scan_results.get(scan_id, []))+1:04d}",
                scanner='nuclei',
                host=data.get('host', data.get('matched-at', '')),
                port=data.get('port'),
                severity=severity,
                title=data.get('info', {}).get('name', 'Unknown'),
                description=data.get('info', {}).get('description', ''),
                cve_ids=list(set(cve_ids)),
                cwe_ids=classification.get('cwe-id', []),
                cvss_score=classification.get('cvss-score'),
                evidence=data.get('extracted-results', ''),
                remediation=data.get('info', {}).get('remediation', ''),
                references=data.get('info', {}).get('reference', []),
                tags=tags,
                matched_at=data.get('matched-at', ''),
                template_id=data.get('template-id', ''),
                raw_output=json_line[:2000]
            )
            
            return finding
            
        except Exception as e:
            logger.debug(f"Error parsing Nuclei result: {e}")
            return None
    
    def _run_nikto_scan(self, scan_id: str, target: str, options: Dict):
        """Run Nikto web server scan"""
        nikto_path = self._tool_paths.get('nikto')
        if not nikto_path:
            raise RuntimeError("Nikto not installed")
        
        progress = self.active_scans[scan_id]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                nikto_path,
                '-h', target,
                '-Format', 'json',
                '-o', output_path,
                '-nointeractive',
                '-maxtime', options.get('max_time', '300s')
            ]

            # Add port if specified
            if options.get('port'):
                cmd.extend(['-p', str(options['port'])])

            # Add HTTP Basic Auth if provided (Nikto native support)
            if options.get('http_basic_auth'):
                auth_parts = options['http_basic_auth'].split(':', 1)
                if len(auth_parts) == 2:
                    cmd.extend(['-id', f'{auth_parts[0]}:{auth_parts[1]}'])

            # Note: Nikto doesn't support custom headers for bearer_token, api_key, or cookie auth
            # These auth methods are better suited for Nuclei scans which support -H flag

            logger.info(f"Running Nikto: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=600)
            
            if stdout:
                logger.debug(f"Nikto stdout: {stdout[:500]}")
            if stderr:
                logger.debug(f"Nikto stderr: {stderr[:500]}")
            
            progress.current_check = "Parsing Nikto results..."
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    raw_content = f.read()
                    logger.info(f"Nikto output file size: {len(raw_content)} bytes")
                    if raw_content:
                        logger.debug(f"Nikto raw output (first 1000 chars): {raw_content[:1000]}")
                        try:
                            results = json.loads(raw_content)
                            logger.info(f"Nikto parsed JSON keys: {list(results.keys()) if isinstance(results, dict) else 'array'}")
                            self._parse_nikto_results(results, scan_id, target)
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse Nikto JSON output: {e}")
                            # Try to parse as plain text output
                            self._parse_nikto_text_output(raw_content, scan_id, target)
                    else:
                        logger.warning("Nikto output file is empty")
            else:
                logger.warning(f"Nikto output file not found: {output_path}")
                        
        except subprocess.TimeoutExpired:
            process.kill()
            progress.error_message = "Nikto scan timed out"
        except Exception as e:
            logger.error(f"Nikto scan error: {e}")
            progress.error_message = str(e)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _parse_nikto_results(self, results: Any, scan_id: str, target: str = ''):
        """Parse Nikto JSON results"""
        try:
            vulnerabilities = []
            host = target
            port = None
            
            # Nikto 2.5+ JSON format is often an array with a single object containing 'vulnerabilities'
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        host = item.get('host', host) or item.get('ip', host)
                        port = item.get('port', port)
                        vulns = item.get('vulnerabilities', [])
                        if vulns:
                            vulnerabilities.extend(vulns)
            elif isinstance(results, dict):
                host = results.get('host', host) or results.get('ip', host)
                port = results.get('port', port)
                vulnerabilities = results.get('vulnerabilities', [])
            
            logger.info(f"Nikto found {len(vulnerabilities)} vulnerabilities for {host}:{port}")
            
            for vuln in vulnerabilities:
                # Map Nikto OSVDB/id to severity
                osvdb = str(vuln.get('OSVDB', vuln.get('id', '0')))
                msg = vuln.get('msg', vuln.get('message', 'Nikto Finding'))
                method = vuln.get('method', 'GET')
                uri = vuln.get('url', vuln.get('uri', '/'))
                
                # Determine severity based on keywords
                severity = VulnSeverity.INFO
                msg_lower = msg.lower()
                if any(kw in msg_lower for kw in ['sql injection', 'xss', 'rce', 'command injection', 'critical']):
                    severity = VulnSeverity.HIGH
                elif any(kw in msg_lower for kw in ['directory listing', 'backup', 'config', 'password', 'admin']):
                    severity = VulnSeverity.MEDIUM
                elif any(kw in msg_lower for kw in ['outdated', 'version', 'disclosure', 'header']):
                    severity = VulnSeverity.LOW
                
                finding = VulnerabilityFinding(
                    finding_id=f"{scan_id}-nikto-{len(self.scan_results.get(scan_id, []))+1:04d}",
                    scanner='nikto',
                    host=str(host),
                    port=int(port) if port else None,
                    severity=severity,
                    title=f"[{method}] {uri}" if uri else msg[:80],
                    description=msg,
                    references=[f"OSVDB-{osvdb}"] if osvdb != '0' else [],
                    tags=['nikto', 'web'],
                    raw_output=json.dumps(vuln)[:1000]
                )
                
                self.scan_results[scan_id].append(finding)
                logger.debug(f"Added Nikto finding: {finding.title}")
                
        except Exception as e:
            logger.error(f"Error parsing Nikto results: {e}")
    
    def _parse_nikto_text_output(self, text: str, scan_id: str, target: str):
        """Parse Nikto plain text output as fallback"""
        try:
            lines = text.split('\n')
            for line in lines:
                line = line.strip()
                # Nikto text format: + /path: Description
                if line.startswith('+') and ':' in line:
                    parts = line[1:].strip().split(':', 1)
                    if len(parts) == 2:
                        uri = parts[0].strip()
                        msg = parts[1].strip()
                        
                        # Skip info lines
                        if any(skip in msg.lower() for skip in ['target ip:', 'target hostname:', 'target port:', 'start time:', 'end time:', 'host(s) tested']):
                            continue
                        
                        severity = VulnSeverity.INFO
                        msg_lower = msg.lower()
                        if any(kw in msg_lower for kw in ['vulnerable', 'injection', 'xss']):
                            severity = VulnSeverity.HIGH
                        elif any(kw in msg_lower for kw in ['directory', 'listing', 'backup', 'config']):
                            severity = VulnSeverity.MEDIUM
                        elif any(kw in msg_lower for kw in ['outdated', 'version']):
                            severity = VulnSeverity.LOW
                        
                        finding = VulnerabilityFinding(
                            finding_id=f"{scan_id}-nikto-{len(self.scan_results.get(scan_id, []))+1:04d}",
                            scanner='nikto',
                            host=target,
                            severity=severity,
                            title=f"{uri}: {msg[:60]}",
                            description=msg,
                            tags=['nikto', 'web'],
                            raw_output=line[:500]
                        )
                        self.scan_results[scan_id].append(finding)
                        
            logger.info(f"Parsed {len(self.scan_results.get(scan_id, []))} findings from Nikto text output")
        except Exception as e:
            logger.error(f"Error parsing Nikto text output: {e}")
    
    def _run_sqlmap_scan(self, scan_id: str, target: str, options: Dict):
        """Run SQLMap SQL injection scan"""
        sqlmap_path = self._tool_paths.get('sqlmap')
        if not sqlmap_path:
            raise RuntimeError("SQLMap not installed")
        
        progress = self.active_scans[scan_id]
        
        with tempfile.TemporaryDirectory() as output_dir:
            cmd = [
                'python3', sqlmap_path,
                '-u', target,
                '--batch',
                '--level', str(options.get('level', 1)),
                '--risk', str(options.get('risk', 1)),
                '--output-dir', output_dir,
                '--forms' if options.get('forms', False) else '',
                '--crawl', str(options.get('crawl_depth', 1))
            ]
            
            # Remove empty strings
            cmd = [c for c in cmd if c]
            
            logger.debug(f"Running SQLMap: {' '.join(cmd)}")
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Read output for progress
                for line in iter(process.stdout.readline, ''):
                    if 'identified the following injection' in line.lower():
                        progress.findings_count += 1
                    if 'testing' in line.lower():
                        progress.current_check = line.strip()[:100]
                
                process.wait(timeout=1800)  # 30 min max
                
                # Parse output directory for results
                self._parse_sqlmap_output(output_dir, scan_id, target)
                
            except subprocess.TimeoutExpired:
                process.kill()
                progress.error_message = "SQLMap scan timed out"
    
    def _parse_sqlmap_output(self, output_dir: str, scan_id: str, target: str):
        """Parse SQLMap output directory"""
        try:
            # SQLMap stores results in target-specific subdirectories
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    if file == 'log':
                        log_path = os.path.join(root, file)
                        with open(log_path, 'r') as f:
                            content = f.read()
                            
                        # Look for injection points
                        if 'injectable' in content.lower():
                            finding = VulnerabilityFinding(
                                finding_id=f"{scan_id}-sqli-{len(self.scan_results.get(scan_id, []))+1:04d}",
                                scanner='sqlmap',
                                host=target,
                                port=None,
                                severity=VulnSeverity.CRITICAL,
                                title='SQL Injection Vulnerability',
                                description='SQLMap identified SQL injection vulnerability',
                                cwe_ids=['CWE-89'],
                                tags=['sqli', 'injection', 'critical'],
                                evidence=content[:2000],
                                remediation='Use parameterized queries and input validation'
                            )
                            self.scan_results[scan_id].append(finding)
                            
        except Exception as e:
            logger.error(f"Error parsing SQLMap output: {e}")
    
    def _run_nmap_vuln_scan(self, scan_id: str, target: str, options: Dict):
        """Run Nmap vulnerability scripts"""
        nmap_path = self._tool_paths.get('nmap')
        if not nmap_path:
            raise RuntimeError("Nmap not installed")
        
        progress = self.active_scans[scan_id]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            ports = options.get('ports', '21,22,23,25,80,443,445,3306,3389,8080')
            scripts = options.get('scripts', 'vuln,auth,default')
            
            cmd = [
                'sudo', nmap_path,
                '-sV',
                '-p', ports,
                f'--script={scripts}',
                '-oX', output_path,
                '--host-timeout', '10m',
                target
            ]
            
            logger.debug(f"Running Nmap vuln: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=900)
            
            # Parse XML output
            self._parse_nmap_vuln_xml(output_path, scan_id)
            
        except subprocess.TimeoutExpired:
            process.kill()
            progress.error_message = "Nmap vuln scan timed out"
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _parse_nmap_vuln_xml(self, xml_path: str, scan_id: str):
        """Parse Nmap XML output for vulnerabilities"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                addr_elem = host.find('.//address[@addrtype="ipv4"]')
                host_ip = addr_elem.get('addr', '') if addr_elem is not None else ''
                
                for port in host.findall('.//port'):
                    port_id = port.get('portid', '')
                    
                    for script in port.findall('.//script'):
                        script_id = script.get('id', '')
                        output = script.get('output', '')
                        
                        # Look for vulnerability indicators
                        if 'VULNERABLE' in output or 'vuln' in script_id.lower():
                            # Extract CVEs from output
                            cve_pattern = r'CVE-\d{4}-\d+'
                            cves = re.findall(cve_pattern, output)
                            
                            severity = VulnSeverity.HIGH if cves else VulnSeverity.MEDIUM
                            
                            finding = VulnerabilityFinding(
                                finding_id=f"{scan_id}-nmap-{len(self.scan_results.get(scan_id, []))+1:04d}",
                                scanner='nmap_vuln',
                                host=host_ip,
                                port=int(port_id) if port_id.isdigit() else None,
                                severity=severity,
                                title=f"Nmap {script_id}",
                                description=output[:500],
                                cve_ids=cves,
                                tags=['nmap', 'vuln-script'],
                                raw_output=output[:2000]
                            )
                            
                            self.scan_results[scan_id].append(finding)
                            
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
    
    def _run_whatweb_scan(self, scan_id: str, target: str, options: Dict):
        """Run WhatWeb technology fingerprinting"""
        whatweb_path = self._tool_paths.get('whatweb')
        if not whatweb_path:
            raise RuntimeError("WhatWeb not installed")
        
        progress = self.active_scans[scan_id]
        
        try:
            cmd = [
                whatweb_path,
                '--log-json=-',
                '-a', str(options.get('aggression', 3)),
                target
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Parse JSON output
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        self._parse_whatweb_result(data, scan_id)
                    except json.JSONDecodeError:
                        continue
                        
        except subprocess.TimeoutExpired:
            progress.error_message = "WhatWeb scan timed out"
    
    def _parse_whatweb_result(self, data: Dict, scan_id: str):
        """Parse WhatWeb JSON result"""
        try:
            plugins = data.get('plugins', {})
            target = data.get('target', '')
            
            for plugin_name, plugin_data in plugins.items():
                # Check for version info or interesting findings
                version = None
                if isinstance(plugin_data, dict):
                    version = plugin_data.get('version', [])
                    if isinstance(version, list) and version:
                        version = version[0]
                
                # Only create findings for interesting technologies
                interesting = ['WordPress', 'Drupal', 'Joomla', 'phpMyAdmin', 
                             'Apache', 'nginx', 'IIS', 'PHP', 'ASP.NET']
                
                if plugin_name in interesting:
                    finding = VulnerabilityFinding(
                        finding_id=f"{scan_id}-whatweb-{len(self.scan_results.get(scan_id, []))+1:04d}",
                        scanner='whatweb',
                        host=target,
                        port=None,
                        severity=VulnSeverity.INFO,
                        title=f"Technology: {plugin_name}",
                        description=f"Detected {plugin_name}" + (f" version {version}" if version else ""),
                        tags=['technology', 'fingerprint', plugin_name.lower()],
                        evidence=str(version) if version else ''
                    )
                    
                    self.scan_results[scan_id].append(finding)
                    
        except Exception as e:
            logger.debug(f"Error parsing WhatWeb result: {e}")

    # =========================================================================
    # OWASP ZAP Integration
    # =========================================================================

    def _is_zap_running(self) -> bool:
        """Check if ZAP daemon is running and responsive"""
        try:
            url = f"{self._zap_base_url}/JSON/core/view/version/?apikey={self._zap_api_key}"
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200
        except urllib.error.HTTPError as e:
            # ZAP is running but API key is wrong (401/403) - it's still running
            if e.code in (401, 403):
                logger.warning(f"ZAP is running but API key may be incorrect (HTTP {e.code}). "
                              f"Try disabling the API key in ZAP or setting it to match.")
                return True
            return False
        except Exception:
            return False

    def _zap_api_call(self, endpoint: str, params: Dict = None) -> Dict:
        """Make a ZAP API call and return JSON response"""
        params = params or {}
        params['apikey'] = self._zap_api_key

        query_string = urllib.parse.urlencode(params)
        url = f"{self._zap_base_url}/{endpoint}?{query_string}"

        try:
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            # Read the error response body for more details
            error_body = ""
            try:
                error_body = e.read().decode('utf-8', errors='replace')
            except:
                pass
            logger.error(f"ZAP API HTTP error: {e.code} - {e.reason}. Endpoint: {endpoint}. Response: {error_body[:500]}")

            # Parse ZAP error response for better messages
            friendly_error = self._parse_zap_error(e.code, error_body, endpoint, params)
            raise RuntimeError(friendly_error)
        except urllib.error.URLError as e:
            logger.error(f"ZAP API URL error: {e.reason}. Is ZAP running?")
            raise RuntimeError(f"Cannot connect to ZAP: {e.reason}. Make sure ZAP daemon is running.")
        except Exception as e:
            logger.error(f"ZAP API error: {e}")
            raise

    def _parse_zap_error(self, code: int, error_body: str, endpoint: str, params: Dict) -> str:
        """Parse ZAP error response into a user-friendly message"""
        # Try to parse JSON error from ZAP
        error_detail = ""
        try:
            error_json = json.loads(error_body)
            error_detail = error_json.get('message', '') or error_json.get('error', '')
        except:
            error_detail = error_body[:200] if error_body else ""

        # Check for common 500 error causes
        if code == 500:
            target_url = params.get('url', '')

            # URL-related errors
            if 'url' in endpoint.lower() or target_url:
                if not target_url:
                    return "ZAP Error: No target URL provided for scan."

                # Check URL format
                if not target_url.startswith(('http://', 'https://')):
                    return f"ZAP Error: Invalid URL format '{target_url}'. URL must start with http:// or https://"

                # Common ZAP 500 causes
                if 'failed to connect' in error_detail.lower() or 'connection' in error_detail.lower():
                    return f"ZAP Error: Cannot connect to target '{target_url}'. Check if the target is accessible and the URL is correct."

                if 'timeout' in error_detail.lower():
                    return f"ZAP Error: Connection to '{target_url}' timed out. Target may be slow or unreachable."

                if 'ssl' in error_detail.lower() or 'certificate' in error_detail.lower():
                    return f"ZAP Error: SSL/TLS error connecting to '{target_url}'. The target may have certificate issues."

                # Generic target error
                return (f"ZAP Error: Failed to access target '{target_url}'. "
                        f"Possible causes: target unreachable, invalid URL, SSL issues, or network problems. "
                        f"Details: {error_detail[:100]}" if error_detail else
                        f"ZAP Error: Failed to access target '{target_url}'. Check if the URL is correct and the target is accessible.")

            # Spider/scan errors
            if 'spider' in endpoint.lower():
                return f"ZAP Spider Error: {error_detail[:150] if error_detail else 'Internal error during spidering. Try clearing ZAP session and retrying.'}"

            if 'ascan' in endpoint.lower():
                return f"ZAP Active Scan Error: {error_detail[:150] if error_detail else 'Internal error during active scan. Try clearing ZAP session and retrying.'}"

            # Context errors
            if 'context' in endpoint.lower():
                return f"ZAP Context Error: {error_detail[:150] if error_detail else 'Error managing scan context. Try clearing ZAP session.'}"

            # Generic 500 error
            return f"ZAP Internal Error (500): {error_detail[:200] if error_detail else 'An internal error occurred. Try restarting ZAP or clearing the session.'}"

        # Other HTTP errors
        return f"ZAP API error {code}: {error_detail[:200] if error_detail else 'Unknown error'}"

    def _validate_target_url(self, target: str) -> Tuple[bool, str]:
        """Validate that a target URL is properly formatted and potentially reachable"""
        if not target:
            return False, "Target URL is empty"

        # Check URL scheme
        if not target.startswith(('http://', 'https://')):
            return False, f"Invalid URL scheme. URL must start with http:// or https://, got: {target[:50]}"

        # Parse URL
        try:
            parsed = urllib.parse.urlparse(target)
            if not parsed.netloc:
                return False, f"Invalid URL format - no host found: {target[:50]}"
        except Exception as e:
            return False, f"URL parsing error: {e}"

        # Quick connectivity check (with short timeout)
        try:
            host = parsed.netloc.split(':')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result != 0:
                return False, f"Cannot connect to {host}:{port}. Target may be unreachable or firewall is blocking."
        except socket.gaierror:
            return False, f"Cannot resolve hostname: {parsed.netloc}. Check if the URL is correct."
        except socket.timeout:
            return False, f"Connection to {parsed.netloc} timed out. Target may be slow or unreachable."
        except Exception as e:
            # Don't fail on connectivity check errors, just warn
            logger.warning(f"Target connectivity check failed (non-fatal): {e}")

        return True, ""

    def start_zap_daemon(self, port: int = None) -> bool:
        """Start ZAP in daemon mode"""
        if self._is_zap_running():
            # Verify API key works by making a real API call
            try:
                self._zap_api_call('JSON/core/view/version')
                logger.info("ZAP daemon already running and API key is valid")
                return True
            except Exception as e:
                logger.warning(f"ZAP daemon is running but API key validation failed: {e}. "
                              f"Will try to disable API key requirement or restart ZAP.")
                # Try with no API key (ZAP may have been started without one)
                try:
                    url = f"{self._zap_base_url}/JSON/core/view/version/"
                    req = urllib.request.Request(url, method='GET')
                    with urllib.request.urlopen(req, timeout=5) as response:
                        if response.status == 200:
                            logger.info("ZAP is running without API key - disabling API key requirement")
                            self._zap_api_key = ''
                            return True
                except Exception:
                    pass
                # ZAP is running with a different API key - cannot use it
                logger.error("ZAP daemon is running with a different API key. "
                            "Please stop ZAP and let Ragnar start it, or configure matching API keys.")
                return False

        zap_path = self._tool_paths.get('zap')
        if not zap_path:
            logger.error("OWASP ZAP not installed")
            return False

        port = port or self._zap_port
        self._zap_port = port
        self._zap_base_url = f"http://127.0.0.1:{port}"

        # Build command based on platform
        import sys
        is_windows = sys.platform == 'win32'

        if is_windows:
            # Windows uses .bat file or java directly
            cmd = [
                zap_path,
                '-daemon',
                '-port', str(port),
                '-config', f'api.key={self._zap_api_key}',
                '-config', 'api.addrs.addr.name=127.0.0.1',
                '-config', 'api.addrs.addr.regex=true',
                '-config', 'connection.timeoutInSecs=120',
            ]
        else:
            cmd = [
                zap_path,
                '-daemon',
                '-port', str(port),
                '-config', f'api.key={self._zap_api_key}',
                '-config', 'api.addrs.addr.name=127.0.0.1',
                '-config', 'api.addrs.addr.regex=true',
                '-config', 'connection.timeoutInSecs=120',
            ]

        logger.info(f"Starting ZAP daemon on port {port}...")

        try:
            # Use shell=True on Windows for .bat files
            popen_kwargs = {
                'stdout': subprocess.PIPE,
                'stderr': subprocess.PIPE,
                'text': True,
                'shell': is_windows,  # Required for .bat files on Windows
            }
            # CREATE_NO_WINDOW only exists on Windows
            if is_windows:
                popen_kwargs['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

            self._zap_process = subprocess.Popen(cmd, **popen_kwargs)

            # Wait for ZAP to start
            start_time = time.time()
            while time.time() - start_time < self.ZAP_STARTUP_TIMEOUT:
                if self._is_zap_running():
                    logger.info(f"ZAP daemon started successfully on port {port}")
                    return True
                time.sleep(2)

            logger.error("ZAP daemon failed to start within timeout")
            return False

        except Exception as e:
            logger.error(f"Failed to start ZAP daemon: {e}")
            return False

    def stop_zap_daemon(self) -> bool:
        """Stop the ZAP daemon"""
        try:
            if self._is_zap_running():
                self._zap_api_call('JSON/core/action/shutdown')
                time.sleep(2)

            if self._zap_process:
                self._zap_process.terminate()
                self._zap_process.wait(timeout=10)
                self._zap_process = None

            logger.info("ZAP daemon stopped")
            return True

        except Exception as e:
            logger.error(f"Error stopping ZAP daemon: {e}")
            if self._zap_process:
                self._zap_process.kill()
                self._zap_process = None
            return False

    def get_zap_status(self) -> Dict[str, Any]:
        """Get ZAP daemon status and info"""
        status = {
            'installed': self._tool_paths.get('zap') is not None,
            'running': False,
            'port': self._zap_port,
            'version': None,
            'hosts_accessed': 0,
            'alerts_count': 0,
            'messages_count': 0,
        }

        if not self._is_zap_running():
            return status

        status['running'] = True

        try:
            # Get version
            version_resp = self._zap_api_call('JSON/core/view/version')
            status['version'] = version_resp.get('version')

            # Get stats
            hosts_resp = self._zap_api_call('JSON/core/view/hosts')
            status['hosts_accessed'] = len(hosts_resp.get('hosts', []))

            alerts_resp = self._zap_api_call('JSON/core/view/numberOfAlerts')
            status['alerts_count'] = int(alerts_resp.get('numberOfAlerts', 0))

            msgs_resp = self._zap_api_call('JSON/core/view/numberOfMessages')
            status['messages_count'] = int(msgs_resp.get('numberOfMessages', 0))

        except Exception as e:
            logger.debug(f"Error getting ZAP status: {e}")

        return status

    def _zap_add_to_scope(self, target: str) -> bool:
        """Add target URL to ZAP scope (for focused scanning)"""
        try:
            # Create a context for the target
            context_name = f"ragnar_{int(time.time())}"
            self._zap_api_call('JSON/context/action/newContext', {'contextName': context_name})

            # Add target to context scope
            # Escape the URL for regex
            url_pattern = target.replace('.', '\\.').replace('/', '\\/')
            if not url_pattern.endswith('.*'):
                url_pattern += '.*'

            self._zap_api_call('JSON/context/action/includeInContext', {
                'contextName': context_name,
                'regex': url_pattern
            })

            logger.info(f"Added {target} to ZAP scope (context: {context_name})")
            return True

        except Exception as e:
            logger.error(f"Error adding target to ZAP scope: {e}")
            return False

    def _run_zap_spider(self, scan_id: str, target: str, options: Dict):
        """Run ZAP spider to discover URLs"""
        if not self._is_zap_running():
            if not self.start_zap_daemon():
                raise RuntimeError("Failed to start ZAP daemon")

        progress = self.active_scans[scan_id]
        progress.current_check = "Validating target URL..."

        # Validate target URL first
        is_valid, error_msg = self._validate_target_url(target)
        if not is_valid:
            raise RuntimeError(f"Target URL validation failed: {error_msg}")

        progress.current_check = "Starting ZAP spider..."

        try:
            # Add target to scope
            self._zap_add_to_scope(target)

            # Access the target first to seed ZAP
            progress.current_check = "Accessing target URL..."
            try:
                self._zap_api_call('JSON/core/action/accessUrl', {'url': target, 'followRedirects': 'true'})
            except RuntimeError as e:
                # If accessing URL fails, provide helpful message
                error_str = str(e)
                if '500' in error_str:
                    raise RuntimeError(f"ZAP cannot access target '{target}'. Verify the URL is correct and the target is accessible from this machine.")
                raise
            time.sleep(2)

            # Start spider
            max_children = options.get('max_children', 10)
            recurse = options.get('recurse', True)
            subtree_only = options.get('subtree_only', True)

            spider_resp = self._zap_api_call('JSON/spider/action/scan', {
                'url': target,
                'maxChildren': str(max_children),
                'recurse': str(recurse).lower(),
                'subtreeOnly': str(subtree_only).lower()
            })

            spider_id = spider_resp.get('scan')
            if not spider_id:
                raise RuntimeError("Failed to start ZAP spider")

            logger.info(f"ZAP spider started with ID: {spider_id}")

            # Monitor spider progress
            while True:
                status_resp = self._zap_api_call('JSON/spider/view/status', {'scanId': spider_id})
                spider_progress = int(status_resp.get('status', 0))
                progress.progress_percent = spider_progress
                progress.current_check = f"Spidering... {spider_progress}%"

                if spider_progress >= 100:
                    break

                time.sleep(2)

            # Get spider results
            results_resp = self._zap_api_call('JSON/spider/view/results', {'scanId': spider_id})
            urls_found = results_resp.get('results', [])

            logger.info(f"ZAP spider completed. Found {len(urls_found)} URLs")

            # Create info finding for discovered URLs
            if urls_found:
                finding = VulnerabilityFinding(
                    finding_id=f"{scan_id}-zap-spider-001",
                    scanner='zap_spider',
                    host=target,
                    port=None,
                    severity=VulnSeverity.INFO,
                    title=f"Spider Discovery: {len(urls_found)} URLs found",
                    description=f"ZAP spider discovered {len(urls_found)} URLs on the target",
                    tags=['zap', 'spider', 'discovery'],
                    evidence='\n'.join(urls_found[:50]),  # First 50 URLs
                    raw_output=json.dumps(urls_found[:100])
                )
                self.scan_results[scan_id].append(finding)

            # Also fetch any passive scan alerts found during spidering
            self._fetch_zap_alerts(scan_id, target)

        except Exception as e:
            logger.error(f"ZAP spider error: {e}")
            # Add auth hint if auth is configured
            error_msg = str(e)
            auth_status = self.zap_get_auth_status()
            if auth_status.get('has_auth'):
                error_msg += " [Note: Authentication is configured. If target doesn't require auth, clear ZAP auth settings.]"
            raise RuntimeError(error_msg)

    def _run_zap_active_scan(self, scan_id: str, target: str, options: Dict):
        """Run ZAP active vulnerability scan"""
        if not self._is_zap_running():
            if not self.start_zap_daemon():
                raise RuntimeError("Failed to start ZAP daemon")

        progress = self.active_scans[scan_id]
        progress.current_check = "Validating target URL..."

        # Validate target URL first
        is_valid, error_msg = self._validate_target_url(target)
        if not is_valid:
            raise RuntimeError(f"Target URL validation failed: {error_msg}")

        progress.current_check = "Starting ZAP active scan..."

        try:
            # Add target to scope
            self._zap_add_to_scope(target)

            # Access target first to seed ZAP
            progress.current_check = "Accessing target URL..."
            try:
                self._zap_api_call('JSON/core/action/accessUrl', {'url': target, 'followRedirects': 'true'})
            except RuntimeError as e:
                error_str = str(e)
                if '500' in error_str:
                    raise RuntimeError(f"ZAP cannot access target '{target}'. Verify the URL is correct and the target is accessible from this machine.")
                raise
            time.sleep(2)

            # Run a quick spider first to discover URLs for active scanning
            progress.current_check = "Quick spider to discover URLs..."
            logger.info(f"Running quick spider before active scan on {target}")

            spider_resp = self._zap_api_call('JSON/spider/action/scan', {
                'url': target,
                'maxChildren': '5',
                'recurse': 'true',
                'subtreeOnly': 'true'
            })
            spider_id = spider_resp.get('scan')

            if spider_id:
                # Wait for spider to complete (with timeout)
                spider_start = time.time()
                spider_timeout = 120  # 2 minutes max for quick spider

                while time.time() - spider_start < spider_timeout:
                    try:
                        status_resp = self._zap_api_call('JSON/spider/view/status', {'scanId': spider_id})
                        spider_progress = int(status_resp.get('status', 0))
                        progress.progress_percent = int(spider_progress * 0.2)  # 0-20% for spider
                        progress.current_check = f"Discovering URLs... {spider_progress}%"

                        if spider_progress >= 100:
                            break
                    except Exception as e:
                        logger.warning(f"Spider status check error: {e}")
                        break

                    time.sleep(2)

                # Get URLs found
                try:
                    results_resp = self._zap_api_call('JSON/spider/view/results', {'scanId': spider_id})
                    urls_found = results_resp.get('results', [])
                    logger.info(f"Quick spider found {len(urls_found)} URLs")
                except Exception:
                    urls_found = []

            # Configure scan policy if specified
            scan_policy = options.get('scan_policy', 'Default Policy')

            # Start active scan
            progress.current_check = "Starting active vulnerability scan..."
            scan_params = {
                'url': target,
                'recurse': str(options.get('recurse', True)).lower(),
                'inScopeOnly': str(options.get('in_scope_only', True)).lower(),
            }

            if scan_policy and scan_policy in self.ZAP_SCAN_POLICIES:
                scan_params['scanPolicyName'] = scan_policy

            scan_resp = self._zap_api_call('JSON/ascan/action/scan', scan_params)
            scan_id_zap = scan_resp.get('scan')

            if not scan_id_zap:
                raise RuntimeError("Failed to start ZAP active scan - no scan ID returned")

            logger.info(f"ZAP active scan started with ID: {scan_id_zap}")

            # Monitor scan progress with timeout
            scan_start = time.time()
            scan_timeout = 1800  # 30 minutes max for active scan
            last_progress = -1
            stall_count = 0

            while time.time() - scan_start < scan_timeout:
                try:
                    status_resp = self._zap_api_call('JSON/ascan/view/status', {'scanId': scan_id_zap})
                    scan_progress = int(status_resp.get('status', 0))

                    # Map 0-100 to 20-100 (spider was 0-20)
                    progress.progress_percent = 20 + int(scan_progress * 0.8)
                    progress.current_check = f"Active scanning... {scan_progress}%"

                    # Update findings count (no baseurl filter for reliability)
                    alerts_resp = self._zap_api_call('JSON/core/view/numberOfAlerts', {})
                    progress.findings_count = int(alerts_resp.get('numberOfAlerts', 0))

                    if scan_progress >= 100:
                        break

                    # Check for stalled scan (no progress for 60 seconds)
                    if scan_progress == last_progress:
                        stall_count += 1
                        if stall_count >= 12:  # 12 * 5 seconds = 60 seconds
                            logger.warning(f"Active scan appears stalled at {scan_progress}%, checking if complete")
                            # Check if scan is actually done
                            scanners_resp = self._zap_api_call('JSON/ascan/view/scanProgress', {'scanId': scan_id_zap})
                            if not scanners_resp.get('scanProgress'):
                                logger.info("Scan appears complete (no active scanners)")
                                break
                    else:
                        stall_count = 0
                        last_progress = scan_progress

                except Exception as e:
                    logger.warning(f"Active scan status check error: {e}")

                time.sleep(5)

            if time.time() - scan_start >= scan_timeout:
                logger.warning(f"Active scan timed out after {scan_timeout} seconds")

            logger.info(f"ZAP active scan completed")

            # Fetch all alerts
            self._fetch_zap_alerts(scan_id, target)

        except Exception as e:
            logger.error(f"ZAP active scan error: {e}")
            # Add auth hint if auth is configured
            error_msg = str(e)
            auth_status = self.zap_get_auth_status()
            if auth_status.get('has_auth'):
                error_msg += " [Note: Authentication is configured. If target doesn't require auth, clear ZAP auth settings.]"
            raise RuntimeError(error_msg)

    def _get_zap_context_id(self, context_name: str = 'default') -> Optional[str]:
        """Get ZAP context ID by name, returns None if not found"""
        try:
            ctx_resp = self._zap_api_call('JSON/context/view/context', {'contextName': context_name})
            return ctx_resp.get('context', {}).get('id')
        except Exception:
            return None

    def _verify_zap_auth(self, target: str, options: Dict, progress: ScanProgress) -> bool:
        """Verify authentication works by making an authenticated request to the target.
        Returns True if auth is verified or not needed, False if auth failed."""
        auth_status = self.zap_get_auth_status()
        if not auth_status.get('has_auth'):
            return True  # No auth configured, skip verification

        progress.current_check = "Verifying authentication..."
        auth_type = auth_status.get('auth_type', 'unknown')
        logger.info(f"Verifying {auth_type} authentication against {target}")

        try:
            # For simple auth types, verify by making a request through ZAP
            # Access the target URL - ZAP will apply configured auth
            self._zap_api_call('JSON/core/action/accessUrl', {
                'url': target, 'followRedirects': 'true'
            })
            time.sleep(1)

            # Check if we got a non-error response by looking at ZAP's message history
            try:
                msgs_resp = self._zap_api_call('JSON/core/view/messages', {
                    'baseurl': target, 'start': '0', 'count': '5'
                })
                messages = msgs_resp.get('messages', [])
                if messages:
                    last_msg = messages[-1]
                    status_code = 0
                    resp_header = last_msg.get('responseHeader', '')
                    if resp_header:
                        # Parse "HTTP/1.1 200 OK" format safely
                        parts = resp_header.split(' ', 2)
                        if len(parts) >= 2 and parts[1].isdigit():
                            status_code = int(parts[1])
                    if status_code in (401, 403):
                        logger.warning(f"Auth verification got {status_code} - credentials may be invalid")
                        progress.current_check = f"Auth verification warning: got HTTP {status_code}"
                    else:
                        logger.info(f"Auth verification OK - got HTTP {status_code}")
            except Exception as msg_err:
                logger.debug(f"Could not check auth verification response: {msg_err}")

            return True
        except Exception as e:
            logger.warning(f"Auth verification failed: {e}")
            return True  # Don't block scan on verification failure

    def _apply_scan_auth(self, options: Dict) -> Tuple[bool, str]:
        """Apply authentication for this scan using ZAP Replacer rules.
        Returns (auth_applied: bool, auth_type: str)."""
        auth_type = ""
        
        # Cookie auth
        if options.get('cookie_value'):
            try:
                # Remove any existing cookie rule first
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-Cookie'})
                except Exception:
                    pass
                
                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-Cookie',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': 'Cookie',
                    'replacement': options['cookie_value'],
                    'initiators': ''
                })
                logger.info("Applied cookie auth for scan")
                auth_type = "cookie"
            except Exception as e:
                logger.error(f"Failed to apply cookie auth: {e}")
                return (False, "cookie (failed)")
        
        # Bearer token auth
        if options.get('bearer_token'):
            try:
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-Bearer'})
                except Exception:
                    pass
                
                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-Bearer',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': 'Authorization',
                    'replacement': f"Bearer {options['bearer_token']}",
                    'initiators': ''
                })
                logger.info("Applied bearer token auth for scan")
                auth_type = "bearer_token"
            except Exception as e:
                logger.error(f"Failed to apply bearer token auth: {e}")
                return (False, "bearer_token (failed)")
        
        # API key auth
        if options.get('api_key'):
            try:
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-APIKey'})
                except Exception:
                    pass
                
                header_name = options.get('api_key_header', 'X-API-Key')
                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-APIKey',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': header_name,
                    'replacement': options['api_key'],
                    'initiators': ''
                })
                logger.info(f"Applied API key auth for scan ({header_name})")
                auth_type = f"api_key ({header_name})"
            except Exception as e:
                logger.error(f"Failed to apply API key auth: {e}")
                return (False, "api_key (failed)")
        
        # HTTP Basic auth
        if options.get('http_basic_auth'):
            try:
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {'description': 'ScanAuth-Basic'})
                except Exception:
                    pass
                
                import base64
                auth_string = base64.b64encode(options['http_basic_auth'].encode()).decode()
                self._zap_api_call('JSON/replacer/action/addRule', {
                    'description': 'ScanAuth-Basic',
                    'enabled': 'true',
                    'matchType': 'REQ_HEADER',
                    'matchRegex': 'false',
                    'matchString': 'Authorization',
                    'replacement': f"Basic {auth_string}",
                    'initiators': ''
                })
                logger.info("Applied HTTP Basic auth for scan")
                auth_type = "http_basic"
            except Exception as e:
                logger.error(f"Failed to apply HTTP Basic auth: {e}")
                return (False, "http_basic (failed)")
        
        return (bool(auth_type), auth_type)

    def _clear_scan_auth(self):
        """Clear all scan-specific auth rules from ZAP Replacer"""
        rules_to_remove = ['ScanAuth-Cookie', 'ScanAuth-Bearer', 'ScanAuth-APIKey', 'ScanAuth-Basic']
        for rule in rules_to_remove:
            try:
                self._zap_api_call('JSON/replacer/action/removeRule', {'description': rule})
            except Exception:
                pass  # Rule may not exist

    def _verify_auth_request(self, target: str) -> Tuple[bool, int]:
        """
        Make a test request to verify auth is working.
        Returns (verified: bool, http_status: int)
        - verified=True if status is 2xx or 3xx (success/redirect)
        - verified=False if status is 401/403 (auth failed) or other error
        """
        try:
            # Access the target URL via ZAP to test auth
            self._zap_api_call('JSON/core/action/accessUrl', {
                'url': target,
                'followRedirects': 'true'
            })
            
            # Give ZAP a moment to process the request
            time.sleep(1)
            
            # Get the most recent message from the history
            messages = self._zap_api_call('JSON/core/view/messages', {
                'baseurl': target,
                'start': '0',
                'count': '5'
            })
            
            if messages and 'messages' in messages and len(messages['messages']) > 0:
                # Get the most recent message
                latest_msg = messages['messages'][-1]
                status_code = int(latest_msg.get('responseHeader', '').split(' ')[1]) if 'responseHeader' in latest_msg else 0
                
                if status_code == 0:
                    # Try to extract from responseStatusCode if available
                    status_code = int(latest_msg.get('statusCode', 0) or 0)
                
                if 200 <= status_code < 400:
                    return (True, status_code)
                else:
                    return (False, status_code)
            
            # If we can't get messages, return unknown status
            logger.warning("Could not retrieve response to verify auth")
            return (True, 0)  # Assume applied if we can't verify
            
        except Exception as e:
            logger.error(f"Error verifying auth request: {e}")
            return (True, 0)  # Assume applied if we can't verify

    def _run_zap_full_scan(self, scan_id: str, target: str, options: Dict):
        """Run complete ZAP scan: spider + ajax spider + active scan"""
        if not self._is_zap_running():
            if not self.start_zap_daemon():
                raise RuntimeError("Failed to start ZAP daemon")

        progress = self.active_scans[scan_id]
        progress.current_check = "Validating target URL..."

        # Validate target URL first
        is_valid, error_msg = self._validate_target_url(target)
        if not is_valid:
            raise RuntimeError(f"Target URL validation failed: {error_msg}")

        # Apply inline auth if provided in options (per-scan auth)
        auth_applied, auth_type = self._apply_scan_auth(options)
        has_auth = auth_applied
        
        # Update progress with auth info and verify auth
        if auth_type:
            progress.auth_type = auth_type
            progress.auth_status = "applied"
            progress.current_check = f"Verifying {auth_type} auth..."
            
            # Verify auth by making a test request
            auth_verified, http_status = self._verify_auth_request(target)
            if auth_verified:
                progress.auth_status = f"verified (HTTP {http_status})"
                progress.current_check = f"Auth verified: {auth_type} (HTTP {http_status})"
                logger.info(f"Auth verification successful: HTTP {http_status}")
            else:
                progress.auth_status = f"failed (HTTP {http_status})"
                progress.current_check = f"Auth may have failed: {auth_type} (HTTP {http_status})"
                logger.warning(f"Auth verification warning: HTTP {http_status}")
        
        # Get or create context ID if auth is configured
        context_id = self._get_zap_context_id('default')
        if has_auth and not context_id:
            # Auth is configured - create 'default' context for the target URL
            try:
                self._zap_api_call('JSON/context/action/newContext', {'contextName': 'default'})
                context_id = self._get_zap_context_id('default')
                logger.info(f"Created 'default' context for authenticated scan (ID: {context_id})")
            except Exception as e:
                logger.warning(f"Could not create default context: {e}")
        
        if context_id:
            options['_context_id'] = context_id
            options['_has_auth'] = has_auth
            logger.info(f"Using ZAP context ID {context_id} for scan (auth configured: {has_auth})")
        elif has_auth:
            options['_has_auth'] = has_auth

        alerts_fetched = False

        try:
            # Phase 1: Spider
            progress.current_check = "Phase 1/3: Running spider..."
            self._run_zap_spider_phase(scan_id, target, options, progress)

            # Phase 2: Ajax Spider (if enabled)
            if options.get('ajax_spider', True):
                progress.current_check = "Phase 2/3: Running Ajax spider..."
                self._run_zap_ajax_spider_phase(scan_id, target, options, progress)

            # Phase 3: Active Scan (this now fetches alerts if it stalls)
            progress.current_check = "Phase 3/3: Running active scan..."
            self._run_zap_active_scan_phase(scan_id, target, options, progress)

            # Final: Fetch all alerts (in case active scan completed normally)
            progress.current_check = "Fetching vulnerability alerts..."
            try:
                self._fetch_zap_alerts(scan_id, target)
                alerts_fetched = True
            except Exception as fetch_err:
                logger.error(f"Failed to fetch alerts after scan phases: {fetch_err}")
                progress.error_message = f"Scan phases completed but alert fetching failed: {fetch_err}"

            findings_count = len(self.scan_results.get(scan_id, []))
            logger.info(f"ZAP full scan completed with {findings_count} findings")

            if findings_count == 0 and not alerts_fetched:
                logger.warning(f"ZAP scan {scan_id} completed with 0 findings - alert fetching may have failed")

        except Exception as e:
            logger.error(f"ZAP full scan error: {e}")
            # Try to fetch alerts even on error - don't lose findings
            if not alerts_fetched:
                try:
                    logger.info("Attempting to fetch ZAP alerts after error...")
                    self._fetch_zap_alerts(scan_id, target)
                except Exception as fetch_error:
                    logger.error(f"Failed to fetch alerts after error: {fetch_error}")
            raise RuntimeError(str(e))
        finally:
            # Clean up scan-specific auth rules
            if auth_applied:
                self._clear_scan_auth()
                logger.info("Cleared scan auth rules")

    def _run_zap_spider_phase(self, scan_id: str, target: str, options: Dict, progress: ScanProgress):
        """Spider phase of full scan"""
        # If auth is configured, add target to the 'default' context where auth lives
        # Otherwise, create a new scope context
        has_auth = options.get('_context_id') or options.get('_has_auth')
        if has_auth:
            # Auth is configured - add target URL to the 'default' context
            try:
                parsed_url = urllib.parse.urlparse(target)
                include_regex = f"{parsed_url.scheme}://{parsed_url.netloc}.*"
                self._zap_api_call('JSON/context/action/includeInContext', {
                    'contextName': 'default',
                    'regex': include_regex
                })
                logger.info(f"Added {include_regex} to auth context 'default'")
            except Exception as e:
                logger.warning(f"Could not add target to auth context: {e}")
                # Fall back to creating new scope
                self._zap_add_to_scope(target)
        else:
            self._zap_add_to_scope(target)

        # Access target with better error handling
        try:
            self._zap_api_call('JSON/core/action/accessUrl', {'url': target, 'followRedirects': 'true'})
        except RuntimeError as e:
            error_str = str(e)
            if '500' in error_str:
                raise RuntimeError(f"ZAP cannot access target '{target}'. Verify the URL is correct and the target is accessible from this machine.")
            raise
        time.sleep(1)

        spider_params = {
            'url': target,
            'maxChildren': str(options.get('max_children', 10)),
            'recurse': 'true',
            'subtreeOnly': 'true'
        }
        # Pass context name if auth is configured
        if has_auth:
            spider_params['contextName'] = 'default'
        spider_resp = self._zap_api_call('JSON/spider/action/scan', spider_params)
        spider_id = spider_resp.get('scan')

        if not spider_id:
            logger.warning("Failed to start spider phase, continuing...")
            return

        # Spider with timeout
        spider_start = time.time()
        spider_timeout = 300  # 5 minutes max for spider phase

        while time.time() - spider_start < spider_timeout:
            try:
                status_resp = self._zap_api_call('JSON/spider/view/status', {'scanId': spider_id})
                spider_progress = int(status_resp.get('status', 0))
                progress.progress_percent = int(spider_progress * 0.3)  # 30% of total
                progress.current_check = f"Phase 1/3: Spidering... {spider_progress}%"

                if spider_progress >= 100:
                    break
            except Exception as e:
                logger.warning(f"Spider status error: {e}")
                break

            time.sleep(2)

        if time.time() - spider_start >= spider_timeout:
            logger.warning("Spider phase timed out")

    def _run_zap_ajax_spider_phase(self, scan_id: str, target: str, options: Dict, progress: ScanProgress):
        """Ajax spider phase of full scan"""
        try:
            self._zap_api_call('JSON/ajaxSpider/action/scan', {
                'url': target,
                'inScope': 'true'
            })

            max_duration = options.get('ajax_spider_duration', 60)  # seconds
            start_time = time.time()

            while time.time() - start_time < max_duration:
                status_resp = self._zap_api_call('JSON/ajaxSpider/view/status')
                status = status_resp.get('status', 'stopped')
                if status == 'stopped':
                    break

                elapsed = time.time() - start_time
                progress.progress_percent = 30 + int((elapsed / max_duration) * 20)  # 30-50%
                time.sleep(3)

            # Stop ajax spider if still running
            self._zap_api_call('JSON/ajaxSpider/action/stop')

        except Exception as e:
            logger.warning(f"Ajax spider phase error (continuing): {e}")

    def _run_zap_active_scan_phase(self, scan_id: str, target: str, options: Dict, progress: ScanProgress):
        """Active scan phase of full scan"""
        ascan_params = {
            'url': target,
            'recurse': 'true',
            'inScopeOnly': 'true'
        }
        # Pass context ID if auth is configured
        context_id = options.get('_context_id')
        if context_id:
            ascan_params['contextId'] = context_id
        elif options.get('_has_auth'):
            # Auth is configured but no context ID - try to get it
            context_id = self._get_zap_context_id('default')
            if context_id:
                ascan_params['contextId'] = context_id
        scan_resp = self._zap_api_call('JSON/ascan/action/scan', ascan_params)
        ascan_id = scan_resp.get('scan')

        if not ascan_id:
            logger.warning("Failed to start active scan phase, continuing to alert fetch...")
            return

        # Active scan with timeout and stall detection
        scan_start = time.time()
        scan_timeout = 1800  # 30 minutes max for active scan phase
        last_progress = -1
        stall_count = 0

        while time.time() - scan_start < scan_timeout:
            try:
                status_resp = self._zap_api_call('JSON/ascan/view/status', {'scanId': ascan_id})
                scan_progress = int(status_resp.get('status', 0))
                progress.progress_percent = 50 + int(scan_progress * 0.5)  # 50-100%
                progress.current_check = f"Phase 3/3: Active scanning... {scan_progress}%"

                # Update findings count (fetch total without baseurl filter for reliability)
                try:
                    alerts_resp = self._zap_api_call('JSON/core/view/numberOfAlerts', {})
                    progress.findings_count = int(alerts_resp.get('numberOfAlerts', 0))
                except Exception:
                    pass

                if scan_progress >= 100:
                    break

                # Check for stalled scan
                if scan_progress == last_progress:
                    stall_count += 1
                    if stall_count >= 12:  # 60 seconds of no progress
                        logger.warning(f"Active scan phase stalled at {scan_progress}%, stopping active scan...")
                        break
                else:
                    stall_count = 0
                    last_progress = scan_progress

            except Exception as e:
                logger.warning(f"Active scan status error: {e}")
                break

            time.sleep(5)

        if time.time() - scan_start >= scan_timeout:
            logger.warning("Active scan phase timed out")

    def _fetch_zap_alerts(self, scan_id: str, target: str):
        """Fetch all ZAP alerts and convert to VulnerabilityFinding"""
        try:
            # Parse target to get host for flexible matching
            parsed_target = urllib.parse.urlparse(target)
            target_host = parsed_target.netloc or target
            target_host_no_port = parsed_target.hostname or ''
            target_no_slash = target.rstrip('/')

            # Always fetch ALL alerts - ZAP's baseurl filtering is unreliable
            logger.info(f"Fetching all ZAP alerts (target: {target}, host: {target_host})")
            alerts_resp = self._zap_api_call('JSON/core/view/alerts', {
                'start': '0',
                'count': '5000'
            })
            all_alerts = alerts_resp.get('alerts', [])
            logger.info(f"Total alerts in ZAP: {len(all_alerts)}")

            # Filter alerts matching this target by host
            alerts = []
            for alert in all_alerts:
                alert_url = alert.get('url', '')
                if not alert_url:
                    continue
                parsed_alert = urllib.parse.urlparse(alert_url)
                alert_host = parsed_alert.netloc or ''
                alert_host_no_port = parsed_alert.hostname or ''

                # Match by: full netloc (host:port), hostname only, or URL prefix
                if (target_host == alert_host or
                        target_host_no_port == alert_host_no_port or
                        alert_url.startswith(target_no_slash)):
                    alerts.append(alert)

            if all_alerts and not alerts:
                sample_urls = [a.get('url', 'N/A') for a in all_alerts[:5]]
                logger.warning(f"Found {len(all_alerts)} total alerts but none matched host '{target_host}'. Sample alert URLs: {sample_urls}")

            logger.info(f"Matched {len(alerts)} of {len(all_alerts)} alerts for {target}")

            for alert in alerts:
                finding = self._parse_zap_alert(alert, scan_id)
                if finding:
                    self.scan_results[scan_id].append(finding)

        except Exception as e:
            logger.error(f"Error fetching ZAP alerts: {e}", exc_info=True)
            # Propagate the error so callers know alert fetching failed
            raise RuntimeError(f"Failed to fetch ZAP alerts: {e}") from e

    def _parse_zap_alert(self, alert: Dict, scan_id: str) -> Optional[VulnerabilityFinding]:
        """Parse a ZAP alert into VulnerabilityFinding"""
        try:
            risk = int(alert.get('risk', 0))
            confidence = int(alert.get('confidence', 0))

            severity = self.ZAP_RISK_MAP.get(risk, VulnSeverity.INFO)
            confidence_str = self.ZAP_CONFIDENCE_MAP.get(confidence, 'Unknown')

            # Extract CWE ID if present
            cwe_ids = []
            cwe_id = alert.get('cweid', '')
            if cwe_id and cwe_id != '-1':
                cwe_ids.append(f"CWE-{cwe_id}")

            # Extract WASC ID
            wasc_id = alert.get('wascid', '')

            # Build references
            references = []
            if alert.get('reference'):
                refs = alert['reference'].split('\n')
                references.extend([r.strip() for r in refs if r.strip()])

            # Parse URL for host/port
            url = alert.get('url', '')
            host = url
            port = None
            try:
                parsed = urllib.parse.urlparse(url)
                host = parsed.netloc
                if parsed.port:
                    port = parsed.port
            except Exception:
                pass

            finding = VulnerabilityFinding(
                finding_id=f"{scan_id}-zap-{alert.get('alertRef', 'unknown')}-{len(self.scan_results.get(scan_id, []))+1:04d}",
                scanner='zap',
                host=host,
                port=port,
                severity=severity,
                title=alert.get('name', 'Unknown ZAP Alert'),
                description=alert.get('description', ''),
                cwe_ids=cwe_ids,
                evidence=alert.get('evidence', '')[:1000],
                remediation=alert.get('solution', ''),
                references=references[:10],
                tags=['zap', 'web', f'confidence-{confidence_str.lower()}'],
                matched_at=url,
                raw_output=json.dumps(alert)[:2000],
                details={
                    'method': alert.get('method', ''),
                    'parameter': alert.get('param', ''),
                    'attack': alert.get('attack', ''),
                    'wasc_id': wasc_id,
                    'confidence': confidence_str,
                    'plugin_id': alert.get('pluginId', ''),
                    'alert_ref': alert.get('alertRef', ''),
                }
            )

            return finding

        except Exception as e:
            logger.debug(f"Error parsing ZAP alert: {e}")
            return None

    def zap_set_authentication(self, context_name: str, auth_type: str, auth_params: Dict) -> tuple:
        """
        Configure authentication for ZAP context.

        auth_type: 'form', 'http_basic', 'json'
        auth_params for 'form':
            - login_url: URL of login form
            - login_request_data: POST data (e.g., "username={%username%}&password={%password%}")
            - username_field: Name of username parameter
            - password_field: Name of password parameter
            - username: Actual username
            - password: Actual password

        Returns: (success: bool, error_message: str or None)
        """
        # Check if ZAP is running first
        if not self._is_zap_running():
            return (False, "ZAP daemon is not running. Please start ZAP first.")

        try:
            # First, ensure we have a context - create one if needed
            context_id = None
            try:
                # Try to get existing context
                contexts_resp = self._zap_api_call('JSON/context/view/contextList', {})
                contexts = contexts_resp.get('contextList', [])

                if context_name in contexts:
                    # Get context ID
                    context_resp = self._zap_api_call('JSON/context/view/context', {'contextName': context_name})
                    context_id = context_resp.get('context', {}).get('id', '1')
                else:
                    # Create new context
                    new_ctx_resp = self._zap_api_call('JSON/context/action/newContext', {'contextName': context_name})
                    context_id = new_ctx_resp.get('contextId', '1')
                    logger.info(f"Created new ZAP context: {context_name} (ID: {context_id})")
            except Exception as ctx_err:
                logger.warning(f"Could not manage context, using default: {ctx_err}")
                context_id = '1'

            if auth_type == 'form':
                # Validate required parameters
                login_url = auth_params.get('login_url', '').strip()
                username = auth_params.get('username', '').strip()
                password = auth_params.get('password', '')

                if not login_url:
                    return (False, "Login URL is required for form-based authentication")
                if not username:
                    return (False, "Username is required for form-based authentication")
                if not password:
                    return (False, "Password is required for form-based authentication")

                # Include the login URL's host in the context
                try:
                    parsed_url = urllib.parse.urlparse(login_url)
                    include_regex = f"{parsed_url.scheme}://{parsed_url.netloc}.*"
                    self._zap_api_call('JSON/context/action/includeInContext', {
                        'contextName': context_name,
                        'regex': include_regex
                    })
                    logger.info(f"Added {include_regex} to context {context_name}")
                except Exception as e:
                    logger.warning(f"Could not add URL to context: {e}")

                # Build login request data if not provided
                login_request_data = auth_params.get('login_request_data', '').strip()
                if not login_request_data:
                    username_field = auth_params.get('username_field', 'username')
                    password_field = auth_params.get('password_field', 'password')
                    login_request_data = f"{username_field}={{%username%}}&{password_field}={{%password%}}"

                # Set form-based authentication
                try:
                    self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                        'contextId': context_id,
                        'authMethodName': 'formBasedAuthentication',
                        'authMethodConfigParams': urllib.parse.urlencode({
                            'loginUrl': login_url,
                            'loginRequestData': login_request_data,
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set authentication method: {str(e)}")

                # Create and configure user
                try:
                    user_resp = self._zap_api_call('JSON/users/action/newUser', {
                        'contextId': context_id,
                        'name': 'test_user'
                    })
                    user_id = user_resp.get('userId')
                except Exception as e:
                    return (False, f"Failed to create user in ZAP: {str(e)}")

                if not user_id:
                    return (False, "Failed to create user - no user ID returned from ZAP")

                # Set user credentials
                try:
                    self._zap_api_call('JSON/users/action/setAuthenticationCredentials', {
                        'contextId': context_id,
                        'userId': user_id,
                        'authCredentialsConfigParams': urllib.parse.urlencode({
                            'username': username,
                            'password': password,
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set user credentials: {str(e)}")

                # Enable user
                try:
                    self._zap_api_call('JSON/users/action/setUserEnabled', {
                        'contextId': context_id,
                        'userId': user_id,
                        'enabled': 'true'
                    })
                except Exception as e:
                    return (False, f"Failed to enable user: {str(e)}")

                logger.info(f"ZAP form authentication configured for context {context_name}")
                return (True, None)

            elif auth_type == 'http_basic':
                # Validate required parameters
                hostname = auth_params.get('hostname', '').strip()
                if not hostname:
                    return (False, "Hostname is required for HTTP Basic authentication")

                # HTTP Basic authentication
                try:
                    self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                        'contextId': context_id,
                        'authMethodName': 'httpAuthentication',
                        'authMethodConfigParams': urllib.parse.urlencode({
                            'hostname': hostname,
                            'realm': auth_params.get('realm', ''),
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set HTTP Basic authentication: {str(e)}")

                logger.info("ZAP HTTP Basic authentication configured")
                return (True, None)

            elif auth_type == 'oauth2_bba':
                # OAuth2 / Microsoft Login using Browser-Based Authentication (BBA)
                # ZAP's BBA mode drives a real browser to handle complex OAuth flows
                # including Microsoft Online login sequences with multiple screens

                login_url = auth_params.get('login_url', '').strip()
                username = auth_params.get('username', '').strip()
                password = auth_params.get('password', '')
                wait_for_url = auth_params.get('wait_for_url', '').strip()  # URL pattern indicating successful login
                login_page_wait = auth_params.get('login_page_wait', 5)  # Seconds to wait for login page

                if not login_url:
                    return (False, "Login URL is required for OAuth2/BBA authentication")
                if not username:
                    return (False, "Username is required for OAuth2/BBA authentication")
                if not password:
                    return (False, "Password is required for OAuth2/BBA authentication")

                # Include the target URL's host in the context
                try:
                    parsed_url = urllib.parse.urlparse(login_url)
                    include_regex = f"{parsed_url.scheme}://{parsed_url.netloc}.*"
                    self._zap_api_call('JSON/context/action/includeInContext', {
                        'contextName': context_name,
                        'regex': include_regex
                    })
                    logger.info(f"Added {include_regex} to context {context_name}")

                    # Also include Microsoft login domains if this appears to be MS OAuth
                    if 'microsoft' in login_url.lower() or 'login.live' in login_url.lower() or 'microsoftonline' in login_url.lower():
                        ms_domains = [
                            'https://login.microsoftonline.com/.*',
                            'https://login.live.com/.*',
                            'https://login.microsoft.com/.*'
                        ]
                        for ms_domain in ms_domains:
                            try:
                                self._zap_api_call('JSON/context/action/includeInContext', {
                                    'contextName': context_name,
                                    'regex': ms_domain
                                })
                            except:
                                pass  # Best effort to add MS domains
                except Exception as e:
                    logger.warning(f"Could not add URL to context: {e}")

                # Configure Browser-Based Authentication
                try:
                    # Set authentication method to browser-based
                    bba_config = {
                        'loginPageUrl': login_url,
                        'loginPageWait': str(login_page_wait),
                    }

                    # Add wait_for_url if specified (helps ZAP know when login is complete)
                    if wait_for_url:
                        bba_config['waitForUrl'] = wait_for_url

                    self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                        'contextId': context_id,
                        'authMethodName': 'browserBasedAuthentication',
                        'authMethodConfigParams': urllib.parse.urlencode(bba_config)
                    })
                    logger.info(f"Set browser-based authentication for context {context_id}")
                except Exception as e:
                    return (False, f"Failed to set BBA method: {str(e)}")

                # Create user for BBA
                try:
                    user_resp = self._zap_api_call('JSON/users/action/newUser', {
                        'contextId': context_id,
                        'name': 'oauth_user'
                    })
                    user_id = user_resp.get('userId')
                except Exception as e:
                    return (False, f"Failed to create user for BBA: {str(e)}")

                if not user_id:
                    return (False, "Failed to create user - no user ID returned from ZAP")

                # Set user credentials for BBA
                try:
                    self._zap_api_call('JSON/users/action/setAuthenticationCredentials', {
                        'contextId': context_id,
                        'userId': user_id,
                        'authCredentialsConfigParams': urllib.parse.urlencode({
                            'username': username,
                            'password': password,
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set BBA credentials: {str(e)}")

                # Enable user
                try:
                    self._zap_api_call('JSON/users/action/setUserEnabled', {
                        'contextId': context_id,
                        'userId': user_id,
                        'enabled': 'true'
                    })
                except Exception as e:
                    return (False, f"Failed to enable BBA user: {str(e)}")

                logger.info(f"ZAP OAuth2/BBA authentication configured for context {context_name}")
                return (True, None)

            elif auth_type == 'script_auth':
                # Script-Based Authentication for custom/complex flows
                # This allows users to provide a custom authentication script

                script_name = auth_params.get('script_name', '').strip()
                login_url = auth_params.get('login_url', '').strip()
                username = auth_params.get('username', '').strip()
                password = auth_params.get('password', '')

                if not login_url:
                    return (False, "Login URL is required for script-based authentication")
                if not username:
                    return (False, "Username is required for script-based authentication")
                if not password:
                    return (False, "Password is required for script-based authentication")

                # Include the target URL's host in the context
                try:
                    parsed_url = urllib.parse.urlparse(login_url)
                    include_regex = f"{parsed_url.scheme}://{parsed_url.netloc}.*"
                    self._zap_api_call('JSON/context/action/includeInContext', {
                        'contextName': context_name,
                        'regex': include_regex
                    })
                except Exception as e:
                    logger.warning(f"Could not add URL to context: {e}")

                # If a script name is provided, use script-based auth
                # Otherwise fall back to form-based as a starting point
                if script_name:
                    try:
                        self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                            'contextId': context_id,
                            'authMethodName': 'scriptBasedAuthentication',
                            'authMethodConfigParams': urllib.parse.urlencode({
                                'scriptName': script_name,
                                'loginUrl': login_url,
                            })
                        })
                    except Exception as e:
                        return (False, f"Failed to set script-based authentication: {str(e)}")
                else:
                    # Use Client-Script Authentication (CSA) which is similar to BBA
                    # but allows more control via JavaScript
                    try:
                        self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                            'contextId': context_id,
                            'authMethodName': 'browserBasedAuthentication',
                            'authMethodConfigParams': urllib.parse.urlencode({
                                'loginPageUrl': login_url,
                                'loginPageWait': '10',  # Longer wait for complex flows
                            })
                        })
                    except Exception as e:
                        return (False, f"Failed to set CSA method: {str(e)}")

                # Create and configure user
                try:
                    user_resp = self._zap_api_call('JSON/users/action/newUser', {
                        'contextId': context_id,
                        'name': 'script_user'
                    })
                    user_id = user_resp.get('userId')
                except Exception as e:
                    return (False, f"Failed to create user for script auth: {str(e)}")

                if not user_id:
                    return (False, "Failed to create user - no user ID returned")

                # Set credentials
                try:
                    self._zap_api_call('JSON/users/action/setAuthenticationCredentials', {
                        'contextId': context_id,
                        'userId': user_id,
                        'authCredentialsConfigParams': urllib.parse.urlencode({
                            'username': username,
                            'password': password,
                        })
                    })
                except Exception as e:
                    return (False, f"Failed to set script auth credentials: {str(e)}")

                # Enable user
                try:
                    self._zap_api_call('JSON/users/action/setUserEnabled', {
                        'contextId': context_id,
                        'userId': user_id,
                        'enabled': 'true'
                    })
                except Exception as e:
                    return (False, f"Failed to enable script auth user: {str(e)}")

                logger.info(f"ZAP script-based authentication configured for context {context_name}")
                return (True, None)

            elif auth_type == 'bearer_token':
                # Bearer token auth - use ZAP's Replacer to add Authorization header
                bearer_token = auth_params.get('bearer_token', '').strip()
                if not bearer_token:
                    return (False, "Bearer token is required")

                try:
                    # Remove any existing Authorization replacer rule
                    try:
                        self._zap_api_call('JSON/replacer/action/removeRule', {
                            'description': 'Auth-BearerToken'
                        })
                    except Exception:
                        pass  # Rule may not exist yet

                    self._zap_api_call('JSON/replacer/action/addRule', {
                        'description': 'Auth-BearerToken',
                        'enabled': 'true',
                        'matchType': 'REQ_HEADER',
                        'matchRegex': 'false',
                        'matchString': 'Authorization',
                        'replacement': f'Bearer {bearer_token}',
                        'initiators': ''
                    })
                    logger.info("ZAP bearer token authentication configured via Replacer")
                    return (True, None)
                except Exception as e:
                    return (False, f"Failed to set bearer token: {str(e)}")

            elif auth_type == 'api_key':
                # API Key auth - use ZAP's Replacer to add custom header
                api_key = auth_params.get('api_key', '').strip()
                header_name = auth_params.get('api_key_header', 'X-API-Key').strip()
                if not api_key:
                    return (False, "API key is required")

                try:
                    try:
                        self._zap_api_call('JSON/replacer/action/removeRule', {
                            'description': 'Auth-APIKey'
                        })
                    except Exception:
                        pass

                    self._zap_api_call('JSON/replacer/action/addRule', {
                        'description': 'Auth-APIKey',
                        'enabled': 'true',
                        'matchType': 'REQ_HEADER',
                        'matchRegex': 'false',
                        'matchString': header_name,
                        'replacement': api_key,
                        'initiators': ''
                    })
                    logger.info(f"ZAP API key authentication configured via Replacer ({header_name})")
                    return (True, None)
                except Exception as e:
                    return (False, f"Failed to set API key: {str(e)}")

            elif auth_type == 'cookie':
                # Cookie auth - use ZAP's Replacer to add Cookie header
                cookie_value = auth_params.get('cookie_value', '').strip()
                if not cookie_value:
                    return (False, "Cookie value is required")

                try:
                    try:
                        self._zap_api_call('JSON/replacer/action/removeRule', {
                            'description': 'Auth-Cookie'
                        })
                    except Exception:
                        pass

                    self._zap_api_call('JSON/replacer/action/addRule', {
                        'description': 'Auth-Cookie',
                        'enabled': 'true',
                        'matchType': 'REQ_HEADER',
                        'matchRegex': 'false',
                        'matchString': 'Cookie',
                        'replacement': cookie_value,
                        'initiators': ''
                    })
                    logger.info("ZAP cookie authentication configured via Replacer")
                    return (True, None)
                except Exception as e:
                    return (False, f"Failed to set cookie auth: {str(e)}")

            else:
                return (False, f"Unsupported authentication type: '{auth_type}'. Supported types: 'form', 'http_basic', 'oauth2_bba', 'script_auth', 'bearer_token', 'api_key', 'cookie'")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error configuring ZAP authentication: {error_msg}")
            return (False, f"Unexpected error: {error_msg}")

    def zap_import_openapi(self, spec_url: str, target_url: str = None) -> bool:
        """Import OpenAPI/Swagger specification for API scanning"""
        try:
            params = {'url': spec_url}
            if target_url:
                params['hostOverride'] = target_url

            self._zap_api_call('JSON/openapi/action/importUrl', params)
            logger.info(f"Imported OpenAPI spec from {spec_url}")
            return True

        except Exception as e:
            logger.error(f"Error importing OpenAPI spec: {e}")
            return False

    def zap_diagnose_target(self, target: str) -> Dict[str, Any]:
        """
        Diagnose potential issues with a target URL before scanning.

        Returns a dict with:
        - valid: bool - whether target appears valid for scanning
        - errors: list - list of issues found
        - warnings: list - list of potential issues
        - recommendations: list - suggestions for fixing issues
        """
        result = {
            'valid': True,
            'target': target,
            'errors': [],
            'warnings': [],
            'recommendations': []
        }

        # Check URL format
        if not target:
            result['valid'] = False
            result['errors'].append("Target URL is empty")
            result['recommendations'].append("Provide a valid URL starting with http:// or https://")
            return result

        if not target.startswith(('http://', 'https://')):
            result['valid'] = False
            result['errors'].append(f"Invalid URL scheme: {target[:30]}")
            result['recommendations'].append("URL must start with http:// or https://")
            return result

        # Parse URL
        try:
            parsed = urllib.parse.urlparse(target)
            if not parsed.netloc:
                result['valid'] = False
                result['errors'].append("URL has no host/domain")
                result['recommendations'].append("Check URL format - should be http://hostname:port/path")
                return result

            result['host'] = parsed.netloc
            result['scheme'] = parsed.scheme

        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"URL parsing error: {e}")
            return result

        # Test DNS resolution
        host = parsed.netloc.split(':')[0]
        try:
            ip_addr = socket.gethostbyname(host)
            result['resolved_ip'] = ip_addr
        except socket.gaierror as e:
            result['valid'] = False
            result['errors'].append(f"Cannot resolve hostname '{host}': {e}")
            result['recommendations'].append("Check that the hostname is correct and DNS is working")
            return result

        # Test TCP connectivity
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn_result = sock.connect_ex((host, port))
            sock.close()

            if conn_result != 0:
                result['valid'] = False
                result['errors'].append(f"Cannot connect to {host}:{port} (error code: {conn_result})")
                result['recommendations'].append(
                    f"Target may be down, firewalled, or not listening on port {port}. "
                    "Check if the target is accessible from this machine."
                )
                return result

            result['port'] = port
            result['connectivity'] = 'ok'

        except socket.timeout:
            result['valid'] = False
            result['errors'].append(f"Connection to {host}:{port} timed out")
            result['recommendations'].append("Target may be slow, overloaded, or blocking connections")
            return result
        except Exception as e:
            result['warnings'].append(f"Connectivity check error (non-fatal): {e}")

        # Test HTTP accessibility (quick check)
        try:
            req = urllib.request.Request(target, method='HEAD')
            req.add_header('User-Agent', 'Mozilla/5.0 (compatible; OWASP ZAP; Security Scanner)')
            with urllib.request.urlopen(req, timeout=10) as response:
                result['http_status'] = response.status
                if response.status >= 400:
                    result['warnings'].append(f"Target returned HTTP {response.status}")
                    if response.status == 401:
                        result['recommendations'].append("Target requires authentication - configure ZAP auth if needed")
                    elif response.status == 403:
                        result['recommendations'].append("Target is returning 403 Forbidden - may block scanners")
                    elif response.status == 404:
                        result['warnings'].append("Target URL returned 404 - check if path is correct")
        except urllib.error.HTTPError as e:
            result['http_status'] = e.code
            if e.code == 401:
                result['warnings'].append("Target requires authentication (401)")
                result['recommendations'].append("Configure ZAP authentication if scanning authenticated areas")
            elif e.code == 403:
                result['warnings'].append("Target returned 403 Forbidden - may block scanning")
            elif e.code == 404:
                result['warnings'].append("Target path not found (404) - check URL path")
            elif e.code >= 500:
                result['warnings'].append(f"Target is returning server errors ({e.code})")
        except urllib.error.URLError as e:
            if 'ssl' in str(e.reason).lower() or 'certificate' in str(e.reason).lower():
                result['warnings'].append(f"SSL/TLS issue: {e.reason}")
                result['recommendations'].append("Target may have certificate issues - ZAP should still work but may need config")
            else:
                result['warnings'].append(f"HTTP request failed: {e.reason}")
        except Exception as e:
            result['warnings'].append(f"HTTP check error: {e}")

        # Check ZAP state if running
        if self._is_zap_running():
            try:
                auth_status = self.zap_get_auth_status()
                if auth_status.get('has_auth'):
                    result['zap_auth_configured'] = True
                    result['warnings'].append(
                        f"ZAP has authentication configured ({auth_status.get('auth_type')}). "
                        "If target doesn't need auth, this may cause issues."
                    )
                    result['recommendations'].append(
                        "If scanning without auth, clear ZAP auth settings first using 'Clear Auth'"
                    )
            except Exception:
                pass

        return result

    def zap_clear_session(self) -> bool:
        """Clear ZAP session data"""
        try:
            self._zap_api_call('JSON/core/action/newSession', {'overwrite': 'true'})
            logger.info("ZAP session cleared")
            return True
        except Exception as e:
            logger.error(f"Error clearing ZAP session: {e}")
            return False

    def zap_get_auth_status(self) -> Dict:
        """Get current ZAP authentication configuration status"""
        auth_status = {
            'has_auth': False,
            'contexts': [],
            'auth_type': None,
            'details': None
        }

        if not self._is_zap_running():
            auth_status['error'] = 'ZAP is not running'
            return auth_status

        try:
            # Get list of contexts
            contexts_resp = self._zap_api_call('JSON/context/view/contextList', {})
            context_list = contexts_resp.get('contextList', [])

            if isinstance(context_list, str):
                # Sometimes ZAP returns a comma-separated string
                context_list = [c.strip() for c in context_list.split(',') if c.strip()]

            for context_name in context_list:
                if not context_name:
                    continue

                try:
                    # Get context details
                    ctx_resp = self._zap_api_call('JSON/context/view/context', {'contextName': context_name})
                    context_info = ctx_resp.get('context', {})
                    context_id = context_info.get('id', '1')

                    # Check authentication method for this context
                    auth_resp = self._zap_api_call('JSON/authentication/view/getAuthenticationMethod', {'contextId': context_id})
                    auth_method = auth_resp.get('method', {})
                    method_name = auth_method.get('methodName', 'none')

                    context_auth = {
                        'name': context_name,
                        'id': context_id,
                        'auth_method': method_name,
                        'in_scope': context_info.get('inScope', [])
                    }

                    # Check if there are users configured
                    try:
                        users_resp = self._zap_api_call('JSON/users/view/usersList', {'contextId': context_id})
                        users = users_resp.get('usersList', [])
                        context_auth['users_configured'] = len(users) > 0
                        context_auth['user_count'] = len(users)
                    except:
                        context_auth['users_configured'] = False
                        context_auth['user_count'] = 0

                    auth_status['contexts'].append(context_auth)

                    # If this context has authentication configured, mark it
                    # ZAP uses various names for "no auth": none, manual, manualAuthentication, etc.
                    no_auth_methods = ['none', 'manual', 'manualauthentication', '']
                    if method_name and method_name.lower() not in no_auth_methods:
                        auth_status['has_auth'] = True
                        auth_status['auth_type'] = method_name
                        auth_status['details'] = f"Context '{context_name}' has {method_name} authentication"

                except Exception as ctx_err:
                    logger.debug(f"Error checking context {context_name}: {ctx_err}")
                    continue

            # Also check for Replacer-based auth (bearer_token, api_key, cookie)
            if not auth_status['has_auth']:
                try:
                    rules_resp = self._zap_api_call('JSON/replacer/view/rules', {})
                    rules = rules_resp.get('rules', [])
                    auth_rules = [r for r in rules if isinstance(r, dict) and
                                  r.get('description', '').startswith('Auth-') and
                                  r.get('enabled') == 'true']
                    if auth_rules:
                        rule_desc = auth_rules[0].get('description', '')
                        auth_type_map = {
                            'Auth-BearerToken': 'bearer_token',
                            'Auth-APIKey': 'api_key',
                            'Auth-Cookie': 'cookie'
                        }
                        auth_status['has_auth'] = True
                        auth_status['auth_type'] = auth_type_map.get(rule_desc, 'header_replacement')
                        auth_status['details'] = f"Header-based auth via Replacer: {rule_desc}"
                except Exception:
                    pass  # Replacer add-on may not be available

            if not auth_status['has_auth']:
                auth_status['details'] = 'No authentication configured'

        except Exception as e:
            logger.error(f"Error getting ZAP auth status: {e}")
            auth_status['error'] = str(e)

        return auth_status

    def zap_clear_auth(self) -> tuple:
        """Clear all ZAP authentication configurations and contexts by starting a new session"""
        if not self._is_zap_running():
            return (False, "ZAP is not running")

        try:
            # The most reliable way to clear all auth is to start a new session
            # This wipes everything: contexts, auth, users, scan history
            logger.info("Clearing ZAP session to reset all authentication...")

            try:
                self._zap_api_call('JSON/core/action/newSession', {'overwrite': 'true'})
                logger.info("ZAP session cleared - all authentication reset")
                return (True, "ZAP session cleared. All authentication configurations have been reset.")
            except Exception as session_err:
                logger.warning(f"Could not create new session: {session_err}, trying manual cleanup...")

            # Fallback: manually remove contexts and reset auth
            cleared_contexts = []
            errors = []

            # Get list of contexts
            contexts_resp = self._zap_api_call('JSON/context/view/contextList', {})
            context_list = contexts_resp.get('contextList', [])

            if isinstance(context_list, str):
                context_list = [c.strip() for c in context_list.split(',') if c.strip()]

            for context_name in context_list:
                if not context_name:
                    continue

                try:
                    # Get context ID first
                    ctx_resp = self._zap_api_call('JSON/context/view/context', {'contextName': context_name})
                    context_id = ctx_resp.get('context', {}).get('id', '1')

                    # Remove all users from this context
                    try:
                        users_resp = self._zap_api_call('JSON/users/view/usersList', {'contextId': context_id})
                        users = users_resp.get('usersList', [])
                        for user in users:
                            user_id = user.get('id') if isinstance(user, dict) else user
                            if user_id:
                                self._zap_api_call('JSON/users/action/removeUser', {
                                    'contextId': context_id,
                                    'userId': str(user_id)
                                })
                    except Exception as user_err:
                        logger.debug(f"Could not remove users from {context_name}: {user_err}")

                    # Reset authentication method to manual (no auth)
                    try:
                        self._zap_api_call('JSON/authentication/action/setAuthenticationMethod', {
                            'contextId': context_id,
                            'authMethodName': 'manualAuthentication'
                        })
                        logger.info(f"Reset auth on context {context_name}")
                    except Exception as auth_err:
                        logger.debug(f"Could not reset auth on {context_name}: {auth_err}")

                    # Remove non-default contexts entirely
                    if context_name != 'Default Context':
                        self._zap_api_call('JSON/context/action/removeContext', {'contextName': context_name})
                        cleared_contexts.append(context_name)
                        logger.info(f"Removed ZAP context: {context_name}")

                except Exception as e:
                    errors.append(f"Failed to clear {context_name}: {e}")

            # Also clear any Replacer-based auth rules (bearer, api_key, cookie)
            for rule_name in ['Auth-BearerToken', 'Auth-APIKey', 'Auth-Cookie']:
                try:
                    self._zap_api_call('JSON/replacer/action/removeRule', {
                        'description': rule_name
                    })
                except Exception:
                    pass  # Rule may not exist

            if cleared_contexts:
                msg = f"Cleared {len(cleared_contexts)} context(s) and reset authentication: {', '.join(cleared_contexts)}"
            else:
                msg = "Reset authentication on all contexts"

            if errors:
                msg += f". Some errors: {'; '.join(errors[:3])}"

            logger.info(msg)
            return (True, msg)

        except Exception as e:
            error_msg = f"Error clearing ZAP authentication: {e}"
            logger.error(error_msg)
            return (False, error_msg)

    # =========================================================================
    # End ZAP Integration
    # =========================================================================

    def _run_full_scan(self, scan_id: str, target: str, options: Dict):
        """Run all available scanners in parallel"""
        progress = self.active_scans[scan_id]
        scanners = self.get_available_scanners()
        is_web_target = target.startswith('http') or options.get('port', 80) in [80, 443, 8080, 8443]

        # Create sub-scans for each available scanner
        sub_futures = []

        with ThreadPoolExecutor(max_workers=4) as executor:
            if scanners.get('nuclei'):
                sub_futures.append(
                    executor.submit(self._run_nuclei_scan, scan_id, target, options)
                )
            if scanners.get('nikto') and is_web_target:
                sub_futures.append(
                    executor.submit(self._run_nikto_scan, scan_id, target, options)
                )
            if scanners.get('nmap_vuln'):
                sub_futures.append(
                    executor.submit(self._run_nmap_vuln_scan, scan_id, target, options)
                )
            # Include ZAP for web targets if available and enabled
            if scanners.get('zap') and is_web_target and options.get('include_zap', True):
                sub_futures.append(
                    executor.submit(self._run_zap_full_scan, scan_id, target, options)
                )

            # Wait for all to complete
            for future in as_completed(sub_futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Sub-scan error: {e}")
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get status of a scan (checks memory first, then database)"""
        with self._lock:
            if scan_id in self.active_scans:
                progress = self.active_scans[scan_id]
                progress.findings_count = len(self.scan_results.get(scan_id, []))
                return progress.to_dict()

        # Check database for historical scans
        if self._db:
            try:
                scan_data = self._db.get_scan_job(scan_id)
                if scan_data:
                    return {
                        'scan_id': scan_data.get('scan_id'),
                        'scan_type': scan_data.get('scan_type'),
                        'target': scan_data.get('target'),
                        'status': scan_data.get('status'),
                        'progress_percent': scan_data.get('progress_percent', 0),
                        'findings_count': scan_data.get('findings_count', 0),
                        'current_check': scan_data.get('current_check', ''),
                        'started_at': scan_data.get('started_at'),
                        'completed_at': scan_data.get('completed_at'),
                        'error_message': scan_data.get('error_message', ''),
                    }
            except Exception as e:
                logger.debug(f"Error getting scan from DB: {e}")

        return None

    def get_active_scans_list(self) -> List[Dict]:
        """Get list of all active/recent scans with their status"""
        scans = []

        with self._lock:
            for scan_id, progress in self.active_scans.items():
                progress.findings_count = len(self.scan_results.get(scan_id, []))
                scans.append(progress.to_dict())

        # Also include recent scans from database
        if self._db:
            try:
                db_scans = self._db.get_scan_jobs(limit=20)
                db_scan_ids = {s.get('scan_id') for s in scans}

                for scan_data in db_scans:
                    if scan_data.get('scan_id') not in db_scan_ids:
                        scans.append({
                            'scan_id': scan_data.get('scan_id'),
                            'scan_type': scan_data.get('scan_type'),
                            'target': scan_data.get('target'),
                            'status': scan_data.get('status'),
                            'progress_percent': scan_data.get('progress_percent', 0),
                            'findings_count': scan_data.get('findings_count', 0),
                            'current_check': scan_data.get('current_check', ''),
                            'started_at': scan_data.get('started_at'),
                            'completed_at': scan_data.get('completed_at'),
                            'error_message': scan_data.get('error_message', ''),
                        })
            except Exception as e:
                logger.debug(f"Error getting scans from DB: {e}")

        # Sort by start time, most recent first
        scans.sort(key=lambda x: x.get('started_at') or '', reverse=True)
        return scans[:20]  # Limit to 20 most recent

    def get_scan_results(self, scan_id: str) -> List[Dict]:
        """Get results for a scan (checks memory first, then database)"""
        with self._lock:
            if scan_id in self.scan_results:
                findings = self.scan_results[scan_id]
                return [f.to_dict() for f in findings]

        # Check database for historical results
        if self._db:
            try:
                findings_data = self._db.get_scan_findings(scan_id)
                return findings_data
            except Exception as e:
                logger.debug(f"Error getting findings from DB: {e}")

        return []

    def get_all_findings(self, severity: str = None, limit: int = 100) -> List[Dict]:
        """Get all findings across all scans (combines memory and database)"""
        all_findings = []

        with self._lock:
            for findings in self.scan_results.values():
                all_findings.extend(findings)

        # Also get from database
        if self._db:
            try:
                db_findings = self._db.get_all_findings(severity=severity, limit=limit)
                # Merge with memory findings (avoid duplicates by finding_id)
                memory_ids = {f.finding_id for f in all_findings}
                for db_finding in db_findings:
                    if db_finding.get('finding_id') not in memory_ids:
                        all_findings.append(self._dict_to_finding(db_finding))
            except Exception as e:
                logger.debug(f"Error getting findings from DB: {e}")

        # Filter by severity if specified
        if severity:
            try:
                sev = VulnSeverity(severity.lower())
                all_findings = [f for f in all_findings if f.severity == sev]
            except ValueError:
                pass

        # Sort by severity (critical first) then by timestamp
        severity_order = {
            VulnSeverity.CRITICAL: 0,
            VulnSeverity.HIGH: 1,
            VulnSeverity.MEDIUM: 2,
            VulnSeverity.LOW: 3,
            VulnSeverity.INFO: 4
        }
        all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.timestamp), reverse=True)

        return [f.to_dict() for f in all_findings[:limit]]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get overall vulnerability summary (combines memory and database)"""
        severity_counts = {s.value: 0 for s in VulnSeverity}
        scanner_counts = {}
        total_findings = 0

        with self._lock:
            for findings in self.scan_results.values():
                for f in findings:
                    total_findings += 1
                    severity_counts[f.severity.value] += 1
                    scanner_counts[f.scanner] = scanner_counts.get(f.scanner, 0) + 1

            active_scans = sum(1 for p in self.active_scans.values() if p.status == 'running')

        # Also get summary from database
        if self._db:
            try:
                db_summary = self._db.get_findings_summary()
                # Merge database counts (database may have findings not in memory)
                db_total = db_summary.get('total', 0)
                if db_total > total_findings:
                    total_findings = db_total
                    for sev, count in db_summary.get('by_severity', {}).items():
                        severity_counts[sev] = max(severity_counts.get(sev, 0), count)
                    for scanner, count in db_summary.get('by_scanner', {}).items():
                        scanner_counts[scanner] = max(scanner_counts.get(scanner, 0), count)
            except Exception as e:
                logger.debug(f"Error getting summary from DB: {e}")

        return {
            'total_findings': total_findings,
            'severity_counts': severity_counts,
            'scanner_counts': scanner_counts,
            'total_scans': len(self.active_scans),
            'active_scans': active_scans,
            'available_scanners': self.get_available_scanners()
        }

    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        with self._lock:
            if scan_id in self.active_scans:
                progress = self.active_scans[scan_id]
                if progress.status == 'running':
                    progress.status = 'cancelled'
                    progress.error_message = 'Cancelled by user'
                    progress.completed_at = datetime.now()
                    # Save to database
                    self._save_scan_to_db(scan_id, progress)
                    return True
        return False

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its findings from memory and database"""
        deleted = False

        with self._lock:
            # Remove from active scans
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
                deleted = True

            # Remove findings from memory
            if scan_id in self.scan_results:
                del self.scan_results[scan_id]
                deleted = True

        # Remove from database
        if self._db:
            try:
                with self._db.get_connection() as conn:
                    cursor = conn.cursor()
                    # Delete findings for this scan
                    cursor.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))
                    # Delete scan job record
                    cursor.execute("DELETE FROM scan_jobs WHERE scan_id = ?", (scan_id,))
                    conn.commit()
                deleted = True
                logger.info(f"Deleted scan {scan_id} from database")
            except Exception as e:
                logger.error(f"Error deleting scan from database: {e}")

        return deleted

    def delete_all_scans(self) -> int:
        """Delete all scans and findings"""
        count = 0

        with self._lock:
            count = len(self.active_scans) + len(self.scan_results)
            self.active_scans.clear()
            self.scan_results.clear()

        # Clear database
        if self._db:
            try:
                with self._db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM scan_findings")
                    cursor.execute("DELETE FROM scan_jobs")
                    conn.commit()
                logger.info("Deleted all scans from database")
            except Exception as e:
                logger.error(f"Error clearing scans from database: {e}")

        return count

    def generate_zap_report(self, report_format: str = 'html') -> Optional[bytes]:
        """Generate a ZAP scan report"""
        if not self._is_zap_running():
            logger.error("ZAP is not running, cannot generate report")
            return None

        try:
            # ZAP report formats: html, xml, json, md
            format_endpoints = {
                'html': 'JSON/reports/action/generate',
                'xml': 'OTHER/core/other/xmlreport',
                'json': 'JSON/core/view/alerts',
                'md': 'JSON/reports/action/generate'
            }

            if report_format == 'json':
                # For JSON, get all alerts
                alerts_resp = self._zap_api_call('JSON/core/view/alerts', {
                    'start': '0',
                    'count': '10000'
                })
                report_data = json.dumps(alerts_resp, indent=2)
                return report_data.encode('utf-8')

            elif report_format == 'xml':
                # XML report
                url = f"{self._zap_base_url}/OTHER/core/other/xmlreport/?apikey={self._zap_api_key}"
                req = urllib.request.Request(url, method='GET')
                with urllib.request.urlopen(req, timeout=60) as response:
                    return response.read()

            elif report_format in ('html', 'md'):
                # Use ZAP's report generation API
                # First check if traditional report is available
                try:
                    template = 'traditional-html' if report_format == 'html' else 'traditional-md'
                    report_resp = self._zap_api_call('JSON/reports/action/generate', {
                        'title': 'Ragnar Security Scan Report',
                        'template': template,
                        'reportDir': '',
                        'reportFileName': f'ragnar_report.{report_format}'
                    })

                    # Get the report file path
                    report_file = report_resp.get('generate')
                    if report_file:
                        # Read the generated report
                        with open(report_file, 'rb') as f:
                            return f.read()
                except Exception as e:
                    logger.warning(f"Modern report generation failed, trying legacy: {e}")

                # Fallback to legacy HTML report
                if report_format == 'html':
                    url = f"{self._zap_base_url}/OTHER/core/other/htmlreport/?apikey={self._zap_api_key}"
                    req = urllib.request.Request(url, method='GET')
                    with urllib.request.urlopen(req, timeout=60) as response:
                        return response.read()

            logger.error(f"Unsupported report format: {report_format}")
            return None

        except Exception as e:
            logger.error(f"Error generating ZAP report: {e}")
            return None

    def cleanup(self):
        """Cleanup resources"""
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None


# Global instance
_advanced_scanner: Optional[AdvancedVulnScanner] = None


def get_advanced_vuln_scanner(shared_data=None) -> AdvancedVulnScanner:
    """Get or create the global AdvancedVulnScanner instance"""
    global _advanced_scanner
    if _advanced_scanner is None:
        _advanced_scanner = AdvancedVulnScanner(shared_data)
    return _advanced_scanner
