"""
Web Recon Engine for Ragnar Server Mode

Pre-flight reconnaissance phase that runs before the existing OWASP ZAP scan:
- TLS_AUDIT          via sslyze (cert validity, weak ciphers, protocol versions)
- DNS_PASSIVE        via crt.sh (cert transparency) + dnspython (resolve + liveness)
- CONTENT_DISCOVERY  via ffuf subprocess (directory/path discovery)

Findings flow into the existing VulnerabilityFinding pipeline so they appear in
the same UI list and DB table as ZAP/nuclei findings. Discovered subdomains and
paths are exposed via handoff-options for operator approval before being fed
into the AdvancedVulnScanner as augmented targets / forced-browse seeds.

Server-mode only (mirrors advanced_vuln_scanner.py).
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from logger import Logger
from advanced_vuln_scanner import VulnerabilityFinding, VulnSeverity

logger = Logger(name="recon_engine", level=logging.INFO)


CRTSH_URL_TEMPLATE = "https://crt.sh/?q=%25.{domain}&output=json"
CRTSH_TIMEOUT = 30
DNS_RESOLVE_TIMEOUT = 5
LIVENESS_TIMEOUT = 5
DEFAULT_RUNNER_TIMEOUT = 300
DEFAULT_ENGINE_TIMEOUT = 600
DEFAULT_WORDLIST_PATH = "/opt/ragnar/wordlists/common.txt"
RESULT_RETENTION_SECONDS = 3600

INTERESTING_PATH_PATTERNS = [
    re.compile(r"^/?\.git/?", re.IGNORECASE),
    re.compile(r"^/?\.env$", re.IGNORECASE),
    re.compile(r"^/?\.htaccess$", re.IGNORECASE),
    re.compile(r"^/?admin/?", re.IGNORECASE),
    re.compile(r"^/?backup/?", re.IGNORECASE),
    re.compile(r"^/?config/?", re.IGNORECASE),
    re.compile(r"^/?\.svn/?", re.IGNORECASE),
    re.compile(r"^/?\.ds_store$", re.IGNORECASE),
    re.compile(r"^/?phpmyadmin/?", re.IGNORECASE),
    re.compile(r"^/?wp-admin/?", re.IGNORECASE),
]

SECRET_TXT_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"gho_[A-Za-z0-9]{36}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]+"),
]


class ReconType(Enum):
    TLS_AUDIT = "tls_audit"
    DNS_PASSIVE = "dns_passive"
    CONTENT_DISCOVERY = "content_discovery"


@dataclass
class ReconResult:
    recon_type: ReconType
    target: str
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    status: str = "pending"
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recon_type": self.recon_type.value,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": self.artifacts,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "error_message": self.error_message,
        }


@dataclass
class ReconScanState:
    scan_id: str
    target: str
    recon_types: List[ReconType]
    status: str = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Dict[ReconType, ReconResult] = field(default_factory=dict)
    handed_off: bool = False
    handoff_zap_scan_id: Optional[str] = None
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "recon_types": [r.value for r in self.recon_types],
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "results": {r.value: result.to_dict() for r, result in self.results.items()},
            "handed_off": self.handed_off,
            "handoff_zap_scan_id": self.handoff_zap_scan_id,
            "error_message": self.error_message,
            "duration_seconds": (
                (self.completed_at or datetime.now()) - self.started_at
            ).total_seconds() if self.started_at else 0,
        }


class ReconEngine:
    """Coordinates the three recon runners and tracks scan state."""

    def __init__(self, shared_data=None):
        self.shared_data = shared_data
        self._lock = threading.Lock()
        self.active_scans: Dict[str, ReconScanState] = {}
        self._scan_history: deque = deque(maxlen=100)
        self._tool_paths: Dict[str, str] = {}
        self._detect_tools()
        threading.Thread(target=self._reaper_loop, daemon=True, name="recon-reaper").start()

    def is_available(self) -> bool:
        # Pre-flight recon is lightweight network work — a TLS handshake, DNS
        # lookups and (optionally) an ffuf content sweep — the same class as
        # the CLI vuln scanners, which run on any board. It used to require
        # server mode (8GB RAM), which was the wrong bar and hid it on smaller
        # boards where the rest of the Adv Scan tab now works. It runs anywhere;
        # content discovery degrades to status=error if ffuf isn't installed.
        return True

    def _detect_tools(self) -> None:
        for tool in ("ffuf",):
            path = shutil.which(tool)
            if path:
                self._tool_paths[tool] = path
                logger.info(f"Found {tool} at {path}")
            else:
                logger.warning(f"{tool} not found in PATH; CONTENT_DISCOVERY will report status=error")

    def start_scan(
        self,
        target: str,
        recon_types: List[ReconType],
        timeout: int = DEFAULT_ENGINE_TIMEOUT,
    ) -> str:
        if not self.is_available():
            raise RuntimeError("Recon engine is not available")
        if not recon_types:
            raise ValueError("recon_types must not be empty")

        scan_id = f"RECON-{uuid.uuid4().hex[:12]}-{int(time.time())}"
        state = ReconScanState(scan_id=scan_id, target=target, recon_types=list(recon_types))
        with self._lock:
            self.active_scans[scan_id] = state

        threading.Thread(
            target=self._run_scan,
            args=(scan_id, target, recon_types, timeout),
            name=f"recon-{scan_id}",
            daemon=True,
        ).start()

        logger.info(f"Started recon scan {scan_id} against {target} ({[r.value for r in recon_types]})")
        return scan_id

    def get_scan_state(self, scan_id: str) -> Optional[ReconScanState]:
        with self._lock:
            return self.active_scans.get(scan_id)

    def cancel_scan(self, scan_id: str) -> bool:
        with self._lock:
            state = self.active_scans.get(scan_id)
            if not state or state.status not in ("pending", "running"):
                return False
            state.status = "cancelled"
            state.completed_at = datetime.now()
        return True

    def get_handoff_options(self, scan_id: str) -> Optional[Dict[str, Any]]:
        state = self.get_scan_state(scan_id)
        if not state:
            return None

        subdomains: List[Dict[str, Any]] = []
        dns_result = state.results.get(ReconType.DNS_PASSIVE)
        if dns_result and dns_result.status in ("ok", "partial"):
            subdomains = dns_result.artifacts.get("subdomains", [])

        paths: List[Dict[str, Any]] = []
        content_result = state.results.get(ReconType.CONTENT_DISCOVERY)
        if content_result and content_result.status in ("ok", "partial"):
            paths = content_result.artifacts.get("hits", [])

        tls_findings: List[Dict[str, Any]] = []
        tls_result = state.results.get(ReconType.TLS_AUDIT)
        if tls_result:
            tls_findings = [f.to_dict() for f in tls_result.findings]

        return {
            "scan_id": scan_id,
            "target": state.target,
            "subdomains": subdomains,
            "paths": paths,
            "tls_findings": tls_findings,
        }

    def _run_scan(
        self,
        scan_id: str,
        target: str,
        recon_types: List[ReconType],
        timeout: int,
    ) -> None:
        state = self.get_scan_state(scan_id)
        if not state:
            return

        state.status = "running"
        state.started_at = datetime.now()

        runner_map = {
            ReconType.TLS_AUDIT: self._run_tls_audit,
            ReconType.DNS_PASSIVE: self._run_dns_passive,
            ReconType.CONTENT_DISCOVERY: self._run_content_discovery,
        }

        try:
            with ThreadPoolExecutor(max_workers=len(recon_types)) as pool:
                futures = {
                    pool.submit(runner_map[rt], target): rt for rt in recon_types if rt in runner_map
                }
                for future in as_completed(futures, timeout=timeout):
                    rt = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        import traceback
                        logger.error(f"Recon runner {rt.value} raised in {scan_id}: {exc}\n{traceback.format_exc()}")
                        result = ReconResult(
                            recon_type=rt,
                            target=target,
                            status="error",
                            error_message=str(exc),
                        )
                    state.results[rt] = result
        except TimeoutError:
            state.error_message = f"engine timeout after {timeout}s"
            logger.warning(f"Recon scan {scan_id} hit engine timeout")
        except Exception as exc:
            import traceback
            state.error_message = str(exc)
            logger.error(f"Recon scan {scan_id} engine failed: {exc}\n{traceback.format_exc()}")

        state.status = "completed"
        state.completed_at = datetime.now()
        self._scan_history.append(scan_id)

    def _run_tls_audit(self, target: str) -> ReconResult:
        result = ReconResult(recon_type=ReconType.TLS_AUDIT, target=target)
        started = time.monotonic()
        try:
            from sslyze import (
                ServerNetworkLocation,
                Scanner,
                ServerScanRequest,
                ScanCommand,
            )
        except ImportError as exc:
            result.status = "error"
            result.error_message = f"sslyze not installed: {exc}"
            result.duration_seconds = time.monotonic() - started
            return result

        host, port = _split_host_port(target, default_port=443)
        try:
            location = ServerNetworkLocation(hostname=host, port=port)
            request = ServerScanRequest(
                server_location=location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.HTTP_HEADERS,
                },
            )
            scanner = Scanner()
            scanner.queue_scans([request])
            scan_results = list(scanner.get_results())
        except Exception as exc:
            result.status = "error"
            result.error_message = f"sslyze scan failed: {exc}"
            result.duration_seconds = time.monotonic() - started
            return result

        if not scan_results:
            result.status = "error"
            result.error_message = "sslyze returned no results"
            result.duration_seconds = time.monotonic() - started
            return result

        scan = scan_results[0]
        findings, artifacts = _parse_sslyze_result(scan, host, port)
        result.findings = findings
        result.artifacts = artifacts
        result.status = "ok"
        result.duration_seconds = time.monotonic() - started
        return result

    def _run_dns_passive(self, target: str) -> ReconResult:
        result = ReconResult(recon_type=ReconType.DNS_PASSIVE, target=target)
        started = time.monotonic()

        host, _ = _split_host_port(target, default_port=443)
        domain = _registrable_domain(host)
        if not domain:
            result.status = "error"
            result.error_message = f"could not derive registrable domain from {host}"
            result.duration_seconds = time.monotonic() - started
            return result

        try:
            names = _query_crtsh(domain)
        except Exception as exc:
            result.status = "error"
            result.error_message = f"crt.sh query failed: {exc}"
            result.duration_seconds = time.monotonic() - started
            return result

        try:
            import dns.resolver
        except ImportError as exc:
            result.status = "error"
            result.error_message = f"dnspython not installed: {exc}"
            result.duration_seconds = time.monotonic() - started
            return result

        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_RESOLVE_TIMEOUT
        resolver.timeout = DNS_RESOLVE_TIMEOUT

        subdomains = []
        seen = set()
        for name in sorted(names):
            if name in seen:
                continue
            seen.add(name)
            entry = {"name": name, "a_records": [], "aaaa_records": [], "alive": False}
            entry["a_records"] = _safe_resolve(resolver, name, "A")
            entry["aaaa_records"] = _safe_resolve(resolver, name, "AAAA")
            if entry["a_records"] or entry["aaaa_records"]:
                entry["alive"] = _probe_liveness(name)
            subdomains.append(entry)

        findings = []
        for name in subdomains:
            for txt in _safe_resolve(resolver, name["name"], "TXT"):
                for pattern in SECRET_TXT_PATTERNS:
                    if pattern.search(txt):
                        findings.append(_make_finding(
                            scanner="recon_dns",
                            host=name["name"],
                            severity=VulnSeverity.MEDIUM,
                            title=f"Possible secret in TXT record for {name['name']}",
                            description="A TXT record contains a string matching a known secret pattern.",
                            evidence=txt[:500],
                            remediation="Rotate the exposed credential and remove it from DNS.",
                        ))
                        break

        result.findings = findings
        result.artifacts = {"registrable_domain": domain, "subdomains": subdomains}
        result.status = "ok"
        result.duration_seconds = time.monotonic() - started
        return result

    def _run_content_discovery(self, target: str) -> ReconResult:
        result = ReconResult(recon_type=ReconType.CONTENT_DISCOVERY, target=target)
        started = time.monotonic()

        ffuf_path = self._tool_paths.get("ffuf")
        if not ffuf_path:
            result.status = "error"
            result.error_message = "ffuf not installed (install via package manager)"
            result.duration_seconds = time.monotonic() - started
            return result

        wordlist = DEFAULT_WORDLIST_PATH
        import os
        if not os.path.isfile(wordlist):
            result.status = "error"
            result.error_message = f"wordlist not found at {wordlist}"
            result.duration_seconds = time.monotonic() - started
            return result

        base_url = _normalize_base_url(target)
        cmd = [
            ffuf_path,
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-of", "json",
            "-o", "-",
            "-mc", "200,204,301,302,307,401,403",
            "-t", "20",
            "-timeout", "10",
            "-s",
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=DEFAULT_RUNNER_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result.status = "error"
            result.error_message = "ffuf timed out"
            result.duration_seconds = time.monotonic() - started
            return result
        except Exception as exc:
            result.status = "error"
            result.error_message = f"ffuf failed: {exc}"
            result.duration_seconds = time.monotonic() - started
            return result

        hits: List[Dict[str, Any]] = []
        if proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                for entry in data.get("results", []):
                    hits.append({
                        "path": entry.get("input", {}).get("FUZZ", ""),
                        "url": entry.get("url", ""),
                        "status": entry.get("status", 0),
                        "length": entry.get("length", 0),
                        "words": entry.get("words", 0),
                        "content_type": entry.get("content-type", ""),
                    })
            except json.JSONDecodeError as exc:
                result.status = "error"
                result.error_message = f"ffuf JSON parse failed: {exc}"
                result.duration_seconds = time.monotonic() - started
                return result

        findings = []
        for hit in hits:
            if _is_interesting_path(hit["path"], hit["status"]):
                findings.append(_make_finding(
                    scanner="recon_content",
                    host=urllib.parse.urlparse(base_url).hostname or base_url,
                    severity=VulnSeverity.LOW,
                    title=f"Sensitive path exposed: /{hit['path']}",
                    description=(
                        f"Content discovery found /{hit['path']} returning HTTP {hit['status']}. "
                        "This path matches a known-sensitive pattern."
                    ),
                    evidence=f"{hit['url']} (status={hit['status']}, length={hit['length']})",
                    remediation="Remove the path from production or restrict access.",
                    matched_at=hit["url"],
                ))

        result.findings = findings
        result.artifacts = {"base_url": base_url, "hits": hits, "wordlist": wordlist}
        result.status = "ok"
        result.duration_seconds = time.monotonic() - started
        return result

    def assert_handoff_scope(
        self,
        scan_id: str,
        subdomains: List[str],
        force: bool = False,
    ) -> List[str]:
        """Return any subdomains that violate registrable-domain scope. Empty list = ok."""
        state = self.get_scan_state(scan_id)
        if not state:
            return list(subdomains)
        target_host, _ = _split_host_port(state.target, default_port=443)
        target_domain = _registrable_domain(target_host)
        if not target_domain or force:
            return []
        violations = []
        for sub in subdomains:
            sub_domain = _registrable_domain(sub)
            if sub_domain != target_domain:
                violations.append(sub)
        return violations

    def _reaper_loop(self) -> None:
        while True:
            time.sleep(60)
            cutoff = time.time() - RESULT_RETENTION_SECONDS
            with self._lock:
                stale = [
                    sid for sid, state in self.active_scans.items()
                    if state.completed_at and state.completed_at.timestamp() < cutoff
                ]
                for sid in stale:
                    del self.active_scans[sid]
            if stale:
                logger.info(f"Reaped {len(stale)} stale recon scans")


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else default_port)
        return host, port
    if ":" in target and target.count(":") == 1:
        host, port_str = target.split(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            pass
    return target, default_port


def _normalize_base_url(target: str) -> str:
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return f"https://{target}".rstrip("/")


def _registrable_domain(host: str) -> Optional[str]:
    if not host:
        return None
    try:
        import tldextract
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return None
    except ImportError:
        parts = host.rsplit(".", 2)
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host


def _query_crtsh(domain: str) -> List[str]:
    url = CRTSH_URL_TEMPLATE.format(domain=urllib.parse.quote(domain))
    req = urllib.request.Request(url, headers={"User-Agent": "Ragnar-Recon/1.0"})
    with urllib.request.urlopen(req, timeout=CRTSH_TIMEOUT) as resp:
        body = resp.read()
    data = json.loads(body)
    names = set()
    for entry in data:
        for raw in (entry.get("name_value", ""), entry.get("common_name", "")):
            for line in raw.split("\n"):
                name = line.strip().lower().lstrip("*.")
                if not name or name.startswith(".") or " " in name:
                    continue
                if name.endswith(domain):
                    names.add(name)
    return sorted(names)


def _safe_resolve(resolver, name: str, rdtype: str) -> List[str]:
    try:
        import dns.resolver
        answers = resolver.resolve(name, rdtype)
        return [str(rdata).strip('"') for rdata in answers]
    except Exception:
        return []


def _probe_liveness(host: str) -> bool:
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}", method="HEAD")
            with urllib.request.urlopen(req, timeout=LIVENESS_TIMEOUT) as resp:
                if 200 <= resp.status < 400:
                    return True
        except Exception:
            continue
    return False


def _is_interesting_path(path: str, status: int) -> bool:
    if status in (401, 403):
        return False
    normalized = "/" + path.lstrip("/")
    return any(p.search(normalized) for p in INTERESTING_PATH_PATTERNS)


def _make_finding(
    scanner: str,
    host: str,
    severity: VulnSeverity,
    title: str,
    description: str,
    evidence: str = "",
    remediation: str = "",
    port: Optional[int] = None,
    matched_at: str = "",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        finding_id=uuid.uuid4().hex,
        scanner=scanner,
        host=host,
        port=port,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        matched_at=matched_at,
    )


def _parse_sslyze_result(scan, host: str, port: int) -> tuple[List[VulnerabilityFinding], Dict[str, Any]]:
    findings: List[VulnerabilityFinding] = []
    artifacts: Dict[str, Any] = {"host": host, "port": port}

    try:
        attempts = scan.scan_result if hasattr(scan, "scan_result") else None
    except Exception:
        attempts = None
    if attempts is None:
        return findings, artifacts

    cert_attempt = getattr(attempts, "certificate_info", None)
    if cert_attempt and getattr(cert_attempt, "result", None):
        cert_result = cert_attempt.result
        deployments = getattr(cert_result, "certificate_deployments", []) or []
        for dep in deployments:
            for cert in getattr(dep, "received_certificate_chain", []) or []:
                _add_cert_findings(findings, host, port, cert)
            artifacts.setdefault("cert_deployments", []).append(_describe_deployment(dep))

    for attr, label, severity in (
        ("ssl_2_0_cipher_suites", "SSLv2", VulnSeverity.HIGH),
        ("ssl_3_0_cipher_suites", "SSLv3", VulnSeverity.HIGH),
        ("tls_1_0_cipher_suites", "TLS 1.0", VulnSeverity.MEDIUM),
        ("tls_1_1_cipher_suites", "TLS 1.1", VulnSeverity.MEDIUM),
    ):
        attempt = getattr(attempts, attr, None)
        if not attempt or not getattr(attempt, "result", None):
            continue
        accepted = getattr(attempt.result, "accepted_cipher_suites", []) or []
        if accepted:
            findings.append(_make_finding(
                scanner="recon_tls",
                host=host,
                port=port,
                severity=severity,
                title=f"Deprecated protocol enabled: {label}",
                description=f"The server accepts connections over {label}, which is deprecated and insecure.",
                evidence=f"{len(accepted)} cipher suite(s) accepted",
                remediation=f"Disable {label} in the server configuration.",
            ))

    weak_keywords = ("RC4", "DES", "NULL", "EXPORT", "anon", "MD5")
    for attr in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
        attempt = getattr(attempts, attr, None)
        if not attempt or not getattr(attempt, "result", None):
            continue
        for accepted in getattr(attempt.result, "accepted_cipher_suites", []) or []:
            name = getattr(getattr(accepted, "cipher_suite", None), "name", "") or ""
            if any(kw in name for kw in weak_keywords):
                findings.append(_make_finding(
                    scanner="recon_tls",
                    host=host,
                    port=port,
                    severity=VulnSeverity.MEDIUM,
                    title=f"Weak cipher suite: {name}",
                    description="The server negotiates a cipher suite known to be weak.",
                    evidence=name,
                    remediation="Remove weak cipher suites from the server configuration.",
                ))

    hh_attempt = getattr(attempts, "http_headers", None)
    if hh_attempt and getattr(hh_attempt, "result", None):
        hsts = getattr(hh_attempt.result, "strict_transport_security_header", None)
        if hsts is None:
            findings.append(_make_finding(
                scanner="recon_tls",
                host=host,
                port=port,
                severity=VulnSeverity.LOW,
                title="Missing HSTS header",
                description="The server does not advertise HTTP Strict-Transport-Security.",
                remediation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            ))

    return findings, artifacts


def _add_cert_findings(findings: List[VulnerabilityFinding], host: str, port: int, cert) -> None:
    try:
        not_after = cert.not_valid_after
    except Exception:
        return
    now = datetime.utcnow()
    if not_after < now:
        findings.append(_make_finding(
            scanner="recon_tls",
            host=host,
            port=port,
            severity=VulnSeverity.HIGH,
            title="Expired TLS certificate",
            description=f"Certificate expired on {not_after.isoformat()}.",
            remediation="Renew the certificate immediately.",
        ))
    elif (not_after - now).days < 30:
        findings.append(_make_finding(
            scanner="recon_tls",
            host=host,
            port=port,
            severity=VulnSeverity.MEDIUM,
            title="TLS certificate expiring soon",
            description=f"Certificate expires on {not_after.isoformat()} ({(not_after - now).days} days).",
            remediation="Renew the certificate before it expires.",
        ))


def _describe_deployment(dep) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    chain = getattr(dep, "received_certificate_chain", []) or []
    if chain:
        leaf = chain[0]
        try:
            info["subject"] = leaf.subject.rfc4514_string()
            info["issuer"] = leaf.issuer.rfc4514_string()
            info["not_before"] = leaf.not_valid_before.isoformat()
            info["not_after"] = leaf.not_valid_after.isoformat()
        except Exception:
            pass
    return info


_recon_engine_instance: Optional[ReconEngine] = None
_recon_engine_lock = threading.Lock()


def get_recon_engine(shared_data=None) -> ReconEngine:
    global _recon_engine_instance
    if _recon_engine_instance is not None:
        return _recon_engine_instance
    with _recon_engine_lock:
        if _recon_engine_instance is not None:
            return _recon_engine_instance
        _recon_engine_instance = ReconEngine(shared_data)
    return _recon_engine_instance
