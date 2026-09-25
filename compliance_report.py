#!/usr/bin/env python3
"""
Compliance reporting for Ragnar.

Maps existing data sources to control frameworks:
  - CIS: Lynis authenticated-audit findings (test IDs) -> CIS Benchmark areas
  - PCI: scan_findings + hosts + discovered credentials -> PCI DSS v4.0 requirements

This produces INFORMAL, internal reports. It is not a certified CIS-CAT
assessment nor a PCI ASV scan. See compliance_mappings.json.
"""

import os
import re
import json
import html
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from logger import Logger
from lynis_parser import parse_lynis_dat

logger = Logger(name="compliance_report", level=logging.INFO)

_MAPPINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "compliance_mappings.json")
_LYNIS_DAT_RE = re.compile(r"^lynis_(?P<host>.+?)_(?P<ts>\d{8}_\d{6})\.dat$")
_CLEARTEXT_PORTS = {21: "ftp", 23: "telnet", 80: "http", 110: "pop3", 143: "imap", 389: "ldap", 8080: "http-alt"}
_HIGH_SEVERITIES = {"critical", "high"}


class ComplianceReporter:
    """Builds CIS and PCI compliance views from data Ragnar already collects."""

    def __init__(self, shared_data=None, db=None):
        self.shared_data = shared_data
        self.db = db or getattr(shared_data, "db", None)
        self.mappings = self._load_mappings()

    def _load_mappings(self) -> Dict[str, Any]:
        try:
            with open(_MAPPINGS_FILE, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception as exc:
            logger.error(f"Could not load compliance mappings: {exc}")
            return {"cis": {"lynis_to_cis": {}, "prefix_to_cis": {}}, "pci": {"requirements": []}}

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def _vuln_dir(self) -> Optional[str]:
        return getattr(self.shared_data, "vulnerabilities_dir", None)

    def _collect_lynis(self, host: Optional[str] = None) -> List[Dict[str, Any]]:
        records = []
        base = self._vuln_dir()
        if not base or not os.path.isdir(base):
            return records

        for root, _dirs, files in os.walk(base):
            for filename in files:
                match = _LYNIS_DAT_RE.match(filename)
                if not match:
                    continue
                rec_host = match.group("host")
                if host and rec_host != host:
                    continue
                path = os.path.join(root, filename)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                        parsed = parse_lynis_dat(handle.read()) or {}
                except Exception as exc:
                    logger.warning(f"Failed to parse Lynis dat {filename}: {exc}")
                    continue

                metadata = parsed.get("metadata", {}) if isinstance(parsed, dict) else {}
                scan_date = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
                records.append({
                    "host": rec_host,
                    "scan_date": scan_date,
                    "hardening_index": metadata.get("hardening_index"),
                    "warnings": parsed.get("warnings", []),
                    "suggestions": parsed.get("suggestions", []),
                    "vulnerable_packages": parsed.get("vulnerable_packages", []),
                })

        records.sort(key=lambda r: r["scan_date"], reverse=True)
        seen = set()
        deduped = []
        for rec in records:
            if rec["host"] in seen:
                continue
            seen.add(rec["host"])
            deduped.append(rec)
        return deduped

    def _collect_findings(self) -> List[Dict[str, Any]]:
        if not self.db:
            return []
        try:
            return self.db.get_all_findings(limit=2000)
        except Exception as exc:
            logger.error(f"Failed to read scan findings: {exc}")
            return []

    def _collect_hosts(self) -> List[Dict[str, Any]]:
        if not self.db:
            return []
        try:
            return self.db.get_all_hosts()
        except Exception as exc:
            logger.error(f"Failed to read hosts: {exc}")
            return []

    # ------------------------------------------------------------------
    # CIS
    # ------------------------------------------------------------------

    def _map_lynis_code(self, code: str) -> Dict[str, Any]:
        cis = self.mappings.get("cis", {})
        exact = cis.get("lynis_to_cis", {})
        prefix = cis.get("prefix_to_cis", {})
        if code in exact:
            return exact[code]
        head = code.split("-", 1)[0] if code else ""
        if head in prefix:
            return prefix[head]
        return {"title": "Unmapped finding (informational)", "controls": ["Unmapped (informational)"]}

    def build_cis_report(self, host: Optional[str] = None) -> Dict[str, Any]:
        lynis = self._collect_lynis(host)
        controls: Dict[str, Dict[str, Any]] = {}

        def bucket(entry: Dict[str, str], rec_host: str, kind: str):
            code = (entry.get("code") or "").strip()
            mapping = self._map_lynis_code(code)
            for control in mapping["controls"]:
                slot = controls.setdefault(control, {
                    "control": control,
                    "title": mapping["title"],
                    "warnings": 0,
                    "suggestions": 0,
                    "findings": [],
                })
                if kind == "warning":
                    slot["warnings"] += 1
                else:
                    slot["suggestions"] += 1
                slot["findings"].append({
                    "host": rec_host,
                    "code": code or "—",
                    "kind": kind,
                    "message": entry.get("message", ""),
                    "remediation": entry.get("remediation", ""),
                    "severity": "high" if kind == "warning" else "medium",
                })

        for rec in lynis:
            for warning in rec["warnings"]:
                bucket(warning, rec["host"], "warning")
            for suggestion in rec["suggestions"]:
                bucket(suggestion, rec["host"], "suggestion")

        control_rows = []
        for slot in controls.values():
            if slot["warnings"] > 0:
                slot["status"] = "attention"
            elif slot["suggestions"] > 0:
                slot["status"] = "review"
            else:
                slot["status"] = "ok"
            control_rows.append(slot)
        control_rows.sort(key=lambda s: (s["status"] != "attention", s["control"]))

        indices = [float(r["hardening_index"]) for r in lynis
                   if str(r.get("hardening_index") or "").replace(".", "", 1).isdigit()]
        summary = {
            "hosts_assessed": len(lynis),
            "controls_flagged": sum(1 for r in control_rows if r["status"] == "attention"),
            "controls_review": sum(1 for r in control_rows if r["status"] == "review"),
            "total_warnings": sum(r["warnings"] for r in control_rows),
            "total_suggestions": sum(r["suggestions"] for r in control_rows),
            "avg_hardening_index": round(sum(indices) / len(indices), 1) if indices else None,
            "hosts": [{"host": r["host"], "hardening_index": r["hardening_index"], "scan_date": r["scan_date"]}
                      for r in lynis],
        }
        return {
            "framework": self.mappings.get("cis", {}).get("framework", "CIS (informal)"),
            "controls": control_rows,
            "summary": summary,
            "data_available": bool(lynis),
        }

    # ------------------------------------------------------------------
    # PCI
    # ------------------------------------------------------------------

    def _lynis_prefix_count(self, lynis: List[Dict[str, Any]], prefixes) -> int:
        count = 0
        for rec in lynis:
            for warning in rec["warnings"]:
                code = (warning.get("code") or "")
                if any(code.startswith(p) for p in prefixes):
                    count += 1
        return count

    def _evaluate_rule(self, rule: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        findings = ctx["findings"]
        hosts = ctx["hosts"]
        lynis = ctx["lynis"]
        credentials = ctx["credentials"]
        has_lynis = bool(lynis)
        evidence: List[str] = []

        if rule == "firewall_config":
            hits = self._lynis_prefix_count(lynis, ("FIRE",))
            if not has_lynis:
                return {"status": "not_assessed", "matched": 0, "evidence": ["No authenticated host audit available."]}
            if hits:
                return {"status": "attention", "matched": hits, "evidence": [f"{hits} firewall finding(s) from Lynis."]}
            return {"status": "ok", "matched": 0, "evidence": ["No host-firewall gaps detected by Lynis."]}

        if rule == "secure_config":
            hits = sum(len(r["warnings"]) for r in lynis)
            if not has_lynis:
                return {"status": "not_assessed", "matched": 0, "evidence": ["No authenticated host audit available."]}
            if hits:
                return {"status": "attention", "matched": hits, "evidence": [f"{hits} hardening warning(s) from Lynis."]}
            return {"status": "ok", "matched": 0, "evidence": ["No insecure-config warnings from Lynis."]}

        if rule == "default_credentials":
            if credentials is None:
                return {"status": "not_assessed", "matched": 0, "evidence": ["Credential data not supplied."]}
            if credentials:
                sample = ", ".join(sorted({c.get("ip", "?") for c in credentials})[:8])
                return {"status": "attention", "matched": len(credentials),
                        "evidence": [f"{len(credentials)} credential(s) recovered (hosts: {sample})."]}
            return {"status": "ok", "matched": 0, "evidence": ["No credentials recovered by brute-force."]}

        if rule == "strong_crypto_transit":
            flagged = []
            for host in hosts:
                ports = {int(p) for p in re.findall(r"\d+", host.get("ports", "") or "")}
                cleartext = sorted(ports & set(_CLEARTEXT_PORTS))
                if cleartext:
                    flagged.append((host.get("ip", "?"), cleartext))
            if not hosts:
                return {"status": "not_assessed", "matched": 0, "evidence": ["No hosts discovered."]}
            if flagged:
                ev = [f"{ip}: {', '.join(_CLEARTEXT_PORTS[p] for p in ports)}" for ip, ports in flagged[:12]]
                return {"status": "attention", "matched": len(flagged), "evidence": ev}
            return {"status": "ok", "matched": 0, "evidence": ["No cleartext services exposed."]}

        if rule == "anti_malware":
            hits = self._lynis_prefix_count(lynis, ("MALW",))
            if not has_lynis:
                return {"status": "not_assessed", "matched": 0, "evidence": ["No authenticated host audit available."]}
            if hits:
                return {"status": "attention", "matched": hits, "evidence": [f"{hits} malware-defense finding(s) from Lynis."]}
            return {"status": "ok", "matched": 0, "evidence": ["No malware-defense gaps detected by Lynis."]}

        if rule == "patch_vulns":
            high = [f for f in findings if (f.get("severity") or "").lower() in _HIGH_SEVERITIES]
            pkgs = sum(len(r["vulnerable_packages"]) for r in lynis)
            total = len(high) + pkgs
            if not findings and not has_lynis:
                return {"status": "not_assessed", "matched": 0, "evidence": ["No vulnerability scan data."]}
            if total:
                ev = []
                if high:
                    ev.append(f"{len(high)} high/critical scan finding(s).")
                if pkgs:
                    ev.append(f"{pkgs} vulnerable package(s) from Lynis.")
                return {"status": "attention", "matched": total, "evidence": ev}
            return {"status": "ok", "matched": 0, "evidence": ["No high/critical vulnerabilities outstanding."]}

        if rule == "audit_logging":
            hits = self._lynis_prefix_count(lynis, ("LOGG", "ACCT"))
            if not has_lynis:
                return {"status": "not_assessed", "matched": 0, "evidence": ["No authenticated host audit available."]}
            if hits:
                return {"status": "attention", "matched": hits, "evidence": [f"{hits} logging/audit finding(s) from Lynis."]}
            return {"status": "ok", "matched": 0, "evidence": ["Logging/audit configured per Lynis."]}

        if rule == "vuln_scanning_process":
            if findings or has_lynis:
                bits = []
                if findings:
                    bits.append(f"{len(findings)} scan finding(s) on record.")
                if has_lynis:
                    bits.append(f"{len(lynis)} authenticated host audit(s).")
                return {"status": "ok", "matched": len(findings), "evidence": bits}
            return {"status": "not_assessed", "matched": 0, "evidence": ["No scan activity on record."]}

        return {"status": "not_assessed", "matched": 0, "evidence": ["Unknown rule."]}

    def build_pci_report(self, credentials: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        ctx = {
            "findings": self._collect_findings(),
            "hosts": self._collect_hosts(),
            "lynis": self._collect_lynis(),
            "credentials": credentials,
        }
        requirements = []
        for req in self.mappings.get("pci", {}).get("requirements", []):
            result = self._evaluate_rule(req.get("rule", ""), ctx)
            requirements.append({
                "id": req.get("id", ""),
                "title": req.get("title", ""),
                "guidance": req.get("guidance", ""),
                "status": result["status"],
                "matched": result["matched"],
                "evidence": result["evidence"],
            })
        requirements.sort(key=lambda r: {"attention": 0, "ok": 1, "not_assessed": 2}.get(r["status"], 3))
        summary = {
            "requirements_total": len(requirements),
            "attention": sum(1 for r in requirements if r["status"] == "attention"),
            "ok": sum(1 for r in requirements if r["status"] == "ok"),
            "not_assessed": sum(1 for r in requirements if r["status"] == "not_assessed"),
            "findings_considered": len(ctx["findings"]),
            "hosts_considered": len(ctx["hosts"]),
            "lynis_hosts": len(ctx["lynis"]),
        }
        return {
            "framework": self.mappings.get("pci", {}).get("framework", "PCI DSS (informal)"),
            "requirements": requirements,
            "summary": summary,
            "data_available": bool(ctx["findings"] or ctx["hosts"] or ctx["lynis"]),
        }

    def build(self, framework: str, host: Optional[str] = None,
              credentials: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        if framework == "cis":
            return self.build_cis_report(host=host)
        if framework == "pci":
            return self.build_pci_report(credentials=credentials)
        raise ValueError(f"Unknown framework: {framework}")


_STATUS_COLORS = {
    "attention": "#f87171",
    "review": "#facc15",
    "ok": "#4ade80",
    "not_assessed": "#9ca3af",
}
_STATUS_LABELS = {
    "attention": "Action needed",
    "review": "Review",
    "ok": "No issues detected",
    "not_assessed": "Not assessed",
}


def render_compliance_html(cis: Dict[str, Any], pci: Dict[str, Any]) -> str:
    """Render a self-contained HTML compliance report from both framework views."""
    def e(value):
        return html.escape(str(value if value is not None else ""))

    def badge(status):
        return (f'<span style="color:{_STATUS_COLORS.get(status, "#9ca3af")};font-weight:600">'
                f'{e(_STATUS_LABELS.get(status, status))}</span>')

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cis_summary = cis.get("summary", {})
    cis_rows = ""
    for row in cis.get("controls", []):
        finding_lines = "<br>".join(
            f'<span class="mono small">{e(f["host"])} · {e(f["code"])}</span> — {e(f["message"][:140])}'
            for f in row["findings"][:6]
        )
        if len(row["findings"]) > 6:
            finding_lines += f'<br><span class="small">…and {len(row["findings"]) - 6} more</span>'
        cis_rows += f"""<tr>
            <td>{e(row['control'])}</td>
            <td>{e(row['title'])}</td>
            <td>{badge(row['status'])}</td>
            <td>{row['warnings']}</td>
            <td>{row['suggestions']}</td>
            <td class="small">{finding_lines or '—'}</td>
        </tr>"""

    pci_rows = ""
    for row in pci.get("requirements", []):
        evidence = "<br>".join(e(x) for x in row["evidence"])
        pci_rows += f"""<tr>
            <td class="mono">{e(row['id'])}</td>
            <td>{e(row['title'])}</td>
            <td>{badge(row['status'])}</td>
            <td class="small">{e(row['guidance'])}</td>
            <td class="small">{evidence or '—'}</td>
        </tr>"""

    pci_summary = pci.get("summary", {})

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ragnar Compliance Report — {e(generated_at)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}}
  h1{{font-size:1.8rem;margin-bottom:0.25rem;color:#f8fafc}}
  .subtitle{{color:#94a3b8;margin-bottom:1.5rem;font-size:0.9rem}}
  .disclaimer{{background:#1e293b;border:1px solid #334155;border-left:3px solid #facc15;border-radius:0.4rem;padding:0.75rem 1rem;margin-bottom:2rem;font-size:0.8rem;color:#cbd5e1}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:1.5rem}}
  .stat{{background:#1e293b;border:1px solid #334155;border-radius:0.5rem;padding:1rem;text-align:center}}
  .stat-value{{font-size:2rem;font-weight:700;color:#f8fafc}}
  .stat-label{{font-size:0.75rem;color:#94a3b8;margin-top:0.25rem;text-transform:uppercase;letter-spacing:.05em}}
  section{{margin-bottom:2.5rem}}
  h2{{font-size:1.1rem;font-weight:600;color:#cbd5e1;border-bottom:1px solid #334155;padding-bottom:0.5rem;margin-bottom:1rem;text-transform:uppercase;letter-spacing:.05em}}
  .table-wrap{{overflow-x:auto}}
  table{{width:100%;border-collapse:collapse;font-size:0.8rem}}
  th{{background:#1e293b;color:#94a3b8;text-align:left;padding:0.5rem 0.75rem;font-weight:600;white-space:nowrap}}
  td{{padding:0.45rem 0.75rem;border-bottom:1px solid #1e293b;vertical-align:top}}
  .mono{{font-family:'SF Mono',monospace}}
  .small{{font-size:0.72rem}}
  .empty{{color:#475569;font-style:italic;padding:1rem 0}}
  .footer{{margin-top:3rem;color:#475569;font-size:0.75rem;text-align:center}}
</style>
</head>
<body>
<h1>Ragnar Compliance Report</h1>
<p class="subtitle">Generated: {e(generated_at)}</p>
<div class="disclaimer">
  <strong>Informal / internal report.</strong> Mappings are a curated subset. This is NOT a certified
  CIS-CAT assessment or a PCI DSS ASV scan, and findings are not false-positive validated. Use for
  internal hardening guidance only.
</div>

<section>
  <h2>CIS Hardening — {e(cis.get('framework', ''))}</h2>
  <div class="stats">
    <div class="stat"><div class="stat-value">{cis_summary.get('hosts_assessed', 0)}</div><div class="stat-label">Hosts Audited</div></div>
    <div class="stat"><div class="stat-value" style="color:#f87171">{cis_summary.get('controls_flagged', 0)}</div><div class="stat-label">Controls Flagged</div></div>
    <div class="stat"><div class="stat-value" style="color:#facc15">{cis_summary.get('controls_review', 0)}</div><div class="stat-label">Review</div></div>
    <div class="stat"><div class="stat-value">{e(cis_summary.get('avg_hardening_index') if cis_summary.get('avg_hardening_index') is not None else 'n/a')}</div><div class="stat-label">Avg Hardening Index</div></div>
  </div>
  <div class="table-wrap">
  {'<table><thead><tr><th>CIS Area</th><th>Topic</th><th>Status</th><th>Warn</th><th>Sugg</th><th>Findings</th></tr></thead><tbody>' + cis_rows + '</tbody></table>' if cis_rows else '<p class="empty">No Lynis audit data found. Run a Lynis SSH audit against a host with known credentials.</p>'}
  </div>
</section>

<section>
  <h2>PCI DSS — {e(pci.get('framework', ''))}</h2>
  <div class="stats">
    <div class="stat"><div class="stat-value">{pci_summary.get('requirements_total', 0)}</div><div class="stat-label">Requirements</div></div>
    <div class="stat"><div class="stat-value" style="color:#f87171">{pci_summary.get('attention', 0)}</div><div class="stat-label">Action Needed</div></div>
    <div class="stat"><div class="stat-value" style="color:#4ade80">{pci_summary.get('ok', 0)}</div><div class="stat-label">No Issues</div></div>
    <div class="stat"><div class="stat-value" style="color:#9ca3af">{pci_summary.get('not_assessed', 0)}</div><div class="stat-label">Not Assessed</div></div>
  </div>
  <div class="table-wrap">
  {'<table><thead><tr><th>Req</th><th>Title</th><th>Status</th><th>Guidance</th><th>Evidence</th></tr></thead><tbody>' + pci_rows + '</tbody></table>' if pci_rows else '<p class="empty">No data available.</p>'}
  </div>
</section>

<p class="footer">Ragnar Security Scanner — For authorized testing only</p>
</body>
</html>"""
