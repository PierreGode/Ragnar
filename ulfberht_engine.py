#!/usr/bin/env python3
"""
Ulfberht Engagement engine -- coordinated, data-driven security workflows.

This is the professional/educational differentiator of the Ragnar OS Ulfberht
edition: not a drawer of tools, but **playbooks** that chain the phases of a real
engagement -- discovery -> diagnostics -> assessment -> reporting -- under one
scope, into one methodology-aligned report (NIST SP 800-115 / PTES).

v2 — playbooks are now DATA, not code:
  * A playbook is an ordered list of **steps**; each step runs one **action**
    from a fixed catalog (nmap / posture / nuclei / command / report) with
    validated parameters.
  * Built-in playbooks ship with the image; **operators can author and upload
    their own** `.json` playbooks, which live in data/engagement_playbooks/ and
    show up in the Files tab (same pattern as Device Console scripts and Rubber
    Ducky payloads). Uploaded playbooks are validated on load.
  * The `command` action can run an **allowlisted** tool with validated args
    (no shell, no metacharacters) — power for experts without turning a JSON
    file into arbitrary shell.

It is EXCLUSIVE to the official Ulfberht image: every entry point checks the
build-time edition marker via ragnar_edition. On the standard image, or on a
stock Kali box that merely ran install_ragnar.sh, the engine refuses to run and
the UI never shows it.

Safety model:
  * Scope is entered once; {scope} is the only target placeholder and every tool
    is pointed at it (or at hosts discovered inside it).
  * Discovery + diagnostics are passive/safe and always allowed.
  * Any step marked "active" (and the built-in assessment actions) runs ONLY
    when the caller passes enable_active=True (wired to Ragnar's enable_attacks
    opt-in). An uploaded playbook cannot bypass that gate.
  * `command` tools are allowlisted; args are validated to contain no shell
    metacharacters; everything runs via a list argv (never shell=True) with a
    per-step timeout.

In-memory run registry (ephemeral; a run does not survive a service restart),
which is the right scope for a live engagement console.
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET

try:
    import ragnar_edition
except Exception:  # pragma: no cover - defensive
    ragnar_edition = None

_HERE = os.path.dirname(os.path.abspath(__file__))
PLAYBOOKS_DIR = os.path.join(_HERE, "data", "engagement_playbooks")
RUNS_DIR = os.path.join(_HERE, "data", "engagements")   # persisted engagement history

# ── Methodology ─────────────────────────────────────────────────────────────
# Phases map to NIST SP 800-115 ("Technical Guide to Information Security
# Testing and Assessment"). Kept explicit so reports and teaching line up.
PHASES = ("discovery", "diagnostics", "assessment", "reporting")
PHASE_META = {
    "discovery":   {"name": "Discovery",   "nist": "NIST SP 800-115 §4 (Target Identification)", "active": False},
    "diagnostics": {"name": "Diagnostics", "nist": "NIST SP 800-115 §4 (Vulnerability / posture analysis)", "active": False},
    "assessment":  {"name": "Assessment",  "nist": "NIST SP 800-115 §5 (Target Vulnerability Validation)", "active": True},
    "reporting":   {"name": "Reporting",   "nist": "NIST SP 800-115 §8 (Post-Testing / Reporting)", "active": False},
}

# Tools an operator may invoke from a `command` step. Recon/diagnostic tools are
# always allowed; the ones marked active (offensive/validation) run only when
# enable_active is on. Everything is argv-only (no shell).
# Tools a `command` step may invoke. This is a SAFETY allowlist, not a feature
# list: the step runs argv-only (never a shell), so the allowlist is what stops
# a shared/uploaded playbook from running an arbitrary binary AS ROOT (rm, dd, a
# reverse shell). It deliberately covers the whole installed security toolset,
# not arbitrary system commands.
#
# Passive recon tools are always allowed; everything else is "active" and runs
# only in an active step (gated by enable_attacks). Beyond this curated set we
# also merge in every offensive tool the edition actually detected on this image
# (see _merge_edition_tools below) so any installed Arsenal tool can be scripted
# and the list stays current as tools are added. Note: Wi-Fi (aircrack-ng/
# airodump-ng/wifite/reaver/bully/kismet) and cracking (hashcat/john) tools need
# a monitor-mode capture or hash+wordlist inputs rather than an IP scope, and
# interactive/long-running tools (msfconsole/setoolkit/responder/ettercap) will
# run until the step timeout unless invoked non-interactively — they are allowed
# but need the right args to be useful in a run-to-completion step.
_RECON_TOOLS = ["nmap", "masscan", "dig", "host", "whois", "whatweb",
                "nbtscan", "onesixtyone", "snmpwalk", "fping", "arp-scan"]
_OFFENSIVE_TOOLS = [
    # web / service validation
    "nuclei", "nikto", "wpscan", "sslscan", "sslyze", "testssl.sh",
    "feroxbuster", "gobuster", "ffuf", "sqlmap",
    # SMB / AD / credentials
    "enum4linux", "enum4linux-ng", "smbclient", "netexec", "nxc", "responder", "hydra",
    # crack (need hash + wordlist inputs)
    "hashcat", "john",
    # wireless (need monitor mode + a capture, not an IP scope)
    "aircrack-ng", "airodump-ng", "wifite", "reaver", "bully", "kismet",
    # framework / MITM / capture (interactive or long-running; pass non-interactive args)
    "msfconsole", "setoolkit", "ettercap", "tcpdump", "tshark",
]
_ALLOWED_TOOLS = {t: {"active": False} for t in _RECON_TOOLS}
_ALLOWED_TOOLS.update({t: {"active": True} for t in _OFFENSIVE_TOOLS})


def _merge_edition_tools():
    """Allow every offensive tool the edition detected on THIS image too, so any
    installed Arsenal tool can be scripted (active-gated) and the allowlist stays
    in sync with what is actually installed. No-op off the Ulfberht image."""
    try:
        if ragnar_edition:
            for t in (ragnar_edition.detect().get("tools") or []):
                b = t.get("bin")
                if b and b not in _ALLOWED_TOOLS:
                    _ALLOWED_TOOLS[b] = {"active": True}
    except Exception:
        pass


_merge_edition_tools()

# Characters that must never appear in a command arg — closes shell-injection
# even though we never use a shell. Also blocks path traversal of the binary.
_ARG_BAD = re.compile(r"[;&|<>$`\n\r\\\"']")

# Cleartext / high-risk services we flag in the diagnostics posture pass.
# (service-name or port) -> (severity, title, reference)
_RISK_SERVICES = {
    "telnet":   ("high",   "Cleartext remote administration (Telnet)", "CWE-319 / MITRE T1021"),
    "ftp":      ("medium", "Cleartext file transfer (FTP)", "CWE-319"),
    "http":     ("low",    "Unencrypted web service (HTTP)", "CWE-319"),
    "rlogin":   ("high",   "Legacy r-service (rlogin)", "CWE-319"),
    "rsh":      ("high",   "Legacy r-service (rsh)", "CWE-319"),
    "vnc":      ("medium", "Remote desktop exposed (VNC)", "MITRE T1021.005"),
    "microsoft-ds": ("medium", "SMB exposed to the scope", "MITRE T1021.002"),
    "netbios-ssn":  ("medium", "NetBIOS/SMB exposed", "MITRE T1021.002"),
    "snmp":     ("medium", "SNMP exposed (often default community)", "CWE-1188"),
    "ms-sql-s": ("medium", "Database service exposed (MSSQL)", "MITRE T1210"),
    "mysql":    ("low",    "Database service exposed (MySQL)", "MITRE T1210"),
    "rdp":      ("medium", "Remote Desktop exposed (RDP)", "MITRE T1021.001"),
}
_RISK_PORTS = {23: "telnet", 21: "ftp", 513: "rlogin", 514: "rsh",
               5900: "vnc", 445: "microsoft-ds", 139: "netbios-ssn",
               161: "snmp", 1433: "ms-sql-s", 3306: "mysql", 3389: "rdp"}

# One-line remediation per risk key — shown per finding in the report so the
# output is actionable (operators) and instructive (students).
_REMEDIATION = {
    "telnet": "Disable Telnet; use SSH and restrict it to management networks.",
    "ftp": "Replace FTP with SFTP/FTPS and disable anonymous access.",
    "http": "Serve over HTTPS (redirect 80→443) with a valid TLS certificate.",
    "rlogin": "Disable the r-services (rlogin/rsh/rexec); use SSH with key auth.",
    "rsh": "Disable the r-services (rlogin/rsh/rexec); use SSH with key auth.",
    "vnc": "Don't expose VNC directly; tunnel it over SSH/VPN and require strong auth.",
    "microsoft-ds": "Restrict SMB to trusted hosts, require SMB signing, disable SMBv1.",
    "netbios-ssn": "Disable NetBIOS over TCP/IP and retire legacy SMB.",
    "snmp": "Drop SNMP v1/v2c and default communities; use SNMPv3 (auth/priv) and firewall it.",
    "ms-sql-s": "Don't expose the database to untrusted networks; enforce TLS + strong auth.",
    "mysql": "Bind the database to localhost/trusted subnets; enforce TLS + strong auth.",
    "rdp": "Put RDP behind a VPN/gateway, enable NLA, and enforce MFA + strong passwords.",
}

_SCOPE_RE = re.compile(r"^[0-9a-zA-Z\.\:/\-\s]{1,200}$")
_PORTSPEC_RE = re.compile(r"^[0-9,\-]{1,64}$")

_runs = {}
_lock = threading.Lock()


# ── Built-in playbooks (step form) ──────────────────────────────────────────
# Each is a dict: id, name, description, steps[]. A step is
#   {"phase", "action", "params"{}, "active"?}.
BUILTIN_PLAYBOOKS = {
    "scoped-network-assessment": {
        "id": "scoped-network-assessment",
        "name": "Scoped Network Assessment",
        "description": ("Sweep a scope for live hosts and services, derive a "
                        "security posture from what is exposed, optionally "
                        "validate web findings, and produce one report."),
        "steps": [
            {"phase": "discovery",   "action": "nmap",
             "params": {"ports": "top-100", "service_version": True, "timing": "T4"}},
            {"phase": "diagnostics", "action": "posture"},
            {"phase": "assessment",  "action": "nuclei",
             "params": {"severity": ["medium", "high", "critical"]}, "active": True},
            {"phase": "reporting",   "action": "report"},
        ],
    },
    "web-app-assessment": {
        "id": "web-app-assessment",
        "name": "Web Application Assessment",
        "description": ("Find web services across the scope, fingerprint them, "
                        "and run nuclei + a Nikto pass against each — a focused "
                        "web engagement with a consolidated report."),
        "steps": [
            {"phase": "discovery",   "action": "nmap",
             "params": {"ports": "80,443,8080,8443,8000,8888", "service_version": True, "timing": "T4"}},
            {"phase": "diagnostics", "action": "posture"},
            {"phase": "diagnostics", "action": "command",
             "params": {"tool": "whatweb", "args": ["--no-errors", "{web_urls}"]}},
            {"phase": "assessment",  "action": "nuclei",
             "params": {"severity": ["low", "medium", "high", "critical"]}, "active": True},
            {"phase": "assessment",  "action": "command",
             "params": {"tool": "nikto", "args": ["-ask", "no", "-nointeractive", "-host", "{web_urls}"],
                        "per_target": True}, "active": True},
            {"phase": "reporting",   "action": "report"},
        ],
    },
    "host-service-audit": {
        "id": "host-service-audit",
        "name": "Full-Port Host & Service Audit",
        "description": ("Deep per-host audit: all TCP ports with version + safe "
                        "default NSE scripts, posture analysis, and a report. "
                        "Passive — no active exploitation."),
        "steps": [
            {"phase": "discovery",   "action": "nmap",
             "params": {"ports": "1-65535", "service_version": True, "default_scripts": True, "timing": "T4"}},
            {"phase": "diagnostics", "action": "posture"},
            {"phase": "reporting",   "action": "report"},
        ],
    },
    "smb-ad-recon": {
        "id": "smb-ad-recon",
        "name": "SMB / Active Directory Recon",
        "description": ("Hunt SMB/LDAP/Kerberos across the scope and enumerate "
                        "exposed SMB with enum4linux-ng. Enumeration is active "
                        "— it runs only with active testing enabled."),
        "steps": [
            {"phase": "discovery",   "action": "nmap",
             "params": {"ports": "88,135,139,389,445,636,3268,5985", "service_version": True, "timing": "T4"}},
            {"phase": "diagnostics", "action": "posture"},
            {"phase": "assessment",  "action": "command",
             "params": {"tool": "enum4linux-ng", "args": ["-A", "{host}"], "per_host": True},
             "active": True},
            {"phase": "reporting",   "action": "report"},
        ],
    },
}


def is_enabled():
    """True only on the genuine Ulfberht image."""
    try:
        return bool(ragnar_edition and ragnar_edition.detect().get("is_ulfberht"))
    except Exception:
        return False


# ── Playbook loading / validation ───────────────────────────────────────────
def _slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or ("playbook-" + uuid.uuid4().hex[:6])


def _validate_playbook(spec):
    """Return (normalized_spec, error_or_None). Does not raise."""
    if not isinstance(spec, dict):
        return None, "Playbook must be a JSON object."
    name = str(spec.get("name") or spec.get("id") or "").strip()
    if not name:
        return None, "Playbook needs a 'name'."
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps:
        return None, "Playbook needs a non-empty 'steps' array."
    norm_steps = []
    for i, st in enumerate(steps):
        if not isinstance(st, dict):
            return None, f"Step {i+1} must be an object."
        action = st.get("action")
        if action not in _ACTIONS:
            return None, f"Step {i+1}: unknown action '{action}'. Allowed: {', '.join(sorted(_ACTIONS))}."
        phase = st.get("phase") or _DEFAULT_PHASE.get(action, "diagnostics")
        if phase not in PHASES:
            return None, f"Step {i+1}: unknown phase '{phase}'."
        params = st.get("params") or {}
        if not isinstance(params, dict):
            return None, f"Step {i+1}: 'params' must be an object."
        if action == "command":
            tool = params.get("tool")
            if tool not in _ALLOWED_TOOLS:
                return None, (f"Step {i+1}: tool '{tool}' is not allowlisted. "
                              f"Allowed: {', '.join(sorted(_ALLOWED_TOOLS))}.")
            args = params.get("args", [])
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                return None, f"Step {i+1}: 'args' must be an array of strings."
            for a in args:
                if _ARG_BAD.search(a):
                    return None, f"Step {i+1}: arg '{a}' contains forbidden shell characters."
        if action == "nmap":
            ps = params.get("ports")
            if ps and not (ps in ("top-100", "top-1000") or _PORTSPEC_RE.match(str(ps))):
                return None, f"Step {i+1}: invalid ports '{ps}'."
        norm_steps.append({
            "phase": phase, "action": action, "params": params,
            "active": bool(st.get("active")) or PHASE_META[phase]["active"],
        })
    return {
        "id": _slugify(spec.get("id") or name),
        "name": name,
        "description": str(spec.get("description") or "").strip(),
        "steps": norm_steps,
    }, None


def _derive_phases(steps):
    seen = []
    for st in steps:
        if st["phase"] not in seen:
            seen.append(st["phase"])
    return [p for p in PHASES if p in seen]


def _public_playbook(spec, source, valid=True, error=None):
    return {
        "id": spec["id"], "name": spec["name"],
        "description": spec.get("description", ""),
        "steps": spec.get("steps", []),
        "phases": _derive_phases(spec.get("steps", [])),
        "source": source, "valid": valid, "error": error,
        "active_steps": sum(1 for s in spec.get("steps", []) if s.get("active")),
    }


def _load_user_playbooks():
    """Read data/engagement_playbooks/*.json. Returns list of _public_playbook."""
    out = []
    try:
        files = sorted(f for f in os.listdir(PLAYBOOKS_DIR) if f.endswith(".json"))
    except OSError:
        return out
    for fn in files:
        path = os.path.join(PLAYBOOKS_DIR, fn)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception as e:
            out.append({"id": _slugify(fn[:-5]), "name": fn, "description": "",
                        "steps": [], "phases": [], "source": "user",
                        "valid": False, "error": f"Invalid JSON: {e}", "active_steps": 0,
                        "file": fn})
            continue
        if "id" not in raw:
            raw["id"] = fn[:-5]
        norm, err = _validate_playbook(raw)
        if err:
            out.append({"id": _slugify(raw.get("id") or fn[:-5]),
                        "name": raw.get("name") or fn, "description": raw.get("description", ""),
                        "steps": raw.get("steps", []) if isinstance(raw.get("steps"), list) else [],
                        "phases": [], "source": "user", "valid": False, "error": err,
                        "active_steps": 0, "file": fn})
        else:
            pub = _public_playbook(norm, "user")
            pub["file"] = fn
            out.append(pub)
    return out


def list_playbooks():
    """Built-in + user playbooks, each tagged with source/validity for the UI."""
    pbs = [_public_playbook(p, "builtin") for p in BUILTIN_PLAYBOOKS.values()]
    pbs += _load_user_playbooks()
    return pbs


def _resolve_playbook(playbook_id):
    """Return a runnable, validated spec {id,name,steps} or None."""
    if playbook_id in BUILTIN_PLAYBOOKS:
        return BUILTIN_PLAYBOOKS[playbook_id]
    for pub in _load_user_playbooks():
        if pub["id"] == playbook_id and pub["valid"]:
            return {"id": pub["id"], "name": pub["name"],
                    "description": pub["description"], "steps": pub["steps"]}
    return None


def list_action_catalog():
    """Describe the action catalog + allowlisted tools (for the authoring UI)."""
    return {
        "actions": [
            {"action": "nmap", "phase": "discovery",
             "params": {"ports": "top-100|top-1000|<portspec>", "service_version": "bool",
                        "default_scripts": "bool (safe NSE)", "timing": "T0-T5"}},
            {"action": "posture", "phase": "diagnostics",
             "params": {"custom_rules": "[{match,severity,title,ref}]"}},
            {"action": "nuclei", "phase": "assessment (active)",
             "params": {"severity": "[info..critical]", "tags": "[...]"}},
            {"action": "command", "phase": "any",
             "params": {"tool": "any installed security tool (allowlisted)", "args": "[str,...]",
                        "per_host": "bool", "per_target": "bool", "timeout": "seconds 10-3600 (default 900)"}},
            {"action": "report", "phase": "reporting", "params": {}},
        ],
        "tools": sorted(_ALLOWED_TOOLS),
        "active_tools": sorted(t for t, m in _ALLOWED_TOOLS.items() if m["active"]),
        "placeholders": ["{scope}", "{host}", "{hosts}", "{ports}", "{web_urls}"],
        "phases": [{"id": p, **PHASE_META[p]} for p in PHASES],
    }


# ── Run registry ─────────────────────────────────────────────────────────────
def _valid_scope(scope):
    return bool(scope) and bool(_SCOPE_RE.match(scope.strip()))


# A single target (one line of a targets file): an IP / CIDR / host, no spaces.
_TARGET_RE = re.compile(r"^[0-9A-Za-z._:/\-]{1,100}$")
_MAX_TARGETS = 4096


def _valid_target(t):
    return bool(t) and bool(_TARGET_RE.match(t.strip()))


def start_run(playbook_id, scope, enable_active=False, targets=None):
    """Kick off an engagement run in a background thread. Returns (run_id, err).
    Scope may be a single IP/CIDR/host (``scope``) or a list of them (``targets``,
    e.g. parsed from an uploaded targets file — one per line)."""
    if not is_enabled():
        return None, "Ulfberht engine is available only on the Ragnar OS Ulfberht image."
    spec = _resolve_playbook(playbook_id)
    if not spec:
        return None, "Unknown or invalid playbook."
    # Build the validated target list — an explicit list wins over the single scope.
    if isinstance(targets, list):
        tlist = [t.strip() for t in targets if isinstance(t, str) and _valid_target(t)]
    else:
        scope = (scope or "").strip()
        tlist = [scope] if _valid_scope(scope) else []
    if not tlist:
        return None, "Invalid or empty scope."
    tlist = tlist[:_MAX_TARGETS]
    scope_display = tlist[0] if len(tlist) == 1 else f"{len(tlist)} targets"
    run_id = uuid.uuid4().hex[:12]
    run = {
        "id": run_id,
        "playbook": spec["id"],
        "playbook_name": spec["name"],
        "steps": spec["steps"],
        "scope": scope_display,
        "targets": tlist,
        "enable_active": bool(enable_active),
        "status": "running",
        "phase": None,
        "phases_done": [],
        "started": time.time(),
        "finished": None,
        "hosts": [],
        "findings": [],
        "log": [],
        "report_md": "",
        "report_html": "",
    }
    with _lock:
        _runs[run_id] = run
    t = threading.Thread(target=_execute, args=(run,), daemon=True)
    t.start()
    return run_id, None


_RUN_SUMMARY_KEYS = ("id", "playbook_name", "scope", "status", "phase",
                     "started", "finished")
_PERSIST_KEYS = ("id", "playbook", "playbook_name", "scope", "targets",
                 "enable_active", "status", "phase", "phases_done", "started",
                 "finished", "hosts", "findings", "log", "report_md", "report_html")


def _persist_run(run_id):
    """Write a finished run to RUNS_DIR/<id>.json so history survives a restart."""
    try:
        with _lock:
            run = _runs.get(run_id)
            if not run:
                return
            data = {k: run.get(k) for k in _PERSIST_KEYS}
        os.makedirs(RUNS_DIR, exist_ok=True)
        tmp = os.path.join(RUNS_DIR, f".{run_id}.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, os.path.join(RUNS_DIR, f"{run_id}.json"))
    except Exception:
        pass


def _load_persisted_run(run_id):
    try:
        with open(os.path.join(RUNS_DIR, f"{run_id}.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _list_persisted():
    out = []
    try:
        files = os.listdir(RUNS_DIR)
    except OSError:
        return out
    for fn in files:
        if fn.endswith(".json"):
            d = _load_persisted_run(fn[:-5])
            if d:
                out.append(d)
    return out


def get_run(run_id):
    with _lock:
        run = _runs.get(run_id)
        if run:
            return dict(run)
    return _load_persisted_run(run_id)   # fall back to persisted history


def list_runs():
    seen = {}
    with _lock:
        for r in _runs.values():
            seen[r["id"]] = {k: r.get(k) for k in _RUN_SUMMARY_KEYS}
    for d in _list_persisted():           # add history not currently in memory
        if d.get("id") and d["id"] not in seen:
            seen[d["id"]] = {k: d.get(k) for k in _RUN_SUMMARY_KEYS}
    return sorted(seen.values(), key=lambda x: x.get("started") or 0, reverse=True)


def get_report(run_id, fmt="md"):
    run = get_run(run_id)
    if not run:
        return None
    return run.get("report_html") if fmt == "html" else run.get("report_md")


# ── Execution ─────────────────────────────────────────────────────────────────
def _log(run, msg):
    with _lock:
        _runs[run["id"]]["log"].append(f"{time.strftime('%H:%M:%S')}  {msg}")


def _set(run, **kw):
    with _lock:
        _runs[run["id"]].update(kw)


def _finding(run, severity, title, host, detail, ref="", remediation=""):
    with _lock:
        _runs[run["id"]]["findings"].append({
            "severity": severity, "title": title, "host": host,
            "detail": detail, "ref": ref, "remediation": remediation,
        })


def run_findings(run):
    with _lock:
        return list(_runs[run["id"]]["findings"])


def _mark_phase(run, phase):
    _set(run, phase=phase)
    _log(run, f"── {PHASE_META[phase]['name']} ({PHASE_META[phase]['nist']})")
    cur = get_run(run["id"])["phases_done"]
    if phase not in cur:
        _set(run, phases_done=cur + [phase])


def _execute(run):
    """Run the playbook's steps in order, grouped by phase in the log/report."""
    try:
        last_phase = None
        for step in run["steps"]:
            phase = step["phase"]
            if phase != last_phase:
                _mark_phase(run, phase)
                last_phase = phase
            action = step["action"]
            if step.get("active") and not run["enable_active"]:
                _log(run, f"skipped active step '{action}' — active testing not enabled (enable_attacks off).")
                continue
            try:
                _ACTIONS[action](run, step.get("params") or {})
            except Exception as e:
                _log(run, f"step '{action}' error: {e}")
        # Always finish with a report even if the playbook omitted one.
        if not get_run(run["id"])["report_md"]:
            _act_report(run, {})
        _set(run, status="completed", phase=None, finished=time.time())
    except Exception as e:  # never leave a run wedged in "running"
        _log(run, f"ERROR: {e}")
        _set(run, status="failed", finished=time.time())
    _persist_run(run["id"])   # engagement history survives a restart


# ── Target helpers ───────────────────────────────────────────────────────────
def _web_targets(run):
    out = []
    for h in get_run(run["id"])["hosts"]:
        for p in h["ports"]:
            if p["service"] in ("http", "https") or p["port"] in (80, 443, 8080, 8443, 8000, 8888):
                scheme = "https" if (p["service"] == "https" or p["port"] in (443, 8443)) else "http"
                out.append(f"{scheme}://{h['ip']}:{p['port']}")
    return out


def _host_ips(run):
    return [h["ip"] for h in get_run(run["id"])["hosts"]]


def _discovered_ports(run):
    ports = sorted({str(p["port"]) for h in get_run(run["id"])["hosts"] for p in h["ports"]})
    return ",".join(ports)


# ── Actions ──────────────────────────────────────────────────────────────────
def _act_nmap(run, params):
    nmap = shutil.which("nmap")
    if not nmap:
        _log(run, "nmap not found; discovery skipped.")
        return
    cmd = [nmap]
    if params.get("service_version", True):
        cmd.append("-sV")
    if params.get("default_scripts"):
        cmd.append("-sC")
    timing = str(params.get("timing", "T4"))
    if re.match(r"^T[0-5]$", timing):
        cmd.append("-" + timing)
    ports = str(params.get("ports", "top-100"))
    if ports == "top-100":
        cmd += ["--top-ports", "100"]
    elif ports == "top-1000":
        cmd += ["--top-ports", "1000"]
    elif _PORTSPEC_RE.match(ports):
        cmd += ["-p", ports]
    else:
        cmd += ["--top-ports", "100"]
    cmd += ["-oX", "-"] + run["targets"]   # nmap accepts multiple targets as argv
    _log(run, "nmap " + " ".join(cmd[1:]))
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3600)
        hosts = _parse_nmap_xml(proc.stdout.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        _log(run, "nmap timed out."); return
    except Exception as e:
        _log(run, f"nmap failed: {e}"); return
    # Merge into any hosts already discovered (ports deduped per host).
    existing = {h["ip"]: h for h in get_run(run["id"])["hosts"]}
    for h in hosts:
        if h["ip"] in existing:
            seen = {(p["port"], p["proto"]) for p in existing[h["ip"]]["ports"]}
            for p in h["ports"]:
                if (p["port"], p["proto"]) not in seen:
                    existing[h["ip"]]["ports"].append(p)
        else:
            existing[h["ip"]] = h
    merged = list(existing.values())
    _set(run, hosts=merged)
    _log(run, f"{len(merged)} live host(s), {sum(len(h['ports']) for h in merged)} open port(s).")


def _parse_nmap_xml(xml_text):
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for h in root.findall("host"):
        state = h.find("status")
        if state is not None and state.get("state") != "up":
            continue
        addr = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr"); break
        hn = h.find("hostnames/hostname")
        name = hn.get("name") if hn is not None else ""
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
            })
        if addr:
            hosts.append({"ip": addr, "name": name, "ports": ports})
    return hosts


def _act_posture(run, params):
    custom = params.get("custom_rules") or []
    custom_map = {}
    for r in custom:
        if isinstance(r, dict) and r.get("match"):
            custom_map[str(r["match"]).lower()] = (
                r.get("severity", "medium"), r.get("title", f"Custom rule: {r['match']}"),
                r.get("ref", ""))
    n0 = len(run_findings(run))
    for h in get_run(run["id"])["hosts"]:
        for p in h["ports"]:
            key = p["service"] or _RISK_PORTS.get(p["port"], "")
            risk = _RISK_SERVICES.get(key) or custom_map.get(key) or custom_map.get(str(p["port"]))
            if risk:
                sev, title, ref = risk
                banner = " ".join(x for x in (p["product"], p["version"]) if x)
                detail = f"{p['port']}/{p['proto']} {key}" + (f" — {banner}" if banner else "")
                _finding(run, sev, title, h["ip"], detail, ref, _REMEDIATION.get(key, ""))
    _log(run, f"Posture analysis produced {len(run_findings(run)) - n0} finding(s).")


def _act_nuclei(run, params):
    nuclei = shutil.which("nuclei")
    web = _web_targets(run)
    if not web:
        _log(run, "No web services found to validate."); return
    if not nuclei:
        _log(run, "nuclei not installed; web assessment skipped."); return
    sev = params.get("severity") or ["medium", "high", "critical"]
    tags = params.get("tags") or []
    for target in web[:25]:
        cmd = [nuclei, "-u", target, "-silent", "-nc"]
        if sev:
            cmd += ["-severity", ",".join(s for s in sev if re.match(r"^[a-z]+$", str(s)))]
        if tags:
            cmd += ["-tags", ",".join(t for t in tags if re.match(r"^[a-z0-9,_-]+$", str(t)))]
        _log(run, "nuclei " + " ".join(cmd[1:]))
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=900)
            for line in proc.stdout.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if line:
                    _finding(run, "medium", "Nuclei match", target, line, "nuclei")
        except Exception as e:
            _log(run, f"nuclei failed on {target}: {e}")


def _expand_args(run, args, target=None):
    """Substitute placeholders; returns None if a placeholder yields nothing."""
    out = []
    for a in args:
        if a == "{scope}":
            out += run["targets"]
        elif a == "{host}":
            out.append(target or "")
        elif a == "{hosts}":
            out += _host_ips(run)
        elif a == "{ports}":
            out.append(_discovered_ports(run) or "1-1000")
        elif a == "{web_urls}":
            if target:
                out.append(target)
            else:
                out += _web_targets(run)
        else:
            out.append(a)
    return [x for x in out if x != ""]


def _act_command(run, params):
    tool = params.get("tool")
    meta = _ALLOWED_TOOLS.get(tool)
    if not meta:
        _log(run, f"command: tool '{tool}' not allowlisted; skipped."); return
    binpath = shutil.which(tool)
    if not binpath:
        _log(run, f"command: '{tool}' not installed; skipped."); return
    args = params.get("args", [])
    try:
        tmo = max(10, min(int(params.get("timeout", 900)), 3600))
    except (TypeError, ValueError):
        tmo = 900
    # Decide the iteration set for per-host / per-target steps.
    targets = [None]
    if params.get("per_host"):
        targets = _host_ips(run) or []
    elif params.get("per_target"):
        targets = _web_targets(run) or []
    if not targets:
        _log(run, f"command: no targets for {tool}; skipped."); return
    for tgt in targets[:25]:
        argv = _expand_args(run, args, tgt)
        if not argv:
            continue
        # Final safety sweep — no metacharacters survived substitution.
        if any(_ARG_BAD.search(a) for a in argv):
            _log(run, f"command: refusing unsafe args for {tool}."); continue
        _log(run, f"{tool} " + " ".join(argv))
        try:
            proc = subprocess.run([binpath] + argv, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=tmo)
            out = proc.stdout.decode("utf-8", "replace")
            lines = [l for l in out.splitlines() if l.strip()]
            tail = "\n".join(lines[-40:]) if lines else "(no output)"
            host = tgt or run["scope"]
            _finding(run, "info", f"{tool} output", host, tail[:4000], tool)
            _log(run, f"{tool} finished ({len(lines)} line(s)).")
        except subprocess.TimeoutExpired:
            _log(run, f"{tool} timed out.")
        except Exception as e:
            _log(run, f"{tool} failed: {e}")


def _sev_rank(s):
    return {"high": 0, "critical": 0, "medium": 1, "low": 2, "info": 3}.get(s, 4)


def _act_report(run, params):
    # mark reporting done before rendering so the report reflects itself
    cur = get_run(run["id"])["phases_done"]
    if "reporting" not in cur:
        _set(run, phases_done=cur + ["reporting"], phase="reporting")
    run = get_run(run["id"])  # snapshot with all findings + phases
    findings = sorted(run["findings"], key=lambda f: _sev_rank(f["severity"]))
    lines = []
    A = lines.append
    A(f"# Engagement Report — {run['playbook_name']}")
    A("")
    A(f"- **Scope:** `{run['scope']}`")
    if len(run.get("targets", [])) > 1:
        _tg = run["targets"]
        A("- **Targets:** " + ", ".join(f"`{t}`" for t in _tg[:50])
          + (f" … (+{len(_tg) - 50} more)" if len(_tg) > 50 else ""))
    A(f"- **Started:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(run['started']))}")
    A("- **Methodology:** NIST SP 800-115 (Discovery → Diagnostics → Assessment → Reporting)")
    A(f"- **Active validation:** {'enabled' if run['enable_active'] else 'not run (passive engagement)'}")
    A("")
    A("## Summary")
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    A(f"- Hosts live: **{len(run['hosts'])}**")
    A(f"- Findings: **{len(findings)}** "
      f"(high {counts.get('high',0)+counts.get('critical',0)}, "
      f"medium {counts.get('medium',0)}, low {counts.get('low',0)}, info {counts.get('info',0)})")
    A("")
    A("## Hosts & services")
    if run["hosts"]:
        A("| Host | Port | Service | Product/Version |")
        A("|------|------|---------|-----------------|")
        for h in run["hosts"]:
            for p in h["ports"]:
                pv = " ".join(x for x in (p["product"], p["version"]) if x)
                A(f"| {h['ip']}{(' ('+h['name']+')') if h['name'] else ''} | "
                  f"{p['port']}/{p['proto']} | {p['service']} | {pv} |")
    else:
        A("_No live hosts found in scope._")
    A("")
    A("## Findings")
    if findings:
        for f in findings:
            A(f"### [{f['severity'].upper()}] {f['title']} — {f['host']}")
            det = f["detail"]
            if "\n" in det:
                A("```"); A(det); A("```")
            else:
                A(f"- {det}")
            if f["ref"]:
                A(f"- Reference: {f['ref']}")
            if f.get("remediation"):
                A(f"- **Remediation:** {f['remediation']}")
            A("")
    else:
        A("_No posture findings. Scope looks clean for the checks run._")
    A("")
    A("## Phases executed")
    for ph in PHASES:
        done = "✓" if ph in run["phases_done"] else "—"
        A(f"- {done} **{PHASE_META[ph]['name']}** — {PHASE_META[ph]['nist']}")
    A("")
    A("---")
    A("_Ragnar OS Ulfberht — for authorized security testing only._")
    _set(run, report_md="\n".join(lines),
         report_html=_render_report_html(run, findings, counts))


def _risk_rating(counts):
    """Overall engagement risk rating from the finding severity counts."""
    if counts.get("critical") or counts.get("high"):
        return ("High", "#f87171")
    if counts.get("medium"):
        return ("Medium", "#fbbf24")
    if counts.get("low"):
        return ("Low", "#60a5fa")
    return ("Informational", "#4ade80")


def _render_report_html(run, findings, counts):
    """A self-contained, printable (→ PDF) HTML engagement report."""
    e = html.escape
    sev_color = {"critical": "#dc2626", "high": "#ef4444", "medium": "#f59e0b",
                 "low": "#3b82f6", "info": "#6b7280"}
    rating, rating_col = _risk_rating(counts)
    high = counts.get("high", 0) + counts.get("critical", 0)
    started = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(run['started']))
    out = []
    A = out.append
    A("<!doctype html><html lang=en><head><meta charset=utf-8>")
    A("<meta name=viewport content='width=device-width,initial-scale=1'>")
    A(f"<title>Engagement Report — {e(run['playbook_name'])}</title>")
    A("""<style>
*{box-sizing:border-box} body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
color:#1e293b;background:#f8fafc;margin:0;padding:32px;max-width:960px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 10px;border-bottom:2px solid #e2e8f0;padding-bottom:6px}
.sub{color:#64748b;font-size:13px;margin-bottom:18px}
.kpis{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}
.kpi{flex:1;min-width:120px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px}
.kpi .n{font-size:22px;font-weight:700} .kpi .l{color:#64748b;font-size:12px}
.rating{display:inline-block;padding:4px 12px;border-radius:999px;color:#fff;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:13px;margin:6px 0 }
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #e2e8f0;vertical-align:top}
th{background:#f1f5f9;font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:#475569}
.f{background:#fff;border:1px solid #e2e8f0;border-left-width:5px;border-radius:8px;padding:12px 14px;margin:10px 0}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:11px;font-weight:700;vertical-align:middle}
.rem{background:#ecfdf5;border:1px solid #a7f3d0;border-radius:6px;padding:8px 10px;margin-top:8px;font-size:13px}
.rem b{color:#047857} code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow:auto;white-space:pre-wrap}
.muted{color:#64748b} .foot{margin-top:28px;color:#94a3b8;font-size:12px;border-top:1px solid #e2e8f0;padding-top:12px}
@media print{body{padding:0;background:#fff}.kpi,.f,table{break-inside:avoid}}
</style></head><body>""")
    A(f"<h1>Engagement Report</h1>")
    A(f"<div class=sub>{e(run['playbook_name'])} &middot; scope <code>{e(run['scope'])}</code> &middot; {e(started)} "
      f"&middot; active validation: {'enabled' if run['enable_active'] else 'not run (passive)'}</div>")
    # executive summary
    A("<h2>Executive summary</h2>")
    A(f"<p>Overall risk: <span class=rating style='background:{rating_col}'>{rating}</span>. "
      f"The engagement swept <b>{e(run['scope'])}</b> and found <b>{len(run['hosts'])}</b> live host(s) "
      f"and <b>{len(findings)}</b> finding(s) across the exposed services, following the NIST SP 800-115 "
      f"methodology (discovery → diagnostics → assessment → reporting).</p>")
    A("<div class=kpis>")
    A(f"<div class=kpi><div class=n>{len(run['hosts'])}</div><div class=l>Live hosts</div></div>")
    A(f"<div class=kpi><div class=n style='color:#ef4444'>{high}</div><div class=l>High / Critical</div></div>")
    A(f"<div class=kpi><div class=n style='color:#f59e0b'>{counts.get('medium',0)}</div><div class=l>Medium</div></div>")
    A(f"<div class=kpi><div class=n style='color:#3b82f6'>{counts.get('low',0)}</div><div class=l>Low</div></div>")
    A(f"<div class=kpi><div class=n class=muted>{counts.get('info',0)}</div><div class=l>Informational</div></div>")
    A("</div>")
    # targets (if a list)
    if len(run.get("targets", [])) > 1:
        A("<h2>Targets</h2><p class=muted>" + ", ".join(f"<code>{e(t)}</code>" for t in run["targets"][:100])
          + (f" … (+{len(run['targets'])-100} more)" if len(run["targets"]) > 100 else "") + "</p>")
    # hosts & services
    A("<h2>Hosts &amp; services</h2>")
    if run["hosts"]:
        A("<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Product / version</th></tr>")
        for h in run["hosts"]:
            for p in h["ports"]:
                pv = e(" ".join(x for x in (p["product"], p["version"]) if x))
                hn = f" ({e(h['name'])})" if h["name"] else ""
                A(f"<tr><td>{e(h['ip'])}{hn}</td><td>{p['port']}/{e(p['proto'])}</td>"
                  f"<td>{e(p['service'])}</td><td>{pv}</td></tr>")
        A("</table>")
    else:
        A("<p class=muted>No live hosts found in scope.</p>")
    # findings
    A("<h2>Findings</h2>")
    if findings:
        for f in findings:
            col = sev_color.get(f["severity"], "#6b7280")
            A(f"<div class=f style='border-left-color:{col}'>")
            A(f"<div><span class=badge style='background:{col}'>{e(f['severity'].upper())}</span> "
              f"<b>{e(f['title'])}</b> <span class=muted>— {e(f['host'])}</span></div>")
            det = f["detail"]
            if "\n" in det:
                A(f"<pre>{e(det)}</pre>")
            else:
                A(f"<div style='margin-top:6px'>{e(det)}</div>")
            if f.get("ref"):
                A(f"<div class=muted style='margin-top:4px;font-size:12px'>Reference: {e(f['ref'])}</div>")
            if f.get("remediation"):
                A(f"<div class=rem><b>Remediation:</b> {e(f['remediation'])}</div>")
            A("</div>")
    else:
        A("<p class=muted>No posture findings. Scope looks clean for the checks run.</p>")
    # phases
    A("<h2>Methodology — phases executed</h2><table><tr><th></th><th>Phase</th><th>Standard</th></tr>")
    for ph in PHASES:
        done = "✓" if ph in run["phases_done"] else "—"
        A(f"<tr><td>{done}</td><td>{e(PHASE_META[ph]['name'])}</td><td class=muted>{e(PHASE_META[ph]['nist'])}</td></tr>")
    A("</table>")
    A("<div class=foot>Generated by <b>Ragnar OS Ulfberht</b> — for authorized security testing only.</div>")
    A("</body></html>")
    return "\n".join(out)


_ACTIONS = {
    "nmap": _act_nmap,
    "posture": _act_posture,
    "nuclei": _act_nuclei,
    "command": _act_command,
    "report": _act_report,
}
_DEFAULT_PHASE = {"nmap": "discovery", "posture": "diagnostics",
                  "nuclei": "assessment", "command": "assessment", "report": "reporting"}


# ── Playbook file management (for the Files tab / upload API) ─────────────────
def _safe_pb_name(name):
    base = os.path.basename(str(name or "")).strip()
    if not base.endswith(".json"):
        base += ".json"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return base if base != ".json" else ""


def save_playbook(name, content):
    """Create/overwrite a user playbook .json. content is a JSON string or dict.
    Returns {success, error?, id?, file?, warning?}."""
    fn = _safe_pb_name(name)
    if not fn:
        return {"success": False, "error": "Invalid playbook name."}
    if isinstance(content, (dict, list)):
        raw = content
    else:
        try:
            raw = json.loads(content)
        except Exception as e:
            return {"success": False, "error": f"Not valid JSON: {e}"}
    norm, err = _validate_playbook(raw if isinstance(raw, dict) else {})
    # We still save an invalid playbook so the operator can fix it in Files, but
    # report the validation error so the UI can warn.
    os.makedirs(PLAYBOOKS_DIR, exist_ok=True)
    path = os.path.join(PLAYBOOKS_DIR, fn)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, indent=2)
    except Exception as e:
        return {"success": False, "error": str(e)}
    res = {"success": True, "file": fn, "id": _slugify((raw.get("id") if isinstance(raw, dict) else None) or fn[:-5])}
    if err:
        res["warning"] = err
    return res


# ── Arsenal → playbook builder ──────────────────────────────────────────────
# Sensible starting steps per tool, so selecting tools in the Pentest-tab
# Arsenal generates a runnable, methodology-ordered playbook. Everything is a
# starting point the operator refines in the Files tab. Keyed by tool binary;
# (phase, action, params). Tools without a template get a generic command step
# targeting {scope} that the operator must edit (Wi-Fi / cracking / interactive
# tools especially — they need a capture, a wordlist, or non-interactive args).
_TOOL_STEP_TEMPLATES = {
    # ── discovery / recon ────────────────────────────────────────────────────
    "nmap":          ("discovery",  "nmap",    {"ports": "top-100", "service_version": True}),
    "masscan":       ("discovery",  "command", {"tool": "masscan", "args": ["-p1-1000", "--rate", "1000", "{scope}"]}),
    "arp-scan":      ("discovery",  "command", {"tool": "arp-scan", "args": ["{scope}"]}),
    "fping":         ("discovery",  "command", {"tool": "fping", "args": ["-a", "-g", "{scope}"]}),
    "nbtscan":       ("discovery",  "command", {"tool": "nbtscan", "args": ["{scope}"]}),
    "dig":           ("discovery",  "command", {"tool": "dig", "args": ["{scope}"]}),
    "host":          ("discovery",  "command", {"tool": "host", "args": ["{host}"], "per_host": True}),
    "whois":         ("discovery",  "command", {"tool": "whois", "args": ["{scope}"]}),
    "whatweb":       ("diagnostics", "command", {"tool": "whatweb", "args": ["--no-errors", "{web_urls}"], "per_target": True}),
    # ── web / service validation ─────────────────────────────────────────────
    "nuclei":        ("assessment", "nuclei",  {"severity": ["medium", "high", "critical"]}),
    "nikto":         ("assessment", "command", {"tool": "nikto", "args": ["-ask", "no", "-nointeractive", "-host", "{web_urls}"], "per_target": True}),
    "sqlmap":        ("assessment", "command", {"tool": "sqlmap", "args": ["-u", "{web_urls}", "--batch", "--crawl=1"], "per_target": True}),
    "wpscan":        ("assessment", "command", {"tool": "wpscan", "args": ["--url", "{web_urls}", "--no-banner"], "per_target": True}),
    "gobuster":      ("assessment", "command", {"tool": "gobuster", "args": ["dir", "-u", "{web_urls}", "-w", "/usr/share/wordlists/dirb/common.txt"], "per_target": True}),
    "ffuf":          ("assessment", "command", {"tool": "ffuf", "args": ["-u", "{web_urls}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt"], "per_target": True}),
    "feroxbuster":   ("assessment", "command", {"tool": "feroxbuster", "args": ["-u", "{web_urls}"], "per_target": True}),
    "sslscan":       ("assessment", "command", {"tool": "sslscan", "args": ["{web_urls}"], "per_target": True}),
    "sslyze":        ("assessment", "command", {"tool": "sslyze", "args": ["{web_urls}"], "per_target": True}),
    "testssl.sh":    ("assessment", "command", {"tool": "testssl.sh", "args": ["{web_urls}"], "per_target": True}),
    # ── SMB / AD / network services ──────────────────────────────────────────
    "enum4linux-ng": ("assessment", "command", {"tool": "enum4linux-ng", "args": ["-A", "{host}"], "per_host": True}),
    "enum4linux":    ("assessment", "command", {"tool": "enum4linux", "args": ["-a", "{host}"], "per_host": True}),
    "smbclient":     ("assessment", "command", {"tool": "smbclient", "args": ["-L", "{host}", "-N"], "per_host": True}),
    "netexec":       ("assessment", "command", {"tool": "netexec", "args": ["smb", "{host}"], "per_host": True}),
    "nxc":           ("assessment", "command", {"tool": "nxc", "args": ["smb", "{host}"], "per_host": True}),
    "snmpwalk":      ("assessment", "command", {"tool": "snmpwalk", "args": ["-v2c", "-c", "public", "{host}"], "per_host": True}),
    "onesixtyone":   ("assessment", "command", {"tool": "onesixtyone", "args": ["{host}"], "per_host": True}),
    # ── credentials / cracking (need a hash file + wordlist — edit the paths) ─
    "hydra":         ("assessment", "command", {"tool": "hydra", "args": ["-L", "/usr/share/wordlists/metasploit/unix_users.txt", "-P", "/usr/share/wordlists/rockyou.txt", "-t", "4", "-f", "{host}", "ssh"], "per_host": True, "timeout": 1200}),
    "hashcat":       ("assessment", "command", {"tool": "hashcat", "args": ["-m", "0", "-a", "0", "/root/engagement/hashes.txt", "/usr/share/wordlists/rockyou.txt"], "timeout": 1800}),
    "john":          ("assessment", "command", {"tool": "john", "args": ["--wordlist=/usr/share/wordlists/rockyou.txt", "/root/engagement/hashes.txt"], "timeout": 1800}),
    # ── wireless (need a monitor-mode interface / a capture — edit these) ─────
    "airodump-ng":   ("discovery",  "command", {"tool": "airodump-ng", "args": ["wlan1mon"], "timeout": 120}),
    "aircrack-ng":   ("assessment", "command", {"tool": "aircrack-ng", "args": ["-w", "/usr/share/wordlists/rockyou.txt", "/root/engagement/capture.cap"], "timeout": 1800}),
    "wifite":        ("assessment", "command", {"tool": "wifite", "args": ["-i", "wlan1mon", "--kill"], "timeout": 600}),
    "reaver":        ("assessment", "command", {"tool": "reaver", "args": ["-i", "wlan1mon", "-b", "AA:BB:CC:DD:EE:FF", "-vv"], "timeout": 1200}),
    "bully":         ("assessment", "command", {"tool": "bully", "args": ["wlan1mon", "-b", "AA:BB:CC:DD:EE:FF"], "timeout": 1200}),
    "kismet":        ("discovery",  "command", {"tool": "kismet", "args": ["-c", "wlan1mon"], "timeout": 120}),
    # ── framework / MITM / capture (interactive or long-running) ─────────────
    "responder":     ("assessment", "command", {"tool": "responder", "args": ["-I", "eth0", "-A"], "timeout": 120}),
    "msfconsole":    ("assessment", "command", {"tool": "msfconsole", "args": ["-q", "-r", "/root/engagement/msf.rc"], "timeout": 1200}),
    "ettercap":      ("assessment", "command", {"tool": "ettercap", "args": ["-T", "-q", "-i", "eth0", "-M", "arp", "//", "//"], "timeout": 120}),
    "tcpdump":       ("discovery",  "command", {"tool": "tcpdump", "args": ["-i", "eth0", "-c", "200", "-w", "/root/engagement/capture.pcap"], "timeout": 120}),
    "tshark":        ("discovery",  "command", {"tool": "tshark", "args": ["-i", "eth0", "-c", "200"], "timeout": 120}),
}

# Tools whose generated step needs the operator to supply input before it will
# run (wordlist, hash file, capture, monitor interface, resource script). Flagged
# in the generated playbook's description so the starter is honest about them.
_TOOLS_NEED_INPUT = {
    "hydra": "a userlist / passlist + the right service",
    "hashcat": "a hash file + hash mode",
    "john": "a hash file",
    "aircrack-ng": "a .cap capture",
    "airodump-ng": "a monitor-mode interface",
    "wifite": "a monitor-mode interface",
    "reaver": "a monitor-mode interface + target BSSID",
    "bully": "a monitor-mode interface + target BSSID",
    "kismet": "a capture interface",
    "responder": "the right interface",
    "msfconsole": "a .rc resource script",
    "setoolkit": "interactive — not suited to unattended runs",
    "ettercap": "the right interface + MITM targets",
    "tcpdump": "the right interface",
    "tshark": "the right interface",
}

# Coarse category per tool — drives the generated playbook's description so it
# reads like a focused engagement, not a generic tool dump.
_TOOL_CATEGORY = {
    "nuclei": "web", "nikto": "web", "wpscan": "web", "sqlmap": "web",
    "gobuster": "web", "ffuf": "web", "feroxbuster": "web", "whatweb": "web",
    "sslscan": "web", "sslyze": "web", "testssl.sh": "web",
    "enum4linux": "SMB/AD", "enum4linux-ng": "SMB/AD", "smbclient": "SMB/AD",
    "netexec": "SMB/AD", "nxc": "SMB/AD", "responder": "SMB/AD",
    "hydra": "credential", "hashcat": "password-cracking", "john": "password-cracking",
    "aircrack-ng": "wireless", "airodump-ng": "wireless", "wifite": "wireless",
    "reaver": "wireless", "bully": "wireless", "kismet": "wireless",
    "nmap": "network", "masscan": "network", "arp-scan": "network",
    "fping": "network", "nbtscan": "network", "dig": "network", "host": "network",
    "whois": "network", "snmpwalk": "network", "onesixtyone": "network",
    "msfconsole": "exploitation", "setoolkit": "social-engineering",
    "ettercap": "MITM", "tcpdump": "capture", "tshark": "capture",
}


def _describe_selection(tools):
    """A category-aware description + a 'needs input' note for a tool selection."""
    cats = []
    for t in tools:
        c = _TOOL_CATEGORY.get(t)
        if c and c not in cats:
            cats.append(c)
    lead = (", ".join(cats[:-1]) + " & " + cats[-1]) if len(cats) > 1 else (cats[0] if cats else "mixed")
    lead = lead[:1].upper() + lead[1:]   # capitalize first letter only (keep SMB/AD, MITM)
    desc = (f"{lead} engagement built from the Arsenal ({', '.join(tools)}). "
            f"Flow: nmap discovery → the selected tools → posture → report. "
            f"Review the tool args before running.")
    need = [f"{t} ({_TOOLS_NEED_INPUT[t]})" for t in tools if t in _TOOLS_NEED_INPUT]
    if need:
        desc += "  ⚠ Edit before running: " + "; ".join(need) + "."
    return desc


def suggest_step(tool):
    """Return a starting playbook step for a tool binary."""
    tmpl = _TOOL_STEP_TEMPLATES.get(tool)
    if tmpl:
        phase, action, params = tmpl
        step = {"phase": phase, "action": action, "params": dict(params)}
    else:
        # No template (Wi-Fi/cracking/interactive/unknown) — a safe editable
        # placeholder confined to {scope}; the operator fills in real args.
        step = {"phase": "assessment", "action": "command",
                "params": {"tool": tool, "args": ["{scope}"]}}
    if _ALLOWED_TOOLS.get(tool, {}).get("active"):
        step["active"] = True
    return step


def build_playbook_spec(name, tools, description=None):
    """Assemble a methodology-ordered playbook spec from tool binaries (as picked
    in the Arsenal) WITHOUT saving — for the editor preview. Returns (spec, error).
    Always includes an nmap discovery sweep (so {host}/{web_urls}/{ports} resolve),
    a posture pass, and a report."""
    tools = [t for t in (tools or []) if t in _ALLOWED_TOOLS]
    if not name:
        return None, "Playbook needs a name."
    if not tools:
        return None, "Select at least one tool."
    steps = []
    if "nmap" not in tools:   # ensure discovery populates the target placeholders
        steps.append({"phase": "discovery", "action": "nmap",
                      "params": {"ports": "top-100", "service_version": True}})
    for t in tools:
        steps.append(suggest_step(t))
    steps.append({"phase": "diagnostics", "action": "posture"})
    steps.append({"phase": "reporting", "action": "report"})
    order = {p: i for i, p in enumerate(PHASES)}
    steps.sort(key=lambda s: order.get(s["phase"], 2))   # stable → methodology order
    spec = {
        "id": _slugify(name), "name": name,
        "description": description or _describe_selection(tools),
        "steps": steps,
    }
    return spec, None


def build_playbook_from_tools(name, tools, description=None):
    """Build the spec from tools and save it (one-shot, no editor step)."""
    spec, err = build_playbook_spec(name, tools, description)
    if err:
        return {"success": False, "error": err}
    return save_playbook(name, spec)


_AI_INSTRUCTION_MAX = 2000


def build_ai_prompt(name, tools, instruction):
    """Return (prompt, error): a complete, copy-pasteable prompt the operator feeds
    to their OWN AI (Claude / ChatGPT / a local model) to author an Engagements
    playbook from a free-text instruction plus the tools picked in the Arsenal.

    No AI runs on the device — Ragnar only *builds the prompt* (offline, no key),
    embedding the exact schema, the action catalog, the tool allowlist and the
    argv/no-shell safety rules so whatever the AI returns passes validation. The
    operator pastes the AI's JSON back into the editor to validate and save."""
    tools = [t for t in (tools or []) if t in _ALLOWED_TOOLS]
    instruction = (instruction or "").strip()[:_AI_INSTRUCTION_MAX]
    if not instruction and not tools:
        return None, "Describe what you want, or select at least one tool."

    cat = list_action_catalog()
    action_lines = []
    for a in cat["actions"]:
        params = ", ".join(f"{k}: {v}" for k, v in a["params"].items()) or "(none)"
        action_lines.append(f'  - "{a["action"]}" (phase {a["phase"]}): {params}')
    example = {
        "name": "Example — Web Triage",
        "description": "Discover web services, fingerprint them, validate with nuclei.",
        "steps": [
            {"phase": "discovery", "action": "nmap",
             "params": {"ports": "80,443,8080,8443", "service_version": True}},
            {"phase": "diagnostics", "action": "posture"},
            {"phase": "diagnostics", "action": "command",
             "params": {"tool": "whatweb", "args": ["--no-errors", "{web_urls}"], "per_target": True}},
            {"phase": "assessment", "action": "nuclei",
             "params": {"severity": ["medium", "high", "critical"]}, "active": True},
            {"phase": "reporting", "action": "report"},
        ],
    }
    lines = [
        "You are a senior penetration tester authoring an \"Engagement playbook\" for",
        "Ragnar OS Ulfberht. Produce ONE JSON object and nothing else — no prose, no",
        "explanation, no markdown code fences.",
        "",
        "OPERATOR'S GOAL:",
        (instruction or "(none given — design a sensible engagement for the selected tools)"),
        "",
        "TOOLS THE OPERATOR SELECTED (prefer these; you may add allowlisted recon/support steps):",
        ("  " + ", ".join(tools)) if tools else "  (none selected — choose appropriate allowlisted tools)",
        "",
        "OUTPUT SCHEMA (exact):",
        '  {"name": "<short title>", "description": "<1-2 sentences>", "steps": [ <step>, ... ]}',
        '  step = {"phase": <phase>, "action": <action>, "params": {...}, "active": <bool, optional>}',
        "",
        "PHASES (NIST SP 800-115 order — order your steps this way):",
        "  discovery -> diagnostics -> assessment -> reporting",
        "  The assessment phase is the only active one (set \"active\": true on active steps).",
        "",
        "ACTIONS and their params:",
        *action_lines,
        "",
        "PLACEHOLDERS (substituted at run time, confined to the engagement scope — use",
        "these, do NOT hardcode targets): " + " ".join(cat["placeholders"]),
        "  Use {host} with \"per_host\": true to iterate discovered hosts, and {web_urls}",
        "  with \"per_target\": true to iterate discovered web URLs.",
        "",
        "HARD RULES (a playbook that breaks these is rejected):",
        "  1. Start with an nmap discovery step so {host}/{web_urls}/{ports} resolve,",
        "     unless the goal is purely wireless/offline.",
        "  2. \"command\" steps run as an argv list, NEVER through a shell. Each arg is a",
        "     string. These characters are FORBIDDEN in any arg:  ; & | < > $ ` \\ \" '  and newlines.",
        "     No pipes, redirects, command chaining, globbing or sub-shells.",
        "  3. \"tool\" MUST be one of the allowlisted tools below — or best fit.",
        "  4. End with a {\"phase\": \"reporting\", \"action\": \"report\"} step.",
        "  5. Output valid JSON only.",
        "",
        "ALLOWLISTED TOOLS:",
        "  " + ", ".join(cat["tools"]),
        "",
        "EXAMPLE of a valid playbook:",
        json.dumps(example, indent=2),
        "",
        "Now output the JSON playbook for the operator's goal.",
    ]
    prompt = "\n".join(lines)
    if name:
        prompt = prompt.replace('"<short title>"', json.dumps(str(name)[:120]))
    return prompt, None


def delete_playbook(playbook_id):
    for pub in _load_user_playbooks():
        if pub["id"] == playbook_id or pub.get("file") == playbook_id:
            try:
                os.remove(os.path.join(PLAYBOOKS_DIR, pub["file"]))
                return {"success": True}
            except Exception as e:
                return {"success": False, "error": str(e)}
    return {"success": False, "error": "No such user playbook."}


def ensure_examples():
    """Drop a commented example playbook on first use so operators have a
    template in the Files tab. Never overwrites."""
    try:
        os.makedirs(PLAYBOOKS_DIR, exist_ok=True)
        ex = os.path.join(PLAYBOOKS_DIR, "example-quick-triage.json")
        if not os.path.exists(ex) and not os.listdir(PLAYBOOKS_DIR):
            with open(ex, "w", encoding="utf-8") as fh:
                json.dump({
                    "id": "example-quick-triage",
                    "name": "Example — Quick Triage",
                    "description": "Top-100 sweep + posture + a safe whatweb pass. Copy and edit me.",
                    "steps": [
                        {"phase": "discovery", "action": "nmap",
                         "params": {"ports": "top-100", "service_version": True}},
                        {"phase": "diagnostics", "action": "posture"},
                        {"phase": "diagnostics", "action": "command",
                         "params": {"tool": "whatweb", "args": ["--no-errors", "{web_urls}"]}},
                        {"phase": "reporting", "action": "report"},
                    ],
                }, fh, indent=2)
    except Exception:
        pass


if __name__ == "__main__":
    import sys
    os.environ.setdefault("RAGNAR_EDITION", "ulfberht")  # dev test
    if ragnar_edition:
        ragnar_edition._cache = None
    pb = sys.argv[1] if len(sys.argv) > 1 else "scoped-network-assessment"
    scope = os.environ.get("ULF_SCOPE", "127.0.0.1")
    rid, err = start_run(pb, scope, enable_active=("--active" in sys.argv))
    if err:
        print("error:", err); raise SystemExit(1)
    while True:
        r = get_run(rid)
        if r["status"] != "running":
            break
        time.sleep(1)
    print(json.dumps({"status": r["status"], "hosts": r["hosts"],
                      "findings": r["findings"], "log": r["log"]}, indent=2))
    print("\n----- REPORT -----\n")
    print(get_report(rid))
