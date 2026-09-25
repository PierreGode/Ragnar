# Scanning & Attacks — the core loop

Ragnar's heart is the autonomous scan-and-act loop it inherits from
[Bjorn](https://github.com/infinition/Bjorn) and extends. On the **Network** tab
the box discovers hosts, assesses them, and — when explicitly enabled — runs
offensive modules against the ones that look vulnerable, logging everything as it
goes.

> **For educational and authorized testing only.** The offensive modules
> (brute-force, file extraction) act against live services. Only point Ragnar at
> networks and hosts you own or are authorized to test.

---

## Network scanning

Identifies live hosts and open ports and records them in the hosts database.
Passive discovery feeds the same table — hosts that never answer an active scan
still show up if [Traffic Analysis](traffic-analysis.md) sees them on the wire.

- **Per-host Ignore** — each row on the Network tab has an **Ignore** button that
  excludes a MAC/IP from future scans and automated actions. The master switch
  ("Honor Scan Blacklists") lives in Settings.
- Results and every nmap invocation are logged (see **Logging** below).

## Vulnerability assessment

Scans discovered hosts with **Nmap** and companion tools, mapping open services
to known weaknesses. Findings are correlated against live threat intelligence
(below) so a result carries CVE / exploit context, not just a version string.

For the deeper web-application scanners (Nuclei, Nikto, SQLMap, WhatWeb, OWASP
ZAP) see [Advanced Vulnerability Scanning](adv-scan.md).

## Multi-source threat intelligence

Real-time fusion from **CISA KEV**, **NVD CVE**, **AlienVault OTX**, and **MITRE
ATT&CK**, surfaced on the dashboard and used to prioritize findings. For host/IP
attribution (geo, ASN, reputation) see [IP Attribution](ip-intel.md).

## AI-powered analysis

Optional LLM assistance turns raw findings into security summaries, prioritized
remediation, and plain-language explanations. Works with hosted models or
**self-hosted / OpenAI-compatible** endpoints (Ollama, LocalAI, vLLM, LM Studio)
so inference can stay on hardware you control. See
[AI Integration](AI_INTEGRATION.md).

## System attacks (brute force)

Credential attacks against common services: **FTP, SSH, SMB, RDP, Telnet, SQL**.
Off unless enabled, and governed by the same scan blacklist as everything else.

## File stealing

Extracts data from services that authentication attacks open up, storing what it
retrieves for review in the web UI.

## Logging

Every nmap command and its results are written to `data/logs/nmap.log`, so a run
is fully auditable after the fact.

---

## Related

- [Advanced Vulnerability Scanning](adv-scan.md) — Nuclei / Nikto / SQLMap / ZAP, mesh delegation, RAM gating
- [Traffic Analysis](traffic-analysis.md) — passive host discovery + C2 / scan / tunnel detection
- [Authority Verification & network tools](nettools.md) — the detection-only L2→L7 watcher suite
- [Asset Inventory & change detection](asset-inventory.md) — turns the hosts table into a living inventory
