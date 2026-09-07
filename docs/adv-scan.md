# Advanced Vulnerability Scanning (Adv Scan tab)

The **Adv Scan** tab runs deeper web-application and vulnerability scanners on top
of the [core scan loop](scanning-and-attacks.md). Most of it runs on **any board
that has `nmap`** — only OWASP ZAP and parallel scanning need a server-class box.

---

## What runs where

The tab is **no longer 8GB-only.** The CLI scanners — **Nuclei, Nikto, SQLMap,
WhatWeb** and **Nmap vuln scripts** — are light enough to run anywhere `nmap` is
installed, so the tab shows up on every board.

- **OWASP ZAP** is the sole exception: its Java daemon holds ~1GB+ resident, so it
  stays gated at **8GB+ RAM** and greys out below that while the rest of the tab
  keeps working. **Parallel scanning** is likewise an 8GB+ feature.
- **Nuclei is gated at 900MB RAM** — it loads a heavy template engine that would
  OOM a 512MB Pi Zero 2 W, so it greys out below its floor (a 1GB Pi 3 runs it
  fine). From 900MB up it **auto-tunes to the board's RAM**: lower concurrency, a
  capped Go heap and high/critical-only templates on 1–2GB boards, full tilt on
  big ones. On constrained boards it **refuses to start when free RAM is already
  too low** (reporting how much is free) rather than risk a lock-up, and where the
  kernel memory cgroup is enabled it wraps nuclei in a **hard memory cap**
  (`systemd-run`, swap off) — enable it with `cgroup_enable=memory
  cgroup_memory=1` in `/boot/firmware/cmdline.txt` + reboot.

## Mesh delegation

A gated scanner isn't a dead end. When any **mesh** unit can run it, the scan is
**transparently delegated** to that peer and its live progress + findings relay
back into the local scan view — a small "🛰️ Mesh ready — Nuclei → ylva" flag shows
who's handling it. Discovery / auto-pick / relay ride the existing Tailscale
peer-identity auth. (Needs 2+ units; a single-unit board just sees the normal
grey-out.) See [Ragnar Mesh](mesh.md).

---

## Scanners & features

- **Pre-flight recon** — optional phase before ZAP: **port discovery** (parallel
  TCP connect-scan of common web ports, each classified http/https via a TLS
  probe), TLS audit, passive DNS subdomain enumeration, and HTTP content
  discovery. In the handoff gate the operator ticks exactly which discovered
  `scheme://host:port` URLs, subdomains and paths get fed to ZAP — so a bare IP is
  scanned on the ports *actually* listening instead of defaulting to :80/:443.
- **OWASP ZAP** *(8GB+ RAM)* — spider + AJAX spider + active scan with automatic
  browser detection. Given a bare host with no port, ZAP probes common web ports
  and scans whichever is listening (HTTPS-only / alt-port included); the same
  auto-resolution applies to delegated mesh scans (the probe runs from the
  delegate's vantage).
- **Authenticated scanning** — 8 auth types: form-based, HTTP Basic, OAuth2,
  Bearer Token, API Key, Cookie, Script-based.
- **Nuclei** — 5000+ templates from ProjectDiscovery; if the binary isn't present
  the card shows a **⤓ Install** button that fetches the right build for your
  board (templates download automatically after).
- **Nikto** — comprehensive web-server assessment.
- **SQLMap** — automated SQL-injection detection.
- **WhatWeb** — web technology fingerprinting.
- **Parallel scanning** *(8GB+ RAM)* — multi-threaded for faster results.
- **CVE correlation** — automatic correlation with NVD, CISA KEV, and threat feeds.
- **Live progress** — real-time log panel and animated progress bar.
- **Web and API modes** — scan web apps or API endpoints with OpenAPI spec import.

---

## Installation

Fresh installs with 8GB+ RAM get the advanced tools automatically. For an existing
install, run the advanced-tools installer:

```bash
cd /home/ragnar/Ragnar
sudo ./scripts/install_advanced_tools.sh
sudo systemctl restart ragnar
```

**What gets installed:**

- **Traffic tools**: tcpdump, tshark, ngrep, iftop, nethogs
- **Vulnerability scanners**: Nuclei, Nikto, SQLMap, WhatWeb
- **Web app security**: OWASP ZAP (requires Java)
- **Nmap scripts**: vulners.nse, vulscan database

Ragnar auto-detects available tools and enables the corresponding features in the
web interface.

---

## Related

- [Scanning & Attacks](scanning-and-attacks.md) — the core discovery/assess/attack loop
- [Traffic Analysis](traffic-analysis.md) — the light `tcpdump`-based analyzer that runs on any board
- [Ragnar Mesh](mesh.md) — how gated scans are delegated to a capable peer
