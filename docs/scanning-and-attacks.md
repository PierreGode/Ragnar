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

### Discovered Hosts: live Online / Offline status

The **Status** column of the Discovered Hosts table is a live presence
verdict, not the stored scan result. A small in-process monitor
(`host_presence.py`) keeps asking every known host on the LAN "are you still
there?" and pushes each change to the open page over the WebSocket, so only
the affected Status cell is redrawn.

- **How it checks.** Each known host gets a unicast ARP request to its last
  known MAC. A host cannot use the network without answering ARP, so this
  works on firewalled devices too, and an access point buffers unicast frames
  for a sleeping Wi-Fi client where a broadcast is often lost. A host that
  misses a reply is also pinged (ICMP echo) and ARPed by broadcast; an answer
  on any channel keeps it Online.
- **How fast.** While a dashboard is open, hosts are probed every 2 seconds
  and a silent host turns **Offline within about 10 seconds** (6 seconds of
  silence after the first unanswered probe, at least 4 probes). With no
  dashboard open the monitor idles: a probe every 10 seconds, Offline after
  about 30.
- **Coming back.** The monitor listens to every ARP frame on the segment. A
  device that powers on announces itself by ARP (including the `0.0.0.0`
  probe a DHCP client sends), so it turns Online at once. Offline hosts are
  also re-probed every 4 seconds, and every 12 seconds once they have been
  gone for 10 minutes.
- **What it costs.** No subprocesses and no disk writes: one 42-byte frame
  per host per interval over a single raw socket. It needs root (the service
  already runs as root) and an IPv4 address on the LAN interface. At most
  1024 hosts are tracked.
- **What it does not change.** The hosts database keeps its slower
  alive/degraded bookkeeping (see
  [Asset Inventory](asset-inventory.md#how-a-hosts-alivedegraded-status-is-decided)),
  which decides what the orchestrator scans and what the Dashboard target
  counts show. Presence is kept in memory only.
- **Sleeping devices.** A phone or battery device that stops answering for
  more than about 8 seconds shows Offline until it wakes. That is the
  trade-off of a 10 second verdict.
- **Fallback.** If the monitor cannot run (not root, no address yet,
  `host_presence_enabled` set to `false` in the config), the column falls back
  to the stored status and the banner above the table says so. A saved network
  other than the one Ragnar is attached to always shows its stored status.

Endpoint: `GET /api/network/presence` returns the verdict per IP plus the
monitor's mode and counters. `GET /api/network/stable` carries the same
verdict in each host's `status` (`up`, `down`, or `unknown`).

### IP range scan (host discovery)

On the **Networking → Hosts** tab, the **IP Range Scan** card sweeps a whole
range and lists the live hosts — the Angry IP Scanner / Advanced IP Scanner
pattern. It is *discovery only*: a single `nmap -sn` ping/ARP sweep with **no
port scan**, so it is fast and safe to run against a big range.

- **Input** — a CIDR (`192.168.1.0/24`) or a start-end range
  (`192.168.1.1-192.168.1.254`, or the short `192.168.1.1-254`). The range is
  bounded server-side to **1024 addresses**.
- **Per live host** it shows IP, DNS hostname, NetBIOS name (optional — tick
  *NetBIOS lookup* to add a UDP/137 `nbstat` probe), MAC address, MAC
  vendor (OUI), status and response time. MAC and vendor resolve only for hosts
  on your **local segment** (ARP does not cross a router) and need root — Ragnar
  uses passwordless `sudo -n nmap` and falls back to an unprivileged sweep
  (hostnames + response time, no MAC) otherwise.
- **Per-host “Scan ports”** runs the existing deep scan (top 3000 ports) for
  that IP, with live results in the console — no need to retype the address.
- **Export CSV** downloads the current results.
- Discovered hosts with a MAC are folded into the hosts database, so they also
  appear in the persistent **Discovered Hosts** table below.

Endpoint: `POST /api/scan/range` — body `{"range": "<cidr|start-end>", "netbios": <bool>}`.

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

- [Rubber Ducky Script Executor](rubber-ducky.md) — Pentest-tab USB HID keystroke injection
- [Reverse Shell](reverse-shell.md) — connect-back one-liner generator + catch listener
- [Advanced Vulnerability Scanning](adv-scan.md) — Nuclei / Nikto / SQLMap / ZAP, mesh delegation, RAM gating
- [Traffic Analysis](traffic-analysis.md) — passive host discovery + C2 / scan / tunnel detection
- [Authority Verification & network tools](nettools.md) — the detection-only L2→L7 watcher suite
- [Asset Inventory & change detection](asset-inventory.md) — turns the hosts table into a living inventory
