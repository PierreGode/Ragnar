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
  which decides what the orchestrator scans. Presence is kept in memory only.
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

### Dashboard Targets card

The first Dashboard card uses the same live verdict, so it always agrees with
the Discovered Hosts table:

| Number | Meaning |
| --- | --- |
| **Targets** (large) | hosts that are Online right now, Ragnar itself included |
| **Tot** | every host Ragnar knows on this network |
| **Offline** | Tot minus Targets |
| **New** | hosts first seen in the last 24 hours |
| **Lost** | hosts that were answering and went Offline in the last 24 hours, and are still Offline |

Hover **New** or **Lost** for the addresses. A host with no live verdict
(another saved network, or the first seconds after start) is counted from its
stored status. **Lost** is kept in memory, so it starts again from 0 when
Ragnar restarts; hosts that were already silent at start are Offline, not Lost.
The e-paper target count follows the same Online number. Push notifications
for new and lost devices are unchanged and still follow the stored status.

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

### Distro-aware CVE check (Debian / Ubuntu)

The Nmap `vulners` script matches a service against its **upstream** version
(`cpe:/a:openbsd:openssh:9.2p1`) and returns every CVE ever filed against it.
Debian and Ubuntu backport security fixes without changing that upstream
version, so a fully patched host still shows CVEs that were fixed years ago, and
the one finding that is really open is buried under them.

The distro patch level is usually in the service banner
(`OpenSSH 9.2p1 Debian 2+deb12u10`). With **Distro-aware CVE Check** on, Ragnar
reads it and asks the distro's own security tracker about each CVE before
showing it.

**Turn it on:** Config → General → **Distro-aware CVE Check**
(`distro_cve_enrichment`, off by default). It applies to scans that run after
you enable it; a host scanned in the last hour is re-checked on its next scan.

Every finding is **tagged, never deleted**:

| Tag | Meaning | Default view |
|-----|---------|--------------|
| `distro-fixed` | The host's package revision already contains the fix | Hidden |
| `distro-not-affected` | The distro marks its package as not affected (or "unimportant") | Hidden |
| `exploit-ref` | An exploit reference (githubexploit, PacketStorm, EDB…) that names no CVE, on a service whose CVEs were checked | Hidden |
| `distro-deferred` | Vulnerable; the distro postponed or will not ship a fix | Shown |
| `distro-open` | Vulnerable: no fix yet, or a fix exists and the host is behind (the fixed version is named) | Shown |
| `unverified` | No revision in the banner, unknown product, or no tracker data. Same as before | Shown |

In **Threat Intel**, hidden findings do not count towards a host's totals or its
risk level. Each host shows how many are suppressed, and **Show N suppressed**
in the host's details lists them with their tag and the tracker's reason. The
dashboard and on-device vulnerability count use the same rule. Within a host,
**CISA KEV** entries come first, then tracker-confirmed open findings, then the
rest by severity. A CVE in the CISA KEV catalogue is never hidden, even when the
distro says it is fixed.

What it can check:

- **Debian** — releases the security tracker still carries (currently bookworm,
  trixie and forky). Older releases stay `unverified`.
- **Ubuntu** — the release is worked out from the tracker's fixed versions,
  because an Ubuntu revision such as `3ubuntu0.10` does not name it. When that
  is ambiguous the findings stay `unverified` rather than guessed.
- **RHEL (`elN`) and Amazon Linux (`amznN`)** markers are recognised but there is
  no tracker lookup for them yet, so they stay `unverified`.
- The banner must carry the revision. OpenSSH, MariaDB/MySQL and BIND usually
  do; Apache and nginx normally only say `(Debian)`, which is not enough.

Data and privacy:

- Debian: one snapshot of the tracker (about 15 MB to download), trimmed on disk
  to the ~30 service packages Ragnar can fingerprint (under 1 MB) and refreshed
  every 24 hours (`distro_cve_cache_hours`). After the first sync the check works
  offline from that cache.
- Ubuntu: one request per CVE, cached for the same period.
- Only CVE ids are sent. Nothing about the scanned host leaves the box.
- Cache: `data/distro_cve/`. If a tracker cannot be reached and there is no
  cache, findings stay `unverified` and the scan carries on.

Limits worth knowing: the verdict trusts the banner, so a host that hides or
fakes its version string is not covered; and exploit references are hidden only
because they cannot be tied to a CVE, not because each was proven harmless.
Expand them when in doubt.

Try one service by hand:

```bash
python3 distro_cve.py "OpenSSH 9.2p1 Debian 2+deb12u10" CVE-2024-6387 CVE-2026-60002
```

API: `/api/vulnerabilities/grouped` and `/api/vulnerabilities` add
`distro_status`, `distro` (release, package, host and fixed version, note,
tracker link), `kev` and `suppressed` to each finding, plus `suppressed_count`
per host and `total_suppressed`.

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
