# Ulfberht Engagements — coordinated security workflows

The **Engagements** engine is what makes [Ragnar OS Ulfberht](ragnar-os-ulfberht.md)
a professional tool rather than a Kali spin with extra packages. Instead of a
drawer of tools, it runs **playbooks** that chain the phases of a real
engagement — **discovery → diagnostics → assessment → reporting** — over one
scope, into one methodology-aligned report.

It is **exclusive to the official Ulfberht image**: the engine and its UI only
appear when the build-time edition marker (`/etc/ragnar-edition`) is present.
On the standard image, or on a stock Kali box running Ragnar, the Engagements
tab and the engine are hidden and the API refuses to run. For authorized
security testing only.

## Methodology

Phases map to **NIST SP 800-115** (and align with PTES), so an engagement
follows a defensible standard and the output is something a professional hands
to a client — and something a student can be graded on.

| Phase | NIST SP 800-115 | Safety | What it does |
|-------|-----------------|--------|--------------|
| **Discovery** | §4 Target identification | passive | `nmap` host + service sweep of the scope (XML-parsed). |
| **Diagnostics** | §4 Vulnerability/posture analysis | passive | Derives a security posture from what's exposed (cleartext protocols, legacy r-services, exposed SMB/RDP/DB/SNMP…), each mapped to a CWE / MITRE ATT&CK reference. This safe phase also *aims* the active phase. |
| **Assessment** | §5 Target vulnerability validation | **active (gated)** | Validates findings against discovered services (e.g. `nuclei` on web services). Runs **only** when the operator opts in per-run; it is authorized by the **Ulfberht edition** itself (the engine is marker-locked to the official image), **not** the global auto-attacks toggle. |
| **Reporting** | §8 Post-testing / reporting | passive | One report: executive summary with an overall risk rating, host/service table, findings by severity with references **and per-finding remediation**, phases executed. Viewable in-tab and downloadable as **Markdown** or a styled, printable **HTML (→ PDF)** report. Every finished run is **saved on the device**. |

## Safety model

- **Scope is entered once and every step is confined to it.** No phase targets
  anything outside the scope you give.
- **Passive by default.** Discovery and diagnostics are non-intrusive and always
  allowed. The **assessment** phase is the only active one. It is authorized by
  the **Ulfberht edition** (the engine is marker-locked to the official image)
  together with a **per-run opt-in** — tick "enable active assessment" — and is
  deliberately **not** tied to the global auto-attacks toggle: choosing the
  edition is the authorization. Leave the opt-in off and the phase is skipped and
  the report says so.
- Everything runs in a background thread with per-tool timeouts.

## Using it

1. Boot the Ulfberht image; open the web UI (`:8000`). The **⚔️ Engagements** tab
   appears (it won't on a non-Ulfberht box). The detected offensive toolset also
   shows as the **Arsenal** panel on the Pentest tab.
2. Pick a playbook — built-in or one of your own from the **Playbook library**
   (where you can also **Upload .json** playbooks and delete your custom ones) —
   enter a **scope** (IP / CIDR / host), optionally enable the active phase, and
   **Run engagement**.
3. Watch the phases progress and findings stream in; when it completes, **open
   the HTML report** (print → PDF in the browser) or **download** it as HTML or
   Markdown.
4. Past engagements are saved on the device and listed under **Recent
   engagements** (survives a restart) — click one to reopen its findings and
   report.

### Built-in playbooks

| Playbook | What it does |
|----------|--------------|
| **Scoped Network Assessment** | Top-100 sweep → posture → (gated) nuclei on web services → report. The flagship. |
| **Web Application Assessment** | Web ports → posture → `whatweb` fingerprint → (gated) nuclei + Nikto per web target → report. |
| **Full-Port Host & Service Audit** | All 65 535 TCP ports with version + safe default NSE scripts → posture → report. Passive. |
| **SMB / Active Directory Recon** | SMB/LDAP/Kerberos sweep → posture → (gated) `enum4linux-ng` per host → report. |

### Playbooks are data — author and upload your own

A playbook is a small **JSON** file: an ordered list of **steps**, each running
one **action** with validated parameters. You can write your own and **upload**
them in the Engagements tab; they sync to the **`engagement_playbooks`** folder
in the **Files tab** (exactly like Device Console scripts and Rubber Ducky
payloads), where you can edit or delete them. Uploaded playbooks are validated
on load — an invalid one is shown with the reason and cannot be run.

**Or build one from the Arsenal.** On the **Pentest** tab, the **Ulfberht
Arsenal** lists every offensive tool detected on the image. Click the tools you
want, give it a name, and **Build playbook** — a valid, methodology-ordered
playbook is generated from your selection and opened in an editor to review
before saving. The starter is **tailored to the tools you picked**: each gets a
real, sensible step (cracking tools get a hash file + wordlist, wireless tools a
monitor-mode interface, capture/MITM/framework tools a non-interactive
invocation), an nmap discovery sweep + a posture pass are prepended, a report is
appended, and the description is category-aware and flags any step that needs
you to supply input first (a hash file, a capture, an interface).

**Or let your own AI write it.** Still in the Arsenal, describe the engagement
in plain language under **Generate with AI** and click **Generate AI prompt**.
Ragnar assembles a complete, copy-pasteable prompt — the exact playbook schema,
the action catalog, the tool allowlist, the argv/no-shell safety rules, your
selected tools and your instruction, plus a worked example — that you paste into
**your own AI** (Claude, ChatGPT, a local model). Paste the AI's JSON reply back
into the editor and **Save**. No AI runs on the device and no API key is needed,
so it works on an offline/airgapped box; the prompt is built so a well-formed
reply validates and runs as-is.

```json
{
  "id": "my-playbook",
  "name": "My Playbook",
  "description": "What this engagement does",
  "steps": [
    { "phase": "discovery",   "action": "nmap",    "params": { "ports": "top-100", "service_version": true } },
    { "phase": "diagnostics", "action": "posture" },
    { "phase": "assessment",  "action": "command", "params": { "tool": "nikto", "args": ["-host", "{web_urls}"], "per_target": true }, "active": true },
    { "phase": "reporting",   "action": "report" }
  ]
}
```

**Actions**

| Action | Phase | Parameters |
|--------|-------|------------|
| `nmap` | discovery | `ports` (`top-100` \| `top-1000` \| a portspec like `80,443,8000-8100`), `service_version`, `default_scripts` (safe NSE), `timing` (`T0`–`T5`) |
| `posture` | diagnostics | `custom_rules`: `[{match, severity, title, ref}]` to flag your own services/ports on top of the built-in risk map |
| `nuclei` | assessment | `severity` (`[info..critical]`), `tags` — runs against discovered web services |
| `command` | any | `tool` (allowlisted security tool), `args` (`[str,…]`), `per_host` / `per_target` to iterate discovered hosts / web URLs, `timeout` (seconds, 10–3600, default 900) |
| `report` | reporting | — (added automatically if omitted) |

**Placeholders** substituted at run time, always confined to your scope:
`{scope}`, `{host}`, `{hosts}`, `{ports}`, `{web_urls}`.

**The `command` action** lets experts invoke a tool directly, but safely. The
allowlist covers the **whole installed offensive toolset** — every tool the
edition detects on the image (nmap, masscan, nuclei, nikto, wpscan, sqlmap,
hydra, netexec, enum4linux-ng, responder, ettercap, aircrack-ng/wifite/reaver,
hashcat/john, msfconsole, tcpdump/tshark, …) plus a set of recon helpers (dig,
whois, whatweb, nbtscan, snmpwalk, sslscan/sslyze, gobuster/ffuf/feroxbuster, …).
It is a **safety** allowlist, not a feature list: the step runs as an **argv list,
never through a shell**, args are rejected if they contain shell metacharacters,
and the allowlist is what stops a shared/uploaded playbook from running an
arbitrary binary (`rm`, `dd`, a reverse shell) — the engine runs as root.
Everything offensive is classed **active** and runs **only** when active testing
is enabled, same as the assessment phase.

> **Fit note.** Scanners/enumerators (nmap, nuclei, sqlmap, netexec,
> enum4linux-ng, the busters) fit the step model directly — point them at
> `{scope}`/`{host}`/`{web_urls}` and read the output. Tools that need external
> inputs or state are allowed but need the right args: **cracking** (hashcat,
> john) wants a hash file + wordlist, **Wi-Fi** (aircrack-ng, airodump-ng,
> wifite, reaver, bully, kismet) wants a monitor-mode capture rather than an IP
> scope, and **interactive / long-running** tools (msfconsole, setoolkit,
> responder, ettercap, tcpdump) should be invoked non-interactively (e.g.
> `msfconsole -q -x …`) or they will run until the step `timeout`.

## Reports & history

Every finished engagement produces a report in two forms and is saved on the
device so nothing is lost on a restart:

- **HTML report (print → PDF).** A self-contained, styled, printable page:
  executive summary with an overall **risk rating** badge, KPI tiles (live hosts
  / high+critical / medium / low / info), the targets, a hosts-&-services table,
  and per-finding cards — each with a severity badge and a **remediation box**
  (a one-line fix per risk class: disable Telnet, restrict SMB, drop SNMP
  v1/v2c, …) — followed by the NIST SP 800-115 phase table. Open it with **Open
  report (print / PDF)** and use the browser's *Print → Save as PDF*.
- **Markdown report.** The same content as text, with remediation inline — handy
  to paste into a ticket or wiki. **Download .md** (or `.html`).
- **Recent engagements.** Finished runs are written to
  `data/engagements/<id>.json` and listed in a collapsible panel on the
  Engagements tab (playbook · scope · time · status); click one to reopen it.

API: `GET /api/ulfberht/report/<id>` returns Markdown JSON; add
`?format=html` for the HTML page, and `&download=1` on either to save the file.

## Roadmap

- SIEM push of engagement findings (reusing Ragnar's existing SIEM egress).
- Wi-Fi playbooks driving the Nexmon onboard radio.
- Deeper feed-forward from the passive watcher/guard layer into the diagnostics
  phase.

See also: [Ragnar OS Ulfberht](ragnar-os-ulfberht.md).
