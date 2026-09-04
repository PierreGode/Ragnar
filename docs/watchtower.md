# Watchtower — one pane for every standalone watcher

Ragnar ships a family of deep, continuous passive monitors that each run as their
own daemon: [`arp_guard`](arp_guard.md), [`ndpwatch`](ndpwatch.md),
[`wifiwatch`](wifiwatch.md), [`legacywatch`](legacywatch.md),
[`wpswatch`](wpswatch.md), [`certwatch`](certwatch.md),
[`snmpwatch`](snmpwatch.md), [`isiswatch`](isiswatch.md) and
[`igmpwatch`](igmpwatch.md). They are the suite's sharpest detectors — but each
wrote to its own log with its own schema, so there was **no single place to see
them and no single notification path.** Watchtower is that place.

`watchtower.py` **tails every watcher's JSON-lines log, normalizes the records
into one common shape, and shows them in one deduped feed** — in the web UI
(Diagnostics → *Watchtower*) and, for new high/critical findings, through one
Pushover path. It is **read-only over the log files**: it never captures a
packet or sends one. The watchers stay the sensors; Watchtower is the aggregator.

Alongside the standalone daemons, the **in-app vendor CVE guards** —
[`cisco_guard`, `juniper_guard`, `arista_guard`](nettools.md#vendor-cve-guards-cisco--juniper--arista)
and [`comware_guard`](nettools.md#comware-guard) — append their findings as
JSON-lines to `/var/log/ragnar/<guard>.jsonl` (time-window deduplicated so the
background rotation cannot spam the log with a standing condition). Watchtower
picks them up through the same glob and treats them exactly like any other
source, so a Cisco SNMP-overflow attempt or a Comware VRF-hop lands in the same
pane and the same Pushover path as an ARP-poisoning or an evil-twin. Unlike the
daemons, the guards need no systemd unit — they feed Watchtower automatically
whenever **Extended Monitoring** is on.

The in-app **L5–L7 observers** [`ssh_watch`](nettools.md#ssh-watch) and
[`telnet_watch`](nettools.md#telnet-watch) feed the pane the same way, appending
their **non-`info`** findings to `/var/log/ragnar/ssh_watch.jsonl` and
`/var/log/ragnar/telnet_watch.jsonl` (deduplicated per code + server). Pure
inventory/posture stays off the pane; a Terrapin exposure lands as **high** and a
confirmed Telnet argument injection as **critical**. Both also run in the Network
Integrity Monitor rotation, so their verdicts surface there as chips as well.

Two L3 routing observers feed the pane the same way. [`icmp_watch`](nettools.md#icmp-watch)
appends its **HIGH/CRITICAL** redirect findings to `/var/log/ragnar/icmp_watch.jsonl`
(deduplicated per check + source) — a gateway-MAC spoof or ARP-poison-then-redirect
lands as **critical**, an off-subnet / non-router redirect as **high**.
[`pathwatch`](nettools.md#bgp-collector--path-asymmetry-control-plane--data-plane)
(BGP Path Watch v2, the on-demand path-convergence probe) appends a
**suspected/active/confirmed** convergence verdict to `/var/log/ragnar/pathwatch.jsonl`
(deduplicated per target + severity) — a RIB-corroborated convergence event lands as
**critical**, loss-plus-path-change as **high**.

[`smb_watch`](nettools.md#smb-watch) (SMB & Kerberos Watch v2) appends a **HIGH/CRITICAL**
verdict to `/var/log/ragnar/smb_watch.jsonl` (deduplicated per verdict + interface) — a
static Responder challenge lands as **critical**, and Responder poisoning, SMBv1 in
active use, Kerberos roasting/downgrade, or a KDC-error recon burst as **high**. This is
the harvest + Kerberos half of the credential-relay chain; the Relay/Coercion Watch owns
the relay + unsigned-target half, and Watchtower's incident-correlation engine fuses the
two streams into one named attack chain.

[`rpc_watch`](nettools.md#rpc--netlogon-watch) (RPC / NetLogon Watch) appends its
**HIGH/CRITICAL** DCERPC / NetLogon / NTLM / WinRM findings to
`/var/log/ragnar/rpc_watch.jsonl` (deduplicated per code + subject) — the **Zerologon**
chain (CVE-2020-1472), an unsigned NetLogon bind, **DCSync**, DPAPI backup-key access
and WinRM Basic/unencrypted land as **critical**, the rest of the auth-posture set as
**high**. Authentication **coercion** is excluded from this feed on purpose: the
Relay/Coercion Watch already streams it (see above), so the RPC/NetLogon feed never
double-reports the same PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce event.

[`lacp_watch`](nettools.md#lacp-watch) (LACP Watch) appends its **HIGH/CRITICAL**
slow-protocol integrity findings to `/var/log/ragnar/lacp_watch.jsonl` (deduplicated per
code + session) — a correlated **LAG hijack** lands as **critical**, and delivery-path
anomalies (VLAN-tagged / non-group-MAC LACPDUs), identity manipulation and sync/timeout
flapping as **high**.

These vendor guards are **LAN-only**: their findings only mean anything on a
wired switch/router uplink or a SPAN/mirror port, so the background rotation
runs them **only when a genuine wired LAN interface is up** and always over that
wired NIC — never `wlan0`. On a Wi-Fi-only unit they simply don't auto-run, so
Comware can't falsely report VRF/MPLS findings off wlan. A manual scan from the
dashboard is always available regardless of link type.

## Why one normalizer, not seven adapters

The watchers disagree on nearly every field, so Watchtower uses a single
key-aware normalizer rather than a brittle adapter per tool:

| Field | Where watchers put it |
|---|---|
| severity | `severity` (`critical`/`high`/…), `status` (`CRIT`/`WARN`/`INFO`/`OK`), or `sev` (`INFO`/`LOW`/`MED`/`HIGH`) |
| timestamp | epoch float **or** ISO-8601 string |
| finding id | `codes[]`, `code`, `detector`, `rule`, or `findings[].code` |
| endpoints | `src`/`sender_ip`/`server_ip`/`identity`/`system`, `target`/`dst`/`group` |

`normalize()` searches a priority-ordered set of keys for each field. The upshot:
**a new watcher that emits JSON lines with any recognisable severity field shows
up with zero code changes.** Records that aren't alerts — an `OK`/`clean` status,
certwatch inventory noise — normalize to *no severity* and are dropped.

Alerts land on a canonical severity ladder: `critical > high > medium > low >
info`. `WARN`/`warning` maps to `medium`; an unrecognised-but-present severity
surfaces as `medium` rather than being dropped.

## Enabling it

**On by default** — unlike the Network Integrity Monitor, Watchtower makes no
outbound calls and captures nothing; it only reads log files the watchers already
write, and is a no-op until a watcher is actually running. Toggle it in
**Diagnostics → Watchtower**, or:

```json
"watchtower_enabled": false
```

A background poller reads the delta from each watcher log every
`watchtower_interval_s` seconds, updates the panes, and pages new findings at or
above `watchtower_notify_min_severity`.

> **Config changes need a service restart** to take effect — the running process
> holds the config and the routes in memory (`sudo systemctl restart ragnar`).

### Config keys

| Key | Default | Meaning |
|---|---|---|
| `watchtower_enabled` | `true` | master switch for the aggregator + poller |
| `watchtower_interval_s` | `30` | poll cadence (min 5s) |
| `watchtower_max_alerts` | `500` | size of the rolling in-memory/persisted ring |
| `watchtower_notify_enabled` | `true` | send Pushover for new findings |
| `watchtower_notify_min_severity` | `high` | floor for paging (`critical`/`high`/`medium`/`low`) |
| `watchtower_notify_cooldown_s` | `300` | min seconds between Pushover sends (burst backstop) |
| `watchtower_realert_hours` | `0` | re-page a still-standing finding after N hours (`0` = page once) |
| `watchtower_dirs` | *(unset)* | override the watched log directories (list) |

**No re-paging on restart:** on first sight of a log file Watchtower skips to its
end (`tail -f` semantics), so a service restart never replays — and re-pages —
the backlog. Rotation and truncation are detected (inode + size) and re-read from
the top. Per-finding dedup memory persists to `data/watchtower_seen.json`; the
display ring persists to `data/watchtower_alerts.json` so the pane isn't blank
after a restart.

## Making every watcher visible: the common log dir

Watchtower reads two things: each watcher's known default log path **and** every
`*.jsonl` file in `/var/log/ragnar/`. The recommended setup — and the "drop a
file in and it appears" path — is to point each watcher at
`/var/log/ragnar/<tool>.jsonl`.

**Streaming today (appear with no change):**

- **ndpwatch** → `/var/log/ndpwatch/alerts.jsonl` (its unit already writes JSONL)
- **wifiwatch** → `/var/lib/ragnar/wifiwatch/events.jsonl` (already JSONL)

**Need a one-line change to stream JSON-lines to a file:**

```ini
# common dir, once
sudo mkdir -p /var/log/ragnar

# arp_guard / ndpwatch / wifiwatch: add/point --jsonl at the common dir
ExecStart=… python3 python/arp_guard.py -i eth0 --jsonl /var/log/ragnar/arp_guard.jsonl

# certwatch logs --json to stdout (journald); stream it to a file instead:
StandardOutput=append:/var/log/ragnar/certwatch.jsonl

# igmpwatch: set its alert sink to /var/log/ragnar/igmpwatch.jsonl in igmpwatch.yaml
```

**Not line-delimited yet:** `snmpwatch --json` and `isiswatch --web-json` write a
*snapshot/at-exit report*, not a per-alert stream, so they won't feed a live tail
until pointed at a JSON-lines sink. Until then they're absent from the pane (shown
as `○` in the source line) rather than silently wrong.

The Watchtower card shows a source line — `● ARP Guard  ○ Cert Watch …` — so you
can see at a glance which watchers are actually logging where Watchtower can read
them (`●` present, `○` no log found / not running).

## The panes

**Dashboard** — a Watchtower card sits under the stats grid on the landing tab:
severity chips (or a green *All clear*), the five newest findings, and a
`3/9 watchers logging: ● ARP Guard ○ Cert Watch …` source line. It refreshes with
the dashboard (on open, then every 20s), so an active attack is visible without
digging.

**Diagnostics → Watchtower** — the full pane: severity-count chips, newest-alert
time, per-source presence, and a newest-first alert list (source · title · codes ·
endpoints · time). A severity filter (`all` … `critical`) narrows both the list
and what the API returns.

API: `GET /api/net/watchtower?limit=100&min_severity=high` →
`{success, enabled, summary, alerts[]}`.

## Self-test

```bash
python3 watchtower.py --self-test        # 31/31 — no root, no daemons, no wire
```

The harness drives real ndpwatch/arp_guard/wifiwatch/certwatch/igmpwatch/snmpwatch
record shapes through the normalizer (severity/status/sev vocabularies, epoch vs
ISO timestamps, the `findings[]`/`rule`/`detector` id variants, OK-is-not-an-alert)
and exercises the tailer end-to-end over real files: incremental deltas, a
partial line held until its newline, truncation/rotation re-reads, and the
`tail_only` backlog-skip.

Debug from the CLI without the web app:

```bash
python3 watchtower.py --dir /var/log/ragnar --once            # dump current alerts
python3 watchtower.py --dir /var/log/ragnar --follow --min-severity high
```

## Correlation

The same normalized stream feeds the [incident correlation
engine](incident-correlation.md), which fuses related alerts into named
attack-chain *incidents* (e.g. an evil-twin beacon + a deauth + a captured
handshake, all sharing one BSSID, become one "Evil-twin WPA handshake capture").
Incidents lead both the dashboard card and the Diagnostics pane, above the raw
alert feed.

## Limitations

- **Same vantage as its sensors.** Watchtower only sees what the watchers see;
  place each watcher on the segment / SPAN it needs (see each tool's doc).
- **A watcher must be running and logging to a file** Watchtower can read. It does
  not start the watchers; it aggregates their output.
- **snapshot-only outputs** (`snmpwatch`, `isiswatch` as shipped) need a JSON-lines
  sink before they stream into the pane — see the common-dir section above.
