# Asset Inventory

Ragnar has always *discovered* hosts and kept them in a table (MAC, IP, hostname,
vendor, open ports, first/last seen). The **Assets** tab turns that flat list into
a living inventory: it classifies every device, lets you mark which ones are
*supposed* to be here, and — most importantly — **notices when things change** and
raises an alert through the same pipeline as every other Ragnar detector.

It is entirely **passive and read-only**: it reads the existing hosts database
(populated by the normal network/passive discovery) and its own metadata file. It
sends no packets of its own.

## What it does

- **Classification & enrichment.** Each host is tagged with a device type
  (router, switch, AP, phone, server, SBC, camera, printer…) and screened against
  Ragnar's rogue-device signatures (O.MG cable, Flipper/Marauder/Deauther
  Espressif nodes, **HaleHound-CYD** attack multitool, Pineapple-style APs, …).
  Reuses `device_classifier.py`. A HaleHound-class Espressif host on the LAN is
  also fused into the [HaleHound correlation](wifi-defense.md#halehound-cyd-correlation).
- **Ownership & criticality.** Annotate any asset with an **owner**, a
  **criticality** (`none`→`critical`), an **authorized** flag (yes/no/—), free-form
  **tags**, and **notes**. Stored in `data/asset_meta.json`, keyed by MAC.
- **Ignore / mute.** Permanently silence a device you don't want to hear about
  (a noisy IoT gadget, a known-good bring-your-own device, your own test rig).
  Ragnar keeps tracking it, but it raises no more change or threat events — see
  [Ignoring a device](#ignoring-a-device).
- **Change detection.** Every snapshot diffs the current hosts against the previous
  one and emits typed events (below).
- **One exit.** Events are written as JSON-lines to
  `/var/log/ragnar/asset_inventory.jsonl` in the standard Ragnar watcher shape, so
  **Watchtower** ingests them automatically — which means they also reach Pushover,
  the [incident correlation engine](incident-correlation.md), and the
  [SIEM forwarder](siem.md) with no extra wiring.

## The killer signal: unauthorized devices

Once "authorized" exists, a new device raising its hand becomes meaningful:

| Authorized flag | New-device severity |
|---|---|
| `yes` | `info` |
| `—` (unclassified) | `medium` |
| `no` | `high` |

Mark your known-good fleet as authorized once; from then on, anything new and
unknown pages at `medium`/`high`, and anything you've explicitly banned pages at
`high`. This is the "a device you didn't authorize just appeared on the network"
alert that both a home lab and a SOC want.

## Change events

| Code | Fires when | Severity |
|---|---|---|
| `ASSET-NEW` | a MAC never seen before appears | info / medium / high (by authorized) |
| `ASSET-THREAT-*` | a rogue-device signature matches | signature's own severity |
| `ASSET-IP-CHANGE` | a known MAC moves to a new IP | medium |
| `ASSET-VENDOR-CHANGE` | the resolved OUI vendor for a MAC changes from one **real** vendor to a different **real** vendor | high *(possible spoof/clone)* |
| `ASSET-HOSTNAME-CHANGE` | a known asset's hostname changes | low |
| `ASSET-PORT-OPENED` | a new listening port appears | medium, **high** if sensitive¹ |
| `ASSET-PORT-CLOSED` | a port a host had is gone | info |
| `ASSET-OFFLINE` | a host goes non-alive | low, **high** if the asset is criticality ≥ high |
| `ASSET-BACK-ONLINE` | a host returns to alive | info |

### How a host's alive/degraded status is decided

Liveness is not a single probe. Every discovery cycle unions two independent
sources, so one unlucky sweep can't take the whole inventory down:

1. **`arp-scan` broadcast sweep** on the interface that carries the LAN — the
   one owning the default route, wired or wireless. It is run with retries
   (`--retry=3 --timeout=500`) because a single 100 ms probe loses hosts behind
   a power-saving Wi-Fi client.
2. **The kernel neighbour table** (`ip -4 neigh`), which remembers every host
   this box has actually exchanged frames with. Entries in `REACHABLE`,
   `STALE`, `DELAY`, `PROBE` or `PERMANENT` count as alive; `FAILED` and
   `INCOMPLETE` do not.

A host only drops to **degraded** after `network_max_failed_pings` (default 15)
*consecutive* cycles in which neither source saw it. Two cases are explicitly
**not** counted as a failed ping:

- a discovery cycle that returned **zero** hosts — that is a broken sensor (no
  `arp-scan` binary, no `sudo`, wrong interface), not the whole LAN going down;
- a repeat read of a sweep that has already been accounted for, so polling the
  dashboard cannot burn through the failure budget.

If every target flaps Offline and back on a cycle, check `arp-scan` is
installed and that passwordless `sudo` works for it — the log line
`Host discovery returned 0 hosts` names that condition directly.

### Wired Ethernet and Wi-Fi on the same network

A box plugged in by cable **and** joined to the same LAN over Wi-Fi (an Alfa
adapter, say) is one network reached two ways, and is scanned as one:

- In multi-interface mode, scan jobs that share a subnet collapse to **one
  scan per cycle** over the preferred interface (Ethernet, when
  `ethernet_prefer_over_wifi` is on — the default), filed under the Wi-Fi SSID
  so its hosts land in that network's store. The log names the merge:
  `wlan1 (HomeNet) is on the same network 192.168.1.0/24 as eth0 — scanning it
  once via eth0`. Interfaces on **different** subnets are still scanned
  separately.
- A scan temporarily switches the active network context to the one it is
  scanning. That override is never mistaken for the box changing networks:
  the Wi-Fi monitor compares against the storage layer's durable network, not
  the scan's temporary one, and only a real change runs the
  "mark every host degraded" hand-off between network stores.

- The network's identity is its **SSID**, never the NetworkManager
  *connection name*. Adding a USB Wi-Fi dongle moves the client role onto it,
  and its profile is often named differently from the SSID — netplan on Ubuntu
  names them `netplan-wlan1-<SSID>`, and NetworkManager auto-names a second
  profile for a known network `"<SSID> 1"`. Reading that label as the SSID made
  the dongle joining the *same* network look like a switch to a new one, which
  degraded every host and opened a duplicate network store.

Before this (issue #818), the Ethernet job ran as a separate `LAN` context;
the Wi-Fi loop read that as a switch away from the SSID and degraded every
host once per scan cycle — Degraded in the inventory, Offline on the
dashboard — until the next scan brought them back.

¹ *Sensitive* ports are cleartext-admin / remote-desktop / file-share / database
services (telnet, ftp, tftp, smb, rdp, vnc, mssql, mysql, postgres, redis, mongodb,
snmp, ldap, …). SSH is deliberately **not** sensitive — it's normal everywhere and
would be pure noise.

## Using it

Open **Assets** in the web UI:

- **Summary tiles** — total / authorized / unauthorized / unclassified / with-threats
  / offline / ignored.
- **Asset table** — every device with type, vendor, ports, status, inline
  **Authorized** and **Criticality** dropdowns (changes save immediately), and an
  **Ignore** button to mute/un-mute the device.
- **Recent changes** — the rolling event log.
- **Auto-monitor** — toggle the background snapshotter; **Scan now** runs one
  immediately.

### Ignoring a device

Some devices are just noisy — a smart plug that flaps offline, a phone that
opens and closes ports, a lab box you keep re-imaging — and every blip pages you.
Click **Ignore** on that device's row to permanently silence it:

- It **stays in the inventory** and Ragnar keeps tracking its state, so the moment
  you un-ignore it, change detection resumes cleanly (no stale-state false alarms).
- While ignored it emits **no change events and no threat events**, so nothing from
  it reaches Watchtower, Pushover, the incident engine, or your SIEM.
- Its rogue-device threats stop counting toward the **With threats** tile, the row
  is dimmed, and any threat marker is struck through. It's tallied under **Ignored**.
- Click the button again (**Ignored → Ignore**) to re-enable alerts.

The flag lives in `data/asset_meta.json` as `"muted": true` on that MAC, so it
survives restarts. It is independent of the *authorized* flag — you can ignore an
authorized device or an unauthorized one alike.

### First run is quiet by design

The first snapshot has nothing to diff against, so it **seeds a baseline silently**
— it does *not* page you about every existing device. Only genuine changes from that
point on raise events. (Set `asset_inventory_alert_on_baseline: true` if you
actually want the first run to enumerate everything as new.)

## Configuration

Flat keys in `config/shared_config.json` (defaults shown):

```jsonc
"asset_inventory_enabled": false,        // run the periodic snapshotter
"asset_inventory_interval_s": 120,       // seconds between diffs (min 30)
"asset_inventory_alert_on_baseline": false
```

## Files

- `asset_inventory.py` — the module. Self-test: `python3 asset_inventory.py --self-test`.
- `data/asset_inventory_state.json` — last snapshot (for diffing).
- `data/asset_meta.json` — operator ownership/criticality metadata.
- `data/asset_events.json` — bounded recent-events log for the UI.
- `/var/log/ragnar/asset_inventory.jsonl` — emitted events (tailed by Watchtower).

## API

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/inventory` | enriched asset list + summary + recent events |
| `POST` | `/api/inventory/meta` | annotate one asset (`{mac, owner, criticality, authorized, tags, notes, label, muted}`) — `muted: true` permanently ignores warnings from the device |
| `POST` | `/api/inventory/scan` | run one snapshot now (`{alert_on_baseline?}`) |
| `POST` | `/api/inventory/config` | `{enabled, interval_s}` |

## Notes & limits

- Outbound alerting rides Watchtower, so keep **Watchtower enabled** for asset
  events to page or forward. The Assets tab itself works regardless.
- MAC is the identity. A device that randomizes its MAC per association will look
  like a series of new devices — expected for privacy-MAC clients.
