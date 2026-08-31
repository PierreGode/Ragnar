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

¹ *Sensitive* ports are cleartext-admin / remote-desktop / file-share / database
services (telnet, ftp, tftp, smb, rdp, vnc, mssql, mysql, postgres, redis, mongodb,
snmp, ldap, …). SSH is deliberately **not** sensitive — it's normal everywhere and
would be pure noise.

## Using it

Open **Assets** in the web UI:

- **Summary tiles** — total / authorized / unauthorized / unclassified / with-threats
  / offline.
- **Asset table** — every device with type, vendor, ports, status, and inline
  **Authorized** and **Criticality** dropdowns (changes save immediately).
- **Recent changes** — the rolling event log.
- **Auto-monitor** — toggle the background snapshotter; **Scan now** runs one
  immediately.

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
| `POST` | `/api/inventory/meta` | annotate one asset (`{mac, owner, criticality, authorized, tags, notes, label}`) |
| `POST` | `/api/inventory/scan` | run one snapshot now (`{alert_on_baseline?}`) |
| `POST` | `/api/inventory/config` | `{enabled, interval_s}` |

## Notes & limits

- Outbound alerting rides Watchtower, so keep **Watchtower enabled** for asset
  events to page or forward. The Assets tab itself works regardless.
- MAC is the identity. A device that randomizes its MAC per association will look
  like a series of new devices — expected for privacy-MAC clients.
