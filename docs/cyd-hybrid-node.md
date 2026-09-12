# CYD hybrid node

A low-cost **companion node** for a Ragnar Pi, built on the **ESP32‑2432S028R**
("Cheap Yellow Display" / CYD) — an ESP32‑WROOM‑32 with a 2.8" 240×320 ILI9341
resistive‑touch screen.

Firmware lives in [`cyd_firmware/ragnar_cyd`](../cyd_firmware/); the Ragnar‑side
registry and auth live in [`cyd_node.py`](../cyd_node.py); the device endpoints
are in `webapp_modern.py`.

## Why it is a *companion*, not a Ragnar

Ragnar is a Linux/Python application (Flask, nmap, tshark, scapy, the watcher
suite). A WROOM‑32 has **520 KB RAM, 4 MB flash, no PSRAM** and **no browser** —
it cannot run Ragnar and cannot render the Flask web UI. So the CYD plays the
same role as HuginnESP / the ESP‑Now coordinators / RuSense CSI nodes: it does
its own work with its own radio and **reports to Ragnar over a protocol
boundary**. Ragnar does not get driver‑level access to the ESP32's WiFi/BLE
chip; it sends it commands and receives its findings.

```
 CYD (own firmware)                         Ragnar (Pi)
 ├─ touch dashboard of Ragnar status  ◄───  GET  /api/cyd/status
 ├─ 2.4 GHz sniff + BLE scan (own radio) ─► POST /api/cyd/ingest
 └─ operator taps an action           ───► POST /api/cyd/action
        authenticated by a Bearer device token (not a mesh peer)
```

## The one hard constraint: a single 2.4 GHz radio

The WROOM‑32 has one 2.4 GHz radio shared by WiFi and BT, and **cannot be
joined to an AP while sniffing other channels**. The firmware therefore
**time‑shares** in a duty cycle (tunable in `config.h`):

| Phase | State | Does |
|------|-------|------|
| SYNC (~2.5 s) | connected to WiFi | pull status, push counts, flush queued actions |
| SNIFF (~6 s) | disconnected, promiscuous | hop ch 1..13, count beacons/probes/deauths, unique BSSIDs |
| BLE (~3 s) | disconnected | passive advertisement scan (count) |

Consequences: the display shows the **last‑synced** values (near‑real‑time, not
live), and WiFi‑sniff and BLE never run at full rate simultaneously.

**Not available on this hardware:** 5 GHz, WiFi 6, simultaneous WiFi+BLE at full
rate, and the real Flask web page (the screen is a native LVGL‑style panel).

## Authentication

A CYD reaches Ragnar over plain WiFi, so it is **not** a tailnet/mesh peer and
cannot use WireGuard identity. Instead it carries an **operator‑issued Bearer
token** (`shared_data.config['cyd_device_tokens']`), matched constant‑time in
`cyd_node.valid_token`. The token role is enforced in
`webapp_modern.check_authentication()` and grants **only** these three
device‑facing endpoints — everything else stays session‑gated, fail‑closed:

- `GET  /api/cyd/status`
- `POST /api/cyd/ingest`
- `POST /api/cyd/action`

This mirrors the existing mesh *share‑token* role exactly.

## API reference

### Device‑facing (CYD device token required)

**`GET /api/cyd/status`** — compact, flat status for the touch display:

```json
{ "unit": "Bjorn", "mesh_nodes": 3, "nets_24": 0, "nets_5": 0,
  "threat": 15, "bluetooth": "idle", "uptime": 84213, "ts": 1789225000 }
```

The shape is intentionally flat — the firmware parses it with lightweight string
matching (no JSON library) to stay small.

**`POST /api/cyd/ingest`** — a node's 2.4 GHz sensor report:

```json
{ "node": "cyd-01", "beacons": 42, "probes": 7, "deauths": 0,
  "frames": 310, "bssids": 18, "ble_adv": 5, "rssi": -58 }
```

Unknown fields are dropped; counts are coerced to non‑negative ints. Returns the
node's stored summary.

**`POST /api/cyd/action`** — request an allowlisted operator action
(`wifi_defense_scan`, `ble_scan`, `watchtower_clear`). Validated against the
allowlist, then **dispatched to the live subsystem**: `watchtower_clear` runs
synchronously (`done`), `ble_scan` starts via the Bluetooth manager (`started`),
`wifi_defense_scan` runs a WIDS scan in a background thread (`started`, then the
thread records `completed` / `no-monitor-iface` / `error`). The outcome status
is logged against the node and visible in `/api/cyd/nodes`.

### Operator‑facing (session‑gated)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/cyd/nodes` | GET | nodes that have reported, with latest counts + recent action requests |
| `/api/cyd/tokens` | GET | issued tokens (previews only, never the raw secret) |
| `/api/cyd/token/generate` | POST | issue a token (`{"name":"cyd-01"}`); raw token returned **once** |
| `/api/cyd/token/revoke` | POST | revoke a token (`{"id":"…"}`) |

## Hardware pin‑map (ESP32‑2432S028R)

TFT (ILI9341, VSPI): SCLK 14 · MOSI 13 · MISO 12 · CS 15 · DC 2 · BL 21.
Touch (XPT2046, separate bus): SCLK 25 · MOSI 32 · MISO 39 · CS 33 · IRQ 36.
Extras: RGB LED 4/16/17 (active LOW), LDR 34. See `config.h`.

## Operator UI

**Ragnar Mesh → CYD Nodes** sub‑tab: a live list of reporting nodes (status dot,
last‑seen, per‑node beacon/AP/probe/deauth/BLE/frame tiles, recent action
outcomes) and device‑token management (generate — shown once — list, revoke).
Reachable whenever the Mesh tab is enabled (its default), independent of whether
Tailscale mesh itself is running.

## Roadmap

- [x] Wire `/api/cyd/action` to the live WIDS / BLE / Watchtower subsystems.
- [x] Operator UI (nodes list + token management).
- [ ] Fill `nets_24` / `nets_5` from the WiFi‑analyzer cache.
- [ ] ESP Web Tools flasher page (manifest stub in `cyd_firmware/flasher`).
- [ ] WiFiManager captive‑portal provisioning (drop creds from `config.h`).
