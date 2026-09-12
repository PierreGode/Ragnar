# Ragnar CYD hybrid node

A **companion node** for a Ragnar Pi built on the cheap, ubiquitous
**ESP32‑2432S028R** — the "Cheap Yellow Display" (CYD): an ESP32‑WROOM‑32 with a
2.8" 240×320 ILI9341 touch screen.

> **This is not Ragnar running on an ESP32.** Ragnar is a Linux/Python
> application and cannot run on a WROOM‑32 (520 KB RAM, 4 MB flash, no PSRAM).
> The node is a *hybrid companion*: it shows Ragnar's status on its touch
> screen, lets you trigger a small allowlist of Ragnar actions, and scans
> 2.4 GHz with its own radio and reports the counts back to Ragnar.

## What it does

The single 2.4 GHz radio can't be joined to WiFi **and** sniff other channels at
the same time, so the firmware **time‑shares** in a duty cycle:

```
 CONNECT + SYNC   GET /api/cyd/status   (pull status for the display)
      │           POST /api/cyd/ingest  (push last window's sensor counts)
      │           POST /api/cyd/action  (flush any queued operator taps)
      ▼
 DISCONNECT ─ WiFi promiscuous sweep ch 1..13  (beacons/probes/deauths/BSSIDs)
      ▼
 DISCONNECT ─ BLE advertisement scan           (advert count)   ── loops ──
```

The screen always shows the **last‑synced** values, so status and findings are
near‑real‑time, not continuous — the price of a WROOM‑32 vs an S3/C5.

Three touch tabs: **STATUS** (Ragnar's live state), **SCAN** (this node's own
2.4 GHz counts), **ACT** (buttons that queue an allowlisted action).

### Limits (be honest about the hardware)
- **2.4 GHz only** — no 5 GHz, no WiFi 6.
- WiFi and BLE share one radio; they run in separate duty‑cycle phases, never
  simultaneously at full rate.
- Resistive touch (XPT2046) — fine for big buttons, not fine‑grained gestures.

## Build & flash

Requires `arduino-cli`, the `esp32` core, and the **GFX Library for Arduino**
(moononournation) — the same library the other Ragnar ESP32 firmware uses.

```bash
# one-time: core + library
arduino-cli core install esp32:esp32
arduino-cli lib install "GFX Library for Arduino"

# edit cyd_firmware/ragnar_cyd/config.h first (WiFi, Ragnar URL, device token)

arduino-cli compile \
  --fqbn "esp32:esp32:esp32:PartitionScheme=huge_app,FlashSize=4M" \
  cyd_firmware/ragnar_cyd

arduino-cli upload -p /dev/ttyUSB0 \
  --fqbn "esp32:esp32:esp32:PartitionScheme=huge_app,FlashSize=4M" \
  cyd_firmware/ragnar_cyd
```

> **Power:** the CYD's WiFi browns out on some PC USB ports. If it reboots when
> WiFi starts, power it from a 5 V wall charger.

To drop BLE (saves flash/RAM), set `CYD_ENABLE_BLE 0` in `config.h`.

## Ragnar‑side setup

1. In Ragnar, issue a device token:
   `POST /api/cyd/token/generate` with `{"name":"cyd-01"}` → returns the raw
   token **once**. (List/revoke via `/api/cyd/tokens` and
   `/api/cyd/token/revoke`.)
2. Paste that token + your WiFi creds + Ragnar's LAN URL into `config.h`.
3. Flash. The node connects, the STATUS tab fills in, and reports show up under
   `GET /api/cyd/nodes`.

The node authenticates purely by the Bearer token (it is **not** a mesh peer),
and that token grants **only** the three `/api/cyd/*` device endpoints —
scoped and fail‑closed in `webapp_modern.py`'s `check_authentication()`.

## Status

- ✅ Firmware: boots, touch UI, duty‑cycle WiFi‑sniff + BLE scan, REST client.
- ✅ Ragnar: `/api/cyd/status` + `/api/cyd/ingest` live; token role wired.
- ✅ `POST /api/cyd/action` **dispatches** to the live subsystems — `watchtower_clear`
  (sync), `ble_scan` (via the Bluetooth manager), `wifi_defense_scan` (WIDS scan
  in a background thread) — and logs the outcome, visible in `/api/cyd/nodes`.
- ✅ Operator UI: **Ragnar Mesh → CYD Nodes** sub‑tab (node list with live
  counts + token generate/list/revoke).
- ⏳ `/api/cyd/status` `nets_24`/`nets_5` are placeholders pending a wire to the
  WiFi‑analyzer cache.
- ⏳ ESP Web Tools flasher page (manifest stub included; needs the built `.bin`).
- ⏳ WiFiManager captive‑portal provisioning (drop creds from `config.h`).

See [docs/cyd-hybrid-node.md](../docs/cyd-hybrid-node.md) for the full design
and API reference.
