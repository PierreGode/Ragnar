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
 ├─ touch console of Ragnar status    ◄───  status frames
 ├─ 2.4 GHz sniff + BLE scan (own radio) ─► sensor reports
 └─ operator taps an action           ───► action requests
        over the serial cable (default), or the REST API on the legacy WiFi build
```

## How it connects to the Pi: a cabled serial console

The CYD is a **cabled companion**: it links to the Pi over a serial line (USB or
GPIO) and the two exchange newline-delimited JSON. This is the default and the
supported path — the whole on-screen console (dashboard, RF waterfall, mesh
roster, Net-Conn, traffic, etc.) is built on this link. A legacy WiFi build still
exists as a compile flag but is intentionally limited (see the note below).

The transport is chosen at compile time (`CYD_TRANSPORT_SERIAL` in `config.h`):

- **Serial (default, `=1`) — the cabled console.** The node is wired to
  the Pi and exchanges newline-delimited JSON over USB; **no WiFi association, no
  device token, no provisioning**, and the 2.4 GHz radio is free for sensing the
  whole time. The Pi end is `cyd_serial_bridge.py`, a self-managing daemon
  thread started by the webapp — it only opens a port while the **USB-serial
  bridge** toggle (Mesh → CYD Nodes) is on *and* a device is present, and
  reconnects on unplug. Line protocol:
  ```
  node → Pi : {"t":"in", <sensor counts>}          (sensor report)
              {"t":"ac","node":..,"action":".."}     (operator tap)
  Pi → node : {"t":"st", <the /api/cyd/status dict>} (dashboard, ~2 s)
  ```
  The bridge feeds reports into the same registry and dispatches actions through
  the same allowlist as the HTTP path — the endpoints below are the WiFi path's
  door to the very same machinery.

  The link is **UART0** either way, so it needs no firmware change: run it over
  the **USB cable** (auto-detected, `/dev/ttyUSB*`), or over the CYD's **P1
  header** (VIN/GND/TX0/RX0) wired straight to the Pi's GPIO UART — both 3.3 V,
  no level shifter. Pick the port with the **Serial port** field under Mesh →
  CYD Nodes (empty = auto-detect USB; `/dev/serial0` = the GPIO wiring), which
  sets `config['cyd_serial_port']` — `POST /api/cyd/serial/port`. SPI isn't
  usable: the board breaks out only 3 free pins (one input-only).

  Auto-detect only claims the USB-UART bridges CYDs ship with (Silicon Labs
  CP210x, QinHeng CH340/CH9102 — `/dev/serial/by-id` names containing `cp210`,
  `1a86`, …). It never takes a port whose by-id name marks a GPS (u-blox,
  `gps`/`gnss`, Prolific BU-353), and it only falls back to a bare
  `ttyUSB*`/`ttyACM*` when that port has no by-id name. The bridge publishes
  the port it holds and wardriving skips it, so claiming a GPS here would hide
  the GPS from wardriving ("GPS: no"). It also skips any port another
  component holds (`serial_claims.py`), e.g. a Meshtastic Heltec V3 on the
  same CP2102 chip. If the Meshtastic link later pins an auto-detected port,
  the bridge hands it back. If your CYD uses some other bridge chip, or shares
  a chip type with another device, set the port explicitly.

- **WiFi (`=0`) — legacy, limited.** The node joins WiFi and calls the REST API
  below, authenticated by a Bearer device token, provisioned via the on-device
  captive portal. This predates the cabled console and only carries **status +
  the basic actions** — the RF waterfall, mesh roster, Net-Conn and traffic
  screens are **serial-only** (they stream over the cable). Use the serial build
  unless you specifically need an untethered node and can live without those.

Serial I/O in the bridge is **poll-based** (`in_waiting`+`read`, never
`readline`/`select`) — Ragnar runs with 700+ FDs and pyserial's select() path
breaks past FD 1024 (the landmine `roomscan_bridge.py` documents).

## The one hard constraint: a single 2.4 GHz radio

The WROOM‑32 has one 2.4 GHz radio shared by WiFi and BT, and **cannot be
joined to an AP while sniffing other channels**. The firmware therefore
**time‑shares** in a duty cycle (tunable in `config.h`):

| Phase | State | Does |
|------|-------|------|
| SYNC (~2.5 s) | linked to the Pi (cable) | read pushed status, send counts, flush queued actions |
| SNIFF (~6 s) | radio started, promiscuous | hop ch 1..13, count beacons/probes/deauths, unique BSSIDs (feeds SCAN/DEFENSE/SIGINT). NB: use `WiFi.disconnect(false,...)` — `disconnect(true)` powers the radio OFF and promiscuous then captures nothing (all counts 0). |
| BLE (~3 s) | disconnected | passive advertisement scan (count) |

Consequences: the display shows the **last‑synced** values (near‑real‑time, not
live), and WiFi‑sniff and BLE never run at full rate simultaneously.

**Not available on this hardware:** 5 GHz, WiFi 6, simultaneous WiFi+BLE at full
rate, and the real Flask web page (the screen is a native LVGL‑style panel).

## Authentication

The **cabled default needs no token** — the serial link is physical, so the Pi
trusts what arrives on its own UART. Tokens matter only for the **legacy WiFi
build**: a CYD on WiFi is not a tailnet/mesh peer and cannot use WireGuard
identity, so it carries an **operator‑issued Bearer token**
(`shared_data.config['cyd_device_tokens']`), matched constant‑time in
`cyd_node.valid_token`. That token role is enforced in
`webapp_modern.check_authentication()` and grants **only** the device‑facing
endpoints (`GET /api/cyd/status`, `GET /api/cyd/wf`, `POST /api/cyd/ingest`,
`POST /api/cyd/action`) — everything else stays session‑gated, fail‑closed. It
mirrors the existing mesh *share‑token* role.

## API reference

### Device‑facing (CYD device token required)

**`GET /api/cyd/status`** — compact, flat status for the touch console (the
serial bridge pushes this same dict as a frame). `unit` is the mesh Viking
short‑name, or **`Ragnar`** when there's no mesh identity:

```json
{ "unit": "Ragnar", "mesh_nodes": 3, "nets_24": 11, "nets_5": 7, "threat": 15,
  "bluetooth": "idle", "uptime": 84213, "iface": "eth0", "ip": "192.168.1.5",
  "wardrive": "off", "alerts": 2, "worst": "high", "netint": "ok",
  "pwn": "off", "tf_run": 0, "ts": 1789225000 }
```

The shape is intentionally flat — the firmware parses it with lightweight string
matching (no JSON library). It is built by `_cyd_build_status_dict()` and every
field is refreshed **off the hot path** (wardrive state, `iw scan dump` band
counts, Watchtower/net-integrity summaries all come from background-refreshed
caches) so a slow probe can never stall the status feed or the serial bridge.
`nets_24`/`nets_5` are distinct BSSIDs per band from the kernel's cached scan
(non-disruptive); `0`/`0` just means no recent scan is cached.

**`POST /api/cyd/ingest`** — a node's 2.4 GHz sensor report:

```json
{ "node": "cyd-01", "beacons": 42, "probes": 7, "deauths": 0,
  "frames": 310, "bssids": 18, "ble_adv": 5, "rssi": -58 }
```

Unknown fields are dropped; counts are coerced to non‑negative ints. Returns the
node's stored summary.

**`POST /api/cyd/action`** — request an allowlisted operator action. Validated
against `cyd_node.ALLOWED_ACTIONS`, then **dispatched to the live subsystem** in
`_cyd_dispatch_action` (blocking work runs in a background thread; the outcome is
logged against the node and shown in `/api/cyd/nodes`). Current allowlist:
`wifi_defense_scan`, `ble_scan`, `watchtower_clear`, `wardrive_start` /
`wardrive_stop` / `wardrive_toggle`, `network_scan`, `speed_test`,
`captive_check`, `traffic_toggle`, `ap_toggle`, `scanner_start` / `scanner_stop`,
`service_restart`, `ragnar_update`, `pwn_swap`. A spoofed node can only ever ask
for these — never arbitrary operations.

**`GET /api/cyd/wf`** — one downsampled RF-waterfall row (the serial bridge
streams these). Drives Ragnar's SDR (HackRF via `sdr_spectrum`, else RTL-SDR via
`rtl_sdr`), piggybacking an already-running sweep rather than fighting it;
returns a 120-bin row, `{"waiting":1}`, or `{"err":"no SDR"}`.

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

## Provisioning & flashing

Flash it from `cyd_firmware/flasher/index.html` (ESP Web Tools, Chrome/Edge,
committed bins under `flasher/firmware/` — the **USB-serial build**), or build
and upload with `arduino-cli`.

- **USB-serial build (default):** no provisioning — cable it to the Pi and turn
  on the **USB-serial bridge** toggle (Mesh → CYD Nodes).
- **WiFi build (`CYD_TRANSPORT_SERIAL 0`):** the firmware ships **no baked-in
  secrets**; on first boot — or when it can't connect, or when **BOOT** (GPIO0)
  is held at power-on — the node raises a **setup portal**: a SoftAP
  `Ragnar-CYD-setup`
(password `ragnarcyd`) + a captive form for WiFi SSID/password, Ragnar URL,
device token and node name. Values persist in NVS (`Preferences`), the node
reboots, connects, and appears under `/api/cyd/nodes`. Hold **BOOT** at power-on
to re-provision. See [`cyd-firmware.md`](cyd-firmware.md).

## WiFi-Defense sensor (2.4 GHz offload)

The node's own radio is a **coarse second WiFi-Defense vantage point** — not a
replacement for the Pi's monitor-mode WIDS, but a continuous 2.4 GHz watch that
frees the Pi's radio and adds a viewpoint. `cyd_sensor.py` folds its detections
into Ragnar's **existing** alert plumbing: it writes JSON-lines to
`/var/log/ragnar/cydsensor.jsonl`, which **Watchtower already tails** (any
`*.jsonl` there is picked up), so they appear in the unified Watchtower feed +
Pushover with no parallel system. Two Stage-1 detections:

- **Deauth/disassoc flood** (`CYD-DEAUTH-FLOOD`, high) — from the deauth count
  the node already sends; `≥ cyd_deauth_flood_threshold` (default 8) in a report
  window fires, deduped for `cyd_deauth_realert_sec` (default 60 s).
- **New / rogue AP** (`CYD-NEW-AP`, medium) — the firmware reports the beacons it
  saw this window (`aps`: BSSID/SSID/channel/RSSI, ≤ 32); the first report from a
  node **seeds a baseline silently**, then a BSSID not in the baseline alerts.
  `cyd_reset_baseline` / `cyd_sensor.reset_baseline()` re-learns after a move.

Records use the schema `watchtower.normalize` expects (`severity`/`code`/
`summary`/`src`/`module: cyd:<node>`). This is 2.4 GHz only, and coarse — the Pi
still owns real monitor-mode WIDS, PMKID/handshake analysis, and 5/6 GHz.

## Boot animation

At power-on the node plays the full-screen splash (`ragnar-240x320-tools.gif`) at
its **natural 15 s speed and loops it until the Pi's Ragnar service is up** — the
first status frame over serial flips the `g_bootRagnarUp` flag and the loop ends
(after a 5 s minimum). If the node reset while the Pi was already up, the first
status arrives almost immediately, so it stops after just the 5 s minimum — a
quick splash instead of the full clip. A hard cap (`CYD_BOOT_ANIM_MAX_MS`, 90 s)
keeps a Pi-less node from looping forever. The GIF is decoded **on-device** by the
`AnimatedGIF` library from a compact copy embedded in the firmware
(`ragnar_boot_gif.h`, ~1 MB) — the ESP32 cannot read the Pi's web `.gif`.

Tunables in the sketch: `CYD_BOOT_ANIM_MS` (minimum splash, default 5000),
`CYD_BOOT_ANIM_MAX_MS` (give-up cap, default 90000), `CYD_GIF_BE` (flip 0↔1 if
colours look byte-swapped). The clip is 240×320 and fills the panel, so
`GIF_Y_OFF` is 0 (a 240-wide *square* clip would be centred). Over the WiFi
transport there's no serial readiness signal during boot, so it's a plain fixed
`CYD_BOOT_ANIM_MS` splash (`playBootAnimation` is called with min==max).

**Regenerating the embedded animation** from a source GIF (needs `ffmpeg`). Note a
GIF's *size* is driven by frame COUNT, not playback duration — `fps` sets both the
number of frames sampled and the per-frame delay, so `fps=4` over a 15 s clip is
60 frames that also play back over 15 s at natural speed (no `setpts` needed):

```bash
IN=web/images/ragnar-240x320-tools.gif     # 240x320 / 300f / 15 s / 6.5 MB source
# native 240x320, fps=4 (=> 60 frames @ 250ms = 15.0s natural), 32-colour palette,
# dither=none (compresses graphic content far better than bayer); 2-pass:
ffmpeg -y -i "$IN" -vf "fps=4,palettegen=max_colors=32:stats_mode=diff" pal.png
ffmpeg -y -i "$IN" -i pal.png -lavfi "fps=4 [x];[x][1:v] paletteuse=dither=none" small.gif
# embed as a PROGMEM byte array (keep it under the flash headroom — see below):
python3 - small.gif cyd_firmware/ragnar_cyd/ragnar_boot_gif.h <<'PY'
import sys; d=open(sys.argv[1],'rb').read(); o=open(sys.argv[2],'w')
o.write('#ifndef RAGNAR_BOOT_GIF_H\n#define RAGNAR_BOOT_GIF_H\n#include <Arduino.h>\n\n')
o.write('const uint8_t ragnar_boot_gif[] PROGMEM = {\n')
[o.write('  '+','.join(map(str,d[i:i+20]))+',\n') for i in range(0,len(d),20)]
o.write('};\nconst uint32_t ragnar_boot_gif_len = %d;\n\n#endif\n'%len(d))
PY
```

Keep the embedded size modest — the app partition is 3 MB and the firmware sits
at ~88 % with this splash. It's a trade of frames×colours against flash: for a
smaller build cut colours (`max_colors=24`) or frames (`fps=3`); for smoother
motion raise `fps` and watch the flash %. Playback length is independent — the
`fps` value already sets it (natural timing), so leave `setpts` out.

## On-screen console (app launcher)

The CYD's screen is a native, Ragnar-themed **touch console** — not the web page
(no browser), and not framed as a mesh node. A HOME launcher of tiles drills into
full screens, each with a back bar:


> **HOME tile labels** use a small proportional GFX font (`ragnar_label_font.h`,
> DejaVuSans-Bold rendered to ~10px caps via PIL) — a bit smaller than the size-2
> built-in font, since the bitmap font only scales in whole steps. It's applied
> ONLY to the tile labels (`gfx->setFont(&RagnarLabel)` then `gfx->setFont()` to
> restore), so every other screen keeps the built-in font. Regenerate with the PIL
> script kept with the firmware.

> **UI stays responsive during sensing.** The 2.4 GHz sniff dwell and the BLE
> scan (run asynchronously) both service touch + the display cooperatively, so
> touch never goes dead mid-cycle. The panel repaints per-field (a full wipe only
> on a screen change), and the LED is a steady link indicator — so there's no
> per-phase flicker or LED blink.

The launcher is a **dense, data-driven grid** of half-height tiles (add one row
to `g_menu[]` to add a feature); each tile shows a compact live value.

| Tile | Screen |
|------|--------|
| **DASH** | Ragnar status: threat, alerts+worst, 2.4/5 GHz counts, wardrive, link (iface/IP), last-sync |
| **DEFEND** | this node's live 2.4 GHz Defense view (deauth/APs/probes/BLE) — what it reports to WiFi Defense |
| **ALERTS** | count + worst severity + the latest Watchtower findings, pushed from Ragnar |
| **SCAN** | raw 2.4 GHz counters (beacons/APs/probes/deauth/BLE/frames) |
| **SIGINT** | a native **radar/dome** of the APs it hears — centre = the node, radius ∝ RSSI, colour by strength |
| **WFALL** | **RF waterfall** streamed from Ragnar's SDR (see below) |
| **NET** | status header + a grid of subpages/actions: **Net Int** (integrity monitor detail), **Watchtower** (→ ALERTS), **Wardrive** (live wardriving page), Speed test, Captive check, Airspace sweep, WIDS |
| **WARDRIVE** | own page (NET → Wardrive) with **live** status in a single centred column, large fonts: RUNNING/IDLE + band, then NETWORKS (headline), BLE, COMPANIONS, GPS, and a Start/Stop button that toggles in place (greys to `starting…`/`stopping…` until confirmed). Refreshed off the hot path; disabled unless wardriving is enabled in Ragnar |
| **NETCONN** | drive the **Pi's** WiFi: scrollable scan list → tap an SSID → on-screen keyboard for the password → connect; plus AP-mode toggle and scanner start/stop |
| **MESH** | scrollable roster of mesh nodes (online dot · name · IP), streamed from `mesh_manager` |
| **TRAFFIC** | live capture stats (throughput/pps/hosts/conns/alerts) + a start/stop button |
| **SETTINGS** | device-local (NVS): BLE scan on/off, backlight, **Invert colors** (INVON/INVOFF), **Flip 180** (rotation 2 + touch axes XOR'd to match); plus Ragnar update, Restart service, Pwnagotchi swap (shown only when installed), and a touch-test/orientation screen |
| **CTRL** | the allowlisted action buttons (WIDS scan, BLE scan, Watchtower clear, restart Ragnar) |

The header shows the unit's identity — its mesh Viking short-name (e.g.
`Yrsa Wolfsbane`), or the brand **`Ragnar`** (big R) when there's no mesh name.

### Actions & the serial protocol

**Action progress feedback.** The Action subpage shows an animated spinner + an
elapsed clock while an action runs (so a slow Pi Zero never looks frozen), and for
time-bounded actions a live **countdown + progress bar**. The Pi sends `act_dur`
(seconds) and a "what's happening" `act_detail` from `_CYD_ACTION_INFO`
(e.g. WiFi Defense -> "listening 2.4GHz", 16 s); the node counts down locally from
when it first sees `running`. New-AP sensor findings are `info` severity (routine —
no Pushover).


Every tappable action maps to one entry in `cyd_node.ALLOWED_ACTIONS` and one
Ragnar subsystem call in `_cyd_dispatch_action` (a queued tap → an `{"t":"ac"}`
serial frame, or `POST /api/cyd/action`). A spoofed node can only ever request
the allowlist — never arbitrary ops. The serial bridge (`cyd_serial_bridge.py`)
also carries per-screen streams: `wr`→`wf` (waterfall rows), `mr`→`me` (mesh
roster), `wsr`→`wl` (Pi WiFi scan) and `wc` (connect by scan index). Its status
counters live in `/api/cyd/nodes` → `serial.dbg`.

### RF waterfall (streamed, SDR-gated)

The CYD has no SDR, so the waterfall is **Ragnar's** SDR spectrum, downsampled
and streamed to the console. `cyd_waterfall.py` auto-selects the attached radio —
HackRF (`sdr_spectrum`) or **RTL-SDR** (`rtl_sdr`) — and **piggybacks a sweep
that's already running** (e.g. the web RF-waterfall) rather than fighting it for
the one dongle. It returns a **120-bin** row (0..255) per frame, quantised over a
robust per-frame range (10th-percentile floor → dark, frame peak → pale) so the
palette reads right. The ESP32 scrolls it with the **same 5-stop inferno LUT the
web waterfall uses**, and below it draws a **live spectrum strip** (current signal
per frequency) and a **frequency axis** (lo · mid · hi MHz) — matching the web.
Tap the band bar to cycle **Sub-GHz ISM** (433/868/915/315) and a few **RF** bands
(fm/air/2.4); on an RTL-SDR the 2.4/5/6 requests fall back to 433.

- Transport: **serial only** (~8 rows/s over the cable; the console pauses its
  sniff cycle while the waterfall is open). The legacy WiFi build shows
  "USB-serial only". `GET /api/cyd/wf?band=&on=` exists for a manual/WiFi path.
- **Needs a HackRF/RTL-SDR attached to the Pi** — otherwise the screen shows
  "no SDR". It is a coarse postage-stamp, never the full web waterfall.

## Operator UI

**Ragnar Mesh → CYD Nodes** sub‑tab: a live list of reporting nodes (status dot,
last‑seen, per‑node beacon/AP/probe/deauth/BLE/frame tiles, recent action
outcomes) and device‑token management (generate — shown once — list, revoke).
Reachable whenever the Mesh tab is enabled (its default), independent of whether
Tailscale mesh itself is running.

## Roadmap

- [x] Wire `/api/cyd/action` to the live WIDS / BLE / Watchtower subsystems.
- [x] Operator UI (nodes list + token management).
- [x] Fill `nets_24` / `nets_5` from the kernel's cached scan (`iw scan dump`).
- [x] On-device captive-portal provisioning (WiFi build; no secrets in `config.h`).
- [x] USB-serial transport (`cyd_serial_bridge.py` + UI toggle) — cabled node.
- [x] Selectable serial port (USB auto-detect or `/dev/serial0` GPIO/P1 UART).
- [x] WiFi-Defense sensor: deauth-flood + new-AP → `cydsensor.jsonl` → Watchtower.
- [x] App-launcher console (dense data-driven tile grid).
- [x] RF waterfall streamed from the Pi's SDR — HackRF or RTL-SDR, piggybacking a running sweep.
- [x] NET subpages (Net Integrity, Watchtower detail) + Speed test / Captive / Airspace / WIDS.
- [x] SETTINGS: BLE, backlight, invert colors, flip 180, Ragnar update, restart, Pwnagotchi swap.
- [x] Traffic Analysis live-capture screen.
- [x] MESH roster (scrollable) streamed from `mesh_manager`.
- [x] Net-Conn: scan + connect the **Pi's** WiFi via an on-screen keyboard; AP + scanner toggles.
- [x] 5 s boot splash (`ragnar-240x320-tools.gif`, on-device AnimatedGIF decode).
- [x] ESP Web Tools flasher page + committed bins (`cyd_firmware/flasher`).
- [ ] Move the operator web UI out of the Ragnar Mesh tab (de-mesh, pending).
