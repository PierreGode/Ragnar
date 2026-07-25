# 📊 WiFi Spectrum Analyzer

A passive, tri-band Wi-Fi RF troubleshooter built into Ragnar's web UI —
**Network → WiFi Analyzer** (the sub-tab after *Interfaces*). Think of it as a
software [Ekahau Sidekick 2](https://www.ekahau.com/products/sidekick/): the
same survey-and-heatmap workflow a wireless engineer expects, on a Raspberry Pi
Zero 2 W with an off-the-shelf Wi-Fi 6E dongle instead of a $4,000 instrument.

> **Strictly passive.** The analyzer only ever runs `iw dev <iface> scan -u
> passive`, which *listens for beacons* and **never transmits a probe request**
> to any AP, and reads the radio's own channel table with `iw phy`. No frame is
> injected. It is a diagnostic/troubleshooting tool, not an attack tool. (`-u`
> only changes how the results are *printed* — see the Wi-Fi 7 note below.)

---

## What it shows

For every beaconing BSS it hears:

| Field | Source |
|-------|--------|
| **SSID** (or *hidden*) | beacon SSID IE |
| **BSSID** | beacon header |
| **RSSI (dBm)** | radiotap signal |
| **Band** — 2.4 / 5 / 6 GHz | centre frequency |
| **Channel** (number) | centre frequency |
| **Channel width** — 20/40/80/160/320 MHz | HT / VHT / HE / EHT operation IEs |
| **Security** — Open/WEP/WPA/WPA2/WPA3 | RSN / WPA IE (SAE ⇒ WPA3) |
| **Channel utilisation %** | the AP-advertised **BSS-Load IE** — a real, passive medium-busy metric |
| **Stations** | BSS-Load IE station count |
| **DFS/radar** | flagged live from `iw phy <phy> channels` |
| **Vendor** | OUI lookup (nmap/IEEE prefix DB; locally-administered bit ⇒ *Randomized/private*) |
| **Generation** — Wi-Fi 4/5/6/6E/7 | HT/VHT/HE/EHT capability IEs |
| **Max PHY rate** | derived from generation × width × spatial streams (NSS) |
| **Spatial streams (NSS)** | HT/VHT/HE MCS maps |
| **SNR** | RSSI − noise floor from `iw survey dump` (when the radio reports it) |
| **Security detail** | PMF/MFP (off/capable/required), 802.1X-Enterprise, WPS, 802.11k/v/r roaming |
| **TX power / country / DTIM** | TPC report, Country and TIM IEs when advertised |

Supported bands are detected **per radio**, so the tool lights up 2.4/5/6 GHz on
the Alfa AWUS036AXM and 2.4/5 GHz on the Pi's onboard radio automatically.

### Wi-Fi 7 (802.11be) detection

`iw` (through at least 6.9) has **no scan-side EHT printer**: a Wi-Fi 7
beacon's EHT IEs are silently dropped from `iw scan` output, so the AP would
be mislabelled Wi-Fi 6/6E from the HE IEs it also advertises. The analyzer
therefore scans with `-u` ("print unknown IEs"), which makes iw hex-dump the
undecoded IEs as `Unknown Extension ID (…)` lines, and recognises the raw
extension IDs itself: **106** (EHT Operation, also parsed for 320 MHz width
and the wide-channel centre), **107** (Multi-Link) and **108** (EHT
Capabilities). The decoded `EHT capabilities:` section headers are still
matched too, so nothing breaks when iw eventually learns to print them.

---

## AP inventory, networks & export

The AP table is sortable on 9 columns (SSID, Vendor, Band, Channel, Width, Rate,
Signal, Security, Utilisation), with a **search** box, an **issues-only**
filter, and a **generation filter** (Wi‑Fi 7 / 6E / 6 / 5 / 4 / legacy — applies
to both the AP and Networks views). Generation and security are shown as inline
badges (Wi‑Fi 6E, 802.1X, PMF, WPS, 11k/v/r). A **Networks** view collapses
BSSIDs that share an SSID into one logical network (bands, AP count, best
signal). **Export CSV** dumps the full
enriched inventory for offline analysis.

---

## Change tracking (session history)

Every BSSID is remembered across scans in `data/wifi_analyzer_db.json`
(`seen_count`, `first_seen`, a rolling RSSI history and per-AP max/min). Each
scan diffs against the previous one and surfaces a **"Since last scan"** strip:

- **＋ new** — a BSSID heard for the first time,
- **－ gone** — a previously-seen BSSID that dropped out,
- **▼ weakened** — an AP now ≥18 dB below its own peak (moved/failing/blocked).

New APs carry a **NEW** badge and each row shows an inline **RSSI sparkline** of
its recent history. `POST /api/net/wifi/history` resets the store. This is an
**operational** aid (coverage/movement), not the security WIDS — that lives in
the separate **WiFi Defense** tab.

---

## The spectrum graph — two views

A big center horizontal graph plots every AP on a per-band segmented axis
(2.4 | 5 | 6 GHz), x = channel, y = RSSI (−30 dBm top … −95 dBm bottom), colour =
signal strength (green = strong → red = very weak). DFS/radar channels are
shaded. Toggle between:

- **📊 Bar** — one bar per AP at its channel; bar **width tracks the channel
  width** (an 80 MHz AP is 4× wider than a 20 MHz one), height = RSSI.
- **◗ Cone/Dome** — the classic Wi-Fi-analyzer filled **bell curve** per AP,
  centred on its operating channel and spanning its channel width, peak = RSSI.
  This is the view that makes channel overlap and crowding obvious at a glance.

**WIDS pivot:** clicking a BSSID in a **WiFi Defense** detection (or a row of
its AP table) lands here with that AP pre-selected and marked by a red dashed
**⚠ WIDS** locator line + outline in the spectrum, a red *"Flagged by WiFi
Defense"* banner above the graph, and a red **⚠ WIDS** badge on its AP-table
row. The highlight persists across re-scans (auto-refresh keeps tracking the
rogue's RSSI) until dismissed from the banner; if the flagged BSSID isn't heard
in the current survey the analyzer re-scans once and the banner reports it as
not heard.

**On the device (1.44" LCD HAT):** the Bar view is also available head-less as
the **SPECTRUM** card in on-screen Network Diagnostic mode — a per-channel
occupancy graph for one band (height ∝ the strongest AP's signal, DFS/radar
channels hollow, busiest channel tick-marked); the joystick ↑/↓ picks the band.
It auto-scans the **widest-band adapter present** (plug in the Alfa AWUS036AXM
for 5/6 GHz — a 2.4-only onboard radio only ever shows 2.4) and names the
scanned interface in the header. See
[Display Controls](DISPLAY_CONTROLS.md#network-diagnostic-mode).

---

## Interference & channel planning

Per band you get a congestion chip (`clear` / `moderate` / `congested`) and a
**"best channel"** recommendation. The analysis surfaces:

- **Co-channel interference** — APs sharing the exact same channel (they take
  turns on the air, so each one's throughput drops).
- **Adjacent-channel overlap** — mainly a 2.4 GHz problem; the recommender only
  ever suggests the non-overlapping **1 / 6 / 11**.
- A per-channel **congestion score** weighting the number of co-/overlapping APs
  by their relative power and their advertised channel utilisation.

---

## Signal-radius estimate

Click any AP row to model its coverage. Using a **log-distance path-loss model**
(`RSSI = RSSI@1m − 10·n·log₁₀(d)`) the analyzer draws concentric coverage rings
for three thresholds and estimates how far *you* currently are from the AP:

| Ring | Threshold | Meaning |
|------|-----------|---------|
| voice | −67 dBm | VoIP / seamless roaming |
| data | −72 dBm | reliable data / video |
| edge | −80 dBm | usable edge of coverage |

The transmit-power assumption (`Tx dBm`, default 20 — auto-filled from the AP's
advertised TPC power when present) and the environment path-loss exponent (`n`,
default 3.0 for indoor) are adjustable, and the model and its assumptions are
shown so the numbers stay honest. An **Env preset** dropdown sets `n` for common
environments — Open/LOS (2.0), Open indoor (2.5), Light indoor (3.0), Office/few
walls (3.5), Heavy walls (5.0) — or **Custom** to type your own; the preset and
the manual `n` field stay in sync. Through walls, a single free-space model reads
*long* (it attributes wall loss to distance), so bump `n` up (or use two-point
calibration) for wall-heavy paths.

### Calibration (make the estimate site-accurate)

Four knobs let you calibrate the model to your adapter and environment rather
than a textbook assumption:

- **RSSI offset (dB)** — per-adapter correction added to every reading (e.g. an
  Alfa that reads 3 dB low → `+3`).
- **Antenna gain (dBi)** / **Cable loss (dB)** — receive-chain EIRP correction
  folded into the reference level.
- **Two-point calibration** — enter two measured `(distance, RSSI)` points and
  the analyzer solves the **path-loss exponent** and the **reference RSSI@1m**
  for *this* site (`n = (RSSI₁−RSSI₂) / (10·log₁₀(d₂/d₁))`), then applies them.
  The model is then labelled **calibrated** rather than *assumed*.

Even calibrated, it remains an **estimate**, not a survey-grade measurement.

---

## Coverage heatmap (walk-around survey)

The Ekahau workflow, in miniature:

1. Pick the **target AP** to map.
2. Optionally **load a floorplan** image.
3. **Walk the space and click where you're standing** — each click takes a live
   passive reading of that AP (RSSI, SNR, noise, band/channel) and drops a
   sample at that spot.
4. Samples are interpolated (**inverse-distance weighting**, computed in real
   metres) into a coverage heatmap with a **calibrated colour scale** and
   labelled legend (excellent/good/fair/weak/dead break points).

**Real-world scale, rulers and zoom** — the plan is a large **square canvas**
with **metre rulers along the left and bottom edges** and a matching grid, so
you always know how far apart things are. Set the **Floor size (m / side)** to
the real size of the space — anything from a 10 m² room (~3.2 m/side) to a
300+ m² office (~17.3 m/side); the live area (m²) is shown next to the input,
and the rulers, IDW blending, predicted distances and column sizes all follow
it. **Scroll on the plan (or use the − / + / ⤢ Fit buttons) to zoom** up to
16×, and **drag to pan** while zoomed — the rulers re-scale adaptively (down to
centimetre ticks) and a header line shows the visible window (e.g. "viewing
4.3 × 4.3 m"). Zooming never moves your data: samples, walls and APs stay
anchored to their true floor positions.

**Active survey (throughput + latency)** — tick **Active test on click** to also
run an Ekahau-style performance measurement at each point: it pings the gateway
for **latency / jitter / loss** and measures **throughput**. Give it a LAN
**iperf3 server** (best — measures both up *and* down) or leave it blank to use a
WAN **download speed test**. The result is stored on the sample, so the heatmap
**Metric** toggle can map **RSSI (dBm)** (−90→−30), **SNR (dB)** (5→40),
**Throughput ↓/↑ (Mbps)** or **Latency (ms)** (lower = greener). **Test now** runs
a one-off measurement without dropping a sample. Samples lacking the chosen
metric render grey and are excluded from interpolation.

**Named surveys** — save the current floorplan + samples under a name, then
list/load/delete them (`data/wifi_surveys.json`) to keep several sites or
before/after comparisons. **📄 Report** opens a printable one-page survey report
(heatmap image, coverage stats, band/channel plan, interference, security issues
and the full AP inventory) — print or "Save as PDF" from the browser dialog.

### Mesh survey (whole-SSID, per-node coverage)

Tick **Mesh** to survey an entire mesh / ESS instead of one AP. Pick the **SSID**
and each click records the RSSI of **every node (BSSID)** of that network at that
spot, tagging the **serving** (strongest) node — what a client there would
associate with. Two mesh-only metrics then light up:

- **Serving node** — colours each area by *which* node owns it (Node A / B / C…),
  so you can see each node's real coverage footprint and where a client hands off.
- **Hand-off zones** — colours by the margin between the two strongest nodes:
  **green** = good overlap (&lt;6 dB, clean roaming), **amber** = marginal,
  **red** = "sticky"/no overlap (&gt;12 dB — a client may cling to a far node),
  grey = only one node heard. The node registry + per-point node vectors persist
  with the survey.

### Design / predictive coverage

Switch the heatmap to **Design / Predict** mode to *plan* coverage instead of
measuring it — Ekahau's predictive-design feature in miniature:

1. **Draw walls** on the floorplan (click two points per wall) and pick the
   **material** — each carries a real attenuation: drywall 3 dB, wood 4, glass 6,
   brick 10, concrete 15, metal 20. Walls and columns are **colour-coded by
   material** so the construction reads at a glance — 🧱 brick red, glass white,
   concrete grey, steel/metal blue, drywall beige, wood brown (a legend sits
   under the Design tools).
2. **Place AP nodes** — click where an AP would go. **Click again to drop more
   nodes and plan a whole mesh** (they're labelled AP1, AP2, …); **Undo AP** /
   **Clear APs** manage them. The **Floor size (m / side)** control above the
   plan sets the real metric scale (changing it re-scales existing nodes too).
3. **Place columns** — structural pillars are a *major* open-floor coverage
   killer, so drop them with the **⬤ Column** tool: pick the **material**
   (concrete 15 dB, steel/metal 20, brick 10) and the **radius (m)** (a typical
   pillar is ~0.3 m). Each column is drawn to scale (amber, hatched) and **casts
   a signal shadow** on the far side — any AP→point line that passes through the
   pillar loses its dB. **Undo column** / **Clear columns** manage them.
4. Tick **Predict coverage** — the map fills with **modelled RSSI** everywhere.
   With several nodes, each spot shows the **best signal any node delivers**
   (served by its strongest node — exactly how a real mesh behaves), using the
   log-distance path-loss model **minus the summed loss of every wall the
   node→point line crosses and every column it passes through**. Move nodes,
   walls or columns and it updates live.

**Drag to rearrange:** in Design mode you can **grab and drag** any placed
object — drag an **AP node** or a **column** to move it, drag a **wall endpoint**
(the small handles) to re-angle a wall, or drag a **wall's body** to slide the
whole wall. The cursor shows a grab hand over anything draggable, and the
predicted coverage re-renders live as you move. (Dragging never drops a new
object; click empty space to add one.)

Walls, columns and the modelled AP nodes persist with the heatmap (and inside
saved surveys). The prediction math (`predict_point_rssi` per node with wall
segment-crossing + `_seg_circle_hit` column shadowing, `predict_point_rssi_multi`
for the best-node mesh combine) is identical in the Python backend and the JS
renderer, and is covered by selftest.

Live samples persist in `data/wifi_heatmap.json`; **Clear** starts a fresh
survey.

---

## Bluetooth / BLE overlay (2.4 GHz)

Tick **📶 Bluetooth** in the toolbar to overlay nearby **Bluetooth Classic
(BR/EDR)** and **Bluetooth Low Energy** activity onto the 2.4 GHz segment of the
spectrum — the two radios share the ISM band, so BT/BLE is a real, often
invisible, source of 2.4 GHz Wi-Fi interference.

**What it draws:**

- **BLE advertising markers** — the three fixed advertising channels **37 / 38 /
  39** at **2402 / 2426 / 2480 MHz**, placed (by design) in the gaps around Wi-Fi
  1/6/11. Marker opacity scales with how many advertisers are heard.
- **A band-wide "BT hopping" strip** — BLE data (37 channels) and Classic BT (79
  channels) frequency-hop across the whole band, drawn as a hatched activity
  strip whose height scales with device count, proximity and Classic presence.
- **A device table** — every in-range device with **RSSI**, kind (BLE / Classic /
  dual-mode), **vendor** (IEEE OUI for public addresses, Bluetooth SIG company
  ID for randomised ones), and decoded **class-of-device** (Audio/Video, Phone,
  Wearable, …). Randomised (LE-privacy) addresses are tagged `rnd`. **Click any
  row to highlight that device on the spectrum** (like selecting a Wi-Fi AP): its
  RSSI is drawn as a level line across the 2.4 GHz band, with its energy marked
  on the three BLE advertising channels (BLE) or shaded band-wide (Classic, which
  hops). Click again to clear.
- **Per-channel BT pressure chips** — an estimated low/moderate/high interference
  level for Wi-Fi channels 1/6/11/13.

**It is a device-activity estimate, not a measured RF sweep.** We ask the
Bluetooth controller (via BlueZ) which devices it can hear and model where their
energy lands — a true per-Hz energy sweep of BT hopping needs an SDR. Capture is
**receive-only**: device *discovery* only, never pairing or connecting.

**Hardware / capture.** Discovery runs over BlueZ's D-Bus API (`python3-dbus`),
falling back to `bluetoothctl` text mode if unavailable. Any BlueZ controller
works — the Pi's **onboard** radio or the tri-band **Alfa's built-in BT 5.2**.
When the Alfa combo dongle is plugged in its controller enumerates on **USB**
while the onboard radio is **UART**, so the scanner prefers the USB controller
(same adapter as the Wi-Fi capture). On a combo chip the Wi-Fi and BT radios
time-share the RF front-end, so the overlay is best-effort and duty-cycled —
running BT discovery and Wi-Fi monitor capture flat-out can cost frames on both.

The scan always runs on the controller it selected: a just-plugged USB dongle
shows up in `hciconfig` a moment before `bluetoothd` registers it on D-Bus, so
the scanner waits briefly for the chosen adapter to appear rather than falling
back onto the onboard radio. That fallback used to make the *first* overlay
scan run on the onboard `hci0` (slow, and mislabelled) before settling on the
dongle — subsequent scans were always fast on the right controller.

## Zigbee / 802.15.4 overlay (via Huginn)

Tick **🐝 Zigbee** to overlay nearby **Zigbee / Thread / 802.15.4** activity onto
the 2.4 GHz spectrum — another real Wi-Fi interference source (smart-home hubs,
bulbs, sensors, locks) that shares the band.

The Pi has no 802.15.4 radio, so this uses a **HuginnESP companion**
(ESP32-C5/C6/H2) on demand — **no wardriving needed**. On toggle, Ragnar opens
the Huginn's USB-serial port, sends the `zigbee` command, reads the streamed
`{"type":"ZIGBEE",…}` device lines for ~8 s while Huginn hops **channels 11–26**,
then sends `stop`. **The toggle stays greyed out until a Huginn is detected on
USB** (`/api/net/zigbee/status`).

**What it draws** — a labelled marker per occupied Zigbee channel (Z11–Z26 at
2405–2480 MHz; 15/20/25/26 fall in the Wi-Fi 1/6/11 gaps), scaled by how many
devices and how strong; a **device table** (address, proto, channel, PAN ID,
vendor from the EUI-64 OUI, RSSI) — **click a row to highlight it** on the
spectrum like a Wi-Fi AP; and an estimated **per-Wi-Fi-channel Zigbee pressure**.

**Caveats.** Huginn is a packet sniffer, so this is device-activity, not a
per-channel energy sweep. One ESP32-C5 can't do Wi-Fi and 802.15.4 at once, so
the scan briefly switches the Huginn into zigbee mode (a board without an
802.15.4 radio answers with a "not compiled in" notice). If wardriving is
running it owns the serial port — stop it first to sniff on demand. Receive-only.

## True-RF Waterfall (HackRF SDR)

The Bar and Dome views draw the *beacon* picture (what APs announce). The
**📈 Waterfall** view is different: it measures the **actual radio energy on the
air** with a Software Defined Radio — so it sees what nothing else here can:
microwave ovens, drones, analog cameras, jammers, the true noise floor, and
Wi-Fi/BT energy as *measured* rather than modelled.

**The button stays greyed out until Ragnar actually detects a HackRF.** The UI
polls `/api/net/sdr/status` and only un-greys 📈 Waterfall when the `hackrf`
tools are installed **and** a board answers; otherwise the tooltip tells you
what's missing. Bar/Dome keep working with no SDR at all.

**What it shows** — a live **spectrum line** with **max-hold** on top, above a
scrolling **time × frequency × power waterfall**, with your Wi-Fi channel ticks
(and BT advertising markers in 2.4 GHz) overlaid on the measured energy. Change
the band selector to retune the sweep (2.4 / 5 GHz).

**How it works** — `sdr_spectrum.py` runs `hackrf_sweep -f LO:HI`, parses its
power-per-bin CSV, assembles each sweep into a fixed-width frame plus a
cumulative max-hold, and streams frames to the browser. **Receive-only** — an
SDR sweep never transmits.

**Hardware.** Needs a **HackRF One** (1 MHz–6 GHz — covers 2.4 *and* 5 GHz).
The cheap RTL-SDR only reaches ~1.7 GHz and **cannot** see these bands. Install
the tools with `apt install hackrf` (done by `install_ragnar.sh` / ensured by
`update_ragnar.sh`). The HackRF draws real USB current — a **powered USB hub** is
recommended on the Pi. Wi-Fi 6 GHz is within HackRF's range but its band edges
vary by region, so only 2.4/5 ship as presets.

## Hardware

Tuned for the **Alfa AWUS036AXM** (MediaTek MT7921AU, `mt7921u` driver — a
Wi-Fi 6E 2.4/5/6 GHz USB dongle) on a **Raspberry Pi Zero 2 W**, but it runs on
any `nl80211`/`cfg80211` radio `iw` can drive (it also works on the Pi's onboard
`brcmfmac`). 6 GHz and DFS/radar channels require **passive** scanning by
regulation — which is exactly what this tool does.

Requires the `iw` package (installed by `install_ragnar.sh` /
`install_packages.sh`).

---

## API & CLI

All endpoints are passive and read-only except the heatmap store.

| Endpoint | Purpose |
|----------|---------|
| `GET /api/net/wifi/interfaces` | wireless interfaces + supported bands |
| `GET /api/net/wifi/scan?interface=&band=` | passive survey + spectrum + interference + groups + change diff |
| `GET /api/net/wifi/radius?interface=&bssid=&tx=&ple=&rssi_offset=&antenna_gain=&cable_loss=&rssi0=` | signal-radius rings (with calibration) |
| `GET /api/net/wifi/calibrate?d1=&rssi1=&d2=&rssi2=` | two-point path-loss fit (n + ref RSSI@1m) |
| `GET/POST /api/net/wifi/heatmap` | get / add-sample / sample-live (optional `active` throughput) / `throughput` one-off / floorplan / clear |
| `GET/POST /api/net/wifi/surveys` | list / save / load / delete named surveys |
| `GET/POST /api/net/wifi/history` | get AP history DB / reset it |
| `GET /api/net/wifi/selftest` | parser + analyzer self-test |
| `GET /api/net/bt/controllers` | Bluetooth controllers (USB-first: Alfa before onboard) |
| `GET /api/net/bt/scan?controller=&duration=` | BT/BLE discovery + 2.4 GHz interference model |
| `GET /api/net/bt/selftest` | Bluetooth parser + model self-test |
| `GET /api/net/sdr/status` | HackRF detection (gates the Waterfall button) + capture state |
| `POST /api/net/sdr/start` `{band}` | start the HackRF sweep (2.4/5) |
| `POST /api/net/sdr/stop` | stop the sweep |
| `GET /api/net/sdr/frames?since=` | new waterfall frames + max-hold since a seq |
| `GET /api/net/sdr/selftest` | sweep parser + frame-assembly self-test |
| `GET /api/net/zigbee/status` | HuginnESP detection (gates the Zigbee toggle) |
| `GET /api/net/zigbee/scan?duration=&port=` | on-demand Huginn 802.15.4 sniff → channel markers + devices |
| `GET /api/net/zigbee/selftest` | Zigbee line-parser + overlay-model self-test |

```bash
python3 wifi_analyzer.py interfaces
python3 wifi_analyzer.py scan --interface wlan0 --band all
python3 wifi_analyzer.py radius --interface wlan0 --bssid aa:bb:cc:dd:ee:ff
python3 wifi_analyzer.py selftest

# Bluetooth / BLE 2.4 GHz overlay (bt_scanner.py)
python3 bt_scanner.py controllers
python3 bt_scanner.py scan --duration 12
python3 bt_scanner.py selftest

# True-RF waterfall (sdr_spectrum.py — needs a HackRF)
python3 sdr_spectrum.py detect
python3 sdr_spectrum.py sweep --band 2.4 --frames 5
python3 sdr_spectrum.py selftest

# Zigbee / 802.15.4 overlay (needs a HuginnESP companion)
python3 zigbee_scan.py detect
python3 zigbee_scan.py scan --duration 8
python3 zigbee_scan.py selftest      # + zigbee_overlay.py selftest
```

The Bluetooth scanner ships its own offline self-test — **28 checks** covering
the D-Bus/`bluetoothctl` parsers, class-of-device decode, public-vs-random
address handling, OUI/company-ID vendor attribution, device classification
(BLE/Classic/dual), controller enumeration, and the 2.4 GHz interference model.

The self-test (`selftest`) drives the beacon parser (2.4/5/6 GHz, HT/VHT/HE
widths, a Wi-Fi 7 / 802.11be AP with EHT IEs and 320 MHz width, BSS-Load,
security, generation, NSS, roaming, TPC), the congestion/interference
analysis, SSID/device grouping, the AP-history change detector, the
frequency↔channel conversions, the radius model and its two-point
calibration, and the named-survey store — all against synthetic `iw`
output, **91 checks, all offline**.
