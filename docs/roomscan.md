# RoomScan — touchscreen floor-plan tracer

RoomScan is a handheld **touchscreen device** that captures a room's shape on-site
and feeds it straight into Ragnar's **Coverage Heatmap** (Signal Intelligence).
It fills the one gap the web heatmap can't: getting a floor-plan when you have no
blueprint to upload. You walk the space, tap the corners, place the access points
Ragnar scanned, drop in the furniture/pillars that block Wi-Fi, and sync it all
back over the USB cable.

- **Hardware:** Waveshare **ESP32-S3-Touch-LCD-4B** ("Smart 86 Box") — ESP32-S3
  (16 MB flash / 8 MB PSRAM), 480×480 IPS panel (ST7701, RGB), GT911 5-point
  capacitive touch, native USB-Serial-JTAG.
- **Firmware source:** `roomscan_firmware/roomscan_s3_lcd/`
- **Ragnar bridge:** `roomscan_bridge.py` (USB-serial glue)
- **Web controls:** Network → **Signal Intelligence → Coverage Heatmap** → the
  **📐 RoomScan device** row.

## What it is (and isn't)

The web Coverage Heatmap already **uploads floor-plan images**, **places AP nodes**,
**draws walls** and **columns** (Design/Predict), and runs the **walk-around survey**.
RoomScan does **not** replace any of that and it measures no signal. Its job is to
**capture geometry** — the room outline, the on-site positions of real scanned APs,
and the furniture/structure that attenuates Wi-Fi — when there is no blueprint to
upload. The result becomes the base layer the existing Design/Predict tools build on.

## The round-trip (over one USB cable)

1. **Ragnar scans Wi-Fi** (the existing passive Signal-Intelligence scan).
2. **Push APs → device:** Ragnar sends that AP list to the device.
3. **On the device:**
   - Sketch the room — tap each corner, tap the first corner again to close it.
   - Place APs — tap **APs**, pick one, tap where it physically sits.
   - Place obstructions — tap **OBJ**, pick a furniture/structure type, tap its spot.
4. **Import map ← device:** Ragnar pulls the finished map and loads it into the
   Coverage Heatmap as **walls** (outline) + **predict APs** (AP positions) +
   **columns** (objects), shown in Design/Predict — so predicted coverage shadows
   behind the metal cabinet and the concrete pillar.

All coordinates are fractions (0..1) of a square floor whose real edge length in
metres is set on the device (the `−/+` scale control), matching the heatmap model.

## On-device UI

- **Grid canvas** with metre rulers; `−/+` sets the floor size.
- Toolbar: **UNDO · CLOSE · CLEAR · APs · OBJ**. There is **no SEND button** —
  Ragnar pulls the map itself with its *Import* button (the firmware still answers
  the `SEND` serial command).
- **APs** opens the scanned-AP list (SSID · MAC · dBm · band · channel), paged; pick
  one, then tap the map to drop the marker.
- **OBJ** opens the furniture/structure palette (below); each object shadows Wi-Fi
  in the predicted heatmap by a realistic dB amount.

### Objects and their Wi-Fi effect

Each placed object becomes a heatmap **column** (a point obstruction with a footprint
radius and a dB loss). The dB values reflect real 2.4/5 GHz behaviour — metal and
water block hard, soft furniture barely at all:

| Object | Loss | Footprint | Why |
|--------|------|-----------|-----|
| Steel pillar / Fridge | 20 dB | 0.3–0.5 m | metal blocks & reflects |
| Metal cabinet | 18 dB | 0.5 m | metal |
| Concrete pillar | 15 dB | 0.3 m | dense masonry |
| Mirror | 12 dB | 0.4 m | metal backing |
| Aquarium (water) | 10 dB | 0.4 m | water absorbs 2.4 GHz |
| TV / electronics | 8 dB | 0.5 m | mixed metal/glass |
| Wardrobe (wood) | 5 dB | 0.6 m | wood |
| Bookshelf | 4 dB | 0.5 m | wood + paper |
| Couch / Bed | 3 dB | 0.7–0.8 m | soft furnishing |
| Desk / table | 2 dB | 0.6 m | thin wood |

## Serial protocol (115200 baud, line-based)

Ragnar → device:

| Line | Meaning |
|------|---------|
| `PING` | device replies `PONG` |
| `SEND` | device emits the map JSON line |
| `APCLEAR` | clear the received AP list |
| `AP\t<i>\t<ssid>\t<bssid>\t<rssi>\t<band>\t<ch>` | append one AP |
| `APDONE` | finalise (redraw the list if open) |

device → Ragnar:

- On boot: `{"type":"roomscan_hello","fw":"1.1","proto":1}`
- On `PING`: `PONG`
- On `SEND` (which Ragnar's *Import* sends):
  `{"type":"ragnar_roomscan","v":1,"scale_m":10,"rooms":[[[x,y],…],…],"aps":[{"ssid":…,"bssid":…,"x":…,"y":…},…],"objects":[{"type":…,"x":…,"y":…,"radius_m":…,"loss_db":…},…]}`

The bridge uses **poll-based** serial I/O (never `select`/`readline`) because the
Ragnar process runs with 700+ open FDs — pyserial's `select()` path raises
"filedescriptor out of range" past FD 1024 (same landmine `wardriving.py` documents).

## Flashing

Flash from the web flasher at **https://pierregode.github.io/Ragnar/** → the
**📐 RoomScan Floor-Plan Tracer** panel (board-agnostic esptool-js flow, same as the
CSI nodes). The binary is built in CI (`.github/workflows/build-rusense-flasher.yml`)
from `roomscan_firmware/roomscan_s3_lcd/` with `arduino-cli` (esp32 core 3.3.0, GFX
1.6.7) and merged with `esptool merge_bin` — no eFuses are ever burned.

## Status / limitations

- Validated on real hardware: display bring-up, GT911 touch (1:1 coordinate
  mapping), corner drawing, and the full bidirectional serial round-trip.
- Imported APs land as **positions** (`predict_aps`) and objects as **columns**;
  the outline as **walls**. The AP's SSID/BSSID and the object's type are carried in
  the map; showing those labels on the heatmap markers is a follow-up.
- The device holds its state in RAM; a **power cycle clears the pushed AP list and
  the drawn map** (flash persistence is a planned follow-up). Keep it powered while
  walking (battery / power bank).
