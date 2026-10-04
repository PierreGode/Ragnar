# Wardrive firmware comparison — ESP32-C5

Measured comparison of wardriving firmwares running on the **same Seeed XIAO
ESP32-C5** (8 MB flash), in the same spot, on 2026-10-04. Everything here was
measured on real hardware.

| Firmware | Version |
|---|---|
| [HuginnESP](https://github.com/PierreGode/HuginnESP) | `main` (calibrated scan timing + hidden networks) |
| [Piglet](https://github.com/Hamspiced/piglet) | v2.63 (fork build with USB serial file sync), stock settings |

## Summary

- **Huginn is the fastest.** A full 2.4 + 5 GHz sweep takes about **5.3 s**
  against **9.7 s** for Piglet. That's about 1.8× more sweeps and detections
  per minute, and Huginn scans BLE at the same time.
- **Piglet hears slightly more per sweep** (91% vs 87–89% of the reference
  APs), especially on 2.4 GHz.
- **Both now find hidden networks.** Huginn didn't until `show_hidden` was
  enabled; the hidden networks were found because Piglet reported 5 that
  Huginn never did.
- **Open issue in Huginn:** one weak 2.4 GHz AP (channel 5) dropped from ~58%
  to ~6% of sweeps after hidden networks were enabled. That single AP stretches
  Huginn's "be sure of everything" time to over 5 minutes, against ~1 minute for
  Piglet. The cause isn't proven yet (see [Open questions](#open-questions)).

## Setup and method

- **Board:** Seeed XIAO ESP32-C5, USB to a Raspberry Pi 5. It was stationary
  indoors, and the APs around it are stationary too (neighbouring homes; no
  guarantee).
- **One firmware at a time:** each was flashed onto the same board, so runs
  can't be simultaneous. Huginn was run **before and after** Piglet
  (Huginn → Piglet → Huginn, 10 min each) to show whether the surroundings
  changed in between.
- **Data source, Huginn:** its JSON lines over USB. The firmware's
  `wardrive WiFi phase` log line marks the end of each sweep.
- **Data source, Piglet:** its USB live mirror **drops rows** when the 256-byte
  USB buffer is full (reported 18, delivered 11), so it can't be used for
  counting. The scans were rebuilt from Piglet's **SD log**, pulled over its
  serial file sync after the run. All rows of one scan share the same
  `FirstSeen` second, and each scan was checked against Piglet's own "N
  networks" count.
- **Reference set:** every AP that at least one run saw in ≥ 50% of its sweeps.
  That's 20 APs, 4 of them hidden.
- **Metrics:**
  - **Per-sweep recall:** share of reference APs seen in a sweep.
  - **Time to 99%:** for each AP, sweeps needed until the chance of having
    missed it every time is under 1%, multiplied by the sweep time. The table
    shows the slowest AP.
  - **Detections per minute:** reference APs reported per minute.

### Independent baseline (Pi 5 `wlan0`)

Before the firmware tests, the Pi 5's onboard radio ran 3 minutes of repeated
`iw dev wlan0 scan`: 44 scans, one every 4.2 s, **8 unique APs, 7 stable**
(3 × 2.4 GHz, 4 × 5 GHz). The onboard antenna inside the case hears far less
than the C5 boards (22–24 APs), so `wlan0` only works as a **drift tracker**
and floor. All firmwares found those 7.

## Results — Huginn vs Piglet (A/B/A, 10 min each)

| | **Huginn #1** | **Piglet** | **Huginn #2** |
|---|---|---|---|
| Time per full sweep (2.4 + 5 GHz) | **5.28 s** | 9.72 s | **5.33 s** |
| Sweeps per minute | **11.4** | 6.2 | **11.2** |
| Per-sweep recall (20 reference APs) | 87.1% | **91.0%** | 88.6% |
| — 2.4 GHz | 79.7% | **91.4%** | 83.0% |
| — 5 GHz | **98.2%** | 90.3% | **96.9%** |
| — hidden networks | 82.7% | 85.7% | **88.9%** |
| Detections per minute | **198** | 112 | **199** |
| Unique APs in total | **24** | 22 | 22 |
| BLE devices per sweep | 42 | – (no BLE) | 41 |
| Time to 99% for **all** reference APs | 338 s | **58 s** | 389 s |

The two Huginn runs agree closely (sweep 5.28 vs 5.33 s, recall 87–89%), so
the surroundings were stable around the Piglet run.

### Per AP (share of sweeps the AP was seen in)

| AP | Ch | Hidden | Huginn #1 | Piglet | Huginn #2 |
|---|---|---|---|---|---|
| A0:A3:F0:62:FC:35 | 1 | | 100% | 100% | 100% |
| 38:A6:59:85:CF:66 | 1 | | 99% | 97% | 100% |
| A2:A3:F0:62:FC:35 | 1 | ✓ | 100% | 95% | 100% |
| 62:7F:F0:1F:A4:87 | 3 | | 75% | 79% | 78% |
| E8:48:B8:76:E7:B4 | 4 | | 98% | 100% | 98% |
| **40:9B:CD:A2:5B:78** | **5** | | **7%** | **56%** | **6%** |
| B0:6E:BF:28:00:A0 | 8 | | 96% | 100% | 94% |
| A8:42:A1:EA:DB:E2 | 10 | | 92% | 97% | 86% |
| F8:08:4F:84:4E:FE | 11 | | 83% | 94% | 88% |
| 94:A6:7E:B2:27:71 | 12 | | 84% | 94% | 88% |
| A2:A3:F0:62:FC:2D | 13 | ✓ | 42% | 87% | 71% |
| A0:A3:F0:62:FC:2D | 13 | | 78% | 98% | 87% |
| 66:7F:F0:1F:A4:80 | 36 | | 99% | 70% | 91% |
| B0:6E:BF:28:00:A4 | 36 | | 100% | 100% | 100% |
| A0:A3:F0:62:FC:36 | 36 | | 100% | 94% | 100% |
| A2:A3:F0:62:FC:36 | 36 | ✓ | 96% | 90% | 99% |
| 66:7F:F0:1F:A4:81 | 36 | ✓ | 92% | 70% | 86% |
| A8:42:A1:EA:DB:E3 | 44 | | 100% | 98% | 100% |
| E8:48:B8:76:E7:B5 | 48 | | 100% | 100% | 100% |
| B0:6E:BF:28:00:A8 | 100 | | 98% | 100% | 99% |

## Huginn scan-timing calibration

Huginn's per-channel dwell was made runtime-tunable (`set wifi_active_min_ms`,
`wifi_active_max_ms`, `wifi_passive_ms`) and swept on the same board: ~85
minutes against 16 stable APs, with four interleaved baselines at the old
values.

| Setting | Sweep | Per-sweep recall | Verdict |
|---|---|---|---|
| Baseline (active 30–120 ms, DFS passive 120 ms, BLE 1.5 s) | 6.13–6.21 s | 90.2–93.1% | reference |
| Active max 90 ms | 5.63 s | 90.7% | ✅ no measurable loss |
| Active max 70 ms | 5.18 s | 89.0% | ⚠️ weak 2.4 GHz APs on single-visit channels start dropping |
| Active max ≤ 50 ms | 4.26–4.74 s | 78.7–83.9% | ❌ clear losses (channels 3, 5, 11) |
| DFS passive 105 ms | 5.89 s | 90.9% | ✅ |
| DFS passive 70 ms | 5.32 s | 87.2% | ❌ lost the DFS AP in 1 of 3 sweeps (below the ~102 ms beacon interval) |
| BLE phase 1000 / 700 / 500 ms | 5.71 / 5.33 / 5.21 s | Wi-Fi unchanged | ❌ 15 / 27 / 35% fewer BLE devices per phase |
| **Chosen: active 25–90 ms, DFS 105 ms, BLE 1.5 s** | **5.34 s** | 89.5% (10 min confirmation) | ✅ 0 stable APs missed |

Net: sweep **6.2 s → 5.3 s (−13%)** with recall inside the baseline's own
variation. One finding for later: even at 25 ms per channel, a 52-visit sweep
takes 2.76 s, about **53 ms of fixed overhead per channel scan**. Trimming the
C5 channel list (which revisits the busy channels) is the next lever, but it's
a design choice and hasn't been done.

## Open questions

1. **Huginn and the channel-5 AP:** one weak 2.4 GHz AP dropped from ~58% to
   ~6% of sweeps. The only Huginn change between the two measurements is
   `show_hidden = true`. Next step: make it runtime-switchable and alternate
   on/off in the same session to prove or rule out the cause.
2. **Piglet's 9.7 s sweep:** Piglet uses one `WiFi.scanNetworks()` over all
   channels. The long sweep most likely comes from ESP-IDF's default passive
   time on DFS channels, which Piglet doesn't set. Not verified.
3. **Unequal tuning:** Huginn was tuned on this board; Piglet ran stock
   ("aggressive") settings.

## Caveats

- **One spot, one board:** indoors and stationary. Results on the move (where
  more sweeps per minute matter most) will differ.
- **Not simultaneous:** the A/B/A design controls for drift between runs, not
  within them.
- **Small reference:** the 20 reference APs include a single DFS AP, so DFS
  conclusions rest on one device.
