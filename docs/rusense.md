# 📡 RuSense — Camera-Free Surveillance

RuSense is Ragnar's **no-camera surveillance** system. Instead of pointing a lens at
a room, it listens to the ordinary 2.4 GHz WiFi already filling your space and reads
the tiny distortions that a moving body imprints on those radio waves. From those
distortions it can tell you whether a room is **occupied**, whether there is
**motion**, roughly **how many people** are present, and — with a trained model —
coarse **posture / pose** and **vital signs** (breathing and heart rate at rest).

No images are ever captured. There is nothing to leak, nothing to point at a bed or a
desk, and it works in total darkness and through walls. That makes it suited to places
a camera is unwelcome or impractical: **homes, offices, care/elderly monitoring,
bathrooms and bedrooms, server rooms, warehouses, and after-hours premises**.

> [!IMPORTANT]
> For monitoring spaces **you own or are authorized to monitor**. Sensing people
> through walls carries the same privacy responsibilities as any surveillance system —
> use it lawfully and disclose it where required.

← Back to the [Ragnar README](../README.md).

---

## How it works

### 1. WiFi Channel State Information (CSI)

Every WiFi packet is carried across dozens of frequency *subcarriers*. The receiver
measures the amplitude and phase of each one — this is **Channel State Information
(CSI)**. When a person moves, breathes, or simply stands in the room, their body
reflects, absorbs and scatters those subcarriers in a measurable way. RuSense treats
the stream of CSI as a kind of low-resolution radar.

A RuSense sensor node samples up to **114 subcarriers at roughly 100 Hz** on 2.4 GHz.
That continuous fingerprint of the room is what gets analysed — never any video.

### 2. The pieces

```
  ESP32 CSI node(s)  ──UDP CSI frames──▶  sensing-server  ──HTTP/WS──▶  Ragnar web UI
   (ESP32-S3 / C6)        :5005             (127.0.0.1:3000)            (RuSense tabs)
```

| Component | What it is | Where it lives |
|---|---|---|
| **CSI sensor node** | An ESP32-S3 or ESP32-C6 running the RuSense CSI firmware. Listens to 2.4 GHz WiFi and streams CSI frames over UDP to the server. | Flashed from the browser — see [Flashing a node](#flashing-a-sensor-node) |
| **sensing-server** | A prebuilt Rust engine (`bin/sensing-server`, crate `wifi-densepose-sensing-server`) that ingests CSI, runs inference, and exposes a REST + WebSocket API on `127.0.0.1:3000`. | Vendored in this repo; installed as `ragnar-sensing.service` |
| **Ragnar web UI** | The dashboard tabs (Nodes, Live, Training, Models) that visualise presence/motion/people and let you record and train. `webapp_modern.py` proxies `/api/v1/*` and `/ws/sensing` to the sensing-server. | `web/rusense/` |

One node gives you presence and motion for a room. **Multiple nodes** placed around a
space let the engine fuse their views (multistatic fusion) for better people-counting
and coarse positioning.

### 3. What it can report

- **Presence / occupancy** — is anyone in the room?
- **Motion** — movement intensity and events.
- **People count** — estimated number of people present.
- **Pose / posture** — coarse body keypoints and posture, with a trained model.
- **Vital signs** — breathing and heart rate for a still subject (e.g. someone at rest).
- **Signal quality** — so you know when a reading is trustworthy.

---

## Flashing a sensor node

You don't need a toolchain. The firmware is flashed straight from your browser over
USB using the **RuSense CSI Node Flasher** (Web Serial / esptool-js):

### → **[Open the RuSense Flasher](https://pierregode.github.io/Ragnar/)**

1. Open the flasher page in **Chrome or Edge** (Web Serial isn't available in Firefox/Safari).
2. Plug your ESP32 into a **data-capable** USB-C cable (charge-only cables won't work).
3. Pick your board. All ESP32-S3 variants live in one panel behind a **board dropdown**:
   - **ESP32-S3-DevKitC-1 (N16R8)** *(recommended)* — headless, 16 MB flash. No display, so it
     captures the full MGMT+DATA WiFi traffic — the best sensor for presence/motion/people-count.
   - **Seeed XIAO ESP32S3** — thumbnail-sized (21 × 17.8 mm), 8 MB flash, headless (same full
     capture as the DevKitC). **Attach the bundled U.FL antenna first** — without it the radio
     hears nothing.
   - **Seeed XIAO ESP32S3 Plus** — same tiny footprint with 16 MB flash, headless.
   - **AMOLED display board** — 8 MB flash with an RM67162 screen; sensing is limited to a
     single self-ping link, so prefer a headless board when the node's job is sensing.
   - **ESP32-C6** *(Wi-Fi 6 research, separate panel)* — RISC-V, 4 MB flash, dual-band 802.11ax for experiments.
4. Click **Forge**, select the `USB JTAG/serial debug unit` port, and let it flash.
5. If the board isn't detected, hold **BOOT** while tapping **RST**, then retry. On the XIAO
   boards those are the tiny **B** and **R** buttons — or hold **B** while plugging in the cable.
6. **Provision WiFi** — flashing **erases** the node's saved config, so a fresh node
   falls back to wrong defaults and never connects. In the flasher's **🛰️ Provision
   WiFi** panel, enter your **2.4 GHz** SSID + password and your **Ragnar box's IP**
   (the RuSense server), then **Write WiFi config**. This writes the `csi_cfg` NVS at
   `0x9000` (the same partition RuView's `provision.py` produces) without touching the
   firmware. Press **RST** — the node joins your WiFi and starts streaming.

> [!IMPORTANT]
> **Don't mix S3 and C6 nodes in the same mesh — pick one chip type and use it for
> every node.** The two chips capture different CSI widths (e.g. 128 vs 192
> subcarriers), and the engine's multistatic fusion needs all nodes the same width.
> A mixed fleet makes fusion fail and fall back to per-node processing, which costs
> you accurate people-counting, positioning, pose and vital-signs. Presence/motion/
> geofence still work, but for a clean setup keep the whole mesh **all-S3 or all-C6**.
> **S3 is recommended** (steadier, best-tested); use C6 only if you specifically want
> Wi-Fi 6 — and then make *every* node a C6.

The firmware bins served by the flasher are vendored bit-identically from upstream
**RuView** at a pinned commit (see `rusense_flasher/rusense-csi-node.version`).

---

## Running the sensing backend on Ragnar

The sensing engine is bundled with Ragnar — no separate RuView checkout needed.

```bash
cd /home/ragnar/Ragnar
sudo ./scripts/install_sensing.sh
```

This installs and starts `ragnar-sensing.service`:

- On **Raspberry Pi (arm64)** it installs the prebuilt binary at `bin/sensing-server`.
- On **other architectures** (or with `--rebuild`) it installs Rust and compiles from
  the pinned RuView source.

Default ports: HTTP `3000`, WebSocket `3100`, UDP CSI ingest `5005`. The service is
idempotent — safe to re-run.

> The UDP CSI receiver binds `0.0.0.0` so the ESP32 nodes on your LAN can reach it
> — newer sensing-server builds default that socket to loopback-only and would
> otherwise drop LAN frames. To restrict it, set `SENSING_UDP_ALLOW="192.168.1.0/24"`
> (comma-separated CIDRs) before running the installer, or `SENSING_UDP_BIND=127.0.0.1`
> to accept loopback only.

> By default the sensing API (`/api/v1/*`) is unauthenticated and bound to localhost,
> reached only through Ragnar's web proxy. If you expose it directly, set
> `RUVIEW_API_TOKEN=<token>` to enforce bearer auth.

### Observatory position tracking (multi-node)

The Observatory's moving figure is a **coarse activity centroid**, not precise
tracking. With **≥2 nodes** whose positions you've told the server, the blob drifts
toward whichever node is currently flaring most *relative to its own baseline* (so a
persistently-noisy node can't hog it, and a quiet node still registers when you
approach). Configure it at install time:

```bash
SENSING_NODE_POSITIONS="x,y,z;x,y,z;x,y,z" sudo ./scripts/install_sensing.sh
```

Positions are in **metres**, ordered by **ascending node_id** (node 1 first), with the
room centred on the origin. `SENSING_LOCALIZE_POWER` (default `2`) sharpens the pull
toward a single node (higher = snappier but jumpier). Both are stored in a systemd
drop-in (`ragnar-sensing.service.d/node-positions.conf`) that survives reinstalls, so
you can retune live with `systemctl edit`/`daemon-reload`.

> **Honest limit:** a moving person perturbs *every* WiFi link, so this is
> proximity-by-activity, **not** calibrated (x, z) triangulation. Expect the blob to
> drift toward the right region, not pinpoint you. Precise localization would need true
> multistatic RTI, which single-link CSI can't provide.

---

## Using it from the web UI

Open Ragnar's dashboard at `http://<ragnar-ip>:8000` and use the RuSense tabs:

1. **Dashboard** — the operator overview: a presence banner, key live stats
   (people, confidence, breathing, heart rate), a **RuSense + node health** card
   (backend status, source, and each node online/RSSI by its custom name), and a
   **Recent sightings** log (see below).
2. **Sensing** — real-time CSI features, classification, vital signs and the
   signal-field heatmap for the monitored space.
3. **Nodes** — provisioned CSI nodes appear here once they start streaming (confirm
   frames-per-second is climbing). Shows each node's custom name, status, RSSI,
   motion and last-seen. Name your nodes in the Settings tab.
4. **Training** — the **Record → Train → Active** loop. Record CSI while you act out
   labelled scenarios (empty room, one person, two people, walking, sitting…), then
   train a lightweight on-device adaptive classifier tuned to *your* space. The same
   tab's **Models** section loads, activates or unloads trained models (`.rvf`
   containers and LoRA profiles).
5. **Settings** — configure **push notifications** for sensing events (see below),
   the **geofence**, and your **node names / positions** (Observatory → Room & Nodes).

> **Demo vs. live.** The **Observatory** 3D view falls back to a built-in demo
> reel whenever no real sensing node is streaming (no ESP32 connected, or the
> server is running synthetic `--source auto`/`simulated` data). In that state it
> shows an amber **"DEMO — no node connected"** flag and labels the placeholder
> node **demo** — it never wears your configured node name (e.g. "s3"). The flag
> clears and real node names return the instant a live frame arrives from an
> `esp32`/`wifi` source. Data Source (Demo Generator / Live WebSocket) is set in
> **Settings → Observatory**.

---

## Push notifications (alerts)

RuSense can send a **Pushover** push notification when it detects activity — so a
camera-free space can still alert your phone. Alerts are evaluated **server-side**, so
they fire even when no browser has the RuSense tab open.

### Monitoring modes

The **Monitoring mode** selector at the top of the Settings tab decides the *direction*
of the alerts — the same sensing, inverted logic:

- **Security** *(default)* — the space is expected **empty**: alert when someone
  **appears** (presence/motion/people). What you want for a home you're away from.
  Optionally restrict these alerts to a **permitted schedule** (Settings → *Permitted
  alert times*): chosen weekdays + a daily time window — e.g. an office watched only on
  **weekends**, or a space only at **night**. Outside the window nothing is pushed
  (sightings are still logged; node-offline warnings still fire). Config keys:
  `rusense_alert_schedule_enabled`, `rusense_alert_days` (0=Sun..6=Sat), `rusense_alert_start`,
  `rusense_alert_end` (start==end = all day; start>end wraps past midnight).
- **Health** — the space is expected **occupied** (wellness monitoring, e.g. an elderly
  relative living alone): presence alerts would fire on every normal movement, so they're
  off; instead an **inactivity** alert fires when the home shows *no* activity for a set
  number of awake hours (a fall, not getting out of bed), and the Dashboard leads with
  the **Health trends** card. A configurable **quiet window** (default 22:00–07:00)
  excludes sleep — the timer only runs outside it and restarts each morning, so a normal
  night never alerts.
- **Both** — presence *and* inactivity alerts together, for a space that's empty at
  some hours and occupied at others.

Picking a mode presets the alert toggles; you can still fine-tune each one afterwards.
(Config keys: `rusense_mode`, `rusense_notify_inactivity`, `rusense_inactivity_hours`,
`rusense_quiet_start`, `rusense_quiet_end`.)

### Health trends (vitals history)

Independent of mode, the backend aggregates every confident heart-rate / breathing
reading plus the presence duty into **5-minute buckets**, kept for **7 days**
(`data/rusense_vitals_history.json`, endpoint `/api/rusense/vitals-history`). The
Dashboard's **Health trends** card charts them (24h/7d) with **resting averages**
(overnight readings when available). Instant vitals are inherently sparse — the engine
needs ~15 s+ of a *still* subject per confident reading — so the health value is the
*trend*: a resting breathing rate drifting up over days signals illness earlier than any
single reading ever could. RuSense is wellness tracking, **not a medical device** — use
it for trends and check-ins, never for emergencies or diagnosis.

Configure alerts in the RuSense **Settings** tab. Available triggers:

- **Presence / occupancy** — a monitored space goes from empty to occupied (and back).
- **Motion** — significant (active) motion is detected.
- **People-count threshold** — the number of people crosses a value you set. The engine
  exposes only a *per-node* count (which ghosts on individual nodes), so RuSense uses the
  **median across active nodes** — a single node spiking can't move the median, so a count
  is only believed when a majority of nodes agree.
- **Node offline** — a provisioned CSI sensor node stops streaming.
- **Inactivity (health)** — the inverse of presence: an expected-occupied space shows
  **no** activity for the configured awake hours. Sleep hours (quiet window) never count.

A configurable **cooldown** prevents a flapping signal from spamming you, and each
trigger can be toggled independently under a master on/off switch.

To suppress false positives, an event only fires when **all** of these hold:

- **Minimum confidence** — the detector must be at least this confident (default **95%**);
  low-confidence flickers are ignored. (`rusense_notify_min_confidence`)
- **Must last** — the condition has to hold continuously for at least this long
  (default 2 seconds) before an alert is sent. (`rusense_notify_sustain_s`)
- **Geofence** — the disturbance must sit *inside* the mapped room perimeter, not be a
  hallway walk-by or through-wall neighbour. See [Geofence](#geofence--confining-alerts-to-the-room).

All are adjustable in the Settings tab (defaults: 95% confidence, 2 s sustain, people
threshold 1, 60 s cooldown).

> [!NOTE]
> **The confidence gate is model-aware.** Confidence is only *calibrated* — and so
> only trustworthy as a filter — when an adaptive model is loaded (an occupied room
> then reads ~1.0, an empty room stays low). **Model-less**, confidence is
> uninformative (~0.5), so the alert/sighting confidence gate automatically **relaxes
> to 0** and RuSense leans on the presence rule + sustain debounce instead. This means
> a real occupant is **never missed for lack of a model**, while an empty room stays
> quiet (the presence rule alone rejects the raw ~46 Hz flicker). Loading or unloading
> a model retunes this within ~30 s — no setting to change. For best accuracy, keep a
> trained model active (see [Training](#two-training-paths)).

Alerts reuse Ragnar's existing **Pushover** account: set your **User Key** and **API
Token** once under the main dashboard's **Config → Pushover Notifications**, then enable
the RuSense triggers in the Settings tab. Use **Send test notification** to confirm
delivery. (Config keys: `rusense_notify_*` in `shared.py`.)

> [!IMPORTANT]
> The alert monitor runs inside the `ragnar` service process. After you change alert
> settings **or pull new code**, restart it so the changes take effect:
> ```bash
> sudo systemctl restart ragnar
> ```

### Sighting history

Every confirmed presence event is also written to a **sighting log**, shown as
**Recent sightings** on the Dashboard — so a person who has already left is still on
record. Each row shows the local **time**, how long they were **seen for**, the peak
**confidence**, and the **heart rate / breathing** captured during the stay (vitals lag
first detection, so the highest-confidence reading of the episode is kept).

- The "seen for" timer **counts up live** while the space is occupied and **locks** to
  the total when it goes empty. A very short locked sighting (under a few seconds) is
  flagged — more likely a perimeter leak than a real occupant.
- The log is **independent of Pushover**: sightings are recorded whenever the sensing
  backend is reachable, even with phone alerts switched off. It persists across restarts
  (a 50-entry ring buffer at `data/rusense_sightings.json`) and is served by
  `GET /api/rusense/sightings`.
- **Phantom rejection.** A sighting is only kept once its **peak confidence** clears the
  (model-aware) gate — with a model loaded that's 95%, so empty-room disturbances (which
  cap ~86%) never make the log while a real occupant (~100%) does. Model-less the gate is
  0 and the motion-corroborated presence rule does the filtering instead. A sighting is
  vetted once, when it closes, and then kept — so one logged model-less survives a later
  restart with a model loaded.

### Geofence — confining alerts to the room

The biggest source of false alerts is motion *outside* the room — neighbours through a
wall, people in the hallway. The **geofence** rejects these: it treats each node as a
disturbance sensor anchored at its mapped corner and only lets an alert through when the
disturbance is **corroborated and interior** to the polygon of node corners. A lone-node
or edge-pinned disturbance (a walk-by) is suppressed. The "room empty" alert is never
suppressed.

To use it:

1. Map each node's **X / Y** corner position in **Settings → Observatory → Room & Nodes**
   (these auto-sync to the backend). You need **≥ 3 nodes mapped**; with fewer the geofence
   is a no-op and alerts behave as before.
2. Leave **"Confine alerts to the room (geofence)"** enabled in the Settings tab.
3. Validate it live: `GET /api/rusense/geofence` (or the status line under the toggle)
   shows the current verdict — `inside perimeter`, `edge/outside`, or `quiet`.

It's a coarse RSSI-based filter, not a hard RF wall (2.4 GHz leaks through walls); tune the
`_GF_*` constants in `webapp_modern.py` if ghosts persist. Config keys:
`rusense_geofence_enabled`, `rusense_node_positions`, `rusense_geofence_window`.

### Two training paths

RuSense can learn in two different ways:

- **Adaptive (on-device)** — a lightweight classifier learned directly from your own
  recorded/live CSI. Fast, runs on the Pi, tuned to your room. This is the
  Record→Train→Active loop in the Training tab.
- **Deep-model dataset training** — heavy training from an external MM-Fi / Wi-Pose
  dataset into a `.rvf` model, for pose/vital-sign capable models. Done offline, not
  from live CSI.

#### Recording classes (adaptive)

The trainer is **discriminative**: it uses *every* `train_<label>` recording as a class
and learns to tell them apart. So a single class isn't enough —

> **Record at least two classes** to get a useful model, e.g. `train_empty` **and**
> `train_present`. With only `train_empty` the classifier has nothing to contrast
> against: it knows "empty" but was never shown what "occupied" looks like, so its
> confidence stays uncalibrated (which is why the confidence gate above relaxes when no
> proper model is active).

Each extra class sharpens a capability — `train_present` (one still person) enables
reliable occupied-vs-empty and vitals, `train_walking` teaches motion, `train_sitting` a
still posture, `train_two_people` improves people-count (fused across nodes), and a
`train_<custom>` clip covers anything else. Give each class a clip of comparable length,
keep the room and node placement fixed, and remember a model **only applies to the room
it was recorded in**.

---

## Placement & tuning tips

- Position nodes so the area you care about sits **between the node and the WiFi
  traffic** it's listening to — CSI is richest along that path.
- More nodes around a room = better people-counting and coarser positioning via fusion.
- Keep nodes powered and on a stable WiFi channel; CSI yield (pps) should be non-zero
  and steady once provisioned.
- Vital-sign readings need a **still** subject; expect motion to dominate otherwise.

### Node time-sync & the Mesh health card

Multi-node **fusion** (people-count, coarse position) needs the nodes' frames to
line up in time. Ragnar does this by **timestamping every frame the moment it
reaches the Pi** — so all nodes are measured against the Pi's single clock, not
their own. The fleet stays aligned **regardless of the order you power the nodes
on**, and a node that loses power **re-syncs on its own** the instant it starts
streaming again — you don't have to power them all up at the same time.

The **Mesh health** card (Nodes tab) shows each node's **lag** — how far its latest
frame trailed the freshest node — and a fleet **spread**. Healthy is a spread inside
the fusion window (~200 ms); keep it there by putting every node on **one access
point + a fixed channel** and in good signal range so their packets arrive together.
(Nodes also run a legacy peer-to-peer clock sync; its per-leader "offset" can read
**seconds** even when fusion is perfectly fine — it no longer gates fusion, so ignore
it and watch **lag** instead.)

> Per-node presence & motion don't need any of this — they work on a single node.
> Only cross-node fusion cares about the clock spread.

---

## Credits

RuSense is powered by **[RuView](https://github.com/ruvnet/ruview)** — the WiFi-CSI
DensePose sensing engine (crate `wifi-densepose-sensing-server`), created by
**ruvnet**. All of the CSI ingestion, inference, pose estimation and training logic
originates there. Ragnar vendors RuView's prebuilt sensing server and the ESP32
CSI-node firmware (from the [PierreGode/RuView](https://github.com/PierreGode/RuView)
fork). Full credit and thanks to the RuView project.

- Source project: **[github.com/ruvnet/ruview](https://github.com/ruvnet/ruview)** (ruvnet)
- Fork Ragnar vendors bins from: [github.com/PierreGode/RuView](https://github.com/PierreGode/RuView)
- This integration lives in Ragnar: see the [README](../README.md).

---

← Back to the [Ragnar README](../README.md).
