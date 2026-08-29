# Sub-GHz SDR (RTL-SDR)

Ragnar's **SDR** tab turns a cheap **RTL-SDR** dongle into two receive-only
sub-GHz tools. It's the low-band counterpart to the HackRF
[True-RF Waterfall](wifi-analyzer.md#true-rf-waterfall-hackrf-sdr): the RTL-SDR
**cannot** see the 2.4/5/6 GHz Wi-Fi bands (it tops out ~1.7 GHz), but the range
it *can* reach — the 433 / 868 / 915 MHz ISM bands — is where most of the
non-Wi-Fi world lives.

Everything here is **receive-only** — nothing ever transmits.

## The two tools

| Tool | Backed by | What it does |
|---|---|---|
| **📡 ISM Devices** | `rtl_433 -F json` | A live table of every device it decodes — TPMS tyre-pressure sensors, weather stations, door/window & PIR contacts, remotes/keyfobs, utility meters, doorbells — with model, id, RSSI, hit count, last-seen, and the decoded fields. |
| **📈 Sub-GHz Waterfall** | `rtl_power` | A scrolling power-vs-frequency heatmap (same look as the HackRF Waterfall) over 433 / 868 / 915 MHz or a wide **300–960 MHz** sweep. Raw energy only — no decode — for spotting activity, carriers and jammers below 1.7 GHz. |

## One dongle, one claim

An RTL-SDR is a single USB device only one program can open at a time. So the
two tools are **mutually exclusive** — starting one stops the other — and the
tab reflects that automatically. The same rule is why a device probe
(`rtl_test`) is never run while a capture is streaming: opening the dongle a
second time would knock the capture offline (the lesson learned from the HackRF
view). While anything is running, `/status` reports availability from a cached
probe instead of touching the bus.

## Hardware

Any **RTL2832U**-based dongle works — Ragnar shells out to the standard
`rtl_power` / `rtl_433` / `rtl_test`, so it's brand-agnostic. Tested/supported
families, with what Ragnar shows for each:

| Dongle | Tuner | Ragnar shows | Notes |
|---|---|---|---|
| **RTL-SDR Blog V3** (RTL-SDR.com) | R820T2 | `RTL-SDR Blog V3` | TCXO, HF direct-sampling, software bias-tee. Works with the stock driver. |
| **RTL-SDR Blog V4** (RTL-SDR.com) | **R828D** | `RTL-SDR Blog V4` ⚠ | **Needs the RTL-SDR Blog librtlsdr fork** — the stock distro driver mis-tunes the R828D (see below). |
| **Nooelec NESDR** (SMArt / Nano / Mini 2+) | R820T2 | `Nooelec NESDR …` | TCXO models recommended. Works with the stock driver. |
| **Generic RTL2832U** (R820T / R820T2 / R860) | R820T/T2 | `RTL-SDR (R820T2)` | Any no-name stick. Works with the stock driver. |

Ragnar identifies the dongle from its USB product string and tuner chip
(`rtl_sdr.py` → `identify_model`). When a vendor flashed an EEPROM string
("Blog V4", "NESDR SMArt", …) that name is used verbatim; otherwise the tuner
chip decides (an **R828D** tuner is reported as a Blog V4).

The dongle draws real USB current — a **powered USB hub** is recommended on the
Pi (see the undervoltage note in the HackRF section). Leaving the tab, or
switching modes, stops the capture and frees the dongle.

**The tab's buttons stay greyed until Ragnar detects a dongle.** It polls
`/api/net/rtl/status` and un-greys once `rtl_test -t` answers.

Install the tools (done by `install_ragnar.sh`, ensured by `update_ragnar.sh`):

```bash
sudo apt install rtl-sdr rtl-433
```

The installer/updater also **blacklists the DVB-T kernel driver**
(`dvb_usb_rtl28xxu`, via `/etc/modprobe.d/blacklist-rtl-sdr.conf`) that would
otherwise grab the dongle before `rtl_*` can, and unloads it on the spot so a
plugged-in stick works without a reboot. If you set one up by hand: blacklist
that module, replug, and confirm with `rtl_test -t`.

### RTL-SDR Blog V4 (R828D) driver

The V4 swapped the R820T2 tuner for an **R828D**, which the *stock* Debian /
Raspberry Pi OS `librtlsdr` does not tune correctly — the sweep appears but lands
on the wrong frequencies. The V4 needs the **RTL-SDR Blog fork** of `librtlsdr`.
Ragnar detects the R828D tuner and flags it in the SDR tab ("⚠ needs Blog
driver"). To install the fork:

```bash
sudo apt purge -y ^librtlsdr        # remove the stock lib
sudo apt install -y libusb-1.0-0-dev git cmake pkg-config
git clone https://github.com/rtlsdrblog/rtl-sdr-blog
cd rtl-sdr-blog && mkdir build && cd build
cmake ../ -DINSTALL_UDEV_RULES=ON && make -j"$(nproc)"
sudo make install && sudo ldconfig
```

The V3, Nooelec and generic (R820T2) dongles need none of this — they work with
the stock driver as soon as the DVB blacklist is in place.

### Troubleshooting "not detected"

The fastest path is the **🩺 SDR check** button in the Wi-Fi Spectrum Analyzer
(always available, even with no dongle). It calls `/api/net/rtl/diagnose`, which
walks every layer detection depends on and prints a one-line verdict plus the
exact fix — "no dongle on the USB bus (power/cable)", "tools not installed", or
"DVB-T driver holding it".

When the fix is server-side (tools missing, or the DVB-T driver holding the
device), the check shows a one-click button — **⬇ Install RTL-SDR tools** /
**🔓 Free the dongle** — that POSTs to `/api/net/rtl/install`, which apt-installs
`rtl-sdr` + `rtl-433`, writes the DVB blacklist and unloads the DVB-T driver
(runs as the service user), then re-runs the check. The manual equivalents are
below.

Detection runs a ladder (`rtl_sdr.py` → `detect`): `rtl_test -t` to open the
radio, then an `lsusb` VID:PID fallback (`0bda:2838`/`2832` and common rebadges)
so a plugged-in dongle is still reported when the tools are missing or the DVB
driver is holding it. That lets `/status` tell three cases apart:

- **`usb_id: null`, `device_present: false`** — the dongle is **not on the USB
  bus at all**. This is below Ragnar: check power and the cable/port. RTL-SDR
  dongles (NESDR SMArt especially, with its TCXO + LNA) draw ~300 mA; on a Pi
  that's browning out (`vcgencmd get_throttled` != `0x0`) the port may fail to
  enumerate it. Use a solid PSU + a **powered USB hub**, a *data* cable (not
  charge-only), and confirm with `lsusb` that a `Realtek ... RTL283x` line shows.
- **`device_present: true` but `available: false`** — the dongle *is* on the bus
  but `rtl_test` can't open it: either the rtl-sdr tools aren't installed, or the
  DVB-T driver still holds it (blacklist `dvb_usb_rtl28xxu`, replug).
- **`available: true`** — good; the SDR tab and RF Waterfall button light up.

## Mesh overlays (Z-Wave / Meshtastic / MeshCore / LoRaWAN)

The RF Waterfall page's sub-GHz panel has a **📡 Mesh / LoRa** dropdown that
sweeps a chosen mesh's band and overlays its exact channel centres on the
spectrum, so you can watch the mesh's bursts/chirps land on its channels — device
chatter, retries, or a **jammer** parked on a channel.

- **Z-Wave** (FSK) — per-region channels (EU 868.42/869.85, US 908.42/916.0,
  US-LR 912/920, ANZ/JP/KR/IN/IL/HK/RU/CN). `GET /api/net/rtl/zwave`.
- **Meshtastic / MeshCore / LoRaWAN** (LoRa/CSS) — per protocol+region band +
  channels: Meshtastic US/EU868/EU433/ANZ, MeshCore EU/US, LoRaWAN
  EU868/US915/IN865/AS923. `GET /api/net/rtl/lora`.

**This is an energy / occupancy view, not a decoder — and deliberately so:**

- **LoRa cannot be demodulated with `rtl_power`/`rtl_433`.** LoRa is chirp
  spread-spectrum; demodulating it needs `gr-lora_sdr` (GNU Radio — heavy) or a
  real LoRa radio (SX127x/SX126x). This view never claims to read LoRa frames.
- **The payloads are encrypted anyway** — Meshtastic AES-256 (channel PSK;
  the *public* channel key is well-known), LoRaWAN AES-128. So even a demodulator
  gives you addresses/metadata at best, not message contents.
- **What you get RF-only:** presence, activity/occupancy per channel, and which
  band a mesh is on. Not node IDs or messages.
- **To actually identify/enumerate a mesh** (node list, names, and to read the
  Meshtastic public channel), use the **Mesh Nodes** page below — a companion
  Meshtastic node over USB does the LoRa demod the RTL-SDR can't.

Frequencies: LoRaWAN entries follow the published regional band plans; Meshtastic
default channels are preset/hash-derived and MeshCore's are user-configurable, so
those are marked "~" / "default" — scan the band for the actual chirps.

## Mesh Nodes (Meshtastic companion node)

The spectrum overlay shows *where* a LoRa mesh is; the **Mesh Nodes** page
(`/mesh-nodes`, `meshtastic_node.py`) shows *who's on it*. A cheap Meshtastic
device (Heltec / RAK / LILYGO T-Beam …) plugged into **USB** does the LoRa
demodulation in hardware, and the `meshtastic` Python API hands Ragnar the
decoded mesh:

- **Node DB** — id, long/short name, hardware model, role, SNR, hops away,
  battery/voltage, GPS position, last-heard. Plotted on a compact node radar
  (self at centre, links coloured by SNR) plus a full table.
- **🗺 Full map view** (`/mesh-map`, `demos/mesh_map.html`) — a full-screen
  **Leaflet** slippy map (vendored `web/vendor/leaflet`, key-free dark
  Esri / OSM / satellite tile layers — no API key, like the wardrive map) with
  clustered node markers, popups (hw/role/SNR/hops/battery), SNR-coloured links
  from your node, and Fit/Links controls. Fed by the same serial+MQTT node data,
  so it works with a node or MQTT-only. Reached from the Mesh Nodes toolbar. Map
  tiles need Internet (CSP allows remote `https:` images); markers still render
  on the dark base when offline.
- **🌍 World** — one button connects the **public MQTT broker** on its global
  topic and zooms the map out to the whole planet: **public mesh nodes worldwide**
  stream in and cluster as they beacon.
  - **Encrypted feed decoded.** The MQTT subscription is `msh/+/2/#`, covering
    both the JSON stream *and* the encrypted protobuf stream (`/e/`) that carries
    most nodes — few gateways enable JSON, so JSON-only saw almost nothing.
    `parse_mqtt_protobuf` hand-parses the ServiceEnvelope→MeshPacket→Data
    protobuf wire format (no protobuf/meshtastic dependency) and AES-CTR-decrypts
    the public-channel payload with the well-known default key. Private-channel
    packets don't decrypt and are dropped, so only shareable public traffic shows.
  - **Viewport-prioritised.** The map sends its current bounds
    (`/api/net/mesh/nodes?s=&w=&n=&e=`) and reloads on pan/zoom, so a zoomed-in
    view loads just that area instead of the whole world; results are capped
    most-recent-first, and MQTT positions are capped (`_MQTT_STATION_MAX`).
  - Still a large *live sample* (nodes appear as they beacon; RF-only/private
    nodes never reach MQTT), not a full census.
- **Public-channel messages** — the default Meshtastic channel key is
  well-known, so its text traffic is decoded and shown live. Private channels
  stay encrypted.
- **MQTT (Internet bridge)** — Meshtastic gateways bridge the mesh to an MQTT
  broker the way APRS IGates bridge to APRS-IS. The **☁ MQTT** button connects a
  broker (default the public `mqtt.meshtastic.org`, JSON topic `msh/+/2/json/#`)
  and streams mesh traffic **worldwide with no node at all** — nodes, positions
  and text messages parsed from the JSON stream (`parse_mqtt_json`). Runs
  independently of the USB node and of the RTL-SDR. Uses **paho-mqtt** (in
  `requirements.txt`; the Install button grabs it too).
- **Transmit** — the **Send** box puts a text message onto the mesh: through the
  connected node's **LoRa RF** when a node is present (licence-free ISM), else
  over **MQTT** (which reaches RF only via a downlink-enabled gateway). Messages
  you send show in the feed tagged `TX`; RF/serial and MQTT sources are tagged
  too.
- **Own USB radio** — this does *not* contend for the RTL-SDR, so it can run
  alongside the sub-GHz sweep / ADS-B.
- **Needs the `meshtastic` pip package** (serial) and **paho-mqtt** (MQTT) —
  installed best-effort by the installer/updater; if missing, the page shows an
  **⬇ Install meshtastic** button (`POST /api/net/mesh/install`, installs both).
- **MeshCore:** its companion tooling is still immature, so only the spectrum
  overlay covers it for now; node enumeration here is Meshtastic.

> Meshtastic transmit is licence-free ISM (unlike ham APRS), so sending through
> your own node is fine; over MQTT, mind the network's etiquette (don't flood
> the public broker). Public-channel traffic is readable; private channels stay
> encrypted.

## ADS-B radar (1090 MHz aircraft)

The RTL-SDR's other classic trick: at **1090 MHz** it hears the ADS-B position
broadcasts every airliner (and most GA) sends in the clear — ICAO address,
callsign, lat/lon, altitude, speed, heading. The **ADS-B Radar** page
(`/adsb-radar`, `adsb.py` driving **dump1090**) renders them on a PPI radar:
range rings, compass, your receiver at centre, and altitude-coloured blips with
heading vectors + a contacts table.

- **Reachable** from the RF Waterfall page ("✈ ADS-B Radar") and the Wi-Fi
  Spectrum Analyzer button (shown when an RTL-SDR is present or the demo is on).
- **Set your lat/lon** (or use the browser location) so range/bearing are
  correct — aircraft carry their own GPS position; the page computes distance and
  bearing relative to you client-side.
- **Each contact is identified three ways:** the **ICAO** callsign (e.g.
  `DLH427`); the airline's **IATA** flight + name looked up from a cross-reference
  table (`LH427 · Lufthansa` — ICAO and IATA are separate code systems, so this
  is a lookup, not a conversion); and the **tail registration** + country decoded
  from the ICAO 24-bit address (exact N-number algorithm for the US; country from
  the ICAO address block elsewhere).
- **Aircraft type** (`A320`, `B738`, `B77W`…) fills the **Type** column: ADS-B
  doesn't broadcast type, so it's looked up by ICAO hex from **adsb.lol** (free,
  no key) in the background and cached to `data/adsb_types.json` (gitignored), so
  the column fills in over a few seconds and is instant thereafter.
- **My location** (receiver position) resolves in priority order: **GPS fix →
  browser geolocation → rough IP location**. The **GPS** comes from the box's own
  receiver (the shared wardriving `/api/wardriving/gps`, so no second serial
  reader) and is exact. Browsers **block geolocation on plain-HTTP origins** (how
  Ragnar is usually reached on a LAN), so with no GPS it falls back to the box's
  **public-IP location** (`/api/net/adsb/iploc`; same LAN ⇒ same town, ~city
  accuracy — fine for a 100–400 km radar). Free geolocation services rate-limit
  hard, so `iploc` fans out across several providers (ipapi.co, ip-api.com,
  ipwho.is) and **caches the last good fix** (memory + `data/adsb_iploc.json`); a
  public IP rarely moves, so a cached fix is served when every provider is briefly
  down — this is what keeps the deaf-SDR radar from blanking out. The page
  auto-locates on load when nothing is saved, so the radar can place aircraft
  without manual entry.
- **No SDR? (demo)** With the RF-waterfall demo on but no dump1090, the radar and
  route maps show the **real** aircraft near you, pulled live from **adsb.lol**
  (`/api/net/adsb/nearby`) — real positions, types and routes — falling back to a
  synthetic sky only with no location or no internet. Mode reads **internet**.
- **SDR connected but hearing nothing?** A poor/indoor antenna at 1090 MHz (e.g. a
  wide-band telescopic whip) may decode zero aircraft even with dump1090 running.
  Rather than leave the radar empty, Ragnar falls back to the **internet** feed
  (real aircraft near you) and says so plainly — a banner reads *"Local SDR quiet
  — showing INTERNET traffic near you"* with the live msg count, so it's never
  mistaken for what the antenna actually decoded. As soon as your receiver decodes
  a real contact, local RF takes over automatically. Tip: for 1090 MHz a
  quarter-wave whip is ≈6.9 cm (or 3/4-wave ≈20.7 cm) — *shorter is better here* —
  placed at a window.
- **One dongle:** ADS-B uses the whole RTL-SDR, so starting the radar stops the
  sub-GHz sweep/decoder and vice-versa.
- **Needs `dump1090`** (any fork: dump1090-fa / dump1090-mutability / dump1090).
  The installer/updater install it best-effort; if it's missing the page shows an
  **⬇ Install dump1090** button (POSTs `/api/net/adsb/install`). Everything here
  is receive-only, and ADS-B is unauthenticated/unencrypted by design — the same
  data every flight-tracking site shows.

### Flight routes (click a contact → world map)

ADS-B carries the live position but **not** the filed route (origin →
destination). Click any contact (row or blip) and Ragnar opens a **world-map
route view**, FlightAware-style:

- **Origin/destination** come from a lookup on the callsign via
  [adsbdb.com](https://www.adsbdb.com) — **free, no API key**. Answers are cached
  to `data/adsb_routes.json` (gitignored), so repeat sightings are instant and
  known routes still render with **no connectivity**. Only the first look-up of a
  given callsign touches the network, and only when you click an aircraft (no
  background polling — light on the free service).
- The map is **Leaflet** with **Esri dark-gray tiles** — the same vendored
  library (`/web/vendor/leaflet/`) and basemap as the **Mesh Map**, for one
  consistent map UX across Ragnar. It auto-fits (`fitBounds`) to the route, draws
  the true **great-circle** arc (curved, not a straight line) as a sampled
  polyline, splits it **flown** (cyan) vs **remaining** (dashed) at the live
  position, and marks both airports (labelled) and the aircraft (heading-oriented
  marker). The basemap tiles need connectivity like any slippy map; the route
  data itself is cached, so a known route still draws its line/markers offline.
- The plane is placed at its **real live position** and its **type** is shown:
  clicking fetches the flight from **adsb.lol** by hex, so the marker matches
  reality (not a stale/synthetic local fix). The side panel shows **% progress**,
  distance flown / remaining / total, a rough **ETA** from ground speed, and
  current altitude/speed — recomputed as the plane moves.
- **Stale-route guard:** adsbdb keys routes on the *callsign*, which is the
  *scheduled* route — but a callsign is reused across legs/days, so the aircraft
  flying it right now may be on a different (or return) leg, and adsbdb then hands
  back a confidently-wrong destination. Ragnar cross-checks the filed route against
  the aircraft's **real live heading**: if it is well en-route yet flying *away*
  from the filed destination (>100° off), the route is drawn faded/amber and the
  panel warns *"Filed route may be stale"* (progress/ETA are hidden, since they'd
  be meaningless). The live position stays accurate — only the filed route is
  flagged. Exposed as `route_match: {ok, delta}` on `/flight`.
- **Offline / unknown callsign:** the live position still plots on the map; the
  panel notes no filed route was found (adsbdb had no match, or you're offline).
  Backed by `GET /api/net/adsb/flight?hex=…&callsign=…&lat=&lon=&gs=`
  (`adsb.flight()` = adsbdb route + adsb.lol live position/type); the older
  `/api/net/adsb/route` remains. Pure parsers/geometry are covered by
  `adsb.py selftest` (24/24).

## Session record & replay

The sub-GHz waterfall toolbar has a **● Rec** button that captures the running
power sweep to a JSONL file under `data/rf_recordings/` (gitignored), and a
**Replay** dropdown to load any past recording back into the waterfall with a
transport bar (play/pause, seek, restart, delete). Frames are small, so a
recording is cheap; capped at a few thousand frames. Routes:
`/api/net/rtl/record/{start,stop,status,list,get,delete}`.

## Local Radio (FM / AM, listen)

The RF Waterfall page has a **📻 Local Radio** bar: type a frequency, pick a mode
(**FM** broadcast, **NFM** narrowband, **AM**), and press **Listen**. `radio.py`
runs `rtl_fm` to demodulate and streams the audio to the browser as a live WAV
(`/api/net/radio/stream?freq_hz=…&mode=…`) that an `<audio>` element plays, with a
volume slider and band presets (FM broadcast, airband AM, marine/PMR NFM, MW).
Frequencies below 24 MHz use the dongle's direct-sampling mode (MW/SW AM,
best-effort). One dongle, so listening pauses the sub-GHz sweep. `rtl_fm` ships
in the already-installed `rtl-sdr` package. Receive-only.

## Pager Decode (POCSAG / FLEX)

Pagers are still everywhere — hospitals, industrial SCADA/telemetry, alarms,
on-call teams — and **POCSAG/FLEX are transmitted in the clear**. The **Pager
Decode** page (`/pager-decode`, `pagerdecode.py`) tunes a pager channel with
`rtl_fm` and decodes it with `multimon-ng`, showing each message's capcode
(address), function bits, and alphanumeric/numeric text, live. A second mode
adds **Motorola Quick Call II** (two-tone sequential, fire/EMS dispatch),
decoded in-process (no multimon-ng) — see `qcii_detect` in `pagerdecode.py`.

> Note: the decoder is `pagerdecode.py`, deliberately **not** `pager.py` — a
> separate `pager/` package (a physical pager-device UI) already owns the
> `pager` import name, so the decoder module was renamed to avoid the clash.

- **Channels** — a preset list of common POCSAG/FLEX frequencies plus a
  free-form MHz box. Uses the current PPM/gain tuning.
- **`multimon-ng`** is in the Debian/Pi OS apt repos, so the installer/updater
  install it cleanly; if missing, the page shows an **⬇ Install multimon-ng**
  button (`POST /api/net/pager/install`).
- **One dongle** — pager decode uses `rtl_fm` (the whole RTL-SDR), so starting
  it stops the sub-GHz sweep/decoder and ADS-B (and vice-versa).
- **Legality** — pager traffic is unencrypted but frequently *sensitive*
  (patient data, security callouts). Decode third-party traffic only where
  lawful; this is receive-only.

## ACARS datalink (on the ADS-B radar)

The ADS-B radar page has an **✉ ACARS datalink** panel. ACARS is the VHF text
system airliners use for ops — position reports, OOOI (out/off/on/in) times,
weather, load sheets, and free-text crew↔ops messages — transmitted in the clear
around **131 MHz**. `acars.py` drives `acarsdec` and shows each message's tail,
flight, label (+ its meaning), text, and frequency/level. Messages are matched to
the radar contacts by tail/flight and flagged **● on radar**.

- **One dongle** — ACARS (131 MHz) and the 1090 MHz radar can't run at once, so
  starting ACARS pauses the radar (and vice-versa). The panel has its own
  Start/Stop.
- **`acarsdec`** isn't in apt, so the installer/updater build it from source
  (`scripts/install_acarsdec.sh`); if missing, the panel shows an **⬇ Install
  acarsdec** button. Receive-only.

## VOR radial decode (108–118 MHz nav beacon)

The **VOR Radial** page (`/vor-radial`, `vor.py`) decodes a VOR nav beacon the
way an aircraft's receiver does, and shows the **radial** you're on — the
magnetic bearing *from* the station — on a compass rose.

A VOR transmits two 30 Hz tones: a **reference** (FM-modulated on a 9960 Hz
subcarrier, the same phase in every direction) and a **variable** (AM-modulated
by the station's rotating pattern, so its phase equals your bearing). The phase
difference between them *is* the radial. `rtl_fm -M am` gives the composite
audio; `vor_decode` recovers the variable 30 Hz straight from it and the
reference 30 Hz by FM-demodulating the 9960 Hz subcarrier, then reports
`(reference_phase − variable_phase) mod 360`. It's pure numpy DSP (no scipy) —
`vor.selftest` recovers synthesised radials to <2°.

- **Cal°** — a fixed offset added to the radial, to trim a receiver/site bias.
- **One dongle** — VOR uses `rtl_fm` (the whole RTL-SDR), so it's mutually
  exclusive with the sweep/ISM, ADS-B, pager, ACARS and radio.
- **Not for navigation** — a hobby SDR + wire antenna is a demonstrator, not a
  certified nav receiver. Receive-only.

## APRS (ham packet + messaging)

The **APRS** page (`/aprs`, `aprs.py`) receives APRS — the ham packet network of
position beacons, weather, telemetry and short **messages** — from two sources
into one station map + packet feed + message view:

- **RF (SDR)** — `rtl_fm | multimon-ng -a AFSK1200` decodes the local APRS
  channel (144.390 MHz North America, 144.800 Europe, 145.175 Australia, …; a
  region picker sets the frequency, or type your own MHz). Receive-only; no
  licence needed to listen.
- **APRS-IS (Internet)** — a TCP client to the global network
  (`rotate.aprs2.net:14580`). A **read-only** login (no callsign) streams **any
  region** via a server filter (`r/lat/lon/km`); with **your own callsign +
  passcode** you get **write access to send messages**, which IGates near the
  recipient relay onward. The passcode is the standard APRS-IS callsign hash
  (`aprs.aprs_passcode`).

`parse_aprs` handles uncompressed & compressed positions (with/without
timestamp), **Mic-E**, messages/acks, objects, status and best-effort weather —
13 selftests including a Mic-E round-trip and the passcode algorithm.

- **One dongle** — RF APRS shares the RTL-SDR with the sweep / ISM / ADS-B /
  pager / VOR / radio, so starting one stops the others. **APRS-IS is
  independent** (Internet only) and keeps running regardless — so the page is
  useful even with no dongle at all.
- **No RF transmit** — RTL-SDR can't transmit and HackRF TX (licence + amp/
  filter care) is deliberately out of scope; APRS-IS carries the messaging.
  Sending still injects under your callsign on the ham network — **only licensed
  operators should send.**

## API

| Route | Purpose |
|---|---|
| `GET  /api/net/rtl/status` | Dongle detection (gates the tab) + capture state for both modes |
| `GET  /api/net/rtl/diagnose` | SDR health check (USB/tools/DVB/power) — the "SDR check" button |
| `POST /api/net/rtl/install` | One-click install of rtl-sdr/rtl-433 + DVB unblock |
| `POST /api/net/rtl/ism/start` `{band}` | Start the ISM scanner (433/868/915) |
| `POST /api/net/rtl/ism/stop` | Stop the ISM scanner |
| `GET  /api/net/rtl/ism/devices` | The live decoded-device table |
| `POST /api/net/rtl/power/start` `{band, lo_hz?, hi_hz?, label?}` | Start the sub-GHz sweep (band or custom/zoom/mesh span) |
| `POST /api/net/rtl/power/stop` | Stop the sweep |
| `GET  /api/net/rtl/power/frames?since=` | New waterfall frames + max-hold since a seq |
| `GET  /api/net/rtl/zwave` | Z-Wave regional plan (spans + channel centres) |
| `GET  /api/net/rtl/lora` | LoRa mesh plan — Meshtastic/MeshCore/LoRaWAN (spans + channels) |
| `GET  /api/net/rtl/tuning` · POST `{ppm,gain}` | Read / set PPM freq-correction + tuner gain (reapplied live) |
| `GET  /api/net/adsb/status` · `/aircraft` | ADS-B radar: dump1090 state + live aircraft (icao/iata/tail/country) |
| `GET  /api/net/adsb/route?callsign=…&lat=&lon=&gs=` | Filed route (origin/dest via adsbdb, cache-first) + live great-circle progress for the map view |
| `GET  /api/net/adsb/flight?hex=…&callsign=…&lat=&lon=&gs=` | Route (adsbdb) + REAL live position/type (adsb.lol) for the route map |
| `GET  /api/net/adsb/nearby?lat=&lon=&dist=` | Real aircraft near a point (adsb.lol) — the no-SDR/demo live feed, with types |
| `GET  /api/net/adsb/iploc` | Approx receiver location from the box's public IP — multi-provider + last-good cache (browser-geolocation fallback) |
| `POST /api/net/adsb/start` · `/stop` | Start / stop dump1090 (takes the dongle from the sub-GHz sweep) |
| `POST /api/net/adsb/install` | One-click install of dump1090 (fixed package set) |
| `…/rtl/record/{start,stop,status,list,get,delete}` | Session record & replay of the power sweep |
| `GET  /api/net/mesh/status` · `/nodes` · `/messages` | Mesh Nodes: serial + MQTT link state + merged nodes/messages (src-tagged) |
| `POST /api/net/mesh/start` · `/stop` · `/install` | Connect / disconnect the USB Meshtastic node; install meshtastic + paho-mqtt |
| `POST /api/net/mesh/mqtt/connect` `{host?,port?,user?,password?,topic?}` · `/mqtt/disconnect` | Connect/disconnect the Meshtastic MQTT Internet feed (no node needed) |
| `POST /api/net/mesh/send` `{text,to?,channel?,via?}` | Send a mesh text message via the node (LoRa) or MQTT (`via`=auto\|serial\|mqtt) |
| `GET  /api/net/pager/status` · `/messages?since=` | Pager decode state (`mode`, `qcii_available`) + decoded POCSAG/FLEX/QCII messages |
| `POST /api/net/pager/start` `{freq_hz, mode?}` · `/stop` · `/install` | Start/stop pager decode (`mode`=`pocsag_flex`\|`qcii`); install multimon-ng |
| `GET  /api/net/vor/status` | VOR decode state + latest `fix` (radial/lock/quality) |
| `POST /api/net/vor/start` `{freq_hz, cal_deg?}` · `/stop` | Start/stop VOR radial decode on a 108–118 MHz station |
| `GET  /api/net/aprs/status` · `/packets?since=` · `/stations` · `/messages?since=` | APRS state + packet feed + station map + messages |
| `POST /api/net/aprs/rf/start` `{freq_hz}` · `/rf/stop` | Start/stop off-air APRS decode (rtl_fm\|multimon-ng, one dongle) |
| `POST /api/net/aprs/is/connect` `{callsign,passcode,filter}` · `/is/disconnect` | Connect/disconnect APRS-IS (read-only, or write with a valid passcode) |
| `POST /api/net/aprs/send` `{to,text}` | Send an APRS message via APRS-IS (needs write access) |
| `GET  /api/net/acars/status` · `/messages?since=` | ACARS datalink state + decoded messages (tail/flight/label/text) |
| `POST /api/net/acars/start` · `/stop` · `/install` | Start/stop ACARS decode; build acarsdec from source |
| `GET  /api/net/{pager,vor}/selftest` · `/api/net/rtl/selftest` | Offline DSP / parser self-tests |

## CLI

`rtl_sdr.py` runs standalone for quick checks (no web server needed):

```bash
python3 rtl_sdr.py detect
python3 rtl_sdr.py ism   --band 433 --seconds 20
python3 rtl_sdr.py power --band subghz --seconds 20
python3 rtl_sdr.py selftest
python3 pagerdecode.py run --freq 154.265M --seconds 30   # POCSAG/FLEX/QCII
python3 vor.py run --freq 113.600M --seconds 30           # live VOR radial
python3 aprs.py parse 'SRC>APRS,WIDE1-1:=5132.07N/00007.24W-hi'   # APRS parser
python3 aprs.py selftest
```

## Legality

Listening is passive, but decoding third-party device telemetry (TPMS, meters,
sensors) can be regulated where you live. Use it on your own devices and within
local law.
