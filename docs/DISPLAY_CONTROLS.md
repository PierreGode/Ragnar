# Display Buttons & Joystick Reference

Ragnar's HATs carry hardware controls that change what they do depending on the
**mode** the display is in:

- **Default** — the normal Ragnar dashboard (the everyday screens).
- **Wardriving** — while the wardriving engine is running.
- **Network Diagnostic** — while `network_diagnostic_mode` is on (a standalone
  field tester; documented in full in the [Network Tools Guide](nettools.md#-on-screen-network-diagnostic-mode)).

Two HATs have controls:

- **2.7" e‑Paper HAT** — 4 keys (`KEY1`–`KEY4`).
- **1.44" ST7735S LCD HAT** — 3 keys (`KEY1`–`KEY3`) + a 5‑way joystick.

> The smaller square/OLED panels (GC9A01, SSD1306) have no onboard buttons.

---

## 2.7" e‑Paper HAT (4 keys)

GPIO pins (BCM), fixed by the HAT: `KEY1=5`, `KEY2=6`, `KEY3=13`, `KEY4=19`.
In Default and Wardriving layers the keys act **on press**.

### Default mode

| Key | Action |
|-----|--------|
| **KEY1** | Swap to/from **Pwnagotchi** (10 s cooldown) |
| **KEY2** | **Rotate / flip** the screen (0° → 90° → 180° → 270°) |
| **KEY3** | **Next page** — cycle through the Ragnar screens |
| **KEY4** | **Restart** the Ragnar service |

### Wardriving mode (engine running)

| Key | Action |
|-----|--------|
| **KEY1** | Toggle a **phone-access AP** serving the minimal wardriving page |
| **KEY2** | **Rotate / flip** the screen |
| **KEY3** | Toggle the **live e‑paper map** (GPS track + network dots) |
| **KEY4** | **Connect** to a known Wi‑Fi (wardriving keeps running) |

> **Compact wardriving page on the 1.44" ST7735S:** the 128×128 panel is too
> small for the full stat page, so it drops the "WARDRIVING" header and shows
> only the essentials — the **2.4 / 5 / 6 GHz** network counts as large numbers,
> the **GPS** fix, **speed** (only while moving), and the **companion** status —
> with the key hints in the footer. Larger panels still get the full stat page.
> The speed uses the **Speed Unit** setting (km/h or mph) from Config → Wardriving.
>
> The count font **auto-shrinks** as the numbers grow, so a long drive that
> pushes a band into the thousands (or higher) still fits its column instead of
> overlapping the neighbouring band. All three share one size so the row stays
> visually even.
>
> That page is the first of **five** wardriving screens on the LCD HAT — see
> [Wardriving mode](#wardriving-mode-engine-running-1) below for the joystick
> carousel and its key map.

> **Exit Wardriving from the phone page:** the minimal wardriving page (join the
> KEY1 AP, open `http://192.168.4.1:8000/`) has an **Exit Wardriving** button at
> the bottom. It stops the current session and then tears down the phone-access
> AP so the device returns to normal Ragnar operation. Because dropping the AP
> disconnects the phone, the button confirms first and, once the stop is issued,
> tells you to reconnect to your normal Wi-Fi to reach Ragnar web.
>
> The page also has a **Restart Ragnar Service** button — the field recovery
> when the UI or a scan thread wedges. The AP is run by hostapd/dnsmasq rather
> than the Ragnar service, so the phone stays connected across the restart; the
> page polls until the service answers again and then resumes live updates.
> These two buttons are the *only* write actions an un-authenticated AP client
> is allowed — everything else on that page is read-only.
>
> Below them sits a **Diagnostics** panel, collapsed by default (a native
> `<details>`, so the toggle works even if a script errors — this is the panel
> you read when something is already wrong). Its summary always shows a live
> hint (`GPS fix` / `GPS searching` / `no GPS`, plus `· error`), and expanding it
> lists everything `/api/wardriving/status` exposes, grouped as **GPS ·
> Session · Scanning · Companions · Device**. GPS comes first and includes
> **SNR max** and **satellites used / in view** — the two numbers that separate
> a weak-signal problem from a receiver that keeps restarting when it sees
> satellites but never fixes. Fields with no value are omitted rather than shown
> blank, and the panel skips its DOM work entirely while collapsed. The same
> panel is on the main dashboard's **Wardriving** tab (which adds an antenna
> **Coverage** group) — see
> [Diagnostics Panel (UI)](wardriving.md#diagnostics-panel-ui).
>
> **The AP does not carry your phone's internet.** Ragnar never routes for AP
> clients (no NAT, no `ip_forward`, and while wardriving the radio is usually
> borrowed so there's no uplink at all), so the wardriving AP hands out an
> address and deliberately nothing else — no gateway, no DNS, no captive-portal
> DNS hijack. Your phone keeps its own default route and stays on **cellular**
> for internet while 192.168.4.1 remains directly reachable. Expect iOS/Android
> to label the network "No Internet" — that is the intended state. The separate
> Wi-Fi-**setup** AP is unaffected and still runs its captive portal.

### Network Diagnostic mode

Each key gains a **short** and a **long** (hold ~0.6 s) press — see the full
[field‑test key pad](nettools.md#field-test-key-pad-27-hat) table.

---

## 1.44" ST7735S LCD HAT (3 keys + joystick)

GPIO pins (BCM), fixed by the HAT: `KEY1=21`, `KEY2=20`, `KEY3=16`; joystick
`Up=6 Down=19 Left=5 Right=26 Press=13`.

> **Joystick orientation:** the joystick is physically mounted 90° clockwise of
> the panel's text, so Ragnar remaps every push into the frame **you read on the
> screen** — and re‑aligns automatically when **KEY2** rotates the display.
> The directions in the tables below are always relative to the upright text.

### Default mode

| Input | Action |
|-------|--------|
| **Joystick ↑ / ←** | Previous display page |
| **Joystick ↓ / →** | Next display page |
| **Joystick press** | **Start / stop page autoscroll** — auto-cycle the pages every 5 s |
| **KEY1** | **Toggle On‑Screen Network Diagnostic Mode** |
| **KEY2** | **Rotate** the screen (0° → 90° → 180° → 270°) |
| **KEY3** short / hold | **Next page** / **restart** the Ragnar service |

> The e‑paper HAT uses KEY1 for the Pwnagotchi swap; on the LCD HAT KEY1 is the
> field‑tester switch instead — it flips Network Diagnostic Mode on and off.
> Autoscroll pauses automatically during Network Diagnostic mode and wardriving,
> and any manual joystick page-nav switches it off.

### Wardriving mode (engine running)

While the wardriving engine runs **and the display is on the main page**, the
joystick pages a carousel of **five wardriving screens** and the three keys
become wardriving actions:

| Input | Action |
|-------|--------|
| **Joystick ↑ / ←** | Previous wardriving screen |
| **Joystick ↓ / →** | Next wardriving screen |
| **Joystick press** | Jump back to the **STATS** screen |
| **KEY1** | **Return to the Ragnar view** — leave the wardriving screens (wardriving keeps running) |
| **KEY2** | **Reconnect** to a known Wi‑Fi (wardriving keeps running) |
| **KEY3** | **Start / stop** the phone-access AP |

The screens, in carousel order (the footer shows the key hints and an `n/6`
counter):

| # | Screen | Shows |
|---|--------|-------|
| 1 | **STATS** | 2.4 / 5 / 6 GHz counts as big numbers, GPS, speed, companion |
| 2 | **MAP** | Live GPS breadcrumb + located networks, auto-scaled, current fix ringed |
| 3 | **GPS** | Lat / lon / altitude, satellites used-in-view, HDOP, speed, course |
| 4 | **SKY** | Polar sky view — satellites plotted by azimuth/elevation (North up, horizon = outer ring, zenith = centre); filled dot = strong signal, hollow = weak |
| 5 | **SESSION** | Session duration, total networks, open, WEP, Bluetooth, cells, trackpoints |
| 6 | **VIKING** | The Ragnar viking filling the panel — the "still alive?" glance screen |

> **KEY1 does not stop wardriving** — it only steps the display off the main
> page, which is where the wardriving render overrides the dashboard. The
> engine, GPS and companions keep running; joystick back round to the main page
> to return to the wardriving screens. (To actually stop a session, use the web
> UI or the **Exit Wardriving** button on the phone-access AP page.)
>
> This layer replaces the default one only while wardriving is live, so KEY1's
> Network Diagnostic toggle and KEY3's next-page/restart pair come back as soon
> as you leave the wardriving screens. The 2.7" e‑paper HAT is unaffected — it
> keeps its 4‑key map and its KEY3 stats/map toggle.

### Network Diagnostic mode

Navigated as **cards**: `LINK · IP · SWITCH · DHCP · WIFI · SIGNAL · SPECTRUM ·
IFACE · BT · ZIGBEE`.

| Input | Action |
|-------|--------|
| **Joystick ← / →** | Previous / next **card** |
| **Joystick ↑ / ↓** | Cycle the highlighted **function** inside the card |
| **Joystick press** | **OK / select** — run the highlighted function (or dismiss a result) |
| **KEY1** | **Switch to Ragnar** — toggle the mode off |
| **KEY2** | **Card-selection menu** (press again to leave) |
| **KEY3** | **Pause / start auto-switch** — auto-cycle the cards every 5 s |

Pause auto-switch (KEY3) on the **WIFI** or **SIGNAL** card and it redraws
**every second** with live RSSI — SIGNAL's bars are refreshed by a fast passive
poll of just the listed APs' channels, so they move as you walk around.

Functions: **LINK/SWITCH** → Locate Port · L2 Health; **IP** → Ping GW · Ping
WAN · DNS Doctor · Speedtest; **DHCP/WIFI/SIGNAL** are read-only. On the
**SPECTRUM** card the ↑/↓ "functions" select the **band** (2.4 / 5 / 6 GHz) —
it draws that band's live **channel-occupancy spectrum** (a bar per channel,
height ∝ the strongest AP's signal, DFS/radar channels hollow, busiest channel
tick-marked) — the WiFi Spectrum Analyzer's Bar view on the panel. Press KEY3 to
freeze the auto-cycle, then ↑/↓ to sweep bands. It scans the **widest-band
adapter present** (so a tri-band dongle like the **Alfa AWUS036AXM** is used for
5/6 GHz instead of a 2.4-only onboard radio) and shows the scanned interface
name in the header — a band reads *"not supported"* when the chosen radio can't
reach it. See the full
[field‑test pad](nettools.md#field-test-pad-144-lcd-hat--joystick) table.

The **BT** and **ZIGBEE** cards cover the other two occupants of 2.4 GHz, so the
band's whole story is on the panel next to SPECTRUM. Both are **one-shot**: the
centre press runs a scan (~8 s) and the card then shows that result until you
scan again — unlike the Wi-Fi cards nothing polls in the background, because BT
discovery and an 802.15.4 sniff each cost radio time and the auto-cycle would
otherwise re-trigger them every few seconds. Each card shows the device count,
an **Age** so a stale scan doesn't read as live, and the strongest few
neighbours as signal bars:

| Card | Needs | Shows |
|------|-------|-------|
| **BT** | a BlueZ controller (`rfkill unblock bluetooth`) | Devices, LE/Classic split, close-by count, adapter, and the Wi-Fi channel under the most BT pressure; then the loudest devices by name/vendor + RSSI |
| **ZIGBEE** | a **HuginnESP** companion with an 802.15.4 radio (ESP32-C5/C6/H2) | Devices, distinct channels, close-by count, busiest channel; then the loudest devices as `c<channel> <addr>` + RSSI |

When the hardware isn't there the card says why in short (`no adapter`,
`no Huginn`, `no 15.4 rx`, `port busy`) and the press retries. These two cards
are LCD-HAT only — the 2.7" e‑paper HAT still cycles just LINK/IP/SWITCH.

The **IFACE** card picks which NIC the egress tests (**Speedtest**, **Ping GW**,
**Ping WAN**) originate from: ↑/↓ highlights **Auto** or an interface, the
centre press selects it (`*` marks the active choice, and each row shows the
NIC's IP, *no IP*, or *down*). **Auto** follows a fixed priority — **built-in
Ethernet → USB Ethernet → wlan1 → wlan0** — picking the first interface that is
up, addressed and (for the speedtest) verified able to reach the internet, so a
plugged-in cable is tested instead of whatever holds the default route. A pinned
interface really binds the socket to that device; Ping GW then targets that
link's own gateway. The choice resets to Auto when the mode is switched on.

---

## Notes

- **Mode precedence:** Network Diagnostic mode takes over the keys/joystick while
  it's on; turning it off restores the Default (or Wardriving) behaviour.
- **Diagnostic mode ⇄ wardriving are mutually exclusive:** both own the panel and
  the HAT keys, and the diagnostic layer wins the render race, so they are never
  on together. Starting wardriving (including `wardriving_on_boot` at boot) turns
  Network Diagnostic mode **off**; turning Network Diagnostic mode on stops a live
  wardriving session. Enabling wardriving-on-boot is safe even if you left
  diagnostic mode enabled — it is cleared automatically at boot.
- **Rotation:** `KEY2` cycles the screen rotation on both HATs. On the square
  128×128 LCD the panel realises two visual orientations (upright / 180°), and
  the joystick tracks whichever is shown.
- Headless installs (no display) accept the display toggles but have nothing to
  render on and no buttons to read.
