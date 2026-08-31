# 🛡️ WiFi Defense — 802.11 Frame Monitor / WIDS

A passive **wireless intrusion-detection system** built into Ragnar's web UI —
its own top-level **WiFi Defense** tab (next to *Network*). It listens on a
**monitor-mode** adapter for 802.11 management frames and flags the classic
Wi-Fi attacks a defender cares about.

> **Receive-only.** WiFi Defense never transmits a frame — it does not deauth
> attackers back, inject, or probe. It is a detection tool (a WIDS), not an
> attack tool. It complements the passive **[WiFi Analyzer](wifi-analyzer.md)**
> (which surveys the spectrum); this tab watches for *attacks*.

---

## What it detects

| Attack | What it is | How it's flagged |
|--------|-----------|------------------|
| **Deauth / disassoc flood** | The 802.11 deauthentication DoS (`aireplay-ng`, `mdk4`): spoofed deauth/disassoc frames kick clients off an AP. | A burst of deauth/disassoc management frames; ≥ 15 in a window is called a **flood**. The **scope** (broadcast — to all clients — vs targeted), the dominant **reason code**, and the **Protected-Frame** posture are reported: an all-unprotected burst is a spoof, and aimed at a PMF/802.11w (6 GHz/WPA3) network it's an anomalous bypass attempt even though the frames are ignored. The attacker (transmitter) and target are listed. |
| **Beacon flood** | A storm of fake APs (`mdk3`/`mdk4` beacon mode, ESP32 spammers) — bogus SSIDs to drown the air or bait clients. | Two triggers. **(1) Randomized-BSSID burst** — mdk4's beacon mode emits random, **locally-administered** MACs, so a burst of ≥ 18 distinct BSSIDs whose **LA ratio ≥ 50 %** is a fake-AP storm (**critical**) even *below* the absolute count threshold. Ordinary neighbourhood density uses burned-in (global) MACs (~0 % LA) and stays quiet — so this is robust in dense RF without guessing a count. **(2) Absolute count** — distinct SSIDs ≥ a user-tunable threshold (default 100) or BSSIDs ≥ 150; a dense airspace over the threshold but with global MACs is a **warning** (unusually dense), not a critical storm. The capture's live SSID/BSSID counts **and LA ratio** are shown for calibration. |
| **Rogue AP / evil twin** | A look-alike AP advertising a **known** SSID from a BSSID that isn't yours, set up to harvest clients. | An SSID in the **trusted baseline** appearing from an untrusted BSSID → *evil twin*; or one SSID from ≥ 2 BSSIDs → *duplicate SSID* (set a baseline to confirm). |
| **KARMA / MANA** | An AP that answers probe requests for **many different SSIDs** — it pretends to be every network a client has ever joined. | A single BSSID that beacons/probe-responds for ≥ 5 distinct SSIDs. |
| **Auth flood** | The 802.11 authentication DoS (`mdk4 a`, ESP32 Marauder/Bruce, **HaleHound Auth Flood**): authentication-request frames sprayed from many spoofed/random source MACs at one AP to exhaust its client table. | Auth frames grouped by **target BSSID**; a target hit by ≥ 30 frames from ≥ 12 **distinct** source MACs is flagged. A high **locally-administered** (randomized) source ratio (≥ 50 %) is the spoof signature that separates it from ordinary roaming — real association comes from a handful of burned-in client MACs, never dozens of randomized ones at once. |

A big banner summarises the capture: **CLEAR**, **WARNING**, or **⚠ UNDER
ATTACK** (critical). Below it, one card per detection with the offending
BSSIDs/attackers, then frame counts and an inventory of every AP heard.

---

## Monitor mode (how it's set up)

WiFi Defense needs an adapter in **monitor mode**, configured with plain `iw`
(no `aircrack-ng` required):

- A **separate monitor vif** (`ragmon0`) is added on the adapter's radio (e.g.
  the **Alfa AWUS036AXM** / `mt7921u`). While monitoring, that adapter's
  **managed interface is brought down** — on a single-radio adapter a managed
  interface that stays up *holds the channel*, so the monitor can't be tuned
  (`iw set channel` → `EBUSY -16`) and hears nothing. Taking it down hands the
  radio to the monitor; **Disable monitor** brings it back up. Use the Pi's
  onboard Wi-Fi (or Ethernet) for connectivity while that adapter monitors.
  While monitoring, the adapter is also set **unmanaged in NetworkManager** (and
  `wpa_supplicant` released) so it isn't re-upped/reset under the monitor — the
  cause of `ragmon0` "disappearing" (ENODEV) right after a disable→re-enable.
  Disable re-manages it.
- If a concurrent vif can't be created/tuned, the adapter itself is switched
  into monitor mode (also off your network until you disable it; the UI warns).

The Pi's **onboard `brcmfmac` radio does not support monitor mode** at all, so
you need a capable USB adapter. **Enable monitor** sets it up; **Disable
monitor** restores the interface.

**Channel:** a monitor radio only hears one channel at a time. Leave the channel
box on **`hop`** to cycle the common 2.4/5 GHz channels during the capture
(catches attacks on any channel), or pin a specific channel number to dwell on
it (best when you already know where the attack is).

### Dedicated monitor (boot-time) — most robust

If you have an adapter you can **dedicate 100% to sniffing** (a spare USB dongle,
with the Pi's onboard Wi-Fi / Ethernet carrying connectivity), claim it as a
**dedicated monitor at boot** instead of toggling it from the web UI. The whole
interface is switched into `type monitor` (switch-mode) once, before the app
starts, so there is **no shared-radio vif, no runtime enable/disable dance, and
none of the EBUSY / "`ragmon0` disappeared" (ENODEV) failure modes**. WiFi
Defense then just captures on the already-monitor interface. The web UI detects
this and shows **"Dedicated monitor (wlan1) — boot-managed"** with the toggle
disabled (systemd owns the adapter).

Set it up (opt-in):

```bash
# 1. Try it once by hand (root):
sudo scripts/wifidef_dedicate.sh wlan1 US 2437 0
#      <iface> <regdomain> <init-freq-MHz> <six_ghz:0|1>

# 2. Make it persistent across reboots:
sudo cp scripts/ragnar-wifidef-monitor.service /etc/systemd/system/
sudo mkdir -p /etc/ragnar
sudo cp scripts/wifidef-monitor.env.example /etc/ragnar/wifidef-monitor.env
sudoedit /etc/ragnar/wifidef-monitor.env        # set WIFIDEF_IFACE=wlan1 etc.
sudo systemctl daemon-reload
sudo systemctl enable --now ragnar-wifidef-monitor
```

The unit runs **before** `ragnar.service` and, on stop/disable, hands the adapter
back to NetworkManager. Config lives in `/etc/ragnar/wifidef-monitor.env`:

| Var | Meaning |
|-----|---------|
| `WIFIDEF_IFACE` | the dedicated capture adapter (e.g. `wlan1`) — **not** the Pi's onboard `wlan0` |
| `WIFIDEF_REGDOMAIN` | 2-letter ISO regdomain (`iw reg set`) — needed to unlock 5 GHz DFS / 6 GHz |
| `WIFIDEF_INIT_FREQ` | MHz to park on at boot; the scan hopper retunes immediately |
| `WIFIDEF_SIX_GHZ` | `1` also hops 6 GHz — requires a Wi-Fi 6E radio (e.g. `mt7921u` / AXM) and a correct regdomain |

You can also run it directly: `python3 wifi_defense.py dedicate --interface wlan1
--regdomain US --init-freq 2437 [--six-ghz]`.

---

## Using it

1. Plug in a monitor-capable adapter and pick it in **Monitor adapter**.
2. **Enable monitor** (adds `ragmon0`, or switches the adapter). The **same
   button toggles it off** — it reads *Disable monitor (ragmon0)* while active.
   Enabling always rebuilds a **fresh, channel-primed** vif (tearing down any
   lingering one first), so disable→re-enable reliably comes back working rather
   than a vif that exists but hears nothing. Disabling also stops a running
   **Continuous** scan (otherwise its next loop would just re-enable monitor).
3. **Trust current APs** in a known-good environment — this **adds** the
   currently-shown APs to the SSID→BSSID baseline that powers **evil-twin**
   detection. It *accumulates* (union), so run it a few times / across a scan or
   two: a single capture window can't hear every BSSID of every SSID (dual-band
   radios, mesh nodes and band-steering publish one SSID from several BSSIDs),
   and any legit BSSID not yet trusted would otherwise be flagged as an evil
   twin. **Reset baseline** clears it to start over.
4. **Scan** for a capture window (default 15 s), or tick **Continuous** to
   re-scan on a loop as a live monitor — each capture starts only after the
   previous one finishes (no overlap). Hit **■ Stop** to end the loop.

### Pivot to the Spectrum Analyzer

Every BSSID in a detection card (evil twin / duplicate SSID, KARMA, the source
MAC of a deauth attacker) and every row of the **Access Points seen**,
**Airtime & link quality** and **Client isolation observer** tables is
clickable — it jumps to **Network → WiFi Analyzer**, selects that AP and marks
it in the spectrum with a red dashed **⚠ WIDS** locator (band filter is widened
to *All* so it can't be hidden). A red *"Flagged by WiFi Defense"* banner above
the spectrum shows what you're chasing; the highlight survives re-scans until
you hit **✕ dismiss**. If the analyzer's last survey doesn't contain the BSSID
it re-scans once, and the banner says so when the AP still isn't heard (rogue
gone quiet, out of range of the survey radio, or beaconing intermittently).
From there you get the analyzer's full toolkit on the rogue: RSSI history,
channel + width, vendor OUI, and the **signal-radius rings** to walk it down
physically.

### 📄 Incident report (HTML → PDF)

The **Report** button turns the capture currently on screen into a
self-contained, printable **WIDS incident report** — open it in the new tab and
use the browser's *Save as PDF* for a shareable evidence artifact. It uses the
panel's last scan (no fresh capture) and contains:

- a **CLEAR / WARNING / CRITICAL** threat verdict;
- a colour-coded **detections table** — deauth/disassoc floods, beacon floods,
  evil twins / duplicate SSIDs, KARMA/MANA — each with its detail line;
- **airspace posture**: distinct SSID/BSSID counts against the flood
  thresholds, plus the randomized-MAC **LA-ratio** (high = spoofed frames);
- the full **access-point inventory** (BSSID, SSID, channel, RSSI, beacons);
- when you've run **Analyze with AI**, the **AI analysis** itself, rendered
  inline (it notes which of the three modules it covered).

The same shared report engine renders the Spectrum Analyzer and Wardriving
reports, so all three are one visual family. Informal — not a certified
assessment.

### 🤖 Analyze with AI (all three modules, one read)

The **Analyze with AI** button sends whatever the panel currently holds — the
WIDS scan plus any **Airtime** and **Client-isolation** captures you've run — to
the AI in a **single** call, and returns one correlated read across all three
modules. Because it reasons over the modules together it can tie evidence across
them (a deauth burst lining up with a retry spike, or a "rogue AP" that's really
a legit AP with a randomized-MAC client), and it calibrates severity against the
capture length so a short hopping capture reads as weak evidence rather than an
incident. Run each module first for the fullest picture. The read is stashed so
the **Report** button embeds it. Needs an OpenAI token configured in **Config**
(the button is a no-op with a hint otherwise). Advisory only — see
[AI integration](AI_INTEGRATION.md).

---

## API & CLI

Detection-only; the only state written is the trusted-AP baseline.

| Endpoint | Purpose |
|----------|---------|
| `GET /api/wifidef/interfaces` | wireless adapters + monitor capability + current monitor state |
| `POST /api/wifidef/monitor` | `{action: enable|disable, interface}` — set up / tear down monitor mode |
| `GET /api/wifidef/scan?interface=&seconds=&channel=` | capture window + WIDS analysis |
| `GET/POST /api/wifidef/baseline` | get / add-to (`{aps}` or capture) / `{action:clear}` the trusted SSID→BSSID baseline |
| `GET/POST /api/wifidef/thresholds` | get / set the beacon-flood thresholds (`{beacon_ssids, beacon_bssids}`) |
| `GET /api/wifidef/airtime?interface=&seconds=&channel=` | passive airtime / retry / PHY-rate / roaming diagnostics |
| `GET /api/wifidef/isolation?interface=&seconds=&channel=` | passive per-BSS client-isolation audit (+ mesh/ESS rollup) |
| `POST /api/wifidef/report` | `{scan, ai?}` (the panel's last capture + optional AI read) → printable HTML incident report |
| `POST /api/ai/wifidef-analyze` | `{wids, airtime?, isolation?}` → one AI read correlated across all three modules |
| `POST /api/wifidef/halehound` | `{scan?, bt?, portal?, subghz?}` → fused ESP32-attack-tool assessment (see below); `subghz:true` adds an opt-in RTL-SDR sweep |
| `GET/POST /api/wifidef/halehound/watch` | headless 24/7 watcher — `POST {enable, interface, …}` to toggle (persists across restart), `GET` for status (see below) |
| `POST /api/wifidef/halehound/portal-probe` | `{url}` → **actively** fetch a captive portal (read-only) and match the GARMR signature (see below) |
| `GET /api/wifidef/selftest` | parser + detector self-test |
| `GET /api/wifidef/halehound/selftest` | HaleHound correlation self-test |

## ESP32 attack-tool correlation (HaleHound / Marauder / Bruce)

This is a general **ESP32 attack-multitool** detector — HaleHound-CYD included,
but not only it. [HaleHound-CYD](https://github.com/JesseCHale/HaleHound-CYD) is
an ESP32 **attack multitool** — 40+ modules across Wi-Fi (deauth, beacon spam,
auth flood, evil-twin **GARMR** captive portal, KARMA), BLE (Fast Pair spam,
FindMy/AirTag flood, tracker spoofing), 2.4 GHz NRF24, SubGHz CC1101 and NFC.
**ESP32 Marauder, Bruce and Ghost ESP** run the same silicon and the same
techniques. The correlation is **folded into the main WIDS scan** — every WiFi
Defense scan also renders a fused ESP32 verdict inline (above the detections),
reusing that same capture rather than re-scanning. It does **not** re-implement
the Wi-Fi checks; it consumes the WIDS detections and fuses them with the other
radios/domains.

**What it can and cannot do.** None of these tools can be *uniquely*
fingerprinted, nor told apart from each other: same ESP32 silicon, same
techniques, and they randomize source MACs during floods. So this does **not**
claim "that is HaleHound" — it scores how strongly the observed behaviour matches
an ESP32 attack multitool *of that class* (0–100 → *trace / possible / likely /
confirmed*), fusing signals across domains:

| Domain | Signals | Source |
|--------|---------|--------|
| **Wi-Fi** | auth flood, evil-twin, beacon flood, KARMA, deauth — tool-agnostic behaviour | this WIDS capture |
| **LAN** | an Espressif host flagged as a known attack tool (`halehound_cyd`, `esp32_marauder`, `esp_deauther`, `flipper_wifi`) or an unknown ESP32 (`rogue_espressif`) — e.g. HaleHound's **IoT Recon** joins your LAN with a real ESP32 MAC. Matched on the Espressif **OUI/vendor**. | asset inventory (`device_classifier.detect_threats`) |

> **No false alarms from ordinary IoT.** ESP32 is one of the most common IoT
> chips — a home can hold a dozen (smart plugs, bulbs, sensors). So an *unknown*
> Espressif host (`rogue_espressif`) is treated as **corroboration only**: it adds
> to the score **only when real, attack-grade behaviour is already seen** in
> another domain, and multiple quiet ESP32s **never stack**. A shelf full of smart
> plugs scores **zero** and raises nothing. Only a device that literally advertises
> an attack-tool name (`halehound_cyd`, `esp32_marauder`, …), or an ESP32 seen
> *alongside* an actual Wi-Fi/BLE attack, moves the needle. (OUI is also useless on
> the *attack frames* themselves — those tools randomize their source MAC — which
> is why the Wi-Fi detectors key on the randomization ratio, not the OUI.)
| **BLE** | Apple (0x004C) FindMy/AirTag flood or Continuity pairing-popup spam, Microsoft Swift Pair (0x0006) spam, **Google Fast Pair** (service-data UUID `0xFE2C`) / WhisperPair spam, advertisement flood | the Bluetooth 2.4 GHz overlay (`bt_scanner` — now parses **both** manufacturer-data company IDs **and** service-data UUIDs) |
| **SubGHz** | 300–439 MHz **replay** (one captured code re-sent many times) or **brute / rolling-code sweep** (many distinct codes from one protocol) | an **RTL-SDR** via `rtl_433` (`subghz_watch`), opt-in sweep — see below |
| **Portal** | a GARMR-style **DNS-hijack** captive portal (all DNS → the AP's IP + a credential page) | observed portal behaviour, if collected |

The correlation is deliberately **multi-domain**: a single noisy domain is capped
so it can only reach *possible* on its own, while behaviour spanning two or three
RF domains at once — the ESP32-multitool signature — escalates to *likely* /
*confirmed*. A **named** attack tool on the LAN (HaleHound, Marauder, deauther,
Flipper) is floored to at least *likely*. When the score crosses a tier it is
emitted into the **Watchtower** feed as a `halehound` alert (`HH-CONFIRM` /
`HH-LIKELY` / `HH-POSSIBLE`) and fused by the **incident engine** into an *ESP32
attack multitool active* incident.

### Actively confirming a GARMR portal

HaleHound exposes **no management API** — it's a touch-driven device, and OTA is
from its SD card, so there's nothing on the network to politely query. The **only**
page it ever serves is the **GARMR evil-twin captive portal**, and only while it's
actively running that attack. So the one "ask it" move is: associate with the
rogue SSID and fetch that portal.

`POST /api/wifidef/halehound/portal-probe {"url":"http://<portal-ip>/"}` does
exactly that — a **read-only GET** (it *never* submits credentials) — then
extracts the page `<title>`, HTTP `Server` header, `<input>` field names and a
body hash, and matches them against a **GARMR signature table**
(`halehound_watch._GARMR_SIGNATURES`). A match is a **HaleHound-specific**
confirm and floors the verdict to *likely*/*confirmed* on its own — far stronger
than the generic DNS-hijack tell. Safety: the target is restricted to a
**private/link-local/loopback IP literal** (the portal gateway), so it can't be
pointed at arbitrary hosts, and a hostname is refused (it would resolve through
the hijacked DNS).

The signature table ships **empty** — so it never false-matches — with a
documented schema (title/Server/form-fields/HTML-markers/SHA-256). Drop in the
real GARMR fingerprints and the confirm goes live with no code change.

### SubGHz sweep (RTL-SDR)

SubGHz is **opt-in** because it briefly claims the RTL-SDR and takes ~20 s: tick
**+SubGHz** in the WIDS controls (or `POST /api/wifidef/halehound {"subghz":
true}`) — it runs on manual scans only, never in the continuous loop.
`subghz_watch.scan()` runs `rtl_433` across 433.92 MHz + 315 MHz and flags a
**replay** (same model+id+payload re-sent ≥ 8× in the window — well above any real
remote's cadence) or a **brute / rolling-code sweep** (≥ 16 distinct codes from
one protocol). Thresholds are deliberately conservative so ordinary 433 MHz
telemetry (weather stations, TPMS, doorbells — which repeat a few frames per
burst) reads as benign `subghz_active`, not an attack. The sweep is **skipped**
(with a stated reason) when no SDR is present or another SDR job — ADS-B, ACARS,
VDL2, the waterfall — already holds the radio; Ragnar never yanks it away. *This
path is validated end-to-end on real RTL-SDR hardware, but not yet against a live
CC1101/HaleHound emitter.*

**Blind spots are hardware-aware — the panel reports what THIS node can actually
see.** The list adapts to the attached radios rather than claiming a fixed set:

- **SubGHz** — with an RTL-SDR on the bus it is a *live domain* (or "present but
  not swept this pass" until you enable it), **not** "needs an SDR". You do **not**
  need a CC1101; an RTL-SDR covers 300–439 MHz. Only a bare node (no SDR) shows
  "needs an SDR".
- **Google Fast Pair (`0xFE2C`)** — no longer a blind spot when a BLE radio is
  attached; `bt_scanner` now parses service-data, so Fast Pair spam is a scored
  BLE signal.
- **GATT-level** BLE attacks (BLE Predator honeypot, Airoha RACE, SkeletonKey)
  remain out of view — that's a limit of *passive* scanning (they need an active
  connection), independent of the radio.
- **NRF24 2.4 GHz** (MouseJack, jammers) and **NFC/RFID** remain genuine hardware
  gaps — Ragnar carries no nRF24 receiver or NFC reader.

All of these are *listed* rather than silently missed. Everything here is passive
analysis — nothing is transmitted (the SubGHz sweep only receives).

### Headless 24/7 watch (continuous)

The inline verdict updates with each scan you run (or each cycle of the
**Continuous** loop). The **24/7 watch** checkbox in the WIDS controls turns the
*same* fusion into a headless background monitor: a daemon thread
(`halehound_daemon.py`) periodically captures
a Wi-Fi window, refreshes a **cached** BLE snapshot on a slower cadence, scores it
through `halehound_watch.assess`, and emits into the **Watchtower** feed /
incident engine (and thus Pushover) whenever the verdict crosses the alert tier —
**with no browser open**.

It is deliberately **slow and Pi-Zero-friendly**: a short (~12 s) capture then a
long idle gap (~90 s), with BLE refreshed only every ~5 min and **SubGHz never
auto** (it holds the shared SDR). The enabled flag + config are **persisted**
(`data/halehound_daemon.json`), so "if enabled" survives a restart —
`resume_if_enabled` relaunches it at startup. It needs **monitor mode enabled**
(it captures continuously); a failed capture is caught, counted, and backed off,
never crashing the thread. Toggle via `POST /api/wifidef/halehound/watch
{"enable":true,"interface":"<mon>"}`; `GET` the same route for live status
(cycles, last verdict, last error). The one-shot button and the daemon share one
scoring core, so their verdicts are identical.

### Field-test playbook (HaleHound / Marauder / Bruce / Ghost ESP)

Ragnar does **not** detect a *firmware* — it detects the **attacks** a firmware
performs. HaleHound-CYD, ESP32 Marauder, Bruce and Ghost ESP run the same ESP32
silicon and the same techniques, so they trip the **same** detectors. To validate,
you don't test the firmware, you **run an attack mode and watch the matching
detector fire**. The mapping is identical whichever tool you flash.

**What to run on the ESP32 tool → what Ragnar detects:**

| Attack mode on the tool | Ragnar detector | Where it shows | Domain |
|---|---|---|---|
| Deauth attack | `deauth` flood | WiFi Defense → 💥 Deauth FLOOD | wifi |
| Beacon spam / fake-AP flood | `beacon_flood` (randomized-MAC ratio) | 📡 Beacon flood | wifi |
| Auth flood / Auth DoS ("Auth Flood") | `auth_flood` | 🌊 Auth flood | wifi |
| Evil twin / rogue AP (clone your SSID) | `rogue_ap` evil-twin — **needs a baseline set first** | 👿 Evil twin | wifi |
| GARMR captive portal (evil-twin + DNS hijack) | portal fingerprint | HaleHound card / `portal-probe` | portal |
| KARMA / "answer every probe" | `karma` | 🎣 KARMA/MANA | wifi |
| BLE spam — Sour Apple / AppleJuice / Swift Pair / Fast Pair / AirTag flood | `apple_ble_flood` / `swiftpair_spam` / `fastpair_spam` / `ble_advert_flood` | HaleHound card → ble | ble |
| SubGHz replay / brute (CC1101, 315/433 MHz) | `subghz_replay` / `subghz_brute` | HaleHound card (tick **SubGHz sweep**) | subghz |
| Join your Wi-Fi (HaleHound "IoT Recon", or just connect it) | `rogue_espressif` (or `halehound_cyd` if it announces that hostname) | asset inventory / HaleHound suspects | lan |

**The real test is fusion.** Any single attack is capped at *trace / possible* on
its own, on purpose — it must not cry wolf. The *likely / confirmed* "ESP32 attack
multitool" verdict comes from running **two or more domains at once**, which is how
these tools actually operate. The headline demo:

1. Put the ESP32 on your Wi-Fi (→ **lan**: Espressif host), **and**
2. Run a deauth or auth flood (→ **wifi**), **and**
3. Start its BLE spam (→ **ble**).

→ Ragnar fuses wifi + lan + ble → **likely/confirmed**, emits a `halehound`
Watchtower alert, and the incident engine raises an *"ESP32 attack multitool
active"* incident.

**Ragnar-side prerequisites (or the detector stays dark):**

- **Wi-Fi** detectors need the adapter in **monitor mode** on the attack's channel
  (WiFi Defense → enable monitor). Deauth / beacon / auth / KARMA / evil-twin all
  come from that capture.
- **Evil twin** specifically needs a **baseline** set first — otherwise a legit
  multi-BSSID SSID (band-steering/mesh) is correctly *not* flagged.
- **BLE** needs a Bluetooth controller. Thresholds are set **above** ordinary room
  density (≥20 distinct Apple, ≥15 Swift/Fast Pair advertisers) so a quiet home
  never false-flags — a single pairing press won't trip it, the tool's *continuous*
  spam mode will.
- **SubGHz** needs the RTL-SDR free (no ADS-B/ACARS/waterfall running) and the
  **SubGHz sweep** box ticked (opt-in, ~20 s).
- **LAN** detection needs Ragnar to have **scanned the network** (host inventory)
  so the ESP32 shows up as a host.

**Honest limit — state it plainly.** Ragnar reports *"ESP32 attack multitool of the
HaleHound / Marauder / Bruce class"*; it **cannot** say *"this is HaleHound
specifically"*, because the radio evidence is identical across these tools and they
randomize MACs. The only tool-specific confirms are (1) a **GARMR captive-portal
signature** match — the table ships empty, so drop in HaleHound's real portal
`title` / `Server` header / form-field names and it becomes a hard confirm — or
(2) the device announcing a `halehound` / `garmr` hostname on the LAN.

## Airtime & link quality

A separate passive diagnostic (the "why is it slow" view). Capture all 802.11
frames — ideally on a **fixed channel** (airtime % is only meaningful when not
hopping) — and get, per AP: the **SSID** (named from beacons/probe responses
heard in the capture; a BSSID that only sent data frames shows —), **airtime %**
(estimated on-air time / capture time), **retry rate** (retransmit flag), the
**PHY-rate spread** (min/median/max Mbps), plus **roaming churn** (clients
re-associating/authing repeatedly). Findings flag high retry (≥30%), airtime
hogs (≥50%) and unstable roaming. Route `GET /api/wifidef/airtime`; analysis is
a pure function covered by selftest.

### Airtime starvation / the "legacy client tax"

On 2.4 GHz the medium is half-duplex CSMA/CA: airtime — not bandwidth — is the
finite shared resource, and a single slow station consumes it out of all
proportion to the bytes it moves. A client stuck at 1–11 Mbps DSSS (802.11b)
needs enormously more time-on-air per frame than a Wi-Fi 6 client at hundreds of
Mbps, and its mere presence makes the AP announce **ERP protection** (RTS /
CTS-to-self) that every station in the BSS then pays on every frame. The cell
looks "downgraded" but the mechanism is airtime starvation, not a rate drop.

Ragnar pinpoints this two ways from the same passive capture:

- **ERP protection detection** — the ERP Information element (ID 42) in beacons
  carries a *Use_Protection* bit. When set, the AP is telling everyone a legacy
  DSSS client is present; the AP row shows an **ERP** badge and an
  `erp_protection` finding names the BSS.
- **Per-client airtime attribution** — airtime is also bucketed by the
  transmitting station (addr2), not just the AP. A station transmitting at DSSS
  rates while eating real airtime is classified `802.11b (DSSS/CCK)` and raised
  as a `slow_client` finding naming its MAC — the device to move to its own
  SSID / 5 GHz, or to lock out by disabling the low basic rates on the AP.

The per-client table (`clients[]` in the response) lists each station's PHY
generation, frame count, airtime % and rate spread, with legacy rows
highlighted.

#### Naming the device (radio + network fusion)

The monitor radio only sees a client by **MAC** — it can say *"this MAC is
802.11b"* but not *what the device is*. Device identity (hostname, vendor,
printer/phone/TV) is a **network-layer** fact that needs an association to the
AP, which a monitor interface never has. So the two layers are fused by MAC:

- **radio layer** (monitor mode) → MAC → PHY / airtime (the `clients[]` rows);
- **network layer** (the connected radio's host inventory: DHCP/mDNS/ARP + the
  device classifier) → MAC → ip / hostname / vendor / device type.

The `/api/wifidef/airtime` route joins the two on MAC (`enrich_identity()` +
`_enrich_airtime_identity()`), so each client row also carries `hostname`, `ip`,
`vendor`, `device_type` and `device_label`, and the `slow_client` finding names
the device (e.g. *"HP-LaserJet (192.168.1.42) [aa:bb:…] is 802.11b …"*). MACs
not in the inventory fall back to an OUI vendor and show as *unidentified* until
a network scan records them; randomized MACs are left unnamed.

Each client row also carries the **SSID** of the AP it is transmitting to
(joined from the AP's `bssid`→`ssid` map; a client whose AP never beaconed in
the capture falls back to showing the BSSID). The per-client table has an
**SSID filter** dropdown so a multi-network capture can be narrowed to one
network — you see exactly which clients belong to which SSID.

**Recommended deployment (Pi Zero 2 W + one Alfa AWUS036AXM).** Legacy 802.11b
is a 2.4 GHz-only phenomenon, so a 2.4-only onboard radio loses nothing here.
Let the **Pi onboard radio stay connected** (managed mode) to the target 2.4 GHz
SSID — it populates the host inventory (hostnames / device types) — and put the
**Alfa in dedicated monitor mode on that same channel** for the PHY/airtime
capture. One Alfa is enough; the onboard radio can't do monitor mode but does
managed fine, and each radio does the one job it's suited to. (A single
mt7921u Alfa can alternatively do both at once via a concurrent monitor vif
pinned to the connected channel.)

### Per-AP security & PHY generation

Each AP row also reports two metrics read straight from its beacons (no active
probing):

- **Security** — `Open` / `WEP` / `WPA` / `WPA2` / `WPA2-Ent` / `WPA3` /
  `WPA2/3` (transition) / `OWE`, decoded from the Privacy capability bit, the
  RSN element (ID 48) and its AKM suites, and the legacy WPA v1 vendor element.
  `Open` and `WEP` also raise a `weak_security` finding.
- **PHY** — the 802.11 generation from the capability IEs: `802.11n (Wi-Fi 4)`,
  `802.11ac (Wi-Fi 5)`, `802.11ax (Wi-Fi 6)`, `802.11be (Wi-Fi 7)`, or — when no
  HT/VHT/HE/EHT IE is present — the legacy PHY split by band and rate set:
  `802.11a`, `802.11g` (OFDM rates advertised) or `802.11b` (DSSS-only). The
  b/g split is what the Spectrum Analyzer's coarser "legacy" label can't do.

### Accuracy model (how PHY and airtime are attributed)

The per-client analysis was hardened against the classic 802.11 attribution
traps (mirroring the standalone `legacywatch` methodology):

- **Both directions.** Airtime is keyed on the *station*, resolved from the
  DS bits (`ToDS`/`FromDS`) — uplink `addr2`, downlink `addr1` — so a station's
  downlink cost is counted for it, not misfiled onto the AP. Counting `addr2`
  alone (uplink) understates a legacy station by ~half.
- **PHY from data frames only.** Management/control frames (probe requests,
  ACKs) are sent at basic rates even by modern clients, so they are excluded
  from PHY-rate observation — otherwise a Wi-Fi 6 phone that probes at 1 Mbps
  would be mislabeled `802.11b`.
- **Declared beats observed.** A station's own (re)assoc/probe request declares
  its capability directly: an HT/VHT/HE element present ⇒ `802.11n+` for
  certain; absent ⇒ genuine pre-802.11n. Each client row carries a
  `confidence` of `declared` (from the capability element) or `observed` (rates
  only, weaker — a modern client at the cell edge can look legacy).
- **Preamble-accurate airtime.** On-air time is PHY preamble + data-symbol time;
  a 1 Mbps DSSS frame carries a 192 µs long preamble (1500 B ⇒ 12 192 µs), which
  a flat overhead constant would miss.
- **Disproportion.** Each client reports airtime-share ÷ byte-share — the number
  that names the culprit: a station moving 2% of the bytes while eating 54% of
  the airtime.

### Cipher as a throughput problem

The RSN cipher suites (group + pairwise) are parsed, because encryption choice
is also a speed ceiling: a **TKIP group cipher** disables 802.11n rates for
group-addressed frames BSS-wide (`cipher_tkip_group`), and **pairwise TKIP**
hard-caps any client that selects it at 54 Mbps (`cipher_tkip_pairwise`). The
beacon's **HT Operation** element is read too — `HT Protection = Non-HT Mixed`
(`ht_protection_mixed`) means a pre-802.11n station is associated and 11n rates
are protected for everyone.

### WPS / Wi-Fi Simple Config posture

The WSC element an AP advertises (WFA vendor element `00:50:F2:04`) describes
its own enrollment surface in plaintext — no association, no keys. We parse:

- **WPS State** (`0x1044`) — `Not Configured` ⇒ out-of-box enrollment open
  (`wps_unconfigured`).
- **AP Setup Locked** (`0x1057`) — clear ⇒ PIN attempts are not rate-limited.
- **Config Methods** (`0x1008`) — Label/Display/Keypad = the external-registrar
  **PIN** path (brute-forceable); PushButton needs physical presence.
- **Version2 subelement** — its *absence* means **WSC 1.0**, which has no
  mandatory lockout, so an online PIN brute force runs to completion.

The headline finding is `wps_pin_open`: the PIN method is offered and the AP is
not locked — an attacker in range can brute-force the 8-digit PIN (~11 000
attempts). WSC 1.0 makes it worse (no lockout at all). The AP row shows a
`WPS-PIN` / `WPS-1.0` badge (red when exposed) or a grey `WPS` badge for
pushbutton-only / locked APs. This is detection only — nothing derives PINs.

## Client isolation observer

A passive audit of whether an AP — or a whole mesh/ESS — actually enforces
**client isolation** (guest networks, hotel/office WLANs, IoT segments).
Encryption hides payloads, but the cleartext 802.11 header always reveals who
the AP is relaying frames *for*: a **ToDS** frame carries the wireless client
as SA, and a **FromDS** frame carries the original source as `addr3`. The
observer never transmits and never reads a payload.

Evidence collected per BSS over the capture window:

- **Peer relays** — the AP transmitted a unicast FromDS frame whose source is
  one of its *own wireless clients* and destination is another. That is the AP
  forwarding intra-BSS traffic: **isolation OFF** (verdict `open`), with the
  talking client pairs listed.
- **Broadcast relays** — the AP re-broadcast a client-originated broadcast
  (ARP and friends) into the cell: clients can at least discover each other
  (verdict `broadcast_open`).
- **Peer attempts / client broadcasts with no relay** — clients addressed each
  other (or broadcast repeatedly) yet the AP relayed nothing back: it is
  filtering (verdict `isolating`).
- Anything else — too little peer-directed traffic to judge (`no_evidence`).

Multi-node SSIDs get a **mesh/ESS rollup**: nodes grouped by SSID, plus
**cross-node forwarding** detection (a node airing traffic sourced from a
client that only ever appeared on a sibling node — mesh-wide isolation off
even when each node looks clean alone). 4-address **WDS/backhaul** frames are
counted as mesh-link evidence. Normal upstream traffic (wired-side sources
like the gateway) never counts against an AP.

Run it on a **fixed channel** (the channel of the AP/mesh under audit) —
catching a peer request *and* the AP's relay of it requires dwelling on the
BSS's channel; hopping yields only weak evidence. Route
`GET /api/wifidef/isolation`; `analyze_isolation()` is a pure function covered
by selftest (open / isolating / broadcast / mesh-cross-node cases, all
offline).

```bash
python3 wifi_defense.py interfaces
python3 wifi_defense.py monitor --interface wlan1 --enable
python3 wifi_defense.py scan --interface wlan1 --seconds 15         # or --channel 6
python3 wifi_defense.py baseline --interface wlan1 --seconds 20     # learn trusted APs
python3 wifi_defense.py isolation --interface wlan1 --seconds 30 --channel 6
python3 wifi_defense.py monitor --interface wlan1 --disable
python3 wifi_defense.py selftest
```

The self-test crafts real 802.11 frames with **Scapy** (deauth flood, 35-SSID
beacon flood, a 6-SSID KARMA AP, an evil twin, plus open / isolating /
mesh-cross-node client-isolation traffic), writes them to a pcap, then runs
the full parse → analyse pipeline and asserts each detection fires (and that
clean traffic stays **CLEAR**) — all offline.

Requires `iw` and **Scapy** (both installed by `install_ragnar.sh` /
`requirements.txt`).

---

## Troubleshooting

**"capture failed: … Errno 19 no such device" (ENODEV) / "ragmon0 is gone".**
The monitor vif named in the saved state (`ragmon0`) no longer exists — this
happens after a **reboot, a service restart, or the USB adapter being
unplugged/reset**, since the vif is not persistent but the bookmark is. This
breaks **both** the WIDS scan (AP/beacon-flood detection) *and* the
airtime/link-quality capture, because both need that monitor. Recovery is now
**automatic and two-layered**: Scan / Airtime verify the interface still exists
*before* sniffing (dropping a dead bookmark and re-enabling from scratch), and if
the vif dies *during* a capture they **rebuild it once and retry the capture** in
the same call. Continuous mode keeps looping through a recovery, so live
monitoring self-heals. If it still fails after that, **Disable monitor** then
**Enable monitor** to force a fresh vif. Your trusted-AP baseline and tuned
thresholds are preserved across all monitor bookkeeping.

*Why a **service restart** used to be the only thing that fixed it:* recreating
`ragmon0` (a disable→re-enable) gives it a **new kernel ifindex**, but the packet
library (scapy) caches the interface's old ifindex for the life of the process
and keeps binding the capture socket to the dead index → ENODEV on every scan —
until the process restarts and rebuilds that cache. Ragnar now **refreshes that
cache before every capture**, so a runtime re-enable heals just like a restart
(no `sudo systemctl restart ragnar` needed).

**Diagnosing a stubborn adapter — `scripts/wifidef_doctor.sh`.** When monitor
comes up but captures nothing (or a specific dongle misbehaves), run the doctor:

```bash
sudo ./scripts/wifidef_doctor.sh            # auto-detects the adapter
sudo ./scripts/wifidef_doctor.sh wlan1      # or name it explicitly
```

It records the environment (kernel, driver, `rfkill`, radio modes, code version
and **when the service last restarted** — a common gotcha after `git pull`),
then enables monitor through Ragnar's own code and compares an **OS-level
capture (`tcpdump`)** against Ragnar's capture on a channel that has traffic. The
contrast is the diagnosis: if `tcpdump` hears frames but Ragnar reports `frames=0`
the bug is in the capture path; if neither hears anything while `iw dev ragmon0
info` shows a real monitor channel, it's the driver/firmware. It also does a
disable→re-enable cycle and a manual vif rebuild, and dumps `dmesg`. Everything
is saved to `/tmp/wifidef_doctor_*.log` to paste into a bug report.

---

## Standalone deep monitor — `wifiwatch`

For a continuous, daemon-shaped monitor beyond the capture-window WIDS above —
raw-byte 802.11 parsers, a warmup census, per-scope refractory alerting,
JSON-lines output, pcap `--replay`, an ambient-calibration tool, and a hardened
systemd unit — see **[wifiwatch](wifiwatch.md)** (`python3 python/wifiwatch.py`). It
shares the LA-ratio beacon-flood and deauth scope/PMF logic documented above,
and adds the **WPA client / handshake layer** that this capture-window WIDS does
not cover: **PMKID harvesting** (a clientless offline-crack handle on the air),
**forced 4-way-handshake capture** (deauth-then-reconnect), **WPA3→WPA2
downgrade** (transition-mode exposure and a live SAE-strip evil twin), and
**PNL leakage** (your own devices broadcasting their saved-network lists — the
exact input a KARMA rig needs).
