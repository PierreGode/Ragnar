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
- **To actually identify/enumerate a mesh** (node list, names, and to decrypt the
  Meshtastic public channel), the practical path is a **companion LoRa node**
  (a Meshtastic/MeshCore device over USB, the way Huginn/Zigbee attach) — a
  possible future integration, not part of this receive-only spectrum view.

Frequencies: LoRaWAN entries follow the published regional band plans; Meshtastic
default channels are preset/hash-derived and MeshCore's are user-configurable, so
those are marked "~" / "default" — scan the band for the actual chirps.

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
  `DLH427`), the derived **IATA** flight + airline (`LH427 · Lufthansa`), and the
  **tail registration** + country decoded from the ICAO 24-bit address (exact
  N-number algorithm for the US; country from the ICAO address block elsewhere).
- **One dongle:** ADS-B uses the whole RTL-SDR, so starting the radar stops the
  sub-GHz sweep/decoder and vice-versa.
- **Needs `dump1090`** (any fork: dump1090-fa / dump1090-mutability / dump1090).
  The installer/updater install it best-effort; if it's missing the page shows an
  **⬇ Install dump1090** button (POSTs `/api/net/adsb/install`). Everything here
  is receive-only, and ADS-B is unauthenticated/unencrypted by design — the same
  data every flight-tracking site shows.

## Session record & replay

The sub-GHz waterfall toolbar has a **● Rec** button that captures the running
power sweep to a JSONL file under `data/rf_recordings/` (gitignored), and a
**Replay** dropdown to load any past recording back into the waterfall with a
transport bar (play/pause, seek, restart, delete). Frames are small, so a
recording is cheap; capped at a few thousand frames. Routes:
`/api/net/rtl/record/{start,stop,status,list,get,delete}`.

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
| `POST /api/net/adsb/start` · `/stop` | Start / stop dump1090 (takes the dongle from the sub-GHz sweep) |
| `POST /api/net/adsb/install` | One-click install of dump1090 (fixed package set) |
| `…/rtl/record/{start,stop,status,list,get,delete}` | Session record & replay of the power sweep |
| `GET  /api/net/rtl/selftest` | Offline parser / frame-assembly self-test |

## CLI

`rtl_sdr.py` runs standalone for quick checks (no web server needed):

```bash
python3 rtl_sdr.py detect
python3 rtl_sdr.py ism   --band 433 --seconds 20
python3 rtl_sdr.py power --band subghz --seconds 20
python3 rtl_sdr.py selftest
```

## Legality

Listening is passive, but decoding third-party device telemetry (TPMS, meters,
sensors) can be regulated where you live. Use it on your own devices and within
local law.
