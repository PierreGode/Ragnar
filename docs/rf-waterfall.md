# RF Waterfall page

A dedicated full-screen page that stacks two true-RF **waterfalls** — an RTL-SDR
sub-GHz/broadcast panel (24 MHz–1.7 GHz) over a HackRF panel (1 MHz–6 GHz) —
each scrolling a power-over-frequency heatmap, with band-scope presets and a
free-frequency manual tune.

- Page: `demos/rf_waterfall.html`
- Route: `GET /rf-waterfall` (alias `GET /demo/rf-waterfall`), login required
- Backends: `sdr_spectrum.py` (HackRF, `hackrf_sweep`) and `rtl_sdr.py`
  (RTL-SDR, `rtl_power`), exposed at `/api/net/sdr/*` and `/api/net/rtl/*`.

## Live vs synthetic — per panel, automatic

Each panel decides its own state every few seconds:

- **LIVE** — its radio is detected: the page starts a sweep and streams real
  frames (`/api/net/{sdr,rtl}/power? frames`). Plug a radio in and the panel
  flips to live on its own; unplug it and it drops back.
- **SYNTHETIC** — no radio, but the **RF Waterfall demo** toggle is on: the panel
  models that band's real occupants (433.92 MHz TPMS/remote bursts, 868 MHz
  metering, 915 MHz hoppers, Wi-Fi OFDM on ch 1/6/11) so the display stays alive.
- **IDLE** — no radio and demo off: the panel shows a "connect a device" note.

## Band presets + manual tune

Each panel has a row of **band-scope presets** and a **Manual tune** box:

- **Presets** retune the real sweep when live and swap the synthetic model
  otherwise. Both radios carry the same broadcast/ISM scopes —
  `AM · SW · FM · Air · 27 · 40 · 315 · 433 · 868 · 915` — and the HackRF panel
  adds the Wi-Fi bands `2.4G · 5G · 6G` (it reaches 1 MHz–6 GHz, so it can sweep
  everything the RTL-SDR can). The band tables live in `rtl_sdr.RTL_BANDS` and
  `sdr_spectrum.BANDS`; keep them and the page's `SUBGHZ_BANDS`/`BAND_MHZ` in sync.
- **Manual tune** (the `Tune ___ MHz ± ___ Go` box) sweeps an arbitrary window
  centred on any frequency the dongle can reach, reusing the zoom path
  (`lo_hz`/`hi_hz`). Hardware reach is clamped per panel:
  - **RTL-SDR:** 24–1766 MHz (the `rtl_power` tuner range). It can't sweep below
    ~24 MHz — HF broadcast (AM/SW) only *listens* via the Local Radio bar
    (`rtl_fm -E direct` direct sampling), it doesn't waterfall.
  - **HackRF:** 1–6000 MHz. AM's low edge is clamped to HackRF's 1 MHz floor;
    narrow scopes (AM/27/40) are widened to a ≥2 MHz sweep window internally so
    `hackrf_sweep` is happy, while the display still bins to the requested span.
- **📡 Mesh / LoRa overlay** (the dropdown, on *both* panels) sweeps a chosen
  mesh/LPWAN band and overlays its exact channel centres — Z-Wave (FSK) regions
  plus the LoRa meshes Meshtastic / MeshCore / LoRaWAN. It's an
  **energy/occupancy view only** (LoRa CSS can't be demodulated by
  `rtl_power`/`hackrf_sweep`, and the payloads are encrypted): you see bursts
  land on the channels, not IDs or messages. Options come from
  `rtl_sdr.zwave_plan()` / `lora_plan()` via `/api/net/rtl/{zwave,lora}`. Some
  overlay spans are narrow (e.g. Meshtastic-EU868 is 0.45 MHz), so the HackRF
  custom-span gate accepts ≥0.1 MHz and `_run_loop` widens the actual sweep.

## The button and the toggle (WiFi Spectrum Analyzer)

- **"RF Waterfall page" button** — appears in the analyzer's controls once a
  HackRF *and/or* RTL-SDR is detected (or while the demo toggle is on), and
  opens the page in a new tab.
- **"🌊 RF Waterfall demo" toggle** — a config switch (`sdr_demo`). On: the page
  is always reachable and fills empty panels with the synthetic feed; each panel
  still flips to live automatically when its radio is connected. Off: the page is
  served only when a radio is present (otherwise `/rf-waterfall` 404s).

Env `RAGNAR_SDR_DEMO=1` forces the demo on without touching config.

## Notes

- The page uses Google Fonts with system fallbacks, so it still renders on an
  offline field unit.
- Honours `prefers-reduced-motion`: starts paused with a Play control.
- Receive-only. The sweeps measure on-air energy; nothing is transmitted.
