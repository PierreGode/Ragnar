# RF Waterfall page

A dedicated full-screen page that stacks two true-RF **waterfalls** — an RTL-SDR
sub-GHz/broadcast panel (24 MHz–1.7 GHz) over a HackRF panel (1 MHz–6 GHz) —
each scrolling a power-over-frequency heatmap, with band-scope presets and a
free-frequency manual tune.

- Page: `demos/rf_waterfall.html`
- Route: `GET /rf-waterfall` (alias `GET /demo/rf-waterfall`), login required
- Backends: `sdr_spectrum.py` (HackRF, `hackrf_sweep`) and `rtl_sdr.py`
  (RTL-SDR, real-time `rtl_sdr` IQ FFT with an `rtl_power` fallback), exposed at
  `/api/net/sdr/*` and `/api/net/rtl/*`.

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
    any window narrower than `_MIN_SWEEP_MHZ` (~2 MHz) is widened symmetrically
    by `_widen_span()` — `hackrf_sweep`'s FFT floor is ~2.5 kHz/bin, so a
    sub-~1.3 MHz span can't feed all 512 display columns and would paint floor
    streaks. The widen applies to **both** the sweep and the display, and the
    frame's `band_mhz` reports the widened `[lo, hi]` so the page's ruler
    matches what's drawn. The panel's zoom/manual-tune floor (`minSpan:2`) is
    aligned to this, so HackRF's effective resolution floor is uniform.
- **📡 Mesh / LoRa overlay** (the dropdown, on *both* panels) sweeps a chosen
  mesh/LPWAN band and overlays its exact channel centres — Z-Wave (FSK) regions
  plus the LoRa meshes Meshtastic / MeshCore / LoRaWAN. It's an
  **energy/occupancy view only** (LoRa CSS can't be demodulated by
  `rtl_power`/`hackrf_sweep`, and the payloads are encrypted): you see bursts
  land on the channels, not IDs or messages. Options come from
  `rtl_sdr.zwave_plan()` / `lora_plan()` via `/api/net/rtl/{zwave,lora}`. Some
  overlay spans are narrow (e.g. Meshtastic-EU868 is 0.45 MHz), so the HackRF
  custom-span gate accepts ≥0.1 MHz and `_widen_span()` grows it to the ~2 MHz
  resolution floor (see Manual tune above) before the sweep.

## Sub-GHz engine: real-time IQ FFT vs `rtl_power` sweep

The RTL-SDR panel picks its capture engine automatically per span — the page and
the frames look identical either way; only the speed differs. The active engine
is named under the panel title (`RTL-SDR · IQ FFT · real-time` vs
`RTL-SDR · rtl_power sweep`), and **Rows/s** shows the *measured* frame rate, not
the scroll-speed setting.

- **IQ FFT (real-time)** — for any span that fits a **single RTL-SDR tune**
  (≤ `rtl_sdr._IQ_MAX_SPAN_HZ`, ~2.8 MHz: zooms, manual tunes, Z-Wave regions,
  most mesh/LoRa overlays), Ragnar streams raw IQ from `rtl_sdr` and FFTs it
  continuously with numpy — the way SDR++/GQRX draw a waterfall. No retuning, so
  rows scroll smoothly at `_IQ_DISPLAY_HZ` (~16/s) with sub-100 ms latency. The
  colour floor self-calibrates to the measured noise level (`floor_dbm` tracks a
  smoothed low-percentile), since the IQ power scale is relative dBFS, not
  absolute dBm.
- **`rtl_power` sweep** — the fallback for **wide bands** that can't fit one tune
  (the full `868`/`915`/`subghz` scans need the dongle to retune across the
  range) and for any host missing `rtl_sdr` or numpy. `rtl_power` integrates
  `-i 1 s` per sweep, so it advances at best ~1 row/s — fine for a broad "what's
  out there" scan, slow for a narrow zoom (which is exactly why the IQ engine
  exists).

Both engines emit the same frame shape, feed the same ring buffer, recorder and
`/api/net/rtl/power/frames`, so nothing else on the page changes.

## Measurement layer

The waterfall is also an instrument, not just a display. Every panel measures the
live spectrum client-side from the incoming frames:

- **Readout tiles** — Peak f, Peak level, **SNR** and **Noise** (a robust
  low-percentile noise-floor estimate), plus Busy% (fraction of the span above
  noise) and Span.
- **Click to measure** — click any signal and the marker snaps to the nearest
  peak and reports centre frequency, level, **SNR**, **−20 dB bandwidth**, **99%
  occupied bandwidth** and relative **channel power**. (Values are relative dB —
  the RTL front end isn't absolute-calibrated — so treat them as consistent, not
  survey-grade.)
- **Trace math (Hold)** — the spectrum trace overlays user-toggled **Avg**
  (digs weak carriers out of the noise), **Max-hold** (catches intermittent
  bursts, on by default) and **Min-hold** (reveals the true noise floor), with a
  dashed line marking the measured noise floor.
- **Signal list (CFAR)** — the panel lists every emitter above `noise + 8 dB`
  with centre frequency, bandwidth, SNR and a **duty-cycle** estimate (so a
  bursty remote reads ~5% and a continuous carrier ~100%). This is the "what's
  actually on the band" answer.

## Colour palettes

The top toolbar has a **Palette** selector for the waterfall colour map. Five are
built in — **Aurora** (default: cool navy→teal→lavender), **Inferno** (hot
black→red→orange), **Viridis** (perceptually-uniform, colour-blind friendly),
**Classic** (the traditional SDR#/GQRX blue→green→red rainbow) and **Mono**
(grayscale). The choice is remembered per-browser (`localStorage`
`ragnar_rf_palette`) and the legend gradient tracks it. Switching recolours new
rows going forward and applies to both panels; rows already painted keep their
colours until they scroll off (the page paints incrementally and keeps no
per-row dB history). Add one by dropping an entry into `PALETTES` +
`PALETTE_ORDER` in the page — the selector builds itself from that list.

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
