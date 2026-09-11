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

## Frequency calibration (PPM)

A cheap RTL-SDR crystal is typically tens of ppm off — tens of kHz at 900 MHz,
enough to mis-name a narrow channel. The tuner bar has a **Calibrate** control
that does the standard *reference-carrier* calibration (what kalibrate-rtl does):

1. Point the sweep at a signal whose true frequency you know (a broadcast pilot,
   a signal generator, any known carrier), click it to drop the marker.
2. Type its true frequency in the **Cal @ ___ MHz** box and hit **Calibrate**.

Ragnar measures where that carrier actually lands, solves for the ppm error
(`ppm_from_reference()`, added to the current ppm and clamped to ±1000), applies
it via the existing tuning path and re-tunes the sweep. The status shows the
measured offset and the ppm before→after. Route `/api/net/rtl/calibrate`
`{true_mhz, near_mhz?}`.

A true GPSDO disciplines the oscillator off a 1PPS input, which an NESDR-class
dongle doesn't have — so GPS on Ragnar is position/time truth, not a crystal
reference. Reference-carrier calibration is the correct method for an RTL-SDR.

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

## Baseline + anomaly detection (Watchtower)

The RTL record bar has a **☙ Baseline** toggle. Arm it and the running sweep
learns a "known-normal" per-bin spectrum (~80 frames), then watches for what
changed and raises alerts:

- **RF_NEW_EMITTER** (high) — energy where the baseline was quiet (a new
  transmitter / rogue device).
- **RF_CARRIER_LOST** (medium) — a baseline carrier that vanished.
- **RF_BROADBAND_JAMMING** (critical) — a large fraction of the span rising at
  once (a jammer / broadband interference).

Regions must persist a few frames before alerting, with a per-region cooldown, so
it doesn't chatter. Alerts are written to `rfwatch.jsonl` in
`$RAGNAR_WATCH_LOG_DIR` (default `/var/log/ragnar`), which **Watchtower**
auto-discovers as the *RF Spectrum Watch (sub-GHz)* source — so they fold into
the one unified alert pane and the Pushover path like every other watcher. This
is spectrum monitoring / interference-hunting the way regulators and SIGINT
teams do it. Backend: `rtl_sdr.SpectrumBaseline` + pure
`detect_spectrum_anomalies()`; routes `/api/net/rtl/baseline/{arm,clear,status}`.

## Persistence + click-to-decode

- **Persist** (toolbar toggle) turns the spectrum trace into a **digital-phosphor
  persistence display**: each sweep is accumulated into a fading offscreen buffer
  (additive, ~9%/frame decay), so continuously-occupied frequencies glow bright
  and rare bursts leave a decaying trail. It's the RTSA-style view that surfaces
  intermittent signals and modulation shape a scrolling waterfall hides. Per
  panel, resets on a band/zoom change.
- **Click-to-decode** — clicking a signal also **classifies** it from the measured
  bandwidth + frequency (narrowband OOK/FSK ISM remote/TPMS/sensor · wideband
  LoRa/mesh chirp, energy-only · POCSAG/FLEX pager · ACARS · VHF airband/VOR · FM
  broadcast) and offers a one-click hand-off to the decoder that can name it: a
  **▶ Decode (band)** button switches the RTL panel to rtl_433 on the nearest ISM
  band, and the pager / ACARS / VOR classes link to their decode pages. LoRa is
  labelled energy-only (chirp spread-spectrum can't be demodulated here).

## Raw-IQ capture (SigMF)

The RTL panel's record bar has an **⤓ SigMF** button that captures raw baseband
IQ to a [SigMF](https://sigmf.org) recording — a `.sigmf-data` file (the RTL's
native `cu8` complex-uint8 samples) plus a `.sigmf-meta` JSON sidecar with the
tune frequency, sample rate, UTC datetime, a sha512 of the data and the band
label. SigMF is the open interoperability standard, so a capture opens directly
in **GNU Radio, inspectrum, Universal Radio Hacker**, or any SigMF-aware tool —
turning Ragnar into a real capture instrument rather than a closed viewer.

- Centres on the marker (if one is dropped) else the span centre, at a
  single-tune sample rate (≤ 2.4 MS/s); length is the seconds box (capped at
  `rtl_sdr._IQ_CAP_MAX_SECONDS`, 30 s).
- One dongle: capturing pauses the live sweep and every other RTL consumer, then
  the sweep resumes automatically when the capture finishes. `status()` reports
  the capture as `streaming` so the 15 s status poll never re-probes the device
  mid-capture (the same contention guard the sweep uses).
- Files live under `data/iq_captures/` (gitignored); the finished capture offers
  `.sigmf-data` + `.sigmf-meta` download links. Backend: `rtl_sdr.iq_capture_*`
  + `sigmf_meta()`; routes `/api/net/rtl/iq/{start,status,stop,list,delete,file}`.

## Signal Analyzer (on-box SigMF analysis)

A finished SigMF capture shows an **📈 Open in Analyzer** link that opens
**`/rf-analyzer`** (`demos/rf_analyzer.html`) — a dedicated page that analyses the
recording *on the device* so it works from a phone, no desktop DSP tools needed.
All the maths runs in numpy/scipy in `sigmf_analyzer.py`; the page is a viewer
that requests windows:

- **Summary** — center/rate/duration, measured noise floor, peak frequency, SNR,
  occupied bandwidth, burst count.
- **Zoomable spectrogram** — a time × frequency image for any window; drag a box
  to zoom, click to drop a marker. Rendered client-side with the waterfall
  palettes (the backend returns a compact base64 dB grid).
- **Spectrum + time-envelope** panels for the shown window.
- **Burst / packet list** — automatic on/off detection (start/end/BW/level);
  click a row to zoom to it and pre-fill the demodulator.
- **Demodulate** — shift to the marked signal, low-pass to a chosen bandwidth,
  and demodulate **OOK/AM** (envelope) or **FSK/FM** (instantaneous frequency),
  estimate the symbol rate and **recover a bitstream**.

Routes (read-only over `data/iq_captures/`, so no dongle needed):
`/api/net/rtl/analyze/{list,summary,spectrogram,psd,envelope,bursts,demod}` and
the page at `/rf-analyzer` (optionally `?name=<capture>`). For heavier work the
raw `.sigmf-data` still opens in GNU Radio / inspectrum / URH. `scipy` is used
for decimation/filtering in the demodulator.

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
- **Phone-friendly.** Segmented controls (scroll/palette/band/view) wrap instead
  of clipping, the readout tiles reflow to a 3-across grid, control groups
  (tuner/hold/mesh) wrap, tap targets grow, and the waterfall canvas gets taller
  (`min(46vh,340px)`) — all under a `≤640px` media query, so the desktop layout
  is unchanged. No horizontal scroll at 360px.
- Receive-only. The sweeps measure on-air energy; nothing is transmitted.
