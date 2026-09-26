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

**On this page.** Reading the display:
[engine](#sub-ghz-engine-real-time-iq-fft-vs-rtl_power-sweep) ·
[resolution & hardware](#resolution-and-hardware-settings) ·
[display range](#display-range) ·
[hover, time axis & history](#hover-readout-time-axis-and-history) ·
[zoom & pan](#zoom-and-pan).
Measuring: [measurement layer](#measurement-layer) ·
[markers](#markers) ·
[zero-span & keys](#zero-span-and-keyboard-shortcuts) ·
[band plan & signal ID](#band-plan-and-signal-identification) ·
[dBm calibration](#level-calibration-dbm) ·
[PPM calibration](#frequency-calibration-ppm) ·
[noise print](#noise-print-background-subtraction).
Monitoring: [limit lines](#limit-lines-and-masks-pass--fail) ·
[baseline alerts](#baseline--anomaly-detection-watchtower) ·
[unattended survey](#unattended-survey) ·
[mesh direction finding](#mesh-direction-finding-where-is-it-transmitting-from).
Capture & audio: [Local Radio](#local-radio) ·
[raw IQ / SigMF](#raw-iq-capture-sigmf) ·
[Signal Analyzer](#signal-analyzer-on-box-sigmf-analysis) ·
[CSV export](#csv-export).
The bar this is all measured against: the
[professional feature checklist](#professional-feature-checklist).

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
- **📡 Mesh / LoRa / HaLow overlay** (the dropdown, on *both* panels) sweeps a chosen
  mesh/LPWAN band and overlays its exact channel centres — Z-Wave (FSK) regions,
  the LoRa meshes Meshtastic / MeshCore / LoRaWAN, and **Wi-Fi HaLow (802.11ah)**
  for the US, EU, AU/NZ, Japan, Korea, China, India and Singapore (see
  [sdr-subghz.md](sdr-subghz.md#mesh-overlays-z-wave--meshtastic--meshcore--lorawan--wi-fi-halow)). It's an
  **energy/occupancy view only** (LoRa CSS and HaLow OFDM can't be demodulated by
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

**Steady flow.** Live rows are never painted as they arrive. They go into a small
buffer (~0.8 s), and the page releases them at **one steady rate**: the SDR's
measured data rate, worked out from the frames' own timestamps rather than from
the jittery poll timing. The buffer is kept full by nudging the pace **at most
±12%**, which is imperceptible, so network or backend jitter never shows up as
a change of speed. After an interruption the buffer grows (up to 2 s) so a
repeat is absorbed. A backlog that is seconds old (the tab was in the
background, or the backend stalled for a long time) is skipped, not fast-forwarded.

- **IQ FFT (real-time)** — for any span that fits a **single RTL-SDR tune**
  (≤ `rtl_sdr._IQ_MAX_SPAN_HZ`, ~2.8 MHz: zooms, manual tunes, Z-Wave regions,
  most mesh/LoRa overlays), Ragnar streams raw IQ from `rtl_sdr` and FFTs it
  continuously with numpy — the way SDR++/GQRX draw a waterfall. No retuning, so
  rows scroll smoothly at `_IQ_DISPLAY_HZ` (~16/s), under a second behind real time. The
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

## What ships by default, and why


These are the settings a fresh install starts with. They were chosen by
measurement on real hardware, not by taste, and each one is a click away from
being something else. **Your changes are saved** (`data/rf_settings.json`) and
survive a restart; a fresh install has no such file and gets the defaults below.

| Setting | Default | Why |
| --- | --- | --- |
| **Gain** | **Managed**, starting at 25.4 dB | The dongle's own AGC is *not* the default: on an R820T it routinely drives the 8-bit ADC into clipping near any strong signal, and a clipped capture invents harmonics and intermodulation that look like transmitters. Measured on a real dongle: 9–22% of samples pinned to the rail on AGC, none at all at 12–28 dB. |
| **Detector** | **RMS** | Measured cost against peak on live signals: **0.54 dB** of visible SNR, because auto FFT sizing already keeps ~2 bins per display column, and the wide sweep asks `rtl_power` for exactly one bin per column (where the detector does nothing at all). In exchange every level, channel power and noise figure is a true power measurement instead of one biased high. |
| **FFT size** | Auto | Keeps ≥2 bins per display column at any zoom, so a narrow zoom sharpens the resolution instead of leaving dead columns. |
| **Averaging** | 24 windows | Uses most of each row's samples for the estimate. It averages *within* a row, so it does not blur bursts across time. |
| **Window** | Hann | The general-purpose compromise between resolution and leakage. |
| **Columns** | 480 | Matches a typical display width without wasting CPU. |
| **Display range** | Auto | Follows the measured noise floor, so the picture is usable before anything is configured. |

### Managed gain

An RTL-SDR has one knob that decides whether you can hear anything and whether
what you hear is real. Too little and the ADC's own noise sets the floor; too
much and it clips. Both extremes are silent about it.

The managed loop uses the same measurement the **Front end** tile shows — the
fraction of samples on a rail, and the headroom of the loudest sample — and
holds the gain so the headroom stays between **10 and 25 dB**, within
**7.7–38.6 dB** of tuner gain. It moves one tuner notch at a time, at most once
every 12 seconds, and only when the headroom is outside that band, so it settles
instead of hunting — each change restarts the capture, and restarting captures
in a tight loop is what wedges an RTL-SDR.

Why it starts at 25.4 dB: measuring the noise floor against gain on a real
dongle, the floor rises *slower* than the gain up to about 24 dB (the ADC is
still setting the floor, so more gain genuinely buys sensitivity) and 1 dB per
dB above it (the front end sets the floor, so more gain buys nothing and costs
headroom). 25.4 dB is the first supported tuner notch past that knee. On this
antenna it settles at 16–18 dB of headroom and the loop makes no changes at all.

**↺ Restore defaults** (⚙ Settings → Hardware, or
`POST /api/net/rtl/tuning/reset`) puts PPM, gain, detector, resolution and the
hardware options back to the values above — useful when a box has been
experimented on and you want to know what it is measuring with again.

The gain control in **⚙ Settings → Hardware** offers all three: **Managed**,
**Manual** (you set the dB, nothing touches it) and **Hardware AGC** (the
dongle's own, labelled as able to clip). The panel shows the managed gain and
the reason for its last change.

## Resolution and hardware settings


**Resolution.** The **RBW** tile in the readout shows the current resolution
bandwidth (the width of one FFT bin).
- *RTL-SDR:* **FFT size** (Auto, or 256–32768), **Averaging** (1–64 FFT
  windows per row: smoother vs. quicker to react), **Window** (Hann;
  Blackman-Harris to separate a weak signal next to a strong one; Flat-top for
  the most accurate levels; Rectangular) and **Columns** (240–1920). *Auto* FFT
  keeps at least two FFT bins per display column at any zoom, so zooming in
  also sharpens the resolution (1 MHz ≈ 560 Hz, 250 kHz ≈ 244 Hz, 120 kHz ≈
  122 Hz RBW). These settings apply to the whole dongle, the slower
  `rtl_power` sweep included (which now uses a proper window, not its
  rectangle default).
- *HackRF:* **RBW** (hackrf_sweep bin width: Auto, or 2.5 kHz–1 MHz).

**Detector.** An FFT produces far more bins than the display has columns, so
several bins have to be combined into each column — and the rule used decides
every level on the page. The **Det** tile shows the active rule and
**⚙ Settings → Resolution → Detector** changes it:

| Detector | Combines a column's bins by | Use it for |
| --- | --- | --- |
| **Peak** (default) | the largest bin | *finding* signals — catches anything narrower than a column, but reads a noise floor several dB high |
| **RMS** | averaging in the power domain | *measuring* — the right detector for a level, channel power or noise figure |
| **Average** | averaging in dB (video average) | a steady trace; reads noise ~2.5 dB below RMS, so never quote it as power |
| **Sample** | the bin at the column centre | seeing the trace exactly as the FFT produced it |
| **Min** | the smallest bin | digging the true floor out from under bursty traffic |

Peak finds, RMS measures. Quote a noise floor or a channel power from a
peak-detected trace and it will be optimistic; the ordering
`peak ≥ rms ≥ avg ≥ min` always holds on noise. The setting applies to the
dongle (both engines) and to the browser's own bin→pixel reduction, so zooming
out cannot silently change what a level means.

**Hardware.**
- *RTL-SDR:* PPM / Gain / Calibrate (moved here from the toolbar), plus:
  - **Bias-T**: 4.5 V on the antenna port to power an LNA or active antenna.
    RTL-SDR Blog V3/V4 or bias-tee dongles only, and it asks before switching
    on. The raw-IQ engine switches it with `rtl_biast`; the others with `-T`.
  - **Direct sampling**: *Auto* (on for HF below 28.8 MHz), *On* or *Off*.
    Receives HF without an upconverter on dongles that support it.
  - **Converter**: an up/down-converter's LO (Ham It Up +125 MHz, SpyVerter
    +120 MHz, Ku-band LNB 9750 / 10600 MHz, or custom). The waterfall, ruler,
    markers, Tune box, radio, rtl_433 and SigMF recordings all use the **real RF
    frequency**; the dongle is tuned to RF + LO.
- *HackRF:* **LNA** (0–40 dB, 8 dB steps) and **VGA** (0–62 dB, 2 dB steps)
  gain, the **RF amp** (+~11 dB for weak signals), and **antenna power**
  (3.3 V for active antennas, asks first). Remembered per browser and applied
  on the next sweep start.

Zooming in sharpens the resolution rather than thinning the data: the FFT keeps
at least two bins per display column at any span, and columns between bins are
interpolated, so a narrow zoom stays a filled picture. A retune that finds the
dongle still busy is retried before falling back to the slower sweep.

## Display range


**⚙ Settings → Display range** sets the colour scale. **Auto** (the default)
keeps the old behaviour: the bottom follows the measured noise floor and the top
is fixed at −20 dB. Drag **Ref level** (top of the scale) or **Range** (dB from
top to bottom), or press **Fit to signal**, which sets the top just above the
strongest signal on screen and the bottom just under the noise floor. The
setting is remembered per panel.

The page keeps a history of every row it has shown (about 10 MB per panel), so a
range or palette change **recolours the whole waterfall at once**, not just new
rows. The same history is redrawn when the window is resized or goes full screen,
instead of starting blank.

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

## 2D / 3D waterfall view

**The 3D view is rotatable** — drag to turn and tilt it, wheel or pinch to zoom; the angle is remembered per browser. Power is height, older sweeps recede along the time axis.


Each panel has a **View: 2D | 3D** toggle in the toolbar (default **2D**, the
classic flat scrolling waterfall). **3D** renders the same sweeps as a receding
**terrain surface** — signal power becomes height, older sweeps shrink and set
back toward the horizon, so a steady carrier stands up as a ridge running back
through time and bursts appear as hills. It uses the active colour palette
(power → colour and height), with far rows dimmed for depth.

It's drawn with the **plain 2D canvas** (a small ring buffer of recent rows,
projected back-to-front with the painter's algorithm) — **no WebGL/GPU**, so it
works offline on the Pi's own browser and on phones, and falls back to nothing
worse than the 2D view. Per panel, redraw is throttled (~16 fps); the PNG export
captures whichever view is showing.

## Hover readout, time axis and history


- **Hover** over the waterfall to read the frequency, the exact stored level of
  that cell, and when it was received (`433.92 MHz · −29 dB · −1.9 s ·
  07:57:57`). With a noise print active the raw level is shown too. Over the
  spectrum trace it shows the live level plus any Max/Avg hold at that
  frequency. A thin crosshair marks the cursor frequency. (Mouse and pen; on a
  phone, tap to measure as before.)
- **Time axis:** clock times down the left edge of the 2D waterfall, spaced to
  suit the scroll speed (every 1 s … 1 h).
- **Colour bar:** the right edge of each waterfall shows the dB range its
  colours map to. The top-bar legend is just a weak → strong colour key, since
  each panel has its own range.
- **History:** drag the **History** slider, or **Shift + mouse wheel** on the
  waterfall, to scroll back through past rows. While you're looking back the
  view holds still and new rows keep being recorded. **▲ Live** jumps back to
  the live edge. Roughly the last 10 MB of rows is kept per panel (about 3–5
  minutes of the real-time engine).

## Zoom and pan


- **Mouse wheel** over the waterfall or trace zooms in and out around the
  cursor. **Drag** left/right pans; **double-click** returns to the full band.
  On a phone, **pinch** zooms and a one-finger sideways drag pans (an up/down
  swipe still scrolls the page). *Zoom here* / *Reset zoom* still work.
- The view changes **instantly**, and most of the time the radio doesn't move
  at all. Each panel captures a little wider than it shows, so zooming in,
  zooming back out and small pans are served from data already in hand. The
  radio is only retuned when the window leaves what it is sweeping, or when you
  have zoomed in far enough that a narrower capture buys real resolution — and
  then at most once every 1.2 s, after the gesture settles.
- Retuning means closing and reopening the USB device, so it is deliberately
  rationed: a burst of wheel notches costs zero retunes, and the backend runs
  one capture at a time, closing each cleanly and letting the device settle
  before the next one opens it.
- Zoom stays within the selected band (use *Tune* to go elsewhere), down to the
  panel's minimum span.
- The frequency ruler uses round 1-2-5 steps with as many decimals as the zoom
  needs, and fewer labels on a narrow screen. The Span readout is precise too
  (e.g. `433.790–434.050`).

## Measurement layer


The waterfall is also an instrument, not just a display. Every panel measures the
live spectrum client-side from the incoming frames:

- **Readout tiles** — Peak f, Peak level, **SNR** and **Noise** (a robust
  low-percentile noise-floor estimate), plus Busy% (fraction of the span above
  noise) and Span.
- **Click to measure** — click any signal and the marker snaps to the nearest
  peak and reports centre frequency, level, **SNR**, **bandwidth** (at the
  deepest drop the SNR supports, and it says which: `BW−20`, or e.g. `BW−5` for
  a weak signal), **99% occupied bandwidth** and **channel power**. Levels are
  relative dB unless you've done a [dBm calibration](#level-calibration-dbm) —
  consistent either way, but a one-point calibration, not survey-grade.
- **Trace math (Hold)** — the spectrum trace overlays user-toggled **Avg**
  (digs weak carriers out of the noise), **Max-hold** (catches intermittent
  bursts, on by default) and **Min-hold** (reveals the true noise floor), with a
  dashed line marking the measured noise floor.
- **Signal list (CFAR)** — the panel lists every emitter above `noise + 8 dB`
  with centre frequency, bandwidth, SNR and a **duty-cycle** estimate (so a
  bursty remote reads ~5% and a continuous carrier ~100%). This is the "what's
  actually on the band" answer.

## When the dongle stops responding


An RTL2832U can end up in a state where it still enumerates, still opens and
still passes `rtl_test` — but never delivers a single sample. The panel then
sits there: engine running, no rows. Repeated open/close cycles are what put it
there, which is why captures are serialised and the USB device is given time to
settle between them.

The panel now detects it — running, but nothing arriving for several seconds —
and offers **⭮ Reset dongle**, which is also in **⚙ Settings → Hardware**. It
re-enumerates the device over USB (`USBDEVFS_RESET`), exactly what the kernel
does when you unplug and replug it: whatever is using the radio is stopped
first, the device is reset, and the sweep you were running is restarted. No walk
to the box, no `sudo`, no power cycle.

It needs root (the web UI normally runs as root); if it cannot, it says so
rather than pretending to have fixed anything.
API: `POST /api/net/rtl/reset`.

## Front-end health and proving a signal is real


Two things routinely put transmitters on a screen that are not on the air. Both
are reported rather than quietly drawn.

**Overload.** The **Front end** tile appears when the receiver is being driven
too hard: the RTL-SDR's 8-bit ADC starts clipping, and clipping manufactures
harmonics and intermodulation products that look exactly like signals. The panel
measures this from the samples themselves — the fraction sitting on a rail, and
how much headroom the loudest sample leaves — and shows `near clip` (under 3 dB
of headroom) or a flashing `OVERLOAD` with a red outline on the waterfall. When
it appears, **lower the gain**: every level in an overloaded capture is wrong,
and some of the signals are not there at all. The `rtl_power` sweep engine never
sees raw samples, so it reports no figure.

**Images and the DC spike.** A mixer also delivers signals from the wrong side
of the local oscillator, and the dongle has a permanent spike at whatever it is
tuned to. Both measure like transmitters. The **✓ Verify** button next to a
measurement settles it on the hardware: the frequency is measured through two
tuner centres 500 kHz apart, and

- a **real signal** keeps its radio frequency in both,
- an **image / alias** moves with the tuner,
- the **DC spike** sits at the centre of both windows,
- **nothing heard** is reported as such, not as a pass.

It takes a few seconds and needs the dongle, so it refuses while the dongle is
busy with a decode or a survey, and restores the sweep you were running
afterwards. API: `POST /api/net/rtl/image-check {freq_hz, bw_hz}`.

## Measurement set (band power, noise, ACPR, spurs, harmonics)


Buttons in the **Markers** strip. Each one answers a question the raw trace
cannot.

- **Σ Band power** — total power between the two outermost markers, plus the
  same figure per Hz. The per-Hz density is what makes two measurements taken at
  different spans or RBWs comparable. It names the detector in use, and says so
  when that detector is peak (which reads high).
- **N Noise** — the level at the marker normalised to a 1 Hz bandwidth. The raw
  reading is corrected for the resolution bandwidth, for the FFT window's
  noise-equivalent bandwidth (Hann 1.5×, Blackman-Harris 2.0×, Flat-top 3.77×,
  rectangular 1.0×) and for the +2.51 dB bias of a log-averaged trace, and it is
  averaged over a window of bins rather than read off one. Those corrections are
  worth several dB, which is the difference between a noise figure and a guess.
- **ACPR** — power in the channels either side of the marked carrier, relative
  to the carrier's own channel. The channel width comes from the signal's
  measured 99% occupied bandwidth, so it works without knowing the standard.
  It refuses, rather than guesses, when the neighbouring channels are not in
  view.
- **Spurs** — every other peak in view as an offset and a level in **dBc**
  relative to the marked carrier. A peak counts when it rises 6 dB out of the
  dip beside it and sits 10 dB over the noise, so ripple is not reported as a
  spurious emission. Use **✓ Verify** on anything surprising: a receiver image
  is not a transmitter's spur.
- **Harmonics** (RTL panel) — measures 2×, 3× and 4× the marked frequency on the
  hardware, one tune at a time, and reports each in dBc against the fundamental
  measured the same way. Harmonics past the tuner's range are reported as out of
  reach, not as absent. It takes roughly 7 s per harmonic and interrupts the
  sweep, then puts it back. A strong "harmonic" can also be made inside an
  overloaded receiver, so check the **Front end** tile and repeat with less
  gain. API: `POST /api/net/rtl/harmonics {freq_hz, bw_hz, n}`.

**Reference trace (⎖ Store ref).** Stores the live trace and switches the plot
to **live − reference**, drawn against its own zero line with an auto-ranged
±dB scale. This is how you show what changed since yesterday, or measure a
filter, an attenuator or an antenna against a known-good baseline. The
reference belongs to the span it was taken on and retires itself when the view
moves off it.

A **spectral emission mask** is the existing
[limit line / mask](#limit-lines-and-masks-pass--fail): learn it from Max-hold,
or set it flat, and the trace fills red where the signal exceeds it.

## Markers


The **Markers** strip under the toolbar handles up to four markers, **M1–M4**
(amber, cyan, green, rose):

- **Click** the waterfall or trace to move the *active* marker (it snaps to
  the nearby peak and shows the full measurement: level, SNR, −3/−20 dB and 99%
  bandwidth, channel power). **Shift + click**, or **＋ Marker**, adds another.
- The **table** shows each marker's frequency and live level. M2–M4 also show
  their **Δ frequency and Δ level against M1** (the reference). Click a row to
  make it active; ↔ centres on it, ✕ removes it.
- **Peak** moves the active marker to the strongest signal on screen.
  **◀ Next / Next ▶** step to the next peak left/right using an analyser-style
  *6 dB peak excursion*: a peak only counts if it rises 6 dB above the dip
  before it and 6 dB over the noise floor, so a signal's own sidelobes are
  skipped.
- **↔ Centre** re-centres the view on the active marker (at full band span it
  zooms 4× onto it instead). **Clear** removes all markers.

## Zero-span and keyboard shortcuts


**Zero-span** (Markers strip, or key **Z**) adds a strip chart under the trace
showing the level at the **active marker's frequency over time**, with now /
min / max, the noise floor and any limit line. It auto-scales to what it shows.
Use it to see a transmitter key on and off, its duty cycle, or fading. It's
built from the row history, so it resolves at the row rate (~16 per second
on the real-time engine). For sample-rate detail take a raw IQ capture into
the Signal Analyzer.

**Keyboard shortcuts** act on the panel your mouse was last over (**?** or
the ⌨ Keys button shows them). They're ignored while you're typing in a box:

| Key | Action | Key | Action |
|---|---|---|---|
| Space | Pause / resume | P | Peak search |
| [ / ] | Next peak left / right | M | Add a marker |
| C | Marker → centre | X | Clear markers |
| Z | Zero-span | + / − | Zoom in / out around the marker |
| ← / → | Pan | 0 | Full band |
| L | Back to live (history) | 3 | 2D / 3D |
| A | Fit display range | F | Full screen |
| S | Settings | ? / Esc | Help / close |

**Measurement accuracy.** A click measures bandwidth and 99% occupied
bandwidth on the smoothed *Avg* trace; the level comes from the live row. A
"−20 dB bandwidth" only exists when a signal is more than 20 dB over the
noise. Weaker signals are measured at the deepest drop their SNR allows, and
the readout says which (e.g. `BW−5 4 kHz`). The width also stops at the valley
between a signal and its neighbour, so a cluttered floor doesn't inflate it.

## Band plan and signal identification


**Band plan.** A strip under the frequency ruler shows the allocations in view
(broadcast, amateur, ISM/SRD, cellular, aviation, marine, satellite, …).
Overlapping allocations get separate lanes, and hovering one shows its full
range and use. The hover readout also names the most specific allocation
under the cursor. **⚙ Settings → Display range → Band plan** turns the strip
on or off and picks the **ITU region** (1 Europe/Africa, 2 Americas,
3 Asia-Pacific), since some bands differ (80/40/2 m, MW, 915 ISM, TV,
paging). The table covers ~0.15 MHz to 7 GHz. It shows common use, not a
legal reference.

**Signal-ID hints.** A click-measurement names the likely emitter from its
frequency and measured bandwidth: e.g. ADS-B 1090, ATC AM voice, marine VHF
/ channel 16, AIS, APRS (144.800 EU / 144.390 US), 2 m / 70 cm FM, PMR446,
FRS/GMRS, TETRA, NOAA / Meteor satellites, DAB multiplex, DVB-T, GSM / LTE
carriers, DECT, Wi-Fi vs. Bluetooth, analogue FPV, CB, HF SSB and CW, ISM
remotes / sensors and LoRa. Hints with a decoder or radio link offer it.
Anything else falls back to "narrowband / wideband signal — in *allocation*".
Every measurement also links to the **🔎 Signal ID wiki** (sigidwiki.com)
for that frequency (needs internet).

Paging hints are restricted to the real paging allocations for the selected
region, so marine channel 16, AIS, APRS and 2 m voice are identified as
themselves.

## Level calibration (dBm)


**Level calibration.** Out of the box the levels are relative (dB / dBFS: the
real-time engine measures against the ADC's full scale). To read **dBm**, put
a marker on a signal whose true level you know (a signal generator, a
calibrated source), type that level under **⚙ Settings → Level calibration →
Known level** and press **Calibrate to marker**. You can also type an offset
directly. Everything switches to dBm at once: the waterfall and colour bar,
trace, readouts, markers, hover, Signals list and exports. The past rows
already on screen are shifted too, so nothing mixes units. The offset is
per panel and remembered. **Reset** returns to relative dB. Re-calibrate
after changing the gain or the antenna. SNR and Δ values are differences, so
they stay in dB.

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

## Noise print (background subtraction)


Some lines are always there: Pi/USB/PSU "birdies", the RTL-SDR DC spike at the
centre frequency in IQ mode, a neighbour's always-on carrier. They hide the short
bursts you actually want to see. The **Noise print** group in each panel's
toolbar removes them from the picture:

1. Pick a length (**3 / 5 / 10 / 30 s**) and press **● Record** while the band is
   quiet. Press **■ Stop** to end early.
2. When it finishes, the print is applied automatically. **Filter** turns it
   on and off, and the slider sets the **strength** (0% = raw, 100% = constant
   lines fully flattened).

**How it works:** the print is the per-frequency **median** of the recorded
rows, so a burst that is on for only part of the recording isn't learned as
noise. Only the print's excess above its own noise floor is subtracted. Ordinary
noise is untouched, constant lines drop to the floor, and a known line that
suddenly gets *louder* still shows by how much louder it got. The filter applies
to the 2D and 3D views, the spectrum trace, the peak/SNR/Busy readouts and the
Signals list. **Click-to-measure keeps reporting true levels**, and the backend,
recordings and IQ captures never see filtered data.

A print is valid only for the exact span it was recorded on. It is saved in the
browser per panel and per span, comes back when you return to that band or zoom,
and simply doesn't apply elsewhere. The status line shows the print's length and
age ("5 s print · 12 min ago"). Re-record after changing gain or if the dongle's
temperature has drifted.

**Limits:** it can't separate a signal sitting exactly on a constant line (only
"stronger than usual" shows), and a print recorded while something was
transmitting the whole time learns that transmitter as noise.

This is separate from **Baseline** below, which *alerts* on new or vanished
carriers but never changes what's drawn.

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

## Limit lines and masks (pass / fail)


**⚙ Settings → Limit line / mask** turns a panel into a pass/fail monitor,
the way EMC and spectrum-compliance work is done:
- **Level line**: a flat limit (in the panel's units, so dBm once calibrated).
- **Mask (learned)**: let *Max-hold* run while the band shows its normal
  traffic, then **Learn from Max-hold**. The mask is that trace plus your
  **margin** (dB). Masks are saved per exact span.

The limit is drawn on the trace as a red dashed line. Any bin above it is
filled red, the panel gets a red outline, and a **PASS / FAIL** tag (with a
running count) appears next to the LIVE tag. Each violation (start of an
excursion) is logged with time, frequency, level and dB over. Tick **Alert
to Watchtower** to also send it to the Watchtower feed as `RF_LIMIT_EXCEEDED`
(`/var/log/ragnar/rfwatch.jsonl`, same feed as Baseline). This is rate-limited
to one alert per panel per 10 s, both in the page and the backend.

## Memory channels (a watch list)


**⚙ Settings → Channels** keeps up to 32 frequencies per panel with a name each,
and measures them from the rows already arriving — adding a channel never
retunes the radio, because repeated retuning is what fights the waterfall for
the one dongle. Each channel shows its live level, the share of the time it has
been active (above the noise floor by the margin you set), and when it was last
heard. A channel outside the current span says *not in view* rather than reading
zero. Add one by typing a frequency, or straight from the marker, with the
band-plan identification as its name. Channels are kept in the browser per
panel, and travel with a saved [setup](#setups-and-reports).

## Setups and reports


**⚙ Settings → Setups & report**.

A **setup** is everything that decides what a number means: span and zoom,
display range and palette, resolution, detector, gain / PPM / bias-T /
converter, markers, the limit line and its learned mask, channels, the level
calibration and the antenna factor. Save it under a name, recall it before
repeating a measurement, or download it as a file and load it on another unit so
it measures the same way. Recalling a setup pushes the tuner settings back to
the radio, and retunes only if the span actually changed. A setup saved on one
panel is refused on the other rather than half-applied.

A **measurement report** opens a printable page — print it to keep a PDF — with
the marked measurement, the marker table, the waterfall image, and the
conditions behind the numbers: engine, RBW, detector, gain, PPM, window,
calibration state, antenna factor, noise floor, front-end health and the
pass/fail verdict of any limit line. It says plainly when the detector was not
RMS, and when the front end was overloading, because a report that hides that is
worse than no report.

## Trigger and capture (armed recording with a lead-in)


Free-running recording is a bet: press record and hope the burst happens while
the file is open. **⚙ Settings → Trigger & capture** arms a condition instead,
and the radio keeps a rolling buffer of raw samples — so when the condition
fires, the recording **starts before the event**: the rise, the preamble and the
first bits, which is exactly the part a decoder needs and the part free-running
recording misses.

- **Trigger on** — the limit line / mask you already set up, or a flat level.
  A mask is the useful case: learn it from Max-hold over normal traffic, and the
  trigger fires on anything that is not normal.
- **Watch** — the whole visible span, or just the marked signal's channel.
- **Capture** — seconds *before* the event (up to 5) and seconds *after* (up to
  30). At 2 MS/s each second is about 4 MB, so a 1 s lead-in holds ~4 MB of
  samples in memory; the buffer is bounded in bytes, not in blocks.
- **Stop after** *n* captures, with a minimum gap between them, so an armed
  panel left overnight cannot fill the disk.

Each event writes a SigMF pair into the same folder as manual captures, so the
[Signal Analyzer](#signal-analyzer-on-box-sigmf-analysis) lists it, with two
annotations: the event itself, and a **`trigger point`** marker at the exact
sample where the mask was crossed — everything before it is lead-in. Events are
also logged to Watchtower as `RF_TRIGGER_CAPTURE`.

The trigger runs inside the real-time IQ engine, so it needs a span that fits one
tune; the `rtl_power` sweep has no samples to keep. Levels are sent as the
capture produces them, with any dBm calibration offset removed first, so the
arm means what the trace shows.

API: `POST /api/net/rtl/trigger/arm {mask|level_db, f0_hz, f1_hz, pre_s, post_s,
max_events, min_gap_s}`, `POST …/trigger/disarm`, `GET …/trigger/status`.

Measured on the hardware: armed at 2.001 MS/s with a 1.5 s lead-in, the rolling
buffer held a steady 1.5 s for 90 s without firing, and the capture it finally
wrote was 2.117 s long with the trigger point annotated at sample 3,110,912 —
1.555 s in.

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

## Unattended survey


**⚙ Settings → Unattended survey** (RTL-SDR panel) visits each ticked band for a
**dwell** time (5 s – 1 h per band), for 1 / 3 / 10 rounds or continuously, and
writes a **report**. While it runs it owns the dongle: the panel's waterfall
follows it, and band/zoom changes wait until you stop it.

For each band the report gives the **noise floor**, how much of the band was
busy, and every **emitter**: frequency, bandwidth, peak level, **how much of
the time it was on** (≥10 dB over the row's noise floor), first/last seen, and
a likely identity. A narrow emitter that's on ≥95% of the time is flagged as
a constant carrier (usually a local birdie; see Noise print). Reports are kept
in `data/rf_surveys/` and can be viewed, downloaded as **CSV** or deleted from
the same section.

Narrow bands (≤ 2.8 MHz, e.g. 433) are surveyed with the real-time engine
(~16 rows/s). Wide ones (868, 915, the full sub-GHz) use the `rtl_power` sweep
(~1 row/s), so very short bursts can be missed there.

API: `POST /api/net/rtl/survey/start {bands, dwell_s, rounds, name}`,
`POST …/stop`, `GET …/status`, `GET …/list`, `GET …/report?name=`,
`GET …/report.csv?name=`, `POST …/delete {name}`.

## Mesh direction finding (where is it transmitting from?)


Put a marker on a signal and press **📡 Locate (mesh)** (Markers strip, RTL
panel). Every Ragnar in the mesh measures that frequency at the same time and
this unit estimates where the transmitter is.

- Each unit answers with its **level, noise and SNR** plus its position. A unit
  whose dongle is busy (sweeping for someone else, decoding, a survey, radio)
  says so instead of interrupting what it's doing; an idle one takes a short
  measurement and releases the dongle again.
- With **3+ positioned units** it fits a log-distance model
  (level = P0 − 10·n·log10 d, n adjustable, default 2.5) by grid search, and
  reports the position with a **1σ radius** obtained by re-fitting with ~3 dB of
  random per-unit error (a bootstrap). Two units give a rough weighted point
  between them; one gives "somewhere around this unit".
- The result view draws the units, the estimate and its uncertainty circle to
  scale (offline SVG), lists every unit's level/SNR/position, and links to
  OpenStreetMap. Units without GPS can be given a fixed position there.

**Accuracy, honestly.** This is RSSI ranging, not TDOA: it assumes the units
have comparable antennas and gains (calibrate them, ⚙ Level calibration), and
multipath/obstructions bias it. On synthetic geometry (4 units ~1–2 km apart,
3 dB of per-unit error) fixes land **220–480 m** from the truth, inside the
reported 1σ radius about 60% of the time and inside 2σ about 90%. Indoors or
with mismatched antennas, expect worse. Time-difference (TDOA) DF would be far
more accurate but needs tightly synchronised clocks the units don't have.

*Validated:* the measurement endpoint and the coordinator run on the real mesh
(this unit measures; offline peers are reported per unit). The multi-unit fit
is validated on synthetic geometry only — a live multi-unit fix needs a second
unit with an SDR.

Endpoints: `GET /api/mesh/rf/level?freq_hz&bw_hz&secs` (peer-readable, mesh-tag
authenticated), `POST /api/net/rtl/df {freq_mhz, bw_khz, secs, n}`,
`GET|POST /api/net/rtl/df/position`.

## Local Radio


The **📻 Local Radio** bar demodulates one frequency to audio with `rtl_fm`
(one dongle, so listening pauses the sub-GHz sweep).

- **Modes:** FM (broadcast), NFM, AM, **USB**, **LSB** and **CW**. CW is
  received as USB tuned 700 Hz below the carrier, so Morse comes out as a clean
  700 Hz tone. Clicking a signal on the waterfall picks the likely mode: AM for
  MW and the shortwave broadcast bands, LSB below 10 MHz, USB above, AM on the
  airband, NFM elsewhere.
- **Squelch** (0 = open) mutes the audio until a signal is stronger than the
  level. While it's closed the stream is kept alive with silence, so the
  browser's player doesn't stall.
- **● Rec** records what you're hearing to an audio file (WebM/Opus or the
  browser's equivalent) while you keep listening; press again to save.
- Bias-T, direct sampling and the converter offset from ⚙ Settings apply
  here too (a converter-equipped HF setup listens on the real RF frequency).

The narrow modes demodulate at 12 kHz and are resampled to 48 kHz for the
browser; FM broadcast is demodulated at 48 kHz directly.

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

**The waterfall keeps running while you record.** One dongle serves one job, so
the sweep stops for the duration — but the capture feeds its own FFT rows to the
panel, so you watch exactly what is being written to the file, across the
capture's own window (centre ± half the sample rate). Writing the file always
takes priority: rows are only computed when there is time for them, so a
recording is never shortened or thinned for the sake of the display. Band and
zoom changes wait until the capture finishes.

## What a capture records about itself


Every SigMF recording this unit writes — manual, and triggered — carries more
than samples, because a recording that cannot say where and when it was made is
an anecdote:

- `core:datetime` — UTC start time.
- `core:sha512` — a hash of the data file, so tampering or corruption shows.
- `core:geolocation` — a GeoJSON point (longitude first, per the spec) from the
  live GPS fix when there is one, plus `ragnar:position_source` saying whether
  it was a live fix, a manually set position or the last known one, and the
  satellite count and HDOP when the receiver reports them.
- `core:frequency`, `core:sample_rate`, `core:gain_db`,
  `core:freq_correction_ppm` and `ragnar:detector` — enough to reproduce the
  measurement.

No fix means no `core:geolocation` key at all, rather than a zero-zero position.

## Signal Analyzer (on-box SigMF analysis)


Two ways in: a finished SigMF capture shows an **📈 Open in Analyzer** link, and
the **Signal Intelligence** page has a **Signal Analyzer** button (always shown —
analysis is offline, so no SDR need be connected) alongside RF Waterfall / ADS-B /
etc. Both open **`/rf-analyzer`** (`demos/rf_analyzer.html`) — a dedicated page
that analyses the recording *on the device* so it works from a phone, no desktop
DSP tools needed.
All the maths runs in numpy/scipy in `sigmf_analyzer.py`; the page is a viewer
that requests windows.

**Not sure what a control does?** Open **ⓘ What every control does** under the
top bar: every button, selector and field on the page, grouped by panel, in plain
language (the same text appears as a tooltip when you hover a control).

**Built to run on small boards.** Analysis happens on the Ragnar itself, so it is
kept inside what a 1–2 GB board can afford:

- **The busiest 2 seconds.** Classify, demodulate, pulse decode, constellation,
  FM/AM and squelch-tag analysis, de-chirp, cyclostationary and filtering never
  need more than a couple of seconds of samples. When the selection is longer —
  the whole capture, for instance — they analyse its busiest 2 s (at 2 MS/s),
  and the page says which part it used. Zoom in to choose a different part.
- **One heavy analysis at a time.** A second request waits for the first to
  finish instead of running alongside it; the page says so if it has to wait.
- **A memory budget for open captures.** A recording takes 8 bytes per sample in
  memory (a 60 MB file is 240 MB), so the analyzer keeps recently opened
  captures only within a budget of a fifth of free RAM (at most 768 MB), and
  always keeps the one you are working on.

Measured on a 60 MB capture: Ragnar's memory peaked at 1.1 GB instead of 2.8 GB,
cyclostationary detection over the whole capture takes 5 s instead of several
minutes, and whole-capture classify / demodulate take about half a second.

- **Summary** — center/rate/duration, measured noise floor, peak frequency, SNR,
  occupied bandwidth, burst count.
- **Zoomable spectrogram** — a time × frequency image for any window; drag a box
  to zoom, click to drop a marker. Rendered client-side with the waterfall
  palettes (the backend returns a compact base64 dB grid).
- **Spectrum + time-envelope** panels for the shown window.
- **Burst / packet list** — automatic on/off detection (start/end/BW/level);
  click a row to zoom to it and pre-fill the demodulator.
- **Signals survey** — finds **every simultaneous carrier** in the window (an
  STFT → per-frame peak detection above the noise floor → tracks linked across
  time), listing each with its frequency, bandwidth, time span and SNR. Click a
  row to zoom + mark that carrier. A min-SNR control (default 12 dB) trades
  weak-signal reach for a cleaner list — so a busy band's signals become
  individually selectable. Route `/analyze/signals`; see the
  [roadmap](rf-analyzer-roadmap.md) (Segment 10).
- **Demodulate** — shift to the marked signal, low-pass to a chosen bandwidth,
  and demodulate **OOK/AM** (envelope) or **FSK/FM** (instantaneous frequency),
  estimate the symbol rate and **recover a bitstream** (view as binary or **hex**,
  optional **Manchester** decode, copy to clipboard).
- **Decoded devices** — runs **rtl_433** over the whole capture (`-r`) to *name*
  known ISM devices (TPMS / weather / remotes / doorbells…) straight from the
  recording, with their decoded fields.
- **Modulation quality** — service-monitor figures for the selection, shown
  alongside the classification: **FM peak and RMS deviation**, the carrier
  offset and the Carson bandwidth, and **AM modulation depth**. Both families
  are always computed, because the interesting answer is often the one you did
  not ask for — an "FM" transmitter carrying 40% AM depth is telling you
  something about itself. The frequency discriminator ignores samples where the
  envelope collapses (they carry no phase), and deviation is taken at a
  percentile so one wild sample cannot become the answer. Verified against
  synthesised signals: a ±25 kHz tone reads 25.6 kHz peak / 17680 Hz RMS
  (theory 17678), and a 60%-modulated carrier reads 61.1%.
  Route `/analyze/modulation_quality`.
- **Squelch tag (CTCSS / DCS)** — an FM repeater channel usually carries a tag
  under the audio saying which group a transmission belongs to. Both are read
  straight from the frequency discriminator: a **CTCSS** tone (the full 54-tone
  standard table, found by Goertzel and reported with how many dB it stands
  clear of the next candidate — a real tone is many dB clear, noise scores every
  tone alike), or a **DCS** code (the repeating 23-bit Golay word at
  134.4 bit/s, matched against all 83 standard codes at any rotation, with
  inverted-polarity transmissions decoded and flagged). Nothing found normally
  means the channel is carrier-squelch. Verified against synthesised signals: a
  100 Hz tone under 12 dB louder "speech" reads 100.0 Hz with a 28.8 dB margin,
  and DCS 251 decodes exactly in both polarities while noise is rejected.
  Route `/analyze/subaudible`.
- **Constellation demod (PSK)** — on one clean burst, recover symbol timing +
  carrier and classify the constellation (BPSK / QPSK / 8PSK) with an EVM/SNR
  read and a scatter plot, plus rotation-invariant differential bits. PSK only,
  no QAM — see the [roadmap](rf-analyzer-roadmap.md) (Segment 9) for the honest
  scope.
- **Upload / import** — an **⤴ Upload** button brings recordings from other
  tools into the capture list so every analyzer tool works on them:
  - **Flipper Zero `.sub` (RAW)** — a `.sub` isn't IQ, it's an OOK pulse-timing
    list, so Ragnar **synthesises a baseband IQ waveform** from it (carrier
    on/off at the file's frequency, +40 kHz off DC). It then opens as a real
    burst — spectrogram, demod, frames/CRC all work. (Decoded *protocol* `.sub`
    files have no RAW data; re-record as **Read RAW** on the Flipper.)
  - **Raw IQ** (`.cu8`/`.cs8`/`.cs16`/`.cf32`) — you supply the datatype, sample
    rate and centre frequency, and a SigMF `.sigmf-meta` wrapper is written.
  - **SigMF** (`.sigmf-meta` + `.sigmf-data`) recorded on another SDR/box —
    stored as-is (any datatype the loader understands: cu8/cs8/cs16/cu16/cf32).
  Untrusted input is sanitised, size-capped (keep under ~50 MB on a 512 MB Pi),
  and read only as data. Route `POST /analyze/upload`.

- **Ask the RF analyst (AI)** — when Ragnar's AI service is enabled (Settings ›
  AI), the analyzer shows an assistant card that reuses that service
  (`/api/ai/signal` → `AIService.analyze_signal`). It's **grounded**: the server
  re-derives the capture's measured summary and the page sends what you've run
  (classification, bursts, demod bits, frame analysis, marker), so the AI reasons
  about *your* signal — explaining measurements, suggesting demod settings,
  reading the bits/frame/CRC, guessing the likely device/protocol and the next
  step. It's told the honest caveats (relative dB, LoRa is energy-only,
  rolling-code remotes aren't "named"). The card is hidden when AI is disabled.
  **It can also take actions:** the assistant may propose analyzer actions
  (tune/zoom/demod/classify/frames/decode433/reset), returned as an allowlisted,
  validated list (`sigmf_analyzer.parse_ai_actions`) and rendered as one-click
  buttons (plus "Run all") that drive the analyzer's real controls — nothing runs
  without a click, and every action is read-only DSP on the local capture.

Roadmap for where this is going (built in segments): see
[rf-analyzer-roadmap.md](rf-analyzer-roadmap.md).

Routes (read-only over `data/iq_captures/`, so no dongle needed):
`/api/net/rtl/analyze/{list,summary,spectrogram,psd,envelope,bursts,demod}` and
the page at `/rf-analyzer` (optionally `?name=<capture>`). For heavier work the
raw `.sigmf-data` still opens in GNU Radio / inspectrum / URH. `scipy` is used
for decimation/filtering in the demodulator.

## CSV export

Exports from **⚙ Settings → Export**:
- **Spectrum**: frequency plus live / avg / max / min trace per bin.
- **Signals**: the Signals list (frequency, bandwidth, peak, SNR, duty).
- **Markers**: each marker's frequency and level, with Δ to M1.
- **Waterfall**: the whole row history as a time × frequency matrix
  (ISO time per row, one column per frequency, resampled onto the current span).

Frequencies are written with Hz precision; levels in the on-screen units.

## The button and the toggle (WiFi Spectrum Analyzer)


- **"RF Waterfall page" button** — appears in the analyzer's controls once a
  HackRF *and/or* RTL-SDR is detected (or while the demo toggle is on), and
  opens the page in a new tab.
- **"🌊 RF Waterfall demo" toggle** — a config switch (`sdr_demo`). On: the page
  is always reachable and fills empty panels with the synthetic feed; each panel
  still flips to live automatically when its radio is connected. Off: the page is
  served only when a radio is present (otherwise `/rf-waterfall` 404s).

Env `RAGNAR_SDR_DEMO=1` forces the demo on without touching config.

## Professional feature checklist


What this page provides, measured against what professional spectrum analysers
and SDR tools (SDR++, SDR#, GQRX, Signal Hound Spike, benchtop RSA/FSV
analysers) provide as a matter of course. Keep this list as the standard: a
capability that isn't here is a gap worth closing.

**Tier 1 — basics**
- [x] Hover readout: frequency / level / time under the cursor
- [x] Display range: Auto, or manual Ref level + Range, plus *Fit to signal*
- [x] Mouse-wheel zoom, drag to pan, pinch on touch
- [x] Resolution: FFT size (RBW), averaging, window, display bins
- [x] Markers: several, delta marker, peak search / next peak, marker → centre
- [x] HackRF gain (LNA / VGA / amp) in the UI
- [x] Pause and scroll back through history, with a time axis

**Tier 2 — pro-grade**
- [x] CSV export (spectrum, traces, signal list, waterfall)
- [x] Limit lines / masks with pass/fail alarms
- [x] Absolute dBm calibration offset
- [x] Converter/LNB frequency offset, bias-T, RTL direct sampling
- [x] Radio: SSB / CW, squelch, audio recording
- [x] Keyboard shortcuts
- [x] Zero-span (level over time at one frequency)

**Tier 11 — recovery**
- [x] Managed gain: held where the front end has headroom, seeded at the measured knee
- [x] Settings persist across restarts; shipped defaults chosen by measurement
- [x] Software USB reset for a wedged dongle, with automatic detection

**Tier 10 — signalling**
- [x] CTCSS tone decode (54-tone table)
- [x] DCS code decode (83 codes, Golay(23,12), both polarities)
- [ ] RDS on broadcast FM — not implemented (57 kHz subcarrier, differential
      BPSK and group parsing; a project of its own, not a gap in the analyser's
      measurement path)

**Tier 9 — operating**
- [x] Memory channels with live activity monitoring
- [x] Instrument setups: save, recall, export and import
- [x] Printable measurement report with the conditions behind the numbers
- [x] Documented remote API for scripting (docs/rf-api.md)

**Tier 8 — provenance**
- [x] Geotagged captures (GeoJSON, with the source of the fix)
- [x] Antenna factor + feedline loss → field strength in dBµV/m

**Tier 7 — modulation**
- [x] FM deviation (peak / RMS / Carson) and AM modulation depth
- [x] EVM for PSK (constellation demod, Segment 9)

**Tier 6 — measurement set**
- [x] Band-power markers and a corrected noise marker (dB/Hz)
- [x] ACPR, spur search (dBc), hardware harmonic check
- [x] Reference trace with live − reference trace math

**Tier 5 — capture**
- [x] Frequency-mask / level trigger with pre-trigger buffer
- [x] Triggered SigMF capture with the trigger point annotated

**Tier 4 — measurement correctness**
- [x] Detectors: peak / RMS / average / sample / min, applied on device and in the browser
- [x] Front-end overload + clipping indicator
- [x] Image / alias / DC-spike verification against the hardware

**Tier 3 — differentiators**
- [x] Band-plan labels
- [x] Signal-ID hints
- [x] Unattended survey with a log and a report
- [x] Mesh-wide direction finding (RSSI across Ragnar units)

## Driving it from a script


Every control on the page is an HTTP call, documented in
[rf-api.md](rf-api.md): sweep a band, set the detector and gain, arm a trigger,
pull frames, run any analyzer operation. A cron job can arm a mask overnight and
a notebook can pull the captures out in the morning without the page being open.

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
