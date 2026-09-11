# Signal Analyzer

The **Signal Analyzer** is Ragnar's on-box SigMF analysis page: open any recorded
IQ capture and characterise it *on the device* — spectrogram, measurements,
demodulation, protocol/CRC, modulation classification, filtering, LoRa de-chirp,
cyclostationary symbol-rate, PSK constellation demod, a multi-signal survey, SigMF
annotations, and a grounded AI analyst — all running in numpy/scipy on the Pi so it
works from a phone with no desktop DSP tools.

- **Page:** `demos/rf_analyzer.html` · **Route:** `GET /rf-analyzer` (login required)
- **Engine:** `sigmf_analyzer.py` (all the maths; pure + selftested — run
  `python3 sigmf_analyzer.py selftest`)
- **API:** `GET/POST /api/net/rtl/analyze/*` (read-only over `data/iq_captures/`, so
  no dongle needed)
- **The page is a viewer.** It requests windows/measurements; the DSP runs on the
  box. No capture is ever trusted as code.

It is the analysis companion to the live [RF Waterfall page](rf-waterfall.md) (which
is where most captures are recorded); the build plan and honest scope of each tool
live in the [roadmap](rf-analyzer-roadmap.md).

---

## Opening it

Three ways in — all land on `/rf-analyzer`:

1. **From a capture** — a finished SigMF recording on the RF Waterfall page shows an
   **📈 Open in Analyzer** link (`/rf-analyzer?name=<capture>`).
2. **Signal Intelligence page** — a **Signal Analyzer** button in the RF-tools row
   (always shown; analysis is offline, so no SDR need be connected).
3. **A shared deep-link** — the URL always mirrors the current view (see
   *Shareable deep-links* below), so a link reopens the exact capture, zoom, marker
   and palette.

## Captures & loading

The analyzer reads SigMF pairs (`.sigmf-meta` + `.sigmf-data`) from
`data/iq_captures/`. The **Capture** dropdown lists them newest-first; recordings
made on the RF Waterfall page and anything you **⤴ Upload** (below) both appear here.

Supported IQ datatypes (decoded to normalised complex on load): **cu8** (default,
what the RTL/HackRF recorder writes), **cs8/ci8**, **cs16/ci16**, **cu16**, and
**cf32/cf64** (GNU Radio / IQEngine).

**Memory note (ⓘ).** The analyzer loads the whole capture into RAM as complex64
(≈ 4× the file size). On a 512 MB Pi Zero keep captures under ~50 MB; the capture
size button carries this reminder, and uploads are size-capped.

## Upload / import (⤴ Upload)

Bring recordings from other tools into the capture list. The button opens a small
panel that accepts:

| Kind | What happens |
|---|---|
| **Flipper Zero `.sub` (RAW)** | A `.sub` isn't IQ — it's an OOK pulse-timing list. Ragnar **synthesises a baseband IQ waveform** from it (carrier on/off at the file's frequency, placed +40 kHz off DC) and it opens as a real burst — spectrogram, demod, frames/CRC all work. Decoded *protocol* `.sub` files have no RAW data and are rejected with guidance to use **Read RAW** on the Flipper. |
| **Raw IQ** (`.cu8/.cs8/.cs16/.cf32`) | You supply the datatype, sample rate and centre frequency; a SigMF `.sigmf-meta` wrapper is written. |
| **SigMF** (`.sigmf-meta` + `.sigmf-data`) | Recorded on another SDR/box — stored as-is (any datatype above). Select **both** sidecars. |

Untrusted input is sanitised (safe filenames), size-capped, and read only as data.
Route `POST /api/net/rtl/analyze/upload`. *Left for later:* WAV-IQ, `.sigmf` tar
archives, re-synthesising decoded (protocol) `.sub` files.

---

## The spectrogram (top-left)

A zoomable time × frequency image for any window, rendered client-side with the
waterfall **palettes** (Aurora / Inferno / Viridis / Classic / Mono; the backend
returns a compact base64 dB grid). The toolbar has three drag modes:

- **Zoom** — drag a box to zoom in; **Back** steps through zoom history, **Reset**
  returns to the whole capture.
- **Measure** — drag a box → **channel power**, peak frequency + level, and mean over
  the boxed time × frequency region.
- **Annotate** — drag a box, type a label, and it's **saved into the `.sigmf-meta`**
  as a standard SigMF annotation (`core:sample_start`/`sample_count` +
  `core:freq_lower_edge`/`freq_upper_edge` + `core:label`). Saved annotations draw as
  dashed green boxes and list as chips with ✕-delete; they round-trip through
  IQEngine / inspectrum / any SigMF tool.

**Cursors.** Click once to drop cursor **A**, again for **B**; the readout shows
**Δt / Δf** and the implied **symbol rate** (1/Δt). Clear cursors resets them.

## Summary, Spectrum & Time envelope

- **Summary** tiles — centre / sample-rate / duration, measured **noise floor**,
  **peak** frequency, **SNR**, **occupied bandwidth**, burst count.
- **Spectrum** — averaged PSD for the window, with an **Avg ↔ Max-hold** toggle
  (max-hold reveals intermittent carriers a mean buries).
- **Time envelope** — power over time for the window.

*Values are relative dB (the RTL/HackRF front end isn't absolute-calibrated) — treat
them as consistent, not survey-grade dBm.*

## Bursts / packets

Automatic on/off burst detection (start / end / bandwidth / level / duty), with a
**merge-gap** control that bridges pulses closer than *N* ms into one transmission
(lower it to split repeated frames). Click a row to zoom to that burst and pre-fill
the demodulator.

## Signals survey

Finds **every simultaneous carrier** in the window and makes each one selectable — an
STFT → per-frame peak detection above the noise floor → detections linked across
frames into **tracks** (a carrier persists while its frequency stays within a
tolerance, bridging short gaps). Each carrier is listed with its **frequency,
bandwidth, time span and SNR**; **click a row** to zoom + mark it. A **min-SNR**
control (default 12 dB) trades weak-signal reach for a cleaner list. *Honest:* a
peak-tracking survey for amplitude carriers — very weak / overlapping signals and the
exact band edges are approximate.

## Modulation

Driven by the marker + bandwidth (point it at one clean burst):

- **Automatic classification** — a feature decision tree (envelope variance,
  instantaneous-frequency spread & bimodality, spectral occupancy, phase jumps) that
  labels **CW / OOK-ASK / FSK / FM / PSK / chirp-spread** with a confidence, plus a
  run-length **symbol-rate** estimate.
- **IQ constellation** scatter for the selection.
- **Derived plots** (inspectrum-style) — the raw **I/Q sample plot**, plus
  instantaneous **amplitude / frequency / phase**, rendered **stacked** (multi-select
  show/hide).
- **Symbol-period cursor** — overlay symbol boundaries on the derived plots; drag one
  symbol width to set the baud (or type it / pull it from the demod).

Classification is **per-selection** — aim it at one burst, not a whole recording with
silence gaps.

## Demodulate

Shift to the marked signal, low-pass to a chosen bandwidth, and demodulate **OOK/AM**
(envelope) or **FSK/FM** (instantaneous frequency); it estimates the symbol rate and
recovers a **bitstream** — view as **binary or hex** (grouped), optional **Manchester**
decode, copy to clipboard.

- **Decoded devices** — runs **rtl_433** over the whole capture (`-r`) to *name* known
  ISM devices (TPMS / weather / remotes / doorbells…) with their decoded fields.
- **⌗ Frames** — protocol structure on the recovered bits: leading-preamble detection,
  repeated-frame **period** via normalised autocorrelation (fundamental, not a
  harmonic), a per-bit **fixed-vs-rolling** stability map + consensus hex, plus a
  **CRC/checksum scanner** (CRC-8 variants, CRC-16 CCITT/XMODEM/ARC/MODBUS, sum-8,
  XOR-8). It also ranks several **candidate frame lengths** and CRC-scans each — a
  length whose trailer validates a CRC wins the headline (clickable candidate chips
  force a length).

## Advanced DSP (three cards side by side)

- **Cyclostationary** — a symbol-rate detector from the transition energy
  |x[n]−x[n−1]|² (whose spectrum lines up at the symbol rate even for *random* data),
  with harmonic→fundamental resolution, a strength/lock readout and clickable
  candidate rates that feed the symbol tool. Targets amplitude/phase-transition mods
  (OOK/ASK/PSK); FSK / very weak / very low baud read low-confidence.
- **LoRa de-chirp** — multiply by a reference down-chirp so LoRa's chirps collapse to
  horizontal **symbol tones**; returns the symbol sequence, a **lock quality**
  (peak/mean; wrong SF ≠ lock) and a symbol×time grid. Pick BW + SF (7–12), centre on
  the marker. *Honest:* a de-chirp **view** + rough symbol readout, **not** a full LoRa
  decoder (no sync/Gray/interleave/FEC/CRC/header).
- **Filter** — band-pass (isolate a signal) / notch (reject an interferer) over the
  A/B-cursor or marker±BW band, with a **spectrum before-vs-after** plot and a
  power-kept %.

## Constellation demod (PSK)

On one clean burst, recover **symbol timing** (grid-search over the sample phase) and
the **carrier** (residual offset + phase via the M-power method), classify the
constellation **order** — **BPSK / QPSK / 8PSK** (the smallest order whose M-power tone
locks, so QPSK isn't mislabelled 8PSK) — and slice symbols to **bits** (Gray + a
rotation-invariant **differential** decode), with **EVM %** and an EVM-derived **SNR**
and a scatter plot showing the ideal cluster centres. Symbol rate is taken from the
field or auto-estimated by the cyclostationary detector (its candidate chips fill the
baud field). *Honest:* PSK only (no QAM), rectangular symbol sampling (no matched
filter); PSK's absolute-phase ambiguity means the differential bits are the trustworthy
ones — it's a constellation demod, not a full frame decoder.

## Ask the RF analyst (AI)

When Ragnar's AI service is enabled (Settings › AI), an assistant card reuses that
service (`/api/ai/signal` → `AIService.analyze_signal`). It's **grounded**: the server
re-derives the capture's measured summary and the page sends what you've run
(classification, bursts, demod bits, frame analysis, marker), so the AI reasons about
*your* signal — explaining measurements, suggesting demod settings, reading the
bits/frame/CRC, guessing the likely device/protocol and the next step. It's told the
honest caveats (relative dB, LoRa is energy-only, rolling-code remotes aren't "named").

**It can also take actions:** the assistant may propose analyzer actions
(tune / zoom / demod / classify / frames / decode433 / reset), returned as an
allowlisted, validated list (`sigmf_analyzer.parse_ai_actions`) and rendered as
one-click buttons (plus "Run all") that drive the analyzer's real controls — nothing
runs without a click, and every action is read-only DSP on the local capture. The card
is hidden when AI is disabled.

---

## Shareable deep-links & keyboard shortcuts

The URL always mirrors the current view —
`/rf-analyzer?name=…&t0=…&t1=…&f0=…&f1=…&mf=…&pal=…` (times in s, freqs in MHz, `mf` =
marker frequency, `pal` = palette) — updated on every zoom/pan, marker change and
palette change. **🔗 Copy link** copies the exact view; opening such a link restores it.

| Key | Action | Key | Action |
|---|---|---|---|
| `R` | reset zoom | `D` | demodulate |
| `B` | back (zoom history) | `L` | copy link |
| `[` / `]` | cycle palette | `?` | toggle shortcut help |
| `Z` / `X` / `C` | zoom / measure / annotate mode | | |

Shortcuts are ignored while typing in a field; a `⌨` button shows the same legend.

## API routes

All under `/api/net/rtl/analyze/` (GET unless noted), read-only over
`data/iq_captures/`:

| Route | Purpose |
|---|---|
| `list` | captures (newest first) |
| `summary` | centre/rate/duration, noise, peak, SNR, occupied BW, bursts |
| `spectrogram` | base64 dB grid for a time×freq window |
| `psd` | averaged/max-hold spectrum |
| `envelope` | power over time |
| `bursts` | on/off burst list (`gap_ms`, `thresh_db`) |
| `signals` | multi-signal survey (`snr_db`, `nfft`) |
| `demod` | OOK/AM or FSK/FM → baud + bits |
| `decode433` | rtl_433 device names from the capture |
| `classify` / `constellation` / `instantaneous` | modulation card |
| `constellation_demod` | PSK symbol/bit recovery (`baud`, `order`) |
| `measure` | box channel-power/peak/mean |
| `frames` | line-decode + frame/CRC analysis (`bits`, `line`, `period`) |
| `filter` | band-pass / notch before-vs-after |
| `dechirp` | LoRa de-chirp (`bw`, `sf`) |
| `cyclic` | cyclostationary symbol-rate |
| `annotations` / `annotate` / `annotation/delete` | SigMF annotations (write = user-only) |
| `upload` (POST) | import Flipper `.sub` / raw IQ / SigMF |

## Scope honesty

This is a genuinely strong, on-device analyzer — not a drop-in replacement for desktop
GNU Radio / URH. Values are relative dB, not calibrated dBm; classification and PSK
demod are per-selection; LoRa is a de-chirp view, not a decoder; the multi-signal
survey is a peak tracker. For the heaviest work the raw `.sigmf-data` always opens in
GNU Radio / inspectrum / URH — the goal here is that **most** analysis never needs to
leave the box or the phone. See the [roadmap](rf-analyzer-roadmap.md) for what's shipped
and what's next.
