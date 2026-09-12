# Signal Analyzer — roadmap

The on-box [Signal Analyzer](rf-waterfall.md#signal-analyzer-on-box-sigmf-analysis)
(`sigmf_analyzer.py` + `/rf-analyzer`) is built in shippable **segments**. The
honest north star is the capability set of GNU Radio + inspectrum + URH + IQEngine
+ rtl_433 — years of work — so each segment is a self-contained, on-device,
phone-usable increment that stands on its own and is validated (pure-DSP
selftests + a real capture) before the next begins.

Principles: everything runs on the Pi (numpy/scipy), the page stays a viewer,
no capture is trusted as code, and memory stays bounded (a 512 MB Pi Zero must
not OOM — see the capture ⓘ note).

---

## Segment 0 — Foundation ✅ shipped
Load `cu8`/`cs8` SigMF captures; summary (center/rate/duration, noise floor,
peak, SNR, occupied BW, burst count); zoomable time×freq spectrogram
(drag-zoom, click-marker, palettes); averaged PSD; time envelope; automatic
burst/packet detection; OOK/AM + FSK/FM demod with symbol-rate estimate and a
recovered bitstream; session management (list / open / rename / delete) and the
capture-size ⓘ memory note.

## Segment 1 — Decode & bits  ← next
Turn "here are bits" into "here is what it says."
- **rtl_433 from capture** — run `rtl_433 -r <capture>` offline to *name* known
  ISM devices (TPMS, weather, remotes, doorbells, …) straight from a recording;
  show them in a **Decoded** panel.
- **Bit views** — show the recovered bits as binary **and hex**, grouped.
- **Line coding** — Manchester / differential decode toggles (common in ISM).
- **Packetise** — split the bitstream into packets on inter-burst gaps; per-packet
  length + hex.
- **Export** — copy/save the decoded bits.
- *Done when:* a real doorbell/TPMS capture names the device via rtl_433, and an
  unknown OOK signal yields clean per-packet hex.

## Segment 2 — Measurement (inspectrum-grade) ✅ shipped
- **Dual A/B cursors** (time + frequency) with **Δt / Δf** and the implied
  **symbol rate** (1/Δt) — click for A, click again for B.
- **Box power** measurement (Zoom↔Measure mode; drag a box → channel power, peak
  freq+level, mean).
- **Zoom history** (Back button) + Reset.
- **Max-hold vs Avg** on the Spectrum panel (max-hold reveals intermittent
  carriers a mean buries).
- Follow-ups shipped alongside: burst **merge-gap** control (split repeated
  frames vs one transmission) and **newest-first** capture ordering.
- *Left for later:* on-spectrogram persistence, prettier ruler tick steps.

## Segment 3 — Modulation analysis ✅ shipped
- **Derived plots** (added 2026-09-11): the instantaneous toggle now includes an **I/Q sample plot** alongside Freq/Amp/Phase — inspectrum's full derived-plot set.
- **Stacked derived plots** (added 2026-09-11): the derived plots (I/Q, Freq, Amp, Phase) now render **stacked simultaneously** (multi-select show/hide) instead of one-at-a-time — inspectrum's multi-plot model; the symbol grid overlays every visible plot.
- **Symbol-period cursor** (added 2026-09-11): overlay symbol boundaries on the derived plots — drag one symbol width on the plot to set the baud (or type it / pull from the demod), readout shows period + symbol count. inspectrum's symbol-cursor parity.
- **IQ constellation** for a selection (scatter) + **instantaneous** amplitude /
  frequency / phase (toggle) — a Modulation card driven by the marker + BW.
- **Automatic modulation classification** — a feature decision tree (envelope
  variance, inst-freq spread & bimodality, spectral occupancy, phase jumps) that
  labels CW / OOK-ASK / FSK / FM / PSK / chirp-spread with a confidence, plus a
  run-length **symbol-rate** estimate.
- *Validated:* 4/4 synthetic classes + the real garage remote (OOK @ 2552 baud).
  Classification is **per-selection** — point it at one clean burst, not a whole
  recording with silence gaps.
- *Left for later:* robust cyclostationary symbol-rate; PSK order (BPSK/QPSK)
  from constellation clustering; OFDM detection.

## Segment 4 — Protocol framework ✅ shipped
- **Line coding** decode: Manchester (01→1/10→0), NRZI, differential-Manchester
  (`line_decode`).
- **Frame structure** (`frame_analysis`): leading-preamble detection, repeated-
  frame **period** via normalised autocorrelation (picks the fundamental, not a
  harmonic), aligns the repeats and marks a **per-bit stability map** — the fixed
  code/address vs the rolling/counter/checksum bits — plus a consensus hex.
- **CRC/checksum scanner** (`crc_scan`): tries CRC-8 (× variants), CRC-16
  (CCITT/XMODEM/ARC/MODBUS), sum-8 and XOR-8 over the trailing byte(s) and reports
  matches — a ⌗ Frames button on the demod card.
- **Candidate frame lengths + per-candidate CRC** (`_period_candidates` /
  `_eval_period`): beyond the single autocorr fundamental, the tool ranks several
  plausible frame lengths (autocorr peaks above a low floor + common byte-aligned
  lengths), aligns each (from 0 AND after the preamble), and **CRC-scans each
  independently**; a length whose trailer validates a CRC wins the headline.
  Clickable candidate chips (force a length); the AI `frames` action can pass
  `period_bits`. This directly fixes the jitter limitation below — on the real
  garage bits (which the single-period pass returned "no period" for) it now
  surfaces candidates incl. a **24-bit frame with a CRC match** (a lead to verify;
  a short-frame CRC hit can be coincidental).
- *Validated:* 40/40 selftests — line decode, period=fundamental, fixed-vs-rolling
  map, appended CRC-8 / sum-8, candidate list incl. the true period, explicit
  period honoured, CRC-validated length wins the headline. **Note:** run-length
  demod jitter still weakens the *single* autocorr pick; candidates + CRC are the
  mitigation. Clock recovery remains a later improvement.
- *Left for later:* deeper rtl_433 hooks (per-protocol enable, raw pulse view),
  user-defined field layouts.

## Segment 5 — Scale & Pi-safety
- **Memory-budgeted loading** — refuse or auto-window captures larger than a
  budget derived from `/proc/meminfo`, so a Pi Zero can't OOM.
- **Tiled spectrogram cache** for instant pan/zoom on long captures.
- **Decimate-on-load** option for very wide/long files.
- *Done when:* a 30 s / 120 MB capture is analysable on a 512 MB board.

## Segment 6 — SigMF annotations & interop ✅ shipped
- **Annotate on the spectrogram** — an **Annotate** drag mode: drag a box around a
  signal, label it, and it's **saved into the `.sigmf-meta` as a standard SigMF
  annotation** (`core:sample_start`/`core:sample_count` + `core:freq_lower_edge`/
  `core:freq_upper_edge` + `core:label`). Saved annotations draw as dashed
  green boxes with labels and list as chips with ✕-delete under the spectrogram;
  they load automatically when a capture opens (so a capture's band-label
  annotation from capture time shows too).
- **Round-trips / interop:** annotations persist in the SigMF file, so a capture
  labelled here opens with its labels in IQEngine / inspectrum / any SigMF tool,
  and vice-versa. Backend `add_annotation` / `list_annotations` /
  `delete_annotation` (+ pure `_box_to_annotation`/`_annotation_to_box`); routes
  `/analyze/{annotations,annotate,annotation/delete}`. Writes are user-only (not
  in the AI action allowlist — those stay read-only).
- *Validated:* 6 new selftests (46/46) — box↔annotation round-trip, add persists
  in the file (interop-visible), delete, zero-span rejected; plus a real-capture
  add→verify-in-file→delete.
- *Left for later:* export a selection as a new SigMF sub-capture; export decoded
  bits / CSV.

## Segment 7 — Advanced DSP  (in progress)
- **Filter design + apply** ✅ — band-pass (isolate a signal) / notch (reject an
  interferer) over the A/B-cursor or marker±BW band, with a **spectrum
  before-vs-after** plot and a power-kept %. FFT-domain band mask
  (`_fft_bandmask` / `filter_preview`), route `/analyze/filter`, Filter card on
  the page. 4 selftests (50/50); on the real garage capture band-pass/notch keep
  37.5%/62.5% (sum 100%, complementary).
- **LoRa de-chirp view** ✅ — multiply by a reference down-chirp so LoRa's
  diagonal chirps collapse to horizontal **symbol tones**; returns the symbol
  sequence, a **lock quality** (peak/mean; wrong SF ≠ lock), and a symbol-value×
  time grid drawn with the palette LUT. Pick BW + SF (7–12), centre on the marker.
  `_lora_base_upchirp`/`_lora_dechirp` (pure) + `dechirp()` (resample to os·BW,
  mix, de-chirp); route `/analyze/dechirp`; a LoRa de-chirp card. 5 selftests
  (55/55) — **8/8 symbol recovery on synthetic LoRa under noise, wrong-SF doesn't
  lock**. HONEST: it's a de-chirp *view* + rough symbol readout, **not** a full
  LoRa decoder (no sync/Gray/interleave/FEC/CRC/header). On the real weak
  Meshtastic RTL capture it did **not** lock across an SF/BW/offset sweep (faint
  packet in a 1 MS/s recording) — the lock readout says so honestly.
- **Cyclostationary symbol-rate detector** ✅ — a cyclic-feature profile from the
  transition energy |x[n]-x[n-1]|² (whose spectrum lines up at the symbol rate
  even for *random* data — the point of cyclostationarity), with harmonic→
  fundamental resolution, a strength/lock readout and clickable candidate rates
  that feed the symbol tool. `_cyclic_profile`/`_fundamental_rate`/`cyclic()`;
  route `/analyze/cyclic`; a Cyclostationary card. 4 selftests (59/59), stable
  over repeated random runs — OOK 5k/20k + BPSK land on the true baud, CW shows
  no confident feature. HONEST: targets amplitude/phase-transition mods
  (OOK/ASK/PSK); FSK / very weak / very low baud read low-confidence (the
  strength says so). It's a symbol-rate cyclic feature, not the full 2-D SCF
  surface.
- *Left for later:* full 2-D **spectral-correlation** surface; **multi-signal
  tracking**; long-capture **tiled waterfall** overview; filtered-audio export.
- *Done when:* the analyzer handles chirp-spread and cyclostationary signals a
  plain spectrogram can't characterise.

## Segment 8 — UX & sharing  (in progress)
- **Shareable deep-links** ✅ — the URL always mirrors the current view:
  `/rf-analyzer?name=…&t0=…&t1=…&f0=…&f1=…&mf=…&pal=…` (times in s, freqs in MHz,
  `mf` = marker frequency, `pal` = palette). `updateURL()` (a `history.replaceState`)
  fires on every zoom/pan (`refreshWindow`), marker set/clear and palette change;
  opening such a link restores the capture, zoom window, marker and palette
  (parsed into a one-shot `DEEP` object applied in `loadCapture`; the URL palette
  wins over the saved localStorage one). A **🔗 Copy link** button copies the exact
  view (clipboard API with an execCommand fallback).
- **Keyboard shortcuts** ✅ — <kbd>R</kbd> reset zoom · <kbd>B</kbd> back ·
  <kbd>[</kbd>/<kbd>]</kbd> cycle palette · <kbd>Z</kbd>/<kbd>X</kbd>/<kbd>C</kbd>
  zoom/measure/annotate mode · <kbd>D</kbd> demodulate · <kbd>L</kbd> copy link ·
  <kbd>?</kbd> toggle the shortcut help. Ignored while typing in an input/select/
  textarea; a ⌨ button opens the same legend. Each shortcut drives the existing
  buttons, so behaviour stays in one place.
- *Left for later:* per-signal notes, saved analysis presets.

## Segment 9 — Constellation demod (PSK) ✅ shipped
- **PSK symbol/bit recovery** — point it at one clean burst (marker + BW) and it
  recovers **symbol timing** (grid-search over the sample phase), the **carrier**
  (residual CFO + constant phase via the **M-power method**), the **constellation
  order** M ∈ {2,4,8} = **BPSK/QPSK/8PSK** (the *smallest* order whose M-power tone
  locks, so QPSK is never mislabelled 8PSK — a BPSK/QPSK signal also locks at higher
  multiples), slices symbols to **bits** (Gray, plus a **rotation-invariant
  differential** decode) and reports **EVM %** + an EVM-derived **SNR**. A
  constellation scatter with the ideal cluster centres, and a single-tone/CW guard.
- Symbol rate comes from the field or is **auto-estimated** with the
  cyclostationary detector; the Cyclostationary card's candidate chips fill the
  baud field. `_psk_symbol_demod` / `constellation_demod` (+ `_gray_bits`); route
  `/analyze/constellation_demod`; a **Constellation demod** card.
- *Validated:* 7 new selftests (66/66, stable over repeated random runs) — BPSK/
  QPSK/8PSK order detection (QPSK not mislabelled 8PSK), low EVM, QPSK differential
  symbols recovered rotation-invariantly, Gray mapping, CW flagged as a single
  cluster, baud auto-estimate near truth. Proven **on-box** on a synthetic QPSK
  capture (`psk-demo-qpsk-50k`, gitignored fixture): QPSK, EVM 6.9 %, lock-by-order
  {2:0.03, 4:0.98, 8:0.93}.
- *HONEST:* **PSK only** (no QAM), **rectangular** symbol sampling (no matched
  filter), absolute-phase ambiguity resolved only by the differential decode; it's
  a constellation demod, not a full frame decoder — pair it with Frames / CRC.

## Upload / import ✅ shipped (out-of-band, user-requested)
Bring recordings from other tools into the capture list (an **⤴ Upload** button):
- **Flipper Zero `.sub` (RAW)** → not IQ but an OOK pulse-timing list, so a
  baseband IQ waveform is **synthesised** (carrier on/off at the file's frequency)
  and it opens as a real burst — spectrogram/demod/frames/CRC all work.
- **Raw IQ** (`.cu8/.cs8/.cs16/.cf32`) → a SigMF meta wrapper is written from the
  datatype / sample-rate / centre-freq you give.
- **SigMF** (meta + data) recorded elsewhere → stored as-is.
`load()` was extended to decode cf32/cs16/cu16 alongside cu8/cs8. Pure helpers
(`parse_flipper_sub` / `flipper_raw_to_cu8` / `import_*`) selftested (77/77 incl.
a Flipper .sub → loadable OOK capture → bursts); route `POST /analyze/upload`
(size-capped, names sanitised, bytes read as data only). *Left for later:*
WAV-IQ, decoded (protocol) `.sub` re-synthesis, `.sigmf` tar archives.

## Segment 10 — Multi-signal & long captures  (next)
- **Tiled / decimated spectrogram overview** for long or large captures — pan/zoom
  without loading the whole file (Pi-Zero-safe; overlaps the skipped Segment 5).
- **Memory-budgeted loading** derived from `/proc/meminfo`.
- **Multi-signal detection & tracking** — find several carriers and follow each over
  time; click a track to jump / zoom / measure.
- *Done when:* a 30 s / 120 MB capture is analysable on a 512 MB board and several
  simultaneous carriers are individually selectable.

## Segment 11 — Device fingerprint & bit workbench ✅ shipped
Close the loop from *"what kind of signal"* to *"what device, saying what"* — the
two moves that turn a mystery emitter into a cracked one.
- **Device fingerprinting** — measured features (modulation, frame length,
  CRC family, centre frequency) are scored against a catalog of ISM device
  *families* (EV1527/PT2262 fixed-code remotes, KeeLoq rolling-code, TPMS,
  weather/environmental, security sensors, LoRa). Returns **ranked candidates**
  with a confidence and a per-feature rationale — honest family guesses, never a
  single certainty. rtl_433 stays the heavyweight decoder for supported devices;
  this classifies the ones it can't, and the unknowns. Auto-runs after *Frames*.
- **Bit workbench** — transforms on the recovered bitstream *before* framing:
  **invert** (complement), **reflect** (MSB↔LSB per byte), and a **bit offset**
  to slide the byte grid — on top of the existing Manchester/NRZI/diff line codes.
- **CRC brute-force** (`crc_brute`) — finds a check trailer that validates even
  when a leading header byte isn't covered, in either 16-bit endianness; surfaced
  alongside the per-candidate CRC scan.
- **Cross-capture field diff** (`field_diff`) — the "press the button twice"
  move: add ≥2 captures of the same emitter to a compare set, and it aligns their
  frames and separates **fixed** bits (device ID / type) from **varying** ones,
  classing each varying field as a monotonic **counter**, a high-entropy
  **rolling** code, or plain varying. This is how you reverse a protocol no
  library knows.
- Pure cores selftested (90/90): bit transforms, `crc_brute` (CRC-8 after a
  skipped length byte), `field_diff` (fixed ID + counter + rolling separated),
  and `fingerprint` (EV1527 / TPMS / LoRa families). Routes: `GET
  /analyze/fingerprint`, `POST /analyze/diff`, and transform params on `GET
  /analyze/frames`.
## Segment 12 — Pulse (PWM / PPM) symbol decoder ✅ shipped
Many sub-GHz OOK remotes (PT2262 / EV1527 / HT12E / Princeton, and Flipper `.sub`
RAW captures) encode a bit as a *pulse width* (short/long high) or a *pulse
position* (short/long gap after a fixed pulse), **not** as raw NRZ levels — so the
level-sampling demod turned one symbol into several raw bits and the frame length
came out wrong. A new **Pulse** demod mode decodes the true symbol stream:
- `pulse_decode` shifts / decimates / envelopes an OOK selection, then the pure
  `_decode_pulses` run-length-encodes the on/off stream, two-means-clusters the
  high widths and gaps (`_two_class`), auto-detects **PWM vs PPM** from whichever
  dimension is bimodal, splits frames at the long inter-frame gap, and decodes
  each symbol (wide high = 1 for PWM; wide gap = 1 for PPM/PDM).
- Returns a **demod-shaped** result (`bits` / `baud` / `wave`) so the recovered
  symbols flow straight into **Frames → Fingerprint → Field diff**, plus the
  coding, the base pulse width **Te**, and the per-frame symbol bits. The page's
  fingerprint call maps `pulse → ook` (a decoded pulse train is still OOK), so an
  EV1527's 24-bit frame now lines up with the family match.
- 96/96 selftests (6 new: PWM + PPM auto-detect and bit recovery, forced coding,
  run-length + two-class cores, and an **end-to-end** synthesised PWM cu8 capture
  → symbols). Route `GET /analyze/pulse?name&f_offset&bw&t0&t1&coding`; UI adds a
  Pulse mode toggle + a coding selector (auto / PWM / PPM).
- *Next:* a bigger device signature catalog; decoded-`.sub` re-synthesis so
  Flipper protocol files (not just RAW) round-trip.

---

*Scope honesty:* this will be a genuinely strong, on-device analyzer — not a
drop-in replacement for desktop GNU Radio / URH. For the heaviest work the raw
`.sigmf-data` always opens in those; the goal here is that **most** analysis
never needs to leave the box or the phone.
