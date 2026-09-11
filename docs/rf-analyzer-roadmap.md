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

## Segment 6 — SigMF annotations & interop
- **Annotate on the spectrogram** — draw/label a signal box and **save it back to
  the `.sigmf-meta` as SigMF annotations** (the IQEngine model); reload shows them.
- **Export a selection** as a new SigMF sub-capture; export decoded bits / CSV.
- *Done when:* annotations round-trip through the SigMF file and open elsewhere.

## Segment 7 — Advanced DSP
- **Filter design + apply** (band-pass/notch) with before/after; export/listen.
- **LoRa / chirp** analysis (de-chirp view); **spectral correlation** (cyclo)
  display; **multi-signal tracking** across time.
- Long-capture **tiled waterfall** overview.
- *Done when:* the analyzer handles chirp-spread and cyclostationary signals a
  plain spectrogram can't characterise.

## Segment 8 — UX & sharing
- Keyboard shortcuts, per-signal notes, saved analysis presets, shareable
  deep-links (`/rf-analyzer?name=…&t0=…&f0=…`).

---

*Scope honesty:* this will be a genuinely strong, on-device analyzer — not a
drop-in replacement for desktop GNU Radio / URH. For the heaviest work the raw
`.sigmf-data` always opens in those; the goal here is that **most** analysis
never needs to leave the box or the phone.
