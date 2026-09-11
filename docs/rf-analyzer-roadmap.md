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

## Segment 2 — Measurement (inspectrum-grade)
- Draggable **dual cursors** (time + frequency) with **Δt / Δf** readouts and the
  implied **symbol rate** (1/Δt).
- **Box power** measurement over a selection (channel power, peak, mean).
- **Persistence / max-hold** on the spectrogram; **zoom history** (back).
- Cleaner rulers (nice tick steps, absolute + relative axes).
- *Done when:* you can measure a burst's timing and a channel's power to a number
  without leaving the page.

## Segment 3 — Modulation analysis
- **IQ constellation** for a selection (PSK/QAM); **instantaneous** amplitude /
  frequency / phase plots.
- Robust **symbol-rate estimation** via autocorrelation / cyclostationarity (not
  just run-length).
- **Automatic modulation classification** (AM/FM/ASK/FSK/PSK/OFDM/chirp) with a
  confidence, from spectral + envelope features.
- *Done when:* the analyzer guesses the modulation of a signal it's never seen and
  is usually right.

## Segment 4 — Protocol framework
- A pluggable **frame decoder** stage over recovered bits (preamble/sync search,
  field layouts, bit/byte order).
- A **CRC/checksum** library (common ISM polynomials) to validate frames.
- Deeper rtl_433 hooks (per-protocol enable, confidence, raw pulse view).
- *Done when:* a user can define a simple frame layout and read decoded fields.

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
