# RF Waterfall — operator's guide

How to use the RF Waterfall as a spectrum instrument: what each control does,
how to measure something properly, and how to trust the numbers you read off it.
For routes, backends and exact constants see [rf-waterfall.md](rf-waterfall.md)
and [sdr-subghz.md](sdr-subghz.md).

The page stacks two panels. The **sub-GHz panel** runs an RTL-SDR
(~24 MHz–1.7 GHz); the **RF Bands panel** runs a HackRF (1 MHz–6 GHz). Both are
**receive-only**. A panel with no radio attached shows a synthetic demo feed so
the layout still makes sense.

---

## Start here

0. Nothing needs configuring first: the gain is managed, the detector is RMS and
   the display range follows the noise floor. Anything you change is remembered.
1. Pick a **band** (e.g. `433`) or type a centre frequency into **Tune**.
2. Let it run a few seconds so **Max-hold** and the **Signals** list fill in.
3. **Click a signal.** The marker snaps to its peak and prints frequency, level,
   SNR, bandwidth and channel power.
4. **Scroll-wheel** over the waterfall to zoom into it; **drag** to pan;
   **double-click** to return to the whole band.
5. Press **?** for the keyboard shortcuts.

---

## 1. The picture

**Capture engine.** Any span that fits a single tune (≲2.8 MHz — a zoom, a band
like 433, most mesh overlays) streams raw IQ and FFTs it continuously, giving a
smooth ~16 rows/s. Wider spans (a full 868 / 915 / sub-GHz scan) are swept with
`rtl_power` at roughly 1 row/s. The panel names the engine it is using
(`IQ FFT · real-time` or `rtl_power sweep`) and **Rows/s** shows the measured
rate. Rows are released at a steady pace about 0.8 s behind live, so the scroll
stays even when the network or the backend hiccups.

**Resolution.** The **RBW** tile shows the width of one FFT bin. On the RTL
panel the FFT size follows the zoom automatically, so a narrow span resolves
finer (1 MHz ≈ 560 Hz, 250 kHz ≈ 244 Hz, 120 kHz ≈ 122 Hz). Override it, along
with averaging, the FFT window and the number of display columns, in
**⚙ Settings → Resolution**:

- **Averaging** — more averaging is smoother and steadier, less averaging reacts
  faster to bursts.
- **Detector** — how the FFT bins inside one display column are combined, and
  therefore what every level on the page means. **RMS** is the default and is
  the one to measure with. Switch to **Peak** when hunting for something very
  narrow at a wide span: it catches a signal thinner than a column, at the cost
  of reading the noise floor several dB high. *Average* is steadier and
  reads lower still, *Sample* is unsmoothed, *Min* digs out the floor under
  bursty traffic.
- **Window** — *Hann* for general use, *Blackman-Harris* to separate a weak
  signal sitting next to a strong one, *Flat-top* when the level reading matters
  most, *Rectangular* for the sharpest possible peaks (and the worst leakage).

**Display range** decides how the colours map to dB (**⚙ Settings → Display
range**). *Auto* tracks the measured noise floor. To dig out something weak, set
**Ref level** (the top of the scale) and a narrower **Range**, or press **Fit to
signal**. The colour bar on the right edge of each waterfall always shows the
range in use, and the whole waterfall — including rows already on screen —
recolours as you change it. Five palettes are available in the top bar.

---

## 2. Navigating

- **Wheel** zooms around the pointer, **drag** pans, **double-click** resets to
  the full band. On a phone, **pinch** to zoom and drag sideways to pan.
- The view responds immediately and the radio retunes once you stop moving, so a
  burst of wheel clicks is a single retune.
- **History**: drag the History slider (or **Shift + wheel**) to scroll back
  through the last few minutes. The view holds still while new rows keep
  recording; **▲ Live** returns to the live edge. Clock times run down the left
  edge of the waterfall.
- **2D / 3D** switches between the flat waterfall and a 3D surface (power = height). **Drag the 3D view to rotate it**, wheel or pinch to zoom; the angle is remembered.

---

## 3. Measuring

Read numbers; don't judge by colour.

- **Readout tiles** — peak frequency and level, live **SNR**, measured **noise
  floor**, **Busy %** of the span, the span itself, **Rows/s** and **RBW**.
- **Click to measure** — the marker snaps to the nearest peak and reports centre
  frequency, level, SNR, **bandwidth**, **99% occupied bandwidth** and **channel
  power**. Bandwidth is measured on the smoothed *Avg* trace at the deepest drop
  the signal's SNR supports, and the readout names it: `BW−20` for a strong
  signal, `BW−5` for one only a few dB out of the noise. A "−20 dB bandwidth"
  is only meaningful when the signal is more than 20 dB above the floor.
- **Hover** anywhere for the frequency, the level of that exact cell and when it
  was received, plus the band-plan allocation under the pointer.
- **Markers M1–M4** — click to place the active marker, **Shift + click** or
  **＋ Marker** to add another. The table lists each marker's frequency and
  level, and M2–M4 also show **Δ frequency and Δ level against M1**. **Peak**
  jumps to the strongest signal on screen; **◀ Next / Next ▶** step between
  peaks (a peak counts when it rises 6 dB above the dip beside it, so one
  signal's sidelobes are skipped); **↔ Centre** re-centres the view on it.
- **Zero-span** plots the level at the active marker's frequency over time —
  the way to see keying, duty cycle and fading. It resolves at the row rate
  (~16 per second), not the sample rate.
- **Trace math (Hold)** — **Avg** digs weak carriers out of the noise,
  **Max-hold** catches intermittent bursts, **Min-hold** shows the true floor. A
  dashed line marks the measured noise floor.
- **Signals list** — every emitter above the floor with frequency, bandwidth,
  SNR and a **duty-cycle** estimate. ~5% means a bursty remote; ~100% means a
  continuous carrier.
- **Σ Band power / N Noise** measure a segment's total power (and its power per
  Hz) and a noise level normalised to 1 Hz. The noise figure corrects for RBW,
  the window and the detector — without those corrections a noise reading is
  several dB out.
- **ACPR / Spurs / Harmonics** answer "how clean is this transmitter?": power
  leaking into the neighbouring channels, every other peak in view in dBc, and —
  on the hardware — whether 2× and 3× the frequency are radiating too.
- **⎖ Store ref** freezes the current trace and shows **live − reference**. Use
  it to prove what changed, or to measure an antenna, filter or attenuator.
- **Persist** turns the trace into a fading density cloud, so frequently
  occupied frequencies glow and rare bursts leave a trail — the real-time
  analyser view for spotting intermittent signals and modulation shape.

---

**Two checks before you believe a signal.**

- The **Front end** tile appears when the receiver is overloading. An
  overdriven ADC clips, and clipping invents harmonics and intermodulation that
  look like transmitters. `OVERLOAD` (red, and the waterfall gets an outline)
  means lower the gain and measure again — nothing in that capture is
  trustworthy. `near clip` means you have under 3 dB left.
- **✓ Verify** next to a measurement proves the peak is on the air. It measures
  the frequency through two different tuner centres: a real transmitter keeps
  its frequency, a mixer image moves with the tuner, and the receiver's own DC
  spike stays at the centre of both. Use it before recording or reporting
  anything you have not seen before.

---

## 4. Identifying what you found

- The **band plan** strip under the ruler labels the allocations in view
  (broadcast, amateur, ISM, cellular, aviation, marine, satellite…). Pick your
  **ITU region** in ⚙ Settings, since allocations differ.
- A measurement adds a **likely identity** from the frequency and measured
  bandwidth: ISM remotes/TPMS/sensors, LoRa chirp, pagers, ADS-B, ACARS,
  airband, marine VHF and AIS, APRS, ham FM, PMR446, TETRA, weather satellites,
  DAB, DVB-T, GSM/LTE carriers, DECT, Wi-Fi vs Bluetooth, CB, HF SSB and CW.
- Where a decoder exists, the measurement offers it: **Decode** switches the RTL
  panel to `rtl_433` on the nearest ISM band; pager / ACARS / VOR / APRS
  classes link to their pages. Every measurement also links to the **Signal ID
  wiki** for that frequency.
- LoRa, Z-Wave and the mesh overlays are **energy and occupancy only**. Chirp
  spread-spectrum can't be demodulated with `rtl_power`/`rtl_433`, and the
  payloads are encrypted regardless.

---

## 5. Cleaning up the view

Some lines never go away: birdies from the Pi, its USB bus and the dongle's own
clock, the DC spike at the centre frequency, a neighbour's always-on carrier.

**Noise print** removes them. Choose a length (3–30 s), press **● Record** while
the band is quiet, and the print is applied. The print is the per-frequency
*median* of the recorded rows, so a burst during recording is not learned as
noise, and only its excess over its own floor is subtracted: ordinary noise is
untouched, constant lines drop to the floor, and a known line that gets louder
still shows by how much. The **Filter** toggle and strength slider control it.
A print belongs to the exact span it was recorded on, and is remembered per
panel. Re-record after changing gain.

---

## 6. Calibration

- **Frequency (PPM)** — click a carrier whose exact frequency you know, enter
  that frequency and press **Calibrate**. The crystal offset is measured and
  applied to every capture. Do this before trusting narrow-channel work.
- **Field strength (dBµV/m)** — once levels read dBm, enter your antenna's gain
  (or its antenna factor) and the cable loss under **⚙ Settings → Level
  calibration**, and measurements also report field strength — the unit EMC and
  site-survey work is specified in. The gain form is frequency-dependent and is
  recomputed for each measurement.
- **Level (dBm)** — levels are relative dB until calibrated. Put a marker on a
  signal of known strength, enter that level under **⚙ Settings → Level
  calibration** and press **Calibrate to marker**. Every level on the page then
  reads dBm. It is a one-point calibration: redo it when gain or antenna
  changes.

---

## 7. Monitoring unattended

- **Baseline** learns the normal spectrum, then alerts on new or vanished
  carriers and broadband jamming, into the Watchtower feed.
- **Limit line / mask** is a pass/fail test. Set a flat **level line**, or let
  Max-hold run over normal traffic and press **Learn from Max-hold** for a
  **mask** with a margin. Anything above it fills red on the trace, the panel
  shows a red **FAIL** tag and outline, and each excursion is logged — optionally
  to Watchtower as well.
- **Unattended survey** visits each ticked band for a dwell time, for a set
  number of rounds or continuously, and writes a report: per band the noise
  floor and how much of it was busy, and every emitter with frequency,
  bandwidth, peak, **how much of the time it was on**, and first/last seen.
  Reports are viewable in the page and downloadable as CSV. A narrow emitter on
  ≥95% of the time is flagged as a constant carrier rather than a remote.

---

## 8. Locating a transmitter

With several Ragnar units in the mesh, put a marker on a signal and press
**📡 Locate (mesh)**. Every unit measures that frequency at once and reports its
level and position; this unit fits a path-loss model and shows the estimate, an
uncertainty circle and each unit's contribution on a scale drawing.

Three or more positioned units that can hear the signal give a real fix; two
give a rough point between them; one just says "near this unit". A unit whose
dongle is busy says so instead of interrupting its own work, and units without
GPS can be given a fixed position.

This is **RSSI ranging**: it assumes the units have comparable antennas and
gains (calibrate them), and multipath biases it. Expect hundreds of metres
outdoors, and worse indoors.

---

## 9. Capturing and exporting

- **⤓ SigMF** captures raw IQ to a standard SigMF recording — open it in the
  on-box [Signal Analyzer](rf-waterfall.md#signal-analyzer-on-box-sigmf-analysis),
  or in URH / GNU Radio / inspectrum. Watch the size: ~4 MB per second at
  2 MS/s. The waterfall keeps scrolling while it records, showing the capture's
  own window, so you can see what you are getting. Retuning waits until it
  finishes.
- **Trigger & capture** (⚙ Settings) records *on a condition* instead of on
  hope. Set a limit line or learn a mask, choose how many seconds before and
  after the event you want, and arm it. The radio keeps a rolling buffer, so
  the file starts before the thing that triggered it — you get the rise and the
  preamble, not the tail. Each capture opens in the Signal Analyzer with the
  trigger point marked. Leave it armed: it stops after the number of captures
  you set.
- **Rec / Replay** records the sweep itself and plays it back through the same
  view.
- **CSV** exports the spectrum, the Signals list, the markers, or the whole
  waterfall history as a time × frequency matrix.
- **⇩ PNG** saves the waterfall with its labels.

---

## 10. Listening

The **📻 Local Radio** bar demodulates one frequency to audio: **FM**, **NFM**,
**AM**, **USB**, **LSB** or **CW** (heard as a 700 Hz tone). Clicking a signal
on the waterfall picks the likely mode for that frequency. **Squelch** mutes
until a signal beats the level, and **● Rec** saves what you hear to a file.
One dongle serves one job, so listening pauses the sub-GHz sweep.

---

## 11. Repeating a measurement, and writing it up

- **Channels** (⚙ Settings) is a watch list: add the frequencies you care about
  and the panel tracks each one's level, how much of the time it is active and
  when it was last heard, without retuning anything.
- **Setups** save everything that decides what a number means — span, display
  range, resolution, detector, gain, markers, limits, channels, calibration.
  Recall one before repeating a measurement so you are measuring the same way;
  export it to a file to give another unit the same configuration.
- **⎙ Measurement report** produces a printable page with the measurement, the
  markers, the waterfall and the conditions: detector, RBW, gain, calibration,
  front-end health and the limit verdict. Print it to PDF. If the detector was
  not RMS, or the front end was overloading, the report says so.

---

## A practical workflow

1. Pick a band, let **Max-hold** and the **Signals** list fill.
2. **Noise print** the band so permanent birdies stop hiding real bursts.
3. Click the interesting signal; read its frequency, SNR, bandwidth and duty.
4. **Zoom** into it — finer resolution reveals whether it's one carrier or
   several, and **zero-span** shows how it keys.
5. Sensor or remote? **Decode** names it with `rtl_433`.
6. Need the waveform? **⤓ SigMF** and open it in the Signal Analyzer.
7. Leaving it running? **Baseline** or a **limit line** for alerts, or a
   **survey** for a written report of the whole band.
8. Several units? **Locate (mesh)** for an estimate of where it transmits from.

---

## If the panel goes quiet

An RTL-SDR that has been started and stopped many times can get stuck: it still
opens, but sends no samples. The panel notices (running, but no rows) and offers
**⭮ Reset dongle** — also in ⚙ Settings → Hardware. It re-enumerates the device
over USB, which is the same as unplugging and replugging it, and restarts your
sweep.

---

## Limits worth knowing

- The sub-GHz panel reaches ~24 MHz–1.7 GHz. Above that, use the HackRF panel.
- HF below ~24 MHz needs a dongle that supports direct sampling, or an
  upconverter (set its LO under ⚙ Settings → Hardware).
- LoRa / Z-Wave / mesh overlays show energy and occupancy, not decoded traffic.
- Levels are relative dB until you calibrate against a known source; even then
  it is a one-point calibration, not a laboratory standard.
- The live view sits ~0.8 s behind real time. That buffer is what keeps the
  scroll steady.
- Wide bands are swept at ~1 row/s, so a very short burst can be missed there.
  Zoom into a span that fits one tune to catch it.
- Direction finding is RSSI-based and needs 3+ positioned units for a real fix;
  accuracy is hundreds of metres at best.
- **Gain is managed for you by default**, held where the front end has headroom
  but is not deaf (see
  [what ships by default](rf-waterfall.md#what-ships-by-default-and-why)). If you
  switch to the dongle's own **Hardware AGC**, expect it to clip near strong
  signals — the **Front end** tile will say so, and everything measured while it
  is lit is wrong.
- One dongle does one thing at a time: decoding, listening, ADS-B, a survey and
  the waterfall take turns.
