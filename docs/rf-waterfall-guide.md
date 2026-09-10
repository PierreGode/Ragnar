# RF Waterfall — capability guide

A plain-English tour of what the RF Waterfall's sub-GHz (RTL-SDR) panel can do
and how to use it. For the implementation reference — routes, backends, exact
constants — see [rf-waterfall.md](rf-waterfall.md) and
[sdr-subghz.md](sdr-subghz.md).

It started as a scrolling picture of radio energy. It is now a working sub-GHz
**spectrum instrument** — the kind of thing you'd otherwise open SDR++ or a bench
analyzer for. Everything here runs off a single RTL-SDR (~24 MHz–1.7 GHz) and is
**receive-only**.

---

## 1. It's fast now

The RTL waterfall used to crawl (~1 row/s) because `rtl_power` sweeps the band
and dwells on each step. For any span that fits a single tune (≈ ≤ 2.8 MHz — a
zoom, a band like 433, most mesh overlays) it now **streams raw IQ and does live
FFTs the way SDR++/GQRX do** → a smooth ~16 rows/s with sub-100 ms latency. Wide
scans (full 868 / 915 / sub-GHz) fall back to `rtl_power` automatically. The
panel names the active engine (`IQ FFT · real-time` vs `rtl_power sweep`), and
**Rows/s** shows the *measured* rate.

## 2. Measure, don't eyeball

Experts read numbers off a signal; they never guess from colour.

- **Click any signal** — the marker snaps to the peak and reports exact
  **frequency, level, SNR, −20 dB bandwidth, 99% occupied bandwidth** and
  **channel power**.
- **Readout tiles** — peak freq / peak level, live **SNR**, measured **noise
  floor**, band **busy %**, and span.
- **Trace math (Hold)** — **Avg** (digs weak carriers out of the noise),
  **Max-hold** (catches intermittent bursts), **Min-hold** (reveals the true
  noise floor). A dashed line marks the measured floor.
- **Signal list (CFAR)** — an automatic table of every emitter above the noise
  floor with frequency, bandwidth, SNR and a **duty-cycle** estimate (≈5% = a
  bursty remote, ≈100% = a continuous carrier). This is the "what's actually
  transmitting here" answer.

## 3. Persistence display (the RTSA view)

Toggle **Persist** and the spectrum trace becomes a fading density cloud instead
of a single line: constantly-occupied frequencies glow bright, rare bursts leave
a decaying trail. It surfaces intermittent signals and modulation shape a plain
scrolling waterfall hides — the signature feature of expensive real-time
spectrum analyzers.

## 4. Click-to-decode

Clicking a signal also **classifies** it from its measured bandwidth and
frequency — narrowband OOK/FSK ISM (remote / TPMS / sensor), wideband LoRa/mesh
chirp, POCSAG/FLEX pager, ACARS, VHF airband/VOR, or FM broadcast — and offers a
one-click hand-off to the decoder that can *name* it:

- a **Decode** button flips the RTL panel to `rtl_433` on the nearest ISM band;
- pager / ACARS / VOR classes link straight to their decode pages.

LoRa is honestly labelled *energy-only* — chirp spread-spectrum can't be
demodulated with `rtl_power`/`rtl_433`, and the payloads are encrypted anyway.

## 5. Spectrum monitoring / interference hunting → Watchtower

Hit **Baseline**. Ragnar learns a "known-normal" spectrum (~80 frames), then
watches for what changed and raises alerts:

- **RF_NEW_EMITTER** — energy where the baseline was quiet (a new / rogue
  transmitter);
- **RF_CARRIER_LOST** — a baseline carrier that vanished;
- **RF_BROADBAND_JAMMING** — a large fraction of the span rising at once.

Alerts flow into **[Watchtower](watchtower.md)** as the *RF Spectrum Watch
(sub-GHz)* source, so they land in the one unified alert pane and the Pushover
path like every other watcher. This is how regulators and monitoring teams catch
interference.

## 6. Real signal capture (SigMF)

**⤓ SigMF** records raw IQ plus a metadata sidecar in the open
[SigMF](https://sigmf.org) standard (`.sigmf-data` + `.sigmf-meta`, `cu8`
samples, tune frequency, sample rate, UTC datetime, sha512, band label). A
capture opens directly in **GNU Radio, inspectrum or Universal Radio Hacker** —
turning Ragnar into a real capture instrument you can hand to serious DSP tools,
not a closed viewer. Files land under `data/iq_captures/` with download links.

## 7. Trustworthy frequencies (PPM calibration)

A cheap RTL-SDR crystal is typically tens of ppm off — tens of kHz at 900 MHz,
enough to mis-name a narrow channel. **Calibrate**: point at a carrier whose true
frequency you know, type it in the **Cal @ ___ MHz** box, and Ragnar measures the
error and trims the ppm so every readout afterward is accurate. (This is the
standard `kalibrate-rtl` reference-carrier method; a true GPS-disciplined lock
needs a 1PPS input the RTL-SDR doesn't have, so GPS on Ragnar stays position/time
truth.)

## 8. Polish

- **Five colour palettes** — Aurora (default), Inferno, Viridis, Classic, Mono —
  remembered per browser.
- **Phone-friendly** — controls wrap instead of clipping, bigger tap targets, a
  taller waterfall, no horizontal scroll down to 360px; the desktop layout is
  unchanged.
- Everything that was already there: band presets, zoom, manual tune, mesh/LoRa
  & Z-Wave channel overlays, session record/replay, Local Radio listen, and
  links to ADS-B / Pager / ACARS / VOR / APRS / Mesh.

---

## A practical workflow

1. Pick a band (e.g. **433**) → a smooth live waterfall.
2. Turn on **Max-hold** + **Persist** → see every carrier, including bursty ones.
3. Watch the **Signal list** populate; click one → read its freq / BW / SNR /
   duty.
4. If it's a sensor or remote, hit **Decode** → `rtl_433` names the device.
5. Want to analyse it deeper? **⤓ SigMF** → open the capture in URH / GNU Radio.
6. Leaving it as a monitor? **Baseline** → get pinged in Watchtower if a new
   signal or a jammer shows up.
7. Need accurate numbers first? **Calibrate** against a known carrier.

## Honest limits

- Reaches only ~24 MHz–1.7 GHz — no 2.4/5 GHz (that's the HackRF panel's job).
- LoRa / Z-Wave / mesh overlays are **energy / occupancy only**, not decoded.
- IQ measurements are **relative dB** — consistent, but not lab-calibrated dBm.
- **Direction-finding / geolocation is intentionally not built.** Locating a
  transmitter by comparing it across nodes needs 2+ SDR-equipped Ragnar units;
  with a single dongle it would be untestable, so it was left out rather than
  shipped unvalidated.
