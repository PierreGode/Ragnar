# RF Waterfall page

A dedicated full-screen page that stacks two true-RF **waterfalls** — sub-GHz
ISM (RTL-SDR, 433/868/915 MHz) over the Wi-Fi bands (HackRF, 2.4/5/6 GHz) — each
scrolling a power-over-frequency heatmap.

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

The band selector on each panel retunes the real sweep when live (RTL-SDR:
433/868/915; HackRF: 2.4/5/6) and swaps the synthetic model otherwise.

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
