# RF Waterfall — synthetic demo (hidden)

A self-contained, synthetic RF **Waterfall** page that runs with **no SDR
attached**. It stacks two scopes — sub-GHz ISM (RTL-SDR, 433/868/915) over the
Wi-Fi bands (HackRF, 2.4/5/6 GHz) — and scrolls a power-over-frequency heatmap
built from modelled emitters (433.92 MHz TPMS/remote bursts, 868 MHz metering,
915 MHz frequency hoppers, Wi-Fi OFDM on ch 1/6/11, BLE advertising spikes).

It exists so the waterfall display can be shown or screenshotted on a unit that
has no radio. It is **not** real capture — every panel is labelled `synthetic`.

## Hidden by default

Nothing in the UI links to it, and the route **404s unless the demo is switched
on**, so it stays out of sight until you deliberately enable it.

- Page: `demos/rf_waterfall.html`
- Route: `GET /demo/rf-waterfall` (login required — not in the auth whitelist)
- Gate: config key `sdr_demo` (default `false`) **or** env `RAGNAR_SDR_DEMO`

## Enable / disable in the background

Persisted (survives restarts), flipped via the config API — no visible switch:

```bash
# enable
curl -X POST http://localhost:8000/api/config \
     -H 'Content-Type: application/json' -d '{"sdr_demo": true}'
# disable
curl -X POST http://localhost:8000/api/config \
     -H 'Content-Type: application/json' -d '{"sdr_demo": false}'
```

Transient (this boot only) — set before the service starts:

```bash
RAGNAR_SDR_DEMO=1
```

Then open `http://<unit>:8000/demo/rf-waterfall`. When disabled the same URL
returns `404 Not Found`.

## Notes

- The page uses Google Fonts with system fallbacks, so it still renders on an
  offline field unit (it just falls back to system fonts).
- Honours `prefers-reduced-motion`: it starts paused and offers a Play control.
