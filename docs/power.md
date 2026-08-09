# Dashboard Power Badge

A small, always-on power-health indicator on the main **Dashboard**, so an
under-voltage board is visible without opening the Wardriving diagnostics panel
or the Mesh tab. Click it for a full breakdown of what is drawing the power.

- **UI:**
  - **Dashboard** — a small badge at the top of the **Current Status** card,
    hidden while the supply is healthy so a healthy board stays quiet. It only
    appears on a real warning; click it for the full breakdown.
  - **System tab** — a **Power** stat card (always shown on a Pi, including when
    healthy) plus a full **Power & Supply** panel with the same breakdown inline,
    since the System tab is the deep view where you expect the detail up front.
- **Backend:** [`power_budget.py`](../power_budget.py)
- **Endpoints:** compact summary rides along on `GET /api/status`
  (`power` key); full detail is `GET /api/power`.

---

## What lights the badge — and what doesn't

The badge's severity comes **only** from the SoC throttle register
(`vcgencmd get_throttled`). That register is the *measured* truth: the Pi
firmware sets the under-voltage bit when the 5 V rail actually sags below spec,
and the throttling / ARM-frequency-capped bits when it has actually reduced the
clock in response. The badge never lights on an estimate or a guess.

| Level | Colour | When |
|-------|--------|------|
| *(hidden)* | — | no under-voltage or throttling recorded since boot |
| **warning** | amber | under-voltage / throttling **occurred since boot** (headroom is gone, but not happening this instant), or a soft-temperature limit was hit |
| **critical** | red | under-voltage or throttling **right now** — the board is being starved as you look |

The compact summary on `/api/status` (`level`, `undervoltage`,
`undervoltage_now`, `throttled_now`, `headline`) is cached ~15 s in
`power_budget.assess()` and never raises, so folding it into the frequently
polled status endpoint stays cheap.

## What the detail modal shows

1. **What it costs.** Plain-language effect of the current state — under-voltage
   caps the ARM clock (the CPU runs *slower*), and a deeper dip browns out and
   resets the whole board with no log line, which is why it looks like an
   unexplained crash.
2. **Supply health (measured).** The throttle flags now / since boot, the raw
   register value, core voltage, temperature, and Pi 5 PMIC board power.
3. **Estimated draw (what's using the power).** A realistic 5 V current for each
   USB device that is actually plugged in, plus the board's own draw, summed
   against the recommended supply with the headroom at peak. When the board
   reports under-voltage **while the estimated budget still shows headroom**, a
   note reconciles the two: that is a **cable/connector voltage drop**, not
   excess current — the 5 V rail sags between the PSU and the board (a thin/long
   micro-USB cable, a tired connector, or a flat 5.0 V supply), so a short thick
   cable and a 5.1 V supply fix it before a bigger PSU would.
4. **Reference configs.** The two named field profiles — *Stationary / recon*
   (Alfa + Ethernet) and *Roaming / wardrive* (Alfa + GPS + ESP32) — costed at
   peak on the detected board.

## Why the draw is an *estimate*, not a measurement

There is no per-port current meter on a Pi, and on a Pi Zero / Pi 3 the
USB/Ethernet HAT is a single USB **hub** — the board only ever sees one
aggregate draw, never which downstream port is pulling it. The USB descriptor's
`bMaxPower` is close to useless for budgeting (a LAN9514 declares 2 mA; an Alfa
declares 500 mA while it can pull ~900 mA on transmit). So `power_budget.py`
**recognises** the devices Ragnar actually uses — USB Wi-Fi (Alfa-class), u-blox
GPS, ESP32 companion, USB Ethernet — and attributes a realistic typical/peak
current to each. Everything on that side is labelled as an estimate, because it
is one. Unrecognised devices fall back to their declared value and are marked as
such.

## Field notes baked into the model

- On a Pi Zero / Pi 3 the Alfa is **not hot-pluggable** — it only enumerates if
  it is connected when power is applied. A config that under-volts often does so
  the moment the radio comes up at boot.
- The real limiter on a Zero / Pi 3 is usually the micro-USB connector and cable
  voltage drop, not the PSU's nameplate rating — a "2.5 A" charger through a
  thin cable can still under-volt with an Alfa attached.
- The fix is usually a **powered USB hub** for the dongles, not a bigger PSU.

## Related

- [Wardriving Diagnostics Panel](diagnostics.md) — the deep read-only Power
  group (same `vcgencmd` source, plus per-radio detail) lives there.
- The **Mesh** tab rolls the same under-voltage flag up across the fleet and
  names the offending units in its health chips.
