# Waveshare UPS HAT battery monitor

Ragnar shows the battery percentage of a Waveshare INA219-based UPS HAT on the
display header and on the web dashboard. Nothing needs to be installed and
there is no background service: Ragnar reads the HAT itself.

## Supported boards

| Board | I2C address | Battery |
|---|---|---|
| **UPS HAT (C)** (Pi Zero / Zero 2 W, pogo pins) | `0x43` | one 3.7 V Li-po cell |
| UPS HAT / UPS HAT (B) | `0x42` | two 18650 cells in series |

The UPS HAT (C) is the board this was built for. The two-cell boards use the
same chip and the same formula scaled to two cells, but have not been tested on
hardware.

A PiSugar keeps working as before. If both a PiSugar and a UPS HAT answer, the
PiSugar reading is shown.

## Setup

1. Fit the HAT and its battery, and switch the HAT on.
2. Make sure I2C is enabled. The Ragnar installer does this; on a manual
   install run `sudo raspi-config nonint do_i2c 0` and reboot.
3. Restart Ragnar. The HAT is detected at start.

To check the HAT from a shell:

```bash
cd /home/ragnar/Ragnar && sudo python3 ups_hat.py
# Waveshare UPS HAT (C): 75% (3.90 V, -310 mA, on battery)
```

`i2cdetect -y 1` should list `43` (or `42`).

## Where it shows

- **Display** — the percentage sits in the top-right of the header on the
  e-Paper, LCD HAT and TFT layouts, the same slot the PiSugar uses. A `+`
  after the number (`75%+`) means external power is connected.
- **Web** — **System** tab → **Battery** card: percentage, voltage and
  *Charging* / *On battery*. The card stays hidden when no battery is detected.
- **API** — `battery` in `/api/system/status`:
  `{"level": 75.0, "charging": false, "voltage": 3.9, "model": "Waveshare UPS HAT (C)"}`.

## How the number is worked out

- **Percentage** is Waveshare's own formula from their demo script: linear from
  3.0 V (0 %) to 4.2 V (100 %) per cell, so Ragnar matches what `INA219.py`
  prints. It is a voltage estimate, not a fuel gauge: it dips a little under
  load and rises a little while charging.
- **Smoothing.** The voltage is sampled every 5 seconds and averaged over the
  last 30 seconds so a scan starting does not make the number jump.
- **External power** is read from the direction of the battery current: current
  flowing out of the cell means *On battery*; anything else, including a full
  battery sitting at about 0 mA, means external power.
- **Read-only.** Ragnar never writes to the chip. Before trusting an address it
  checks that the voltage looks like a Li-ion pack (2.4–4.5 V per cell), so
  another I2C device on `0x42`/`0x43`, or a HAT with no battery fitted, does not
  put a bogus percentage on the screen.

## Turning it off

**Config → Display → Waveshare UPS HAT Battery** (`ups_hat_monitor`, on by
default), then restart Ragnar. With no HAT attached the monitor probes the bus a
few times at start and then stays idle, so there is normally no reason to turn
it off.

## Limits

- No automatic shutdown at low battery; the HAT's protection circuit cuts power
  when the cell is empty.
- The current figure printed by `ups_hat.py` uses the 0.01 Ω shunt shown on
  Waveshare's UPS HAT (C) schematic (R9) and used by their demo calibration.
  Their wiki FAQ says 0.1 Ω, which does not match either. Percentage and charge
  state do not depend on the shunt value.
- For UPS Lite v1.2 boards (MAX17040 / CW2015) see [UPS_INTEGRATION.md](UPS_INTEGRATION.md).
