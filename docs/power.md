# Power: Badge, System Tab, USB Limit & Power Test

A small, always-on power-health indicator on the main **Dashboard**, so an
under-voltage board is visible without opening the Wardriving diagnostics panel
or the Mesh tab. Click it for a full breakdown of what is drawing the power.

- **UI:**
  - **Dashboard** — a small badge at the top of the **Current Status** card,
    hidden while the supply is healthy so a healthy board stays quiet. It only
    appears on a real warning; click it for the full breakdown.
  - **System tab** — a **Power** stat card plus a **Power & Supply** panel
    (measured input voltage, board power, temperature, throttle flags, the Pi 5
    USB limit with a one-click fix, USB dropouts and the estimated draw), and a
    **Power test** panel (see below).
- **Backend:** [`power_budget.py`](../power_budget.py) (assessment),
  [`power_tools.py`](../power_tools.py) (Pi 5 USB limit, USB dropouts, power test)
- **Endpoints:** compact summary rides along on `GET /api/status`
  (`power` key); full detail is `GET /api/power`; `POST /api/power/usb-current`
  `{"enable": true|false}`; `GET|POST /api/power/test`
  `{"duration": 40, "loads": ["cpu","sdr","wifi","gps"]}`.

## Pi 5 USB current limit (600 mA → 1.6 A)

The Pi 5 firmware caps the **total** current of all USB ports at **600 mA**
unless it negotiated a **5 V / 5 A** USB-PD supply. Almost no third-party PD
charger or power bank offers 5 A at 5 V (a typical 100 W PD charger gives 5 V /
3 A), so the cap is usually on. A USB Wi-Fi adapter plus an SDR or GPS exceeds
it: the supply voltage stays fine, but the adapter **drops off USB and
re-enumerates every few seconds**. Setting `usb_max_current_enable=1` in
`config.txt` raises the cap to **1.6 A**. It only tells the Pi what it may
draw; it does not make the supply stronger, so use a supply rated ≥ 3 A.

Measured on a Pi 5 with a 5 V / 3 A PD supply, Alfa AWUS036AXML (MT7921U) +
RTL-SDR streaming at 2.4 MS/s:

| | 600 mA (default) | 1.6 A |
|---|---|---|
| Alfa USB disconnects during a 60 s test | 13 (one every ~7 s) | 0 |
| Input voltage min | 5.12 V | 5.15 V |
| Throttle flags | none | none |

**Only the Pi 5 family (Pi 5, Pi 500) has this limit.** Pi 3, Pi 4 and Zero
boards have no firmware USB current cap to raise (the old Pi B+/Pi 2
`max_usb_current` setting is obsolete), so the UI shows nothing for them.

- **Installer / updater:** on a Pi 5, `install_ragnar.sh` and
  `update_ragnar.sh` (Step 6.65) add `usb_max_current_enable=1` under `[all]`
  with a timestamped `config.txt` backup. Any existing setting, including an
  explicit `=0`, is left alone. Opt out with `RAGNAR_USB_MAX_CURRENT=0`.
- **System tab:** *Raise to 1.6 A* / *Revert to 600 mA* writes the setting
  (backup kept, `=0` written explicitly so the updater respects it), then shows
  *Reboot to apply* until the firmware reports the new value.
- The panel reads the live value and the negotiated supply current from the
  device tree (`/proc/device-tree/chosen/power/`), so it shows what is actually
  in effect, not just what `config.txt` says.

## USB dropouts

The panel counts `USB disconnect` events per port in the kernel log since boot.
One disconnect is usually someone unplugging a device. Three or more on the same
port within a minute is marked as a **reconnect loop**: a device losing power.

## Power test

The System tab's **Power test** runs an idle phase, then a load phase (20–120 s
total). It samples the input voltage (Pi 5 PMIC `EXT5V`), board power,
temperature and throttle register every second and counts USB dropouts in each
phase. Loads you can select (greyed out when not present):

- **CPU:** one busy process per core
- **RTL-SDR:** `rtl_sdr` streaming at 2.4 MS/s; reports the achieved rate, or
  says so if another program has the SDR open
- **USB Wi-Fi:** repeated `iw scan` on each USB Wi-Fi adapter; a downed adapter
  is brought up for the test and put back down afterwards
- **USB GPS:** not a load. The receiver is watched through **both** phases via
  Ragnar's own GPS reader (started if it isn't running, so the test never fights
  gpsd or wardriving for the serial port). Per phase it reports seconds with no
  NMEA data, % of time with a fix, satellites used / in view and the best SNR.
  A GPS that goes silent under load is losing power; one whose best SNR drops
  ≥ 4 dB under load while data keeps flowing is being desensed by RF from the
  Wi-Fi adapter or SDR (move it away, e.g. on a USB extension). ESP32
  companions (Espressif USB id) are not offered as a GPS.

The result compares idle and load, gives a verdict (stable, under-voltage, USB
dropouts, GPS silence / signal loss / lost fix, heat) and the next step, e.g. *raise the Pi 5 USB limit* or *use a
powered hub*. One test runs at a time.

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
| **warning** | amber | under-voltage / throttling **occurred since boot** (headroom is gone, but not happening this instant), or a soft-temperature limit was hit. Heat-only flags are labelled *Heat throttled*, not as a supply problem (`cause: thermal`) |
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
4. **Pi 5 extras.** Negotiated supply current, the USB limit and a fix button
   (System tab), and USB dropouts per port. On a Pi 5 the total is compared with
   the *negotiated* supply current rather than the recommended 5 A rating.

## Why the draw is an *estimate*, not a measurement

There is no per-port current meter on a Pi, and on a Pi Zero / Pi 3 the
USB/Ethernet HAT is a single USB **hub** — the board only ever sees one
aggregate draw, never which downstream port is pulling it. The USB descriptor's
`bMaxPower` is close to useless for budgeting (a LAN9514 declares 2 mA; an Alfa
declares 500 mA while it can pull ~900 mA on transmit). So `power_budget.py`
**recognises** the devices Ragnar actually uses — USB Wi-Fi (Alfa-class), u-blox
GPS, ESP32 companion, USB Ethernet, RTL-SDR / HackRF / Airspy — and attributes a realistic typical/peak
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
