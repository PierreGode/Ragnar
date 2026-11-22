# Cooling Fan: Status & Control

The **System** tab shows the Raspberry Pi's cooling fan and lets you control it.
It appears only when a fan driver exists: always on a Pi 5, and on a Pi 4 or
other board only with `dtoverlay=gpio-fan`.

- **UI:** a **Fan** stat card (RPM, duty, auto/manual) and a **Cooling fan**
  panel under the power panels.
- **Backend:** [`fan_tools.py`](../fan_tools.py) (stdlib only, reads sysfs
  directly; `sudo python3 fan_tools.py` prints the status as JSON)
- **Endpoints:**
  - `GET /api/fan`: status
  - `POST /api/fan/mode` with `{"mode": "auto"}` or `{"mode": "manual", "percent": 0-100}`
  - `POST /api/fan/test`: spin test
  - `POST /api/fan/curve` with `{"temps": [50, 60, 67.5, 75], "persist": false}` or `{"reset": true}`

## What it shows

| | Where it comes from |
|---|---|
| **Connected / Not detected / Idle** | Tachometer (see below) |
| **Speed (rpm)** | `fan1_input` of the `pwmfan` hwmon |
| **Duty (%)** | `pwm1` (0–255) |
| **Step n / 4** | cooling device `cur_state`: the curve step the kernel chose |
| **SoC temp** | CPU thermal zone |
| **Max rpm** | Fastest speed seen at full duty (spin test or 100 % manual) |
| **Health** | Current rpm at full duty as a % of max rpm; a worn fan slows down |
| **Fan curve** | The zone's `active` trip points, with the speed each one switches to |

### Is a fan connected?

On a Pi 5 the fan driver exists whether or not a fan is plugged in, so the
panel infers presence from the tachometer:

- **Connected:** the fan is turning (rpm > 0).
- **Not detected:** the fan is commanded on but reads 0 rpm, so nothing is on the
  header or the fan has stalled.
- **Idle:** below the first trip (50 °C by default), the fan is off and nothing
  can be measured. Press **Spin test**: it runs the fan at 100 % for about 3.5 s,
  reads the rpm and restores the previous state. The result is used for the next
  10 minutes.

A `gpio-fan` (Pi 4) has no tachometer, so it only shows the on/off state. A
2-wire fan wired straight to the 5 V pins can't be seen by software at all.

## Control

**Automatic** (default): the kernel's step_wise governor moves the fan through
5 steps (off / 30 / 50 / 70 / 100 % on a Pi 5) as the SoC temperature crosses the
curve's trip points.

**Manual**: pick a speed and press **Manual**. Ragnar sets the CPU thermal zone
to `mode=disabled` so the governor stops overriding it, then writes the duty.
Once in manual mode, moving the slider applies the new speed right away.
Safety:

- A watchdog returns the fan to automatic control and **full speed** if the SoC
  reaches **75 °C**. The panel shows when this happened. The firmware also
  throttles the CPU at 85 °C no matter what.
- Setting a speed below 100 % is refused while the SoC is already at 75 °C.
- Manual mode is **runtime only**. A reboot restores automatic control, and so
  does restarting Ragnar after a crash (a marker in `/run` records that Ragnar
  owns the zone).
- On the way back to automatic, the fan is set to the step the curve calls for
  at the current temperature. step_wise only changes steps when a trip point is
  crossed, so without this a fan left at 100 % in a cool room would stay there.

## Fan curve

On a Pi 5 the four trip temperatures can be changed at runtime (30–85 °C, each
step warmer than the one before). The step speeds are fixed by the device tree.
Tick **Keep after reboot** to also write them to `config.txt`:

```
[all]
# Ragnar: fan curve (System tab)
dtparam=fan_temp0=45000
dtparam=fan_temp0_hyst=5000
...
```

A timestamped backup (`config.txt.ragnar-YYYYmmdd-HHMMSS`) is made first. Only
the `dtparam=fan_tempN` lines are replaced, so saving again doesn't pile up lines.
**Defaults** restores the Pi 5 firmware curve (50 / 60 / 67.5 / 75 °C,
5 °C hysteresis) and removes the saved lines.

Pi 5 defaults for reference:

| Step | Switches on at | Off again below | Fan |
|---|---|---|---|
| 1 | 50 °C | 45 °C | 30 % |
| 2 | 60 °C | 55 °C | 50 % |
| 3 | 67.5 °C | 62.5 °C | 70 % |
| 4 | 75 °C | 70 °C | 100 % |

See also: [Power](power.md) (supply, throttling, power test).
