# M5Stack CardputerZero

Ragnar runs on the [M5Stack CardputerZero](https://docs.m5stack.com/en/CardputerZero)
— a pocket-sized Linux computer with a built-in 1.9" LCD and a 46-key keyboard.

> [!IMPORTANT]
> The first units are in users' hands, and their reports shaped this page: the
> screen orientation, the battery reading, the colour screens and the key hints
> below all come from that feedback. The project itself still has no unit to test
> on, so each change is checked against M5Stack's published docs and simulated
> hardware. Report anything that differs; the display, keyboard and backlight
> settings can all be changed without editing code (see below).

---

## TL;DR

- The CardputerZero is a **real Raspberry Pi** (Compute Module Zero, BCM2837), so
  **full Ragnar runs on it unchanged** — web dashboard, HDMI, Ethernet, USB, WiFi.
  It is **not** a cut-down "app" build.
- The only board-specific parts are its two built-in peripherals: the **1.9" LCD**
  and the **46-key keyboard**. Ragnar drives both.
- Install it by choosing **option 7 — "M5Stack CardputerZero"** in `install_ragnar.sh`.
- The screen is in **colour** with the full-colour Viking or shieldmaiden, the
  header shows the **battery percentage**, and **`F` `X` `Z` `C`** page through
  the screens.
- On M5Stack's stock image this **replaces the APPLaunch launcher** on the LCD and
  keyboard. It is reversible; see [Taking over from APPLaunch](#taking-over-from-applaunch).

---

## Is it an ESP32? No.

The *original* M5Stack Cardputer is an ESP32. The **CardputerZero is different** — it
is built around a **Raspberry Pi Compute Module Zero (CM0 / RP3A0 / BCM2837)**:

| | CardputerZero |
|---|---|
| SoC | Raspberry Pi CM0 — RP3A0 (BCM2837), quad-core Cortex-A53 @ 1 GHz, ARMv8-A (aarch64) |
| RAM | 512 MB LPDDR2 |
| Storage | microSD (32 GB bundled on the standard model) |
| Display | 1.9" LCD, **ST7789v3**, 170×320 native (used landscape as **320×170**), SPI |
| Keyboard | 46-key matrix via a **TCA8418** keypad controller (I²C `0x34`, INT on GPIO27) |
| I/O expander | **M5IOE1** (I²C `0x4F`) — drives the LCD reset + backlight, board power/peripheral resets |
| Ethernet | 10/100M via an **SR9900A** USB-to-Ethernet chip |
| Wi-Fi / BT | 2.4 GHz 802.11 b/g/n + Bluetooth |
| Video out | HDMI |
| USB | 1× USB-A, 2× USB-C (right port = OTG); internal GL852G hub |
| Other | 8 MP camera, BMI270+BMM150 IMU, RX8130CE RTC, ES8389 audio, 1750 mAh battery |

Because it is a Pi running a Pi-based Linux from microSD, **everything Ragnar already
does on a Raspberry Pi works here with no special build.**

---

## What "runs on it" means

### Full Ragnar, everywhere it can reach
- **Web dashboard** over Wi-Fi or the USB Ethernet port — this is the primary, full
  interface (all tabs, scanning, config, mesh, etc.).
- **HDMI** output works like any Pi — plug in a monitor for a desktop/console.
- **USB, Wi-Fi, Bluetooth, Ethernet** are all standard Pi peripherals.

Nothing about the core product is gated on the small screen — it is a **complement**,
not the main UI. On the 512 MB CM0, the RAM-gated advanced features (Nuclei/ZAP, 8 GB+
capabilities) stay off, exactly as on any small board; those can be delegated to a
capable mesh peer.

### The built-in 1.9" LCD — the on-device HUD
The LCD is Ragnar's **glanceable status screen + field control surface**, the same
on-device UI family the e-Paper and LCD-HAT builds show — just in full color at
320×170, and it gets the **full stat pages**, not the stripped-down 128×128 layout
reserved for the tiny ST7735S HAT.

It renders all three on-device modes (see [Display Controls](DISPLAY_CONTROLS.md)):

- **Default** — the main screen, then five stat pages (Network, Vuln, Discovered,
  Adv Scanner, Traffic).
- **Wardriving** (engine running) — six screens: band counts (2.4 / 5 / 6 GHz),
  map, GPS, sky view, session and the character.
- **Network Diagnostic** — the on-screen field-tester cards.

#### The main screen

The character fills the right-hand side at twice its usual size, in full colour.
The left column has the header (Wi-Fi strength, last IP octet, unit name, battery),
eight stat counters, the current status and what Ragnar is saying. Counts above 999
are shortened (`1.9k`, `19k`).

Every screen uses a dark colour theme. `lcd_color: false` in
`config/shared_config.json` switches the main screen, stat pages and net-diag cards
back to black-on-white; `wardriving_lcd_color: false` does the same for the
wardriving screens. Colour applies while the screen is in landscape, which is the
only orientation the keyboard offers.

#### Viking or shieldmaiden

The character follows the unit's gender, the same setting the web dashboard uses.
Set `mesh_viking_gender` to `female` for the shieldmaiden or `male` for the Viking
(**Mesh** tab, or `config/shared_config.json`). On a mesh, a unit that carries a
woman's Viking name gets the shieldmaiden without being told.

#### Orientation

The panel is mounted upside down relative to the picture its driver shows, so the
first start on a CardputerZero turns the screen 180°. This is a one-time default:
a unit already turned by hand is left as it is, and a later choice is kept.
**Backspace** flips the screen between its two landscape positions and saves the
choice. **Config → Display** can set any rotation.

### The battery

The CardputerZero has a 1750 mAh cell and a **BQ27220** fuel gauge. Ragnar reads it
and shows the percentage in the header of the main screen (with a `+` while
charging) and in the **System** tab's Battery card. Nothing needs installing or
configuring, and the installer does not ask about a PiSugar on this board.

| Source | When |
|---|---|
| `/sys/class/power_supply/*` (type `Battery`) | M5Stack's image, whose kernel loads the gauge driver. Preferred. |
| The gauge itself, I²C `0x55` on bus 1 | A kernel without that driver. Read-only. |

Check it from a shell:

```bash
python3 sysfs_battery.py          # BQ27220 fuel gauge: 76% (3.91 V, on battery)
python3 sysfs_battery.py --i2c    # also try the gauge directly over I2C
cat /sys/class/power_supply/*/capacity
```

`builtin_battery_monitor: false` turns the reading off. A PiSugar or Waveshare UPS
HAT, if one is ever attached and answering, takes precedence. The I²C path is
written from the gauge's datasheet and has not been confirmed on a unit.

### The 46-key keyboard — replaces the HAT buttons/joystick
The keyboard is mapped onto the **same logical controls** the LCD-HAT joystick and
keys use (`cardputer_input.py` subclasses the LCD-HAT input layer), so every on-device
control Ragnar already has works from the keys:

`F` `X` `Z` `C` are the keys with the arrow legends. They work as arrows on their
own, as M5Stack's key guide recommends, and with **fn** held.

| Key(s) | Ragnar screens | Wardriving screens | Network Diagnostic |
|---|---|---|---|
| `F` / `Z` (up / left) | previous page | previous screen | `Z` previous card, `F` previous function |
| `X` / `C` (down / right) | next page | next screen | `C` next card, `X` next function |
| Enter (OK) | start / stop page autoscroll | back to the first screen | run the highlighted function |
| Space | Network Diagnostic on | back to the Ragnar screens | Network Diagnostic off |
| Backspace | flip the screen 180° | reconnect to a known Wi-Fi | card list |
| Tab or Esc | next page (hold: restart Ragnar) | phone-access AP on / off | auto-switch cards on / off |

The footer of each screen names the keys that apply there, for example
`F/X/Z/C:Page  OK:Auto  Space:NetDiag  Bksp:Flip`.

These are the 1.44" LCD HAT's controls on a keyboard; see
[Display Controls](DISPLAY_CONTROLS.md) for what each mode does.

---

## Installing

Run the installer and pick **option 7**:

```
   * 1) Raspberry Pi with e-Paper display
   * 2) Raspberry Pi with TFT LCD display
   * 3) Server install with display
   * 4) Server install (headless, no display)
   * 5) WiFi Pineapple Pager (beta)
   * 6) Docker container (headless web UI)
   * 7) M5Stack CardputerZero (built-in LCD + keyboard)
```

Option 7 runs a normal Raspberry Pi install, **pinned** to the board's built-in
display driver (`st7789v2`, 320×170 landscape) and its keyboard. It skips the panel
picker and takes the LCD and keyboard over from the stock launcher. For an unattended
install use `RAGNAR_PROFILE=cardputer`.

> The display driver key is `st7789v2` for historical reasons — V2 and V3 share the
> register set this driver uses; only the on-screen labels say "V3".

The display choice is written to `config/shared_config.json`, which is gitignored and
survives `update_ragnar.sh`. Picking the CardputerZero under **Config → Display** or
with `installhead.sh st7789v2` sets up the same things, and the updater re-applies them.

### Taking over from APPLaunch

M5Stack's image runs **APPLaunch**, which draws on the LCD and grabs the keyboard
exclusively, so nothing else can use them while it runs. Stopping it is not enough
either: the image's `fb_load` bridge only refreshes the LCD while a process running the
APPLaunch binary exists. `scripts/cardputer_takeover.sh` therefore:

- moves the binary to `…/M5CardputerZero-APPLaunch.real` and runs `sleep infinity` under
  its name, so `fb_load` keeps refreshing the LCD;
- takes the kernel console off the LCD: backs up `cmdline.txt`, removes `console=tty1`,
  adds `fbcon=map:99`, and disables `getty@tty1`. **Reboot** for this to take effect.

It makes no changes on any other board. To get the stock launcher back:

```bash
sudo scripts/cardputer_takeover.sh revert    # then reboot
sudo scripts/cardputer_takeover.sh status    # shows the current state
```

On 512 MB, also consider `sudo systemctl disable --now lightdm` if your image runs a
desktop; Ragnar does not change this for you.

---

## The display in depth

The driver (`resources/waveshare_epd/st7789v2.py`) exposes the standard Waveshare
EPD-style interface, so it plugs into Ragnar's display stack transparently. It tries
two transports, in order:

### 1. Linux framebuffer (preferred)
The stock image binds the panel to a kernel driver and exposes it as `/dev/fb0` or
`/dev/fb1`, depending on the image. Ragnar finds it by its driver name in
`/sys/class/graphics/fb*/name` (`st7789v_m5st` or `panel-mipi-dbi`), unblanks it, turns
the backlight on if it is off, and writes native-endian RGB565 frames.

Without a matching name, Ragnar **only adopts a framebuffer whose resolution matches
the 1.9" LCD** (320×170 or 170×320), so it can never paint over an HDMI console. To
force a node:

```bash
RAGNAR_CARDPUTER_FB=/dev/fbN
```

### 2. Native SPI (fallback)
For a plain kernel with no panel driver, Ragnar drives the ST7789 directly over SPI
(MOSI=GPIO10, SCLK=GPIO11, CS=GPIO8/CE0, DC=GPIO25, TE=GPIO5). This path only runs when
the board's M5IOE1 expander answers, because SPI has no read-back and would otherwise
"find" this panel on any Pi. `RAGNAR_CARDPUTER_SPI=1` skips that check. Its MADCTL and
offsets are the standard 170-wide ST7789 values and have not been confirmed on this board.

A CardputerZero whose LCD fails to start keeps its panel setting: because the LCD is
built in, Ragnar skips the usual auto-detect fallback, stays reachable over the web UI,
and tries again on its next start.

---

## M5IOE1 expander — LCD reset & backlight

On the framebuffer path the kernel owns the expander and the backlight, which appears at
`/sys/class/backlight/*/brightness` (0–255). `m5ioe1.py` is only used on the SPI path:

| Function | M5IOE1 pin | Detail |
|---|---|---|
| I²C address | — | `0x4F` on I²C bus 1 (SDA=GPIO2, SCL=GPIO3) |
| LCD reset | **IO12** (`PYG12_LCD_RST`) | GPIO, active-low; pulsed high→low→high before init |
| LCD backlight | **IO10 → PWM4** (`PYG10_BL_PWM`) | PWM, duty = brightness |

> The generic M5IOE1 chip manual lists `0x6F–0x76` as the part's configurable address
> range, but on the CardputerZero this unit is pinned at **`0x4F`**. Use `0x4F`.

Read/modify/write is used on the expander's GPIO registers so Ragnar never clobbers the
other pins on the same registers (which hold board power and peripheral-reset state).

### Environment overrides
If a board revision moves a pin, correct it without touching code:

| Variable | Default | Meaning |
|---|---|---|
| `RAGNAR_M5IOE1_ADDR` | `0x4F` | Expander I²C address |
| `RAGNAR_M5IOE1_BUS` | `1` | I²C bus number |
| `RAGNAR_M5IOE1_BL_PWM` | `4` | Backlight PWM channel (1–4) |
| `RAGNAR_M5IOE1_RST_IO` | `12` | LCD reset expander IO (1–14) |
| `RAGNAR_M5IOE1_BL_DUTY` | `0xFFF` | Backlight brightness (12-bit, 0–0xFFF) |
| `RAGNAR_M5IOE1_PWM_HZ` | `500` | PWM frequency (Hz) |

---

## Keyboard calibration

On the stock image the kernel owns the keyboard, which appears as
`/dev/input/by-path/platform-3f804000.i2c-event`, and Ragnar reads standard Linux key
codes from it with no extra dependency. `RAGNAR_CARDPUTER_KBD=/dev/input/eventN` forces
a device. On a plain kernel without that driver, Ragnar talks to the TCA8418 over I²C
(`0x34`) instead; matrix positions are unpublished, so that default map is a best guess.

Either map can be changed **without editing code**:

Ragnar finds the keyboard by its fixed path, then by an input device whose name
contains `tca8418`, `cardputer` or `m5stack`, then by any `platform-*.i2c-event`
node.

1. Watch the log. Every **unmapped** key press logs its code:
   ```
   CardputerZero keyboard: unmapped key code 30 (add to config/cardputer_keymap.json to use it)
   ```
2. Put the codes you want into `config/cardputer_keymap.json` as `{"<code>": "<action>"}`:
   ```json
   { "30": "press", "31": "key2" }
   ```
   Valid actions: `up`, `down`, `left`, `right`, `press`, `key1`, `key2`, `key3`.

The file is read at startup and **overrides** individual defaults. Unlike the LCD-HAT
joystick (mounted 90° off), the keyboard arrows already point the way you read them, so
no direction remap is applied.

---

## Troubleshooting

| Symptom | Try |
|---|---|
| **Stock launcher still on screen / LCD frozen** | Run `sudo scripts/cardputer_takeover.sh status`, then `apply` if needed. |
| **Text console draws over Ragnar** | Reboot after the takeover; the `cmdline.txt` change only applies at boot. |
| **Screen is upside down** | Press **Backspace** on a Ragnar screen, or set the rotation under **Config → Display**. |
| **No battery percentage** | Run `python3 sysfs_battery.py`. If it finds nothing, check `ls /sys/class/power_supply/`; an empty list means the kernel has no gauge driver, so try `python3 sysfs_battery.py --i2c`. |
| **Arrow keys do nothing** | Look for `CardputerZero keyboard: reading /dev/input/...` in the log. If it is missing, see "Keys do nothing" below. |
| **Screen stays black** | Check `cat /sys/class/graphics/fb*/name` and `cat /sys/class/backlight/*/brightness`. On the SPI path, confirm the expander answers at `0x4F` (`i2cdetect -y 1`). |
| **Ragnar painted over the HDMI console** | Shouldn't happen, but if forced, unset `RAGNAR_CARDPUTER_FB` or point it at the correct LCD `/dev/fbN`. |
| **Image mirrored / rotated wrong (SPI path only)** | Try the alternate MADCTL values noted in `st7789v2.py`. |
| **Keys do nothing** | Check nothing else holds the keyboard: `sudo fuser /dev/input/by-path/*i2c-event`. A grabbed device delivers no events. |
| **Wrong action on a key** | Remap it (above). The log shows `unmapped key code N` for unmapped keys. |

---

## Files involved

| File | Role |
|---|---|
| `resources/waveshare_epd/st7789v2.py` | LCD driver — kernel framebuffer first, SPI fallback |
| `m5ioe1.py` | M5IOE1 expander driver — LCD reset + backlight (SPI path) |
| `scripts/cardputer_takeover.sh` | Hands the LCD and keyboard from APPLaunch to Ragnar, and back |
| `cardputer_input.py` | Keyboard listener — kernel input device first, TCA8418 I²C fallback (reuses the LCD-HAT input layer) |
| `sysfs_battery.py` | Battery percentage — kernel power-supply class first, BQ27220 over I²C as fallback |
| `config/cardputer_keymap.json` | Optional per-board keymap override |
| `install_ragnar.sh` / `update_ragnar.sh` | Install option 7 + dependency parity |
| `shared.py`, `epd_helper.py`, `display.py`, `web/scripts/ragnar_modern.js` | Display profile + selector wiring |

---

## Status

Running on users' units: install, display and web UI are confirmed by their reports.
The project has no unit of its own, so changes are covered by
`tests/test_cardputer_zero.py` and `tests/test_sysfs_battery.py` against simulated
hardware and by rendering the real screens at 320×170. Not yet confirmed on a unit:
the battery reading, the colour screens, the SPI fallback's rotation and offsets, and
the direct-I²C paths for the keyboard and the fuel gauge.
