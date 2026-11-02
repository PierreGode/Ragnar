# M5Stack CardputerZero

Ragnar runs on the [M5Stack CardputerZero](https://docs.m5stack.com/en/CardputerZero)
— a pocket-sized Linux computer with a built-in 1.9" LCD and a 46-key keyboard.

> [!IMPORTANT]
> CardputerZero support is **new and not yet validated on physical hardware**. The
> display rotation/offsets, the keyboard map, and the M5IOE1 backlight/reset
> mapping may need a one-time on-device tuning pass (all covered below, all doable
> without editing code).

---

## TL;DR

- The CardputerZero is a **real Raspberry Pi** (Compute Module Zero, BCM2837), so
  **full Ragnar runs on it unchanged** — web dashboard, HDMI, Ethernet, USB, WiFi.
  It is **not** a cut-down "app" build.
- The only board-specific parts are its two built-in peripherals: the **1.9" LCD**
  and the **46-key keyboard**. Ragnar drives both.
- Install it by choosing **option 6 — "M5Stack CardputerZero"** in `install_ragnar.sh`.

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
320×170. At that size it counts as a **"wide" display**, so it gets the **full stat
pages**, not the stripped-down 128×128 layout reserved for the tiny ST7735S HAT.

It renders all three on-device modes (see [Display Controls](DISPLAY_CONTROLS.md)):

- **Default** — the Ragnar character/status frame and a carousel of stat pages
  (host/target counts, vulnerability count, Wi-Fi/BT/PAN/USB connectivity, service
  status, …).
- **Wardriving** (engine running) — live **2.4 / 5 / 6 GHz** network counts as large
  numbers, **GPS fix**, **speed**, companion status, and a live GPS/network map,
  across a 5-screen carousel.
- **Network Diagnostic** — the on-screen field-tester cards.

### The 46-key keyboard — replaces the HAT buttons/joystick
The keyboard is mapped onto the **same logical controls** the LCD-HAT joystick and
keys use (`cardputer_input.py` subclasses the LCD-HAT input layer), so every on-device
control Ragnar already has works from the keys:

| Key(s) | Logical action |
|---|---|
| Arrow keys | navigate / cycle pages (and steer the wardriving carousel) |
| Enter | press / select |
| Three edge keys | stand in for **KEY1 / KEY2 / KEY3** — Pwnagotchi swap, rotate/flip screen, next-page / restart, toggle phone AP, etc. (mode-dependent) |

See [Display Controls](DISPLAY_CONTROLS.md) for the exact per-mode key actions.

---

## Installing

Run the installer and pick **option 6**:

```
   * 1) Raspberry Pi with e-Paper display
   * 2) Raspberry Pi with TFT LCD display
   * 3) Server install with display
   * 4) Server install (headless, no display)
   * 5) WiFi Pineapple Pager (beta)
   * 6) M5Stack CardputerZero (built-in LCD + keyboard)
```

Option 6 runs a normal Raspberry Pi install, **pinned** to the board's built-in
display driver (`st7789v2`, 320×170 landscape) and its keyboard. It skips the panel
picker and installs the SPI/I²C Python deps (`spidev`, `smbus2`). SPI and I²C are
enabled by the installer's common display step.

> The display driver key is `st7789v2` for historical reasons — V2 and V3 share the
> register set this driver uses; only the on-screen labels say "V3".

The display choice is written to `config/shared_config.json`, which is gitignored and
survives `update_ragnar.sh`. Update-only boxes on a CardputerZero profile get the
`spidev` + `smbus2` deps re-ensured automatically (installer fix mirrored into the
updater).

---

## The display in depth

The driver (`resources/waveshare_epd/st7789v2.py`) exposes the standard Waveshare
EPD-style interface, so it plugs into Ragnar's display stack transparently. It tries
two transports, in order:

### 1. Linux framebuffer (preferred)
M5Stack ships the CardputerZero as a pocket Linux computer, so its image usually
drives the LCD as a framebuffer device. When one is present, Ragnar blits RGB565
frames straight to it. This is the most reliable path and needs no extra wiring.

Auto-detection **only adopts a framebuffer whose resolution matches the 1.9" LCD**
(320×170 or 170×320), so it can never paint over an HDMI console framebuffer. If your
LCD framebuffer reports an unexpected size or node, force it:

```bash
RAGNAR_CARDPUTER_FB=/dev/fbN
```

### 2. Native SPI (fallback)
If no matching framebuffer exists, Ragnar drives the ST7789 directly over SPI
(MOSI=GPIO10, SCLK=GPIO11, CS=GPIO25, DC=GPIO8, TE=GPIO5). Because DC sits on SPI0's
hardware CE0 (GPIO8), chip-select is asserted manually on GPIO25.

The LCD **reset** and **backlight** are not on Pi GPIOs — they hang off the M5IOE1
I²C expander (see next section). On the SPI path Ragnar does a real hardware reset and
turns the backlight on through the expander; if the expander does not answer, it falls
back to a software reset and relies on the power-on backlight default.

---

## M5IOE1 expander — LCD reset & backlight

The built-in LCD's reset and backlight lines are behind M5Stack's **M5IOE1** I/O
expander. Ragnar controls them via `m5ioe1.py`, using the board's schematic mapping:

| Function | M5IOE1 pin | Detail |
|---|---|---|
| I²C address | — | `0x4F` on I²C bus 1 (SDA=GPIO2, SCL=GPIO3) |
| LCD reset | **IO12** (`PYG12_LCD_RST`) | GPIO, active-low; pulsed high→low→high before init |
| LCD backlight | **IO10 → PWM4** (`PYG10_BL_PWM`) | PWM, duty = brightness |

> The generic M5IOE1 chip manual lists `0x6F–0x76` as the part's configurable address
> range, but on the CardputerZero this unit is pinned at **`0x4F`**. Use `0x4F`.

The expander is probed at startup; if it does not ACK, every reset/backlight call is a
harmless no-op and the display falls back to its software path — so this can never make
the screen *worse* than before.

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

The keyboard is a matrix behind the **TCA8418** controller (I²C `0x34`). The controller
reports a raw key number per key; M5Stack has **not published** which physical key sits
at which matrix position for the CardputerZero, so Ragnar's default key map is a
**best guess** and is calibratable **without editing code**:

1. Boot Ragnar and watch the log. Every **unmapped** key press logs its raw code:
   ```
   CardputerZero keyboard: unmapped key code 37 (add to config/cardputer_keymap.json to use it)
   ```
2. Press each key you want to use and note its code.
3. Put the codes you want into `config/cardputer_keymap.json` as
   `{"<code>": "<action>"}`:
   ```json
   {
     "31": "up", "41": "down", "40": "left", "42": "right", "43": "press",
     "1": "key1", "11": "key2", "30": "key3"
   }
   ```
   Valid actions: `up`, `down`, `left`, `right`, `press`, `key1`, `key2`, `key3`.

The file is read at startup and **overrides** the defaults — no reinstall, no code
change. Unlike the LCD-HAT joystick (mounted 90° off), the keyboard arrows already
point the way you read them, so no direction remap is applied.

---

## Troubleshooting

| Symptom | Try |
|---|---|
| **Screen stays black** | If on the SPI path, the backlight relies on the M5IOE1 expander — confirm it answers at `0x4F` (`i2cdetect -y 1`). Prefer the framebuffer path, or raise `RAGNAR_M5IOE1_BL_DUTY`. |
| **Ragnar painted over the HDMI console** | Shouldn't happen (the fb guard rejects non-LCD sizes), but if forced, unset `RAGNAR_CARDPUTER_FB` or point it at the correct LCD `/dev/fbN`. |
| **Image mirrored / rotated wrong** | The SPI init uses a fixed MADCTL for landscape; on-hardware this may need adjusting (try the alternate MADCTL values noted in `st7789v2.py`). |
| **Keys do nothing / wrong action** | Calibrate the keymap (above). Check the log for `unmapped key code N`. Confirm the TCA8418 answers at `0x34` (`i2cdetect -y 1`). |
| **No LCD/keyboard after an update** | Ensure `spidev` + `smbus2` import (`python3 -c "import spidev, smbus2"`); the updater re-ensures them for CardputerZero profiles, but a failed pip leaves them missing. |

---

## Files involved

| File | Role |
|---|---|
| `resources/waveshare_epd/st7789v2.py` | LCD driver — framebuffer-preferred, SPI fallback |
| `m5ioe1.py` | M5IOE1 expander driver — LCD reset + backlight |
| `cardputer_input.py` | TCA8418 keyboard listener (reuses the LCD-HAT input layer) |
| `config/cardputer_keymap.json` | Optional per-board keymap override |
| `install_ragnar.sh` / `update_ragnar.sh` | Install option 6 + dependency parity |
| `shared.py`, `epd_helper.py`, `display.py`, `web/scripts/ragnar_modern.js` | Display profile + selector wiring |

---

## Status

Implemented on branch `M5StackCardputerZero`. **Not yet validated on physical
hardware** — expect a one-time tuning pass for the display rotation/offsets, the
keyboard map, and (if needed) the M5IOE1 backlight polarity/brightness. Every one of
those is adjustable from config or environment variables without code changes.
