# M5Stack CardputerZero

Ragnar runs on the [M5Stack CardputerZero](https://docs.m5stack.com/en/CardputerZero)
— a pocket-sized Linux computer with a built-in 1.9" LCD and a 46-key keyboard.

> [!IMPORTANT]
> CardputerZero support follows M5Stack's published pin map and developer docs and
> is tested against simulated hardware, but it has **not been run on a physical
> unit yet**. Report anything that differs; the display, keyboard and backlight
> settings can all be changed without editing code (see below).

---

## TL;DR

- The CardputerZero is a **real Raspberry Pi** (Compute Module Zero, BCM2837), so
  **full Ragnar runs on it unchanged** — web dashboard, HDMI, Ethernet, USB, WiFi.
  It is **not** a cut-down "app" build.
- The only board-specific parts are its two built-in peripherals: the **1.9" LCD**
  and the **46-key keyboard**. Ragnar drives both.
- Install it by choosing **option 7 — "M5Stack CardputerZero"** in `install_ragnar.sh`.
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
| `F` `X` `Z` `C`, or the Fn arrows | up / down / left / right — cycle pages, steer the wardriving carousel |
| Enter | press / select |
| Space | **KEY1** — mode toggle (net-diag on/off, leave the wardriving screens) |
| Backspace | **KEY2** — rotate screen / reconnect Wi-Fi |
| Tab or Esc | **KEY3** — next page (hold: restart Ragnar) / toggle phone AP |

See [Display Controls](DISPLAY_CONTROLS.md) for the exact per-mode key actions.

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
| `config/cardputer_keymap.json` | Optional per-board keymap override |
| `install_ragnar.sh` / `update_ragnar.sh` | Install option 7 + dependency parity |
| `shared.py`, `epd_helper.py`, `display.py`, `web/scripts/ragnar_modern.js` | Display profile + selector wiring |

---

## Status

Follows M5Stack's published pin map and developer docs, and is covered by
`tests/test_cardputer_zero.py` against simulated hardware. **Not yet run on a physical
unit.** The likeliest things to need attention are the launcher takeover, which depends
on how a given M5Stack image is built, and the SPI fallback's rotation and offsets.
