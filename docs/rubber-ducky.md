# Rubber Ducky Script Executor

A card on the **Pentest** tab that turns the Pi into a USB keyboard and types a
script into whatever host it is plugged into — the classic "Rubber Ducky"
keystroke-injection workflow, for authorised testing of systems you own or have
explicit permission to test.

> Pentest Mode must be enabled for the tab to appear, and keystroke injection is
> gated by the global `enable_attacks` flag — with attacks off, the execute
> endpoint refuses with `403`.

## How it works

**HID** (Human Interface Device) is the standard USB class for input devices —
keyboards, mice, controllers. A USB keyboard talks to a computer by sending
small 8-byte *reports* ("these keys are held now", plus modifiers like Shift);
press sends one report, release sends zeros. Any OS understands this with no
driver, which is exactly why a keyboard "just works" when plugged in.

This feature makes the **Pi pretend to be that keyboard**. Linux presents the Pi
over USB as a HID keyboard gadget, exposed as the device node `/dev/hidg0`;
anything written to it is delivered to the connected computer as keystrokes.
Ragnar parses your script into key reports and streams them to `/dev/hidg0`, so
the host sees ordinary typing and cannot tell it from a real keyboard.

- **Target:** the device dropdown lists the Pi's own keyboard gadget
  (`/dev/hidg0`). This is deliberately *not* `/dev/hidraw*` — hidraw is a
  peripheral attached **to** the Pi, which cannot inject keystrokes into a host.
- **Direction:** plug the Pi's USB-gadget port into the machine under test; the
  Pi types, the host receives.

## Hardware requirements

To *be* a USB keyboard, the Pi must expose a USB **gadget / OTG** port and be
plugged into the target with a real **data** cable (charge-only cables have no
data lines and do nothing). The big USB-A ports on any Pi are **host** ports and
can never be the keyboard side.

| Board | HID gadget? | Notes |
| --- | --- | --- |
| Pi Zero / Zero W / **Zero 2 W** | ✅ Yes | The reliable platform. Use the **middle "USB"** micro-port (not "PWR"); one cable to the laptop carries data **and** power. |
| Pi 3A+ | ✅ Yes | Single USB port is OTG-capable. |
| Pi 4 / 400 | ✅ Yes | Via the USB-C power port (dwc2). |
| Pi 5 | ⚠️ Finicky | Single USB-C shared with power; gadget mode is awkward. |
| Pi 3B / 3B+ | ❌ No | OTG port is consumed internally by the onboard USB hub + LAN chip; USB-A ports are host-only. |
| Pi 1 / 2 | ❌ No | Same hub reason. |

A **Pi Zero 2 W** is the recommended box for testing and demos.

## Software setup

The HID gadget function (`hid.usb0`) is added to the composite USB gadget by the
installer. On boxes installed before this feature shipped, run the updater — it
patches the gadget script in place (no live network disruption) and the
`/dev/hidg0` node appears after the next reboot. Gadget mode (`dwc2`) must be
enabled, and the gadget only binds — so `/dev/hidg0` only appears — once the
gadget port is physically connected to a host. If no gadget node is present the
device dropdown stays empty and shows a hint explaining how to enable it.

## Script formats

Two formats are auto-detected by file extension:

**Official Ducky syntax** (`.ducky`)

```
DELAY 500
STRING Hello, World!
GUI r
DELAY 200
STRING notepad
ENTER
```

Supported: `DELAY <ms>`, `STRING <text>`, `ENTER`/`SPACE`/`TAB`, any named key,
and a modifier (`CTRL`/`SHIFT`/`ALT`/`GUI`) optionally followed by a key
(e.g. `GUI r`). A `REM` line, or a line beginning with `#`, is a comment; an
inline `#` inside a `STRING` is kept as a literal character.

**Plain text** (`.txt`)

```
type: Hello, World!
wait: 500
press: enter
key: ctrl+c
```

`type:` types a string, `press:` presses one named key, `wait:`/`delay:` pauses
in milliseconds, and `key:` sends a combo like `ctrl+alt+t`.

Typing is Shift-aware on a US layout, so capitals and shifted symbols
(`!`, `?`, `_`, …) are sent correctly.

## Uploading scripts

Scripts live in `files/rubber-ducky/`, which is exposed in the **Files** tab as
its own `rubber-ducky` folder. Upload `.ducky` or `.txt` files there (the folder
ships with one safe demo, `demo_hello.ducky`); they appear in the script
dropdown immediately. Selecting a script
shows a human-readable **preview** of every action before you run it.

## Workflow

1. Enable Pentest Mode (and `enable_attacks`).
2. Plug the Pi into the target host's USB port.
3. Pentest tab → **Rubber Ducky Script Executor**.
4. Pick a script (preview appears), pick the `/dev/hidg0` target, press
   **Execute Script**. The status line reports how many commands ran.

## Testing & validation

The target is a **normal computer** (laptop/desktop) that the Pi types into —
*not* a peripheral. A Flipper Zero, another microcontroller, or anything plugged
*into* the Pi is not a valid target: it isn't a host with a text field receiving
the keystrokes. (A Flipper's own BadUSB, where the Flipper is the keyboard, is a
separate thing Ragnar does not drive.)

To validate end to end:

1. On a gadget-capable Pi (a Zero 2 W is easiest), complete the software setup
   above and reboot.
2. Plug the Pi's gadget port into the computer with a **data** cable.
3. Confirm the computer sees a new keyboard and that Ragnar lists `/dev/hidg0`
   in the device dropdown (otherwise re-check the port, cable, and `dwc2`).
4. Focus a plain text field on that computer (a text editor, a search box).
5. Run the bundled **`demo_hello.ducky`** — it only *types* a couple of lines
   (no commands, no `GUI`/Run shortcuts), so it is a safe way to prove the whole
   path works. You should see its two lines appear in the focused field.

There is no software-only way to observe the keystrokes: injection only shows up
as typing on the physically connected host.

## Files

| Path | Role |
| --- | --- |
| `python/rubber_ducky.py` | Parser, preview, HID gadget writer, device/script enumeration |
| `files/rubber-ducky/` | Script folder (managed from the Files tab) |
| `/api/rubber-ducky/{scripts,devices,preview,execute}` | Backend endpoints |

---

## Related

- [Scanning & Attacks](scanning-and-attacks.md) — the core manual-attack loop
- [AirSnitch](airsnitch.md) — Wi-Fi client-isolation testing on the Pentest tab
