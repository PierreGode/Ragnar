# Rubber Ducky Script Executor

A card on the **Pentest** tab that turns the Pi into a USB keyboard and types a
script into whatever host it is plugged into — the classic "Rubber Ducky"
keystroke-injection workflow, for authorised testing of systems you own or have
explicit permission to test.

> Pentest Mode must be enabled for the tab to appear. That is the only gate —
> like the other manual Pentest-tab tools, the Ducky does **not** depend on the
> global `enable_attacks` flag.

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
| Pi 4 / 400 | ✅ Yes | Via the USB-C power port (dwc2). That port carries the data, so **power the Pi from the 5V GPIO pins** to keep USB-C free for the target (see below). |
| Pi 5 | ⚠️ Finicky | Single USB-C shared with power; gadget mode is awkward. Same fix: **power via the 5V GPIO pins**, USB-C to the target. |
| Pi 3B / 3B+ | ❌ No | OTG port is consumed internally by the onboard USB hub + LAN chip; USB-A ports are host-only. |
| Pi 1 / 2 | ❌ No | Same hub reason. |

A **Pi Zero 2 W** is the recommended box for testing and demos.

### Powering via the GPIO pins (Pi 4 / Pi 5)

On the Pi 4 and Pi 5, the **only** gadget-capable port is the USB-C port — which
is also the power input. If you plug USB-C into the target for the HID data link,
you can no longer power the Pi from USB-C, and relying on the data cable to also
power the Pi is unreliable. Power the Pi from the **5V GPIO header** instead:

- **Pin 2 or Pin 4** → +5V
- **Pin 6** (or any GND pin) → GND

Then USB-C goes to the target and the Pi stays powered independently. A Pi Zero /
Zero 2 W does **not** need this — it has a dedicated **PWR** micro-port separate
from the data **USB** port.

> ⚠️ The GPIO 5V rail is **unfused** and bypasses the board's input protection.
> Feed it clean, current-limited 5V (a solid 5V/3A+ supply), and never power from
> both the GPIO pins and USB-C at the same time.

## Software setup

The HID gadget is **opt-in** — it is off by default so the plain ECM gadget, and
boards such as the Cardputer (Pi CM0), are left untouched.

**Permanent (installer/updater):** run either with `RAGNAR_HID_GADGET=1`, e.g.
`sudo RAGNAR_HID_GADGET=1 bash update_ragnar.sh`. That writes the marker
`/etc/ragnar/hid_gadget.enabled` (so later updates keep it) and applies three
things: the `dwc2,dr_mode=peripheral` overlay in `config.txt` (creates the USB
device controller), removal of the legacy `g_ether` from `cmdline.txt` plus a
blacklist (it otherwise claims the controller and blocks the gadget), and the
`hid.usb0` function in the gadget script. **A reboot is required** for the boot
config to take effect; the gadget then binds — and `/dev/hidg0` appears — once
the gadget port is connected to a host.

**On-demand (web UI):** the card has an **Enable / Disable** control that brings
`/dev/hidg0` up or down live (via `scripts/hid_gadget.sh`), without a reboot —
provided the USB device controller already exists (i.e. the overlay above is in
place). Use this to toggle the keyboard off when you are not testing. If no
controller is present, the control says so and points you at the installer
option. This is runtime only; persistence across reboots is the installer flag.

If no gadget node is present, the device dropdown stays empty and shows a hint
explaining how to enable it.

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
and one or more modifiers (`CTRL`/`SHIFT`/`ALT`/`GUI`) optionally followed by a
key — `GUI r`, `CTRL ALT t`, `CTRL ALT DELETE`. A `REM` line, or a line
beginning with `#`, is a comment; an inline `#` inside a `STRING` is kept as a
literal character.

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
its own `rubber-ducky` folder. Browse into it and use **⬆ Upload here** to add
`.ducky` or `.txt` files (the folder ships with one safe demo,
`demo_hello.ducky`); they appear in the script dropdown immediately. The card's
own **Upload** button (next to the script picker) does the same thing without
leaving the Pentest tab. `.ducky` files open as editable text in the Files tab
(like `.txt`/`.json`), so you can tweak a script in place. Selecting a script
shows a human-readable **preview** of every action before you run it.

## Payload library & inline editor

The card has two helpers under the status line:

- **Payload library** — one combined list of ready-made payloads from two
  sources, each row tagged so you can tell them apart:
  - **bundled** — shipped in the repo (`resources/ducky_payloads/`): host recon
    for Windows/Linux/macOS, a Windows saved-Wi-Fi-profile dump, and a Windows
    reverse-shell template.
  - **RagnarScripts** — the shared [RagnarScripts](ragnarscripts.md) library
    (`rubber-ducky/`), shown here automatically once the repo is present (Ragnar
    [auto-clones/pulls](ragnarscripts.md#auto-sync) it). A RagnarScripts payload
    already copied locally shows **Reinstall**.

  **Install** copies the chosen payload into `files/rubber-ducky/` to run or
  edit; your own scripts there are never touched.
- **Editor** — write a script inline: **New** clears it, **Edit selected**
  loads the chosen script, **Save Script** writes it to `files/rubber-ducky/`
  (name must end in `.ducky`/`.txt`) and selects it. Pairs with the
  [Reverse Shell](reverse-shell.md) card — generate a one-liner, paste it into a
  payload, save, run.

## Workflow

1. Enable Pentest Mode.
2. Plug the Pi into the target host's USB port.
3. Pentest tab → **Rubber Ducky Script Executor**.
4. Pick a script (preview appears), pick the `/dev/hidg0` target, press
   **Execute Script**. The status line reports how many commands ran.

## Driving another unit over the mesh

When a Ragnar is plugged into a host PC over USB-OTG, that port is both its power
and its data link to the target — so it can't also use wired Ethernet, and it
runs on **Wi-Fi**. That's enough for a *second* Ragnar on the LAN/mesh to drive
its HID: you operate from your own unit and the keystrokes come out of the one
cabled to the host. Same model as the [Device Console](serial-console.md) across
the mesh.

- **Run on** — the picker at the top of the card. `This unit` is the default;
  pick a mesh peer to target its `/dev/hidg0`. The list shows each peer's state
  (`HID, mesh-allowed`, `HID (not allowed)`, `no HID`, offline/unreachable).
  Script list, device list, preview and **Execute** then all act on that unit.
- **Allow mesh units to run payloads on this unit** — the checkbox. Off by
  default: a unit will not let the mesh touch its keyboard until its own operator
  ticks this. Set it on the unit that's **cabled to the host** (reach its
  dashboard over Wi-Fi, or tick it before you plug it in).
- **Mesh secret** — cross-unit control rides the same secret-gated gateway as
  the rest of hub mode, so the [mesh secret](mesh.md) must be armed on **both**
  units (Config → Mesh). Tag membership alone is not enough. Without it the card
  tells you what's missing.

So the two gates are independent: the **secret** proves the request came from
your mesh (transport), and the **checkbox** is the target unit's explicit opt-in
(per-unit). A relayed **Execute**, gadget enable/disable, save or install is
refused unless the target has ticked the box.

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
| `python/rubber_ducky.py` | Parser, preview, HID gadget writer, device/script enumeration, library + save |
| `files/rubber-ducky/` | Script folder (managed from the Files tab) |
| `resources/ducky_payloads/` | Bundled, read-only payload library |
| `scripts/hid_gadget.sh` | On-demand gadget control (`status`/`up`/`down`) |
| `/api/rubber-ducky/{scripts,devices,preview,execute}` | Script endpoints |
| `/api/rubber-ducky/{library,library/install,save}` | Payload library + inline-editor endpoints |
| `/api/rubber-ducky/gadget/{status,enable,disable}` | On-demand gadget control endpoints |
| `/etc/ragnar/hid_gadget.enabled` | Opt-in marker (persists the gadget across updates) |

---

## Related

- [Scanning & Attacks](scanning-and-attacks.md) — the core manual-attack loop
- [AirSnitch](airsnitch.md) — Wi-Fi client-isolation testing on the Pentest tab
