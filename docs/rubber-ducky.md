# Rubber Ducky Script Executor

A card on the **Pentest** tab that turns the Pi into a USB keyboard and types a
script into whatever host it is plugged into — the classic "Rubber Ducky"
keystroke-injection workflow, for authorised testing of systems you own or have
explicit permission to test.

> Pentest Mode must be enabled for the tab to appear, and keystroke injection is
> gated by the global `enable_attacks` flag — with attacks off, the execute
> endpoint refuses with `403`.

## How it works

The Pi presents itself to the connected host as a standard USB HID keyboard
(a composite gadget that also carries the ECM Ethernet link). Scripts are parsed
into a sequence of key reports and streamed to the gadget node `/dev/hidg0`,
which the host sees as ordinary typing.

- **Target:** the device dropdown lists the Pi's own keyboard gadget
  (`/dev/hidg0`). This is deliberately *not* `/dev/hidraw*` — hidraw is a
  peripheral attached **to** the Pi, which cannot inject keystrokes into a host.
- **Direction:** plug the Pi's USB-gadget port into the machine under test; the
  Pi types, the host receives.

## Requirements

The HID gadget function (`hid.usb0`) is added to the composite USB gadget by the
installer. On boxes installed before this feature shipped, run the updater — it
patches the gadget script in place (no live network disruption) and the
`/dev/hidg0` node appears after the next reboot. If no gadget is present the
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
(e.g. `GUI r`). Lines after `#` are comments.

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

**Quick validation:** run the bundled `demo_hello.ducky` with any text field
focused on the target host — it only types a couple of lines (no commands), so
it is a safe way to confirm the whole path works end to end.

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
