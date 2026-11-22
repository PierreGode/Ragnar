# Device Console

Watch — and optionally command — a switch, router or firewall's **serial console**
from the Ragnar dashboard. Plug a USB console cable into a Ragnar and the RJ45 end
into the device's console port; the **Device Console** card (Dashboard tab, below the
Activity Log) streams whatever the device prints. It works for **any unit in the
mesh**: pick another Ragnar in the card and you see the console cabled to that unit,
wherever it is.

> **Read-only by default.** The port opens `O_RDONLY` until you tick **Allow write**
> in the card. With the write gate enabled, a command input bar appears and you can
> send commands (`show version`, etc.) to the device.

## What you will see

A console cable makes Ragnar the console session itself (the DTE), so you see what
the device writes to its console port:

- **Always:** boot and POST output, the **exact firmware version** and platform in
  the boot banner, ROMMON / bootloader, kernel panics, crash dumps and tracebacks —
  a device writes these to console regardless of its logging config.
- **If the device sends logging to console:** config changes, login failures,
  interface / STP / err-disable events. This depends on `logging console <level>`
  (Cisco) or the vendor equivalent; many production devices limit or disable
  console logging, so a healthy box may print nothing for hours. A quiet console is
  normal.
- **Never:** traffic, or another operator's SSH session. This is not a tap: it sees
  only what the device writes to *this* port.

## Hardware

Any USB-to-RJ45 **rollover** console cable: it is a USB-UART (FTDI, CP210x, PL2303)
with an RS-232 rollover pinout. Debian loads the driver automatically and the port
appears as `/dev/ttyUSB0` (listed in the card by its stable `/dev/serial/by-id`
path, so it survives re-plugging).

| Vendor | Default |
|---|---|
| Cisco, Arista, Juniper, HPE / Aruba | 9600 8N1 |
| MikroTik (CRS / CCR) | 115200 8N1 |

**Auto baud** detects the rate passively: it reads at a candidate rate and, if the
bytes arriving are mostly unprintable framing garbage, re-reads at the next one
(9600 → 115200 → 38400 → 19200 → 57600) until the text is clean. It needs the
device to be printing something (a reboot, a log line) and **never sends anything
to provoke output**. If you know the rate, pick it.

For belt-and-braces safety on a critical device **with write disabled**, use a cable
with the **TX conductor cut** (RJ45 pin 6 in a rollover pinout — the device's RxD):
then transmission is impossible physically as well as in software.

## Read-only vs read-write

By default the port is opened **`O_RDONLY | O_NOCTTY`** — a write is impossible at
the file descriptor level. The self-test proves a write attempt is refused.

Tick **Allow write** to enable the gated write path:

- The port is reopened `O_RDWR | O_NOCTTY` (an automatic restart happens).
- A **command input bar** (`cmd>`) appears below the output pane. Type a command and
  press Enter (or click Send); a `\r` is appended automatically.
- The badge changes from **READ-ONLY** to **READ-WRITE**.
- The setting is saved in `data/serial_console.json` and remembered across restarts.
- Untick **Allow write** to return to read-only at any time.

In both modes:

- Raw termios with **`HUPCL` cleared** (no DTR drop when the port closes), hardware
  flow control off and `CLOCAL` set (modem-control lines ignored). No **BREAK** is
  ever generated — a BREAK during boot drops a Cisco into ROMMON.
- **The port stays reserved** (in `serial_claims`) from the moment you assign it,
  even while the viewer is stopped, and across reboots. GPS, CYD, RoomScan and
  wardriving auto-detection skip it — several of those write probe bytes to the
  ports they open, which on a console port would land on the device's console. Use
  **Release port** only after unplugging the cable (or if you re-purpose it).

## Living with Ragnar's other USB-serial devices

Ragnar auto-detects several USB-serial devices, and a console cable's USB-UART
chip looks just like some of them. How each one coexists with a console port:

| Component | What it looks for | With the console port assigned | Before you assign it |
|---|---|---|---|
| **Huginn / Piglet** (wardriving companions) | Espressif USB (VID `303a`) only | skipped | never matches a console cable |
| **Zigbee sniff** (Huginn) | Espressif only | skipped | never matches |
| **GPS** (direct + `gpsd` setup) | `by-id` GPS names, then an NMEA *read* probe of other ports | skipped — also in the separate `setup_gpsd.sh` process, which reads the reservation file | may open it briefly to listen for NMEA; a console never produces NMEA, so it is not adopted. `gpsd` hotplug is off (`USBAUTO="false"`) |
| **CYD bridge** (when enabled, auto port) | CP210x / CH340 | skipped | opens it but **stays silent** until a genuine CYD frame arrives; a port that never answers is released within 30 s and ignored for 10 min |
| **RoomScan** | Espressif, then first `ttyUSB` | skipped | could pick it as a fallback — assign the console port first |
| **Meshtastic** (Wardrift link, auto port) | CP210x / CH340 / nRF / Espressif | skipped | could pick a CP210x/CH340 cable when the link starts — set the Meshtastic port explicitly, or assign the console port first |
| **Power test** | lists ports | — | lists only, never opens |

**Rule of thumb:** plug the console cable in and **assign it in the card straight
away**. From then on it is reserved (even while stopped, and across reboots), and
nothing else will open it. An FTDI-based cable (VID `0403`) is the safest choice: no
auto-detecting component claims FTDI chips at all. The Alfa and other USB Wi-Fi
adapters are network interfaces, not serial ports, and are unaffected.

If the port shows *in use by cyd* in the picker, the CYD bridge is still inside
its silent identify window; press ↻ after ~30 s and it will be free.

## Viewing a console on another mesh unit

The unit picker lists this unit plus every Ragnar in the mesh, labelled
*console live*, *console cabled*, *no console*, *offline* or *unreachable*.
Discovery reads a small, **content-free** status route on each peer
(`GET /api/mesh/serial-console/status` — port assigned? running? shared? baud? —
never any output). There are two ways to view a remote console:

1. **Share with mesh** — on the unit **with the cable**, tick **Share with mesh**
   in the card. Every other unit in the mesh can then pick it and watch the
   output; the port, baud and Start/Stop controls are locked on the viewing side
   (start and stop it on the unit itself). This works on tag trust — no mesh
   secret needed — and is **off by default**, per unit, so nothing leaves a unit
   until its operator switches it on. The choice is remembered across restarts
   and survives *Release port*. The label changes automatically:
   - **Share with mesh (view-only)** — when Allow write is off.
   - **Share with mesh (read-write)** — when Allow write is also on. Mesh peers
     get a **REMOTE WRITE** badge and the `cmd>` input bar, so they can send
     commands to the device from the remote dashboard. The command relays via
     `POST /api/serial-console/peer-write` → `POST /api/mesh/serial-console/write`.
2. **Mesh secret — full view and control.** With a
   [mesh secret](mesh.md#hardening-a-shared-tailnet-the-mesh-secret) armed on both
   units, the card talks to the remote unit through the
   [mesh gateway](mesh.md#mesh-gateway-reach-the-fleet-through-one-unit)
   (`X-Ragnar-Target`): you can pick its port, set the baud, start/stop and write
   commands as if it were local.

If neither applies, picking the unit tells you it has not shared its console.
Console output can contain sensitive material (a `show running-config` someone
ran at the console), which is why sharing is an explicit, per-unit opt-in rather
than automatic on tag trust.

A typical deployment: a small Ragnar (Pi Zero 2 W is enough) cabled to the console
of a core switch or edge firewall in a rack, joined to the mesh, and watched from
the unit on your desk.

## Operational notes

- **You occupy the console.** A technician who needs the port has to unplug the
  cable. Plan for one Ragnar (or one USB hub of adapters) per device.
- **A logged-in console is attack surface.** If a session is left logged in on the
  console, anyone with that Ragnar has the device — especially with **Allow write**
  enabled. Log out of consoles you leave cabled, and disable the write gate when
  you are done sending commands.
- The viewer keeps the last 5,000 lines per unit in memory; **Download log** saves
  what the page has received (up to 20,000 lines) as a timestamped text file.
- If the cable is unplugged, the viewer shows *disconnected* and resumes by itself
  when it returns. It also resumes after a Ragnar restart if it was running.
- All console settings live in **`data/serial_console.json`**, not in
  `shared_config.json`: the assigned `port`, `baud` (or `auto`), whether it was
  running (`enabled`), `allow_write` and `share_mesh`. Delete the file to reset
  the console to unassigned and read-only.

## Console scripts

With **Allow write** enabled a **Run script** picker appears below the command
input. Select a script and click **Run Script**, then confirm. Each command is
sent in order, followed by the delay defined in the script file. The status next
to the button shows *Step 3/7…*, then *Done*, or *Failed at step N* with the
reason.

- **One script at a time** per unit. A second run is refused while one is
  running.
- **To abort** a running script, untick **Allow write**. The port reopens
  read-only, the next command is refused, and the script stops with
  *Failed at step N*. There is no separate stop button.
- Scripts are **fire-and-forget**: the delay is a fixed pause, not a wait for
  the device's prompt. A slow device (for example a `write memory` on a large
  config) needs a longer delay after that command.
- **On another mesh unit**, scripts run on *that* unit (the list and progress
  also come from it), which requires the
  [mesh secret](#viewing-a-console-on-another-mesh-unit) (gateway mode). A
  console that is only *shared* with the mesh relays single commands; the
  script picker is hidden there.

Five built-in scripts are created in `data/console_scripts/` the first time
the script list is read:

| Script (file) | Vendor | Sends |
|---|---|---|
| Reboot Device (`reboot_device`) | Cisco | Enter → `enable` → `write memory` → `reload` → `yes` (confirms the reload prompt). **Reboots the device.** |
| Monitor Logs (`monitor_logs`) | Cisco | Enter → `enable` → `terminal monitor` → `terminal length 0` → `show logging last 50` |
| Version Info (`version_info`) | Generic | Enter → `show version` → `show inventory` |
| Configure VLANs (`configure_vlans`) | Cisco | Enter → `enable` → `configure terminal` → VLAN 10 *Management*, VLAN 20 *Users* → `end` → `write memory` → `show vlan brief`. **Changes and saves the running config.** |
| Interface Status (`interface_status`) | Generic | Enter → `show ip interface brief` → `show interfaces status` → `show interfaces counters errors` |

Every built-in starts with an empty command, which sends a bare Enter to wake
the prompt. `enable` assumes no enable password is set; if one is, the next
command lands on the password prompt. Add your own script with the password
step, or run `enable` by hand first.

A built-in script is only created when its file is **missing**. Your edits to a
built-in are never overwritten by an update. Deleting a built-in brings back
the default on the next read; to hide one for good, replace its contents
instead.

**Install from RagnarScripts:** expand **Install console scripts** on the
console card to browse the shared [RagnarScripts](ragnarscripts.md) library
(`console-scripts/`) and **Install** a script into this unit with one click —
clone the library first (see [RagnarScripts](ragnarscripts.md)).

**Create your own:** the quickest way is the **Upload** button next to the
**Run Script** picker on the console card — pick a `.json` file and it is added
to this unit's library and selected straight away. You can also drop a `.json`
file into `data/console_scripts/` by hand, or upload one from the
**Files** tab (browse into **console_scripts** and use **⬆ Upload here**).
The format:

```json
{
  "id": "my_script",
  "name": "My Script",
  "description": "What it does",
  "vendor": "cisco",
  "commands": [
    {"cmd": "enable", "delay": 1},
    {"cmd": "show version", "delay": 2}
  ]
}
```

- The **file name is the script's id**: `my_script.json` is listed and run as
  `my_script`. It may contain only letters, digits, `_` and `-`. The `id` field
  inside the file is informational only.
- `name`, `description` and `vendor` are shown in the picker. If `name` is
  missing, the file name is used.
- Each `cmd` is sent with a `\r` appended; `""` sends a bare Enter. `delay`
  (seconds, default `0.5`) is the pause *after* that command. A command can
  also be a plain string (`"commands": ["show clock", "show users"]`), which
  uses the default delay.
- A file that isn't valid JSON is skipped in the list.

A script refuses to run unless write is enabled and the console is started. You can also edit existing scripts directly from the dashboard: open
the file in **Files > console_scripts**, click **Edit**, make your changes, and
**Save**.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/serial-console/ports` | USB-serial adapters and who holds each |
| GET | `/api/serial-console/status` | viewer state, baud, bytes, reserved port |
| POST | `/api/serial-console/start` | `{port, baud}` — `baud` is a rate or `"auto"` |
| POST | `/api/serial-console/stop` | `{release}` — stop; `release: true` un-reserves the port |
| GET | `/api/serial-console/output?since=N` | lines after sequence `N` |
| POST | `/api/serial-console/clear` | clear the buffered lines |
| GET | `/api/serial-console/units` | this unit + mesh peers with their console summary |
| GET | `/api/mesh/serial-console/status` | peer-readable, content-free console summary |
| POST | `/api/serial-console/share` | `{share}` — opt this unit's console in/out of view-only mesh sharing |
| POST | `/api/serial-console/allow-write` | `{allow_write}` — enable/disable the write gate (restarts the reader) |
| POST | `/api/serial-console/write` | `{data}` — send data to the device (refuses unless allow_write is enabled) |
| GET | `/api/mesh/serial-console/output/<since>` | peer-readable output — **only** while sharing is on (cursor in the path: the mesh proof covers the path, not the query) |
| POST | `/api/mesh/serial-console/write` | `{data}` — peer-writable: send a command (requires share_mesh + allow_write) |
| GET | `/api/serial-console/peer-output?unit=ID&since=N` | this unit fetches a peer's *shared* output over the mesh |
| POST | `/api/serial-console/peer-write` | `{unit, data}` — relay a write command to a peer's shared-write console |
| GET | `/api/serial-console/scripts` | list available console scripts |
| POST | `/api/serial-console/run-script` | `{script_id}` — the file stem; run a script (requires allow_write + console running; one at a time) |
| GET | `/api/serial-console/script-status` | `{running, script_id, step, total, error}` for the current or last run |

Any of the `/api/serial-console/*` calls can be sent to another unit with the
`X-Ragnar-Target` header (mesh secret required). Self-test:
`python3 serial_console.py --selftest` (a pseudo-terminal stands in for the
USB-UART; it checks the termios flags, that a write is refused when the gate is
closed, that a write succeeds and reaches the device side when the gate is open,
ANSI stripping, prompt surfacing, passive auto-baud, the port reservation, and that
the CYD bridge stays silent on — and releases — a port that never identifies as a
CYD).
