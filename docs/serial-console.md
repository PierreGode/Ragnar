# Device Console (read-only serial console)

Watch a switch, router or firewall's **serial console** from the Ragnar dashboard.
Plug a USB console cable into a Ragnar and the RJ45 end into the device's console
port; the **Device Console** card (Dashboard tab, below the Activity Log) streams
whatever the device prints. It works for **any unit in the mesh**: pick another
Ragnar in the card and you see the console cabled to that unit, wherever it is.

> **Read-only, always.** Ragnar never sends a byte to the device. You get what the
> device *prints*; you cannot type into the console from Ragnar.

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

For belt-and-braces safety on a critical device, use a cable with the **TX
conductor cut** (RJ45 pin 6 in a rollover pinout — the device's RxD): then
transmission is impossible physically as well as in software.

## How "read-only" is guaranteed

- The tty is opened **`O_RDONLY | O_NOCTTY`** — a write is impossible at the file
  descriptor level (the self-test proves a write attempt is refused).
- Raw termios with **`HUPCL` cleared** (no DTR drop when the port closes), hardware
  flow control off and `CLOCAL` set (modem-control lines ignored). No **BREAK** is
  ever generated — a BREAK during boot drops a Cisco into ROMMON.
- `serial_console.py` contains **no write call at all**; an AST guard in its
  self-test fails if one is ever added.
- **The port stays reserved** (in `serial_claims`) from the moment you assign it,
  even while the viewer is stopped, and across reboots. GPS, CYD, RoomScan and
  wardriving auto-detection skip it — several of those write probe bytes to the
  ports they open, which on a console port would land on the device's console. Use
  **Release port** only after unplugging the cable (or if you re-purpose it).

## Viewing a console on another mesh unit

The unit picker lists this unit plus every Ragnar in the mesh, labelled
*console live*, *console cabled*, *no console*, *offline* or *unreachable*.
Discovery reads a small, **content-free** status route on each peer
(`GET /api/mesh/serial-console/status` — port assigned? running? baud? — never
any output). Viewing, starting and stopping a remote console go through the
[mesh gateway](mesh.md#mesh-gateway-reach-the-fleet-through-one-unit): the
dashboard sends `X-Ragnar-Target: <unit>` and this unit relays the request.
The gateway is **gated behind the mesh secret**, so console output never crosses
the mesh on tag trust alone — set a [mesh secret](mesh.md#hardening-a-shared-tailnet-the-mesh-secret)
to view remote consoles. Console output can contain sensitive material (a
`show running-config` someone ran at the console), which is why it is not exposed
on the tag-only peer routes.

A typical deployment: a small Ragnar (Pi Zero 2 W is enough) cabled to the console
of a core switch or edge firewall in a rack, joined to the mesh, and watched from
the unit on your desk.

## Operational notes

- **You occupy the console.** A technician who needs the port has to unplug the
  cable. Plan for one Ragnar (or one USB hub of adapters) per device.
- **A logged-in console is attack surface.** If a session is left logged in on the
  console, anyone with that Ragnar has the device. Ragnar never types, but log out
  of consoles you leave cabled.
- The viewer keeps the last 5,000 lines per unit in memory; **Download log** saves
  what the page has received (up to 20,000 lines) as a timestamped text file.
- If the cable is unplugged, the viewer shows *disconnected* and resumes by itself
  when it returns. It also resumes after a Ragnar restart if it was running.

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

Any of the `/api/serial-console/*` calls can be sent to another unit with the
`X-Ragnar-Target` header (mesh secret required). Self-test:
`python3 serial_console.py --selftest` (a pseudo-terminal stands in for the
USB-UART; it checks the termios flags, that a write is refused, ANSI stripping,
prompt surfacing, passive auto-baud and the port reservation).
