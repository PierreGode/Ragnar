# Ragnar Mobile over Bluetooth

The [Ragnar Mobile](https://github.com/PierreGode/Ragnarmobile) app finds a unit
over Bluetooth (BLE) and talks to it over Bluetooth. The phone and the unit only
have to be within radio range of each other — in a car, in the field, on a desk.

## Using it

1. On the unit: **Settings → Bluetooth → Use the app over Bluetooth → on**. The
   card shows the name the unit advertises (`Ragnar-xxxx`) and its **link code**.
2. In the app: **Connect → Bluetooth → Connect over Bluetooth**. The app picks
   the nearest Ragnar.
3. Enter the link code. The app remembers it for that unit.

## What it carries

The app's ordinary API requests travel over two GATT characteristics and are
answered by the same routes that answer them over HTTP (`ble_link.py`). Every
screen of the app therefore works over Bluetooth as it is:

- the dashboard numbers and system health,
- wardriving: live status, start and stop, sessions, and
  [Phone GPS](wardriving.md#phone-gps-ragnar-mobile-app) — the phone's position,
  once a second,
- alerts, sensing, device inventory,
- toggles and other actions, and switching to another unit through this one.

Answers are compressed before they are sent, typically ten to one for JSON: the
test unit's 33 kB device list crosses as 2.7 kB. BLE moves some tens of kB per
second, so the link is sized for answers up to 128 kB compressed.

Live streams such as the RF waterfall, and the full web UI, run over the mesh or
Wi-Fi (the app's **Network** tab). Over Bluetooth a stream is answered with
`415` and an answer above the size limit with `413`; the app shows "Too much
data for Bluetooth".

## Access

A phone proves it knows the unit's 8-digit **link code**, shown on the card, and
the unit proves the same to the phone. Five wrong codes lock the link for a
minute, doubling up to fifteen. **New code** on the card replaces the code and
signs every phone out.

After the code, the unit's own login applies exactly as it does over HTTP: the
app shows its login screen. The link code is what protects a unit over
Bluetooth; a login password under Settings → Security adds a second lock.

What a phone can read before it has proven the code is `{name, box_id, link}` —
enough to recognise a Ragnar.

## Encryption

Every connection starts with a handshake, and everything after it is encrypted.

1. **Key exchange from the code (SPAKE2).** Phone and unit each combine the link
   code with a fresh random secret and exchange the results. Both arrive at the
   same session keys when they used the same code. Someone recording the
   exchange gets nothing to test guesses against, so a code can only be tried
   one connection at a time, against the lockout above.
2. **Proof both ways.** The phone shows the unit it reached the keys, then the
   unit shows the phone. A device that only pretends to be your Ragnar fails
   here, before the app sends it anything.
3. **Sealed traffic.** Each request and each answer is encrypted and
   authenticated with ChaCha20-Poly1305 under those keys. Requests carry a
   counter that only goes up, so a recorded request cannot be replayed, and an
   answer only opens for the request it belongs to.

Keys last for one connection: every reconnect runs the handshake again with new
secrets. The phone remembers the code, so this happens by itself.

The group arithmetic and the cipher come from libsodium (PyNaCl) on the unit and
from the audited `@noble` libraries in the app. `tests/test_ble_link.py` and the
app's `tests/linkproto.test.ts` check the same known-answer values, so the two
sides are proven to agree byte for byte.

## Upload accounts

The app and the unit share one set of WiGLE / WDGWars / Wardrift accounts. Each
time the app connects it reads the unit's accounts, keeps any it did not have,
and hands the unit any that only the phone holds — in the background, over the
encrypted link. An account entered in the app is saved on both at once.
`GET/POST /api/wardriving/upload-accounts`; details in
[wardriving.md](wardriving.md).

## How it is built

- `ble_peripheral.py` owns the radio: adapter choice, advertising, the D-Bus
  GATT objects. Config `ble_enabled`, `ble_adapter`.
- `ble_link.py` owns the protocol and runs with plain Python: frames, the key
  exchange and sealing, dispatch into Flask, size limits. Config
  `ble_link_code`. Needs `pynacl` (in `requirements.txt`).

**Adapter.** The peripheral uses the built-in controller by default so a USB
dongle stays free for scanning. A unit with more than one controller gets an
adapter picker on the card.

**API.**

- `GET  /api/ble/status` → `{enabled, running, starting, error, hint, name, adapters, link: {code, connected, requests, bytes_out, locked_for, login}, …}`
- `POST /api/ble/toggle` → `{enabled}`; also takes `adapter` and `new_link_code: true`.

**GATT service** `fc453ae1-7464-49fb-9018-52ded4f4086d`, advertised as
`Ragnar-<id>` (id = last 2 bytes of the adapter address).

| Characteristic | UUID | Access | Payload |
|---|---|---|---|
| Device info | `8c310633-…` | read | `{name, box_id, link}` |
| Link RX | `a3f1c2d4-…f601` | write | one frame of a request (app → unit) |
| Link TX | `a3f1c2d4-…f602` | notify | one frame of an answer (unit → app) |

**Wire format.** frame = `id:u16 | seq:u16 (bit 15 = last) | payload`, sized to
the connection's MTU. Request = JSON `{"t":"hello"|"auth"|"req", …}`. Answer =
`status:u16 | flags:u8 | body` (flag 1 = zlib, 2 = JSON).

**Reviewing it from a desk.** With `ble_link_sim: true` in the config, the unit
accepts link messages over HTTP at `POST /api/ble/link/sim`, and the browser
build of the app offers **Simulate Bluetooth** on its Connect screen. The same
hub answers, with the same code check and size limits, and the app feeds the
answer back at about BLE speed. It is a development switch and defaults to off.

## Changed from earlier releases

- **Bluetooth is now the connection itself.** Earlier releases used Bluetooth to
  hand the app the unit's IP address, after which the app connected over Wi-Fi
  ("handover"). The app now talks to the unit over Bluetooth. An app version
  from before this change finds the unit but cannot connect; update the app.
- **Removed:** the network-status, hotspot-credentials and hotspot-control
  characteristics, the "auto-stop" option, and the Bluetooth access
  point (PAN) with `bt_pan.py` and `/api/bt/pan/*`. A unit that had the access
  point on removes its `pan0` bridge, DHCP server and pairing agent the first
  time it starts after the update.

- **Old pairings are removed.** The app connects without pairing. A phone,
  tablet or computer still paired with the unit from the access-point days kept
  a saved copy of the unit's services and reported "This Ragnar is too old".
  When the link starts, the unit removes its pairings with phones, tablets and
  computers; the Android app removes its own half and connects again. Pairings
  with other devices (controllers, speakers, sensors) stay.
- **Faster to find.** While the link is on the unit advertises every
  100–150 ms (the kernel default is 1.28 s), so the app connects within a
  second or two.

- **The app finds the unit and cannot stay connected, on a unit updated from a
  release before 2026-11-16:** reboot it once. Switching the link off and on
  used to restart Ragnar and leave extra advertisements behind in the Bluetooth
  service; `bluetoothctl show` lists them as `ActiveInstances` (1 is correct).

## CLI / troubleshooting

```bash
sudo python3 ble_peripheral.py doctor   # why isn't it advertising?
python3 ble_peripheral.py info          # print the payloads, no Bluetooth
python3 ble_peripheral.py selftest      # register with BlueZ, verify, unregister
python3 ble_peripheral.py run           # advertise until Ctrl-C
```

**The switch does not take right after an update.** The update restarts Ragnar
only when dependencies and network tools are installed, which can take 15–20
minutes on a small board. The card says "Ragnar is finishing an update" until
then; switch Bluetooth on after the restart. The Update card shows the same
steps.

**"Starting — registering with BlueZ…" that never finishes.** Registering the
GATT application and advertisement takes noticeably longer on a slow board (a
Pi Zero 2 W), and can outlast the wait inside the API call that started it.
That is reported as `starting`, distinct from a failure, and the web UI keeps
polling until it settles — a peripheral in this state is usually a second or
two from advertising. If it stays there for more than ~20 s, run `doctor`.

**`RegisterApplication: org.bluez.Error.AlreadyExists`.** The GATT application
and advertisement use fixed D-Bus object paths (`/one/gode/ragnar/ble`), so a
registration left behind by an earlier run blocks every later start — and it
used to persist until the whole Ragnar process restarted. Two faults caused it,
both fixed: teardown ran the advertisement and application unregisters in one
`try`, so the routine failure of the first (BlueZ releases the advertisement
itself) skipped the second; and restarting the peripheral
replaced the server object without stopping the old one, orphaning its
registration. A start that still meets `AlreadyExists` now reclaims the path and
retries once, so a box already stuck heals itself on the next enable. If you see
this on an older build, restarting Ragnar clears it.

**`RegisterAdvertisement: org.bluez.Error.Failed: Failed to register
advertisement`** — shown in the UI as *"Enabled, but not advertising"*. This is
**not** a Ragnar-side rejection: BlueZ is relaying that the *controller* refused
the advertisement, which is why the same build advertises on one box and not on
another. The causes, in the order they turn up:

- **The controller does not support an advertising include we asked for.**
  `tx-power` is the one that bites: a radio that cannot report its LE
  advertising TX power does not list it in `SupportedIncludes`, and asking for
  it anyway gets the *whole* advertisement refused. The peripheral now reads
  the controller's `SupportedIncludes` first and only asks for what is there.
- **No advertising slot free.** Something else is already advertising and the
  controller supports only so many instances (`ActiveInstances` /
  `SupportedInstances`) — often a leftover `bluetoothctl advertise on`.
- **A scan is running on the same radio.** Some controllers will not advertise
  while `bt_scanner` / WIDS holds a discovery. Pin the peripheral to another
  adapter, or run them at different times.
- **The controller was still settling** right after power-on, and refused the
  first registration only.

- **The controller cannot be an LE peripheral at all.** A central-only radio
  (`Roles: central`, no `peripheral`) will not advertise connectably however
  small the advertisement is — and connectable is the point, since the phone
  has to connect to read the GATT characteristics.
- **The radio is wedged**, typically left advertising by a raw-HCI tool
  (`hciconfig hciX leadv`) so every `Add Advertising` comes back refused until
  it is reset.
- **A raw-HCI scan is holding the radio.** The BLE **scan / pentest** path
  (`actions/ble.py`, `actions/ble_pentest.py`) drives the controller with
  `hcitool lescan`, `hcidump`, `btmon`, `l2ping` — *underneath* BlueZ. A scan
  they start does **not** set `Adapter1.Discovering`, so the "is a scan
  running?" check reads clean while the controller is in fact busy and refuses
  to advertise. This is the most likely reason a box that used to advertise
  suddenly won't. Ragnar detects these directly from the process list and calls
  them out; stop the scan/pentest (or use a second controller) and switch
  Bluetooth back on. `hcitool lescan` in particular often leaves the radio wedged
  when killed, so a `hciconfig hciX reset` (or `bluetoothctl power off/on`) may
  be needed after — which is what the automatic power-cycle retry does.

A refused advertisement is retried down a ladder of progressively smaller ones
— the same advertisement once more, then without `tx-power`, then the bare
service UUID — because a box findable by service UUID alone still works
(the app scans filtered by that UUID). If every rung is refused, the controller
is **power-cycled once** and the whole ladder retried, which clears the wedged
case. Only then is it reported as a failure — and the message carries the
controller's own capabilities plus **the mgmt status bluetoothd logged**, which
is the actual reason BlueZ hides behind that one opaque string:

```
RegisterAdvertisement: org.bluez.Error.Failed: Failed to register advertisement
[hci0; instances 0/5; includes tx-power,appearance,local-name; max adv len 31;
 roles central,peripheral] [bluetoothd: Rejected (0x0b)]
```

The `[bluetoothd: …]` part is the one that decides it — every cause above
produces the same D-Bus text, but a different mgmt status:

| bluetoothd says | What it means | Fix |
| --- | --- | --- |
| `Rejected (0x0b)` | LE is disabled on the controller | remove `ControllerMode = bredr` from `/etc/bluetooth/main.conf`, then `sudo btmgmt --index hci0 le on` |
| `Not Supported (0x0c)` | the radio has no LE advertising | use a BT 4.0+ adapter |
| `Invalid Parameters (0x0d)` | refused even at minimum size — the radio/firmware, not the advertisement | (1) if it's a USB dongle, switch to the **built-in** radio; (2) add `Experimental = true` under `[General]` in `/etc/bluetooth/main.conf` and restart bluetooth; (3) `dmesg \| grep -i bluetooth` for a failed firmware load |
| `Busy (0x0a)` | the controller is mid-operation | stop the scanners (bt_scanner / WIDS overlay) |
| `No Resources` | no advertising slot left | `bluetoothctl advertise off`, or another controller |
| `Not Powered` | radio off / rfkill | `sudo rfkill unblock all && bluetoothctl power on` |

If the journal is unreadable (not root, no systemd) the line is simply absent —
run the doctor with `sudo`, or read it directly:

```bash
journalctl -u bluetooth -n 50 | grep -i advertis
```

**Is it Ragnar or the controller?** When the advertise test fails, the doctor
also runs BlueZ's *own* advertiser (`bluetoothctl advertise on`) — a bare,
flags-only advertisement with no service UUID. If **that** is refused too, the
controller cannot advertise via BlueZ at all and it is not Ragnar's
advertisement content:

```
CONFIRMED: BlueZ's own advertiser (bluetoothctl advertise on) is refused here
too — so this is the controller/firmware, NOT Ragnar. Use a different adapter.
```

An `Invalid Parameters (0x0d)` with that confirmation is a controller that
simply won't advertise on this firmware/driver — the reliable fix is to
use the **built-in** radio (the doctor names it) and leave the dongle
for scanning.

**Start with `doctor`.** It is the "the toggle does nothing" tool: it checks
each prerequisite in turn — `python3-dbus` and `python3-gi` importable,
`bluetoothctl` present, at least one controller found, Bluetooth not
rfkill-blocked, then what that controller can actually advertise — and finally
registers an advertisement for a few seconds and reports what BlueZ said. Every
FAIL line carries the command that fixes it; WARN lines are conditions that
only matter if the advertise test below them fails:

```
  [PASS] python3-dbus importable
  [PASS] python3-gi importable
  [PASS] bluetoothctl present
  [PASS] Bluetooth controller found (1)
        - hci0 DC:A6:32:00:B4:E2 (built-in)
  [PASS] Bluetooth not rfkill-blocked
        BlueZ 5.82
  [PASS] hci0 exposes LEAdvertisingManager1
        includes:  tx-power, appearance, local-name
        instances: 0/4 in use
        max adv len: 31
        roles:     central, peripheral
  [PASS] Controller can act as an LE peripheral
  [PASS] An advertising slot is free
  [PASS] No scan running on this adapter
  [PASS] No raw-HCI tool holding the radio
  [PASS] Advertising starts
        advertising as "Ragnar-b4e2" on hci0
```

The **raw-HCI** line is the one the plain scan check misses: it names any
`hcitool`/`hcidump`/`btmon`/`l2ping` (the BLE scan/pentest tools) that is on
the radio below BlueZ, with its PID, so you can stop exactly that process.

Those middle lines are the ones to paste in a bug report: they are what differs
between a box that advertises and one that does not.

When the advertise test fails, the doctor keeps digging instead of stopping at
the error — it registers a **non-connectable (broadcast)** advertisement to
tell "this radio will not advertise at all" apart from "it will not advertise
*connectably*", prints the mgmt status from bluetoothd, flags a
`ControllerMode = bredr` in `main.conf`, and tails any Bluetooth firmware
errors out of `dmesg`:

```
  [FAIL] Advertising starts  -> RegisterAdvertisement: org.bluez.Error.Failed: ...
        Bluetooth LE is off on this controller. Check /etc/bluetooth/main.conf ...
        NOTE: a non-connectable (broadcast) advertisement WAS accepted — this
        controller will not advertise connectably, so it cannot serve GATT.
        bluetoothd says: Rejected (0x0b)
```

A pass here means the box is on the air — if the phone still can't see it, scan
for that name with a generic BLE app (nRF Connect) to split "box isn't
advertising" from "app isn't finding it".

Confirm it is really advertising while running:

```bash
busctl get-property org.bluez /org/bluez/hci0 \
    org.bluez.LEAdvertisingManager1 ActiveInstances   # → y 1
```

New Bluetooth dongles come up soft-blocked — `rfkill unblock all` first.

## Dependencies

`bluez`, `python3-dbus`, and `python3-gi` (the GLib main loop). All three are
installed by `install_ragnar.sh` and ensured by `update_ragnar.sh`.
