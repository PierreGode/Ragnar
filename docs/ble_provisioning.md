# BLE Provisioning

> **Note (deprecated client path).** The Ragnar mobile app no longer uses
> Bluetooth to find a box — it connects over the [Ragnar Mesh](mesh.md)
> (Tailscale) and selects units by their `tag:ragnar-mesh` tag. This BLE
> peripheral still ships and works, but nothing currently consumes it; it is
> kept for other provisioning clients and may be retired later.

`ble_provisioning.py` is a BlueZ GATT peripheral that lets a client discover a
box over Bluetooth and learn how to reach it over IP.

## What it is — and isn't

It is **provisioning only**. No dashboard data ever crosses Bluetooth:

- iOS cannot use Bluetooth Classic / RFCOMM without MFi hardware, so BLE GATT
  is the only cross-platform option — and GATT manages only ~5–20 KB/s.
- Ragnar's real API (hundreds of KB per response, plus a Socket.IO stream)
  belongs on Wi-Fi. The box already runs hostapd for the no-infrastructure
  case.

So the peripheral answers exactly one question — *where do I find this box on
IP?* — then gets out of the way. Everything it exposes fits inside a single
512-byte GATT attribute, so neither side implements chunking.

## Off by default

The service is disabled unless `ble_provisioning_enabled` is set. Advertising
as a peripheral contends with `bt_scanner.py`'s active discovery on the same
adapter, so turning it on is a deliberate choice. On a box with a single
controller, run the BLE overlay scans and the provisioning peripheral at
different times; with two controllers, pin the peripheral to one with
`ble_provisioning_adapter`.

**Adapter choice.** Linux/BlueZ runs multiple controllers at once (unlike
Windows, which allows one Bluetooth radio). The Pi's onboard radio sits on the
UART bus; a USB dongle (e.g. an Alfa) enumerates on USB. With no explicit
`ble_provisioning_adapter`, the peripheral prefers the **built-in** controller
so the dongle stays free for the active scanners — even if the dongle happened
to enumerate as `hci0`.

## Web config

The Ragnar web UI → **Config → Bluetooth Provisioning** has an enable toggle
and an adapter picker (each controller is listed, the built-in one tagged).
These write `ble_provisioning_enabled` and `ble_provisioning_adapter`;
switching the adapter restarts the peripheral on the new one. The mobile app's
Settings tab exposes the same enable toggle.

## Auto-stop after provisioning

`ble_provisioning_autostop` (a checkbox on the same card) makes the peripheral
**free the adapter once a phone has provisioned**. When a central reads the
network-status or AP-credentials characteristic, a short grace timer
(`AUTOSTOP_GRACE_MS`, 15 s, reset on each read) arms; when it expires the
peripheral stops advertising and releases the controller for Ragnar's other
Bluetooth work (`bt_scanner`, WIDS).

This is for **single-radio** boxes. The trade-off: once stopped, the app can no
longer rediscover the box over Bluetooth until it advertises again — use the
**Re-advertise** button (shown once auto-stopped) or re-toggle enable. With two
controllers you don't need this: leave provisioning always-on on the built-in
radio and let the USB dongle scan.

## Enabling it

Once — over IP, from the mobile app's **Box** tab, or directly:

```bash
curl -X POST http://<box>:8000/api/ble/provisioning/toggle \
     -H 'Content-Type: application/json' -d '{"enabled":true}'
```

After that the phone can discover the box over Bluetooth on every later
connect. The setting persists and the peripheral comes back up on boot.

- `GET  /api/ble/provisioning`        → `{enabled, running, error, name}`
- `POST /api/ble/provisioning/toggle` → `{enabled}` (omit to flip)

## GATT service

Advertised name `Ragnar-<id>` (id = last 2 bytes of the adapter address).
Service UUID `fc453ae1-7464-49fb-9018-52ded4f4086d`, in the advertisement so
the app can scan filtered by it and iOS can discover in the background.

| Characteristic | UUID | Access | Payload |
|---|---|---|---|
| Device info | `8c310633-…` | read | `{name, hostname, model, version, box_id}` |
| Network status | `7322574d-…` | read, notify | `{api_port, ifaces:[{name,ip}], ap_active, ap_ssid}` |
| AP credentials | `2fdc016e-…` | encrypted read | `{ssid, psk}` |
| AP control | `b8a58eb8-…` | encrypted write | `{action: "start_ap"｜"stop_ap"}` |

The two AP characteristics require a bonded (encrypted) link, so BlueZ runs
pairing on first use — the hotspot key is never exposed on an open link, and
an unauthenticated peer cannot toggle the box's uplink.

The app picks a reachable address from the interface list the same way
Ragnar's net-diag does: wired, then USB ethernet, then `wlan1`, then `wlan0`.

## CLI / troubleshooting

```bash
sudo python3 ble_provisioning.py doctor   # why isn't it advertising?
python3 ble_provisioning.py info          # print the payloads, no Bluetooth
python3 ble_provisioning.py selftest      # register with BlueZ, verify, unregister
python3 ble_provisioning.py run           # advertise until Ctrl-C
```

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
itself on **auto-stop**) skipped the second; and restarting the peripheral
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
  them out; stop the scan/pentest (or use a second controller) and re-enable
  provisioning. `hcitool lescan` in particular often leaves the radio wedged
  when killed, so a `hciconfig hciX reset` (or `bluetoothctl power off/on`) may
  be needed after — which is what the automatic power-cycle retry does.

A refused advertisement is retried down a ladder of progressively smaller ones
— the same advertisement once more, then without `tx-power`, then the bare
service UUID — because a box findable by service UUID alone still provisions
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
provision on the **built-in** radio (the doctor names it) and leave the dongle
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
