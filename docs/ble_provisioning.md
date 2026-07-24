# BLE Provisioning

`ble_provisioning.py` is a BlueZ GATT peripheral that lets the **Ragnar mobile
app** discover a box over Bluetooth and learn how to reach it over IP. It is
the Pi side of the contract documented in the Ragnarmobile repo
(`docs/PROTOCOL.md`).

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
python3 ble_provisioning.py info       # print the payloads, no Bluetooth
python3 ble_provisioning.py selftest   # register with BlueZ, verify, unregister
python3 ble_provisioning.py run        # advertise until Ctrl-C
```

Confirm it is really advertising while running:

```bash
busctl get-property org.bluez /org/bluez/hci0 \
    org.bluez.LEAdvertisingManager1 ActiveInstances   # → y 1
```

New Bluetooth dongles come up soft-blocked — `rfkill unblock all` first.

## Dependencies

`bluez`, `python3-dbus`, and `python3-gi` (the GLib main loop). All three are
installed by `install_ragnar.sh` and ensured by `update_ragnar.sh`.
