# Bluetooth: how the app connects over it

The [Ragnar Mobile](https://github.com/PierreGode/Ragnarmobile) app normally
reaches units over the [Ragnar Mesh](mesh.md) (Tailscale). There are two
Bluetooth ideas below — read this first, because only one of them works with
Android.

## Bluetooth handover (this is the one that works)

**Android will not run an IP stack over a Bluetooth PAN** — it connects the
profile but never DHCPs, in *either* direction (box-as-AP and box-as-client both
proven dead on real devices, IPv4 and IPv6 alike). So Bluetooth cannot carry the
app's traffic.

Instead, Bluetooth does the one thing it is good at here: a tiny **GATT read
that hands over the box's LAN address**. The app scans for the box over BLE,
reads its IP + port, then connects to that address **over Wi-Fi** — where the
traffic is fast. A small BLE read works on Android where PAN does not.

- **Box:** Config → **Bluetooth handover** → on (`ble_provisioning.py`, GATT
  service `fc453ae1-…`, characteristic `net_status` returns `{api_port, ifaces}`).
- **App:** Connect → Bluetooth → **Find Ragnar over Bluetooth** (`src/ble.ts`),
  pick the box, done. The box is added as an ordinary Wi-Fi unit.
- **Requirement:** the phone and the box must be on the **same network** — the
  handed-over address is a LAN address, reached over Wi-Fi, not over Bluetooth.

This is the recommended Bluetooth path. The PAN documentation below is kept for
reference and for non-Android clients, but does not work with Android phones.

---

# Bluetooth access point (PAN) — does not work with Android

> **Superseded — see [Bluetooth handover](#bluetooth-handover-this-is-the-one-that-works) above.**
> Android connects the PAN profile but runs no IP on it, so this never reaches
> the box from an Android phone. Kept for reference / non-Android clients only.

The box becomes a Bluetooth **network access point (NAP)**. A phone pairs it in
its own Bluetooth settings and turns on tethering, which gives the phone an IP
route to the box. The app then talks ordinary **HTTP** to the box's PAN address
— so the whole app, waterfall included, works unchanged over Bluetooth.


The box becomes a Bluetooth **network access point (NAP)**. A phone pairs it in
its own Bluetooth settings and turns on tethering, which gives the phone an IP
route to the box. The app then talks ordinary **HTTP** to the box's PAN address
— so the whole app, waterfall included, works unchanged over Bluetooth.

```
 ┌─────────┐   Bluetooth    ┌────────── box ──────────┐
 │  phone  │   PAN / bnep   │  pan0 bridge            │
 │ .44.x   │ ─────────────▶ │  192.168.44.1   :8000   │
 └─────────┘                │  dnsmasq (DHCP only)    │
                            │  bt-network -s nap      │
                            └─────────────────────────┘
```

## Enabling it

On the box: **Config → Bluetooth access point → on** (or `POST /api/bt/pan/toggle
{"enabled": true}`). The setting is persisted (`bt_pan_enabled`) and comes back
up on boot.

**Dependencies.** The NAP needs `bluez-tools` (`bt-network`, `bt-agent`) and
`dnsmasq`. A lean image may not ship them; if they are missing the card shows an
**Install dependencies** button, and turning the toggle on installs them for you
first (apt in the background, with a streamed log). `POST /api/bt/pan/install`
starts it and `GET /api/bt/pan/install-log` reports progress; the NAP comes up
once they land. Nothing is persisted until it actually starts, so a box that
can't install the packages never boot-loops trying.

On the phone (**Android only** — iOS does not support Bluetooth PAN to a device
like this):

1. **Pair the box** in the system Bluetooth settings.
2. Open the paired device and turn on **Internet access / tethering** for it.
3. In the app, choose **Bluetooth** on the connect screen and connect to
   `192.168.44.1:8000` (the default, pre-filled).

A direct link reaches exactly **one** unit, so the app disables **Switch Ragnar**
and the **Fleet** view while on it and shows a **BT** badge in the header.

## How it is built

`bt_pan.py` orchestrates, using `bluez-tools`:

- a private bridge `pan0` at `192.168.44.1/24`;
- a scoped `dnsmasq` bound to `pan0` only, DHCP-only (`port=0`), advertising
  **no default route** — so the link never hijacks the phone's internet and can
  never bridge onto the box's other networks;
- `bt-agent -c NoInputNoOutput` for "just works" pairing on a headless box;
- `bt-network -s nap pan0` for the NAP server, which enslaves each incoming
  `bnep` link to the bridge;
- the adapter is named **"Ragnar"**, powered, discoverable and pairable via
  **D-Bus** (bounded calls — `bluetoothctl` hangs on a busy stack and even wedges
  bluetoothd);
- paired devices are kept **Trusted** (a background poll). On a box that also
  runs Bluetooth audio (pipewire/wireplumber register their own agent), an
  incoming PAN connection is otherwise sent to *that* agent and cancelled
  (`Access denied`), so the phone pairs but never tethers — a Trusted device is
  auto-authorized with no agent prompt.

## Troubleshooting

- **"incorrect PIN" when re-pairing** — a stale bond (one side holds a link key
  the other lost). There is no real PIN — the NAP pairs "just works" — so this
  is always a key mismatch. The Config card lists paired devices with a
  **Forget** button (`GET /api/bt/pan/devices`, `POST /api/bt/pan/forget
  {address}`), and a **Clear all Bluetooth pairings** button that wipes every
  bond on the box at once (`POST /api/bt/pan/clear-keys`) for when a phone keeps
  failing. Clear it on the box, forget "Ragnar" on the phone too, then pair
  fresh.
- **"Ragnar" doesn't appear when scanning** — the NAP isn't up; enable it in
  Config, and check a Bluetooth controller is present and unblocked (`rfkill`).
  (bluetoothd sometimes drops discoverability on its own — notably when a device
  connects — so bt_pan re-asserts discoverable + the network class on an 8s poll
  while the NAP is enabled.)
- **Pairs, but the app won't connect** — first, is it an **iPhone**? iOS does not
  support connecting to a Bluetooth NAP, so it pairs but never forms the PAN
  link; use Android. On Android, open the paired device and turn on **Internet
  access / tethering** — that is what actually establishes the link. A `bnep0`
  interface appearing under `ip link show master pan0` confirms it connected.
- **The phone shows the box as "headphones" / an audio device** — the box's
  audio stack (pipewire/wireplumber) flagged the adapter's Class-of-Device as
  audio, so the phone paired it as a speaker and never offered the tethering
  toggle. The NAP now forces a Networking / LAN-Access class (`NAP_CLASS`), but a
  phone that already paired caches the old class: **forget the device on the
  phone and pair again**, then the "Internet access" toggle appears. Verify on
  the box with `hciconfig hci0 class` → should read `Networking, LAN Access`.

It is **opt-in** and **fully reversible**: turning it off removes the NAP server,
the agent, dnsmasq, and the bridge, leaving networking exactly as before. The
webapp runs as root under systemd, so no `sudo` is involved at runtime.

### Why not a raw Bluetooth transport in the app?

The app speaks **no Bluetooth** itself: the phone's OS provides the IP link and
the app just makes HTTP requests over it, so it needs no BLE plugin or extra
permission. A raw in-app BLE transport (GATT) tops out around ~20 KB/s — fine
for status, useless for a waterfall — and iOS blocks it too. PAN gives a real IP
link at usable bandwidth, which is why the app treats a Bluetooth connection as
just "a direct address, single unit".

This is distinct from the older `ble_provisioning.py` GATT peripheral, which only
ever handed the app the box's Wi-Fi address and carried no traffic.

## Status

| Piece | State |
|---|---|
| `bt_pan.py` NAP manager (start/stop/status, reversible) | Built |
| `/api/bt/pan/status` + `/api/bt/pan/toggle`, boot autostart | Built |
| Config → Bluetooth access point toggle | Built |
| App Bluetooth connect mode + single-unit gating | Built (Ragnarmobile) |
| **End-to-end pairing + tethering from a real Android phone** | **Needs on-device validation** |

The pairing/tethering handshake is the one part that cannot be exercised without
hardware; everything else (bridge, dnsmasq, NAP registration, teardown) is
standard `bluez-tools` and degrades safely when a controller or tool is absent.
