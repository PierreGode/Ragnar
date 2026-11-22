# Cellular Uplink Fallback

Plug a cellular hotspot, a phone or an LTE modem into a Ragnar's USB port and
it becomes a **backup internet path**. It carries traffic only when Ethernet and
Wi-Fi are down, whether their link has dropped or their internet is dead
upstream (see [Heartbeat failover](#heartbeat-failover)). It is never scanned. A leave-behind unit therefore stays
reachable (Ragnar Mesh / Tailscale works through carrier NAT) and keeps sending
push alerts after the site network goes away.

Find it under **Network → Interfaces → Cellular Uplink Fallback**.

## Supported devices

No drivers need to be added. The stock Raspberry Pi OS kernel ships every USB
host driver these devices use:

| Device | Presents as | Kernel driver |
|---|---|---|
| Orbic Speed, Netgear Nighthawk/MiFi, Inseego, most hotspots | RNDIS or CDC-Ethernet | `rndis_host` / `cdc_ether` |
| Android phone (USB tethering) | RNDIS (older) or CDC-NCM (Android 11+) | `rndis_host` / `cdc_ncm` |
| iPhone (Personal Hotspot over USB) | Apple tethering | `ipheth` |
| QMI / MBIM LTE modem (Quectel, Sierra, Telit…) | WWAN | `qmi_wwan` / `cdc_mbim` |
| Huawei HiLink / E3372 | NCM | `huawei_cdc_ncm` / `cdc_ether` |

On the hotspot, turn on **USB tethering** in its settings or web UI (on many
hotspots it is off by default). Plug it into a **USB-A host port**:

- **Pi 5 / Pi 4**: the USB-A ports work as-is. Ragnar's USB-gadget link
  (`usb0`, for plugging Ragnar into a laptop) sits on the USB-C port only and
  does not conflict.
- **Pi Zero 2 W**: the one data port is also the gadget port. Use a micro-USB
  OTG adapter; its ID pin puts the port in host mode.

The hotspot shows up as `enx<mac>` (or `wwan0` for a modem), gets an address by
DHCP, and appears in the card within about 10 s.

If the device instead shows up as a CD-ROM (`lsusb` lists it, but no network
interface appears), it needs a mode switch. `usb_modeswitch` is installed and
usually handles this automatically; `dmesg | tail -30` shows what happened.

## What Ragnar does with it

**It stays a fallback.** On their own, dhcpcd gives a USB network adapter
metric `1000+ifindex` and NetworkManager gives it `100`. Both beat Wi-Fi
(`600`/`3000+`), so a plugged-in hotspot would silently become the *primary*
uplink and use cellular data even while Wi-Fi works. Ragnar pins every cellular
interface's default route (IPv4 and IPv6) to metric **20000**, in three ways:

1. `/etc/NetworkManager/conf.d/90-ragnar-cellular.conf`: NetworkManager's
   connection defaults, matched by driver.
2. `/lib/dhcpcd/dhcpcd-hooks/90-ragnar-cellular`: re-pins the metric right
   after every dhcpcd lease or router advertisement.
3. The web server's monitor re-checks every 10 s. This is the only path for
   `cdc_ether`/`cdc_ncm` devices, which are detected by USB vendor (see below).

The kernel always uses the lowest-metric default route. As long as Ethernet or
Wi-Fi has one, cellular is on **standby**. A route alone isn't enough, though:
it only disappears when Wi-Fi or Ethernet loses its *link*. If the ISP dies
upstream, Wi-Fi stays associated, keeps its route, and without heartbeats
traffic would sit on a dead WAN forever.

### Heartbeat failover

About every 10 s, while a cellular link is plugged in, Ragnar checks the
internet **through each primary interface**. The socket is bound to that
interface, so the check can't take a shortcut over cellular.

- **Beyond the gateway, not just the gateway.** Each check is a TCP handshake
  to public targets, by default `1.1.1.1:443`, `8.8.8.8:443` and
  `9.9.9.9:443`. A target that is the interface's gateway, or on its own
  subnet, is skipped and shown as *skipped* in the card. A router that answers
  while its upstream is dead can't count as healthy. Only a completed
  handshake counts: a *connection refused* can come from that same router, so
  it counts as a failure.
- **Several targets.** A round is **good** when at least *N* targets answer
  (default 1). One unreachable target never triggers failover.
- **Failover:** after **3** consecutive bad rounds (about 30 s), Ragnar first
  checks the cellular link the same way. If cellular passes, its route metric
  is **promoted** from 20000 to **50**, below every Wi-Fi/Ethernet metric, and
  traffic moves to cellular even though the primary still has a route. If
  cellular fails too, Ragnar stays put and sends one warning.
- **Failback hysteresis:** traffic returns to the primary only after **6**
  *consecutive* good rounds (about 60 s). One bad round in between resets the
  count, so a flapping WAN doesn't bounce Ragnar back and forth. The same
  hysteresis applies when Wi-Fi loses its link and later reconnects: cellular
  keeps the traffic until the returning link has proved itself.
- **Outage window:** the restore alert reports when the outage started, when
  it ended, how long it lasted, and how much data cellular carried, e.g.
  *"Uplink restored to wlan0 after a 33m 20s outage (13:46:40 → 14:20:00);
  cellular carried 36.4 MB"*.

The failover state is kept in `/run/ragnar-cellular.json`, so a service
restart mid-outage stays failed over, and the dhcpcd hook applies the right
metric if the hotspot reconnects. A reboot starts clean. Heartbeats run only
while a cellular link is present: a unit with nothing to fail over to sends
no probes. Each round is a few TCP handshakes, well under 1 KB.

The card shows the live state:

| Card state | Meaning |
|---|---|
| *idle — no cellular link to fail over to* | No hotspot with a route is plugged in, so no heartbeats are sent |
| *primary healthy* | The last round was good |
| *primary failing 2/3* | Two bad rounds in a row; failover at 3 |
| *FAILED OVER since … — fail back 4/6* | On cellular; four consecutive good rounds so far, failback at 6 |

Below the state it shows each target's result (✓/✗, fastest response time),
any skipped targets, and the last outage. The card updates when you open the
Interfaces tab or press **Refresh**; it does not update live.

### Testing it

With the hotspot plugged in and on *standby*:

1. **Dead upstream:** block this Ragnar's internet on your router (for example
   a firewall rule, or unplug the router's WAN cable) and leave Wi-Fi
   connected. After about 30 s the card shows *FAILED OVER* and the push alert
   arrives. Remove the block; about 60 s later it fails back and the restore
   alert gives the outage window.
2. **Link loss:** `sudo nmcli radio wifi off`, then `on` again. Failback waits
   for the six good rounds even though Wi-Fi reconnects within seconds.

If you manage the unit over Wi-Fi, connect through the Ragnar Mesh / Tailscale
for the test so you don't cut yourself off. `sudo python3 cellular_uplink.py
probe wlan0` shows one heartbeat round from the shell.

**It is never scanned.** The network scanner, ARP liveness sweeps, the
Ethernet lists, the passive-capture interface pickers (L2/L3 watchers, vendor
guards) and the e-Paper/LCD Auto interface all skip cellular interfaces.
Scanning over the hotspot would only find the hotspot and would spend metered
data. When cellular is the *only* uplink, the network scan is skipped
("No LAN (cellular only)"). If a LAN leg without a default route still has an
address, such as a SPAN/monitor cable, that leg is scanned instead. To opt back
in, enable **Allow network scans over cellular**.

In the Interfaces table a cellular interface is labelled **📶 cellular**. On the
HAT's IFACE card it is last in Auto order, but you can still pin it to
speed-test the cellular link itself.

**Failover alerts.** With push notifications enabled, **Config → Push
Notifications → Cellular Failover** sends one alert on failover (high priority,
with the per-interface target counts that triggered it) and one on restore
(with the full outage window). The failover alert goes out over cellular, so
you still receive it after the site network is gone.

## Detection

| Rule | Treated as cellular |
|---|---|
| Driver `rndis_host`, `ipheth`, `qmi_wwan`, `cdc_mbim`, `huawei_cdc_ncm` | always |
| Interface name `wwan*` | always |
| Driver `cdc_ether` / `cdc_ncm` | only when the USB vendor is a phone/hotspot/modem maker (Qualcomm, Samsung, Google, Apple, Huawei, ZTE, Netgear, Inseego, Sierra, Quectel, …) or the USB product string says hotspot / modem / LTE / 5G / phone |
| Listed in **Always treat as cellular** | always |
| Listed in **Never treat as cellular** | never |

`cdc_ether`/`cdc_ncm` also drive some ordinary USB Ethernet adapters (for
example RTL8156 2.5 GbE dongles), which is why those drivers need a vendor
match. If a hotspot is missed, or a real Ethernet dongle is flagged by mistake,
add it to the matching override list.

## Settings

| Key (`shared_config.json`) | Default | Meaning |
|---|---|---|
| `cellular_fallback_enabled` | `true` | Pin the metric. Turning it off removes the NM/dhcpcd hooks; routes already pinned keep their metric until the link reconnects. |
| `cellular_route_metric` | `20000` | Fallback metric (1000–65535). Must stay above every Wi-Fi/Ethernet metric. |
| `cellular_allow_scan` | `false` | Allow the network scanner to target a cellular LAN. |
| `cellular_force_ifaces` / `cellular_exclude_ifaces` | `""` | Space/comma-separated interface names. |
| `cellular_heartbeat_enabled` | `true` | Heartbeat failover. Off = cellular takes over only on link/route loss, with no hysteresis. |
| `cellular_heartbeat_targets` | `1.1.1.1:443 8.8.8.8:443 9.9.9.9:443` | Public IPv4 `ip[:port]` targets (up to 8; no DNS names, no loopback/link-local). |
| `cellular_heartbeat_min_ok` | `1` | Targets that must answer for a good round. |
| `cellular_failover_after` | `3` | Consecutive bad rounds before failover (1–60). |
| `cellular_failback_after` | `6` | Consecutive good rounds before failback (1–360). |
| `cellular_promoted_metric` | `50` | Cellular metric while failed over (must beat every primary). |
| `pushover_notify_cellular` | `true` | Failover / restore push notifications. |

## API & CLI

- `GET /api/cellular/status`: settings, the active uplink, `on_cellular`, and
  per-interface role (`active` / `standby` / `no route`), driver, USB device,
  IPv4, gateway, metric and rx/tx byte counters. Also returns the last monitor
  events and `heartbeat`: state, streaks, per-interface target results, and
  the last outage.
- `POST /api/cellular/settings`: `{enabled, metric, allow_scan, force_ifaces,
  exclude_ifaces, heartbeat_enabled, heartbeat_targets, heartbeat_min_ok,
  failover_after, failback_after}`. Saves, re-installs the hooks and enforces
  immediately.

```bash
sudo python3 cellular_uplink.py status            # same JSON as the API
sudo python3 cellular_uplink.py is-cellular enx0a1b2c3d4e5f
sudo python3 cellular_uplink.py enforce           # pin metrics now
sudo python3 cellular_uplink.py probe wlan0       # one heartbeat round through wlan0
sudo python3 cellular_uplink.py install           # (re)write NM + dhcpcd hooks
```

`install_ragnar.sh`, `update_ragnar.sh` (Step 6.97) and the web updater
(`scripts/post_update.sh`) all run `install`, and the service re-runs it at
start, so existing units pick it up on their next update.

## Notes

- **Subnet clash.** Many hotspots use `192.168.1.0/24` (and Orbic may default
  to that as well), which is also a very common home/office LAN. While the
  hotspot is on standby this is harmless: routes to the LAN still go out the
  LAN interface. If both are up and you see odd routing, change the hotspot's
  LAN subnet in its web UI.
- **Data use.** On cellular, Ragnar still does its non-scan internet work:
  mesh polling, push alerts, update checks, and Nuclei template fetches if you
  run Adv Scan. The rx/tx counters in the card show what the link has carried
  since it came up.
- **Cell-tower capture is different.** Logging cell towers while wardriving
  needs a ModemManager modem (QMI/MBIM/serial). A tethered hotspot can't do
  that; see [Cellular modem](cell.md). A QMI/MBIM modem can do both at once.
