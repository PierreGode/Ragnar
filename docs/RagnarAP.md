# Ragnar AP Mode

How Ragnar gets itself onto a network, and what it does when it can't.

The short version: if Ragnar cannot join a saved network, it raises its own
access point and **leaves it up until you use it**. Join it, tell it which
network to use, and it switches over. That is the whole flow for a new box and
for a box you have carried somewhere new.

- [Joining a network](#joining-a-network)
- [When AP mode starts](#when-ap-mode-starts)
- [When AP mode does *not* start](#when-ap-mode-does-not-start)
- [Getting back onto a known network](#getting-back-onto-a-known-network)
- [Using a USB Wi-Fi dongle](#using-a-usb-wi-fi-dongle)
- [The wardriving AP is a different thing](#the-wardriving-ap-is-a-different-thing)
- [Settings](#settings)
- [Troubleshooting](#troubleshooting)

---

## Joining a network

| | |
|---|---|
| Network name | `Ragnar` |
| Password | `ragnarconnect` |
| Setup page | `http://192.168.4.1:8000` |
| Ragnar's address on its own AP | `192.168.4.1` |
| Client addresses | `192.168.4.2` – `192.168.4.20` |

Join the `Ragnar` network from a phone or laptop and open the setup page. Pick
the network you want, enter its password, and the box switches over.

**Two things worth knowing.** The AP does not time out — it is there whether you
look after ten seconds or an hour. And Ragnar's web interface is on **port 8000
only**; plain `http://<address>` with no port opens nothing.

### Taking a box somewhere new

This is the same flow. Bring a Ragnar to a summer house, an office or a hotel,
power it on, and it will:

1. look for its saved networks for about a minute;
2. fail to find them, and raise the `Ragnar` AP;
3. wait — indefinitely — for you to join and add the local network.

Old networks are kept. Back home, the box rejoins the home network on its own
(see [below](#getting-back-onto-a-known-network)) without you touching anything.

---

## When AP mode starts

At boot Ragnar checks for an existing connection. Ethernet counts and is
preferred; if a cable is live, Wi-Fi is left alone entirely.

Otherwise it enables the radio and gives NetworkManager **60 seconds** to
auto-join a saved network. If that fails, one last connectivity check runs
(a real ping, not just an association) to catch a working link that the earlier
checks missed. Only then does the AP come up.

---

## When AP mode does *not* start

Two modes own the radio for their own purposes, and the automatic AP fallback is
skipped for both. Wi-Fi searching still continues in each — only the AP is
suppressed, so the box will still rejoin a network on its own if one appears.

| Mode | Config key | Why |
|---|---|---|
| Wardriving | `wardriving_enabled` | Needs the radio for scanning. `hostapd` would take the interface over. Wardriving has its own AP, started deliberately — see [below](#the-wardriving-ap-is-a-different-thing). |
| On-Screen Network Diagnostic Mode | `network_diagnostic_mode` | It is a field test *of the network the box is on*. Converting the radio into an access point mid-test invalidates every reading on the screen. |

---

## Getting back onto a known network

Once the AP is up, Ragnar keeps looking for a network it knows, and hands over
when it finds one. This is what makes a router reboot a non-event.

**How it looks without dropping the AP.** Scanning uses a secondary adapter if
one is fitted, otherwise `iwlist` on the AP interface — deliberately chosen so
the scan does not interrupt `hostapd`.

**Cadence.** A 30-second settle after the AP comes up, then a check every 30
seconds. Measured as elapsed time, so it holds under load rather than drifting.

**It will not interrupt you.** Recovery is skipped entirely while somebody is
connected to the AP. If you are sitting on the setup page entering a password,
the box will not pull the network out from under you — however long you take.

### When the AP stays up

With nobody connected, the AP is left running. Two cases still bring it down,
because otherwise the box could never rejoin anything:

- **Scanning is not working on this hardware.** Ragnar tracks whether a scan has
  recently returned *any* result, which separates "scanned, nothing in range"
  from "cannot scan at all". Only the latter falls back to dropping the AP to
  search the ordinary way.
- **There is at least one saved network.** With none — a fresh install — there
  is nothing to search for and the AP is the entire point, so it stays up
  indefinitely.

---

## Using a USB Wi-Fi dongle

With a second adapter the two jobs split across radios:

| Radio | Role |
|---|---|
| `wlan0` (built-in) | hosts the `Ragnar` access point |
| `wlan1` (dongle) | client connection and background scanning |

The AP stays on the **built-in** radio on purpose. Not every USB dongle's driver
supports AP mode, whereas the Pi's on-board chip reliably does, and 2.4 GHz is
the band every phone can find.

Two things this buys you:

- **A failed join no longer costs you the AP.** With one radio Ragnar must drop
  the AP to attempt a connection, and put it back if the attempt fails. With a
  dongle it joins on `wlan1` while `hostapd` keeps running on `wlan0`, untouched.
- **5 GHz becomes reachable on a Pi Zero 2 W**, whose built-in radio is 2.4 GHz
  only. Without a dongle a 5 GHz-only network cannot be joined at all.

Once the uplink is up the setup AP shuts down. It is not left broadcasting: the
box is reachable through the dashboard by then, and the default AP password is
published in this documentation.

On a single-radio box the client and AP interfaces resolve to the same adapter
and behaviour is exactly as described everywhere else in this document.

---

## The wardriving AP is a different thing

The **KEY1 phone-access AP** used during wardriving is separate from everything
above:

- it is **started deliberately** by the user, not as a fallback;
- it advertises **no gateway and no DNS**, so a joined phone keeps using its own
  cellular data;
- it serves the minimal live wardriving page rather than the setup portal;
- the automatic logic never tears it down — it stays up until KEY1 is pressed
  again.

See the [Wardriving Guide](wardriving.md).

---

## Settings

| Key | Default | Meaning |
|---|---|---|
| `wifi_ap_ssid` | `Ragnar` | AP network name |
| `wifi_ap_password` | `ragnarconnect` | AP password |
| `wifi_default_interface` | `auto` | Which radio is the built-in / AP interface |
| `wardriving_enabled` | `false` | Suppresses the automatic AP |
| `network_diagnostic_mode` | `false` | Suppresses the automatic AP |

Timings live in `wifi_manager.py`: a 60-second join attempt, a 30-second settle
(`ap_recovery_grace`), a 30-second recovery cadence
(`ap_reconnect_check_interval`), and a 300-second window
(`scan_trust_window`) after which a scan that has returned nothing is treated as
a broken scan rather than an empty sky.

**Change the AP password if the box lives somewhere untrusted.** The default is
public — it is printed above.

---

## Troubleshooting

### The setup portal appears instead of the dashboard

If `http://<box>:8000` shows the Wi-Fi Configuration Portal while the box is
plainly already connected, your router hands out addresses in
**192.168.4.0/24** — the same range Ragnar uses for its own AP. **eero mesh
systems default to this subnet.**

Ragnar decides "this request came from an AP client" by checking that it holds
the AP gateway address `192.168.4.1` itself, not merely that the client sits in
that subnet, so an ordinary client on a 192.168.4.0/24 LAN gets the dashboard.
If you are seeing the portal, update and restart:

```bash
sudo ./update_ragnar.sh && sudo systemctl restart ragnar
```

### The `Ragnar` network is not in my Wi-Fi list

- Give it a moment after power-on: the box spends about a minute trying saved
  networks before the AP comes up.
- Check the box is not in wardriving or diagnostic mode — the automatic AP is
  suppressed in both.
- On a box with a dongle, the AP is on the **built-in** radio; a dongle that is
  unplugged or asleep does not affect it.

The AP does **not** disappear on a timer. If it is missing after a couple of
minutes, something failed to start rather than timed out.

### It joined the network but I cannot reach it

Ragnar listens on **port 8000**. `http://<address>` alone will not open.

### Nothing opens at 192.168.4.1:8000

Confirm your device actually took a `192.168.4.x` address from the AP. Phones
sometimes stay on cellular when a network offers no internet — the setup AP
deliberately provides none, since it has no uplink to share yet.
