# Uplink IP stability

> **Symptom:** *"Since I switched to the Red Team (Ulfberht) edition, the box
> keeps changing its own IP address on both wired and wireless. I keep having to
> re-flash the nodes (ruview) with the new address. Never had that before."*

This page explains why that happened and the fix that ships with Ragnar.

## What was going on

Ragnar's management uplink is a normal NetworkManager connection that gets its
address over DHCP. A DHCP server decides *which* address to hand back from two
things it sees on the wire: the interface's **MAC address** and the DHCP
**client identifier**. Give it the same two, you get the same lease back every
time. Change either one and, as far as the router is concerned, a brand-new
device just appeared — so it hands out a **different** address and your old one
sits reserved until it expires.

Ragnar used to configure the uplink with NetworkManager's default
`cloned-mac-address=preserve`. "Preserve" means *use whatever MAC is currently
on the interface when the connection comes up*. On the standard (defensive)
edition nothing ever changes an interface's MAC, so this was invisible.

The **offensive (Ulfberht / Red Team) edition is different**: its tooling
legitimately changes interface MACs — monitor mode, `macchanger`, `airmon-ng`,
and Nexmon on the onboard radio all do. The moment one of those touched an
interface and NetworkManager then re-activated the uplink on it, `preserve`
faithfully carried the **changed** MAC into the managed connection. The router
saw a new MAC, handed out a new lease, and the box's IP moved. When the real MAC
came back, it moved again. Because there was no setting for Ethernet either
(NetworkManager's built-in default there is also `preserve`), the exact same
thing happened on the wired side. Hence *"both wired and wireless."*

## The fix

Ragnar now pins the uplink to the hardware MAC and keys the lease on it, in
`/etc/NetworkManager/conf.d/99-ragnar-wifi.conf`:

```ini
[device]
wifi.scan-rand-mac-address=no

[connection]
wifi.cloned-mac-address=permanent
ethernet.cloned-mac-address=permanent
ipv4.dhcp-client-id=mac
```

- **`cloned-mac-address=permanent`** (Wi-Fi *and* Ethernet) — the managed uplink
  always associates with the burned-in hardware MAC, no matter what monitor
  mode or `macchanger` did to the live interface in the meantime.
- **`ipv4.dhcp-client-id=mac`** — the DHCP client identifier (option 61) is the
  hardware MAC. So even if the connection profile is deleted and recreated (a
  new profile has a new UUID, which otherwise feeds a new client-id), the router
  still sees the same identity and returns the same lease.

A per-connection `cloned-mac-address` still **overrides** this default, so if an
engagement genuinely needs a spoofed *uplink* you can still set one on that
connection. Only the box-wide default changed.

This file is written at install time (`install_ragnar.sh`) **and** re-asserted
on every update (`scripts/provision_network_tools.sh`, which both the CLI
`update_ragnar.sh` and the in-app **Update** button run), so existing boxes heal
themselves the next time they update. The update path only *reloads*
NetworkManager — it never tears down the live connection mid-update.

## Making it take effect, and the permanent cure

The new settings apply at the **next activation** of the uplink — i.e. the next
reconnect or reboot. Applying them can move the address **one last time** (the
client-id changes from the old UUID-derived value to the MAC), after which it
stays put.

Because the box now presents a **stable hardware MAC** to DHCP, the bullet-proof
finish is a **DHCP reservation on your router** for that MAC — then the address
is fixed for good and the nodes never need re-flashing again. Find the MAC with:

```bash
cat /sys/class/net/eth0/address      # wired
cat /sys/class/net/wlan0/address     # onboard Wi-Fi
```

## Applying it by hand to a box that can't update yet

```bash
sudo tee /etc/NetworkManager/conf.d/99-ragnar-wifi.conf >/dev/null << 'EOF'
[main]
# Ragnar network management
dns=default

[device]
wifi.scan-rand-mac-address=no

[connection]
wifi.cloned-mac-address=permanent
ethernet.cloned-mac-address=permanent
ipv4.dhcp-client-id=mac
EOF
sudo nmcli connection reload
# applies on the next reconnect/reboot; to apply now (may change the IP once):
# sudo nmcli device reapply wlan0
```
