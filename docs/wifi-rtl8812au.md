# 📶 RTL8812AU (ALFA) Monitor-Mode Driver Setup

The **Realtek RTL8812AU** is one of the most common "big antenna" USB Wi-Fi adapters
(ALFA AWUS036ACH / AWUS036AC and many clones). It works great for Pwnagotchi mode — **but
only with the right driver.** The in-kernel `rtw88_8812au` driver is unstable for the
monitor-mode + packet-injection workload Pwnagotchi needs, and the fix has one non-obvious
step. This guide covers both.

Back to the [Pwnagotchi Bridge Guide](PWNAGOTCHI.md).

---

## Symptoms of the in-kernel driver problem

If your RTL8812AU adapter is on the stock `rtw88_8812au` driver, you'll typically see:

- Pwnagotchi runs but captures **0 or very few handshakes**, even in a busy area.
- AP count on the dashboard **drops to 0 intermittently**; networks appear and vanish.
- `epoch` log lines show `deauths=0` and low `assocs=` (it can't inject to force handshakes).
- `wlan1` keeps falling out of monitor mode back to `type managed`.
- `dmesg` shows the adapter **re-enumerating on USB over and over** plus firmware TX errors:

  ```
  rtw88_8812au ... failed to get tx report from firmware
  usb 1-1: New USB device found ... idProduct=8812      <-- repeats every few minutes
  ```

## Confirm it's the driver (not power or NetworkManager)

```bash
# 1) USB re-enumerations since boot — a healthy adapter shows ~1, not dozens:
sudo dmesg | grep -c "idProduct=8812"

# 2) Rule out power/undervoltage — must be 0x0:
vcgencmd get_throttled

# 3) Which driver is loaded:
sudo ethtool -i wlan1 | grep driver          # "rtw88_8812au" = the unstable in-kernel driver
```

High reset count + `throttled=0x0` + driver `rtw88_8812au` ⇒ this guide fixes it.

---

## Fix — install the morrownr `8812au` DKMS driver (with monitor mode enabled)

We replace the in-kernel driver with the out-of-tree
[`morrownr/8812au-20210820`](https://github.com/morrownr/8812au-20210820) driver, which is
built for monitor mode + injection and stays stable under load.

> ⚠️ **The critical, easy-to-miss step:** this driver ships with `CONFIG_WIFI_MONITOR = n`,
> so a **default build has no monitor mode** — `iw ... set type monitor` returns
> `Operation not supported (-95)` and bettercap can't start. You **must** flip it to `y`
> before building.

### 1. Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y dkms bc git raspberrypi-kernel-headers
# Confirm headers exist for your running kernel (the usual dealbreaker):
ls /lib/modules/$(uname -r)/build/Makefile
```

### 2. Clone and **enable monitor mode**

```bash
cd ~
git clone https://github.com/morrownr/8812au-20210820.git
cd 8812au-20210820
sed -i 's/^CONFIG_WIFI_MONITOR = n/CONFIG_WIFI_MONITOR = y/' Makefile
grep '^CONFIG_WIFI_MONITOR' Makefile          # must read: CONFIG_WIFI_MONITOR = y
```

### 3. Build, install, reboot

```bash
sudo ./install-driver.sh NoPrompt             # non-interactive DKMS build; auto-blacklists rtw88_8812au
sudo reboot
```

### 4. Verify after reboot

```bash
sudo ethtool -i wlan1 | grep driver           # now: rtl8812au
# monitor mode must now be listed as a supported mode:
sudo iw phy phy$(iw dev wlan1 info | awk '/wiphy/{print $2}') info \
  | sed -n '/Supported interface modes/,/Band /p' | grep -i monitor
```

Switch to Pwnagotchi mode and within a minute you should see bettercap sending association
and deauth frames, `epoch` lines with `assocs=` in the dozens/hundreds, and handshakes
starting to land.

---

## Maintenance — rebuild before kernel upgrades

A DKMS module built for one kernel can break on a major kernel bump (monitor mode may vanish).
Before upgrading, or if monitor mode stops working after an update:

```bash
cd ~/8812au-20210820 && git pull && sudo ./install-driver.sh NoPrompt && sudo reboot
```

---

## Notes

- **`aireplay-ng --test wlan1` is unreliable here.** It can report `0%` injection even when
  injection actually works, because many APs simply don't answer its directed probes. Judge
  injection by whether **bettercap actually sends association/deauth frames** and captures
  handshakes — not by this test.
- **Adapter choice for handshake capture:**
  | Chipset | Monitor RX | Injection (deauth) | USB stability | Verdict |
  |---|---|---|---|---|
  | **RTL8812AU** + this driver | ✅ | ✅ | ✅ | **Recommended** |
  | **MT7612U** (ALFA AWUS036ACM) | ✅ | ✅ | ✅ | Good alternative |
  | **MT7921U** (`mt7921u`) | ✅ | ⚠️ failed in our test | ✅ | Verify injection first (see note) |

  The MT7921U we tested (on kernel 6.18) was very stable with excellent monitor RX, but
  bettercap could not inject deauths through it, so it captured almost nothing — great for
  *passive* wardriving (logging networks + GPS) but not handshake hunting on that setup.
  We can't confirm whether that's universal to the MT7921U or specific to a driver/kernel
  version, so **test injection first** (does bettercap actually send deauths and capture
  handshakes?) before relying on one.
