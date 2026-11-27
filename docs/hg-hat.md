# HackerGadgets Pwnagotchi HAT

The HackerGadgets Pwnagotchi HAT puts a UPS (one 18650 cell), a GPS, a
dual-band Wi-Fi adapter (MediaTek MT7921AU), a 4-port USB hub and an RTC on one
board under a Raspberry Pi Zero / Zero 2 W. Ragnar detects it on its own and:

- shows the battery percentage and charger state on the display header, the
  **System** tab Battery card and `/api/system/status`;
- shuts down cleanly when the battery runs low, then has the HAT switch itself
  off;
- switches the HAT off after every normal power-off, once the SD card is safe;
- enables the HAT's real-time clock, so the time is right at boot without a
  network.

The GPS and the Wi-Fi adapter are ordinary USB devices behind the hub: Ragnar
uses them like any other GPS receiver (CH340 serial, NMEA at 9600 baud) and
Wi-Fi adapter.

## How it connects

| Part | Where |
|---|---|
| 5 V and GND | spring pins pressing on the underside of header pins 2/4 and 6/9 |
| Power controller | I2C bus 1, address `0x50` (pins 3/5) |
| RTC (PCF85063A) | I2C bus 1, address `0x51` |
| Controller interrupt / RTC alarm | GPIO22 (pin 15) / GPIO23 (pin 16) |
| USB hub (GPS, Wi-Fi, USB-A) | leaf springs on the Pi's USB test pads |

The **USB** slide switch picks hub mode (the internal hub, GPS and Wi-Fi are on
the Pi's USB) or OTG mode (the Pi's USB goes to the HAT's USB-C port for a gadget
link to a computer, and the hub disappears). The Battery card shows which one is
active. **PWR** switches the HAT's output.

## Setup

1. Fit the HAT under the Pi and switch **PWR** on.
2. Make sure I2C is enabled. The Ragnar installer does this; on a manual
   install run `sudo raspi-config nonint do_i2c 0` and reboot.
3. Start Ragnar. The first time it sees the HAT it installs the RTC overlay and
   the power-off step (`scripts/hg_hat_setup.sh`); updates run the same script.
4. Reboot once so the RTC driver loads.

Check it from a shell:

```bash
sudo i2cdetect -y 1                            # 50 and 51 should be listed
sudo python3 /home/ragnar/Ragnar/hg_hat.py
# HackerGadgets Pwnagotchi HAT: 97% (4.31 V, charger connected, charging, USB hub)
```

## Battery reading

The percentage is the HAT controller's own fuel-gauge figure. *Charging* on the
Battery card means a charger is connected to the HAT's USB-C port (charging or
already full); *On battery* means the cell is powering the Pi. Ragnar only
reads the controller to show this; it writes to it only at the very end of a
power-off (below).

When more than one battery source answers, Ragnar shows a PiSugar first, then a
Waveshare UPS HAT, then this HAT, then a built-in fuel gauge.

## Low-battery shutdown

On battery power (no charger) below the threshold for a full minute of fresh
readings, Ragnar shuts the system down cleanly. Plugging a charger in, or the
battery reading above the threshold, restarts the minute.

**Config → Display**:

| Setting | Key | Default |
|---|---|---|
| HackerGadgets Pwnagotchi HAT Battery | `hg_hat_monitor` | on |
| HackerGadgets HAT: Shut Down on Low Battery | `hg_hat_lowbatt_shutdown` | on |
| HackerGadgets HAT: Low-Battery Threshold (%) | `hg_hat_lowbatt_percent` | 10 (3–50) |

Restart Ragnar after changing them.

## Power-off

`scripts/hg_hat_setup.sh` installs
`/usr/lib/systemd/system-shutdown/ragnar-hg-hat-poweroff`. systemd runs it at the
very end of a **power-off** (not a reboot), after every service has stopped and
the file systems are read-only; it asks the HAT to switch its output off 10
seconds later. So a shutdown from Ragnar, `sudo poweroff` or the low-battery
shutdown never cuts power while the SD card is being written, and the halted Pi
does not drain the battery.

To start again, switch **PWR** off and on.

Check it without powering off (reads the HAT, writes nothing):

```bash
sudo RAGNAR_HG_HAT_DRYRUN=1 /usr/lib/systemd/system-shutdown/ragnar-hg-hat-poweroff poweroff
```

## Real-time clock

The HAT's PCF85063A keeps time on its own coin cell. `scripts/hg_hat_setup.sh`
adds `dtoverlay=i2c-rtc,pcf85063a` to `config.txt`; after one reboot the kernel
driver takes it from there:

- at boot, loading the driver sets the system clock from the RTC, so log
  timestamps, wardriving sessions and GPS assistance have the right time before
  any network is up;
- once NTP has synchronised the clock, the kernel writes it back to the RTC
  (within about a minute here, then every 11 minutes).

A brand-new RTC holds no valid time, so the very first boot after enabling it
can start at an old date until NTP answers; from then on the RTC is right.

```bash
cat /sys/class/rtc/rtc0/name                       # rtc-pcf85063 1-0051
cat /sys/class/rtc/rtc0/date /sys/class/rtc/rtc0/time
```

An existing `dtoverlay=i2c-rtc…` line in `config.txt` is left alone.

## Turning it off

- `hg_hat_monitor` off: no reading, no low-battery shutdown.
- `sudo touch /etc/ragnar/hg_hat.disabled`: the setup script installs nothing.
- `sudo touch /etc/ragnar/hg_hat_poweroff.disabled`: power-off no longer
  switches the HAT off.

## Troubleshooting

### It will not boot on the battery, but boots with USB power in the Pi

The HAT powers the Pi through spring pins pressing on the **underside of the
header pins** (2/4 for 5 V, 6/9 for GND). If the solder joints there are tall,
uneven or covered in flux, the springs make poor contact: the Pi gets enough to
light its LED but not enough to read the SD card, and the green LED blinks a
repeating pattern instead of booting. Powering the Pi's own micro-USB bypasses
the springs, which is why that works.

Fix: clean the joints under pins 2–6 with isopropyl alcohol and file tall
joints flat so the springs land squarely. The I2C springs (pins 3/5) are in the
same corner, so when `sudo i2cdetect -y 1` lists **50** and **51** the power
springs are seated too.

### `i2cdetect` shows nothing at 50 / 51

Same cause as above, or I2C is not enabled (`ls /dev/i2c-1`).

### The identity reads 0xEC instead of 0x6C

Normal on a Raspberry Pi. The controller holds the I2C clock before it answers,
and the Pi's I2C hardware can then read bit 7 of the first byte as 1. Ragnar
masks that one bit on the first byte of each read; every other byte is checked
strictly.
