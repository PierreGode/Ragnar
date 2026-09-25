## 🔧 Installation and Configuration

<p align="center">
   <img src="https://github.com/user-attachments/assets/463d32c7-f6ca-447c-b62b-f18f2429b2b2" alt="thumbnail_IMG_0546" width="130"> 
</p>

## 📚 Table of Contents

- [Prerequisites](#-prerequisites)
- [Quick Install](#-quick-install)
- [Manual Install](#-manual-install)
- [Pwnagotchi Bridge](#-pwnagotchi-bridge)
- [License](#-license)

Use Raspberry Pi Imager to install your OS
https://www.raspberrypi.com/software/

### 📌 Prerequisites for RPI zero W2 (64bits)

![image](https://github.com/user-attachments/assets/e8d276be-4cb2-474d-a74d-b5b6704d22f5)

Use Raspberry Pi OS Lite (64-bit) Debian Trixie with no desktop environment. 

- Raspberry Pi OS installed. 
    - Stable:
      - System: 64-bit
      - Kernel version: 6.6
      - Debian version: Debian GNU/Linux 13 (trixie)'
- Username and hostname set to `ragnar`.
- 2.13-inch e-Paper HAT connected to GPIO pins.
- **Optional:** [PiSugar UPS](https://www.pisugar.com/) for battery power, battery monitoring, and hardware button support. The installer will prompt you to install `pisugar-server` if you have one attached. You can also install it manually later:
  ```bash
  curl http://cdn.pisugar.com/release/pisugar-power-manager.sh | sudo bash
  ```


At the moment the paper screen v2  v4 have been tested and implemented.
I juste hope the V1 & V3 will work the same.
 
### ⚡ Quick Install

The fastest way to install ragnar is using the automatic installation script :

```bash
# Download and run the installer
wget https://raw.githubusercontent.com/PierreGode/Ragnar/main/install_ragnar.sh
sudo chmod +x install_ragnar.sh && sudo ./install_ragnar.sh
# Choose the choice 1 for automatic installation. It may take a while as a lot of packages and modules will be installed. You must reboot at the end.
```

#### "Some packages won't install"

Not every package is required. The installer splits them in two, and prints a
summary of both when the dependency step ends:

- **Required** — a miss here is a real `WARNING`, and the summary repeats the
  exact `apt-get install` line to fix it. The install continues regardless.
- **Optional** — `hackrf`, `nikto`, `sqlmap`, `whatweb`, `ffuf`,
  `libatlas-base-dev`. These back single features (SDR Waterfall, the recon and
  vulnerability scanners) that look their binary up at runtime and stay disabled
  without it. Not every Debian suite carries all of them — `ffuf` only arrived in
  trixie — so seeing these listed as unavailable is expected, not a failed
  install.

##### nikto on Debian / WSL

Debian ships `nikto` in the **non-free** component, which is disabled by
default, so `apt install nikto` fails ("Unable to locate package") on a stock
Debian or Debian-on-WSL box. The advanced-tools installer handles this: run

```bash
cd ~/Ragnar   # wherever the repo is cloned; run from inside it
sudo bash install_advanced_tools.sh
```

If the distro package is unavailable it falls back to cloning
[`sullo/nikto`](https://github.com/sullo/nikto) into `/opt/nikto`, installs the
required Perl modules (`libnet-ssleay-perl`, `libxml-writer-perl`), and drops a
`nikto` wrapper in `/usr/local/bin` so Ragnar finds it. This also gives a far
newer nikto than Debian's packaged 2.1.5. (`sudo bash` runs as root, so make
sure your working directory is the actual checkout — `~` resolves to `/root`
under sudo.)

Two steps in the install are also slow and silent, which can look like a hang on
a Pi Zero 2 W — the pip build of `sslyze`/`cryptography`, and
`nmap --script-updatedb`. Give them time before interrupting.

#### Headless install on Ubuntu / a non-Pi server — display driver noise

On a generic Ubuntu/Debian server (or any host that is not a Raspberry Pi) the
installer skips every Pi-only display step, because there is no SPI/I2C/GPIO
peripheral to drive a screen. Specifically, when the platform is not a Pi it:

- **skips `RPi.GPIO` / `spidev`** — these only exist for GPIO-attached displays.
  `RPi.GPIO` fails to build (or installs and then crashes on import, since there
  is no `/dev/gpiomem`) off-Pi, which used to surface as alarming errors on
  headless installs that never use a display at all.
- **only adds the groups that exist** — the `spi`, `gpio`, and `i2c` groups ship
  with Raspberry Pi OS but not with stock Ubuntu/Debian. `usermod` is
  all-or-nothing, so naming a missing group used to abort the whole call and
  leave the `ragnar` user out of `sudo`/`netdev` too (breaking WiFi management).
  The installer now filters the list down to the groups present on the host.
- **skips `raspi-config`** SPI/I2C enablement and the Waveshare e-Paper library.

If you *did* pick a display profile on non-Pi hardware, the driver summary will
honestly report the display types that will not work — that is expected, not a
failed install.

#### Boards with a built-in DPI/HDMI panel (HackBerry Pi and similar)

Some Pi-based devices ship with their own DPI/HDMI screen that already owns SPI0
and the display GPIOs (e.g. the HackBerry Pi, HyperPixel, or any
`dtoverlay=vc4-kms-dpi` panel). Ragnar's e-Paper/TFT driver drives those same
pins, so a **display** install would blank that panel. For these boards pick a
**headless (web-only) profile** — `Raspberry Pi headless` or `hbp0_ragnar`
(HackBerry Pi) — which runs `headlessRagnar.py` and never touches the display.

Headless installs set `RAGNAR_HEADLESS=1` (in the entrypoint and in the systemd
unit), which skips EPD initialization entirely. This matters because the display
is initialized at import time: without the guard, simply importing Ragnar's
shared state would seize SPI0 + GPIO and blank the DPI panel — regardless of
which entrypoint launched. If a device with a DPI panel was accidentally set up
with a display profile, `sudo bash update_ragnar.sh` repoints an already-headless
unit and adds the guard, or re-run the installer and choose a headless profile.

#### Changing your screen

The installer asks which screen you have, but that is only a starting value —
**support for every screen is installed regardless of what you pick.** All the
backing dependencies go on (`spidev`, `smbus2`, `luma.led_matrix`, the Waveshare
e-Paper library), and SPI and I2C are both enabled.

So you can change screens at any time in the web UI under **Config → Display**
without reinstalling. The choice is written to `config/shared_config.json`, which
is gitignored — it survives both reboots and `update_ragnar.sh`, so the screen
you select stays selected.

All 17 profiles are offered in both places:

| Type | Screens |
|---|---|
| e-Paper | `epd2in13`, `_V2`, `_V3`, `_V4`, `epd2in13b_V4`, `epd2in7`, `epd2in7_V2`, `epd2in9_V2`, `epd3in7`, `epd4in26` |
| TFT | `gc9a01` (1.28" round), `st7735s` (1.44" HAT + joystick), `whisplay` (1.69" PiSugar) |
| OLED | `ssd1306` (0.96") |
| Character LCD | `lcd1602` (16×2 I2C) |
| LED matrix | `max7219_8panel`, `max7219_4panel` |

In the web selector the e-Paper models are grouped by size (2.13", 2.7", …). If
your current driver already matches the size you pick, the exact variant is
kept — selecting "2.13"" on a box running `epd2in13_V4` leaves it on `_V4`
rather than resetting it.

If the install log ends with `These display types will NOT work until fixed:`,
that names the dependency that failed — a screen of that type will stay blank
until it is installed.

### 📶 Connecting Ragnar to a network

Ragnar looks for a saved network for about a minute at boot. If it cannot join
one, it starts its own access point:

| | |
|---|---|
| Network | `Ragnar` (`wifi_ap_ssid`) |
| Password | `ragnarconnect` (`wifi_ap_password`) |
| Setup page | `http://192.168.4.1:8000` |

Join it from a phone or laptop and enter the credentials for the network you
want. **The access point stays up until you use it** — it does not time out, so
it is still there whether you look after ten seconds or an hour.

This is also how you move a box between places. Take a Ragnar to a summer house
or an office, power it on, and it will fail to find your home network, raise the
`Ragnar` AP, and wait. Add the new network and it switches over.

Once at least one network is saved, the box keeps watching for it in the
background while the AP is up, and hands over on its own within about half a
minute of that network coming back in range — no reboot, and nothing to press.
That covers the everyday case of a router rebooting or the box booting faster
than the router.

Full details — when the AP does and does not start, how it recovers, and how a
USB Wi-Fi dongle lets the AP and the client connection run on separate radios —
are in the **[Ragnar AP Mode guide](RagnarAP.md)**.

> Ragnar's AP uses `192.168.4.0/24`. If your own router uses that range too —
> eero does by default — see the portal note below.

#### The Wi-Fi setup portal keeps appearing instead of the dashboard

If `http://<box>:8000` shows the **Wi-Fi Configuration Portal** asking you to
join a network — while the box is plainly already connected — your router hands
out addresses in **192.168.4.0/24**. That is the same range Ragnar uses for its
own access point, and Ragnar used to treat *any* client in it as an AP client
and serve the captive portal. **eero mesh systems default to this subnet**, so
they hit it consistently; it is not a fault in the router.

Ragnar now also requires that the box itself holds the AP gateway address
`192.168.4.1` before treating a request as an AP client, so an ordinary client
on a 192.168.4.0/24 LAN gets the dashboard. Update and restart:

```bash
sudo ./update_ragnar.sh && sudo systemctl restart ragnar
```

Note also that Ragnar listens on **port 8000 only** — plain `http://<box>` with
no port will not open anything. Always include `:8000`.

#### "dpkg was interrupted" — nothing installs

```
E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a'
```

This is a **system** state, not a Ragnar one, and it blocks *every* apt
operation until cleared — the main install, updates, and the Pwnagotchi
installer alike. Fix it with:

```bash
sudo dpkg --configure -a
sudo apt-get install -f -y
```

A Pi reaches this state when a package install is cut off part-way: the OOM
killer on a 512 MB board, a power loss, or Ctrl-C during one of the long silent
steps. It often surfaces later than it happened — the Pwnagotchi installer
failing is a common first symptom of a state broken during the main install.

`install_ragnar.sh`, `update_ragnar.sh` and `scripts/install_pwnagotchi.sh` all
detect and repair this automatically before their first apt call, so it should
no longer need doing by hand.

#### Updates in general

How updating works — from the web UI and the terminal — what happens to local
changes, what each error code on the update card means, and how to recover a box
by hand: **[Updating Ragnar](updates.md)**.

#### "No git command works" / updates fail

Check this first:

```bash
git --version
```

If that prints **Illegal instruction** (or nothing), git itself is broken — not
Ragnar. Debian Trixie arm64 can ship a git built with ARMv8.1+ atomics that
crashes on a Cortex-A53, which is the Pi Zero 2 W's core. Reinstall it:

```bash
sudo apt update && sudo apt install --reinstall git
```

This has a knock-on effect worth knowing about. The installer checks git up
front, and when it is unusable it downloads a release tarball instead of
cloning. That produces a complete, working Ragnar — but with **no `.git`
directory**, so every later update has no repository to update. If your box was
installed that way, nothing needs reinstalling: the web update check rebuilds the
metadata in place the first time it runs, and `update_ragnar.sh` or re-running
`install_ragnar.sh` do the same, keeping every file on disk.

Note that the up-front check only ever *stood in* for "git is broken". A stock
Raspberry Pi OS Lite or Debian image simply ships without git, and the installer
apt-installs it a few steps later — but the verdict had already been latched, so
those perfectly healthy boxes took the tarball path too and ended up unable to
update themselves. The installer now re-checks immediately before each clone and
installs git if it is merely missing, so only a genuinely crashing git (the
SIGILL case above) still falls back to a tarball.

Re-running the installer used to be a no-op here: it treats a directory
containing `actions/` as an existing install and skips the clone, so a tarball
tree stayed permanently without `.git`. Note that the installer never re-clones
over an existing directory — the path that would `rm -rf` it would take your
`data/` with it — so reattaching in place is the only safe repair.

#### Ragnar installed to the wrong directory

Ragnar always installs to `/home/ragnar/Ragnar`, and the `ragnar` user is
created if missing. If you find the tree somewhere else — `/home/Ragnar`, or
wherever you ran the installer from — you hit a bug in installers before this
fix, where a failure to enter `/home/ragnar` was ignored and the relative clone
landed in the current directory instead. Move it into place and re-run:

```bash
sudo systemctl stop ragnar.service
sudo mv /home/Ragnar /home/ragnar/Ragnar        # adjust the source path
sudo chown -R ragnar:ragnar /home/ragnar/Ragnar
sudo /home/ragnar/Ragnar/update_ragnar.sh
```

### 🧰 Manual Install

#### Step 1: Activate SPI & I2C

```bash
sudo raspi-config
```

- Navigate to **"Interface Options"**.
- Enable **SPI**.
- Enable **I2C**.

#### Step 2: System Dependencies

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install required packages

 sudo apt install -y \
  libjpeg-dev \
  zlib1g-dev \
  libpng-dev \
  python3-dev \
  libffi-dev \
  libssl-dev \
  libgpiod-dev \
  libi2c-dev \
  libatlas-base-dev \
  build-essential \
  python3-pip \
  wget \
  lsof \
  git \
  libopenjp2-7 \
  nmap \
  libopenblas-dev \
  bluez-tools \
  bluez \
  dhcpcd5 \
  bridge-utils \
  python3-pil


# Update Nmap scripts database

sudo nmap --script-updatedb

```

#### Step 3: ragnar Installation

```bash
# Clone the ragnar repository
cd /home/ragnar
git clone https://github.com/infinition/ragnar.git
cd ragnar

# Install Python dependencies within the virtual environment
sudo pip install -r requirements.txt --break-system-packages
# As i did not succeed "for now" to get a stable installation with a virtual environment, i installed the dependencies system wide (with --break-system-packages), it did not cause any issue so far. You can try to install them in a virtual environment if you want.
```

##### 3.1: Configure E-Paper Display Type
Choose your e-Paper HAT version by modifying the configuration file:

1. Open the configuration file:
```bash
sudo vi /home/ragnar/Ragnar/config/shared_config.json
```
Press i to enter insert mode
Locate the line containing "epd_type":
Change the value according to your screen model:

- For 2.13 V1: "epd_type": "epd2in13",
- For 2.13 V2: "epd_type": "epd2in13_V2",
- For 2.13 V3: "epd_type": "epd2in13_V3",
- For 2.13 V4: "epd_type": "epd2in13_V4",
- For 1.28" GC9A01 round TFT: "epd_type": "gc9a01",
- For 1.44" ST7735S LCD HAT (keys + joystick): "epd_type": "st7735s",
- For 0.96" SSD1306 OLED: "epd_type": "ssd1306",

You can also pick the display from the web UI under **Display settings** instead
of editing this file — that path auto-detects and restarts the service for you.

If your HAT has hardware controls (the 2.7" e‑Paper HAT's 4 keys, or the 1.44"
LCD HAT's 3 keys + joystick), see the
[Display Buttons & Joystick Reference](DISPLAY_CONTROLS.md) for what every key
does in each mode.

Press Esc to exit insert mode
Type :wq and press Enter to save and quit

#### Step 4: Configure File Descriptor Limits

To prevent `OSError: [Errno 24] Too many open files`, it's essential to increase the file descriptor limits.

##### 4.1: Modify File Descriptor Limits for All Users

Edit `/etc/security/limits.conf`:

```bash
sudo vi /etc/security/limits.conf
```

Add the following lines:

```
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
```

##### 4.2: Configure Systemd Limits

Edit `/etc/systemd/system.conf`:

```bash
sudo vi /etc/systemd/system.conf
```

Uncomment and modify:

```
DefaultLimitNOFILE=65535
```

Edit `/etc/systemd/user.conf`:

```bash
sudo vi /etc/systemd/user.conf
```

Uncomment and modify:

```
DefaultLimitNOFILE=65535
```

##### 4.3: Create or Modify `/etc/security/limits.d/90-nofile.conf`

```bash
sudo vi /etc/security/limits.d/90-nofile.conf
```

Add:

```
root soft nofile 65535
root hard nofile 65535
```

##### 4.4: Adjust the System-wide File Descriptor Limit

Edit `/etc/sysctl.conf`:

```bash
sudo vi /etc/sysctl.conf
```

Add:

```
fs.file-max = 2097152
```

### 🐝 Pwnagotchi Bridge

Running Ragnar and Pwnagotchi on the same SD card is now supported through a helper script plus new dashboard controls. The workflow is optional and completely disabled until you run the installer.

1. **Execute the installer as root inside the Ragnar repository:**
    ```bash
    cd /home/ragnar/Ragnar
    sudo ./scripts/install_pwnagotchi.sh
    ```
2. The script will:
    - Install the required apt packages (python3, libpcap-dev, hcxdumptool, etc.).
    - Upgrade `pip` when possible and install the `pwnagotchi` Python module system-wide.
    - Clone the upstream repo into `/opt/pwnagotchi` and generate `/etc/pwnagotchi/config.toml` plus plugin folders.
    - Drop `pwnagotchi.service` in `/etc/systemd/system/` but leave it disabled so Ragnar keeps control after installation.
    - Stream logs to `/var/log/ragnar/pwnagotchi_install_<timestamp>.log` and write a JSON status file at `data/pwnagotchi_status.json`.
3. **Use the web UI to manage swaps:** open the Ragnar dashboard → Config tab → *Pwnagotchi Bridge*.
    - *Install or Repair* re-runs the script in the background.
    - *Switch to Pwnagotchi* schedules a service hand-off (Ragnar stops, Pwnagotchi starts). Keep SSH open because the web UI becomes unreachable until you return.
    - *Return to Ragnar* brings the original service back (usually after rebooting out of Pwnagotchi).
4. A read-only card also appears in the Discovered tab showing the latest status, phase, and last switch timestamp so you can monitor the bridge while viewing loot.

Re-run the installer any time you need to refresh dependencies or repair a failed upgrade. It is idempotent: existing repos/configs are updated in place.

Apply the changes:

```bash
sudo sysctl -p
```

#### Step 5: Reload Systemd and Apply Changes

Reload systemd to apply the new file descriptor limits:

```bash
sudo systemctl daemon-reload
```

#### Step 6: Modify PAM Configuration Files

PAM (Pluggable Authentication Modules) manages how limits are enforced for user sessions. To ensure that the new file descriptor limits are respected, update the following configuration files.

##### Step 6.1: Edit `/etc/pam.d/common-session` and `/etc/pam.d/common-session-noninteractive`

```bash
sudo vi /etc/pam.d/common-session
sudo vi /etc/pam.d/common-session-noninteractive
```

Add this line at the end of both files:

```
session required pam_limits.so
```

This ensures that the limits set in `/etc/security/limits.conf` are enforced for all user sessions.

#### Step 7: Configure Services

##### 7.1: ragnar Service

Create the service file:

```bash
sudo vi /etc/systemd/system/ragnar.service
```

Add the following content:

```ini
[Unit]
Description=ragnar Service
DefaultDependencies=no
Before=basic.target
After=local-fs.target

[Service]
ExecStartPre=/home/ragnar/ragnar/kill_port_8000.sh
ExecStart=/usr/bin/python3 /home/ragnar/ragnar/ragnar.py
WorkingDirectory=/home/ragnar/ragnar
StandardOutput=inherit
StandardError=inherit
Restart=always
User=root

# Check open files and restart if it reached the limit (ulimit -n buffer of 1000)
ExecStartPost=/bin/bash -c 'FILE_LIMIT=$(ulimit -n); THRESHOLD=$(( FILE_LIMIT - 1000 )); while :; do TOTAL_OPEN_FILES=$(lsof | wc -l); if [ "$TOTAL_OPEN_FILES" -ge "$THRESHOLD" ]; then echo "File descriptor threshold reached: $TOTAL_OPEN_FILES (threshold: $THRESHOLD). Restarting service."; systemctl restart ragnar.service; exit 0; fi; sleep 10; done &'

[Install]
WantedBy=multi-user.target
```



##### 7.2: Port 8000 Killer Script

Create the script to free up port 8000:

```bash
vi /home/ragnar/ragnar/kill_port_8000.sh
```

Add:

```bash
#!/bin/bash
PORT=8000
PIDS=$(lsof -t -i:$PORT)

if [ -n "$PIDS" ]; then
    echo "Killing PIDs using port $PORT: $PIDS"
    kill -9 $PIDS
fi
```

Make the script executable:

```bash
chmod +x /home/ragnar/ragnar/kill_port_8000.sh
```


##### 7.3: USB Gadget Configuration

Modify `/boot/firmware/cmdline.txt`:

```bash
sudo vi /boot/firmware/cmdline.txt
```

Add the following right after `rootwait`:

```
modules-load=dwc2,g_ether
```

Modify `/boot/firmware/config.txt`:

```bash
sudo vi /boot/firmware/config.txt
```

Add at the end of the file:

```
dtoverlay=dwc2
```

Create the USB gadget script:

```bash
sudo vi /usr/local/bin/usb-gadget.sh
```

Add the following content:

```bash
#!/bin/bash
set -e

modprobe libcomposite
cd /sys/kernel/config/usb_gadget/
mkdir -p g1
cd g1

echo 0x1d6b > idVendor
echo 0x0104 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "fedcba9876543210" > strings/0x409/serialnumber
echo "Raspberry Pi" > strings/0x409/manufacturer
echo "Pi Zero USB" > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "Config 1: ECM network" > configs/c.1/strings/0x409/configuration
echo 250 > configs/c.1/MaxPower

mkdir -p functions/ecm.usb0

# Check for existing symlink and remove if necessary
if [ -L configs/c.1/ecm.usb0 ]; then
    rm configs/c.1/ecm.usb0
fi
ln -s functions/ecm.usb0 configs/c.1/

# Ensure the device is not busy before listing available USB device controllers
max_retries=10
retry_count=0

while ! ls /sys/class/udc > UDC 2>/dev/null; do
    if [ $retry_count -ge $max_retries ]; then
        echo "Error: Device or resource busy after $max_retries attempts."
        exit 1
    fi
    retry_count=$((retry_count + 1))
    sleep 1
done

# Check if the usb0 interface is already configured
if ! ip addr show usb0 | grep -q "172.20.2.1"; then
    ifconfig usb0 172.20.2.1 netmask 255.255.255.0
else
    echo "Interface usb0 already configured."
fi
```

Make the script executable:

```bash
sudo chmod +x /usr/local/bin/usb-gadget.sh
```

Create the systemd service:

```bash
sudo vi /etc/systemd/system/usb-gadget.service
```

Add:

```ini
[Unit]
Description=USB Gadget Service
After=network.target

[Service]
ExecStartPre=/sbin/modprobe libcomposite
ExecStart=/usr/local/bin/usb-gadget.sh
Type=simple
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Configure `usb0`:

```bash
sudo vi /etc/network/interfaces
```

Add:

```bash
allow-hotplug usb0
iface usb0 inet static
    address 172.20.2.1
    netmask 255.255.255.0
```

Reload the services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable systemd-networkd
sudo systemctl enable usb-gadget
sudo systemctl start systemd-networkd
sudo systemctl start usb-gadget
```

You must reboot to be able to use it as a USB gadget (with ip)
###### Windows PC Configuration

Set the static IP address on your Windows PC:

- **IP Address**: `172.20.2.2`
- **Subnet Mask**: `255.255.255.0`
- **Default Gateway**: `172.20.2.1`
- **DNS Servers**: `8.8.8.8`, `8.8.4.4`

---

## 📜 License

2025 - ragnar is distributed under the MIT License. For more details, please refer to the [LICENSE](LICENSE) file included in this repository.
