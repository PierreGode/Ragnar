# CardputerZero: Caps, GPIO header and camera — where to find them and how to use them

A how-to for the hardware you plug into (or find built into) an M5Stack
CardputerZero, and where each piece shows up in Ragnar's web UI. For the board
itself (screen, keyboard, battery, install) see
[M5Stack CardputerZero](M5StackCardputerZero.md).

---

## At a glance

| Hardware | Where in the web UI | What you can do |
|---|---|---|
| Any Cap, the 14-pin header | **System** → *CardputerZero hardware* | See which Cap is fitted, its radios, Cap power, and the live state of all 14 pins |
| GNSS (LoRa Cap) | **Wardriving** tab; state also under **System** → *CardputerZero hardware* | GPS position for wardriving and maps, with no USB GPS puck |
| GPS on the Grove port (e.g. M5Stack GPS Unit, no Cap) | **Wardriving** tab; state also under **System** → *CardputerZero hardware* | Same GPS for wardriving, maps and the Meshtastic node, straight from the Grove port |
| LoRa SX1262 (LoRa Cap) | **Network** → **Signal Intelligence** → **Mesh Nodes** | Run it as a Meshtastic node: node list, messages, map |
| Sub-GHz CC1101 (CC1101 Cap) | **Network** → **Signal Intelligence** → **RF Waterfall page** → *Sub-GHz (CC1101)* panel | Watch activity on 315 / 433 / 868 / 915 MHz |
| NFC ST25R3916 (CC1101 Cap) | Not in the UI | Not supported yet |
| Camera (built in) | **System** → *Camera*, and the **P** key on the CardputerZero itself | Live view, photos and videos, from the browser or on the device's own screen |

The two **System** panels only appear on a CardputerZero (the Camera panel on any
board with a camera). The *Sub-GHz (CC1101)* panel is always listed on the RF
Waterfall page and shows as not detected without the Cap.

---

## Before you start: fitting a Cap

**Caps are not hot-swappable.** M5Stack: "Hot-plugging Cap expansion modules is
not supported and may cause abnormal operation. Power off before installing or
removing a Cap."

1. Switch the CardputerZero **off**.
2. Fit the Cap on the 14-pin header on the top edge. Only one Cap fits at a time.
3. Switch it on and let Ragnar start.
4. Open **System** and scroll to **CardputerZero hardware**.

What you should see, for the LoRa Cap:

```
Cap power (5 V)   On
Cap               Cap LoRa-1262 + GNSS
Radio             SX1262 LoRa 868-923 MHz
Radio             ATGM336H GNSS
GNSS              Receiving on /dev/ttyS0
Camera            imx219 3280x2464
```

Ragnar identifies the Cap **once, when it starts**. The **Refresh** button updates
GNSS, camera and pin state; it does not look for a different Cap. To change Caps:
power off, swap, power on.

The same check from a shell (SSH or the Terminal tab):

```bash
sudo python3 /home/ragnar/Ragnar/cardputer_caps.py
```

```
Cap 5 V rail: on
Cap: Cap LoRa-1262 + GNSS
  - SX1262 LoRa 868-923 MHz
  - ATGM336H GNSS
  GNSS: 3 NMEA sentence(s) heard on /dev/ttyS0
Camera: imx219 (3280x2464)
```

If it says `Cap: none detected`, see [Troubleshooting](#troubleshooting).

---

## GNSS (the GPS in the LoRa Cap)

**Where:** the **Wardriving** tab uses it. Its state is also the *GNSS* row under
**System** → *CardputerZero hardware*.

**Setup:** none for the receiver. Ragnar powers the Cap at start and its GPS
auto-detection finds the receiver on `/dev/ttyS0` at 115200 baud.

### Example: wardrive with the Cap's GPS

1. If you have no **Wardriving** tab yet: **Config** → **Wardriving** → turn on
   **Enable Wardriving**.
2. Leave **GPS Serial Port** on `auto`. You do not need to change
   **GPS Baud Rate**; Ragnar uses the rate it detects.
3. Take the unit outside or to a window. The antenna is inside the Cap and needs
   a view of the sky. The first fix can take a few minutes.
4. Open **Wardriving** and start a session. The GPS indicator shows the fix and
   satellite count, and networks are logged with positions.
5. On the device itself, the wardriving screens (`Z` / `C` to page) include GPS
   and sky-view screens.

**What the GNSS row means**

| Row text | Meaning |
|---|---|
| Fix, 9 satellites | Working; position available |
| Connected, waiting for a fix | Receiver is talking; no position yet (needs sky) |
| In use by GPS | Ragnar's GPS reader has the port open |
| Receiving on /dev/ttyS0 | Data seen; GPS not started yet |
| Silent | Nothing on the serial port (Cap not powered or not seated) |
| A serial login prompt is using the port | Linux has a login prompt on the UART and it is taking the receiver's data; see below |

**If a serial login prompt has the port.** Many images put a login prompt on this
UART. Ragnar takes it off by itself when it finds the LoRa + GNSS Cap fitted, so
this row normally clears on its own a few seconds after start. If it stays, press
**Free the port for GPS** under the row, or from a shell:

```bash
sudo /home/ragnar/Ragnar/scripts/cardputer_hardware.sh gnss
```

Either way the prompt is stopped at once (no reboot needed, GPS can be started
right away) and `console=serial0` is removed from `cmdline.txt` so it stays away
after a reboot. The original file is kept as `cmdline.txt.ragnar-bak`;
`sudo scripts/cardputer_hardware.sh gnss-undo` puts it back. To stop Ragnar doing
this on its own, set `cardputer_free_gnss_uart` to `false`.

**Check from a shell**

```bash
# raw NMEA from the receiver (Ctrl+C to stop). Stop wardriving first:
# two readers on one port each get half the data.
sudo stty -F /dev/ttyS0 115200 raw && sudo cat /dev/ttyS0
```

You should see lines starting with `$GN` or `$GP`.

---

## GPS on the Grove port

You do not need the LoRa Cap to have GPS. The Grove port on the side is a UART
(Port C), so a plain UART GPS — for example the **M5Stack GPS Unit** (AT6668,
labelled *PORT.C.UART*) — plugs straight in and drives **wardriving** and the
**Meshtastic** node, exactly like the Cap's GNSS.

**Why it just works.** The Grove port's data lines are the UART the Cap's GNSS
also uses (`/dev/ttyS0`, reached through the Pi's `/dev/serial0` alias), so there
is only one thing to arrange: the serial login prompt that Linux puts on that
UART has to come off, or it eats the receiver's data. When you switch the Grove
rail on (see **Powering the Grove port** below), Ragnar does that the same way it
does for the Cap — it listens for a receiver on the UART, and when it hears NMEA
it hands the port to GPS (stops the login prompt, takes the serial console out of
`cmdline.txt`, keeping `cmdline.txt.ragnar-bak`). If nothing is heard, the login
prompt is left alone, so a unit with no Grove GPS keeps its serial console.

The login prompt can be named `serial-getty@ttyS0`, `@ttyAMA0` or `@serial0`
depending on the image, and the Grove UART can enumerate as `ttyS0` or `ttyAMA0`;
Ragnar tries all of them, so it finds and frees the prompt whatever it is called.

**"Source: serial" is correct.** The Grove port *is* a serial (UART) port, so
once the GPS is running the status reads `source: serial` (direct NMEA over the
serial port, as opposed to a `gpsd` daemon). That is the working state — there is
no separate "grove" GPS source. *Grove* is only the hardware-panel label telling
you where the serial GPS is plugged in.

**Powering the Grove port.** The Grove 5 V pin is **off by default** — the safe,
stock state. Plug the GPS in **with the port unpowered**, then switch the rail on:
**fn + Backspace** (the **del** key) on the Cardputer, or the **Grove 5 V** control
in *System → CardputerZero hardware*. Switching it on also kicks the GPS
detection, so the receiver is picked up within a few seconds — no restart. The
choice is saved (`cardputer_grove_power`), so if you leave it on it comes back on
at the next start.

> **Why off by default / connect with power off.** Switching a GPS (or any unit)
> onto a **live** Grove 5 V rail draws a current surge that can brown the board
> out for a moment — a black LCD or a battery-read-out glitch. Connecting while
> the rail is off, then switching it on, keeps that surge small and under your
> control. (Ragnar also rides a brief battery-gauge glitch out now — the icon
> keeps its last reading and recovers on its own rather than vanishing until a
> reboot.)

Once powered, leave **GPS Serial Port** on `auto` and **GPS Baud Rate** as it is —
Ragnar uses the rate it detects (an M5Stack GPS Unit is 9600). Within a minute the
GPS indicator in the **Wardriving** tab shows the fix, the Meshtastic node on this
unit gets the same fix (`meshtastic_share_gps`), and *System → CardputerZero
hardware* shows a **GPS (Grove port)** row.

> One UART, one receiver. The Grove GPS and a LoRa + GNSS Cap use the same port,
> so use one or the other. When a LoRa + GNSS Cap is fitted, Ragnar leaves the
> Grove probe alone and uses the Cap's GNSS.

**Switch it off:** set `cardputer_grove_gnss` to `false` to stop Ragnar probing
the Grove port and keep the serial login console; `true` always hands the UART
over (skip the listen). The master switch `cardputer_free_gnss_uart: false` keeps
the serial console for both the Cap and the Grove GPS.

**Check from a shell** (stop wardriving first):

```bash
# which prompt holds the UART, and what the port resolves to
systemctl list-units 'serial-getty@*' --all --no-legend ; ls -l /dev/serial0
# raw NMEA (serial0 is the safe alias for the Grove UART; M5 GPS Unit is 9600)
sudo stty -F /dev/serial0 9600 raw && sudo timeout 5 cat /dev/serial0
```

---

## LoRa (SX1262) as a Meshtastic node

**Where:** **Network** → **Signal Intelligence** → **Mesh Nodes** (opens the Mesh
Nodes page, which links to the Mesh Map).

**How this works without a Meshtastic board.** A normal Meshtastic node is a
small board running the Meshtastic firmware. The Cap is only the radio chip, so
the firmware runs on the CardputerZero instead:
[meshtasticd](https://meshtastic.org/docs/hardware/devices/linux-native-hardware/)
is the same Meshtastic firmware built for Linux, and it drives the SX1262
directly. The CardputerZero then *is* the node, and Ragnar connects to it at
`127.0.0.1` like it would to a node on USB. Until meshtasticd is set up, the
Mesh Nodes page has nothing to find.

**Setup:** the installer and the updater do it by themselves when the LoRa + GNSS
Cap is fitted (they add Meshtastic's package repository and install
`meshtasticd`; this needs internet). If the Cap was fitted later, or that step
failed, do it by hand, once. In **System** → **CardputerZero hardware**, the **Meshtastic**
row says *Not set up*; press **Set up Meshtastic** under it. It needs internet
and takes a few minutes. The row then reads *Running on this device*.

### Example: join the local Meshtastic mesh

1. Press **Set up Meshtastic** in the hardware panel, or run the same thing from
   a shell:

   ```bash
   sudo /home/ragnar/Ragnar/scripts/cardputer_lora_meshtastic.sh install
   ```

   It adds Meshtastic's package repository, installs `meshtasticd`, writes the
   radio settings for the Cap and starts the service.
2. Wait for the **Meshtastic** row to say *Running on this device*.
3. Set your region **once**. The radio stays silent until you do:

   ```bash
   meshtastic --host 127.0.0.1 --set lora.region EU_868
   ```

   Use the region for your country (`US`, `EU_868`, `ANZ`, …). Transmitting on
   the wrong band is illegal in most places.
4. In Ragnar: **Network** → **Signal Intelligence** → **Mesh Nodes**, then press
   **▶ Node**. With no USB Meshtastic device plugged in, Ragnar connects to the
   daemon on the CardputerZero itself.
5. Nodes heard on the mesh appear in the list; the Mesh Map shows those that
   share a position.

**Check and undo**

```bash
sudo /home/ragnar/Ragnar/scripts/cardputer_lora_meshtastic.sh status
sudo /home/ragnar/Ragnar/scripts/cardputer_lora_meshtastic.sh remove
journalctl -u meshtasticd -n 40          # the daemon's own log
```

**Good to know**

- **GPS for the node.** The Meshtastic daemon cannot read the Cap's GNSS itself:
  Ragnar reads that serial port, and two readers on one port corrupt both. So
  Ragnar hands its GPS fix to the node while the **Node** link is on (every two
  minutes, sooner when moving), and the node uses it as its own position. The
  device tag on the Mesh Nodes page says *GPS from Ragnar* once a fix has been
  handed over, or *waiting for GPS fix* (indoors, or just started). A node with
  a position broadcasts it to the mesh; switch the hand-over off with
  `meshtastic_share_gps: false` in the config if you do not want that.
- The **Mesh Nodes** button only appears once a Meshtastic source is available
  (the daemon running, or a USB node plugged in).
- `cardputer_lora_meshtastic.sh remove` is remembered: updates do not set it up
  again until you run `install` or press the button yourself.
- The Mesh Nodes page itself needs the `meshtastic` Python package, and its MQTT
  source needs `paho-mqtt`. Both are installed with Ragnar on every board.
- The script only writes two files: the radio's wiring for meshtasticd, and a
  start-up step that powers the Cap before the daemon opens the radio.
- LoRa and GNSS are on the same Cap and work at the same time.

---

## Sub-GHz (CC1101)

**Where:** **Network** → **Signal Intelligence** → **RF Waterfall page**, then the
**Sub-GHz (CC1101)** panel (the fourth panel).

**Setup:** none. Fit the CC1101 Cap with the power off and start Ragnar.

### Example: see who is transmitting around 433 MHz

1. Open the RF Waterfall page. The header shows `CC1101 · 300–928 MHz` with a
   green tag when the Cap is detected.
2. In the **Sub-GHz (CC1101)** panel choose **433** and press play (▶).
3. Press a 433 MHz remote (garage door, car key, weather station) nearby. A
   bright trace appears at its frequency, and **PEAK F** shows where.
4. Switch to **315**, **868** or **915**, or type a frequency in **TUNE**.

**What it is and is not**

- A stepped signal-strength sweep: the radio hops across the band and measures
  power at each step. It shows *that* something transmits and *where*, in steps
  of about 30 to 100 kHz depending on the band.
- It does not decode or record signals, and it never transmits.
- The chip tunes 300–348, 387–464 and 779–928 MHz. A span outside those, or one
  that crosses between them, is refused with a message.
- For decoding sub-GHz devices use an RTL-SDR and the *Sub-GHz ISM* panel on the
  same page.

**Check from a shell**

```bash
sudo python3 /home/ragnar/Ragnar/cc1101_scan.py 433
```

```
430.0-440.0 MHz, 257 steps: min -104 dBm, max -47 dBm at 433.906 MHz
```

---

## NFC (ST25R3916 on the CC1101 Cap)

Not supported yet: Ragnar has no driver for the reader, so there is nothing in
the UI. One preparation step exists, so the reader is reachable when a driver
arrives:

```bash
sudo /home/ragnar/Ragnar/scripts/cardputer_hardware.sh nfc   # then reboot
```

It enables the reader's SPI chip-select overlay. It needs M5Stack's image, which
ships that overlay.

---

## Camera

**Where:** **System** → **Camera** (shown when a camera is detected).

### Example: take a photo from the browser

1. Open **System** and scroll to **Camera**. The model shows top-right
   (`imx219 · 3280x2464`).
2. Press **Live view** to frame the shot. Press it again (**Stop live view**) when
   done; the camera switches off a few seconds after the last viewer leaves.
3. Press **Take photo**. The photo appears under **Photos**; click it to open it
   full size, or ✕ to delete it.

Photos are kept on the unit in `data/camera/` as `ragnar_YYYYMMDD_HHMMSS.jpg`.

### Where photos and videos are saved

Everything the camera takes, from the browser or from the device's own screen,
is saved on the unit in `data/camera/`. Open it under **Files** → **Camera**
(or press *Files → Camera* in the Camera panel): preview a photo, play a video,
download, rename, move or delete, like any other folder there. The **Photos**
and **Videos** lists in the Camera panel show the files that still carry
Ragnar's own names; a renamed or moved file stays in **Files** only.

### Example: record a video from the browser

1. Press **Record video**. The button turns into **Stop recording** and a timer
   runs. You can open the live view to watch what is being recorded.
2. Press **Stop recording**. The video appears under **Videos**.
3. It is first saved as an AVI and then converted to an MP4 in the background
   (the list says *converting to MP4…*). An MP4 plays right in the page, also on
   a phone. **Download** saves it; **Delete** removes it.

Videos are kept in `data/camera/` too, as `ragnar_YYYYMMDD_HHMMSS.mp4`.

### Example: use the CardputerZero as a camera

1. On the CardputerZero, press **P**. The screen shows what the camera sees, with
   **PHOTO** beside it.
2. Press **OK** to take a photo. *Taking photo...* shows while it is taken, then
   *Photo saved*.
3. Press **Z** or **C** to switch to **VIDEO**. **OK** starts recording (a red
   frame and a **REC** timer show), **OK** again stops it.
4. Press **Esc** or **P** to go back to Ragnar's screens. Leaving ends a video
   that is still recording.

Photos and videos taken on the device land in the same `data/camera/` folder and
show up under **System** → **Camera** in the browser.

### Picture upside down?

Press **Flip** in the Camera panel. The choice is saved (`camera_rotation`: `0`,
`180` or `auto`) and applies to the live view, photos, videos and the device
screen. On a CardputerZero `auto` already means 180°, because the sensor is
mounted upside down.

**From a shell**

```bash
python3 /home/ragnar/Ragnar/pi_camera.py /tmp/test.jpg
rpicam-hello --list-cameras          # what the system sees
```

**Good to know**

- Taking a photo while the live view runs pauses the view for the shot. While a
  video records, a photo is a frame of that video (640×480) so the recording is
  not interrupted.
- Live view is 640×480 at 10 frames a second, to stay light on a 512 MB board.
  Photos are 1640×1232. Videos are the live view: 640×480, about 8 to 10 frames
  a second, without sound.
- A video stops by itself after 10 minutes, or when less than 200 MB of disk is
  free. It takes roughly 25 MB a minute before conversion.
- Converting to MP4 needs `ffmpeg` (the installer puts it in place) and takes
  about twice the video's length on this board. Without `ffmpeg` the video
  stays an AVI: download it and play it with VLC.
- The camera is part of the CardputerZero itself, not of a Cap. It needs two
  things: the `rpicam-apps` tools, and `dtoverlay=imx219` in `config.txt` (this
  board's camera is not auto-detected). The installer and updater set up both;
  the overlay needs one reboot.
- When the camera is missing, the **Camera** row in the hardware panel says why
  (overlay not enabled, sensor did not answer, tools missing) and offers
  **Set up the camera** when that fixes it. By hand:
  `sudo /home/ragnar/Ragnar/scripts/cardputer_hardware.sh camera`, then reboot.

---

## The 14-pin header for your own hardware

**Where:** the *Expansion header* grid under **System** → *CardputerZero
hardware*. Each box is one pin, in the same two rows as the label on the case,
with its current function and level (`op hi` = output, high; `ip lo` = input,
low; `a0`/`a5` = in use by SPI, I²C or UART). A green border means the pin reads
high.

```
G26   G23   G22   G11   G10   G9    G7
5VIN  GND   5VOUT G2    G3    G14   G15
                  SDA   SCL   TX    RX
```

| Pin | Use | Free for your own GPIO? |
|---|---|---|
| G26, G23, G22 | Plain GPIO | Yes, when no Cap is fitted |
| G7 | SPI0 chip-select 1 (`/dev/spidev0.1`) | Yes, if you do not use SPI |
| G11, G10, G9 | SPI0 clock, MOSI, MISO | **No** — shared with the screen |
| G2, G3 | I²C bus 1 | For I²C devices only; shared with the board's own chips |
| G14, G15 | UART TX, RX (`/dev/ttyS0`) | Yes, if you do not use the UART |
| 5V OUT | Switched 5 V | Power for your module; on while Ragnar runs |

Signals are **3.3 V**. Wire with the power off, like a Cap.

### Example: blink an LED on G26

LED and a 330 Ω resistor between G26 and GND.

```bash
pinctrl set 26 op dh     # output, high: LED on
pinctrl set 26 op dl     # low: LED off
pinctrl get 26           # 26: op dl pd | lo // GPIO26 = output
```

The G26 box in the header grid follows within a few seconds.

### Example: read a switch on G23

Switch between G23 and GND.

```bash
pinctrl set 23 ip pu     # input with pull-up
pinctrl get 23           # "hi" when open, "lo" when pressed
```

### Example: find an I²C device

Connect SDA to G2, SCL to G3, plus 5V OUT (or your own 3.3 V) and GND.

```bash
sudo i2cdetect -y 1
```

Addresses already taken by the board: `0x34` keyboard, `0x4F` I/O expander,
`0x55` battery gauge, `0x32` clock, `0x68` motion sensor. `0x43` is the LoRa
Cap. Your device must use a different one.

### Example: talk to a serial device

TX of your device to G15 (RX), RX to G14 (TX), GND to GND.

```bash
sudo stty -F /dev/ttyS0 9600 raw
sudo cat /dev/ttyS0          # read
echo hello | sudo tee /dev/ttyS0   # write
```

If Ragnar's GPS is running it may claim the port; set **Config** → **Wardriving**
→ **GPS Serial Port** to your USB GPS, or stop wardriving, while you use the UART
for something else.

### Everything as data

```bash
sudo python3 /home/ragnar/Ragnar/cardputer_caps.py --json
```

or, from another machine, `GET http://<unit>:8000/api/cardputer/hardware`.

---

## Settings

All in `config/shared_config.json`; none of them is needed for normal use.

| Setting | Default | Effect |
|---|---|---|
| `cardputer_cap_power` | `true` | Switch the header's 5 V on at start. `false`: Ragnar leaves it alone, and a Cap stays unpowered |
| `cardputer_grove_power` | `false` | **Off by default** (the safe stock state): the Grove port's 5 V pin stays off at start, so nothing plugged in is powered until you ask. **fn** + **Backspace** (the **del** key), or the web control, switches it on — which also detects a Grove GPS — and saves the choice, so `true` here means it comes back on at the next start |
| `cardputer_free_gnss_uart` | `true` | With a GNSS receiver on the UART (the LoRa + GNSS Cap, or a GPS on the Grove port), take the serial login prompt off the UART so GPS can read it. `false`: Ragnar only reports it, and the serial console stays |
| `cardputer_grove_gnss` | `auto` | A UART GPS on the Grove port (no Cap). `auto` listens for it and hands over the UART when heard; `true` always hands over; `false` never (keeps the serial console) |
| `wardriving_gps_port` | `auto` | Which serial port the GPS reads. `auto` finds the Cap's GNSS or a Grove GPS |
| `wardriving_gps_baudrate` | `9600` | Fallback only; the detected rate wins |

---

## Troubleshooting

| What you see | Try |
|---|---|
| No *CardputerZero hardware* panel under **System** | The unit is not set up as a CardputerZero: **Config** → **Display** must be the CardputerZero LCD (installer option 7). |
| `Cap: none detected` | Power off, reseat the Cap, power on. Then `sudo python3 cardputer_caps.py`: "Cap 5 V rail: not present" means Ragnar cannot switch Cap power on this system image. |
| Cap fitted while running is not seen | Expected. Power off, fit it, power on. |
| GNSS says "Silent" | Cap not powered or not seated. Check *Cap power (5 V)* says On. |
| GNSS never gets a fix | Needs a view of the sky; wait several minutes outdoors the first time. |
| Meshtastic finds no LoRa | meshtasticd is not set up yet: press **Set up Meshtastic** in the hardware panel. If you set it up before this fix, press **Set up again** (the earlier radio settings named a chip-select pin the daemon could not use). |
| Mesh Nodes asks for a USB node although the LoRa Cap is fitted | The Cap's service is not running. Update Ragnar (older installs could not start it), or press **Set up again** in the hardware panel. Check: `sudo systemctl status meshtasticd`. |
| No **Mesh Nodes** button | The daemon is not running: `sudo scripts/cardputer_lora_meshtastic.sh status`. |
| Meshtastic node has no position | Press **▶ Node** in Mesh Nodes and wait for a GPS fix (outdoors, a few minutes after power-on). The tag shows *waiting for GPS fix* until then. The node gets the position from Ragnar, not from the GNSS directly. |
| **Camera** panel disappears now and then | Fixed: update Ragnar. A camera that was found now stays found. |
| Mesh Nodes connects but hears nothing | Region not set (step 3 above), or no Meshtastic traffic in range. |
| CC1101 tag says not detected | The LoRa Cap is fitted instead, or the CC1101 Cap was fitted with the power on. |
| CC1101 sweep stops with "never entered receive" | The radio did not lock; power-cycle the unit with the Cap fitted. |
| No **Camera** panel | Read the reason on the **Camera** row of the hardware panel. Usually: press **Set up the camera**, then reboot. |
| CC1101 waterfall is black but the readouts move | Fixed: the colour scale started at the wrong level for this radio. Reload the page; if you changed the scale yourself, open **Settings** on the panel and set Ref to -40, Range to 70. |
| GNSS says a login prompt is using the port | Press **Free the port for GPS** (see the GNSS section). |
| Live view stays black | Another program has the camera. Stop it, then press **Live view** again. |
| Screen freezes after pulling a Cap | That is the hot-plug problem. Power-cycle the unit. |

When reporting a problem, the output of these two commands says most of what is
needed:

```bash
sudo python3 /home/ragnar/Ragnar/cardputer_caps.py --json
journalctl -u ragnar -n 80 | grep -i -E "cardputer|cap|gps|camera|cc1101"
```
