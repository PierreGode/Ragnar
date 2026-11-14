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
| LoRa SX1262 (LoRa Cap) | **Network** → **Signal Intelligence** → **Mesh Nodes** | Run it as a Meshtastic node: node list, messages, map |
| Sub-GHz CC1101 (CC1101 Cap) | **Network** → **Signal Intelligence** → **RF Waterfall page** → *Sub-GHz (CC1101)* panel | Watch activity on 315 / 433 / 868 / 915 MHz |
| NFC ST25R3916 (CC1101 Cap) | Not in the UI | Not supported yet |
| Camera (built in) | **System** → *Camera* | Live view, take and keep photos |

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
| Serial console is using the port | The Linux serial console owns the UART; see below |

**If the serial console owns the port** (not the case on M5Stack's own image):

```bash
sudo /home/ragnar/Ragnar/scripts/cardputer_hardware.sh status
```

prints the exact command that frees it, followed by a reboot.

**Check from a shell**

```bash
# raw NMEA from the receiver (Ctrl+C to stop). Stop wardriving first:
# two readers on one port each get half the data.
sudo stty -F /dev/ttyS0 115200 raw && sudo cat /dev/ttyS0
```

You should see lines starting with `$GN` or `$GP`.

---

## LoRa (SX1262) as a Meshtastic node

**Where:** **Network** → **Signal Intelligence** → **Mesh Nodes** (opens the Mesh
Nodes page, which links to the Mesh Map).

**Setup:** one script, once. Ragnar drives the radio through
[meshtasticd](https://meshtastic.org/docs/hardware/devices/linux-native-hardware/),
Meshtastic's Linux daemon.

### Example: join the local Meshtastic mesh

1. Install `meshtasticd` if it is not there yet. The script in the next step tries
   `apt` once; if that fails, follow Meshtastic's guide linked above and come
   back.
2. Configure it for the Cap and start it:

   ```bash
   sudo /home/ragnar/Ragnar/scripts/cardputer_lora_meshtastic.sh install
   ```

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

- The **Mesh Nodes** button only appears once a Meshtastic source is available
  (the daemon running, or a USB node plugged in).
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

**From a shell**

```bash
python3 /home/ragnar/Ragnar/pi_camera.py /tmp/test.jpg
rpicam-hello --list-cameras          # what the system sees
```

**Good to know**

- Taking a photo while the live view runs pauses the view for the shot.
- Live view is 640×480 at 10 frames a second, to stay light on a 512 MB board.
  Photos are 1640×1232.
- The panel needs the `rpicam-apps` tools. The installer and updater add them; by
  hand: `sudo /home/ragnar/Ragnar/scripts/cardputer_hardware.sh`.

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
| `wardriving_gps_port` | `auto` | Which serial port the GPS reads. `auto` finds the Cap's GNSS |
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
| No **Mesh Nodes** button | The daemon is not running: `sudo scripts/cardputer_lora_meshtastic.sh status`. |
| Mesh Nodes connects but hears nothing | Region not set (step 3 above), or no Meshtastic traffic in range. |
| CC1101 tag says not detected | The LoRa Cap is fitted instead, or the CC1101 Cap was fitted with the power on. |
| CC1101 sweep stops with "never entered receive" | The radio did not lock; power-cycle the unit with the Cap fitted. |
| No **Camera** panel | `rpicam-hello --list-cameras` must list a camera. If the command is missing: `sudo scripts/cardputer_hardware.sh`. |
| Live view stays black | Another program has the camera. Stop it, then press **Live view** again. |
| Screen freezes after pulling a Cap | That is the hot-plug problem. Power-cycle the unit. |

When reporting a problem, the output of these two commands says most of what is
needed:

```bash
sudo python3 /home/ragnar/Ragnar/cardputer_caps.py --json
journalctl -u ragnar -n 80 | grep -i -E "cardputer|cap|gps|camera|cc1101"
```
