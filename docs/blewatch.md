# blewatch — passive Bluetooth Low Energy attack monitor

`blewatch` (`python/blewatch.py`) is the **BLE counterpart to Ragnar's Wi-Fi /
Neighbor-Discovery spoofing watchers**. Where those tap a NIC, BLE is captured by
an **external sniffer** and blewatch only **parses** the captured BLE Link-Layer
PDUs. **Both nRF Sniffer generations are supported:**
- **nRF51** — [Adafruit Bluefruit LE Sniffer](https://www.adafruit.com/product/2269) (nRF51822)
- **nRF52** — nRF52840 Dongle / DK, or any nRF52-based nRF Sniffer

The bundled Nordic extcap emits the same BLE Link-Layer PDU for both, so the parser and
every finding are identical across them; only the device autodetect and the
capture quality differ (see [Hardware reality](#hardware-reality)).

**Detection only** — it never transmits a BLE packet or scans; the sniffer does
the RX. **Passive:** field extraction is a hand-rolled **raw-byte parser** over
the BLE Link-Layer PDU (no dissector), so `--self-test` and pcap `--replay` need
no radio and the self-test needs no Scapy. Findings carry a stable `BLE-0xx`
code; findings about one PDU are merged into a single alert (highest severity +
evidence).

| Wi-Fi / LAN attack | BLE equivalent blewatch catches |
|---|---|
| rogue AP / Evil Twin | **device clone** (`BLE-001`), **two radios one address** (`BLE-002`) |
| beacon / SSID spoof | **beacon UUID from a new address** (`BLE-005`), **GATT service masquerade** (`BLE-016`) |
| MAC reuse / identity churn | **public-address reuse across names** (`BLE-003`), **RPA rotation storm** (`BLE-004`) |
| deauth / beacon flood | **advertising flood** (`BLE-007`), **BLE-spam tooling** (`BLE-013`), **per-AdvA flood** (`BLE-006`) |
| ARP/ND MITM | **CONNECT_IND race** (`BLE-009`), **hijack attempt on a known device** (`BLE-008`) |
| downgrade / session attacks | **Just-Works pairing downgrade** (`BLE-011`), **version swap** (`BLE-010`), **forced re-pair** (`BLE-012`) |

- **Test floor:** Raspberry Pi Zero 2 W (parse/replay path; the sniffer is USB).
- **Self-test:** 34/34 (`python3 python/blewatch.py --self-test`), including the
  sniffer-detection probe and a DLT-272 cross-check against Nordic's own decoder.
- **Deps:** Python 3.8+. The parse/replay path is stdlib only. Live capture uses
  the **bundled** Nordic nRF Sniffer extcap (`python/nrf_sniffer/`) with
  `pyserial` + `psutil`, both already in Ragnar's requirements. Nothing to install.

## Findings (stable codes)

| Code | Sev | Fires when |
|---|---|---|
| `BLE-001` | high | known device AdvA advertising a changed identity (name/services) — clone |
| `BLE-002` | critical | one AdvA advertising conflicting payloads at once — two radios (impersonation) |
| `BLE-003` | high | one public address bound to conflicting device names (identity reuse) |
| `BLE-004` | medium | resolvable-private-address rotation storm (tracking evasion / adv churn) |
| `BLE-005` | high | trusted beacon UUID advertised from a new address (beacon spoof) |
| `BLE-006` | medium | advertising-interval collapse — beacon flood from one AdvA |
| `BLE-007` | high | advertising flood across many AdvAs (advertising-channel DoS) |
| `BLE-008` | high | CONNECT_IND targeting a known device (connection hijack attempt) |
| `BLE-009` | critical | duplicate CONNECT_IND racing a central for one device (connection MITM) |
| `BLE-010` | high | LL_VERSION_IND identity changed mid-connection (device swap) |
| `BLE-011` | high | pairing downgraded to Just-Works where baseline required MITM protection |
| `BLE-012` | high | repeated LL_TERMINATE_IND / reconnect for one device (forced re-pair window) |
| `BLE-013` | high | advertising flood matching BLE-spam tooling signatures |
| `BLE-014` | medium | malformed / truncated BLE PDU or over-running AD structure |
| `BLE-015` | low | manufacturer-specific data shape inconsistent with the claimed vendor |
| `BLE-016` | high | untrusted AdvA advertising a protected service-UUID set (GATT masquerade) |

## Capture link types

blewatch reads classic libpcap files (either endianness) and strips these DLTs
down to a BLE Link-Layer PDU:

| DLT | Name | Notes |
|---|---|---|
| 251 | `LINKTYPE_BLUETOOTH_LE_LL` | bare LE LL PDU (starts at the Access Address) |
| 256 | `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` | 10-byte BLE pseudo-header (channel/RSSI/CRC) + PDU — the canonical Wireshark BLE link type |
| 272 | `LINKTYPE_NORDIC_BLE` | what the nRF Sniffer extcap writes: board id + UART header + BLE header (flags/channel/RSSI) + PDU, protocol v1–v3 |

> **Validation note.** 256/251 are exercised by the self-test. 272 follows
> Nordic's `sniffer_uart_protocol.txt` and the self-test cross-checks it against
> the bundled `SnifferAPI.Packet` decoder for protocol v1, v2 and v3. The full
> live path (probe → bundled extcap → DLT-272 pcap → findings) was run against an
> emulated sniffer on a pty. It has **not yet been run against a physical
> sniffer** on the dev box.

## Usage

```sh
# Offline self-test (no radio, no root, no Scapy)
python3 python/blewatch.py --self-test

# What is plugged in? Lists every USB serial port and the firmware answering on it
# ($RAGNAR_BLE_SNIFFER overrides autodetect; --no-probe = never open a port)
python3 python/blewatch.py --list-devices

# Replay a capture taken in Wireshark + nRF Sniffer
python3 python/blewatch.py --replay capture.pcap --echo

# Live, autodetected sniffer, 30s, JSON-lines to a log
python3 python/blewatch.py --seconds 30 -c python/blewatch.example.json \
    --jsonl /var/log/blewatch/alerts.jsonl
```

Baseline **trusted devices**, **beacon UUIDs** and **protected services** in a
JSON config (`python/blewatch.example.json`): `trusted_devices` may be a bare
list of addresses or a map `addr → {name, services, mitm}`. A device whose
advertised name no longer matches its baseline, or a connection to it requesting
Just-Works where the baseline required MITM protection, is flagged even on the
first sighting.

In the web UI the trusted-device list lives in `data/ble_watch.json` and is
managed from the BLE Watch panel: **Trust current** adds every advertiser seen
in the last scan (address + name/services) to the list so they stop being
flagged as clones or GATT masquerades, and **Clear list** empties it. The scan
loads this list automatically, so no config path has to be passed on the web.

**Rotating addresses are skipped.** Phones, watches and most modern peripherals
advertise with a resolvable/non-resolvable *private* address that reshuffles
every ~15 minutes, so trusting one by address is pointless — the next scan sees
a different MAC. "Trust current" therefore only persists **stable** addresses
(`public` and random-`static`) and reports how many rotating ones it skipped;
otherwise the trusted list would grow without bound.

## In Ragnar (web)

**Network → Diagnostics → L2 tab → Passive · Bluetooth LE → BLE Watch.** The card is
**device-gated**: with no sniffer attached it says so plainly (not a red error)
rather than pretending to listen. HIGH/CRITICAL findings reach
[Watchtower](watchtower.md); the detector self-test is part of **validate
detectors** (`do_routing_selftest`). The standalone `blewatch.service`
(`scripts/blewatch.service`) runs it as an opt-in, least-privilege daemon.

## Hardware reality

Both generations run the **same parser and codes** — the difference is capture
quality:

- **nRF51** (Bluefruit LE Sniffer) follows **one** connection at a time and drops
  packets on busy advertising channels. The **advertising-layer** findings
  (`BLE-001`–`BLE-007`, `BLE-013`–`BLE-016`) are solid on it; the
  **connection-layer** findings (`BLE-008`–`BLE-012`) are best-effort.
- **nRF52** (nRF52840 Dongle/DK) is the better radio — more memory, follows
  connections more reliably and keeps up on busy channels, so the
  connection-layer findings are far more dependable. Prefer it if you have one.
- An **Ubertooth** is an alternative for heavy connection-following; again the
  parser and codes are unchanged, only the capture front end differs.

## Which board, and how to plug it in

**Plug the sniffer in normally. Don't hold any button, and switch position doesn't
matter.** Sniffer firmware ignores the CMD/DAT switch, which only affects the
Friend firmware. The DFU button is for Friend over-the-air updates, so don't hold
it either.

### Detection is by firmware, not USB name

The Adafruit **Bluefruit LE Sniffer** (#2269) has no USB identity of its own. It
enumerates only as a **Silicon Labs CP210x USB-to-UART bridge** (`/dev/ttyUSB0`,
by-id `usb-Silicon_Labs_CP2104_…`), as do its look-alike, the Bluefruit LE
**Friend**, and many ESP32 boards. So blewatch asks each candidate port
(CP210x, Nordic `1915:*` and SEGGER `1366:*` devices) what firmware it runs:

| Answer on the port | Verdict |
|---|---|
| SLIP-framed **PING_RESP** of the Nordic nRF Sniffer UART protocol (tried at 1 000 000 then 460 800 baud) | **nRF Sniffer** — used for capture; the firmware version is shown |
| `ATI` at 9600 baud → `BLEFRIEND…` / `nRF51822 …` / `OK` | **Bluefruit LE Friend**, which is **not a sniffer** (see below) |
| nothing | unknown CP210x device: wrong firmware, an ESP32/GPS, or a Friend in DAT mode |
| Nordic USB ID `1915:c00a` / `1915:521f` (read from sysfs, port not opened) | **nRF52 with other firmware**: Connectivity firmware or the DFU bootloader. **Not a sniffer yet** (see below) |

An nRF52840 dongle flashed with nRF Sniffer announces itself as "nRF Sniffer"
over USB and is accepted by name. The probe only writes those two read-only
requests. It never flashes anything or changes modes, and it skips ports that
another Ragnar component holds (GPS, CYD, Meshtastic, via `serial_claims`). A
CYD bridge only *listening* on a port, with no CYD answering, hands it over:
blewatch reserves each port for the probe and for the capture
(`serial_claims.take()`), so no other reader splits the byte stream.
During a live capture blewatch holds the port itself, so those components leave
it alone.

A port typed into the card's **device** field (or passed with `-i` /
`$RAGNAR_BLE_SNIFFER`) bypasses autodetect but is **still checked** before
capture. A Friend, a missing port, or a port held by another component stops
with that reason. A port that simply doesn't answer is still tried, because the
user chose it.

### "It only shows up as a CP210x" — Friend vs Sniffer

Check the silkscreen. A board labelled **"Bluefruit LE Friend"** is Adafruit's
AT-command UART module. It has the same nRF51822 hardware as the Sniffer, but its
firmware never streams packets, whatever the switch or button position. Ragnar
reports it as a Friend instead of saying "no sniffer". To turn it into a sniffer:

1. You can't do it with the DFU button or the Bluefruit app. The sniffer image
   replaces the bootloader and SoftDevice, so it must be flashed over **SWD**.
2. Wire a J-Link (or another nRF51-capable SWD probe) to the four pads on the
   back: **3V, GND, SWCLK, SWDIO**.
3. Fully erase the chip (`nrfjprog --eraseall -f NRF51`, or OpenOCD
   `nrf51 mass_erase`), then flash the **nRF51** sniffer hex. Use the Nordic
   nRF Sniffer release that Adafruit's sniffer guide links; newer Nordic
   releases target nRF52 boards.

The simpler route is a real Bluefruit LE Sniffer (#2269) or an **nRF52840
dongle** running nRF Sniffer. Keep the Friend for something else.

### nRF52840 dongle shows up as "nRF52 Connectivity"

The dongle is fine, but it's running the wrong firmware. `1915:c00a` /
`…nRF52_Connectivity…` is Nordic's **Connectivity** firmware, the image nRF
Connect for Desktop's Bluetooth app installs. Many nRF52840 USB dongles,
including USB-A clones of Nordic's PCA10059, ship with it. It never streams sniffed
packets. An nRF52840 running nRF Sniffer enumerates as **"nRF Sniffer for
Bluetooth LE"** instead, and Ragnar picks it up by itself.

To flash nRF Sniffer onto it:

1. Download **nRF Sniffer for Bluetooth LE 4.1.1** from Nordic. The image is
   `hex/sniffer_nrf52840dongle_nrf52840_4.1.1.hex`.
2. Press the dongle's **RESET** button (sideways on Nordic's own dongle; P0.18
   on the clones). The LED pulses red and the dongle re-enumerates as
   `1915:521f` "Open DFU Bootloader". Ragnar reports that state too.
3. Flash the hex with **nRF Connect Programmer**: select the dongle, add the
   file, then click **Write**.
4. Re-plug the dongle and run BLE Watch with the device field empty.

If RESET doesn't bring up `1915:521f`, the board has no Nordic DFU bootloader.
Flash the same hex over the **SWD** pads (SWDCLK/SWDIO/GND/3.3V) with a J-Link
or another SWD probe (`nrfjprog --program … --chiperase -f NRF52 --reset`).
Ragnar never flashes the dongle itself.

### Live capture: bundled Nordic extcap

Live capture drives Nordic's **nRF Sniffer for Bluetooth LE 4.1.1** extcap
(`nrf_sniffer_ble.py` + `SnifferAPI/`, MIT licence, `LICENSE.txt` alongside).
It is bundled in `python/nrf_sniffer/`, so no Wireshark plugin install is
needed. It records `seconds` of traffic to a temporary DLT-272 pcap, which
blewatch then replays through the detectors.

- **Works with both firmware generations:** 4.1.1 drives the Bluefruit LE
  Sniffer's **V2** firmware (nRF51, 460 800 baud) and the V3+ nRF52 builds
  (1 000 000 baud). Nordic's older V2-era extcap (`nrf_sniffer.py`) is
  **Python 2 only**, which is why it isn't used.
- **Ragnar change:** the helper splits its interface argument `PORT-VERSION` on
  `-`, which breaks on `/dev/serial/by-id/...` paths (the problem Adafruit's
  guide warns about). The bundled copy uses `rsplit('-', 1)`, and blewatch
  always passes the real tty (`/dev/ttyUSB0-4.1`).
- **Baud rate:** the one the probe found is passed with `--baudrate`, skipping
  the helper's slow rate discovery. `--scan-follow-rsp` is on, so scan
  responses (device names) are captured too.
- **If a capture fails:** the card shows the helper's exit reason, and Nordic's
  own log is at `/tmp/logs/log.txt`. `$RAGNAR_NRF_EXTCAP` points blewatch at a
  different extcap copy.

`$RAGNAR_BLE_SNIFFER` pins a specific `/dev/serial/by-id/...` path and skips
detection.
