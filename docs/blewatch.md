# blewatch — passive Bluetooth Low Energy attack monitor

`blewatch` (`python/blewatch.py`) is the **BLE counterpart to Ragnar's Wi-Fi /
Neighbor-Discovery spoofing watchers**. Where those tap a NIC, BLE is captured by
an **external sniffer** and blewatch only **parses** the captured BLE Link-Layer
PDUs. **Both nRF Sniffer generations are supported:**
- **nRF51** — [Adafruit Bluefruit LE Sniffer](https://www.adafruit.com/product/2269) (nRF51822)
- **nRF52** — nRF52840 Dongle / DK, or any nRF52-based nRF Sniffer

The vendor extcap emits the same BLE Link-Layer PDU for both, so the parser and
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
- **Self-test:** 27/27 (`python3 python/blewatch.py --self-test`), including the
  sniffer-detection probe logic.
- **Deps:** Python 3.8+ (stdlib only). Live capture needs the **Nordic nRF
  Sniffer for Bluetooth LE** extcap helper (`nrf_sniffer_ble.py`); the
  parse/replay path needs nothing.

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
| 272 | `LINKTYPE_NORDIC_BLE` | Nordic sniffer header + PDU — parsed **best-effort** |

> **Hardware-validation note.** The 256/251 paths are fully exercised by the
> self-test. The Nordic (272) header layout is version-dependent and is parsed
> best-effort; it is **unvalidated against a real sniffer** on the dev box (none
> attached). If a live capture mis-parses, capture to a pcap in Wireshark with
> the nRF Sniffer plugin (DLT 256) and use `--replay`.

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

An nRF52840 dongle flashed with nRF Sniffer announces itself as "nRF Sniffer"
over USB and is accepted by name. The probe only writes those two read-only
requests. It never flashes anything or changes modes, and it skips ports that
another Ragnar component holds (GPS, CYD, Meshtastic, via `serial_claims`).
During a live capture blewatch holds the port itself, so those components leave
it alone.

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

### Live capture needs the Nordic extcap

Live capture drives Nordic's `nrf_sniffer_ble.py` Wireshark extcap. Unzip
the nRF Sniffer release's `extcap/` folder into `~/.config/wireshark/extcap/` (or
the system extcap directory, e.g. `/usr/lib/aarch64-linux-gnu/wireshark/extcap/`
on a Pi) and `pip install -r requirements.txt` from that folder. Without it the
card says the helper is missing, and `--replay` of a Wireshark capture still
works.

`$RAGNAR_BLE_SNIFFER` pins a specific `/dev/serial/by-id/...` path and skips
detection.
