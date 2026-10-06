# blewatch — passive Bluetooth Low Energy attack monitor

`blewatch` (`python/blewatch.py`) is the **BLE counterpart to Ragnar's Wi-Fi /
Neighbor-Discovery spoofing watchers**. Where those tap a NIC, BLE is captured by
an **external sniffer** — an [Adafruit Bluefruit LE Sniffer](https://www.adafruit.com/product/2269)
(nRF51822) or any nRF-Sniffer device — and blewatch only **parses** the captured
BLE Link-Layer PDUs.

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
- **Self-test:** 19/19 (`python3 python/blewatch.py --self-test`).
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

# Which sniffer did we find? ($RAGNAR_BLE_SNIFFER overrides autodetect)
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

**Network → Diagnostics → Passive · wireless → BLE Watch.** The card is
**device-gated**: with no sniffer attached it says so plainly (not a red error)
rather than pretending to listen. HIGH/CRITICAL findings reach
[Watchtower](watchtower.md); the detector self-test is part of **validate
detectors** (`do_routing_selftest`). The standalone `blewatch.service`
(`scripts/blewatch.service`) runs it as an opt-in, least-privilege daemon.

## Hardware reality

The nRF51822 / Bluefruit LE Sniffer follows **one** connection at a time and
drops packets on busy advertising channels, so the **advertising-layer** findings
(`BLE-001`–`BLE-007`, `BLE-013`–`BLE-016`) are solid on it while the
**connection-layer** findings (`BLE-008`–`BLE-012`) are best-effort. For reliable
multi-connection capture, an nRF52-based sniffer or Ubertooth is the upgrade —
the parser and codes are unchanged; only the capture front end differs.
