# legacywatch

Passive 802.11 legacy-PHY, cipher-downgrade and airtime-attribution detector —
part of the Ragnar passive network security suite (`python/legacywatch.py`).

Answers the question ordinary Wi-Fi tooling does not: **which specific station
is making this cell slow, by MAC (and name), and by how much** — plus the
encryption/PHY posture that caps the whole BSS.

- Version: 1.0.0 · 22 finding codes · self-test 33/33
- Hardware floor: Raspberry Pi Zero 2 W · needs `CAP_NET_RAW` only
- Detection-only, receive-only: never transmits, never touches radio state

Run the offline self-test (no root, no Scapy, no radio):

```sh
python3 python/legacywatch.py --self-test
python3 python/legacywatch.py --list-findings
```

## What it detects

Three layers, cheapest first.

**1. The AP confesses (from beacons).**

| Code | Sev | Meaning |
|---|---|---|
| `LEG-001` NONERP_STA_PRESENT | HIGH | ERP element says a non-ERP (802.11b) STA is on the BSS |
| `LEG-002` ERP_PROTECTION_ACTIVE | HIGH | ERP Use_Protection — every OFDM frame pays CTS-to-Self (~212 µs) |
| `LEG-003` BARKER_PREAMBLE_REQUIRED | MED | long (Barker) preamble forced |
| `LEG-004` HT_PROTECTION_MIXED | HIGH | HT Operation Protection = Non-HT Mixed |
| `LEG-006` BSS_ADMITS_11B | MED | basic-rate set still contains CCK rates |
| `LEG-007` BSS_NO_HT_CAPABILITY | HIGH | the AP itself is pre-802.11n |
| `LEG-008` LONG_SLOT_TIME | MED | 20 µs slot time on 2.4 GHz |

**2. Cipher as a throughput problem.**

| Code | Sev | Meaning |
|---|---|---|
| `LEG-010` BSS_OPEN | HIGH | no encryption |
| `LEG-011` BSS_WEP | CRIT | broken cipher **and** no HT rates (54 Mbps cap) |
| `LEG-012` BSS_WPA1_ONLY | HIGH | WPA1/TKIP only — 54 Mbps cap |
| `LEG-013` GROUP_CIPHER_TKIP | HIGH | TKIP group cipher disables 11n for group frames BSS-wide |
| `LEG-014` PAIRWISE_TKIP_OFFERED | MED | a client selecting TKIP caps at 54 Mbps |
| `LEG-015` WPA_WPA2_MIXED | MED | transitional WPA/WPA2 |
| `LEG-016` MFP_ABSENT | LOW | no management frame protection |

**3. Per-station attribution.**

| Code | Sev | Meaning |
|---|---|---|
| `LEG-020` CLIENT_11B_ONLY | HIGH | an 802.11b station, named |
| `LEG-021` CLIENT_11G_ONLY | MED | a pre-802.11n a/g station |
| `LEG-022` CLIENT_LEGACY_RATE_STUCK | MED | HT-capable but stuck on legacy rates (RF/coverage, not inventory) |
| `LEG-023` CLIENT_AIRTIME_DISPROPORTIONATE | HIGH | the culprit — airtime share ≫ byte share |
| `LEG-024` CLIENT_HIGH_RETRY_LEGACY | MED | high retries at legacy rates |
| `LEG-025` CLIENT_NO_AGGREGATION | LOW | no A-MPDU (pre-802.11n) |
| `LEG-026` CLIENT_IDENTITY_DISCLOSED | INFO | a device name leaked in a WPS/P2P element |
| `LEG-027` CLIENT_TABLE_PRESSURE | MED | station table evicting under load |

## Accuracy model

The parser was written to avoid the classic 802.11 attribution traps:

- **Both directions.** Airtime is attributed to the *station*, resolved from the
  ToDS/FromDS bits (uplink `addr2`, downlink `addr1`) — not `addr2` alone, which
  undercounts a legacy station by ~half and misfiles its downlink onto the AP.
- **PHY from data frames only.** Management/control frames ride at basic rates
  even on modern clients, so a Wi-Fi 6 phone probing at 1 Mbps is not mislabeled.
- **Declared beats observed.** A station's own (re)assoc/probe request declares
  its capability (HT/VHT/HE element present ⇒ `n+`; absent ⇒ pre-n). Each finding
  carries `confidence` = `declared` or `observed`.
- **Preamble-accurate airtime.** PPDU = PHY preamble + data-symbol time; a
  1 Mbps DSSS frame is 192 µs preamble + payload (1500 B ⇒ 12 192 µs).
- **Disproportion.** airtime-share ÷ byte-share is the number that names the
  culprit (`LEG-023`).

## Identity without keys

Precedence, strongest first: `inventory` CSV (`--enrich mac,hostname[,note]`) →
`wps` device name → `p2p` device name → `oui` vendor (`--oui-csv`, MA-L/M/S,
longest-prefix first). On an encrypted BSS the WPS/P2P element in a probe/assoc
request is often the only name available without touching the controller.

## Station table

Three segments — eviction is treated as detection logic, not memory hygiene: a
plain LRU would let anyone mint throwaway MACs and push the real legacy station
out. `probation` (first sighting, LRU) → `protected` (2nd sighting or legacy
classification, LRU, capped independently) → `pinned` (operator, never evicted).
`LEG-027` fires on eviction pressure.

## CLI

```
--iface        live monitor-mode interface (root / CAP_NET_RAW)
--replay       replay a radiotap pcap instead
--config       JSON config
--jsonl / -o   JSON-lines output ('-' = stdout) — the Watchtower feed
--oui-csv      IEEE registry CSV
--enrich       inventory CSV (mac,hostname[,note])
--echo         echo alerts to stderr
--self-test / --list-findings / --version
```

You prepare the interface yourself (legacywatch never sets monitor mode or
channel — that would need `CAP_NET_ADMIN` and break the passive guarantee):

```sh
sudo ip link set wlan1 down && sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up  && sudo iw dev wlan1 set channel 6
sudo python3 python/legacywatch.py --iface wlan1 -o /var/log/ragnar/legacywatch-wlan1.jsonl
```

## Validation & deployment

| Tier | Command | Result |
|---|---|---|
| self-test | `python3 python/legacywatch.py --self-test` | 33/33 |
| conformance | `python3 python/legacywatch_conformance.py` | 35/35 |
| replay (real Scapy path) | `lab/make_lab_pcap.py legacy … && --replay` | 10 codes observed |
| live lab (hwsim) | `sudo lab/hwsim_lab.sh legacy` | written, hardware-gated (see `lab/LAB.md`) |

- **Watchtower**: emits JSONL to `/var/log/legacywatch/alerts.jsonl`, wired into
  `watchtower.py` (`DEFAULT_SOURCES['legacywatch']`) so alerts land in the
  unified feed.
- **systemd**: `scripts/legacywatch.service` (dedicated `legacymon` user,
  `CAP_NET_RAW` only, `systemd-analyze verify` clean); config
  `python/legacywatch.example.json`.

Not implemented: `LEG-005` (OBSS non-HT — needs cross-BSS correlation better
suited to `isowatch`) and a README-verifier. The hwsim live lab is written but
not yet run (the dev box has no wireless stack).
