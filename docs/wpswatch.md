# wpswatch

Passive WPS / Wi-Fi Simple Config posture and attack detector — part of the
Ragnar passive network security suite (`python/wpswatch.py`).

Answers two questions ordinary Wi-Fi tooling does not: **can this AP be enrolled
by someone in range, and is anyone trying right now.**

- Version: 1.0.0 · 22 finding codes · self-test 25/25
- Hardware floor: Raspberry Pi Zero 2 W · needs `CAP_NET_RAW` only
- Detection-only: derives no PINs, recovers no nonces, completes no enrollment
  (`--crack` is a documented no-op that says exactly this)

Built as a **separate module** from `legacywatch` on purpose: `legacywatch`
needs continuous channel dwell (airtime accounting), a WPS survey wants to sweep
the band — one module whose halves disagree about the radio is worse than two.
They share a monitor interface happily (both receive-only). wpswatch reuses
legacywatch's raw radiotap/802.11 parsers.

```sh
python3 python/wpswatch.py --self-test
python3 python/wpswatch.py --list-findings
```

## What it detects

**AP posture, from beacons/probe responses.** The WSC element an AP advertises
describes its own enrollment surface in plaintext — no association, no keys.

| Code | Sev | Meaning |
|---|---|---|
| `WPS-001` WPS_ENABLED | MED | WPS is on (the anchor; everything else says how exposed) |
| `WPS-002` WPS_PIN_METHOD_AVAILABLE | HIGH | Label/Display/Keypad — the external-registrar PIN path |
| `WPS-003` WPS_AP_NOT_LOCKED | HIGH | PIN offered **and** not locked → brute-forceable |
| `WPS-004` WPS_STATE_NOT_CONFIGURED | HIGH | out-of-box, enrollment wide open |
| `WPS-005` WPS_VERSION_1 | HIGH | no Version2 subelement ⇒ WSC 1.0, no mandatory lockout |
| `WPS-006` WPS_WEAK_NONCE_FAMILY | CRIT | model matches a documented weak-nonce family (screening hint) |
| `WPS-007` WPS_MAC_DERIVED_PIN_FAMILY | HIGH | family whose factory PIN derives from the BSSID |
| `WPS-008` WPS_REGISTRAR_ACTIVE | MED | an enrollment window is open right now |
| `WPS-009` WPS_UUID_MAC_DERIVED | MED | UUID-E embeds the BSSID |
| `WPS-010` WPS_AP_INFO_DISCLOSURE | LOW | serial/device name in every beacon |
| `WPS-011` WPS_PUSHBUTTON_ONLY | INFO | good posture (recorded for inventory) |
| `WPS-012` WPS_AP_LOCKED | INFO | good posture |
| `WPS-013` WPS_LOCK_STATE_CHANGED | MED | 0→1 = the AP locked *itself* (it was being hammered) — fires even for a baselined AP |
| `WPS-014` WPS_POSTURE_CHANGED | LOW | config methods / state / registrar differ from last observation |

The single most important signal is **not** "WPS is on" — it is the *absence*
of the Version2 subelement (`WPS-005`). The Version attribute `0x104A` is not a
substitute; nearly every AP advertises `0x10` there regardless of generation.

**Live sessions, from EAP-WSC.** WPS runs over EAPOL *before* any key exists, so
M1..M8 are readable on a WPA2 BSS by a keyless sensor. Message-type accounting
separates the two opposite attack shapes:

| Code | Sev | Meaning |
|---|---|---|
| `WPS-020` WPS_SESSION_OBSERVED | INFO | someone is enrolling |
| `WPS-021` WPS_BRUTE_FORCE_IN_PROGRESS | CRIT | high attempt rate **and** NACKs ≥ half (not a retrying printer) |
| `WPS-022` WPS_NACK_FLOOD | HIGH | NACKs keyed on the BSSID (catches MAC rotation) |
| `WPS-023` WPS_NONCE_HARVEST | HIGH | repeated M1–M3 abandoned before M4 (offline collection) |
| `WPS-024` WPS_AUTH_FAILURE_BURST | HIGH | EAP-Failure burst |
| `WPS-025` WPS_UNKNOWN_ENROLLEE | MED | enrollment from a station not in `known_enrollees` (empty list disables) |
| `WPS-026` WPS_ENROLLMENT_COMPLETED | MED | a station now holds the key |
| `WPS-027` WPS_SESSION_TABLE_PRESSURE | MED | session table evicting under load |

## Passive & detection-only

No transmit or exec primitives anywhere (verified: no `subprocess`/`socket`/
`send*`). It never sets monitor mode, channel or promiscuity — you prepare the
interface, it opens it read-only. The vulnerable-family tables map a model
string to a **risk note and nothing else**; there is no PIN, nonce model or
algorithm in the tree, and `--crack` only prints that fact.

## Config highlights

`baseline_wps_aps` suppresses posture findings for reviewed APs — but
**lock-state transitions still fire**, deliberately (an AP that locks itself is
evidence it was attacked). `known_enrollees` empty disables `WPS-025` rather
than alerting on everything. `vuln_families` is `[regex, note]` pairs that
*extend* (never replace) the built-in screen; a bad regex is dropped with a
warning. Full key list: `--list-findings` and the `DEFAULTS` in the source.

## CLI

```
--iface / --replay / --config / --jsonl / --enrich / --echo
--self-test / --list-findings / --version / --crack (no-op)
```

Prepare the interface yourself (a WPS survey wants band coverage; use an
external hopper such as isowatch's, or lock a channel):

```sh
sudo python3 python/wpswatch.py --iface wlan1 -o /var/log/ragnar/wpswatch-wlan1.jsonl
```

## Status / not yet built

Implemented: both evidence paths (WSC posture + EAP-WSC sessions), all 22
finding codes, raw-byte parsing, alert suppression, baseline/known-enrollee
handling, family screen, JSONL output, pcap replay, and the offline self-test
(25/25). Follow-on: a separate conformance harness, a `mac80211_hwsim` netns
lab, README-verifier and systemd unit files.
