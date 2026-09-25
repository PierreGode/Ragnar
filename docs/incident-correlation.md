# Incident correlation — fusing alerts into attack chains

Ragnar has many sharp point detectors, and [Watchtower](watchtower.md) already
gathers their alerts into one normalized feed. But a flat feed is still a pile of
dots: a deauth here, a rogue RA there, a cert name-mismatch somewhere else. The
capability an enterprise NDR (Darktrace, Vectra, Cisco SecureNetwork) actually
sells is **fusion** — recognising that those dots are one campaign against one
victim, and saying so. `incident_engine.py` is that layer.

It is **pure analysis over already-collected alerts** — no capture, no I/O of its
own. It consumes the same Watchtower-normalized stream and produces *incidents*.

## How it correlates

1. **Entity clustering.** Every alert is mined for the network entities it is
   *about* — MACs, IPs, BSSIDs, SSIDs. Alerts that share an entity inside a
   sliding window (`incident_window_s`, default 600 s) are joined into one
   incident, **transitively**: if alert A shares the attacker MAC with incident
   X, and later alert B names both that MAC and a victim IP already in incident
   Y, X and Y fuse. Three detectors implicating one attacker is one story.
   Broadcast/multicast/unspecified addresses are never used as keys (they would
   collapse everything into one blob).

2. **Attack-chain recognition.** Each alert maps to an abstract *signal category*
   (`wifi_recon`, `wifi_dos`, `wifi_handshake`, `l2_spoof`, `rogue_gateway`,
   `dns_hijack`, `tls_intercept`, `routing_inject`, …). Categories — not raw
   detector codes — are what the pattern library is written against, so changing
   any single detector's codes never breaks correlation. An incident's
   accumulated categories are matched against named campaigns.

### Named campaigns

| Pattern | Signals it fuses | Severity |
|---|---|---|
| `evil_twin_handshake_capture` | rogue AP / deauth **+** WPA handshake/PMKID | critical |
| `wifi_handshake_harvest` | deauth **+** handshake/PMKID | critical |
| `pnl_impersonation` | PNL leak **+** rogue AP | high |
| `l2_mitm_tls` | ARP/L2 spoof **+** TLS interception (cert mismatch) | critical |
| `ipv6_mitm` | rogue RA / NA-spoof **+** DNS or TLS interception | critical |
| `rogue_first_hop` | rogue DHCP / RA **+** DNS hijack or redirect | critical |
| `routing_hijack` | OSPF/EIGRP/IS-IS/BGP injection | high |
| `halehound_multitool` | a HaleHound-class ESP32 CYD multitool verdict (`HH-CONFIRM`/`HH-LIKELY`/`HH-POSSIBLE`) — itself a multi-domain fusion of Wi-Fi/LAN/BLE signals (see [WiFi Defense → HaleHound](wifi-defense.md#halehound-cyd-correlation)) | critical |

A named match raises the incident's **confidence** and **severity** above any
single alert — a lone `medium` deauth is noise, but a deauth that shares a BSSID
with an evil-twin beacon and a captured handshake is a `critical` incident.

## Confidence

`0–100`, from three independent signals: **distinct detector sources** (two
detectors agreeing on one entity is far stronger than one firing twice),
**distinct signal categories**, and **a named pattern** (+40). A cluster that
spans ≥ 2 sources is treated as at least `high` even before it matches a pattern.

## Where it shows

- **Dashboard** — incidents lead the Watchtower card (they are the "so what"
  behind a cluster of alerts).
- **Diagnostics → Watchtower** — an incident list sits above the raw alert feed.
- **Pushover** — one page per incident when it first becomes a named campaign (or
  escalates), at/above `incident_notify_min_confidence` (default 50). The raw
  per-alert Watchtower page still fires independently; the incident page is the
  higher-signal one.

API: `GET /api/net/incidents?min_severity=&limit=&active_within=` →
`{success, enabled, window_s, summary, incidents[]}`.

## Config

| Key | Default | Meaning |
|---|---|---|
| `incident_correlation_enabled` | `true` | run the engine on the Watchtower stream |
| `incident_window_s` | `600` | entity-correlation sliding window (seconds) |
| `incident_notify_min_confidence` | `50` | page a named incident at/above this % |

## Self-test

```bash
python3 incident_engine.py --self-test        # 26/26 — no I/O, no daemons
python3 incident_engine.py --replay watchtower.jsonl   # replay a saved alert feed
```

The harness drives each named chain end-to-end (evil-twin capture, L2+TLS MITM,
rogue first-hop) plus the correlation invariants that keep it honest: unrelated
alerts on different entities stay **separate** incidents, a lone expired cert is
**not** a named campaign, alerts on the same entity but outside the window open a
**fresh** incident, and a bridging alert that names two entities **fuses** two
existing incidents into one.

## Honest limits

- It correlates on **entity + time**, not deep packet causality — it says "these
  alerts are about the same actor/victim and look like campaign X," not "packet A
  caused packet B."
- It is only as good as its inputs: an attack no detector saw cannot be
  correlated. It raises the value of the detectors you have; it does not add
  sight.
- Entity over-merge is bounded by the window and the broadcast/multicast skip
  list, but a very busy segment with one shared gateway could still cluster
  loosely — tune `incident_window_s` down if incidents feel too broad.
