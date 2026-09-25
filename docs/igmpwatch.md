# igmpwatch — passive IGMP snooping security monitor

`igmpwatch` is a standalone, **passive-first, detection-only** IGMP monitor — the
deep companion to the integrated [IGMP Watch](nettools.md#igmp-watch) inside
`network_diagnostics.py`. It sits on a SPAN/mirror and watches the multicast
**control plane** (IGMPv1/v2/v3) for storms, malformed/spoofed messages,
reconnaissance, querier hijack, and hosts joining groups they have no business
in — plus a **data-plane** rate sampler and an out-of-band **SNMP** tier.

It carries its own **pure-Python binary IGMP decoder** (no Scapy in the decode /
detect / eval path — the self-test runs with no Scapy and no NIC). Scapy is used
only for live capture.

- **Test floor:** Raspberry Pi Zero 2 W.
- **Self-test:** 79/79 (`python3 python/selftest.py` or `python3 -m igmpwatch --self-test`).
- **Deps:** Python 3.9+, Scapy (live capture only), pyyaml (config), net-snmp
  `snmpbulkwalk` (SNMP tier only).

## Passive by design

Zero transmit. The capture socket is RX-only with a kernel BPF of `ip proto 2`,
so non-IGMP frames never reach Python. There is deliberately **no active mode** —
sending a general query to enumerate group membership is exactly the recon
signature `igmpwatch` flags, so the sensor must never become the threat it
watches for.

`decode` slices the IGMP message out of the *original* frame bytes by IP
total-length (padding-safe) and parses it directly — not via scapy's IP binding,
which only binds IGMP at `ttl==1` and would hide spoofed off-link packets.
Detectors are read-only against shared state; the pipeline mutates state only
*after* they run, so e.g. querier-change logic compares against the prior querier.

## Detection matrix

| Module | Rule | Sev | Signal |
|---|---|---|---|
| flood | `multicast_storm` | HIGH | segment-wide IGMP rate over threshold |
| flood | `report_storm` / `query_storm` | HIGH | per-source report/query flood |
| flood | `leave_storm` | MED | per-source leave flood |
| flood | `join_leave_flap` | MED | (host,group) toggling — thrashes snooping |
| anomaly | `bad_checksum` | HIGH | corrupt/crafted message |
| anomaly | `bad_ttl` | HIGH | IGMP not TTL 1 → off-link injection |
| anomaly | `no_router_alert` | MED | query missing Router Alert |
| anomaly | `non_multicast_group` | HIGH | report/leave for a non-224/4 addr |
| anomaly | `reserved_group_report` | HIGH | membership asserted in 224.0.0.1/.2 |
| anomaly | `version_downgrade` | HIGH | v1/v2 query after v3 seen |
| anomaly | `truncated_v3` | MED | numgrp/length mismatch |
| recon | `spoofed_querier` | HIGH | query sourced from 0.0.0.0 |
| recon | `nonquerier_query` | HIGH | general query from a non-elected host |
| recon | `querier_takeover` | HIGH | lower-IP source that would win election |
| recon | `querier_contention` | MED | multiple query sources in a short window |
| recon | `group_scan` | HIGH | one source probing many groups |
| policy | `unauthorized_join` | HIGH | (enforce) join outside allowlist/baseline |
| policy | `sensitive_group_join` | HIGH | any unlisted join to a restricted group |
| policy | `ssm_source_denied` | MED | IGMPv3 INCLUDE source outside allowed set |
| policy | `new_group` | INFO | (learn) first observation of a group |
| dataplane | `mcast_storm` | HIGH | received multicast pps over threshold |
| dataplane | `mcast_flood_no_members` | HIGH | multicast on the wire with **no** subscribed data groups |
| dataplane | `mcast_ratio` | MED | multicast dominates the link |
| dataplane | `rx_drops` | MED | NIC `rx_dropped` climbing — ring overrun |
| snmp | `iface_mcast_storm` | HIGH | per-interface multicast pps over threshold |
| snmp | `unsubscribed_forwarding` | HIGH | switch forwards a group with no join seen |
| snmp | `census_not_forwarded` | LOW | join seen the switch's table omits (opt-in) |

Identity for policy is the **Ethernet source MAC**, not the IGMP source IP
(trivially 0.0.0.0 or spoofed). Pair with `macwatch`: a spoofed MAC inheriting an
allowed host's multicast privileges shows up there.

## Learn → enforce

Run `mode: learn` for a baseline window (`learn_window_s`, default 180 s). It
records observed (host, group) pairs, the elected querier, and every group. Flip
to `mode: enforce` (or `--enforce`) and any join outside the learned baseline /
allowlist alerts. Sensitive-group and querier/anomaly rules fire in both modes.

## Run

```bash
pip install scapy pyyaml --break-system-packages
sudo python3 -m igmpwatch -c igmpwatch.yaml            # or -i eth0
python3 -m igmpwatch --self-test                        # 79/79, no root

# validate a switch's SNMP OIDs in one shot (no root, no capture iface);
# also seeds the capability cache
python3 -m igmpwatch --snmp-probe --snmp-host 10.10.0.2 --snmp-community readonly \
    --db /var/lib/igmpwatch/igmpwatch.db
```

## Data-plane rate sampler

A lightweight sampler reads the NIC's kernel counters from
`/sys/class/net/<iface>/statistics` (`rx_packets`, `multicast`, `rx_dropped`),
turns successive reads into rates, and cross-references them against the live
IGMP subscriber census. Still passive — it only reads counters the kernel keeps,
opens no network handle, and imports no socket library (the self-test asserts
this). The standout is **`mcast_flood_no_members`**: sustained multicast on the
wire while **zero data groups are subscribed** — unregistered-multicast flooding,
a switch snooping failure, or injected traffic, which a join/leave/query view
can't see. Counter resets (iface bounce, wrap) re-prime silently.

## SNMP poller (off by default)

The sysfs sampler sees only the mirror port's aggregate rate. The switch keeps
the per-group and per-interface state; the SNMP poller reads it and ties it back
to the census, giving you *which egress port* and *which group* a flood is on
without putting the Pi inline. **Out-of-band**: it polls the switch's management
address, sends nothing on the mirrored segment, transmits no IGMP. Credentialed,
so **disabled by default** (`snmp.enable: true` + a `host`). Transport shells out
to net-snmp (`snmpbulkwalk`); an absent binary or unreachable switch degrades to
a silent no-op.

**Capability cache.** L2-only gear often populates `ifXTable` but returns an
empty `igmpCacheTable`. Each switch's verdict is cached with **strikes** (3
consecutive reachable-but-empty walks before "unsupported" — one empty read
during a lull isn't a verdict), **never on unreachable** (a transport problem
records nothing), and a **TTL** (default 1 h) that forces a re-check so a switch
that later gains an SVI is picked back up. `--snmp-probe` seeds the cache
directly (authoritative, no strikes), so a fleet sweep pre-configures every
switch. `--no-cache` reports without writing.

## Deploy (systemd)

`scripts/igmpwatch.service` runs least-privilege (`CAP_NET_RAW`/`CAP_NET_ADMIN`,
`ProtectSystem=strict`, `MemoryMax=128M`).

```bash
sudo install -Dm644 igmpwatch.yaml /etc/igmpwatch/igmpwatch.yaml
sudoedit /etc/igmpwatch/igmpwatch.yaml         # set iface: eth0
sudo cp scripts/igmpwatch.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now igmpwatch
```

## Sensor-interface hardening

The capture NIC should be a SPAN destination. Keep it quiet so the Pi's own
stack doesn't inject multicast into the mirror:

```bash
ip addr flush dev eth0                 # no IP on the capture leg
sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
# stop avahi/mdns on this NIC so the sensor isn't a multicast talker
```

## Storage

`events` (alerts, with rolled-up suppressed counts), `memberships`
(group↔host↔version↔sources), `queriers`, `hosts`, and `snmp_capabilities`.
Same DB conventions as the rest of the suite so multicast events correlate with
macwatch / arp_guard / DNS detections on a shared timeline.

## Relation to the integrated IGMP Watch

- **IGMP Watch** (`do_igmp_watch` in `network_diagnostics.py`) is the web-UI /
  Network-Integrity-Monitor path: a short `tcpdump` capture classified into the
  suite verdict ladder, with high-value crafted-message detectors added inline.
- **igmpwatch** is the standalone deep monitor: a binary decoder, the full
  control-plane detector matrix with learn→enforce, a data-plane sampler, an
  out-of-band SNMP tier with a capability cache, SQLite, and a hardened daemon.
