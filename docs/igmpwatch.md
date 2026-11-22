# igmpwatch

Passive IGMP **and MLD** snooping security monitor for the Pi Zero 2W sensor suite. Sits on
a SPAN/mirror and watches the multicast **control plane** (IGMPv1/v2/v3) for
storms, malformed/spoofed messages, reconnaissance, querier hijack, and hosts
joining groups they have no business in.

Same shape as `macwatch` / `arp_guard`: layered pipeline, SQLite persistence,
systemd unit, Scapy self-test harness (**37/37**).

## Passive by design

Zero transmit. The capture socket is RX-only with a kernel BPF of `ip proto 2`,
so non-IGMP frames never reach Python. There is deliberately **no active mode** —
sending a general query to enumerate group membership is exactly the recon
signature `igmpwatch` flags, so the sensor must never become the threat it
watches for. This is the persistent passive floor; no cued active bursts here.

## Pipeline

```
sniff(BPF ip proto 2) -> decode -> [4 detectors] -> alert(dedup) -> state.apply
                                         |                              |
                                    read-only                     SQLite + JSONL
```

`decode` slices the IGMP message out of the *original* frame bytes by IP
total-length (padding-safe) and parses it directly — not via scapy's IP binding,
which only binds IGMP at `ttl==1` and would otherwise hide spoofed off-link
packets. Detectors are read-only against shared state; the pipeline mutates state
only *after* they run, so e.g. querier-change logic compares against the prior
querier.

Framing is length-bounded on purpose: the IGMP message is sliced by the IP
total-length field, so the kernel's pad-to-60B is never parsed as IGMP (which
would otherwise fail the checksum and fire a false `bad_checksum`), and the v3
record walk is bounded by `numgrp`, not buffer length. Non-zero bytes trailing a
valid message — data smuggled in the padding — are surfaced as
`anomaly.trailing_data` rather than silently dropped. When the IP length field
is unusable (NIC offload zeroed it), the message is re-bounded by its own IGMP
structure, never by raw length. A captured 4-byte FCS tail is tolerated; on an
FCS-stripped SPAN (the norm) any non-zero tail is flagged.

## Detection matrix

| Module | Rule | Sev | Signal |
|---|---|---|---|
| flood | `multicast_storm` | HIGH | segment-wide IGMP msg rate over threshold |
| flood | `report_storm` / `query_storm` | HIGH | per-source report/query flood |
| flood | `leave_storm` | MED | per-source leave flood |
| flood | `join_leave_flap` | MED | (host,group) toggling — thrashes snooping table |
| anomaly | `bad_checksum` | HIGH | corrupt/crafted message |
| anomaly | `bad_ttl` | HIGH | IGMP not TTL 1 → off-link injection |
| anomaly | `no_router_alert` | MED | v2/v3 query missing Router Alert |
| anomaly | `non_multicast_group` | HIGH | report/leave for a non-224/4 addr |
| anomaly | `reserved_group_report` | HIGH | membership asserted in a reserved control group (224.0.0.1/.2, ff02::1/2) |
| anomaly | `version_downgrade` | HIGH | v1/v2 query after v3 seen → defeats SSM filtering |
| anomaly | `truncated_v3` | MED | numgrp/length mismatch |
| anomaly | `trailing_data` | MED | non-zero bytes after the IGMP message — data smuggled in frame padding |
| cve | `invalid_record_type` | HIGH | **IGMPW-001** / CVE-2025-50681 (7.5) — report with out-of-range group record type |
| cve | `query_source_overrun` | HIGH | **IGMPW-002** / CVE-2026-53275 (8.8) — query declares more sources than carried |
| cve | `fragmented_membership` | HIGH | **IGMPW-003** / CVE-2019-5608 (9.8) — fragmented membership message |
| posture | `ssm_version_mismatch` | MED | **IGMPW-P01** / RFC 4604 — IGMPv1/v2 or MLDv1 membership in the SSM range |
| recon | `spoofed_querier` | HIGH | query sourced from 0.0.0.0 |
| recon | `nonquerier_query` | HIGH | general query from a non-elected host |
| recon | `querier_takeover` | HIGH | lower-IP source that would win querier election |
| recon | `querier_contention` | MED | multiple query sources in a short window |
| recon | `group_scan` | HIGH | one source probing many groups (enumeration) |
| policy | `unauthorized_join` | HIGH | (enforce) join outside allowlist/baseline |
| policy | `sensitive_group_join` | HIGH | any unlisted join to a restricted group |
| policy | `ssm_source_denied` | MED | IGMPv3 INCLUDE source outside allowed set |
| policy | `new_group` | INFO | (learn) first observation of a group |
| dataplane | `mcast_storm` | HIGH | received multicast pps over threshold |
| dataplane | `mcast_flood_no_members` | HIGH | multicast on the wire with **no** subscribed data groups |
| dataplane | `mcast_ratio` | MED | multicast dominates the link (fraction of rx) |
| dataplane | `rx_drops` | MED | NIC `rx_dropped` climbing — ring-buffer overrun / storm symptom |
| snmp | `iface_mcast_storm` | HIGH | per-interface in/out multicast pps over threshold (switch counters) |
| snmp | `unsubscribed_forwarding` | HIGH | switch forwards a group igmpwatch never saw a join for |
| snmp | `census_not_forwarded` | LOW | igmpwatch saw a join the switch's group table doesn't list (opt-in) |

Identity for policy is the **Ethernet source MAC**, not the IGMP source IP
(which is trivially 0.0.0.0 or spoofed). Pair with `macwatch`: a spoofed MAC
inheriting an allowed host's multicast privileges shows up there, so the two
modules together close the "spoof-then-subscribe" gap.

## MLD (IPv6) support

The same engine decodes MLD — the IPv6/ICMPv6 parallel to IGMP — so an IPv6 or
dual-stack segment gets identical coverage. MLDv1 (RFC 2710) maps onto the v2
detection model (report/done/query) and MLDv2 (RFC 3810) onto v3 (source lists,
SSM, records). The wire format differs — ICMPv6 types 130/131/132/143 carried
behind a Hop-by-Hop Router Alert — so decode validates the ICMPv6 checksum over
the IPv6 pseudo-header, bounds the message by the IPv6 payload length (same
padding/trailing discipline as IGMP), and parses MLDv2 records from raw bytes
(scapy under-parses consecutive records). MLDv2 report records are bounded by
the record count, not buffer length.

State is **per address family**: querier election, segment-version tracking, and
the downgrade check are tracked separately for IPv4 and IPv6, so an IGMPv3 report
never arms an MLD downgrade alert and vice-versa. All the flood, recon, anomaly,
and policy rules apply to both; alerts carry `family`/`protocol` so IGMP and MLD
findings are distinguishable on the shared timeline. Hop-limit-1, Router-Alert,
reserved-group (ff02::1/2), and spoofed-querier (`::`) checks are all MLD-aware.

MLD rides in on `icmp6` in the capture filter (the kernel can't cheaply match
past the Hop-by-Hop header, so non-MLD ICMPv6 is dropped in decode). Set
`mld.enable: false` to decode IGMP only, or `capture_filter` to override the BPF.

## CVE trigger-shape detection

Three documented CVEs have wire-observable trigger shapes that this module's
existing parse already exposes. Each is a **finding code**, config-gated under
`cve:`, and each runs on **both address families** regardless of which family the
CVE was filed under — the malformation class is what matters, not the CVE's
originating stack.

| Code | CVE | CVSS | Trigger shape observed |
|---|---|---|---|
| IGMPW-001 | CVE-2025-50681 | 7.5 | Membership report carrying a group record type outside 1–6. igmpproxy's `recv_igmp()` passes it to `inet_fmtsrc()` and NULL-derefs. Checked on IGMPv3 **and** MLDv2 reports. |
| IGMPW-002 | CVE-2026-53275 | 8.8 | Query whose declared source count implies more bytes than the packet carries. Drives the `pskb_may_pull()` realloc after which the Linux MLD path dereferences a stale group-address pointer. Checked on MLDv2 **and** IGMPv3 queries. |
| IGMPW-003 | CVE-2019-5608 | 9.8 | A fragmented membership message. IGMP/MLD are fixed-footprint link-local control traffic and are never conformantly fragmented; FreeBSD's ICMPv6 input mishandled an MLDv2 query split across mbufs. Checked on IP fragments **and** IPv6 Fragment headers. |

**What a hit means.** These rules detect that a packet matching the published
malformation crossed the segment. They do **not** confirm the receiver is
unpatched, nor that exploitation succeeded — igmpwatch never probes a target to
find out. Treat a hit as "someone put this shape on the wire", which on a
production segment is itself the actionable signal.

Non-first fragments are handled as a special case: those bytes are a message
*tail* with no IGMP/MLD header, so the checksum can't be computed over them and
content rules are skipped (otherwise every fragment tail would fire
`bad_checksum`). The fragmentation itself is still reported via IGMPW-003.

Two CVEs were evaluated and **rejected**: CVE-2018-0292 (8.8, NX-OS IGMP snooping
RCE) has no published malformation to key on — any detector would be a guess; and
CVE-2015-4324 (NX-OS IGMPv3 source-count/allocation mismatch) scores 6.1, below
the 6.5 floor, and its artifact is already caught by `anomaly.truncated_v3`
without a CVE badge.

## Posture: RFC 4604 SSM version conformance

`IGMPW-P01` (`posture.ssm_version_mismatch`, MEDIUM) flags an IGMPv1/IGMPv2 or
MLDv1 **report or leave/done** naming a group in the source-specific multicast
range — IPv4 `232.0.0.0/8` or IPv6 `ff3x::/32`.

RFC 4604 requires IGMPv3/MLDv2 for SSM groups, because only those versions carry
the source list that makes delivery source-specific. A pre-v3 message asserts
any-source membership in a range where no source filter can be expressed, so a
router honouring it delivers traffic from *any* source to that group. That is
both what legacy or misconfigured stacks do by accident and what an attacker
wants from a downgrade: the source filtering the operator believes is in force
is not in force.

This is posture, not a CVE — it reports non-conformance, not exploitation. It is
distinct from `policy.ssm_source_denied`, which only inspects v3/MLDv2 reports
that *do* carry sources and only fires when `ssm_source_allow` is configured;
pre-v3 SSM membership was previously invisible to that rule. Disable with
`posture.flag_ssm_version_mismatch: false`.

## Learn → enforce

Run `mode: learn` for a baseline window (default 180 s) plus however long you
want to observe. It records observed (host, group) pairs, the elected querier,
and every group on the segment. Flip to `mode: enforce` (or `--enforce`) and any
join outside the learned baseline / explicit allowlist alerts. Sensitive-group
and querier/anomaly rules fire in both modes.

## Run

```bash
pip install scapy pyyaml --break-system-packages
sudo python3 -m igmpwatch -c igmpwatch.yaml            # or -i eth0
python3 selftest.py                                     # 123/123, no root needed
```

Before relying on the SNMP tier, validate a switch in one shot (no root, no
capture iface needed) — it reports which target OIDs the platform actually
answers and what they return:

```bash
python3 -m igmpwatch --snmp-probe --snmp-host 10.10.0.2 --snmp-community readonly
```

The probe also seeds the capability cache (below), so sweeping the access layer
once configures the poller for every switch:

```bash
for sw in sw-a sw-b sw-c; do
  echo "== $sw =="
  python3 -m igmpwatch --snmp-probe --snmp-host "$sw" --snmp-community readonly --db /var/lib/igmpwatch/igmpwatch.db
done
```

Deploy: drop the package under `/opt/igmpwatch`, config at
`/etc/igmpwatch/igmpwatch.yaml`, then the unit runs unprivileged with just
`CAP_NET_RAW`/`CAP_NET_ADMIN` and a 128 MB cap.

## Sensor-interface hardening

The capture NIC should be a SPAN destination. Keep it quiet so the Pi's own
stack doesn't inject multicast into the mirror you're analyzing:

```bash
ip link set eth0 up
ip addr flush dev eth0                 # no IP on the capture leg
sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
# stop avahi/mdns on this NIC so the sensor isn't a multicast talker
```

## Data-plane rate sampler

The detectors above watch the multicast *control plane*. A separate lightweight
sampler closes the loop on the *data plane*: every `interval` seconds it reads
the NIC's kernel counters from `/sys/class/net/<iface>/statistics`
(`rx_packets`, `multicast`, `rx_dropped`), turns successive reads into rates,
and cross-references them against the live IGMP subscriber census.

Still passive — it only reads counters the kernel already keeps; it opens no
network handle and imports no socket library (enforced by the self-test).

The counters are segment-level, not per-group (sysfs doesn't break multicast
down by group), so the useful signal is the **cross-reference**:

- `mcast_storm` — raw received-multicast pps over threshold.
- `mcast_flood_no_members` — sustained multicast on the wire while **zero data
  groups are subscribed**. Control-plane silence + data-plane multicast means
  traffic is being flooded to groups nobody joined: unregistered-multicast
  flooding, a switch snooping failure, or injected traffic. This is exactly the
  case a join/leave/query view can't see.
- `mcast_ratio` — multicast as a fraction of total rx (gated by a pps floor so
  an idle link stays quiet).
- `rx_drops` — `rx_dropped` climbing means the ring buffer is overrunning,
  which on a mirror port is itself a storm symptom (and a warning that the
  sensor may be dropping frames it should be analyzing).

"Active data groups" excludes 224.0.0.0/24 link-local control (mDNS/LLMNR are
always present and aren't the data-plane multicast in question). The sampler
runs on its own thread; counter reads happen outside the pipeline lock, and only
the group-census snapshot + emit are locked. Counter resets (iface bounce,
32-bit wrap) re-prime silently instead of firing a bogus spike.

## SNMP poller (per-interface / per-group, off by default)

The sysfs sampler sees only the mirror port's aggregate multicast rate. The
switch already keeps the per-group and per-interface state; the SNMP poller
reads it and ties it back to the same IGMP census. It gives you what the mirror
can't: *which egress port* and *which group* a multicast flood is on, without
putting the Pi inline.

**Out-of-band, not segment traffic.** SNMP polls the switch's management
address. It sends nothing on the mirrored segment, transmits no IGMP, and joins
no group — so it never becomes the recon signature the packet detectors watch
for. It is still credentialed network I/O, so it is **disabled by default**; set
`snmp.enable: true` and a `host` to use it. The self-test asserts the module
carries no packet-transmit path.

Default MIBs (all OIDs overridable for L2-only or vendor platforms):

- Per-interface multicast — IF-MIB `ifXTable` 64-bit counters
  (`ifHCInMulticastPkts` / `ifHCOutMulticastPkts`), delta'd into pps →
  `iface_mcast_storm` per port, with an optional `monitor_ifaces` whitelist.
- Per-group membership — IGMP-STD-MIB `igmpCacheTable` (group + ifIndex in the
  index, last-reporter in the value), cross-referenced against the census:
  - `unsubscribed_forwarding` (HIGH) — switch forwards a group igmpwatch never
    saw a join for. Either the mirror is missing a segment, or the switch is
    forwarding to a group with no legitimate join on the monitored port.
    Link-local (224.0.0.0/24) and benign groups (mDNS/LLMNR/SSDP/SLP) excluded.
  - `census_not_forwarded` (LOW, opt-in) — igmpwatch saw a join the switch's
    table doesn't list. Off by default (timing-sensitive); only evaluates after
    the learning window and when the switch actually returned a group table.

### Capability cache

L2-only gear commonly populates `ifXTable` but returns an empty
`igmpCacheTable` (no SVI in the VLAN, or the switch isn't the elected querier).
Walking it every 30 s is a wasted round-trip forever. Each switch's verdict is
cached in the `snmp_capabilities` table and the poller skips walks a platform
doesn't answer:

- **Strikes, not one strike.** `capability_strikes` (default 3) consecutive
  *reachable-but-empty* walks are required before a group table is marked
  unsupported — one empty read during a membership lull isn't a verdict.
- **Unreachable is never a verdict.** A failed walk is a transport problem, so
  it records nothing and never poisons the cache.
- **Never permanent.** `capability_ttl` (default 1h) forces a re-check, so a
  switch that later gains an SVI or wins the querier election is picked back up
  automatically and the cross-reference re-enables itself.
- **Per-switch**, keyed by host — one L2 access switch's verdict never mutes
  the distribution pair.

`--snmp-probe` seeds the cache directly (a deliberate probe is authoritative —
no strikes needed), so a fleet sweep pre-configures every switch in one pass.
Use `--no-cache` to report without writing. `snmp_group_walks_skipped` in the
stats line shows the cache working; set `cache_capabilities: false` to disable.

Transport shells out to net-snmp (`snmpbulkwalk`), so there's no fragile Python
SNMP dependency on the Pi (`apt install snmp`). If the binary or MIB is absent,
or the switch is unreachable, the poller degrades to a silent no-op instead of
failing the process. Evaluation logic is pure and driven by injected snapshots
in the self-test — no switch or snmp binary needed to test. Runs on its own
thread at `snmp.interval` (default 30 s); the SNMP round-trip happens outside
the pipeline lock, only the census snapshot + emit are locked.

## Storage

`events` (alerts, with rolled-up suppressed counts), `memberships`
(group↔host↔version↔sources), `queriers`, `hosts` (baseline). Same DB
conventions as the rest of the suite so multicast events correlate with
macwatch / arp_guard / DNS detections on a shared timeline.
