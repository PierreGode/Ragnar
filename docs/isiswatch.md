# isiswatch — passive IS-IS security scanner

`isiswatch.py` is a standalone, **passive-first, detection-only** IS-IS monitor —
the deep companion to the integrated [IS-IS Watch](nettools.md#is-is-watch)
inside `network_diagnostics.py`. Where the integrated watch classifies
`tcpdump`-decoded text into the shared verdict ladder, `isiswatch.py` carries its
own **pure-Python binary TLV parser**, which unlocks the detectors that depend on
fields tcpdump text renders unreliably (HMAC-MD5 vs HMAC-SHA, the P2P three-way
TLV, padding, narrow-vs-wide metric TLVs, DIS priority, malformed structure).

It **never** transmits IS-IS, forms adjacencies, injects LSPs, or otherwise
touches the control plane. Scapy is used for live capture only; the parser and
detector engine are pure Python, so `--self-test` runs with no Scapy and no NIC.

- **Test floor:** Raspberry Pi Zero 2 W.
- **Self-test:** 79/79 (`python3 python/isiswatch.py --self-test`).
- **Deps:** Python 3.9+, Scapy (live capture only).

## Why IS-IS is different

Unlike OSPF (IP multicast) and EIGRP (IP proto 88), **IS-IS rides directly on
Layer 2** — ISO CLNS carried in 802.3 frames with an LLC header where
`DSAP == SSAP == 0xFE`. Two consequences:

1. **You cannot route to it.** The scanner must sit on the same broadcast domain
   / VLAN as the adjacency, or be fed the frames via a **SPAN/mirror** or a
   **passive tap**.
2. The NIC must receive the IS-IS multicast MACs (`01:80:C2:00:00:14` AllL1IS,
   `01:80:C2:00:00:15` AllL2IS), so capture runs in **promiscuous mode**.

Control-plane rates are low, so a Zero 2 W is never capture-bound on a normal
core link.

## Detectors

| Code | Severity | What it catches |
|------|----------|-----------------|
| `ISIS-AUTH-CLEARTEXT` | critical | Type-1 cleartext password auth (length + first char logged, rest redacted) |
| `ISIS-AUTH-MISSING` | high\* | PDU with no Authentication TLV |
| `ISIS-AUTH-HMAC-MD5` | medium | Deprecated HMAC-MD5 (RFC 5304); recommend RFC 5310 HMAC-SHA |
| `ISIS-AUTH-MIXED` | medium | Same system seen both authenticated and unauthenticated |
| `ISIS-AUTH-UNKNOWN` | low | Non-standard authentication type value |
| `ISIS-ROGUE-SYSTEM` | high | System ID not in the known/learned baseline |
| `ISIS-AREA-MISMATCH` | medium | L1 speaker advertising an area outside the expected set |
| `ISIS-LSP-PURGE` | high | LSP with Remaining Lifetime 0 (purge/blackhole) |
| `ISIS-LSP-OVERLOAD` | medium | Overload (OL) bit set — traffic steering/denial |
| `ISIS-LSP-SEQ-ANOMALY` | medium | Sequence number near `0xFFFFFFFF` (seq-number attack) |
| `ISIS-LSP-CHURN` | medium | Rapid LSP re-flooding within the window (instability / flood DoS) |
| `ISIS-DIS-MAXPRIO` | low | Hello advertising DIS priority 127 (possible DIS takeover) |
| `ISIS-P2P-NO-3WAY` | medium | P2P Hello without the three-way adjacency TLV (RFC 5303) |
| `ISIS-HELLO-PADDING` | info | Hello padding (TLV 8) — bandwidth waste / amplification vector |
| `ISIS-NARROW-METRICS` | low | Legacy narrow metrics (TLV 2/128/130) instead of wide (RFC 5305) |
| `ISIS-MALFORMED` | medium | Structurally inconsistent PDU (crafted packet / truncation) |
| `ISIS-TRAILING-DATA` | medium | Non-zero bytes after the declared PDU length — data smuggled past the PDU end (covert channel / Etherleak, CVE-2003-0001) |

\* `ISIS-AUTH-MISSING` escalates from medium → high when the baseline declares
`expected_auth`.

The TLV walk is bounded by the IS-IS **PDU Length** header field, not the
captured frame length. The kernel/NIC pads every frame to the 60-byte Ethernet
minimum, so a short PDU arrives with trailing zeros; walking those as TLVs would
parse them as `type=0/len=0` (and a kept FCS or a snaplen cut would trip a bogus
`ISIS-MALFORMED`). Bytes past the PDU end are classified: all-zero padding is
benign and ignored, any non-zero trailer raises `ISIS-TRAILING-DATA` (a kept
4-byte FCS is excluded so it isn't mistaken for a leak).

Findings are **deduplicated and counted** (per code + system + level) with
first/last-seen timestamps, and sorted by severity in the snapshot.

## Usage

```bash
# Self-test (no root, no NIC needed) — 79/79
python3 python/isiswatch.py --self-test

# Live passive scan on a SPAN/segment interface
sudo python3 python/isiswatch.py -i eth0 -v

# With an operator baseline + web-UI snapshot feed + a final report
sudo python3 python/isiswatch.py -i eth0 \
    --baseline baseline.example.json \
    --web-json /run/ragnar/isiswatch.json \
    --json-out /var/log/ragnar/isis-report.json

# Auto-learn systems for the first 120s, then alert on anything new
# (set "learn_window": 120 in the baseline)
```

### Baseline file (`baseline.example.json`)

```json
{
  "known_systems": ["0000.0000.0001", "0000.0000.0002"],
  "expected_areas": ["490001"],
  "expected_auth": "crypto-hmac",
  "learn_window": 0
}
```

- **`known_systems`** — allowlisted System IDs. If empty *and* `learn_window` is
  0, `ISIS-ROGUE-SYSTEM` stays quiet (no baseline = no crying wolf).
- **`expected_areas`** — expected L1 area address(es) (hex, e.g. `490001`);
  mismatches flagged.
- **`expected_auth`** — declaring an expectation escalates missing-auth to high.
- **`learn_window`** — seconds to auto-learn System IDs before rogue alerting.

### Key options

| Flag | Purpose |
|------|---------|
| `-i, --iface` | Capture interface (SPAN/tap-facing) |
| `-b, --baseline` | Baseline JSON |
| `-v, --verbose` | Print each PDU as it's seen |
| `--web-json PATH` | Periodically write a snapshot for the web UI |
| `--json-out PATH` | Write final snapshot on exit |
| `--churn-threshold N` / `--churn-window S` | LSP re-flood tuning (default 5 / 20s) |
| `--filter BPF` | Override the capture BPF (see VLAN note) |
| `--duration N` | Stop after N seconds |

## Capture filter & VLAN note

Default BPF:

```
(ether[14:2] = 0xfefe) or ether dst 01:80:c2:00:00:14 or ether dst 01:80:c2:00:00:15
```

The `ether dst` clauses catch **LAN** IS-IS even on 802.1Q-tagged frames (the
destination MAC precedes any tag). The LSAP clause (`0xfefe`) catches untagged
frames, including **P2P** Hellos. The one gap is *VLAN-tagged P2P* Hellos
(unicast, LSAP shifted by the tag) — for those pass `--filter ""` to disable BPF
and filter in Python. The parser handles a single 802.1Q tag transparently
either way.

## systemd

`scripts/isiswatch.service` runs least-privilege (`CAP_NET_RAW`/`CAP_NET_ADMIN`,
`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryMax=128M`) and writes a live
snapshot to `/run/ragnar/isiswatch.json` for the web UI.

```bash
sudo install -Dm644 baseline.example.json /etc/ragnar/isis-baseline.json
sudo cp scripts/isiswatch.service /etc/systemd/system/isiswatch.service
sudoedit /etc/ragnar/isiswatch.env         # set ISISWATCH_IFACE=eth0
sudo systemctl daemon-reload && sudo systemctl enable --now isiswatch
```

## Lab validation (FRR)

FRR's `isisd` builds a two-node namespace lab (as the EIGRP lab does):

```
ip netns add r1; ip netns add r2
ip link add veth1 netns r1 type veth peer name veth2 netns r2
# configure isisd on r1/r2 with 'isis network point-to-point' or broadcast,
# 'isis authentication ...' to exercise the auth detectors,
# 'set-overload-bit' to exercise ISIS-LSP-OVERLOAD, etc.
```

Point `isiswatch -i <veth-on-a-bridge>` (or a SPAN of the segment) and toggle
auth modes / overload / area IDs to walk each detector.

## Relation to the integrated IS-IS Watch

- **IS-IS Watch** (`do_isis_watch` in `network_diagnostics.py`) is the web-UI /
  Network-Integrity-Monitor path: a short `tcpdump` capture classified into the
  suite verdict ladder (injection / rogue / anomaly / weak-auth), with the
  high-value binary detectors (purge / overload / seq / mixed-auth) added inline.
- **isiswatch.py** is the standalone deep monitor: a binary TLV parser, the full
  16-detector set with per-code severity + dedup, baseline learning, a snapshot
  feed, and a hardened daemon.

## OSI coverage

IS-IS closes the L2/L3 boundary case in Ragnar's routing-protocol coverage:
OSPF (L3/IP), EIGRP (L3/IP), and IS-IS (L2-borne L3 control plane).
