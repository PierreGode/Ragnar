# ndpwatch — passive IPv6 Neighbor Discovery attack monitor

`ndpwatch` (`python/ndpwatch.py`) is the **IPv6 counterpart to
[arp_guard](arp_guard.md)**. IPv6 has no ARP — hosts resolve neighbours and
discover routers via ICMPv6 **Neighbor Discovery** (RS/RA/NS/NA/Redirect) — and
the same MITM threat model maps over:

| ARP attack | NDP equivalent |
|---|---|
| ARP-reply spoofing (poison IP→MAC) | **NA spoofing** (parasite6) — poison the neighbour cache |
| gateway impersonation | **rogue RA** (fake_router6) — advertise yourself as the router / inject a SLAAC prefix |
| gratuitous-ARP flood | **RA / prefix / NS flood** (flood_router6) |
| — | **DAD DoS** (defend every tentative address), **spoofed ICMPv6 Redirect** |

**Detection only** — it never sends an ND packet or corrects anything. **Passive:**
Scapy is only the live-capture front end; field extraction is a hand-rolled
**raw-byte parser** (Ethernet → IPv6 → ICMPv6 ND + options), so `--self-test` and
pcap `--replay` need no NIC/IPv6 kernel and the self-test needs no Scapy.

- **Test floor:** Raspberry Pi Zero 2 W.
- **Self-test:** 24/24 (`python3 python/ndpwatch.py --self-test`).
- **Deps:** Python 3.8+, Scapy (live capture only).

## Findings (stable codes)

| Code | Sev | Fires when |
|---|---|---|
| `NDP-001` | critical | NA overriding a learned neighbour binding (cache poison) |
| `NDP-002` | high | override-flag NA flood for one target (active poisoning) |
| `NDP-003` | critical | target IPv6 flapping between MACs (two hosts racing) |
| `NDP-004` | medium | NA Router (R) flag inconsistent for a host/router |
| `NDP-005` | high | ND link-layer option ≠ Ethernet source (forged) |
| `NDP-006` | critical | RA from a router not in the trusted set (rogue gateway) |
| `NDP-007` | high | trusted gateway RA with router-lifetime 0 (kill default route) |
| `NDP-008` | high | RA advertises a prefix outside the baseline (SLAAC hijack) |
| `NDP-009` | high | RA router-preference High from an untrusted source |
| `NDP-010` | high | RA RDNSS (DNS) option from an untrusted router (DNS hijack) |
| `NDP-011` | medium | RA MTU implausibly low / changed (PMTU blackhole) |
| `NDP-012` | high | Router Advertisement flood |
| `NDP-013` | medium | one source soliciting many distinct targets (NS sweep) |
| `NDP-014` | high | answering NS for tentative (DAD) addresses (DAD DoS) |
| `NDP-015` | medium | Router Solicitation flood |
| `NDP-016` | high | ICMPv6 Redirect not from the first-hop router (spoofed) |
| `NDP-017` | high | ND with IPv6 Hop Limit ≠ 255 (off-link injection) |
| `NDP-018` | medium | malformed / truncated ND message |
| `NDP-019` | high | distinct-target flood approaching `neigh_max` (table pressure) |
| `NDP-020` | high | a router link-local speaking ND that is not the pinned gateway |

Findings from multiple codes about one packet are **merged into a single alert**
(highest severity + `evidence[]`) — a rogue RA typically fires
NDP-006/008/009/010/020 at once. `NDP-017` (Hop Limit 255) is the ND analog of
arp_guard's structural checks: RFC 4861 requires ND to arrive at Hop Limit 255,
so anything else is off-link injection.

## Run

```bash
python3 python/ndpwatch.py --self-test                  # 24/24, no root/Scapy/IPv6
sudo python3 python/ndpwatch.py -i eth0 --echo          # live, echo to stderr
sudo python3 python/ndpwatch.py -i eth0 -c ndpwatch.json --jsonl /var/log/ndpwatch/alerts.jsonl
python3 python/ndpwatch.py --replay attack.pcap --echo  # replay a capture (no NIC)
```

The rogue-RA / NDP-006/007/008/016/020 detectors need a **trusted set** — pin your
real routers (link-local + MAC) in `trusted_routers` and their SLAAC prefixes in
`trusted_prefixes`. Pin **out of band** (from the router/controller), not
auto-learned at boot: if an attacker is already active, auto-learning blesses
them. Without a trusted set, the flood/structural/binding detectors still work.

## Alerts

One JSON object per line: `ts`, `module`, `severity`, `type` (RS/RA/NS/NA/
Redirect), `src`, `eth_src`, `target`, `codes[]`, `summary`, `evidence[]`.

## systemd

`scripts/ndpwatch.service` runs as a dedicated non-root `ndpmon` user with only
`CAP_NET_RAW`/`CAP_NET_ADMIN`, `ProtectSystem=strict`, `MemoryMax=128M`; alerts
land in `/var/log/ndpwatch/alerts.jsonl`.

## Validation lab

`ndpwatch-lab.sh` (+ `ndp_inject.py`, `conftest_packets.py`) builds a
network-namespace topology with a real RA daemon and kernel SLAAC/DAD, then runs
learn → benign (must stay silent) → attack (drives the live capture path). It
needs **IPv6 in the kernel**, so run it on the Pi or a privileged host — not a CI
container with IPv6 compiled out. The offline conformance harness feeds the
injector's exact packets through ndpwatch's parser with no interface.

## Relation to the integrated NDP Watch

Ragnar also has an integrated **NDP Watch** (`do_ndp_watch` in
`network_diagnostics.py`) — a short tcpdump capture classified into the suite
verdict ladder, wired into the web UI and the Network Integrity Monitor.
`ndpwatch` is the standalone continuous daemon: a raw-byte parser, 20 coded
findings with merged alerts, JSON-lines, pcap replay, and a hardened unit.

## Same-broadcast-domain only

Like ARP/ND itself, it sees only what reaches its interface — the attack traffic,
the victim, or a SPAN/mirror. Place it accordingly.
