# EIGRP FRR Namespace Lab (`eigrp_lab.sh`)

A self-contained, isolated lab for validating **EIGRP Watch** (`network_diagnostics.py
eigrp-watch`) against **real** FRR EIGRP traffic — the EIGRP analogue of an
`ospfwatch` FRR lab.

```
              br-eigrp (Linux bridge, no uplink)
   ┌──────────────┼───────────────┐
   │              │               │
 r1-br          r2-br         (eigrp-watch sniffs br-eigrp here)
   │              │
[ netns r1 ]   [ netns r2 ]
 zebra+eigrpd   zebra+eigrpd
 AS 100         AS 100
 10.10.0.1/24   10.10.0.2/24
 172.16.1.0/24  172.16.2.0/24   (advertised LANs, on dummy lan0)
```

Everything lives in network namespaces on a bridge with **no route to any real
network**. `eigrp-watch` stays passive/RX-only; the optional injector
(`eigrp_inject.py`) is the only thing that transmits, and only onto this
isolated bridge.

## Requirements

- `iproute2`, and FRR with `eigrpd` (`/usr/lib/frr/{zebra,eigrpd}`; FRR ≥ 8.x).
- `CAP_NET_ADMIN` + `CAP_NET_RAW` (root, or a suitably privileged container).
- The run user must be in the `frrvty` group or FRR won't finish starting
  (`vty_serv_un: could chown socket`). `eigrp_lab.sh up` creates the group and
  adds `root` for you.
- `python3` + `scapy` (with the EIGRP contrib) for the injector; `tcpdump` for
  the capture the watcher uses.

## Usage

```bash
sudo ./eigrp_lab.sh up               # build topology, start FRR (unauthenticated)
sudo ./eigrp_lab.sh up auth          # ... with MD5 key-chain auth instead
sudo ./eigrp_lab.sh status           # show adjacency: learned EIGRP routes in each RIB
sudo ./eigrp_lab.sh watch 20         # run eigrp-watch on the bridge for 20s
sudo ./eigrp_lab.sh flap [lan|link]  # churn topology to emit Update/Query TLVs
sudo ./eigrp_lab.sh demo [sec]       # watch (+route view) while flapping — one shot
sudo ./eigrp_lab.sh down             # tear everything down
```

`watch`/`demo` call the repo's real detector CLI
(`python3 network_diagnostics.py eigrp-watch --iface br-eigrp --seconds N`) — the
same code path the web UI and the Network Integrity Monitor use. Routes and
routers print by default; there is no separate `eigrpwatch` binary.

Proof of a real adjacency is route exchange in each router's kernel RIB:

```
$ sudo ./eigrp_lab.sh status
== netns r1 : EIGRP-learned routes ==
172.16.2.0/24 nhid 10 via 10.10.0.2 dev r1-eth0 proto eigrp metric 20
== netns r2 : EIGRP-learned routes ==
172.16.1.0/24 nhid 10 via 10.10.0.1 dev r2-eth0 proto eigrp metric 20
```

## Capturing route TLVs (flap)

Steady-state EIGRP is mostly Hellos, which carry no routes. To see real
Update/Query route TLVs, force a topology change while sniffing:

```bash
sudo ./eigrp_lab.sh demo 24
```

`demo` runs `eigrp-watch` and flaps r2's LAN (route withdraw + re-advertise)
then r2's uplink (adjacency reset + full Update):

- `flap lan`  — bounce r2's advertised LAN → withdraw/re-advertise 172.16.2.0/24
- `flap link` — bounce r2-eth0 → adjacency reset, INIT, full-table Update

## Injecting attacks (lab-only)

`eigrp_inject.py` **transmits** crafted EIGRP to prove the passive detector
fires on real on-wire attacks. **Never point it at a production network.** Each
scenario maps to the `eigrp-watch` verdict it provokes (once a baseline has been
learned from the two legit routers):

| scenario | what it sends | eigrp-watch verdict |
|---|---|---|
| `rogue` | Hello from a new speaker not in the baseline | `rogue-router` |
| `default-route` | Update injecting `0.0.0.0/0` | `injection` |
| `metric` | victim prefix re-advertised via the attacker (next-hop hijack, superior metric) | `injection` |
| `goodbye` | Hello with all K-values 255, spoofed from a neighbour | teardown (see below) |
| `wide-external` | named-mode wide External route TLV (0x0603) | `rogue-router`¹ |
| `wide-metric` | named-mode wide Internal route TLV (0x0602) | `rogue-router`¹ |

```bash
# in one shell: watch
sudo ./eigrp_lab.sh watch 30
# in another: inject (or use the `inject` shortcut, which targets br-eigrp)
sudo ./eigrp_lab.sh inject --scenario rogue
sudo ./eigrp_lab.sh inject --scenario default-route
sudo ./eigrp_lab.sh inject --scenario metric
sudo ./eigrp_lab.sh inject --scenario goodbye        # spoofs r1 by default
sudo ./eigrp_lab.sh inject --scenario wide-external
sudo ./eigrp_lab.sh inject --scenario wide-metric
```

`goodbye` defaults to sourcing from r1 (`10.10.0.1`) — a spoofed teardown. On
its own it reads as `weak-auth`; **live**, while the real r1 is still sending
normal Hellos, the capture holds two different K-value sets for `10.10.0.1` and
`eigrp-watch` escalates to **anomaly** (K-value mismatch). Its real effect is on
FRR: the adjacency drops, and older `eigrpd` can crash (`eigrpd ... Aborted`) —
a live reminder that these are real attacks and FRR's EIGRP daemon is itself
fragile against crafted packets.

¹ The wide named-mode TLVs are best-effort raw encodings. The detector's
classic tcpdump-text parser reads the *speaker* but not the wide route, so from
an off-baseline source these surface as `rogue-router` rather than `injection` —
a genuine coverage note for named-mode EIGRP, which the lab makes visible.

### Verify crafting without a bridge (`--dry-run`)

`eigrp_inject.py --dry-run` builds the frame, writes it to a pcap, and runs it
back through the **real** detector (`tcpdump → _parse_eigrp_capture →
_eigrp_analyze`) against the lab baseline — no transmit, no bridge, no root:

```bash
python3 python/eigrp_inject.py --iface br-eigrp --scenario metric --dry-run
# ... prints the parsed route (172.16.2.0/24 via 10.10.0.66) and:
# --- detector verdict (lab baseline): injection ---
```

Use `--baseline none` to see the raw (baseline-free) classification instead.

## Container note

FRR's `-d` daemonize works once the `frrvty` group is set. In a minimal
container whose process reaper kills survivors, run the whole `up → watch →
down` cycle within a single shell/command so no daemon outlives it. On a real
host (or the Pi), `up`/`watch`/`down` as separate commands is fine — FRR
daemonizes and persists normally.
