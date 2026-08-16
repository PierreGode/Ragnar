# arp_guard — layered ARP poisoning / spoofing detector

`arp_guard` (`python/arp_guard.py`) is a standalone, **detection-only** ARP
monitor. It never sends a corrective ARP, blocks traffic, or intervenes — it
watches the live ARP packet stream and alerts. **Passive:** Scapy is used only as
the live-capture front end; field extraction is a hand-rolled **raw-byte parser**
(no library dissector), so `--self-test` and pcap `--replay` run with no radio/NIC
and the self-test needs no Scapy.

Unlike the snapshot-based ARP check in the web UI ([ARP Poisoning](nettools.md#arp-poisoning),
which reads the kernel's *resolved* neighbour table), arp_guard watches the live
stream — so it sees the attack **in progress**: gratuitous-ARP floods, a binding
flapping between two racing hosts, and per-packet structural anomalies a snapshot
can't show.

- **Test floor:** Raspberry Pi Zero 2 W.
- **Self-test:** 14/14 (`python3 python/arp_guard.py --self-test`).
- **Deps:** Python 3.8+, Scapy (live capture only).

## Four layers

Each observed ARP frame is scored by four independent, stateful layers; findings
from multiple layers about one packet are **merged into a single alert** (highest
severity, combined evidence) to avoid alert fatigue during a sustained attack.

1. **`binding`** — IP→MAC conflict tracker. Flags any change to a learned binding;
   severity scales with how long the old binding was stable, and a binding
   **flapping** between two MACs (two hosts racing to answer) escalates to
   `critical` — the live signature of arpspoof/ettercap in progress.
2. **`gratuitous`** — gratuitous-ARP rate/breadth. Per source MAC in a sliding
   window: a high **rate** to one IP (targeted poisoning) and, separately, one MAC
   claiming **many distinct IPs** (subnet-wide poisoning, ettercap's "poison whole
   subnet" mode).
3. **`structural`** — per-packet field/opcode/consistency sanity: bad
   hwtype/ptype/length, invalid opcode, **Ethernet-source ≠ ARP-sender-hardware**
   (forged), multicast/broadcast sender IP, a **solicited reply sent to broadcast**
   (real replies are unicast; a *gratuitous* announcement is legitimately
   broadcast and is not flagged here), and an invalid `0.0.0.0` reply. Judges
   well-formedness only — a careful attacker crafts a clean packet, which is why
   this layer doesn't stand alone.
4. **`gateway`** — trusted IP→MAC pins set **manually, out of band** in the config.
   A packet claiming a pinned IP from a non-pinned MAC is `critical` (gateway/host
   impersonation). Deliberately **not** auto-learned at boot: if an attacker is
   already active, auto-learning would pin *their* MAC as trusted. Use
   `--learn-gateway` once, on a segment you currently trust, then copy the result
   into `trusted_bindings`.

## FHRP (HSRP/VRRP) awareness

A redundant gateway pair legitimately moves its virtual IP between physical
routers with a **gratuitous ARP** — the exact pattern layers 1 & 2 catch — so
without this a normal failover looks like an attack. Handled two ways, kept
strictly apart:

- **Shape match** (`00:00:0c:07:ac:GG` HSRPv1, `00:00:0c:9f:fG:GG` HSRPv2,
  `00:00:5e:00:01:VV` VRRP) is **informational only**. A MAC is spoofable, so a
  MAC merely *looking* like an FHRP virtual MAC is annotated in the alert but
  never trusted — otherwise sourcing poison traffic from that range would be a
  trivial evasion (the same reasoning `ndpwatch` used to refuse prefix-only trust).
- **Trust** comes only from an operator-confirmed `(virtual_ip, virtual_mac)` pair
  in `trusted_fhrp_groups`. Then: a clean move **into** that virtual MAC is the
  expected failover shape → de-escalated to `info` (`fhrp_transition`); a move
  **away** from a confirmed virtual MAC is the direction a real first-hop hijack
  takes → escalated to `critical` (`fhrp_hijack`), never suppressed; and a
  confirmed virtual MAC announcing its own IP is not counted as a gratuitous flood.

Populate `trusted_fhrp_groups` by cross-pivoting from **FHRP Watch** — it learns
the segment's HSRP/VRRP groups, and `--suggest-fhrp` derives the pinnable pairs
for you to **verify** before pasting them in:

```bash
python3 python/arp_guard.py --suggest-fhrp    # reads data/fhrp_watch.json
```

## Run

```bash
python3 python/arp_guard.py --self-test                 # 24/24, no root/Scapy
sudo python3 python/arp_guard.py -i eth0 --echo         # live, echo to stderr
sudo python3 python/arp_guard.py -i eth0 --jsonl /var/log/arp-guard/alerts.jsonl
python3 python/arp_guard.py --replay attack.pcap --echo # replay a capture (no NIC)

# one-time, passive: read the gateway MAC from the kernel neighbour table
# (/proc/net/arp — sends NOTHING). Ping the gateway once first if there's no entry.
python3 python/arp_guard.py --learn-gateway --gateway-ip 192.168.1.1
# copy the printed MAC into trusted_bindings in the config
```

## Alerts

One JSON object per line: `ts`, `module`, `severity` (`info`/`low`/`medium`/
`high`/`critical`), `sender_ip`, `sender_mac`, `eth_src`, `opcode`, `codes[]`
(all layer codes that fired), `summary` (the worst finding), and `evidence[]` (the
per-layer detail, severity-sorted).

## Tuning (config JSON)

`garp_window_s`, `garp_rate_threshold`, `garp_breadth_threshold` (gratuitous-ARP);
`flap_window_s`, `flap_count`, `stable_threshold_s` (binding); and
`trusted_bindings` (the layer-4 pins). Defaults suit a small home/lab subnet;
loosen `garp_rate_threshold` if you run things that legitimately send frequent
gratuitous ARPs (VRRP/keepalived, VM live-migration).

## systemd

`scripts/arp-guard.service` runs as a dedicated non-root `arpmon` user with only
`CAP_NET_RAW`/`CAP_NET_ADMIN`, `ProtectSystem=strict`, and `MemoryMax=128M`;
alerts land in `/var/log/arp-guard/alerts.jsonl`.

## Known limitations

- **Same-broadcast-domain only** — it sees only what reaches its interface (the
  attack traffic, the victim, or a SPAN/mirror).
- **No HSRP/VRRP virtual-MAC awareness** — a legitimate first-hop-redundancy
  failover moves a virtual MAC on purpose and would look like a binding conflict;
  pin both routers' real MACs or pair with FHRP Watch.
- **Layer 3 catches sloppy tooling, not careful attackers** — a well-crafted
  spoofed packet passes every structural check; layers 1 and 4 catch the *impact*.
- **No IPv6 NDP** (structurally different — see [NDP Watch](nettools.md#ndp-watch))
  and no switch-level MAC-flooding coverage (different attack surface).

## Relation to the integrated ARP check

The web UI's **ARP Poisoning** check (`do_arp_check`) is a point-in-time snapshot
of the resolved neighbour table (gateway-MAC-vs-baseline + one-MAC-many-IPs).
arp_guard is the continuous live-stream companion: the rate/flap/structural
signals that only exist while the attack is happening.
