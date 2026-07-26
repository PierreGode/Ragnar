# Traffic Analysis

Live packet capture and passive network monitoring, in its own web-UI tab
(**Traffic**). It runs `tcpdump` on one interface and reads the output line by
line: per-host bandwidth, connection tracking, protocol mix, DNS logging, and
detection of port scans, DNS tunnelling and C2 beacons.

**Detection-only.** It never sends a packet.

## Where it runs

Traffic Analysis used to be gated behind server mode (7.5GB+ RAM), alongside
OpenVAS-class vulnerability scanning. That was the wrong bar — the two have
nothing in common in what they cost. Measured on a Pi 5 against a live LAN at
~90 packets/sec:

| Component | Cost |
|---|---|
| Analyzer (Python parse loop) | **0.4%** of one core, **18MB** RSS |
| `tcpdump` | **8MB** RSS |
| JA3 / IRC sidecars (`tshark`, optional) | ~**290MB** RSS *each*, plus a ~155MB `dumpcap` child |

So the capture core is a Pi Zero workload, and it is now available on **any
board Ragnar runs on**. The single hard requirement is `tcpdump`:

```bash
sudo apt-get install tcpdump
```

If it is missing, the Traffic tab is hidden and the API says so by name rather
than blaming the hardware.

The gates live in `server_capabilities.py`:

| Gate | Floor | Why |
|---|---|---|
| `traffic_capable` | `tcpdump` present, supported arch, RAM readable (`TRAFFIC_MIN_RAM_GB`) | the capture core |
| `traffic_sidecars_enabled` | `tshark` present **and** 3.5GB RAM (`TRAFFIC_SIDECAR_MIN_RAM_GB`) | a tshark pair outweighs everything a Zero has |
| `is_server_capable` | 7.5GB RAM | unrelated — OpenVAS, Nuclei, big dictionaries |

A board below the sidecar bar loses only JA3 fingerprinting and IRC DPI. Packet
capture, host/connection stats, port-scan, DNS-tunnel and beacon detection are
unaffected, and the skip is logged with the board's actual numbers.

## Memory on a small board

Alerts and DNS queries were already ring buffers, but tracked hosts,
connections and beacon flow history gain an entry per new peer seen — on a
capture left running for a week, that is the only state without a ceiling.
`TrafficAnalyzer._prune_state()` runs every 60s off the packet path and evicts
the least-recently-seen entries back under the caps:

| | ≥1GB RAM | <1GB RAM (Pi Zero class) |
|---|---|---|
| Hosts | 4000 | 500 |
| Connections | 8000 | 1000 |
| Beacon flows | 2000 | 250 |

At the low-memory numbers the tracked state tops out around 3MB. A RAM read of
0 (detection failed) takes the low-memory branch — that is when conservative
numbers are wanted most. Per-IP side tables (MAC, hostname, listening ports,
DNS timing) are dropped along with the host they belong to; they rebuild from
the next packet.

## What it detects

| Category | Signal |
|---|---|
| `port_scan` | many distinct ports from one source (vertical), or one port across many hosts (horizontal sweep). Default gateway gets a softer threshold |
| `c2_beacon` | repeated contact with an external `(ip, port)` at low-jitter intervals and consistent payload sizes — scored `0.6 × interval regularity + 0.4 × size regularity` |
| `dns_tunneling` | query rate from a single host over threshold |
| `suspicious_port` | traffic to known backdoor / C2 / Tor ports (TCP unicast only for the ports where a UDP broadcast would just be IoT noise) |
| `data_exfiltration`, `high_bandwidth`, `brute_force`, `protocol_anomaly` | volume and pattern heuristics |

Alerts are rate-limited (10/min) and deduplicated in a 300s window.

Capture also feeds **passive host discovery**: LAN hosts seen only in traffic —
firewalled boxes that never answer a scan — are flushed into the hosts DB every
30s, with MACs learned from ARP replies and services inferred from the ports
they answer on.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/traffic/status` | availability + `reason` when unavailable, plus the summary |
| `POST /api/traffic/start` / `stop` | control capture (optional `interface`) |
| `GET /api/traffic/hosts` `?limit=&sort=` | top talkers |
| `GET /api/traffic/connections` | active connections |
| `GET /api/traffic/alerts` `?limit=&level=` | alert feed |
| `GET /api/traffic/beacons` | scored beacon candidates |
| `GET /api/traffic/ja3` / `irc` | sidecar output (empty when sidecars are gated off) |
| `GET /api/traffic/debug` | tcpdump path, sudo check, queue depth, interface list |
| `GET /api/server/capabilities` | `features.traffic_analysis`, `features.traffic_sidecars` |

`POST /api/server/install-tools` with `{"feature": "traffic_analysis"}` installs
the capture tools, and unlike the vulnerability-scanner tools it works on any
board — that is the path that installs the missing `tcpdump`.

## Notes

- Capture excludes ports 22 and 8000 so SSH and the web UI do not analyze
  themselves.
- `tcpdump` runs under `sudo`; the installer's sudoers rules cover it.
- On a managed-mode Wi-Fi interface you see the host's own traffic plus
  broadcast, not the whole segment. For full visibility, capture on a wired port
  with a SPAN/mirror.
