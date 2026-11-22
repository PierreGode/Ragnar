# certwatch — passive TLS certificate triage (Ragnar)

Watches TLS handshakes crossing a tap / SPAN / bridge and triages every X.509
certificate it can **observe** for expiry and validity problems. Detection
only — certwatch never opens a socket, never probes, never sends a byte. Same
passive-first posture as `dnswatch` / `igmpwatch` / `ospfwatch`.

## The one caveat that shapes everything

The server certificate is cleartext on the wire **only for TLS 1.0/1.1/1.2**.
In **TLS 1.3 the Certificate message is encrypted** under the handshake keys
(it's sent after ServerHello), so it is **not observable passively** — no keys,
no cert. This is a property of TLS 1.3, not a limitation of the parser.

certwatch turns that into a feature: for a 1.3 flow it emits an **inventory**
record (SNI + negotiated version) marked *cert-not-observable*, so you can tell
"no cert because 1.3" apart from "no cert because parse failure." And in
practice the certs that are actually broken — expired mgmt interfaces, iDRAC/
iLO/IPMI, self-signed appliances, legacy medical/IoT gear, internal PKI — are
exactly the population still speaking 1.2. Passive catches the problem certs
and inventories the modern ones.

## What it flags

| Code            | Sev  | Meaning                                              |
|-----------------|------|------------------------------------------------------|
| `EXPIRED`       | CRIT | `notAfter` in the past                               |
| `NOT_YET_VALID` | CRIT | `notBefore` in the future                            |
| `EXPIRING_SOON` | WARN | within `--warn-days` (default 30) of expiry          |
| `NAME_MISMATCH` | CRIT | observed SNI not covered by cert CN/SAN              |
| `WEAK_SIG_MD5`  | CRIT | MD5/MD2 signature                                    |
| `WEAK_SIG_SHA1` | CRIT | SHA-1 signature                                      |
| `WEAK_KEY`      | WARN | RSA <2048, DSA, or EC <256                           |
| `SELF_SIGNED`   | WARN | issuer == subject                                    |
| `MISSING_SAN`   | WARN | CN-only cert, no subjectAltName                      |
| `LONG_VALIDITY` | INFO | validity window >398d (internal/non-public PKI)      |
| `WILDCARD`      | INFO | wildcard SAN present                                 |

Records also carry `module`, `days_left` (signed; negative once expired, so a
SIEM can alert on `days_left < 7` without regexing a string), `validity_days`,
`server_ip`/`server_port`, and in batch mode the `pcap` provenance.
| `CA_CERT`       | INFO | BasicConstraints CA:TRUE presented as leaf           |

`NAME_MISMATCH` only fires when the SNI was observed in the same connection's
ClientHello; certwatch keys flows canonically and matches the client-side SNI
to the server-side Certificate without needing to know which side is "server"
up front.

## Usage

```bash
# live, on a mirror/monitor interface, JSON lines to stdout
sudo python3 certwatch.py -i mon0 --json

# offline triage from a capture
python3 certwatch.py -r handshakes.pcap

# widen the port set (or 'any' for all TCP — heavier)
python3 certwatch.py -i eth0 --ports 443,8443,9443,10250 --warn-days 14

# batch-triage a directory of captures, collapsing repeat sightings
python3 certwatch.py --pcap-dir /captures --recursive --dedupe --min-status WARN

# self-test (no wire, no interface needed)
python3 certwatch.py --selftest
```

Default port set is the common TLS-bearing ports; keep it tight on the Zero 2W.

## Batch mode (`--pcap-dir`)

Triages every capture in a directory: `.pcap` / `.pcapng` / `.cap` / `.dmp`,
gzipped or not, **including tcpdump rotation suffixes** (`capture.pcap0`,
`capture.pcap1`, … — the number lands *after* the extension, which a naive
`endswith('.pcap')` silently skips). Files are processed in natural order, so
`.pcap2` precedes `.pcap10`.

- `--recursive` descends into subdirectories.
- `--dedupe` collapses repeat sightings of the same cert (keyed on
  server+serial) into one record carrying `seen_count` and `seen_in`. The same
  expired iDRAC across 40 rotated captures is one problem, not 40.
- `--carry-state` keeps flow state across files. **Use only on a genuine
  rotation set.** The default is a fresh tracker per file: carrying state
  across unrelated captures lets a 4-tuple in one file merge with a colliding
  4-tuple in another and fabricate a record. False data is worse than a false
  negative, and a handshake straddling a rotation boundary is all you lose.
- A corrupt or truncated capture is skipped with a note on stderr and never
  aborts the run. Progress goes to stderr, records to stdout, so
  `--json | ragnar_syslog.py` stays clean.

A `batch_summary` record (counts by status and finding code) is emitted at the
end in `--json` mode, and printed to stderr otherwise.

## Self-test

`python3 certwatch.py --selftest` → **38/38**. The harness mints certs
in-memory (expired, not-yet-valid, self-signed, weak-key, wildcard, no-SAN,
long-validity, CA, name-match/mismatch), ships a real openssl-minted SHA-1
cert as a fixture (cryptography 46 refuses to *sign* SHA-1), and synthesizes
TLS byte streams to exercise the reassembler: SNI extraction, ServerHello
version + supported_versions (1.3), single/chained Certificate messages,
handshake fragmented across TLS records, cert spanning multiple TCP segments,
coalesced ServerHello+Certificate, TLS 1.3 inventory path, ApplicationData
teardown, non-TLS/garbage input, flow eviction, per-flow buffer cap, MAX_FLOWS
LRU eviction, malformed-length safety, and TTL sweep. Two checks drive real
scapy IPv4/IPv6 packets through the capture handler.

## Shipping findings off the box

`ragnar_syslog.py` forwards the JSON-lines to a SIEM as CEF/LEEF/RFC5424/
RFC3164. It is **suite-wide, not certwatch-specific** — it keys off the shared
record conventions (`module` / `type` / `status` / `findings[].code`), so the
same shim serves dnswatch, ospfwatch, isiswatch and the rest:

```bash
certwatch.py -i mon0 --json \
  | ragnar_syslog.py --transport udp --host siem --port 514 \
      --format cef --min-status WARN
```

See `ragnar_syslog.md`. Note the split: **certwatch never transmits**; the
forwarder transmits and never touches the wire. Separate processes keep the
passive guarantee a property of the scanner rather than a promise in a README,
and let the forwarder carry its own egress allowlist
(`certwatch-forward.service`).

## Deploy (systemd)

`certwatch.service` runs as an unprivileged `certwatch` user with only
`CAP_NET_RAW`/`CAP_NET_ADMIN`, `ProtectSystem=strict`, a seccomp
`@system-service` filter, and `MemoryMax=128M`. JSON records go to journald.

```bash
sudo useradd -r -s /usr/sbin/nologin certwatch
sudo install -D certwatch.py /opt/ragnar/certwatch.py
sudo install -D certwatch_selftest.py /opt/ragnar/certwatch_selftest.py
sudo install -D certwatch.service /etc/systemd/system/certwatch.service
# edit ExecStart's -i <iface> first
sudo systemctl daemon-reload && sudo systemctl enable --now certwatch
journalctl -u certwatch -f
```

## Pi Zero 2W notes

- **Capture drops**, not CPU, are the ceiling: scapy's Python receive path is
  the bottleneck long before the A53 cores are. On a busy SPAN keep `--ports`
  tight or mirror only the VLAN/subnet of interest. For line-rate taps move to
  a Pi 5 or add an AF_PACKET/eBPF prefilter — the parser is happy either way.
- **Memory** is bounded: `MAX_FLOWS` (512) × `MAX_FLOW_BYTES` (64K) ≈ 32 MB
  worst case, with LRU + 30s TTL eviction. Flows are freed the instant the
  Certificate (or a 1.3 ServerHello) is seen. Safe on 512 MB.
- **Hostile input**: every parser is length-checked and wrapped; a malformed
  or adversarial handshake drops that one flow, never the daemon.

## Ragnar / OSI placement

certwatch sits at **L6 (presentation)** — X.509 / TLS handshake semantics —
complementing the L2/L3 modules (`macwatch`, `arp_guard`, `dnswatch`,
`dhcp_doctor`, `igmpwatch`, `ospfwatch`). Requires `scapy` and `cryptography`.
