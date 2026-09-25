# certwatch — passive TLS certificate triage

`certwatch.py` watches TLS handshakes crossing a tap / SPAN / bridge and triages
every X.509 certificate it can **observe** for expiry and validity problems.
**Detection only** — certwatch never opens a socket, never probes, never sends a
byte. Same passive-first posture as the rest of the Ragnar Watch suite.

It reuses `tls_watch.py`'s audited handshake byte-parsers (ClientHello SNI,
ServerHello version, the Certificate message, record/segment reassembly) — one
parser, not two — and adds a cert-focused triage engine, a bounded passive flow
tracker, batch triage over pcap directories, and a self-test.

## The one caveat that shapes everything

The server certificate is cleartext on the wire **only for TLS 1.0/1.1/1.2**. In
**TLS 1.3 the Certificate message is encrypted** under the handshake keys (sent
after ServerHello), so it is **not observable passively** — no keys, no cert.
This is a property of TLS 1.3, not a parser limitation.

certwatch turns that into a feature: for a 1.3 flow it emits an **inventory**
record (SNI + negotiated version) with a `CERT_NOT_OBSERVABLE` finding, so you
can tell "no cert because 1.3" apart from "no cert because parse failure." And in
practice the certs that are actually broken — expired mgmt interfaces, iDRAC/
iLO/IPMI, self-signed appliances, legacy medical/IoT gear, internal PKI — are
exactly the population still speaking 1.2. Passive catches the problem certs and
inventories the modern ones.

## What it flags

| Code            | Sev  | Meaning                                              |
|-----------------|------|------------------------------------------------------|
| `EXPIRED`       | CRIT | `notAfter` in the past                               |
| `NOT_YET_VALID` | CRIT | `notBefore` in the future                            |
| `NAME_MISMATCH` | CRIT | observed SNI not covered by cert CN/SAN              |
| `WEAK_SIG_MD5`  | CRIT | MD5/MD2 signature                                    |
| `WEAK_SIG_SHA1` | CRIT | SHA-1 signature                                      |
| `EXPIRING_SOON` | WARN | within `--warn-days` (default 30) of expiry          |
| `WEAK_KEY`      | WARN | RSA <2048, DSA, or EC <256                           |
| `SELF_SIGNED`   | WARN | issuer == subject                                    |
| `MISSING_SAN`   | WARN | CN-only cert, no subjectAltName                      |
| `LONG_VALIDITY` | INFO | validity window >398d (internal/non-public PKI)      |
| `WILDCARD`      | INFO | wildcard SAN present                                 |
| `CA_CERT`       | INFO | BasicConstraints CA:TRUE presented as leaf           |

A record's `status` is the worst finding severity (`CRIT`/`WARN`/`INFO`/`OK`).
Records also carry `module`, `type` (`cert` or `inventory`), `days_left`
(signed — negative once expired, so a SIEM can alert on `days_left < 7` without
regexing a string), `validity_days`, `subject_cn`/`issuer_cn`, `serial`,
`sig_alg`, `key_type`/`key_bits`, `version`, `server_ip`/`server_port`, and in
batch mode the `pcap` provenance.

`NAME_MISMATCH` only fires when the SNI was observed in the same connection's
ClientHello; certwatch keys flows canonically and matches the client-side SNI to
the server-side Certificate without needing to know which side is "server" up
front.

## Usage

```bash
# live, on a mirror/monitor interface, JSON lines to stdout
sudo python3 python/certwatch.py -i mon0 --json

# offline triage from a capture (.gz ok)
python3 python/certwatch.py -r handshakes.pcap

# widen the port set (or 'any' for all TCP — heavier)
python3 python/certwatch.py -i eth0 --ports 443,8443,9443,10250 --warn-days 14

# batch-triage a directory of captures, collapsing repeat sightings
python3 python/certwatch.py --pcap-dir /captures --recursive --dedupe --min-status WARN

# self-test (no wire, no interface needed)
python3 python/certwatch.py --selftest
```

The default port set is the common TLS-bearing ports; keep it tight on the Zero
2 W. `--min-status WARN` suppresses the OK/INFO noise (inventory records are
INFO, so `--min-status WARN` hides them).

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
  rotation set.** The default is a fresh tracker per file: carrying state across
  unrelated captures lets a 4-tuple in one file merge with a colliding 4-tuple
  in another and fabricate a record. A handshake straddling a rotation boundary
  is all you lose otherwise.
- A corrupt or truncated capture is skipped with a note on stderr and never
  aborts the run. Progress goes to stderr, records to stdout, so
  `--json | your_forwarder` stays clean.

A `batch_summary` record (counts by status and finding code) is emitted at the
end in `--json` mode, and printed to stderr otherwise.

## Self-test

`python3 python/certwatch.py --selftest` → **58/58**. The harness mints certs in-memory
(expired, not-yet-valid, expiring-soon, self-signed, weak-key, wildcard, no-SAN,
long-validity, name-match/mismatch), ships a real openssl-minted SHA-1 cert as a
fixture (the `cryptography` lib refuses to *sign* SHA-1), and synthesizes TLS
byte streams to exercise the reassembler: SNI extraction, ServerHello version +
`supported_versions` (1.3), single/chained Certificate messages, handshake
fragmented across TLS records, a cert spanning multiple TCP segments,
out-of-order segments, coalesced ServerHello+Certificate, the TLS 1.3 inventory
path, non-TLS/garbage input, malformed-length safety, per-flow buffer cap,
`MAX_FLOWS` LRU eviction, and the TTL sweep. Two checks drive real scapy
IPv4/IPv6 packets through the live capture handler, and the flow-path tests
assert findings actually fire end-to-end (not just that a record was shaped).

## Deploy (systemd)

`scripts/certwatch.service` runs as an unprivileged `certwatch` user with only
`CAP_NET_RAW`, `ProtectSystem=strict`, a seccomp `@system-service` filter, and
`MemoryMax=128M`. JSON records go to journald.

```bash
sudo useradd -r -s /usr/sbin/nologin certwatch
sudo cp scripts/certwatch.service /etc/systemd/system/certwatch.service
sudoedit /etc/ragnar/certwatch.env         # set CERTWATCH_IFACE=mon0 etc.
sudo systemctl daemon-reload && sudo systemctl enable --now certwatch
journalctl -u certwatch -f
```

## Pi Zero 2 W notes

- **Capture drops**, not CPU, are the ceiling: scapy's Python receive path is
  the bottleneck long before the A53 cores are. On a busy SPAN keep `--ports`
  tight or mirror only the VLAN/subnet of interest. For line-rate taps move to a
  Pi 5 or add an AF_PACKET/eBPF prefilter — the parser is happy either way.
- **Memory** is bounded: `MAX_FLOWS` (512) × `MAX_FLOW_BYTES` (64 K) ≈ 32 MB
  worst case, with LRU + 30 s TTL eviction. Flows are freed the instant the
  Certificate (or a 1.3 ServerHello) is seen. Safe on 512 MB.
- **Hostile input**: every parser is length-checked and wrapped; a malformed or
  adversarial handshake drops that one flow, never the daemon.

## Relation to the existing TLS / Cert Watch

- **`tls_watch.py`** (Switch & L2/L3 → TLS Watch) is a passive TLS/QUIC
  *handshake* observer — fingerprints (JA4/JA3), SNI/ALPN, SNI↔cert mismatch. It
  shares its parsers with certwatch.
- **Cert Watch** (`do_cert_watch`) is the *active* certificate/hygiene checker
  that opens sockets to grade named targets.
- **certwatch** is the passive, standalone, batch-capable cert-triage daemon —
  detection-only, journald/JSON-lines oriented, for taps and capture archives.

## OSI placement

certwatch sits at **L6 (presentation)** — X.509 / TLS handshake semantics —
complementing the L2/L3 Watch modules. Requires `scapy` and `cryptography`.
