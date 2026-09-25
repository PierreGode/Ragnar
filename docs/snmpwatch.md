# snmpwatch — passive SNMP community-exposure scanner

`snmpwatch` is a standalone, **detection-only** SNMP monitor — the deep companion
to the integrated [SNMP Watch](nettools.md#snmp-watch) inside
`network_diagnostics.py`. It never emits an SNMP packet — no walking, no community
guessing, no GET/SET. It watches SNMP already on the wire (BPF `udp port 161/162`)
and flags the exposure. The community strings it prints are the ones the network
is leaking on its own.

Where the integrated watch classifies `tcpdump`-decoded text, `snmpwatch` carries
its own **pure-Python BER/ASN.1 SNMP decoder**, which unlocks what tcpdump text
can't: SNMPv3 `msgFlags` mode analysis, plaintext-`scopedPDU` detection by BER
tag, and an OID-hint pass over the varbinds. The decoder is Scapy-free, so
`--selftest` runs with no Scapy and no NIC.

- **Test floor:** Raspberry Pi Zero 2 W.
- **Self-test:** 82/82 (`python3 python/snmpwatch.py --selftest`).
- **Deps:** Python 3.9+, Scapy (live capture only).

## What it detects

| Observation | Severity | Why |
|---|---|---|
| SNMPv1/v2c **SetRequest** | CRITICAL | Cleartext **write** access; replayable/forgeable |
| SNMPv3 **noAuthNoPriv SetRequest** | CRITICAL | No auth key — the write is **forgeable**, same as v2c SET |
| SNMPv1/v2c with **default community** (`public`, …) | HIGH | Guessable *and* in cleartext |
| Any SNMPv1/v2c community string | HIGH | Cleartext — harvestable by any on-path listener |
| SNMPv3 **claims priv, ships plaintext** | HIGH | msgFlags assert privacy but msgData is a plaintext ScopedPDU |
| SNMPv3 **noAuthNoPriv** (reads) | MEDIUM | Auth + encryption both off; no benefit over v2c |
| SNMPv3 **privNoAuth** | MEDIUM | Illegal flag combo (RFC 3412 §6.4); malformed/hostile |
| SNMPv3 **authNoPriv** | LOW | Authenticated but varbinds still visible |
| SNMPv3 **authPriv** | INFO | Properly secured (the goal state) |

Findings are keyed on `(src, dst, version, community, PDU, v3-mode)` so distinct
exposures don't mask each other, and repeats aggregate with a count.

### OID-hint pass

For every plaintext PDU (v1/v2c, and any plaintext v3 scopedPDU), snmpwatch
decodes the varbind OIDs and matches them (longest-prefix) against a table of
write-sensitive branches — turning "a SET happened" into "a SET is writing
**CISCO-CONFIG-COPY-MIB** — config exfil to a TFTP server in cleartext." Covered:
the Cisco config-copy / writeNet / writeMem trees, `usmUserTable` (v3 user
creation), vacm/target/notification MIBs, `ifAdminStatus` (interface DoS),
`ipForwarding`, and the sysName/Contact/Location identity leaves. For writes the
hint is spliced into the reason; reads keep their base severity but are annotated.

### SNMPv3 plaintext scopedPDU decoding

v3 is not automatically safe. Per RFC 3412 the `msgData` field is a **CHOICE**: a
plaintext `ScopedPDU` (SEQUENCE, tag `0x30`) when the priv flag is clear, or an
`encryptedPDU` OCTET STRING (tag `0x04`) when set. **The BER tag alone
discriminates** — so snmpwatch reads the *wire*, not the flags, and decodes
varbind OIDs from any plaintext scopedPDU (covering both `noAuthNoPriv` and
`authNoPriv` — authentication is not encryption). Plaintext v3 findings carry
`contextEngineID` and `contextName`.

Because the tag is authoritative, snmpwatch also catches an agent whose
`msgFlags` **claim privacy while msgData is a plain SEQUENCE** — the payload is
not encrypted regardless of the flag (real ciphertext wouldn't parse as a
well-formed SEQUENCE).

Write severity tracks **authentication, not encryption**: an `authNoPriv` SET is
authenticated, so not forgeable (LOW, hint-annotated); a `noAuthNoPriv` SET has
no key, so any on-path host can forge one — **CRITICAL**, like a cleartext v2c SET.

### Community-reuse correlator (blast radius)

At report time, snmpwatch groups each cleartext community by the set of **agents**
that accept it. A string on 2+ devices is a shared-secret blast-radius signal —
sniff it once, own them all. **HIGH** by default, **CRITICAL** if a SET was ever
seen with that community (one capture = write access to N devices). Emitted as a
`community_reuse[]` block in the report.

## Run

```bash
python3 python/snmpwatch.py --selftest                         # 82/82, no root
sudo python3 python/snmpwatch.py -i eth0 --json /var/lib/ragnar/snmpwatch.json
sudo python3 python/snmpwatch.py -i eth0 -t 300 --json -       # bounded audit, JSON to stdout
```

Requires `CAP_NET_RAW` (sudo, or the systemd unit which grants only that).

## Capture placement

- **SPAN / mirror port (preferred).** Mirror the uplink or management VLAN
  carrying SNMP to `eth0`. Zero data-path risk.
- **Inline bridge tap.** Bridge two NICs and sniff `br0` (same pattern as
  `dhcp_doctor`). SNMP is low-volume and the BPF pre-filter drops everything else,
  so inline mode is safe on the Zero 2 W test floor.

## systemd

`scripts/snmpwatch.service` runs least-privilege (`CAP_NET_RAW`, `ProtectSystem=
strict`, `MemoryMax=128M`); set `RAGNAR_IFACE=` in the unit (`br0` for inline).

## Web UI

`report()` emits `{module, generated, stats, severity_counts,
insecure_versions_present, community_reuse[], findings[]}` — the same JSON shape
the other modules use. `insecure_versions_present` is the one-glance red/green
tile; `findings[]` (each with `oids[]` and `oid_hints[]`) drives the detail
table; `community_reuse[]` drives a blast-radius panel.

## Relation to the integrated SNMP Watch

- **SNMP Watch** (`do_snmp_watch` in `network_diagnostics.py`) is the web-UI /
  Network-Integrity-Monitor path: a short `tcpdump` capture classified into the
  suite verdict ladder (write-exposed / cleartext / amplification / enumeration),
  with the community-reuse blast-radius correlator added inline.
- **snmpwatch** is the standalone deep monitor: a BER decoder, per-message
  severity with v3 mode analysis + plaintext-scopedPDU detection, the OID-hint
  pass, and a hardened daemon.

## OSI coverage

Application-layer (L7) exposure detection, complementing the L2/L3 modules —
fills the SNMP slot alongside `dnswatch` on the app-layer side of the suite.
