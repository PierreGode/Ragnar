# ragnar_syslog — JSON-lines → syslog/CEF/LEEF (Ragnar)

Reads the JSON-lines any Ragnar `*watch` module writes to stdout and forwards
it to a SIEM/collector. **Module-agnostic by design**: it keys off the suite's
shared record conventions (`module` / `type` / `status` / `findings[].code`),
so one shim serves certwatch, dnswatch, ospfwatch, isiswatch, smbwatch and the
rest instead of each module growing its own SIEM plumbing.

```bash
certwatch.py -i mon0 --json \
  | ragnar_syslog.py --transport udp --host siem.example.net --port 514 \
      --format cef --min-status WARN
```

## Why it's a separate process

This is the only component in the suite that transmits. The scanners are
strictly passive; forwarding your own findings to your own collector is a
different act, so it lives in its own process with its own systemd unit and its
own egress rules. `certwatch` keeps `CAP_NET_RAW` and never sends a byte;
`ragnar_syslog` sends bytes and never touches the wire. That split makes the
passive guarantee enforceable (`IPAddressAllow=` your SIEM only) rather than a
promise in a README.

## Options

| Flag | Default | Notes |
|---|---|---|
| `--format` | `cef` | `cef`, `leef`, `json`, `text` |
| `--transport` | `stdout` | `stdout`, `udp`, `tcp`, `unix` |
| `--host` / `--port` | `127.0.0.1:514` | collector |
| `--unix-path` | `/dev/log` | local rsyslog/journald |
| `--syslog` | `5424` | `5424`, `3164`, or `none` (bare payload) |
| `--tcp-framing` | `lf` | `lf`, or `octet` for RFC 6587 octet-counting |
| `--facility` | `local0` | |
| `--min-status` | `INFO` | drop below this severity |
| `--fanout` | off | one event per finding instead of per record |
| `--module` | `ragnar` | fallback for records lacking a `module` field |
| `--max-len` | `8192` | truncate over-long payloads |

## Severity mapping

| Ragnar | syslog | CEF/LEEF |
|---|---|---|
| `CRITICAL` | crit (2) | 9 |
| `WARN` | warning (4) | 6 |
| `INFO` | info (6) | 3 |
| `OK` | debug (7) | 0 |

PRI = facility×8 + severity, so `local0` + `CRITICAL` = `<130>`.

## Signature / event class

By default one event per record, with the **worst** finding as the CEF
signature — so a rule can alert on `deviceEventClassId=EXPIRED` directly
instead of substring-matching a joined list. All codes still land in `cs1`.
`--fanout` emits one event per finding (higher volume, strictly one
signature per event); each fanned event carries its own severity and PRI.

## Field mapping

certwatch has a curated map onto standard CEF keys:

`dst`/`dpt` ← server · `rt` ← ts (epoch ms) · `outcome` ← status ·
`cn1` ← days_left · `cs1` ← findings · `cs2` ← subject · `cs3` ← issuer ·
`cs4` ← SNI · `cs5` ← key/sig · `cs6` ← TLS version ·
`deviceCustomDate1` ← notAfter · `externalId` ← serial · `fname` ← pcap ·
`cnt` ← seen_count

Other modules get a best-effort generic map (`src`/`dst`/`smac`/`dmac`/`spt`/
`dpt`/`deviceInboundInterface` where present, findings → `cs1`, remaining
scalars passed through under sanitized keys). Lossy-but-safe beats dropping
data from the 20+ modules without bespoke maps. Add one to `MODULE_MAPS` when a
module earns it.

## Robustness

- **TCP**: lazy connect, exponential backoff to 30s, bounded queue
  (1000, drops oldest). A SIEM restart must not stall the capture path or
  balloon RAM on a Zero 2W — losing findings during an outage beats either.
- **UDP**: fire-and-forget; send errors are logged, never fatal.
- Malformed JSON lines are counted and skipped (first 5 noted on stderr); the
  stream continues.
- No TLS transport. If you need encrypted syslog, front it with `stunnel` or
  point `--transport unix` at a local rsyslog that has the TLS config.

## Self-test

`python3 ragnar_syslog.py --selftest` → **65/65**. Covers CEF header vs
extension escaping (they have *different* rules — `|` in the header, `=` in
extensions; swapping them silently corrupts field boundaries at the collector),
escape ordering, RFC 5424 shape, RFC 3164 space-padded day (`Jul  5`), PRI
arithmetic, MSGID charset, severity mapping, min-status filtering, fanout,
truncation, malformed input, and the generic module map. UDP and TCP are tested
against **real loopback listeners** — including octet-count verification and a
dead-collector case — plus a subprocess end-to-end run of the actual CLI.

## Deploy

`certwatch-forward.service` runs the scanner and forwarder as one pipeline,
two programs. Uncomment `IPAddressDeny=any` / `IPAddressAllow=<siem>` to pin
egress to the collector.
