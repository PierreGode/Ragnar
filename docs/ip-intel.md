# IP Attribution (`ip_intel.py`)

Answers the question you actually have about a hostile IP: **whose network is
this, what country, and who do I report it to?**

```bash
python3 ip_intel.py 1.1.1.1            # human report
python3 ip_intel.py 1.1.1.1 --json     # machine-readable
python3 ip_intel.py 1.1.1.1 --offline  # cache + local classification only
python3 ip_intel.py --self-test        # 41/41, no network, no keys
```

## What is and isn't knowable

| Field | Reliability | Source |
|---|---|---|
| Country | High | RIR registry (RDAP) + Team Cymru |
| ASN + AS org | **Authoritative** | Team Cymru / RDAP |
| Network owner + CIDR | **Authoritative** | RDAP |
| Registry (RIPE/ARIN/APNIC/…) | **Authoritative** | RDAP |
| **Abuse contact** | **Authoritative** | RDAP — *the actionable field* |
| Reverse DNS (PTR) | High when set | DNS |
| City | Estimate, often wrong | GeoIP (only if a local DB is present) |
| **Street address** | **Never reported** | — |

### Why no street address

Sites that show one are showing either the **ISP's registered corporate address**
or a **centroid** — a fallback midpoint used when the database only knows
"somewhere in this country". MaxMind's US default centroid famously resolved to
**a farm in Kansas**, whose residents were harassed for years over IPs that had
nothing to do with them.

Emitting a street address means emitting confident, precise, *wrong* data that
can point at an innocent household. Every record instead carries a
`location_note` stating exactly this.

## Attribution honesty

Most IPs that attack you are **not the actor's home connection**. `classification`
labels the endpoint (`vpn` / `tor` / `hosting` / `mobile` / `residential` /
`unknown` / `special`) and `attribution_note` says what that means — e.g. for a
VPN exit: *"the location and ISP describe the VPN server, not whoever was using
it — attribution stops here."*

For UDP-based attacks the source IP can also be **outright spoofed**. The honest
framing: an IP trace tells you **which network to report to**, not who did it.

`confidence` (0–100) measures how much of the *ownership* picture resolved (ASN,
AS org, country, prefix, abuse contact) — **not** confidence in a physical
location.

## Anycast / country disagreement

The registry country and the routing country legitimately differ — `1.1.1.1`
registers to APNIC-LABS in **AU** but is announced worldwide. When RDAP and Team
Cymru disagree, both are reported (`country`, `country_routing`) with a
`country_note` explaining why, rather than silently picking one.

## Non-public addresses

RFC1918 / loopback / link-local / multicast / reserved addresses are classified
**locally with no network call at all** — there is no registry owner to look up,
and the record says so instead of making a pointless query.

## Privacy / opsec

Ownership lookups are RDAP (HTTPS to `rdap.org`) and Team Cymru (DNS). Both are
outbound queries about the IP you are investigating. Set
`ip_intel_allow_network: false` to run fully offline (cache + local scope
classification only) — for a passive sensor there are situations where you'd
rather not signal that you looked. Results are cached (24 h TTL) in
`data/ip_intel_cache.json`, so repeat views cost nothing.

## Where it shows

- **Diagnostics → IP Attribution** — a lookup box (accepts an IP or a hostname).
- **Incidents** — public IPs inside a correlated
  [incident](incident-correlation.md) are attributed automatically at serve time
  (from cache), so a hostile IP arrives pre-labelled with country, operator, and
  the abuse address to report it to.

API: `POST /api/net/ip-intel {"ip": "…", "offline": false}`.

## Config

| Key | Default | Meaning |
|---|---|---|
| `ip_intel_allow_network` | `true` | permit RDAP/DNS lookups (`false` = offline only) |
| `ip_intel_enrich_incidents` | `true` | auto-attribute public IPs in incidents |

## Self-test

`python3 ip_intel.py --self-test` → **41/41**, entirely offline: scope
classification (v4/v6/private/ULA/link-local/multicast/invalid), RDAP parsing
from a fixture including a **nested** abuse entity and the start/end-address CIDR
fallback, Team Cymru origin/AS-name parsing, endpoint classification, the
cache round-trip **and TTL expiry**, and an assertion that **no address /
latitude / longitude field is ever produced**.
