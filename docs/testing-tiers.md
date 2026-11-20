# Ragnar Testing Tiers — Glossary

As of Nov 20, 2026

Every Ragnar module is proven by a stack of tiers, each built to catch a class of bug the others structurally cannot. A full build runs them in roughly this order, usually from one `run_all.sh`:

1. Module self-test (with golden bytes)
2. Conformance harness
3. Cross-check (xcheck) against independent oracles
4. README + machine verifier
5. Systemd unit verifier
6. Sealed-namespace lab, plus pcap replay where the kernel can't carry a case
7. Bite harness run against all of the above

The rule behind the whole stack: a tier only counts if a bite mutation inside its subject area moves it.

## Core tiers

| Tier | What it is | Why it exists |
| --- | --- | --- |
| Module self-test | In-process tests shipped inside the module, driving the parser and detection engine with built fixtures. | Fast proof each detector fires and stays quiet on its fixtures. Cannot catch an error the builder and parser share (LESSON A). |
| Golden bytes | Hand-computed expected byte strings from the standard, with boundary values (e.g. mrpwatch's 215 valid / 216 invalid vector byte). | Ground truth where no third-party dissector exists for the protocol. |
| Conformance harness | Stdlib-only harness that drives the production parsers and engine section by section: structure, flags and BPF, passive invariant, live capture path, parsers, per-CVE, thresholds, robustness/fuzz, clean-set silence, coverage, lab artefacts. | Exhaustive spec conformance, run standalone from an empty directory so it can't lean on the repo. |
| Cross-check (xcheck) | Feeds the same traffic to implementations Claude did not write and compares answers field by field. See Oracles below. | The only tier that catches a bug the module's own builder and parser agree on. |
| README + machine verifier | A script that reads claims out of the README and checks them against the module source, the systemd unit, and live runs of the other tiers. Codes, severities, flags, CVSS, constants, JSON examples, per-tier counts. | Turns documentation drift into a build failure. Strongest form re-runs the behaviour a claim describes rather than grepping prose. |
| Systemd unit verifier | Static checks on the unit (capabilities, `ProtectSystem`, `RestrictAddressFamilies` compared as a set, `IPAddressDeny`) plus a real `setpriv` run: capture must fail without `CAP_NET_RAW` and succeed non-root with it. | Proves the hardening exists and that the service can still do its job under it. |
| Sealed-namespace lab | Two network namespaces joined by a veth pair, no default route, the module sniffing its own interface through the real capture path while real servers or an injector generate traffic. | Proves the kernel accepts the filter and the live path works on real frames. Cannot reproduce reordering, since veth delivers in order. |
| Pcap replay | Recorded pcaps driven through the real `run_capture()` and the real BPF via offline sniff. | Covers what the lab kernel can't carry, notably IPv6 where the sandbox kernel has it compiled out. |
| Smoke test | Quick start-and-run check: module imports, starts, parses one known frame, exits clean. | Catches a broken build in seconds before the long tiers run. Not a separately named tier in the build records. |

## Oracles (what the cross-check compares against)

| Oracle | What it is | Why it exists |
| --- | --- | --- |
| Scapy | Scapy's dissectors, run both ways: scapy builds and the module parses, and the module's fixtures are dissected by scapy. | Independent field reading; the reverse direction catches a malformed fixture the repo's builder and parser happen to agree on. |
| Real production stacks | Genuine handshakes through real software over loopback, recorded by a relay that never terminates the session: OpenSSL, GnuTLS, aioquic, OpenSSH. | The software's own report is the oracle. Finds behavioural bugs (segment splitting vs coalescing) that encoding checks miss. |
| BER cross-check | Independent decode of ASN.1 BER (the LDAP encoding) against ldapwatch's hand-rolled BER parser. | BER length and tag rules are where a self-consistent parser goes silently wrong. |
| FRR cross-check | A real FRR routing daemon (ripwatch used ripd 8.4.4) runs a live session, and the module watches its traffic. FRR's own steady-state behaviour is the ground truth. | Real routing speakers do legitimate things fixtures never do. ripd's startup full-table Request and unicast Response would otherwise have fired RIP-107 and RIP-108, so the tier delivered two false-positive fixes and a zero-FP clean baseline. |
| tshark / Wireshark | `tshark -T fields` reads named fields from a pcap, written from the RFC by people with no knowledge of the module. | Third-party field offsets for protocols scapy doesn't cover. Needs a both-ways guard, since many dissectors are conversation-stateful and return empty fields on short fixtures. |
| Counterfactual | A deliberately wrong but internally consistent model (e.g. a nibble moved to the wrong half), asserted to disagree with both implementations. | Proves the agreement on the correct fixture actually means something. |
| Wire round-trip | Fixtures serialized to bytes and re-dissected before the pipeline sees them. | A built scapy object can expose fields the same bytes off the wire never would (LESSONs AD and AG). |

## Bite harness and mutations

| Term | What it is | Why it exists |
| --- | --- | --- |
| Bite test | A harness that injects a known regression into the module, README or unit, runs the tiers, records which ones caught it, then restores. Scored as caught / total (e.g. pimwatch 18/18). | Tests the tests: proves each tier has teeth. |
| Mutation | One injected regression: a removed guard, an off-by-one, a little-endian read, a dropped fixture, a downgraded severity. Length-preserving mutations (swapping one offset for another) are the most valuable. | The unit a bite run measures. |
| Escape | A mutation no tier caught. Either a real detection gap or a fixture set that can't tell the two behaviours apart (LESSON X). | Every escape is investigated, never waved through. |
| Per-tier delta | Which tiers moved on each mutation, not just whether one did. | A tier that doesn't move on a mutation in its own subject area is thin there (LESSON AF). |
| Mutation hygiene | Separating "module broken" (SyntaxError, missing import, crash) from "regression undetected"; announcing any skipped section (`--fast`). | A crash produces zero FAIL lines and looks like an escape (LESSON L). |
| Baseline guards | Pristine copy restored at the start of every run, exact clean baseline asserted before mutating, byte-identical check at the end, `__pycache__` dropped after every write and restore. | A killed run leaves the tree mutated, and stale bytecode can survive a restore (LESSONs AI and AM). |

## Drift and guard checks

These run inside the tiers above rather than as tiers of their own.

| Check | What it is | Why it exists |
| --- | --- | --- |
| Code drift | Set comparisons in both directions between code and docs (codes, flags, CVE ids, constants), plus live per-section counts reconciled against the README's tables. | Catches undocumented flags, stale counts and renamed codes the moment they drift. |
| Passive-invariant AST guard | Scans the module's syntax tree for any transmit call, split by AST shape (bare `sendp()` vs `subprocess.run`) with a receiver allow-list. | Proves the module can't put a packet on the monitored wire. |
| Live capture path test | Swaps a recorder in for scapy's sniffer and asserts interface, `store=False`, the BPF installed and `offline=` not set. | The capture function is the one path no offline tier otherwise executes (LESSON C). |
| Coverage check | Every finding code has at least one fixture that fires it; extractor handles literal, assigned and loop-unpacked codes. | A code with no fixture is untested by definition (LESSON M). |
| Non-vacuity check | Asserts a check actually looked at something: row counts, an oracle recognised the protocol, an extracted section isn't nine characters long. | Stops checks passing because they iterated zero times. |
| Clean-set silence (FP gate) | Benign real traffic must produce no attack-class finding, asserted positively (`transport == "tls"`), not just "nothing fired". | Silence can be satisfied by the wrong path (LESSON AL). |
| Fuzz / truncation sweep | Every prefix of a valid message plus random and structured garbage; only the expected error may escape. | Hostile input must never crash a passive sensor. |
| Duplicate / unused name scan | AST check that no module-level name is defined twice and no import is dead. | A fixture builder once shadowed a production parser (LESSON G). |

## Lab techniques

| Technique | What it is | Why it exists |
| --- | --- | --- |
| Seal proof | The lab script counts interfaces and checks for a default route, aborting if either is wrong. Teardown runs unconditionally. | Proves the lab is sealed rather than assuming it. |
| Readiness canary | A known flow sent to a dedicated port; the lab blocks until that exact finding appears before running scenarios. | A fixed sleep silently lost the first six telnetwatch scenarios (LESSON AB). |
| Runtime code list | Expected codes read from `--print-lab-codes` at runtime, never hardcoded. | New codes show up as MISS until a scenario is added. |
| Sender-side reorder | A flow's segments emitted in reverse sequence order onto a real interface. | `sch_netem` isn't in the sandbox kernel; this is the only way out-of-order frames cross a real NIC here. |
| Loud skip | A scenario the host can't run (IPv6 compiled out) skips with a visible reason. | A silent pass on an impossible case is worse than no test (LESSON AE). |
| Scale run | Paced raw-socket traffic driven to a real threshold (tlswatch's 32 GiB SWEET32 tier), target computed from the threshold constant with margin. | Proves counters latch correctly at volumes no offline test reaches. |
| On-hardware run | Capture on the Pi Zero 2W under USB-bus contention. | The one condition no sandbox tier reproduces; stays open per module until a device capture closes it. |

## Where the tiers live in this repository

The tiers above run when a detection module is built, before it is vendored into
Ragnar. What ships with the module, and where you can run it:

- **Module self-tests** ship inside every vendored watcher and guard, and run on the
  box itself from **Network → Diagnostics → Overview → Detector Self-Test**
  (`GET /api/net/routing-selftest`). See
  [Detector Self-Test](nettools.md#detector-self-test).
- **Conformance and cross-check (xcheck) files** ship for some modules, under
  `python/`: for example `lldpwatch_conformance.py`, `lldpwatch_scapy_xcheck.py`,
  `aristaguard_conformance.py`, `mrpwatch_conformance.py`, `oamwatch_tests/` and
  `cfmwatch_tests/`.
- **The README verifier, systemd unit verifier, sealed-namespace lab, pcap replay and
  bite harness** stay with the module's build. When a module is ported into Ragnar,
  its self-test is added to the Detector Self-Test, and its CVEs are added to the
  [CVE index](CVE.md).
