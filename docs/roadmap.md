# Ragnar Roadmap

A working checklist of things that would take Ragnar to the next level. This is a
*mature* codebase (700+ merged PRs, ~110 root modules, an L2→L7 watcher suite, RF/SDR,
mesh, RuSense), so most of what's left is **hardening, finishing half-done work, and
keeping a large codebase maintainable** — not net-new features.

Ordered by leverage. Each item cites the evidence it came from so it can be checked
rather than taken on faith.

> **Provenance.** Tiers 1, 2 and 4 were verified against the tree on 2026-10-05
> (file/line cited). Tier 3 is drawn from the project's own working notes and
> release log — re-confirm each against current code before starting, as notes lag
> the tree.

---

## Tier 1 — Engineering hygiene (highest leverage)

- [ ] **Run the test suite in CI.** There are **53 `tests/test_*.py` files plus 40
  modules exposing a `selftest()`**, but the only GitHub workflows are `codeql.yml`,
  `docker-publish.yml` and `build-rusense-flasher.yml` — **nothing runs the tests on
  push/PR.** Every "Selftest N/N" line in [releases.md](releases.md) is verified by
  hand today. Add a `pytest` + selftest-runner workflow on `pull_request`.
- [ ] **Wire the linter into CI.** `.pylintrc` exists (22 KB) but no workflow invokes
  it. Add a lint job (pylint or ruff) so style regressions are caught automatically.
- [ ] **Pin dependencies / add a lockfile.** `requirements.txt` has 32 entries but only
  **3 are `==`-pinned**; the other 29 are `>=` floors. That undermines the standing
  "a fresh clone/install must work everywhere" rule — one breaking upstream release
  can silently break new installs. Add a constraints/lock file (or pin known-good
  versions), referenced from [INSTALL.md](INSTALL.md).
- [ ] **Decompose the monoliths.** `webapp_modern.py` is **30,603 lines / 499 route
  handlers**, `network_diagnostics.py` is **30,309 lines**, and
  `web/scripts/ragnar_modern.js` is **39,641 lines** in a single file. Split the Flask
  app into blueprints and the JS into ES modules (the pattern already used under
  `web/rusense/`). This is the main drag on future velocity.

## Tier 2 — Harden the tool itself

Ragnar launches attacks, a reverse shell, and rubber-ducky HID injection, and controls
a fleet over the mesh — its own front door should model the security it tests for.

- [ ] **Login brute-force throttling / lockout.** `auth_manager.py` has no
  rate-limiting, lockout, or failed-attempt tracking anywhere in the codebase. Add
  per-IP/per-account throttling with backoff.
- [ ] **Optional TOTP 2FA for the dashboard.** No TOTP/`pyotp` anywhere. The encrypted
  **recovery-code** infrastructure already in `auth_manager.py` (Fernet-wrapped) is a
  natural base to build opt-in authenticator-app 2FA on.
- [ ] **Generate an OpenAPI spec for the ~499 routes.** The only `openapi` artifact in
  the tree is a bundled ZAP plugin. A generated spec would feed the ZAP self-scan, the
  Home Assistant integration, Ragnarmobile and RagnarScripts — all of which track the
  API by hand today (`config/routes.json` is docs-only / non-authoritative).

## Tier 3 — Finish half-done features

From the project's own notes and release log — **re-verify against current code.**

- [ ] **RuSense live-person validation** — flagged as a pending 2-part person-entry
  validation. See [rusense.md](rusense.md).
- [ ] **EIGRP FRR lab** — FRR adjacency still unvalidated (`eigrp_lab.sh` /
  `eigrp_inject.py`). See [eigrp_lab.md](eigrp_lab.md).
- [ ] **Net Integrity wired capture** — real-cable path unvalidated.
- [ ] **Cellular uplink** — Orbic hardware test pending (`cellular_uplink.py`). See
  [cellular-uplink.md](cellular-uplink.md).
- [ ] **BT/BLE + WiFi 2.4 GHz coexistence** — coexistence pending (`bt_scanner.py`
  overlay on the WiFi analyzer).
- [ ] **RF Waterfall slow-sweep fix** — the 2026-10-05 smooth-scroll fix is "not yet
  confirmed on live hardware." Confirm on a real dongle. See
  [rf-waterfall.md](rf-waterfall.md).
- [ ] **Gamification RF events** — RF events still unwired into the v2 level system.
- [ ] **Deferred detector work** — SR-MPLS IPv6 refactor (excluded in v2), DHCP
  Guardian structural CVEs, and NTP oversize handling were all deferred. See
  [nettools.md](nettools.md).

## Tier 4 — Concrete code gaps (verified live)

- [ ] **Persist OS / services / deep-scan to the database.**
  `webapp_modern.py:12005-12006` hard-code `'os':'Unknown'` / `'services':'Unknown'`,
  and `shared.py:2110-2111` leave `Deep_Scanned` / `Deep_Scan_Ports` blank — all four
  marked *"TODO: add to database schema."* nmap already collects this; the asset
  inventory and reports show "Unknown" only because it is never stored. See
  [asset-inventory.md](asset-inventory.md).
- [ ] **AlienVault OTX is advertised but disabled.** The README lists threat intel
  "from CISA KEV, NVD CVE, AlienVault OTX, and MITRE," but
  `threat_intelligence.py:645` returns `None` — *"DISABLED… requires API key."* Either
  wire up a real OTX API-key path or soften the README/[scanning-and-attacks.md](scanning-and-attacks.md)
  claim so docs match behaviour.

## Tier 5 — Possible new directions (lower confidence)

These are suggestions, not proven gaps — weigh them against your own priorities.

- [ ] **Real-hardware integration tests** (Pi 5 / Zero 2 W / Pager) alongside the
  selftests. The recurring risk is "works on the dev box, breaks on the Zero 2 W or
  Pager"; a small smoke-test matrix on actual boards would catch it.
- [ ] **A living public roadmap.** [Upcoming.md](Upcoming.md) is currently one line;
  this document is a start toward something contributors can read at the 700-PR pace.
