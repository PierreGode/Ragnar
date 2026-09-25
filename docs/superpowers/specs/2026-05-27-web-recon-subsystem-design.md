# Web Recon Subsystem — Design

**Date:** 2026-05-27
**Status:** Design approved, pending implementation plan
**Scope:** Add TLS audit, passive DNS subdomain enumeration, and HTTP content discovery as a pre-flight recon phase that feeds the existing ZAP scanner.

## Goals

Expand Ragnar's offensive toolset with three reconnaissance capabilities that every web pentest engagement needs, and wire them as a pre-flight phase before the existing OWASP ZAP scan. The operator gates which discovered assets get fed into ZAP, preserving engagement scope.

## Non-goals

- Active DNS brute-force (passive sources only for v1).
- Pi-mode availability (server-mode only, consistent with `advanced_vuln_scanner.py`).
- New schema for findings (reuse existing `VulnerabilityFinding`).
- Standalone CLI runners (UI-triggered only for v1).

## Architecture

New module `recon_engine.py`, sibling to `advanced_vuln_scanner.py`. Server-mode gated via the same `is_server_mode()` check used by the existing advanced scanner.

```
ReconType (Enum)        PORT_SCAN | TLS_AUDIT | DNS_PASSIVE | CONTENT_DISCOVERY
ReconResult (dataclass) recon_type, target, findings[VulnerabilityFinding],
                        artifacts (dict), duration_seconds,
                        status (ok|partial|error), error_message

class ReconEngine:
    def run(self, target: str, recon_types: list[ReconType],
            timeout: int = 600) -> dict[ReconType, ReconResult]
    def _run_port_scan(self, target) -> ReconResult
    def _run_tls_audit(self, target) -> ReconResult
    def _run_dns_passive(self, target) -> ReconResult
    def _run_content_discovery(self, target) -> ReconResult
```

`ReconEngine.run()` fans out the requested runners in parallel via `ThreadPoolExecutor(max_workers=3)`. Each runner is fully independent. One runner failing marks only its own `ReconResult.status = "error"`; the others continue.

The engine tracks in-flight scans in a class-level `active_scans: dict[scan_id, ReconState]` (same pattern as `AdvancedVulnScanner.active_scans`). `scan_id` is a UUID minted on POST; status endpoints look up by id; results are retained for 1h then evicted.

Registrable-domain extraction uses `tldextract` (Public Suffix List–aware) so that `*.co.uk` and similar multi-label TLDs behave correctly.

### Data flow

```
operator triggers recon in UI
        ↓
POST /api/recon/scan { target, recon_types[] }
        ↓
ReconEngine.run() executes in background thread
   ├── TLS audit       (sslyze, in-process)
   ├── DNS passive     (crt.sh HTTP + dnspython resolve)
   └── Content disco   (ffuf subprocess, JSON output)
        ↓
results streamed via existing status-polling pattern
        ↓
recon findings (weak TLS, etc.) land in existing findings list immediately
        ↓
operator reviews discovered subdomains + interesting paths in UI gate
        ↓
POST /api/recon/scan/<id>/handoff { subdomains[], paths[] }
        ↓
existing AdvancedVulnScanner is invoked with augmented:
   - target_urls[]   = original + approved subdomains
   - extra_paths[]   = approved paths seeded into ZAP forced-browse
        ↓
ZAP scan proceeds as today
```

## Tool wrappers

### TLS_AUDIT — sslyze

- Library: `sslyze` (pure Python, no subprocess)
- Inputs: hostname + port (default 443; auto-detected from URL if scheme-qualified)
- Outputs:
  - Findings: expired/expiring (<30d) certs, weak cipher suites (RC4, 3DES, anonymous, NULL, CBC where downgradable), missing HSTS, SSLv2/SSLv3/TLS1.0/TLS1.1 enabled, self-signed or untrusted chains, mismatched hostname
  - Artifact: serialized cert chain (issuer, subject, SANs, validity dates), negotiated cipher list, protocol support matrix
- Failure modes: connection refused → `status="error"`; sslyze internal exception → caught, message in `error_message`

### DNS_PASSIVE — crt.sh + dnspython

- HTTP source: `https://crt.sh/?q=%25.<domain>&output=json` (certificate transparency logs)
- Resolution: `dnspython` for A/AAAA lookups on discovered names
- Liveness probe: HEAD request, 5s timeout, accept any 2xx/3xx
- Inputs: registrable domain (extracted from target URL if needed)
- Outputs:
  - Artifact: deduped subdomain list `[{name, a_records[], aaaa_records[], alive: bool}]`
  - Findings: wildcard records, TXT records containing apparent secrets (regex: AWS keys, GitHub tokens, basic-auth-style strings) — informational severity
- Failure modes: crt.sh rate-limited / down → `status="error"` with the upstream error message. No fallback in v1 (active brute-force is out of scope).

### CONTENT_DISCOVERY — ffuf

- Binary: `ffuf` (subprocess, JSON output mode)
- Wordlist: SecLists `Discovery/Web-Content/common.txt`, bundled at install time; operator-configurable path in scan config
- Inputs: base URL, wordlist path, optional extensions list (`.php,.bak,.old`)
- Outputs:
  - Artifact: `[{path, status, length, words, content_type}]` for every hit
  - Findings: "interesting" hits — admin/, backup/, .git/, .env, .htaccess; any 200 OK on path matching a known-sensitive pattern; any path returning a different size class than the 404 baseline (auto-detected by ffuf)
- Failure modes: ffuf binary missing → `status="error"` with install hint; base URL unreachable → `status="error"`

### Shared helpers

- `_run_subprocess_with_timeout(cmd, timeout)` for ffuf and any future subprocess tools
- `_to_vulnerability_finding(scanner: str, ...)` adapter to coerce tool-specific output into the existing `VulnerabilityFinding` dataclass

## Webapp endpoints

Follows the existing `/api/vuln-advanced/...` naming convention.

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/api/recon/scan` | `{target, recon_types[]}` | `{scan_id}` |
| GET | `/api/recon/scan/<scan_id>` | — | `{status, progress, partial_results}` |
| POST | `/api/recon/scan/<scan_id>/cancel` | — | `{ok}` |
| GET | `/api/recon/scan/<scan_id>/handoff-options` | — | `{ports[], subdomains[], paths[], tls_findings[]}` |
| POST | `/api/recon/scan/<scan_id>/handoff` | `{ports[], subdomains[], paths[]}` | `{zap_scans[]}` |

### PORT_SCAN — web-port discovery

A parallel TCP connect-scan over a curated `COMMON_WEB_PORTS` list (80/443/8080/8443/8000/3000/5000/9443/…). Each open port is classified `http` vs `https` by attempting a TLS handshake (self-signed tolerated: `check_hostname=False`, `CERT_NONE`), yielding `{port, scheme, url}` artifacts plus INFO findings. This solves the "bare IP defaults to :80 but nothing's there" problem: the operator sees the actual listening web ports and, in the handoff gate, ticks exactly which `scheme://host:port` URLs get fed to ZAP (80/443 pre-checked, non-standard ports opt-in). When ports are selected they replace the bare target as the ZAP scan seed.

The handoff endpoint invokes the existing `AdvancedVulnScanner` instance directly (in-process function call, not an HTTP self-call) with an augmented target list (selected ports + subdomains) and a new `extra_paths` argument that the scanner will pass to ZAP's forced-browse / spider-seed API. **This requires a small additive change to `AdvancedVulnScanner.start_scan()` (or its equivalent entry point) to accept and forward `extra_paths`.** No ZAP-trigger logic is duplicated in `recon_engine.py`.

All endpoints reuse the existing `@check_authentication` guard.

## UI integration

One new card in the vuln-scan view (`web/index_modern.html` + `web/scripts/ragnar_modern.js`), placed above the existing "Start ZAP scan" button.

**State 1 — pre-recon:** three checkboxes (TLS audit, DNS passive, content discovery), all on by default. "Run recon" button.

**State 2 — recon running:** progress per runner (3 mini progress bars), live findings counter, cancel button.

**State 3 — operator gate:** discovered subdomains (with alive/dead indicator and A record) and interesting paths (with status + size), each checkbox-selectable. "Hand off to ZAP scan" button. Scope warning surfaces in red if a checked subdomain doesn't match the target's registrable domain.

**State 4 — handed off:** card collapses; existing ZAP scan card takes over, showing the augmented target list.

Recon findings (weak TLS ciphers, expired certs, surprising TXT records) appear in the existing findings list immediately as they're discovered — they do not wait on the handoff gate.

## Error handling

- Per-runner timeout: 300s default, configurable per scan
- Whole-engine hard cap: 600s
- Runner exceptions are caught at the `_run_*` boundary; result is returned with `status="error"` and the exception message in `error_message`
- The engine never raises; callers always get a `dict[ReconType, ReconResult]`
- Scope guard: handoff endpoint validates that every requested subdomain shares the registrable domain with the original target; mismatches return HTTP 400 with the offending names listed (operator must explicitly override via a `force: true` flag)

## Testing

- **Unit:** each `_run_*` method with recorded fixtures (saved crt.sh JSON, captured sslyze ServerScanResult, sample ffuf JSON output)
- **Unit:** the engine's parallel-fanout + partial-failure behavior (mock one runner to raise, assert other two still complete)
- **Unit:** the handoff scope guard (same-registrable accepted, cross-registrable rejected without `force`, accepted with `force`)
- **Integration:** end-to-end recon against `https://expired.badssl.com` and `https://wrong.host.badssl.com` to validate the TLS finding pipeline against real network conditions
- **Integration:** handoff endpoint actually augments the ZAP scan target list (mock the AdvancedVulnScanner, assert call args)

No new fixtures for ffuf integration tests (ffuf binary on CI is brittle); covered by unit tests with recorded JSON.

## Install changes

`install_ragnar.sh` additions:

- `pip install sslyze dnspython` (both pure Python, no native deps)
- `apt install ffuf` (or download binary release for the target arch)
- Clone SecLists `Discovery/Web-Content/` subset to `/opt/ragnar/wordlists/`

No Pager (MIPS) changes — server-mode only.

## Future work (out of scope for v1)

- Active DNS brute-force as opt-in mode
- Pi-mode availability (after server-mode lands)
- Additional recon types: web tech fingerprinting (whatweb is already in ScanType but unused), reverse DNS sweep, Shodan/Censys lookups
- Bundling the recon phase into the ZAP scan as a single "deep scan" preset
