# Ragnar Releases

## Releases

### 2026-10-05

#### feat(mesh): downloadable trace route / ping / diagnose results
*branch `feature/mesh-probe-download` · PR pending*

- Each **Trace route**, **Ping** and **Diagnose** result on a unit's node page now has a **⬇ Download** link alongside the on-page display — it saves the result as a plain-text report (parsed summary plus, for trace/ping, the raw `traceroute`/`ping` output). Built client-side from the result already in the browser (Blob + `<a download>`), so there is no re-run and no server round-trip; filenames are `trace_<target>_<ts>.txt` / `ping_…` / `diagnose_…`
- No backend change — the probe/diagnose endpoints already return everything the report needs
- Verified: report builders against mock trace/ping/diagnose payloads (hop table, loss/RTT, category/hint/error); results render with the Download link at desktop width

#### feat(mesh): live PCAP capture on the Ragnar fleet node page
*branch `feature/mesh-pcap-capture` · PR pending*

- New **Packet Capture** feature on a unit's node page, next to Traffic Analyzer / Integrity / Threats / Watchtower: start a **bounded** `tcpdump`-to-`.pcap` on any reachable unit (self or peer), pick interface / duration / packet cap / optional **BPF filter**, watch live progress (packets · bytes · elapsed), and **Download** the finished `.pcap` — the real frames for Wireshark, which the Traffic Analyzer (text stats only) never writes
- New `pcap_capture.py` capture engine — strictly bounded (defaults 5 min / 100 MB / one capture at a time, oldest pruned), validates interface + BPF (no option/shell injection), runs `tcpdump` directly as root or via `sudo -n` otherwise. Selftest 10/10; live loopback capture verified (bounded stop, valid pcap, packet count)
- Mesh plumbing mirrors scan delegation: **worker** routes on each unit (`POST /api/mesh/capture/start`, `cancel/<id>`; peer-readable `GET …/status/<id>`, `/list`, `/download/<id>`) with the two writes added to the exact-path **peer-write allowlist**; **operator** routes (`/api/mesh/peer-capture/*`, session-only) relay to the chosen unit and, for a peer, **stream the `.pcap` back over the tailnet** (WireGuard) straight to the browser. Trust boundary is the mesh tag, same as control/scans. A `capture` block was added to the mesh `features` payload so the node page shows interfaces + recent captures per unit
- Docs: [mesh.md](mesh.md) *Live packet capture (PCAP)* section + security-model allowlist; README mesh line
- Verified: `pcap_capture.selftest()` 10/10; live loopback capture (20-packet cap → valid pcap read back by tcpdump); capture card rendered against the real pruned Tailwind at desktop and phone (400px) widths (controls/rows wrap, no overflow)

### 2026-10-04

#### feat(mesh): node filters + actions (trace the jumps) on both the Ragnar fleet and Meshtastic node lists
*branch `feature/mesh-node-filters-actions` · PR pending*

**Ragnar Mesh (Tailscale fleet) — Mesh Nodes card:**
- **Filter/sort toolbar** above the list (appears once there is more than one peer): search by name / unit number (`3`, `03`, `unit 03`) / site label / hostname / tailnet IP; filter by status (*All / Online / Needs attention / Unreachable / Not polled*); sort by name, unit number, worst **severity**, open **alerts**, or **CPU**. A *Showing X of Y* counter plus **Reset**. All client-side over the already-polled roster — **no round-trip**, instant even on a Pi Zero; your own unit is never filtered out
- **"Needs attention"** reuses the exact Mesh Health test (unreachable, offline, node-key warning/expiry, undervoltage, or a high/critical finding), so the filter and the summary agree
- **Node-page Actions bar** — probes a peer *from the unit you are looking at*: a **Tailnet path** line (direct WireGuard vs. relayed via DERP + region, from already-polled data, no probe), **Trace route** (`traceroute` drawn as a hop list — "the jumps" — with a hop-count badge), **Ping** (loss + min/avg/max RTT), plus the existing **Diagnose** and a **Copy IP**. An unreachable node gets Trace + Ping next to **Diagnose** on its banner, to show where the path dies
- New `POST /api/mesh/probe` (`{ip, kind: "trace"|"ping"}`), session-gated like `/api/mesh/diagnose` and **not** peer-callable. The target is pinned server-side to the known mesh roster (self or a tagged peer), so the route is a fleet tool, not an arbitrary-target traceroute box

**Meshtastic — Mesh Nodes page (`/mesh-nodes`):**
- **Filter/sort toolbar** over the node table: search (name / id / hardware / role), a role picker built from the roles present, an activity/attribute filter (Active &lt;15m, Heard &lt;2h, Has GPS, Direct 0-hop, Multi-hop), and sort by heard / name / SNR / hops / battery. Self first; *Showing X of Y* in the caption
- **Per-node actions** (click a row): **Trace route**, **Message** (prefills the send box with the node id), **Focus on map**, **Copy ID**
- **Trace route (see the jumps)** — Meshtastic's own traceroute: draws the LoRa path `you → relay (SNR) → … → target (SNR)` with per-link SNR and a hop count. The library call blocks, so it runs on a background thread and the reply is captured off the receive bus; needs a connected USB node (MQTT can't trace) and can take 10–40 s (airtime + firmware rate-limit). New `POST /api/net/mesh/traceroute` + `GET /api/net/mesh/traceroute/result?id=`

- Docs: [mesh.md](mesh.md) (fleet filters + path/trace/ping) and [sdr-subghz.md](sdr-subghz.md) (Meshtastic filters + traceroute, API rows); README mesh lines
- Verified: `traceroute`/`ping` parsers against live loopback output; Meshtastic traceroute-reply parser via `meshtastic_node.selftest()` (32/32, incl. hop-chain order, /4 SNR scaling, name resolution); filter/sort/search + all renderers against mock payloads; offline chromium render of both cards at desktop and phone (400px) widths

#### docs: wardrive firmware comparison on the ESP32-C5
*branch `docs/wardrive-comparison` · PR pending*

- New [wardrivecomparison.md](wardrivecomparison.md): Huginn vs Piglet measured on the same Seeed XIAO ESP32-C5 (Huginn → Piglet → Huginn, 10 min each, Pi 5 `wlan0` as drift tracker). Huginn sweeps in ~5.3 s vs 9.7 s (1.8× more detections/min, plus BLE); Piglet hears slightly more per sweep; Huginn's scan-timing calibration; open issue with one channel-5 AP after `show_hidden`
- Linked from the [docs index](README.md)

#### fix(rf-waterfall): keep the scroll flowing on a slow sweep instead of freezing
*branch `fix/rf-waterfall-smooth-scroll` · PR pending*

- **Symptom:** the RF Waterfall froze for ~1 s every couple of seconds, then jumped to catch up, instead of scrolling as a smooth constant flow
- **Root cause:** live rows are genlocked to their producer timestamp behind a ~0.6 s buffer. The real-time IQ engine feeds 16 rows/s so the buffer stays full and the scroll is smooth — but wide sub-GHz bands fall back to the `rtl_power` sweep, which emits only ~1 row per completed sweep (`-i 1`). That gap is longer than the 0.6 s buffer, so the playhead starves between sweeps: freeze, then a jump when the next frame lands (same for any wide/slow producer, e.g. a wide HackRF span)
- **Fix:** when the queue drains between frames, hold the last line and scroll it at the chosen **Scroll rate** (Slow/Normal/Fast = 5/12/24 rows/s) until real data resumes — the way SDR++/gqrx scroll on a slow sweep. New spectrum still arrives at the engine's true rate and **Rows/s** still reports it; the hold only keeps the picture moving
- Held rows are recorded in history with their own wall-clock time, so the time grid, repaint, scroll-back and CSV export stay 1:1 with the pixels on screen; measurement, detection and the noise-print recorder see only real rows. A fast engine never starves, so the hold never engages there (IQ path unchanged); a genuine multi-second stall stops the hold and lets the panel raise its waiting veil
- Verified by pacing simulation: `rtl_power` ~1/s now scrolls at a constant 12/s with ≤67 ms hitches (was ~1 s freezes); IQ 16/s is unchanged (zero hold rows). Not yet confirmed on live hardware (the DVB-T driver was holding the dongle on the dev box)
- Also changed the **default colour window** to a fixed **Ref level −50 dB, Range 15** (top −50, bottom −65) instead of auto-range; a per-browser setting saved in Settings → Display range still wins
- **Docs:** [rf-waterfall.md](rf-waterfall.md) "Sub-GHz engine" — rewrote the steady-flow note, added "No freeze on a slow sweep"

#### [#911](https://github.com/PierreGode/Ragnar/pull/911) — feat(net): Liebert Guard v2 — bounded reassembly
*branch `feature/liebert-guard-v2`*

- Vendored **liebert_guard v2**: reassembly is now incremental with a per-flow work budget (`MAX_WORK` 200,000 steps, `MAX_CANDS` 16), so a stream of tiny TCP segments can no longer make one frame expensive — on the Pi 5, 1,524 one-byte segments went from **12.35 s to 0.08 s**
- Same codes (LG-001/002/003/101), CVEs and output; new limit: a head or request line split into more than ~630 in-order one-byte segments is not judged
- Conformance tier updated (493 → 501). All author tiers pass on the Pi 5 (ARM64): module 198 incl. live loopback, conformance 501, scapy 554, perf 29, unit verifier 74; Detector Self-Test 206/206, all 47 suites green from the web path
- **Docs:** [nettools.md](nettools.md) "Liebert Guard"

#### [#910](https://github.com/PierreGode/Ragnar/pull/910) — fix(gc9a01): stop the round TFT showing only static
*branch `fix/gc9a01-spi-speed`*

- **Root cause:** the GC9A01 1.28" round display driver hardcoded SPI at the panel's 40 MHz maximum. Over Dupont/jumper wiring that clock corrupts the init-sequence command bytes, so the controller is never configured and the panel shows only its power-on noise ("snow"/static)
- Default SPI clock lowered to a safe **20 MHz**, matching the conservative approach of the ILI9486 driver
- Added environment overrides mirroring the 3.5" TFT driver: `RAGNAR_GC9A01_SPI_HZ`, `RAGNAR_GC9A01_MADCTL`, `RAGNAR_GC9A01_INVERT`, and `RAGNAR_GC9A01_RST_PIN` / `_DC_PIN` / `_BL_PIN` (`-1` disables backlight control). Users can drop the clock further (`10000000`) if still noisy
- Display inversion (`INVON`) and MADCTL are now env-tunable instead of hardcoded; backlight pin respects `-1`
- New "1.28" GC9A01 round TFT" section in [Display Controls](DISPLAY_CONTROLS.md) with wiring and a static/snow troubleshooting table

#### feat(mesh): pick the Meshtastic MQTT region
*branch `feature/meshtastic-mqtt-region` · PR pending*

- **Region picker** next to the MQTT Topic box on Mesh Nodes and Mesh Map: All regions (`msh/+/2/#`), or one region root (`msh/EU_868/#`, `msh/US/#`, ANZ, CN, JP, …) including country and city sub-topics; *Custom topic* for a hand-typed filter. Choice is remembered per browser
- Changing the topic while MQTT is on reconnects at once, and the backend drops the old region's nodes/messages (`MeshMqtt.connect`)
- Region list served by `detect()` (`mqtt_defaults.regions`); `mqtt_region_topic()` + 4 self-tests (26/26)
- **Region badge on every MQTT message** (e.g. `EU_868/SE`, `US`, `ANZ`), read off the topic by `mqtt_topic_region()`; hover shows the full topic; map popups show **Region** for MQTT stations. +2 self-tests (28/28)
- **Docs:** [sdr-subghz.md](sdr-subghz.md) "Choosing a region" / "Where a message came from"

### 2026-10-03

#### fix(wardriving): Piglet sync — newest drive first, give up on stuck files, sync on plug-in
*branch `feature/piglet-sync-newest-plugin` · PR pending*

- **Newest first:** with Piglet v2.61 `LIST` carries each file's last-write time; Ragnar fetches the newest drive first (unknown times next, previously failed files last). On a full card the first field sync imported months-old drives before the new ones
- **Stuck files:** SD read errors (`@PG ERR read-error`, v2.61) stop that file at once; 2 no-progress resumes abandon it; a failed file waits 6 h before a retry and is skipped after 3 failed syncs (`unreadable`); a vanished port stops the sync instead of failing every remaining file
- **Sync on plug-in:** new `PlugWatcher` syncs a Piglet when it's plugged in even with wardriving stopped (Espressif native-USB devices only, once per plug-in, respects serial claims; defers to the wardriving listener while it runs). Button and watcher share one guarded `_piglet_sync_on_port()`
- **Docs:** [wardriving.md](wardriving.md) "USB sync of solo drives"

#### [#907](https://github.com/PierreGode/Ragnar/pull/907) — feat(net): Liebert Guard + updated visibility matrix
*branch `feature/liebert-guard`*

- **Liebert Guard**, the companion to APC Guard for Vertiv / Liebert power cards: vendored stdlib-only `python/liebert_guard.py` replayed in-app from a bounded `tcpdump` capture of the card's HTTP port. **LG-001** RomPager banner below 4.34 (**Misfortune Cookie**, CVE-2014-9222 — Liebert MPH / RPC-1000), **LG-002/003** unparseable / patched banner, **LG-101** HTTP method over 64 bytes (CVE-2025-41426 — Liebert RDU101 / IS-UNITY overflow)
- Card in **Diagnostics → L7** right after APC Guard (port picker); `GET /api/net/liebert-guard`, CLI `liebert-guard` / `liebert-guard-selftest`; Detector Self-Test row **206/206** (module tier in its own interpreter, incl. live loopback capture)
- Opt-in hardened `scripts/liebert_guard@.service` → `/var/log/ragnar/liebertguard.jsonl`, tested on the Pi 5; runs as `ragnar` (a dynamic user would move `/var/log/ragnar`)
- Watchtower: Liebert sources, `note` as headline, attempt source = client / banner source = card
- New **module visibility matrix** (52 detectors) in the docs and the web UI reference cards; CVE index 268 named / 227 detected
- **Docs:** [nettools.md](nettools.md) "Liebert Guard", [watchtower.md](watchtower.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md), [README (root)](../README.md)

#### [#906](https://github.com/PierreGode/Ragnar/pull/906) — feat(wardriving): import Piglet solo drives over USB
*branch `feature/piglet-serial-sync`*

- A drive done with Piglet on its own only lived on its SD card. Piglet firmware **v2.60** (SerialSync) answers `@PIGLET HELLO/LIST/GET` on its USB port, and new [`piglet_sync.py`](../piglet_sync.py) pulls every finished CSV and imports each one as its own session (`session_<first seen>_piglet`)
- Runs automatically when a Piglet connects while wardriving (`wardriving_piglet_sync`, default on) and on demand via **Import from Piglet (USB)** on the Import card (`POST/GET /api/wardriving/piglet/sync`). With wardriving stopped it opens the free ESP32 port itself under a `piglet-sync` serial claim
- Per-chunk CRC32 + resume-at-offset (up to 8 resumes per file); Piglet mutes IDF logging while serving so Wi-Fi log lines can't corrupt data lines. About 140 KiB/s on an ESP32-C5
- Skips the file Piglet is writing (the live stream covers it) and files with no GPS positions; remembers imports per Piglet MAC + file name (`data/wardriving/piglet_imports.json`), so a file Piglet later moves to `/uploaded` is not imported twice
- **CSV import now keeps real times:** rows use their `FirstSeen` instead of the import time, a GPS track is rebuilt from positioned rows, `0,0` is stored as "no position", pre-clock `1970` rows take the file's nearest valid time; also fixes a `TypeError` on cell rows (`upsert_cell_tower` missing args). Applies to the manual **Import CSV** too
- **Docs:** [wardriving.md](wardriving.md) "USB sync of solo drives", [README.md](../README.md)

### 2026-10-02

#### [#905](https://github.com/PierreGode/Ragnar/pull/905) — feat(ducky): drive the Rubber Ducky HID across the mesh
*branch `feat/ducky-mesh` · 6 file(s)*

- A Ragnar plugged into a host PC via USB-OTG can't use wired Ethernet at the same time, so it rides Wi-Fi — and now a **second Ragnar on the mesh can run Ducky payloads on its HID**, the same way the Device Console is driven across the mesh
- **Run on** picker added to the Rubber Ducky card (this unit + mesh peers, each showing HID/allowed state); selecting a peer tags every script/device/preview/execute/install call with `X-Ragnar-Target` so this unit's secret-gated gateway relays it (`duckyState` + `rdFetch` in ragnar_modern.js)
- **Allow mesh units to run payloads on this unit** checkbox (off by default), persisted in `data/rubber_ducky.json` (`mesh_allowed()` / `set_mesh_allowed()` in `python/rubber_ducky.py`). `_ducky_mesh_write_guard()` refuses a *relayed* execute / gadget enable-disable / save / install unless the target unit ticked it — so the two gates are independent: the **mesh secret** authorises transport, the **checkbox** is the target's per-unit opt-in
- New endpoints: `GET /api/rubber-ducky/units`, `GET/POST /api/rubber-ducky/mesh-allow`, and the peer-discovery `GET /api/mesh/rubber-ducky/status`
- **Docs:** [rubber-ducky.md](rubber-ducky.md) "Driving another unit over the mesh"

#### [#904](https://github.com/PierreGode/Ragnar/pull/904) — feat(scripts): install ducky + console scripts from the external RagnarScripts library
*branch `feat/ragnarscripts-install-library` · 12 file(s)*

- Ragnar now reads a second, **user-cloned** script source — [RagnarScripts](https://github.com/PierreGode/RagnarScripts) — alongside the built-in demos, which stay exactly where they are. Discovery order: `$RAGNAR_SCRIPTS_DIR` → a `RagnarScripts/` folder beside the repo → `~/RagnarScripts` → `/home/pi` or `/home/ragnar`
- **Auto-sync** (`ragnar_scripts.py`): best-effort `git clone` (when missing) / `git pull` (when present) on web-server start and when the **Dashboard**/**Pentest** tabs open, so pushed scripts appear without a manual pull. Anonymous HTTPS (public repo, no creds), throttled ~30 s, backgrounded, `safe.directory=*` for cross-user checkouts, never fatal. New endpoint `POST /api/ragnar-scripts/sync`; the two `_ragnar_scripts_repo()` helpers now delegate to this module
- **Rubber Ducky card:** RagnarScripts `.ducky`/`.txt` payloads (repo's `rubber-ducky/` folder) are folded directly into the existing **Payload Library** list, mixed with the bundled `resources/ducky_payloads/` payloads and tagged **RagnarScripts** vs **bundled**, with per-row Install/Reinstall (`list_ragnar_scripts()` / `install_ragnar_script()` in `python/rubber_ducky.py`)
- **Device Console card:** new expandable **Install console scripts** section lists `.json` sequences from the repo's `console-scripts/` folder (name/vendor/command-count), installs into this unit's `data/console_scripts/` and refreshes the Run-script picker (`list_library()` / `install_library_script()` in `serial_console.py`)
- APIs: `GET/POST /api/rubber-ducky/ragnar-scripts[/install]`, `GET/POST /api/serial-console/library[/install]`. Installs are name/id-validated (traversal rejected) and JSON-validated for console scripts
- The **local folders stay fully editable** — Upload here / Files-tab / inline editor all still work; installing never deletes a user's own scripts (same-name install overwrites, shown as *Reinstall*)
- Bumped the `ragnar_modern.js` cache-bust (`?v=20261002-ragnarscripts`)
- **RagnarScripts repo** seeded with the folder structure and a few harmless test scripts (3 ducky payloads, 3 console scripts) + READMEs
- **Docs:** new [ragnarscripts.md](ragnarscripts.md); updated [rubber-ducky.md](rubber-ducky.md), [serial-console.md](serial-console.md), [README.md](../README.md), [docs index](README.md)

#### [#903](https://github.com/PierreGode/Ragnar/pull/903) — fix(files): upload scripts into console_scripts & rubber-ducky + console-card Upload button
*branch `fix/files-upload-console-ducky` · 7 file(s)*

- **Bug:** the Files tab only showed the **⬆ Upload here** toolbar inside `/uploads` and `/backups`, so there was no way to add a script from the **console_scripts** or **rubber-ducky** folders — the upload always fell back to `/uploads`. The backend also rejected `/console_scripts` as an upload target
- Added an `isUploadablePath()` superset (writable trees **plus** the two script libraries) so the folder toolbar's **Upload here** button now appears in `console_scripts` and `rubber-ducky`, and `uploadFile()` targets the folder actually being browsed. The general-purpose **+ New folder** button stays limited to Uploads/Backups (the libraries are flat)
- Backend: `_resolve_upload_target()` now accepts `/console_scripts` (mapped to `data/console_scripts/`); `/rubber-ducky` was already allowed. Uploaded `.json` scripts are picked up by `serial_console.list_scripts()` immediately
- **Feature:** added an **Upload** button next to the **Run Script** picker on the Dashboard **Device Console** card (mirrors the Rubber Ducky card) — pick a `.json` console script, it's added to the local unit's library and auto-selected (`scUploadScript()`)
- Bumped the `ragnar_modern.js` cache-bust (`?v=20261002-folder-upload`)
- **Docs:** [serial-console.md](serial-console.md), [rubber-ducky.md](rubber-ducky.md), [README.md](../README.md), [releases.md](releases.md)

#### [#900](https://github.com/PierreGode/Ragnar/pull/900) — docs(pentest): Rubber Ducky card shows supported boards + GPIO-powering note
*branch `fix/ducky-board-power-info` · 2 file(s)*

- Added a collapsible **Supported boards & powering** panel to the Rubber Ducky Script Executor card: a board-compatibility table (Zero 2 W ✅ / 3A+ ✅ / Pi 4 ✅ / Pi 5 ⚠️ / 3B ❌) and the key caveat that on **Pi 4 / Pi 5** the single USB-C port is both power and the OTG/data port
- Documents the fix: **power the Pi from the 5V GPIO pins** (pin 2/4 + pin 6 GND) and keep USB-C plugged into the target, so the data link doesn't have to also power the Pi ("steal" the port) — the Pi-4-style workaround; includes the unfused-rail safety caveat
- Mirrored the same guidance into [rubber-ducky.md](rubber-ducky.md) (board table + new "Powering via the GPIO pins" section)
- **Docs:** [rubber-ducky.md](rubber-ducky.md), [releases.md](releases.md)

#### [#899](https://github.com/PierreGode/Ragnar/pull/899) — fix(ui): clipboard "Copy" buttons work over plain HTTP
*branch `fix/revshell-copy-http` · 3 file(s)*

- **Root cause:** `navigator.clipboard` is exposed by browsers only in a secure context (HTTPS/localhost). On a plain-HTTP LAN/Tailscale Ragnar (`http://192.168.x`/`100.x`) it is `undefined`, so copy handlers calling it directly either threw a synchronous `TypeError` (uncaught by their `.catch()`) or silently no-op'd
- Hardened the shared `copyToClipboard()` helper: non-flashing `execCommand('copy')` fallback, returns a success boolean, honest "Copy failed" toast, and an optional `{ silent }` mode for callers that render their own feedback
- Routed **four** copy buttons through it:
  - Pentest → **Reverse Shell** one-liners (`revshellCopy`)
  - Scan → captured-credential **password** copy (`copyCredToClipboard`)
  - Account → **2FA recovery codes** copy (`copyRecoveryCodes`) — previously a lock-out risk when set up over HTTP
  - WiFi map → **BSSID** copy (`wifiFsCopy`)
- Bumped the `ragnar_modern.js` cache-bust (`?v=20261002-clipboard-http`) so returning browsers load the fix
- **Docs:** [releases.md](releases.md)

### 2026-10-01

#### [#895](https://github.com/PierreGode/Ragnar/pull/895) — feat(pentest): Rubber Ducky script executor (USB HID keystroke injection)
*branch `work/2026-10-01` · 13 file(s)*

- New Pentest-tab card: pick a script, pick the `/dev/hidg0` keyboard-gadget target, preview the actions, and run — gated by Pentest Mode only (no dependency on the global `enable_attacks` flag, matching the other manual tools)
- `python/rubber_ducky.py`: parses official `.ducky` syntax and plain-text scripts, Shift-aware typing, streams HID reports to the gadget node (opens once; handles `GUI r`-style modifier combos)
- **Opt-in** HID gadget setup in installer/updater (`RAGNAR_HID_GADGET=1` + `/etc/ragnar/hid_gadget.enabled` marker): adds the `dwc2,dr_mode=peripheral` overlay, drops the conflicting legacy `g_ether`, and adds `hid.usb0` — default off so the Cardputer/plain-ECM boxes are untouched; also fixes the non-idempotent `cmdline.txt` edit
- On-demand **Enable/Disable** gadget control in the card (`scripts/hid_gadget.sh` + `/api/rubber-ducky/gadget/*`): brings `/dev/hidg0` up/down live, preserving `usb0` networking
- `files/rubber-ducky/` surfaced as its own folder in the Files tab for uploads, with a bundled safe demo (`demo_hello.ducky`) for end-to-end validation; `.ducky` files are editable text in the Files tab
- Ducky card gains a **Refresh/Upload** for scripts, a **payload library** (`resources/ducky_payloads/`: Win/Linux/macOS recon, Wi-Fi-profile dump, reverse-shell template) with one-click Install, and an **inline editor**; `.ducky` parser now handles multi-modifier combos (`CTRL ALT t`)
- New **Reverse Shell** card: generates connect-back one-liners (Bash/nc/Python/PowerShell/Perl/PHP) + a built-in catch listener (`python/revshell.py`)
- **Docs:** [rubber-ducky.md](rubber-ducky.md), [reverse-shell.md](reverse-shell.md), [scanning-and-attacks.md](scanning-and-attacks.md), [docs index](README.md), [releases.md](releases.md)

#### [#879](https://github.com/PierreGode/Ragnar/pull/879) — fix(display): don't error when an interface (e.g. usb0) is absent
*Merged 2026-10-01 · branch `fix/usb0-missing-interface` · 2 file(s), +15 / −12*

- `is_interface_connected()` returns `False` quietly when `/sys/class/net/<iface>` is missing; stops the per-poll `Cannot find device "usb0"` error on non-USB-gadget boxes (Wi-Fi / HAT / dongle, Pi Zero 2 W, VMs)
- `is_usb_connected()` now reuses it (one code path); unchanged behaviour when `usb0` exists
- **Docs:** [releases.md](releases.md)

#### [#893](https://github.com/PierreGode/Ragnar/pull/893) — docs: per-PR release log (docs/releases.md)
*Merged 2026-10-01 · branch `docs/releases-log` · 3 file(s)*

- New `docs/releases.md`: one entry per PR merged to `main`, newest on top, with summary and doc links
- Backfilled the last 600 merged PRs (#209–#892) from the merge history
- Linked from the root README and the docs index
- **Docs:** [releases.md](releases.md), [README (root)](../README.md), [docs index](README.md)

### 2026-09-30

#### [#892](https://github.com/PierreGode/Ragnar/pull/892) — fix(apc-guard): run the module self-test tier in its own interpreter
*Merged 2026-09-30 · branch `fix/apc-selftest-thread` · 1 file(s), +10 / −11*

#### [#891](https://github.com/PierreGode/Ragnar/pull/891) — fix(ui): move APC Guard card to the Diagnostics sub-tab
*Merged 2026-09-30 · branch `fix/apc-guard-diagnostics` · 18 file(s), +1350 / −1141*

- feat(ui): sort Network > Diagnostics by OSI layer
- feat(ui): visibility matrix as a reference guide in Diagnostics
- **Docs:** [README (root)](../README.md), [docs index](README.md), [certwatch.md](certwatch.md), [nettools.md](nettools.md)

#### [#890](https://github.com/PierreGode/Ragnar/pull/890) — feat(net): APC Guard — passive APC/Schneider NMC Ripple20 guard
*Merged 2026-09-30 · branch `feature/apc-guard` · 17 file(s), +3773 / −43*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#889](https://github.com/PierreGode/Ragnar/pull/889) — feat(gps): set the clock from GPS offline and repair sessions on clock steps
*Merged 2026-09-30 · branch `feature/gps-clock-set` · 9 file(s), +304 / −6*

- **Docs:** [wardriving.md](wardriving.md)

#### [#888](https://github.com/PierreGode/Ragnar/pull/888) — fix(wardriving): stop reopening a session from overwriting its start time
*Merged 2026-09-30 · branch `fix/wardriving-session-start-time` · 2 file(s), +78 / −3*

### 2026-09-29

#### [#887](https://github.com/PierreGode/Ragnar/pull/887) — docs(cellular): heartbeat states, test procedure, IFACE order and push details
*Merged 2026-09-29 · branch `feature/cellular-heartbeat-failover` · 9 file(s), +125 / −35*

- docs(device-console): complete the guide; fix script id handling
- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [docs index](README.md), [cellular-uplink.md](cellular-uplink.md), [nettools.md](nettools.md), [push-notifications.md](push-notifications.md), [serial-console.md](serial-console.md)

#### [#886](https://github.com/PierreGode/Ragnar/pull/886) — feat(network): heartbeat failover + failback hysteresis for cellular uplink
*Merged 2026-09-29 · branch `feature/cellular-heartbeat-failover` · 8 file(s), +505 / −35*

- **Docs:** [README (root)](../README.md), [docs index](README.md), [cellular-uplink.md](cellular-uplink.md)

#### [#885](https://github.com/PierreGode/Ragnar/pull/885) — feat(gps): inject saved almanac/ephemeris on offline boots too
*Merged 2026-09-29 · branch `fix/gps-assist-offline-orbits` · 3 file(s), +58 / −27*

- **Docs:** [wardriving.md](wardriving.md)

#### [#884](https://github.com/PierreGode/Ragnar/pull/884) — fix(gps): orbit-data saves run from first fix and merge per satellite
*Merged 2026-09-29 · branch `fix/gps-aid-save-schedule-merge` · 4 file(s), +103 / −52*

- **Docs:** [wardriving.md](wardriving.md)

#### [#883](https://github.com/PierreGode/Ragnar/pull/883) — fix(wifi): reconnect key falls back to saved NetworkManager profiles
*Merged 2026-09-29 · branch `fix/key2-reconnect-nm-profiles` · 3 file(s), +295 / −10*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#882](https://github.com/PierreGode/Ragnar/pull/882) — fix(gps): save orbit data 15 s after a fix, not 60 s
*Merged 2026-09-29 · branch `fix/gps-assist-early-save` · 3 file(s), +28 / −7*

- fix(gps): save orbit data 5 s after a fix, then at 1 min, then every 5 min
- **Docs:** [wardriving.md](wardriving.md)

#### [#881](https://github.com/PierreGode/Ragnar/pull/881) — feat(gps): assisted start — pre-load position, NTP time and saved orbit data
*Merged 2026-09-29 · branch `feature/gps-assist-preload` · 11 file(s), +733 / −6*

- docs(gps): assist store lives in data/, next to last_gps.json
- **Docs:** [README (root)](../README.md), [wardriving.md](wardriving.md)

### 2026-09-28

#### [#880](https://github.com/PierreGode/Ragnar/pull/880) — feat(ui): group Settings into sub-tabs
*Merged 2026-09-28 · branch `feature/settings-subtabs` · 3 file(s), +69 / −3*

- **Docs:** [spec.md](spec.md)

#### [#878](https://github.com/PierreGode/Ragnar/pull/878) — feat(network): cellular uplink fallback via USB-tethered hotspot
*Merged 2026-09-28 · branch `feature/cellular-uplink-fallback` · 19 file(s), +952 / −15*

- **Docs:** [README (root)](../README.md), [docs index](README.md), [cell.md](cell.md), [cellular-uplink.md](cellular-uplink.md), [nettools.md](nettools.md), [push-notifications.md](push-notifications.md)

#### [#877](https://github.com/PierreGode/Ragnar/pull/877) — feat(system): cooling fan status and control in the System tab
*Merged 2026-09-28 · branch `feature/pi-fan-status` · 9 file(s), +1052 / −4*

- **Docs:** [README (root)](../README.md), [docs index](README.md), [fan.md](fan.md), [power.md](power.md)

#### [#876](https://github.com/PierreGode/Ragnar/pull/876) — fix(wardriving): parse iw's decimal channel frequencies
*Merged 2026-09-28 · branch `fix/iw-decimal-freqs` · 2 file(s), +38 / −2*

#### [#875](https://github.com/PierreGode/Ragnar/pull/875) — Delete .github/codeql/codeql-config.yml
*Merged 2026-09-28 · branch `PierreGode-patch-5` · 1 file(s), +0 / −81*

#### [#874](https://github.com/PierreGode/Ragnar/pull/874) — perf(actions): lazy-import pandas in connectors to cut startup RAM
*Merged 2026-09-28 · branch `perf/lazy-pandas-imports` · 8 file(s), +55 / −74*

#### [#846](https://github.com/PierreGode/Ragnar/pull/846) — fix(system-tab): make the System tab work on phones
*Merged 2026-09-28 · branch `system-tab-mobile` · 2 file(s), +52 / −29*

#### [#873](https://github.com/PierreGode/Ragnar/pull/873) — fix(serial-console): script picker no longer resets on every poll tick
*Merged 2026-09-28 · branch `fix/console-script-select` · 2 file(s), +12 / −3*

#### [#872](https://github.com/PierreGode/Ragnar/pull/872) — fix(files): dark editor textarea (pruned Tailwind has no bg-black/80)
*Merged 2026-09-28 · branch `fix/files-editor-dark` · 2 file(s), +2 / −2*

#### [#871](https://github.com/PierreGode/Ragnar/pull/871) — fix(console-scripts): seed defaults at runtime, never overwrite user edits
*Merged 2026-09-28 · branch `fix/console-scripts-seed` · 7 file(s), +88 / −150*

#### [#870](https://github.com/PierreGode/Ragnar/pull/870) — feat(files): in-browser text file editor with save
*Merged 2026-09-28 · branch `feature/files-editor` · 5 file(s), +134 / −7*

- **Docs:** [README (root)](../README.md), [serial-console.md](serial-console.md)

#### [#869](https://github.com/PierreGode/Ragnar/pull/869) — feat(serial-console): add console scripts — run pre-made command sequences
*Merged 2026-09-28 · branch `feature/console-scripts` · 11 file(s), +388 / −4*

- **Docs:** [README (root)](../README.md), [serial-console.md](serial-console.md)

#### [#868](https://github.com/PierreGode/Ragnar/pull/868) — refactor(serial-console): simplify mesh write — no separate checkbox
*Merged 2026-09-28 · branch `fix/console-mesh-write-simplify` · 5 file(s), +25 / −68*

- **Docs:** [serial-console.md](serial-console.md)

#### [#867](https://github.com/PierreGode/Ragnar/pull/867) — fix(cyd): stop orphaned rtl_sdr subprocess from blocking CYD waterfall
*Merged 2026-09-28 · branch `fix/cyd-display` · 4 file(s), +32 / −11*

- **Docs:** [cyd-firmware.md](cyd-firmware.md), [rf-waterfall.md](rf-waterfall.md)

### 2026-09-27

#### [#865](https://github.com/PierreGode/Ragnar/pull/865) — fix(wardrift): interpolate export times along the GPS track
*Merged 2026-09-27 · branch `fix/wardrift-trail-jumps` · 5 file(s), +60 / −11*

- **Docs:** [wardriving.md](wardriving.md)

#### [#866](https://github.com/PierreGode/Ragnar/pull/866) — Implement gated write functionality in serial_console.py
*Merged 2026-09-27 · branch `Consoleupdate` · 6 file(s), +413 / −97*

- fix(serial-console): wire up write-gate UI, routes and strip broken prose
- fix(serial-console): allow_write state consistent across all endpoints
- feat(serial-console): mesh write — send commands to a remote Ragnar's console
- **Docs:** [README (root)](../README.md), [serial-console.md](serial-console.md)

#### [#864](https://github.com/PierreGode/Ragnar/pull/864) — feat(install): installhead.sh — add/switch a screen on a headless install
*Merged 2026-09-27 · branch `feature/installhead` · 4 file(s), +320 / −1*

- **Docs:** [README (root)](../README.md), [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [INSTALL.md](INSTALL.md)

#### [#863](https://github.com/PierreGode/Ragnar/pull/863) — feat(mikrotik-guard): v2 — MikroTrick SSH exposure (MTK-021)
*Merged 2026-09-27 · branch `feature/mikrotik-guard-v2` · 7 file(s), +197 / −16*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md), [nettools.md](nettools.md)

### 2026-09-26

#### [#862](https://github.com/PierreGode/Ragnar/pull/862) — fix(rf-waterfall): SDR-spike hatch only on the trace, not over the waterfall
*Merged 2026-09-26 · branch `adjust` · 2 file(s), +3 / −4*

- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#861](https://github.com/PierreGode/Ragnar/pull/861) — fix
*Merged 2026-09-26 · branch `adjust` · 11 file(s), +1010 / −92*

- water
- feat(sdr): self-healing RTL-SDR USB recovery
- feat(rf-waterfall): 3D view peaks 30% taller
- Revert "feat(rf-waterfall): 3D view peaks 30% taller"
- feat(rf-waterfall): 3D panel 30% taller on screen
- feat(rf-waterfall): "Hide the SDR centre spike" setting
- …and 1 more commit(s)
- **Docs:** [README (root)](../README.md), [rf-api.md](rf-api.md), [rf-waterfall.md](rf-waterfall.md), [sdr-subghz.md](sdr-subghz.md)

#### [#860](https://github.com/PierreGode/Ragnar/pull/860) — feat(notifications): rename Pushover Notifications to Push Notifications, add Slack
*Merged 2026-09-26 · branch `feature/push-notifications-slack` · 11 file(s), +268 / −38*

- **Docs:** [README (root)](../README.md), [docs index](README.md), [push-notifications.md](push-notifications.md), [rusense.md](rusense.md)

#### [#859](https://github.com/PierreGode/Ragnar/pull/859) — feat(rf-waterfall): Zigbee Suzi (sub-GHz Zigbee 4.0) presets in the Mesh dropdown
*Merged 2026-09-26 · branch `feature/rf-zigbee-suzi-presets` · 5 file(s), +75 / −23*

- **Docs:** [README (root)](../README.md), [rf-waterfall.md](rf-waterfall.md), [sdr-subghz.md](sdr-subghz.md)

#### [#856](https://github.com/PierreGode/Ragnar/pull/856) — fix(analyzer): stop the Signal Analyzer running Ragnar out of memory; explain every control
*Merged 2026-09-26 · branch `fix/rf-analyzer-crashes` · 4 file(s), +369 / −47*

- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#855](https://github.com/PierreGode/Ragnar/pull/855) — feat(serial-console): per-unit 'Share with mesh' view-only console sharing
*Merged 2026-09-26 · branch `feature/serial-console-mesh-share` · 6 file(s), +162 / −23*

- **Docs:** [mesh.md](mesh.md), [serial-console.md](serial-console.md)

#### [#852](https://github.com/PierreGode/Ragnar/pull/852) — feat(rf-waterfall): Wi-Fi HaLow (802.11ah) presets in the Mesh dropdown
*Merged 2026-09-26 · branch `feature/rf-halow-presets` · 5 file(s), +142 / −13*

- **Docs:** [README (root)](../README.md), [rf-waterfall.md](rf-waterfall.md), [sdr-subghz.md](sdr-subghz.md)

#### [#851](https://github.com/PierreGode/Ragnar/pull/851) — feat(wardriving): pause orchestrator active scans while driving
*Merged 2026-09-26 · branch `wardrive-pause-scans` · 6 file(s), +193 / −8*

- feat(wardriving): also pause the nmap scanner when triggered manually
- **Docs:** [wardriving.md](wardriving.md)

#### [#850](https://github.com/PierreGode/Ragnar/pull/850) — feat(serial-console): read-only device console on the dashboard, mesh-wide
*Merged 2026-09-26 · branch `feature/serial-console` · 11 file(s), +1208 / −6*

- fix(cyd): identify-before-write on auto-detected ports; console coexistence
- **Docs:** [README (root)](../README.md), [mesh.md](mesh.md), [serial-console.md](serial-console.md)

#### [#847](https://github.com/PierreGode/Ragnar/pull/847) — feat(rpc-watch): v3 — IRemoteWinSpool relay level + PetitPotam attribution
*Merged 2026-09-26 · branch `feature/rpc-watch-v3` · 25 file(s), +208 / −20*

- chore: commit the exec bit on 16 top-level modules + the TFT kiosk script
- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md), [nettools.md](nettools.md)

#### [#849](https://github.com/PierreGode/Ragnar/pull/849) — Update nettools.md
*Merged 2026-09-26 · branch `PierreGode-patch-4` · 1 file(s), +1 / −8*

- **Docs:** [nettools.md](nettools.md)

#### [#848](https://github.com/PierreGode/Ragnar/pull/848) — feat(telnet-watch): v5 — r-services, CVE-2011-4862, CVE-2022-39028
*Merged 2026-09-26 · branch `feature/telnet-watch-v5` · 11 file(s), +2509 / −144*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

### 2026-09-25

#### [#845](https://github.com/PierreGode/Ragnar/pull/845) — feat(power-test): watch a USB GPS through the power test
*Merged 2026-09-25 · branch `power-test-gps` · 6 file(s), +235 / −26*

- **Docs:** [power.md](power.md)

#### [#844](https://github.com/PierreGode/Ragnar/pull/844) — feat(power): Pi 5 USB current limit fix, power test and cleaner System tab
*Merged 2026-09-25 · branch `pi5-usb-power` · 11 file(s), +1231 / −445*

- **Docs:** [README (root)](../README.md), [docs index](README.md), [power.md](power.md)

#### [#843](https://github.com/PierreGode/Ragnar/pull/843) — Update nettools.md
*Merged 2026-09-25 · branch `PierreGode-patch-3` · 1 file(s), +1 / −3*

- **Docs:** [nettools.md](nettools.md)

### 2026-09-24

#### [#842](https://github.com/PierreGode/Ragnar/pull/842) — feat(smtp-watch): add CVE-2019-16928 overlong EHLO detection
*Merged 2026-09-24 · branch `feature/smtp-watch-update` · 8 file(s), +87 / −15*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#841](https://github.com/PierreGode/Ragnar/pull/841) — feat(smtp-watch): passive Exim CVE detector on the SMTP conversation
*Merged 2026-09-24 · branch `feature/smtp-watch` · 12 file(s), +1346 / −15*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#840](https://github.com/PierreGode/Ragnar/pull/840) — feat(ftp-watch): passive ProFTPD CVE detector on the FTP control channel
*Merged 2026-09-24 · branch `feature/ftp-watch` · 12 file(s), +1700 / −14*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#839](https://github.com/PierreGode/Ragnar/pull/839) — feat(wardriving): Pushover summary after each auto-uploaded drive
*Merged 2026-09-24 · branch `feature/wardrive-upload-pushover` · 6 file(s), +182 / −11*

- **Docs:** [wardriving.md](wardriving.md)

#### [#838](https://github.com/PierreGode/Ragnar/pull/838) — feat(wardriving): upload sessions to Wardrift
*Merged 2026-09-24 · branch `feature/wardrift-upload` · 16 file(s), +2533 / −231*

- fix(cyd): stop the CYD serial bridge from claiming the USB GPS
- feat(wardriving): Wardrift logo on the upload card
- feat(wardrift): report a Meshtastic node to Wardrift (USB or WiFi)
- fix(wardrift): explain and stop retrying rejected mesh reports
- fix(wardrift): reject masked/garbled API keys on save
- wardriving: GPS backfill setting tweaks
- …and 7 more commit(s)
- **Docs:** [README (root)](../README.md), [cyd-hybrid-node.md](cyd-hybrid-node.md), [sdr-subghz.md](sdr-subghz.md), [wardriving.md](wardriving.md)

#### [#837](https://github.com/PierreGode/Ragnar/pull/837) — docs: RTL8812AU monitor-mode driver setup & troubleshooting
*Merged 2026-09-24 · branch `docs/rtl8812au-driver-troubleshooting` · 2 file(s), +149 / −1*

- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md), [wifi-rtl8812au.md](wifi-rtl8812au.md)

### 2026-09-23

#### [#836](https://github.com/PierreGode/Ragnar/pull/836) — feat(rf-waterfall): detectors, front-end overload warning, image verification
*Merged 2026-09-23 · branch `feature/rf-instrument-grade` · 11 file(s), +3288 / −94*

- feat(rf-waterfall): armed trigger with pre-trigger IQ capture
- feat(rf-waterfall): band-power and noise markers, ACPR, spurs, harmonics, reference trace
- feat(analyzer): FM deviation and AM modulation depth
- feat(rf): geotagged captures and field-strength measurements
- feat(rf-waterfall): memory channels, instrument setups, measurement report, API reference
- feat(analyzer): CTCSS and DCS squelch-tag decoding
- …and 11 more commit(s)
- **Docs:** [README (root)](../README.md), [rf-api.md](rf-api.md), [rf-waterfall-guide.md](rf-waterfall-guide.md), [rf-waterfall.md](rf-waterfall.md)

### 2026-09-22

#### [#835](https://github.com/PierreGode/Ragnar/pull/835) — feat(rf-waterfall): display range, row history, settings drawer
*Merged 2026-09-22 · branch `fix/rf-waterfall-retune-storm` · 10 file(s), +3259 / −356*

- feat(rf-waterfall): hover readout, time axis, history scroll-back, colour bar
- feat(rf-waterfall): wheel zoom, drag pan, pinch, precise ruler
- feat(rf-waterfall): markers M1-M4 with delta, peak search, next peak, centre
- feat(sdr): resolution + hardware settings; fix dead columns on narrow zoom; radio SSB/CW/squelch
- feat(rf-waterfall): Resolution + Hardware settings UI, RBW readout
- feat(rf-waterfall): radio USB/LSB/CW, squelch slider, audio recording
- …and 10 more commit(s)
- **Docs:** [README (root)](../README.md), [rf-waterfall-guide.md](rf-waterfall-guide.md), [rf-waterfall.md](rf-waterfall.md), [sdr-subghz.md](sdr-subghz.md)

#### [#834](https://github.com/PierreGode/Ragnar/pull/834) — feat(rf-waterfall): noise print, record the background and subtract it
*Merged 2026-09-22 · branch `feature/rf-waterfall-noise-print` · 2 file(s), +132 / −5*

- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#833](https://github.com/PierreGode/Ragnar/pull/833) — fix(rf-waterfall): steady live scroll, no speed-up/slow-down surges
*Merged 2026-09-22 · branch `fix/rf-waterfall-steady-flow` · 2 file(s), +44 / −18*

- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#832](https://github.com/PierreGode/Ragnar/pull/832) — style(rf-waterfall): double waterfall height on desktop (210 -> 420 px)
*Merged 2026-09-22 · branch `fix/rf-waterfall-desktop-height` · 1 file(s), +2 / −2*

#### [#831](https://github.com/PierreGode/Ragnar/pull/831) — fix(smb-watch): stop mDNS DNS-SD PTRs raising spoof-conflict
*Merged 2026-09-22 · branch `fix/smb-mdns-spoof-conflict-fp` · 3 file(s), +143 / −25*

- fix(smb-watch): close the evasions the DNS-SD fix opened
- **Docs:** [nettools.md](nettools.md)

### 2026-09-21

#### [#830](https://github.com/PierreGode/Ragnar/pull/830) — fixes
*Merged 2026-09-21 · branch `data` · 3 file(s), +164 / −21*

#### [#829](https://github.com/PierreGode/Ragnar/pull/829) — docs: add unified CVE index (docs/CVE.md) + generator
*Merged 2026-09-21 · branch `docs/unified-cve-list` · 4 file(s), +669 / −9*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [CVE.md](CVE.md)

#### [#828](https://github.com/PierreGode/Ragnar/pull/828) — feat(dns-watch): port DNS Poison Checker v5 passive detectors
*Merged 2026-09-21 · branch `feature/dns-poison-v5` · 11 file(s), +847 / −37*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

#### [#827](https://github.com/PierreGode/Ragnar/pull/827) — fix(network): stop dual-homed boxes degrading every host each scan (#818)
*Merged 2026-09-21 · branch `fix/818-dual-homed-degraded-flap` · 6 file(s), +488 / −29*

- fix(wifi): identify the network by SSID, not the NM profile name (#818)
- **Docs:** [asset-inventory.md](asset-inventory.md)

#### [#826](https://github.com/PierreGode/Ragnar/pull/826) — docs(ui): name D(HE)at in the TLS and SSH Watch cards
*Merged 2026-09-21 · branch `feature/tls-ssh-dheat-card-wording` · 1 file(s), +2 / −2*

#### [#825](https://github.com/PierreGode/Ragnar/pull/825) — docs(ui): note OSPFv3-SR in the SR-MPLS Watch card
*Merged 2026-09-21 · branch `feature/srmpls-card-ospfv3sr-wording` · 1 file(s), +3 / −3*

#### [#824](https://github.com/PierreGode/Ragnar/pull/824) — feat(watchers): SR-MPLS Watch v3 (OSPFv3-SR) + OSPF Watch v5 (OSPFv3 instance anomaly)
*Merged 2026-09-21 · branch `feature/srmpls-v3-ospfv3sr` · 4 file(s), +558 / −20*

- Update nettools.md
- **Docs:** [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

### 2026-09-20

#### [#823](https://github.com/PierreGode/Ragnar/pull/823) — Update nettools.md
*Merged 2026-09-20 · branch `PierreGode-patch-2` · 1 file(s), +2 / −1*

- **Docs:** [nettools.md](nettools.md)

#### [#822](https://github.com/PierreGode/Ragnar/pull/822) — fix(config): only restart the service for settings that actually need it
*Merged 2026-09-20 · branch `fix/restart-only-when-needed` · 7 file(s), +277 / −15*

- **Docs:** [ble_provisioning.md](ble_provisioning.md), [spec.md](spec.md)

#### [#821](https://github.com/PierreGode/Ragnar/pull/821) — fix(network): stop every target flapping Offline/Degraded between scans
*Merged 2026-09-20 · branch `fix/host-liveness-flapping` · 5 file(s), +399 / −17*

- **Docs:** [README (root)](../README.md), [asset-inventory.md](asset-inventory.md)

#### [#820](https://github.com/PierreGode/Ragnar/pull/820) — feat(watchers): BGP v4 + OSPF v4 + EIGRP v5 + IS-IS v5 CVE coverage
*Merged 2026-09-20 · branch `feature/bgp4-ospf4-eigrp5-isis5` · 6 file(s), +205 / −36*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

#### [#819](https://github.com/PierreGode/Ragnar/pull/819) — feat(watchers): LACP v2 + LDAP v4 + DHCP Guardian v3 + IPv6 RA Guard v2
*Merged 2026-09-20 · branch `feature/lacp2-dhcp3-raguard2-ldap4` · 6 file(s), +457 / −28*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

#### [#817](https://github.com/PierreGode/Ragnar/pull/817) — feat(watchers): SR-MPLS Watch v2 (SR-TLV overrun) + BFD Watch v3 (auth-bypass / micro-flap)
*Merged 2026-09-20 · branch `feature/srmpls-v2-bfd-v3` · 6 file(s), +643 / −47*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

### 2026-09-19

#### [#816](https://github.com/PierreGode/Ragnar/pull/816) — feat(watchers): ARP v4 frame capture + SMB/Kerberos v3 CVEs + RPC/NetLogon v2
*Merged 2026-09-19 · branch `feature/arp-v4-smb-kerb-v3-rpc-v2` · 8 file(s), +1074 / −45*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

#### [#815](https://github.com/PierreGode/Ragnar/pull/815) — feat(mesh): hub gateway — relay app requests to fleet peers over Tailscale
*Merged 2026-09-19 · branch `feat/mesh-gateway` · 2 file(s), +123 / −1*

- docs(mesh): document the hub gateway (relay app requests to fleet peers)
- fix(mesh): import requests in the gateway (NameError crashed every relay)
- **Docs:** [mesh.md](mesh.md)

#### [#814](https://github.com/PierreGode/Ragnar/pull/814) — fix(ble): private D-Bus bus so provisioning works inside the webapp
*Merged 2026-09-19 · branch `feat/ble-ip-handover` · 3 file(s), +67 / −13*

- feat(ble): expose 'Bluetooth handover' — app finds box + reads LAN IP over BLE
- **Docs:** [bluetooth-pan.md](bluetooth-pan.md)

#### [#813](https://github.com/PierreGode/Ragnar/pull/813) — fix(cyd): stop Watchtower new-AP warnings from the ESP32 CYD sensor
*Merged 2026-09-19 · branch `vik` · 1 file(s), +3 / −1*

#### [#812](https://github.com/PierreGode/Ragnar/pull/812) — feat(tls-watch): Heartbleed + oversized-DH-prime passive detection (TLS Watch v7)
*Merged 2026-09-19 · branch `feature/tls-v7-ptp-v3` · 5 file(s), +350 / −15*

- feat(ptp-watch): Class V CVE-attributed signatures (PTP Watch v3)
- docs(credits): +6 CVEs (TLS v7 Heartbleed/oversized-DH, PTP v3 Class V) -> ~165
- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

#### [#811](https://github.com/PierreGode/Ragnar/pull/811) — feat(watch): passive SNMP/IGMP/NTP CVE detection (SNMP v4, IGMP v4, NTP v6)
*Merged 2026-09-19 · branch `feature/snmp-igmp-ntp-v4` · 7 file(s), +1016 / −55*

- chore(web): cache-bust ragnar_modern.js for the SNMP 'exploit' verdict style
- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

#### [#810](https://github.com/PierreGode/Ragnar/pull/810) — feat(bt-pan): 'Clear all Bluetooth pairings' button
*Merged 2026-09-19 · branch `feat/bt-pan-client-mode` · 5 file(s), +302 / −4*

- feat(bt-pan): box-as-client mode (connect to phone's BT tethering)
- **Docs:** [bluetooth-pan.md](bluetooth-pan.md)

### 2026-09-18

#### [#809](https://github.com/PierreGode/Ragnar/pull/809) — fix(bt-pan): self-heal discoverability + class on the poll loop
*Merged 2026-09-18 · branch `fix/bt-pan-keepalive-discoverable` · 2 file(s), +19 / −2*

- **Docs:** [bluetooth-pan.md](bluetooth-pan.md)

#### [#808](https://github.com/PierreGode/Ragnar/pull/808) — feat(bt-pan): list + forget paired Bluetooth devices in the Config card
*Merged 2026-09-18 · branch `feat/bt-pan-device-list` · 5 file(s), +141 / −0*

- **Docs:** [bluetooth-pan.md](bluetooth-pan.md)

#### [#807](https://github.com/PierreGode/Ragnar/pull/807) — fix(bt-pan): advertise a network Class-of-Device so phones offer tethering
*Merged 2026-09-18 · branch `fix/bt-pan-network-class` · 2 file(s), +27 / −0*

- **Docs:** [bluetooth-pan.md](bluetooth-pan.md)

### 2026-09-17

#### [#801](https://github.com/PierreGode/Ragnar/pull/801) — fix(advscan): serialize ZAP scans, delete from all network DBs, stop ghost resurrection
*Merged 2026-09-17 · branch `fix/advscan-ghost-scans` · 3 file(s), +274 / −18*

- fix(advscan): serialize ZAP scans, delete scans from all network DBs, stop ghost resurrection

#### [#806](https://github.com/PierreGode/Ragnar/pull/806) — feat(icmp-watch): CVE-2020-16898 "Bad Neighbor" (ICMPv6 RA RDNSS overflow)
*Merged 2026-09-17 · branch `feature/icmp-watch-v4` · 5 file(s), +191 / −6*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md)

#### [#805](https://github.com/PierreGode/Ragnar/pull/805) — feat(dns): DNS Doctor v4 — passive DNS-response watcher + DNSSEC-CVE posture
*Merged 2026-09-17 · branch `feature/dns-doctor-v4` · 16 file(s), +2461 / −9*

- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#804](https://github.com/PierreGode/Ragnar/pull/804) — feat(bt-pan): on-demand dependency install for the Bluetooth access point
*Merged 2026-09-17 · branch `feat/bt-pan-install-deps` · 5 file(s), +325 / −16*

- fix(bt-pan): box now shows up as 'Ragnar' and is actually discoverable
- fix(bt-pan): trust paired devices so the PAN actually connects (Android)
- **Docs:** [bluetooth-pan.md](bluetooth-pan.md)

#### [#803](https://github.com/PierreGode/Ragnar/pull/803) — feat(cyd): Settings toggles for Invert colors + Flip 180 (persisted)
*Merged 2026-09-17 · branch `vik` · 8 file(s), +399 / −66*

- feat(cyd): compact 4x6 font — ~25% smaller UI text everywhere
- revert(cyd): drop compact 4x6 font — restore readable built-in font
- feat(cyd): compact HOME menu — size-1 tile labels + tighter tiles
- fix(cyd): restore HOME tile size + size-2 labels
- feat(cyd): small proportional font for HOME tile labels only
- feat(cyd): action progress — spinner, elapsed clock, countdown + progress bar
- …and 2 more commit(s)
- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#802](https://github.com/PierreGode/Ragnar/pull/802) — feat(bt-pan): Bluetooth PAN (NAP) as a direct link for the mobile app
*Merged 2026-09-17 · branch `feat/bluetooth-pan` · 5 file(s), +505 / −0*

- **Docs:** [bluetooth-pan.md](bluetooth-pan.md)

#### [#800](https://github.com/PierreGode/Ragnar/pull/800) — feat(dheat): D(HE)at (CVE-2002-20001) across TLS + SSH + a new IPsec/IKE watcher
*Merged 2026-09-17 · branch `feature/dheater-cross-protocol` · 16 file(s), +1985 / −20*

- fix(ipsec): wire IPsec Watch into Watchtower + background rotation + docs
- docs(credits): update CVE corpus count for the D(HE)at / IPsec wave
- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

### 2026-09-16

#### [#799](https://github.com/PierreGode/Ragnar/pull/799) — feat(ssh-watch): SWEET32 (CVE-2016-2183) attribution for DES/3DES-CBC
*Merged 2026-09-16 · branch `feature/ssh-watch-v4-sweet32` · 3 file(s), +119 / −10*

- **Docs:** [nettools.md](nettools.md)

#### [#798](https://github.com/PierreGode/Ragnar/pull/798) — test(relay-watch): add IPv6 self-test parity for Relay/Coercion Watch
*Merged 2026-09-16 · branch `feature/relay-watch-ipv6-parity` · 2 file(s), +54 / −4*

- **Docs:** [nettools.md](nettools.md)

#### [#797](https://github.com/PierreGode/Ragnar/pull/797) — Update CREDITS.md
*Merged 2026-09-16 · branch `PierreGode-patch-1` · 0 file(s), +0 / −0*

#### [#796](https://github.com/PierreGode/Ragnar/pull/796) — Update CREDITS.md
*Merged 2026-09-16 · branch `PierreGode-patch-1-1` · 1 file(s), +2 / −4*

- **Docs:** [CREDITS.md](CREDITS.md)

#### [#787](https://github.com/PierreGode/Ragnar/pull/787) — Display fix so that when on pi5's webui, ragnar's display updates correctly
*Merged 2026-09-16 · branch `fix/display-null-epd-guard` · 1 file(s), +28 / −0*

- fix(display): don't crash-loop when an EPD panel's helper is None

#### [#795](https://github.com/PierreGode/Ragnar/pull/795) — docs: add docs/CREDITS.md crediting Solarflere for the CVE research
*Merged 2026-09-16 · branch `docs/consolidate-md-into-docs` · 10 file(s), +65 / −71*

- docs: move remaining loose .md files under docs/
- docs: merge the two Home Assistant docs into one
- **Docs:** [README (root)](../README.md), [CREDITS.md](CREDITS.md), [docs index](README.md), [cyd-firmware.md](cyd-firmware.md), [cyd-hybrid-node.md](cyd-hybrid-node.md), [lab.md](lab.md), [legacywatch.md](legacywatch.md), [wpswatch.md](wpswatch.md)

#### [#794](https://github.com/PierreGode/Ragnar/pull/794) — tune(cyd): raise deauth-flood alert threshold 8 -> 15 frames
*Merged 2026-09-16 · branch `vik` · 2 file(s), +7 / −3*

- feat(cyd): CYD WiFi-Defense button runs a DEEP WIDS scan

### 2026-09-15

#### [#793](https://github.com/PierreGode/Ragnar/pull/793) — fix(cyd): revive 2.4GHz sniff + centred wardrive layout + snappier mesh/wifi streams
*Merged 2026-09-15 · branch `vik` · 6 file(s), +50 / −33*

- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#792](https://github.com/PierreGode/Ragnar/pull/792) — feat(arista-guard): port aristaguard v3 BlastRADIUS engine in-app
*Merged 2026-09-15 · branch `feature/arista-guard-v3-blastradius` · 3 file(s), +264 / −35*

- **Docs:** [nettools.md](nettools.md)

#### [#791](https://github.com/PierreGode/Ragnar/pull/791) — Add files via upload
*Merged 2026-09-15 · branch `vik` · 8 file(s), +51725 / −24001*

- feat(cyd): new full-screen 240x320 boot animation
- feat(cyd): boot animation plays at natural 15s, loops until Ragnar is up
- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#790](https://github.com/PierreGode/Ragnar/pull/790) — fix(cyd): keep the serial link responsive over the GPIO UART
*Merged 2026-09-15 · branch `vik` · 5 file(s), +58 / −12*

#### [#789](https://github.com/PierreGode/Ragnar/pull/789) — feat(cyd): rich live Wardrive page (nets/BLE/cell/zigbee/companions/GPS)
*Merged 2026-09-15 · branch `vik` · 7 file(s), +166 / −36*

- fix(cyd): stop wardriving from grabbing the CYD serial port
- feat(cyd): grey out wardrive Start/Stop while the action is in flight
- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#788](https://github.com/PierreGode/Ragnar/pull/788) — feat(cyd): Wardrive is its own page with live status
*Merged 2026-09-15 · branch `vik` · 5 file(s), +86 / −23*

- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

### 2026-09-14

#### [#786](https://github.com/PierreGode/Ragnar/pull/786) — feat(cyd): action result subpage — no more fire-and-forget taps
*Merged 2026-09-14 · branch `vik` · 6 file(s), +223 / −66*

- fix(cyd): stop the every-cycle reboot — reclaim ~53KB DRAM for WiFi
- fix(cyd): Traffic 'TOTAL PKTS' value green (was gray)
- feat(cyd): waterfall matches web inferno + adds spectrum strip & freq axis
- fix(cyd): brighter waterfall — gamma lift on the quantised row
- fix(cyd): brighter waterfall — raise black level + stronger gamma
- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#785](https://github.com/PierreGode/Ragnar/pull/785) — feat(selftest): surface Dell/MikroTik/Aruba + BFD/PTP/SR-MPLS/LACP/RPC in the Detector Self-Test
*Merged 2026-09-14 · branch `feature/detector-selftest-coverage` · 4 file(s), +64 / −5*

- **Docs:** [nettools.md](nettools.md)

#### [#784](https://github.com/PierreGode/Ragnar/pull/784) — Add files via upload
*Merged 2026-09-14 · branch `vik` · 8 file(s), +24168 / −74*

- feat(cyd): 5s glitch boot animation splash
- fix(cyd): header brand renders 'Ragnar' with a big R
- docs(cyd): refresh for the cabled console — de-emphasise WiFi, drop 'Bjorn'
- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#783](https://github.com/PierreGode/Ragnar/pull/783) — docs(aruba-guard): trim skip prose, drop non-PAPI CVEs, drop InstantOS from titles
*Merged 2026-09-14 · branch `feature/aruba-guard-text-cleanup` · 4 file(s), +12 / −25*

- Update nettools.md
- **Docs:** [nettools.md](nettools.md)

#### [#782](https://github.com/PierreGode/Ragnar/pull/782) — feat(cyd): honest bridge counters + fixed waterfall gain
*Merged 2026-09-14 · branch `feature/cyd-console-menu` · 2 file(s), +18 / −9*

#### [#781](https://github.com/PierreGode/Ragnar/pull/781) — feat(cyd): network actions, alerts view, expanded status fields
*Merged 2026-09-14 · branch `feature/cyd-console-menu` · 10 file(s), +1411 / −185*

- feat(cyd): touch-test / orientation validator screen
- fix(cyd): correct touch Y axis — validated on real hardware
- fix(cyd): bigger, easier back-button target
- fix(cyd): stop the every-2s graphics twitch (redraw only on change)
- feat(cyd): compact NET tile, short unit name, dense network grid
- fix(cyd): waterfall works with RTL-SDR; drop name from Dashboard
- …and 9 more commit(s)
- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#780](https://github.com/PierreGode/Ragnar/pull/780) — feat(cyd): dense data-driven launcher + Network & Settings screens
*Merged 2026-09-14 · branch `feature/cyd-console-menu` · 3 file(s), +149 / −40*

#### [#779](https://github.com/PierreGode/Ragnar/pull/779) — fix(cyd): touch axis orientation (was mirrored vs display)
*Merged 2026-09-14 · branch `fix/cyd-ui-responsive` · 5 file(s), +25 / −3*

- chore(cyd-flasher): drop the boar glyph from the flasher header

#### [#778](https://github.com/PierreGode/Ragnar/pull/778) — feat(aruba-guard): passive HPE Aruba PAPI CVE guard
*Merged 2026-09-14 · branch `feature/aruba-guard` · 5 file(s), +593 / −5*

- **Docs:** [nettools.md](nettools.md)

#### [#777](https://github.com/PierreGode/Ragnar/pull/777) — fix(cyd): responsive console — no twitch, steady LED, live touch
*Merged 2026-09-14 · branch `fix/cyd-ui-responsive` · 4 file(s), +90 / −67*

- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

### 2026-09-13

#### [#776](https://github.com/PierreGode/Ragnar/pull/776) — fix(rf-waterfall): smooth, even fall instead of stepping
*Merged 2026-09-13 · branch `fix/rtl-waterfall-smooth` · 2 file(s), +121 / −43*

#### [#775](https://github.com/PierreGode/Ragnar/pull/775) — feat(cyd): selectable serial port (GPIO/P1 UART, not just USB)
*Merged 2026-09-13 · branch `feature/cyd-hybrid-node` · 12 file(s), +913 / −111*

- feat(cyd): 2.4 GHz WiFi-Defense sensor -> Watchtower
- feat(cyd): app-launcher console + SigInt radar + streamed RF waterfall
- **Docs:** [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#774](https://github.com/PierreGode/Ragnar/pull/774) — feat(cyd): ESP32-2432S028R hybrid companion node (firmware + ingest)
*Merged 2026-09-13 · branch `feature/cyd-hybrid-node` · 19 file(s), +2204 / −14*

- feat(cyd): live action dispatch + operator UI (Mesh → CYD Nodes)
- feat(cyd): status nets_24/nets_5 from cached iw scan dump
- feat(cyd): captive-portal provisioning + browser flasher (bins)
- feat(cyd): USB-serial transport — one cabled unit (no WiFi)
- ci(cyd): publish the CYD flasher on GitHub Pages
- **Docs:** [docs index](README.md), [cyd-hybrid-node.md](cyd-hybrid-node.md)

#### [#773](https://github.com/PierreGode/Ragnar/pull/773) — feat(ui): informational Dell Guard card (standalone daemon, no scan)
*Merged 2026-09-13 · branch `feature/dell-guard-info-card` · 3 file(s), +218 / −1*

- feat(dell-guard): enable/disable switch on the card (drives systemd)
- fix(dell-guard): --no-block systemctl so the switch doesn't time out

#### [#772](https://github.com/PierreGode/Ragnar/pull/772) — feat(mikrotik-guard): passive RouterOS (CCR/CRS) CVE guard
*Merged 2026-09-13 · branch `feature/mikrotik-guard` · 5 file(s), +752 / −5*

- **Docs:** [nettools.md](nettools.md)

#### [#770](https://github.com/PierreGode/Ragnar/pull/770) — Wdgwars Wardrive Upload Feature
*Merged 2026-09-13 · branch `feature/wdgwars-wardrive-upload` · 4 file(s), +409 / −0*

- wardriving: add WiGLE/WDGWars session upload endpoint
- wardriving UI: branded WDGWars/WiGLE upload card + per-session buttons
- wardriving UI: WDGWars card standalone; WiGLE creds move under Import WiGLE CSV
- wardriving: auto-upload finished wardrives (queued, offline-safe)
- wardriving: exclude WDGWars/WiGLE keys from config export
- wardriving: add WDGWars logo asset + render it as a badge

#### [#771](https://github.com/PierreGode/Ragnar/pull/771) — feat(dellguard): vendor Dell SmartFabric OS10 SSRF-egress sensor (CVE-2025-22474)
*Merged 2026-09-13 · branch `feature/dell-guard` · 9 file(s), +3875 / −2*

- **Docs:** [nettools.md](nettools.md)

#### [#767](https://github.com/PierreGode/Ragnar/pull/767) — tft kiosk: debounce mode detection to survive boot-time flapping
*Merged 2026-09-13 · branch `fix/tft35-kiosk-debounce` · 1 file(s), +19 / −7*

#### [#769](https://github.com/PierreGode/Ragnar/pull/769) — feat(tls-watch,ssh-watch): IPv6 extension-header capture (TLS v5 / SSH v3)
*Merged 2026-09-13 · branch `feature/watch-batch-tls-ssl-ntp-juniper` · 4 file(s), +86 / −11*

- **Docs:** [nettools.md](nettools.md)

### 2026-09-12

#### [#768](https://github.com/PierreGode/Ragnar/pull/768) — feat(ntp-watch): crypto-NAK auth-bypass + zero-origin injection (v4)
*Merged 2026-09-12 · branch `feature/ntp-watch-v4` · 4 file(s), +154 / −11*

- **Docs:** [nettools.md](nettools.md)

#### [#766](https://github.com/PierreGode/Ragnar/pull/766) — Make the SPI TFT kiosk mode-aware (Ragnar + Pwnagotchi)
*Merged 2026-09-12 · branch `feature/tft35-mode-aware-kiosk` · 4 file(s), +208 / −21*

- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

#### [#760](https://github.com/PierreGode/Ragnar/pull/760) — feat(rf-analyzer): multi-signal survey — find + track every carrier (Segment 10)
*Merged 2026-09-12 · branch `feature/analyzer-multisignal` · 5 file(s), +224 / −6*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md), [rf-waterfall.md](rf-waterfall.md)

#### [#765](https://github.com/PierreGode/Ragnar/pull/765) — Fix Pwnagotchi mode: make live capture, counting, and wpa-sec upload work
*Merged 2026-09-12 · branch `fix/pwnagotchi-pwn-mode` · 2 file(s), +120 / −0*

#### [#764](https://github.com/PierreGode/Ragnar/pull/764) — feat(tls-watch): RC4 + record-layer CVEs (v4)
*Merged 2026-09-12 · branch `feature/tls-watch-v4` · 3 file(s), +329 / −21*

- **Docs:** [nettools.md](nettools.md)

#### [#763](https://github.com/PierreGode/Ragnar/pull/763) — feat(rf-analyzer): PWM/PPM pulse symbol decoder (Segment 12)
*Merged 2026-09-12 · branch `feature/analyzer-pulse` · 4 file(s), +240 / −10*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#762](https://github.com/PierreGode/Ragnar/pull/762) — feat(rf-analyzer): device fingerprint + bit workbench (Segment 11)
*Merged 2026-09-12 · branch `feature/analyzer-fingerprint` · 4 file(s), +589 / −21*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

### 2026-09-11

#### [#761](https://github.com/PierreGode/Ragnar/pull/761) — feat(ssh-watch): duplicate host key detection (v2, CVE-2025-38741 family)
*Merged 2026-09-11 · branch `feature/ssh-watch-v2` · 3 file(s), +332 / −12*

- **Docs:** [nettools.md](nettools.md)

#### [#759](https://github.com/PierreGode/Ragnar/pull/759) — feat(cisco-guard): CAPWAP malformed-header detection (v5, CVE-2025-20315)
*Merged 2026-09-11 · branch `feature/cisco-guard-v5` · 3 file(s), +97 / −4*

- **Docs:** [nettools.md](nettools.md)

#### [#758](https://github.com/PierreGode/Ragnar/pull/758) — feat(rf-analyzer): upload/import recordings (Flipper .sub, raw IQ, SigMF)
*Merged 2026-09-11 · branch `feature/analyzer-upload` · 5 file(s), +382 / −3*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md), [rf-waterfall.md](rf-waterfall.md)

#### [#757](https://github.com/PierreGode/Ragnar/pull/757) — feat(rf-waterfall): optional 3D terrain waterfall view (2D | 3D toggle)
*Merged 2026-09-11 · branch `feature/waterfall-3d` · 2 file(s), +99 / −6*

- fix(rf-waterfall): smooth the 3D surface (rounded crests, finer, anti-aliased)
- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#756](https://github.com/PierreGode/Ragnar/pull/756) — feat(rf-analyzer): PSK constellation demod (Segment 9)
*Merged 2026-09-11 · branch `feature/analyzer-constellation` · 5 file(s), +267 / −9*

- style(rf-analyzer): lay Cyclostationary + LoRa + Constellation side by side
- style(rf-analyzer): swap the Constellation demod and Filter card slots
- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md), [rf-waterfall.md](rf-waterfall.md)

#### [#755](https://github.com/PierreGode/Ragnar/pull/755) — refactor(signal-intel): tidy the toolbar into two logical rows
*Merged 2026-09-11 · branch `feature/signal-intel-toolbar-tidy` · 3 file(s), +26 / −11*

- fix(signal-intel): analyzer back-link, dead wifi-status id, button spacing
- style(signal-intel): more horizontal spacing between toolbar controls
- fix(signal-intel): use gap classes that exist in the compiled Tailwind
- style(signal-intel): tighten toolbar spacing to gap-4 (24px -> 16px)

#### [#754](https://github.com/PierreGode/Ragnar/pull/754) — feat(rf-analyzer): shareable deep-links + keyboard shortcuts (Segment 8)
*Merged 2026-09-11 · branch `feature/analyzer-ux` · 5 file(s), +106 / −15*

- feat(signal-intel): add a Signal Analyzer button to the SI tool row
- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md), [rf-waterfall.md](rf-waterfall.md)

#### [#753](https://github.com/PierreGode/Ragnar/pull/753) — feat(rf-analyzer): cyclostationary symbol-rate detector (Segment 7)
*Merged 2026-09-11 · branch `feature/analyzer-cyclo` · 4 file(s), +192 / −3*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#752](https://github.com/PierreGode/Ragnar/pull/752) — feat(rf-analyzer): LoRa de-chirp view (Segment 7)
*Merged 2026-09-11 · branch `feature/analyzer-lora` · 4 file(s), +244 / −31*

- feat(rf-analyzer): move Modulation card under Time envelope; upgrade the symbol tool
- fix(rf-analyzer): LoRa de-chirp card — inset the BW/SF controls and plot from the edge
- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#751](https://github.com/PierreGode/Ragnar/pull/751) — feat(rf-analyzer): Segment 7 (start) — band-pass / notch filter with before/after spectrum
*Merged 2026-09-11 · branch `feature/analyzer-dsp` · 4 file(s), +125 / −5*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#750](https://github.com/PierreGode/Ragnar/pull/750) — feat(rf-analyzer): symbol-period cursor on the derived plots (inspectrum parity)
*Merged 2026-09-11 · branch `feature/analyzer-symcursor` · 2 file(s), +82 / −12*

- feat(rf-analyzer): stack the derived plots (inspectrum multi-plot model)
- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#749](https://github.com/PierreGode/Ragnar/pull/749) — feat(rf-analyzer): I/Q sample plot (inspectrum's "Add sample plot")
*Merged 2026-09-11 · branch `feature/analyzer-sampleplot` · 3 file(s), +26 / −5*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#748](https://github.com/PierreGode/Ragnar/pull/748) — feat(rf-analyzer): Segment 6 — SigMF annotations (label signals, round-trip to the file)
*Merged 2026-09-11 · branch `feature/analyzer-annotations` · 4 file(s), +216 / −9*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#747](https://github.com/PierreGode/Ragnar/pull/747) — feat(rf-analyzer): candidate frame lengths + per-candidate CRC scan
*Merged 2026-09-11 · branch `feature/analyzer-frame-candidates` · 4 file(s), +188 / −44*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#746](https://github.com/PierreGode/Ragnar/pull/746) — feat(rf-analyzer): AI assistant can take actions (agentic — drives the analyzer)
*Merged 2026-09-11 · branch `feature/analyzer-ai-actions` · 5 file(s), +190 / −5*

- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#745](https://github.com/PierreGode/Ragnar/pull/745) — feat(rf-analyzer): AI RF-analyst assistant on the Signal Analyzer page
*Merged 2026-09-11 · branch `feature/analyzer-ai` · 4 file(s), +157 / −1*

- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#744](https://github.com/PierreGode/Ragnar/pull/744) — feat(rf-analyzer): loading spinner while the spectrogram computes
*Merged 2026-09-11 · branch `fix/analyzer-spinner` · 1 file(s), +14 / −1*

#### [#743](https://github.com/PierreGode/Ragnar/pull/743) — feat(rf-analyzer): Segment 4 — protocol framework (line coding, frame alignment, CRC scan)
*Merged 2026-09-11 · branch `feature/analyzer-protocol` · 4 file(s), +296 / −6*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#742](https://github.com/PierreGode/Ragnar/pull/742) — feat(rf-analyzer): Segment 3 — modulation analysis (classify + constellation + instantaneous)
*Merged 2026-09-11 · branch `feature/analyzer-modclass` · 4 file(s), +237 / −9*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#741](https://github.com/PierreGode/Ragnar/pull/741) — feat(rf-analyzer): Segment 2 — measurement (cursors/Δ, box power, zoom history, max-hold) + follow-ups
*Merged 2026-09-11 · branch `feature/analyzer-measure` · 4 file(s), +157 / −48*

- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md)

#### [#740](https://github.com/PierreGode/Ragnar/pull/740) — feat(rf-analyzer): Segment 1 — decode-from-capture (rtl_433) + bit views; add roadmap
*Merged 2026-09-11 · branch `feature/analyzer-decode` · 5 file(s), +310 / −35*

- fix(rf-analyzer): robust burst detection — gap-merge + duty (handles held & pulse-train signals)
- **Docs:** [rf-analyzer-roadmap.md](rf-analyzer-roadmap.md), [rf-waterfall.md](rf-waterfall.md)

#### [#739](https://github.com/PierreGode/Ragnar/pull/739) — feat(rf-analyzer): on-box SigMF IQ analyzer page + "Open in Analyzer" button
*Merged 2026-09-11 · branch `feature/sigmf-analyzer` · 8 file(s), +1050 / −1*

- feat(rf-waterfall): Sessions dropdown — open any recorded SigMF capture in the Analyzer
- feat(rf-waterfall): ⓘ info popup on IQ capture — size/memory guidance
- feat(rf-waterfall): rename + delete for SigMF sessions
- **Docs:** [rf-waterfall-guide.md](rf-waterfall-guide.md), [rf-waterfall.md](rf-waterfall.md)

#### [#738](https://github.com/PierreGode/Ragnar/pull/738) — fix(radio): stream Local Radio as MP3 so it plays on iOS / mobile
*Merged 2026-09-11 · branch `fix/radio-ios-mp3` · 5 file(s), +90 / −15*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#737](https://github.com/PierreGode/Ragnar/pull/737) — docs: add RF Waterfall capability guide
*Merged 2026-09-11 · branch `docs/rf-waterfall-guide` · 2 file(s), +131 / −1*

- **Docs:** [docs index](README.md), [rf-waterfall-guide.md](rf-waterfall-guide.md)

### 2026-09-10

#### [#736](https://github.com/PierreGode/Ragnar/pull/736) — feat(rf-waterfall): measurement layer — markers, SNR/noise, trace math, CFAR signal list
*Merged 2026-09-10 · branch `feature/rf-waterfall-palettes` · 6 file(s), +1143 / −63*

- feat(rf-waterfall): SigMF raw-IQ capture (GNU Radio / inspectrum / URH interop)
- feat(rf-waterfall): persistence (digital-phosphor) display + click-to-decode
- feat(rf-waterfall): spectrum baseline + anomaly detection -> Watchtower
- feat(rf-waterfall): reference-carrier frequency (PPM) calibration
- fix(rf-waterfall): make the page phone-friendly
- fix(rf-waterfall): sweep-restart race crashed Calibrate ('NoneType' has no stdout)
- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#735](https://github.com/PierreGode/Ragnar/pull/735) — feat(rf-waterfall): selectable waterfall colour palettes (Aurora default)
*Merged 2026-09-10 · branch `feature/rf-waterfall-palettes` · 2 file(s), +67 / −9*

- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#734](https://github.com/PierreGode/Ragnar/pull/734) — feat(rtl-sdr): real-time IQ FFT waterfall for the sub-GHz SIGINT view
*Merged 2026-09-10 · branch `feature/rtl-iq-waterfall` · 4 file(s), +357 / −13*

- **Docs:** [rf-waterfall.md](rf-waterfall.md), [sdr-subghz.md](sdr-subghz.md)

#### [#733](https://github.com/PierreGode/Ragnar/pull/733) — feat(guards): VXLAN/NGOAM detection in the in-app Cisco & Juniper CVE guards
*Merged 2026-09-10 · branch `feature/guards-vxlan` · 3 file(s), +244 / −8*

- **Docs:** [nettools.md](nettools.md)

#### [#732](https://github.com/PierreGode/Ragnar/pull/732) — dashboard: rename Console to Activity Log and drop the double timestamp
*Merged 2026-09-10 · branch `fix/dashboard-logs-panel` · 2 file(s), +205 / −127*

- dashboard: one unified, filterable Activity Log (stop the mode-jumping)
- dashboard: double the Activity Log panel height (16rem -> 32rem)

### 2026-09-09

#### [#730](https://github.com/PierreGode/Ragnar/pull/730) — db: actually collapse duplicate real-MAC host rows (stop 400+ log warnings)
*Merged 2026-09-09 · branch `fix/db-dedup-multiple-real-macs` · 2 file(s), +36 / −38*

- env_manager: quiet the per-construction path logs (INFO -> DEBUG)

#### [#729](https://github.com/PierreGode/Ragnar/pull/729) — WiFi Defense: persist scan-option checkboxes across a browser refresh
*Merged 2026-09-09 · branch `fix/wifidef-persist-checkboxes` · 2 file(s), +38 / −1*

#### [#728](https://github.com/PierreGode/Ragnar/pull/728) — WiFi Defense: only flag genuine findings on the Signal Intelligence pivot
*Merged 2026-09-09 · branch `fix/wifidef-benign-ap-selection` · 4 file(s), +83 / −39*

- Signal Intelligence: prefer a managed survey radio (wlan1 > wlan0 > monitor)
- **Docs:** [wifi-analyzer.md](wifi-analyzer.md), [wifi-defense.md](wifi-defense.md)

#### [#727](https://github.com/PierreGode/Ragnar/pull/727) — Fix epd2in13b_V4 (tri-color) e-Paper display not working (#585)
*Merged 2026-09-09 · branch `fix/epd2in13b-v4-driver` · 1 file(s), +13 / −4*

#### [#726](https://github.com/PierreGode/Ragnar/pull/726) — Asset Inventory: permanently ignore warnings from a device
*Merged 2026-09-09 · branch `feature/asset-inventory-ignore-warnings` · 6 file(s), +114 / −21*

- **Docs:** [README (root)](../README.md), [asset-inventory.md](asset-inventory.md)

#### [#725](https://github.com/PierreGode/Ragnar/pull/725) — wifi analyzer: timeshare the radio to survey the Alfa while monitor is on
*Merged 2026-09-09 · branch `fix/survey-timeshare-monitor` · 1 file(s), +68 / −9*

#### [#724](https://github.com/PierreGode/Ragnar/pull/724) — wifidef: revert fragile survey auto-toggle; make duplicate_ssid informational
*Merged 2026-09-09 · branch `fix/wifidef-survey-and-flag-noise` · 4 file(s), +18 / −59*

### 2026-09-08

#### [#723](https://github.com/PierreGode/Ragnar/pull/723) — wifi analyzer: honor the selected radio when it's in monitor mode
*Merged 2026-09-08 · branch `fix/dedupe-rogue-ap-swarm` · 1 file(s), +54 / −19*

#### [#722](https://github.com/PierreGode/Ragnar/pull/722) — scorers: stop a duplicate-SSID swarm faking a HaleHound/PineAP verdict
*Merged 2026-09-08 · branch `fix/dedupe-rogue-ap-swarm` · 3 file(s), +108 / −32*

#### [#721](https://github.com/PierreGode/Ragnar/pull/721) — wifi analyzer: auto-survey on the free radio when the target is in monitor
*Merged 2026-09-08 · branch `feat/wifidef-info-threat` · 1 file(s), +21 / −1*

#### [#720](https://github.com/PierreGode/Ragnar/pull/720) — wifi_defense: add an "info" threat level below "warning"
*Merged 2026-09-08 · branch `feat/wifidef-info-threat` · 5 file(s), +80 / −12*

- web: fix inline WiFi Defense cards never showing (hidden class vs attribute)
- fix: stop PineAP false-positive incidents on randomized/invalid BSSIDs

#### [#719](https://github.com/PierreGode/Ragnar/pull/719) — wifi_defense: deep scan opt-in + capture only EAPOL, not all data
*Merged 2026-09-08 · branch `fix/wpa3-downgrade-false-positives` · 3 file(s), +12 / −7*

#### [#718](https://github.com/PierreGode/Ragnar/pull/718) — wifi_defense: stop WPA3 downgrade false positives
*Merged 2026-09-08 · branch `fix/wpa3-downgrade-false-positives` · 2 file(s), +66 / −51*

#### [#717](https://github.com/PierreGode/Ragnar/pull/717) — wifi_defense: detect WPA3-strip downgrade in the panel scan
*Merged 2026-09-08 · branch `feature/wifidef-full-wifiwatch` · 6 file(s), +333 / −23*

- wifi_defense: fold wifiwatch's client/handshake detectors into a deep scan

### 2026-09-07

#### [#715](https://github.com/PierreGode/Ragnar/pull/715) — web: bump JS cache-buster + show PineAP card on tab open
*Merged 2026-09-07 · branch `fix/pineap-card-cachebuster` · 2 file(s), +9 / −1*

#### [#714](https://github.com/PierreGode/Ragnar/pull/714) — Add PineAP / Wi-Fi Pineapple detection (pineap_watch)
*Merged 2026-09-07 · branch `feature/pineap-detection` · 9 file(s), +1264 / −3*

- tests: fix stale halehound BLE-flood threshold (8 -> 20)
- pineap: add opt-in active probe-response test (the one that transmits)
- docs: mention Wi-Fi Pineapple / PineAP in WiFi Defense description
- web: add PineAP panel + active-probe button to WiFi Defense tab
- **Docs:** [README (root)](../README.md)

#### [#713](https://github.com/PierreGode/Ragnar/pull/713) — docs: slim the README to summaries + links, add a docs index and 3 missing guides
*Merged 2026-09-07 · branch `docs/readme-slim-and-index` · 5 file(s), +348 / −249*

- Update README.md
- Fix link in README for scanning and actions
- Revise multi-source threat intelligence description
- **Docs:** [README (root)](../README.md), [docs index](README.md), [adv-scan.md](adv-scan.md), [pager.md](pager.md), [scanning-and-attacks.md](scanning-and-attacks.md)

#### [#712](https://github.com/PierreGode/Ragnar/pull/712) — Replace image in nettools.md
*Merged 2026-09-07 · branch `PierreGode-patch-1` · 1 file(s), +2 / −1*

- **Docs:** [nettools.md](nettools.md)

#### [#711](https://github.com/PierreGode/Ragnar/pull/711) — docs(ptp): document PTP Watch in Watchtower feed list + cross-link the two PTP cards
*Merged 2026-09-07 · branch `docs/ptp-watch-watchtower-crossref` · 2 file(s), +14 / −2*

- **Docs:** [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#710](https://github.com/PierreGode/Ragnar/pull/710) — Replace visibility matrix image with new image
*Merged 2026-09-07 · branch `PierreGode-matrix` · 1 file(s), +2 / −1*

- **Docs:** [nettools.md](nettools.md)

### 2026-09-06

#### [#709](https://github.com/PierreGode/Ragnar/pull/709) — fix(ptp): unique element IDs for PTP Watch card (was colliding with PTP presence card)
*Merged 2026-09-06 · branch `fix/ptp-watch-dup-element-id` · 2 file(s), +8 / −8*

#### [#708](https://github.com/PierreGode/Ragnar/pull/708) — feat(ptp): passive PTP/gPTP timing-plane watcher (IEEE-1588 v2, 42 codes)
*Merged 2026-09-06 · branch `feature/ptp-watch-v2` · 6 file(s), +2894 / −2*

- **Docs:** [nettools.md](nettools.md)

#### [#707](https://github.com/PierreGode/Ragnar/pull/707) — fix(bfd,guards): handle IPv6 Authentication Header (AH, proto 51) in ext-header walks
*Merged 2026-09-06 · branch `fix/bfd-v2-ah-and-guard-extheaders` · 3 file(s), +68 / −21*

- **Docs:** [nettools.md](nettools.md)

#### [#706](https://github.com/PierreGode/Ragnar/pull/706) — fix(cisco,juniper): dual-stack guard capture via next-header-qualified ip6[6] BPF
*Merged 2026-09-06 · branch `fix/cisco-guard-dhcpv6-ipv6-capture` · 2 file(s), +89 / −17*

- **Docs:** [nettools.md](nettools.md)

#### [#705](https://github.com/PierreGode/Ragnar/pull/705) — feat(juniper): dual-stack Juniper guard + shared IPv6 guard-parse infra
*Merged 2026-09-06 · branch `feature/juniper-guard-v2-ipv6` · 3 file(s), +116 / −13*

- **Docs:** [nettools.md](nettools.md)

#### [#704](https://github.com/PierreGode/Ragnar/pull/704) — feat(vpn,snmp,mac,cisco): dual-stack VPN egress, SNMP-over-IPv6, MAC EUI-64 identity, Cisco IKEv2/DHCPv6/RH0 CVEs
*Merged 2026-09-06 · branch `feature/vpn-snmp-mac-cisco-v2` · 4 file(s), +353 / −48*

- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

### 2026-09-05

#### [#703](https://github.com/PierreGode/Ragnar/pull/703) — feat(ntp,eigrp): NTP on-path forgery + version/stratum sanity; EIGRP IPv6 route TLVs (RFC 7868)
*Merged 2026-09-05 · branch `feature/ntp-v3-eigrp-v4-watch` · 4 file(s), +201 / −21*

- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#702](https://github.com/PierreGode/Ragnar/pull/702) — feat(isis): IPv6 reachability content checks for IS-IS Watch (RFC 5308 TLV 236/237)
*Merged 2026-09-05 · branch `feature/isis-watch-v4-ipv6` · 4 file(s), +185 / −13*

- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#701](https://github.com/PierreGode/Ragnar/pull/701) — feat(fhrp): IPv6 dual-stack for FHRP Watch (HSRPv6/VRRPv3/GLBPv6)
*Merged 2026-09-05 · branch `feature/fhrp-watch-v4-dualstack` · 4 file(s), +303 / −41*

- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#700](https://github.com/PierreGode/Ragnar/pull/700) — feat(bgp): MP-BGP IPv6 dual-stack for passive BGP Path Watch + receive-only collector
*Merged 2026-09-05 · branch `feature/bgp-pathwatch-v3-dualstack` · 5 file(s), +275 / −45*

- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#699](https://github.com/PierreGode/Ragnar/pull/699) — fix(net): auto-select interface for LACP/RPC/BFD/SR-MPLS watch cards
*Merged 2026-09-05 · branch `fix/watch-card-auto-iface` · 1 file(s), +4 / −0*

#### [#698](https://github.com/PierreGode/Ragnar/pull/698) — ICMP Watch v3: add ICMPv6 Redirect (type 137) dual-stack detection
*Merged 2026-09-05 · branch `feature/ipv6-dualstack-v3-watch` · 6 file(s), +1099 / −103*

- DNS Doctor v3: dual-stack cross-family hijack detection (AAAA)
- OSPF Watch v3: parse OSPFv3 (IPv6) so its packets reach the detectors
- DHCP Doctor v2: add zero-config DNS6_LINKLOCAL mitm6 tell to IPv6 First-Hop Watch
- docs(README): note IPv6 dual-stack coverage for ICMP/OSPF/DNS/DHCPv6 watchers
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#697](https://github.com/PierreGode/Ragnar/pull/697) — BFD Watch: passive failover-manipulation detector (forged teardown / CVE-2018-0155)
*Merged 2026-09-05 · branch `feature/bfd-srmpls-arpv3-igmpv3-watch` · 10 file(s), +6193 / −49*

- SR-MPLS Watch: passive MPLS/SR-MPLS/SRv6 label & segment-injection detector
- IGMP Watch v3: add MLD (IPv6 multicast) to the in-app watcher
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

### 2026-09-04

#### [#696](https://github.com/PierreGode/Ragnar/pull/696) — LACP Watch + RPC/NetLogon Watch: two new passive in-app watchers
*Merged 2026-09-04 · branch `feature/lacp-rpc-netlogon-watch` · 10 file(s), +5273 / −5*

- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

### 2026-09-03

#### [#695](https://github.com/PierreGode/Ragnar/pull/695) — SMB & Kerberos Watch v2
*Merged 2026-09-03 · branch `feature/smb-kerberos-watch-v2` · 6 file(s), +388 / −18*

- SMB & Kerberos Watch v2: KDC-error recon (K7), NTLM relay tells (N2/N3), RC4-offer refinement (K2), Watchtower feed
- **Docs:** [nettools.md](nettools.md), [watchtower.md](watchtower.md)

### 2026-09-02

#### [#694](https://github.com/PierreGode/Ragnar/pull/694) — fix(display): dedicated landscape layout for 2.13" e-paper lying down (90°/270°)
*Merged 2026-09-02 · branch `fix/epaper-2in13-horizontal-122` · 0 file(s), +0 / −0*

- fix(display): fill the 2.13" landscape lower zone (mood + big speech + framed sprite)

#### [#692](https://github.com/PierreGode/Ragnar/pull/692) — fix(display): dedicated landscape layout for 2.13" e-paper lying down (90°/270°)
*Merged 2026-09-02 · branch `fix/epaper-2in13-horizontal-122` · 2 file(s), +207 / −0*

- fix(display): fill the 2.13" landscape lower zone (mood + big speech + framed sprite)
- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#691](https://github.com/PierreGode/Ragnar/pull/691) — docs(homeassistant): add captive-portal → LED-strip-red automation example
*Merged 2026-09-02 · branch `docs/ha-hue-captive-portal-example` · 1 file(s), +194 / −5*

- docs(homeassistant): fix HA automation triggers — event ENTITY needs a state trigger
- docs(homeassistant): captive-portal → red LED worked example + state-trigger fix
- **Docs:** [homeassistant.md](homeassistant.md)

#### [#690](https://github.com/PierreGode/Ragnar/pull/690) — ICMP Watch v2 (redirect/ARP-poison) + BGP Path Watch v2 (convergence) in-app
*Merged 2026-09-02 · branch `feature/bgp-icmp-watch-v2` · 9 file(s), +2508 / −46*

- Update image in Authority Verification suite
- **Docs:** [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#689](https://github.com/PierreGode/Ragnar/pull/689) — Detect HaleHound-CYD attack multitool (Wi-Fi + LAN + BLE fusion)
*Merged 2026-09-02 · branch `feature/halehound-detection` · 16 file(s), +3254 / −30*

- HaleHound card: use compiled fuchsia classes (pink was purged)
- HaleHound: drop "Cheap Yellow Display" wording
- HaleHound: move correlation card to the bottom of the WiFi Defense tab
- HaleHound: reframe as general ESP32 attack-tool detector (Marauder/Bruce)
- HaleHound card: drop dog emoji, add HaleHound wordmark logo in heading
- HaleHound card: plain heading, use logo inline for HaleHound-CYD in description
- …and 21 more commit(s)
- **Docs:** [asset-inventory.md](asset-inventory.md), [incident-correlation.md](incident-correlation.md), [wifi-defense.md](wifi-defense.md)

### 2026-08-31

#### [#688](https://github.com/PierreGode/Ragnar/pull/688) — pager: add 929.9375 + 931.0625 MHz US FLEX channels to preset dropdown
*Merged 2026-08-31 · branch `feature/pager-preset-929937` · 1 file(s), +2 / −0*

### 2026-08-30

#### [#687](https://github.com/PierreGode/Ragnar/pull/687) — pager: add POCSAG baud / FLEX demod selector + invert + cleaner FM demod
*Merged 2026-08-30 · branch `feature/pager-baud-demod-selector` · 4 file(s), +124 / −16*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#686](https://github.com/PierreGode/Ragnar/pull/686) — acars: fix silent panel — use acarsdec -o 4 (msg JSON), not -o 5 (route JSON)
*Merged 2026-08-30 · branch `feature/vdl2-atn-decode` · 1 file(s), +7 / −3*

#### [#685](https://github.com/PierreGode/Ragnar/pull/685) — install_dumpvdl2: add required libglib2.0-dev + apt lock timeout
*Merged 2026-08-30 · branch `feature/vdl2-atn-decode` · 1 file(s), +10 / −5*

#### [#684](https://github.com/PierreGode/Ragnar/pull/684) — install_dumpvdl2: surface real build errors + auto -j1 fallback for low-RAM Pis
*Merged 2026-08-30 · branch `feature/vdl2-atn-decode` · 2 file(s), +74 / −27*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#683](https://github.com/PierreGode/Ragnar/pull/683) — VDL Mode 2 / ATN decoding on the ADS-B radar (dumpvdl2 + libacars)
*Merged 2026-08-30 · branch `feature/vdl2-atn-decode` · 7 file(s), +884 / −11*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#682](https://github.com/PierreGode/Ragnar/pull/682) — Add Flipper One (RK3576 ARM64 Linux) feasibility & porting notes
*Merged 2026-08-30 · branch `feature/flipper-one-support` · 2 file(s), +121 / −0*

- **Docs:** [README (root)](../README.md), [flipper-one.md](flipper-one.md)

#### [#681](https://github.com/PierreGode/Ragnar/pull/681) — ADS-B: click a contact for a world-map flight route (FlightAware-style)
*Merged 2026-08-30 · branch `feature/adsb-flight-routes` · 4 file(s), +1010 / −40*

- ADS-B route map: use Leaflet + Esri tiles like the Mesh Map
- ADS-B: real live position + aircraft type + IP-geo location fallback
- ADS-B: fix empty radar diagnosis + stop demo feed fighting a live SDR
- ADS-B: use the box GPS as the primary receiver location (then browser, then IP)
- ADS-B: internet fallback when SDR is deaf + flag stale filed routes
- ADS-B: fix empty radar when SDR runs but is deaf (regression vs main)
- …and 4 more commit(s)
- **Docs:** [sdr-subghz.md](sdr-subghz.md)

### 2026-08-28

#### [#680](https://github.com/PierreGode/Ragnar/pull/680) — Add SPI TFT kiosk installer for MPI3501 / ILI9486 3.5" display
*Merged 2026-08-28 · branch `screen35` · 3 file(s), +354 / −0*

### 2026-08-27

#### [#679](https://github.com/PierreGode/Ragnar/pull/679) — Replace image in nettools documentation
*Merged 2026-08-27 · branch `PierreGode-patch-5` · 1 file(s), +2 / −1*

- **Docs:** [nettools.md](nettools.md)

#### [#678](https://github.com/PierreGode/Ragnar/pull/678) — Signal Intelligence tools: open in the same tab, not a new one
*Merged 2026-08-27 · branch `feature/si-back-link` · 1 file(s), +6 / −6*

#### [#677](https://github.com/PierreGode/Ragnar/pull/677) — Signal Intelligence tools: '← Ragnar' returns to the Signal Intelligence tab
*Merged 2026-08-27 · branch `feature/si-back-link` · 6 file(s), +6 / −6*

#### [#676](https://github.com/PierreGode/Ragnar/pull/676) — Mesh Nodes: node map 20% narrower
*Merged 2026-08-27 · branch `feature/mesh-map` · 1 file(s), +19 / −7*

- Mesh Nodes: narrow the Node map CARD so the Nodes table gets width (no scroll)
- Mesh Nodes: table scroll box fills the card height (was a short 360px box)
- Mesh Nodes messages: Follow checkbox, timestamps, highlight the latest

#### [#675](https://github.com/PierreGode/Ragnar/pull/675) — Mesh: full-screen Leaflet map (/mesh-map) + Full map view button
*Merged 2026-08-27 · branch `feature/mesh-map` · 6 file(s), +583 / −29*

- Mesh map: drop CARTO (needs API key) for key-free tile providers
- Mesh map: 🌍 World view — public worldwide mesh nodes
- Mesh map: decode encrypted MQTT (real node data) + viewport-prioritised loading
- Mesh map: World is a proper toggle — second click hides the public nodes
- Mesh MQTT: fix 'no nodes' + 'super slow' (harden decoder + throttle firehose)
- Mesh MQTT: fix disconnect deadlock ('MQTT won't stop')
- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#674](https://github.com/PierreGode/Ragnar/pull/674) — Mesh Nodes: serve /mesh-nodes unconditionally (fix 'Not Found' with no hardware)
*Merged 2026-08-27 · branch `feature/mesh-page-always` · 1 file(s), +5 / −20*

#### [#673](https://github.com/PierreGode/Ragnar/pull/673) — Signal Intelligence: fix invisible VOR button + always show Mesh Nodes
*Merged 2026-08-27 · branch `feature/si-button-fixes` · 2 file(s), +7 / −8*

#### [#672](https://github.com/PierreGode/Ragnar/pull/672) — Meshtastic: MQTT Internet source + transmit (the full mesh suite)
*Merged 2026-08-27 · branch `feature/meshtastic-mqtt` · 5 file(s), +453 / −53*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

### 2026-08-26

#### [#671](https://github.com/PierreGode/Ragnar/pull/671) — APRS: ham packet RX + messaging (off-air SDR + APRS-IS worldwide)
*Merged 2026-08-26 · branch `feature/aprs-messaging` · 8 file(s), +1341 / −8*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#670](https://github.com/PierreGode/Ragnar/pull/670) — Add RoomScan: touchscreen floor-plan tracer for Coverage Heatmap
*Merged 2026-08-26 · branch `feature/roomscan-s3-lcd` · 13 file(s), +1674 / −13*

- Coverage Heatmap: transcode TIFF/BMP floorplans to PNG on upload
- Coverage Heatmap: move + resize the uploaded floorplan image
- **Docs:** [README (root)](../README.md), [roomscan.md](roomscan.md)

#### [#669](https://github.com/PierreGode/Ragnar/pull/669) — Pager: add Motorola QCII two-tone decode; new VOR radial decoder
*Merged 2026-08-26 · branch `feature/qcii-vor` · 12 file(s), +1480 / −421*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#668](https://github.com/PierreGode/Ragnar/pull/668) — Asset Inventory: stop false-positive vendor-change "spoof" alerts
*Merged 2026-08-26 · branch `fix/asset-vendor-change-false-positive` · 2 file(s), +47 / −8*

- **Docs:** [asset-inventory.md](asset-inventory.md)

### 2026-08-25

#### [#667](https://github.com/PierreGode/Ragnar/pull/667) — Add Docker installation (headless web UI)
*Merged 2026-08-25 · branch `feature/docker-install` · 12 file(s), +758 / −22*

- Docker: install git + sudo, document in-container update behavior
- Fix orchestrator never starting without NetworkManager (containers)
- Installer: add Docker container as a menu option
- Updater: rebuild Docker deployment instead of native flow when detected
- CI: publish multi-arch Docker image to GHCR on release/tag
- Docker: sharpen positioning + optional hardware-passthrough overlay
- **Docs:** [README (root)](../README.md), [DOCKER.md](DOCKER.md)

#### [#666](https://github.com/PierreGode/Ragnar/pull/666) — Add Asset Inventory + SIEM/outbound forwarding
*Merged 2026-08-25 · branch `feature/asset-inventory-siem` · 10 file(s), +2608 / −2*

- Move Assets from top-level tab to Network sub-tab (after AP Archive)
- Asset Inventory: gateway classification, broadcast filter, vendor cleanup
- Assets tab: mobile-friendly layout
- **Docs:** [README (root)](../README.md), [asset-inventory.md](asset-inventory.md), [siem.md](siem.md)

### 2026-08-24

#### [#665](https://github.com/PierreGode/Ragnar/pull/665) — RF Waterfall: Mesh/LoRa overlay dropdown on HackRF too (full panel parity)
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 3 file(s), +85 / −22*

- RF Waterfall: fix HackRF narrow-span floor streaks (code-review follow-up)
- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#664](https://github.com/PierreGode/Ragnar/pull/664) — RF Waterfall: manual free-tune on both panels + all sub-GHz presets on HackRF
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 3 file(s), +130 / −14*

- RF Waterfall: show all presets in the RTL demo panel too (band-aware synth)
- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#663](https://github.com/PierreGode/Ragnar/pull/663) — RF Waterfall: add AM (medium-wave) + Shortwave HF band scopes
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 2 file(s), +12 / −3*

#### [#662](https://github.com/PierreGode/Ragnar/pull/662) — RF Waterfall: FM/Airband band scopes + click-a-peak-to-tune the radio
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 2 file(s), +22 / −1*

#### [#661](https://github.com/PierreGode/Ragnar/pull/661) — Signal Intelligence: Dome is the default view, moved before Bar
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 2 file(s), +6 / −6*

#### [#654](https://github.com/PierreGode/Ragnar/pull/654) — Fix Pwangotchi Captures Paneel showing 0 handshakes
*Merged 2026-08-24 · branch `main` · 1 file(s), +2 / −2*

#### [#660](https://github.com/PierreGode/Ragnar/pull/660) — Feature/rtl sdr radio presets
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 2 file(s), +43 / −10*

- ADS-B: show ICAO airline designator alongside IATA in the Airline column
- RF Waterfall radio: custom presets — save/remember your own stations

#### [#659](https://github.com/PierreGode/Ragnar/pull/659) — Rename WiFi Analyzer / WiFi Spectrum Analyzer -> Signal Intelligence
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 3 file(s), +17 / −17*

#### [#658](https://github.com/PierreGode/Ragnar/pull/658) — Feature/rtl sdr
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 7 file(s), +494 / −29*

- ADS-B: correct IATA wording — it's an ICAO->IATA cross-reference, not derived
- ADS-B Radar: click a contact to highlight it on the radar
- Mesh Nodes: click a node to highlight + zoom to it on the map
- RF Waterfall: Local Radio (FM/AM) with live audio you can listen to
- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#657](https://github.com/PierreGode/Ragnar/pull/657) — ADS-B: force max gain, recognise R860 (NESDR SMArt v5), on-radar no-RX hint
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 3 file(s), +34 / −3*

#### [#656](https://github.com/PierreGode/Ragnar/pull/656) — SDR pages: full-width on desktop, mobile unchanged
*Merged 2026-08-24 · branch `feature/rtl-sdr-support-fullscreen` · 4 file(s), +9 / −7*

- ADS-B Radar: shrink radar ~20%, give Contacts the freed width

### 2026-08-23

#### [#655](https://github.com/PierreGode/Ragnar/pull/655) — ADS-B ACARS panel + IATA-next-to-ICAO + pager full-text; airline DB x1.5
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 11 file(s), +714 / −20*

- ADS-B: reception diagnostics + robust dump1090 launch (no-hits triage)
- Show Mesh Nodes button when any SDR present (collaborator couldn't see it)
- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#653](https://github.com/PierreGode/Ragnar/pull/653) — ADS-B: build dump1090 from source ('can't find the package' fix)
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 14 file(s), +806 / −55*

- Pager Decode: POCSAG/FLEX via rtl_fm | multimon-ng
- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#652](https://github.com/PierreGode/Ragnar/pull/652) — Fix blank ADS-B Radar / Mesh Nodes pages (404 before the install button)
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 1 file(s), +25 / −15*

#### [#651](https://github.com/PierreGode/Ragnar/pull/651) — Feature/rtl sdr
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 14 file(s), +2524 / −13*

- RF Waterfall: 315/40/27 MHz bands, PPM+gain tuning, PNG snapshot
- ADS-B Radar: live aircraft (1090 MHz) on a PPI radar screen
- SDR: session record/replay + ADS-B ICAO/IATA/tail-registration
- Mesh Nodes: real Meshtastic enumeration via a USB companion node
- Fix ADS-B Radar button colour (bg-teal purged from tailwind.css)
- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#650](https://github.com/PierreGode/Ragnar/pull/650) — Mesh overlay: Meshtastic / MeshCore / LoRaWAN spectrum view (energy-only)
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 4 file(s), +190 / −34*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#649](https://github.com/PierreGode/Ragnar/pull/649) — Feature/rtl sdr
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 3 file(s), +161 / −17*

- Z-Wave Spectrum: region-aware sub-GHz energy view (nobody scans this)
- RF Waterfall: switch heat colormap to eye-kinder 'Aurora' (drop yellow)

#### [#648](https://github.com/PierreGode/Ragnar/pull/648) — RTL-SDR: fix 433 band never loading (single-crop sweep finalization)
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 1 file(s), +17 / −3*

#### [#647](https://github.com/PierreGode/Ragnar/pull/647) — SDR check: one-click Install button to fix tools-missing / DVB-held
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 5 file(s), +133 / −2*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#646](https://github.com/PierreGode/Ragnar/pull/646) — RTL-SDR: guarantee rtl-sdr/rtl-433 install in installer + updater
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 2 file(s), +36 / −18*

#### [#645](https://github.com/PierreGode/Ragnar/pull/645) — RTL-SDR: lsusb VID:PID detection fallback + better 'not detected' diagnostics
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 5 file(s), +294 / −6*

- SDR check: inline diagnostic button in the Wi-Fi Spectrum Analyzer
- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#644](https://github.com/PierreGode/Ragnar/pull/644) — RF Waterfall: per-panel full-screen buttons + broad RTL-SDR dongle support
*Merged 2026-08-23 · branch `feature/rtl-sdr-support-fullscreen` · 8 file(s), +212 / −12*

- Make ups.py and ups_api.py executable (755)
- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#643](https://github.com/PierreGode/Ragnar/pull/643) — Sub-GHz SDR tab: doc + front-end (RTL-SDR ISM/waterfall)
*Merged 2026-08-23 · branch `feature/subghz-sdr-tab` · 3 file(s), +361 / −0*

- **Docs:** [sdr-subghz.md](sdr-subghz.md)

#### [#642](https://github.com/PierreGode/Ragnar/pull/642) — RF Waterfall: pro upgrades — decode, occupancy+log, zoom, click-to-tune
*Merged 2026-08-23 · branch `fix/rf-waterfall-scroll-and-back` · 4 file(s), +443 / −310*

#### [#641](https://github.com/PierreGode/Ragnar/pull/641) — RF Waterfall: stop scroll from resetting the waterfall + add Return to Ragnar
*Merged 2026-08-23 · branch `fix/rf-waterfall-scroll-and-back` · 1 file(s), +15 / −4*

#### [#640](https://github.com/PierreGode/Ragnar/pull/640) — Feature/sdr waterfall
*Merged 2026-08-23 · branch `feature/sdr-waterfall-demo` · 10 file(s), +1507 / −6*

- Add hidden synthetic RF Waterfall demo (opt-in, no SDR required)
- RF Waterfall page: promote to real feature with live HackRF + RTL-SDR
- Install rtl-sdr + rtl-433 for the RF Waterfall sub-GHz (RTL-SDR) path
- **Docs:** [rf-waterfall.md](rf-waterfall.md)

#### [#639](https://github.com/PierreGode/Ragnar/pull/639) — RuSense flasher: add fixed CSI channel field to Provision WiFi
*Merged 2026-08-23 · branch `feature/rusense-flasher-channel` · 3 file(s), +22 / −4*

### 2026-08-22

#### [#638](https://github.com/PierreGode/Ragnar/pull/638) — Move observatory layer controls to compact top-right icon buttons on mobile
*Merged 2026-08-22 · branch `observatory-mobile-chips` · 4 file(s), +28 / −16*

- Lift the observatory no-fix note above the scrubber and fade it to 15% opacity
- Tune observatory overlay opacities: note 80%, slider 60%, layer buttons 70% transparent
- **Docs:** [diagnostics.md](diagnostics.md)

#### [#637](https://github.com/PierreGode/Ragnar/pull/637) — up
*Merged 2026-08-22 · branch `3gss` · 3 file(s), +16 / −6*

#### [#636](https://github.com/PierreGode/Ragnar/pull/636) — Feed SSH Watch and Telnet Watch into Watchtower + Network Integrity Monitor
*Merged 2026-08-22 · branch `feature/ssh-telnet-monitor-watchtower` · 7 file(s), +149 / −3*

- **Docs:** [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#635](https://github.com/PierreGode/Ragnar/pull/635) — Make the GNSS observatory mobile/touch friendly
*Merged 2026-08-22 · branch `observatory-mobile` · 4 file(s), +101 / −12*

- **Docs:** [diagnostics.md](diagnostics.md)

#### [#634](https://github.com/PierreGode/Ragnar/pull/634) — Add SSH Watch and Telnet Watch passive observers
*Merged 2026-08-22 · branch `feature/ssh-telnet-watch` · 9 file(s), +3983 / −4*

- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#633](https://github.com/PierreGode/Ragnar/pull/633) — sgs
*Merged 2026-08-22 · branch `3gss` · 15 file(s), +2276 / −40*

- 3gss
- hs
- https
- threee
- cont
- plan
- …and 14 more commit(s)

#### [#632](https://github.com/PierreGode/Ragnar/pull/632) — Starview: satellites follow the time scrubber + one consistent sat set
*Merged 2026-08-22 · branch `patchingnss` · 4 file(s), +174 / −25*

- **Docs:** [diagnostics.md](diagnostics.md)

### 2026-08-21

#### [#631](https://github.com/PierreGode/Ragnar/pull/631) — Comware Guard: stop the default role from self-flagging every scan
*Merged 2026-08-21 · branch `feature/comware-role-default` · 3 file(s), +25 / −12*

- **Docs:** [nettools.md](nettools.md)

#### [#630](https://github.com/PierreGode/Ragnar/pull/630) — Fix typo in RuSense section header
*Merged 2026-08-21 · branch `PierreGode-patch-4` · 1 file(s), +1 / −1*

- **Docs:** [README (root)](../README.md)

#### [#629](https://github.com/PierreGode/Ragnar/pull/629) — Ragnar Starview: turn the easter egg into a GNSS observatory
*Merged 2026-08-21 · branch `feature/starview-observatory` · 7 file(s), +632 / −25*

- **Docs:** [README (root)](../README.md), [diagnostics.md](diagnostics.md)

#### [#628](https://github.com/PierreGode/Ragnar/pull/628) — TLS Watch v3: name SWEET32 / CVE-2016-2183 on the wire
*Merged 2026-08-21 · branch `feature/tls-watch-v3` · 3 file(s), +132 / −3*

- **Docs:** [nettools.md](nettools.md)

#### [#627](https://github.com/PierreGode/Ragnar/pull/627) — Add Clear button to the Watchtower card
*Merged 2026-08-21 · branch `feature/watchtower-clear-button` · 5 file(s), +55 / −2*

- Mirror the Watchtower Clear button on the Dashboard summary card
- Clear the correlated incidents too, not just the raw alerts

### 2026-08-20

#### [#626](https://github.com/PierreGode/Ragnar/pull/626) — LDAP Watch v3: detect LDAPNightmare external-referral vector (CVE-2024-49112/49113)
*Merged 2026-08-20 · branch `feature/ldap-watch-v3-referral` · 4 file(s), +152 / −6*

- **Docs:** [nettools.md](nettools.md)

#### [#625](https://github.com/PierreGode/Ragnar/pull/625) — Gate vendor switch/router guards to LAN-only in the Net-Integrity auto rotation
*Merged 2026-08-20 · branch `fix/vendor-guards-lan-only` · 4 file(s), +40 / −12*

- **Docs:** [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#624](https://github.com/PierreGode/Ragnar/pull/624) — fix
*Merged 2026-08-20 · branch `smallpatch` · 6 file(s), +1046 / −48*

- ff
- rt
- gs
- gss
- inf
- ju
- …and 3 more commit(s)

### 2026-08-19

#### [#623](https://github.com/PierreGode/Ragnar/pull/623) — RuSense: persistent Calibrated badge + quality % on node rows
*Merged 2026-08-19 · branch `feature/rusense-nodecal-quality` · 5 file(s), +67 / −16*

- **Docs:** [rusense.md](rusense.md)

#### [#622](https://github.com/PierreGode/Ragnar/pull/622) — RuSense: bump loader.js cache-bust tag in ragnar_modern.js
*Merged 2026-08-19 · branch `fix/rusense-nodecal-cachebust` · 5 file(s), +8 / −8*

- RuSense: node calibration recording lasts 15s (was 6s)
- **Docs:** [rusense.md](rusense.md)

#### [#621](https://github.com/PierreGode/Ragnar/pull/621) — RuSense: per-node proximity calibration button in Nodes tab
*Merged 2026-08-19 · branch `feature/rusense-node-proximity-calibration` · 4 file(s), +281 / −9*

- **Docs:** [rusense.md](rusense.md)

#### [#620](https://github.com/PierreGode/Ragnar/pull/620) — security: triage & remediate CodeQL code-scanning alerts
*Merged 2026-08-19 · branch `fix/codeql-advanced-setup` · 7 file(s), +107 / −25*

#### [#619](https://github.com/PierreGode/Ragnar/pull/619) — ci: add advanced CodeQL workflow (python + js, build-mode none)
*Merged 2026-08-19 · branch `fix/codeql-advanced-setup` · 1 file(s), +61 / −0*

#### [#618](https://github.com/PierreGode/Ragnar/pull/618) — comware guard: passive HPE Comware / Huawei VRF-hopping monitor + Watchtower feed
*Merged 2026-08-19 · branch `feature/hpe-comware-guard` · 7 file(s), +726 / −11*

- ntp watch card: name the detected Autokey CVEs explicitly
- **Docs:** [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#617](https://github.com/PierreGode/Ragnar/pull/617) — observatory: refine the activity blob (smoothing, single blob, fingerprinting)
*Merged 2026-08-19 · branch `feature/observatory-blob-refine` · 7 file(s), +254 / −5*

- observatory: expand fingerprint calibration to a 9-point floor grid
- observatory: persist fingerprints server-side (shared across browsers)
- **Docs:** [rusense.md](rusense.md)

#### [#616](https://github.com/PierreGode/Ragnar/pull/616) — rusense: coarse multi-node Observatory localization (blob follows activity)
*Merged 2026-08-19 · branch `feature/rusense-activity-localization` · 3 file(s), +45 / −1*

- **Docs:** [rusense.md](rusense.md)

#### [#615](https://github.com/PierreGode/Ragnar/pull/615) — rusense: add Restart button to the Sensing backend card
*Merged 2026-08-19 · branch `feature/sensing-restart-button` · 4 file(s), +57 / −1*

- **Docs:** [rusense.md](rusense.md)

#### [#614](https://github.com/PierreGode/Ragnar/pull/614) — rusense: refresh sensing-server to upstream RuView + fix LAN UDP bind
*Merged 2026-08-19 · branch `feature/rusense-upstream-refresh` · 5 file(s), +49 / −3*

- **Docs:** [rusense.md](rusense.md)

#### [#613](https://github.com/PierreGode/Ragnar/pull/613) — ntp watch: Autokey extension-field detection (CVE-2014-9295 crypto_recv RCE)
*Merged 2026-08-19 · branch `feature/vendor-guards-arista-juniper-cisco` · 5 file(s), +1626 / −25*

- vendor guards: passive Cisco / Juniper / Arista router+switch CVE monitors
- vendor guards: rename Cisco card to 'Cisco Switch and Router Guard'
- **Docs:** [nettools.md](nettools.md)

### 2026-08-18

#### [#612](https://github.com/PierreGode/Ragnar/pull/612) — Feature/cyberdeck cm5 kiosk DezusAZ update
*Merged 2026-08-18 · branch `feature/cyberdeck-cm5-kiosk` · 12 file(s), +361 / −6*

- Kiosk: escape hatch + small-screen scaling for handheld decks (Hackberry Pi CM5)
- Kiosk: handheld (CM5) toggle + display-scale field in Settings → On-screen Display
- **Docs:** [README (root)](../README.md), [kiosk.md](kiosk.md)

#### [#610](https://github.com/PierreGode/Ragnar/pull/610) — docs: add Hackberry Pi CM5 community port to Supported Platforms
*Merged 2026-08-18 · branch `docs/hackberry-cm5-port` · 1 file(s), +10 / −0*

- **Docs:** [README (root)](../README.md)

#### [#609](https://github.com/PierreGode/Ragnar/pull/609) — Fix HackRF waterfall dying after a few seconds (USB re-probe during sweep)
*Merged 2026-08-18 · branch `fix/sdr-waterfall-smooth` · 1 file(s), +61 / −5*

#### [#608](https://github.com/PierreGode/Ragnar/pull/608) — Sharpen SDR waterfall: 512 columns, 600 rows, finer sweep bins
*Merged 2026-08-18 · branch `fix/sdr-waterfall-smooth` · 4 file(s), +14 / −7*

- **Docs:** [wifi-analyzer.md](wifi-analyzer.md)

#### [#607](https://github.com/PierreGode/Ragnar/pull/607) — Smooth SDR waterfall: dwell-integrate hackrf_sweep into a steady frame rate
*Merged 2026-08-18 · branch `fix/sdr-waterfall-smooth` · 4 file(s), +66 / −8*

- **Docs:** [wifi-analyzer.md](wifi-analyzer.md)

#### [#606](https://github.com/PierreGode/Ragnar/pull/606) — Fix headless install blanking DPI/HDMI panels (HackBerry Pi)
*Merged 2026-08-18 · branch `fix/headless-epd-guard` · 5 file(s), +54 / −2*

- **Docs:** [INSTALL.md](INSTALL.md)

#### [#605](https://github.com/PierreGode/Ragnar/pull/605) — Update install_ragnar.sh
*Merged 2026-08-18 · branch `PierreGode-patch-3` · 1 file(s), +1 / −1*

#### [#604](https://github.com/PierreGode/Ragnar/pull/604) — Update README.md
*Merged 2026-08-18 · branch `PierreGode-patch-2` · 1 file(s), +2 / −1*

- **Docs:** [README (root)](../README.md)

#### [#603](https://github.com/PierreGode/Ragnar/pull/603) — mac watch: HSRP/VRRP/GLBP virtual-MAC awareness + VIP-hijack detection
*Merged 2026-08-18 · branch `feature/mac-watch-fhrp-awareness` · 5 file(s), +188 / −24*

- **Docs:** [nettools.md](nettools.md)

#### [#602](https://github.com/PierreGode/Ragnar/pull/602) — install: skip Pi-only display/GPIO steps on non-Pi headless hosts
*Merged 2026-08-18 · branch `fix/headless-ubuntu-display-drivers` · 2 file(s), +61 / −8*

- **Docs:** [INSTALL.md](INSTALL.md)

### 2026-08-17

#### [#601](https://github.com/PierreGode/Ragnar/pull/601) — net integrity monitor: cover MAC Watch + rank CDPwn critical (Pushover)
*Merged 2026-08-17 · branch `fix/integrity-monitor-mac-cdpwn` · 4 file(s), +14 / −8*

- watchtower: complete the source list on both cards + docs
- web: refresh Network Integrity Monitor card to match actual coverage
- **Docs:** [watchtower.md](watchtower.md)

#### [#600](https://github.com/PierreGode/Ragnar/pull/600) — detector self-test: add MAC Watch + DHCP Guardian (both with Scapy e2e)
*Merged 2026-08-17 · branch `fix/selftest-mac-dhcp` · 3 file(s), +190 / −9*

#### [#597](https://github.com/PierreGode/Ragnar/pull/597) — Fix battetry green filling icon
*Merged 2026-08-17 · branch `main` · 4 file(s), +293 / −219*

- moving UPS 1.2 lite to system tab
- **Docs:** [UPS_INTEGRATION.md](UPS_INTEGRATION.md)

#### [#599](https://github.com/PierreGode/Ragnar/pull/599) — Networking updates
*Merged 2026-08-17 · branch `thefixes` · 13 file(s), +1365 / −54*

- isiswatch: bound TLV walk by IS-IS PDU Length (Ethernet-padding false positive)
- netdiag watchers: add trailing-data / Etherleak detector (CDP/DTP/VTP/EIGRP/FHRP/OSPF)
- docs: document PDU-length bounding + trailing-data/Etherleak detection
- cdpwatch: add CDPwn byte-level exploit-shape + CVE-screening detectors
- web: surface CDPwn on the CDP Watch card
- arp_guard: FHRP (HSRP/VRRP) virtual-MAC awareness + fhrpwatch cross-pivot
- …and 9 more commit(s)
- **Docs:** [arp_guard.md](arp_guard.md), [isiswatch.md](isiswatch.md), [nettools.md](nettools.md)

### 2026-08-16

#### [#598](https://github.com/PierreGode/Ragnar/pull/598) — Observatory: vendor Three.js so it loads under the hardening CSP
*Merged 2026-08-16 · branch `feature/observatory-demo-flag` · 6 file(s), +120 / −13*

- Observatory: flag demo data + label placeholder node 'demo' until a real node connects
- Observatory: pin DEMO flag to top-left on phones so it no longer overlaps the scenario dropdown
- Observatory: fix dead fullscreen button + mobile hardening
- Observatory: stack auto-cycle under the DEMO flag; it rises when a node connects
- **Docs:** [rusense.md](rusense.md)

### 2026-08-15

#### [#596](https://github.com/PierreGode/Ragnar/pull/596) — Move UPS Power card from Config tab to System tab below Power
*Merged 2026-08-15 · branch `ups-move-to-system` · 1 file(s), +30 / −33*

#### [#595](https://github.com/PierreGode/Ragnar/pull/595) — Add ups lite clone(MJ) 1.2 and other that use diffrient adress
*Merged 2026-08-15 · branch `main` · 6 file(s), +611 / −0*

- Added UPS lite 1.2 clone
- Create ups-api.service
- **Docs:** [UPS_INTEGRATION.md](UPS_INTEGRATION.md)

### 2026-08-14

#### [#593](https://github.com/PierreGode/Ragnar/pull/593) — Observatory: vendor Three.js so it loads under the hardening CSP
*Merged 2026-08-14 · branch `security/zap-hardening-headers` · 14 file(s), +55617 / −11*

- **Docs:** [SECURITY.md](SECURITY.md)

#### [#592](https://github.com/PierreGode/Ragnar/pull/592) — Mesh/share: confirm dialog dismisses on Confirm, not just Cancel
*Merged 2026-08-14 · branch `feature/mesh-secret` · 2 file(s), +9 / −3*

#### [#591](https://github.com/PierreGode/Ragnar/pull/591) — Mesh: add opt-in per-mesh secret as a second factor over the tag
*Merged 2026-08-14 · branch `feature/mesh-secret` · 7 file(s), +455 / −27*

- Mesh secret: default the Join form to Generate a new secret
- Mesh secret: add a Show mesh secret reveal for when the one-time display was missed
- Mesh secret: keep the generated key on screen, move armed note to the page bottom
- Mesh secret: download the generated key once, never show it in the UI
- Mesh secret: modal + auto-download together, refresh gated on Done
- Mesh/share: fix Copy on plain-HTTP Ragnars (non-secure context)
- **Docs:** [mesh.md](mesh.md)

### 2026-08-13

#### [#590](https://github.com/PierreGode/Ragnar/pull/590) — Mesh: share-only guest role (tag:ragnar-share)
*Merged 2026-08-13 · branch `feature/mesh-share-guest` · 10 file(s), +1573 / −79*

- Mesh Share: token-based remote shares (Ragnar<->Ragnar across tailnets)
- Mesh Share: one-click 'Join a tailnet (share-only)' from the web UI
- Mesh Share: share-only Join can switch tailnets (logout-first)
- docs: add detailed Mesh Share & File Transfer guide (docs/mesh-share.md)
- Mesh Share: share-only guest reads as 'share-only', not a mistagged mesh node
- Mesh Share: a share-only guest no longer sees the host mesh
- …and 9 more commit(s)
- **Docs:** [README (root)](../README.md), [mesh-share.md](mesh-share.md), [mesh.md](mesh.md)

#### [#589](https://github.com/PierreGode/Ragnar/pull/589) — Inbox Save: make the Vault option reflect the Vault's lock state
*Merged 2026-08-13 · branch `fix/inbox-vault-option` · 2 file(s), +25 / −3*

- Inbox: stop the 2s poll from wiping the destination dropdown

#### [#588](https://github.com/PierreGode/Ragnar/pull/588) — Fix: confirm dialog invisible when triggered from another tab
*Merged 2026-08-13 · branch `feature/files-nav-flag` · 2 file(s), +8 / −2*

### 2026-08-12

#### [#587](https://github.com/PierreGode/Ragnar/pull/587) — Flag the Files nav tab when a file is sent to this unit
*Merged 2026-08-12 · branch `feature/files-nav-flag` · 2 file(s), +70 / −2*

- Files nav flag: also cover shared-to-mesh + the mobile Files entry

#### [#586](https://github.com/PierreGode/Ragnar/pull/586) — Update nettools.md
*Merged 2026-08-12 · branch `PierreGode-patch-1` · 1 file(s), +2 / −1*

- **Docs:** [nettools.md](nettools.md)

#### [#584](https://github.com/PierreGode/Ragnar/pull/584) — Mesh transfer: stronger validation of transferred files
*Merged 2026-08-12 · branch `filshare` · 9 file(s), +706 / −17*

- File Management: move files/folders between folders
- Add Mesh Share — a folder published to the whole mesh
- Add a Mesh Share shortcut to the Files-tab Directories list
- **Docs:** [mesh.md](mesh.md), [vault.md](vault.md)

#### [#583](https://github.com/PierreGode/Ragnar/pull/583) — Fix mesh transfer failing with 'Invalid chunk header'
*Merged 2026-08-12 · branch `fix/mesh-transfer-chunked` · 2 file(s), +40 / −16*

#### [#582](https://github.com/PierreGode/Ragnar/pull/582) — Mesh file transfer: send files between Ragnar units over Tailscale
*Merged 2026-08-12 · branch `feature/mesh-file-transfer` · 7 file(s), +966 / −4*

- Mesh File Transfer: send a file already on this unit (Ragnar→Ragnar)
- Mesh transfer: show the failure reason inline + clearer send errors
- Mesh transfer picker: show the Vault when unlocked
- Fix: uploaded/deleted/cleared files not showing until manual refresh
- **Docs:** [mesh.md](mesh.md)

#### [#581](https://github.com/PierreGode/Ragnar/pull/581) — Rename Safe→Vault, add file/folder rename, Back/Up nav, MB/GB size input
*Merged 2026-08-12 · branch `feature/vault-rename-nav-rename` · 6 file(s), +352 / −129*

- Vault size: bring back the slider, show GB once past 999 MB
- **Docs:** [README (root)](../README.md), [vault.md](vault.md)

#### [#580](https://github.com/PierreGode/Ragnar/pull/580) — Add encrypted Safe vault to Files tab
*Merged 2026-08-12 · branch `feature/files-safe-vault` · 8 file(s), +1718 / −93*

- Make File Management tab mobile-friendly
- Add full-screen viewer for image previews
- Show unlocked Safe as a folder in Directories + Lock/Unlock button
- Fix: image full-screen viewer could not be closed on mobile
- Fix: image preview modal overflowed on phones, hiding the close button
- Add subfolders + upload-into-folder for Uploads and the Safe
- …and 5 more commit(s)
- **Docs:** [README (root)](../README.md)

### 2026-08-11

#### [#579](https://github.com/PierreGode/Ragnar/pull/579) — Fix AI endpoint scan crashing on Pi Zero (interpreter shutdown) (#462)
*Merged 2026-08-11 · branch `fix/ai-discover-threadpool-pizero` · 1 file(s), +70 / −16*

- Use safe thread pool for mesh update-all fan-out (#462)

#### [#578](https://github.com/PierreGode/Ragnar/pull/578) — Support self-hosted / OpenAI-compatible AI endpoints (#462)
*Merged 2026-08-11 · branch `feature/selfhosted-ai-462` · 7 file(s), +725 / −26*

- Add Connect + model dropdown for self-hosted AI endpoints (#462)
- Normalize self-hosted AI base URLs + port hint (#462)
- Adapt AI label to active model + cloud fallback on endpoint loss (#462)
- Add Scan Network: auto-discover Ollama on tailnet + local subnet (#462)
- Fix Scan Network button/badges stripped by Tailwind purge (#462)
- **Docs:** [README (root)](../README.md), [AI_INTEGRATION.md](AI_INTEGRATION.md)

#### [#577](https://github.com/PierreGode/Ragnar/pull/577) — Add per-host scan ignore-list button on the Network tab (#459)
*Merged 2026-08-11 · branch `feature/web-ignore-list-459` · 5 file(s), +181 / −13*

- Harden ignore-list client against non-JSON responses (#459)
- **Docs:** [README (root)](../README.md), [spec.md](spec.md)

#### [#576](https://github.com/PierreGode/Ragnar/pull/576) — Harden web server: security headers, no wildcard CORS, vendor CDN libs
*Merged 2026-08-11 · branch `security/zap-hardening-headers` · 15 file(s), +861 / −13*

- **Docs:** [SECURITY.md](SECURITY.md)

#### [#575](https://github.com/PierreGode/Ragnar/pull/575) — Update INSTALL.md
*Merged 2026-08-11 · branch `Solarflere-patch-2` · 1 file(s), +1 / −1*

- **Docs:** [INSTALL.md](INSTALL.md)

#### [#574](https://github.com/PierreGode/Ragnar/pull/574) — Update README.md
*Merged 2026-08-11 · branch `Solarflere-patch-1` · 1 file(s), +3 / −3*

- **Docs:** [README (root)](../README.md)

### 2026-08-10

#### [#573](https://github.com/PierreGode/Ragnar/pull/573) — UI: collapse main nav to hamburger by window size, wrap items to a second row
*Merged 2026-08-10 · branch `menu-responsive-wrap` · 2 file(s), +30 / −53*

- Fix: restore closing </script> tag dropped in nav-wrap cache-buster bump
- UI: move connection status dot under brand name, drop the text label
- UI: keep wrapping nav out of the brand-name area (logo shrink-0, nav flex-1/min-w-0)

#### [#572](https://github.com/PierreGode/Ragnar/pull/572) — Mesh: expand the Viking name pool with historic names
*Merged 2026-08-10 · branch `mesh-name-unnumbered-units` · 2 file(s), +106 / −14*

- Mesh: keep auto-derived names on the frozen legacy pool (no renames)
- **Docs:** [mesh.md](mesh.md)

#### [#571](https://github.com/PierreGode/Ragnar/pull/571) — Mesh: dice-roll a Viking name + gender choice for custom names
*Merged 2026-08-10 · branch `mesh-name-unnumbered-units` · 3 file(s), +206 / −10*

#### [#570](https://github.com/PierreGode/Ragnar/pull/570) — Mesh: name which reachable units have no unit number
*Merged 2026-08-10 · branch `mesh-name-unnumbered-units` · 4 file(s), +117 / −5*

- Mesh: let a joined unit set its number/identity after onboarding

### 2026-08-09

#### [#569](https://github.com/PierreGode/Ragnar/pull/569) — Power panel: reconcile under-voltage vs healthy estimated headroom
*Merged 2026-08-09 · branch `power-warning-dashboard` · 3 file(s), +17 / −2*

- **Docs:** [power.md](power.md)

#### [#568](https://github.com/PierreGode/Ragnar/pull/568) — Mark power_budget.py and mesh_scan.py executable (top-level .py = 755)
*Merged 2026-08-09 · branch `power-warning-dashboard` · 2 file(s), +0 / −0*

#### [#567](https://github.com/PierreGode/Ragnar/pull/567) — Dashboard power badge: surface real under-voltage on the main dashboard
*Merged 2026-08-09 · branch `power-warning-dashboard` · 7 file(s), +711 / −8*

- Power badge: add always-on Power card + detail panel to the System tab
- **Docs:** [README (root)](../README.md), [diagnostics.md](diagnostics.md), [power.md](power.md)

#### [#566](https://github.com/PierreGode/Ragnar/pull/566) — AI insights: never wedge on "Analyzing…" — always resolve to data or retry
*Merged 2026-08-09 · branch `fix-ai-insights-background-compute` · 4 file(s), +75 / −36*

- AI insights: run analyses sequentially in the background (tiny-board safe)

#### [#565](https://github.com/PierreGode/Ragnar/pull/565) — Dashboard AI insights: compute in background so slow boards never block
*Merged 2026-08-09 · branch `fix-ai-insights-background-compute` · 4 file(s), +148 / −66*

- **Docs:** [AI_INTEGRATION.md](AI_INTEGRATION.md)

#### [#564](https://github.com/PierreGode/Ragnar/pull/564) — Dashboard AI insights: survive shared-key rate limits + per-call timeout
*Merged 2026-08-09 · branch `fix-ai-insights-shared-key-resilience` · 4 file(s), +68 / −19*

- **Docs:** [AI_INTEGRATION.md](AI_INTEGRATION.md)

#### [#563](https://github.com/PierreGode/Ragnar/pull/563) — Dashboard AI insights: parallelize calls + stop silent hang
*Merged 2026-08-09 · branch `fix-dashboard-ai-insights-latency` · 4 file(s), +62 / −21*

- **Docs:** [AI_INTEGRATION.md](AI_INTEGRATION.md)

#### [#562](https://github.com/PierreGode/Ragnar/pull/562) — WiFi Analyzer: fix Report button ignoring Bluetooth/Zigbee + AI
*Merged 2026-08-09 · branch `fix-wifi-report-bt-ai-shadow` · 2 file(s), +88 / −12*

- Bump ragnar_modern.js cache-bust for WiFi report BT/AI fix

#### [#561](https://github.com/PierreGode/Ragnar/pull/561) — Adv Scan: ZAP auto-resolves a live web port for bare-host targets
*Merged 2026-08-09 · branch `zap-target-port-autoresolve` · 3 file(s), +188 / −1*

- **Docs:** [README (root)](../README.md)

#### [#560](https://github.com/PierreGode/Ragnar/pull/560) — WiFi Analyzer: fold BT/Zigbee 2.4 GHz overlays into AI + spectrum report
*Merged 2026-08-09 · branch `ai-bt-zigbee-coexistence` · 9 file(s), +590 / −27*

- WiFi Defense: unified AI read across all 3 modules + report inclusion
- **Docs:** [AI_INTEGRATION.md](AI_INTEGRATION.md), [wifi-analyzer.md](wifi-analyzer.md), [wifi-defense.md](wifi-defense.md)

#### [#559](https://github.com/PierreGode/Ragnar/pull/559) — Adv Scan: explain the default port in connect-failure error
*Merged 2026-08-09 · branch `zap-delegate-tunnel` · 8 file(s), +220 / −10*

- Recon: add web-port discovery + operator-selectable ports for ZAP handoff
- **Docs:** [README (root)](../README.md), [superpowers/specs/2026-05-27-web-recon-subsystem-design.md](superpowers/specs/2026-05-27-web-recon-subsystem-design.md)

#### [#558](https://github.com/PierreGode/Ragnar/pull/558) — Adv Scan: show scan egress (tunnel vs LAN) — confirms ZAP tunnels too
*Merged 2026-08-09 · branch `zap-delegate-tunnel` · 2 file(s), +47 / −12*

- Adv Scan: clear error for invalid dotted-quad targets (712.20.10.1)
- Adv Scan: accept uppercase URL schemes (HTTP:// / Http://)
- Adv Scan: auto-add http scheme for bare IPs; drop ZAP's default :80 from host

#### [#557](https://github.com/PierreGode/Ragnar/pull/557) — Adv Scan: show scan egress (tunnel vs LAN) — confirms ZAP tunnels too
*Merged 2026-08-09 · branch `zap-delegate-tunnel` · 4 file(s), +57 / −5*

### 2026-08-05

#### [#555](https://github.com/PierreGode/Ragnar/pull/555) — config: export/import settings for fleet deployment
*Merged 2026-08-05 · branch `config-export-import` · 5 file(s), +294 / −6*

- config: fix export download on iOS Safari
- **Docs:** [README (root)](../README.md), [mesh.md](mesh.md)

#### [#554](https://github.com/PierreGode/Ragnar/pull/554) — mesh: add Update mesh card to fan the git update across the fleet
*Merged 2026-08-05 · branch `mesh-fleet-update` · 4 file(s), +359 / −4*

- mesh: show available-unit and pending-update counts on Update mesh card
- **Docs:** [mesh.md](mesh.md)

#### [#553](https://github.com/PierreGode/Ragnar/pull/553) — install: add Firefox as a required package (ZAP AJAX spider)
*Merged 2026-08-05 · branch `install-require-firefox` · 2 file(s), +21 / −0*

#### [#552](https://github.com/PierreGode/Ragnar/pull/552) — advtools: install nikto via git fallback when apt lacks it (Debian non-free)
*Merged 2026-08-05 · branch `advtools-nikto-debian-fallback` · 3 file(s), +145 / −2*

- **Docs:** [INSTALL.md](INSTALL.md)

### 2026-08-04

#### [#550](https://github.com/PierreGode/Ragnar/pull/550) — Mesh: enable IP forwarding when advertising subnet routes
*Merged 2026-08-04 · branch `advscan-unhide-zap-gate` · 3 file(s), +73 / −3*

#### [#549](https://github.com/PierreGode/Ragnar/pull/549) — RuSense flasher: fix u.FL antenna checkbox overflow on mobile
*Merged 2026-08-04 · branch `advscan-unhide-zap-gate` · 1 file(s), +10 / −3*

#### [#548](https://github.com/PierreGode/Ragnar/pull/548) — Displays: show the mesh Viking name in the header (abbreviated + fit)
*Merged 2026-08-04 · branch `advscan-unhide-zap-gate` · 5 file(s), +106 / −14*

- espnow bridge: select XIAO ESP32-C6 external u.FL antenna
- RuSense flasher: external u.FL antenna checkbox (XIAO ESP32-C6)
- RuSense flasher: add legal/ethical monitoring notice

#### [#547](https://github.com/PierreGode/Ragnar/pull/547) — Adv Scan: show tab on any board, gate only OWASP ZAP on 8GB RAM
*Merged 2026-08-04 · branch `advscan-unhide-zap-gate` · 21 file(s), +1962 / −143*

- Adv Scan: fix whole-form grey-out, add on-demand nuclei install
- Adv Scan: make the nuclei Install a real, always-visible button
- Adv Scan: show nuclei template download progress after install
- Recon engine: run on any board, drop the server-mode gate
- Adv Scan: relabel recon handoff "to scan" (not ZAP-specific)
- Nuclei: auto-download templates when installed but missing
- …and 18 more commit(s)
- **Docs:** [README (root)](../README.md), [PWNAGOTCHI.md](PWNAGOTCHI.md), [grade.md](grade.md)

### 2026-08-03

#### [#546](https://github.com/PierreGode/Ragnar/pull/546) — homeassistant: organise device card via entity categories
*Merged 2026-08-03 · branch `ha-card-organization` · 2 file(s), +51 / −4*

- homeassistant: revert diagnostic entity categories so all entities stay visible
- **Docs:** [homeassistant.md](homeassistant.md)

#### [#545](https://github.com/PierreGode/Ragnar/pull/545) — homeassistant: add connectivity + mesh-fleet-health entities
*Merged 2026-08-03 · branch `ha-phase2-defense-connectivity` · 9 file(s), +179 / −7*

- **Docs:** [README (root)](../README.md), [homeassistant.md](homeassistant.md)

#### [#544](https://github.com/PierreGode/Ragnar/pull/544) — homeassistant: add HACS custom integration for RuSense + security alerts
*Merged 2026-08-03 · branch `homeassistant-integration` · 17 file(s), +1097 / −0*

- homeassistant: import DeviceInfo from device_registry (fixes setup crash)
- docs: add Home Assistant integration guide (docs/homeassistant.md)
- **Docs:** [README (root)](../README.md), [homeassistant.md](homeassistant.md)

#### [#543](https://github.com/PierreGode/Ragnar/pull/543) — pwnagotchi: install undeclared prctl dep so the service stops exit-code looping
*Merged 2026-08-03 · branch `pwn-reinstall-service-fix` · 3 file(s), +31 / −11*

- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

#### [#542](https://github.com/PierreGode/Ragnar/pull/542) — pwnagotchi: verify runtime before claiming reinstall success
*Merged 2026-08-03 · branch `pwn-reinstall-service-fix` · 3 file(s), +120 / −2*

- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

### 2026-08-02

#### [#541](https://github.com/PierreGode/Ragnar/pull/541) — PCAP monitor capture: channel-hop by default for a real survey
*Merged 2026-08-02 · branch `pcap-monitor-channel-hop` · 4 file(s), +53 / −13*

- **Docs:** [nettools.md](nettools.md)

#### [#540](https://github.com/PierreGode/Ragnar/pull/540) — PCAP capture: show 'Analyzing…' after the window + grey out monitor when unsupported
*Merged 2026-08-02 · branch `pcap-capture-ui-polish` · 2 file(s), +40 / −1*

#### [#539](https://github.com/PierreGode/Ragnar/pull/539) — PCAP capture: add Wi-Fi monitor-mode (802.11) capture
*Merged 2026-08-02 · branch `pcap-monitor-mode` · 4 file(s), +100 / −22*

- **Docs:** [nettools.md](nettools.md)

#### [#538](https://github.com/PierreGode/Ragnar/pull/538) — PCAP capture: explain 0-packet Wi-Fi captures accurately
*Merged 2026-08-02 · branch `pcap-zero-packet-wifi-note` · 1 file(s), +40 / −3*

#### [#537](https://github.com/PierreGode/Ragnar/pull/537) — PCAP: fix 500 on capture — expert loop clobbered the summary dict
*Merged 2026-08-02 · branch `pcap-summary-clobber-fix` · 1 file(s), +3 / −3*

#### [#536](https://github.com/PierreGode/Ragnar/pull/536) — PCAP AI: calibrate severity to volume; drop normal TCP teardown noise
*Merged 2026-08-02 · branch `pcap-ai-calibration` · 2 file(s), +35 / −13*

#### [#535](https://github.com/PierreGode/Ragnar/pull/535) — PCAP capture: robust Auto interface (LAN > USB LAN > wlan1 > wlan0)
*Merged 2026-08-02 · branch `pcap-auto-iface-fallback` · 2 file(s), +60 / −8*

- **Docs:** [nettools.md](nettools.md)

#### [#534](https://github.com/PierreGode/Ragnar/pull/534) — PCAP Analyzer: capture interface picker now matches the L2/L3 selectors
*Merged 2026-08-02 · branch `pcap-iface-static` · 4 file(s), +40 / −18*

- **Docs:** [nettools.md](nettools.md)

#### [#533](https://github.com/PierreGode/Ragnar/pull/533) — PCAP AI: instruct model to use only valid Wireshark filter syntax
*Merged 2026-08-02 · branch `pcap-ai-valid-filters` · 1 file(s), +5 / −1*

#### [#532](https://github.com/PierreGode/Ragnar/pull/532) — PCAP Analyzer: match capture interface selector to ARP scan styling
*Merged 2026-08-02 · branch `pcap-iface-selector` · 2 file(s), +3 / −3*

#### [#531](https://github.com/PierreGode/Ragnar/pull/531) — PCAP Analyzer: include AI analysis in the PDF report
*Merged 2026-08-02 · branch `pcap-pdf-ai-summary` · 3 file(s), +36 / −4*

- PCAP Analyzer: rename PDF 'AI analysis' section to 'Analysis'
- **Docs:** [nettools.md](nettools.md)

#### [#530](https://github.com/PierreGode/Ragnar/pull/530) — PCAP Analyzer: add Export as PDF report
*Merged 2026-08-02 · branch `pcap-export-pdf` · 3 file(s), +100 / −3*

- **Docs:** [nettools.md](nettools.md)

#### [#529](https://github.com/PierreGode/Ragnar/pull/529) — PCAP Analyzer: move card up to sit below ARP Scan
*Merged 2026-08-02 · branch `pcap-reorder-below-arp` · 1 file(s), +16 / −16*

#### [#528](https://github.com/PierreGode/Ragnar/pull/528) — PCAP Analyzer: browse stored captures + capture live traffic
*Merged 2026-08-02 · branch `pcap-capture-and-browse` · 5 file(s), +394 / −46*

- PCAP Analyzer: make the stored-pcap list mobile-friendly
- PCAP Analyzer: make Protocol hierarchy mobile-friendly
- **Docs:** [nettools.md](nettools.md)

#### [#527](https://github.com/PierreGode/Ragnar/pull/527) — pcap ai: generalize root-cause analysis beyond Wi-Fi client-drops
*Merged 2026-08-02 · branch `pcap-ai-analysis` · 2 file(s), +47 / −19*

- **Docs:** [nettools.md](nettools.md)

#### [#526](https://github.com/PierreGode/Ragnar/pull/526) — sdr: fix Waterfall not activating — probe HackRF once, handle probe timeout
*Merged 2026-08-02 · branch `sdr-hackrf-not-activating` · 1 file(s), +20 / −5*

### 2026-08-01

#### [#525](https://github.com/PierreGode/Ragnar/pull/525) — lcd144: netsignal card — strongest SSID on top, shorter signal bar
*Merged 2026-08-01 · branch `lcd144-netsignal-tweaks` · 1 file(s), +9 / −1*

#### [#524](https://github.com/PierreGode/Ragnar/pull/524) — rusense: fix #503 node time-sync — report Pi arrival-time alignment
*Merged 2026-08-01 · branch `fix-503-node-sync` · 6 file(s), +75 / −11*

- **Docs:** [rusense.md](rusense.md)

### 2026-07-31

#### [#523](https://github.com/PierreGode/Ragnar/pull/523) — wardriving: add printable Wi-Fi survey report export (HTML→PDF)
*Merged 2026-07-31 · branch `feature-report-export` · 10 file(s), +867 / −6*

- reports: add printable WIDS + spectrum reports; share one report engine
- **Docs:** [README (root)](../README.md), [wardriving.md](wardriving.md), [wifi-analyzer.md](wifi-analyzer.md), [wifi-defense.md](wifi-defense.md)

#### [#522](https://github.com/PierreGode/Ragnar/pull/522) — wardriving: switch display to wardriving mode on manual start (starting state)
*Merged 2026-07-31 · branch `fix-wardriving-display-mode` · 3 file(s), +67 / −8*

- **Docs:** [wardriving.md](wardriving.md)

#### [#521](https://github.com/PierreGode/Ragnar/pull/521) — pwnagotchi: harden clean reinstall (keep config, ignore-installed pydrive2)
*Merged 2026-07-31 · branch `pwn-install-healthcheck` · 4 file(s), +32 / −13*

- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

#### [#520](https://github.com/PierreGode/Ragnar/pull/520) — pwnagotchi: self-heal a status stuck at 'installing' when the install is healthy
*Merged 2026-07-31 · branch `pwn-install-healthcheck` · 5 file(s), +118 / −13*

- pwnagotchi: add always-available Reinstall (clean) button
- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

#### [#519](https://github.com/PierreGode/Ragnar/pull/519) — pwnagotchi: require stable portal readiness before offering the swap link
*Merged 2026-07-31 · branch `pwn-install-healthcheck` · 5 file(s), +249 / −22*

- pwnagotchi: add ragnar_return web plugin to redirect the browser back to :8000
- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

#### [#518](https://github.com/PierreGode/Ragnar/pull/518) — pwnagotchi: validate install components + Repair button; disable pwn self-updater
*Merged 2026-07-31 · branch `pwn-install-healthcheck` · 5 file(s), +260 / −6*

- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

### 2026-07-30

#### [#517](https://github.com/PierreGode/Ragnar/pull/517) — wifi-defense: harden legacy PHY/airtime accuracy + add WPS posture detection
*Merged 2026-07-30 · branch `investigate/legacy-wps-watch` · 29 file(s), +3791 / −99*

- legacywatch: standalone passive 802.11 legacy/cipher/airtime detector
- wpswatch: standalone passive WPS/WSC posture + EAP-WSC attack detector
- legacywatch/wpswatch: Watchtower wiring, systemd units, conformance + hwsim lab
- wifi-defense: make Airtime & link-quality tables mobile-friendly
- wifi-defense: per-panel wlan* interface selector for Airtime + Isolation
- wifi-defense: fix per-panel iface dropdown hiding USB/PCI wireless adapters
- …and 2 more commit(s)
- **Docs:** [README (root)](../README.md), [AI_INTEGRATION.md](AI_INTEGRATION.md), [RELEASE_NOTES.md](RELEASE_NOTES.md), [legacywatch.md](legacywatch.md), [spec.md](spec.md), [wifi-defense.md](wifi-defense.md), [wpswatch.md](wpswatch.md)

#### [#516](https://github.com/PierreGode/Ragnar/pull/516) — wifi-defense: pinpoint 2.4 GHz airtime starvation (legacy 802.11b client tax)
*Merged 2026-07-30 · branch `investigate/airtime-starvation-detection` · 5 file(s), +570 / −16*

- wifi-defense: add per-AP encryption + 802.11 generation to airtime panel
- wifi-defense: name the legacy client — fuse radio PHY with host inventory
- wifi-defense: add SSID column + SSID filter to per-client airtime table
- wifi-defense: bump backend _BUILD to match UI (20260729-airtime-ssid-filter)
- **Docs:** [wifi-defense.md](wifi-defense.md)

### 2026-07-29

#### [#515](https://github.com/PierreGode/Ragnar/pull/515) — display: add 3.5" SPI TFT (ILI9486/ILI9488) driver support
*Merged 2026-07-29 · branch `investigate/display-tft-epaper` · 7 file(s), +442 / −30*

- **Docs:** [README (root)](../README.md), [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#514](https://github.com/PierreGode/Ragnar/pull/514) — Remove Ragnar mobile app section from README
*Merged 2026-07-29 · branch `PierreGode-patch-6` · 1 file(s), +0 / −7*

- **Docs:** [README (root)](../README.md)

#### [#513](https://github.com/PierreGode/Ragnar/pull/513) — Update image in nettools documentation
*Merged 2026-07-29 · branch `PierreGode-matrix` · 1 file(s), +2 / −1*

- **Docs:** [nettools.md](nettools.md)

### 2026-07-28

#### [#512](https://github.com/PierreGode/Ragnar/pull/512) — web: hide the Bluetooth Provisioning settings section
*Merged 2026-07-28 · branch `chore/hide-ble-provisioning` · 1 file(s), +6 / −2*

#### [#511](https://github.com/PierreGode/Ragnar/pull/511) — docs: mobile app connects over the mesh, not Bluetooth
*Merged 2026-07-28 · branch `feat/ragnarmobile-tailscale` · 3 file(s), +53 / −10*

- docs: mobile app discovers the mesh via /api/mesh/status, no token
- **Docs:** [README (root)](../README.md), [ble_provisioning.md](ble_provisioning.md), [mesh.md](mesh.md)

### 2026-07-27

#### [#510](https://github.com/PierreGode/Ragnar/pull/510) — Fix Discord badge link in README
*Merged 2026-07-27 · branch `PierreGode-patch-5` · 1 file(s), +1 / −1*

- **Docs:** [README (root)](../README.md)

#### [#509](https://github.com/PierreGode/Ragnar/pull/509) — Discord
*Merged 2026-07-27 · branch `PierreGode-patch-4` · 1 file(s), +1 / −0*

- Update README.md
- **Docs:** [README (root)](../README.md)

#### [#508](https://github.com/PierreGode/Ragnar/pull/508) — Add Ragnar Mesh: a controller-free unit mesh over Tailscale
*Merged 2026-07-27 · branch `feat/tailscale-fleet` · 14 file(s), +6025 / −13*

- Fix mesh serve hanging when tailnet HTTPS certs are disabled
- Make HTTP the default mesh publish path, HTTPS opt-in
- Add a self-service "Install Tailscale" button to the Mesh tab
- Diagnose "on the tailnet but not in the mesh" in the Mesh tab
- Fix false "Ragnar not answering"; one-click enable data sharing
- Add a Diagnose probe that names why a mesh peer is degraded
- …and 26 more commit(s)
- **Docs:** [README (root)](../README.md), [mesh.md](mesh.md)

### 2026-07-26

#### [#507](https://github.com/PierreGode/Ragnar/pull/507) — Only record a listening port a host actually served from
*Merged 2026-07-26 · branch `fix-passive-listening-ports` · 5 file(s), +459 / −29*

- **Docs:** [traffic-analysis.md](traffic-analysis.md)

#### [#506](https://github.com/PierreGode/Ragnar/pull/506) — Make Traffic Analysis available on every board, not just servers
*Merged 2026-07-26 · branch `traffic-analysis-everywhere` · 11 file(s), +641 / −60*

- **Docs:** [README (root)](../README.md), [grade.md](grade.md), [traffic-analysis.md](traffic-analysis.md)

#### [#505](https://github.com/PierreGode/Ragnar/pull/505) — Make the on-screen kiosk a Ragnar Pi server feature
*Merged 2026-07-26 · branch `kiosk-server-only` · 9 file(s), +358 / −24*

- **Docs:** [README (root)](../README.md), [kiosk.md](kiosk.md)

#### [#504](https://github.com/PierreGode/Ragnar/pull/504) — ip_intel: attribute a hostile IP — country, ASN, network owner, abuse contact
*Merged 2026-07-26 · branch `isp` · 8 file(s), +844 / −1*

- fix(ui): restore Whois to its grid position
- Update ip_intel.py
- Add 'allocated' field and update confidence scoring
- Fix allocation assignment in ip_intel.py
- Update ragnar_modern.js
- Update index_modern.html
- …and 5 more commit(s)
- **Docs:** [ip-intel.md](ip-intel.md), [nettools.md](nettools.md)

#### [#501](https://github.com/PierreGode/Ragnar/pull/501) — Kiosk: find the Xorg log, and tell a live kiosk from a dead one
*Merged 2026-07-26 · branch `fix/kiosk-mode` · 3 file(s), +72 / −14*

- **Docs:** [kiosk.md](kiosk.md)

#### [#500](https://github.com/PierreGode/Ragnar/pull/500) — Give the kiosk somewhere real to look when it shows nothing
*Merged 2026-07-26 · branch `fix/kiosk-mode` · 7 file(s), +467 / −93*

- Make the kiosk toggle do what running the installer by hand does
- Kiosk service mode: stop passing Xorg a flag it refuses
- **Docs:** [kiosk.md](kiosk.md)

#### [#499](https://github.com/PierreGode/Ragnar/pull/499) — Stop the update card sticking on "Finishing update: network tools..."
*Merged 2026-07-26 · branch `fix/update-robustness` · 4 file(s), +106 / −7*

- **Docs:** [updates.md](updates.md)

#### [#498](https://github.com/PierreGode/Ragnar/pull/498) — Stop fresh installs from reporting "Needs attention"
*Merged 2026-07-26 · branch `fix/update-robustness` · 6 file(s), +204 / −27*

- **Docs:** [INSTALL.md](INSTALL.md), [updates.md](updates.md)

#### [#497](https://github.com/PierreGode/Ragnar/pull/497) — Update year in license statement to 2025
*Merged 2026-07-26 · branch `PierreGode-patch-3` · 1 file(s), +1 / −1*

- **Docs:** [INSTALL.md](INSTALL.md)

#### [#496](https://github.com/PierreGode/Ragnar/pull/496) — Fix license year in README.md
*Merged 2026-07-26 · branch `PierreGode-patch-2` · 1 file(s), +1 / −1*

- **Docs:** [README (root)](../README.md)

#### [#495](https://github.com/PierreGode/Ragnar/pull/495) — Make the in-app update rock solid instead of "error"
*Merged 2026-07-26 · branch `fix/update-robustness` · 10 file(s), +2283 / −889*

- Remove empty line in README.md
- **Docs:** [README (root)](../README.md), [INSTALL.md](INSTALL.md), [updates.md](updates.md)

### 2026-07-25

#### [#494](https://github.com/PierreGode/Ragnar/pull/494) — WiFi analyzer: make the spectrum readable at full size
*Merged 2026-07-25 · branch `fullspectrum` · 4 file(s), +961 / −85*

- **Docs:** [README (root)](../README.md), [wifi-analyzer.md](wifi-analyzer.md)

#### [#493](https://github.com/PierreGode/Ragnar/pull/493) — BT overlay: scan the controller we chose, not a cold-start stand-in
*Merged 2026-07-25 · branch `fix/ble-adv-register-failed` · 3 file(s), +90 / −5*

- **Docs:** [wifi-analyzer.md](wifi-analyzer.md)

#### [#492](https://github.com/PierreGode/Ragnar/pull/492) — BLE provisioning: confirm Invalid Parameters is the controller, not us
*Merged 2026-07-25 · branch `fix/ble-adv-register-failed` · 3 file(s), +116 / −4*

- **Docs:** [ble_provisioning.md](ble_provisioning.md)

#### [#491](https://github.com/PierreGode/Ragnar/pull/491) — BLE provisioning: name the real reason a controller refuses to advertise
*Merged 2026-07-25 · branch `fix/ble-adv-register-failed` · 3 file(s), +528 / −31*

- BLE provisioning: detect the raw-HCI scan BlueZ can't see
- **Docs:** [ble_provisioning.md](ble_provisioning.md)

#### [#490](https://github.com/PierreGode/Ragnar/pull/490) — BLE provisioning: survive a controller that refuses the advertisement
*Merged 2026-07-25 · branch `fix/ble-adv-register-failed` · 5 file(s), +452 / −23*

- **Docs:** [ble_provisioning.md](ble_provisioning.md)

#### [#489](https://github.com/PierreGode/Ragnar/pull/489) — Serve the dashboard, not the captive portal, on a 192.168.4.0/24 LAN
*Merged 2026-07-25 · branch `fix/wifi-portal-blocks-dashboard` · 5 file(s), +501 / −33*

- AP fallback: honour diagnostic mode, and fix the reconnect cadence
- AP recovery: gate on connected clients, not on a 3-minute clock
- Keep the setup AP up instead of flapping it every 3 minutes
- Split AP and client across radios when a Wi-Fi dongle is present
- Document AP mode in docs/RagnarAP.md
- **Docs:** [README (root)](../README.md), [INSTALL.md](INSTALL.md), [RagnarAP.md](RagnarAP.md)

#### [#488](https://github.com/PierreGode/Ragnar/pull/488) — Kiosk: add a doctor, and stop crash-looping against a running X server
*Merged 2026-07-25 · branch `fix/kiosk-doctor` · 4 file(s), +276 / −1*

- **Docs:** [kiosk.md](kiosk.md)

#### [#487](https://github.com/PierreGode/Ragnar/pull/487) — BLE provisioning: fix the leak behind RegisterApplication AlreadyExists
*Merged 2026-07-25 · branch `fix/ble-already-exists` · 3 file(s), +92 / −4*

- **Docs:** [ble_provisioning.md](ble_provisioning.md)

#### [#486](https://github.com/PierreGode/Ragnar/pull/486) — Kiosk: stop calling a slow install a failure, and report the real error
*Merged 2026-07-25 · branch `fix/kiosk-install-progress` · 4 file(s), +106 / −3*

- **Docs:** [kiosk.md](kiosk.md)

#### [#485](https://github.com/PierreGode/Ragnar/pull/485) — Install display support for every screen, not just the one selected
*Merged 2026-07-25 · branch `fix/installer-repairs-tarball-install` · 8 file(s), +399 / −90*

- Offer every supported screen in the installer menus
- Fix the two package failures a fresh install actually reports
- Repair an interrupted dpkg state instead of failing on it
- BLE provisioning: stop reporting a slow start as a permanent 'Enabling...'
- **Docs:** [INSTALL.md](INSTALL.md), [ble_provisioning.md](ble_provisioning.md)

#### [#484](https://github.com/PierreGode/Ragnar/pull/484) — Installer: repair a tarball install instead of skipping it
*Merged 2026-07-25 · branch `fix/installer-repairs-tarball-install` · 2 file(s), +38 / −3*

- **Docs:** [INSTALL.md](INSTALL.md)

#### [#483](https://github.com/PierreGode/Ragnar/pull/483) — Installer: don't fail a fresh install over optional security tools
*Merged 2026-07-25 · branch `fix/install-package-resilience` · 4 file(s), +212 / −25*

- Installer: stop a broken git from wrecking the install layout
- **Docs:** [INSTALL.md](INSTALL.md), [ble_provisioning.md](ble_provisioning.md)

### 2026-07-24

#### [#482](https://github.com/PierreGode/Ragnar/pull/482) — BLE provisioning: add a 'doctor' command to diagnose why it won't advertise
*Merged 2026-07-24 · branch `feat/ble-provisioning-doctor` · 1 file(s), +70 / −0*

#### [#481](https://github.com/PierreGode/Ragnar/pull/481) — BLE provisioning: surface an under-voltage warning
*Merged 2026-07-24 · branch `feat/license-provenance` · 3 file(s), +29 / −0*

#### [#480](https://github.com/PierreGode/Ragnar/pull/480) — Ble
*Merged 2026-07-24 · branch `feat/license-provenance` · 1 file(s), +21 / −10*

- BLE provisioning: actionable error when python3-gi is missing
- BLE provisioning: stop exposing the hostname over Classic Bluetooth

#### [#479](https://github.com/PierreGode/Ragnar/pull/479) — Mob
*Merged 2026-07-24 · branch `feat/license-provenance` · 3 file(s), +165 / −2*

- License restrictions, embedded authorship, and origin verification

#### [#477](https://github.com/PierreGode/Ragnar/pull/477) — BLE provisioning: web-config toggle + adapter picker, prefer built-in radio
*Merged 2026-07-24 · branch `feat/ble-provisioning-config` · 5 file(s), +342 / −17*

- BLE provisioning: auto-stop after provisioning to free the adapter
- **Docs:** [ble_provisioning.md](ble_provisioning.md)

#### [#476](https://github.com/PierreGode/Ragnar/pull/476) — README: mention the mobile app and BLE provisioning
*Merged 2026-07-24 · branch `feat/ble-provisioning` · 1 file(s), +7 / −0*

- **Docs:** [README (root)](../README.md)

#### [#475](https://github.com/PierreGode/Ragnar/pull/475) — Add BLE provisioning peripheral for the mobile app
*Merged 2026-07-24 · branch `feat/ble-provisioning` · 5 file(s), +912 / −4*

- **Docs:** [ble_provisioning.md](ble_provisioning.md)

#### [#473](https://github.com/PierreGode/Ragnar/pull/473) — Net-diag LCD: add BT and ZIGBEE scan cards to the 1.44" HAT
*Merged 2026-07-24 · branch `netdiag-bt-zigbee-cards` · 5 file(s), +214 / −19*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [nettools.md](nettools.md)

### 2026-07-23

#### [#472](https://github.com/PierreGode/Ragnar/pull/472) — Wardriving LCD: add GPS SKY VIEW as a paged screen on the 1.44" HAT
*Merged 2026-07-23 · branch `wardrive-lcd-skyview` · 5 file(s), +95 / −12*

- **Docs:** [README (root)](../README.md), [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#471](https://github.com/PierreGode/Ragnar/pull/471) — Wardriving and On-Screen Network Diagnostic mode are mutually exclusive
*Merged 2026-07-23 · branch `wardrive-netdiag-exclusive` · 4 file(s), +64 / −0*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [wardriving.md](wardriving.md)

#### [#470](https://github.com/PierreGode/Ragnar/pull/470) — WiFi Analyzer: auto-refresh also re-runs BT + Zigbee overlays
*Merged 2026-07-23 · branch `bluespectrum` · 2 file(s), +13 / −3*

#### [#468](https://github.com/PierreGode/Ragnar/pull/468) — WiFi Analyzer: Zigbee/802.15.4 overlay via on-demand HuginnESP sniff
*Merged 2026-07-23 · branch `bluespectrum` · 7 file(s), +846 / −3*

- **Docs:** [README (root)](../README.md), [wifi-analyzer.md](wifi-analyzer.md)

#### [#467](https://github.com/PierreGode/Ragnar/pull/467) — WiFi Analyzer: Bluetooth/BLE 2.4 GHz interference overlay
*Merged 2026-07-23 · branch `bluespectrum` · 9 file(s), +1929 / −8*

- WiFi Analyzer: make Bluetooth device rows selectable on the spectrum
- WiFi Analyzer: true-RF Waterfall view via HackRF SDR
- WiFi Analyzer: clearer disabled Waterfall button on mobile
- **Docs:** [README (root)](../README.md), [wifi-analyzer.md](wifi-analyzer.md)

### 2026-07-22

#### [#466](https://github.com/PierreGode/Ragnar/pull/466) — Wardriving: per-Huginn role switch (WiFi+BLE vs Zigbee/Thread-only)
*Merged 2026-07-22 · branch `wardrive-companion-role-switch` · 5 file(s), +139 / −19*

- Wardriving UI: role-aware companion stats (2.4/5/BLE vs Zigbee)
- **Docs:** [wardriving.md](wardriving.md)

#### [#465](https://github.com/PierreGode/Ragnar/pull/465) — Wardriving: classify Thread vs Zigbee (proto) and rename the card
*Merged 2026-07-22 · branch `wardrive-thread-zigbee-proto` · 5 file(s), +52 / −22*

- **Docs:** [wardriving.md](wardriving.md)

#### [#464](https://github.com/PierreGode/Ragnar/pull/464) — Wardriving: show companion mode as 'wardrive', not stuck 'ble-all'
*Merged 2026-07-22 · branch `wardrive-companion-mode-label` · 1 file(s), +13 / −2*

#### [#463](https://github.com/PierreGode/Ragnar/pull/463) — Wardriving: opt-in to include Zigbee in WiGLE CSV export
*Merged 2026-07-22 · branch `wardrive-web-zigbee-counts` · 5 file(s), +48 / −5*

- **Docs:** [wardriving.md](wardriving.md)

#### [#461](https://github.com/PierreGode/Ragnar/pull/461) — Wardriving web: surface Zigbee/802.15.4 counts on both pages
*Merged 2026-07-22 · branch `wardrive-web-zigbee-counts` · 4 file(s), +75 / −3*

- **Docs:** [wardriving.md](wardriving.md)

#### [#460](https://github.com/PierreGode/Ragnar/pull/460) — Wardriving: count and store Zigbee/802.15.4 devices from Huginn
*Merged 2026-07-22 · branch `claude/huginn-zigbee-support-y7ntke` · 4 file(s), +230 / −5*

- **Docs:** [wardriving.md](wardriving.md)

### 2026-07-21

#### [#458](https://github.com/PierreGode/Ragnar/pull/458) — Diagnostics: explain 'tracking N satellites but no fix'
*Merged 2026-07-21 · branch `gps-nofix-hint` · 2 file(s), +31 / −0*

- **Docs:** [diagnostics.md](diagnostics.md)

#### [#457](https://github.com/PierreGode/Ragnar/pull/457) — Wardriving: hot-plug WiFi adapters mid-session, no restart needed
*Merged 2026-07-21 · branch `wardriving-hotplug-iface` · 2 file(s), +83 / −4*

- **Docs:** [wardriving.md](wardriving.md)

#### [#456](https://github.com/PierreGode/Ragnar/pull/456) — Wardriving phone-AP: run on the built-in radio, not the Alfa
*Merged 2026-07-21 · branch `wardriving-ap-alfa` · 2 file(s), +57 / −3*

#### [#455](https://github.com/PierreGode/Ragnar/pull/455) — GPS sky view: make the fullscreen view actually live (1 Hz, uncached)
*Merged 2026-07-21 · branch `gps-sky-view` · 6 file(s), +51 / −11*

- **Docs:** [diagnostics.md](diagnostics.md)

#### [#454](https://github.com/PierreGode/Ragnar/pull/454) — GPS sky view: fullscreen planetarium with real starfield
*Merged 2026-07-21 · branch `gps-sky-view` · 9 file(s), +566 / −14*

- GPS sky view: persist last-known position, use it before a fix
- GPS sky view: populate constellations + sky view on the gpsd path
- GPS: stop DOP-only gpsd SKY reports from zeroing satellite counts
- **Docs:** [README (root)](../README.md), [diagnostics.md](diagnostics.md)

#### [#453](https://github.com/PierreGode/Ragnar/pull/453) — docs: add Diagnostics panel guide, move cell.md into docs/
*Merged 2026-07-21 · branch `gps-sky-view` · 4 file(s), +166 / −1*

- **Docs:** [README (root)](../README.md), [cell.md](cell.md), [diagnostics.md](diagnostics.md), [wardriving.md](wardriving.md)

#### [#452](https://github.com/PierreGode/Ragnar/pull/452) — Wardriving GPS sky view: per-satellite azimuth/elevation polar plot
*Merged 2026-07-21 · branch `gps-sky-view` · 6 file(s), +202 / −11*

- **Docs:** [wardriving.md](wardriving.md)

#### [#451](https://github.com/PierreGode/Ragnar/pull/451) — Add cell.md: ModemManager-supported cellular modems for wardriving cell capture
*Merged 2026-07-21 · branch `docs-cell-modems` · 1 file(s), +70 / −0*

### 2026-07-20

#### [#450](https://github.com/PierreGode/Ragnar/pull/450) — rusense flasher CI: pin ESP32 core 3.3.0 + -fpermissive for the coordinator build
*Merged 2026-07-20 · branch `rusense-flasher-coordinator-egg` · 1 file(s), +18 / −4*

#### [#449](https://github.com/PierreGode/Ragnar/pull/449) — Remove extra newline before License section
*Merged 2026-07-20 · branch `PierreGode-patch-1` · 1 file(s), +0 / −1*

- **Docs:** [README (root)](../README.md)

#### [#448](https://github.com/PierreGode/Ragnar/pull/448) — rusense flasher: hidden Piglet Coordinator forge behind the Skál rune
*Merged 2026-07-20 · branch `rusense-flasher-coordinator-egg` · 5 file(s), +245 / −5*

#### [#447](https://github.com/PierreGode/Ragnar/pull/447) — wardriving diagnostics: detect stalled feeds, fix USB attribution and Pi-5-only row
*Merged 2026-07-20 · branch `wardriving-diag-stale` · 5 file(s), +104 / −24*

- **Docs:** [wardriving.md](wardriving.md)

#### [#446](https://github.com/PierreGode/Ragnar/pull/446) — wardriving diagnostics: radios + power + richer GPS, and fix a raw timestamp
*Merged 2026-07-20 · branch `wardriving-diag-power` · 7 file(s), +754 / −12*

- wardriving diagnostics: bump the ragnar_modern.js cache-buster
- **Docs:** [wardriving.md](wardriving.md)

#### [#445](https://github.com/PierreGode/Ragnar/pull/445) — wardriving: diagnostics panel on the main dashboard tab too
*Merged 2026-07-20 · branch `wardriving-web-diagnostics` · 4 file(s), +241 / −3*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [wardriving.md](wardriving.md)

#### [#444](https://github.com/PierreGode/Ragnar/pull/444) — wardriving AP: restart-service button + stop hijacking the phone's internet
*Merged 2026-07-20 · branch `wardriving-ap-network` · 4 file(s), +332 / −23*

- wardriving AP page: collapsible diagnostics panel
- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#443](https://github.com/PierreGode/Ragnar/pull/443) — wardriving: LCD HAT wardriving layer — joystick screen carousel + key map
*Merged 2026-07-20 · branch `wardriving-lcd-pages` · 5 file(s), +443 / −51*

- **Docs:** [README (root)](../README.md), [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#442](https://github.com/PierreGode/Ragnar/pull/442) — wardriving: Exit Wardriving button on the phone AP page
*Merged 2026-07-20 · branch `wardriving-exit-button` · 3 file(s), +105 / −2*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#441](https://github.com/PierreGode/Ragnar/pull/441) — wifi analyzer: detect Wi-Fi 7 from raw EHT extension IEs (iw scan -u)
*Merged 2026-07-20 · branch `wifi7-eht-detection` · 3 file(s), +90 / −17*

- **Docs:** [README (root)](../README.md), [wifi-analyzer.md](wifi-analyzer.md)

#### [#440](https://github.com/PierreGode/Ragnar/pull/440) — wardriving: show GPS speed on the 1.44" ST7735S compact page
*Merged 2026-07-20 · branch `wardriving-st7735s-speed` · 2 file(s), +13 / −3*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#439](https://github.com/PierreGode/Ragnar/pull/439) — wardriving: add mph/kph speed unit switch in Config
*Merged 2026-07-20 · branch `gps-ubx-recovery-pacing` · 5 file(s), +101 / −6*

- wardriving: promote speed unit to a dedicated card toggle
- **Docs:** [wardriving.md](wardriving.md)

#### [#438](https://github.com/PierreGode/Ragnar/pull/438) — gps: make the UBX auto-recovery survive real u-blox 7 clones
*Merged 2026-07-20 · branch `gps-ubx-recovery-pacing` · 3 file(s), +220 / −6*

- **Docs:** [wardriving.md](wardriving.md)

### 2026-07-19

#### [#437](https://github.com/PierreGode/Ragnar/pull/437) — wardriving: auto-fit band counts on ST7735S compact page
*Merged 2026-07-19 · branch `wardriving-st7735s-autofit` · 2 file(s), +24 / −3*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#436](https://github.com/PierreGode/Ragnar/pull/436) — wardriving: compact header-less layout for 1.44" ST7735S LCD
*Merged 2026-07-19 · branch `wardriving-st7735s-compact` · 2 file(s), +114 / −0*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md)

#### [#435](https://github.com/PierreGode/Ragnar/pull/435) — nettools: Switch Discovery gets the interface dropdown
*Merged 2026-07-19 · branch `Wifi` · 4 file(s), +69 / −15*

- **Docs:** [nettools.md](nettools.md)

#### [#434](https://github.com/PierreGode/Ragnar/pull/434) — wardriving: split companion network counts into 2.4 GHz and 5 GHz
*Merged 2026-07-19 · branch `Wifi` · 5 file(s), +58 / −5*

- **Docs:** [wardriving.md](wardriving.md)

#### [#433](https://github.com/PierreGode/Ragnar/pull/433) — chmod +x incident_engine.py and watchtower.py (top-level .py must be executable)
*Merged 2026-07-19 · branch `Wifi` · 21 file(s), +1166 / −58*

- netdiag: egress tests get interface priority (eth > USB eth > wlan1 > wlan0) + joystick IFACE card
- airsnitch: auto-detect victim/attacker radios from spare adapters
- wardriving: show 6 GHz count in the web More card
- wardriving: union nmcli+sysfs for adapter detection so a third radio is seen
- wardriving: protect the uplink radio from NM claim + warn on under-voltage
- install/update: enable persistent journald so crashes leave evidence
- …and 5 more commit(s)
- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [airsnitch.md](airsnitch.md), [nettools.md](nettools.md), [wardriving.md](wardriving.md)

#### [#432](https://github.com/PierreGode/Ragnar/pull/432) — nettools: Locate Port and L2 Link Health get the interface dropdown
*Merged 2026-07-19 · branch `Wifi` · 4 file(s), +69 / −20*

- **Docs:** [nettools.md](nettools.md)

#### [#431](https://github.com/PierreGode/Ragnar/pull/431) — nettools: ARP Scan card gets interface dropdown like the other L2/L3 cards
*Merged 2026-07-19 · branch `Wifi` · 4 file(s), +44 / −19*

- **Docs:** [nettools.md](nettools.md)

#### [#430](https://github.com/PierreGode/Ragnar/pull/430) — wifi-analyzer: filter AP list by Wi-Fi generation (7/6E/6/5/4/legacy)
*Merged 2026-07-19 · branch `Wifi` · 3 file(s), +22 / −7*

- **Docs:** [wifi-analyzer.md](wifi-analyzer.md)

#### [#429](https://github.com/PierreGode/Ragnar/pull/429) — wifi-analyzer: cover Wi-Fi 7 (802.11be/EHT) labeling and 320 MHz width in selftest
*Merged 2026-07-19 · branch `Wifi` · 2 file(s), +40 / −6*

- **Docs:** [wifi-analyzer.md](wifi-analyzer.md)

### 2026-07-18

#### [#428](https://github.com/PierreGode/Ragnar/pull/428) — webapp: no-store cache headers for index/HTML/manifest so rebrand isn't pinned by stale browser/PWA cache
*Merged 2026-07-18 · branch `note` · 1 file(s), +17 / −4*

#### [#427](https://github.com/PierreGode/Ragnar/pull/427) — docs: cross-reference wifiwatch's WPA handshake/PNL layer from WiFi Defense docs and README
*Merged 2026-07-18 · branch `docs/wifiwatch-crossref` · 2 file(s), +8 / −2*

- **Docs:** [README (root)](../README.md), [wifi-defense.md](wifi-defense.md)

#### [#426](https://github.com/PierreGode/Ragnar/pull/426) — wifi defense: SSID column in airtime table; all three tables pivot to analyzer
*Merged 2026-07-18 · branch `feat/wids-analyzer-pivot` · 4 file(s), +38 / −20*

- **Docs:** [wifi-defense.md](wifi-defense.md)

#### [#425](https://github.com/PierreGode/Ragnar/pull/425) — wifi defense → analyzer pivot: click a flagged BSSID to highlight it in the spectrum
*Merged 2026-07-18 · branch `feat/wids-analyzer-pivot` · 5 file(s), +116 / −11*

- **Docs:** [README (root)](../README.md), [wifi-analyzer.md](wifi-analyzer.md), [wifi-defense.md](wifi-defense.md)

### 2026-07-17

#### [#424](https://github.com/PierreGode/Ragnar/pull/424) — incident engine: cross-signal correlation into attack-chain incidents
*Merged 2026-07-17 · branch `feat/incident-correlation-engine` · 8 file(s), +792 / −1*

- **Docs:** [incident-correlation.md](incident-correlation.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#423](https://github.com/PierreGode/Ragnar/pull/423) — wifiwatch: WPA handshake/PMKID harvest, WPA3 downgrade, PNL leak
*Merged 2026-07-17 · branch `feat/wifiwatch-handshake-pnl` · 3 file(s), +432 / −25*

- **Docs:** [wifiwatch.md](wifiwatch.md)

#### [#422](https://github.com/PierreGode/Ragnar/pull/422) — fix(speedtest): pin the device (SO_BINDTODEVICE), not the source address
*Merged 2026-07-17 · branch `fix/speedtest-multihomed-bind` · 3 file(s), +210 / −51*

- **Docs:** [nettools.md](nettools.md)

#### [#421](https://github.com/PierreGode/Ragnar/pull/421) — fix(speedtest): don't bind egress to an interface with no route to the internet
*Merged 2026-07-17 · branch `fix/speedtest-egress-route` · 2 file(s), +71 / −10*

- **Docs:** [nettools.md](nettools.md)

#### [#420](https://github.com/PierreGode/Ragnar/pull/420) — watchtower: unified alert pane for the standalone passive watchers
*Merged 2026-07-17 · branch `feat/watchtower-unified-alerts` · 10 file(s), +1179 / −16*

- watchtower: dashboard card + on by default
- watchtower: fix Open pane navigation + move card above Last Sync
- speedtest: interface selector, wired-first by default
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md), [watchtower.md](watchtower.md)

#### [#419](https://github.com/PierreGode/Ragnar/pull/419) — ndpwatch: standalone passive IPv6 Neighbor Discovery attack monitor
*Merged 2026-07-17 · branch `ndp` · 9 file(s), +1342 / −0*

- ndpwatch validation lab: ndpwatch-lab.sh + ndp_inject.py + conftest_packets.py
- **Docs:** [ndpwatch.md](ndpwatch.md), [nettools.md](nettools.md)

#### [#418](https://github.com/PierreGode/Ragnar/pull/418) — web update: make one click reliable — serialize git ops, spare live locks, verify on dropped connection
*Merged 2026-07-17 · branch `web-update-oneclick` · 7 file(s), +237 / −118*

- repo hygiene: stop the tree from going permanently dirty after every update

### 2026-07-16

#### [#416](https://github.com/PierreGode/Ragnar/pull/416) — installer: fix stall after iputils-ping — debconf prompt in iperf3 blocked apt
*Merged 2026-07-16 · branch `installer-noninteractive-apt` · 1 file(s), +4 / −2*

#### [#415](https://github.com/PierreGode/Ragnar/pull/415) — OSPF Watch: fix LSA seq/age parsing on real tcpdump (MaxSeq/MaxAge/fight-back were dead)
*Merged 2026-07-16 · branch `ospf-lsa-parse-fix` · 11 file(s), +1013 / −73*

- BGP: per-peer multi-carrier collector — name which ISP a convergence event hit
- arp_guard: standalone layered live ARP-poisoning detector
- ARP Poisoning: add interface selection (scope to one segment)
- **Docs:** [arp_guard.md](arp_guard.md), [nettools.md](nettools.md)

#### [#414](https://github.com/PierreGode/Ragnar/pull/414) — Network Integrity Monitor: persist alert memory so findings don't re-page
*Merged 2026-07-16 · branch `hardening` · 58 file(s), +7411 / −262*

- EIGRP FRR namespace lab: validate eigrp-watch against real FRR + injected attacks
- certwatch: passive standalone TLS certificate triage
- IS-IS Watch: detect LSP purge, overload bit, seq-number attack, mixed-auth
- isiswatch: standalone passive IS-IS security scanner (binary TLV parser)
- IGMP Watch: detect spoofed querier, bad TTL, bogus groups, join/leave flap, leave flood
- igmpwatch: standalone passive IGMP-snooping security monitor (package)
- …and 7 more commit(s)
- **Docs:** [README (root)](../README.md), [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [certwatch.md](certwatch.md), [eigrp_lab.md](eigrp_lab.md), [igmpwatch.md](igmpwatch.md), [isiswatch.md](isiswatch.md), [nettools.md](nettools.md), [snmpwatch.md](snmpwatch.md) (+2 more)

### 2026-07-15

#### [#411](https://github.com/PierreGode/Ragnar/pull/411) — Provision WiFi: normalize + validate the Server IP field
*Merged 2026-07-15 · branch `provision-ip-validation` · 2 file(s), +26 / −2*

#### [#410](https://github.com/PierreGode/Ragnar/pull/410) — Skald's Ear: survive device resets — auto-reconnect + boot-loop detection
*Merged 2026-07-15 · branch `skalds-ear-reconnect` · 2 file(s), +76 / −28*

#### [#409](https://github.com/PierreGode/Ragnar/pull/409) — RuSense flasher: Seeed XIAO ESP32S3 + XIAO ESP32S3 Plus support, S3 board dropdown
*Merged 2026-07-15 · branch `xiao-flasher` · 11 file(s), +151 / −46*

- **Docs:** [README (root)](../README.md), [rusense.md](rusense.md)

#### [#408](https://github.com/PierreGode/Ragnar/pull/408) — Network Integrity Monitor: capture on a link-up wired port by default
*Merged 2026-07-15 · branch `eth` · 7 file(s), +203 / −86*

- Network Integrity Monitor: don't repeat Pushover alerts for the same finding
- Update image in nettools documentation
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#406](https://github.com/PierreGode/Ragnar/pull/406) — Fix manual network scan detection over Ethernet
*Merged 2026-07-15 · branch `fix/manual-scan-ethernet-detection` · 1 file(s), +12 / −0*

#### [#407](https://github.com/PierreGode/Ragnar/pull/407) — LDAP Watch: passive Active Directory / LDAP security watch
*Merged 2026-07-15 · branch `ldapwatch` · 9 file(s), +1972 / −54*

- FHRP Watch: add GLBP byte decoder + AVG/AVF two-plane hijack detection
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

### 2026-07-14

#### [#405](https://github.com/PierreGode/Ragnar/pull/405) — SMB Watch: add passive Kerberos downgrade/roasting watch (Part 3)
*Merged 2026-07-14 · branch `smbw` · 5 file(s), +607 / −30*

- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#404](https://github.com/PierreGode/Ragnar/pull/404) — Added small readme fixes
*Merged 2026-07-14 · branch `SolarFlere` · 2 file(s), +6 / −4*

- Update README.md
- Update hardware-gen2.md
- **Docs:** [README (root)](../README.md), [hardware-gen2.md](hardware-gen2.md)

#### [#402](https://github.com/PierreGode/Ragnar/pull/402) — Create CODEOWNERS
*Merged 2026-07-14 · branch `SolarFlere` · 1 file(s), +2 / −0*

#### [#401](https://github.com/PierreGode/Ragnar/pull/401) — docs: add Ragnar Gen 2 minimal hardware requirements
*Merged 2026-07-14 · branch `Heatmap` · 2 file(s), +80 / −0*

- docs: credit Solarflere collaboration on Gen 2 hardware
- **Docs:** [README (root)](../README.md), [hardware-gen2.md](hardware-gen2.md)

#### [#400](https://github.com/PierreGode/Ragnar/pull/400) — fix(display): LCD spectrum scans the widest-band adapter (Alfa), not just onboard
*Merged 2026-07-14 · branch `Heatmap` · 4 file(s), +79 / −19*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [nettools.md](nettools.md), [wifi-analyzer.md](wifi-analyzer.md)

#### [#399](https://github.com/PierreGode/Ragnar/pull/399) — feat(display): WiFi Spectrum Analyzer SPECTRUM card on the 1.44" LCD HAT
*Merged 2026-07-14 · branch `Heatmap` · 6 file(s), +155 / −28*

- fix(display): drop the 'NET CARDS' title from the KEY2 card menu
- Update nettools.md
- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [nettools.md](nettools.md), [wifi-analyzer.md](wifi-analyzer.md)

#### [#398](https://github.com/PierreGode/Ragnar/pull/398) — feat(locate-port): add traffic-burst method (ACTIVITY LED) alongside link flap
*Merged 2026-07-14 · branch `Heatmap` · 4 file(s), +129 / −40*

- **Docs:** [nettools.md](nettools.md)

### 2026-07-13

#### [#397](https://github.com/PierreGode/Ragnar/pull/397) — feat(net-identity): per-interface scope for gateway + nameservers + domains
*Merged 2026-07-13 · branch `Heatmap` · 4 file(s), +153 / −38*

- **Docs:** [nettools.md](nettools.md)

#### [#396](https://github.com/PierreGode/Ragnar/pull/396) — feat(wifi-defense): passive AP/mesh client-isolation observer
*Merged 2026-07-13 · branch `Heatmap` · 6 file(s), +523 / −12*

- fix(wifi-defense): live countdown + progress bar on all capture buttons
- **Docs:** [README (root)](../README.md), [wifi-defense.md](wifi-defense.md)

#### [#395](https://github.com/PierreGode/Ragnar/pull/395) — feat(wifi-analyzer): true-to-scale heatmap — square plan, metre rulers, floor size, zoom/pan
*Merged 2026-07-13 · branch `Heatmap` · 5 file(s), +525 / −141*

- fix
- paint
- fixes
- better
- ui fix
- **Docs:** [README (root)](../README.md), [wifi-analyzer.md](wifi-analyzer.md)

#### [#394](https://github.com/PierreGode/Ragnar/pull/394) — fix(wifi-defense): reliable monitor re-enable + stop continuous on disable
*Merged 2026-07-13 · branch `screen` · 10 file(s), +834 / −21*

- tools(wifi-defense): add wifidef_doctor.sh monitor-mode diagnostic
- fix(wifi-defense): free the radio (base iface down) so monitor can capture
- fix(wifi-defense): stop NM/wpa_supplicant resetting the adapter on re-enable
- fix(wifi-defense): never treat the monitor vif (ragmon0) as a base adapter
- fix(wifi-defense): stop other features deleting ragmon0; flag stale service
- feat(wifi-defense): dedicated boot-time monitor mode (switch-mode, regdomain, 6 GHz)
- …and 1 more commit(s)
- **Docs:** [wifi-defense.md](wifi-defense.md)

### 2026-07-12

#### [#393](https://github.com/PierreGode/Ragnar/pull/393) — fix(wifi-defense): auto-rebuild ragmon0 when it dies mid-capture (ENODEV)
*Merged 2026-07-12 · branch `screen` · 2 file(s), +74 / −24*

- **Docs:** [wifi-defense.md](wifi-defense.md)

#### [#392](https://github.com/PierreGode/Ragnar/pull/392) — This pull request introduces major new features and enhancements to the WiFi Analyzer and Defense tools, focusing on active survey capabilities (throughput/latency tests), mesh/ESS coverage mapping, predictive/design coverage planning, and improved diagnostics. It also adds supporting UI controls, API endpoints, and documentation, along with minor dependency updates.
*Merged 2026-07-12 · branch `screen` · 9 file(s), +1716 / −64*

- feat(wifi-analyzer): active survey — throughput + latency per heatmap point
- feat(wifi-analyzer): predictive coverage + wall drawing (design mode)
- feat(wifi-defense): passive airtime / retry / PHY-rate / roaming diagnostics
- feat(wifi-analyzer): printable survey report (save as PDF)
- fix(wifi-analyzer): widen the iperf3 server input so the label is not cut off
- feat(wifi-analyzer): mesh survey — per-node coverage + serving-node / hand-off maps
- …and 6 more commit(s)
- **Docs:** [wifi-analyzer.md](wifi-analyzer.md), [wifi-defense.md](wifi-defense.md)

#### [#391](https://github.com/PierreGode/Ragnar/pull/391) — feat(wifi-defense): 802.11 frame monitor / WIDS backend
*Merged 2026-07-12 · branch `screen` · 12 file(s), +2821 / −114*

- feat(wifi-defense): WiFi Defense top-level tab (WIDS UI)
- docs(wifi-defense): guide, README bullet, declare scapy dependency
- feat(wifi-analyzer): enterprise AP enrichment + SNR + measured TX-power radius
- feat(wifi-analyzer): AP grouping (ESS + physical radios) + width advice
- feat(wifi-analyzer): enterprise AP table — badges, filter/sort, networks, CSV
- feat(wifi-analyzer): persistent AP history — new/gone/weakened change alerts + RSSI sparklines
- …and 13 more commit(s)
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md), [wifi-analyzer.md](wifi-analyzer.md), [wifi-defense.md](wifi-defense.md)

#### [#390](https://github.com/PierreGode/Ragnar/pull/390) — feat(lcd-hat): WiFi + Signal net-diag pages; reverse joystick axes
*Merged 2026-07-12 · branch `screen` · 6 file(s), +357 / −81*

- Add files via upload
- feat(lcd-hat): card-based net-diag navigation per joystick diagram
- docs(lcd-hat): document the card-based net-diag navigation
- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [nettools.md](nettools.md)

### 2026-07-11

#### [#389](https://github.com/PierreGode/Ragnar/pull/389) — feat(wifi-analyzer): passive tri-band spectrum analyzer backend
*Merged 2026-07-11 · branch `screen` · 9 file(s), +1655 / −2*

- feat(wifi-analyzer): WiFi Analyzer sub-tab with Bar + Dome spectrum
- feat(wifi-analyzer): coverage heatmap, docs, and iw dependency
- fix(wifi-analyzer): show every wireless dongle in the interface list
- **Docs:** [README (root)](../README.md), [wifi-analyzer.md](wifi-analyzer.md)

#### [#387](https://github.com/PierreGode/Ragnar/pull/387) — Replace image in nettools.md
*Merged 2026-07-11 · branch `PierreGode-patch-1` · 1 file(s), +2 / −1*

- **Docs:** [nettools.md](nettools.md)

#### [#386](https://github.com/PierreGode/Ragnar/pull/386) — Update nettools.md
*Merged 2026-07-11 · branch `screen` · 1 file(s), +2 / −1*

- **Docs:** [nettools.md](nettools.md)

#### [#385](https://github.com/PierreGode/Ragnar/pull/385) — This pull request expands the passive network security monitoring and detection capabilities by adding support for three new protocols—NDP (IPv6 Neighbor Discovery Protocol), CDP (Cisco Discovery Protocol), and VTP (VLAN Trunking Protocol)—across the documentation, API, and web UI. These additions close important detection gaps for IPv6 neighbor spoofing and Cisco-specific attacks, and provide new self-tests and mitigation guidance. The summary below highlights the most important changes.
*Merged 2026-07-11 · branch `screen` · 6 file(s), +2008 / −113*

- feat(ndp-watch): passive IPv6 Neighbor Discovery spoofing detector
- feat(cdp-watch): passive Cisco Discovery Protocol flood/spoof/leak scanner
- feat(vtp-watch): passive VTP bomb / rogue-server scanner
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#384](https://github.com/PierreGode/Ragnar/pull/384) — Restore API tools description in nettools.md
*Merged 2026-07-11 · branch `screen` · 1 file(s), +6 / −8*

- **Docs:** [nettools.md](nettools.md)

#### [#383](https://github.com/PierreGode/Ragnar/pull/383) — refactor: rename active TLS Watch -> Cert Watch, freeing "TLS Watch" for a passive observer
*Merged 2026-07-11 · branch `screen` · 11 file(s), +1625 / −78*

- feat(tls-watch): M1 passive ClientHello parser + JA3/JA4 client fingerprints
- feat(tls-watch): M2 ServerHello + JA3S + TLS1.2 cert findings
- feat(tls-watch): M3 passive QUIC Initial recovery (RFC 9001/9369)
- feat(tls-watch): M4a/b live capture, verdict, JA4S (license-gated)
- feat(tls-watch): M4c wire passive TLS Watch into network_diagnostics
- feat(tls-watch): M4d/e web card, monitor rotation, docs
- …and 1 more commit(s)
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

#### [#382](https://github.com/PierreGode/Ragnar/pull/382) — fix(arp-scan): resolve duplicate arp-results id so scan results render
*Merged 2026-07-11 · branch `screen` · 3 file(s), +7 / −3*

- Add image and update tool index section in nettools.md
- **Docs:** [nettools.md](nettools.md)

### 2026-07-10

#### [#381](https://github.com/PierreGode/Ragnar/pull/381) — lcd fix
*Merged 2026-07-10 · branch `screen` · 1 file(s), +59 / −10*

#### [#380](https://github.com/PierreGode/Ragnar/pull/380) — nettools: add IPv6 First-Hop Watch (rogue RA / DHCPv6 / mitm6 scanner)
*Merged 2026-07-10 · branch `lcdhat` · 7 file(s), +10155 / −1001*

- nettools: add NTP Watch — passive rogue-NTP / clock-injection scanner
- nettools: add ICMP Watch — passive ICMP-redirect / L3-injection scanner
- nettools: add SNMP Watch — passive v1/v2c cleartext-exposure scanner
- nettools: add TLS Watch — active cert/TLS hygiene checker + passive discovery
- docs: trim README Network Tools bullet, keep detail in docs/nettools.md
- ui: move TLS Watch card to the Diagnostics tab (was Switch & L2/L3)
- …and 12 more commit(s)
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md)

### 2026-07-09

#### [#379](https://github.com/PierreGode/Ragnar/pull/379) — lcdhat: joystick press toggles page autoscroll; KEY3 hold restarts
*Merged 2026-07-09 · branch `lcdhat` · 3 file(s), +78 / −20*

- **Docs:** [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [nettools.md](nettools.md)

#### [#378](https://github.com/PierreGode/Ragnar/pull/378) — docs: consolidate all markdown under docs/ and de-clutter the repo root
*Merged 2026-07-09 · branch `lcdhat` · 13 file(s), +96 / −2005*

- **Docs:** [README (root)](../README.md), [RELEASE_NOTES.md](RELEASE_NOTES.md), [espreadme.md](espreadme.md), [grade.md](grade.md)

#### [#377](https://github.com/PierreGode/Ragnar/pull/377) — lcdhat: KEY1 toggles On-Screen Network Diagnostic Mode + rename
*Merged 2026-07-09 · branch `lcdhat` · 6 file(s), +83 / −38*

- **Docs:** [README (root)](../README.md), [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [nettools.md](nettools.md)

#### [#376](https://github.com/PierreGode/Ragnar/pull/376) — display: add Waveshare 1.44" ST7735S LCD HAT (128x128) with keys + joystick
*Merged 2026-07-09 · branch `lcdhat` · 15 file(s), +4719 / −22*

- nettools: add IGMP Watch — passive IGMP-snooping security scanner (Switch & L2)
- nettools: add OSPF Security Scanner — passive routing-security scanner (Switch & L2)
- nettools: add BGP Path Watch + rename tab to Switch & L2/L3
- nettools: one-click Scapy install + Detector Self-Test panel (Switch & L2/L3)
- nettools: BGP Path Watch ASN enrichment via Team Cymru (soft-fail, per Solarflere)
- nettools: add receive-only BGP collector + path-asymmetry (OWD) with control-plane↔data-plane correlator
- …and 7 more commit(s)
- **Docs:** [README (root)](../README.md), [DISPLAY_CONTROLS.md](DISPLAY_CONTROLS.md), [INSTALL.md](INSTALL.md), [nettools.md](nettools.md)

### 2026-07-08

#### [#374](https://github.com/PierreGode/Ragnar/pull/374) — Dhcp doctor
*Merged 2026-07-08 · branch `DHCPDoctor` · 15 file(s), +1511 / −57*

- Diagnostics: add DHCP Guardian (rogue-DHCP + starvation, DHCP snooping)
- install/update: enable the Pi hardware watchdog (auto-reboot on hard hang)
- Fix: Network Integrity "Check now" hung on the slow DHCP scan
- Move DHCP Guardian card from Diagnostics to Switch & L2
- Switch & L2: add inline-bridge DHCP Snooping (2-NIC, trusted/untrusted)
- UI: unify toggle switches to match the Wardriving switch style
- …and 4 more commit(s)
- **Docs:** [README (root)](../README.md), [kiosk.md](kiosk.md), [nettools.md](nettools.md)

#### [#373](https://github.com/PierreGode/Ragnar/pull/373) — docs(readme): list the newer Network Tools in the feature summary
*Merged 2026-07-08 · branch `MACwatch` · 1 file(s), +1 / −1*

- **Docs:** [README (root)](../README.md)

#### [#372](https://github.com/PierreGode/Ragnar/pull/372) — Ma cwatch
*Merged 2026-07-08 · branch `MACwatch` · 1 file(s), +56 / −2*

- docs(nettools): document MAC Watch (spoof + randomization + tracking)
- **Docs:** [nettools.md](nettools.md)

#### [#371](https://github.com/PierreGode/Ragnar/pull/371) — Diagnostics: add CSV export to MAC Watch
*Merged 2026-07-08 · branch `MACwatch` · 2 file(s), +19 / −2*

#### [#370](https://github.com/PierreGode/Ragnar/pull/370) — Ma cwatch
*Merged 2026-07-08 · branch `MACwatch` · 4 file(s), +620 / −1*

- Diagnostics: add MAC Watch card — detection-only spoof + randomization + tracking
- Diagnostics: add interface selector to MAC Watch (scan WiFi or LAN)
- Diagnostics: list every MAC observed in MAC Watch results

### 2026-07-07

#### [#369](https://github.com/PierreGode/Ragnar/pull/369) — docs(nettools): document DNS poisoning + ARP poisoning + integrity monitor, e-Paper key pad, VPN egress check
*Merged 2026-07-07 · branch `Keys` · 1 file(s), +142 / −12*

- **Docs:** [nettools.md](nettools.md)

#### [#368](https://github.com/PierreGode/Ragnar/pull/368) — Net integrity monitor: ARP-spoof detection + passive DNS/ARP watch with alerts
*Merged 2026-07-07 · branch `Keys` · 6 file(s), +483 / −1*

- DNS Doctor: explicit note that it checks for DNS poisoning/hijacking
- Diagnostics: give ARP poisoning its own card (on-demand check)

#### [#367](https://github.com/PierreGode/Ragnar/pull/367) — Net diag: 2.7" HAT key pad for diagnostic mode + DNS poisoning detection
*Merged 2026-07-07 · branch `Keys` · 6 file(s), +533 / −39*

### 2026-07-06

#### [#366](https://github.com/PierreGode/Ragnar/pull/366) — Network tools: re-enable VPN indicators — known-VPN egress-IP list catches VPN/Tor on the router
*Merged 2026-07-06 · branch `features07` · 6 file(s), +306 / −19*

- RuSense: self-heal data ownership so CSI recording survives root-run updates
- Network tools: per-interface VPN egress check + stop hiding NICs without an address

### 2026-07-05

#### [#364](https://github.com/PierreGode/Ragnar/pull/364) — Rusense and Net tools
*Merged 2026-07-05 · branch `View` · 148 file(s), +21404 / −320*

- Bundle WiFi-CSI sensing backend + RuSense dashboard fixes
- Observatory fullscreen + branding cleanup; fix RuSense Training tab
- Sync pending working-tree changes to install/pager/wifi scripts and assets
- Gitignore secrets and runtime data (zap api key, auth db, scan state)
- Replace Piglet flasher Pages with RuSense CSI-node flasher (ESP32-S3/C6)
- Update README.md
- …and 141 more commit(s)
- **Docs:** [README (root)](../README.md), [nettools.md](nettools.md), [rusense.md](rusense.md)

### 2026-06-10

#### [#360](https://github.com/PierreGode/Ragnar/pull/360) — real
*Merged 2026-06-10 · branch `export` · 4 file(s), +10 / −8*

- hy
- **Docs:** [wardriving.md](wardriving.md)

#### [#359](https://github.com/PierreGode/Ragnar/pull/359) — Rows whose position was estimated via backfill_gps_from_track
*Merged 2026-06-10 · branch `export` · 5 file(s), +139 / −33*

- Rows whose position was estimated via backfill_gps_from_track (gps_backfilled = 1) are excluded. Interpolated coordinates are not actual observations, so they're omitted from WiGLE submissions to avoid polluting the dataset with synthetic positions.
- **Docs:** [wardriving.md](wardriving.md)

### 2026-06-07

#### [#357](https://github.com/PierreGode/Ragnar/pull/357) — huginn
*Merged 2026-06-07 · branch `Huginn` · 8 file(s), +868 / −35*

- paper
- wee
- claims
- fixes
- auto

### 2026-06-03

#### [#354](https://github.com/PierreGode/Ragnar/pull/354) — patch
*Merged 2026-06-03 · branch `overview` · 2 file(s), +12 / −0*

#### [#353](https://github.com/PierreGode/Ragnar/pull/353) — gps
*Merged 2026-06-03 · branch `overview` · 6 file(s), +241 / −7*

- **Docs:** [wardriving.md](wardriving.md)

#### [#352](https://github.com/PierreGode/Ragnar/pull/352) — sate
*Merged 2026-06-03 · branch `overview` · 1 file(s), +19 / −4*

### 2026-06-02

#### [#351](https://github.com/PierreGode/Ragnar/pull/351) — zap fixes
*Merged 2026-06-02 · branch `overview` · 2 file(s), +194 / −5*

### 2026-06-01

#### [#350](https://github.com/PierreGode/Ragnar/pull/350) — str
*Merged 2026-06-01 · branch `structure` · 5 file(s), +139 / −95*

- clean

#### [#348](https://github.com/PierreGode/Ragnar/pull/348) — grade
*Merged 2026-06-01 · branch `grade` · 0 file(s), +0 / −0*

- dd
- gt
- kl

### 2026-05-31

#### [#347](https://github.com/PierreGode/Ragnar/pull/347) — patch
*Merged 2026-05-31 · branch `grades` · 0 file(s), +0 / −0*

- fix

#### [#346](https://github.com/PierreGode/Ragnar/pull/346) — patch
*Merged 2026-05-31 · branch `bughunt` · 2 file(s), +16 / −3*

#### [#345](https://github.com/PierreGode/Ragnar/pull/345) — CIS PCI DSS
*Merged 2026-05-31 · branch `grades` · 17 file(s), +1190 / −322*

- Update grade.md
- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

#### [#344](https://github.com/PierreGode/Ragnar/pull/344) — server network
*Merged 2026-05-31 · branch `servers` · 14 file(s), +320 / −313*

- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

#### [#343](https://github.com/PierreGode/Ragnar/pull/343) — pwnss
*Merged 2026-05-31 · branch `pwnss` · 9 file(s), +243 / −36*

- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

### 2026-05-30

#### [#342](https://github.com/PierreGode/Ragnar/pull/342) — Update README.md
*Merged 2026-05-30 · branch `PierreGode-patch-2` · 1 file(s), +2 / −0*

- **Docs:** [README (root)](../README.md)

#### [#341](https://github.com/PierreGode/Ragnar/pull/341) — Stop web portal during wardriving without WiFi; reconnect on device disconnect
*Merged 2026-05-30 · branch `claude/ragnar-wifi-auto-connect-e5k4Z` · 4 file(s), +179 / −6*

#### [#340](https://github.com/PierreGode/Ragnar/pull/340) — sort
*Merged 2026-05-30 · branch `comp` · 3 file(s), +135 / −174*

#### [#339](https://github.com/PierreGode/Ragnar/pull/339) — companions
*Merged 2026-05-30 · branch `comp` · 4 file(s), +478 / −527*

- **Docs:** [wardriving.md](wardriving.md)

#### [#338](https://github.com/PierreGode/Ragnar/pull/338) — nuclei
*Merged 2026-05-30 · branch `nuclei` · 7 file(s), +576 / −184*

### 2026-05-29

#### [#337](https://github.com/PierreGode/Ragnar/pull/337) — names
*Merged 2026-05-29 · branch `netscanner` · 3 file(s), +101 / −15*

### 2026-05-28

#### [#336](https://github.com/PierreGode/Ragnar/pull/336) — feat(pwn-bridge): add _execute_pwn_git_update helper and PWN_REPO_PATH
*Merged 2026-05-28 · branch `pwns` · 4 file(s), +703 / −1*

- fix(pwn-bridge): address Task 1 review issues
- feat(pwn-bridge): add /api/pwn/check-updates endpoint
- fix(pwn-bridge): address Task 2 review issues
- feat(pwn-bridge): add /api/pwn/update endpoint
- feat(pwn-bridge): add /api/pwn/stash-update endpoint
- feat(pwn-bridge): add Pwnagotchi Updates card to Bridge section
- …and 7 more commit(s)

#### [#335](https://github.com/PierreGode/Ragnar/pull/335) — network
*Merged 2026-05-28 · branch `NetworkScan` · 9 file(s), +1478 / −112*

- **Docs:** [spec.md](spec.md)

#### [#334](https://github.com/PierreGode/Ragnar/pull/334) — traffic
*Merged 2026-05-28 · branch `2628` · 11 file(s), +2152 / −12*

- data
- alerts
- no false irc

### 2026-05-27

#### [#333](https://github.com/PierreGode/Ragnar/pull/333) — zap
*Merged 2026-05-27 · branch `2628` · 9 file(s), +1685 / −1*

- **Docs:** [superpowers/specs/2026-05-27-web-recon-subsystem-design.md](superpowers/specs/2026-05-27-web-recon-subsystem-design.md)

### 2026-05-26

#### [#332](https://github.com/PierreGode/Ragnar/pull/332) — gps from piglet
*Merged 2026-05-26 · branch `pigletgps` · 2 file(s), +115 / −1*

- gps

### 2026-05-25

#### [#330](https://github.com/PierreGode/Ragnar/pull/330) — Love to Hamspiced
*Merged 2026-05-25 · branch `Hamspiced` · 1 file(s), +2 / −2*

- Update wardriving.md
- **Docs:** [wardriving.md](wardriving.md)

#### [#329](https://github.com/PierreGode/Ragnar/pull/329) — Love Hamspiced, Update Piglet (USB) mode description for clarity
*Merged 2026-05-25 · branch `Hamspiced` · 1 file(s), +1 / −1*

- **Docs:** [wardriving.md](wardriving.md)

### 2026-05-24

#### [#328](https://github.com/PierreGode/Ragnar/pull/328) — Update README.md
*Merged 2026-05-24 · branch `PierreGode-patch-1` · 1 file(s), +1 / −1*

- **Docs:** [README (root)](../README.md)

#### [#323](https://github.com/PierreGode/Ragnar/pull/323) — Fix command to delete monitor interface
*Merged 2026-05-24 · branch `fix-services-script-typo` · 1 file(s), +1 / −1*

#### [#324](https://github.com/PierreGode/Ragnar/pull/324) — bug: Pwnagotchi swap status not clearing after switching back to Ragnar
*Merged 2026-05-24 · branch `fix-pwnagotchi-handout` · 1 file(s), +3 / −1*

- bug: Fix ragnar to pwngotchi handout

#### [#327](https://github.com/PierreGode/Ragnar/pull/327) — Ragnar Piglet Coordinator
*Merged 2026-05-24 · branch `Ragnar-piglet-coordinator` · 15 file(s), +3368 / −83*

- web
- site
- branch
- Read this for wardriving
- **Docs:** [wardriving.md](wardriving.md)

### 2026-05-23

#### [#321](https://github.com/PierreGode/Ragnar/pull/321) — mobile fit
*Merged 2026-05-23 · branch `2623` · 3 file(s), +111 / −60*

- mobile

### 2026-05-22

#### [#318](https://github.com/PierreGode/Ragnar/pull/318) — Auto-detect WiGLE 1.6 column shift
*Merged 2026-05-22 · branch `piglet` · 6 file(s), +1263 / −18*

- update
- piglet parsing
- parse
- updates
- external scanning
- external scan
- …and 5 more commit(s)

### 2026-05-21

#### [#317](https://github.com/PierreGode/Ragnar/pull/317) — settings
*Merged 2026-05-21 · branch `2621` · 8 file(s), +291 / −15*

- data fixes
- fixes

### 2026-05-20

#### [#316](https://github.com/PierreGode/Ragnar/pull/316) — Revert power warning feature entirely
*Merged 2026-05-20 · branch `2620` · 4 file(s), +3 / −110*

- den

#### [#315](https://github.com/PierreGode/Ragnar/pull/315) — Power warning: lower EXT5V thresholds to match real Pi 5 readings
*Merged 2026-05-20 · branch `gps` · 1 file(s), +3 / −3*

#### [#314](https://github.com/PierreGode/Ragnar/pull/314) — Wardriving card: power-health warning banner
*Merged 2026-05-20 · branch `gps` · 3 file(s), +109 / −2*

#### [#313](https://github.com/PierreGode/Ragnar/pull/313) — Backfill: use endpoint speeds for constant-accel interpolation
*Merged 2026-05-20 · branch `gps` · 3 file(s), +163 / −34*

- docs: update wardriving guide with current behavior
- docs: highlight GPS recovery during dropouts
- **Docs:** [README (root)](../README.md), [wardriving.md](wardriving.md)

#### [#312](https://github.com/PierreGode/Ragnar/pull/312) — Bump Huginn serial baud to 460800
*Merged 2026-05-20 · branch `gps` · 4 file(s), +64 / −34*

- Always drive Huginn with its fast wardrive loop
- Strip explanatory comments
- Don't null GPS columns when stronger RSSI lands without a fix

#### [#311](https://github.com/PierreGode/Ragnar/pull/311) — Gps updates
*Merged 2026-05-20 · branch `gps` · 3 file(s), +102 / −15*

- Fix GPS parser to surface pre-fix state (sats in view + alive signal)
- Wardriving GPS card: show satellites in view + SNR

### 2026-05-17

#### [#309](https://github.com/PierreGode/Ragnar/pull/309) — Add gpsd and native serial port GPS support
*Merged 2026-05-17 · branch `claude/add-serial-gps-support-d6vhm` · 1 file(s), +172 / −21*

### 2026-05-14

#### [#308](https://github.com/PierreGode/Ragnar/pull/308) — fields
*Merged 2026-05-14 · branch `e-paper` · 1 file(s), +35 / −20*

#### [#307](https://github.com/PierreGode/Ragnar/pull/307) — Count only unique WiFi networks for HuginnESP display
*Merged 2026-05-14 · branch `claude/filter-duplicate-networks-hn3Ls` · 1 file(s), +11 / −6*

### 2026-05-13

#### [#306](https://github.com/PierreGode/Ragnar/pull/306) — companions
*Merged 2026-05-13 · branch `kiosk` · 1 file(s), +18 / −0*

### 2026-05-12

#### [#304](https://github.com/PierreGode/Ragnar/pull/304) — Kiosk mode for ON display
*Merged 2026-05-12 · branch `kiosk` · 9 file(s), +1224 / −4*

- test
- fix
- kiosk
- site
- xorg

### 2026-05-11

#### [#303](https://github.com/PierreGode/Ragnar/pull/303) — Expand camera detection: add SSID pattern matching + more OUIs
*Merged 2026-05-11 · branch `claude/investigate-camera-detection-IRHvc` · 2 file(s), +38 / −4*

#### [#302](https://github.com/PierreGode/Ragnar/pull/302) — map
*Merged 2026-05-11 · branch `ward` · 5 file(s), +279 / −12*

- wardrive

#### [#301](https://github.com/PierreGode/Ragnar/pull/301) — wigle: header-driven CSV parser for Piglet (1.4 + 1.6 compatible)
*Merged 2026-05-11 · branch `huginn` · 1 file(s), +123 / −46*

#### [#300](https://github.com/PierreGode/Ragnar/pull/300) — Better wifi
*Merged 2026-05-11 · branch `huginn` · 7 file(s), +1045 / −56*

- wardriving: WiFi adapter details + fix USB serial conflicts
- fix: suppress Pylance import-not-found for pyserial (Pi-only dep)
- revert: remove type: ignore comments, keep get_shared_data bugfix
- multiple wifi-antenas
- wifi pach
- wifi
- …and 12 more commit(s)

### 2026-05-10

#### [#299](https://github.com/PierreGode/Ragnar/pull/299) — wardriving: active full-channel sweep for faster stationary discovery
*Merged 2026-05-10 · branch `huginn` · 1 file(s), +53 / −3*

#### [#298](https://github.com/PierreGode/Ragnar/pull/298) — GPS updates
*Merged 2026-05-10 · branch `huginn` · 4 file(s), +319 / −107*

- sec
- GPS fix

#### [#297](https://github.com/PierreGode/Ragnar/pull/297) — update
*Merged 2026-05-10 · branch `huginn` · 2 file(s), +50 / −30*

#### [#296](https://github.com/PierreGode/Ragnar/pull/296) — patch
*Merged 2026-05-10 · branch `huginn` · 3 file(s), +96 / −20*

### 2026-05-09

#### [#293](https://github.com/PierreGode/Ragnar/pull/293) — Wardrive
*Merged 2026-05-09 · branch `huginn` · 3 file(s), +9 / −27*

#### [#292](https://github.com/PierreGode/Ragnar/pull/292) — huginn
*Merged 2026-05-09 · branch `huginn` · 1 file(s), +55 / −12*

#### [#291](https://github.com/PierreGode/Ragnar/pull/291) — huginn
*Merged 2026-05-09 · branch `huginn` · 5 file(s), +283 / −1*

### 2026-05-08

#### [#288](https://github.com/PierreGode/Ragnar/pull/288) — fix: blacklisted hosts were still written to DB during scans
*Merged 2026-05-08 · branch `devel/blacklist` · 3 file(s), +67 / −25*

- fix: enforce blacklist across all remaining upsert_host call sites
- fix: filter blacklisted hosts when loading existing DB entries in update_netkb

#### [#287](https://github.com/PierreGode/Ragnar/pull/287) — Issue #284 fix: web preview no longer rotated when screen_reversed is set
*Merged 2026-05-08 · branch `devel/webdisplay` · 1 file(s), +6 / −6*

- fix: web preview no longer rotated when screen_reversed is set

#### [#290](https://github.com/PierreGode/Ragnar/pull/290) — WarDriving
*Merged 2026-05-08 · branch `wardriving` · 3 file(s), +45 / −10*

#### [#289](https://github.com/PierreGode/Ragnar/pull/289) — ward
*Merged 2026-05-08 · branch `wardriving` · 15 file(s), +4938 / −26*

- fix wardriving: robust freq/channel parsing, SSID sanitization, WPA/WEP detection
- feat: wardriving display mode for all screens (EPD, GC9A01, SSD1306, LCD1602, MAX7219)
- fix: sanitize literal \\xNN escape sequences in SSIDs from iw scan
- fix: wardriving start/stop button reliability and tab refresh
- fix: wardriving toggle button + fix indent syntax error in wardriving.py
- feat: add GPS column to wardriving network table
- …and 53 more commit(s)
- **Docs:** [wardriving.md](wardriving.md)

### 2026-05-05

#### [#286](https://github.com/PierreGode/Ragnar/pull/286) — fixes
*Merged 2026-05-05 · branch `260505` · 8 file(s), +108 / −33*

#### [#285](https://github.com/PierreGode/Ragnar/pull/285) — not rotate in ui
*Merged 2026-05-05 · branch `260505` · 7 file(s), +60 / −28*

- path fix
- scroll fix

### 2026-04-27

#### [#281](https://github.com/PierreGode/Ragnar/pull/281) — Waveshare EPD  driver "epd2in13b_V4" (black/white/red) added.
*Merged 2026-04-27 · branch `epd2in13b_V4-driver` · 3 file(s), +284 / −23*

- Update shared.py
- Update install_ragnar.sh

### 2026-04-22

#### [#280](https://github.com/PierreGode/Ragnar/pull/280) — Wifi updates
*Merged 2026-04-22 · branch `wifi` · 4 file(s), +151 / −47*

- wifi
- fix
- wifi fix
- patch
- button
- del

#### [#279](https://github.com/PierreGode/Ragnar/pull/279) — Support for open WiFi networks
*Merged 2026-04-22 · branch `wifi` · 1 file(s), +8 / −7*

- open networks

#### [#278](https://github.com/PierreGode/Ragnar/pull/278) — Install fixes
*Merged 2026-04-22 · branch `merge` · 2 file(s), +386 / −16*

- install fixes
- **Docs:** [PWNAGOTCHI.md](PWNAGOTCHI.md)

#### [#277](https://github.com/PierreGode/Ragnar/pull/277) — min
*Merged 2026-04-22 · branch `merge` · 1 file(s), +1 / −1*

#### [#267](https://github.com/PierreGode/Ragnar/pull/267) — fix: stop auto-scroll caused by password manager extension
*Merged 2026-04-22 · branch `fix/auto-scroll-password-manager-extension` · 2 file(s), +17 / −16*

- fix: stop auto-scroll caused by password manager extension reacting to frequent DOM mutations

#### [#268](https://github.com/PierreGode/Ragnar/pull/268) — fix: resolve permanent 'Loading...' in Data Management card (Config tab)
*Merged 2026-04-22 · branch `fix/data-management-loading-duplicate-id` · 2 file(s), +3 / −1*

- fix: resolve permanent 'Loading...' in Data Management card

#### [#269](https://github.com/PierreGode/Ragnar/pull/269) — feat: display human-readable temperature sensor names
*Merged 2026-04-22 · branch `feat/temperature-sensor-labels` · 1 file(s), +33 / −1*

#### [#271](https://github.com/PierreGode/Ragnar/pull/271) — fix: show filter-aware empty state in Vulnerabilities by Host
*Merged 2026-04-22 · branch `fix/vuln-filter-empty-state` · 1 file(s), +8 / −2*

### 2026-04-07

#### [#272](https://github.com/PierreGode/Ragnar/pull/272) — fix: prevent XSS in onclick handlers and innerHTML
*Merged 2026-04-07 · branch `fix/xss-escaping` · 1 file(s), +25 / −11*

- fix: prevent XSS in onclick handlers and innerHTML (Critical/High)
- fix: escape file.name in innerHTML (XSS follow-up)

#### [#273](https://github.com/PierreGode/Ragnar/pull/273) — chore: update socket.io client from 4.5.4 to 4.8.3
*Merged 2026-04-07 · branch `chore/update-socketio-4.8.3` · 1 file(s), +1 / −1*

### 2026-03-31

#### [#266](https://github.com/PierreGode/Ragnar/pull/266) — docs: add attribution for brAinphreAk's Loki/PagerBjorn pager work (closes #265)
*Merged 2026-03-31 · branch `fix/issue-265-pager-attribution` · 1 file(s), +13 / −0*

- docs: add attribution for brAinphreAk's Loki/PagerBjorn pager work (issue #265)
- **Docs:** [README (root)](../README.md)

### 2026-03-23

#### [#262](https://github.com/PierreGode/Ragnar/pull/262) — test
*Merged 2026-03-23 · branch `Fixes` · 12 file(s), +289 / −177*

- fa
- flip
- 90
- up

### 2026-03-22

#### [#261](https://github.com/PierreGode/Ragnar/pull/261) — update
*Merged 2026-03-22 · branch `Fixes` · 7 file(s), +152 / −28*

- nr
- nrf
- test
- fix
- df
- hm
- …and 4 more commit(s)

#### [#239](https://github.com/PierreGode/Ragnar/pull/239) — feat: add LCD1602 16x2 I2C character display support
*Merged 2026-03-22 · branch `pr/lcd1602-upstream` · 6 file(s), +574 / −38*

- feat: redesign LCD1602 display with rotating info pages
- fix: skip EPD buffer validation for character displays (lcd1602)
- fix: use f-string in logger.info for character display init message
- fix: handle None epd_helper for character displays in Display init
- fix: f-string logger calls and increase EN pulse timing in lcd1602
- feat: redesign lcd1602 display with independent top/bottom timers
- …and 5 more commit(s)

### 2026-03-21

#### [#260](https://github.com/PierreGode/Ragnar/pull/260) — patch
*Merged 2026-03-21 · branch `Fixes` · 4 file(s), +33 / −16*

#### [#259](https://github.com/PierreGode/Ragnar/pull/259) — fix: add timeout to epd4in26 ReadBusy to prevent startup hang
*Merged 2026-03-21 · branch `claude/fix-epaper-startup-BkBHf` · 1 file(s), +7 / −2*

#### [#258](https://github.com/PierreGode/Ragnar/pull/258) — fix(web): start web server before EPD display init to prevent startup delays
*Merged 2026-03-21 · branch `claude/fix-web-startup-8pYL9` · 2 file(s), +15 / −10*

#### [#257](https://github.com/PierreGode/Ragnar/pull/257) — Claude/add spi clock config 7 u gw m
*Merged 2026-03-21 · branch `claude/add-spi-clock-config-7UGwM` · 4 file(s), +45 / −5*

- Add configurable SPI clock speed for e-paper display
- Rebuild minified JS after SPI clock config addition

### 2026-03-20

#### [#256](https://github.com/PierreGode/Ragnar/pull/256) — Add Waveshare 4.26" e-paper (epd4in26) support
*Merged 2026-03-20 · branch `claude/add-epaper-426-support-7OyQh` · 7 file(s), +247 / −14*

### 2026-03-19

#### [#254](https://github.com/PierreGode/Ragnar/pull/254) — Bundle vulners.nse NSE script for Pineapple Pager vuln scanning
*Merged 2026-03-19 · branch `funcs` · 4 file(s), +442 / −0*

### 2026-03-18

#### [#252](https://github.com/PierreGode/Ragnar/pull/252) — fix(pager): readable fonts + pager-only settings (no ethernet/websrv)
*Merged 2026-03-18 · branch `Pineapple` · 2 file(s), +107 / −89*

- fix

#### [#250](https://github.com/PierreGode/Ragnar/pull/250) — feat(pager): add 4 interactive settings pages to pager display
*Merged 2026-03-18 · branch `Pineapple` · 1 file(s), +393 / −18*

#### [#240](https://github.com/PierreGode/Ragnar/pull/240) — feat: add MAX7219 LED matrix display support (4-panel and 8-panel)
*Merged 2026-03-18 · branch `pr/max7219-upstream` · 9 file(s), +427 / −17*

- feat: add display_brightness config for non-e-ink displays
- fix: skip EPD init for MAX7219 display types in shared.py
- fix: guard epd_helper.init_partial_update() in Display.__init__
- fix: skip wipe_epd for non-EPD displays; use sudo pip3 for luma install
- fix: MAX7219 all-pixels-on on startup
- fix: correct MAX7219 block_orientation default to -90 for horizontal strips
- …and 3 more commit(s)
- **Docs:** [README (root)](../README.md)

#### [#243](https://github.com/PierreGode/Ragnar/pull/243) — feat(ui): rename E-Paper to Display across all user-facing web UI text
*Merged 2026-03-18 · branch `pr/display-rename` · 2 file(s), +36 / −36*

- feat(ui): rename E-Paper → Display across all user-facing web UI text

#### [#244](https://github.com/PierreGode/Ragnar/pull/244) — feat(ui): add AP Archive tab — browse collected data per access point
*Merged 2026-03-18 · branch `pr/ap-archive` · 3 file(s), +430 / −1*

- feat(networks): add /api/networks/all and /api/networks/<slug>/files endpoints
- feat(networks): add All Scanned Networks tab to web UI
- fix(qa): restore missing wrapper divs in Network Map tab
- fix(networks): escape JSON strings in onclick to prevent HTML attribute breakage
- feat(networks): rename 'Networks' tab to 'AP Archive' across all user-facing UI

#### [#245](https://github.com/PierreGode/Ragnar/pull/245) — fix(discovered): fix View Full Report 404 for per-network scans
*Merged 2026-03-18 · branch `pr/fix-view-full-report` · 1 file(s), +34 / −19*

### 2026-03-17

#### [#248](https://github.com/PierreGode/Ragnar/pull/248) — Claude/optimize pager deploy y pd ax
*Merged 2026-03-17 · branch `claude/optimize-pager-deploy-yPdAx` · 3 file(s), +69 / −5*

- Fix Resolve Git Conflicts button in Settings
- Rebuild minified JS with terser

#### [#247](https://github.com/PierreGode/Ragnar/pull/247) — Pinapple Pager
*Merged 2026-03-17 · branch `pagers` · 15 file(s), +998 / −175*

- pager
- ui
- fix
- Organise pager files, fix vuln display, slim deployment
- Fix pager crash on Exit from main menu
- pinapple

### 2026-03-14

#### [#242](https://github.com/PierreGode/Ragnar/pull/242) — fix(airsnitch): correct interface order and wire client.conf credentials
*Merged 2026-03-14 · branch `claude/add-airsnitch-tool-oWS7y` · 5 file(s), +63 / −7*

#### [#241](https://github.com/PierreGode/Ragnar/pull/241) — airsnitch tool
*Merged 2026-03-14 · branch `claude/add-airsnitch-tool-oWS7y` · 8 file(s), +1123 / −2*

- feat: integrate AirSnitch Wi-Fi client isolation testing tool
- feat: add AirSnitch UI panel to the Pentest tab
- chore: rebuild minified JS bundle
- fix: move AirSnitch above Bluetooth, fix install reliability, add live install log
- fix: install libnl-3/openssl build deps before running AirSnitch setup.sh
- fix: correct airsnitch.py path and clone submodules
- …and 3 more commit(s)
- **Docs:** [README (root)](../README.md), [airsnitch.md](airsnitch.md)

### 2026-03-11

#### [#235](https://github.com/PierreGode/Ragnar/pull/235) — feat: add GC9A01 1.28" 240x240 round TFT LCD display support
*Merged 2026-03-11 · branch `screens` · 9 file(s), +1264 / −40*

- feat: add GC9A01 TFT LCD as install-time display option
- fix: prevent GPIO27 'already in use' on repeated init() calls
- feat(gc9a01): fix flashing + add round display UI
- fix(gc9a01): correct mirrored display + wifi label
- feat(gc9a01): animated mascot using status BMP frame sequences
- feat(gc9a01): revert mascot to flat tint colorization
- …and 13 more commit(s)

### 2026-03-09

#### [#229](https://github.com/PierreGode/Ragnar/pull/229) — fix: display selection during install ignored when reinstalling
*Merged 2026-03-09 · branch `fix/epd-type-install-overwrite` · 1 file(s), +25 / −18*

- fix: epd_type selection ignored on install when not epd2in13_V4

#### [#233](https://github.com/PierreGode/Ragnar/pull/233) — req
*Merged 2026-03-09 · branch `deptpatch` · 3 file(s), +28 / −6*

### 2026-03-06

#### [#226](https://github.com/PierreGode/Ragnar/pull/226) — pwn
*Merged 2026-03-06 · branch `pi` · 6 file(s), +587 / −2*

- test
- pw
- ok
- low
- page
- fix
- …and 3 more commit(s)

### 2026-03-03

#### [#210](https://github.com/PierreGode/Ragnar/pull/210) — fixed ZAP
*Merged 2026-03-03 · branch `releases` · 2 file(s), +225 / −50*

- zap fix
- zapfix
- fixes

#### [#209](https://github.com/PierreGode/Ragnar/pull/209) — faster
*Merged 2026-03-03 · branch `releases` · 2 file(s), +9 / −2*

