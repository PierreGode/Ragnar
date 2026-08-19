// Nodes — per-node CSI sensor health, mesh status, hardware spec.
import { icons } from '../icons.js';
import { html, $, fetchJSON, fmt, toast } from '../lib.js?v=20260704-sparkfit';
import { sensingService } from '../../services/sensing.service.js';

// Graduated node health from last_seen. The sensing-server exposes a binary
// active/stale that flips the instant a node gaps for ~a second, which reads as
// "dead" even though the node is still streaming and recovers immediately. Base
// the shown status on how long ago we actually heard from it:
//   live    (<5s)  — streaming normally
//   lagging (5-45s)— a recent gap; still around, RF/mesh hiccup (see mesh offsets)
//   offline (>=45s)— genuinely silent
function nodeHealth(lastSeenMs) {
  const s = (lastSeenMs == null) ? Infinity : lastSeenMs / 1000;
  if (s < 5) return { label: 'live', badge: 'badge-ok', dot: 'bg-ok', key: 'live' };
  if (s < 45) return { label: 'lagging', badge: 'badge-warn', dot: 'bg-warn', key: 'lagging' };
  return { label: 'offline', badge: 'badge-bad', dot: 'bg-bad', key: 'offline' };
}

// Convert a mesh clock offset (microseconds) to a human string.
function fmtOffset(us) {
  const a = Math.abs(us || 0);
  if (a < 1000) return `${us || 0} \u00b5s`;
  if (a < 1e6) return `${((us || 0) / 1000).toFixed(1)} ms`;
  return `${((us || 0) / 1e6).toFixed(1)} s`;
}

// Classify a node's TIME-SYNC from its clock offset vs the leader + how long
// since its last mesh sync packet. A healthy mesh syncs to sub-millisecond
// offsets with sub-second freshness. Seconds of offset, or tens of seconds with
// no sync, means the sync path is broken — typically because the nodes are on
// DIFFERENT access points (the sync traffic doesn't cross between routers), even
// while the CSI data path (unicast to the Pi) keeps working.
function syncState(offsetUs, stalenessMs, isLeader) {
  if (isLeader) return { label: 'leader', cls: 'badge-ok', key: 'synced' };
  const a = Math.abs(offsetUs || 0), st = stalenessMs || 0;
  if (a <= 5000 && st <= 10000) return { label: 'synced', cls: 'badge-ok', key: 'synced' };
  if (a <= 500000 && st <= 30000) return { label: 'syncing', cls: 'badge-warn', key: 'syncing' };
  return { label: 'desynced', cls: 'badge-bad', key: 'desynced' };
}

// Fix #503 — Pi-anchored per-node sync classifier. `relOffUs` is this node's
// Pi-anchored offset relative to the fleet (server_offset_us minus the fleet
// minimum), i.e. how far it sits from the other nodes on the Pi's single
// clock. Unlike the legacy mesh offset (which explodes to seconds when the
// ESP-NOW leader election doesn't converge — the #503 symptom), this stays
// tiny whenever the nodes actually reach the Pi together, which is all fusion
// needs. Judged against the server's real fusion guard window.
function piSyncState(relOffUs, stalenessMs, guardUs) {
  const a = Math.abs(relOffUs || 0), st = stalenessMs || 0, g = guardUs || 200000;
  if (st > 30000) return { label: 'stale sync', cls: 'badge-warn', key: 'syncing' };
  if (a <= g) return { label: 'synced', cls: 'badge-ok', key: 'synced' };
  if (a <= g * 3) return { label: 'syncing', cls: 'badge-warn', key: 'syncing' };
  return { label: 'desynced', cls: 'badge-bad', key: 'desynced' };
}

function nodeRow(n, names = {}) {
  const h = nodeHealth(n.last_seen_ms);
  const nm = names[String(n.node_id)];
  const label = nm ? `${nm} <span class="text-ink-muted text-xs">#${n.node_id}</span>` : `#${n.node_id}`;
  return `<tr class="border-b border-ink-3 last:border-0">
    <td class="py-2.5 pr-3 font-mono">${label}</td>
    <td class="py-2.5 pr-3"><span class="${h.badge}" title="last frame ${fmt.ago((n.last_seen_ms ?? 0) / 1000)}"><span class="dot ${h.dot}"></span>${h.label}</span></td>
    <td class="py-2.5 pr-3 font-mono text-right">${fmt.dbm(n.rssi_dbm)}</td>
    <td class="py-2.5 pr-3 text-ink-soft">${(n.motion_level || '—').replace(/_/g, ' ')}</td>
    <td class="py-2.5 pr-3 text-right font-mono">${n.person_count ?? 0}</td>
    <td class="py-2.5 pr-3 text-right text-ink-muted">${fmt.ago((n.last_seen_ms ?? 0) / 1000)}</td>
    <td class="py-2.5 text-right"><button class="btn-ghost !py-1 !px-2.5 text-xs" data-cal-node="${n.node_id}" title="Walk to this node and watch the bar fill green as you get close">Calibrate</button></td>
  </tr>`;
}

// Bar colour for a proximity value (0..1): red far → amber mid → green close.
function proxColor(v) {
  if (v >= 0.6) return 'rgb(34 197 94)';    // ok / green
  if (v >= 0.34) return 'rgb(245 158 11)';  // warn / amber
  return 'rgb(239 68 68)';                   // bad / red
}

export default {
  id: 'nodes',
  label: 'Nodes',
  icon: icons.nodes,

  async mount(root) {
    // Custom node names come from Ragnar config (Settings), not the sensing
    // roster; load them once so the table shows names instead of just "#id".
    let nodeNames = {};
    fetchJSON('/api/config').then((c) => { nodeNames = (c && c.rusense_node_names) || {}; });

    root.appendChild(html`
      <section class="space-y-5">
        <div class="grid grid-cols-3 gap-3">
          <div class="stat"><span class="stat-label">Live</span><span class="stat-value text-ok" id="n-live">—</span></div>
          <div class="stat"><span class="stat-label">Lagging</span><span class="stat-value text-warn" id="n-lagging">—</span></div>
          <div class="stat"><span class="stat-label">Offline</span><span class="stat-value text-bad" id="n-offline">—</span></div>
        </div>

        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Sensor nodes</h2>
            <div class="flex items-center gap-2">
              <button id="n-logs" class="btn-ghost !py-1.5 !px-3 text-xs" title="Capture EVERYTHING to a JSON file: 30s node/mesh/engine time-series + server-side tcpdump, journalctl, ss, systemctl, wifi/system state, binary md5s and API snapshots">Download logs</button>
              <button id="n-refresh" class="btn-ghost !py-1.5 !px-3 text-xs">Refresh</button>
            </div>
          </div>
          <div class="overflow-x-auto -mx-1">
            <table class="w-full text-sm min-w-[480px]">
              <thead><tr class="text-left text-xs uppercase tracking-wide text-ink-muted border-b border-ink-3">
                <th class="py-2 pr-3 font-medium">Node</th><th class="py-2 pr-3 font-medium">Status</th>
                <th class="py-2 pr-3 font-medium text-right">RSSI</th><th class="py-2 pr-3 font-medium">Motion</th>
                <th class="py-2 pr-3 font-medium text-right">People</th><th class="py-2 pr-3 font-medium text-right">Last seen</th>
                <th class="py-2 font-medium text-right">Calibrate</th>
              </tr></thead>
              <tbody id="n-body"><tr><td colspan="7" class="py-6 text-center text-ink-muted">Loading…</td></tr></tbody>
            </table>
          </div>
        </div>

        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Mesh health</h2>
            <span id="mesh-verdict-badge" class="badge-mut">—</span>
          </div>
          <p id="mesh-verdict" class="text-sm text-ink-soft leading-snug">Reading mesh…</p>
          <div id="mesh-nodes" class="space-y-2"></div>
          <p class="text-xs text-ink-muted pt-1 border-t border-ink-3">
            <strong>CSI</strong> = data path (node → Pi). <strong>sync</strong> = frame alignment for
            multi-node fusion. Ragnar timestamps every frame as it arrives, so a node's
            <strong>lag</strong> — how far its latest frame trails the freshest node — is what matters; keep it
            under the fusion window (~200&nbsp;ms) by putting all nodes on the <em>same AP &amp; channel</em>.
            The old per-leader offset can read seconds even when fusion is fine.
          </p>
          <details class="text-xs">
            <summary class="text-ink-muted cursor-pointer select-none">Raw mesh JSON</summary>
            <pre id="mesh-raw" class="mt-2 font-mono text-ink-soft whitespace-pre-wrap break-words">—</pre>
          </details>
        </div>

        <div class="card card-pad space-y-2">
          <h2 class="card-title">Hardware reference</h2>
          <dl class="text-sm space-y-2">
            ${[['Node chip', 'ESP32-S3 / C6'], ['Band', '2.4 GHz WiFi CSI'], ['Subcarriers', 'up to 114'], ['Sample rate', '~100 Hz'], ['mmWave option', 'Seeed MR60BHA2 (60 GHz)']]
              .map(([k, v]) => `<div class="flex justify-between border-b border-ink-3 pb-2 last:border-0"><dt class="text-ink-muted">${k}</dt><dd class="font-mono text-right">${v}</dd></div>`).join('')}
          </dl>
        </div>

        <!-- Per-node proximity calibration modal (walk to the node, watch the bar fill green) -->
        <div id="cal-modal" class="fixed top-0 bottom-0 inset-x-0 z-50 backdrop-blur" style="display:none;background:rgba(0,0,0,.55);align-items:center;justify-content:center;padding:1rem;">
          <div class="card" style="width:100%;max-width:30rem;max-height:92vh;overflow-y:auto;">
            <div class="card-pad space-y-4">
              <div class="flex items-center justify-between">
                <h2 class="card-title" id="cal-title">Calibrate node</h2>
                <button id="cal-close" class="btn-ghost !py-1 !px-2.5 text-xs">Close</button>
              </div>
              <p class="text-sm text-ink-soft leading-snug">
                Walk to <strong id="cal-nodename">this node</strong> and <strong>move around</strong> near it.
                The bar fills and turns <span class="text-ok">green</span> the closer you are — it reads how
                strongly you're perturbing <em>this node's</em> link versus the others. Hold at the greenest
                spot, then <strong>Record</strong> to save a reference for it.
              </p>

              <!-- Big proximity bar -->
              <div>
                <div class="flex items-baseline justify-between mb-1">
                  <span class="stat-label">Proximity</span>
                  <span id="cal-prox-pct" class="font-mono text-lg font-bold">—</span>
                </div>
                <div style="position:relative;width:100%;height:1.75rem;border-radius:9999px;overflow:hidden;background:rgb(31 40 49);">
                  <span id="cal-bar" style="display:block;height:100%;width:0%;border-radius:9999px;background:rgb(239 68 68);transition:width .25s ease,background-color .25s ease;"></span>
                  <span id="cal-peak" title="best seen" style="position:absolute;top:0;bottom:0;width:2px;background:rgb(103 232 249);left:0%;display:none;"></span>
                </div>
                <div class="flex justify-between text-xs text-ink-muted mt-1">
                  <span>far</span><span id="cal-hint">move near the node</span><span>close</span>
                </div>
              </div>

              <!-- Full live output -->
              <div class="rounded-lg bg-ink-1 border border-ink-3 p-3">
                <div class="flex items-center justify-between mb-2">
                  <span class="stat-label">Live output</span>
                  <span id="cal-src" class="badge-mut">—</span>
                </div>
                <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  ${[['Motion band power', 'cal-motion'], ['Baseline (quiet floor)', 'cal-base'],
                     ['Activity vs floor', 'cal-act'], ['Share of all nodes', 'cal-share'],
                     ['Peak proximity', 'cal-peakv'], ['RSSI', 'cal-rssi']]
                    .map(([k, id]) => `<div class="flex justify-between border-b border-ink-3 pb-1"><dt class="text-ink-muted">${k}</dt><dd class="font-mono text-right" id="${id}">—</dd></div>`).join('')}
                </dl>
                <div id="cal-others" class="mt-2 space-y-1"></div>
              </div>

              <div class="flex items-center gap-2">
                <button id="cal-record" class="btn-primary flex-1 !py-2 text-sm">Record calibration (15s)</button>
                <button id="cal-reset" class="btn-ghost !py-2 text-sm" title="Forget the learned quiet-floor baselines and start fresh">Reset baseline</button>
              </div>
              <p class="text-xs text-ink-muted leading-snug">
                Honest limits: WiFi CSI proximity is <strong>near-field</strong> — a moving body perturbs every
                link, so the bar is sharpest when you're right beside a node and fuzzier mid-room. This is
                relative guidance, not survey-grade ranging.
              </p>
            </div>
          </div>
        </div>
      </section>`);

    // Cross-poll history so we can detect reboots (sequence going backwards) and
    // offset TREND (so you can watch offsets collapse toward zero on one AP).
    const seqPrev = {}, offPrev = {}, rebootAt = {};
    const renderMeshHealth = (mesh, nodeList, status) => {
      const raw = $('#mesh-raw'); if (raw) raw.textContent = mesh ? JSON.stringify(mesh, null, 2) : 'unavailable';
      const wrap = $('#mesh-nodes'), vEl = $('#mesh-verdict'), vb = $('#mesh-verdict-badge');
      const nodes = (mesh && mesh.nodes) || {};
      const ids = Object.keys(nodes).sort((a, b) => (+a) - (+b));
      if (!ids.length) {
        if (wrap) wrap.innerHTML = '<div class="text-sm text-ink-muted">No mesh data — no nodes reporting.</div>';
        if (vEl) vEl.textContent = ''; if (vb) { vb.textContent = '—'; vb.className = 'badge-mut'; }
        return;
      }
      const rssi = {}, lastSeen = {};
      for (const n of (nodeList || [])) { rssi[String(n.node_id)] = n.rssi_dbm; lastSeen[String(n.node_id)] = n.last_seen_ms; }
      // Fix #503 — Pi-anchored fleet sync from host arrival-time spread
      // (present once the rebuilt sensing-server is deployed; falls back to
      // legacy mesh offsets on older binaries where these fields are absent).
      const serverSkewUs = (mesh && mesh.server_skew_us != null) ? mesh.server_skew_us : null;
      const guardUs = (mesh && mesh.guard_interval_us) || 200000;
      const serverSynced = !!(mesh && mesh.synced === true);
      let desynced = 0, syncing = 0, dataOkAmongBad = 0;
      const badWeak = [], rebootIds = [], stalledIds = [];
      const rows = ids.map((id) => {
        const m = nodes[id] || {};
        const off = m.offset_us || 0, stale = m.staleness_ms || 0, seq = m.sequence || 0;
        // Fix #503 — this node's host arrival lag vs the freshest node (how
        // far its latest frame trailed the rest = its share of the fusion
        // skew). Falls back to the legacy mesh offset on older binaries.
        const relOff = (m.arrival_lag_us != null) ? m.arrival_lag_us : null;
        const dispOff = (relOff != null) ? relOff : off;
        const prevSeq = seqPrev[id];
        if (prevSeq != null && seq < prevSeq - 2) rebootAt[id] = Date.now();
        const frozen = prevSeq != null && seq === prevSeq;   // sequence not advancing between polls
        seqPrev[id] = seq;
        const rebooted = rebootAt[id] && (Date.now() - rebootAt[id] < 120000);
        if (rebooted) rebootIds.push(id);
        const stalled = frozen && stale > 20000;             // frozen + minutes stale = mesh dead here
        if (stalled) stalledIds.push(id);
        let trend = '';
        if (offPrev[id] != null) {
          const d = Math.abs(dispOff) - Math.abs(offPrev[id]);
          if (d < -50000) trend = ' <span class="text-ok">\u2193 converging</span>';
          else if (d > 50000) trend = ' <span class="text-warn">\u2191 drifting</span>';
        }
        offPrev[id] = dispOff;
        const ss = stalled ? { label: 'stalled', cls: 'badge-bad', key: 'stalled' }
          : (relOff != null ? piSyncState(relOff, stale, guardUs) : syncState(off, stale, m.is_leader));
        if (ss.key === 'desynced') { desynced++; badWeak.push({ id, rssi: rssi[id], stale, off }); }
        else if (ss.key === 'syncing') syncing++;
        const ls = lastSeen[id];
        const dataFlowing = ls != null && ls < 5000;
        if (ss.key === 'desynced' && dataFlowing) dataOkAmongBad++;
        const nm = nodeNames[id];
        const label = nm ? `${nm} <span class="text-ink-muted">#${id}</span>` : `#${id}`;
        const rv = rssi[id];
        return `<div class="rounded-lg bg-ink-1 border border-ink-3 p-2.5 space-y-1">
          <div class="flex items-center justify-between">
            <span class="font-mono text-sm">${label}${m.is_leader ? ' <span class="text-xs text-ink-muted">(leader)</span>' : ''}</span>
            <span class="${ss.cls}">${ss.label}</span>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-x-3 gap-y-1 text-xs text-ink-muted">
            <span title="${relOff != null ? 'host arrival lag vs the freshest node — legacy mesh/leader offset was ' + fmtOffset(off) : 'mesh clock offset vs leader'}">${relOff != null ? 'lag' : 'offset'} <span class="font-mono text-ink-soft">${fmtOffset(dispOff)}</span>${trend}</span>
            <span>last sync <span class="font-mono text-ink-soft">${fmt.ago(stale / 1000)}</span></span>
            <span>CSI <span class="font-mono ${dataFlowing ? 'text-ok' : 'text-warn'}">${dataFlowing ? `${Math.round(m.csi_fps_ema || 0)} fps` : (ls != null ? fmt.ago(ls / 1000) : '—')}</span></span>
            <span>RSSI <span class="font-mono text-ink-soft">${rv != null ? `${Math.round(rv)} dBm` : '—'}</span></span>
          </div>
          ${stalled ? '<div class="text-xs text-bad">\u26a0 mesh frozen — no updates from this node</div>'
            : (rebooted ? '<div class="text-xs text-bad">\u26a0 sequence reset — this node rebooted</div>' : '')}
        </div>`;
      });
      if (wrap) wrap.innerHTML = rows.join('');
      // ── plain-language verdict, most-serious first ──
      const src = (status && status.source) ? String(status.source) : '';
      const offline = /offline/i.test(src);
      let badge, bcls, msg;
      if (offline || (stalledIds.length && stalledIds.length === ids.length)) {
        badge = 'Not reaching server'; bcls = 'badge-bad';
        msg = `The server reports <span class="font-mono">offline</span> and the mesh is frozen (sequences aren't advancing, last-sync is minutes old). Two causes look identical here — <strong>run “Download logs”</strong>, which now auto-classifies the packets: <br>1) <strong>Nodes are streaming but in edge mode</strong> (~60 B feature packets, <span class="font-mono">edge_tier≥1</span>): the server needs raw CSI (148–404 B) and ignores edge packets, so it shows offline even though data flows. Fix = reprovision <span class="font-mono">edge_tier=0</span> (flasher “Write WiFi config” after a hard refresh). <br>2) <strong>No packets at all</strong>: the nodes joined an AP that can't reach the Pi — a strong RSSI on the wrong AP/subnet still delivers nothing. Get all nodes onto the <strong>same AP/network as the Ragnar box</strong> (unique SSID or turn off other radios; no guest / client-isolation).`;
      } else if (stalledIds.length) {
        badge = 'Node(s) stalled'; bcls = 'badge-bad';
        msg = `Node(s) ${stalledIds.map((i) => '#' + i).join(', ')} stopped updating (mesh frozen, minutes stale) while others are live — that node likely dropped to a different AP or lost the Pi. Check its WiFi association and placement.`;
      } else if (rebootIds.length) {
        badge = 'Rebooting'; bcls = 'badge-bad';
        msg = `Node(s) ${rebootIds.map((i) => '#' + i).join(', ')} reset their sequence — a reboot loop. Check power (ESP32-S3 browns out under WiFi TX spikes) or a weak/dropping AP.`;
      } else if (serverSynced) {
        // Fix #503 — the server re-bases every node onto the Pi's single clock,
        // so the fleet is aligned for fusion regardless of the (flaky) ESP-NOW
        // leader election. This is the normal healthy state now.
        badge = 'Healthy'; bcls = 'badge-ok';
        const skewMs = serverSkewUs != null ? (serverSkewUs / 1000).toFixed(1) : '<1';
        msg = `All nodes are <strong>aligned on the Pi</strong> — their latest frames arrive within <strong>${skewMs} ms</strong> of each other, inside the ${Math.round(guardUs / 1000)} ms fusion window. Ragnar timestamps every frame as it lands, so multi-node fusion works no matter the boot order or whether the ESP-NOW leader election ever converges. Any large per-node “offset” you saw before was the legacy peer-sync figure — it no longer gates fusion.`;
      } else if (serverSkewUs != null) {
        // Pi-anchored data present but the fleet's arrival-time spread exceeds
        // the fusion guard — a genuine alignment problem (a node on a slow/far
        // hop), not the cosmetic ESP-NOW offset.
        badge = 'Frames not aligned'; bcls = 'badge-warn';
        const weakN = ids.map((id) => ({ id, rssi: rssi[id] })).filter((b) => b.rssi != null && b.rssi < -75).sort((a, b) => a.rssi - b.rssi)[0];
        const weakHint = weakN ? ` Node #${weakN.id} is weak at ${Math.round(weakN.rssi)} dBm — likely on a far/slow AP hop.` : '';
        msg = `Nodes reach the Pi, but their latest frames arrive <strong>${(serverSkewUs / 1000).toFixed(1)} ms</strong> apart — beyond the ${Math.round(guardUs / 1000)} ms fusion window — so multi-node fusion may drop frames. Per-node <strong>presence &amp; motion still work</strong>. Get every node onto <strong>one AP + a fixed channel</strong> and in good signal range so their packets arrive together.${weakHint}`;
      } else if (desynced) {
        // Read the evidence before blaming APs: a big offset with FRESH sync and
        // STRONG signal is the ESP-NOW clock not converging, NOT a far/other AP.
        const offList = badWeak.map((b) => `#${b.id} ${fmtOffset(b.off)}`).join(', ');
        const allFresh = badWeak.every((b) => (b.stale ?? 0) < 10000);
        const allStrong = badWeak.every((b) => b.rssi == null || b.rssi >= -70);
        if (allFresh && allStrong) {
          badge = 'Clock not converging'; bcls = 'badge-warn';
          msg = `Sync packets are arriving <strong>fresh</strong> and the signal is <strong>strong</strong>, so this is <strong>not</strong> an access-point / range problem — the ESP-NOW clock offset just isn't converging to the leader (${offList}). CSI is streaming, so per-node <strong>presence &amp; motion work fine</strong>; only multi-node <strong>fusion</strong> (position / people-count) needs the clocks within ~200&nbsp;ms. Power-cycle the desynced node(s) to re-run leader election; if the offset stays multi-second it's the mesh time-sync not locking — safe to ignore if you only need presence.`;
        } else {
          badge = 'Sync failing'; bcls = 'badge-bad';
          const weak = badWeak.filter((b) => b.rssi != null && b.rssi < -70).sort((a, b) => a.rssi - b.rssi)[0];
          const weakHint = weak ? ` Node #${weak.id} is weak at ${Math.round(weak.rssi)} dBm — likely on a far router.` : '';
          const staleHint = badWeak.some((b) => (b.stale ?? 0) >= 10000) ? ' Sync packets are stale (not arriving).' : '';
          const dataHint = dataOkAmongBad ? ' CSI data is still streaming, so the data path is fine — only time-sync is broken.' : '';
          msg = `Time-sync failing on ${desynced} node(s): clocks are off the leader (${offList}).${staleHint}${dataHint} Commonly the signature of nodes on <strong>different access points</strong> — one SSID across several routers makes each node roam to a different AP, breaking mesh sync. Put all nodes on <strong>one AP + a fixed channel</strong>.${weakHint}`;
        }
      } else if (syncing) {
        badge = 'Converging'; bcls = 'badge-warn';
        msg = 'Mesh is settling — offsets shrinking toward zero. Give it a few seconds; if they never reach sub-millisecond, the nodes are probably on different APs.';
      } else {
        badge = 'Healthy'; bcls = 'badge-ok';
        msg = 'All nodes time-synced — sub-millisecond offsets, fresh sync. Same AP, coherent mesh. This is what good looks like.';
      }
      if (vb) { vb.textContent = badge; vb.className = bcls; }
      if (vEl) vEl.innerHTML = msg;
    };

    const refresh = async () => {
      const [data, mesh, status] = await Promise.all([fetchJSON('/api/v1/nodes'), fetchJSON('/api/v1/mesh'), fetchJSON('/api/v1/status')]);
      const body = $('#n-body');
      const list = data?.nodes || [];
      const by = { live: 0, lagging: 0, offline: 0 };
      for (const nd of list) by[nodeHealth(nd.last_seen_ms).key]++;
      $('#n-live').textContent = by.live;
      $('#n-lagging').textContent = by.lagging;
      $('#n-offline').textContent = by.offline;
      body.innerHTML = list.length
        ? list.map((n) => nodeRow(n, nodeNames)).join('')
        : '<tr><td colspan="7" class="py-6 text-center text-ink-muted">No nodes reporting. Power on an ESP32 CSI node and provision it to this server.</td></tr>';
      renderMeshHealth(mesh, list, status);
    };

    // Download logs: a ROLLING capture (not a single snapshot) of node roster +
    // mesh + engine trust, so a reboot loop (mesh `sequence` resetting), clock-
    // offset drift, or an engine demotion is visible over time. ~30s @ 3s.
    let capturing = false;
    const captureLogs = async (btn) => {
      if (capturing) return;
      capturing = true;
      const CAP_MS = 30000, STEP = 3000, started = Date.now(), samples = [];
      const orig = btn.textContent;
      btn.disabled = true;
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      // Fire the server-side deep diagnostics in parallel (tcpdump on the CSI UDP
      // port, journalctl for the sensing engine, ss/systemctl, system+wifi state,
      // binary md5s, API snapshots) — the browser can't run those. Returns in
      // ~8s, well inside the 30s sample window, so it adds no extra wait.
      const diagPromise = fetchJSON('/api/rusense/diagnostics?secs=6', { timeout: 25000 }).catch(() => null);  // endpoint runs tcpdump+journal ~10s; default 6s timeout would abort it
      try {
        while (Date.now() - started < CAP_MS && capturing) {
          const [nodes, mesh, status, adaptive] = await Promise.all([
            fetchJSON('/api/v1/nodes'), fetchJSON('/api/v1/mesh'),
            fetchJSON('/api/v1/status'), fetchJSON('/api/v1/adaptive/status'),
          ]);
          samples.push({ t: new Date().toISOString(), nodes, mesh, status, adaptive });
          const left = Math.max(0, Math.ceil((CAP_MS - (Date.now() - started)) / 1000));
          btn.textContent = `Capturing… ${left}s`;
          if (Date.now() - started < CAP_MS && capturing) await sleep(STEP);
        }
        btn.textContent = 'Collecting server logs…';
        const server = await diagPromise;   // tcpdump / journal / ss / systemctl / md5 / api
        if (!samples.length && !server) return;
        const bundle = {
          captured_at: new Date().toISOString(),
          capture_seconds: Math.round((Date.now() - started) / 1000),
          sample_count: samples.length,
          node_names: nodeNames,
          hint: 'READ server_diagnostics.packet_analysis FIRST — it auto-classifies the tcpdump: mode=small_only (streaming ~60B, NO raw CSI — either edge_tier>=1 OR edge_tier=0 with yield=0/starved CSI; check node serial for yield=0pps + re-Forge 0.7.0+ for the #954 self-ping), raw_csi (correct), or no_packets (nodes not reaching Pi). server_diagnostics = one-shot server-side deep capture (tcpdump on UDP 5005 -> packet sizes tell edge_tier: ~60B=edge mode, 148-404B=raw CSI; journal_sensing -> fusion/spread/dimension errors; binaries.*_md5 -> confirm the running binary; sockets_udp Recv-Q -> ingestion backlog; api.mesh offset_us/staleness_ms -> clock sync). samples = 30s time-series (mesh sequence resets = reboots; growing offset = desync; trust.demoted/errors climbing = engine degrading).',
          server_diagnostics: server,
          samples,
        };
        const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }));
        const a = document.createElement('a');
        a.href = url;
        a.download = `rusense-node-logs-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
      } finally {
        capturing = false;
        btn.disabled = false;
        btn.textContent = orig;
      }
    };

    // ── Per-node proximity calibration ────────────────────────────────────
    // Walk to a node, watch the bar fill green. The proximity signal mirrors
    // the server's activity-centroid localizer: each node's live motion is
    // measured RELATIVE to its own slowly-learned quiet floor (asymmetric EMA —
    // rises slowly, falls fast), so a node that always reads hot doesn't win by
    // default. When ≥2 nodes stream, proximity = the selected node's SHARE of
    // total activity; with a single node it's activity auto-scaled to its own
    // peak. Baselines persist across the modal being closed so they stay warm.
    const cal = {
      open: false, nodeId: null,
      base: {},          // node_id -> EMA quiet-floor of motion_band_power
      latest: {},        // node_id -> { motion, act, share, rssi, stale }
      peak: 0,           // best proximity seen for the selected node (hold)
      selPeakAct: 0,     // running peak activity (single-node auto-scale)
      smooth: 0,         // smoothed proximity 0..1
      rec: null,         // { n, motion, act, share, rssi, peakShare }
      recTimer: null,
      lastRender: 0,
    };
    const A_UP = 0.005, A_DOWN = 0.05, POW = 2;   // baseline EMA + share sharpening

    // Fold one live frame into the per-node baselines / activities / shares.
    const calFeed = (data) => {
      const feats = (data && data.node_features) || [];
      if (!feats.length) return;
      const acts = {};
      let anyActive = 0;
      for (const f of feats) {
        const id = f.node_id;
        const stale = f.stale === true;
        const motion = Math.max(0, (f.features && f.features.motion_band_power) || f.motion_band_power || 0);
        const b = (cal.base[id] == null) ? motion : cal.base[id];
        cal.base[id] = (motion > b) ? b + A_UP * (motion - b) : b + A_DOWN * (motion - b);
        const act = stale ? 0 : Math.max(0, motion - cal.base[id]);
        acts[id] = act;
        if (!stale) anyActive++;
        cal.latest[id] = { motion, act, base: cal.base[id], rssi: f.rssi_dbm, stale };
      }
      // Shares from activity^POW across all nodes.
      let denom = 0;
      for (const id in acts) denom += Math.pow(acts[id], POW);
      for (const id in cal.latest) {
        cal.latest[id].share = denom > 1e-9 ? Math.pow(acts[id] || 0, POW) / denom : 0;
      }
      // Proximity of the selected node.
      if (cal.nodeId != null && cal.latest[cal.nodeId]) {
        const L = cal.latest[cal.nodeId];
        let prox;
        if (anyActive >= 2) {
          prox = L.share;                                   // spatial share
        } else {
          cal.selPeakAct = Math.max(cal.selPeakAct * 0.999, L.act);
          prox = cal.selPeakAct > 1e-6 ? L.act / cal.selPeakAct : 0;  // self-relative
        }
        cal.smooth += 0.2 * (prox - cal.smooth);
        if (cal.smooth > cal.peak) cal.peak = cal.smooth;
        if (cal.rec) {
          cal.rec.n++; cal.rec.motion += L.motion; cal.rec.act += L.act;
          cal.rec.share += (L.share || 0); cal.rec.rssi += (L.rssi || 0);
          cal.rec.peakShare = Math.max(cal.rec.peakShare, cal.smooth);
        }
      }
      if (cal.open) calRender();
    };

    const calRender = () => {
      const now = Date.now();
      if (now - cal.lastRender < 90) return;   // ~11 fps DOM cap
      cal.lastRender = now;
      const L = cal.nodeId != null ? cal.latest[cal.nodeId] : null;
      const v = Math.max(0, Math.min(1, cal.smooth));
      const pct = Math.round(v * 100);
      const bar = $('#cal-bar'); if (bar) { bar.style.width = pct + '%'; bar.style.background = proxColor(v); }
      const pk = $('#cal-peak');
      if (pk) { if (cal.peak > 0.02) { pk.style.display = 'block'; pk.style.left = Math.round(cal.peak * 100) + '%'; } else pk.style.display = 'none'; }
      const set = (id, txt) => { const el = $('#' + id); if (el) el.textContent = txt; };
      set('cal-prox-pct', L ? pct + '%' : '—');
      set('cal-hint', !L ? 'waiting for live CSI…' : (v >= 0.6 ? 'close — hold here' : v >= 0.34 ? 'getting warmer' : 'move near the node'));
      set('cal-motion', L ? fmt.num(L.motion, 4) : '—');
      set('cal-base', L ? fmt.num(L.base, 4) : '—');
      set('cal-act', L ? fmt.num(L.act, 4) : '—');
      set('cal-share', L ? Math.round((L.share || 0) * 100) + '%' : '—');
      set('cal-peakv', Math.round(cal.peak * 100) + '%');
      set('cal-rssi', L && L.rssi != null ? fmt.dbm(L.rssi) : '—');
      const src = $('#cal-src');
      if (src) {
        const live = sensingService.dataSource === 'live';
        src.textContent = L ? (live ? 'live CSI' : sensingService.dataSource) : 'no data';
        src.className = L && live ? 'badge-ok' : 'badge-mut';
      }
      // Other nodes' shares for context (so you can see this node winning).
      const others = $('#cal-others');
      if (others) {
        const ids = Object.keys(cal.latest).filter((id) => String(id) !== String(cal.nodeId)).sort((a, b) => (+a) - (+b));
        others.innerHTML = ids.length
          ? '<div class="text-xs text-ink-muted mb-1">Other nodes (share)</div>' + ids.map((id) => {
              const o = cal.latest[id]; const sp = Math.round((o.share || 0) * 100);
              const nm = nodeNames[id] ? `${nodeNames[id]} #${id}` : `#${id}`;
              return `<div class="flex items-center gap-2 text-xs"><span class="font-mono w-16 shrink-0">${nm}</span>
                <span class="meter" style="flex:1;"><span style="width:${sp}%;background:rgb(138 154 168);"></span></span>
                <span class="font-mono text-ink-muted" style="width:2.5rem;text-align:right;">${sp}%</span></div>`;
            }).join('')
          : '';
      }
    };

    const openCal = (nodeId) => {
      cal.open = true; cal.nodeId = String(nodeId);
      cal.peak = 0; cal.smooth = 0; cal.selPeakAct = 0;
      const nm = nodeNames[cal.nodeId] ? `${nodeNames[cal.nodeId]} #${cal.nodeId}` : `Node #${cal.nodeId}`;
      const tEl = $('#cal-title'); if (tEl) tEl.textContent = `Calibrate ${nm}`;
      const nEl = $('#cal-nodename'); if (nEl) nEl.textContent = nm;
      const m = $('#cal-modal'); if (m) m.style.display = 'flex';
      calRender();
    };
    const closeCal = () => {
      cal.open = false;
      if (cal.recTimer) { clearTimeout(cal.recTimer); cal.recTimer = null; }
      cal.rec = null;
      const rb = $('#cal-record'); if (rb) { rb.disabled = false; rb.textContent = 'Record calibration (15s)'; }
      const m = $('#cal-modal'); if (m) m.style.display = 'none';
    };

    const recordCal = async (btn) => {
      if (cal.rec || cal.nodeId == null) return;
      cal.rec = { n: 0, motion: 0, act: 0, share: 0, rssi: 0, peakShare: 0 };
      const SECS = 15, started = Date.now();
      btn.disabled = true;
      const tick = () => {
        if (!cal.rec) return;
        const left = Math.max(0, SECS - Math.round((Date.now() - started) / 1000));
        btn.textContent = `Recording… ${left}s (move near it)`;
        if (left > 0) cal.recTimer = setTimeout(tick, 250);
      };
      tick();
      await new Promise((r) => setTimeout(r, SECS * 1000));
      const rec = cal.rec; cal.rec = null;
      btn.disabled = false; btn.textContent = 'Record calibration (15s)';
      if (!rec || rec.n < 5) { toast('Not enough live frames — retry while moving near the node.', 'warn'); return; }
      const entry = {
        node_id: Number(cal.nodeId),
        mean_motion: +(rec.motion / rec.n).toFixed(5),
        mean_activity: +(rec.act / rec.n).toFixed(5),
        mean_share: +(rec.share / rec.n).toFixed(4),
        peak_proximity: +rec.peakShare.toFixed(4),
        mean_rssi: +(rec.rssi / rec.n).toFixed(1),
        samples: rec.n,
        ts: new Date().toISOString(),
      };
      // Merge into the shared per-node calibration map on the server config.
      let store = {};
      try { const c = await fetchJSON('/api/config'); store = (c && c.rusense_node_calibration) || {}; } catch (_) {}
      store[String(cal.nodeId)] = entry;
      try {
        const resp = await fetch('/api/config', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rusense_node_calibration: store }),
        });
        if (resp.ok) toast(`Saved calibration for node #${cal.nodeId} (peak ${Math.round(entry.peak_proximity * 100)}%, ${rec.n} frames).`, 'ok');
        else toast('Save failed — config endpoint rejected the write.', 'bad');
      } catch (_) { toast('Save failed — could not reach the server.', 'bad'); }
    };

    const offCal = sensingService.onData(calFeed);
    // Delegated: Calibrate buttons live in rows that get re-rendered each refresh.
    $('#n-body').addEventListener('click', (e) => {
      const b = e.target.closest('[data-cal-node]');
      if (b) openCal(b.getAttribute('data-cal-node'));
    });
    $('#cal-close').addEventListener('click', closeCal);
    $('#cal-modal').addEventListener('click', (e) => { if (e.target.id === 'cal-modal') closeCal(); });
    $('#cal-record').addEventListener('click', (e) => recordCal(e.currentTarget));
    $('#cal-reset').addEventListener('click', () => {
      cal.base = {}; cal.peak = 0; cal.smooth = 0; cal.selPeakAct = 0;
      toast('Baselines reset — hold still a few seconds to relearn the quiet floor.', 'info');
    });

    refresh();
    $('#n-refresh').addEventListener('click', refresh);
    const logsBtn = $('#n-logs');
    if (logsBtn) logsBtn.addEventListener('click', (e) => captureLogs(e.currentTarget));
    const t = setInterval(refresh, 4000);
    return () => { clearInterval(t); capturing = false; offCal(); if (cal.recTimer) clearTimeout(cal.recTimer); };
  },
};
