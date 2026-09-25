// Dashboard — live operator overview. No marketing; leads with real data.
import { icons } from '../icons.js';
import { html, $, fetchJSON, fmt, sparkPath, throttleLatest } from '../lib.js?v=20260704-sparkfit';
import { sensingService } from '../../services/sensing.service.js';
import { makeVitalHold } from '../vital-hold.js?v=20260704-sparkfit';

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

function bigStat(label, id, unit = '') {
  return `<div class="stat">
    <span class="stat-label">${label}</span>
    <span class="flex items-baseline gap-1"><span class="stat-value" id="${id}">—</span>
    ${unit ? `<span class="text-sm text-ink-muted">${unit}</span>` : ''}</span>
  </div>`;
}

// Local-time timestamp for a sighting (epoch seconds).
function fmtLocalTime(ts) {
  try {
    return new Date(ts * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return '—'; }
}

// Human "seen for" duration from a second count.
function fmtDuration(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60), s = sec % 60;
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

// Path for a sparse trend series: x is positioned by bucket TIME (not index) so
// gaps in coverage render as gaps in the line, and missing values lift the pen.
function trendPath(buckets, key, t0, t1, w, h, lo, hi) {
  const span = (t1 - t0) || 1, vspan = (hi - lo) || 1;
  let d = '', pen = false;
  for (const b of buckets) {
    const v = b[key];
    if (v == null) { pen = false; continue; }
    const x = ((b.t - t0) / span) * w;
    const y = h - 2 - ((v - lo) / vspan) * (h - 4);
    d += `${pen ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`;
    pen = true;
  }
  return d;
}

// Dots for the same series — vitals are sparse enough that an isolated bucket
// (a single confident reading between long gaps) would be an invisible
// zero-length path segment without a marker.
function trendDots(buckets, key, t0, t1, w, h, lo, hi) {
  const span = (t1 - t0) || 1, vspan = (hi - lo) || 1;
  return buckets.map((b) => {
    const v = b[key];
    if (v == null) return '';
    const x = ((b.t - t0) / span) * w;
    const y = h - 2 - ((v - lo) / vspan) * (h - 4);
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="1.6"/>`;
  }).join('');
}

// Coarsen 5-min buckets into larger groups (weighted by sample counts) so the
// 7-day view draws ~340 points instead of 2016.
function mergeBuckets(buckets, groupS) {
  const out = new Map();
  for (const b of buckets) {
    const t = b.t - (b.t % groupS);
    const g = out.get(t) || { t, n: 0, pres: 0, hrS: 0, hrN: 0, brS: 0, brN: 0 };
    g.n += b.n || 0;
    g.pres += (b.duty || 0) * (b.n || 0);
    if (b.hr != null) { g.hrS += b.hr * (b.hr_n || 1); g.hrN += b.hr_n || 1; }
    if (b.br != null) { g.brS += b.br * (b.br_n || 1); g.brN += b.br_n || 1; }
    out.set(t, g);
  }
  return [...out.values()].sort((a, b) => a.t - b.t).map((g) => ({
    t: g.t, n: g.n, duty: g.n ? g.pres / g.n : 0,
    hr: g.hrN ? g.hrS / g.hrN : null, hr_n: g.hrN || 0,
    br: g.brN ? g.brS / g.brN : null, br_n: g.brN || 0,
  }));
}

export default {
  id: 'dashboard',
  label: 'Dashboard',
  icon: icons.dashboard,

  async mount(root) {
    // Hold vitals through brief confidence dips / dropped frames; clear to "—"
    // only after holdMs of no confident reading. Both the live WS frames and the
    // 4 s REST poll feed the same holders, so they reinforce rather than fight.
    this._hrHold = makeVitalHold({ holdMs: 30000, decimals: 0 });
    this._brHold = makeVitalHold({ holdMs: 30000, decimals: 1 });
    // Presence toggles 0↔1 at ~46 Hz (even in an empty room); smooth it with a
    // duty-cycle hysteresis biased toward PRESENT. Fed at full frame rate below.
    // Custom node names live in Ragnar config (set in Settings), not in the
    // sensing-server's /api/v1/nodes roster — fetch them once to label nodes.
    this._nodeNames = {};
    fetchJSON('/api/config').then((c) => {
      this._nodeNames = (c && c.rusense_node_names) || {};
      // Health mode leads with the trends: lift the card above the signal grid
      // (the sparse instant readings matter less than the long-horizon trend).
      if (c && c.rusense_mode === 'health') {
        const tc = $('#trends-card'), grid = $('#dash-grid');
        if (tc && grid && grid.parentNode) grid.parentNode.insertBefore(tc, grid);
      }
    });
    this._sightings = [];
    this._nodePeople = null;  // corroborated people count (median across nodes)
    this._gf = null;          // last geofence verdict (5s poll)
    // Authoritative presence comes from the BACKEND (/api/rusense/presence):
    // the same smoothed, model-aware duty decision that gates alerts. The
    // frontend no longer re-derives presence from its own noisier 2s window.
    this._bk = { present: false, people: 0, motion: 'absent', fresh: false };
    this._trendHours = 24;
    this._trendBuckets = [];
    this._trendBucketS = 300;

    root.appendChild(html`
      <section class="space-y-5">
        <!-- Presence banner -->
        <div id="presence-card" class="card card-pad flex items-center gap-4">
          <span id="presence-dot" class="dot w-3.5 h-3.5 bg-ink-4 rs-pulse"></span>
          <div class="flex-1">
            <div id="presence-text" class="text-lg font-semibold flex items-center gap-2"><span class="rs-spin text-ink-muted"></span>Connecting…</div>
            <div id="presence-sub" class="text-sm text-ink-muted">Waiting for the sensing stream</div>
          </div>
          <span id="motion-badge" class="badge-mut rs-pulse">—</span>
        </div>

        <!-- Key live stats -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
          ${bigStat('People', 'stat-people')}
          ${bigStat('Confidence', 'stat-conf')}
          ${bigStat('Breathing', 'stat-br', 'bpm')}
          ${bigStat('Heart rate', 'stat-hr', 'bpm')}
        </div>

        <div id="dash-grid" class="grid gap-4 lg:grid-cols-2">
          <!-- Signal -->
          <div class="card card-pad space-y-4">
            <div class="flex items-center justify-between">
              <h2 class="card-title">Signal</h2>
              <span id="rssi-now" class="text-sm font-mono text-ink-soft">—</span>
            </div>
            <svg id="rssi-spark" viewBox="0 0 300 60" preserveAspectRatio="none" class="w-full h-16">
              <path id="rssi-path" fill="none" stroke="currentColor" class="text-brand-400" stroke-width="1.5"/>
            </svg>
            <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <div class="flex justify-between"><dt class="text-ink-muted">Variance</dt><dd id="f-var" class="font-mono">—</dd></div>
              <div class="flex justify-between"><dt class="text-ink-muted">Motion band</dt><dd id="f-motion" class="font-mono">—</dd></div>
              <div class="flex justify-between"><dt class="text-ink-muted">Breath band</dt><dd id="f-breath" class="font-mono">—</dd></div>
              <div class="flex justify-between"><dt class="text-ink-muted">Dom. freq</dt><dd id="f-freq" class="font-mono">—</dd></div>
            </dl>
          </div>

          <!-- RuSense + node health -->
          <div class="card card-pad space-y-4">
            <div class="flex items-center justify-between">
              <h2 class="card-title">RuSense health</h2>
              <span id="rs-backend" class="badge-mut">—</span>
            </div>
            <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
              <div class="flex justify-between"><dt class="text-ink-muted">Source</dt><dd id="rs-source" class="font-mono">—</dd></div>
              <div class="flex justify-between"><dt class="text-ink-muted">Nodes online</dt><dd id="rs-nodes" class="font-mono">—</dd></div>
            </dl>
            <div id="rs-node-list" class="space-y-2 pt-1 border-t border-ink-3 text-sm">
              <div class="text-ink-muted">Loading nodes…</div>
            </div>
          </div>
        </div>

        <!-- Recent sightings — a reviewable log of confirmed presence alerts -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Recent sightings</h2>
            <span class="text-xs text-ink-muted">last 5 · presence alerts</span>
          </div>
          <div id="sightings-body">
            <div class="text-sm text-ink-muted py-2">Loading…</div>
          </div>
        </div>

        <!-- Health trends — long-horizon vitals/activity from the history ring.
             The health value is the TREND (resting rates drifting over days),
             not any single sparse reading. -->
        <div id="trends-card" class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Health trends</h2>
            <div class="flex items-center gap-1">
              <button id="trend-24h" class="badge-ok">24h</button>
              <button id="trend-7d" class="badge-mut">7d</button>
            </div>
          </div>
          <div id="trend-body">
            <div class="text-sm text-ink-muted py-2">Loading…</div>
          </div>
        </div>
      </section>`);

    // ── Live sensing frames ──
    // Frames can arrive 10-20×/s; coalesce to a calm cadence so the cards
    // don't re-render (and visibly jitter) several times a second.
    const off = sensingService.onData(throttleLatest((d) => this.applyFrame(d), 250));
    // Presence needs the raw ~46 Hz signal to measure its duty cycle, so feed it
    // from a separate un-throttled listener (cheap: no DOM unless state changes).
    const offP = sensingService.onData((d) => this.applyPresence(d));

    // RuSense backend + node health (replaces generic host CPU/mem/disk).
    const refreshHealth = async () => {
      const [st, svc, n, gf] = await Promise.all([
        fetchJSON('/api/v1/status'),
        fetchJSON('/api/sensing/status'),
        fetchJSON('/api/v1/nodes'),
        fetchJSON('/api/rusense/geofence'),
      ]);
      // Last geofence verdict — lets the presence banner tell "person in the
      // room" apart from "through-wall disturbance" (same rule the backend
      // uses to suppress alerts: energetic but NOT corroborated interior).
      this._gf = (gf && gf.enabled && gf.verdict && gf.verdict.ok) ? gf.verdict : null;
      const be = $('#rs-backend');
      if (be) {
        const running = svc?.active === true;
        be.textContent = running ? (st?.status || 'running') : (st ? 'reachable' : 'unreachable');
        be.className = running ? 'badge-ok' : (st ? 'badge-warn' : 'badge-bad');
      }
      const src = $('#rs-source'); if (src) src.textContent = st?.source || '—';
      const nodes = (n?.nodes || []).slice().sort((a, b) => (a.node_id || 0) - (b.node_id || 0));
      const live = nodes.filter((x) => nodeHealth(x.last_seen_ms).key === 'live').length;
      // People: per-node person_count ghosts on single nodes, so use the LOWER
      // MEDIAN across live nodes (same corroboration rule as the backend) —
      // a count is only believed when a majority of nodes agree.
      const counts = nodes.filter((x) => nodeHealth(x.last_seen_ms).key === 'live' && typeof x.person_count === 'number')
        .map((x) => x.person_count).sort((a, b) => a - b);
      this._nodePeople = counts.length ? counts[Math.floor((counts.length - 1) / 2)] : null;
      const ne = $('#rs-nodes'); if (ne) ne.textContent = `${live}/${nodes.length} live`;
      const list = $('#rs-node-list');
      if (list) {
        list.innerHTML = nodes.length ? nodes.map((x) => {
          const h = nodeHealth(x.last_seen_ms);
          const rssi = x.rssi_dbm != null ? `${Number(x.rssi_dbm).toFixed(0)} dBm` : '—';
          const nm = this._nodeNames[String(x.node_id)];
          const label = nm ? `${nm} <span class="text-ink-muted">#${x.node_id}</span>` : `Node ${x.node_id}`;
          return `<div class="flex items-center justify-between">
            <span class="flex items-center gap-2"><span class="dot w-2 h-2 ${h.dot}" title="${h.label} · last frame ${fmt.ago((x.last_seen_ms ?? 0) / 1000)}"></span>${label}</span>
            <span class="font-mono text-ink-soft">${rssi}</span>
          </div>`;
        }).join('') : '<div class="text-ink-muted">No nodes reporting</div>';
      }
    };
    const refreshSightings = async () => {
      const r = await fetchJSON('/api/rusense/sightings');
      this._sightings = (r?.sightings || []).slice(0, 5);
      this.renderSightings();
    };
    const refreshVitals = async () => {
      // Vitals may not ride every WS frame — poll the dedicated endpoint.
      const v = await fetchJSON('/api/v1/vital-signs');
      const vs = v?.vital_signs; if (!vs) return;
      const present = this._bk.present === true;
      this._brHold.push(vs.breathing_rate_bpm, vs.breathing_confidence, present);
      this._hrHold.push(vs.heart_rate_bpm, vs.heartbeat_confidence, present);
      this.renderVitals();
    };

    const refreshTrends = async () => {
      const r = await fetchJSON(`/api/rusense/vitals-history?hours=${this._trendHours}`);
      if (!r || !Array.isArray(r.buckets)) return;
      this._trendBucketS = r.bucket_s || 300;
      // 7d = 2016 raw buckets; coarsen to 30-min groups for a sane path.
      this._trendBuckets = this._trendHours > 48 ? mergeBuckets(r.buckets, 1800) : r.buckets;
      this.renderTrends();
    };
    const setRange = (hours) => {
      this._trendHours = hours;
      const b24 = $('#trend-24h'), b7 = $('#trend-7d');
      if (b24) b24.className = hours === 24 ? 'badge-ok' : 'badge-mut';
      if (b7) b7.className = hours === 168 ? 'badge-ok' : 'badge-mut';
      refreshTrends();
    };
    const b24 = $('#trend-24h'), b7 = $('#trend-7d');
    if (b24) b24.addEventListener('click', () => setRange(24));
    if (b7) b7.addEventListener('click', () => setRange(168));

    // Authoritative presence from the backend (~1.3s poll — presence doesn't need
    // frame-rate). If the backend loop has stalled (age_s large / unreachable),
    // hold the last state rather than flapping to empty.
    const refreshPresence = async () => {
      const p = await fetchJSON('/api/rusense/presence');
      if (!p || p.success === false) { this._bk.fresh = false; return; }
      if (p.age_s != null && p.age_s > 12) { this._bk.fresh = false; return; }
      this._bk = { present: p.present === true, people: p.people || 0,
        motion: p.motion_level || 'absent', fresh: true };
      this.renderPresence();
    };

    refreshHealth(); refreshVitals(); refreshSightings(); refreshTrends(); refreshPresence();
    const t1 = setInterval(refreshHealth, 5000);
    const t2 = setInterval(refreshSightings, 7000);
    const t3 = setInterval(refreshVitals, 4000);
    // Re-render on a steady tick so a held value still clears to "—" after the
    // hold window even if frames/polls stop arriving (stalled stream).
    const t4 = setInterval(() => { this.renderVitals(); this.renderSightings(); }, 1000);
    const t5 = setInterval(refreshTrends, 60000);
    const t6 = setInterval(refreshPresence, 1300);

    return () => { off(); offP(); clearInterval(t1); clearInterval(t2); clearInterval(t3); clearInterval(t4); clearInterval(t5); clearInterval(t6); };
  },

  renderVitals() {
    const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
    set('#stat-br', this._brHold.text());
    set('#stat-hr', this._hrHold.text());
  },

  // Health trends: three sparse-tolerant sparklines (HR / breathing / activity)
  // + resting averages. Vitals only exist while a subject is STILL, so the
  // charts show dots-with-gaps by design — the trend line matters, not density.
  renderTrends() {
    const body = $('#trend-body'); if (!body) return;
    const bks = this._trendBuckets || [];
    const t1 = Date.now() / 1000, t0 = t1 - this._trendHours * 3600;
    if (!bks.length) {
      body.innerHTML = '<div class="text-sm text-ink-muted py-2">Collecting history — trends appear after a few minutes of sensing.</div>';
      return;
    }
    const hrB = bks.filter((b) => b.hr != null);
    const brB = bks.filter((b) => b.br != null);
    // Resting rate = overnight readings (00:00–06:00 local) when there are any;
    // otherwise all confident readings in range. Weighted by reading count.
    const resting = (arr, key, nKey) => {
      let pool = arr.filter((b) => { const h = new Date(b.t * 1000).getHours(); return h < 6; });
      if (!pool.length) pool = arr;
      let sum = 0, n = 0;
      for (const b of pool) { const w = b[nKey] || 1; sum += b[key] * w; n += w; }
      return n ? sum / n : null;
    };
    const restHr = hrB.length ? resting(hrB, 'hr', 'hr_n') : null;
    const restBr = brB.length ? resting(brB, 'br', 'br_n') : null;
    const activeS = bks.reduce((a, b) => a + (b.duty || 0) * this._trendBucketS, 0);
    const range = (arr, key, pad, floor) => {
      if (!arr.length) return [0, 1];
      const vs = arr.map((b) => b[key]);
      return [Math.max(floor, Math.min(...vs) - pad), Math.max(...vs) + pad];
    };
    const [hrLo, hrHi] = range(hrB, 'hr', 5, 30);
    const [brLo, brHi] = range(brB, 'br', 2, 4);
    const last = (arr, key, f) => (arr.length ? f(arr[arr.length - 1][key]) : '—');
    const chart = (label, latest, series, key, lo, hi, color, dots) => `
      <div class="space-y-1">
        <div class="flex items-baseline justify-between text-sm">
          <span class="text-ink-muted">${label}</span>
          <span class="font-mono">${latest}</span>
        </div>
        <svg viewBox="0 0 300 40" preserveAspectRatio="none" class="w-full h-10 ${color}">
          <path d="${trendPath(series, key, t0, t1, 300, 40, lo, hi)}" fill="none" stroke="currentColor" stroke-width="1.5"/>
          ${dots ? `<g fill="currentColor">${trendDots(series, key, t0, t1, 300, 40, lo, hi)}</g>` : ''}
        </svg>
      </div>`;
    body.innerHTML = `
      <div class="grid gap-4 sm:grid-cols-3">
        ${chart('Heart rate', last(hrB, 'hr', (v) => `${Math.round(v)} bpm`), hrB, 'hr', hrLo, hrHi, 'text-bad', true)}
        ${chart('Breathing', last(brB, 'br', (v) => `${Number(v).toFixed(1)} bpm`), brB, 'br', brLo, brHi, 'text-brand-400', true)}
        ${chart('Activity', last(bks, 'duty', (v) => `${Math.round(v * 100)}%`), bks, 'duty', 0, 1, 'text-ok', false)}
      </div>
      <div class="grid grid-cols-3 gap-3 text-sm pt-2 border-t border-ink-3">
        <div><div class="text-ink-muted text-xs">Resting heart rate</div><div class="font-mono">${restHr != null ? `${Math.round(restHr)} bpm` : '—'}</div></div>
        <div><div class="text-ink-muted text-xs">Resting breathing</div><div class="font-mono">${restBr != null ? `${restBr.toFixed(1)} bpm` : '—'}</div></div>
        <div><div class="text-ink-muted text-xs">Active time</div><div class="font-mono">${fmtDuration(activeS)}</div></div>
      </div>`;
  },

  // Render the sightings table from cached rows. Called on each 7s fetch and on
  // the 1s tick so the open sighting's "seen for" duration counts up live.
  renderSightings() {
    const body = $('#sightings-body'); if (!body) return;
    const rows = this._sightings || [];
    if (!rows.length) {
      body.innerHTML = '<div class="text-sm text-ink-muted py-2">No sightings yet — confirmed presence alerts will appear here.</div>';
      return;
    }
    const now = Date.now() / 1000;
    const cell = (v) => `<td class="text-right font-mono py-2">${v}</td>`;
    body.innerHTML = `<div class="overflow-x-auto -mx-1"><table class="w-full text-sm min-w-[480px]">
      <thead><tr class="text-ink-muted">
        <th class="text-left font-semibold py-2">Time</th>
        <th class="text-right font-semibold py-2">Seen for</th>
        <th class="text-right font-semibold py-2">Confidence</th>
        <th class="text-right font-semibold py-2">Heart rate</th>
        <th class="text-right font-semibold py-2">Breathing</th>
      </tr></thead>
      <tbody>${rows.map((s) => {
        const conf = s.confidence != null ? `${Math.round(s.confidence * 100)}%` : '—';
        const hr = s.hr != null ? `${Math.round(s.hr)} bpm` : '—';
        const br = s.br != null ? `${Number(s.br).toFixed(1)} bpm` : '—';
        const live = s.ended_ts == null;
        const dur = live ? (now - s.ts) : (s.ended_ts - s.ts);
        // Live = green; a very short locked sighting (<3s) is more likely a
        // perimeter leak than a real occupant, so flag it amber.
        const durCls = live ? 'text-ok' : (dur < 3 ? 'text-warn' : '');
        const durText = live ? `${fmtDuration(dur)} · live` : fmtDuration(dur);
        return `<tr class="border-t border-ink-3">
          <td class="text-left font-mono text-ink-soft py-2">${fmtLocalTime(s.ts)}</td>
          <td class="text-right font-mono py-2 ${durCls}">${durText}</td>
          ${cell(conf)}${cell(hr)}${cell(br)}</tr>`;
      }).join('')}</tbody></table></div>`;
  },

  // Full-rate vitals push. Presence itself is NOT decided here anymore (the
  // backend owns it — see refreshPresence); we only keep the sparse confident
  // vital readings, gated on the backend's present flag.
  applyPresence(d) {
    if (!d || !d.classification) return;
    this._lastSource = d.source;
    const present = this._bk.present === true;
    const dvs = d.vital_signs || {};
    this._brHold.push(dvs.breathing_rate_bpm, dvs.breathing_confidence, present);
    this._hrHold.push(dvs.heart_rate_bpm, dvs.heartbeat_confidence, present);
  },

  // Render the presence banner from the BACKEND decision + geofence verdict.
  renderPresence() {
    const bk = this._bk;
    const present = bk.present === true;
    // Through-wall discrimination: a body in the next room (one node sees it
    // through the wall) is energetic but not interior. Show it as its own amber
    // state rather than "Person present" — same rule that suppresses alerts.
    const gfOutside = present && this._gf && this._gf.energetic && !this._gf.inside_perimeter;
    const people = present ? (bk.people || 1) : 0;
    const motion = present ? (bk.motion || 'present') : 'absent';
    const simulated = this._lastSource === 'simulated';
    const dot = $('#presence-dot'), txt = $('#presence-text'), sub = $('#presence-sub'), mb = $('#motion-badge');
    if (dot) dot.className = `dot w-3.5 h-3.5 ${present ? (gfOutside ? 'bg-warn pulse-live' : 'bg-ok pulse-live') : 'bg-ink-4'}`;
    if (txt) txt.textContent = !present ? 'Room empty'
      : gfOutside ? 'Activity outside perimeter'
      : (people > 1 ? `${people} people present` : 'Person present');
    if (sub) sub.textContent = simulated ? 'Simulated data (no live hardware)'
      : gfOutside ? 'Disturbance not corroborated inside the room — next room or hallway (alerts suppressed)'
      : `${motion.replace(/_/g, ' ')} · source: ${this._lastSource || 'esp32'}`;
    if (mb) {
      const kind = motion === 'active' ? 'badge-ok' : (present ? 'badge-warn' : 'badge-mut');
      mb.className = kind; mb.textContent = motion.replace(/_/g, ' ');
    }
    const pe = $('#stat-people'); if (pe) pe.textContent = String(people);
  },

  applyFrame(d) {
    if (!d || !d.classification) return;
    const c = d.classification;

    const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
    set('#stat-conf', fmt.pct(c.confidence, 0));
    // Vitals are pushed at full rate in applyPresence(); here we just re-render.
    this.renderVitals();

    const f = d.features || {};
    set('#f-var', fmt.num(f.variance, 3));
    set('#f-motion', fmt.num(f.motion_band_power, 3));
    set('#f-breath', fmt.num(f.breathing_band_power, 3));
    set('#f-freq', `${fmt.num(f.dominant_freq_hz, 2)} Hz`);
    set('#rssi-now', fmt.dbm(f.mean_rssi));

    const hist = sensingService.getRssiHistory();
    const path = $('#rssi-path');
    if (path && hist.length > 1) path.setAttribute('d', sparkPath(hist, 300, 60, -90, -30));
  },
};
