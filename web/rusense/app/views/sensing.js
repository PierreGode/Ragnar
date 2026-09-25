// Sensing — live CSI features, classification, vital signs + signal-field heatmap.
import { icons } from '../icons.js';
import { html, $, fmt, throttleLatest } from '../lib.js?v=20260704-sparkfit';
import { sensingService } from '../../services/sensing.service.js';
import { geofenceService } from '../../services/geofence.service.js?v=20260628-geofence';
import { makeVitalHold } from '../vital-hold.js?v=20260704-sparkfit';
import { makePresenceHold } from '../presence-hold.js?v=20260701-cal';

// Teal→amber→red ramp for the field heatmap.
function heat(v) {
  v = Math.max(0, Math.min(1, v));
  const stops = [[15, 30, 38], [33, 128, 141], [245, 158, 11], [239, 68, 68]];
  const seg = v * (stops.length - 1);
  const i = Math.min(stops.length - 2, Math.floor(seg));
  const t = seg - i;
  const c = (a, b) => Math.round(a + (b - a) * t);
  const [r, g, b] = [0, 1, 2].map((k) => c(stops[i][k], stops[i + 1][k]));
  return `rgb(${r},${g},${b})`;
}

export default {
  id: 'sensing',
  label: 'Sensing',
  icon: icons.sensing,

  async mount(root) {
    // Hold vitals through brief confidence dips / dropped frames; a steady tick
    // (below) clears them to "—" after holdMs so a stalled stream can't freeze.
    const hrHold = makeVitalHold({ holdMs: 30000, decimals: 0 });
    const brHold = makeVitalHold({ holdMs: 30000, decimals: 1 });
    // Presence flickers 0↔1 at ~46 Hz; smooth it (duty-cycle hysteresis) from a
    // full-rate listener below. smPresent is the smoothed state the rest reads.
    const presence = makePresenceHold();
    let smPresent = false, lastMotion = '', presSig = null;

    root.appendChild(html`
      <section class="space-y-5">
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Signal field</h2>
            <span id="sf-status" class="badge-mut">no data</span>
          </div>
          <canvas id="sf-canvas" class="w-full rounded-lg bg-ink-0 aspect-[2/1]" aria-label="Signal field heatmap"></canvas>
          <p class="text-xs text-ink-muted">CSI energy map across the sensing grid. Brighter = stronger perturbation.</p>
        </div>

        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between gap-2">
            <h2 class="card-title">Perimeter geofence <span class="text-xs text-ink-muted font-normal">prototype</span></h2>
            <span id="gf-verdict" class="badge-mut shrink-0" style="min-width:7.5rem;justify-content:center">—</span>
          </div>
          <canvas id="gf-canvas" class="w-full rounded-lg bg-ink-0 aspect-[3/2]" aria-label="Room geofence plan"></canvas>
          <div class="grid grid-cols-3 gap-3 text-sm">
            <div class="stat"><span class="stat-label">Disturbed corners</span><span class="stat-value" id="gf-hot">—</span></div>
            <div class="stat"><span class="stat-label">Disturbance</span><span class="stat-value" id="gf-total">—</span></div>
            <div class="stat"><span class="stat-label">Inside score</span><span class="stat-value" id="gf-score">—</span></div>
          </div>
          <p class="text-xs text-ink-muted truncate" id="gf-reason" title="">—</p>
          <p class="text-xs text-ink-muted" id="gf-note">
            Motion is confined to the polygon of mapped node corners (Settings → node X/Y).
            A disturbance that lights up only one corner — a hallway walk-by — is rejected as outside.
            Coarse zone-level filter, not a hard RF wall.
          </p>
        </div>

        <div class="grid gap-4 sm:grid-cols-2">
          <div class="card card-pad space-y-3">
            <h2 class="card-title">Classification</h2>
            <dl class="space-y-2 text-sm" id="cls-list">
              ${[['Presence', 'cls-presence'], ['Motion level', 'cls-motion'], ['Confidence', 'cls-conf'], ['Posture', 'cls-posture'], ['Signal quality', 'cls-quality']]
                .map(([l, id]) => `<div class="flex justify-between border-b border-ink-3 pb-2 last:border-0"><dt class="text-ink-muted">${l}</dt><dd id="${id}" class="font-mono">—</dd></div>`).join('')}
            </dl>
          </div>

          <div class="card card-pad space-y-3">
            <h2 class="card-title">Vital signs</h2>
            <div class="grid grid-cols-2 gap-3">
              <div class="stat"><span class="stat-label">Breathing</span><span class="stat-value" id="vs-br">—</span><span class="text-xs text-ink-muted" id="vs-br-c">confidence —</span></div>
              <div class="stat"><span class="stat-label">Heart rate</span><span class="stat-value" id="vs-hr">—</span><span class="text-xs text-ink-muted" id="vs-hr-c">confidence —</span></div>
            </div>
            <div class="text-xs text-ink-muted" id="vs-buf">buffer —</div>
          </div>
        </div>

        <div class="card card-pad space-y-3">
          <h2 class="card-title">CSI features</h2>
          <dl class="grid grid-cols-2 lg:grid-cols-4 gap-x-4 gap-y-3 text-sm">
            ${[['Mean RSSI', 'ft-rssi'], ['Variance', 'ft-var'], ['Motion band', 'ft-motion'], ['Breath band', 'ft-breath'], ['Dominant freq', 'ft-freq'], ['Change points', 'ft-cp'], ['Spectral power', 'ft-spec'], ['Tick', 'ft-tick']]
              .map(([l, id]) => `<div><dt class="text-ink-muted text-xs">${l}</dt><dd id="${id}" class="font-mono">—</dd></div>`).join('')}
          </dl>
        </div>
      </section>`);

    const canvas = $('#sf-canvas');
    const ctx = canvas.getContext('2d');
    const resize = () => { canvas.width = canvas.clientWidth; canvas.height = canvas.clientHeight; };
    resize();
    window.addEventListener('resize', resize);

    const draw = (field) => {
      if (!field?.values?.length || !field.grid_size) return;
      const [gx, , gz] = field.grid_size;
      const cols = gx || Math.sqrt(field.values.length) | 0;
      const rows = gz || (field.values.length / cols) | 0;
      const cw = canvas.width / cols, ch = canvas.height / rows;
      for (let z = 0; z < rows; z++) {
        for (let x = 0; x < cols; x++) {
          ctx.fillStyle = heat(field.values[z * cols + x] || 0);
          ctx.fillRect(x * cw, z * ch, cw + 1, ch + 1);
        }
      }
    };

    // --- Geofence floor-plan ---------------------------------------------
    const gfCanvas = $('#gf-canvas');
    const gfCtx = gfCanvas.getContext('2d');
    const gfResize = () => { gfCanvas.width = gfCanvas.clientWidth; gfCanvas.height = gfCanvas.clientHeight; };
    gfResize();
    window.addEventListener('resize', gfResize);

    let lastVerdict = null;
    const drawGeofence = (v) => {
      const W = gfCanvas.width, H = gfCanvas.height, pad = 28;
      gfCtx.clearRect(0, 0, W, H);
      if (!v || !v.ok || !v.polygon.length) {
        gfCtx.fillStyle = '#7b8794';
        gfCtx.font = '13px system-ui, sans-serif';
        gfCtx.textAlign = 'center';
        gfCtx.fillText(v?.reason || 'map node corners in Settings', W / 2, H / 2);
        return;
      }
      // World→screen: fit polygon (+ nodes) bounds into the padded canvas, y up.
      const pts = v.nodes;
      const xs = pts.map((p) => p.x), ys = pts.map((p) => p.y);
      const minX = Math.min(...xs), maxX = Math.max(...xs);
      const minY = Math.min(...ys), maxY = Math.max(...ys);
      const sx = (maxX - minX) || 1, sy = (maxY - minY) || 1;
      const scale = Math.min((W - 2 * pad) / sx, (H - 2 * pad) / sy);
      const ox = (W - sx * scale) / 2, oy = (H - sy * scale) / 2;
      const tx = (x) => ox + (x - minX) * scale;
      const ty = (y) => H - (oy + (y - minY) * scale); // flip y

      const ring = (poly, stroke, fill) => {
        if (poly.length < 2) return;
        gfCtx.beginPath();
        poly.forEach((p, i) => { const X = tx(p.x), Y = ty(p.y); i ? gfCtx.lineTo(X, Y) : gfCtx.moveTo(X, Y); });
        gfCtx.closePath();
        if (fill) { gfCtx.fillStyle = fill; gfCtx.fill(); }
        if (stroke) { gfCtx.strokeStyle = stroke; gfCtx.lineWidth = 2; gfCtx.stroke(); }
      };

      // Perimeter (outer) + inset (effective fence).
      ring(v.polygon, 'rgba(120,135,148,0.55)', 'rgba(33,128,141,0.06)');
      ring(v.inset, 'rgba(120,135,148,0.25)', null);

      // Node corners, coloured by disturbance.
      for (const n of v.nodes) {
        const X = tx(n.x), Y = ty(n.y);
        gfCtx.beginPath(); gfCtx.arc(X, Y, n.hot ? 9 : 6, 0, Math.PI * 2);
        gfCtx.fillStyle = heat(n.disturbance); gfCtx.fill();
        if (n.hot) { gfCtx.strokeStyle = '#fff'; gfCtx.lineWidth = 1.5; gfCtx.stroke(); }
        gfCtx.fillStyle = '#cdd6df'; gfCtx.font = '11px system-ui, sans-serif'; gfCtx.textAlign = 'center';
        gfCtx.fillText(n.id, X, Y - 12);
      }

      // Disturbance centroid.
      if (v.centroid) {
        const X = tx(v.centroid.x), Y = ty(v.centroid.y);
        gfCtx.beginPath(); gfCtx.arc(X, Y, 7, 0, Math.PI * 2);
        gfCtx.fillStyle = v.insideMotion ? 'rgba(34,197,94,0.9)' : 'rgba(245,158,11,0.9)';
        gfCtx.fill();
        gfCtx.strokeStyle = '#0b0f12'; gfCtx.lineWidth = 2; gfCtx.stroke();
      }
    };

    const offGeo = geofenceService.onVerdict(throttleLatest((v) => {
      lastVerdict = v;
      const badge = $('#gf-verdict');
      if (badge) {
        if (!v.ok) { badge.textContent = 'not mapped'; badge.className = 'badge-mut shrink-0'; }
        else if (v.insideMotion) { badge.textContent = 'MOTION INSIDE'; badge.className = 'badge-ok shrink-0'; }
        else if (v.reason === 'quiet') { badge.textContent = 'quiet'; badge.className = 'badge-mut shrink-0'; }
        else { badge.textContent = 'outside'; badge.className = 'badge-warn shrink-0'; }
      }
      const set = (id, val) => { const e = $(id); if (e) e.textContent = val; };
      set('#gf-hot', v.ok ? `${v.hotCount} / ${v.nodes.length}` : '—');
      set('#gf-total', v.ok ? fmt.num(v.total, 2) : '—');
      set('#gf-score', v.ok ? fmt.pct(v.score, 0) : '—');
      const reason = $('#gf-reason');
      if (reason) { reason.textContent = v.reason || '—'; reason.title = v.reason || ''; }
      drawGeofence(v);
    }, 250));

    const off = sensingService.onData(throttleLatest((d) => {
      const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
      const c = d.classification || {}, f = d.features || {};
      // Presence + motion are rendered by the full-rate smoother listener below;
      // here we just reuse the smoothed state for vital gating.
      const present = smPresent;
      set('#cls-conf', fmt.pct(c.confidence, 0));
      set('#cls-posture', d.posture || '—');
      set('#cls-quality', d.quality_verdict || (d.signal_quality_score != null ? fmt.num(d.signal_quality_score, 2) : '—'));

      set('#ft-rssi', fmt.dbm(f.mean_rssi)); set('#ft-var', fmt.num(f.variance, 4));
      set('#ft-motion', fmt.num(f.motion_band_power, 4)); set('#ft-breath', fmt.num(f.breathing_band_power, 4));
      set('#ft-freq', `${fmt.num(f.dominant_freq_hz, 2)} Hz`); set('#ft-cp', fmt.int(f.change_points));
      set('#ft-spec', fmt.num(f.spectral_power, 4)); set('#ft-tick', fmt.int(d.tick));

      // Vitals are pushed at FULL rate in the offP listener below (confident
      // readings are sparse; this 250ms-throttled block would drop them). Here
      // we just render the held value + live confidence.
      const vs = d.vital_signs || {};
      set('#vs-br', brHold.text());
      set('#vs-hr', hrHold.text());
      set('#vs-br-c', `confidence ${fmt.pct(vs.breathing_confidence, 0)}`);
      set('#vs-hr-c', `confidence ${fmt.pct(vs.heartbeat_confidence, 0)}`);

      const st = $('#sf-status');
      if (st) { st.textContent = d.source === 'simulated' ? 'simulated' : 'live'; st.className = d.source === 'simulated' ? 'badge-warn' : 'badge-ok'; }
      draw(d.signal_field);
    }, 250));

    // Full-rate presence smoother: feed every frame, update the presence/motion
    // readout only when the smoothed state changes (no 46 Hz DOM churn).
    const offP = sensingService.onData((d) => {
      const c = d.classification || {};
      smPresent = presence.push(c);
      // Vitals at full rate (sparse confident frames would be dropped by the
      // throttle above); held 30s and rendered by the throttled block + tick.
      const vvs = d.vital_signs || {};
      brHold.push(vvs.breathing_rate_bpm, vvs.breathing_confidence, smPresent);
      hrHold.push(vvs.heart_rate_bpm, vvs.heartbeat_confidence, smPresent);
      const ml = c.motion_level || '';
      if (ml.startsWith('present') || ml === 'active') lastMotion = ml;
      const motion = smPresent ? (lastMotion || 'present') : 'absent';
      const sig = `${smPresent}|${motion}`;
      if (sig === presSig) return;
      presSig = sig;
      const pEl = $('#cls-presence');
      if (pEl) { pEl.textContent = smPresent ? 'PRESENT' : 'empty'; pEl.className = `font-mono ${smPresent ? 'text-ok' : 'text-ink-muted'}`; }
      const mEl = $('#cls-motion'); if (mEl) mEl.textContent = motion.replace(/_/g, ' ');
    });

    // Re-render held vitals on a steady tick so a stalled stream clears to "—"
    // after the hold window even without new frames.
    const vitalsTick = setInterval(() => {
      const brEl = $('#vs-br'), hrEl = $('#vs-hr');
      if (brEl) brEl.textContent = brHold.text();
      if (hrEl) hrEl.textContent = hrHold.text();
    }, 1000);

    return () => {
      off(); offP(); offGeo(); clearInterval(vitalsTick);
      window.removeEventListener('resize', resize);
      window.removeEventListener('resize', gfResize);
    };
  },
};
