// Training — models, recordings and training-run control. Wired to /api/v1/*.
import { icons } from '../icons.js';
import { html, $, fetchJSON, fmt, toast } from '../lib.js?v=20260704-sparkfit';

// Action helper: unlike fetchJSON (which collapses every failure to null), this
// reports HTTP success/failure separately and keeps any JSON body so we can
// surface the backend's own error text ("training already running", etc.) and
// never toast a false "success" when the sensing-server is down or rejects us.
async function req(method, url, body) {
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* empty / non-JSON body is fine */ }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: String(e) };
  }
}
const post = (url, body) => req('POST', url, body);
const del = (url) => req('DELETE', url);

// Pull a human message out of a response, preferring the backend's own text.
function msgOf(r, fallback) {
  return (r && r.data && (r.data.error || r.data.message || r.data.detail)) || fallback;
}

const REC_STATE_KEY = 'rusense-rec-state';
let recState = (() => {
  try { const s = JSON.parse(localStorage.getItem(REC_STATE_KEY) || 'null'); return s && s.active ? s : null; }
  catch { return null; }
})();
function persistRecState() {
  try {
    if (recState && recState.active) localStorage.setItem(REC_STATE_KEY, JSON.stringify(recState));
    else localStorage.removeItem(REC_STATE_KEY);
  } catch { /* storage unavailable — module-scope state still carries the session */ }
}
function fmtElapsed(ms) {
  const total = Math.max(0, Math.floor(ms / 1000));
  const s = total % 60, m = Math.floor(total / 60) % 60, h = Math.floor(total / 3600);
  const pad = (n) => String(n).padStart(2, '0');
  return h ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

function modelCard(m, activeId) {
  const id = m.id ?? m.name ?? '?';
  const isActive = activeId && id === activeId;
  const meta = [m.kind, m.size_mb ? `${fmt.num(m.size_mb, 1)} MB` : null, m.created].filter(Boolean).join(' · ');
  return `<div class="flex items-center gap-3 rounded-lg bg-ink-1 border border-ink-3 p-3">
    <div class="flex-1 min-w-0">
      <div class="font-medium truncate">${id} ${isActive ? '<span class="badge-ok ml-1">active</span>' : ''}</div>
      <div class="text-xs text-ink-muted truncate">${meta || '—'}</div>
    </div>
    ${isActive
      ? `<button data-act="unload" class="btn-ghost !py-1.5 !px-3 text-xs">Unload</button>`
      : `<button data-act="load" data-id="${id}" class="btn-primary !py-1.5 !px-3 text-xs">Load</button>`}
    <button data-act="del-model" data-id="${id}" class="btn-danger !py-1.5 !px-3 text-xs" aria-label="Delete model">✕</button>
  </div>`;
}

export default {
  id: 'training',
  label: 'Training',
  icon: icons.training,

  async mount(root) {
    root.appendChild(html`
      <section class="space-y-5">
        <!-- Calibration (guided model-free floor + records the dataset) -->
        <div class="card card-pad space-y-3">
          <h2 class="card-title">Calibration <span class="badge-mut ml-1">start here</span></h2>
          <p class="text-xs text-ink-muted">Teach RuSense your room. It measures the <strong>empty room</strong>, then <strong>you walking</strong>, sets the motion-detection threshold for this space, and saves both scans as <code>train_empty</code> / <code>train_walking</code> recordings — so you can Train the adaptive model below with one click. Two ~25&nbsp;s scans.</p>
          <button id="cal-start" class="btn-primary">Start calibration</button>
          <div id="cal-status" class="text-sm"></div>
          <div id="cal-result" class="text-sm"></div>
          <details>
            <summary class="cursor-pointer text-xs text-ink-muted">Advanced — set thresholds manually</summary>
            <div class="mt-3 space-y-3">
              <div id="cal-presets" class="grid gap-2 sm:grid-cols-3">
                <button type="button" data-floor="0.14" data-deb="4" class="text-left rounded-lg border border-ink-3 px-3 py-2 cursor-pointer"><span class="block text-sm font-semibold">High</span><span class="block text-xs text-ink-muted">Catch everything</span></button>
                <button type="button" data-floor="0.15" data-deb="6" class="text-left rounded-lg border border-ink-3 px-3 py-2 cursor-pointer"><span class="block text-sm font-semibold">Balanced</span><span class="block text-xs text-ink-muted">Default</span></button>
                <button type="button" data-floor="0.16" data-deb="10" class="text-left rounded-lg border border-ink-3 px-3 py-2 cursor-pointer"><span class="block text-sm font-semibold">Low</span><span class="block text-xs text-ink-muted">Fewest false alarms</span></button>
              </div>
              <div class="grid gap-4 sm:grid-cols-2">
                <label class="block"><span class="block text-sm font-medium mb-1">Presence floor</span><input type="number" id="cal-floor" min="0.03" max="0.40" step="0.01" class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" /></label>
                <label class="block"><span class="block text-sm font-medium mb-1">Debounce frames</span><input type="number" id="cal-deb" min="1" max="30" step="1" class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" /></label>
              </div>
              <button id="cal-apply" class="btn-ghost">Apply thresholds</button>
            </div>
          </details>
        </div>

        <!-- Recording -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <h2 class="card-title">CSI recording</h2>
              <button id="rec-info-btn" type="button" aria-label="What does training do?" title="What does this do?"
                class="shrink-0 w-5 h-5 grid place-items-center rounded-full border border-ink-3 text-ink-muted text-xs leading-none hover:text-ink-fg hover:border-ink-4">i</button>
            </div>
            <span id="rec-state" class="badge-mut">idle</span>
          </div>
          <p class="text-xs text-ink-muted">Capture raw WiFi Channel State Information to disk. These recordings are the dataset the adaptive classifier learns from.</p>
          <div id="rec-info" class="hidden rounded-lg bg-ink-1 border border-ink-3 p-3 text-xs text-ink-soft space-y-2">
            <p><strong>Training teaches RuSense what <em>your</em> room looks like</strong> in different situations, so it can recognise them live. WiFi bounces off your walls and furniture in a way unique to your space, so it learns by example.</p>
            <p>It's a 3-step loop:</p>
            <ol class="list-decimal pl-4 space-y-1">
              <li><strong>Record</strong> — pick a scenario from the dropdown (Empty room, Walking, Two people…) and record one clip for each. Each scenario maps to a <code>train_&lt;label&gt;</code> class the trainer uses; pick <em>Custom name…</em> for anything not listed.</li>
              <li><strong>Train</strong> — click <em>Train adaptive model</em>; it learns the signal "fingerprint" of each <code>train_*</code> class for your room. (There's no separate "select" step — it uses all <code>train_*</code> recordings.)</li>
              <li><strong>Active</strong> — the trained model classifies what's happening in real time.</li>
            </ol>
            <p class="text-ink-muted">Tip: record at least 2 classes (e.g. <code>train_empty</code> + <code>train_present</code>), give each a good clip, and remember a model only applies to the room you recorded it in. Recordings without the <code>train_</code> prefix are kept but ignored by training.</p>
          </div>
          <div class="space-y-2">
            <div class="flex gap-2">
              <select id="rec-id" class="flex-1 min-w-0 rounded-lg bg-ink-1 border border-ink-3 px-3 py-2.5 text-sm focus-visible:ring-2 focus-visible:ring-brand-400">
                <option value="" disabled selected>Choose a scenario…</option>
                <option value="train_empty">Empty room</option>
                <option value="train_present">Person present (still)</option>
                <option value="train_walking">Walking</option>
                <option value="train_sitting">Sitting</option>
                <option value="train_standing">Standing</option>
                <option value="train_two_people">Two people</option>
                <option value="train_sleeping">Lying / sleeping</option>
                <option value="__custom__">Custom name…</option>
              </select>
              <button id="rec-start" class="btn-primary shrink-0">Record</button>
              <button id="rec-stop" class="btn-ghost shrink-0">Stop</button>
            </div>
            <input id="rec-id-custom" placeholder="train_&lt;label&gt; (e.g. train_running)"
              class="hidden w-full rounded-lg bg-ink-1 border border-ink-3 px-3 py-2.5 text-sm focus-visible:ring-2 focus-visible:ring-brand-400" />
          </div>
          <div id="rec-live" class="hidden flex items-center gap-3 rounded-lg bg-bad/20 border border-ink-3 p-2.5 text-sm">
            <span class="dot bg-bad pulse-live shrink-0"></span>
            <span class="flex-1 min-w-0 truncate font-mono" id="rec-live-id">—</span>
            <span class="shrink-0 font-mono text-xs text-ink-muted" id="rec-live-meta">0:00</span>
          </div>
          <div id="rec-list" class="space-y-2"></div>
        </div>

        <!-- Adaptive (on-device) training -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Adaptive training <span class="badge-mut ml-1">on-device</span></h2>
            <span id="ad-status" class="badge-mut">—</span>
          </div>
          <p class="text-xs text-ink-muted">Fits a lightweight classifier to <em>this</em> environment from captured CSI (per-class signal statistics). Fast, runs on the Pi, and becomes the active model immediately. Trains on your <code>train_*</code> recordings — one class per label (e.g. <code>train_empty</code>, <code>train_present</code>).</p>
          <div id="ad-stats" class="text-xs font-mono text-ink-muted"></div>
          <div class="flex gap-2">
            <button id="ad-train" class="btn-primary flex-1">Train adaptive model</button>
            <button id="ad-unload" class="btn-ghost flex-1">Unload</button>
          </div>
        </div>

        <!-- Training run (dataset deep-training) -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Training run <span class="badge-mut ml-1">dataset</span></h2>
            <span id="tr-status" class="badge-mut">—</span>
          </div>
          <p class="text-xs text-ink-muted">Heavy deep-model training from an external pose dataset directory (MM-Fi / Wi-Pose) on the server. Produces an .rvf model. This does not use the CSI recordings above.</p>
          <div class="flex gap-2">
            <button id="tr-start" class="btn-primary flex-1">Start training</button>
            <button id="tr-stop" class="btn-ghost flex-1">Stop</button>
          </div>
          <pre id="tr-config" class="text-xs font-mono text-ink-muted whitespace-pre-wrap break-words max-h-32 overflow-auto"></pre>
        </div>

        <!-- Models -->
        <div class="card card-pad space-y-3">
          <div class="flex items-center justify-between">
            <h2 class="card-title">Models</h2>
            <button id="m-refresh" class="btn-ghost !py-1.5 !px-3 text-xs">Refresh</button>
          </div>
          <div id="m-list" class="space-y-2"><div class="text-sm text-ink-muted">Loading…</div></div>
        </div>
      </section>`);

    // ── Models ──
    const loadModels = async () => {
      const [list, active] = await Promise.all([fetchJSON('/api/v1/models'), fetchJSON('/api/v1/models/active')]);
      const models = list?.models || [];
      const activeId = active?.active?.id ?? null;
      const box = $('#m-list');
      box.innerHTML = models.length ? models.map((m) => modelCard(m, activeId)).join('')
        : '<div class="text-sm text-ink-muted">No models found. Record CSI data and train a model, or drop an .rvf file in the models directory.</div>';
    };
    $('#m-list').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-act]'); if (!btn) return;
      const { act, id } = btn.dataset;
      let r;
      if (act === 'load') { r = await post('/api/v1/models/load', { id }); toast(r.ok ? `Loading ${id}` : msgOf(r, `Could not load ${id}`), r.ok ? 'ok' : 'bad'); }
      else if (act === 'unload') { r = await post('/api/v1/models/unload'); toast(r.ok ? 'Model unloaded' : msgOf(r, 'Could not unload model'), r.ok ? 'ok' : 'bad'); }
      else if (act === 'del-model') { if (!confirm(`Delete model ${id}?`)) return; r = await del(`/api/v1/models/${encodeURIComponent(id)}`); toast(r.ok ? `Deleted ${id}` : msgOf(r, `Could not delete ${id}`), r.ok ? 'warn' : 'bad'); }
      loadModels();
    });
    $('#m-refresh').addEventListener('click', loadModels);

    // ── Recording ──
    const recInfoBtn = $('#rec-info-btn');
    if (recInfoBtn) recInfoBtn.addEventListener('click', () => {
      const el = $('#rec-info');
      if (el) el.classList.toggle('hidden');
    });

    const loadRecordings = async () => {
      const r = await fetchJSON('/api/v1/recording/list');
      const recs = r?.recordings || [];
      if (recState && recState.active) {
        const live = recs.find((x) => (x.id ?? x.name) === recState.id);
        if (live) {
          if (live.frames != null) { recState.frames = live.frames; persistRecState(); renderRecLive(); }
        } else {
          setRecState(false);
        }
      }
      const box = $('#rec-list');
      box.innerHTML = recs.length ? recs.map((rec) => {
        const id = rec.id ?? rec.name ?? rec;
        const isLive = !!(recState && recState.active && id === recState.id);
        const parts = [];
        if (rec.frames != null) parts.push(`${fmt.int(rec.frames)} frames`);
        if (rec.size_bytes != null) parts.push(`${(rec.size_bytes / 1e6).toFixed(1)} MB`);
        else if (rec.size_mb != null) parts.push(`${fmt.num(rec.size_mb, 1)} MB`);
        const meta = parts.join(' \u00b7 ');
        return `<div class="flex items-center gap-3 rounded-lg bg-ink-1 border border-ink-3 p-2.5 text-sm">
          <span class="flex-1 truncate font-mono">${id}${isLive ? ' <span class="badge-bad ml-1">recording</span>' : ''}</span>
          ${meta ? `<span class="text-xs text-ink-muted shrink-0">${meta}</span>` : ''}
          <a href="/api/rusense/recording/download?id=${encodeURIComponent(id)}" download="${id}.jsonl"
             class="btn-ghost !py-1 !px-2.5 text-xs shrink-0" title="Download recording (.jsonl)">\u2b07</a>
          <button data-rid="${id}" class="btn-danger !py-1 !px-2.5 text-xs shrink-0"${isLive ? ' disabled' : ''}>\u2715</button>
        </div>`;
      }).join('') : '<div class="text-sm text-ink-muted">No recordings yet.</div>';
    };
    $('#rec-list').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-rid]'); if (!btn) return;
      if (!confirm(`Delete recording ${btn.dataset.rid}?`)) return;
      const r = await del(`/api/v1/recording/${encodeURIComponent(btn.dataset.rid)}`);
      toast(r.ok ? 'Recording deleted' : msgOf(r, 'Could not delete recording'), r.ok ? 'warn' : 'bad');
      loadRecordings();
    });
    let liveTimer = null;
    const renderRecLive = () => {
      const box = $('#rec-live');
      if (!box) return;
      if (!recState || !recState.active) { box.classList.add('hidden'); return; }
      box.classList.remove('hidden');
      const idEl = $('#rec-live-id');
      if (idEl) idEl.textContent = recState.id || '—';
      const metaEl = $('#rec-live-meta');
      if (metaEl) {
        const parts = [];
        if (recState.startedAt) parts.push(fmtElapsed(Date.now() - recState.startedAt));
        if (recState.frames != null) parts.push(`${fmt.int(recState.frames)} frames`);
        metaEl.textContent = parts.join(' · ') || 'recording';
      }
    };
    const setRecState = (recording, info) => {
      if (recording) {
        recState = {
          active: true,
          id: (info && info.id) || (recState && recState.id) || '?',
          startedAt: (info && info.startedAt) || (recState && recState.startedAt) || null,
          frames: (info && info.frames != null) ? info.frames : (recState ? recState.frames : null),
        };
      } else {
        recState = null;
      }
      persistRecState();
      const el = $('#rec-state');
      if (el) {
        el.textContent = recording ? 'recording' : 'idle';
        el.className = recording ? 'badge-bad' : 'badge-mut';
      }
      renderRecLive();
      if (recording && !liveTimer) liveTimer = setInterval(renderRecLive, 1000);
      if (!recording && liveTimer) { clearInterval(liveTimer); liveTimer = null; }
    };
    // Scenario dropdown: "Custom name…" reveals a free-text field.
    const recSelect = $('#rec-id'), recCustom = $('#rec-id-custom');
    if (recSelect) recSelect.addEventListener('change', () => {
      const isCustom = recSelect.value === '__custom__';
      if (recCustom) {
        recCustom.classList.toggle('hidden', !isCustom);
        if (isCustom) recCustom.focus();
      }
    });
    $('#rec-start').addEventListener('click', async () => {
      let id = recSelect ? recSelect.value : '';
      if (id === '__custom__') id = (recCustom?.value || '').trim();
      if (!id || id === '__custom__') {
        toast('Pick a scenario (or enter a custom name) first', 'warn');
        return;
      }
      const r = await post('/api/v1/recording/start', { id });
      const started = r.ok && r.data?.success !== false;
      if (started) {
        toast(`Recording "${id}"`, 'ok');
        setRecState(true, { id, startedAt: Date.now(), frames: 0 });
      } else if (r.data?.recording_id) {
        toast(msgOf(r, 'A recording is already active'), 'warn');
        setRecState(true, { id: r.data.recording_id });
      } else {
        toast(msgOf(r, 'Could not start recording'), 'bad');
      }
      loadRecordings();
    });
    $('#rec-stop').addEventListener('click', async () => {
      const r = await post('/api/v1/recording/stop');
      const stopped = r.ok && r.data?.success !== false;
      const alreadyIdle = r.ok && /no recording/i.test(String(r.data?.error || ''));
      toast(stopped ? 'Recording stopped' : msgOf(r, 'Could not stop recording'), stopped ? 'ok' : 'bad');
      if (stopped || alreadyIdle) setRecState(false);
      loadRecordings();
    });

    // ── Adaptive (on-device) training ──
    const loadAdaptive = async () => {
      const a = await fetchJSON('/api/v1/adaptive/status');
      const st = $('#ad-status');
      const stats = $('#ad-stats');
      if (!a) { st.textContent = 'unavailable'; st.className = 'badge-mut'; stats.textContent = ''; return; }
      // A trained model reports frame counts / accuracy / classes; otherwise none.
      const frames = a.trained_frames ?? a.frames;
      const trained = a.trained === true || frames != null || (Array.isArray(a.class_names) && a.class_names.length > 0);
      if (trained) {
        st.textContent = 'trained'; st.className = 'badge-ok';
        const acc = a.training_accuracy != null ? `${fmt.num(a.training_accuracy * (a.training_accuracy <= 1 ? 100 : 1), 1)}% acc` : null;
        const classes = Array.isArray(a.class_names) && a.class_names.length ? `classes: ${a.class_names.join(', ')}` : null;
        stats.textContent = [frames != null ? `${fmt.int(frames)} frames` : null, acc, classes].filter(Boolean).join('  ·  ');
      } else {
        st.textContent = 'none'; st.className = 'badge-mut';
        stats.textContent = a.message || 'No adaptive model yet — record CSI (with ground-truth labels), then train.';
      }
    };
    $('#ad-train').addEventListener('click', async () => {
      $('#ad-train').disabled = true;
      const r = await post('/api/v1/adaptive/train');
      toast(r.ok ? (msgOf(r, 'Adaptive model trained')) : msgOf(r, 'Adaptive training failed'), r.ok ? 'ok' : 'bad');
      $('#ad-train').disabled = false;
      loadAdaptive(); loadModels();
    });
    $('#ad-unload').addEventListener('click', async () => {
      const r = await post('/api/v1/adaptive/unload');
      toast(r.ok ? 'Adaptive model unloaded' : msgOf(r, 'Could not unload adaptive model'), r.ok ? 'warn' : 'bad');
      loadAdaptive(); loadModels();
    });

    // ── Training run (dataset) ──
    const loadTrain = async () => {
      const t = await fetchJSON('/api/v1/train/status');
      const st = $('#tr-status');
      const status = t?.status || (t === null ? 'unavailable' : 'idle');
      st.textContent = status;
      st.className = /run|train|active/i.test(String(status)) ? 'badge-ok' : 'badge-mut';
      $('#tr-config').textContent = t?.config ? JSON.stringify(t.config, null, 2) : '';
    };
    $('#tr-start').addEventListener('click', async () => {
      const r = await post('/api/v1/train/start');
      toast(r.ok ? msgOf(r, 'Training started') : msgOf(r, 'Could not start training'), r.ok ? 'ok' : 'bad');
      loadTrain();
    });
    $('#tr-stop').addEventListener('click', async () => {
      const r = await post('/api/v1/train/stop');
      toast(r.ok ? msgOf(r, 'Training stopped') : msgOf(r, 'Could not stop training'), r.ok ? 'warn' : 'bad');
      loadTrain();
    });

    // -- Calibration: guided per-room threshold setup. Each phase records the
    //    matching train_* clip (so adaptive training reuses it) AND samples the
    //    engine's sm to place the model-free presence floor in the gap. --
    (function wireCalibration() {
      const startBtn = $('#cal-start');
      if (!startBtn) return;
      const statusEl = $('#cal-status');
      const resultEl = $('#cal-result');
      const SCAN = 25;
      let emptyStats = null;

      (async () => {
        const cur = await fetchJSON('/api/rusense/sensitivity');
        if (cur) {
          if ($('#cal-floor')) $('#cal-floor').value = cur.floor ?? 0.15;
          if ($('#cal-deb')) $('#cal-deb').value = cur.debounce_frames ?? 6;
        }
      })();

      const scanPhase = async (label, recId) => {
        const rs = await post('/api/v1/recording/start', { id: recId });
        if (!rs.ok) { statusEl.textContent = msgOf(rs, `Could not start recording ${recId}`); return null; }
        let left = SCAN;
        const paint = () => { statusEl.textContent = `Recording “${label}” (${recId})… ${Math.max(0, left)}s left`; };
        paint();
        const tmr = setInterval(() => { left -= 1; paint(); }, 1000);
        const r = await req('POST', '/api/rusense/calibrate/sample', { secs: SCAN });
        clearInterval(tmr);
        await post('/api/v1/recording/stop');
        loadRecordings();
        if (!r.ok || !r.data || r.data.error) { statusEl.textContent = (r.data && r.data.error) || 'Scan failed — is a node streaming? Check the Nodes tab.'; return null; }
        return r.data;
      };

      const resetBtn = () => { startBtn.textContent = 'Start calibration'; startBtn.disabled = false; startBtn.onclick = begin; };

      const recommend = (empty, moving) => {
        const eHi = empty.p95, mLo = moving.p05;
        let floor, deb, note;
        if (mLo > eHi + 0.01) {
          floor = Math.round(((eHi + mLo) / 2) * 1000) / 1000; deb = 6;
          note = `Clean separation — empty sm tops out ≈${eHi}, walking stays ≥${mLo}.`;
        } else {
          floor = Math.round((eHi + 0.01) * 1000) / 1000; deb = 10;
          note = `Empty (≤${eHi}) and walking (≥${mLo}) overlap — floor set just above the empty noise with extra debounce; may miss very slow movement.`;
        }
        floor = Math.max(0.05, Math.min(0.35, floor));
        if ($('#cal-floor')) $('#cal-floor').value = floor;
        if ($('#cal-deb')) $('#cal-deb').value = deb;
        statusEl.textContent = '';
        resultEl.innerHTML = `<div class="rounded-lg bg-ink-1 border border-ink-3 p-3 space-y-2">
            <div>Recommended: <strong>floor ${floor}</strong> &middot; <strong>debounce ${deb}</strong></div>
            <div class="text-xs text-ink-muted">${note}<br>Empty sm max ${empty.max} (p95 ${empty.p95}) · walking sm p05 ${moving.p05}, median ${moving.p50}. Saved <code>train_empty</code> + <code>train_walking</code> — Train the adaptive model below to add people-count.</div>
            <button id="cal-do-apply" class="btn-primary">Apply calibration</button>
          </div>`;
        resetBtn();
        const b = $('#cal-do-apply');
        if (b) b.onclick = async () => {
          b.disabled = true; b.textContent = 'Applying…';
          const r = await post('/api/rusense/sensitivity', { floor, debounce_frames: deb });
          toast(r.ok ? `Calibrated — floor ${floor}, debounce ${deb} (sensing restarted)` : msgOf(r, 'Could not apply'), r.ok ? 'ok' : 'bad');
          b.disabled = false; b.textContent = 'Apply calibration';
        };
      };

      const step2 = () => {
        resultEl.innerHTML = '';
        statusEl.innerHTML = '<strong>Step 2 of 2:</strong> now WALK around the room normally — cover the whole space.';
        startBtn.textContent = "I'm walking — scan (25s)";
        startBtn.disabled = false;
        startBtn.onclick = async () => {
          startBtn.disabled = true;
          const moving = await scanPhase('walking', 'train_walking');
          if (!moving) { resetBtn(); return; }
          recommend(emptyStats, moving);
        };
      };

      function begin() {
        emptyStats = null; resultEl.innerHTML = '';
        statusEl.innerHTML = '<strong>Step 1 of 2:</strong> LEAVE the room (stand a few metres away). When you are out, click below.';
        startBtn.textContent = "I'm out — scan empty (25s)";
        startBtn.disabled = false;
        startBtn.onclick = async () => {
          startBtn.disabled = true;
          const empty = await scanPhase('empty', 'train_empty');
          if (!empty) { resetBtn(); return; }
          emptyStats = empty; step2();
        };
      }
      startBtn.onclick = begin;

      root.querySelectorAll('#cal-presets button').forEach((b) => b.addEventListener('click', () => {
        if ($('#cal-floor')) $('#cal-floor').value = b.dataset.floor;
        if ($('#cal-deb')) $('#cal-deb').value = b.dataset.deb;
      }));
      if ($('#cal-apply')) $('#cal-apply').addEventListener('click', async () => {
        const floor = Math.max(0.03, Math.min(0.40, parseFloat($('#cal-floor').value) || 0.15));
        let deb = parseInt($('#cal-deb').value, 10); if (isNaN(deb)) deb = 6; deb = Math.max(1, Math.min(30, deb));
        const r = await post('/api/rusense/sensitivity', { floor, debounce_frames: deb });
        toast(r.ok ? `Thresholds applied — floor ${floor}, debounce ${deb}` : msgOf(r, 'Could not apply'), r.ok ? 'ok' : 'bad');
      });
    })();

    if (recState && recState.active) setRecState(true, recState);

    loadModels(); loadRecordings(); loadTrain(); loadAdaptive();
    const t = setInterval(() => {
      loadTrain(); loadAdaptive();
      if (recState && recState.active) loadRecordings();
    }, 4000);
    return () => {
      clearInterval(t);
      if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
    };
  },
};
