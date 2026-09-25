// Settings — RuSense camera-free surveillance alerts (Pushover) plus a full
// mirror of the Observatory 3D-view controls. The alert toggles read/write
// Ragnar's own config (/api/config) + the shared Pushover key status; the
// server-side monitor in webapp_modern.py does the edge detection and sending.
//
// The Observatory section edits the SAME localStorage the Observatory itself
// reads on boot (keys 'ruview-observatory-settings' + 'ruview-settings-version',
// see observatory/js/main.js) AND mirrors the whole blob to the server config
// (key 'rusense_observatory_settings') so the values persist for everyone — like
// Ragnar's main settings — instead of being trapped in one browser. localStorage
// is the local cache; the server is the shared source of truth, seeded on load.
// The 3D scene only exists inside the Observatory iframe, so changes here are
// saved instantly and take effect the next time the Observatory sub-tab is opened
// (there is no live scene on this tab to preview).
import { icons } from '../icons.js';
import { html, $, $$, fetchJSON, toast } from '../lib.js?v=20260704-sparkfit';
import { DEFAULTS, PRESETS, SETTINGS_VERSION, seedObsFromServerConfig, pushObsSettingsToServer } from '../../../observatory/js/hud-controller.js?v=20260629-obsserver';

// Action helper that — unlike fetchJSON — keeps HTTP ok/fail and the JSON body
// separate, so we never toast a false success (mirrors training.js).
async function req(method, url, body) {
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* empty / non-JSON is fine */ }
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: null, error: String(e) };
  }
}

// Debounced push of node-corner positions to Ragnar's backend config, so the
// server-side geofence (which confines the Pushover alerts) reasons over the
// SAME node map the Observatory uses. The positions live in localStorage for
// the 3D view; this mirrors them to the server where the alert loop can read.
let _posSyncTimer = null;
function syncNodePositionsToBackend(positions) {
  clearTimeout(_posSyncTimer);
  _posSyncTimer = setTimeout(() => {
    req('POST', '/api/config', { rusense_node_positions: positions || {} });
  }, 800);
}

// Node names are not just a UI label — mirror them to the backend too, so
// server-side alerts (e.g. "node offline") can say "Living room" instead of "#2".
let _nameSyncTimer = null;
function syncNodeNamesToBackend(names) {
  clearTimeout(_nameSyncTimer);
  _nameSyncTimer = setTimeout(() => {
    req('POST', '/api/config', { rusense_node_names: names || {} });
  }, 800);
}

// Each alert kind: config key + label + helper text.
const TOGGLES = [
  ['rusense_notify_presence', 'Presence / occupancy', 'When a monitored space goes from empty to occupied (and back).'],
  ['rusense_notify_motion', 'Motion', 'When significant (active) motion is detected.'],
  ['rusense_notify_people', 'People-count threshold', 'When the estimated number of people crosses the threshold below.'],
  ['rusense_notify_node_offline', 'Node offline', 'When a provisioned CSI sensor node stops streaming.'],
  ['rusense_notify_inactivity', 'Inactivity (health)', 'The inverse of presence: when an expected-occupied space shows NO activity for the awake-hours set below. For wellness monitoring.'],
];

function row(key, label, help, checked) {
  return `<label class="flex items-start justify-between gap-4 py-3 border-b border-ink-3 last:border-0 cursor-pointer">
    <span class="min-w-0">
      <span class="block text-sm font-medium">${label}</span>
      <span class="block text-xs text-ink-muted">${help}</span>
    </span>
    <input type="checkbox" data-key="${key}" ${checked ? 'checked' : ''}
      class="mt-1 shrink-0 w-5 h-5 accent-brand-400 cursor-pointer" />
  </label>`;
}

// ── Observatory settings model ──────────────────────────────────────────────
const OBS_KEY = 'ruview-observatory-settings';
const OBS_VER_KEY = 'ruview-settings-version';

function loadObsSettings() {
  const s = JSON.parse(JSON.stringify(DEFAULTS)); // deep clone (nodeLabels/Positions)
  try {
    if (localStorage.getItem(OBS_VER_KEY) === SETTINGS_VERSION) {
      const saved = localStorage.getItem(OBS_KEY);
      if (saved) Object.assign(s, JSON.parse(saved));
    }
  } catch { /* corrupt/unavailable storage — fall back to defaults */ }
  if (!s.nodeLabels || typeof s.nodeLabels !== 'object') s.nodeLabels = {};
  if (!s.nodePositions || typeof s.nodePositions !== 'object') s.nodePositions = {};
  return s;
}

function saveObsSettings(s) {
  try {
    // Stamp the version too, otherwise the Observatory treats our write as
    // stale on its next boot and wipes it.
    localStorage.setItem(OBS_VER_KEY, SETTINGS_VERSION);
    localStorage.setItem(OBS_KEY, JSON.stringify(s));
  } catch { /* storage full / disabled — silently ignore */ }
  // Mirror to the server config (debounced) so these settings persist for
  // everyone, like Ragnar's main settings — not just in this browser.
  pushObsSettingsToServer(s);
}

// Trim float noise for the value readouts next to sliders.
const fmtVal = (v) => String(Math.round(Number(v) * 10000) / 10000);

// Control definitions, grouped exactly like the Observatory's own dialog tabs.
const OBS_RANGES = {
  Rendering: [
    ['bloom', 'Bloom Strength', 0, 3, 0.1],
    ['bloomRadius', 'Bloom Radius', 0, 1, 0.05],
    ['bloomThresh', 'Bloom Threshold', 0, 1, 0.05],
    ['exposure', 'Exposure', 0.3, 2, 0.05],
    ['vignette', 'Vignette', 0, 1, 0.05],
    ['grain', 'Film Grain', 0, 0.15, 0.005],
    ['chromatic', 'Chromatic Aberration', 0, 0.008, 0.0005],
  ],
  Wireframe: [
    ['boneThick', 'Bone Thickness', 0.005, 0.06, 0.002],
    ['jointSize', 'Joint Size', 0.02, 0.12, 0.005],
    ['glow', 'Glow Intensity', 0, 2, 0.1],
    ['trail', 'Particle Trail', 0, 1, 0.05],
    ['aura', 'Aura Opacity', 0, 0.2, 0.01],
  ],
  Scene: [
    ['field', 'Signal Field', 0, 1, 0.05],
    ['waves', 'WiFi Waves', 0, 1, 0.05],
    ['ambient', 'Room Brightness', 0, 1, 0.05],
    ['reflect', 'Floor Reflection', 0, 1, 0.05],
    ['fov', 'FOV', 30, 90, 1],
    ['orbitSpeed', 'Orbit Speed', 0.02, 0.5, 0.02],
  ],
};
const OBS_COLORS = [['wireColor', 'Wireframe Color'], ['jointColor', 'Joint Color']];
const OBS_CHECKS = [['grid', 'Show Grid'], ['room', 'Show Room Boundary']];
const OBS_ROOMNUM = [['roomX', 'Room Width X (m)', 1, 30, 0.1], ['roomY', 'Room Length Y (m)', 1, 30, 0.1]];

const SCENARIOS = [
  ['auto', 'Auto-Cycle'],
  ['empty_room', 'Empty Room'],
  ['single_breathing', 'Vital Signs (Breathing)'],
  ['two_walking', 'Multi-Person Tracking'],
  ['fall_event', 'Fall Detection'],
  ['sleep_monitoring', 'Sleep Monitoring (Apnea)'],
  ['elderly_care', 'Elderly Care (Gait)'],
  ['fitness_tracking', 'Fitness Tracking'],
  ['intrusion_detect', 'Intrusion Detection'],
  ['security_patrol', 'Security Patrol'],
  ['crowd_occupancy', 'Crowd Occupancy (4 ppl)'],
  ['gesture_control', 'Gesture Control (DTW)'],
  ['search_rescue', 'Search & Rescue (WiFi-Mat)'],
];
const PRESET_OPTS = [
  ['custom', 'Custom'],
  ['foundation', 'Foundation (Default)'],
  ['cinematic', 'Cinematic'],
  ['minimal', 'Minimal / Clean'],
  ['neon', 'Neon Glow'],
  ['tactical', 'Tactical / Military'],
  ['medical', 'Medical Monitor'],
];

const rangeRow = (key, label, min, max, step) => `
  <label class="block py-2 border-b border-ink-3 last:border-0">
    <span class="flex items-center justify-between text-sm mb-1">
      <span class="text-ink-soft">${label}</span>
      <span class="font-mono text-xs text-ink-muted" data-obs-val="${key}">—</span>
    </span>
    <input type="range" data-obs-range="${key}" min="${min}" max="${max}" step="${step}"
      class="w-full accent-brand-400 cursor-pointer" />
  </label>`;

const colorRow = (key, label) => `
  <label class="flex items-center justify-between gap-4 py-2 border-b border-ink-3 last:border-0">
    <span class="text-sm text-ink-soft">${label}</span>
    <input type="color" data-obs-color="${key}" class="w-10 h-8 bg-transparent cursor-pointer rounded" />
  </label>`;

const checkRow = (key, label) => `
  <label class="flex items-center justify-between gap-4 py-2 border-b border-ink-3 last:border-0 cursor-pointer">
    <span class="text-sm text-ink-soft">${label}</span>
    <input type="checkbox" data-obs-check="${key}" class="shrink-0 w-5 h-5 accent-brand-400 cursor-pointer" />
  </label>`;

const numRow = (key, label, min, max, step) => `
  <label class="flex flex-wrap items-center justify-between gap-2 py-2 border-b border-ink-3 last:border-0">
    <span class="text-sm text-ink-soft min-w-0">${label}</span>
    <input type="number" data-obs-num="${key}" min="${min}" max="${max}" step="${step}"
      class="w-24 bg-ink-1 border border-ink-3 rounded-lg px-3 py-1.5 text-sm font-mono" />
  </label>`;

const selectRow = (attr, label, opts) => `
  <label class="block py-2 border-b border-ink-3 last:border-0">
    <span class="block text-sm text-ink-soft mb-1">${label}</span>
    <select ${attr} class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm">
      ${opts.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}
    </select>
  </label>`;

function observatorySectionHtml() {
  const grp = (title, body) => `
    <div class="card card-pad space-y-1">
      <h3 class="card-title mb-1">${title}</h3>
      ${body}
    </div>`;

  return `
    <section class="space-y-5 max-w-2xl">
      <div class="card card-pad space-y-2">
        <h2 class="text-xl font-bold">Observatory</h2>
        <p class="text-ink-soft text-sm">Visual controls for the Observatory 3D view. Changes save instantly and
          apply the next time you open the <strong>Observatory</strong> sub-tab — there is no live scene on this
          page to preview against.</p>
      </div>

      ${grp('Rendering', OBS_RANGES.Rendering.map(r => rangeRow(...r)).join(''))}

      ${grp('Wireframe', OBS_RANGES.Wireframe.map(r => rangeRow(...r)).join('') +
        OBS_COLORS.map(c => colorRow(...c)).join(''))}

      ${grp('Scene', OBS_RANGES.Scene.map(r => rangeRow(...r)).join('') +
        OBS_CHECKS.map(c => checkRow(...c)).join('') +
        `<div class="setting-section-title text-xs uppercase tracking-wide text-ink-muted pt-3 pb-1">Room &amp; Nodes</div>` +
        OBS_ROOMNUM.map(n => numRow(...n)).join('') +
        `<div id="obs-node-list" class="pt-1"></div>
         <div class="flex items-center justify-between pt-2">
           <span id="obs-node-hint" class="text-xs text-ink-muted">Loading nodes…</span>
           <button id="obs-node-refresh" class="btn-ghost !py-1 !px-2.5 text-xs">Refresh nodes</button>
         </div>`)}

      ${grp('Data', selectRow('data-obs-select="scenario"', 'Scenario', SCENARIOS) +
        rangeRow('cycle', 'Cycle Speed (s)', 10, 120, 5) +
        selectRow('data-obs-preset', 'Style Preset', PRESET_OPTS) +
        selectRow('data-obs-select="dataSource"', 'Data Source', [['demo', 'Demo Generator'], ['ws', 'Live WebSocket']]) +
        `<label class="block py-2" id="obs-wsurl-row">
           <span class="block text-sm text-ink-soft mb-1">WS URL</span>
           <input type="text" data-obs-text="wsUrl" placeholder="ws://localhost:3000/ws/sensing"
             class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
         </label>`)}

      <div class="flex flex-wrap gap-3">
        <button id="obs-reset" class="btn-ghost">Reset to defaults</button>
        <button id="obs-export" class="btn-ghost">Export settings</button>
      </div>
    </section>`;
}

export default {
  id: 'settings',
  label: 'Settings',
  icon: icons.settings,

  async mount(root) {
    // Pull current config + Pushover key status together.
    const [cfg, keys] = await Promise.all([
      fetchJSON('/api/config'),
      fetchJSON('/api/pushover/keys'),
    ]);
    const c = cfg || {};
    const configured = !!(keys && keys.user_key_configured && keys.api_token_configured);
    const enabledGlobally = !!c.pushover_enabled;
    const ready = configured && enabledGlobally;

    const banner = ready
      ? `<div class="rounded-lg bg-ok/15 text-ok px-3 py-2 text-sm">✓ Pushover is configured and enabled. RuSense alerts will be delivered.</div>`
      : `<div class="rounded-lg bg-warn/15 text-warn px-3 py-2 text-sm">
           ⚠ Pushover ${configured ? 'is configured but disabled' : 'keys are not set'}.
           Set your User Key and API Token under <strong>Config → Pushover Notifications</strong> in the main
           Ragnar dashboard first — RuSense alerts use the same account.
         </div>`;

    root.appendChild(html`
      <section class="space-y-5 max-w-2xl">
        <div class="card card-pad space-y-2">
          <h2 class="text-xl font-bold">Sensing Alerts</h2>
          <p class="text-ink-soft text-sm">Get a push notification when RuSense detects activity in a monitored
            space — no camera, no app open. Alerts are evaluated on the server, so they fire even when this tab is closed.</p>
          <div class="rounded-lg bg-warn/15 text-warn px-3 py-2 text-sm">
            ⚠ <strong>Experimental — not a life-safety device.</strong> RuSense infers presence from WiFi signal
            changes; it can miss real events and raise false alarms. Don’t rely on it as your only alarm — always
            keep a dedicated alarm (security, smoke/CO, or medical alert) for anything safety-critical.
          </div>
          ${banner}
        </div>

        <div class="card card-pad space-y-1">
          <label class="flex items-center justify-between gap-4 py-1 cursor-pointer">
            <span>
              <span class="block text-sm font-semibold">Enable RuSense alerts</span>
              <span class="block text-xs text-ink-muted">Master switch for all sensing notifications below.</span>
            </span>
            <input type="checkbox" id="st-master" data-key="rusense_notify_enabled"
              ${c.rusense_notify_enabled ? 'checked' : ''}
              class="shrink-0 w-6 h-6 accent-brand-400 cursor-pointer" />
          </label>
        </div>

        <div class="card card-pad space-y-2">
          <h3 class="card-title mb-1">Monitoring mode</h3>
          <p class="text-xs text-ink-muted">What is this space watched for? Picking a mode presets the alert
            toggles below — the direction of the alerts is what changes. Fine-tune afterwards if you like.</p>
          <div id="st-mode" class="grid gap-2 sm:grid-cols-3">
            <button type="button" data-mode="security" class="text-left rounded-lg border border-ink-3 px-3 py-2 cursor-pointer">
              <span class="block text-sm font-semibold">\u{1F6E1}\uFE0F Security</span>
              <span class="block text-xs text-ink-muted">Space should be EMPTY — alert when someone appears.</span>
            </button>
            <button type="button" data-mode="health" class="text-left rounded-lg border border-ink-3 px-3 py-2 cursor-pointer">
              <span class="block text-sm font-semibold">\u2764\uFE0F Health</span>
              <span class="block text-xs text-ink-muted">Space should be OCCUPIED — alert when it goes quiet; lead with vitals trends.</span>
            </button>
            <button type="button" data-mode="both" class="text-left rounded-lg border border-ink-3 px-3 py-2 cursor-pointer">
              <span class="block text-sm font-semibold">\u2696\uFE0F Both</span>
              <span class="block text-xs text-ink-muted">Empty at times, occupied at others — presence and inactivity alerts together.</span>
            </button>
          </div>
        </div>

        <div class="card card-pad space-y-1">
          <h3 class="card-title mb-1">Alert on</h3>
          ${TOGGLES.map(([k, l, h]) => row(k, l, h, c[k])).join('')}
        </div>

        <div class="card card-pad space-y-3">
          <h3 class="card-title">Sensitivity (false-positive guards)</h3>
          <p class="text-xs text-ink-muted">An event only fires when the detector is confident enough <em>and</em>
            the condition holds long enough — this filters out brief flickers.</p>
          <div class="grid gap-4 sm:grid-cols-2">
            <label class="block">
              <span class="block text-sm font-medium mb-1">Minimum confidence (%)</span>
              <input type="number" id="st-minconf" min="50" max="99" step="1"
                value="${Math.round(Number(c.rusense_notify_min_confidence ?? 0.95) * 100)}"
                class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
              <span class="block text-xs text-ink-muted mt-1">Ignore detections below this confidence.</span>
            </label>
            <label class="block">
              <span class="block text-sm font-medium mb-1">Must last (seconds)</span>
              <input type="number" id="st-sustain" min="0" max="30" step="1"
                value="${Number(c.rusense_notify_sustain_s ?? 2)}"
                class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
              <span class="block text-xs text-ink-muted mt-1">Condition must persist this long before alerting.</span>
            </label>
          </div>
        </div>

        <div class="card card-pad grid gap-4 sm:grid-cols-2">
          <label class="block">
            <span class="block text-sm font-medium mb-1">People-count threshold</span>
            <input type="number" id="st-threshold" min="1" max="20" step="1"
              value="${Number(c.rusense_notify_people_threshold ?? 1)}"
              class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
            <span class="block text-xs text-ink-muted mt-1">Alert when estimated people ≥ this.</span>
          </label>
          <label class="block">
            <span class="block text-sm font-medium mb-1">Cooldown (seconds)</span>
            <input type="number" id="st-cooldown" min="5" max="3600" step="5"
              value="${Number(c.rusense_notify_cooldown_s ?? 60)}"
              class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
            <span class="block text-xs text-ink-muted mt-1">Minimum gap between repeats of the same alert kind.</span>
          </label>
        </div>

        <div class="card card-pad space-y-3">
          <h3 class="card-title">Health monitoring</h3>
          <p class="text-xs text-ink-muted">Settings for the inactivity alert. Sleep hours are excluded — the
            no-activity timer only runs outside the quiet window, so a normal night never alerts. Each morning it
            restarts at the quiet-window end.</p>
          <div class="grid gap-4 sm:grid-cols-3">
            <label class="block">
              <span class="block text-sm font-medium mb-1">Alert after (hours)</span>
              <input type="number" id="st-inact-hours" min="1" max="24" step="1"
                value="${Number(c.rusense_inactivity_hours ?? 4)}"
                class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
              <span class="block text-xs text-ink-muted mt-1">Awake hours with no activity seen.</span>
            </label>
            <label class="block">
              <span class="block text-sm font-medium mb-1">Quiet from (hour)</span>
              <input type="number" id="st-quiet-start" min="0" max="23" step="1"
                value="${Number(c.rusense_quiet_start ?? 22)}"
                class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
              <span class="block text-xs text-ink-muted mt-1">Bedtime — the timer pauses.</span>
            </label>
            <label class="block">
              <span class="block text-sm font-medium mb-1">Quiet until (hour)</span>
              <input type="number" id="st-quiet-end" min="0" max="23" step="1"
                value="${Number(c.rusense_quiet_end ?? 7)}"
                class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
              <span class="block text-xs text-ink-muted mt-1">Wake-up — the timer resumes.</span>
            </label>
          </div>
        </div>

        <div class="card card-pad space-y-3">
          <div class="flex items-start justify-between gap-4">
            <span class="min-w-0">
              <h3 class="card-title">Permitted alert times (schedule)</h3>
              <p class="text-xs text-ink-muted">Restrict presence / motion / people alerts to chosen days and a time
                window — e.g. an office watched only on <strong>weekends</strong>, or a space only at <strong>night</strong>.
                Outside the window nothing is pushed to your phone (sightings are still logged, and node-offline
                warnings still fire). Off = alerts any time.</p>
            </span>
            <input type="checkbox" id="st-sched" data-key="rusense_alert_schedule_enabled"
              ${c.rusense_alert_schedule_enabled ? 'checked' : ''}
              class="mt-1 shrink-0 w-6 h-6 accent-brand-400 cursor-pointer" />
          </div>
          <div id="st-sched-body" class="space-y-3 ${c.rusense_alert_schedule_enabled ? '' : 'opacity-40 pointer-events-none'}">
            <div>
              <div class="flex items-center justify-between mb-1">
                <span class="block text-sm font-medium">Days</span>
                <span class="flex gap-1">
                  <button type="button" id="st-days-wd" class="badge-mut text-xs">Weekdays</button>
                  <button type="button" id="st-days-we" class="badge-mut text-xs">Weekends</button>
                  <button type="button" id="st-days-all" class="badge-mut text-xs">All</button>
                </span>
              </div>
              <div id="st-days" class="flex gap-1"></div>
            </div>
            <div class="grid gap-4 sm:grid-cols-2">
              <label class="block">
                <span class="block text-sm font-medium mb-1">From (hour)</span>
                <input type="number" id="st-sched-start" min="0" max="23" step="1"
                  value="${Number(c.rusense_alert_start ?? 0)}"
                  class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
              </label>
              <label class="block">
                <span class="block text-sm font-medium mb-1">Until (hour)</span>
                <input type="number" id="st-sched-end" min="0" max="23" step="1"
                  value="${Number(c.rusense_alert_end ?? 0)}"
                  class="w-full bg-ink-1 border border-ink-3 rounded-lg px-3 py-2 text-sm font-mono" />
              </label>
            </div>
            <p id="st-sched-summary" class="text-xs text-ink-muted"></p>
          </div>
        </div>

        <div class="card card-pad space-y-1">
          <label class="flex items-start justify-between gap-4 py-1 cursor-pointer">
            <span class="min-w-0">
              <span class="block text-sm font-semibold">Confine alerts to the room (geofence)</span>
              <span class="block text-xs text-ink-muted">Suppress motion/presence/people alerts whose signature points
                <em>outside</em> the room — hallway walk-bys and through-wall neighbours. Needs <strong>≥3 nodes mapped
                with X/Y</strong> in the Observatory → <em>Room &amp; Nodes</em> section below; with fewer it's a no-op.
                The "room empty" alert is never suppressed.</span>
            </span>
            <input type="checkbox" id="st-geofence" data-key="rusense_geofence_enabled"
              ${(c.rusense_geofence_enabled ?? true) ? 'checked' : ''}
              class="mt-1 shrink-0 w-6 h-6 accent-brand-400 cursor-pointer" />
          </label>
          <p id="st-geofence-status" class="text-xs text-ink-muted pt-1">Checking geofence status…</p>
        </div>

        <div class="flex flex-wrap gap-3">
          <button id="st-save" class="btn-primary">Save settings</button>
          <button id="st-test" class="btn-ghost">Send test notification</button>
        </div>
        <p class="text-xs text-ink-muted">Powered by RuView · alerts delivered via your Pushover account.</p>
      </section>`);

    // Observatory section appended after the alert settings.
    root.appendChild(html([observatorySectionHtml()]));

    const clampInt = (el, lo, hi, dflt) => {
      let v = parseInt(el && el.value, 10);
      if (isNaN(v)) v = dflt;
      return Math.max(lo, Math.min(hi, v));
    };

    // ── Monitoring mode: presets the DIRECTION of the alerts. Security =
    //    expected-empty (alert on someone appearing); Health = expected-
    //    occupied (alert on inactivity). Clicking a mode flips the toggles
    //    above; Save persists the mode + toggles together. ──
    let mode = ['security', 'health', 'both'].includes(c.rusense_mode) ? c.rusense_mode : 'security';
    const MODE_PRESETS = {
      security: { rusense_notify_presence: true, rusense_notify_motion: false,
                  rusense_notify_people: false, rusense_notify_inactivity: false },
      health: { rusense_notify_presence: false, rusense_notify_motion: false,
                rusense_notify_people: false, rusense_notify_inactivity: true },
      both: { rusense_notify_presence: true, rusense_notify_inactivity: true },
    };
    const paintMode = () => {
      root.querySelectorAll('#st-mode button').forEach((b) => {
        const on = b.dataset.mode === mode;
        b.className = 'text-left rounded-lg border px-3 py-2 cursor-pointer '
          + (on ? 'border-brand-400 bg-brand-400/10' : 'border-ink-3');
      });
    };
    paintMode();
    root.querySelectorAll('#st-mode button').forEach((b) => b.addEventListener('click', () => {
      mode = b.dataset.mode;
      paintMode();
      for (const [k, v] of Object.entries(MODE_PRESETS[mode] || {})) {
        const box = root.querySelector(`input[data-key="${k}"]`);
        if (box) box.checked = v;
      }
    }));

    // ── Alert schedule (permitted times) ──
    const DAY_LABELS = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];  // JS getDay(): 0=Sun
    let schedDays = new Set(Array.isArray(c.rusense_alert_days) ? c.rusense_alert_days
      : [0, 1, 2, 3, 4, 5, 6]);
    const paintDays = () => {
      const box = $('#st-days'); if (!box) return;
      box.innerHTML = DAY_LABELS.map((d, i) => {
        const on = schedDays.has(i);
        return `<button type="button" data-day="${i}" class="flex-1 rounded-lg border px-0 py-2 text-xs font-medium cursor-pointer `
          + (on ? 'border-brand-400 bg-brand-400/10 text-ink' : 'border-ink-3 text-ink-muted') + `">${d}</button>`;
      }).join('');
      box.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
        const i = Number(b.dataset.day);
        if (schedDays.has(i)) schedDays.delete(i); else schedDays.add(i);
        paintDays(); paintSchedSummary();
      }));
    };
    const paintSchedSummary = () => {
      const el = $('#st-sched-summary'); if (!el) return;
      const start = clampInt($('#st-sched-start'), 0, 23, 0);
      const end = clampInt($('#st-sched-end'), 0, 23, 0);
      const days = [...schedDays].sort((a, b) => a - b);
      const dayTxt = !days.length ? 'no days (alerts never fire)'
        : days.length === 7 ? 'every day'
        : days.map((d) => DAY_LABELS[d]).join(' ');
      const hh = (h) => `${String(h).padStart(2, '0')}:00`;
      const timeTxt = start === end ? 'all day' : `${hh(start)}–${hh(end)}${end <= start ? ' (next day)' : ''}`;
      el.textContent = `Alerts fire on ${dayTxt}, ${timeTxt}.`;
    };
    const syncSchedEnabled = () => {
      const body = $('#st-sched-body'), on = $('#st-sched') && $('#st-sched').checked;
      if (body) body.className = `space-y-3 ${on ? '' : 'opacity-40 pointer-events-none'}`;
    };
    paintDays(); paintSchedSummary();
    if ($('#st-sched')) $('#st-sched').addEventListener('change', syncSchedEnabled);
    ['#st-sched-start', '#st-sched-end'].forEach((sel) => {
      if ($(sel)) $(sel).addEventListener('input', paintSchedSummary);
    });
    const setDays = (arr) => { schedDays = new Set(arr); paintDays(); paintSchedSummary(); };
    if ($('#st-days-wd')) $('#st-days-wd').addEventListener('click', () => setDays([1, 2, 3, 4, 5]));
    if ($('#st-days-we')) $('#st-days-we').addEventListener('click', () => setDays([0, 6]));
    if ($('#st-days-all')) $('#st-days-all').addEventListener('click', () => setDays([0, 1, 2, 3, 4, 5, 6]));

    $('#st-save').addEventListener('click', async () => {
      const payload = { rusense_notify_enabled: $('#st-master').checked };
      for (const [k] of TOGGLES) {
        const box = root.querySelector(`input[data-key="${k}"]`);
        payload[k] = !!(box && box.checked);
      }
      payload.rusense_notify_people_threshold = clampInt($('#st-threshold'), 1, 20, 1);
      payload.rusense_notify_cooldown_s = clampInt($('#st-cooldown'), 5, 3600, 60);
      payload.rusense_notify_min_confidence = clampInt($('#st-minconf'), 50, 99, 95) / 100;
      payload.rusense_notify_sustain_s = clampInt($('#st-sustain'), 0, 30, 2);
      payload.rusense_mode = mode;
      payload.rusense_inactivity_hours = clampInt($('#st-inact-hours'), 1, 24, 4);
      payload.rusense_quiet_start = clampInt($('#st-quiet-start'), 0, 23, 22);
      payload.rusense_quiet_end = clampInt($('#st-quiet-end'), 0, 23, 7);
      payload.rusense_alert_schedule_enabled = $('#st-sched').checked;
      payload.rusense_alert_days = [...schedDays].sort((a, b) => a - b);
      payload.rusense_alert_start = clampInt($('#st-sched-start'), 0, 23, 0);
      payload.rusense_alert_end = clampInt($('#st-sched-end'), 0, 23, 0);
      payload.rusense_geofence_enabled = $('#st-geofence').checked;
      // Reconcile the node map to the backend on every save (positions + names
      // also auto-sync as you edit them in the Observatory section below).
      try {
        const obs = loadObsSettings();
        payload.rusense_node_positions = obs.nodePositions || {};
        payload.rusense_node_names = obs.nodeLabels || {};
      } catch { /* ignore */ }

      const r = await req('POST', '/api/config', payload);
      toast(r.ok ? 'Settings saved' : ((r.data && r.data.error) || 'Could not save settings'),
        r.ok ? 'ok' : 'bad');
      refreshGeofenceStatus();
    });

    // Live geofence diagnostic — shows whether confinement is actually active.
    const refreshGeofenceStatus = async () => {
      const el = $('#st-geofence-status');
      if (!el) return;
      const g = await fetchJSON('/api/rusense/geofence');
      if (!g) { el.textContent = 'Geofence status unavailable (sensing backend offline?).'; return; }
      if (!g.enabled) { el.textContent = 'Geofence is OFF — alerts are not confined to the room.'; return; }
      if ((g.mapped_nodes || 0) < 3) {
        el.textContent = `Geofence ON but only ${g.mapped_nodes || 0} node(s) mapped — needs ≥3 to confine (currently a no-op).`;
        return;
      }
      const v = g.verdict || {};
      el.textContent = `Geofence ON · ${g.mapped_nodes} nodes mapped · live: ${v.reason || '—'} `
        + `(hot ${v.hot_count ?? '—'}, energy ${v.total ?? '—'}).`;
    };
    refreshGeofenceStatus();

    $('#st-test').addEventListener('click', async () => {
      const r = await req('POST', '/api/pushover/test');
      const ok = r.ok && r.data && r.data.success;
      toast(ok ? 'Test notification sent' : ((r.data && r.data.message) || 'Test failed — check Pushover keys'),
        ok ? 'ok' : 'bad');
    });

    // ── Wire the Observatory controls (pass config so node names/positions
    //    saved on another device seed this browser) ──
    this.wireObservatory(root, c);
  },

  // Bind every Observatory control to the shared localStorage. Pure
  // read-on-build + write-on-change — no timers, so this view stays static.
  wireObservatory(root, cfg) {
    // Server is the shared source of truth: seed localStorage from the config
    // we just fetched so a save made on any device shows up here, then read.
    seedObsFromServerConfig(cfg);
    let s = loadObsSettings();

    // Backend is the durable source of truth for node names/positions across
    // browsers. Seed any the local store is missing (never overwrite a local
    // edit) so a fresh device shows the saved map instead of blank labels.
    const bNames = (cfg && cfg.rusense_node_names) || {};
    const bPos = (cfg && cfg.rusense_node_positions) || {};
    let seeded = false;
    for (const [id, nm] of Object.entries(bNames)) {
      if (s.nodeLabels[id] == null && typeof nm === 'string' && nm.trim()) { s.nodeLabels[id] = nm; seeded = true; }
    }
    for (const [id, p] of Object.entries(bPos)) {
      if (!s.nodePositions[id] && p && typeof p === 'object') { s.nodePositions[id] = p; seeded = true; }
    }
    if (seeded) saveObsSettings(s);

    const syncRange = (key) => {
      const inp = root.querySelector(`[data-obs-range="${key}"]`);
      const val = root.querySelector(`[data-obs-val="${key}"]`);
      if (inp) inp.value = s[key];
      if (val) val.textContent = fmtVal(s[key]);
    };

    // Ranges
    $$('[data-obs-range]', root).forEach((inp) => {
      const key = inp.dataset.obsRange;
      syncRange(key);
      inp.addEventListener('input', () => {
        const v = parseFloat(inp.value);
        s[key] = Number.isFinite(v) ? v : DEFAULTS[key];
        const val = root.querySelector(`[data-obs-val="${key}"]`);
        if (val) val.textContent = fmtVal(s[key]);
        markCustom();
        saveObsSettings(s);
      });
    });

    // Colors
    $$('[data-obs-color]', root).forEach((inp) => {
      const key = inp.dataset.obsColor;
      inp.value = s[key] || DEFAULTS[key];
      inp.addEventListener('input', () => { s[key] = inp.value; markCustom(); saveObsSettings(s); });
    });

    // Checkboxes
    $$('[data-obs-check]', root).forEach((inp) => {
      const key = inp.dataset.obsCheck;
      inp.checked = !!s[key];
      inp.addEventListener('change', () => { s[key] = inp.checked; saveObsSettings(s); });
    });

    // Room number inputs
    $$('[data-obs-num]', root).forEach((inp) => {
      const key = inp.dataset.obsNum;
      inp.value = s[key];
      inp.addEventListener('input', () => {
        const v = parseFloat(inp.value);
        if (Number.isFinite(v)) { s[key] = v; saveObsSettings(s); }
      });
    });

    // Plain selects (scenario, dataSource)
    $$('[data-obs-select]', root).forEach((sel) => {
      const key = sel.dataset.obsSelect;
      sel.value = s[key];
      sel.addEventListener('change', () => {
        s[key] = sel.value;
        if (key === 'dataSource') toggleWsRow();
        saveObsSettings(s);
      });
    });

    // WS URL text
    const wsText = root.querySelector('[data-obs-text="wsUrl"]');
    if (wsText) {
      wsText.value = s.wsUrl || '';
      wsText.addEventListener('change', () => { s.wsUrl = wsText.value; saveObsSettings(s); });
    }
    const toggleWsRow = () => {
      const r = root.querySelector('#obs-wsurl-row');
      if (r) r.style.display = s.dataSource === 'ws' ? 'block' : 'none';
    };
    toggleWsRow();

    // Style preset → overlay onto defaults, persist, and refresh every control.
    const presetSel = root.querySelector('[data-obs-preset]');
    const markCustom = () => { if (presetSel) presetSel.value = 'custom'; };
    if (presetSel) {
      presetSel.value = 'custom';
      presetSel.addEventListener('change', () => {
        const p = PRESETS[presetSel.value];
        if (!p) return; // 'custom' — leave current values untouched
        // Preserve node/room/data fields; presets only touch visual knobs.
        const preserve = {
          scenario: s.scenario, cycle: s.cycle, dataSource: s.dataSource, wsUrl: s.wsUrl,
          grid: s.grid, room: s.room, roomX: s.roomX, roomY: s.roomY,
          nodeLabels: s.nodeLabels, nodePositions: s.nodePositions,
        };
        s = Object.assign(JSON.parse(JSON.stringify(DEFAULTS)), p, preserve);
        saveObsSettings(s);
        // Refresh all visual controls to the new values.
        Object.keys(OBS_RANGES).forEach((grp) => OBS_RANGES[grp].forEach(([k]) => syncRange(k)));
        $$('[data-obs-color]', root).forEach((inp) => { inp.value = s[inp.dataset.obsColor]; });
        toast('Preset applied', 'ok');
      });
    }

    // Reset / export
    const resetBtn = root.querySelector('#obs-reset');
    if (resetBtn) resetBtn.addEventListener('click', () => {
      s = JSON.parse(JSON.stringify(DEFAULTS));
      saveObsSettings(s);
      // Re-sync every control.
      Object.keys(OBS_RANGES).forEach((grp) => OBS_RANGES[grp].forEach(([k]) => syncRange(k)));
      $$('[data-obs-color]', root).forEach((inp) => { inp.value = s[inp.dataset.obsColor]; });
      $$('[data-obs-check]', root).forEach((inp) => { inp.checked = !!s[inp.dataset.obsCheck]; });
      $$('[data-obs-num]', root).forEach((inp) => { inp.value = s[inp.dataset.obsNum]; });
      $$('[data-obs-select]', root).forEach((sel) => { sel.value = s[sel.dataset.obsSelect]; });
      if (wsText) wsText.value = s.wsUrl || '';
      if (presetSel) presetSel.value = 'custom';
      toggleWsRow();
      renderNodes();
      toast('Observatory settings reset', 'ok');
    });

    const exportBtn = root.querySelector('#obs-export');
    if (exportBtn) exportBtn.addEventListener('click', () => {
      const blob = new Blob([JSON.stringify(s, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'ruview-observatory-settings.json';
      a.click();
      URL.revokeObjectURL(a.href);
    });

    // ── Interactive floor plan: drag node dots onto a top-down room square +
    //    rename inline. Replaces the old X/Y/Z numeric grid (X/Y is what the
    //    geofence uses; Z = height is a small optional field). Fetched once;
    //    "Refresh nodes" re-pulls. SVG viewBox is in metres (0..roomX, 0..roomY)
    //    so node coords map 1:1 to the picture.
    const NODE_PALETTE = ['#38bdf8', '#f472b6', '#facc15', '#34d399', '#a78bfa', '#fb923c', '#f87171', '#22d3ee'];

    const renderNodes = async () => {
      const container = root.querySelector('#obs-node-list');
      const hint = root.querySelector('#obs-node-hint');
      if (!container) return;
      let ids = [];
      try {
        const n = await fetchJSON('/api/v1/nodes');
        ids = (n?.nodes || []).map((x) => x.node_id).filter((x) => x != null);
      } catch { /* offline — keep whatever node overrides are already saved */ }
      if (!ids.length) {
        ids = [...new Set([...Object.keys(s.nodeLabels), ...Object.keys(s.nodePositions)])];
      }
      ids = [...new Set(ids.map(String))].sort((a, b) => {
        const na = Number(a), nb = Number(b);
        return (Number.isFinite(na) && Number.isFinite(nb)) ? na - nb : a.localeCompare(b);
      });

      const roomX = Number(s.roomX) > 0 ? Number(s.roomX) : 5;
      const roomY = Number(s.roomY) > 0 ? Number(s.roomY) : 5;
      const clampX = (v) => Math.max(0, Math.min(roomX, v));
      const clampY = (v) => Math.max(0, Math.min(roomY, v));

      if (hint) hint.textContent = ids.length
        ? `${ids.length} node${ids.length > 1 ? 's' : ''} · drag the dots to match your room`
        : 'No nodes reporting — open the Observatory once nodes are live.';

      // Auto-place any node without a saved (x,y) so it lands on the plan ready
      // to drag (spread around the centre). Saved immediately so the geofence
      // gets ≥3 corners without manual typing.
      let placedAny = false;
      ids.forEach((id, i) => {
        const p = s.nodePositions[id];
        if (!p || typeof p !== 'object' || !Number.isFinite(p.x) || !Number.isFinite(p.y)) {
          const ang = (i / Math.max(1, ids.length)) * Math.PI * 2;
          s.nodePositions[id] = {
            x: +clampX(roomX / 2 + Math.cos(ang) * roomX * 0.3).toFixed(2),
            y: +clampY(roomY / 2 + Math.sin(ang) * roomY * 0.3).toFixed(2),
            z: (p && Number.isFinite(p.z)) ? p.z : 0,
          };
          placedAny = true;
        }
      });
      if (placedAny) { saveObsSettings(s); syncNodePositionsToBackend(s.nodePositions); }

      const span = Math.max(roomX, roomY);
      const r = span * 0.045;          // handle radius, metres
      const fs = r * 1.5;              // label font size, metres
      const sw = span * 0.005;         // grid stroke, metres
      const pos = (id) => s.nodePositions[id];
      const labelOf = (id) => (s.nodeLabels[id] && s.nodeLabels[id].trim()) || `#${id}`;

      let grid = '';
      for (let gx = 1; gx < roomX; gx++) grid += `<line x1="${gx}" y1="0" x2="${gx}" y2="${roomY}" stroke="#1e293b" stroke-width="${sw}"/>`;
      for (let gy = 1; gy < roomY; gy++) grid += `<line x1="0" y1="${gy}" x2="${roomX}" y2="${gy}" stroke="#1e293b" stroke-width="${sw}"/>`;

      const handle = (id, i) => {
        const p = pos(id), c = NODE_PALETTE[i % NODE_PALETTE.length];
        const cx = clampX(p.x), cy = clampY(p.y);
        return `<g data-handle="${id}" style="cursor:grab">
          <circle cx="${cx}" cy="${cy}" r="${r}" fill="${c}" fill-opacity="0.85" stroke="#0b0f12" stroke-width="${r * 0.18}"/>
          <text x="${cx}" y="${cy - r * 1.35}" text-anchor="middle" font-size="${fs}" fill="#e8eef3"
                style="pointer-events:none;font-weight:600">${labelOf(id)}</text>
        </g>`;
      };

      container.innerHTML = `
        <div class="rounded-lg bg-ink-0 border border-ink-3 p-2" style="max-width:50%">
          <svg id="node-plan" viewBox="0 0 ${roomX} ${roomY}" preserveAspectRatio="xMidYMid meet"
               style="width:100%;aspect-ratio:${roomX}/${roomY};display:block;touch-action:none">
            <rect x="0" y="0" width="${roomX}" height="${roomY}" fill="#0e1726" stroke="#334155" stroke-width="${span * 0.01}"/>
            ${grid}
            ${ids.map(handle).join('')}
          </svg>
        </div>
        <p class="text-xs text-ink-muted mt-1">Top-down view · room ${roomX}×${roomY} m. Drag each dot to where the node sits;
          set room size under <em>Scene</em>. ≥3 nodes needed for the geofence.</p>
        <div id="node-rows" class="mt-2"></div>`;

      const rows = container.querySelector('#node-rows');
      rows.innerHTML = ids.map((id, i) => {
        const c = NODE_PALETTE[i % NODE_PALETTE.length], p = pos(id);
        return `<div class="flex flex-wrap items-center gap-2 py-2 border-b border-ink-3 last:border-0">
          <span class="shrink-0 w-3 h-3 rounded-full" style="background:${c}"></span>
          <input type="text" data-node-name="${id}" placeholder="Node ${id}"
            class="flex-1 min-w-[8rem] bg-ink-1 border border-ink-3 rounded-lg px-2.5 py-1.5 text-sm" />
          <span data-readout="${id}" class="shrink-0 text-xs font-mono text-ink-muted w-24 text-right">(${p.x.toFixed(1)}, ${p.y.toFixed(1)}) m</span>
          <input type="number" step="0.1" data-node-z="${id}" value="${Number.isFinite(p.z) ? p.z : 0}" title="Height Z (m)"
            class="shrink-0 w-16 bg-ink-1 border border-ink-3 rounded-lg px-2 py-1.5 text-sm font-mono" />
        </div>`;
      }).join('');

      // Names — update both the saved label and the live plan text.
      $$('[data-node-name]', rows).forEach((inp) => {
        const id = inp.dataset.nodeName;
        inp.value = s.nodeLabels[id] != null ? s.nodeLabels[id] : '';
        inp.addEventListener('input', () => {
          if (inp.value.length) s.nodeLabels[id] = inp.value; else delete s.nodeLabels[id];
          saveObsSettings(s);
          syncNodeNamesToBackend(s.nodeLabels);
          const t = container.querySelector(`#node-plan g[data-handle="${id}"] text`);
          if (t) t.textContent = inp.value.trim() || `#${id}`;
        });
      });
      // Z (height) — optional, used only by the 3D Observatory view.
      $$('[data-node-z]', rows).forEach((inp) => {
        const id = inp.dataset.nodeZ;
        inp.addEventListener('input', () => {
          const v = parseFloat(inp.value);
          if (!Number.isFinite(v)) return;
          (s.nodePositions[id] || (s.nodePositions[id] = {})).z = v;
          saveObsSettings(s);
          syncNodePositionsToBackend(s.nodePositions);
        });
      });

      // Drag handles — pointer capture so the drag tracks outside the dot too.
      const svg = container.querySelector('#node-plan');
      const toMeters = (e) => {
        const b = svg.getBoundingClientRect();
        return { x: clampX((e.clientX - b.left) / b.width * roomX), y: clampY((e.clientY - b.top) / b.height * roomY) };
      };
      let drag = null;
      svg.querySelectorAll('g[data-handle]').forEach((g) => {
        const id = g.dataset.handle;
        g.addEventListener('pointerdown', (e) => {
          e.preventDefault();
          drag = g; g.style.cursor = 'grabbing';
          try { g.setPointerCapture(e.pointerId); } catch { /* ignore */ }
        });
        g.addEventListener('pointermove', (e) => {
          if (drag !== g) return;
          const m = toMeters(e);
          g.querySelector('circle').setAttribute('cx', m.x);
          g.querySelector('circle').setAttribute('cy', m.y);
          const t = g.querySelector('text');
          t.setAttribute('x', m.x); t.setAttribute('y', m.y - r * 1.35);
          const ro = container.querySelector(`[data-readout="${id}"]`);
          if (ro) ro.textContent = `(${m.x.toFixed(1)}, ${m.y.toFixed(1)}) m`;
          const p = s.nodePositions[id] || (s.nodePositions[id] = {});
          p.x = +m.x.toFixed(2); p.y = +m.y.toFixed(2);
          if (!Number.isFinite(p.z)) p.z = 0;
        });
        const end = (e) => {
          if (drag !== g) return;
          drag = null; g.style.cursor = 'grab';
          try { g.releasePointerCapture(e.pointerId); } catch { /* ignore */ }
          saveObsSettings(s);
          syncNodePositionsToBackend(s.nodePositions);
        };
        g.addEventListener('pointerup', end);
        g.addEventListener('pointercancel', end);
      });
    };

    const refreshBtn = root.querySelector('#obs-node-refresh');
    if (refreshBtn) refreshBtn.addEventListener('click', renderNodes);
    // Re-draw the plan when the room size changes (on commit, not every keystroke).
    ['roomX', 'roomY'].forEach((k) => {
      const el = root.querySelector(`[data-obs-num="${k}"]`);
      if (el) el.addEventListener('change', () => renderNodes());
    });
    renderNodes();
  },
};
