// About — a getting-started guide for RuSense: flashing nodes, placing them,
// the geofence, phone alerts, and full credit to the RuView project that powers
// it. Sourced from docs/rusense.md so the UI and docs stay in agreement.
import { icons } from '../icons.js';
import { html } from '../lib.js?v=20260704-sparkfit';

const FLASHER_URL = 'https://pierregode.github.io/Ragnar/';
const RUVIEW_URL = 'https://github.com/ruvnet/ruview';          // the source project (by ruvnet)
const RUVIEW_FORK_URL = 'https://github.com/PierreGode/RuView';  // the fork Ragnar vendors bins from

const PIPELINE = [
  ['CSI input', 'Channel State Information from the WiFi antenna array'],
  ['Phase sanitization', 'Remove hardware-specific noise, normalize signal phase'],
  ['Feature extraction', 'Variance, motion/breath bands, spectral power, change points'],
  ['Inference', 'Presence, posture, vital signs and (optional) pose keypoints'],
  ['Fusion & output', 'Multistatic fusion across nodes → trusted sensing output'],
];
const APPS = [
  ['🛟', 'Elderly & fall monitoring', 'Detect falls and routine anomalies without cameras.'],
  ['🏠', 'Presence & security', 'Through-wall occupancy and intrusion sensing, no line of sight.'],
  ['🏥', 'Patient monitoring', 'Breathing and heart-rate trends from CSI, contact-free.'],
  ['🏢', 'Smart buildings', 'Occupancy-driven HVAC / lighting without privacy intrusion.'],
];

// ── small render helpers ────────────────────────────────────────────────────
const stepList = (items) => `<ol class="space-y-2.5">${items.map((d, i) => `<li class="flex gap-3">
  <span class="shrink-0 w-6 h-6 rounded-full bg-brand-500/20 text-brand-300 text-xs font-bold grid place-items-center">${i + 1}</span>
  <div class="text-sm text-ink-soft">${d}</div></li>`).join('')}</ol>`;

const bullets = (items) => `<ul class="space-y-2 text-sm text-ink-soft">${items.map((d) =>
  `<li class="flex gap-2"><span class="text-brand-300 shrink-0">•</span><span>${d}</span></li>`).join('')}</ul>`;

const callout = (label, text) => `<div class="rounded-lg border border-ink-3 bg-ink-1 p-3 text-sm text-ink-soft">
  <span class="text-warn font-semibold">⚠ ${label}</span> — ${text}</div>`;

const linkBtn = (href, text, ext = false) =>
  `<a href="${href}" ${ext ? 'target="_blank" rel="noopener"' : ''} class="btn-ghost">${text}</a>`;

export default {
  id: 'about',
  label: 'About',
  icon: icons.about,

  async mount(root) {
    root.appendChild(html`
      <section class="space-y-6">
        <!-- Hero -->
        <div class="card card-pad space-y-3">
          <h2 class="text-xl font-bold">RuSense — camera-free WiFi sensing</h2>
          <p class="text-ink-soft">No cameras, no microphones. RuSense reads the tiny distortions a moving body imprints on the ordinary 2.4 GHz WiFi already filling your space, and turns them into presence, motion, people-count, coarse pose and resting vital signs — in total darkness and through walls, on low-cost ESP32 nodes.</p>
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            ${[['🏠', 'Through walls'], ['🔒', 'Privacy-preserving'], ['⚡', 'Real-time'], ['💰', 'Low-cost HW']]
              .map(([i, t]) => `<div class="stat items-center text-center"><span class="text-2xl">${i}</span><span class="text-xs text-ink-muted">${t}</span></div>`).join('')}
          </div>
          <a href="${RUVIEW_URL}" target="_blank" rel="noopener" class="block rounded-lg border border-brand-500/30 bg-brand-500/10 p-3 text-sm">
            <span class="font-semibold text-brand-300">⚡ Powered by RuView</span>
            <span class="text-ink-soft"> — the WiFi-CSI DensePose sensing engine and ESP32 CSI-node firmware behind RuSense, by ruvnet. All the sensing magic is theirs.</span>
          </a>
        </div>

        <!-- How it works -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">How it works</h3>
          <p class="text-sm text-ink-soft">Every WiFi packet spreads across dozens of frequency <em>subcarriers</em>; the receiver measures each one's amplitude and phase — its <strong>Channel State Information (CSI)</strong>. A body moving, breathing, or simply standing reflects and scatters those subcarriers in a measurable way. A RuSense node samples up to <strong>114 subcarriers at ~100 Hz</strong> on 2.4 GHz and streams that fingerprint of the room for analysis — never any video.</p>
          <div class="overflow-x-auto -mx-1">
            <pre class="text-xs font-mono text-ink-soft bg-ink-0 rounded-lg p-3 whitespace-pre">  ESP32 CSI node(s)  ──UDP CSI frames──▶  sensing-server  ──HTTP/WS──▶  Ragnar web UI
   (ESP32-S3 / C6)        :5005             (127.0.0.1:3000)            (RuSense tabs)</pre>
          </div>
          <div class="text-sm font-medium">What it can report</div>
          ${bullets([
            '<strong>Presence / occupancy</strong> — is anyone in the room?',
            '<strong>Motion</strong> — movement intensity and events.',
            '<strong>People count</strong> — estimated number of people present.',
            '<strong>Pose / posture</strong> — coarse body keypoints, with a trained model.',
            '<strong>Vital signs</strong> — breathing and heart rate for a still subject.',
            '<strong>Signal quality</strong> — so you know when a reading is trustworthy.',
          ])}
        </div>

        <!-- 1 · Flash -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">1 · Flash your nodes</h3>
          <p class="text-sm text-ink-soft">No toolchain needed — the firmware flashes straight from your browser over USB (Web Serial / esptool-js).</p>
          <div>${linkBtn(FLASHER_URL, '🔥 Open the RuSense Flasher →', true)}</div>
          ${stepList([
            'Open the flasher in <strong>Chrome or Edge</strong> (Web Serial isn\'t available in Firefox/Safari).',
            'Plug the ESP32 in with a <strong>data-capable</strong> USB-C cable — charge-only cables won\'t work.',
            'Pick your board: <strong>ESP32-S3</strong> <em>(recommended, production — dual-core, 8 MB, steadiest for live CSI)</em> or <strong>ESP32-C6</strong> <em>(Wi-Fi 6 research — RISC-V, 4 MB, dual-band 802.11ax)</em>.',
            'Click <strong>Forge</strong>, select the <span class="font-mono">USB JTAG/serial debug unit</span> port, and let it flash.',
            'Not detected? Hold <strong>BOOT</strong> while tapping <strong>RST</strong>, then retry.',
          ])}
          ${callout('Use one chip type for every node', 'S3 and C6 capture different CSI widths (128 vs 192 subcarriers) and the engine\'s multistatic fusion needs them all the same. A mixed fleet breaks fusion and falls back to per-node processing — you lose accurate people-counting, positioning, pose and vitals (presence, motion and the geofence still work). S3 is recommended; use C6 only if you specifically want Wi-Fi 6, and then make <em>every</em> node a C6.')}
          <p class="text-xs text-ink-muted">Firmware bins are vendored bit-identically from RuView at a pinned commit.</p>
        </div>

        <!-- 2 · Place -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">2 · Place your nodes</h3>
          ${bullets([
            'One node covers <strong>presence and motion</strong> for a room. Add more around the space and the engine fuses their views (multistatic fusion) for better people-counting and coarse positioning.',
            'Position each node so the area you care about sits <strong>between the node and the WiFi traffic</strong> it\'s listening to — CSI is richest along that path.',
            'Keep nodes on <strong>mains power</strong> and a stable WiFi channel. Once provisioned, frames-per-second on the <strong>Nodes</strong> tab should be non-zero and steady.',
            'Keep nodes <strong>stationary</strong> — moving one changes its CSI fingerprint.',
            'Vital signs need a <strong>still</strong> subject (someone at rest); motion otherwise dominates.',
            'For the geofence, aim for <strong>≥ 3 nodes</strong> roughly at the room\'s corners.',
          ])}
          ${callout('Put every node on ONE access point + one fixed channel', 'The nodes sync their clocks to each other over WiFi, and that only works when they are all joined to the <strong>same access point on the same 2.4 GHz channel</strong>. If your home has several routers or a mesh/extenders sharing one SSID, each node can latch onto a different AP on a different channel — their clocks then drift by <em>seconds</em>, the engine can\'t fuse them, and the Nodes tab shows <em>“Sync failing” / offline</em>. Give the nodes a <strong>single AP</strong> (ideally a dedicated SSID served by one router), <strong>lock it to a fixed channel</strong> (disable auto-channel), and keep every node in good signal range of it. Watch the <strong>Mesh health</strong> panel on the Nodes tab — healthy is sub-millisecond offsets; seconds mean split APs.')}
        </div>

        <!-- 3 · Geofence -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">3 · Confine alerts with a geofence</h3>
          <p class="text-sm text-ink-soft">The biggest source of false alerts is motion <em>outside</em> the room — neighbours through a wall, people in the hallway. The geofence treats each node as a disturbance sensor anchored at its mapped corner and only passes an alert when the disturbance is <strong>corroborated and interior</strong> to the polygon of node corners. A lone-node or edge-pinned walk-by is suppressed; the "room empty" alert never is.</p>
          ${stepList([
            'Map each node\'s <strong>X / Y</strong> corner in <strong>Settings → Observatory → Room &amp; Nodes</strong> (auto-syncs to the backend). You need <strong>≥ 3 nodes mapped</strong>; with fewer, the geofence is a no-op.',
            'Leave <strong>"Confine alerts to the room (geofence)"</strong> enabled in the Settings tab.',
            'Validate live: the status line under the toggle shows the verdict — <span class="font-mono">inside perimeter</span>, <span class="font-mono">edge/outside</span>, or <span class="font-mono">quiet</span>.',
          ])}
          <p class="text-xs text-ink-muted">It\'s a coarse RSSI-based filter, not a hard RF wall — 2.4 GHz leaks through walls.</p>
        </div>

        <!-- 4 · Alerts -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">4 · Phone alerts (Pushover)</h3>
          <p class="text-sm text-ink-soft">RuSense sends a <strong>Pushover</strong> push when it detects activity — evaluated <strong>server-side</strong>, so alerts fire even with no browser open.</p>
          ${stepList([
            'Set your Pushover <strong>User Key + API Token</strong> once under the main dashboard\'s <strong>Config → Pushover Notifications</strong>.',
            'Pick a <strong>Monitoring mode</strong> in Settings: <strong>Security</strong> (space should be empty — alert when someone appears), <strong>Health</strong> (space should be occupied — alert when it goes quiet, e.g. checking in on grandparents), or <strong>Both</strong>.',
            'Enable the triggers you want in the RuSense <strong>Settings</strong> tab (a master switch plus per-trigger toggles).',
            'Optionally set <strong>Permitted alert times</strong> (Settings) to restrict surveillance alerts to chosen days + hours — e.g. an office only on weekends, or a space only at night.',
            'Use <strong>Send test notification</strong> to confirm delivery.',
          ])}
          <div class="text-sm font-medium">Triggers</div>
          ${bullets([
            '<strong>Presence / occupancy</strong> — a space goes empty → occupied (and back).',
            '<strong>Motion</strong> — significant active motion is detected.',
            '<strong>People-count threshold</strong> — the count crosses a value you set (median across active nodes, so one spiking node can\'t trip it).',
            '<strong>Node offline</strong> — a provisioned CSI node stops streaming.',
            '<strong>Inactivity (health)</strong> — the inverse of presence: an expected-occupied space shows <em>no</em> activity for the set awake hours. The quiet (sleep) window never counts, so a normal night stays silent.',
          ])}
          ${callout('False-positive guards', 'An alert only fires when <strong>all</strong> hold: minimum confidence (default 80%), the condition lasts a sustain window (default 2 s), and the disturbance is inside the geofence. A cooldown stops a flapping signal from spamming you.')}
          <p class="text-sm text-ink-soft">Every confirmed presence alert is also logged to the Dashboard\'s <strong>Recent sightings</strong> — with how long the person was seen — so you can review a detection even after they\'ve left. The Dashboard\'s <strong>Health trends</strong> card additionally charts 7 days of heart-rate / breathing / activity history with resting averages — wellness tracking, <em>not</em> a medical device.</p>
          <p class="text-xs text-ink-muted">The alert monitor runs inside the <span class="font-mono">ragnar</span> service. After changing alert settings or pulling new code, restart it: <span class="font-mono">sudo systemctl restart ragnar</span>.</p>
        </div>

        <!-- Training -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">Training (optional)</h3>
          ${bullets([
            '<strong>Adaptive (on-device)</strong> — a lightweight classifier learned from your own recorded/live CSI via the <strong>Record → Train → Active</strong> loop in the Training tab. Fast, runs on the Pi, tuned to your room.',
            '<strong>Deep-model dataset training</strong> — heavy offline training from MM-Fi / Wi-Pose datasets into a <span class="font-mono">.rvf</span> model, for pose- and vital-sign-capable models.',
          ])}
        </div>

        <!-- Pipeline -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">Processing pipeline</h3>
          <ol class="space-y-2">
            ${PIPELINE.map(([t, d], i) => `<li class="flex gap-3">
              <span class="shrink-0 w-6 h-6 rounded-full bg-brand-500/20 text-brand-300 text-xs font-bold grid place-items-center">${i + 1}</span>
              <div><div class="font-medium text-sm">${t}</div><div class="text-xs text-ink-muted">${d}</div></div></li>`).join('')}
          </ol>
        </div>

        <!-- Applications -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">Applications</h3>
          <div class="grid gap-3 sm:grid-cols-2">
            ${APPS.map(([i, t, d]) => `<div class="rounded-lg bg-ink-1 border border-ink-3 p-3">
              <div class="text-xl mb-1">${i}</div><div class="font-medium text-sm">${t}</div><div class="text-xs text-ink-muted">${d}</div></div>`).join('')}
          </div>
        </div>

        <!-- Reference performance -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">Reference performance</h3>
          <p class="text-xs text-ink-muted">Published WiFi-DensePose benchmark (same-layout). Live accuracy depends on calibration and hardware.</p>
          <div class="grid grid-cols-3 gap-3">
            ${[['AP@50', '87.2%'], ['Avg precision', '43.5%'], ['AP@75', '44.6%']]
              .map(([l, v]) => `<div class="stat"><span class="stat-value text-brand-300">${v}</span><span class="stat-label">${l}</span></div>`).join('')}
          </div>
        </div>

        <!-- Credits -->
        <div class="card card-pad space-y-3">
          <h3 class="card-title">Credits — RuView</h3>
          <p class="text-sm text-ink-soft">RuSense is powered by <a href="${RUVIEW_URL}" target="_blank" rel="noopener" class="text-brand-300 font-semibold">RuView</a> — the WiFi-CSI DensePose sensing engine (crate <span class="font-mono">wifi-densepose-sensing-server</span>), created by <strong>ruvnet</strong>. <strong>All of the CSI ingestion, inference, pose estimation and training logic originates there.</strong> Ragnar just vendors RuView's prebuilt sensing server and ESP32 CSI-node firmware (via the <a href="${RUVIEW_FORK_URL}" target="_blank" rel="noopener" class="text-brand-300">PierreGode/RuView</a> fork). Full credit and thanks to the RuView project.</p>
          <div>${linkBtn(RUVIEW_URL, 'github.com/ruvnet/ruview →', true)}</div>
        </div>

        <!-- Links -->
        <div class="card card-pad flex flex-wrap gap-3">
          ${linkBtn(FLASHER_URL, 'RuSense Flasher', true)}
          ${linkBtn('observatory.html', 'Observatory')}
          ${linkBtn(RUVIEW_URL, 'RuView on GitHub', true)}
          ${linkBtn('/api/v1/info', 'API info')}
        </div>
        <p class="text-center text-xs text-ink-muted pb-2">RuSense · powered by RuView · WiFi-DensePose v2</p>
      </section>`);
  },
};
