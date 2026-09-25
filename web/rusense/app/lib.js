// Tiny DOM + formatting helpers shared across views. No framework, no deps.

/** Create an element from an HTML string (first root node). */
export function html(strings, ...values) {
  const tpl = document.createElement('template');
  tpl.innerHTML = String.raw({ raw: strings }, ...values).trim();
  return tpl.content.firstElementChild;
}

/** Scope root for $/$$ — set to a ShadowRoot when embedded so view lookups
 *  resolve inside the shadow island instead of the host document. */
let _queryRoot = (typeof document !== 'undefined') ? document : null;
export function setQueryRoot(root) { _queryRoot = root || _queryRoot; }
/** querySelector shorthand scoped to the active query root (or an explicit root). */
export const $ = (sel, root) => (root || _queryRoot).querySelector(sel);
export const $$ = (sel, root) => [...(root || _queryRoot).querySelectorAll(sel)];

/** Coalesce rapid calls into a steady cadence: run at most once per `ms`,
 *  always using the most recent arguments, with a guaranteed trailing call so
 *  the final frame still renders. Stops fast live frames (10-20/s) from
 *  re-laying-out the dashboard cards several times a second. */
export function throttleLatest(fn, ms = 250) {
  let lastRun = 0, timer = null, lastArgs = null;
  const now = () => (typeof performance !== 'undefined' ? performance.now() : 0);
  return (...args) => {
    lastArgs = args;
    const wait = ms - (now() - lastRun);
    if (wait <= 0) {
      lastRun = now();
      fn(...lastArgs);
    } else if (!timer) {
      timer = setTimeout(() => { timer = null; lastRun = now(); fn(...lastArgs); }, wait);
    }
  };
}

/** Fetch JSON with a short timeout; returns null on any failure. */
export async function fetchJSON(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeout ?? 6000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, ...opts });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

export const fmt = {
  pct: (v, d = 0) => (v == null || isNaN(v) ? '—' : `${(v * (v <= 1 ? 100 : 1)).toFixed(d)}%`),
  num: (v, d = 2) => (v == null || isNaN(v) ? '—' : Number(v).toFixed(d)),
  int: (v) => (v == null || isNaN(v) ? '—' : Math.round(v).toLocaleString()),
  dbm: (v) => (v == null || isNaN(v) ? '—' : `${Number(v).toFixed(1)} dBm`),
  ago: (sec) => {
    if (sec == null) return '—';
    const s = Math.max(0, Math.floor(sec));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
  },
};

/** Confidence below which a WiFi-CSI vital sign is treated as noise, not a
 *  reading. CSI vitals always produce *some* spectral peak (even on an empty
 *  room or through walls), so an unconfident value is a phantom, not a pulse. */
export const VITAL_MIN_CONFIDENCE = 0.3;

/** Render a vital sign ONLY when someone is present AND the detector is
 *  confident; otherwise "—". Always returns a string so a stale reading clears
 *  the instant the signal drops, instead of freezing on screen. */
export function vitalText(value, confidence, decimals = 0, present = true) {
  if (!present || value == null || !(Number(confidence) >= VITAL_MIN_CONFIDENCE)) return '—';
  return fmt.num(value, decimals);
}

/** Set a meter bar fill (0..1) + colour by threshold. */
export function setMeter(spanEl, value, { warn = 0.7, bad = 0.9 } = {}) {
  const v = Math.max(0, Math.min(1, value ?? 0));
  spanEl.style.width = `${v * 100}%`;
  const cls = v >= bad ? 'bg-bad' : v >= warn ? 'bg-warn' : 'bg-brand-400';
  spanEl.className = `block h-full rounded-full transition-all duration-500 ${cls}`;
}

/** Lightweight toast. */
export function toast(msg, kind = 'info') {
  const root = (_queryRoot && _queryRoot.querySelector('#toast-root')) || document.getElementById('toast-root');
  if (!root) return;
  const colors = { info: 'bg-ink-3 text-ink-fg', ok: 'bg-ok/20 text-ok', warn: 'bg-warn/20 text-warn', bad: 'bg-bad/20 text-bad' };
  const t = html`<div class="pointer-events-auto rounded-lg px-4 py-2.5 text-sm shadow-card ${colors[kind] || colors.info}">${msg}</div>`;
  root.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .4s'; }, 3200);
  setTimeout(() => t.remove(), 3700);
}

/** Draw a simple sparkline path into an inline SVG given values + bounds. */
export function sparkPath(values, w, h, min, max, pad = 2) {
  if (!values.length) return '';
  const lo = min ?? Math.min(...values);
  const hi = max ?? Math.max(...values);
  const span = hi - lo || 1;
  const step = w / Math.max(1, values.length - 1);
  const ih = h - pad * 2; // inset so the stroke isn't clipped at the viewBox edges
  return values
    .map((v, i) => {
      const t = Math.max(0, Math.min(1, (v - lo) / span));
      return `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(h - pad - t * ih).toFixed(1)}`;
    })
    .join(' ');
}
