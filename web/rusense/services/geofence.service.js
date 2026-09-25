// Geofence (Tier 1, web-layer prototype) — confine motion detection to the
// polygon formed by the mapped node corners, and reject disturbances whose
// spatial signature points OUTSIDE that perimeter (hallway walk-bys, through-
// wall motion from one side).
//
// HONEST SCOPE — read before trusting this:
//   RuSense nodes are passive receivers of ambient WiFi (one/few transmitters,
//   not a node<->node mesh), so we do NOT have clean pairwise link tomography.
//   What we DO have, live, is per-node RSSI. This module treats each node as a
//   disturbance sensor anchored at its mapped (x,y) corner and reasons about
//   the *pattern across corners*:
//     - A person genuinely INSIDE the room sits within the hull of all corners,
//       so several corners react and the disturbance centroid lands interior.
//     - A walk-by just OUTSIDE one edge lights up mainly the nearest corner(s),
//       so the centroid is pinned to an edge/corner and few nodes corroborate.
//   This is coarse, zone-level confinement — not precise (x,y) tracking, and
//   not a hard RF wall (2.4 GHz leaks through walls). It is a tunable filter to
//   cut outside-the-room ghosts, evaluated visually on the Sensing tab.
//
// The proper version (true radio-tomographic reconstruction clipped to the
// polygon) lives in the Rust backend — see docs / RuView. This file is JS-only
// and changes nothing server-side, including the Pushover alert loop.

import { sensingService } from './sensing.service.js';

const OBS_SETTINGS_KEY = 'ruview-observatory-settings';

// --- Tunables -------------------------------------------------------------
export const GEOFENCE_DEFAULTS = {
  windowSize: 60,        // RSSI samples per node kept for the disturbance stat (~3-6 s)
  dbmScale: 2.0,         // dBm of RSSI std that maps to ~0.63 disturbance (soft knee)
  hotThreshold: 0.35,    // a node counts as "disturbed" above this (0..1)
  minHotNodes: 2,        // corroboration floor — kills single-corner walk-bys
  insetFraction: 0.08,   // shrink the polygon toward its centre; boundary leans "outside"
  minTotalDisturbance: 0.5, // floor on summed disturbance so idle jitter stays quiet
};

// --- Pure geometry helpers (exported for testing/visualisation) -----------

/** Andrew's monotone-chain convex hull of [{x,y,id}] -> ordered ring (CCW). */
export function convexHull(pts) {
  const p = pts.filter((q) => Number.isFinite(q.x) && Number.isFinite(q.y))
    .slice().sort((a, b) => (a.x - b.x) || (a.y - b.y));
  if (p.length < 3) return p;
  const cross = (o, a, b) => (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const lower = [];
  for (const q of p) {
    while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], q) <= 0) lower.pop();
    lower.push(q);
  }
  const upper = [];
  for (let i = p.length - 1; i >= 0; i--) {
    const q = p[i];
    while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], q) <= 0) upper.pop();
    upper.push(q);
  }
  upper.pop(); lower.pop();
  return lower.concat(upper);
}

/** Ray-casting point-in-polygon. polygon = ordered ring of {x,y}. */
export function pointInPolygon(pt, polygon) {
  if (!polygon || polygon.length < 3) return false;
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const xi = polygon[i].x, yi = polygon[i].y, xj = polygon[j].x, yj = polygon[j].y;
    const hit = ((yi > pt.y) !== (yj > pt.y)) &&
      (pt.x < ((xj - xi) * (pt.y - yi)) / ((yj - yi) || 1e-9) + xi);
    if (hit) inside = !inside;
  }
  return inside;
}

/** Polygon centroid (vertex average — good enough for an inset anchor). */
export function polygonCentroid(polygon) {
  const n = polygon.length || 1;
  return polygon.reduce((a, p) => ({ x: a.x + p.x / n, y: a.y + p.y / n }), { x: 0, y: 0 });
}

/** Shrink a polygon toward its centroid by `frac` (0..1). */
export function insetPolygon(polygon, frac) {
  if (!polygon || polygon.length < 3 || !frac) return polygon;
  const c = polygonCentroid(polygon);
  return polygon.map((p) => ({ x: p.x + (c.x - p.x) * frac, y: p.y + (c.y - p.y) * frac, id: p.id }));
}

/** Standard deviation of an array. */
export function std(arr) {
  if (arr.length < 2) return 0;
  const m = arr.reduce((a, b) => a + b, 0) / arr.length;
  const v = arr.reduce((a, b) => a + (b - m) * (b - m), 0) / arr.length;
  return Math.sqrt(v);
}

function emptyVerdict(reason) {
  return { ok: false, reason, insideMotion: false, score: 0, hotCount: 0,
    total: 0, centroid: null, polygon: [], inset: [], nodes: [] };
}

/**
 * Pure geofence decision. `positions` = {id: {x,y,z}}, `windows` = {id: [rssi…]}.
 * Exported so the verdict can be unit-tested without DOM/localStorage/WS.
 */
export function evaluateGeofence(positions, windows, opts) {
  const o = { ...GEOFENCE_DEFAULTS, ...(opts || {}) };
  const { dbmScale, hotThreshold, minHotNodes, insetFraction, minTotalDisturbance } = o;

  // Per-node disturbance from RSSI std, soft-kneed into 0..1.
  const nodes = [];
  for (const [id, pos] of Object.entries(positions || {})) {
    if (!pos || !Number.isFinite(pos.x) || !Number.isFinite(pos.y)) continue;
    const win = (windows && windows[id]) || [];
    const disturbance = 1 - Math.exp(-std(win) / (dbmScale || 1e-9));
    nodes.push({ id, x: pos.x, y: pos.y, samples: win.length, disturbance,
      hot: disturbance >= hotThreshold });
  }

  if (nodes.length < 3) return emptyVerdict('map >=3 node corners (X/Y) in Settings');

  const polygon = convexHull(nodes);
  const inset = insetPolygon(polygon, insetFraction);

  // Disturbance-weighted centroid across the corners.
  const total = nodes.reduce((a, n) => a + n.disturbance, 0);
  let centroid = null;
  if (total > 1e-6) {
    centroid = nodes.reduce((a, n) => ({
      x: a.x + (n.x * n.disturbance) / total,
      y: a.y + (n.y * n.disturbance) / total,
    }), { x: 0, y: 0 });
  }

  const hotCount = nodes.filter((n) => n.hot).length;
  const interior = centroid ? pointInPolygon(centroid, inset) : false;
  const corroborated = hotCount >= minHotNodes;
  const energetic = total >= minTotalDisturbance;

  const insideMotion = interior && corroborated && energetic;
  const breadth = Math.min(1, hotCount / nodes.length);
  const score = insideMotion ? Math.min(1, breadth * 0.5 + Math.min(1, total / nodes.length) * 0.5) : 0;

  let reason = 'inside perimeter';
  if (!energetic) reason = 'quiet';
  else if (!corroborated) reason = `edge/outside — only ${hotCount} corner disturbed`;
  else if (!interior) reason = 'disturbance centroid outside perimeter';

  return { ok: true, reason, insideMotion, score, hotCount, total, centroid, polygon, inset, nodes };
}

// --- Service --------------------------------------------------------------

class GeofenceService {
  constructor() {
    this.opts = { ...GEOFENCE_DEFAULTS };
    this._windows = {};        // node_id -> recent RSSI samples
    this._listeners = new Set();
    this._off = null;
    this._latest = this._emptyVerdict('no nodes mapped');
  }

  configure(partial) { this.opts = { ...this.opts, ...partial }; }

  /** Subscribe to verdicts. Returns an unsubscribe fn. Lazily attaches to the
   *  sensing stream on first listener; detaches when the last one leaves. */
  onVerdict(cb) {
    this._listeners.add(cb);
    if (!this._off) this._off = sensingService.onData((d) => this._ingest(d));
    cb(this._latest);
    return () => {
      this._listeners.delete(cb);
      if (this._listeners.size === 0 && this._off) { this._off(); this._off = null; }
    };
  }

  getState() { return this._latest; }

  /** Read the mapped node (x,y) corners from the shared Observatory settings. */
  _readNodePositions() {
    try {
      const raw = localStorage.getItem(OBS_SETTINGS_KEY);
      if (!raw) return {};
      const s = JSON.parse(raw);
      return (s && typeof s.nodePositions === 'object' && s.nodePositions) || {};
    } catch { return {}; }
  }

  _emptyVerdict(reason) { return emptyVerdict(reason); }

  _ingest(frame) {
    const feats = frame && Array.isArray(frame.node_features) ? frame.node_features : [];
    const W = this.opts.windowSize;
    for (const nf of feats) {
      if (nf == null || nf.node_id == null || nf.rssi_dbm == null) continue;
      const id = String(nf.node_id);
      (this._windows[id] || (this._windows[id] = [])).push(Number(nf.rssi_dbm));
      if (this._windows[id].length > W) this._windows[id].shift();
    }
    this._latest = this._evaluate();
    for (const cb of this._listeners) { try { cb(this._latest); } catch (e) { /* ignore */ } }
  }

  _evaluate() {
    return evaluateGeofence(this._readNodePositions(), this._windows, this.opts);
  }
}

export const geofenceService = new GeofenceService();
