/**
 * Fingerprint positioning for the Observatory blob.
 *
 * Instead of assuming a signal→distance formula (unreliable indoors — multipath,
 * unknown path-loss), we LEARN the room: the operator stands at a few known spots
 * and we record the per-node motion *distribution* (a "fingerprint") there. Live,
 * we match the current distribution to the nearest fingerprints (k-NN) and
 * interpolate their positions. This captures room-specific quirks the weighted
 * centroid can't — e.g. "node 2 reads hottest" mapping to *center*, not node 2.
 *
 * Signature = per-node motion normalized to sum 1 (the spatial *pattern*, scale-
 * free), in fixed node_id order 1,2,3. Persisted in localStorage (per browser/room).
 */
const STORE_KEY = 'ragnar_observatory_fingerprints_v1';

export class Fingerprinter {
  constructor() {
    this.fps = [];             // [{ pos:[x,y,z], sig:[s1,s2,s3] }]
    this._live = [0, 0, 0];    // smoothed live signature
    this._liveInit = false;
    this._rec = null;          // { pos, acc:[3], n }
    this.load();
  }

  get count() { return this.fps.length; }
  get recording() { return !!this._rec; }

  /** Normalized per-node motion distribution [n1,n2,n3] (sum 1), or null if quiet. */
  _sig(nodeFeatures) {
    const m = { 1: 0, 2: 0, 3: 0 };
    let sum = 0;
    for (const f of nodeFeatures || []) {
      if (f.stale) continue;
      const v = Math.max(0, (f.features && f.features.motion_band_power) || 0);
      if (f.node_id in m) { m[f.node_id] = v; sum += v; }
    }
    if (sum <= 1e-6) return null;
    return [m[1] / sum, m[2] / sum, m[3] / sum];
  }

  /** Feed one live frame: update the smoothed live signature + any active recording. */
  feed(nodeFeatures) {
    const s = this._sig(nodeFeatures);
    if (!s) return;
    const a = this._liveInit ? 0.12 : 1.0;   // smooth the live signature
    for (let i = 0; i < 3; i++) this._live[i] += a * (s[i] - this._live[i]);
    this._liveInit = true;
    if (this._rec) {
      for (let i = 0; i < 3; i++) this._rec.acc[i] += s[i];
      this._rec.n++;
    }
  }

  startRecording(pos) { this._rec = { pos, acc: [0, 0, 0], n: 0 }; }

  /** Finish recording: average the samples into a fingerprint at its position. */
  finishRecording() {
    const r = this._rec;
    this._rec = null;
    if (!r || r.n < 5) return null;                 // too few samples
    const sig = r.acc.map((v) => v / r.n);
    const idx = this.fps.findIndex(
      (fp) => fp.pos[0] === r.pos[0] && fp.pos[2] === r.pos[2],
    );
    const fp = { pos: r.pos, sig };
    if (idx >= 0) this.fps[idx] = fp; else this.fps.push(fp);
    this.save();
    return { samples: r.n, sig };
  }

  /** k-NN locate → interpolated [x,y,z], or null if not enough fingerprints. */
  locate() {
    if (this.fps.length < 2 || !this._liveInit) return null;
    const ranked = this.fps
      .map((fp) => {
        let d = 0;
        for (let i = 0; i < 3; i++) { const e = this._live[i] - fp.sig[i]; d += e * e; }
        return { fp, d: Math.sqrt(d) };
      })
      .sort((a, b) => a.d - b.d);
    const k = Math.min(3, ranked.length);
    let wsum = 0, x = 0, z = 0;
    for (let i = 0; i < k; i++) {
      const w = 1 / (ranked[i].d + 0.02);           // inverse-distance weight
      wsum += w;
      x += ranked[i].fp.pos[0] * w;
      z += ranked[i].fp.pos[2] * w;
    }
    if (wsum <= 0) return null;
    return [x / wsum, 0, z / wsum];
  }

  clear() { this.fps = []; this.save(); }

  save() { try { localStorage.setItem(STORE_KEY, JSON.stringify(this.fps)); } catch (_) {} }
  load() {
    try { this.fps = JSON.parse(localStorage.getItem(STORE_KEY) || '[]') || []; }
    catch (_) { this.fps = []; }
  }
}
