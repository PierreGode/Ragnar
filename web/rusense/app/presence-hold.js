// Presence hold — the aggregate `classification.presence` boolean toggles
// 0 ↔ 1 at the full frame rate (~46 Hz) and does so even in an EMPTY room
// (~20% of frames read "present") and even at high confidence. So neither a
// confidence gate nor a "latch on any hit" hold works: the former can't tell
// empty from occupied-still apart, the latter would stick PRESENT forever on
// empty-room noise.
//
// Instead we measure the DUTY CYCLE of an "occupied" signal over a sliding
// window and apply hysteresis with a wide dead-band, biased toward PRESENT:
//   - turn ON only when occupancy clearly dominates (well above the empty-room
//     noise floor),
//   - once ON, stay ON until the signal collapses to the floor for `lingerMs`,
//     so a motionless body — whose duty sags into the dead-band — keeps
//     reading present instead of flickering to empty.
//
// Feed EVERY raw frame (not the throttled render frames) so the duty estimate
// reflects the real ~46 Hz signal. Defaults assume an empty-room floor around
// 20% duty; onFrac/offFrac are tunable per environment.
export function makePresenceHold({
  windowMs = 2000,   // sliding window for the duty-cycle estimate
  onFrac = 0.18,     // duty ≥ this flips to PRESENT. Live data: empty ~2% (≤20% noisy),
                     // a STILL/sitting person ~27-35% — 0.18 clears empty with margin, catches sitting.
  offFrac = 0.08,    // duty ≤ this (for lingerMs) flips back to EMPTY
  lingerMs = 4000,   // once present, require the floor to hold this long before clearing
  minSamples = 10,   // don't let a lone startup spike (duty 1.0 of 1 sample) latch ON
} = {}) {
  const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
  let samples = [];        // { t, occ }
  let state = false;
  let lastOccAt = -Infinity;

  return {
    /** Feed one frame's `classification` object; returns the smoothed boolean. */
    push(cls) {
      const t = now();
      const ml = String((cls && cls.motion_level) || '');
      // "Occupied" = aggregate presence OR a present_*/active motion level
      // (the per-frame motion level spikes together with presence).
      const occ = !!(cls && cls.presence) || ml.startsWith('present') || ml === 'active';
      samples.push({ t, occ });
      const cutoff = t - windowMs;
      while (samples.length && samples[0].t < cutoff) samples.shift();
      let hits = 0;
      for (const s of samples) if (s.occ) hits++;
      const duty = samples.length ? hits / samples.length : 0;
      if (!state) {
        if (samples.length >= minSamples && duty >= onFrac) { state = true; lastOccAt = t; }
      } else if (duty >= offFrac) {
        lastOccAt = t;                       // still occupied-ish — refresh linger
      } else if (t - lastOccAt >= lingerMs) {
        state = false;                       // floor held long enough — declare empty
      }
      return state;
    },
    get present() { return state; },
    reset() { samples = []; state = false; lastOccAt = -Infinity; },
  };
}
