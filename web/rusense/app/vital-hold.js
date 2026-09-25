// Vital-sign hold — smooths the flicker where a WiFi-CSI vital briefly dips
// below the confidence gate (or a frame omits it) and then recovers. Holds the
// last CONFIDENT reading on screen through those sub-second gaps, and only
// falls back to "—" once no confident reading has arrived for `holdMs`.
//
// Why hold instead of raising the confidence threshold: the sensing-server
// recomputes HR/BR over a multi-second window and stamps that value onto every
// 10-20 Hz frame, so the *number* is steady — the flicker is the value ↔ "—"
// toggle as `heartbeat_confidence` grazes 0.5 (or presence blips false, or the
// bpm arrives null between recomputes). A time-based hold is temporal
// hysteresis: bridge the dip, but respect staleness.
//
// Callers must re-render on a timer as well as on frames — text() is
// wall-clock based, so a stalled stream still clears to "—" after holdMs
// instead of freezing the last value on screen forever.
import { fmt, VITAL_MIN_CONFIDENCE } from './lib.js?v=20260704-sparkfit';

export function makeVitalHold({ holdMs = 4000, decimals = 0 } = {}) {
  let value = null;        // last confident numeric reading
  let goodAt = -Infinity;  // performance.now() when it was captured
  const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

  return {
    /** Feed one reading. Confident readings are captured; everything else is
     *  ignored so the last good value keeps showing. */
    push(v, confidence, present = true) {
      if (present && v != null && Number(confidence) >= VITAL_MIN_CONFIDENCE) {
        value = Number(v);
        goodAt = now();
      }
    },
    /** Current display string — the held number while still fresh, else "—". */
    text() {
      if (value != null && (now() - goodAt) <= holdMs) return fmt.num(value, decimals);
      value = null;
      return '—';
    },
    /** Force-clear (e.g. on view teardown). */
    reset() { value = null; goodAt = -Infinity; },
  };
}
