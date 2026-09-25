"""
Per-zone state: LRU-capped, ring-buffered, EMA baselines.

MEMORY DISCIPLINE (Pi Zero 2W floor, 512 MB): every per-zone
structure is FIXED SIZE. __slots__ everywhere, deques with maxlen,
floats rather than history lists. Nothing here grows with traffic
volume -- only with the number of distinct zones, which is capped.

THE GRAB-AND-GO PROBLEM, stated plainly because it shapes this file:

Ragnar's deployment model is arrive-at-a-site-and-plug-in, with no
per-site tuning. That is the documented reason snmpwatch was rejected
-- not its false-positive rate as such, but that reducing the rate
required weeks of per-customer baseline learning, which the model
cannot supply.

Three detectors in this tier (DNSD-020 DNSBomb, DNSD-021 NSEC3
encloser, DNSD-022 water torture) are baseline-dependent in exactly
that way. They are implemented, but they are:

  1. OFF by default (Config.enable_baseline_detectors = False), and
  2. even when enabled, structurally incapable of emitting until
     their zone's baseline is WARM -- which requires both a minimum
     observation count and a minimum wall-clock duration.

So a grab-and-go deployment gets the eleven structural, posture and
integrity findings immediately and silently skips the three that
would otherwise fire on an unlearned baseline. A permanently-sited
sensor (the stealth Pi, an MSP desktop node) can turn them on and
will start getting them once warm. The operator is never shown a
behavioural finding derived from a baseline that does not exist yet.
"""
import time
from collections import deque, OrderedDict


class Config:
    __slots__ = ("max_zones", "enable_baseline_detectors", "baseline_alpha",
                 "baseline_sample_every", "baseline_min_observations", "baseline_min_seconds",
                 "baseline_deviation_factor", "excluded_zones",
                 "nxns_window_seconds", "nxns_min_referrals",
                 "nxns_min_ns", "keytrap_dnskey_collisions", "keytrap_rrsig_per_rrset",
                 "keytrap_crypto_product", "nsec3_max_iterations",
                 "nsec3_encloser_min_rrs", "short_ttl_seconds",
                 "port_entropy_min_samples", "port_entropy_min_distinct_ratio",
                 "ring_size", "inflight_max", "inflight_ttl_seconds",
                 "svcb_max_servicemode", "duplicate_rr_threshold",
                 "xfr_max_streams", "xfr_ttl_seconds")

    def __init__(self, **kw):
        # LRU cap. MEASURED per-zone cost after lazy ring allocation:
        # ~1.1 kB for the common query-only zone, ~5.1 kB for a zone
        # that exercises all six rings. The preflight budgeted 592 B
        # and 10k zones (5.8 MB); the real envelope at 10k would have
        # been 10.9 MB typical and 48 MB in a worst case an attacker
        # can drive by touching every behaviour across 10k zones.
        # 4096 keeps it at ~4.7 MB typical / ~20 MB adversarial.
        #
        # Lowering this is cheap here, unlike ndpwatch where eviction
        # was itself a detection bypass: every structural, posture and
        # integrity finding in this tier is stateless per-packet, so
        # eviction can only delay a BEHAVIOURAL baseline arming -- and
        # those are off by default anyway. Raise it on a sited sensor
        # with RAM to spare.
        self.max_zones = 4096
        self.ring_size = 64

        # --- grab-and-go gate -------------------------------------
        self.enable_baseline_detectors = False
        self.baseline_alpha = 0.1
        # Fold the EMA once per this many observations, per the
        # preflight. See Baseline for why per-packet folding is a bug.
        self.baseline_sample_every = 100
        self.baseline_min_observations = 500
        self.baseline_min_seconds = 3600.0
        self.baseline_deviation_factor = 5.0
        self.excluded_zones = set()

        # --- structural thresholds (no learning needed) -----------
        self.nxns_window_seconds = 0.100
        self.nxns_min_referrals = 4
        # Ordinary delegations carry 2-6 NS records, and delegating to
        # a third-party provider legitimately produces out-of-bailiwick
        # targets with no glue. The COUNT is the discriminator, not the
        # shape -- see detect_nxnsattack.
        self.nxns_min_ns = 8
        # Technitium's mitigation threshold; legitimate zone rotations
        # publish 2-4 DNSKEYs, and a key-tag COLLISION among them is
        # rare by construction (tags are ~uniform over 16 bits).
        self.keytrap_dnskey_collisions = 2
        self.keytrap_rrsig_per_rrset = 8
        self.keytrap_crypto_product = 64
        self.nsec3_max_iterations = 0          # RFC 9276
        self.nsec3_encloser_min_rrs = 6
        self.short_ttl_seconds = 60

        self.port_entropy_min_samples = 32
        self.port_entropy_min_distinct_ratio = 0.5

        self.inflight_max = 4096
        self.inflight_ttl_seconds = 10.0

        # --- new-code thresholds (all stateless structural checks) --
        self.svcb_max_servicemode = 14      # per CVE-2026-81563
        self.duplicate_rr_threshold = 8
        self.xfr_max_streams = 512
        self.xfr_ttl_seconds = 300.0

        for k, v in kw.items():
            if not hasattr(self, k):
                raise KeyError(f"unknown config key: {k}")
            setattr(self, k, v)


class Baseline:
    """
    Exponential moving average. Constant time, one float of state, plus
    the counters that decide whether it may be trusted yet.

    THE EMA IS FOLDED ON A CADENCE, NOT PER PACKET. This is not a
    performance choice, it is a correctness one. Updating on every
    observation lets the baseline CHASE a ramping attack: each
    intermediate sample is individually below the deviation threshold,
    so it is treated as normal and folded in, raising the threshold
    just as fast as the attack raises the signal. Measured during the
    conformance build -- a burst ramping 1..12/s against a baseline of
    1.0/s never fired, because by the time the rate hit 12 the
    threshold had been dragged from 5.0 to 29.1 by the attack's own
    traffic. With a cadence of 100 the baseline cannot move at all
    inside a burst of a few dozen packets.

    (The preflight specified this cadence; the first implementation
    dropped it, and folding per packet silently disabled all three
    behavioural detectors.)
    """
    __slots__ = ("value", "observations", "first_seen", "_since_fold")

    def __init__(self):
        self.value = 0.0
        self.observations = 0
        self.first_seen = None
        self._since_fold = 0

    def update(self, sample, now=None, cfg=None):
        now = now if now is not None else time.monotonic()
        alpha = cfg.baseline_alpha if cfg is not None else 0.1
        cadence = cfg.baseline_sample_every if cfg is not None else 1
        self.observations += 1
        if self.first_seen is None:
            self.first_seen = now
            self.value = float(sample)
            self._since_fold = 0
            return
        self._since_fold += 1
        if self._since_fold >= cadence:
            self.value = (1.0 - alpha) * self.value + alpha * float(sample)
            self._since_fold = 0

    def is_warm(self, cfg, now=None):
        if self.first_seen is None:
            return False
        now = now if now is not None else time.monotonic()
        return (self.observations >= cfg.baseline_min_observations
                and (now - self.first_seen) >= cfg.baseline_min_seconds)

    def exceeds(self, sample, cfg):
        """Deviation test. A zero baseline can't be multiplied into a
        threshold, so it never trips -- silence beats dividing by zero
        and alerting on the first packet."""
        if self.value <= 0.0:
            return False
        return float(sample) > self.value * cfg.baseline_deviation_factor


# Ring names, allocated lazily -- see ZoneState.
_RINGS = ("referral_times", "short_ttl_times", "nxdomain_times",
          "query_times", "src_ports", "subdomain_hashes")


class ZoneState:
    """
    MEASURED, not estimated: a CPython deque costs a flat ~768 bytes
    the moment it exists, regardless of maxlen, because a whole block
    is preallocated. Six eagerly-created rings therefore cost ~4.6 kB
    per zone before a single event is recorded -- and at the 10k-zone
    cap that is 48 MB, not the 5.8 MB the preflight budgeted.

    The fix is that rings and baselines are allocated ON FIRST USE.
    The overwhelmingly common zone is one seen only in ordinary
    queries, which touches exactly one ring; the referral, NSEC3,
    short-TTL and port-entropy rings stay unallocated for it forever.
    Cost scales with what a zone actually DOES rather than with what
    it might hypothetically do.
    """
    __slots__ = ("zone", "last_access", "nsec3_iterations_seen",
                 "bl_query_rate", "bl_nxdomain_ratio", "bl_short_ttl_ratio") + _RINGS

    def __init__(self, zone, ring_size):
        self.zone = zone
        self.last_access = time.monotonic()
        self.nsec3_iterations_seen = 0
        for r in _RINGS:
            setattr(self, r, None)
        self.bl_query_rate = None
        self.bl_nxdomain_ratio = None
        self.bl_short_ttl_ratio = None

    def ring(self, name, ring_size, create=True):
        """Fetch a ring, allocating it only if something is about to be
        written. Readers pass create=False and get an empty tuple, so a
        detector reading a ring that never existed costs nothing."""
        r = getattr(self, name)
        if r is None:
            if not create:
                return ()
            r = deque(maxlen=ring_size)
            setattr(self, name, r)
        return r

    def push(self, name, value, ring_size):
        self.ring(name, ring_size).append(value)

    def baseline(self, name, create=True):
        b = getattr(self, name)
        if b is None:
            if not create:
                return None
            b = Baseline()
            setattr(self, name, b)
        return b

    def touch(self, now=None):
        self.last_access = now if now is not None else time.monotonic()

    def rate_in_window(self, ring, window):
        """Events in `ring` within `window` seconds of the newest entry.
        Reads from the newest backwards and stops early. Accepts the
        empty tuple a never-allocated ring returns."""
        if not ring:
            return 0
        newest = ring[-1]
        n = 0
        for t in reversed(ring):
            if newest - t > window:
                break
            n += 1
        return n


class ZoneTable:
    """
    LRU over zones. Eviction here is pure memory hygiene, NOT detection
    logic -- unlike ndpwatch's neighbour table, where evicting the
    gateway record was attacker-triggerable and had to become an SLRU
    with pinning. The distinction: ndpwatch's table holds a SECURITY
    BINDING whose absence changes a verdict, while these are counters
    whose absence only resets a behavioural baseline that was already
    gated behind warmth. An attacker who evicts a zone here buys
    themselves a LONGER wait before behavioural detection arms, not a
    bypass of a structural check -- every structural, posture and
    integrity finding in this tier is stateless per-packet and cannot
    be evicted at all.
    """
    __slots__ = ("cfg", "zones", "evictions")

    def __init__(self, cfg):
        self.cfg = cfg
        self.zones = OrderedDict()
        self.evictions = 0

    def get(self, zone, now=None):
        st = self.zones.get(zone)
        if st is None:
            if len(self.zones) >= self.cfg.max_zones:
                self.zones.popitem(last=False)
                self.evictions += 1
            st = ZoneState(zone, self.cfg.ring_size)
            self.zones[zone] = st
        else:
            self.zones.move_to_end(zone)
        st.touch(now)
        return st

    def __len__(self):
        return len(self.zones)


class InFlight:
    """
    Outstanding queries, keyed by (txid, qname, qtype, client port).
    Used only by SAD DNS duplicate detection (DNSD-030). Capped and
    TTL-swept so a query flood cannot grow it without bound.
    """
    __slots__ = ("cfg", "entries")

    def __init__(self, cfg):
        self.cfg = cfg
        self.entries = OrderedDict()

    def note_query(self, key, now):
        if len(self.entries) >= self.cfg.inflight_max:
            self.entries.popitem(last=False)
        self.entries[key] = {"t": now, "answers": []}

    def note_response(self, key, answer_sig, now):
        """Returns the previously-seen conflicting signature, or None."""
        e = self.entries.get(key)
        if e is None:
            return None
        if now - e["t"] > self.cfg.inflight_ttl_seconds:
            del self.entries[key]
            return None
        for prev in e["answers"]:
            if prev != answer_sig:
                return prev
        e["answers"].append(answer_sig)
        return None

    def sweep(self, now):
        dead = [k for k, e in self.entries.items()
                if now - e["t"] > self.cfg.inflight_ttl_seconds]
        for k in dead:
            del self.entries[k]
        return len(dead)


class XferStream:
    """
    One TCP zone-transfer conversation, keyed by 4-tuple.

    Fixed size: five scalars, no buffers. This is the ONLY per-stream
    state in the module and it exists solely for DNSD-060.
    """
    __slots__ = ("started", "last_seen", "messages", "signed_messages",
                 "last_signed", "soa_count", "qtype", "reported")

    def __init__(self, now, qtype):
        self.started = now
        self.last_seen = now
        self.messages = 0
        self.signed_messages = 0
        self.last_signed = False
        self.soa_count = 0
        self.qtype = qtype
        self.reported = False


class XferTable:
    """
    Bounded table of in-progress transfers, LRU-capped and TTL-swept.

    SCOPE LIMIT, stated because it decides where this is worth
    deploying: this only sees transfers that cross the tap. On an ISP's
    own DNS infrastructure that is the primary-to-secondary path and is
    exactly in scope; carrier-internal transfers inside a customer cage
    are not visible and never will be.
    """
    __slots__ = ("cfg", "streams")

    def __init__(self, cfg):
        self.cfg = cfg
        self.streams = OrderedDict()

    def get(self, key, now, qtype=None):
        st = self.streams.get(key)
        if st is None:
            if len(self.streams) >= self.cfg.xfr_max_streams:
                self.streams.popitem(last=False)
            st = XferStream(now, qtype)
            self.streams[key] = st
        else:
            self.streams.move_to_end(key)
        st.last_seen = now
        return st

    def sweep(self, now):
        dead = [k for k, s in self.streams.items()
                if now - s.last_seen > self.cfg.xfr_ttl_seconds]
        for k in dead:
            del self.streams[k]
        return len(dead)
