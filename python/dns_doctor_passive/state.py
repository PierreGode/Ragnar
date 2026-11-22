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
                 "xfr_max_streams", "xfr_ttl_seconds",
                 "mdns_enabled", "mdns_local_prefixes", "mdns_census_max",
                 "mdns_fingerprint", "mdns_include_device_name",
                 "ddns_enabled", "ddns_allowed_updater_prefixes",
                 "ddns_max_pending", "ddns_pending_ttl_seconds",
                 "rdns_enabled", "rdns_internal_prefixes",
                 "ip6_walk_enabled", "ip6_walk_window_seconds",
                 "ip6_walk_min_queries", "ip6_walk_min_distinct_ratio",
                 "ip6_walk_min_common_nibbles", "walk_max_sources",
                 "sigred_report_near_miss", "xfr_allowed_secondary_prefixes",
                 "llmnr_enabled", "nbns_enabled", "encrypted_dns_enabled",
                 "dns_own_resolver_prefixes", "dnssd_enabled",
                 "dnssd_max_instances", "nbstat_window_seconds",
                 "nbstat_min_queries", "tsig_max_fudge", "posture_seen_max",
                 "spf_enabled", "spf_exp_literal_min", "spf_max_exp_targets",
                 "tcp_reasm_enabled", "tcp_reasm_max_bytes",
                 "tcp_reasm_stream_max_bytes", "tcp_reasm_max_streams",
                 "tcp_reasm_timeout", "tcp_reasm_shadow_bytes")

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

        # --- mDNS tier ---------------------------------------------
        self.mdns_enabled = True
        # Operator-supplied CIDRs for THIS link. The two off-link
        # scope detectors stay silent without them -- see mdns.py for
        # why the obvious "public address means off-link" shortcut is
        # wrong on a carrier-neutral colo or ISP LAN.
        self.mdns_local_prefixes = ()
        self.mdns_census_max = 2048
        # Decode Matter/Thread TXT records into a device fingerprint
        # rather than reporting bare service types.
        self.mdns_fingerprint = True
        # The DNS-SD 'DN' key is the USER-CHOSEN device name ("Dave's
        # Bedroom Lamp"). Included by default because it is the field
        # that makes a census line actionable for smart-home
        # troubleshooting -- a vendor ID identifies a model, only DN
        # identifies the thing on the shelf.
        #
        # It is also tenant-chosen free text, so it lands in the
        # findings feed verbatim. The switch exists for a deployment
        # that must not retain it; the default is on.
        self.mdns_include_device_name = True

        # --- DDNS tier (RFC 2136 opcode 5) -------------------------
        self.ddns_enabled = True
        # Operator-supplied CIDRs of hosts PERMITTED to send dynamic
        # updates. DNSD-082 stays silent without them.
        #
        # WHY CONFIG AND NOT A LEARNED ALLOWLIST: a learned allowlist
        # would arm itself from whatever it happened to see first,
        # which means the finding's meaning depends on when the sensor
        # was plugged in. On a grab-and-go deployment that is not a
        # detector, it is a coin flip -- and a newly-promoted DC or a
        # second DHCP server would read as an attack. An operator who
        # cannot name their updaters does not want this check on.
        self.ddns_allowed_updater_prefixes = ()
        # Pending UPDATE requests awaiting their response. Small and
        # short-lived: an UPDATE is answered in milliseconds.
        self.ddns_max_pending = 1024
        self.ddns_pending_ttl_seconds = 10.0

        # --- rDNS tier (PTR) ---------------------------------------
        self.rdns_enabled = True
        # CIDRs of THIS organisation's resolvers and networks. A
        # private-zone PTR query addressed inside them is ordinary
        # internal business; one addressed outside them is the leak.
        # Silent without config, for the same reason as mDNS off-link.
        self.rdns_internal_prefixes = ()

        self.ip6_walk_enabled = True
        self.ip6_walk_window_seconds = 60.0
        # Fixed thresholds, NOT a learned baseline. A single source
        # asking for scores of distinct ip6.arpa names inside a minute
        # is anomalous on every network, so there is nothing a baseline
        # would add except a warmup window this deployment cannot
        # assume. That is why DNSD-091 ships ON by default while the
        # three rate-baseline detectors ship off.
        self.ip6_walk_min_queries = 64
        self.ip6_walk_min_distinct_ratio = 0.9
        # The discriminator that separates a WALK from ordinary bulk
        # reverse lookups: a walk probes DOWN one delegation, so its
        # queries share a long leading nibble run. A mail server doing
        # rDNS on many v6 senders touches unrelated /32s and shares
        # almost nothing. 8 nibbles = a /32 in common.
        self.ip6_walk_min_common_nibbles = 8
        self.walk_max_sources = 1024

        # SIGRed reports only the arithmetic that actually wraps.
        # See detect_sigred for why a near miss is deliberately silent.
        self.sigred_report_near_miss = False

        # --- LLMNR / NBNS posture tiers ---------------------------
        # Both ship ON, unlike the behavioural detectors, because
        # neither needs a baseline: the finding is that a deprecated,
        # unauthenticated name-resolution protocol is in use at all,
        # which is a fact about one packet.
        self.llmnr_enabled = True
        self.nbns_enabled = True
        self.nbstat_window_seconds = 60.0
        self.nbstat_min_queries = 8

        # --- encrypted-DNS transport tier -------------------------
        self.encrypted_dns_enabled = True
        # CIDRs of resolvers this operator runs. DoT/DoQ TO them is
        # good practice; DoT/DoQ PAST them is a bypass of the logging,
        # RPZ and filtering they provide. Without the config the
        # census still reports the session and says the verdict is
        # undecidable, rather than guessing which it was.
        self.dns_own_resolver_prefixes = ()

        # --- DNS-SD over unicast ----------------------------------
        self.dnssd_enabled = True
        # Instances behind one DNS-SD PTR response before it counts as
        # a fan-out. A real service type on a real zone publishes a
        # handful; an enumeration answer publishes everything.
        self.dnssd_max_instances = 32

        # --- TSIG posture -----------------------------------------
        # RFC 8945 s5.2.1 recommends 300s. The fudge IS the replay
        # window, so this is reported rather than assumed benign.
        self.tsig_max_fudge = 300

        # Shared first-sighting cap for every posture code that
        # reports a STATE rather than an event.
        self.posture_seen_max = 4096

        # --- SPF parser tier (libspf2) ----------------------------
        # ---- TCP stream reassembly (tcpreasm.py) ----
        # The only genuinely memory-hungry part of the module: a
        # single SIGRed message is ~64 kB and needs a buffer that
        # size. Every number here is a ceiling, and every byte
        # refused is counted.
        self.tcp_reasm_enabled = True
        # 4 MB across all streams, which keeps the module near its
        # stated ~10 MB envelope on the Pi Zero 2W floor. Eviction is
        # least-recently-used and counted.
        self.tcp_reasm_max_bytes = 4 * 1024 * 1024
        # Per stream: a 64 kB message plus its prefix plus room for
        # out-of-order segments around it.
        self.tcp_reasm_stream_max_bytes = 128 * 1024
        self.tcp_reasm_max_streams = 256
        # A stream whose gap never closes is reclaimed after this.
        self.tcp_reasm_timeout = 30.0
        # Trailing bytes kept after framing, so a late contradicting
        # retransmission can still be compared for DNSD-160. This is
        # the documented bound on that detection.
        self.tcp_reasm_shadow_bytes = 2048

        self.spf_enabled = True
        # Concatenated explanation-literal length at which a TXT record
        # named by exp= is reported (DNSD-152). libspf2's compile
        # budget is 511 and the overflow needs a literal that fills
        # it; 480 leaves room for the surrounding term while staying
        # far above anything a real explanation string contains --
        # RFC 7208 s6.2 explanations are short human-readable text.
        self.spf_exp_literal_min = 508
        # Bounded set of exp= targets remembered from SPF records, so
        # the explanation TXT can be recognised when it arrives.
        self.spf_max_exp_targets = 1024

        # --- zone transfer ----------------------------------------
        # CIDRs of secondaries permitted to pull your zones. DNSD-061
        # reports a COMPLETED transfer to anything outside them and is
        # silent without the config, for the same reason as every
        # other prefix-gated code here: on an ISP tap the config-free
        # version would fire on every legitimate transfer between your
        # own nameservers.
        self.xfr_allowed_secondary_prefixes = ()

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

    Fixed size: scalars and one small set of reported codes, no
    record buffers. `reported` stays a plain bool for DNSD-060 and the
    later codes each get their own flag, rather than one shared
    "already reported" that would let whichever fired first silence
    the others.

    `client` is stored rather than re-derived from the table key.
    The key is (server, client, server_port, client_port) and the
    client is therefore key[1] -- but a detector that unpacked the key
    itself would break silently the first time the key shape changed,
    and the key shape has already changed once in this module.
    """
    __slots__ = ("started", "last_seen", "messages", "signed_messages",
                 "last_signed", "soa_count", "qtype", "reported",
                 "client", "records", "first_message_done",
                 "reported_leak", "reported_struct", "reported_apex", "apex")

    def __init__(self, now, qtype, client=None):
        self.started = now
        self.last_seen = now
        self.messages = 0
        self.signed_messages = 0
        self.last_signed = False
        self.soa_count = 0
        self.qtype = qtype
        self.reported = False
        self.client = client
        self.records = 0
        self.first_message_done = False
        self.reported_leak = False
        self.reported_struct = False
        self.reported_apex = False
        # The transferred zone's apex, remembered from whichever
        # message carried the Question section. RFC 5936 s2.2 requires
        # only the FIRST message to copy it, so without this the apex
        # checks could not run on later messages -- and CVE-2021-25214's
        # malformed SOA has no reason to arrive in message one.
        self.apex = None


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

    def get(self, key, now, qtype=None, client=None):
        st = self.streams.get(key)
        if st is None:
            if len(self.streams) >= self.cfg.xfr_max_streams:
                self.streams.popitem(last=False)
            st = XferStream(now, qtype, client=client)
            self.streams[key] = st
        elif st.client is None and client is not None:
            st.client = client
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


class CensusTable:
    """
    Bounded first-sighting set for the mDNS census.

    mDNS hosts re-announce continuously, so the census MUST emit once
    per (service, instance) rather than per packet -- otherwise the
    informational leg would bury the scope leg it shares a tier with.

    Eviction here is pure hygiene and carries no detection meaning: an
    evicted key simply gets reported again on its next announcement,
    which is noisier but never silent. That is the opposite of
    ndpwatch's neighbour table, where eviction was a detection bypass,
    and the asymmetry is why a plain LRU is correct here.
    """
    __slots__ = ("cap", "seen", "evictions")

    def __init__(self, cap=2048):
        self.cap = cap
        self.seen = OrderedDict()
        self.evictions = 0

    def first_sighting(self, key, now):
        if key in self.seen:
            self.seen.move_to_end(key)
            self.seen[key] = now
            return False
        if len(self.seen) >= self.cap:
            self.seen.popitem(last=False)
            self.evictions += 1
        self.seen[key] = now
        return True

    def __len__(self):
        return len(self.seen)


class UpdatePending:
    """
    Dynamic-update requests awaiting their response, keyed by
    (txid, client, server, client port).

    WHY THIS TABLE EXISTS AT ALL: both DDNS posture findings are about
    an OUTCOME, not a packet. "An unsigned UPDATE was sent" is an
    attempt and worth nothing -- every scanner does it. "An unsigned
    UPDATE was sent and the server answered NOERROR" is a vulnerable
    zone, and that sentence needs two packets. So the request side is
    remembered only long enough to read the verdict off the response.

    Bounded and TTL-swept like InFlight. Eviction carries no detection
    meaning beyond losing one correlation: an UPDATE is answered in
    milliseconds, so an entry that survives to eviction was never
    going to be answered.
    """
    __slots__ = ("cfg", "entries", "evictions")

    def __init__(self, cfg):
        self.cfg = cfg
        self.entries = OrderedDict()
        self.evictions = 0

    def note_request(self, key, info, now):
        if key in self.entries:
            self.entries.move_to_end(key)
        elif len(self.entries) >= self.cfg.ddns_max_pending:
            self.entries.popitem(last=False)
            self.evictions += 1
        info = dict(info)
        info["t"] = now
        self.entries[key] = info

    def take_response(self, key, now):
        """Consume and return the matching request, or None. Consuming
        rather than peeking is deliberate: one request yields at most
        one verdict, so a retransmitted response cannot double-report."""
        e = self.entries.get(key)
        if e is None:
            return None
        del self.entries[key]
        if now - e["t"] > self.cfg.ddns_pending_ttl_seconds:
            return None
        return e

    def sweep(self, now):
        dead = [k for k, e in self.entries.items()
                if now - e["t"] > self.cfg.ddns_pending_ttl_seconds]
        for k in dead:
            del self.entries[k]
        return len(dead)

    def __len__(self):
        return len(self.entries)


class WalkState:
    """
    One source's reverse-tree enumeration window.

    Constant-size state per source: a count, a window start, a bounded
    distinct-name set, and the running COMMON NIBBLE PREFIX, which is
    the piece that does the real work. It is intersected on every query
    and can only shrink, so after a handful of scattered lookups it
    collapses to nothing and the source can never trip the threshold.
    That is what keeps a busy mail server -- which legitimately asks
    for many distinct ip6.arpa names across unrelated networks -- from
    looking like a walk, without any learning.
    """
    __slots__ = ("window_start", "count", "common", "distinct", "cap", "reported")

    def __init__(self, now, cap):
        self.window_start = now
        self.count = 0
        self.common = None
        self.distinct = set()
        self.cap = cap
        self.reported = False

    def reset(self, now):
        self.window_start = now
        self.count = 0
        self.common = None
        self.distinct = set()
        self.reported = False

    def observe(self, nibbles, now, window):
        if now - self.window_start > window:
            self.reset(now)
        self.count += 1
        if len(self.distinct) < self.cap:
            self.distinct.add(hash(nibbles) & 0xFFFFFFFF)
        if self.common is None:
            self.common = nibbles
        else:
            n = 0
            for a, b in zip(self.common, nibbles):
                if a != b:
                    break
                n += 1
            self.common = self.common[:n]

    def distinct_ratio(self):
        if self.count == 0:
            return 0.0
        return min(len(self.distinct), self.count) / float(self.count)


class WalkTable:
    """Bounded LRU of per-source WalkState. Eviction only delays a
    report; the next window rebuilds from scratch."""
    __slots__ = ("cfg", "entries", "evictions")

    def __init__(self, cfg):
        self.cfg = cfg
        self.entries = OrderedDict()
        self.evictions = 0

    def get(self, src, now):
        st = self.entries.get(src)
        if st is not None:
            self.entries.move_to_end(src)
            return st
        if len(self.entries) >= self.cfg.walk_max_sources:
            self.entries.popitem(last=False)
            self.evictions += 1
        cap = max(self.cfg.ip6_walk_min_queries * 2, 256)
        st = WalkState(now, cap)
        self.entries[src] = st
        return st

    def __len__(self):
        return len(self.entries)


class CounterTable:
    """
    Per-source event counts inside a sliding window.

    Deliberately simpler than WalkTable: NBSTAT enumeration needs only
    "how many from this source lately", with none of the distinctness
    or common-prefix machinery the ip6.arpa walk depends on. Reusing
    WalkState here by passing a query name as its nibble tuple would
    have worked and would have left two unrelated detectors sharing a
    structure whose fields mean different things in each -- which is
    how a later change to one silently breaks the other.
    """
    __slots__ = ("cap", "window", "entries", "evictions")

    def __init__(self, cap=1024, window=60.0):
        self.cap = cap
        self.window = window
        self.entries = OrderedDict()
        self.evictions = 0

    def bump(self, key, now):
        """Count one event and return the count inside the window."""
        e = self.entries.get(key)
        if e is None:
            if len(self.entries) >= self.cap:
                self.entries.popitem(last=False)
                self.evictions += 1
            e = [now, 0, False]       # window_start, count, reported
            self.entries[key] = e
        else:
            self.entries.move_to_end(key)
            if now - e[0] > self.window:
                e[0], e[1], e[2] = now, 0, False
        e[1] += 1
        return e[1]

    def reported(self, key):
        e = self.entries.get(key)
        return bool(e and e[2])

    def mark_reported(self, key):
        e = self.entries.get(key)
        if e:
            e[2] = True

    def __len__(self):
        return len(self.entries)


class ExpTargetTable:
    """
    Domains named by an SPF `exp=` modifier, remembered so that the
    EXPLANATION record can be recognised when it arrives.

    CVE-2021-20314's artifact is not the SPF record -- it is the
    separate TXT record that `exp=` points at, fetched later and
    compiled through the same macro path. A detector that looked only
    at the SPF record would see a perfectly ordinary `exp=` modifier
    and nothing else, so the two halves have to be joined, and the
    only thing linking them is a domain name.

    Bounded and LRU-evicted. Eviction costs one correlation: an
    explanation record whose SPF record has aged out is not reported,
    which is silence rather than a false alarm.
    """
    __slots__ = ("cap", "targets", "evictions")

    def __init__(self, cap=1024):
        self.cap = cap
        self.targets = OrderedDict()
        self.evictions = 0

    def note(self, name, zone, now):
        key = name.lower().rstrip(".")
        if key in self.targets:
            self.targets.move_to_end(key)
        elif len(self.targets) >= self.cap:
            self.targets.popitem(last=False)
            self.evictions += 1
        self.targets[key] = (zone, now)

    def lookup(self, name):
        got = self.targets.get(name.lower().rstrip("."))
        return got[0] if got else None

    def __len__(self):
        return len(self.targets)
