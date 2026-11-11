"""
The detectors, grouped by class.

Every detector is a PURE function of (message, context) -> list of
findings. No I/O, no sockets, no clock reads except the `now` passed
in. That is what lets conformance.py drive all of them exhaustively
offline, and it is why the stateful ones take their state object as
an argument rather than reaching for a global.

Split by cost, because the Pi Zero 2W runs these at line rate:
  - STRUCTURAL / POSTURE / INTEGRITY-per-packet run on the critical
    path. All are O(records in the message).
  - BEHAVIOURAL update ring buffers and read EMAs. Also O(1) amortised,
    but gated behind baseline warmth (see state.py).
"""
from collections import Counter, defaultdict

import parse
import netscope
from bailiwick import (in_bailiwick, is_subdomain_of, normalize,
                       out_of_bailiwick_rrs)
from findings import finding, BASELINE_DEPENDENT


def _question(msg):
    return msg.questions[0] if msg.questions else None


def _qname_text(msg):
    q = _question(msg)
    return q["name"].text() if q else "."


# ======================================================================
# STRUCTURAL
# ======================================================================

def detect_keytrap(msg, cfg, zone):
    """
    CVE-2023-50387. Three independent signatures, three codes.

    The attack makes a validator do O(keys x signatures) crypto for one
    response. All three inputs are visible in the record counts, so
    this needs no state and no baseline -- which is why it survives
    the grab-and-go constraint that kills the behavioural detectors.
    """
    out = []
    dnskeys = [r for r in msg.all_rrs() if r.rtype == parse.T_DNSKEY]
    rrsigs = [r for r in msg.all_rrs() if r.rtype == parse.T_RRSIG]

    # DNSD-001: colliding key tags.
    # Key tags are a 16-bit checksum over the key, so among a handful
    # of legitimately-rotated keys a collision is genuinely rare.
    # Deliberately counts DISTINCT keys per tag, not records per tag:
    # the same key appearing twice is a duplicate record, not a
    # collision, and must not fire.
    if dnskeys:
        by_tag = defaultdict(set)
        for r in dnskeys:
            tag = r.parsed.get("key_tag")
            if tag is not None:
                by_tag[tag].add(bytes(r.rdata))
        for tag, keys in by_tag.items():
            if len(keys) >= cfg.keytrap_dnskey_collisions:
                out.append(finding(
                    "DNSD-001", zone,
                    f"{len(keys)} distinct DNSKEYs share key tag {tag} -- a validator "
                    f"must try every one of them against each signature",
                    {"key_tag": tag, "colliding_keys": len(keys),
                     "dnskey_count": len(dnskeys), "qname": _qname_text(msg)},
                ))

    # DNSD-002: many RRSIGs over ONE RRset.
    # Grouped by (owner, type covered) because a response legitimately
    # carries several RRSIGs across DIFFERENT RRsets during a rollover;
    # what is not legitimate is many signatures over the same RRset.
    if rrsigs:
        groups = Counter()
        for r in rrsigs:
            groups[(tuple(normalize(r.name)), r.parsed.get("type_covered"))] += 1
        for (owner, covered), n in groups.items():
            if n >= cfg.keytrap_rrsig_per_rrset:
                oname = b".".join(owner).decode("ascii", "replace") or "."
                out.append(finding(
                    "DNSD-002", zone,
                    f"{n} RRSIGs cover one RRset ({oname} type {covered}) -- "
                    f"each one forces another verification attempt",
                    {"rrsig_count": n, "owner": oname, "type_covered": covered,
                     "qname": _qname_text(msg)},
                ))

    # DNSD-003: the work PRODUCT, which is the actual KeyTrap primitive.
    # Either factor alone can look ordinary; their product is the cost.
    if dnskeys and rrsigs:
        product = len(dnskeys) * len(rrsigs)
        if product >= cfg.keytrap_crypto_product:
            out.append(finding(
                "DNSD-003", zone,
                f"{len(dnskeys)} DNSKEYs x {len(rrsigs)} RRSIGs = up to {product} "
                f"signature verifications for a single response",
                {"dnskey_count": len(dnskeys), "rrsig_count": len(rrsigs),
                 "verifications": product, "qname": _qname_text(msg)},
            ))
    return out


def _referral_shape(msg, cfg):
    """
    Returns (is_glueless_referral, ns_records, glue_count, oob_targets)
    for NXNSAttack analysis.

    A referral is: no answer records, NS records in authority.
    """
    if msg.answers:
        return (False, [], 0, [])
    ns = [r for r in msg.authority if r.rtype == parse.T_NS]
    if not ns:
        return (False, [], 0, [])

    q = _question(msg)
    zone_name = q["name"] if q else None

    targets = []
    for r in ns:
        t = r.parsed.get("target")
        if t is not None:
            targets.append(t)

    # Glue = an address record in additional whose owner is one of the
    # NS targets.
    target_set = {tuple(normalize(t)) for t in targets}
    glue = 0
    for r in msg.additional:
        if r.rtype in (parse.T_A, parse.T_AAAA):
            if tuple(normalize(r.name)) in target_set:
                glue += 1

    # Out-of-bailiwick TARGETS are what the victim resolver must chase.
    oob = []
    if zone_name is not None:
        for t in targets:
            if not in_bailiwick(t, zone_name):
                oob.append(t)
    return (True, ns, glue, oob)


def detect_nxnsattack(msg, cfg, zone, zstate=None, now=None):
    """
    CVE-2020-8616 family. Referral amplification: a malicious
    authoritative returns many NS records, all out of bailiwick, none
    with glue, so the victim resolver fires one lookup per name.

    THE FALSE-POSITIVE CONTROL THAT MATTERS: delegating to a
    third-party DNS provider produces out-of-bailiwick NS targets with
    no glue, and that is completely normal -- it describes most of the
    internet (Cloudflare, Route 53, any managed DNS). What is NOT
    normal is the COUNT. Ordinary delegations carry 2-6 NS records.
    The threshold, not the shape, is the discriminator.
    """
    is_referral, ns, glue, oob = _referral_shape(msg, cfg)
    if not is_referral:
        return []

    out = []
    if (len(ns) >= cfg.nxns_min_ns and glue == 0 and len(oob) >= cfg.nxns_min_ns):
        out.append(finding(
            "DNSD-004", zone,
            f"referral carries {len(ns)} NS records, {len(oob)} of them out of "
            f"bailiwick, with zero glue -- each one costs the resolver a fresh lookup",
            {"ns_count": len(ns), "out_of_bailiwick": len(oob), "glue_count": glue,
             "qname": _qname_text(msg)},
        ))

        # DNSD-005: the same shape repeating for one zone inside a
        # short window. This is the HIGH-confidence leg: one odd
        # referral is a curiosity, several in 100 ms is an attack in
        # progress. Window-based, NOT baseline-learned, so it is
        # grab-and-go safe.
        if zstate is not None and now is not None:
            zstate.push("referral_times", now, cfg.ring_size)
            n = zstate.rate_in_window(zstate.ring("referral_times", cfg.ring_size, create=False),
                                      cfg.nxns_window_seconds)
            if n >= cfg.nxns_min_referrals:
                out.append(finding(
                    "DNSD-005", zone,
                    f"{n} glueless out-of-bailiwick referrals for this zone within "
                    f"{cfg.nxns_window_seconds * 1000:.0f} ms -- referral amplification in progress",
                    {"referrals_in_window": n,
                     "window_ms": cfg.nxns_window_seconds * 1000,
                     "ns_count": len(ns), "qname": _qname_text(msg)},
                ))
    return out


# The chain walk is bounded. A response can carry a CNAME loop or an
# arbitrarily long chain, and an unbounded follow would either spin or
# let an attacker extend the exemption set as far as they liked by
# stacking hops.
CHAIN_MAX_HOPS = 16


def _chain_targets(msg, qname):
    """
    The QNAME plus every CNAME/DNAME target reachable from it through
    the ANSWER section.

    Returns (ordered list of normalized names, stopped_early).

    `stopped_early` is True on a loop or on hitting the hop cap, and
    when it is set the caller must NOT treat anything past the stop
    point as accounted -- the whole purpose of the cap is that an
    attacker cannot buy exemptions by stacking hops, so a truncated
    walk has to exempt less, never more.

    DNAME is followed owner -> target as though it were a CNAME. That
    is an approximation: a DNAME rewrites a subtree rather than one
    name, and a real resolver synthesises the CNAME. It is the
    conservative direction HERE only because every exemption in this
    classifier downgrades critical to notice and never suppresses the
    record, so a slightly wide chain set costs alert severity, not
    visibility.
    """
    by_owner = {}
    for r in msg.answers:
        if r.rtype in (parse.T_CNAME, parse.T_DNAME):
            t = r.parsed.get("target")
            if t is not None:
                by_owner.setdefault(tuple(normalize(r.name)), []).append(
                    tuple(normalize(t)))

    start = tuple(normalize(qname))
    chain = [start]
    seen = {start}
    cur = start
    stopped_early = False
    for _ in range(CHAIN_MAX_HOPS):
        nxt = by_owner.get(cur)
        if not nxt:
            break
        cur = nxt[0]
        if cur in seen:
            stopped_early = True       # loop
            break
        seen.add(cur)
        chain.append(cur)
    else:
        # The loop ran the full cap without breaking: there may be more
        # chain we refused to follow.
        stopped_early = cur in by_owner

    return chain, stopped_early


def _anchored_ns_targets(msg, zone_name, chain):
    """
    RDATA targets of the NS records we are willing to treat as a real
    delegation in this response.

    An NS record anchors glue only if its OWNER is something this
    response has standing to delegate from: either inside the queried
    zone's bailiwick, or at (or above) a name the CNAME/DNAME chain
    actually reached.

    THIS IS THE WHOLE FIX FOR T5. The previous implementation accepted
    the target of ANY NS record in the authority section, so an
    attacker could inject `victim.example NS ns.attacker.example`
    plus matching A glue and have the glue silently exempted by the NS
    record that came in the same forged packet. Anchoring means a
    foreign NS cannot authorise its own glue.
    """
    targets = set()
    for r in msg.all_rrs():
        if r.rtype != parse.T_NS or r.section not in ("authority", "answer"):
            continue
        owner = r.name
        anchored = in_bailiwick(owner, zone_name)
        if not anchored:
            for ct in chain:
                # owner is the chain target itself, or an ancestor of it
                if is_subdomain_of(ct, owner):
                    anchored = True
                    break
        if not anchored:
            continue
        t = r.parsed.get("target")
        if t is not None:
            targets.add(tuple(normalize(t)))
    return targets


def detect_maginotdns(msg, cfg, zone, table=None, src_raw=None, now=0.0):
    """
    CVE-2021-25220 / CVE-2025-40778 attack class. Cache-poisoning by
    smuggling records for a zone the responder has no authority over.

    THIS DETECTOR CLASSIFIES, IT NO LONGER JUST MATCHES. Every record
    outside the queried zone's bailiwick is sorted into one of three
    buckets, and all three are reported -- the split changes the
    SEVERITY an operator sees, never whether the record is visible.

      glue   -- A/AAAA in ADDITIONAL whose owner is the target of an
                ANCHORED NS record            -> DNSD-170, notice
      chain  -- owner is a CNAME/DNAME chain target, or NS/SOA for an
                ancestor of one               -> DNSD-170, notice
      none   -- everything else               -> DNSD-006, critical

    WHY THE SPLIT EXISTS. DNSD-006 was purely structural with no
    version awareness, and reverse DNS at an ISP legitimately produces
    out-of-bailiwick data all day: referral glue for out-of-zone NS
    targets (`2.0.192.in-addr.arpa NS ns1.customer.example`) and RFC
    2317 / CNAME chains into customer domains. Those are normal
    operation, and reporting them as a critical cache-poisoning finding
    against a patched BIND is a false positive that costs an operator
    real time.

    WHAT IT DELIBERATELY DOES NOT DO. It does not become
    version-aware, consult a declared patch level, or take an operator
    allowlist of expected NS targets -- all three were ruled out of
    scope. It is still one packet in, a verdict out, with no probing
    and nothing sent.

    The shared bailiwick utility is NOT touched: NXNSAttack
    (DNSD-004/005) asks it the same question and must keep getting the
    same answer. The split lives here.
    """
    q = _question(msg)
    if q is None:
        return []
    zone_name = q["name"]

    oob = out_of_bailiwick_rrs(msg, zone_name)
    if not oob:
        return []

    chain, chain_truncated = _chain_targets(msg, zone_name)
    chain_set = set(chain)
    ns_targets = _anchored_ns_targets(msg, zone_name, chain)

    def _classify(rr):
        """-> ('glue', detail) | ('chain', detail) | (None, None)"""
        owner = tuple(normalize(rr.name))
        if (rr.section == "additional" and rr.rtype in (parse.T_A, parse.T_AAAA)
                and owner in ns_targets):
            return "glue", {"anchored_ns_target": rr.name.text()}
        if owner in chain_set:
            return "chain", {"chain_hop": chain.index(owner)}
        if rr.rtype in (parse.T_NS, parse.T_SOA):
            for i, ct in enumerate(chain):
                if is_subdomain_of(ct, rr.name):
                    return "chain", {"ancestor_of_chain_hop": i}
        return None, None

    accounted, suspicious = [], []
    for rr in oob:
        reason, detail = _classify(rr)
        if reason is None:
            if rr.section == "additional" and rr.rtype not in (
                    parse.T_A, parse.T_AAAA, parse.T_CNAME, parse.T_NS,
                    parse.T_DNSKEY, parse.T_RRSIG):
                # Pseudo-records and record types that cannot poison a
                # cache keep their pre-split handling: not reported.
                continue
            suspicious.append(rr)
        else:
            accounted.append((rr, reason, detail))

    out = []

    # ---- the accounted records: notice, deduped -------------------
    for rr, reason, detail in accounted:
        key = ("DNSD-170", bytes(src_raw or b""), zone_name.text().lower(),
               rr.name.text().lower())
        if table is not None and not table.first_sighting(key, now):
            continue
        ev = {"qname": _qname_text(msg), "qzone": zone_name.text(),
              "rr_owner": rr.name.text(), "rr_type": rr.rtype,
              "section": rr.section, "reason": reason,
              "responder": _fmt_addr(src_raw) if src_raw else None,
              "family": ("v6" if src_raw and len(src_raw) == 16 else
                         "v4" if src_raw else None),
              "chain_len": len(chain), "chain_truncated": chain_truncated}
        ev.update(detail)
        out.append(finding(
            "DNSD-170", zone,
            f"out-of-bailiwick {rr.name.text()} in {rr.section} is accounted for by "
            f"this response's own {reason} structure, not injection",
            ev,
        ))

    # ---- the rest: unchanged DNSD-006 -----------------------------
    if suspicious:
        names = sorted({r.name.text() for r in suspicious})[:5]
        out.append(finding(
            "DNSD-006", zone,
            f"{len(suspicious)} record(s) outside the queried zone's bailiwick and "
            f"not accounted for by delegation glue or a CNAME/DNAME chain: "
            f"{', '.join(names)}",
            {"count": len(suspicious), "names": names, "qzone": zone_name.text(),
             "sections": sorted({r.section for r in suspicious}),
             "accounted_count": len(accounted),
             "chain_len": len(chain), "chain_truncated": chain_truncated},
        ))
    return out


def detect_tudoor(msg, cfg, zone):
    """
    The TuDoor CVE cluster is ~33 CVEs across many resolvers, all
    reached through malformed or unexpected response packets. Passive
    detection cannot tell which one (or whether the target resolver is
    even vulnerable), so this is ONE generic informational code rather
    than 33 codes claiming precision that isn't there -- the same
    reasoning that caps sshwatch's regreSSHion posture at notice.
    """
    if not msg.malformed:
        return []
    return [finding(
        "DNSD-007", zone,
        f"malformed DNS message: {msg.malformed_reason}",
        {"reason": msg.malformed_reason, "txid": msg.txid,
         "qname": _qname_text(msg)},
    )]


# ======================================================================
# POSTURE
# ======================================================================

def detect_nsec3_iterations(msg, cfg, zone):
    """
    CVE-2023-50868 / RFC 9276. Iterations above 0 buy no security and
    cost the validator a hash chain per lookup. This is a POSTURE
    finding about the zone being served, not an attack in progress.
    """
    out = []
    worst = None
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_NSEC3:
            continue
        it = rr.parsed.get("iterations")
        if it is None:
            continue
        if it > cfg.nsec3_max_iterations and (worst is None or it > worst):
            worst = it
    if worst is not None:
        out.append(finding(
            "DNSD-010", zone,
            f"NSEC3 iteration count {worst} exceeds the RFC 9276 ceiling of "
            f"{cfg.nsec3_max_iterations} -- pure validator CPU cost, no added security",
            {"iterations": worst, "rfc9276_max": cfg.nsec3_max_iterations,
             "qname": _qname_text(msg)},
        ))
    return out


def detect_algo_downgrade(msg, cfg, zone):
    """
    A signed response using an algorithm the validator cannot verify,
    where AD is clear and the resolver did NOT SERVFAIL, means
    validation was silently skipped rather than failed.

    FP control: an UNSIGNED delegation looks similar from the outside,
    so this requires an actual RRSIG or DNSKEY carrying the unsupported
    algorithm -- absence of signatures is not evidence of downgrade.
    """
    algos = set()
    for rr in msg.all_rrs():
        if rr.rtype in (parse.T_RRSIG, parse.T_DNSKEY):
            a = rr.parsed.get("algorithm")
            if a is not None:
                algos.add(a)
    if not algos:
        return []
    unsupported = {a for a in algos
                   if a not in parse.SUPPORTED_ALGOS}
    if not unsupported:
        return []
    if msg.ad:
        return []      # validator says it authenticated -- nothing skipped
    if msg.rcode == 2:
        return []      # SERVFAIL: it failed loudly, which is correct behaviour

    deprecated = sorted(unsupported & parse.DEPRECATED_ALGOS)
    unknown = sorted(unsupported - parse.DEPRECATED_ALGOS)
    return [finding(
        "DNSD-011", zone,
        f"signed with algorithm(s) {sorted(unsupported)} that a modern validator "
        f"cannot verify, AD is clear and the response is not SERVFAIL -- validation "
        f"was skipped rather than failed",
        {"algorithms": sorted(unsupported), "deprecated": deprecated,
         "unknown": unknown, "ad": msg.ad, "rcode": msg.rcode,
         "qname": _qname_text(msg)},
    )]


# ======================================================================
# BEHAVIOURAL (baseline-dependent -- gated, see state.py)
# ======================================================================

def _baseline_gate(cfg, zstate, baseline_name, now):
    """
    THE grab-and-go gate. Returns the baseline only if behavioural
    detection is enabled AND this zone's baseline is warm. Every
    behavioural detector goes through here; none can emit without it.
    """
    if not cfg.enable_baseline_detectors:
        return None
    b = zstate.baseline(baseline_name)
    if not b.is_warm(cfg, now):
        return None
    return b


def _random_subdomain_ratio(zstate, cfg):
    """
    Fraction of recently-seen first labels for this zone that are
    distinct. A pseudo-random subdomain flood approaches 1.0; ordinary
    traffic to a real site repeats www/mail/api and sits far lower.
    Uses hashes, never the labels themselves -- a passive sensor has
    no business retaining queried hostnames.
    """
    ring = zstate.ring("subdomain_hashes", cfg.ring_size, create=False)
    if len(ring) < 8:
        return 0.0
    return len(set(ring)) / float(len(ring))


def detect_dnsbomb(msg, cfg, zone, zstate, now):
    """
    CVE-2024-33655. DNSBomb accumulates short-TTL queries and releases
    them as a pulse. The accumulation phase is what is visible
    passively: short-TTL answers for one zone far above its norm.
    """
    ttls = [rr.ttl for rr in msg.answers]
    if not ttls:
        return []
    short = [t for t in ttls if t <= cfg.short_ttl_seconds]
    if not short:
        return []

    zstate.push("short_ttl_times", now, cfg.ring_size)
    rate = zstate.rate_in_window(
        zstate.ring("short_ttl_times", cfg.ring_size, create=False), 1.0)

    b = _baseline_gate(cfg, zstate, "bl_short_ttl_ratio", now)
    if b is None:
        # Not warm (or disabled): still LEARN, never EMIT.
        zstate.baseline("bl_short_ttl_ratio").update(rate, now, cfg)
        return []
    exceeded = b.exceeds(rate, cfg)
    baseline_value = b.value
    if not exceeded:
        b.update(rate, now, cfg)
        return []
    # DELIBERATELY do NOT fold an anomalous sample back into the
    # baseline. Updating unconditionally lets the baseline CHASE the
    # attack: a ramping flood raises the threshold as fast as it raises
    # the signal and never trips. Caught by conformance -- the warm
    # 5x-burst case silently produced nothing, because by the time the
    # rate reached 40/s the baseline it was compared against had been
    # dragged up by the same 40 samples. Freeze while anomalous.
    return [finding(
        "DNSD-020", zone,
        f"short-TTL answer rate {rate}/s is {rate / max(baseline_value, 1e-9):.1f}x this "
        f"zone's learned baseline of {baseline_value:.2f}/s",
        {"rate": rate, "baseline": round(baseline_value, 3),
         "factor": cfg.baseline_deviation_factor, "min_ttl": min(short),
         "qname": _qname_text(msg)},
    )]


def detect_nsec3_encloser(msg, cfg, zone, zstate, now):
    """
    CVE-2023-50868, behavioural leg. The closest-encloser attack needs
    THREE things together: a high iteration count, many NSEC3 records
    per response, and a random-subdomain flood driving them. Any one
    alone is ordinary; the conjunction is the attack.
    """
    nsec3 = [rr for rr in msg.all_rrs() if rr.rtype == parse.T_NSEC3]
    if len(nsec3) < cfg.nsec3_encloser_min_rrs:
        return []
    iters = max((r.parsed.get("iterations") or 0) for r in nsec3)
    if iters <= cfg.nsec3_max_iterations:
        return []

    ratio = _random_subdomain_ratio(zstate, cfg)
    b = _baseline_gate(cfg, zstate, "bl_nxdomain_ratio", now)
    if b is None:
        return []
    if ratio < 0.9:
        return []
    return [finding(
        "DNSD-021", zone,
        f"{len(nsec3)} NSEC3 records at {iters} iterations, against a "
        f"{ratio:.0%} distinct-subdomain query mix -- closest-encloser CPU exhaustion",
        {"nsec3_count": len(nsec3), "iterations": iters,
         "distinct_subdomain_ratio": round(ratio, 3), "qname": _qname_text(msg)},
    )]


def detect_water_torture(msg, cfg, zone, zstate, now):
    """
    Pseudo-random subdomain flood. Highest false-positive risk in the
    tier by a wide margin -- typo traffic, antivirus/telemetry domain
    enumeration and CDN health checks all produce NXDOMAIN bursts with
    high subdomain entropy.

    Three controls: the zone exclusion list, the learned baseline, and
    a requirement that the subdomain mix actually be near-unique.
    """
    if zone in cfg.excluded_zones:
        return []
    if msg.rcode != 3:      # NXDOMAIN only
        return []

    zstate.push("nxdomain_times", now, cfg.ring_size)
    q = _question(msg)
    if q is not None:
        labels = normalize(q["name"])
        if labels:
            zstate.push("subdomain_hashes", hash(labels[0]) & 0xFFFFFFFF, cfg.ring_size)

    rate = zstate.rate_in_window(
        zstate.ring("nxdomain_times", cfg.ring_size, create=False), 1.0)

    b = _baseline_gate(cfg, zstate, "bl_nxdomain_ratio", now)
    if b is None:
        zstate.baseline("bl_nxdomain_ratio").update(rate, now, cfg)
        return []

    ratio = _random_subdomain_ratio(zstate, cfg)
    exceeded = b.exceeds(rate, cfg)
    baseline_value = b.value
    if not exceeded:
        # Same baseline-chasing guard as DNSBomb above: only quiet
        # traffic teaches the baseline what quiet looks like.
        b.update(rate, now, cfg)
        return []
    if ratio < 0.9:
        return []
    return [finding(
        "DNSD-022", zone,
        f"NXDOMAIN rate {rate}/s is {rate / max(baseline_value, 1e-9):.1f}x this zone's "
        f"baseline of {baseline_value:.2f}/s, with {ratio:.0%} distinct subdomains",
        {"rate": rate, "baseline": round(baseline_value, 3),
         "distinct_subdomain_ratio": round(ratio, 3), "qname": _qname_text(msg)},
    )]


# ======================================================================
# RESPONSE INTEGRITY (SAD DNS)
# ======================================================================

def answer_signature(msg):
    """
    Canonical signature of a response's answer set, for detecting two
    DIFFERENT answers to one query.

    Built from decoded record fields, never from raw wire bytes: the
    same answer legitimately differs byte-for-byte between two
    responses through name compression alone, and comparing raw bytes
    would make every retransmission look like a forgery.
    """
    parts = []
    for rr in msg.answers:
        parts.append((tuple(normalize(rr.name)), rr.rtype, rr.rclass, bytes(rr.rdata)))
    return tuple(sorted(parts))


def detect_sad_dns_conflict(msg, cfg, zone, inflight, key, now):
    """
    CVE-2020-25705. Two responses to one outstanding query carrying
    different answers means one of them is forged -- there is no benign
    reading, which is why this is HIGH confidence despite being cheap.

    TTL is deliberately excluded from the signature: a legitimate
    retransmission or a second cached copy can carry a decremented TTL
    for the same data, and treating that as a conflict would fire on
    ordinary traffic.
    """
    sig = answer_signature(msg)
    prev = inflight.note_response(key, sig, now)
    if prev is None:
        return []
    return [finding(
        "DNSD-030", zone,
        f"two responses to one outstanding query (txid {msg.txid}) carry different "
        f"answer sets -- one of them is forged",
        {"txid": msg.txid, "qname": _qname_text(msg),
         "first_answer_records": len(prev), "second_answer_records": len(sig)},
    )]


def detect_source_port_entropy(cfg, zone, zstate, sport, now):
    """
    Posture only. Low source-port entropy makes off-path spoofing
    practical; it is not evidence that spoofing happened, which is why
    it is capped at notice/low (LESSON T).
    """
    zstate.push("src_ports", sport, cfg.ring_size)
    ring = zstate.ring("src_ports", cfg.ring_size, create=False)
    if len(ring) < cfg.port_entropy_min_samples:
        return []
    distinct = len(set(ring))
    ratio = distinct / float(len(ring))
    if ratio >= cfg.port_entropy_min_distinct_ratio:
        return []
    return [finding(
        "DNSD-031", zone,
        f"only {distinct} distinct source ports across {len(ring)} queries "
        f"({ratio:.0%}) -- port prediction is easier than it should be",
        {"distinct_ports": distinct, "samples": len(ring),
         "distinct_ratio": round(ratio, 3)},
    )]


# ======================================================================
# STRUCTURAL, continued -- DNSD-008 / DNSD-009
# ======================================================================

def detect_pointer_anomaly(msg, cfg, zone):
    """
    CVE-2026-81642 (Unbound, DNSKEY owner name is a compression pointer
    into its own RDATA -- possible RCE), CVE-2026-2291 and CVE-2026-5172
    (dnsmasq extract_name / extract_addresses memory bugs).

    Deliberately SEPARATE from DNSD-007. A truncated record is ordinary
    on a real network and rates notice/low; a pointer loop, a forward
    pointer, or a pointer into RDATA is a memory-safety primitive and
    rates critical/high. Folding them together would bury the second
    under the volume of the first.

    Note which check does the work. Loops and forward pointers are
    rejected by the parser's strictly-decreasing rule. A pointer into an
    EARLIER record's RDATA is not -- it points backwards perfectly
    legally -- so it takes an explicit span check, and that is precisely
    the Unbound shape.
    """
    if msg.pointer_anomaly is None:
        return []
    return [finding(
        "DNSD-008", zone,
        f"compression pointer anomaly: {msg.pointer_anomaly}",
        {"reason": msg.pointer_anomaly, "txid": msg.txid,
         "pointer_targets": list(msg.pointer_targets)[:8],
         "qname": _qname_text(msg)},
    )]


def detect_dnskey_malformed(msg, cfg, zone):
    """
    CVE-2025-8677 (BIND, CPU exhaustion), CVE-2026-4890 (dnsmasq DNSSEC
    infinite loop), CVE-2026-4891 (dnsmasq heap over-read).

    Checks the DNSKEY rdata invariants RFC 4034 s2.1 actually fixes,
    rather than guessing at key material:
      - protocol octet MUST be 3; any other value makes the record
        undefined, and a resolver that keeps parsing it is the bug
      - the public key MUST be non-empty
      - the REVOKE bit with SEP set is contradictory: a revoked key
        cannot also be a valid secure entry point
      - a zone key must have the ZONE bit set
    """
    out = []
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_DNSKEY:
            continue
        p = rr.parsed
        if "algorithm" not in p:
            continue
        problems = []
        if p.get("protocol") != 3:
            problems.append(f"protocol octet is {p.get('protocol')}, RFC 4034 requires 3")
        if p.get("keylen", 0) == 0:
            problems.append("public key field is empty")
        flags = p.get("flags", 0)
        if (flags & 0x0080) and (flags & 0x0001):
            problems.append("REVOKE and SEP both set -- a revoked key cannot be a secure entry point")
        if p.get("keylen", 0) and p.get("algorithm") in (8, 10) and p["keylen"] < 64:
            problems.append(f"RSA key material is {p['keylen']} bytes, far below any valid modulus")
        if problems:
            out.append(finding(
                "DNSD-009", zone,
                f"malformed DNSKEY for {rr.name.text()}: " + "; ".join(problems),
                {"owner": rr.name.text(), "flags": flags,
                 "protocol": p.get("protocol"), "algorithm": p.get("algorithm"),
                 "keylen": p.get("keylen"), "problems": problems},
            ))
    return out


# ======================================================================
# DNSSEC STRUCTURAL INTEGRITY (040-049)
# ======================================================================

def detect_rrsig_label_mismatch(msg, cfg, zone):
    """
    CVE-2026-11721 (BIND), CVE-2026-52688 (PowerDNS Recursor).

    RFC 4034 s3.1.3: the labels field holds the number of labels in the
    original owner name, NOT counting the root and NOT counting a
    leading wildcard.

    THE FALSE-POSITIVE CONTROL THAT MATTERS: labels LESS than the owner
    name's label count is entirely legal and completely routine -- it is
    how wildcard expansion is signalled, and firing on it would alert on
    every wildcard-served zone on the internet. Only labels GREATER than
    the owner's count is impossible, and that is the direction a
    validator reconstructing the signed name reads off the end.
    """
    out = []
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_RRSIG:
            continue
        claimed = rr.parsed.get("labels")
        if claimed is None:
            continue
        actual = len(normalize(rr.name))
        if claimed > actual:
            out.append(finding(
                "DNSD-040", zone,
                f"RRSIG over {rr.name.text()} claims {claimed} labels but the owner name "
                f"has {actual} -- a validator reconstructing the signed name reads past it",
                {"owner": rr.name.text(), "claimed_labels": claimed,
                 "actual_labels": actual,
                 "type_covered": rr.parsed.get("type_covered"),
                 "note": "labels < actual is legal wildcard signalling and is not reported"},
            ))
    return out


def detect_nsec_next_out_of_zone(msg, cfg, zone):
    """
    CVE-2026-13321 (BIND). The NSEC chain is a closed loop WITHIN a
    zone: every next-domain name is another name in the same zone, and
    the last one wraps back to the apex. A next-domain outside the zone
    walks a validator out of the zone it was authenticating.

    Bailiwick is judged against the NSEC record's own OWNER name's zone,
    derived from the question, rather than against the record owner
    itself -- a subdomain owner legitimately points to a sibling.
    """
    q = _question(msg)
    if q is None:
        return []
    zone_name = q["name"]
    out = []
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_NSEC:
            continue
        nxt = rr.parsed.get("next")
        if nxt is None:
            continue
        # The apex wrap is the normal terminating case and is in zone.
        if in_bailiwick(nxt, zone_name):
            continue
        # An NSEC proving a delegation may legitimately sit at or above
        # the queried name; judge against the RECORD's own apex too
        # before reporting, to avoid firing on referral-side NSECs.
        if in_bailiwick(nxt, rr.name) or in_bailiwick(rr.name, nxt):
            continue
        out.append(finding(
            "DNSD-041", zone,
            f"NSEC at {rr.name.text()} points to next-domain {nxt.text()}, which is outside "
            f"the zone {zone_name.text()} -- the NSEC chain should close within the zone",
            {"owner": rr.name.text(), "next": nxt.text(), "zone": zone_name.text()},
        ))
    return out


def detect_nsec3_apex_impersonation(msg, cfg, zone):
    """
    CVE-2026-10723 (BIND). ISC's internal title: DNSSEC validation
    bypass via NSEC3 apex hash label parent impersonation (CWE-345).

    An NSEC3 record's owner is <base32-hash>.<zone>. If that owner sits
    OUTSIDE the queried zone, the record is claiming to be an apex hash
    belonging to a parent -- a denial proof for a zone the responder
    does not hold.

    MEDIUM confidence, matching the CVE's AC:H. Judging a zone cut
    passively is inherently partial: we can see that the owner is out of
    bailiwick, not whether the responder was genuinely authoritative.
    """
    q = _question(msg)
    if q is None:
        return []
    zone_name = q["name"]
    out = []
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_NSEC3:
            continue
        if in_bailiwick(rr.name, zone_name):
            continue
        labels = normalize(rr.name)
        if not labels:
            continue
        out.append(finding(
            "DNSD-042", zone,
            f"NSEC3 record owned by {rr.name.text()} is outside the queried zone "
            f"{zone_name.text()} -- claiming an apex hash for a parent it does not hold",
            {"owner": rr.name.text(), "zone": zone_name.text(),
             "hash_label": labels[0].decode("ascii", "replace"),
             "iterations": rr.parsed.get("iterations")},
        ))
    return out


def detect_nsec_nsec3_coexistence(msg, cfg, zone):
    """
    CVE-2026-13204 (BIND). Three conditions, all three required:
      1. the response carries NSEC records, AND
      2. it carries NSEC3 records for the same zone, AND
      3. RRSIGs cover only ONE of the two denial types.

    A zone uses NSEC or NSEC3, never both. When both appear and only one
    is signed, the unsigned half is attacker-substitutable while still
    looking like a complete denial proof.

    Requiring all three is what keeps this quiet: an NSEC3-only or
    NSEC-only response, however odd, produces nothing here.
    """
    nsec = [r for r in msg.all_rrs() if r.rtype == parse.T_NSEC]
    nsec3 = [r for r in msg.all_rrs() if r.rtype == parse.T_NSEC3]
    if not nsec or not nsec3:
        return []

    covered = {r.parsed.get("type_covered") for r in msg.all_rrs()
               if r.rtype == parse.T_RRSIG}
    nsec_signed = parse.T_NSEC in covered
    nsec3_signed = parse.T_NSEC3 in covered
    if nsec_signed == nsec3_signed:
        return []          # both signed, or neither -- not this CVE

    unsigned = "NSEC3" if nsec_signed else "NSEC"
    return [finding(
        "DNSD-043", zone,
        f"response carries both NSEC ({len(nsec)}) and NSEC3 ({len(nsec3)}) denial records "
        f"but RRSIGs cover only the {'NSEC' if nsec_signed else 'NSEC3'} half -- "
        f"the {unsigned} records are unsigned and substitutable",
        {"nsec_count": len(nsec), "nsec3_count": len(nsec3),
         "nsec_signed": nsec_signed, "nsec3_signed": nsec3_signed,
         "unsigned_type": unsigned, "qname": _qname_text(msg)},
    )]


# ======================================================================
# PROTOCOL ABUSE (050-059)
# ======================================================================

def detect_svcb_alias_abuse(msg, cfg, zone):
    """
    CVE-2026-81563 and CVE-2026-81736 (BIND). An SVCB/HTTPS AliasMode
    record (SvcPriority 0) that fans out to a large number of
    ServiceMode records in one response drives a qpcache leak, and the
    cached alias tree makes a later root query burn CPU.

    Bounded by construction: the chain is counted WITHIN one response,
    never followed across responses, so there is no unbounded traversal
    and no per-zone state.
    """
    svcb = [r for r in msg.all_rrs() if r.rtype in (parse.T_SVCB, parse.T_HTTPS)]
    if not svcb:
        return []
    alias = [r for r in svcb if r.parsed.get("alias_mode")]
    service = [r for r in svcb if r.parsed.get("service_mode")]
    if not alias:
        return []
    if len(service) < cfg.svcb_max_servicemode:
        return []
    return [finding(
        "DNSD-050", zone,
        f"SVCB/HTTPS AliasMode record fans out to {len(service)} ServiceMode records in one "
        f"response (threshold {cfg.svcb_max_servicemode}) -- qpcache fan-out abuse",
        {"alias_count": len(alias), "servicemode_count": len(service),
         "threshold": cfg.svcb_max_servicemode,
         "alias_targets": [r.parsed.get("target").text() for r in alias[:4]
                           if r.parsed.get("target")],
         "qname": _qname_text(msg)},
    )]


def detect_edns_option_duplication(msg, cfg, zone):
    """
    CVE-2026-42944 (Unbound). An option code that RFC permits at most
    once, appearing more than once in a single OPT record, is itself the
    denial-of-service primitive -- no payload needed.

    Only SINGLETON option codes are checked. Some options legitimately
    repeat, and reporting those would be wrong rather than merely noisy.
    """
    out = []
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_OPT:
            continue
        opts = rr.parsed.get("options") or []
        counts = Counter(c for c, _ln in opts if isinstance(c, int))
        dupes = {c: n for c, n in counts.items()
                 if n > 1 and c in parse.EDNS_SINGLETON_OPTIONS}
        if not dupes:
            continue
        named = {parse.EDNS_OPTION_NAMES.get(c, str(c)): n for c, n in dupes.items()}
        out.append(finding(
            "DNSD-051", zone,
            f"EDNS0 OPT record repeats single-use option(s): "
            f"{', '.join(f'{k} x{v}' for k, v in sorted(named.items()))}",
            {"duplicates": named, "total_options": len(opts),
             "qname": _qname_text(msg)},
        ))
    return out


def detect_duplicate_rr_flood(msg, cfg, zone):
    """
    CVE-2026-75029 (BIND). Identical SOA, CNAME or DNAME records
    repeated in one response each get stored separately and bloat the
    negative cache.

    Scoped to those three types on purpose. Repeated A or AAAA records
    for one name are ordinary round-robin, and including them would turn
    this into a false-positive generator.
    """
    # ONE table, not two. An earlier version kept the set of watched
    # types and the rtype->name map as separate literals; adding a type
    # to one and not the other raised KeyError inside the detector
    # instead of reporting, and engine.handle_frame's try/except would
    # have swallowed that in production -- findings silently gone while
    # every test still passed. Deriving the set from the map's keys
    # makes the divergence impossible to write.
    DUP_TYPE_NAMES = {parse.T_SOA: "SOA", parse.T_CNAME: "CNAME", parse.T_DNAME: "DNAME"}
    interesting = tuple(DUP_TYPE_NAMES)
    counts = Counter()
    for rr in msg.all_rrs():
        if rr.rtype in interesting:
            counts[(tuple(normalize(rr.name)), rr.rtype, bytes(rr.rdata))] += 1
    worst = [(k, n) for k, n in counts.items() if n >= cfg.duplicate_rr_threshold]
    if not worst:
        return []
    (owner, rtype, _rd), n = max(worst, key=lambda kv: kv[1])
    tname = DUP_TYPE_NAMES.get(rtype, f"type-{rtype}")
    return [finding(
        "DNSD-052", zone,
        f"{n} byte-identical {tname} records for "
        f"{b'.'.join(owner).decode('ascii', 'replace') or '.'} in one response -- "
        f"each copy is cached separately",
        {"record_type": tname, "duplicate_count": n,
         "threshold": cfg.duplicate_rr_threshold,
         "distinct_duplicated_sets": len(worst), "qname": _qname_text(msg)},
    )]


def detect_tkey_query(msg, cfg, zone):
    """
    CVE-2026-76163 (BIND 9.20.0-9.20.27 / 9.21.0-9.21.25): a QTYPE TKEY
    query trips an assertion failure when named.conf has no global
    options block.

    MEDIUM confidence, and the wording says why: TKEY is a legitimate
    QTYPE for GSS-TSIG, and the vulnerable condition is a CONFIG state
    this sensor cannot see. So this reports an attack ATTEMPT reaching a
    resolver, not a vulnerable resolver. The operator correlates with
    their own BIND version.
    """
    out = []

    # --- LEG 2: a TKEY record whose SPNEGO token is impossible -------
    # CVE-2020-8625 / CVE-2021-25216, folded in here rather than given
    # a code of their own because the ceiling on what the wire can say
    # is identical: BIND's SPNEGO decoder is only reachable when
    # tkey-gssapi-keytab or tkey-gssapi-credential is set, and no
    # packet reveals whether it is. Same evidence ceiling, same code.
    #
    # Scanned in BOTH directions, unlike leg 1. The client->server
    # token is the documented vector, but a malicious server's
    # response token reaches a client-side GSS stack through the same
    # decoder, and restricting this to queries would have made that
    # invisible for no gain.
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_TKEY:
            continue
        p = rr.parsed or {}
        reason = p.get("struct_error") or p.get("spnego_error")
        if not reason:
            continue
        out.append(finding(
            "DNSD-053", zone,
            f"TKEY record for {rr.name.text()} in the {rr.section} section carries an "
            f"impossible structure: {reason}. A malformed SPNEGO/ASN.1 length is the "
            f"precondition for the BIND GSSAPI buffer overflow -- an attempt, since "
            f"tkey-gssapi-keytab is not visible from the wire",
            {"qname": rr.name.text(), "section": rr.section,
             "tkey_mode": p.get("mode"), "gssapi": p.get("gssapi"),
             "key_size": p.get("key_size"), "reason": reason,
             "affected": "BIND 9.5.0-9.11.27, 9.12.0-9.16.11, 9.17.0-9.17.18 "
                         "(CVE-2020-8625/CVE-2021-25216)"},
        ))

    # --- LEG 1: a bare TKEY query ------------------------------------
    if msg.qr:
        return out
    q = _question(msg)
    if q is None or q["qtype"] != parse.QT_TKEY:
        return out
    out.append(finding(
        "DNSD-053", zone,
        f"QTYPE TKEY query for {q['name'].text()} -- trips a BIND assertion failure where "
        f"named.conf has no global options block. TKEY is legitimate for GSS-TSIG, so this "
        f"is an attempt reaching the resolver, not proof it is vulnerable",
        {"qname": q["name"].text(), "qtype": q["qtype"],
         "affected": "BIND 9.20.0-9.20.27, 9.21.0-9.21.25 (+ -S1)"},
    ))
    return out


# ======================================================================
# ZONE TRANSFER INTEGRITY (060-069)
# ======================================================================

def detect_xfr_tsig_absent(msg, cfg, zone, xstream, now, is_tcp):
    """
    CVE-2026-19033 (BIND 9.11.0-9.18.50, 9.20.0-9.20.27, 9.21.0-9.21.25
    and -S1 equivalents).

    RFC 8945 requires every message of a multi-message transfer to be
    TSIG-signed. A secondary with TSIG-restricted transfers that applies
    data from unsigned intermediate messages has already served it and
    never rolls back -- so this detects a COMPLETED attack, not an
    attempt, which is why it is critical/high.

    Near-zero false positive by ISC's own assessment: modern name
    servers already sign every message, so a correctly-behaving transfer
    simply never reaches the reporting condition.

    WHAT THIS CAN AND CANNOT SEE. Completion is judged by the transfer's
    terminating SOA (AXFR opens and closes with SOA; IXFR closes with
    the final SOA), because a passive observer has no connection-close
    signal it can rely on. A transfer whose terminating SOA never
    crosses the tap is not reported at all -- the failure mode is
    silence, not a false alarm.
    """
    if not is_tcp or xstream is None:
        return []
    q = _question(msg)
    qtype = q["qtype"] if q else xstream.qtype
    if qtype not in (parse.QT_IXFR, parse.QT_AXFR):
        return []
    if not msg.qr:
        xstream.qtype = qtype
        return []

    xstream.messages += 1
    signed = any(rr.rtype == parse.T_TSIG for rr in msg.additional)
    xstream.last_signed = signed
    if signed:
        xstream.signed_messages += 1
    xstream.soa_count += sum(1 for rr in msg.answers if rr.rtype == parse.T_SOA)

    # Terminating SOA seen and this was genuinely multi-message.
    complete = xstream.soa_count >= 2 and xstream.messages >= 2
    if not complete or xstream.reported:
        return []

    unsigned = xstream.messages - xstream.signed_messages
    if unsigned == 0 or xstream.last_signed:
        return []          # fully signed, or properly closed with a TSIG

    xstream.reported = True
    kind = "IXFR" if qtype == parse.QT_IXFR else "AXFR"
    return [finding(
        "DNSD-060", zone,
        f"multi-message TCP {kind} completed with {unsigned} of {xstream.messages} messages "
        f"unsigned and no final TSIG -- a secondary applying this has already served "
        f"data it will not roll back",
        {"transfer_type": kind, "messages": xstream.messages,
         "signed_messages": xstream.signed_messages, "unsigned_messages": unsigned,
         "final_message_signed": xstream.last_signed,
         "soa_records_seen": xstream.soa_count, "qname": _qname_text(msg)},
    )]


# ======================================================================
# SIGRed + TSIG STRUCTURAL
# ======================================================================

def detect_sigred(msg, cfg, zone, is_tcp=False):
    """
    CVE-2020-1350 (SIGRed, CVSS 10.0, CISA KEV). Windows DNS sizes its
    record buffer as

        uncompressed_signer_name_length + 0x14 + signature_length

    and RR_AllocateEx then uses only the low 16 bits of that sum. A
    total of 65536 or more wraps to a tiny allocation, and the
    following memcpy writes the full data into it.

    THE DETECTOR RECOMPUTES THAT SUM IN FULL PRECISION. Doing the
    arithmetic in 16 bits here would reproduce the bug rather than
    detect it, which is why parse._sigred_geometry uses Python ints.

    BOTH SIG(24) AND RRSIG(46). Windows parses them through one
    function, SigWireRead, and both type numbers reach it -- a
    detector watching only RRSIG would miss half the attack surface
    for no reason other than that RRSIG is the type people think of.

    WHY THE SIGNER-NAME TERM MATTERS. The two terms are not equally
    obvious: the signature length is capped by the 16-bit rdlength and
    by what fits in a 64 KB TCP message, so on its own it cannot quite
    reach the wrap. The name closes the gap, because a COMPRESSION
    POINTER costs two bytes on the wire while contributing its full
    uncompressed length -- up to 255 -- to the sum. That is also why
    this is not already covered by DNSD-008: the pointer here is
    perfectly legal, backwards, and need not land in any RDATA.

    NOT GATED ON TCP. SIGRed needs TCP in practice, because no UDP
    datagram carries a 64 KB record. But the gate is the ARITHMETIC,
    which is unreachable over UDP anyway, so adding a transport
    condition could only ever subtract a detection -- transport goes
    in the evidence instead.

    NEAR MISSES ARE DELIBERATELY SILENT. An allocation that lands at
    65400 is a failed attempt that harmed nothing, and reporting it
    would mean inventing a threshold. The wrap is an exact condition
    with no legitimate counterpart: the largest real signature in use
    is a few hundred bytes.
    """
    out = []
    for rr in msg.all_rrs():
        if rr.rtype not in (parse.T_SIG, parse.T_RRSIG):
            continue
        p = rr.parsed or {}
        if not p.get("sigred_wraps"):
            continue
        if not cfg.sigred_report_near_miss and p["sigred_alloc"] < parse.SIGRED_ALLOC_WRAP:
            continue
        type_name = "SIG" if rr.rtype == parse.T_SIG else "RRSIG"
        out.append(finding(
            "DNSD-044", zone,
            f"{type_name} record for {rr.name.text()} computes a Windows DNS allocation of "
            f"{p['sigred_alloc']} bytes ({p['signer_uncompressed_len']} name + 0x14 + "
            f"{p['signature_len']} signature), which truncates to "
            f"{p['sigred_alloc'] & 0xFFFF} in 16 bits -- SIGRed heap overflow"
            + (f". The signer name was reached through a compression pointer, "
               f"contributing {p['signer_uncompressed_len']} bytes from "
               f"{p['signer_wire_bytes']} on the wire"
               if p.get("signer_compressed") else ""),
            {"record_type": type_name, "owner": rr.name.text(),
             "signer_uncompressed_len": p["signer_uncompressed_len"],
             "signer_wire_bytes": p["signer_wire_bytes"],
             "signer_compressed": p.get("signer_compressed"),
             "signature_len": p["signature_len"],
             "alloc": p["sigred_alloc"],
             "alloc_truncated_16bit": p["sigred_alloc"] & 0xFFFF,
             "rdlength": rr.rdlength, "transport": "tcp" if is_tcp else "udp",
             "section": rr.section},
        ))
    return out


def detect_tsig_malformed(msg, cfg, zone):
    """
    CVE-2020-8622 (CVSS 6.5). ISC: "Attempting to verify a truncated
    response to a TSIG-signed request leads to an assertion failure."

    WHAT THIS DOES NOT CHECK: the TC flag. That is the naive reading of
    "truncated response" and it would be wrong in the worst way -- TC
    is set on legitimate truncated responses constantly, above all on
    the zone transfers that are the main users of TSIG, so a TC-based
    version of this check would fire on normal operation and tell an
    operator nothing. The actual condition is a TSIG the receiver could
    not fully read, so the test is whether the record's own internal
    length fields can coexist with its rdlength.

    Near-zero false positive by construction: every field involved is
    written by the signer from a known MAC length. There is no
    legitimate path that emits a TSIG whose MAC size overruns its own
    rdata.

    RUNS ON EVERY MESSAGE, not just UPDATEs -- TSIG covers zone
    transfers and NOTIFY too, and the assertion does not care which.
    """
    out = []
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_TSIG:
            continue
        err = (rr.parsed or {}).get("struct_error")
        if not err:
            continue
        out.append(finding(
            "DNSD-054", zone,
            f"TSIG record for {rr.name.text()} is internally impossible: {err}. A receiver "
            f"verifying a TSIG it could not fully read asserts and exits",
            {"owner": rr.name.text(), "section": rr.section,
             "algorithm": (rr.parsed or {}).get("algorithm"),
             "mac_size": (rr.parsed or {}).get("mac_size"),
             "rdlength": rr.rdlength, "reason": err,
             "affected": "BIND 9.0.0-9.11.21, 9.12.0-9.16.5, 9.17.0-9.17.3"},
        ))
    return out


# ======================================================================
# DNS-SD OVER UNICAST (100-109)
# ======================================================================

def detect_dnssd_enumeration(msg, cfg, table, src_raw, now):
    """
    DNSD-100. A PTR query for `_services._dns-sd._udp.<domain>` returns
    every service type published in that domain (RFC 6763 s9).

    RESTRICTED TO UNICAST ZONES, and the restriction is the entire
    false-positive control. The identical query against `.local` is
    what any Mac, iPhone or Bonjour-aware application issues on
    joining a network -- "show me what is on this LAN" -- so reporting
    it would put a warning on every laptop in the building. Against a
    real zone over unicast DNS it is service enumeration, and it is
    rare enough that a single one is worth a line.

    This runs on port 53 only, so the `.local` case cannot reach it
    through the mDNS fork anyway; the domain check is belt and braces
    for a unicast query that names `.local` explicitly, which is both
    legal and meaningless.
    """
    if not cfg.dnssd_enabled or msg.qr:
        return []
    q = _question(msg)
    if q is None or q["qtype"] != parse.T_PTR:
        return []
    domain = parse.is_dnssd_meta_query(q["name"].labels)
    if domain is None:
        return []
    if domain.rstrip(".").lower() in ("local", ""):
        return []
    if not table.first_sighting(("DNSD-100", bytes(src_raw), domain), now):
        return []
    return [finding(
        "DNSD-100", domain,
        f"service-type enumeration: PTR query for _services._dns-sd._udp.{domain} from "
        f"{_fmt_addr(src_raw)} -- one question that returns every service type published "
        f"in that zone",
        {"source": _fmt_addr(src_raw), "domain": domain,
         "qname": q["name"].text(), "rfc": "RFC 6763 s9"},
    )]


def detect_dnssd_fanout(msg, cfg, zone):
    """
    DNSD-101. One DNS-SD PTR response carrying an excessive number of
    instance records.

    Two things at once: a small question answered by a large reply is
    an amplification vector, and a large reply to a service-type query
    is what a successful enumeration looks like from the server's side.
    Counted per OWNER NAME rather than per message, because a response
    legitimately answering several different service types should not
    add up into a fan-out that none of them is.
    """
    if not cfg.dnssd_enabled or not msg.qr:
        return []
    per_owner = defaultdict(list)
    for rr in msg.answers:
        if rr.rtype != parse.T_PTR:
            continue
        svc = parse.service_type_of(rr.name)
        if svc is None:
            continue
        per_owner[(tuple(rr.name.lower_labels()), svc)].append(rr)
    out = []
    for (labels, svc), rrs in per_owner.items():
        if len(rrs) <= cfg.dnssd_max_instances:
            continue
        out.append(finding(
            "DNSD-101", zone,
            f"DNS-SD PTR response for {svc} enumerates {len(rrs)} service instances in "
            f"one answer -- an amplification vector, and the shape of an enumeration "
            f"being answered",
            {"service_type": svc, "instances": len(rrs),
             "threshold": cfg.dnssd_max_instances,
             "owner": ".".join(l.decode("ascii", "replace") for l in labels) + "."},
        ))
    return out


# ======================================================================
# TSIG / SIG(0) POSTURE (140-149)
# ======================================================================

def detect_tsig_posture(msg, cfg, zone):
    """
    DNSD-140 and DNSD-141, read off TSIG records this module already
    decodes for DNSD-054 and DNSD-081.

    WHAT CANNOT BE SEEN, and is therefore not claimed: the key. A
    passive sensor has no way to judge whether a shared secret is
    strong, reused across zones, or still the one from the runbook
    nobody has rotated. What it CAN see is the algorithm and the
    replay window, and both are stated in the clear in every signed
    message.

    THE FUDGE IS THE REPLAY WINDOW. RFC 8945 s5.2.1 recommends 300
    seconds, and the field is 16 bits -- so the worst case on the wire
    is 65535 seconds, a little over eighteen hours, not the "a whole
    day" an earlier draft of this comment claimed. The ceiling matters:
    it is what makes this a bounded, checkable posture value rather
    than an open-ended one, and a detector that described an
    impossible figure would have been describing a packet nobody can
    send. (Caught by a fixture: struct refused to pack 86400 into a
    u16.)

    This is the posture check in the pair an operator can actually act
    on, because the fudge is a configuration value rather than a
    property of the key.

    A TIME-SKEW CHECK WAS CONSIDERED AND REJECTED. Comparing a TSIG's
    time_signed against the sensor's own clock would detect replays and
    broken server clocks -- but the reference would be the Pi's clock,
    which is the single thing in the measurement most likely to be
    wrong, and a sensor with drifted NTP would report every signed
    message on the network as skewed. A check whose reference is its
    own weakest link is not worth the alert budget.
    """
    out = []
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_TSIG:
            continue
        p = rr.parsed or {}
        if p.get("struct_error"):
            continue        # DNSD-054's business; fields are untrustworthy
        algo = p.get("algorithm")
        if algo in parse.TSIG_WEAK_ALGOS:
            out.append(finding(
                "DNSD-140", zone,
                f"TSIG for {rr.name.text()} uses {algo}, deprecated for new deployments "
                f"by RFC 8945 s5.2 -- the key itself is unobservable, so this reports the "
                f"algorithm and nothing about the secret's strength",
                {"owner": rr.name.text(), "algorithm": algo, "section": rr.section,
                 "deprecated_by": "RFC 8945 s5.2"},
            ))
        fudge = p.get("fudge")
        if fudge is not None and fudge > cfg.tsig_max_fudge:
            out.append(finding(
                "DNSD-141", zone,
                f"TSIG for {rr.name.text()} carries a fudge of {fudge}s against the "
                f"{parse.TSIG_RECOMMENDED_FUDGE}s RFC 8945 s5.2.1 recommends -- the fudge "
                f"IS the replay window, so a captured signed message stays replayable "
                f"for {fudge}s ({fudge / 3600.0:.1f}h of the 18.2h the 16-bit field "
                f"allows at most)",
                {"owner": rr.name.text(), "fudge": fudge,
                 "recommended": parse.TSIG_RECOMMENDED_FUDGE,
                 "threshold": cfg.tsig_max_fudge, "algorithm": algo,
                 "section": rr.section},
            ))
    return out


def detect_sig0(msg, cfg, zone, table, src_raw, now):
    """
    DNSD-142. A SIG(0) transaction signature (RFC 2931).

    SIG(0) is a SIG record covering type 0 -- it signs the MESSAGE
    rather than an RRset. It was largely abandoned in favour of TSIG
    because it drags public-key management into the transaction path,
    so seeing one is unusual enough to be worth a line and ordinary
    enough not to be an alarm. Notice severity, suppressed per signer.
    """
    out = []
    for rr in msg.all_rrs():
        if rr.rtype != parse.T_SIG:
            continue
        p = rr.parsed or {}
        if p.get("type_covered") != 0:
            continue
        signer = p.get("signer")
        signer_text = signer.text() if signer is not None else rr.name.text()
        if not table.first_sighting(("DNSD-142", bytes(src_raw), signer_text), now):
            continue
        out.append(finding(
            "DNSD-142", zone,
            f"SIG(0) transaction signature from {_fmt_addr(src_raw)}, signer "
            f"{signer_text} -- RFC 2931 rather than TSIG, which is unusual enough to "
            f"note and not in itself a weakness",
            {"source": _fmt_addr(src_raw), "signer": signer_text,
             "algorithm": p.get("algorithm"), "key_tag": p.get("key_tag"),
             "section": rr.section},
        ))
    return out


def _fmt_addr(raw):
    import ipaddress
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return bytes(raw).hex()


# ======================================================================
# ZONE TRANSFER, continued (061-064)
#
# Two of these four are AXFR-ONLY, and the reason is the same both
# times: IXFR is a DIFFERENT protocol with a different RFC, and the
# AXFR rules do not apply to it. Getting that wrong would have
# produced detectors that fire on conforming incremental transfers --
# the same class of error as transferring the mDNS TTL rule to LLMNR.
#
#   RFC 5936 s2.2 (AXFR): intermediate messages MUST NOT contain an
#   SOA; the first message MUST begin with the zone's apex SOA and the
#   last MUST end with the same one.
#
#   RFC 1995 (IXFR): SOA records ARE the delta markers. The RFC's own
#   example response contains SIX of them. An SOA count rule applied
#   to IXFR is guaranteed to be wrong.
#
#   RFC 5936 s4.2 (AXFR): "AXFR sessions over UDP transport are not
#   defined."  RFC 1995 s2 (IXFR): "Transport of a query may be by
#   either UDP or TCP" -- IXFR over UDP is explicitly PERMITTED, and a
#   server that cannot fit the answer replies with a single SOA to say
#   "retry over TCP". So a UDP rule applied to IXFR fires on correct
#   behaviour, and a single-SOA IXFR response is not an incomplete
#   transfer.
# ======================================================================

def _apex_labels(msg, xstream):
    """The transferred zone's apex, from the query name.

    Taken from the QUESTION rather than derived by bailiwick: RFC 5936
    s2.2 requires the first message to copy the query's Question
    section, and the zone being transferred is named there exactly.
    Guessing it any other way would only add a way to be wrong about
    which owner names count as the apex.
    """
    q = _question(msg)
    if q is not None:
        apex = tuple(q["name"].lower_labels())
        if xstream is not None and xstream.apex is None:
            xstream.apex = apex
        return apex
    # Later messages may legally omit the Question, so fall back to the
    # apex this stream already established. Without this the apex
    # checks only ever ran on message one, and a malformed SOA has no
    # reason to arrive there -- the xstream argument was accepted and
    # then ignored, which is the quietest kind of dead parameter.
    if xstream is not None:
        return xstream.apex
    return None


def detect_xfr_completed_disclosure(msg, cfg, zone, xstream, allowed_nets,
                                    client_raw, now, is_tcp):
    """
    DNSD-061. A transfer that COMPLETED to a client outside the
    permitted-secondary list.

    THE COMPLETION IS THE FINDING. An AXFR query is worth nothing on
    its own -- the internet is full of them, and a server with a
    correct ACL answers REFUSED. What matters is a transfer that
    finished, because at that point the entire zone has already been
    handed over and there is nothing to prevent any more. So this is
    read off the terminating SOA, exactly like DNSD-060, and it is
    critical/high for the same reason: a completed disclosure, not an
    attempt.

    COMPLETION IS soa_count >= 2, which works for both forms. A
    single-message AXFR carries the apex SOA as its first and last
    record, so two; a multi-message one carries one in the first
    message and one in the last. An IXFR that fell back to a full
    transfer looks the same. An IXFR that genuinely had deltas carries
    more, which also satisfies it.

    CONFIG-GATED AND SILENT WITHOUT IT. On an ISP's own tap the
    config-free version of this check fires on every legitimate
    transfer between the operator's own nameservers, which is the one
    thing guaranteed to get it switched off in the first hour.
    """
    if not is_tcp or xstream is None or not msg.qr:
        return []
    qtype = xstream.qtype
    if qtype not in (parse.QT_IXFR, parse.QT_AXFR):
        return []
    if msg.rcode != 0:
        # REFUSED / NOTAUTH means the ACL did its job. A rejected
        # transfer says nothing about disclosure.
        return []
    if xstream.soa_count < 2 or xstream.reported_leak:
        return []
    target = client_raw if xstream.client is None else xstream.client
    inside = netscope.in_any_prefix(target, allowed_nets)
    if inside is not False:
        # True  -> a permitted secondary, which is ordinary operation.
        # None  -> undecidable, no prefixes configured. Stay silent.
        return []
    xstream.reported_leak = True
    kind = "IXFR" if qtype == parse.QT_IXFR else "AXFR"
    return [finding(
        "DNSD-061", zone,
        f"{kind} for {zone} COMPLETED to {_fmt_addr(target)}, which is outside every "
        f"configured permitted-secondary prefix -- {xstream.records} records across "
        f"{xstream.messages} message(s); the zone has already been disclosed",
        {"transfer_type": kind, "client": _fmt_addr(target),
         "records": xstream.records, "messages": xstream.messages,
         "soa_records_seen": xstream.soa_count,
         "signed_messages": xstream.signed_messages,
         "configured_prefixes": [str(n) for n in allowed_nets],
         "qname": _qname_text(msg)},
    )]


def detect_ixfr_soa_apex(msg, cfg, zone, xstream, is_tcp=True):
    """
    DNSD-062. CVE-2021-25214 (CVSS 6.5, availability).

    ISC's own description: an incremental transfer stream containing
    "SOA records with an owner name other than the transferred zone's
    apex" causes the receiving server to remove the zone's SOA record,
    and named then terminates on the next SOA refresh query for that
    zone.

    THE OWNER NAME IS THE DISCRIMINATOR, NEVER THE COUNT. IXFR uses
    SOA records as its delta markers -- the RFC 1995 example response
    contains six of them, all at the zone apex -- so any rule that
    counted SOAs in an IXFR would fire on every correct incremental
    transfer. The bug is one SOA in the wrong place in the name tree,
    and that is exactly what is checked.

    IXFR ONLY. A non-apex SOA in an AXFR is also wrong, but it is
    wrong under RFC 5936 rather than under this CVE, and DNSD-063
    reports it there. Keeping them apart means an operator reading
    DNSD-062 knows they are looking at the CVE shape and not at a
    generic structural complaint.

    `PR:L` in the CVE vector means the attacker has to be a source the
    target accepts transfers from. That bounds the likelihood, not the
    detectability -- the same accept call as CVE-2020-8622.
    """
    q = _question(msg)
    qtype = q["qtype"] if q is not None else (xstream.qtype if xstream else None)
    if qtype != parse.QT_IXFR or not msg.qr:
        return []
    apex = _apex_labels(msg, xstream)
    if apex is None:
        # No Question section to establish the apex from. RFC 5936
        # permits later messages to omit it, and without the apex this
        # check cannot be made -- so it is not made, rather than
        # guessed at from the first SOA it happens to see.
        return []
    out = []
    for rr in msg.answers:
        if rr.rtype != parse.T_SOA:
            continue
        if tuple(rr.name.lower_labels()) == apex:
            continue
        out.append(finding(
            "DNSD-062", zone,
            f"IXFR for {zone} carries an SOA record owned by {rr.name.text()}, which is "
            f"not the transferred zone's apex -- the CVE-2021-25214 shape: a receiving "
            f"BIND deletes the zone's own SOA and terminates on its next refresh query",
            {"soa_owner": rr.name.text(), "zone_apex": _labels_text(apex),
             "section": rr.section, "qname": _qname_text(msg),
             "affected": "BIND 9.5.0-9.11.29, 9.12.0-9.16.13, 9.17.0-9.17.11 "
                         "(CVE-2021-25214)"},
        ))
    return out


def detect_axfr_structure(msg, cfg, zone, xstream, is_tcp=True):
    """
    DNSD-063. RFC 5936 s2.2 structure, AXFR only.

    Three violations, all of which a conforming server never produces:

      * an SOA in an INTERMEDIATE message (the first and last may
        carry one; nothing in between may),
      * the first message not BEGINNING with an SOA,
      * an SOA whose owner is not the zone apex.

    AXFR ONLY, and this is the half of the pair that would do real
    damage if it leaked onto IXFR: RFC 1995 makes SOA records the
    delta markers of an incremental transfer, so "an SOA in an
    intermediate message" describes every multi-message IXFR ever
    sent. Conformance asserts a six-SOA IXFR stays silent here.
    """
    if xstream is None:
        return []
    q = _question(msg)
    qtype = q["qtype"] if q is not None else xstream.qtype
    if qtype != parse.QT_AXFR or not msg.qr or msg.rcode != 0:
        return []
    soas = [rr for rr in msg.answers if rr.rtype == parse.T_SOA]
    first_message = not xstream.first_message_done
    apex = _apex_labels(msg, xstream)
    out = []

    if first_message:
        if msg.answers and msg.answers[0].rtype != parse.T_SOA:
            out.append(finding(
                "DNSD-063", zone,
                f"AXFR for {zone} does not begin with an SOA record -- its first answer "
                f"is type {msg.answers[0].rtype}, and RFC 5936 s2.2 requires the first "
                f"message to open with the zone's apex SOA",
                {"violation": "first message does not begin with SOA",
                 "first_record_type": msg.answers[0].rtype,
                 "qname": _qname_text(msg)},
            ))
        elif len(soas) >= 2 and msg.answers[-1].rtype != parse.T_SOA:
            # A SECOND SOA inside the first message with records still
            # after it. RFC 5936 s2.2 allows an SOA only as the very
            # first and very last record of the whole stream, so
            # SOA..SOA..record cannot be conforming however the stream
            # continues.
            #
            # This leg was missing, and it mattered more than it looks:
            # the intermediate-message check below only arms from
            # message two onward, so a SINGLE-message AXFR carrying a
            # mid-stream SOA went unreported -- and a single-message
            # transfer is precisely the case this tier sees reliably,
            # because it is the one that fits inside a TCP segment
            # without the reassembly this module does not have.
            xstream.reported_struct = True
            out.append(finding(
                "DNSD-063", zone,
                f"AXFR for {zone} carries {len(soas)} SOA records in its first message "
                f"with records still following the last of them -- RFC 5936 s2.2 allows "
                f"an SOA only as the very first and very last record of the stream",
                {"violation": "SOA mid-stream in the first message",
                 "soa_records_in_message": len(soas),
                 "last_record_type": msg.answers[-1].rtype,
                 "qname": _qname_text(msg)},
            ))
    elif soas and xstream.soa_count >= 1:
        # An SOA after the opening one, in a message that is neither
        # the first nor provably the last. A conforming server puts
        # exactly one closing SOA at the very end, so this fires only
        # when a second SOA shows up with records still following it.
        trailing = msg.answers[-1].rtype != parse.T_SOA
        if trailing and not xstream.reported_struct:
            xstream.reported_struct = True
            out.append(finding(
                "DNSD-063", zone,
                f"AXFR for {zone} carries an SOA in an intermediate message with records "
                f"still following it -- RFC 5936 s2.2 allows an SOA only as the very "
                f"first and very last record of the whole stream",
                {"violation": "SOA in an intermediate message",
                 "message_number": xstream.messages,
                 "soa_records_in_message": len(soas), "qname": _qname_text(msg)},
            ))

    if apex is not None and not xstream.reported_apex:
        for rr in soas:
            if tuple(rr.name.lower_labels()) == apex:
                continue
            xstream.reported_apex = True
            out.append(finding(
                "DNSD-063", zone,
                f"AXFR for {zone} carries an SOA owned by {rr.name.text()}, which is not "
                f"the transferred zone's apex -- RFC 5936 s2.2 requires the opening and "
                f"closing SOA to be the zone's own",
                {"violation": "SOA owner is not the zone apex",
                 "soa_owner": rr.name.text(), "zone_apex": _labels_text(apex),
                 "qname": _qname_text(msg)},
            ))
            break
    return out


def detect_axfr_over_udp(msg, cfg, zone, is_tcp):
    """
    DNSD-064. RFC 5936 s4.2: "AXFR sessions over UDP transport are not
    defined."

    AXFR ONLY, and the IXFR exclusion here is not a nicety. RFC 1995
    s2 says "Transport of a query may be by either UDP or TCP", and a
    server that cannot fit an incremental answer into a datagram
    replies with a single SOA to tell the client to retry over TCP.
    IXFR over UDP is therefore CORRECT BEHAVIOUR that happens
    constantly, and a UDP rule covering both would have reported it as
    a violation -- which is the same mistake as transferring the mDNS
    TTL requirement to LLMNR, caught the same way, by reading the
    other protocol's RFC instead of assuming it matched.

    Stated precisely: RFC 5936 does not mandate a server response to a
    UDP AXFR, so this is UNDEFINED rather than forbidden. The finding
    is that no conforming client emits it, which makes it a
    reconnaissance or amplification probe rather than a broken
    secondary.
    """
    if is_tcp or msg.qr:
        return []
    q = _question(msg)
    if q is None or q["qtype"] != parse.QT_AXFR:
        return []
    return [finding(
        "DNSD-064", zone,
        f"AXFR query for {zone} arrived over UDP -- RFC 5936 s4.2 leaves AXFR over UDP "
        f"undefined and no conforming client emits it, so this is a probe rather than a "
        f"misconfigured secondary",
        {"qname": q["name"].text(), "qtype": q["qtype"], "transport": "udp",
         "rfc": "RFC 5936 s4.2",
         "note": "IXFR over UDP is explicitly permitted by RFC 1995 s2 and is NOT "
                 "reported"},
    )]


def _labels_text(labels):
    if not labels:
        return "."
    return ".".join(l.decode("ascii", "replace") for l in labels) + "."
