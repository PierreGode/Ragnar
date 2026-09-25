"""
Shared bailiwick checker -- used by BOTH the NXNSAttack detector
(DNSD-004/005, glue validation) and the MaginotDNS detector
(DNSD-006, out-of-zone record injection).

Deliberately ONE implementation. Two detectors asking the same
question ("is this name inside that zone?") with two implementations
is the LESSON A failure shape waiting to happen: they can disagree,
and whichever is wrong is wrong silently.

The rule, per RFC 2181 s5.4.1 ranking: a record is in bailiwick of a
zone if its owner name is the zone itself or a subdomain of it.
Comparison is case-insensitive on labels (DNS names are
case-insensitive but case-PRESERVING, so raw bytes must not be
compared directly) and label-wise, never by string suffix --
"notexample.com" is NOT inside "example.com" but a naive
str.endswith() says it is.
"""


def normalize(name):
    """Name object or list of label bytes -> tuple of lowercase labels."""
    if hasattr(name, "lower_labels"):
        return tuple(name.lower_labels())
    if isinstance(name, str):
        s = name.rstrip(".")
        if not s:
            return ()
        return tuple(l.lower().encode("ascii", "replace") for l in s.split("."))
    return tuple(l.lower() for l in name)


def is_subdomain_of(child, parent):
    """True if `child` is `parent` or below it. Root is the parent of
    everything, including itself."""
    c, p = normalize(child), normalize(parent)
    if len(p) == 0:
        return True
    if len(c) < len(p):
        return False
    return c[len(c) - len(p):] == p


def in_bailiwick(rr_name, zone):
    return is_subdomain_of(rr_name, zone)


def zone_of_query(qname, min_labels=2):
    """
    Best-effort zone for a query name, used to key per-zone state.

    A passive observer does NOT know the real zone cut -- that needs
    the delegation chain. This takes the registrable-ish suffix
    (default: last two labels) as a STABLE GROUPING KEY, not as a
    claim about where the zone cut is. Detectors that need true
    bailiwick use in_bailiwick() against the QUESTION name instead;
    this is only for bucketing per-zone counters.

    Deliberately NOT a public-suffix list: a PSL is a ~10k-entry
    download that goes stale, and being wrong about co.uk changes
    which BUCKET a counter lands in, not whether a structural finding
    fires. No structural detector depends on this.
    """
    labels = normalize(qname)
    if len(labels) <= min_labels:
        return b".".join(labels).decode("ascii", "replace") or "."
    return b".".join(labels[-min_labels:]).decode("ascii", "replace")


def out_of_bailiwick_rrs(msg, zone, sections=("authority", "additional")):
    """
    Every RR in the named sections whose owner name falls outside
    `zone`. This is MaginotDNS's core test.

    Two legitimate exceptions are excluded rather than reported:
      - OPT pseudo-records (type 41) always have an empty owner name
        and are not zone data at all.
      - The root itself as an owner name (referrals to the root).
    """
    out = []
    for rr in msg.all_rrs():
        if rr.section not in sections:
            continue
        if rr.rtype == 41:
            continue
        if len(normalize(rr.name)) == 0:
            continue
        if not in_bailiwick(rr.name, zone):
            out.append(rr)
    return out
