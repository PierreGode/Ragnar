"""
DNS Doctor passive tier -- rDNS leg (PTR / reverse DNS).

NO CVE TIER HERE, DELIBERATELY. There is no PTR-specific CVE set at
CVSS 6.5 or above worth a detector: the recurring "PTR record carrying
CRLF or shell metacharacters to break a log parser" family is a bug in
whatever consumes the record, not in DNS, and the malformed-record
shape it produces is already DNSD-007's job. So this leg is two
posture checks and nothing else.

Both are dual-stack, but in opposite ways, and the asymmetry is the
point rather than a gap:

  DNSD-090 is dual-stack BY SUBJECT -- it covers in-addr.arpa and
  ip6.arpa with one code path, because a leaked 10.0.0.0/8 reverse
  query and a leaked fd00::/8 one are the same mistake.

  DNSD-091 is IPv6-only by subject and dual-stack by TRANSPORT. The
  v4 analogue was considered and rejected: enumerating in-addr.arpa
  needs no RFC 8020 inference at all, because v4 reverse space is
  small enough to walk directly, so there is no "walk" signature
  distinguishable from ordinary scanning. In v6 the inference IS the
  attack -- the address space is unenumerable, and the NXDOMAIN
  versus empty-non-terminal distinction is the only thing that makes
  host discovery tractable. Reporting a v4 variant would mean
  inventing a threshold for background noise.
"""
import ipaddress

import parse
import netscope
from findings import finding

V4_ARPA = (b"in-addr", b"arpa")
V6_ARPA = (b"ip6", b"arpa")


def reverse_suffix(labels):
    """'v4', 'v6' or None, from the trailing labels of a qname."""
    if len(labels) < 2:
        return None
    tail = (labels[-2].lower(), labels[-1].lower())
    if tail == V4_ARPA:
        return "v4"
    if tail == V6_ARPA:
        return "v6"
    return None


def reverse_name_to_network(labels):
    """
    Turn a reverse qname's labels into the network it names, or None.

    PARTIAL NAMES ARE NORMAL AND MUST WORK: '10.in-addr.arpa' is a
    zone, '1.0.0.10.in-addr.arpa' is a host, and both leak the same
    fact. So the label count becomes the prefix length rather than
    being required to be full -- a detector that only understood
    complete addresses would miss every SOA and NS query for a private
    reverse zone, which is the form a misconfigured resolver actually
    emits when it is hunting for a delegation.
    """
    kind = reverse_suffix(labels)
    if kind is None:
        return None
    body = labels[:-2]
    if not body:
        return None
    try:
        if kind == "v4":
            octets = [int(l) for l in reversed(body)]
            if len(octets) > 4 or any(o < 0 or o > 255 for o in octets):
                return None
            prefix = 8 * len(octets)
            octets += [0] * (4 - len(octets))
            addr = ipaddress.IPv4Address(bytes(octets))
            return ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        nibbles = [l.decode("ascii") for l in reversed(body)]
        if len(nibbles) > 32:
            return None
        for n in nibbles:
            if len(n) != 1 or n.lower() not in "0123456789abcdef":
                return None
        prefix = 4 * len(nibbles)
        hexstr = "".join(nibbles) + "0" * (32 - len(nibbles))
        addr = ipaddress.IPv6Address(bytes.fromhex(hexstr))
        return ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    except (ValueError, UnicodeDecodeError):
        return None


# ======================================================================
# DNSD-090 -- private reverse zone leaving for a public resolver
# ======================================================================

def detect_ptr_private_leak(msg, cfg, src, dst, internal_nets, now, seen):
    """
    A reverse query for private, CGNAT, link-local or ULA space
    addressed to a resolver OUTSIDE the operator's own prefixes.

    WHY THE DESTINATION IS THE TEST. A passive tap has no idea which
    way is "out" -- it sees a frame, not a routing table. Every
    internal resolver legitimately answers private reverse queries for
    its own ranges all day, so a direction-free version of this check
    would fire on ordinary business on an ISP's own resolver tap and be
    switched off within the hour. The destination being outside the
    configured internal prefixes is what makes it a leak, and without
    that configuration this check says nothing at all.

    QTYPE IS NOT RESTRICTED TO PTR. The leak is the NAME: asking a
    public resolver for the SOA of 10.in-addr.arpa discloses the same
    internal addressing as asking for a PTR inside it, and a
    misconfigured resolver hunting for a delegation emits SOA and NS,
    not PTR.
    """
    if not cfg.rdns_enabled or msg.qr:
        return []
    q = msg.questions[0] if msg.questions else None
    if q is None:
        return []
    net = reverse_name_to_network(q["name"].labels)
    if net is None:
        return []
    if not netscope.is_private_space(net.network_address):
        return []
    if netscope.in_any_prefix(dst, internal_nets) is not False:
        # True -> an internal resolver, which is correct behaviour.
        # None -> undecidable (no prefixes); stay silent.
        return []
    dst_s = _fmt(dst)
    if not seen.first_sighting(("DNSD-090", bytes(dst), str(net)), now):
        return []
    sink = dst_s in netscope.AS112_SINKS
    return [finding(
        "DNSD-090", q["name"].text(),
        f"reverse query for {net} ({'IPv6 ULA/link-local' if net.version == 6 else 'private/CGNAT IPv4'}) "
        f"sent from {_fmt(src)} to {dst_s}, which is outside every configured internal prefix"
        + (" -- an AS112 sink, so the leak is already reaching the public tree" if sink else ""),
        {"qname": q["name"].text(), "network": str(net), "qtype": q["qtype"],
         "source": _fmt(src), "destination": dst_s, "as112_sink": sink,
         "family": net.version},
    )]


# ======================================================================
# DNSD-091 -- ip6.arpa tree enumeration
# ======================================================================

def nibble_path(labels):
    """Most-significant-first nibble tuple for an ip6.arpa name.

    ip6.arpa is nibble-REVERSED, so the leading labels are the least
    significant nibbles and the network prefix is at the far end. The
    tuple is reversed back into network order here so that a shared
    leading run of this tuple means a shared DELEGATION -- which is the
    quantity the detector keys on. Getting this backwards would make
    the common-prefix test compare host nibbles instead, and it would
    then group together addresses that share nothing but a last digit.
    """
    if reverse_suffix(labels) != "v6":
        return None
    body = labels[:-2]
    if not body:
        return None
    out = []
    for l in reversed(body):
        if len(l) != 1:
            return None
        c = l.decode("ascii", "replace").lower()
        if c not in "0123456789abcdef":
            return None
        out.append(c)
    return tuple(out)


def detect_ip6_arpa_walk(msg, cfg, walks, src, now):
    """
    Reverse-tree enumeration of ip6.arpa by one source.

    FIXED THRESHOLDS, NO LEARNED BASELINE -- and that is why this ships
    on by default while the three rate-baseline detectors ship off. A
    baseline exists to answer "is this rate unusual FOR THIS ZONE",
    which is a real question for NXDOMAIN volume and a meaningless one
    here: scores of distinct ip6.arpa names from a single source inside
    a minute is anomalous on every network that exists. A baseline
    would add nothing except a warmup window a grab-and-go sensor
    cannot assume.

    THE COMMON-PREFIX REQUIREMENT IS THE FALSE-POSITIVE CONTROL, and
    it carries the whole check. Count and distinctness alone would
    fire on a busy mail server, which legitimately resolves many
    distinct ip6.arpa names -- that is what rDNS checks on inbound mail
    ARE. The difference is shape, not volume: a walk descends ONE
    delegation and so its queries share a long leading nibble run,
    while a mail server's lookups are scattered across unrelated /32s
    and their common run collapses to nothing after a handful. The
    running intersection in WalkState can only shrink, so a scattered
    source can never climb back to the threshold.
    """
    if not cfg.rdns_enabled or not cfg.ip6_walk_enabled or msg.qr:
        return []
    q = msg.questions[0] if msg.questions else None
    if q is None:
        return []
    path = nibble_path(q["name"].labels)
    if path is None:
        return []

    st = walks.get(bytes(src), now)
    st.observe(path, now, cfg.ip6_walk_window_seconds)
    if st.reported:
        return []
    if st.count < cfg.ip6_walk_min_queries:
        return []
    ratio = st.distinct_ratio()
    if ratio < cfg.ip6_walk_min_distinct_ratio:
        return []
    common = len(st.common or ())
    if common < cfg.ip6_walk_min_common_nibbles:
        return []

    st.reported = True
    prefix = _nibbles_to_prefix(st.common)
    return [finding(
        "DNSD-091", prefix,
        f"{_fmt(src)} issued {st.count} ip6.arpa queries in "
        f"{cfg.ip6_walk_window_seconds:.0f}s, {ratio:.0%} of them distinct, all sharing "
        f"the leading {common} nibbles ({prefix}) -- reverse-tree enumeration of that "
        f"delegation, not bulk reverse lookup",
        {"source": _fmt(src), "queries": st.count,
         "distinct_ratio": round(ratio, 3), "common_nibbles": common,
         "common_prefix": prefix, "window_seconds": cfg.ip6_walk_window_seconds,
         "last_qname": q["name"].text()},
    )]


def _nibbles_to_prefix(nibbles):
    """Render a nibble run as a readable IPv6 prefix."""
    if not nibbles:
        return "::/0"
    hexstr = "".join(nibbles) + "0" * (32 - len(nibbles))
    addr = ipaddress.IPv6Address(bytes.fromhex(hexstr))
    return f"{addr}/{4 * len(nibbles)}"


def _fmt(raw):
    ip = netscope._ip_or_none(raw)
    return str(ip) if ip is not None else repr(raw)


def handle_rdns(msg, cfg, walks, seen, src, dst, internal_nets, now):
    out = []
    out += detect_ptr_private_leak(msg, cfg, src, dst, internal_nets, now, seen)
    out += detect_ip6_arpa_walk(msg, cfg, walks, src, now)
    return out
