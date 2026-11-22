"""
Address-scope predicates shared by the mDNS, DDNS and rDNS tiers.

WHY THIS IS ONE MODULE AND NOT THREE COPIES: three tiers now ask a
variant of "is this address inside a set the operator named", and
bailiwick.py already set the precedent in this module -- two detectors
with two implementations of the same predicate is the LESSON A shape,
where both copies share a blind spot and no test can see it because
the test exercises whichever copy it imported.

The three tiers differ in WHICH set they ask about, not in how
membership is decided, so the set stays per-tier config and the
decision lives here exactly once.
"""
import ipaddress

# RFC 1918 / RFC 6598 / RFC 3927 / RFC 4193 / RFC 4291 -- the space
# whose reverse zones must never be asked of a public resolver.
#
# 100.64/10 (CGNAT) is in the list for a reason specific to an ISP:
# it is the one range here that an operator may be using as GLOBAL
# customer-facing space, and its reverse delegation still does not
# exist in the public tree. 0.0.0.0/8 and 240/4 are left out: they
# are not addresses anything reverse-resolves.
PRIVATE_V4 = tuple(ipaddress.ip_network(c) for c in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10", "169.254.0.0/16",
))
PRIVATE_V6 = tuple(ipaddress.ip_network(c) for c in (
    "fc00::/7",        # ULA; fd00::/8 is the assigned half
    "fe80::/10",       # link-local
))

# The AS112 anycast sinks, which exist only to absorb exactly the
# queries DNSD-090 reports. Seeing one as the DESTINATION is not the
# finding -- the finding is the query leaving at all -- but naming
# them in the evidence tells an operator the leak is already landing
# somewhere public rather than being dropped.
AS112_SINKS = frozenset({
    "192.175.48.1", "192.175.48.6", "192.175.48.42",
    "199.7.91.13",
    "2620:4f:8000::1", "2620:4f:8000::6", "2620:4f:8000::42",
})


def parse_prefixes(values):
    """Turn operator-supplied CIDR strings into network objects once,
    at load, rather than per packet. Bad entries are dropped loudly
    instead of silently disabling a detector."""
    nets, bad = [], []
    for v in values or ():
        try:
            nets.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            bad.append(v)
    return nets, bad


def in_any_prefix(raw_addr, networks):
    """True / False / None, where None means UNDECIDABLE.

    None is returned when no prefixes are configured or the bytes are
    not an address. Every caller must treat None as "say nothing",
    never as False -- the whole reason these checks are config-gated is
    that the config-free guess is wrong on the networks they run on.
    """
    if not networks:
        return None
    ip = _ip_or_none(raw_addr)
    if ip is None:
        return None
    for net in networks:
        if ip.version == net.version and ip in net:
            return True
    return False


def _ip_or_none(raw_addr):
    try:
        if isinstance(raw_addr, (bytes, bytearray)):
            return ipaddress.ip_address(bytes(raw_addr))
        return ipaddress.ip_address(raw_addr)
    except ValueError:
        return None


def is_private_space(ip):
    """Membership in the private/CGNAT/link-local/ULA set above.

    Deliberately NOT ipaddress.is_private. Python's is_private also
    covers the RFC 5737 documentation ranges (192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24) and the benchmarking range, none
    of which are private addressing -- and an earlier mDNS build had a
    mutation survive the whole suite precisely because a fixture used
    203.0.113.x and Python agreed with the wrong code about it
    (LESSON K). An explicit list cannot drift that way.
    """
    if ip is None:
        return False
    table = PRIVATE_V4 if ip.version == 4 else PRIVATE_V6
    return any(ip in net for net in table)
