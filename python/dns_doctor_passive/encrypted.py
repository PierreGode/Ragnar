"""
DNS Doctor passive tier -- encrypted-DNS transport leg.

THE README USED TO CALL DoT/DoH AN HONEST ZERO, and half of that
stands. Nothing INSIDE an encrypted transport is parseable and never
will be: there are no records to read, so there is no detector to
write. That half has not changed.

What changed is noticing that the other half is a different question.
Detecting the TRANSPORT is entirely possible, and for anyone running
their own resolvers it is operational rather than academic: DoT, DoQ
and DoH past your resolver bypass its logging, its RPZ and its
filtering. "Which of my clients have stopped using my resolver" is a
DNS posture question that a passive tap can answer.

FOUR SIGNALS, ALL DNS-NATIVE OR PORT-NATIVE:

  DoT  TCP 853 (RFC 7858)            -- port
  DoQ  UDP 853 (RFC 9250)            -- port plus a QUIC long header
  DDR  SVCB for _dns.resolver.arpa   -- cleartext on port 53
  DoH  the cleartext lookup of a known provider hostname

DoH ON 443 IS DELIBERATELY ABSENT. It is identifiable only from the
TLS SNI, and tlswatch already parses TLS and QUIC handshakes. A second
ClientHello parser here would be the LESSON A shape exactly: two
hand-rolled implementations of one thing, sharing a blind spot that
neither module's tests can see, because each exercises its own copy.
So DNSD-133 reports the DNS-visible precursor and emits a CORRELATION
RECORD for tlswatch to join a later TLS session against -- client,
hostname and the answer addresses, which is everything needed to
match a session to a provider without this module knowing what a
ClientHello is.
"""
import parse
import netscope
from findings import finding


def _addr(raw):
    import ipaddress
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return bytes(raw).hex()


def _scope(raw, own_nets):
    """True inside the operator's own resolvers, False outside, None
    undecidable. None is a real answer and is reported as one -- the
    config-free guess here would be 'a public address means bypass',
    which is wrong on a network whose own resolvers are publicly
    addressed. That is every ISP."""
    return netscope.in_any_prefix(raw, own_nets)


def _verdict(inside):
    if inside is True:
        return "to your own resolver, which is the good case"
    if inside is False:
        return "PAST your own resolvers, so its queries are invisible to them"
    return "destination not classifiable -- no own-resolver prefixes configured"


# ======================================================================
# DNSD-130 / DNSD-131 -- the transports themselves
# ======================================================================

def detect_encrypted_session(cfg, table, src_raw, dst_raw, sport, dport,
                             proto, payload, own_nets, now):
    """
    A session on port 853.

    NOTHING IS PARSED out of it, and the finding says so. The session's
    existence and its endpoints are the entire evidence, which is why
    these are notice-severity census codes rather than alarms: an
    encrypted resolver session is not a vulnerability, it is a fact
    about where DNS is going.

    DoQ IS CONFIRMED BY A QUIC LONG HEADER, not by the port alone.
    UDP 853 is assigned to DoQ, but assigned is not the same as
    occupied, and reporting arbitrary UDP as a DNS transport on the
    strength of a port number is how a census becomes untrustworthy.
    """
    if not cfg.encrypted_dns_enabled:
        return []
    server_is_dst = dport == parse.DOT_PORT
    server, client = ((dst_raw, src_raw) if server_is_dst else (src_raw, dst_raw))

    if proto == "tcp":
        code, label, rfc = "DNSD-130", "DNS-over-TLS", "RFC 7858"
    else:
        if not parse.is_quic_long_header(payload):
            # UDP 853 that is not QUIC. Could be anything; saying
            # nothing is better than saying DoQ.
            return []
        code, label, rfc = "DNSD-131", "DNS-over-QUIC", "RFC 9250"

    key = (code, bytes(client), bytes(server))
    if not table.first_sighting(key, now):
        return []
    inside = _scope(server, own_nets)
    return [finding(
        code, "encrypted-dns.",
        f"{label} session ({rfc}) from {_addr(client)} to {_addr(server)} -- "
        f"{_verdict(inside)}",
        {"client": _addr(client), "server": _addr(server),
         "transport": "tcp/853" if proto == "tcp" else "udp/853",
         "inside_own_resolvers": inside,
         "configured_prefixes": [str(n) for n in own_nets],
         "note": "the transport is observable; its contents are not, and never will be"},
    )]


# ======================================================================
# DNSD-132 -- DDR / DNR discovery (RFC 9462 / RFC 9463)
# ======================================================================

def detect_ddr_discovery(msg, cfg, table, src_raw, dst_raw, now):
    """
    A client probing for an encrypted-DNS endpoint to upgrade to.

    This is the signal that makes the whole leg work from inside DNS:
    the probe for encrypted DNS travels in CLEARTEXT on port 53,
    because it has to -- the client does not yet know where the
    encrypted endpoint is. So the intent to leave is visible even
    though the departure is not.

    SVCB QUERIES ONLY. `_dns` is a legal DNS-SD service label, so
    matching the leading label alone would catch ordinary service
    discovery. Requiring QTYPE SVCB narrows it to the DDR shape, and
    `resolver.arpa` is matched in full.
    """
    if not cfg.encrypted_dns_enabled or msg.qr:
        return []
    q = msg.questions[0] if msg.questions else None
    if q is None or q["qtype"] not in (parse.T_SVCB, parse.T_HTTPS):
        return []
    target = parse.is_ddr_query_name(q["name"].labels)
    if target is None:
        return []
    key = ("DNSD-132", bytes(src_raw), target)
    if not table.first_sighting(key, now):
        return []
    well_known = target == "resolver.arpa"
    return [finding(
        "DNSD-132", "encrypted-dns.",
        f"{_addr(src_raw)} issued an SVCB query for _dns.{target} -- "
        + ("the RFC 9462 well-known DDR name" if well_known
           else "an RFC 9463 network-designated resolver name")
        + ", so it is probing to upgrade itself off cleartext DNS",
        {"source": _addr(src_raw), "destination": _addr(dst_raw),
         "qname": q["name"].text(), "qtype": q["qtype"],
         "discovery_target": target, "well_known": well_known,
         "rfc": "RFC 9462 (DDR)" if well_known else "RFC 9463 (DNR)"},
    )]


# ======================================================================
# DNSD-133 -- the cleartext lookup that precedes a DoH session
# ======================================================================

def detect_doh_endpoint(msg, cfg, table, src_raw, dst_raw, now):
    """
    A cleartext query for a known public DoH resolver's hostname.

    WHY A PROVIDER LIST AND NOT A HEURISTIC. There is no way to
    recognise a private DoH endpoint from a DNS query -- `doh.acme.net`
    looks exactly like `www.acme.net`. A heuristic would either miss
    those anyway or guess, and a guessing posture check on an ISP's
    own resolver tap is one that gets switched off. So the list is the
    known public providers, the limitation is stated, and nothing
    pretends to be complete.

    THE CORRELATION RECORD is the part that closes the gap. This module
    does not parse TLS and must not start: tlswatch already does, and a
    second ClientHello parser would be two implementations of one
    thing sharing a blind spot. Instead the finding carries the client,
    the hostname and the ANSWER ADDRESSES, which is exactly what
    tlswatch needs to match a later session on 443 to this provider --
    one module reads DNS, the other reads TLS, and the join happens
    where the two findings meet rather than inside either parser.
    """
    if not cfg.encrypted_dns_enabled:
        return []
    q = msg.questions[0] if msg.questions else None
    if q is None:
        return []
    if q["qtype"] not in (parse.T_A, parse.T_AAAA, parse.T_HTTPS, parse.T_SVCB):
        return []
    host = q["name"].text().rstrip(".").lower()
    if host not in parse.DOH_PROVIDER_HOSTS:
        return []

    # Answer addresses, when this is the response half. They are what
    # makes the correlation record actionable.
    addrs = []
    for rr in msg.answers:
        if rr.rtype == parse.T_A and len(rr.rdata) == 4:
            addrs.append(_addr(rr.rdata))
        elif rr.rtype == parse.T_AAAA and len(rr.rdata) == 16:
            addrs.append(_addr(rr.rdata))

    # Keyed WITHOUT the addresses: a provider's anycast set rotates,
    # and keying on it would re-report the same client every time a
    # different edge answered.
    client = dst_raw if msg.qr else src_raw
    key = ("DNSD-133", bytes(client), host)
    if not table.first_sighting(key, now):
        return []
    return [finding(
        "DNSD-133", "encrypted-dns.",
        f"{_addr(client)} resolved {host}, a known public DoH resolver -- the step "
        f"before an encrypted session this sensor cannot read"
        + (f"; it answers at {', '.join(addrs)}" if addrs else ""),
        {"client": _addr(client), "hostname": host, "qtype": q["qtype"],
         "answer_addresses": addrs,
         # For tlswatch to join against. DoH on 443 is identifiable
         # only from the SNI, which this module deliberately does not
         # parse.
         "correlation": {"join": "tls_sni", "sni": host,
                         "client": _addr(client), "addresses": addrs},
         "note": "known-provider list, not a heuristic: a private DoH endpoint is "
                 "indistinguishable from any other hostname in a DNS query"},
    )]


def handle_encrypted_dns_query(msg, cfg, table, src_raw, dst_raw, now):
    """The two port-53 signals, run on ordinary cleartext DNS."""
    out = []
    out += detect_ddr_discovery(msg, cfg, table, src_raw, dst_raw, now)
    out += detect_doh_endpoint(msg, cfg, table, src_raw, dst_raw, now)
    return out
