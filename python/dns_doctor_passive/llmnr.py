"""
DNS Doctor passive tier -- LLMNR leg (RFC 4795, UDP/TCP 5355).

NO CVE TIER, and that is a verified verdict rather than an omission.
The LLMNR weaknesses that matter are protocol DESIGN -- it is
unauthenticated by construction, so whoever answers first wins -- and
a CVE search turned up no qualifying LLMNR-specific implementation
set. So this is posture, the same honest shape as the rDNS leg.

BOUNDARY WITH smbwatch, applying the precedent already set for mDNS:
smbwatch owns LLMNR/NBT-NS name POISONING (Responder, Inveigh). This
tier never judges whether an LLMNR answer is legitimate. It reports
that the protocol is in use, that a transport rule was broken, and
what is being asked for. Both modules see the same packets; only one
reports spoofing, so there is no double alert.

THE RULE THAT DOES NOT TRANSFER FROM mDNS. DNSD-074 reports any mDNS
packet whose TTL is not 255, because RFC 6762 s11 makes that a MUST.
RFC 4795 s2.5 says the LLMNR TTL "MAY be set to any value" and merely
RECOMMENDS 255 for compatibility with early RFC 3927 implementations.
So there is deliberately NO TTL check here: it would fire on
conforming traffic. What LLMNR does constrain is the DESTINATION -- a
query sent to any multicast address other than its two groups MUST be
silently discarded -- and that is DNSD-111.
"""
import parse
from findings import finding


def _addr(raw):
    import ipaddress
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return bytes(raw).hex()


def _qname(msg):
    q = msg.questions[0] if msg.questions else None
    return q["name"] if q else None


# ======================================================================
# DNSD-110 -- the protocol is in use at all
# ======================================================================

def detect_llmnr_in_use(msg, cfg, table, src_raw, now):
    """
    Presence is the finding.

    Unlike every other posture check in this module, this one does not
    look at the packet's contents. LLMNR has no authentication by
    design, Microsoft's own guidance is to disable it, and nothing on a
    managed network requires it -- so "a conforming LLMNR packet" and
    "a malicious LLMNR packet" are the same finding at this level, and
    the useful report is which hosts are still speaking it.

    Suppressed per source, so a chatty host produces one line rather
    than one per name it fails to resolve.
    """
    if not cfg.llmnr_enabled:
        return []
    if not table.first_sighting(("DNSD-110", bytes(src_raw)), now):
        return []
    n = _qname(msg)
    return [finding(
        "DNSD-110", "llmnr.",
        f"LLMNR in use by {_addr(src_raw)}"
        + (f" (asking for {n.text()})" if n is not None else "")
        + " -- unauthenticated by design and recommended for disabling; "
          "the finding is that it is enabled, not that this packet is bad",
        {"source": _addr(src_raw), "qname": n.text() if n is not None else None,
         "qr": bool(msg.qr),
         "note": "name poisoning on this protocol is smbwatch's half"},
    )]


# ======================================================================
# DNSD-111 -- the one transport rule LLMNR actually has
# ======================================================================

def detect_wrong_group(msg, cfg, src_raw, dst_raw):
    """
    RFC 4795 s2: a query sent to a multicast address other than
    224.0.0.252 or ff02::1:3 MUST be silently discarded.

    Only MULTICAST destinations are judged. LLMNR legitimately travels
    unicast as well -- RFC 4795 has responders listening on TCP 5355
    for unicast queries, and a unicast UDP response goes straight back
    to the querier -- so treating any non-group destination as a
    violation would fire on every correct response on the link.
    """
    if not cfg.llmnr_enabled:
        return []
    if not _is_multicast(dst_raw):
        return []
    if parse.is_llmnr_group(bytes(dst_raw)):
        return []
    n = _qname(msg)
    return [finding(
        "DNSD-111", "llmnr.",
        f"LLMNR packet from {_addr(src_raw)} addressed to {_addr(dst_raw)}, which is "
        f"neither 224.0.0.252 nor ff02::1:3 -- RFC 4795 s2 requires a responder to "
        f"discard this, so a conforming sender never emits it",
        {"source": _addr(src_raw), "destination": _addr(dst_raw),
         "qname": n.text() if n is not None else None,
         "expected": ["224.0.0.252", "ff02::1:3"]},
    )]


def _is_multicast(raw):
    import ipaddress
    try:
        ip = ipaddress.ip_address(bytes(raw))
    except ValueError:
        return False
    return ip.is_multicast


# ======================================================================
# DNSD-112 -- WPAD over LLMNR
# ======================================================================

def detect_wpad(msg, cfg, table, src_raw, now):
    """
    A host asking for WPAD over LLMNR will take its web-proxy
    configuration from whoever answers first.

    QUERIES ONLY. The vulnerable state is the question -- it proves the
    host is configured for proxy auto-discovery and will fall back to
    link-local name resolution to find it. The poisoned ANSWER is the
    attack, and that belongs to smbwatch. Reporting both halves here
    would double-alert on one event.
    """
    if not cfg.llmnr_enabled or msg.qr:
        return []
    n = _qname(msg)
    if n is None or not n.labels:
        return []
    if n.labels[0].lower() != b"wpad":
        return []
    if not table.first_sighting(("DNSD-112", bytes(src_raw)), now):
        return []
    return [finding(
        "DNSD-112", "llmnr.",
        f"{_addr(src_raw)} asked for WPAD over LLMNR -- it is configured for web-proxy "
        f"auto-discovery and will accept a proxy configuration from the first responder "
        f"on this link",
        {"source": _addr(src_raw), "qname": n.text(),
         "note": "the query is the vulnerable state; the poisoned answer is smbwatch's"},
    )]


def handle_llmnr(msg, cfg, table, src_raw, dst_raw, now):
    out = []
    out += detect_llmnr_in_use(msg, cfg, table, src_raw, now)
    out += detect_wrong_group(msg, cfg, src_raw, dst_raw)
    out += detect_wpad(msg, cfg, table, src_raw, now)
    return out
