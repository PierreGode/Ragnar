"""
DNS Doctor passive tier -- DDNS leg (RFC 2136 UPDATE, opcode 5).

WHY OPCODE ROUTING IS THE RISKY PART OF THIS TIER, not the detection:
an UPDATE message is wire-identical to a QUERY in its header layout
and REUSES all four section counts with different meanings --

    qdcount -> ZONE          (one record, ZTYPE=SOA)
    ancount -> PREREQUISITE
    nscount -> UPDATE        (the mutations; class NONE/ANY delete)
    arcount -> ADDITIONAL    (TSIG / SIG(0) live here)

so feeding an UPDATE to the ordinary QUERY detectors is the same class
of mistake as feeding mDNS to them, and it goes wrong in the same
direction -- quietly, as a steady drip of plausible findings. Three
concrete ways it would have:

  * DNSD-022 water torture counts NXDOMAIN responses. An UPDATE is
    answered NXDOMAIN (rcode 3) when a prerequisite says "this name
    must exist" and it does not -- a completely routine negative
    answer that has nothing to do with a random-subdomain flood.
  * DNSD-031 measures the source-port entropy of a RESOLVER's
    outbound queries, as a cache-poisoning-resistance posture check.
    Dynamic updaters are not resolvers; mixing their ports into the
    same ring corrupts the measurement rather than adding to it.
  * DNSD-052 counts repeated SOA/CNAME/DNAME records. A bulk UPDATE
    legitimately carries many records for one name.

So UPDATE is routed here and nowhere else. What still runs on an
UPDATE is the OPCODE-INDEPENDENT structural layer -- malformed-packet,
compression-pointer, TSIG structural -- because those judge the wire
encoding itself, which an opcode cannot change.

BOTH POSTURE CODES REPORT AN OUTCOME, NOT AN ATTEMPT. "An unsigned
UPDATE was sent" is worth nothing; every scanner on the internet sends
them. "An unsigned UPDATE was sent AND the server answered NOERROR" is
a writable zone. That sentence needs two packets, which is why this
module is stateful and why both codes are high confidence.
"""
import parse
import netscope
from findings import finding


def is_update(msg):
    """Opcode 5 and nothing else. Checked on the parsed opcode rather
    than inferred from section shape, because an attacker controls the
    section shape and does not control the opcode's meaning."""
    return msg.opcode == parse.OPCODE_UPDATE


def _zone_of_update(msg):
    """The ZONE section name -- NOT a bailiwick computation. RFC 2136
    puts exactly one record there and it names the zone directly, so
    deriving it any other way would only introduce a way to be wrong."""
    if not msg.questions:
        return "."
    return msg.questions[0]["name"].text()


def _tsig_rr(msg):
    """TSIG must be the LAST record in ADDITIONAL (RFC 8945 s5.1), but
    this looks anywhere in the section on purpose: a TSIG in the wrong
    position still proves the sender attempted authentication, and
    treating a misplaced one as absent would turn a signed-but-broken
    update into a false DNSD-080."""
    for rr in msg.additional:
        if rr.rtype == parse.T_TSIG:
            return rr
    return None


def _sig0_rr(msg):
    """SIG(0) is a SIG record covering type 0 -- transaction signature
    rather than an RRset signature (RFC 2931)."""
    for rr in msg.additional:
        if rr.rtype == parse.T_SIG and rr.parsed.get("type_covered") == 0:
            return rr
    return None


def _update_section_summary(msg):
    """Counts of adds versus deletes, from the UPDATE section classes."""
    adds = dels = 0
    names = []
    for rr in msg.authority:
        if rr.rclass in (parse.CLASS_NONE, parse.CLASS_ANY):
            dels += 1
        else:
            adds += 1
        if len(names) < 8:
            names.append(rr.name.text())
    return {"adds": adds, "deletes": dels, "total": len(msg.authority),
            "names": names}


def request_key(msg, src, dst, sport):
    return (msg.txid, bytes(src), bytes(dst), sport)


def response_key(msg, src, dst, dport):
    """A response's destination is the client, so the key is built from
    the reversed 4-tuple to land on the request that produced it."""
    return (msg.txid, bytes(dst), bytes(src), dport)


# ======================================================================
# REQUEST SIDE
# ======================================================================

def handle_update_request(msg, cfg, pending, seen, src, dst, sport, allowed_nets, now):
    """Record the request for later correlation, and run the one check
    that needs no response (DNSD-082)."""
    out = []
    zone = _zone_of_update(msg)
    tsig = _tsig_rr(msg)
    sig0 = _sig0_rr(msg)
    summary = _update_section_summary(msg)

    pending.note_request(request_key(msg, src, dst, sport), {
        "zone": zone,
        "has_tsig": tsig is not None,
        "has_sig0": sig0 is not None,
        "tsig": dict(tsig.parsed) if tsig is not None else None,
        "prereq_count": len(msg.answers),
        "summary": summary,
    }, now)

    inside = netscope.in_any_prefix(src, allowed_nets)
    if inside is False and seen.first_sighting(("DNSD-082", bytes(src)), now):
        out.append(finding(
            "DNSD-082", zone,
            f"dynamic update for {zone} from {_fmt(src)}, which is outside every "
            f"configured permitted-updater prefix",
            {"source": _fmt(src), "zone": zone,
             "signed": tsig is not None or sig0 is not None,
             "update_records": summary["total"],
             "configured_prefixes": [str(n) for n in allowed_nets]},
        ))
    return out


# ======================================================================
# RESPONSE SIDE -- where the verdicts are read
# ======================================================================

def handle_update_response(msg, cfg, pending, seen, src, dst, dport, now):
    out = []
    req = pending.take_response(response_key(msg, src, dst, dport), now)
    if req is None:
        # No matching request means no verdict is available. Reporting
        # anything here would be guessing at what was asked, and a
        # guess is exactly what makes a posture finding worthless.
        return out

    zone = req["zone"] or _zone_of_update(msg)
    accepted = msg.rcode == 0
    resp_tsig = _tsig_rr(msg)

    if not accepted:
        # REFUSED / NOTAUTH / NXRRSET etc. The server rejected it,
        # which is the CORRECT behaviour and the common case. Nothing
        # about a rejected update says anything about posture.
        return out

    # --- DNSD-081: authentication failed but the update was applied ---
    # Checked BEFORE DNSD-080 because an exchange that carried a TSIG
    # is never an "unsigned update" however badly that TSIG fared.
    if req["has_tsig"] or resp_tsig is not None:
        reason, ev = _tsig_bypass_reason(req.get("tsig"), resp_tsig)
        if reason:
            ev.update({"zone": zone, "source": _fmt(dst), "server": _fmt(src),
                       "rcode": msg.rcode,
                       "update_records": req["summary"]["total"],
                       "names": req["summary"]["names"]})
            out.append(finding(
                "DNSD-081", zone,
                f"update to {zone} from {_fmt(dst)} was answered NOERROR although "
                f"{reason} -- the zone was modified without a verified signature",
                ev,
            ))
            return out
        return out

    # --- DNSD-080: no authentication attempted, and it worked ---------
    if req["has_sig0"]:
        return out
    if req["summary"]["total"] == 0:
        # An UPDATE with an EMPTY update section mutates nothing, so a
        # NOERROR proves only that the prerequisites held. RFC 4703
        # DHCP clients send exactly this shape to test name ownership,
        # and they get NOERROR routinely -- without this guard that
        # ordinary probe would read as a writable zone.
        return out
    # Steady-state posture: the answer is the same on every update for
    # the life of the zone, so it is reported once per zone rather than
    # once per packet. A busy DHCP server would otherwise emit this
    # hundreds of times an hour and bury everything else.
    if not seen.first_sighting(("DNSD-080", zone), now):
        return out
    out.append(finding(
        "DNSD-080", zone,
        f"UPDATE to {zone} from {_fmt(dst)} carried no TSIG and no SIG(0) and was "
        f"answered NOERROR by {_fmt(src)} -- {req['summary']['adds']} add(s) and "
        f"{req['summary']['deletes']} delete(s) were accepted unauthenticated",
        {"zone": zone, "source": _fmt(dst), "server": _fmt(src),
         "adds": req["summary"]["adds"], "deletes": req["summary"]["deletes"],
         "names": req["summary"]["names"], "prerequisites": req["prereq_count"]},
    ))
    return out


def _tsig_bypass_reason(req_tsig, resp_tsig):
    """Why this signed exchange counts as a bypass, or (None, {}).

    THE THREE OBSERVABLE SHAPES. A passive sensor cannot verify a MAC
    -- it does not have the key and never will. What it CAN see is the
    server contradicting itself, and that is enough:

      1. The response's own TSIG error field says BADSIG / BADKEY /
         BADTIME while the message rcode says NOERROR. The server is
         reporting that verification failed and that it applied the
         update anyway. Correct servers answer NOTAUTH (9) here, which
         is why rcode 0 is required before this is even consulted.
      2. The request's MAC is empty (size 0) and the update succeeded.
      3. The request's MAC is truncated below the RFC 8945 s5.2 floor
         -- half the digest length, never under 80 bits -- and the
         update succeeded. gss-tsig is excluded from the truncation
         rule in the parser, since its MAC length is genuinely
         variable.
    """
    if resp_tsig is not None:
        p = resp_tsig.parsed
        name = p.get("error_name")
        if name:
            return (f"the response's own TSIG reports {name}",
                    {"tsig_error": p.get("error"), "tsig_error_name": name,
                     "tsig_algorithm": p.get("algorithm")})
    if req_tsig:
        if req_tsig.get("mac_empty"):
            return ("the request's TSIG carried a zero-length MAC",
                    {"mac_size": 0, "tsig_algorithm": req_tsig.get("algorithm")})
        if req_tsig.get("mac_truncated"):
            return (f"the request's TSIG MAC was truncated to "
                    f"{req_tsig.get('mac_size')} bytes, below the "
                    f"{req_tsig.get('mac_floor')}-byte RFC 8945 floor for "
                    f"{req_tsig.get('algorithm')}",
                    {"mac_size": req_tsig.get("mac_size"),
                     "mac_floor": req_tsig.get("mac_floor"),
                     "mac_full": req_tsig.get("mac_full"),
                     "tsig_algorithm": req_tsig.get("algorithm")})
    return (None, {})


def _fmt(raw):
    ip = netscope._ip_or_none(raw)
    return str(ip) if ip is not None else repr(raw)


# ======================================================================
# ENTRY POINT
# ======================================================================

def handle_ddns(msg, cfg, pending, seen, src, dst, sport, dport, allowed_nets, now):
    if not cfg.ddns_enabled:
        return []
    if msg.qr:
        return handle_update_response(msg, cfg, pending, seen, src, dst, dport, now)
    return handle_update_request(msg, cfg, pending, seen, src, dst, sport,
                                 allowed_nets, now)
