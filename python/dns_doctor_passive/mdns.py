"""
DNS Doctor mDNS tier (RFC 6762 multicast DNS / RFC 6763 DNS-SD).

TWO LEGS, kept separate because they answer different questions:

  CENSUS (DNSD-070..073) -- what Matter and Thread infrastructure
  exists on this LAN. Informational, never an alarm. This exists
  because Ragnar can see Zigbee, Z-Wave, LoRaWAN, Wi-Fi HaLow,
  MeshCore, Meshtastic, BLE and Classic, but had no way to know
  Matter existed at all. Matter's operational traffic on UDP 5540 is
  encrypted per session, so mDNS discovery is the only cleartext
  plane that names it -- and it works over Wi-Fi and Ethernet without
  any 802.15.4 radio, including devices sitting behind a Thread
  border router.

  SCOPE (DNSD-074..076) -- the RFC 6762 transport rules, which is the
  CERT VU#550620 family: responders that answer off-link become
  amplification reflectors and leak their whole service inventory.

WHAT THIS TIER DELIBERATELY DOES NOT DO: judge whether an mDNS answer
is legitimate. smbwatch already owns LLMNR/NBT-NS/mDNS name poisoning
(Responder/Inveigh). Both modules see the same packets; only smbwatch
reports spoofing. This one judges scope and census only, so there is
no double report and no disagreement between two detectors about the
same frame.

WHY THE AVAHI CVEs ARE ABSENT: the remote crafted-packet bugs
(CVE-2008-5081 source-port-0 assertion, CVE-2010-2244 checksum crash,
CVE-2011-1002 empty-packet loop) are all 2006-2011 and score ~5.0 on
CVSS v2, under the 6.5 floor. CVE-2008-5081 has a Metasploit module
and high EPSS but is not in CISA KEV, so no exception applies. The
2023 and 2025 Avahi CVEs are local D-Bus resource exhaustion -- not
on the wire at all, so not passively detectable by construction.
"""
import ipaddress

import netscope

import parse
from findings import finding

LAYER = "mdns"

# DNS-SD service types the census reports, mapped to their code.
CENSUS_SERVICES = {
    "_matter._tcp":    ("DNSD-070", "Matter operational node"),
    "_matterc._udp":   ("DNSD-071", "Matter commissionable device (setup mode)"),
    "_matterd._udp":   ("DNSD-072", "Matter commissioner (controller or hub)"),
    "_meshcop._udp":   ("DNSD-073", "Thread border router"),
    # The ephemeral-key border agent endpoint, alongside the ordinary
    # PSKc one. Reported as presence rather than as an open window,
    # because this tier could not establish from the wire whether the
    # service is advertised continuously by a capable router or only
    # while an epskc session is live -- and the louder reading is the
    # one that would be wrong on every Thread border router in the
    # building if the former is true.
    "_meshcop-e._udp": ("DNSD-078", "Thread border agent, ephemeral-key endpoint"),
    # Silicon Labs Z/IP Gateway. No Matter/Thread fingerprint
    # vocabulary applies -- Z-Wave publishes no VP/vn-style identity
    # keys this tier reads -- so it censuses as bare presence with the
    # instance name, like the simplest Matter entry does when a PTR
    # arrives without its TXT.
    "_z-wave._udp":    ("DNSD-079", "Z-Wave Z/IP Gateway"),
}

# Which fingerprint vocabulary applies to each service type. Matter
# and Thread use DIFFERENT, case-differing key sets for the same kinds
# of fact (Matter 'VP' vs Thread 'vn'), so the tables are separate and
# the lookup is by service rather than by trying every key on every
# record.
MATTER_SERVICES = ("_matter._tcp", "_matterc._udp", "_matterd._udp")
THREAD_SERVICES = ("_meshcop._udp", "_meshcop-e._udp")
ZWAVE_SERVICES = ("_z-wave._udp",)

# Matter DNS-SD TXT keys, lowercased (RFC 6763 s6.4 makes key
# comparison case-insensitive; Matter publishes them uppercase).
# Only the keys with identification or posture value are named. The
# session-timing and pairing-hint keys (SII, SAI, SAT, PH, PI, T) are
# deliberately absent: they are tuning parameters with no security
# content, and they CHANGE, which would churn a census keyed on them.
MATTER_TXT = {
    "vp": "vendor_product",      # "<vendorId>+<productId>", decimal
    "dt": "device_type",         # 32-bit Matter device type ID
    "dn": "device_name",         # USER-CHOSEN free text -- see cfg.mdns_include_device_name
    "d":  "discriminator",       # 12-bit, distinguishes identical devices
    "cm": "commissioning_mode",  # 0 = closed; non-zero = open (DNSD-077)
    "ri": "rotating_device_id",
    "icd": "intermittently_connected",
}

# Thread MeshCoP TXT keys (lowercase on the wire).
THREAD_TXT = {
    "rv": "record_version",
    "tv": "thread_version",
    "nn": "network_name",
    "xp": "extended_pan_id",     # raw 8 bytes
    "xa": "extended_address",    # raw 8 bytes, EUI-64
    "vn": "vendor_name",
    "mn": "model_name",
    "sb": "state_bitmap",        # raw 4 bytes -- see fingerprint() for why
    "omr": "omr_prefix",         # raw: Off-Mesh-Routable IPv6 prefix
    "dn": "thread_domain_name",  # NOTE: Thread's 'dn' is a DOMAIN name, not a device name
    "id": "border_agent_id",
}

# Z-Wave Z/IP Gateway DNS-SD TXT keys (Silicon Labs SDS11756). Keys
# are lowercase here because the parser lowercases every TXT key per
# RFC 6763 s6.4; the gateway publishes several mixed-case ('productID',
# 'securityClasses').
#
# THERE IS NO USER-SET DEVICE NAME ON THE WIRE. Unlike Matter's 'dn',
# the Z/IP announcement carries no human-chosen name -- the friendly
# name someone types in their hub is set in the controller and lives
# inside the encrypted Z/IP tunnel (DTLS 41230), which a passive tap
# cannot read. So this fingerprint identifies the node by PRODUCT and
# NETWORK POSITION, not by label, and nothing here is called a device
# name.
ZWAVE_TXT = {
    "productid":       "product_id",            # product identity
    "epid":            "endpoint_id",           # multichannel endpoint
    "securityclasses": "security_classes_hex",  # raw hex; S0/S2 decode NOT attempted
    "mode":            "mode",
    "txtvers":         "txt_version",
    "icon":            "icon_type",             # device-type icon ID
    # 'info' is deliberately NOT read. Silicon Labs' doc lists the key
    # but does not define its contents, and this build will not guess
    # at a field it has not seen decoded on the wire -- the same
    # discipline applied to Thread's 'sb' and 'omr'. Left for a live
    # capture to settle.
}

# Keys the spec defines as INTEGERS, rendered as ints so a consumer
# does not have to know which TXT values are numeric. An unparseable
# value falls back to its raw text rather than being dropped: a
# malformed CM should stay visible to whoever is debugging the device.
TXT_INT_KEYS = {"dt", "d", "cm"}

# Keys whose value is raw binary rather than text, rendered as hex.
#
# 'omr' and 'sb' are in here for the same reason, and it is worth
# stating: their on-wire encodings could not be pinned from a source
# that agreed with itself. 'sb' is a packed state bitmap whose
# published bit layout is self-inconsistent in the one place it is
# written down, and 'omr' carries an IPv6 prefix in an encoding this
# build did not confirm. Both are therefore reported as hex EVIDENCE
# and nothing is inferred from them -- no bit is named, no prefix is
# rendered, and no finding is raised on either. A detector built on a
# guessed bit layout is worse than no detector, because it is
# confidently wrong on every border router on the link.
TXT_BINARY_KEYS = {"xp", "xa", "sb", "id", "ri", "omr", "securityclasses"}


def _addr_text(raw):
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw.hex()


# Both predicates now live in netscope.py, shared with the DDNS and
# rDNS tiers. Re-exported under their original names so this tier's
# existing call sites and tests keep working unchanged -- one
# implementation, three callers.
_in_any_prefix = netscope.in_any_prefix
parse_local_prefixes = netscope.parse_prefixes


# ======================================================================
# CENSUS
# ======================================================================

def census_records(msg):
    """
    Every (service_type, instance) pair this message advertises.

    Reads the ANSWER and ADDITIONAL sections only. Questions are
    excluded on purpose: a QUERY for _matter._tcp proves someone is
    LOOKING for Matter, not that Matter is present -- and any host
    running a Matter controller app browses for it on every network it
    joins, including ones with no Matter at all. Counting queries
    would put a Matter census line on every LAN a phone touches.
    """
    out = []
    for rr in msg.answers + msg.additional:
        if rr.rtype not in (parse.T_PTR, parse.T_SRV, parse.T_TXT):
            continue
        # ONE census entry per record, never one per matching name.
        # For a PTR the service type is the OWNER and the instance is
        # in the rdata target; for SRV/TXT it is the other way round.
        # Both names on a PTR therefore carry the same service type,
        # and looping over them emitted the service twice -- once
        # with an instance and once without, so the same device
        # appeared in the census as two entries, one anonymous.
        # Prefer whichever candidate actually yields an instance.
        svc = inst = None
        for candidate in (rr.parsed.get("target"), rr.name):
            if candidate is None:
                continue
            cand_svc = parse.service_type_of(candidate)
            if cand_svc not in CENSUS_SERVICES:
                continue
            cand_inst = parse.instance_of(candidate)
            if svc is None:
                svc, inst = cand_svc, cand_inst
            if cand_inst is not None:
                svc, inst = cand_svc, cand_inst
                break
        if svc is not None:
            out.append((svc, inst))
    return out


def detect_census(msg, cfg, census_table, src_raw, now):
    """
    Emit one finding per (service, instance) first sighting.

    mDNS hosts re-announce on a schedule and on every topology change,
    so a per-packet census would emit continuously. The table is
    bounded and the suppression is the point, not an optimisation.
    """
    out = []
    for svc, inst in census_records(msg):
        code, label = CENSUS_SERVICES[svc]
        fp = describe(msg, svc, inst, cfg)
        # The fingerprint is part of the KEY, as a boolean, for a
        # reason worth keeping. A device's announcement does not always
        # carry its TXT: a bare PTR response censuses the instance with
        # nothing but a name, and if that were the only key the TXT
        # arriving in the next packet would be suppressed forever and
        # the fingerprint would be permanently invisible for exactly
        # the devices that announce in pieces.
        #
        # Including a BOOLEAN rather than the fingerprint's contents
        # bounds this at two emissions per instance -- one bare, one
        # fingerprinted -- where keying on the contents would re-emit
        # every time a device renamed itself or a timing parameter
        # drifted, which is the churn CENSUS_CODES exists to prevent.
        key = (svc, inst or "", bool(fp))
        if not census_table.first_sighting(key, now):
            continue
        who = f"'{inst}'" if inst else "an unnamed instance"
        detail = f"{label} seen on this LAN: {who} advertising {svc}"
        if fp:
            detail += " -- " + _summarise(fp)
        out.append(finding(
            code, "local.",
            detail,
            {"service_type": svc, "instance": inst,
             "source": _addr_text(src_raw), "fingerprint": fp,
             "note": "census only -- presence, not a vulnerability"},
        ))
    return out


def split_zwave_instance(instance):
    """
    A Z/IP Gateway instance label is a generic device TYPE followed by
    a bracketed hex token, e.g. "Static Controller [d24ac4700200]".
    The hex concatenates the home ID, node ID and multichannel
    endpoint (Silicon Labs SDS11756, the Z/IP DNS-SD support doc).

    This extracts what is UNAMBIGUOUS and no more:
      - device_type: the label text before the bracket
      - network_hex:  the full bracketed hex token, verbatim
      - home_id:      the first 8 hex digits. The Z-Wave home ID is a
                      fixed 32-bit value, so this split is safe.

    The node ID / endpoint split WITHIN the remaining hex is NOT
    attempted. Classic Z-Wave uses an 8-bit node ID and Z-Wave Long
    Range a 16-bit one, so the boundary is not decidable from the
    hostname alone -- guessing it would mislabel every Long Range
    node. The endpoint is taken from the 'epid' TXT key instead, which
    states it outright.

    Returns a dict (possibly with only device_type), or None.
    """
    if not instance:
        return None
    out = {}
    lb, rb = instance.rfind("["), instance.rfind("]")
    if lb != -1 and rb > lb:
        dtype = instance[:lb].strip()
        hexpart = instance[lb + 1:rb].strip()
        if dtype:
            out["device_type"] = dtype
        if hexpart and all(ch in "0123456789abcdefABCDEF" for ch in hexpart):
            out["network_hex"] = hexpart.lower()
            if len(hexpart) >= 8:
                out["home_id"] = hexpart[:8].lower()
    else:
        dtype = instance.strip()
        if dtype:
            out["device_type"] = dtype
    return out or None


def _summarise(fp):
    """A one-line human summary, for the operator who reads the detail
    string and never opens the evidence dict.

    Ordered by what identifies the thing on the shelf first: the
    user-chosen name, then the model, then the network. A vendor ID
    identifies a product line; only the device name identifies the
    lamp someone is standing next to, which is why it leads.
    """
    bits = []
    for name, label in (("device_name", None),
                        ("vendor_product", "VID+PID"),
                        ("device_type", "device type"),
                        ("product_id", "productID"),
                        ("model_name", None),
                        ("vendor_name", None),
                        ("network_name", "Thread network"),
                        ("thread_version", "Thread"),
                        ("node_id", "node"),
                        ("home_id", "Z-Wave home"),
                        ("endpoint_id", "endpoint")):
        v = fp.get(name)
        if v in (None, True):
            continue
        bits.append(f"{label} {v}" if label else str(v))
    return ", ".join(bits) if bits else "no identifying TXT fields"


# ======================================================================
# SCOPE (RFC 6762 transport rules / CERT VU#550620)
# ======================================================================

def detect_ttl_violation(msg, cfg, ttl, src_raw, dst_raw):
    """
    RFC 6762 s11: mDNS MUST be sent with IP TTL / IPv6 hop limit 255,
    and a receiver SHOULD check it. Anything else crossed a router or
    was not generated as link-local traffic.

    This is the CONFIG-FREE leg. It needs no knowledge of the site's
    addressing, which matters because the two stronger scope checks
    below cannot run without it.
    """
    if ttl is None or ttl == parse.MDNS_REQUIRED_TTL:
        return []
    return [finding(
        "DNSD-074", "local.",
        f"mDNS packet from {_addr_text(src_raw)} arrived with TTL/hop-limit {ttl}, "
        f"not the 255 RFC 6762 s11 requires -- it crossed a router or was not "
        f"generated as link-local traffic",
        {"ttl": ttl, "required": parse.MDNS_REQUIRED_TTL,
         "source": _addr_text(src_raw), "destination": _addr_text(dst_raw),
         "is_response": bool(msg.qr)},
    )]


def detect_off_link_source(msg, cfg, src_raw, dst_raw, local_nets):
    """
    An mDNS packet whose SOURCE is outside the site's own prefixes.

    Requires operator-supplied prefixes and returns nothing without
    them. That is deliberate rather than lazy: the obvious config-free
    shortcut is "a public/global source address means off-link", and
    that is WRONG on exactly the networks this has to run on. A
    carrier-neutral colo or an ISP backbone uses public addressing on
    the LAN, so the shortcut would fire on every ordinary mDNS packet
    in the building. An undecidable check must stay silent.
    """
    inside = _in_any_prefix(src_raw, local_nets)
    if inside is not False:
        return []
    return [finding(
        "DNSD-075", "local.",
        f"mDNS packet sourced from {_addr_text(src_raw)}, outside the configured local "
        f"prefixes -- mDNS is link-local by definition, so this service is reachable "
        f"beyond its intended scope",
        {"source": _addr_text(src_raw), "destination": _addr_text(dst_raw),
         "local_prefixes": [str(n) for n in local_nets],
         "is_response": bool(msg.qr)},
    )]


def detect_off_link_unicast_response(msg, cfg, src_raw, dst_raw, local_nets):
    """
    CERT VU#550620, and the CVE cluster that instantiates it
    (CVE-2015-2809 Synology/Avahi, CVE-2017-6520 Bose,
    CVE-2015-1892 IBM ISAM).

    A responder that answers a unicast query from off-link is an open
    reflector: amplification fuel, and a full disclosure of every
    service it advertises.

    THE FALSE-POSITIVE CONTROL: a unicast mDNS response is NOT by
    itself a violation. RFC 6762 s5.4 defines the QU bit precisely so
    a querier can request one, and on-link QU exchanges are ordinary.
    What makes it a violation is the DESTINATION being off-link, so
    that -- not unicast-ness -- is the test.
    """
    if not msg.qr:
        return []
    if parse.is_mdns_group(dst_raw):
        return []                       # ordinary multicast response
    inside = _in_any_prefix(dst_raw, local_nets)
    if inside is not False:
        return []                       # on-link unicast (QU) or undecidable
    services = sorted({s for s, _ in census_records(msg)})
    return [finding(
        "DNSD-076", "local.",
        f"mDNS responder {_addr_text(src_raw)} answered to off-link unicast destination "
        f"{_addr_text(dst_raw)} -- an open reflector (CERT VU#550620): amplification "
        f"fuel and an inventory leak",
        {"source": _addr_text(src_raw), "destination": _addr_text(dst_raw),
         "answer_records": len(msg.answers),
         "services_disclosed": services,
         "local_prefixes": [str(n) for n in local_nets]},
    )]


def handle_mdns(msg, cfg, census_table, src_raw, dst_raw, ttl, local_nets, now):
    """Whole tier for one mDNS packet."""
    out = []
    out += detect_ttl_violation(msg, cfg, ttl, src_raw, dst_raw)
    out += detect_off_link_source(msg, cfg, src_raw, dst_raw, local_nets)
    out += detect_off_link_unicast_response(msg, cfg, src_raw, dst_raw, local_nets)
    out += detect_census(msg, cfg, census_table, src_raw, now)
    out += detect_commissioning_window(msg, cfg, census_table, src_raw, now)
    return out


# ======================================================================
# MATTER / THREAD FINGERPRINT
#
# All of this is CLEARTEXT and already captured: mDNS discovery is the
# only plane that names Matter at all, because operational traffic on
# UDP 5540 is encrypted per session. So the fingerprint costs nothing
# on the wire -- it is a decode of records the tier already reads.
#
# EVERYTHING HERE IS A CLAIM, NOT A FACT. mDNS is unauthenticated, so
# a vendor ID is "what this host says it is". That is fine for a
# census, and it is why no severity in this tier climbs on the
# strength of a TXT value: DNSD-077 reports that a device SAYS its
# window is open, which is exactly what the finding claims. Judging
# whether an advertisement is legitimate at all remains smbwatch's
# job under the existing boundary.
# ======================================================================

def split_matter_instance(instance):
    """
    An operational Matter instance name IS its identity: the 64-bit
    compressed fabric ID and the 64-bit node ID in hex, hyphen-joined
    (e.g. 2906C908D115D362-8FC7772401CD0696).

    So the fabric and node IDs were already being captured before this
    build -- as one opaque label. This splits it, which is what turns
    the census from "Matter is here" into "these N nodes on these M
    fabrics are here".

    Returns (compressed_fabric_id, node_id) as lowercase hex, or None.
    Strict on the shape: 16 hex digits either side and nothing else.
    A looser parse would quietly accept any hyphenated instance name
    and report halves of a user-chosen service name as fabric IDs.
    """
    if not instance or "-" not in instance:
        return None
    left, _, right = instance.partition("-")
    if len(left) != 16 or len(right) != 16:
        return None
    try:
        int(left, 16), int(right, 16)
    except ValueError:
        return None
    return left.lower(), right.lower()


def _render(key, value):
    """One TXT value, rendered the way that field is actually defined."""
    if value is None:
        return True                      # boolean attribute, present
    if key in TXT_BINARY_KEYS:
        return value.hex()
    text = value.decode("utf-8", "replace")
    if key in TXT_INT_KEYS:
        try:
            return int(text)
        except ValueError:
            return text
    return text


def txt_fingerprint(service, pairs, cfg):
    """
    Named fields for one service's TXT pairs.

    The vocabulary is chosen BY SERVICE, not by trying both tables.
    Matter and Thread both publish a 'dn' key and they mean different
    things -- Matter's is the user-chosen DEVICE name, Thread's is the
    DOMAIN name -- so a merged table would file a Thread domain under
    a device name and put a network's topology where an operator reads
    equipment labels.
    """
    if not cfg.mdns_fingerprint:
        return {}
    if service in MATTER_SERVICES:
        table = MATTER_TXT
    elif service in THREAD_SERVICES:
        table = THREAD_TXT
    elif service in ZWAVE_SERVICES:
        table = ZWAVE_TXT
    else:
        return {}
    out = {}
    for key, name in table.items():
        if key not in pairs:
            continue
        if name == "device_name" and not cfg.mdns_include_device_name:
            # Redacted rather than omitted, so a reader can tell the
            # difference between "no name advertised" and "name
            # withheld by configuration".
            out["device_name"] = "<redacted by mdns_include_device_name=False>"
            continue
        out[name] = _render(key, pairs[key])
    return out


def _owns(rr, service, instance):
    """Does this record belong to <instance>.<service>?

    BOTH halves are compared, and the instance alone is not enough.
    A Thread border router advertises the SAME instance name under
    _meshcop._udp and _meshcop-e._udp, so matching on the instance
    alone attributed the PSKc service's TXT to the ephemeral endpoint
    -- harmless there, since it is one device, but the mechanism was
    wrong: two genuinely different devices can share a human-readable
    instance name ("Office Printer" under _ipp._tcp and under
    _matterc._udp), and that would have filed one device's vendor,
    model and network under the other.
    """
    return (parse.service_type_of(rr.name) == service
            and parse.instance_of(rr.name) == instance)


def _txt_pairs_for(msg, service, instance):
    """Merge the TXT pairs of every TXT record owned by this instance.

    Merged across records because a device may split its attributes
    over more than one TXT record in the same announcement, and
    first-occurrence-wins is already enforced inside each record.
    """
    merged = {}
    for rr in msg.answers + msg.additional:
        if rr.rtype != parse.T_TXT or not _owns(rr, service, instance):
            continue
        for k, v in (rr.parsed or {}).get("pairs", {}).items():
            merged.setdefault(k, v)
    return merged


def _srv_for(msg, service, instance):
    """Port and target host for this instance, if an SRV is present.

    SRV has been decoded by the parser since the mDNS build but only
    its target was ever read; the port is the part that tells an
    operator where the thing actually listens.
    """
    for rr in msg.answers + msg.additional:
        if rr.rtype != parse.T_SRV or not _owns(rr, service, instance):
            continue
        p = rr.parsed or {}
        t = p.get("target")
        return {"port": p.get("port"),
                "host": t.text() if t is not None else None}
    return None


def describe(msg, service, instance, cfg):
    """Full fingerprint for one censused instance."""
    fp = {}
    pairs = _txt_pairs_for(msg, service, instance)
    fp.update(txt_fingerprint(service, pairs, cfg))
    if service == "_matter._tcp":
        ids = split_matter_instance(instance)
        if ids:
            fp["compressed_fabric_id"], fp["node_id"] = ids
    if service == "_z-wave._udp":
        zi = split_zwave_instance(instance)
        if zi:
            fp.update(zi)
    srv = _srv_for(msg, service, instance)
    if srv:
        fp["srv"] = srv
    return fp


# ======================================================================
# DNSD-077 -- the device's own statement that its window is open
# ======================================================================

def detect_commissioning_window(msg, cfg, table, src_raw, now):
    """
    A non-zero CM in a Matter TXT record.

    WHY THIS EXISTS ALONGSIDE DNSD-071. DNSD-071 fires on the presence
    of _matterc._udp and infers "setup mode" from it. That inference is
    weaker than it looks: the service type says the device is
    commissionABLE, while CM says whether the window is open RIGHT NOW.
    A device can advertise the service with CM=0. So DNSD-077 is the
    authoritative statement and DNSD-071 is the hint, which is why one
    is a warning and the other a notice.

    WHAT IS DELIBERATELY NOT CLAIMED: the difference between CM=1 and
    CM=2. Both are non-zero and both mean the window is open; which
    one corresponds to which commissioning method, and whether either
    uses the factory-printed passcode, could not be established from a
    source that stated it plainly. So the raw value goes in the
    evidence and the finding claims only what CM=0-versus-non-zero
    supports. Naming CM=2 "the weaker mode" in a detail string would
    have been a guess an operator then acts on.

    SUPPRESSION INCLUDES THE CM VALUE, so a window opening and closing
    re-reports once per state change rather than once per announcement
    -- mDNS devices re-announce constantly, and a commissioning window
    is precisely the transient an operator wants the edges of.
    """
    if not cfg.mdns_enabled:
        return []
    out = []
    for svc, inst in census_records(msg):
        if svc not in MATTER_SERVICES:
            continue
        pairs = _txt_pairs_for(msg, svc, inst)
        raw = pairs.get("cm")
        if raw is None:
            continue
        try:
            cm = int(raw.decode("ascii", "strict"))
        except (ValueError, UnicodeDecodeError):
            # A non-numeric CM is malformed, but inventing a finding
            # for it would be a detector for a typo. The census still
            # carries the raw value as evidence.
            continue
        if cm == 0:
            continue
        key = ("DNSD-077", svc, inst or "", cm)
        if not table.first_sighting(key, now):
            continue
        fp = describe(msg, svc, inst, cfg)
        who = f"'{inst}'" if inst else "an unnamed instance"
        out.append(finding(
            "DNSD-077", "local.",
            f"Matter device {who} reports CM={cm} on {svc} -- its own TXT record says "
            f"the commissioning window is open, so anything on this link can attempt "
            f"to pair with it",
            {"service_type": svc, "instance": inst, "commissioning_mode": cm,
             "source": _addr_text(src_raw), "fingerprint": fp,
             "note": "CM is self-reported over unauthenticated mDNS; it states intent, "
                     "not whether pairing would succeed"},
        ))
    return out
