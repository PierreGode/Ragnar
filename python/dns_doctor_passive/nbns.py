"""
DNS Doctor passive tier -- NBNS / NBT-NS leg (RFC 1001/1002, UDP 137).

NBNS IS NOT DNS, despite sharing the 12-byte header layout, and both
differences are traps this module had to be told about explicitly:

  1. NAMES use a two-level encoding. Sixteen name bytes are each split
     into two 4-bit nibbles, each mapped to 'A' + nibble, producing 32
     printable characters that then travel as ONE ordinary DNS label.
     A DNS parser reads that label without complaint and returns
     "FHFAEBEECACACACACACACACACACACAAA" -- which is "WPAD". So the
     WPAD detection that is the whole point of this leg is not merely
     awkward without the codec in parse.py, it is invisible.

  2. OPCODE 5 MEANS NAME REGISTRATION, while in DNS it means UPDATE
     (RFC 2136). NBNS reaching the opcode router would therefore be
     read as dynamic update, and an ordinary Windows registration
     storm would be reported as unsigned dynamic updates being
     accepted -- a critical finding, fabricated from a port confusion.
     Port 137 is forked BEFORE the opcode fork for this reason, and
     conformance asserts it in both directions.

BOUNDARY WITH smbwatch: unchanged from the LLMNR leg. smbwatch owns
NBT-NS name poisoning; this tier reports posture, the WPAD query and
NBSTAT enumeration.
"""
import parse
from findings import finding


def _addr(raw):
    import ipaddress
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return bytes(raw).hex()


def decode_question(msg):
    """The decoded NetBIOS name of the first question, or None."""
    if not msg.questions:
        return None
    q = msg.questions[0]
    info = parse.nbns_name(q["name"])
    if info is None:
        return None
    info = dict(info)
    info["qtype"] = q["qtype"]
    return info


def opcode_name(msg):
    return parse.NBNS_OPCODES.get(msg.opcode, f"opcode {msg.opcode}")


# ======================================================================
# DNSD-120 -- the protocol is in use at all
# ======================================================================

def detect_nbns_in_use(msg, cfg, table, src_raw, now):
    if not cfg.nbns_enabled:
        return []
    if not table.first_sighting(("DNSD-120", bytes(src_raw)), now):
        return []
    info = decode_question(msg)
    return [finding(
        "DNSD-120", "nbns.",
        f"NBT-NS in use by {_addr(src_raw)} ({opcode_name(msg)})"
        + (f", name {info['netbios_name']}<{info['suffix']:02X}>" if info else "")
        + " -- unauthenticated by design and more thoroughly deprecated than LLMNR",
        {"source": _addr(src_raw), "opcode": msg.opcode,
         "opcode_name": opcode_name(msg), "qr": bool(msg.qr),
         "netbios": info,
         "note": "name poisoning on this protocol is smbwatch's half"},
    )]


# ======================================================================
# DNSD-121 -- WPAD over NBNS (CVE-2016-3213 / CVE-2016-3236)
# ======================================================================

def detect_wpad(msg, cfg, table, src_raw, now):
    """
    MS16-077. CVE-2016-3213 is CVSS 8.8 and is exploited, in NVD's own
    words, "via NetBIOS name responses": Windows' WPAD implementation
    had an improper fallback that let a NBNS responder supply the
    proxy configuration.

    QUERIES ONLY, for the same reason as the LLMNR half: the query is
    the vulnerable state this sensor can establish, and the response is
    the attack, which smbwatch reports. A host still emitting a WPAD
    NBNS query will take its proxy configuration from the first
    answer on the link whether or not it is patched against the
    specific 2016 fallback bug.
    """
    if not cfg.nbns_enabled or msg.qr:
        return []
    info = decode_question(msg)
    if info is None or info["netbios_name"].upper() != "WPAD":
        return []
    if not table.first_sighting(("DNSD-121", bytes(src_raw)), now):
        return []
    return [finding(
        "DNSD-121", "nbns.",
        f"{_addr(src_raw)} asked for WPAD over NBNS (encoded on the wire as "
        f"{info['encoded']}) -- the MS16-077 precondition; this host will take its "
        f"web-proxy configuration from the first NetBIOS name response it receives",
        {"source": _addr(src_raw), "netbios": info,
         "affected": "MS16-077; CVE-2016-3213 (CVSS 8.8), CVE-2016-3236",
         "note": "the query is the vulnerable state; the poisoned answer is smbwatch's"},
    )]


# ======================================================================
# DNSD-122 -- NBSTAT enumeration
# ======================================================================

def detect_nbstat(msg, cfg, counter, src_raw, now):
    """
    NBSTAT (type 33) returns a host's whole NetBIOS name table and its
    adapter MAC address, so a sweep of NBSTAT queries is host and
    domain-role enumeration -- it is how an attacker learns which box
    is the domain master browser without authenticating to anything.

    RATE-BASED, not presence-based, and the distinction matters: a
    single NBSTAT is what ordinary Windows browsing does, so reporting
    one would bury DNSD-120 under noise from the same hosts. A
    threshold of several inside a minute from one source is the sweep.
    Fixed threshold rather than a learned baseline, for the same reason
    as the ip6.arpa walk: there is no network on which a host
    legitimately NBSTATs dozens of peers in a minute.
    """
    if not cfg.nbns_enabled or msg.qr:
        return []
    if not msg.questions or msg.questions[0]["qtype"] != parse.T_NBSTAT:
        return []
    key = ("DNSD-122", bytes(src_raw))
    n = counter.bump(key, now)
    if n < cfg.nbstat_min_queries or counter.reported(key):
        return []
    counter.mark_reported(key)
    info = decode_question(msg)
    return [finding(
        "DNSD-122", "nbns.",
        f"{_addr(src_raw)} issued {n} NBSTAT queries in "
        f"{cfg.nbstat_window_seconds:.0f}s -- NBSTAT returns a host's full NetBIOS name "
        f"table and adapter address, so a sweep is host and domain-role enumeration",
        {"source": _addr(src_raw), "queries": n,
         "window_seconds": cfg.nbstat_window_seconds,
         "last_name": info["netbios_name"] if info else None},
    )]


def handle_nbns(msg, cfg, table, counter, src_raw, dst_raw, now):
    out = []
    out += detect_nbns_in_use(msg, cfg, table, src_raw, now)
    out += detect_wpad(msg, cfg, table, src_raw, now)
    out += detect_nbstat(msg, cfg, counter, src_raw, now)
    return out
