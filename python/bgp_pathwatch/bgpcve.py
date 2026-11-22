"""
bgpcve.py -- passive CVE detectors for BGP messages observed on a tap.

Covers 13 CVEs (CVSS >= 6.5) whose trigger is visible in the message itself,
so detection is pure inspection: no probing, no session, nothing emitted.

DESIGN CONSTRAINT THAT DRIVES EVERYTHING HERE
---------------------------------------------
These detectors run on *deliberately malformed* messages. bgp.parse_update()
is a conformant parser -- on exactly the inputs we care about it will raise,
truncate, or silently mis-slice. So it CANNOT be the basis for detection.

Everything below is built on a lenient walker (walk_update / iter_attributes)
that never raises, reports overruns and underflows as data rather than
exceptions, and preserves raw offsets. A detector that crashes on the attack
it was written to find is worse than no detector.

CONFIDENCE MODEL
----------------
Every finding carries a confidence. The honest split:
  high   -- the malformation is structurally unambiguous on the wire
            (length arithmetic that cannot be valid under any reading)
  medium -- structurally malformed, but a benign encoder bug could produce it
  low    -- shape matches the CVE but a conformant-but-unusual encoding could
            also produce it

A finding says "a message with this CVE's trigger shape crossed the tap." It
does NOT say the receiving router is vulnerable -- version is not on the wire.
That distinction is in every finding's `note` and must survive into alerting.

DUAL-STACK
----------
Detectors key on BGP structure, not transport family, so they fire identically
on v4- and v6-transported sessions. Where a detector is AFI-specific
(PW-BGP-007/009 touch IPv6 NLRI and IPv6 extended communities) both families
are exercised explicitly. The tap layer (bgptap.py) carries transport family
through to the finding so v4/v6 parity is observable in the output, not
assumed.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional

import bgp

# --- attribute type codes -------------------------------------------------- #
ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3
ATTR_MP_REACH = 14
ATTR_MP_UNREACH = 15
NOTIFICATION = bgp.NOTIFICATION

ATTR_PMSI_TUNNEL = 22          # RFC 6514 -- NOT an encap attribute, see d001
ATTR_TUNNEL_ENCAP = 23         # RFC 9012 (obsoletes RFC 5512)
ATTR_IPV6_EXT_COMMUNITIES = 25  # RFC 5701
ATTR_PREFIX_SID = 40           # RFC 8669

# The NHC ("Next Hop Dependent Capabilities/Characteristics") attribute is still
# draft-stage: draft-ietf-idr-nhc / draft-ietf-idr-entropy-label carry it as
# "TBD1", and implementations have used different provisional code points.
# CONFIRM THIS AGAINST YOUR FRR BUILD (grep BGP_ATTR_NHC in bgpd/bgp_attr.h)
# before trusting PW-BGP-008 -- a wrong code point yields silent false
# negatives, which is why it is configurable rather than hard-coded.
ATTR_NHC_DEFAULT = 39
NHC_TLV_MIN_LEN = 3            # 1B code + 2B length, per the draft's TLV shape

MANDATORY_ATTRS = (ATTR_ORIGIN, ATTR_AS_PATH)

SAFI_FLOWSPEC = 133
SAFI_FLOWSPEC_VPN = 134
SAFI_SR_POLICY = 73

# --- labelled-VPN NLRI (RFC 8277 + RFC 4364/4659), CVE-2026-93345 ---------- #
SAFI_MPLS_VPN = 128            # MPLS-labelled VPN unicast (VPNv4 / VPNv6)
VPN_LABEL_BITS = 24            # one label: 20b label + 3b Rsrv + 1b S
VPN_RD_BITS = 64               # 8-octet Route Distinguisher
# RFC 8277 s2: the Length octet counts BITS and covers the label bits as well
# as the prefix bits, and for SAFI 128 "the prefix is at least 64 bits long"
# (the RD). One label plus an RD therefore consumes 88 bits before a single
# address bit exists, so a declared length below 88 describes a route with a
# NEGATIVE-length address portion. That floor holds whether or not the peers
# exchanged the Multiple Labels Capability -- extra labels only raise it -- so
# the check needs no capability state and no baseline.
VPN_NLRI_MIN_BITS = VPN_LABEL_BITS + VPN_RD_BITS      # 88

# SAFIs whose MP_REACH NLRI really is a plain prefix list ([1B length][prefix]),
# and which may therefore be prefix-walked. Everything else carries its own
# NLRI encoding and MUST NOT be walked as prefixes: labeled unicast (4) and
# MPLS VPN (128) prepend label/RD octets, EVPN (70) is route-type TLVs,
# FlowSpec (133/134) is component TLVs, SR Policy (73) is a fixed
# distinguisher/colour/endpoint tuple, and BGP-LS (71/72) is descriptor TLVs.
# Walking any of those as prefixes overruns immediately and reports a
# malformation on wholly legitimate traffic.
PREFIX_SHAPED_SAFIS = (1, 2)

AFI_IPV4 = 1
AFI_IPV6 = 2


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    code: str
    cves: tuple
    cvss: float
    title: str
    confidence: str            # high | medium | low
    detail: str
    note: str = ""
    src: str = ""
    dst: str = ""
    family: int = 0            # transport family: 4 or 6
    afi: Optional[int] = None  # NLRI address family where applicable

    def as_dict(self) -> dict:
        return {
            "code": self.code, "cves": list(self.cves), "cvss": self.cvss,
            "title": self.title, "confidence": self.confidence,
            "detail": self.detail, "note": self.note,
            "src": self.src, "dst": self.dst,
            "family": self.family, "afi": self.afi,
        }


_VPN_NOTE = ("the malformation is invalid for every BGP implementation, so "
             "this fires on the packet shape from any peer; the RouterOS "
             "range (all versions before 7.25beta4 -- stable 7.24.2 and "
             "long-term 7.23.5 included) is enrichment, not a gate. CVSS 3.1 "
             "7.5 / CVSS 4.0 8.7. Indicates the trigger crossed the tap, not "
             "that the receiving router crashed -- see PW-BGP-014 for that")

_EXPOSURE_NOTE = ("indicates a message with this trigger shape crossed the tap; "
                  "does not establish that the receiving router is a vulnerable "
                  "version (version is not on the wire)")


# --------------------------------------------------------------------------- #
# Lenient walkers -- never raise
# --------------------------------------------------------------------------- #
@dataclass
class RawAttr:
    flags: int
    atype: int
    declared_len: int
    value: bytes
    overrun: bool = False        # declared length ran past the attribute block
    header_truncated: bool = False

    @property
    def extended(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def optional(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def transitive(self) -> bool:
        return bool(self.flags & 0x40)


def iter_attributes(attrs: bytes) -> Iterator[RawAttr]:
    """Walk a path-attribute block leniently. Never raises; signals problems
    through RawAttr.overrun / header_truncated and stops cleanly."""
    i = 0
    n = len(attrs)
    while i < n:
        if i + 2 > n:
            yield RawAttr(0, 0, 0, attrs[i:], header_truncated=True)
            return
        flags = attrs[i]
        atype = attrs[i + 1]
        i += 2
        if flags & 0x10:
            if i + 2 > n:
                yield RawAttr(flags, atype, 0, attrs[i:], header_truncated=True)
                return
            alen = struct.unpack("!H", attrs[i:i + 2])[0]
            i += 2
        else:
            if i + 1 > n:
                yield RawAttr(flags, atype, 0, attrs[i:], header_truncated=True)
                return
            alen = attrs[i]
            i += 1
        overrun = (i + alen) > n
        yield RawAttr(flags, atype, alen, attrs[i:i + alen], overrun=overrun)
        if overrun:
            return
        i += alen


@dataclass
class RawUpdate:
    """Lenient decomposition of an UPDATE body. Every field that can be
    inconsistent is reported rather than assumed."""
    body_len: int
    withdrawn_len: int = 0
    withdrawn: bytes = b""
    attrs_len: int = 0
    attrs: bytes = b""
    nlri: bytes = b""
    # inconsistency flags -- these ARE the detection substrate
    header_truncated: bool = False
    withdrawn_overrun: bool = False
    attrs_overrun: bool = False
    underflow: bool = False
    underflow_detail: str = ""


def walk_update(body: bytes) -> RawUpdate:
    """Decompose an UPDATE body without trusting any length field.

    UPDATE body: [2B withdrawn_len][withdrawn][2B attrs_len][attrs][NLRI tail]
    Each declared length is checked against what is actually present; an
    over-declaration is exactly the integer-underflow substrate that
    CVE-2026-37462 and friends exploit (remaining = total - declared goes
    negative and wraps in unsigned arithmetic).
    """
    n = len(body)
    u = RawUpdate(body_len=n)

    if n < 2:
        u.header_truncated = True
        return u
    u.withdrawn_len = struct.unpack("!H", body[:2])[0]
    off = 2
    if off + u.withdrawn_len > n:
        u.withdrawn_overrun = True
        u.underflow = True
        u.underflow_detail = (
            f"withdrawn_routes_len={u.withdrawn_len} exceeds remaining "
            f"body bytes={n - off}")
        u.withdrawn = body[off:]
        return u
    u.withdrawn = body[off:off + u.withdrawn_len]
    off += u.withdrawn_len

    if off + 2 > n:
        u.header_truncated = True
        return u
    u.attrs_len = struct.unpack("!H", body[off:off + 2])[0]
    off += 2
    if off + u.attrs_len > n:
        u.attrs_overrun = True
        u.underflow = True
        u.underflow_detail = (
            f"total_path_attribute_len={u.attrs_len} exceeds remaining "
            f"body bytes={n - off}")
        u.attrs = body[off:]
        return u
    u.attrs = body[off:off + u.attrs_len]
    off += u.attrs_len
    u.nlri = body[off:]
    return u


def walk_prefixes(data: bytes, bits: int) -> tuple[int, bool]:
    """Count NLRI prefixes, reporting overrun. Returns (count, overrun)."""
    i = 0
    count = 0
    while i < len(data):
        plen = data[i]
        i += 1
        if plen > bits:
            return count, True
        nbytes = (plen + 7) // 8
        if i + nbytes > len(data):
            return count, True
        i += nbytes
        count += 1
    return count, False


# --------------------------------------------------------------------------- #
# Detectors
# --------------------------------------------------------------------------- #
@dataclass
class VpnNlri:
    """One labelled-VPN NLRI record, decoded leniently."""
    declared_bits: int
    address_bits: int = 0        # declared_bits - 88; negative is the defect
    nbytes: int = 0
    below_minimum: bool = False
    overrun: bool = False
    remaining: int = 0


def walk_labelled_vpn_nlri(data: bytes,
                           min_bits: int = VPN_NLRI_MIN_BITS) -> list:
    """Decode a run of SAFI 128 NLRI without trusting the length octet.

    Stops at the first structurally impossible record: a malformed length
    desynchronises everything after it, so continuing would report garbage
    rather than findings. Never raises.
    """
    out: list = []
    i = 0
    n = len(data)
    while i < n:
        rec = VpnNlri(declared_bits=data[i])
        i += 1
        rec.nbytes = (rec.declared_bits + 7) // 8
        rec.address_bits = rec.declared_bits - min_bits
        if rec.declared_bits < min_bits:
            rec.below_minimum = True
            out.append(rec)
            return out
        if i + rec.nbytes > n:
            rec.overrun = True
            rec.remaining = n - i
            out.append(rec)
            return out
        i += rec.nbytes
        out.append(rec)
    return out


def d013_labelled_vpn_nlri(u: RawUpdate,
                           vpn_safis: tuple = (SAFI_MPLS_VPN,)) -> list:
    """PW-BGP-013 -- CVE-2026-93345 (MikroTik RouterOS, CWE-1284).

    A labelled-VPN MP_REACH_NLRI whose prefix-length octet is below the
    structural minimum for the family. RouterOS's labelled-VPN NLRI iterators
    accept it and then walk a negative-length address portion, crashing the
    routing service; the session drops with no NOTIFICATION and a single
    repeated packet holds the BGP plane down indefinitely.

    Pathognomonic and capability-independent: no arming condition, no
    baseline, no threshold. A length below 88 bits cannot describe a valid
    labelled-VPN route under any implementation or any label stack depth, so
    this is zero-false-positive by construction.

    The RouterOS version range is ENRICHMENT on the finding, never the gate --
    the malformation is invalid for every implementation, and only the
    consequence (indefinite hold-down rather than a NOTIFICATION) is
    RouterOS-specific. The rule fires on the shape, from any peer.

    SAFI 129 (labelled-VPN multicast) shares the label+RD structure and can be
    added via vpn_safis if that family is carried; it is not enabled by default
    because the advisory names VPNv4/VPNv6 unicast.
    """
    out = []
    for a in iter_attributes(u.attrs):
        if a.atype not in (ATTR_MP_REACH, ATTR_MP_UNREACH) or a.overrun:
            continue
        v = a.value
        if len(v) < 3:
            continue
        afi = struct.unpack("!H", v[:2])[0]
        safi = v[2]
        if safi not in vpn_safis:
            continue
        if a.atype == ATTR_MP_REACH:
            if len(v) < 4:
                continue
            off = 4 + v[3] + 1              # next hop + reserved octet
        else:
            off = 3
        if off > len(v):
            continue
        fam = {AFI_IPV4: "VPNv4", AFI_IPV6: "VPNv6"}.get(afi, f"AFI {afi}")
        for rec in walk_labelled_vpn_nlri(v[off:]):
            if rec.below_minimum:
                out.append(Finding(
                    "PW-BGP-013", ("CVE-2026-93345",), 7.5,
                    "Labelled-VPN NLRI prefix-length below the structural "
                    "minimum", "high",
                    f"{fam} (AFI {afi}/SAFI {safi}): NLRI length octet is "
                    f"{rec.declared_bits} bits, below the "
                    f"{VPN_NLRI_MIN_BITS}-bit minimum "
                    f"({VPN_LABEL_BITS}b label + {VPN_RD_BITS}b RD), "
                    f"describing an address portion of "
                    f"{rec.address_bits} bits",
                    _VPN_NOTE, afi=afi))
            elif rec.overrun:
                out.append(Finding(
                    "PW-BGP-013", ("CVE-2026-93345",), 7.5,
                    "Labelled-VPN NLRI length overruns the attribute",
                    "medium",
                    f"{fam} (AFI {afi}/SAFI {safi}): NLRI length octet is "
                    f"{rec.declared_bits} bits ({rec.nbytes} octets) but only "
                    f"{rec.remaining} octet(s) remain -- the same length-field "
                    f"validation defect in the opposite direction to the "
                    f"shape the advisory describes",
                    _VPN_NOTE, afi=afi))
    return out


def _attrs_present(u: RawUpdate) -> set:
    return {a.atype for a in iter_attributes(u.attrs) if not a.header_truncated}


_ENCAP_CVES = ("CVE-2023-38802", "CVE-2024-30395", "CVE-2024-44070")


@dataclass
class TunnelTlv:
    ttype: int
    tlen: int
    value: bytes
    overrun: bool = False
    truncated: bool = False


def iter_tunnel_tlvs(value: bytes) -> Iterator[TunnelTlv]:
    """Walk the Tunnel TLVs of a Tunnel Encapsulation attribute (type 23).

    RFC 9012 s2: each Tunnel TLV is [2B Tunnel Type][2B Length][Value].
    The Length field is TWO octets and always has been -- RFC 5512, which
    RFC 9012 obsoletes, used the same 2-octet TLV length; only the SUB-TLV
    length rule changed between them (see iter_encap_subtlvs). Reading this
    as one octet silently desynchronises the walk on any legitimate tunnel
    attribute, which manufactures findings rather than finding them.

    Never raises; problems are reported on the yielded record.
    """
    i = 0
    n = len(value)
    while i < n:
        if i + 4 > n:
            yield TunnelTlv(0, 0, value[i:], truncated=True)
            return
        ttype, tlen = struct.unpack("!HH", value[i:i + 4])
        i += 4
        over = (i + tlen) > n
        yield TunnelTlv(ttype, tlen, value[i:i + tlen], overrun=over)
        if over:
            return
        i += tlen


def iter_encap_subtlvs(value: bytes) -> Iterator[TunnelTlv]:
    """Walk the sub-TLVs inside one Tunnel TLV.

    RFC 9012 s1.4: the sub-TLV Type field is 1 octet, and the Length field is
    1 octet for types 0-127 but 2 octets for types 128-255. RFC 5512 used a
    1-octet Length for every sub-TLV; this type-dependent rule is the change
    RFC 9012 introduced. Never raises.
    """
    i = 0
    n = len(value)
    while i < n:
        t = value[i]
        i += 1
        if t >= 128:
            if i + 2 > n:
                yield TunnelTlv(t, 0, value[i:], truncated=True)
                return
            l = struct.unpack("!H", value[i:i + 2])[0]
            i += 2
        else:
            if i + 1 > n:
                yield TunnelTlv(t, 0, value[i:], truncated=True)
                return
            l = value[i]
            i += 1
        over = (i + l) > n
        yield TunnelTlv(t, l, value[i:i + l], overrun=over)
        if over:
            return
        i += l


def d001_tunnel_encap(u: RawUpdate) -> list:
    """PW-BGP-001 -- CVE-2023-38802 (FRR), CVE-2024-30395 (Juniper rpd),
    CVE-2024-44070 (FRR bgp_attr_encap).

    All three are a declared length running past the remaining payload inside
    the Tunnel Encapsulation attribute (type 23). They share ONE wire
    signature: nothing in the packet distinguishes "the FRR-crashing
    malformation" from "the Juniper-crashing one" -- the difference is which
    implementation mishandles it, and implementation is not on the wire. So
    this is one detector reporting all three rather than three codes claiming
    a precision the bytes do not contain.

    Scope is attribute 23 ONLY. Attribute 22 is PMSI_TUNNEL (RFC 6514), a
    completely different structure ([1B flags][1B tunnel type][3B label]
    [tunnel identifier]) used by MVPN/EVPN. Walking it as Tunnel TLVs
    desynchronises immediately and manufactures findings on ordinary
    multicast-VPN traffic, so it is deliberately excluded.

    Both nesting levels are checked, because FRR's bgp_attr_encap() walks
    both: the Tunnel TLV length (2 octets, RFC 9012 s2) and each sub-TLV
    length (1 or 2 octets by type, RFC 9012 s1.4).
    """
    out = []
    for a in iter_attributes(u.attrs):
        if a.atype != ATTR_TUNNEL_ENCAP:
            continue
        if a.overrun:
            out.append(Finding(
                "PW-BGP-001", _ENCAP_CVES, 7.5,
                "Malformed BGP Tunnel Encapsulation attribute", "high",
                f"attribute 23 declared length {a.declared_len} overruns the "
                f"path-attribute block", _EXPOSURE_NOTE))
            continue

        bad = None
        for tlv in iter_tunnel_tlvs(a.value):
            if tlv.truncated:
                bad = ("Tunnel TLV header truncated: fewer than the 4 octets "
                       "needed for a 2-octet type and 2-octet length")
                break
            if tlv.overrun:
                bad = (f"Tunnel TLV type {tlv.ttype} declares length "
                       f"{tlv.tlen}, exceeding the remaining attribute payload")
                break
            for sub in iter_encap_subtlvs(tlv.value):
                if sub.truncated:
                    bad = (f"sub-TLV header truncated inside Tunnel TLV type "
                           f"{tlv.ttype}")
                    break
                if sub.overrun:
                    bad = (f"sub-TLV type {sub.ttype} inside Tunnel TLV type "
                           f"{tlv.ttype} declares length {sub.tlen}, "
                           f"exceeding the remaining tunnel payload")
                    break
            if bad:
                break
        if bad:
            out.append(Finding(
                "PW-BGP-001", _ENCAP_CVES, 7.5,
                "Malformed BGP Tunnel Encapsulation attribute", "high",
                bad, _EXPOSURE_NOTE))
    return out


def d002_zero_attrlen_with_nlri(u: RawUpdate) -> list:
    """PW-BGP-002 -- CVE-2023-41358. FRR's bgp_packet.c processes NLRI even
    when the total path attribute length is zero. A conformant UPDATE carrying
    NLRI must carry at least ORIGIN/AS_PATH/NEXT_HOP, so attrs_len==0 with a
    non-empty NLRI tail is never legitimate."""
    if u.attrs_len == 0 and u.nlri and not u.underflow:
        count, overrun = walk_prefixes(u.nlri, 32)
        return [Finding(
            "PW-BGP-002", ("CVE-2023-41358",), 7.5,
            "BGP UPDATE with NLRI present and zero-length path attributes",
            "high",
            f"total_path_attribute_len=0 with {len(u.nlri)} bytes of trailing "
            f"NLRI ({count} prefix(es)"
            + (", walk overruns" if overrun else "") + ")",
            _EXPOSURE_NOTE, afi=AFI_IPV4)]
    return []


def d003_mp_unreach_missing_mandatory(u: RawUpdate) -> list:
    """PW-BGP-003 -- CVE-2023-47234. Crafted UPDATE carrying MP_UNREACH_NLRI
    plus additional NLRI that lacks the mandatory path attributes."""
    if u.underflow:
        return []
    present = _attrs_present(u)
    if ATTR_MP_UNREACH not in present or not u.nlri:
        return []
    missing = [t for t in MANDATORY_ATTRS if t not in present]
    if not missing:
        return []
    names = {ATTR_ORIGIN: "ORIGIN", ATTR_AS_PATH: "AS_PATH"}
    return [Finding(
        "PW-BGP-003", ("CVE-2023-47234",), 7.5,
        "MP_UNREACH_NLRI with trailing NLRI lacking mandatory attributes",
        "high",
        f"MP_UNREACH_NLRI present with {len(u.nlri)} bytes trailing NLRI; "
        f"missing mandatory attribute(s): "
        + ", ".join(names.get(m, str(m)) for m in missing),
        _EXPOSURE_NOTE)]


def d004_eor_malformed(u: RawUpdate) -> list:
    """PW-BGP-004 -- CVE-2023-47235. A malformed UPDATE carrying an EOR does
    not get treat-as-withdraw handling in FRR.

    A clean IPv4 EOR is exactly a 4-byte body (both length fields zero) and is
    NOT a finding. The trigger is an EOR-shaped message (no withdrawn routes,
    no NLRI) that nonetheless carries a malformed attribute block.
    """
    if u.header_truncated:
        return []
    eor_shaped = (u.withdrawn_len == 0 and not u.nlri)
    if not eor_shaped:
        return []
    if u.body_len == 4 and u.attrs_len == 0:
        return []                      # conformant EOR
    problems = []
    if u.attrs_overrun:
        problems.append(u.underflow_detail)
    for a in iter_attributes(u.attrs):
        if a.header_truncated:
            problems.append("attribute header truncated")
        elif a.overrun:
            problems.append(
                f"attribute type {a.atype} length {a.declared_len} overruns block")
    if not problems:
        return []
    return [Finding(
        "PW-BGP-004", ("CVE-2023-47235",), 7.5,
        "EOR-shaped BGP UPDATE carrying malformed path attributes",
        "high",
        "no withdrawn routes and no NLRI (EOR shape) but attribute block is "
        "malformed: " + "; ".join(problems[:3]),
        _EXPOSURE_NOTE)]


def d005_prefix_sid(u: RawUpdate) -> list:
    """PW-BGP-005 -- CVE-2024-31948. Malformed Prefix-SID attribute (type 40)
    crashes FRR's bgpd. RFC 8669 requires optional-transitive flags; FRR's fix
    was to treat a malformed Prefix-SID as discard-worthy rather than set the
    flag unconditionally. Both bad flags and a bad TLV walk are triggers."""
    out = []
    for a in iter_attributes(u.attrs):
        if a.atype != ATTR_PREFIX_SID:
            continue
        if a.overrun:
            out.append(Finding(
                "PW-BGP-005", ("CVE-2024-31948",), 6.5,
                "Malformed BGP Prefix-SID attribute (type 40)", "high",
                f"attribute 40 declared length {a.declared_len} overruns the "
                f"path-attribute block", _EXPOSURE_NOTE))
            continue
        # RFC 8669: Prefix-SID is optional (0x80) transitive (0x40)
        if not (a.optional and a.transitive):
            out.append(Finding(
                "PW-BGP-005", ("CVE-2024-31948",), 6.5,
                "BGP Prefix-SID attribute with non-conformant flags", "medium",
                f"attribute 40 flags=0x{a.flags:02x} "
                f"(optional={a.optional}, transitive={a.transitive}); RFC 8669 "
                f"requires optional-transitive", _EXPOSURE_NOTE))
            continue
        v = a.value
        i = 0
        while i < len(v):
            if i + 3 > len(v):
                out.append(Finding(
                    "PW-BGP-005", ("CVE-2024-31948",), 6.5,
                    "Malformed BGP Prefix-SID attribute (type 40)", "high",
                    f"Prefix-SID TLV header truncated at offset {i}",
                    _EXPOSURE_NOTE))
                break
            tlv_len = struct.unpack("!H", v[i + 1:i + 3])[0]
            if i + 3 + tlv_len > len(v):
                out.append(Finding(
                    "PW-BGP-005", ("CVE-2024-31948",), 6.5,
                    "Malformed BGP Prefix-SID attribute (type 40)", "high",
                    f"Prefix-SID TLV type {v[i]} at offset {i} declares length "
                    f"{tlv_len}, exceeding {len(v) - i - 3} remaining bytes",
                    _EXPOSURE_NOTE))
                break
            i += 3 + tlv_len
    return out


def _flowspec_scan(nlri: bytes) -> Optional[str]:
    """Walk FlowSpec components (RFC 8955) looking for the operator-value
    boundary defect behind CVE-2026-37457.

    Each component is [1B type] then a sequence of [1B operator][value], where
    the operator's bit 7 (0x80) is the end-of-list marker and bits 4-5 encode
    value length as 1<<((op>>4)&3). FRR's bgp_flowspec_op_decode() treated the
    terminating index as inclusive, permitting a single-byte write one past the
    buffer -- so an operator-value run that lands exactly at or past the
    component boundary is the signature.
    """
    i = 0
    n = len(nlri)
    if n == 0:
        return None
    # FlowSpec NLRI: 1 or 2 byte length, then components
    if nlri[0] < 0xF0:
        flen = nlri[0]
        i = 1
    else:
        if n < 2:
            return "FlowSpec NLRI extended length truncated"
        flen = ((nlri[0] & 0x0F) << 8) | nlri[1]
        i = 2
    if i + flen > n:
        return (f"FlowSpec NLRI declares length {flen}, exceeding "
                f"{n - i} remaining bytes")
    end = i + flen
    while i < end:
        i += 1                       # component type
        if i > end:
            return "FlowSpec component type past NLRI end"
        guard = 0
        while i < end:
            guard += 1
            if guard > 64:
                return "FlowSpec operator list exceeds sane length"
            op = nlri[i]
            i += 1
            vlen = 1 << ((op >> 4) & 0x03)
            if i + vlen > end:
                return (f"FlowSpec operator-value at offset {i} needs {vlen} "
                        f"bytes but only {end - i} remain (off-by-one write "
                        f"boundary)")
            i += vlen
            if op & 0x80:            # end-of-operator-list
                break
        else:
            return "FlowSpec operator list not terminated before NLRI end"
    return None


def d006_flowspec(u: RawUpdate) -> list:
    """PW-BGP-006 -- CVE-2026-37457. Off-by-one OOB write in FRR's
    bgp_flowspec_op_decode(). Fires on FlowSpec SAFI (133/134) in either
    MP_REACH or MP_UNREACH, for AFI 1 and AFI 2 alike."""
    out = []
    for a in iter_attributes(u.attrs):
        if a.atype not in (ATTR_MP_REACH, ATTR_MP_UNREACH) or a.overrun:
            continue
        v = a.value
        if len(v) < 3:
            continue
        afi = struct.unpack("!H", v[:2])[0]
        safi = v[2]
        if safi not in (SAFI_FLOWSPEC, SAFI_FLOWSPEC_VPN):
            continue
        if a.atype == ATTR_MP_REACH:
            if len(v) < 4:
                continue
            nh_len = v[3]
            nlri_off = 4 + nh_len + 1
        else:
            nlri_off = 3
        if nlri_off > len(v):
            continue
        problem = _flowspec_scan(v[nlri_off:])
        if problem:
            out.append(Finding(
                "PW-BGP-006", ("CVE-2026-37457",), 7.5,
                "Malformed BGP FlowSpec component (operator-value boundary)",
                "high", f"AFI {afi} SAFI {safi}: {problem}",
                _EXPOSURE_NOTE, afi=afi))
    return out


def d007_mp_reach(u: RawUpdate) -> list:
    """PW-BGP-007 -- CVE-2026-37458. Missing input validation in FRR's
    MP_REACH_NLRI handling. Checks the RFC 4760 structure end to end:
    [2B AFI][1B SAFI][1B nh_len][next hop][1B reserved][NLRI].
    Exercised for AFI 1 and AFI 2 (v6 next hops may be 16 or 32 bytes per
    RFC 2545 global+link-local)."""
    out = []
    for a in iter_attributes(u.attrs):
        if a.atype != ATTR_MP_REACH:
            continue
        if a.overrun:
            out.append(Finding(
                "PW-BGP-007", ("CVE-2026-37458",), 6.5,
                "Malformed MP_REACH_NLRI attribute (type 14)", "high",
                f"attribute 14 declared length {a.declared_len} overruns the "
                f"path-attribute block", _EXPOSURE_NOTE))
            continue
        v = a.value
        if len(v) < 4:
            out.append(Finding(
                "PW-BGP-007", ("CVE-2026-37458",), 6.5,
                "Truncated MP_REACH_NLRI attribute (type 14)", "high",
                f"attribute value is {len(v)} bytes; RFC 4760 requires at "
                f"least 4 (AFI+SAFI+next-hop length)", _EXPOSURE_NOTE))
            continue
        afi = struct.unpack("!H", v[:2])[0]
        safi = v[2]
        nh_len = v[3]
        if 4 + nh_len > len(v):
            out.append(Finding(
                "PW-BGP-007", ("CVE-2026-37458",), 6.5,
                "MP_REACH_NLRI next-hop length exceeds attribute", "high",
                f"AFI {afi} SAFI {safi}: next-hop length {nh_len} exceeds "
                f"{len(v) - 4} remaining bytes", _EXPOSURE_NOTE, afi=afi))
            continue
        if 4 + nh_len + 1 > len(v):
            out.append(Finding(
                "PW-BGP-007", ("CVE-2026-37458",), 6.5,
                "MP_REACH_NLRI missing reserved octet", "high",
                f"AFI {afi} SAFI {safi}: no room for the reserved octet after "
                f"a {nh_len}-byte next hop", _EXPOSURE_NOTE, afi=afi))
            continue
        # Next-hop length sanity. Skipped for FlowSpec (nh_len 0) and keyed
        # per-SAFI rather than purely per-AFI, because SR Policy decouples the
        # two: RFC 9830 s2.1 permits a 4-, 16- or 32-octet next hop on SAFI 73
        # regardless of whether the NLRI AFI is 1 or 2, so an AFI-keyed
        # expectation reports a malformation on a legal SRv6 policy that is
        # simply reachable over an IPv4 next hop.
        if safi == SAFI_SR_POLICY:
            if nh_len not in (4, 16, 32):
                out.append(Finding(
                    "PW-BGP-007", ("CVE-2026-37458",), 6.5,
                    "MP_REACH_NLRI implausible next-hop length for SR Policy",
                    "medium",
                    f"AFI {afi} SAFI 73: next-hop length {nh_len}; RFC 9830 "
                    f"permits 4, 16 or 32 octets", _EXPOSURE_NOTE, afi=afi))
        elif safi not in (SAFI_FLOWSPEC, SAFI_FLOWSPEC_VPN):
            expected = {AFI_IPV4: (4, 12), AFI_IPV6: (16, 32, 24, 48)}.get(afi)
            if expected and nh_len not in expected:
                out.append(Finding(
                    "PW-BGP-007", ("CVE-2026-37458",), 6.5,
                    "MP_REACH_NLRI implausible next-hop length for AFI",
                    "medium",
                    f"AFI {afi} SAFI {safi}: next-hop length {nh_len} is not a "
                    f"valid size for this address family "
                    f"(expected one of {expected})", _EXPOSURE_NOTE, afi=afi))
                continue
            if safi in PREFIX_SHAPED_SAFIS:
                bits = 128 if afi == AFI_IPV6 else 32
                _, overrun = walk_prefixes(v[4 + nh_len + 1:], bits)
                if overrun:
                    out.append(Finding(
                        "PW-BGP-007", ("CVE-2026-37458",), 6.5,
                        "MP_REACH_NLRI prefix list overruns attribute", "high",
                        f"AFI {afi} SAFI {safi}: NLRI prefix walk runs past "
                        f"the end of the attribute value",
                        _EXPOSURE_NOTE, afi=afi))
    return out


def d008_nhc_tlv(u: RawUpdate, nhc_type: int = ATTR_NHC_DEFAULT) -> list:
    """PW-BGP-008 -- CVE-2026-37459. Integer underflow validating the NHC TLV
    header length in FRR's bgp_attr.c: a declared length below the TLV header
    minimum makes (length - MIN_LEN) wrap.

    NOTE: the NHC attribute code point is draft-stage (see ATTR_NHC_DEFAULT).
    Confirm against your FRR build before relying on this detector.
    """
    out = []
    for a in iter_attributes(u.attrs):
        if a.atype != nhc_type:
            continue
        if a.overrun:
            out.append(Finding(
                "PW-BGP-008", ("CVE-2026-37459",), 7.5,
                "Malformed BGP NHC attribute", "high",
                f"NHC attribute (type {nhc_type}) declared length "
                f"{a.declared_len} overruns the path-attribute block",
                _EXPOSURE_NOTE))
            continue
        v = a.value
        i = 0
        while i < len(v):
            if i + NHC_TLV_MIN_LEN > len(v):
                out.append(Finding(
                    "PW-BGP-008", ("CVE-2026-37459",), 7.5,
                    "BGP NHC TLV header truncated", "high",
                    f"NHC TLV at offset {i}: only {len(v) - i} bytes remain, "
                    f"below the {NHC_TLV_MIN_LEN}-byte TLV header minimum",
                    _EXPOSURE_NOTE))
                break
            tlv_len = struct.unpack("!H", v[i + 1:i + 3])[0]
            if tlv_len < NHC_TLV_MIN_LEN:
                out.append(Finding(
                    "PW-BGP-008", ("CVE-2026-37459",), 7.5,
                    "BGP NHC TLV length below header minimum (underflow)",
                    "high",
                    f"NHC TLV at offset {i} declares length {tlv_len}, below "
                    f"the {NHC_TLV_MIN_LEN}-byte minimum; "
                    f"length - MIN_LEN underflows", _EXPOSURE_NOTE))
                break
            if i + tlv_len > len(v):
                out.append(Finding(
                    "PW-BGP-008", ("CVE-2026-37459",), 7.5,
                    "BGP NHC TLV length exceeds attribute", "high",
                    f"NHC TLV at offset {i} declares length {tlv_len}, "
                    f"exceeding {len(v) - i} remaining bytes", _EXPOSURE_NOTE))
                break
            i += tlv_len
    return out


def d009_ipv6_ext_communities(u: RawUpdate) -> list:
    """PW-BGP-009 -- CVE-2026-37461. OOB read in GoBGP's ParseIP6Extended.

    RFC 5701: each IPv6 Address Specific Extended Community is exactly 20
    octets (2 type + 16 global admin + 2 local admin). A value length that is
    not a multiple of 20 leaves a short trailing chunk that the parser reads
    past. This is the cleanest signature in the set and is inherently IPv6.
    """
    out = []
    for a in iter_attributes(u.attrs):
        if a.atype != ATTR_IPV6_EXT_COMMUNITIES:
            continue
        if a.overrun:
            out.append(Finding(
                "PW-BGP-009", ("CVE-2026-37461",), 7.5,
                "Malformed IPv6 Address Specific Extended Community (type 25)",
                "high",
                f"attribute 25 declared length {a.declared_len} overruns the "
                f"path-attribute block", _EXPOSURE_NOTE, afi=AFI_IPV6))
            continue
        if len(a.value) % 20 != 0:
            out.append(Finding(
                "PW-BGP-009", ("CVE-2026-37461",), 7.5,
                "IPv6 Extended Communities length not a multiple of 20",
                "high",
                f"attribute 25 value is {len(a.value)} bytes; RFC 5701 "
                f"communities are 20 bytes each, leaving a "
                f"{len(a.value) % 20}-byte trailing read past the buffer",
                _EXPOSURE_NOTE, afi=AFI_IPV6))
    return out


def d010_update_underflow(u: RawUpdate) -> list:
    """PW-BGP-010 -- CVE-2026-37462. Integer underflow in GoBGP's
    BGPUpdate.DecodeFromBytes: a declared withdrawn-routes or path-attribute
    length larger than the remaining body makes the "bytes remaining"
    computation wrap in unsigned arithmetic."""
    if not u.underflow:
        return []
    return [Finding(
        "PW-BGP-010", ("CVE-2026-37462",), 7.5,
        "BGP UPDATE length field exceeds message body (integer underflow)",
        "high", u.underflow_detail, _EXPOSURE_NOTE)]


def d011_open_ext_optparm(body: bytes) -> list:
    """PW-BGP-011 -- CVE-2022-40302. A BGP OPEN optional parameter of type
    0xFF is the RFC 9072 extended-length form, which needs a 3-byte read where
    FRR's boundary checks assumed 2."""
    out = []
    if len(body) < 10:
        return out
    opt_len = body[9]
    opts = body[10:10 + opt_len]
    if 10 + opt_len > len(body):
        return out                       # handled by d012
    i = 0
    while i < len(opts):
        ptype = opts[i]
        if ptype == 0xFF:
            # extended form: [type][2B length]
            if i + 3 > len(opts):
                out.append(Finding(
                    "PW-BGP-011", ("CVE-2022-40302",), 6.5,
                    "BGP OPEN extended optional parameter (type 0xFF) "
                    "truncated", "high",
                    f"parameter type 0xFF at offset {i} needs a 3-byte header "
                    f"but only {len(opts) - i} bytes remain", _EXPOSURE_NOTE))
                break
            plen = struct.unpack("!H", opts[i + 1:i + 3])[0]
            if i + 3 + plen > len(opts):
                out.append(Finding(
                    "PW-BGP-011", ("CVE-2022-40302",), 6.5,
                    "BGP OPEN extended optional parameter length overruns",
                    "high",
                    f"parameter type 0xFF at offset {i} declares length "
                    f"{plen}, exceeding {len(opts) - i - 3} remaining bytes",
                    _EXPOSURE_NOTE))
                break
            out.append(Finding(
                "PW-BGP-011", ("CVE-2022-40302",), 6.5,
                "BGP OPEN with RFC 9072 extended optional parameter (0xFF)",
                "low",
                f"parameter type 0xFF present at offset {i} with length {plen}; "
                f"this is the encoding whose 3-byte read FRR mis-bounded",
                _EXPOSURE_NOTE + "; RFC 9072 is legitimate on modern speakers, "
                "so this is reported as exposure surface, not an attack"))
            i += 3 + plen
        else:
            if i + 2 > len(opts):
                break
            plen = opts[i + 1]
            i += 2 + plen
    return out


def d012_open_truncated_optparm(body: bytes) -> list:
    """PW-BGP-012 -- CVE-2022-43681. An OPEN that ends exactly at the optional
    parameter length octet makes FRR read past the packet and SIGABRT."""
    out = []
    if len(body) < 9:
        out.append(Finding(
            "PW-BGP-012", ("CVE-2022-43681",), 6.5,
            "BGP OPEN truncated before the optional parameter length", "high",
            f"OPEN body is {len(body)} bytes; the fixed header alone requires "
            f"10", _EXPOSURE_NOTE))
        return out
    if len(body) == 9:
        out.append(Finding(
            "PW-BGP-012", ("CVE-2022-43681",), 6.5,
            "BGP OPEN ends exactly at the optional parameter length octet",
            "high",
            "OPEN body is 9 bytes: the opt-parm-len octet itself is absent, "
            "which is the out-of-bounds read condition", _EXPOSURE_NOTE))
        return out
    opt_len = body[9]
    if 10 + opt_len > len(body):
        out.append(Finding(
            "PW-BGP-012", ("CVE-2022-43681",), 6.5,
            "BGP OPEN optional parameter length exceeds message", "high",
            f"opt_parm_len={opt_len} but only {len(body) - 10} bytes follow",
            _EXPOSURE_NOTE))
    return out


# --------------------------------------------------------------------------- #
# Session correlation -- CVE-2026-93345's post-trigger artifact
# --------------------------------------------------------------------------- #
class BgpCveTracker:
    """Correlates a PW-BGP-013 trigger with the way the CVE says the session
    then dies: torn down with NO NOTIFICATION message.

    Standing alone, an abnormal close is weak evidence -- a TCP reset can come
    from a firewall, a reload, or anything else -- so it is never reported on
    its own. It is only emitted when all three hold on the same flow:

        1. a PW-BGP-013 trigger was seen,
        2. the session then tore down,
        3. no NOTIFICATION was seen on that flow at any point.

    That combination is the CVE's signature end to end, which makes
    PW-BGP-014 a confirmation ("the trigger landed and the plane dropped")
    rather than another attempt indicator. Bounded per-flow state.
    """

    MAX_FLOWS = 4096
    WINDOW_S = 120.0

    def __init__(self, window_s: float = WINDOW_S):
        self.window_s = window_s
        self.flows: dict = {}

    def _state(self, flow) -> dict:
        st = self.flows.get(flow)
        if st is None:
            if len(self.flows) >= self.MAX_FLOWS:
                self.flows.clear()
            st = {"trigger_ts": None, "notification": False,
                  "afi": None, "family": 0, "reported": False}
            self.flows[flow] = st
        return st

    def note_message(self, flow, msg_type: int, findings: list,
                     ts: Optional[float] = None) -> None:
        """Record what this message means for the correlation. Takes the
        already-computed findings so the detectors are not run twice."""
        st = self._state(flow)
        if msg_type == NOTIFICATION:
            st["notification"] = True
        for f in findings or ():
            if f.code == "PW-BGP-013":
                st["trigger_ts"] = ts if ts is not None else time.time()
                st["afi"] = f.afi
                st["family"] = f.family or st["family"]

    def note_teardown(self, flow, ts: Optional[float] = None,
                      src: str = "", dst: str = "", family: int = 0) -> list:
        """Call when the tap sees the session close (RST/FIN).

        Stamps flow context onto the finding itself rather than relying on the
        caller to do it: this finding is produced at teardown, when no message
        is in hand to carry src/dst/family, so leaving it to the caller makes
        an unstamped finding the easy mistake. src/dst/family are taken from
        the flow tuple when not supplied.
        """
        st = self.flows.get(flow)
        if st is None:
            return []
        self.flows.pop(flow, None)
        if st["reported"] or st["trigger_ts"] is None or st["notification"]:
            return []
        now = ts if ts is not None else time.time()
        if now - st["trigger_ts"] > self.window_s:
            return []
        st["reported"] = True
        # flow is (src, sport, dst, dport) as keyed by bgptap
        f_src = src or (flow[0] if isinstance(flow, tuple) and flow else "")
        f_dst = dst or (flow[2] if isinstance(flow, tuple) and len(flow) > 2
                        else "")
        fam = family or st.get("family") or 0
        return [Finding(
            "PW-BGP-014", ("CVE-2026-93345",), 7.5,
            "BGP session torn down with no NOTIFICATION after a labelled-VPN "
            "NLRI trigger", "high",
            f"a PW-BGP-013 malformation was observed on this session "
            f"{now - st['trigger_ts']:.1f}s before it closed, and no "
            f"NOTIFICATION was sent -- the exact post-trigger artifact "
            f"CVE-2026-93345 describes",
            "confirms the trigger was followed by an abnormal close on the "
            "same session; reported only in combination with PW-BGP-013 and "
            "only when no NOTIFICATION was seen, because an abnormal close on "
            "its own is ordinary and would be noise",
            src=f_src, dst=f_dst, family=fam, afi=st["afi"])]


# --------------------------------------------------------------------------- #
# Registry / dispatch
# --------------------------------------------------------------------------- #
UPDATE_DETECTORS = (
    d001_tunnel_encap,
    d002_zero_attrlen_with_nlri,
    d003_mp_unreach_missing_mandatory,
    d004_eor_malformed,
    d005_prefix_sid,
    d006_flowspec,
    d007_mp_reach,
    d009_ipv6_ext_communities,
    d010_update_underflow,
)

OPEN_DETECTORS = (
    d011_open_ext_optparm,
    d012_open_truncated_optparm,
)

# code -> (CVEs, CVSS) for reporting/inventory
REGISTRY = {
    "PW-BGP-001": (_ENCAP_CVES, 7.5),
    "PW-BGP-002": (("CVE-2023-41358",), 7.5),
    "PW-BGP-003": (("CVE-2023-47234",), 7.5),
    "PW-BGP-004": (("CVE-2023-47235",), 7.5),
    "PW-BGP-005": (("CVE-2024-31948",), 6.5),
    "PW-BGP-006": (("CVE-2026-37457",), 7.5),
    "PW-BGP-007": (("CVE-2026-37458",), 6.5),
    "PW-BGP-008": (("CVE-2026-37459",), 7.5),
    "PW-BGP-009": (("CVE-2026-37461",), 7.5),
    "PW-BGP-010": (("CVE-2026-37462",), 7.5),
    "PW-BGP-011": (("CVE-2022-40302",), 6.5),
    "PW-BGP-012": (("CVE-2022-43681",), 6.5),
    "PW-BGP-013": (("CVE-2026-93345",), 7.5),
    "PW-BGP-014": (("CVE-2026-93345",), 7.5),
}


def inspect_message(msg_type: int, body: bytes,
                    nhc_type: int = ATTR_NHC_DEFAULT,
                    vpn_safis: tuple = (SAFI_MPLS_VPN,)) -> list:
    """Run every applicable detector over one BGP message body.

    Never raises: a detector that fails is contained so one malformed message
    cannot silence the rest of the tier.
    """
    findings: list = []
    if msg_type == bgp.UPDATE:
        u = walk_update(body)
        for det in UPDATE_DETECTORS:
            try:
                findings.extend(det(u))
            except Exception:
                continue
        try:
            findings.extend(d008_nhc_tlv(u, nhc_type))
        except Exception:
            pass
        try:
            findings.extend(d013_labelled_vpn_nlri(u, tuple(vpn_safis)))
        except Exception:
            pass
    elif msg_type == bgp.OPEN:
        for det in OPEN_DETECTORS:
            try:
                findings.extend(det(body))
            except Exception:
                continue
    return findings


def inspect_tap_message(msg, nhc_type: int = ATTR_NHC_DEFAULT,
                        vpn_safis: tuple = (SAFI_MPLS_VPN,)) -> list:
    """Run detectors over a bgptap.TapMessage, stamping flow context
    (including transport family, so v4/v6 parity is visible in output)."""
    findings = inspect_message(msg.msg_type, msg.body, nhc_type, vpn_safis)
    for f in findings:
        f.src = msg.src
        f.dst = msg.dst
        f.family = msg.family
    return findings
