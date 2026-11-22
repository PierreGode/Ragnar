"""
bgpsrte.py -- passive SR Policy (BGP-SRTE) and BGP-LS decode + injection posture.

ONE TIER, TWO NLRI FAMILIES
---------------------------
SR Policy (RFC 9830, AFI 1|2 / SAFI 73) and BGP-LS (RFC 9552, AFI 16388 /
SAFI 71) are decoded in the same pass. They ride the same TCP/179 session the
tap already reads, and they share one detection pattern -- a forged BGP
attribute carrying control-plane intent -- so splitting them into separate
modules would duplicate the session tracking for no gain.

NOT A CVE TIER
--------------
Neither family has CVEs. The abuse cases are not parser bugs:

  * SR Policy -- hijack-shaped, but for *traffic steering* rather than
    reachability. A forged SR Policy for a given (color, endpoint) redirects
    traffic onto an attacker-chosen segment list. The prefix still resolves;
    the path changes.
  * BGP-LS   -- forged topology fed to a PCE/controller, so downstream SR-TE
    path computation is computed over a lie.

Findings therefore carry no CVE and no CVSS, and are graded on confidence,
exactly like the BGPsec posture tier in bgpsec.py.

OVERLAP WITH THE CVE TIER (deliberate, do not "fix")
----------------------------------------------------
The Tunnel Encapsulation attribute (type 23) is also inspected by
bgpcve.d001_tunnel_encap, which reports CVE-2023-38802 / CVE-2024-30395 /
CVE-2024-44070 on a sub-TLV length that overruns. That is a *parser-crash*
concern. This module's concern is the *semantics* of tunnel type 15 (SR
Policy): what the segment list actually steers through. So this module does
NOT emit a generic "malformed type 23" finding -- that would double-alert on
the same bytes. It decodes what it can and reports only SR-Policy-specific
structure and posture.

DUAL-STACK
----------
Both families have genuinely distinct v4/v6 parse paths, so this is not a
"protocol-agnostic, parity is free" case:

  * SR Policy NLRI  -- endpoint is 4 octets (AFI 1) or 16 (AFI 2), and the
    NLRI length field is 96 or 192 *bits* respectively. Different sizes,
    different validation.
  * Segment lists   -- Segment Type A is an SR-MPLS label (4 octets);
    Segment Type B is a 128-bit SRv6 SID. These are the v4/v6 analogues of
    the same steering primitive. NOTE: Type B is codepoint 13, and codepoint
    2 is deprecated -- an easy and silent thing to get wrong.
  * BGP-LS         -- Prefix NLRI types 3 (IPv4 topology) and 4 (IPv6
    topology) are distinct; descriptor TLVs 259/260 (IPv4 interface/neighbour)
    and 261/262 (IPv6) are distinct; Router-ID TLVs 1028/1030 (v4) and
    1029/1031 (v6) are distinct.

Transport family (v4/v6 TCP) is orthogonal and stamped by the tap.

Layering: every decoder here is lenient -- it reports structural problems as
data and never raises, because the traffic worth catching is malformed by
construction.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

import bgp
from bgpcve import (Finding, RawUpdate, iter_attributes, iter_encap_subtlvs,
                    iter_tunnel_tlvs, walk_update)

# --- attribute / AFI / SAFI codepoints ------------------------------------- #
ATTR_TUNNEL_ENCAP = 23          # RFC 9012
ATTR_BGP_LS = 29                # RFC 9552
ATTR_MP_REACH = 14
ATTR_MP_UNREACH = 15

AFI_IPV4, AFI_IPV6 = 1, 2
AFI_BGP_LS = 16388
SAFI_SR_POLICY = 73
SAFI_BGP_LS = 71
SAFI_BGP_LS_VPN = 72

AFI_NAMES = {AFI_IPV4: "IPv4", AFI_IPV6: "IPv6", AFI_BGP_LS: "BGP-LS"}

# --- SR Policy (RFC 9830) -------------------------------------------------- #
TUNNEL_TYPE_SR_POLICY = 15
# tunnel-encaps sub-TLV namespace
SR_SUBTLV_PREFERENCE = 12
SR_SUBTLV_BINDING_SID = 13
SR_SUBTLV_ENLP = 14
SR_SUBTLV_PRIORITY = 15
SR_SUBTLV_SRV6_BINDING_SID = 20
SR_SUBTLV_SEGMENT_LIST = 128
SR_SUBTLV_CP_NAME = 129
SR_SUBTLV_POLICY_NAME = 130
# segment-list inner namespace (NOT the same namespace as above)
SEG_WEIGHT = 9
SEG_TYPE_A = 1                  # SR-MPLS label
SEG_TYPE_B = 13                 # SRv6 SID (codepoint 13, not 2)
SEG_TYPE_DEPRECATED = 2         # retired codepoint; must not appear
SEG_TYPES_EXT = {3: "C", 4: "D", 5: "E", 6: "F", 7: "G",
                 8: "H", 9: "I", 10: "J", 11: "K"}
SEG_TYPE_NAMES = {SEG_TYPE_A: "A (SR-MPLS label)", SEG_TYPE_B: "B (SRv6 SID)"}

SR_NLRI_BITS = {AFI_IPV4: 96, AFI_IPV6: 192}      # NLRI length field, in bits
SR_NLRI_OCTETS = {AFI_IPV4: 12, AFI_IPV6: 24}

MPLS_LABEL_MAX = (1 << 20) - 1
MPLS_LABEL_RESERVED_MAX = 15
SEGMENT_LIST_SANE_MAX = 48        # deeper than any real SR-TE path

# --- BGP-LS (RFC 9552 / RFC 9085) ------------------------------------------ #
LS_NLRI_NODE, LS_NLRI_LINK = 1, 2
LS_NLRI_PREFIX_V4, LS_NLRI_PREFIX_V6 = 3, 4
LS_NLRI_NAMES = {1: "Node", 2: "Link", 3: "IPv4 Topology Prefix",
                 4: "IPv6 Topology Prefix"}
LS_PROTO_NAMES = {1: "IS-IS L1", 2: "IS-IS L2", 3: "OSPFv2",
                  4: "Direct", 5: "Static", 6: "OSPFv3"}

LS_TLV_LOCAL_NODE, LS_TLV_REMOTE_NODE = 256, 257
LS_TLV_LINK_IDS = 258
LS_TLV_IPV4_IFACE, LS_TLV_IPV4_NEIGH = 259, 260
LS_TLV_IPV6_IFACE, LS_TLV_IPV6_NEIGH = 261, 262
LS_TLV_MT_ID, LS_TLV_OSPF_ROUTE_TYPE, LS_TLV_IP_REACH = 263, 264, 265
# node descriptor sub-TLVs
LS_SUB_AS, LS_SUB_LS_ID = 512, 513
LS_SUB_OSPF_AREA, LS_SUB_IGP_ROUTER_ID = 514, 515
# attribute TLVs (v4/v6 pairs matter for parity)
LS_ATTR_ROUTER_ID_V4_LOCAL, LS_ATTR_ROUTER_ID_V6_LOCAL = 1028, 1029
LS_ATTR_ROUTER_ID_V4_REMOTE, LS_ATTR_ROUTER_ID_V6_REMOTE = 1030, 1031
# SR attribute TLVs (RFC 9085)
LS_ATTR_SR_CAPS, LS_ATTR_SR_ALGO = 1034, 1035
LS_ATTR_SRLB, LS_ATTR_SRMS_PREF = 1036, 1037
LS_ATTR_ADJ_SID, LS_ATTR_LAN_ADJ_SID = 1099, 1100
LS_ATTR_PREFIX_SID, LS_ATTR_RANGE = 1158, 1159

_POSTURE_NOTE = ("structural/posture observation only -- a finding reports what "
                 "crossed the tap, never that a policy or topology is "
                 "authoritative or forged on its own; SR Policy and BGP-LS "
                 "have no CVEs, so this carries no CVE or CVSS")


# --------------------------------------------------------------------------- #
# generic lenient TLV walkers
# --------------------------------------------------------------------------- #
@dataclass
class Tlv:
    ttype: int
    tlen: int
    value: bytes
    overrun: bool = False
    truncated: bool = False


def iter_tlv16(data: bytes) -> Iterator[Tlv]:
    """2-octet type, 2-octet length (BGP-LS). Never raises."""
    i = 0
    n = len(data)
    while i < n:
        if i + 4 > n:
            yield Tlv(0, 0, data[i:], truncated=True)
            return
        t, l = struct.unpack("!HH", data[i:i + 4])
        i += 4
        over = (i + l) > n
        yield Tlv(t, l, data[i:i + l], overrun=over)
        if over:
            return
        i += l


def mp_families(u: RawUpdate) -> list:
    """Every (afi, safi, payload, attr_type) carried in MP_REACH/MP_UNREACH."""
    out = []
    for a in iter_attributes(u.attrs):
        if a.atype not in (ATTR_MP_REACH, ATTR_MP_UNREACH) or a.overrun:
            continue
        v = a.value
        if len(v) < 3:
            continue
        afi = struct.unpack("!H", v[:2])[0]
        safi = v[2]
        if a.atype == ATTR_MP_REACH:
            if len(v) < 4:
                continue
            nh_len = v[3]
            off = 4 + nh_len + 1          # next hop + reserved octet
            if off > len(v):
                continue
            out.append((afi, safi, v[off:], a.atype))
        else:
            out.append((afi, safi, v[3:], a.atype))
    return out


# --------------------------------------------------------------------------- #
# SR Policy NLRI
# --------------------------------------------------------------------------- #
@dataclass
class SrPolicyNlri:
    afi: int
    length_bits: int = 0
    distinguisher: int = 0
    color: int = 0
    endpoint: Optional[str] = None
    problems: list = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (self.distinguisher, self.color, self.endpoint)


def parse_sr_policy_nlri(data: bytes, afi: int) -> list:
    """Decode a run of SR Policy NLRI (RFC 9830 s2.1). Never raises.

    Wire: [1B length-in-BITS][4B distinguisher][4B color][endpoint 4 or 16].
    The length field being in bits, not octets, is the trap here.
    """
    out = []
    ep_len = 16 if afi == AFI_IPV6 else 4
    want_bits = SR_NLRI_BITS.get(afi)
    i = 0
    n = len(data)
    while i < n:
        p = SrPolicyNlri(afi=afi)
        p.length_bits = data[i]
        i += 1
        body_len = (p.length_bits + 7) // 8
        if want_bits is not None and p.length_bits != want_bits:
            p.problems.append(
                f"NLRI length field is {p.length_bits} bits; RFC 9830 requires "
                f"{want_bits} for AFI {afi} ({AFI_NAMES.get(afi, afi)})")
        if i + body_len > n:
            p.problems.append(
                f"NLRI body of {body_len} octet(s) exceeds the "
                f"{n - i} remaining")
            out.append(p)
            return out
        body = data[i:i + body_len]
        i += body_len
        if len(body) >= 8:
            p.distinguisher = struct.unpack("!I", body[:4])[0]
            p.color = struct.unpack("!I", body[4:8])[0]
            ep = body[8:8 + ep_len]
            if len(ep) == ep_len:
                try:
                    p.endpoint = (socket.inet_ntoa(ep) if ep_len == 4
                                  else socket.inet_ntop(socket.AF_INET6, ep))
                except OSError:
                    p.problems.append("endpoint is not a valid address")
            else:
                p.problems.append(
                    f"endpoint truncated: {len(ep)} of {ep_len} octet(s)")
        else:
            p.problems.append(
                f"NLRI body too short for distinguisher+color "
                f"({len(body)} octet(s))")
        out.append(p)
    return out


# --------------------------------------------------------------------------- #
# SR Policy tunnel-encaps contents
# --------------------------------------------------------------------------- #
@dataclass
class Segment:
    seg_type: int
    length: int
    label: Optional[int] = None       # Type A
    sid: Optional[str] = None         # Type B
    problems: list = field(default_factory=list)


@dataclass
class SegmentList:
    weight: Optional[int] = None
    segments: list = field(default_factory=list)
    problems: list = field(default_factory=list)


@dataclass
class SrPolicyTunnel:
    preference: Optional[int] = None
    binding_sid: Optional[bytes] = None
    srv6_binding_sid: Optional[bytes] = None
    priority: Optional[int] = None
    segment_lists: list = field(default_factory=list)
    problems: list = field(default_factory=list)
    present: bool = False


def parse_segment_list(value: bytes) -> SegmentList:
    sl = SegmentList()
    for sub in iter_encap_subtlvs(value):
        if sub.truncated:
            sl.problems.append("segment sub-TLV header truncated")
            break
        if sub.overrun:
            sl.problems.append(
                f"segment sub-TLV type {sub.ttype} length {sub.tlen} overruns "
                f"the segment list")
            break
        if sub.ttype == SEG_WEIGHT:
            if len(sub.value) >= 6:
                sl.weight = struct.unpack("!I", sub.value[2:6])[0]
            continue
        seg = Segment(sub.ttype, sub.tlen)
        if sub.ttype == SEG_TYPE_DEPRECATED:
            seg.problems.append(
                "segment type codepoint 2 is deprecated and must not be used")
        elif sub.ttype == SEG_TYPE_A:
            # [1B flags][1B reserved][4B label entry]
            if sub.tlen != 6:
                seg.problems.append(
                    f"Segment Type A length {sub.tlen}; RFC 9830 requires 6")
            if len(sub.value) >= 6:
                entry = struct.unpack("!I", sub.value[2:6])[0]
                seg.label = entry >> 12
                if seg.label > MPLS_LABEL_MAX:
                    seg.problems.append(
                        f"MPLS label {seg.label} exceeds the 20-bit maximum")
                elif seg.label <= MPLS_LABEL_RESERVED_MAX:
                    seg.problems.append(
                        f"MPLS label {seg.label} is in the reserved range "
                        f"0-{MPLS_LABEL_RESERVED_MAX}")
        elif sub.ttype == SEG_TYPE_B:
            if sub.tlen not in (18, 26):
                seg.problems.append(
                    f"Segment Type B length {sub.tlen}; RFC 9830 requires 18, "
                    f"or 26 with the SRv6 endpoint behaviour structure")
            if len(sub.value) >= 18:
                try:
                    seg.sid = socket.inet_ntop(socket.AF_INET6,
                                               sub.value[2:18])
                except OSError:
                    seg.problems.append("SRv6 SID is not a valid IPv6 address")
        elif sub.ttype not in SEG_TYPES_EXT:
            seg.problems.append(
                f"segment type {sub.ttype} is not an assigned codepoint")
        sl.segments.append(seg)
    return sl


def parse_sr_policy_tunnel(attr_value: bytes) -> SrPolicyTunnel:
    """Decode tunnel type 15 inside a Tunnel Encapsulation attribute.

    Uses the shared RFC 9012 walkers in bgpcve so the two tiers cannot drift
    on the framing: Tunnel TLV length is 2 octets, sub-TLV length is 1 or 2
    octets by type.

    Structural malformation of the attribute itself is the CVE tier's job
    (bgpcve PW-BGP-001); here we stop cleanly on it and report only what SR
    Policy semantics require.
    """
    t = SrPolicyTunnel()
    for tlv in iter_tunnel_tlvs(attr_value):
        if tlv.truncated or tlv.overrun:
            return t                         # malformed: CVE tier reports it
        if tlv.ttype != TUNNEL_TYPE_SR_POLICY:
            continue
        t.present = True
        for sub in iter_encap_subtlvs(tlv.value):
            if sub.truncated or sub.overrun:
                t.problems.append(
                    f"SR Policy sub-TLV type {sub.ttype} is truncated or "
                    f"overruns the tunnel TLV")
                break
            if sub.ttype == SR_SUBTLV_PREFERENCE and len(sub.value) >= 6:
                t.preference = struct.unpack("!I", sub.value[2:6])[0]
            elif sub.ttype == SR_SUBTLV_BINDING_SID:
                t.binding_sid = sub.value
                if sub.tlen not in (2, 6, 18):
                    t.problems.append(
                        f"Binding SID length {sub.tlen}; RFC 9830 allows "
                        f"2, 6 or 18")
            elif sub.ttype == SR_SUBTLV_SRV6_BINDING_SID:
                t.srv6_binding_sid = sub.value
                if sub.tlen not in (18, 26):
                    t.problems.append(
                        f"SRv6 Binding SID length {sub.tlen}; RFC 9830 allows "
                        f"18 or 26")
            elif sub.ttype == SR_SUBTLV_PRIORITY and len(sub.value) >= 1:
                t.priority = sub.value[0]
            elif sub.ttype == SR_SUBTLV_SEGMENT_LIST:
                t.segment_lists.append(parse_segment_list(sub.value))
    return t


# --------------------------------------------------------------------------- #
# BGP-LS NLRI
# --------------------------------------------------------------------------- #
@dataclass
class LsNlri:
    nlri_type: int = 0
    total_len: int = 0
    proto_id: int = 0
    identifier: int = 0
    local_as: Optional[int] = None
    igp_router_id: Optional[bytes] = None
    descriptors: list = field(default_factory=list)   # TLV types seen
    problems: list = field(default_factory=list)

    @property
    def type_name(self) -> str:
        return LS_NLRI_NAMES.get(self.nlri_type, f"type {self.nlri_type}")


def parse_ls_nlri(data: bytes, safi: int = SAFI_BGP_LS) -> list:
    """Decode a run of Link-State NLRI (RFC 9552 s5.2). Never raises.

    Wire: [2B type][2B total length]{[8B RD if VPN]}[1B proto][8B identifier]
          [descriptor TLVs...]
    """
    out = []
    i = 0
    n = len(data)
    while i < n:
        o = LsNlri()
        if i + 4 > n:
            o.problems.append("NLRI header truncated")
            out.append(o)
            return out
        o.nlri_type, o.total_len = struct.unpack("!HH", data[i:i + 4])
        i += 4
        if i + o.total_len > n:
            o.problems.append(
                f"NLRI total length {o.total_len} exceeds the {n - i} "
                f"remaining octet(s)")
            out.append(o)
            return out
        body = data[i:i + o.total_len]
        i += o.total_len

        if o.nlri_type not in LS_NLRI_NAMES:
            o.problems.append(
                f"Link-State NLRI type {o.nlri_type} is not assigned "
                f"(RFC 9552 defines 1-4)")

        j = 0
        if safi == SAFI_BGP_LS_VPN:
            if len(body) < 8:
                o.problems.append("VPN NLRI shorter than its route distinguisher")
                out.append(o)
                continue
            j = 8
        if len(body) < j + 9:
            o.problems.append(
                "NLRI body too short for protocol-ID and identifier")
            out.append(o)
            continue
        o.proto_id = body[j]
        o.identifier = struct.unpack("!Q", body[j + 1:j + 9])[0]
        if o.proto_id not in LS_PROTO_NAMES:
            o.problems.append(
                f"protocol-ID {o.proto_id} is not assigned "
                f"(RFC 9552 defines 1-6)")
        j += 9

        for tlv in iter_tlv16(body[j:]):
            if tlv.truncated:
                o.problems.append("descriptor TLV header truncated")
                break
            if tlv.overrun:
                o.problems.append(
                    f"descriptor TLV {tlv.ttype} length {tlv.tlen} overruns "
                    f"the NLRI")
                break
            o.descriptors.append(tlv.ttype)
            if tlv.ttype in (LS_TLV_LOCAL_NODE, LS_TLV_REMOTE_NODE):
                for sub in iter_tlv16(tlv.value):
                    if sub.truncated or sub.overrun:
                        o.problems.append(
                            "node descriptor sub-TLV truncated or overruns")
                        break
                    if (sub.ttype == LS_SUB_AS and len(sub.value) >= 4
                            and tlv.ttype == LS_TLV_LOCAL_NODE):
                        o.local_as = struct.unpack("!I", sub.value[:4])[0]
                    elif (sub.ttype == LS_SUB_IGP_ROUTER_ID
                            and tlv.ttype == LS_TLV_LOCAL_NODE):
                        o.igp_router_id = sub.value

        if LS_TLV_LOCAL_NODE not in o.descriptors:
            o.problems.append(
                "mandatory Local Node Descriptors TLV (256) is absent")
        out.append(o)
    return out


# --------------------------------------------------------------------------- #
# session state -- negotiation and conflict tracking
# --------------------------------------------------------------------------- #
CAP_MP_BGP = 1


def negotiated_families(open_body: bytes) -> set:
    """(afi, safi) pairs advertised in an OPEN's MP-BGP capabilities."""
    out = set()
    try:
        from bgpsec import iter_capabilities
    except Exception:
        return out
    for code, val in iter_capabilities(open_body):
        if code == CAP_MP_BGP and len(val) >= 4:
            afi = struct.unpack("!H", val[:2])[0]
            out.add((afi, val[3]))
    return out


def open_my_as(open_body: bytes) -> Optional[int]:
    try:
        return bgp.parse_open(open_body).my_as
    except Exception:
        return None


@dataclass
class SrteSession:
    families: set = field(default_factory=set)
    open_as: list = field(default_factory=list)
    policies: dict = field(default_factory=dict)      # key -> (origin, seglists)
    ls_nodes: dict = field(default_factory=dict)      # router-id -> (as, origin)
    reported: set = field(default_factory=set)

    @property
    def ebgp(self) -> Optional[bool]:
        """True/False once both OPENs are seen; None while undetermined."""
        if len(self.open_as) < 2:
            return None
        return self.open_as[0] != self.open_as[1]


class SrteTracker:
    """Per-flow SR Policy / BGP-LS session state.

    Carries three things a single message cannot know: which AFI/SAFI pairs the
    session actually negotiated, whether the session is eBGP or iBGP, and
    whether two origins have advertised conflicting intent for the same policy
    key or node identity.
    """

    MAX_FLOWS = 4096

    def __init__(self, segment_list_max: int = SEGMENT_LIST_SANE_MAX):
        self.sessions: dict = {}
        self.segment_list_max = segment_list_max

    def _state(self, flow) -> SrteSession:
        st = self.sessions.get(flow)
        if st is None:
            if len(self.sessions) >= self.MAX_FLOWS:
                self.sessions.clear()
            st = SrteSession()
            self.sessions[flow] = st
        return st

    def observe_open(self, flow, open_body: bytes) -> list:
        st = self._state(flow)
        st.families |= negotiated_families(open_body)
        a = open_my_as(open_body)
        if a is not None and len(st.open_as) < 2:
            st.open_as.append(a)
        return []

    def observe_update(self, flow, body: bytes) -> list:
        st = self._state(flow)
        u = walk_update(body)
        findings = inspect_update(u, segment_list_max=self.segment_list_max)
        findings += self._stateful(st, u, flow)
        return findings

    def _stateful(self, st: SrteSession, u: RawUpdate, flow) -> list:
        out = []
        for afi, safi, payload, atype in mp_families(u):
            is_sr = (safi == SAFI_SR_POLICY and afi in (AFI_IPV4, AFI_IPV6))
            is_ls = (afi == AFI_BGP_LS and safi in (SAFI_BGP_LS,
                                                    SAFI_BGP_LS_VPN))
            if not (is_sr or is_ls):
                continue

            # negotiation check: NLRI for a family the session never announced
            if st.families and (afi, safi) not in st.families:
                key = ("nonneg", afi, safi)
                if key not in st.reported:
                    st.reported.add(key)
                    code = "SRTE-010" if is_sr else "BGPLS-010"
                    out.append(Finding(
                        code, (), 0.0,
                        ("SR Policy NLRI on a session that never negotiated "
                         "AFI/SAFI 73" if is_sr else
                         "BGP-LS NLRI on a session that never negotiated "
                         "AFI 16388/SAFI 71"),
                        "high",
                        f"AFI {afi}/SAFI {safi} NLRI present, but the OPEN "
                        f"advertised only "
                        f"{sorted(st.families)}; a speaker must not send NLRI "
                        f"for an unnegotiated family",
                        _POSTURE_NOTE, afi=afi))

            if is_sr and atype == ATTR_MP_REACH:
                out += self._sr_stateful(st, u, afi, payload)
            if is_ls and atype == ATTR_MP_REACH:
                out += self._ls_stateful(st, payload, safi, afi)
        return out

    def _sr_stateful(self, st, u: RawUpdate, afi: int, payload: bytes) -> list:
        out = []
        # SR Policy is normally iBGP: controller -> headend. On eBGP it is a
        # third party steering your traffic.
        if st.ebgp is True:
            key = ("ebgp-sr", afi)
            if key not in st.reported:
                st.reported.add(key)
                out.append(Finding(
                    "SRTE-011", (), 0.0,
                    "SR Policy received on an eBGP session", "medium",
                    f"session AS {st.open_as[0]} <-> AS {st.open_as[1]} is "
                    f"eBGP and is carrying AFI {afi}/SAFI 73; SR Policy is "
                    f"normally iBGP from a controller to its headend",
                    _POSTURE_NOTE, afi=afi))

        tun = None
        for a in iter_attributes(u.attrs):
            if a.atype == ATTR_TUNNEL_ENCAP and not a.overrun:
                tun = parse_sr_policy_tunnel(a.value)
                break
        sig = None
        if tun is not None:
            sig = tuple(tuple((s.seg_type, s.label, s.sid)
                              for s in sl.segments)
                        for sl in tun.segment_lists)

        for p in parse_sr_policy_nlri(payload, afi):
            if p.endpoint is None:
                continue
            prev = st.policies.get(p.key)
            if prev is None:
                st.policies[p.key] = sig
            elif sig is not None and prev is not None and prev != sig:
                key = ("sr-conflict", p.key)
                if key not in st.reported:
                    st.reported.add(key)
                    out.append(Finding(
                        "SRTE-012", (), 0.0,
                        "Conflicting SR Policy for the same colour and endpoint",
                        "high",
                        f"policy (distinguisher {p.key[0]}, colour {p.key[1]}, "
                        f"endpoint {p.key[2]}) has been advertised with two "
                        f"different segment lists on this session -- the later "
                        f"one re-steers traffic already matching that colour",
                        _POSTURE_NOTE, afi=afi))
                st.policies[p.key] = sig
        return out

    def _ls_stateful(self, st, payload: bytes, safi: int, afi: int) -> list:
        out = []
        for o in parse_ls_nlri(payload, safi):
            # forged topology: the node claims an AS the session cannot speak for
            if (o.local_as is not None and st.ebgp is True
                    and len(st.open_as) == 2
                    and o.local_as not in st.open_as):
                key = ("ls-as", o.local_as)
                if key not in st.reported:
                    st.reported.add(key)
                    out.append(Finding(
                        "BGPLS-011", (), 0.0,
                        "BGP-LS node descriptor claims an AS unrelated to the "
                        "session", "high",
                        f"{o.type_name} NLRI advertises Autonomous System "
                        f"{o.local_as}, which is neither endpoint of this eBGP "
                        f"session (AS {st.open_as[0]} <-> AS {st.open_as[1]}); "
                        f"topology attributed to a third-party AS would "
                        f"mislead a PCE computing paths over it",
                        _POSTURE_NOTE, afi=afi))
            if o.igp_router_id and o.local_as is not None:
                prev = st.ls_nodes.get(o.igp_router_id)
                if prev is None:
                    st.ls_nodes[o.igp_router_id] = o.local_as
                elif prev != o.local_as:
                    key = ("ls-node", o.igp_router_id)
                    if key not in st.reported:
                        st.reported.add(key)
                        out.append(Finding(
                            "BGPLS-012", (), 0.0,
                            "BGP-LS node identity conflict", "high",
                            f"IGP Router-ID {o.igp_router_id.hex()} has been "
                            f"advertised under AS {prev} and AS {o.local_as} "
                            f"on this session; one of the two topologies is "
                            f"not real",
                            _POSTURE_NOTE, afi=afi))
                    st.ls_nodes[o.igp_router_id] = o.local_as
        return out


# --------------------------------------------------------------------------- #
# stateless inspection
# --------------------------------------------------------------------------- #
def _sr_findings(afi: int, payload: bytes, u: RawUpdate,
                 segment_list_max: int) -> list:
    out = []
    policies = parse_sr_policy_nlri(payload, afi)
    for p in policies:
        if p.problems:
            out.append(Finding(
                "SRTE-002", (), 0.0,
                "Malformed SR Policy NLRI", "high",
                "; ".join(p.problems[:3]), _POSTURE_NOTE, afi=afi))
        else:
            out.append(Finding(
                "SRTE-001", (), 0.0,
                "SR Policy NLRI observed", "high",
                f"distinguisher {p.distinguisher}, colour {p.color}, endpoint "
                f"{p.endpoint} ({AFI_NAMES.get(afi, afi)})",
                _POSTURE_NOTE + "; informational inventory", afi=afi))
        if not p.problems and p.color == 0:
            out.append(Finding(
                "SRTE-004", (), 0.0,
                "SR Policy with colour zero", "medium",
                "RFC 9830 requires the policy colour to be a non-zero "
                "unsigned integer", _POSTURE_NOTE, afi=afi))

    for a in iter_attributes(u.attrs):
        if a.atype != ATTR_TUNNEL_ENCAP or a.overrun:
            continue
        tun = parse_sr_policy_tunnel(a.value)
        if not tun.present:
            continue
        for prob in tun.problems[:3]:
            out.append(Finding(
                "SRTE-026", (), 0.0,
                "Malformed SR Policy sub-TLV", "high", prob,
                _POSTURE_NOTE, afi=afi))
        if not tun.segment_lists:
            out.append(Finding(
                "SRTE-020", (), 0.0,
                "SR Policy tunnel with no Segment List", "high",
                "tunnel type 15 is present but carries no Segment List "
                "sub-TLV (128), so the policy specifies no path",
                _POSTURE_NOTE, afi=afi))
        for sl in tun.segment_lists:
            for prob in sl.problems[:2]:
                out.append(Finding(
                    "SRTE-026", (), 0.0,
                    "Malformed SR Policy Segment List", "high", prob,
                    _POSTURE_NOTE, afi=afi))
            if not sl.segments and not sl.problems:
                out.append(Finding(
                    "SRTE-021", (), 0.0,
                    "SR Policy Segment List with no segments", "high",
                    "an empty segment list steers traffic onto an undefined "
                    "path", _POSTURE_NOTE, afi=afi))
            if len(sl.segments) > segment_list_max:
                out.append(Finding(
                    "SRTE-027", (), 0.0,
                    "SR Policy Segment List implausibly deep", "medium",
                    f"{len(sl.segments)} segments (threshold "
                    f"{segment_list_max}); a stack this deep is far beyond a "
                    f"real SR-TE path and inflates the label stack",
                    _POSTURE_NOTE, afi=afi))
            for seg in sl.segments:
                if seg.seg_type == SEG_TYPE_DEPRECATED:
                    out.append(Finding(
                        "SRTE-022", (), 0.0,
                        "SR Policy uses the deprecated segment type codepoint 2",
                        "high", "; ".join(seg.problems) or
                        "codepoint 2 is deprecated", _POSTURE_NOTE, afi=afi))
                elif seg.seg_type in (SEG_TYPE_A, SEG_TYPE_B):
                    for prob in seg.problems[:2]:
                        code = ("SRTE-024" if seg.seg_type == SEG_TYPE_A
                                else "SRTE-025")
                        out.append(Finding(
                            code, (), 0.0,
                            f"Malformed SR Policy Segment Type "
                            f"{SEG_TYPE_NAMES[seg.seg_type]}",
                            "high", prob, _POSTURE_NOTE, afi=afi))
                elif seg.seg_type not in SEG_TYPES_EXT:
                    out.append(Finding(
                        "SRTE-023", (), 0.0,
                        "SR Policy unknown segment type", "medium",
                        "; ".join(seg.problems) or
                        f"segment type {seg.seg_type} is unassigned",
                        _POSTURE_NOTE, afi=afi))
    return out


def _ls_findings(afi: int, safi: int, payload: bytes, u: RawUpdate) -> list:
    out = []
    for o in parse_ls_nlri(payload, safi):
        if o.problems:
            out.append(Finding(
                "BGPLS-002" if o.nlri_type not in LS_NLRI_NAMES
                else "BGPLS-003", (), 0.0,
                "Malformed BGP-LS NLRI", "high",
                f"{o.type_name}: " + "; ".join(o.problems[:3]),
                _POSTURE_NOTE, afi=afi))
        else:
            out.append(Finding(
                "BGPLS-001", (), 0.0,
                "BGP-LS NLRI observed", "high",
                f"{o.type_name} via "
                f"{LS_PROTO_NAMES.get(o.proto_id, o.proto_id)}"
                + (f", AS {o.local_as}" if o.local_as else ""),
                _POSTURE_NOTE + "; informational inventory", afi=afi))

    for a in iter_attributes(u.attrs):
        if a.atype != ATTR_BGP_LS or a.overrun:
            continue
        for tlv in iter_tlv16(a.value):
            if tlv.truncated or tlv.overrun:
                out.append(Finding(
                    "BGPLS-021", (), 0.0,
                    "Malformed BGP-LS attribute TLV", "high",
                    f"TLV {tlv.ttype} length {tlv.tlen} overruns or truncates "
                    f"the BGP-LS attribute", _POSTURE_NOTE, afi=afi))
                break
            if tlv.ttype in (LS_ATTR_SR_CAPS, LS_ATTR_SRLB):
                name = ("SR Capabilities (SRGB)"
                        if tlv.ttype == LS_ATTR_SR_CAPS else "SR Local Block")
                for prob in _check_sr_range(tlv.value):
                    out.append(Finding(
                        "BGPLS-022", (), 0.0,
                        f"BGP-LS {name} declares an invalid label range",
                        "high", prob + " -- a controller allocating SIDs from "
                        "this range would program unusable or colliding labels",
                        _POSTURE_NOTE, afi=afi))
    return out


def _check_sr_range(value: bytes) -> list:
    """SR Capabilities / SR Local Block (RFC 9085 s2.1.2 / s2.1.4).

    Wire: [1B flags][1B reserved] then one or more
    [3B range size][SID/Label TLV (1161)], where the SID/Label value is a
    3-octet MPLS label or a 4-octet SID. Validates the resulting label window,
    because a controller allocating SIDs from a bad range programs unusable or
    colliding labels on every node that trusts it.
    """
    problems: list = []
    if len(value) < 2:
        return ["range TLV shorter than its flags field"]
    i = 2
    n = len(value)
    while i + 3 <= n:
        size = int.from_bytes(value[i:i + 3], "big")
        i += 3
        if i + 4 > n:
            problems.append("range entry missing its SID/Label TLV")
            break
        sub_type, sub_len = struct.unpack("!HH", value[i:i + 4])
        i += 4
        if i + sub_len > n:
            problems.append("SID/Label TLV overruns the range TLV")
            break
        sub_val = value[i:i + sub_len]
        i += sub_len
        base = None
        if sub_len == 3:
            base = int.from_bytes(sub_val, "big") & 0xFFFFF
        elif sub_len == 4:
            base = struct.unpack("!I", sub_val)[0] & 0xFFFFF
        if size == 0:
            problems.append("range size is 0, so the block allocates no SIDs")
        if base is not None:
            if base <= MPLS_LABEL_RESERVED_MAX:
                problems.append(
                    f"range base label {base} is in the reserved range "
                    f"0-{MPLS_LABEL_RESERVED_MAX}")
            elif size and base + size - 1 > MPLS_LABEL_MAX:
                problems.append(
                    f"range {base}..{base + size - 1} exceeds the 20-bit "
                    f"MPLS label maximum {MPLS_LABEL_MAX}")
        if problems:
            break
    return problems


def inspect_update(u: RawUpdate,
                   segment_list_max: int = SEGMENT_LIST_SANE_MAX) -> list:
    """Stateless SR Policy / BGP-LS checks on one UPDATE. Never raises."""
    out = []
    saw_ls_nlri = False
    for afi, safi, payload, atype in mp_families(u):
        if safi == SAFI_SR_POLICY and afi in (AFI_IPV4, AFI_IPV6):
            if atype == ATTR_MP_REACH:
                out += _sr_findings(afi, payload, u, segment_list_max)
        elif afi == AFI_BGP_LS and safi in (SAFI_BGP_LS, SAFI_BGP_LS_VPN):
            saw_ls_nlri = True
            if atype == ATTR_MP_REACH:
                out += _ls_findings(afi, safi, payload, u)

    has_ls_attr = any(a.atype == ATTR_BGP_LS
                      for a in iter_attributes(u.attrs))
    if has_ls_attr and not saw_ls_nlri:
        out.append(Finding(
            "BGPLS-020", (), 0.0,
            "BGP-LS attribute without BGP-LS NLRI", "high",
            "path attribute 29 is present but the UPDATE carries no AFI "
            "16388 NLRI; the attribute describes topology for nothing",
            _POSTURE_NOTE))
    return out


# --------------------------------------------------------------------------- #
# registry / dispatch
# --------------------------------------------------------------------------- #
REGISTRY = {
    "SRTE-001": "SR Policy NLRI observed (posture inventory)",
    "SRTE-002": "Malformed SR Policy NLRI",
    "SRTE-004": "SR Policy with colour zero",
    "SRTE-010": "SR Policy NLRI on an unnegotiated AFI/SAFI",
    "SRTE-011": "SR Policy received on an eBGP session",
    "SRTE-012": "Conflicting SR Policy for the same colour and endpoint",
    "SRTE-020": "SR Policy tunnel with no Segment List",
    "SRTE-021": "SR Policy Segment List with no segments",
    "SRTE-022": "Deprecated segment type codepoint 2",
    "SRTE-023": "Unknown segment type",
    "SRTE-024": "Malformed Segment Type A (SR-MPLS label)",
    "SRTE-025": "Malformed Segment Type B (SRv6 SID)",
    "SRTE-026": "Malformed SR Policy sub-TLV or Segment List",
    "SRTE-027": "SR Policy Segment List implausibly deep",
    "BGPLS-001": "BGP-LS NLRI observed (posture inventory)",
    "BGPLS-002": "Unassigned Link-State NLRI type",
    "BGPLS-003": "Malformed BGP-LS NLRI",
    "BGPLS-010": "BGP-LS NLRI on an unnegotiated AFI/SAFI",
    "BGPLS-011": "BGP-LS node descriptor claims an unrelated AS",
    "BGPLS-012": "BGP-LS node identity conflict",
    "BGPLS-020": "BGP-LS attribute without BGP-LS NLRI",
    "BGPLS-021": "Malformed BGP-LS attribute TLV",
    "BGPLS-022": "BGP-LS SRGB/SRLB declares an invalid label range",
}


def inspect_message(msg_type: int, body: bytes,
                    segment_list_max: int = SEGMENT_LIST_SANE_MAX) -> list:
    try:
        if msg_type == bgp.UPDATE:
            return inspect_update(walk_update(body),
                                  segment_list_max=segment_list_max)
    except Exception:
        return []
    return []


def inspect_tap_message(msg, tracker: Optional[SrteTracker] = None,
                        segment_list_max: int = SEGMENT_LIST_SANE_MAX) -> list:
    """Run SR Policy / BGP-LS checks over a bgptap.TapMessage.

    With a tracker, session negotiation, eBGP/iBGP posture and conflict
    detection are available; without one, only stateless checks run.
    """
    try:
        if tracker is not None:
            if msg.msg_type == bgp.OPEN:
                findings = tracker.observe_open(msg.flow, msg.body)
            elif msg.msg_type == bgp.UPDATE:
                findings = tracker.observe_update(msg.flow, msg.body)
            else:
                findings = []
        else:
            findings = inspect_message(msg.msg_type, msg.body, segment_list_max)
    except Exception:
        return []
    for f in findings:
        f.src = msg.src
        f.dst = msg.dst
        f.family = msg.family
    return findings
