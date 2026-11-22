"""
bgpsec.py -- passive BGPsec (RFC 8205) posture and downgrade detector.

WHY THIS IS NOT A CVE TIER
--------------------------
There are no BGPsec-specific CVEs. A CVE sweep (Oct 2026) found none: the
attack surface that matters here is not a parser bug, it is whether path
signing is actually in force on a session that claims to support it. So this
tier reports POSTURE and DOWNGRADE, and its findings are graded on a posture
scale rather than carrying CVE identifiers. The parser-CVE tier lives in
bgpcve.py and is unaffected.

THE PASSIVE-ONLY BOUNDARY (hard line, do not cross)
---------------------------------------------------
This module NEVER validates a signature. Cryptographic validation of a
BGPsec_PATH requires the signing router's certificate from the RPKI, which
means an outbound fetch to RPKI repositories (rsync/RRDP) -- an active
operation. Ragnar passive modules do not transmit, so:

    * structural checks on the signature block -- YES (pure inspection)
    * "is this signature cryptographically valid" -- NO, out of scope

A BSEC finding therefore means "the signing posture on this session looks like
X", never "this route is forged". Anything claiming otherwise would be lying
about what a tap can know. Every finding's note carries this.

WHAT BGPsec LOOKS LIKE ON THE WIRE (RFC 8205)
---------------------------------------------
Capability (code 7), in OPEN, 3 octets:
    [1B version(4b)|dir(1b)|reserved(3b)][2B AFI]
  Advertised once per AFI and once per direction, so a dual-stack send+receive
  speaker emits four of them.

BGPsec_PATH attribute (type 33), optional NON-transitive:
    Secure_Path:    [2B length][N x 6B segment: pCount(1) Flags(1) ASN(4)]
    Signature_Blocks (1 or 2):
                    [2B length][1B algorithm suite ID]
                    [N x: SKI(20B) SigLen(2B) Signature(variable)]

Two structural rules carry real weight:
  * the signature-segment count MUST equal the secure-path segment count
  * a BGPsec UPDATE carries NLRI in MP_REACH_NLRI and MUST NOT carry AS_PATH
    (true even for IPv4 -- this is why BGPsec is inherently dual-stack and why
    an AS_PATH alongside BGPsec_PATH is a strong signal)

DUAL-STACK
----------
BGPsec is negotiated per-AFI, and BGPsec NLRI always rides MP_REACH, so AFI 1
and AFI 2 are distinct capability advertisements and distinct signed paths.
Both are parsed, tracked and tested at parity; the AFI is carried on every
finding so a v4-signed / v6-unsigned asymmetry is visible rather than averaged
away. Transport family (v4/v6 TCP) is orthogonal and stamped by the tap.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

import bgp
from bgpcve import Finding, RawUpdate, iter_attributes, walk_update

# --- constants ------------------------------------------------------------- #
ATTR_BGPSEC_PATH = 33
ATTR_AS_PATH = 2
ATTR_MP_REACH = 14

CAP_BGPSEC = 7
BGPSEC_CAP_LEN = 3

SECURE_PATH_SEG_LEN = 6
SKI_LEN = 20

# RFC 8608: 1 = ECDSA P-256 with SHA-256. Anything else is unassigned today.
ALGO_ECDSA_P256_SHA256 = 1
KNOWN_ALGO_SUITES = {ALGO_ECDSA_P256_SHA256: "ECDSA P-256 / SHA-256"}
# DER-encoded ECDSA P-256 signatures are ~70-72 bytes; shorter is possible when
# r/s have leading zero octets stripped, but very short or over-long is not.
ECDSA_P256_SIG_MAX = 72
ECDSA_P256_SIG_MIN = 64

AFI_IPV4 = 1
AFI_IPV6 = 2
AFI_NAMES = {AFI_IPV4: "IPv4", AFI_IPV6: "IPv6"}

DIR_RECEIVE = 0
DIR_SEND = 1

# pCount above this is path-length inflation rather than ordinary prepending.
PCOUNT_INFLATION_DEFAULT = 32

_PASSIVE_NOTE = ("structural/posture observation only -- this module never "
                 "validates signatures (that needs RPKI router certificates, "
                 "which would require an outbound fetch and is therefore not "
                 "passive); a finding never means a route is forged")


# --------------------------------------------------------------------------- #
# Capability parsing (OPEN)
# --------------------------------------------------------------------------- #
@dataclass
class BgpsecCap:
    version: int
    direction: int            # 0 = receive, 1 = send
    reserved: int
    afi: int
    raw_len: int
    malformed: bool = False

    @property
    def dir_name(self) -> str:
        return "send" if self.direction == DIR_SEND else "receive"


def iter_capabilities(open_body: bytes) -> Iterator[tuple]:
    """Lenient walk of an OPEN's optional parameters -> (cap_code, cap_value).

    Handles RFC 9072 extended optional parameters (type 0xFF) as well as the
    classic form. Never raises.
    """
    if len(open_body) < 10:
        return
    opt_len = open_body[9]
    opts = open_body[10:10 + opt_len]
    i = 0
    while i < len(opts):
        ptype = opts[i]
        if ptype == 0xFF:                      # RFC 9072 extended parameter
            if i + 3 > len(opts):
                return
            plen = struct.unpack("!H", opts[i + 1:i + 3])[0]
            val = opts[i + 3:i + 3 + plen]
            i += 3 + plen
        else:
            if i + 2 > len(opts):
                return
            plen = opts[i + 1]
            val = opts[i + 2:i + 2 + plen]
            i += 2 + plen
        if ptype != 2:                         # 2 = Capabilities
            continue
        j = 0
        while j + 2 <= len(val):
            cap_code = val[j]
            cap_len = val[j + 1]
            cap_val = val[j + 2:j + 2 + cap_len]
            j += 2 + cap_len
            yield (cap_code, cap_val)


def parse_bgpsec_capability(cap_val: bytes) -> BgpsecCap:
    """Decode a BGPsec capability value (RFC 8205 s4.1). Never raises."""
    if len(cap_val) != BGPSEC_CAP_LEN:
        return BgpsecCap(0, 0, 0, 0, len(cap_val), malformed=True)
    b = cap_val[0]
    version = (b >> 4) & 0x0F
    direction = (b >> 3) & 0x01
    reserved = b & 0x07
    afi = struct.unpack("!H", cap_val[1:3])[0]
    return BgpsecCap(version, direction, reserved, afi, len(cap_val))


def bgpsec_caps_in_open(open_body: bytes) -> list:
    out = []
    for code, val in iter_capabilities(open_body):
        if code == CAP_BGPSEC:
            out.append(parse_bgpsec_capability(val))
    return out


# --------------------------------------------------------------------------- #
# BGPsec_PATH parsing (lenient -- reports, never raises)
# --------------------------------------------------------------------------- #
@dataclass
class SecurePathSeg:
    pcount: int
    flags: int
    asn: int

    @property
    def confed(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def reserved_bits(self) -> int:
        return self.flags & 0x7F


@dataclass
class SigSegment:
    ski: bytes
    sig_len: int
    sig: bytes
    truncated: bool = False


@dataclass
class SigBlock:
    declared_len: int
    algo_suite: int
    segments: list = field(default_factory=list)
    overrun: bool = False
    truncated: bool = False


@dataclass
class BgpsecPath:
    secure_path_len: int = 0
    segments: list = field(default_factory=list)
    blocks: list = field(default_factory=list)
    # structural problems, reported as data
    truncated: bool = False
    secure_path_bad_len: bool = False
    secure_path_overrun: bool = False
    trailing_bytes: int = 0
    problems: list = field(default_factory=list)


def walk_bgpsec_path(value: bytes) -> BgpsecPath:
    """Decompose a BGPsec_PATH attribute value without trusting any length."""
    p = BgpsecPath()
    n = len(value)
    if n < 2:
        p.truncated = True
        p.problems.append("attribute shorter than the Secure_Path length field")
        return p

    p.secure_path_len = struct.unpack("!H", value[:2])[0]
    # Secure_Path Length counts itself (2) plus 6 bytes per segment
    if p.secure_path_len < 2 or (p.secure_path_len - 2) % SECURE_PATH_SEG_LEN:
        p.secure_path_bad_len = True
        p.problems.append(
            f"Secure_Path length {p.secure_path_len} is not 2 + 6N")
    if p.secure_path_len > n:
        p.secure_path_overrun = True
        p.problems.append(
            f"Secure_Path length {p.secure_path_len} exceeds the "
            f"{n}-byte attribute value")
        return p

    off = 2
    end_sp = p.secure_path_len
    while off + SECURE_PATH_SEG_LEN <= end_sp:
        pcount = value[off]
        flags = value[off + 1]
        asn = struct.unpack("!I", value[off + 2:off + 6])[0]
        p.segments.append(SecurePathSeg(pcount, flags, asn))
        off += SECURE_PATH_SEG_LEN
    if off != end_sp:
        p.problems.append(
            f"Secure_Path has {end_sp - off} trailing byte(s) after whole segments")

    off = max(off, end_sp)
    # one or two signature blocks
    while off < n:
        if off + 3 > n:
            p.problems.append("Signature_Block header truncated")
            break
        blk_len = struct.unpack("!H", value[off:off + 2])[0]
        algo = value[off + 2]
        blk = SigBlock(blk_len, algo)
        if blk_len < 3:
            blk.truncated = True
            p.problems.append(
                f"Signature_Block length {blk_len} below the 3-byte minimum")
            p.blocks.append(blk)
            break
        if off + blk_len > n:
            blk.overrun = True
            p.problems.append(
                f"Signature_Block length {blk_len} exceeds the "
                f"{n - off} remaining bytes")
            p.blocks.append(blk)
            break
        inner = value[off + 3:off + blk_len]
        i = 0
        while i < len(inner):
            if i + SKI_LEN + 2 > len(inner):
                blk.segments.append(SigSegment(inner[i:], 0, b"", truncated=True))
                p.problems.append(
                    "Signature segment header truncated (SKI + length)")
                break
            ski = inner[i:i + SKI_LEN]
            sig_len = struct.unpack("!H", inner[i + SKI_LEN:i + SKI_LEN + 2])[0]
            i2 = i + SKI_LEN + 2
            if i2 + sig_len > len(inner):
                blk.segments.append(SigSegment(ski, sig_len, inner[i2:], True))
                p.problems.append(
                    f"Signature length {sig_len} exceeds the "
                    f"{len(inner) - i2} bytes remaining in the block")
                break
            blk.segments.append(SigSegment(ski, sig_len, inner[i2:i2 + sig_len]))
            i = i2 + sig_len
        p.blocks.append(blk)
        off += blk_len

    p.trailing_bytes = max(0, n - off)
    return p


# --------------------------------------------------------------------------- #
# Session tracking -- downgrade detection needs a little state
# --------------------------------------------------------------------------- #
@dataclass
class SessionState:
    """Per-flow BGPsec posture, built from the OPENs then tested by UPDATEs."""
    caps_seen: dict = field(default_factory=dict)   # (afi, dir) -> BgpsecCap
    signed_afis: set = field(default_factory=set)   # AFIs seen with BGPsec_PATH
    unsigned_afis: set = field(default_factory=set)
    downgrade_reported: set = field(default_factory=set)

    def advertises(self, afi: int) -> bool:
        return any(a == afi for (a, _d) in self.caps_seen)

    @property
    def any_capability(self) -> bool:
        return bool(self.caps_seen)


class BgpsecTracker:
    """Keeps per-flow BGPsec session posture so downgrade can be detected.

    Keyed by the tap's flow tuple. Bounded: a cap on tracked flows keeps a
    long-running tap on a Pi from growing without limit on a busy mirror.
    """

    MAX_FLOWS = 4096

    def __init__(self, pcount_inflation: int = PCOUNT_INFLATION_DEFAULT):
        self.sessions: dict = {}
        self.pcount_inflation = pcount_inflation

    def _state(self, flow) -> SessionState:
        st = self.sessions.get(flow)
        if st is None:
            if len(self.sessions) >= self.MAX_FLOWS:
                self.sessions.clear()        # cheap bound; posture rebuilds
            st = SessionState()
            self.sessions[flow] = st
        return st

    def observe_open(self, flow, open_body: bytes) -> list:
        st = self._state(flow)
        findings = []
        for cap in bgpsec_caps_in_open(open_body):
            findings.extend(_cap_findings(cap))
            if not cap.malformed:
                st.caps_seen[(cap.afi, cap.direction)] = cap
        return findings

    def observe_update(self, flow, body: bytes) -> list:
        st = self._state(flow)
        u = walk_update(body)
        findings = inspect_update(u, pcount_inflation=self.pcount_inflation)

        has_bgpsec = any(a.atype == ATTR_BGPSEC_PATH
                         for a in iter_attributes(u.attrs))
        has_aspath = any(a.atype == ATTR_AS_PATH
                         for a in iter_attributes(u.attrs))
        afi = _mp_reach_afi(u)

        if has_bgpsec and afi:
            st.signed_afis.add(afi)
        elif has_aspath and afi and not has_bgpsec:
            st.unsigned_afis.add(afi)

        # Downgrade: the session advertised BGPsec for this AFI, yet routes for
        # that AFI arrive unsigned. Reported once per (flow, afi).
        if (afi and not has_bgpsec and has_aspath
                and st.advertises(afi) and afi not in st.downgrade_reported):
            st.downgrade_reported.add(afi)
            findings.append(Finding(
                "BSEC-010", (), 0.0,
                "BGPsec downgrade: capability negotiated but routes arrive unsigned",
                "high",
                f"peer advertised the BGPsec capability for "
                f"{AFI_NAMES.get(afi, afi)} but this UPDATE carries AS_PATH "
                f"with no BGPsec_PATH -- signing is not in force for this AFI",
                _PASSIVE_NOTE, afi=afi))

        # Mixed posture: same session signs one AFI and not the other. Easy to
        # miss operationally because each AFI looks fine on its own.
        if (st.signed_afis and st.unsigned_afis
                and "mixed" not in st.downgrade_reported):
            unsigned_only = st.unsigned_afis - st.signed_afis
            if unsigned_only:
                st.downgrade_reported.add("mixed")
                findings.append(Finding(
                    "BSEC-011", (), 0.0,
                    "BGPsec applied to one address family but not the other",
                    "medium",
                    "signed: "
                    + ", ".join(sorted(AFI_NAMES.get(a, str(a))
                                       for a in st.signed_afis))
                    + "; unsigned: "
                    + ", ".join(sorted(AFI_NAMES.get(a, str(a))
                                       for a in unsigned_only)),
                    _PASSIVE_NOTE))
        return findings


def _mp_reach_afi(u: RawUpdate) -> Optional[int]:
    for a in iter_attributes(u.attrs):
        if a.atype == ATTR_MP_REACH and not a.overrun and len(a.value) >= 2:
            return struct.unpack("!H", a.value[:2])[0]
    return None


# --------------------------------------------------------------------------- #
# Capability-level findings
# --------------------------------------------------------------------------- #
def _cap_findings(cap: BgpsecCap) -> list:
    out = []
    if cap.malformed:
        out.append(Finding(
            "BSEC-004", (), 0.0,
            "Malformed BGPsec capability", "high",
            f"BGPsec capability value is {cap.raw_len} bytes; RFC 8205 "
            f"requires exactly {BGPSEC_CAP_LEN}", _PASSIVE_NOTE))
        return out
    out.append(Finding(
        "BSEC-001", (), 0.0,
        "BGPsec capability advertised", "high",
        f"version {cap.version}, direction {cap.dir_name}, AFI "
        f"{AFI_NAMES.get(cap.afi, cap.afi)}",
        _PASSIVE_NOTE + "; informational posture inventory", afi=cap.afi))
    if cap.version != 0:
        out.append(Finding(
            "BSEC-002", (), 0.0,
            "BGPsec capability with unknown version", "medium",
            f"version field is {cap.version}; RFC 8205 defines version 0",
            _PASSIVE_NOTE, afi=cap.afi))
    if cap.reserved:
        out.append(Finding(
            "BSEC-003", (), 0.0,
            "BGPsec capability reserved bits set", "medium",
            f"reserved bits = 0b{cap.reserved:03b}; RFC 8205 requires zero",
            _PASSIVE_NOTE, afi=cap.afi))
    return out


# --------------------------------------------------------------------------- #
# BGPsec_PATH findings
# --------------------------------------------------------------------------- #
def inspect_update(u: RawUpdate,
                   pcount_inflation: int = PCOUNT_INFLATION_DEFAULT) -> list:
    """Structural + abuse checks on any BGPsec_PATH in this UPDATE."""
    out: list = []
    attrs = list(iter_attributes(u.attrs))
    bgpsec_attrs = [a for a in attrs if a.atype == ATTR_BGPSEC_PATH]
    if not bgpsec_attrs:
        return out

    has_aspath = any(a.atype == ATTR_AS_PATH for a in attrs)
    has_mp_reach = any(a.atype == ATTR_MP_REACH for a in attrs)
    afi = _mp_reach_afi(u)

    for a in bgpsec_attrs:
        # RFC 8205: optional, NON-transitive. A transitive BGPsec_PATH would
        # propagate past a speaker that cannot validate it.
        if not (a.optional and not a.transitive):
            out.append(Finding(
                "BSEC-020", (), 0.0,
                "BGPsec_PATH with non-conformant attribute flags", "high",
                f"flags=0x{a.flags:02x} (optional={a.optional}, "
                f"transitive={a.transitive}); RFC 8205 requires optional "
                f"non-transitive", _PASSIVE_NOTE, afi=afi))

        if a.overrun:
            out.append(Finding(
                "BSEC-021", (), 0.0,
                "BGPsec_PATH attribute length overruns the attribute block",
                "high",
                f"declared length {a.declared_len} exceeds the path-attribute "
                f"block", _PASSIVE_NOTE, afi=afi))
            continue

        p = walk_bgpsec_path(a.value)

        if p.truncated or p.secure_path_bad_len or p.secure_path_overrun:
            out.append(Finding(
                "BSEC-021", (), 0.0,
                "Malformed BGPsec_PATH Secure_Path", "high",
                "; ".join(p.problems[:3]) or "Secure_Path structurally invalid",
                _PASSIVE_NOTE, afi=afi))

        sig_problems = [x for x in p.problems if "Signature" in x]
        if sig_problems:
            out.append(Finding(
                "BSEC-022", (), 0.0,
                "Malformed BGPsec_PATH Signature_Block", "high",
                "; ".join(sig_problems[:3]), _PASSIVE_NOTE, afi=afi))

        if not p.segments and not p.truncated and not p.secure_path_overrun:
            out.append(Finding(
                "BSEC-032", (), 0.0,
                "BGPsec_PATH with zero Secure_Path segments", "high",
                "a signed path must contain at least one AS segment",
                _PASSIVE_NOTE, afi=afi))

        # RFC 8205 s5.2: signature segment count must equal secure path count
        for blk in p.blocks:
            if blk.overrun or blk.truncated:
                continue
            if len(blk.segments) != len(p.segments):
                out.append(Finding(
                    "BSEC-023", (), 0.0,
                    "BGPsec_PATH signature/path segment count mismatch", "high",
                    f"{len(p.segments)} Secure_Path segment(s) but "
                    f"{len(blk.segments)} signature segment(s) in the block "
                    f"(algorithm suite {blk.algo_suite}); RFC 8205 requires "
                    f"them to match", _PASSIVE_NOTE, afi=afi))
            if blk.algo_suite not in KNOWN_ALGO_SUITES:
                out.append(Finding(
                    "BSEC-024", (), 0.0,
                    "BGPsec_PATH unknown algorithm suite", "medium",
                    f"algorithm suite identifier {blk.algo_suite} is not "
                    f"assigned (RFC 8608 defines "
                    f"{ALGO_ECDSA_P256_SHA256} = ECDSA P-256 / SHA-256)",
                    _PASSIVE_NOTE, afi=afi))
            else:
                for seg in blk.segments:
                    if seg.truncated:
                        continue
                    if seg.sig_len == 0:
                        out.append(Finding(
                            "BSEC-033", (), 0.0,
                            "BGPsec_PATH zero-length signature", "high",
                            "a signature segment declares length 0",
                            _PASSIVE_NOTE, afi=afi))
                    elif seg.sig_len > ECDSA_P256_SIG_MAX:
                        out.append(Finding(
                            "BSEC-033", (), 0.0,
                            "BGPsec_PATH implausible signature length",
                            "medium",
                            f"signature length {seg.sig_len} exceeds the "
                            f"{ECDSA_P256_SIG_MAX}-byte maximum for a "
                            f"DER-encoded ECDSA P-256 signature",
                            _PASSIVE_NOTE, afi=afi))

        if len(p.blocks) > 2:
            out.append(Finding(
                "BSEC-026", (), 0.0,
                "BGPsec_PATH with more than two Signature_Blocks", "high",
                f"{len(p.blocks)} signature blocks; RFC 8205 permits at most 2",
                _PASSIVE_NOTE, afi=afi))

        if not p.blocks and p.segments:
            out.append(Finding(
                "BSEC-022", (), 0.0,
                "BGPsec_PATH with no Signature_Block", "high",
                f"{len(p.segments)} Secure_Path segment(s) but no signature "
                f"block present", _PASSIVE_NOTE, afi=afi))

        # per-segment abuse checks
        for seg in p.segments:
            if seg.reserved_bits:
                out.append(Finding(
                    "BSEC-029", (), 0.0,
                    "BGPsec_PATH Secure_Path segment reserved flag bits set",
                    "medium",
                    f"AS {seg.asn}: flags=0x{seg.flags:02x}, reserved bits "
                    f"must be zero (bit 7 is Confed_Segment)",
                    _PASSIVE_NOTE, afi=afi))
            if seg.asn == 0:
                out.append(Finding(
                    "BSEC-034", (), 0.0,
                    "BGPsec_PATH Secure_Path segment with AS 0", "high",
                    "AS 0 is reserved and must not appear in a signed path",
                    _PASSIVE_NOTE, afi=afi))
            if seg.pcount == 0:
                out.append(Finding(
                    "BSEC-030", (), 0.0,
                    "BGPsec_PATH segment with pCount 0", "low",
                    f"AS {seg.asn} has pCount 0 -- legitimate for a transparent "
                    f"route server, but it removes that AS from path-length "
                    f"calculations, so it is worth knowing where it occurs",
                    _PASSIVE_NOTE, afi=afi))
            elif seg.pcount >= pcount_inflation:
                out.append(Finding(
                    "BSEC-031", (), 0.0,
                    "BGPsec_PATH segment with inflated pCount", "medium",
                    f"AS {seg.asn} has pCount {seg.pcount} (threshold "
                    f"{pcount_inflation}); inflates path length far beyond "
                    f"ordinary prepending", _PASSIVE_NOTE, afi=afi))

    # message-level rules
    if has_aspath:
        out.append(Finding(
            "BSEC-027", (), 0.0,
            "BGPsec_PATH and AS_PATH in the same UPDATE", "high",
            "RFC 8205 forbids carrying both; a receiver that ignores "
            "BGPsec_PATH would act on the unsigned AS_PATH instead",
            _PASSIVE_NOTE, afi=afi))
    if not has_mp_reach and not u.withdrawn:
        out.append(Finding(
            "BSEC-028", (), 0.0,
            "BGPsec_PATH without MP_REACH_NLRI", "high",
            "RFC 8205 carries BGPsec NLRI in MP_REACH_NLRI (for IPv4 as well "
            "as IPv6); a BGPsec_PATH with no MP_REACH has nothing to sign",
            _PASSIVE_NOTE, afi=afi))
    return out


# --------------------------------------------------------------------------- #
# Registry / dispatch
# --------------------------------------------------------------------------- #
REGISTRY = {
    "BSEC-001": "BGPsec capability advertised (posture inventory)",
    "BSEC-002": "BGPsec capability unknown version",
    "BSEC-003": "BGPsec capability reserved bits set",
    "BSEC-004": "Malformed BGPsec capability",
    "BSEC-010": "Downgrade: capability negotiated, routes arrive unsigned",
    "BSEC-011": "BGPsec applied to one address family but not the other",
    "BSEC-020": "BGPsec_PATH non-conformant attribute flags",
    "BSEC-021": "Malformed BGPsec_PATH Secure_Path",
    "BSEC-022": "Malformed or absent BGPsec_PATH Signature_Block",
    "BSEC-023": "Signature/path segment count mismatch",
    "BSEC-024": "Unknown algorithm suite",
    "BSEC-026": "More than two Signature_Blocks",
    "BSEC-027": "BGPsec_PATH and AS_PATH in the same UPDATE",
    "BSEC-028": "BGPsec_PATH without MP_REACH_NLRI",
    "BSEC-029": "Secure_Path segment reserved flag bits set",
    "BSEC-030": "Secure_Path segment with pCount 0",
    "BSEC-031": "Secure_Path segment with inflated pCount",
    "BSEC-032": "BGPsec_PATH with zero Secure_Path segments",
    "BSEC-033": "Implausible or zero signature length",
    "BSEC-034": "Secure_Path segment with AS 0",
}


def inspect_message(msg_type: int, body: bytes,
                    pcount_inflation: int = PCOUNT_INFLATION_DEFAULT) -> list:
    """Stateless inspection (no downgrade detection -- that needs session
    state, use BgpsecTracker). Never raises."""
    try:
        if msg_type == bgp.OPEN:
            out = []
            for cap in bgpsec_caps_in_open(body):
                out.extend(_cap_findings(cap))
            return out
        if msg_type == bgp.UPDATE:
            return inspect_update(walk_update(body),
                                  pcount_inflation=pcount_inflation)
    except Exception:
        return []
    return []


def inspect_tap_message(msg, tracker: Optional[BgpsecTracker] = None,
                        pcount_inflation: int = PCOUNT_INFLATION_DEFAULT) -> list:
    """Run BGPsec checks over a bgptap.TapMessage, stamping flow context.

    With a tracker, session posture is carried across messages so downgrade
    (BSEC-010/011) can be detected; without one, only stateless checks run.
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
            findings = inspect_message(msg.msg_type, msg.body, pcount_inflation)
    except Exception:
        return []
    for f in findings:
        f.src = msg.src
        f.dst = msg.dst
        f.family = msg.family
    return findings
