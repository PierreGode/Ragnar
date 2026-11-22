"""
ike_parser.py — hand-rolled IKE (ISAKMP) wire parser for ipsecwatch.

Design principles (learned from tlswatch/ldapwatch parser traps):
  * NEVER trust a length field without bounding it against the actual buffer.
  * NEVER advance by zero — a zero-length payload/transform is a malformed-packet
    infinite-loop trap. Bail instead.
  * Parse defensively: a truncated capture must yield partial results, not a crash.
  * Endianness is always network byte order (big-endian, struct '!').
  * The parser extracts *observable structure*; detectors decide what's a finding.

Two entry points:
  parse_ike(payload, src, dst, sport, dport) -> IKEMessage | None
    Auto-detects IKEv1 vs IKEv2 from the version byte, strips NAT-T marker.

The IKEMessage it returns is transport-agnostic: identical shape whether the
UDP came in over IPv4 or IPv6. That is the whole basis of dual-stack parity —
address family never enters proposal parsing.
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional

from ike_constants import (
    IKE_VERSION_1, IKE_VERSION_2, IKE_NATT_PORT,
    IKEV1_PAYLOAD_SA, IKEV1_PAYLOAD_PROPOSAL, IKEV1_PAYLOAD_TRANSFORM,
    IKEV1_PAYLOAD_HASH, IKEV1_PAYLOAD_NONE,
    IKEV1_ATTR_ENCRYPTION_ALGORITHM, IKEV1_ATTR_HASH_ALGORITHM,
    IKEV1_ATTR_AUTHENTICATION_METHOD, IKEV1_ATTR_GROUP_DESCRIPTION,
    IKEV2_PAYLOAD_SA, IKEV2_PAYLOAD_NOTIFY, IKEV2_PAYLOAD_NONE,
    IKEV2_TRANSFORM_TYPE_ENCR, IKEV2_TRANSFORM_TYPE_PRF,
    IKEV2_TRANSFORM_TYPE_INTEG, IKEV2_TRANSFORM_TYPE_DH,
)

# NAT-T (UDP/4500) prepends 4 zero bytes ("non-ESP marker") before the IKE header
# to disambiguate from ESP. IKE natively never starts with 4 zero bytes there.
NON_ESP_MARKER = b"\x00\x00\x00\x00"

IKE_HEADER_LEN = 28          # both v1 and v2: 8+8+1+1+1+1+4+4
GENERIC_PAYLOAD_HDR_LEN = 4  # next(1) + critical/reserved(1) + length(2)


# ─────────────────────────────────────────────────────────────────────────────
# Data model — what the detectors consume
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class IKETransform:
    """One transform. For IKEv1 it carries parsed Phase-1 attributes; for IKEv2
    it carries (transform_type, transform_id)."""
    # IKEv2 form
    transform_type: Optional[int] = None
    transform_id: Optional[int] = None
    # IKEv1 form (Phase-1 transform attributes, decoded from TV/TLV)
    v1_encryption: Optional[int] = None
    v1_hash: Optional[int] = None
    v1_auth_method: Optional[int] = None
    v1_dh_group: Optional[int] = None


@dataclass
class IKEProposal:
    protocol_id: int = 0
    transforms: List[IKETransform] = field(default_factory=list)


@dataclass
class IKEMessage:
    version: int                      # 1 or 2
    exchange_type: int
    flags: int
    initiator_spi: bytes
    responder_spi: bytes
    message_id: int
    is_initiator: Optional[bool]      # v2 only (from flag); None for v1
    is_response: Optional[bool]       # v2 only
    proposals: List[IKEProposal] = field(default_factory=list)
    # IKEv1-only: presence + bytes of a HASH payload (E2 aggressive-mode extraction)
    v1_hash_payload: Optional[bytes] = None
    # IKEv2-only: notify message-type IDs present (E3 transcript-auth check)
    v2_notify_types: List[int] = field(default_factory=list)
    # Transport context (filled by caller); NEVER used in detection logic
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    family: str = ""                  # "IPv4" | "IPv6" — for reporting only
    truncated: bool = False           # parser hit a bound; results are partial


# ─────────────────────────────────────────────────────────────────────────────
# Top-level entry
# ─────────────────────────────────────────────────────────────────────────────
def parse_ike(payload: bytes, src="", dst="", sport=0, dport=0, family="") -> Optional[IKEMessage]:
    """Parse a UDP payload as IKE. Returns None if it isn't IKE at all."""
    if payload is None:
        return None

    # NAT-T (UDP/4500) prepends a 4-byte non-ESP marker before the IKE header.
    # Strip it ONLY in a 4500 context. Doing it unconditionally would misalign a
    # packet on 500 whose (invalid but craftable) initiator SPI begins 00000000,
    # and a real IKE header never legitimately starts with 4 zero bytes on 500
    # anyway (RFC 7296: initiator SPI MUST be non-zero). When port is unknown
    # (sport==dport==0, e.g. raw vector tests) we only strip if stripping yields
    # a plausible IKE version nibble AND the un-stripped bytes do not.
    on_natt = (sport == IKE_NATT_PORT or dport == IKE_NATT_PORT)
    if len(payload) >= 4 and payload[:4] == NON_ESP_MARKER:
        if on_natt:
            payload = payload[4:]
        elif sport == 0 and dport == 0:
            # ambiguous/unknown context: strip only if it reveals a valid version
            stripped = payload[4:]
            if len(stripped) >= 18 and ((stripped[17] >> 4) in (1, 2)):
                payload = stripped

    if len(payload) < IKE_HEADER_LEN:
        return None

    init_spi = payload[0:8]
    resp_spi = payload[8:16]
    next_payload = payload[16]
    version_byte = payload[17]
    exchange_type = payload[18]
    flags = payload[19]
    message_id = struct.unpack("!I", payload[20:24])[0]
    length = struct.unpack("!I", payload[24:28])[0]

    major_version = (version_byte >> 4) & 0x0F

    msg = IKEMessage(
        version=major_version,
        exchange_type=exchange_type,
        flags=flags,
        initiator_spi=init_spi,
        responder_spi=resp_spi,
        message_id=message_id,
        is_initiator=None,
        is_response=None,
        src=src, dst=dst, sport=sport, dport=dport, family=family,
    )

    # Bound the body by the smaller of declared length and actual buffer.
    body_end = min(length, len(payload)) if length >= IKE_HEADER_LEN else len(payload)
    if body_end < len(payload):
        # declared length shorter than buffer is fine; longer means truncated capture
        pass
    if length > len(payload):
        msg.truncated = True

    if major_version == IKE_VERSION_1:
        _parse_v1_payloads(msg, payload, next_payload, IKE_HEADER_LEN, body_end)
    elif major_version == IKE_VERSION_2:
        from ike_constants import IKEV2_FLAG_INITIATOR, IKEV2_FLAG_RESPONSE
        msg.is_initiator = bool(flags & IKEV2_FLAG_INITIATOR)
        msg.is_response = bool(flags & IKEV2_FLAG_RESPONSE)
        _parse_v2_payloads(msg, payload, next_payload, IKE_HEADER_LEN, body_end)
    else:
        return None  # unknown major version — not something we handle

    return msg


# ─────────────────────────────────────────────────────────────────────────────
# IKEv1 payload chain
# ─────────────────────────────────────────────────────────────────────────────
def _parse_v1_payloads(msg, buf, first_next, offset, end):
    next_payload = first_next
    guard = 0
    while next_payload != IKEV1_PAYLOAD_NONE and offset + GENERIC_PAYLOAD_HDR_LEN <= end:
        guard += 1
        if guard > 64:  # pathological chain — bail
            msg.truncated = True
            break
        this_next = buf[offset]
        # buf[offset+1] is RESERVED
        plen = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
        if plen < GENERIC_PAYLOAD_HDR_LEN or offset + plen > end:
            msg.truncated = True
            break
        body = buf[offset + GENERIC_PAYLOAD_HDR_LEN: offset + plen]

        if next_payload == IKEV1_PAYLOAD_SA:
            _parse_v1_sa(msg, body)
        elif next_payload == IKEV1_PAYLOAD_HASH:
            msg.v1_hash_payload = bytes(body)   # E2: aggressive-mode PSK hash

        offset += plen
        next_payload = this_next


def _parse_v1_sa(msg, sa_body):
    """SA payload body: DOI(4) + Situation(4) + Proposal payload(s)."""
    if len(sa_body) < 8:
        return
    offset = 8  # skip DOI + Situation
    end = len(sa_body)
    next_payload = IKEV1_PAYLOAD_PROPOSAL
    guard = 0
    while next_payload == IKEV1_PAYLOAD_PROPOSAL and offset + GENERIC_PAYLOAD_HDR_LEN <= end:
        guard += 1
        if guard > 64:
            break
        this_next = sa_body[offset]
        plen = struct.unpack("!H", sa_body[offset + 2:offset + 4])[0]
        if plen < 8 or offset + plen > end:
            break
        # Proposal header: next(1) resv(1) len(2) prop#(1) proto(1) spisize(1) #transforms(1)
        proto_id = sa_body[offset + 5]
        spi_size = sa_body[offset + 6]
        prop = IKEProposal(protocol_id=proto_id)
        tf_start = offset + 8 + spi_size
        _parse_v1_transforms(prop, sa_body, tf_start, offset + plen)
        msg.proposals.append(prop)
        offset += plen
        next_payload = this_next


def _parse_v1_transforms(prop, buf, offset, end):
    next_payload = IKEV1_PAYLOAD_TRANSFORM
    guard = 0
    while next_payload == IKEV1_PAYLOAD_TRANSFORM and offset + GENERIC_PAYLOAD_HDR_LEN <= end:
        guard += 1
        if guard > 128:
            break
        this_next = buf[offset]
        plen = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
        if plen < 8 or offset + plen > end:
            break
        # Transform header: next(1) resv(1) len(2) transform#(1) transformID(1) resv2(2)
        attr_start = offset + 8
        tf = IKETransform()
        _parse_v1_attributes(tf, buf, attr_start, offset + plen)
        prop.transforms.append(tf)
        offset += plen
        next_payload = this_next


def _parse_v1_attributes(tf, buf, offset, end):
    """IKEv1 Data Attributes (RFC 2408 §3.3). Each attr:
       AF/Type(2) then, if AF=1 (TV): Value(2);  if AF=0 (TLV): Length(2)+Value(len).
    """
    while offset + 4 <= end:
        af_type = struct.unpack("!H", buf[offset:offset + 2])[0]
        af = (af_type >> 15) & 0x1          # 1 = TV (short form), 0 = TLV
        attr_type = af_type & 0x7FFF
        if af == 1:
            value = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
            _assign_v1_attr(tf, attr_type, value)
            offset += 4
        else:
            alen = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
            vstart = offset + 4
            vend = vstart + alen
            if vend > end:
                break
            raw = buf[vstart:vend]
            # decode as big-endian int if it fits (life-duration etc. can be long)
            value = int.from_bytes(raw, "big") if raw else 0
            _assign_v1_attr(tf, attr_type, value)
            offset = vend


def _assign_v1_attr(tf, attr_type, value):
    if attr_type == IKEV1_ATTR_ENCRYPTION_ALGORITHM:
        tf.v1_encryption = value
    elif attr_type == IKEV1_ATTR_HASH_ALGORITHM:
        tf.v1_hash = value
    elif attr_type == IKEV1_ATTR_AUTHENTICATION_METHOD:
        tf.v1_auth_method = value
    elif attr_type == IKEV1_ATTR_GROUP_DESCRIPTION:
        tf.v1_dh_group = value


# ─────────────────────────────────────────────────────────────────────────────
# IKEv2 payload chain
# ─────────────────────────────────────────────────────────────────────────────
def _parse_v2_payloads(msg, buf, first_next, offset, end):
    next_payload = first_next
    guard = 0
    while next_payload != IKEV2_PAYLOAD_NONE and offset + GENERIC_PAYLOAD_HDR_LEN <= end:
        guard += 1
        if guard > 64:
            msg.truncated = True
            break
        this_next = buf[offset]
        # buf[offset+1]: critical bit + reserved
        plen = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
        if plen < GENERIC_PAYLOAD_HDR_LEN or offset + plen > end:
            msg.truncated = True
            break
        body = buf[offset + GENERIC_PAYLOAD_HDR_LEN: offset + plen]

        if next_payload == IKEV2_PAYLOAD_SA:
            _parse_v2_sa(msg, body)
        elif next_payload == IKEV2_PAYLOAD_NOTIFY:
            _parse_v2_notify(msg, body)

        offset += plen
        next_payload = this_next


def _parse_v2_notify(msg, body):
    """Notify payload body: protoID(1) spiSize(1) notifyType(2) [spi] [data]."""
    if len(body) < 4:
        return
    spi_size = body[1]
    notify_type = struct.unpack("!H", body[2:4])[0]
    msg.v2_notify_types.append(notify_type)


def _parse_v2_sa(msg, sa_body):
    """SA payload body is a chain of Proposal substructures (RFC 7296 §3.3.1)."""
    offset = 0
    end = len(sa_body)
    guard = 0
    while offset + 8 <= end:
        guard += 1
        if guard > 64:
            break
        # Proposal: last(1) resv(1) len(2) prop#(1) protoID(1) spiSize(1) #transforms(1)
        last = sa_body[offset]
        plen = struct.unpack("!H", sa_body[offset + 2:offset + 4])[0]
        if plen < 8 or offset + plen > end:
            break
        proto_id = sa_body[offset + 5]
        spi_size = sa_body[offset + 6]
        num_transforms = sa_body[offset + 7]
        prop = IKEProposal(protocol_id=proto_id)
        tf_start = offset + 8 + spi_size
        _parse_v2_transforms(prop, sa_body, tf_start, offset + plen, num_transforms)
        msg.proposals.append(prop)
        offset += plen
        if last == 0:   # 0 = last proposal
            break


def _parse_v2_transforms(prop, buf, offset, end, expected):
    """Transform substructure (RFC 7296 §3.3.2):
       last(1) resv(1) len(2) type(1) resv(1) id(2) [attrs]."""
    count = 0
    guard = 0
    while offset + 8 <= end:
        guard += 1
        if guard > 128:
            break
        last = buf[offset]
        tlen = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
        if tlen < 8 or offset + tlen > end:
            break
        ttype = buf[offset + 4]
        tid = struct.unpack("!H", buf[offset + 6:offset + 8])[0]
        prop.transforms.append(IKETransform(transform_type=ttype, transform_id=tid))
        count += 1
        offset += tlen
        if last == 0:   # 0 = last transform
            break
