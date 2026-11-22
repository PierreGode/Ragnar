"""
ike_forge.py — byte-level IKE packet builder for ipsecwatch test vectors.

We hand-build wire bytes rather than lean on scapy's IKE layer because:
  * scapy's IKEv2 transform/attribute support is patchy;
  * building the exact RFC byte layout ourselves is the strongest possible test
    of the parser (we control every octet and know the ground truth);
  * zero external dependency keeps the lab reproducible on any Ragnar node.

All integers network byte order. Helpers mirror RFC 2408/2409/7296 layouts.
"""

import struct

# ── IKEv1 attribute encoders (Data Attributes, RFC 2408 §3.3) ────────────────
def v1_attr_tv(attr_type, value):
    """Short-form (TV) attribute: AF=1. type|0x8000 then 2-byte value."""
    return struct.pack("!HH", attr_type | 0x8000, value)


def v1_transform(transform_num, transform_id, attrs: bytes, is_last: bool):
    """IKEv1 Transform payload (RFC 2408 §3.6):
       generic hdr: next(1) resv(1) len(2)
       then: transform#(1) transformID(1) resv2(2) attrs
    """
    next_payload = 0 if is_last else 3   # 3 = Transform
    tf_hdr = struct.pack("!BBH", transform_num, transform_id, 0)  # tnum, tid, resv2(2)
    length = 4 + len(tf_hdr) + len(attrs)
    return struct.pack("!BBH", next_payload, 0, length) + tf_hdr + attrs


def v1_proposal(proposal_num, protocol_id, transforms: list, is_last: bool):
    """IKEv1 Proposal payload: next(1) resv(1) len(2) pnum(1) proto(1) spisize(1) #tf(1) [spi] transforms."""
    next_payload = 0 if is_last else 2   # 2 = Proposal
    spi = b""
    tf_bytes = b"".join(transforms)
    length = 4 + 4 + len(spi) + len(tf_bytes)
    hdr = struct.pack("!BBH", next_payload, 0, length)
    body = struct.pack("!BBBB", proposal_num, protocol_id, len(spi), len(transforms)) + spi
    return hdr + body + tf_bytes


def v1_sa_payload(proposals: list, next_payload_after_sa: int):
    """IKEv1 SA payload: generic hdr + DOI(4) + Situation(4) + proposals."""
    doi = struct.pack("!I", 1)          # IPSEC DOI
    situation = struct.pack("!I", 1)    # SIT_IDENTITY_ONLY
    prop_bytes = b"".join(proposals)
    body = doi + situation + prop_bytes
    length = 4 + len(body)
    return struct.pack("!BBH", next_payload_after_sa, 0, length) + body


def v1_generic_payload(payload_type_next, this_payload_body):
    """Wrap an arbitrary body in a generic payload header (used for HASH)."""
    length = 4 + len(this_payload_body)
    return struct.pack("!BBH", payload_type_next, 0, length) + this_payload_body


def ike_v1_header(init_spi, resp_spi, next_payload, exchange_type, flags, msg_id, total_len):
    version = 0x10  # major 1, minor 0
    return (init_spi + resp_spi +
            struct.pack("!BBBB", next_payload, version, exchange_type, flags) +
            struct.pack("!II", msg_id, total_len))


def build_ikev1(init_spi, resp_spi, exchange_type, payloads_first_type, payload_bytes,
                flags=0, msg_id=0):
    """Assemble a full IKEv1 message given the already-chained payload bytes."""
    total_len = 28 + len(payload_bytes)
    hdr = ike_v1_header(init_spi, resp_spi, payloads_first_type, exchange_type,
                        flags, msg_id, total_len)
    return hdr + payload_bytes


# ── IKEv2 encoders (RFC 7296) ────────────────────────────────────────────────
def v2_transform(ttype, tid, is_last: bool):
    """IKEv2 Transform substructure: last(1) resv(1) len(2) type(1) resv(1) id(2)."""
    last = 0 if is_last else 3   # 3 = more transforms
    length = 8
    return struct.pack("!BBHBBH", last, 0, length, ttype, 0, tid)


def v2_proposal(proposal_num, protocol_id, transforms: list, is_last: bool):
    """IKEv2 Proposal substructure: last(1) resv(1) len(2) pnum(1) proto(1) spisize(1) #tf(1) [spi] tfs."""
    last = 0 if is_last else 2   # 2 = more proposals
    spi = b""
    tf_bytes = b"".join(transforms)
    length = 8 + len(spi) + len(tf_bytes)
    return (struct.pack("!BBH", last, 0, length) +
            struct.pack("!BBBB", proposal_num, protocol_id, len(spi), len(transforms)) +
            spi + tf_bytes)


def v2_sa_payload(proposals: list, next_payload_after_sa: int):
    """IKEv2 SA payload: generic hdr + proposals."""
    body = b"".join(proposals)
    length = 4 + len(body)
    return struct.pack("!BBH", next_payload_after_sa, 0, length) + body


def v2_notify_payload(protocol_id, notify_type, next_payload_after, spi=b"", data=b""):
    """IKEv2 Notify payload: generic hdr + proto(1) spisize(1) type(2) [spi][data]."""
    body = struct.pack("!BBH", protocol_id, len(spi), notify_type) + spi + data
    length = 4 + len(body)
    return struct.pack("!BBH", next_payload_after, 0, length) + body


def ike_v2_header(init_spi, resp_spi, next_payload, exchange_type, flags, msg_id, total_len):
    version = 0x20  # major 2, minor 0
    return (init_spi + resp_spi +
            struct.pack("!BBBB", next_payload, version, exchange_type, flags) +
            struct.pack("!II", msg_id, total_len))


def build_ikev2(init_spi, resp_spi, exchange_type, first_payload_type, payload_bytes,
                flags=0, msg_id=0):
    total_len = 28 + len(payload_bytes)
    hdr = ike_v2_header(init_spi, resp_spi, first_payload_type, exchange_type,
                        flags, msg_id, total_len)
    return hdr + payload_bytes


def natt_wrap(ike_bytes):
    """Prepend the NAT-T non-ESP marker (UDP/4500)."""
    return b"\x00\x00\x00\x00" + ike_bytes
