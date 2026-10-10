"""Test frame builders for oamwatch.

Every malformed fixture here is STRUCTURAL - a bad length, an out-of-range
field, an illegal encoding, an absurd count. None of them is a working exploit
and none is a payload builder. These exist so the parser and engine can be
driven offline and through a sealed veth pair; nothing in the shipped package
imports this module.
"""

import struct

DST = b"\x01\x80\xc2\x00\x00\x02"
SRC_A = b"\x00\x11\x22\x33\x44\x55"
SRC_B = b"\x00\xaa\xbb\xcc\xdd\xee"
ETHERTYPE = 0x8809
SUBTYPE = 0x03

OUI_A = b"\x00\x0a\x0b"
OUI_B = b"\x00\xde\xad"
VENDOR_A = b"\x00\x00\x00\x01"
VENDOR_B = b"\x00\x00\x00\x02"

# Flags
F_LINK_FAULT = 0x0001
F_DYING_GASP = 0x0002
F_CRITICAL = 0x0004
F_LOCAL_EVAL = 0x0008
F_LOCAL_STABLE = 0x0010
F_REMOTE_EVAL = 0x0020
F_REMOTE_STABLE = 0x0040
FLAGS_OPERATIONAL = F_LOCAL_STABLE | F_REMOTE_STABLE
FLAGS_DISCOVERY = F_LOCAL_EVAL | F_REMOTE_EVAL

# OAM Configuration bits
C_ACTIVE = 0x01
C_UNIDIR = 0x02
C_LOOPBACK = 0x04
C_EVENTS = 0x08
C_VARS = 0x10
CFG_TYPICAL = C_ACTIVE | C_LOOPBACK | C_EVENTS


def eth(code, body, flags=FLAGS_OPERATIONAL, src=SRC_A, dst=DST,
        ethertype=ETHERTYPE, subtype=SUBTYPE, pad=True):
    f = (dst + src + struct.pack("!H", ethertype) + bytes([subtype])
         + struct.pack("!H", flags) + bytes([code]) + body)
    if pad and len(f) < 60:
        f = f.ljust(60, b"\x00")
    return f


def info_tlv(kind=1, version=1, revision=0, state=0x00, config=CFG_TYPICAL,
             max_pdu=1518, oui=OUI_A, vendor=VENDOR_A, length=0x10):
    """Local (kind=1) or Remote (kind=2) Information TLV."""
    val = (bytes([version]) + struct.pack("!H", revision)
           + bytes([state, config]) + struct.pack("!H", max_pdu)
           + oui + vendor)
    return bytes([kind, length]) + val


def information(tlvs=None, flags=FLAGS_OPERATIONAL, src=SRC_A, end=True,
                **kw):
    if tlvs is None:
        tlvs = [info_tlv()]
    body = b"".join(tlvs) + (b"\x00" if end else b"")
    return eth(0x00, body, flags=flags, src=src, **kw)


def keepalive(flags=FLAGS_OPERATIONAL, src=SRC_A):
    """Information OAMPDU with no TLVs. Legal once discovery has completed."""
    return eth(0x00, b"\x00", flags=flags, src=src)


def event_tlv(kind, length=None, timestamp=0):
    fixed = {0x01: 40, 0x02: 26, 0x03: 28, 0x04: 18}
    ln = fixed[kind] if length is None else length
    val = struct.pack("!H", timestamp) + b"\x00" * max(0, ln - 4)
    return bytes([kind, ln]) + val


def event_notification(seq=1, tlvs=None, src=SRC_A, flags=FLAGS_OPERATIONAL):
    if tlvs is None:
        tlvs = [event_tlv(0x02)]
    body = struct.pack("!H", seq) + b"".join(tlvs) + b"\x00"
    return eth(0x01, body, flags=flags, src=src)


def variable_request(descriptors=((0x07, 0x0001),), src=SRC_A,
                     flags=FLAGS_OPERATIONAL):
    body = b"".join(bytes([b]) + struct.pack("!H", l) for b, l in descriptors)
    return eth(0x02, body + b"\x00", flags=flags, src=src)


def variable_response(containers=((0x07, 0x0001, b"\xde\xad\xbe\xef"),),
                      src=SRC_A, flags=FLAGS_OPERATIONAL, width_override=None):
    out = b""
    for br, leaf, val in containers:
        w = len(val) if width_override is None else width_override
        out += bytes([br]) + struct.pack("!H", leaf) + bytes([w]) + val
    return eth(0x03, out + b"\x00", flags=flags, src=src)


def variable_response_error(branch=0x07, leaf=0x0001, width=0x81, src=SRC_A):
    body = bytes([branch]) + struct.pack("!H", leaf) + bytes([width])
    return eth(0x03, body + b"\x00", flags=FLAGS_OPERATIONAL, src=src)


def loopback_control(command=0x01, src=SRC_A, flags=FLAGS_OPERATIONAL,
                     omit=False):
    body = b"" if omit else bytes([command])
    return eth(0x04, body, flags=flags, src=src)


def org_specific(oui=OUI_A, data=b"\x01\x02\x03", src=SRC_A):
    return eth(0xFE, oui + data, src=src)


# ---- clean reference set -------------------------------------------------
def clean_set():
    """Well-formed, non-suspicious traffic. Nothing here may produce a
    structural or abuse finding; posture findings are expected and are
    excluded explicitly by the silence contract."""
    return [
        information(flags=FLAGS_DISCOVERY),
        information([info_tlv(1), info_tlv(2, oui=OUI_B, vendor=VENDOR_B)]),
        keepalive(),
        keepalive(),
        event_notification(seq=1),
        event_notification(seq=2, tlvs=[event_tlv(0x01), event_tlv(0x04)]),
        information(),
        keepalive(),
        variable_response_error(),
        org_specific(),
    ]
