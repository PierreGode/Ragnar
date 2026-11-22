#!/usr/bin/env python3
"""
lldpwatch_frames — dependency-free LLDP frame builders and pcap writer.

For test fixtures and lab replay ONLY. There are no sockets here and nothing
in this file transmits: it returns bytes and writes files. The lab borrows
tcpreplay against a sealed veth; Ragnar ships no LLDP transmitter in-tree.

Malformed builders are STRUCTURAL ONLY — a bad declared length, an oversized
field, an illegal subtype, an absurd count. No shellcode, no ROP, no gadgets,
no working exploit for any of the referenced CVEs.
"""

from __future__ import annotations

import struct
from typing import Iterable, List, Optional, Sequence, Tuple

ETHERTYPE_LLDP = 0x88CC
DST_NEAREST_BRIDGE = b"\x01\x80\xc2\x00\x00\x0e"
DST_NEAREST_NON_TPMR = b"\x01\x80\xc2\x00\x00\x03"
DST_NEAREST_CUSTOMER = b"\x01\x80\xc2\x00\x00\x00"

ETH_MIN_PAYLOAD = 46  # 60-octet minimum frame less the 14-octet header


def mac(s: str) -> bytes:
    return bytes(int(p, 16) for p in s.replace("-", ":").split(":"))


# --------------------------------------------------------------------------
# TLV primitives
# --------------------------------------------------------------------------


def tlv(ttype: int, value: bytes, declared: Optional[int] = None) -> bytes:
    """Build one TLV. `declared` overrides the length field, which is how the
    length-lie fixtures are made; it is never used by a benign builder."""
    ln = len(value) if declared is None else declared
    if not 0 <= ttype <= 0x7F:
        raise ValueError("TLV type out of range")
    if not 0 <= ln <= 0x1FF:
        raise ValueError("TLV length out of range (9-bit field)")
    return struct.pack("!H", ((ttype & 0x7F) << 9) | (ln & 0x1FF)) + value


def t_chassis_id(subtype: int = 4, body: bytes = b"\x00\x11\x22\x33\x44\x55",
                 declared: Optional[int] = None) -> bytes:
    return tlv(1, bytes([subtype]) + body, declared)


def t_port_id(subtype: int = 5, body: bytes = b"Gi1/0/1",
              declared: Optional[int] = None) -> bytes:
    return tlv(2, bytes([subtype]) + body, declared)


def t_ttl(seconds: int = 120, declared: Optional[int] = None) -> bytes:
    return tlv(3, struct.pack("!H", seconds), declared)


def t_port_desc(s: bytes = b"uplink to agg", declared: Optional[int] = None) -> bytes:
    return tlv(4, s, declared)


def t_sys_name(s: bytes = b"srv-14", declared: Optional[int] = None) -> bytes:
    return tlv(5, s, declared)


def t_sys_desc(s: bytes = b"GenericBox 400", declared: Optional[int] = None) -> bytes:
    return tlv(6, s, declared)


def t_sys_cap(cap: int = 0x0014, ena: int = 0x0004,
              declared: Optional[int] = None) -> bytes:
    return tlv(7, struct.pack("!HH", cap, ena), declared)


def t_mgmt_addr(
    af: int = 1,
    addr: bytes = b"\xc0\xa8\x01\x01",
    if_subtype: int = 2,
    if_number: int = 1,
    oid: bytes = b"",
    addr_strlen: Optional[int] = None,
    oid_len: Optional[int] = None,
    declared: Optional[int] = None,
) -> bytes:
    """Management Address TLV (type 8).

    DUAL-STACK: `af` is the IANA address-family subtype — 1 = IPv4 (4 octets),
    2 = IPv6 (16 octets). Both are first-class here; every bounds fixture has
    a v4 and a v6 form.
    """
    strlen = (1 + len(addr)) if addr_strlen is None else addr_strlen
    ol = len(oid) if oid_len is None else oid_len
    body = (
        bytes([strlen & 0xFF, af & 0xFF])
        + addr
        + bytes([if_subtype & 0xFF])
        + struct.pack("!I", if_number)
        + bytes([ol & 0xFF])
        + oid
    )
    return tlv(8, body, declared)


def t_org(oui: bytes, subtype: int, body: bytes = b"",
          declared: Optional[int] = None) -> bytes:
    return tlv(127, oui + bytes([subtype]) + body, declared)


def t_end() -> bytes:
    return tlv(0, b"")


OUI_8021 = b"\x00\x80\xc2"
OUI_8023 = b"\x00\x12\x0f"
OUI_MED = b"\x00\x12\xbb"

IPV4_ADDR = b"\xc0\xa8\x01\x01"
IPV6_ADDR = bytes.fromhex("20010db8000000000000000000000009")


# --------------------------------------------------------------------------
# Framing
# --------------------------------------------------------------------------


def frame(
    tlvs: Sequence[bytes],
    src: str = "02:00:00:00:00:01",
    dst: bytes = DST_NEAREST_BRIDGE,
    vlans: Sequence[int] = (),
    pad: bool = True,
    tail: bytes = b"",
) -> bytes:
    payload = b"".join(tlvs) + tail
    hdr = dst + mac(src)
    for vid in vlans:
        hdr += struct.pack("!HH", 0x8100, vid & 0x0FFF)
    out = hdr + struct.pack("!H", ETHERTYPE_LLDP) + payload
    if pad and len(out) < 60:
        out += b"\x00" * (60 - len(out))
    return out


def mandatory(
    chassis: bytes = None, port: bytes = None, ttl: bytes = None
) -> List[bytes]:
    return [
        chassis if chassis is not None else t_chassis_id(),
        port if port is not None else t_port_id(),
        ttl if ttl is not None else t_ttl(),
    ]


# --------------------------------------------------------------------------
# Benign fixtures
#
# LESSON (cdpwatch lab-fixture bug): a "clean" fixture must not carry an
# identity that legitimately screens. These neutral builders advertise a
# vendor-free System Name / Description so the clean-set silence contract
# means what it says. The vendor fixtures below are deliberately SEPARATE.
# --------------------------------------------------------------------------


def benign_minimal(src: str = "02:00:00:00:00:01") -> bytes:
    """Three mandatory TLVs and End — short enough that the kernel pads it,
    which is the exact shape that false-positived cdpwatch."""
    return frame(mandatory() + [t_end()], src=src)


def benign_full(src: str = "02:00:00:00:00:02") -> bytes:
    return frame(
        mandatory()
        + [
            t_port_desc(b"uplink to agg"),
            t_sys_name(b"srv-14"),
            t_sys_desc(b"GenericBox 400 software, build 7"),
            t_sys_cap(),
            t_mgmt_addr(af=1, addr=IPV4_ADDR),
            t_org(OUI_8021, 1, struct.pack("!H", 100)),
            t_org(OUI_8023, 4, struct.pack("!H", 1522)),
            t_end(),
        ],
        src=src,
    )


def benign_full_v6(src: str = "02:00:00:00:00:03") -> bytes:
    """Same shape with an IPv6 Management Address — the dual-stack clean case."""
    return frame(
        mandatory()
        + [
            t_sys_name(b"srv-15"),
            t_sys_desc(b"GenericBox 400 software, build 7"),
            t_mgmt_addr(af=2, addr=IPV6_ADDR),
            t_end(),
        ],
        src=src,
    )


def benign_tagged(src: str = "02:00:00:00:00:04", vid: int = 300) -> bytes:
    return frame(mandatory() + [t_end()], src=src, vlans=(vid,))


def benign_qinq(src: str = "02:00:00:00:00:05") -> bytes:
    return frame(mandatory() + [t_end()], src=src, vlans=(300, 12))


def benign_med_phone(src: str = "02:00:00:00:00:06") -> bytes:
    """A well-formed LLDP-MED advert. lldpwatch bounds-checks MED TLVs and
    builds NO voice semantics, so this must be silent."""
    return frame(
        mandatory()
        + [
            t_sys_name(b"desk-phone-22"),
            t_org(OUI_MED, 1, b"\x00\x21\x02"),
            t_org(OUI_MED, 2, b"\x01\x20\x64\x28"),
            t_org(OUI_MED, 4, b"\x01\x00\x90"),
            t_org(OUI_MED, 5, b"PH-9000"),
            t_end(),
        ],
        src=src,
    )


def benign_long_banner(src: str = "02:00:00:00:00:07") -> bytes:
    """A 200-octet System Description. Real banners run long; this must NOT
    fire LLDP-050 (the ceiling is the 255-octet spec maximum)."""
    return frame(
        mandatory() + [t_sys_desc(b"G" * 200), t_end()], src=src
    )


def _benign_padded_by(n: int, src: str) -> bytes:
    """A benign frame whose unpadded length leaves exactly `n` octets of
    kernel padding.

    WHY THESE EXIST (suite LESSON Z): with 1-3 octets of padding the all-zero
    tail is too short for the FCS branch to absorb, so it is the ONLY traffic
    that can tell a correct padding rule from one that has collapsed into the
    FCS rule. Without these fixtures a padding regression passes the lab's
    clean-set gate untouched - measured, not hypothesised.
    """
    fixed = len(frame(mandatory() + [t_end()], src=src, pad=False))
    want_total = 60 - n
    fill = want_total - fixed - 2  # 2 octets of TLV header for the System Name
    if fill < 0:
        raise ValueError("cannot build a frame padded by %d" % n)
    out = frame(
        mandatory()[:2] + [t_ttl(), t_sys_name(b"P" * fill), t_end()],
        src=src, pad=False,
    )
    if len(out) != want_total:
        out = frame(
            mandatory()[:2] + [t_ttl(), t_sys_name(b"P" * (fill + want_total - len(out))),
                               t_end()],
            src=src, pad=False,
        )
    return out + b"\x00" * (60 - len(out))


def benign_pad1(src: str = "02:00:00:00:00:0b") -> bytes:
    return _benign_padded_by(1, src)


def benign_pad2(src: str = "02:00:00:00:00:0c") -> bytes:
    return _benign_padded_by(2, src)


def benign_pad3(src: str = "02:00:00:00:00:0d") -> bytes:
    return _benign_padded_by(3, src)


def benign_with_fcs(src: str = "02:00:00:00:00:08") -> bytes:
    """Padded frame with a trailing 4-octet FCS, as some capture paths
    deliver. Must be silent when allow_fcs_tail is set."""
    return frame(mandatory() + [t_end()], src=src) + b"\xde\xad\xbe\xef"


# --- vendor fixtures (screen on purpose) ----------------------------------


def vendor_cisco(src: str = "02:00:00:00:0c:01") -> bytes:
    return frame(
        mandatory()
        + [
            t_sys_name(b"nexus-agg-01"),
            t_sys_desc(b"Cisco NX-OS(tm) n9000, Software (nxos.9.3.5.bin), Version 9.3(5)"),
            t_end(),
        ],
        src=src,
    )


def vendor_juniper(src: str = "02:00:00:00:0c:02") -> bytes:
    return frame(
        mandatory()
        + [
            t_sys_name(b"mx-edge-02"),
            t_sys_desc(b"Juniper Networks, Inc. mx480, Junos OS 20.4R3.8"),
            t_end(),
        ],
        src=src,
    )


def vendor_lldpd(src: str = "02:00:00:00:0c:03") -> bytes:
    return frame(
        mandatory()
        + [
            t_sys_name(b"leaf-07"),
            t_sys_desc(b"Debian GNU/Linux 12, lldpd 0.7.19"),
            t_end(),
        ],
        src=src,
    )


def vendor_ovs(src: str = "02:00:00:00:0c:04") -> bytes:
    return frame(
        mandatory()
        + [t_sys_desc(b"Open vSwitch 2.13.3"), t_end()], src=src
    )


def vendor_aruba_cx(src: str = "02:00:00:00:0c:07") -> bytes:
    return frame(
        mandatory()
        + [
            t_sys_name(b"cx-leaf-01"),
            t_sys_desc(b"Aruba JL658A 6300M 24SR5 CL6 PoE 4SFP56 Switch, FL.10.08.1010"),
            t_end(),
        ],
        src=src, pad=False,
    )


def vendor_ruckus(src: str = "02:00:00:00:0c:08") -> bytes:
    return frame(
        mandatory()
        + [
            t_sys_name(b"ap-lobby-03"),
            t_sys_desc(b"Ruckus R750 Multimedia Hotzone Wireless AP, version 6.1.0.0.1419"),
            t_end(),
        ],
        src=src, pad=False,
    )


def vendor_fortiswitch(src: str = "02:00:00:00:0c:09") -> bytes:
    return frame(
        mandatory()
        + [t_sys_desc(b"FortiSwitch-124E v6.4.5,build0000,210315"), t_end()],
        src=src, pad=False,
    )


def vendor_panos(src: str = "02:00:00:00:0c:0a") -> bytes:
    return frame(
        mandatory()
        + [
            t_sys_name(b"fw-edge-01"),
            t_sys_desc(b"Palo Alto Networks PA-3220 series firewall, PAN-OS 11.1.3"),
            t_end(),
        ],
        src=src, pad=False,
    )


# --------------------------------------------------------------------------
# DCBX fixtures.
#
# The two benign builders below are the frames that were verified byte for
# byte against Wireshark 4.2.2's independent DCBX dissector — zero malformed
# indications, every field read back as intended. They are the ground truth
# the rest of the DCBX work was written against, not hand-waved examples.
# --------------------------------------------------------------------------

OUI_CEE = b"\x00\x1b\x21"

ETS_PRIO_TABLE = bytes([0x01, 0x23, 0x45, 0x67])   # prio n -> TC n
ETS_BW_100 = bytes([25, 25, 0, 10, 10, 10, 10, 10])  # sums to 100 over ETS TCs
ETS_TSA_OK = bytes([2, 2, 0, 2, 2, 2, 2, 2])         # TC2 strict, rest ETS


def t_ets_config(maxtc: int = 0, willing: int = 1,
                 prio: bytes = None, bw: bytes = None, tsa: bytes = None,
                 declared: Optional[int] = None) -> bytes:
    """802.1Qaz ETS Configuration (subtype 9), 25 octets.

    maxtc is the RAW 3-bit field: 0 encodes 8 traffic classes.
    """
    b = (bytes([(willing << 7) | (maxtc & 0x07)])
         + (ETS_PRIO_TABLE if prio is None else prio)
         + (ETS_BW_100 if bw is None else bw)
         + (ETS_TSA_OK if tsa is None else tsa))
    return t_org(OUI_8021, 9, b, declared)


def t_ets_recommend(prio: bytes = None, bw: bytes = None,
                    tsa: bytes = None) -> bytes:
    return t_org(OUI_8021, 10,
                 bytes([0])
                 + (ETS_PRIO_TABLE if prio is None else prio)
                 + (ETS_BW_100 if bw is None else bw)
                 + (ETS_TSA_OK if tsa is None else tsa))


def t_pfc(cap: int = 8, enable: int = 0x18, willing: int = 1,
          declared: Optional[int] = None) -> bytes:
    """802.1Qaz PFC Configuration (subtype 11), 6 octets.

    cap is a 4-bit field where 8 encodes 8 — a DIFFERENT encoding from the
    ETS max-TC field above.
    """
    return t_org(OUI_8021, 11,
                 bytes([(willing << 7) | (cap & 0x0F), enable & 0xFF]),
                 declared)


def t_app(entries=((1, 1, 0x8906),), declared: Optional[int] = None,
          raw_table: Optional[bytes] = None) -> bytes:
    """802.1Qaz Application Priority (subtype 12). Entries are
    (priority, selector, protocol id), 3 octets each."""
    if raw_table is None:
        raw_table = b"".join(
            bytes([((p & 0x07) << 5) | (s & 0x07)]) + struct.pack("!H", pid)
            for p, s, pid in entries)
    return t_org(OUI_8021, 12, bytes([0]) + raw_table, declared)


def cee_subtlv(st: int, body: bytes, declared: Optional[int] = None) -> bytes:
    ln = len(body) if declared is None else declared
    return struct.pack("!H", ((st & 0x7F) << 9) | (ln & 0x1FF)) + body


def cee_control(seq: int = 1, ack: int = 0) -> bytes:
    return cee_subtlv(1, bytes([0, 0]) + struct.pack("!I", seq)
                      + struct.pack("!I", ack))


def cee_pg(bw: bytes = None, numtc: int = 8) -> bytes:
    # oper, max, flags, SUBTYPE, pgid(4), bw(8), numTC(1) — the subtype octet
    # is the one the dissector caught missing.
    return cee_subtlv(2, bytes([0, 0, 0xE0, 0x00]) + ETS_PRIO_TABLE
                      + (ETS_BW_100 if bw is None else bw) + bytes([numtc]))


def cee_pfc(enable: int = 0x18, numtc: int = 8) -> bytes:
    return cee_subtlv(3, bytes([0, 0, 0xE0, 0x00]) + bytes([enable, numtc]))


def t_cee(subtlvs: Sequence[bytes] = None,
          declared: Optional[int] = None) -> bytes:
    if subtlvs is None:
        subtlvs = (cee_control(), cee_pg(), cee_pfc())
    return t_org(OUI_CEE, 2, b"".join(subtlvs), declared)


def benign_dcbx_ieee(src: str = "02:00:00:00:dc:b1") -> bytes:
    """VERIFIED against Wireshark: ETS-Config + ETS-Recommendation + PFC +
    Application Priority, all fields read back correctly, no malformed."""
    return frame(
        mandatory() + [t_ets_config(), t_ets_recommend(), t_pfc(), t_app(),
                       t_end()],
        src=src, pad=False,
    )


def benign_dcbx_cee(src: str = "02:00:00:00:dc:b2") -> bytes:
    """VERIFIED against Wireshark: CEE 1.01 Control + Priority Groups + PFC."""
    return frame(mandatory() + [t_cee(), t_end()], src=src, pad=False)


def vendor_cisco_sb220(src: str = "02:00:00:00:0c:0d") -> bytes:
    return frame(
        mandatory()
        + [t_sys_name(b"sb220-closet-4"),
           t_sys_desc(b"Cisco SB220-24P-2SFP Smart Plus Switch, firmware 1.2.1.2"),
           t_end()],
        src=src, pad=False,
    )


def vendor_cisco_rv(src: str = "02:00:00:00:0c:0e") -> bytes:
    return frame(
        mandatory()
        + [t_sys_name(b"rv340-branch-7"),
           t_sys_desc(b"Cisco RV340 Dual WAN Gigabit VPN Router, 1.0.03.20"),
           t_end()],
        src=src, pad=False,
    )


def vendor_trendnet(src: str = "02:00:00:00:0c:0b") -> bytes:
    return frame(
        mandatory()
        + [
            t_sys_name(b"ti-pg1284i-plant-2"),
            t_sys_desc(b"TRENDnet TI-PG1284i Industrial Switch, firmware 1.0.4.S0"),
            t_end(),
        ],
        src=src, pad=False,
    )


def vendor_qnap(src: str = "02:00:00:00:0c:0c") -> bytes:
    return frame(
        mandatory()
        + [t_sys_desc(b"QSW-M2108-2C Managed Switch, QSS 1.0.1 build 20201215"),
           t_end()],
        src=src, pad=False,
    )


def vendor_sonicwall(src: str = "02:00:00:00:0c:05") -> bytes:
    return frame(
        mandatory()
        + [t_sys_desc(b"SonicWall SWS12-10FPOE firmware 1.0.1.3"), t_end()],
        src=src,
    )


# --------------------------------------------------------------------------
# Malformed fixtures — one per structural code, each in a v4 and v6 form
# where the Management Address surface makes that meaningful.
# --------------------------------------------------------------------------


def mal_length_overrun(src: str = "02:00:00:00:04:00") -> bytes:
    """LLDP-040 — System Description declares 400 octets, carries 10."""
    return frame(
        mandatory() + [t_sys_desc(b"shortvalue", declared=400), t_end()],
        src=src, pad=False,
    )


def mal_ttl_illegal(src: str = "02:00:00:00:04:01") -> bytes:
    """LLDP-041 — TTL TLV with a length the standard fixes at 2."""
    return frame(
        [t_chassis_id(), t_port_id(), tlv(3, b"\x00\x78\x00\x00"), t_end()],
        src=src,
    )


def mal_stray_octet(src: str = "02:00:00:00:04:0f") -> bytes:
    """LLDP-041 — a single trailing octet where a 2-octet TLV header must be."""
    return frame(
        mandatory(), src=src, pad=False, tail=b"\x02"
    )


def mal_missing_mandatory(src: str = "02:00:00:00:04:02") -> bytes:
    """LLDP-042 — no TTL TLV at all."""
    return frame([t_chassis_id(), t_port_id(), t_sys_name(b"srv-14"), t_end()], src=src)


def mal_missing_chassis_id(src: str = "02:00:00:00:04:1b") -> bytes:
    """LLDP-042 — an LLDPDU with NO Chassis ID TLV.

    The exact CVE-2021-33317 trigger (TRENDnet TI-series, null-pointer
    dereference on a frame that omits the mandatory Chassis ID). Already
    covered by the mandatory-TLV grammar rule; named separately so the
    specific trigger shape has its own fixture rather than riding on the
    generic missing-TTL case.
    """
    return frame([t_port_id(), t_ttl(), t_sys_name(b"srv-14"), t_end()], src=src)


def mal_chassis_id_underflow(src: str = "02:00:00:00:04:1c") -> bytes:
    """LLDP-046 — a Chassis ID TLV declaring length 1: a subtype octet and no
    identifier at all.

    The CVE-2021-33316 trigger shape (TRENDnet, 9.8): the length field is not
    validated, so the device's own arithmetic underflows and hands memcpy() a
    negative count. On the wire the signal is a mandatory ID TLV too short to
    hold what its subtype promises. Structural only.
    """
    return frame([tlv(1, b"\x04"), t_port_id(), t_ttl(), t_end()], src=src)


def mal_port_id_underflow(src: str = "02:00:00:00:04:1d") -> bytes:
    """LLDP-047 — the same shape on the Port ID TLV: the CVE-2021-33315
    trigger (TRENDnet, 9.8). Separate fixture because it is a separate code
    path and a separate CVE, and one fixture cannot stand in for both."""
    return frame([t_chassis_id(), tlv(2, b"\x05"), t_ttl(), t_end()], src=src)


def mal_out_of_order(src: str = "02:00:00:00:04:03") -> bytes:
    """LLDP-043 — Port ID before Chassis ID."""
    return frame([t_port_id(), t_chassis_id(), t_ttl(), t_end()], src=src)


def mal_duplicate_tlv(src: str = "02:00:00:00:04:04") -> bytes:
    """LLDP-044 — two System Name TLVs."""
    return frame(
        mandatory() + [t_sys_name(b"srv-14"), t_sys_name(b"other-14"), t_end()],
        src=src,
    )


def mal_mgmt_oversized_strlen(src: str = "02:00:00:00:04:05") -> bytes:
    """LLDP-045 — address string length 200, over the 31-octet legal maximum.
    This is the CVE-2015-8011 shape (oversized management address)."""
    return frame(
        mandatory()
        + [t_mgmt_addr(af=1, addr=IPV4_ADDR, addr_strlen=200), t_end()],
        src=src,
    )


def mal_mgmt_strlen_overrun(src: str = "02:00:00:00:04:06") -> bytes:
    """LLDP-045 — declared address string length runs past the TLV end."""
    return frame(
        mandatory()
        + [t_mgmt_addr(af=1, addr=IPV4_ADDR, addr_strlen=30), t_end()],
        src=src,
    )


def mal_mgmt_v6_short(src: str = "02:00:00:00:04:07") -> bytes:
    """LLDP-045 DUAL-STACK — subtype 2 (IPv6) carrying a 4-octet address.
    A v4-only length check reads this as fine."""
    return frame(
        mandatory() + [t_mgmt_addr(af=2, addr=IPV4_ADDR), t_end()], src=src
    )


def mal_mgmt_v4_long(src: str = "02:00:00:00:04:08") -> bytes:
    """LLDP-045 DUAL-STACK — subtype 1 (IPv4) carrying a 16-octet address."""
    return frame(
        mandatory() + [t_mgmt_addr(af=1, addr=IPV6_ADDR), t_end()], src=src
    )


def mal_mgmt_oid_overrun(src: str = "02:00:00:00:04:09") -> bytes:
    """LLDP-045 — OID length claims more than the TLV holds."""
    return frame(
        mandatory()
        + [t_mgmt_addr(af=1, addr=IPV4_ADDR, oid=b"\x01\x02", oid_len=120), t_end()],
        src=src,
    )


def mal_mgmt_truncated(src: str = "02:00:00:00:04:0a") -> bytes:
    """LLDP-045 — TLV ends immediately after the address."""
    return frame(
        mandatory() + [tlv(8, bytes([5, 1]) + IPV4_ADDR), t_end()], src=src
    )


def mal_chassis_mac_wrong_len(src: str = "02:00:00:00:04:0b") -> bytes:
    """LLDP-046 — subtype 4 (MAC address) with 9 octets."""
    return frame(
        [t_chassis_id(subtype=4, body=b"\x01" * 9), t_port_id(), t_ttl(), t_end()],
        src=src,
    )


def mal_chassis_reserved_subtype(src: str = "02:00:00:00:04:0c") -> bytes:
    """LLDP-046 — subtype 9 is reserved."""
    return frame(
        [t_chassis_id(subtype=9, body=b"abc"), t_port_id(), t_ttl(), t_end()],
        src=src,
    )


def mal_chassis_v6_mismatch(src: str = "02:00:00:00:04:0d") -> bytes:
    """LLDP-046 DUAL-STACK — network-address subtype claiming IPv6 with a
    4-octet address."""
    return frame(
        [
            t_chassis_id(subtype=5, body=bytes([2]) + IPV4_ADDR),
            t_port_id(), t_ttl(), t_end(),
        ],
        src=src,
    )


def mal_port_mac_wrong_len(src: str = "02:00:00:00:04:0e") -> bytes:
    """LLDP-047 — Port ID subtype 3 (MAC) with 2 octets."""
    return frame(
        [t_chassis_id(), t_port_id(subtype=3, body=b"\xaa\xbb"), t_ttl(), t_end()],
        src=src,
    )


def mal_port_v6_mismatch(src: str = "02:00:00:00:04:10") -> bytes:
    """LLDP-047 DUAL-STACK — Port ID network-address subtype 4 claiming IPv4
    with a 16-octet address."""
    return frame(
        [
            t_chassis_id(),
            t_port_id(subtype=4, body=bytes([1]) + IPV6_ADDR),
            t_ttl(), t_end(),
        ],
        src=src,
    )


def mal_oversized_sysdesc(src: str = "02:00:00:00:04:11") -> bytes:
    """LLDP-050 — 400-octet System Description, over the 255-octet spec max
    but inside the 9-bit length field, so it is reachable on the wire."""
    return frame(mandatory() + [t_sys_desc(b"A" * 400), t_end()], src=src, pad=False)


def mal_oversized_sysname(src: str = "02:00:00:00:04:12") -> bytes:
    """LLDP-050 — 300-octet System Name."""
    return frame(mandatory() + [t_sys_name(b"N" * 300), t_end()], src=src, pad=False)


def mal_org_short(src: str = "02:00:00:00:04:13") -> bytes:
    """LLDP-051 — Organizationally Specific TLV shorter than OUI + subtype."""
    return frame(mandatory() + [tlv(127, b"\x00\x80"), t_end()], src=src)


def mal_org_fixed_len(src: str = "02:00:00:00:04:14") -> bytes:
    """LLDP-051 — 802.3 MAC/PHY (fixed at 9) carrying 20 octets."""
    return frame(
        mandatory() + [t_org(OUI_8023, 1, b"\x00" * 16), t_end()], src=src, pad=False
    )


def mal_med_inventory_oversized(src: str = "02:00:00:00:04:15") -> bytes:
    """LLDP-051 — MED inventory string over the 32-octet ceiling. Bounds only;
    no MED semantics are evaluated."""
    return frame(
        mandatory() + [t_org(OUI_MED, 5, b"X" * 60), t_end()], src=src, pad=False
    )


def mal_org_oversized_unknown_oui(src: str = "02:00:00:00:04:19") -> bytes:
    """LLDP-051 — a 420-octet Organizationally Specific TLV under an OUI the
    engine does not recognise.

    This is the CVE-2026-22627 structural class (FortiSwitch, buffer overflow
    in the LLDP OUI field, unauthenticated adjacent RCE). Before the general
    ceiling existed this frame was COMPLETELY SILENT: every org-specific rule
    was keyed on a recognised (OUI, subtype) pair, so an unknown OUI had no
    upper length bound at all. Structural only — an oversized field, no
    working exploit.
    """
    return frame(
        mandatory() + [t_org(b"\x00\xde\xad", 9, b"A" * 416), t_end()],
        src=src, pad=False,
    )


def mal_org_oversized_known_oui_unknown_sub(src: str = "02:00:00:00:04:1a") -> bytes:
    """LLDP-051 — the same gap reached the other way: a RECOGNISED OUI
    (LLDP-MED) with a subtype that has no fixed-length rule, at 400 octets.
    A ceiling applied only to unknown OUIs would miss this."""
    return frame(
        mandatory() + [t_org(OUI_MED, 99, b"B" * 396), t_end()],
        src=src, pad=False,
    )


# --- DCBX malformed fixtures (structural only) ----------------------------

def mal_dcbx_ets_wrong_len(src: str = "02:00:00:00:dc:01") -> bytes:
    """LLDP-060 — ETS Configuration that really is 20 octets; 802.1Qaz fixes
    it at 25.

    Built with a genuinely SHORT BODY, not a shortened length field. Using
    `declared=20` over a 21-octet body left one octet stranded outside the
    TLV, which the walker then read as a stray header and cascaded into three
    unrelated codes — a fixture testing four rules instead of one.
    """
    short = (bytes([0x88]) + ETS_PRIO_TABLE + ETS_BW_100 + bytes([2, 2, 0]))
    return frame(mandatory() + [t_org(OUI_8021, 9, short), t_end()],
                 src=src, pad=False)


def mal_dcbx_oversized(src: str = "02:00:00:00:dc:02") -> bytes:
    """LLDP-060 — a 300-octet CEE DCBX TLV, over the 256-octet ceiling."""
    filler = cee_subtlv(9, b"\x00" * 280)
    return frame(mandatory() + [t_cee(subtlvs=(cee_control(), filler)),
                                t_end()], src=src, pad=False)


def mal_dcbx_ets_bw_sum(src: str = "02:00:00:00:dc:03") -> bytes:
    """LLDP-061 — ETS bandwidth totals 90% across its ETS traffic classes.

    802.1Qaz requires exactly 100. The single best self-marking signal that
    an ETS advertisement was not produced by a conforming scheduler.
    """
    return frame(mandatory()
                 + [t_ets_config(bw=bytes([25, 25, 0, 10, 10, 10, 10, 0])),
                    t_end()], src=src, pad=False)


def mal_dcbx_tsa_illegal(src: str = "02:00:00:00:dc:04") -> bytes:
    """LLDP-062 — TSA value 7, which 802.1Qaz does not define. Bandwidth is
    rebalanced so the ETS total stays exactly 100 and this fixture tests one
    rule, not two."""
    return frame(mandatory()
                 + [t_ets_config(bw=bytes([0, 30, 0, 14, 14, 14, 14, 14]),
                                 tsa=bytes([7, 2, 0, 2, 2, 2, 2, 2])),
                    t_end()], src=src, pad=False)


def mal_dcbx_prio_beyond_tc(src: str = "02:00:00:00:dc:05") -> bytes:
    """LLDP-062 — priorities mapped onto TC 4-7 while advertising 4 traffic
    classes; a receiver indexing its TC table by that value reads past it."""
    return frame(mandatory() + [t_ets_config(maxtc=4), t_end()],
                 src=src, pad=False)


def mal_dcbx_bw_on_strict(src: str = "02:00:00:00:dc:06") -> bytes:
    """LLDP-062 — bandwidth assigned to a strict-priority traffic class,
    where a bandwidth share has no meaning. ETS total still 100."""
    return frame(mandatory()
                 + [t_ets_config(bw=bytes([25, 25, 10, 10, 10, 10, 10, 10])),
                    t_end()], src=src, pad=False)


def mal_dcbx_pfc_cap_high(src: str = "02:00:00:00:dc:07") -> bytes:
    """LLDP-063 — PFC capability 12; the field cannot exceed 8."""
    return frame(mandatory() + [t_pfc(cap=12), t_end()], src=src, pad=False)


def mal_dcbx_pfc_over_cap(src: str = "02:00:00:00:dc:08") -> bytes:
    """LLDP-063 — PFC enabled on all 8 priorities while advertising capacity
    for 2. Enabling more lossless classes than the device can honour is the
    forged-PFC shape that starves a traffic class."""
    return frame(mandatory() + [t_pfc(cap=2, enable=0xFF), t_end()],
                 src=src, pad=False)


def mal_dcbx_app_truncated(src: str = "02:00:00:00:dc:09") -> bytes:
    """LLDP-064 — Application Priority table truncated mid-entry."""
    return frame(mandatory() + [t_app(raw_table=b"\x21\x89\x06\x21"),
                                t_end()], src=src, pad=False)


def mal_dcbx_app_reserved_sel(src: str = "02:00:00:00:dc:0a") -> bytes:
    """LLDP-064 — Application selector 6, a reserved value."""
    return frame(mandatory() + [t_app(entries=((1, 6, 0x8906),)), t_end()],
                 src=src, pad=False)


def mal_dcbx_duplicate_ets(src: str = "02:00:00:00:dc:0b") -> bytes:
    """LLDP-065 — two ETS Configuration TLVs; at most one is permitted and
    which copy a receiver keeps is implementation-defined."""
    return frame(mandatory() + [t_ets_config(), t_ets_config(), t_end()],
                 src=src, pad=False)


def mal_dcbx_version_conflict(src: str = "02:00:00:00:dc:0c") -> bytes:
    """LLDP-066 — IEEE 802.1Qaz and CEE DCBX advertised together."""
    return frame(mandatory() + [t_ets_config(), t_cee(), t_end()],
                 src=src, pad=False)


def mal_dcbx_cee_overrun(src: str = "02:00:00:00:dc:0d") -> bytes:
    """LLDP-067 — a CEE sub-TLV declaring more octets than the enclosing
    TLV holds."""
    return frame(mandatory()
                 + [t_cee(subtlvs=(cee_control(),
                                   cee_subtlv(3, b"\x00" * 6, declared=400))),
                    t_end()], src=src, pad=False)


def mal_dcbx_cee_unknown_overrun(src: str = "02:00:00:00:dc:11") -> bytes:
    """LLDP-067 — a sub-TLV with NO pinned length whose declared size runs
    past the enclosing TLV.

    Exists because mal_dcbx_cee_overrun could not reach the bounds check:
    it used the PFC type, which has a fixed length, so the fixed-length rule
    fired first and disabling the bounds check changed nothing in any tier
    (suite LESSON AF). The Application feature has no pinned size, so this
    frame can only be caught by the bounds walk.
    """
    return frame(mandatory()
                 + [t_cee(subtlvs=(cee_control(),
                                   cee_subtlv(4, b"\x00\x00\xE0\x00",
                                              declared=400))),
                    t_end()], src=src, pad=False)


def mal_dcbx_cee_pg_wrong_len(src: str = "02:00:00:00:dc:0e") -> bytes:
    """LLDP-067 — Priority Groups sub-TLV one octet short of the pinned
    17-octet layout. This is the exact shape the Wireshark cross-check caught
    in the first draft, where the subtype octet had been omitted."""
    short = cee_subtlv(2, bytes([0, 0, 0xE0, 0x00]) + ETS_PRIO_TABLE
                       + ETS_BW_100)
    return frame(mandatory() + [t_cee(subtlvs=(cee_control(), short)),
                                t_end()], src=src, pad=False)


def mal_dcbx_cee_empty(src: str = "02:00:00:00:dc:0f") -> bytes:
    """LLDP-067 — CEE DCBX TLV with no sub-TLVs; Control is mandatory."""
    return frame(mandatory() + [t_cee(subtlvs=()), t_end()],
                 src=src, pad=False)


def mal_dcbx_cee_stray_octet(src: str = "02:00:00:00:dc:10") -> bytes:
    """LLDP-067 — a single stray octet where a 2-octet sub-TLV header must
    begin."""
    return frame(mandatory()
                 + [t_org(OUI_CEE, 2, b"".join([cee_control()]) + b"\x01"),
                    t_end()], src=src, pad=False)


def dcbx_conflict_frames() -> List[bytes]:
    """LLDP-068 — two neighbours on one segment advertising DIFFERENT PFC
    configuration. Not merely two speakers, which is legal."""
    return [
        frame(mandatory() + [t_pfc(cap=8, enable=0x18), t_end()],
              src="02:00:00:00:dc:21", pad=False),
        frame(mandatory() + [t_pfc(cap=8, enable=0x03), t_end()],
              src="02:00:00:00:dc:22", pad=False),
    ]


def dcbx_churn_frames(n: int = 6) -> List[bytes]:
    """LLDP-069 — one source repeatedly re-advertising which priorities are
    lossless: the observable half of a pause attack."""
    out = []
    for i in range(n):
        out.append(frame(mandatory()
                         + [t_pfc(cap=8, enable=0x18 if i % 2 else 0x03),
                            t_end()],
                         src="02:00:00:00:dc:30", pad=False))
    return out


DCBX_MALFORMED = {
    "LLDP-060": (mal_dcbx_ets_wrong_len, mal_dcbx_oversized),
    "LLDP-061": (mal_dcbx_ets_bw_sum,),
    "LLDP-062": (mal_dcbx_tsa_illegal, mal_dcbx_prio_beyond_tc,
                 mal_dcbx_bw_on_strict),
    "LLDP-063": (mal_dcbx_pfc_cap_high, mal_dcbx_pfc_over_cap),
    "LLDP-064": (mal_dcbx_app_truncated, mal_dcbx_app_reserved_sel),
    "LLDP-065": (mal_dcbx_duplicate_ets,),
    "LLDP-066": (mal_dcbx_version_conflict,),
    "LLDP-067": (mal_dcbx_cee_overrun, mal_dcbx_cee_unknown_overrun,
                 mal_dcbx_cee_pg_wrong_len, mal_dcbx_cee_empty,
                 mal_dcbx_cee_stray_octet),
}


def mal_reserved_tlv_type(src: str = "02:00:00:00:04:16") -> bytes:
    """LLDP-052 — TLV type 64, inside the reserved 9-126 range."""
    return frame(mandatory() + [tlv(64, b"\x00\x01\x02"), t_end()], src=src)


def mal_trailing_data(src: str = "02:00:00:00:04:17") -> bytes:
    """LLDP-053 — non-zero data after End-of-LLDPDU, past where a
    length-respecting parser stops reading."""
    return frame(
        mandatory() + [t_end()], src=src, pad=False,
        tail=b"SMUGGLED-PAST-THE-END",
    )


def mal_no_end(src: str = "02:00:00:00:04:18") -> bytes:
    """LLDP-054 — no End-of-LLDPDU TLV. Unpadded, or the padding would supply
    a perfectly legal one."""
    return frame(mandatory() + [t_sys_name(b"srv-14")], src=src, pad=False)


MALFORMED_BUILDERS = {
    **DCBX_MALFORMED,
    "LLDP-040": (mal_length_overrun,),
    "LLDP-041": (mal_ttl_illegal, mal_stray_octet),
    "LLDP-042": (mal_missing_mandatory, mal_missing_chassis_id),
    "LLDP-043": (mal_out_of_order,),
    "LLDP-044": (mal_duplicate_tlv,),
    "LLDP-045": (
        mal_mgmt_oversized_strlen, mal_mgmt_strlen_overrun, mal_mgmt_v6_short,
        mal_mgmt_v4_long, mal_mgmt_oid_overrun, mal_mgmt_truncated,
    ),
    "LLDP-046": (
        mal_chassis_mac_wrong_len, mal_chassis_reserved_subtype,
        mal_chassis_v6_mismatch, mal_chassis_id_underflow,
    ),
    "LLDP-047": (mal_port_mac_wrong_len, mal_port_v6_mismatch,
                 mal_port_id_underflow),
    "LLDP-050": (mal_oversized_sysdesc, mal_oversized_sysname),
    "LLDP-051": (
        mal_org_short, mal_org_fixed_len, mal_med_inventory_oversized,
        mal_org_oversized_unknown_oui, mal_org_oversized_known_oui_unknown_sub,
    ),
    "LLDP-052": (mal_reserved_tlv_type,),
    "LLDP-053": (mal_trailing_data,),
    "LLDP-054": (mal_no_end,),
}

BENIGN_BUILDERS = (
    benign_minimal, benign_full, benign_full_v6, benign_tagged, benign_qinq,
    benign_med_phone, benign_long_banner, benign_with_fcs,
    benign_pad1, benign_pad2, benign_pad3,
    benign_dcbx_ieee, benign_dcbx_cee,
)

VENDOR_BUILDERS = {
    "LLDP-020": vendor_cisco,
    "LLDP-021": vendor_juniper,
    "LLDP-022": vendor_lldpd,
    "LLDP-023": vendor_ovs,
    "LLDP-024": vendor_sonicwall,
    "LLDP-027": vendor_aruba_cx,
    "LLDP-028": vendor_ruckus,
    "LLDP-029": vendor_fortiswitch,
    "LLDP-030": vendor_panos,
    "LLDP-033": vendor_cisco_sb220,
    "LLDP-034": vendor_cisco_rv,
    "LLDP-031": vendor_trendnet,
    "LLDP-032": vendor_qnap,
}


def flood_frames(count: int = 40, base_src: int = 0x020000000900) -> List[bytes]:
    """A burst from many distinct source MACs — the neighbour-table
    exhaustion / sustained-leak shape behind CVE-2020-27827 and
    CVE-2023-20089. Each frame is individually WELL-FORMED, which is the
    honest point: these two CVEs have no crisp single-frame signature."""
    out = []
    for i in range(count):
        v = base_src + i
        s = ":".join("%02x" % ((v >> (8 * (5 - k))) & 0xFF) for k in range(6))
        out.append(
            frame(
                [
                    t_chassis_id(body=bytes.fromhex("%012x" % v)),
                    t_port_id(body=b"eth0"),
                    t_ttl(),
                    t_end(),
                ],
                src=s,
            )
        )
    return out


# --------------------------------------------------------------------------
# pcap writer
# --------------------------------------------------------------------------

PCAP_MAGIC = 0xA1B2C3D4
DLT_EN10MB = 1


def write_pcap(
    path: str,
    frames: Iterable[bytes],
    base_ts: float = 1_700_000_000.0,
    interval: float = 0.001,
    snaplen: int = 65535,
) -> int:
    """Write a DLT_EN10MB pcap.

    TIMESTAMPS (cdpwatch bug, do not reintroduce): each frame is stamped
    base_ts + i*interval with a microsecond carry. Stamping the frame INDEX
    into the seconds field makes tcpreplay — which replays at the recorded
    rate by default — space frames a second apart, which silently prevents
    any rate-based finding from ever accumulating.
    """
    n = 0
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, snaplen, DLT_EN10MB))
        for i, f in enumerate(frames):
            t = base_ts + i * interval
            sec = int(t)
            usec = int(round((t - sec) * 1_000_000))
            if usec >= 1_000_000:  # carry
                sec += 1
                usec -= 1_000_000
            fh.write(struct.pack("<IIII", sec, usec, len(f), len(f)))
            fh.write(f)
            n += 1
    return n


def read_pcap(path: str) -> List[Tuple[float, bytes]]:
    """Minimal reader, used by the harness to assert its own artefacts."""
    out: List[Tuple[float, bytes]] = []
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            raise ValueError("short pcap header")
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic != PCAP_MAGIC:
            raise ValueError("unexpected pcap magic 0x%08x" % magic)
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                break
            sec, usec, incl, _orig = struct.unpack("<IIII", rec)
            data = fh.read(incl)
            if len(data) < incl:
                raise ValueError("truncated pcap record")
            out.append((sec + usec / 1_000_000.0, data))
    return out
