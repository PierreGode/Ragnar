#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the cfmwatch fixture corpus.

This writes pcap FILES. It opens no socket and sends nothing; the frames
only ever reach a wire when the sealed-lab tier hands a file to tcpreplay
inside a routeless network namespace. The transmit-guard scan (tier 3)
asserts that against this file as well as the module.

Timestamps are base_ts + cumulative offset. Never stamp the frame index
into the seconds field: tcpreplay then replays at one frame per second and
silently disarms every rate-based finding.
"""

from __future__ import annotations

import json
import os
import struct
import sys
from typing import Dict, List, Tuple

BASE_TS = 1760000000.0          # fixed, so fixtures are reproducible
FIXDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

MAC_A = bytes.fromhex("001122aa0001")
MAC_B = bytes.fromhex("001122bb0002")
MAC_C = bytes.fromhex("001122cc0003")
MAC_X = bytes.fromhex("00deadbeef99")


def cfm_group(level: int, klass: int = 1) -> bytes:
    return bytes.fromhex("0180c2000030")[:5] + \
        bytes([0x30 | (level & 0x7) | (0x08 if klass == 2 else 0)])


def eth(dst: bytes, src: bytes, payload: bytes,
        vlans: Tuple[Tuple[int, int], ...] = ((0x8100, 100),),
        minlen: int = 60) -> bytes:
    body = b""
    for tpid, vid in vlans:
        body += struct.pack("!HH", tpid, vid & 0x0FFF)
    body += struct.pack("!H", 0x8902) + payload
    frame = dst + src + body
    if len(frame) < minlen:
        frame += b"\x00" * (minlen - len(frame))
    return frame


def cfm(level: int, opcode: int, flags: int, fto: int, body: bytes = b"",
        tlvs: bytes = b"", version: int = 0) -> bytes:
    hdr = bytes([((level & 0x7) << 5) | (version & 0x1F), opcode, flags, fto])
    return hdr + body + tlvs


def maid(md_fmt: int = 4, md_name: bytes = b"DOMAIN1",
         ma_fmt: int = 2, ma_name: bytes = b"MA-100",
         md_len: int | None = None, ma_len: int | None = None) -> bytes:
    out = bytes([md_fmt])
    if md_fmt != 1:
        out += bytes([md_len if md_len is not None else len(md_name)])
        out += md_name
    out += bytes([ma_fmt, ma_len if ma_len is not None else len(ma_name)])
    out += ma_name
    return out.ljust(48, b"\x00")[:48]


def ccm_body(seq: int, mepid: int, m: bytes) -> bytes:
    return struct.pack("!IH", seq, mepid) + m + b"\x00" * 16


def ccm(level: int, mepid: int, seq: int = 1, interval: int = 4,
        rdi: bool = False, m: bytes | None = None, fto: int = 70) -> bytes:
    flags = (0x80 if rdi else 0) | (interval & 0x07)
    return cfm(level, 1, flags, fto,
               ccm_body(seq, mepid, m if m is not None else maid()),
               b"\x00")


def tlv(ttype: int, value: bytes) -> bytes:
    return bytes([ttype]) + struct.pack("!H", len(value)) + value


END = b"\x00"


def lbm(level: int, tid: int = 1, extra: bytes = b"") -> bytes:
    return cfm(level, 3, 0, 4, struct.pack("!I", tid), extra + END)


def lbr(level: int, tid: int = 1, extra: bytes = b"") -> bytes:
    return cfm(level, 2, 0, 4, struct.pack("!I", tid), extra + END)


def ltm(level: int, tid: int, ttl: int, orig: bytes, target: bytes) -> bytes:
    return cfm(level, 5, 0x80, 17,
               struct.pack("!IB", tid, ttl) + orig + target, END)


def ltr(level: int, tid: int, ttl: int, relay: int = 2,
        extra: bytes = b"") -> bytes:
    return cfm(level, 4, 0x60, 6, struct.pack("!IBB", tid, ttl, relay),
               extra + END)


def ais(level: int, period: int = 4) -> bytes:
    return cfm(level, 33, period & 0x07, 0, b"", END)


def lck(level: int, period: int = 4) -> bytes:
    return cfm(level, 35, period & 0x07, 0, b"", END)


def csf(level: int, period: int = 4) -> bytes:
    return cfm(level, 52, period & 0x07, 0, b"", END)


def lmm(level: int) -> bytes:
    return cfm(level, 43, 0, 12, struct.pack("!III", 1000, 0, 0), END)


def aps(level: int, request: int, ptype: int = 0x1, req_sig: int = 1,
        br_sig: int = 1, octet4: int = 0x00) -> bytes:
    """G.8031 linear APS. ptype is the A/B/D/R nibble; octet4's top bit is
    the bridge type and the remaining seven bits are reserved."""
    o1 = ((request & 0x0F) << 4) | (ptype & 0x0F)
    return cfm(level, 39, 0, 4, bytes([o1, req_sig, br_sig, octet4]), END)


# ---- G.8032 R-APS (opcode 40) --------------------------------------------
# Body is 32 octets: req/state 4b + sub-code 4b, status octet, 6-octet
# Node ID, 24 reserved. First TLV Offset is 32.

RB = 0x80
DNF = 0x40
BPR = 0x20

NODE_A = MAC_A
NODE_B = MAC_B
NODE_C = MAC_C
RING_VLAN = ((0x8100, 500),)


def raps(level: int, request: int, sub_code: int = 0, status: int = 0,
         node_id: bytes | None = None, resv: bytes | None = None,
         flags: int = 0, version: int = 1) -> bytes:
    """Build an R-APS. version 1 is G.8032v2, version 0 is G.8032v1.

    The default is 1 (G.8032v2) because that is what every current
    deployment speaks; v1 is exercised deliberately by the revision
    fixture.
    """
    body = bytes([((request & 0x0F) << 4) | (sub_code & 0x0F), status])
    body += (node_id if node_id is not None else MAC_A)
    body += (resv if resv is not None else b"\x00" * 24)
    return cfm(level, 40, flags, 32, body, END, version=version)


def eth_ring(src: bytes, payload: bytes, dst: bytes | None = None) -> bytes:
    # The R-APS destination is vendor-configurable and ring-ID dependent,
    # so the fixtures use the CFM group for the level and the ring rules
    # key on the control VLAN instead of a hardcoded address.
    return eth(dst if dst is not None else cfm_group(3), src, payload,
               vlans=RING_VLAN)


# ---- Y.1731 measurement and maintenance ---------------------------------

def dm_stamps(*pairs: Tuple[int, int]) -> bytes:
    """Y.1731 delay timestamps: 32-bit seconds then 32-bit nanoseconds,
    8 octets each, so DMM/DMR carry four in 32 and 1DM two in 16."""
    return b"".join(struct.pack("!II", s, n) for s, n in pairs)


def lm(level: int, reply: bool, txfcf: int, rxfcf: int = 0,
       txfcb: int = 0) -> bytes:
    return cfm(level, 42 if reply else 43, 0, 12,
               struct.pack("!III", txfcf, rxfcf, txfcb), END)


def dm(level: int, opcode: int, *pairs: Tuple[int, int]) -> bytes:
    body = dm_stamps(*pairs)
    return cfm(level, opcode, 0, len(body), body, END)


def sl(level: int, opcode: int, src_mep: int, test_id: int, txfcf: int,
       rsp_mep: int = 0, txfcb: int = 0) -> bytes:
    return cfm(level, opcode, 0, 16,
               struct.pack("!HHIII", src_mep, rsp_mep, test_id, txfcf,
                           txfcb), END)


def tst(level: int, seq: int, pad: int = 0) -> bytes:
    body = struct.pack("!I", seq)
    tail = tlv(32, b"\x00" * pad) if pad else b""
    return cfm(level, 37, 0, 4, body, tail + END)


def oui_pdu(level: int, opcode: int, oui: bytes = b"\x00\x11\x22",
            sub: int = 7, data: bytes = b"") -> bytes:
    return cfm(level, opcode, 0, 4, oui + bytes([sub]), data + END)


def vxlan(inner: bytes, vni: int = 1000, src_ip: bytes = b"\x0a\x00\x00\x01",
          dst_ip: bytes = b"\x0a\x00\x00\x02") -> bytes:
    """Wrap an inner Ethernet frame in EVPN-VXLAN, as a tap on the
    underlay of a VXLAN fabric would see it."""
    vx = struct.pack("!BBHI", 0x08, 0, 0, (vni << 8))
    udp = struct.pack("!HHHH", 40000, 4789, 8 + len(vx) + len(inner), 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0,
                     20 + len(udp) + len(vx) + len(inner), 1, 0, 64, 17, 0,
                     src_ip, dst_ip)
    return (bytes.fromhex("001122330044") + bytes.fromhex("001122330055")
            + struct.pack("!H", 0x0800) + ip + udp + vx + inner)


# ---- E-LMI (MEF 16) ------------------------------------------------------

ELMI_GROUP = bytes.fromhex("0180c2000007")


def elmi_ie(tag: int, val: bytes) -> bytes:
    return bytes([tag, len(val)]) + val


def elmi(msg: int = 0x7D, version: int = 1, snd: int = 1, rcv: int = 0,
         evcs: Tuple[Tuple[int, int], ...] = ((7, 0x02),),
         uni: bytes = b"UNI-1", dst: bytes | None = None,
         src: bytes | None = None) -> bytes:
    body = bytes([version, msg])
    body += elmi_ie(0x02, bytes([snd, rcv]))
    body += elmi_ie(0x01, bytes([0]))
    body += elmi_ie(0x11, bytes([0x02]) + elmi_ie(0x51, uni))
    for ref, status in evcs:
        body += elmi_ie(0x21, struct.pack("!H", ref) + bytes([status])
                        + elmi_ie(0x62, b"EVC-%d" % ref))
    f = (dst or ELMI_GROUP) + (src or MAC_A) + struct.pack("!H", 0x88EE) \
        + body
    return f + b"\x00" * max(0, 60 - len(f))


EVC_DECL = ["--evc", "7,vlan=500,name=cust-A"]


def write_pcap(path: str, frames: List[Tuple[float, bytes]]) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, data in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1000000:
                sec += 1
                usec -= 1000000
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)


def timeline(items: List[Tuple[float, bytes]]) -> List[Tuple[float, bytes]]:
    """Convert (offset_seconds, frame) into absolute capture timestamps."""
    return [(BASE_TS + off, raw) for off, raw in items]


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

Scenario = Tuple[str, List[Tuple[float, bytes]], List[str], List[str]]
SCENARIOS: List[Scenario] = []


def scenario(name: str, codes: List[str], args: List[str] | None = None):
    def deco(fn):
        SCENARIOS.append((name, fn(), codes, args or []))
        return fn
    return deco


D3 = cfm_group(3)
D3L = cfm_group(3, klass=2)
D5 = cfm_group(5)


@scenario("baseline", ["CFM-080", "CFM-093", "CFM-160", "CFM-161",
                       "CFM-162", "CFM-163", "CFM-230"])
def _baseline():
    f = []
    t = 0.0
    for i in range(6):
        f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=i + 1))))
        f.append((t + 0.05, eth(D3, MAC_B, ccm(3, 20, seq=i + 1))))
        t += 1.0
    f.append((t, eth(D3, MAC_A, aps(3, 0))))          # No Request
    f.append((t + 0.1, eth(D3, MAC_A, lmm(3))))       # Y.1731 overlay marker
    return f


@scenario("structural",
          ["CFM-001", "CFM-002", "CFM-003", "CFM-004", "CFM-005", "CFM-006",
           "CFM-007", "CFM-008", "CFM-009", "CFM-010", "CFM-100",
           "CFM-140", "CFM-160", "CFM-161", "CFM-163"])
def _structural():
    f = []
    t = 0.0

    def add(frame):
        nonlocal t
        f.append((t, frame))
        t += 0.25

    # CFM-001: First TLV Offset addresses past the payload
    add(eth(D3, MAC_X, cfm(3, 3, 0, 200, struct.pack("!I", 1), END)))
    # CFM-002: Data TLV declares 0xFFFF octets
    add(eth(D3, MAC_X, cfm(3, 3, 0, 4, struct.pack("!I", 2),
                           bytes([3]) + struct.pack("!H", 0xFFFF) + b"AB")))
    # CFM-003: a TLV type byte as the final octet of the frame
    body = struct.pack("!I", 3)
    chain = tlv(3, b"F" * 34) + bytes([0x03])
    add(eth(D3, MAC_X, cfm(3, 3, 0, 4, body, chain), minlen=0))
    # CFM-004: TLV chain consumes the payload exactly, no End TLV
    add(eth(D3, MAC_X, cfm(3, 3, 0, 4, struct.pack("!I", 4),
                           tlv(3, b"G" * 35)), minlen=0))
    # CFM-005: MD Name Length overruns the MAID
    add(eth(D3, MAC_X, ccm(3, 11, m=maid(md_len=200))))
    # CFM-006: CCM body truncated below the specified 70 octets
    add(eth(D3, MAC_X, cfm(3, 1, 0x04, 70, b"\x00" * 20, END)))
    # CFM-007: unassigned opcode
    add(eth(D3, MAC_X, cfm(3, 99, 0, 0, b"", END)))
    # CFM-008: non-zero version
    add(eth(D3, MAC_X, cfm(3, 3, 0, 4, struct.pack("!I", 8), END, version=3)))
    # CFM-009: eight non-zero octets after the End TLV
    add(eth(D3, MAC_X, cfm(3, 3, 0, 4, struct.pack("!I", 9),
                           END + b"SMUGGLED")))
    # CFM-010: First TLV Offset disagrees with the opcode's specified value
    add(eth(D3, MAC_X, cfm(3, 3, 0, 7, struct.pack("!I", 10) + b"xxx", END)))
    return f


@scenario("level", ["CFM-020", "CFM-022", "CFM-024", "CFM-160", "CFM-161",
                    "CFM-163"])
def _level():
    f = []
    # CFM-020: header says level 3, class 1 group address says level 5
    f.append((0.0, eth(D5, MAC_A, ccm(3, 10))))
    # CFM-022: one MAID carried at two MD levels
    f.append((0.5, eth(cfm_group(4), MAC_A, ccm(4, 10))))
    f.append((1.0, eth(D3, MAC_A, ccm(3, 10))))
    # CFM-024: CCM to a unicast destination, outside the CFM group
    f.append((1.5, eth(MAC_B, MAC_A, ccm(3, 10))))
    return f


@scenario("ceiling", ["CFM-021", "CFM-160", "CFM-161", "CFM-163"],
          args=["--md-ceiling", "4"])
def _ceiling():
    return [(0.0, eth(cfm_group(6), MAC_A, ccm(6, 10))),
            (1.0, eth(cfm_group(6), MAC_A, ccm(6, 10, seq=2)))]


@scenario("ccm",
          ["CFM-040", "CFM-041", "CFM-042", "CFM-043", "CFM-044", "CFM-045",
           "CFM-046", "CFM-047", "CFM-048", "CFM-049", "CFM-121",
           "CFM-160", "CFM-161", "CFM-163"])
def _ccm():
    f = []
    t = 0.0
    # settle the association: three CCMs from MEP 10 at 1s
    for i in range(3):
        f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=i + 1))))
        t += 1.0
    # CFM-045: a new MEP joins the settled association
    f.append((t, eth(D3, MAC_B, ccm(3, 20))))
    t += 1.0
    # CFM-046 then CFM-041: MEP 10 moves to MAC_C, then MAC_A speaks again
    f.append((t, eth(D3, MAC_C, ccm(3, 10, seq=4))))
    t += 1.0
    f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=5))))
    t += 1.0
    # CFM-042 + CFM-047: MEP 10 switches to a 3.33ms interval
    f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=6, interval=1))))
    t += 1.0
    # CFM-043: interval field 0
    f.append((t, eth(D3, MAC_A, ccm(3, 30, interval=0))))
    t += 0.5
    # CFM-044: RDI asserted
    f.append((t, eth(D3, MAC_A, ccm(3, 40, rdi=True))))
    t += 0.5
    # CFM-049, both arms: reserved bits set above the 13-bit MEP ID, and
    # the excluded value 0
    f.append((t, eth(D3, MAC_A, ccm(3, 9000))))
    t += 0.5
    f.append((t, eth(D3, MAC_A, ccm(3, 0))))
    t += 0.5
    # CFM-048: reserved MD name format
    f.append((t, eth(D3, MAC_A, ccm(3, 50, m=maid(md_fmt=0)))))
    t += 0.5
    # CFM-040: a second MAID inside the established VLAN/level
    f.append((t, eth(D3, MAC_A, ccm(3, 60, m=maid(ma_name=b"MA-OTHER")))))
    t += 0.5
    # CFM-121: MEP 70 declares 1s but arrives every 100ms
    for i in range(8):
        f.append((t, eth(D3, MAC_B, ccm(3, 70, seq=i + 1, interval=4))))
        t += 0.1
    return f


@scenario("y1731",
          ["CFM-060", "CFM-061", "CFM-062", "CFM-063", "CFM-064", "CFM-065",
           "CFM-160", "CFM-161", "CFM-162", "CFM-163"])
def _y1731():
    f = []
    t = 0.0
    for i in range(3):
        f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=i + 1))))
        t += 0.5
    # CFM-060/061/063: AIS at level 5 from a MAC with no CCM history, while
    # level-3 CCMs are still live
    f.append((t, eth(D5, MAC_X, ais(5, period=4))))
    t += 0.5
    # CFM-065: AIS period field 0
    f.append((t, eth(D5, MAC_X, ais(5, period=0))))
    t += 0.5
    f.append((t, eth(D5, MAC_A, lck(5))))        # CFM-062
    t += 0.5
    f.append((t, eth(D5, MAC_A, csf(5))))        # CFM-064
    return f


@scenario("aps",
          ["CFM-080", "CFM-081", "CFM-082", "CFM-083", "CFM-084", "CFM-085",
           "CFM-086", "CFM-087", "CFM-093", "CFM-160", "CFM-161", "CFM-162",
           "CFM-163"])
def _aps():
    f = []
    t = 0.0
    for i in range(3):
        f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=i + 1))))
        t += 0.4
    f.append((t, eth(D3, MAC_A, aps(3, 0))))      # NR, establishes the group
    t += 0.4
    f.append((t, eth(D3, MAC_A, aps(3, 13))))     # CFM-081 Forced Switch
    t += 0.4
    f.append((t, eth(D3, MAC_A, aps(3, 7))))      # CFM-082 Manual Switch
    t += 0.4
    f.append((t, eth(D3, MAC_A, aps(3, 11))))     # CFM-083 SF, CCMs healthy
    t += 0.4
    f.append((t, eth(D3, MAC_A, aps(3, 15))))     # CFM-087 Lockout (+churn)
    t += 0.4
    f.append((t, eth(D3, MAC_A, aps(3, 3))))      # CFM-086 reserved code
    t += 0.4
    f.append((t, eth(D3, MAC_X, aps(3, 0))))      # CFM-084 new source MAC
    return f


@scenario("measurement",
          ["CFM-160", "CFM-161", "CFM-162", "CFM-163", "CFM-220", "CFM-221",
           "CFM-222", "CFM-223", "CFM-224", "CFM-230"])
def _measurement():
    """Y.1731 performance measurement: LM, DM and SL.

    The CCM run at the front is what arms CFM-220 - a measurement frame
    from a MAC with no CCM history on the service.
    """
    f = []
    t = 0.0
    for i in range(3):
        f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=i + 1))))
        t += 0.4
    # loss measurement, then a counter that goes backwards (CFM-221)
    f.append((t, eth(D3, MAC_A, lm(3, False, 100))))
    t += 0.3
    f.append((t, eth(D3, MAC_A, lm(3, True, 200, 150, 140))))
    t += 0.3
    f.append((t, eth(D3, MAC_A, lm(3, True, 190, 150, 140))))
    t += 0.3
    # one-way delay, then a DMR with an out-of-range nanoseconds field
    f.append((t, eth(D3, MAC_A, dm(3, 45, (100, 0), (100, 500000)))))
    t += 0.3
    f.append((t, eth(D3, MAC_A, dm(3, 46, (100, 0), (101, 0), (102, 0),
                                   (103, 1500000000)))))
    t += 0.3
    # a DMR whose backward pair is reversed (CFM-223)
    f.append((t, eth(D3, MAC_A, dm(3, 46, (100, 0), (101, 0), (105, 0),
                                   (104, 0)))))
    t += 0.3
    # synthetic loss: a test is requested, then a reply for another
    f.append((t, eth(D3, MAC_A, sl(3, 55, 10, 0xAAAA0001, 10))))
    t += 0.3
    f.append((t, eth(D3, MAC_B, sl(3, 54, 10, 0xBBBB0002, 10, rsp_mep=20,
                                   txfcb=5))))
    t += 0.3
    # a measurement frame from a MAC that never sourced a CCM (CFM-220)
    f.append((t, eth(D3, MAC_X, lm(3, False, 1))))
    return f


@scenario("maintenance",
          ["CFM-160", "CFM-163", "CFM-225", "CFM-226", "CFM-227", "CFM-228",
           "CFM-229", "CFM-230", "CFM-162"])
def _maintenance():
    """TST, MCC, VSM/VSR and the experimental opcodes.

    TST is the one Y.1731 opcode built to move bulk data, so the burst is
    the finding rather than the presence.
    """
    f = []
    t = 0.0
    for i in range(22):
        f.append((t, eth(D3, MAC_X, tst(3, i, pad=64))))
        t += 0.1
    f.append((t, eth(D3, MAC_A, oui_pdu(3, 41, b"\x00\x19\xa7", 1))))
    t += 0.3
    f.append((t, eth(D3, MAC_A, oui_pdu(3, 51))))
    t += 0.3
    f.append((t, eth(D3, MAC_B, oui_pdu(3, 50))))
    t += 0.3
    f.append((t, eth(D3, MAC_X, oui_pdu(3, 49, sub=9))))
    t += 0.3
    f.append((t, eth(D3, MAC_X, oui_pdu(3, 48, sub=9))))
    return f


@scenario("opcodes",
          ["CFM-160", "CFM-162", "CFM-163"])
def _opcodes():
    """The three opcodes that used to be reported as unassigned.

    RFM (6), SFM (7) and GNM (32) are defined by 802.1Q/Y.1731. Before
    they were added to the opcode table every one of them raised CFM-007,
    and MCC/EXM/VSM raised CFM-010 for declaring the offset they are
    supposed to declare. This fixture is the regression guard: it must
    stay free of both.
    """
    f = []
    t = 0.0
    f.append((t, eth(D3, MAC_A, cfm(3, 6, 0, 4, struct.pack("!I", 1), END))))
    t += 0.3
    f.append((t, eth(D3, MAC_A, cfm(3, 7, 0, 4, struct.pack("!I", 2), END))))
    t += 0.3
    f.append((t, eth(D3, MAC_A, cfm(3, 32, 0, 13, bytes([1]), END))))
    return f


@scenario("elmi",
          ["CFM-060", "CFM-061", "CFM-160", "CFM-161", "CFM-162", "CFM-163",
           "CFM-230", "CFM-250", "CFM-251", "CFM-252", "CFM-253"],
          args=EVC_DECL)
def _elmi():
    """E-LMI cross-plane contradiction.

    The agreeing case comes first and must stay silent, then each
    direction of the contradiction: Active while CFM shows a fault, and
    Not Active while CFM is healthy. Neither is visible from either plane
    alone, which is why E-LMI is in this module at all.
    """
    f = []
    t = 0.0
    V = ((0x8100, 500),)
    for i in range(3):
        f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=i + 1), vlans=V)))
        t += 0.4
    # agreeing: Active and healthy -> no contradiction
    f.append((t, elmi(snd=1, evcs=((7, 0x02),))))
    t += 0.4
    # contradiction one way: reported Not Active while CFM is healthy
    f.append((t, elmi(snd=2, evcs=((7, 0x00),))))
    t += 0.4
    # a real fault appears, and E-LMI keeps reporting Active
    f.append((t, eth(D3, MAC_X, ais(3, period=4), vlans=V)))
    t += 0.3
    f.append((t, elmi(snd=3, evcs=((7, 0x02),))))
    t += 0.4
    # a replayed frame: the send sequence does not advance
    f.append((t, elmi(snd=3, evcs=((7, 0x02),))))
    t += 0.4
    # structural: bad version, undefined EVC status, wrong destination
    f.append((t, elmi(snd=4, version=3, evcs=((7, 0x09),), dst=MAC_B)))
    # a measurement frame so the inventory code is exercised too
    t += 0.4
    f.append((t, eth(D3, MAC_A, lm(3, False, 10), vlans=V)))
    return f


@scenario("elmi_undeclared", ["CFM-250", "CFM-254"])
def _elmi_undeclared():
    """E-LMI with no --evc mapping: fails loud rather than looking clean,
    and the cross-plane rule stays inert."""
    f = []
    t = 0.0
    for i in range(3):
        f.append((t, elmi(snd=i + 1, evcs=((7, 0x02), (9, 0x04)))))
        t += 0.4
    return f


@scenario("vxlan",
          ["CFM-160", "CFM-161", "CFM-162", "CFM-163", "CFM-230",
           "CFM-240"])
def _vxlan():
    """CFM inside EVPN-VXLAN, as seen from a tap on the underlay.

    Without decapsulation none of this is visible and the module reports
    the service plane clean. The second VNI reuses the SAME inner VLAN on
    purpose: the two tenants must not share maintenance-association
    state, which is what the VNI in the service key prevents. CFM-040
    firing would mean they had merged.
    """
    f = []
    t = 0.0
    for i in range(3):
        f.append((t, vxlan(eth(D3, MAC_A, ccm(3, 10, seq=i + 1),
                               vlans=((0x8100, 500),)), vni=1000)))
        t += 0.4
    # a different tenant, same inner VLAN, different MAID
    for i in range(3):
        f.append((t, vxlan(eth(D3, MAC_B, ccm(3, 20, seq=i + 1,
                                              m=maid(ma_name=b"MA-T2")),
                               vlans=((0x8100, 500),)), vni=2000)))
        t += 0.4
    # and a measurement frame inside the tunnel
    f.append((t, vxlan(eth(D3, MAC_A, lm(3, False, 50),
                           vlans=((0x8100, 500),)), vni=1000)))
    return f


@scenario("elps",
          ["CFM-080", "CFM-084", "CFM-085", "CFM-086", "CFM-088", "CFM-089",
           "CFM-090", "CFM-091", "CFM-092", "CFM-093", "CFM-160", "CFM-161",
           "CFM-162", "CFM-163"])
def _elps():
    """G.8031 / ELPS linear protection.

    Also the regression guard for the SF-P semantics: SF-P reports that
    the PROTECTION path failed, so the working path is still carrying
    traffic and its CCMs stay healthy. Running SF-P through the
    uncorroborated-fault test raises a CRITICAL forged-switch alarm on
    every genuine protection failure, so CFM-083 must NOT fire here.
    """
    f = []
    t = 0.0
    # working path healthy and settled, which arms CFM-083 if it were wrong
    for i in range(3):
        f.append((t, eth(D3, MAC_A, ccm(3, 10, seq=i + 1))))
        t += 0.4
    f.append((t, eth(D3, MAC_A, aps(3, 0x0, ptype=0xF))))      # NR, ABDR
    t += 0.4
    # CFM-088: SF-P. CFM-083 must stay silent.
    f.append((t, eth(D3, MAC_A, aps(3, 0xE, ptype=0xF))))
    t += 0.4
    f.append((t, eth(D3, MAC_A, aps(3, 0x9, ptype=0xF))))      # CFM-089 SD
    t += 0.4
    # CFM-090: the far end advertises a different protection type
    f.append((t, eth(D3, MAC_B, aps(3, 0x0, ptype=0x5))))
    t += 0.4
    # CFM-091: requests normal while bridging null
    f.append((t, eth(D3, MAC_A, aps(3, 0x0, ptype=0xF, br_sig=0))))
    t += 0.4
    # CFM-092: reserved bits set in the body's last octet
    f.append((t, eth(D3, MAC_A, aps(3, 0x0, ptype=0xF, octet4=0x40))))
    t += 0.4
    # CFM-086: the deprecated request code
    f.append((t, eth(D3, MAC_A, aps(3, 0x6, ptype=0xF))))
    return f


@scenario("lblt",
          ["CFM-100", "CFM-101", "CFM-102", "CFM-103", "CFM-104", "CFM-105",
           "CFM-106", "CFM-160", "CFM-163"])
def _lblt():
    f = []
    t = 0.0
    for i in range(22):                            # CFM-100 + CFM-101
        f.append((t, eth(D3, MAC_X, lbm(3, tid=i + 1))))
        t += 0.1
    # CFM-105: oversized Data TLV in a loopback
    f.append((t, eth(D3, MAC_X, lbm(3, tid=99, extra=tlv(3, b"P" * 1200)))))
    t += 0.2
    # CFM-102 + CFM-103: ascending-TTL linktrace sweep
    for ttl in (1, 2, 3, 4):
        f.append((t, eth(D3L, MAC_X, ltm(3, 7, ttl, MAC_X, MAC_B))))
        t += 0.2
    # CFM-106: TTL 255
    f.append((t, eth(D3L, MAC_X, ltm(3, 8, 255, MAC_X, MAC_B))))
    t += 0.2
    # CFM-104: reply carries ingress and egress identifier TLVs
    f.append((t, eth(MAC_X, MAC_B,
                     ltr(3, 7, 2, extra=tlv(5, b"\x01" + MAC_B) +
                         tlv(8, b"\x00\x00" + MAC_B)))))
    return f


@scenario("rate", ["CFM-100", "CFM-101", "CFM-120", "CFM-122", "CFM-141",
                   "CFM-160", "CFM-163"])
def _rate():
    f = []
    t = 0.0
    for i in range(120):
        f.append((t, eth(D3, MAC_X, lbm(3, tid=i + 1))))
        t += 0.01
    return f


SUB_VLAN = ((0x8100, 600),)


def eth_sub(src: bytes, payload: bytes, dst: bytes | None = None) -> bytes:
    return eth(dst if dst is not None else cfm_group(3), src, payload,
               vlans=SUB_VLAN)


# A G.8032v2 interconnected topology: major ring 500 with sub-ring 600
# attached at interconnection nodes A and B, no virtual channel.
SUBRING_DECL = [
    "--ring", "500,role=major,rpl=%s,interconnect=%s/%s,nodes=%s/%s,"
              "name=major-500" % (MAC_A.hex(":"), MAC_A.hex(":"),
                                  MAC_B.hex(":"), MAC_A.hex(":"),
                                  MAC_B.hex(":")),
    "--ring", "600,role=sub,parent=major-500,vc=no,interconnect=%s/%s,"
              "nodes=%s/%s,name=sub-600" % (MAC_A.hex(":"), MAC_B.hex(":"),
                                            MAC_C.hex(":"), MAC_X.hex(":")),
]

RING_DECL = ["--ring",
             "500,rpl=%s,nodes=%s/%s,name=ring-500"
             % (MAC_A.hex(":"), MAC_B.hex(":"), MAC_C.hex(":"))]


@scenario("raps_baseline",
          ["CFM-060", "CFM-160", "CFM-161", "CFM-162", "CFM-163",
           "CFM-180", "CFM-185", "CFM-201"],
          args=RING_DECL)
def _raps_baseline():
    """A healthy declared ring: RPL owner announces NR,RB, then a real
    failure arrives WITH an AIS corroborating it, so CFM-186 must stay
    silent. That is the negative control for the forged-switch rule."""
    f = []
    t = 0.0
    # Both ring nodes source CCMs on the control VLAN, which is what a real
    # ring looks like. A fixture where only the RPL owner sends CCMs makes
    # the other node's AIS look injected (CFM-061) for a reason that is an
    # artefact of the fixture rather than of the ring.
    for i in range(4):
        f.append((t, eth_ring(MAC_A, ccm(3, 10, seq=i + 1))))
        f.append((t + 0.02, eth_ring(MAC_B, ccm(3, 20, seq=i + 1))))
        f.append((t + 0.05, eth_ring(MAC_A, raps(3, 0, status=RB))))
        t += 1.0
    # a genuine fault: AIS first, then SF. CFM-186 must not fire.
    f.append((t, eth_ring(MAC_B, ais(3, period=4))))
    t += 0.2
    f.append((t, eth_ring(MAC_B, raps(3, 0xB, node_id=MAC_B))))
    t += 0.2
    f.append((t, eth_ring(MAC_B, raps(3, 0xB, node_id=MAC_B))))
    return f


@scenario("raps_forged",
          ["CFM-160", "CFM-161", "CFM-163", "CFM-180", "CFM-185", "CFM-186",
           "CFM-187", "CFM-188", "CFM-191", "CFM-192", "CFM-193", "CFM-195",
           "CFM-197", "CFM-201", "CFM-162"],
          args=RING_DECL)
def _raps_forged():
    """Forgery against a declared ring."""
    f = []
    t = 0.0
    # settle the ring: owner MAC_A holds the block, CCMs healthy
    for i in range(3):
        f.append((t, eth_ring(MAC_A, ccm(3, 10, seq=i + 1))))
        f.append((t + 0.05, eth_ring(MAC_A, raps(3, 0, status=RB))))
        t += 0.5
    # CFM-185 + CFM-186: SF while CCMs are live and no AIS was seen
    f.append((t, eth_ring(MAC_B, raps(3, 0xB, node_id=MAC_B))))
    t += 0.3
    # CFM-187 Forced Switch, CFM-188 Manual Switch
    f.append((t, eth_ring(MAC_B, raps(3, 0xD, node_id=MAC_B))))
    t += 0.3
    f.append((t, eth_ring(MAC_B, raps(3, 0x7, node_id=MAC_B))))
    t += 0.3
    # CFM-191: DNF set on an SF, suppressing the flush
    f.append((t, eth_ring(MAC_B, raps(3, 0xB, status=DNF, node_id=MAC_B))))
    t += 0.3
    # CFM-192 + CFM-193: MAC_C claims RB while the owner still holds it
    f.append((t, eth_ring(MAC_C, raps(3, 0, status=RB, node_id=MAC_C))))
    t += 0.3
    # CFM-195: off-ring node injects
    f.append((t, eth_ring(MAC_X, raps(3, 0xB, node_id=MAC_X))))
    return f


@scenario("raps_structural",
          ["CFM-160", "CFM-163", "CFM-180", "CFM-181", "CFM-182", "CFM-183",
           "CFM-184", "CFM-185", "CFM-189", "CFM-190", "CFM-191", "CFM-197",
           "CFM-200", "CFM-201", "CFM-162"])
def _raps_structural():
    """Structural conformance plus the flush primitive, with NO ring
    declared - so CFM-200 fires and the topology rules stay inert."""
    f = []
    t = 0.0

    def add(frame):
        nonlocal t
        f.append((t, frame))
        t += 0.3

    # CFM-181: reserved request/state
    add(eth_ring(MAC_X, raps(3, 0x5, node_id=MAC_X)))
    # CFM-182: non-zero Flags, status reserved bits and reserved octets
    add(eth_ring(MAC_X, raps(3, 0, status=0x05, node_id=MAC_X, flags=0x7F,
                             resv=b"\x00" * 20 + b"LEAK")))
    # CFM-183: Node ID disagrees with the source MAC
    add(eth_ring(MAC_X, raps(3, 0, node_id=MAC_B)))
    # CFM-184: sub-code on a request that defines none
    add(eth_ring(MAC_X, raps(3, 0xB, sub_code=3, node_id=MAC_X)))
    # CFM-189 + CFM-190: Event/Flush burst
    for _ in range(4):
        add(eth_ring(MAC_X, raps(3, 0xE, sub_code=0, node_id=MAC_X)))
    # CFM-191 via Event with DNF
    add(eth_ring(MAC_X, raps(3, 0xE, sub_code=0, status=DNF,
                             node_id=MAC_X)))
    return f


@scenario("raps_ring_open",
          ["CFM-160", "CFM-163", "CFM-180", "CFM-194", "CFM-201", "CFM-162"],
          args=RING_DECL)
def _raps_ring_open():
    """A declared ring whose R-APS(NR) stream never asserts RB: either no
    node holds the block (a ring loop) or the tap cannot see the owner."""
    f = []
    t = 0.0
    for i in range(7):
        f.append((t, eth_ring(MAC_B, raps(3, 0, node_id=MAC_B))))
        t += 0.5
    return f


@scenario("raps_offvlan",
          ["CFM-160", "CFM-163", "CFM-180", "CFM-196", "CFM-201", "CFM-162"],
          args=RING_DECL)
def _raps_offvlan():
    """Ring 500 is declared; R-APS turns up on VLAN 900 instead. Either an
    undeclared ring exists, or R-APS is being injected where no ring
    runs."""
    f = []
    t = 0.0
    for i in range(3):
        f.append((t, eth(cfm_group(3), MAC_B,
                         raps(3, 0, node_id=MAC_B),
                         vlans=((0x8100, 900),))))
        t += 0.5
    return f


@scenario("raps_revision",
          ["CFM-160", "CFM-162", "CFM-163", "CFM-180", "CFM-182", "CFM-187",
           "CFM-188", "CFM-189", "CFM-197", "CFM-201", "CFM-202", "CFM-203",
           "CFM-204"],
          args=RING_DECL)
def _raps_revision():
    """G.8032 revision handling.

    The revision is carried in the CFM common-header Version field: 0 is
    G.8032v1, 1 is G.8032v2. A v1 frame using a v2-only request or the BPR
    bit is non-conforming (CFM-202); both revisions on one ring is a
    convergence fault (CFM-203); and two R-APS destinations on one control
    VLAN means two ring instances share it (CFM-204), since the ring ID
    lives in that address.

    Also the regression guard for the version rule: a conforming v2 frame
    must NOT raise CFM-008, or every frame of every modern ERPS deployment
    would be reported as structurally malformed.
    """
    f = []
    t = 0.0
    # conforming G.8032v2 - must stay structurally clean
    for i in range(2):
        f.append((t, eth_ring(MAC_A, raps(3, 0, status=RB, version=1))))
        t += 0.4
    # CFM-202, both arms: a v1 frame using FS, and one setting BPR
    f.append((t, eth_ring(MAC_B, raps(3, 0xD, node_id=MAC_B, version=0))))
    t += 0.4
    f.append((t, eth_ring(MAC_B, raps(3, 0x7, status=BPR, node_id=MAC_B,
                                      version=0))))
    t += 0.4
    # CFM-204: a second ring instance on the same control VLAN, reached at
    # a different R-APS destination
    f.append((t, eth_ring(MAC_C, raps(3, 0xE, sub_code=0, node_id=MAC_C,
                                      version=1),
                          dst=cfm_group(3, klass=2))))
    return f


@scenario("subring",
          ["CFM-160", "CFM-162", "CFM-163", "CFM-180", "CFM-185", "CFM-195",
           "CFM-201", "CFM-205", "CFM-207", "CFM-208", "CFM-209"],
          args=SUBRING_DECL)
def _subring():
    """G.8032v2 interconnected topology.

    The point of the fixture is the NEGATIVE control: a legitimate
    topology-change propagation from an interconnection node must NOT
    raise CFM-189 or CFM-190, which is what cfmwatch did before sub-rings
    were modelled. It is recorded as CFM-209 instead.
    """
    f = []
    t = 0.0
    # sub-ring 600 changes state, which is what a propagation follows
    f.append((t, eth_sub(MAC_C, raps(3, 0, node_id=MAC_C))))
    t += 0.4
    f.append((t, eth_sub(MAC_C, raps(3, 0xB, node_id=MAC_C))))
    t += 0.4
    # CFM-209: interconnection node A propagates onto the major ring.
    # CFM-189/190 must stay silent.
    f.append((t, eth_ring(MAC_A, raps(3, 0xE, sub_code=0))))
    t += 0.4
    # CFM-205: a flush on the major ring from a non-interconnection node
    f.append((t, eth_ring(MAC_X, raps(3, 0xE, sub_code=0, node_id=MAC_X))))
    t += 0.4
    # CFM-207: a flush INTO the sub-ring from the parent's interconnect
    f.append((t, eth_sub(MAC_B, raps(3, 0xE, sub_code=0, node_id=MAC_B))))
    t += 0.4
    # CFM-208: a declared sub-ring node on the parent with no virtual
    # channel
    f.append((t, eth_ring(MAC_C, raps(3, 0, node_id=MAC_C))))
    return f


@scenario("raps_withdrawn",
          ["CFM-160", "CFM-162", "CFM-163", "CFM-180", "CFM-201", "CFM-206"],
          args=RING_DECL)
def _raps_withdrawn():
    """The RPL block was observed and then vanished.

    Stronger than CFM-194: having seen the block removes the tap-vantage
    explanation. Timed at a realistic 5s R-APS interval so the block goes
    stale.
    """
    f = []
    t = 0.0
    for i in range(3):
        f.append((t, eth_ring(MAC_A, raps(3, 0, status=RB))))
        t += 5.0
    for i in range(7):
        f.append((t, eth_ring(MAC_B, raps(3, 0, node_id=MAC_B))))
        t += 5.0
    return f


@scenario("raps_flood",
          ["CFM-120", "CFM-160", "CFM-163", "CFM-180", "CFM-194", "CFM-198",
           "CFM-201", "CFM-162"],
          args=RING_DECL)
def _raps_flood():
    f = []
    t = 0.0
    for i in range(60):
        f.append((t, eth_ring(MAC_B, raps(3, 0, node_id=MAC_B))))
        t += 0.02
    return f


@scenario("raps_ccm_loss",
          ["CFM-160", "CFM-161", "CFM-163", "CFM-180", "CFM-199", "CFM-201",
           "CFM-162"],
          args=RING_DECL)
def _raps_ccm_loss():
    """MEP 10 declares a 1s interval, then goes quiet past the G.8032
    three-miss threshold. On a ring that is the protection trigger."""
    f = []
    t = 0.0
    for i in range(4):
        f.append((t, eth_ring(MAC_A, ccm(3, 10, seq=i + 1))))
        t += 1.0
    # silence, broken only by R-APS keepalives, well past 3 x 1s
    t += 4.0
    for i in range(3):
        f.append((t, eth_ring(MAC_A, raps(3, 0, status=RB))))
        t += 0.5
    return f


def main() -> int:
    os.makedirs(FIXDIR, exist_ok=True)
    manifest: List[Dict[str, object]] = []
    for name, frames, codes, args in SCENARIOS:
        path = os.path.join(FIXDIR, "%s.pcap" % name)
        write_pcap(path, timeline(frames))
        manifest.append({
            "name": name, "pcap": os.path.basename(path),
            "frames": len(frames), "expect": sorted(codes), "args": args,
        })
        print("%-12s %3d frames -> %s" % (name, len(frames), path))
    mpath = os.path.join(FIXDIR, "manifest.json")
    with open(mpath, "w") as fh:
        json.dump(manifest, fh, indent=2)
    covered = sorted({c for m in manifest for c in m["expect"]})
    print("\nmanifest: %s" % mpath)
    print("codes claimed by fixtures: %d" % len(covered))
    return 0


if __name__ == "__main__":
    sys.exit(main())
