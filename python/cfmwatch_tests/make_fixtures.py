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
        br_sig: int = 1) -> bytes:
    o1 = ((request & 0x0F) << 4) | (ptype & 0x0F)
    return cfm(level, 39, 0, 4, bytes([o1, req_sig, br_sig, 0x00]), END)


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


@scenario("baseline", ["CFM-080", "CFM-160", "CFM-161", "CFM-162",
                       "CFM-163"])
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
           "CFM-086", "CFM-087", "CFM-160", "CFM-161", "CFM-162",
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
