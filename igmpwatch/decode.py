"""Decode a sniffed Ether/IP/IGMP packet into a normalized IgmpEvent.

Important: Scapy's IGMP contrib only binds to IP when ``ttl==1``, so a spoofed
off-link IGMP packet (ttl!=1) would otherwise never be dissected - blinding the
exact anomaly we care about. We therefore slice the IGMP message out of the
original received bytes (by IP total-length, so Ethernet padding is excluded)
and parse it directly, independent of scapy's ttl-gated binding. That same slice
is what the checksum is validated against.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.inet import IP, IPOption_Router_Alert
from scapy.layers.inet6 import (IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt,
                                IPv6ExtHdrRouting, IPv6ExtHdrFragment, RouterAlert,
                                ICMPv6MLQuery, ICMPv6MLReport, ICMPv6MLDone,
                                ICMPv6MLQuery2, ICMPv6MLReport2, in6_chksum)
from scapy.utils import checksum as inet_checksum
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq, IGMPv3mr

from .models import GroupRecord, IgmpEvent, MsgType


def _l3_offset(pkt) -> int:
    off = 14  # Ethernet II
    if Ether in pkt:
        p = pkt[Ether].payload
        while isinstance(p, Dot1Q):
            off += 4
            p = p.payload
    return off


def _igmp_len(msg: bytes) -> int:
    """Length of the IGMP message computed from its own structure, so a caller
    with no usable IP length field can still bound it (and separate any trailing
    bytes) instead of folding frame padding into the message."""
    n = len(msg)
    if n < 8:
        return n
    t = msg[0]
    if t == 0x22:  # v3 report: 8B header + numgrp group records
        numgrp = int.from_bytes(msg[6:8], "big")
        off = 8
        for _ in range(numgrp):
            if off + 8 > n:
                return n
            auxdlen = msg[off + 1]
            numsrc = int.from_bytes(msg[off + 2:off + 4], "big")
            off += 8 + numsrc * 4 + auxdlen * 4
        return min(off, n)
    if t == 0x11 and n >= 12:  # v3 query: 12B header + numsrc sources
        numsrc = int.from_bytes(msg[10:12], "big")
        return min(12 + numsrc * 4, n)
    return 8  # v1/v2 query/report/leave are fixed 8B


def _igmp_split(pkt, ip) -> tuple[bytes, bytes]:
    """Return (igmp_message, trailing_bytes).

    The message is bounded strictly by the IP total-length field, so the
    kernel's frame padding (every frame padded to the 60-byte minimum) is never
    parsed as IGMP nor folded into the checksum. ``trailing`` is whatever follows
    the IP payload in the L2 frame -- normally all-zero padding, surfaced so a
    caller can flag *non-zero* trailing bytes (data smuggled behind a valid
    advert). When ip.len is unusable (e.g. a NIC that offloaded and zeroed it)
    the message is instead bounded by its own IGMP structure -- never by raw
    length, which would re-admit the padding.
    """
    raw = bytes(pkt.original) if getattr(pkt, "original", None) else bytes(pkt)
    l3 = _l3_offset(pkt)
    start = l3 + ip.ihl * 4
    hdr_min = ip.ihl * 4 + 8

    if ip.len and ip.len >= hdr_min and l3 + ip.len <= len(raw):
        end = l3 + ip.len
        return raw[start:end], raw[end:]

    cand = raw[start:]
    if len(cand) < 8:
        cand = bytes(ip.payload)  # last resort for a truncated capture
    n = _igmp_len(cand)
    return cand[:n], cand[n:]


def _checksum_ok(msg: bytes) -> bool:
    if len(msg) < 8:
        return False
    return inet_checksum(msg) == 0


def _router_alert_bytes(raw: bytes, l3: int, ihl: int) -> bool:
    """Scan the IPv4 header's actual option bytes for Router Alert (type 148).

    Read from the wire rather than scapy's parsed ``options`` list: that list is
    version-dependent and has been observed reporting a phantom option on a
    header with ihl=5 (i.e. no option space at all). ihl is ground truth.
    """
    if ihl <= 5:
        return False
    opts = raw[l3 + 20: l3 + ihl * 4]
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:          # End of Option List
            return False
        if kind == 1:          # No-Operation
            i += 1
            continue
        if kind == 148:        # Router Alert (copy=1, class=0, number=20)
            return True
        if i + 1 >= len(opts):
            return False
        length = opts[i + 1]
        if length < 2:
            return False
        i += length
    return False


def decode(pkt) -> Optional[IgmpEvent]:
    if IP not in pkt:
        if IPv6 in pkt:
            return _decode_mld(pkt)
        return None
    ip = pkt[IP]
    if ip.proto != 2:
        return None

    eth_src = pkt[Ether].src if Ether in pkt else "00:00:00:00:00:00"
    eth_dst = pkt[Ether].dst if Ether in pkt else "00:00:00:00:00:00"

    try:
        msg, trailing = _igmp_split(pkt, ip)
    except Exception:
        return None
    if not msg:
        return None

    raw_frame = bytes(pkt.original) if getattr(pkt, "original", None) else bytes(pkt)
    l3_off = _l3_offset(pkt)
    cks_ok = _checksum_ok(msg)
    # Ordinary frames pad to the 60B minimum with ZEROES; a captured 4-byte FCS
    # (if the path doesn't strip it) is the only expected non-zero tail. Ignore
    # up to a trailing 4-byte FCS window; anything non-zero beyond it is a
    # payload smuggled behind a valid message.
    core_trailing = trailing[:-4] if len(trailing) > 4 else b""
    trailing_nonzero = sum(1 for b in core_trailing if b)
    ts = float(getattr(pkt, "time", 0.0)) or 0.0
    # IGMP is a link-local control protocol and is never legitimately fragmented;
    # MF set or a non-zero fragment offset is an evasion / parser-stress artifact.
    fragmented = bool((int(ip.flags) & 1) or int(ip.frag) > 0)
    frag_nonfirst = int(ip.frag) > 0
    base = dict(ts=ts, eth_src=eth_src, eth_dst=eth_dst,
                ip_src=ip.src, ip_dst=ip.dst, ttl=ip.ttl,
                router_alert=_router_alert_bytes(raw_frame, l3_off, int(ip.ihl)),
                checksum_ok=cks_ok, raw_len=len(ip),
                trailing_len=len(trailing), trailing_nonzero=trailing_nonzero,
                actual_msg_len=len(msg), fragmented=fragmented,
                frag_nonfirst=frag_nonfirst)

    t = msg[0]

    if t == 0x22:
        # Parsed from raw bytes rather than scapy's IGMPv3mr: scapy versions
        # disagree about whether IGMPv3mr carries its own base header and about
        # populating numgrp, and it under-parses consecutive variable-length
        # records. The wire layout is fixed, so walk it directly.
        recs, numrec = _parse_v3_records(msg, addrlen=4)
        return IgmpEvent(version=3, msg_type=MsgType.REPORT_V3,
                         records=recs, truncated=(numrec != len(recs)), **base)

    if t == 0x11 and len(msg) >= 12:
        # IGMPv3 query: type(1) mrcode(1) cksum(2) gaddr(4) resv/S/QRV(1)
        # QQIC(1) numsrc(2) [sources...]
        gaddr = str(ipaddress.ip_address(msg[4:8]))
        qrv = msg[8] & 0x07
        numsrc = int.from_bytes(msg[10:12], "big")
        if gaddr in (None, "0.0.0.0"):
            mt, grp = MsgType.QUERY_GENERAL, None
        elif numsrc > 0:
            mt, grp = MsgType.QUERY_GROUP_SRC, gaddr
        else:
            mt, grp = MsgType.QUERY_GROUP, gaddr
        return IgmpEvent(version=3, msg_type=mt, group=grp, qrv=qrv,
                         declared_numsrc=numsrc, declared_msg_len=12 + numsrc * 4,
                         max_resp=float(msg[1]), **base)

    ig = IGMP(msg)
    gaddr = ig.gaddr
    mr = int(ig.mrcode or 0)
    if t == 0x11:
        version = 1 if mr == 0 else 2
        if gaddr in (None, "0.0.0.0"):
            return IgmpEvent(version=version, msg_type=MsgType.QUERY_GENERAL,
                             group=None, max_resp=mr / 10.0, **base)
        return IgmpEvent(version=version, msg_type=MsgType.QUERY_GROUP,
                         group=gaddr, max_resp=mr / 10.0, **base)
    if t == 0x12:
        return IgmpEvent(version=1, msg_type=MsgType.REPORT_V1, group=gaddr, **base)
    if t == 0x16:
        return IgmpEvent(version=2, msg_type=MsgType.REPORT_V2, group=gaddr, **base)
    if t == 0x17:
        return IgmpEvent(version=2, msg_type=MsgType.LEAVE, group=gaddr, **base)
    return IgmpEvent(version=2, msg_type=MsgType.UNKNOWN, group=gaddr, **base)


# ---------------------------------------------------------------------------
# MLD (Multicast Listener Discovery) -- IPv6/ICMPv6 parallel to IGMP
# ---------------------------------------------------------------------------
_MLD_TYPES = {130, 131, 132, 143}   # Query, v1 Report, v1 Done, v2 Report


def _v6_ext_len(ip6) -> int:
    """Total byte length of the IPv6 extension-header chain before ICMPv6."""
    total = 0
    p = ip6.payload
    while True:
        if isinstance(p, (IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrRouting)):
            total += (int(getattr(p, "len", 0)) + 1) * 8
        elif isinstance(p, IPv6ExtHdrFragment):
            total += 8
        else:
            break
        p = p.payload
    return total


def _mld_len(msg: bytes) -> int:
    """Structural length of an MLD message, to bound it when plen is unusable."""
    n = len(msg)
    if n < 4:
        return n
    t = msg[0]
    if t == 143:  # MLDv2 report: 8B header + records
        numrec = int.from_bytes(msg[6:8], "big")
        off = 8
        for _ in range(numrec):
            if off + 20 > n:
                return n
            auxlen = msg[off + 1]
            numsrc = int.from_bytes(msg[off + 2:off + 4], "big")
            off += 20 + numsrc * 16 + auxlen * 4
        return min(off, n)
    if t == 130 and n >= 28:  # MLDv2 query: 28B + numsrc*16
        numsrc = int.from_bytes(msg[26:28], "big")
        return min(28 + numsrc * 16, n)
    return 24  # MLDv1 query/report/done are fixed 24B


def _mld_split(pkt, ip6) -> tuple[bytes, bytes]:
    raw = bytes(pkt.original) if getattr(pkt, "original", None) else bytes(pkt)
    l3 = _l3_offset(pkt)
    ext = _v6_ext_len(ip6)
    start = l3 + 40 + ext
    if ip6.plen and l3 + 40 + ip6.plen <= len(raw) and ip6.plen >= ext + 4:
        end = l3 + 40 + ip6.plen
        return raw[start:end], raw[end:]
    # plen unusable (offload/jumbo): bound by MLD structure
    cand = raw[start:]
    if len(cand) < 4:
        cand = bytes(ip6.payload.payload)  # last resort past the HBH
    n = _mld_len(cand)
    return cand[:n], cand[n:]


def _hbh_router_alert(ip6) -> bool:
    p = ip6.payload
    while isinstance(p, (IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, IPv6ExtHdrRouting,
                         IPv6ExtHdrFragment)):
        if isinstance(p, IPv6ExtHdrHopByHop):
            for opt in getattr(p, "options", []) or []:
                if isinstance(opt, RouterAlert):
                    return True
        p = p.payload
    return False


def _parse_v3_records(msg: bytes, addrlen: int):
    """Walk IGMPv3 / MLDv2 group records from raw bytes.

    Both protocols share one record layout, differing only in address width:
      rtype(1) auxdatalen(1) numsrc(2) maddr(addrlen) sources(numsrc*addrlen)
      auxdata(auxdatalen*4)
    Parsed directly because scapy's record lists are version-dependent and
    under-parse consecutive variable-length records. Returns (records,
    declared_count) so the caller can flag a count/content mismatch.
    """
    n = len(msg)
    numrec = int.from_bytes(msg[6:8], "big") if n >= 8 else 0
    hdr = 4 + addrlen          # rtype+auxdlen+numsrc, then the group address
    recs = []
    off = 8
    for _ in range(numrec):
        if off + hdr > n:
            break
        rtype = msg[off]
        auxlen = msg[off + 1]
        numsrc = int.from_bytes(msg[off + 2:off + 4], "big")
        try:
            maddr = str(ipaddress.ip_address(msg[off + 4:off + hdr]))
        except ValueError:
            break
        srcs = []
        p = off + hdr
        for _ in range(numsrc):
            if p + addrlen > n:
                break
            try:
                srcs.append(str(ipaddress.ip_address(msg[p:p + addrlen])))
            except ValueError:
                pass
            p += addrlen
        recs.append(GroupRecord(int(rtype), maddr, srcs))
        off = p + auxlen * 4
    return recs, numrec


def _parse_mld_records(msg: bytes):
    """MLDv2 report records (128-bit addresses)."""
    return _parse_v3_records(msg, addrlen=16)


def _decode_mld(pkt) -> Optional[IgmpEvent]:
    ip6 = pkt[IPv6]
    try:
        msg, trailing = _mld_split(pkt, ip6)
    except Exception:
        return None
    if len(msg) < 4 or msg[0] not in _MLD_TYPES:
        return None

    eth_src = pkt[Ether].src if Ether in pkt else "00:00:00:00:00:00"
    eth_dst = pkt[Ether].dst if Ether in pkt else "00:00:00:00:00:00"

    # ICMPv6 checksum covers the IPv6 pseudo-header; a valid message sums to 0.
    try:
        cks_ok = in6_chksum(58, ip6, msg) == 0
    except Exception:
        cks_ok = False

    core_trailing = trailing[:-4] if len(trailing) > 4 else b""
    trailing_nonzero = sum(1 for b in core_trailing if b)
    ts = float(getattr(pkt, "time", 0.0)) or 0.0
    # MLD is link-local, hop-limit-1 control traffic; a Fragment header means the
    # message was split, which no conforming sender does and which is exactly the
    # condition that stresses reassembly/mbuf handling in receivers.
    fragh = ip6.payload.getlayer(IPv6ExtHdrFragment) if ip6.payload else None
    fragmented = fragh is not None
    frag_nonfirst = bool(fragh is not None and int(getattr(fragh, "offset", 0) or 0) > 0)
    base = dict(ts=ts, eth_src=eth_src, eth_dst=eth_dst,
                ip_src=ip6.src, ip_dst=ip6.dst, ttl=ip6.hlim,
                router_alert=_hbh_router_alert(ip6), checksum_ok=cks_ok,
                raw_len=ip6.plen, family=6,
                trailing_len=len(trailing), trailing_nonzero=trailing_nonzero,
                actual_msg_len=len(msg), fragmented=bool(fragmented),
                frag_nonfirst=frag_nonfirst)

    t = msg[0]

    if t == 143:  # MLDv2 report ~ IGMPv3 report
        recs, numrec = _parse_mld_records(msg)
        truncated = numrec != len(recs)
        return IgmpEvent(version=3, msg_type=MsgType.REPORT_V3,
                         records=recs, truncated=truncated, **base)

    if t == 130:  # Multicast Listener Query (v1 24B, v2 >=28B)
        if len(msg) >= 28:
            obj = ICMPv6MLQuery2(msg)
            version = 3
            numsrc = int(getattr(obj, "sources_number", 0) or 0)
            qrv = int(getattr(obj, "QRV", 0) or 0)
        else:
            obj = ICMPv6MLQuery(msg)
            version, numsrc, qrv = 2, 0, 0
        gaddr = getattr(obj, "mladdr", "::")
        mrd = float(getattr(obj, "mrd", 0) or 0) / 1000.0
        if gaddr in (None, "::"):
            mt, grp = MsgType.QUERY_GENERAL, None
        elif numsrc > 0:
            mt, grp = MsgType.QUERY_GROUP_SRC, gaddr
        else:
            mt, grp = MsgType.QUERY_GROUP, gaddr
        return IgmpEvent(version=version, msg_type=mt, group=grp, qrv=qrv,
                         declared_numsrc=numsrc,
                         declared_msg_len=(28 + numsrc * 16) if version == 3 else 24,
                         max_resp=mrd, **base)

    if t == 131:  # MLDv1 report ~ IGMPv2 report
        obj = ICMPv6MLReport(msg)
        return IgmpEvent(version=2, msg_type=MsgType.REPORT_V2,
                         group=obj.mladdr, **base)

    if t == 132:  # MLDv1 Done ~ IGMP leave
        obj = ICMPv6MLDone(msg)
        return IgmpEvent(version=2, msg_type=MsgType.LEAVE,
                         group=obj.mladdr, **base)

    return None
