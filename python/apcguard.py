#!/usr/bin/env python3
"""apcguard -- APC/Schneider Network Management Card (NMC) Guard.

Passive Ragnar module. Detects Ripple20 (Treck TCP/IP stack) exposure and
attack attempts against APC NMC-managed gear (rack PDUs first). Never transmits.

Sources (locked at preflight, Sept 2026):
  * Schneider kBase FA410359 / SEVD-2020-174-01 V2.3 -- per-product gates.
  * McAfee ATR + JSOF "Ripple20 Detection Logic" -- 11896 / 11901 conditions.

CVE set: 11896 (10.0), 11898 (9.1), 11901 (9.0), 11902 (7.3), 11899 (5.4, KEV).
11899 has NO attack-attempt code (trigger undocumented -> quarantined); it is
carried by the Class B version gates only. 11897 does not apply to APC.

Address families follow the CVE, not a blanket rule (see AF_SCOPE):
  * Class B (SNMP sysDescr) ........ IPv4 + IPv6; gated on the hw/app tokens in PN/AN1,
                                     never on the MN model number
  * APC-101/102 (IPv4-in-IPv4) ..... IPv4 outer ONLY -- the CVE conditions are
                                     IPv4-outer (McAfee/JSOF); no IPv6-outer variant
                                     is documented, so none is claimed
  * APC-103/106 (ICMP reply) ....... IPv4 ONLY -- CVE-2020-11898 is IPv4-in-IPv4 with an
                                     ICMPv4 protocol-unreachable reply
  * APC-107/108 (tunnel rejected) .. IPv4 ONLY; informational, attributes NO CVE
  * APC-109 (rejected by ANOTHER device) IPv4 ONLY; informational, attributes NO CVE
  * APC-104 (tunnel to an NMC) ..... IPv4 + IPv6, attributes NO CVE
  * APC-105 (IPv6-in-IPv4, 11902) .. IPv4 outer ONLY -- no IPv6 variant exists
  * APC-111/112 (DNS, 11901) ....... IPv4 + IPv6 transport

Everything except run_capture() is pure Python over raw bytes. scapy is
imported ONLY inside run_capture() (LESSON C).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import struct
import sys
import time

VERSION = "0.1.0-dev"

# ---------------------------------------------------------------- registry
CODES = {
    "APC-001": ("warn", "NMC2 AOS <= 6.9.4 -- Ripple20 affected range",
                ["CVE-2020-11896", "CVE-2020-11898", "CVE-2020-11899",
                 "CVE-2020-11901", "CVE-2020-11902"]),
    "APC-002": ("warn", "NMC1 AOS <= 3.9.2 -- Ripple20 affected range (EOL hardware)",
                ["CVE-2020-11896", "CVE-2020-11898", "CVE-2020-11899",
                 "CVE-2020-11901", "CVE-2020-11902"]),
    "APC-003": ("warn", "NMC3 AOS <= 1.3.3.1 (AP9640/AP9641) -- Ripple20 affected range",
                ["CVE-2020-11896", "CVE-2020-11898", "CVE-2020-11899",
                 "CVE-2020-11901", "CVE-2020-11902"]),
    "APC-010": ("info", "APC NMC identified (inventory)", []),
    "APC-011": ("notice", "APC NMC sysDescr seen but not gateable (missing, unknown or inconsistent "
                          "tokens, or a version between last-affected and first-fixed)", []),
    "APC-101": ("critical", "Fragmented IPv4-in-IP tunnel datagram sent to an NMC",
                ["CVE-2020-11896"]),
    "APC-102": ("critical", "Reassembled tunnel: inner IPv4 total length < data present "
                            "(Treck trimming condition)", ["CVE-2020-11896"]),
    "APC-103": ("warn", "NMC decapsulated a flagged IP-in-IP datagram and answered with ICMP "
                        "protocol-unreachable (tunnelling prerequisite observed)",
                ["CVE-2020-11898"]),
    "APC-012": ("warn", "Observed-NMC table is full: cards not already known are being ignored "
                        "(sysDescr spoofing, or a fleet larger than the cap -- declare cards with --nmc)", []),
    "APC-104": ("notice", "Tunnel traffic sent to an NMC that meets no CVE condition "
                          "(NMCs never terminate tunnels; includes all IPv6-outer tunnels)", []),
    "APC-105": ("warn", "IPv6-in-IPv4 (protocol 41) sent to an NMC", ["CVE-2020-11902"]),
    "APC-106": ("critical", "ICMP protocol-unreachable from an NMC quotes bytes that are not in the "
                            "offending packet: heap memory disclosed", ["CVE-2020-11898"]),
    "APC-107": ("info", "NMC answered an outer IP-in-IP (protocol 4) packet with ICMP "
                        "protocol-unreachable: it did not decapsulate it", []),
    "APC-108": ("info", "NMC answered an outer IPv6-in-IPv4 (protocol 41) packet with ICMP "
                        "protocol-unreachable: it did not decapsulate it", []),
    "APC-109": ("info", "A DIFFERENT device than the card answered a tunnel datagram sent to it with ICMP "
                        "protocol-unreachable (a middlebox rejecting on its behalf, or a spoof): the card's own "
                        "tunnelling is not established", []),
    "APC-110": ("notice", "SNMP reply from a card with a declared MAC arrived from a different MAC: the declaration "
                          "does not match this tap's view of the card, or something else is answering as it", []),
    "APC-111": ("critical", "DNS response to NMC: CNAME RDATA labels overrun RDLENGTH",
                ["CVE-2020-11901"]),
    "APC-112": ("critical", "DNS response to NMC: name decompresses past 255 bytes, "
                            "loops, chains pointers, or uses reserved label types",
                ["CVE-2020-11901"]),
}

# Declared address-family scope per code. IPv6 is applied where the CVE has an
# IPv6 variant; APC-105 is IPv4-only BY DEFINITION (protocol 41 in an IPv4 outer).
AF_SCOPE = {
    "APC-001": "v4+v6", "APC-002": "v4+v6", "APC-003": "v4+v6",
    "APC-010": "v4+v6", "APC-011": "v4+v6", "APC-012": "v4+v6",
    "APC-101": "v4", "APC-102": "v4", "APC-103": "v4", "APC-104": "v4+v6",
    "APC-105": "v4", "APC-106": "v4", "APC-107": "v4", "APC-108": "v4", "APC-109": "v4", "APC-110": "v4+v6",
    "APC-111": "v4+v6", "APC-112": "v4+v6",
}

# Gate key = the hardware token and application token embedded in PN/AN1
# (e.g. apc_hw05_rpdu2g_694.bin), NOT the MN model number. Real captures show model
# prefixes cannot carry platform: AP7900B is NMC2 (hw05/rpdu2g, PF 6.5.6) although AP79xx
# is NMC1 elsewhere; XRDP reports MN:0G-9354-01; and Schneider's own FAQ puts NMC3 cards in
# post-2021 AP84/86/88/89xx PDUs. Schneider's table is per APPLICATION, so this is the key.
PLATFORMS = {
    "hw02": dict(name="NMC1", max_affected=(3, 9, 2), first_fixed=(3, 9, 4), code="APC-002",
                 apps={"rpdu": "rack_pdu", "ats": "rack_ats", "sumx": "ups", "raru": "cooling"}),
    "hw05": dict(name="NMC2", max_affected=(6, 9, 4), first_fixed=(6, 9, 6), code="APC-001",
                 apps={"rpdu2g": "rack_pdu", "ats4g": "rack_ats", "sumx": "ups", "sy": "ups",
                       "px2": "ups", "sy3p": "ups", "x84p": "power_dist", "xpdu": "power_dist",
                       "xrdp": "power_dist", "xrdp2g": "power_dist", "pmm": "power_dist",
                       "nb250": "env_monitor"}),
    "hw21": dict(name="NMC3", max_affected=(1, 3, 3, 1), first_fixed=(1, 4), code="APC-003",
                 apps={"su": "ups", "sy": "ups"}),
}
# (hardware token, application token) pairs actually SEEN in public sysDescr captures.
# The rest come from Schneider's kBase application names and are unverified as tokens:
# if a guess is wrong the card simply lands in APC-011, never in a wrong verdict.
VERIFIED_APP_TOKENS = {("hw02", "rpdu"), ("hw02", "sumx"), ("hw05", "rpdu2g"),
                       ("hw05", "sumx"), ("hw21", "su")}
NMC2_PARTIAL_NOTE = ("NMC2 AOS 6.9.2/6.9.4 addressed 14 of 15 Treck CVEs; "
                     "CVE-2020-11901 is fixed only in 6.9.6")

OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
APC_ENTERPRISE = "1.3.6.1.4.1.318"

SEV_ORDER = {"info": 0, "notice": 1, "warn": 2, "critical": 3}

# ICMP-response correlation (APC-103/106). The reply to a malformed tunnelled datagram is
# immediate, so a short window suffices; the table is bounded for a Pi Zero 2W. Only the bytes
# a quote can contain (60-byte header + 8) are kept, never the whole reassembled datagram.
TUNNEL_FACT_NOTE = ("a statement about this address and path as of now: not a claim the card is immune "
                    "(JSOF: a DoS can remain when the tunnelling prerequisite is unmet), and a device "
                    "answering on the card's behalf produces the same reply")
# Bounded state (measured: the observed-card table cost ~604 B per spoofed source and never shrank;
# the reported-fragment set grew without limit). Operator-declared cards are PINNED and never evicted; the
# observed table REFUSES new entries at the cap instead of evicting (an LRU would let a flood of spoofed
# sources push a real card out, after which attacks on it go unanalysed).
MAX_OBSERVED_NMCS = 8192
MAX_SEEN_101 = 4096
FULL_NOTICE_EVERY = 300.0
# Attribution by source MAC, and the severity policy that depends on it. A MAC DECLARED by the operator is the only
# evidence strong enough to lower a severity: a MAC LEARNED from the card's SNMP replies is only an annotation, because
# in a routed topology every frame from the card carries the router's MAC and a firewall answering for the card would
# match it. The fact expires; the lowering is one step and never a suppression.
TUNNEL_FACT_TTL = 3600.0
MAX_TUNNEL_FACT_TTL = 86400.0      # a fact that never expires is a stale "safe" signal; nan/inf are refused too
MAX_MACS_PER_CARD = 4
MAX_DIFF_MACS = 8
LOWER_ONE_STEP = {"critical": "warn", "warn": "notice"}
TUNNEL_KINDS = {4: "ip-in-ip", 41: "ipv6-in-ipv4"}
ANSWER_WINDOW = 10.0
MAX_PENDING = 256
PENDING_KEEP = 80

# LESSON AE: the bare `ip6` term is the only form that admits extension-header
# chains; `(udp port N) or (ip6 and udp port N)` is a measured no-op.
BPF_FILTER = ("(udp port 161) or (udp port 53) or icmp or (ip proto 4) or (ip proto 41) "
              "or (ip[6:2] & 0x3fff != 0) or ip6")



class ParseError(Exception):
    pass


# ---------------------------------------------------------------- helpers
def parse_version(s: str):
    """'v6.9.4' / '1.3.3.1' -> tuple of ints. Compares ALL components."""
    m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", s.strip())
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def version_le(a, b):
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) <= b + (0,) * (n - len(b))


def norm_mac(s: str) -> str:
    """Canonical aa:bb:cc:dd:ee:ff. Rejects anything that cannot be a card's own address: wrong length,
    multicast/broadcast, all-zero."""
    h = re.sub(r"[:\-]", "", str(s).strip().lower())
    if not re.fullmatch(r"[0-9a-f]{12}", h):
        raise ValueError(f"not a MAC address: {s!r}")
    if int(h[1], 16) & 1:
        raise ValueError(f"a multicast MAC cannot be a card's own address: {s!r}")
    if h == "0" * 12:
        raise ValueError("the all-zero MAC cannot be a card's own address")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def mac_str(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def parse_nmc_spec(spec: str):
    """`ADDR` or `ADDR=MAC` (the separator cannot be ':': IPv6 addresses and MACs both contain it)."""
    addr, sep, mac = spec.partition("=")
    addr = str(ipaddress.ip_address(addr.strip()))
    return (addr, norm_mac(mac)) if sep else addr


def norm_addr(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))


def render_ep(addr: str, port=None) -> str:
    if port is None:
        return addr
    if ":" in addr:
        return f"[{addr}]:{port}"
    return f"{addr}:{port}"


def split_ep(ep: str):
    """Inverse of render_ep for host:port strings (round-trip check)."""
    if ep.startswith("["):
        host, _, port = ep[1:].partition("]:")
        return host, int(port)
    host, _, port = ep.rpartition(":")
    return host, int(port)


# ---------------------------------------------------------------- L2/L3
class L3:
    __slots__ = ("af", "src", "dst", "proto", "payload", "frag", "frag_key",
                 "frag_off", "more", "l4_usable", "ident", "smac")

    def __init__(self):
        self.frag = False
        self.smac = None
        self.ident = None
        self.frag_key = None
        self.frag_off = 0
        self.more = False
        self.l4_usable = True


def parse_ether(frame: bytes):
    """Returns (ethertype, offset_of_l3). Handles 802.1Q / 802.1ad stacks."""
    if len(frame) < 14:
        raise ParseError("short ethernet")
    et = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    depth = 0
    while et in (0x8100, 0x88A8, 0x9100):
        if len(frame) < off + 4 or depth > 3:
            raise ParseError("short vlan")
        et = struct.unpack_from("!H", frame, off + 2)[0]
        off += 4
        depth += 1
    return et, off


def parse_ipv4(buf: bytes, off: int = 0) -> L3:
    if len(buf) < off + 20:
        raise ParseError("short ipv4")
    vihl = buf[off]
    if vihl >> 4 != 4:
        raise ParseError("not ipv4")
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(buf) < off + ihl:
        raise ParseError("bad ihl")
    total = struct.unpack_from("!H", buf, off + 2)[0]
    ident = struct.unpack_from("!H", buf, off + 4)[0]
    ff = struct.unpack_from("!H", buf, off + 6)[0]
    l3 = L3()
    l3.af = 4
    l3.ident = ident
    l3.proto = buf[off + 9]
    l3.src = norm_addr(buf[off + 12:off + 16])
    l3.dst = norm_addr(buf[off + 16:off + 20])
    end = off + total if ihl <= total <= len(buf) - off else len(buf)
    l3.payload = buf[off + ihl:end]
    l3.more = bool(ff & 0x2000)
    l3.frag_off = (ff & 0x1FFF) * 8
    if l3.more or l3.frag_off:
        l3.frag = True
        l3.frag_key = (4, l3.src, l3.dst, ident, l3.proto)
        l3.l4_usable = False
    return l3


EXT_HDRS = {0, 43, 60}   # hop-by-hop, routing, destination options


def parse_ipv6(buf: bytes, off: int = 0) -> L3:
    if len(buf) < off + 40:
        raise ParseError("short ipv6")
    if buf[off] >> 4 != 6:
        raise ParseError("not ipv6")
    plen = struct.unpack_from("!H", buf, off + 4)[0]
    nh = buf[off + 6]
    l3 = L3()
    l3.af = 6
    l3.src = norm_addr(buf[off + 8:off + 24])
    l3.dst = norm_addr(buf[off + 24:off + 40])
    end = min(off + 40 + plen, len(buf))
    p = off + 40
    hops = 0
    while True:
        hops += 1
        if hops > 12:
            l3.l4_usable = False
            break
        if nh in EXT_HDRS:
            if p + 2 > end:
                raise ParseError("short ext")
            nh2 = buf[p]
            p += (buf[p + 1] + 1) * 8
            nh = nh2
            continue
        if nh == 44:
            if p + 8 > end:
                raise ParseError("short frag hdr")
            nh2 = buf[p]
            fo = struct.unpack_from("!H", buf, p + 2)[0]
            ident = struct.unpack_from("!I", buf, p + 4)[0]
            p += 8
            nh = nh2
            l3.frag_off = fo & 0xFFF8
            l3.more = bool(fo & 1)
            if l3.more or l3.frag_off:
                l3.frag = True
                l3.frag_key = (6, l3.src, l3.dst, ident, nh)
                l3.l4_usable = False
                break
            continue      # atomic fragment -- keep walking
        break
    if p > end:
        raise ParseError("ext overrun")
    l3.proto = nh
    l3.payload = buf[p:end]
    return l3


def parse_l3(frame: bytes) -> L3 | None:
    et, off = parse_ether(frame)
    if et == 0x0800:
        l3 = parse_ipv4(frame, off)
    elif et == 0x86DD:
        l3 = parse_ipv6(frame, off)
    else:
        return None
    l3.smac = mac_str(frame[6:12])
    return l3


# ---------------------------------------------------------------- reassembly
class Reassembler:
    """Generic IP fragment reassembly for datagrams TO KNOWN NMCs only."""

    def __init__(self, timeout=30.0, max_dgrams=256, max_bytes=65535):
        self.timeout = timeout
        self.max_dgrams = max_dgrams
        self.max_bytes = max_bytes
        self.tab = {}

    def add(self, l3: L3, now: float):
        self._expire(now)
        ent = self.tab.get(l3.frag_key)
        if ent is None:
            if len(self.tab) >= self.max_dgrams:
                return None
            ent = {"t": now, "frags": {}, "total": None}
            self.tab[l3.frag_key] = ent
        if l3.frag_off + len(l3.payload) > self.max_bytes:
            self.tab.pop(l3.frag_key, None)
            return None
        ent["frags"].setdefault(l3.frag_off, (l3.payload, l3.more))
        if not l3.more:
            ent["total"] = l3.frag_off + len(l3.payload)
        if ent["total"] is None:
            return None
        data = bytearray()
        for fo in sorted(ent["frags"]):
            chunk, _ = ent["frags"][fo]
            if fo > len(data):
                return None           # hole -- wait for more fragments
            data += chunk[len(data) - fo:]   # first-wins on overlap
        if len(data) < ent["total"]:
            return None
        sizes = [len(ent["frags"][fo][0]) for fo in sorted(ent["frags"])]
        del self.tab[l3.frag_key]
        return bytes(data[:ent["total"]]), sizes

    def _expire(self, now):
        for k in [k for k, v in self.tab.items() if now - v["t"] > self.timeout]:
            del self.tab[k]


# ---------------------------------------------------------------- SNMP (BER)
def ber_tlv(buf: bytes, i: int, limit: int):
    if i + 2 > limit:
        raise ParseError("short tlv")
    tag = buf[i]
    ln = buf[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or i + n > limit:
            raise ParseError("bad length")
        ln = int.from_bytes(buf[i:i + n], "big")
        i += n
    if i + ln > limit:
        raise ParseError("tlv overrun")
    return tag, i, i + ln


def ber_oid(b: bytes) -> str:
    if not b:
        raise ParseError("empty oid")
    first = b[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(str(v))
            v = 0
    return ".".join(parts)


def parse_snmp_response(payload: bytes):
    """v1/v2c GetResponse -> {oid: value}. None for v3 / other PDUs."""
    tag, i, end = ber_tlv(payload, 0, len(payload))
    if tag != 0x30:
        raise ParseError("not sequence")
    tag, vi, ve = ber_tlv(payload, i, end)
    if tag != 0x02:
        raise ParseError("no version")
    ver = int.from_bytes(payload[vi:ve], "big")
    if ver not in (0, 1):
        return None                       # SNMPv3: scoped PDU may be encrypted
    tag, ci, ce = ber_tlv(payload, ve, end)
    if tag != 0x04:
        raise ParseError("no community")
    tag, pi, pe = ber_tlv(payload, ce, end)
    if tag != 0xA2:
        return None
    j = pi
    for _ in range(3):
        tag, _a, j = ber_tlv(payload, j, pe)
    tag, li, le = ber_tlv(payload, j, pe)
    if tag != 0x30:
        raise ParseError("no varbind list")
    out = {}
    k = li
    while k < le:
        tag, bi, be = ber_tlv(payload, k, le)
        k = be
        if tag != 0x30:
            raise ParseError("bad varbind")
        tag, oi, oe = ber_tlv(payload, bi, be)
        if tag != 0x06:
            raise ParseError("bad oid")
        oid = ber_oid(payload[oi:oe])
        vtag, xi, xe = ber_tlv(payload, oe, be)
        raw = payload[xi:xe]
        if vtag == 0x04:
            out[oid] = raw.decode("latin-1")
        elif vtag == 0x06:
            out[oid] = ber_oid(raw) if raw else ""
    return out


def looks_apc(descr: str | None, objid: str | None) -> bool:
    if objid and (objid == APC_ENTERPRISE or objid.startswith(APC_ENTERPRISE + ".")):
        return True
    return bool(descr) and ("APC Web/SNMP Management Card" in descr
                            or "Network Management Card" in descr)


def parse_sysdescr(text: str):
    """Parse an APC NMC sysDescr (first parenthesised group only). None if not APC-looking.

    Grammar confirmed against public captures of NMC1/NMC2/NMC3, rack PDUs, UPS and XRDP:
      APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.4.0 PN:apc_hw05_aos_640.bin AF1:v6.4.0
        AN1:apc_hw05_rpdu2g_640.bin MN:AP8841 HR:02 SN: <serial> MD:04/14/2015)
        [ (Embedded PowerNet SNMP Agent SW v2.2 compatible) ]
    Note the SPACE after `SN:` on the wire, and that MN is the card/device model (which can
    be a part number such as 0G-9354-01), so it is reported but never used to gate.
    """
    if "APC" not in text and "Schneider" not in text:
        return None
    rec = {"raw": text[:300]}
    m = re.search(r"\(([^()]*)\)", text)
    if not m:
        rec["parse"] = "no_field_block"
        return rec
    fields, key = {}, None
    for tok in m.group(1).split():
        head = tok.split(":", 1)[0]
        if ":" in tok and head.isalnum() and head.upper() == head:
            key, val = tok.split(":", 1)
            fields[key] = val
        elif key is not None and fields.get(key, "") == "":
            fields[key] = tok                              # "SN: ZA123" form
    pn, an1 = fields.get("PN", ""), fields.get("AN1", "")
    hws = {p for p in pn.split("_") + an1.split("_") if re.fullmatch(r"hw\d+", p)}
    parts = an1.split("_")
    rec.update(fields=fields, pf=fields.get("PF"), af1=fields.get("AF1"), model=fields.get("MN"),
               app=(parts[2].lower() if len(parts) >= 3 else None),
               hw=(next(iter(hws)) if len(hws) == 1 else None),
               hw_conflict=(sorted(hws) if len(hws) > 1 else None),
               parse="ok" if fields else "no_fields")
    return rec


def screen_version(rec):
    """Gate a parsed sysDescr against Schneider's per-application table (FA410359).

    Outcomes (state): affected | fixed | gap | not_gateable. Gate is on PF (AOS): the vendor's
    affected column is stated in AOS terms. A version between the last affected and first
    fixed release is NOT assumed safe -- it is reported as APC-011 (state=gap)."""
    def ng(reason, **kw):
        return {"code": "APC-011", "state": "not_gateable", "reason": reason, **kw}
    if rec.get("parse") != "ok":
        return ng(rec.get("parse", "unparsed"))
    if rec.get("hw_conflict"):
        return ng("hw_token_conflict", hw=rec["hw_conflict"])
    plat = PLATFORMS.get(rec.get("hw") or "")
    if plat is None:
        return ng("unknown_platform", hw=rec.get("hw"))
    app = rec.get("app")
    if app not in plat["apps"]:
        return ng("app_not_in_vendor_table", app=app, platform=plat["name"])
    v = parse_version(rec.get("pf") or "")
    if v is None:
        return ng("no_aos_version", platform=plat["name"])
    base = {"platform": plat["name"], "app": app, "product_class": plat["apps"][app],
            "first_fixed": ".".join(map(str, plat["first_fixed"])),
            "app_token_verified": (rec["hw"], app) in VERIFIED_APP_TOKENS}
    if version_le(v, plat["max_affected"]):
        out = {**base, "code": plat["code"], "state": "affected",
               "gate": ".".join(map(str, plat["max_affected"]))}
        if plat["name"] == "NMC2" and version_le((6, 9, 2), v):
            out["note"] = NMC2_PARTIAL_NOTE
        return out
    if version_le(plat["first_fixed"], v):
        return {**base, "code": None, "state": "fixed"}
    return {**base, "code": "APC-011", "state": "gap",
            "reason": "version_gap_between_last_affected_and_first_fixed"}


# ---------------------------------------------------------------- DNS
def dns_name_walk(msg: bytes, off: int):
    """Standard-rules walk. Returns (end_of_name_in_place, decompressed_len,
    anomalies list). Never raises on hostile input; truncation is an anomaly."""
    anomalies = []
    total = 0
    pos = off
    end_in_place = None
    jumps = 0
    consecutive_ptr = 0
    seen = set()
    while True:
        if pos >= len(msg):
            anomalies.append("truncated")
            break
        b = msg[pos]
        kind = b & 0xC0
        if kind == 0xC0:
            if pos + 1 >= len(msg):
                anomalies.append("truncated")
                break
            target = ((b & 0x3F) << 8) | msg[pos + 1]
            if end_in_place is None:
                end_in_place = pos + 2
            consecutive_ptr += 1
            if consecutive_ptr >= 4:
                anomalies.append("pointer-chain")
            if target in seen:
                anomalies.append("pointer-loop")
                break
            seen.add(target)
            jumps += 1
            if jumps > 64:
                anomalies.append("pointer-loop")
                break
            pos = target
            continue
        if kind in (0x40, 0x80):
            anomalies.append("reserved-label-type")   # Treck treats as pointer
            break
        consecutive_ptr = 0
        if b == 0:
            total += 1
            if end_in_place is None:
                end_in_place = pos + 1
            break
        total += 1 + b
        pos += 1 + b
    if total > 255:
        anomalies.append("name>255")
    return end_in_place, total, sorted(set(anomalies))


def treck_rdata_len(msg: bytes, start: int) -> int:
    """Treck's CNAME RDATA length: sum labels until NUL, pointer, or payload end."""
    n = 0
    p = start
    while p < len(msg):
        b = msg[p]
        if b == 0:
            return n + 1
        if b & 0xC0:
            return n + 2
        n += 1 + b
        p += 1 + b
    return n


NAME_RDATA_TYPES = {2, 5, 12, 15}   # NS, CNAME, PTR, MX (preference first)


def analyze_dns(msg: bytes):
    """-> list of (code, detail). Only responses (QR=1) are examined."""
    if len(msg) < 12:
        return []
    flags = struct.unpack_from("!H", msg, 2)[0]
    if not flags & 0x8000:
        return []
    qd, an, ns, ar = struct.unpack_from("!4H", msg, 4)
    hits = []
    pos = 12
    name_anoms = set()

    def name_at(p):
        endp, _, an_ = dns_name_walk(msg, p)
        name_anoms.update(a for a in an_ if a != "truncated")
        return endp

    try:
        for _ in range(qd):
            e = name_at(pos)
            if e is None:
                raise ParseError("q name")
            pos = e + 4
        for _ in range(an + ns + ar):
            e = name_at(pos)
            if e is None or e + 10 > len(msg):
                raise ParseError("rr")
            rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", msg, e)
            rstart = e + 10
            if rtype == 5:
                actual = treck_rdata_len(msg, rstart)
                if actual > rdlen:
                    hits.append(("APC-111", {"rdlength": rdlen, "treck_len": actual,
                                             "rr_offset": e}))
            if rtype in NAME_RDATA_TYPES and rstart < len(msg):
                name_at(rstart + (2 if rtype == 15 else 0))
            pos = rstart + rdlen
            if pos > len(msg):
                break
    except ParseError:
        pass
    if name_anoms:
        hits.append(("APC-112", {"anomalies": sorted(name_anoms)}))
    return hits


# ---------------------------------------------------------------- engine
class Engine:
    def __init__(self, nmcs=(), emit=None, clock=time.time, max_observed=MAX_OBSERVED_NMCS,
                 tunnel_fact_ttl=TUNNEL_FACT_TTL, lower_attempts=True):
        if not (0 <= tunnel_fact_ttl <= MAX_TUNNEL_FACT_TTL):          # also rejects nan
            raise ValueError(f"the tunnel-fact freshness window must be between 0 and {MAX_TUNNEL_FACT_TTL:g} "
                             f"seconds, got {tunnel_fact_ttl}")
        self.tunnel_fact_ttl = tunnel_fact_ttl
        self.lower_attempts = lower_attempts
        self.max_observed = max_observed
        self.observed = 0                 # cards learned from SNMP (operator-declared ones are not counted)
        self._full_t = None
        self.nmcs = {}
        for entry in nmcs:                # an address, or (address, declared MAC)
            addr, mac = entry if isinstance(entry, (tuple, list)) else (entry, None)
            addr = str(ipaddress.ip_address(addr))
            rec = self.nmcs.setdefault(addr, {"source": "operator"})
            if mac:
                mac = norm_mac(mac)
                if rec.get("mac_declared", mac) != mac:
                    raise ValueError(f"{addr} is declared with two different MACs: {rec['mac_declared']} and {mac}")
                rec["mac_declared"] = mac          # a duplicate WITHOUT a MAC never erases one
        self.emit = emit or (lambda f: print(json.dumps(f), flush=True))
        self.clock = clock
        self.reasm = Reassembler()
        self.seen_b = {}
        self.seen_101 = {}                # key -> time last reported; insertion order == age order
        self.pending_102 = {}
        self.pending_outer = {}
        self.stats = {"frames": 0, "parse_errors": 0, "findings": 0, "nmc_ignored": 0, "lowered": 0}

    def _finding(self, code, l3=None, src=None, dst=None, sport=None, dport=None,
                 detail=None, confidence="high", cves=None, severity=None):
        sev, title, default_cves = CODES[code]
        f = {"module": "apcguard", "code": code, "severity": severity or sev, "title": title,
             "cves": cves if cves is not None else list(default_cves),
             "confidence": confidence, "ts": self.clock()}
        if l3 is not None:
            f["af"] = f"ipv{l3.af}"
            src = src or l3.src
            dst = dst or l3.dst
        f["src"] = render_ep(src, sport) if src else None
        f["dst"] = render_ep(dst, dport) if dst else None
        if detail:
            f["detail"] = detail
        self.stats["findings"] += 1
        self.emit(f)

    def _maybe_lower(self, code: str, dst: str, proto: int):
        """(severity, detail) for an ATTEMPT finding against `dst`.

        Lowers ONE step, and only when this card was observed rejecting THIS tunnel protocol, the reply carried the
        card's DECLARED MAC, the observation is younger than tunnel_fact_ttl, and nothing since has shown the card
        decapsulating. Anything weaker (learned MAC, unknown source, stale, another protocol) leaves the severity
        alone. The finding is still emitted: lowered, never suppressed."""
        if not self.lower_attempts:
            return None, {}
        kind = TUNNEL_KINDS.get(proto)
        fact = self.nmcs.get(dst, {}).get("tunnel", {}).get(kind)
        if not fact or fact["state"] != "inactive" or fact["attr"] != "declared-mac":
            return None, {}
        age = self.clock() - fact["t"]
        low = LOWER_ONE_STEP.get(CODES[code][0])
        if age > self.tunnel_fact_ttl or low is None:
            return None, {}
        self.stats["lowered"] += 1
        return low, {"severity_lowered_from": CODES[code][0],
                     "lowered_because": "this card answered an outer %s packet with ICMP protocol-unreachable "
                                        "from its declared MAC %d s ago" % (kind, int(age))}

    def handle_frame(self, frame: bytes):
        self.stats["frames"] += 1
        try:
            l3 = parse_l3(frame)
        except ParseError:
            self.stats["parse_errors"] += 1
            return
        if l3 is None:
            return
        self.handle_l3(l3)

    def handle_l3(self, l3: L3):
        to_nmc = l3.dst in self.nmcs
        if l3.frag:
            if not to_nmc:
                return
            if l3.proto == 4 and l3.af == 4:
                key = l3.frag_key
                if self._new_101(key):
                    sev, extra = self._maybe_lower("APC-101", l3.dst, 4)
                    self._finding("APC-101", l3, detail={"outer_frag_offset": l3.frag_off, **extra}, severity=sev)
            res = self.reasm.add(l3, self.clock())
            if res is None:
                return
            data, sizes = res
            whole = L3()
            whole.af, whole.src, whole.dst, whole.proto = l3.af, l3.src, l3.dst, l3.proto
            whole.ident = l3.ident
            whole.smac = l3.smac
            whole.payload = data
            self.seen_101.pop(l3.frag_key, None)
            self._dispatch(whole, fragmented=True, sizes=sizes)
            return
        self._dispatch(l3, fragmented=False, sizes=None)

    def _dispatch(self, l3: L3, fragmented: bool, sizes):
        to_nmc = l3.dst in self.nmcs
        if l3.proto in (4, 41) and to_nmc:
            self._tunnel(l3, fragmented, sizes)
            return
        if l3.proto == 1 and l3.af == 4 and l3.src in self.nmcs:
            self._icmp(l3)
            return
        if l3.proto == 17 and len(l3.payload) >= 8:
            sport, dport = struct.unpack_from("!HH", l3.payload, 0)
            body = l3.payload[8:]
            if sport == 161:
                self._snmp(l3, body, sport, dport)
            elif sport == 53 and to_nmc:
                for code, det in analyze_dns(body):
                    self._finding(code, l3, sport=sport, dport=dport, detail=det)

    def _tunnel(self, l3: L3, fragmented: bool, sizes):
        if l3.af == 4:
            self._remember_outer(l3, fragmented)
        if l3.af == 6:
            self._finding("APC-104", l3, detail={
                "outer": "ipv6", "inner_proto": l3.proto, "fragmented": fragmented,
                "note": "tunnel to an NMC over IPv6; CVE-2020-11896/11898/11902 are "
                        "IPv4-outer conditions, no CVE claimed"})
            return
        if l3.proto == 41:
            sev, extra = self._maybe_lower("APC-105", l3.dst, 41)
            self._finding("APC-105", l3, detail=extra or None, severity=sev)
            return
        inner = l3.payload
        detail = {"outer": f"ipv{l3.af}", "fragmented": fragmented}
        if sizes and len(sizes) > 1 and sizes[-1] > max(sizes[:-1]):
            detail["final_fragment_largest"] = True
        if len(inner) >= 20 and inner[0] >> 4 == 4:
            inner_total = struct.unpack_from("!H", inner, 2)[0]
            inner_proto = inner[9]
            detail.update({"inner_total_length": inner_total, "inner_data": len(inner),
                           "inner_proto": inner_proto})
            if fragmented and inner_total < len(inner):
                # Same trimming root cause for both CVEs (JSOF whitepaper ch.2-4). CVE-2020-11898
                # adds the INVALID inner protocol that makes the stack answer with an ICMP
                # protocol-unreachable copying out-of-bounds data; the only value the whitepaper
                # and the NVISO reproduction use is protocol 0, so only 0 is attributed.
                cves = ["CVE-2020-11896"]
                if inner_proto == 0:
                    cves.append("CVE-2020-11898")
                sev, extra = self._maybe_lower("APC-102", l3.dst, 4)
                detail.update(extra)
                self._finding("APC-102", l3, detail=detail, cves=cves, severity=sev)
                self._remember_102(l3, inner, sizes)
                return
        if not fragmented:
            self._finding("APC-104", l3, detail=detail)

    def _new_101(self, key) -> bool:
        """True if this fragment key should be reported: never seen, or last reported longer ago than the
        reassembly timeout (the datagram could no longer have completed). Age is checked HERE, not only when
        other keys are inserted -- otherwise a stale entry keeps suppressing a repeat."""
        t = self.seen_101.get(key)
        if t is not None and self.clock() - t <= self.reasm.timeout:
            return False
        self._note_101(key)
        return True

    def _note_101(self, key):
        """Record a reported fragment key. Bounded: entries older than the reassembly timeout (the datagram
        can no longer complete) and anything beyond MAX_SEEN_101 are dropped oldest-first, O(1) amortised."""
        d, now = self.seen_101, self.clock()
        d.pop(key, None)
        d[key] = now
        while d and (len(d) > MAX_SEEN_101 or now - d[next(iter(d))] > self.reasm.timeout):
            del d[next(iter(d))]

    def _table_full(self, l3: L3):
        self.stats["nmc_ignored"] += 1
        now = self.clock()
        if self._full_t is not None and now - self._full_t < FULL_NOTICE_EVERY:
            return
        self._full_t = now
        self._finding("APC-012", l3, detail={
            "observed_cards": self.observed, "cap": self.max_observed,
            "ignored_so_far": self.stats["nmc_ignored"],
            "note": "cards already known are still analysed; declared cards (--nmc) are pinned and unaffected"})

    def _remember_outer(self, l3: L3, fragmented: bool):
        """Remember an outer protocol-4/41 datagram sent to an NMC, so a reply that quotes ITS header
        (not an inner packet's) can be recognised as the card rejecting the tunnel itself."""
        now = self.clock()
        self.pending_outer = {k: v for k, v in self.pending_outer.items() if now - v["t"] <= ANSWER_WINDOW}
        if len(self.pending_outer) >= MAX_PENDING:
            del self.pending_outer[min(self.pending_outer, key=lambda k: self.pending_outer[k]["t"])]
        self.pending_outer[(l3.src, l3.dst, l3.ident, l3.proto)] = {"t": now, "nmc": l3.dst, "frag": fragmented}

    def tunnel_state(self, addr: str) -> dict:
        """Per-card tunnelling observations: {"ip-in-ip"|"ipv6-in-ipv4": "inactive"|"active"}. Each is
        as of the observation, never a standing guarantee."""
        return {k: v["state"] for k, v in self.nmcs.get(addr, {}).get("tunnel", {}).items()}

    def _remember_102(self, l3: L3, inner: bytes, sizes):
        """Remember a datagram reported as APC-102 so the card's ICMP reply can be matched to it."""
        now = self.clock()
        self.pending_102 = {k: v for k, v in self.pending_102.items() if now - v["t"] <= ANSWER_WINDOW}
        if len(self.pending_102) >= MAX_PENDING:
            del self.pending_102[min(self.pending_102, key=lambda k: self.pending_102[k]["t"])]
        key = (norm_addr(inner[12:16]), norm_addr(inner[16:20]),
               struct.unpack_from("!H", inner, 4)[0], inner[9])
        self.pending_102[key] = {"t": now, "nmc": l3.dst, "inner": inner[:PENDING_KEEP],
                                 "first": sizes[0] if sizes else len(inner)}

    def _icmp(self, l3: L3):
        """An ICMP protocol-unreachable FROM an NMC. Matched to a flagged tunnel datagram by the
        inner header it quotes; a bare protocol-unreachable is ordinary scanner noise and is ignored.

        CVE-2020-11898 (JSOF whitepaper ch.4): tfIcmpErrPacket copies min(IPhdrLen + 8, link-data
        length) bytes of the offending packet. Link-data length was trimmed to the inner header's
        (larger) total length, so it reads PAST the first fragment. The bytes beyond the first
        fragment are therefore heap contents, not the packet."""
        p = l3.payload
        if len(p) < 8 + 20 or p[0] != 3 or p[1] != 2:          # type 3 / code 2: protocol unreachable
            return
        quote = p[8:]
        if quote[0] >> 4 != 4:
            return
        qkey = (norm_addr(quote[12:16]), norm_addr(quote[16:20]),
                struct.unpack_from("!H", quote, 4)[0], quote[9])
        pend = self.pending_102.get(qkey)
        if pend is None or l3.src != pend["nmc"] or l3.dst != qkey[0]:
            self._rejected(l3, qkey, len(quote))                # perhaps the OUTER header was quoted
            return
        del self.pending_102[qkey]                              # one answer per flagged datagram
        if self.clock() - pend["t"] > ANSWER_WINDOW:
            return
        first, inner = pend["first"], pend["inner"]
        d103 = {"inner_proto": qkey[3], "quote_bytes": len(quote), "first_fragment_bytes": first}
        tun = self.nmcs.get(l3.src, {}).setdefault("tunnel", {})
        prev = tun.get("ip-in-ip")
        if prev is not None and prev["state"] == "inactive":
            d103["previously_observed"] = "inactive"           # the earlier fact is stale
        tun["ip-in-ip"] = {"state": "active", "t": self.clock(), "attr": "decapsulated"}
        self._finding("APC-103", l3, detail=d103)
        # The first 20 bytes are the fixed header (TTL/checksum may legitimately differ), and
        # everything up to `first` came from the first fragment. Compare only what lies beyond.
        start, end = max(first, 20), min(len(quote), len(inner))
        bad = [i for i in range(start, end) if quote[i] != inner[i]]
        if bad:
            # counts and offsets ONLY: the disclosed bytes can be another user's traffic (NVISO's
            # capture shows an HTTP request) and findings reach the mesh, the UI and PDF reports.
            self._finding("APC-106", l3, detail={
                "inner_proto": qkey[3], "quote_bytes": len(quote), "first_fragment_bytes": first,
                "beyond_first_fragment": len(quote) - first, "first_mismatch_offset": bad[0],
                "mismatching_bytes": len(bad)})

    def _rejected(self, l3: L3, qkey, qbytes: int):
        """An ICMP protocol-unreachable FROM an NMC quoting the OUTER header of a tunnel datagram we saw
        sent to it: this address answered as a host with no handler for the tunnel protocol.

        A statement about this address and path, NOT a claim of immunity: a device answering on the
        card's behalf (e.g. a firewall REJECT) sends the same message, JSOF notes a DoS can remain when
        the tunnelling prerequisite is unmet, and protocol 4 says nothing about protocol 41. It is
        informational, names no CVE, and never suppresses another finding."""
        code = {4: "APC-107", 41: "APC-108"}.get(qkey[3])
        outer = self.pending_outer.get(qkey) if code else None
        if outer is None or l3.src != outer["nmc"] or l3.dst != qkey[0]:
            return
        del self.pending_outer[qkey]
        if self.clock() - outer["t"] > ANSWER_WINDOW:
            return
        kind = TUNNEL_KINDS[qkey[3]]
        rec = self.nmcs.get(l3.src, {})
        attr, card_mac = self._attribute(rec, l3.smac)
        if attr == "different-source":
            self._different_source(l3, rec, kind, qkey, card_mac)
            return                                              # NOT the card: record nothing about it
        tun = rec.setdefault("tunnel", {})
        prev = tun.get(kind)
        tun[kind] = {"state": "inactive", "t": self.clock(), "attr": attr}
        if prev is not None and prev["state"] == "inactive":
            return                                              # already reported: a fact, not a stream
        self._finding(code, l3, detail={
            "outer_proto": qkey[3], "outer_fragmented": outer["frag"], "quote_bytes": qbytes,
            "attribution": attr, "reply_src_mac": l3.smac, "card_mac": card_mac,
            "prerequisite_of": "CVE-2020-11896,CVE-2020-11898" if qkey[3] == 4 else "CVE-2020-11902",
            "note": TUNNEL_FACT_NOTE})

    def _declared_mismatch(self, l3: L3, rec: dict, sport, declared: str):
        """An SNMP reply that looks like this card's arrived from a MAC other than the one declared for it. Two
        causes: the declaration is wrong for where this tap sits (a router's or another interface's MAC), or
        something else is answering as the card. Bounded per card, once per observed MAC."""
        seen = rec.setdefault("snmp_off_macs", set())
        if l3.smac in seen or len(seen) >= MAX_DIFF_MACS:
            return
        seen.add(l3.smac)
        self._finding("APC-110", l3, sport=sport, detail={
            "declared_mac": declared, "observed_mac": l3.smac,
            "note": "the declared MAC does not match the frames this tap sees from the card; either the declaration "
                    "is wrong for this tap position, or another device is answering as the card"})

    def _attribute(self, rec: dict, smac):
        """Whose frame is this ICMP reply? -> (label, the MAC it was compared with).

        declared-mac         the operator declared this card's MAC and the reply carries it   (STRONG)
        same-source-as-snmp  it matches the one MAC seen on the card's SNMP replies             (annotation only)
        different-source     it does NOT match the declared or the learned MAC: another device sent it
        ambiguous            several MACs have answered SNMP as this address
        unknown              no MAC known for the card, or the frame carried none
        Only declared-mac may lower a severity: in a routed topology every frame from the card carries the
        router's MAC, so a learned MAC cannot tell the card from a firewall answering for it."""
        if smac is None:
            return "unknown", None
        declared = rec.get("mac_declared")
        if declared:
            return ("declared-mac" if smac == declared else "different-source"), declared
        learned = rec.get("macs") or set()
        if len(learned) == 1:
            (only,) = learned
            return ("same-source-as-snmp" if smac == only else "different-source"), only
        if len(learned) > 1:
            return "ambiguous", None
        return "unknown", None

    def _different_source(self, l3: L3, rec: dict, kind: str, qkey, card_mac):
        """Bounded per card: one report per (protocol, source MAC), at most MAX_DIFF_MACS of them."""
        seen = rec.setdefault("diff_macs", set())
        if (kind, l3.smac) in seen or len(seen) >= MAX_DIFF_MACS:
            return
        seen.add((kind, l3.smac))
        self._finding("APC-109", l3, detail={
            "outer_proto": qkey[3], "reply_src_mac": l3.smac, "card_mac": card_mac,
            "note": "answered from a different L2 source than the card's own; the card's tunnelling is not established"})

    def _snmp(self, l3: L3, body: bytes, sport, dport):
        try:
            vb = parse_snmp_response(body)
        except ParseError:
            return
        if not vb:
            return
        descr = vb.get(OID_SYSDESCR)
        objid = vb.get(OID_SYSOBJECTID)
        if not looks_apc(descr, objid):
            return
        addr = l3.src
        rec = self.nmcs.get(addr)
        first = rec is None or "observed" not in rec["source"]
        if rec is None:
            if self.observed >= self.max_observed:
                self._table_full(l3)
                return
            self.observed += 1
            rec = self.nmcs[addr] = {"source": "observed"}
        elif rec["source"] == "operator":
            rec["source"] = "operator+observed"
        if l3.smac:
            macs = rec.setdefault("macs", set())               # capped: an attacker can send any number of MACs
            if len(macs) < MAX_MACS_PER_CARD:
                macs.add(l3.smac)
        declared = rec.get("mac_declared")
        if declared and l3.smac and l3.smac != declared:
            self._declared_mismatch(l3, rec, sport, declared)
        parsed = (parse_sysdescr(descr) if descr else None) or {}
        scr = screen_version(parsed) if descr else {}
        rec.update({k: parsed[k] for k in ("model", "pf", "hw", "app") if parsed.get(k)})
        det = {"model": parsed.get("model"), "aos": parsed.get("pf"), "hw": parsed.get("hw"),
               "app": parsed.get("app"), "app_fw": parsed.get("af1"), "state": scr.get("state"),
               "attribution": rec["source"],
               "via": "sysDescr" if descr else "sysObjectID only"}
        if first:
            self._finding("APC-010", l3, sport=sport, detail=det)
        if not descr:
            return                        # objid alone: inventory only, cannot gate
        code = scr.get("code")
        key = (code, scr.get("state"), parsed.get("pf"), parsed.get("hw"), parsed.get("app"))
        if code and self.seen_b.get(addr) != key:
            self.seen_b[addr] = key
            d = dict(det)
            d["basis"] = ("Schneider FA410359 per-application table; sysDescr grammar checked "
                          "against public captures, not this fleet")
            for k in ("platform", "product_class", "first_fixed", "gate", "note", "reason",
                      "app_token_verified"):
                if k in scr:
                    d[k] = scr[k]
            self._finding(code, l3, sport=sport, detail=d,
                          confidence="version-in-range" if scr["state"] == "affected" else "low")
        elif code is None:
            self.seen_b.pop(addr, None)


# ---------------------------------------------------------------- capture
def run_capture(engine: Engine, iface=None, pcap=None, timeout=None, bpf=BPF_FILTER):
    """The ONLY function importing scapy (LESSON C)."""
    from scapy.all import sniff   # noqa: WPS433

    def cb(pkt):
        try:
            engine.handle_frame(bytes(pkt))
        except Exception as e:   # never let one packet kill the sensor
            engine.stats["parse_errors"] += 1
            print(json.dumps({"module": "apcguard", "error": repr(e)}), file=sys.stderr)

    kw = {"prn": cb, "store": False, "filter": bpf}
    if pcap:
        kw["offline"] = pcap
    else:
        kw["iface"] = iface
    if timeout:
        kw["timeout"] = timeout
    sniff(**kw)


def load_nmc_file(path):
    """One card per line: `ADDRESS` or `ADDRESS MAC`. -> [address | (address, mac)]."""
    out = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            tok = line.split("#", 1)[0].split()
            if not tok:
                continue
            if len(tok) > 2:
                raise ValueError(f"{path}:{n}: expected 'ADDRESS [MAC]', got {len(tok)} fields")
            addr = str(ipaddress.ip_address(tok[0]))
            out.append((addr, norm_mac(tok[1])) if len(tok) == 2 else addr)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="apcguard -- APC NMC Ripple20 passive guard")
    ap.add_argument("--iface")
    ap.add_argument("--pcap")
    ap.add_argument("--timeout", type=float)
    ap.add_argument("--nmc", action="append", default=[],
                    help="known NMC: ADDR or ADDR=MAC (repeatable; v4 and v6). A declared MAC lets the sensor "
                         "attribute ICMP replies to the card itself")
    ap.add_argument("--tunnel-fact-ttl", type=float, default=TUNNEL_FACT_TTL,
                    help="seconds a card's tunnel-rejection observation stays fresh enough to lower attempt severity")
    ap.add_argument("--no-lower-attempts", action="store_true",
                    help="never lower an attempt finding's severity, whatever a card was seen to reject")
    ap.add_argument("--nmc-file")
    ap.add_argument("--max-observed-nmcs", type=int, default=MAX_OBSERVED_NMCS,
                    help="cap on cards learned from SNMP (declared --nmc cards are pinned and not counted)")
    ap.add_argument("--min-severity", default="info", choices=list(SEV_ORDER))
    ap.add_argument("--print-codes", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args(argv)
    if a.print_codes:
        for c, (sev, title, cves) in CODES.items():
            print(f"{c}\t{sev}\t{AF_SCOPE[c]}\t{','.join(cves) or '-'}\t{title}")
        return 0
    if a.self_test:
        import apcguard_selftest
        return apcguard_selftest.run()
    try:
        nmcs = [parse_nmc_spec(x) for x in a.nmc] + (load_nmc_file(a.nmc_file) if a.nmc_file else [])
    except (ValueError, OSError) as e:
        ap.error(f"cannot use the declared cards: {e}")
    floor = SEV_ORDER[a.min_severity]

    def emit(f):
        if SEV_ORDER[f["severity"]] >= floor:
            print(json.dumps(f), flush=True)

    try:
        eng = Engine(nmcs=nmcs, emit=emit, max_observed=a.max_observed_nmcs,
                     tunnel_fact_ttl=a.tunnel_fact_ttl, lower_attempts=not a.no_lower_attempts)
    except ValueError as e:
        ap.error(f"cannot use the declared cards: {e}")
    if not (a.iface or a.pcap):
        ap.error("--iface or --pcap required")
    import signal

    def _stop(signum, frame):                     # SIGTERM is what `systemctl stop` sends: exit cleanly, stats included
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        run_capture(eng, iface=a.iface, pcap=a.pcap, timeout=a.timeout)
    except KeyboardInterrupt:
        pass
    print(json.dumps({"module": "apcguard", "stats": eng.stats}), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
