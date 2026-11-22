#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
radiuswatch - "RADIUS Watch"

Vendor-neutral passive RADIUS detector.  Part of the Ragnar passive network
security suite.  Takes over the Blast-RADIUS (CVE-2024-3596) detection that
lived in aristaguard (whose rule_radius was never vendor-gated), and adds
RADIUS / EAP posture and the FreeRADIUS wire-shape CVEs.

PASSIVE INVARIANT
    This module NEVER transmits.  No socket imports, no subprocess use, no
    transmit primitives.  scapy is imported lazily inside run_capture() only,
    so every offline tier runs pure-python.  Enforced by an AST guard in the
    self-test, not by grep.

WIRE SCOPE
    RADIUS/UDP auth 1812 + 1645, accounting 1813 + 1646, CoA/Disconnect 3799.
    RadSec (TCP/DTLS 2083) is OBSERVED FOR PRESENCE ONLY (RDW-125); its TLS is
    tlswatch's.  IPv4 and IPv6, including IPv6 behind extension headers.

DIRECTION (D8)
    Request/response is decided by the RADIUS CODE, never by the port.  Ports
    only choose the family (auth / acct / CoA).  aristaguard inferred direction
    from the destination port, so 1812 -> 1812 traffic (proxies, some NAS
    stacks) had every response read as a request: injected Proxy-State was
    missed, response hardening was missed, and known_infra scoped on the NAS.

SEVERITY FLOOR
    CVSSv3 >= 6.5.  Scores are NVD's where NVD publishes one.

Version: 0.1.0-dev
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import re
import struct
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Iterable, Optional

__version__ = "0.1.0-dev"
DISPLAY_NAME = "RADIUS Watch"
MODULE = "radiuswatch"

# ---------------------------------------------------------------------------
# CVE catalog
# ---------------------------------------------------------------------------
#
#   detect            attack | heuristic | exposure | posture | none
#   score_confidence  nvd       - read from the NVD record (vector quoted)
#                     secondary - NVD publishes no score; source named in note


@dataclass(frozen=True)
class CVEEntry:
    cve: str
    cvss: float
    vector: str
    title: str
    detect: str
    score_confidence: str
    codes: tuple[str, ...] = ()
    affected: str = ""
    note: str = ""


CVE_CATALOG: tuple[CVEEntry, ...] = (
    CVEEntry(
        cve="CVE-2024-3596", cvss=9.0, vector="",
        title="RADIUS Response Authenticator forgery (Blast-RADIUS)",
        detect="attack", score_confidence="secondary",
        codes=("RDW-101", "RDW-102", "RDW-110", "RDW-201", "RDW-212",
               "RDW-213", "RDW-214"),
        affected="RADIUS/UDP protocol - every implementation",
        note=(
            "NVD's record carries NO CVSS metric at all (checked Oct 16 2026). "
            "9.0 is the figure vendor advisories publish (e.g. Arista SA-0101). "
            "RADIUS/UDP is cleartext, so both the precondition (no "
            "Message-Authenticator) and the attack (an oversized "
            "attacker-controlled attribute carrying the chosen-prefix collision "
            "block) are on the wire. TWO LEGS: RDW-201 covers attacker->SERVER "
            "(colliding Access-Reject must use Proxy-State); RDW-212/213/214 "
            "cover attacker->NAS, where per blastradius.fail the forged Accept "
            "may carry the block in Vendor-Specific or Reply-Message instead."
        ),
    ),
    CVEEntry(
        cve="CVE-2019-11234", cvss=9.8,
        vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        title="FreeRADIUS EAP-pwd reflection authentication bypass (Dragonblood)",
        detect="attack", score_confidence="nvd", codes=("RDW-217",),
        affected="FreeRADIUS < 3.0.19",
        note=(
            "EAP-pwd Commit travels in cleartext inside EAP-Message. Reflection "
            "is the peer returning the server's own scalar AND element in the "
            "same exchange - an exact equality, no threshold."
        ),
    ),
    CVEEntry(
        cve="CVE-2019-11235", cvss=9.8,
        vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        title="FreeRADIUS EAP-pwd invalid-curve / scalar-range bypass (Dragonblood)",
        detect="attack", score_confidence="nvd", codes=("RDW-218",),
        affected="FreeRADIUS < 3.0.19",
        note=(
            "The fix validates that the received scalar is in range and the "
            "received element is a point on the negotiated curve. Both are pure "
            "arithmetic on cleartext bytes."
        ),
    ),
    CVEEntry(
        cve="CVE-2017-10979", cvss=9.8,
        vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        title="FreeRADIUS v2 rad_coalesce() write overflow (FR-GV-202)",
        detect="attack", score_confidence="nvd", codes=("RDW-215",),
        affected="FreeRADIUS 2.0.0 - 2.2.9",
        note="Trigger per the FreeRADIUS fuzzer advisory: a WiMAX attribute "
             "whose length octet exceeds the data actually present.",
    ),
    CVEEntry(
        cve="CVE-2017-10984", cvss=9.8,
        vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        title="FreeRADIUS v3 data2vp_wimax() write overflow (FR-GV-301)",
        detect="attack", score_confidence="nvd", codes=("RDW-215",),
        affected="FreeRADIUS 3.0.0 - 3.0.14",
        note="Trigger per the advisory: WiMAX attributes with the continuation "
             "flag set but no following data.",
    ),
    CVEEntry(
        cve="CVE-2017-10985", cvss=7.5,
        vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        title="FreeRADIUS v3 decode_concat() infinite loop (FR-GV-302)",
        detect="attack", score_confidence="nvd", codes=("RDW-216",),
        affected="FreeRADIUS 3.0.0 - 3.0.14",
        note=(
            "Published trigger bytes 4f 02, 89 02, 90 02, b4 02. 4f 02 is ALSO "
            "RFC 3579 EAP-Start, a legal NAS message, so a zero-length "
            "EAP-Message is reported only when radius_flag_eap_start is set. "
            "PARTIAL COVERAGE BY DESIGN for that one byte pair."
        ),
    ),
    CVEEntry(
        cve="CVE-2017-10978", cvss=7.5,
        vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        title="FreeRADIUS make_secret() read/write overflow (FR-GV-201)",
        detect="attack", score_confidence="nvd", codes=("RDW-221",),
        affected="FreeRADIUS 2.0.0 - 3.0.14",
        note=(
            "READ case only: an incoming Ascend-Send-Secret / Ascend-Receive-"
            "Secret (encrypt=3) shorter than the 16 octets make_secret() always "
            "reads. The WRITE case is the server's OWN outgoing packet near 4K - "
            "it is generated by the victim, not sent to it, and is not an "
            "attack shape."
        ),
    ),
    CVEEntry(
        cve="CVE-2022-41860", cvss=7.5,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        title="FreeRADIUS EAP-SIM unknown attribute NULL dereference",
        detect="attack", score_confidence="nvd", codes=("RDW-219",),
        affected="FreeRADIUS < 3.0.26 / 3.2.1",
        note=(
            "Fix commit f1cdbb33 rejects unknown NON-SKIPPABLE (0-127) types "
            "and zero attribute length; unknown skippable types are legal and "
            "skipped. 'Unknown' here is judged against the IANA EAP-SIM/AKA "
            "registry, which is a SUPERSET of older FreeRADIUS dictionaries - "
            "the safe direction: a type FreeRADIUS lacks but IANA assigns is a "
            "miss, never a false positive."
        ),
    ),
    CVEEntry(
        cve="CVE-2022-41861", cvss=6.5,
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        title="FreeRADIUS print_abinary() generic-filter overflow",
        detect="attack", score_confidence="nvd", codes=("RDW-220",),
        affected="FreeRADIUS < 3.0.26 / 3.2.1",
        note=(
            "Fix commit 0ec2b39d adds `if (masklen >= sizeof(mask))` for "
            "RAD_FILTER_GENERIC. An abinary value of exactly 32 bytes (the only "
            "size print_abinary decodes), type 0, with generic.len > 6 overruns "
            "the 6-byte mask. len == 6 is in bounds and stays silent even though "
            "the fix's >= also rejects it. PR:L - needs a trusted client or "
            "home server, which is exactly who is on a RADIUS tap."
        ),
    ),
)

# Triaged and REJECTED, with the reason.  Disjoint from CVE_CATALOG.
DEFERRED_CVES: dict[str, str] = {
    "CVE-2017-10980": "FreeRADIUS DHCP decoder (option 82 leak). DHCP on UDP 67, "
                      "not the RADIUS wire.",
    "CVE-2017-10981": "FreeRADIUS DHCP decoder (fr_dhcp_decode leak). Not RADIUS.",
    "CVE-2017-10982": "FreeRADIUS DHCP decoder (option OOB read). Not RADIUS.",
    "CVE-2017-10983": "FreeRADIUS DHCP decoder (option 63). Not RADIUS.",
    "CVE-2017-10986": "FreeRADIUS DHCP decoder (dhcp_attr2vp). Not RADIUS.",
    "CVE-2017-10987": "FreeRADIUS DHCP decoder (sub-option overflow). Not RADIUS.",
    "CVE-2019-17185": "EAP-pwd shared BN_CTX crash. Triggered by CONCURRENT "
                      "ordinary handshakes - no anomalous wire shape exists.",
    "CVE-2019-13456": "EAP-pwd hash-to-curve timing side channel. Leakage is in "
                      "server computation time; nothing anomalous is sent.",
    "CVE-2022-41859": "EAP-pwd compute_password_element() information leak. "
                      "Side channel; ordinary traffic on the wire.",
    "CVE-2019-10143": "Local logrotate privilege escalation. Never on the wire.",
}


# ---------------------------------------------------------------------------
# Finding registry
# ---------------------------------------------------------------------------
#
# 1xx EXPOSURE (scoped by known_infra), 2xx ATTACK (never scoped).
# Digits of the codes migrated from aristaguard are kept 1:1 (AG-101 -> RDW-101).


@dataclass(frozen=True)
class FindingSpec:
    code: str
    name: str
    severity: str
    klass: str
    cves: tuple[str, ...] = ()
    pivot: tuple[str, ...] = ()


FINDINGS: dict[str, FindingSpec] = {f.code: f for f in (
    # ---- EXPOSURE ------------------------------------------------------
    FindingSpec("RDW-101", "RADIUS_CLEARTEXT_OBSERVED", "MEDIUM", "exposure",
                ("CVE-2024-3596",), ("snmpwatch", "tlswatch")),
    FindingSpec("RDW-102", "RADIUS_NO_MESSAGE_AUTHENTICATOR", "HIGH", "exposure",
                ("CVE-2024-3596",)),
    FindingSpec("RDW-110", "RADIUS_RESPONSE_UNAUTHENTICATED", "HIGH", "exposure",
                ("CVE-2024-3596",)),
    FindingSpec("RDW-120", "RADIUS_PAP_OVER_UDP", "HIGH", "exposure"),
    FindingSpec("RDW-121", "RADIUS_CHAP_IN_USE", "MEDIUM", "exposure"),
    FindingSpec("RDW-122", "RADIUS_WEAK_EAP_METHOD", "HIGH", "exposure",
                (), ("macwatch",)),
    FindingSpec("RDW-124", "RADIUS_COA_WITHOUT_MA", "MEDIUM", "exposure"),
    FindingSpec("RDW-125", "RADIUS_RADSEC_PAIR_CLEARTEXT", "HIGH", "exposure",
                ("CVE-2024-3596",), ("tlswatch",)),
    # ---- ATTACK --------------------------------------------------------
    FindingSpec("RDW-201", "RADIUS_FORGERY_ATTEMPT", "CRITICAL", "attack",
                ("CVE-2024-3596",)),
    FindingSpec("RDW-212", "RADIUS_PROXY_STATE_INJECTED", "CRITICAL", "attack",
                ("CVE-2024-3596",)),
    FindingSpec("RDW-213", "RADIUS_REPLY_MESSAGE_MALFORMED", "HIGH", "attack",
                ("CVE-2024-3596",)),
    FindingSpec("RDW-214", "RADIUS_OPAQUE_VENDOR_ATTRIBUTE", "HIGH", "attack",
                ("CVE-2024-3596",)),
    FindingSpec("RDW-215", "RADIUS_WIMAX_VSA_MALFORMED", "CRITICAL", "attack",
                ("CVE-2017-10979", "CVE-2017-10984")),
    FindingSpec("RDW-216", "RADIUS_CONCAT_ATTR_ZERO_LENGTH", "HIGH", "attack",
                ("CVE-2017-10985",)),
    FindingSpec("RDW-217", "EAP_PWD_COMMIT_REFLECTED", "CRITICAL", "attack",
                ("CVE-2019-11234",)),
    FindingSpec("RDW-218", "EAP_PWD_COMMIT_INVALID", "CRITICAL", "attack",
                ("CVE-2019-11235",)),
    FindingSpec("RDW-219", "EAP_SIM_UNKNOWN_ATTRIBUTE", "HIGH", "attack",
                ("CVE-2022-41860",)),
    FindingSpec("RDW-220", "RADIUS_ABINARY_FILTER_OVERFLOW", "HIGH", "attack",
                ("CVE-2022-41861",)),
    FindingSpec("RDW-221", "RADIUS_ASCEND_SECRET_SHORT", "HIGH", "attack",
                ("CVE-2017-10978",)),
)}

# Numbers that will never be live.  Never reused (mikrotikwatch MTK-015).
RETIRED_CODES: dict[str, str] = {
    "RDW-123": ("Proposed in the preflight as an M-A policy-mismatch code. "
                "Folded into RDW-110 as detail request_had_ma (Oct 15 2026): a "
                "separate code would report the same unhardened response twice."),
    "RDW-202": ("Mirrors aristaguard AG-202 (RADIUS_RESPONSE_UNAUTHENTICATED as "
                "ATTACK), reclassified to exposure as AG-110 / RDW-110. Reserved "
                "so an old AG-202 alert can never match a live code."),
}

# aristaguard -> radiuswatch mapping, for the parity run and its retirement.
AG_MIGRATION: dict[str, str] = {
    "AG-101": "RDW-101", "AG-102": "RDW-102", "AG-110": "RDW-110",
    "AG-201": "RDW-201", "AG-212": "RDW-212", "AG-213": "RDW-213",
    "AG-214": "RDW-214",
}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class Config:
    min_cvss: float = 6.5

    # --- ports: they choose the FAMILY only, never the direction (D8) ---
    radius_auth_ports: tuple[int, ...] = (1812, 1645)
    radius_acct_ports: tuple[int, ...] = (1813, 1646)
    radius_coa_ports: tuple[int, ...] = (3799,)
    radsec_ports: tuple[int, ...] = (2083,)

    # --- LIFTED from aristaguard ----------------------------------------
    # STRUCTURAL ANOMALY BOUND, not a published exploit constant. Per-packet
    # TOTAL across Proxy-State attributes (D1/D2).
    radius_proxy_state_total_max: int = 128
    # F2 opacity bands, MEASURED for RADIUS attribute sizes.
    radius_opaque_min_len: int = 64
    radius_opaque_entropy_min: float = 0.88
    radius_opaque_print_run_max: int = 16
    radius_cleartext_print_run_min: int = 24
    # F1 correlation.
    radius_correlate_window_s: float = 30.0
    radius_pending_max: int = 4096
    radius_report_unmatched_proxy_state: bool = False
    # NOTE: there is deliberately NO radius_total_len_max knob. RFC 2865 fixes
    # the legal packet length at 20..4096, so the bound is a property of the
    # wire format, not a policy choice. Do not re-add it.

    # --- new ------------------------------------------------------------
    # Posture codes (RDW-120..125) are reported once per (family, NAS, server)
    # pair per this interval - not once per process, so a restarted dashboard
    # is never blind.
    posture_reemit_s: float = 86400.0
    pair_registry_max: int = 16384
    # EAP exchange table (EAP-pwd Commit correlation via State).
    eap_exchange_window_s: float = 60.0
    eap_exchange_max: int = 4096
    # RFC 3579 EAP-Start is a LEGAL zero-length EAP-Message (4f 02), which is
    # also CVE-2017-10985's first published trigger. Off by default: on a NAS
    # that uses EAP-Start it would be attack-class noise.
    radius_flag_eap_start: bool = False

    # known_infra = RADIUS SERVER addresses. Scopes EXPOSURE only.
    known_infra: tuple[str, ...] = ()

    # --- alert suppression (lifted codes keep it for parity) ------------
    suppress_s: int = 300
    suppress_max: int = 4096

    # --- runtime --------------------------------------------------------
    learn: bool = False
    iface: str = ""
    pcap: str = ""
    timeout: int = 0

    def dump(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def load(cls, blob: dict[str, Any]) -> "Config":
        known = set(cls.__dataclass_fields__)
        kwargs: dict[str, Any] = {}
        for k, v in blob.items():
            if k not in known:
                sys.stderr.write(f"{MODULE}: warning: unknown config key {k!r} ignored\n")
                continue
            cur = getattr(cls, k, None)
            if isinstance(cur, tuple) and isinstance(v, list):
                v = tuple(v)
            kwargs[k] = v
        return cls(**kwargs)


# ---- LIFTED: bounded raw-byte parsers + IPv6 EH walk (D7) ----------------
ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ETH_P_LLDP = 0x88CC
ETH_P_EAPOL = 0x888E

IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_GRE = 47
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_IPIP = 4
IPPROTO_IPV6 = 41
IPPROTO_OSPF = 89

# ---- IPv6 extension headers (D7 / PRIME DIRECTIVE) ------------------------
#
# parse_l3 previously took the IPv6 next-header byte as the L4 protocol with
# no chain walk, so the identical RADIUS packet behind a Hop-by-Hop header
# raised NOTHING while plain IPv6 worked. That blind spot hides traffic from
# EVERY L4 rule in the module - RADIUS, VXLAN, gNMI/gNOI, CVX, SSH, TACACS+ -
# not just the RADIUS ones. Ported from ciscoguard, which measured the same
# failure with tcpdump.
IPV6_EXT_HOPOPT = 0
IPV6_EXT_ROUTING = 43
IPV6_EXT_FRAGMENT = 44
IPV6_EXT_AH = 51
IPV6_EXT_DSTOPTS = 60
IPV6_NO_NEXT_HEADER = 59

IPV6_EXT_HEADERS = frozenset((IPV6_EXT_HOPOPT, IPV6_EXT_ROUTING,
                              IPV6_EXT_FRAGMENT, IPV6_EXT_AH,
                              IPV6_EXT_DSTOPTS))

# Bounded at 8 links. An unbounded walk is a denial-of-service primitive
# against the sensor itself; ciscoguard uses the same bound and documents it
# as a limitation rather than pretending the chain is walked to the end.
IPV6_MAX_EXT_HEADERS = 8

TUNNEL_PROTOS = {
    IPPROTO_GRE: "GRE",
    IPPROTO_IPIP: "IP-in-IP",
    IPPROTO_IPV6: "IPv6-in-IP",
}


def _u16(b: bytes, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def _mac(b: bytes, o: int) -> str:
    return b[o:o + 6].hex(":")


def _ipv4(b: bytes, o: int) -> str:
    return ".".join(str(x) for x in b[o:o + 4])


def _ipv6(b: bytes, o: int) -> str:
    parts = [b[o + i:o + i + 2].hex() for i in range(0, 16, 2)]
    return ":".join(p.lstrip("0") or "0" for p in parts)


@dataclass
class L2:
    dst: str = ""
    src: str = ""
    ethertype: int = 0
    vlan_tags: tuple[int, ...] = ()
    tpids: tuple[int, ...] = ()
    payload: bytes = b""
    truncated: bool = False


def parse_l2(frame: bytes) -> Optional[L2]:
    if not isinstance(frame, (bytes, bytearray)):
        raise TypeError("parse_l2 expects bytes; got %r" % type(frame).__name__)
    frame = bytes(frame)
    if len(frame) < 14:
        return None
    out = L2(dst=_mac(frame, 0), src=_mac(frame, 6))
    off = 12
    tags: list[int] = []
    tpids: list[int] = []
    # Bound the tag walk so a crafted stack cannot spin us.
    for _ in range(8):
        if off + 2 > len(frame):
            out.truncated = True
            return out
        et = _u16(frame, off)
        if et in (ETH_P_8021Q, ETH_P_8021AD):
            if off + 4 > len(frame):
                out.truncated = True
                return out
            tags.append(_u16(frame, off + 2) & 0x0FFF)
            tpids.append(et)
            off += 4
            continue
        out.ethertype = et
        off += 2
        break
    out.vlan_tags = tuple(tags)
    out.tpids = tuple(tpids)
    out.payload = frame[off:]
    return out


@dataclass
class L3:
    version: int = 0
    src: str = ""
    dst: str = ""
    proto: int = 0
    payload: bytes = b""
    total_len: int = 0
    truncated: bool = False
    # IPv6 extension-header chain state. ext_headers records the header types
    # traversed, in order. l4_reachable is False when no L4 header is present
    # to parse - a non-first fragment, a No-Next-Header chain, a malformed
    # length, or a chain longer than IPV6_MAX_EXT_HEADERS.
    ext_headers: tuple[int, ...] = ()
    frag_offset: int = 0
    l4_reachable: bool = True
    ext_chain_truncated: bool = False


def parse_l3(payload: bytes, ethertype: int) -> Optional[L3]:
    if ethertype == ETH_P_IPV4:
        if len(payload) < 20:
            return None
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return None
        tl = _u16(payload, 2)
        body = payload[ihl:tl] if 0 < tl <= len(payload) else payload[ihl:]
        return L3(4, _ipv4(payload, 12), _ipv4(payload, 16), payload[9], body, tl,
                  truncated=(0 < tl > len(payload)))
    if ethertype == ETH_P_IPV6:
        if len(payload) < 40:
            return None
        plen = _u16(payload, 4)
        body = payload[40:40 + plen] if plen else payload[40:]
        proto, l4body, chain, frag_off, reachable, chain_trunc = \
            walk_ipv6_chain(body, payload[6])
        return L3(6, _ipv6(payload, 8), _ipv6(payload, 24), proto, l4body,
                  40 + plen, truncated=(len(payload) < 40 + plen),
                  ext_headers=chain, frag_offset=frag_off,
                  l4_reachable=reachable, ext_chain_truncated=chain_trunc)
    return None


def walk_ipv6_chain(body: bytes, next_header: int) -> tuple:
    """
    Walk an IPv6 extension-header chain to the first non-extension header.

    Returns (proto, payload, ext_headers, frag_offset, l4_reachable,
             chain_truncated).

    Header lengths differ by type and getting this wrong silently mis-parses:
      - Hop-by-Hop / Routing / Dest-Opts: Hdr Ext Len is in 8-octet units NOT
        counting the first 8, so the real length is (len + 1) * 8.
      - Authentication Header: RFC 4302 makes its length field 4-octet units
        MINUS 2, so the real length is (len + 2) * 4. Using the 8-octet rule
        here walks off the end of the header.
      - Fragment: always exactly 8 bytes.

    A NON-FIRST fragment carries no L4 header at all, so l4_reachable is
    False - reporting a protocol there would invite every L4 rule to parse
    payload bytes as a header.
    """
    chain: list[int] = []
    off = 0
    nh = next_header
    for _ in range(IPV6_MAX_EXT_HEADERS):
        if nh == IPV6_NO_NEXT_HEADER:
            return (nh, b"", tuple(chain), 0, False, False)
        if nh not in IPV6_EXT_HEADERS:
            return (nh, body[off:], tuple(chain), 0, True, False)
        if off + 2 > len(body):
            return (nh, b"", tuple(chain), 0, False, True)
        chain.append(nh)
        nxt = body[off]
        if nh == IPV6_EXT_FRAGMENT:
            if off + 8 > len(body):
                return (nh, b"", tuple(chain), 0, False, True)
            frag_off = _u16(body, off + 2) >> 3
            if frag_off != 0:
                return (nxt, b"", tuple(chain), frag_off, False, False)
            hlen = 8
        elif nh == IPV6_EXT_AH:
            hlen = (body[off + 1] + 2) * 4
        else:
            hlen = (body[off + 1] + 1) * 8
        if hlen <= 0 or off + hlen > len(body):
            return (nh, b"", tuple(chain), 0, False, True)
        off += hlen
        nh = nxt
    # Chain longer than the bound. Reporting l4_reachable=True here would
    # hand a rule bytes from the middle of an extension header.
    return (nh, b"", tuple(chain), 0, False, True)


@dataclass
class L4:
    sport: int = 0
    dport: int = 0
    payload: bytes = b""


def parse_l4(l3: L3) -> Optional[L4]:
    # No L4 header is present behind a non-first fragment, a No-Next chain, a
    # malformed extension length, or a chain past the bound.
    if not l3.l4_reachable:
        return None
    p = l3.payload
    if l3.proto == IPPROTO_UDP:
        if len(p) < 8:
            return None
        ln = _u16(p, 4)
        body = p[8:ln] if 8 <= ln <= len(p) else p[8:]
        return L4(_u16(p, 0), _u16(p, 2), body)
    if l3.proto == IPPROTO_TCP:
        if len(p) < 20:
            return None
        off = ((p[12] >> 4) & 0x0F) * 4
        if off < 20 or len(p) < off:
            return None
        return L4(_u16(p, 0), _u16(p, 2), p[off:])
    return None



# ---- RADIUS ---------------------------------------------------------------
#
# RFC 2865.  Cleartext UDP, which is precisely why BlastRADIUS is the
# strongest signature in this module: the vulnerable precondition and the
# attack payload are both directly readable.

RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCESS_CHALLENGE = 11

RADIUS_CODE_NAMES = {
    1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
    4: "Accounting-Request", 5: "Accounting-Response",
    11: "Access-Challenge",
}

RADIUS_ATTR_USER_NAME = 1
RADIUS_ATTR_USER_PASSWORD = 2
RADIUS_ATTR_PROXY_STATE = 33
RADIUS_ATTR_MESSAGE_AUTHENTICATOR = 80

RADIUS_RESPONSE_CODES = {RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT,
                         RADIUS_ACCESS_CHALLENGE}

# Codes whose mitigation requires Message-Authenticator as the FIRST
# attribute, not merely present. Access-Challenge is presence-only.
RADIUS_MA_FIRST_CODES = {RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT}

# 4096-byte maximum packet, 20-byte header, 2-byte minimum attribute.
RADIUS_MAX_ATTRS = (4096 - 20) // 2


RADIUS_ATTR_REPLY_MESSAGE = 18
RADIUS_ATTR_VENDOR_SPECIFIC = 26


def _norm_entropy(b: bytes) -> float:
    """
    Shannon entropy normalised against the MAXIMUM ACHIEVABLE for this length.

    arubaguard's lesson: raw entropy thresholds are wrong for short buffers -
    64 random bytes can only reach 6.0 bits, so a fixed "7.5 bits" test never
    fires on anything short. Dividing by log2(min(256, n)) makes the number
    comparable across lengths.
    """
    if not b:
        return 0.0
    counts: dict[int, int] = {}
    for x in b:
        counts[x] = counts.get(x, 0) + 1
    n = len(b)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    hmax = math.log2(min(256, n))
    return h / hmax if hmax else 0.0


def _longest_printable_run(b: bytes) -> int:
    best = cur = 0
    for x in b:
        if 32 <= x <= 126 or x in (9, 10, 13):
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def classify_opacity(b: bytes, cfg: "Config") -> str:
    """
    Classify an attribute value as "opaque", "cleartext" or "unknown".

    MEASURED for RADIUS attribute sizes (values cap at 253 bytes), NOT reused
    from arubaguard's numbers - those were measured for 32-1024 byte PAPI
    datagrams and do not transfer. 400 random samples per size 32..247 against
    real vendor AV-pair strings (Cisco-AVPair, Aruba-User-Role, Filter-Id,
    Tunnel-Private-Group-Id, Class):

        normalised entropy   cleartext 0.717-0.902   random 0.881-0.952
        longest printable    cleartext 31-60         random 3-13

    ENTROPY ALONE DOES NOT SEPARATE THEM - the ranges overlap at 0.881-0.902.
    The printable run is the discriminator, with entropy as corroboration.
    The 17..23 gap between the two run bands is deliberately left as an
    "unknown" band that emits NOTHING, exactly as arubaguard does: a middle
    band that guesses is worse than one that abstains.
    """
    if len(b) < cfg.radius_opaque_min_len:
        return "unknown"
    run = _longest_printable_run(b)
    if run >= cfg.radius_cleartext_print_run_min:
        return "cleartext"
    if run <= cfg.radius_opaque_print_run_max \
            and _norm_entropy(b) >= cfg.radius_opaque_entropy_min:
        return "opaque"
    return "unknown"



# ---- radiuswatch attribute constants --------------------------------------

RADIUS_ATTR_CHAP_PASSWORD = 3
RADIUS_ATTR_STATE = 24
RADIUS_ATTR_EAP_MESSAGE = 79

RADIUS_ACCOUNTING_RESPONSE = 5
RADIUS_DISCONNECT_REQUEST = 40
RADIUS_DISCONNECT_ACK = 41
RADIUS_DISCONNECT_NAK = 42
RADIUS_COA_REQUEST = 43
RADIUS_COA_ACK = 44
RADIUS_COA_NAK = 45

RADIUS_CODE_NAMES.update({
    40: "Disconnect-Request", 41: "Disconnect-ACK", 42: "Disconnect-NAK",
    43: "CoA-Request", 44: "CoA-ACK", 45: "CoA-NAK",
})

# D8. Direction is a property of the CODE. A code in neither set is not
# judged for direction at all - guessing is what produced D8.
RADIUS_REQUEST_CODES = frozenset({RADIUS_ACCESS_REQUEST,
                                  RADIUS_ACCOUNTING_REQUEST,
                                  RADIUS_DISCONNECT_REQUEST,
                                  RADIUS_COA_REQUEST})
RADIUS_REPLY_CODES = frozenset({RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT,
                                RADIUS_ACCOUNTING_RESPONSE,
                                RADIUS_ACCESS_CHALLENGE,
                                RADIUS_DISCONNECT_ACK, RADIUS_DISCONNECT_NAK,
                                RADIUS_COA_ACK, RADIUS_COA_NAK})
# CoA / Disconnect requests are SENT BY the RADIUS server (or a Dynamic
# Authorization Client) TO the NAS - the server is the requester there.
RADIUS_SERVER_ORIGINATED_REQUESTS = frozenset({RADIUS_DISCONNECT_REQUEST,
                                               RADIUS_COA_REQUEST})

# CVE-2017-10985 (FR-GV-302). The advisory's published trigger bytes are
# 4f 02 / 89 02 / 90 02 / b4 02 -> 79, 137, 144, 180. 138 (PKM-CA-Cert) is
# marked `concat` in the shipped FreeRADIUS 3.2 dictionary alongside 137, so
# it is included: the advisory's examples are "e.g.", the dictionary flag is
# the actual condition.
RADIUS_CONCAT_TYPES = frozenset({79, 137, 138, 144, 180})

VENDOR_ASCEND = 529
VENDOR_LUCENT = 4846          # FreeRADIUS dictionary: format=2,1
VENDOR_ALCATEL_SR = 6527
VENDOR_WIMAX = 24757          # type(1) length(1) continuation(1) value

ASCEND_SECRET_TYPES = frozenset({214, 215})   # Send-Secret / Receive-Secret
ASCEND_SECRET_LEN = 16                        # make_secret() always reads 16
# abinary-typed attributes, per the shipped FreeRADIUS dictionaries.
ABINARY_VSAS = frozenset({(VENDOR_ASCEND, 242), (VENDOR_ASCEND, 243),
                          (VENDOR_LUCENT, 242), (VENDOR_LUCENT, 243),
                          (VENDOR_ALCATEL_SR, 159)})
ABINARY_FILTER_SIZE = 32      # sizeof(ascend_filter_t); other sizes print as hex
ABINARY_FILTER_GENERIC = 0
ABINARY_MAX_FILTER_LEN = 6    # RAD_MAX_FILTER_LEN, the generic mask size
WIMAX_CONTINUATION = 0x80


@dataclass
class VsaFacts:
    wimax_bad: list = field(default_factory=list)
    abinary_bad: list = field(default_factory=list)
    ascend_short: list = field(default_factory=list)
    wimax_cont: Optional[int] = None


def wimax_first_type(value: bytes) -> Optional[int]:
    if len(value) >= 5 and int.from_bytes(value[:4], "big") == VENDOR_WIMAX:
        return value[4]
    return None


def _abinary_overflow(val: bytes) -> Optional[int]:
    """generic.len when it overruns the 6-byte mask, else None.

    ascend_filter_t: type(0) forward(1) direction(2) fill(3) then the union;
    ascend_generic_filter_t opens offset(4-5) len(6-7), network order.
    print_abinary() decodes ONLY values of exactly sizeof(ascend_filter_t).
    """
    if len(val) != ABINARY_FILTER_SIZE or val[0] != ABINARY_FILTER_GENERIC:
        return None
    glen = _u16(val, 6)
    return glen if glen > ABINARY_MAX_FILTER_LEN else None


def inspect_vsa(value: bytes) -> VsaFacts:
    """Walk ONE Vendor-Specific value for the vendor-format CVE shapes.

    Bounded by the value length; never raises; retains nothing.
    """
    out = VsaFacts()
    if len(value) < 4:
        return out
    vendor = int.from_bytes(value[:4], "big")
    data = value[4:]
    if vendor == VENDOR_WIMAX:
        off = 0
        while off < len(data):
            if off + 3 > len(data):
                out.wimax_bad.append(("inner_length_overflow", data[off]))
                break
            wtype, wlen, flags = data[off], data[off + 1], data[off + 2]
            if wlen < 3 or off + wlen > len(data):
                # FR-GV-202: the length octet exceeds the data present.
                out.wimax_bad.append(("inner_length_overflow", wtype))
                break
            last = off + wlen == len(data)
            if flags & WIMAX_CONTINUATION:
                if wlen == 3:
                    out.wimax_bad.append(("continuation_empty_value", wtype))
                elif last:
                    out.wimax_cont = wtype
            off += wlen
        return out
    if vendor == VENDOR_LUCENT:
        tlen, hdr = 2, 3
    elif vendor in (VENDOR_ASCEND, VENDOR_ALCATEL_SR):
        tlen, hdr = 1, 2
    else:
        return out
    off = 0
    while off + hdr <= len(data):
        vtype = int.from_bytes(data[off:off + tlen], "big")
        vlen = data[off + tlen]
        if vlen < hdr or off + vlen > len(data):
            break
        val = data[off + hdr:off + vlen]
        if vendor == VENDOR_ASCEND and vtype in ASCEND_SECRET_TYPES \
                and len(val) < ASCEND_SECRET_LEN:
            out.ascend_short.append((vtype, len(val)))
        if (vendor, vtype) in ABINARY_VSAS:
            glen = _abinary_overflow(val)
            if glen is not None:
                out.abinary_bad.append((vendor, vtype, glen))
        off += vlen
    return out


# ---- EAP ------------------------------------------------------------------

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_TYPE_NAK = 3
EAP_TYPE_MD5 = 4
EAP_TYPE_LEAP = 17
EAP_TYPE_SIM = 18
EAP_TYPE_AKA = 23
EAP_TYPE_AKA_PRIME = 50
EAP_TYPE_PWD = 52

WEAK_EAP_METHODS = {EAP_TYPE_MD5: "EAP-MD5", EAP_TYPE_LEAP: "LEAP"}
SIM_FAMILY = frozenset({EAP_TYPE_SIM, EAP_TYPE_AKA, EAP_TYPE_AKA_PRIME})


@dataclass
class EapPacket:
    code: int = 0
    ident: int = 0
    length: int = 0
    etype: int = 0
    data: bytes = b""


def parse_eap(b: bytes) -> Optional[EapPacket]:
    if len(b) < 4:
        return None
    length = _u16(b, 2)
    if length < 4 or length > len(b):
        return None
    p = EapPacket(code=b[0], ident=b[1], length=length)
    if p.code in (EAP_REQUEST, EAP_RESPONSE):
        if length < 5:
            return None
        p.etype = b[4]
        p.data = b[5:length]
    return p


# ---- EAP-pwd (RFC 5931) ---------------------------------------------------

PWD_EXCH_ID = 1
PWD_EXCH_COMMIT = 2
PWD_EXCH_CONFIRM = 3
PWD_FLAG_L = 0x80
PWD_FLAG_M = 0x40

# NIST curves, a = -3. Values from SEC 2 / FIPS 186-4; the self-test checks
# each generator lies on its curve and the cross-check tier compares the
# validity verdict with the `cryptography` library's own point validation.
EC_GROUPS: dict[int, dict[str, int]] = {
    19: dict(  # P-256
        plen=32,
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
    20: dict(  # P-384
        plen=48,
        p=int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
              "ffffffff0000000000000000ffffffff", 16),
        b=int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
              "c656398d8a2ed19d2a85c8edd3ec2aef", 16),
        n=int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
              "581a0db248b0a77aecec196accc52973", 16),
        gx=int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
               "5502f25dbf55296c3a545e3872760ab7", 16),
        gy=int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
               "0a60b1ce1d7e819d7a431d7c90ea0e5f", 16)),
    21: dict(  # P-521
        plen=66,
        p=(1 << 521) - 1,
        b=int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1"
              "09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50"
              "3f00", 16),
        n=int("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
              "fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138"
              "6409", 16),
        gx=int("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d"
               "3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5"
               "bd66", 16),
        gy=int("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e"
               "662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1"
               "6650", 16)),
}
# Commit = element (x || y) + scalar; each field padded to the group size.
# The three ECC payload lengths are DISTINCT, so the group is recovered from
# the Commit itself without depending on having seen the PWD-ID exchange.
PWD_COMMIT_LEN_TO_GROUP = {g["plen"] * 3: gid for gid, g in EC_GROUPS.items()}


def ec_on_curve(gid: int, x: int, y: int) -> bool:
    g = EC_GROUPS[gid]
    p = g["p"]
    if not (0 <= x < p and 0 <= y < p):
        return False
    return (y * y - (x * x * x - 3 * x + g["b"])) % p == 0


@dataclass
class PwdMessage:
    exch: int = 0
    fragmented: bool = False
    payload: bytes = b""


def parse_eap_pwd(data: bytes) -> Optional[PwdMessage]:
    """data = the EAP Type-Data after the type byte (RFC 5931 s3.1)."""
    if not data:
        return None
    flags = data[0]
    m = PwdMessage(exch=flags & 0x3F)
    if flags & PWD_FLAG_L:
        if len(data) < 3:
            return None
        total = _u16(data, 1)
        m.payload = data[3:]
        m.fragmented = bool(flags & PWD_FLAG_M) or total != len(m.payload)
    else:
        m.payload = data[1:]
        m.fragmented = bool(flags & PWD_FLAG_M)
    return m


@dataclass
class PwdCommit:
    group: int
    x: int
    y: int
    scalar: int
    digest: str  # of element||scalar, for equality without retaining bytes


def parse_pwd_commit(payload: bytes) -> Optional[PwdCommit]:
    gid = PWD_COMMIT_LEN_TO_GROUP.get(len(payload))
    if gid is None:
        return None
    pl = EC_GROUPS[gid]["plen"]
    return PwdCommit(
        group=gid,
        x=int.from_bytes(payload[:pl], "big"),
        y=int.from_bytes(payload[pl:2 * pl], "big"),
        scalar=int.from_bytes(payload[2 * pl:], "big"),
        digest=hashlib.blake2b(payload, digest_size=16).hexdigest())


def pwd_commit_problems(c: PwdCommit) -> list[str]:
    """CVE-2019-11235: what the FreeRADIUS 3.0.19 fix checks."""
    n = EC_GROUPS[c.group]["n"]
    out: list[str] = []
    if not (1 < c.scalar < n):
        out.append("scalar_out_of_range")
    if not ec_on_curve(c.group, c.x, c.y):
        out.append("element_not_on_curve")
    return out


# ---- EAP-SIM / AKA / AKA' attributes (RFC 4186 / 4187 / 9048) -------------
#
# NON-SKIPPABLE (0-127) assignments, transcribed from the IANA
# "EAP-AKA and EAP-SIM Parameters" registry (fetched Oct 16 2026). The
# self-test pins the exact set so an edit cannot slip in unnoticed.
SIM_NON_SKIPPABLE: dict[int, str] = {
    1: "AT_RAND", 2: "AT_AUTN", 3: "AT_RES", 4: "AT_AUTS", 6: "AT_PADDING",
    7: "AT_NONCE_MT", 10: "AT_PERMANENT_ID_REQ", 11: "AT_MAC",
    12: "AT_NOTIFICATION", 13: "AT_ANY_ID_REQ", 14: "AT_IDENTITY",
    15: "AT_VERSION_LIST", 16: "AT_SELECTED_VERSION", 17: "AT_FULLAUTH_ID_REQ",
    19: "AT_COUNTER", 20: "AT_COUNTER_TOO_SMALL", 21: "AT_NONCE_S",
    22: "AT_CLIENT_ERROR_CODE", 23: "AT_KDF_INPUT", 24: "AT_KDF",
}
SIM_SKIPPABLE_MIN = 128


def sim_attribute_problems(data: bytes) -> list[tuple[str, int]]:
    """data = Type-Data after the EAP type: subtype(1) reserved(2) attrs.

    Reports what fix commit f1cdbb33 rejects that the old code crashed on:
    an unknown NON-SKIPPABLE type, and an attribute whose length octet is 0.
    Unknown SKIPPABLE types are legal and silent.
    """
    out: list[tuple[str, int]] = []
    off = 3
    for _ in range(256):
        if off + 2 > len(data):
            break
        atype, units = data[off], data[off + 1]
        if units == 0:
            out.append(("zero_length", atype))
            break                       # the old loop could not advance
        if atype < SIM_SKIPPABLE_MIN and atype not in SIM_NON_SKIPPABLE:
            out.append(("unknown_non_skippable", atype))
        off += units * 4
    return out


@dataclass
class RadiusPacket:
    code: int = 0
    identifier: int = 0
    length: int = 0
    authenticator: bytes = b""
    # (type, length) only.  Attribute VALUES are deliberately not retained -
    # this module never logs credential material.
    attrs: tuple[tuple[int, int], ...] = ()
    max_attr_type: int = 0
    max_attr_len: int = 0
    # D1/D2. RDW-201 keys on Proxy-State ONLY, and on the per-packet TOTAL.
    #
    # D1: the old rule tested the largest attribute of ANY type against a
    # per-attribute bound. EAP-TLS and PEAP routinely fragment EAP-Message
    # (type 79) into 255-byte attributes, so a perfectly normal 802.1X
    # exchange raised RDW-201 at CRITICAL - on the request AND on the server's
    # own Access-Challenge.
    #
    # D2: a per-attribute bound is also trivially evaded. A collision block
    # split across four Proxy-State attributes of 100 bytes each stayed under
    # the 128-byte threshold and raised nothing. The chosen-prefix block must
    # arrive in full, so the per-packet SUM is the quantity that matters. A
    # legitimate proxy adds one small Proxy-State per hop.
    proxy_state_total: int = 0
    proxy_state_count: int = 0
    # F1. Digests of the Proxy-State VALUES, never the values themselves.
    # Proxy-State must be echoed back byte-for-byte by a conforming server,
    # so comparing digests detects injection or substitution without this
    # module ever retaining attribute content.
    proxy_state_digests: tuple[str, ...] = ()
    # F2. Derived statistics only - the bytes are analysed during the walk
    # and discarded. Nothing here can reconstruct an attribute value.
    reply_message_invalid_utf8: int = 0
    reply_message_count: int = 0
    opaque_vendor_attrs: tuple[tuple[int, float, int], ...] = ()
    cleartext_vendor_attrs: int = 0
    unknown_vendor_attrs: int = 0
    malformed: bool = False
    # ---- radiuswatch additions. Booleans, digests and lengths only - the
    # one exception is eap_message, the concatenated EAP-Message payload,
    # which is needed to decode the EAP method. It lives as long as the
    # packet object and never enters a finding.
    has_user_password: bool = False
    has_chap_password: bool = False
    state_digest: str = ""
    eap_message: bytes = b""
    eap_message_count: int = 0
    # RDW-216: attribute type of every zero-length concat attribute.
    zero_len_concat: tuple[int, ...] = ()
    # RDW-215: (case, wimax_type) for each malformed WiMAX VSA.
    wimax_malformed: tuple[tuple[str, int], ...] = ()
    # RDW-220: (vendor, vtype, generic_len) for each overflowing filter.
    abinary_overflow: tuple[tuple[int, int, int], ...] = ()
    # RDW-221: (vtype, value_len) for each short Ascend secret.
    ascend_secret_short: tuple[tuple[int, int], ...] = ()

    @property
    def has_message_authenticator(self) -> bool:
        return any(t == RADIUS_ATTR_MESSAGE_AUTHENTICATOR for t, _ in self.attrs)

    @property
    def ma_is_first(self) -> bool:
        """D3. Mitigation requires M-A as the FIRST attribute in a response."""
        return bool(self.attrs) and \
            self.attrs[0][0] == RADIUS_ATTR_MESSAGE_AUTHENTICATOR

    @property
    def code_name(self) -> str:
        return RADIUS_CODE_NAMES.get(self.code, f"code-{self.code}")


def parse_radius(payload: bytes,
                 cfg: Optional["Config"] = None) -> Optional[RadiusPacket]:
    """
    cfg is optional so the parser stays usable standalone; without it the
    Vendor-Specific opacity classification is skipped (it is the only part
    that needs tunable bounds). Reply-Message UTF-8 validity and Proxy-State
    digests are computed either way, since neither needs a threshold.
    """
    if len(payload) < 20:
        return None
    pkt = RadiusPacket(code=payload[0], identifier=payload[1],
                       length=_u16(payload, 2), authenticator=payload[4:20])
    if pkt.length < 20 or pkt.length > 4096:
        pkt.malformed = True
    body = payload[20:pkt.length] if 20 <= pkt.length <= len(payload) else payload[20:]
    attrs: list[tuple[int, int]] = []
    ps_digests: list[str] = []
    opaque: list[tuple[int, float, int]] = []
    eap_parts: list[bytes] = []
    zero_concat: list[int] = []
    wimax_bad: list[tuple[str, int]] = []
    abinary_bad: list[tuple[int, int, int]] = []
    ascend_short: list[tuple[int, int]] = []
    # WiMAX continuation: the WiMAX type whose C bit was set on the PREVIOUS
    # attribute, or None. The next RADIUS attribute must be a WiMAX VSA of the
    # same type, otherwise the continuation has "no following data".
    wimax_cont: Optional[int] = None
    off = 0
    # D6. The old cap of 256 was below what a legal packet can carry: RFC 2865
    # allows 4096 bytes and an attribute is at least 2, so 2038 attributes fit
    # after the 20-byte header. A legitimate packet with 300 small attributes
    # before Message-Authenticator stopped the walk early, the M-A was never
    # seen, and RDW-102 fired falsely.
    for _ in range(RADIUS_MAX_ATTRS):
        if off + 2 > len(body):
            break
        atype, alen = body[off], body[off + 1]
        if alen < 2:
            pkt.malformed = True
            break
        if off + alen > len(body):
            pkt.malformed = True
            break
        attrs.append((atype, alen))
        if alen > pkt.max_attr_len:
            pkt.max_attr_len = alen
            pkt.max_attr_type = atype
        value = body[off + 2:off + alen]
        # ---- radiuswatch additions (independent of the lifted chain below)
        if wimax_cont is not None:
            if not (atype == RADIUS_ATTR_VENDOR_SPECIFIC
                    and wimax_first_type(value) == wimax_cont):
                wimax_bad.append(("continuation_without_next", wimax_cont))
            wimax_cont = None
        if alen == 2 and atype in RADIUS_CONCAT_TYPES:
            zero_concat.append(atype)
        if atype == RADIUS_ATTR_USER_PASSWORD:
            pkt.has_user_password = True
        elif atype == RADIUS_ATTR_CHAP_PASSWORD:
            pkt.has_chap_password = True
        elif atype == RADIUS_ATTR_STATE:
            pkt.state_digest = hashlib.blake2b(value, digest_size=8).hexdigest()
        elif atype == RADIUS_ATTR_EAP_MESSAGE:
            eap_parts.append(value)
        elif atype == RADIUS_ATTR_VENDOR_SPECIFIC:
            facts = inspect_vsa(value)
            wimax_bad.extend(facts.wimax_bad)
            abinary_bad.extend(facts.abinary_bad)
            ascend_short.extend(facts.ascend_short)
            wimax_cont = facts.wimax_cont
        # ---- lifted chain
        if atype == RADIUS_ATTR_PROXY_STATE:
            pkt.proxy_state_total += alen
            pkt.proxy_state_count += 1
            # Digest only. See the field comment above.
            ps_digests.append(
                hashlib.blake2b(value, digest_size=8).hexdigest())
        elif atype == RADIUS_ATTR_REPLY_MESSAGE:
            pkt.reply_message_count += 1
            # RFC 2865 defines Reply-Message as displayable text, so invalid
            # UTF-8 is a DETERMINISTIC structural anomaly - no threshold and
            # no entropy estimate needed.
            try:
                value.decode("utf-8")
            except UnicodeDecodeError:
                pkt.reply_message_invalid_utf8 += 1
        elif atype == RADIUS_ATTR_VENDOR_SPECIFIC and cfg is not None:
            # Classify the VENDOR PAYLOAD, not the whole attribute body.
            # RFC 2865 s5.26 puts a 4-byte vendor-id plus a 2-byte
            # vendor-type/vendor-length sub-header in front of it. Those six
            # bytes are structured protocol fields, not attacker-controlled
            # content, and including them dilutes the entropy of short
            # payloads in the wrong direction. The scapy cross-check tier is
            # what surfaced the difference: scapy's RadiusAttr_Vendor_Specific
            # exposes .value as the inner payload only, and its boundary is
            # the correct one to measure.
            vendor_payload = value[6:] if len(value) >= 8 else value
            verdict = classify_opacity(vendor_payload, cfg)
            if verdict == "opaque":
                opaque.append((alen, round(_norm_entropy(vendor_payload), 3),
                               _longest_printable_run(vendor_payload)))
            elif verdict == "cleartext":
                pkt.cleartext_vendor_attrs += 1
            else:
                pkt.unknown_vendor_attrs += 1
        off += alen
    if wimax_cont is not None:
        # C bit set on the LAST attribute of the packet: nothing follows.
        wimax_bad.append(("continuation_without_next", wimax_cont))
    pkt.attrs = tuple(attrs)
    pkt.proxy_state_digests = tuple(ps_digests)
    pkt.opaque_vendor_attrs = tuple(opaque)
    pkt.eap_message = b"".join(eap_parts)
    pkt.eap_message_count = len(eap_parts)
    pkt.zero_len_concat = tuple(zero_concat)
    pkt.wimax_malformed = tuple(wimax_bad)
    pkt.abinary_overflow = tuple(abinary_bad)
    pkt.ascend_secret_short = tuple(ascend_short)
    return pkt



# ---- LIFTED: findings + suppression ---------------------------------------
@dataclass
class Finding:
    code: str
    name: str
    severity: str
    klass: str
    ts: float
    detail: dict[str, Any] = field(default_factory=dict)
    cves: tuple[str, ...] = ()
    pivot: tuple[str, ...] = ()

    def to_json(self) -> str:
        return json.dumps({
            "module": "radiuswatch",
            "version": __version__,
            "code": self.code,
            "finding": self.name,
            "severity": self.severity,
            "class": self.klass,
            "ts": round(self.ts, 6),
            "cves": list(self.cves),
            "pivot": list(self.pivot),
            "detail": self.detail,
        }, sort_keys=True)


class Suppressor:
    """
    Throttles ALERTS, never DETECTION.  Fails OPEN - an evicted key just
    alerts again, which is noisy rather than silent.  NEVER auto-learns:
    a suppressed key is not added to any allow-list, because that would be a
    back door for an attacker to teach the sensor to ignore them.
    """

    def __init__(self, window_s: int, cap: int) -> None:
        self.window_s = window_s
        self.cap = cap
        self._seen: dict[tuple, tuple[float, int]] = {}

    def should_alert(self, key: tuple, now: float) -> tuple[bool, int]:
        first, count = self._seen.get(key, (0.0, 0))
        if first and now - first < self.window_s:
            self._seen[key] = (first, count + 1)
            return False, count + 1
        if len(self._seen) >= self.cap:
            oldest = min(self._seen, key=lambda k: self._seen[k][0])
            del self._seen[oldest]
        self._seen[key] = (now, 1)
        return True, count



# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class RadiusEngine:
    def __init__(self, cfg: Optional[Config] = None,
                 emit: Optional[Callable[[Finding], None]] = None) -> None:
        self.cfg = cfg or Config()
        self.findings: list[Finding] = []
        self._emit = emit
        self.sup = Suppressor(self.cfg.suppress_s, self.cfg.suppress_max)
        # F1 (lifted). key -> (ts, proxy_state_digests, authenticator_hex,
        # request_had_ma). Bounded and time-windowed; eviction fails SILENT.
        self.radius_pending: dict[tuple, tuple] = {}
        # Posture registry: (code, family, nas, server) -> last emit ts.
        self.pairs: dict[tuple, float] = {}
        # RDW-125: pairs seen on RadSec / on cleartext RADIUS. Bounded by
        # pair_registry_max with the same oldest-first eviction.
        self.radsec_pairs: dict[tuple, float] = {}
        self.cleartext_pairs: dict[tuple, float] = {}
        # EAP-pwd: (family, nas, server, state_digest) -> (ts, commit_digest,
        # group). Holds digests only.
        self.eap_exchanges: dict[tuple, tuple[float, str, int]] = {}
        self.stats: dict[str, int] = {
            "radius_packets": 0, "radius_unknown_code": 0,
            "radsec_segments": 0, "eap_pwd_commits_judged": 0,
            "eap_pwd_unjudged_fragmented": 0, "eap_pwd_unjudged_group": 0,
            "eap_pwd_reflection_unlinked": 0,
        }

    # -- emission (LIFTED) -----------------------------------------------
    def add(self, code: str, ts: float, detail: dict[str, Any],
            suppress_key: Optional[tuple] = None) -> Optional[Finding]:
        spec = FINDINGS[code]
        if suppress_key is not None:
            ok, count = self.sup.should_alert((code,) + suppress_key, ts)
            if not ok:
                return None
            if count:
                detail = dict(detail, suppressed_since_last=count)
        f = Finding(code=spec.code, name=spec.name, severity=spec.severity,
                    klass=spec.klass, ts=ts, detail=detail,
                    cves=spec.cves, pivot=spec.pivot)
        self.findings.append(f)
        if self._emit and not self.cfg.learn:
            self._emit(f)
        return f

    def _exposure_scoped(self, addr: Optional[str]) -> bool:
        """known_infra scopes EXPOSURE findings only. Never ATTACK."""
        if not self.cfg.known_infra:
            return True
        if addr is None:
            return True
        return addr in self.cfg.known_infra

    @staticmethod
    def _bounded_put(table: dict, key: tuple, value: Any, cap: int) -> None:
        table[key] = value
        while len(table) > cap:
            del table[min(table, key=lambda k: table[k] if not isinstance(
                table[k], tuple) else table[k][0])]

    def _posture(self, code: str, ts: float, fam: str, nas: str,
                 server: str, detail: dict[str, Any]) -> None:
        """Once per (family, NAS, server) pair per posture_reemit_s."""
        if not self._exposure_scoped(server):
            return
        key = (code, fam, nas, server)
        last = self.pairs.get(key)
        if last is not None and ts - last < self.cfg.posture_reemit_s:
            return
        self._bounded_put(self.pairs, key, ts, self.cfg.pair_registry_max)
        self.add(code, ts, dict(detail, family=fam, nas=nas, server=server))

    # -- top level -------------------------------------------------------
    def handle_frame(self, frame: bytes, ts: Optional[float] = None) -> None:
        ts = time.time() if ts is None else ts
        l2 = parse_l2(frame)
        if l2 is None:
            return
        l3 = parse_l3(l2.payload, l2.ethertype)
        if l3 is None:
            return
        l4 = parse_l4(l3)
        if l4 is None:
            return
        c = self.cfg
        if l4.dport in c.radsec_ports or l4.sport in c.radsec_ports:
            if l3.proto in (IPPROTO_TCP, IPPROTO_UDP):
                self.rule_radsec_presence(l3, l4, ts)
            return
        if l3.proto != IPPROTO_UDP:
            return
        for fam, ports in (("auth", c.radius_auth_ports),
                           ("acct", c.radius_acct_ports),
                           ("coa", c.radius_coa_ports)):
            if l4.dport in ports or l4.sport in ports:
                self.rule_radius(l3, l4, ts, fam)
                return

    # -- roles (D8) ------------------------------------------------------
    def _roles(self, l3: L3, l4: L4, code: int,
               family: str) -> tuple[Optional[bool], str, str]:
        """(is_request, nas, server) from the CODE.

        is_request is None for a code in neither set; then the server is the
        endpoint on the family port, used for RDW-101 scoping only.
        """
        if code in RADIUS_REQUEST_CODES:
            if code in RADIUS_SERVER_ORIGINATED_REQUESTS:
                return True, l3.dst, l3.src
            return True, l3.src, l3.dst
        if code in RADIUS_REPLY_CODES:
            if code in (RADIUS_DISCONNECT_ACK, RADIUS_DISCONNECT_NAK,
                        RADIUS_COA_ACK, RADIUS_COA_NAK):
                return False, l3.src, l3.dst
            return False, l3.dst, l3.src
        ports = {"auth": self.cfg.radius_auth_ports,
                 "acct": self.cfg.radius_acct_ports,
                 "coa": self.cfg.radius_coa_ports}[family]
        if l4.dport in ports:
            return None, l3.src, l3.dst
        return None, l3.dst, l3.src

    @staticmethod
    def _fam(l3: L3) -> str:
        return "ipv6" if l3.version == 6 else "ipv4"

    # -- RADIUS ----------------------------------------------------------
    def rule_radius(self, l3: L3, l4: L4, ts: float, family: str) -> None:
        pkt = parse_radius(l4.payload, self.cfg)
        if pkt is None:
            return
        self.stats["radius_packets"] += 1
        is_request, nas, server = self._roles(l3, l4, pkt.code, family)
        if is_request is None:
            self.stats["radius_unknown_code"] += 1
        fam = self._fam(l3)

        # LIFTED RDW-101, suppression key unchanged for the parity run.
        if self._exposure_scoped(server):
            self.add("RDW-101", ts, {
                "src": l3.src, "dst": l3.dst,
                "sport": l4.sport, "dport": l4.dport,
                "radius_code": pkt.code_name, "server": server,
                "family_port": family,
                "note": "RADIUS/UDP is cleartext; CVE-2024-3596 requires only an "
                        "on-path position to forge responses",
            }, suppress_key=(l3.src, l3.dst))

        self._note_cleartext_pair(ts, fam, nas, server, l3, family)

        if family != "acct":
            if pkt.code in RADIUS_RESPONSE_CODES:
                case = None
                if not pkt.has_message_authenticator:
                    case = "absent"
                elif pkt.code in RADIUS_MA_FIRST_CODES and not pkt.ma_is_first:
                    case = "not_first"
                if case is not None and self._exposure_scoped(server):
                    # Folded RDW-123: did the REQUEST carry M-A? Peeked, not
                    # popped - the F1 correlation below consumes the entry.
                    ent = self.radius_pending.get(
                        self._radius_key(l3, l4, False) + (pkt.identifier,))
                    had = "unobserved" if ent is None else bool(ent[3])
                    detail = {
                        "src": l3.src, "dst": l3.dst,
                        "radius_code": pkt.code_name,
                        "identifier": pkt.identifier,
                        "server": server, "case": case,
                        "first_attr_type": pkt.attrs[0][0] if pkt.attrs else None,
                        "request_had_ma": had,
                    }
                    if case == "absent":
                        detail["note"] = (
                            "Response carries no Message-Authenticator "
                            "(attribute 80). It is protected only by the MD5 "
                            "Response Authenticator, which is what "
                            "CVE-2024-3596 defeats.")
                    else:
                        detail["note"] = (
                            "Message-Authenticator is present but is NOT the "
                            "first attribute. The CVE-2024-3596 mitigation "
                            "requires it first in Access-Accept and "
                            "Access-Reject, so this response is not actually "
                            "hardened despite carrying the attribute.")
                    if had is True:
                        detail["policy_mismatch"] = (
                            "the NAS signed its request but the server did not "
                            "sign the response - the server side is the "
                            "unhardened one")
                    self.add("RDW-110", ts, detail,
                             suppress_key=(l3.src, l3.dst, pkt.code, case))
            elif (pkt.code == RADIUS_ACCESS_REQUEST
                  and not pkt.has_message_authenticator
                  and self._exposure_scoped(server)):
                self.add("RDW-102", ts, {
                    "src": l3.src, "dst": l3.dst,
                    "radius_code": pkt.code_name, "server": server,
                    "note": "Access-Request carries no Message-Authenticator; "
                            "the mitigation for CVE-2024-3596 is to require it "
                            "on all requests and responses.",
                }, suppress_key=(l3.src, l3.dst))

        # New posture (pair registry).
        self.rule_auth_posture(l3, pkt, ts, fam, nas, server)

        # LIFTED F1 / F2 / RDW-201. F1 skips codes it cannot place.
        if is_request is not None:
            self.rule_radius_proxy_state_correlation(l3, l4, pkt, ts,
                                                     is_request)
        self.rule_radius_opaque_payload(l3, l4, pkt, ts)
        if pkt.proxy_state_total > self.cfg.radius_proxy_state_total_max:
            self.add("RDW-201", ts, {
                "src": l3.src, "dst": l3.dst,
                "radius_code": pkt.code_name,
                "proxy_state_total": pkt.proxy_state_total,
                "proxy_state_count": pkt.proxy_state_count,
                "threshold": self.cfg.radius_proxy_state_total_max,
                "has_message_authenticator": pkt.has_message_authenticator,
                "note": "Proxy-State bytes in this packet total more than a "
                        "legitimate proxy chain would add, consistent with a "
                        "chosen-prefix collision block - counted as a SUM so that "
                        "splitting the block across several attributes does not "
                        "evade it. THRESHOLD IS A STRUCTURAL ANOMALY BOUND, not a "
                        "published exploit constant. Attributes of other types "
                        "(notably 255-byte EAP-Message fragments in ordinary "
                        "EAP-TLS) are deliberately NOT counted.",
            }, suppress_key=(l3.src, l3.dst))

        # New attack shapes.
        self.rule_decoder_shapes(l3, pkt, ts)
        if pkt.eap_message:
            self.rule_eap(l3, pkt, ts, fam, nas, server)

    # -- posture ---------------------------------------------------------
    def rule_auth_posture(self, l3: L3, pkt: RadiusPacket, ts: float,
                          fam: str, nas: str, server: str) -> None:
        if pkt.code == RADIUS_ACCESS_REQUEST:
            if pkt.has_user_password:
                self._posture("RDW-120", ts, fam, nas, server, {
                    "note": "PAP over RADIUS/UDP. User-Password is hidden only "
                            "by MD5(shared secret || Request Authenticator); one "
                            "captured exchange plus an offline shared-secret "
                            "guess recovers the plaintext password. Value never "
                            "captured."})
            if pkt.has_chap_password:
                self._posture("RDW-121", ts, fam, nas, server, {
                    "note": "CHAP-Password present: an MD5 challenge/response "
                            "whose challenge and response are both on the wire, "
                            "so the password is open to offline dictionary "
                            "attack. Value never captured."})
        elif pkt.code in RADIUS_SERVER_ORIGINATED_REQUESTS \
                and not pkt.has_message_authenticator:
            self._posture("RDW-124", ts, fam, nas, server, {
                "radius_code": pkt.code_name,
                "note": "CoA / Disconnect-Request without Message-Authenticator. "
                        "Hardening posture: these requests change or tear down "
                        "live sessions and are authenticated only by the MD5 "
                        "Request Authenticator. No CVE is claimed."})

    def _note_cleartext_pair(self, ts: float, fam: str, nas: str,
                             server: str, l3: L3, family: str) -> None:
        key = (fam, nas, server)
        self._bounded_put(self.cleartext_pairs, key, ts,
                          self.cfg.pair_registry_max)
        if key in self.radsec_pairs:
            self._radsec_fire(ts, key, "cleartext_after_radsec", family)

    def rule_radsec_presence(self, l3: L3, l4: L4, ts: float) -> None:
        """PRESENCE ONLY - the TLS itself is tlswatch's. Port-level."""
        self.stats["radsec_segments"] += 1
        if l4.dport in self.cfg.radsec_ports:
            nas, server = l3.src, l3.dst
        else:
            nas, server = l3.dst, l3.src
        key = (self._fam(l3), nas, server)
        self._bounded_put(self.radsec_pairs, key, ts,
                          self.cfg.pair_registry_max)
        if key in self.cleartext_pairs:
            self._radsec_fire(ts, key, "radsec_after_cleartext", "auth")

    def _radsec_fire(self, ts: float, key: tuple, order: str,
                     family: str) -> None:
        fam, nas, server = key
        self._posture("RDW-125", ts, fam, nas, server, {
            "order": order, "cleartext_family_port": family,
            "note": "This NAS<->server pair speaks RadSec (port 2083) AND "
                    "cleartext RADIUS/UDP. The hardened transport exists but "
                    "is bypassed or falls back, so CVE-2024-3596 still applies "
                    "to the cleartext leg. Port 2083 is also cPanel's TLS port; "
                    "the finding needs the SAME pair on cleartext RADIUS, which "
                    "keeps that collision narrow."})

    # -- attack: FreeRADIUS decoder shapes -------------------------------
    def rule_decoder_shapes(self, l3: L3, pkt: RadiusPacket, ts: float) -> None:
        # FreeRADIUS signature-checks every packet type before decoding
        # EXCEPT an Access-Request without Message-Authenticator, so only
        # that shape reaches these bugs from an unauthenticated sender.
        reach = (pkt.code == RADIUS_ACCESS_REQUEST
                 and not pkt.has_message_authenticator)
        base = {"src": l3.src, "dst": l3.dst, "radius_code": pkt.code_name,
                "identifier": pkt.identifier,
                "reachable_unauthenticated": reach}
        for case, wtype in pkt.wimax_malformed:
            self.add("RDW-215", ts, dict(base, case=case, wimax_type=wtype,
                     note="Malformed WiMAX (vendor 24757) attribute. "
                          "inner_length_overflow is the FreeRADIUS v2 "
                          "rad_coalesce() shape (CVE-2017-10979); a "
                          "continuation with no following data is the v3 "
                          "data2vp_wimax() shape (CVE-2017-10984)."),
                     suppress_key=(l3.src, l3.dst, case))
        types = [t for t in pkt.zero_len_concat
                 if t != RADIUS_ATTR_EAP_MESSAGE or self.cfg.radius_flag_eap_start]
        if types:
            self.add("RDW-216", ts, dict(base, attr_types=types,
                     note="Zero-length 'concat' attribute - the FR-GV-302 "
                          "decode_concat() infinite loop (CVE-2017-10985). "
                          "A zero-length EAP-Message is RFC 3579 EAP-Start and "
                          "is only reported when radius_flag_eap_start is set."),
                     suppress_key=(l3.src, l3.dst))
        for vendor, vtype, glen in pkt.abinary_overflow:
            self.add("RDW-220", ts, dict(base, vendor=vendor, vendor_type=vtype,
                     generic_len=glen, mask_len=ABINARY_MAX_FILTER_LEN,
                     note="Ascend abinary GENERIC filter whose length exceeds "
                          "its 6-byte mask - the print_abinary() overflow "
                          "(CVE-2022-41861). Needs a trusted client or home "
                          "server (PR:L)."),
                     suppress_key=(l3.src, l3.dst, vendor, vtype))
        for vtype, vlen in pkt.ascend_secret_short:
            self.add("RDW-221", ts, dict(base, vendor_type=vtype,
                     value_len=vlen, expected_len=ASCEND_SECRET_LEN,
                     note="Ascend-Send/Receive-Secret shorter than the 16 "
                          "octets make_secret() reads - the FR-GV-201 read "
                          "overflow (CVE-2017-10978). Value never captured."),
                     suppress_key=(l3.src, l3.dst, vtype))

    # -- EAP -------------------------------------------------------------
    def _eap_prune(self, now: float) -> None:
        w = self.cfg.eap_exchange_window_s
        for k in [k for k, v in self.eap_exchanges.items() if now - v[0] > w]:
            del self.eap_exchanges[k]

    def rule_eap(self, l3: L3, pkt: RadiusPacket, ts: float, fam: str,
                 nas: str, server: str) -> None:
        eap = parse_eap(pkt.eap_message)
        if eap is None:
            return
        self._eap_prune(ts)
        from_peer = (pkt.code == RADIUS_ACCESS_REQUEST
                     and eap.code == EAP_RESPONSE)
        from_server = (pkt.code == RADIUS_ACCESS_CHALLENGE
                       and eap.code == EAP_REQUEST)

        # RDW-122: a Response OF a weak type means the peer accepted it - a
        # peer that refuses answers with Legacy-NAK (type 3) instead.
        if from_peer and eap.etype in WEAK_EAP_METHODS:
            self._posture("RDW-122", ts, fam, nas, server, {
                "eap_method": WEAK_EAP_METHODS[eap.etype],
                "eap_type": eap.etype,
                "note": "The supplicant answered with a weak EAP method: no "
                        "mutual authentication, no key derivation, and the "
                        "challenge/response is offline-crackable from this "
                        "exchange."})

        if from_peer and eap.etype in SIM_FAMILY:
            probs = sim_attribute_problems(eap.data)
            if probs:
                self.add("RDW-219", ts, {
                    "src": l3.src, "dst": l3.dst, "eap_type": eap.etype,
                    "problems": [{"case": c, "attr_type": t} for c, t in probs],
                    "reachable_unauthenticated":
                        not pkt.has_message_authenticator,
                    "note": "EAP-SIM/AKA attribute FreeRADIUS < 3.0.26 "
                            "dereferenced as NULL (CVE-2022-41860): an unknown "
                            "NON-SKIPPABLE type, or a zero length octet. Unknown "
                            "skippable (>=128) types are legal and not reported."},
                    suppress_key=(l3.src, l3.dst))

        if eap.etype != EAP_TYPE_PWD:
            return
        msg = parse_eap_pwd(eap.data)
        if msg is None or msg.exch != PWD_EXCH_COMMIT:
            return
        if msg.fragmented:
            # Decision 3: unfragmented Commits only. Counted, never guessed.
            self.stats["eap_pwd_unjudged_fragmented"] += 1
            return
        commit = parse_pwd_commit(msg.payload)
        if commit is None:
            self.stats["eap_pwd_unjudged_group"] += 1
            return
        if from_server:
            if pkt.state_digest:
                self._bounded_put(
                    self.eap_exchanges,
                    (fam, nas, server, pkt.state_digest),
                    (ts, commit.digest, commit.group),
                    self.cfg.eap_exchange_max)
            return
        if not from_peer:
            return
        self.stats["eap_pwd_commits_judged"] += 1
        probs = pwd_commit_problems(commit)
        if probs:
            self.add("RDW-218", ts, {
                "src": l3.src, "dst": l3.dst, "group": commit.group,
                "problems": probs,
                "note": "Peer EAP-pwd Commit fails the checks FreeRADIUS 3.0.19 "
                        "added: scalar must satisfy 1 < s < r and the element "
                        "must be a point on the negotiated curve "
                        "(CVE-2019-11235, invalid-curve authentication bypass). "
                        "Pure arithmetic on the cleartext Commit."},
                suppress_key=(l3.src, l3.dst))
        ex = self.eap_exchanges.get((fam, nas, server, pkt.state_digest)) \
            if pkt.state_digest else None
        if ex is None:
            self.stats["eap_pwd_reflection_unlinked"] += 1
            return
        if ex[1] == commit.digest:
            self.add("RDW-217", ts, {
                "src": l3.src, "dst": l3.dst, "group": commit.group,
                "note": "The peer's EAP-pwd Commit is byte-identical to the "
                        "server's Commit in the same exchange (linked by the "
                        "State attribute). That is the reflection attack "
                        "FreeRADIUS < 3.0.19 accepted (CVE-2019-11234). Exact "
                        "equality, no threshold; values never captured."},
                suppress_key=(l3.src, l3.dst))

    # -- LIFTED: F1 correlation and F2 opaque-payload rules --------------
    def _radius_key(self, l3: L3, l4: L4, is_request: bool) -> tuple:
        """
        Correlation key for matching a response back to its request.

        NOTE / CORRECTION TO THE ORIGINAL DESIGN: the Request Authenticator
        CANNOT be part of the lookup key. A response's Authenticator field is
        the RESPONSE Authenticator - MD5(code|id|len|RequestAuth|attrs|secret)
        - not a copy of the request's, so it is not derivable from the
        response without the shared secret. The key is therefore the standard
        RADIUS pairing: the socket 4-tuple plus the Identifier. The request
        authenticator IS stored alongside and reported in the finding, so an
        analyst can disambiguate an Identifier reused inside the window.
        """
        if is_request:
            return (l3.src, l3.dst, l4.sport, l4.dport, 0)
        # Flip the tuple so a response keys to the request that produced it.
        return (l3.dst, l3.src, l4.dport, l4.sport, 0)

    def _radius_prune(self, now: float) -> None:
        window = self.cfg.radius_correlate_window_s
        stale = [k for k, v in self.radius_pending.items()
                 if now - v[0] > window]
        for k in stale:
            del self.radius_pending[k]
        # Hard cap regardless of the window, so a flood cannot grow the table.
        while len(self.radius_pending) > self.cfg.radius_pending_max:
            oldest = min(self.radius_pending,
                         key=lambda k: self.radius_pending[k][0])
            del self.radius_pending[oldest]

    def rule_radius_proxy_state_correlation(self, l3: L3, l4: L4,
                                            pkt: RadiusPacket, ts: float,
                                            is_request: bool) -> None:
        """
        F1. A conforming RADIUS server echoes back EXACTLY the Proxy-State
        attributes the request carried, byte for byte. A response carrying
        Proxy-State the request did not, or a different set, means something
        between the observed request and the server injected it - which is
        what a forged Access-Accept on the NAS-side leg looks like.

        Correlating rather than applying a flat "a NAS must never receive
        Proxy-State" rule is deliberate: legitimate proxy chains DO return
        Proxy-State to the proxy that added it, so a role-free rule would
        fire on every proxy hop. Correlation needs no operator configuration.
        """
        self._radius_prune(ts)
        key = self._radius_key(l3, l4, is_request) + (pkt.identifier,)

        if is_request:
            # radiuswatch: 4th field request_had_ma feeds RDW-110's detail
            # (the folded RDW-123), so no second code reports the same
            # unhardened response.
            self.radius_pending[key] = (ts, pkt.proxy_state_digests,
                                        pkt.authenticator.hex(),
                                        pkt.has_message_authenticator)
            # Enforce the cap AFTER inserting. Pruning only on the way in left
            # the table sitting at radius_pending_max + 1 - caught by the
            # bound assertion in the self-test, which is why that assertion
            # uses a strict <= rather than a rounded "about".
            while len(self.radius_pending) > self.cfg.radius_pending_max:
                oldest = min(self.radius_pending,
                             key=lambda k: self.radius_pending[k][0])
                del self.radius_pending[oldest]
            return

        if pkt.code not in RADIUS_RESPONSE_CODES:
            return
        entry = self.radius_pending.pop(key, None)

        if entry is None:
            if not (pkt.proxy_state_count
                    and self.cfg.radius_report_unmatched_proxy_state):
                return
            self.add("RDW-212", ts, {
                "src": l3.src, "dst": l3.dst,
                "radius_code": pkt.code_name, "identifier": pkt.identifier,
                "case": "no_matching_request",
                "confidence": "low",
                "response_proxy_state_count": pkt.proxy_state_count,
                "note": "A response carries Proxy-State but the matching request "
                        "was not observed, so this CANNOT be judged - an "
                        "asymmetric tap, a capture started mid-exchange, or a tap "
                        "placed inside a proxy chain all produce it legitimately. "
                        "Reported only because radius_report_unmatched_proxy_state "
                        "is enabled. LOW CONFIDENCE BY CONSTRUCTION.",
            }, suppress_key=(l3.src, l3.dst))
            return

        _req_ts, req_digests, req_auth, _req_ma = entry
        if set(pkt.proxy_state_digests) == set(req_digests):
            return

        injected = [d for d in pkt.proxy_state_digests if d not in req_digests]
        dropped = [d for d in req_digests if d not in pkt.proxy_state_digests]
        case = "added_to_bare_request" if not req_digests else "set_mismatch"
        self.add("RDW-212", ts, {
            "src": l3.src, "dst": l3.dst,
            "radius_code": pkt.code_name, "identifier": pkt.identifier,
            "case": case, "confidence": "high",
            "request_proxy_state_count": len(req_digests),
            "response_proxy_state_count": pkt.proxy_state_count,
            "injected_attr_count": len(injected),
            "dropped_attr_count": len(dropped),
            "request_authenticator": req_auth,
            "note": "The observed request and its response disagree about "
                    "Proxy-State. A conforming server echoes Proxy-State back "
                    "unchanged, so a response carrying attributes the request did "
                    "not is evidence of injection between the tap and the server - "
                    "the shape of a forged Access-Accept on the NAS-side leg of "
                    "CVE-2024-3596. Attribute VALUES are never retained; the "
                    "comparison is over digests only.",
        }, suppress_key=(l3.src, l3.dst, case))

    def rule_radius_opaque_payload(self, l3: L3, l4: L4, pkt: RadiusPacket,
                                   ts: float) -> None:
        """
        F2. Per blastradius.fail the forged Access-Accept does not have to use
        Proxy-State - the collision data can sit in Vendor-Specific or
        Reply-Message instead. RDW-201 is Proxy-State-only by design (D1), so
        without these two rules the NAS-side leg is unmonitored.

        Restricted to Access-Accept and Access-Challenge: a REQUEST carrying
        an opaque vendor attribute is ordinary. EAP-Message stays excluded,
        which is the D1 lesson.
        """
        if pkt.code not in (RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_CHALLENGE):
            return

        if pkt.reply_message_invalid_utf8:
            self.add("RDW-213", ts, {
                "src": l3.src, "dst": l3.dst,
                "radius_code": pkt.code_name, "identifier": pkt.identifier,
                "invalid_reply_messages": pkt.reply_message_invalid_utf8,
                "reply_message_count": pkt.reply_message_count,
                "note": "RFC 2865 defines Reply-Message as displayable text, so "
                        "invalid UTF-8 is a DETERMINISTIC structural anomaly - no "
                        "threshold and no entropy estimate involved. Consistent "
                        "with a chosen-prefix collision block smuggled in a "
                        "Reply-Message on the NAS-side leg of CVE-2024-3596. "
                        "Message content is never captured.",
            }, suppress_key=(l3.src, l3.dst))

        if pkt.opaque_vendor_attrs:
            worst = max(pkt.opaque_vendor_attrs, key=lambda r: r[0])
            self.add("RDW-214", ts, {
                "src": l3.src, "dst": l3.dst,
                "radius_code": pkt.code_name, "identifier": pkt.identifier,
                "opaque_attr_count": len(pkt.opaque_vendor_attrs),
                "largest_attr_len": worst[0],
                "normalised_entropy": worst[1],
                "longest_printable_run": worst[2],
                "cleartext_vendor_attrs": pkt.cleartext_vendor_attrs,
                "unknown_vendor_attrs": pkt.unknown_vendor_attrs,
                "thresholds": {
                    "min_len": self.cfg.radius_opaque_min_len,
                    "entropy_min": self.cfg.radius_opaque_entropy_min,
                    "print_run_max": self.cfg.radius_opaque_print_run_max,
                },
                "note": "A Vendor-Specific attribute is long, high-entropy and "
                        "essentially non-printable, unlike the printable AV-pair "
                        "strings vendors actually send. Consistent with collision "
                        "data smuggled outside Proxy-State on the NAS-side leg. "
                        "THRESHOLDS ARE STRUCTURAL ANOMALY BOUNDS measured against "
                        "real AV-pairs, NOT published exploit constants - entropy "
                        "alone does not separate the two populations, so the "
                        "printable-run length is the discriminator and a middle "
                        "band deliberately emits nothing. Values never captured.",
            }, suppress_key=(l3.src, l3.dst))



# ---------------------------------------------------------------------------
# Capture path
# ---------------------------------------------------------------------------
#
# libpcap CANNOT chase an IPv6 extension-header chain: `udp port 1812` reads
# the next-header byte at a FIXED offset, so the identical packet behind a
# Hop-by-Hop header is dropped in the kernel. IPv6 whose FIRST next-header is
# an extension header is therefore admitted and the bounded walk decides.
# radiuswatch has no IPsec `proto 51` term (aristaguard did), so `ip6[6] = 51`
# is the ONLY path for AH-wrapped IPv6 here. `vlan` shifts every offset after
# it and MUST stay last.

def build_bpf_filter(cfg: "Config") -> str:
    udp = sorted(set(cfg.radius_auth_ports) | set(cfg.radius_acct_ports)
                 | set(cfg.radius_coa_ports) | set(cfg.radsec_ports))
    terms = [f"udp port {p}" for p in udp]
    terms += [f"tcp port {p}" for p in sorted(set(cfg.radsec_ports))]
    return (f"({' or '.join(terms)}) or ip6[6] = 0 or ip6[6] = 43 or "
            f"ip6[6] = 44 or ip6[6] = 51 or ip6[6] = 60 or vlan")


BPF_FILTER = build_bpf_filter(Config())


def run_capture(cfg: Config, engine: RadiusEngine) -> None:  # pragma: no cover
    """Live (--iface) or offline (--pcap). Both go through the SAME BPF, so a
    pcap replay exercises the filter instead of bypassing it."""
    from scapy.all import sniff  # noqa: PLC0415  - lazy by design

    def _cb(pkt: Any) -> None:
        engine.handle_frame(bytes(pkt), float(pkt.time))

    kw: dict[str, Any] = dict(filter=build_bpf_filter(cfg), prn=_cb, store=False)
    if cfg.pcap:
        kw["offline"] = cfg.pcap
    else:
        kw["iface"] = cfg.iface or None
        kw["timeout"] = cfg.timeout or None
    sniff(**kw)


# ---- LIFTED: self-test harness + fixture builders -------------------------

_CHECKS = 0
_FAILS: list[str] = []


def check(cond: bool, label: str) -> None:
    global _CHECKS
    _CHECKS += 1
    if not cond:
        _FAILS.append(label)

def _mk_eth(dst: bytes, src: bytes, et: int, payload: bytes = b"",
         vlans: Iterable[int] = ()) -> bytes:
    out = dst + src
    for v in vlans:
        out += b"\x81\x00" + bytes([(v >> 8) & 0x0F, v & 0xFF])
    out += bytes([(et >> 8) & 0xFF, et & 0xFF]) + payload
    return out


def _mk_ipv4(src: str, dst: str, proto: int, payload: bytes = b"") -> bytes:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    tl = 20 + len(payload)
    return (b"\x45\x00" + tl.to_bytes(2, "big") + b"\x00\x00\x40\x00\x40"
            + bytes([proto]) + b"\x00\x00" + s + d + payload)


def _mk_udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    ln = 8 + len(payload)
    return (sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + ln.to_bytes(2, "big") + b"\x00\x00" + payload)


def _mk_tcp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return (sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x02" + b"\x50\x18"
            + b"\xff\xff\x00\x00\x00\x00" + payload)


def _mk_radius_v(code: int, ident: int,
                 attrs: Iterable[tuple[int, bytes]],
                 auth: bytes = b"\xaa" * 16) -> bytes:
    """Build a RADIUS packet from (type, VALUE) pairs, for the F1/F2 tests
    where attribute CONTENT is what is being exercised."""
    body = b"".join(bytes([t, 2 + len(v)]) + v for t, v in attrs)
    return (bytes([code, ident]) + struct.pack("!H", 20 + len(body))
            + auth + body)


def _mk_vsa(payload: bytes, vendor: int = 9) -> bytes:
    return (vendor.to_bytes(4, "big") + bytes([1, len(payload) + 2]) + payload)


def _mk_radius(code: int, ident: int, attrs: Iterable[tuple[int, int]]) -> bytes:
    body = b""
    for atype, alen in attrs:
        body += bytes([atype, alen]) + b"\x00" * (alen - 2)
    total = 20 + len(body)
    return (bytes([code, ident]) + total.to_bytes(2, "big")
            + b"\xaa" * 16 + body)


RADIUS_ATTR_EAP_MESSAGE = 79


def _mk_ip6(nh: int, payload: bytes,
            src: bytes = b"\x20\x01" + b"\x00" * 14,
            dst: bytes = b"\x20\x01" + b"\x00" * 13 + b"\x02") -> bytes:
    return (b"\x60\x00\x00\x00" + len(payload).to_bytes(2, "big")
            + bytes([nh, 64]) + src + dst + payload)


def _mk_exthdr(kind: int, nxt: int, frag_offset: int = 0) -> bytes:
    """Build one IPv6 extension header of the given kind."""
    if kind == IPV6_EXT_FRAGMENT:
        return bytes([nxt, 0]) + ((frag_offset << 3) | (1 if frag_offset else 0)
                                  ).to_bytes(2, "big") + b"\x00" * 4
    if kind == IPV6_EXT_AH:
        # RFC 4302: length is in 4-octet units MINUS 2, so 1 -> 12 bytes.
        return bytes([nxt, 1]) + b"\x00" * 10
    # HBH / Routing / Dest-Opts: 8-octet units not counting the first 8.
    return bytes([nxt, 0]) + b"\x00" * 6


def _run(frames: Iterable[bytes], cfg: Optional[Config] = None) -> RadiusEngine:
    if isinstance(frames, (bytes, bytearray)):
        raise TypeError("_run expects a SEQUENCE of frames, not a bare bytes "
                        "object - iterating bytes yields ints and would test "
                        "nothing at all")
    eng = RadiusEngine(cfg or Config())
    for i, f in enumerate(frames):
        eng.handle_frame(f, ts=1000.0 + i)
    return eng


def _codes(eng: RadiusEngine) -> set[str]:
    return {f.code for f in eng.findings}


# ---- LIFTED: carried acceptance + rule tests (renumbered only) ------------

def test_radius_rules() -> None:
    # RDW-101: RADIUS on the wire at all.
    good = _mk_radius(RADIUS_ACCESS_REQUEST, 1,
                      [(RADIUS_ATTR_USER_NAME, 8),
                       (RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 18)])
    frame = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                    _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                             _mk_udp(50000, 1812, good)))
    c = _codes(_run([frame]))
    check("RDW-101" in c, "RDW-101 RADIUS observed")
    check("RDW-102" not in c,
          "RDW-102 must stay silent when Message-Authenticator IS present")
    check("RDW-201" not in c, "RDW-201 must stay silent on a normal request")

    # RDW-102: request without Message-Authenticator.
    bare = _mk_radius(RADIUS_ACCESS_REQUEST, 2, [(RADIUS_ATTR_USER_NAME, 8)])
    c = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                             _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                                      _mk_udp(50000, 1812, bare)))]))
    check("RDW-102" in c, "RDW-102 fires on a request with no Message-Authenticator")

    # RDW-110 (was RDW-202, retired): an unauthenticated RESPONSE. Exposure-class.
    resp = _mk_radius(RADIUS_ACCESS_ACCEPT, 3, [(RADIUS_ATTR_USER_NAME, 8)])
    eng = _run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                        _mk_ipv4("10.0.0.2", "10.0.0.1", IPPROTO_UDP,
                                 _mk_udp(1812, 50000, resp)))])
    c = _codes(eng)
    check("RDW-110" in c, "RDW-110 fires on an unauthenticated Access-Accept")
    check("RDW-102" not in c, "a response must raise RDW-110, not RDW-102")
    f = next(x for x in eng.findings if x.code == "RDW-110")
    check(f.detail["case"] == "absent", "RDW-110 records the absent case")
    check(f.klass == "exposure",
          "RDW-110 is EXPOSURE - an unhardened server is a standing condition, "
          "not an attack event, and attack-class codes cannot be scoped")

    # RDW-201: Proxy-State total over the bound.
    big = _mk_radius(RADIUS_ACCESS_REQUEST, 4, [(RADIUS_ATTR_PROXY_STATE, 250)])
    eng = _run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                        _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                                 _mk_udp(50000, 1812, big)))])
    check("RDW-201" in _codes(eng), "RDW-201 fires on oversized Proxy-State")
    f = next(x for x in eng.findings if x.code == "RDW-201")
    check(f.detail["proxy_state_total"] == 250, "RDW-201 reports the total")
    check(f.severity == "CRITICAL", "RDW-201 is the module's top severity")
    check("STRUCTURAL ANOMALY BOUND" in f.detail["note"],
          "RDW-201 must say its threshold is not a published exploit constant")

    # Boundary: exactly at the threshold stays silent.
    at = _mk_radius(RADIUS_ACCESS_REQUEST, 5,
                    [(RADIUS_ATTR_PROXY_STATE,
                      Config().radius_proxy_state_total_max)])
    check("RDW-201" not in _codes(_run([
        _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                         _mk_udp(50000, 1812, at)))
    ])), "RDW-201 at exactly the threshold must stay silent")

    # Raising the knob must SILENCE the finding.
    cfg = Config(radius_proxy_state_total_max=255)
    check("RDW-201" not in _codes(_run([
        _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                         _mk_udp(50000, 1812, big)))
    ], cfg)), "raising radius_proxy_state_total_max must silence RDW-201")

    # Credentials must never reach a finding.
    for f in _run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                           _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP,
                                    _mk_udp(50000, 1812, big)))]).findings:
        blob = json.dumps(f.detail).lower()
        for word in ("password", "secret", "user_password"):
            check(word not in blob, f"RADIUS finding leaked {word!r}")


def test_radius_blastradius_fixes() -> None:
    """
    The eight acceptance tests for the Sept 2026 RADIUS review (D1-D6).

    Every one of these passed a 494-check self-test, a 538-check conformance
    run, a 230-check cross-check and a live lab before the review, because no
    fixture anywhere contained an EAP-Message attribute, a split Proxy-State,
    a Message-Authenticator in a non-first position, or 300 attributes.
    """
    def radius_udp(pkt: bytes, dport: int = 1812, sport: int = 50000,
                   src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                       _mk_ipv4(src, dst, IPPROTO_UDP,
                                _mk_udp(sport, dport, pkt)))

    UN, MA, PS, EAP = (RADIUS_ATTR_USER_NAME, RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                       RADIUS_ATTR_PROXY_STATE, RADIUS_ATTR_EAP_MESSAGE)

    # A1 (D1). EAP-TLS request with two 255-byte EAP-Message fragments.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 1,
                                           [(UN, 8), (EAP, 255), (EAP, 255),
                                            (MA, 18)]))]))
    check(c == {"RDW-101"},
          f"D1: ordinary EAP-TLS must raise RDW-101 only, got {c}. EAP-Message "
          f"fragments at 255 bytes are normal 802.1X, not a collision block")

    # A2 (D1). Server Access-Challenge, M-A first, EAP fragments.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_CHALLENGE, 2,
                                           [(MA, 18), (EAP, 255), (EAP, 255)]),
                                dport=50000, sport=1812,
                                src="10.0.0.2", dst="10.0.0.1")]))
    check(c == {"RDW-101"},
          f"D1: a correctly hardened Access-Challenge must raise RDW-101 only, "
          f"got {c}")

    # A3 (D3). Access-Reject with Proxy-State BEFORE Message-Authenticator.
    eng = _run([radius_udp(_mk_radius(RADIUS_ACCESS_REJECT, 3,
                                      [(PS, 40), (MA, 18)]),
                           dport=50000, sport=1812,
                           src="10.0.0.2", dst="10.0.0.1")])
    check("RDW-110" in _codes(eng),
          "D3: M-A present but not first must still fire - the mitigation "
          "requires it FIRST in Access-Accept/Access-Reject")
    f = next(x for x in eng.findings if x.code == "RDW-110")
    check(f.detail["case"] == "not_first",
          f"D3: detail must say which case, got {f.detail.get('case')!r}")
    check(f.detail["first_attr_type"] == PS,
          "D3: detail should record what WAS first")

    # A3b. The same response with M-A first must stay silent.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REJECT, 4,
                                           [(MA, 18), (PS, 40)]),
                                dport=50000, sport=1812,
                                src="10.0.0.2", dst="10.0.0.1")]))
    check("RDW-110" not in c, f"D3: a correctly hardened reject must be silent, got {c}")

    # A3c. Access-Challenge is presence-only - M-A not first must NOT fire.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_CHALLENGE, 5,
                                           [(PS, 40), (MA, 18)]),
                                dport=50000, sport=1812,
                                src="10.0.0.2", dst="10.0.0.1")]))
    check("RDW-110" not in c,
          f"D3: Access-Challenge is a PRESENCE-only check, not position, got {c}")

    # A4 (D2). Four 100-byte Proxy-State attributes = 400 bytes total.
    eng = _run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 6, [(PS, 100)] * 4))])
    check("RDW-201" in _codes(eng),
          "D2: a collision block split across four Proxy-State attributes "
          "must fire - the bound is a per-packet SUM")
    f = next(x for x in eng.findings if x.code == "RDW-201")
    check(f.detail["proxy_state_total"] == 400, "D2: total recorded")
    check(f.detail["proxy_state_count"] == 4, "D2: attribute count recorded")
    check("STRUCTURAL ANOMALY BOUND" in f.detail["note"],
          "D2: the structural-bound wording must survive the rewrite")

    # A4b. The knob must still change behaviour.
    check("RDW-201" not in _codes(_run(
        [radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 7, [(PS, 100)] * 4))],
        Config(radius_proxy_state_total_max=500))),
        "D2: raising radius_proxy_state_total_max must SILENCE RDW-201")

    # A4c. At the limit silent, one over fires.
    for total, want in ((Config().radius_proxy_state_total_max, False),
                        (Config().radius_proxy_state_total_max + 1, True)):
        got = "RDW-201" in _codes(_run(
            [radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 8, [(PS, total)]))]))
        check(got is want, f"D2: proxy_state_total={total} expected {want}")

    # A5 (D5). known_infra set, bare PAP request to a non-infra destination.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 9, [(UN, 8)]),
                                dst="10.9.9.9")],
                    Config(known_infra=("172.16.0.1",))))
    check("RDW-102" not in c,
          f"D5: RDW-102 is EXPOSURE and must honour known_infra, got {c}")
    check("RDW-101" not in c, "D5: RDW-101 scoped away too")
    # ... and an in-scope server must still surface.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 10, [(UN, 8)]),
                                dst="10.9.9.9")],
                    Config(known_infra=("10.9.9.9",))))
    check("RDW-102" in c, f"D5: an in-scope server must still raise RDW-102, got {c}")

    # A5b. RDW-201 is ATTACK-class and must NEVER be scoped away.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 11,
                                           [(PS, 100)] * 4), dst="10.9.9.9")],
                    Config(known_infra=("172.16.0.1",))))
    check("RDW-201" in c,
          "D5: known_infra must NEVER filter an ATTACK finding - that would "
          "turn a noise knob into a detection blind spot")

    # A5c. The server side of a RESPONSE is the SOURCE, not the destination.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_ACCEPT, 12, [(UN, 8)]),
                                dport=50000, sport=1812,
                                src="10.5.5.5", dst="10.0.0.1")],
                    Config(known_infra=("10.5.5.5",))))
    check("RDW-110" in c,
          "D5: on a response the RADIUS server is l3.src; scoping on dst would "
          "put the NAS address through the infra check instead")

    # A6 (D6). 300 two-byte attributes followed by Message-Authenticator.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 13,
                                           [(26, 2)] * 300 + [(MA, 18)]))]))
    check("RDW-102" not in c,
          f"D6: the attribute walk must reach an M-A past attribute 256, got {c}")
    check(RADIUS_MAX_ATTRS >= 2038, f"D6: cap is {RADIUS_MAX_ATTRS}, want >= 2038")

    # A8 (regressions). Accounting skips the M-A checks entirely.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCOUNTING_REQUEST, 14,
                                           [(UN, 8)]), dport=1813)]))
    check("RDW-102" not in c and "RDW-110" not in c,
          f"regression: accounting has no Message-Authenticator requirement, got {c}")
    # A single small Proxy-State from a legitimate proxy stays silent.
    c = _codes(_run([radius_udp(_mk_radius(RADIUS_ACCESS_REQUEST, 15,
                                           [(UN, 8), (PS, 12), (MA, 18)]))]))
    check(c == {"RDW-101"},
          f"regression: one small Proxy-State is ordinary proxying, got {c}")

    # RDW-202 is retired and must never come back.
    check("RDW-202" not in FINDINGS, "RDW-202 must not be a live code")
    check("RDW-202" in RETIRED_CODES, "RDW-202 must be recorded as retired")
    check(FINDINGS["RDW-110"].klass == "exposure", "D4: RDW-110 is exposure-class")



def test_ipv6_extension_headers() -> None:
    """
    A7 (D7). The PRIME DIRECTIVE case: plain IPv6 worked and the identical
    packet behind a Hop-by-Hop header raised NOTHING. This affected EVERY L4
    rule in the module, not just RADIUS.
    """
    bare = _mk_radius(RADIUS_ACCESS_REQUEST, 1, [(RADIUS_ATTR_USER_NAME, 8)])
    l4 = _mk_udp(50000, 1812, bare)

    plain = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                                 _mk_ip6(IPPROTO_UDP, l4))]))
    check("RDW-101" in plain and "RDW-102" in plain,
          f"plain IPv6 RADIUS must fire, got {plain}")

    for kind, name in ((IPV6_EXT_HOPOPT, "Hop-by-Hop"),
                       (IPV6_EXT_ROUTING, "Routing"),
                       (IPV6_EXT_FRAGMENT, "Fragment"),
                       (IPV6_EXT_AH, "AH"),
                       (IPV6_EXT_DSTOPTS, "Dest-Opts")):
        body = _mk_exthdr(kind, IPPROTO_UDP) + l4
        got = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                                   _mk_ip6(kind, body))]))
        check("RDW-101" in got and "RDW-102" in got,
              f"D7: RADIUS behind a {name} header must produce the same "
              f"findings as plain IPv6; got {got}")

    # A chain of several headers.
    chain = (_mk_exthdr(IPV6_EXT_HOPOPT, IPV6_EXT_DSTOPTS)
             + _mk_exthdr(IPV6_EXT_DSTOPTS, IPV6_EXT_ROUTING)
             + _mk_exthdr(IPV6_EXT_ROUTING, IPPROTO_UDP) + l4)
    got = _codes(_run([_mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                               _mk_ip6(IPV6_EXT_HOPOPT, chain))]))
    check("RDW-101" in got, f"D7: a 3-header chain must resolve, got {got}")

    # A NON-FIRST fragment carries no L4 header - reporting one would hand a
    # rule payload bytes to parse as a header.
    body = _mk_exthdr(IPV6_EXT_FRAGMENT, IPPROTO_UDP, frag_offset=185) + l4
    l3 = parse_l3(_mk_ip6(IPV6_EXT_FRAGMENT, body), ETH_P_IPV6)
    check(l3 is not None and not l3.l4_reachable,
          "D7: a non-first fragment must report l4_reachable=False")
    check(parse_l4(l3) is None, "D7: parse_l4 must refuse a non-first fragment")
    check(l3.frag_offset == 185, f"D7: fragment offset recorded, got {l3.frag_offset}")

    # No-Next-Header terminates the chain with no L4.
    l3 = parse_l3(_mk_ip6(IPV6_NO_NEXT_HEADER, b""), ETH_P_IPV6)
    check(l3 is not None and not l3.l4_reachable, "D7: No-Next yields no L4")

    # The walk is BOUNDED - an unbounded walk is a DoS primitive against the
    # sensor itself.
    deep = b"".join(_mk_exthdr(IPV6_EXT_DSTOPTS, IPV6_EXT_DSTOPTS)
                    for _ in range(40)) + l4
    l3 = parse_l3(_mk_ip6(IPV6_EXT_DSTOPTS, deep), ETH_P_IPV6)
    check(l3 is not None, "D7: a deep chain must not crash the parser")
    check(len(l3.ext_headers) <= IPV6_MAX_EXT_HEADERS,
          f"D7: walk must stop at {IPV6_MAX_EXT_HEADERS}, got {len(l3.ext_headers)}")
    check(not l3.l4_reachable,
          "D7: past the bound the module must NOT claim to have found an L4 "
          "header - it would be handing a rule mid-header bytes")
    check(l3.ext_chain_truncated, "D7: exceeding the bound is recorded")

    # AH length uses 4-octet units MINUS 2, not the 8-octet rule. Getting
    # this wrong walks off the end of the header and silently mis-parses.
    ah = _mk_exthdr(IPV6_EXT_AH, IPPROTO_UDP)
    check(len(ah) == 12, f"AH header should be 12 bytes here, got {len(ah)}")
    l3 = parse_l3(_mk_ip6(IPV6_EXT_AH, ah + l4), ETH_P_IPV6)
    check(l3 is not None and l3.proto == IPPROTO_UDP,
          f"D7: AH must resolve to UDP, got proto {l3.proto if l3 else None}")
    check(l3.payload == l4,
          "D7: the AH length rule must land exactly on the L4 header")

    # Truncated / lying extension lengths must not raise or over-read.
    for bad in (b"\x11", b"\x11\xff", b"\x11\xff\x00\x00"):
        try:
            parse_l3(_mk_ip6(IPV6_EXT_HOPOPT, bad), ETH_P_IPV6)
        except Exception as exc:  # noqa: BLE001
            check(False, f"D7: malformed ext header raised {exc!r}")
            break
    else:
        check(True, "D7: malformed extension headers never raise")

    # Other L4 rules must work behind an extension header too - the blind


    # SEED-GLUE replacement for the aristaguard SSH/gNMI tail: BPF clause.
    for nh in (0, 43, 44, 51, 60):
        check(f"ip6[6] = {nh}" in BPF_FILTER, f"D7: BPF omits ip6[6] = {nh}")
    check(BPF_FILTER.rstrip().endswith("vlan"), "D7: vlan must stay LAST")


def cfg_default_entropy_floor() -> float:
    return Config().radius_opaque_entropy_min


def test_blastradius_nas_side_leg() -> None:
    """
    F1/F2. The NAS-SIDE LEG of CVE-2024-3596.

    A tap sees only one of the two legs. RDW-201 (Proxy-State total) is correct
    for the attacker->SERVER leg, where the colliding Access-Reject must use
    Proxy-State because a server echoes it back unchanged. On the
    attacker->NAS leg, where the forged Access-Accept arrives,
    blastradius.fail states the collision data can sit in Vendor-Specific or
    Reply-Message instead - so a Proxy-State-only rule is blind there.

    Every case is run over IPv4, plain IPv6 and IPv6 behind an extension
    header, because the prime directive applies to new rules too.
    """
    UN, MA, PS, RM, VSA, EAP = (RADIUS_ATTR_USER_NAME,
                                RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                                RADIUS_ATTR_PROXY_STATE,
                                RADIUS_ATTR_REPLY_MESSAGE,
                                RADIUS_ATTR_VENDOR_SPECIFIC,
                                RADIUS_ATTR_EAP_MESSAGE)

    # Deterministic pseudo-random bytes: os.urandom would make a failure
    # unreproducible, and the classifier's behaviour must be pinned exactly.
    def prand(n: int, seed: int = 7) -> bytes:
        out = bytearray()
        x = seed * 2654435761 & 0xFFFFFFFF
        while len(out) < n:
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
            out.append((x >> 16) & 0xFF)
        return bytes(out)

    # --- three transports, exercised identically -------------------------
    def v4(pkt: bytes, request: bool) -> bytes:
        sp, dp = (50000, 1812) if request else (1812, 50000)
        a, b = ("10.0.0.1", "10.0.0.2") if request else ("10.0.0.2", "10.0.0.1")
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                       _mk_ipv4(a, b, IPPROTO_UDP, _mk_udp(sp, dp, pkt)))

    def v6(pkt: bytes, request: bool) -> bytes:
        sp, dp = (50000, 1812) if request else (1812, 50000)
        a = b"\x20\x01" + b"\x00" * 14
        b_ = b"\x20\x01" + b"\x00" * 13 + b"\x02"
        src, dst = (a, b_) if request else (b_, a)
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                       _mk_ip6(IPPROTO_UDP, _mk_udp(sp, dp, pkt), src, dst))

    def v6eh(pkt: bytes, request: bool) -> bytes:
        sp, dp = (50000, 1812) if request else (1812, 50000)
        a = b"\x20\x01" + b"\x00" * 14
        b_ = b"\x20\x01" + b"\x00" * 13 + b"\x02"
        src, dst = (a, b_) if request else (b_, a)
        body = _mk_exthdr(IPV6_EXT_HOPOPT, IPPROTO_UDP) + _mk_udp(sp, dp, pkt)
        return _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV6,
                       _mk_ip6(IPV6_EXT_HOPOPT, body, src, dst))

    transports = (("IPv4", v4), ("IPv6", v6), ("IPv6+EH", v6eh))

    for label, mk in transports:
        # F1.1 - request with NO Proxy-State, Accept WITH one.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 7,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 7,
                                           [(MA, b"\x00" * 16),
                                            (PS, prand(60))]), False)]))
        check("RDW-212" in got,
              f"F1.1 [{label}]: Proxy-State in a response whose request had "
              f"none must fire, got {sorted(got)}")

        # F1.2 - legitimate proxy hop: the SAME Proxy-State echoed back.
        hop = b"proxy-hop-1-opaque-token"
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 8,
                                           [(UN, b"op"), (PS, hop)]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 8,
                                           [(MA, b"\x00" * 16),
                                            (PS, hop)]), False)]))
        check("RDW-212" not in got,
              f"F1.2 [{label}]: a conforming server echoing Proxy-State back "
              f"unchanged is a legitimate proxy hop and must stay SILENT - "
              f"this is why the rule correlates instead of applying a flat "
              f"'a NAS never receives Proxy-State'. Got {sorted(got)}")

        # F1.3 - request has A, response has A plus an injected B.
        eng = _run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 9,
                                    [(PS, b"A" * 10)]), True),
                    mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 9,
                                    [(MA, b"\x00" * 16), (PS, b"A" * 10),
                                     (PS, b"B" * 10)]), False)])
        check("RDW-212" in eng and True, f"F1.3 [{label}] placeholder") \
            if False else None
        got = _codes(eng)
        check("RDW-212" in got,
              f"F1.3 [{label}]: a response carrying MORE Proxy-State than the "
              f"request must fire, got {sorted(got)}")
        f = next(x for x in eng.findings if x.code == "RDW-212")
        check(f.detail["case"] == "set_mismatch",
              f"F1.3 [{label}]: case should be set_mismatch, got {f.detail['case']}")
        check(f.detail["injected_attr_count"] == 1,
              f"F1.3 [{label}]: one injected attribute expected")

        # F1.4 - response with no matching request: SILENT by default.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 10,
                                           [(MA, b"\x00" * 16),
                                            (PS, b"A" * 10)]), False)]))
        check("RDW-212" not in got,
              f"F1.4 [{label}]: with no matching request observed the module "
              f"must not guess - an asymmetric tap produces this legitimately. "
              f"Got {sorted(got)}")

        # F2.5 - Reply-Message with invalid UTF-8.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 12,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 12,
                                           [(MA, b"\x00" * 16),
                                            (RM, b"\xff\xfe\x80\x81 bad")]),
                              False)]))
        check("RDW-213" in got,
              f"F2.5 [{label}]: invalid UTF-8 in Reply-Message must fire, "
              f"got {sorted(got)}")

        # F2.6 - oversized high-entropy Vendor-Specific.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 13,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 13,
                                           [(MA, b"\x00" * 16),
                                            (VSA, _mk_vsa(prand(180, 11)))]),
                              False)]))
        check("RDW-214" in got,
              f"F2.6 [{label}]: an oversized high-entropy Vendor-Specific on "
              f"an Accept must fire, got {sorted(got)}")

        # F2.7a - long PRINTABLE vendor AV-pair must stay silent.
        av = (b"Aruba-User-Role=authenticated-employee-vlan-200-floor3"
              b"-corp-secure-wireless-policy")
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 14,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 14,
                                           [(MA, b"\x00" * 16),
                                            (VSA, _mk_vsa(av))]), False)]))
        check("RDW-214" not in got,
              f"F2.7a [{label}]: vendors legitimately send long printable "
              f"AV-pairs; length alone must not fire. Got {sorted(got)}")

        # F2.7b - EAP-TLS fragments stay excluded (the D1 lesson).
        #
        # The payload MUST be high-entropy pseudo-random, not a constant run.
        # A real EAP-TLS fragment is TLS ciphertext and is indistinguishable
        # from random bytes, so it is precisely the content that would trip an
        # entropy rule. An earlier version of this test used b"\x01" * 253 - a
        # zero-entropy constant that could never have tripped anything, so it
        # proved nothing at all. Bite verification caught it: removing the
        # EAP-Message exclusion went undetected.
        eap_ciphertext = prand(253, 29)
        check(_norm_entropy(eap_ciphertext) >= cfg_default_entropy_floor(),
              "the EAP fixture must genuinely be high-entropy, or this test "
              "cannot detect the exclusion being removed")
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 15,
                                           [(UN, b"op"), (EAP, eap_ciphertext),
                                            (MA, b"\x00" * 16)]), True)]))
        check("RDW-214" not in got and "RDW-201" not in got,
              f"F2.7b [{label}]: EAP-Message stays excluded even when its "
              f"content is high-entropy ciphertext, got {sorted(got)}")
        # And on a RESPONSE, where F2 is actually armed.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 17,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_CHALLENGE, 17,
                                           [(MA, b"\x00" * 16),
                                            (EAP, eap_ciphertext)]), False)]))
        check("RDW-214" not in got,
              f"F2.7b [{label}]: a high-entropy EAP-Message on a CHALLENGE - "
              f"an entirely ordinary EAP-TLS exchange - must stay silent, "
              f"got {sorted(got)}")

        # F2.7c - ordinary readable Reply-Message.
        got = _codes(_run([mk(_mk_radius_v(RADIUS_ACCESS_REQUEST, 16,
                                           [(UN, b"op")]), True),
                           mk(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 16,
                                           [(MA, b"\x00" * 16),
                                            (RM, b"Welcome to the network")]),
                              False)]))
        check("RDW-213" not in got,
              f"F2.7c [{label}]: a normal Reply-Message must stay silent, "
              f"got {sorted(got)}")

    # --- knobs must change behaviour -------------------------------------
    accept_opaque = [v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 20, [(UN, b"op")]), True),
                     v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 20,
                                     [(MA, b"\x00" * 16),
                                      (VSA, _mk_vsa(prand(180, 11)))]), False)]
    # The classifier must measure the VENDOR PAYLOAD, not the whole attribute
    # body. The 6-byte vendor-id/type/len sub-header barely shifts entropy, so
    # a verdict comparison can never catch this - assert the recorded
    # statistics EXACTLY equal a payload-only computation.
    payload = prand(180, 11)
    eng = _run(accept_opaque)
    f = next(x for x in eng.findings if x.code == "RDW-214")
    check(f.detail["normalised_entropy"] == round(_norm_entropy(payload), 3),
          f"RDW-214 must measure the vendor PAYLOAD: recorded "
          f"{f.detail['normalised_entropy']}, payload-only "
          f"{round(_norm_entropy(payload), 3)}. Including the 6-byte "
          f"vendor-id/type/len sub-header changes the number without "
          f"changing the verdict, which is why this asserts the statistic "
          f"rather than the classification.")
    check(f.detail["longest_printable_run"] == _longest_printable_run(payload),
          "RDW-214's printable run must be measured over the vendor payload")

    check("RDW-214" in _codes(_run(accept_opaque)), "RDW-214 fires at defaults")
    check("RDW-214" not in _codes(_run(accept_opaque,
                                      Config(radius_opaque_min_len=250))),
          "raising radius_opaque_min_len must SILENCE RDW-214")
    check("RDW-214" not in _codes(_run(accept_opaque,
                                      Config(radius_opaque_entropy_min=0.99))),
          "raising radius_opaque_entropy_min must SILENCE RDW-214")
    check("RDW-214" not in _codes(_run(accept_opaque,
                                      Config(radius_opaque_print_run_max=1))),
          "lowering radius_opaque_print_run_max must SILENCE RDW-214")

    unmatched = [v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 21,
                                 [(MA, b"\x00" * 16), (PS, b"A" * 10)]), False)]
    check("RDW-212" not in _codes(_run(unmatched)), "unmatched silent by default")
    eng = _run(unmatched, Config(radius_report_unmatched_proxy_state=True))
    check("RDW-212" in _codes(eng), "the knob must enable the low-confidence note")
    f = next(x for x in eng.findings if x.code == "RDW-212")
    check(f.detail["confidence"] == "low",
          "an unmatched response must be labelled LOW CONFIDENCE")
    check(f.detail["case"] == "no_matching_request", "case recorded")

    # --- attack class, never scoped by known_infra ------------------------
    for code in ("RDW-212", "RDW-213", "RDW-214"):
        check(FINDINGS[code].klass == "attack", f"{code} must be attack-class")
    scoped = Config(known_infra=("172.16.0.1",),
                    radius_report_unmatched_proxy_state=True)
    got = _codes(_run([v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 22, [(UN, b"op")]), True),
                       v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 22,
                                       [(MA, b"\x00" * 16), (PS, prand(60)),
                                        (VSA, _mk_vsa(prand(180, 11))),
                                        (RM, b"\xff\xfe bad")]), False)], scoped))
    for code in ("RDW-212", "RDW-213", "RDW-214"):
        check(code in got,
              f"{code} is ATTACK-class and must NEVER be scoped away by "
              f"known_infra, got {sorted(got)}")
    check("RDW-101" not in got, "the EXPOSURE finding IS scoped away")

    # --- requests must not trigger the F2 rules ---------------------------
    got = _codes(_run([v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 23,
                                       [(VSA, _mk_vsa(prand(180, 11))),
                                        (RM, b"\xff\xfe bad")]), True)]))
    check("RDW-213" not in got and "RDW-214" not in got,
          f"F2 applies to Accept/Challenge only; a REQUEST carrying an opaque "
          f"vendor attribute is ordinary. Got {sorted(got)}")

    # --- the pending table must stay bounded ------------------------------
    eng = RadiusEngine(Config(radius_pending_max=64))
    for i in range(500):
        eng.handle_frame(
            _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
                    _mk_ipv4(f"10.1.{i // 256}.{i % 256}", "10.0.0.2",
                             IPPROTO_UDP,
                             _mk_udp(50000, 1812,
                                     _mk_radius_v(RADIUS_ACCESS_REQUEST,
                                                  i % 256, [(UN, b"op")])))),
            ts=2000.0 + i * 0.001)
    check(len(eng.radius_pending) <= 64,
          f"the pending-request table must stay bounded, got "
          f"{len(eng.radius_pending)} - an unbounded correlation table is a "
          f"memory-exhaustion primitive against the sensor")

    # Entries older than the window must be pruned, not matched.
    eng = RadiusEngine(Config(radius_correlate_window_s=1.0))
    eng.handle_frame(v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 30, [(UN, b"op")]), True),
                     ts=3000.0)
    eng.handle_frame(v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 30,
                                     [(MA, b"\x00" * 16), (PS, b"A" * 10)]), False),
                     ts=3100.0)
    check("RDW-212" not in {x.code for x in eng.findings},
          "a request outside the correlation window must be pruned, and the "
          "unmatched response must then stay silent rather than firing")

    # --- values must never reach a finding --------------------------------
    eng = _run([v4(_mk_radius_v(RADIUS_ACCESS_REQUEST, 40, [(UN, b"op")]), True),
                v4(_mk_radius_v(RADIUS_ACCESS_ACCEPT, 40,
                                [(MA, b"\x00" * 16),
                                 (PS, b"SECRETPROXYSTATE" * 4),
                                 (RM, b"\xff\xfe SECRETMESSAGE"),
                                 (VSA, _mk_vsa(prand(180, 11)))]), False)])
    for f in eng.findings:
        blob = json.dumps(f.detail)
        check("SECRETPROXYSTATE" not in blob,
              f"{f.code} leaked Proxy-State content into a finding")
        check("SECRETMESSAGE" not in blob,
              f"{f.code} leaked Reply-Message content into a finding")


def test_opacity_classifier() -> None:
    """
    The measured basis for RDW-214. Entropy ALONE does not separate real
    vendor AV-pairs from random bytes - measured ranges overlap at
    0.881-0.902 normalised - so the printable-run length is the
    discriminator and the gap between the bands emits nothing.
    """
    cfg = Config()

    def prand(n: int, seed: int = 3) -> bytes:
        out = bytearray()
        x = seed * 2654435761 & 0xFFFFFFFF
        while len(out) < n:
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
            out.append((x >> 16) & 0xFF)
        return bytes(out)

    check(_norm_entropy(b"") == 0.0, "empty buffer has no entropy")
    check(_norm_entropy(b"A" * 100) == 0.0, "a constant buffer has zero entropy")
    check(_norm_entropy(prand(200)) > 0.85, "random bytes are high-entropy")
    # Normalisation is the whole point: short random buffers must still score
    # high, which a raw-bits threshold would miss.
    check(_norm_entropy(prand(32)) > 0.85,
          "32 random bytes can only reach 5 bits, so a RAW entropy threshold "
          "would never fire on them - normalisation is what makes short "
          "attributes comparable")

    check(_longest_printable_run(b"hello world") == 11, "printable run")
    check(_longest_printable_run(b"ab\x00cdef") == 4, "run resets on non-print")
    check(_longest_printable_run(b"\x00\x01\x02") == 0, "no printable run")

    # These must be at or above radius_opaque_min_len. A SHORTER AV-pair
    # correctly returns "unknown" - the length gate runs first and the module
    # deliberately does not judge short values at all. The first version of
    # this test used 58-60 byte strings and expected "cleartext", which was a
    # wrong expectation rather than a classifier bug.
    for av in (b"Cisco-AVPair=ip:inacl#1=permit tcp any any established log-input",
               b"Aruba-User-Role=authenticated-employee-vlan-200-floor3-corp-secure",
               b"Class=CACS:0a000101000000AB5F2C9E:ise01/512345678/9876543210/xyz"):
        check(len(av) >= cfg.radius_opaque_min_len,
              f"fixture must clear the length gate to test the run bands: "
              f"{len(av)} < {cfg.radius_opaque_min_len}")
        check(classify_opacity(av, cfg) == "cleartext",
              f"a real AV-pair must classify as cleartext: {av[:30]!r}")
    check(classify_opacity(b"Cisco-AVPair=shell:priv-lvl=15", cfg) == "unknown",
          "a SHORT printable AV-pair is not judged at all - the length gate "
          "runs before the content test")
    for seed in range(1, 8):
        check(classify_opacity(prand(180, seed), cfg) == "opaque",
              f"random 180-byte payload (seed {seed}) must classify as opaque")

    # Short values are never judged, whatever they contain.
    check(classify_opacity(prand(16), cfg) == "unknown",
          "below radius_opaque_min_len nothing is judged")

    # The middle band must genuinely exist and emit nothing.
    mid = b"\x00" * 40 + b"printable-ish-run-here" + b"\x01\x02" * 20
    check(classify_opacity(mid, cfg) in ("unknown", "cleartext"),
          "a mixed buffer must not be called opaque")
    check(cfg.radius_opaque_print_run_max < cfg.radius_cleartext_print_run_min,
          "the opaque and cleartext run bands must not touch - the gap IS the "
          "unknown band, and a classifier with no abstain band guesses")



def test_suppression() -> None:
    bare = _mk_radius(RADIUS_ACCESS_REQUEST, 2, [(RADIUS_ATTR_USER_NAME, 8)])
    fr = _mk_eth(b"\x01" * 6, b"\x02" * 6, ETH_P_IPV4,
              _mk_ipv4("10.0.0.1", "10.0.0.2", IPPROTO_UDP, _mk_udp(50000, 1812, bare)))
    eng = RadiusEngine(Config())
    for i in range(5):
        eng.handle_frame(fr, ts=2000.0 + i)
    hits = [f for f in eng.findings if f.code == "RDW-102"]
    check(len(hits) == 1, f"5 detections should raise 1 alert, got {len(hits)}")

    eng = RadiusEngine(Config(suppress_s=1))
    for i in range(3):
        eng.handle_frame(fr, ts=3000.0 + i * 10)
    hits = [f for f in eng.findings if f.code == "RDW-102"]
    check(len(hits) == 3, "past the window each detection alerts again")
    check(hits[1].detail.get("suppressed_since_last") == 1,
          "a re-fire carries the suppressed count")




# ---- radiuswatch fixtures --------------------------------------------------

NAS4, SRV4 = "10.0.0.1", "10.0.0.2"
NAS6 = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"
SRV6 = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x02"
EH_KINDS = ((None, "plain"), (IPV6_EXT_HOPOPT, "HBH"), (IPV6_EXT_ROUTING, "Routing"),
            (IPV6_EXT_FRAGMENT, "Fragment"), (IPV6_EXT_AH, "AH"),
            (IPV6_EXT_DSTOPTS, "Dest-Opts"))
STACKS = [("v4", None)] + [("v6", k) for k, _ in EH_KINDS]


def fr(pkt: bytes, request: bool = True, stack: str = "v4",
       eh: Optional[int] = None, sport: int = 50000, dport: int = 1812,
       proto: int = IPPROTO_UDP, l4: Optional[bytes] = None) -> bytes:
    """NAS<->server frame. request=True: NAS -> server, else server -> NAS."""
    if l4 is None:
        sp, dp = (sport, dport) if request else (dport, sport)
        l4 = (_mk_udp(sp, dp, pkt) if proto == IPPROTO_UDP
              else _mk_tcp(sp, dp, pkt))
    if stack == "v4":
        s, d = (NAS4, SRV4) if request else (SRV4, NAS4)
        return _mk_eth(b"\x02" * 6, b"\x04" * 6, ETH_P_IPV4,
                       _mk_ipv4(s, d, proto, l4))
    s, d = (NAS6, SRV6) if request else (SRV6, NAS6)
    if eh is None:
        return _mk_eth(b"\x02" * 6, b"\x04" * 6, ETH_P_IPV6,
                       _mk_ip6(proto, l4, src=s, dst=d))
    return _mk_eth(b"\x02" * 6, b"\x04" * 6, ETH_P_IPV6,
                   _mk_ip6(eh, _mk_exthdr(eh, proto) + l4, src=s, dst=d))


def _rv(code: int, ident: int, attrs, auth: bytes = b"\xaa" * 16) -> bytes:
    return _mk_radius_v(code, ident, attrs, auth)


MA = (RADIUS_ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16)
UN = (RADIUS_ATTR_USER_NAME, b"op")


def eap_attr(eap: bytes) -> list:
    """Split an EAP packet into <=253-byte EAP-Message attributes."""
    return [(RADIUS_ATTR_EAP_MESSAGE, eap[i:i + 253])
            for i in range(0, len(eap), 253)] or [(RADIUS_ATTR_EAP_MESSAGE, b"")]


def mk_eap(code: int, ident: int, etype: int, data: bytes) -> bytes:
    return bytes([code, ident]) + struct.pack("!H", 5 + len(data)) \
        + bytes([etype]) + data


def wimax_vsa(wtype: int, value: bytes, cont: bool = False,
              wlen: Optional[int] = None) -> tuple[int, bytes]:
    wl = 3 + len(value) if wlen is None else wlen
    return (RADIUS_ATTR_VENDOR_SPECIFIC,
            VENDOR_WIMAX.to_bytes(4, "big")
            + bytes([wtype, wl, WIMAX_CONTINUATION if cont else 0]) + value)


def std_vsa(vendor: int, vtype: int, value: bytes) -> tuple[int, bytes]:
    if vendor == VENDOR_LUCENT:
        sub = vtype.to_bytes(2, "big") + bytes([3 + len(value)]) + value
    else:
        sub = bytes([vtype, 2 + len(value)]) + value
    return (RADIUS_ATTR_VENDOR_SPECIFIC, vendor.to_bytes(4, "big") + sub)


def abinary(ftype: int = 0, glen: int = 7) -> bytes:
    return bytes([ftype, 1, 0, 0]) + struct.pack("!HHH", 0, glen, 0) \
        + b"\x00" * 22


# ---- elliptic-curve test helpers (a = -3); used only to MAKE fixtures -----

def _ec_add(gid: int, P, Q):
    p = EC_GROUPS[gid]["p"]
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] - 3) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def _ec_mul(gid: int, k: int, P=None):
    g = EC_GROUPS[gid]
    P = P or (g["gx"], g["gy"])
    R = None
    while k:
        if k & 1:
            R = _ec_add(gid, R, P)
        P = _ec_add(gid, P, P)
        k >>= 1
    return R


def pwd_commit(gid: int, x: int, y: int, s: int) -> bytes:
    pl = EC_GROUPS[gid]["plen"]
    return x.to_bytes(pl, "big") + y.to_bytes(pl, "big") + s.to_bytes(pl, "big")


def pwd_eap(code: int, ident: int, payload: bytes, flags: int = PWD_EXCH_COMMIT,
            total: Optional[int] = None) -> bytes:
    data = bytes([flags])
    if flags & PWD_FLAG_L:
        data += struct.pack("!H", len(payload) if total is None else total)
    return mk_eap(code, ident, EAP_TYPE_PWD, data + payload)


def valid_commit(gid: int, k: int = 7, s: int = 12345) -> bytes:
    x, y = _ec_mul(gid, k)
    return pwd_commit(gid, x, y, s)


STATE1 = (RADIUS_ATTR_STATE, b"state-0001")


def pwd_exchange(peer_commit: bytes, server_commit: bytes, stack="v4", eh=None,
                 link_state: bool = True):
    chal = _rv(RADIUS_ACCESS_CHALLENGE, 9,
               [MA, STATE1] + eap_attr(pwd_eap(EAP_REQUEST, 3, server_commit)))
    req_attrs = [MA] + ([STATE1] if link_state else []) \
        + eap_attr(pwd_eap(EAP_RESPONSE, 3, peer_commit))
    req = _rv(RADIUS_ACCESS_REQUEST, 10, req_attrs)
    return [fr(chal, False, stack, eh), fr(req, True, stack, eh)]


def sim_eap(attrs: list[tuple[int, int, bytes]], code: int = EAP_RESPONSE,
            etype: int = EAP_TYPE_SIM) -> bytes:
    body = bytes([11, 0, 0])  # subtype Start, reserved
    for t, units, val in attrs:
        body += bytes([t, units]) + val
    return mk_eap(code, 5, etype, body)


# Canonical trigger per NEW code. Each is a list of RADIUS frames builders
# taking (stack, eh). Shared with the conformance tier.
def new_code_fixtures() -> dict[str, Callable[[str, Optional[int]], list[bytes]]]:
    gid = 19
    x, y = _ec_mul(gid, 7)
    return {
        "RDW-120": lambda st, eh: [fr(_rv(1, 1, [MA, UN, (2, b"\x11" * 16)]),
                                      True, st, eh)],
        "RDW-121": lambda st, eh: [fr(_rv(1, 1, [MA, UN, (3, b"\x01" + b"\x22" * 16)]),
                                      True, st, eh)],
        "RDW-122": lambda st, eh: [fr(_rv(1, 1, [MA] + eap_attr(
            mk_eap(EAP_RESPONSE, 2, EAP_TYPE_MD5, b"\x10" + b"\x33" * 16))),
            True, st, eh)],
        "RDW-124": lambda st, eh: [fr(_rv(43, 1, [UN]), False, st, eh,
                                      dport=3799)],
        "RDW-125": lambda st, eh: [
            fr(b"", True, st, eh, dport=2083, proto=IPPROTO_TCP),
            fr(_rv(1, 1, [MA, UN]), True, st, eh)],
        "RDW-215": lambda st, eh: [fr(_rv(1, 1, [UN, wimax_vsa(1, b"ab", wlen=40)]),
                                      True, st, eh)],
        "RDW-216": lambda st, eh: [fr(_rv(1, 1, [UN, (137, b"")]), True, st, eh)],
        "RDW-217": lambda st, eh: pwd_exchange(pwd_commit(gid, x, y, 999),
                                               pwd_commit(gid, x, y, 999), st, eh),
        "RDW-218": lambda st, eh: pwd_exchange(pwd_commit(gid, x, y + 1, 999),
                                               valid_commit(gid, 5), st, eh),
        "RDW-219": lambda st, eh: [fr(_rv(1, 1, [MA] + eap_attr(
            sim_eap([(5, 1, b"\x00\x00")]))), True, st, eh)],
        "RDW-220": lambda st, eh: [fr(_rv(1, 1, [UN, std_vsa(VENDOR_ASCEND, 242,
                                                            abinary(0, 7))]),
                                      True, st, eh)],
        "RDW-221": lambda st, eh: [fr(_rv(1, 1, [UN, std_vsa(VENDOR_ASCEND, 214,
                                                            b"\x00" * 15)]),
                                      True, st, eh)],
    }


def _crun(frames, cfg=None) -> set:
    return _codes(_run(frames, cfg))


# ---- tests -----------------------------------------------------------------

def test_d8_direction() -> None:
    """D8: direction from the CODE. aristaguard read it from the port."""
    req = _rv(1, 7, [UN])
    acc = _rv(2, 7, [MA, (RADIUS_ATTR_PROXY_STATE, b"x" * 10)])
    c = _crun([fr(req, True, sport=1812), fr(acc, False, sport=1812)])
    check("RDW-212" in c, f"D8: 1812->1812 injected Proxy-State must fire, got {c}")
    bad = _rv(2, 9, [UN])
    c = _crun([fr(bad, False, sport=1812)], Config(known_infra=(SRV4,)))
    check("RDW-110" in c, "D8: 1812->1812 Accept from a known_infra server -> RDW-110")
    c = _crun([fr(bad, False, sport=1812)], Config(known_infra=(NAS4,)))
    check("RDW-110" not in c, "D8: scoping must use the SERVER, not the NAS")
    eng = _run([fr(req, True, sport=1812)])
    check(len(eng.radius_pending) == 1, "D8: a request enters the pending table")
    eng = _run([fr(acc, False, sport=1812)])
    check(len(eng.radius_pending) == 0,
          "D8: a RESPONSE must never be inserted as a request")
    # CoA roles: the SERVER originates CoA-Request.
    eng = _run([fr(_rv(43, 1, [UN]), False, dport=3799)],
               Config(known_infra=(SRV4,)))
    f = [x for x in eng.findings if x.code == "RDW-124"]
    check(len(f) == 1 and f[0].detail["server"] == SRV4
          and f[0].detail["nas"] == NAS4,
          "CoA-Request: server is the SOURCE, NAS the destination")
    eng = _run([fr(_rv(44, 1, [UN]), True, sport=3799)])
    check("RDW-124" not in _codes(eng), "a CoA-ACK is never RDW-124")
    eng = _run([fr(_rv(99, 1, [UN]), True)])
    check(eng.stats["radius_unknown_code"] == 1 and len(eng.radius_pending) == 0,
          "an unknown code is counted and never placed as request or response")
    check("RDW-101" in _codes(eng), "an unknown code is still cleartext RADIUS")


def test_rdw110_request_had_ma() -> None:
    bad = _rv(2, 3, [UN])
    def det(frames):
        e = _run(frames)
        f = [x for x in e.findings if x.code == "RDW-110"]
        return f[0].detail if f else {}
    d = det([fr(_rv(1, 3, [MA, UN])), fr(bad, False)])
    check(d.get("request_had_ma") is True and "policy_mismatch" in d,
          f"signed request + unsigned response -> request_had_ma True, got {d}")
    d = det([fr(_rv(1, 3, [UN])), fr(bad, False)])
    check(d.get("request_had_ma") is False and "policy_mismatch" not in d,
          "unsigned request -> request_had_ma False, no mismatch claim")
    d = det([fr(bad, False)])
    check(d.get("request_had_ma") == "unobserved",
          "no observed request -> 'unobserved', never a guess")
    check("RDW-123" not in FINDINGS and "RDW-123" in RETIRED_CODES,
          "RDW-123 is folded, never live")


def test_posture_pairs() -> None:
    pap = _rv(1, 1, [MA, UN, (2, b"\x11" * 16)])
    eng = RadiusEngine(Config())
    for i in range(5):
        eng.handle_frame(fr(pap), ts=1000.0 + i)
    check(sum(f.code == "RDW-120" for f in eng.findings) == 1,
          "RDW-120 once per pair inside the re-emit window")
    eng.handle_frame(fr(pap), ts=1000.0 + 86400)
    check(sum(f.code == "RDW-120" for f in eng.findings) == 2,
          "RDW-120 re-emits after posture_reemit_s (Decision 4)")
    eng = RadiusEngine(Config(posture_reemit_s=10))
    eng.handle_frame(fr(pap), ts=0.0)
    eng.handle_frame(fr(pap), ts=9.999)
    eng.handle_frame(fr(pap), ts=10.0)
    check(sum(f.code == "RDW-120" for f in eng.findings) == 2,
          "re-emit boundary: 9.999 s silent, exactly 10 s re-emits")
    eng = _run([fr(pap), fr(pap, stack="v6")])
    check(sum(f.code == "RDW-120" for f in eng.findings) == 2,
          "a different pair (family) gets its own posture finding")
    check("RDW-120" not in _crun([fr(pap)], Config(known_infra=("10.9.9.9",))),
          "known_infra scopes posture (exposure)")
    check("RDW-120" in _crun([fr(pap)], Config(known_infra=(SRV4,))),
          "an in-scope server still surfaces")
    check("RDW-120" not in _crun([fr(_rv(1, 1, [MA, UN]))]), "no PAP, no RDW-120")
    check("RDW-121" in _crun([fr(_rv(1, 1, [MA, UN, (3, b"\x01" * 17)]))]),
          "CHAP-Password -> RDW-121")
    check("RDW-124" not in _crun([fr(_rv(43, 1, [MA, UN]), False, dport=3799)]),
          "a signed CoA-Request is silent")
    check("RDW-124" in _crun([fr(_rv(40, 1, [UN]), False, dport=3799)]),
          "unsigned Disconnect-Request -> RDW-124")
    eng = RadiusEngine(Config(pair_registry_max=8))
    for i in range(40):
        eng.handle_frame(_mk_eth(b"\x02" * 6, b"\x04" * 6, ETH_P_IPV4,
                                 _mk_ipv4(f"10.1.0.{i}", SRV4, IPPROTO_UDP,
                                          _mk_udp(50000, 1812, pap))), ts=float(i))
    check(len(eng.pairs) <= 8 and len(eng.cleartext_pairs) <= 8,
          "pair registries are bounded by pair_registry_max")
    for f in eng.findings:
        check(b"\x11" * 4 not in json.dumps(f.detail).encode(), "no password bytes")


def test_radsec_presence() -> None:
    syn = fr(b"", True, dport=2083, proto=IPPROTO_TCP)
    clr = fr(_rv(1, 1, [MA, UN]))
    check("RDW-125" in _crun([syn, clr]), "RadSec then cleartext -> RDW-125")
    check("RDW-125" in _crun([clr, syn]), "cleartext then RadSec -> RDW-125")
    dtls = fr(b"\x16\xfe\xfd", True, dport=2083)
    check("RDW-125" in _crun([dtls, clr]), "DTLS/UDP 2083 counts as RadSec")
    check("RDW-125" not in _crun([syn]), "RadSec alone is silent")
    check("RDW-125" not in _crun([clr]), "cleartext alone is RDW-101, not RDW-125")
    other = _mk_eth(b"\x02" * 6, b"\x04" * 6, ETH_P_IPV4,
                    _mk_ipv4("10.5.5.5", SRV4, IPPROTO_TCP, _mk_tcp(40000, 2083, b"")))
    check("RDW-125" not in _crun([other, clr]), "a DIFFERENT NAS on RadSec is silent")
    synack = fr(b"", False, dport=2083, proto=IPPROTO_TCP)
    check("RDW-125" in _crun([synack, clr]),
          "server->NAS RadSec segment resolves the same pair")
    eng = _run([syn])
    check(eng.stats["radsec_segments"] == 1 and "RDW-101" not in _codes(eng),
          "RadSec is presence-only: never parsed as RADIUS")


def test_decoder_shapes() -> None:
    def one(attrs, cfg=None, code=1):
        return _crun([fr(_rv(code, 1, attrs))], cfg)
    # RDW-215
    check("RDW-215" in one([UN, wimax_vsa(1, b"ab", wlen=40)]), "WiMAX len > data")
    check("RDW-215" in one([UN, wimax_vsa(1, b"ab", wlen=2)]), "WiMAX len < header")
    check("RDW-215" in one([UN, wimax_vsa(1, b"ab", cont=True)]),
          "C bit on the LAST attribute -> continuation_without_next")
    check("RDW-215" not in one([UN, wimax_vsa(1, b"ab", cont=True),
                                wimax_vsa(1, b"cd")]),
          "C bit followed by the same WiMAX type is legal")
    check("RDW-215" in one([UN, wimax_vsa(1, b"ab", cont=True),
                            wimax_vsa(2, b"cd")]),
          "C bit followed by a DIFFERENT WiMAX type -> fires")
    check("RDW-215" in one([UN, wimax_vsa(1, b"", cont=True), wimax_vsa(1, b"cd")]),
          "C bit with an EMPTY value fires even when the continuation follows")
    check("RDW-215" not in one([UN, wimax_vsa(1, b"abc"), wimax_vsa(2, b"\x00")]),
          "well-formed WiMAX is silent")
    # RDW-216
    check("RDW-216" in one([UN, (137, b"")]), "zero-length PKM-SS-Cert")
    for t in (138, 144, 180):
        check("RDW-216" in one([UN, (t, b"")]), f"zero-length concat type {t}")
    check("RDW-216" not in one([UN, (79, b"")]), "EAP-Start (4f 02) silent by default")
    check("RDW-216" in one([UN, (79, b"")], Config(radius_flag_eap_start=True)),
          "radius_flag_eap_start reports it")
    check("RDW-216" not in one([UN, (137, b"x")]), "1-byte concat is silent")
    check("RDW-216" not in one([UN, (1, b"")]), "zero-length NON-concat is not this CVE")
    # RDW-220
    for v, t in sorted(ABINARY_VSAS):
        check("RDW-220" in one([UN, std_vsa(v, t, abinary(0, 7))]),
              f"abinary overflow vendor {v} type {t}")
    check("RDW-220" not in one([UN, std_vsa(VENDOR_ASCEND, 242, abinary(0, 6))]),
          "generic len == 6 is in bounds")
    check("RDW-220" not in one([UN, std_vsa(VENDOR_ASCEND, 242, abinary(1, 900))]),
          "IP filter (type 1) is not the generic path")
    check("RDW-220" not in one([UN, std_vsa(VENDOR_ASCEND, 242,
                                            abinary(0, 7)[:31])]),
          "a non-32-byte value prints as hex, never decoded")
    check("RDW-220" not in one([UN, std_vsa(9, 242, abinary(0, 7))]),
          "vendor 9 type 242 is not abinary")
    # RDW-221
    check("RDW-221" in one([UN, std_vsa(VENDOR_ASCEND, 214, b"\x00" * 15)]),
          "15-byte Ascend-Send-Secret")
    check("RDW-221" in one([UN, std_vsa(VENDOR_ASCEND, 215, b"")]),
          "empty Ascend-Receive-Secret")
    check("RDW-221" not in one([UN, std_vsa(VENDOR_ASCEND, 214, b"\x00" * 16)]),
          "16 bytes is the legal size")
    check("RDW-221" not in one([UN, std_vsa(VENDOR_LUCENT, 214, b"\x00")]),
          "only Ascend's 214/215 carry encrypt=3")
    # reachable_unauthenticated
    e = _run([fr(_rv(1, 1, [UN, (137, b"")]))])
    check(e.findings[-1].detail.get("reachable_unauthenticated") is True
          or any(f.detail.get("reachable_unauthenticated") is True
                 for f in e.findings if f.code == "RDW-216"),
          "unsigned Access-Request is reachable unauthenticated")
    e = _run([fr(_rv(1, 1, [MA, UN, (137, b"")]))])
    check(any(f.detail.get("reachable_unauthenticated") is False
              for f in e.findings if f.code == "RDW-216"),
          "a signed request is not")
    check(any(f.klass == "attack" for f in e.findings if f.code == "RDW-216"),
          "decoder shapes are ATTACK class")
    check("RDW-216" in _crun([fr(_rv(1, 1, [UN, (137, b"")]))],
                             Config(known_infra=("10.9.9.9",))),
          "attack codes are never scoped by known_infra")
    # malformed VSAs never raise
    for junk in (b"", b"\x00", b"\x00\x00\x02\x11", b"\x00\x00\x60\xb5\x01",
                 b"\x00\x00\x12\xee\x00\xf2\x00", b"\x00\x00\x02\x11\xd6\x01"):
        try:
            inspect_vsa(junk)
            ok = True
        except Exception:  # noqa: BLE001
            ok = False
        check(ok, f"inspect_vsa never raises on {junk.hex()}")


def test_eap_rules() -> None:
    md5 = mk_eap(EAP_RESPONSE, 2, EAP_TYPE_MD5, b"\x10" + b"\x33" * 16)
    check("RDW-122" in _crun([fr(_rv(1, 1, [MA] + eap_attr(md5)))]),
          "EAP-MD5 Response -> RDW-122")
    leap = mk_eap(EAP_RESPONSE, 2, EAP_TYPE_LEAP, b"\x01\x00\x18" + b"\x00" * 24)
    check("RDW-122" in _crun([fr(_rv(1, 1, [MA] + eap_attr(leap)))]), "LEAP -> RDW-122")
    nak = mk_eap(EAP_RESPONSE, 2, EAP_TYPE_NAK, bytes([25]))
    md5_offer = mk_eap(EAP_REQUEST, 2, EAP_TYPE_MD5, b"\x10" + b"\x44" * 16)
    check("RDW-122" not in _crun([
        fr(_rv(11, 1, [MA] + eap_attr(md5_offer)), False),
        fr(_rv(1, 2, [MA] + eap_attr(nak)))]),
          "server OFFERED MD5, peer NAK'd -> silent")
    # EAP-SIM
    def sim(attrs, code=1, request=True, etype=EAP_TYPE_SIM):
        ec = EAP_RESPONSE if request else EAP_REQUEST
        return _crun([fr(_rv(code, 1, [MA] + eap_attr(sim_eap(attrs, ec, etype))),
                         request)])
    check("RDW-219" in sim([(5, 1, b"\x00\x00")]), "unknown non-skippable 5")
    check("RDW-219" in sim([(25, 1, b"\x00\x00")]), "unknown non-skippable 25")
    check("RDW-219" in sim([(16, 0, b"")]), "zero length octet")
    check("RDW-219" not in sim([(200, 1, b"\x00\x00")]), "unknown SKIPPABLE is legal")
    check("RDW-219" not in sim([(16, 1, b"\x00\x01"), (7, 5, b"\x00" * 18)]),
          "registered attributes are silent")
    check("RDW-219" in sim([(5, 1, b"\x00\x00")], etype=EAP_TYPE_AKA), "EAP-AKA too")
    check("RDW-219" in sim([(5, 1, b"\x00\x00")], etype=EAP_TYPE_AKA_PRIME), "AKA'")
    check("RDW-219" not in sim([(5, 1, b"\x00\x00")], code=11, request=False),
          "server-sent SIM attributes are not the CVE direction")
    # EAP-pwd, all three groups
    for gid in (19, 20, 21):
        n = EC_GROUPS[gid]["n"]
        x, y = _ec_mul(gid, 11)
        good = pwd_commit(gid, x, y, 777)
        srv = valid_commit(gid, 5, 4242)
        check(not ({"RDW-217", "RDW-218"} & _crun(pwd_exchange(good, srv))),
              f"group {gid}: a valid peer Commit is silent")
        check("RDW-218" in _crun(pwd_exchange(pwd_commit(gid, x, y + 1, 777), srv)),
              f"group {gid}: off-curve element -> RDW-218")
        for bad_s in (0, 1, n, n + 1):
            if bad_s.bit_length() > EC_GROUPS[gid]["plen"] * 8:
                continue
            check("RDW-218" in _crun(pwd_exchange(pwd_commit(gid, x, y, bad_s), srv)),
                  f"group {gid}: scalar {bad_s if bad_s < 2 else 'n' if bad_s == n else 'n+1'}"
                  " out of range -> RDW-218")
        check("RDW-218" not in _crun(pwd_exchange(pwd_commit(gid, x, y, 2), srv)),
              f"group {gid}: scalar 2 is the lowest legal value")
        check("RDW-218" not in _crun(pwd_exchange(pwd_commit(gid, x, y, n - 1), srv)),
              f"group {gid}: scalar n-1 is the highest legal value")
        p = EC_GROUPS[gid]["p"]
        if p.bit_length() < EC_GROUPS[gid]["plen"] * 8:
            check("RDW-218" in _crun(pwd_exchange(pwd_commit(gid, x + p, y, 777), srv)),
                  f"group {gid}: coordinate >= p -> RDW-218")
        check("RDW-217" in _crun(pwd_exchange(srv, srv)),
              f"group {gid}: reflected Commit -> RDW-217")
    srv = valid_commit(19, 5)
    eng = _run(pwd_exchange(srv, srv, link_state=False))
    check("RDW-217" not in _codes(eng) and eng.stats["eap_pwd_reflection_unlinked"] == 1,
          "no State link -> reflection cannot be judged; counted, silent")
    # Fragmented (Decision 3)
    x, y = _ec_mul(19, 3)
    bad = pwd_commit(19, x, y + 1, 5)
    frag = pwd_eap(EAP_RESPONSE, 3, bad[:50], PWD_EXCH_COMMIT | PWD_FLAG_L | PWD_FLAG_M,
                   total=96)
    eng = _run([fr(_rv(1, 1, [MA] + eap_attr(frag)))])
    check("RDW-218" not in _codes(eng) and eng.stats["eap_pwd_unjudged_fragmented"] == 1,
          "a fragmented Commit is counted, never judged")
    first_of_two = pwd_eap(EAP_RESPONSE, 3, bad, PWD_EXCH_COMMIT | PWD_FLAG_L,
                           total=192)
    eng = _run([fr(_rv(1, 1, [MA] + eap_attr(first_of_two)))])
    check("RDW-218" not in _codes(eng) and eng.stats["eap_pwd_unjudged_fragmented"] == 1,
          "L total larger than this payload is a fragment even with M clear - "
          "a Commit-sized first fragment must not be judged")
    whole_l = pwd_eap(EAP_RESPONSE, 3, bad, PWD_EXCH_COMMIT | PWD_FLAG_L)
    check("RDW-218" in _crun([fr(_rv(1, 1, [MA] + eap_attr(whole_l)))]),
          "L bit with total == payload is a whole Commit and is judged")
    eng = _run([fr(_rv(1, 1, [MA] + eap_attr(pwd_eap(EAP_RESPONSE, 3, b"\x01" * 50))))])
    check(eng.stats["eap_pwd_unjudged_group"] == 1, "unknown Commit length counted")
    # Window
    eng = RadiusEngine(Config(eap_exchange_window_s=5))
    f1, f2 = pwd_exchange(srv, srv)
    eng.handle_frame(f1, ts=0.0)
    eng.handle_frame(f2, ts=6.0)
    check("RDW-217" not in _codes(eng), "server Commit ages out of the window")
    eng = RadiusEngine(Config(eap_exchange_max=4))
    for i in range(20):
        chal = _rv(11, i, [MA, (RADIUS_ATTR_STATE, b"s%03d" % i)]
                   + eap_attr(pwd_eap(EAP_REQUEST, 3, srv)))
        eng.handle_frame(fr(chal, False), ts=float(i))
    check(len(eng.eap_exchanges) <= 4, "EAP exchange table is bounded")


def test_ec_parameters() -> None:
    """The curve constants are typed in; prove them, don't trust them."""
    for gid, g in EC_GROUPS.items():
        check(ec_on_curve(gid, g["gx"], g["gy"]), f"group {gid}: G on curve")
        check(_ec_mul(gid, g["n"]) is None, f"group {gid}: n*G is the identity")
        check(g["p"].bit_length() <= g["plen"] * 8, f"group {gid}: plen fits p")
    check(PWD_COMMIT_LEN_TO_GROUP == {96: 19, 144: 20, 198: 21},
          "Commit lengths map to exactly groups 19/20/21")


def test_sim_registry_pinned() -> None:
    check(set(SIM_NON_SKIPPABLE) == {1, 2, 3, 4, 6, 7, 10, 11, 12, 13, 14, 15,
                                     16, 17, 19, 20, 21, 22, 23, 24},
          "SIM_NON_SKIPPABLE matches the IANA registry fetched Oct 16 2026")
    check(all(t < SIM_SKIPPABLE_MIN for t in SIM_NON_SKIPPABLE), "all < 128")


def test_catalog() -> None:
    cves = {e.cve for e in CVE_CATALOG}
    check(len(cves) == len(CVE_CATALOG), "no duplicate CVE")
    check(not (cves & set(DEFERRED_CVES)), "DEFERRED_CVES disjoint from catalog")
    for e in CVE_CATALOG:
        check(e.cvss >= Config().min_cvss, f"{e.cve} meets the 6.5 floor")
        check(e.score_confidence in ("nvd", "secondary"), f"{e.cve} confidence")
        if e.score_confidence == "nvd":
            check(e.vector.startswith("CVSS:3."), f"{e.cve}: NVD score carries vector")
        else:
            check("NVD" in e.note, f"{e.cve}: secondary score explains NVD's gap")
        for c in e.codes:
            check(c in FINDINGS, f"{e.cve} -> {c} is live")
            check(e.cve in FINDINGS[c].cves, f"{c} lists {e.cve} back")
    for code, spec in FINDINGS.items():
        for cve in spec.cves:
            check(cve in cves, f"{code} cites catalogued {cve}")
        check(spec.klass == ("attack" if code[4] == "2" else "exposure"),
              f"{code}: class matches its number band")
    for code in RETIRED_CODES:
        check(code not in FINDINGS, f"{code} retired, not live")
    for cve, why in list(DEFERRED_CVES.items()) + list(RETIRED_CODES.items()):
        check(len(why) >= 40, f"{cve}: reason is substantive")
    check(set(AG_MIGRATION.values()) <= set(FINDINGS), "migration targets live")
    check(all(k[3:] == v[4:] for k, v in AG_MIGRATION.items()),
          "migrated codes keep their digits")


def test_new_codes_dual_stack() -> None:
    """PRIME DIRECTIVE: every new code over IPv4, plain IPv6 and IPv6 behind
    each extension header type."""
    for code, mk in new_code_fixtures().items():
        for stack, eh in STACKS:
            got = _crun(mk(stack, eh))
            name = dict(EH_KINDS).get(eh, stack)
            check(code in got, f"{code} over {stack}/{name}: got {sorted(got)}")


def test_bpf_terms() -> None:
    for t in ("udp port 1812", "udp port 1813", "udp port 1645", "udp port 1646",
              "udp port 3799", "udp port 2083", "tcp port 2083"):
        check(t in BPF_FILTER, f"BPF has {t}")
    for nh in (0, 43, 44, 51, 60):
        check(f"ip6[6] = {nh}" in BPF_FILTER, f"BPF has ip6[6] = {nh}")
    check(BPF_FILTER.rstrip().endswith("vlan"), "vlan LAST")
    check("proto 51" not in BPF_FILTER,
          "no IPsec term here: ip6[6] = 51 is the only AH path (documented)")
    custom = build_bpf_filter(Config(radius_auth_ports=(18120,)))
    check("udp port 18120" in custom and "udp port 1812 " not in custom + " ",
          "the filter follows the configured ports")


def test_values_never_leak() -> None:
    mark = b"LEAKMARK"
    frames = [fr(_rv(1, 1, [(1, mark), (2, mark * 2), (3, b"\x01" + mark * 2),
                            (RADIUS_ATTR_PROXY_STATE, mark * 20),
                            std_vsa(VENDOR_ASCEND, 214, mark),
                            (RADIUS_ATTR_STATE, mark)]))]
    frames += [fr(_rv(2, 1, [(18, b"\xff" + mark), (RADIUS_ATTR_VENDOR_SPECIFIC,
                                                   b"\x00\x00\x00\x09" + mark)]),
                  False)]
    for f in _run(frames).findings:
        blob = f.to_json().encode()
        check(mark not in blob, f"{f.code} leaked an attribute value")


def test_config_and_learn() -> None:
    cfg = Config.load(json.loads(json.dumps(Config().dump())))
    check(cfg == Config(), "config round-trips through JSON")
    check(isinstance(cfg.radsec_ports, tuple), "lists become tuples")
    out: list = []
    eng = RadiusEngine(Config(learn=True), emit=out.append)
    eng.handle_frame(fr(_rv(1, 1, [UN])), ts=1.0)
    check(out == [] and eng.findings, "learn mode detects but emits nothing")


def test_passive_invariant() -> None:
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    banned_mod = {"socket", "subprocess", "ssl", "asyncio", "urllib", "http"}
    banned_call = {"send", "sendp", "sr", "sr1", "srp", "srp1", "sendpfast",
                   "sendto", "connect"}
    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) \
                else [node.module or ""]
            for m in mods:
                if m.split(".")[0] in banned_mod:
                    problems.append(f"imports {m}")
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else \
                fn.id if isinstance(fn, ast.Name) else ""
            if name in banned_call:
                problems.append(f"calls {name}()")
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            m = node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
            if (m or "").startswith("scapy"):
                problems.append("top-level scapy import")
    rc = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "run_capture")
    scapy_fns = {f.name for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                 and any(isinstance(n, ast.ImportFrom) and (n.module or "")
                         .startswith("scapy") for n in ast.walk(f))}
    check(scapy_fns == {"run_capture"}, f"scapy imported only in run_capture: {scapy_fns}")
    check(not problems, f"passive invariant: {problems}")
    check(rc is not None, "run_capture exists")


NEW_TESTS = (test_d8_direction, test_rdw110_request_had_ma, test_posture_pairs,
             test_radsec_presence, test_decoder_shapes, test_eap_rules,
             test_ec_parameters, test_sim_registry_pinned, test_catalog,
             test_new_codes_dual_stack, test_bpf_terms, test_values_never_leak,
             test_config_and_learn, test_passive_invariant)
CARRIED_TESTS = (test_radius_rules, test_radius_blastradius_fixes,
                 test_ipv6_extension_headers, test_blastradius_nas_side_leg,
                 test_opacity_classifier, test_suppression)


def selftest() -> int:
    for t in CARRIED_TESTS + NEW_TESTS:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            _FAILS.append(f"{t.__name__} raised {exc!r}")
    for f in _FAILS:
        print("FAIL:", f)
    print(f"{_CHECKS - len(_FAILS)}/{_CHECKS} checks passed")
    return 1 if _FAILS else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_catalog(cfg: Config) -> None:
    print(f"{DISPLAY_NAME} {__version__} - tracked CVEs (floor {cfg.min_cvss})")
    for e in CVE_CATALOG:
        if e.cvss < cfg.min_cvss:
            continue
        print(f"  {e.cve:16} {e.cvss:4}  {e.score_confidence:9} "
              f"{','.join(e.codes):40} {e.title}")
    print("Deferred (triaged out):")
    for cve, why in DEFERRED_CVES.items():
        print(f"  {cve:16} {why}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog=MODULE, description=(
        f"{DISPLAY_NAME} - passive RADIUS / EAP detector (Blast-RADIUS, "
        "FreeRADIUS wire-shape CVEs, auth posture)"))
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--selftest", action="store_true", help="offline self-test")
    ap.add_argument("--print-catalog", action="store_true")
    ap.add_argument("--print-codes", action="store_true",
                    help="machine-readable live finding codes")
    ap.add_argument("--print-config", action="store_true")
    ap.add_argument("--print-bpf", action="store_true")
    ap.add_argument("--iface", help="interface to capture on")
    ap.add_argument("--pcap", help="read a capture file through the same BPF")
    ap.add_argument("--config", help="path to a json config file")
    ap.add_argument("--learn", action="store_true",
                    help="baseline mode: detect but emit nothing")
    ap.add_argument("--timeout", type=int, default=0)
    ap.add_argument("--stats", action="store_true",
                    help="print engine counters to stderr on exit")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    cfg = Config()
    if a.config:
        with open(a.config, encoding="utf-8") as fh:
            cfg = Config.load(json.load(fh))
    for k in ("iface", "pcap"):
        if getattr(a, k):
            setattr(cfg, k, getattr(a, k))
    if a.learn:
        cfg.learn = True
    if a.timeout:
        cfg.timeout = a.timeout
    if a.print_catalog:
        print_catalog(cfg)
        return 0
    if a.print_codes:
        print("\n".join(sorted(FINDINGS)))
        return 0
    if a.print_config:
        print(json.dumps(cfg.dump(), indent=2, sort_keys=True))
        return 0
    if a.print_bpf:
        print(build_bpf_filter(cfg))
        return 0

    def emit(f: Finding) -> None:
        print(f.to_json(), flush=True)

    eng = RadiusEngine(cfg, emit=emit)
    try:
        run_capture(cfg, eng)
    except KeyboardInterrupt:
        pass
    if a.stats:
        sys.stderr.write(json.dumps(eng.stats, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
