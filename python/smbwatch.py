#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smbwatch  --  Passive SMB / NTLM-relay attack-surface monitor for Ragnar
============================================================================

Part of the Ragnar network-engineering toolbox. Passive-first, detection-only,
in keeping with the rest of the suite (macwatch / arp_guard / dnswatch /
dhcp_doctor / igmpwatch / ospfwatch). Nothing here transmits, injects, spoofs,
answers, or probes. It only listens on a mirror/SPAN port (or a bridged tap)
and reports.

Thesis
------
smbwatch watches BOTH halves of the classic Windows credential-relay chain
from a single vantage point:

  FRONT HALF  -- name-resolution poisoning (Responder / Inveigh):
                 LLMNR (udp/5355), NBT-NS (udp/137), mDNS (udp/5353).
                 An attacker answers name queries -- especially for names that
                 do not exist, or WPAD -- to lure a victim into authenticating
                 to an attacker-controlled endpoint.

  BACK HALF   -- the SMB endpoint the victim then hits:
                 * SMBv1 (CIFS) negotiated on the wire  -> deprecated + the
                   EternalBlue/DoublePulsar surface.
                 * SMB2/3 signing NOT required by the server -> that server is
                   a valid *relay target*; captured NTLM can be relayed to it.

Seeing both on one tap tells you not just "someone is poisoning names" but
"...and here are the boxes they can cash the hashes out against."

Detection heuristics (name poisoning)
-------------------------------------
  R1  WPAD answered over LLMNR/NBT-NS/mDNS            -> CRITICAL
      (MS16-077 disabled WPAD-via-LLMNR/NBT-NS by default; an answer for it is
       almost always Responder-class activity.)
  R2  One responder IP answers for >= N distinct names in a window -> HIGH
      (a legitimate host answers for its own name(s) only.)
  R3  Same name answered by 2+ distinct responders / with conflicting IPs
      inside a window                                 -> MEDIUM
      (the poisoner races the real owner.)
  R4  One responder IP answers the same name across 2+ of the three protocols
                                                       -> HIGH
      (Responder listens on all three at once; ordinary hosts don't.)
  R5  First time a given IP is seen answering names   -> INFO (baseline)

Detection heuristics (SMB posture)
----------------------------------
  S1  SMBv1 negotiate response selecting a real dialect -> MEDIUM
  S2  SMB2/3 server negotiate: signing NOT required     -> HIGH  (relay target)
  S3  SMBv1 server negotiate: signing not required      -> HIGH

Correlation (the money finding)
-------------------------------
  C1  A confirmed poisoner (R1/R2/R4) sharing the monitored segment with either
      an unsigned relay target (S2/S3) or a Kerberos-downgrade client (strong
      K-rules)                                          -> CRITICAL / HIGH
      One finding per poisoner. CRITICAL when a real relay path exists; HIGH
      when only a downgrade client keeps it company. Re-fires only when a new
      target or downgrade client appears.

Detection heuristics (Kerberos downgrade)
-----------------------------------------
  Request side -- what a client OFFERS (AS-REQ / TGS-REQ):
    K1  offers DES (etype 1/3)                          -> HIGH
    K2  offers RC4 (etype 23/24)                        -> MEDIUM
        (HIGH when RC4 is the most-preferred etype -- an explicit downgrade)
    K3  offers no AES at all                            -> HIGH
  Reply side -- what the KDC actually GRANTS (AS-REP / TGS-REP), read from the
  cleartext etype of the ticket's / reply's EncryptedData:
    K4  KDC granted RC4 (crackable ticket on the wire) -> HIGH
    K5  KDC granted DES                                 -> CRITICAL
      The reply side catches the KDC handing out RC4 service tickets
      (Kerberoastable) even when the offer looked benign. Etypes are parsed
      with a small custom DER walk (no library dissector).

Design notes
------------
* Single entry point:  SMBWatch.process_packet(scapy_pkt).  Live capture, pcap
  replay, and the self-test harness all funnel through it, so what you test is
  exactly what runs in production.
* SMB negotiate parsing is done at the byte level (framing-agnostic: works for
  direct-hosted tcp/445 and NBT-framed tcp/139). We deliberately do NOT lean on
  Scapy's partial SMB2 layer.
* Pi Zero 2W is the test floor. The BPF filter is narrow and per-packet work is
  cheap; the only caveat is the usual USB-2 bus-contention note if you run the
  capture NIC and an inline bridge on the same hub (see dhcp_doctor).

Self-test:   python3 smbwatch.py --self-test
Live:        sudo python3 smbwatch.py -i eth0
Replay:      python3 smbwatch.py --pcap capture.pcap
Unit file:   python3 smbwatch.py --print-unit
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import json
import re
import struct
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Deque, Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
#  Build identity
# --------------------------------------------------------------------------- #
#  Emitted with every JSON finding and printed by --version. An alert read in a
#  dashboard hours later must be attributable to the exact detection logic that
#  raised it; RULE_SET_ID is the cheap fingerprint for that, because two builds
#  can share a version string but implement different rules.
# --------------------------------------------------------------------------- #
__version__ = "0.4.0-dev"

RULE_SET = (
    "R1", "R2", "R3", "R4", "R5",          # name poisoning
    "S1", "S2", "S3",                      # SMB posture
    "C1", "C2",                            # correlation
    "K1", "K2", "K3", "K4", "K5", "K6", "K7",   # Kerberos
    "N1", "N2", "N3",                      # NTLM relay in progress
    "V1", "V2", "V3", "V4", "V5", "V6",    # named CVEs
    "F1", "F2", "F3", "F4", "F5",          # SMB file operations / credential exfil
)
RULE_SET_ID = "%d:%s" % (
    len(RULE_SET),
    hashlib.sha256(",".join(RULE_SET).encode()).hexdigest()[:8],
)


# --------------------------------------------------------------------------- #
# Scapy is imported lazily so that --help / --print-unit work without root or
# without scapy present. Capture/self-test need it.
# --------------------------------------------------------------------------- #
def _import_scapy():
    from scapy.all import (  # noqa: F401
        sniff, rdpcap, IP, IPv6, UDP, TCP, DNS, DNSQR, DNSRR, Raw,
    )
    from scapy.layers.netbios import NBNSHeader, NBNSQueryResponse  # noqa: F401
    import scapy.all as _s
    return _s


# =========================================================================== #
#  Constants
# =========================================================================== #

# SMB dialect revisions (SMB2 NEGOTIATE Response DialectRevision field)
SMB2_DIALECTS = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
    0x02FF: "SMB2 wildcard (2.???)",
}

# SMB2 NEGOTIATE Response SecurityMode flags
SMB2_SIGNING_ENABLED  = 0x0001
SMB2_SIGNING_REQUIRED = 0x0002

# SMB1 NEGOTIATE Response SecurityMode byte flags
SMB1_SIGNING_ENABLED  = 0x04
SMB1_SIGNING_REQUIRED = 0x08

SMB2_MAGIC = b"\xfeSMB"
SMB2_TRANSFORM_MAGIC = b"\xfdSMB"   # encrypted SMB3
SMB1_MAGIC = b"\xffSMB"

SMB2_CMD_NEGOTIATE = 0x0000
SMB1_CMD_NEGOTIATE = 0x72
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001

# ---- SMB2 file-operation tier (F-series) ---------------------------------- #
#  Commands (MS-SMB2 2.2.1.2 Command). smbwatch previously knew only NEGOTIATE;
#  the file tier needs the three that carry a share name, a path or an FSCTL.
SMB2_CMD_TREE_CONNECT = 0x0003
SMB2_CMD_CREATE       = 0x0005
SMB2_CMD_CLOSE        = 0x0006
SMB2_CMD_READ         = 0x0008
SMB2_CMD_WRITE        = 0x0009
SMB2_CMD_IOCTL        = 0x000B

# SMB2 header (MS-SMB2 2.2.1.2), offsets from the start of the header
SMB2_HDR_LEN          = 64
SMB2_OFF_COMMAND      = 12
SMB2_OFF_FLAGS        = 16
SMB2_OFF_NEXT_COMMAND = 20
SMB2_OFF_MESSAGE_ID   = 24
SMB2_OFF_TREE_ID      = 36

# TREE_CONNECT request (MS-SMB2 2.2.9)
SMB2_TC_OFF_PATH_OFFSET = SMB2_HDR_LEN + 4      # 68
SMB2_TC_OFF_PATH_LENGTH = SMB2_HDR_LEN + 6      # 70
# CREATE request (MS-SMB2 2.2.13). NameOffset counts from the HEADER start.
SMB2_CR_OFF_DESIRED_ACCESS = SMB2_HDR_LEN + 24  # 88
SMB2_CR_OFF_CREATE_DISPOSITION = SMB2_HDR_LEN + 36   # 100
SMB2_CR_OFF_CREATE_OPTIONS = SMB2_HDR_LEN + 40  # 104
SMB2_CR_OFF_NAME_OFFSET = SMB2_HDR_LEN + 44     # 108
SMB2_CR_OFF_NAME_LENGTH = SMB2_HDR_LEN + 46     # 110
SMB2_CR_STRUCTURE_SIZE = 57
# IOCTL request (MS-SMB2 2.2.31)
SMB2_IO_OFF_CTL_CODE = SMB2_HDR_LEN + 4         # 68

# Access / option bits we classify on (MS-DTYP 2.4.3, MS-SMB2 2.2.13)
FILE_READ_DATA        = 0x00000001
FILE_WRITE_DATA       = 0x00000002
ACCESS_DELETE         = 0x00010000
FILE_DELETE_ON_CLOSE  = 0x00001000

# FSCTL codes (MS-SMB2 2.2.31 / MS-FSCC 2.3)
FSCTL_SRV_ENUMERATE_SNAPSHOTS = 0x00144064

# Administrative shares the credential-exfil rules key on. impacket's
# secretsdump uses ADMIN$ exclusively (connectTree('ADMIN$')); C$ is included
# because a hand operator reaches the same files through it.
SMB_ADMIN_SHARES = {"admin$", "c$"}

# impacket's remote-execution output file -- a fixed literal, so it has no
# false-positive surface. psexec and smbexec land here too, not just
# secretsdump.
SMB_REMOTE_EXEC_OUTPUT = "temp\\__output"

# Credential stores that are essentially never read over SMB in normal
# operation. secretsdump deliberately does NOT take this path (it reads a
# randomly-named copy instead), so these catch hand operators and other tools.
SMB_CREDENTIAL_PATHS = (
    "system32\\config\\sam",
    "system32\\config\\security",
    "system32\\config\\system",
    "ntds.dit",
    "ntds.jfm",
)
SMB_CREDENTIAL_MARKERS = ("globalroot", "harddiskvolumeshadowcopy")
# EDB*.log transaction logs alongside ntds.dit
SMB_EDB_LOG_RE = re.compile(r"(^|\\)edb[0-9a-f]*\.log$", re.I)

# impacket: ''.join(random.choice(string.ascii_letters) for _ in range(8))+'.tmp'
# Measured against realistic Windows temp names: GetTempFileName emits
# <=3-char prefix + 4 HEX digits, so any digit disqualifies and the pattern
# collides with nothing in normal use.
SMB_TEMP_EXFIL_DEFAULT = r"^temp\\[A-Za-z]{8}\.tmp$"

# Bounds for per-flow reassembly on a Pi Zero 2W.
SMB_STREAM_MAX_BYTES = 128 * 1024
SMB_STREAM_MAX_FLOWS = 512
SMB2_MAX_MESSAGE = 16 * 1024 * 1024

# NetBIOS suffix -> human label (last byte of the 16-byte NetBIOS name)
NBT_SUFFIX = {
    0x00: "Workstation",
    0x03: "Messenger",
    0x1B: "Domain Master Browser",
    0x1C: "Domain Controllers",
    0x1D: "Master Browser",
    0x1E: "Browser Elections",
    0x20: "File Server",
}

# DNS RR types we care about for host poisoning
DNS_TYPE_A    = 1
DNS_TYPE_AAAA = 28

# Ports
PORT_NBTNS = 137
PORT_LLMNR = 5355
PORT_MDNS  = 5353
PORT_SMB   = 445
PORT_NBSS  = 139
PORT_KRB   = 88

PROTO_LLMNR = "LLMNR"
PROTO_NBTNS = "NBT-NS"
PROTO_MDNS  = "mDNS"
PROTO_KRB   = "Kerberos"

# Kerberos encryption types (RFC 3961/4120/8009). We only need to classify
# offered etypes in an AS-REQ as strong vs. weak.
KRB_ETYPE = {
    1:  "des-cbc-crc",
    3:  "des-cbc-md5",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    23: "rc4-hmac",
    24: "rc4-hmac-exp",
    -128: "rsadsi-rc4-md4",
}
KRB_ETYPE_DES  = {1, 3}
KRB_ETYPE_RC4  = {23, 24, -128}
KRB_ETYPE_WEAK = KRB_ETYPE_DES | KRB_ETYPE_RC4
KRB_ETYPE_AES  = {17, 18, 19, 20}

# Application tags (class=application, constructed): 0x60 | number
KRB_APP_AS_REQ  = 0x6A           # [APPLICATION 10] AS-REQ
KRB_APP_AS_REP  = 0x6B           # [APPLICATION 11] AS-REP
KRB_APP_TGS_REQ = 0x6C           # [APPLICATION 12] TGS-REQ
KRB_APP_TGS_REP = 0x6D           # [APPLICATION 13] TGS-REP
KRB_APP_TICKET  = 0x61           # [APPLICATION 1]  Ticket
KRB_APP_ERROR   = 0x7E           # [APPLICATION 30] KRB-ERROR
KRB_MSG_NAME = {KRB_APP_AS_REQ: "AS-REQ", KRB_APP_AS_REP: "AS-REP",
                KRB_APP_TGS_REQ: "TGS-REQ", KRB_APP_TGS_REP: "TGS-REP",
                KRB_APP_ERROR: "KRB-ERROR"}
KRB_REQ_APPS = (KRB_APP_AS_REQ, KRB_APP_TGS_REQ)
KRB_REP_APPS = (KRB_APP_AS_REP, KRB_APP_TGS_REP)

# PA-DATA / KRB-ERROR
KRB_PA_ENC_TIMESTAMP = 2         # padata-type for encrypted-timestamp pre-auth
KRB_ERR_C_PRINCIPAL_UNKNOWN = 6  # user does not exist -> enumeration probe
KRB_ERR_PREAUTH_FAILED = 24      # bad password -> spray / roast attempt
KRB_ERR_PREAUTH_REQUIRED = 25    # account requires pre-auth (NOT roastable)
KRB_ERR_NAME = {6: "C_PRINCIPAL_UNKNOWN", 7: "S_PRINCIPAL_UNKNOWN",
                18: "CLIENT_REVOKED", 24: "PREAUTH_FAILED", 25: "PREAUTH_REQUIRED"}

# SPN service classes that mean "SMB access to a host"
KRB_SMB_SERVICE_CLASSES = {"cifs", "host"}

# Context tags we navigate.
KRB_CTX_REQ_BODY = 0xA4          # [4] req-body (KDC-REQ)
KRB_CTX_REQ_PADATA = 0xA3        # [3] padata  (KDC-REQ, sibling of req-body)
KRB_CTX_PADATA_TYPE = 0xA1       # [1] padata-type (PA-DATA)
KRB_CTX_ETYPE  = 0xA8            # [8] etype  (SEQUENCE OF Int32, in KDC-REQ-BODY)
KRB_CTX_CNAME_REQ = 0xA1         # [1] cname  (in KDC-REQ-BODY)
KRB_CTX_SNAME_REQ = 0xA3         # [3] sname  (in KDC-REQ-BODY)
KRB_CTX_NAMESTRING = 0xA1        # [1] name-string inside PrincipalName
KRB_CTX_REALM_REQ = 0xA2         # [2] realm  (in KDC-REQ-BODY)
# KDC-REP fields
KRB_CTX_REP_CREALM = 0xA3        # [3] crealm
KRB_CTX_REP_CNAME  = 0xA4        # [4] cname
KRB_CTX_REP_TICKET = 0xA5        # [5] ticket
KRB_CTX_REP_ENCPART = 0xA6       # [6] enc-part (reply, EncryptedData)
# Ticket fields ([APPLICATION 1] SEQUENCE)
KRB_CTX_TKT_SNAME  = 0xA2        # [2] sname
KRB_CTX_TKT_ENCPART = 0xA3       # [3] enc-part (ticket, EncryptedData)
# EncryptedData field
KRB_CTX_ED_ETYPE   = 0xA0        # [0] etype
# KRB-ERROR fields
KRB_CTX_ERR_CODE   = 0xA6        # [6] error-code
KRB_CTX_ERR_CNAME  = 0xA8        # [8] cname
KRB_CTX_ERR_REALM  = 0xA9        # [9] realm
KRB_CTX_ERR_SNAME  = 0xAA        # [10] sname
KRB_CTX_ERR_EDATA  = 0xAC        # [12] e-data (carries PA-ETYPE-INFO2)

# ---- CVE-2020-0796 "SMBGhost" ---------------------------------------------
# SMB 3.1.1 negotiate contexts (MS-SMB2 2.2.3.1). Compression capabilities
# being advertised at all is what makes a 3.1.1 host SMBGhost-exposed.
SMB2_NEGOTIATE_CONTEXT_COMPRESSION = 0x0003
SMB2_NEGOTIATE_CONTEXT_NAMES = {
    0x0001: "PREAUTH_INTEGRITY", 0x0002: "ENCRYPTION",
    0x0003: "COMPRESSION", 0x0005: "NETNAME", 0x0006: "TRANSPORT",
    0x0007: "RDMA_TRANSFORM", 0x0008: "SIGNING",
}
SMB2_DIALECT_311 = 0x0311
# Offsets inside an SMB2 NEGOTIATE response (after the 64-byte header)
SMB2_NEG_CTX_COUNT_OFF = 70      # NegotiateContextCount (2)
SMB2_NEG_CTX_OFFSET_OFF = 124    # NegotiateContextOffset (4), from header start
# COMPRESSION_TRANSFORM_HEADER (MS-SMB2 2.2.42): 16 bytes
SMB2_COMPRESSION_MAGIC = b"\xfcSMB"
SMB2_COMPRESSION_ALGS = {0: "NONE", 1: "LZNT1", 2: "LZ77", 3: "LZ77+Huffman",
                         4: "Pattern_V1"}
U32_MAX = 0xFFFFFFFF

# ---- CVE-2017-0144 "EternalBlue" ------------------------------------------
SMB1_CMD_TRANS2 = 0x32
SMB1_TRANS2_SESSION_SETUP = 0x000E   # the subcommand EternalBlue abuses

# ---- CVE-2022-33679 / CVE-2022-33647 (RC4-MD4 downgrade) ------------------
# RSADSI RC4-MD4, etype -128. Not a legitimate modern etype under any
# circumstance -- its key is 8 bytes with no IV or salt.
KRB_ETYPE_RC4_MD4 = -128
KRB_PA_ETYPE_INFO2 = 19          # padata-type carrying the KDC's etype list

# ---- CVE-2025-33073 (SMB client NTLM/Kerberos reflection) -----------------
# A marshalled CREDENTIAL_TARGET_INFORMATION embedded in a hostname/SPN.
# Base64 of the structure always opens with this magic and closes with BAAAA.
MARSHALLED_TARGET_MAGIC = "1UWhRC"
MARSHALLED_TARGET_TAIL = "BAAAA"

# ---- NTLMSSP (relay-in-progress detection) ---------------------------------
NTLMSSP_SIG = b"NTLMSSP\x00"
NTLM_TYPE_NEGOTIATE = 1
NTLM_TYPE_CHALLENGE = 2          # server -> client, carries the server challenge
NTLM_TYPE_AUTHENTICATE = 3       # client -> server, carries domain/user/workstation
# Responder / Inveigh default static challenge -- a rogue-server tell
NTLM_STATIC_CHALLENGES = {bytes.fromhex("1122334455667788")}

# BPF: everything smbwatch needs and nothing else.
BPF_FILTER = (
    "(tcp port 445 or tcp port 139) or "
    "(udp port 5355 or udp port 137 or udp port 5353) or "
    "(tcp port 88 or udp port 88)"
)

# IPv6 extension-header next-header values worth capturing. libpcap compiles
# "tcp port 445" into a fixed-offset test and CANNOT walk the IPv6 header
# chain, so a single Destination-Options header makes an SMB session invisible
# to the filter even though the engine parses it perfectly. These frames are
# captured by next-header value instead and port-filtered in Python, where the
# chain can actually be walked. ESP (50) is omitted: its payload is encrypted,
# so there is nothing to parse.
IPV6_EH_NEXT_HEADERS = (
    0,    # Hop-by-Hop Options
    43,   # Routing
    44,   # Fragment
    51,   # Authentication Header
    60,   # Destination Options
    135,  # Mobility
)
BPF_IPV6_EH = "(ip6 and (%s))" % " or ".join(
    "ip6[6] = %d" % nh for nh in IPV6_EH_NEXT_HEADERS)


def build_bpf(ipv6_eh: bool = True) -> str:
    """The capture filter actually installed on the interface."""
    return BPF_FILTER + (" or " + BPF_IPV6_EH if ipv6_eh else "")


def canon_addr(value: str) -> str:
    """Canonical text form of an IP address; anything else passes through.

    RFC 5952 form for IPv6, so 2001:DB8::9, 2001:0db8::0009 and 2001:db8::9
    are one host rather than three.
    """
    try:
        return ipaddress.ip_address(str(value).strip().rstrip(".")).compressed
    except ValueError:
        return value


def _pkt_time(pkt) -> float:
    """Coerce a scapy packet timestamp to a plain float.

    Live/crafted packets carry a float .time; rdpcap() packets carry an
    EDecimal, which breaks time.localtime()/json.dumps downstream.
    """
    t = getattr(pkt, "time", None)
    if t is None:
        return time.time()
    try:
        return float(t)
    except (TypeError, ValueError):
        return time.time()


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


# =========================================================================== #
#  Findings
# =========================================================================== #

@dataclass
class Finding:
    rule: str
    severity: Severity
    subject: str                 # the IP the finding is about (responder/server)
    title: str
    detail: str
    proto: Optional[str] = None
    names: List[str] = field(default_factory=list)
    evidence: Dict[str, str] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    count: int = 1

    def key(self) -> Tuple[str, str, Optional[str]]:
        return (self.rule, self.subject, self.proto)

    def to_json(self) -> str:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["first_seen"] = round(self.first_seen, 3)
        d["last_seen"] = round(self.last_seen, 3)
        # Stamp the build that produced this finding. When an alert surfaces in
        # a dashboard hours later, this is what tells you which detection logic
        # raised it -- without it, triage turns into archaeology.
        d["module_version"] = __version__
        d["rule_set"] = RULE_SET_ID
        return json.dumps(d, sort_keys=True)


# =========================================================================== #
#  Configuration
# =========================================================================== #

@dataclass
class Config:
    window: float = 60.0            # sliding window (seconds) for rate heuristics
    name_threshold: int = 3        # R2: distinct names from one responder -> HIGH
    mdns_name_threshold: int = 8   # R2 for mDNS (chattier; higher bar)
    conflict_window: float = 30.0  # R3: window for conflicting answers
    krb_err_threshold: int = 10    # K7: KDC errors from one requester in window
    # Known-good responders / bindings suppress findings (reduce FP on your net).
    allow_responders: Set[str] = field(default_factory=set)   # IPs never flagged
    allow_bindings: Dict[str, str] = field(default_factory=dict)  # name(lower)->ip
    # SMB servers known/accepted to be SMBv1 or unsigned (legacy gear you own).
    allow_smb: Set[str] = field(default_factory=set)
    # Widen the capture filter to IPv6 frames carrying extension headers.
    # libpcap cannot walk the IPv6 header chain, so "tcp port 445" silently
    # misses any IPv6 packet with a Hop-by-Hop/Routing/Fragment/DestOpt header.
    ipv6_eh: bool = True
    # ---- F-series file tier ------------------------------------------- #
    # The random-name length is an impacket implementation detail, not a
    # protocol invariant, so the pattern is configurable rather than welded in.
    temp_exfil_pattern: str = SMB_TEMP_EXFIL_DEFAULT
    # Hosts legitimately enumerating shadow copies (backup software). Same
    # shape as rpcwatch's --drs-replicators: listed -> LOW, unlisted -> HIGH.
    backup_hosts: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        # Canonicalise every operator-supplied address.
        #
        # Addresses off the wire arrive already canonical (scapy renders them
        # through inet_ntop), but an operator types what the documentation
        # shows -- and RFC 3849's documentation prefix is conventionally
        # written "2001:DB8::". Comparing those as raw strings means
        # --allow-smb 2001:DB8::9 silently fails to allowlist 2001:db8::9:
        # the operator believes a device is suppressed and it is not. Silent
        # allowlist failure is the worst kind, so normalise at the boundary.
        self.allow_responders = {canon_addr(a) for a in self.allow_responders}
        self.allow_smb = {canon_addr(a) for a in self.allow_smb}
        self.allow_bindings = {self._norm_name(n): canon_addr(ip)
                               for n, ip in self.allow_bindings.items()}
        self.backup_hosts = {canon_addr(a) for a in self.backup_hosts}

    @staticmethod
    def _norm_name(name: str) -> str:
        return name.rstrip(".").lower()


# =========================================================================== #
#  Per-responder state
# =========================================================================== #

def _canon_name(name: str) -> str:
    """Collapse a name to its cross-protocol identity.

    mDNS names carry the `.local` namespace; LLMNR and NBT-NS names don't. The
    same host is `ws7` on LLMNR and `ws7.local` on mDNS, and Responder answers
    `wpad` on LLMNR and `wpad.local` on mDNS. Comparing raw strings therefore
    treats one identity as two -- which both inflates R2's distinct-name count
    and blinds R4's cross-protocol correlation.
    """
    n = name.rstrip(".").lower()
    if n.endswith(".local"):
        n = n[: -len(".local")]
    return n


@dataclass
class ResponderProfile:
    ip: str
    # deque of (ts, name, proto) inside the sliding window
    events: Deque[Tuple[float, str, str]] = field(default_factory=deque)
    protos_for_name: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    ever_seen: bool = False

    def prune(self, now: float, window: float) -> None:
        while self.events and (now - self.events[0][0]) > window:
            self.events.popleft()

    def distinct_names(self, proto: Optional[str] = None) -> Set[str]:
        if proto is None:
            return {n for _, n, _ in self.events}
        return {n for _, n, p in self.events if p == proto}

    def distinct_canon(self) -> Set[str]:
        """Distinct names after collapsing the mDNS `.local` suffix, so one host
        defending `ws7` (LLMNR) and `ws7.local` (mDNS) counts as ONE identity,
        not two."""
        return {_canon_name(n) for _, n, _ in self.events}

    def protos_for_canon(self, canon: str) -> Set[str]:
        """Which protocols this host used to answer a given canonical name."""
        return {p for _, n, p in self.events if _canon_name(n) == canon}


# =========================================================================== #
#  The engine
# =========================================================================== #

class SMBWatch:
    def __init__(self, cfg: Optional[Config] = None, emit=None):
        self.cfg = cfg or Config()
        self.profiles: Dict[str, ResponderProfile] = {}
        # name(lower) -> {ip -> last_ts}  for conflict detection
        # name -> {answered_address: (responder_ip, timestamp)}. The responder
        # is tracked because R3 needs "two different hosts disagree", not
        # "one host has two addresses".
        self.name_answers: Dict[str, Dict[str, Tuple[str, float]]] = defaultdict(dict)
        # dedup of already-emitted findings, keyed
        self._emitted: Dict[Tuple, Finding] = {}
        self.findings: List[Finding] = []
        self._emit_cb = emit  # optional callback(Finding)
        # ---- relay-path correlation (C1) --------------------------------- #
        # poisoner IP -> the poisoned names that confirmed it (R1/R2/R4)
        self._poisoners: Dict[str, Set[str]] = defaultdict(set)
        # relay-target IP -> reason string (S2/S3, i.e. unsigned)
        self._relay_targets: Dict[str, str] = {}
        # poisoner IP -> set of target IPs already reported for it, so C1
        # re-fires only when a genuinely new cashout target appears
        self._relay_reported: Dict[str, Set[str]] = defaultdict(set)
        # downgrade clients: client IP -> set of short reason tags (populated by
        # the "strong" Kerberos rules). Folded into C1 when a poisoner shares
        # the monitored segment.
        self._downgrade_clients: Dict[str, Set[str]] = defaultdict(set)
        self._downgrade_reported: Dict[str, Set[str]] = defaultdict(set)
        # per-poisoner set of targets already reported as SMBGhost-compound
        self._compound_reported: Dict[str, Set[str]] = defaultdict(set)
        # ---- pre-auth tracking (K6/K7) ----------------------------------- #
        # cname(lower) -> {"preauth": bool, "required": bool, "ts": float}
        self._krb_preauth: Dict[str, Dict] = {}
        # requester IP -> deque[(ts, error_code)] for enumeration/spray (K7)
        self._krb_err: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._krb_err_reported: Set[str] = set()
        # ---- directed Kerberos->SMB edge (C2) ---------------------------- #
        # passive name->IP resolution learned from LLMNR/NBT-NS/mDNS answers
        self._resolved: Dict[str, Set[str]] = defaultdict(set)
        # client IP -> set of SMB-service SPN hosts it sought a ticket for
        self._smb_intent: Dict[str, Set[str]] = defaultdict(set)
        # observed SMB sessions as (client_ip, server_ip)
        self._smb_sessions: Set[Tuple[str, str]] = set()
        self._edge_reported: Set[Tuple[str, str]] = set()
        # (client, target) -> (weak_client, smbghost_target, poisoner_live) so an
        # edge re-fires when it gains a dimension, not on every packet
        self._edge_reported_sig: Dict[Tuple[str, str], Tuple] = {}
        # ---- NTLM relay-in-progress (N1/N2/N3) --------------------------- #
        # challenge bytes -> {"srcs": {ip: ts}, "sessions": {(src,dst): ts}}
        self._ntlm_chal: Dict[bytes, Dict] = {}
        self._ntlm_chal_reported: Set[bytes] = set()
        # ---- F-series file tier ------------------------------------------ #
        # per-direction reassembly buffers, bounded (see SMB_STREAM_MAX_*)
        self._smb_streams: Dict[Tuple, Dict] = {}
        # (conn, message_id) -> share, pending until the TREE_CONNECT response
        self._tc_pending: Dict[Tuple, str] = {}
        # (conn, tree_id) -> share leaf, e.g. 'admin$'
        self._tree_share: Dict[Tuple, str] = {}
        # (conn, tree_id, path) -> {"access": set(), "first": ts, ...}
        self._exfil: Dict[Tuple, Dict] = {}
        self._exfil_reported: Dict[Tuple, Tuple] = {}
        self._file_reported: Set[Tuple] = set()
        # servers observed using SMB3 encryption: the file tier is blind there
        self._smb_encrypted: Set[str] = set()
        try:
            self._temp_exfil_re = re.compile(self.cfg.temp_exfil_pattern, re.I)
        except re.error:
            self._temp_exfil_re = re.compile(SMB_TEMP_EXFIL_DEFAULT, re.I)
        # ---- SMBGhost-exposed hosts (V1), folded into C1/C2 -------------- #
        # ip -> compression algorithms advertised. A host that is BOTH an
        # unsigned relay target and SMBGhost-exposed is a compound finding:
        # the attacker can relay to it *or* take it pre-auth outright.
        self._smbghost: Dict[str, str] = {}

    # ----- finding emission ------------------------------------------------ #
    def _emit(self, f: Finding, refresh: bool = False) -> None:
        k = f.key()
        prev = self._emitted.get(k)
        if prev is not None:
            # merge rather than spam; only re-notify on genuine escalation
            prev.count += 1
            prev.last_seen = f.last_seen
            prev.names = sorted(set(prev.names) | set(f.names))
            escalated = f.severity > prev.severity
            if escalated:
                prev.severity = f.severity
            # `refresh` is for correlation rules that re-fire because they
            # LEARNED something new. Those can gain a whole dimension without
            # gaining severity (an already-CRITICAL edge whose client turns out
            # to be a downgrade client), and the stale text would be wrong.
            if escalated or refresh:
                prev.title = f.title
                prev.detail = f.detail
                prev.evidence = f.evidence
            # A refresh means new information, and it is already rate-limited by
            # the caller's own dedupe, so a live consumer should hear about it.
            if (escalated or refresh) and self._emit_cb:
                self._emit_cb(prev)
            return
        self._emitted[k] = f
        self.findings.append(f)
        if self._emit_cb:
            self._emit_cb(f)

    # ----- public entry point --------------------------------------------- #
    def process_packet(self, pkt) -> None:
        """Single funnel for live capture, pcap replay, and self-tests."""
        try:
            from scapy.all import IP, IPv6, UDP, TCP
        except Exception:
            return
        l3_src = None
        if pkt.haslayer(IP):
            l3_src = pkt[IP].src
        elif pkt.haslayer(IPv6):
            l3_src = pkt[IPv6].src

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            if PORT_LLMNR in (sport, dport):
                self._handle_dns_like(pkt, l3_src, PROTO_LLMNR)
            elif PORT_MDNS in (sport, dport):
                self._handle_dns_like(pkt, l3_src, PROTO_MDNS)
            elif PORT_NBTNS in (sport, dport):
                self._handle_nbtns(pkt, l3_src)
            elif PORT_KRB in (sport, dport):
                self._handle_kerberos(pkt, udp, l3_src, framed=False)
        elif pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if PORT_SMB in (tcp.sport, tcp.dport) or PORT_NBSS in (tcp.sport, tcp.dport):
                self._handle_smb(pkt, tcp, l3_src)
            elif PORT_KRB in (tcp.sport, tcp.dport):
                self._handle_kerberos(pkt, tcp, l3_src, framed=True)

    # ===================================================================== #
    #  Name-poisoning handlers
    # ===================================================================== #
    def _profile(self, ip: str) -> ResponderProfile:
        p = self.profiles.get(ip)
        if p is None:
            p = ResponderProfile(ip=ip)
            self.profiles[ip] = p
        return p

    @staticmethod
    def _is_wpad(name: str) -> bool:
        first = name.rstrip(".").split(".")[0].lower()
        return first == "wpad"

    @staticmethod
    def _norm(name: str) -> str:
        return name.rstrip(".").lower()

    def _register_answer(self, src: str, name: str, proto: str,
                         answered_ip: Optional[str], now: float) -> None:
        """Core scoring shared by LLMNR / NBT-NS / mDNS responses."""
        if src is None:
            return
        name_n = self._norm(name)
        if not name_n:
            return

        # ---- false-positive gate 1: DNS-SD service types ----------------- #
        # A service type is not a host name. Bonjour networks (Apple TVs,
        # HomePods, printers, Chromecasts) answer these constantly and from
        # many devices at once -- that is service discovery, not poisoning.
        # Dropping them here keeps them out of R2's distinct-name count, R3's
        # conflict book, R4's cross-protocol check and the C2 resolution map.
        if self._is_service_discovery_name(name_n):
            return

        # ---- false-positive gate 2: rdata that is not an address --------- #
        # Never let a name masquerade as an address (see _is_ip_literal).
        if answered_ip is not None and not self._is_ip_literal(answered_ip):
            answered_ip = None

        prof = self._profile(src)
        first_time_responder = not prof.ever_seen
        prof.ever_seen = True

        prof.prune(now, self.cfg.window)
        prof.events.append((now, name_n, proto))
        prof.protos_for_name[name_n].add(proto)

        # passive name->IP resolution (used by the directed C2 edge). This is
        # plain observation of any answer, poisoned or not.
        if answered_ip:
            if answered_ip not in self._resolved[name_n]:
                self._resolved[name_n].add(answered_ip)
                self._check_directed_edge(now)  # a resolution may complete an edge

        # CVE-2025-33073: a name-resolution answer for a marshalled target name
        self._check_marshalled_target(name_n, src, "name-resolution answer", now)

        # ---- allowlist short-circuit ------------------------------------- #
        if src in self.cfg.allow_responders:
            return
        bound = self.cfg.allow_bindings.get(name_n)
        allow_this = bound is not None and answered_ip is not None and bound == answered_ip

        # ---- R1: WPAD ---------------------------------------------------- #
        if self._is_wpad(name_n) and not allow_this:
            self._emit(Finding(
                rule="R1", severity=Severity.CRITICAL, subject=src,
                title="WPAD answered over %s" % proto,
                detail=("Host is answering WPAD name resolution via %s. WPAD over "
                        "LLMNR/NBT-NS/mDNS is disabled by default on patched Windows "
                        "(MS16-077); an answer is almost certainly Responder-class "
                        "proxy/credential capture." % proto),
                proto=proto, names=[name_n],
                evidence={"answered_ip": answered_ip or "?"},
                first_seen=now, last_seen=now,
            ))
            self._mark_poisoner(src, name_n, now)

        # ---- R5: baseline (first sighting) ------------------------------- #
        if first_time_responder and src not in self.cfg.allow_responders:
            self._emit(Finding(
                rule="R5", severity=Severity.INFO, subject=src,
                title="New name responder observed",
                detail="First time this host has been seen answering name "
                       "resolution. Baseline entry; not itself an alarm.",
                proto=proto, names=[name_n],
                first_seen=now, last_seen=now,
            ))

        # ---- R2: aggressive responder ------------------------------------ #
        threshold = (self.cfg.mdns_name_threshold if proto == PROTO_MDNS
                     else self.cfg.name_threshold)
        # canonical, so a host defending `ws7` on LLMNR and `ws7.local` on mDNS
        # counts as one name toward the threshold rather than two
        distinct = prof.distinct_canon()
        if len(distinct) >= threshold:
            self._emit(Finding(
                rule="R2", severity=Severity.HIGH, subject=src,
                title="Aggressive name responder (possible poisoner)",
                detail=("Host answered %d distinct names within %ds. Legitimate "
                        "hosts answer only for their own name(s); answering for "
                        "many names is the signature of LLMNR/NBT-NS/mDNS poisoning."
                        % (len(distinct), int(self.cfg.window))),
                proto=None, names=sorted(distinct),   # per-IP, cross-protocol
                evidence={"distinct_names": str(len(distinct)),
                          "threshold": str(threshold),
                          "last_proto": proto},
                first_seen=now, last_seen=now,
            ))
            self._mark_poisoner(src, sorted(distinct), now)

        # ---- R4: same name across multiple protocols --------------------- #
        #  Matched on the CANONICAL name, because Responder answers 'wpad' on
        #  LLMNR and 'wpad.local' on mDNS -- raw string comparison never
        #  correlated those two legs.
        #
        #  The discriminator that keeps this the lowest-FP rule in the set: a
        #  legitimate host answers on several protocols only to defend its OWN
        #  single identity (a Windows box answering `ws7` and `ws7.local`).
        #  Responder answers for names it does not own, so it accumulates more
        #  than one identity. Answering exactly one canonical name is therefore
        #  normal and is suppressed -- unless that name is WPAD, which no host
        #  legitimately owns.
        canon = _canon_name(name_n)
        protos = prof.protos_for_canon(canon)
        if len(protos) >= 2:
            identities = prof.distinct_canon()
            own_identity_only = len(identities) == 1 and not self._is_wpad(canon)
            if not own_identity_only:
                self._emit(Finding(
                    rule="R4", severity=Severity.HIGH, subject=src,
                    title="One host answering a name across multiple protocols",
                    detail=("Host answered '%s' over %s while answering %d distinct "
                            "name(s) overall. A single box answering the same name "
                            "on multiple name-resolution protocols at once is "
                            "characteristic of Responder/Inveigh, which listens on "
                            "all of them simultaneously." %
                            (canon, "+".join(sorted(protos)), len(identities))),
                    proto=None, names=[canon],
                    evidence={"protocols": "+".join(sorted(protos)),
                              "canonical_name": canon,
                              "distinct_identities": str(len(identities))},
                    first_seen=now, last_seen=now,
                ))
                self._mark_poisoner(src, canon, now)

        # ---- R3: conflicting answers ------------------------------------- #
        #  A conflict is two DIFFERENT hosts claiming the same name -- a
        #  poisoner racing the real owner. It is NOT one host answering its own
        #  name with several of its own addresses, which is routine: Apple and
        #  Windows machines with Wi-Fi + Ethernet (+ link-local, + VPN) answer
        #  `host.local` with every address they hold, and a Bonjour Sleep Proxy
        #  answers for a sleeping device using that device's address. Keying
        #  only on the address set flagged all of those.
        if answered_ip:
            book = self.name_answers[name_n]
            for addr in list(book):
                if now - book[addr][1] > self.cfg.conflict_window:
                    del book[addr]
            book[answered_ip] = (src, now)
            responders = {who for who, _ in book.values()}
            if len(book) >= 2 and len(responders) >= 2 and not allow_this:
                self._emit(Finding(
                    rule="R3", severity=Severity.MEDIUM, subject=src,
                    title="Conflicting answers for one name",
                    detail=("Name '%s' answered with %d different addresses by %d "
                            "different hosts inside %ds (%s). A poisoner racing the "
                            "legitimate owner produces exactly this." %
                            (name_n, len(book), len(responders),
                             int(self.cfg.conflict_window),
                             ", ".join("%s from %s" % (a, book[a][0])
                                       for a in sorted(book)))),
                    proto=proto, names=[name_n],
                    evidence={"addresses": ", ".join(sorted(book)),
                              "responders": ", ".join(sorted(responders))},
                    first_seen=now, last_seen=now,
                ))

    # ----- LLMNR & mDNS (DNS wire format) --------------------------------- #
    def _handle_dns_like(self, pkt, src, proto: str) -> None:
        from scapy.all import UDP, DNS
        try:
            payload = bytes(pkt[UDP].payload)
            dns = DNS(payload)
        except Exception:
            return
        if getattr(dns, "qr", 0) != 1:          # only responses
            return
        an = getattr(dns, "an", None)
        if an is None or getattr(dns, "ancount", 0) < 1:
            return
        now = _pkt_time(pkt)

        # iterate answer RRs (scapy stacks them via .an with .payload chain)
        rr = an
        seen_any = False
        while rr is not None and getattr(rr, "rrname", None) is not None:
            rtype = int(getattr(rr, "type", 0))
            rname = rr.rrname.decode(errors="replace") if isinstance(rr.rrname, bytes) else str(rr.rrname)
            if proto == PROTO_MDNS:
                # only host A/AAAA answers matter for poisoning; skip
                # PTR/SRV/TXT service-discovery chatter to avoid false positives
                if rtype in (DNS_TYPE_A, DNS_TYPE_AAAA):
                    ip = self._rdata_str(rr)
                    self._register_answer(src, rname, proto, ip, now)
                    seen_any = True
            else:  # LLMNR
                ip = self._rdata_str(rr) if rtype in (DNS_TYPE_A, DNS_TYPE_AAAA) else None
                self._register_answer(src, rname, proto, ip, now)
                seen_any = True
            rr = getattr(rr, "payload", None)
            if rr is not None and not hasattr(rr, "rrname"):
                break
        _ = seen_any

    @staticmethod
    def _rdata_str(rr) -> Optional[str]:
        rd = getattr(rr, "rdata", None)
        if rd is None:
            return None
        if isinstance(rd, bytes):
            try:
                return rd.decode()
            except Exception:
                return None
        return str(rd)

    @staticmethod
    def _is_ip_literal(value: Optional[str]) -> bool:
        """True only for a real IPv4/IPv6 literal.

        Defensive root-cause guard. Anything that reaches the binding/conflict
        logic as an 'address' must actually BE an address. A PTR/SRV rdata is a
        name, and treating one as an address produced findings that read
        'answered with conflicting IPs (Jacks rum._companion-link._tcp.local.)'
        -- nonsense on its face. Record-type filtering already stops that
        upstream; this makes the whole class impossible if a record type ever
        slips through a parser edge case.
        """
        if not value:
            return False
        try:
            ipaddress.ip_address(value.strip().rstrip("."))
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_service_discovery_name(name: Optional[str]) -> bool:
        """True for a DNS-SD / reverse-lookup name rather than a host name.

        Any label beginning with '_' is a DNS-SD service type or subtype
        ('_companion-link._tcp.local', '_sleep-proxy._udp.local',
        '_services._dns-sd._udp.local'). Many different devices answering the
        same service type is the protocol working exactly as designed -- it is
        service enumeration, not a name conflict, and nobody relays credentials
        to a service type. Reverse-lookup zones are likewise not host names.
        """
        if not name:
            return False
        n = name.strip().rstrip(".").lower()
        if n.endswith(".in-addr.arpa") or n.endswith(".ip6.arpa"):
            return True
        return any(label.startswith("_") for label in n.split("."))

    # ----- NBT-NS --------------------------------------------------------- #
    def _handle_nbtns(self, pkt, src) -> None:
        from scapy.all import UDP
        from scapy.layers.netbios import NBNSHeader
        try:
            hdr = NBNSHeader(bytes(pkt[UDP].payload))
        except Exception:
            return
        if int(getattr(hdr, "RESPONSE", 0)) != 1:
            return
        if int(getattr(hdr, "ANCOUNT", 0)) < 1:
            return
        now = _pkt_time(pkt)

        body = hdr.payload
        # walk NBNSQueryResponse record(s)
        from scapy.layers.netbios import NBNSQueryResponse
        while body is not None and isinstance(body, NBNSQueryResponse):
            rr_name = body.RR_NAME
            name = rr_name.decode(errors="replace") if isinstance(rr_name, bytes) else str(rr_name)
            name = name.strip()
            suffix = int(getattr(body, "SUFFIX", 0))
            addr = None
            entries = getattr(body, "ADDR_ENTRY", None) or []
            if entries:
                addr = getattr(entries[0], "NB_ADDRESS", None)
            label = NBT_SUFFIX.get(suffix, "0x%02x" % suffix)
            display = "%s<%s>" % (name, label)
            self._register_answer(src, name, PROTO_NBTNS, addr, now)
            # annotate the most recent finding names with suffix context is
            # optional; keep the bare name for cross-proto correlation.
            _ = display
            body = getattr(body, "payload", None)

    # ===================================================================== #
    #  SMB negotiate posture
    # ===================================================================== #
    @staticmethod
    def tcp_payload_bytes(pkt, tcp) -> bytes:
        """Slice the TCP payload out of the RAW frame, not out of scapy's
        dissection.

        scapy binds NBTSession to tcp/445 and tcp/139, so bytes(tcp.payload)
        is dissected-and-rebuilt rather than read. That round-trips losslessly
        today (measured, including mid-stream fragments whose length field
        lies), but rpcwatch lost a detection to exactly this shape on tcp/135
        where DceRpc5 reorders fields. Reassembly makes byte fidelity
        load-bearing here, so the dependency is removed rather than trusted.
        """
        try:
            raw = bytes(tcp.original) if getattr(tcp, "original", None) else None
            if raw:
                off = (raw[12] >> 4) * 4
                if 20 <= off <= len(raw):
                    return raw[off:]
        except Exception:
            pass
        try:
            return bytes(tcp.payload)
        except Exception:
            return b""

    def _handle_smb(self, pkt, tcp, src) -> None:
        payload = self.tcp_payload_bytes(pkt, tcp)
        if not payload:
            return
        now = _pkt_time(pkt)
        dst = self._l3_dst(pkt)
        server = src or "?"

        # ---- F-series file tier --------------------------------------- #
        # Runs on REASSEMBLED messages, so it sees every byte regardless of
        # how the path was segmented. Must come before the length guard
        # below: a 4-byte continuation segment carries no finding of its own
        # but completes a message that does.
        try:
            msgs = self._smb_stream_push(
                (src, int(tcp.sport), dst, int(tcp.dport)), payload, now)
            if msgs:
                self._handle_smb_files(msgs, src, dst, tcp.sport, tcp.dport, now)
        except Exception:
            pass

        if len(payload) < 8:
            return

        # NTLM relay-in-progress scan -- works on SESSION_SETUP, which is not a
        # negotiate response, so it must run before the negotiate early-return.
        if NTLMSSP_SIG in payload:
            self._handle_ntlmssp(payload, server, dst or "?", now)

        # CVE rules that ride on non-negotiate frames must also run before the
        # negotiate early-return below.
        self._check_smbghost_exploit(payload, server, dst, now)
        self._check_eternalblue(payload, server, dst, now)

        res = self.parse_smb_negotiate_response(payload)
        if res is None:
            return
        # a negotiate *response* is server->client: record the session so the
        # directed C2 edge can tie a Kerberos SMB client to this server.
        if dst:
            self._smb_sessions.add((dst, server))
            self._check_directed_edge(now)
            self._check_reflection(dst, server, now)   # CVE-2025-33073
        if server in self.cfg.allow_smb:
            return

        version, dialect_name, signing_required, signing_enabled = res

        if version == 1:
            self._emit(Finding(
                rule="S1", severity=Severity.MEDIUM, subject=server,
                title="SMBv1 (CIFS) negotiated",
                detail=("Server agreed to speak SMBv1. SMBv1 is deprecated and is "
                        "the EternalBlue/DoublePulsar surface; it should be disabled "
                        "on modern hosts."),
                proto="SMB", names=[],
                evidence={"dialect": dialect_name},
                first_seen=now, last_seen=now,
            ))
            if not signing_required:
                self._emit(Finding(
                    rule="S3", severity=Severity.HIGH, subject=server,
                    title="SMBv1 server: signing not required",
                    detail=("This SMBv1 server does not require message signing, so "
                            "it is a valid target for NTLM relay of captured "
                            "credentials."),
                    proto="SMB", names=[],
                    evidence={"signing_enabled": str(bool(signing_enabled))},
                    first_seen=now, last_seen=now,
                ))
                self._mark_relay_target(server, dialect_name, now)
        else:
            # CVE-2020-0796 posture: 3.1.1 + compression capability advertised
            self._check_smbghost_posture(payload, server, dialect_name, now)
            if not signing_required:
                self._emit(Finding(
                    rule="S2", severity=Severity.HIGH, subject=server,
                    title="%s server: signing not required" % dialect_name,
                    detail=("Server negotiate advertises signing as %s but not "
                            "REQUIRED. It is therefore a valid NTLM-relay target: "
                            "credentials captured by the front half of the chain "
                            "(LLMNR/NBT-NS/mDNS poisoning) can be relayed here."
                            % ("enabled" if signing_enabled else "disabled")),
                    proto="SMB", names=[],
                    evidence={"dialect": dialect_name,
                              "signing_enabled": str(bool(signing_enabled))},
                    first_seen=now, last_seen=now,
                ))
                self._mark_relay_target(server, dialect_name, now)

    # ===================================================================== #
    #  CVE-2020-0796 "SMBGhost" / CoronaBlue  (V1 posture, V2 exploit)
    # ===================================================================== #
    #  SMB 3.1.1 lets both ends advertise SMB2_COMPRESSION_CAPABILITIES in the
    #  negotiate context list. Srv2DecompressData() then allocates
    #  OriginalCompressedSegmentSize + Offset without checking the 32-bit sum,
    #  so a crafted COMPRESSION_TRANSFORM_HEADER gives a wormable pre-auth
    #  kernel pool overflow. Advertising compression is the exposure; a frame
    #  whose two size fields wrap 0xFFFFFFFF is the attack itself.
    # ===================================================================== #
    def _check_smbghost_posture(self, payload: bytes, server: str,
                                dialect_name: str, now: float) -> None:
        if server in self.cfg.allow_smb:
            return
        ctxs = self.parse_negotiate_contexts(payload)
        if not ctxs:
            return
        comp = [d for t, d in ctxs if t == SMB2_NEGOTIATE_CONTEXT_COMPRESSION]
        if not comp:
            return
        algs = self._compression_algs(comp[0])
        names = [SMB2_NEGOTIATE_CONTEXT_NAMES.get(t, "0x%04x" % t) for t, _ in ctxs]
        # remember it so C1/C2 can report a compound exposure
        self._smbghost[server] = ", ".join(algs) or "unspecified"
        self._check_correlation(now)
        self._check_directed_edge(now)
        self._emit(Finding(
            rule="V1", severity=Severity.HIGH, subject=server,
            title="SMB 3.1.1 compression advertised (CVE-2020-0796 exposure)",
            detail=("Server negotiated %s and advertises SMB2_COMPRESSION_"
                    "CAPABILITIES%s. That is the precondition for CVE-2020-0796 "
                    "(SMBGhost) -- an unauthenticated, wormable kernel pool "
                    "overflow in the SMBv3 decompression path. Unpatched Windows "
                    "10 1903/1909 and Server 1903/1909 are exploitable pre-auth; "
                    "compression can be disabled without a reboot as a stopgap." %
                    (dialect_name, (" (algorithms: %s)" % ", ".join(algs)) if algs else "")),
            proto="SMB", names=[],
            evidence={"cve": "CVE-2020-0796", "dialect": dialect_name,
                      "compression_algorithms": ", ".join(algs) or "unspecified",
                      "negotiate_contexts": ", ".join(names)},
            first_seen=now, last_seen=now))

    @staticmethod
    def _compression_algs(data: bytes) -> List[str]:
        """SMB2_COMPRESSION_CAPABILITIES: AlgorithmCount(2) Padding(2)
        Flags(4) Algorithms[AlgorithmCount](2 each)."""
        out: List[str] = []
        try:
            count = struct.unpack_from("<H", data, 0)[0]
            for i in range(min(count, 8)):
                off = 8 + i * 2
                if off + 2 > len(data):
                    break
                a = struct.unpack_from("<H", data, off)[0]
                out.append(SMB2_COMPRESSION_ALGS.get(a, "alg-%d" % a))
        except Exception:
            pass
        return out

    def _check_smbghost_exploit(self, payload: bytes, src: str,
                                dst: Optional[str], now: float) -> None:
        parsed = self.parse_compression_transform(payload)
        if parsed is None:
            return
        original_size, algorithm, flags, offset = parsed
        # The bug is the unchecked 32-bit addition in Srv2DecompressData().
        if original_size + offset <= U32_MAX:
            return   # a normal compressed frame
        alg = SMB2_COMPRESSION_ALGS.get(algorithm, "alg-%d" % algorithm)
        self._emit(Finding(
            rule="V2", severity=Severity.CRITICAL, subject=src,
            title="SMBGhost exploitation attempt (CVE-2020-0796)",
            detail=("SMB2 COMPRESSION_TRANSFORM_HEADER from %s%s carries "
                    "OriginalCompressedSegmentSize=0x%08x and Offset=0x%08x, "
                    "whose sum overflows a 32-bit register. That is the integer "
                    "overflow CVE-2020-0796 exploits to allocate an undersized "
                    "kernel pool buffer -- this is an exploitation attempt on the "
                    "wire, not a posture finding." %
                    (src, (" to %s" % dst) if dst else "", original_size, offset)),
            proto="SMB", names=[],
            evidence={"cve": "CVE-2020-0796",
                      "original_size": "0x%08x" % original_size,
                      "offset": "0x%08x" % offset,
                      "sum": "0x%x" % (original_size + offset),
                      "algorithm": alg, "flags": "0x%04x" % flags,
                      "target": dst or "?"},
            first_seen=now, last_seen=now))

    # ===================================================================== #
    #  CVE-2017-0144 "EternalBlue"  (V6)
    # ===================================================================== #
    #  S1 already reports that a host speaks SMBv1. This is the other half:
    #  a Trans2 SESSION_SETUP (subcommand 0x000E) request, which no legitimate
    #  SMB client emits -- it is the EternalBlue/DoublePulsar probe.
    # ===================================================================== #
    def _check_eternalblue(self, payload: bytes, src: str,
                           dst: Optional[str], now: float) -> None:
        sub = self.parse_smb1_trans2_subcommand(payload)
        if sub != SMB1_TRANS2_SESSION_SETUP:
            return
        self._emit(Finding(
            rule="V6", severity=Severity.HIGH, subject=src,
            title="SMBv1 Trans2 SESSION_SETUP (EternalBlue probe, CVE-2017-0144)",
            detail=("%s sent an SMBv1 TRANS2 request with subcommand "
                    "SESSION_SETUP (0x000E)%s. No legitimate SMB client issues "
                    "this subcommand; it is the EternalBlue / DoublePulsar "
                    "reconnaissance and exploitation primitive. Treat the source "
                    "as compromised or actively scanning." %
                    (src, (" to %s" % dst) if dst else "")),
            proto="SMB", names=[],
            evidence={"cve": "CVE-2017-0144", "trans2_subcommand": "0x%04x" % sub,
                      "target": dst or "?"},
            first_seen=now, last_seen=now))

    # ===================================================================== #
    #  CVE-2025-33073 (SMB client NTLM/Kerberos reflection)  (V3)
    # ===================================================================== #
    #  The coercion needs a name carrying a marshalled
    #  CREDENTIAL_TARGET_INFORMATION so the SMB client treats the connection as
    #  local authentication. Microsoft's own patch is "refuse to authenticate
    #  when the target name contains a marshalled structure" -- so the patch
    #  condition is the detection signature.
    # ===================================================================== #
    def _check_marshalled_target(self, name: Optional[str], subject: str,
                                 where: str, now: float) -> bool:
        if not self.has_marshalled_target(name):
            return False
        sev = Severity.CRITICAL if self._poisoners else Severity.HIGH
        self._emit(Finding(
            rule="V3", severity=sev, subject=subject,
            title="Marshalled target name (CVE-2025-33073 reflection coercion)",
            detail=("A %s carries a marshalled CREDENTIAL_TARGET_INFORMATION "
                    "blob: %s. Windows treats such a target as local "
                    "authentication, which is the coercion primitive for "
                    "CVE-2025-33073 -- reflected NTLM/Kerberos yielding SYSTEM on "
                    "any host not enforcing SMB signing. No legitimate hostname "
                    "or SPN has this shape.%s" %
                    (where, name,
                     " A poisoner is live on this segment." if self._poisoners else "")),
            proto="SMB/Kerberos", names=[name or ""],
            evidence={"cve": "CVE-2025-33073", "observed_in": where,
                      "target_name": name or ""},
            first_seen=now, last_seen=now))
        return True

    def _check_reflection(self, client: str, server: str, now: float) -> None:
        """The reflection itself: an SMB session whose client and server are the
        same host means the authentication was looped back."""
        if not client or not server or client != server:
            return
        key = ("V3R", client)
        if key in self._edge_reported:
            return
        self._edge_reported.add(key)
        self._emit(Finding(
            rule="V3", severity=Severity.CRITICAL, subject=client,
            title="SMB authentication reflected to its own host (CVE-2025-33073)",
            detail=("An SMB session was observed with %s as both client and "
                    "server -- the host authenticating to itself. That is the "
                    "reflection CVE-2025-33073 produces once a marshalled target "
                    "name coerces local authentication, and it grants SYSTEM on "
                    "hosts that do not enforce SMB signing." % client),
            proto="SMB", names=[],
            evidence={"cve": "CVE-2025-33073", "host": client},
            first_seen=now, last_seen=now))

    @staticmethod
    def parse_negotiate_contexts(payload: bytes) -> Optional[List[Tuple[int, bytes]]]:
        """Walk the SMB2 3.1.1 NegotiateContextList of a negotiate RESPONSE and
        return [(context_type, data), ...], or None if this isn't a 3.1.1
        negotiate response with contexts. Framing-agnostic like its sibling.

        Each context is ContextType(2) DataLength(2) Reserved(4) Data[], padded
        to an 8-byte boundary (MS-SMB2 2.2.3.1).
        """
        for base in (4, 0):
            if len(payload) < base + 4:
                continue
            if payload[base:base + 4] != SMB2_MAGIC:
                continue
            p = payload[base:]
            if len(p) < 128:
                continue
            try:
                command = struct.unpack_from("<H", p, 12)[0]
                flags = struct.unpack_from("<I", p, 16)[0]
                if command != SMB2_CMD_NEGOTIATE:
                    continue
                if not (flags & SMB2_FLAGS_SERVER_TO_REDIR):
                    continue
                dialect = struct.unpack_from("<H", p, 68)[0]
                if dialect != SMB2_DIALECT_311:
                    return []          # contexts only exist for 3.1.1
                count = struct.unpack_from("<H", p, SMB2_NEG_CTX_COUNT_OFF)[0]
                off = struct.unpack_from("<I", p, SMB2_NEG_CTX_OFFSET_OFF)[0]
            except Exception:
                continue
            out: List[Tuple[int, bytes]] = []
            for _ in range(min(count, 16)):   # sanity cap
                if off + 8 > len(p):
                    break
                ctx_type, data_len = struct.unpack_from("<HH", p, off)
                start = off + 8
                end = start + data_len
                if end > len(p):
                    break
                out.append((ctx_type, p[start:end]))
                off = end + ((8 - (end % 8)) % 8)   # 8-byte align
            return out
        return None

    @staticmethod
    def parse_compression_transform(payload: bytes):
        """Parse an SMB2 COMPRESSION_TRANSFORM_HEADER (MS-SMB2 2.2.42).

        Returns (original_size, algorithm, flags, offset) or None. The SMBGhost
        overflow is original_size + offset wrapping a 32-bit register, so both
        fields are returned raw for the caller to check.
        """
        for base in (4, 0):
            if len(payload) < base + 16:
                continue
            if payload[base:base + 4] != SMB2_COMPRESSION_MAGIC:
                continue
            p = payload[base:]
            try:
                original_size = struct.unpack_from("<I", p, 4)[0]
                algorithm = struct.unpack_from("<H", p, 8)[0]
                flags = struct.unpack_from("<H", p, 10)[0]
                offset = struct.unpack_from("<I", p, 12)[0]
            except Exception:
                continue
            return (original_size, algorithm, flags, offset)
        return None

    @staticmethod
    def parse_smb1_trans2_subcommand(payload: bytes) -> Optional[int]:
        """Return the Trans2 subcommand of an SMBv1 TRANS2 *request*, or None.

        SMB1 header is 32 bytes; Trans2 request parameters start at WordCount+1.
        The Setup words follow 14 words of fixed parameters, and Setup[0] is the
        subcommand. EternalBlue's tell is SESSION_SETUP (0x000E), which no
        legitimate client sends.
        """
        for base in (4, 0):
            if len(payload) < base + 64:
                continue
            if payload[base:base + 4] != SMB1_MAGIC:
                continue
            p = payload[base:]
            try:
                if p[4] != SMB1_CMD_TRANS2:
                    continue
                if p[9] & 0x80:          # response, not request
                    continue
                word_count = p[32]
                if word_count < 15:      # need the 14 fixed words + setup
                    continue
                # Setup[0] sits after WordCount(1) + 14 words (28 bytes) +
                # SetupCount(1) + Reserved3(1)
                setup_off = 33 + 28 + 2
                if setup_off + 2 > len(p):
                    continue
                return struct.unpack_from("<H", p, setup_off)[0]
            except Exception:
                continue
        return None

    @staticmethod
    def has_marshalled_target(name: Optional[str]) -> bool:
        """True if a hostname/SPN carries a marshalled
        CREDENTIAL_TARGET_INFORMATION blob (CVE-2025-33073 coercion record).

        The base64 of the structure always opens with the same magic and closes
        with BAAAA, e.g. srv011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.
        No legitimate hostname looks like this.
        """
        if not name:
            return False
        # Case-insensitive: the name pipeline normalises to lowercase before
        # this is reached, and DNS/SPN comparisons are case-insensitive anyway.
        hay = name.upper()
        idx = hay.find(MARSHALLED_TARGET_MAGIC.upper())
        if idx < 0:
            return False
        rest = hay[idx + len(MARSHALLED_TARGET_MAGIC):]
        # strip any trailing DNS suffix the attacker appended
        blob = rest.split(".", 1)[0]
        return len(blob) >= 20 and blob.endswith(MARSHALLED_TARGET_TAIL.upper())

    @staticmethod
    def parse_smb_negotiate_response(payload: bytes
                                     ) -> Optional[Tuple[int, str, bool, bool]]:
        """
        Framing-agnostic byte parser for an SMB NEGOTIATE *response*.

        Returns (version, dialect_name, signing_required, signing_enabled) or
        None if this isn't a negotiate response.

        Handles both transports:
          * direct-hosted tcp/445 : 4-byte length prefix (00 + 3-byte len)
          * NBT-framed  tcp/139   : 4-byte NBT session header (type + len)
        In both cases the SMB message begins 4 bytes in with the magic.
        """
        # Try with and without the 4-byte transport framing.
        for base in (4, 0):
            if len(payload) < base + 4:
                continue
            magic = payload[base:base + 4]

            # ---- SMB2/3 ---------------------------------------------------- #
            if magic in (SMB2_MAGIC, SMB2_TRANSFORM_MAGIC):
                p = payload[base:]
                if len(p) < 72:
                    continue
                command = struct.unpack_from("<H", p, 12)[0]
                flags = struct.unpack_from("<I", p, 16)[0]
                if command != SMB2_CMD_NEGOTIATE:
                    continue
                if not (flags & SMB2_FLAGS_SERVER_TO_REDIR):
                    continue  # request, not response
                security_mode = struct.unpack_from("<H", p, 66)[0]
                dialect = struct.unpack_from("<H", p, 68)[0]
                name = SMB2_DIALECTS.get(dialect, "SMB2 0x%04x" % dialect)
                required = bool(security_mode & SMB2_SIGNING_REQUIRED)
                enabled = bool(security_mode & SMB2_SIGNING_ENABLED)
                return (2, name, required, enabled)

            # ---- SMB1 ------------------------------------------------------ #
            if magic == SMB1_MAGIC:
                p = payload[base:]
                if len(p) < 37:
                    continue
                command = p[4]
                flags = p[9]
                if command != SMB1_CMD_NEGOTIATE:
                    continue
                if not (flags & 0x80):   # 0x80 = response
                    continue
                word_count = p[32]
                if word_count < 1:
                    # negotiate response with WordCount 1 = "no dialect chosen"
                    return (1, "SMBv1 (no dialect index)", False, False)
                # NT LM 0.12 response layout: WordCount, DialectIndex(2),
                # SecurityMode(1), ...
                dialect_index = struct.unpack_from("<H", p, 33)[0]
                security_mode = p[35]
                if dialect_index == 0xFFFF:
                    return None  # server rejected all dialects; not "in use"
                required = bool(security_mode & SMB1_SIGNING_REQUIRED)
                enabled = bool(security_mode & SMB1_SIGNING_ENABLED)
                return (1, "SMBv1 (NT LM 0.12)", required, enabled)
        return None

    # ===================================================================== #
    #  SMB2 file-operation parsing  (F-series)
    # ===================================================================== #
    #  The negotiate parser above reads one segment. The file tier cannot:
    #  an SMB2 CREATE carries its filename as UTF-16LE at NameOffset, which on
    #  a long path lands beyond the first segment -- the shape that produced
    #  rpcwatch's WinRM half-message bug. So file-tier parsing runs off
    #  REASSEMBLED messages, framed by the 4-byte session-service header that
    #  precedes every SMB2 message on tcp/445 and tcp/139.
    #
    #  Boundary with rpcwatch: rpcwatch owns named-pipe traffic (it carves
    #  DCERPC out of SMB2 WRITE/READ/IOCTL on \\pipe\\*). smbwatch owns file
    #  operations. Pipe paths are skipped here so one PDU never double-fires
    #  across two sensors.
    # ===================================================================== #
    @staticmethod
    def _conn_key(src, sport, dst, dport):
        """Direction-independent connection identity, so a TREE_CONNECT
        request and its response land in the same bucket."""
        a, b = (str(src), int(sport)), (str(dst), int(dport))
        return (a, b) if a <= b else (b, a)

    def _smb_stream_push(self, key, payload: bytes, now: float):
        """Append to a per-direction buffer and return complete SMB2 messages.

        Bounded on purpose: this runs on a Pi Zero 2W watching a SPAN port.
        """
        st = self._smb_streams.get(key)
        if st is None:
            if len(self._smb_streams) >= SMB_STREAM_MAX_FLOWS:
                self._smb_stream_prune(now)
            if len(self._smb_streams) >= SMB_STREAM_MAX_FLOWS:
                return []
            st = {"buf": bytearray(), "ts": now}
            self._smb_streams[key] = st
        st["ts"] = now
        buf = st["buf"]
        buf += payload
        if len(buf) > SMB_STREAM_MAX_BYTES:
            # keep the tail; a message we can no longer frame is unrecoverable
            del buf[:len(buf) - SMB_STREAM_MAX_BYTES]
        return self._smb_frame(buf)

    def _smb_stream_prune(self, now: float) -> None:
        for k in [k for k, v in self._smb_streams.items()
                  if now - v["ts"] > self.cfg.window]:
            del self._smb_streams[k]

    @staticmethod
    def _smb_frame(buf: bytearray) -> List[bytes]:
        """Drain complete SMB2 messages from a half-stream buffer.

        Framing is the 4-byte header that precedes every message on both
        transports: a zero type byte then a 3-byte big-endian length. A sensor
        that joins mid-stream starts out of phase, so an unparseable prefix
        resyncs to the next SMB magic rather than discarding the stream.
        """
        out: List[bytes] = []
        guard = 0
        while True:
            # Defence in depth: every branch below is proven to consume at
            # least one byte or return, but a framer that can spin is a
            # sensor that stops forwarding findings, so the invariant is
            # enforced rather than trusted.
            guard += 1
            if guard > 4096:
                del buf[:]
                return out
            if len(buf) < 4:
                return out
            if buf[0] == 0:
                n = int.from_bytes(bytes(buf[1:4]), "big")
                if 4 <= n <= SMB2_MAX_MESSAGE:
                    if len(buf) < 4 + n:
                        return out                      # wait for more
                    msg = bytes(buf[4:4 + n])
                    del buf[:4 + n]
                    if msg[:4] in (SMB2_MAGIC, SMB1_MAGIC, SMB2_TRANSFORM_MAGIC):
                        out.append(msg)
                        continue
                    # framed but not SMB: fall through to resync
            # ---- resync ---------------------------------------------------
            idx = -1
            for magic in (SMB2_MAGIC, SMB2_TRANSFORM_MAGIC, SMB1_MAGIC):
                i = buf.find(magic)
                if i >= 0 and (idx < 0 or i < idx):
                    idx = i
            if idx < 0:
                # keep only what could be the start of a magic
                del buf[:max(0, len(buf) - 3)]
                return out
            if idx > 4 and buf[idx - 4] == 0:
                del buf[:idx - 4]                       # realign onto its header
                continue
            # idx == 4 means we are ALREADY aligned and the length field was
            # still unusable, so realigning would consume nothing and spin.
            # The message cannot be framed here; step past this magic.
            del buf[:idx + 4]

    @classmethod
    def iter_smb2_messages(cls, msg: bytes):
        """Yield each SMB2 header in a message, following NextCommand chaining.

        MS-SMB2 2.2.1.2: compounded requests chain through NextCommand, and a
        CREATE is routinely chained. Walking only the first header would miss
        them.
        """
        off = 0
        for _ in range(16):                             # sanity cap
            if off + SMB2_HDR_LEN > len(msg):
                return
            if msg[off:off + 4] != SMB2_MAGIC:
                return
            try:
                nxt = struct.unpack_from("<I", msg, off + SMB2_OFF_NEXT_COMMAND)[0]
            except Exception:
                return
            end = off + nxt if nxt else len(msg)
            yield msg[off:min(end, len(msg))]
            if not nxt or off + nxt <= off:
                return
            off += nxt

    @staticmethod
    def smb2_header(msg: bytes):
        """(command, flags, message_id, tree_id) or None."""
        if len(msg) < SMB2_HDR_LEN or msg[:4] != SMB2_MAGIC:
            return None
        try:
            return (struct.unpack_from("<H", msg, SMB2_OFF_COMMAND)[0],
                    struct.unpack_from("<I", msg, SMB2_OFF_FLAGS)[0],
                    struct.unpack_from("<Q", msg, SMB2_OFF_MESSAGE_ID)[0],
                    struct.unpack_from("<I", msg, SMB2_OFF_TREE_ID)[0])
        except Exception:
            return None

    @staticmethod
    def _utf16_at(msg: bytes, offset: int, length: int) -> Optional[str]:
        """A UTF-16LE string located by an offset counted from the header."""
        if length <= 0 or offset < 0 or offset + length > len(msg):
            return None
        try:
            return msg[offset:offset + length].decode("utf-16-le")
        except Exception:
            return None

    @classmethod
    def parse_tree_connect_request(cls, msg: bytes) -> Optional[str]:
        """Share path from a TREE_CONNECT request, e.g. \\\\DC01\\ADMIN$."""
        hdr = cls.smb2_header(msg)
        if hdr is None or hdr[0] != SMB2_CMD_TREE_CONNECT:
            return None
        if hdr[1] & SMB2_FLAGS_SERVER_TO_REDIR:
            return None                                 # response carries no path
        try:
            po = struct.unpack_from("<H", msg, SMB2_TC_OFF_PATH_OFFSET)[0]
            pl = struct.unpack_from("<H", msg, SMB2_TC_OFF_PATH_LENGTH)[0]
        except Exception:
            return None
        return cls._utf16_at(msg, po, pl)

    @classmethod
    def parse_create_request(cls, msg: bytes):
        """(filename, desired_access, create_options, create_disposition) or None."""
        hdr = cls.smb2_header(msg)
        if hdr is None or hdr[0] != SMB2_CMD_CREATE:
            return None
        if hdr[1] & SMB2_FLAGS_SERVER_TO_REDIR:
            return None
        if len(msg) < SMB2_CR_OFF_NAME_LENGTH + 2:
            return None
        try:
            if struct.unpack_from("<H", msg, SMB2_HDR_LEN)[0] != SMB2_CR_STRUCTURE_SIZE:
                return None
            da = struct.unpack_from("<I", msg, SMB2_CR_OFF_DESIRED_ACCESS)[0]
            cd = struct.unpack_from("<I", msg, SMB2_CR_OFF_CREATE_DISPOSITION)[0]
            co = struct.unpack_from("<I", msg, SMB2_CR_OFF_CREATE_OPTIONS)[0]
            no = struct.unpack_from("<H", msg, SMB2_CR_OFF_NAME_OFFSET)[0]
            nl = struct.unpack_from("<H", msg, SMB2_CR_OFF_NAME_LENGTH)[0]
        except Exception:
            return None
        name = cls._utf16_at(msg, no, nl)
        if name is None:
            return None
        return (name, da, co, cd)

    @classmethod
    def parse_ioctl_request(cls, msg: bytes) -> Optional[int]:
        """CtlCode from an IOCTL request."""
        hdr = cls.smb2_header(msg)
        if hdr is None or hdr[0] != SMB2_CMD_IOCTL:
            return None
        if hdr[1] & SMB2_FLAGS_SERVER_TO_REDIR:
            return None
        try:
            return struct.unpack_from("<I", msg, SMB2_IO_OFF_CTL_CODE)[0]
        except Exception:
            return None

    @staticmethod
    def smb_share_leaf(path: Optional[str]) -> Optional[str]:
        """'\\\\DC01\\ADMIN$' -> 'admin$'."""
        if not path:
            return None
        return path.rstrip("\\").split("\\")[-1].lower() or None

    @staticmethod
    def smb_norm_path(name: Optional[str]) -> str:
        """Normalise an SMB2 CREATE filename for matching."""
        if not name:
            return ""
        return name.replace("/", "\\").lstrip("\\").lower()

    # ===================================================================== #
    #  File-operation tier  (F1-F5)  -- secretsdump's SMB half
    # ===================================================================== #
    #  rpcwatch covers secretsdump's RPC paths (DCSync, and the registry
    #  method via winreg opnum 20 hive-save). It does NOT cover the step that
    #  moves the credentials off the box: reading the saved file back over
    #  SMB. That is this tier.
    #
    #  Neither module claims the chain alone. rpcwatch sees the hive written,
    #  smbwatch sees it read and deleted; an operator correlating the two by
    #  timestamp has the whole attack. Same shape as ESC8, where rpcwatch sees
    #  the coercion and httpwatch sees the relay land.
    #
    #  PRECONDITION: every rule here reads a filename out of an SMB2 CREATE.
    #  That works when a session is SIGNED and not when it is ENCRYPTED --
    #  F5 reports when the tier has gone blind rather than leaving an
    #  operator to infer it from silence.
    # ===================================================================== #
    def _handle_smb_files(self, msgs, src, dst, sport, dport, now) -> None:
        conn = self._conn_key(src, sport, dst, dport)
        for msg in msgs:
            if msg[:4] == SMB2_TRANSFORM_MAGIC:
                # server is the endpoint on the SMB port -- deterministic, so
                # the notice is attributed to the host, not to a direction
                server = src if int(sport) in (PORT_SMB, PORT_NBSS) else dst
                self._note_smb_encrypted(server, now)
                continue
            if msg[:4] != SMB2_MAGIC:
                continue
            for sub in self.iter_smb2_messages(msg):
                hdr = self.smb2_header(sub)
                if hdr is None:
                    continue
                cmd, flags, msgid, tid = hdr
                is_resp = bool(flags & SMB2_FLAGS_SERVER_TO_REDIR)

                if cmd == SMB2_CMD_TREE_CONNECT:
                    if not is_resp:
                        share = self.smb_share_leaf(
                            self.parse_tree_connect_request(sub))
                        if share:
                            self._tc_pending[(conn, msgid)] = share
                            if len(self._tc_pending) > SMB_STREAM_MAX_FLOWS:
                                self._tc_pending.clear()
                    else:
                        share = self._tc_pending.pop((conn, msgid), None)
                        if share:
                            self._tree_share[(conn, tid)] = share
                    continue

                if is_resp:
                    continue        # the request side carries what we need

                if cmd == SMB2_CMD_IOCTL:
                    if self.parse_ioctl_request(sub) == FSCTL_SRV_ENUMERATE_SNAPSHOTS:
                        self._emit_shadow_enum(src, dst, now)
                    continue

                if cmd == SMB2_CMD_CREATE:
                    parsed = self.parse_create_request(sub)
                    if parsed is not None:
                        self._handle_smb_create(parsed, conn, tid, src, dst, now)

    def _note_smb_encrypted(self, server: str, now: float) -> None:
        if not server or server in self._smb_encrypted:
            return
        self._smb_encrypted.add(server)
        self._emit(Finding(
            rule="F5", severity=Severity.INFO, subject=server,
            title="SMB3 encryption in use -- file tier is blind to this server",
            detail=("Traffic to/from %s carries SMB3 TRANSFORM headers, so the "
                    "session is encrypted rather than merely signed. Filenames "
                    "live inside that encryption, so the F1-F4 file rules "
                    "cannot see credential exfiltration on this server. This is "
                    "a statement about visibility, not a problem with the "
                    "server -- encryption is the stronger posture. It is "
                    "reported so the coverage gap is observed rather than "
                    "assumed." % server),
            proto="SMB", names=[],
            evidence={"server": server, "blind_rules": "F1, F2, F3, F4"},
            first_seen=now, last_seen=now))

    def _emit_shadow_enum(self, client: str, server: str, now: float) -> None:
        """F3 -- FSCTL_SRV_ENUMERATE_SNAPSHOTS. Legitimate backup software does
        this; a workstation doing it to a DC does not."""
        key = ("F3", client, server)
        if key in self._file_reported:
            return
        self._file_reported.add(key)
        known = client in self.cfg.backup_hosts
        self._emit(Finding(
            rule="F3", severity=Severity.LOW if known else Severity.HIGH,
            subject=client,
            title=("Shadow-copy enumeration from a known backup host" if known
                   else "Shadow-copy enumeration over SMB"),
            detail=("%s issued SMB2 IOCTL FSCTL_SRV_ENUMERATE_SNAPSHOTS "
                    "(0x%08X) against %s. Enumerating shadow copies is how an "
                    "operator reaches a locked ntds.dit or registry hive; "
                    "impacket's secretsdump does exactly this with -use-vss. "
                    "%s" %
                    (client, FSCTL_SRV_ENUMERATE_SNAPSHOTS, server,
                     "This client is on the configured backup-host list, so it "
                     "is reported for the record only."
                     if known else
                     "This client is NOT on the configured backup-host list "
                     "(--backup-host); backup software is expected here, a "
                     "workstation is not.")),
            proto="SMB", names=[],
            evidence={"client": client, "server": server,
                      "fsctl": "FSCTL_SRV_ENUMERATE_SNAPSHOTS",
                      "ctl_code": "0x%08X" % FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                      "known_backup_host": str(known),
                      "alias": "SMB-SHADOW-COPY-ENUM"},
            first_seen=now, last_seen=now))

    def _handle_smb_create(self, parsed, conn, tid, client, server, now) -> None:
        name, desired, options, disposition = parsed
        path = self.smb_norm_path(name)
        if not path:
            return
        share = self._tree_share.get((conn, tid))

        # ---- rpcwatch boundary ------------------------------------------- #
        # Named pipes belong to rpcwatch, which already carves DCERPC out of
        # SMB2 on \pipe\* and IPC$. Double-firing one PDU across two sensors
        # would be worse than a gap.
        if share == "ipc$" or path.startswith("pipe\\") or "\\pipe\\" in path:
            return

        read = bool(desired & FILE_READ_DATA)
        write = bool(desired & FILE_WRITE_DATA)
        delete = bool(desired & ACCESS_DELETE) or bool(options & FILE_DELETE_ON_CLOSE)

        # ---- F2: impacket's remote-execution output file ------------------ #
        if path == SMB_REMOTE_EXEC_OUTPUT:
            key = ("F2", client, server)
            if key not in self._file_reported:
                self._file_reported.add(key)
                self._emit(Finding(
                    rule="F2", severity=Severity.HIGH, subject=client,
                    title="impacket remote-execution output file accessed",
                    detail=("%s opened '%s' on %s. That is the fixed filename "
                            "impacket's service-based remote execution uses to "
                            "return command output -- psexec, smbexec and "
                            "secretsdump all land on it. It is a literal with "
                            "no legitimate use, so one sighting is the finding."
                            % (client, name, server)),
                    proto="SMB", names=[name],
                    evidence={"client": client, "server": server, "path": name,
                              "share": share or "unknown",
                              "alias": "SMB-REMOTE-EXEC-OUTPUT"},
                    first_seen=now, last_seen=now))
            return

        # ---- F4: credential stores by name -------------------------------- #
        # secretsdump does NOT take this path -- it reads a randomly-named
        # copy. This rule exists for hand operators and other tools, so that
        # the module is technique-specific rather than tool-specific.
        hit = None
        for frag in SMB_CREDENTIAL_PATHS:
            if path.endswith(frag) or ("\\" + frag) in path:
                hit = frag
                break
        if hit is None and SMB_EDB_LOG_RE.search(path):
            hit = "edb*.log"
        if hit is None:
            for marker in SMB_CREDENTIAL_MARKERS:
                if marker in path:
                    hit = marker
                    break
        if hit is not None:
            key = ("F4", client, server, path)
            if key not in self._file_reported:
                self._file_reported.add(key)
                self._emit(Finding(
                    rule="F4", severity=Severity.CRITICAL, subject=client,
                    title="Credential store accessed over SMB",
                    detail=("%s opened '%s' on %s (matched: %s). The registry "
                            "hives and the AD database are essentially never "
                            "read over SMB in normal operation; reading them "
                            "is credential theft. Note that impacket's "
                            "secretsdump does NOT do this -- it reads a "
                            "randomly-named copy instead, which is F1 -- so "
                            "this finding points at a hand operator or a "
                            "different tool." % (client, name, server, hit)),
                    proto="SMB", names=[name],
                    evidence={"client": client, "server": server, "path": name,
                              "share": share or "unknown", "matched": hit,
                              "alias": "SMB-CREDENTIAL-FILE-READ"},
                    first_seen=now, last_seen=now))
            return

        # ---- F1: impacket's randomly-named hive copy ---------------------- #
        # Restricted to the administrative shares, because that is where the
        # signature lives. A share we never saw a TREE_CONNECT for (sensor
        # joined mid-stream) still reports, one severity lower and labelled.
        if share is not None and share not in SMB_ADMIN_SHARES:
            return
        if not self._temp_exfil_re.match(path):
            return

        key = (conn, tid, path)
        st = self._exfil.get(key)
        if st is None:
            st = {"access": set(), "first": now, "client": client,
                  "server": server, "name": name, "share": share}
            self._exfil[key] = st
        st["last"] = now
        if share is not None:
            st["share"] = share
        for flag, label in ((read, "read"), (write, "write"), (delete, "delete")):
            if flag:
                st["access"].add(label)

        acc = st["access"]
        complete = "read" in acc and "delete" in acc
        sev = Severity.CRITICAL if complete else Severity.HIGH
        known_share = st["share"] is not None
        if not known_share:
            # honest confidence: we could not confirm the share
            sev = Severity.HIGH if complete else Severity.MEDIUM

        sig = (tuple(sorted(acc)), known_share)
        if self._exfil_reported.get(key) == sig:
            return
        self._exfil_reported[key] = sig

        self._emit(Finding(
            rule="F1", severity=sev, subject=st["client"],
            title=("Credential exfiltration over SMB (read then deleted)"
                   if complete else
                   "Credential-exfil temp file accessed over SMB"),
            detail=("%s accessed '%s' on %s%s. The name matches impacket's "
                    "generated hive copy -- eight ASCII letters plus .tmp "
                    "under Temp\\ -- which secretsdump writes with the "
                    "registry method and then reads back over SMB. Observed "
                    "operations: %s.%s" %
                    (st["client"], st["name"], st["server"],
                     (" (share %s)" % st["share"]) if known_share
                     else " (share unconfirmed: no TREE_CONNECT seen, sensor "
                          "likely joined mid-stream)",
                     ", ".join(sorted(acc)) or "open",
                     " The read and the delete both landed, so this is the "
                     "exfiltration completed and cleaned up."
                     if complete else
                     " No delete seen yet; the capture may have missed a leg.")),
            proto="SMB", names=[st["name"]],
            evidence={"client": st["client"], "server": st["server"],
                      "path": st["name"], "share": st["share"] or "unknown",
                      "operations": ", ".join(sorted(acc)),
                      "sequence_complete": str(complete),
                      "alias": "SMB-CREDENTIAL-EXFIL-TEMP"},
            first_seen=st["first"], last_seen=now), refresh=True)

    # ===================================================================== #
    #  Correlation  (C1)  -- the money finding
    # ===================================================================== #
    #  A confirmed poisoner (R1/R2/R4) sharing the monitored segment with a
    #  concrete attacker avenue is folded into one finding per poisoner:
    #    * an unsigned SMB relay target (S2/S3)        -> live NTLM-relay path
    #    * a Kerberos-downgrade client (strong K-rules) -> weak-auth neighbour
    #  CRITICAL when a real relay path exists; HIGH when only downgrade clients
    #  keep the poisoner company. Re-fires only when a new target or downgrade
    #  client appears, so it doesn't spam.
    # ===================================================================== #
    def _mark_poisoner(self, ip: str, names, now: float) -> None:
        if isinstance(names, str):
            names = [names]
        self._poisoners[ip].update(self._norm(n) for n in names)
        self._check_correlation(now)

    def _mark_relay_target(self, ip: str, reason: str, now: float) -> None:
        self._relay_targets[ip] = reason
        self._check_correlation(now)
        self._check_directed_edge(now)

    def _mark_downgrade_client(self, ip: str, reason: str, now: float) -> None:
        if ip:
            self._downgrade_clients[ip].add(reason)
            self._check_correlation(now)
            self._check_directed_edge(now)   # may upgrade an existing C2 edge

    def _check_correlation(self, now: float) -> None:
        if not self._poisoners:
            return
        if not self._relay_targets and not self._downgrade_clients:
            return
        for pois, pnames in self._poisoners.items():
            # a poisoner is never its own target / downgrade client
            targets = {ip: why for ip, why in self._relay_targets.items() if ip != pois}
            dclients = {ip: sorted(r) for ip, r in self._downgrade_clients.items()
                        if ip != pois}
            if not targets and not dclients:
                continue
            new_t = set(targets) - self._relay_reported[pois]
            new_d = set(dclients) - self._downgrade_reported[pois]
            # a target we already reported can BECOME compound later, when its
            # SMBGhost exposure is learned from a subsequent negotiate
            compound = {ip for ip in targets if ip in self._smbghost}
            new_c = compound - self._compound_reported[pois]
            if not new_t and not new_d and not new_c:
                continue  # nothing new; stay quiet
            self._relay_reported[pois] = set(targets)
            self._downgrade_reported[pois] = set(dclients)
            self._compound_reported[pois] = set(compound)

            tlist = sorted(targets)
            dlist = sorted(dclients)
            clist = sorted(compound)
            answered = ", ".join(sorted(pnames)) or "-"
            parts = ["Attacker foothold on the monitored segment: poisoner %s "
                     "(answered: %s)." % (pois, answered)]
            if tlist:
                parts.append(
                    "Live NTLM-relay path -- captured authentication can be relayed "
                    "to %d unsigned SMB target(s): %s." %
                    (len(tlist), ", ".join("%s (%s)" % (ip, targets[ip]) for ip in tlist)))
            if dlist:
                parts.append(
                    "%d Kerberos-downgrade client(s) share this segment: %s -- weak "
                    "Kerberos crypto compounds the exposure." %
                    (len(dlist), ", ".join("%s [%s]" % (ip, "; ".join(dclients[ip]))
                                           for ip in dlist)))
            if clist:
                parts.append(
                    "COMPOUND EXPOSURE -- %d of those target(s) also advertise SMB "
                    "compression (CVE-2020-0796): %s. The attacker does not even "
                    "need the relay for these; they are reachable pre-auth." %
                    (len(clist), ", ".join(clist)))
            if tlist:
                parts.append("Both halves of the relay chain are present now; this is "
                             "an exploitable condition, not a latent misconfiguration.")
            severity = Severity.CRITICAL if tlist else Severity.HIGH
            title = ("Live NTLM-relay path (poisoner + unsigned target)" if tlist
                     else "Poisoner co-located with Kerberos-downgrade client(s)")
            if clist:
                title = "Live NTLM-relay path + SMBGhost-exposed target(s)"
            evidence = {}
            if tlist:
                evidence["relay_targets"] = ", ".join(tlist)
                evidence["target_count"] = str(len(tlist))
            if dlist:
                evidence["downgrade_clients"] = ", ".join(dlist)
                evidence["downgrade_client_count"] = str(len(dlist))
            if clist:
                evidence["smbghost_targets"] = ", ".join(clist)
                evidence["compound_cve"] = "CVE-2020-0796"
            self._emit_c1(pois, sorted(pnames), " ".join(parts), severity,
                          title, evidence, now)

    def _emit_c1(self, poisoner: str, pnames: List[str], detail: str,
                 severity: Severity, title: str, evidence: Dict[str, str],
                 now: float) -> None:
        """C1 is emitted directly (not via _emit) so it can re-fire whenever the
        target / downgrade-client set grows, refreshing everything each time and
        escalating severity if a relay path appears after a downgrade-only fire."""
        f = Finding(
            rule="C1", severity=severity, subject=poisoner, title=title,
            detail=detail, proto=None, names=pnames, evidence=evidence,
            first_seen=now, last_seen=now,
        )
        key = f.key()
        prev = self._emitted.get(key)
        if prev is None:
            self._emitted[key] = f
            self.findings.append(f)
        else:
            prev.count += 1
            prev.last_seen = now
            prev.detail = detail
            prev.title = title
            prev.names = sorted(set(prev.names) | set(pnames))
            prev.evidence = evidence
            if severity > prev.severity:
                prev.severity = severity
            f = prev
        if self._emit_cb:
            self._emit_cb(f)

    # ===================================================================== #
    #  Directed Kerberos -> SMB edge  (C2)
    # ===================================================================== #
    #  C1 says "a poisoner and an unsigned target share this segment." C2 is
    #  tighter: it names WHICH client is authenticating to WHICH unsigned relay
    #  target, by tying a Kerberos SMB-service ticket (SPN class cifs/host) to a
    #  relay-target IP -- either because the SPN host resolves (via passively
    #  observed name resolution) to that IP, or because we directly saw the
    #  client open an SMB session to it. HIGH; CRITICAL if a poisoner is live.
    # ===================================================================== #
    @staticmethod
    def _spn_host(spn: Optional[str]) -> Optional[Tuple[str, str]]:
        """From 'cifs/fs01.corp.local:445' -> ('cifs', 'fs01.corp.local').
        Returns (service_class, host) or None."""
        if not spn or "/" not in spn:
            return None
        cls, _, rest = spn.partition("/")
        host = rest.split(":", 1)[0].split("/", 1)[0].strip().lower()
        return (cls.lower(), host) if host else None

    def _mark_smb_intent(self, client: str, spn: Optional[str], now: float) -> None:
        parsed = self._spn_host(spn)
        if not parsed or not client:
            return
        cls, host = parsed
        if cls not in KRB_SMB_SERVICE_CLASSES:
            return
        self._smb_intent[client].add(host)
        self._check_directed_edge(now)

    def _resolve_host_ips(self, host: str) -> Set[str]:
        """Resolve a SPN host to IPs via passively observed name resolution.
        Matches the full name and the short (first-label) name."""
        ips: Set[str] = set()
        h = host.rstrip(".").lower()
        ips |= self._resolved.get(h, set())
        short = h.split(".", 1)[0]
        ips |= self._resolved.get(short, set())
        for name, addrs in self._resolved.items():
            if name.split(".", 1)[0] == short:
                ips |= addrs
        return ips

    def _check_directed_edge(self, now: float) -> None:
        if not self._smb_intent or not self._relay_targets:
            return
        poisoner_live = bool(self._poisoners)
        for client, hosts in self._smb_intent.items():
            targets: Dict[str, str] = {}   # target_ip -> how we linked it
            # (a) SPN host resolves to a relay-target IP
            for host in hosts:
                for ip in self._resolve_host_ips(host):
                    if ip in self._relay_targets and ip != client:
                        targets[ip] = "SPN %s -> %s" % (host, ip)
            # (b) we directly observed this client open an SMB session to a
            #     relay-target IP (session confirms the intent landed)
            for (c, srv) in self._smb_sessions:
                if c == client and srv in self._relay_targets and srv != client:
                    targets.setdefault(srv, "observed SMB session")
            for tip, how in targets.items():
                key = (client, tip)
                # an edge already reported can gain new weight later: the client
                # may become a known downgrade client, or the target may turn
                # out to be SMBGhost-exposed. Re-fire once per new dimension.
                weak_client = sorted(self._downgrade_clients.get(client, ()))
                ghost = tip in self._smbghost
                sig = (bool(weak_client), ghost, poisoner_live)
                if self._edge_reported_sig.get(key) == sig:
                    continue
                self._edge_reported_sig[key] = sig
                self._edge_reported.add(key)

                # Severity: a downgrade client walking into an unsigned target is
                # the blend both correlations were built to find -- the victim's
                # own Kerberos crypto is weak AND the destination won't sign.
                sev = (Severity.CRITICAL if (poisoner_live or weak_client or ghost)
                       else Severity.HIGH)
                extra = ""
                if poisoner_live:
                    extra += (" A poisoner is live on this segment and could hijack "
                              "this exact authentication.")
                if weak_client:
                    extra += (" The client is itself a Kerberos-downgrade client "
                              "[%s], so the authentication is weak at BOTH ends -- "
                              "crackable offline and relayable on arrival." %
                              "; ".join(weak_client))
                if ghost:
                    extra += (" The target also advertises SMB compression "
                              "(CVE-2020-0796, algorithms: %s), so it is reachable "
                              "pre-auth without the relay at all." % self._smbghost[tip])
                ev = {"client": client, "target": tip,
                      "target_dialect": self._relay_targets[tip], "link": how}
                if weak_client:
                    ev["client_downgrade"] = "; ".join(weak_client)
                if ghost:
                    ev["target_smbghost"] = self._smbghost[tip]
                    ev["compound_cve"] = "CVE-2020-0796"
                title = "Directed Kerberos->SMB path to unsigned relay target"
                if weak_client:
                    title = "Directed path: downgrade client -> unsigned relay target"
                self._emit(Finding(
                    rule="C2", severity=sev, subject=client,
                    title=title,
                    detail=("Client %s is authenticating over Kerberos to SMB on "
                            "unsigned relay target %s (%s; %s). This is a concrete "
                            "victim->target edge, not just co-location: creds for "
                            "this session are relayable to a server that won't "
                            "enforce signing.%s" %
                            (client, tip, self._relay_targets[tip], how, extra)),
                    proto="SMB/Kerberos", names=[],
                    evidence=ev,
                    first_seen=now, last_seen=now,
                ), refresh=True)
    #  REQUEST side (AS-REQ / TGS-REQ): what etypes the client OFFERS.
    #    K1 DES offered, K2 RC4 offered, K3 no AES offered.
    #  REPLY side (AS-REP / TGS-REP): what the KDC actually GRANTED, read from
    #  the (cleartext) etype of the ticket's EncryptedData and the reply's
    #  EncryptedData.
    #    K4 KDC granted RC4, K5 KDC granted DES.
    #  The reply side is the stronger signal -- it catches the KDC handing out
    #  RC4 service tickets (Kerberoastable) even when the offer looked benign.
    # ===================================================================== #
    def _handle_kerberos(self, pkt, l4, src, framed: bool) -> None:
        try:
            payload = bytes(l4.payload)
        except Exception:
            return
        if len(payload) < 4:
            return
        dst = self._l3_dst(pkt)

        req = self.parse_kdc_req(payload)
        if req is not None:
            self._handle_krb_request(req, src or "?", pkt)
            return
        rep = self.parse_kdc_rep(payload)
        if rep is not None:
            # a REP travels KDC -> client; attribute to the client (dst)
            self._handle_krb_reply(rep, dst or "?", pkt)
            return
        err = self.parse_krb_error(payload)
        if err is not None:
            # a KRB-ERROR travels KDC -> client; the requester is the dst
            self._handle_krb_error(err, dst or "?", pkt)

    @staticmethod
    def _etype_names(lst) -> List[str]:
        return [KRB_ETYPE.get(e, "etype-%d" % e) for e in lst]

    # ----- request side (offers + pre-auth + intent): K1/K2/K3 ------------ #
    def _handle_krb_request(self, req, client: str, pkt) -> None:
        app_tag, etypes, cname, realm, sname, has_pa_enc_ts = req
        now = _pkt_time(pkt)

        # pre-auth state (AS-REQ only): remember whether this AS-REQ carried an
        # encrypted-timestamp. The final AS-REQ before an AS-REP decides it, so
        # the with-preauth resend correctly overwrites the initial probe.
        if app_tag == KRB_APP_AS_REQ and cname:
            st = self._krb_preauth.setdefault(cname.lower(),
                                              {"preauth": False, "required": False})
            st["preauth"] = bool(has_pa_enc_ts)
            st["ts"] = now
        # directed-edge intent (TGS-REQ names the target SPN)
        if app_tag == KRB_APP_TGS_REQ:
            self._mark_smb_intent(client, sname, now)

        # CVE-2025-33073: a requested SPN carrying a marshalled target blob
        self._check_marshalled_target(sname, client, "Kerberos SPN in a %s"
                                      % KRB_MSG_NAME.get(app_tag, "KDC-REQ"), now)

        if not etypes:
            return
        msg = KRB_MSG_NAME.get(app_tag, "KDC-REQ")

        # CVE-2022-33679/33647: RC4-MD4 (etype -128) offered
        if KRB_ETYPE_RC4_MD4 in etypes:
            principal_s = (cname + ("@" + realm if realm else "")) if cname else ""
            self._emit(Finding(
                rule="V4", severity=Severity.CRITICAL, subject=client,
                title="Kerberos RC4-MD4 requested (CVE-2022-33679)",
                detail=("%s%s requests etype -128 (RSADSI RC4-MD4). This "
                        "algorithm has a 40-bit effective key with no IV or salt "
                        "and is never negotiated by a healthy client -- its "
                        "presence is the downgrade step of CVE-2022-33679, which "
                        "lets an unauthenticated attacker brute-force the session "
                        "key from the AS-REP and obtain a TGT." %
                        (msg, (" for %s" % principal_s) if principal_s else "")),
                proto=PROTO_KRB, names=[principal_s] if principal_s else [],
                evidence={"cve": "CVE-2022-33679", "message": msg,
                          "offered_etypes": ", ".join(self._etype_names(etypes))},
                first_seen=now, last_seen=now))
            self._mark_downgrade_client(client, "RC4-MD4 requested (%s)" % msg, now)

        weak = [e for e in etypes if e in KRB_ETYPE_WEAK]
        des = [e for e in etypes if e in KRB_ETYPE_DES]
        rc4 = [e for e in etypes if e in KRB_ETYPE_RC4]
        has_aes = any(e in KRB_ETYPE_AES for e in etypes)
        most_preferred = etypes[0]  # etype list is in client preference order
        names_of = self._etype_names

        principal = (cname + ("@" + realm if realm else "")) if cname else ""
        ev_common = {"message": msg, "offered_etypes": ", ".join(names_of(etypes))}
        if principal:
            ev_common["principal"] = principal
        pname = [principal] if principal else []

        if des:
            ev = dict(ev_common); ev["des_etypes"] = ", ".join(names_of(des))
            self._emit(Finding(
                rule="K1", severity=Severity.HIGH, subject=client,
                title="Kerberos %s offers DES" % msg,
                detail=("Client %s%s offers DES encryption (%s). DES is "
                        "cryptographically broken; a KDC honoring it exposes "
                        "trivially-crackable tickets. This should not appear on a "
                        "modern network." %
                        (msg, (" for %s" % principal) if principal else "",
                         ", ".join(names_of(des)))),
                proto=PROTO_KRB, names=pname, evidence=ev,
                first_seen=now, last_seen=now))
            self._mark_downgrade_client(client, "DES offered (%s)" % msg, now)

        if rc4:
            rc4_preferred = most_preferred in KRB_ETYPE_RC4
            sev = Severity.HIGH if rc4_preferred else Severity.MEDIUM
            ev = dict(ev_common)
            ev["rc4_etypes"] = ", ".join(names_of(rc4))
            ev["rc4_most_preferred"] = str(rc4_preferred)
            self._emit(Finding(
                rule="K2", severity=sev, subject=client,
                title="Kerberos %s offers RC4%s"
                      % (msg, " (as top preference)" if rc4_preferred else ""),
                detail=("Client %s%s offers RC4 (%s)%s. RC4-HMAC enables "
                        "Kerberoasting and NTLM/Kerberos downgrade; on a healthy "
                        "AES-only domain it should be absent. Listing RC4 as the "
                        "most-preferred etype is a strong downgrade signal." %
                        (msg, (" for %s" % principal) if principal else "",
                         ", ".join(names_of(rc4)),
                         " and prefers it over any AES" if rc4_preferred else "")),
                proto=PROTO_KRB, names=pname, evidence=ev,
                first_seen=now, last_seen=now))
            # only a *strong* offer folds into C1 (plain RC4 offers are common)
            if rc4_preferred:
                self._mark_downgrade_client(client, "RC4 offered top-pref (%s)" % msg, now)

        if not has_aes and weak:
            self._emit(Finding(
                rule="K3", severity=Severity.HIGH, subject=client,
                title="Kerberos %s offers no AES (downgrade posture)" % msg,
                detail=("Client %s%s offers only legacy/weak etypes with no AES "
                        "(%s). Either a very old client or an attacker forcing weak "
                        "crypto; in both cases tickets minted here are weakly "
                        "protected." %
                        (msg, (" for %s" % principal) if principal else "",
                         ", ".join(names_of(etypes)))),
                proto=PROTO_KRB, names=pname, evidence=dict(ev_common),
                first_seen=now, last_seen=now))
            self._mark_downgrade_client(client, "no AES offered (%s)" % msg, now)

    # ----- reply side (grants + roastable + intent): K4/K5/K6 ------------- #
    def _handle_krb_reply(self, rep, client: str, pkt) -> None:
        app_tag, ticket_etype, reply_etype, cname, realm, sname = rep
        now = _pkt_time(pkt)
        msg = KRB_MSG_NAME.get(app_tag, "KDC-REP")

        # directed-edge intent: a TGS-REP ticket names the SMB service host
        if app_tag == KRB_APP_TGS_REP:
            self._mark_smb_intent(client, sname, now)

        # CVE-2025-33073: a granted ticket for a marshalled target name
        self._check_marshalled_target(sname, client, "Kerberos ticket SPN in a %s"
                                      % KRB_MSG_NAME.get(app_tag, "KDC-REP"), now)

        # CVE-2022-33679/33647: the KDC actually granted RC4-MD4
        if KRB_ETYPE_RC4_MD4 in (ticket_etype, reply_etype):
            self._emit(Finding(
                rule="V4", severity=Severity.CRITICAL, subject=client,
                title="KDC granted RC4-MD4 (CVE-2022-33679)",
                detail=("KDC issued a %s using etype -128 (RSADSI RC4-MD4). The "
                        "downgrade succeeded: the session key in this reply is "
                        "recoverable byte-by-byte from the keystream, which is "
                        "exactly the CVE-2022-33679 primitive for obtaining a TGT "
                        "without credentials. Treat any account in this exchange "
                        "as compromised." % msg),
                proto=PROTO_KRB, names=[],
                evidence={"cve": "CVE-2022-33679", "message": msg,
                          "ticket_etype": str(ticket_etype),
                          "reply_etype": str(reply_etype)},
                first_seen=now, last_seen=now))
            self._mark_downgrade_client(client, "RC4-MD4 granted (%s)" % msg, now)

        # ---- K6: AS-REP-roastable account (no pre-auth was required) ------ #
        if app_tag == KRB_APP_AS_REP and cname:
            st = self._krb_preauth.get(cname.lower())
            # an AS-REP whose matching AS-REQ carried no encrypted-timestamp and
            # was never met with a PREAUTH_REQUIRED error => pre-auth disabled.
            if st is not None and not st.get("preauth") and not st.get("required"):
                principal = cname + ("@" + realm if realm else "")
                ekind = KRB_ETYPE.get(reply_etype, "etype-%s" % reply_etype) \
                    if reply_etype is not None else "?"
                self._emit(Finding(
                    rule="K6", severity=Severity.HIGH, subject=client,
                    title="AS-REP-roastable account (pre-auth not required)",
                    detail=("KDC returned an AS-REP for %s without ever requiring "
                            "encrypted-timestamp pre-authentication. The account has "
                            "'do not require pre-auth' set, so its AS-REP enc-part "
                            "(%s) can be captured and cracked offline (AS-REP "
                            "roasting) with no interaction." % (principal, ekind)),
                    proto=PROTO_KRB, names=[principal],
                    evidence={"principal": principal, "reply_etype": ekind},
                    first_seen=now, last_seen=now))
                if reply_etype in KRB_ETYPE_RC4 or reply_etype in KRB_ETYPE_DES:
                    self._mark_downgrade_client(client, "AS-REP-roastable (%s)" % ekind, now)
                else:
                    self._mark_downgrade_client(client, "AS-REP-roastable account", now)

        roles = []  # (role, etype)
        if ticket_etype is not None:
            roles.append(("ticket", ticket_etype))
        if reply_etype is not None:
            roles.append(("reply", reply_etype))
        weak_roles = [(r, e) for (r, e) in roles if e in KRB_ETYPE_WEAK]
        if not weak_roles:
            return  # KDC granted AES -- healthy

        principal = (cname + ("@" + realm if realm else "")) if cname else ""
        ename = lambda e: KRB_ETYPE.get(e, "etype-%d" % e)

        notes = []
        for role, e in weak_roles:
            if role == "ticket":
                if app_tag == KRB_APP_TGS_REP:
                    notes.append("service ticket%s encrypted with %s -- Kerberoastable "
                                 "offline" % ((" for SPN %s" % sname) if sname else "",
                                              ename(e)))
                else:  # AS-REP: ticket is the TGT (krbtgt key)
                    notes.append("TGT encrypted with %s (KDC still issues %s tickets)"
                                 % (ename(e), "RC4" if e in KRB_ETYPE_RC4 else "DES"))
            else:  # reply enc-part
                if app_tag == KRB_APP_AS_REP:
                    notes.append("AS-REP reply encrypted with %s -- AS-REP-roasting "
                                 "surface%s" % (ename(e),
                                                (" for %s" % principal) if principal else ""))
                else:
                    notes.append("reply enc-part uses %s" % ename(e))

        has_des = any(e in KRB_ETYPE_DES for _, e in weak_roles)
        ev = {"message": msg,
              "ticket_etype": ename(ticket_etype) if ticket_etype is not None else "?",
              "reply_etype": ename(reply_etype) if reply_etype is not None else "?"}
        if principal:
            ev["principal"] = principal
        if sname:
            ev["spn"] = sname
        pname = [principal] if principal else ([sname] if sname else [])

        if has_des:
            self._emit(Finding(
                rule="K5", severity=Severity.CRITICAL, subject=client,
                title="Kerberos %s: KDC granted DES" % msg,
                detail=("KDC granted weak Kerberos crypto in a %s: %s. DES is "
                        "trivially broken; an attacker capturing this exchange can "
                        "recover keys offline." % (msg, "; ".join(notes))),
                proto=PROTO_KRB, names=pname, evidence=ev,
                first_seen=now, last_seen=now))
            self._mark_downgrade_client(client, "DES granted by KDC (%s)" % msg, now)
        else:  # RC4
            self._emit(Finding(
                rule="K4", severity=Severity.HIGH, subject=client,
                title="Kerberos %s: KDC granted RC4" % msg,
                detail=("KDC granted RC4 in a %s: %s. This is the KDC actually "
                        "handing out weak crypto -- not merely a client offering it "
                        "-- so the resulting ticket is crackable offline." %
                        (msg, "; ".join(notes))),
                proto=PROTO_KRB, names=pname, evidence=ev,
                first_seen=now, last_seen=now))
            self._mark_downgrade_client(client, "RC4 granted by KDC (%s)" % msg, now)

    # ----- KRB-ERROR side: pre-auth-required marking + K7 ----------------- #
    def _handle_krb_error(self, err, client: str, pkt) -> None:
        code, cname, realm, sname, etype_info2 = err
        now = _pkt_time(pkt)

        # ---- V5: CVE-2022-33679 downgrade injection ---------------------- #
        # A KDC answering PREAUTH_REQUIRED normally lists every etype it will
        # accept. If that list contains RC4-MD4 -- above all if it is the ONLY
        # entry -- the client will derive its pre-auth timestamp key with the
        # broken algorithm even though it never asked for it. That is the
        # man-in-the-middle step of CVE-2022-33679/33647.
        if etype_info2 and KRB_ETYPE_RC4_MD4 in etype_info2:
            only = len(set(etype_info2)) == 1
            principal_e = (cname + ("@" + realm if realm else "")) if cname else ""
            self._emit(Finding(
                rule="V5", severity=Severity.CRITICAL, subject=client,
                title="Kerberos PA-ETYPE-INFO2 offers RC4-MD4 (CVE-2022-33679 "
                      "downgrade injection)",
                detail=("A KRB-ERROR (%s)%s carries PA-ETYPE-INFO2 advertising "
                        "etype -128 (RSADSI RC4-MD4)%s. A client trusts this list "
                        "when deriving its pre-auth key, so an injected or "
                        "tampered reply forces the broken algorithm even on a "
                        "client that offered only AES -- the CVE-2022-33679 / "
                        "CVE-2022-33647 downgrade step. A genuine KDC does not "
                        "advertise RC4-MD4." %
                        (KRB_ERR_NAME.get(code, "code %d" % code),
                         (" for %s" % principal_e) if principal_e else "",
                         " as the ONLY acceptable etype" if only else "")),
                proto=PROTO_KRB, names=[principal_e] if principal_e else [],
                evidence={"cve": "CVE-2022-33679",
                          "error_code": KRB_ERR_NAME.get(code, str(code)),
                          "etype_info2": ", ".join(self._etype_names(etype_info2)),
                          "rc4_md4_only": str(only)},
                first_seen=now, last_seen=now))
            self._mark_downgrade_client(client, "RC4-MD4 offered by KDC reply", now)

        # CVE-2025-33073: an error naming a marshalled target SPN
        self._check_marshalled_target(sname, client, "Kerberos SPN in a KRB-ERROR", now)

        # PREAUTH_REQUIRED tells us the account is NOT roastable -- record it so
        # a later legitimate AS-REP for it is never mis-flagged as K6.
        if code == KRB_ERR_PREAUTH_REQUIRED and cname:
            st = self._krb_preauth.setdefault(cname.lower(),
                                              {"preauth": False, "required": False})
            st["required"] = True
            st["ts"] = now

        # K7: a burst of "unknown principal" / "preauth failed" errors toward one
        # requester is user enumeration or password-spray / AS-REP-roast probing.
        if code in (KRB_ERR_C_PRINCIPAL_UNKNOWN, KRB_ERR_PREAUTH_FAILED) and client:
            dq = self._krb_err[client]
            dq.append((now, code))
            while dq and (now - dq[0][0]) > self.cfg.window:
                dq.popleft()
            if len(dq) >= self.cfg.krb_err_threshold and client not in self._krb_err_reported:
                self._krb_err_reported.add(client)
                unknown = sum(1 for _, c in dq if c == KRB_ERR_C_PRINCIPAL_UNKNOWN)
                failed = sum(1 for _, c in dq if c == KRB_ERR_PREAUTH_FAILED)
                if unknown >= failed:
                    kind, why = ("user enumeration",
                                 "repeated UNKNOWN-principal errors map out which "
                                 "accounts exist")
                else:
                    kind, why = ("password spray / AS-REP-roast probing",
                                 "repeated PREAUTH-FAILED errors are guesses against "
                                 "known accounts")
                self._emit(Finding(
                    rule="K7", severity=Severity.HIGH, subject=client,
                    title="Kerberos %s pattern" % kind,
                    detail=("%d Kerberos KDC errors toward %s within %ds -- %s. "
                            "Characteristic of pre-attack reconnaissance against the "
                            "domain." % (len(dq), client, int(self.cfg.window), why)),
                    proto=PROTO_KRB, names=[],
                    evidence={"errors": str(len(dq)),
                              "unknown_principal": str(unknown),
                              "preauth_failed": str(failed)},
                    first_seen=now, last_seen=now))

    # ===================================================================== #
    #  NTLM relay-in-progress  (N1/N2/N3)
    # ===================================================================== #
    #  Behavioural signatures of an active relay, parsed from NTLMSSP messages
    #  carried in SMB SESSION_SETUP (the "NTLMSSP\\0" blob is located directly, so
    #  this is framing-agnostic):
    #    N1  the same NTLM server challenge appears in 2+ sessions / from 2+
    #        server IPs -- a relay passes one challenge through both legs.
    #    N2  a Type-3 AUTHENTICATE whose stated workstation doesn't match the
    #        connecting host's observed name -- relayed auth carries the victim's
    #        identity, not the relay box's.
    #    N3  a static/known Responder challenge (0x1122334455667788).
    # ===================================================================== #
    def _handle_ntlmssp(self, payload: bytes, src: str, dst: str, now: float) -> None:
        off = payload.find(NTLMSSP_SIG)
        if off < 0 or off + 12 > len(payload):
            return
        try:
            msg_type = struct.unpack_from("<I", payload, off + 8)[0]
        except Exception:
            return

        if msg_type == NTLM_TYPE_CHALLENGE:
            # server -> client: src is the (possibly relayed) authenticating server
            if off + 32 > len(payload):
                return
            challenge = payload[off + 24:off + 32]
            if challenge == b"\x00" * 8:
                return

            # N3: known static challenge = a rogue NTLM server on the wire
            if challenge in NTLM_STATIC_CHALLENGES:
                if challenge not in self._ntlm_chal_reported:
                    self._ntlm_chal_reported.add(challenge)
                    self._emit(Finding(
                        rule="N3", severity=Severity.CRITICAL, subject=src,
                        title="Static Responder NTLM challenge on the wire",
                        detail=("SMB server %s issued the fixed NTLM challenge %s -- "
                                "the Responder/Inveigh default. A rogue "
                                "authentication server is active and harvesting "
                                "NetNTLM responses." % (src, challenge.hex())),
                        proto="SMB/NTLM", names=[],
                        evidence={"challenge": challenge.hex(), "server": src},
                        first_seen=now, last_seen=now))

            rec = self._ntlm_chal.get(challenge)
            if rec is None:
                rec = {"srcs": {}, "sessions": {}}
                self._ntlm_chal[challenge] = rec
            # prune by window
            for d in (rec["srcs"], rec["sessions"]):
                for k in [k for k, ts in d.items() if now - ts > self.cfg.window]:
                    del d[k]
            rec["srcs"][src] = now
            rec["sessions"][(src, dst)] = now

            # N1: one challenge across two servers (the relay hallmark) or two
            # distinct sessions -- random 8-byte challenges never collide, so any
            # reuse is anomalous.
            distinct_srcs = len(rec["srcs"])
            distinct_sess = len(rec["sessions"])
            if (distinct_srcs >= 2 or distinct_sess >= 2) \
                    and challenge not in self._ntlm_chal_reported:
                self._ntlm_chal_reported.add(challenge)
                cross = distinct_srcs >= 2
                self._emit(Finding(
                    rule="N1",
                    severity=Severity.CRITICAL if cross else Severity.HIGH,
                    subject=src,
                    title="NTLM challenge reuse across sessions (relay in progress)",
                    detail=("The same NTLM server challenge %s was seen in %d "
                            "session(s) across %d server IP(s): %s. A challenge is "
                            "random per authentication, so reuse means one handshake "
                            "is being passed through another -- an NTLM relay "
                            "actively in progress." %
                            (challenge.hex(), distinct_sess, distinct_srcs,
                             ", ".join(sorted(rec["srcs"])))),
                    proto="SMB/NTLM", names=[],
                    evidence={"challenge": challenge.hex(),
                              "server_ips": ", ".join(sorted(rec["srcs"])),
                              "sessions": str(distinct_sess)},
                    first_seen=now, last_seen=now))

        elif msg_type == NTLM_TYPE_AUTHENTICATE:
            # client -> server: src is the connecting host
            fields = self._ntlm_type3_fields(payload, off)
            if fields is None:
                return
            domain, user, workstation = fields
            ws = (workstation or "").rstrip(".").lower()
            if not ws:
                return
            known = self._names_for_ip(src)
            if not known:
                return  # can't judge without a confident name for the source
            ws_short = ws.split(".", 1)[0]
            known_short = {n.split(".", 1)[0] for n in known}
            if ws_short not in known_short:
                who = ("%s\\%s" % (domain, user)) if (domain or user) else "?"
                self._emit(Finding(
                    rule="N2", severity=Severity.MEDIUM, subject=src,
                    title="NTLM auth workstation/source mismatch (possible relay)",
                    detail=("Host %s (known here as %s) presented an NTLM "
                            "AUTHENTICATE claiming workstation '%s' for %s. Relayed "
                            "authentication carries the victim's workstation name "
                            "rather than the relay box's -- this mismatch is a relay "
                            "tell." % (src, "/".join(sorted(known)), workstation, who)),
                    proto="SMB/NTLM", names=[],
                    evidence={"source": src, "claimed_workstation": workstation,
                              "known_names": ", ".join(sorted(known)),
                              "account": who},
                    first_seen=now, last_seen=now))

    @staticmethod
    def _ntlm_type3_fields(payload: bytes, off: int):
        """Extract (domain, user, workstation) from an NTLM Type-3 message.
        Security-buffer descriptors: DomainName @28, UserName @36, Workstation
        @44 (each Len[2] MaxLen[2] BufferOffset[4], strings in the payload)."""
        def field(desc_off):
            try:
                ln, _mx, boff = struct.unpack_from("<HHI", payload, off + desc_off)
                if ln == 0:
                    return ""
                raw = payload[off + boff: off + boff + ln]
                if len(raw) != ln:
                    return ""
                # Unicode (UTF-16LE) is by far the common case; fall back to OEM.
                try:
                    return raw.decode("utf-16-le")
                except Exception:
                    return raw.decode("latin-1", errors="replace")
            except Exception:
                return None
        if off + 52 > len(payload):
            return None
        dom = field(28); usr = field(36); wks = field(44)
        if dom is None or usr is None or wks is None:
            return None
        return (dom, usr, wks)

    def _names_for_ip(self, ip: str) -> Set[str]:
        """Reverse of the passive resolution map: names that resolved to ip."""
        out: Set[str] = set()
        for name, addrs in self._resolved.items():
            if ip in addrs:
                out.add(name)
        return out

    @staticmethod
    def _l3_dst(pkt) -> Optional[str]:
        try:
            from scapy.all import IP, IPv6
            if pkt.haslayer(IP):
                return pkt[IP].dst
            if pkt.haslayer(IPv6):
                return pkt[IPv6].dst
        except Exception:
            pass
        return None

    # ----- Kerberos DER parsing (custom, no library dissector) ------------ #
    @staticmethod
    def _der_read_tlv(buf: bytes, off: int) -> Tuple[int, bytes, int]:
        """Return (tag, value_bytes, next_offset). Supports short & long form
        length. Raises on truncation."""
        tag = buf[off]; off += 1
        length = buf[off]; off += 1
        if length & 0x80:
            nbytes = length & 0x7F
            if nbytes == 0 or off + nbytes > len(buf):
                raise ValueError("bad DER length")
            length = int.from_bytes(buf[off:off + nbytes], "big")
            off += nbytes
        if off + length > len(buf):
            raise ValueError("DER value overruns buffer")
        return tag, buf[off:off + length], off + length

    @classmethod
    def _der_children(cls, buf: bytes) -> List[Tuple[int, bytes]]:
        out: List[Tuple[int, bytes]] = []
        off = 0
        while off < len(buf):
            tag, val, off = cls._der_read_tlv(buf, off)
            out.append((tag, val))
        return out

    @classmethod
    def _der_find(cls, buf: bytes, want_tag: int) -> Optional[bytes]:
        for tag, val in cls._der_children(buf):
            if tag == want_tag:
                return val
        return None

    @classmethod
    def _der_unwrap(cls, buf: bytes) -> bytes:
        """Read a single TLV and return its value (strip one layer)."""
        _, val, _ = cls._der_read_tlv(buf, 0)
        return val

    @classmethod
    def parse_kdc_req(cls, payload: bytes):
        """Extract (app_tag, etypes, cname, realm, sname, has_pa_enc_ts) from an
        AS-REQ or TGS-REQ. sname is the requested service SPN (the target, for
        TGS-REQ); has_pa_enc_ts is whether the padata carried an encrypted
        timestamp (pre-auth). Returns None if the message is neither. Tries the
        4-byte TCP length prefix and raw UDP framing."""
        for base in (4, 0):
            try:
                if len(payload) < base + 2:
                    continue
                tag, app_val, _ = cls._der_read_tlv(payload, base)
                if tag not in KRB_REQ_APPS:
                    continue
                kdc_req = cls._der_unwrap(app_val)                 # SEQUENCE
                has_pa = cls._krb_has_pa_enc_ts(kdc_req)
                body_wrap = cls._der_find(kdc_req, KRB_CTX_REQ_BODY)  # [4]
                if body_wrap is None:
                    continue
                body_seq = cls._der_unwrap(body_wrap)             # SEQUENCE
                etype_wrap = cls._der_find(body_seq, KRB_CTX_ETYPE)  # [8]
                etypes = []
                if etype_wrap is not None:
                    etype_seq = cls._der_unwrap(etype_wrap)       # SEQUENCE OF
                    etypes = [int.from_bytes(v, "big", signed=True)
                              for t, v in cls._der_children(etype_seq) if t == 0x02]
                cname = cls._krb_principal(body_seq, KRB_CTX_CNAME_REQ)
                realm = cls._krb_kerberos_string(body_seq, KRB_CTX_REALM_REQ)
                sname = cls._krb_principal(body_seq, KRB_CTX_SNAME_REQ)  # [3]
                return (tag, etypes, cname, realm, sname, has_pa)
            except Exception:
                continue
        return None

    @classmethod
    def _krb_has_pa_enc_ts(cls, kdc_req: bytes) -> bool:
        """Does the KDC-REQ padata [3] contain a PA-ENC-TIMESTAMP (type 2)?"""
        try:
            padata_wrap = cls._der_find(kdc_req, KRB_CTX_REQ_PADATA)  # [3]
            if padata_wrap is None:
                return False
            padata_seq = cls._der_unwrap(padata_wrap)             # SEQUENCE OF
            for _, pd in cls._der_children(padata_seq):
                tw = cls._der_find(pd, KRB_CTX_PADATA_TYPE)       # [1] padata-type
                if tw is None:
                    continue
                _, v, _ = cls._der_read_tlv(tw, 0)
                if int.from_bytes(v, "big", signed=True) == KRB_PA_ENC_TIMESTAMP:
                    return True
        except Exception:
            return False
        return False

    @classmethod
    def parse_as_req(cls, payload: bytes
                     ) -> Optional[Tuple[List[int], Optional[str], Optional[str]]]:
        """Back-compat wrapper: AS-REQ only, returns (etypes, cname, realm)."""
        r = cls.parse_kdc_req(payload)
        if r is None or r[0] != KRB_APP_AS_REQ:
            return None
        return (r[1], r[2], r[3])

    @classmethod
    def parse_krb_error(cls, payload: bytes):
        """Extract (error_code, cname, realm, sname, etype_info2) from a
        KRB-ERROR ([APPLICATION 30]). etype_info2 is the list of etypes the KDC
        offers in the PA-ETYPE-INFO2 of e-data (empty when absent). Returns None
        if not a KRB-ERROR."""
        for base in (4, 0):
            try:
                if len(payload) < base + 2:
                    continue
                tag, app_val, _ = cls._der_read_tlv(payload, base)
                if tag != KRB_APP_ERROR:
                    continue
                body = cls._der_unwrap(app_val)                   # SEQUENCE
                code_wrap = cls._der_find(body, KRB_CTX_ERR_CODE)  # [6]
                if code_wrap is None:
                    continue
                _, v, _ = cls._der_read_tlv(code_wrap, 0)
                code = int.from_bytes(v, "big", signed=True)
                cname = cls._krb_principal(body, KRB_CTX_ERR_CNAME)   # [8]
                realm = cls._krb_kerberos_string(body, KRB_CTX_ERR_REALM)  # [9]
                sname = cls._krb_principal(body, KRB_CTX_ERR_SNAME)   # [10]
                etinfo = cls._krb_error_etype_info2(body)
                return (code, cname, realm, sname, etinfo)
            except Exception:
                continue
        return None

    @classmethod
    def _krb_error_etype_info2(cls, body: bytes) -> List[int]:
        """e-data [12] of a KRB-ERROR holds a DER-encoded SEQUENCE OF PA-DATA.
        Pull the etypes out of any PA-ETYPE-INFO2 (padata-type 19). Each entry
        is ETYPE-INFO2-ENTRY ::= SEQUENCE { etype [0] Int32, salt [1] ... }."""
        out: List[int] = []
        try:
            edata_wrap = cls._der_find(body, KRB_CTX_ERR_EDATA)   # [12]
            if edata_wrap is None:
                return out
            _, edata, _ = cls._der_read_tlv(edata_wrap, 0)        # OCTET STRING
            padata_seq = cls._der_unwrap(edata)                   # SEQUENCE OF
            for _, pd in cls._der_children(padata_seq):
                tw = cls._der_find(pd, KRB_CTX_PADATA_TYPE)       # [1]
                if tw is None:
                    continue
                _, tv, _ = cls._der_read_tlv(tw, 0)
                if int.from_bytes(tv, "big", signed=True) != KRB_PA_ETYPE_INFO2:
                    continue
                vw = cls._der_find(pd, 0xA2)                      # [2] padata-value
                if vw is None:
                    continue
                _, val, _ = cls._der_read_tlv(vw, 0)              # OCTET STRING
                entries = cls._der_unwrap(val)                    # SEQUENCE OF
                for _, entry in cls._der_children(entries):
                    ew = cls._der_find(entry, KRB_CTX_ED_ETYPE)   # [0] etype
                    if ew is None:
                        continue
                    _, ev, _ = cls._der_read_tlv(ew, 0)
                    out.append(int.from_bytes(ev, "big", signed=True))
        except Exception:
            return out
        return out

    @classmethod
    def parse_kdc_rep(cls, payload: bytes):
        """Extract (app_tag, ticket_etype, reply_etype, cname, realm, sname) from
        an AS-REP or TGS-REP. ticket_etype is the etype of the granted ticket's
        EncryptedData (the account/krbtgt key type); reply_etype is the reply
        EncryptedData etype. Either may be None. Returns None if not a REP."""
        for base in (4, 0):
            try:
                if len(payload) < base + 2:
                    continue
                tag, app_val, _ = cls._der_read_tlv(payload, base)
                if tag not in KRB_REP_APPS:
                    continue
                rep = cls._der_unwrap(app_val)                    # KDC-REP SEQUENCE
                cname = cls._krb_principal(rep, KRB_CTX_REP_CNAME)   # [4]
                realm = cls._krb_kerberos_string(rep, KRB_CTX_REP_CREALM)  # [3]

                ticket_etype = None
                sname = None
                tkt_wrap = cls._der_find(rep, KRB_CTX_REP_TICKET)    # [5]
                if tkt_wrap is not None:
                    app1 = cls._der_unwrap(tkt_wrap)              # [APPLICATION 1]
                    tkt_seq = cls._der_unwrap(app1)               # SEQUENCE
                    sname = cls._krb_principal(tkt_seq, KRB_CTX_TKT_SNAME)  # [2]
                    ed = cls._der_find(tkt_seq, KRB_CTX_TKT_ENCPART)  # [3]
                    if ed is not None:
                        ticket_etype = cls._krb_ed_etype(ed)

                reply_etype = None
                ep_wrap = cls._der_find(rep, KRB_CTX_REP_ENCPART)    # [6]
                if ep_wrap is not None:
                    reply_etype = cls._krb_ed_etype(ep_wrap)

                return (tag, ticket_etype, reply_etype, cname, realm, sname)
            except Exception:
                continue
        return None

    @classmethod
    def _krb_ed_etype(cls, ed_wrap: bytes) -> Optional[int]:
        """EncryptedData ::= SEQUENCE { etype [0] Int32, ... }. ed_wrap is the
        value of the field holding the EncryptedData (a SEQUENCE)."""
        try:
            ed_seq = cls._der_unwrap(ed_wrap)                 # SEQUENCE
            etype_wrap = cls._der_find(ed_seq, KRB_CTX_ED_ETYPE)  # [0]
            if etype_wrap is None:
                return None
            _, v, _ = cls._der_read_tlv(etype_wrap, 0)        # INTEGER
            return int.from_bytes(v, "big", signed=True)
        except Exception:
            return None

    @classmethod
    def _krb_principal(cls, seq: bytes, ctx_tag: int) -> Optional[str]:
        """PrincipalName under ctx_tag -> name-string [1] -> SEQUENCE OF
        KerberosString, joined with '/'. Best-effort; never raises."""
        try:
            wrap = cls._der_find(seq, ctx_tag)
            if wrap is None:
                return None
            principal = cls._der_unwrap(wrap)                 # SEQUENCE
            ns_wrap = cls._der_find(principal, KRB_CTX_NAMESTRING)  # [1]
            if ns_wrap is None:
                return None
            ns_seq = cls._der_unwrap(ns_wrap)                 # SEQUENCE OF
            parts = [v.decode(errors="replace")
                     for t, v in cls._der_children(ns_seq) if t in (0x1B, 0x1A, 0x0C)]
            return "/".join(parts) if parts else None
        except Exception:
            return None

    @classmethod
    def _krb_kerberos_string(cls, seq: bytes, ctx_tag: int) -> Optional[str]:
        """A KerberosString (GeneralString) directly under ctx_tag."""
        try:
            wrap = cls._der_find(seq, ctx_tag)
            if wrap is None:
                return None
            t, v, _ = cls._der_read_tlv(wrap, 0)
            if t in (0x1B, 0x1A, 0x0C):
                return v.decode(errors="replace")
        except Exception:
            return None
        return None


# =========================================================================== #
#  Live capture / pcap replay
# =========================================================================== #

def _print_finding(f: Finding, as_json: bool) -> None:
    if as_json:
        print(f.to_json(), flush=True)
        return
    ts = time.strftime("%H:%M:%S", time.localtime(f.last_seen))
    names = (" [" + ", ".join(f.names) + "]") if f.names else ""
    print("%s  %-8s %-4s %-15s  %s%s"
          % (ts, f.severity.name, f.rule, f.subject, f.title, names), flush=True)
    if f.detail:
        print("           %s" % f.detail, flush=True)


def run_live(iface: str, cfg: Config, as_json: bool) -> None:
    s = _import_scapy()
    watcher = SMBWatch(cfg, emit=lambda f: _print_finding(f, as_json))
    bpf = build_bpf(cfg.ipv6_eh)
    if not as_json:
        print("smbwatch: passive capture on %s  (filter: %s)" % (iface, bpf),
              file=sys.stderr)
        if not cfg.ipv6_eh:
            print("smbwatch: WARNING --no-ipv6-eh: IPv6 frames carrying extension "
                  "headers will not be captured.", file=sys.stderr)
        print("smbwatch: detection-only; nothing is transmitted.", file=sys.stderr)
    try:
        s.sniff(iface=iface, filter=bpf, store=False,
                prn=watcher.process_packet)
    except Exception as exc:
        # The BPF filter is compiled by libpcap. On a host without it, scapy
        # raises a bare "Cannot compile filter" that says nothing an operator
        # can act on -- and under systemd that becomes a restart loop with an
        # inscrutable traceback. Fail with the actual remedy instead.
        msg = str(exc)
        if "libpcap" in msg or "compile filter" in msg:
            raise SystemExit(
                "smbwatch: cannot install the capture filter because libpcap is "
                "not available.\n"
                "  Install it (Debian/Ubuntu: apt install libpcap0.8) and retry.\n"
                "  Offline analysis does not need libpcap: python3 %s --pcap FILE"
                % os.path.basename(__file__))
        if isinstance(exc, PermissionError) or "Operation not permitted" in msg:
            raise SystemExit(
                "smbwatch: permission denied opening a capture socket on %s.\n"
                "  Needs CAP_NET_RAW (and CAP_NET_ADMIN for promiscuous mode); "
                "the bundled systemd unit grants both." % iface)
        raise


def run_pcap(path: str, cfg: Config, as_json: bool) -> None:
    s = _import_scapy()
    watcher = SMBWatch(cfg, emit=lambda f: _print_finding(f, as_json))
    for pkt in s.rdpcap(path):
        watcher.process_packet(pkt)
    if not as_json:
        print("smbwatch: %d finding(s) from %s" % (len(watcher.findings), path),
              file=sys.stderr)


SYSTEMD_UNIT = """\
[Unit]
Description=Ragnar smbwatch - passive SMB / NTLM-relay attack-surface monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Adjust interface and log path for your tap/SPAN port.
ExecStart=/usr/bin/python3 {path} -i {iface} --json
Restart=on-failure
RestartSec=5
# Detection-only: no raw-send needed, only capture.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
StandardOutput=append:/var/log/ragnar/smbwatch.jsonl
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


# =========================================================================== #
#  Self-test harness  (Scapy fixtures -> process_packet -> assert findings)
# =========================================================================== #

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(val)) + val


def _der_int(n: int) -> bytes:
    """Minimal two's-complement DER INTEGER. Kerberos etypes are Int32 and the
    RSADSI RC4-MD4 etype is -128, so negatives must encode correctly."""
    if n == 0:
        return _der_tlv(0x02, b"\x00")
    length = ((n + (n < 0)).bit_length() // 8) + 1
    b = n.to_bytes(length, "big", signed=True)
    return _der_tlv(0x02, b)


def _der_seq(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


def _build_as_req(etypes, cname=None, realm="EXAMPLE.COM",
                  with_prefix=True, app_tag=KRB_APP_AS_REQ,
                  sname="krbtgt/EXAMPLE.COM", pa_enc_ts=None) -> bytes:
    """Fabricate a minimal but DER-valid Kerberos AS-REQ or TGS-REQ. `sname` is
    the requested service SPN; `pa_enc_ts` (True/False) adds/omits an encrypted-
    timestamp padata (defaults: present for AS-REQ, absent for TGS-REQ)."""
    if pa_enc_ts is None:
        pa_enc_ts = (app_tag == KRB_APP_AS_REQ)
    etype_seq = _der_seq(*[_der_int(e) for e in etypes])
    body_items = [_der_tlv(0xA0, _der_tlv(0x03, b"\x00\x00\x00\x00\x00"))]  # [0] kdc-options
    if cname is not None:
        name_strings = _der_seq(*[_der_tlv(0x1B, p.encode()) for p in cname.split("/")])
        principal = _der_seq(_der_tlv(0xA0, _der_int(1)), _der_tlv(0xA1, name_strings))
        body_items.append(_der_tlv(0xA1, principal))          # [1] cname
    body_items.append(_der_tlv(0xA2, _der_tlv(0x1B, realm.encode())))  # [2] realm
    body_items.append(_der_tlv(0xA3, _der_principal(sname.split("/"))))  # [3] sname
    body_items.append(_der_tlv(0xA5, _der_tlv(0x18, b"20250101000000Z")))  # [5] till
    body_items.append(_der_tlv(0xA7, _der_int(0x11223344)))   # [7] nonce
    body_items.append(_der_tlv(0xA8, etype_seq))              # [8] etype
    body = _der_seq(*body_items)

    padata_items = []
    if pa_enc_ts:
        padata_items.append(_der_seq(_der_tlv(0xA1, _der_int(KRB_PA_ENC_TIMESTAMP)),
                                     _der_tlv(0xA2, _der_tlv(0x04, b"\x00\x01\x02\x03"))))
    padata_items.append(_der_seq(_der_tlv(0xA1, _der_int(128)),  # PA-PAC-REQUEST
                                 _der_tlv(0xA2, _der_tlv(0x04, b"\x30\x05"))))
    padata = _der_seq(*padata_items)

    kdc_req = _der_seq(
        _der_tlv(0xA1, _der_int(5)),    # pvno
        _der_tlv(0xA2, _der_int(12 if app_tag == KRB_APP_TGS_REQ else 10)),  # msg-type
        _der_tlv(0xA3, padata),         # [3] padata
        _der_tlv(0xA4, body),           # [4] req-body
    )
    as_req = _der_tlv(app_tag, kdc_req)
    if with_prefix:
        return struct.pack(">I", len(as_req)) + as_req
    return as_req


def _build_krb_error(code, cname="alice", sname="krbtgt/EXAMPLE.COM",
                     realm="EXAMPLE.COM", with_prefix=True,
                     etype_info2=None) -> bytes:
    """etype_info2: list of etypes to advertise in a PA-ETYPE-INFO2 inside
    e-data [12], as a KDC does when answering PREAUTH_REQUIRED."""
    items = [
        _der_tlv(0xA0, _der_int(5)),                      # [0] pvno
        _der_tlv(0xA1, _der_int(30)),                     # [1] msg-type
        _der_tlv(0xA4, _der_tlv(0x18, b"20250101000000Z")),  # [4] stime
        _der_tlv(0xA5, _der_int(0)),                      # [5] susec
        _der_tlv(0xA6, _der_int(code)),                   # [6] error-code
        _der_tlv(0xA8, _der_principal([cname])),          # [8] cname
        _der_tlv(0xA9, _der_tlv(0x1B, realm.encode())),   # [9] realm
        _der_tlv(0xAA, _der_principal(sname.split("/"))), # [10] sname
    ]
    if etype_info2:
        entries = _der_seq(*[_der_seq(_der_tlv(0xA0, _der_int(e)))
                             for e in etype_info2])
        padata = _der_seq(_der_seq(
            _der_tlv(0xA1, _der_int(KRB_PA_ETYPE_INFO2)),
            _der_tlv(0xA2, _der_tlv(0x04, entries)),
        ))
        items.append(_der_tlv(0xAC, _der_tlv(0x04, padata)))   # [12] e-data
    msg = _der_tlv(KRB_APP_ERROR, _der_seq(*items))
    if with_prefix:
        return struct.pack(">I", len(msg)) + msg
    return msg


def _build_negotiate_context(ctx_type: int, data: bytes) -> bytes:
    """One SMB2 negotiate context: ContextType(2) DataLength(2) Reserved(4)."""
    return struct.pack("<HHI", ctx_type, len(data), 0) + data


def _build_compression_capabilities(algs=(1, 2, 3)) -> bytes:
    """SMB2_COMPRESSION_CAPABILITIES body."""
    return (struct.pack("<HHI", len(algs), 0, 0) +
            b"".join(struct.pack("<H", a) for a in algs))


def _build_smb2_negotiate_resp_ctx(secmode=SMB2_SIGNING_ENABLED,
                                   contexts=(), with_framing=True) -> bytes:
    """A 3.1.1 negotiate RESPONSE carrying a negotiate-context list, so the
    SMBGhost posture check has something real to walk."""
    hdr = SMB2_MAGIC + struct.pack("<H", 64) + b"\x00" * 6
    hdr += struct.pack("<H", SMB2_CMD_NEGOTIATE)
    hdr += b"\x00" * 2
    hdr += struct.pack("<I", SMB2_FLAGS_SERVER_TO_REDIR)
    hdr += b"\x00" * (64 - len(hdr))
    assert len(hdr) == 64, len(hdr)

    body = bytearray(b"\x00" * 64)             # fixed part of the response
    struct.pack_into("<H", body, 0, 65)        # StructureSize
    struct.pack_into("<H", body, 2, secmode)   # SecurityMode  (header+66)
    struct.pack_into("<H", body, 4, SMB2_DIALECT_311)   # DialectRevision (+68)
    struct.pack_into("<H", body, 6, len(contexts))      # ContextCount   (+70)
    ctx_blob = b""
    for i, c in enumerate(contexts):
        ctx_blob += c
        if i != len(contexts) - 1:             # pad all but the last to 8
            pad = (8 - (len(ctx_blob) % 8)) % 8
            ctx_blob += b"\x00" * pad
    struct.pack_into("<I", body, 60, 64 + 64)  # NegotiateContextOffset (+124)
    msg = hdr + bytes(body) + ctx_blob
    if with_framing:
        return struct.pack(">I", len(msg)) + msg
    return msg


def _build_compression_transform(original_size, offset, algorithm=1, flags=0,
                                 with_framing=True) -> bytes:
    """SMB2 COMPRESSION_TRANSFORM_HEADER + a token payload."""
    msg = (SMB2_COMPRESSION_MAGIC +
           struct.pack("<I", original_size) +
           struct.pack("<H", algorithm) +
           struct.pack("<H", flags) +
           struct.pack("<I", offset) +
           b"\x41" * 16)
    if with_framing:
        return struct.pack(">I", len(msg)) + msg
    return msg


def _build_smb1_trans2(subcommand, with_framing=True) -> bytes:
    """Minimal SMBv1 TRANS2 *request* whose Setup[0] is `subcommand`."""
    hdr = SMB1_MAGIC + bytes([SMB1_CMD_TRANS2]) + b"\x00" * 4   # magic, cmd, status
    hdr += b"\x00"                     # flags (bit 0x80 clear = request)
    hdr += b"\x00" * (32 - len(hdr))
    assert len(hdr) == 32, len(hdr)
    words = b"\x00" * 28               # 14 fixed words
    body = bytes([15]) + words + bytes([1, 0]) + struct.pack("<H", subcommand)
    body += b"\x00" * 8
    msg = hdr + body
    if with_framing:
        return struct.pack(">I", len(msg)) + msg
    return msg


def _build_ntlm_type2(challenge: bytes) -> bytes:
    return (NTLMSSP_SIG + struct.pack("<I", NTLM_TYPE_CHALLENGE) +
            b"\x00" * 8 +          # TargetName fields
            b"\x00" * 4 +          # NegotiateFlags
            challenge +            # ServerChallenge (offset 24)
            b"\x00" * 8 +          # Reserved
            b"\x00" * 8)           # TargetInfo fields


def _build_ntlm_type3(domain="CORP", user="victim", workstation="WS7") -> bytes:
    du = domain.encode("utf-16-le"); uu = user.encode("utf-16-le")
    wu = workstation.encode("utf-16-le")

    def sec(off, data):
        return struct.pack("<HHI", len(data), len(data), off)
    base = 64
    pay = b""
    lm_off = base + len(pay); pay += b"\x00" * 24
    nt_off = base + len(pay); pay += b"\x00" * 24
    d_off = base + len(pay); pay += du
    u_off = base + len(pay); pay += uu
    w_off = base + len(pay); pay += wu
    hdr = NTLMSSP_SIG + struct.pack("<I", NTLM_TYPE_AUTHENTICATE)
    hdr += sec(lm_off, b"\x00" * 24)   # LmChallengeResponse
    hdr += sec(nt_off, b"\x00" * 24)   # NtChallengeResponse
    hdr += sec(d_off, du)              # DomainName @28
    hdr += sec(u_off, uu)              # UserName @36
    hdr += sec(w_off, wu)              # Workstation @44
    hdr += sec(base, b"")              # EncryptedRandomSessionKey @52
    hdr += struct.pack("<I", 0x82)      # NegotiateFlags @60
    return hdr + pay


def _der_principal(names, ntype=1) -> bytes:
    ns = _der_seq(*[_der_tlv(0x1B, n.encode()) for n in names])
    return _der_seq(_der_tlv(0xA0, _der_int(ntype)), _der_tlv(0xA1, ns))


def _der_encrypted_data(etype, cipher=b"\x00\x00\x00\x00") -> bytes:
    # EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] opt, cipher [2] OCTET STRING }
    return _der_seq(_der_tlv(0xA0, _der_int(etype)), _der_tlv(0xA2, _der_tlv(0x04, cipher)))


def _build_kdc_rep(app_tag, ticket_etype, reply_etype,
                   cname="alice", sname="cifs/fs01", realm="EXAMPLE.COM",
                   with_prefix=True) -> bytes:
    """Fabricate a minimal DER-valid AS-REP / TGS-REP whose granted ticket and
    reply EncryptedData carry the given etypes."""
    ticket_inner = _der_seq(
        _der_tlv(0xA0, _der_int(5)),                      # [0] tkt-vno
        _der_tlv(0xA1, _der_tlv(0x1B, realm.encode())),   # [1] realm
        _der_tlv(0xA2, _der_principal(sname.split("/"))), # [2] sname
        _der_tlv(0xA3, _der_encrypted_data(ticket_etype)),# [3] enc-part
    )
    ticket = _der_tlv(KRB_APP_TICKET, ticket_inner)       # [APPLICATION 1]
    rep = _der_seq(
        _der_tlv(0xA0, _der_int(5)),                      # [0] pvno
        _der_tlv(0xA1, _der_int(11 if app_tag == KRB_APP_AS_REP else 13)),  # [1] msg-type
        _der_tlv(0xA3, _der_tlv(0x1B, realm.encode())),   # [3] crealm
        _der_tlv(0xA4, _der_principal(cname.split("/"))), # [4] cname
        _der_tlv(0xA5, ticket),                           # [5] ticket
        _der_tlv(0xA6, _der_encrypted_data(reply_etype)), # [6] enc-part
    )
    msg = _der_tlv(app_tag, rep)
    if with_prefix:
        return struct.pack(">I", len(msg)) + msg
    return msg


def _nbss(raw: bytes) -> bytes:
    """4-byte session-service header: zero type + 3-byte big-endian length."""
    return b"\x00" + len(raw).to_bytes(3, "big") + raw


def _smb2_hdr(command: int, tree_id: int = 0, message_id: int = 0,
              response: bool = False, next_command: int = 0) -> bytes:
    h = bytearray(SMB2_HDR_LEN)
    h[0:4] = SMB2_MAGIC
    struct.pack_into("<H", h, 4, SMB2_HDR_LEN)
    struct.pack_into("<H", h, SMB2_OFF_COMMAND, command)
    struct.pack_into("<I", h, SMB2_OFF_FLAGS,
                     SMB2_FLAGS_SERVER_TO_REDIR if response else 0)
    struct.pack_into("<I", h, SMB2_OFF_NEXT_COMMAND, next_command)
    struct.pack_into("<Q", h, SMB2_OFF_MESSAGE_ID, message_id)
    struct.pack_into("<I", h, SMB2_OFF_TREE_ID, tree_id)
    return bytes(h)


def _build_tree_connect_req(share, message_id=1, framed=True, host="DC01"):
    path = ("\\\\%s\\%s" % (host, share)).encode("utf-16-le")
    body = bytearray(8)
    struct.pack_into("<H", body, 0, 9)                     # StructureSize
    struct.pack_into("<H", body, 4, SMB2_HDR_LEN + 8)      # PathOffset
    struct.pack_into("<H", body, 6, len(path))             # PathLength
    msg = _smb2_hdr(SMB2_CMD_TREE_CONNECT, message_id=message_id) + bytes(body) + path
    return _nbss(msg) if framed else msg


def _build_tree_connect_resp(tree_id, message_id=1, framed=True):
    body = bytearray(16)
    struct.pack_into("<H", body, 0, 16)
    msg = _smb2_hdr(SMB2_CMD_TREE_CONNECT, tree_id=tree_id,
                    message_id=message_id, response=True) + bytes(body)
    return _nbss(msg) if framed else msg


def _build_create_req(name, tree_id, desired=FILE_READ_DATA, options=0,
                      disposition=1, message_id=2, framed=True):
    nm = name.encode("utf-16-le")
    body = bytearray(56)
    struct.pack_into("<H", body, 0, SMB2_CR_STRUCTURE_SIZE)
    struct.pack_into("<I", body, 24, desired)              # DesiredAccess
    struct.pack_into("<I", body, 36, disposition)          # CreateDisposition
    struct.pack_into("<I", body, 40, options)              # CreateOptions
    struct.pack_into("<H", body, 44, SMB2_HDR_LEN + 56)    # NameOffset
    struct.pack_into("<H", body, 46, len(nm))              # NameLength
    msg = _smb2_hdr(SMB2_CMD_CREATE, tree_id=tree_id,
                    message_id=message_id) + bytes(body) + nm
    return _nbss(msg) if framed else msg


def _build_ioctl_req(ctl_code, tree_id, message_id=3, framed=True):
    body = bytearray(56)
    struct.pack_into("<H", body, 0, 57)
    struct.pack_into("<I", body, 4, ctl_code)
    msg = _smb2_hdr(SMB2_CMD_IOCTL, tree_id=tree_id,
                    message_id=message_id) + bytes(body)
    return _nbss(msg) if framed else msg


def _build_smb2_transform(framed=True):
    """SMB3 TRANSFORM_HEADER -- an encrypted message."""
    msg = SMB2_TRANSFORM_MAGIC + b"\x00" * 48 + b"\xAA" * 16
    return _nbss(msg) if framed else msg


def _build_smb2_negotiate_resp(dialect: int, secmode: int,
                               framing: bytes = b"\x00\x00\x00\x00") -> bytes:
    hdr = SMB2_MAGIC
    hdr += struct.pack("<H", 64)
    hdr += b"\x00\x00"
    hdr += b"\x00\x00\x00\x00"
    hdr += struct.pack("<H", SMB2_CMD_NEGOTIATE)
    hdr += b"\x00\x00"
    hdr += struct.pack("<I", SMB2_FLAGS_SERVER_TO_REDIR)
    hdr += b"\x00" * 4
    hdr += b"\x00" * 8
    hdr += b"\x00" * 4
    hdr += b"\x00" * 4
    hdr += b"\x00" * 8
    hdr += b"\x00" * 16
    body = struct.pack("<H", 65)
    body += struct.pack("<H", secmode)
    body += struct.pack("<H", dialect)
    body += b"\x00" * 120
    return framing + hdr + body


def _build_smb2_negotiate_request() -> bytes:
    hdr = SMB2_MAGIC + struct.pack("<H", 64) + b"\x00" * 6
    hdr += struct.pack("<H", SMB2_CMD_NEGOTIATE) + b"\x00\x00"
    hdr += struct.pack("<I", 0)          # flags: NOT a response
    hdr += b"\x00" * (64 - len(hdr))
    body = struct.pack("<H", 36) + struct.pack("<H", 0) + struct.pack("<H", 0)
    body += b"\x00" * 40
    return b"\x00\x00\x00\x00" + hdr + body


def _build_smb1_negotiate_resp(dialect_index: int, secmode: int) -> bytes:
    # 32-byte SMB1 header
    hdr = SMB1_MAGIC
    hdr += bytes([SMB1_CMD_NEGOTIATE])   # command
    hdr += b"\x00\x00\x00\x00"           # status
    hdr += bytes([0x80])                 # flags: response
    hdr += b"\x00\x00"                   # flags2
    hdr += b"\x00\x00"                   # PIDHigh
    hdr += b"\x00" * 8                   # signature
    hdr += b"\x00\x00"                   # reserved
    hdr += b"\x00\x00"                   # TID
    hdr += b"\x00\x00"                   # PIDLow
    hdr += b"\x00\x00"                   # UID
    hdr += b"\x00\x00"                   # MID
    assert len(hdr) == 32, len(hdr)
    words = bytes([17])                                 # WordCount
    words += struct.pack("<H", dialect_index)           # DialectIndex
    words += bytes([secmode])                           # SecurityMode
    words += b"\x00" * (17 * 2 - 3)                      # rest of words
    tail = b"\x00\x00"                                   # ByteCount
    return b"\x00\x00\x00\x00" + hdr + words + tail


def _run_self_tests() -> int:
    s = _import_scapy()
    IP, IPv6, UDP, TCP = s.IP, s.IPv6, s.UDP, s.TCP
    DNS, DNSQR, DNSRR = s.DNS, s.DNSQR, s.DNSRR
    from scapy.layers.netbios import NBNSHeader, NBNSQueryResponse
    try:
        from scapy.layers.netbios import NBNS_ADD_ENTRY
    except Exception:
        NBNS_ADD_ENTRY = None

    passed = 0
    failed = 0
    results: List[Tuple[bool, str]] = []

    def check(cond: bool, label: str) -> None:
        nonlocal passed, failed
        if cond:
            passed += 1
        else:
            failed += 1
        results.append((cond, label))

    # ---- helpers to fabricate packets ---------------------------------- #
    def llmnr_resp(src, name, ip, port=PORT_LLMNR, rtype="A", dst="10.0.0.10"):
        L3 = IPv6 if ":" in src else IP
        return (L3(src=src, dst=dst) / UDP(sport=port, dport=61000) /
                DNS(qr=1, qd=DNSQR(qname=name),
                    an=DNSRR(rrname=name, type=rtype, rdata=ip)))

    def mdns_resp(src, records, dst="224.0.0.251"):
        an = None
        for (nm, tp, rd) in records:
            rr = DNSRR(rrname=nm, type=tp, rdata=rd)
            an = rr if an is None else an / rr
        return (IP(src=src, dst=dst) / UDP(sport=PORT_MDNS, dport=PORT_MDNS) /
                DNS(qr=1, an=an))

    def nbtns_resp(src, name, ip, suffix=0x20, dst="10.0.0.255"):
        if NBNS_ADD_ENTRY is not None:
            qr = NBNSQueryResponse(RR_NAME=name, SUFFIX=suffix,
                                   ADDR_ENTRY=[NBNS_ADD_ENTRY(NB_ADDRESS=ip)])
        else:  # pragma: no cover
            qr = NBNSQueryResponse(RR_NAME=name, SUFFIX=suffix)
        pkt = (IP(src=src, dst=dst) / UDP(sport=PORT_NBTNS, dport=PORT_NBTNS) /
               NBNSHeader(RESPONSE=1, OPCODE=0, ANCOUNT=1) / qr)
        return pkt

    def smb_pkt(src, payload, sport=PORT_SMB, dst="10.0.0.10"):
        return IP(src=src, dst=dst) / TCP(sport=sport, dport=50000) / s.Raw(load=payload)

    def krb_pkt(src, etypes, cname=None, over_tcp=True, dst="10.0.0.2",
                app_tag=KRB_APP_AS_REQ, sname="krbtgt/EXAMPLE.COM", pa_enc_ts=None):
        payload = _build_as_req(etypes, cname=cname, with_prefix=over_tcp,
                                app_tag=app_tag, sname=sname, pa_enc_ts=pa_enc_ts)
        L4 = TCP if over_tcp else UDP
        return IP(src=src, dst=dst) / L4(sport=50000, dport=PORT_KRB) / s.Raw(load=payload)

    def krb_rep_pkt(client_dst, ticket_etype, reply_etype=18, app_tag=KRB_APP_TGS_REP,
                    cname="alice", sname="cifs/fs01", kdc="10.0.0.2"):
        # a REP travels KDC -> client, so KDC is src and the client is dst
        payload = _build_kdc_rep(app_tag, ticket_etype, reply_etype,
                                 cname=cname, sname=sname)
        return (IP(src=kdc, dst=client_dst) /
                TCP(sport=PORT_KRB, dport=50000) / s.Raw(load=payload))

    def krb_err_pkt(client_dst, code, cname="alice", kdc="10.0.0.2"):
        payload = _build_krb_error(code, cname=cname)
        return (IP(src=kdc, dst=client_dst) /
                TCP(sport=PORT_KRB, dport=50000) / s.Raw(load=payload))

    def krb_err_pkt_ei(client_dst, code, etype_info2, cname="alice", kdc="10.0.0.2"):
        payload = _build_krb_error(code, cname=cname, etype_info2=etype_info2)
        return (IP(src=kdc, dst=client_dst) /
                TCP(sport=PORT_KRB, dport=50000) / s.Raw(load=payload))

    def smb_ntlm_pkt(src, dst, ntlm_blob, sport=PORT_SMB, dport=50000):
        # embed the NTLMSSP blob after a plausible SMB2 SESSION_SETUP-ish header;
        # the detector locates the NTLMSSP signature directly.
        pad = b"\x00\x00\x00\x00\xfeSMB" + b"\x00" * 40
        return (IP(src=src, dst=dst) /
                TCP(sport=sport, dport=dport) / s.Raw(load=pad + ntlm_blob))

    def resolve(w, name, ip, proto="NBT-NS"):
        # seed the passive resolution map by feeding a name-resolution answer
        if proto == "NBT-NS":
            w.process_packet(nbtns_resp(ip, name, ip))
        else:
            w.process_packet(llmnr_resp(ip, name, ip))

    def fresh(cfg=None):
        return SMBWatch(cfg or Config())

    def get(w, rule, subject=None):
        for f in w.findings:
            if f.rule == rule and (subject is None or f.subject == subject):
                return f
        return None

    def has(w, rule, subject=None, sev=None):
        for f in w.findings:
            if f.rule != rule:
                continue
            if subject is not None and f.subject != subject:
                continue
            if sev is not None and f.severity != sev:
                continue
            return True
        return False

    def none(w, rule):
        return not any(f.rule == rule for f in w.findings)

    # ===================================================================== #
    #  Group A: SMB negotiate parsing (unit-level, no packet)
    # ===================================================================== #
    for dlt, dname in [(0x0202, "SMB 2.0.2"), (0x0210, "SMB 2.1"),
                       (0x0300, "SMB 3.0"), (0x0302, "SMB 3.0.2"),
                       (0x0311, "SMB 3.1.1")]:
        raw = _build_smb2_negotiate_resp(dlt, SMB2_SIGNING_REQUIRED)
        r = SMBWatch.parse_smb_negotiate_response(raw)
        check(r is not None and r[0] == 2 and r[1] == dname and r[2] is True,
              "SMB2 parse dialect=%s signing-required" % dname)

    # signing enabled but not required
    raw = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED)
    r = SMBWatch.parse_smb_negotiate_response(raw)
    check(r == (2, "SMB 3.1.1", False, True), "SMB2 signing enabled-not-required")

    # neither bit
    raw = _build_smb2_negotiate_resp(0x0210, 0x0000)
    r = SMBWatch.parse_smb_negotiate_response(raw)
    check(r == (2, "SMB 2.1", False, False), "SMB2 signing disabled")

    # request must NOT parse as a response
    r = SMBWatch.parse_smb_negotiate_response(_build_smb2_negotiate_request())
    check(r is None, "SMB2 request is not a negotiate response")

    # NBT-framed (tcp/139) SMB2 -- same 4-byte framing, must still parse
    raw = _build_smb2_negotiate_resp(0x0300, SMB2_SIGNING_REQUIRED,
                                     framing=b"\x00\x00\x00\x80")
    r = SMBWatch.parse_smb_negotiate_response(raw)
    check(r is not None and r[1] == "SMB 3.0", "SMB2 over NBT framing parses")

    # payload with no framing (defensive: base=0 path)
    raw_noframe = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_REQUIRED)[4:]
    r = SMBWatch.parse_smb_negotiate_response(raw_noframe)
    check(r is not None and r[1] == "SMB 3.1.1", "SMB2 without transport framing")

    # SMBv1 negotiate response, signing required
    raw = _build_smb1_negotiate_resp(0x0000, SMB1_SIGNING_ENABLED | SMB1_SIGNING_REQUIRED)
    r = SMBWatch.parse_smb_negotiate_response(raw)
    check(r is not None and r[0] == 1 and r[2] is True, "SMBv1 parse signing-required")

    # SMBv1 negotiate response, signing NOT required
    raw = _build_smb1_negotiate_resp(0x0000, SMB1_SIGNING_ENABLED)
    r = SMBWatch.parse_smb_negotiate_response(raw)
    check(r is not None and r[0] == 1 and r[2] is False and r[3] is True,
          "SMBv1 parse signing-not-required")

    # SMBv1 server rejected all dialects (0xFFFF) -> not "in use"
    raw = _build_smb1_negotiate_resp(0xFFFF, 0x00)
    r = SMBWatch.parse_smb_negotiate_response(raw)
    check(r is None, "SMBv1 dialect 0xFFFF rejected -> None")

    # garbage
    check(SMBWatch.parse_smb_negotiate_response(b"not smb at all") is None,
          "Garbage payload -> None")

    # ===================================================================== #
    #  Group B: SMB findings via full packets
    # ===================================================================== #
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.50",
                             _build_smb1_negotiate_resp(0x0000, SMB1_SIGNING_ENABLED)))
    check(has(w, "S1", "10.0.0.50", Severity.MEDIUM), "S1 SMBv1 negotiated flagged")
    check(has(w, "S3", "10.0.0.50", Severity.HIGH), "S3 SMBv1 unsigned flagged")

    w = fresh()
    w.process_packet(smb_pkt("10.0.0.51",
                             _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED)))
    check(has(w, "S2", "10.0.0.51", Severity.HIGH), "S2 SMB3 unsigned flagged")

    w = fresh()
    w.process_packet(smb_pkt("10.0.0.52",
                             _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_REQUIRED)))
    check(none(w, "S2") and none(w, "S1"), "SMB3 signing-required: no finding")

    # NBT session port 139 path
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.53",
                             _build_smb2_negotiate_resp(0x0202, 0x0000),
                             sport=PORT_NBSS))
    check(has(w, "S2", "10.0.0.53"), "SMB2 on tcp/139 flagged")

    # allowlisted legacy SMB server suppressed
    cfg = Config(allow_smb={"10.0.0.60"})
    w = fresh(cfg)
    w.process_packet(smb_pkt("10.0.0.60",
                             _build_smb1_negotiate_resp(0x0000, SMB1_SIGNING_ENABLED)))
    check(none(w, "S1") and none(w, "S3"), "SMB allowlist suppresses findings")

    # ===================================================================== #
    #  Group C: LLMNR poisoning
    # ===================================================================== #
    # WPAD over LLMNR -> CRITICAL
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    check(has(w, "R1", "10.0.0.66", Severity.CRITICAL), "R1 LLMNR WPAD -> CRITICAL")
    check(has(w, "R5", "10.0.0.66", Severity.INFO), "R5 new responder baseline")

    # Aggressive responder: 3 distinct names -> HIGH
    w = fresh()
    for nm in ("fileserv", "printsrv", "hrshare"):
        w.process_packet(llmnr_resp("10.0.0.66", nm, "10.0.0.66"))
    check(has(w, "R2", "10.0.0.66", Severity.HIGH), "R2 aggressive LLMNR responder")

    # Two distinct names: below threshold -> no R2
    w = fresh()
    for nm in ("fileserv", "printsrv"):
        w.process_packet(llmnr_resp("10.0.0.66", nm, "10.0.0.66"))
    check(none(w, "R2"), "R2 below threshold: no finding")

    # Conflicting answers for one name from two responders -> R3
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "fileserv", "10.0.0.66"))
    w.process_packet(llmnr_resp("10.0.0.99", "fileserv", "10.0.0.99"))
    check(has(w, "R3"), "R3 conflicting LLMNR answers")

    # ===================================================================== #
    #  Group T: Apple / Bonjour false-positive regressions (field-reported)
    # ===================================================================== #
    #  A production alert read "Name '_companion-link._tcp.local' is answered
    #  with conflicting IPs (Jacks rum._companion-link._tcp.local., ...)" -- a
    #  service TYPE treated as a host name, and PTR rdata treated as addresses.
    #  These pin the whole class shut.
    # ------------------------------------------------------------------- #
    # the exact reported traffic: DNS-SD PTR chatter must be silent
    w = fresh()
    w.process_packet(mdns_resp("192.168.1.195", [
        ("_companion-link._tcp.local", 12, "Jacks rum._companion-link._tcp.local"),
        ("_companion-link._tcp.local", 12, "Vardagsrum._companion-link._tcp.local"),
        ("_sleep-proxy._udp.local", 12,
         "70-35-60-63.1 Edvins Apple Tv._sleep-proxy._udp.local"),
    ]))
    check(none(w, "R3") and none(w, "R2") and none(w, "R4"),
          "Bonjour PTR service chatter raises nothing")

    # a service type is never treated as a host name
    check(SMBWatch._is_service_discovery_name("_companion-link._tcp.local"),
          "DNS-SD service type recognised")
    check(SMBWatch._is_service_discovery_name("_services._dns-sd._udp.local"),
          "DNS-SD meta-query recognised")
    check(SMBWatch._is_service_discovery_name("1.1.168.192.in-addr.arpa"),
          "reverse-lookup zone recognised")
    check(not SMBWatch._is_service_discovery_name("vardagsrum.local"),
          "ordinary .local host name is NOT a service type")
    check(not SMBWatch._is_service_discovery_name("wpad"),
          "wpad is NOT a service type")

    # a PTR/SRV target can never masquerade as an address
    check(not SMBWatch._is_ip_literal("Jacks rum._companion-link._tcp.local."),
          "PTR rdata rejected as an address")
    check(SMBWatch._is_ip_literal("192.168.1.195")
          and SMBWatch._is_ip_literal("fe80::1c2b:3aff:fe44:5566"),
          "real v4/v6 literals accepted as addresses")

    # one host answering its OWN name on several interfaces is not a conflict
    w = fresh()
    w.process_packet(mdns_resp("192.168.1.195", [("Vardagsrum.local", 1, "192.168.1.195")]))
    w.process_packet(mdns_resp("192.168.1.195", [("Vardagsrum.local", 1, "192.168.1.60")]))
    check(none(w, "R3"), "One host, own name, two interfaces -> no R3")

    # ... including a v4 + v6 pair (dual-stack parity for the fix itself)
    w = fresh()
    w.process_packet(mdns_resp("192.168.1.195", [("Vardagsrum.local", 1, "192.168.1.195")]))
    w.process_packet(mdns_resp("192.168.1.195",
                               [("Vardagsrum.local", 28, "fe80::1c2b:3aff:fe44:5566")]))
    check(none(w, "R3"), "One host answering A + AAAA for itself -> no R3")

    # a Bonjour Sleep Proxy answering for a sleeping device is one responder
    w = fresh()
    for _ in range(3):
        w.process_packet(mdns_resp("192.168.1.195", [("MacBook.local", 1, "192.168.1.77")]))
    check(none(w, "R3") and none(w, "R2"), "Sleep-proxy answers for a sleeper -> quiet")

    # an Apple TV advertising a pile of services does not look aggressive
    w = fresh()
    for svc in ("_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local",
                "_sleep-proxy._udp.local", "_touch-able._tcp.local", "_homekit._tcp.local",
                "_rdlink._tcp.local", "_mediaremotetv._tcp.local", "_airdrop._tcp.local",
                "_services._dns-sd._udp.local", "_spotify-connect._tcp.local"):
        w.process_packet(mdns_resp("192.168.1.195", [(svc, 12, "AppleTV." + svc)]))
    check(none(w, "R2"), "Service-rich Apple device does not trip R2")

    # DETECTION MUST SURVIVE: two different hosts claiming one name still fires
    w = fresh()
    w.process_packet(mdns_resp("192.168.1.50", [("fileserver.local", 1, "192.168.1.50")]))
    w.process_packet(mdns_resp("192.168.1.66", [("fileserver.local", 1, "192.168.1.66")]))
    r3 = get(w, "R3")
    check(r3 is not None, "R3 still fires when two hosts claim one name")
    check(r3 is not None and "192.168.1.50" in r3.evidence.get("responders", "")
          and "192.168.1.66" in r3.evidence.get("responders", ""),
          "R3 names both responders, not just the addresses")

    # and a poisoner answering a real host name over mDNS is still caught
    w = fresh()
    w.process_packet(mdns_resp("192.168.1.66", [("wpad.local", 1, "192.168.1.66")]))
    check(has(w, "R1", "192.168.1.66", Severity.CRITICAL),
          "WPAD over mDNS still CRITICAL after the FP fix")

    # A single legit host answering only its own single name repeatedly:
    # no R2, no R3.
    w = fresh()
    for _ in range(5):
        w.process_packet(llmnr_resp("10.0.0.20", "workstation7", "10.0.0.20"))
    check(none(w, "R2") and none(w, "R3"), "Legit single-name responder is quiet")

    # IPv6 LLMNR responder
    w = fresh()
    w.process_packet(llmnr_resp("fe80::1", "wpad", "fe80::1", rtype="AAAA",
                                dst="ff02::1:3"))
    check(has(w, "R1", "fe80::1", Severity.CRITICAL), "R1 IPv6 LLMNR WPAD")

    # ===================================================================== #
    #  Group D: NBT-NS poisoning
    # ===================================================================== #
    w = fresh()
    w.process_packet(nbtns_resp("10.0.0.66", "WPAD", "10.0.0.66", suffix=0x00))
    check(has(w, "R1", "10.0.0.66", Severity.CRITICAL), "R1 NBT-NS WPAD -> CRITICAL")

    w = fresh()
    for nm in ("FILESERV", "PRINTSRV", "HRSHARE"):
        w.process_packet(nbtns_resp("10.0.0.66", nm, "10.0.0.66"))
    check(has(w, "R2", "10.0.0.66", Severity.HIGH), "R2 aggressive NBT-NS responder")

    # NBT-NS suffix decoding sanity: response parsed & scored at all
    w = fresh()
    w.process_packet(nbtns_resp("10.0.0.70", "SINGLEHOST", "10.0.0.70"))
    check(has(w, "R5", "10.0.0.70"), "NBT-NS response parsed (baseline emitted)")

    # ===================================================================== #
    #  Group E: mDNS
    # ===================================================================== #
    # WPAD via mDNS A record -> CRITICAL
    w = fresh()
    w.process_packet(mdns_resp("10.0.0.66", [("wpad.local", DNS_TYPE_A, "10.0.0.66")]))
    check(has(w, "R1", "10.0.0.66", Severity.CRITICAL), "R1 mDNS WPAD -> CRITICAL")

    # Legit Bonjour service-discovery chatter (PTR/SRV/TXT) must NOT flag
    w = fresh()
    recs = [("_airplay._tcp.local", 12, "AppleTV._airplay._tcp.local"),
            ("_raop._tcp.local", 12, "AppleTV._raop._tcp.local"),
            ("_companion-link._tcp.local", 12, "iPhone._companion-link._tcp.local"),
            ("_googlecast._tcp.local", 12, "Chromecast._googlecast._tcp.local")]
    w.process_packet(mdns_resp("10.0.0.30", recs))
    check(none(w, "R1") and none(w, "R2") and none(w, "R5"),
          "mDNS service-discovery PTR chatter ignored")

    # mDNS aggressive threshold is higher: 3 host A answers should NOT trip R2
    w = fresh()
    for nm in ("host1.local", "host2.local", "host3.local"):
        w.process_packet(mdns_resp("10.0.0.66", [(nm, DNS_TYPE_A, "10.0.0.66")]))
    check(none(w, "R2"), "mDNS below its higher threshold: no R2")

    # ...but 8 distinct A answers should trip R2
    w = fresh()
    for i in range(8):
        w.process_packet(mdns_resp("10.0.0.66",
                                   [("h%d.local" % i, DNS_TYPE_A, "10.0.0.66")]))
    check(has(w, "R2", "10.0.0.66"), "mDNS aggressive over higher threshold")

    # ===================================================================== #
    #  Group F: cross-protocol correlation (R4) + allowlist
    # ===================================================================== #
    # A host answering the same name on two protocols while ALSO answering
    # other names is Responder-shaped -> R4 HIGH
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "fileserv", "10.0.0.66"))
    w.process_packet(llmnr_resp("10.0.0.66", "printsrv", "10.0.0.66"))
    w.process_packet(nbtns_resp("10.0.0.66", "FILESERV", "10.0.0.66"))
    check(has(w, "R4", "10.0.0.66", Severity.HIGH), "R4 same name across LLMNR+NBT-NS")

    # GAP CLOSED: Responder answers 'wpad' on LLMNR and 'wpad.local' on mDNS.
    # Raw string comparison never correlated those; canonical matching does.
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(mdns_resp("10.0.0.66", [("wpad.local", 1, "10.0.0.66")]))
    r4 = get(w, "R4", "10.0.0.66")
    check(r4 is not None, "R4 correlates wpad (LLMNR) with wpad.local (mDNS)")
    check(r4 is not None and r4.evidence.get("canonical_name") == "wpad",
          "R4 reports the canonical name")
    check(r4 is not None and "LLMNR" in r4.evidence.get("protocols", "")
          and "mDNS" in r4.evidence.get("protocols", ""),
          "R4 names both protocol legs")

    # FP GUARD: a legitimate host defending its OWN single identity on two
    # protocols (Windows answers its hostname over both LLMNR and NBT-NS) is
    # NOT a poisoner and must stay quiet.
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.20", "workstation7", "10.0.0.20"))
    w.process_packet(nbtns_resp("10.0.0.20", "WORKSTATION7", "10.0.0.20"))
    check(none(w, "R4"), "Own-identity host on LLMNR+NBT-NS -> no R4")

    # same, across LLMNR and mDNS with the .local suffix
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.20", "workstation7", "10.0.0.20"))
    w.process_packet(mdns_resp("10.0.0.20", [("workstation7.local", 1, "10.0.0.20")]))
    check(none(w, "R4") and none(w, "R2"),
          "Own-identity host on LLMNR+mDNS -> no R4, no double-counted R2")

    # allowlisted responder suppresses R1/R2/R3/R4 (still may baseline internally)
    cfg = Config(allow_responders={"10.0.0.66"})
    w = fresh(cfg)
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    for nm in ("a", "b", "c", "d"):
        w.process_packet(llmnr_resp("10.0.0.66", nm, "10.0.0.66"))
    check(none(w, "R1") and none(w, "R2"), "Allowlisted responder fully suppressed")

    # allowlisted binding (name->ip) suppresses WPAD/conflict when it matches
    cfg = Config(allow_bindings={"wpad": "10.0.0.5"})
    w = fresh(cfg)
    w.process_packet(llmnr_resp("10.0.0.5", "wpad", "10.0.0.5"))
    check(none(w, "R1"), "Allowlisted correct WPAD binding suppressed")
    # but a DIFFERENT ip answering wpad is still flagged
    w2 = fresh(cfg)
    w2.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    check(has(w2, "R1", "10.0.0.66"), "Wrong-IP WPAD still flagged despite binding")

    # ===================================================================== #
    #  Group G: hygiene / dedup / non-responses
    # ===================================================================== #
    # LLMNR *query* (qr=0) must be ignored
    w = fresh()
    q = (IP(src="10.0.0.10", dst="224.0.0.252") / UDP(sport=61000, dport=PORT_LLMNR) /
         DNS(qr=0, qd=DNSQR(qname="wpad")))
    w.process_packet(q)
    check(len(w.findings) == 0, "LLMNR query (qr=0) ignored")

    # dedup: same WPAD finding twice -> single finding, count increments
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    r1s = [f for f in w.findings if f.rule == "R1"]
    check(len(r1s) == 1 and r1s[0].count >= 2, "R1 deduped with count increment")

    # non-SMB TCP is ignored
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.80", b"GET / HTTP/1.1\r\n"))
    check(len(w.findings) == 0, "Non-SMB tcp/445 payload ignored")

    # Finding JSON round-trips
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    j = json.loads(w.findings[0].to_json())
    check(j["rule"] == "R1" and j["severity"] == "CRITICAL" and j["subject"] == "10.0.0.66",
          "Finding serializes to JSON")

    # ===================================================================== #
    #  Group H: relay-path correlation (C1)
    # ===================================================================== #
    unsigned = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED)
    signed = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_REQUIRED)

    # poisoner first (R2), then unsigned target -> C1 CRITICAL naming the target
    w = fresh()
    for nm in ("fileserv", "printsrv", "hrshare"):
        w.process_packet(llmnr_resp("10.0.0.66", nm, "10.0.0.66"))
    check(none(w, "C1"), "No relay path until a target is seen")
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    c1 = get(w, "C1", "10.0.0.66")
    check(c1 is not None and c1.severity == Severity.CRITICAL,
          "C1 fires when poisoner + unsigned target coexist")
    check(c1 is not None and "10.0.0.9" in c1.evidence.get("relay_targets", ""),
          "C1 enumerates the relay target")

    # reverse order: unsigned target first, then poisoner -> still C1
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    check(none(w, "C1"), "Target alone is not a relay path")
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))  # R1 poisoner
    check(has(w, "C1", "10.0.0.66"), "C1 fires regardless of packet order")

    # poisoner via R4 also drives C1
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "fileserv", "10.0.0.66"))
    w.process_packet(llmnr_resp("10.0.0.66", "printsrv", "10.0.0.66"))
    w.process_packet(nbtns_resp("10.0.0.66", "FILESERV", "10.0.0.66"))  # R4
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    check(has(w, "C1", "10.0.0.66"), "C1 driven by R4 poisoner")

    # SIGNED target must NOT create a relay path
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(smb_pkt("10.0.0.9", signed))
    check(none(w, "C1"), "Signing-required target yields no relay path")

    # SMBv1-unsigned (S3) target also counts
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(smb_pkt("10.0.0.7",
                             _build_smb1_negotiate_resp(0x0000, SMB1_SIGNING_ENABLED)))
    check(has(w, "C1", "10.0.0.66"), "C1 counts SMBv1-unsigned target")

    # a second distinct target grows the finding and re-fires (count increments)
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    w.process_packet(smb_pkt("10.0.0.11", unsigned))
    c1 = get(w, "C1", "10.0.0.66")
    check(c1 is not None and "10.0.0.11" in c1.evidence.get("relay_targets", "")
          and c1.count >= 2, "C1 grows and re-fires on a new target")

    # the poisoner being itself unsigned is not listed as its own target
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.9", "wpad", "10.0.0.9"))   # poisoner 10.0.0.9
    w.process_packet(smb_pkt("10.0.0.9", unsigned))               # same box unsigned
    check(none(w, "C1"), "Poisoner is not its own relay target")

    # allowlisted SMB target -> no S2 -> no relay path
    w = fresh(Config(allow_smb={"10.0.0.9"}))
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    check(none(w, "C1"), "Allowlisted target suppresses relay path")

    # ===================================================================== #
    #  Group I: Kerberos downgrade watch (K1/K2/K3)
    # ===================================================================== #
    # DES offered -> K1 HIGH
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.40", [18, 17, 3, 1]))
    check(has(w, "K1", "10.0.0.40", Severity.HIGH), "K1 DES offered -> HIGH")

    # RC4 present but AES preferred -> K2 MEDIUM
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.41", [18, 17, 23]))
    k2 = get(w, "K2", "10.0.0.41")
    check(k2 is not None and k2.severity == Severity.MEDIUM,
          "K2 RC4 offered (AES preferred) -> MEDIUM")

    # RC4 as most-preferred etype -> K2 escalates to HIGH
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.42", [23, 18, 17]))
    k2 = get(w, "K2", "10.0.0.42")
    check(k2 is not None and k2.severity == Severity.HIGH,
          "K2 RC4 most-preferred -> HIGH")

    # only weak etypes, no AES -> K3 HIGH (and K2 for the RC4)
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.43", [23, 1]))
    check(has(w, "K3", "10.0.0.43", Severity.HIGH), "K3 no-AES downgrade -> HIGH")

    # healthy AES-only AS-REQ -> no Kerberos findings
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.44", [18, 17]))
    check(none(w, "K1") and none(w, "K2") and none(w, "K3"),
          "AES-only AS-REQ is clean")

    # etype order preserved by the parser (preference matters)
    check(SMBWatch.parse_as_req(_build_as_req([23, 18, 17]))[0] == [23, 18, 17],
          "AS-REQ etype preference order preserved")

    # cname extraction (best-effort) populates principal
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.45", [23, 18], cname="svc_sql"))
    k2 = get(w, "K2", "10.0.0.45")
    check(k2 is not None and "svc_sql" in k2.evidence.get("principal", ""),
          "Kerberos cname extracted into principal")

    # UDP/88 transport (no 4-byte prefix) parses too
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.46", [1], over_tcp=False))
    check(has(w, "K1", "10.0.0.46"), "Kerberos over UDP/88 parses")

    # AS-REP / non-AS-REQ Kerberos is ignored (wrong app tag)
    w = fresh()
    as_rep = b"\x6B" + bytes([2]) + b"\x30\x00"       # [APPLICATION 11] stub
    w.process_packet(IP(src="10.0.0.2", dst="10.0.0.47") /
                     TCP(sport=PORT_KRB, dport=50000) /
                     s.Raw(load=struct.pack(">I", len(as_rep)) + as_rep))
    check(len(w.findings) == 0, "Non-AS-REQ Kerberos ignored")

    # garbage on tcp/88 doesn't crash or fire
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.48", b"\x00\x00\x00\x04junk", sport=PORT_KRB))
    check(len(w.findings) == 0, "Garbage on tcp/88 ignored")

    # ===================================================================== #
    #  Group J: Kerberos REPLY-side grants (K4/K5) + TGS-REQ
    # ===================================================================== #
    # TGS-REQ offering RC4 top-preference -> K2 HIGH (request side, TGS)
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.50", [23, 18, 17], app_tag=KRB_APP_TGS_REQ))
    k2 = get(w, "K2", "10.0.0.50")
    check(k2 is not None and k2.severity == Severity.HIGH
          and "TGS-REQ" in k2.title, "TGS-REQ RC4 top-pref -> K2 HIGH")

    # TGS-REP granting an RC4 service ticket -> K4 HIGH, attributed to the client
    # (packet dst), with the SPN captured (Kerberoast)
    w = fresh()
    w.process_packet(krb_rep_pkt("10.0.0.60", ticket_etype=23, reply_etype=18,
                                 app_tag=KRB_APP_TGS_REP, sname="MSSQLSvc/db01"))
    k4 = get(w, "K4", "10.0.0.60")
    check(k4 is not None and k4.severity == Severity.HIGH, "K4 KDC granted RC4 -> HIGH")
    check(k4 is not None and k4.evidence.get("spn") == "MSSQLSvc/db01",
          "K4 captures the Kerberoast SPN")
    check(k4 is not None and "Kerberoastable" in k4.detail,
          "K4 TGS-REP flags Kerberoastable ticket")

    # AS-REP with RC4 reply enc-part -> K4 with AS-REP-roast wording
    w = fresh()
    w.process_packet(krb_rep_pkt("10.0.0.61", ticket_etype=18, reply_etype=23,
                                 app_tag=KRB_APP_AS_REP, cname="jdoe"))
    k4 = get(w, "K4", "10.0.0.61")
    check(k4 is not None and "AS-REP-roasting" in k4.detail,
          "AS-REP RC4 reply -> K4 AS-REP-roast")

    # KDC granting DES -> K5 CRITICAL
    w = fresh()
    w.process_packet(krb_rep_pkt("10.0.0.62", ticket_etype=1, reply_etype=18,
                                 app_tag=KRB_APP_TGS_REP))
    check(has(w, "K5", "10.0.0.62", Severity.CRITICAL), "K5 KDC granted DES -> CRITICAL")

    # AES-only REP -> no grant finding
    w = fresh()
    w.process_packet(krb_rep_pkt("10.0.0.63", ticket_etype=18, reply_etype=18))
    check(none(w, "K4") and none(w, "K5"), "AES-only REP is clean")

    # parser extracts the granted ticket etype and SPN
    tag, tkt_e, rep_e, cn, rlm, spn = SMBWatch.parse_kdc_rep(
        _build_kdc_rep(KRB_APP_TGS_REP, 23, 18, cname="svc", sname="http/web01"))
    check(tag == KRB_APP_TGS_REP and tkt_e == 23 and rep_e == 18
          and spn == "http/web01", "parse_kdc_rep extracts ticket etype + SPN")

    # ===================================================================== #
    #  Group K: fold a downgrade client into C1
    # ===================================================================== #
    unsigned = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED)

    # poisoner + KDC-granted-RC4 client on the segment, NO unsigned SMB target:
    # C1 fires at HIGH and names the downgrade client.
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))       # poisoner (R1)
    w.process_packet(krb_rep_pkt("10.0.0.70", ticket_etype=23))         # K4 downgrade client
    c1 = get(w, "C1", "10.0.0.66")
    check(c1 is not None and c1.severity == Severity.HIGH,
          "C1 fires HIGH for poisoner + downgrade client (no SMB target)")
    check(c1 is not None and "10.0.0.70" in c1.evidence.get("downgrade_clients", ""),
          "C1 enumerates the downgrade client")

    # add an unsigned SMB target later -> C1 escalates to CRITICAL and lists both
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    c1 = get(w, "C1", "10.0.0.66")
    check(c1 is not None and c1.severity == Severity.CRITICAL
          and "10.0.0.9" in c1.evidence.get("relay_targets", "")
          and "10.0.0.70" in c1.evidence.get("downgrade_clients", ""),
          "C1 escalates to CRITICAL and carries both dimensions")

    # a plain RC4 *offer* (AES preferred, K2 MEDIUM) does NOT fold into C1
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(krb_pkt("10.0.0.71", [18, 17, 23]))               # K2 MEDIUM only
    check(none(w, "C1"), "Plain RC4 offer does not fold into C1")

    # the downgrade client being the poisoner itself is not double-counted
    w = fresh()
    for nm in ("a", "b", "c"):
        w.process_packet(llmnr_resp("10.0.0.66", nm, "10.0.0.66"))     # R2 poisoner
    w.process_packet(krb_rep_pkt("10.0.0.66", ticket_etype=23))        # same box, K4
    check(none(w, "C1"), "Poisoner is not folded as its own downgrade client")

    # ===================================================================== #
    #  Group L: pre-auth watching (K6 roastable, K7 enum/spray)
    # ===================================================================== #
    # AS-REQ without pre-auth -> AS-REP for same principal = roastable (K6)
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.80", [18, 17], cname="svc_web", pa_enc_ts=False))
    w.process_packet(krb_rep_pkt("10.0.0.80", ticket_etype=18, reply_etype=18,
                                 app_tag=KRB_APP_AS_REP, cname="svc_web"))
    check(has(w, "K6", "10.0.0.80", Severity.HIGH), "K6 AS-REP-roastable account")

    # normal account: AS-REQ WITH pre-auth then AS-REP -> no K6
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.81", [18, 17], cname="normaluser", pa_enc_ts=True))
    w.process_packet(krb_rep_pkt("10.0.0.81", ticket_etype=18, reply_etype=18,
                                 app_tag=KRB_APP_AS_REP, cname="normaluser"))
    check(none(w, "K6"), "Pre-auth present -> no roastable finding")

    # PREAUTH_REQUIRED error marks the account as requiring pre-auth: the normal
    # two-leg flow (no-preauth probe -> error -> preauth resend -> REP) is clean
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.82", [18], cname="realuser", pa_enc_ts=False))
    w.process_packet(krb_err_pkt("10.0.0.82", KRB_ERR_PREAUTH_REQUIRED, cname="realuser"))
    w.process_packet(krb_pkt("10.0.0.82", [18], cname="realuser", pa_enc_ts=True))
    w.process_packet(krb_rep_pkt("10.0.0.82", ticket_etype=18, reply_etype=18,
                                 app_tag=KRB_APP_AS_REP, cname="realuser"))
    check(none(w, "K6"), "PREAUTH_REQUIRED error suppresses false roastable")

    # an AS-REP with no preceding AS-REQ we saw -> cannot judge -> no K6
    w = fresh()
    w.process_packet(krb_rep_pkt("10.0.0.83", ticket_etype=18, reply_etype=18,
                                 app_tag=KRB_APP_AS_REP, cname="ghost"))
    check(none(w, "K6"), "No matching AS-REQ -> no roastable claim")

    # K7: burst of UNKNOWN-principal errors toward one requester = enumeration
    w = fresh(Config(krb_err_threshold=5))
    for i in range(5):
        w.process_packet(krb_err_pkt("10.0.0.84", KRB_ERR_C_PRINCIPAL_UNKNOWN,
                                     cname="user%d" % i))
    check(has(w, "K7", "10.0.0.84", Severity.HIGH), "K7 user-enumeration burst")
    k7 = get(w, "K7", "10.0.0.84")
    check(k7 is not None and "enumeration" in k7.title, "K7 classifies enumeration")

    # K7: burst of PREAUTH_FAILED = spray / AS-REP-roast probing
    w = fresh(Config(krb_err_threshold=5))
    for i in range(5):
        w.process_packet(krb_err_pkt("10.0.0.85", KRB_ERR_PREAUTH_FAILED,
                                     cname="admin"))
    k7 = get(w, "K7", "10.0.0.85")
    check(k7 is not None and "spray" in k7.title, "K7 classifies password-spray")

    # KRB_ERROR parser sanity
    ec, cn, rlm, sn, ei = SMBWatch.parse_krb_error(
        _build_krb_error(KRB_ERR_PREAUTH_REQUIRED, cname="bob"))
    check(ec == KRB_ERR_PREAUTH_REQUIRED and cn == "bob", "parse_krb_error extracts code+cname")

    # ===================================================================== #
    #  Group M: directed Kerberos->SMB edge (C2)
    # ===================================================================== #
    unsigned = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED)
    signed = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_REQUIRED)

    # client gets a TGS for cifs/FS01, FS01 resolves to an unsigned relay target
    w = fresh()
    resolve(w, "FS01", "10.0.0.9")                                   # passive name->IP
    w.process_packet(smb_pkt("10.0.0.9", unsigned))                 # FS01 is unsigned (S2)
    w.process_packet(krb_pkt("10.0.0.30", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/FS01"))                     # intent
    c2 = get(w, "C2", "10.0.0.30")
    check(c2 is not None and c2.evidence.get("target") == "10.0.0.9",
          "C2 directed edge via SPN resolution")
    check(c2 is not None and c2.severity == Severity.HIGH, "C2 HIGH without poisoner")

    # same, but a poisoner is live -> C2 escalates to CRITICAL
    w = fresh()
    resolve(w, "FS01", "10.0.0.9")
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))   # poisoner
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    w.process_packet(krb_rep_pkt("10.0.0.30", ticket_etype=18, reply_etype=18,
                                 app_tag=KRB_APP_TGS_REP, sname="cifs/FS01"))
    check(has(w, "C2", "10.0.0.30", Severity.CRITICAL),
          "C2 CRITICAL when a poisoner is live")

    # directed edge via a directly observed SMB session (no name resolution)
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.31", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/UNKNOWNHOST"))              # intent, unresolved
    w.process_packet(smb_pkt("10.0.0.9", unsigned, dst="10.0.0.31"))  # session ->target
    check(has(w, "C2", "10.0.0.31"), "C2 via observed SMB session")

    # SPN host resolves to a SIGNED server -> not a relay target -> no C2
    w = fresh()
    resolve(w, "DC01", "10.0.0.5")
    w.process_packet(smb_pkt("10.0.0.5", signed))
    w.process_packet(krb_pkt("10.0.0.32", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/DC01"))
    check(none(w, "C2"), "No C2 to a signing-required server")

    # a non-SMB SPN (e.g. MSSQLSvc) does not create an SMB edge
    w = fresh()
    resolve(w, "DB01", "10.0.0.9")
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    w.process_packet(krb_pkt("10.0.0.33", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="MSSQLSvc/DB01:1433"))
    check(none(w, "C2"), "Non-SMB SPN class does not create an SMB edge")

    # ===================================================================== #
    #  Group N: NTLM relay in progress (N1/N2/N3)
    # ===================================================================== #
    # N3: static Responder challenge
    w = fresh()
    w.process_packet(smb_ntlm_pkt("10.0.0.66", "10.0.0.50",
                                  _build_ntlm_type2(bytes.fromhex("1122334455667788"))))
    check(has(w, "N3", "10.0.0.66", Severity.CRITICAL), "N3 static Responder challenge")

    # N1: same challenge from two different server IPs = cross-server relay
    w = fresh()
    chal = bytes.fromhex("a1b2c3d4e5f60718")
    w.process_packet(smb_ntlm_pkt("10.0.0.9", "10.0.0.66", _build_ntlm_type2(chal)))
    w.process_packet(smb_ntlm_pkt("10.0.0.66", "10.0.0.30", _build_ntlm_type2(chal)))
    check(has(w, "N1", sev=Severity.CRITICAL), "N1 challenge reuse across servers -> CRITICAL")
    n1 = get(w, "N1")
    check(n1 is not None and "10.0.0.9" in n1.evidence.get("server_ips", "")
          and "10.0.0.66" in n1.evidence.get("server_ips", ""),
          "N1 lists both server IPs")

    # unique challenges per session -> no N1 (the normal case)
    w = fresh()
    w.process_packet(smb_ntlm_pkt("10.0.0.9", "10.0.0.30",
                                  _build_ntlm_type2(bytes.fromhex("1111111111111111"))))
    w.process_packet(smb_ntlm_pkt("10.0.0.9", "10.0.0.31",
                                  _build_ntlm_type2(bytes.fromhex("2222222222222222"))))
    check(none(w, "N1"), "Unique challenges per session -> no N1")

    # N2: Type-3 workstation name doesn't match the source's known name
    w = fresh()
    resolve(w, "ATTACKER", "10.0.0.66")                             # src is known as ATTACKER
    w.process_packet(smb_ntlm_pkt("10.0.0.66", "10.0.0.9",
                                  _build_ntlm_type3(domain="CORP", user="ceo",
                                                    workstation="CEO-LAPTOP")))
    check(has(w, "N2", "10.0.0.66", Severity.MEDIUM), "N2 workstation/source mismatch")

    # N2 negative: workstation matches the source's known name -> no finding
    w = fresh()
    resolve(w, "WS7", "10.0.0.40")
    w.process_packet(smb_ntlm_pkt("10.0.0.40", "10.0.0.9",
                                  _build_ntlm_type3(domain="CORP", user="joe",
                                                    workstation="WS7")))
    check(none(w, "N2"), "Matching workstation name -> no N2")

    # N2 requires a known source name (no baseline -> no guess)
    w = fresh()
    w.process_packet(smb_ntlm_pkt("10.0.0.41", "10.0.0.9",
                                  _build_ntlm_type3(workstation="WHATEVER")))
    check(none(w, "N2"), "No known source name -> N2 stays silent")

    # NTLM Type-3 field parser sanity
    fields = SMBWatch._ntlm_type3_fields(_build_ntlm_type3("D", "u", "WKS"),
                                         0)  # blob starts at 0 here
    check(fields == ("D", "u", "WKS"), "NTLM Type-3 fields parsed")

    # ===================================================================== #
    #  Group O: CVE-2020-0796 SMBGhost (V1 posture, V2 exploit)
    # ===================================================================== #
    comp_ctx = _build_negotiate_context(SMB2_NEGOTIATE_CONTEXT_COMPRESSION,
                                        _build_compression_capabilities((1, 2, 3)))
    preauth_ctx = _build_negotiate_context(0x0001, b"\x00" * 38)

    # 3.1.1 advertising compression -> V1 HIGH
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.90",
                             _build_smb2_negotiate_resp_ctx(contexts=[preauth_ctx, comp_ctx])))
    v1 = get(w, "V1", "10.0.0.90")
    check(v1 is not None and v1.severity == Severity.HIGH, "V1 SMBGhost posture -> HIGH")
    check(v1 is not None and v1.evidence.get("cve") == "CVE-2020-0796",
          "V1 carries the CVE id")
    check(v1 is not None and "LZNT1" in v1.evidence.get("compression_algorithms", ""),
          "V1 decodes the compression algorithms")

    # 3.1.1 WITHOUT a compression context -> no V1
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.91",
                             _build_smb2_negotiate_resp_ctx(contexts=[preauth_ctx])))
    check(none(w, "V1"), "No compression context -> no V1")

    # a plain 3.0.2 negotiate (no context list at all) -> no V1
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.92",
                             _build_smb2_negotiate_resp(0x0302, SMB2_SIGNING_ENABLED)))
    check(none(w, "V1"), "Pre-3.1.1 dialect -> no V1")

    # allowlisted server is suppressed for V1 too
    w = fresh(Config(allow_smb={"10.0.0.90"}))
    w.process_packet(smb_pkt("10.0.0.90",
                             _build_smb2_negotiate_resp_ctx(contexts=[comp_ctx])))
    check(none(w, "V1"), "allow-smb suppresses V1")

    # exploit: OriginalCompressedSegmentSize + Offset overflows 32 bits
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.93",
                             _build_compression_transform(0xFFFFFFFF, 0xFFFFFFFF)))
    v2 = get(w, "V2", "10.0.0.93")
    check(v2 is not None and v2.severity == Severity.CRITICAL,
          "V2 SMBGhost exploit -> CRITICAL")
    check(v2 is not None and v2.evidence.get("offset") == "0xffffffff",
          "V2 records the overflowing offset")

    # a normal compressed frame (no overflow) -> silent
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.94", _build_compression_transform(4096, 16)))
    check(none(w, "V2"), "Well-formed compressed frame -> no V2")

    # boundary: sum exactly 0xFFFFFFFF does not overflow
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.95",
                             _build_compression_transform(0xFFFFFFF0, 0x0F)))
    check(none(w, "V2"), "Sum at exactly 0xFFFFFFFF -> no V2")

    # parser sanity
    ctxs = SMBWatch.parse_negotiate_contexts(
        _build_smb2_negotiate_resp_ctx(contexts=[preauth_ctx, comp_ctx]))
    check(ctxs is not None and
          SMB2_NEGOTIATE_CONTEXT_COMPRESSION in [t for t, _ in ctxs],
          "parse_negotiate_contexts finds the compression context")

    # ===================================================================== #
    #  Group P: CVE-2017-0144 EternalBlue (V6)
    # ===================================================================== #
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.96",
                             _build_smb1_trans2(SMB1_TRANS2_SESSION_SETUP)))
    check(has(w, "V6", "10.0.0.96", Severity.HIGH), "V6 EternalBlue Trans2 probe")

    # an ordinary Trans2 subcommand (QUERY_PATH_INFO) is silent
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.97", _build_smb1_trans2(0x0005)))
    check(none(w, "V6"), "Ordinary Trans2 subcommand -> no V6")

    # ===================================================================== #
    #  Group Q: CVE-2022-33679 RC4-MD4 (V4 offer/grant, V5 injection)
    # ===================================================================== #
    # client requests etype -128
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.100", [KRB_ETYPE_RC4_MD4], cname="victim"))
    v4 = get(w, "V4", "10.0.0.100")
    check(v4 is not None and v4.severity == Severity.CRITICAL,
          "V4 RC4-MD4 requested -> CRITICAL")
    check(v4 is not None and v4.evidence.get("cve") == "CVE-2022-33679",
          "V4 carries the CVE id")

    # KDC grants RC4-MD4
    w = fresh()
    w.process_packet(krb_rep_pkt("10.0.0.101", ticket_etype=KRB_ETYPE_RC4_MD4,
                                 reply_etype=18, app_tag=KRB_APP_AS_REP))
    check(has(w, "V4", "10.0.0.101", Severity.CRITICAL), "V4 RC4-MD4 granted -> CRITICAL")

    # ordinary RC4 (23) must NOT be mistaken for RC4-MD4
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.102", [23, 18]))
    check(none(w, "V4"), "Plain rc4-hmac does not fire V4")

    # V5: KRB-ERROR PREAUTH_REQUIRED advertising only RC4-MD4
    w = fresh()
    w.process_packet(krb_err_pkt_ei("10.0.0.103", KRB_ERR_PREAUTH_REQUIRED,
                                    [KRB_ETYPE_RC4_MD4]))
    v5 = get(w, "V5", "10.0.0.103")
    check(v5 is not None and v5.severity == Severity.CRITICAL,
          "V5 RC4-MD4 downgrade injection -> CRITICAL")
    check(v5 is not None and v5.evidence.get("rc4_md4_only") == "True",
          "V5 notes RC4-MD4 was the only offered etype")

    # a normal KDC offering AES only -> no V5
    w = fresh()
    w.process_packet(krb_err_pkt_ei("10.0.0.104", KRB_ERR_PREAUTH_REQUIRED, [18, 17]))
    check(none(w, "V5"), "AES-only PA-ETYPE-INFO2 -> no V5")

    # parser sanity
    ec, cn, rlm, sn, ei = SMBWatch.parse_krb_error(
        _build_krb_error(KRB_ERR_PREAUTH_REQUIRED, etype_info2=[18, KRB_ETYPE_RC4_MD4]))
    check(ei == [18, KRB_ETYPE_RC4_MD4], "parse_krb_error extracts PA-ETYPE-INFO2")

    # ===================================================================== #
    #  Group R: CVE-2025-33073 reflection (V3)
    # ===================================================================== #
    MARSHALLED = "srv01" + MARSHALLED_TARGET_MAGIC + "A" * 30 + "YBAAAA"

    # helper recognises the blob, and does not cry wolf on normal names
    check(SMBWatch.has_marshalled_target(MARSHALLED), "marshalled blob recognised")
    check(SMBWatch.has_marshalled_target(MARSHALLED + ".corp.local"),
          "marshalled blob recognised with a DNS suffix appended")
    check(not SMBWatch.has_marshalled_target("fileserver01.corp.local"),
          "ordinary hostname is not flagged")
    check(not SMBWatch.has_marshalled_target("wpad"), "short name is not flagged")

    # a TGS-REQ for a marshalled SPN
    w = fresh()
    w.process_packet(krb_pkt("10.0.0.110", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/" + MARSHALLED))
    v3 = get(w, "V3", "10.0.0.110")
    check(v3 is not None and v3.severity == Severity.HIGH,
          "V3 marshalled SPN in TGS-REQ -> HIGH")
    check(v3 is not None and v3.evidence.get("cve") == "CVE-2025-33073",
          "V3 carries the CVE id")

    # with a poisoner live it escalates
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(krb_pkt("10.0.0.111", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/" + MARSHALLED))
    check(has(w, "V3", "10.0.0.111", Severity.CRITICAL),
          "V3 escalates to CRITICAL with a live poisoner")

    # a name-resolution answer for a marshalled name
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", MARSHALLED, "10.0.0.66"))
    check(has(w, "V3", "10.0.0.66"), "V3 marshalled name answered on the wire")

    # the reflection itself: client and server are the same host
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.112",
                             _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED),
                             dst="10.0.0.112"))
    v3 = get(w, "V3", "10.0.0.112")
    check(v3 is not None and v3.severity == Severity.CRITICAL,
          "V3 self-directed SMB session -> CRITICAL reflection")

    # a normal client->server session is not reflection
    w = fresh()
    w.process_packet(smb_pkt("10.0.0.9",
                             _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED),
                             dst="10.0.0.30"))
    check(none(w, "V3"), "Ordinary SMB session is not flagged as reflection")

    # IPv6 parity: reflection and marshalled names must work on v6 too
    w = fresh()
    v6p = (IPv6(src="2001:db8::112", dst="2001:db8::112") /
           TCP(sport=PORT_SMB, dport=50000) /
           s.Raw(load=_build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED)))
    w.process_packet(v6p)
    check(has(w, "V3", "2001:db8::112", Severity.CRITICAL),
          "V3 reflection detected over IPv6")

    w = fresh()
    v6k = (IPv6(src="2001:db8::30", dst="2001:db8::2") /
           TCP(sport=50000, dport=PORT_KRB) /
           s.Raw(load=_build_as_req([18], app_tag=KRB_APP_TGS_REQ,
                                    sname="cifs/" + MARSHALLED)))
    w.process_packet(v6k)
    check(has(w, "V3", "2001:db8::30"), "V3 marshalled SPN detected over IPv6")

    # IPv6 parity for the SMB-side CVEs
    w = fresh()
    w.process_packet(IPv6(src="2001:db8::90", dst="2001:db8::10") /
                     TCP(sport=PORT_SMB, dport=50000) /
                     s.Raw(load=_build_smb2_negotiate_resp_ctx(contexts=[comp_ctx])))
    check(has(w, "V1", "2001:db8::90"), "V1 SMBGhost posture detected over IPv6")

    w = fresh()
    w.process_packet(IPv6(src="2001:db8::93", dst="2001:db8::10") /
                     TCP(sport=PORT_SMB, dport=50000) /
                     s.Raw(load=_build_compression_transform(0xFFFFFFFF, 0xFFFFFFFF)))
    check(has(w, "V2", "2001:db8::93"), "V2 SMBGhost exploit detected over IPv6")

    w = fresh()
    w.process_packet(IPv6(src="2001:db8::96", dst="2001:db8::10") /
                     TCP(sport=PORT_SMB, dport=50000) /
                     s.Raw(load=_build_smb1_trans2(SMB1_TRANS2_SESSION_SETUP)))
    check(has(w, "V6", "2001:db8::96"), "V6 EternalBlue detected over IPv6")

    w = fresh()
    w.process_packet(IPv6(src="2001:db8::2", dst="2001:db8::103") /
                     TCP(sport=PORT_KRB, dport=50000) /
                     s.Raw(load=_build_krb_error(KRB_ERR_PREAUTH_REQUIRED,
                                                 etype_info2=[KRB_ETYPE_RC4_MD4])))
    check(has(w, "V5", "2001:db8::103"), "V5 RC4-MD4 injection detected over IPv6")

    # ===================================================================== #
    #  Group S: compound correlation (V1 folded into C1/C2, downgrade origin)
    # ===================================================================== #
    ghost_unsigned = _build_smb2_negotiate_resp_ctx(secmode=SMB2_SIGNING_ENABLED,
                                                    contexts=[comp_ctx])

    # poisoner + a target that is BOTH unsigned and SMBGhost-exposed -> C1
    # names the compound exposure
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(smb_pkt("10.0.0.9", ghost_unsigned))
    c1 = get(w, "C1", "10.0.0.66")
    check(c1 is not None and c1.severity == Severity.CRITICAL,
          "C1 still CRITICAL with a compound target")
    check(c1 is not None and "10.0.0.9" in c1.evidence.get("smbghost_targets", ""),
          "C1 names the SMBGhost-exposed target")
    check(c1 is not None and "COMPOUND EXPOSURE" in c1.detail,
          "C1 explains the compound exposure")

    # an unsigned-but-not-SMBGhost target does not claim compound exposure
    w = fresh()
    w.process_packet(llmnr_resp("10.0.0.66", "wpad", "10.0.0.66"))
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    c1 = get(w, "C1", "10.0.0.66")
    check(c1 is not None and "smbghost_targets" not in c1.evidence,
          "Plain unsigned target -> no compound claim")

    # C2: a downgrade client walking into an unsigned target -> CRITICAL even
    # with no poisoner anywhere on the segment
    w = fresh()
    resolve(w, "FS01", "10.0.0.9")
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    w.process_packet(krb_rep_pkt("10.0.0.30", ticket_etype=23))      # K4 -> downgrade
    w.process_packet(krb_pkt("10.0.0.30", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/FS01"))
    c2 = get(w, "C2", "10.0.0.30")
    check(c2 is not None and c2.severity == Severity.CRITICAL,
          "C2 CRITICAL for a downgrade client -> unsigned target (no poisoner)")
    check(c2 is not None and "downgrade" in c2.title,
          "C2 title names the downgrade origin")
    check(c2 is not None and c2.evidence.get("client_downgrade"),
          "C2 records why the client is a downgrade client")

    # the same edge from a clean client stays HIGH
    w = fresh()
    resolve(w, "FS01", "10.0.0.9")
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    w.process_packet(krb_pkt("10.0.0.31", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/FS01"))
    c2 = get(w, "C2", "10.0.0.31")
    check(c2 is not None and c2.severity == Severity.HIGH,
          "C2 from a clean client stays HIGH")

    # order independence: the edge fires first, THEN the client turns out to be
    # a downgrade client -> the existing finding escalates in place
    w = fresh()
    resolve(w, "FS01", "10.0.0.9")
    w.process_packet(smb_pkt("10.0.0.9", unsigned))
    w.process_packet(krb_pkt("10.0.0.32", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/FS01"))
    check(has(w, "C2", "10.0.0.32", Severity.HIGH), "C2 starts HIGH")
    w.process_packet(krb_rep_pkt("10.0.0.32", ticket_etype=23))      # now weak
    c2 = get(w, "C2", "10.0.0.32")
    check(c2 is not None and c2.severity == Severity.CRITICAL,
          "C2 escalates in place when the client becomes a downgrade client")
    check(c2 is not None and c2.evidence.get("client_downgrade"),
          "escalated C2 refreshes its evidence rather than keeping the old text")

    # C2 target that is also SMBGhost-exposed is called out
    w = fresh()
    resolve(w, "FS02", "10.0.0.11")
    w.process_packet(smb_pkt("10.0.0.11", ghost_unsigned))
    w.process_packet(krb_pkt("10.0.0.33", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/FS02"))
    c2 = get(w, "C2", "10.0.0.33")
    check(c2 is not None and c2.evidence.get("target_smbghost"),
          "C2 flags an SMBGhost-exposed target")
    check(c2 is not None and c2.severity == Severity.CRITICAL,
          "C2 to an SMBGhost target -> CRITICAL")

    # a clean signed target still produces no edge at all
    w = fresh()
    resolve(w, "DC02", "10.0.0.6")
    w.process_packet(smb_pkt("10.0.0.6", signed))
    w.process_packet(krb_rep_pkt("10.0.0.34", ticket_etype=23))
    w.process_packet(krb_pkt("10.0.0.34", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/DC02"))
    check(none(w, "C2"), "Downgrade client to a SIGNED target -> still no C2")

    # REGRESSION: an edge that is ALREADY CRITICAL (SMBGhost target) and then
    # learns its client is a downgrade client gains no severity -- but it does
    # gain a dimension, so the text must still refresh rather than go stale.
    w = fresh()
    resolve(w, "FS03", "10.0.0.12")
    w.process_packet(smb_pkt("10.0.0.12", ghost_unsigned))
    w.process_packet(krb_pkt("10.0.0.35", [18], app_tag=KRB_APP_TGS_REQ,
                             sname="cifs/FS03"))
    c2 = get(w, "C2", "10.0.0.35")
    check(c2 is not None and c2.severity == Severity.CRITICAL
          and not c2.evidence.get("client_downgrade"),
          "C2 CRITICAL on SMBGhost target, client not yet known weak")
    w.process_packet(krb_rep_pkt("10.0.0.35", ticket_etype=23))   # now weak
    c2 = get(w, "C2", "10.0.0.35")
    check(c2 is not None and c2.evidence.get("client_downgrade"),
          "C2 refreshes on new information even without escalation")
    check(c2 is not None and "downgrade" in c2.title,
          "refreshed C2 title names the downgrade origin")

    # ===================================================================== #
    #  Group U: IPv6 dual-stack parity (PRIME DIRECTIVE)
    # ===================================================================== #
    #  Two defects lived here and neither was in the engine: libpcap cannot
    #  port-filter past an IPv6 extension header, and operator-supplied IPv6
    #  addresses were compared as raw strings.
    # ------------------------------------------------------------------- #
    # canonical address form (RFC 5952)
    check(canon_addr("2001:DB8::9") == "2001:db8::9", "canon_addr lowercases v6")
    check(canon_addr("2001:0db8:0000:0000:0000:0000:0000:0009") == "2001:db8::9",
          "canon_addr compresses a fully-expanded v6 address")
    check(canon_addr("2001:db8:0:0:0:0:0:9") == "2001:db8::9",
          "canon_addr compresses zero runs")
    check(canon_addr("10.0.0.9") == "10.0.0.9", "canon_addr leaves IPv4 alone")
    check(canon_addr("fileserver.corp") == "fileserver.corp",
          "canon_addr passes hostnames through unchanged")
    check(canon_addr("2001:db8::9.") == "2001:db8::9",
          "canon_addr tolerates a trailing dot")

    # --allow-smb must work however the operator spelled the address.
    # RFC 3849's documentation prefix is conventionally written 2001:DB8::,
    # so uppercase is the LIKELY input, not an exotic one.
    unsigned_v6 = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED)
    for form in ("2001:db8::9", "2001:DB8::9", "2001:db8:0:0:0:0:0:9",
                 "2001:0db8:0000:0000:0000:0000:0000:0009"):
        w = fresh(Config(allow_smb={form}))
        w.process_packet(IPv6(src="2001:db8::9", dst="2001:db8::30") /
                         TCP(sport=PORT_SMB, dport=50000) / s.Raw(load=unsigned_v6))
        check(none(w, "S2"), "allow-smb suppresses S2 given %s" % form)

    # the same for a responder allowlist and a name binding
    w = fresh(Config(allow_responders={"2001:DB8::66"}))
    w.process_packet(IPv6(src="2001:db8::66", dst="ff02::1:3") /
                     UDP(sport=PORT_LLMNR, dport=61000) /
                     DNS(qr=1, qd=DNSQR(qname="wpad"),
                         an=DNSRR(rrname="wpad", type="AAAA", rdata="2001:db8::66")))
    check(none(w, "R1"), "allow-responder suppresses R1 given uppercase v6")

    w = fresh(Config(allow_bindings={"WPAD.": "2001:DB8::66"}))
    w.process_packet(IPv6(src="2001:db8::66", dst="ff02::1:3") /
                     UDP(sport=PORT_LLMNR, dport=61000) /
                     DNS(qr=1, qd=DNSQR(qname="wpad"),
                         an=DNSRR(rrname="wpad", type="AAAA", rdata="2001:db8::66")))
    check(none(w, "R1"), "allow-binding suppresses R1 given uppercase v6 + dotted name")

    # a DIFFERENT v6 host must still be flagged -- canonicalisation must not
    # collapse distinct addresses
    w = fresh(Config(allow_smb={"2001:DB8::9"}))
    w.process_packet(IPv6(src="2001:db8::10", dst="2001:db8::30") /
                     TCP(sport=PORT_SMB, dport=50000) / s.Raw(load=unsigned_v6))
    check(has(w, "S2", "2001:db8::10"), "canonicalisation does not over-match")

    # capture filter must cover IPv6 extension headers
    check(BPF_IPV6_EH in build_bpf(True), "default filter widens for IPv6 EH")
    check(BPF_IPV6_EH not in build_bpf(False), "--no-ipv6-eh narrows the filter")
    check(Config().ipv6_eh is True, "IPv6 extension-header capture is on by default")
    for nh in (0, 43, 44, 51, 60, 135):
        check("ip6[6] = %d" % nh in BPF_IPV6_EH,
              "IPv6 next-header %d is captured" % nh)
    check("ip6[6] = 50" not in BPF_IPV6_EH,
          "ESP (50) excluded -- payload is encrypted, nothing to parse")

    # engine parity: the same attack on both families yields the same rule
    neg6 = _build_smb2_negotiate_resp(0x0311, SMB2_SIGNING_ENABLED)
    w4 = fresh(); w4.process_packet(smb_pkt("10.0.0.9", neg6))
    w6 = fresh()
    w6.process_packet(IPv6(src="2001:db8::9", dst="2001:db8::30") /
                      TCP(sport=PORT_SMB, dport=50000) / s.Raw(load=neg6))
    check({f.rule for f in w4.findings} == {f.rule for f in w6.findings},
          "S2 parity across address families")

    # ===================================================================== #
    #  Group V: SMB file-operation tier (F1-F5) -- secretsdump's SMB half
    # ===================================================================== #
    #  rpcwatch sees the hive written over winreg; this tier sees it read back
    #  and deleted over SMB. Every fact below was read out of impacket's
    #  secretsdump.py, not recalled: share is always ADMIN$, the hive copy is
    #  Temp\<8 ascii_letters>.tmp, remote-exec output is the literal
    #  Temp\__output, and -use-vss issues FSCTL_SRV_ENUMERATE_SNAPSHOTS.
    # ------------------------------------------------------------------- #
    TIDF = 0x1001
    CLI, SRVF = "10.0.0.30", "10.0.0.9"

    def fcli(payload, src=CLI, dst=SRVF):
        return IP(src=src, dst=dst) / TCP(sport=50000, dport=PORT_SMB,
                                          flags="PA") / s.Raw(load=payload)

    def fsrv(payload, src=SRVF, dst=CLI):
        return IP(src=src, dst=dst) / TCP(sport=PORT_SMB, dport=50000,
                                          flags="PA") / s.Raw(load=payload)

    def ftree(w, share="ADMIN$"):
        """Establish a tree so the share is known, as a real session does."""
        w.process_packet(fcli(_build_tree_connect_req(share, message_id=1)))
        w.process_packet(fsrv(_build_tree_connect_resp(TIDF, message_id=1)))
        return w

    # ---- parsers round-trip ------------------------------------------- #
    check(SMBWatch.parse_tree_connect_request(
        _build_tree_connect_req("ADMIN$")[4:]) == "\\\\DC01\\ADMIN$",
        "TREE_CONNECT share path parsed")
    check(SMBWatch.smb_share_leaf("\\\\DC01\\ADMIN$") == "admin$",
          "share leaf extracted and lowercased")
    parsed = SMBWatch.parse_create_request(
        _build_create_req("Temp\\ABCDefgh.tmp", TIDF,
                          desired=FILE_READ_DATA)[4:])
    check(parsed is not None and parsed[0] == "Temp\\ABCDefgh.tmp"
          and parsed[1] == FILE_READ_DATA, "CREATE filename and access parsed")
    check(SMBWatch.parse_ioctl_request(
        _build_ioctl_req(FSCTL_SRV_ENUMERATE_SNAPSHOTS, TIDF)[4:])
        == FSCTL_SRV_ENUMERATE_SNAPSHOTS, "IOCTL CtlCode parsed")
    check(SMBWatch.parse_create_request(
        _build_tree_connect_req("ADMIN$")[4:]) is None,
        "CREATE parser rejects a TREE_CONNECT")
    check(SMBWatch.parse_tree_connect_request(
        _build_tree_connect_resp(TIDF)[4:]) is None,
        "TREE_CONNECT parser ignores the response side")

    # ---- framer: must always make progress ----------------------------- #
    for label, raw in (("bogus length + magic at 4",
                        bytearray(b"\x00\x00\x00\x01" + SMB2_MAGIC + b"\x00" * 60)),
                       ("no magic at all", bytearray(b"\xAA" * 200)),
                       ("all zeros", bytearray(b"\x00" * 200)),
                       ("length exceeds buffer",
                        bytearray(b"\x00\x00\xff\xff" + SMB2_MAGIC))):
        before = len(raw)
        got = SMBWatch._smb_frame(raw)
        check(len(raw) < before or not got,
              "framer consumes or returns on %s (no spin)" % label)
    buf = bytearray(_build_create_req("Temp\\ABCDefgh.tmp", TIDF)
                    + _build_ioctl_req(FSCTL_SRV_ENUMERATE_SNAPSHOTS, TIDF))
    check(len(SMBWatch._smb_frame(buf)) == 2,
          "framer drains two messages from one buffer")

    # ---- F1: the credential exfil read-back ----------------------------- #
    w = ftree(fresh())
    w.process_packet(fcli(_build_create_req("Temp\\ABCDefgh.tmp", TIDF,
                                            desired=FILE_READ_DATA, message_id=2)))
    f1 = get(w, "F1", CLI)
    check(f1 is not None and f1.severity == Severity.HIGH,
          "F1 read-only -> HIGH")
    check(f1 is not None and f1.evidence.get("share") == "admin$",
          "F1 resolves the share through TREE_CONNECT")
    # the delete leg is itself a CREATE with DELETE|FILE_DELETE_ON_CLOSE
    w.process_packet(fcli(_build_create_req(
        "Temp\\ABCDefgh.tmp", TIDF, desired=ACCESS_DELETE | 0x80,
        options=0x40 | FILE_DELETE_ON_CLOSE, message_id=3)))
    f1 = get(w, "F1", CLI)
    check(f1 is not None and f1.severity == Severity.CRITICAL,
          "F1 escalates to CRITICAL once the delete lands")
    check(f1 is not None and f1.evidence.get("sequence_complete") == "True",
          "F1 records the completed sequence")
    check(f1 is not None and f1.evidence.get("alias") == "SMB-CREDENTIAL-EXFIL-TEMP",
          "F1 carries the cross-module alias")

    # share never observed -> still reported, one level down and labelled
    w = fresh()
    w.process_packet(fcli(_build_create_req("Temp\\ABCDefgh.tmp", TIDF,
                                            desired=FILE_READ_DATA, message_id=2)))
    f1 = get(w, "F1", CLI)
    check(f1 is not None and f1.severity == Severity.MEDIUM,
          "F1 drops a level when the share was never seen")
    check(f1 is not None and f1.evidence.get("share") == "unknown",
          "F1 labels the unconfirmed share rather than guessing")

    # ---- F1 negatives: the measured discriminators ---------------------- #
    #  GetTempFileName emits <=3-char prefix + 4 HEX digits, so any digit
    #  disqualifies. Measured: 0/6000 realistic Windows temp names match.
    for nm in ("Temp\\tmp1A2B.tmp", "Temp\\MSI4F3C.tmp", "Temp\\Cab1234.tmp",
               "Temp\\ABCDefg.tmp", "Temp\\ABCDefghi.tmp", "Temp\\ABCDef12.tmp",
               "Temp\\ABCDefgh.dat", "Windows\\Temp\\ABCDefgh.tmp"):
        w = ftree(fresh())
        w.process_packet(fcli(_build_create_req(nm, TIDF, message_id=2)))
        check(none(w, "F1"), "F1 silent on %s" % nm)
    w = ftree(fresh(), share="Users")
    w.process_packet(fcli(_build_create_req("Temp\\ABCDefgh.tmp", TIDF,
                                            message_id=2)))
    check(none(w, "F1"), "F1 silent on a non-administrative share")

    # tunable, because the random length is a tool detail not a protocol one
    w = ftree(fresh(Config(temp_exfil_pattern=r"^temp\\[A-Za-z]{6}\.tmp$")))
    w.process_packet(fcli(_build_create_req("Temp\\ABCDef.tmp", TIDF,
                                            message_id=2)))
    check(has(w, "F1", CLI), "F1 honours --temp-exfil-pattern")

    # ---- F2: impacket's remote-execution output file -------------------- #
    w = ftree(fresh())
    w.process_packet(fcli(_build_create_req("Temp\\__output", TIDF, message_id=2)))
    check(has(w, "F2", CLI, Severity.HIGH), "F2 Temp\\__output -> HIGH")
    w = ftree(fresh())
    w.process_packet(fcli(_build_create_req("Temp\\_output", TIDF, message_id=2)))
    check(none(w, "F2"), "F2 is a literal, not a prefix match")

    # ---- F3: shadow-copy enumeration ------------------------------------ #
    w = ftree(fresh())
    w.process_packet(fcli(_build_ioctl_req(FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                                           TIDF, message_id=5)))
    check(has(w, "F3", CLI, Severity.HIGH), "F3 shadow-copy enum -> HIGH")
    w = ftree(fresh(Config(backup_hosts={CLI})))
    w.process_packet(fcli(_build_ioctl_req(FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                                           TIDF, message_id=5)))
    check(has(w, "F3", CLI, Severity.LOW), "F3 LOW for a listed backup host")
    w = ftree(fresh(Config(backup_hosts={"2001:DB8::30"})))
    w.process_packet(IPv6(src="2001:db8::30", dst="2001:db8::9") /
                     TCP(sport=50000, dport=PORT_SMB, flags="PA") /
                     s.Raw(load=_build_ioctl_req(FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                                                 TIDF, message_id=5)))
    check(has(w, "F3", "2001:db8::30", Severity.LOW),
          "F3 backup-host list is canonical for IPv6")
    w = ftree(fresh())
    w.process_packet(fcli(_build_ioctl_req(0x00090000, TIDF, message_id=5)))
    check(none(w, "F3"), "F3 silent on an unrelated FSCTL")

    # ---- F4: credential stores by name ---------------------------------- #
    for nm in ("System32\\config\\SAM", "System32\\config\\SECURITY",
               "System32\\config\\SYSTEM", "NTDS\\ntds.dit",
               "NTDS\\edb00001.log",
               "GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\x"):
        w = ftree(fresh())
        w.process_packet(fcli(_build_create_req(nm, TIDF, message_id=6)))
        check(has(w, "F4", CLI, Severity.CRITICAL), "F4 fires on %s" % nm)
    for nm in ("Temp\\report.docx", "System32\\drivers\\etc\\hosts",
               "Users\\jdoe\\system.ini"):
        w = ftree(fresh())
        w.process_packet(fcli(_build_create_req(nm, TIDF, message_id=6)))
        check(none(w, "F4"), "F4 silent on %s" % nm)

    # ---- rpcwatch boundary: pipes are NOT ours -------------------------- #
    #  rpcwatch already carves DCERPC out of SMB2 on \pipe\* and IPC$.
    #  Double-firing one PDU across two sensors is worse than a gap.
    w = ftree(fresh(), share="IPC$")
    w.process_packet(fcli(_build_create_req("svcctl", TIDF, message_id=2)))
    w.process_packet(fcli(_build_create_req("winreg", TIDF, message_id=3)))
    check(not w.findings, "IPC$ named pipes left entirely to rpcwatch")
    w = ftree(fresh())
    w.process_packet(fcli(_build_create_req("pipe\\winreg", TIDF, message_id=2)))
    check(not w.findings, "\\pipe\\ paths left entirely to rpcwatch")

    # ---- F5: the tier reports when it has gone blind -------------------- #
    w = fresh()
    w.process_packet(fsrv(_build_smb2_transform()))
    f5 = get(w, "F5", SRVF)
    check(f5 is not None and f5.severity == Severity.INFO,
          "F5 reports SMB3 encryption as INFO")
    check(f5 is not None and "F1" in f5.evidence.get("blind_rules", ""),
          "F5 names the rules it has blinded")
    w.process_packet(fsrv(_build_smb2_transform()))
    check(len([x for x in w.findings if x.rule == "F5"]) == 1,
          "F5 fires once per server, not per frame")

    # ---- segmentation: the shape no single-segment parser survives ------ #
    #  An SMB2 CREATE carries its filename at NameOffset, which on a long
    #  path lands beyond the first segment. This is the rpcwatch WinRM bug.
    stream = (_build_create_req("Temp\\ABCDefgh.tmp", TIDF,
                                desired=FILE_READ_DATA, message_id=2)
              + _build_create_req("Temp\\" + ("sub\\" * 20) + "WXYZabcd.tmp",
                                  TIDF, message_id=4)
              + _build_ioctl_req(FSCTL_SRV_ENUMERATE_SNAPSHOTS, TIDF,
                                 message_id=5))
    for mss in (1460, 512, 64, 17, 7, 1):
        w = ftree(fresh())
        for i in range(0, len(stream), mss):
            w.process_packet(fcli(stream[i:i + mss]))
        check(has(w, "F1", CLI) and has(w, "F3", CLI),
              "file tier survives MSS %d" % mss)

    # ---- compounded requests (NextCommand chaining) --------------------- #
    first = _build_create_req("Temp\\ABCDefgh.tmp", TIDF,
                              desired=FILE_READ_DATA, message_id=2,
                              framed=False)
    pad = (-len(first)) % 8
    chained = _smb2_hdr(SMB2_CMD_CREATE, tree_id=TIDF, message_id=2,
                        next_command=len(first) + pad)
    body = first[SMB2_HDR_LEN:] + b"\x00" * pad
    second = _build_ioctl_req(FSCTL_SRV_ENUMERATE_SNAPSHOTS, TIDF,
                              message_id=3, framed=False)
    w = ftree(fresh())
    w.process_packet(fcli(_nbss(chained + body + second)))
    check(has(w, "F1", CLI) and has(w, "F3", CLI),
          "compounded request: both chained commands reached")

    # ---- IPv6 parity (PRIME DIRECTIVE) ---------------------------------- #
    V6C, V6S = "2001:db8::30", "2001:db8::9"

    def f6cli(payload):
        return IPv6(src=V6C, dst=V6S) / TCP(sport=50000, dport=PORT_SMB,
                                            flags="PA") / s.Raw(load=payload)

    def f6srv(payload):
        return IPv6(src=V6S, dst=V6C) / TCP(sport=PORT_SMB, dport=50000,
                                            flags="PA") / s.Raw(load=payload)
    w = fresh()
    w.process_packet(f6cli(_build_tree_connect_req("ADMIN$", message_id=1)))
    w.process_packet(f6srv(_build_tree_connect_resp(TIDF, message_id=1)))
    w.process_packet(f6cli(_build_create_req("Temp\\ABCDefgh.tmp", TIDF,
                                             desired=FILE_READ_DATA, message_id=2)))
    w.process_packet(f6cli(_build_create_req(
        "Temp\\ABCDefgh.tmp", TIDF, desired=ACCESS_DELETE | 0x80,
        options=0x40 | FILE_DELETE_ON_CLOSE, message_id=3)))
    w.process_packet(f6cli(_build_create_req("Temp\\__output", TIDF, message_id=4)))
    w.process_packet(f6cli(_build_ioctl_req(FSCTL_SRV_ENUMERATE_SNAPSHOTS,
                                            TIDF, message_id=5)))
    w.process_packet(f6cli(_build_create_req("System32\\config\\SAM", TIDF,
                                             message_id=6)))
    w.process_packet(f6srv(_build_smb2_transform()))
    for code in ("F1", "F2", "F3", "F4", "F5"):
        check(any(x.rule == code for x in w.findings),
              "%s fires over IPv6" % code)
    check(has(w, "F1", V6C, Severity.CRITICAL),
          "F1 reaches CRITICAL over IPv6 and is attributed to the v6 client")

    # ---- flow isolation -------------------------------------------------- #
    #  A tree id is only meaningful inside its own connection.
    w = fresh()
    w.process_packet(fcli(_build_tree_connect_req("ADMIN$", message_id=1)))
    w.process_packet(fsrv(_build_tree_connect_resp(TIDF, message_id=1)))
    other = IP(src="10.0.0.77", dst=SRVF) / TCP(sport=50001, dport=PORT_SMB,
                                                flags="PA")
    w.process_packet(other / s.Raw(load=_build_create_req(
        "Temp\\ABCDefgh.tmp", TIDF, desired=FILE_READ_DATA, message_id=2)))
    f1 = get(w, "F1", "10.0.0.77")
    check(f1 is not None and f1.evidence.get("share") == "unknown",
          "a tree id does not leak across connections")

    # ------------------------------------------------------------------- #
    #  Build identity: the advertised rule set must match reality, or the
    #  fingerprint stamped into every alert is a lie.
    # ------------------------------------------------------------------- #
    import re as _re
    try:
        with open(__file__, encoding="utf-8") as _fh:
            src_text = _fh.read()
    except Exception:
        src_text = ""
    emitted_rules = set(_re.findall(r'rule="([A-Z]\d+)"', src_text))
    check(bool(emitted_rules), "rule-set integrity check could read the source")
    check(emitted_rules == set(RULE_SET),
          "RULE_SET matches the rules actually emitted (%s)" %
          (", ".join(sorted(emitted_rules ^ set(RULE_SET))) or "in sync"))
    check(RULE_SET_ID.startswith("%d:" % len(RULE_SET)),
          "rule-set fingerprint encodes the rule count")

    # ------------------------------------------------------------------- #
    #  report
    # ------------------------------------------------------------------- #
    total = passed + failed
    print("=" * 66)
    for ok, label in results:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", label))
    print("=" * 66)
    print("smbwatch self-test: %d/%d passed" % (passed, total))
    return 0 if failed == 0 else 1


# =========================================================================== #
#  CLI
# =========================================================================== #

def _parse_kv_list(items: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in items or []:
        if "=" in it:
            k, v = it.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="smbwatch",
        description="Ragnar passive SMB / NTLM-relay attack-surface monitor "
                    "(LLMNR/NBT-NS/mDNS poisoning + SMB posture). Detection-only.",
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("-i", "--iface", help="interface to sniff (SPAN/mirror/tap)")
    src.add_argument("--pcap", help="replay a capture file instead of live sniffing")
    ap.add_argument("--self-test", action="store_true", help="run the self-test harness")
    ap.add_argument("--print-unit", action="store_true",
                    help="print a systemd unit and exit")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON lines")

    ap.add_argument("--window", type=float, default=60.0,
                    help="sliding window seconds for rate heuristics (default 60)")
    ap.add_argument("--name-threshold", type=int, default=3,
                    help="distinct names from one responder to flag (default 3)")
    ap.add_argument("--mdns-threshold", type=int, default=8,
                    help="distinct mDNS host names to flag (default 8)")
    ap.add_argument("--version", action="store_true",
                    help="print module version and rule-set fingerprint, then exit")
    ap.add_argument("--backup-host", action="append", default=[], metavar="IP",
                    help="host legitimately enumerating shadow copies; F3 is "
                         "LOW for it instead of HIGH (repeatable)")
    ap.add_argument("--temp-exfil-pattern", default=SMB_TEMP_EXFIL_DEFAULT,
                    metavar="RE",
                    help="regex for the credential-exfil temp filename (F1). "
                         "Default matches impacket's 8 ASCII letters + .tmp "
                         "under Temp\\; the length is a tool detail, not a "
                         "protocol invariant, so it is tunable")
    ap.add_argument("--no-ipv6-eh", dest="ipv6_eh", action="store_false",
                    default=True,
                    help="do NOT widen the capture filter to IPv6 frames with "
                         "extension headers (default: widen, because libpcap "
                         "cannot port-filter past the IPv6 header chain)")
    ap.add_argument("--krb-err-threshold", type=int, default=10,
                    help="KDC errors from one requester in the window to flag K7 "
                         "(default 10)")
    ap.add_argument("--allow-responder", action="append", metavar="IP",
                    help="responder IP to never flag (repeatable)")
    ap.add_argument("--allow-binding", action="append", metavar="NAME=IP",
                    help="known-good name->ip binding (repeatable)")
    ap.add_argument("--allow-smb", action="append", metavar="IP",
                    help="SMB server IP to never flag for SMBv1/unsigned (repeatable)")

    args = ap.parse_args(argv)

    if args.version:
        print("smbwatch %s" % __version__)
        print("rule-set  %s" % RULE_SET_ID)
        print("rules     %s" % " ".join(RULE_SET))
        return 0

    if args.print_unit:
        iface = args.iface or "eth0"
        print(SYSTEMD_UNIT.format(path="/opt/ragnar/smbwatch.py", iface=iface))
        return 0

    if args.self_test:
        return _run_self_tests()

    cfg = Config(
        window=args.window,
        name_threshold=args.name_threshold,
        mdns_name_threshold=args.mdns_threshold,
        krb_err_threshold=args.krb_err_threshold,
        ipv6_eh=args.ipv6_eh,
        backup_hosts=set(args.backup_host),
        temp_exfil_pattern=args.temp_exfil_pattern,
        allow_responders=set(args.allow_responder or []),
        allow_bindings={k: v for k, v in _parse_kv_list(args.allow_binding).items()},
        allow_smb=set(args.allow_smb or []),
    )

    if args.pcap:
        run_pcap(args.pcap, cfg, args.json)
        return 0
    if args.iface:
        try:
            run_live(args.iface, cfg, args.json)
        except PermissionError:
            print("smbwatch: need CAP_NET_RAW (run with sudo).", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            return 0
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
