#!/usr/bin/env python3
"""
rpcwatch - passive DCERPC / NetLogon / WinRM authentication posture monitor.

Part of the Ragnar passive detection suite.  OSI L5-L7.  Pi Zero 2W floor.

PASSIVE BY DESIGN.  This module contains no transmit primitives.  It observes
MS-RPCE (DCERPC) association setup, NetLogon secure-channel establishment, NTLM
security-provider messages and WinRM/WS-Man HTTP exchanges, and reports on the
authentication posture it can see on the wire.  It never injects, probes,
answers, spoofs or decrypts.

What makes DCERPC tractable passively: the per-PDU security trailer
(auth_type / auth_level) is CLEARTEXT even when the RPC stub is sealed with
PKT_PRIVACY.  So the single most important question -- "is this call integrity
protected?" -- is answerable from the wire regardless of encryption.

Wire formats handled here (all hand-rolled, no dissector libraries):
  * DCERPC connection-oriented PDUs   (ncacn_ip_tcp: 135 + dynamic 49152-65535)
  * DCERPC over SMB2 named pipes      (ncacn_np: tcp/445, carved from
                                       WRITE / READ / IOCTL FSCTL_PIPE_TRANSCEIVE)
  * NDR tail-anchored field extraction for the NetLogon secure-channel opnums
  * NTLMSSP NEGOTIATE / CHALLENGE / AUTHENTICATE messages
  * WinRM: HTTP/1.1 request+response headers on tcp/5985 (cleartext) and
    connection-level observation only on tcp/5986 (TLS, not dissected)

Deliberate non-goals: no credential capture, no hash extraction, no NTLM
cracking, no decryption of sealed stubs, no active endpoint-mapper queries.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import signal
import sys
import time
from collections import deque

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# DCERPC constants -- DCE 1.1 / C706 + [MS-RPCE]
# ---------------------------------------------------------------------------

PTYPE_REQUEST = 0
PTYPE_PING = 1
PTYPE_RESPONSE = 2
PTYPE_FAULT = 3
PTYPE_BIND = 11
PTYPE_BIND_ACK = 12
PTYPE_BIND_NAK = 13
PTYPE_ALTER_CONTEXT = 14
PTYPE_ALTER_CONTEXT_RESP = 15
PTYPE_AUTH3 = 16
PTYPE_SHUTDOWN = 17
PTYPE_CO_CANCEL = 18
PTYPE_ORPHANED = 19

PTYPE_NAMES = {
    PTYPE_REQUEST: "request",
    PTYPE_PING: "ping",
    PTYPE_RESPONSE: "response",
    PTYPE_FAULT: "fault",
    PTYPE_BIND: "bind",
    PTYPE_BIND_ACK: "bind_ack",
    PTYPE_BIND_NAK: "bind_nak",
    PTYPE_ALTER_CONTEXT: "alter_context",
    PTYPE_ALTER_CONTEXT_RESP: "alter_context_resp",
    PTYPE_AUTH3: "auth3",
    PTYPE_SHUTDOWN: "shutdown",
    PTYPE_CO_CANCEL: "co_cancel",
    PTYPE_ORPHANED: "orphaned",
}

# pfc_flags
PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02
PFC_PENDING_CANCEL = 0x04
PFC_CONC_MPX = 0x10
PFC_DID_NOT_EXECUTE = 0x20
PFC_MAYBE = 0x40
PFC_OBJECT_UUID = 0x80

# Authentication service identifiers -- [MS-RPCE] 2.2.1.1.7
RPC_C_AUTHN_NONE = 0x00
RPC_C_AUTHN_DCE_PRIVATE = 0x01
RPC_C_AUTHN_DCE_PUBLIC = 0x02
RPC_C_AUTHN_DEC_PUBLIC = 0x04
RPC_C_AUTHN_GSS_NEGOTIATE = 0x09  # SPNEGO
RPC_C_AUTHN_WINNT = 0x0A          # NTLM
RPC_C_AUTHN_GSS_SCHANNEL = 0x0E   # TLS
RPC_C_AUTHN_GSS_KERBEROS = 0x10
RPC_C_AUTHN_NETLOGON = 0x44
RPC_C_AUTHN_DEFAULT = 0xFF

AUTHN_NAMES = {
    RPC_C_AUTHN_NONE: "none",
    RPC_C_AUTHN_DCE_PRIVATE: "dce-private",
    RPC_C_AUTHN_DCE_PUBLIC: "dce-public",
    RPC_C_AUTHN_DEC_PUBLIC: "dec-public",
    RPC_C_AUTHN_GSS_NEGOTIATE: "spnego",
    RPC_C_AUTHN_WINNT: "ntlm",
    RPC_C_AUTHN_GSS_SCHANNEL: "schannel",
    RPC_C_AUTHN_GSS_KERBEROS: "kerberos",
    RPC_C_AUTHN_NETLOGON: "netlogon",
    RPC_C_AUTHN_DEFAULT: "default",
}

# Authentication levels -- [MS-RPCE] 2.2.1.1.8
RPC_C_AUTHN_LEVEL_DEFAULT = 0
RPC_C_AUTHN_LEVEL_NONE = 1
RPC_C_AUTHN_LEVEL_CONNECT = 2
RPC_C_AUTHN_LEVEL_CALL = 3
RPC_C_AUTHN_LEVEL_PKT = 4
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6

AUTHN_LEVEL_NAMES = {
    RPC_C_AUTHN_LEVEL_DEFAULT: "default",
    RPC_C_AUTHN_LEVEL_NONE: "none",
    RPC_C_AUTHN_LEVEL_CONNECT: "connect",
    RPC_C_AUTHN_LEVEL_CALL: "call",
    RPC_C_AUTHN_LEVEL_PKT: "pkt",
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: "pkt-integrity",
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY: "pkt-privacy",
}

# bind_nak reject reasons -- C706 12.6.4.5
NAK_REASONS = {
    0: "reason-not-specified",
    1: "temporary-congestion",
    2: "local-limit-exceeded",
    3: "called-paddr-unknown",
    4: "protocol-version-not-supported",
    5: "default-context-not-supported",
    6: "user-data-not-readable",
    7: "no-psap-available",
    8: "auth-type-not-recognized",
    9: "invalid-checksum",
}

# ---------------------------------------------------------------------------
# Interface UUIDs.  Keys are canonical lowercase dashed form.
# class: what kind of exposure a bind to this interface represents.
# ---------------------------------------------------------------------------

IF_NETLOGON = "12345678-1234-abcd-ef00-01234567cffb"
IF_LSARPC = "12345778-1234-abcd-ef00-0123456789ab"
IF_SAMR = "12345778-1234-abcd-ef00-0123456789ac"
IF_DRSUAPI = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
# MS-EFSR 1.9 binds one UUID per pipe.  Keep them straight: PetitPotam and
# friends reach EFSRPC through \pipe\lsarpc, so IF_EFSR_LSA is the entry that
# fires in practice.
IF_EFSR_LSA = "c681d488-d850-11d0-8c52-00c04fd90f7e"   # \pipe\lsarpc
IF_EFSR_EFS = "df1941c5-fe89-4e79-bf10-463657acf44d"   # \pipe\efsrpc
IF_RPRN = "12345678-1234-abcd-ef00-0123456789ab"
IF_PAR = "76f03f96-cdfd-44fc-a22c-64950a001209"
IF_DFSNM = "4fc742e0-4a10-11cf-8273-00aa004ae673"
IF_FSRVP = "a8e0653c-2744-4389-a61d-7373df8b2292"
IF_EVEN = "82273fdc-e32a-18c3-3f78-827929dc23ea"
IF_SVCCTL = "367abb81-9844-35f1-ad32-98f038001003"
IF_ATSVC = "1ff70682-0a51-30e8-076d-740be8cee98b"
IF_ITASKSCHED = "86d35949-83c9-4044-b424-db363231fd0c"
IF_WINREG = "338cd001-2244-31f1-aaaa-900038001003"
IF_BKRP = "3dde7c30-165d-11d1-ab8f-00805f14db40"
IF_EPM = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
IF_ISYSTEMACTIVATOR = "000001a0-0000-0000-c000-000000000046"
IF_SRVSVC = "4b324fc8-1670-01d3-1278-5a47bf6ee188"
IF_WKSSVC = "6bffd098-a112-3610-9833-46c3f87e345a"

INTERFACES = {
    IF_NETLOGON: ("netlogon", "netlogon", "MS-NRPC Netlogon Remote Protocol"),
    IF_LSARPC: ("lsarpc", "directory", "MS-LSAD/LSAT Local Security Authority"),
    IF_SAMR: ("samr", "directory", "MS-SAMR Security Account Manager"),
    IF_DRSUAPI: ("drsuapi", "directory", "MS-DRSR Directory Replication"),
    IF_EFSR_LSA: ("efsrpc-lsa", "coercion", "MS-EFSR over \\pipe\\lsarpc"),
    IF_EFSR_EFS: ("efsrpc", "coercion", "MS-EFSR over \\pipe\\efsrpc"),
    IF_RPRN: ("spoolss", "coercion", "MS-RPRN Print System Remote"),
    IF_PAR: ("iremotewinspool", "coercion", "MS-PAR Print System Asynchronous"),
    IF_DFSNM: ("netdfs", "coercion", "MS-DFSNM DFS Namespace Management"),
    IF_FSRVP: ("fssagentrpc", "coercion", "MS-FSRVP File Server VSS Agent"),
    IF_EVEN: ("eventlog", "coercion", "MS-EVEN EventLog Remoting"),
    IF_SVCCTL: ("svcctl", "exec", "MS-SCMR Service Control Manager Remote"),
    IF_ATSVC: ("atsvc", "exec", "MS-TSCH Task Scheduler (ATSvc)"),
    IF_ITASKSCHED: ("itaskschedulerservice", "exec", "MS-TSCH Task Scheduler Service"),
    IF_WINREG: ("winreg", "exec", "MS-RRP Remote Registry"),
    IF_BKRP: ("backupkey", "directory", "MS-BKRP BackupKey Remote (DPAPI)"),
    IF_EPM: ("epmapper", "epm", "DCE Endpoint Mapper"),
    IF_ISYSTEMACTIVATOR: ("isystemactivator", "exec", "MS-DCOM ISystemActivator"),
    IF_SRVSVC: ("srvsvc", "other", "MS-SRVS Server Service Remote"),
    IF_WKSSVC: ("wkssvc", "other", "MS-WKST Workstation Service Remote"),
}

# Transfer syntaxes
XFER_NDR32 = "8a885d04-1ceb-11c9-9fe8-08002b104860"
XFER_NDR64 = "71710533-beba-4937-8319-b5dbef9ccc36"
XFER_BIND_TIME_FEATURE_PREFIX = "6cb71c2c-9812-4540"  # negotiation pseudo-syntax

# ---------------------------------------------------------------------------
# [MS-NRPC] opnums and negotiate flags
# ---------------------------------------------------------------------------

NRPC_SERVER_REQ_CHALLENGE = 4
NRPC_SERVER_AUTHENTICATE = 5
NRPC_SERVER_PASSWORD_SET = 6
NRPC_SERVER_AUTHENTICATE2 = 15
NRPC_SERVER_AUTHENTICATE3 = 26
NRPC_LOGON_GET_DOMAIN_INFO = 29
NRPC_SERVER_PASSWORD_SET2 = 30
NRPC_SERVER_PASSWORD_GET = 31
NRPC_SERVER_TRUST_PASSWORDS_GET = 42
NRPC_LOGON_SAM_LOGON_EX = 39
NRPC_LOGON_SAM_LOGON_WITH_FLAGS = 45

NRPC_OPNAMES = {
    NRPC_SERVER_REQ_CHALLENGE: "NetrServerReqChallenge",
    NRPC_SERVER_AUTHENTICATE: "NetrServerAuthenticate",
    NRPC_SERVER_PASSWORD_SET: "NetrServerPasswordSet",
    NRPC_SERVER_AUTHENTICATE2: "NetrServerAuthenticate2",
    NRPC_SERVER_AUTHENTICATE3: "NetrServerAuthenticate3",
    NRPC_LOGON_GET_DOMAIN_INFO: "NetrLogonGetDomainInfo",
    NRPC_SERVER_PASSWORD_SET2: "NetrServerPasswordSet2",
    NRPC_SERVER_PASSWORD_GET: "NetrServerPasswordGet",
    NRPC_SERVER_TRUST_PASSWORDS_GET: "NetrServerTrustPasswordsGet",
    NRPC_LOGON_SAM_LOGON_EX: "NetrLogonSamLogonEx",
    NRPC_LOGON_SAM_LOGON_WITH_FLAGS: "NetrLogonSamLogonWithFlags",
}

NRPC_AUTH_OPNUMS = (
    NRPC_SERVER_AUTHENTICATE,
    NRPC_SERVER_AUTHENTICATE2,
    NRPC_SERVER_AUTHENTICATE3,
)

# Netlogon Negotiable Options -- [MS-NRPC] 3.1.4.2
NETLOGON_NEG_STRONG_KEY = 0x00004000       # 128-bit MD5 session key
NETLOGON_NEG_SUPPORTS_AES = 0x01000000     # AES-CFB8 + SHA2 (Zerologon precondition)
NETLOGON_NEG_AUTHENTICATED_RPC = 0x40000000  # "Supports Secure RPC" -- sign/seal

# The canonical Zerologon tester value: a Win10 client's flags with sign/seal off.
ZEROLOGON_TESTER_FLAGS = 0x212FFFFF

# NETLOGON_SECURE_CHANNEL_TYPE -- [MS-NRPC] 2.2.1.3.13
SECURE_CHANNEL_TYPES = {
    0: "NullSecureChannel",
    1: "MsvApSecureChannel",
    2: "WorkstationSecureChannel",
    3: "TrustedDnsDomainSecureChannel",
    4: "TrustedDomainSecureChannel",
    5: "UasServerSecureChannel",
    6: "ServerSecureChannel",
    7: "CdcServerSecureChannel",
}

# ---------------------------------------------------------------------------
# Coercion opnums -- calls that make a server authenticate to an arbitrary UNC
# ---------------------------------------------------------------------------

COERCION_CALLS = {
    IF_EFSR_LSA: {
        0: "EfsRpcOpenFileRaw",
        4: "EfsRpcEncryptFileSrv",
        5: "EfsRpcDecryptFileSrv",
        6: "EfsRpcQueryUsersOnFile",
        7: "EfsRpcQueryRecoveryAgents",
        12: "EfsRpcFileKeyInfo",
        13: "EfsRpcDuplicateEncryptionInfoFile",
        15: "EfsRpcAddUsersToFileEx",
    },
    IF_EFSR_EFS: {
        0: "EfsRpcOpenFileRaw",
        4: "EfsRpcEncryptFileSrv",
        5: "EfsRpcDecryptFileSrv",
        6: "EfsRpcQueryUsersOnFile",
        7: "EfsRpcQueryRecoveryAgents",
        12: "EfsRpcFileKeyInfo",
        13: "EfsRpcDuplicateEncryptionInfoFile",
    },
    IF_DFSNM: {
        12: "NetrDfsAddStdRoot",
        13: "NetrDfsRemoveStdRoot",
    },
    IF_FSRVP: {
        8: "IsPathSupported",
        9: "IsPathShadowCopied",
    },
    IF_RPRN: {
        65: "RpcRemoteFindFirstPrinterChangeNotificationEx",
    },
    IF_PAR: {
        14: "RpcAsyncOpenPrinter",
    },
    IF_EVEN: {
        9: "ElfrOpenBELW",
    },
}

# Opnums that are lateral-movement primitives rather than coercion.
EXEC_CALLS = {
    IF_SVCCTL: {
        12: "RCreateServiceW",
        19: "RStartServiceW",
        24: "RCreateServiceA",
        31: "RChangeServiceConfigW",
        44: "RCreateServiceWOW64W",
    },
    IF_ATSVC: {
        0: "NetrJobAdd",
    },
    IF_ITASKSCHED: {
        1: "SchRpcRegisterTask",
        3: "SchRpcRun",
    },
    IF_DRSUAPI: {
        0: "DRSBind",
        3: "DRSGetNCChanges",
    },
    IF_WINREG: {
        2: "OpenHKLM",
        6: "BaseRegCreateKey",
        22: "BaseRegSetValue",
    },
    IF_BKRP: {
        0: "BackuprKey",
    },
}

EPM_LOOKUP_OPNUMS = (2, 3)  # ept_lookup, ept_map

# ---------------------------------------------------------------------------
# NTLMSSP -- [MS-NLMP]
# ---------------------------------------------------------------------------

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
NTLM_NEGOTIATE = 1
NTLM_CHALLENGE = 2
NTLM_AUTHENTICATE = 3

NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_NEGOTIATE_OEM = 0x00000002
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_NEGOTIATE_SEAL = 0x00000020
NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_NEGOTIATE_ANONYMOUS = 0x00000800
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
NTLMSSP_NEGOTIATE_56 = 0x80000000

# AV_PAIR identifiers -- [MS-NLMP] 2.2.2.1
MSV_AV_EOL = 0x0000
MSV_AV_FLAGS = 0x0006
MSV_AV_TIMESTAMP = 0x0007
MSV_AV_CHANNEL_BINDINGS = 0x000A
MSV_AV_TARGET_NAME = 0x0009
MSV_AV_FLAGS_MIC = 0x00000002

# ---------------------------------------------------------------------------
# WinRM / WS-Man
# ---------------------------------------------------------------------------

WINRM_HTTP_PORT = 5985
WINRM_HTTPS_PORT = 5986
EPMAPPER_PORT = 135
SMB_PORT = 445
NBT_SESSION_PORT = 139

WSMAN_ENCRYPTED_TYPES = (
    "multipart/encrypted",
    "multipart/x-multi-encrypted",
    "application/http-spnego-session-encrypted",
    "application/http-kerberos-session-encrypted",
    "application/http-ntlm-session-encrypted",
)

# ---------------------------------------------------------------------------
# Findings catalogue
# ---------------------------------------------------------------------------

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

FINDINGS = {
    # --- netlogon / Zerologon family -------------------------------------
    "RPC-ZEROLOGON-ZERO-CHALLENGE": (
        "critical", "netlogon",
        "NetrServerReqChallenge carrying an all-zero ClientChallenge"),
    "RPC-ZEROLOGON-ZERO-CREDENTIAL": (
        "critical", "netlogon",
        "NetrServerAuthenticate* carrying an all-zero ClientCredential"),
    "RPC-ZEROLOGON-BRUTE-FORCE": (
        "critical", "netlogon",
        "Repeated NetLogon authenticate attempts from one client (CVE-2020-1472 loop)"),
    "RPC-NETLOGON-NO-SECURE-RPC": (
        "high", "netlogon",
        "NetLogon NegotiateFlags with Secure RPC (sign/seal) bit cleared"),
    "RPC-NETLOGON-UNSIGNED-BIND": (
        "critical", "netlogon",
        "NetLogon interface bound without packet integrity protection"),
    "RPC-NETLOGON-PASSWORD-SET": (
        "high", "netlogon",
        "NetrServerPasswordSet2 observed - machine account password change"),
    "RPC-NETLOGON-PASSWORD-RESET-AFTER-BRUTE": (
        "critical", "netlogon",
        "Machine account password set by a client that just brute-forced NetLogon"),
    "RPC-NETLOGON-PASSWORD-GET": (
        "high", "netlogon",
        "NetrServerPasswordGet / NetrServerTrustPasswordsGet - credential retrieval"),
    "RPC-NETLOGON-UNEXPECTED-SERVER": (
        "high", "netlogon",
        "NetLogon secure channel to a host outside the configured DC set"),
    "RPC-NETLOGON-WEAK-CRYPTO": (
        "medium", "netlogon",
        "NetLogon negotiated without AES support (falls back to DES/MD5)"),

    # --- DCERPC auth posture ---------------------------------------------
    "RPC-BIND-NO-AUTH": (
        "high", "auth",
        "Bind to a security-sensitive interface with no authentication trailer"),
    "RPC-NO-PACKET-INTEGRITY": (
        "high", "auth",
        "Association running below RPC_C_AUTHN_LEVEL_PKT_INTEGRITY"),
    "RPC-AUTH-DOWNGRADE": (
        "high", "auth",
        "alter_context or rebind lowering the negotiated authentication level"),
    "RPC-NTLM-OVER-SPNEGO": (
        "medium", "auth",
        "SPNEGO association resolved to NTLM rather than Kerberos"),
    "RPC-NTLMV1-IN-USE": (
        "high", "auth",
        "NTLMv1 response (24-byte NtChallengeResponse) accepted on the wire"),
    "RPC-NTLM-NO-EXTENDED-SESSION-SECURITY": (
        "high", "auth",
        "NTLM negotiated without extended session security (NTLM2)"),
    "RPC-NTLM-NO-SIGNING": (
        "high", "auth",
        "NTLM negotiated without SIGN/SEAL - session is relayable"),
    "RPC-NTLM-NO-MIC": (
        "medium", "auth",
        "NTLM AUTHENTICATE without a MIC - relay-protection absent"),
    "RPC-NTLM-ANONYMOUS": (
        "high", "auth",
        "Anonymous / null NTLM authentication to an RPC interface"),
    "RPC-NTLM-LM-KEY": (
        "high", "auth",
        "NTLM negotiated the LAN Manager session key"),

    # --- interface exposure ----------------------------------------------
    "RPC-COERCION-INTERFACE-BIND": (
        "medium", "interface",
        "Bind to a known authentication-coercion interface"),
    "RPC-COERCION-CALL": (
        "critical", "interface",
        "Coercion opnum invoked with a remote UNC listener path"),
    "RPC-DCSYNC-CALL": (
        "critical", "interface",
        "DRSUAPI DRSGetNCChanges - directory replication (DCSync) request"),
    "RPC-REMOTE-EXEC-INTERFACE": (
        "high", "interface",
        "Remote service / scheduled-task / registry execution primitive invoked"),
    "RPC-BACKUPKEY-ACCESS": (
        "high", "interface",
        "MS-BKRP BackuprKey - DPAPI domain backup key access"),
    "RPC-EPM-SWEEP": (
        "medium", "interface",
        "Endpoint mapper lookups at a rate consistent with RPC interface enumeration"),

    # --- protocol anomalies ----------------------------------------------
    "RPC-BIND-NAK": (
        "low", "protocol",
        "Bind rejected by the server"),
    "RPC-FRAG-ANOMALY": (
        "medium", "protocol",
        "Malformed or inconsistent DCERPC fragment length"),
    "RPC-LEGACY-VERSION": (
        "medium", "protocol",
        "DCERPC major version other than 5 on a connection-oriented port"),

    # --- WinRM ------------------------------------------------------------
    "WINRM-CLEARTEXT-HTTP": (
        "high", "winrm",
        "WS-Man traffic on tcp/5985 without transport encryption"),
    "WINRM-BASIC-AUTH": (
        "critical", "winrm",
        "HTTP Basic authentication to WinRM over cleartext"),
    "WINRM-UNENCRYPTED-PAYLOAD": (
        "critical", "winrm",
        "WS-Man SOAP body readable in the clear (AllowUnencrypted)"),
    "WINRM-AUTH-DOWNGRADE": (
        "high", "winrm",
        "WinRM client selected a weaker scheme than the server offered"),
    "WINRM-CREDSSP": (
        "medium", "winrm",
        "CredSSP authentication - credentials delegated to the remote host"),
    "WINRM-SHELL-CREATE": (
        "medium", "winrm",
        "WS-Man Shell Create - remote command execution session opened"),
}

CATEGORIES = sorted({v[1] for v in FINDINGS.values()})


# ---------------------------------------------------------------------------
# Byte helpers.  Every accessor is bounds-checked: a hostile PDU must not be
# able to raise anything other than RPCError out of the parser layer.
# ---------------------------------------------------------------------------


class RPCError(Exception):
    """Raised on any malformed or unparseable input."""


def _need(buf: bytes, off: int, n: int) -> None:
    if off < 0 or n < 0 or off + n > len(buf):
        raise RPCError(f"short read: need {n} at {off}, have {len(buf)}")


def u8(buf: bytes, off: int) -> int:
    _need(buf, off, 1)
    return buf[off]


def u16(buf: bytes, off: int, big: bool = False) -> int:
    _need(buf, off, 2)
    return int.from_bytes(buf[off:off + 2], "big" if big else "little")


def u32(buf: bytes, off: int, big: bool = False) -> int:
    _need(buf, off, 4)
    return int.from_bytes(buf[off:off + 4], "big" if big else "little")


def uuid_from_wire(buf: bytes, off: int, big: bool = False) -> str:
    """DCE UUID: first three fields honour the PDU's byte order, last 8 raw."""
    _need(buf, off, 16)
    d1 = u32(buf, off, big)
    d2 = u16(buf, off + 4, big)
    d3 = u16(buf, off + 6, big)
    rest = buf[off + 8:off + 16]
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, rest[0:2].hex(), rest[2:8].hex())


def utf16le(buf: bytes, off: int, nbytes: int) -> str:
    _need(buf, off, nbytes)
    try:
        return buf[off:off + nbytes].decode("utf-16-le", "replace").rstrip("\x00")
    except Exception:
        return ""


def is_all_zero(b: bytes) -> bool:
    return len(b) > 0 and not any(b)


# ---------------------------------------------------------------------------
# DCERPC connection-oriented PDU parsing
# ---------------------------------------------------------------------------

CO_HEADER_LEN = 16
SEC_TRAILER_LEN = 8
MAX_FRAG = 65535


def parse_co_header(data: bytes) -> dict:
    """Parse the 16-byte connection-oriented common header."""
    _need(data, 0, CO_HEADER_LEN)
    vers = data[0]
    vers_minor = data[1]
    ptype = data[2]
    pfc = data[3]
    drep0 = data[4]
    big = (drep0 >> 4) == 0
    frag_len = u16(data, 8, big)
    auth_len = u16(data, 10, big)
    call_id = u32(data, 12, big)
    if frag_len < CO_HEADER_LEN or frag_len > MAX_FRAG:
        raise RPCError(f"implausible frag_length {frag_len}")
    if auth_len and auth_len + SEC_TRAILER_LEN + CO_HEADER_LEN > frag_len:
        raise RPCError(f"auth_length {auth_len} does not fit frag_length {frag_len}")
    return {
        "rpc_vers": vers,
        "rpc_vers_minor": vers_minor,
        "ptype": ptype,
        "ptype_name": PTYPE_NAMES.get(ptype, f"unknown({ptype})"),
        "pfc_flags": pfc,
        "big_endian": big,
        "drep": data[4:8].hex(),
        "frag_length": frag_len,
        "auth_length": auth_len,
        "call_id": call_id,
    }


def peek_frag_length(data: bytes) -> int | None:
    """Return frag_length if a full common header is buffered, else None."""
    if len(data) < CO_HEADER_LEN:
        return None
    big = (data[4] >> 4) == 0
    n = int.from_bytes(data[8:10], "big" if big else "little")
    if n < CO_HEADER_LEN or n > MAX_FRAG:
        raise RPCError(f"implausible frag_length {n}")
    return n


def looks_like_dcerpc(data: bytes) -> bool:
    if len(data) < CO_HEADER_LEN:
        return False
    if data[0] != 5 or data[1] > 1:
        return False
    if data[2] not in PTYPE_NAMES:
        return False
    return True


def parse_sec_trailer(pdu: bytes, hdr: dict) -> dict | None:
    """
    The security trailer sits at the tail of the PDU, immediately before the
    auth_value.  It is CLEARTEXT at every auth_level including PKT_PRIVACY,
    which is what makes the auth posture passively observable.
    """
    auth_len = hdr["auth_length"]
    if auth_len == 0:
        return None
    frag = hdr["frag_length"]
    off = frag - auth_len - SEC_TRAILER_LEN
    if off < CO_HEADER_LEN:
        raise RPCError("sec_trailer offset inside common header")
    _need(pdu, off, SEC_TRAILER_LEN)
    auth_type = pdu[off]
    auth_level = pdu[off + 1]
    pad_len = pdu[off + 2]
    ctx_id = u32(pdu, off + 4, hdr["big_endian"])
    value = pdu[off + SEC_TRAILER_LEN:off + SEC_TRAILER_LEN + auth_len]
    return {
        "auth_type": auth_type,
        "auth_type_name": AUTHN_NAMES.get(auth_type, f"unknown({auth_type})"),
        "auth_level": auth_level,
        "auth_level_name": AUTHN_LEVEL_NAMES.get(auth_level, f"unknown({auth_level})"),
        "auth_pad_length": pad_len,
        "auth_context_id": ctx_id,
        "auth_value": value,
        "trailer_offset": off,
    }


def _body_end(hdr: dict) -> int:
    """Offset at which the PDU body stops and the auth padding/trailer begins."""
    if hdr["auth_length"] == 0:
        return hdr["frag_length"]
    return hdr["frag_length"] - hdr["auth_length"] - SEC_TRAILER_LEN


def parse_bind(pdu: bytes, hdr: dict) -> dict:
    """bind / alter_context share a body layout."""
    big = hdr["big_endian"]
    end = _body_end(hdr)
    off = CO_HEADER_LEN
    max_xmit = u16(pdu, off, big)
    max_recv = u16(pdu, off + 2, big)
    assoc_group = u32(pdu, off + 4, big)
    off += 8
    n_ctx = u8(pdu, off)
    off += 4  # n_context_elem(1) + reserved(1) + reserved2(2)
    contexts = []
    for _ in range(min(n_ctx, 64)):
        if off + 24 > end:
            break
        cont_id = u16(pdu, off, big)
        n_xfer = u8(pdu, off + 2)
        off += 4
        if_uuid = uuid_from_wire(pdu, off, big)
        if_ver = u32(pdu, off + 16, big)
        off += 20
        xfers = []
        for _ in range(min(n_xfer, 8)):
            if off + 20 > end:
                break
            xfers.append((uuid_from_wire(pdu, off, big), u32(pdu, off + 16, big)))
            off += 20
        contexts.append({
            "context_id": cont_id,
            "interface": if_uuid,
            "if_version": "%d.%d" % (if_ver & 0xFFFF, if_ver >> 16),
            "transfer_syntaxes": xfers,
        })
    return {
        "max_xmit_frag": max_xmit,
        "max_recv_frag": max_recv,
        "assoc_group_id": assoc_group,
        "n_context_elem": n_ctx,
        "contexts": contexts,
    }


def parse_bind_ack(pdu: bytes, hdr: dict) -> dict:
    big = hdr["big_endian"]
    end = _body_end(hdr)
    off = CO_HEADER_LEN + 8
    sec_addr_len = u16(pdu, off, big)
    off += 2
    sec_addr = ""
    if sec_addr_len:
        _need(pdu, off, sec_addr_len)
        sec_addr = pdu[off:off + sec_addr_len].decode("ascii", "replace").rstrip("\x00")
        off += sec_addr_len
    off = (off + 3) & ~3  # 4-byte alignment before the result list
    results = []
    try:
        n_res = u8(pdu, off)
        off += 4
        for _ in range(min(n_res, 64)):
            if off + 24 > end:
                break
            results.append({
                "result": u16(pdu, off, big),
                "reason": u16(pdu, off + 2, big),
                "transfer_syntax": uuid_from_wire(pdu, off + 4, big),
            })
            off += 24
    except RPCError:
        pass
    return {"sec_addr": sec_addr, "results": results}


def parse_bind_nak(pdu: bytes, hdr: dict) -> dict:
    big = hdr["big_endian"]
    reason = u16(pdu, CO_HEADER_LEN, big)
    return {
        "reject_reason": reason,
        "reject_reason_name": NAK_REASONS.get(reason, f"unknown({reason})"),
    }


def parse_request(pdu: bytes, hdr: dict) -> dict:
    big = hdr["big_endian"]
    off = CO_HEADER_LEN
    alloc_hint = u32(pdu, off, big)
    cont_id = u16(pdu, off + 4, big)
    opnum = u16(pdu, off + 6, big)
    off += 8
    obj_uuid = None
    if hdr["pfc_flags"] & PFC_OBJECT_UUID:
        obj_uuid = uuid_from_wire(pdu, off, big)
        off += 16
    end = _body_end(hdr)
    # auth_pad_length is padding inside the body, not part of the stub.
    return {
        "alloc_hint": alloc_hint,
        "context_id": cont_id,
        "opnum": opnum,
        "object_uuid": obj_uuid,
        "stub_offset": off,
        "stub_end": end,
    }


def parse_response(pdu: bytes, hdr: dict) -> dict:
    big = hdr["big_endian"]
    off = CO_HEADER_LEN
    return {
        "alloc_hint": u32(pdu, off, big),
        "context_id": u16(pdu, off + 4, big),
        "cancel_count": u8(pdu, off + 6),
        "stub_offset": off + 8,
        "stub_end": _body_end(hdr),
    }


def parse_fault(pdu: bytes, hdr: dict) -> dict:
    big = hdr["big_endian"]
    off = CO_HEADER_LEN
    out = {
        "alloc_hint": u32(pdu, off, big),
        "context_id": u16(pdu, off + 4, big),
        "cancel_count": u8(pdu, off + 6),
        "status": 0,
    }
    try:
        out["status"] = u32(pdu, off + 8, big)
    except RPCError:
        pass
    return out


def extract_stub(pdu: bytes, hdr: dict, body: dict, trailer: dict | None) -> bytes:
    """Stub bytes with auth padding removed."""
    start = body["stub_offset"]
    end = body["stub_end"]
    if trailer:
        end -= trailer["auth_pad_length"]
    if end < start or end > len(pdu):
        end = min(len(pdu), max(start, body["stub_end"]))
    return pdu[start:end]


# ---------------------------------------------------------------------------
# NDR field extraction for the NetLogon secure-channel opnums.
#
# Full NDR unmarshalling would require modelling conformant varying strings,
# unique-pointer referent IDs and alignment for every parameter.  We do not
# need that.  For these specific calls every variable-length parameter comes
# FIRST and every fixed-size parameter comes LAST, so the security-relevant
# fields are at a known negative offset from the end of the stub.  This is the
# same anchor the published Snort/Zeek rules for CVE-2020-1472 use, and it is
# immune to name-length variation.
#
# NetrServerReqChallenge(PrimaryName, ComputerName, ClientChallenge[8])
#     -> request stub tail: ClientChallenge (8)
# NetrServerAuthenticate(PrimaryName, AccountName, SecureChannelType,
#                        ComputerName, ClientCredential[8])
#     -> request stub tail: ClientCredential (8)
# NetrServerAuthenticate2/3(..., ClientCredential[8], NegotiateFlags[4])
#     -> request stub tail: ClientCredential (8) + NegotiateFlags (4)
# ---------------------------------------------------------------------------


def _ndr_align(off: int, n: int) -> int:
    return (off + n - 1) & ~(n - 1)


def _ndr_skip_cvstring(stub: bytes, off: int) -> int:
    """Skip a conformant varying wide string: MaxCount/Offset/ActualCount + chars."""
    off = _ndr_align(off, 4)
    if off + 12 > len(stub):
        raise RPCError("cvstring header past end of stub")
    actual = int.from_bytes(stub[off + 8:off + 12], "little")
    if actual > 4096:
        raise RPCError(f"implausible cvstring length {actual}")
    off += 12 + actual * 2
    if off > len(stub):
        raise RPCError("cvstring body past end of stub")
    return off


def _ndr_skip_unique_string(stub: bytes, off: int) -> int:
    """A [unique, string] pointer: 4-byte referent id, then the string if non-null."""
    off = _ndr_align(off, 4)
    if off + 4 > len(stub):
        raise RPCError("unique pointer past end of stub")
    referent = int.from_bytes(stub[off:off + 4], "little")
    off += 4
    if referent == 0:
        return off
    return _ndr_skip_cvstring(stub, off)


def netlogon_req_challenge_fields(stub: bytes) -> dict | None:
    """
    NetrServerReqChallenge(PrimaryName [unique,string], ComputerName [string],
                           ClientChallenge [8]).

    ClientChallenge is 1-byte aligned and last, so the tail is exact.  We still
    walk forward first and only fall back to the tail if the walk fails, so a
    surprising layout downgrades confidence instead of producing a wrong answer.
    """
    if len(stub) < 8:
        return None
    try:
        off = _ndr_skip_unique_string(stub, 0)
        off = _ndr_skip_cvstring(stub, off)
        if off + 8 == len(stub):
            return {"client_challenge": stub[off:off + 8], "field_confidence": "exact"}
    except RPCError:
        pass
    return {"client_challenge": stub[-8:], "field_confidence": "tail-anchored"}


def netlogon_authenticate_fields(stub: bytes, opnum: int) -> dict | None:
    """
    NetrServerAuthenticate2/3(PrimaryName [unique,string], AccountName [string],
                              SecureChannelType [enum16], ComputerName [string],
                              ClientCredential [8], NegotiateFlags [ulong]).

    NegotiateFlags is a ULONG and must start on a 4-byte boundary, so NDR
    inserts 0-3 bytes of padding AFTER the 8-byte credential whenever the
    preceding strings leave the stream unaligned.  The padding bytes are
    unspecified - impacket emits 0xbf, Windows emits whatever - so the
    credential is NOT at a fixed negative offset.  A forward walk is the only
    correct way to locate it.  The tail anchor survives as a fallback and is
    labelled as such in the finding.

    NetrServerAuthenticate (opnum 5) has no NegotiateFlags, so its credential
    is the final field and the tail is exact.
    """
    if opnum == NRPC_SERVER_AUTHENTICATE:
        if len(stub) < 8:
            return None
        try:
            off = _ndr_skip_unique_string(stub, 0)
            off = _ndr_skip_cvstring(stub, off)
            off = _ndr_align(off, 2) + 2
            off = _ndr_skip_cvstring(stub, off)
            if off + 8 == len(stub):
                return {"client_credential": stub[off:off + 8],
                        "negotiate_flags": None, "field_confidence": "exact"}
        except RPCError:
            pass
        return {"client_credential": stub[-8:], "negotiate_flags": None,
                "field_confidence": "tail-anchored"}

    if opnum not in (NRPC_SERVER_AUTHENTICATE2, NRPC_SERVER_AUTHENTICATE3):
        return None
    if len(stub) < 12:
        return None
    try:
        off = _ndr_skip_unique_string(stub, 0)
        off = _ndr_skip_cvstring(stub, off)
        off = _ndr_align(off, 2) + 2          # SecureChannelType
        off = _ndr_skip_cvstring(stub, off)
        cred_off = off
        flags_off = _ndr_align(cred_off + 8, 4)
        if flags_off + 4 == len(stub):
            return {
                "client_credential": stub[cred_off:cred_off + 8],
                "negotiate_flags": int.from_bytes(stub[flags_off:flags_off + 4],
                                                  "little"),
                "pad_bytes": flags_off - (cred_off + 8),
                "field_confidence": "exact",
            }
    except RPCError:
        pass
    # Fallback: flags are always the final 4 bytes; the credential precedes
    # them across an unknown 0-3 byte pad, so report the widest safe window.
    return {
        "client_credential": stub[-12:-4],
        "negotiate_flags": int.from_bytes(stub[-4:], "little"),
        "field_confidence": "tail-anchored",
    }


def netlogon_authenticate_reply_flags(stub: bytes, opnum: int) -> int | None:
    """
    Reply stub for Authenticate2: ServerCredential(8) + NegotiateFlags(4) +
    NTSTATUS(4).  For Authenticate3 an AccountRid(4) sits between the flags and
    the status.  The negotiated (AND-ed) flags are what actually took effect.
    """
    if opnum == NRPC_SERVER_AUTHENTICATE2 and len(stub) >= 16:
        return int.from_bytes(stub[-8:-4], "little")
    if opnum == NRPC_SERVER_AUTHENTICATE3 and len(stub) >= 20:
        return int.from_bytes(stub[-12:-8], "little")
    return None


def rpc_status_tail(stub: bytes) -> int | None:
    """Most NRPC replies end in a 4-byte NTSTATUS."""
    if len(stub) < 4:
        return None
    return int.from_bytes(stub[-4:], "little")


STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022


_UNC_RE = re.compile(rb"(?:\\\x00){2}(?:[\x20-\x7e]\x00){1,255}")


def extract_unc_paths(stub: bytes, limit: int = 4) -> list[str]:
    """
    Best-effort UTF-16LE UNC extraction from a request stub.  We do not attempt
    to identify WHICH parameter a path came from - only that the call carries
    one, which is the whole point of a coercion primitive.
    """
    out = []
    for m in _UNC_RE.finditer(stub):
        try:
            s = m.group(0).decode("utf-16-le", "strict")
        except Exception:
            continue
        s = s.split("\x00")[0]
        if len(s) >= 5 and s.startswith("\\\\"):
            out.append(s)
        if len(out) >= limit:
            break
    return out


def unc_host(path: str) -> str:
    body = path.lstrip("\\")
    return body.split("\\", 1)[0] if body else ""


# ---------------------------------------------------------------------------
# NTLMSSP -- [MS-NLMP].  Never records challenge, response or session-key bytes.
# ---------------------------------------------------------------------------

_NTLM_FIELD_OFFSETS = {
    NTLM_AUTHENTICATE: {
        "lm_response": 12,
        "nt_response": 20,
        "domain": 28,
        "user": 36,
        "workstation": 44,
        "session_key": 52,
    },
}
NTLM_AUTH_FLAGS_OFF = 60
NTLM_AUTH_MIC_OFF = 72
NTLM_AUTH_MIC_MIN_PAYLOAD = 88


def _ntlm_field(msg: bytes, off: int) -> tuple[int, int]:
    """(len, offset) pair; MaxLen at off+2 is ignored per spec."""
    ln = u16(msg, off)
    boff = u32(msg, off + 4)
    return ln, boff


def parse_ntlmssp(msg: bytes) -> dict | None:
    """Parse an NTLMSSP message.  Returns None if this is not one."""
    if len(msg) < 12 or not msg.startswith(NTLMSSP_SIGNATURE):
        return None
    try:
        mtype = u32(msg, 8)
    except RPCError:
        return None
    out = {"message_type": mtype}
    try:
        if mtype == NTLM_NEGOTIATE:
            out["flags"] = u32(msg, 12)
        elif mtype == NTLM_CHALLENGE:
            out["flags"] = u32(msg, 20)
            out["target_info_len"] = u16(msg, 40)
        elif mtype == NTLM_AUTHENTICATE:
            fields = {}
            min_payload = len(msg)
            for name, off in _NTLM_FIELD_OFFSETS[NTLM_AUTHENTICATE].items():
                ln, boff = _ntlm_field(msg, off)
                fields[name] = (ln, boff)
                if ln and boff < min_payload:
                    min_payload = boff
            out["flags"] = u32(msg, NTLM_AUTH_FLAGS_OFF)
            out["lm_response_len"] = fields["lm_response"][0]
            out["nt_response_len"] = fields["nt_response"][0]
            out["session_key_len"] = fields["session_key"][0]
            unicode_names = bool(out["flags"] & NTLMSSP_NEGOTIATE_UNICODE)
            for name in ("domain", "user", "workstation"):
                ln, boff = fields[name]
                val = ""
                if ln and boff + ln <= len(msg):
                    raw = msg[boff:boff + ln]
                    val = (raw.decode("utf-16-le", "replace") if unicode_names
                           else raw.decode("latin-1", "replace"))
                out[name] = val
            # MIC occupies bytes 72..88 when the payload starts at or after 88.
            has_mic = min_payload >= NTLM_AUTH_MIC_MIN_PAYLOAD and len(msg) >= NTLM_AUTH_MIC_MIN_PAYLOAD
            mic_nonzero = False
            if has_mic:
                mic_nonzero = any(msg[NTLM_AUTH_MIC_OFF:NTLM_AUTH_MIC_OFF + 16])
            out["mic_present"] = bool(has_mic and mic_nonzero)
            # NTLMv2 blobs carry AV pairs; MsvAvFlags bit 1 signals a MIC.
            out["av_mic_flag"] = False
            ntl, ntoff = fields["nt_response"]
            if ntl > 24 and ntoff + ntl <= len(msg):
                out["av_mic_flag"] = _ntlmv2_av_mic(msg[ntoff:ntoff + ntl])
            out["ntlm_version"] = (
                1 if out["nt_response_len"] == 24
                else (2 if out["nt_response_len"] > 24 else 0))
            out["anonymous"] = (
                bool(out["flags"] & NTLMSSP_NEGOTIATE_ANONYMOUS)
                or (out["nt_response_len"] == 0 and not out.get("user")))
        else:
            return None
    except RPCError:
        return None
    return out


def _ntlmv2_av_mic(blob: bytes) -> bool:
    """Walk the NTLMv2 AV_PAIR list looking for MsvAvFlags with the MIC bit."""
    # NTLMv2 response: Response(16) + NTLMv2_CLIENT_CHALLENGE.  AV pairs start
    # at offset 44 of the client challenge, i.e. 16 + 28 = 44 into the blob.
    off = 44
    guard = 0
    while off + 4 <= len(blob) and guard < 64:
        guard += 1
        av_id = int.from_bytes(blob[off:off + 2], "little")
        av_len = int.from_bytes(blob[off + 2:off + 4], "little")
        off += 4
        if av_id == MSV_AV_EOL:
            return False
        if off + av_len > len(blob):
            return False
        if av_id == MSV_AV_FLAGS and av_len >= 4:
            flags = int.from_bytes(blob[off:off + 4], "little")
            if flags & MSV_AV_FLAGS_MIC:
                return True
        off += av_len
    return False


def find_ntlmssp(blob: bytes) -> dict | None:
    """Locate an NTLMSSP message anywhere in a GSS/SPNEGO auth_value."""
    idx = blob.find(NTLMSSP_SIGNATURE)
    if idx < 0:
        return None
    return parse_ntlmssp(blob[idx:])


def gss_mech_is_kerberos(blob: bytes) -> bool:
    """Kerberos 5 mech OID 1.2.840.113554.1.2.2 as it appears inside SPNEGO."""
    return b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" in blob


# ---------------------------------------------------------------------------
# DCERPC over SMB2 named pipes (ncacn_np).
#
# The interesting attacks live here, not on tcp/135: PetitPotam rides
# \pipe\lsarpc, DFSCoerce rides \pipe\netdfs, and Zerologon works fine over
# \pipe\netlogon.  We carve DCERPC payloads out of SMB2 WRITE requests, READ
# responses and IOCTL FSCTL_PIPE_TRANSCEIVE in both directions.  We do NOT
# reimplement SMB posture checks - smbwatch owns that surface.
# ---------------------------------------------------------------------------

SMB2_MAGIC = b"\xfeSMB"
SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_TREE_CONNECT = 0x0003
SMB2_CREATE = 0x0005
SMB2_READ = 0x0008
SMB2_WRITE = 0x0009
SMB2_IOCTL = 0x000B
SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001
FSCTL_PIPE_TRANSCEIVE = 0x0011C017

_RPC_PIPE_NAMES = {
    "lsarpc", "netlogon", "lsass", "samr", "netdfs", "spoolss", "svcctl",
    "atsvc", "winreg", "srvsvc", "wkssvc", "eventlog", "efsrpc",
    "fssagentrpc", "epmapper", "browser", "ntsvcs",
}


def smb2_carve(data: bytes) -> list[dict]:
    """
    Walk NBT-framed SMB2 messages in a half-stream chunk and return carved
    payloads: {"kind": "dcerpc"|"pipe_name"|"ntlmssp", "data"/"name", ...}.
    Tolerant by design - anything unparseable is skipped, never raised.
    """
    out: list[dict] = []
    pos = 0
    guard = 0
    while pos + 4 <= len(data) and guard < 64:
        guard += 1
        if data[pos] != 0x00:
            break
        nbt_len = int.from_bytes(data[pos + 1:pos + 4], "big")
        body = data[pos + 4:pos + 4 + nbt_len]
        pos += 4 + nbt_len
        if len(body) < 64 or not body.startswith(SMB2_MAGIC):
            continue
        _smb2_walk_compound(body, out)
    return out


def _smb2_walk_compound(msg: bytes, out: list[dict]) -> None:
    off = 0
    guard = 0
    while off + 64 <= len(msg) and guard < 16:
        guard += 1
        if not msg[off:off + 4] == SMB2_MAGIC:
            return
        try:
            cmd = u16(msg, off + 12)
            flags = u32(msg, off + 16)
            nxt = u32(msg, off + 20)
        except RPCError:
            return
        is_response = bool(flags & SMB2_FLAGS_SERVER_TO_REDIR)
        body = off + 64
        try:
            _smb2_extract(msg, off, body, cmd, is_response, out)
        except RPCError:
            pass
        if nxt == 0 or nxt < 64:
            return
        off += nxt


def _smb2_extract(msg: bytes, hdr_off: int, body: int, cmd: int,
                  is_response: bool, out: list[dict]) -> None:
    if cmd == SMB2_CREATE and not is_response:
        name_off = u16(msg, body + 44)
        name_len = u16(msg, body + 46)
        if name_len and hdr_off + name_off + name_len <= len(msg):
            name = utf16le(msg, hdr_off + name_off, name_len)
            if name:
                out.append({"kind": "pipe_name", "name": name})
        return
    if cmd == SMB2_SESSION_SETUP:
        sec_off = u16(msg, body + 12)
        sec_len = u16(msg, body + 14)
        if sec_len and hdr_off + sec_off + sec_len <= len(msg):
            blob = msg[hdr_off + sec_off:hdr_off + sec_off + sec_len]
            out.append({"kind": "gss", "data": blob})
        return
    if cmd == SMB2_WRITE and not is_response:
        d_off = u16(msg, body + 2)
        d_len = u32(msg, body + 4)
        _emit_pipe_payload(msg, hdr_off + d_off, d_len, out)
        return
    if cmd == SMB2_READ and is_response:
        d_off = u8(msg, body + 2)
        d_len = u32(msg, body + 4)
        _emit_pipe_payload(msg, hdr_off + d_off, d_len, out)
        return
    if cmd == SMB2_IOCTL:
        ctl = u32(msg, body + 4)
        if ctl != FSCTL_PIPE_TRANSCEIVE:
            return
        if is_response:
            i_off, i_len = u32(msg, body + 24), u32(msg, body + 28)
            o_off, o_len = u32(msg, body + 32), u32(msg, body + 36)
        else:
            i_off, i_len = u32(msg, body + 24), u32(msg, body + 28)
            o_off, o_len = u32(msg, body + 36), u32(msg, body + 40)
        for o, ln in ((i_off, i_len), (o_off, o_len)):
            if ln:
                _emit_pipe_payload(msg, hdr_off + o, ln, out)


def _emit_pipe_payload(msg: bytes, off: int, ln: int, out: list[dict]) -> None:
    """
    Emit the payload with a flag saying whether it STARTS a PDU.  The carve
    layer must not drop continuation bytes: a fragment split across two writes
    has no DCERPC header in its second half.  Whether to accept it is the flow
    layer's call, since only it knows if a partial is already buffered.
    """
    if ln <= 0 or ln > MAX_FRAG or off < 0 or off + ln > len(msg):
        return
    payload = msg[off:off + ln]
    out.append({"kind": "dcerpc", "data": payload,
                "pdu_start": looks_like_dcerpc(payload)})


def pipe_basename(name: str) -> str:
    n = name.replace("/", "\\").rstrip("\\")
    n = n.rsplit("\\", 1)[-1]
    return n.lower()


# ---------------------------------------------------------------------------
# WinRM / WS-Man over HTTP
# ---------------------------------------------------------------------------

_HTTP_REQ_RE = re.compile(
    rb"^(GET|POST|PUT|HEAD|OPTIONS|DELETE) ([^\s]{1,512}) HTTP/1\.[01]\r\n")
_HTTP_RESP_RE = re.compile(rb"^HTTP/1\.[01] (\d{3})[^\r\n]*\r\n")


def parse_http_head(data: bytes) -> dict | None:
    """
    Parse request or response headers.  Body is deliberately NOT retained
    beyond a length and a content-type judgement.
    """
    m = _HTTP_REQ_RE.match(data)
    resp = None
    if not m:
        resp = _HTTP_RESP_RE.match(data)
        if not resp:
            return None
    end = data.find(b"\r\n\r\n")
    if end < 0:
        end = len(data)
        head = data
    else:
        head = data[:end]
    lines = head.split(b"\r\n")[1:]
    headers: dict[str, list[str]] = {}
    for line in lines:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        key = k.decode("latin-1", "replace").strip().lower()
        headers.setdefault(key, []).append(v.decode("latin-1", "replace").strip())
    out = {"headers": headers, "body_offset": end + 4 if end < len(data) else len(data)}
    if m:
        out["kind"] = "request"
        out["method"] = m.group(1).decode()
        out["path"] = m.group(2).decode("latin-1", "replace")
    else:
        out["kind"] = "response"
        out["status"] = int(resp.group(1))
    return out


MAX_HTTP_BUFFER = 256 * 1024          # cap on an un-terminated HTTP head/body
_HTTP_STARTS = (b"POST ", b"GET ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                b"HTTP/1.")


def _http_content_length(head: bytes) -> int | None:
    """Content-Length from a raw head, or None if absent/chunked/malformed."""
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        name = k.strip().lower()
        if name == b"transfer-encoding" and b"chunked" in v.lower():
            return None
        if name == b"content-length":
            try:
                n = int(v.strip())
            except ValueError:
                return None
            return n if 0 <= n <= MAX_HTTP_BUFFER else None
    return 0


def _http_resync(buf: bytes) -> int | None:
    """Offset of the next plausible message start after byte 0, or None."""
    best = None
    for tok in _HTTP_STARTS:
        i = buf.find(tok, 1)
        if i >= 0 and (best is None or i < best):
            best = i
    return best


def http_head_span(buf: bytearray) -> tuple[int, int | None] | None:
    """
    Locate one complete HTTP head at the front of a half-stream buffer.

    Returns (offset just past the blank line, declared body length) or None if
    more bytes are needed.  Body length is None for chunked encoding.

    This exists because WinRM Authorization headers carrying SPNEGO/Kerberos
    or CredSSP blobs run to several kilobytes and therefore always span TCP
    segments on a real network.  Parsing each segment in isolation sees a
    truncated head, which silently loses every auth-posture finding on exactly
    the traffic that matters most.
    """
    if not buf:
        return None
    head_start = bytes(buf[:512])
    if not (_HTTP_REQ_RE.match(head_start) or _HTTP_RESP_RE.match(head_start)):
        # Only conclude the buffer is misaligned once a whole start line has
        # arrived.  Below that we simply do not have enough bytes to match yet,
        # and resyncing here would discard a message being delivered one byte
        # at a time.
        if b"\r\n" not in head_start and len(buf) < 512:
            return None
        skip = _http_resync(bytes(buf))
        if skip is None:
            if len(buf) > MAX_HTTP_BUFFER:
                del buf[:]
            return None
        del buf[:skip]
        if not buf:
            return None
    end = bytes(buf).find(b"\r\n\r\n")
    if end < 0:
        return None                       # head still incomplete: wait
    return end + 4, _http_content_length(bytes(buf[:end]))


def http_header(parsed: dict, name: str) -> str:
    vals = parsed["headers"].get(name.lower())
    return vals[0] if vals else ""


def http_header_all(parsed: dict, name: str) -> list[str]:
    return parsed["headers"].get(name.lower(), [])


def auth_schemes_offered(parsed: dict) -> list[str]:
    out = []
    for v in http_header_all(parsed, "www-authenticate"):
        for part in v.split(","):
            tok = part.strip().split(" ", 1)[0].strip()
            if tok:
                out.append(tok.lower())
    return out


def auth_scheme_used(parsed: dict) -> tuple[str, str]:
    v = http_header(parsed, "authorization")
    if not v:
        return "", ""
    scheme, _, blob = v.partition(" ")
    return scheme.strip().lower(), blob.strip()


def decode_auth_blob(blob: str) -> bytes:
    if not blob:
        return b""
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return b""


def is_wsman_path(path: str) -> bool:
    p = path.lower().split("?", 1)[0]
    return p.startswith("/wsman") or p.startswith("/powershell") or "/wsman" in p


def content_type_encrypted(ctype: str) -> bool:
    c = ctype.lower()
    return any(t in c for t in WSMAN_ENCRYPTED_TYPES)


# ---------------------------------------------------------------------------
# Configuration, findings emission
# ---------------------------------------------------------------------------


class Config:
    # Every accepted knob, with its default.  Declared rather than implied by a
    # sequence of kw.get() calls so that an unknown key is an error: a typo
    # like Config(dcs=...) for dc_hosts would otherwise be swallowed in
    # silence, leaving the feature off while the caller believes it is on.
    DEFAULTS = {
        "window": 60,
        "zerologon_threshold": 8,
        "epm_threshold": 20,
        "dedup_seconds": 60,
        "min_severity": "low",
        "local_nets": (),
        "dc_hosts": (),
        "allow_clients": (),
        "allow_interfaces": (),
        "rpc_ports": None,
        "dynamic_range": False,
        "ntlm_from_smb": False,
        "record_identities": True,
    }

    def __init__(self, **kw):
        unknown = set(kw) - set(self.DEFAULTS)
        if unknown:
            raise TypeError(
                "Config got unknown option(s): %s (known: %s)"
                % (", ".join(sorted(unknown)), ", ".join(sorted(self.DEFAULTS))))
        self.window = kw.get("window", 60)
        self.zerologon_threshold = kw.get("zerologon_threshold", 8)
        self.epm_threshold = kw.get("epm_threshold", 20)
        self.dedup_seconds = kw.get("dedup_seconds", 60)
        self.min_severity = kw.get("min_severity", "low")
        self.local_nets = list(kw.get("local_nets", []))
        self.dc_hosts = list(kw.get("dc_hosts", []))
        self.allow_clients = set(kw.get("allow_clients", []))
        self.allow_interfaces = set(kw.get("allow_interfaces", []))
        ports = kw.get("rpc_ports") or [EPMAPPER_PORT, SMB_PORT, NBT_SESSION_PORT]
        self.rpc_ports = set(ports)
        self.dynamic_range = kw.get("dynamic_range", False)
        self.ntlm_from_smb = kw.get("ntlm_from_smb", False)
        self.record_identities = kw.get("record_identities", True)

    def in_local(self, ip: str) -> bool | None:
        if not self.local_nets:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return any(addr in net for net in self.local_nets)

    def is_dc(self, ip: str) -> bool | None:
        if not self.dc_hosts:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for entry in self.dc_hosts:
            if isinstance(entry, ipaddress.IPv4Network) or isinstance(entry, ipaddress.IPv6Network):
                if addr in entry:
                    return True
            elif addr == entry:
                return True
        return False


class Finding:
    __slots__ = ("ts", "code", "severity", "category", "title", "subject",
                 "details", "count")

    def __init__(self, ts, code, severity, category, title, subject, details):
        self.ts = ts
        self.code = code
        self.severity = severity
        self.category = category
        self.title = title
        self.subject = subject
        self.details = details
        self.count = 1

    def as_dict(self) -> dict:
        return {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.ts)),
            "epoch": round(self.ts, 3),
            "code": self.code,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "subject": self.subject,
            "count": self.count,
            "details": self.details,
        }

    def as_text(self) -> str:
        when = time.strftime("%H:%M:%S", time.localtime(self.ts))
        extra = " ".join(f"{k}={v}" for k, v in sorted(self.details.items())
                         if v not in (None, "", []))
        tail = f"  [{extra}]" if extra else ""
        seen = f" (x{self.count})" if self.count > 1 else ""
        return (f"{when} {self.severity.upper():8} {self.code:42} "
                f"{self.subject}{seen}{tail}")


class Emitter:
    """Dedup + severity floor.  Re-fires only on genuine severity escalation."""

    def __init__(self, config: Config, sink=None):
        self.config = config
        self.sink = sink
        self.seen: dict[tuple, Finding] = {}
        self.emitted: list[Finding] = []

    def _passes(self, severity: str) -> bool:
        return SEVERITY_RANK[severity] >= SEVERITY_RANK[self.config.min_severity]

    def emit(self, ts, code, subject, details=None, severity=None, key_extra=()):
        if code not in FINDINGS:
            raise KeyError(f"undeclared finding code {code}")
        base_sev, category, title = FINDINGS[code]
        sev = severity or base_sev
        details = details or {}
        key = (code, subject) + tuple(key_extra)
        prev = self.seen.get(key)
        if prev is None:
            f = Finding(ts, code, sev, category, title, subject, details)
            self.seen[key] = f
        else:
            last_ts = prev.ts
            prev.count += 1
            prev.ts = ts
            escalated = SEVERITY_RANK[sev] > SEVERITY_RANK[prev.severity]
            if escalated:
                prev.severity = sev
                prev.details.update(details)
            elif (ts - last_ts) < self.config.dedup_seconds:
                return None
            f = prev
        if not self._passes(f.severity):
            return None
        self.emitted.append(f)
        if self.sink:
            self.sink(f)
        return f


# ---------------------------------------------------------------------------
# Per-association and per-peer state
# ---------------------------------------------------------------------------


class Association:
    """One DCERPC association (a TCP connection or a named pipe instance)."""

    __slots__ = ("contexts", "auth_type", "auth_level", "auth_reported",
                 "ntlm_reported", "spnego_seen", "kerberos_seen", "pipe_name",
                 "pending_calls", "created")

    def __init__(self, ts):
        self.contexts: dict[int, dict] = {}
        self.auth_type = None
        self.auth_level = None
        self.auth_reported = False
        self.ntlm_reported = set()
        self.spnego_seen = False
        self.kerberos_seen = False
        self.pipe_name = ""
        self.pending_calls: dict[int, tuple] = {}
        self.created = ts


class NetlogonPeer:
    """Per (client, server) NetLogon secure-channel history."""

    __slots__ = ("attempts", "zero_credential", "zero_challenge",
                 "brute_fired", "last_flags")

    def __init__(self):
        self.attempts = deque()
        self.zero_credential = False
        self.zero_challenge = False
        self.brute_fired = False
        self.last_flags = None

    def record(self, ts, window):
        self.attempts.append(ts)
        cutoff = ts - window
        while self.attempts and self.attempts[0] < cutoff:
            self.attempts.popleft()
        return len(self.attempts)


# ---------------------------------------------------------------------------
# RPC detection engine
# ---------------------------------------------------------------------------

SENSITIVE_CLASSES = ("netlogon", "directory", "coercion", "exec")


class RPCEngine:
    def __init__(self, config: Config, emitter: Emitter):
        self.config = config
        self.emitter = emitter
        self.assocs: dict[tuple, Association] = {}
        self.netlogon: dict[tuple, NetlogonPeer] = {}
        self.epm_lookups: dict[str, deque] = {}

    # -- helpers ---------------------------------------------------------
    def _assoc(self, flow, ts) -> Association:
        a = self.assocs.get(flow)
        if a is None:
            a = Association(ts)
            self.assocs[flow] = a
        return a

    def _allowed(self, client_ip: str) -> bool:
        return client_ip in self.config.allow_clients

    def _iface_info(self, uuid: str):
        return INTERFACES.get(uuid, (uuid, "other", "unknown interface"))

    # -- entry point -----------------------------------------------------
    def process_pdu(self, ts, flow, client_ip, server_ip, pdu: bytes,
                    from_client: bool, pipe_name: str = ""):
        try:
            hdr = parse_co_header(pdu)
        except RPCError:
            return
        subject = f"{client_ip} -> {server_ip}"
        if self._allowed(client_ip):
            return
        if hdr["rpc_vers"] != 5:
            self.emitter.emit(ts, "RPC-LEGACY-VERSION", subject, {
                "rpc_vers": hdr["rpc_vers"],
                "rpc_vers_minor": hdr["rpc_vers_minor"],
            })
            return
        if hdr["frag_length"] > len(pdu):
            self.emitter.emit(ts, "RPC-FRAG-ANOMALY", subject, {
                "frag_length": hdr["frag_length"],
                "observed_bytes": len(pdu),
            })
            return
        assoc = self._assoc(flow, ts)
        if pipe_name and not assoc.pipe_name:
            assoc.pipe_name = pipe_name
        try:
            trailer = parse_sec_trailer(pdu, hdr)
        except RPCError:
            self.emitter.emit(ts, "RPC-FRAG-ANOMALY", subject, {
                "reason": "sec_trailer out of bounds",
                "frag_length": hdr["frag_length"],
                "auth_length": hdr["auth_length"],
            })
            return
        ptype = hdr["ptype"]
        try:
            if ptype in (PTYPE_BIND, PTYPE_ALTER_CONTEXT):
                self._on_bind(ts, subject, assoc, pdu, hdr, trailer, client_ip, server_ip)
            elif ptype == PTYPE_BIND_ACK or ptype == PTYPE_ALTER_CONTEXT_RESP:
                self._on_bind_ack(ts, subject, assoc, pdu, hdr)
            elif ptype == PTYPE_BIND_NAK:
                self._on_bind_nak(ts, subject, pdu, hdr)
            elif ptype == PTYPE_AUTH3:
                self._on_auth3(ts, subject, assoc, hdr, trailer)
            elif ptype == PTYPE_REQUEST and from_client:
                self._on_request(ts, subject, assoc, pdu, hdr, trailer,
                                 client_ip, server_ip)
            elif ptype == PTYPE_RESPONSE and not from_client:
                self._on_response(ts, subject, assoc, pdu, hdr, trailer,
                                  client_ip, server_ip)
            elif ptype == PTYPE_FAULT and not from_client:
                self._on_fault(ts, subject, assoc, pdu, hdr)
        except RPCError:
            self.emitter.emit(ts, "RPC-FRAG-ANOMALY", subject, {
                "reason": "truncated PDU body",
                "ptype": hdr["ptype_name"],
                "frag_length": hdr["frag_length"],
            })

    # -- bind ------------------------------------------------------------
    def _on_bind(self, ts, subject, assoc, pdu, hdr, trailer, client_ip, server_ip):
        body = parse_bind(pdu, hdr)
        is_alter = hdr["ptype"] == PTYPE_ALTER_CONTEXT
        new_level = trailer["auth_level"] if trailer else RPC_C_AUTHN_LEVEL_NONE
        new_type = trailer["auth_type"] if trailer else RPC_C_AUTHN_NONE

        if is_alter and assoc.auth_level is not None:
            if new_level < assoc.auth_level:
                self.emitter.emit(ts, "RPC-AUTH-DOWNGRADE", subject, {
                    "from": AUTHN_LEVEL_NAMES.get(assoc.auth_level, assoc.auth_level),
                    "to": AUTHN_LEVEL_NAMES.get(new_level, new_level),
                    "auth_type": AUTHN_NAMES.get(new_type, new_type),
                })
        assoc.auth_type = new_type
        assoc.auth_level = new_level
        if trailer:
            self._inspect_auth_value(ts, subject, assoc, trailer["auth_type"],
                                     trailer["auth_value"], "rpc")

        for ctx in body["contexts"]:
            uuid = ctx["interface"]
            if uuid in self.config.allow_interfaces:
                continue
            name, klass, desc = self._iface_info(uuid)
            assoc.contexts[ctx["context_id"]] = {
                "interface": uuid, "name": name, "class": klass,
                "version": ctx["if_version"],
            }
            base = {
                "interface": name,
                "uuid": uuid,
                "if_version": ctx["if_version"],
                "auth": AUTHN_NAMES.get(new_type, new_type),
                "auth_level": AUTHN_LEVEL_NAMES.get(new_level, new_level),
            }
            if assoc.pipe_name:
                base["pipe"] = assoc.pipe_name

            if klass == "netlogon":
                self._netlogon_bind_posture(ts, subject, base, trailer,
                                            client_ip, server_ip)
            elif klass in SENSITIVE_CLASSES:
                if trailer is None:
                    sev = "high" if klass in ("directory", "exec") else "medium"
                    self.emitter.emit(ts, "RPC-BIND-NO-AUTH", subject,
                                      dict(base), severity=sev,
                                      key_extra=(uuid,))
                elif new_level < RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
                    sev = "high" if klass in ("directory", "exec") else "medium"
                    self.emitter.emit(ts, "RPC-NO-PACKET-INTEGRITY", subject,
                                      dict(base), severity=sev,
                                      key_extra=(uuid,))
            if klass == "coercion":
                self.emitter.emit(ts, "RPC-COERCION-INTERFACE-BIND", subject,
                                  dict(base, description=desc), key_extra=(uuid,))

    def _netlogon_bind_posture(self, ts, subject, base, trailer, client_ip, server_ip):
        level = trailer["auth_level"] if trailer else RPC_C_AUTHN_LEVEL_NONE
        if trailer is None or level < RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
            self.emitter.emit(ts, "RPC-NETLOGON-UNSIGNED-BIND", subject, dict(base))
        is_dc = self.config.is_dc(server_ip)
        if is_dc is False:
            self.emitter.emit(ts, "RPC-NETLOGON-UNEXPECTED-SERVER", subject,
                              dict(base, server=server_ip))

    def _on_bind_ack(self, ts, subject, assoc, pdu, hdr):
        body = parse_bind_ack(pdu, hdr)
        if body["sec_addr"]:
            assoc.pipe_name = assoc.pipe_name or body["sec_addr"]

    def _on_bind_nak(self, ts, subject, pdu, hdr):
        body = parse_bind_nak(pdu, hdr)
        self.emitter.emit(ts, "RPC-BIND-NAK", subject, {
            "reason": body["reject_reason_name"],
            "reason_code": body["reject_reason"],
        })

    def _on_auth3(self, ts, subject, assoc, hdr, trailer):
        if not trailer:
            return
        if (assoc.auth_level is not None
                and trailer["auth_level"] < assoc.auth_level):
            self.emitter.emit(ts, "RPC-AUTH-DOWNGRADE", subject, {
                "from": AUTHN_LEVEL_NAMES.get(assoc.auth_level, assoc.auth_level),
                "to": trailer["auth_level_name"],
                "stage": "auth3",
            })
        assoc.auth_level = trailer["auth_level"]
        self._inspect_auth_value(ts, subject, assoc, trailer["auth_type"],
                                 trailer["auth_value"], "rpc")

    # -- calls -----------------------------------------------------------
    def _on_request(self, ts, subject, assoc, pdu, hdr, trailer, client_ip, server_ip):
        body = parse_request(pdu, hdr)
        ctx = assoc.contexts.get(body["context_id"])
        stub = extract_stub(pdu, hdr, body, trailer)
        assoc.pending_calls[hdr["call_id"]] = (
            ctx["interface"] if ctx else None, body["opnum"], ts)
        if trailer:
            self._inspect_auth_value(ts, subject, assoc, trailer["auth_type"],
                                     trailer["auth_value"], "rpc")
        if ctx is None:
            return
        uuid, klass, name = ctx["interface"], ctx["class"], ctx["name"]
        opnum = body["opnum"]
        sealed = bool(trailer and trailer["auth_level"] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        base = {"interface": name, "opnum": opnum,
                "auth_level": (trailer["auth_level_name"] if trailer else "none")}
        if assoc.pipe_name:
            base["pipe"] = assoc.pipe_name

        if klass == "netlogon":
            self._netlogon_call(ts, subject, base, stub, opnum, sealed,
                                client_ip, server_ip)
        if uuid in COERCION_CALLS and opnum in COERCION_CALLS[uuid]:
            self._coercion_call(ts, subject, base, stub, uuid, opnum, sealed,
                                server_ip)
        if uuid in EXEC_CALLS and opnum in EXEC_CALLS[uuid]:
            self._exec_call(ts, subject, base, uuid, opnum)
        if uuid == IF_EPM and opnum in EPM_LOOKUP_OPNUMS:
            self._epm_call(ts, subject, base, client_ip)

    def _netlogon_call(self, ts, subject, base, stub, opnum, sealed,
                       client_ip, server_ip):
        peer = self.netlogon.setdefault((client_ip, server_ip), NetlogonPeer())
        opname = NRPC_OPNAMES.get(opnum, f"opnum{opnum}")
        base = dict(base, call=opname)

        if opnum == NRPC_SERVER_REQ_CHALLENGE and not sealed:
            f = netlogon_req_challenge_fields(stub)
            if f and is_all_zero(f["client_challenge"]):
                peer.zero_challenge = True
                self.emitter.emit(
                    ts, "RPC-ZEROLOGON-ZERO-CHALLENGE", subject,
                    dict(base, cve="CVE-2020-1472",
                         field_confidence=f["field_confidence"]))
            return

        if opnum in NRPC_AUTH_OPNUMS:
            n = peer.record(ts, self.config.window)
            if not sealed:
                f = netlogon_authenticate_fields(stub, opnum)
                if f:
                    if is_all_zero(f["client_credential"]):
                        peer.zero_credential = True
                        self.emitter.emit(
                            ts, "RPC-ZEROLOGON-ZERO-CREDENTIAL", subject,
                            dict(base, cve="CVE-2020-1472",
                                 field_confidence=f["field_confidence"]))
                    flags = f["negotiate_flags"]
                    if flags is not None:
                        peer.last_flags = flags
                        self._netlogon_flags(ts, subject, base, flags, "requested")
            if n >= self.config.zerologon_threshold and not peer.brute_fired:
                peer.brute_fired = True
                self.emitter.emit(ts, "RPC-ZEROLOGON-BRUTE-FORCE", subject, dict(
                    base, attempts=n, window_seconds=self.config.window,
                    zero_credential_seen=peer.zero_credential,
                    cve="CVE-2020-1472"))
            return

        if opnum in (NRPC_SERVER_PASSWORD_SET, NRPC_SERVER_PASSWORD_SET2):
            if peer.brute_fired or peer.zero_credential:
                self.emitter.emit(ts, "RPC-NETLOGON-PASSWORD-RESET-AFTER-BRUTE",
                                  subject, dict(base, cve="CVE-2020-1472",
                                                prior_attempts=len(peer.attempts)))
            else:
                self.emitter.emit(ts, "RPC-NETLOGON-PASSWORD-SET", subject, dict(base))
            return

        if opnum in (NRPC_SERVER_PASSWORD_GET, NRPC_SERVER_TRUST_PASSWORDS_GET):
            self.emitter.emit(ts, "RPC-NETLOGON-PASSWORD-GET", subject, dict(base))

    def _netlogon_flags(self, ts, subject, base, flags, stage):
        d = dict(base, negotiate_flags="0x%08x" % flags, stage=stage)
        if flags == ZEROLOGON_TESTER_FLAGS:
            d["matches_public_tester_value"] = True
        if not flags & NETLOGON_NEG_AUTHENTICATED_RPC:
            self.emitter.emit(ts, "RPC-NETLOGON-NO-SECURE-RPC", subject,
                              dict(d, cve="CVE-2020-1472"), key_extra=(stage,))
        if not flags & NETLOGON_NEG_SUPPORTS_AES:
            self.emitter.emit(ts, "RPC-NETLOGON-WEAK-CRYPTO", subject,
                              dict(d, strong_key=bool(flags & NETLOGON_NEG_STRONG_KEY)),
                              key_extra=(stage,))

    def _coercion_call(self, ts, subject, base, stub, uuid, opnum, sealed, server_ip):
        """
        A coercion primitive is only an attack when it names a listener other
        than the server itself.  External listener -> critical; an internal one
        is still a relay path but may be legitimate tooling, so it lands high.
        A sealed stub hides the path entirely: report the call at medium and
        say so rather than guessing.
        """
        opname = COERCION_CALLS[uuid][opnum]
        d = dict(base, call=opname)
        if sealed:
            self.emitter.emit(ts, "RPC-COERCION-CALL", subject,
                              dict(d, unc_path_visible=False,
                                   note="stub sealed; UNC target not observable"),
                              severity="medium", key_extra=(uuid, opnum))
            return
        paths = extract_unc_paths(stub)
        targets = [p for p in paths if unc_host(p) and unc_host(p) != server_ip]
        if not targets:
            return
        external = [p for p in targets if self.config.in_local(unc_host(p)) is not True]
        sev = "critical" if external else "high"
        self.emitter.emit(ts, "RPC-COERCION-CALL", subject,
                          dict(d, unc_paths=targets, external_listener=bool(external)),
                          severity=sev, key_extra=(uuid, opnum))

    def _exec_call(self, ts, subject, base, uuid, opnum):
        opname = EXEC_CALLS[uuid][opnum]
        d = dict(base, call=opname)
        if uuid == IF_DRSUAPI and opnum == 3:
            self.emitter.emit(ts, "RPC-DCSYNC-CALL", subject, d)
            return
        if uuid == IF_BKRP:
            self.emitter.emit(ts, "RPC-BACKUPKEY-ACCESS", subject, d)
            return
        if uuid == IF_DRSUAPI:
            return
        sev = "medium" if uuid == IF_WINREG else "high"
        self.emitter.emit(ts, "RPC-REMOTE-EXEC-INTERFACE", subject, d,
                          severity=sev, key_extra=(uuid, opnum))

    def _epm_call(self, ts, subject, base, client_ip):
        q = self.epm_lookups.setdefault(client_ip, deque())
        q.append(ts)
        cutoff = ts - self.config.window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.config.epm_threshold:
            self.emitter.emit(ts, "RPC-EPM-SWEEP", subject, dict(
                base, lookups=len(q), window_seconds=self.config.window))

    def _on_response(self, ts, subject, assoc, pdu, hdr, trailer, client_ip, server_ip):
        body = parse_response(pdu, hdr)
        pending = assoc.pending_calls.pop(hdr["call_id"], None)
        if trailer:
            self._inspect_auth_value(ts, subject, assoc, trailer["auth_type"],
                                     trailer["auth_value"], "rpc")
        if not pending:
            return
        uuid, opnum, _ = pending
        if uuid != IF_NETLOGON or opnum not in NRPC_AUTH_OPNUMS:
            return
        if trailer and trailer["auth_level"] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
            return
        stub = extract_stub(pdu, hdr, body, trailer)
        status = rpc_status_tail(stub)
        if status != STATUS_SUCCESS:
            return
        flags = netlogon_authenticate_reply_flags(stub, opnum)
        if flags is None:
            return
        base = {"interface": "netlogon", "opnum": opnum,
                "call": NRPC_OPNAMES.get(opnum, str(opnum))}
        self._netlogon_flags(ts, f"{client_ip} -> {server_ip}", base, flags,
                             "negotiated")

    def _on_fault(self, ts, subject, assoc, pdu, hdr):
        assoc.pending_calls.pop(hdr["call_id"], None)

    # -- NTLM / SPNEGO ---------------------------------------------------
    def _inspect_auth_value(self, ts, subject, assoc, auth_type, blob, transport):
        if not blob:
            return
        if auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
            assoc.spnego_seen = True
            if gss_mech_is_kerberos(blob):
                assoc.kerberos_seen = True
        elif auth_type == RPC_C_AUTHN_GSS_KERBEROS:
            assoc.kerberos_seen = True
        if auth_type not in (RPC_C_AUTHN_WINNT, RPC_C_AUTHN_GSS_NEGOTIATE):
            return
        msg = find_ntlmssp(blob)
        if not msg:
            return
        self.analyse_ntlm(ts, subject, assoc, msg, transport)

    def analyse_ntlm(self, ts, subject, assoc, msg, transport):
        mtype = msg["message_type"]
        if mtype in assoc.ntlm_reported:
            return
        assoc.ntlm_reported.add(mtype)
        flags = msg.get("flags", 0)
        base = {"transport": transport, "ntlm_flags": "0x%08x" % flags}
        if assoc.pipe_name:
            base["pipe"] = assoc.pipe_name

        if mtype == NTLM_AUTHENTICATE:
            if assoc.spnego_seen:
                self.emitter.emit(ts, "RPC-NTLM-OVER-SPNEGO", subject, dict(
                    base, kerberos_offered=assoc.kerberos_seen))
            if msg.get("anonymous"):
                self.emitter.emit(ts, "RPC-NTLM-ANONYMOUS", subject, dict(base))
                return
            ident = {}
            if self.config.record_identities:
                ident = {"user": msg.get("user", ""), "domain": msg.get("domain", ""),
                         "workstation": msg.get("workstation", "")}
            d = dict(base, **ident)
            if msg.get("ntlm_version") == 1:
                self.emitter.emit(ts, "RPC-NTLMV1-IN-USE", subject, dict(
                    d, nt_response_len=msg.get("nt_response_len")))
            if not flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                self.emitter.emit(ts, "RPC-NTLM-NO-EXTENDED-SESSION-SECURITY",
                                  subject, dict(d))
            if not flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL):
                self.emitter.emit(ts, "RPC-NTLM-NO-SIGNING", subject, dict(
                    d, always_sign=bool(flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)))
            if not (msg.get("mic_present") or msg.get("av_mic_flag")):
                self.emitter.emit(ts, "RPC-NTLM-NO-MIC", subject, dict(d))
            if flags & NTLMSSP_NEGOTIATE_LM_KEY:
                self.emitter.emit(ts, "RPC-NTLM-LM-KEY", subject, dict(d))


# ---------------------------------------------------------------------------
# WinRM engine
# ---------------------------------------------------------------------------

_SHELL_HINTS = (
    b"http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    b"microsoft.powershell",
    b"<rsp:Shell",
)


class WinRMFlow:
    __slots__ = ("offered", "reported", "assoc", "cbuf", "sbuf",
                 "cpend", "spend")

    def __init__(self, ts):
        self.offered: set[str] = set()
        self.reported: set[str] = set()
        self.assoc = Association(ts)
        self.cbuf = bytearray()       # client -> server, awaiting a full message
        self.sbuf = bytearray()       # server -> client
        self.cpend = None             # head seen, body still arriving
        self.spend = None


class WinRMEngine:
    def __init__(self, config: Config, emitter: Emitter, rpc: RPCEngine):
        self.config = config
        self.emitter = emitter
        self.rpc = rpc
        self.flows: dict[tuple, WinRMFlow] = {}

    def process(self, ts, flow, client_ip, server_ip, data: bytes,
                from_client: bool, server_port: int):
        if server_port == WINRM_HTTPS_PORT:
            return  # TLS: observed at the flow level only, never dissected
        if client_ip in self.config.allow_clients:
            return
        st = self.flows.get(flow)
        if st is None:
            st = WinRMFlow(ts)
            self.flows[flow] = st
        buf = st.cbuf if from_client else st.sbuf
        buf += data
        if len(buf) > MAX_HTTP_BUFFER:
            del buf[:-MAX_HTTP_BUFFER]
        pend = st.cpend if from_client else st.spend
        while True:
            if pend is None:
                span = http_head_span(buf)
                if span is None:
                    break
                head_end, clen = span
                # Head-level posture is emitted the moment the head is
                # complete.  Waiting for the body would mean a reset, truncated
                # or mis-declared message loses its auth findings entirely,
                # and Content-Length is attacker-controlled anyway.
                self._handle_head(ts, st, client_ip, server_ip,
                                  bytes(buf[:head_end]), server_port)
                pend = (head_end, clen)
            head_end, clen = pend
            total = head_end + (clen or 0)
            if len(buf) < total and len(buf) < MAX_HTTP_BUFFER:
                break                      # body still arriving
            take = min(total, len(buf))
            msg = bytes(buf[:take])
            del buf[:take]
            self._handle_body(ts, st, client_ip, server_ip, msg, server_port)
            pend = None
        if from_client:
            st.cpend = pend
        else:
            st.spend = pend

    def _handle_body(self, ts, st, client_ip, server_ip, data: bytes,
                     server_port: int):
        parsed = parse_http_head(data)
        if parsed is None or parsed["kind"] != "request":
            return
        path = parsed.get("path", "")
        if not is_wsman_path(path):
            return
        subject = f"{client_ip} -> {server_ip}:{server_port}"
        self._body_checks(ts, subject, parsed, data, path)

    def _handle_head(self, ts, st, client_ip, server_ip, data: bytes,
                     server_port: int):
        parsed = parse_http_head(data)
        if parsed is None:
            return
        subject = f"{client_ip} -> {server_ip}:{server_port}"
        if parsed["kind"] == "response":
            for s in auth_schemes_offered(parsed):
                st.offered.add(s)
            return
        path = parsed.get("path", "")
        if not is_wsman_path(path):
            return
        if "cleartext" not in st.reported:
            st.reported.add("cleartext")
            self.emitter.emit(ts, "WINRM-CLEARTEXT-HTTP", subject, {
                "path": path, "port": server_port})
        scheme, blob = auth_scheme_used(parsed)
        if scheme == "basic":
            self.emitter.emit(ts, "WINRM-BASIC-AUTH", subject, {
                "path": path, "credential_bytes": len(blob)})
        elif scheme == "credssp":
            self.emitter.emit(ts, "WINRM-CREDSSP", subject, {"path": path})
        elif scheme in ("negotiate", "ntlm", "kerberos"):
            raw = decode_auth_blob(blob)
            if raw:
                if scheme == "negotiate":
                    st.assoc.spnego_seen = True
                    if gss_mech_is_kerberos(raw):
                        st.assoc.kerberos_seen = True
                msg = find_ntlmssp(raw)
                if msg:
                    self.rpc.analyse_ntlm(ts, subject, st.assoc, msg, "winrm")
        if scheme in ("basic", "ntlm") and (
                "negotiate" in st.offered or "kerberos" in st.offered):
            self.emitter.emit(ts, "WINRM-AUTH-DOWNGRADE", subject, {
                "selected": scheme, "offered": sorted(st.offered)})

    def _body_checks(self, ts, subject, parsed, data, path):
        ctype = http_header(parsed, "content-type")
        body = data[parsed["body_offset"]:]
        if not body:
            return
        if ctype and not content_type_encrypted(ctype):
            if b"<" in body[:64] or "soap" in ctype.lower() or "xml" in ctype.lower():
                self.emitter.emit(ts, "WINRM-UNENCRYPTED-PAYLOAD", subject, {
                    "content_type": ctype, "path": path, "body_bytes": len(body)})
        lowered = body[:4096].lower()
        if any(h.lower() in lowered for h in _SHELL_HINTS):
            self.emitter.emit(ts, "WINRM-SHELL-CREATE", subject, {"path": path})


# ---------------------------------------------------------------------------
# TCP half-stream reassembly and dispatch
# ---------------------------------------------------------------------------

MAX_BUFFER = 512 * 1024


class HalfStream:
    __slots__ = ("buf", "pipe_buf", "pipe_name")

    def __init__(self):
        self.buf = bytearray()        # transport bytes (TCP or NBT framed)
        self.pipe_buf = bytearray()   # DCERPC bytes carved out of SMB2
        self.pipe_name = ""


class FlowManager:
    """
    One buffer per direction per flow.  DCERPC is self-framing via
    frag_length, so we pull whole PDUs and keep partials.  SMB2 half-streams
    are framed by the NBT 4-byte length and carved for pipe payloads.  WinRM
    is handled at the HTTP message level.
    """

    def __init__(self, config: Config, rpc: RPCEngine, winrm: WinRMEngine):
        self.config = config
        self.rpc = rpc
        self.winrm = winrm
        self.streams: dict[tuple, HalfStream] = {}

    def server_port_for(self, sport: int, dport: int) -> int | None:
        watched = set(self.config.rpc_ports) | {WINRM_HTTP_PORT, WINRM_HTTPS_PORT}
        if dport in watched:
            return dport
        if sport in watched:
            return sport
        if self.config.dynamic_range:
            if 49152 <= dport <= 65535 and not (49152 <= sport <= 65535):
                return dport
            if 49152 <= sport <= 65535 and not (49152 <= dport <= 65535):
                return sport
            if 49152 <= dport <= 65535:
                return dport
        return None

    def handle_segment(self, ts, src, sport, dst, dport, payload: bytes):
        if not payload:
            return
        server_port = self.server_port_for(sport, dport)
        if server_port is None:
            return
        from_client = (dport == server_port)
        if from_client:
            client_ip, client_port, server_ip = src, sport, dst
        else:
            client_ip, client_port, server_ip = dst, dport, src
        flow = (client_ip, client_port, server_ip, server_port)
        key = flow + (from_client,)

        if server_port in (WINRM_HTTP_PORT, WINRM_HTTPS_PORT):
            self.winrm.process(ts, flow, client_ip, server_ip, payload,
                               from_client, server_port)
            return

        hs = self.streams.get(key)
        if hs is None:
            hs = HalfStream()
            self.streams[key] = hs
        hs.buf += payload
        if len(hs.buf) > MAX_BUFFER:
            del hs.buf[:-MAX_BUFFER]

        if server_port in (SMB_PORT, NBT_SESSION_PORT):
            self._drain_smb(ts, flow, key, hs, client_ip, server_ip, from_client)
        else:
            self._drain_dcerpc(ts, flow, hs, client_ip, server_ip, from_client, "")

    def _drain_smb(self, ts, flow, key, hs, client_ip, server_ip, from_client):
        # Consume whole NBT messages; leave a partial tail buffered.
        while len(hs.buf) >= 4:
            if hs.buf[0] != 0x00:
                del hs.buf[:]
                return
            nbt_len = int.from_bytes(hs.buf[1:4], "big")
            if nbt_len > MAX_BUFFER:
                del hs.buf[:]
                return
            if len(hs.buf) < 4 + nbt_len:
                return
            msg = bytes(hs.buf[:4 + nbt_len])
            del hs.buf[:4 + nbt_len]
            for item in smb2_carve(msg):
                if item["kind"] == "pipe_name":
                    name = pipe_basename(item["name"])
                    if name in _RPC_PIPE_NAMES:
                        hs.pipe_name = item["name"]
                        peer = self.streams.get(flow + (not from_client,))
                        if peer is not None and not peer.pipe_name:
                            peer.pipe_name = item["name"]
                elif item["kind"] == "dcerpc":
                    # Buffer rather than dispatch: a fragment may span writes.
                    # Only a PDU start may open a buffer; once one is open,
                    # everything on that pipe is continuation data.
                    if not (hs.pipe_buf or item["pdu_start"]):
                        continue
                    hs.pipe_buf += item["data"]
                    self._drain_frames(ts, flow, hs, hs.pipe_buf, client_ip,
                                       server_ip, from_client)
                elif item["kind"] == "gss" and self.config.ntlm_from_smb:
                    assoc = self.rpc._assoc(flow, ts)
                    self.rpc._inspect_auth_value(
                        ts, f"{client_ip} -> {server_ip}", assoc,
                        RPC_C_AUTHN_GSS_NEGOTIATE, item["data"], "smb")

    def _drain_dcerpc(self, ts, flow, hs, client_ip, server_ip, from_client, pipe):
        self._drain_frames(ts, flow, hs, hs.buf, client_ip, server_ip,
                           from_client, pipe)

    def _drain_frames(self, ts, flow, hs, buf, client_ip, server_ip,
                      from_client, pipe=""):
        """Pull whole frag_length-framed PDUs out of `buf`, keep the partial."""
        while True:
            try:
                n = peek_frag_length(bytes(buf[:CO_HEADER_LEN]))
            except RPCError:
                # Framing is unrecoverable.  Report it, then resynchronise by
                # dropping this half-stream's backlog rather than guessing.
                self.rpc.emitter.emit(ts, "RPC-FRAG-ANOMALY",
                                      f"{client_ip} -> {server_ip}", {
                                          "reason": "unframeable frag_length",
                                          "buffered_bytes": len(buf),
                                      })
                del buf[:]
                return
            if n is None or len(buf) < n:
                return
            pdu = bytes(buf[:n])
            del buf[:n]
            self.rpc.process_pdu(ts, flow, client_ip, server_ip, pdu,
                                 from_client, pipe or hs.pipe_name)


class RPCWatch:
    """Single entry point.  Live capture, pcap replay and the self-test all
    funnel through process_packet, so what is tested is what runs."""

    def __init__(self, config: Config, sink=None):
        self.config = config
        self.emitter = Emitter(config, sink)
        self.rpc = RPCEngine(config, self.emitter)
        self.winrm = WinRMEngine(config, self.emitter, self.rpc)
        self.flows = FlowManager(config, self.rpc, self.winrm)

    def process_packet(self, pkt):
        if not pkt.haslayer("TCP"):
            return
        tcp = pkt["TCP"]
        if pkt.haslayer("IP"):
            src, dst = pkt["IP"].src, pkt["IP"].dst
        elif pkt.haslayer("IPv6"):
            src, dst = pkt["IPv6"].src, pkt["IPv6"].dst
        else:
            return
        payload = tcp_payload_bytes(pkt, tcp)
        ts = float(getattr(pkt, "time", time.time()))
        self.flows.handle_segment(ts, src, int(tcp.sport), dst, int(tcp.dport),
                                  payload)

    def feed(self, ts, src, sport, dst, dport, payload):
        """Framing-level entry point used by the self-test and pcap harnesses."""
        self.flows.handle_segment(ts, src, sport, dst, dport, payload)


def bpf_filter(config: Config) -> str:
    ports = sorted(set(config.rpc_ports) | {WINRM_HTTP_PORT, WINRM_HTTPS_PORT})
    clause = " or ".join(f"tcp port {p}" for p in ports)
    if config.dynamic_range:
        clause += " or (tcp and portrange 49152-65535)"
    return clause


# ---------------------------------------------------------------------------
# CLI / live capture
# ---------------------------------------------------------------------------


def _parse_nets(values):
    out = []
    for v in values or []:
        out.append(ipaddress.ip_network(v, strict=False))
    return out


def _parse_hosts(values):
    out = []
    for v in values or []:
        if "/" in v:
            out.append(ipaddress.ip_network(v, strict=False))
        else:
            out.append(ipaddress.ip_address(v))
    return out


def build_config(args) -> Config:
    rpc_ports = set(args.rpc_port or []) | {EPMAPPER_PORT, SMB_PORT, NBT_SESSION_PORT}
    return Config(
        window=args.window,
        zerologon_threshold=args.zerologon_threshold,
        epm_threshold=args.epm_threshold,
        dedup_seconds=args.dedup_seconds,
        min_severity=args.min_severity,
        local_nets=_parse_nets(args.local_net),
        dc_hosts=_parse_hosts(args.dc),
        allow_clients=set(args.allow_client or []),
        allow_interfaces=set(u.lower() for u in (args.allow_interface or [])),
        rpc_ports=rpc_ports,
        dynamic_range=args.dynamic_range,
        ntlm_from_smb=args.ntlm_from_smb,
        record_identities=not args.no_identities,
    )


def make_sink(as_json: bool):
    def sink(f: Finding):
        if as_json:
            sys.stdout.write(json.dumps(f.as_dict(), sort_keys=True) + "\n")
        else:
            sys.stdout.write(f.as_text() + "\n")
        sys.stdout.flush()
    return sink


def tcp_payload_bytes(pkt, tcp) -> bytes:
    """
    The raw TCP payload, taken from the wire bytes rather than the layer tree.

    bytes(tcp.payload) is wrong here.  Port 135 is "epmap", and scapy binds
    DceRpc5 to it, so the payload gets DISSECTED and bytes() then returns a
    re-serialised representation rather than what was on the wire.  For a
    complete, well-formed PDU the round trip is usually lossless; for a
    mid-stream TCP segment - half a PDU, or one PDU's tail followed by the
    next one's head - the dissector misreads it and rebuilds something else
    entirely, reordering fields.  A capture then yields different findings
    than the same bytes fed directly, and NetLogon NegotiateFlags in
    particular come back as zero.

    Slicing the original bytes by the header lengths avoids the layer tree
    completely, and the network-layer length field lets us drop any
    link-layer padding on short frames.
    """
    raw = getattr(tcp, "original", None) or bytes(tcp)
    off = (tcp.dataofs or 5) * 4
    if off >= len(raw):
        return b""
    data = raw[off:]
    seg_len = None
    try:
        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            seg_len = int(ip.len) - int(ip.ihl) * 4
        elif pkt.haslayer("IPv6"):
            seg_len = int(pkt["IPv6"].plen)
    except Exception:                       # malformed header: use what we have
        seg_len = None
    if seg_len is not None:
        n = seg_len - off
        if 0 <= n <= len(data):
            data = data[:n]
    return data


def run_capture(watch: RPCWatch, iface: str, bpf: str):
    """The ONE function that imports scapy.  Everything else is pure python."""
    from scapy.all import sniff  # noqa: F401
    sniff(iface=iface, filter=bpf, store=False, prn=watch.process_packet)


def run_pcap(watch: RPCWatch, path: str, bpf: str | None = None):
    from scapy.all import sniff  # noqa: F401
    kw = {"offline": path, "store": False, "prn": watch.process_packet}
    if bpf:
        kw["filter"] = bpf
    sniff(**kw)


TRANSMIT_PRIMITIVES = (
    "sendp(", "sendpfast(", "send(", "sr(", "sr1(", "srp(", "srp1(",
    "socket.socket", "sendto(", "L2socket", "L3socket", ".connect(",
    "os.system", "subprocess",
)


def assert_passive(path: str | None = None) -> list[str]:
    """Grep our own source for transmit primitives.  Same discipline as the
    rest of the suite: the passive invariant is asserted, not assumed."""
    path = path or os.path.abspath(__file__)
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    hits = []
    in_guard = False
    for i, line in enumerate(lines, 1):
        if "TRANSMIT_PRIMITIVES = (" in line:
            in_guard = True
            continue
        if in_guard:
            if line.strip() == ")":
                in_guard = False
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for prim in TRANSMIT_PRIMITIVES:
            if prim in line:
                hits.append(f"{i}: {stripped}")
                break
    return hits




# ===========================================================================
# In-app adapter (Ragnar): a snapshot-over-pcap wrapper around the streaming
# engine above, a Watchtower JSON-lines feed, and an aggregator-shaped
# selftest(). Detection-only: the module has no transmit primitive (asserted by
# assert_passive()); this adapter only reads a capture and classifies it.
#
# MODULE BOUNDARY: the existing in-app Relay/Coercion Watch already owns
# authentication-coercion (PetitPotam / PrinterBug / DFSCoerce / ShadowCoerce)
# by the same DCE/RPC interface UUIDs. So the two coercion-category codes
# (RPC-COERCION-INTERFACE-BIND / RPC-COERCION-CALL) are deliberately suppressed
# from this watcher's verdict, reasons and Watchtower feed — it focuses on the
# genuinely-new surface: Zerologon, NetLogon secure-channel posture, DCERPC
# auth-trailer posture, DCSync / remote-exec / backupkey / EPM-sweep, and
# WinRM/WS-Man posture. DCSync et al. are the interface category MINUS coercion.
# ===========================================================================

import struct           # noqa: E402  (adapter + selftest PDU encoders)
import subprocess       # noqa: E402
import tempfile         # noqa: E402
import threading        # noqa: E402
from datetime import datetime, timezone   # noqa: E402
from shutil import which as _which         # noqa: E402

# Coercion is Relay/Coercion Watch's job — don't double-report it here.
_DEFER_TO_RELAY = frozenset({"RPC-COERCION-INTERFACE-BIND", "RPC-COERCION-CALL"})

_ZEROLOGON_VERDICT_CODES = frozenset({
    "RPC-ZEROLOGON-ZERO-CHALLENGE", "RPC-ZEROLOGON-ZERO-CREDENTIAL",
    "RPC-ZEROLOGON-BRUTE-FORCE", "RPC-NETLOGON-PASSWORD-RESET-AFTER-BRUTE",
    "RPC-NETLOGON-UNSIGNED-BIND"})
_DCSYNC_VERDICT_CODES = frozenset({"RPC-DCSYNC-CALL"})
_CREDTHEFT_VERDICT_CODES = frozenset({
    "RPC-BACKUPKEY-ACCESS", "RPC-NETLOGON-PASSWORD-GET",
    "WINRM-BASIC-AUTH", "WINRM-UNENCRYPTED-PAYLOAD"})


def _rpc_verdict(findings):
    """Reduce the (coercion-suppressed) finding list to a card verdict + ranked list."""
    kept = [f for f in findings if f.code not in _DEFER_TO_RELAY]
    ranked = sorted(kept, key=lambda f: SEVERITY_RANK.get(f.severity, 0),
                    reverse=True)
    codes = {f.code for f in kept}
    if codes & _ZEROLOGON_VERDICT_CODES:
        return "zerologon", ranked
    if codes & _DCSYNC_VERDICT_CODES:
        return "dcsync", ranked
    if codes & _CREDTHEFT_VERDICT_CODES:
        return "credential-exposure", ranked
    worst = max((SEVERITY_RANK.get(f.severity, 0) for f in kept), default=0)
    if worst >= SEVERITY_RANK["high"]:
        return "exposure", ranked
    if worst >= SEVERITY_RANK["medium"]:
        return "posture", ranked
    return "clean", ranked


# --- Watchtower feed --------------------------------------------------------
_WT_LOG_DIR = os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_WT_DEDUP_S = 300.0
_WT_EMIT_SEV = frozenset(("high", "critical"))
_wt_lock = threading.Lock()
_wt_seen = {}


def _emit_watchtower(result):
    """Append HIGH/CRITICAL RPC/NetLogon/WinRM findings to <log-dir>/rpc_watch.jsonl in
    the shape Watchtower.normalize() reads. Coercion codes are already excluded from
    result['findings']. Deduped per (code, subject) over the window. Best-effort."""
    if not result.get("success"):
        return
    verdict = result.get("verdict", "clean")
    iface = result.get("interface")
    now = time.time()
    iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    with _wt_lock:
        for f in result.get("findings", []):
            if f.get("severity") not in _WT_EMIT_SEV:
                continue
            code = f.get("code")
            subj = f.get("subject")
            key = (code, subj)
            last = _wt_seen.get(key)
            if last is not None and now - last < _WT_DEDUP_S:
                continue
            _wt_seen[key] = now
            det = f.get("details") or {}
            cve = det.get("cve")
            lines.append(json.dumps({
                "module": "rpc_watch", "ts": now, "iso": iso, "iface": iface,
                "severity": f.get("severity"), "code": code, "codes": [code],
                "src": subj, "cves": [cve] if cve else [],
                "summary": f.get("title"), "verdict": verdict}))
        if len(_wt_seen) > 4096:
            cutoff = now - _WT_DEDUP_S
            for k in [k for k, t in _wt_seen.items() if t < cutoff]:
                _wt_seen.pop(k, None)
    if not lines:
        return
    try:
        os.makedirs(_WT_LOG_DIR, exist_ok=True)
        with open(os.path.join(_WT_LOG_DIR, "rpc_watch.jsonl"), "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def _capture_pcap(interface, seconds, bpf):
    """tcpdump a DCERPC/SMB/WinRM snapshot to a temp classic-pcap file.
    Returns (path, error). snaplen 1200 keeps the RPC bind/opnum + NTLMSSP +
    NetLogon stub intact. Detection-only."""
    if not _which("tcpdump"):
        return None, "tcpdump is not installed. Click Install to add it."
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        res = subprocess.run(
            ["timeout", str(int(seconds) + 3), "tcpdump", "-i", interface,
             "-nn", "-s", "1200", "-c", "20000", "-w", path, bpf],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=int(seconds) + 8)
        err = (res.stderr or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        err = ""
    except OSError as e:
        try:
            os.remove(path)
        except OSError:
            pass
        return None, "capture failed: {}".format(e)
    if (os.path.getsize(path) <= 24 and err
            and any(s in err.lower() for s in
                    ("permission", "no such device", "syntax error", "couldn't"))):
        try:
            os.remove(path)
        except OSError:
            pass
        return None, err.strip()[:200]
    return path, None


def do_rpc_watch(interface=None, seconds=20, dcs=None, local_nets=None):
    """Passive DCERPC / NetLogon / WinRM authentication-posture scan (detection-only).
    One tcpdump snapshot on `interface`, replayed through the streaming engine; reports
    the Zerologon chain (zero challenge / zero credential / brute-force / post-brute
    password reset), NetLogon secure-channel posture (unsigned bind, Secure-RPC cleared,
    weak crypto, unexpected DC), DCERPC auth-trailer posture (no-auth / no-integrity /
    downgrade), NTLM weaknesses (NTLMv1, no-MIC, no-signing, anonymous, LM key), DCSync /
    remote-exec / backup-key / EPM-sweep interface abuse, and WinRM/WS-Man posture.
    Authentication-COERCION is deferred to Relay/Coercion Watch. Never transmits."""
    if not interface:
        return {"success": False, "error": "no interface specified"}
    seconds = max(8, min(int(seconds or 20), 60))
    try:
        import scapy  # noqa: F401
    except Exception:
        return {"success": False, "interface": interface, "missing_tool": "scapy",
                "error": 'the Python "scapy" package is required for pcap dissection'}
    cfg_kw = {}
    if dcs:
        cfg_kw["dc_hosts"] = _parse_hosts(dcs)
    if local_nets:
        cfg_kw["local_nets"] = _parse_nets(local_nets)
    config = Config(**cfg_kw)
    bpf = bpf_filter(config)
    path, err = _capture_pcap(interface, seconds, bpf)
    if err:
        return {"success": False, "interface": interface, "error": err,
                "missing_tool": "tcpdump" if "not installed" in err else None}
    watch = RPCWatch(config)
    try:
        run_pcap(watch, path, None)      # bpf already applied at capture time
    except Exception as e:
        return {"success": False, "interface": interface,
                "error": "capture parse failed: {}".format(type(e).__name__)}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    emitted = list(watch.emitter.emitted)
    verdict, ranked = _rpc_verdict(emitted)
    # findings: coercion-suppressed, worst-first, as dicts for the UI + Watchtower.
    findings = [f.as_dict() for f in ranked]
    reasons, seen = [], set()
    for f in ranked:
        if f.code in seen:
            continue
        seen.add(f.code)
        subj = f.subject or "-"
        reasons.append("{}: {} [{}]".format(f.code, f.title, subj))
        if len(reasons) >= 8:
            break
    if not reasons:
        reasons = ["No Zerologon, NetLogon-posture, DCERPC-auth, DCSync/EPM or "
                   "WinRM exposure detected on this segment"]

    by_sev = {}
    for f in ranked:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    # How many coercion findings we deferred, for transparency in the card.
    deferred = sum(1 for f in emitted if f.code in _DEFER_TO_RELAY)

    result = {
        "success": True, "interface": interface, "seconds": seconds,
        "verdict": verdict, "reasons": reasons, "findings": findings,
        "by_severity": by_sev, "coercion_deferred_to_relay": deferred,
    }
    _emit_watchtower(result)
    return result


# ===========================================================================
# selftest — aggregator shape {'success', 'scenarios':[{name,pass,detail}]}.
# Builds real DCERPC / NTLMSSP / WinRM bytes with a test-side encoder and pushes
# them through the production ingestion path (RPCWatch.feed). Dependency-free.
# The PDU encoders are copied from the module's own offline suite so the in-app
# check needs no external test file.
# ===========================================================================
_NDR32 = "8a885d04-1ceb-11c9-9fe8-08002b104860"


def _st_uuid_wire(u):
    p = u.split("-")
    return (struct.pack("<IHH", int(p[0], 16), int(p[1], 16), int(p[2], 16))
            + bytes.fromhex(p[3] + p[4]))


def _st_sec_trailer(auth_type, level, value, pad=0, ctx=0):
    return struct.pack("<BBBBI", auth_type, level, pad, 0, ctx) + value


def _st_co_pdu(ptype, body, call_id=1, pfc=0x03, auth=None, vers=5, vers_minor=0):
    auth = auth or b""
    alen = (len(auth) - SEC_TRAILER_LEN) if auth else 0
    total = CO_HEADER_LEN + len(body) + len(auth)
    hdr = struct.pack("<BBBB4sHHI", vers, vers_minor, ptype, pfc,
                      b"\x10\x00\x00\x00", total, alen, call_id)
    return hdr + body + auth


def _st_bind_body(interfaces, ctx_ids=None, xfer=_NDR32, assoc_group=0):
    ctx_ids = ctx_ids or list(range(len(interfaces)))
    out = struct.pack("<HHI", 5840, 5840, assoc_group)
    out += struct.pack("<BBH", len(interfaces), 0, 0)
    for cid, (uuid, ver) in zip(ctx_ids, interfaces):
        out += struct.pack("<HBB", cid, 1, 0)
        out += _st_uuid_wire(uuid) + struct.pack("<I", ver)
        out += _st_uuid_wire(xfer) + struct.pack("<I", 2)
    return out


def _st_request_body(opnum, stub, ctx_id=0):
    return struct.pack("<IHH", len(stub), ctx_id, opnum) + stub


def _st_response_body(stub, ctx_id=0):
    return struct.pack("<IHBB", len(stub), ctx_id, 0, 0) + stub


def _st_ndr_wstr(s, unique=False, trailing_pad=True):
    out = b""
    if unique:
        out += struct.pack("<I", 0x00020000)
    data = (s + "\x00").encode("utf-16-le")
    n = len(s) + 1
    out += struct.pack("<III", n, 0, n) + data
    if trailing_pad:
        out += b"\x00" * ((4 - len(data) % 4) % 4)
    return out


def _st_req_challenge(primary, computer, challenge):
    return _st_ndr_wstr(primary, unique=True) + _st_ndr_wstr(computer) + challenge


def _st_authenticate3(primary, account, chan_type, computer, credential, flags):
    out = _st_ndr_wstr(primary, unique=True) + _st_ndr_wstr(account)
    out += struct.pack("<HH", chan_type, 0) + _st_ndr_wstr(computer)
    out += credential + struct.pack("<I", flags)
    return out


def _st_authenticate3_reply(server_cred, flags, rid, status=0):
    return server_cred + struct.pack("<III", flags, rid, status)


def _st_ntlm_neg(flags):
    return NTLMSSP_SIGNATURE + struct.pack("<II", 1, flags) + b"\x00" * 16


def _st_av_pairs(mic):
    out = b""
    if mic:
        out += struct.pack("<HH", MSV_AV_FLAGS, 4) + struct.pack("<I", 0x00000002)
    out += struct.pack("<HH", MSV_AV_TIMESTAMP, 8) + b"\x00" * 8
    out += struct.pack("<HH", MSV_AV_EOL, 0)
    return out


def _st_ntlmv2_blob(av_mic):
    body = struct.pack("<BBHI", 1, 1, 0, 0) + b"\x00" * 8 + b"\x22" * 8
    body += struct.pack("<I", 0)
    return b"\x33" * 16 + body + _st_av_pairs(av_mic)


def _st_ntlm_auth(flags, user="svc", domain="CORP", workstation="WS01",
                  ntlm_version=2, mic=False, av_mic=False, lm_len=24):
    uni = bool(flags & NTLMSSP_NEGOTIATE_UNICODE)

    def enc(s):
        return s.encode("utf-16-le") if uni else s.encode("latin-1")
    if ntlm_version == 1:
        nt = b"\x44" * 24
    else:
        nt = _st_ntlmv2_blob(av_mic)
    lm = b"\x55" * lm_len if lm_len else b""
    d_b, u_b, w_b = enc(domain), enc(user), enc(workstation)
    sess = b"\x66" * 16 if flags & NTLMSSP_NEGOTIATE_KEY_EXCH else b""
    header_len = 88 if mic else 72
    parts = [lm, nt, d_b, u_b, w_b, sess]
    offsets, cur = [], header_len
    for p in parts:
        offsets.append(cur)
        cur += len(p)
    out = NTLMSSP_SIGNATURE + struct.pack("<I", 3)
    for p, off in zip(parts, offsets):
        out += struct.pack("<HHI", len(p), len(p), off)
    out += struct.pack("<I", flags) + b"\x00" * 8
    if mic:
        out += b"\x77" * 16
    for p in parts:
        out += p
    return out


def _st_spnego(ntlm, kerberos=False):
    prefix = b"\x60\x28\x06\x06\x2b\x06\x01\x05\x05\x02"
    if kerberos:
        prefix += b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
    return prefix + ntlm


def _st_http_request(method, path, headers, body=b""):
    out = "{} {} HTTP/1.1\r\n".format(method, path).encode()
    for k, v in headers.items():
        out += "{}: {}\r\n".format(k, v).encode()
    return out + b"\r\n" + body


def _st_http_response(status, headers, body=b""):
    out = "HTTP/1.1 {} X\r\n".format(status).encode()
    for k, v in headers:
        out += "{}: {}\r\n".format(k, v).encode()
    return out + b"\r\n" + body


_GOOD_NTLM = (NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_SIGN
              | NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
              | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
              | NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_128
              | NTLMSSP_NEGOTIATE_KEY_EXCH)
_NORMAL_FLAGS = 0x612FFFFF
_EXPLOIT_FLAGS = 0x212FFFFF
_AUTH_TOKEN = b"\xaa" * 16


class _STHarness:
    def __init__(self, client="10.20.0.50", server="10.20.0.10", **cfg):
        self.client, self.server = client, server
        self.watch = RPCWatch(Config(**cfg))
        self.t = 1_700_000_000.0
        self.sport = 50000

    def tick(self, dt=0.01):
        self.t += dt
        return self.t

    def c2s(self, payload, dport=135, ts=None):
        self.watch.feed(ts or self.tick(), self.client, self.sport,
                        self.server, dport, payload)

    def s2c(self, payload, dport=135, ts=None):
        self.watch.feed(ts or self.tick(), self.server, dport,
                        self.client, self.sport, payload)

    @property
    def codes(self):
        return {f.code for f in self.watch.emitter.emitted}


def _st_bind(h, iface, level=None, auth_type=None, value=None, ctx=0,
             ptype=None):
    auth_type = RPC_C_AUTHN_GSS_NEGOTIATE if auth_type is None else auth_type
    ptype = PTYPE_BIND if ptype is None else ptype
    tr = None
    if level is not None:
        tr = _st_sec_trailer(auth_type, level, value if value else _AUTH_TOKEN)
    h.c2s(_st_co_pdu(ptype, _st_bind_body([(iface, 1)], ctx_ids=[ctx]), auth=tr))


def _st_netlogon_bind(h, level=None):
    _st_bind(h, IF_NETLOGON, level=level)
    _st_bind(h, IF_NETLOGON, level=level)


def _st_auth3(h, credential, flags, opnum=None, call_id=10):
    opnum = NRPC_SERVER_AUTHENTICATE3 if opnum is None else opnum
    stub = _st_authenticate3("\\\\DC01", "WS01$", 2, "WS01", credential, flags)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(opnum, stub), call_id=call_id))


def selftest():
    scen = []

    def check(name, ok, detail=""):
        scen.append({"name": name, "pass": bool(ok), "detail": str(detail)})

    # 1. Zerologon zero challenge.
    h = _STHarness(client="10.20.2.1")
    _st_netlogon_bind(h)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        NRPC_SERVER_REQ_CHALLENGE,
        _st_req_challenge("\\\\DC01", "WS01", b"\x00" * 8)), call_id=5))
    check("zerologon-zero-challenge",
          "RPC-ZEROLOGON-ZERO-CHALLENGE" in h.codes, sorted(h.codes))

    # 2. Random challenge stays quiet.
    h = _STHarness(client="10.20.2.2")
    _st_netlogon_bind(h)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        NRPC_SERVER_REQ_CHALLENGE,
        _st_req_challenge("\\\\DC01", "WS01", b"\x9f\x1c\x30\x77\xaa\x02\xbe\x51")),
        call_id=5))
    check("zerologon-random-challenge-quiet",
          "RPC-ZEROLOGON-ZERO-CHALLENGE" not in h.codes, sorted(h.codes))

    # 3. Zerologon zero credential + Secure-RPC cleared.
    h = _STHarness(client="10.20.2.3")
    _st_netlogon_bind(h)
    _st_auth3(h, b"\x00" * 8, _EXPLOIT_FLAGS)
    check("zerologon-zero-credential",
          "RPC-ZEROLOGON-ZERO-CREDENTIAL" in h.codes
          and "RPC-NETLOGON-NO-SECURE-RPC" in h.codes, sorted(h.codes))

    # 4. Real credential + AES-capable stays quiet.
    h = _STHarness(client="10.20.2.4")
    _st_netlogon_bind(h)
    _st_auth3(h, b"\x8a\x31\x02\xcc\x71\x4f\x90\x12", _NORMAL_FLAGS)
    check("zerologon-real-credential-quiet",
          "RPC-ZEROLOGON-ZERO-CREDENTIAL" not in h.codes
          and "RPC-NETLOGON-NO-SECURE-RPC" not in h.codes, sorted(h.codes))

    # 5. Brute-force threshold.
    h = _STHarness(client="10.20.2.8", zerologon_threshold=8, window=60)
    _st_netlogon_bind(h)
    for i in range(8):
        _st_auth3(h, b"\x00" * 8, _EXPLOIT_FLAGS, call_id=100 + i)
    check("zerologon-brute-force",
          "RPC-ZEROLOGON-BRUTE-FORCE" in h.codes, sorted(h.codes))

    # 6. NetLogon unsigned bind (default CONNECT-less bind).
    h = _STHarness(client="10.20.2.13")
    _st_netlogon_bind(h)
    check("netlogon-unsigned-bind",
          "RPC-NETLOGON-UNSIGNED-BIND" in h.codes, sorted(h.codes))

    # 7. Weak crypto (no AES).
    h = _STHarness(client="10.20.2.17")
    _st_netlogon_bind(h)
    _st_auth3(h, b"\x22" * 8, _NORMAL_FLAGS & ~NETLOGON_NEG_SUPPORTS_AES)
    check("netlogon-weak-crypto",
          "RPC-NETLOGON-WEAK-CRYPTO" in h.codes, sorted(h.codes))

    # 8. Negotiated reply flags inspected (Secure-RPC cleared in server reply).
    h = _STHarness(client="10.20.2.19")
    _st_netlogon_bind(h)
    _st_auth3(h, b"\x22" * 8, _NORMAL_FLAGS, call_id=42)
    h.s2c(_st_co_pdu(PTYPE_RESPONSE, _st_response_body(
        _st_authenticate3_reply(b"\x33" * 8, _EXPLOIT_FLAGS, 1001, 0)), call_id=42))
    check("netlogon-reply-flags-inspected",
          "RPC-NETLOGON-NO-SECURE-RPC" in h.codes, sorted(h.codes))

    # 9. Bind with no auth to a sensitive interface.
    h = _STHarness(client="10.20.1.1")
    _st_bind(h, IF_SAMR)
    check("rpc-bind-no-auth", "RPC-BIND-NO-AUTH" in h.codes, sorted(h.codes))

    # 10. Unauthenticated bind to a benign interface stays quiet.
    h = _STHarness(client="10.20.1.2")
    _st_bind(h, IF_SRVSVC)
    check("rpc-bind-no-auth-benign-quiet",
          "RPC-BIND-NO-AUTH" not in h.codes, sorted(h.codes))

    # 11. Below-integrity association.
    h = _STHarness(client="10.20.1.3")
    _st_bind(h, IF_SAMR, level=RPC_C_AUTHN_LEVEL_CONNECT)
    check("rpc-no-packet-integrity",
          "RPC-NO-PACKET-INTEGRITY" in h.codes, sorted(h.codes))

    # 12. NTLMv1 over an authenticated bind + auth3.
    h = _STHarness(client="10.20.4.2")
    neg = _st_spnego(_st_ntlm_neg(_GOOD_NTLM))
    _st_bind(h, IF_SAMR, level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, value=neg)
    h.c2s(_st_co_pdu(PTYPE_AUTH3, b"\x00" * 4, auth=_st_sec_trailer(
        RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
        _st_spnego(_st_ntlm_auth(_GOOD_NTLM, ntlm_version=1, mic=True)))))
    check("ntlmv1-in-use", "RPC-NTLMV1-IN-USE" in h.codes, sorted(h.codes))

    # 13. DCSync (DRSUAPI DRSGetNCChanges, opnum 3).
    h = _STHarness(client="10.20.3.6")
    _st_bind(h, IF_DRSUAPI, level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(3, b"\x00" * 32), call_id=2))
    check("dcsync-call", "RPC-DCSYNC-CALL" in h.codes, sorted(h.codes))

    # 14. Remote-exec interface (svcctl create service, opnum 12).
    h = _STHarness(client="10.20.3.8")
    _st_bind(h, IF_SVCCTL, level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(12, b"\x00" * 16), call_id=2))
    check("remote-exec-interface",
          "RPC-REMOTE-EXEC-INTERFACE" in h.codes, sorted(h.codes))

    # 15. Backup-key access (MS-BKRP).
    h = _STHarness(client="10.20.3.10")
    _st_bind(h, IF_BKRP, level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(0, b"\x00" * 8), call_id=2))
    check("backupkey-access", "RPC-BACKUPKEY-ACCESS" in h.codes, sorted(h.codes))

    # 16. EPM sweep over threshold.
    h = _STHarness(client="10.20.3.11", epm_threshold=20, window=60)
    _st_bind(h, IF_EPM)
    for i in range(21):
        h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(2, b"\x00" * 8), call_id=i))
    check("epm-sweep", "RPC-EPM-SWEEP" in h.codes, sorted(h.codes))

    # 17. WinRM cleartext + unencrypted payload.
    soap = (b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            b'<s:Body/></s:Envelope>')
    h = _STHarness(client="10.20.6.1")
    h.c2s(_st_http_request("POST", "/wsman", {
        "Host": "dc01:5985", "Content-Type": "application/soap+xml;charset=UTF-8",
        "Content-Length": str(len(soap))}, soap), dport=WINRM_HTTP_PORT)
    check("winrm-cleartext",
          "WINRM-CLEARTEXT-HTTP" in h.codes
          and "WINRM-UNENCRYPTED-PAYLOAD" in h.codes, sorted(h.codes))

    # 18. WinRM Basic auth (critical) — and the credential is never recorded.
    import base64 as _b64
    h = _STHarness(client="10.20.6.3")
    h.c2s(_st_http_request("POST", "/wsman", {
        "Host": "dc01:5985",
        "Authorization": "Basic " + _b64.b64encode(b"CORP\\admin:hunter2").decode()},
        b""), dport=WINRM_HTTP_PORT)
    blob = repr([f.as_dict() for f in h.watch.emitter.emitted])
    check("winrm-basic-auth",
          "WINRM-BASIC-AUTH" in h.codes and "hunter2" not in blob, sorted(h.codes))

    # 19. MODULE BOUNDARY: coercion codes are recognised by the engine but the
    #     in-app verdict/findings suppress them (Relay/Coercion Watch owns them).
    h = _STHarness(client="10.20.3.1")
    _st_bind(h, IF_EFSR_LSA)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        0, _st_ndr_wstr("\\\\10.99.99.99\\x\\y.txt")), call_id=3))
    raw_has_coercion = bool(h.codes & _DEFER_TO_RELAY)
    v, ranked = _rpc_verdict(list(h.watch.emitter.emitted))
    kept_codes = {f.code for f in ranked}
    check("coercion-recognised-but-deferred",
          raw_has_coercion and not (kept_codes & _DEFER_TO_RELAY),
          "raw={} kept={}".format(sorted(h.codes), sorted(kept_codes)))

    # 20. Verdict mapping: zerologon scenario -> 'zerologon'.
    h = _STHarness(client="10.20.2.3")
    _st_netlogon_bind(h)
    _st_auth3(h, b"\x00" * 8, _EXPLOIT_FLAGS)
    v, _ = _rpc_verdict(list(h.watch.emitter.emitted))
    check("verdict-zerologon", v == "zerologon", "verdict=%s" % v)

    # 21. Clean scenario -> 'clean'.
    h = _STHarness(client="10.20.9.9")
    _st_bind(h, IF_SRVSVC, level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    v, _ = _rpc_verdict(list(h.watch.emitter.emitted))
    check("verdict-clean", v == "clean", "verdict=%s codes=%s" % (v, sorted(h.codes)))

    # 22. Catalogue integrity: every declared code has a known severity.
    bad = [c for c, spec in FINDINGS.items() if spec[0] not in SEVERITY_RANK]
    check("catalogue-severity-integrity", not bad, bad)

    return {"success": all(s["pass"] for s in scen), "scenarios": scen}


if __name__ == "__main__":       # pragma: no cover - manual smoke test
    import pprint
    r = selftest()
    pprint.pprint([s for s in r["scenarios"] if not s["pass"]] or "ALL PASS")
    print("success:", r["success"])
