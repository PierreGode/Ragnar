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
# Terminal Server / Remote Desktop Licensing (lserver.exe), CVE-2024-38077
# "MadLicense".  No MS open specification exists for this interface, so the
# provenance of each constant is recorded next to it rather than assumed.
IF_TSLICENSING = "3d267954-eeb7-11d1-b94e-00c04fa3080d"
IF_BKRP = "3dde7c30-165d-11d1-ab8f-00805f14db40"
IF_EPM = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
IF_ISYSTEMACTIVATOR = "000001a0-0000-0000-c000-000000000046"
IF_SRVSVC = "4b324fc8-1670-01d3-1278-5a47bf6ee188"
IF_WKSSVC = "6bffd098-a112-3610-9833-46c3f87e345a"

# Promoted out of the reference table once they earned a rule of their own:
# MS-ICPR and MS-WCCE for ESC11, MS-DNSP for the ServerLevelPluginDll path.
IF_ICPR = "91ae6020-9e3c-11cf-8d7c-00aa00c091be"
IF_WCCE_CERTREQD = "d99e6e70-fc88-11d0-b498-00a0c90312f3"
# MS-CSRA, the CA REMOTE ADMINISTRATION interfaces.  Neither was catalogued
# before: MS-CSRA has its own IF_ENFORCEENCRYPTICERTADMIN, which demands
# PKT_PRIVACY exactly as IF_ENFORCEENCRYPTICERTREQUEST does for enrollment.
# So an admin bind below privacy is the ESC11 condition on the CA MANAGEMENT
# interface - strictly more powerful than enrollment, and unnumbered by the
# ESC catalogue.
IF_CSRA_ADMIND = "d99e6e71-fc88-11d0-b498-00a0c90312f3"
IF_CSRA_ADMIND2 = "7fe0d935-dda6-443f-85d0-1cfb58fe41dd"
IF_DNSSERVER = "50abc2a4-574d-40b3-9d66-ee4fd5fba076"
# MS-TSTS TermSrvEnumeration, reached over \pipe\LSM_API_service.  Opnum 8
# RpcGetSessionIds is an unimplemented stub on Win11/Server 2025 that crashes
# LSM on a single call (CVE-2025-26651).  Confirmed against MS-TSTS Appendix A.
IF_TSTS_ENUM = "88143fd0-c28d-4b2b-8fef-8d882f6a9390"
# The LSM container-management interface (TermSrv).  No MS open spec - the UUID
# and method names come from Akamai's research (Ben Barnea): it is meant only
# for Hyper-V containers over hvsocket, but endpoint multiplexing makes it
# reachable over \pipe\LSM_API_service.  A network bind is never legitimate
# (CVE-2022-37973 memory-leak crash, CVE-2022-37998 critical-section deadlock).
IF_LSM_CONTAINER = "c938b419-5092-4385-8360-7cdc9625976a"

INTERFACES = {
    IF_ICPR: ("icertpassage", "certenroll", "MS-ICPR ICertPassage"),
    IF_CSRA_ADMIND: ("certadmin", "certenroll",
                     "MS-CSRA ICertAdminD (CA remote administration)"),
    IF_CSRA_ADMIND2: ("certadmin2", "certenroll",
                      "MS-CSRA ICertAdminD2 (CA remote administration)"),
    IF_WCCE_CERTREQD: ("icertrequestd", "certenroll",
                       "MS-WCCE ICertRequestD"),
    IF_DNSSERVER: ("dnsserver", "dnsadmin", "MS-DNSP DNS Server Management"),
    IF_TSTS_ENUM: ("termsrv-enum", "lsm", "MS-TSTS TermSrvEnumeration (LSM)"),
    IF_LSM_CONTAINER: ("lsm-container", "lsm",
                       "TermSrv container interface (hvsocket-only; Akamai)"),
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
    IF_TSLICENSING: ("tslicensing", "exec",
                     "Terminal Server Licensing (MS-RDL, \\pipe\\HydraLsPipe)"),
    IF_WINREG: ("winreg", "exec", "MS-RRP Remote Registry"),
    IF_BKRP: ("backupkey", "directory", "MS-BKRP BackupKey Remote (DPAPI)"),
    IF_EPM: ("epmapper", "epm", "DCE Endpoint Mapper"),
    IF_ISYSTEMACTIVATOR: ("isystemactivator", "exec", "MS-DCOM ISystemActivator"),
    IF_SRVSVC: ("srvsvc", "other", "MS-SRVS Server Service Remote"),
    IF_WKSSVC: ("wkssvc", "other", "MS-WKST Workstation Service Remote"),
}

# ---------------------------------------------------------------------------
# Reference catalogue: network-reachable Windows RPC interfaces that rpcwatch
# knows about but has no RULE for.
#
# INTERFACES above is the WATCHED set - every entry there has at least one
# finding behind it, and its class drives behaviour (a "coercion" class arms
# the coercion-call path).  This table is deliberately separate and inert.
# Nothing here is classified, so nothing here can arm a rule by accident; it
# exists so that a bind to one of these is reported as a DOCUMENTED interface
# nobody is watching, rather than as an unknown one.
#
# That distinction is the whole value of the inventory finding.  "An
# uncatalogued UUID appeared" is noise on a real network.  "A documented
# Windows RPC interface with no rule behind it appeared" is an inventory fact,
# and "a UUID in neither table appeared" is third-party or bespoke RPC that no
# enumeration of Microsoft's own specs will ever cover.
#
# Sources are the MS open specs named in each value; the RD Licensing
# interface is in INTERFACES, not here, because it has a rule.  ALPC- and
# ncalrpc-only interfaces are excluded on purpose: they never reach a tap.
REFERENCE_INTERFACES = {
    # core / infrastructure
    "99fcfec4-5260-101b-bbcb-00aa0021347a": "MS-DCOM IObjectExporter",
    "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57": "MS-DCOM IRemoteActivation (legacy)",
    "378e52b0-c0a9-11cf-822d-00aa0051e40f": "MS-TSCH SASec",
    "f6beaff7-1e19-4fbb-9f8f-b89e2018337c": "MS-EVEN6 IEventService",
    "894de0c0-0d55-11d3-a322-00c04fa321a1": "MS-RSP InitShutdown",
    "d95afe70-a6d5-4259-822e-2c84da1ddb0d": "MS-RSP WindowsShutdown",
    "8fb6d884-2388-11d0-8c35-00c04fda2795": "MS-W32T W32Time",
    "f309ad18-d86a-11d0-a075-00c04fb68820": "MS-WMI IWbemLevel1Login",
    # file / print / SMB-adjacent
    "6bffd098-a112-3610-9833-012892020162": "MS-BRWSA browser (legacy)",
    "897e2e5f-93f3-4376-9c9c-fd2277495c27": "MS-FRS2 FrsTransport",
    "f5cc59b4-4264-101a-8c59-08002b2f8426": "MS-FRS1 frsrpc (legacy)",
    # identity / domain controller
    "3919286a-b10c-11d0-9ba8-00c04fd92ef5": "MS-DSSP dssetup",
    "b9785960-524f-11df-8b6d-83dcded72085": "MS-GKDI ISDKey",
    # role services, present only when the role is installed
    "6bffd098-a112-3610-9833-46c3f874532d": "MS-DHCPM dhcpsrv",
    "5b821720-f63b-11d0-aad2-00c04fc324db": "MS-DHCPM dhcpsrv2",
    "484809d6-4239-471b-b5bc-61df8c23ac48": "MS-TSTS LSM session",
    "5ca4a760-ebb1-11cf-8611-00a0245420ed": "MS-TSTS winstation_rpc",
    "906b0ce0-c70b-1067-b317-00dd010662da": "MS-CMPO IXnRemote (MSDTC)",
    "b97db8b2-4c63-11cf-bff6-08002be23f2f": "MS-CMRP clusapi",
    "ccd8c074-d0e5-4a40-92b4-d074faa6ba28": "MS-SWN Witness",
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

# --- MS-RRP registry hive save / load -------------------------------------
# How impacket's secretsdump.py takes credentials when it is NOT doing DCSync:
# enable and start RemoteRegistry over svcctl, OpenLocalMachine, open the SAM /
# SECURITY / SYSTEM hive with BaseRegCreateKey, then BaseRegSaveKey the hive out
# to a file and read it back over SMB.  The service start and the HKLM open were
# already reported as lateral-movement primitives, but the call that actually
# writes the credential hives out was not watched - so the dump was detected
# without being characterised.
#   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/
# Opnums confirmed against impacket's own MS-RRP table; transcribed again in
# the conformance harness.  Each is in the cleartext REQUEST header, so these
# rules hold at PKT_PRIVACY and the destination path grades rather than gates.
WINREG_SAVE_KEY = 20            # BaseRegSaveKey      - what secretsdump calls
WINREG_SAVE_KEY_EX = 31         # BaseRegSaveKeyEx
WINREG_LOAD_KEY = 13            # BaseRegLoadKey      - the write direction
WINREG_RESTORE_KEY = 19         # BaseRegRestoreKey   - the write direction
WINREG_CREATE_KEY = 6           # BaseRegCreateKey    - names the hive
WINREG_OPEN_KEY = 15            # BaseRegOpenKey      - names the hive

WINREG_HIVE_OPNAMES = {
    WINREG_SAVE_KEY: "BaseRegSaveKey",
    WINREG_SAVE_KEY_EX: "BaseRegSaveKeyEx",
    WINREG_LOAD_KEY: "BaseRegLoadKey",
    WINREG_RESTORE_KEY: "BaseRegRestoreKey",
}
WINREG_SAVE_OPNUMS = (WINREG_SAVE_KEY, WINREG_SAVE_KEY_EX)
WINREG_LOAD_OPNUMS = (WINREG_LOAD_KEY, WINREG_RESTORE_KEY)
# Opnums that NAME a key rather than moving one.  These only latch: opnum 6 is
# already reported as an exec primitive, so emitting here too would double-fire
# on one call.
WINREG_KEY_NAME_OPNUMS = (WINREG_CREATE_KEY, WINREG_OPEN_KEY)
# The three hives that hold credentials.  SAM has the local account hashes,
# SECURITY holds the LSA secrets and cached domain credentials, and SYSTEM
# carries the boot key needed to decrypt either.
WINREG_CREDENTIAL_HIVES = ("sam", "security", "system")
WINREG_HIVE_STAGE_SEVERITY = {"save": "high", "load": "high"}
# OS Credential Dumping: Security Account Manager.  Behaviour, not a CVE - a
# hive save is a legitimate backup operation performed by the wrong principal.
WINREG_TECHNIQUE = "T1003.002"
WINREG_TOOL_UNATTRIBUTABLE = "not attributable"

# --- AD CS escalations that are visible in the REQUEST ----------------------
# Every ESC misconfiguration lives somewhere a tap cannot see: a certificate
# template attribute, the CA's registry, or an object ACL.  What IS visible is
# the request, and only while the association is below PKT_PRIVACY - which is
# itself the ESC11 condition this module already reports.
#
# Four distinct wire shapes, which is why these get four codes rather than one
# with stages:
#   ESC6  - the SAN arrives in the ICPR ATTRIBUTES string (CA EditFlags)
#   ESC1  - subjectAltName inside the CSR, with a client-auth EKU
#   ESC17 - subjectAltName inside the CSR, with a server-auth EKU
#   ESC3  - the Certificate Request Agent EKU (on-behalf-of enrollment)
# and ESC15 injects Application Policies into the CSR (CVE-2024-49019).
#
# Out of scope here, recorded so the boundary is explicit: ESC2/ESC9/ESC12/
# ESC16 put nothing distinctive on the wire; ESC4/ESC5/ESC13/ESC14 are LDAP
# writes; ESC8 is NTLM relay over HTTP; ESC10 authenticates over Schannel.
ESC_OUT_OF_SCOPE = {
    "ESC2": "template EKU state; the request is indistinguishable",
    "ESC4": "AD ACL write on the template object - LDAP",
    "ESC5": "AD ACL write on PKI container objects - LDAP",
    "ESC8": "NTLM relay to the HTTP web-enrollment endpoint",
    "ESC9": "absent SID extension in the ISSUED certificate, not the request",
    "ESC10": "Schannel certificate mapping; authentication is over TLS",
    "ESC12": "HSM/key-storage weakness on the CA host",
    "ESC13": "msDS-OIDToGroupLink on the OID object - LDAP",
    "ESC14": "altSecurityIdentities on user/computer objects - LDAP",
    "ESC16": "CA DisableExtensionList; same shape as ESC9",
}

# Request attributes are LPWSTR, so every marker needs both encodings - the
# trap the Certighost chase attribute fell into once already.
ESC_SAN_ATTR = b"san:"
ESC_SAN_ATTR_W = "san:".encode("utf-16-le")
ESC_UPN_ATTR = b"upn="
ESC_UPN_ATTR_W = "upn=".encode("utf-16-le")
ESC_DNS_ATTR = b"dns="
ESC_DNS_ATTR_W = "dns=".encode("utf-16-le")
ESC_TEMPLATE_ATTR = b"certificatetemplate:"
ESC_TEMPLATE_ATTR_W = "certificatetemplate:".encode("utf-16-le")

# DER-encoded OID CONTENT bytes (no tag, no length), computed from the dotted
# forms and transcribed again in the conformance harness.  This module has no
# BER parser by design - DCERPC is NDR, not ASN.1 - so the CSR is SCANNED for
# these rather than decoded, and every finding says so through
# field_confidence: "oid-scan".
OID_CLIENT_AUTH = bytes.fromhex("2b06010505070302")             # 1.3.6.1.5.5.7.3.2
OID_SERVER_AUTH = bytes.fromhex("2b06010505070301")             # 1.3.6.1.5.5.7.3.1
OID_ANY_PURPOSE = bytes.fromhex("2b0601040182370a0c01")         # 311.10.12.1
OID_CERT_REQUEST_AGENT = bytes.fromhex("2b060104018237140201")  # 311.20.2.1
OID_UPN_OTHERNAME = bytes.fromhex("2b060104018237140203")       # 311.20.2.3
OID_APP_POLICIES = bytes.fromhex("2b060104018237150a")          # 311.21.10
OID_SUBJECT_ALT_NAME = bytes.fromhex("551d11")                  # 2.5.29.17

ESC15_CVE = "CVE-2024-49019"
# Steal or Forge Authentication Certificates.  These are legitimate
# enrollment operations asking for an identity the requester does not own, so
# they are attributed by behaviour and not by CVE - except ESC15, which is one.
ESC_TECHNIQUE = "T1649"
ESC_TOOL_UNATTRIBUTABLE = "not attributable"
ESC_SAN_VALUE_MAX = 256
# Characters legal in a UPN or DNS SAN value, spelled out as EXPLICIT ASCII.
# str.isalnum() is Unicode-aware, so UTF-16LE-decoding the binary that follows
# an attributes string yields letters like U+0100 that pass it - which is how
# a DER byte ended up glued to a reported name.
ESC_SAN_VALUE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789.-_@$")

# --- MS-CSRA opnums --------------------------------------------------------
# ICertAdminD occupies 3-30 and ICertAdminD2 31-48.  The ICertAdminD table is
# stated outright by MS-CSRA 3.1.4.1.  Five ICertAdminD2 values are confirmed
# by Microsoft's own section titles: 37 SetCASecurity, 40 GetAuditFilter,
# 42 GetOfficerRights, 44 GetConfigEntry, 45 SetConfigEntry.
#
# CSRA_SET_OFFICER_RIGHTS = 43 is DERIVED, not directly sourced.  It is the one
# method the full IDL places between the confirmed 42 and 44, so there is no
# room for another value - but it is flagged derived the same way
# TLSRpcConnect opnum 1 is, and the conformance harness asserts the flag.
CSRA_SET_EXTENSION = 3
CSRA_SET_ATTRIBUTES = 4
CSRA_RESUBMIT_REQUEST = 5
CSRA_DENY_REQUEST = 6
CSRA_SERVER_CONTROL = 17
CSRA_SET_CA_PROPERTY = 33
CSRA_SET_CA_SECURITY = 37
CSRA_SET_AUDIT_FILTER = 41
CSRA_SET_OFFICER_RIGHTS = 43          # derived; see above
CSRA_SET_CONFIG_ENTRY = 45
CSRA_IMPORT_KEY = 46

CSRA_OPNAMES = {
    CSRA_SET_EXTENSION: "SetExtension",
    CSRA_SET_ATTRIBUTES: "SetAttributes",
    CSRA_RESUBMIT_REQUEST: "ResubmitRequest",
    CSRA_DENY_REQUEST: "DenyRequest",
    CSRA_SERVER_CONTROL: "ServerControl",
    CSRA_SET_CA_PROPERTY: "SetCAProperty",
    CSRA_SET_CA_SECURITY: "SetCASecurity",
    CSRA_SET_AUDIT_FILTER: "SetAuditFilter",
    CSRA_SET_OFFICER_RIGHTS: "SetOfficerRights",
    CSRA_SET_CONFIG_ENTRY: "SetConfigEntry",
    CSRA_IMPORT_KEY: "ImportKey",
}
# Manipulating a PENDING request - the Manage Certificates half of ESC7.
CSRA_REQUEST_OPNUMS = (CSRA_SET_EXTENSION, CSRA_SET_ATTRIBUTES,
                       CSRA_RESUBMIT_REQUEST, CSRA_DENY_REQUEST)
# Reconfiguring the CA - the Manage CA half, and how ESC6 and ESC11 get
# ENABLED in the first place.  SetAuditFilter is here because turning off CA
# auditing is an anti-forensic step, not a tuning change.
CSRA_CONFIG_OPNUMS = (CSRA_SET_CA_PROPERTY, CSRA_SET_CA_SECURITY,
                      CSRA_SET_AUDIT_FILTER, CSRA_SET_OFFICER_RIGHTS,
                      CSRA_SET_CONFIG_ENTRY, CSRA_IMPORT_KEY)
CSRA_DERIVED_OPNUMS = (CSRA_SET_OFFICER_RIGHTS,)
CSRA_INTERFACES = (IF_CSRA_ADMIND, IF_CSRA_ADMIND2)
# MS-CSRA 3.1.4.1: with IF_ENFORCEENCRYPTICERTADMIN set the CA refuses any
# call below PKT_PRIVACY.  Same bar as enrollment, same reasoning as ESC11.
CSRA_REQUIRED_LEVEL = 6               # RPC_C_AUTHN_LEVEL_PKT_PRIVACY
CSRA_STAGE_SEVERITY = {
    "bind-below-privacy": "high",
    "request-manipulation": "critical",
    "config-write": "critical",
    "server-control": "high",
}

# MS-LSAD secret access.  This is how the DPAPI domain backup key is actually
# taken: mimikatz lsadump::backupkeys, SharpDPAPI backupkey and DSInternals
# Get-LsaBackupKey all call LsarRetrievePrivateData for the LSA secret
# G$BCKUPKEY_*.  None of them use MS-BKRP, which is the LEGITIMATE protocol for
# the same key material - so watching BKRP alone misses every one of them.
#   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/
#     2c6f3cf9-d792-4e8b-9af5-5470f636c20a   (3.1.4 opnum table)
# Every opnum below is in the cleartext REQUEST header, so these rules hold at
# PKT_PRIVACY; the secret NAME is NDR in the body and grades, never gates.
# The conformance harness carries its own transcribed copy of each value.
LSA_CREATE_SECRET = 16          # LsarCreateSecret
LSA_OPEN_SECRET = 28            # LsarOpenSecret  (names the secret; latch only)
LSA_SET_SECRET = 29             # LsarSetSecret   (handle-based write)
LSA_QUERY_SECRET = 30           # LsarQuerySecret (handle-based read)
LSA_STORE_PRIVATE_DATA = 42     # LsarStorePrivateData    (names the secret)
LSA_RETRIEVE_PRIVATE_DATA = 43  # LsarRetrievePrivateData (names the secret)

LSA_SECRET_OPNAMES = {
    LSA_CREATE_SECRET: "LsarCreateSecret",
    LSA_OPEN_SECRET: "LsarOpenSecret",
    LSA_SET_SECRET: "LsarSetSecret",
    LSA_QUERY_SECRET: "LsarQuerySecret",
    LSA_STORE_PRIVATE_DATA: "LsarStorePrivateData",
    LSA_RETRIEVE_PRIVATE_DATA: "LsarRetrievePrivateData",
}
# Opnums that act on a handle opened earlier; the name comes from the
# association latch set by LsarOpenSecret, when that was readable.
LSA_SECRET_HANDLE = (LSA_SET_SECRET, LSA_QUERY_SECRET)
LSA_SECRET_READ_OPNUMS = (LSA_RETRIEVE_PRIVATE_DATA, LSA_QUERY_SECRET)
LSA_SECRET_WRITE_OPNUMS = (LSA_STORE_PRIVATE_DATA, LSA_SET_SECRET,
                           LSA_CREATE_SECRET)
# RPC_UNICODE_STRING buffers are UTF-16LE, so an ASCII-only marker would never
# match - the same trap the Certighost chase attribute fell into.
LSA_DPAPI_BACKUP_MARKER = "G$BCKUPKEY"
LSA_DPAPI_BACKUP_MARKER_W = LSA_DPAPI_BACKUP_MARKER.encode("utf-16-le")
LSA_POLICY_HANDLE_LEN = 20      # [MS-DTYP] context handle: attributes + GUID
LSA_SECRET_NAME_MAX = 512       # sanity bound on the conformant array count
# Behaviour, not a CVE: retrieving an LSA secret is a legitimate privileged
# operation performed by the wrong principal.  T1003.004 is LSA Secrets.
LSA_TECHNIQUE_CREDS = "T1003.004"
LSA_TOOL_UNATTRIBUTABLE = "not attributable"

# MS-BKRP BackuprKey (opnum 0) selects its operation with pguidActionAgent, an
# [in] GUID* in the NDR stub - NOT in the cleartext header.
#   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp/
#     7accb903-3863-4385-9c99-11af8c18d656
BKRP_BACKUP_GUID = "7f752b10-178e-11d1-ab8f-00805f14db40"
BKRP_RESTORE_GUID_WIN2K = "7fe94d50-178e-11d1-ab8f-00805f14db40"
BKRP_RETRIEVE_BACKUP_KEY_GUID = "018ff48a-eaba-40c6-8f6d-72370240e967"
BKRP_RESTORE_GUID = "47270c64-2fc7-499b-ac5b-0e37cdce899a"
# guid -> (stage, severity).  The wrap and public-key fetches are what every
# ordinary domain client does on a master-key backup, which is why Windows own
# event 4692 is documented as noisy; they are recorded, not alerted on.  Only
# the unwraps decrypt somebody's secret.
BKRP_ACTIONS = {
    BKRP_BACKUP_GUID: ("wrap", "low"),
    BKRP_RETRIEVE_BACKUP_KEY_GUID: ("public-key", "low"),
    BKRP_RESTORE_GUID_WIN2K: ("unwrap", "high"),
    BKRP_RESTORE_GUID: ("unwrap", "high"),
}
BKRP_GUID_SCAN_BYTES = 24   # referent id + GUID, however the stub marshals it

# MS-DRSR, the directory replication interface.  Every opnum below is in the
# cleartext REQUEST header, so these rules hold at PKT_PRIVACY; the stub - DSA
# GUID, naming context, extended operation, and the secrets themselves - is
# NDR inside the sealed body and is never mined.
#   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/
# The conformance harness carries its own transcribed copy of each value.
DRS_BIND = 0                   # IDL_DRSBind
DRS_GET_NC_CHANGES = 3         # IDL_DRSGetNCChanges - the DCSync pull
DRS_REPLICA_ADD = 5            # IDL_DRSReplicaAdd - the DCShadow push trigger
DRS_CRACK_NAMES = 12           # IDL_DRSCrackNames - benign; member servers call it
DRS_OPNAMES = {
    DRS_BIND: "IDL_DRSBind",
    DRS_GET_NC_CHANGES: "IDL_DRSGetNCChanges",
    DRS_REPLICA_ADD: "IDL_DRSReplicaAdd",
    DRS_CRACK_NAMES: "IDL_DRSCrackNames",
}
# Only these two decide anything.  Bind and CrackNames are what every member
# server, Exchange box and admin tool does all day, and they stay silent.
DRS_WATCHED_OPNUMS = (DRS_GET_NC_CHANGES, DRS_REPLICA_ADD)
DRS_SILENT_OPNUMS = (DRS_BIND, DRS_CRACK_NAMES)

# Neither technique has a CVE - they are abuse of a working feature - so the
# findings carry ATT&CK ids for ticketing instead, and say outright that the
# tool cannot be named from the wire.
DRS_STAGE_SEVERITY = {
    "call": "critical",             # non-DC pulling from a known DC
    "unlisted-server": "high",      # neither end listed: config gap or rogue pair
    "trigger": "high",              # ReplicaAdd from a non-DC
    "rogue-source": "critical",     # a DC pulling from a non-DC
}
DRS_TECHNIQUE_DCSYNC = "T1003.006"
DRS_TECHNIQUE_ROGUE_DC = "T1207"
DRS_TOOL_UNATTRIBUTABLE = "not attributable"

# ept_map's REPLY carries a tower: floor 4 is the TCP port, floor 5 an IPv4
# address.  Only the port is taken.  An IPv4 host floor cannot carry a v6
# address and how Windows fills the tower over v6 is unmeasured here, so the
# learned port is keyed to the server of the 5-TUPLE THE REPLY RODE ON, never
# to the tower's own host floor.
EPM_MAP_OPNUM = 3
EPM_TOWER_TCP_PROTO = 0x07     # protocol identifier for TCP in a floor
EPM_TOWER_MAX_FLOORS = 8

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

# WS-Man compatibility listeners.  EnableCompatibilityHttpListener and its
# HTTPS twin put /wsman on tcp/80 and tcp/443, and the optional WinRM IIS
# Extension serves it from IIS on the same two ports.  Both are off by
# default on Windows, and both are indistinguishable from ordinary web
# traffic until the request line is read.
#
# So they are opt-in here, for the same reason --dynamic-range and --ipv6-eh
# are: watching 80 and 443 on a datacentre segment means watching the web,
# and on a Zero 2W that cost is real.  Everything downstream still gates on
# the /wsman path, so enabling them does not turn rpcwatch into an HTTP IDS.
WSMAN_COMPAT_HTTP_PORT = 80
WSMAN_COMPAT_HTTPS_PORT = 443
HTTPAPI_BANNER = "microsoft-httpapi"
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
    "RPC-PRINTNIGHTMARE-DRIVER-ADD": (
        "critical", "interface",
        "Printer driver installation call (PrintNightmare CVE-2021-34527 / "
        "CVE-2021-1675); opnum is cleartext even when the stub is sealed"),
    "RPC-EVENTLOG-BACKUP-WRITE": (
        "critical", "interface",
        "MS-EVEN event-log backup used as an arbitrary file-write primitive "
        "(EventLogin, CVE-2025-29969 / CVE-2026-50502) - off-box source or a "
        "destination that is not a .evtx log"),
    "RPC-EVENTLOG-PATH-PROBE": (
        "low", "interface",
        "Burst of ElfrOpenBELW opens against varied paths - the unfixed "
        "arbitrary-path-existence check in MS-EVEN, used for enumeration"),
    "RPC-LSM-CONTAINER-REMOTE": (
        "high", "interface",
        "Bind to the LSM container interface (hvsocket-only) over the network "
        "- never legitimate remotely; a sustained call loop crashes LSM "
        "(CVE-2022-37973 / CVE-2022-37998)"),
    "RPC-LSM-GETSESSIONIDS-CRASH": (
        "high", "interface",
        "MS-TSTS RpcGetSessionIds (opnum 8) from the network - an "
        "unimplemented stub on current builds that crashes LSM on one call "
        "(CVE-2025-26651)"),
    "RPC-ADCS-CHASE": (
        "critical", "interface",
        "AD CS enrollment host opened an outbound LSARPC bind to a non-DC "
        "shortly after serving a certificate request - the Certighost DC "
        "'chase' (CVE-2026-54121)"),
    "RPC-CERTENROLL-RELAY-LEVEL": (
        "high", "interface",
        "AD CS certificate enrollment interface bound below "
        "RPC_C_AUTHN_LEVEL_PKT_PRIVACY (ESC11) - either "
        "IF_ENFORCEENCRYPTICERTREQUEST is off or an NTLM relay is in "
        "progress"),
    "RPC-DNS-SERVERLEVELPLUGINDLL": (
        "critical", "interface",
        "R_DnssrvOperation setting ServerLevelPluginDll - the DNS server "
        "will load this DLL in-process as SYSTEM (DnsAdmin to SYSTEM)"),
    "RPC-INTERFACE-UNCATALOGUED": (
        "low", "interface",
        "Bind to an RPC interface with no rule behind it - a documented "
        "Windows interface nobody is watching, or third-party RPC entirely; "
        "inventory, not a vulnerability"),
    "RPC-WINREG-RELAY-FALLBACK": (
        "high", "auth",
        "Remote Registry bound over ncacn_ip_tcp at RPC_C_AUTHN_LEVEL_CONNECT "
        "(CVE-2024-43532) - the insecure transport fallback used for NTLM relay"),
    "RPC-LSA-ANONYMOUS-COERCION": (
        "critical", "interface",
        "Unauthenticated coercion call on the LSARPC pipe (CVE-2022-26925, "
        "PetitPotam) - anonymous access is the vulnerability"),
    "RPC-RUNTIME-BINDACK-UNDERFLOW": (
        "critical", "protocol",
        "Malformed big-endian bind_ack with a zero secondary address length "
        "(CVE-2022-26809) - the RPC runtime integer underflow"),
    "WINRM-HTTPSYS-ACCEPT-ENCODING": (
        "high", "winrm",
        "Malformed Accept-Encoding with an empty coding-list element "
        "(CVE-2021-31166 / CVE-2022-21907 http.sys kernel RCE)"),
    "RPC-TSLICENSING-PREAUTH": (
        "critical", "interface",
        "RD Licensing interface reached below RPC_C_AUTHN_LEVEL_PKT_PRIVACY "
        "(CVE-2024-38077 MadLicense) - heap spray or the overflow call"),
    "RPC-WINSPOOL-RELAY-LEVEL": (
        "high", "auth",
        "IRemoteWinSpool bound below RPC_C_AUTHN_LEVEL_PKT_PRIVACY "
        "(CVE-2021-1678) - the insufficient auth level an NTLM relay needs"),
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
    "RPC-DRS-PORT-LEARNED": (
        "info", "interface",
        "DRSUAPI's dynamic port learned from an ept_map reply - the port to "
        "pin with --rpc-port so replication is captured without a range"),
    "RPC-DRS-DCSYNC": (
        "critical", "interface",
        "DRSUAPI replication pull (IDL_DRSGetNCChanges) with an end that is "
        "not a known DC - the DCSync behaviour; no CVE, technique T1003.006"),
    "RPC-DRS-DCSHADOW": (
        "critical", "interface",
        "DRSUAPI replication involving a host that is not a known DC - the "
        "DCShadow behaviour; no CVE, technique T1207"),
    "RPC-DCSYNC-CALL": (
        "critical", "interface",
        "DRSUAPI DRSGetNCChanges - directory replication (DCSync) request"),
    "RPC-REMOTE-EXEC-INTERFACE": (
        "high", "interface",
        "Remote service / scheduled-task / registry execution primitive invoked"),
    "RPC-BACKUPKEY-ACCESS": (
        "high", "interface",
        "MS-BKRP BackuprKey - DPAPI domain backup key access"),
    "RPC-LSA-SECRET-READ": (
        "high", "interface",
        "MS-LSAD secret read - LSA private data / secret value retrieved"),
    "RPC-LSA-SECRET-WRITE": (
        "high", "interface",
        "MS-LSAD secret write - LSA private data / secret value stored"),
    "RPC-CERTENROLL-ESC1-SAN": (
        "critical", "interface",
        "ESC1 - enrollment request carries a subjectAltName with a client-auth EKU"),
    "RPC-CERTENROLL-ESC3-AGENT": (
        "high", "interface",
        "ESC3 - enrollment request carries the Certificate Request Agent EKU"),
    "RPC-CERTENROLL-ESC6-SAN-ATTR": (
        "critical", "interface",
        "ESC6 - SAN supplied in the ICPR request attributes string"),
    "RPC-CERTENROLL-ESC15-APP-POLICY": (
        "critical", "interface",
        "ESC15 - Application Policies injected into the certificate request"),
    "RPC-CERTENROLL-ESC17-DNS": (
        "high", "interface",
        "ESC17 - enrollment request names a DNS identity with a server-auth EKU"),
    "RPC-CERTADMIN-REMOTE": (
        "high", "interface",
        "MS-CSRA CA remote administration - posture or mutating call"),
    "RPC-WINREG-HIVE-SAVE": (
        "high", "interface",
        "MS-RRP registry hive written to or loaded from a caller-named file"),
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
        "WS-Man traffic on a cleartext HTTP listener (tcp/5985, or "
        "tcp/80 with --wsman-compat) - no transport encryption"),
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
    "WINRM-ANON-IDENTIFY": (
        "low", "winrm",
        "Request to the anonymous WS-Man Identify endpoint (/wsman-anon/"
        "identify) - a pre-auth confirmation that a WinRM listener exists"),
    "WINRM-WEC-SUBSCRIPTION": (
        "low", "winrm",
        "Windows Event Collector source-initiated subscription endpoint "
        "(/wsman/SubscriptionManager/WEC) in use over cleartext HTTP"),
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
    # The raw length is kept, not just the decoded string: CVE-2022-26809 turns
    # on sec_addr_len being zero, which an empty string alone cannot distinguish
    # from a parse that simply found nothing.
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
    return {"sec_addr": sec_addr, "sec_addr_len": sec_addr_len,
            "results": results}


def parse_bind_nak(pdu: bytes, hdr: dict) -> dict:
    big = hdr["big_endian"]
    reason = u16(pdu, CO_HEADER_LEN, big)
    return {
        "reject_reason": reason,
        "reject_reason_name": NAK_REASONS.get(reason, f"unknown({reason})"),
    }


def lsa_secret_name(stub: bytes) -> tuple:
    """
    Pull the secret name out of an LsarRetrievePrivateData /
    LsarStorePrivateData / LsarOpenSecret / LsarCreateSecret stub.

    After the 20-byte policy context handle comes an RPC_UNICODE_STRING whose
    buffer is a conformant varying array:

        Length(2) MaximumLength(2) referent(4) MaxCount(4) Offset(4)
        ActualCount(4) then ActualCount UTF-16LE code units

    The Buffer is [size_is(MaximumLength/2), length_is(Length/2)] WCHAR*, so
    it is a conformant VARYING array and carries three counts, not one: the
    chars begin 20 bytes past the string header, not 16.  Getting that wrong
    is the NDR-alignment bug all over again, and it was caught here only
    because the test encoder does not share this model.

    Returns (name, field_confidence).  The exact walk is tried first and a
    marker scan is the LABELLED fallback - never silently substituted, the
    lesson from the NetLogon tail-anchor bug.
    """
    name = handle_then_unicode_string(stub)
    if name:
        return name, "exact"
    if LSA_DPAPI_BACKUP_MARKER_W in stub:
        return LSA_DPAPI_BACKUP_MARKER + "*", "marker-scan"
    return None, "unreadable"


def handle_then_unicode_string(stub: bytes):
    """
    The leading "20-byte context handle, then one RPC_UNICODE_STRING" shape.

    MS-LSAD's LsarRetrievePrivateData and MS-RRP's BaseRegSaveKey,
    BaseRegOpenKey and BaseRegCreateKey all begin this way, confirmed against
    impacket's own structures.  One implementation serves all of them, because
    the three-count conformant VARYING array is exactly the detail this module
    got wrong once and should not get wrong again in a second copy.
    """
    off = LSA_POLICY_HANDLE_LEN
    if len(stub) < off + 20:
        return None
    length = int.from_bytes(stub[off:off + 2], "little")
    referent = int.from_bytes(stub[off + 4:off + 8], "little")
    actual = int.from_bytes(stub[off + 16:off + 20], "little")
    start = off + 20
    if not (referent and 0 < actual <= LSA_SECRET_NAME_MAX
            and length <= actual * 2
            and start + actual * 2 <= len(stub)):
        return None
    try:
        name = stub[start:start + actual * 2].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return name.rstrip(chr(0)) or None


def bkrp_action_guid(stub: bytes):
    """
    Find pguidActionAgent in a BackuprKey stub.

    Whether the [in] GUID* marshals with a referent id first depends on the
    IDL pointer_default, which MS-BKRP's method page does not state - so the
    GUID is located by matching the four documented values rather than by
    trusting a fixed offset.  The NDR cross-check tier pins the real offset
    against impacket.
    """
    last = min(len(stub), BKRP_GUID_SCAN_BYTES) - 15
    for off in range(0, max(last, 0)):
        g = uuid_from_wire(stub, off, False)
        if g in BKRP_ACTIONS:
            return g
    return None


def _attr_value(low: bytes, marker: bytes, wide: bool,
                original: bytes = b"") -> str:
    """
    Text following an attributes-string marker, to the next delimiter.

    The marker is located in the case-folded copy but the value is sliced out
    of the ORIGINAL bytes, so a mixed-case name is reported as it was sent
    rather than silently lowercased.
    """
    i = low.find(marker)
    if i < 0:
        return ""
    src = original if len(original) == len(low) else low
    raw = src[i + len(marker):i + len(marker) + ESC_SAN_VALUE_MAX * (2 if wide else 1)]
    try:
        text = raw.decode("utf-16-le", "ignore") if wide else raw.decode("latin-1")
    except UnicodeDecodeError:
        return ""
    # A WHITELIST, not a delimiter list.  An attributes string is followed
    # immediately by the request blob in a real marshalled CertServerRequest,
    # with no terminator between them, so anything that merely stops at known
    # separators runs straight into binary and reports a name with DER glued
    # to the end of it.  Found by the impacket cross-check, which lays the
    # bytes out the way the wire really does.
    out = []
    for ch in text:
        if ch in ESC_SAN_VALUE_CHARS:
            out.append(ch)
        else:
            break
    return "".join(out)[:ESC_SAN_VALUE_MAX].strip()


def same_principal(account: str, san_value: str) -> bool:
    """
    Is a SAN value naming the account that authenticated the association?

    account is DOMAIN\\user from NTLM; san_value may be a bare name or a UPN.
    Only the account portion is compared, case-folded, with a trailing $
    dropped so a machine account matches its own UPN.  This decides ESC6's
    severity, so a wrong answer under-reports rather than over-reports: an
    unmatched pair is treated as impersonation.
    """
    if not account or not san_value:
        return False
    user = account.split("\\")[-1].strip().lower().rstrip("$")
    cand = san_value.strip().lower()
    if "@" in cand:
        cand = cand.split("@", 1)[0]
    cand = cand.rstrip("$")
    return bool(user) and user == cand


def certenroll_request_shape(stub: bytes) -> dict:
    """
    What can be read out of an UNSEALED MS-ICPR CertServerRequest.

    Two different places matter and they mean different things.  The
    ATTRIBUTES string is LPWSTR name:value text, so a "san:" there is the
    CA-level ESC6 path.  The CSR is DER, and this module has no BER parser by
    design - DCERPC is NDR - so the request is SCANNED for known OID content
    bytes rather than decoded.  Everything derived that way is reported with
    field_confidence "oid-scan" so it is never mistaken for a parse.
    """
    if not stub:
        return {}
    low = stub.lower()

    def has(ascii_m, wide_m):
        return ascii_m in low or wide_m in low

    san_attr = has(ESC_SAN_ATTR, ESC_SAN_ATTR_W)
    wide = ESC_SAN_ATTR_W in low
    out = {
        "san_attribute": san_attr,
        "template_named": has(ESC_TEMPLATE_ATTR, ESC_TEMPLATE_ATTR_W),
        "attr_upn": has(ESC_UPN_ATTR, ESC_UPN_ATTR_W),
        "attr_dns": has(ESC_DNS_ATTR, ESC_DNS_ATTR_W),
        "csr_subject_alt_name": OID_SUBJECT_ALT_NAME in stub,
        "csr_upn_othername": OID_UPN_OTHERNAME in stub,
        "eku_client_auth": OID_CLIENT_AUTH in stub,
        "eku_server_auth": OID_SERVER_AUTH in stub,
        "eku_any_purpose": OID_ANY_PURPOSE in stub,
        "eku_request_agent": OID_CERT_REQUEST_AGENT in stub,
        "app_policies": OID_APP_POLICIES in stub,
    }
    out["san_value"] = ""
    if san_attr:
        for marker, wide_marker in ((ESC_UPN_ATTR, ESC_UPN_ATTR_W),
                                    (ESC_DNS_ATTR, ESC_DNS_ATTR_W)):
            v = _attr_value(low, wide_marker if wide else marker, wide, stub)
            if v:
                out["san_value"] = v
                break
    return out


def parse_epm_tower(blob: bytes) -> dict:
    r"""
    Pull the interface UUID and the TCP port out of an ept_map tower.

    A tower is a floor count followed by floors, each
    `lhs_length(2) | protocol id + lhs data | rhs_length(2) | rhs data`
    (MS-RPCE 2.2.1.2.5).  Rather than unmarshal the NDR wrapper around it -
    conformant arrays behind a pointer behind a handle - this scans for the
    two floors whose shapes are unambiguous:

      interface : 13 00 0D <16-byte UUID LE> <major LE> 02 00 <minor LE>
      TCP port  : 01 00 07 02 00 <port BIG-endian>

    The port is BIG-endian inside an otherwise little-endian PDU; that is in
    the spec and is the single easiest thing to get backwards, so the NDR
    cross-check builds these towers with impacket and the conformance harness
    carries its own copy of both floor shapes.

    Floor 5 (`01 00 09 04 00 <IPv4>`) is deliberately NOT returned: an IPv4
    host floor cannot carry a v6 address, and how Windows fills the tower
    over v6 is unmeasured here, so the caller keys the learned port to the
    5-tuple the PDU rode on instead.
    """
    out = {"interface": None, "tcp_port": None}
    i = blob.find(b"\x13\x00\x0d")
    if i >= 0 and i + 3 + 18 <= len(blob):
        out["interface"] = uuid_from_wire(blob, i + 3, False)
    j = blob.find(b"\x01\x00\x07\x02\x00")
    if j >= 0 and j + 7 <= len(blob):
        port = (blob[j + 5] << 8) | blob[j + 6]
        if 1 <= port <= 65535:
            out["tcp_port"] = port
    return out


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
        s = s.split(chr(0))[0]
        if len(s) >= 5 and s.startswith("\\\\"):
            out.append(s)
        if len(out) >= limit:
            break
    return out


def unc_host(path: str) -> str:
    body = path.lstrip("\\")
    return body.split("\\", 1)[0] if body else ""


_WIDE_PATH_RE = re.compile(
    rb"(?:[A-Za-z]\x00:\x00|\\\x00\\\x00|\\\x00\?\x00\?\x00)"
    rb"(?:[\x20-\x7e]\x00){1,300}")


def extract_wide_paths(stub: bytes, limit: int = 6) -> list[str]:
    r"""
    Pull UTF-16LE path-like strings from a request stub - both UNC
    (\\host\share), \??\ device paths, and drive-letter paths (C:\...).

    extract_unc_paths only matches \\..., which is right for the coercion
    primitives but not for an ElfrBackupELFW DESTINATION, which is usually a
    local path.  Same best-effort discipline: find the string, do not try to
    say which NDR parameter it came from.
    """
    out = []
    for m in _WIDE_PATH_RE.finditer(stub):
        try:
            txt = m.group(0).decode("utf-16-le", "strict").split(chr(0))[0]
        except Exception:
            continue
        if len(txt) >= 4 and ("\\" in txt or ":" in txt):
            out.append(txt)
        if len(out) >= limit:
            break
    return out


def _is_off_box(path: str) -> str:
    r"""Return the off-box host named by a UNC or \??\UNC\ path, else ""."""
    low = path.lower()
    if low.startswith("\\??\\unc\\"):
        return path[8:].split("\\", 1)[0]
    if path.startswith("\\\\") or path.startswith("\\"):
        return unc_host(path)
    return ""


def _backup_dest_suspect(path: str) -> str | None:
    """
    Why an ElfrBackupELFW destination looks like a write primitive, or None.

    A legitimate backup is a .evtx file in the log directory.  "Outside the
    log dir" cannot be checked without %SystemRoot%, so a non-.evtx extension
    stands in for it; an autostart path is called out specifically because it
    is the CVE-2026-50502 target.
    """
    low = path.lower().split("\x00", 1)[0]
    for marker in AUTORUN_MARKERS:
        if marker in low:
            return "destination in a per-user autostart path"
    dot = low.rfind(".")
    slash = low.rfind("\\")
    ext = low[dot:] if dot > slash else ""
    if ext != EVTX_EXTENSION:
        return f"destination extension {ext or '(none)'} is not .evtx"
    return None


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
    "fssagentrpc", "epmapper", "browser", "ntsvcs", "hydralspipe",
    "lsm_api_service",
    # MS-BKRP rides \pipe\protected_storage, and that pipe over SMB is the
    # path the DPAPI-backup-key hunting literature actually watches.  Without
    # it the graded BackuprKey rule only ever fired on the epmapper TCP path.
    "protected_storage",
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


# WS-Man lands on more than one URL reservation, and which one a request hit
# changes what it means.  All three are in the cleartext request line, so the
# distinction is free even when the SOAP envelope is sealed.
#
#   /wsman-anon/identify            - the anonymous Identify endpoint.  It is
#       on whenever a listener is, needs NO credentials, and answers with the
#       product vendor and protocol version.  A pre-auth confirmation that a
#       WinRM listener exists, which is why it is worth saying out loud.
#   /wsman/SubscriptionManager/WEC  - the Windows Event Collector endpoint for
#       source-initiated subscriptions.  Legitimate and common, but it is a
#       standing authenticated channel from every forwarding host to the
#       collector, so knowing it is in use on cleartext 5985 matters.
#   /wsman                          - everything else: PowerShell remoting,
#       JEA, WinRS, WMI-over-WS-Man.  Which plugin is behind it lives in the
#       ResourceURI, inside the envelope, so it is NOT observable once the
#       session is encrypted.  rpcwatch does not guess at it.
WSMAN_ANON_IDENTIFY = "/wsman-anon/identify"
WSMAN_WEC_SUBSCRIPTION = "/wsman/subscriptionmanager/wec"


def wsman_endpoint(path: str) -> str:
    p = path.lower().split("?", 1)[0].rstrip("/")
    if p.startswith(WSMAN_ANON_IDENTIFY):
        return "anon-identify"
    if p.startswith(WSMAN_WEC_SUBSCRIPTION):
        return "wec-subscription"
    return "wsman"


# http.sys parses Accept-Encoding in the kernel, before any routing decision,
# so these two CVEs are reachable on any path a listener is bound to - which
# on a Windows host means tcp/5985 whether or not WinRM is the target.
# RFC 7230 s7 tells senders not to produce empty list elements but tells
# recipients to tolerate them, so a single empty element can be a sloppy
# client rather than an attack.  That is why the count is graded, not gated.
HTTPSYS_LONG_LIST = 8            # codings beyond which a list is unusual
HTTPSYS_LONG_HEADER = 200        # bytes beyond which the header is unusual


def accept_encoding_shape(value: str) -> dict:
    """
    Split an Accept-Encoding field-value and count the empty elements.

    The CVE-2021-31166 / CVE-2022-21907 trigger is an element that is empty or
    whitespace-only - "whitespace (or nothing at all) between the commas",
    including a bare trailing comma.  UlpParseContentCoding returns a special
    error for such an element and leaves a dangling entry in its coding list.
    """
    elems = value.split(",")
    empty = [i for i, e in enumerate(elems) if not e.strip()]
    return {
        "elements": len(elems),
        "empty_elements": len(empty),
        "empty_positions": empty[:8],
        "header_bytes": len(value),
    }


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
        "tslicensing_spray_threshold": 50,
        "dedup_seconds": 60,
        "min_severity": "low",
        "local_nets": (),
        "dc_hosts": (),
        "allow_clients": (),
        "allow_interfaces": (),
        "rpc_ports": None,
        "dynamic_range": False,
        "ipv6_eh": False,
        "wsman_compat": False,
        "ca_hosts": (),
        "drs_replicators": (),
        "drs_epm_follow": True,
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
        self.tslicensing_spray_threshold = kw.get(
            "tslicensing_spray_threshold", 50)
        self.dedup_seconds = kw.get("dedup_seconds", 60)
        self.min_severity = kw.get("min_severity", "low")
        self.local_nets = list(kw.get("local_nets", []))
        self.dc_hosts = list(kw.get("dc_hosts", []))
        self.allow_clients = set(kw.get("allow_clients", []))
        self.allow_interfaces = set(kw.get("allow_interfaces", []))
        self.wsman_compat = bool(kw.get("wsman_compat", False))
        self.ca_hosts = list(kw.get("ca_hosts", []))
        self.drs_replicators = list(kw.get("drs_replicators", []))
        self.drs_epm_follow = bool(kw.get("drs_epm_follow", True))
        ports = kw.get("rpc_ports") or [EPMAPPER_PORT, SMB_PORT, NBT_SESSION_PORT]
        self.rpc_ports = set(ports)
        self.dynamic_range = kw.get("dynamic_range", False)
        self.ipv6_eh = kw.get("ipv6_eh", False)
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

    def is_replicator(self, ip: str) -> bool:
        """
        True when the host is a declared legitimate DRS replication caller
        (Entra Connect sync, an identity-backup or AD-audit appliance).

        Unlike is_dc / is_ca this returns a plain bool, never None: an empty
        replicator list is a meaningful answer ("nobody is exempt"), not an
        undecidable one.  The DC list is what arms the tier.
        """
        if not self.drs_replicators:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self.drs_replicators:
            if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if addr in entry:
                    return True
            elif addr == entry:
                return True
        return False

    @property
    def drs_armed(self) -> bool:
        """
        The DRS tier needs a DC list to mean anything: every stage is a
        statement about which end is or is not a domain controller.  With no
        --dc it stays disarmed rather than guessing.
        """
        return bool(self.dc_hosts)

    def is_ca(self, ip: str) -> bool | None:
        if not self.ca_hosts:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for entry in self.ca_hosts:
            if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
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
                 "pending_calls", "created", "over_pipe", "anonymous",
                 "tsl_connects", "tsl_spray_fired",
                 "elfr_open_offbox", "elfr_probe_paths", "elfr_backup_fired",
                 "elfr_probe_fired",
                 "lsm_bind_reported", "lsm_call_count", "lsm_loop_fired",
                 "drs_calls", "drs_bytes", "drs_stages", "drs_outcome_fired",
                 "lsa_secret_name", "ntlm_account", "csra_bind_reported",
                 "winreg_key_name")

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
        self.over_pipe = False     # ncacn_np (carved from SMB) vs ncacn_ip_tcp
        self.anonymous = False     # bound with no auth, or NTLM anonymous
        self.tsl_connects = deque()   # CVE-2024-38077 heap-spray window
        self.tsl_spray_fired = False  # latch: report the spray once
        self.elfr_open_offbox = None  # last ElfrOpenBELW off-box source, if any
        self.elfr_probe_paths = set() # distinct ElfrOpenBELW paths (probe)
        self.elfr_backup_fired = False  # latch the sealed-sequence finding
        self.elfr_probe_fired = False  # latch the path-probe finding
        self.lsm_bind_reported = False  # latch the LSM container bind
        self.lsm_call_count = 0         # calls on the LSM container assoc
        self.lsm_loop_fired = False     # latch the sustained-loop escalation
        self.lsa_secret_name = None     # LsarOpenSecret name, when readable
        self.ntlm_account = None        # domain\\user from NTLM AUTHENTICATE
        self.csra_bind_reported = False  # latch the CA-admin bind posture
        self.winreg_key_name = None     # last registry key named on this assoc
        # DRS: a full DCSync is a run of paged GetNCChanges calls on ONE
        # handle, so the stage latches and these counters carry the volume.
        self.drs_calls = 0
        self.drs_bytes = 0
        self.drs_stages = set()         # stages already reported here
        self.drs_outcome_fired = False  # latch the answer-graded emission


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

# --- CVE-mapped call sets -------------------------------------------------
#
# MS-RPRN 3.1.4 / MS-PAR 3.1.4: the printer-driver installation calls behind
# PrintNightmare (CVE-2021-1675, CVE-2021-34527).  Windows does not verify that
# pDriverPath/pConfigFile/pDataFile are local to the machine, so an attacker
# serves a DLL over UNC and has the spooler load it as SYSTEM.
#
# The opnum sits in the cleartext REQUEST header, so this is observable even at
# PKT_PRIVACY where the driver container itself is ciphertext.
RPRN_ADD_PRINTER_DRIVER = 9
RPRN_ADD_PRINTER_DRIVER_EX = 89
PAR_ASYNC_ADD_PRINTER_DRIVER = 39

PRINTNIGHTMARE_CALLS = {
    IF_RPRN: {
        RPRN_ADD_PRINTER_DRIVER: "RpcAddPrinterDriver",
        RPRN_ADD_PRINTER_DRIVER_EX: "RpcAddPrinterDriverEx",
    },
    IF_PAR: {
        PAR_ASYNC_ADD_PRINTER_DRIVER: "RpcAsyncAddPrinterDriver",
    },
}

# CVE-2024-38077 "MadLicense": a pre-auth heap overflow in the RD Licensing
# service (lserver.dll), reached over the Terminal Server Licensing interface.
# CDataCoding::DecodeData base24-decodes a caller-supplied string into a fixed
# 21-byte heap buffer without checking the input against that allocation.
#
# Provenance, since this interface has no published MS specification:
#   UUID and \pipe\HydraLsPipe  - runZero's RDL discovery write-up
#   opnum 49 TLSRpcTelephoneRegisterLKP - Star Labs patch-diff RCA
#   opnum 1  TLSRpcConnect       - public PoC only, NOT independently confirmed
# The conformance harness carries its own copy of these and records the same
# provenance, so a wrong value is a disagreement rather than a shared belief.
TSL_RPC_CONNECT = 1
TSL_RPC_TELEPHONE_REGISTER_LKP = 49

# The patch registers TLSRpcSecurityCallback on the interface, which rejects a
# call unless the authentication level is RPC_C_AUTHN_LEVEL_PKT_PRIVACY.  So
# the signal is the LEVEL, not merely the absence of an auth verifier: a call
# authenticated at CONNECT or PKT_INTEGRITY is refused by a patched host too.
TSLICENSING_REQUIRED_LEVEL = 6      # RPC_C_AUTHN_LEVEL_PKT_PRIVACY

# The July 2024 Patch Tuesday fixed SEVEN bugs in this one service.  Only
# CVE-2024-38077 has a public patch diff, so it is the only one whose opnum is
# known.  But TLSRpcSecurityCallback is registered on the INTERFACE, not on a
# method, so every one of them shares a single passive precondition: a call to
# this interface below packet privacy.  That is why the cluster is attributed
# rather than given a code each - there is no wire evidence that separates
# them, and inventing one per CVE would be inventing precision.
#   ZDI July 2024 review for the cluster and scores; Star Labs' archive for
#   which ones were diffed (only 38077).
RDL_RCE_CLUSTER = ("CVE-2024-38074", "CVE-2024-38076", "CVE-2024-38077")
# CVE-2024-38099 scores 5.9, below the suite's usual 6.5 bar, but it is in the
# same service behind the same interface-wide callback, so the precondition
# that detects it is already being evaluated.  Including it costs nothing and
# completes the patch mapping; excluding it on score alone would leave one
# seventh of a single Patch Tuesday's work for this service unaccounted for.
RDL_DOS_CLUSTER = ("CVE-2024-38071", "CVE-2024-38072", "CVE-2024-38073",
                   "CVE-2024-38099")
RDL_SUB_BAR = ("CVE-2024-38099",)   # in the cluster, but below 6.5 on score

# CVEs evaluated for this module and deliberately NOT claimed by name.  Each
# entry is a CVE whose service rpcwatch already watches, which is exactly why
# it has to be written down: the temptation is to attach it to a finding that
# fires nearby and call the mapping done.
#
#   CVE-2021-36936 (8.8, AV:N/PR:L) and CVE-2021-36947 (8.8) - August 2021
#       Print Spooler RCEs, found internally by Microsoft.  No researcher
#       credit, no PoC, no root-cause analysis, so no published opnum.  Their
#       AV:N/PR:L shape is CONSISTENT with the driver-install family, but
#       consistent is not evidence, and the August 2021 batch shares no
#       interface-wide gate the way the RD Licensing seven do - there is no
#       single precondition that could honestly stand for all of them.  If
#       either one is in fact an AddPrinterDriver-family bug then
#       RPC-PRINTNIGHTMARE-DRIVER-ADD already fires on it, because that
#       finding keys on the CALL and its off-box UNC rather than on a CVE.
#       Coverage is therefore incidental and free; the attribution is not
#       available and is not invented.
#
#   CVE-2026-50346 (7.8) - "Netlogon RPC Elevation of Privilege" in
#       Microsoft's own title, which is why it reached this module at all.
#       Its vector is CVSS:3.1/AV:L/... - LOCAL.  Improper authorization in
#       the RPC runtime, exploited by an already-authenticated local user.
#       Nothing crosses the wire, so no passive sensor anywhere can see it.
#       Rejected on transport, not on score.
#
# The conformance harness greps this module and fails if any of these is ever
# claimed as cve="...", the same guard the un-diffed RDL cluster gets.
EVALUATED_NOT_CLAIMED = {
    "CVE-2021-36936": "spooler RCE with no public mechanism; no opnum to key on",
    "CVE-2021-36947": "spooler RCE with no public mechanism; no opnum to key on",
    "CVE-2026-50346": "local vector (AV:L); never observable on the wire",
}

# ESC11 - NTLM relay to the AD CS certificate enrollment RPC interfaces.
#
# MS-ICPR has exactly one method, CertServerRequest (opnum 0), through which a
# caller submits a certificate request to the CA.  There is no CVE here: the
# CA hardening flag IF_ENFORCEENCRYPTICERTREQUEST, set under CA\InterfaceFlags
# with "certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST",
# makes the interface accept only RPC_C_AUTHN_LEVEL_PKT_PRIVACY.  It is ON by
# default, and routinely turned OFF so that clients which cannot reach that
# level can still enroll.  With it off, a relayed NTLM authentication reaches
# the enrollment interface and comes back with a certificate.
#
# So this is structurally the CVE-2021-1678 rule with the CVE removed: the
# signal is the LEVEL on an enrollment bind, and a bind below packet privacy
# means either the flag is off or a relay is in progress.  Both are worth
# saying; neither is proof of exploitation on its own.
ICPR_CERT_SERVER_REQUEST = 0        # MS-ICPR 3.2.4.1.1 CertServerRequest
CERTENROLL_REQUIRED_LEVEL = 6       # RPC_C_AUTHN_LEVEL_PKT_PRIVACY

# MS-WCCE's ICertRequestD is the DCOM counterpart and is covered by the same
# hardening flag, but its opnums are NOT claimed here: the flag is registered
# on the interface rather than on a method, so the bind posture is the whole
# signal.  Same reasoning as the RD Licensing cluster - reporting the
# condition without inventing a method mapping nobody published.
CERTENROLL_INTERFACES = (IF_ICPR, IF_WCCE_CERTREQD)
CERTENROLL_CALLS = {IF_ICPR: {ICPR_CERT_SERVER_REQUEST: "CertServerRequest"}}

# MS-DNSP: the DnsAdmin-to-SYSTEM path.  R_DnssrvOperation's pszOperation
# parameter can be the literal "ServerLevelPluginDll", whose pData is a path
# to a DLL that dns.exe then LOADS IN-PROCESS as SYSTEM on next restart.  It
# is a documented administrative feature, not a vulnerability - which is why
# this is abuse detection and carries no CVE.
#
# Four opnums reach it.  0-4 are deprecated in favour of 5-9, but the spec
# says servers SHOULD still support all of them, so a detection keyed only on
# the modern opnum would be trivially evaded by calling the obsolete one.
DNSP_OPERATION_OPNUMS = {
    0: "R_DnssrvOperation",          # MS-DNSP 3.1.4.1, deprecated
    5: "R_DnssrvOperation2",         # MS-DNSP 3.1.4.6
    12: "R_DnssrvOperation3",        # MS-DNSP 3.1.4.13
    15: "R_DnssrvOperation4",        # MS-DNSP 3.1.4.16, virtualization
}

# pszOperation is LPCSTR - a null-terminated UTF-8/ASCII string - while the
# DLL path that follows is a DNSSRV_TYPEID_LPWSTR, UTF-16LE.  That mixture is
# in the IDL and is the reason this is matched as ASCII and extracted as
# UTF-16LE rather than one or the other.
DNSP_PLUGIN_OPERATION = b"ServerLevelPluginDll"
DNSSRV_TYPEID_LPWSTR = 3            # MS-DNSP 2.2.1.1.1 DNS_RPC_TYPEID

# MS-PAR 3.1.4 opnum 62.  CVE-2021-1678: an attacker relays an NTLM session to
# the IRemoteWinSpool interface and calls this to execute code.  The root cause
# is an insufficient authentication level on the interface itself, so the
# detection is the bind posture; the call is corroboration, not the trigger.
PAR_ASYNC_INSTALL_PRINTER_DRIVER_FROM_PACKAGE = 62

# The level Microsoft's fix requires on IRemoteWinSpool.  The June 8 2021
# enforcement phase made this the default, so a bind below it today is either
# an unpatched host or a live relay - both worth saying out loud, but it is a
# posture finding and not proof of exploitation.
WINSPOOL_REQUIRED_LEVEL = 6      # RPC_C_AUTHN_LEVEL_PKT_PRIVACY

# EFSR opnum 0 is EfsRpcOpenFileRaw, and the August 2021 patch for
# CVE-2021-36942 fixed ONLY that method - which is why the downlevel variants
# stayed exploitable and CVE-2022-26925 had to follow.  That makes opnum 0 a
# correct discriminator for attributing the coercion call to its CVE.
COERCION_CVES = {
    (IF_EFSR_LSA, 0): "CVE-2021-36942",
    (IF_EFSR_EFS, 0): "CVE-2021-36942",
}

# MS-EFSR reached over \pipe\lsarpc is the interface Microsoft's advisory for
# CVE-2022-26925 refers to as "the LSARPC interface": the patch made anonymous
# connections to it illegal, because an unauthenticated caller could coerce a
# DC into authenticating to the attacker over NTLM.
LSA_PIPE_INTERFACES = (IF_EFSR_LSA, IF_LSARPC)

# MS-EVEN 3.1.4: the event-log backup pair behind the "EventLogin" arbitrary
# file-write chain.  ElfrOpenBELW (opnum 9) opens a *backed-up* log for
# reading and validates the EVTX format at open; ElfrBackupELFW (opnum 1)
# backs up a *live* log to a caller-named destination and did NOT re-validate.
#   CVE-2025-29969 (7.5, May 2025, SafeBreach "EventLogin") - TOCTOU: the file
#       validated at ElfrOpenBELW is swapped before ElfrBackupELFW uses it.
#   CVE-2026-50502 (8.0, Jul 2026) - bypasses the 29969 fix by appending an
#       HTA payload after a valid EVTX header; backup destination is the
#       victim's Startup folder with a .hta extension, run at next logon.
# Opnums confirmed against the MS-EVEN 3.1.4 method table; the conformance
# harness carries its own transcribed copy so a wrong value is a disagreement.
ELFR_BACKUP_ELFW = 1
ELFR_OPEN_BELW = 9
EVENTLOG_BACKUP_CALLS = {
    IF_EVEN: {
        ELFR_OPEN_BELW: "ElfrOpenBELW",
        ELFR_BACKUP_ELFW: "ElfrBackupELFW",
    },
}
# One finding, both CVEs: the wire sequence is identical and the two
# differentiators - the TOCTOU swap and the HTA-after-EVTX-header payload -
# happen on the attacker's SMB server or inside file content, neither of
# which is on the tap.  Attribute the cluster rather than mint a code each.
EVENTLOG_BACKUP_CLUSTER = ("CVE-2025-29969", "CVE-2026-50502")

# A legitimate backup lands in the log directory with a .evtx extension.  A
# destination that is off-box, not .evtx, or inside a per-user autostart path
# is the write primitive.  "Outside the log dir" cannot be checked precisely
# without knowing %SystemRoot%, so a non-.evtx extension stands in for it -
# a backup that is not an .evtx file is already not a backup.
EVTX_EXTENSION = ".evtx"
AUTORUN_MARKERS = (
    "\\start menu\\programs\\startup\\",   # per-user Startup, the 50502 target
    "\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
)

# SafeBreach report that ElfrOpenBELW can still TEST whether arbitrary paths
# exist (unfixed), so a burst of opens against varied paths is a path-probe.
# Off by default sensitivity: distinct paths on one association.
EVENTLOG_PROBE_THRESHOLD = 10

# MS-TSTS TermSrvEnumeration opnum 8.  On Win11/Server 2025 this is a stub
# (DebugBreak + E_NOTIMPL) and a single call crashes LSM; a domain account is
# enough to kill LSM on a DC.  Win10 still implements it, so the crash is
# graded by the server's answer rather than assumed.  CVE-2025-26651 (6.5).
# Opnum confirmed from the MS-TSTS method order (Opnum7NotUsedOnWire precedes).
TSTS_GET_SESSION_IDS = 8

# The LSM container interface methods, from Akamai's write-up.  Not used to
# gate - a bind to the interface over the network is the whole signal - but
# named so a readable call can be reported precisely.
LSM_CONTAINER_CALLS = {
    1: "ContainerCom_AskForSession",
    2: "ContainerCom_SessionLoggedOff",
}
# A sustained call loop is what turns the leak (CVE-2022-37973, ~3 MB/s) into
# a crash.  Report the bind at high; escalate to critical once the loop is
# clearly running.  CVE-2022-37998 (deadlock) shares the interface and wire
# shape, so attribute the cluster rather than split it.
LSM_CONTAINER_CLUSTER = ("CVE-2022-37973", "CVE-2022-37998")
LSM_CONTAINER_LOOP_THRESHOLD = 50

# Certighost (CVE-2026-54121).  A CA with EDITF_ENABLECHASECLIENTDC set can be
# steered by cdc:/rmd: request attributes into "chasing" an attacker-run host
# for a DC's identity, then issuing it a DC certificate -> PKINIT -> DCSync.
# The enrollment request is sealed, so cdc:/rmd: are normally invisible; the
# OBSERVABLE signal is the chase itself - the CA opening an OUTBOUND LSARPC
# bind to a host that is not a known DC, shortly after serving enrollment.
CERTENROLL_ENROLL_INTERFACES = (IF_ICPR, IF_WCCE_CERTREQD)
CHASE_WINDOW_SECONDS = 120
# When a legacy CA accepts an UNSEALED enrollment request, the attribute string
# is readable and the chase-directing attribute can be seen directly.
CHASE_ATTR_MARKER = b"cdc:"
CHASE_ATTR_MARKER_W = "cdc:".encode("utf-16-le")

SENSITIVE_CLASSES = ("netlogon", "directory", "coercion", "exec")


class RPCEngine:
    def __init__(self, config: Config, emitter: Emitter):
        self.config = config
        self.emitter = emitter
        self.assocs: dict[tuple, Association] = {}
        self.netlogon: dict[tuple, NetlogonPeer] = {}
        self.epm_lookups: dict[str, deque] = {}
        # Latch for the inventory finding.  An interface is an inventory fact,
        # not an event: say it once per (server, uuid) and never again, so a
        # busy management host does not drown the catalogue in repeats.
        self.inventory_seen: set[tuple[str, str]] = set()
        # Certighost: when each host last served AD CS enrollment, so an
        # outbound LSARPC bind from it can be correlated as a "chase".  A CA
        # named by --ca-hosts is always eligible, with no prior-enrollment
        # requirement.  Keyed by server IP -> last-enrollment timestamp.
        self.ca_enroll_seen: dict[str, float] = {}
        # --drs-epm-follow: server IP -> the DRSUAPI port(s) its epmapper
        # handed out, learned from ept_map replies.  Keyed on the 5-tuple's
        # server, never on the tower's own host floor.
        self.learned_drs_ports: dict[str, set] = {}
        self.drs_port_logged: set = set()
        # ept_map call_id -> the interface UUID that request asked to map.
        self.epm_pending_map: dict[tuple, str] = {}
        self.chase_fired: set[tuple[str, str]] = set()

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
        """
        Name an interface for a finding.

        A reference-table hit is named and described but classed "other", so
        it reads legibly in a report without arming any class-driven rule.
        Only INTERFACES carries behaviour; this method must never promote a
        reference entry into a watched one.
        """
        if uuid in INTERFACES:
            return INTERFACES[uuid]
        spec = REFERENCE_INTERFACES.get(uuid)
        if spec:
            return (spec.split(" ", 1)[-1], "other", spec)
        return (uuid, "other", "unknown interface")

    # -- entry point -----------------------------------------------------
    def process_pdu(self, ts, flow, client_ip, server_ip, pdu: bytes,
                    from_client: bool, pipe_name: str = "",
                    over_pipe: bool = False):
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
        if over_pipe:
            assoc.over_pipe = True
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
                self._on_bind_ack(ts, subject, assoc, pdu, hdr, from_client)
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
        if trailer is None:
            assoc.anonymous = True
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
            if uuid not in INTERFACES:
                self._uncatalogued_interface(ts, subject, base, uuid,
                                             server_ip, assoc)
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

            # CVE-2024-43532.  The WinReg client's BaseBindToMachine falls back
            # to a legacy transport when SMB is unavailable and binds with
            # RpcBindingSetAuthInfo at RPC_C_AUTHN_LEVEL_CONNECT, which neither
            # signs nor verifies - the condition an NTLM relay to AD CS needs.
            # A healthy Remote Registry session runs over \pipe\winreg, so it
            # is the combination of interface, transport and level that matters.
            # CVE-2021-1678.  IRemoteWinSpool accepted sessions below packet
            # privacy, so a relayed NTLM authentication could reach it and
            # call RpcAsyncInstallPrinterDriverFromPackage for code execution.
            if (uuid == IF_PAR and trailer is not None
                    and new_level < WINSPOOL_REQUIRED_LEVEL):
                self.emitter.emit(ts, "RPC-WINSPOOL-RELAY-LEVEL", subject,
                                  dict(base, cve="CVE-2021-1678",
                                       required_level=AUTHN_LEVEL_NAMES[
                                           WINSPOOL_REQUIRED_LEVEL],
                                       stage="bind",
                                       note="below the level Microsoft's fix "
                                            "requires; unpatched host or an "
                                            "active relay, not proof of "
                                            "exploitation"),
                                  key_extra=(uuid, "bind"))

            # ESC11.  The enrollment interfaces are deliberately NOT in
            # SENSITIVE_CLASSES: this rule supersedes the generic
            # RPC-BIND-NO-AUTH / RPC-NO-PACKET-INTEGRITY posture for them,
            # and two findings for one condition is noise, not thoroughness.
            if uuid in CERTENROLL_INTERFACES and new_level < CERTENROLL_REQUIRED_LEVEL:
                self._certenroll_level(ts, subject, base, uuid, new_level,
                                       trailer, "bind")

            # Certighost: learn CA identity passively.  A host that serves an
            # AD CS enrollment bind is a CA; remember when, so an outbound
            # LSARPC bind from it can be correlated as a chase.
            if uuid in CERTENROLL_ENROLL_INTERFACES:
                self.ca_enroll_seen[server_ip] = ts

            # The chase itself: a known CA (learned above or named by
            # --ca-hosts) is the CLIENT of an LSARPC bind to a host that is not
            # a declared DC, within the window.  The bind header is cleartext,
            # so this survives PKT_PRIVACY on the enrollment leg.
            if uuid == IF_LSARPC:
                self._adcs_chase_bind(ts, subject, base, client_ip, server_ip)

            # MS-CSRA: CA remote administration below packet privacy.
            if uuid in CSRA_INTERFACES and new_level < CSRA_REQUIRED_LEVEL:
                self._certadmin_bind(ts, subject, base, assoc, new_level)

            # LSM container interface: any bind we see is over the network
            # (local hvsocket/ALPC never reaches the tap), which is never
            # legitimate for this interface.
            if uuid == IF_LSM_CONTAINER:
                self._lsm_container_bind(ts, subject, base, assoc)

            if (uuid == IF_WINREG and not assoc.over_pipe
                    and trailer is not None
                    and new_level == RPC_C_AUTHN_LEVEL_CONNECT):
                self.emitter.emit(ts, "RPC-WINREG-RELAY-FALLBACK", subject,
                                  dict(base, cve="CVE-2024-43532",
                                       transport="ncacn_ip_tcp",
                                       expected_transport="ncacn_np"),
                                  key_extra=(uuid,))

    def _netlogon_bind_posture(self, ts, subject, base, trailer, client_ip, server_ip):
        level = trailer["auth_level"] if trailer else RPC_C_AUTHN_LEVEL_NONE
        if trailer is None or level < RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
            self.emitter.emit(ts, "RPC-NETLOGON-UNSIGNED-BIND", subject, dict(base))
        is_dc = self.config.is_dc(server_ip)
        if is_dc is False:
            self.emitter.emit(ts, "RPC-NETLOGON-UNEXPECTED-SERVER", subject,
                              dict(base, server=server_ip))

    def _on_bind_ack(self, ts, subject, assoc, pdu, hdr, from_client=False):
        body = parse_bind_ack(pdu, hdr)
        if body["sec_addr"]:
            assoc.pipe_name = assoc.pipe_name or body["sec_addr"]
        if not from_client:
            self._bindack_underflow(ts, subject, pdu, hdr, body)

    def _bindack_underflow(self, ts, subject, pdu, hdr, body):
        """
        CVE-2022-26809, as it actually appears on the wire.

        The vulnerable code is OSF_CASSOCIATION::ProcessBindAckOrNak - the
        CLIENT parsing a bind_ack, not the server parsing a fragmented request.
        A zero secondary-address length drives an integer underflow, and a
        big-endian data representation forces the byte-swapping path where the
        underflowed value is used for out-of-bounds reads and writes.

        Big-endian is what makes this cheap to detect: effectively every real
        DCERPC implementation emits little-endian, so a big-endian bind_ack on a
        production network is already an anomaly.  Requiring both conditions,
        and reporting whether frag_length agrees with what actually arrived,
        is what keeps it off ordinary traffic.
        """
        if not hdr["big_endian"] or body["sec_addr_len"] != 0:
            return
        self.emitter.emit(ts, "RPC-RUNTIME-BINDACK-UNDERFLOW", subject, {
            "cve": "CVE-2022-26809",
            "data_representation": "big-endian",
            "sec_addr_len": 0,
            "frag_length": hdr["frag_length"],
            "observed_bytes": len(pdu),
            "frag_length_consistent": hdr["frag_length"] == len(pdu),
            "direction": "server -> client",
        })

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
        if uuid in PRINTNIGHTMARE_CALLS and opnum in PRINTNIGHTMARE_CALLS[uuid]:
            self._printer_driver_call(ts, subject, base, stub, uuid, opnum,
                                      sealed, server_ip)
        if uuid == IF_TSLICENSING:
            self._tslicensing_call(ts, subject, base, assoc, opnum, trailer,
                                   stub, hdr)

        # The driver-install call on an association that never reached packet
        # privacy is the exploit step, not just the posture.
        if (uuid == IF_PAR
                and opnum == PAR_ASYNC_INSTALL_PRINTER_DRIVER_FROM_PACKAGE
                and (assoc.auth_level or RPC_C_AUTHN_LEVEL_NONE)
                < WINSPOOL_REQUIRED_LEVEL):
            self.emitter.emit(ts, "RPC-WINSPOOL-RELAY-LEVEL", subject,
                              dict(base, cve="CVE-2021-1678",
                                   call="RpcAsyncInstallPrinterDriverFromPackage",
                                   stage="call",
                                   required_level=AUTHN_LEVEL_NAMES[
                                       WINSPOOL_REQUIRED_LEVEL]),
                              severity="critical", key_extra=(uuid, "call"))

        # ESC11 at the call: the enrollment request itself, on an
        # association that never reached packet privacy.
        if (uuid in CERTENROLL_CALLS and opnum in CERTENROLL_CALLS[uuid]
                and (assoc.auth_level or RPC_C_AUTHN_LEVEL_NONE)
                < CERTENROLL_REQUIRED_LEVEL):
            self._certenroll_level(ts, subject, base, uuid,
                                   assoc.auth_level or RPC_C_AUTHN_LEVEL_NONE,
                                   trailer, "call",
                                   call=CERTENROLL_CALLS[uuid][opnum])

        if uuid == IF_DNSSERVER and opnum in DNSP_OPERATION_OPNUMS:
            self._dnssrv_operation(ts, subject, base, stub, opnum, sealed,
                                   server_ip)

        if uuid == IF_EVEN and opnum in EVENTLOG_BACKUP_CALLS[IF_EVEN]:
            self._eventlog_backup(ts, subject, base, assoc, stub, opnum,
                                  sealed, server_ip)

        if (uuid == IF_DRSUAPI and opnum in DRS_WATCHED_OPNUMS
                and self.config.drs_armed):
            self._drs_call(ts, subject, base, assoc, opnum, client_ip,
                           server_ip, hdr["call_id"])

        if uuid == IF_TSTS_ENUM and opnum == TSTS_GET_SESSION_IDS:
            self._tsts_getsessionids(ts, subject, base, assoc, hdr["call_id"])

        if uuid == IF_LSM_CONTAINER:
            self._lsm_container_call(ts, subject, base, assoc, opnum)

        if uuid == IF_LSARPC and opnum in LSA_SECRET_OPNAMES:
            self._lsa_secret_call(ts, subject, base, assoc, stub, opnum,
                                  sealed)

        if uuid == IF_BKRP and opnum == 0:
            self._backupkey_call(ts, subject, base, stub, sealed)

        # On an unsealed legacy CA, the enrollment request attributes are
        # readable, so the chase-directing attribute can be seen outright.
        if uuid in CERTENROLL_ENROLL_INTERFACES and not sealed:
            self._adcs_chase_attr(ts, subject, base, stub)
            self._certenroll_content(ts, subject, base, assoc, stub)

        if uuid in CSRA_INTERFACES:
            self._certadmin_call(ts, subject, base, opnum)

        if uuid in COERCION_CALLS and opnum in COERCION_CALLS[uuid]:
            self._coercion_call(ts, subject, base, stub, uuid, opnum, sealed,
                                server_ip)
            if assoc.anonymous and uuid in LSA_PIPE_INTERFACES:
                self._lsa_anonymous_coercion(ts, subject, base, assoc, uuid,
                                             opnum)
        # MS-RRP: latch the key being named, then grade the hive move.  The
        # latch runs before the exec-primitive dispatch so a save that follows
        # a create on the same association can name its hive.
        if uuid == IF_WINREG:
            if opnum in WINREG_KEY_NAME_OPNUMS and not sealed:
                named = handle_then_unicode_string(stub)
                if named:
                    assoc.winreg_key_name = named
            if opnum in WINREG_SAVE_OPNUMS + WINREG_LOAD_OPNUMS:
                self._winreg_hive(ts, subject, base, assoc, stub, opnum,
                                  sealed, server_ip)

        if uuid in EXEC_CALLS and opnum in EXEC_CALLS[uuid]:
            self._exec_call(ts, subject, base, uuid, opnum)
        if uuid == IF_EPM and opnum in EPM_LOOKUP_OPNUMS:
            self._epm_call(ts, subject, base, client_ip)
            if (opnum == EPM_MAP_OPNUM and self.config.drs_epm_follow
                    and not sealed):
                asked = parse_epm_tower(stub).get("interface")
                if asked:
                    self.epm_pending_map[(server_ip, hdr["call_id"])] = asked

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

    def _uncatalogued_interface(self, ts, subject, base, uuid, server_ip,
                                assoc):
        """
        Inventory, from the one field DCERPC always leaves in the clear.

        The abstract-syntax UUID is in the bind body, outside the security
        trailer, so it is readable at every auth level including PKT_PRIVACY.
        That makes a passive tap a complete interface inventory for the
        segment it watches, at no cost and with nothing sent.

        Two grades, because they mean different things to an operator:
          documented  - in REFERENCE_INTERFACES: a Microsoft-specified
                        interface rpcwatch has no rule for.  Expected on a
                        managed network; worth knowing is reachable.
          unknown     - in neither table: third-party RPC (backup, AV,
                        monitoring, a vendor agent) or something bespoke.  No
                        enumeration of Microsoft's specs will ever name it,
                        which is exactly why it is the more interesting grade.

        This claims no CVE and asserts no vulnerability.  It is the one
        finding in the module whose job is to describe the network rather
        than to accuse it.
        """
        key = (server_ip, uuid)
        if key in self.inventory_seen:
            return
        self.inventory_seen.add(key)
        spec = REFERENCE_INTERFACES.get(uuid)
        d = dict(base,
                 grade="documented" if spec else "unknown",
                 spec=spec or "no MS open spec maps this UUID",
                 transport="ncacn_np" if assoc.pipe_name else "ncacn_ip_tcp")
        if assoc.pipe_name:
            d["pipe"] = assoc.pipe_name
        self.emitter.emit(ts, "RPC-INTERFACE-UNCATALOGUED", subject, d,
                          key_extra=(uuid,))

    def _drs_stage(self, opnum, client_ip, server_ip):
        """
        Decide the stage from the four cleartext facts: interface, opnum,
        client address, server address.  Returns (code, stage, severity) or
        None.  Membership is set logic only - nothing here reads the stub,
        and nothing depends on the address family.

        Order matters.  A DC pulling FROM a non-DC is checked first: that is
        the DCShadow tell, and it would otherwise fall through to the
        "neither end listed" arm and be graded down.
        """
        dc_client = self.config.is_dc(client_ip) is True
        dc_server = self.config.is_dc(server_ip) is True
        rep_client = self.config.is_replicator(client_ip)
        listed_client = dc_client or rep_client
        listed_server = dc_server or self.config.is_replicator(server_ip)

        if opnum == DRS_REPLICA_ADD:
            # ReplicaAdd is the push trigger.  --drs-replicators exempts
            # hosts from the opnum-3 PULL only, by its own definition, so a
            # replicator calling ReplicaAdd is still reported.
            if not dc_client and dc_server:
                return ("RPC-DRS-DCSHADOW", "trigger",
                        DRS_STAGE_SEVERITY["trigger"])
            return None

        # opnum 3, the replication pull.
        if dc_client and not dc_server:
            return ("RPC-DRS-DCSHADOW", "rogue-source",
                    DRS_STAGE_SEVERITY["rogue-source"])
        if not listed_client and dc_server:
            return ("RPC-DRS-DCSYNC", "call", DRS_STAGE_SEVERITY["call"])
        if not listed_client and not listed_server:
            return ("RPC-DRS-DCSYNC", "unlisted-server",
                    DRS_STAGE_SEVERITY["unlisted-server"])
        return None

    def _drs_call(self, ts, subject, base, assoc, opnum, client_ip,
                  server_ip, call_id):
        """
        DCSync and DCShadow, from the cleartext request header.

        No CVE exists for either: both are abuse of directory replication
        working exactly as designed, so the finding names the behaviour and
        carries an ATT&CK id for ticketing.  What separates impacket from
        mimikatz from an agent sits in the sealed stub or in a runtime default
        anyone can change, so the tool is reported as not attributable rather
        than guessed at.

        A passive sensor cannot stop the call.  The value is the alert landing
        while the dump is still paging, which is why the first qualifying call
        emits immediately instead of waiting for the run to finish.
        """
        decided = self._drs_stage(opnum, client_ip, server_ip)
        assoc.drs_calls += 1
        if decided is None:
            return
        code, stage, severity = decided
        technique = (DRS_TECHNIQUE_ROGUE_DC if code == "RPC-DRS-DCSHADOW"
                     else DRS_TECHNIQUE_DCSYNC)
        # Register the pending call so the server's answer can grade it; the
        # answer never gates the finding, which is already out.
        assoc.pending_calls[call_id] = (IF_DRSUAPI, opnum, ts)
        if stage in assoc.drs_stages:
            # Latched.  Later pages of the same run only raise the counters.
            return
        assoc.drs_stages.add(stage)
        d = dict(base, call=DRS_OPNAMES.get(opnum, str(opnum)), stage=stage,
                 technique=technique, tool=DRS_TOOL_UNATTRIBUTABLE,
                 outcome="unanswered", calls=assoc.drs_calls,
                 bytes_from_server=assoc.drs_bytes)
        if stage == "unlisted-server":
            d["note"] = ("neither end is in --dc or --drs-replicators: "
                         "either a DC is missing from --dc, or this is a "
                         "rogue replication pair")
        elif stage == "rogue-source":
            d["note"] = ("a domain controller is pulling changes from a host "
                         "that is not a known DC - the second half of "
                         "lsadump::dcshadow; a healthy domain never does this")
        elif stage == "trigger":
            d["note"] = ("ReplicaAdd from a host that is not a known DC - "
                         "the DCShadow push trigger")
        else:
            d["note"] = ("directory replication pull from a host that is "
                         "neither a DC nor a declared replicator")
        self.emitter.emit(ts, code, subject, d, severity=severity,
                          key_extra=(stage,))

    def _drs_outcome(self, ts, subject, assoc, pending, accepted):
        """
        Grade the run by the server's answer, once per association.

        The Win32 return code lives inside the sealed stub, so a response
        proves the server answered, NOT that the dump succeeded - the detail
        says so rather than implying it.  Latched, because a paged dump
        answers many times and one graded line per run is the useful one.
        """
        uuid, opnum, _ = pending
        if uuid != IF_DRSUAPI or opnum not in DRS_WATCHED_OPNUMS:
            return
        if assoc.drs_outcome_fired or not assoc.drs_stages:
            return
        assoc.drs_outcome_fired = True
        stage = sorted(assoc.drs_stages)[0]
        code = ("RPC-DRS-DCSHADOW" if stage in ("trigger", "rogue-source")
                else "RPC-DRS-DCSYNC")
        # Severity is the STAGE's, unchanged by the answer.  An answer grades
        # what happened, it does not re-rank the behaviour, and the preflight
        # fixes severity per stage.
        severity = DRS_STAGE_SEVERITY[stage]
        self.emitter.emit(
            ts, code, subject,
            {"interface": "drsuapi", "opnum": opnum,
             "call": DRS_OPNAMES.get(opnum, str(opnum)), "stage": stage,
             "outcome": "response" if accepted else "fault",
             "calls": assoc.drs_calls,
             "bytes_from_server": assoc.drs_bytes,
             "technique": (DRS_TECHNIQUE_ROGUE_DC
                           if code == "RPC-DRS-DCSHADOW"
                           else DRS_TECHNIQUE_DCSYNC),
             "tool": DRS_TOOL_UNATTRIBUTABLE,
             "note": ("the Win32 result is inside the sealed stub, so an "
                      "answer does not prove the dump succeeded")},
            severity=severity, key_extra=(stage, "outcome"))

    def _eventlog_backup(self, ts, subject, base, assoc, stub, opnum, sealed,
                         server_ip):
        """
        MS-EVEN event-log backup as an arbitrary file-write primitive:
        SafeBreach's "EventLogin" (CVE-2025-29969) and its bypass
        (CVE-2026-50502).

        ElfrOpenBELW (opnum 9) opens a backed-up log from a caller-named path;
        ElfrBackupELFW (opnum 1) writes a backup to a caller-named
        destination.  The exploit chains them: open an attacker file, back it
        up into the victim's Startup folder as a .hta.  The opnum is in the
        cleartext REQUEST header, so this fires even at PKT_PRIVACY - the
        stub, when readable, grades the finding rather than gating it.

        One finding, both CVEs, because nothing on the wire separates them:
        the TOCTOU swap and the HTA-after-header payload both happen off-tap.
        This supersedes the generic coercion finding for opnum 9 - opnum 9 to
        an off-box path is also an NTLM coercion primitive, and the detail
        says so, so no framing is lost by consolidating.
        """
        cluster = list(EVENTLOG_BACKUP_CLUSTER)
        name = EVENTLOG_BACKUP_CALLS[IF_EVEN][opnum]
        d = dict(base, call=name, cve_cluster=cluster)

        if sealed:
            # Can't read the destination.  Only the sealed open->backup
            # SEQUENCE on one association is worth a word: a lone sealed call
            # on this busy interface is ordinary administration.
            if opnum == ELFR_OPEN_BELW:
                assoc.elfr_open_offbox = assoc.elfr_open_offbox or "sealed"
                return
            if opnum == ELFR_BACKUP_ELFW and assoc.elfr_open_offbox \
                    and not assoc.elfr_backup_fired:
                assoc.elfr_backup_fired = True
                self.emitter.emit(
                    ts, "RPC-EVENTLOG-BACKUP-WRITE", subject,
                    dict(d, confidence="opnum-only", stage="sequence",
                         note="ElfrOpenBELW followed by ElfrBackupELFW on one "
                              "sealed association; stub not readable"),
                    severity="high", key_extra=(opnum, "sealed-seq"))
            return

        paths = extract_wide_paths(stub)

        if opnum == ELFR_OPEN_BELW:
            offbox = next((h for h in (_is_off_box(p) for p in paths) if h), "")
            if offbox:
                assoc.elfr_open_offbox = offbox
                external = self.config.in_local(offbox) is not True
                self.emitter.emit(
                    ts, "RPC-EVENTLOG-BACKUP-WRITE", subject,
                    dict(d, source_paths=paths, source_host=offbox,
                         external_source=bool(external), stage="open",
                         confidence="source-path",
                         note="ElfrOpenBELW against an off-box file: opens the "
                              "write chain AND coerces the server to "
                              "authenticate to that host (NTLM relay vector)"),
                    severity="critical", key_extra=(opnum, offbox))
            else:
                # Local open.  Record it for the probe counter and, if it is
                # the start of a sealed-less sequence, as the prior step; but
                # a single local open is legitimate admin backup reading.
                for pth in paths:
                    assoc.elfr_probe_paths.add(pth.lower())
                if paths:
                    assoc.elfr_open_offbox = assoc.elfr_open_offbox or "local"
                self._eventlog_probe(ts, subject, base, assoc)
            return

        # ElfrBackupELFW: the destination is the write.
        suspect = next(((p, r) for p in paths
                        for r in (_backup_dest_suspect(p),) if r), None)
        offbox = next((h for h in (_is_off_box(p) for p in paths) if h), "")
        if suspect:
            dest, why = suspect
            external = bool(offbox) and self.config.in_local(offbox) is not True
            self.emitter.emit(
                ts, "RPC-EVENTLOG-BACKUP-WRITE", subject,
                dict(d, dest_path=dest, dest_reason=why,
                     external_source=external, stage="backup",
                     confidence="dest-path",
                     note="ElfrBackupELFW to a destination that is not an "
                          "ordinary .evtx backup - the file-write primitive"),
                severity="critical", key_extra=(opnum, dest.lower()))
        elif paths:
            # A .evtx destination named locally: how a legitimate scheduled
            # backup looks.  Record it, do not accuse it.
            self.emitter.emit(
                ts, "RPC-EVENTLOG-BACKUP-WRITE", subject,
                dict(d, dest_path=paths[0], stage="backup",
                     confidence="benign-shape",
                     note="ElfrBackupELFW to a local .evtx path; consistent "
                          "with a legitimate backup"),
                severity="medium", key_extra=(opnum, "local-evtx"))

    def _eventlog_probe(self, ts, subject, base, assoc):
        """
        The unfixed ElfrOpenBELW path-existence oracle SafeBreach noted: a
        burst of opens against varied paths is enumeration, not a backup.
        Latches once per association at the threshold.
        """
        if assoc.elfr_backup_fired:
            return
        if len(assoc.elfr_probe_paths) < EVENTLOG_PROBE_THRESHOLD:
            return
        if assoc.elfr_probe_fired:
            return
        assoc.elfr_probe_fired = True
        self.emitter.emit(
            ts, "RPC-EVENTLOG-PATH-PROBE", subject,
            dict(base, distinct_paths=len(assoc.elfr_probe_paths),
                 note="many ElfrOpenBELW opens against distinct paths on one "
                      "association; the arbitrary-path-existence oracle"),
            key_extra=("probe",))

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
        cve = COERCION_CVES.get((uuid, opnum))
        if cve:
            d["cve"] = cve
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

    def _tslicensing_call(self, ts, subject, base, assoc, opnum, trailer,
                          stub, hdr):
        """
        CVE-2024-38077 "MadLicense".

        The patch registers TLSRpcSecurityCallback on the RD Licensing
        interface, which refuses any call below RPC_C_AUTHN_LEVEL_PKT_PRIVACY.
        So the condition is the LEVEL, not merely a missing auth verifier -
        a call authenticated at CONNECT or PKT_INTEGRITY is refused by a
        patched host as well, and is just as anomalous on the wire.

        Two stages, following the shape used for CVE-2021-1678: the heap spray
        of TLSRpcConnect calls is posture, the TLSRpcTelephoneRegisterLKP call
        that carries the overflow is the exploit step.
        """
        level = trailer["auth_level"] if trailer else RPC_C_AUTHN_LEVEL_NONE
        if level >= TSLICENSING_REQUIRED_LEVEL:
            return      # what the patched callback accepts: legitimate traffic
        d = dict(base,
                 cve_cluster=list(RDL_RCE_CLUSTER + RDL_DOS_CLUSTER),
                 auth_level=AUTHN_LEVEL_NAMES.get(level, level),
                 required_level=AUTHN_LEVEL_NAMES[TSLICENSING_REQUIRED_LEVEL],
                 workgroup_caveat="a host with DisableWorkgroupAuthEnforcement "
                                  "set may legitimately accept this")

        if opnum == TSL_RPC_CONNECT:
            q = assoc.tsl_connects
            cutoff = ts - self.config.window
            q.append(ts)
            while q and q[0] < cutoff:
                q.popleft()
            if (len(q) >= self.config.tslicensing_spray_threshold
                    and not assoc.tsl_spray_fired):
                assoc.tsl_spray_fired = True
                self.emitter.emit(ts, "RPC-TSLICENSING-PREAUTH", subject,
                                  dict(d, stage="spray",
                                       call="TLSRpcConnect",
                                       connects=len(q),
                                       window_seconds=self.config.window),
                                  severity="high", key_extra=("spray",))
            return

        if opnum == TSL_RPC_TELEPHONE_REGISTER_LKP:
            # Reported at the call rather than held until the server answers:
            # a successful overflow can leave no answer at all, and silence is
            # the most alarming outcome, not a reason to stay quiet.
            assoc.pending_calls[hdr["call_id"]] = (
                IF_TSLICENSING, opnum, ts)
            self.emitter.emit(ts, "RPC-TSLICENSING-PREAUTH", subject,
                              dict(d, stage="call",
                                   cve="CVE-2024-38077",
                                   call="TLSRpcTelephoneRegisterLKP",
                                   outcome="unanswered",
                                   stub_bytes=len(stub) if stub else 0),
                              key_extra=("call",))
            return

        # Any OTHER method on this interface below packet privacy.  Six of the
        # seven July 2024 RDL bugs have no public patch diff, so their opnums
        # are unknown - but the callback they all sit behind is interface-wide.
        # Reporting only the one opnum we can name would leave the other two
        # 9.8 RCEs undetectable, so the interface condition is reported on its
        # own, with the opnum stated and no CVE claimed.
        self.emitter.emit(ts, "RPC-TSLICENSING-PREAUTH", subject,
                          dict(d, stage="interface",
                               call=f"opnum {opnum}",
                               attribution="cluster only; no public patch diff "
                                           "maps this opnum to a CVE"),
                          severity="high", key_extra=("iface", opnum))

    def _tslicensing_outcome(self, ts, subject, pending, accepted):
        """Grade the overflow call by how the server answered it."""
        uuid, opnum, _ = pending
        if uuid != IF_TSLICENSING or opnum != TSL_RPC_TELEPHONE_REGISTER_LKP:
            return
        d = {"cve": "CVE-2024-38077",
             "cve_cluster": list(RDL_RCE_CLUSTER + RDL_DOS_CLUSTER),
             "interface": "tslicensing",
             "opnum": opnum, "call": "TLSRpcTelephoneRegisterLKP",
             "stage": "call"}
        if accepted:
            self.emitter.emit(ts, "RPC-TSLICENSING-PREAUTH", subject,
                              dict(d, outcome="accepted",
                                   note="server answered the pre-auth call; "
                                        "the security callback did not stop it"),
                              key_extra=("accepted",))
        else:
            self.emitter.emit(ts, "RPC-TSLICENSING-PREAUTH", subject,
                              dict(d, outcome="rejected",
                                   note="server faulted the call, consistent "
                                        "with the callback enforcing or the "
                                        "host being patched"),
                              severity="high", key_extra=("rejected",))

    def _lsm_container_bind(self, ts, subject, base, assoc):
        r"""
        CVE-2022-37973 / CVE-2022-37998.

        The LSM container interface is meant only for Hyper-V containers over
        hvsocket, and its security callback always returns RPC_S_OK.  Endpoint
        multiplexing exposes it over \pipe\LSM_API_service, so any bind that
        reaches a network tap is illegitimate - there is no remote caller for
        it.  The bind header is cleartext, so this holds at PKT_PRIVACY.

        Reported once per association at high; the sustained call loop that
        actually drives the leak to a crash escalates it (see the call hook).
        Both CVEs share the interface and wire shape, so attribute the cluster
        rather than split a code.
        """
        if assoc.lsm_bind_reported:
            return
        assoc.lsm_bind_reported = True
        self.emitter.emit(
            ts, "RPC-LSM-CONTAINER-REMOTE", subject,
            dict(base, stage="bind", cve_cluster=list(LSM_CONTAINER_CLUSTER),
                 note="hvsocket-only container interface bound over the "
                      "network; no legitimate remote caller exists"),
            severity="high", key_extra=("bind",))

    def _lsm_container_call(self, ts, subject, base, assoc, opnum):
        """A sustained call loop is what turns the leak into an LSM crash."""
        assoc.lsm_call_count += 1
        if (assoc.lsm_call_count >= LSM_CONTAINER_LOOP_THRESHOLD
                and not assoc.lsm_loop_fired):
            assoc.lsm_loop_fired = True
            call = LSM_CONTAINER_CALLS.get(opnum, f"opnum {opnum}")
            self.emitter.emit(
                ts, "RPC-LSM-CONTAINER-REMOTE", subject,
                dict(base, stage="loop", call=call,
                     cve_cluster=list(LSM_CONTAINER_CLUSTER),
                     calls=assoc.lsm_call_count,
                     note="sustained call loop on the container interface; "
                          "the memory leak that ends in an LSM crash"),
                severity="critical", key_extra=("loop",))

    def _tsts_getsessionids(self, ts, subject, base, assoc, call_id):
        """
        CVE-2025-26651.  On Win11 / Server 2025, MS-TSTS RpcGetSessionIds
        (opnum 8) is an unimplemented stub that crashes LSM on one call; a
        domain account is enough to kill LSM on a DC.  Win10 builds still
        implement it, so the crash is graded by the server's answer, not
        assumed: the request is reported at high with outcome "unanswered",
        and the response/fault hook grades it.  The opnum is in the cleartext
        request header, so this fires even when the stub is sealed.
        """
        assoc.pending_calls[call_id] = (
            IF_TSTS_ENUM, TSTS_GET_SESSION_IDS, ts)
        self.emitter.emit(
            ts, "RPC-LSM-GETSESSIONIDS-CRASH", subject,
            dict(base, call="RpcGetSessionIds", cve="CVE-2025-26651",
                 outcome="unanswered",
                 note="no legitimate remote caller on affected builds; one "
                      "call crashes LSM where the method is a stub"),
            severity="high", key_extra=("call",))

    def _tsts_outcome(self, ts, subject, pending, accepted):
        """Grade the RpcGetSessionIds call by how (or whether) the server answered."""
        uuid, opnum, _ = pending
        if uuid != IF_TSTS_ENUM or opnum != TSTS_GET_SESSION_IDS:
            return
        d = {"interface": "termsrv-enum", "opnum": opnum,
             "call": "RpcGetSessionIds", "cve": "CVE-2025-26651"}
        if accepted:
            # A normal result means the build implements the method (Win10):
            # the host is not the crash target.  Lower concern, recorded.
            self.emitter.emit(
                ts, "RPC-LSM-GETSESSIONIDS-CRASH", subject,
                dict(d, outcome="answered", note="server returned a result; "
                     "build appears to implement the method (not the crash "
                     "target)"),
                severity="medium", key_extra=("answered",))
        else:
            # A fault is the stub path (DebugBreak/E_NOTIMPL) - the crash case.
            self.emitter.emit(
                ts, "RPC-LSM-GETSESSIONIDS-CRASH", subject,
                dict(d, outcome="faulted", note="server faulted the call, "
                     "consistent with the unimplemented stub that crashes LSM"),
                severity="critical", key_extra=("faulted",))

    def _adcs_chase_bind(self, ts, subject, base, client_ip, server_ip):
        """
        Certighost (CVE-2026-54121), the observable half.

        A CA steered by cdc:/rmd: attributes "chases" an attacker-run host for
        a DC's identity.  The enrollment request is sealed, so those
        attributes are normally invisible - but the chase is an OUTBOUND
        connection from the CA, and its LSARPC bind header is cleartext.  So
        the signal is: a known CA is the CLIENT of an LSARPC bind to a host
        that is not a declared DC, shortly after it served enrollment.

        CA identity is learned passively from enrollment binds, or declared
        with --ca-hosts (which needs no prior enrollment, since a configured
        CA is always a CA).  The server leg over LDAP/389 belongs to
        ldapwatch; this correlates the LSARPC leg only.
        """
        is_ca = self.config.is_ca(client_ip)
        if is_ca is not True:
            seen = self.ca_enroll_seen.get(client_ip)
            if seen is None or ts - seen > CHASE_WINDOW_SECONDS:
                return
        # The destination must not be a known DC.  If no DC set is declared the
        # rule is undecidable and stays silent, like RPC-NETLOGON-UNEXPECTED.
        if self.config.is_dc(server_ip) is not False:
            return
        key = (client_ip, server_ip)
        if key in self.chase_fired:
            return
        self.chase_fired.add(key)
        self.emitter.emit(
            ts, "RPC-ADCS-CHASE", subject,
            dict(base, cve="CVE-2026-54121", ca_host=client_ip,
                 chase_target=server_ip,
                 ca_source=("configured" if is_ca is True else "observed"),
                 ldap_leg="UDP/389 to the same host belongs to ldapwatch; "
                          "cross-reference",
                 note="AD CS host opened an outbound LSARPC bind to a non-DC "
                      "shortly after serving enrollment - the DC 'chase'"),
            severity="critical", key_extra=("chase", server_ip))

    def _adcs_chase_attr(self, ts, subject, base, stub):
        """
        If a legacy CA accepts an UNSEALED enrollment request, the chase
        attribute is readable directly - a second, independent signal.
        """
        low = stub.lower() if stub else b""
        if not (CHASE_ATTR_MARKER in low or CHASE_ATTR_MARKER_W in low):
            return
        self.emitter.emit(
            ts, "RPC-ADCS-CHASE", subject,
            dict(base, cve="CVE-2026-54121", stage="attribute",
                 note="unsealed enrollment request carries a cdc: chase "
                      "attribute directly"),
            severity="critical", key_extra=("attr",))

    def _winreg_hive(self, ts, subject, base, assoc, stub, opnum, sealed,
                     server_ip):
        """
        MS-RRP hive save and load - secretsdump's non-DCSync path.

        impacket's secretsdump enables and starts RemoteRegistry over svcctl,
        calls OpenLocalMachine, opens the SAM / SECURITY / SYSTEM hive with
        BaseRegCreateKey, then BaseRegSaveKey writes that hive to a file which
        it reads back over SMB.  The service start and the HKLM open were
        already reported as exec primitives; this is the call that says the
        CREDENTIAL HIVES were dumped, which is the part that was missing.

        Attributed by behaviour (T1003.002), not by CVE: saving a hive is a
        legitimate backup operation performed by the wrong principal.

        The opnum is cleartext so this fires at PKT_PRIVACY.  The destination
        path and the hive name grade the finding; when the stub is sealed the
        finding says so rather than guessing.  The hive name comes from the
        BaseRegCreateKey / BaseRegOpenKey that preceded the save on the same
        association - those only latch, never emit, so one dump is one
        finding and not three.

        The dedup key carries the HIVE, not just the opnum.  The subject is
        client -> server, so without it a run that takes SAM, then SECURITY,
        then SYSTEM - which is exactly what secretsdump does - would collapse
        into a single finding naming only the first.
        """
        stage = "save" if opnum in WINREG_SAVE_OPNUMS else "load"
        d = dict(base, call=WINREG_HIVE_OPNAMES[opnum], stage=stage,
                 technique=WINREG_TECHNIQUE, tool=WINREG_TOOL_UNATTRIBUTABLE)
        hive = assoc.winreg_key_name
        if hive:
            d["key"] = hive
        is_cred = bool(hive and hive.strip("\\").split("\\")[0].lower()
                       in WINREG_CREDENTIAL_HIVES)
        d["credential_hive"] = is_cred

        if sealed:
            self.emitter.emit(
                ts, "RPC-WINREG-HIVE-SAVE", subject,
                dict(d, confidence="opnum-only", path_visible=False,
                     note="stub sealed; destination path not observable"),
                severity="critical" if is_cred else "high",
                key_extra=(opnum, "sealed", hive or ""))
            return

        path = handle_then_unicode_string(stub)
        if path:
            d["path"] = path
        remote = [p for p in extract_unc_paths(stub)
                  if unc_host(p) and unc_host(p) != server_ip]
        if remote:
            external = [p for p in remote
                        if self.config.in_local(unc_host(p)) is not True]
            self.emitter.emit(
                ts, "RPC-WINREG-HIVE-SAVE", subject,
                dict(d, unc_paths=remote, external_source=bool(external),
                     path_visible=True, confidence="off-box-path"),
                severity="critical",
                key_extra=(opnum, "unc", hive or "", path or ""))
            return

        # A local destination is what secretsdump actually uses - it writes to
        # ..\Temp\<random>.tmp and reads it back over SMB - so a local path
        # is not a mitigating factor when the hive is a credential store.
        self.emitter.emit(
            ts, "RPC-WINREG-HIVE-SAVE", subject,
            dict(d, path_visible=bool(path), external_source=False,
                 confidence="local-path",
                 note=("credential hive written to a local file; this is the "
                       "shape secretsdump uses before reading it back over "
                       "SMB" if is_cred else
                       "hive written to a local file")),
            severity="critical" if is_cred else
            WINREG_HIVE_STAGE_SEVERITY[stage],
            key_extra=(opnum, "local", hive or "", path or ""))

    def _certenroll_content(self, ts, subject, base, assoc, stub):
        """
        The AD CS escalations that are visible in an UNSEALED enrollment
        request: ESC1, ESC3, ESC6, ESC15 and ESC17.

        None of their misconfigurations are observable - they live in template
        attributes, the CA registry and object ACLs.  What is observable is the
        request asking for an identity or a capability, and only below
        PKT_PRIVACY, which is the ESC11 condition this module already reports.
        Four codes rather than one with stages because the wire shapes are
        genuinely different: ESC6 puts the SAN in the ATTRIBUTES string while
        ESC1 and ESC17 put it in the CSR and differ by EKU.

        Everything taken from the CSR is an OID scan, not a parse, and says so.
        """
        shape = certenroll_request_shape(stub)
        if not shape:
            return
        common = dict(technique=ESC_TECHNIQUE, tool=ESC_TOOL_UNATTRIBUTABLE)

        # --- ESC6: the SAN arrives in the attributes string ---------------
        if shape["san_attribute"]:
            kind = ("upn" if shape["attr_upn"]
                    else "dns" if shape["attr_dns"] else "unknown")
            d = dict(base, **common, esc="ESC6", san_kind=kind,
                     field_confidence="attribute-text")
            value = shape.get("san_value") or ""
            acct = assoc.ntlm_account
            if acct and value:
                if same_principal(acct, value):
                    d["requester_match"] = "self"
                    sev = "high"
                    d["note"] = ("the CA accepts attribute SANs at all, which "
                                 "needs EDITF_ATTRIBUTESUBJECTALTNAME2; this "
                                 "request names its own requester")
                else:
                    d["requester_match"] = "other"
                    sev = "critical"
                    d["note"] = ("request names a principal other than the "
                                 "authenticated requester")
            else:
                d["requester_match"] = "unknown"
                sev = "critical"
                d["note"] = ("requester identity not observable (Kerberos, or "
                             "no NTLM AUTHENTICATE seen)")
            # Honour --no-identities: report the verdict, never the names.
            if value and self.config.record_identities:
                d["san"] = value
            if self.config.record_identities and acct:
                d["requester"] = acct
            self.emitter.emit(ts, "RPC-CERTENROLL-ESC6-SAN-ATTR", subject, d,
                              severity=sev, key_extra=("esc6",))

        # --- ESC1: a UPN subjectAltName in the CSR with client auth -------
        if (shape["csr_subject_alt_name"] and shape["csr_upn_othername"]
                and (shape["eku_client_auth"] or shape["eku_any_purpose"])):
            self.emitter.emit(
                ts, "RPC-CERTENROLL-ESC1-SAN", subject,
                dict(base, **common, esc="ESC1", field_confidence="oid-scan",
                     eku=("any-purpose" if shape["eku_any_purpose"]
                          else "client-auth"),
                     note="CSR carries a UPN subjectAltName and an EKU that "
                          "authenticates; the name itself is DER and is not "
                          "extracted"),
                key_extra=("esc1",))

        # --- ESC17: a DNS identity with server auth -----------------------
        if (shape["csr_subject_alt_name"] and shape["eku_server_auth"]
                and not shape["csr_upn_othername"]):
            self.emitter.emit(
                ts, "RPC-CERTENROLL-ESC17-DNS", subject,
                dict(base, **common, esc="ESC17", field_confidence="oid-scan",
                     note="CSR names a DNS identity with a server-auth EKU: "
                          "the shape used to impersonate a host"),
                key_extra=("esc17",))

        # --- ESC3: the enrollment-agent EKU -------------------------------
        if shape["eku_request_agent"]:
            self.emitter.emit(
                ts, "RPC-CERTENROLL-ESC3-AGENT", subject,
                dict(base, **common, esc="ESC3", field_confidence="oid-scan",
                     note="Certificate Request Agent EKU: enrolling on behalf "
                          "of another principal, or obtaining the agent "
                          "certificate that permits it"),
                key_extra=("esc3",))

        # --- ESC15: Application Policies injected into the request --------
        if shape["app_policies"] and (shape["eku_client_auth"]
                                      or shape["eku_request_agent"]
                                      or shape["eku_any_purpose"]):
            self.emitter.emit(
                ts, "RPC-CERTENROLL-ESC15-APP-POLICY", subject,
                dict(base, **common, esc="ESC15", cve=ESC15_CVE,
                     field_confidence="oid-scan",
                     note="request supplies Application Policies alongside an "
                          "authenticating EKU; on an unpatched CA a v1 "
                          "template grants them"),
                key_extra=("esc15",))

    def _certadmin_bind(self, ts, subject, base, assoc, level):
        """
        MS-CSRA bound below PKT_PRIVACY.

        MS-CSRA 3.1.4.1 says a CA with IF_ENFORCEENCRYPTICERTADMIN refuses any
        admin call that is not at packet privacy - the same requirement
        IF_ENFORCEENCRYPTICERTREQUEST places on enrollment, which is ESC11.
        So this is the ESC11 condition on the CA MANAGEMENT interface, and the
        ESC catalogue never gave it a number.  It is strictly worse than
        ESC11: relaying into enrollment gets a certificate, relaying into
        administration gets the CA.
        """
        if assoc.csra_bind_reported:
            return
        assoc.csra_bind_reported = True
        self.emitter.emit(
            ts, "RPC-CERTADMIN-REMOTE", subject,
            dict(base, stage="bind-below-privacy",
                 technique=ESC_TECHNIQUE, tool=ESC_TOOL_UNATTRIBUTABLE,
                 level=AUTHN_LEVEL_NAMES.get(level, level),
                 required_level=AUTHN_LEVEL_NAMES[CSRA_REQUIRED_LEVEL],
                 note="CA remote administration below packet privacy; a "
                      "patched CA with IF_ENFORCEENCRYPTICERTADMIN refuses "
                      "this, so it is unpatched posture or a live relay"),
            severity=CSRA_STAGE_SEVERITY["bind-below-privacy"],
            key_extra=("csra-bind",))

    def _certadmin_call(self, ts, subject, base, opnum):
        """
        A mutating MS-CSRA call - the ESC7 abuse step, and the step that
        ENABLES ESC6 and ESC11 in the first place.

        The opnum is in the cleartext REQUEST header, so these fire at
        PKT_PRIVACY too.  Read-only methods (Ping, GetCRL, the EnumView and
        BackupGet families) are never reported, the same way IDL_DRSBind and
        IDL_DRSCrackNames stay silent on the replication interface.
        """
        if opnum == CSRA_SERVER_CONTROL:
            stage = "server-control"
        elif opnum in CSRA_REQUEST_OPNUMS:
            stage = "request-manipulation"
        elif opnum in CSRA_CONFIG_OPNUMS:
            stage = "config-write"
        else:
            return
        d = dict(base, stage=stage, call=CSRA_OPNAMES[opnum],
                 technique=ESC_TECHNIQUE, tool=ESC_TOOL_UNATTRIBUTABLE)
        if opnum in CSRA_DERIVED_OPNUMS:
            d["opnum_provenance"] = "derived from the MS-CSRA IDL ordering"
        if stage == "config-write":
            d["note"] = ("CA configuration write: this is how EditFlags "
                         "(ESC6) and InterfaceFlags (ESC11) get enabled, and "
                         "how CA auditing gets turned off")
        elif stage == "request-manipulation":
            d["note"] = ("a pending certificate request was altered or "
                         "resubmitted: the Manage Certificates half of ESC7")
        else:
            d["note"] = ("ServerControl unregisters ICertAdminD/D2: remote "
                         "denial of CA administration")
        self.emitter.emit(ts, "RPC-CERTADMIN-REMOTE", subject, d,
                          severity=CSRA_STAGE_SEVERITY[stage],
                          key_extra=("csra", opnum))

    def _printer_driver_call(self, ts, subject, base, stub, uuid, opnum,
                             sealed, server_ip):
        """
        PrintNightmare (CVE-2021-34527, and CVE-2021-1675 before it).

        Windows does not check that pDriverPath / pConfigFile / pDataFile are
        local to the machine, so the spooler will load a DLL the attacker
        serves over UNC, as SYSTEM.  Both the MS-RPRN and MS-PAR routes are
        covered: the July 2021 out-of-band update closed the MS-RPRN vector
        while RCE remained reachable through MS-PAR with Point and Print on.

        The opnum is in the cleartext REQUEST header, so the call is visible
        even at PKT_PRIVACY.  A readable stub raises confidence rather than
        being required: an off-box UNC in the driver container is the
        confirmation, and its absence is reported, never assumed.
        """
        opname = PRINTNIGHTMARE_CALLS[uuid][opnum]
        d = dict(base, call=opname, cve="CVE-2021-34527")
        if sealed:
            self.emitter.emit(ts, "RPC-PRINTNIGHTMARE-DRIVER-ADD", subject,
                              dict(d, unc_path_visible=False,
                                   confidence="opnum-only",
                                   note="stub sealed; driver path not observable"),
                              severity="high", key_extra=(uuid, opnum))
            return
        paths = extract_unc_paths(stub)
        remote = [p for p in paths if unc_host(p) and unc_host(p) != server_ip]
        if remote:
            external = [p for p in remote
                        if self.config.in_local(unc_host(p)) is not True]
            self.emitter.emit(ts, "RPC-PRINTNIGHTMARE-DRIVER-ADD", subject,
                              dict(d, driver_paths=remote,
                                   external_source=bool(external),
                                   unc_path_visible=True,
                                   confidence="driver-path"),
                              severity="critical", key_extra=(uuid, opnum))
            return
        # A driver install naming only local paths is how legitimate driver
        # deployment looks.  Still worth recording, but not as an exploit.
        self.emitter.emit(ts, "RPC-PRINTNIGHTMARE-DRIVER-ADD", subject,
                          dict(d, unc_path_visible=True,
                               driver_paths=[], external_source=False,
                               confidence="local-paths-only",
                               note="no off-box driver path observed"),
                          severity="medium", key_extra=(uuid, opnum))

    def _lsa_secret_call(self, ts, subject, base, assoc, stub, opnum, sealed):
        """
        MS-LSAD secret access - how the DPAPI domain backup key is stolen.

        Mimikatz lsadump::backupkeys, SharpDPAPI backupkey and DSInternals
        Get-LsaBackupKey all call LsarRetrievePrivateData (opnum 43) for the
        LSA secret G$BCKUPKEY_PREFERRED / G$BCKUPKEY_<guid>.  None of them go
        through MS-BKRP.  One domain backup key decrypts every DPAPI blob in
        the domain, which is why that stage is critical and not high.

        Attributed by behaviour, not CVE: there is nothing to patch here and
        nothing to name.  The opnum is in the cleartext REQUEST header so the
        call is seen at PKT_PRIVACY; the secret NAME is NDR in the body, so it
        grades when readable and the finding says so when it is not.

        LsarOpenSecret only LATCHES the name for the handle-based
        LsarQuerySecret / LsarSetSecret that follows - it never emits, so an
        open-then-query pair is one finding rather than two.
        """
        opname = LSA_SECRET_OPNAMES[opnum]
        name, conf = (None, "sealed") if sealed else lsa_secret_name(stub)

        if opnum == LSA_OPEN_SECRET:
            assoc.lsa_secret_name = name
            return

        if opnum in LSA_SECRET_HANDLE and name is None and assoc.lsa_secret_name:
            name, conf = assoc.lsa_secret_name, "handle-latched"

        code = ("RPC-LSA-SECRET-READ" if opnum in LSA_SECRET_READ_OPNUMS
                else "RPC-LSA-SECRET-WRITE")
        d = dict(base, call=opname, technique=LSA_TECHNIQUE_CREDS,
                 tool=LSA_TOOL_UNATTRIBUTABLE, field_confidence=conf)

        if name and LSA_DPAPI_BACKUP_MARKER in name.upper():
            self.emitter.emit(
                ts, code, subject,
                dict(d, secret=name, stage="dpapi-backup-key",
                     note="DPAPI domain backup key; decrypts every DPAPI "
                          "secret in the domain"),
                severity="critical", key_extra=(opnum, "bckupkey"))
            return
        if name:
            self.emitter.emit(ts, code, subject,
                              dict(d, secret=name, stage="named"),
                              key_extra=(opnum, "named"))
            return
        self.emitter.emit(
            ts, code, subject,
            dict(d, stage="sealed" if sealed else "name-unreadable",
                 note="secret name not observable; the call itself is rare "
                      "and privileged over the network"),
            key_extra=(opnum, "unnamed"))

    def _backupkey_call(self, ts, subject, base, stub, sealed):
        """
        MS-BKRP BackuprKey (opnum 0), graded by its action GUID.

        The rule this replaces fired at high on EVERY call to this opnum,
        which on a real domain means every DPAPI master-key backup - an
        ordinary consequence of a user changing their password.  Windows own
        event 4692 is documented as noisy for exactly that reason, so a
        blanket high here is a false-positive generator.  Same shape as the
        blunt RPC-DCSYNC-CALL that the graded DRS stages superseded.

        pguidActionAgent is an [in] GUID* in the NDR stub: readable below
        privacy, sealed at it.  The wrap and public-key fetches drop to low,
        the unwraps stay high, and the sealed case is reported as sealed
        rather than assumed to be either.
        """
        d = dict(base, call="BackuprKey")
        guid = None if sealed else bkrp_action_guid(stub)
        if guid is None:
            self.emitter.emit(
                ts, "RPC-BACKUPKEY-ACCESS", subject,
                dict(d, stage="sealed" if sealed else "guid-unreadable",
                     confidence="guid-sealed",
                     note="action GUID not observable; cannot separate a "
                          "routine master-key wrap from a secret unwrap"),
                severity="medium", key_extra=("sealed",))
            return
        stage, sev = BKRP_ACTIONS[guid]
        self.emitter.emit(ts, "RPC-BACKUPKEY-ACCESS", subject,
                          dict(d, stage=stage, action_guid=guid,
                               confidence="action-guid"),
                          severity=sev, key_extra=(stage,))

    def _certenroll_level(self, ts, subject, base, uuid, level, trailer,
                          stage, call=None):
        """
        ESC11: NTLM relay to the AD CS enrollment RPC interfaces.

        No CVE exists for this and none is claimed.  The CA flag
        IF_ENFORCEENCRYPTICERTREQUEST makes the interface refuse anything
        below RPC_C_AUTHN_LEVEL_PKT_PRIVACY; it ships ON and gets switched
        OFF to accommodate clients that cannot reach that level.  With it
        off, a relayed authentication enrolls a certificate.

        Reported at the LEVEL, exactly like CVE-2021-1678 on
        IRemoteWinSpool, because the level is what the fix changed.  An
        anonymous bind and an authenticated-but-unsealed one are both below
        the bar but mean different things, so the auth type is carried
        rather than collapsed.

        The bind is posture: a legitimately misconfigured CA and a live
        relay are indistinguishable at bind time.  The enrollment call on
        the same unsealed association is the exploit step, and that is what
        escalates it.
        """
        d = dict(base, technique="ESC11", stage=stage,
                 observed_level=AUTHN_LEVEL_NAMES.get(level, level),
                 required_level=AUTHN_LEVEL_NAMES[CERTENROLL_REQUIRED_LEVEL],
                 setting="IF_ENFORCEENCRYPTICERTREQUEST",
                 authenticated=trailer is not None)
        if call:
            d["call"] = call
        if stage == "call":
            d["note"] = ("certificate request submitted on an association "
                         "that never reached packet privacy")
            self.emitter.emit(ts, "RPC-CERTENROLL-RELAY-LEVEL", subject, d,
                              severity="critical", key_extra=(uuid, "call"))
            return
        d["note"] = ("below the level the CA hardening flag requires; a CA "
                     "with the flag off or an active relay, not proof of "
                     "exploitation")
        self.emitter.emit(ts, "RPC-CERTENROLL-RELAY-LEVEL", subject, d,
                          key_extra=(uuid, "bind"))

    def _dnssrv_operation(self, ts, subject, base, stub, opnum, sealed,
                          server_ip):
        """
        MS-DNSP ServerLevelPluginDll: DnsAdmin to SYSTEM.

        R_DnssrvOperation takes an operation NAME as a string parameter, and
        one of the names it accepts is "ServerLevelPluginDll", whose value is
        a path to a DLL that dns.exe loads in-process as SYSTEM when the
        service next starts.  It is a documented feature, so there is no CVE
        and none is claimed - this is abuse detection.

        The parse is deliberately not a fixed-offset one.  pszOperation is a
        [unique, string] LPCSTR sitting behind another unique pointer and a
        DWORD, so its offset moves with the length of pwszServerName and
        pszZone; the NDR alignment bug this module already shipped once came
        from exactly that assumption.  Instead the operation name is matched
        as the ASCII bytes it is on the wire, and the DLL path - a
        DNSSRV_TYPEID_LPWSTR, UTF-16LE - is extracted separately.  The
        mixture of encodings is in the IDL, not a guess.

        Confidence is graded and never inflated:
          operation-and-path  both the name and a path were readable
          operation-only      the name was there, no path recovered
          opnum-only          the stub is sealed; only the opnum is visible
        """
        opname = DNSP_OPERATION_OPNUMS[opnum]
        d = dict(base, call=opname, technique="DnsAdmin to SYSTEM",
                 operation="ServerLevelPluginDll")
        if sealed:
            # An operation name cannot be read out of ciphertext.  Saying
            # nothing would hide the call entirely; claiming the operation
            # would be inventing it.  So the call is NOT reported here -
            # R_DnssrvOperation is the DNS management workhorse and firing on
            # every sealed one would bury the signal.  The sealed case is
            # covered by the interface posture rules instead.
            return
        if DNSP_PLUGIN_OPERATION not in stub:
            return
        paths = extract_unc_paths(stub)
        remote = [pth for pth in paths
                  if unc_host(pth) and unc_host(pth) != server_ip]
        if remote:
            external = [pth for pth in remote
                        if self.config.in_local(unc_host(pth)) is not True]
            self.emitter.emit(
                ts, "RPC-DNS-SERVERLEVELPLUGINDLL", subject,
                dict(d, plugin_paths=remote, external_source=bool(external),
                     confidence="operation-and-path",
                     note="the DNS service will load this DLL in-process as "
                          "SYSTEM on next restart"),
                severity="critical", key_extra=(opnum, "remote"))
            return
        self.emitter.emit(
            ts, "RPC-DNS-SERVERLEVELPLUGINDLL", subject,
            dict(d, plugin_paths=[], external_source=False,
                 confidence="operation-only",
                 note="operation name observed; no off-box path recovered "
                      "from the stub"),
            severity="high", key_extra=(opnum, "local"))

    def _lsa_anonymous_coercion(self, ts, subject, base, assoc, uuid, opnum):
        """
        CVE-2022-26925.  The coercion call itself was always legal; what the
        May 2022 update changed is that anonymous connections to the LSARPC
        interface are now refused.  So the finding is the anonymity, observed
        on an association that then issues a coercion primitive.
        """
        self.emitter.emit(ts, "RPC-LSA-ANONYMOUS-COERCION", subject,
                          dict(base, cve="CVE-2022-26925",
                               call=COERCION_CALLS[uuid][opnum],
                               auth=AUTHN_NAMES.get(assoc.auth_type,
                                                    assoc.auth_type),
                               anonymous=True),
                          key_extra=(uuid, opnum))

    def _exec_call(self, ts, subject, base, uuid, opnum):
        opname = EXEC_CALLS[uuid][opnum]
        d = dict(base, call=opname)
        if uuid == IF_DRSUAPI and opnum == 3:
            # Superseded by the graded RPC-DRS-DCSYNC stages whenever the tier
            # is armed.  The blunt code fired on EVERY GetNCChanges, which on
            # a real domain means every legitimate DC-to-DC replication, so it
            # is kept only as the disarmed fallback: a deployment with no --dc
            # keeps the visibility it has today instead of going silent.
            if not self.config.drs_armed:
                self.emitter.emit(ts, "RPC-DCSYNC-CALL", subject, d)
            return
        if uuid == IF_BKRP:
            # Superseded by the graded _backupkey_call, which reads the action
            # GUID.  Returning keeps the generic exec-interface code off a
            # call that now has a specific rule, so one condition still
            # yields one finding.
            return
        if uuid == IF_DRSUAPI:
            return
        sev = "medium" if uuid == IF_WINREG else "high"
        self.emitter.emit(ts, "RPC-REMOTE-EXEC-INTERFACE", subject, d,
                          severity=sev, key_extra=(uuid, opnum))

    def _epm_follow(self, ts, subject, assoc, pdu, hdr, body, trailer,
                    server_ip):
        """
        Learn DRSUAPI's dynamic port from the ept_map reply.

        The port is keyed to the SERVER OF THIS 5-TUPLE, not to the address
        in the tower's host floor: floor 5 is an IPv4 address by construction
        and cannot describe a v6 endpoint, so over IPv6 the host floor is
        either absent or something this code has not measured.  The 5-tuple
        is the one thing that is true in both families.

        This is attribution and advice, not admission.  See _drs_port_note.
        """
        asked = self.epm_pending_map.pop((server_ip, hdr["call_id"]), None)
        if asked != IF_DRSUAPI:
            return
        stub = extract_stub(pdu, hdr, body, trailer)
        port = parse_epm_tower(stub).get("tcp_port")
        if not port:
            return
        known = self.learned_drs_ports.setdefault(server_ip, set())
        if port in known:
            return
        known.add(port)
        self._drs_port_note(ts, subject, server_ip, port)

    def _drs_port_note(self, ts, subject, server_ip, port):
        """
        Say the port out loud, once per (server, port).

        A kernel BPF is compiled when the capture starts, so learning a port
        mid-run CANNOT retroactively admit frames the filter already dropped
        - and a DCSync client connects to the mapped port within
        milliseconds of the reply, far faster than any filter could be
        rebuilt.  So the follow does three honest things: it dissects that
        port as DCERPC when the frames do reach us, it names the port in the
        finding, and it tells the operator the one port to pin next run.
        Admission still needs --dynamic-range or --rpc-port.
        """
        if (server_ip, port) in self.drs_port_logged:
            return
        self.drs_port_logged.add((server_ip, port))
        self.emitter.emit(
            ts, "RPC-DRS-PORT-LEARNED", subject,
            {"interface": "epmapper", "drs_server": server_ip,
             "drs_port": port, "source": "ept_map reply tower floor 4",
             "note": f"pin with --rpc-port {port} to watch DRSUAPI on "
                     f"{server_ip} without --dynamic-range"})

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
        if (pending[0] == IF_EPM and pending[1] == EPM_MAP_OPNUM
                and self.config.drs_epm_follow):
            self._epm_follow(ts, subject, assoc, pdu, hdr, body, trailer,
                             server_ip)
        self._tslicensing_outcome(ts, subject, pending, accepted=True)
        self._tsts_outcome(ts, subject, pending, accepted=True)
        if pending[0] == IF_DRSUAPI:
            # Volume of the dump, from the PDU header only - the stub stays
            # sealed and unread.  CO_HEADER_LEN is the fixed 16-byte header
            # plus the 8-byte response prologue.
            assoc.drs_bytes += max(
                0, hdr.get("frag_length", 0) - CO_HEADER_LEN - 8)
            self._drs_outcome(ts, subject, assoc, pending, accepted=True)
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
        pending = assoc.pending_calls.pop(hdr["call_id"], None)
        if pending:
            self._tslicensing_outcome(ts, subject, pending, accepted=False)
            self._tsts_outcome(ts, subject, pending, accepted=False)
            if pending[0] == IF_DRSUAPI:
                self._drs_outcome(ts, subject, assoc, pending, accepted=False)

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
            # Remember who authenticated, so an enrollment request that names
            # somebody else can be told from one that names its own requester.
            user = (msg.get("user") or "").strip()
            if user:
                dom = (msg.get("domain") or "").strip()
                assoc.ntlm_account = f"{dom}\\{user}" if dom else user
            if assoc.spnego_seen:
                self.emitter.emit(ts, "RPC-NTLM-OVER-SPNEGO", subject, dict(
                    base, kerberos_offered=assoc.kerberos_seen))
            if msg.get("anonymous"):
                assoc.anonymous = True
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
                 "cpend", "spend", "httpapi")

    def __init__(self, ts):
        self.offered: set[str] = set()
        self.reported: set[str] = set()
        self.assoc = Association(ts)
        self.cbuf = bytearray()       # client -> server, awaiting a full message
        self.sbuf = bytearray()       # server -> client
        self.cpend = None             # head seen, body still arriving
        self.spend = None
        # Set when a response on this flow carries Server: Microsoft-HTTPAPI.
        # On 5985 http.sys is a given; on a compat port it has to be earned.
        self.httpapi = False


class WinRMEngine:
    def __init__(self, config: Config, emitter: Emitter, rpc: RPCEngine):
        self.config = config
        self.emitter = emitter
        self.rpc = rpc
        self.flows: dict[tuple, WinRMFlow] = {}

    def process(self, ts, flow, client_ip, server_ip, data: bytes,
                from_client: bool, server_port: int):
        if server_port in wsman_tls_ports(self.config):
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
            if HTTPAPI_BANNER in http_header(parsed, "server").lower():
                st.httpapi = True
            return
        path = parsed.get("path", "")

        # Checked BEFORE the wsman-path gate on purpose: http.sys parses
        # Accept-Encoding in the kernel before it routes the request, so the
        # bug is reachable on any path, not just /wsman.
        self._httpsys_accept_encoding(ts, subject, parsed, path,
                                      server_port, st)

        if not is_wsman_path(path):
            return
        if "cleartext" not in st.reported:
            st.reported.add("cleartext")
            self.emitter.emit(ts, "WINRM-CLEARTEXT-HTTP", subject, {
                "path": path, "port": server_port,
                "endpoint": wsman_endpoint(path)})
        endpoint = wsman_endpoint(path)
        if endpoint == "anon-identify" and "anon" not in st.reported:
            st.reported.add("anon")
            self.emitter.emit(ts, "WINRM-ANON-IDENTIFY", subject, {
                "path": path, "port": server_port, "endpoint": endpoint,
                "note": "no credentials required; answers with vendor and "
                        "protocol version"})
        elif endpoint == "wec-subscription" and "wec" not in st.reported:
            st.reported.add("wec")
            self.emitter.emit(ts, "WINRM-WEC-SUBSCRIPTION", subject, {
                "path": path, "port": server_port, "endpoint": endpoint,
                "note": "source-initiated event forwarding channel"})

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

    def _httpsys_accept_encoding(self, ts, subject, parsed, path,
                                 server_port, st):
        """
        CVE-2021-31166 and CVE-2022-21907.

        Both are the same wire shape: an Accept-Encoding coding-list element
        that is empty or whitespace-only, which drives a use-after-free (2021)
        or double free (2022) in http.sys.  Rapid7 reproduced the 2021 crash
        against a WinRM-enabled host on 5985 specifically, which is why this
        belongs here rather than nowhere.

        One finding, both CVEs cited: the wire evidence cannot tell them
        apart, and the 2022 variant additionally needs EnableTrailerSupport on
        the host, which is registry state and not observable from a tap.
        Claiming a specific CVE would be inventing precision we do not have.
        """
        if parsed["kind"] != "request":
            return
        # Which carrier is on this port decides whether the CVEs even apply.
        # On 5985/5986 http.sys is the only thing that answers, so the shape
        # alone is enough.  On a compat port the listener may be IIS, Apache
        # or anything else, so the claim has to be earned by a response that
        # named Microsoft-HTTPAPI.  Responses follow requests, so the first
        # request on a compat flow is not attributable and stays silent -
        # under-claiming, which is the right direction to fail in.
        native = server_port in (WINRM_HTTP_PORT, WINRM_HTTPS_PORT)
        if not native and not st.httpapi:
            return
        value = http_header(parsed, "accept-encoding")
        if not value:
            return
        shape = accept_encoding_shape(value)
        if not shape["empty_elements"]:
            return
        d = dict(shape, path=path, port=server_port,
                 carrier="native WinRM port" if native
                         else "Server: Microsoft-HTTPAPI observed on this flow",
                 cve="CVE-2021-31166 / CVE-2022-21907",
                 note="empty coding-list element; the 2022 variant also "
                      "requires EnableTrailerSupport, which is host state "
                      "and not observable passively")
        unusual = (shape["empty_elements"] > 1
                   or shape["elements"] > HTTPSYS_LONG_LIST
                   or shape["header_bytes"] > HTTPSYS_LONG_HEADER)
        d["confidence"] = "crafted" if unusual else "single-empty-element"
        self.emitter.emit(ts, "WINRM-HTTPSYS-ACCEPT-ENCODING", subject, d,
                          severity="critical" if unusual else "high")

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
        watched = set(self.config.rpc_ports) | wsman_ports(self.config)
        if self.config.drs_epm_follow:
            for learned in self.rpc.learned_drs_ports.values():
                watched |= learned
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

        if server_port in wsman_ports(self.config):
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
                                       server_ip, from_client, over_pipe=True)
                elif item["kind"] == "gss" and self.config.ntlm_from_smb:
                    assoc = self.rpc._assoc(flow, ts)
                    self.rpc._inspect_auth_value(
                        ts, f"{client_ip} -> {server_ip}", assoc,
                        RPC_C_AUTHN_GSS_NEGOTIATE, item["data"], "smb")

    def _drain_dcerpc(self, ts, flow, hs, client_ip, server_ip, from_client, pipe):
        self._drain_frames(ts, flow, hs, hs.buf, client_ip, server_ip,
                           from_client, pipe)

    def _drain_frames(self, ts, flow, hs, buf, client_ip, server_ip,
                      from_client, pipe="", over_pipe=False):
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
                                 from_client, pipe or hs.pipe_name, over_pipe)


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


# libpcap cannot walk an IPv6 extension-header chain: once a Destination
# Options (or Routing, or Fragment) header sits between the fixed header and
# TCP, neither "tcp port N" nor even "ip6 and tcp" matches, because both walk
# to a fixed offset.  Measured, not assumed - see the pcap tier's
# extension-header section.  The only portable filter that still sees those
# frames is a bare "ip6", which means capturing ALL IPv6 and port-filtering in
# userspace.  That costs real CPU on a Pi Zero 2W, so it is opt-in, exactly
# like --dynamic-range.
IPV6_EH_CLAUSE = "ip6"


def wsman_cleartext_ports(config: Config) -> set:
    """Ports where WS-Man is readable: 5985 always, 80 when compat is on."""
    ports = {WINRM_HTTP_PORT}
    if config.wsman_compat:
        ports.add(WSMAN_COMPAT_HTTP_PORT)
    return ports


def wsman_tls_ports(config: Config) -> set:
    """Ports where WS-Man is TLS-wrapped: observed at flow level, never dissected."""
    ports = {WINRM_HTTPS_PORT}
    if config.wsman_compat:
        ports.add(WSMAN_COMPAT_HTTPS_PORT)
    return ports


def wsman_ports(config: Config) -> set:
    return wsman_cleartext_ports(config) | wsman_tls_ports(config)


def bpf_filter(config: Config) -> str:
    ports = sorted(set(config.rpc_ports) | wsman_ports(config))
    clause = " or ".join(f"tcp port {p}" for p in ports)
    if config.dynamic_range:
        clause += " or (tcp and portrange 49152-65535)"
    if config.ipv6_eh:
        clause += f" or {IPV6_EH_CLAUSE}"
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
        tslicensing_spray_threshold=args.tslicensing_spray_threshold,
        dedup_seconds=args.dedup_seconds,
        min_severity=args.min_severity,
        local_nets=_parse_nets(args.local_net),
        dc_hosts=_parse_hosts(args.dc),
        ca_hosts=_parse_hosts(args.ca_host),
        drs_replicators=_parse_hosts(args.drs_replicator),
        drs_epm_follow=not args.no_drs_epm_follow,
        allow_clients=set(args.allow_client or []),
        allow_interfaces=set(u.lower() for u in (args.allow_interface or [])),
        rpc_ports=rpc_ports,
        dynamic_range=args.dynamic_range,
        ipv6_eh=args.ipv6_eh,
        wsman_compat=args.wsman_compat,
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
            # plen counts everything after the fixed 40-byte header, which
            # INCLUDES any extension headers.  Subtract them, or the trim
            # over-counts and silently stops trimming link-layer padding.
            ip6 = pkt["IPv6"]
            seg_len = int(ip6.plen)
            ext = len(bytes(ip6.payload)) - len(bytes(tcp))
            if 0 <= ext <= seg_len:
                seg_len -= ext
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
# v9: the DRSUAPI tier adds DCSync from a non-DC and DCShadow (a rogue replication
# source). It is ARMED only when DCs are declared (Config.dc_hosts via `dcs`);
# without them it stays silent rather than guessing which end is a DC.
_DCSYNC_VERDICT_CODES = frozenset({"RPC-DCSYNC-CALL", "RPC-DRS-DCSYNC",
                                   "RPC-DRS-DCSHADOW"})
# v9: LSA secret access (how the DPAPI backup key is really taken) and the MS-RRP
# hive save (secretsdump's registry path; SMB Watch sees the file read-back).
_CREDTHEFT_VERDICT_CODES = frozenset({
    "RPC-BACKUPKEY-ACCESS", "RPC-NETLOGON-PASSWORD-GET",
    "WINRM-BASIC-AUTH", "WINRM-UNENCRYPTED-PAYLOAD",
    "RPC-LSA-SECRET-READ", "RPC-LSA-SECRET-WRITE", "RPC-WINREG-HIVE-SAVE"})
# v9: AD CS escalations readable in an UNSEALED MS-ICPR enrollment request (ESC1 /
# ESC3 / ESC6 / ESC15 (CVE-2024-49019) / ESC17). Sealed (PKT_PRIVACY) requests
# are invisible, so silence there is not evidence of safety.
_ADCS_VERDICT_CODES = frozenset({
    "RPC-CERTENROLL-ESC1-SAN", "RPC-CERTENROLL-ESC3-AGENT",
    "RPC-CERTENROLL-ESC6-SAN-ATTR", "RPC-CERTENROLL-ESC15-APP-POLICY",
    "RPC-CERTENROLL-ESC17-DNS"})


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
    if codes & _ADCS_VERDICT_CODES:
        return "adcs-abuse", ranked
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
    v9 adds DCSync / DCShadow (armed by `dcs`), LSA secret read / write, MS-RRP hive
    save, MS-CSRA CA administration and the AD CS ESC1 / ESC3 / ESC6 / ESC15 / ESC17
    enrollment shapes in unsealed MS-ICPR requests.
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


def _st_co_pdu_be(ptype, body, call_id=1, pfc=0x03):
    """Big-endian common header: drep high nibble 0, frag/auth/call_id in BE.
    parse_co_header / peek_frag_length read those fields per the drep, so this
    exercises the byte-swapping path (CVE-2022-26809 bind_ack underflow)."""
    total = CO_HEADER_LEN + len(body)
    hdr = struct.pack(">BBBB4sHHI", 5, 0, ptype, pfc,
                      b"\x00\x00\x00\x00", total, 0, call_id)
    return hdr + body


def _st_bind_ack_body_be(sec_addr_len=0):
    """bind_ack body in big-endian: max_xmit/max_recv/assoc_group + sec_addr_len."""
    return struct.pack(">HHI", 5840, 5840, 0) + struct.pack(">H", sec_addr_len)


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

    # 22. WinReg relay fallback (CVE-2024-43532): winreg bound over ncacn_ip_tcp
    #     (default port 135, not a named pipe) at RPC_C_AUTHN_LEVEL_CONNECT.
    h = _STHarness(client="10.20.7.1")
    _st_bind(h, IF_WINREG, level=RPC_C_AUTHN_LEVEL_CONNECT)
    check("winreg-relay-fallback",
          "RPC-WINREG-RELAY-FALLBACK" in h.codes, sorted(h.codes))

    # 23. PrintNightmare (CVE-2021-34527): RpcAddPrinterDriver (opnum 9) naming
    #     an off-box UNC driver path.
    h = _STHarness(client="10.20.7.2")
    _st_bind(h, IF_RPRN)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        RPRN_ADD_PRINTER_DRIVER,
        _st_ndr_wstr("\\\\10.99.99.99\\share\\evil.dll")), call_id=3))
    check("printnightmare-driver-add",
          "RPC-PRINTNIGHTMARE-DRIVER-ADD" in h.codes, sorted(h.codes))

    # 24. PetitPotam anonymous coercion (CVE-2022-26925): anonymous bind to the
    #     LSARPC pipe, then a coercion opnum (EfsRpcOpenFileRaw, opnum 0).
    h = _STHarness(client="10.20.7.3")
    _st_bind(h, IF_EFSR_LSA)                      # no auth level -> anonymous
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        0, _st_ndr_wstr("\\\\10.99.99.99\\x\\y.txt")), call_id=3))
    check("lsa-anonymous-coercion",
          "RPC-LSA-ANONYMOUS-COERCION" in h.codes, sorted(h.codes))

    # 25. RPC runtime bind_ack underflow (CVE-2022-26809): big-endian bind_ack
    #     with a zero secondary-address length, server -> client.
    h = _STHarness(client="10.20.7.4")
    h.s2c(_st_co_pdu_be(PTYPE_BIND_ACK, _st_bind_ack_body_be(0)))
    check("runtime-bindack-underflow",
          "RPC-RUNTIME-BINDACK-UNDERFLOW" in h.codes, sorted(h.codes))

    # 26. http.sys Accept-Encoding (CVE-2021-31166 / CVE-2022-21907): an empty
    #     coding-list element on tcp/5985.
    h = _STHarness(client="10.20.7.5")
    h.c2s(_st_http_request("POST", "/wsman", {
        "Host": "dc01:5985", "Accept-Encoding": "gzip,,deflate"},
        b""), dport=WINRM_HTTP_PORT)
    check("winrm-httpsys-accept-encoding",
          "WINRM-HTTPSYS-ACCEPT-ENCODING" in h.codes, sorted(h.codes))

    # 28-33. IRemoteWinSpool relay level (CVE-2021-1678), ported from the
    #        upstream v3 suite. Bind below PKT_PRIVACY is high posture; the
    #        opnum-62 driver install on such an association is critical.
    def _ws(h):
        return [f for f in h.watch.emitter.emitted
                if f.code == "RPC-WINSPOOL-RELAY-LEVEL"]

    h = _STHarness(client="10.20.8.1")
    _st_bind(h, IF_PAR, level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
    ws = _ws(h)
    check("winspool-bind-below-privacy-high",
          len(ws) == 1 and ws[0].severity == "high"
          and ws[0].details.get("cve") == "CVE-2021-1678"
          and ws[0].details.get("stage") == "bind"
          and ws[0].details.get("required_level") == "pkt-privacy",
          [(f.severity, f.details.get("stage")) for f in ws])

    h = _STHarness(client="10.20.8.2")
    _st_bind(h, IF_PAR, level=RPC_C_AUTHN_LEVEL_CONNECT)
    check("winspool-connect-level-fires", bool(_ws(h)), sorted(h.codes))

    h = _STHarness(client="10.20.8.3")
    _st_bind(h, IF_PAR, level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    check("winspool-privacy-quiet", not _ws(h), sorted(h.codes))

    h = _STHarness(client="10.20.8.4")
    _st_bind(h, IF_PAR, level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        PAR_ASYNC_INSTALL_PRINTER_DRIVER_FROM_PACKAGE, b"\x00" * 32),
        auth=_st_sec_trailer(RPC_C_AUTHN_GSS_NEGOTIATE,
                             RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, _AUTH_TOKEN),
        call_id=2))
    call = [f for f in _ws(h) if f.details.get("stage") == "call"]
    check("winspool-driver-install-critical",
          call and call[0].severity == "critical"
          and call[0].details.get("call") == "RpcAsyncInstallPrinterDriverFromPackage",
          [(f.severity, f.details.get("stage")) for f in _ws(h)])

    h = _STHarness(client="10.20.8.5")
    _st_bind(h, IF_PAR, level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        PAR_ASYNC_INSTALL_PRINTER_DRIVER_FROM_PACKAGE, b"\x00" * 32),
        auth=_st_sec_trailer(RPC_C_AUTHN_GSS_NEGOTIATE,
                             RPC_C_AUTHN_LEVEL_PKT_PRIVACY, _AUTH_TOKEN),
        call_id=3))
    check("winspool-sealed-driver-install-quiet", not _ws(h), sorted(h.codes))

    h = _STHarness(client="10.20.8.6")
    _st_bind(h, IF_RPRN, level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
    check("winspool-scoped-to-par-not-rprn", not _ws(h), sorted(h.codes))

    # 34-35. PetitPotam attribution (CVE-2021-36942): EfsRpcOpenFileRaw is opnum 0,
    #        the only method the August 2021 patch fixed. The engine attributes it;
    #        the in-app verdict still defers coercion to Relay/Coercion Watch.
    def _coercion_cves(h):
        return [f.details.get("cve") for f in h.watch.emitter.emitted
                if f.code == "RPC-COERCION-CALL"]

    h = _STHarness(client="10.20.8.7")
    _st_bind(h, IF_EFSR_LSA, level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        0, _st_ndr_wstr("\\\\10.99.99.99\\x\\y.txt")), call_id=3))
    check("petitpotam-opnum0-attributed-36942",
          "CVE-2021-36942" in _coercion_cves(h), _coercion_cves(h))

    h = _STHarness(client="10.20.8.8")
    _st_bind(h, IF_EFSR_LSA, level=RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        4, _st_ndr_wstr("\\\\10.99.99.99\\x\\y.txt")), call_id=3))
    cves = _coercion_cves(h)
    check("petitpotam-other-opnum-not-36942",
          cves and "CVE-2021-36942" not in cves, cves)

    # ----- v7 detectors (ported from the v7 drop; one positive per new code,
    #       plus the false-positive guards that keep each honest) -------------

    # 36-37. MadLicense / RD Licensing (CVE-2024-38077 + the July-2024 cluster):
    #        the TLSRpcTelephoneRegisterLKP call below packet privacy is the
    #        overflow step; the same call sealed is what a patched host accepts.
    h = _STHarness(client="10.20.10.1")
    _st_bind(h, IF_TSLICENSING, level=RPC_C_AUTHN_LEVEL_CONNECT)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        TSL_RPC_TELEPHONE_REGISTER_LKP, b"\x00" * 64), call_id=4))
    check("tslicensing-preauth-call-38077",
          "RPC-TSLICENSING-PREAUTH" in h.codes, sorted(h.codes))

    h = _STHarness(client="10.20.10.2")
    _st_bind(h, IF_TSLICENSING, level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        TSL_RPC_TELEPHONE_REGISTER_LKP, b"\x00" * 64),
        auth=_st_sec_trailer(RPC_C_AUTHN_GSS_NEGOTIATE,
                             RPC_C_AUTHN_LEVEL_PKT_PRIVACY, _AUTH_TOKEN),
        call_id=4))
    check("tslicensing-sealed-quiet",
          "RPC-TSLICENSING-PREAUTH" not in h.codes, sorted(h.codes))

    # 38. LSM container interface over the network (CVE-2022-37973 / -37998):
    #     any bind reaching the tap is illegitimate — no remote caller exists.
    h = _STHarness(client="10.20.10.3")
    _st_bind(h, IF_LSM_CONTAINER)
    check("lsm-container-bind-remote",
          "RPC-LSM-CONTAINER-REMOTE" in h.codes, sorted(h.codes))

    # 39. RpcGetSessionIds LSM crash (CVE-2025-26651): opnum 8 is in the
    #     cleartext header, so the request fires even sealed.
    h = _STHarness(client="10.20.10.4")
    _st_bind(h, IF_TSTS_ENUM)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        TSTS_GET_SESSION_IDS, b""), call_id=4))
    check("lsm-getsessionids-crash-26651",
          "RPC-LSM-GETSESSIONIDS-CRASH" in h.codes, sorted(h.codes))

    # 40-41. ESC11 — relay to the AD CS enrollment interface (no CVE): a bind
    #        below packet privacy is posture; the same bind sealed is quiet.
    h = _STHarness(client="10.20.10.5")
    _st_bind(h, IF_ICPR, level=RPC_C_AUTHN_LEVEL_CONNECT)
    check("certenroll-relay-level-bind",
          "RPC-CERTENROLL-RELAY-LEVEL" in h.codes, sorted(h.codes))

    h = _STHarness(client="10.20.10.6")
    _st_bind(h, IF_ICPR, level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    check("certenroll-sealed-quiet",
          "RPC-CERTENROLL-RELAY-LEVEL" not in h.codes, sorted(h.codes))

    # 42-43. Certighost chase (CVE-2026-54121): a declared CA opening an
    #        outbound LSARPC bind to a non-DC fires; with no --ca/--dc set the
    #        rule is undecidable and stays silent.
    h = _STHarness(client="10.20.10.7", server="10.20.10.8",
                   ca_hosts=_parse_hosts(["10.20.10.7"]),
                   dc_hosts=_parse_hosts(["10.20.10.9"]))
    _st_bind(h, IF_LSARPC)
    check("adcs-chase-54121",
          "RPC-ADCS-CHASE" in h.codes, sorted(h.codes))

    h = _STHarness(client="10.20.10.10", server="10.20.10.11")
    _st_bind(h, IF_LSARPC)
    check("adcs-chase-undeclared-silent",
          "RPC-ADCS-CHASE" not in h.codes, sorted(h.codes))

    # 44-45. MS-DNSP ServerLevelPluginDll — DnsAdmin to SYSTEM (no CVE): the
    #        operation name plus an off-box DLL path is critical; a sealed call
    #        is deliberately not reported (DNS management workhorse).
    h = _STHarness(client="10.20.10.12")
    _st_bind(h, IF_DNSSERVER)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        0, DNSP_PLUGIN_OPERATION + b"\x00\x00"
        + _st_ndr_wstr("\\\\10.88.88.88\\s\\evil.dll")), call_id=4))
    check("dnsp-serverlevelplugindll-path",
          "RPC-DNS-SERVERLEVELPLUGINDLL" in h.codes, sorted(h.codes))

    h = _STHarness(client="10.20.10.13")
    _st_bind(h, IF_DNSSERVER)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        0, DNSP_PLUGIN_OPERATION),
        auth=_st_sec_trailer(RPC_C_AUTHN_GSS_NEGOTIATE,
                             RPC_C_AUTHN_LEVEL_PKT_PRIVACY, _AUTH_TOKEN),
        call_id=4))
    check("dnsp-sealed-quiet",
          "RPC-DNS-SERVERLEVELPLUGINDLL" not in h.codes, sorted(h.codes))

    # 46. MS-EVEN backup-write (CVE-2025-29969 / CVE-2026-50502): ElfrOpenBELW
    #     against an off-box file opens the write chain.
    h = _STHarness(client="10.20.10.14")
    _st_bind(h, IF_EVEN)
    h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
        ELFR_OPEN_BELW, _st_ndr_wstr("\\\\10.77.77.77\\x\\evil.evtx")),
        call_id=4))
    check("eventlog-backup-write-openbelw",
          "RPC-EVENTLOG-BACKUP-WRITE" in h.codes, sorted(h.codes))

    # 47. MS-EVEN path-existence oracle (no CVE): a burst of ElfrOpenBELW opens
    #     against distinct local paths is enumeration, latched once.
    h = _STHarness(client="10.20.10.15")
    _st_bind(h, IF_EVEN)
    for i in range(EVENTLOG_PROBE_THRESHOLD + 1):
        h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(
            ELFR_OPEN_BELW, _st_ndr_wstr("C:\\logs\\probe%d.evtx" % i)),
            call_id=20 + i))
    check("eventlog-path-probe",
          "RPC-EVENTLOG-PATH-PROBE" in h.codes, sorted(h.codes))

    # 48. Interface inventory (no CVE): a bind to a UUID with no rule behind it
    #     is described, graded unknown vs documented.
    h = _STHarness(client="10.20.10.16")
    _st_bind(h, "deadbeef-0000-0000-0000-00000000cafe")
    check("interface-uncatalogued-unknown",
          "RPC-INTERFACE-UNCATALOGUED" in h.codes, sorted(h.codes))

    # 49-50. WS-Man endpoints (no CVE): the anonymous Identify endpoint and the
    #        Event Collector subscription endpoint, read from the request line.
    h = _STHarness(client="10.20.10.17")
    h.c2s(_st_http_request("POST", "/wsman-anon/identify",
          {"Host": "dc01:5985", "Content-Length": "0"}), dport=5985)
    check("winrm-anon-identify",
          "WINRM-ANON-IDENTIFY" in h.codes, sorted(h.codes))

    h = _STHarness(client="10.20.10.18")
    h.c2s(_st_http_request("POST", "/wsman/SubscriptionManager/WEC",
          {"Host": "collector:5985", "Content-Length": "0"}), dport=5985)
    check("winrm-wec-subscription",
          "WINRM-WEC-SUBSCRIPTION" in h.codes, sorted(h.codes))

    # 51-58. v9 tiers, built from the module author's own wire shapes.
    def _st_ack(sec_addr):
        sa = (sec_addr + "\x00").encode("ascii")
        out = struct.pack("<HHI", 5840, 5840, 1) + struct.pack("<H", len(sa)) + sa
        out += b"\x00" * ((4 - (len(out) % 4)) % 4)
        out += struct.pack("<BBH", 1, 0, 0) + struct.pack("<HH", 0, 0)
        return out + _st_uuid_wire(_NDR32) + struct.pack("<I", 2)

    def _st_uni(value, handle=b"\x22" * 20):
        body = (value + "\x00").encode("utf-16-le")
        return (handle + struct.pack("<HHI", len(value.encode("utf-16-le")), len(body),
                                     0x20000)
                + struct.pack("<III", len(value) + 1, 0, len(value) + 1) + body)

    def _st_assoc(h, iface, pipe, ops, ver=1, auth_type=None):
        tr = _st_sec_trailer(auth_type or RPC_C_AUTHN_GSS_NEGOTIATE,
                             RPC_C_AUTHN_LEVEL_CONNECT, _AUTH_TOKEN)
        h.c2s(_st_co_pdu(PTYPE_BIND, _st_bind_body([(iface, ver)]), auth=tr))
        h.s2c(_st_co_pdu(PTYPE_BIND_ACK, _st_ack(pipe)))
        for i, (op, stub) in enumerate(ops):
            h.c2s(_st_co_pdu(PTYPE_REQUEST, _st_request_body(op, stub),
                             call_id=500 + i, auth=tr))

    # MS-RRP hive save: secretsdump opens SAM then BaseRegSaveKey to a temp file.
    h = _STHarness(client="10.0.0.9", server="10.0.0.1",
                   local_nets=_parse_nets(["10.0.0.0/8"]))
    _st_assoc(h, IF_WINREG, "\\PIPE\\winreg",
              [(WINREG_CREATE_KEY, _st_uni("SAM")),
               (WINREG_SAVE_KEY, _st_uni("..\\Temp\\AbCdEfGh.tmp"))])
    hs = [f for f in h.watch.emitter.emitted if f.code == "RPC-WINREG-HIVE-SAVE"]
    check("v9-winreg-hive-save", bool(hs) and hs[0].severity == "critical",
          [(f.code, f.severity) for f in hs])
    check("v9-hive-save-verdict-credential-exposure",
          _rpc_verdict(h.watch.emitter.emitted)[0] == "credential-exposure",
          _rpc_verdict(h.watch.emitter.emitted)[0])

    # MS-LSAD secret read of the DPAPI domain backup key (G$BCKUPKEY_*).
    h = _STHarness(client="10.0.0.9", server="10.0.0.1")
    _st_assoc(h, IF_LSARPC, "\\PIPE\\lsarpc",
              [(LSA_RETRIEVE_PRIVATE_DATA, _st_uni("G$BCKUPKEY_PREFERRED",
                                                   handle=b"\x11" * 20))], ver=0)
    rd = [f for f in h.watch.emitter.emitted if f.code == "RPC-LSA-SECRET-READ"]
    check("v9-lsa-secret-read-backupkey", bool(rd) and rd[0].severity == "critical",
          [(f.code, f.severity) for f in rd])

    # DRSUAPI: DCSync (a non-DC pulling from a DC) and DCShadow (a non-DC acting as a
    # replication source) - armed only when DCs are declared.
    def _st_drs(opnum, client, server, dcs=("10.30.0.1", "10.30.0.2")):
        cfg = {"rpc_ports": [135, 49200]}
        if dcs:
            cfg["dc_hosts"] = _parse_hosts(list(dcs))
        w = RPCWatch(Config(**cfg))
        w.feed(1.0, client, 40000, server, 49200,
               _st_co_pdu(PTYPE_BIND, _st_bind_body([(IF_DRSUAPI, 1)])))
        w.feed(1.1, server, 49200, client, 40000,
               _st_co_pdu(PTYPE_BIND_ACK, _st_ack("\\PIPE\\drs")))
        w.feed(2.0, client, 40000, server, 49200,
               _st_co_pdu(PTYPE_REQUEST, _st_request_body(opnum, b"\x00" * 16),
                          call_id=700))
        return [f for f in w.emitter.emitted if f.code.startswith("RPC-DRS-DC")]
    got = _st_drs(3, "10.30.0.66", "10.30.0.1")
    check("v9-drs-dcsync-from-non-dc",
          bool(got) and got[0].code == "RPC-DRS-DCSYNC" and got[0].severity == "critical",
          [(f.code, f.severity) for f in got])
    got = _st_drs(3, "10.30.0.1", "10.30.0.66")
    check("v9-drs-dcshadow-rogue-source",
          bool(got) and got[0].code == "RPC-DRS-DCSHADOW",
          [(f.code, f.severity) for f in got])
    check("v9-drs-dc-to-dc-silent", not _st_drs(3, "10.30.0.2", "10.30.0.1"))
    check("v9-drs-disarmed-without-dcs", not _st_drs(3, "10.30.0.66", "10.30.0.1",
                                                     dcs=()))

    # MS-ICPR ESC6: a SAN supplied in the request ATTRIBUTES string.
    h = _STHarness(client="10.0.0.9", server="10.0.0.1")
    _st_assoc(h, IF_ICPR, "\\PIPE\\cert",
              [(0, "CertificateTemplate:User\nsan:upn=Administrator@corp.local"
                .encode("utf-16-le"))], auth_type=RPC_C_AUTHN_WINNT)
    e6 = [f for f in h.watch.emitter.emitted if f.code == "RPC-CERTENROLL-ESC6-SAN-ATTR"]
    check("v9-esc6-san-attr", bool(e6), sorted(h.codes))
    check("v9-esc6-verdict-adcs-abuse",
          _rpc_verdict(h.watch.emitter.emitted)[0] == "adcs-abuse",
          _rpc_verdict(h.watch.emitter.emitted)[0])
    h = _STHarness(client="10.0.0.9", server="10.0.0.1")
    _st_assoc(h, IF_ICPR, "\\PIPE\\cert",
              [(0, "CertificateTemplate:User".encode("utf-16-le"))],
              auth_type=RPC_C_AUTHN_WINNT)
    check("v9-plain-enrollment-silent",
          not any(c.startswith("RPC-CERTENROLL-ESC") for c in h.codes), sorted(h.codes))

    # 27. Catalogue integrity: every declared code has a known severity.
    bad = [c for c, spec in FINDINGS.items() if spec[0] not in SEVERITY_RANK]
    check("catalogue-severity-integrity", not bad, bad)

    return {"success": all(s["pass"] for s in scen), "scenarios": scen}


if __name__ == "__main__":       # pragma: no cover - manual smoke test
    import pprint
    r = selftest()
    pprint.pprint([s for s in r["scenarios"] if not s["pass"]] or "ALL PASS")
    print("success:", r["success"])
