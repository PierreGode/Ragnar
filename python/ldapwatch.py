#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ldapwatch — passive LDAP / CLDAP security posture monitor  (Ragnar suite)

PASSIVE ONLY. This module never transmits. It sniffs LDAP (TCP/389, GC/3268,
LDAPS/636, GC-S/3269) and connectionless LDAP (UDP/389) off the wire, reassembles
TCP byte streams per flow, decodes the BER/ASN.1 LDAPMessage envelope with a
hand-rolled definite-length decoder, and raises findings for insecure transport,
weak/absent authentication, STARTTLS stripping, directory enumeration, filter
injection, brute force, and CLDAP reflection/amplification.

Design conventions (shared across the Ragnar suite):
  * Passive-only Scapy capture. No sockets are opened for transmit; no packet is
    ever built or sent. The self-test greps this source for transmit primitives.
  * Custom raw-byte parser. No library dissectors — BER is decoded here directly.
  * systemd least-privilege unit: CAP_NET_RAW only, drops all other capabilities.
  * Self-test harness (test_ldapwatch.py) fabricates BER LDAP messages and runs
    them through THIS module's production parse+detect path.
  * JSON-lines output (one finding object per line) for the web UI + Pushover.
  * Hardware floor: Raspberry Pi Zero 2 W. Scapy import is lazy so --selftest and
    offline parsing work with zero third-party deps.

RFCs: 4511 (LDAPv3 protocol), 4513 (authentication methods & security),
2830/4513 (StartTLS), 4532 (Who Am I), 3062 (Password Modify), 4514 (DN string).
"""

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import sys
import time
from collections import deque, defaultdict
from datetime import datetime, timezone

__version__ = "1.0.0"
MODULE = "ldapwatch"

log = logging.getLogger(MODULE)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Ports where LDAP is carried in cleartext (dissectable) vs. wrapped in TLS.
JNDI_ALT_PORT = 1389                        # marshalsec/JNDIExploit default listener
CLEARTEXT_LDAP_PORTS = {389, 3268, JNDI_ALT_PORT}   # ldap, global-catalog, rogue-JNDI default
TLS_LDAP_PORTS = {636, 3269}                # ldaps, global-catalog over TLS
CLDAP_PORT = 389                            # connectionless LDAP (UDP)
ALL_TCP_PORTS = CLEARTEXT_LDAP_PORTS | TLS_LDAP_PORTS

# LDAP protocolOp application tag numbers (ASN.1 [APPLICATION n]).
OP_BIND_REQUEST = 0
OP_BIND_RESPONSE = 1
OP_UNBIND_REQUEST = 2
OP_SEARCH_REQUEST = 3
OP_SEARCH_RESULT_ENTRY = 4
OP_SEARCH_RESULT_DONE = 5
OP_MODIFY_REQUEST = 6
OP_MODIFY_RESPONSE = 7
OP_ADD_REQUEST = 8
OP_ADD_RESPONSE = 9
OP_DEL_REQUEST = 10
OP_DEL_RESPONSE = 11
OP_MODDN_REQUEST = 12
OP_MODDN_RESPONSE = 13
OP_COMPARE_REQUEST = 14
OP_COMPARE_RESPONSE = 15
OP_ABANDON_REQUEST = 16
OP_SEARCH_RESULT_REF = 19
OP_EXTENDED_REQUEST = 23
OP_EXTENDED_RESPONSE = 24
OP_INTERMEDIATE_RESPONSE = 25

OP_NAMES = {
    OP_BIND_REQUEST: "bindRequest",
    OP_BIND_RESPONSE: "bindResponse",
    OP_UNBIND_REQUEST: "unbindRequest",
    OP_SEARCH_REQUEST: "searchRequest",
    OP_SEARCH_RESULT_ENTRY: "searchResEntry",
    OP_SEARCH_RESULT_DONE: "searchResDone",
    OP_MODIFY_REQUEST: "modifyRequest",
    OP_MODIFY_RESPONSE: "modifyResponse",
    OP_ADD_REQUEST: "addRequest",
    OP_ADD_RESPONSE: "addResponse",
    OP_DEL_REQUEST: "delRequest",
    OP_DEL_RESPONSE: "delResponse",
    OP_MODDN_REQUEST: "modDNRequest",
    OP_MODDN_RESPONSE: "modDNResponse",
    OP_COMPARE_REQUEST: "compareRequest",
    OP_COMPARE_RESPONSE: "compareResponse",
    OP_ABANDON_REQUEST: "abandonRequest",
    OP_SEARCH_RESULT_REF: "searchResRef",
    OP_EXTENDED_REQUEST: "extendedReq",
    OP_EXTENDED_RESPONSE: "extendedResp",
    OP_INTERMEDIATE_RESPONSE: "intermediateResponse",
}

# Search scope enumerated values.
SCOPE_BASE = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE = 2

# Authentication choice context tags inside BindRequest.
AUTH_SIMPLE = 0     # [0] OCTET STRING (the password, in the clear)
AUTH_SASL = 3       # [3] SaslCredentials SEQUENCE { mechanism, credentials }

# LDAPResult codes we care about.
RESULT_SUCCESS = 0
RESULT_PROTOCOL_ERROR = 2
RESULT_STRONGER_AUTH_REQUIRED = 8
RESULT_SASL_BIND_IN_PROGRESS = 14
RESULT_UNWILLING_TO_PERFORM = 53
RESULT_INVALID_CREDENTIALS = 49
RESULT_CONFIDENTIALITY_REQUIRED = 13
RESULT_REFERRAL = 10

# Well-known extended-operation OIDs (LDAPOID is dotted-decimal ASCII, not BER OID).
OID_STARTTLS = "1.3.6.1.4.1.1466.20037"
OID_PASSWORD_MODIFY = "1.3.6.1.4.1.4203.1.11.1"
OID_WHOAMI = "1.3.6.1.4.1.4203.1.11.3"

# SASL mechanisms that leak credentials in the clear or are cryptographically obsolete.
SASL_CLEARTEXT = {"PLAIN", "LOGIN", "ANONYMOUS", "EXTERNAL"}
SASL_WEAK = {"CRAM-MD5", "DIGEST-MD5"}
SASL_STRONG = {"GSSAPI", "GSS-SPNEGO", "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512"}

# Finding catalogue: code -> (severity, category, title).
FINDINGS = {
    "LDAP-CLEARTEXT-SIMPLE-BIND":  ("critical", "auth",      "Simple bind password transmitted in cleartext"),
    "LDAP-UNAUTH-BIND":            ("high",     "auth",      "Unauthenticated simple bind (DN with empty password)"),
    "LDAP-ANONYMOUS-BIND":         ("low",      "auth",      "Anonymous bind observed"),
    "LDAP-DEPRECATED-VERSION":     ("medium",   "protocol",  "Deprecated LDAPv2 bind"),
    "LDAP-SASL-PLAIN-NO-TLS":      ("high",     "auth",      "SASL cleartext mechanism without TLS"),
    "LDAP-WEAK-SASL-MECH":         ("medium",   "auth",      "Weak/obsolete SASL mechanism negotiated"),
    "LDAP-NO-STARTTLS-BIND":       ("high",     "transport", "Bind on cleartext port with no prior STARTTLS"),
    "LDAP-STARTTLS-DOWNGRADE":     ("high",     "transport", "STARTTLS refused or stripped; session stayed cleartext"),
    "LDAP-STARTTLS-OK":            ("info",     "transport", "STARTTLS negotiated successfully"),
    "LDAP-ROOTDSE-PROBE":          ("low",      "recon",     "RootDSE / naming-context probe"),
    "LDAP-WHOLE-SUBTREE-ENUM":     ("medium",   "recon",     "Whole-subtree enumeration search"),
    "LDAP-INJECTION-FILTER":       ("medium",   "abuse",     "Search filter carries unescaped injection metacharacters"),
    "LDAP-PASSWORD-MODIFY-NO-TLS": ("critical", "auth",      "Password Modify extended op without TLS"),
    "LDAP-WHOAMI-NO-TLS":          ("low",      "recon",     "Who Am I extended op without TLS"),
    "LDAP-MODIFY-NO-TLS":          ("medium",   "integrity", "Directory write (modify/add/del/moddn) without TLS"),
    "LDAP-ADCS-ESC4-TEMPLATE-WRITE": ("critical", "abuse",    "AD CS ESC4: write to a certificate template's enrollment or security attributes"),
    "LDAP-ADCS-ESC5-PKI-OBJECT-WRITE": ("critical", "abuse",  "AD CS ESC5: write to a PKI trust object (NTAuth/AIA/CDP/CA/Public Key Services)"),
    "LDAP-ADCS-ESC13-OID-GROUP-LINK": ("critical", "abuse",   "AD CS ESC13: msDS-OIDToGroupLink written, binding a cert policy to a group"),
    "LDAP-ADCS-ESC14-WEAK-ALT-SEC-ID": ("critical", "abuse",  "AD CS ESC14: altSecurityIdentities written (certificate-to-account mapping)"),
    "LDAP-ADCS-ESC10-UPN-SWAP":    ("critical", "abuse",     "AD CS ESC10: userPrincipalName swap-and-revert or collision with another principal"),
    "LDAP-BIND-BRUTE-FORCE":       ("high",     "abuse",     "Repeated invalid-credential bind failures"),
    "LDAP-EXTERNAL-REFERRAL":      ("medium",   "abuse",     "Referral/continuation to an external LDAP host"),
    "LDAP-LARGE-SEARCH-RESULT":    ("low",      "exfil",     "Unusually large search result set"),
    "LDAP-CLDAP-QUERY":            ("info",     "recon",     "Connectionless LDAP (CLDAP) query observed"),
    "LDAP-CLDAP-AMPLIFICATION":    ("high",     "abuse",     "CLDAP response amplification (reflection DDoS vector)"),
    "LDAP-SASL-NO-SIGNING":        ("medium",   "transport", "SASL bind negotiated no integrity layer (LDAP signing not in effect)"),
    "LDAP-STRONGER-AUTH-REQUIRED": ("info",     "transport", "Server demanded stronger auth/confidentiality (signing/TLS enforced)"),
    "LDAP-BIND-BEFORE-STARTTLS":   ("medium",   "transport", "Credentialed bind sent before STARTTLS (auth outside the TLS channel)"),
    "LDAP-REFERRAL-MSGID-OVERFLOW": ("critical", "abuse",    "Referral response with over-wide messageID (LDAPNightmare CVE-2024-49112/49113)"),
    "LDAP-FILTER-NEST-DOS":        ("high",     "abuse",     "Excessively nested search filter (OpenLDAP CVE-2020-12243 slapd crash)"),
    "LDAP-NETLOGON-NTVER-ANOMALY": ("high",     "abuse",     "CLDAP netlogon ping routed to the legacy builder (CVE-2026-41089 LongLogon)"),
    "LDAP-NETLOGON-OVERFLOW-PRECOND": ("high",  "abuse",     "DC advertises DNS names long enough to overflow the legacy netlogon buffer"),
    "LDAP-JNDI-CODEBASE-DELIVERED": ("critical", "abuse",     "JNDI remote codebase returned to a client (Log4Shell-class delivery)"),
    "LDAP-JNDI-SERIALIZED-OBJECT": ("high",    "abuse",     "Serialized Java object returned to a client (JNDI gadget delivery)"),
    "LDAP-KRB-ROAST-HONEYTOKEN":   ("critical", "abuse",     "TGS-REQ for a decoy SPN (Kerberoasting, T1558.003)"),
    "LDAP-KRB-SPN-ENUM-THEN-ROAST": ("critical", "abuse",    "LDAP servicePrincipalName enumeration followed by TGS-REQs from the same client"),
    "LDAP-KRB-ROAST-OPTIONS":      ("high",     "abuse",     "TGS-REQ for a user-account SPN with canonicalize clear (non-Windows roasting tool)"),
    "LDAP-KRB-ASREP-ROASTABLE":    ("high",     "abuse",     "AS-REQ without pre-authentication (AS-REP roasting, T1558.004)"),
    "LDAP-KRB-RC4-REQUESTED":      ("medium",   "transport", "TGS-REQ offering RC4/DES for a user-account SPN (etype posture)"),
    "LDAP-KRB-S4U-X509-UNKEYED-CKSUM": ("critical", "abuse",  "S4U TGS-REQ asserting identity under an unkeyed checksum (CVE-2025-60704)"),
    "LDAP-KRB-S4U-RC4-DOWNGRADE":  ("high",     "transport", "RC4 negotiated on an S4U/AS flow for a principal previously seen on AES"),
    "LDAP-KRB-S4U2SELF-IMPERSONATION": ("medium", "abuse",   "S4U2Self: a service requested a ticket as another user (protocol transition)"),
    "LDAP-KRB-S4U2PROXY-DELEGATION": ("medium", "abuse",     "S4U2Proxy: constrained delegation with cname-in-addl-tkt and an evidence ticket"),
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------- #
# BER / ASN.1 decoder  (definite-length only, as required by LDAP)
# --------------------------------------------------------------------------- #

class BERError(ValueError):
    """Raised on any malformed or truncated BER encountered while decoding."""


class BERElement:
    """One decoded TLV. `value` is the raw content (bytes); `total` is header+content."""
    __slots__ = ("cls", "constructed", "tag", "length", "value", "header_len", "total")

    def __init__(self, cls, constructed, tag, length, value, header_len):
        self.cls = cls                    # 0=universal 1=application 2=context 3=private
        self.constructed = constructed    # bool
        self.tag = tag                    # tag number (int)
        self.length = length              # content length
        self.value = value                # content bytes
        self.header_len = header_len      # bytes consumed by tag+length
        self.total = header_len + length  # full element size

    def __repr__(self):
        cn = {0: "univ", 1: "app", 2: "ctx", 3: "priv"}[self.cls]
        pc = "cons" if self.constructed else "prim"
        return f"<BER {cn} {pc} tag={self.tag} len={self.length}>"


# Guard rails so a hostile packet cannot exhaust memory/stack on a Pi Zero.
_MAX_DEPTH = 40

# Bounds on a dissected modify/add. A write is attacker-controlled in both
# count and size, so the dissection is capped the same way the filter parser is.
_MAX_ATTR_VALUE  = 1024    # bytes retained per value (a UPN or X509 mapping fits)
_MAX_ATTR_VALUES = 32      # values retained per attribute
_MAX_MOD_CHANGES = 64      # changes dissected per modify/add

# ModifyRequest change operation (RFC 4511 s4.6).
MOD_OPS = {0: "add", 1: "delete", 2: "replace"}
_MAX_LEN_BYTES = 4


def ber_peek(buf, off):
    """Return (header_len, content_len) for the element at `off`, or None if the
    header is not yet fully present in `buf`. Never reads past the header."""
    n = len(buf)
    if off >= n:
        return None
    p = off
    tagb = buf[p]
    p += 1
    if (tagb & 0x1F) == 0x1F:                       # high-tag-number form
        while True:
            if p >= n:
                return None
            b = buf[p]
            p += 1
            if not (b & 0x80):
                break
            if p - off > 6:
                raise BERError("high-tag-number field too long")
    if p >= n:
        return None
    lb = buf[p]
    p += 1
    if lb & 0x80:
        nlen = lb & 0x7F
        if nlen == 0:
            raise BERError("indefinite length forbidden in LDAP")
        if nlen > _MAX_LEN_BYTES:
            raise BERError("length field too long")
        if p + nlen > n:
            return None
        clen = 0
        for _ in range(nlen):
            clen = (clen << 8) | buf[p]
            p += 1
    else:
        clen = lb & 0x7F
    return (p - off, clen)


def ber_read(buf, off=0, depth=0):
    """Decode one definite-length TLV starting at `off`. Returns (BERElement, next_off)."""
    if depth > _MAX_DEPTH:
        raise BERError("maximum BER nesting depth exceeded")
    peek = ber_peek(buf, off)
    if peek is None:
        raise BERError("truncated element header")
    header_len, content_len = peek
    tagb = buf[off]
    cls = (tagb >> 6) & 0x03
    constructed = bool(tagb & 0x20)
    tag = tagb & 0x1F
    p = off + 1
    if tag == 0x1F:
        tag = 0
        while True:
            b = buf[p]
            p += 1
            tag = (tag << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    start_content = off + header_len
    end = start_content + content_len
    if end > len(buf):
        raise BERError("declared length exceeds buffer")
    value = buf[start_content:end]
    return BERElement(cls, constructed, tag, content_len, value, header_len), end


def ber_children(value, depth=0):
    """Decode every TLV contained in `value` sequentially."""
    out = []
    off = 0
    n = len(value)
    while off < n:
        el, off = ber_read(value, off, depth + 1)
        out.append(el)
    return out


def ber_int(value):
    """Decode a (two's-complement, big-endian) INTEGER/ENUMERATED content."""
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=True)


def as_text(b):
    """Best-effort decode of an LDAPString / DN / OID for display and comparison."""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1", "replace")


# --------------------------------------------------------------------------- #
# LDAP message model + dissector
# --------------------------------------------------------------------------- #

class LDAPMessage:
    """A dissected LDAPMessage: message_id, protocolOp name, and an op-specific dict."""

    def __init__(self, message_id, op_tag, op_name, message_id_len=1):
        self.message_id = message_id
        # Encoded width of the messageID INTEGER. RFC 4511 allows any width, but
        # real clients emit 1-2 bytes; an over-wide encoding is the primitive
        # LDAPNightmare (CVE-2024-49112/49113) uses to smuggle a non-zero
        # lm_referral past wldap32's decoder, so the width itself is evidence.
        self.message_id_len = message_id_len
        self.op_tag = op_tag
        self.op_name = op_name
        self.op = {}                # op-specific parsed fields
        self.has_controls = False

    def __repr__(self):
        return f"<LDAPMessage id={self.message_id} op={self.op_name}>"


def dissect_message(data):
    """Decode a single, complete LDAPMessage from `data`. Raises BERError if malformed."""
    top, _ = ber_read(data, 0)
    if not (top.cls == 0 and top.tag == 16 and top.constructed):
        raise BERError("LDAPMessage is not a universal constructed SEQUENCE")
    kids = ber_children(top.value)
    if len(kids) < 2:
        raise BERError("LDAPMessage missing messageID or protocolOp")
    mid_el = kids[0]
    if not (mid_el.cls == 0 and mid_el.tag == 2):
        raise BERError("messageID is not INTEGER")
    message_id = ber_int(mid_el.value)
    message_id_len = len(mid_el.value)

    op_el = kids[1]
    if op_el.cls != 1:
        raise BERError("protocolOp is not APPLICATION-class")
    op_name = OP_NAMES.get(op_el.tag, f"op{op_el.tag}")
    msg = LDAPMessage(message_id, op_el.tag, op_name, message_id_len)

    for extra in kids[2:]:
        if extra.cls == 2 and extra.tag == 0:   # [0] Controls
            msg.has_controls = True

    _dispatch_op(msg, op_el)
    return msg


def _dispatch_op(msg, op_el):
    t = op_el.tag
    if t == OP_BIND_REQUEST:
        _parse_bind_request(msg, op_el)
    elif t == OP_BIND_RESPONSE:
        _parse_result(msg, op_el, extended=False)
    elif t == OP_SEARCH_REQUEST:
        _parse_search_request(msg, op_el)
    elif t == OP_SEARCH_RESULT_REF:
        _parse_search_ref(msg, op_el)
    elif t == OP_SEARCH_RESULT_DONE:
        _parse_result(msg, op_el, extended=False)
    elif t == OP_SEARCH_RESULT_ENTRY:
        _parse_search_entry(msg, op_el)
    elif t == OP_EXTENDED_REQUEST:
        _parse_extended_request(msg, op_el)
    elif t == OP_EXTENDED_RESPONSE:
        _parse_result(msg, op_el, extended=True)
    # modify/add: target DN plus the attribute names and values being written.
    # The AD CS escalation tier reads these, so this is a full dissection and
    # not just write detection.
    elif t == OP_MODIFY_REQUEST:
        _parse_modify_request(msg, op_el)
    elif t == OP_ADD_REQUEST:
        _parse_add_request(msg, op_el)
    elif t == OP_MODDN_REQUEST:
        kids = ber_children(op_el.value)
        if kids and kids[0].cls == 0 and kids[0].tag == 4:
            msg.op["target"] = as_text(kids[0].value)
    elif t == OP_DEL_REQUEST:            # [APPLICATION 10] LDAPDN (primitive)
        msg.op["target"] = as_text(op_el.value)
    # everything else (unbind, abandon, responses we don't inspect) needs no fields.


def _parse_bind_request(msg, op_el):
    kids = ber_children(op_el.value)
    if len(kids) < 3:
        raise BERError("BindRequest missing components")
    msg.op["version"] = ber_int(kids[0].value)
    msg.op["name"] = as_text(kids[1].value)
    auth = kids[2]
    if auth.cls == 2 and auth.tag == AUTH_SIMPLE:            # [0] simple
        msg.op["auth"] = "simple"
        msg.op["password"] = auth.value                     # raw bytes (in the clear)
    elif auth.cls == 2 and auth.tag == AUTH_SASL:           # [3] SaslCredentials
        msg.op["auth"] = "sasl"
        sk = ber_children(auth.value)
        msg.op["sasl_mech"] = as_text(sk[0].value) if sk else ""
        msg.op["sasl_creds"] = sk[1].value if len(sk) > 1 else b""
    else:
        msg.op["auth"] = "unknown"


def _parse_result(msg, op_el, extended):
    kids = ber_children(op_el.value)
    if not kids:
        raise BERError("LDAPResult is empty")
    msg.op["result_code"] = ber_int(kids[0].value)
    msg.op["matched_dn"] = as_text(kids[1].value) if len(kids) > 1 else ""
    msg.op["diagnostic"] = as_text(kids[2].value) if len(kids) > 2 else ""
    referrals = []
    response_name = None
    for el in kids[3:]:
        if el.cls == 2 and el.tag == 3:                     # [3] referral SEQUENCE OF URI
            for uri in ber_children(el.value):
                referrals.append(as_text(uri.value))
        elif extended and el.cls == 2 and el.tag == 10:     # [10] responseName (ext)
            response_name = as_text(el.value)
    msg.op["referrals"] = referrals
    if extended:
        msg.op["response_name"] = response_name


def _parse_search_request(msg, op_el):
    kids = ber_children(op_el.value)
    if len(kids) < 7:
        raise BERError("SearchRequest missing components")
    msg.op["base"] = as_text(kids[0].value)
    msg.op["scope"] = ber_int(kids[1].value)
    msg.op["deref"] = ber_int(kids[2].value)
    msg.op["size_limit"] = ber_int(kids[3].value)
    msg.op["time_limit"] = ber_int(kids[4].value)
    msg.op["types_only"] = bool(kids[5].value and kids[5].value[0])
    filt = _parse_filter(kids[6])
    msg.op["filter_summary"] = filt["summary"]
    msg.op["present_objectclass"] = filt["present_objectclass"]
    msg.op["injection_values"] = filt["injection_values"]
    req_attrs = []
    if len(kids) > 7 and kids[7].constructed:
        for a in ber_children(kids[7].value):
            req_attrs.append(as_text(a.value).lower())
    msg.op["requested_attrs"] = req_attrs
    msg.op["filter_attrs"] = sorted(filt["attrs"])
    msg.op["filter_equalities"] = filt["equalities"]
    msg.op["filter_max_depth"] = filt["max_depth"]
    msg.op["filter_depth_truncated"] = filt["depth_truncated"]


def _parse_search_entry(msg, op_el):
    kids = ber_children(op_el.value)
    if kids and kids[0].cls == 0 and kids[0].tag == 4:
        msg.op["object_name"] = as_text(kids[0].value)
    # PartialAttributeList: SEQUENCE OF SEQUENCE { type, vals SET OF }
    attrs = {}
    if len(kids) > 1 and kids[1].constructed:
        for pa in ber_children(kids[1].value):
            if not pa.constructed:
                continue
            pk = ber_children(pa.value)
            if not pk:
                continue
            name = as_text(pk[0].value).lower()
            vals = []
            if len(pk) > 1 and pk[1].constructed:
                vals = [v.value for v in ber_children(pk[1].value)]
            attrs.setdefault(name, []).extend(vals)
    msg.op["attributes"] = attrs


def _retain(raw):
    """Keep a bounded prefix of an attribute value, plus its true length.

    Written values range from a 30-byte userPrincipalName to a multi-kilobyte
    nTSecurityDescriptor or cACertificate. The rules need the FULL value only
    for the short identity attributes (UPN, altSecurityIdentities, the OID
    group link); for the large ones presence and length are the signal. So a
    prefix is retained and the real length recorded alongside it, which keeps
    a modify carrying a 64 KB descriptor from being held in memory per session.
    """
    return {"val": bytes(raw[:_MAX_ATTR_VALUE]), "len": len(raw),
            "truncated": len(raw) > _MAX_ATTR_VALUE}


def _parse_partial_attr(pa):
    """PartialAttribute ::= SEQUENCE { type AttributeDescription, vals SET OF }

    Returns (lowercased name, [retained values]) or None.

    RFC 4512: an AttributeDescription is case-insensitive, so the name is
    lowercased here once and every rule matches lowercase. A rule that compared
    "msPKI-Certificate-Name-Flag" literally would be defeated by a client that
    sent "mspki-certificate-name-flag", which is equally valid.
    """
    if not pa.constructed:
        return None
    pk = ber_children(pa.value)
    if not pk:
        return None
    name = as_text(pk[0].value).lower()
    vals = []
    if len(pk) > 1 and pk[1].constructed:
        for v in ber_children(pk[1].value)[:_MAX_ATTR_VALUES]:
            vals.append(_retain(v.value))
    return name, vals


def _parse_modify_request(msg, op_el):
    """ModifyRequest ::= [APPLICATION 6] SEQUENCE {
           object  LDAPDN,
           changes SEQUENCE OF change SEQUENCE {
               operation    ENUMERATED { add(0), delete(1), replace(2) },
               modification PartialAttribute } }
    """
    kids = ber_children(op_el.value)
    if kids and kids[0].cls == 0 and kids[0].tag == 4:
        msg.op["target"] = as_text(kids[0].value)
    changes, attrs = [], set()
    if len(kids) > 1 and kids[1].constructed:
        for ch in ber_children(kids[1].value)[:_MAX_MOD_CHANGES]:
            if not ch.constructed:
                continue
            ck = ber_children(ch.value)
            if len(ck) < 2:
                continue
            try:
                op_num = ber_int(ck[0].value)
            except BERError:
                continue
            parsed = _parse_partial_attr(ck[1])
            if parsed is None:
                continue
            name, vals = parsed
            changes.append({"op": MOD_OPS.get(op_num, f"op{op_num}"),
                            "attr": name, "vals": vals})
            attrs.add(name)
    msg.op["changes"] = changes
    msg.op["attrs"] = attrs


def _parse_add_request(msg, op_el):
    """AddRequest ::= [APPLICATION 8] SEQUENCE {
           entry LDAPDN, attributes AttributeList }

    Normalised into the same `changes` shape a modify produces, with op "add",
    so a rule written once covers both. An ESC escalation performed by CREATING
    an object (a rogue template, a new OID object) is the same attack as one
    performed by modifying it, and must not need a second rule.
    """
    kids = ber_children(op_el.value)
    if kids and kids[0].cls == 0 and kids[0].tag == 4:
        msg.op["target"] = as_text(kids[0].value)
    changes, attrs = [], set()
    if len(kids) > 1 and kids[1].constructed:
        for pa in ber_children(kids[1].value)[:_MAX_MOD_CHANGES]:
            parsed = _parse_partial_attr(pa)
            if parsed is None:
                continue
            name, vals = parsed
            changes.append({"op": "add", "attr": name, "vals": vals})
            attrs.add(name)
    msg.op["changes"] = changes
    msg.op["attrs"] = attrs


def _parse_search_ref(msg, op_el):
    uris = [as_text(u.value) for u in ber_children(op_el.value)]
    msg.op["uris"] = uris


def _parse_extended_request(msg, op_el):
    oid = None
    val = None
    for el in ber_children(op_el.value):
        if el.cls == 2 and el.tag == 0:        # [0] requestName (LDAPOID)
            oid = as_text(el.value)
        elif el.cls == 2 and el.tag == 1:      # [1] requestValue
            val = el.value
    msg.op["oid"] = oid
    msg.op["value_len"] = len(val) if val is not None else 0


# ---- Filter walker: enough to spot enumeration & injection ---------------- #

# Filter CHOICE context tags.
F_AND, F_OR, F_NOT = 0, 1, 2
F_EQUALITY, F_SUBSTRINGS, F_GE, F_LE = 3, 4, 5, 6
F_PRESENT, F_APPROX, F_EXTENSIBLE = 7, 8, 9

# Bytes that must be escaped inside an LDAP assertion value (RFC 4515 §3). Their
# raw presence in a decoded value is a strong signal of unescaped user input.
_INJECT_BYTES = {0x00, 0x28, 0x29, 0x5C}    # NUL ( ) backslash


def _parse_filter(el, depth=0, acc=None):
    """Walk a Filter subtree. Returns a dict with a short summary, whether an
    objectClass presence test appears anywhere, and any assertion values that
    look like unescaped injection."""
    if acc is None:
        acc = {"present_objectclass": False, "injection_values": [], "parts": [],
               "max_depth": 0, "depth_truncated": False, "equalities": [],
               "attrs": set()}
    if depth > acc["max_depth"]:
        acc["max_depth"] = depth
    if depth > _MAX_DEPTH:
        # The walk stops here rather than raising, so record that the real filter
        # is deeper than what we parsed — the packet is still evidence.
        acc["depth_truncated"] = True
        return {"summary": "(...)", **acc}

    if el.cls != 2:
        acc["parts"].append("?")
        return {"summary": "(?)", **acc}

    tag = el.tag
    if tag in (F_AND, F_OR):
        op = "&" if tag == F_AND else "|"
        subs = [_parse_filter(c, depth + 1, acc)["summary"] for c in ber_children(el.value)]
        s = "(" + op + "".join(subs) + ")"
    elif tag == F_NOT:
        inner = ber_children(el.value)
        s = "(!" + (_parse_filter(inner[0], depth + 1, acc)["summary"] if inner else "") + ")"
    elif tag in (F_EQUALITY, F_GE, F_LE, F_APPROX):
        kids = ber_children(el.value)
        attr = as_text(kids[0].value) if kids else ""
        raw = kids[1].value if len(kids) > 1 else b""
        opc = {F_EQUALITY: "=", F_GE: ">=", F_LE: "<=", F_APPROX: "~="}[tag]
        if attr:
            acc["attrs"].add(attr.lower())
        if tag == F_EQUALITY:
            # Keep the raw assertion bytes: CLDAP netlogon pings carry NtVer as a
            # 4-byte little-endian equality value, and its bits decide which
            # response builder the DC uses (see _ntver_routes_legacy).
            acc["equalities"].append((attr.lower(), raw))
        _scan_value(raw, acc, equality=(tag == F_EQUALITY))
        s = f"({attr}{opc}{_short(raw)})"
    elif tag == F_SUBSTRINGS:
        kids = ber_children(el.value)
        attr = as_text(kids[0].value) if kids else ""
        if attr:
            acc["attrs"].add(attr.lower())
        pieces = []
        if len(kids) > 1:
            for comp in ber_children(kids[1].value):
                _scan_value(comp.value, acc, equality=False)
                pieces.append(_short(comp.value))
        s = f"({attr}=" + "*".join([""] + pieces + [""]) + ")"
    elif tag == F_PRESENT:
        attr = as_text(el.value)
        if attr:
            acc["attrs"].add(attr.lower())
        if attr.lower() == "objectclass":
            acc["present_objectclass"] = True
        s = f"({attr}=*)"
    elif tag == F_EXTENSIBLE:
        # Shallow scan of any embedded octet strings for injection.
        for c in ber_children(el.value):
            if c.cls == 2 and not c.constructed:
                _scan_value(c.value, acc, equality=False)
        s = "(extensibleMatch)"
    else:
        s = "(?)"

    return {"summary": s, **acc}


def _scan_value(raw, acc, equality):
    if any(b in _INJECT_BYTES for b in raw):
        acc["injection_values"].append(raw)
    elif equality and 0x2A in raw:      # literal '*' inside an equality value
        acc["injection_values"].append(raw)


def _short(b, n=24):
    t = as_text(b)
    return t if len(t) <= n else t[:n] + "…"


# --------------------------------------------------------------------------- #
# Session state + TCP flow reassembly
# --------------------------------------------------------------------------- #

class LDAPSession:
    """Per-connection state for one client<->server LDAP TCP flow."""
    __slots__ = ("key", "server_port", "cleartext", "c2s", "s2c",
                 "tls_active", "starttls_requested", "starttls_msgid",
                 "downgrade_flagged", "entry_counts", "last_seen",
                 "cred_bind_seen", "sasl_pending", "sasl_bound",
                 "signing_flagged", "strongerauth_flagged", "bindbeforetls_flagged",
                 "refoverflow_flagged")

    def __init__(self, key, server_port, cleartext):
        self.key = key
        self.server_port = server_port
        self.cleartext = cleartext
        self.c2s = bytearray()          # client -> server reassembly buffer
        self.s2c = bytearray()          # server -> client reassembly buffer
        self.tls_active = False
        self.starttls_requested = False
        self.starttls_msgid = None
        self.downgrade_flagged = False
        self.entry_counts = defaultdict(int)   # messageID -> searchResEntry count
        self.last_seen = 0.0
        # --- bind security posture (signing / channel binding) ---
        self.cred_bind_seen = False     # a credentialed bind was seen in cleartext
        self.sasl_pending = False       # a SASL bind was initiated on cleartext
        self.sasl_bound = False         # a SASL bind reached success on cleartext
        self.signing_flagged = False    # LDAP-SASL-NO-SIGNING already emitted
        self.strongerauth_flagged = False   # LDAP-STRONGER-AUTH-REQUIRED already emitted
        self.bindbeforetls_flagged = False  # LDAP-BIND-BEFORE-STARTTLS already emitted
        self.refoverflow_flagged = False    # LDAP-REFERRAL-MSGID-OVERFLOW already emitted


class FlowContext:
    """Everything the engine needs to evaluate one message in one direction."""
    __slots__ = ("session", "direction", "client_ip", "client_port",
                 "server_ip", "server_port", "cleartext", "ts")

    def __init__(self, session, direction, client_ip, client_port,
                 server_ip, server_port, cleartext, ts):
        self.session = session
        self.direction = direction          # "c2s" or "s2c"
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.cleartext = cleartext
        self.ts = ts


class FlowManager:
    """Owns sessions, reassembles TCP payload into whole LDAPMessages, and drives
    the detection engine. Also tracks CLDAP request/response sizing for UDP/389."""

    def __init__(self, config, engine, emitter):
        self.config = config
        self.engine = engine
        self.emitter = emitter
        self.sessions = {}
        # CLDAP: (client_ip, client_port, server_ip) -> (req_len, ts)
        self._cldap_reqs = {}
        # --jndi-anyport: canonical endpoint pair -> (server_ip, server_port).
        # On a non-standard port the server is the side that sent the SYN-ACK,
        # never the lower or better-known port number.
        self._anyport_roles = {}
        self._krb_streams = {}                # Kerberos TCP reassembly, 4-byte framed
        self._last_gc = time.time()

    # -- TCP ---------------------------------------------------------------- #

    @staticmethod
    def _pair_key(a_ip, a_port, b_ip, b_port):
        return tuple(sorted(((str(a_ip), a_port), (str(b_ip), b_port))))

    def _anyport_role(self, ts, src, sport, dst, dport, payload, flags):
        """Settle client/server for a flow on a non-standard port.

        Primary signal is the SYN-ACK: only a server sends one. Falling back to
        payload content covers a flow already established when the sensor
        attached, which is the common case on an egress tap. Returns
        (client_ip, client_port, server_ip, server_port, direction) or None.
        """
        key = self._pair_key(src, sport, dst, dport)
        if flags & 0x12 == 0x12:              # SYN+ACK -> the sender is the server
            self._anyport_roles[key] = (str(src), sport)
        role = self._anyport_roles.get(key)
        if role is None and payload[:1] == b"\x30":
            # No handshake seen. An LDAPMessage names an operation that only one
            # side can send, so the content settles the roles.
            try:
                tag = dissect_message(payload).op_tag
            except BERError:
                tag = None
            if tag in _SERVER_SIDE_OPS:
                self._anyport_roles[key] = (str(src), sport)
            elif tag in _CLIENT_SIDE_OPS:
                self._anyport_roles[key] = (str(dst), dport)
            role = self._anyport_roles.get(key)
        if role is None:
            return None
        s_ip, s_port = role
        if (str(src), sport) == (s_ip, s_port):
            return str(dst), dport, s_ip, s_port, "s2c"
        return str(src), sport, s_ip, s_port, "c2s"

    def handle_tcp(self, ts, src, sport, dst, dport, payload, flags):
        kp = self.config.krb_ports
        if dport in kp or sport in kp:
            self.handle_krb_tcp(ts, src, sport, dst, dport, payload, flags)
            return
        # Identify server side by port.
        if dport in ALL_TCP_PORTS:
            client_ip, client_port = src, sport
            server_ip, server_port = dst, dport
            direction = "c2s"
        elif sport in ALL_TCP_PORTS:
            client_ip, client_port = dst, dport
            server_ip, server_port = src, sport
            direction = "s2c"
        elif self.config.jndi_anyport:
            role = self._anyport_role(ts, src, sport, dst, dport, payload, flags)
            if role is None:
                return
            client_ip, client_port, server_ip, server_port, direction = role
        else:
            return

        cleartext = (server_port in CLEARTEXT_LDAP_PORTS
                     or (self.config.jndi_anyport and server_port not in TLS_LDAP_PORTS))
        key = (client_ip, client_port, server_ip, server_port)
        sess = self.sessions.get(key)
        if sess is None:
            sess = LDAPSession(key, server_port, cleartext)
            self.sessions[key] = sess
        sess.last_seen = ts

        # Connection teardown -> forget state.
        if flags & 0x04:                      # RST
            self.sessions.pop(key, None)
            return

        if not cleartext or sess.tls_active:
            # LDAPS from the start, or post-STARTTLS: payload is encrypted, do not dissect.
            return
        if not payload:
            return

        buf = sess.c2s if direction == "c2s" else sess.s2c
        buf.extend(payload)
        self._drain(sess, buf, direction, client_ip, client_port,
                    server_ip, server_port, cleartext, ts)
        self._maybe_gc(ts)

    def _drain(self, sess, buf, direction, client_ip, client_port,
               server_ip, server_port, cleartext, ts):
        off = 0
        n = len(buf)
        while off < n:
            try:
                peek = ber_peek(buf, off)
            except BERError:
                # Unrecoverable framing error: drop this half-stream's backlog.
                del buf[:]
                return
            if peek is None:
                break                          # header not fully arrived yet
            header_len, content_len = peek
            total = header_len + content_len
            if off + total > n:
                break                          # message body not fully arrived yet
            chunk = bytes(buf[off:off + total])
            off += total
            try:
                msg = dissect_message(chunk)
            except BERError as exc:
                log.debug("dissect error on %s:%d->%s:%d: %s",
                          client_ip, client_port, server_ip, server_port, exc)
                continue
            ctx = FlowContext(sess, direction, client_ip, client_port,
                              server_ip, server_port, cleartext, ts)
            for f in self.engine.process(msg, ctx):
                self.emitter.emit(f)
        if off:
            del buf[:off]

    # -- CLDAP (UDP/389) ---------------------------------------------------- #

    def handle_krb_udp(self, ts, src, sport, dst, dport, payload):
        """Kerberos over UDP: one datagram is one message, nothing to reassemble."""
        if not payload:
            return
        for rec in self.engine.krb_findings(ts, src, sport, dst, dport, payload, "udp"):
            self.emitter.emit(rec)

    def handle_krb_tcp(self, ts, src, sport, dst, dport, payload, flags):
        """Kerberos over TCP.

        RFC 4120 s7.2.2: each message is preceded by a 4-octet big-endian
        length. This is NOT the BER-length framing the LDAP path uses, so port
        88 gets its own framer -- draining it with ber_peek would mis-frame
        every message.
        """
        key = ("krb", str(src), sport, str(dst), dport)
        buf = self._krb_streams.setdefault(key, bytearray())
        if flags & 0x04:                      # RST
            self._krb_streams.pop(key, None)
            return
        if not payload:
            return
        buf.extend(payload)
        while len(buf) >= 4:
            n = int.from_bytes(bytes(buf[:4]), "big")
            if n == 0 or n > _KRB_MAX_MSG:
                del buf[:]                    # unrecoverable framing; drop backlog
                return
            if len(buf) < 4 + n:
                return                        # wait for the rest
            msg = bytes(buf[4:4 + n])
            del buf[:4 + n]
            for rec in self.engine.krb_findings(ts, src, sport, dst, dport, msg, "tcp"):
                self.emitter.emit(rec)

    def handle_cldap(self, ts, src, sport, dst, dport, payload):
        if not payload:
            return
        if dport == CLDAP_PORT:               # query: client -> server
            client_ip, client_port, server_ip = src, sport, dst
            self._cldap_reqs[(client_ip, client_port, server_ip)] = (len(payload), ts)
            for f in self.engine.process_cldap_query(ts, src, sport, dst, dport, payload):
                self.emitter.emit(f)
        elif sport == CLDAP_PORT:             # response: server -> client
            server_ip, client_ip, client_port = src, dst, dport
            req = self._cldap_reqs.get((client_ip, client_port, server_ip))
            req_len = req[0] if req else None
            for f in self.engine.process_cldap_response(
                    ts, src, sport, dst, dport, payload, req_len):
                self.emitter.emit(f)
        self._maybe_gc(ts)

    # -- housekeeping ------------------------------------------------------- #

    def _maybe_gc(self, ts):
        if ts - self._last_gc < 60:
            return
        self._last_gc = ts
        idle = self.config.session_idle
        dead = [k for k, s in self.sessions.items() if ts - s.last_seen > idle]
        for k in dead:
            self.sessions.pop(k, None)
        stale = [k for k, (_, t) in self._cldap_reqs.items() if ts - t > 30]
        for k in stale:
            self._cldap_reqs.pop(k, None)
        self.engine.gc(ts)


# --------------------------------------------------------------------------- #
# Detection engine
# --------------------------------------------------------------------------- #

class Config:
    def __init__(self):
        self.local_nets = []                  # list of ip_network for referral scoping
        self.local_domains = []               # DNS suffixes considered local (referrals)
        self.brute_window = 30.0
        self.brute_threshold = 5
        self.large_result_threshold = 200
        self.cldap_amp_ratio = 10.0
        self.cldap_amp_floor = 500            # bytes; ignore tiny responses
        self.netlogon_fill_floor = 305        # wide chars; anchored to the lab crash point
        self.filter_depth_threshold = 12      # nested boolean depth that trips CVE-2020-12243
        self.jndi_allow_nets = []             # CIDRs of legitimate RFC 2713 directories
        self.jndi_allow_domains = []          # FQDN suffixes, same purpose
        self.jndi_anyport = False             # widen capture to any TCP port carrying BER
        self.jndi_dedup_window = 300.0        # seconds, per (client, server:port)
        # --- Kerberos TGS plane (Kerberoasting) ---
        self.krb_ports = {KRB_PORT}           # tcp+udp
        self.kdc_nets = []                    # KDC addresses; arms the correlation rule
        self.krb_honeypot_spns = set()        # decoy SPNs, lowercased; arms the honeytoken rule
        self.krb_native_nets = []             # clients whose stack omits canonicalize
        self.krb_enum_window = 120.0          # LDAP SPN search -> TGS-REQ window
        self.krb_asrep_window = 30.0          # preauth-less AS-REQ -> AS-REP window
        self.krb_dedup_window = 300.0
        # --- S4U delegation plane (CVE-2025-60704) ---
        self.protected_users = set()          # lowercased; escalates S4U2Self
        self.s4u_retry_window = 5.0           # UDP->TCP RESPONSE_TOO_BIG re-send window
        # --- AD CS (ESC) tier ---
        # Window in which two writes to the SAME object's userPrincipalName are
        # treated as a swap-and-revert. 300s is a DESIGN choice, not a measured
        # one: the attack enrols a certificate between the two writes, so it is
        # inherently quick, while the baseline rate of legitimate UPN edits is
        # site-specific and cannot be measured from inside this module. That is
        # exactly why the bare single-write case grades to medium instead of
        # riding on a guessed threshold -- see the README.
        self.adcs_upn_swap_window = 300.0
        self.session_idle = 300.0
        self.dedup_window = 60.0              # seconds to suppress identical findings

    def _in_nets(self, host, nets):
        if not nets:
            return False
        try:
            addr = ipaddress.ip_address(str(host))
        except ValueError:
            return False
        return any(addr in n for n in nets)

    def is_kdc(self, host):
        return self._in_nets(host, self.kdc_nets)

    def krb_native_client(self, host):
        """True for a host whose Kerberos stack legitimately omits canonicalize.

        MIT krb5, Linux, macOS and Java clients do this as a matter of course, so
        without this allowlist the options rule fires on every non-Windows host
        on the segment -- which is the single biggest FP risk in this tier.
        """
        return self._in_nets(host, self.krb_native_nets)

    def is_protected_user(self, name):
        """True when an impersonated principal is operator-declared sensitive.

        Matching is on the bare account name, lowercased, and also on the
        pre-@ part, so --protected-user admin matches both "admin" and
        "admin@CORP.LOCAL".
        """
        if not name or not self.protected_users:
            return False
        low = name.lower()
        return low in self.protected_users or low.split("@")[0] in self.protected_users

    def krb_is_honeypot(self, spn):
        if not spn or not self.krb_honeypot_spns:
            return False
        low = spn.lower()
        if low in self.krb_honeypot_spns:
            return True
        # Match on the service-instance part too, so a decoy declared as
        # "MSSQLSvc/decoy.corp.local" also matches a port-qualified request.
        head = low.split(":")[0]
        return head in self.krb_honeypot_spns

    def jndi_allowed(self, host):
        """True when this server is an operator-declared legitimate RFC 2713 directory.

        With no allowlist configured this is always False, so R2 always fires --
        the safe default, since a serialized Java object on the wire is far more
        often a gadget than a legacy J2EE binding.
        """
        if not self.jndi_allow_nets and not self.jndi_allow_domains:
            return False
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in self.jndi_allow_nets)
        except ValueError:
            pass
        h = host.lower().rstrip(".")
        for dom in self.jndi_allow_domains:
            d = dom.lower().lstrip(".")
            if h == d or h.endswith("." + d):
                return True
        return False

    def is_local(self, host):
        """True/False if we can decide, None if there's no local scope to judge by.
        Referral targets may be IP literals or FQDNs, so handle both."""
        try:
            addr = ipaddress.ip_address(host)
            if not self.local_nets:
                return None                   # no scope configured -> undecidable
            return any(addr in net for net in self.local_nets)
        except ValueError:
            pass                              # not an IP literal; treat as a hostname
        h = host.lower().rstrip(".")
        for dom in self.local_domains:
            d = dom.lower().lstrip(".")
            if h == d or h.endswith("." + d):
                return True
        if self.local_nets or self.local_domains:
            return False                      # scope exists and host isn't in it -> external
        return None                           # nothing configured -> undecidable


# --- RFC 4120 Kerberos (the TGS plane: Kerberoasting / AS-REP roasting) ---- #
# Kerberos is ASN.1 DER, which the hand-rolled BER decoder already reads: DER is
# a restricted BER, and every field used here is definite-length.
KRB_PORT = 88
# Ceiling on a TCP Kerberos message. Real KDC replies with a PAC run tens of KB;
# this only rejects a nonsense length field, and is deliberately well above any
# legitimate message so the framer never discards real traffic.
_KRB_MAX_MSG = 2 * 1024 * 1024

# Application tag numbers (RFC 4120 s5.4.1 / s5.9.1).
KRB_AS_REQ    = 10
KRB_AS_REP    = 11
KRB_TGS_REQ   = 12
KRB_TGS_REP   = 13
KRB_ERROR     = 30
_KRB_APP_TAGS = frozenset({KRB_AS_REQ, KRB_AS_REP, KRB_TGS_REQ, KRB_TGS_REP, KRB_ERROR})

# PA-DATA types (RFC 4120 s7.5.2).
PA_TGS_REQ        = 1
PA_ENC_TIMESTAMP  = 2
PA_PAC_REQUEST    = 128

# Encryption types (RFC 3961/3962 + RFC 4757 for the RC4 legacy pair).
ETYPE_DES_CBC_CRC   = 1
ETYPE_DES_CBC_MD5   = 3
ETYPE_AES128        = 17
ETYPE_AES256        = 18
ETYPE_RC4_HMAC      = 23
ETYPE_RC4_HMAC_EXP  = 24
_WEAK_ETYPES = frozenset({ETYPE_RC4_HMAC, ETYPE_RC4_HMAC_EXP,
                          ETYPE_DES_CBC_CRC, ETYPE_DES_CBC_MD5})

# KDCOptions bit indices (RFC 4120 s5.4.1; canonicalize from RFC 6806 s11).
# KDCOptions is a 32-bit BIT STRING numbered MSB-0: bit 0 is the most
# significant bit, so bit N has mask 1 << (31 - N).
KDCOPT_FORWARDABLE   = 1
KDCOPT_RENEWABLE     = 8
KDCOPT_CNAME_IN_ADDL_TKT = 14    # MS-SFU: MUST be set to request S4U2Proxy
KDCOPT_CANONICALIZE  = 15
KDCOPT_RENEWABLE_OK  = 27

# KRB-ERROR error codes (RFC 4120 s7.5.9) that matter here.
KDC_ERR_PREAUTH_REQUIRED = 25

# ============================ AD CS (ESC) tier ============================= #
# Certificate-template flags, transcribed from MS-CRTD and INDEPENDENTLY
# confirmed against Metasploit's Rex::Proto::MsCrtd. Both agree on every value
# used here. (Metasploit's table is missing CT_FLAG_AUTO_ENROLLMENT = 0x20,
# which this module does not use, so the agreement covers the whole used set.)
#
# MS-CRTD 2.28 msPKI-Certificate-Name-Flag:
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001   # the ESC1 conversion itself
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN   = 0x02000000
# MS-CRTD 2.26 msPKI-Enrollment-Flag:
CT_FLAG_PEND_ALL_REQUESTS         = 0x00000002   # manager approval; clearing it enables ESC1
CT_FLAG_NO_SECURITY_EXTENSION     = 0x00080000   # the ESC9 flag (see README: issued-cert side)

# AD CS objectClass values (lowercased; RFC 4512 makes these case-insensitive).
OBJCLASS_PKI_TEMPLATE        = "pkicertificatetemplate"
OBJCLASS_PKI_ENROLL_SERVICE  = "pkienrollmentservice"

# Container paths, matched as RELATIVE suffixes rather than full DNs.
# MEASURED CONSEQUENCE: everything below CN=Configuration is domain-specific
# (CN=Configuration,DC=corp,DC=local vs any other suffix), so a rule keyed on a
# full DN would work in exactly one forest. These are the invariant parts.
PKI_SERVICES_RDN   = "cn=public key services"
PKI_TEMPLATES_RDN  = "cn=certificate templates," + PKI_SERVICES_RDN
PKI_OID_RDN        = "cn=oid," + PKI_SERVICES_RDN
PKI_ENROLL_RDN     = "cn=enrollment services," + PKI_SERVICES_RDN
PKI_AIA_RDN        = "cn=aia," + PKI_SERVICES_RDN
PKI_CDP_RDN        = "cn=cdp," + PKI_SERVICES_RDN
PKI_NTAUTH_RDN     = "cn=ntauthcertificates," + PKI_SERVICES_RDN

# ESC4: attributes whose write converts or unlocks a template. Split by whether
# the write IS the escalation or merely ENABLES it, which is how the finding
# grades itself.
ADCS_TEMPLATE_CONVERSION_ATTRS = {
    "mspki-certificate-name-flag",            # ENROLLEE_SUPPLIES_SUBJECT -> ESC1
    "mspki-enrollment-flag",                  # clearing PEND_ALL_REQUESTS -> no approval
    "mspki-ra-signature",                     # 0 -> no authorized signature required
    "pkiextendedkeyusage",                    # adding client-auth / agent EKU
    "mspki-certificate-application-policy",   # the application-policy twin of the above
}
ADCS_TEMPLATE_ENABLING_ATTRS = {
    "ntsecuritydescriptor",                   # granting Enroll to a wide principal
}
ADCS_TEMPLATE_ATTRS = ADCS_TEMPLATE_CONVERSION_ATTRS | ADCS_TEMPLATE_ENABLING_ATTRS

# ESC5: writes to the PKI trust objects themselves.
ADCS_TRUST_ATTRS = {
    "ntsecuritydescriptor",     # the usual ESC5 escalation
    "cacertificate",            # planting a CA cert into the domain trust store
    "crosscertificatepair",
}

# ESC13: the OID-to-group link, and the template attribute that references it.
ATTR_OID_GROUP_LINK = "msds-oidtogrouplink"
ATTR_CERT_POLICY    = "mspki-certificate-policy"

# ESC14 / ESC10.
ATTR_ALT_SEC_ID = "altsecurityidentities"
ATTR_UPN        = "userprincipalname"

# altSecurityIdentities mapping strength, per KB5014754 -- the ONLY source that
# actually classifies these.
#
# ORDER IS LOAD-BEARING, for one specific reason that was MEASURED rather than
# assumed. "<s>" is a substring of an X509IssuerSubject value
# ("X509:<I>...<S>...") but is NOT a substring of an X509IssuerSerialNumber
# value, because "<sr>" does not contain "<s>". So:
#   * ("<i>","<s>") MUST precede ("<s>",) -- otherwise X509SubjectOnly matches
#     an IssuerSubject value first and the operator is told the wrong mapping
#     type. Both are weak, so the severity would be right and the NAME wrong,
#     which is the kind of error a severity-only test never catches.
#   * ("<i>","<sr>") vs ("<i>","<s>") ordering does NOT matter, and an earlier
#     revision of this comment wrongly claimed it did. A mutation test that
#     swapped them passed, which is how the claim was caught.
#
# MEASURED CORRECTION: CVE-2025-26647 does NOT reclassify X509SKI as weak.
# Microsoft's advisory for it never uses the words "strong" or "weak"; it adds
# an NTAuth *chaining* requirement gated by AllowNtAuthPolicyBypass. The
# "SKI is weak" claim is a researcher's argument from RFC 5280 (a CA may set
# any SKI value and AD does not verify it) and is NOT Microsoft guidance. SKI
# is therefore graded strong per KB5014754 and carries a `disputed` note, so
# the operator sees the dispute without the module inventing a reclassification.
_ALTSECID_WEAK   = "weak"
_ALTSECID_STRONG = "strong"
_ALTSECID_RULES = (
    # (marker(s) required, mapping name, strength)
    (("<sha1-pukey>",),        "X509SHA1PublicKey",      _ALTSECID_STRONG),
    (("<ski>",),               "X509SKI",                _ALTSECID_STRONG),
    (("<i>", "<sr>"),          "X509IssuerSerialNumber", _ALTSECID_STRONG),
    (("<rfc822>",),            "X509RFC822",             _ALTSECID_WEAK),
    (("<i>", "<s>"),           "X509IssuerSubject",      _ALTSECID_WEAK),
    (("<s>",),                 "X509SubjectOnly",        _ALTSECID_WEAK),
)
# Microsoft's CVE-2025-26647 advisory names two further mapping types,
# X509PublicKeyOnly and X509NSubjectOnly, which KB5014754's strength table does
# NOT cover. Their ON-WIRE markers are not documented in either source, and a
# marker table invented here would be a guess wearing the clothes of a
# measurement -- so they are deliberately NOT matched. A value whose markers are
# unrecognised falls through to ("unrecognised X509 form", None) and is reported
# with its raw value, letting the operator see exactly what was written instead
# of being handed a fabricated classification.
_ALTSECID_UNVERIFIED_TYPES = ("X509PublicKeyOnly", "X509NSubjectOnly")
# SKI's strength is contested; recorded on the finding, not acted on.
_ALTSECID_DISPUTED = {"X509SKI"}


def classify_altsecid(raw):
    """Classify one altSecurityIdentities value.

    Returns (mapping_name, strength) where strength is "weak", "strong" or
    None when the form is not a classified X509 certificate mapping.
    """
    try:
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    except Exception:
        return ("unparseable", None)
    low = text.strip().lower()
    if not low.startswith("x509:"):
        # Kerberos:user@REALM and similar are altSecurityIdentities forms that
        # are not certificate mappings at all. Reported, not graded.
        kind = text.split(":", 1)[0] if ":" in text else "unknown"
        return (f"non-X509 ({kind})", None)
    for markers, name, strength in _ALTSECID_RULES:
        if all(m in low for m in markers):
            return (name, strength)
    return ("unrecognised X509 form", None)


def _dn_leaf(dn):
    """The leaf RDN's value -- "CN=Administrator,CN=Users,.." -> "Administrator".

    Used to test a write target against --protected-user, which names accounts
    rather than full DNs.
    """
    if not dn:
        return ""
    first = dn.split(",", 1)[0].strip()
    return first.split("=", 1)[1].strip() if "=" in first else first


def dn_in(target, *rdns):
    """True when `target` sits at or below any of the given relative paths.

    Case-insensitive, and tolerant of the spacing AD emits around DN commas,
    because a DN is compared as a string here rather than normalised per
    RFC 4514 -- which is enough for a containment test and avoids pulling a
    full DN parser into a passive path.
    """
    if not target:
        return False
    low = target.lower().replace(", ", ",")
    return any(r in low for r in rdns)


# --- S4U (MS-SFU) pre-authentication data types ------------------------------- #
# Both VERIFIED against impacket's PreAuthenticationDataTypes enumeration.
PA_FOR_USER      = 129
PA_S4U_X509_USER = 130

# Kerberos checksum type numbers, transcribed from the IANA "Kerberos Checksum
# Type Numbers" registry.
#
# NOT from impacket. impacket's ChecksumTypes labels 4 as `rsa_md4_des`, but
# IANA assigns 3 = rsa-md4-des and 4 = des-mac. Taking impacket as ground truth
# shifts the unkeyed set by one position, so the registry is the authority here
# and the conformance tier carries its own independent copy of this table.
CKSUM_CRC32              = 1
CKSUM_RSA_MD4            = 2
CKSUM_RSA_MD4_DES        = 3
CKSUM_DES_MAC            = 4
CKSUM_DES_MAC_K          = 5
CKSUM_RSA_MD4_DES_K      = 6
CKSUM_RSA_MD5            = 7
CKSUM_RSA_MD5_DES        = 8
CKSUM_RSA_MD5_DES3       = 9
CKSUM_SHA1_10            = 10        # registry: "sha1 (unkeyed)"
CKSUM_HMAC_SHA1_DES3_KD  = 12
CKSUM_HMAC_SHA1_DES3     = 13
CKSUM_SHA1_14            = 14        # registry: "sha1 (unkeyed)"
CKSUM_HMAC_SHA1_96_AES128 = 15
CKSUM_HMAC_SHA1_96_AES256 = 16
# Microsoft-private (RFC 4757 s4). Negative, and absent from the IANA registry.
CKSUM_HMAC_MD5           = -138

# Checksum types that take NO key, so anyone able to rewrite the protected
# content can also recompute a valid checksum over it. This is the load-bearing
# set for CVE-2025-60704.
#
# IMPORTANT, and documented rather than glossed: the IANA registry explicitly
# annotates only 10 and 14 as "unkeyed". The other three are unkeyed *by
# algorithm* -- CRC32, RSA-MD4 and RSA-MD5 are bare hashes with no key input,
# whereas every -des/-des3/hmac- variant takes a key. This set is therefore
# DERIVED from the algorithms, not read off a registry column, and must not be
# described as registry-labelled.
_UNKEYED_CKSUMS = frozenset({CKSUM_CRC32, CKSUM_RSA_MD4, CKSUM_RSA_MD5,
                             CKSUM_SHA1_10, CKSUM_SHA1_14})

# Registry names, for the finding text. Transcribed from the same IANA table.
_CKSUM_NAMES = {
    CKSUM_CRC32: "CRC32", CKSUM_RSA_MD4: "rsa-md4", CKSUM_RSA_MD4_DES: "rsa-md4-des",
    CKSUM_DES_MAC: "des-mac", CKSUM_DES_MAC_K: "des-mac-k",
    CKSUM_RSA_MD4_DES_K: "rsa-md4-des-k", CKSUM_RSA_MD5: "rsa-md5",
    CKSUM_RSA_MD5_DES: "rsa-md5-des", CKSUM_RSA_MD5_DES3: "rsa-md5-des3",
    CKSUM_SHA1_10: "sha1", CKSUM_HMAC_SHA1_DES3_KD: "hmac-sha1-des3-kd",
    CKSUM_HMAC_SHA1_DES3: "hmac-sha1-des3", CKSUM_SHA1_14: "sha1",
    CKSUM_HMAC_SHA1_96_AES128: "hmac-sha1-96-aes128",
    CKSUM_HMAC_SHA1_96_AES256: "hmac-sha1-96-aes256",
    CKSUM_HMAC_MD5: "KERB_CHECKSUM_HMAC_MD5",
}

# Service classes that exist ONLY on a domain controller. Used to grade the
# S4U2Proxy rule. `cifs` and `host` are deliberately NOT here: they are present
# on every member server, so escalating on them would call ordinary delegation
# to a file server a DC-targeted attack.
_DC_ONLY_CLASSES = frozenset({"ldap", "gc", "krbtgt"})


def kdcopt_mask(bit):
    """Mask for an MSB-0 numbered bit in a 32-bit KDCOptions BIT STRING.

    VERIFIED against impacket's own encoder: forwardable+renewable+canonicalize
    encodes to 0x40810000 on the wire and clearing canonicalize gives
    0x40800000, which is the pair the roasting rule turns on.
    """
    return 1 << (31 - bit)


# Service classes that belong to COMPUTER accounts, whose passwords are random
# 120-character machine secrets and therefore not crackable. A TGS-REQ for one
# of these is not a roast however its options look. krbtgt is here too: a
# TGS-REQ for krbtgt/REALM is a cross-realm referral or TGT renewal, which is
# ordinary traffic and frequently has canonicalize clear.
_NON_ROASTABLE_CLASSES = frozenset({
    "krbtgt", "host", "cifs", "ldap", "gc", "restrictedkrbhost",
    "termsrv", "wsman", "rpcss", "dns", "protectedstorage",
})


class KrbMessage:
    """A parsed Kerberos KDC-REQ / KDC-REP / KRB-ERROR, as far as cleartext goes."""

    __slots__ = ("msg_type", "app_tag", "kdc_options", "sname", "spn", "cname",
                 "realm", "etypes", "padata_types", "rep_etype", "error_code",
                 "for_user", "x509_user", "addl_tickets")

    def __init__(self, app_tag):
        self.app_tag = app_tag
        self.msg_type = None
        self.kdc_options = None
        self.sname = []
        self.spn = ""
        self.cname = ""
        self.realm = ""
        self.etypes = []
        self.padata_types = []
        self.rep_etype = None
        self.error_code = None
        # S4U (MS-SFU). Each is None when the padata was absent or undecodable;
        # a dict when it parsed. Absent and malformed are deliberately NOT
        # collapsed, because a rule keyed on a checksum type must be able to
        # tell "no checksum seen" from "checksum type 2".
        self.for_user = None          # PA-FOR-USER (129)
        self.x509_user = None         # PA-S4U-X509-USER (130)
        self.addl_tickets = 0         # count of additional-tickets entries

    @property
    def is_reply(self):
        return self.app_tag in (KRB_AS_REP, KRB_TGS_REP)

    def preauth_present(self):
        return PA_ENC_TIMESTAMP in self.padata_types

    @property
    def service_class(self):
        return self.sname[0].lower() if self.sname else ""

    @property
    def is_request(self):
        return self.app_tag in (KRB_AS_REQ, KRB_TGS_REQ)

    def roastable_target(self):
        """True when the sname looks like a USER-account SPN.

        Computer accounts (a trailing '$', or a machine service class) hold
        random secrets and cannot be cracked, so they are excluded from the
        roasting rules rather than reported and explained away.
        """
        if not self.sname:
            return False
        if any(part.endswith("$") for part in self.sname):
            return False
        return self.service_class not in _NON_ROASTABLE_CLASSES

    def canonicalize_set(self):
        if self.kdc_options is None:
            return None
        return bool(self.kdc_options & kdcopt_mask(KDCOPT_CANONICALIZE))

    def cname_in_addl_tkt_set(self):
        if self.kdc_options is None:
            return None
        return bool(self.kdc_options & kdcopt_mask(KDCOPT_CNAME_IN_ADDL_TKT))

    def s4u_padata(self):
        """True when this request carries either S4U pre-auth structure."""
        return self.for_user is not None or self.x509_user is not None

    def impersonated(self):
        """(name, realm, source) of the asserted identity, or None.

        PA-S4U-X509-USER wins when both are present, because that is the
        structure the KDC itself prefers: MS-SFU has the KDC check 130 first and
        ignore 129 when 130 is there. Reporting the 129 identity while the KDC
        acted on the 130 one would describe the wrong impersonation -- which is
        exactly the substitution CVE-2025-60704 performs.
        """
        if self.x509_user is not None and self.x509_user.get("name"):
            x = self.x509_user
            return (x["name"], x.get("realm", ""), "PA-S4U-X509-USER")
        if self.for_user is not None and self.for_user.get("name"):
            f = self.for_user
            return (f["name"], f.get("realm", ""), "PA-FOR-USER")
        return None


def krb_explicit(el):
    """Unwrap an EXPLICIT context tag, returning the single inner element.

    RFC 4120's ASN.1 module is EXPLICIT TAGS, so every [n] field on the wire is
    a CONSTRUCTED context tag wrapping the real primitive -- [2] msg-type is a
    constructed [2] holding a UNIVERSAL INTEGER, not a primitive [2]. Verified
    by dumping DER from impacket's encoder; assuming implicit tagging parses
    nothing at all.
    """
    if not el.constructed:
        return None
    kids = ber_children(el.value)
    return kids[0] if kids else None


def _krb_principal(el):
    """PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF }

    `el` is the EXPLICIT [n] wrapper, so unwrap to the SEQUENCE first.
    """
    seq = krb_explicit(el)
    if seq is None or not seq.constructed:
        return []
    out = []
    for field in ber_children(seq.value):
        if field.cls == 2 and field.tag == 1:
            inner = krb_explicit(field)        # SEQUENCE OF KerberosString
            if inner is not None and inner.constructed:
                for comp in ber_children(inner.value):
                    out.append(as_text(comp.value))
    return out


def _krb_bitstring(el):
    """EXPLICIT [n] wrapping a BIT STRING -> int.

    The BIT STRING's first content octet is the count of unused trailing bits;
    the 32 KDCOptions bits follow.
    """
    bs = krb_explicit(el)
    if bs is None or bs.constructed:
        return None
    v = bs.value
    if len(v) < 2:
        return None
    body = bytes(v[1:5]).ljust(4, b"\x00")
    return int.from_bytes(body, "big")


def _krb_int(el):
    inner = krb_explicit(el)
    return None if inner is None or inner.constructed else ber_int(inner.value)


def _krb_str(el):
    inner = krb_explicit(el)
    return "" if inner is None or inner.constructed else as_text(inner.value)


def _krb_checksum(el):
    """Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }

    VERIFIED against impacket's Checksum ASN.1. Returns the cksumtype, or None.
    Only the type is read: the checksum bytes themselves are of no use to a
    passive observer and are not retained.
    """
    seq = krb_explicit(el)
    if seq is None or not seq.constructed:
        return None
    for f in ber_children(seq.value):
        if f.cls == 2 and f.tag == 0:
            return _krb_int(f)
    return None


def _krb_pa_for_user(raw):
    """PA-FOR-USER (129).

    SEQUENCE { userName [0] PrincipalName, userRealm [1] Realm,
               cksum [2] Checksum, auth-package [3] KerberosString }

    Field numbering VERIFIED against impacket's PA_FOR_USER_ENC.

    MS-SFU protects this with a KEYED checksum (KERB_CHECKSUM_HMAC_MD5, key
    usage 17) -- integrity, not confidentiality -- so the impersonated identity
    is plaintext on the wire. That is what makes this whole tier passive.
    """
    try:
        seq, _ = ber_read(raw, 0)
    except BERError:
        return None
    if not seq.constructed:
        return None
    out = {"name": "", "realm": "", "cksumtype": None, "auth_package": ""}
    try:
        for f in ber_children(seq.value):
            if f.cls != 2:
                continue
            if f.tag == 0:
                out["name"] = "/".join(_krb_principal(f))
            elif f.tag == 1:
                out["realm"] = _krb_str(f)
            elif f.tag == 2:
                out["cksumtype"] = _krb_checksum(f)
            elif f.tag == 3:
                out["auth_package"] = _krb_str(f)
    except BERError:
        return None
    return out


def _krb_s4u_x509_user(raw):
    """PA-S4U-X509-USER (130).

    SEQUENCE { user-id [0] S4UUserID, checksum [1] Checksum }
    S4UUserID ::= SEQUENCE { nonce [0] UInt32, cname [1] PrincipalName,
                             crealm [2] Realm, subject-certificate [3] OCTET STRING,
                             options [4] BIT STRING }

    Both layouts VERIFIED against impacket's PA_S4U_X509_USER / S4UUserID.

    This structure has a LEGITIMATE use -- certificate-based S4U identity, where
    cname is omitted and the KDC reads the subject from the certificate. Its
    mere presence therefore proves nothing, and the detection keys on the
    checksum type alone.
    """
    try:
        seq, _ = ber_read(raw, 0)
    except BERError:
        return None
    if not seq.constructed:
        return None
    out = {"name": "", "realm": "", "cksumtype": None, "has_cert": False}
    try:
        for f in ber_children(seq.value):
            if f.cls != 2:
                continue
            if f.tag == 0:
                uid = krb_explicit(f)
                if uid is None or not uid.constructed:
                    continue
                for uf in ber_children(uid.value):
                    if uf.cls != 2:
                        continue
                    if uf.tag == 1:
                        out["name"] = "/".join(_krb_principal(uf))
                    elif uf.tag == 2:
                        out["realm"] = _krb_str(uf)
                    elif uf.tag == 3:
                        out["has_cert"] = True
            elif f.tag == 1:
                out["cksumtype"] = _krb_checksum(f)
    except BERError:
        return None
    return out


def parse_kerberos(payload):
    """Parse a Kerberos message. Returns a KrbMessage, or None if not Kerberos.

    Deliberately tolerant: anything that is not a recognisable KDC message
    returns None rather than raising, because udp/88 and tcp/88 can carry
    other things and a passive observer must not throw on them.
    """
    try:
        outer, _ = ber_read(payload, 0)
    except BERError:
        return None
    if outer.cls != 1 or outer.tag not in _KRB_APP_TAGS:
        return None
    msg = KrbMessage(outer.tag)
    try:
        inner = ber_children(outer.value)
        if not inner or not inner[0].constructed:
            return None
        req_shape = outer.tag in (KRB_AS_REQ, KRB_TGS_REQ)
        for f in ber_children(inner[0].value):
            if f.cls != 2:
                continue
            if not req_shape:
                # KDC-REP: pvno[0] msg-type[1] padata[2] crealm[3] cname[4]
                #          ticket[5] enc-part[6]
                # KRB-ERROR: ... msg-type[1] ... error-code[6] crealm[7]
                #          cname[8] realm[9] sname[10]
                # The numbering differs from KDC-REQ, so a single tag map would
                # silently misread every reply.
                if f.tag == 1:
                    msg.msg_type = _krb_int(f)
                elif f.tag == 6 and outer.tag == KRB_ERROR:
                    msg.error_code = _krb_int(f)
                elif f.tag == 6 and outer.tag in (KRB_AS_REP, KRB_TGS_REP):
                    ep = krb_explicit(f)      # EncryptedData SEQUENCE
                    if ep is not None and ep.constructed:
                        for ef in ber_children(ep.value):
                            if ef.cls == 2 and ef.tag == 0:
                                msg.rep_etype = _krb_int(ef)
                elif f.tag == 4 and outer.tag in (KRB_AS_REP, KRB_TGS_REP):
                    msg.cname = "/".join(_krb_principal(f))
                elif f.tag == 8 and outer.tag == KRB_ERROR:
                    msg.cname = "/".join(_krb_principal(f))
                elif f.tag == 10 and outer.tag == KRB_ERROR:
                    msg.sname = _krb_principal(f)
                elif f.tag == 3 and outer.tag in (KRB_AS_REP, KRB_TGS_REP):
                    msg.realm = _krb_str(f)
                continue
            if f.tag == 2:
                msg.msg_type = _krb_int(f)
            elif f.tag == 3 and msg.app_tag in (KRB_AS_REQ, KRB_TGS_REQ):
                pas = krb_explicit(f)          # SEQUENCE OF PA-DATA
                if pas is not None and pas.constructed:
                    for pa in ber_children(pas.value):
                        if not pa.constructed:
                            continue
                        # PA-DATA ::= SEQUENCE { padata-type [1] Int32,
                        #                        padata-value [2] OCTET STRING }
                        # The value is an OCTET STRING whose content is itself
                        # DER, so the S4U structures are a second decode pass.
                        t, val = None, None
                        for pf in ber_children(pa.value):
                            if pf.cls != 2:
                                continue
                            if pf.tag == 1:
                                t = _krb_int(pf)
                            elif pf.tag == 2:
                                oct_s = krb_explicit(pf)
                                if oct_s is not None and not oct_s.constructed:
                                    val = bytes(oct_s.value)
                        if t is None:
                            continue
                        msg.padata_types.append(t)
                        if val is None:
                            continue
                        if t == PA_FOR_USER:
                            msg.for_user = _krb_pa_for_user(val)
                        elif t == PA_S4U_X509_USER:
                            msg.x509_user = _krb_s4u_x509_user(val)
            elif f.tag == 4:
                body = krb_explicit(f)         # KDC-REQ-BODY SEQUENCE
                if body is None or not body.constructed:
                    continue
                for bf in ber_children(body.value):
                    if bf.cls != 2:
                        continue
                    if bf.tag == 0:
                        msg.kdc_options = _krb_bitstring(bf)
                    elif bf.tag == 1:
                        msg.cname = "/".join(_krb_principal(bf))
                    elif bf.tag == 2:
                        msg.realm = _krb_str(bf)
                    elif bf.tag == 3:
                        msg.sname = _krb_principal(bf)
                    elif bf.tag == 11:
                        # additional-tickets [11] SEQUENCE OF Ticket -- the
                        # evidence ticket an S4U2Proxy request carries.
                        ts_ = krb_explicit(bf)
                        if ts_ is not None and ts_.constructed:
                            msg.addl_tickets = len(ber_children(ts_.value))
                    elif bf.tag == 8:
                        es = krb_explicit(bf)
                        if es is not None and es.constructed:
                            for e in ber_children(es.value):
                                if not e.constructed:
                                    msg.etypes.append(ber_int(e.value))
    except BERError:
        return None
    if msg.sname:
        msg.spn = "/".join(msg.sname)
    return msg


# --- RFC 2713 Java objects in LDAP (the JNDI delivery leg) ----------------- #
# Attribute and objectClass names transcribed from RFC 2713. LDAP attribute
# descriptions are case-insensitive (RFC 4512 s2.5), and the dissector lowercases
# them, so every comparison here is against the lowercase form.
ATTR_JAVA_CLASS_NAME       = "javaclassname"
ATTR_JAVA_CODEBASE         = "javacodebase"
ATTR_JAVA_FACTORY          = "javafactory"
ATTR_JAVA_REFERENCE_ADDRESS = "javareferenceaddress"
ATTR_JAVA_SERIALIZED_DATA  = "javaserializeddata"
OC_JAVA_NAMING_REFERENCE   = "javanamingreference"
OC_JAVA_SERIALIZED_OBJECT  = "javaserializedobject"
OC_JAVA_MARSHALLED_OBJECT  = "javamarshalledobject"
_RFC2713_OBJECTCLASSES = frozenset({
    OC_JAVA_NAMING_REFERENCE, OC_JAVA_SERIALIZED_OBJECT, OC_JAVA_MARSHALLED_OBJECT})

# Java serialization stream header: STREAM_MAGIC 0xACED + STREAM_VERSION 0x0005
# (java.io.ObjectStreamConstants). A serialized object always opens with this.
JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"

# Codebase schemes that actually fetch remote bytes. A javaCodeBase value that is
# not one of these is not a remote-class-load vector, so it must not fire.
_CODEBASE_SCHEMES = ("http://", "https://", "ftp://", "file://")


def codebase_urls(values):
    """Return the javaCodeBase values that parse as fetchable URLs.

    RFC 2713 allows a space-separated list of URLs in javaCodeBase, so each
    value is split before checking. Anything without a fetchable scheme is
    ignored rather than reported -- an attribute merely NAMED javaCodeBase is
    not a delivery payload.
    """
    out = []
    for v in values:
        text = v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)
        for tok in text.split():
            low = tok.lower()
            if any(low.startswith(sch) for sch in _CODEBASE_SCHEMES):
                out.append(tok)
    return out


def url_host_path(url):
    """Split a fetchable URL into (host, path) without importing urllib.

    Only used for IOC logging: the codebase host is attacker infrastructure,
    which is exactly what an operator needs to pivot on.
    """
    rest = url.split("://", 1)[1] if "://" in url else url
    if "/" in rest:
        hostport, path = rest.split("/", 1)
        path = "/" + path
    else:
        hostport, path = rest, "/"
    if "@" in hostport:                       # strip any userinfo
        hostport = hostport.rsplit("@", 1)[1]
    return hostport, path


# --- MS-ADTS netlogon (CLDAP DC-locator) ---------------------------------- #
# Opcodes (MS-ADTS 6.3.1.9). The legacy pair is served by BuildSamLogonResponse,
# the *_EX pair by the bounds-safe BuildSamLogonResponseEx.
NETLOGON_SAM_LOGON_RESPONSE      = 19
NETLOGON_SAM_USER_UNKNOWN        = 21
NETLOGON_SAM_LOGON_RESPONSE_EX   = 23
NETLOGON_SAM_USER_UNKNOWN_EX     = 25
_NETLOGON_LEGACY_OPS = frozenset({NETLOGON_SAM_LOGON_RESPONSE, NETLOGON_SAM_USER_UNKNOWN})
_NETLOGON_EX_OPS = frozenset({NETLOGON_SAM_LOGON_RESPONSE_EX, NETLOGON_SAM_USER_UNKNOWN_EX})

# NtVer flag bits (MS-ADTS 6.3.1.1).
NTVER_V1            = 0x00000001
NTVER_V5            = 0x00000002
NTVER_V5EX          = 0x00000004
NTVER_V5EX_WITH_IP  = 0x00000008

# The 528-byte (264 wide char) stack buffer in BuildSamLogonResponse.
NETLOGON_LEGACY_BUFFER_WCHARS = 264


def ntver_routes_legacy(ntver):
    """True when an NtVer value routes a DC-locator ping to the VULNERABLE
    legacy BuildSamLogonResponse rather than the bounds-safe *Ex builder.

    Per the binary-verified analysis of CVE-2026-41089, the legacy builder is
    reached only when (NtVer & 0x0C) == 0 and (NtVer & 0x02) != 0. Public
    exploit attempts sending 0x16 or 0x06 set bit 0x04 and therefore land in
    BuildSamLogonResponseEx, never triggering the bug.
    """
    return (ntver & (NTVER_V5EX | NTVER_V5EX_WITH_IP)) == 0 and (ntver & NTVER_V5) != 0


def _rfc1035_name(buf, off, _depth=0):
    """Read one RFC 1035 label-encoded name. Returns (name, next_offset).

    Compression pointers are followed for the VALUE but never advance the
    caller's cursor past the pointer, per the format. Depth-capped so a
    self-referential pointer in hostile input cannot loop."""
    labels = []
    cur = off
    after = None
    while cur < len(buf) and _depth < 16:
        ln = buf[cur]
        if ln == 0:
            cur += 1
            break
        if ln & 0xC0 == 0xC0:                       # compression pointer
            if cur + 1 >= len(buf):
                break
            ptr = ((ln & 0x3F) << 8) | buf[cur + 1]
            after = cur + 2
            sub, _ = _rfc1035_name(buf, ptr, _depth + 1)
            if sub:
                labels.append(sub)
            cur = after
            break
        if cur + 1 + ln > len(buf):
            break
        labels.append(buf[cur + 1:cur + 1 + ln].decode("utf-8", "replace"))
        cur += 1 + ln
    return ".".join(l for l in labels if l), (after if after is not None else cur)


def _utf16_z(buf, off):
    """Read a NUL-terminated UTF-16LE string. Returns (text, next_offset)."""
    end = off
    while end + 1 < len(buf) and buf[end:end + 2] != b"\x00\x00":
        end += 2
    return buf[off:end].decode("utf-16-le", "replace"), min(end + 2, len(buf))


def parse_netlogon_response(blob):
    """Decode the DNS names a DC advertises in a NETLOGON_SAM_LOGON_RESPONSE[_EX].

    Returns None when the blob is not a recognisable netlogon response. The
    three DNS names are what BuildSamLogonResponse serializes into its fixed
    stack buffer, so their combined length is the overflow precondition for
    CVE-2026-41089 -- and unlike the attacker's User field, the DC supplies
    them itself, which is why they are the thing worth measuring.
    """
    if len(blob) < 4:
        return None
    op = int.from_bytes(blob[0:2], "little")
    if op in _NETLOGON_EX_OPS:
        off = 2 + 2 + 4 + 16                        # Sbz, Flags, DomainGuid
    elif op in _NETLOGON_LEGACY_OPS:
        off = 2
        for _ in range(3):                          # LogonServer, UserName, DomainName
            _, off = _utf16_z(blob, off)
        off += 16                                   # DomainGuid
    else:
        return None
    if off >= len(blob):
        return None
    forest, off = _rfc1035_name(blob, off)
    domain, off = _rfc1035_name(blob, off)
    host, off = _rfc1035_name(blob, off)
    return {"opcode": op, "legacy": op in _NETLOGON_LEGACY_OPS,
            "dns_forest": forest, "dns_domain": domain, "dns_host": host}


# Which side an operation can only have come FROM. Used to settle the client /
# server roles on a non-standard port when the SYN-ACK was not observed (a
# mid-flow capture on an egress tap), since port numbers carry no meaning there.
_SERVER_SIDE_OPS = frozenset({
    OP_BIND_RESPONSE, OP_SEARCH_RESULT_ENTRY, OP_SEARCH_RESULT_DONE,
    OP_SEARCH_RESULT_REF, OP_EXTENDED_RESPONSE,
})
_CLIENT_SIDE_OPS = frozenset({
    OP_BIND_REQUEST, OP_SEARCH_REQUEST, OP_EXTENDED_REQUEST,
    OP_MODIFY_REQUEST, OP_ADD_REQUEST, OP_DEL_REQUEST, OP_MODDN_REQUEST,
    OP_COMPARE_REQUEST,
})


# "Real" post-bind operations: seeing any of these in cleartext AFTER a completed
# SASL bind proves the SASL layer negotiated no integrity (a signed/sealed session
# would carry GSS-wrapped, unparseable bytes and never reach the dissector).
_POST_BIND_OPS = frozenset({
    OP_SEARCH_REQUEST, OP_SEARCH_RESULT_ENTRY, OP_SEARCH_RESULT_DONE,
    OP_SEARCH_RESULT_REF, OP_MODIFY_REQUEST, OP_ADD_REQUEST, OP_DEL_REQUEST,
    OP_MODDN_REQUEST, OP_COMPARE_REQUEST, OP_EXTENDED_REQUEST,
})


class LDAPEngine:
    """Stateless-per-message except for cross-message correlators (brute force,
    large result sets, CLDAP pairing). All emitted findings are plain dicts."""

    def __init__(self, config):
        self.config = config
        # brute force: (client_ip, server_ip, server_port) -> deque[timestamps]
        self._bind_fail = defaultdict(deque)
        # CVE-2026-41089 correlation / once-only state, keyed by server ip
        # --- Kerberos TGS plane ---
        self._krb_spn_search = {}             # client_ip -> ts of last LDAP SPN search
        self._krb_noauth_as = {}              # (client_ip, cname) -> ts of preauth-less AS-REQ
        self._krb_seen = {}                   # (code, client, spn) -> last emit ts
        self._krb_disarmed_logged = set()
        self._krb_etype_latch = {}            # (realm, principal) -> set of AS-REP etypes
        self._upn_history = {}                # dn(lower) -> [(ts, upn)] UPN writes
        self._upn_owner = {}                  # upn(lower) -> dn, from reads and writes
        self._krb_msg_seen = {}               # (client, sha1(payload)) -> ts, retry guard
        self._jndi_seen = {}                  # (client, server, port) -> last emit ts
        self._jndi_naming_refs = 0            # R3 counter (corroborating only)
        self._legacy_ntver_dcs = set()
        self._netlogon_flagged = set()

    # -- helpers ------------------------------------------------------------ #

    def _finding(self, code, ctx, message_id=None, summary=None, detail=None,
                 src=None, sport=None, dst=None, dport=None, proto="tcp",
                 severity=None):
        sev, cat, title = FINDINGS[code]
        if severity is not None and severity != sev:
            # Graded severity. The catalogue entry stays the declared default
            # and the record carries base_severity, so a downstream consumer can
            # always recover what the code means on its own before grading.
            if severity not in SEVERITY_ORDER:
                raise ValueError(f"unknown severity {severity!r}")
            detail = dict(detail or {})
            detail["base_severity"] = sev
            sev = severity
        rec = {
            "ts": iso(ctx.ts if hasattr(ctx, "ts") else time.time()),
            "module": MODULE,
            "finding": code,
            "severity": sev,
            "category": cat,
            "title": title,
            "proto": proto,
        }
        if ctx is not None and hasattr(ctx, "client_ip"):
            rec["src"] = src if src is not None else ctx.client_ip
            rec["sport"] = sport if sport is not None else ctx.client_port
            rec["dst"] = dst if dst is not None else ctx.server_ip
            rec["dport"] = dport if dport is not None else ctx.server_port
        else:
            rec["src"], rec["sport"] = src, sport
            rec["dst"], rec["dport"] = dst, dport
        if message_id is not None:
            rec["message_id"] = message_id
        if summary:
            rec["summary"] = summary
        if detail:
            rec["detail"] = detail
        return rec

    # -- CVE detectors (address-family agnostic: they read only LDAP payload) #

    @staticmethod
    def _is_referral_msgid_overflow(msg):
        """LDAPNightmare (CVE-2024-49112 RCE / CVE-2024-49113 DoS).

        A referral response is chased by the Windows LDAP client (wldap32). The
        client derives lm_referral from the SAME packet field as the messageID,
        by shifting it right by 25 bits -- so lm_referral is only non-zero if the
        messageID is encoded wide enough (>= 4 bytes) to have bits above 25 set.
        Unpatched wldap32 then indexes a NULL referral table with that value.

        Legitimate clients encode messageID in 1-2 bytes, so an over-wide
        messageID carrying bits >= 25 on a *referral* response is not something a
        conforming implementation produces. Both the RCE and the DoS ride this
        same primitive; they differ only in what follows, which we cannot see.
        """
        if msg.op.get("result_code") != RESULT_REFERRAL:
            return False
        if not msg.op.get("referrals"):
            return False            # must carry ldap:// URLs for the client to chase
        if msg.message_id_len < 4:
            return False            # too narrow to reach bit 25 at all
        return (msg.message_id >> 25) != 0

    def _referral_overflow_finding(self, msg, ctx, **kw):
        return self._finding(
            "LDAP-REFERRAL-MSGID-OVERFLOW", ctx, msg.message_id,
            summary=f"Referral response with {msg.message_id_len}-byte messageID "
                    f"(lm_referral={msg.message_id >> 25}) — LDAPNightmare pattern",
            detail={"cve": ["CVE-2024-49112", "CVE-2024-49113"],
                    "message_id_len": msg.message_id_len,
                    "lm_referral": msg.message_id >> 25,
                    "result_code": RESULT_REFERRAL,
                    "referrals": [r for r in msg.op.get("referrals", [])[:3]],
                    "note": "unpatched wldap32 dereferences a NULL referral table "
                            "with this value; crashes LSASS (DoS) or worse"},
            **kw)

    def _ntver_findings(self, msg, ctx, server_ip=None, **kw):
        """CVE-2026-41089 request leg: a DC-locator ping aimed at the legacy builder.

        This keys on the NtVer ROUTING BITS, not on any length. The attacker's
        User field is capped at 130 wide chars by the binary and cannot overflow
        the 528-byte buffer on its own, so a username-length rule would fire on
        something that cannot crash anything; the routing bits are what decide
        whether the vulnerable code path runs at all.
        """
        out = []
        for attr, raw in msg.op.get("filter_equalities") or ():
            if attr != "ntver" or len(raw) != 4:
                continue
            ntver = int.from_bytes(raw, "little")
            if not ntver_routes_legacy(ntver):
                continue
            if server_ip:
                self._legacy_ntver_dcs.add(server_ip)
            out.append(self._finding(
                "LDAP-NETLOGON-NTVER-ANOMALY", ctx, msg.message_id,
                summary=f"CLDAP netlogon ping with NtVer=0x{ntver:08x} "
                        f"(V5 set, V5EX clear) -> legacy BuildSamLogonResponse",
                detail={"cve": ["CVE-2026-41089"], "ntver": f"0x{ntver:08x}",
                        "routes": "BuildSamLogonResponse (vulnerable)",
                        "note": "modern Windows DC-locator sets V5EX (0x04); this value "
                                "selects the legacy builder that carries the overflow",
                        "confidence": "medium: legacy clients can legitimately omit V5EX, "
                                      "so this is path selection, not proof of exploitation"},
                **kw))
            break
        return out

    def _netlogon_precond_findings(self, msg, ctx, server_ip=None, **kw):
        """CVE-2026-41089 response leg: does this DC meet the overflow precondition?

        The bytes that carry the write onto the stack cookie are the SERVER'S OWN
        forest/domain/host DNS names, which no attacker payload changes. A
        default-named DC cannot be crashed; a pathologically long domain can.
        """
        out = []
        for blob in (msg.op.get("attributes") or {}).get("netlogon", ()):
            info = parse_netlogon_response(blob)
            if not info:
                continue
            fill = (len(info["dns_forest"]) + len(info["dns_domain"])
                    + len(info["dns_host"]) + 3)      # + NUL terminator per name
            if fill < self.config.netlogon_fill_floor:
                continue
            if server_ip and server_ip in self._netlogon_flagged:
                break
            if server_ip:
                self._netlogon_flagged.add(server_ip)
            out.append(self._finding(
                "LDAP-NETLOGON-OVERFLOW-PRECOND", ctx, msg.message_id,
                summary=f"DC DNS names total {fill} wide chars vs a "
                        f"{NETLOGON_LEGACY_BUFFER_WCHARS}-wide-char legacy buffer",
                detail={"cve": ["CVE-2026-41089"],
                        "dns_forest": info["dns_forest"],
                        "dns_domain": info["dns_domain"],
                        "dns_host": info["dns_host"],
                        "fill_wchars": fill,
                        "buffer_wchars": NETLOGON_LEGACY_BUFFER_WCHARS,
                        "floor": self.config.netlogon_fill_floor,
                        "legacy_ntver_seen": bool(server_ip in self._legacy_ntver_dcs),
                        "note": "precondition only: an unpatched DC with names this long "
                                "would overrun the stack cookie when answering a legacy "
                                "ping. Patch state is NOT observable passively -- a patched "
                                "DC takes the identical path and refuses the write",
                        "confidence": "medium: the floor is anchored to one published lab "
                                      "measurement (98-char domain, 7-char host, 2016)"},
                **kw))
            break
        return out

    # --- Kerberos TGS plane: Kerberoasting / AS-REP roasting --------------- #

    def _krb_disarmed(self, rule, reason):
        """Log a disarmed rule ONCE on stderr. Never emits a finding about config."""
        if rule in self._krb_disarmed_logged:
            return
        self._krb_disarmed_logged.add(rule)
        sys.stderr.write(f"ldapwatch: {rule} disarmed ({reason})\n")

    def _krb_retransmission(self, client_ip, payload, ts):
        """True when this exact message was already evaluated moments ago.

        A KRB5KRB_ERR_RESPONSE_TOO_BIG makes the client re-send the IDENTICAL
        request over TCP, and UDP itself can duplicate a datagram. Evaluating
        the retry again would report one event twice.

        This is a SECOND line of defence, not the only one: with the default
        --krb-dedup-window the per-code dedup already absorbs a retry. It is
        load-bearing precisely when an operator turns dedup down to see every
        event, which is where a UDP->TCP re-send would otherwise double-report.
        The etype latch is a set, so it is NOT inflated by a duplicate -- that
        claim would be wrong and is deliberately not made here.

        Byte-identity is a sound test here rather than a heuristic: every
        KDC-REQ carries a fresh nonce and a timestamp, so two genuinely
        distinct requests are never byte-identical. An identical repeat inside
        the window is a retransmission by construction.
        """
        key = (client_ip, hashlib.sha1(payload).digest())
        last = self._krb_msg_seen.get(key)
        if last is not None and 0 <= ts - last <= self.config.s4u_retry_window:
            return True
        self._krb_msg_seen[key] = ts
        return False

    def _etype_baseline(self, realm, principal):
        """Strong etypes previously observed in an AS-REP for this principal."""
        return self._krb_etype_latch.get((realm.upper(), principal.lower()), set())

    def _krb_dedup(self, code, client, spn, ts):
        key = (code, client, spn)
        last = self._krb_seen.get(key)
        if last is not None and ts - last < self.config.krb_dedup_window:
            return False
        self._krb_seen[key] = ts
        return True

    def record_spn_search(self, client_ip, ts):
        """An LDAP search touched servicePrincipalName -- arm the correlation window."""
        self._krb_spn_search[client_ip] = ts

    def _krb_base(self, msg, client_ip, server_ip):
        return {
            "technique": "T1558.003",
            "tool": "not attributable",
            "spn": msg.spn,
            "client": client_ip,
            "kdc": server_ip,
            "af": "ipv6" if ":" in str(client_ip) else "ipv4",
            "kdc_options": (None if msg.kdc_options is None
                            else f"0x{msg.kdc_options:08x}"),
            "etypes": msg.etypes,
            "cname": msg.cname,
            "realm": msg.realm,
            "note": "a roastable ticket was requested; whether the password fell is "
                    "not observable (enc-part is encrypted with the service key)",
        }

    def _s4u_rc4_finding(self, msg, client_ip, server_ip, ts, emit, plane, observed):
        """LDAP-KRB-S4U-RC4-DOWNGRADE -- the CVE-2025-60704 precondition.

        CVE-2025-60704 only reaches the MD4 code path when the TGT session key
        is RC4, so an RC4 session key is the enabling condition for the whole
        attack. Graded, never gated: RC4-only hosts genuinely exist, so with no
        prior AES observation for the principal this drops to medium and says
        so, rather than being suppressed (which would hide the real thing on a
        sensor that had not yet seen the principal authenticate on AES).
        """
        principal = msg.cname or msg.spn
        baseline = sorted(e for e in self._etype_baseline(msg.realm, principal)
                          if e in (ETYPE_AES128, ETYPE_AES256))
        if not self._krb_dedup("LDAP-KRB-S4U-RC4-DOWNGRADE", client_ip,
                               f"{plane}:{principal}", ts):
            return []
        d = self._krb_base(msg, client_ip, server_ip)
        d["technique"] = "T1558"
        d["plane"] = plane
        d["observed_etypes"] = observed
        d["aes_baseline"] = baseline
        d["principal"] = principal
        d["cve"] = "CVE-2025-60704 (precondition)"
        d["measurement_limit"] = (
            "the TGT session key etype is NOT directly readable: the session key "
            "lives inside the encrypted enc-part. The AS-REP enc-part etype is a "
            "PROXY for it, and that is what this rule reads")
        if baseline:
            sev = "high"
            d["note"] = ("this principal was previously observed on AES in an AS-REP and "
                         "is now on RC4 -- a downgrade, which is the enabling condition "
                         "for the S4U unkeyed-checksum forgery")
        else:
            sev = "medium"
            d["confidence"] = ("no-baseline: no prior AES AS-REP observed for this "
                               "principal, so this may be an RC4-only host rather than a "
                               "downgrade. Graded down rather than suppressed")
            d["note"] = ("RC4 negotiated on the S4U/AS path -- the precondition for "
                         "CVE-2025-60704, with no AES baseline to compare against")
        return [emit("LDAP-KRB-S4U-RC4-DOWNGRADE", severity=sev, summary=(
            f"RC4 etype {observed} on the {plane} plane for {principal!r}"
            f"{' (previously AES ' + str(baseline) + ')' if baseline else ' (no AES baseline)'}"),
            detail=d)]

    def _s4u_findings(self, msg, client_ip, server_ip, ts, emit):
        """The S4U rules for one TGS-REQ. Returns (findings, rc4_rule_fired)."""
        out = []
        base = self._krb_base(msg, client_ip, server_ip)
        imp = msg.impersonated()

        # --- R1: CVE-2025-60704, unkeyed checksum on the X509 assertion ---- #
        # Keyed on the CHECKSUM TYPE, never on padata 130's presence: MS-SFU
        # gives 130 a legitimate use (certificate-based S4U identity, where
        # cname is omitted and the KDC reads the subject from the cert), so
        # presence alone would fire on correct smartcard delegation.
        if msg.x509_user is not None:
            ck = msg.x509_user.get("cksumtype")
            if ck in _UNKEYED_CKSUMS and self._krb_dedup(
                    "LDAP-KRB-S4U-X509-UNKEYED-CKSUM", client_ip, msg.spn, ts):
                d = dict(base)
                d["technique"] = "T1558"
                d["cve"] = "CVE-2025-60704"
                d["cksumtype"] = ck
                d["cksum_name"] = _CKSUM_NAMES.get(ck, "unassigned")
                d["asserted_name"] = msg.x509_user.get("name", "")
                d["asserted_realm"] = msg.x509_user.get("realm", "")
                d["subject_certificate_present"] = msg.x509_user.get("has_cert", False)
                d["for_user_also_present"] = msg.for_user is not None
                d["unkeyed_basis"] = (
                    "the IANA Kerberos Checksum Type Numbers registry annotates only "
                    "10 and 14 as unkeyed; 1 (CRC32), 2 (rsa-md4) and 7 (rsa-md5) are "
                    "unkeyed by algorithm -- bare hashes with no key input. This set is "
                    "derived, not read off a registry column")
                d["note"] = ("PA-S4U-X509-USER asserts an identity under a checksum that "
                             "takes no key, so anyone in the path can rewrite the asserted "
                             "principal and recompute a valid checksum. The KDC prefers "
                             "this structure over PA-FOR-USER when both are present")
                out.append(emit("LDAP-KRB-S4U-X509-UNKEYED-CKSUM", summary=(
                    f"S4U identity assertion for {d['asserted_name']!r} under unkeyed "
                    f"checksum {d['cksum_name']} ({ck}) to {msg.spn} from {client_ip}"),
                    detail=d))

        # --- R2 (TGS plane): RC4 offered on an S4U request ----------------- #
        rc4_fired = False
        if msg.s4u_padata():
            weak_rc4 = [e for e in msg.etypes
                        if e in (ETYPE_RC4_HMAC, ETYPE_RC4_HMAC_EXP)]
            if weak_rc4:
                recs = self._s4u_rc4_finding(msg, client_ip, server_ip, ts, emit,
                                             plane="TGS", observed=weak_rc4)
                out.extend(recs)
                # The generic posture code is superseded whether or not dedup
                # let this one through, so a deduplicated repeat does not fall
                # back to the vaguer finding.
                rc4_fired = True

        in_addl = msg.cname_in_addl_tkt_set()

        # --- R4: S4U2Proxy ------------------------------------------------- #
        # MS-SFU: cname-in-addl-tkt (bit 14) MUST be set to request S4U2Proxy,
        # and the evidence ticket travels in additional-tickets. Both are
        # required here so a bit set without a ticket is not called delegation.
        if in_addl and msg.addl_tickets > 0:
            if self._krb_dedup("LDAP-KRB-S4U2PROXY-DELEGATION", client_ip, msg.spn, ts):
                dc_only = msg.service_class in _DC_ONLY_CLASSES
                d = dict(base)
                d["technique"] = "T1550.003"
                d["stage"] = "S4U2Proxy"
                d["additional_tickets"] = msg.addl_tickets
                d["cname_in_addl_tkt"] = True
                d["target_service_class"] = msg.service_class
                d["dc_only_service"] = dc_only
                if imp:
                    d["impersonated"], d["impersonated_realm"], d["asserted_via"] = imp
                d["note"] = ("constrained delegation: this service is presenting an "
                             "evidence ticket to obtain a ticket to another service on a "
                             "user's behalf. Legitimate when the delegation is configured; "
                             "the finding reports the chain, it does not judge it")
                if dc_only:
                    d["escalation"] = (f"target service class {msg.service_class!r} exists "
                                       "only on a domain controller")
                else:
                    d["grading_limit"] = (
                        "not escalated: the SPN class alone cannot tell a DC from a member "
                        "server. Only ldap/gc/krbtgt are DC-only; cifs and host live on "
                        "every server, so they never escalate")
                out.append(emit("LDAP-KRB-S4U2PROXY-DELEGATION",
                                severity=("high" if dc_only else "medium"), summary=(
                    f"S4U2Proxy delegation to {msg.spn} from {client_ip} "
                    f"({msg.addl_tickets} evidence ticket(s))"), detail=d))

        # --- R3: S4U2Self -------------------------------------------------- #
        # S4U2Self is the stage that ASSERTS an identity; S4U2Proxy is the stage
        # that SPENDS it. bit 14 separates them, so the two never double-report
        # on one request.
        elif imp is not None:
            name, realm, via = imp
            if self._krb_dedup("LDAP-KRB-S4U2SELF-IMPERSONATION", client_ip,
                               f"{msg.spn}|{name}", ts):
                prot = self.config.is_protected_user(name)
                if not self.config.protected_users:
                    self._krb_disarmed("LDAP-KRB-S4U2SELF-IMPERSONATION escalation",
                                       "no --protected-user set")
                d = dict(base)
                d["technique"] = "T1134.001"
                d["stage"] = "S4U2Self"
                d["impersonated"] = name
                d["impersonated_realm"] = realm
                d["asserted_via"] = via
                d["requesting_service"] = msg.spn
                d["protected_user"] = prot
                d["cksumtype"] = (msg.x509_user or msg.for_user or {}).get("cksumtype")
                d["note"] = ("S4U2Self is a LEGITIMATE operation -- protocol transition and "
                             "PAC lookup both use it. This rule grades the impersonation, "
                             "it never gates on it; the identity is readable because "
                             "MS-SFU protects PA-FOR-USER for integrity, not confidentiality")
                if prot:
                    d["escalation"] = "impersonated principal is on --protected-user"
                out.append(emit("LDAP-KRB-S4U2SELF-IMPERSONATION",
                                severity=("high" if prot else "medium"), summary=(
                    f"S4U2Self: {msg.spn} requested a ticket as {name!r}"
                    f"{'@' + realm if realm else ''} via {via}"), detail=d))
        return out, rc4_fired

    def krb_findings(self, ts, src, sport, dst, dport, payload, proto):
        """Evaluate the Kerberos rules for one KDC message.

        Direction is settled by which side is the KDC port, which is how the
        client (the potential attacker) is identified for every rule.
        """
        msg = parse_kerberos(payload)
        if msg is None:
            return []
        kp = self.config.krb_ports
        if dport in kp:
            client_ip, server_ip = str(src), str(dst)
        elif sport in kp:
            client_ip, server_ip = str(dst), str(src)
        else:
            return []
        if self._krb_retransmission(client_ip, payload, ts):
            return []

        ctx = _BareCtx(ts)
        emit = lambda code, **kw: self._finding(
            code, ctx, proto=proto, src=client_ip, sport=(sport if dport in kp else dport),
            dst=server_ip, dport=(dport if dport in kp else sport), **kw)
        out = []

        # --- AS-REP roasting, decided on the REPLY -------------------------- #
        # A preauth-less AS-REQ is NOT by itself suspicious: the ordinary
        # Kerberos flow is AS-REQ(no padata) -> KRB-ERROR 25 preauth-required
        # -> AS-REQ(with PA-ENC-TIMESTAMP) -> AS-REP. Keying on the request
        # alone would fire on every normal logon on the network. What is
        # diagnostic is the KDC answering such a request with an AS-REP: that
        # only happens when the account has DONT_REQ_PREAUTH set, and the reply
        # carries material encrypted with the account's own key.
        if msg.app_tag == KRB_AS_REQ and not msg.preauth_present():
            self._krb_noauth_as[(client_ip, msg.cname)] = ts
        elif msg.app_tag == KRB_ERROR and msg.error_code == KDC_ERR_PREAUTH_REQUIRED:
            self._krb_noauth_as.pop((client_ip, msg.cname), None)   # normal flow
        elif msg.app_tag == KRB_AS_REP:
            # --- etype latch (feeds LDAP-KRB-S4U-RC4-DOWNGRADE) ------------- #
            # The AS-REP enc-part etype is a PROXY for the TGT session key
            # etype, not a direct read: the session key itself lives inside the
            # encrypted enc-part and is never on the wire. Documented as a
            # proxy in the finding rather than asserted as the key type.
            if msg.rep_etype is not None and msg.cname:
                lk = (msg.realm.upper(), msg.cname.lower())
                self._krb_etype_latch.setdefault(lk, set()).add(msg.rep_etype)
                if msg.rep_etype in (ETYPE_RC4_HMAC, ETYPE_RC4_HMAC_EXP):
                    out.extend(self._s4u_rc4_finding(
                        msg, client_ip, server_ip, ts, emit, plane="AS",
                        observed=[msg.rep_etype]))
            started = self._krb_noauth_as.pop((client_ip, msg.cname), None)
            if (started is not None and ts - started <= self.config.krb_asrep_window
                    and self._krb_dedup("LDAP-KRB-ASREP-ROASTABLE", client_ip, msg.cname, ts)):
                d = self._krb_base(msg, client_ip, server_ip)
                d["technique"] = "T1558.004"
                d["reply_etype"] = msg.rep_etype
                d["note"] = ("KDC returned an AS-REP to a pre-auth-less AS-REQ, so this "
                             "account has DONT_REQ_PREAUTH set and the reply carries "
                             "crackable material")
                out.append(emit("LDAP-KRB-ASREP-ROASTABLE", summary=(
                    f"AS-REP returned without pre-authentication for {msg.cname!r} "
                    f"(etype {msg.rep_etype})"), detail=d))

        if msg.app_tag != KRB_TGS_REQ:
            return out

        base = self._krb_base(msg, client_ip, server_ip)

        # --- honeytoken: the durable control ------------------------------- #
        if not self.config.krb_honeypot_spns:
            self._krb_disarmed("LDAP-KRB-ROAST-HONEYTOKEN", "no --krb-honeypot-spn set")
        elif self.config.krb_is_honeypot(msg.spn) and self._krb_dedup(
                "LDAP-KRB-ROAST-HONEYTOKEN", client_ip, msg.spn, ts):
            d = dict(base)
            d["note"] = ("a decoy SPN has no legitimate consumer, so any ticket request "
                         "for it is roasting by definition")
            out.append(emit("LDAP-KRB-ROAST-HONEYTOKEN", summary=(
                f"TGS-REQ for decoy SPN {msg.spn} from {client_ip}"), detail=d))

        # --- LDAP SPN enumeration then roast ------------------------------- #
        if not self.config.kdc_nets:
            self._krb_disarmed("LDAP-KRB-SPN-ENUM-THEN-ROAST", "no --kdc set")
        elif self.config.is_kdc(server_ip):
            seen = self._krb_spn_search.get(client_ip)
            if (seen is not None and ts - seen <= self.config.krb_enum_window
                    and msg.roastable_target()
                    and self._krb_dedup("LDAP-KRB-SPN-ENUM-THEN-ROAST",
                                        client_ip, msg.spn, ts)):
                d = dict(base)
                d["spn_search_age_s"] = round(ts - seen, 2)
                d["enum_window_s"] = self.config.krb_enum_window
                d["note"] = ("the same client enumerated servicePrincipalName over LDAP "
                             "and then requested a service ticket -- the two halves of "
                             "Kerberoasting, seen by one sensor")
                out.append(emit("LDAP-KRB-SPN-ENUM-THEN-ROAST", summary=(
                    f"SPN enumeration then TGS-REQ for {msg.spn} from {client_ip} "
                    f"({d['spn_search_age_s']}s apart)"), detail=d))

        # --- options artifact (opportunistic) ------------------------------ #
        canon = msg.canonicalize_set()
        if (canon is False and msg.roastable_target()
                and not self.config.krb_native_client(client_ip)
                and self._krb_dedup("LDAP-KRB-ROAST-OPTIONS", client_ip, msg.spn, ts)):
            d = dict(base)
            d["canonicalize"] = False
            d["confidence"] = ("medium: a tool artifact, not a protocol invariant -- "
                               "Windows sets canonicalize (0x40810000) and roasting tools "
                               "typically do not, but a tool could set it tomorrow. "
                               "Non-Windows Kerberos stacks legitimately omit it; "
                               "allowlist them with --krb-native-client")
            out.append(emit("LDAP-KRB-ROAST-OPTIONS", summary=(
                f"TGS-REQ for user SPN {msg.spn} with canonicalize clear "
                f"(0x{msg.kdc_options:08x}) from {client_ip}"), detail=d))

        # --- S4U plane (CVE-2025-60704 and the delegation dissection) ------ #
        s4u_out, s4u_rc4_fired = self._s4u_findings(msg, client_ip, server_ip, ts, emit)
        out.extend(s4u_out)

        # --- etype posture (NOT the roasting rule) ------------------------- #
        # Specific supersedes generic: when the S4U downgrade rule has already
        # spoken for this request, the generic posture code stays silent. One
        # condition, one finding.
        weak = [e for e in msg.etypes if e in _WEAK_ETYPES]
        if (weak and not s4u_rc4_fired and msg.roastable_target()
                and self._krb_dedup("LDAP-KRB-RC4-REQUESTED", client_ip, msg.spn, ts)):
            d = dict(base)
            d["weak_etypes"] = weak
            d["note"] = ("etype posture only: RC4 is default-off in current Windows with "
                         "AES-256 the baseline, so this is a hardening signal, not "
                         "evidence of roasting -- modern roasting requests AES")
            out.append(emit("LDAP-KRB-RC4-REQUESTED", summary=(
                f"TGS-REQ offering weak etype(s) {weak} for {msg.spn}"), detail=d))
        return out

    # --- RFC 2713 / JNDI delivery (Log4Shell-class callback leg) ----------- #

    def _jndi_port_class(self, server_port):
        if server_port == JNDI_ALT_PORT:
            return "1389"
        if server_port in (389, 3268):
            return "standard"
        return "anyport"

    def _jndi_dedup_ok(self, client_ip, server_ip, server_port, ts):
        """Once per (client, server:port) per jndi_dedup_window seconds (§5)."""
        key = (client_ip, server_ip, server_port)
        last = self._jndi_seen.get(key)
        if last is not None and ts - last < self.config.jndi_dedup_window:
            return False
        self._jndi_seen[key] = ts
        return True

    def _jndi_findings(self, msg, ctx):
        """Detect an RFC 2713 Java-object entry returned BY a server TO a client.

        This is the delivery stage of the JNDI-injection class: the victim JVM
        resolved an ldap:// JNDI name and the directory answered with an object
        it is meant to instantiate. CVE-2021-44228 / CVE-2021-45046 are the
        attribution; the shape is shared by the whole class (rogue-jndi,
        marshalsec, JNDIExploit, Fastjson/H2 gadget paths).

        Finding class is ATTACK OBSERVED, not compromise: that the payload was
        delivered is on the wire, whether the client instantiated it is not.
        """
        attrs = msg.op.get("attributes") or {}
        if not attrs:
            return []
        ocs = {(v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)).lower()
               for v in attrs.get("objectclass", ())}
        codebases = codebase_urls(attrs.get(ATTR_JAVA_CODEBASE, ()))
        serial = [b for b in attrs.get(ATTR_JAVA_SERIALIZED_DATA, ())
                  if isinstance(b, (bytes, bytearray)) and bytes(b[:4]) == JAVA_SERIAL_MAGIC]
        if not codebases and not serial:
            return []                         # nothing delivered; R3 alone never fires

        def _txt(name):
            vals = attrs.get(name) or ()
            if not vals:
                return None
            v = vals[0]
            return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)

        # R3 (corroborating only): a naming reference with a factory already on
        # the victim's classpath is the local-factory bypass shape. The factory
        # CLASS NAME is recorded as an IOC but never matched against a gadget
        # list -- that would be signature-chasing a set the attacker chooses.
        factory = _txt(ATTR_JAVA_FACTORY)
        naming_ref = (OC_JAVA_NAMING_REFERENCE in ocs) and factory is not None
        if naming_ref:
            self._jndi_naming_refs += 1

        server_ip = ctx.server_ip
        server_port = ctx.server_port
        client_ip = ctx.client_ip
        if not self._jndi_dedup_ok(client_ip, server_ip, server_port, ctx.ts):
            return []

        base = {
            "cve": ["CVE-2021-44228", "CVE-2021-45046"],
            "port_class": self._jndi_port_class(server_port),
            "af": "ipv6" if ":" in str(server_ip) else "ipv4",
            "victim_client": client_ip,
            "entry_dn": msg.op.get("object_name", ""),
            "attributes_present": sorted(attrs.keys()),
            "java_class_name": _txt(ATTR_JAVA_CLASS_NAME),
            "java_naming_reference": naming_ref,
            "java_factory": factory,
            "server_in_local_scope": self.config.is_local(str(server_ip)),
            "note": "delivery observed; execution by the client is NOT inferred",
        }

        out = []
        if codebases:
            hosts = []
            for u in codebases[:3]:
                h, pth = url_host_path(u)
                hosts.append({"host": h, "path": pth})
            d = dict(base)
            d["codebase_urls"] = codebases[:3]
            d["codebase_targets"] = hosts
            d["confidence"] = ("high: remote codebase loading is disabled by default since "
                               "JDK 6u211/7u201/8u191, so this has no working legitimate form "
                               "on a supported JDK")
            out.append(self._finding(
                "LDAP-JNDI-CODEBASE-DELIVERED", ctx, msg.message_id,
                summary=f"JNDI entry returned javaCodeBase {hosts[0]['host']} to {client_ip}"
                        f" on :{server_port}",
                detail=d))

        if serial:
            if self.config.jndi_allowed(str(server_ip)):
                return out                    # declared legacy directory: R2 suppressed
            blob = bytes(serial[0])
            d = dict(base)
            d["serialized_len"] = len(blob)
            d["serialized_sha256"] = hashlib.sha256(blob).hexdigest()
            d["confidence"] = ("high on the shape; RFC 2713 permits serialized objects, so a "
                               "genuine legacy J2EE directory can produce this -- use "
                               "--jndi-allow-server for one")
            out.append(self._finding(
                "LDAP-JNDI-SERIALIZED-OBJECT", ctx, msg.message_id,
                summary=f"Serialized Java object ({len(blob)} B) returned to {client_ip}"
                        f" on :{server_port}",
                detail=d))
        return out

    def _filter_nest_finding(self, msg, ctx, **kw):
        op = msg.op
        depth = op.get("filter_max_depth", 0)
        return self._finding(
            "LDAP-FILTER-NEST-DOS", ctx, msg.message_id,
            summary=f"Search filter nested {depth}{'+' if op.get('filter_depth_truncated') else ''} "
                    f"levels deep (threshold {self.config.filter_depth_threshold})",
            detail={"cve": ["CVE-2020-12243"],
                    "filter_depth": depth,
                    "truncated": bool(op.get("filter_depth_truncated")),
                    "threshold": self.config.filter_depth_threshold,
                    "filter": op.get("filter_summary", ""),
                    "note": "nested boolean expressions crash slapd < 2.4.50 (filter.c)"},
            **kw)

    def _nest_exceeded(self, msg):
        op = msg.op
        return (op.get("filter_max_depth", 0) > self.config.filter_depth_threshold
                or op.get("filter_depth_truncated"))

    # -- TCP message entry point ------------------------------------------- #

    def process(self, msg, ctx):
        # Signing posture is evaluated before dispatch: a readable operation after
        # a completed SASL bind is itself the evidence that no integrity layer was
        # negotiated. Then dispatch handles the operation normally.
        out = self._signing_posture(msg, ctx)
        # LDAPNightmare can arrive on any result-bearing op that carries referrals,
        # so it is checked ahead of dispatch rather than per-operation. A malicious
        # LDAP server over TCP reaches the same wldap32 code path as over CLDAP.
        if self._is_referral_msgid_overflow(msg):
            sess = ctx.session
            if not sess.refoverflow_flagged:
                sess.refoverflow_flagged = True
                out.append(self._referral_overflow_finding(msg, ctx))
        return out + self._dispatch(msg, ctx)

    def _signing_posture(self, msg, ctx):
        sess = ctx.session
        if (sess.sasl_bound and ctx.cleartext and not sess.tls_active
                and not sess.signing_flagged and msg.op_tag in _POST_BIND_OPS):
            sess.signing_flagged = True
            return [self._finding(
                "LDAP-SASL-NO-SIGNING", ctx, msg.message_id,
                summary=f"Cleartext {msg.op_name} after SASL bind on :{ctx.server_port} "
                        f"— no signing/sealing layer",
                detail={"note": "SASL security layer negotiated auth-only (no integrity); "
                                "session is authenticated but tamper-able / relay-completable"})]
        return []

    def _dispatch(self, msg, ctx):
        t = msg.op_tag
        if t == OP_BIND_REQUEST:
            return self._bind_request(msg, ctx)
        if t == OP_BIND_RESPONSE:
            return self._bind_response(msg, ctx)
        if t == OP_SEARCH_REQUEST:
            return self._search_request(msg, ctx)
        if t == OP_SEARCH_RESULT_ENTRY:
            # Record which object owns which userPrincipalName as it is READ.
            # This is what gives the ESC10 collision test a baseline: without it
            # the sensor could only compare a UPN against UPNs it had seen
            # WRITTEN, which an attacker never does for the account being
            # impersonated. Observation only -- nothing is queried to build it.
            upns = (msg.op.get("attributes") or {}).get(ATTR_UPN) or []
            for raw in upns[:4]:
                try:
                    self._note_upn_owner(msg.op.get("object_name", ""),
                                         bytes(raw).decode("utf-8", "replace"))
                except Exception:
                    pass
            return self._search_entry(msg, ctx)
        if t == OP_SEARCH_RESULT_REF:
            return self._search_ref(msg, ctx)
        if t in (OP_SEARCH_RESULT_DONE,):
            return self._search_done(msg, ctx)
        if t == OP_EXTENDED_REQUEST:
            return self._extended_request(msg, ctx)
        if t == OP_EXTENDED_RESPONSE:
            return self._extended_response(msg, ctx)
        if t in (OP_MODIFY_REQUEST, OP_ADD_REQUEST, OP_DEL_REQUEST, OP_MODDN_REQUEST):
            return self._write_request(msg, ctx)
        return []

    def _bind_request(self, msg, ctx):
        out = []
        sess = ctx.session
        op = msg.op
        version = op.get("version")
        name = op.get("name", "")
        auth = op.get("auth")

        if version == 2:
            out.append(self._finding(
                "LDAP-DEPRECATED-VERSION", ctx, msg.message_id,
                summary=f"LDAPv2 bind from {ctx.client_ip}",
                detail={"version": version, "bind_dn": name or "<anonymous>"}))

        tls = sess.tls_active
        if auth == "simple":
            pw = op.get("password", b"")
            if not name and not pw:
                out.append(self._finding(
                    "LDAP-ANONYMOUS-BIND", ctx, msg.message_id,
                    summary=f"Anonymous bind to {ctx.server_ip}:{ctx.server_port}"))
            elif name and not pw:
                out.append(self._finding(
                    "LDAP-UNAUTH-BIND", ctx, msg.message_id,
                    summary=f"Unauthenticated bind as {name}",
                    detail={"bind_dn": name,
                            "note": "DN supplied with empty password (RFC 4513 §5.1.2)"}))
            elif pw and not tls:
                out.append(self._finding(
                    "LDAP-CLEARTEXT-SIMPLE-BIND", ctx, msg.message_id,
                    summary=f"Cleartext password for {name or '<dn>'} on :{ctx.server_port}",
                    detail={"bind_dn": name, "password_len": len(pw)}))
        elif auth == "sasl":
            mech = (op.get("sasl_mech") or "").upper()
            if mech in SASL_CLEARTEXT and not tls:
                out.append(self._finding(
                    "LDAP-SASL-PLAIN-NO-TLS", ctx, msg.message_id,
                    summary=f"SASL {mech} without TLS",
                    detail={"mechanism": mech, "creds_len": len(op.get("sasl_creds", b""))}))
            if mech in SASL_WEAK:
                out.append(self._finding(
                    "LDAP-WEAK-SASL-MECH", ctx, msg.message_id,
                    summary=f"Weak SASL mechanism {mech}",
                    detail={"mechanism": mech}))

        # Transport-level: any credentialed bind on cleartext port w/o STARTTLS.
        credentialed = (
            (auth == "simple" and (name or op.get("password"))) or
            (auth == "sasl" and (op.get("sasl_mech") or "").upper() not in SASL_STRONG)
        )
        if ctx.cleartext and not tls and not sess.starttls_requested and credentialed:
            out.append(self._finding(
                "LDAP-NO-STARTTLS-BIND", ctx, msg.message_id,
                summary=f"Bind on cleartext :{ctx.server_port} without STARTTLS",
                detail={"auth": auth}))

        # Posture tracking for signing / channel binding. A bind that actually
        # authenticates (simple-with-password, or any SASL mech) is "authing";
        # any SASL bind is a candidate for a negotiated security layer.
        if ctx.cleartext and not tls:
            _pw = op.get("password", b"") if auth == "simple" else b""
            _mech = (op.get("sasl_mech") or "") if auth == "sasl" else ""
            if _pw or _mech:
                sess.cred_bind_seen = True
            if auth == "sasl":
                sess.sasl_pending = True

        # STARTTLS-strip: client requested STARTTLS then bound in cleartext anyway.
        if sess.starttls_requested and not tls and not sess.downgrade_flagged:
            sess.downgrade_flagged = True
            out.append(self._finding(
                "LDAP-STARTTLS-DOWNGRADE", ctx, msg.message_id,
                summary="Bind proceeded in cleartext after STARTTLS was requested",
                detail={"reason": "cleartext_operation_after_starttls_request"}))
        return out

    def _bind_response(self, msg, ctx):
        out = []
        sess = ctx.session
        rc = msg.op.get("result_code")
        if rc == RESULT_INVALID_CREDENTIALS:
            key = (ctx.client_ip, ctx.server_ip, ctx.server_port)
            dq = self._bind_fail[key]
            dq.append(ctx.ts)
            w = self.config.brute_window
            while dq and ctx.ts - dq[0] > w:
                dq.popleft()
            if len(dq) >= self.config.brute_threshold:
                out.append(self._finding(
                    "LDAP-BIND-BRUTE-FORCE", ctx, msg.message_id,
                    summary=f"{len(dq)} failed binds in {int(w)}s "
                            f"({ctx.client_ip}->{ctx.server_ip})",
                    detail={"failures": len(dq), "window_s": w}))
                dq.clear()                    # reset so we alert once per burst

        # Server-side signing/confidentiality enforcement (good posture): the DC
        # refused the bind demanding stronger auth or a confidential channel.
        if (rc in (RESULT_STRONGER_AUTH_REQUIRED, RESULT_CONFIDENTIALITY_REQUIRED)
                and ctx.cleartext and not sess.tls_active
                and not sess.strongerauth_flagged):
            sess.strongerauth_flagged = True
            out.append(self._finding(
                "LDAP-STRONGER-AUTH-REQUIRED", ctx, msg.message_id,
                summary=f"Server required stronger auth/confidentiality (result {rc})",
                detail={"result_code": rc, "diagnostic": msg.op.get("diagnostic", "")}))

        # A SASL bind that reached success on a cleartext port: whether it signed
        # is decided by what follows (see _signing_posture).
        if (rc == RESULT_SUCCESS and sess.sasl_pending
                and ctx.cleartext and not sess.tls_active):
            sess.sasl_bound = True

        # A server-side referral in a bind response can also point outward.
        out.extend(self._referral_findings(msg.op.get("referrals", []), ctx, msg.message_id))
        return out

    def _search_request(self, msg, ctx):
        out = []
        op = msg.op
        base = op.get("base", "")
        scope = op.get("scope")

        if base == "" and scope == SCOPE_BASE:
            out.append(self._finding(
                "LDAP-ROOTDSE-PROBE", ctx, msg.message_id,
                summary=f"RootDSE probe from {ctx.client_ip}",
                detail={"filter": op.get("filter_summary", "")}))

        if scope == SCOPE_SUBTREE and op.get("present_objectclass"):
            out.append(self._finding(
                "LDAP-WHOLE-SUBTREE-ENUM", ctx, msg.message_id,
                summary=f"Subtree enumeration under '{base or 'ROOT'}'",
                detail={"base": base, "filter": op.get("filter_summary", "")}))

        inj = op.get("injection_values") or []
        if inj:
            samples = [_short(v, 40) for v in inj[:3]]
            out.append(self._finding(
                "LDAP-INJECTION-FILTER", ctx, msg.message_id,
                summary="Unescaped metacharacters in search filter",
                detail={"filter": op.get("filter_summary", ""), "values": samples}))

        if self._nest_exceeded(msg):
            out.append(self._filter_nest_finding(msg, ctx))
        out.extend(self._ntver_findings(msg, ctx, server_ip=ctx.server_ip))
        # Kerberoasting begins here: an LDAP search that touches
        # servicePrincipalName, either in the filter or in the requested
        # attribute list. Recording it is what lets the Kerberos tier correlate
        # the enumeration half with the roast half inside one module.
        if ("serviceprincipalname" in (op.get("filter_attrs") or ())
                or "serviceprincipalname" in (op.get("requested_attrs") or ())):
            self.record_spn_search(ctx.client_ip, ctx.ts)
        return out

    def _search_entry(self, msg, ctx):
        sess = ctx.session
        out = self._jndi_findings(msg, ctx)
        sess.entry_counts[msg.message_id] += 1
        c = sess.entry_counts[msg.message_id]
        thr = self.config.large_result_threshold
        if c == thr:                          # fire exactly once at the threshold
            out.append(self._finding(
                "LDAP-LARGE-SEARCH-RESULT", ctx, msg.message_id,
                summary=f"{c}+ entries returned for one search",
                detail={"entries_so_far": c}))
        return out

    def _search_done(self, msg, ctx):
        ctx.session.entry_counts.pop(msg.message_id, None)
        return self._referral_findings(msg.op.get("referrals", []), ctx, msg.message_id)

    def _search_ref(self, msg, ctx):
        return self._referral_findings(msg.op.get("uris", []), ctx, msg.message_id,
                                       kind="continuation")

    def _referral_findings(self, uris, ctx, message_id, kind="referral"):
        out = []
        for uri in uris:
            host = _ldap_url_host(uri)
            if not host:
                continue
            local = self.config.is_local(host)
            if local is False:                # explicitly outside local nets
                out.append(self._finding(
                    "LDAP-EXTERNAL-REFERRAL", ctx, message_id,
                    summary=f"{kind.title()} to external host {host}",
                    detail={"uri": uri, "host": host, "kind": kind}))
        return out

    def _extended_request(self, msg, ctx):
        out = []
        sess = ctx.session
        oid = msg.op.get("oid")
        if oid == OID_STARTTLS:
            # Channel binding: if a credentialed bind already happened in cleartext
            # on this connection, the authentication was presented outside the TLS
            # channel and cannot be bound to it (and was exposed in cleartext).
            if (sess.cred_bind_seen and not sess.tls_active
                    and not sess.bindbeforetls_flagged):
                sess.bindbeforetls_flagged = True
                out.append(self._finding(
                    "LDAP-BIND-BEFORE-STARTTLS", ctx, msg.message_id,
                    summary="STARTTLS requested after a credentialed bind on the same connection",
                    detail={"note": "authentication presented before/outside the TLS channel; "
                                    "it cannot be channel-bound (and was sent in cleartext)"}))
            sess.starttls_requested = True
            sess.starttls_msgid = msg.message_id
        elif oid == OID_PASSWORD_MODIFY and not sess.tls_active:
            out.append(self._finding(
                "LDAP-PASSWORD-MODIFY-NO-TLS", ctx, msg.message_id,
                summary="Password Modify extended op without TLS",
                detail={"oid": oid}))
        elif oid == OID_WHOAMI and not sess.tls_active:
            out.append(self._finding(
                "LDAP-WHOAMI-NO-TLS", ctx, msg.message_id,
                summary="Who Am I extended op without TLS", detail={"oid": oid}))
        return out

    def _extended_response(self, msg, ctx):
        out = []
        sess = ctx.session
        op = msg.op
        rname = op.get("response_name")
        rc = op.get("result_code")
        is_starttls = (rname == OID_STARTTLS) or (
            sess.starttls_requested and msg.message_id == sess.starttls_msgid)
        if is_starttls:
            if rc == RESULT_SUCCESS:
                sess.tls_active = True
                # Whatever bytes follow are TLS records, not LDAP — drop backlog.
                sess.c2s.clear()
                sess.s2c.clear()
                out.append(self._finding(
                    "LDAP-STARTTLS-OK", ctx, msg.message_id,
                    summary="STARTTLS negotiated"))
            elif not sess.downgrade_flagged:
                sess.downgrade_flagged = True
                out.append(self._finding(
                    "LDAP-STARTTLS-DOWNGRADE", ctx, msg.message_id,
                    summary=f"STARTTLS refused (result {rc}); client may fall back",
                    detail={"result_code": rc, "diagnostic": op.get("diagnostic", "")}))
        return out

    def _write_request(self, msg, ctx):
        out = []
        if ctx.cleartext and not ctx.session.tls_active:
            out.append(self._finding(
                "LDAP-MODIFY-NO-TLS", ctx, msg.message_id,
                summary=f"{msg.op_name} without TLS",
                detail={"operation": msg.op_name, "target": msg.op.get("target", "")}))
        out.extend(self._adcs_findings(msg, ctx))
        return out

    # -- AD CS escalation tier (ESC4/5/13/14/10) ---------------------------- #

    @staticmethod
    def _adcs_base(msg, changed):
        return {"operation": msg.op_name,
                "target": msg.op.get("target", ""),
                "attributes_written": sorted(changed)}

    @staticmethod
    def _int_val(vals):
        """An AD Integer-syntax attribute arrives as its DECIMAL STRING form.

        msPKI-Certificate-Name-Flag is an Integer in the schema, but LDAP
        carries it as text ("33554433"), not as a BER INTEGER -- so it is
        parsed from the string. Returns None when it will not parse, and the
        caller then reports the write without decoding the flags rather than
        inventing a value.
        """
        for v in vals:
            try:
                return int(v["val"].decode("ascii", "strict").strip())
            except (ValueError, UnicodeDecodeError, KeyError):
                continue
        return None

    @staticmethod
    def _texts(vals):
        return [v["val"].decode("utf-8", "replace") for v in vals]

    def _adcs_findings(self, msg, ctx):
        op = msg.op
        changes = op.get("changes") or []
        if not changes:
            return []
        target = op.get("target", "")
        attrs = op.get("attrs") or set()
        by_attr = {}
        for ch in changes:
            by_attr.setdefault(ch["attr"], []).append(ch)
        # An addRequest carries objectClass, so the class is authoritative
        # there; a modify does not, and the DN path is the only discriminator.
        classes = {t.lower() for t in self._texts(
            [v for ch in by_attr.get("objectclass", []) for v in ch["vals"]])}
        out = []

        # --- ESC4: certificate template ----------------------------------- #
        is_template = (dn_in(target, PKI_TEMPLATES_RDN)
                       or OBJCLASS_PKI_TEMPLATE in classes)
        if is_template:
            touched = attrs & ADCS_TEMPLATE_ATTRS
            if touched:
                conv = touched & ADCS_TEMPLATE_CONVERSION_ATTRS
                d = self._adcs_base(msg, touched)
                d["esc"] = "ESC4"
                d["technique"] = "T1649"
                d["object_kind"] = "pKICertificateTemplate"
                d["stage"] = "conversion" if conv else "enabling"
                # Decode the two flag words when they are being written, so the
                # finding says WHICH change was made rather than only that the
                # attribute was touched.
                nf = self._int_val([v for ch in by_attr.get(
                    "mspki-certificate-name-flag", []) for v in ch["vals"]])
                if nf is not None:
                    d["name_flag"] = nf
                    d["enrollee_supplies_subject"] = bool(
                        nf & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
                    d["subject_alt_require_upn"] = bool(
                        nf & CT_FLAG_SUBJECT_ALT_REQUIRE_UPN)
                    if nf & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT:
                        d["note_name_flag"] = (
                            "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set: the requester "
                            "now chooses the subject, which IS the ESC1 conversion")
                ef = self._int_val([v for ch in by_attr.get(
                    "mspki-enrollment-flag", []) for v in ch["vals"]])
                if ef is not None:
                    d["enrollment_flag"] = ef
                    d["pend_all_requests"] = bool(ef & CT_FLAG_PEND_ALL_REQUESTS)
                    d["no_security_extension"] = bool(ef & CT_FLAG_NO_SECURITY_EXTENSION)
                    if not ef & CT_FLAG_PEND_ALL_REQUESTS:
                        d["note_enrollment_flag"] = (
                            "CT_FLAG_PEND_ALL_REQUESTS is CLEAR: manager approval is "
                            "not required for this template")
                ra = self._int_val([v for ch in by_attr.get(
                    "mspki-ra-signature", []) for v in ch["vals"]])
                if ra is not None:
                    d["ra_signature"] = ra
                    if ra == 0:
                        d["note_ra_signature"] = (
                            "msPKI-RA-Signature is 0: no authorized signature is "
                            "required to enrol")
                if "pkiextendedkeyusage" in touched or \
                        "mspki-certificate-application-policy" in touched:
                    d["ekus_written"] = self._texts(
                        [v for k in ("pkiextendedkeyusage",
                                     "mspki-certificate-application-policy")
                         for ch in by_attr.get(k, []) for v in ch["vals"]])[:16]
                d["note"] = ("template objects are near-static in a steady-state "
                             "domain, so a write here is high-signal. A name-flag, "
                             "enrollment-flag or RA-signature change is the ESC1 "
                             "conversion itself; an nTSecurityDescriptor change is "
                             "the enabling step")
                out.append(self._finding(
                    "LDAP-ADCS-ESC4-TEMPLATE-WRITE", ctx, msg.message_id,
                    summary=f"ESC4: {msg.op_name} on certificate template {target!r} "
                            f"touching {sorted(touched)}", detail=d))

        # --- ESC5: the PKI trust objects ---------------------------------- #
        is_trust_obj = (dn_in(target, PKI_NTAUTH_RDN, PKI_AIA_RDN, PKI_CDP_RDN,
                              PKI_ENROLL_RDN)
                        or OBJCLASS_PKI_ENROLL_SERVICE in classes
                        or (dn_in(target, PKI_SERVICES_RDN) and not is_template
                            and not dn_in(target, PKI_OID_RDN)))
        if is_trust_obj:
            touched = attrs & ADCS_TRUST_ATTRS
            if touched:
                d = self._adcs_base(msg, touched)
                d["esc"] = "ESC5"
                d["technique"] = "T1649"
                d["object_kind"] = ("pKIEnrollmentService"
                                   if OBJCLASS_PKI_ENROLL_SERVICE in classes
                                   else "PKI trust object")
                if {"cacertificate", "crosscertificatepair"} & touched:
                    d["ca_cert_planted"] = True
                    d["note_ca_cert"] = (
                        "a CA certificate is being written into the domain trust "
                        "store: this is the END STATE of ESC5, not a precursor")
                d["note"] = ("the PKI trust objects govern which CAs the forest "
                             "trusts for authentication; the usual ESC5 escalation "
                             "is an nTSecurityDescriptor change granting write "
                             "access to one of them")
                out.append(self._finding(
                    "LDAP-ADCS-ESC5-PKI-OBJECT-WRITE", ctx, msg.message_id,
                    summary=f"ESC5: {msg.op_name} on PKI trust object {target!r} "
                            f"touching {sorted(touched)}", detail=d))

        # --- ESC13: OID-to-group link ------------------------------------- #
        if ATTR_OID_GROUP_LINK in attrs or (is_template and ATTR_CERT_POLICY in attrs):
            d = self._adcs_base(msg, attrs & {ATTR_OID_GROUP_LINK, ATTR_CERT_POLICY})
            d["esc"] = "ESC13"
            d["technique"] = "T1649"
            if ATTR_OID_GROUP_LINK in attrs:
                # The value IS the group's DN, so the escalation target is
                # readable rather than inferred.
                d["linked_groups"] = self._texts(
                    [v for ch in by_attr.get(ATTR_OID_GROUP_LINK, [])
                     for v in ch["vals"]])[:8]
                d["stage"] = "group-link"
                d["note"] = ("msDS-OIDToGroupLink binds a certificate issuance "
                             "policy to a group: the KDC then adds that group's SID "
                             "to the TGT of anyone authenticating with a certificate "
                             "carrying the policy. The link IS the attack")
                summ = (f"ESC13: msDS-OIDToGroupLink written on {target!r} -> "
                        f"{d['linked_groups']}")
            else:
                d["policies"] = self._texts(
                    [v for ch in by_attr.get(ATTR_CERT_POLICY, [])
                     for v in ch["vals"]])[:8]
                d["stage"] = "policy-reference"
                d["note"] = ("a certificate policy OID was attached to a template; "
                             "this is the template half of ESC13 and is only an "
                             "escalation if a matching msDS-OIDToGroupLink exists")
                summ = (f"ESC13: msPKI-Certificate-Policy written on template "
                        f"{target!r} -> {d['policies']}")
            out.append(self._finding("LDAP-ADCS-ESC13-OID-GROUP-LINK", ctx,
                                     msg.message_id, summary=summ, detail=d))

        # --- ESC14: altSecurityIdentities ---------------------------------- #
        if ATTR_ALT_SEC_ID in attrs:
            vals = [v for ch in by_attr.get(ATTR_ALT_SEC_ID, []) for v in ch["vals"]]
            mapped = [classify_altsecid(v["val"]) for v in vals]
            weak = [m for m, st in mapped if st == _ALTSECID_WEAK]
            strong = [m for m, st in mapped if st == _ALTSECID_STRONG]
            ungraded = [m for m, st in mapped if st is None]
            d = self._adcs_base(msg, {ATTR_ALT_SEC_ID})
            d["esc"] = "ESC14"
            d["technique"] = "T1556"
            d["mappings"] = [{"mapping": m, "strength": st} for m, st in mapped]
            d["values"] = self._texts(vals)[:8]
            d["mod_ops"] = sorted({ch["op"] for ch in by_attr[ATTR_ALT_SEC_ID]})
            if weak:
                sev = "critical"
                d["note"] = (f"a WEAK certificate mapping was written ({weak}): per "
                             "KB5014754 these do not bind the certificate to the "
                             "account cryptographically, so a certificate with a "
                             "matching subject or issuer authenticates as this account")
            else:
                sev = "high"
                d["note"] = ("writing another principal's altSecurityIdentities is an "
                             "impersonation primitive even when the mapping form is "
                             "strong, so this is reported rather than passed over")
            if strong:
                d["strong_mappings"] = strong
            if _ALTSECID_DISPUTED & set(strong):
                d["disputed"] = (
                    "X509SKI is classified STRONG by KB5014754 and is graded as such "
                    "here. Researchers argue it is effectively weak on RFC 5280 "
                    "grounds -- a CA may set any SKI value and AD does not verify it. "
                    "Microsoft has NOT reclassified it, and CVE-2025-26647 did not do "
                    "so either: that advisory adds an NTAuth chaining requirement and "
                    "never uses the words strong or weak")
            if ungraded:
                d["ungraded_mappings"] = ungraded
                d["ungraded_reason"] = (
                    "KB5014754's strength table does not cover these forms and their "
                    "on-wire markers are undocumented, so no strength is asserted; "
                    "the raw value is reported instead")
            if self.config.is_protected_user(_dn_leaf(target)):
                sev = "critical"
                d["protected_user"] = True
                d["escalation"] = "target object is on --protected-user"
            out.append(self._finding(
                "LDAP-ADCS-ESC14-WEAK-ALT-SEC-ID", ctx, msg.message_id, severity=sev,
                summary=f"ESC14: altSecurityIdentities written on {target!r} "
                        f"({[m for m, _ in mapped]})", detail=d))

        # --- ESC10: userPrincipalName swap -------------------------------- #
        if ATTR_UPN in attrs:
            out.extend(self._esc10_findings(msg, ctx, target, by_attr))
        return out

    def _note_upn_owner(self, dn, upn):
        if upn and dn:
            self._upn_owner.setdefault(upn.strip().lower(), dn)

    def _esc10_findings(self, msg, ctx, target, by_attr):
        """ESC10 rule 5. Stateful: the discriminator is the PATTERN, not the write.

        A bare userPrincipalName write is routine -- every rename does one -- so
        shipping it at high severity would drown the operator. Two patterns earn
        critical, and anything else grades to medium and says why.
        """
        vals = [v for ch in by_attr.get(ATTR_UPN, []) for v in ch["vals"]]
        new_upns = [t for t in self._texts(vals) if t.strip()]
        dn_key = (target or "").lower()
        ts = ctx.ts
        hist = self._upn_history.setdefault(dn_key, [])
        window = self.config.adcs_upn_swap_window
        recent = [(t, u) for (t, u) in hist if 0 <= ts - t <= window]

        reverted, collided = None, None
        for upn in new_upns:
            low = upn.strip().lower()
            # swap-and-revert: this write restores a value this object held
            # earlier in the window, i.e. the UPN went away and came back.
            for (t_prev, u_prev) in recent:
                if u_prev.strip().lower() == low:
                    reverted = (u_prev, round(ts - t_prev, 3))
                    break
            # collision: the UPN now claims an identity the sensor has already
            # seen belonging to a DIFFERENT object.
            owner = self._upn_owner.get(low)
            if owner is not None and owner.lower() != dn_key:
                collided = (upn, owner)

        for upn in new_upns:
            hist.append((ts, upn))
            self._note_upn_owner(target, upn)
        if len(hist) > 16:
            del hist[:-16]

        d = self._adcs_base(msg, {ATTR_UPN})
        d["esc"] = "ESC10"
        d["technique"] = "T1484"
        d["new_upn"] = new_upns[:4]
        d["mod_ops"] = sorted({ch["op"] for ch in by_attr[ATTR_UPN]})
        d["window_sec"] = window
        if reverted is not None:
            sev = "critical"
            d["pattern"] = "swap-and-revert"
            d["reverted_to"] = reverted[0]
            d["seconds_since_prior"] = reverted[1]
            d["note"] = ("this write RESTORES a userPrincipalName the same object held "
                         "moments ago. The swap-and-revert is ESC10's signature: the "
                         "UPN is borrowed, a certificate is enrolled against it, and "
                         "the original value is put back")
        elif collided is not None:
            sev = "critical"
            d["pattern"] = "upn-collision"
            d["collides_with_dn"] = collided[1]
            d["note"] = (f"the userPrincipalName {collided[0]!r} is already known to "
                         f"belong to a different object ({collided[1]!r}), so this "
                         "write claims another principal's identity")
        else:
            sev = "medium"
            d["pattern"] = "single-write"
            d["confidence"] = (
                "no-pattern: a lone userPrincipalName write is indistinguishable from "
                "an administrative rename. Graded DOWN rather than suppressed, and "
                "deliberately not shipped at high: the legitimate rate of UPN edits is "
                "site-specific and is not measurable from inside a passive module")
            d["note"] = "userPrincipalName written with neither ESC10 pattern present"
        if self.config.is_protected_user(_dn_leaf(target)) or any(
                self.config.is_protected_user(u) for u in new_upns):
            sev = "critical"
            d["protected_user"] = True
            d["escalation"] = "object or new UPN is on --protected-user"
        return [self._finding("LDAP-ADCS-ESC10-UPN-SWAP", ctx, msg.message_id,
                              severity=sev,
                              summary=f"ESC10: userPrincipalName written on {target!r} "
                                      f"-> {new_upns[:2]} [{d['pattern']}]", detail=d)]

    # -- CLDAP -------------------------------------------------------------- #

    def process_cldap_query(self, ts, src, sport, dst, dport, payload):
        fake = _BareCtx(ts)
        out = [self._finding(
            "LDAP-CLDAP-QUERY", fake, src=src, sport=sport, dst=dst, dport=dport,
            proto="udp", summary=f"CLDAP query {src} -> {dst}")]
        # Best-effort dissect for enumeration/injection signals inside the datagram.
        try:
            msg = dissect_message(payload)
        except BERError:
            return out
        if msg.op_tag == OP_SEARCH_REQUEST:
            op = msg.op
            if op.get("base") == "" and op.get("scope") == SCOPE_BASE:
                out.append(self._finding(
                    "LDAP-ROOTDSE-PROBE", fake, msg.message_id, proto="udp",
                    src=src, sport=sport, dst=dst, dport=dport,
                    summary="CLDAP RootDSE / netlogon probe",
                    detail={"filter": op.get("filter_summary", "")}))
            if self._nest_exceeded(msg):
                out.append(self._filter_nest_finding(
                    msg, fake, proto="udp", src=src, sport=sport, dst=dst, dport=dport))
            out.extend(self._ntver_findings(
                msg, fake, server_ip=dst, proto="udp",
                src=src, sport=sport, dst=dst, dport=dport))
        return out

    def process_cldap_response(self, ts, src, sport, dst, dport, payload, req_len):
        out = []
        fake = _BareCtx(ts)

        # LDAPNightmare: the malicious CLDAP referral response. This is checked
        # before the amplification gate because it does not depend on having seen
        # the matching request -- an unsolicited crafted response is still the
        # attack, and is arguably worse.
        try:
            msg = dissect_message(payload)
        except BERError:
            msg = None
        if msg is not None and self._is_referral_msgid_overflow(msg):
            out.append(self._referral_overflow_finding(
                msg, fake, proto="udp", src=src, sport=sport, dst=dst, dport=dport))
        if msg is not None and msg.op_tag == OP_SEARCH_RESULT_ENTRY:
            out.extend(self._netlogon_precond_findings(
                msg, fake, server_ip=src, proto="udp",
                src=src, sport=sport, dst=dst, dport=dport))

        if not req_len:
            return out
        ratio = len(payload) / max(req_len, 1)
        if len(payload) >= self.config.cldap_amp_floor and ratio >= self.config.cldap_amp_ratio:
            out.append(self._finding(
                "LDAP-CLDAP-AMPLIFICATION", fake, proto="udp",
                src=src, sport=sport, dst=dst, dport=dport,
                summary=f"CLDAP amplification x{ratio:.1f} ({req_len}->{len(payload)} B)",
                detail={"request_len": req_len, "response_len": len(payload),
                        "amplification": round(ratio, 2)}))
        return out

    def gc(self, ts):
        w = self.config.brute_window
        for key in list(self._bind_fail.keys()):
            dq = self._bind_fail[key]
            while dq and ts - dq[0] > w:
                dq.popleft()
            if not dq:
                del self._bind_fail[key]


class _BareCtx:
    """Minimal context for connectionless (UDP) findings that have no session."""
    __slots__ = ("ts",)

    def __init__(self, ts):
        self.ts = ts


def _ldap_url_host(uri):
    """Extract host from an ldap[s]://host[:port]/... URL (RFC 4516)."""
    m = re.match(r"ldaps?://(\[[^\]]+\]|[^:/]+)", uri, re.IGNORECASE)
    if not m:
        return None
    host = m.group(1)
    return host[1:-1] if host.startswith("[") else host


# --------------------------------------------------------------------------- #
# Output emitter (JSON lines, with dedup/rate-limit)
# --------------------------------------------------------------------------- #

def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds")


class JSONLEmitter:
    def __init__(self, path=None, also_stdout=True, min_severity="info",
                 dedup_window=60.0):
        self.fh = open(path, "a", buffering=1) if path else None
        self.also_stdout = also_stdout
        self.min_rank = SEVERITY_ORDER[min_severity]
        self.dedup_window = dedup_window
        self._seen = {}                       # fingerprint -> last emit ts
        self.count = 0

    @staticmethod
    def _fingerprint(rec):
        return (rec.get("finding"), rec.get("src"), rec.get("dst"),
                rec.get("dport"), rec.get("message_id"))

    def emit(self, rec):
        if SEVERITY_ORDER[rec["severity"]] < self.min_rank:
            return
        now = time.time()
        fp = self._fingerprint(rec)
        last = self._seen.get(fp)
        if last is not None and now - last < self.dedup_window:
            return
        self._seen[fp] = now
        line = json.dumps(rec, sort_keys=True, ensure_ascii=False)
        if self.fh:
            self.fh.write(line + "\n")
        if self.also_stdout:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        self.count += 1

    def close(self):
        if self.fh:
            self.fh.close()


# --------------------------------------------------------------------------- #
# Live capture (lazy Scapy import — only touched when actually sniffing)
# --------------------------------------------------------------------------- #

def run_capture(config, emitter, iface=None, bpf=None, pcap=None):
    try:
        from scapy.all import sniff, TCP, UDP, IP, IPv6, Raw  # noqa: WPS433 (lazy)
    except ImportError:
        log.error("scapy is required for live capture. Install with: "
                  "pip install --break-system-packages scapy")
        return 2

    engine = LDAPEngine(config)
    flows = FlowManager(config, engine, emitter)

    if bpf is None:
        ports = " or ".join(f"tcp port {p}" for p in sorted(ALL_TCP_PORTS))
        krb = " or ".join(f"(tcp port {p}) or (udp port {p})"
                          for p in sorted(config.krb_ports))
        bpf = f"({ports}) or (udp port {CLDAP_PORT}) or ({krb})"
        if getattr(config, "ipv6_eh", False):
            # libpcap's "tcp port N" / "udp port N" primitives cannot walk IPv6
            # extension headers: a v6 packet carrying Hop-by-Hop/Routing/DstOpts
            # (or a fragment) before the L4 header is silently NOT matched, so
            # the whole v6 attack surface can go dark. Widen to all of ip6 and
            # let the Python port gate in FlowManager do the filtering -- it
            # keys off the same port sets, so behaviour is identical, just at a
            # different layer. Costs CPU on a busy v6 link, hence opt-in.
            bpf = f"({bpf}) or ip6"
        if getattr(config, "jndi_anyport", False):
            # A rogue JNDI server listens wherever it likes, so the port set is
            # no longer the gate. Admit any IPv4 TCP segment whose first payload
            # byte is 0x30 -- every LDAPMessage is a BER SEQUENCE, so this is the
            # cheapest kernel-side pre-filter that cannot miss one. The Python
            # BER validator then decides, exactly as it already does.
            #
            # IPv6 needs a different term, and the obvious ones are wrong.
            # MEASURED against libpcap (tcpdump 4.99, see the netns lab's
            # permanent regression check):
            #   tcp[...]                  -> IPv4 only; silently skips IPv6
            #   ip6 and tcp[...]          -> REFUSED at compile time,
            #                                "expression rejects all packets"
            #   ip6 and tcp               -> misses any packet with an
            #                                extension header (the Next Header
            #                                field is the EH, not TCP)
            #   ip6                       -> matches everything, incl. EH
            # So the v6 side admits bare ip6 and lets the Python port/BER gate
            # decide, the same shape --ipv6-eh uses. This is the cost of v6
            # anyport and it is why the flag is opt-in.
            bpf = (f"({bpf}) or (ip and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x30)"
                   f" or ip6")

    def handle(pkt):
        try:
            ts = float(pkt.time)
        except Exception:
            ts = time.time()
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        if TCP in pkt:
            tcp = pkt[TCP]
            payload = bytes(tcp.payload) if isinstance(tcp.payload, Raw) or tcp.payload else b""
            flows.handle_tcp(ts, src, int(tcp.sport), dst, int(tcp.dport),
                             payload, int(tcp.flags))
        elif UDP in pkt:
            udp = pkt[UDP]
            payload = bytes(udp.payload) if udp.payload else b""
            sp, dp = int(udp.sport), int(udp.dport)
            if sp in config.krb_ports or dp in config.krb_ports:
                flows.handle_krb_udp(ts, src, sp, dst, dp, payload)
            else:
                flows.handle_cldap(ts, src, sp, dst, dp, payload)

    log.info("ldapwatch %s starting (passive) — iface=%s bpf=%r",
             __version__, iface or "default", bpf)
    if pcap:
        sniff(offline=pcap, filter=bpf, prn=handle, store=False)
    else:
        sniff(iface=iface, filter=bpf, prn=handle, store=False)
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_config(args):
    cfg = Config()
    for cidr in args.local_net or []:
        try:
            cfg.local_nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as exc:
            log.warning("ignoring bad --local-net %r: %s", cidr, exc)
    cfg.local_domains = list(args.local_domain or [])
    cfg.brute_window = args.brute_window
    cfg.brute_threshold = args.brute_threshold
    cfg.large_result_threshold = args.large_result
    cfg.cldap_amp_ratio = args.cldap_amp_ratio
    cfg.filter_depth_threshold = args.filter_depth
    cfg.netlogon_fill_floor = args.netlogon_fill_floor
    cfg.jndi_anyport = bool(args.jndi_anyport)
    cfg.krb_ports = {int(x) for x in str(args.krb_ports).split(",") if x.strip()}
    cfg.krb_enum_window = args.krb_enum_window
    cfg.krb_honeypot_spns = {sp.strip().lower() for sp in args.krb_honeypot_spn if sp.strip()}
    for spec in args.kdc:
        try:
            cfg.kdc_nets.append(ipaddress.ip_network(spec, strict=False))
        except ValueError:
            log.warning("ignoring --kdc %r: not an address or CIDR", spec)
    for spec in args.krb_native_client:
        try:
            cfg.krb_native_nets.append(ipaddress.ip_network(spec, strict=False))
        except ValueError:
            log.warning("ignoring --krb-native-client %r: not an address or CIDR", spec)
    cfg.protected_users = {u.strip().lower() for u in args.protected_user if u.strip()}
    cfg.s4u_retry_window = float(getattr(args, "s4u_retry_window", 5.0))
    cfg.adcs_upn_swap_window = float(getattr(args, "adcs_upn_swap_window", 300.0))
    for spec in args.jndi_allow_server:
        try:
            cfg.jndi_allow_nets.append(ipaddress.ip_network(spec, strict=False))
        except ValueError:
            cfg.jndi_allow_domains.append(spec)
    cfg.ipv6_eh = bool(getattr(args, "ipv6_eh", False))
    return cfg


def main(argv=None):
    p = argparse.ArgumentParser(
        prog=MODULE,
        description="Passive LDAP/CLDAP security posture monitor (Ragnar suite).")
    p.add_argument("-i", "--iface", help="capture interface (default: Scapy default)")
    p.add_argument("-r", "--read", dest="pcap", help="read from a pcap instead of live capture")
    p.add_argument("-w", "--write", dest="out", help="append JSON-lines findings to this file")
    p.add_argument("--bpf", help="override the capture BPF filter")
    p.add_argument("--local-net", action="append",
                   help="CIDR considered local (repeatable); scopes external-referral checks")
    p.add_argument("--local-domain", action="append",
                   help="DNS suffix considered local (repeatable), e.g. corp.example.com")
    p.add_argument("--min-severity", default="info",
                   choices=list(SEVERITY_ORDER.keys()), help="suppress findings below this")
    p.add_argument("--no-stdout", action="store_true", help="do not print findings to stdout")
    p.add_argument("--brute-window", type=float, default=30.0)
    p.add_argument("--brute-threshold", type=int, default=5)
    p.add_argument("--large-result", type=int, default=200)
    p.add_argument("--cldap-amp-ratio", type=float, default=10.0)
    p.add_argument("--jndi-allow-server", action="append", default=[], metavar="CIDR|DOMAIN",
                   help="declare a legitimate RFC 2713 directory (legacy J2EE); suppresses "
                        "LDAP-JNDI-SERIALIZED-OBJECT for it. Repeatable. With none set, "
                        "that finding always fires")
    p.add_argument("--kdc", action="append", default=[], metavar="ADDR|CIDR",
                   help="KDC/domain-controller addresses (v4 or v6, repeatable). Orients "
                        "which end is the KDC and ARMS the SPN-enumeration correlation rule")
    p.add_argument("--krb-honeypot-spn", action="append", default=[], metavar="SPN",
                   help="decoy SPN with no legitimate consumer (repeatable). ARMS the "
                        "honeytoken rule, which is the durable Kerberoasting control")
    p.add_argument("--krb-native-client", action="append", default=[], metavar="ADDR|CIDR",
                   help="hosts whose Kerberos stack legitimately omits canonicalize "
                        "(MIT krb5, Linux, macOS, Java). Repeatable, v4 and v6")
    p.add_argument("--protected-user", action="append", default=[], metavar="NAME",
                   help="sensitive account name (repeatable). ESCALATES "
                        "LDAP-KRB-S4U2SELF-IMPERSONATION from medium to high when that "
                        "principal is the one being impersonated. Matched case-insensitively "
                        "on the bare name and on the pre-@ part")
    p.add_argument("--adcs-upn-swap-window", type=float, default=300.0, metavar="SEC",
                   help="seconds within which two writes to the same object's "
                        "userPrincipalName count as an ESC10 swap-and-revert "
                        "(default 300). A lone UPN write is reported at medium "
                        "regardless, since every rename does one")
    p.add_argument("--s4u-retry-window", type=float, default=5.0, metavar="SEC",
                   help="seconds within which a byte-identical KDC request is treated as a "
                        "retransmission (RESPONSE_TOO_BIG UDP->TCP retry, UDP duplicate) "
                        "and not re-evaluated (default 5)")
    p.add_argument("--krb-ports", default=str(KRB_PORT), metavar="LIST",
                   help=f"comma-separated Kerberos ports, tcp+udp (default {KRB_PORT})")
    p.add_argument("--krb-enum-window", type=float, default=120.0, metavar="SEC",
                   help="seconds between an LDAP servicePrincipalName search and a "
                        "TGS-REQ for the correlation rule to fire")
    p.add_argument("--jndi-anyport", action="store_true",
                   help="widen capture to any TCP port carrying a BER SEQUENCE, for rogue "
                        "JNDI listeners on non-standard ports (costs CPU; egress taps)")
    p.add_argument("--netlogon-fill-floor", type=int, default=305,
                   help="combined DNS-name length (wide chars) at which a DC is reported "
                        "as meeting the CVE-2026-41089 overflow precondition")
    p.add_argument("--filter-depth", type=int, default=12,
                   help="search-filter nesting depth that trips LDAP-FILTER-NEST-DOS")
    p.add_argument("--ipv6-eh", action="store_true",
                   help="widen the BPF to all of ip6 so IPv6 extension-header packets "
                        "are not dropped by libpcap before the port match (costs CPU)")
    p.add_argument("--selftest", action="store_true", help="run the offline self-test harness")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING - min(args.verbose, 2) * 10,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.selftest:
        try:
            import test_ldapwatch
        except ImportError:
            print("test_ldapwatch.py not found next to ldapwatch.py", file=sys.stderr)
            return 2
        return test_ldapwatch.run_selftest()

    cfg = build_config(args)
    emitter = JSONLEmitter(path=args.out, also_stdout=not args.no_stdout,
                           min_severity=args.min_severity, dedup_window=cfg.dedup_window)

    stop = {"flag": False}

    def _sig(_signum, _frame):
        stop["flag"] = True
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    try:
        return run_capture(cfg, emitter, iface=args.iface, bpf=args.bpf, pcap=args.pcap)
    except KeyboardInterrupt:
        log.info("stopping; %d findings emitted", emitter.count)
        return 0
    finally:
        emitter.close()


if __name__ == "__main__":
    sys.exit(main())
